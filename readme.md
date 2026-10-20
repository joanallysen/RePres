# LakanVault: detection and policy layers

LakanVault is a gateway that sits between an AI-assisted IDE and a cloud LLM so that sensitive data never leaves the machine. It scans each outgoing prompt (plain text, usually an orchestrated prompt) for secrets and personal data, then decides what to do with it.

This document covers the **detection and decision stages**:

1. a **fast layer**: a regex engine for secrets and a Presidio engine for PII
2. a **local LLM classifier** that re-checks anything the fast layer is unsure about
3. a **policy engine** that turns the findings into one action: allow, warn, mask or block
4. a **sanitizer** (`opaque/`) that replaces every finding with a format-preserving surrogate and stores the mapping in SQLite so the response can be restored

## End-to-end flow

| Step | What happens | Status |
|---|---|---|
| 1 | Developer writes a prompt in an AI-assisted tool (Cursor, Claude Code, VS Code) | Gateway integration, not covered here |
| 2 | Before the prompt leaves the machine it passes through the LakanVault gateway | Gateway integration, not covered here |
| 3 | Regex checks for secrets by pattern, Presidio checks for personally identifiable information | Done |
| 4 | Confident results go straight to the policy engine. Unsure results are escalated to the local LLM first | Done |
| 5 | The policy engine decides Allow, Warn, Mask or Block from tier-specific policies | Done |
| 6 | Every finding is replaced with a format-preserving surrogate (not an opaque token), whatever the action, BLOCK included | Done for secrets. PII generators written, untested |
| 7 | The sanitized prompt is sent to the external LLM (OpenAI, Claude, Gemini) | Planned |
| 8 | In the response, surrogates are restored to the original values from the SQLite mapping (`Vault.restore`) | Implemented, not yet wired to the gateway |
| 9 | The restored output is validated before it is returned to the user | Planned |
## Architecture

```mermaid
flowchart LR
    IDE["AI-assisted IDE"] --> GW["LakanVault gateway"]

    subgraph DET["Fast detection layer: detect(text)"]
        direction TB
        RX["RegexDetector<br/>secrets, Gitleaks rules"]
        PR["PresidioDetector<br/>PII, spaCy + recognizers"]
        MG1["_resolve_overlaps<br/>one finding per span"]
        RX --> MG1
        PR --> MG1
    end

    GW --> RX
    GW --> PR
    MG1 --> BAND{"Any finding unsure?<br/>confidence below 0.75"}

    BAND -- "no" --> POL
    BAND -- "yes" --> LLM["Local LLM classifier<br/>ask_llm(text)"]
    LLM -- "ok" --> MG2["Merge + _resolve_overlaps"]
    LLM -- "failed" --> POL
    MG2 --> POL["Policy engine<br/>decide(findings)"]
    POL --> OUT["ALLOW / WARN / MASK / BLOCK"]
    OUT --> SAN["Vault.sanitize<br/>surrogates + SQLite mapping"]
    SAN -.-> CLOUD["External LLM (planned)"]
```

Solid boxes exist today. Dashed paths and boxes marked *planned* are not built yet. Findings below confidence 0.35 are discarded inside the detectors and never reach the diagram above.

### Regex scoring pipeline (per rule)

```mermaid
flowchart TD
    A["Prompt text"] --> B{"Rule keyword<br/>in text?"}
    B -- no --> Z["Skip rule"]
    B -- yes --> C["regex.finditer"]
    C --> D["Extract secret<br/>secretGroup, first group, or whole match"]
    D --> E{"Hard drop?<br/>exact word, hard stopword,<br/>allow regex, Gitleaks allowlist"}
    E -- yes --> X["Score 0, dropped"]
    E -- no --> F["score = rule score (default 0.85)"]
    F --> G{"Contains placeholder<br/>stopword?"}
    G -- yes --> G2["score x 0.4"]
    G -- no --> H
    G2 --> H{"Entropy below<br/>rule threshold?"}
    H -- yes --> H2["score x 0.6"]
    H -- no --> I
    H2 --> I{"score >= 0.35?"}
    I -- yes --> K["Finding, tier SECRET"]
    I -- no --> X
```

## Files

| File | Purpose |
|---|---|
| `regex_and_presidio.py` | Config, `Finding` record, `RegexDetector`, `PresidioDetector`, overlap merge, `detect()`, and a demo/report runner |
| `config_loader.py` | Converts `gitleaks.toml` into `SecretRule` / `Allowlist` objects |
| `local_llm.py` | `ask_llm()`: sends a prompt to the local LLM and returns its findings as `Finding` objects |
| `policy_engine.py` | `POLICY` table, `action_for()` and `decide()` |
| `main.py` | `scan()` ties the stages together; command-line runner that prints a report |
| `samples.py` | Synthetic prompts (all values fake) used to test the detectors |
| `gitleaks.toml` | Gitleaks default config |
| `results/detector_results.txt` | Generated report. Consider adding `results/` to `.gitignore` |
| `opaque/pseudo.py` | Surrogate generators (secrets and PII), `Vault` (SQLite mapping, `sanitize()`, `restore()`) |
| `opaque/keywords.py` | `KEYWORDS`: known secret prefixes preserved in the surrogate |
| `opaque/test_set.py` | Sample secrets to test the surrogate generator |
| `vault.db`, `vault.key` | Generated at runtime. Add both to `.gitignore`: the database holds real values |

## How it works

### 1. Input and output

`detect(text, layers=("regex", "presidio"))` takes one prompt and returns a list of non-overlapping `Finding` objects ordered by position. Each finding holds:

| Field | Meaning |
|---|---|
| `entity_type` | Rule id (`aws-access-token`), Presidio entity (`EMAIL_ADDRESS`), or a free-form label from the local LLM (`api_key`) |
| `text` | The matched value (hidden from `repr`) |
| `start`, `end` | Character offsets in the prompt (end exclusive) |
| `confidence` | 0 to 1 |
| `tier` | Risk tier, see below |
| `source` | `regex`, `presidio` or `llm` |

`needs_escalation` is true when `confidence < 0.75`.

### 2. Regex engine (secrets)

Rules come from `gitleaks.toml` through `config_loader.load_secret_rules()`, plus any custom rules in `SECRET_RULES` in `regex_and_presidio.py`. The Gitleaks file is not modified from the original; put your own rules in `SECRET_RULES` instead of editing the TOML.

The loader:

- skips rules with no `regex` or with a `path` (plain text has no file path)
- reads `keywords`, `entropy`, `secretGroup`, and an optional `score` (a LakanVault extension, not a Gitleaks field)
- reports rules whose Go regex does not compile in Python as `failed`, rather than crashing
- drops allowlists that combine `condition = "AND"` with `paths`, since the path half can never match plain text

Per rule, the detector runs the pipeline in the diagram above: a cheap keyword prefilter, the regex, secret extraction, then scoring.

**Worked example.** `api_key = "your_api_key_here"` contains the placeholder stopword `your_`, so the score becomes 0.85 x 0.4 = 0.34. That is below the discard threshold of 0.35, so it is dropped. A rule with a base score of 0.95 would land at 0.38 and be kept as "unsure".

**Allowlists** follow Gitleaks semantics: stopwords are substring-matched against the extracted secret, and `regexTarget` chooses what the regexes run against (`secret`, `match`, or `line`).

### 3. Presidio engine (PII)

`PresidioDetector` wraps a Presidio `AnalyzerEngine` with a spaCy model (`en_core_web_sm` by default). Notes:

- The analyzer loads lazily because loading spaCy is slow. Call `get_engine("presidio").load()` at startup.
- `tldextract` is forced to use its bundled public-suffix snapshot so the tool never makes a network call.
- Only the entities listed in `PII_ENTITY_TIER` are enabled.
- Email spans are trimmed after detection, because Presidio's email pattern can absorb prefixes such as `to='`.
- `DATE_TIME`, `URL`, `AGE`, `ORGANIZATION` and `CRYPTO` are deliberately off. They fire constantly on ordinary code.

### 4. Tiers

| Tier | Meaning | Examples |
|---|---|---|
| `SECRET` | Credentials | API keys, tokens, private keys, connection-string passwords |
| `PII_HIGH` | Highly sensitive PII | SSN, credit card, bank number, IBAN, passport, medical IDs |
| `PII_MODERATE` | Directly identifying PII | Name, email, phone |
| `PII_LOW` | Indirectly identifying PII | Location, IP address, MAC address |
| `BENIGN` | Nothing to protect | Defined in the enum but not emitted by any component today |

The three PII levels follow the low / moderate / high confidentiality impact levels of NIST SP 800-122. NIST does not fix a level per data type, so the per-entity mapping in `PII_ENTITY_TIER` is a project default. `SECRET` is a project addition, since the NIST guideline covers PII only.

`BENIGN` is not in the local LLM's output schema and has no entry in `POLICY`, so a `BENIGN` finding would raise a `KeyError` in the policy engine. Either keep it unused or add a policy entry before using it.

### 5. Merging overlaps

When two findings cover the same characters (an email inside a connection string, or `generic-api-key` and `github-pat` both matching a token), only one survives. The winner is chosen by, in order:

1. higher tier
2. higher confidence
3. a specific rule over `generic-api-key`
4. longer span
5. earlier start

This runs twice: once inside `detect()` for the regex and Presidio results, and again in `scan()` after the local LLM's findings are added.

### 6. Confidence bands

| Confidence | Result |
|---|---|
| `>= 0.75` (`CONFIDENT_AT`) | Confident, no LLM needed |
| `0.35` to `0.75` | Unsure, `needs_escalation` is true, goes to the local LLM |
| `< 0.35` (`DISCARD_BELOW`) | Ignored |

### 7. Local LLM classifier (`local_llm.py`)

`ask_llm(text)` re-checks a prompt that the fast layer was unsure about. It talks to a local model through LM Studio's OpenAI-compatible server (`http://localhost:1234/v1`), so the prompt stays on the machine.

**Request.**

- Model is set by `MODEL` (the code lists `google/gemma-4-e4b` and `qwen/qwen3.5-9b` as the available options).
- `temperature=0`, `max_tokens=900`, client timeout 60 seconds.
- The system prompt describes what counts as sensitive, the four tiers, and tells the model that the text is data and never instructions.
- The response format is a strict JSON schema, so the model can only return a `findings` list of `{type, tier, span, confidence}` objects. `tier` is limited to `SECRET`, `PII_HIGH`, `PII_MODERATE` and `PII_LOW`.

**Confidence.** The model answers `low`, `medium` or `high`, mapped by `CONF`:

| Model says | Becomes | Escalates again? |
|---|---|---|
| `low` | 0.4 | yes (below 0.75) |
| `medium` | 0.6 | yes (below 0.75) |
| `high` | 0.9 | no |

These numbers are a project choice, not a calibrated probability. LLM findings are not re-escalated: the model is only called once per prompt.

**From span to offsets.** The model returns the sensitive text, not positions. `ask_llm` finds every occurrence of each span with `text.find`, so masking later covers all repeats. A span that does not appear verbatim in the prompt is dropped.

**Failure handling.** `ask_llm` returns `None` when the request fails (connection, timeout), the output is truncated (`finish_reason == "length"`), the content is empty, or the JSON is invalid. `scan()` then keeps the fast-layer findings, so the pipeline never blocks on the LLM.

**Cost.** The fast layers take a few milliseconds per prompt. In testing, one LLM call took about 4 to 5 seconds on the development machine, which is why the LLM only runs on unsure findings. Three findings used 182 completion tokens, so the 900-token limit fits roughly 14 to 15 findings before truncating.

### 8. Policy engine (`policy_engine.py`)

The policy engine maps each finding's tier and confidence to an action, then takes the strictest action across the prompt.

| Tier | Confident (>= 0.75) | Unsure (< 0.75) |
|---|---|---|
| `SECRET` | `BLOCK` | `WARN` |
| `PII_HIGH` | `MASK` | `WARN` |
| `PII_MODERATE` | `MASK` | `WARN` |
| `PII_LOW` | `WARN` | `ALLOW` |

Actions are ranked `ALLOW` (0) < `WARN` (1) < `MASK` (2) < `BLOCK` (3).

- `action_for(finding)` looks up the finding's tier and picks the confident or unsure action from `needs_escalation`.
- `decide(findings)` returns `(final_action, [(finding, action), ...])`. The final action is the highest-ranked per-finding action, or `ALLOW` when there are no findings.

An unsure result usually means the LLM was unavailable or was itself unsure, because LLM answers replace unsure fast-layer findings when they overlap and are more confident.

### 9. Sanitizer (`opaque/pseudo.py`)

Every finding is replaced with a surrogate that looks like the real value, so the cloud LLM still understands the prompt. The action (ALLOW, WARN, MASK, BLOCK) is currently only reported. The sanitizer runs on all findings, so BLOCK does not stop the prompt from being sent in this flow.

**Secrets.** The longest keyword from `KEYWORDS` found anywhere in the secret is kept, and everything else is randomized by character class (digit, upper, lower). Symbols such as `-` and `_` stay.

**PII.**

| Entity | Surrogate |
|---|---|
| `PERSON`, `LOCATION` | Faker name or city |
| `EMAIL_ADDRESS` | Faker `safe_email()` (`example.*` domain, so the real domain does not leak) |
| `CREDIT_CARD` | Random digits with a valid Luhn check digit |
| `IBAN_CODE` | Same country code, random body, recomputed check digits |
| `IP_ADDRESS` | Random address in a documentation range |
| Phone, SSN, ITIN, passport, driver licence, bank number, NHS, medical licence, MAC | Format-preserving randomization |

Unknown labels (free-form LLM types) fall back to the tier: PII tiers use format-preserving randomization, `SECRET` uses the secret logic.

**Deterministic and persistent.** The random generator is seeded from `HMAC-SHA256(key, "attempt:value")`, so the same value always produces the same surrogate across prompts and restarts. The model therefore sees stable values over a conversation. The key lives in `vault.key` (created on first run, owner-only permissions).

**Vault.** Table `mapping(workspace, fake, real)`, primary key `(workspace, fake)`. If a surrogate equals the real value or collides with a different value's surrogate, `surrogate()` retries up to 20 times with a changed `attempt`. `sanitize()` replaces spans right to left, then replaces leftover occurrences of each flagged value (word boundaries for PII). `restore()` replaces all surrogates in one regex pass, longest first.

### 10. Putting it together (`main.py`)

`scan(text)` runs the stages in order:

1. `detect(text)` runs regex and Presidio and resolves overlaps.
2. If any finding needs escalation, `ask_llm(text)` is called. On success its findings are merged and overlaps are resolved again. On failure the fast-layer findings are kept.
3. `decide(findings)` returns the final action and the per-finding actions.

Running `main.py` prints one block per prompt: a table row for each finding (entity, tier, confidence, matched text, source, action), a sentence saying what triggered escalation when the LLM ran, and the final action with timing.

## Setup

Python 3.11 or newer (the loader uses `tomllib`).

```bash
pip install regex presidio-analyzer tldextract spacy openai Faker
python -m spacy download en_core_web_sm
```

Put `gitleaks.toml` in the project root.

For the local LLM, install LM Studio, download the model named in `MODEL`, load it, and start the local server (default port 1234).

## Usage

Scan one prompt from the command line, or run the sample prompts when no argument is given:

```bash
python main.py "the db password is Tr0ub4dor&3"
python main.py
```

Note: please create a samples.py first to run python main.py. samples.py should include a list of samples (samples = ['db password is ...', '...']).

Use the detectors directly:

```python
from regex_and_presidio import detect, get_engine

get_engine("presidio").load()          # optional warm-up at startup

for f in detect("My AWS key is AKIAQ3Z7XK2MPL4WRT5N"):
    print(f.entity_type, f.tier.value, f.confidence, f.start, f.end, f.needs_escalation)
```

Run a single layer with `detect(text, layers=("regex",))` or `layers=("presidio",)`.

Use the full pipeline from code:

```python
from main import scan

result = scan("retrying with key rk_test_Zb7Nq3Wl9Xt2Vm5Kp8Rd4Hs")
action, per_finding = result[0], result[1]
```

To run the detector demo prompts, write the report, and see per-layer latency:

```bash
python regex_and_presidio.py
```

The report is written to `results/detector_results.txt`; the `results/` folder must exist.

To test the local LLM on its own:

```bash
python local_llm.py
```

`main.py` prints a `SANITIZED` line after each prompt. To test the surrogate generator on its own: `python -m opaque.pseudo`

## Configuration

**`regex_and_presidio.py`**

| Setting | Purpose |
|---|---|
| `SPACY_MODEL` | spaCy model for Presidio |
| `CONFIDENT_AT` | Confidence at or above which a finding is decisive |
| `DISCARD_BELOW` | Confidence below which a finding is ignored |
| `GITLEAKS_TOML` | Path to the Gitleaks config |
| `DEFAULT_SCORE` | Base score for rules with no `score` |
| `PII_ENTITY_TIER` | Which Presidio entities run, and their tier |
| `PII_ALLOW_LIST` | Exact strings Presidio must never flag |
| `ALLOW_STOPWORDS` | Placeholder words that demote a secret (x 0.4) |
| `ALLOW_EXACT`, `ALLOW_REGEXES`, `ALLOW_STOPWORDS_HARD` | Values that are dropped outright |

**`local_llm.py`**

| Setting | Purpose |
|---|---|
| `MODEL` | Model id served by LM Studio |
| `CONF` | Mapping from `low` / `medium` / `high` to a 0 to 1 confidence |
| `SYSTEM_PROMPT` | What the model is told counts as sensitive, and the output format |
| `base_url`, `timeout` (on the client) | Where the local server runs and how long to wait |
| `max_tokens` (in the request) | Output limit. Higher values allow more findings but add latency |

**`policy_engine.py`**

| Setting | Purpose |
|---|---|
| `POLICY` | Per tier: action when confident, action when unsure |

**`opaque/pseudo.py`**

| Setting | Purpose |
|---|---|
| `KEY_PATH` | Location of the HMAC key file |
| `Vault(path, workspace)` | Database file and the workspace that scopes the mapping |
| `PII_GENERATORS` | Entity type to surrogate generator |
| `KEYWORDS` (`opaque/keywords.py`) | Prefixes preserved inside secret surrogates |

### Adding a custom secret rule

```python
SECRET_RULES = [
    SecretRule(
        id="uri-credentials",
        description="Password embedded in a connection string or URL.",
        regex=r"""(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'"]{0,64}:([^\s@'"/]{3,128})@""",
        keywords=("://",),
        secret_group=1,
        score=0.9,
    ),
]
```

`secret_group` selects which regex group is reported as the secret, so only the password is flagged here, not the whole URL. The username quantifier is `{0,64}`, so URLs with an empty username such as `redis://:password@host` are matched.

## Known limitations

Observed while testing against the synthetic prompts in `samples.py`:

**Fast layer**

- **Keyword prefilter blind spot.** A random-looking string on a line with no keyword (for example `session_ref = "Tq5W..."`) is never checked by the generic rule.
- **Split secrets.** A key built by string concatenation (`"AKIA" + "Q3Z7..."`) is missed.
- **Misleading confident labels.** A plain-English password such as "the staging DB password is ..." was labelled `PERSON` at 0.85, so it counts as confident and would not escalate.
- **Presidio SSN validation.** The test number `123-45-6789` is rejected by Presidio's SSN validator. Use a number that passes validation in samples (for example `512-34-8675`).
- **Phone numbers** score about 0.40 without context, so most phone numbers will be escalated.
- **spaCy `en_core_web_sm`** misses some names (for example "Priya"). The larger `en_core_web_lg` is untested here.

**Escalation**

- **Silent findings never escalate.** Escalation only starts when at least one finding is unsure. A prompt where the fast layer finds nothing, or is confidently wrong, never reaches the LLM, even though the LLM is the layer built to catch plain-word credentials.
- **Latency.** An LLM call adds seconds, so prompts with an unsure finding are far slower than the rest.

**Local LLM**

- **Labels are free-form.** The model picks its own `type`, so it may report `api_key` where a regex rule reported `stripe-access-token`. If the LLM's finding wins the overlap merge (higher confidence), the more generic label is the one that is shown.
- **Confidence is not comparable across layers.** The LLM's `high` is mapped to 0.9 by choice, which can outrank a regex score of 0.85 in the overlap merge.
- **Prompt injection is untested.** The system prompt tells the model to treat the text as data, but this has not been tested against prompts that try to override it.
- **Small models over-flag.** Whether placeholders, UUIDs and git hashes are correctly ignored has not been tested systematically.

**Policy**

- **Strictest action wins.** An unsure `SECRET` gives `WARN` and a confident email gives `MASK`, so the prompt's final action is `MASK`. The unsure secret still needs its own handling in the sanitization step.
- **`PII_LOW` unsure becomes `ALLOW`.** Low-confidence locations, IP addresses and MAC addresses pass through unflagged.


**Sanitizer**

- **Tested only on secrets.** Secrets were checked on sample prompts. The PII generators are untested.
- **Plaintext mapping.** `vault.db` stores real values unencrypted. Restrict file permissions or encrypt the `real` column.
- **Leftover-copy pass can corrupt fakes.** It runs on text that already contains surrogates, so a short real value can be replaced inside one. Fix: collect all occurrences from the original text and replace in a single pass.
- **Generators can raise on malformed detections** (`fake_card` with no digits, `fake_iban` with symbols). Fall back to `randomize`.
- **Shared Faker instance** is reseeded on each call and is not thread-safe.
- **Restore is exact-match.** A model that replies with only a first name or a possessive will not restore. Expect misses for `PERSON`.
- **Same text with two entity types** gets two different surrogates.
- **Surrogates for randomized entities** (SSN, NHS and similar) may fail Presidio's validators, which affects format-fidelity metrics.
- **Kept keywords are real characters.** The leak-rate metric should exclude them.
- **Partial overlaps.** `_resolve_overlaps` drops the losing finding, so characters of a losing span outside the winner stay unsanitized.
- **Over-flagging** (a code identifier tagged `PERSON` or `LOCATION`) renames it in the code.

## Roadmap

- Step 7: forward the sanitized prompt to the external LLM
- Step 8: token restoration from an SQLite mapping store
- Step 9: validation of the restored response
- Decide how `WARN` findings are handled in step 6
- Escalate prompts where the fast layer finds nothing (for example, only when the text contains hints such as "password" or "token")
- Synthetic dataset to train the local model