# LakanVault: detection layer

LakanVault is a gateway that sits between an AI-assisted IDE and a cloud LLM so that sensitive data never leaves the machine. It scans each outgoing prompt (plain text, usually an orchestrated prompt) for secrets and personal data.

This document covers the **fast detection layer**: a regex engine for secrets and a Presidio engine for PII. Anything the fast layer is unsure about is meant to be escalated to a **local LLM** (planned, not part of this layer yet).

## Architecture

```mermaid
flowchart LR
    IDE["AI-assisted IDE"] --> GW["LakanVault gateway"]

    subgraph DET["Fast detection layer: detect(text)"]
        direction TB
        RX["RegexDetector<br/>secrets, Gitleaks rules"]
        PR["PresidioDetector<br/>PII, spaCy + recognizers"]
        MG["_resolve_overlaps<br/>one finding per span"]
        RX --> MG
        PR --> MG
    end

    GW --> RX
    GW --> PR
    MG --> BAND{"Confidence band"}

    BAND -- ">= 0.75 confident" --> ACT["Decision / redaction<br/>(planned)"]
    BAND -- "0.35 to 0.75 unsure" --> LLM["Local LLM classifier<br/>(planned)"]
    BAND -- "< 0.35" --> DROP["Discarded"]
    LLM -.-> ACT
    ACT -.-> CLOUD["Cloud LLM"]
```

Solid boxes exist today. Dashed paths and boxes marked *planned* are not built yet.

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
| `detector.py` | Config, `Finding` record, `RegexDetector`, `PresidioDetector`, overlap merge, `detect()`, and a demo/report runner |
| `config_loader.py` | Converts `gitleaks.toml` into `SecretRule` / `Allowlist` objects |
| `samples.py` | Synthetic prompts (all values fake) used to test the detectors |
| `gitleaks.toml` | Gitleaks default config. |
| `detector_results.txt` | Generated report. Consider adding it to `.gitignore` |

## How it works

### 1. Input and output

`detect(text, layers=("regex", "presidio"))` takes one prompt and returns a list of non-overlapping `Finding` objects ordered by position. Each finding holds:

| Field | Meaning |
|---|---|
| `entity_type` | Rule id (`aws-access-token`) or Presidio entity (`EMAIL_ADDRESS`) |
| `text` | The matched value (hidden from `repr`) |
| `start`, `end` | Character offsets in the prompt (end exclusive) |
| `confidence` | 0 to 1 |
| `tier` | Risk tier, see below |
| `source` | `regex` or `presidio` (the LLM layer will add `llm`) |

`needs_escalation` is true when `confidence < 0.75`.

### 2. Regex engine (secrets)

Rules come from `gitleaks.toml` through `config_loader.load_secret_rules()`, plus any custom rules in `SECRET_RULES` in `detector.py`. Gitleaks file is not touched from the original gitleaks, put your own rules in `SECRET_RULES` instead of editing the TOML.

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
| `BENIGN` | Nothing to protect | Never emitted by the detectors, reserved for the local LLM |

The three PII levels follow the low / moderate / high confidentiality impact levels of NIST SP 800-122. NIST does not fix a level per data type, so the per-entity mapping in `PII_ENTITY_TIER` is a project default. `SECRET` is a project addition, since the NIST guideline covers PII only.

### 5. Merging overlaps

When two findings cover the same characters (an email inside a connection string, or `generic-api-key` and `github-pat` both matching a token), only one survives. The winner is chosen by, in order:

1. higher tier
2. higher confidence
3. a specific rule over `generic-api-key`
4. longer span
5. earlier start

### 6. Confidence bands

| Confidence | Result |
|---|---|
| `>= 0.75` (`CONFIDENT_AT`) | Confident, no LLM needed |
| `0.35` to `0.75` | Unsure, `needs_escalation` is true, goes to the local LLM |
| `< 0.35` (`DISCARD_BELOW`) | Ignored |

## Setup

Python 3.11 or newer (the loader uses `tomllib`).

```bash
pip install regex presidio-analyzer tldextract spacy
python -m spacy download en_core_web_sm
```

Put `gitleaks.toml` in the project root.

## Usage

```python
from detector import detect, get_engine

get_engine("presidio").load()          # optional warm-up at startup

for f in detect("My AWS key is AKIAQ3Z7XK2MPL4WRT5N"):
    print(f.entity_type, f.tier.value, f.confidence, f.start, f.end, f.needs_escalation)
```

Run a single layer with `detect(text, layers=("regex",))` or `layers=("presidio",)`.

To run the demo prompts, write the report, and see per-layer latency:

```bash
python detector.py
```

## Configuration

All settings live at the top of `detector.py`.

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

### Adding a custom secret rule

```python
SECRET_RULES = [
    SecretRule(
        id="uri-credentials",
        description="Password embedded in a connection string or URL.",
        regex=r"""(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'"]{1,64}:([^\s@'"/]{3,128})@""",
        keywords=("://",),
        secret_group=1,
        score=0.9,
    ),
]
```

`secret_group` selects which regex group is reported as the secret, so only the password is flagged here, not the whole URL.

## Known limitations

Observed while testing against the synthetic prompts in `samples.py`:

- **Keyword prefilter blind spot.** A random-looking string on a line with no keyword (for example `session_ref = "Tq5W..."`) is never checked by the generic rule.
- **Split secrets.** A key built by string concatenation (`"AKIA" + "Q3Z7..."`) is missed.
- **Misleading confident labels.** A plain-English password such as "the staging DB password is ..." was labelled `PERSON` at 0.85, so it counts as confident and would not escalate.
- **Presidio SSN validation.** The test number `123-45-6789` is rejected by Presidio's SSN validator. Use a number that passes validation in samples (for example `512-34-8675`).
- **Phone numbers** score about 0.40 without context, so most phone numbers will be escalated.
- **spaCy `en_core_web_sm`** misses some names (for example "Priya"). The larger `en_core_web_lg` is untested here.
- **`NRP`** produced a false positive on an invoice reference (`INV-2291`). Consider removing it from `PII_ENTITY_TIER`.
- **Empty-username URLs.** The example `uri-credentials` rule needs a username, so `redis://:password@host` is missed unless the quantifier allows zero characters.
- **Silent findings never escalate.** Prompts where the fast layer finds nothing, or is confidently wrong, never reach the LLM stage.

## Roadmap

- Local LLM classifier (stage E) implementing the same `DetectionEngine` interface
- Policy / redaction step in the gateway
- Synthetic dataset to train the local model