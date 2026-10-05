import math
import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

import re

# =============================================================================
# 1. CONFIG - everything you are likely to tweak lives here
# =============================================================================

SPACY_MODEL = "en_core_web_sm"  # switch to "en_core_web_sm" for a lighter model

CONFIDENT_AT = 0.75    # confidence >= this: decisive, no LLM needed
DISCARD_BELOW = 0.35   # confidence <  this: ignored entirely
# Findings between the two values are "unsure" -> needs_escalation == True

GITLEAKS_TOML = "gitleaks.toml"
DEFAULT_SCORE = 0.85

class Tier(str, Enum):
    """
    Risk tiers. The three PII levels follow the PII confidentiality impact
    levels (low / moderate / high) of NIST SP 800-122, section 3.1.
    SECRET is a project addition: NIST SP 800-122 covers PII only, so
    credentials (API keys, tokens, passwords) are not part of that guideline.
    BENIGN = NIST's "not applicable" (nothing to protect); detectors never
    emit it, it exists for the local LLM to return.
    """
    SECRET = "SECRET"
    PII_HIGH = "PII_HIGH"
    PII_MODERATE = "PII_MODERATE"
    PII_LOW = "PII_LOW"
    BENIGN = "BENIGN"


_RANK = {Tier.SECRET: 4, Tier.PII_HIGH: 3, Tier.PII_MODERATE: 2,
         Tier.PII_LOW: 1, Tier.BENIGN: 0}

# --- PII (Presidio layer) ----------------------------------------------------
# NIST SP 800-122 does not fix a level per data type (the level depends on
# identifiability, field sensitivity, context of use, ...), so this is a default
# derived from two of its factors:
#   HIGH     fields NIST calls generally more sensitive (SSN, financial account,
#            medical) and government-issued IDs
#   MODERATE directly identifying fields (name, email, phone) + religion/politics
#   LOW      indirectly identifying / linkable data (location, IP, MAC)
PII_ENTITY_TIER: dict[str, Tier] = {
    "US_SSN": Tier.PII_HIGH,
    "US_ITIN": Tier.PII_HIGH,
    "US_PASSPORT": Tier.PII_HIGH,
    "US_DRIVER_LICENSE": Tier.PII_HIGH,
    "US_BANK_NUMBER": Tier.PII_HIGH,
    "CREDIT_CARD": Tier.PII_HIGH,
    "IBAN_CODE": Tier.PII_HIGH,
    "MEDICAL_LICENSE": Tier.PII_HIGH,
    "UK_NHS": Tier.PII_HIGH,
    "PERSON": Tier.PII_MODERATE,
    "EMAIL_ADDRESS": Tier.PII_MODERATE,
    "PHONE_NUMBER": Tier.PII_MODERATE,
    "NRP": Tier.PII_MODERATE,
    "LOCATION": Tier.PII_LOW,
    "IP_ADDRESS": Tier.PII_LOW,
    "MAC_ADDRESS": Tier.PII_LOW,
    # Deliberately NOT enabled: DATE_TIME, URL, AGE, ORGANIZATION, CRYPTO.
    # They fire constantly on ordinary code and are not PII by themselves.
}

# Exact strings Presidio must never flag (e.g. your own city or company contact).
PII_ALLOW_LIST: list[str] = []

# --- Secrets (regex layer) ---------------------------------------------------
# changed the secret tule to match gitleaks
@dataclass(frozen=True)
class SecretRule:
    id: str
    description: str
    regex: str
    keywords: tuple[str, ...]
    secret_group: int = 0       #  0 = not set
    entropy: float | None=None  # minimum entropy of secret (this is gitleaks semanticcs)
    score: float = DEFAULT_SCORE



# All quantifiers are bounded to avoid catastrophic backtracking on long input.
_START = r"(?<![A-Za-z0-9])" # the character immediately before it must not be a letter or digit.
_END = r"(?![A-Za-z0-9_-])" # the character immediately after it must not be a letter, digit, _, or -.

SECRET_RULES: list[SecretRule] = []

# --- Allowlist (checked against the EXTRACTED secret, like Gitleaks "stopwords") ---
# Placeholder-looking values: confidence x0.4 (lands in the "unsure" band, or is dropped).
ALLOW_STOPWORDS: tuple[str, ...] = (
    "example", "changeme", "change_me", "your_", "your-", "xxxx",
    "placeholder", "dummy", "sample", "fake", "redacted", "todo",
)
# Values that are never a real secret: dropped.
ALLOW_EXACT: set[str] = {"password", "secret", "token", "apikey", "api_key",
                         "string", "null", "none", "true", "false"}
# Regexes matched against the extracted secret: dropped. Example: r"^[0-9a-f]{40}$" ignores git SHAs.
ALLOW_REGEXES: list[str] = []


# =============================================================================
# 2. FINDING - the record every later stage consumes
# =============================================================================

@dataclass(frozen=True)
class Finding:
    entity_type: str          # e.g. "AWS_ACCESS_KEY", "EMAIL_ADDRESS"
    text: str = field(repr=False)  # the matched value (repr=False: never leak in logs)
    start: int                # character offset in the prompt (inclusive)
    end: int                  # character offset (exclusive)
    confidence: float         # 0..1
    tier: Tier
    source: str               # detection layer: "regex" | "presidio" (the LLM layer adds "llm")

    @property
    def needs_escalation(self) -> bool:
        """True when the fast layer is unsure -> hand to the local LLM (Stage E)."""
        return self.confidence < CONFIDENT_AT

    @property
    def preview(self) -> str:
        """Safe-to-print version of text: secrets are truncated."""
        # its okay to show the secret as the sample is not real secret.
        # return self.text[:4] + "***" if self.tier is Tier.SECRET else self.text
        return self.text

    def to_dict(self) -> dict:
        return {"entity_type": self.entity_type, "text": self.text,
                "start": self.start, "end": self.end,
                "confidence": round(self.confidence, 3),
                "tier": self.tier.value, "source": self.source,
                "needs_escalation": self.needs_escalation}


class DetectionEngine(ABC):
    """Common interface. The Stage E LocalLLMClassifier can implement it too."""
    layer: str

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        ...


# =============================================================================
# 3. REGEX DETECTOR - secrets, no Presidio / spaCy involved
# =============================================================================

def _entropy(s: str) -> float:
    """Shannon entropy in bits per character (random-looking strings score high)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


class RegexDetector(DetectionEngine):
    layer = "regex"

    def __init__(self, rules: list[SecretRule] = SECRET_RULES):
        if rules is None:
            from config_loader import load_secret_rules # lazy import, avoid circular import
            rules, _failed = load_secret_rules(GITLEAKS_TOML)
        self._rules = [(r, re.compile(r.regex)) for r in rules]
        self._allow_rx = [re.compile(p) for p in ALLOW_REGEXES]

    @staticmethod
    def _secret_span(rule: SecretRule, m: re.Match) -> tuple[int,int]:
        g = rule.secret_group
        if g == 0 and m.re.groups:
            g = 1
        start, end = m.span(g)
        return m.span() if start < 0 else (start, end)
    

    def detect(self, text: str) -> list[Finding]:
        lowered = text.lower()
        findings: list[Finding] = []
        for rule, rx in self._rules:
            # 1. keyword prefilter: cheap substring test before running the regex
            if not any(k in lowered for k in rule.keywords):
                continue
            # 2. regex: find secret candidates
            for m in rx.finditer(text):
                # 3. extraction: narrow to the secret value itself when the rule has a group
                start, end = self._secret_span(rule, m)
                value = text[start:end]
                # 4 + 5. allowlist and entropy -> final confidence
                score = self._score(rule, value)
                if score >= DISCARD_BELOW:
                    findings.append(Finding(rule.id, value, start, end, score, Tier.SECRET, self.layer))
        return findings

    def _score(self, rule: SecretRule, value: str) -> float:
        low = value.lower()
        if low in ALLOW_EXACT or any(rx.search(value) for rx in self._allow_rx):
            return 0.0
        score = rule.score
        if any(w in low for w in ALLOW_STOPWORDS):
            score *= 0.4
        if rule.entropy and _entropy(value) < rule.entropy:
            score *= 0.6
        return round(score, 3)


# =============================================================================
# 4. PRESIDIO DETECTOR - PII only, built-in recognizers
# =============================================================================

class PresidioDetector(DetectionEngine):
    layer = "presidio"

    def __init__(self, model: str | None = None):
        self._model = model or SPACY_MODEL
        self._analyzer = None  # built lazily: loading the spaCy model is slow

    def load(self):
        """Build the analyzer now (call at startup so the first prompt isn't slow)."""
        if self._analyzer is None:
            import tldextract  # used internally by Presidio's email recognizer
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            # tldextract downloads the public-suffix list on first use. A DLP tool must
            # stay fully local (NFR2), so force the snapshot bundled with the package.
            tldextract.tldextract.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

            nlp_engine = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": self._model}],
            }).create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        return self._analyzer

    def detect(self, text: str) -> list[Finding]:
        results = self.load().analyze(
            text=text,
            language="en",
            entities=list(PII_ENTITY_TIER),
            score_threshold=DISCARD_BELOW,
            allow_list=PII_ALLOW_LIST or None,
        )
        return [
            Finding(r.entity_type, text[r.start:r.end], r.start, r.end,
                    float(r.score), PII_ENTITY_TIER[r.entity_type], self.layer)
            for r in results
        ]


# =============================================================================
# 5. MERGE + detect()
# =============================================================================

def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """
    Two findings on the same characters (e.g. an email inside a connection string,
    or two secret rules hitting one value) must not both survive. Keep one:
    higher tier, then higher confidence, then longer span.
    """
    ranked = sorted(findings, key=lambda f: (-_RANK[f.tier], -f.confidence,
                                             -(f.end - f.start), f.start))
    kept: list[Finding] = []
    for f in ranked:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


_ENGINES: dict[str, DetectionEngine] = {}
_ENGINE_CLASSES = {"regex": RegexDetector, "presidio": PresidioDetector}


# _ENGINES will always start out empty, this get_engine create a new instance of the detector
# example: _ENGINES["presidio"] = PresidioDetector()
def get_engine(layer: str) -> DetectionEngine:
    """One shared instance per layer (rules compiled / model loaded once)."""
    if layer not in _ENGINES:
        _ENGINES[layer] = _ENGINE_CLASSES[layer]()
    return _ENGINES[layer]


def detect(text: str, layers: tuple[str, ...] = ("regex", "presidio")) -> list[Finding]:
    """
    Scan one prompt. Returns non-overlapping findings ordered by position.
    layers=("regex",) or layers=("presidio",) runs a single layer (baselines / timing).
    """
    findings: list[Finding] = []
    for layer in layers:
        findings.extend(get_engine(layer).detect(text))
    return _resolve_overlaps(findings)


# =============================================================================
# 6. DEMO - all values below are fake
# =============================================================================

# write the sample later, i cannot push to github because the sample was too realistic lol
if __name__ == "__main__":
    samples = [

    ]
    
    print(f"spaCy model: {SPACY_MODEL}")
    t0 = time.perf_counter()
    get_engine("presidio").load()
    print(f"Presidio load: {time.perf_counter() - t0:.1f}s\n")

    for s in samples:
        print(f"PROMPT: {s}")
        found = detect(s)
        if not found:
            print("   (no findings)")
        for f in found:
            flag = "ESCALATE" if f.needs_escalation else "confident"
            print(f"   {f.entity_type:<16} {f.tier.value:<13} {f.confidence:<5.2f} "
                  f"[{f.start}:{f.end}] {f.preview!r:<28} {flag:<9} <- {f.source}")
        print()

    # Per-layer latency (RQ2): each layer can be run and timed on its own.
    prompt = samples[5] + " " + samples[1]
    print("Per-layer latency on one prompt (average of 50 runs):")
    for layers in (("regex",), ("presidio",), ("regex", "presidio")):
        t0 = time.perf_counter()
        for _ in range(50):
            detect(prompt, layers=layers)
        print(f"   {'+'.join(layers):<15} {(time.perf_counter() - t0) / 50 * 1000:6.2f} ms")