This codes cover stage C detection layer or secrets + PII on my third year capstone project, the full project can be accessed in the link below:
#TODO add link here later

gitleaks.toml credit: https://github.com/gitleaks
LakanVault - Stage C detection layer (secrets + PII) in a single file.

Two independent detectors that return the same Finding type:

  RegexDetector     layer "regex"     secrets (API keys, tokens, passwords).
                                      A Gitleaks-style pipeline per rule:
                                        1. keyword prefilter   (skip rule if no keyword in text)
                                        2. regex               (find secret candidates)
                                        3. secret extraction   (narrow to the (?P<secret>) group)
                                        4. allowlist           (drop / down-weight known false positives)
                                        5. entropy             (raise / lower confidence)
  PresidioDetector  layer "presidio"  PII, using Presidio's built-in recognizers (regex + spaCy NER).

detect(text) runs both layers and merges the result into one list of
non-overlapping findings. detect(text, layers=("regex",)) runs a single layer,
which is what you need for the regex-only / Presidio-only baselines (RQ1) and
for per-layer latency (RQ2).

Setup:
    pip install regex presidio-analyzer
    python -m spacy download en_core_web_lg      # or en_core_web_sm
Run demo:
    python main.py


This readme will go through how each class work, its function, and output, following the __name__ == "_main__" codes
#TODO add explanation or never ig
samples = [..] to t0 = time.perf_counter() is straightforward

get_engine("presidio").load()
1. call the get_engine function in line 319 with presidio layer
2. create new instance like _ENGINES["presidio"] = PresidioDetector(), then no need to remake instances later
3. load the model, PresidioDetector().load() it will run line 216, loading the analyzer
4. analyzer, first check if it exist then import the necessary tool like Analyzer Engine and NlpEngineProvider (to understand text)
5. tldextract configuration, so it doesnt download the public suffic list 
NlpEngineProvider
       ↓
read configuration
       ↓
"Use spaCy"
       ↓
"Use English model X"
       ↓
create NLP engine
6. Creat the NLPEngineProvider than give that to the AnalyzerEngine

Why need _resolve_overlaps()? imagine the prompt containe something liek
postgres://admin:secret123@example.com
you could probably have
Regex:
        secret123
        └────────┘

Presidio:
        example.com
        └───────────┘
we dont want tit conflict over the same character, so we clean them up, keep the higher tier and hight condiged


using en_core_web_lg
Per-layer latency on one prompt (average of 50 runs):
   regex             0.01 ms
   presidio          3.77 ms / 4.12 ms
   regex+presidio    3.67 ms / 4.06ms

using en_core_web_sm
Per-layer latency on one prompt (average of 50 runs):
   regex             0.01 ms
   presidio          3.54 ms /
   regex+presidio    3.52 ms / 

The difference is 0.1-0.2 ms which is unnoticable.

Some explanation, can ignore.
1. what is abc and ABC, abstract method
ABC / abstractmethod: ABC means Abstract Base Class. It is a template class you can't use directly. @abstractmethod says every subclass must write its own detect(), and Python raises an error if one doesn't. That way RegexDetector and PresidioDetector are guaranteed to have the same detect(text) shape.

2. dataclasses? dataclass and field?
@dataclass auto-writes __init__, __repr__ and __eq__ for a class that is mostly fields. field(...) customizes one field. Here field(repr=False) hides text when you print a Finding, so secrets don't leak into logs.

3. why use regex? instead of re? what is possessive quantifiers and scoped fkags actually mean?
See the fact check above. In short, regex is needed for the repeated secret group name. A possessive quantifier like {8,200}+ means "grab as much as possible and never give it back," which prevents slow backtracking. A scoped flag like (?i:password) makes only that part case-insensitive.

4. is the Tier class jsut VARIABLE = "VARIABLE" what do this even do exactly? is this just like an enum? so in code we can put :SECRET" and they get return SECRET?
Tier.SECRET is a safe, typo-proof label, and its value is the string "SECRET". Because it's (str, Enum), it also behaves like a string. Typing Tier.SECRET gives you the enum member, not just plain text, and .value gives "SECRET".

5. what is _RANK for?
Enums have no built-in "bigger than." _RANK gives each tier a number, so _resolve_overlaps can say "SECRET beats PII_HIGH beats PII_MODERATE" when two findings cover the same characters.

6. for PII_ENTITY_TIER why dont you just use confidence, so if its high then make it to tier pii high? or is this for configuration and user can predefine it?
They measure different things. Confidence means how sure we are that this is an SSN. Tier means how bad it is if it leaks. A 0.99-confidence city name is still only LOW. So PII_ENTITY_TIER is a policy table you can edit.

7. what is dataclass(frozen=True)? jut so this is a container for manu variable?
Yes, it's a container, and frozen means its fields can't be changed after creation. This also makes it hashable and safer to pass around.

8. pattern in SecretRule, so narrow the finding to value only? no regex right? the example is kinda confusing
The pattern is a regex. A (?P<secret>...) group is a named capture. If the rule has one, the finding covers only that part. For password = 'abc', the finding is just abc, not the whole line. Rules without the group, like AWS keys, report the whole match.

9. score, this is from presidio correct?
Not only from Presidio. SecretRule.score is your own base confidence for regex rules, which _score() adjusts. Presidio's r.score is used only in PresidioDetector.

10. keywords???
This is a speed trick. A cheap "akia" in text check runs first, and the slower regex only runs if the keyword is present.

11. entropy is see letter if its randomized or nah. i know this
right. High entropy means random-looking, so more likely a real secret. Low entropy means something like aaaaaaaa or a plain word.

12. what is this _START and _END regex?
_START = (?<![A-Za-z0-9]) means the match can't begin right after a letter or digit. _END = (?![A-Za-z0-9_-]) means it can't be followed by one. Together they stop matches from starting or ending in the middle of a longer token. For example, XAKIA... won't match as an AWS key.

13. SECRET_RULES is predefined and we write this by ourselves? and this is for regex yeah? maybe we can just use free source out there later and just use json or dictioanry in other fiel so we can just loop through the json and make the secret rule even more, or other method, ill provid ethe source later
Yes, they are for the regex layer. Loading rules from JSON, YAML or TOML is a good idea. Gitleaks, for one, keeps its rules in TOML. Two things to watch: JSON has no tuples, so convert keywords and entropy back to tuples when building SecretRule, and check that each pattern compiles with regex, since Gitleaks uses Go syntax.

14. can you explain simply how the _entropy function work?
Count how often each character appears.
Turn each count into a probability p.
Sum -p × log2(p).
"aaaa" gives 0 bits. "abcd" gives 2 bits. A long random string gives roughly 4 to 6 bits.

15. RegexDetector what is layer="regex" for?
It's a label stamped on every Finding as source, so you know which detector found it. This matters for your per-layer latency and accuracy comparisons.

16. how does the score system even work here?
0.75 or above: confident.
0.35 to 0.75: unsure, so escalate to the LLM.
Below 0.35: dropped.
In _score, the steps run in this order:
If the value is in ALLOW_EXACT or matches an allow regex, the score is 0 and the finding is dropped.
Start from the rule's base score.
If the value contains a placeholder word like "example," multiply by 0.4.
If the rule uses entropy, score up or down.
Entropy at or above high adds 0.25, capped at 0.95.
Entropy below low multiplies by 0.6.
Anything in between is unchanged.
Example with the generic rule, base 0.55:
Random-looking value: 0.80, confident.
Mid-entropy value like Summer2024!: 0.55, unsure, so it goes to the LLM.
Low-entropy value: 0.33, dropped.
Your demo's AKIAIOSFODNN7EXAMPLE is a good case. It starts at 0.95, but "example" multiplies it by 0.4 to 0.38, so it lands in the unsure band.