# a very rough config loader

import regex as re
import tomllib
from pathlib import Path

from detector import SecretRule, DEFAULT_SCORE

def _parse_allowlist(section: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
    # return (regexes, stopwords) from one allowlist shaped table. ignore paths
    return tuple(section.get('regexes', [])), tuple(w.lower() for w in section.get('stopwords', []))

# this convert GO to python re, expect error.
def load_secret_rules(path: str | Path) -> tuple[list[SecretRule], list[tuple[str,str]]]:
    # return (rules, failed). basically the second part of tuple retun a list of error, rule that doesnt work in re
    with open(path, "rb") as f:
        data = tomllib.load(f)

    rules, failed = [], []
    for r in data.get("rules", []):
        if "regex" not in r:
            continue
        try: 
            re.compile(r["regex"])
        except re.error as e:
            failed.append((r.get("id", "<no id>"), str(e)))
            continue
        rules.append(
            SecretRule(
                id=r['id'],
                description=r.get('description', ''),
                regex=r['regex'],
                keywords=tuple(k.lower() for k in r.get('keywords', [])),
                secret_group=int(r.get('secretGroup', 0)),
                entropy=float(r['entropy']) if r.get('entropy') else None,
                score=float(r.get('score', DEFAULT_SCORE)),
        ))

    return rules, failed


# [[rules]]
# id = "aws-access-token"
# description = "..."
# regex = '''...'''
# keywords = ["a3t", "akia", "asia", "abia", "acca"]
# score = 0.95
# entropy = 3.0