# a very rough config loader

import regex as re
import tomllib
from pathlib import Path

from detector import SecretRule, Allowlist, DEFAULT_SCORE

def _parse_allowlist(section: dict) -> Allowlist | None:
    # as we are gonna only receive plain text, "AND" + paths can never be true
    if section.get('paths') and section.get('condition', 'OR').upper() == 'AND':
        return None
    al = Allowlist(
        target = section.get('regexTarget', 'secret'),
        regexes = tuple(section.get('regexes', [])),
        stopwords = tuple(w.lower() for w in section.get('stopwords', []))
    )
    return al if (al.regexes or al.stopwords) else None

# this convert GO to python re, expect error.
def load_secret_rules(path: str | Path) -> tuple[list[SecretRule], list[tuple[str,str]], Allowlist | None]:
    # return (rules, failed). basically the second part of tuple retun a list of error, rule that doesnt work in re
    with open(path, "rb") as f:
        data = tomllib.load(f)

    global_allow = _parse_allowlist(data.get("allowlist", {}))

    rules, failed = [], []
    for r in data.get("rules", []):
        if 'regex' not in r or r.get('path'):
            continue
        try: 
            re.compile(r["regex"])
        except re.error as e:
            failed.append((r.get("id", "<no id>"), str(e)))
            continue

        allowlists = []

        if "allowlist" in r:
            al = _parse_allowlist(r["allowlist"])
            if al:
                allowlists.append(al)

        for a in r.get("allowlists", []):
            al = _parse_allowlist(a)
            if al:
                allowlists.append(al)

        rules.append(
            SecretRule(
                id=r['id'],
                description=r.get('description', ''),
                regex=r['regex'],
                keywords=tuple(k.lower() for k in r.get('keywords', [])),
                secret_group=int(r.get('secretGroup', 0)),
                entropy=float(r['entropy']) if r.get('entropy') else None,
                score=float(r.get('score', DEFAULT_SCORE)),
                allowlists=tuple(allowlists),
        ))

    return rules, failed, global_allow


# [[rules]]
# id = "aws-access-token"
# description = "..."
# regex = '''...'''
# keywords = ["a3t", "akia", "asia", "abia", "acca"]
# score = 0.95
# entropy = 3.0