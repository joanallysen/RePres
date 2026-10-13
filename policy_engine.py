from enum import Enum

from detector import Finding, Tier

class Action(str, Enum):
    ALLOW = 'allow'
    WARN = 'warn'
    MASK = 'mask'
    BLOCK = 'block'

_RANK = {Action.ALLOW: 0, Action.WARN: 1, Action.MASK: 2, Action.BLOCK: 3}

# tier to (action when confident, action when not usre)
POLICY = {
    Tier.SECRET: (Action.BLOCK, Action.WARN),
    Tier.PII_HIGH: (Action.MASK, Action.WARN),
    Tier.PII_MODERATE: (Action.MASK, Action.WARN),
    Tier.PII_LOW:(Action.WARN, Action.ALLOW)
}

# regex, presidio, and local LLM uses score, high = confident
def action_for(f : Finding) -> Action:
    confident, unsure = POLICY[f.tier]
    return unsure if f.need_escalation else confident

# return the final action for the whole prompt
def decide(findings: list[Finding]) -> tuple[Action, list[tuple[Finding, Action]]]:
    per_finding = [(f, action_for(f) for f in findings)]
    final = max((a for _, a in per_finding), key=_RANK.get, default=Action.ALLOW)
    return final, per_finding

