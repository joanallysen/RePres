import sys
import time
from detector import detect, _resolve_overlaps
from local_llm import ask_llm 
from policy_engine import decide

def scan(text: str):
    findings = detect(text)
    if any(f.needs_escalation for f in findings):
        llm_findings = ask_llm(text)
        if llm_findings is not None:
            findings = _resolve_overlaps(findings + llm_findings)
    return decide(findings)

if __name__ == '__main__':
    # so you can jst write the smaple to the terminal
    if len(sys.argv) > 1:
        prompts = [' '.join(sys.argv[1:])]
    else:
        from samples import samples
        prompts = samples

    for p  in prompts:
        t0 = time.perf_counter()
        action, per_finding = scan(p)
        ms = (time.perf_counter() - t0) * 1000
        print(f'PROMPT : {p}')
        for f, a in per_finding:
            print(f' {f.entity_type:<20} {f.tier.value:<13} {f.confidence:<5.2f} {f.text!r:<28} <-{f.source:<8} -> {a.value}')
        print(f'ACTION : {action.value.upper()} ({ms:.0f} ms)')
