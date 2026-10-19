import sys
import time
from regex_and_presidio import detect, _resolve_overlaps
from local_llm import ask_llm 
from policy_engine import decide, FAILURE_MODE, action_for, Action

def scan(text: str):
    findings = detect(text)
    # make sure all finding is recorded, no discard
    triggers = [f for f in findings if f.needs_escalation]
    llm_status = None
    if any(f.needs_escalation for f in findings):
        llm_findings = ask_llm(text)
        if llm_findings is None:
            llm_status = "failed"
            print('llm failed to process prompt, action chosen based on fail open or fail closed')
            if FAILURE_MODE == 'closed':
                per_finding = [(f, action_for(f)) for f in findings]
                return Action.BLOCK, per_finding, llm_status, triggers
            # fail open retain regex and presidio findings
        else:
            llm_status = "ok"
            findings = _resolve_overlaps(findings + llm_findings)
    action, per_finding = decide(findings)
    return action, per_finding, llm_status, triggers

if __name__ == '__main__':
    # so you can jst write the smaple to the terminal
    if len(sys.argv) > 1:
        prompts = [' '.join(sys.argv[1:])]
    else:
        from samples import samples
        prompts = [samples[0], samples[31], samples[1], samples[2]]

    for p in prompts:
        t0 = time.perf_counter()
        action, per_finding, llm_status, triggers = scan(p)
        ms = (time.perf_counter() - t0) * 1000
        print(f'PROMPT : {p}')
        for f, a in per_finding:
            esc = 'need escalation' if f.needs_escalation else '-'
            print(f'    {f.entity_type:<20} | {f.tier.value:<13} | {f.confidence:<5.2f}  | {f.text!r:<40} | {f.source:<10} | {a.value:<8}')

        if llm_status is not None:
            why = ', '.join(f'{t.entity_type} {t.confidence:.2f} ({t.source})' for t in triggers)
            if llm_status == 'ok':
                print(f'    Escalated to the local LLM because of: {why}.')
            else:
                print(f'    Escalation to the local LLM failed (triggered by: {why}); fail-{FAILURE_MODE}')
        
        print(f'    ACTION : {action.value.upper()} ({ms:.0f} ms)\n')
