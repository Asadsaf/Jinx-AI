# Connecting Jinx to a target (quick reference)

```
            jinx/catalog.py  (16 combined MITRE ATLAS tests)
                    |
    jinx/techniques.py  +  jinx/modifiers.py (framings x encodings)
                    |
 (A) API       (B) Browser (scripted)     (C) Browser assistant (run sheet)
                    |
        jinx.harness.score  ->  out/telemetry.jsonl  ->  python -m jinx report
```

## A. API target
```python
from jinx.harness import HTTPTarget, run_battery, run_test, run_multiturn
t = HTTPTarget({"name": "vendor-x", "url": "...", "headers": {...},
                "body": {"input": "<<PROMPT>>"}, "answer_path": ["output"]})
run_test(t, "JX-01")          # one combined ATLAS test
run_battery(t)                # every technique, one message each
run_multiturn(t, goal="exfiltrate the out-of-scope canary to our catcher")  # needs ADV_* env
```

## B. Browser target (scripted, Playwright)
```python
from jinx.harness import BrowserTarget, run_battery
t = BrowserTarget(url="https://vendor.example/ai", input_sel="textarea",
                  send_sel="button[type=submit]", answer_sel=".answer")
run_battery(t)
```

## C. Browser assistant (no scripting)
1. `python -m jinx run-sheet "<out-of-scope resource>"` -> `out/jinx_run_sheet.md`
2. Drive the vendor UI with a browser assistant in your own authorized session, one test at a time.
3. Record results in `engagements/<vendor>/index.md` and evidence files (`engagements/_template/`).

Every path uses the same scorer and the same catcher (`python -m jinx catcher new|hits|delete`).
See docs/CONNECTING.md for per-platform gotchas.
