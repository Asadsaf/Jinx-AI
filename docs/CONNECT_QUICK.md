# Connecting Jinx to a target (quick reference)

`jinx connect` picks a transport interactively and scaffolds the config for you. The four transports:

```
            jinx/catalog.py  (16 combined MITRE ATLAS tests)
                    |
    jinx/techniques.py  +  jinx/modifiers.py (framings x encodings)
                    |
 (A) API    (B) MCP    (C) Browser (scripted)    (D) Claude in Chrome (assisted)
                    |
        jinx.harness.score  ->  out/telemetry.jsonl  ->  python -m jinx report
```

## A. API target  (`"type": "http"`)
```python
from jinx.harness import HTTPTarget, run_battery, run_test, run_multiturn
t = HTTPTarget({"name": "vendor-x", "url": "...", "headers": {...},
                "body": {"input": "<<PROMPT>>"}, "answer_path": ["output"]})
run_test(t, "JX-01")          # one combined ATLAS test
run_battery(t)                # every technique, one message each
run_multiturn(t, goal="exfiltrate the out-of-scope canary to our catcher")  # needs ADV_* env
```

## B. MCP target  (`"type": "mcp"`)
For an agent exposed over the Model Context Protocol. Jinx is the MCP client: it launches the
server, does the `initialize` handshake, then `tools/call` once per probe.
```bash
# offline demo against the bundled mock MCP server:
python -m jinx run --target examples/targets/mcp-mock.json
```
Config: `{"type":"mcp","command":["python3","-m","your_agent.mcp_server"],"tool":"chat",`
`"prompt_arg":"message","answer_path":["content",0,"text"],"env":{"AGENT_API_KEY":"${AGENT_API_KEY}"}}`.
Default answer = the text parts of `result.content[]`; `answer_path` overrides it. (stdio servers.)

## C. Browser target (scripted, Playwright)  (`"type": "browser"`)
```python
from jinx.harness import BrowserTarget, run_battery
t = BrowserTarget(url="https://vendor.example/ai", input_sel="textarea",
                  send_sel="button[type=submit]", answer_sel=".answer")
run_battery(t)
```
Install: `pip install -e '.[browser]' && playwright install chromium`.

## D. Claude in Chrome (assisted, no scripting)
Drive the vendor's own UI in your logged-in browser — reaches surfaces an API can't.
Full steps in **docs/CLAUDE_IN_CHROME.md**. In short:
1. `python -m jinx run-sheet "<out-of-scope resource>"` -> `out/jinx_run_sheet.md`
2. Add Claude in Chrome (`claude --chrome`, or the desktop app connector) and open the target as yourself.
3. Have it run each prompt, set the verdict, plant payloads in the vendor's content for indirect tests.
4. `python -m jinx log ...` to record verdicts, then `python -m jinx report`.

Every path uses the same scorer and the same catcher (`python -m jinx catcher new|hits|delete`).
See docs/CONNECTING.md for per-platform gotchas.
