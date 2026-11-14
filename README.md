# Jinx -- AI-Agent Red-Team

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%202026.10-8A2BE2)](https://atlas.mitre.org/)

*put a hex on the agent.*  ·  by **0xAsad**

Jinx tests whether an AI agent or assistant can be made to leak data, cross a tenant boundary,
or take an unauthorized action. Every test is organized by **MITRE ATLAS** (verified against
ATLAS 2026.10). One library, one scorer, one report, across any transport.

> **Authorized testing only.** Your own accounts and tenants, or programs with published safe
> harbor. A content-only jailbreak is **not** a finding: Jinx scores on real impact.
> Every non-mock `jinx run` asks you to confirm authorization before it sends a single probe
> (bypass for scripts: `--authorized` or `JINX_AUTHORIZED=1`). Unauthorized testing of
> someone else's agent may be illegal.

## Layout
```
jinx/                the tool
  catalog.py         16 combined ATLAS tests (JX-01..JX-16); audit() proves nothing was dropped
  techniques.py      32 techniques (24 chat-level, 8 code-exec only), each tagged with ATLAS ids
  modifiers.py       5 planted-content families, 14 framings, 15 encodings, 7 combos, cross-turn
  atlas.py           ATLAS names + tactics, generated from MITRE's official data
  harness.py         targets (API / browser) and runners; rule-based scoring
  targets.py         load a target from a JSON config (examples/targets/)
  testbed.py         local test agents (vulnerable / hardened / hardened-quoting) for selftest
  telemetry.py       append-only run log -> out/telemetry.jsonl (counts + cell diff come from here)
  catcher.py         request catcher client (ground truth for out-of-band fetches)
  catcher_server.py  self-hosted catcher for a domain we own
  report.py          HTML report -> out/jinx_report.html
  cleanup.py         teardown of our run state
examples/targets/    target configs: chat API, browser UI, local mock
.claude/skills/      jinx-engagement: the full per-vendor routine for Claude Code
pyproject.toml       `pip install -e .` gives a `jinx` command
docs/                playbooks (connect, expand, sandbox, report, HackerOne template)
engagements/_template  copy this to start your own engagement (assessment + evidence/E-NNN.md)
out/                 generated run state + reports (gitignored)
```

## Install and use (terminal)
Jinx is a plain Python command-line tool (Python 3.9+, no third-party engine). Claude is not
required to run it.
```bash
git clone https://github.com/Asadsaf/Jinx-AI.git && cd Jinx-AI
python3 -m pip install -e .          # adds the `jinx` command (or use `python3 -m jinx` without installing)
jinx selftest                        # scoring check against local test agents; must say OK
jinx info                            # library stats + audit
```
Run against a target:
```bash
jinx connect                                                # 1. choose API / MCP / Browser / Claude-in-Chrome, scaffold a config
jinx research my-vendor                                      # 2. scaffold engagements/my-vendor/research.md (surfaces, ATLAS patterns, public vulns)
cp examples/targets/chat-api.example.json my-target.json    # or copy a template yourself
export TARGET_API_KEY=...                                   # secrets stay in the shell, never in the file
jinx catcher new                                            # endpoint for out-of-band fetches
jinx run --target my-target.json                            # 3. confirm authorization, then run all 16 ATLAS tests
jinx run --target my-target.json --pack                     # 30 planted-content cells (--combos 35, --matrix 1050)
jinx run --target my-target.json --cross-turn               # split payload over 3 turns of one conversation
jinx catcher hits                                           # ground truth
jinx status                                                 # verdict counts, from the telemetry log
jinx diff my-agent other-agent                              # cell-by-cell difference between two targets
jinx report                                                 # 4. out/jinx_report.html (live verdicts + every check that ran)
```
**Multi-turn over an API** (`--cross-turn`, `--multiturn "GOAL"`, `--sandbox`) needs the target to
remember earlier turns. Add a `conversation` block to the config:
`{"mode": "messages", "path": ["messages"]}` when the API wants the full history each time
(see `examples/targets/chat-api.example.json`), or
`{"mode": "id", "response_path": [...], "request_field": "..."}` (or `"request_header"`) when it
returns a conversation id (`chat-api-thread-id.example.json`). Without it every turn is a new
chat, and multi-turn results are marked INVALID instead of DEFENDED.

**Model sweep** (does the result depend on the model behind the agent?):
```bash
jinx run --target my-target.json --models model-a,model-b,model-c --pack   # same suite, once per model
jinx models my-agent              # verdict counts per model + every cell where they disagree (--all: all shared cells)
```
The config marks where the model goes: `"<<MODEL>>"` anywhere in url/headers/body, or
`"model_path": ["model"]`, or a default `"models": [...]` list. Each model is logged as its own
target `my-agent@<model>`. For UI-only platforms where the model is chosen vendor-side (an agent
per model, as on Snowflake), record each verdict with
`jinx log --target my-agent --model <model> --mode <mode> --cell <key> --verdict DEFENDED --why "..."`
and `jinx models my-agent` compares them the same way.

**The better way:** `jinx run` reaches one API endpoint. For a full engagement, open the repo
in Claude Code with the Claude in Chrome extension and say "run jinx on <vendor>": the
`jinx-engagement` skill drives the vendor's own UI in your logged-in session across every
surface, plants payloads for indirect injection, checks the catcher and writes the evidence.
`jinx run` and `jinx run-sheet` print this note (hide it with `JINX_NO_NOTE=1`).

Four ways to reach a target — `jinx connect` picks one interactively and scaffolds the config
(docs/CONNECT_QUICK.md):
- **API** (`"type": "http"`): fully automated from the terminal.
- **MCP** (`"type": "mcp"`): the agent is exposed over the Model Context Protocol; Jinx is the MCP
  client and calls its tool once per probe. Try it offline: `jinx run --target examples/targets/mcp-mock.json`.
- **Browser, scripted** (`"type": "browser"`, `pip install -e '.[browser]'` then `playwright install chromium`):
  opens the vendor UI, you log in once, Jinx types and reads the answers.
- **Claude in Chrome** (assisted): drive the vendor's own UI in your logged-in browser — the most
  flexible transport, it reaches surfaces an API can't. Full steps: **docs/CLAUDE_IN_CHROME.md**. In
  Claude Code the `jinx-engagement` skill runs the whole routine ("run jinx on &lt;vendor&gt;").

Other commands: `jinx catalog`, `jinx atlas`, `jinx engage new <vendor>`, `jinx bundle <vendor>`,
`jinx catcher serve` (self-hosted catcher), `jinx cleanup [--apply]`, `jinx docs`.

### Verdicts
LEAK (canary in live markup, or a canary the agent could only get from its own data) /
RENDER-EXFIL / TERMINAL-ESCAPE / ECHO (canary only quoted back; check the catcher) / DEFENDED /
INVALID (multi-turn run against a target that forgets earlier turns).
Code in backticks is ignored, since it never renders. `jinx selftest` proves these rules on
known-vulnerable and known-hardened agents before any vendor run.

### Catcher on our own domain
Some agents refuse to fetch well-known request-bin domains on reputation alone, which leaves
the result inconclusive. Run `jinx catcher serve --port 8080` on a host behind a plain domain
we own, then set `JINX_CATCHER_SELF=https://that-domain` and `JINX_CATCHER_KEY=<printed key>`
where Jinx runs. Without them Jinx uses the request-bin service at `JINX_CATCHER_API`.

## How a test is built
technique (what to make the agent do) -> framing (how it is asked) -> encoding (how it is hidden)
-> delivery (direct message or planted content). `jinx/catalog.py` bundles related techniques
under one ATLAS test so one run covers what used to take several.

## Connect (4 ways) -- `jinx connect` chooses one and scaffolds a config; see docs/CONNECT_QUICK.md
- **A. API** (`HTTPTarget`) -- automated, for agents with an API.
- **B. MCP** (`MCPTarget`) -- for agents exposed over the Model Context Protocol.
- **C. Browser, scripted** (`BrowserTarget`, Playwright) -- for UI-only agents.
- **D. Claude in Chrome** -- drive the vendor UI in your own logged-in session; see docs/CLAUDE_IN_CHROME.md.

## Teardown
`python -m jinx cleanup --apply` deletes our catcher and local run state. Engagement-specific
teardown (planted content, test accounts, installed CLIs) lives in `engagements/<vendor>/`.
Jinx never touches credentials or anyone else's account.

## Status
Beta, open-source. The technique library is organized by MITRE ATLAS and proven by `jinx selftest`
against the bundled local test agents (`jinx/testbed.py`) before any run. Techniques are derived from
public prompt-injection research and CVEs. Run Jinx only against systems you own or are explicitly
authorized to test.
