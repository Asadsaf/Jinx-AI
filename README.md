# Jinx — AI-Agent Red-Team

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%202026.10-8A2BE2)](https://atlas.mitre.org/)

> *put a hex on the agent.* — by **0xAsad**

**Jinx tests whether an AI agent can be made to leak data, cross a tenant boundary, or take an
unauthorized action.** One technique library organized by [MITRE ATLAS](https://atlas.mitre.org/)
(2026.10), one scorer that gates on **real impact** — a content-only jailbreak is *not* a finding —
and one HTML report, across any transport: **API, MCP, browser, or Claude-in-Chrome**.

> ⚠️ **Authorized testing only.** Test your own agents and tenants, or a program with published
> safe harbor. Every real run asks you to confirm authorization before it sends a single probe.
> Unauthorized testing of someone else's agent may be illegal.

---

## Install

Pure Python 3.9+, **no dependencies**.

```bash
git clone https://github.com/Asadsaf/Jinx-AI.git && cd Jinx-AI
pipx install --editable .        # recommended — puts `jinx` on your PATH
```
*Alternatives:* `pip install -e .` (pip ≥ 21.3), or zero-install `python3 -m jinx <command>`.

```bash
jinx selftest     # scoring sanity-check — must say OK
jinx info         # 16 tests · 32 techniques · 1050-variant matrix
```

**Try it instantly** against the built-in mock agent (no setup, no target):
```bash
jinx run --target examples/targets/mcp-mock.json --authorized --escalate
jinx report       # → out/jinx_report.html
```

---

## The flow

```
   connect  →  research  →  run  →  report
```

```bash
jinx connect            # 1. pick a transport, scaffold + TEST the connection
jinx research <vendor>  # 2. draft attack-surface notes to fill in before you run
jinx run --target T     # 3. confirm authorization, run the ATLAS tests
jinx report             # 4. → out/jinx_report.html (verdicts + every check that ran)
```

`connect` is an **orchestrator**, not a menu: it scaffolds the config, **tests the connection**
(shows the real call, and tells you if the agent is unreachable, erroring, or returning nothing —
i.e. the techniques can't run), and on a green check runs the suite and builds the report for you.

---

## 4 ways to connect

| # | Transport | Use when | How it works |
|---|-----------|----------|--------------|
| 1 | **API (HTTP)** | the agent has a REST / chat API | fully automated from the terminal |
| 2 | **MCP** | the agent speaks Model Context Protocol | Jinx is the MCP client, calls its tool once per probe |
| 3 | **Browser** | a UI-only agent | scripted (Playwright) **or** manual copy-paste |
| 4 | **Claude in Chrome** ⭐ | anything — reaches surfaces an API can't | Claude drives the vendor's UI in *your* logged-in session |

Secrets stay in env vars (`${API_KEY}`), never in the config file. Saved connections live in
`targets/` — list them any time with **`jinx targets --check`** (shows which are LIVE).

> **💡 For the best results, use option 4 (Claude in Chrome) or add `--judge`.** The rule-based
> scorer is accurate, deterministic and free — but the LLM judge catches subtle semantic cases,
> and the Chrome path reaches surfaces (agents, search, automations) a single API can't.

---

## Run modes

| Command | What it does |
|---------|--------------|
| `jinx run --target T` | all 16 ATLAS tests, in order |
| `… --pack` / `--combos` / `--matrix` | 30 / 35 / 1050 planted-content variants |
| `… --cross-turn` | split a payload across 3 turns of one conversation |
| `… --escalate` | adaptive pressure ladder — climbs low → high, stops at first hit |
| `… --judge` | LLM second opinion on ambiguous verdicts *(recommended)* |
| `… --models a,b,c` | run once per model, then `jinx models T` compares them cell-by-cell |
| `jinx manual --target T` | copy-paste flow: you run each prompt in the UI, paste the reply, Jinx scores it |

**Verdicts:** `LEAK` · `RENDER-EXFIL` · `TERMINAL-ESCAPE` · `ECHO` (quoted back — not proof) ·
`DEFENDED` · `INVALID`. Code in backticks is ignored (it never renders). Scoring is deterministic
and proven by `jinx selftest` on known-vulnerable and known-hardened agents before any real run.

### LLM judge (optional, recommended)
A second opinion on the **ambiguous** cases — **off by default, and it never downgrades a proven hit.**
```bash
export JUDGE_BASE_URL=... JUDGE_MODEL=... JUDGE_API_KEY=...   # any chat-completions endpoint (or reuse ADV_*)
jinx run --target T --judge      # judge ambiguous verdicts
jinx report --judge              # + an analyst wrap-up in the report
```
The rules are the floor; the LLM is the amplifier. The 1050-cell matrix stays rule-based.

---

## Reporting a vulnerability

A confirmed Jinx finding has **proven impact** — a leak, cross-tenant exposure, or an unauthorized
action — not just a jailbroken reply. Report it **responsibly to the vendor that owns the agent**,
and never publicly first. Common channels:

- **Bug-bounty / VDP platforms** — [HackerOne](https://hackerone.com), [Bugcrowd](https://bugcrowd.com),
  [Intigriti](https://intigriti.com), [YesWeHack](https://yeswehack.com), if the vendor runs one.
- **The vendor's security contact** — `security@<vendor>`, or the address in their
  [`/.well-known/security.txt`](https://securitytxt.org/).
- **Coordinated disclosure** — give the vendor time to fix before going public; request a CVE if warranted.

Jinx ships a ready report template at **`docs/HACKERONE_TEMPLATE.md`** (adapt it for any channel), and
`jinx bundle <vendor>` packs your engagement evidence into one handoff archive. Always include:
**impact, CVSS, reproduction steps, and the evidence** (the report + catcher hits).

---

## Reference

<details>
<summary><b>More commands</b></summary>

```
jinx targets [--check]     list saved connections (and ping them)
jinx catalog | atlas       the ATLAS tests / every technique + tactics
jinx catcher new|hits      out-of-band fetch endpoint + ground truth
jinx diff A B              cell-by-cell difference between two targets
jinx engage new <vendor>   start an engagement from the template
jinx bundle <vendor>       pack an engagement into a handoff archive
jinx run-sheet "<oos>"     export a manual run sheet (for UI runs)
jinx cleanup [--apply]     tear down local run state
jinx docs                  list the playbooks in docs/
```
</details>

<details>
<summary><b>Advanced: multi-turn & a self-hosted catcher</b></summary>

**Multi-turn** (`--cross-turn`, `--escalate`, `--multiturn "GOAL"`, `--sandbox`) needs the target to
remember earlier turns. Add a `conversation` block to the config: `{"mode":"messages","path":["messages"]}`
when the API wants the whole history each time, or `{"mode":"id","response_path":[...],"request_field":"..."}`
when it returns a conversation id. Without it, every turn is a fresh chat and results are marked `INVALID`.

**Catcher on your own domain** — some agents refuse well-known request-bin domains. Run
`jinx catcher serve --port 8080` behind a plain domain you own, then set `JINX_CATCHER_SELF` and
`JINX_CATCHER_KEY` where Jinx runs. Otherwise Jinx uses the request-bin at `JINX_CATCHER_API`.
</details>

<details>
<summary><b>Repo map</b></summary>

```
jinx/              the tool (catalog, techniques, modifiers, harness, report, …)
examples/targets/  ready configs: chat API, MCP, browser, local mock
targets/           your saved connections (git-ignored)
engagements/       per-engagement evidence (start from _template/)
docs/              playbooks + the vulnerability-report template
out/               generated reports + run log (git-ignored)
```
</details>

**For a full engagement**, open the repo in Claude Code with the Claude-in-Chrome extension and say
*"run jinx on &lt;vendor&gt;"* — the `jinx-engagement` skill drives every surface, plants payloads for
indirect injection, checks the catcher, and writes the evidence.

---

**License** [MIT](LICENSE) · **Status** Beta · Techniques derived from public prompt-injection
research and CVEs. Run Jinx only against systems you own or are explicitly authorized to test.
