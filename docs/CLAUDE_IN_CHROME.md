# Connecting with Claude in Chrome

Use this when the target agent has **no API and no scriptable UI** you want to automate — you drive
the vendor's own AI in **your** logged-in browser session, and Claude operates the page for you.
This is the most flexible transport: it reaches chat, search, marketplace agents and automations that
a plain HTTP client can't.

> **Authorized testing only.** Your own account/tenant, or a program with published safe harbor.
> Claude acts as *you* in *your* session — it is not a bypass of the vendor's authentication.

## 1. Add Claude in Chrome
Pick one:
- **Claude Code:** start it with `claude --chrome` (same claude.ai account/org as the extension;
  claude.ai login, not an API key). It connects to the Claude for Chrome extension.
- **Claude desktop app:** Settings -> Customize -> Connectors -> enable **Claude in Chrome**.
- Install the **Claude for Chrome** extension if you don't have it, and sign in.

## 2. Open the target, logged in as yourself
In that Chrome, open the vendor's AI surface (chat / search / agent) and make sure you're on the
right account. Confirm the active account before you start — whatever is signed in is what gets tested.

## 3. Get the prompts from Jinx
```bash
python -m jinx connect        # choose option 4, or:
python -m jinx run-sheet "the out-of-scope resource you want it to reach"
```
`run-sheet` writes every probe to `out/jinx_run_sheet.md` (one prompt per check, with the ATLAS id,
the impact it tests, and a verdict slot).

## 4. Drive it
Hand the run sheet to Claude in Chrome and have it, for each row:
1. send the prompt in the agent (for **indirect** families, plant the payload in the vendor's own
   content first -- a doc, message, ticket -- then ask the agent about it);
2. read the reply, note any **action** the agent took (opened a PR, created a record, fetched a URL);
3. set the verdict by impact: **LEAK / RENDER-EXFIL / TERMINAL-ESCAPE / ACTION / DEFENDED** (a
   content-only refusal that merely names the secret is DEFENDED -- avoid false positives);
4. check the catcher for out-of-band fetches: `python -m jinx catcher hits`.

## 5. Record verdicts so the report and model-compare see them
```bash
python -m jinx log --target my-agent --mode ui --cell JX-01 --verdict DEFENDED --why "refused + flagged"
python -m jinx report          # out/jinx_report.html
```

In Claude Code, the `jinx-engagement` skill runs this whole routine for you: say
"run jinx on &lt;vendor&gt;" and it sets up the catcher, drives each surface, records verdicts, and
writes the evidence + report.
