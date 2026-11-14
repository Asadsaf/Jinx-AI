# <vendor> -- <surface>  (Jinx engagement)

Copy this folder to `engagements/<vendor>/` at the start of an engagement.
This file is the **current assessment**. Raw proof goes in `evidence/E-NNN.md`, one clean
reproduction per file. Never mix the two.

## Scope
- Target / surface:
- Account(s) (your own / lab only):
- Authorization (program / VDP / own tenant):
- Catcher: `python -m jinx catcher new` -> url:
- Canary:

## Status per combined ATLAS test (`python -m jinx catalog`)
| Test | Result | Evidence | Note |
|---|---|---|---|
| JX-01 Response-rendering exfiltration | | | |
| JX-02 Exfiltration through the agent's own tools | | | |
| JX-03 Trusted-context poisoning | | | |
| JX-04 Retrieval scope bypass | | | |
| JX-05 Unauthorized agent action | | | |
| JX-06 Destructive action | | | |
| JX-07 Injected phishing content | | | |
| JX-08 Agent discovery | | | |
| JX-09 Hidden-context collection | | | |
| JX-10 Evasion primitives | | | |
| JX-11 Hallucinated dependency | | | |
| JX-12 Backend command injection | | | |
| JX-13 Output control-sequence injection | | | |
| JX-14..16 Sandbox (code-executing targets only) | | | |
| Modifier sweep (framings x encodings) | | | sample or full 1050 -- say which |

Result values: DEFENDED / FINDING / INCONCLUSIVE / HELD (infra line) / N/A (no surface).
Counts come from `python -m jinx status` (the telemetry log), not from memory.

## Findings (report / hold / refute)
For each candidate: claim, **confidence** (how well it holds up) kept separate from
**severity** (impact actually demonstrated), decision, and the evidence file.

## Next action
-

## Cleanup
- [ ] `python -m jinx cleanup --apply` (catcher + local state)
- [ ] engagement-specific teardown (planted content, test accounts)
