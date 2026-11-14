# Browser run (UI-only agents)

For agents with no API: a browser assistant (or a person) drives the vendor's own UI in our
authorized lab session, using the Jinx run sheet.

1. Start an engagement folder: copy `engagements/_template/` to `engagements/<vendor>/`.
2. `python -m jinx catcher new` -> put the catcher URL and a fresh canary in `index.md`.
3. `python -m jinx run-sheet "<out-of-scope resource>"` -> `out/jinx_run_sheet.md`
   (all techniques, grouped by combined ATLAS test).
4. For each test: deliver the probe (direct message or planted content), paste the answer,
   set the verdict (LEAK / RENDER-EXFIL / TERMINAL-ESCAPE / DEFENDED), check
   `python -m jinx catcher hits`.
5. Write one evidence file per real result (`evidence/E-NNN.md`); update the status table.
6. Teardown: `python -m jinx cleanup --apply`, then the engagement's own cleanup list.

Rules: own accounts and tenants only; only the canary ever goes to the catcher; a
content-only jailbreak is not a finding.
