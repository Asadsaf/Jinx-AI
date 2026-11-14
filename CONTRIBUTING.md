# Contributing to Jinx

Thanks for your interest. Jinx stays small and dependency-free on purpose — contributions
should keep it that way.

## Ground rules

- **No third-party runtime dependencies.** The core runs on the Python standard library
  (3.9+). Optional extras (`[browser]`, `[atlas]`) are the only exceptions, and they stay
  optional.
- **Every change must pass `jinx selftest` and `jinx audit`.** CI runs both on 3.9–3.12.
  - `selftest` proves the scoring rules still catch the vulnerable test agent and clear the
    hardened ones.
  - `audit` proves no technique or planted-content family was orphaned (every one maps into
    an ATLAS test).
- **New techniques are tagged with MITRE ATLAS ids** (`atlas=[...]`) and added to a test in
  `jinx/catalog.py`, so `audit` stays green.

## Dev setup

```bash
git clone https://github.com/Asadsaf/Jinx-AI.git && cd Jinx-AI
python3 -m pip install -e .
jinx selftest     # must say OK
jinx audit        # problems: [] 
```

## Making a change

1. Branch from `main`.
2. Make the change. If you add a technique or family, run `jinx audit` and fix any orphan.
3. Run `jinx selftest` and `jinx audit` locally.
4. Open a PR describing what you changed and why. The PR template has the sections.

## Scope

Jinx scores on **real impact** — data exfiltration, cross-tenant exposure, an unauthorized
or destructive action. A content-only jailbreak is not a finding. Keep new techniques aimed
at provable impact, not at "the model said a bad word."
