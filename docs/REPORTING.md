# Writing the report (and knowing if it's worth filing)

The template lives in `docs/HACKERONE_TEMPLATE.md`. This file is the judgement around it.

## The one rule
When a finding survives verification, **offer to write it up — ask first, don't auto-file** —
and write it **humanized**: first person, plain prose, the caveats worked into the text, not a
wall of AI-style bolded bullets. A report that reads like a person wrote it, that names its own
limits, and that cites prior art earns a triager's trust. An oversold one gets closed faster.

## Honesty is a tactic, not just ethics
- **Lead with control failures, not "the model followed the text."** GitHub (and MS) openly
  treat "the model obeyed injected text" as an AI limitation. Reframe as: a *scope* that isn't
  enforced, an *egress/allowlist* control that's missing on this surface, *silent* execution.
- **State the limits yourself** before the triager does: one-click vs zero-click, reliability
  fraction, "not a permissions bypass" if the victim could already read the data. Prove them —
  a live request-catcher with **0 hits** is strong evidence the exfil needs a click.
- **Cite prior art and state your delta.** "Same class as the published image-exfil CVEs (AML.T0077), but a new *surface*
  and a different *channel*, with the old channel confirmed closed." This pre-empts the dup close.
- **Don't inflate CVSS.** Use AT:Present for unreliability and UI:Active for a required click.

## Bounty economics we observed (set expectations honestly)
- **CVE-2025-59145** (CVSS 9.6, zero-click Copilot Chat exfil): paid **~$500**.
- A **one-click markdown-link** exfil equivalent was **rejected** by the vendor as insufficient
  severity / out of scope.
- A **Copilot CLI** injection (2026) was **validated but not paid** — behavior acknowledged,
  not classed as a vuln.
So: zero-click render/auto-fetch channels are the ones that pay; click-required and
terminal-escape variants are usually low/informative. Tell the user this before they spend a
trial report.

## What makes a finding actually strong (worth pushing for)
1. **Zero-click** — data leaves with no victim action (auto-fetched image, server-side tool
   fetch, link unfurl). Prove it with a catcher hit, not an assumption.
2. **Cross-user / realistic delivery** — the *victim* isn't the attacker: injection rides in a
   repo file (README/PR/issue) or a shared resource, and a *different* user's query triggers it.
3. **Action, not just read** — a write-capable agent (coding agent, autofixer) that can be made
   to open a PR, change a file, or run a step is higher impact than a read+link leak.
If a finding has none of these, it's probably low/informative — say so.

## Deliverables the tool can generate
- `python -m jinx report` → HTML report in `out/`.
- The HackerOne field values (Title/Asset/Weakness/CVSS/Description/Impact) per the template.
- A standalone finding write-up (markdown) for the researcher's own records.
Offer these; don't assume the user wants to file.
