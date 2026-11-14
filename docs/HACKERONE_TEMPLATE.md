# HackerOne submission template (GitHub program) — field by field

Everything below is what the real submission form wants, with the exact structure,
the length limits, the CVSS 4.0 mapping, and the one rule that matters most:

> **When Jinx finds something reportable, OFFER to generate this — do not auto-file —
> and write it in a humanized, first-person researcher voice (see `docs/REPORTING.md`).**

The assistant drafts; the human verifies identity, attaches evidence, and clicks Submit.

---

## Form fields, in order

### Title
- Short. The form clips long titles — keep it well under ~90 characters / ~12 words.
- Pattern: `<bug class> in <surface> <one-line effect>`.
- Example: `Indirect prompt injection in Copilot Spaces leaks out-of-scope repo files via a click-link`

### Asset
- Pick the specific product asset, not "Other", or it may be closed out of scope.
- If the form shows `<Product> (OTHER)`, let HackerOne's assistant ("Hai") search and set the
  real asset — a wrong/unmatched asset is a common auto-reject. Verify it's bounty-eligible.

### Weakness (dropdown)
- Prefer the agentic-AI option when the form offers it: **`ASI01: Agent Goal Hijack`** is the
  right class for indirect prompt injection that hijacks an agent. Put the ATLAS ids from
  `python -m jinx catalog` (e.g. AML.T0051.001 + AML.T0077) in the description.
- If that's not offered, fall back to `Improper Access Control - Generic (CWE-284)` or
  `Information Disclosure (CWE-200)`. (CWE-1427 = "Improper Neutralization of Input Used for an
  LLM Prompt" is the precise CWE if the dropdown has it.)

### Severity (CVSS 4.0 — the GitHub form uses 4.0, not 3.1)
Set the buttons; the vector + score build themselves. For a one-click, ~1/3-reliable,
read-a-private-file injection-exfil, an honest mapping is:

| Metric | Value | Why |
|---|---|---|
| Attack Vector (AV) | Network | reachable over the web |
| Attack Complexity (AC) | Low | no mitigation bypass needed |
| Attack Requirements (AT) | **Present** | success depends on the model router / setup (~1 in 3) |
| Privileges Required (PR) | None | attacker just lands content in a source |
| User Interaction (UI) | **Active** | victim asks a question *and* clicks the link |
| Vulnerable Sys Confidentiality (VC) | **High** | private repo file contents |
| VI / VA | None | |
| Subsequent SC / SI / SA | None | avoid double-counting the exfil |

Vector: `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` → ~**5.9 Medium**.
Do not raise AT to None or UI to Passive just to inflate the score — overrating gets flagged.

### Description box (uses its own template — keep the two headers)
```
## Description:

<first-person prose: what you noticed, what you got it to do, and WHY it's a product
 issue not "the model followed text" — list the concrete control failures. Then an
 "upfront about the limits" paragraph: one-click vs zero-click, what the catcher showed,
 reliability, not-a-permissions-bypass. Then the realistic attacker/delivery model.>

## Steps To Reproduce:

1. <step>              <- the form renders repeated "1." as 1,2,3...
1. <step>
1. <step>
```

### Impact box (separate field — do NOT leave it only in Description)
```
<2–3 short paragraphs: who loses what and how; the realistic delivery (repo file / shared
 space / PR); then "for completeness" acknowledge prior art (CVEs) and state your delta
 (surface + channel); then the remediation in one sentence.>
```

### Attachments
- At least one screenshot that shows the whole chain in one frame (the tool call reading the
  out-of-scope file **and** the rendered exfil link). Add the source/injection and the target
  file as supporting shots.

---

## Before Submit becomes clickable
1. **Verify identity** — the red banner blocks submission until done.
2. **Run checks** (HackerOne's "Hai" pre-submission review). Learnings:
   - It suggests a better **Weakness** (took us from CWE-284 → `ASI01: Agent Goal Hijack`).
   - It flags **Asset** not matching scope — let it set the real asset.
   - "Asset recommendation" staying non-blocking after Hai set the asset is fine.
3. **Signal Requirement / trial reports:** new accounts have a small number of trial reports and
   a Signal score; an Informative/N/A close dents signal. Don't spend one on a weak finding.
4. Swap any real catcher URL for a neutral placeholder (`https://attacker.example/?d=DATA`)
   unless you want the triager to confirm a hit themselves.

## Known ineligible / likely-closed (GitHub)
The form lists these as ineligible — don't frame your report as one of them: HTML in Markdown
fields, email leaks via `.patch`, clickjacking a static site, host-header injection, email
verification policy, homoglyph/RTLO phishing. And GitHub openly debates "prompt-injection =
vuln vs AI limitation", so lead with concrete **control failures**, not "the model obeyed text".
