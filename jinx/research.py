"""`jinx research <vendor>`: scaffold a recon doc for a vendor's AI agents.

Auto-fills the generic parts -- the surfaces to map, the attack patterns Jinx runs (by MITRE
ATLAS, straight from the catalog), and public real-world precedents that look like what Jinx tests
-- and leaves the vendor-specific recon and the authorization check as blanks to fill (by you, or by
the jinx-engagement skill in Claude Code, which can research the vendor live).
"""
import os

from . import catalog

# Public, disclosed AI-agent vulnerabilities -- precedents that resemble what Jinx tests.
# All public (CVE / vendor advisory / published research); no private findings.
KNOWN_VULNS = [
    ("EchoLeak", "CVE-2025-32711", "Microsoft 365 Copilot",
     "zero-click indirect injection -> data exfil via rendered image/link (CSP bypass)"),
    ("CamoLeak", "CVE-2025-59145", "GitHub Copilot Chat",
     "injection in PR content -> private-repo exfil via the image proxy"),
    ("ForcedLeak", "-", "Salesforce Agentforce",
     "Web-to-Lead field injection -> CRM data exfil to an allowlisted domain"),
    ("Now Assist agent-to-agent", "CVE-2025-12420", "ServiceNow Now Assist",
     "a low-priv agent recruits a higher-priv agent to act/exfil"),
    ("Gemini Trifecta", "-", "Google Gemini (Cloud Assist / Search)",
     "injection via logs/history/search -> action + exfil"),
    ("Slack AI link exfil", "-", "Slack AI",
     "poisoned public message -> private-channel data via a rendered link"),
    ("Notion agent exfil", "-", "Notion AI",
     "hidden instruction in a shared doc -> web-tool exfil of workspace data"),
]


def generate(vendor, root):
    eng = os.path.join(root, "engagements", vendor)
    os.makedirs(os.path.join(eng, "evidence"), exist_ok=True)
    path = os.path.join(eng, "research.md")
    L = [f"# {vendor} — AI-agent attack-surface research", "",
         "> **Authorized testing only.** Your own account/tenant, or a program with published safe",
         "> harbor. Fill section 5 before running any simulation.", "",
         "## 1. AI surfaces to map (test each separately)",
         "- [ ] Primary chat / assistant",
         "- [ ] Grounded search / RAG over your data",
         "- [ ] Agents / marketplace agents",
         "- [ ] Automations / workflows / scheduled jobs",
         "- [ ] Connectors (and what data each exposes)",
         "- [ ] Code-executing surface, if any (enables the sandbox tests)", "",
         "## 2. Attack patterns Jinx will run (by MITRE ATLAS)"]
    for tid, name, al, _nt, _nf, ce in catalog.describe():
        L.append(f"- **{tid} {name}**{'  [code-exec only]' if ce else ''} — {al}")
    L += ["", "## 3. Real-world precedents (public) — look-alike vulns in other agents"]
    for nm, cve, tgt, note in KNOWN_VULNS:
        L.append(f"- **{nm}** ({cve}) — {tgt}: {note}")
    L += ["", "## 4. Vendor-specific recon (fill in)",
          f"- AI agents {vendor} ships: ______",
          "- Surfaces reachable on your plan/tier: ______",
          "- Tenancy / roles — who can see what: ______",
          "- Connectors available + data they expose: ______",
          "- Any surface that runs code or fetches URLs? ______",
          "- Bug-bounty / VDP + safe-harbor scope (link): ______", "",
          "## 5. Authorization (required before simulation)",
          "- [ ] I own this tenant, OR it is in scope under a published program with safe harbor.",
          "- Evidence / program link: ______", ""]
    with open(path, "w") as f:
        f.write("\n".join(L))
    return path
