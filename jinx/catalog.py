"""Jinx combined test catalog, organized by MITRE ATLAS.

Each TEST bundles related techniques from jinx/techniques.py (and planted-content
families from jinx/modifiers.py) that exercise the same ATLAS technique, so one run
covers what used to be several. Nothing is removed: every technique and every family
belongs to exactly one test (see audit()). Framings and encodings from
jinx/modifiers.py stack on top of any test.

Test ids are ours (JX-NN); ATLAS ids are verified against ATLAS 2026.10 (jinx/atlas.py).
An empty `atlas` list means ATLAS has no matching technique; that is stated, not hidden.
"""
from . import techniques as T
from . import modifiers as M
from .atlas import label as atlas_label

TESTS = [
    dict(id="JX-01", name="Response-rendering exfiltration", atlas=["AML.T0077", "AML.T0136"],
         techniques=["render-refstyle-image", "render-inline-image", "render-link"],
         families=["exfiltration/markdown-image", "exfiltration/markdown-link"]),
    dict(id="JX-02", name="Exfiltration through the agent's own tools", atlas=["AML.T0086", "AML.T0098"],
         techniques=["tool-fetch-exfil", "connector-secret-exfil"]),
    dict(id="JX-03", name="Trusted-context poisoning", atlas=["AML.T0110", "AML.T0051.001", "AML.T0093"],
         techniques=["tool-description-poison", "metadata-field-injection"]),
    dict(id="JX-04", name="Retrieval scope bypass", atlas=["AML.T0085.000"],
         techniques=["scope-override", "cross-workspace-search"],
         families=["escalation/scope-probe"]),
    dict(id="JX-05", name="Unauthorized agent action", atlas=["AML.T0053"],
         techniques=["unrequested-write", "content-triggered-action", "bola", "bfla", "rbac"],
         families=["action/create-task"],
         note="bola/bfla/rbac are app-layer authorization checks; ATLAS has no dedicated technique, nearest is AML.T0053"),
    dict(id="JX-06", name="Destructive action", atlas=["AML.T0101"],
         techniques=["destructive-op"]),
    dict(id="JX-07", name="Injected phishing content", atlas=["AML.T0052", "AML.T0051.001"],
         techniques=[], families=["content-injection/phishing"]),
    dict(id="JX-08", name="Agent discovery (system prompt + tools)", atlas=["AML.T0069.002", "AML.T0133", "AML.T0084.001"],
         techniques=["sysprompt-exfil", "enumerate-tools"]),
    dict(id="JX-09", name="Hidden-context collection", atlas=["AML.T0137.003", "AML.T0085.002"],
         techniques=["divergence-repeat", "prev-session"]),
    dict(id="JX-10", name="Evasion primitives", atlas=["AML.T0054", "AML.T0068"],
         techniques=["config-framing", "hidden-unicode"]),
    dict(id="JX-11", name="Hallucinated dependency", atlas=["AML.T0062", "AML.T0060"],
         techniques=["pkg-hallucination"]),
    dict(id="JX-12", name="Backend command injection", atlas=["AML.T0050"],
         techniques=["sql-shell"], note="shell part maps to AML.T0050; ATLAS has no SQL-injection technique"),
    dict(id="JX-13", name="Output control-sequence injection", atlas=[],
         techniques=["ansi-raw"], note="no ATLAS technique; nearest is AML.T0077"),
    dict(id="JX-14", name="Sandbox reconnaissance", atlas=["AML.T0084", "AML.T0097"],
         techniques=["recon-situational"], code_exec=True),
    dict(id="JX-15", name="Sandbox escape", atlas=["AML.T0105", "AML.T0081"],
         techniques=["trust-handoff", "config-self-widen", "writable-mount-socket", "priv-esc"], code_exec=True),
    dict(id="JX-16", name="Sandbox pivot and persistence", atlas=["AML.T0055", "AML.T0097", "AML.T0105"],
         techniques=["metadata-ssrf-pivot", "cross-sandbox", "persistence-lateral"], code_exec=True),
]


def get(test_id):
    for t in TESTS:
        if t["id"] == test_id:
            return t
    raise KeyError(test_id)


def tests(include_code_exec=True):
    return [t for t in TESTS if include_code_exec or not t.get("code_exec")]


def audit():
    """Prove nothing was dropped: every technique and family appears in exactly one test."""
    tech = [i for t in TESTS for i in t["techniques"]]
    fams = [f for t in TESTS for f in t.get("families", [])]
    all_tech = [e["id"] for e in T.CORPUS]
    problems = []
    for i in all_tech:
        if tech.count(i) != 1:
            problems.append(f"technique {i} appears {tech.count(i)}x")
    for i in tech:
        if i not in all_tech:
            problems.append(f"unknown technique {i}")
    for f in M.FAMILIES:
        if fams.count(f) != 1:
            problems.append(f"family {f} appears {fams.count(f)}x")
    return {"tests": len(TESTS), "techniques": len(all_tech), "families": len(M.FAMILIES),
            "framings": len(M.FRAMINGS), "encodings": len(M.ALL_ENCODINGS),
            "matrix_size": len(M.FAMILIES) * len(M.FRAMINGS) * len(M.ALL_ENCODINGS),
            "problems": problems}


def bundle(test_id, oos="the restricted resource", tool="your tools"):
    """The member probes of one test, ready to send together (direct delivery).
    Returns (combined_text, [(technique_id, prompt), ...])."""
    t = get(test_id)
    prompts = {e: p for e, _f, p, _a, _i in T.for_target(oos=oos, tool=tool)}
    parts = [(i, prompts[i]) for i in t["techniques"]]
    combined = "\n\n".join(f"({n}/{len(parts)}) {p}" for n, (_i, p) in enumerate(parts, 1))
    return combined, parts


def describe():
    rows = []
    for t in TESTS:
        rows.append((t["id"], t["name"], atlas_label(t["atlas"]),
                     len(t["techniques"]), len(t.get("families", [])), bool(t.get("code_exec"))))
    return rows
