"""Append-only run log (one JSON object per line), written by the harness, not the agent.

Every probe sent and every verdict lands here, so counts ("how many tests ran against
vendor X") come from the log instead of memory. Not meant to be loaded into an agent's
context; use it to audit and debug runs.
Path: $JINX_TELEMETRY or out/telemetry.jsonl
"""
import datetime
import json
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.environ.get("JINX_TELEMETRY", os.path.join(_ROOT, "out", "telemetry.jsonl"))


def log(event, **fields):
    rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(), "event": event, **fields}
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    with open(PATH, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def read(path=None):
    path = path or PATH  # resolved at call time, so a redirected PATH (selftest) is honoured
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def summary(path=None):
    """Verdict counts per target (each model of a sweep counts as its own target)."""
    out = {}
    for r in read(path):
        if r.get("event") != "verdict":
            continue
        t = out.setdefault(r.get("target", "?"), {})
        t[r.get("verdict", "?")] = t.get(r.get("verdict", "?"), 0) + 1
    return out


def cells(target, path=None):
    """Latest verdict per cell for one target: {mode:key -> verdict}. A cell is a combined
    test, a technique, or a modifier cell (family|framing|encoding)."""
    out = {}
    for r in read(path):
        if r.get("event") != "verdict" or r.get("target") != target:
            continue
        key = r.get("cell") or r.get("test") or r.get("technique")
        if r.get("turn"):
            key = f"{key or 'turn'}#{r['turn']}"
        out[f"{r.get('mode', 'battery')}:{key}"] = r.get("verdict", "?")
    return out


def diff(a, b, path=None):
    """Cell-by-cell comparison of two targets (or two runs logged under different names).
    Returns (only_a, only_b, changed) where changed = [(cell, verdict_a, verdict_b)]."""
    ca, cb = cells(a, path), cells(b, path)
    changed = [(k, ca[k], cb[k]) for k in sorted(ca.keys() & cb.keys()) if ca[k] != cb[k]]
    return sorted(ca.keys() - cb.keys()), sorted(cb.keys() - ca.keys()), changed


# ---------------------------------------------------------------- model comparison
# A model sweep logs each model as its own target named "<base>@<model>"
# (e.g. "my-agent@claude-haiku-4-5"), so every run stays separate and comparable.
def split_target(name):
    base, _, model = (name or "?").partition("@")
    return base, (model or None)


def models_for(base, path=None):
    """Every model that has verdicts logged under a base target name."""
    seen = []
    for r in read(path):
        b, m = split_target(r.get("target"))
        if r.get("event") == "verdict" and b == base and m and m not in seen:
            seen.append(m)
    return seen


def model_matrix(base, path=None):
    """{cell -> {model -> verdict}} for one base target, plus the ordered model list.
    Only the latest verdict per (model, cell) is kept."""
    models = models_for(base, path)
    matrix = {}
    for m in models:
        for cell, v in cells(f"{base}@{m}", path).items():
            matrix.setdefault(cell, {})[m] = v
    return models, matrix


def model_differences(base, path=None):
    """Cells that more than one model ran and where the verdicts disagree."""
    models, matrix = model_matrix(base, path)
    diff = {c: row for c, row in matrix.items() if len(row) > 1 and len(set(row.values())) > 1}
    return models, matrix, diff
