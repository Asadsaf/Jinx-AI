#!/usr/bin/env python3
"""
Jinx -- AI-agent red-team. Run: python -m jinx <command>

  run --target FILE [what]   run against a target from a JSON config (examples/targets/)
        what: --test JX-05 | --all-tests (default) | --battery | --pack | --combos
              | --matrix [--limit N] | --cross-turn | --multiturn "GOAL" | --sandbox
        also: --oos TEXT --tool TEXT
        --models a,b,c   run the same suite once per model and compare (config needs
                         "<<MODEL>>" or "model_path"; or a "models" list in the config)
  models BASE [--all]  compare models run against a target: counts + every cell they disagree on
                    (--all: every cell two or more models ran)
  log --target BASE [--model M] --mode MODE --cell KEY --verdict V --why TEXT
                    record a verdict from a UI / browser run (counts and model comparison use it)
  selftest          check the scoring against the local test agents (must pass first)
  diff A B          cell-by-cell difference between two targets' runs (from telemetry)
  engage new NAME   start engagements/NAME from the template
  bundle NAME       pack engagements/NAME into out/NAME_handoff.tar.gz for a report
  info              library stats
  catalog           the combined MITRE ATLAS tests and what each covers
  atlas             every ATLAS technique Jinx exercises (verified names + tactics)
  audit             prove nothing was dropped (every technique/family in one test)
  run-sheet [OOS]   export a browser run sheet -> out/jinx_run_sheet.md
  report            build the HTML report -> out/jinx_report.html
  status            verdict counts per target, from the telemetry log
  catcher new|hits|delete|serve
  cleanup [--apply]
  docs              list the playbooks in docs/
"""
import os
import shutil
import sys
import tarfile

from . import atlas, catalog, modifiers, techniques

BANNER = (
    "\n     _ _\n"
    "    | (_)_ __ __  __   Jinx -- AI-Agent Red-Team\n"
    " _  | | | '_ \\ \\/ /   put a hex on the agent\n"
    "| |_| | | | | |>  <    organized by MITRE ATLAS\n"
    " \\___/|_|_| |_/_/\\_\\\n"
)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def info():
    a = catalog.audit()
    nce = sum(1 for e in techniques.CORPUS if techniques.is_code_exec(e))
    print(BANNER)
    print(f"  combined ATLAS tests : {a['tests']}  (python -m jinx catalog)")
    print(f"  techniques           : {a['techniques']}  ({a['techniques'] - nce} chat-level, {nce} code-exec only)")
    print(f"  planted-content fams : {a['families']}")
    print(f"  framings / encodings : {a['framings']} / {a['encodings']}  (stack onto any test)")
    print(f"  full matrix          : {a['matrix_size']} generated variants (modifiers.build_taxonomy_matrix)")
    print(f"  stacked combos       : {len(modifiers.COMBOS)} x {a['families']} families = {len(modifiers.COMBOS) * a['families']}")
    print(f"  ATLAS version        : {atlas.ATLAS_VERSION}")
    print("  audit                : " + ("OK, nothing dropped" if not a["problems"] else "; ".join(a["problems"])))


def show_catalog():
    for tid, name, al, nt, nf, ce in catalog.describe():
        t = catalog.get(tid)
        print(f"{tid}  {name}{'  [code-exec only]' if ce else ''}")
        print(f"       ATLAS: {al}")
        if t["techniques"]:
            print(f"       techniques: {', '.join(t['techniques'])}")
        if t.get("families"):
            print(f"       planted-content: {', '.join(t['families'])}")
        if t.get("note"):
            print(f"       note: {t['note']}")


def show_atlas():
    used = {i for e in techniques.CORPUS for i in e.get("atlas", [])}
    used |= {i for t in catalog.TESTS for i in t["atlas"]}
    for v in modifiers.atlas_coverage().values():
        used |= {x.strip() for x in v.split(",")}
    for i in sorted(used):
        name, tac = atlas.ATLAS.get(i, ("?", []))
        print(f"{i:16s} {name}  [{', '.join(tac)}]")


def _opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


BETTER_WAY = """
  NOTE -- the better way to run a Jinx engagement:
  Open this repo in Claude Code with the Claude in Chrome extension and say
  "run jinx on <vendor>" (the jinx-engagement skill). It drives the vendor's own AI in your
  logged-in browser session, every surface (chat, search, agents, automations), plants the
  payloads in the vendor's content for indirect injection, checks the catcher, keeps one
  conversation for multi-turn tests, and writes the evidence, assessment and report.
  `jinx run` here sends prompts to one API endpoint only. Hide this note: JINX_NO_NOTE=1
"""


def run(args):
    from . import harness, targets, catalog
    path = _opt(args, "--target")
    if not path:
        sys.exit("usage: python -m jinx run --target examples/targets/mock.json [--test JX-05 ...]")
    if not os.environ.get("JINX_NO_NOTE"):
        print(BETTER_WAY)
    t = targets.load(path)
    oos, tool = _opt(args, "--oos", "the restricted resource"), _opt(args, "--tool", "your tools")

    def suite(t):
        if "--battery" in args:
            harness.run_battery(t, oos=oos, tool=tool)
        elif "--pack" in args or "--combos" in args or "--matrix" in args:
            kind = "pack" if "--pack" in args else "combos" if "--combos" in args else "matrix"
            lim = _opt(args, "--limit")
            res = harness.run_matrix(t, kind=kind, limit=int(lim) if lim else None)
            _tally([v for _c, v in res])
        elif "--cross-turn" in args:
            harness.run_cross_turn(t)
        elif "--multiturn" in args:
            harness.run_multiturn(t, _opt(args, "--multiturn", "make the agent reveal the canary"))
        elif "--sandbox" in args:
            harness.run_sandbox_chain(t, oos=oos, tool=tool)
        else:
            ids = [_opt(args, "--test")] if "--test" in args else [x["id"] for x in catalog.TESTS]
            res = [harness.run_test(t, i, oos=oos, tool=tool) for i in ids]
            _tally([r[0] for r in res if r])

    models = _opt(args, "--models")
    models = [m.strip() for m in models.split(",") if m.strip()] if models else getattr(t, "cfg", {}).get("models")
    if models:
        harness.run_model_sweep(t, models, suite)
    else:
        suite(t)
    from . import telemetry
    print(f"logged to {telemetry.PATH}  |  python -m jinx status  |  catcher: python -m jinx catcher hits")


def _tally(vs):
    c = {}
    for v in vs:
        c[v] = c.get(v, 0) + 1
    print("=== " + ", ".join(f"{k}={n}" for k, n in sorted(c.items())))


def engage_new(name):
    dst = os.path.join(_ROOT, "engagements", name)
    if os.path.exists(dst):
        sys.exit(f"{dst} already exists")
    shutil.copytree(os.path.join(_ROOT, "engagements", "_template"), dst)
    print("created", dst, "-- fill index.md; one evidence/E-NNN.md per proof")


def bundle(name):
    src = os.path.join(_ROOT, "engagements", name)
    if not os.path.isdir(src):
        sys.exit(f"no engagement {name}")
    os.makedirs(os.path.join(_ROOT, "out"), exist_ok=True)
    out = os.path.join(_ROOT, "out", f"{name}_handoff.tar.gz")
    skip = ("live", "__pycache__", ".env")
    with tarfile.open(out, "w:gz") as tar:
        for dp, dns, fns in os.walk(src):
            dns[:] = [d for d in dns if d not in skip]
            for fn in fns:
                if not fn.endswith((".py", ".env")) and ".env" not in fn:
                    full = os.path.join(dp, fn)
                    tar.add(full, arcname=os.path.join(name, os.path.relpath(full, src)))
        tar.add(os.path.join(_ROOT, "docs", "HACKERONE_TEMPLATE.md"), arcname=f"{name}/HACKERONE_TEMPLATE.md")
    print("wrote", out, "-- review it before it goes anywhere")


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "info"
    if cmd == "info":
        info()
    elif cmd == "catalog":
        show_catalog()
    elif cmd == "atlas":
        show_atlas()
    elif cmd == "audit":
        a = catalog.audit()
        print(a)
        sys.exit(1 if a["problems"] else 0)
    elif cmd == "run-sheet":
        from .harness import export_run_sheet
        oos = args[1] if len(args) > 1 else "the restricted resource"
        if not os.environ.get("JINX_NO_NOTE"):
            print(BETTER_WAY)
        print("wrote", export_run_sheet(path=os.path.join(_ROOT, "out", "jinx_run_sheet.md"), oos=oos))
    elif cmd == "report":
        from . import report
        print("wrote", report.write())
    elif cmd == "status":
        from . import telemetry
        s = telemetry.summary()
        if not s:
            print("no runs logged yet (out/telemetry.jsonl)")
        for target, counts in sorted(s.items()):
            print(f"{target}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    elif cmd == "catcher":
        sub = args[1] if len(args) > 1 else "hits"
        if sub == "serve":
            from . import catcher_server
            catcher_server.serve(args[2:])
        else:
            from . import catcher
            {"new": catcher.new, "hits": catcher.hits, "delete": catcher.delete}[sub]()
    elif cmd == "run":
        run(args[1:])
    elif cmd == "selftest":
        from . import testbed, telemetry
        telemetry.PATH = os.path.join(_ROOT, "out", "selftest_telemetry.jsonl")
        probs = testbed.selftest(verbose="-v" in args)
        print("selftest: OK -- scoring catches the vulnerable agent and clears both hardened ones"
              if not probs else "selftest FAILED:\n  " + "\n  ".join(probs))
        sys.exit(1 if probs else 0)
    elif cmd == "diff":
        from . import telemetry
        if len(args) < 3:
            sys.exit("usage: python -m jinx diff TARGET_A TARGET_B")
        only_a, only_b, changed = telemetry.diff(args[1], args[2])
        print(f"{len(changed)} cell(s) differ, {len(only_a)} only in {args[1]}, {len(only_b)} only in {args[2]}")
        for k, va, vb in changed:
            print(f"  {k:55s} {va:15s} -> {vb}")
    elif cmd == "models":
        from . import harness
        if len(args) < 2:
            sys.exit("usage: python -m jinx models BASE_TARGET")
        harness.print_model_matrix(args[1], show_all="--all" in args)
    elif cmd == "log":
        from . import telemetry
        base, model = _opt(args, "--target"), _opt(args, "--model")
        cell, verdict = _opt(args, "--cell"), _opt(args, "--verdict")
        if not (base and cell and verdict):
            sys.exit("usage: python -m jinx log --target BASE [--model M] --mode MODE --cell KEY --verdict V --why TEXT")
        tgt = f"{base}@{model}" if model else base
        mode = _opt(args, "--mode", "ui")
        telemetry.log("send", target=tgt, mode=mode, cell=cell, delivery="ui")
        print(telemetry.log("verdict", target=tgt, mode=mode, cell=cell, verdict=verdict.upper(),
                            why=_opt(args, "--why", "")))
    elif cmd == "engage" and len(args) > 2 and args[1] == "new":
        engage_new(args[2])
    elif cmd == "bundle" and len(args) > 1:
        bundle(args[1])
    elif cmd == "cleanup":
        from . import cleanup
        cleanup.main(args[1:])
    elif cmd == "docs":
        d = os.path.join(_ROOT, "docs")
        print("Jinx playbooks (docs/):")
        for f in sorted(os.listdir(d)):
            if f.endswith(".md"):
                print(f"  - docs/{f}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
