#!/usr/bin/env python3
"""
Jinx -- AI-agent red-team. Run: python -m jinx <command>

  run --target FILE [what]   run against a target from a JSON config (examples/targets/)
        what: --test JX-05 | --all-tests (default) | --battery | --pack | --combos
              | --matrix [--limit N] | --cross-turn | --multiturn "GOAL" | --sandbox
        also: --oos TEXT --tool TEXT --authorized (confirm authorization non-interactively)
        --models a,b,c   run the same suite once per model and compare (config needs
                         "<<MODEL>>" or "model_path"; or a "models" list in the config)
  connect           choose how to reach the target (API / MCP / Browser / Claude-in-Chrome)
                    and scaffold a target config to use with `run`
  research VENDOR   scaffold engagements/VENDOR/research.md (AI surfaces, ATLAS attack
                    patterns, public precedents) to fill in before you simulate
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


def _require_authorization(t, args):
    from .testbed import MockAgent
    if isinstance(t, MockAgent):
        return
    if "--authorized" in args or os.environ.get("JINX_AUTHORIZED"):
        return
    name = getattr(t, "name", "this target")
    print("\n" + "=" * 70)
    print("AUTHORIZATION REQUIRED")
    print("Run Jinx only against a system you OWN or are EXPLICITLY authorized to")
    print("test (your own account/tenant, or a program with published safe harbor).")
    print("Unauthorized testing of someone else's agent may be illegal.")
    print("=" * 70)
    try:
        answer = input(f"Type 'yes' to confirm you are authorized to test {name!r}: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "yes":
        sys.exit("aborted: authorization not confirmed (use --authorized or JINX_AUTHORIZED=1 for non-interactive runs)")


def run(args):
    from . import harness, targets, catalog
    path = _opt(args, "--target")
    if not path:
        sys.exit("usage: python -m jinx run --target examples/targets/mock.json [--test JX-05 ...]")
    if not os.environ.get("JINX_NO_NOTE"):
        print(BETTER_WAY)
    t = targets.load(path)
    _require_authorization(t, args)
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
            tot = len(ids)
            print(f"=== {t.name}: {tot} ATLAS tests, in order ===")
            res = [harness.run_test(t, i, oos=oos, tool=tool, n=k, total=tot) for k, i in enumerate(ids, 1)]
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


CONNECT_MENU = (
    "How do you reach the target AI agent?\n"
    "  1) API (HTTP)           - the agent has a REST / chat API\n"
    "  2) MCP server           - the agent is exposed over the Model Context Protocol\n"
    "  3) Browser (Playwright) - script the vendor's web UI from the terminal\n"
    "  4) Claude in Chrome     - drive the vendor UI in YOUR logged-in browser (assisted)\n")

CONNECT_HELP = (
    "\n  1-4   pick how you reach the agent\n"
    "  h     show this help\n"
    "  b     go back to the menu (if you picked the wrong option)\n"
    "  q     quit connect (back to the shell)\n")


def _print_flow(choice, target=None):
    """Print the rest of the engagement, tailored to the transport. Every option ends at
    the report, so no path dead-ends after connect."""
    print("\n--- next, the rest of the engagement (every option ends at the HTML report) ---")
    print("  1. research the vendor:   jinx research <vendor>")
    print("       -> fills engagements/<vendor>/research.md (surfaces, ATLAS patterns, public vulns)")
    if choice == "4":
        print("  2. export the run sheet:  jinx run-sheet \"the resource you want it to reach\"")
        print("  3. drive each row in Claude in Chrome (steps above), and record each verdict:")
        print("       jinx log --target <name> --mode ui --cell JX-01 --verdict DEFENDED --why \"...\"")
        print("  4. build the report:      jinx report        -> out/jinx_report.html")
    else:
        print(f"  2. run it (asks you to confirm authorization first):")
        print(f"       jinx run --target {target}            # all 16 ATLAS tests")
        print(f"       jinx run --target {target} --pack     # + planted-content cells (--combos, --matrix, --cross-turn)")
        print("  3. build the report:      jinx report        -> out/jinx_report.html")
    print("\nAuthorization: only run against a target you own or are explicitly authorized to test.")


def connect():
    """Interactive: pick a transport, scaffold a target config (or show the Chrome guide),
    then print the whole flow through to the report. Loops so a wrong pick can go back."""
    print(BANNER)
    while True:
        print(CONNECT_MENU)
        try:
            choice = input("choose 1-4  (h=help, q=quit): ").strip().lower()
        except EOFError:
            return
        if choice in ("q", "quit", "exit"):
            print("bye.")
            return
        if choice in ("h", "help", "?"):
            print(CONNECT_HELP)
            continue
        if choice == "4":
            guide = os.path.join(_ROOT, "docs", "CLAUDE_IN_CHROME.md")
            print("\n" + (open(guide).read() if os.path.exists(guide) else "see docs/CLAUDE_IN_CHROME.md"))
            _print_flow("4")
        elif choice in ("1", "2", "3"):
            tmpl = {"1": "chat-api.example.json", "2": "mcp.example.json", "3": "browser.example.json"}[choice]
            name = (input("name this target file [my-target.json]: ").strip() or "my-target.json")
            if not name.endswith(".json"):
                name += ".json"
            shutil.copyfile(os.path.join(_ROOT, "examples", "targets", tmpl), name)
            hint = {
                "1": "Edit url / headers / body / answer_path. Keep the key in the shell: export TARGET_API_KEY=...",
                "2": "Edit command / tool / prompt_arg / answer_path. Any server env vars go in \"env\".",
                "3": "Edit url + the CSS selectors. First: pip install -e '.[browser]' && playwright install chromium",
            }[choice]
            print(f"\nwrote {name}\n{hint}")
            _print_flow(choice, name)
        else:
            print("  pick 1, 2, 3 or 4  (h = help, q = quit)")
            continue
        try:
            again = input("\npress Enter to finish, or 'b' to go back to the menu: ").strip().lower()
        except EOFError:
            return
        if again in ("b", "back"):
            print()
            continue
        return


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "info"
    if cmd in ("help", "-h", "--help"):
        print(BANNER + __doc__)
    elif cmd == "info":
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
    elif cmd == "connect":
        connect()
    elif cmd == "research" and len(args) > 1:
        from . import research
        print("wrote", research.generate(args[1], _ROOT))
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
