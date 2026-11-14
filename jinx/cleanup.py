#!/usr/bin/env python3
"""Jinx teardown: remove what a run leaves behind on our side.

  python -m jinx cleanup            dry-run: show what WOULD be removed
  python -m jinx cleanup --apply    delete the catcher endpoint and local run state

Engagement-specific teardown (accounts, planted content, installed CLIs) lives with the
engagement: engagements/<vendor>/cleanup.py or the engagement's notes. Jinx never touches
credentials or anyone else's account.
"""
import glob
import os
import sys

from . import catcher

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv=None):
    apply = "--apply" in (argv or sys.argv[1:])
    print("== Jinx cleanup ==", "(APPLYING)" if apply else "(dry-run; pass --apply)")
    if os.path.exists(catcher.STATE):
        print(("APPLY " if apply else "WOULD ") + f"delete catcher endpoint ({catcher.url()})")
        if apply:
            try:
                catcher.delete()
            except Exception as e:  # noqa: BLE001
                print("   skipped:", e)
    else:
        print("no catcher state found")
    for name in ("jinx_run_sheet.md",):
        p = os.path.join(_ROOT, "out", name)
        if os.path.exists(p):
            print(("APPLY " if apply else "WOULD ") + f"remove {p}")
            if apply:
                os.remove(p)
    scripts = sorted(glob.glob(os.path.join(_ROOT, "engagements", "*", "cleanup.py")))
    if scripts:
        print("\nEngagement teardown scripts (run the one for your engagement):")
        for s in scripts:
            print("  ", os.path.relpath(s, _ROOT))
    print("\nKept on purpose: out/telemetry.jsonl (the run record) and engagements/ (results).")


if __name__ == "__main__":
    main()
