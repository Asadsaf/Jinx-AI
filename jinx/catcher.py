#!/usr/bin/env python3
"""Our request catcher: an observable endpoint for the canary, so an out-of-band fetch is
seen in a log instead of assumed. Only the benign canary is ever sent here.

  python -m jinx catcher new      create an endpoint, save it to out/catcher.json
  python -m jinx catcher hits     list requests it received (ground truth)
  python -m jinx catcher delete   delete the endpoint

Backends:
  - self-hosted (preferred): set JINX_CATCHER_SELF=https://your-domain and JINX_CATCHER_KEY,
    and run `python -m jinx catcher serve` there (jinx/catcher_server.py);
  - otherwise a request-bin service at $JINX_CATCHER_API (default below).
State file: $JINX_CATCHER_STATE or out/catcher.json.
"""
import secrets
import json
import os
import sys
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = os.environ.get("JINX_CATCHER_API", "https://webhook.site").rstrip("/")
SELF = os.environ.get("JINX_CATCHER_SELF", "").rstrip("/")
KEY = os.environ.get("JINX_CATCHER_KEY", "")
STATE = os.environ.get("JINX_CATCHER_STATE", os.path.join(_ROOT, "out", "catcher.json"))


def _req(method, path, base=None):
    r = urllib.request.Request((base or API) + path, method=method, headers={"Accept": "application/json"})
    with urllib.request.urlopen(r, timeout=30) as resp:
        body = resp.read().decode()
        return json.loads(body) if body.strip() else {}


def _state():
    with open(STATE) as f:
        return json.load(f)


def url():
    """The catcher base URL, or None if none was created."""
    return _state()["url"] if os.path.exists(STATE) else None


def new():
    if SELF:
        tok = secrets.token_hex(8)
        st = {"uuid": tok, "url": f"{SELF}/{tok}", "self": SELF}
    else:
        tok = _req("POST", "/token")
        st = {"uuid": tok["uuid"], "url": f"{API}/{tok['uuid']}"}
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(st, f, indent=2)
    print("catcher url:", st["url"])
    return st["url"]


def hits(verbose=True):
    st = _state()
    if st.get("self"):
        rows = _req("GET", f"/_jinx/hits?token={st['uuid']}&key={KEY}", base=st["self"]).get("data", [])
    else:
        rows = _req("GET", f"/token/{st['uuid']}/requests?sorting=newest&per_page=50").get("data", [])
    if verbose:
        print(f"{len(rows)} hit(s) on {st['url']}")
        for h in rows:
            ua = (h.get("headers", {}).get("user-agent") or [""])[0]
            print(f"  {h.get('created_at')}  {h.get('method')} {h.get('url', '').replace(st['url'], '')}"
                  f"  ip={h.get('ip')}  ua={ua[:70]}")
    return rows


def delete():
    st = _state()
    if not st.get("self"):
        _req("DELETE", f"/token/{st['uuid']}")
    os.remove(STATE)
    print("deleted catcher", st["uuid"])


if __name__ == "__main__":
    {"new": new, "hits": hits, "delete": delete}[sys.argv[1] if len(sys.argv) > 1 else "hits"]()
