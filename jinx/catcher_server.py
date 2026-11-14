"""Self-hosted catcher: run it on any host and domain you control.

Why: some agents refuse to fetch well-known request-bin domains by reputation alone, which
makes the result inconclusive (was it the domain or the model?). A plain domain of your own
removes that variable.

  python -m jinx catcher serve [--port 8080] [--host 0.0.0.0]

Put it behind HTTPS on your own domain (any reverse proxy or tunnel), then on the machine
that runs Jinx:
  export JINX_CATCHER_SELF=https://your-domain.example
  export JINX_CATCHER_KEY=<the key printed by serve>
  python -m jinx catcher new | hits | delete

Every request to /<token>/... is answered with a 1x1 PNG (so image renders resolve) and
appended to out/catcher_hits.jsonl. Hits are read back at /_jinx/hits?token=..&key=..
"""
import base64
import datetime
import json
import os
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.environ.get("JINX_CATCHER_LOG", os.path.join(_ROOT, "out", "catcher_hits.jsonl"))
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
KEY = os.environ.get("JINX_CATCHER_KEY") or secrets.token_urlsafe(18)


def _read(token):
    if not os.path.exists(LOG):
        return []
    with open(LOG) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    return [r for r in rows if r.get("token") == token][::-1]


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def _hit(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/_jinx/hits":
            q = urllib.parse.parse_qs(u.query)
            if q.get("key", [""])[0] != KEY:
                return self._send(403, b"forbidden", "text/plain")
            body = json.dumps({"data": _read(q.get("token", [""])[0])}).encode()
            return self._send(200, body, "application/json")
        token = u.path.strip("/").split("/")[0]
        n = int(self.headers.get("Content-Length") or 0)
        rec = {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "token": token, "method": self.command, "url": self.path,
               "ip": self.headers.get("X-Forwarded-For", self.client_address[0]),
               "headers": {k.lower(): [v] for k, v in self.headers.items()},
               "body": self.rfile.read(n).decode("utf-8", "replace")[:4000] if n else ""}
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"HIT {rec['created_at']} {self.command} {self.path} ip={rec['ip']}", flush=True)
        self._send(200, PNG, "image/png")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _hit

    def log_message(self, *a):
        pass


def serve(argv=()):
    argv = list(argv)
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 8080
    host = argv[argv.index("--host") + 1] if "--host" in argv else "0.0.0.0"
    print(f"Jinx catcher on {host}:{port}  log={LOG}")
    print(f"read key (set JINX_CATCHER_KEY to this where Jinx runs): {KEY}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve(sys.argv[1:])
