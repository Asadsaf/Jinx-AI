"""Tiny MCP stdio server exposing one `chat` tool backed by the local vulnerable
test agent. Lets you exercise the MCP transport offline (no real server needed):

    python -m jinx run --target examples/targets/mcp-mock.json

It speaks newline-delimited JSON-RPC 2.0 over stdio: initialize, tools/list, tools/call.
"""
import json
import sys

from .testbed import MockAgent


def _reply(mid, result=None, error=None):
    obj = {"jsonrpc": "2.0", "id": mid}
    obj["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    agent = MockAgent("vulnerable")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            _reply(mid, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                         "serverInfo": {"name": "jinx-mock", "version": "1.0"}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _reply(mid, {"tools": [{"name": "chat", "description": "chat with the agent",
                   "inputSchema": {"type": "object",
                                   "properties": {"message": {"type": "string"}},
                                   "required": ["message"]}}]})
        elif method == "tools/call":
            args = (msg.get("params") or {}).get("arguments") or {}
            out = agent.send(args.get("message", ""))
            _reply(mid, {"content": [{"type": "text", "text": out.get("text", "")}]})
        elif mid is not None:
            _reply(mid, error={"code": -32601, "message": "method not found"})


if __name__ == "__main__":
    main()
