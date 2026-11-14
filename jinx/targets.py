"""Load a target from a JSON config file, so nothing needs to be written in Python.

  {"type": "http", "name": "...", "url": "...", "headers": {...}, "body": {...<<PROMPT>>...},
   "answer_path": [...]}                      -> HTTPTarget (any chat API)
  {"type": "browser", "name": "...", "url": "...", "input_sel": "...", "send_sel": "...",
   "answer_sel": "...", "headless": false}   -> BrowserTarget (needs playwright)
  {"type": "mcp", "name": "...", "command": ["python3","server.py"], "tool": "chat",
   "prompt_arg": "message", "answer_path": [...]}  -> MCPTarget (agent over MCP)
  {"type": "mock", "mode": "vulnerable|hardened|hardened-quoting"}  -> local test agent

Secrets never go in the file: write "${MY_API_KEY}" and export MY_API_KEY in the shell.
See examples/targets/.
"""
import json


def load(path):
    with open(path) as f:
        cfg = json.load(f)
    kind = cfg.pop("type", "http")
    if kind == "http":
        from .harness import HTTPTarget
        return HTTPTarget(cfg)
    if kind == "browser":
        from .harness import BrowserTarget
        return BrowserTarget(cfg["url"], cfg["input_sel"], cfg["send_sel"], cfg["answer_sel"],
                             name=cfg.get("name", "browser"), headless=cfg.get("headless", False))
    if kind == "mcp":
        from .harness import MCPTarget
        return MCPTarget(cfg)
    if kind == "mock":
        from .testbed import MockAgent
        return MockAgent(cfg.get("mode", "vulnerable"))
    raise ValueError(f"unknown target type {kind!r}")
