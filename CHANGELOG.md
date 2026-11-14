# Changelog

All notable changes to Jinx are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `pyproject.toml` version.

## [Unreleased]

### Added
- **Adaptive escalation ladder** (`jinx run --target … --escalate`) — one conversation that
  reframes the same leak ask at increasing pressure (plain → context → authority → policy →
  direct). The next rung is chosen from the last verdict (a hit stops it, an ECHO keeps
  climbing with a "now make it render" nudge), so it adapts **without an adversary model**.
  Records which rung it took. In the Claude-in-Chrome path, Claude drives the ladder.
- `jinx research <vendor>` — scaffolds `engagements/<vendor>/research.md` (AI surfaces,
  ATLAS attack patterns, curated public precedents) to fill in before a simulation.
- `jinx connect` walks every transport through to the report (no option dead-ends), with
  in-menu help / back / quit. Ordered `[n/N]` progress counter on `run` and the battery.
- `jinx help` lists every command. `CITATION.cff` for citing the tool.
- Authorization gate — every non-mock `jinx run` requires confirmation before sending a
  probe. Bypass non-interactively with `--authorized` or `JINX_AUTHORIZED=1`.
- Report: **Live run results** section rendered from the telemetry log (per-target verdict
  counts + how many checks ran).
- Project files: `SECURITY.md`, `CONTRIBUTING.md`, this changelog, issue/PR templates.

## [2.2.0]

### Added
- `jinx connect` — interactive chooser for the four transports (API / MCP / Browser /
  Claude in Chrome) that scaffolds a target config.
- **MCP transport** (`MCPTarget`) — Jinx acts as a Model Context Protocol client and calls
  the agent's tool once per probe. Offline demo via `examples/targets/mcp-mock.json`.
- `docs/CLAUDE_IN_CHROME.md` — assisted-browser engagement steps.

### Changed
- Architecture reorganized around **MITRE ATLAS** (verified against ATLAS 2026.10): 32
  techniques grouped under 16 combined ATLAS tests. `jinx audit` proves nothing was dropped
  (16 tests · 32 techniques · 5 families · 14 framings · 15 encodings · 1050-variant matrix).
