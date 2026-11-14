# Changelog

All notable changes to Jinx are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `pyproject.toml` version.

## [Unreleased]

### Added
- `jinx research <vendor>` — scaffolds `engagements/<vendor>/research.md` (AI surfaces,
  ATLAS attack patterns, curated public precedents) to fill in before a simulation.
- Authorization gate — every non-mock `jinx run` requires confirmation before sending a
  probe. Bypass non-interactively with `--authorized` or `JINX_AUTHORIZED=1`.
- Report: **Live run results** section rendered from the telemetry log (per-target verdict
  counts + how many checks ran).
- Project files: `SECURITY.md`, `CONTRIBUTING.md`, this changelog, CI workflow, issue/PR
  templates.

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
