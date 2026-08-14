# RustRE Validation Infrastructure

Validates RustRE MCP tools against independent reference implementations.

## Structure

- `validators/` — Independent Python (or other) scripts, one per crate. Each implements a reference algorithm for the crate's domain (parsing, analysis, crypto, etc.) used to ground-truth MCP output.
- `mcp_outputs/` — Raw JSON results captured from `mcp__rustre-mcp__*` tool invocations, organized per crate / per tool.
- `comparisons/` — Diff artifacts between `mcp_outputs/` and `validators/` results. One file per crate run.
- `reports/` — Human-readable markdown reports per crate summarizing parity, gaps, regressions.
- `classification.json` — Categorization of every crate (TESTABLE_CORE / TESTABLE_NETWORK / NOT_TESTABLE / INFRASTRUCTURE).
- `WORKLOG.md` — Session-by-session tracking log.

## Workflow

1. Pick a crate from `classification.json` (skip NOT_TESTABLE).
2. Identify MCP tools backed by that crate.
3. Run MCP tool against a known sample binary, save raw JSON to `mcp_outputs/<crate>/<tool>.json`.
4. Run the validator in `validators/<crate>.py` against the same sample.
5. Diff into `comparisons/<crate>.md`.
6. Write summary in `reports/<crate>.md`.
