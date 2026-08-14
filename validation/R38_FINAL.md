# R38 Final Coverage Report

## Build
- `cargo build --release --bin rustre-mcp`: OK

## Tools Registered
- Total MCP tools exposed: **227**

## Coverage Breakdown vs Baseline

| Category  | Baseline (71 tools) | Now (227 tools) | Delta |
|-----------|---------------------|-----------------|-------|
| FULL      | ~4                  | 6               | +2    |
| PARTIAL   | ~40                 | 173             | +133  |
| NONE      | ~135                | 0               | -135  |
| INTERNAL  | 24                  | 24              | 0     |
| **Total crates** | 203          | 203             | 0     |

## Notes
- All workspace crates now have at least one MCP wrapper (NONE = 0).
- Largest remaining PARTIAL crates by pub_fn: rustre-il-lift (955 fn, 4 tools), rustre-trace-navigate (643 fn, 6 tools), rustre-debug-unicorn (632 fn, 12 tools).
- Full breakdown JSON: `validation/R32_COVERAGE_BREAKDOWN.json`
- Tool list: `validation/tools_list.txt`
