# rustre-trace-coverage

## Cargo.toml

- **name**: `rustre-trace-coverage`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repository/readme/keywords/categories/authors**: inherited from workspace
- **dependencies**: `thiserror`, `serde`, `serde_json` (all workspace)
- **lints**: workspace
- **Note**: does NOT depend on `rustre-trace` to avoid a workspace cycle (rustre-trace lists this crate as an optional sub-coverage dep).

## Overview

Lighthouse-style code coverage recording and reporting. Provides:
- `CoverageData` / `CoverageRun`: multiple named runs with BB and edge hit maps
- Format loaders: DRcov, LCOV, custom binary (addr+count pairs), AFL bitmap
- Coverage merge (union with sum), diff (A-only, B-only, both)
- BB coloring: `is_covered`, `visit_count` per address
- Function-level stats: `total_bb`, `covered_bb`, `coverage_pct`
- Export: LightHouse JSON, LCOV info, HTML report
- Heatmap: sorted (addr, count) for gradient display

## Modules (pub)

`cast_helpers`, `bb_heatmap`, `coverage_bitmap`, `coverage_diff`, `coverage_guided_analysis`, `coverage_map`, `coverage_merge`, `coverage_report`, `differential_coverage`, `drcov_import`, `lighthouse_compat`, `source_mapping`, `coverage_bitmap_ext`, `branch_coverage`, `function_coverage`, `coverage_visualizer`, `coverage_timeline`, `path_coverage`.

## Public types (lib.rs root)

- `CovError` (enum): `SizeMismatch`, `InvalidIndex`, `SourceNotFound`, `IncompatibleCoverage`, `Serialization`, `ParseError`, `Io`.
- `CovEdge { from: u64, to: u64 }` — directed CFG edge. `new`, `Display`.
- `CovBitmap { bits: Vec<u8>, size: usize }` — AFL-style edge bitmap.
  - `new`, `from_afl_bitmap`, `set`, `clear`, `toggle`, `get`, `count_set`, `count_clear`
  - `union`, `intersection`, `difference`, `or_assign`
  - `jaccard`, `coverage_ratio`, `set_bits`, `clear_bits`, `is_full`, `is_empty`, `record_edge`
- `CoverageRun { name, bb_hits, edge_hits, timestamp, source_tag }`.
  - `new`, `with_timestamp`, `with_source_tag`
  - `record_bb`, `record_bb_n`, `record_edge`, `record_edge_n`
  - `is_covered`, `visit_count`, `unique_bbs`, `unique_edges`, `total_bb_executions`
  - `hot_bbs(n)`, `heatmap`
- `CoverageData { runs, label }`.
  - `new`, `add_run`, `merge_all`, `run_count`, `total_unique_bbs`, `all_bb_addresses`
- `CoverageDiff { new_in_a, new_in_b, in_both, edges_only_in_a, edges_only_in_b, jaccard }`.
  - `compute(a,b)`, `overlap_pct`
- `FunctionStats { name, start_addr, end_addr, total_bb, covered_bb, call_count }`.
  - `new`, `coverage_pct`, `was_called`, `is_fully_covered`
- `DrcovModule`, `DrcovBasicBlock`, `DrcovData`.
  - `DrcovData::parse`, `resolve_addresses`, `to_run`
- `LcovRecord` with `new`, `line_coverage_ratio`, `function_coverage_ratio`, `Default`.
- `LighthouseJson { name, coverage, timestamp }`.
  - `from_run`, `to_json`, `from_json`, `to_run`
- `CoverageHeatmap { entries, max_count }`.
  - `build`, `heat_at`, `hottest`
- `BlockColorInfo { addr, is_covered, visit_count, heat }`.
  - `for_addr`, `rgba_color`
- `CoverageSession { name, data, bitmap }`.
  - `new`, `add_run`, `merged`, `run_count`, `bitmap_coverage`, ...

## Public free functions

- `compute_function_stats(run, functions) -> Vec<FunctionStats>`
- `parse_custom_binary(&[u8]) -> Result<CoverageRun, CovError>`
- `to_custom_binary(&CoverageRun) -> Vec<u8>`
- `load_afl_bitmap(&[u8]) -> CovBitmap`
- `afl_bitmap_coverage(&CovBitmap) -> usize`
- `afl_new_coverage(&CovBitmap, &CovBitmap) -> usize`
- `merge_runs(a, b, name) -> CoverageRun`
- `merge_all_runs(&CoverageData) -> CoverageRun`
- `parse_lcov(&str) -> Vec<LcovRecord>`
- `to_lcov_string(&[LcovRecord]) -> String`
- `generate_html_report(title, run, function_stats) -> String`
- `generate_block_colors(run, known_addrs) -> Vec<BlockColorInfo>`
- Re-exports from `cast_helpers::*` (numeric conversion helpers).

## Testability

The crate is highly testable: all parsers (`DrcovData::parse`, `parse_lcov`, `parse_custom_binary`), serializers (`to_custom_binary`, `to_lcov_string`, `LighthouseJson::to_json`), and analytics (`CovBitmap::jaccard`, `CoverageDiff::compute`, `compute_function_stats`) are pure functions over in-memory data with no I/O or external dependencies. Round-trip tests (binary, LCOV, Lighthouse JSON) are straightforward, and bitmap/diff invariants can be unit-tested with small fixtures.
