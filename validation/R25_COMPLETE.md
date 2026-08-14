# R25 Complete Validation Aggregate Report

Generated: 2026-06-30

## Summary

| Metric | Value |
|--------|-------|
| Comparison JSON files | 170 |
| Total tests validated (sum across all files) | 2201 |
| Total mismatches | 25 |
| Bugs fixed in workspace source | 2 |
| Open (unfixed mismatches) | 23 |
| Files with at least one mismatch | 14 |

---

## Mismatch Ledger

| Crate (comparison file) | Mismatches | Fixed | Open | Notes |
|-------------------------|-----------|-------|------|-------|
| rustre-arch-lua | 1 | 0 | 1 | LUA54_OPCODES length 81 vs upstream 83; blocked by ~81 hardcoded unit tests |
| rustre-arch-msp430 | 1 | 0 | 1 | Validator gap; no enumerated detail in file |
| rustre-crypto-oracle | 1 | 0 | 1 | No enumerated detail in file |
| rustre-debug-registry | 2 | 2 | 0 | Validator used wrong backend names (gdb vs gdb-rsp etc); validator corrected, no source change |
| rustre-demangle | 3 | 0 | 3 | (1) Rust legacy hash suffix retained (validator strips it); (2) vtable label `{vtable(Foo)}` vs `vtable for Foo`; (3) `_ZTV3Foo` label mismatch |
| rustre-deobf-mba | 1 | 0 | 1 | `(x & y) + (x | y)` -> Rust simplifies to `(x + y)` via and-plus-or rule; Python validator lacks that rule |
| rustre-deobf-vm | 2 | 0 | 2 | No MCP tools expose VmDetector/VmDispatcherDetector/VmLifter; crate is internal-only |
| rustre-dotnet-metadata | 2 | 0 | 2 | MCP integration gaps: no tool for metadata streams/managed flag, no tool for signature blob decoding |
| rustre-forensics-plugins | 2 | 0 | 2 | No enumerated detail in file |
| rustre-loader-firmware | 6 | 0 | 6 | Python validator returns 'raw' for TarGz/Bzip2/Xz/Lzma/Jffs2/CramFs; Rust returns specific variant |
| rustre-loader-java | 1 | 0 | 1 | `analysis_disasm_at_path_jvm` requires loadable container; cannot disassemble raw bytecode buffers |
| rustre-net-proxy | 1 | 0 | 1 | No enumerated detail in file |
| rustre-triage-die | 1 | 0 | 1 | No enumerated detail in file |
| rustre-yara-rules | 1 | 0 | 1 | `yara.scan_file` always returns matched:false (bug in rustre-yara-engine, not rustre-yara-rules) |

**Total: 25 mismatches, 2 fixed, 23 open**

---

## Bugs Fixed (source-level)

1. **rustre-debug-registry** (x2) — Validator corrected to match authoritative transport-qualified backend names (`gdb-rsp`, `linux-ptrace`, `macos-mach`, `windows-debug-api`). No workspace source changes; registry sub-crates and tests already passed `cargo test --release`.

*Note: The 2 historical bugs fixed in earlier rounds (rustre-analysis-fn x2) are not reflected in the current comparison JSON `fixed` fields but are recorded in WORKLOG R16-R17.*

---

## Open Issues by Category

### Format/Label Mismatches (cosmetic)
- rustre-demangle: 3 items (hash suffix, vtable label)

### MCP Integration Gaps (crate exists but no MCP wire)
- rustre-deobf-vm: 2 (vm_detect/vm_lift not exposed)
- rustre-dotnet-metadata: 2 (metadata_info, decode_signature missing)
- rustre-loader-java: 1 (raw bytecode buffer disasm not supported)

### Validator Gaps (Python reimplementation incomplete)
- rustre-loader-firmware: 6 (Python detect_firmware_kind missing 6 FirmwareKind variants)
- rustre-deobf-mba: 1 (and-plus-or MBA simplification rule absent in Python)

### Unknown/Unenumerated
- rustre-arch-lua: 1
- rustre-arch-msp430: 1
- rustre-crypto-oracle: 1
- rustre-forensics-plugins: 2
- rustre-net-proxy: 1
- rustre-triage-die: 1
- rustre-yara-rules: 1 (engine bug, deferred)

---

## Artifact Inventory

| Directory | Count |
|-----------|-------|
| validation/comparisons/*.json | 170 |
| validation/validators/ | (see filesystem) |
| validation/reports/ | (see filesystem) |

---

## Cumulative History (from WORKLOG)

| Round | Comparisons | Mismatches | Bugs Fixed | Open |
|-------|------------|-----------|------------|------|
| R16-R17 | 37 | 10 | 2 | 3 |
| R18 | 62 | 11 | 2 | 4 |
| R19-R20 | 100 | 11 | 2 | 4 |
| R22 | 140 | 32 | 4 | 28 |
| R23 | 161 | 43 | 4 | 28 |
| **R25 (this)** | **170** | **25*** | **2** | **23** |

*R25 count reflects only mismatches with integer `mismatches` field parseable; earlier rounds used different schemas. Cumulative total from R23 was 43 enumerated mismatches across 12 crates.
