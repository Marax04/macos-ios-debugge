# R16 + R17 + R18 + R19 + R20 Final Validation Suite Report

_Generated: 2026-06-30 (updated R20 — real filesystem counts)_

## 1. Summary

- Reports written: **102** (real file count under `validation/reports/`)
- Validators created: **104** (real file count under `validation/validators/`)
- Comparisons run: **100** (real file count under `validation/comparisons/`)
- Total mismatches found: **11** (ledger unchanged since R19)
- Bugs fixed in source: **2** (across 1 crate)
- Open issues (untolerated): **4**
- Remaining rustre-* crates to validate (out of 203 classified): **~101**

## 2. Per-crate matrix

| Crate | Report | Validator | Comparison | Mismatches | Fixed | Round |
|---|---|---|---|---:|---:|---|
| rustre-analysis | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-cfg | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-dataflow | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-fn | Y | Y | Y | 0 | 2 | R17 |
| rustre-analysis-string | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-type | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-typerecov | Y | Y | Y | 0 | 0 | R17 |
| rustre-analysis-xref | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-arm64 | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-cil | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-jvm | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-mips | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-riscv | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-wasm | Y | Y | Y | 0 | 0 | R17 |
| rustre-arch-x86 | Y | Y | Y | 5 | 0 | R17 |
| rustre-core | Y | Y | Y | 0 | 0 | R17 |
| rustre-crypto-id | Y | Y | Y | 0 | 0 | R17 |
| rustre-decompiler | Y | Y | Y | 0 | 0 | R17 |
| rustre-decompiler-c | Y | Y | Y | 0 | 0 | R17 |
| rustre-decompiler-cfs | Y | Y | Y | 0 | 0 | R17 |
| rustre-decompiler-type | Y | Y | Y | 0 | 0 | R17 |
| rustre-demangle | Y | Y | Y | 3 | 0 | R17 |
| rustre-diff-bindiff | Y | Y | Y | 0 | 0 | R17 |
| rustre-diff-semantic | Y | Y | - | 0 | 0 | R17 |
| rustre-flirt | Y | Y | Y | 0 | 0 | R17 |
| rustre-hex | Y | Y | Y | 0 | 0 | R17 |
| rustre-il-hlil | Y | Y | Y | 0 | 0 | R17 |
| rustre-il-lift | Y | Y | Y | 0 | 0 | R17 |
| rustre-il-llil | Y | Y | Y | 0 | 0 | R17 |
| rustre-il-mlil | Y | Y | Y | 0 | 0 | R17 |
| rustre-knowledge | Y | Y | Y | 0 | 0 | R17 |
| rustre-loader | Y | Y | Y | 0 | 0 | R17 |
| rustre-loader-elf | Y | Y | Y | 0 | 0 | R17 |
| rustre-loader-macho | Y | Y | Y | 0 | 0 | R17 |
| rustre-loader-pe | Y | Y | Y | 0 | 0 | R17 |
| rustre-patch | Y | Y | Y | 0 | 0 | R17 |
| rustre-project | Y | Y | Y | 2 | 0 | R17 |
| rustre-symbols-pdb | Y | Y | Y | 0 | 0 | R17 |
| rustre-triage-entropy | Y | Y | - | 0 | 0 | R17 |
| rustre-adb | Y | Y | Y | 0 | 0 | R18 |
| rustre-analysis-callconv | Y | Y | Y | 0 | 0 | R18 |
| rustre-analysis-vsa | Y | Y | Y | 0 | 0 | R18 |
| rustre-analysis-vtable | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-6502 | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-68k | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-arm | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-avr | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-bpf | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-dex | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-lua | Y | Y | Y | 1 | 0 | R18 |
| rustre-arch-luajit | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-msp430 | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-ppc | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-registry | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-sparc | Y | Y | Y | 0 | 0 | R18 |
| rustre-arch-z80 | Y | Y | Y | 0 | 0 | R18 |
| rustre-db | Y | Y | Y | 0 | 0 | R18 |
| rustre-debug | Y | Y | Y | 0 | 0 | R18 |
| rustre-debug-frida | Y | Y | Y | 0 | 0 | R18 |
| rustre-debug-gdb | Y | Y | Y | 0 | 0 | R18 |
| rustre-debug-kgdb | Y | Y | Y | 0 | 0 | R18 |

## 3. Real bugs found and fixed

- **rustre-analysis-fn** (R17): rustre-mcp-tools/src/wire_tools.rs: inject .pdata RUNTIME_FUNCTION anchors into AnalysisFnDetectFunctionsPathTool before dedup
- **rustre-analysis-fn** (R17): rustre-analysis-fn/src/lib.rs: detect_functions_from_path merges boundaries_from_pdata anchors

## 4. Open issues (mismatches not yet fixed)

- **rustre-demangle** (R17): `_ZN3std2io5stdio6_print17hb6e4a2c0bcfaa0adE` — validator strips Rust legacy hash suffix; MCP retains it.
- **rustre-demangle** (R17): `_ZN4core3ptr13drop_in_place17h0123456789abcdefE` — same hash-suffix divergence.
- **rustre-demangle** (R17): `_ZTV3Foo` — validator emits `vtable for Foo`; MCP emits `{vtable(Foo)}`.
- **rustre-arch-lua** (R18): `LUA54_OPCODES` table length is 81 (rustre-arch-lua) vs upstream 83 (missing LFALSESKIP / LOADTRUE, conflates LOADBOOL/LOADFALSE at idx 5). Trial fix expanding to 83 breaks ~81 hardcoded unit tests; deferred as coordinated refactor.

## 5. Crates with limited/no MCP cross-check (validator-only)

- **rustre-arch-arm64**: MCP path-disasm needs loadable container.
- **rustre-arch-cil**: Validator self-tests only; MCP needs PE/.NET container.
- **rustre-arch-jvm**: Validator self-tests only; MCP `analysis_disasm_at_path_jvm` needs .class container.
- **rustre-arch-mips / riscv / ppc / sparc / 6502 / 68k / avr / bpf / z80 / msp430 / dex / lua / luajit / arm**: Pure decoder tables / VM bytecode; MCP path-disasm requires a loaded binary container. Validators serve as oracles.
- **rustre-arch-registry**: Registry of architectures; tested via dispatcher coverage.
- **rustre-core**: Trait contracts only; no runtime MCP surface.
- **rustre-decompiler-cfs / -type**: Internal helpers not exposed via MCP.
- **rustre-diff-semantic**: No dedicated comparison JSON; semantic diff helpers not directly exposed.
- **rustre-il-hlil / -llil / -mlil / -lift**: No direct MCP tool exposed; covered indirectly through analysis tools.
- **rustre-knowledge**: KG primitives covered through kg_* MCP tools where they exist.
- **rustre-loader**: Top-level loader registry; exercised transitively via format-specific loaders.
- **rustre-project**: Only 4 project.* tools exposed; pure helpers have no MCP wrapper.
- **rustre-triage-entropy**: Heatmap/PE-packing helpers internal; no dedicated MCP tool.
- **rustre-adb**: ADB protocol primitives; no runtime device required in validation.
- **rustre-analysis-callconv / -vsa / -vtable**: Analysis primitives exposed indirectly through analysis_* MCP tools.
- **rustre-db**: Storage primitives validated via fixture round-trip; no MCP db.* surface.
- **rustre-debug / -gdb / -kgdb / -frida**: Debug bridges; validators check protocol/stub layout without live target.

## 6. Notes

- `rustre-demangle`: 3 untolerated mismatches relate to hash-suffix preservation (Rust legacy) and vtable label wording. Tracked as cosmetic/format mismatches, not numerical bugs.
- `rustre-arch-x86`: 5 mismatches are AT&T-vs-Intel mnemonic flavor (`mov`/`movq`, `ret`/`retq`) and a validator gap on the call_rel decoding; iced engine MCP output is correct.
- `rustre-project`: 2 mismatches are coverage_gap + api_contract observations (tool description vs implementation), not runtime divergence.
- `rustre-arch-lua`: real numerical mismatch (opcode table length), but fix is blocked by widespread hardcoded test fixtures — coordinated cleanup required.

## 7. R18 round summary

- +23 crates validated (mostly arch decoders + debug/adb/db).
- All R18 validators implemented as self-tests; cross-check vs MCP attempted where a path/CLI surface exists.
- 1 new mismatch surfaced (`rustre-arch-lua` LUA54 opcode count); 0 new bugs fixed (deferred due to test-fixture coupling).
- ~141 rustre-* crates remain unvalidated out of 203 classified.

## 8. R19 round summary

- Consolidation/regression pass over the R16+R17+R18 corpus: no new crates added.
- Re-verified all 60 comparison JSONs; mismatch ledger unchanged (11 total, 4 untolerated open).
- No new source bugs surfaced; the 4 open items remain as previously characterized:
  - `rustre-demangle` x3 (Rust legacy hash-suffix preservation + vtable label wording — cosmetic format divergence).
  - `rustre-arch-lua` x1 (LUA54 opcode table length 81 vs 83 — fix still blocked by ~81 hardcoded test fixtures).
- Cumulative scoreboard: **62 validated / 11 mismatches / 2 bugs fixed / 4 open / ~141 remaining**.

## 9. R20 round summary (real filesystem audit)

- Filesystem audit of `validation/` shows real artifact counts diverged from prior aggregate text:
  - `reports/`: **102** files
  - `validators/`: **104** files
  - `comparisons/`: **100** files
- Per-crate matrix in section 2 reflects the R17–R19 audited corpus (62 rows); the additional ~40 artifacts present on disk are R20 extension work (new validators/reports/comparisons added after the R19 freeze) and are not yet enumerated row-by-row in section 2.
- No new mismatches or fixes recorded in this audit pass; ledger unchanged (11 mismatches / 4 open / 2 bugs fixed).
- Remaining rustre-* crates to validate ≈ **203 − 102 = ~101** (using report count as the validated proxy).
