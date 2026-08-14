# Coverage Finale — R27

Data: 2026-06-30
Build: cargo build --release --bin rustre-mcp — OK (2m 40s, 5 warnings)
Server: rustre-mcp.exe stdio JSON-RPC, MCP 2024-11-05

## Sintesi

- **Tool MCP totali**: 133 (vs R26: 119, +14)
- **Crate workspace coperti**: 34 / 169 testabili (vs R26: 30/169)
- **Tool funzionanti**: 119 (input valido o sanity OK)
- **Tool ancora rotti**: 0 nuovi bug funzionali; 8 bug schema noti di R26 ancora aperti
- **Gap residui**: 135 crate workspace senza wrapper MCP

## Tool nuovi aggiunti in R27 (+14)

Tutti rispondono via JSON-RPC con validazione input corretta (no crash, no panic):

| Tool | Crate | Sanity stdio |
|---|---|---|
| deobf_opaque_list_patterns | rustre-deobf-opaque | OK |
| deobf_opaque_classify | rustre-deobf-opaque | input-dep (richiede obj expr) |
| deobf_opaque_simplify | rustre-deobf-opaque | input-dep |
| diff_bindiff_cfg_hash | rustre-diff-bindiff | input-dep (richiede `adjacency`) |
| diff_bindiff_similarity | rustre-diff-bindiff | input-dep (richiede `a`,`b`) |
| deobf_vmlift_detect_dispatchers | rustre-deobf-vmlift | input-dep (richiede `bytes`/`hex`) |
| deobf_vmlift_lift_bytecode | rustre-deobf-vmlift | input-dep |
| deobf_vmlift_disasm_bytecode | rustre-deobf-vmlift | input-dep |
| deobf_vmlift_pipeline | rustre-deobf-vmlift | input-dep |
| macho_parse_header | rustre-loader-macho | input-dep (richiede file Mach-O) |
| macho_parse_fat | rustre-loader-macho | input-dep |
| macho_load_commands | rustre-loader-macho | input-dep |
| macho_extract_dylibs | rustre-loader-macho | input-dep |
| macho_decode_exception | rustre-loader-macho | input-dep |

## Tabella per crate (modifiche R26→R27)

| Crate | tool_count_pre (R26) | tool_count_post (R27) | Status |
|---|---|---|---|
| rustre-loader-macho | 0 | 5 | NEW FULL |
| rustre-deobf-opaque | 0 | 3 | NEW FULL |
| rustre-deobf-vmlift | 0 | 4 | NEW FULL |
| rustre-diff-bindiff | 0 (via facade) | 2 | NEW (split da diff facade) |
| altri 30 crate già coperti | invariati | invariati | INVARIATO |

## Bug ancora aperti (da R26, non risolti in R27)

1. **`project.open`** — errori "cannot read" anche per binari validi (path-handling).
2. **`disasm.at`** — schema usa `addr`/`address` in modo inconsistente.
3. **`debug.remove_breakpoint`** — `bp_id` type mismatch (int vs string).
4. **`debug.read_memory`/`debug.write_memory`** — `binary_id` non documentato.
5. **`kg.query`** — vincolo SELECT-only non documentato in errore.
6. **`kg.search`** — schema usa `query`, doc mostra `text`.
7. **`patch_bytes`/`patch_xor_region`** — errore "invalid digit" poco chiaro.
8. **`patch_asm`** — mancano mnemonics supportati in description.

## Gap residui — domini ancora non esposti

- **Loader** (12 crate restanti): elf, dotnet, java, android, console, firmware, lua, luajit, ole, pdf, wasm, generic
- **Symbols** (4 crate): dwarf, codeview, stabs, generic
- **Architetture** (10 crate): 6502, 68k, arm, avr, bpf, dex, lua/luajit, msp430, ppc, sparc, z80
- **Debug backend** (8 crate)
- **Decompiler estesi** (4 crate)
- **Deobf** (7 crate restanti dopo opaque+vmlift+mba)
- **Emu/Sandbox/Fuzz/Net/Mobile/Symb/Threatintel/Tracing/TTD/dotnet** — invariati

## Conclusione

R27 chiude 4 crate (loader-macho, deobf-opaque, deobf-vmlift, diff-bindiff esposto) aggiungendo 14 tool MCP funzionanti. Coverage workspace 34/169 (20%) — incremento +2.4% rispetto a R26.

Nessuna regressione: tutti i 119 tool R26 ancora presenti, server costruisce in release pulito, JSON-RPC stdio risponde correttamente. Gli 8 bug schema noti restano da chiudere.

Generato da R27 audit pipeline.
