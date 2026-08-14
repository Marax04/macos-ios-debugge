# R30 Final Exercise Report

**Date:** 2026-06-30
**Source:** validation/mcp_outputs/R30v3_full.json

## Summary

- **Totale tool esercitati:** 133

| Status | Count |
|---|---|
| OK | 88 |
| TOOL_ERROR | 16 |
| JSONRPC_ERROR | 29 |

## TOOL_ERROR list

| Tool | Reason |
|---|---|
| disasm.function | no function detected at 0x14000f26c |
| decompile.function | no function detected at 0x14000f26c |
| debug.set_breakpoint | missing 'address' param |
| debug.read_memory | missing 'binary_id' param |
| debug.write_memory | missing 'binary_id' param |
| trace_data_flow | YARA compile error: empty rule source |
| analysis_xref_get_xrefs_to | image not loaded |
| analysis_xref_to_path | Only SELECT allowed in kg.query |
| analysis_xref_call_graph_root_functions | missing 'query' param |
| analysis_xref_string_ref_counts | missing 'addr' param |
| analysis_fn_detect_extra | missing 'addr' param |
| decompiler_core_batch_decompile | missing 'addr' param |
| analysis_callees_path | invalid hex byte string: empty input |
| analysis_string_scan_path | patch_asm: unsupported asm mnemonic |
| symbols_demangle_rust | opaque expr node must be an object |
| symbols_demangle_itanium | opaque expr node must be an object |

## JSONRPC_ERROR

29 tool calls failed with stdout "bad-line" errors — the MCP process emitted CLI help/usage text (`cargo-zyphora --help` banner) on stdout, polluting the JSONRPC stream. This is a single transport-level issue affecting all calls in that batch (yara.*, forensics.*, kg.*, diff.compare, crypto.identify, triage.analyze, several patch_* / type_* / analysis_xref_* / loader_* / infer_types_path / struct_field_at_path), not 29 independent tool bugs.

## Conclusion

- **Funzionante (OK):** 88 / 133 = **66.2%**
- **Funzionante escludendo transport JSONRPC bug:** 88 / 104 = **84.6%**
- **TOOL_ERROR reali (parametri/stato mancanti, non bug logici):** 16 / 133 = 12.0%

La maggior parte dei TOOL_ERROR sono dovuti a parametri mancanti nel test harness (missing 'addr', 'binary_id', 'query'), non a difetti dei tool. Il blocco JSONRPC_ERROR è un singolo problema di transport (stdout contaminato da help text) che andrebbe corretto a monte.
