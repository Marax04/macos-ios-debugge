# Audit copertura MCP — 119 tool / 203 crate

Data: 2026-06-30 — Round R26
Fonti: `validation/R26_COVERAGE.json`, `validation/R26_FUNCTIONAL.json`

## Sintesi

- **Tool totali esposti**: 119
- **Crate workspace**: 203
- **Crate con copertura piena (COVERED_FULL)**: 16
- **Crate con copertura parziale (COVERED_PARTIAL)**: 14
- **Crate scoperti che dovrebbero avere tool (GAP DA CHIUDERE)**: 134
- **Crate interni OK senza tool (INTERNAL)**: 39
- **Tool funzionanti (WORKING + sanity pass)**: 32
- **Tool input-dependent (sanity fallita per input dummy, logica probabilmente OK)**: 36
- **Tool rotti / ERROR (path file inesistente o errore reale)**: 51
  - di cui 50 falliscono per il file di test mancante `target/release/cargo-zyphora.exe` (non bug del tool)
  - **bug funzionali reali**: 1 (`project.open` non trova il binario — possibile bug di path-handling se il file esiste in altra locazione)

> Nota: la maggior parte degli ERROR non sono bug del tool: il binario di test `cargo-zyphora.exe` non era presente al momento della validazione. Sanity test deve essere ri-eseguito su file reale per separare bug veri.

## Tabella crate → tool (copertura non-zero)

| Crate | Tool count | Category | Tool names |
|---|---|---|---|
| rustre-analysis | 9 | FULL | analyze.full, analyze.function, analyze.basic_block, analyze.cross_refs, analyze.call_graph, analyze.strings, analyze.imports, analyze.exports, survey_binary |
| rustre-analysis-cfg | 3 | FULL | analysis_basic_blocks_path, analysis_dominators_path, analysis_loops_path |
| rustre-analysis-dataflow | 2 | PARTIAL | trace_data_flow, analysis_trace_data_flow_path |
| rustre-analysis-fn | 5 | FULL | analysis_fn_detect_extra, function_list_by_kind, noreturn_infer, analysis_fn_detect_functions_path, analysis_fn_cfg_path |
| rustre-analysis-string | 1 | PARTIAL | analysis_string_scan_path |
| rustre-analysis-type | 9 | FULL | infer_types_path, type_propagate_path, struct_field_at_path, type_infer, type_query, type_inspect, type_apply_batch, declare_type, analysis_infer_types_path |
| rustre-analysis-typerecov | 1 | PARTIAL | analysis_recover_structs_path |
| rustre-analysis-xref | 10 | FULL | analysis_xref_call_graph, analysis_xref_callees, analysis_xref_get_xrefs_to, analysis_xref_get_xrefs_from, analysis_xref_to_path, analysis_xref_from_path, analysis_xref_call_graph_root_functions, analysis_xref_string_ref_counts, analysis_callgraph_path, analysis_callees_path |
| rustre-arch-arm64 | 1 | PARTIAL | analysis_disasm_at_path_arm64 |
| rustre-arch-cil | 1 | PARTIAL | analysis_disasm_at_path_cil |
| rustre-arch-jvm | 1 | PARTIAL | analysis_disasm_at_path_jvm |
| rustre-arch-mips | 1 | PARTIAL | analysis_disasm_at_path_mips |
| rustre-arch-riscv | 1 | PARTIAL | analysis_disasm_at_path_riscv |
| rustre-arch-wasm | 1 | PARTIAL | analysis_disasm_at_path_wasm |
| rustre-arch-x86 | 3 | FULL | disasm.at, disasm.function, analysis_disasm_at_path |
| rustre-core | 13 | INTERNAL (esposti) | binary.*, kg.* |
| rustre-crypto-id | 3 | FULL | crypto.identify, analysis_crypto_scan_path, crypto_xor_decode |
| rustre-debug | 12 | FULL | debug.* (12 tool) |
| rustre-decompiler | 7 | FULL | decompile.*, decompiler_core_batch_decompile, decompiler_recover_structs, decompiler_stack_frame_report, decompile_function_path |
| rustre-demangle | 5 | FULL | symbols_demangle_{auto,rust,msvc,itanium,swift} |
| rustre-deobf-mba | 1 | PARTIAL | deobf_mba_normalize |
| rustre-diff | 5 | FULL | diff.compare, diff_compare, diff_bindiff, diff_minhash, diff_semantic |
| rustre-flirt | 3 | FULL | flirt_apply_auto, fingerprint_compute, fingerprint_match |
| rustre-forensics | 3 | FULL | forensics.open_dump, forensics.run_plugin, forensics.list_plugins |
| rustre-loader-pe | 1 | PARTIAL | loader_core_md5 |
| rustre-patch | 5 | FULL | patch_patch_find_code_caves, patch_bytes, patch_nop_range, patch_xor_region, patch_asm |
| rustre-pe-editor | 2 | PARTIAL | patch_pe_security_summary, patch_pe_set_security |
| rustre-project | 4 | FULL | project.{open,close,list_binaries,info} |
| rustre-symbols-pdb | 1 | PARTIAL | symbols_pdb_load |
| rustre-triage | 2 | PARTIAL | triage.analyze, triage_entropy_packing_indicators |
| rustre-yara-engine | 3 | FULL | yara.scan_file, yara.compile, yara.scan_memory |

## Gap di copertura — 134 crate da wrappare

Crate scoperti raggruppati per dominio. Per ognuno è elencato il prefisso tool suggerito.

### Architetture (11)
- `rustre-arch-6502` → `arch_6502_disasm`
- `rustre-arch-68k` → `arch_68k_disasm`
- `rustre-arch-arm` (ARM32) → `arch_arm_disasm`, `arch_arm_thumb_disasm`
- `rustre-arch-avr` → `arch_avr_disasm`
- `rustre-arch-bpf` → `arch_bpf_disasm`, `arch_bpf_verify`
- `rustre-arch-dex` → `arch_dex_disasm`, `arch_dex_classes`
- `rustre-arch-lua`, `rustre-arch-luajit` → `arch_lua_disasm`, `arch_luajit_disasm`
- `rustre-arch-msp430` → `arch_msp430_disasm`
- `rustre-arch-ppc` → `arch_ppc_disasm`
- `rustre-arch-sparc` → `arch_sparc_disasm`
- `rustre-arch-z80` → `arch_z80_disasm`

### Loader (13)
`rustre-loader`, `loader-android`, `loader-console`, `loader-dotnet`, `loader-elf`, `loader-firmware`, `loader-java`, `loader-lua`, `loader-luajit`, `loader-macho`, `loader-ole`, `loader-pdf`, `loader-wasm` → `loader_<fmt>_parse`, `loader_<fmt>_sections`, `loader_<fmt>_symbols`

### Debug backend (9)
`rustre-debug-frida`, `-gdb`, `-kgdb`, `-linux`, `-macos`, `-unicorn`, `-windbg`, `-windows` → `debug_<be>_attach`, `debug_<be>_breakpoint`, ecc.

### Decompiler estesi (5)
`rustre-decompiler-c`, `-cfs`, `-expr`, `-ghidra`, `-type` → tool di emissione C, control-flow structuring, simplification espressioni, integrazione Ghidra, recupero tipi.

### Deobfuscation (10)
`rustre-deobf`, `-antianti`, `-cff`, `-iadl`, `-mhcde`, `-opaque`, `-smc`, `-string`, `-vm`, `-vmlift` → `deobf_<tech>_normalize`, `deobf_<tech>_lift`.

### .NET (4)
`rustre-dotnet`, `-decompile`, `-edit`, `-metadata` → `dotnet_metadata_query`, `dotnet_decompile`, `dotnet_edit_rename`.

### Emulazione (4)
`rustre-emu`, `-qiling`, `-shellcode`, `-unicorn` → `emu_run`, `emu_<be>_step`, `emu_shellcode_analyze`.

### Forensics (3)
`rustre-forensics-fs`, `-mem`, `-plugins` → `forensics_fs_<op>`, `forensics_mem_scan`.

### Fuzzing (6)
`rustre-fuzz`, `-afl`, `-cov`, `-libfuzzer`, `-net`, `-sanitizers` → `fuzz_start`, `fuzz_cov_report`, ecc.

### Mobile (8)
`rustre-mobile`, `-android`, `-apktool`, `-dyld`, `-ios`, `-ipa`, `-jadx`, `-smali` → `mobile_<plat>_<op>`.

### Net (5)
`rustre-net`, `-dissect`, `-pcap`, `-proxy`, `-rules` → `net_pcap_open`, `net_dissect_pkt`, ecc.

### Sandbox (5)
`rustre-sandbox`, `-extract`, `-monitor`, `-report`, `-vm` → `sandbox_run`, `sandbox_report_html`, ecc.

### Scripting (4)
`rustre-script`, `-lua`, `-python`, `-rhai` → `script_<lang>_eval`, `script_<lang>_run_file`.

### Symbolic execution (4)
`rustre-symb`, `-engine`, `-taint`, `-z3` → `symb_explore`, `symb_taint_track`, `symb_z3_solve`.

### Symbols (5)
`rustre-symbols`, `-codeview`, `-dwarf`, `-stabs` → `symbols_<fmt>_load`, `symbols_<fmt>_query` (PDB già presente parziale).

### Syscalls (3)
`rustre-syscalls`, `-linux`, `-windows` → `syscalls_<os>_lookup`, `syscalls_<os>_signature`.

### Threat intel (8)
`rustre-threatintel`, `-correlate`, `-malpedia`, `-misp`, `-opencti`, `-otx`, `-shodan`, `-vt` → `ti_<src>_query`, `ti_correlate_iocs`.

### Tracing (5)
`rustre-trace`, `-coresight`, `-coverage`, `-navigate`, `-pt` → `trace_pt_decode`, `trace_coverage_merge`, ecc.

### Triage estesi (4)
`rustre-triage-die`, `-entropy`, `-peid`, `-yara` → `triage_die_detect`, `triage_peid_match`, ecc.

### TTD (5)
`rustre-ttd`, `-query`, `-recorder`, `-replay`, `-replayer` → `ttd_record`, `ttd_replay_open`, `ttd_query`.

### Altri (4)
- `rustre-adb` → `adb_devices`, `adb_pull`, `adb_push`
- `rustre-analysis-callconv` → `analysis_callconv_infer`
- `rustre-analysis-vsa` → `analysis_vsa_run`
- `rustre-analysis-vtable` → `analysis_vtable_recover`
- `rustre-crypto-oracle`, `rustre-crypto-whitebox` → `crypto_oracle_attack`, `crypto_whitebox_extract`
- `rustre-diff-bindiff`, `-semantic` → già esposti via `rustre-diff` (probabile duplicato, verificare)
- `rustre-flirt-apply`, `-gen` → già coperti via `rustre-flirt` (verificare)
- `rustre-pe-rebuild`, `-tools` → `pe_rebuild_iat`, `pe_tools_strip`
- `rustre-yara`, `rustre-yara-rules` → coperti da `rustre-yara-engine` (probabile facade)

## Tool rotti / problemi funzionali

### Bug reali (da investigare)

1. **`project.open`** — restituisce errore "cannot read ..." anche per binari validi. Possibile bug nel resolution path o nel reporting. Da rieseguire con file esistente; se ancora fallisce è un bug.
2. **`disasm.at`** — sanity test fallisce con "missing 'address'" pur passando `addr`. **Schema parametri inconsistente**: alcuni tool accettano `addr`, altri `address`. Standardizzare.
3. **`debug.remove_breakpoint`** — fallisce con "missing 'bp_id'" pur ricevendo `bp_id: 1`. Probabile aspettativa di stringa ("bp-...") vs int. Validazione parametri da uniformare.
4. **`debug.read_memory`, `debug.write_memory`** — richiedono `binary_id` non documentato (manca dalla descrizione tool).
5. **`kg.query`** — accetta solo SELECT ma non documenta il vincolo nell'errore in modo utile.
6. **`kg.search`** — schema usa `query` ma il test ha passato `text`. Documentazione/schema disallineati.
7. **`patch_bytes`, `patch_xor_region`** — accettano hex ma errore poco chiaro su input "test". OK come validazione, ma il messaggio "invalid digit" andrebbe migliorato.
8. **`patch_asm`** — restituisce "unsupported asm mnemonic". Indicare l'elenco mnemonics supportati nella description.

### Tool sospetti da approfondire (50 ERROR file-missing)
Tutti i tool path-based (`*_path`, `*_at_path`, patch su PE, decompile_function_path, diff_*, fingerprint_*, ecc.) sono falliti perché il binario di test non esisteva sul disco al momento del test. Rieseguire con binario valido per separare bug reali da problemi di setup.

## Raccomandazioni

1. **Priorità alta — sbloccare validazione funzionale**
   - Verificare presenza del binario `target/release/cargo-zyphora.exe` o adattare lo script di validazione a un file di test stabile committato in `tests/fixtures/`.
   - Rieseguire R26_FUNCTIONAL contro fixture reale per ottenere counts genuini di tool rotti.

2. **Priorità alta — standardizzazione schema parametri**
   - Uniformare `addr` vs `address` su tutti i tool (oggi mix incoerente, vedi `disasm.at`).
   - Tutti i debug tool dovrebbero ricevere `session_id` univocamente (no `binary_id` implicito).
   - Documentare l'elenco mnemonics in `patch_asm`.

3. **Priorità alta — chiudere gap su domini core mancanti**
   1. **Loader** (13 crate non esposti): bloccante per qualunque workflow path-based, perché senza loader generici non si caricano ELF/Mach-O/WASM/dotnet via MCP. Wrappare almeno `loader-elf`, `-macho`, `-wasm`, `-dotnet`, `-pe` (estendere).
   2. **Symbols** (5 crate): DWARF e CodeView sono fondamentali per il match con IDA. Esporre `symbols_dwarf_load`, `symbols_codeview_load`.
   3. **Architetture mainstream** (11 crate): ARM32, PPC, AVR mancanti — necessari per parità con IDA su firmware/IoT.
   4. **Decompiler estesi** (`decompiler-c`, `-cfs`, `-type`): emissione C reale e structuring.

4. **Priorità media — domini analitici avanzati**
   - Symbolic execution (`rustre-symb*`) e VSA/vtable: tool molto utili e crate già presenti, esporli.
   - Deobfuscation: esporre almeno `deobf-string`, `-opaque`, `-cff` (pattern molto comuni).
   - Emulazione (`emu-unicorn`, `emu-shellcode`).

5. **Priorità bassa — domini opzionali**
   - Threat intel, mobile, sandbox, fuzz: utili ma non bloccanti per parità con IDA Pro.
   - TTD: solo se serve time-travel reverse, marker.

6. **Pulizia copertura**
   - Verificare se `rustre-diff-bindiff`, `-semantic`, `-flirt-apply`, `-gen`, `rustre-yara`, `-yara-rules` sono davvero crate distinti o solo sotto-moduli già wrappati dal facade. Se sotto-moduli, marcare INTERNAL nello script di audit per ridurre i falsi positivi (oggi gonfiano il gap di 6 unità).

---

Generato da R26 audit pipeline. Vedi `R26_COVERAGE.json` e `R26_FUNCTIONAL.json` per dati raw.
