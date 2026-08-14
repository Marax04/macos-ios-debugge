# rustre-arch-sparc

## Scopo
Backend di architettura SPARC (V8 + V9) per RustRE: decodifica/encoding istruzioni, disassembly lineare e annotato, gestione delay-slot, register windows (save/restore), trap tables, ABI/calling convention, lifter verso IL, emulazione, e helper sintetici (synth_*). Estende `rustre-core` con un `SparcArch` e tabelle complete (FP opcodes, ASI, condition codes, registri privilegiati, trap).

## Dipendenze
- rustre-core (path)
- serde, thiserror, ahash

## Moduli src
- lib.rs (SparcArch, disassembler, encode_*, synth_*, lookup tables)
- sparc_v9.rs (decode V9)
- sparc_decoder.rs (reg_name, freg_name)
- sparc_delay_slot.rs / sparc_delay_slot_analyzer.rs
- sparc_register_windows.rs (save/restore analysis)
- sparc_register_file.rs / sparc_registers.rs
- sparc_calling_conv.rs (leaf classification, call arg inference)
- sparc_trap_table.rs / sparc_trap_handler.rs
- sparc_emulator.rs, sparc_lifter.rs, sparc_analysis.rs

## Public API (firme principali)
### Encoding (lib.rs)
- `encode_call(disp: i32) -> u32`
- `encode_sethi(rd: u32, imm22: u32) -> u32`
- `encode_nop() -> u32`
- `encode_alu_reg(op3, rs1, rs2, rd) -> u32`
- `encode_alu_imm(op3, rs1, simm13, rd) -> u32`
- `encode_load(op3, rs1, simm13, rd) -> u32`
- `encode_store(op3, rs1, simm13, rd) -> u32`
- `encode_bicc(cond: u32, annul: bool, disp: i32) -> u32`
- `encode_jmpl(rs1, simm13, rd) -> u32`

### Synthetic instructions
- `synth_mov_imm/reg`, `synth_clr`, `synth_not`, `synth_neg`, `synth_tst`,
- `synth_cmp_reg/imm`, `synth_inc`, `synth_dec`, `synth_set(val,rd) -> Vec<u32>`

### Prologo/epilogo/return
- `build_prologue(framesize: u32) -> u32`
- `build_epilogue() -> [u32; 2]`
- `build_return_seq() -> [u32; 2]`

### Lookup tables
- `lookup_v8_trap(u8) -> Option<&'static SparcTrapEntry>`
- `lookup_v9_trap(u8) -> Option<&'static SparcTrapEntry>`
- `lookup_fp_opcode(u16) -> Option<&'static SparcFpOp>`
- `lookup_asi(u8) -> Option<&'static SparcAsiEntry>`
- `lookup_condition(u8) -> Option<&'static SparcCondEntry>`
- `lookup_priv_reg(u8) -> Option<&'static SparcPrivReg>`

### Disassembly / printing / idioms
- `sparc_print_gnu(&Instruction) -> String`
- `sparc_print_sun(&Instruction) -> String`
- `disassemble_annotated(...)`
- `resolve_branches(&[AnnotatedSparcInstr]) -> Vec<(Address,Address,bool,bool)>`
- `format_annotated(&AnnotatedSparcInstr) -> String`
- `extract_branch_targets(bytes: &[u8], base: u64) -> Vec<(u64,u64)>`
- `identify_idiom(first, second) -> SparcIdiom`

### V9 (sparc_v9.rs)
- `decode_v9_instr(word: u32) -> Option<V9Instr>`
- `roundtrip_mulx(rs1, simm13, rd)`, `roundtrip_flushw()`

### Delay slot
- `analyze_branch(pc, branch_word, delay_word) -> Option<SparcDelaySlot>`
- `is_nop(word: u32) -> bool`

### Register windows
- `total_physical_regs(nwindows: u8) -> usize`
- `save_restore_analysis(&[WindowInstr], nwindows) -> SaveRestoreAnalysis`
- `classify_window_instrs(&[u32]) -> Vec<WindowInstr>`
- `is_save(u32) -> bool`, `is_restore(u32) -> bool`

### Calling convention
- `classify_leaf(words: &[u32]) -> LeafClassification`
- `infer_call_args(instrs_before_call: &[u32]) -> Vec<CallArg>`

### Decoder helpers
- `reg_name(r: u8) -> &'static str`
- `freg_name(r: u8) -> String`

### Trap tables
- `sparc_v8_trap_table() / sparc_v9_trap_table() -> SparcTrapTable`
- `sparc_v8_trap_map() / sparc_v9_trap_map() -> HashMap<u8, TrapEntry>`
- `trap_name(tt) / trap_name_v9(tt) -> Option<String>`

## Tipi pubblici principali
`SparcArch`, `SparcLinearDisassembler<'a>`, `SparcInstrKind`, `SparcDelayInfo`,
`SparcBasicBlock`, `SparcCodeStats`, `SparcTrapEntry`, `SparcFpOp`, `SparcAsiEntry`,
`SparcCondEntry`, `SparcPrivReg`, `AnnotatedSparcInstr`, `SparcIdiom`, `V9Instr`,
`WindowInstr`, `SaveRestoreAnalysis`, `LeafClassification`, `CallArg`,
`SparcDelaySlot`, `SparcTrapTable`, `TrapEntry`.

## Input / Output
- Input: word a 32 bit (`u32`), slice `&[u8]` di codice con base address `u64`, sequenze `&[u32]`.
- Output: strutture decodificate (`V9Instr`, `AnnotatedSparcInstr`), parole codificate `u32`/`Vec<u32>`, stringhe di disassembly, tabelle statiche, target di branch.

## Ground truth verificabile esternamente
- **SPARC V8 Architecture Manual** (formati istruzioni, opcode op/op2/op3, trap numbers, condition codes).
- **SPARC V9 Architecture Manual** (mulx, flushw, registri privilegiati, ASI map).
- **GNU binutils `gas`/`objdump`** per SPARC: confronto encoding e mnemonics (gnu vs sun syntax).
- **GCC/Solaris ABI** per leaf function classification, save/restore window, register %o/%i/%l/%g, %o6=sp, %i7=ret addr.
- **delay slot semantics**: branch annul bit, BA, conditional branches (sezione 6 V8 manual).
- Round-trip encode_* -> decode_v9_instr / decoder verificabile via test bit-pattern.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (architettura-agnostico) — SPARC non è tra i wrapper specifici disponibili (`_arm64`, `_cil`, `_jvm`, `_mips`, `_riscv`, `_wasm`); SPARC è raggiunto solo via `SparcArch` registrato in core/dispatcher di disasm, **non c'è tool MCP dedicato `_sparc`**.
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_xref_*`, `decompile_function_path` operano via core e useranno questo backend solo se il binario è riconosciuto come SPARC.
- Nessun tool MCP espone direttamente `lookup_v8_trap`, `lookup_fp_opcode`, `lookup_asi`, `classify_leaf`, `save_restore_analysis`, `analyze_branch`: testabili solo via unit-test del crate (`tests/`).

## Testabilità
- Encoding/synth/build_* : verificabili bit a bit contro V8 manual + binutils.
- decode_v9_instr: verificabile round-trip e contro objdump.
- Trap/ASI/FP/cond tables: verificabili contro manuali V8/V9.
- Register window analysis: verificabile su sequenze save/restore note.
- Calling convention/leaf: verificabile su output GCC SPARC.

testable: true
