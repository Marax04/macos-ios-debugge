# rustre-arch-68k

## Scopo
Implementazione completa dell'architettura Motorola 68000 (M68000/68010/68020/68030/68040/68060) per RustRE: decoder ISA, disassembler lineare e ricorsivo, FPU 68881/68882, MMU, addressing modes, exception vectors, calling conventions, CFG, xref, idiom detection, prologo/epilogo, ABI OS-level (Amiga, Mac 68k, Sun-3), lifter LLIL, encoder per istruzioni comuni.

## Dipendenze
- `rustre-core` (Architecture trait, Address, Endian, CoreError, Instruction, InstrFlags, BranchInfo, RegisterInfo, CallingConvention)
- `thiserror`, `bitflags`, `serde`

## Public API (signature principali)

### Tipi base
- `enum Mc68kVariant { M68000, M68010, M68020, M68030, M68040, M68060, ColdFire, CPU32 }`
- `enum Size { Byte, Word, Long }`
- `enum CondCode` (16 condizioni 68k)
- `enum EaKind` (effective address kinds)
- `struct Mc68kArch` — implementa `rustre_core::arch::Architecture`
- `struct OpcodeEntry` — tabella opcode statica
- `struct Decoded68k` — risultato decode raw

### Decoding
- `fn parse_ea(mode: u8, reg: u8, size: Size, ext: &[u8]) -> Result<(EaKind, usize), CoreError>`
- `fn decode_68k(bytes: &[u8], pc: u64) -> Result<(String, String, usize, InstrFlags), CoreError>` — entry point principale (mnemonic, operands, size, flags)
- `fn decode_68k_group0..group_f(word: u16, ext: &[u8][, pc]) -> Result<Decoded68k, CoreError>` — un decoder per ogni gruppo di 4 bit alti
- `fn decode_fpu_instr(...)` — coprocessore FPU
- `fn lookup_opcode(word: u16) -> Option<&'static OpcodeEntry>`

### Encoding
- `fn encode_moveq(dn: u8, imm: i8) -> [u8; 2]`
- `fn encode_bra8(disp: i8) -> [u8; 2]`
- `fn encode_bsr8(disp: i8) -> [u8; 2]`
- `fn encode_trap(vector: u8) -> [u8; 2]`
- `fn encode_clr(size: Size, dn: u8) -> [u8; 2]`
- `fn encode_addi_word(imm: u16, dn: u8) -> [u8; 4]`
- `fn encode_subq_word(data: u8, dn: u8) -> [u8; 2]`
- `fn encode_link(an: u8, disp: i16) -> [u8; 4]`
- `fn encode_unlk(an: u8) -> [u8; 2]`
- `fn encode_dbra(dn: u8, disp: i16) -> [u8; 4]`
- `fn encode_register_mask(regs: &[&str], predecrement: bool) -> u16`
- `fn decode_register_mask(mask: u16, predecrement: bool) -> String`

### Disassembler
- `struct Mc68kLinearDisassembler<'a>` — sweep lineare
- `struct Mc68kRecursiveDisassembler<'a>` — recursive descent
- `struct DisasmOptions`
- `fn format_instr(instr: &Instruction, opts: &DisasmOptions) -> String`
- `fn format_listing(instrs: &[Instruction], opts: &DisasmOptions) -> String`

### Analisi
- `struct AnalysisResult` + `fn analyze(base: Address, bytes: &[u8]) -> AnalysisResult`
- `fn build_cfg(instrs: &[Instruction]) -> Vec<BasicBlock>`
- `fn build_xrefs(instrs: &[Instruction]) -> Vec<Xref>`
- `fn find_stack_frames(instrs: &[Instruction]) -> Vec<StackFrame>`
- `fn detect_prologue(instrs, max) -> PrologueKind` / `fn detect_epilogue(instrs) -> bool`
- `fn detect_68k_prologue(instrs) -> Option<i16>` (link-frame size)
- `fn detect_68k_epilogue(instrs) -> bool`
- `fn find_idioms(instrs) -> Vec<(usize, &'static str)>`
- `fn instr_matches(instr, pat: &str) -> bool`
- `fn is_nop / is_control_transfer / modifies_ccr(instr) -> bool`
- `fn moveq_value(word: u16) -> i32`
- `fn branch_displacement(from_pc, target, use_long) -> Option<i32>`
- `fn branch_hint(instr, target) -> BranchHint`
- `fn count_movem_regs(mask) -> u32` / `fn movem_reg_names(mask) -> Vec<String>`
- `fn calling_conventions_for(variant: Mc68kVariant) -> Vec<CallingConvention>`

### BCD aritmetica
- `fn abcd_byte(src, dst, x) -> (u8, bool, bool)`
- `fn sbcd_byte(src, dst, x) -> (u8, bool)`

### Patching
- `enum PatchResult`
- `fn nop_sled(buf: &mut [u8]) -> PatchResult`
- `fn patch_call_target(buf, new_target: u32) -> bool`

### Platform-specific
- `fn is_amiga_library_call(instr) -> bool`
- `fn amiga_lvo(instr) -> Option<i16>` (Amiga Library Vector Offset)
- `enum ExceptionVector`, `enum KnownTrap`

### Lifter LLIL
- `enum M68kLlilOp`, `enum M68kArithOp`, `enum M68kCond`
- `fn m68k_lift(instr: &Instruction) -> Vec<M68kLlilOp>`

### Call graph & deps
- `struct M68kCallEdge`
- `fn m68k_build_call_graph(arch: &Mc68kArch, bytes: &[u8], base: Address) -> Vec<M68kCallEdge>`
- `struct M68kRegDep` + `fn m68k_find_deps(instrs) -> Vec<M68kRegDep>`
- `struct M68kHistogram`, `struct M68kReport`

### Reference tables
- `struct M68kInstrRef` + `fn lookup_68k_instr(mnemonic) -> Option<&'static M68kInstrRef>`
- `struct CcrEntry` + `fn lookup_ccr_effects(mnemonic) -> Option<&'static CcrEntry>`
- `struct M68kFpuInstr` + `fn lookup_fpu_instr(fop: u8) -> Option<&'static M68kFpuInstr>`
- `struct M68kRegConv`, `struct M68kVector`, `struct MulDivInfo`, `struct Symbol`, `struct SymbolTable`, `struct FpRegister`, `struct FpuRegFile`, `struct Pattern`

### Sotto-moduli pubblici
`m68k_analysis`, `m68k_os_abi`, `m68k_extensions`, `m68k_platforms`, `m68k_addressing_modes`, `m68k_exception_vectors`, `m68k_disassembler_ext`, `m68k_decoder`, `m68k_disassembler`, `m68k_registers`, `m68k_emulator`, `m68k_register_analyzer`, `m68k_calling_conventions`, `m68k_condition_codes`.

## Input / Output tipici
- Input: slice di byte big-endian + PC base; opcode word + extension words; `&Instruction` di `rustre-core`.
- Output: `Decoded68k`, `(mnemonic, operands, length, InstrFlags)`, `Vec<BasicBlock>`, `Vec<Xref>`, `Vec<M68kCallEdge>`, `Vec<M68kLlilOp>`, byte array codificati.

## Ground truth verificabile esternamente
- **Motorola M68000PRM** (Programmer's Reference Manual) — tabelle opcode, addressing modes, condition codes, exception vectors.
- **Motorola M68000UM / M68020UM / M68030UM / M68040UM / M68060UM** — varianti.
- **Motorola MC68881/MC68882 Floating-Point Coprocessor User's Manual** — FPU opcodes (fop byte), formati extended-precision.
- **GNU binutils `m68k-elf-objdump` / `m68k-elf-as`** — disassembly e encoding di riferimento; confronto byte-per-byte su corpus (es. Linux m68k, AmigaOS binari, ROM Sega Genesis).
- **vasm / vlink** (assembler 68k) — round-trip encode/decode.
- **Capstone** (`CS_ARCH_M68K`) e **Ghidra processor module `68000`** — confronto mnemonic/operandi.
- **AmigaOS LVO tables** (fd files in NDK) — verifica `amiga_lvo()` e `is_amiga_library_call()`.
- **Sega Mega Drive ROM headers / vector table** ($000000–$0000FF) — exception vectors.
- BCD: confronto con calcolatore decimale per `abcd_byte` / `sbcd_byte`.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (generic disasm via path; nessun endpoint specifico 68k — gap)
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_callgraph_path`, `analysis_basic_blocks_path` (consumano `Architecture` trait, quindi 68k accessibile se selezionato)
- `mcp__rustre-mcp__disasm_at`, `disasm_function`
- Manca tool MCP dedicato `analysis_disasm_at_path_m68k` analogo a `_arm64`/`_mips`/`_riscv`/`_wasm`/`_cil`/`_jvm` — **gap rispetto alle altre arch**.

## Testabilità
Sì: encoder deterministici (round-trip vs binutils/vasm), decoder testabile con vettori PRM, tabelle opcode/CCR/FPU verificabili contro documentazione Motorola, ROM pubbliche (Sega Genesis) come corpus reale. Directory `tests/` presente nel crate.
