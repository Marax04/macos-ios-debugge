# rustre-arch-6502

## Scopo
Implementazione architettura MOS 6502, 65C02 e 65816 per RustRE Suite. Copre tutti i 56 opcode ufficiali 6502, tutte le addressing modes, cycle counts, opcode illegali/non documentati NMOS, estensioni 65C02 (BBR/BBS/RMB/SMB/STZ/TRB/TSB/WAI/STP) e 65816 (24-bit, native/emulation mode). Fornisce disassembler, lifter IL, emulatore software (con BCD e interrupt), assembler two-pass, ROM analyzer (iNES/NES, C64 PRG, Atari 2600, Apple II), test harness CPU, tracking zero-page e identificazione piattaforma via vector table.

Dipende solo da `rustre-core` (`Architecture`, `Instruction`, `InstrFlags`, `BranchInfo`, `RegisterInfo`, `CallingConvention`, `Address`, `Endian`, `CoreError`) + `serde`.

## Moduli pubblici
- `decoder_65c02`, `decoder_65816` — decoder estensioni ISA
- `lifter` — mapping istruzioni → IL
- `emulator` — software emulator
- `analysis` — function detection, vector tables, strings, entropy
- `cpu_tester` — TestCase/TestRunner/FlagChecker/CycleCounter + 100+ test
- `assembler_6502` — assembler two-pass con direttive, label, listing
- `mos6502_disassembler` — full 256-opcode table
- `mos6502_addressing_modes`, `mos6502_address_modes` — addressing decode, 64KB memory model
- `mos6502_rom_analyzer` — formati ROM
- `mos6502_zero_page` — tracking variabili ZP
- `mos6502_platform_vectors` — identificazione piattaforma via RESET/NMI/IRQ

## Public API principale (lib.rs)
- `pub const REG_A/X/Y/SP/PC/P: u32` — ID registri
- `mod status { pub const C/Z/I/D/B/U/V/N: u8 }` — bit flag status register
- `pub enum AddrMode` — 17 varianti (Implied, Accumulator, Immediate, ZeroPage[X|Y], Absolute[X|Y], Indirect, IndirectX, IndirectY, Relative, ZeroPageIndirect, AbsoluteIndirectX, RelativeLong, Illegal)
  - `pub const fn extra_bytes(self) -> u16`
  - `pub const fn name(self) -> &'static str`
- `pub struct OpcodeEntry { mnemonic, mode, flags, cycles, illegal, variant }`
- `pub enum CpuVariant { Cpu6502, Cpu65C02, Cpu65816, Illegal6502 }`
- `pub fn opcode_table(b: u8) -> Option<OpcodeEntry>` — lookup completo 256 byte
- `pub fn format_operand(mode: AddrMode, bytes: &[u8], pc: u64) -> String`
- `pub fn branch_target(pc: u64, bytes: &[u8]) -> Option<u64>`
- `pub enum CpuMode { Cpu6502, Cpu65C02, Cpu65816 }` + `name()`
- `pub struct Cpu6502Arch { mode, decode_illegal }`
  - `new()`, `new_65c02()`, `with_illegal_opcodes()`, `cycle_count(opcode) -> Option<u8>`
  - impl `Architecture` (rustre-core): `name`, `pointer_size = 2`, `endian = Little`, `disassemble(addr, bytes) -> Result<Instruction>`, `get_branches(instr) -> Vec<BranchInfo>`, `registers() -> Vec<RegisterInfo>` (A/X/Y/SP/PC/P), `calling_conventions()` (`6502_cc65`, `6502_kick`)
- `pub struct Cpu6502LinearDisassembler<'a>` — linear sweep, `Iterator<Item = Result<Instruction>>`; `new`, `offset`, `is_done`
- `pub struct DisasmResult { text, bytes_consumed }`
- `pub fn disassemble_one(data, offset, addr: u16) -> Option<DisasmResult>` — formato `"MNEM operand  ; mode_name"`
- `pub fn cycles(opcode: u8, crossed_page: bool) -> u8` — base + 1 per page-cross su AbsoluteX/Y, IndirectY
- `pub struct Cpu6502State { a, x, y, sp, pc, p }`
  - `reset(memory: &[u8;65536])` legge PC da $FFFC/$FFFD, SP=0xFD, P=U|I
- `pub fn execute_one(state, memory) -> u8` — esegue 1 istruzione, ritorna cycles
- `pub struct MemoryBus6502`, `pub struct Cpu6502EmuState`, `pub struct Cpu6502`
- `pub const RESET_VECTOR: u16 = 0xFFFC`
- `pub fn disassemble_range(data, start_addr: u16, n_instrs) -> Vec<String>`

## Ground truth verificabile esternamente
- **Opcode map**: tabella 256-entry confrontabile con masswerk.at/6502/6502_instruction_set.html, Visual6502, py65, MAME m6502 core.
- **Cycle counts**: Synertek 6502 datasheet, WDC W65C02S datasheet, Bruce Clark "65C816 Opcodes".
- **Reset vector $FFFC/$FFFD**, stack page $0100–$01FF, SP=$FD post-reset — standard NMOS 6502.
- **Status flags layout** (NV-BDIZC) — datasheet ufficiale.
- **Illegal opcodes** (SLO, RLA, SRE, RRA, SAX, LAX, DCP, ISC, ANC, ALR, ARR, AXS, AHX, TAS, LAS, XAA, KIL): nesdev.org wiki, "NMOS 6510 Unintended Opcodes" by Graham.
- **65C02 additions** (BRA $80, STZ, TRB, TSB, PHX/PLX/PHY/PLY, INC/DEC A): WDC datasheet.
- **Page-crossing penalty**: documentata per AbsoluteX/Y, IndirectY load (non per store) — concordante con la logica di `cycles()`.
- **Test ROM**: Klaus Dormann 6502_functional_test.bin (de-facto suite di conformità) eseguibile tramite l'emulatore per validazione end-to-end.
- **Disasm output verificabile** con ca65/da65, ACME, Easy6502.

## Tool MCP esistenti applicabili
- `mcp__rustre-mcp__analysis_disasm_at_path` — disasm generico path-based (probabile dispatch per arch).
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_xref_*`, `analysis_callgraph_path`, `analysis_basic_blocks_path` — usano l'`Architecture` trait, quindi beneficiano di questo crate quando registrato.
- `mcp__rustre-mcp__decompile_function_path` — via lifter IL.
- Nessun tool MCP dedicato 6502/65C02/65816 specifico (es. `*_arm64`, `*_mips`, `*_riscv`, `*_wasm`, `*_cil`, `*_jvm` esistono — manca `*_6502`). Possibile gap.
- `mcp__rustre-mcp__binary_info` / `triage_analyze` per identificare ROM (iNES/PRG) richiamerebbe `mos6502_rom_analyzer`.

## Testabilità
Sì — il crate ha `tests/` dir, `cpu_tester` con 100+ test integrati, lookup tabellare deterministico (`opcode_table`), state machine pura (`Cpu6502State::reset`, `execute_one`) confrontabile bit-per-bit contro Klaus Dormann functional test e contro emulatori di riferimento (py65, Visual6502). Cycle counts e flag effects verificabili contro datasheet.
