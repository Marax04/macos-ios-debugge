# rustre-arch-z80

## Scopo
Implementazione dell'architettura Zilog Z80 per la suite RustRE: decoder/disassembler/encoder/emulator per l'ISA Z80 (8080-compatibile + estensioni Z80), incluse tabelle prefisso CB/ED/DD/FD, opcode undocumented (IXH/IXL/SLL/DDCB/FDCB), modelli I/O, pattern OS (CP/M BDOS, ZX Spectrum ULA, MSX BIOS, Game Boy SM83), rilevazione piattaforma e header ROM, oltre ad analisi linear-sweep con statistiche T-state.

## Dipendenze
- `rustre-core` (Architecture trait, Instruction, InstrFlags, Address, Endian, CoreError)
- `bitflags`, `serde`

## Public API (firme principali, niente codice)

### lib.rs (root)
- `const REG_A..REG_HL2: u32` — ID registri (A,B,C,D,E,H,L,F,I,R,AF,BC,DE,HL,SP,PC,IX,IY,AF',BC',DE',HL').
- `struct Flags: u8` (bitflags) — C, N, PV, F3, H, F5, Z, S.
- `struct Decoded { mnemonic: String, operands: String, size: usize, flags: InstrFlags }`.
- `fn decode_main(bytes: &[u8], pc: u64) -> Result<Decoded, CoreError>` — decode unprefixed (+CB inline).
- `struct CycleInfo { cycles: u8, cycles_taken: u8 }`.
- `fn opcode_cycles(op: u8) -> CycleInfo` — T-state per opcode singolo byte.
- `enum InterruptMode { Mode0, Mode1, Mode2 }` con `from_str(&str) -> Option<Self>`, `operand() -> &'static str`.
- `struct OpcodeEntry { opcode, mnemonic, min_size, flags_bits, cycles }` + `flags() -> InstrFlags`.
- `static OPCODE_TABLE: &[OpcodeEntry]` — quick lookup di opcodes chiave.
- `fn find_opcode_entry(op: u8) -> Option<&'static OpcodeEntry>`.
- Encoders: `encode_nop`, `encode_halt`, `encode_ret`, `encode_jp(u16)`, `encode_call(u16)`, `encode_jr(i8)`, `encode_djnz(i8)`, `encode_ld_r_n(reg,n)`, `encode_ld_bc_nn`, `encode_ld_de_nn`, `encode_ld_hl_nn`, `encode_ld_sp_nn`, `encode_push(rp)`, `encode_pop(rp)`, `encode_rst(vec)`, `encode_ei`, `encode_di`.
- `struct Z80LinearDisassembler<'a>` + `new`, `offset`, `is_done`; impl `Iterator<Item=Result<Instruction, CoreError>>`.
- `struct AnalysisResult { instructions, call_targets, branch_targets, returns, errors, total_cycles }` + `instr_count`, `has_calls`.
- `fn analyze(base: Address, bytes: &[u8]) -> AnalysisResult` — linear-sweep + statistiche.
- `struct InstrStats { loads, alu, bit_ops, block_ops, branches, calls, returns, stack, io, unknown }`.
- `struct Z80Arch` che implementa il trait `rustre_core::arch::Architecture`.

### Sottomoduli pub
- `z80_decoder`, `z80_disassembler`, `z80_emulator` — decoder/disasm/emu helpers.
- `z80_io_model`, `z80_io_ports` — modello I/O e porte hw note.
- `z80_os_patterns` — CpMBiosCall, Z80BdosCall, ZxSpectrumPatterns, Z80BootloaderDetector, Z80SelfModifying, Z80OsPatterns.
- `z80_undocumented`, `z80_undocumented_opcodes` — IXH/IXL/IYH/IYL, SLL, DDCB/FDCB, `undoc_decode`, `Z80FullDecoder`.
- `z80_platforms`, `z80_platform_detector` — ZX Spectrum/MSX/CP/M/Game Boy SM83.
- `z80_registers`, `z80_register_pairs`, `z80_prefix_tables`, `z80_rom_header`.

Totale: 257 simboli `pub` su 15 file.

## Input/Output
- Input principale: byte slice di codice Z80 (`&[u8]`) + indirizzo base (`Address` / `u64` PC).
- Output: `Decoded` / `Instruction` / `AnalysisResult` / array di byte per gli encoder / `Option<&OpcodeEntry>`.
- Errori: `rustre_core::errors::CoreError::InvalidFormat` per slice troncati / opcode incompleti.

## Ground truth verificabile esternamente
Tutti i mnemonici, dimensioni e T-state sono verificabili contro la documentazione ufficiale Zilog:
- **Zilog Z80 CPU User Manual** (UM008011-0816) — tabelle opcode unprefixed/CB/ED/DD/FD, T-state.
- **The Undocumented Z80 Documented** (Sean Young) — opcode IXH/IXL/IYH/IYL, SLL, DDCB/FDCB, flags F3/F5.
- **ClrHome Z80 instruction set** (clrhome.org/table/) — quick reference mnemonici + cycles.
- **z80.info / z80-heaven** — encoding x/y/z/p/q decomposition usata in `decode_main`.
- Test vector di riferimento: `zexall` / `zexdoc` test suite (Frank Cringle) per verificare flag e cycle.
- Encoding noti: NOP=0x00, HALT=0x76, RET=0xC9, JP nn=0xC3, CALL nn=0xCD, JR=0x18, DJNZ=0x10, DI=0xF3, EI=0xFB, EXX=0xD9 — direttamente confermabili dal manuale.
- Interrupt modes IM 0/1/2 via prefisso ED (0x46/0x56/0x5E) — Zilog manuale §6.

## Tool MCP esistenti utili per validazione
- `mcp__rustre-mcp__analysis_disasm_at_path` — disasm generico (architettura selezionabile).
- `mcp__rustre-mcp__analysis_fn_detect_functions_path` — function detection per binari Z80 (es. ROM ZX Spectrum / .sna / .tap / GameBoy `.gb` per SM83).
- `mcp__rustre-mcp__binary_info`, `binary_hexdump`, `binary_search_bytes` — ispezione raw delle ROM Z80.
- `mcp__rustre-mcp__analysis_xref_*` — xref su entry point Z80 (RST vectors 0x00/0x08/.../0x38, NMI 0x66).
- Nessun tool MCP dedicato `disasm_at_path_z80` risulta presente — la copertura Z80 passa per il dispatcher generico di `analysis_disasm_at_path`. Verificare che `Z80Arch` sia registrata nel dispatcher core.

## Testabilità
- Cargo.toml dichiara cartella `tests/` (test di integrazione).
- Encoders/decoders sono pure function deterministiche → unit test banali (round-trip encode/decode).
- Cycle counts verificabili contro tabella Zilog → test tabellari fattibili.
- Emulator + io_model: testabili con sequenze brevi note (es. somma 8-bit, LDIR di N byte).
- **testable: true**.
