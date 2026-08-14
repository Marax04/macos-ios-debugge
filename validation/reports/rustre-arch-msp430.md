# rustre-arch-msp430

## Scopo
Implementazione dell'architettura Texas Instruments MSP430 (16-bit) e MSP430X (estensioni 20-bit) per la suite RustRE. Fornisce decoder, disassembler (linear + recursive), lifter IL, emulatore step-level con modello periferiche, e analisi di alto livello (memory map, power mode, watchdog, flash, bootloader, ISR detection, xrefs).

## Dipendenze
- `rustre-core` (Architecture trait, Address, Endian, errors, InstrFlags)
- `serde` (derive)

## Moduli pubblici
- `decoder`, `disassembler`, `lifter`, `emulator`, `analysis`
- `msp430_decoder`, `msp430_full_decoder` (Format I/II/III + MSP430X PUSHM/POPM/RPT/MOVA/CMPA/ADDA/SUBA)
- `msp430x_extended` (20-bit, RRCM/RRUM/RLAM/RRAM, CALLA/RETA, BRA)
- `msp430_registers`, `msp430_addressing_modes`, `msp430_calling_convention`
- `msp430_sfr_map`, `msp430_peripherals`, `msp430_peripheral_map`
- `msp430_interrupt_table`, `msp430_interrupt_vectors`
- `msp430_analysis` (MemoryMapAnalyzer, PowerModeAnalysis, CriticalSectionDetector, WatchdogPatterns, FlashWriteDetector, BootloaderAnalysis)
- Inline: `regs`, `sr_bits`, `msp430x`

## Public functions / types principali (lib.rs)
| Nome | Input | Output |
|------|-------|--------|
| `InterruptVector::address` | self | `u16` (es. Reset = 0xFFFE) |
| `InterruptVector::name` | self | `&'static str` |
| `InterruptVector::all` | — | `&'static [Self]` |
| `AddrMode::ext_words` | self | `usize` (0 o 1) |
| `AddrMode::reads_memory` / `writes_memory` | self | `bool` |
| `constant_generator(reg, as_bits)` | `u8,u8` | `Option<i8>` (CG: 0,1,2,4,8,-1) |
| `src_addr_mode(as_bits, reg)` | `u8,u8` | `AddrMode` |
| `reg_name(r)` | `u8` | `&'static str` (PC/SP/SR/CG/R4..R15) |
| `bw_suffix(bw)` | `u8` | `".B"` o `".W"` |
| `format_src` / `format_dst` | mode/reg/ext | `String` (sintassi AT&T) |
| `check_emulated(...)` | opcode4/regs/as/ad/bw | `Option<&str>` (CLR/RET/INC/DEC/INV/NOP) |
| `decode(bytes, pc)` | `&[u8], u64` | `Result<DecodedInstr, CoreError>` |
| `RegisterFile::{new,read,write,pc,sp,sr,carry,zero,negative,overflow,push,pop,update_flags_word/byte}` | — | manipolazione 16x16-bit regfile |
| `alu_add/addc/sub/subc/and/bis/xor/rrc/rra/swpb/sxt` | `u16,...` | `AluResult { result, carry, overflow, zero, negative }` |
| `FlatMemory::{new,read_byte,write_byte,read_word,write_word,load,reset_vector}` | indirizzi 16-bit | mem 64KiB |
| `Msp430Emulator::{new,reset,read_src_operand,step}` | — | esecuzione single-step |
| `build_cfg(bytes, base, entry, max_blocks)` | — | `Result<Vec<BasicBlock>, CoreError>` |
| `encode_jump(cond, offset)` | `u8,i16` | `Result<u16, CoreError>` |
| `encode_two_op(...)` / `encode_single_op(...)` | campi encoding | `Result<u16, CoreError>` |
| `msp430x::is_extension_word/decode_format_a/decode_rotate_extended/decode_pushm_popm/encode_extension_word/max_address` | varie | encoding 20-bit |
| `Msp430Arch` | — | impl `Architecture` di rustre-core |
| `Msp430LinearDisassembler<'a>` | slice + base | iteratore disasm lineare |

## Ground truth verificabile esternamente
- **ISA reference**: TI SLAU144J/SLAU208 (MSP430x2xx / MSP430x5xx Family User's Guide) — definisce esattamente Format I/II/III, constant generator R2/R3 (valori 0,1,2,4,8,-1), bit del SR (C/Z/N/GIE/CPUOFF/OSCOFF/SCG0/SCG1/V), vettori interrupt 0xFFE0-0xFFFE, reset vector a 0xFFFE.
- **Encoding**: confrontabile con `msp430-elf-gcc` + `objdump -d` su .elf di esempio (TI MSP-EXP430G2 demos).
- **Emulator**: confronto step-by-step con `mspdebug` simulatore o `msp430-elf-gdb` su programmi noti.
- **Emulated mnemonics** (CLR/INC/DEC/INV/NOP/RET): definite in SLAU144 §3.4.5 "Emulated Instructions".
- **MSP430X extension word**: prefisso `0001 1xxx xxxx xxxx` da SLAU208 cap. 4.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (nessuna variante msp430 dedicata — usa quella generica)
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_fn_cfg_path`, `analysis_callgraph_path`
- `mcp__rustre-mcp__decompile_function_path`, `decompiler_core_batch_decompile`
- `mcp__rustre-mcp__analysis_infer_types_path`, `analysis_recover_structs_path`
- `mcp__rustre-mcp__binary_info`, `analyze_full`
- Nessun tool MCP `*_msp430` o `*_arm64/cil/jvm/mips/riscv/wasm` esposto specificamente per MSP430 (le varianti per altre arch esistono: `analysis_disasm_at_path_arm64/cil/jvm/mips/riscv/wasm`). **Gap**: manca esposizione `analysis_disasm_at_path_msp430`.

## Testabilità
Sì — il crate ha directory `tests/`, funzioni pure (`alu_*`, `decode`, encoders), tabelle deterministiche (interrupt vectors, SFR map, constant generator) verificabili con vettori da TI datasheets e `msp430-elf-gcc` round-trip.
