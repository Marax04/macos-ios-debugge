# rustre-arch-avr

## Scopo
Implementazione dell'architettura Atmel AVR (Attiny, Atmega, Xmega) per la suite RustRE. Fornisce:
- Decoder di istruzioni AVR a 16 e 32 bit (NOP, ALU, load/store, branch, call, IO).
- Implementazione del trait `rustre_core::arch::Architecture` per integrazione nel core.
- Linear-sweep disassembler.
- Classificazione delle istruzioni (`AvrInstrKind`).
- Descrittori di device (ATmega328P, ATmega2560, ATtiny85, ATtiny13, ATxmega256A3U): flash/SRAM/EEPROM, mappa SFR, IVT, fuse bits.
- Decoder I/O (IN/OUT) con nomi/bitfield, mappe registri per ATmega328P/2560.
- Pattern di analisi codice di alto livello (prologue/epilogue PUSH R28/R29, string detector, bootloader patterns, signature scanner).
- Modello interrupt e vettori, mappa memoria programma.

## Public modules
- `avr_analysis`, `avr_emulator`, `avr_interrupt_model`, `avr_pgm_memory`
- `avr_code_analysis` (AvrPrologue, AvrEpilogue, AvrStringDetector, AvrBootloaderPattern, AvrSignatureScanner, AvrCodeAnalysis)
- `avr_devices` (ATmega/ATtiny/ATxmega descriptors)
- `avr_io_decoder` (IN/OUT decode + maps 328P/2560)
- `avr_decoder`, `avr_disassembler`, `avr_registers`, `avr_io_map`, `avr_io_registers`
- `avr_interrupt_vectors`, `avr_fuse_bits`

## Public types & API (lib.rs)
- `enum AvrVariant { Attiny, Atmega, Xmega }`
- `struct AvrArch { pub variant: AvrVariant }`
  - `pub const fn new(variant: AvrVariant) -> Self`
  - `impl Default` (Atmega)
  - `impl Architecture`:
    - `fn name(&self) -> &str` → "avr-tiny" | "avr-mega" | "avr-xmega"
    - `fn pointer_size(&self) -> usize` → 2
    - `fn endian(&self) -> Endian` → Little
    - `fn disassemble(&self, addr: Address, bytes: &[u8]) -> Result<Instruction, CoreError>`
    - `fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo>`
    - `fn registers(&self) -> Vec<RegisterInfo>` → 38 (R0..R31 + SREG + SP + PC + X + Y + Z)
    - `fn calling_conventions(&self) -> Vec<CallingConvention>` → "avr_gcc" (args R24/R22/R20, ret R24:R25)
- `struct AvrLinearDisassembler<'a>`
  - `pub const fn new(arch, bytes, base: Address) -> Self`
  - `impl Iterator<Item = Result<Instruction, CoreError>>`
- `enum AvrInstrKind { Nop, Arithmetic, Logic, Shift, Compare, Transfer, Load, Store, Io, Stack, CondBranch, Branch, Call, Return, BitOp, System, Unknown }`
  - `pub fn from_mnemonic(mn: &str) -> Self`
  - `pub const fn is_control_flow(&self) -> bool`
  - `pub const fn is_memory(&self) -> bool`
  - `pub fn is_io(&self) -> bool`
- `struct AvrIoReg { pub addr: u8, pub name: &'static str, pub description: &'static str }`
- `pub static ATMEGA328P_IO_MAP: &[AvrIoReg]`

## Input/Output
- Input: bytes raw AVR (little-endian), `Address` PC corrente, mnemonici per classificazione.
- Output: `Instruction { address, size (2 o 4), mnemonic, operands, raw, flags }`, `BranchInfo` con target a 22-bit (mask 0x3F_FFFF), elenco `RegisterInfo`, `CallingConvention`.

## Ground truth verificabile esternamente
Encoding AVR coperto dal "Atmel AVR Instruction Set Manual" (DS40002198, Microchip/Atmel). Verificabili via:
- `avr-objdump -D -m avr` (binutils): disassemblaggio di riferimento (mnemonici, dimensioni 2/4 byte, target RJMP/RCALL/JMP/CALL relativi/assoluti).
- `avra` / `avr-as`: assembla pattern noti (NOP=0x0000, RET=0x9508, RETI=0x9518, SLEEP=0x9588, WDR=0x95A8, BREAK=0x9598, IJMP=0x9409, ICALL=0x9509) e confronta byte→mnemonic.
- Encoding bitfield (ADD 0000 11rd dddd rrrr, LDI 1110 KKKK dddd KKKK, RJMP 1100 kkkk kkkk kkkk con sign-ext a 12 bit, JMP/CALL 32-bit con k_hi/k_lo) verificabili dal manuale.
- Calling convention avr-gcc (args R25:R24, R23:R22, R21:R20; ret R25:R24) documentata in avr-libc / GCC AVR ABI.
- Mappe SFR ATmega328P/2560 vs datasheet Microchip ufficiale.
- Fuse bits, IVT, dimensioni flash/SRAM/EEPROM vs datasheet per device.

## Tool MCP RustRE esistenti rilevanti
- `mcp__rustre-mcp__analysis_disasm_at_path` (generico, dispatch per arch) — potrebbe instradare ad AVR se l'arch è registrata nel registry core.
- Nessun `analysis_disasm_at_path_avr` dedicato nella lista MCP (presenti: arm64, cil, jvm, mips, riscv, wasm). AVR esposto solo come crate library, non come endpoint MCP dedicato.
- `mcp__rustre-mcp__analyze_function`, `analyze_call_graph`, `analyze_basic_block` possono operare su AVR se il loader registra `AvrArch`.
- `mcp__rustre-mcp__binary_info`, `binary_hexdump`, `binary_search_bytes` agnostici.

## Testabile
Sì. La crate include 47+ unit test interni (`#[cfg(test)] mod tests`) che validano encoding/decoding di NOP, RET, RETI, LDI, ADD, RJMP, RCALL, PUSH, POP, BREQ/BRNE/BRCS, JMP/CALL 32-bit, IN/OUT, ADIW/SBIW, SEI/CLI, EOR, MOV/MOVW, IJMP/ICALL, SLEEP, WDR, BREAK, SUB, AND, OR, MUL, MULS, LSR/ROR/ASR, COM/INC/DEC/NEG/SWAP, ANDI/ORI, LD/ST X, LDS/STS, LPM, CPSE, SBRC/SBRS, CP/CPI, BST/BLD, SBI/CBI, conteggio registri, variante name, target branch extraction. Esiste anche directory `tests/` per test di integrazione. Cross-check possibile con avr-objdump.
