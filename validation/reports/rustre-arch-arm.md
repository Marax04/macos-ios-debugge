# rustre-arch-arm

## Scopo
Backend di architettura ARM 32-bit per RustRE. Implementa il trait `Architecture`
di `rustre-core` per A32 (ARM) e T32 (Thumb / Thumb-2), in little- e big-endian.
Copre decoding di istruzioni, semantica (CPSR, ALU, barrel shifter, barriere,
LDREX/STREX), Thumb-2 estesa, coprocessore, NEON e VFP ARMv7, lifting verso LLIL,
oltre ad analisi di livello superiore (interworking ARM/Thumb, IT-block,
ARM ABI/AAPCS, profilazione funzioni).

## Dipendenze
- `rustre-core` (Architecture, Instruction, LiftContext, LlilOp, RegisterInfo, BranchInfo, CallingConvention, Address, Endian)
- `serde` (derive)

## Moduli pubblici
- `arm_thumb2` — decoder Thumb-2 (16/32-bit)
- `arm_instruction_semantics` — CPSR, ALU, shifter, barriere, exclusive monitor
- `coprocessor` — MRC/MCR e accessi coprocessore
- `neon` — decoder NEON SIMD
- `arm_analysis` — ThumbInterworking, ITBlockAnalyzer, ArmAbiDetector, PCSRelativeResolver
- `armv7_full` — set istruzioni ARMv7 esteso, lifter A32, AAPCS

## Tipi pubblici principali
- `ArmArch { mode: ArmMode, little_endian: bool }` — descrittore architettura
- `ArmMode { Arm, Thumb }`
- `ArmLinearDisassembler` — disassemblatore lineare streaming
- `ArmV7Full`, `ThumbExpanded`, `ThumbExpandedKind`
- `ArmCoprocessor`, `CoprocessorKind`
- `NeonFull`, `NeonKind`, `VfpFull`, `VfpKind`
- `ArmV7Lifter`, `V7LiftOp`, `V7BinOp`
- `ArmV7InstrClass`, `AapcsRole`
- `Condition`, `IsaMode`, `InterworkingEvent` (arm_analysis)
- `CpsrFlags`, `ConditionCode`, `ProcessorMode`, `ShifterResult`, `AluResult`,
  `MemBarrier`, `BarrierKind`, `BarrierOption` (arm_instruction_semantics)

## Funzioni pubbliche (selezione, firme)
### `lib.rs`
- `ArmArch::new_arm() -> Self`
- `ArmArch::new_thumb() -> Self`
- `ArmArch::new_arm_be() -> Self`
- `ArmMode::is_thumb(&self) -> bool`
- `ArmLinearDisassembler::disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError>`
- `sreg(n: u32) -> &'static str`

### `arm_thumb2`
- `Thumb16Instr::decode(hw: u16) -> Option<Self>`
- `Thumb16Instr::mnemonic(&self) -> String`
- `Thumb2Instr::decode(hw1: u16, hw2: u16) -> Result<Thumb2Instr, Thumb2DecodeError>`
- `Thumb2Instr::decode_word(word: u32) -> Result<Thumb2Instr, Thumb2DecodeError>`
- `decode_bytes(...)`

### `arm_instruction_semantics`
- `ConditionCode::{from_bits, encoding, mnemonic, evaluate, invert}`
- `CpsrFlags::{from_raw, from_flags, raw, n, z, c, v, q, t, mode, ge, with_nzcv, with_thumb, with_mode, with_irq_disabled}`
- `ProcessorMode::{from_bits, encoding, is_privileged, name, has_spsr}`
- `BarrelShiftType::{from_bits, name}`, `Shifter::{shift_immediate, lsl, lsr, asr, ror, rrx}`
- `Alu::{add, adc, sub, sbc, rsb, and, orr, eor, bic, mov, mvn, cmp, cmn, tst, teq, mul, umull, smull}`
- `MemBarrier::{new, dmb_sy, dsb_sy, isb_sy}`
- `ExclusiveMonitor::{new, mark_exclusive, attempt_store, clear, is_tagged, tagged_address}`
- `ArmCpu::{new, cpsr, spsr, write_cpsr, write_spsr, condition_passes, barrel_shift, apply_alu_flags, exception_entry, exception_return, ldrex, strex, clrex, decode_barrier}`
- Helper liberi: `is_unconditional`, `extract_condition`, `extract_s_bit`, `is_thumb_target`

### `armv7_full`
- `ThumbExpandedKind::classify(hw1, hw2) -> Self`
- `ThumbExpanded::decode(hw1, hw2) -> Self`
- `ArmCoprocessor::format(&self) -> String`
- `NeonFull::format(&self) -> String`
- `VfpFull::format(&self) -> String`
- `ArmV7InstrClass::classify_a32(word: u32) -> Self`
- `aapcs_role(n: u8) -> AapcsRole`
- `decode_bl_target(hw1: u16, hw2: u16, pc: u32) -> u32`

### `neon`
- Helper registri: `dreg`, `qreg`, `sreg` (per indice)
- Suffissi: `neon_size_suffix`, `neon_signed_suffix`, `neon_unsigned_suffix`,
  `neon_float_suffix`, `neon_poly_suffix`
- Decoder: `decode_neon_dp`, `decode_neon_ls`, `decode_neon_shift_imm`,
  `decode_neon_2reg_misc`, `decode_neon_table`, `decode_vdup`,
  `decode_neon_long_mul`, `decode_neon_fp`, `decode_neon_single_lane`
- Mnemonici: `neon_scalar_mnemonic`, `neon_pairwise_mnemonic`

## Input / Output
- **Input**: parole istruzione A32 (`u32`), halfword Thumb (`u16` / coppia
  `(u16,u16)`), o byte slice + `Address`. `CpsrFlags`/`ArmCpu` come stato di
  emulazione semantica.
- **Output**: `Instruction` (mnemonico, operandi, flags, branch info) o errori
  `CoreError`/`Thumb2DecodeError`; oppure strutture decodificate tipizzate
  (`Thumb2Instr`, `NeonInstr`, `ThumbExpanded`, `ArmV7InstrClass`).

## Ground truth verificabile esternamente
Decoder ARM/Thumb-2/NEON sono confrontabili con:
- **GNU binutils**: `arm-none-eabi-objdump -d` / `-Mforce-thumb` su oggetti ELF.
- **LLVM**: `llvm-objdump -d --triple=armv7-none-eabi` o `--triple=thumbv7`.
- **Capstone** (`CS_ARCH_ARM`, modi `CS_MODE_ARM`/`CS_MODE_THUMB`/`CS_MODE_BIG_ENDIAN`).
- **IDA Pro / Ghidra** backend ARM.
- **ARM Architecture Reference Manual (ARMv7-A/R, DDI0406)** per encoding,
  condition codes, regole CPSR, AAPCS (IHI 0042) per `aapcs_role`,
  encoding BL/BLX per `decode_bl_target` (T32 immediate form).
- Semantica ALU/shifter/CPSR confrontabile con emulatori QEMU / Unicorn Engine.
- Vettori NEON/VFP: gas test-suite, hex encoded references nella ARM ARM.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (dispatch generico, usa questo backend per ARM)
- `mcp__rustre-mcp__analysis_disasm_at_path_arm64` (sibling per AArch64; non per A32/T32)
- `mcp__rustre-mcp__disasm_at`, `disasm_function` (richiedono progetto aperto su binario ARM)
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_xref_*` (consumano output di questo crate)
- Confronto esterno: `mcp__ida-pro-mcp__disasm`, `mcp__ida-pro-mcp__decompile` su stesso binario ARM.

Nessun tool MCP dedicato esclusivamente a A32/T32 (a differenza di arm64/cil/jvm/mips/riscv/wasm
che hanno `analysis_disasm_at_path_<arch>`). Il crate è usato via il dispatcher generico.

## Testabilità
Testabile in isolamento: encoding ARM/Thumb sono noti e documentati. I test
esistenti (`tests/blitz.rs`, `tests/blitz2.rs`) e oracoli esterni (objdump,
Capstone, ARM ARM) permettono validazione deterministica delle firme pubbliche
elencate.
