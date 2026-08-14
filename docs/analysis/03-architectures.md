# 03 — Architecture Layer: `rustre-arch` and Sub-Crates

This document covers the 21 crates that form the architecture tier of the RustRE Suite:
`rustre-arch` (hub), `rustre-arch-registry` (aggregator), and the 19 concrete ISA
back-ends.

---

## 1. Design Overview

```
rustre-core (arch traits)
      │
      ▼
rustre-arch  ←─── hub: ArchRegistry, disassemblers, LiftContext, error types,
      │             binary detection, global_registry(), sub-modules
      │
      ├── rustre-arch-x86       depends on: rustre-arch + rustre-il-llil/lift
      ├── rustre-arch-arm       depends on: rustre-arch
      ├── rustre-arch-arm64     depends on: rustre-arch + yaxpeax-arm/arch
      ├── rustre-arch-mips      depends on: rustre-arch
      ├── rustre-arch-ppc       depends on: rustre-arch
      ├── rustre-arch-riscv     depends on: rustre-arch
      ├── rustre-arch-sparc     depends on: rustre-arch + thiserror
      ├── rustre-arch-6502      depends on: rustre-arch
      ├── rustre-arch-68k       depends on: rustre-arch + thiserror + bitflags
      ├── rustre-arch-avr       depends on: rustre-arch + thiserror
      ├── rustre-arch-msp430    depends on: rustre-arch
      ├── rustre-arch-z80       depends on: rustre-arch + bitflags
      ├── rustre-arch-bpf       depends on: rustre-arch + thiserror + bitflags
      ├── rustre-arch-wasm      depends on: rustre-arch + thiserror
      ├── rustre-arch-jvm       depends on: rustre-arch + thiserror + bitflags
      ├── rustre-arch-dex       depends on: rustre-arch + thiserror
      ├── rustre-arch-cil       depends on: rustre-arch + thiserror + bitflags
      ├── rustre-arch-lua       depends on: rustre-arch
      └── rustre-arch-luajit    depends on: rustre-arch
            │
            ▼
      rustre-arch-registry  (depends on ALL sub-crates + rustre-arch)
            └── register_all() → populates global_registry()
```

**Key design decision**: `rustre-arch` (the hub) does *not* path-dep on any
sub-crate. Each sub-crate depends on the hub to get shared types
(`DecodeError`, `LiftContext`, `ArchMetadata`, etc.). The aggregation crate
`rustre-arch-registry` sits above both to avoid a circular dependency.

---

## 2. `rustre-arch` — Hub Crate

**File**: `crates/rustre-arch/src/lib.rs` (2 602 lines)

### 2.1 Purpose

Orchestration layer. Re-exports the `Architecture` trait family from
`rustre-core::arch` and adds concrete runtime infrastructure that is shared
across all ISA back-ends.

### 2.2 Sub-Modules

| Module | Contents |
|---|---|
| `arch_features` | Feature-flag queries for an arch (has_thumb, has_fp, etc.) |
| `arch_meta` | Richer `ArchMetadata` helpers |
| `arch_registry_full` | High-level wrapper around `ArchRegistry` with metadata |
| `calling_conv` | Architecture-agnostic `CallingConvention` helpers |
| `calling_conventions` | Pre-built CC builders per architecture family |
| `instr_analysis` | Instruction-level analysis utilities |
| `instruction_semantics` | Semantic tagging of decoded instructions |
| `register_alias_map` | Maps register aliases to canonical IDs |
| `register_set` | Per-arch register descriptor sets |
| `arch_registry` | `ArchRegistry` implementation (re-exported) |
| `arch_feature_flags` | Bitflags for optional ISA extensions |
| `cross_arch_normalizer` | Cross-architecture instruction normalization |

### 2.3 Key Types

#### Error Types

```rust
pub enum DecodeError { Invalid, Truncated, Other(String) }
pub enum EncodeError { InvalidOperand, Unsupported, Other(String) }
pub enum LiftError  { Unsupported, StackOverflow, Other(String) }
```

#### `LiftContext`

Thread-through lifting context, carrying a temporary variable pool, depth
counter (max 4096), and a bounded warning log (max 4096 entries).

```rust
pub struct LiftContext {
    pub depth: usize,
    pub temps: HashMap<String, u64>,
    pub warnings: Vec<String>,
    pub max_depth: usize,
}
impl LiftContext {
    pub fn push(&mut self) -> Result<(), LiftError>  // overflow guard
    pub fn pop(&mut self)
    pub fn set_temp(&mut self, name, value: u64)
    pub fn get_temp(&self, name) -> Option<u64>
    pub fn warn(&mut self, msg)
}
```

#### `ArchMetadata`

```rust
pub struct ArchMetadata {
    pub description: String,
    pub min_instr_size: usize,
    pub max_instr_size: usize,
    pub variable_length: bool,
    pub nop_bytes: Vec<u8>,
}
// Constructors:
ArchMetadata::fixed_width(size, nop, desc)
ArchMetadata::variable_width(min, max, nop, desc)
```

#### `ArchRegistry`

Thread-safe (`parking_lot::RwLock`) list of `(Arc<dyn Architecture>, Option<ArchMetadata>)` pairs.

```rust
pub struct ArchRegistry { entries: RwLock<Vec<ArchEntry>> }
impl ArchRegistry {
    pub fn register(&self, arch: Arc<dyn Architecture>)
    pub fn register_with_meta(&self, arch, meta: ArchMetadata)
    pub fn find(&self, name: &str) -> Option<Arc<dyn Architecture>>
    pub fn metadata(&self, name: &str) -> Option<ArchMetadata>
    pub fn names(&self) -> Vec<String>
    pub fn remove(&self, name: &str) -> bool
    pub fn len(&self) -> usize
}
```

#### Disassembly Types

| Type | Role |
|---|---|
| `InstrStream` | `Vec<Instruction>` + `Vec<(Address, String)>` errors |
| `DisassemblyResult` | Like `InstrStream` but tracks `total_bytes` consumed |
| `DisasmFilter` | Predicate on `InstrFlags`, mnemonic substring filter |
| `DisasmCache` | `Mutex<HashMap<u64, Instruction>>` — address-keyed cache |
| `LinearDisassembler` | Sweep disassembler — one byte skip on error |
| `RecursiveDisassembler` | Branch-following with visited-set, sorted output |
| `InstrStats` | Counters: total, branches, calls, returns, conditionals, memory_ops |
| `ExtendedInstrStats` | Adds syscalls, nops, privileged, memory_{reads,writes} |
| `RegisterFile` | `HashMap<u32, u64>` register state snapshot |

#### Free Functions

```rust
pub fn global_registry() -> &'static DashMap<String, Arc<dyn Architecture>>
pub fn register_all_builtins()   // inserts PlaceholderArch for known names
pub fn detect_arch_from_bytes(data: &[u8]) -> Option<String>
pub fn detect_from_elf(data) -> Option<String>
pub fn detect_from_pe(data) -> Option<String>
pub fn detect_from_macho(data) -> Option<String>
pub fn disassemble_linear(arch, data, base, max_instrs) -> DisassemblyResult
pub fn disassemble_recursive(arch, data, base, entry) -> DisassemblyResult
```

`detect_arch_from_bytes` covers ELF (`e_machine` at offset 18), PE (`Machine`
after `PE\0\0`), and Mach-O (`cputype` at offset 4). Supported architectures:

| Source | Supported `e_machine` / `Machine` / `cputype` values |
|---|---|
| ELF | x86, x86_64, ARM, ARM64, MIPS, PPC, PPC64, RISC-V, SPARC, MSP430, AVR |
| PE | x86, x86_64, ARM, ARM64, PPC, MIPS |
| Mach-O | x86, x86_64, ARM, ARM64, PPC, PPC64 |

### 2.4 Implementation Status: **COMPLETE**

All types are fully implemented with proper error handling, bounds checks, and
inline documentation. Tests exist for most paths. The `PlaceholderArch`
sentinel correctly propagates "not linked" errors.

---

## 3. `rustre-arch-registry` — Aggregation Crate

**File**: `crates/rustre-arch-registry/src/lib.rs` (77 lines)

### 3.1 Purpose

Cycle-free aggregation crate. Depends on all 19 sub-arch crates plus the hub
and `rustre-core`. Provides two functions:

```rust
pub fn all() -> Vec<Arc<dyn Architecture>>
pub fn register_all()   // installs each arch into global_registry()
```

`register_all()` overwrites any `PlaceholderArch` stubs previously installed
by `register_all_builtins()`. Consumers that want all built-in backends call
this once at startup.

### 3.2 Registered Names

`6502`, `68k`, `arm`, `aarch64`, `avr`, `bpf`, `cil`, `dex`, `jvm`, `lua`,
`luajit`, `mips`, `msp430`, `ppc`, `riscv32/64`, `sparc`, `wasm`,
`x86_16/32/64`, `z80`.

### 3.3 Implementation Status: **COMPLETE**

---

## 4. Per-Architecture Crate Analysis

### 4.1 `rustre-arch-x86` — x86/x64

**Size**: `src/lib.rs` 2 149 lines + multiple companion modules.

**External dep**: `iced-x86 = "1.21"` (production-grade pure-Rust decoder).

**Primary type**: `X86Arch { bits: u32 }` with constructors `new_16bit()`,
`new_32bit()`, `new_64bit()`. Registered names: `x86_16`, `x86_32`, `x86_64`.

#### Modules

| Module | Contents |
|---|---|
| `branch` | Branch-target extraction helpers |
| `fpu_lifter` | x87 FPU instruction lifting |
| `render` | `render_instruction`, `render_instruction_with_syntax`, `Syntax` enum |
| `length` | Instruction length tables |
| `lift` | `X86Lifter` — main lifter to `LlilAnnotatedInstr` |
| `modrm` | ModRM/SIB byte parsing |
| `prefix` | Prefix byte analysis |
| `simd_lifter` | SIMD/AVX instruction lifting |
| `sse` | SSE decode helpers |
| `string_ops_lifter` | REP/MOVS/STOS/LODS/SCAS lifting |
| `system_insn_lifter` | SYSCALL/SYSENTER/privileged lifting |
| `tables` | Opcode tables |
| `x87` | x87 FPU helpers |
| `lift_data_arith` | Data + arithmetic category lifter |
| `x86_decode_table` | `X86DecodeTable`, `OpcodeEntry`, `OpcodeGroup` |
| `x86_instruction_database` | `X86InstructionDatabase`, `FlagEffects`, `InstrCategory` |
| `x86_simd_decoder` | `X86SimdDecoder`, `SimdInsn`, `SimdGroup` |
| `x86_prefix_analyzer` | `X86PrefixAnalyzer`, `Prefix`, `PrefixGroup` |
| `x86_control_flow_graph` | `X86ControlFlowGraph`, `X86Block`, `X86Edge`, `build_cfg()` |

#### `Architecture` impl highlights

- `disassemble()` — delegates to `iced-x86::Decoder`, converts to `Instruction`
  via `GasFormatter` (AT&T syntax), maps `FlowControl` → `InstrFlags`, and
  uses `InstructionInfoFactory` for memory-access flags with fallback heuristic.
- `get_branches()` — re-decodes raw bytes from `instr.bytes` via iced, extracts
  near branch targets. Falls back to operand-string parsing on re-decode failure.
- `registers()` — returns 16/32/64-bit specific tables: 16-bit (31 entries),
  32-bit (66 entries including FPU/MMX/XMM), 64-bit (~250 entries including
  ZMM, AVX-512 opmask k0-k7, MPX bnd0-bnd3).
- `calling_conventions()` — 32-bit: cdecl, stdcall, fastcall, thiscall;
  64-bit: sysv_amd64, ms_x64, syscall.
- `lift()` — re-decodes with iced, dispatches to `X86LiftAdapter::adapt_iced_to_llil`.

#### `X86LiftAdapter`

Bridges iced-x86 to the flat `LlilOp` stack-IR from `rustre-core`. Register
mapping covers RAX family (IDs 0–3), RBX (4–7), RCX (8–11), RDX (12–15),
RSI (16–19), RDI (20–23), RSP (24), RBP (25), R8-R15 (26–33), RIP (34),
XMM0-15 (36–51), YMM0-15 (52–67), plus high-byte regs AH/BH/CH/DH (68–71).

Covered mnemonics: MOV/MOVSX/MOVSXD/MOVZX, LEA, XCHG, PUSH, POP, ADD/ADC,
SUB/SBB, INC, DEC, NEG, MUL/IMUL, DIV/IDIV, AND, OR, XOR, NOT, CMP/TEST,
SHL/SAL, SHR/SAR, JMP, CALL, RET/RETF, all Jcc, SYSCALL/SYSENTER, NOP.

**Status**: **COMPLETE** for decode/disassemble/lift path. Some sub-modules
(`lift_control_system`, `lift_fpu_simd`) are noted as incrementally filled by
enterprise workflow and may be partial.

---

### 4.2 `rustre-arch-arm` — ARM 32-bit

**External dep**: none (hand-written A32/T32 decoder).

**Primary type**: `ArmArch { mode: ArmMode, little_endian: bool }`.
`ArmMode` is `Arm` (A32) or `Thumb` (T32). Default is little-endian A32.

#### Modules

| Module | Contents |
|---|---|
| `arm_thumb2` | Thumb-2 instruction decoder |
| `arm_instruction_semantics` | Semantic tagging |
| `coprocessor` | CP14/CP15 coprocessor instructions |
| `neon` | NEON/VFP instruction decode |
| `arm_analysis` | ThumbInterworking, ITBlockAnalyzer, ConditionalExecution, ArmFunctionProfiler |
| `armv7_full` | Complete ARMv7 ISA including NeonFull, VfpFull, ArmV7Lifter |

The A32 decoder (`decode_arm`) manually unpacks 32-bit instruction words using
bit field extraction. It covers: data processing (MOV, MVN, AND, EOR, SUB, RSB,
ADD, ADC, SBC, RSC, TST, TEQ, CMP, CMN, ORR, BIC), branches (B/BL/BX/BLX),
load/store (LDR/STR/LDM/STM with all addressing modes), multiply, swap.
Condition codes are decoded from bits [31:28] via `CONDS` table.

T32 Thumb decoder handles 16-bit encodings: PUSH/POP, B, BL, BLX, LDR/STR,
ADD/SUB, MOV, CMP, NOP.

Calling conventions: `aapcs` (r0-r3 args, r0-r1 return), `aapcs-vfp`.

**Status**: **PARTIAL** — core decode path works; lifter integration via
`arm_analysis`/`armv7_full` sub-modules is present but the top-level `lift()`
method on `ArmArch` defers to a simple best-effort translation.

---

### 4.3 `rustre-arch-arm64` — AArch64

**External deps**: `yaxpeax-arm = "0.4"`, `yaxpeax-arch = "0.3"`.

**Primary type**: `Arm64Arch` (unit struct, `Copy`). Name: `"aarch64"`.

This is the most complete non-x86 back-end. Every `Architecture` method is fully
implemented.

#### Modules

| Module | Contents |
|---|---|
| `aarch64_neon` | NEON/Advanced SIMD: `NeonDecoder`, `NeonRegister`, `NeonInstruction`, `ArrangementSpec`, `NeonLifter` |
| `aarch64_pac` | Pointer Authentication Code analysis: `PacAnalyzer`, `PacInstruction`, `PacKey`, security findings |
| `aarch64_sve` | SVE/SVE2: `AArch64Sve`, `SvePredicate`, `SveVector`, `SveInstruction`, `SveLifter` |
| `arm64_system_registers` | System register descriptors |
| `arm64_pac_analyzer` | PAC signing/stripping analysis |
| `arm64_sve_decoder` | SVE opcode decoder |
| `arm64_feature_detector` | ISA feature detection |
| `arm64_calling_conventions` | AAPCS64/Apple/Windows ARM64 ABIs |
| `arm64_exception_levels` | EL0/EL1/EL2/EL3 awareness |
| `arm64_jump_table` | `detect_jump_tables()`, `JumpTableInfo`, `JumpTableKind` |

#### `Architecture` impl

- `disassemble()`: calls `yaxpeax_decode()` (wraps `yaxpeax_arm::armv8::a64::InstDecoder`),
  formats via `Display`, splits mnemonic/operands on first whitespace, maps
  opcodes to `InstrFlags` via exhaustive match.
- `get_branches()`: re-decodes, scans operands for `Operand::PCOffset(i64)`,
  computes absolute target. Returns `BranchInfo::ret()` for RET,
  `BranchInfo { kind: ExceptionReturn, .. }` for ERET.
- `registers()`: 250+ entries covering X0-X30/XZR/SP/PC, W0-W30/WZR/WSP,
  V0-V31, Q0-Q31, D0-D31, S0-D31, H0-H31, B0-B31, and 16 system registers
  (NZCV, FPCR, FPSR, DAIF, ELR/SPSR/ESR/FAR/VBAR/SCTLR/TTBR0/TTBR1 EL1,
  TPIDR_EL0, TPIDRRO_EL0, CurrentEL, SPSel).
- `calling_conventions()`: `aapcs64` (x0-x7 args, x0-x1 return) and
  `apple_arm64`.
- Static `ARM64_SYS_REGS` table: 30+ entries for EL0/EL1/EL2/EL3 system
  registers with `op0:op1:CRn:CRm:op2` fields and `encoded() -> u16`.

Also exposes `Arm64SysReg`, `Arm64InstrCategory::classify(mnemonic)`,
`Arm64LinearDisassembler<'a>` (iterator, halts on error), and
`detect_jump_tables()`.

**Status**: **COMPLETE** — 30+ tests, all paths verified.

---

### 4.4 `rustre-arch-mips` — MIPS

**External dep**: none (hand-written decoder).

**Primary type**: `MipsArch { endian: MipsEndian, abi: MipsAbi, bits: u32 }`.
Supports MIPS I/II/III/IV/32r2/64, big-endian and little-endian, O32/N32/N64.

#### Modules

| Module | Contents |
|---|---|
| `mips_fpu` | `MipsFpuState`, `FCSRFlags`, FPU instructions, `MipsFpuLifter` |
| `mips_cop0_registers` | CP0 register catalogue with select-field awareness |
| `mips_calling_conventions` | O32/N32/N64 register lists, callee/caller-saved, stack-frame |
| `mips_delay_slot` | `DelaySlotKind`, `MipsJumpOpcode`, `DelaySlotAnalyzer` |
| `mips_analysis` | `GlobalPointerUsage`, `MipsAbi`, `MipsExceptionHandler`, `MipsBranchTargetTable` |
| `mips_abi_analysis` | `O32Abi`, `N64Abi`, `MipsEabi`, `ArgPassingRules`, `GotEntry` |

32 GPR constants (`REG_ZERO`…`REG_RA`), GPR name table (`$zero`…`$ra`),
COP0 name array (32 entries), 16 FP condition names.

The main decoder manually bit-extracts the 6-bit opcode, `rs/rt/rd/sa` fields,
and immediate values. Delay slots are modeled in LLIL.

Calling conventions: O32 (a0-a3 args, v0-v1 return), N32/N64 (a0-a7 args).

**Status**: **PARTIAL** — decode logic and register/CC tables complete; FPU
lifter and delay-slot LLIL modeling present but integration may be incomplete.

---

### 4.5 `rustre-arch-ppc` — PowerPC

**External dep**: none.

**Primary type**: `PpcArch { bits: u32 }`. 4-byte fixed-width big-endian.

#### Modules

`ppc_analysis`, `ppc_decoder`, `ppc_registers`, `ppc_calling_conv`,
`ppc_disassembler`, `ppc_calling_convention`, `ppc_branch_analyzer`,
`ppc_spr_map`.

Register ID scheme: GPR r0-r31 (0–31), FPR f0-f31 (32–63), CR fields
cr0-cr7 (64+), XER (65), LR (66), CTR (67), PC (68).

Helpers: `gpr(r)`, `fpr(r)`, `crfield(r)`, `simm16(val)`, `uimm16(val)`,
`bc_name(bi, bo)` for conditional branch decoding.

Calling conventions: EABI (r3-r10 args, r3-r4 return), AIX/Linux ABI.

**Status**: **PARTIAL** — instruction decoder covers primary/extended opcodes,
FPU, CR field operations; VLE mode and Book E SPRs present in `ppc_analysis`.

---

### 4.6 `rustre-arch-riscv` — RISC-V

**External dep**: none (manually written decoder).

**Primary type**: `RiscvArch { bits: u32 }`. Constructors: `rv32()`, `rv64()`, `rv128()`.

#### Coverage

- RV32I/RV64I/RV128I base integer
- M extension (MUL, DIV, REM — 32 and 64-bit)
- A extension (LR/SC, AMO variants — 32 and 64-bit)
- F extension (single-precision FP)
- D extension (double-precision FP)
- C extension (16-bit compressed instructions)
- Zicsr (all 6 CSR instructions + hundreds of named CSRs)
- Zifencei (FENCE.I)
- H hypervisor extension basics (HLV, HSV, HFENCE)

#### Modules

| Module | Contents |
|---|---|
| `riscv_vector` | RVV: `VectorDecoder`, `VlenConfig`, `VType`, vector instructions, `VectorRegFile` |
| `riscv_analysis` | `RiscVAbi`, `RiscVCallingConv`, `CompressedInsn`, `PicCode`/GOT analysis |
| `riscv_csr` | `RiscVCsr`, `CsrId`, `CsrAccess`, `McauseDecoder`, `MstatusDecoder`, `Mtvec` |
| `riscv_compressed_decoder` | C extension 16-bit decoder |
| `riscv_csr_map` | Full 4096-address CSR table |
| `riscv_exception_handler` | Exception/interrupt modeling |

Helper `mk()` builds `Instruction` from fields. Calling conventions: LP64,
LP64F, LP64D, ILP32, ILP32F, ILP32D.

**Status**: **PARTIAL-to-COMPLETE** — base ISA + standard extensions fully
decoded; RVV integration present but lifting to LLIL may be incomplete.

---

### 4.7 `rustre-arch-sparc` — SPARC v8/v9

**External deps**: `thiserror`.

**Primary type**: `SparcArch { v9: bool }`. 4-byte big-endian.

#### Modules

`sparc_analysis`, `sparc_calling_conv`, `sparc_decoder`, `sparc_emulator`,
`sparc_lifter`, `sparc_registers`, `sparc_v9`, `sparc_register_file`,
`sparc_delay_slot_analyzer`, `sparc_trap_handler`, `sparc_register_windows`,
`sparc_delay_slot`, `sparc_trap_table`.

Register IDs: %g0-%g7 (0–7), %o0-%o7 (8–15), %l0-%l7 (16–23), %i0-%i7
(24–31), FP f0-f63 (32–95), PC (96), NPC (97), PSR (98), WIM (99), TBR (100),
Y (101). `reg_name()` handles %sp (%o6), %fp (%i6), %o7 etc.

SPARC's register-window mechanism is modeled in `sparc_register_windows`.
Delay slots are handled analogously to MIPS.

Calling conventions: SPARC ABI (o0-o5 args, o0-o1 return), SPARC64 LP64.

**Status**: **PARTIAL** — good decoder coverage; register window modeling and
V9 additions present; LLIL lifting incomplete.

---

### 4.8 `rustre-arch-6502` — MOS 6502 / 65C02 / 65816

**External dep**: none.

**Primary type**: `Cpu6502Arch { variant: Cpu6502Variant }` where variant is
`Mos6502`, `Cpu65c02`, or `Cpu65816`.

#### Modules

`decoder_65c02` (BBR/BBS/RMB/SMB/STZ/TRB/TSB/WAI/STP),
`decoder_65816` (24-bit addressing, native/emulation mode),
`lifter`, `emulator`, `analysis`, `cpu_tester` (100+ test cases),
`assembler_6502` (two-pass assembler with labels),
`mos6502_disassembler` (full 256-opcode table + illegal opcodes),
`mos6502_addressing_modes`, `mos6502_rom_analyzer` (iNES/C64/Atari2600/Apple II),
`mos6502_address_modes`, `mos6502_zero_page`, `mos6502_platform_vectors`.

Register IDs: A (0), X (1), Y (2), SP (3), PC (4), P (5) (processor status).

The 6502 has no register file in the conventional sense; A, X, Y, SP, PC, and
the 8-bit P flags register are modeled as registers. Addressing modes are
extensive (implied, immediate, ZP, ZP+X/Y, absolute, absolute+X/Y, indirect,
(indirect,X), (indirect),Y, relative).

**Status**: **COMPLETE** — the richest embedded-ISA back-end in the suite.
Assembler, emulator, ROM format analyzer, and platform vector table all present.

---

### 4.9 `rustre-arch-68k` — Motorola 68000 Family

**External deps**: `thiserror`, `bitflags`.

**Primary type**: `Mc68kArch { variant: Mc68kVariant }`. Variants: M68000,
M68010, M68020, M68030, M68040. Variable-length big-endian (2–22 bytes).

#### Modules

`m68k_analysis`, `m68k_os_abi` (AmigaABI, MacOS68kABI, A5WorldRelative,
JumpTable), `m68k_extensions` (68000→68060 capability matrix, bitfield ops,
68881/68882 FPU), `m68k_platforms` (Amiga custom chips, Sega Genesis VDP,
Mac A-line traps, Sun-3 SunOS syscalls), `m68k_addressing_modes`,
`m68k_exception_vectors`, `m68k_disassembler_ext` (FPU/MMU),
`m68k_decoder` (`M68kInstr`, `M68kEa`, `M68kSize`, `M68kDecoder`),
`m68k_disassembler` (Motorola-syntax formatter), `m68k_registers`
(`M68kRegFile`, `M68kDReg`, `M68kAReg`, `M68kSr`, `M68kCcr`).

Register IDs: D0-D7 (0–7), A0-A7/SP (8–15), PC (16), SR (17), CCR (18),
USP (19), SSP (20), FP0-FP7 (32–39), FPCR/FPSR/FPIAR (40–42).

Calling conventions: Motorola convention (d0/d1 return, stacked args),
SVR4/ELF (d0/a0/d1 for different types).

**Status**: **PARTIAL** — decoder and platform-specific analysis are extensive;
full LLIL lifting is partially wired.

---

### 4.10 `rustre-arch-avr` — Atmel AVR

**External dep**: `thiserror`.

**Primary type**: `AvrArch { variant: AvrVariant }`. Variants: Attiny, Atmega, Xmega.

The AVR uses a Harvard architecture (separate program and data memory) with
2-byte program-memory words (most instructions 2 bytes; LDS/STS/CALL/JMP 4 bytes).

#### Modules

`avr_analysis`, `avr_emulator`, `avr_interrupt_model`, `avr_pgm_memory`,
`avr_code_analysis` (PUSH R28/R29 prologue, epilogue, string detector,
bootloader patterns, signature scanner), `avr_devices` (ATmega328P,
ATmega2560, ATtiny85, ATtiny13, ATxmega256A3U — flash/SRAM/EEPROM/SFR maps/IVTs),
`avr_io_decoder` (IN/OUT address decoder, bit-field descriptions, timer/USART),
`avr_decoder`, `avr_disassembler`, `avr_registers`, `avr_io_map`,
`avr_io_registers`, `avr_interrupt_vectors`, `avr_fuse_bits`.

Registers: R0-R31 (0–31), X (R26:R27), Y (R28:R29), Z (R30:R31), SP, SREG, PC.

**Status**: **PARTIAL-to-COMPLETE** — device descriptor tables and IO decoder
are very complete; core decode loop handles main instruction classes.

---

### 4.11 `rustre-arch-msp430` — TI MSP430 / MSP430X

**External dep**: none.

**Primary type**: `Msp430Arch`. Covers full 16-bit MSP430 and 20-bit MSP430X.

Three instruction formats:
- Format I (two-operand): `opcode[4] src[4] ad[1] bw[1] as[2] dst[4]`
- Format II (single-operand): `0001 00 opcode[3] bw[1] as[2] reg[4]`
- Format III (jump): `001 cond[3] offset[10]`

#### Modules

`analysis`, `decoder` (`Msp430Insn`), `disassembler` (AT&T formatter),
`emulator`, `lifter` (`IlOp`), `msp430_decoder`, `msp430_registers`,
`msp430_analysis` (`MemoryMapAnalyzer`, `PowerModeAnalysis`,
`CriticalSectionDetector`, `WatchdogPatterns`, `FlashWriteDetector`,
`BootloaderAnalysis`), `msp430_peripherals` (Timer_A, USCI, ADC10/ADC12,
WatchdogTimer, PortRegisters, FlashController), `msp430_full_decoder`
(`Msp430FullDecoder`, X_extended, PUSHM/POPM, RPT, MOVA/CMPA/ADDA/SUBA),
`msp430x_extended` (20-bit address space, MOVA/CMPA/ADDA/SUBA, CALLA/RETA,
BRA), `msp430_sfr_map`, `msp430_interrupt_table`, `msp430_calling_convention`,
`msp430_addressing_modes`, `msp430_interrupt_vectors`, `msp430_peripheral_map`.

Registers: R0/PC, R1/SP, R2/SR, R3/CG, R4-R15.

**Status**: **COMPLETE** — unusually comprehensive for a niche embedded target;
peripheral model, power analysis, and flash write detection are rare features.

---

### 4.12 `rustre-arch-z80` — Zilog Z80

**External dep**: `bitflags`.

**Primary type**: `Z80Arch`. Unprefixed + CB/DD/ED/FD prefix tables, full
8080-compatible set + Z80 extensions.

#### Modules

`z80_emulator`, `z80_io_model`, `z80_prefix_tables`,
`z80_os_patterns` (CP/M BIOS calls, ZX Spectrum patterns, Z80 bootloader),
`z80_undocumented` (IXH/IXL/IYH/IYL access via DDCB/FDCB, SLL shift,
`undoc_decode()`, `Z80FullDecoder`), `z80_platforms` (ZX Spectrum ULA/memory
banking, MSX slot system, CP/M BDOS, Game Boy SM83 ISA differences),
`z80_decoder`, `z80_registers`, `z80_disassembler`, `z80_io_ports`,
`z80_rom_header`, `z80_register_pairs`, `z80_undocumented_opcodes`,
`z80_platform_detector`.

Register IDs: A (0), B (1), C (2), D (3), E (4), H (5), L (6), F (7), I (8),
R (9), AF (10), BC (11), DE (12), HL (13), IX (14), IY (15), SP (16), PC (17),
shadow registers AF'/BC'/DE'/HL' (18–21).

**Status**: **PARTIAL** — excellent coverage of opcode tables, undocumented ops,
and platform-specific knowledge; emulator present; LLIL lifting partial.

---

### 4.13 `rustre-arch-bpf` — eBPF / cBPF

**External deps**: `thiserror`, `bitflags`.

**Primary type**: `BpfArch`. Covers full eBPF (ALU32/ALU64, JMP/JMP32,
load/store, BPF_CALL, BPF_EXIT, BPF_LD_DW_IMM) and classic cBPF.

#### Modules

`bpf_verifier` (`BpfVerifier`, `VerifierState`, `RegisterType`, `BoundsCheck`,
`SafetyProperty`), `bpf_analysis` (`BpfProgType`, `MapAccessPattern`,
`HelperCallAnalysis`, `BpfCfg`, `LoopBound`, `BpfSecurity`),
`bpf_co_re` (Compile Once, Run Everywhere: `BtfType`, `BtfKind`, `BtfParser`,
`CoReReloc`, `CoReApplier`, `KernelBtf`), `btf_parser` (all BTF type kinds,
function prototype recovery), `bpf_verifier_sim` (register type tracking,
pointer arithmetic legality, packet access bounds), `ebpf_verifier`,
`ebpf_jit_analyzer`, `cbpf_to_ebpf`.

Public constants: `BpfClass` enum (Ld/Ldx/St/Stx/Alu/Jmp/Alu64/Jmp32).
200+ helper function entries in a helper table. Map type descriptors.

The instruction format is 64-bit little-endian: `opcode[8] dst_reg[4]
src_reg[4] off[16] imm[32]`. `BPF_LD_DW_IMM` occupies two 8-byte slots.

**Status**: **PARTIAL-to-COMPLETE** — instruction decode very complete; BTF/CO-RE
parsing is exceptional (few RE tools provide this). Verifier simulation gives
security analysis capabilities.

---

### 4.14 `rustre-arch-wasm` — WebAssembly

**External dep**: `thiserror`.

**Primary type**: `WasmArch` (unit struct). Stack-based VM, LEB128-encoded
variable-length instructions.

#### Modules

`atomics` (atomic fence/load/store/RMW), `simd_decoder` (128-bit SIMD ops),
`wasm_analysis`, `wasm_decompiler`, `wasm_lifter`, `wasm_execution_model`,
`wasm_import_analyzer`, `wasm_memory_model`, `wasm_table_model`,
`wasm_type_system`, `wasm_validator`.

Public `read_uleb128()` and `read_sleb128()` are exposed for use by callers.

Wasm has no architectural registers; the `registers()` implementation returns
virtual names for the operand stack slots and local variables.

**Status**: **PARTIAL** — decoder covers MVP + atomics + SIMD extensions;
lifting to LLIL (which assumes a register machine) requires special treatment
via `wasm_lifter`; completeness is partial.

---

### 4.15 `rustre-arch-jvm` — JVM Bytecode

**External deps**: `thiserror`, `bitflags`.

**Primary type**: `JvmArch` (unit struct). ~200 opcodes, variable-length
(1–5 bytes), big-endian stack-based VM.

**Public types**: `JvmInstr` (decoded with opcode, mnemonic, operands, size),
`JvmLinearDisassembler` (iterator), `JvmDecodeError` enum.

#### Modules

`jvm_bytecode_analysis`, `jvm_lifter` (JVM stack → virtual-register lifter),
`wide_opcodes` (WIDE prefix, TABLESWITCH, LOOKUPSWITCH, invoke variants),
`jvm_security` (`JavaSecurityManager`, `PrivilegedBlock`, `ClassLoaderAbuse`,
`SerializationRisk`, `ReflectionSecurity`), `constant_pool_analysis`
(`CpEntry`, `CpCategory`, `InternedString`),
`jvm_invoke_dynamic` (`BootstrapMethod`, `MethodHandle`, `CallSite`,
`LambdaMetafactory`, `StringConcatFactory`), `jvm_constant_pool`,
`jvm_attribute_parser`, `jvm_bytecode_verifier`.

JVM "registers" are modeled as the local variable array (lvar0…lvarN).

**Status**: **PARTIAL** — opcode decode complete; `jvm_lifter` maps JVM stack
operations to a virtual register model; TABLESWITCH/LOOKUPSWITCH require
variable-size parsing.

---

### 4.16 `rustre-arch-dex` — Dalvik/ART

**External dep**: `thiserror`.

**Primary type**: `DexArch`. Full 256+ opcode Dalvik set + extended 0xE3–0xFF
ART opcodes. All DEX version magic constants defined (035–039, CDEX).

#### Modules

`art_opcodes` (ART-optimized opcodes), `dalvik_type_system`, `dex_lifter`,
`full_opcode_table` (complete table for all formats),
`dex_obfuscation` (`ProGuardPatterns`, `R8Optimizer`, `SingleLetterNames`,
`EncryptedStrings`, `ReflectionAbuse`),
`smali_generator` (`SmaliGenerator`, `SmaliClass`, `SmaliMethod`,
`RegisterAllocation`, `LabelGenerator`),
`dalvik_lifter_full` (DalvikLifterFull covering all 256 opcodes),
`dex_string_pool`, `dex_type_system`, `dex_method_analyzer`.

Dalvik uses a register-based VM (unlike JVM) with 16-bit registers (v0–v255
in most formats). Operand formats cover all 34+ DEX instruction formats.

**Status**: **PARTIAL-to-COMPLETE** — opcode tables and format decoders are
comprehensive; `smali_generator` enables round-trip decompilation; obfuscation
detection is unique.

---

### 4.17 `rustre-arch-cil` — .NET CIL / MSIL

**External deps**: `thiserror`, `bitflags`.

**Primary type**: `CilArch`. ~220 opcodes from ECMA-335 Partition III including
2-byte `0xFE xx` prefixed opcodes. Variable-length (1–6 bytes), big-endian
stack-based.

**Public types**: `CilInstr` (decoded), `CilLinearDisassembler` (iterator),
`CilDecodeError` (`Truncated`, `UnknownOpcode(u8)`, `UnknownPrefixedOpcode(u8)`).

#### Modules

`cil_analyzer`, `cil_decompiler`, `cil_decoder`, `cil_lifter`,
`cil_metadata`, `exception_handlers`, `wide_prefix`,
`cil_obfuscation` (`RenameObfuscation`, `ControlFlowObfuscation`,
`StringEncryption`, `VirtualMachineObf`, `ObfuscationScore`),
`cil_stack_tracker`, `cil_branch_analyzer`, `cil_call_graph`,
`cil_type_system` (`CorElementType`, CIL type signature parser),
`cil_execution_engine` (`EvalStack`, `CilValue`, `LocalVars`, `Arguments`),
`cil_pattern_recognition` (string encryption, reflection, anti-debug, P/Invoke).

**Status**: **PARTIAL** — decode path covers full ECMA-335 opcode space; lifter
maps stack VM to virtual registers; obfuscation detection and pattern
recognition are high-value additions.

---

### 4.18 `rustre-arch-lua` — Lua VM (5.1–5.4)

**External dep**: none.

**Primary type**: `LuaArch { version: LuaVersion }`. Supports 5.1, 5.2, 5.3, 5.4.

Instruction format varies by version:
- 5.1/5.2/5.3: iABC `[B:9][C:9][A:8][OP:6]`, iABx `[Bx:18][A:8][OP:6]`, iAsBx
- 5.4: iABC `[C:8][B:8][k:1][A:8][OP:7]`, iABx `[Bx:17][A:8][OP:7]`, iAsBx, iAx, isJ

#### Modules

`lua54_decoder`, `lua_type_inference`, `lua_pattern_matcher`,
`lua_optimizer`, `lua_bytecode_analyzer`, `lua_upvalue_tracker`,
`lua_proto_printer`, `lua_decompiler` (`LuaDecompiler`, `LuaExpr`, `LuaStmt`,
`UpvalueResolver`), `lua_vm_semantics` (`LuaValue`, `LuaTable`, `LuaMetatable`,
`GcSemantics`, `UpvalueClosing`, `YieldResume`),
`lua_disasm`, `lua_cfg`, `lua_vm_opcodes`, `lua_vm_state`,
`lua_closure_analyzer`.

Lua's "registers" are the function's register window within the Lua stack.

**Status**: **PARTIAL** — instruction formats correctly decoded for all 4 versions;
decompiler and VM semantics present; the cross-version version-detection logic
may need hardening for binary blobs without headers.

---

### 4.19 `rustre-arch-luajit` — LuaJIT 2

**External dep**: none.

**Primary type**: `LuaJitArch` (unit struct). 32-bit fixed-width LE instructions.
Format: `opcode[8] A[8] C[8] B[8]` (ABC) or `D = (B<<8)|C` (16-bit operand).
Signed branch targets: `d = D - 0x8000`.

#### Modules

`luajit21_compat` (LuaJIT 2.1 compatibility), `luajit_jit_analysis`,
`trace_ir` (LuaJIT trace IR), `luajit_security` (`SandboxEscape`, `FFIAbuse`,
`JitBypass`, `MemoryCorruption`, `LuaJitROP`),
`bc_optimizer` (`BytecodeOptimizer`, `ConstantFolding`, `DeadCodeElim`,
`CopyPropagation`, `JumpChaining`),
`luajit_assembler` (`LuaJitAssembler`, `LabelResolver`, `RegisterAllocator`),
`luajit_ir_disasm` (`LuaJitIrDisasm`, `IrInsn`, `IrOp`, `IrType`),
`luajit_mcode_analyzer` (`McodeAnalyzer`, `JitTrace`, `TraceExit`, `TraceLink`,
`McodePatch`),
`luajit_proto_analyzer` (`LuaJitProtoAnalyzer`, `ClosureGraph`, `UvInfo`,
`KGCEntry`, `LocalVar`),
`luajit_opcodes`, `luajit_ir`, `luajit_trace_info`.

Public extras: `LuaJitBytecode` (full bytecode dump parser), `LuaJitProto`
(function prototype with constants/upvalues/sub-protos), `LjInstrDetail`
(per-instruction semantic info, operand roles, side effects), `InstrCategory`.

**Status**: **PARTIAL-to-COMPLETE** — the JIT trace IR and machine-code
analyzer are unusual and valuable capabilities; bytecode decode complete.

---

## 5. Implementation Status Summary

| Crate | Decode | Branch Extract | Register Table | Calling Convs | LLIL Lift | Status |
|---|---|---|---|---|---|---|
| rustre-arch (hub) | ✓ sweep+recursive | ✓ | ✓ RegisterFile | N/A | N/A | Complete |
| rustre-arch-registry | N/A | N/A | N/A | N/A | N/A | Complete |
| rustre-arch-x86 | ✓ iced-x86 | ✓ | ✓ (250+) | ✓ cdecl/stdcall/sysv/ms | ✓ LlilAnnotatedInstr | Complete |
| rustre-arch-arm64 | ✓ yaxpeax | ✓ | ✓ (250+) | ✓ aapcs64/apple | Partial | Complete |
| rustre-arch-arm | ✓ manual A32/T32 | ✓ | ✓ | ✓ aapcs/vfp | Partial | Partial |
| rustre-arch-mips | ✓ manual | ✓ | ✓ (O32/N64) | ✓ O32/N32/N64 | Partial | Partial |
| rustre-arch-ppc | ✓ manual | ✓ | ✓ | ✓ EABI/AIX | Partial | Partial |
| rustre-arch-riscv | ✓ manual (RV+exts) | ✓ | ✓ | ✓ LP64/ILP32 | Partial | Partial→Complete |
| rustre-arch-sparc | ✓ manual | ✓ | ✓ | ✓ SPARC ABI | Partial | Partial |
| rustre-arch-6502 | ✓ full 256-op table | ✓ | ✓ | N/A (stack CC) | ✓ lifter | Complete |
| rustre-arch-68k | ✓ manual M68k | ✓ | ✓ | ✓ Motorola/SVR4 | Partial | Partial |
| rustre-arch-avr | ✓ manual | ✓ | ✓ R0-R31 | ✓ avr-gcc | Partial | Partial→Complete |
| rustre-arch-msp430 | ✓ manual fmt I/II/III | ✓ | ✓ R0-R15 | ✓ | ✓ lifter | Complete |
| rustre-arch-z80 | ✓ full prefix tables | ✓ | ✓ + shadow regs | ✓ | Partial | Partial |
| rustre-arch-bpf | ✓ eBPF+cBPF | ✓ | ✓ r0-r10 | ✓ BPF kernel ABI | Partial | Partial→Complete |
| rustre-arch-wasm | ✓ LEB128 decode | ✓ | Virtual | N/A | Partial | Partial |
| rustre-arch-jvm | ✓ all ~200 opcodes | ✓ | Virtual lvar[] | N/A | Partial | Partial |
| rustre-arch-dex | ✓ 256+ opcodes | ✓ | v0-v255 | N/A (register VM) | ✓ lifter | Partial→Complete |
| rustre-arch-cil | ✓ all 220 opcodes | ✓ | Virtual | N/A | Partial | Partial |
| rustre-arch-lua | ✓ 5.1-5.4 formats | ✓ | Register window | N/A | None | Partial |
| rustre-arch-luajit | ✓ 32-bit fixed | ✓ | Register slots | N/A | None | Partial |

---

## 6. External Dependencies

| Crate | External Library | Version | Purpose |
|---|---|---|---|
| rustre-arch | `dashmap`, `parking_lot`, `serde`, `bitflags`, `anyhow`, `thiserror` | workspace | Registry/sync |
| rustre-arch-x86 | `iced-x86` | 1.21 | Full x86/x64 decode + format |
| rustre-arch-arm64 | `yaxpeax-arm`, `yaxpeax-arch` | 0.4 / 0.3 | AArch64 decode |
| All others | none beyond workspace | — | Hand-written decoders |

---

## 7. Integration Points with Other Subsystems

| Subsystem | Integration |
|---|---|
| `rustre-il-llil` | `X86Arch::lift()` returns `Vec<LlilAnnotatedInstr>`. `X86LiftAdapter::adapt_iced_to_llil()` emits flat `LlilOp`. |
| `rustre-il-lift` | `X86Arch::lift()` depends on `rustre-il-lift` path for the `X86Lifter` type. |
| `rustre-core::arch` | Every sub-crate implements `Architecture` trait from core. `InstrFlags`, `BranchInfo`, `RegisterInfo`, `CallingConvention`, `LlilOp`, `LiftContext` all from core. |
| `rustre-loader-*` | Loaders call `detect_arch_from_bytes()` to route to the right back-end, then call `global_registry().get(name)`. |
| `rustre-analysis-*` | Analysis crates receive `Arc<dyn Architecture>` from registry and call `disassemble()` / `get_branches()` / `registers()`. |
| `rustre-mcp-server` | MCP tools expose `arch_list`, `arch_disassemble`, `arch_lift_to_llil` etc., all backed by `global_registry()` look-ups. |
| `rustre-cfg` | CFG builder uses `get_branches()` return values to construct basic block edges. |

---

## 8. Known Gaps and TODOs

1. **ARM lift integration**: `ArmArch::lift()` is not connected to the full
   ARMv7 lifter in `armv7_full`. The `arm_analysis` modules exist but the
   `lift()` method on the trait returns a simplified result.

2. **Wasm register model**: `WasmArch::registers()` returns virtual names;
   `wasm_lifter` must translate stack semantics to register IR, which is
   architecturally awkward with the current flat `LlilOp` model.

3. **JVM/CIL TABLESWITCH/LOOKUPSWITCH/switch**: these variable-size instructions
   require special handling in the linear disassembler since their size is not
   fixed and depends on byte alignment and table count.

4. **MIPS delay slots in LLIL**: `mips_delay_slot` models delay slots but the
   top-level `Architecture::lift()` may not yet reorder the delay-slot instruction
   correctly before its controlling branch.

5. **SPARC register windows**: `sparc_register_windows` exists but the `RegisterFile`
   abstraction in the hub does not natively support banked/windowed register files.

6. **Lua version detection**: `LuaArch` requires the caller to specify the Lua
   version; there is no autodetect from bytecode header magic.

7. **x86 LLIL for FPU/SIMD categories**: `lift_control_system` and
   `lift_fpu_simd` sub-modules are noted as "filled incrementally by the
   enterprise workflow" and may be partially empty, falling through to `LlilOp::Nop`.

8. **No cross-architecture normalization hookup**: `cross_arch_normalizer` is
   present in the hub but not yet wired to any consumer pipeline.

9. **`rustre-arch-lua` lifter**: no `lift()` implementation is present; the
   Lua and LuaJIT back-ends only decode and disassemble — they do not produce
   LLIL output.

10. **Z80 and 68k LLIL**: both have `lift()` defaulting to `Nop` for most
    instructions; the `Z80FullDecoder` and `M68kDecoder` modules exist but
    are not wired to the `Architecture::lift()` path.
