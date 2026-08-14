//! Flag-manipulation and conditional-move/set handlers for x86/x64 lifting.
//!
//! ## Scope
//!
//! This module implements every x86 instruction that either:
//!
//! * **Directly reads or writes an EFLAGS / RFLAGS field**, or
//! * **Conditionally operates based on a condition code** (`SETcc`, `CMOVcc`).
//!
//! ### Instructions covered
//!
//! | Group                  | Mnemonics                                                    |
//! |------------------------|--------------------------------------------------------------|
//! | Carry flag             | `CLC`, `STC`, `CMC`                                         |
//! | Direction flag         | `CLD`, `STD`                                                 |
//! | Interrupt flag         | `CLI`, `STI`                                                 |
//! | EFLAGS save/restore    | `LAHF`, `SAHF`, `PUSHF`/`PUSHFD`/`PUSHFQ`, `POPF`/`POPFD`/`POPFQ` |
//! | Undocumented / legacy  | `SALC` (alias `SETALC`)                                      |
//! | `SETcc` (16 conditions)  | `SETO`…`SETG`                                               |
//! | `CMOVcc` (16 conditions) | `CMOVO`…`CMOVG`                                             |
//! | SMAP flag control      | `CLAC`, `STAC`                                               |
//! | CR0 flag control       | `CLTS`                                                       |
//!
//! ## Flag semantics summary
//!
//! ### Carry-flag group
//!
//! * `CLC` — CF ← 0. No other flags affected.
//! * `STC` — CF ← 1. No other flags affected.
//! * `CMC` — CF ← ¬CF. No other flags affected.
//!
//! ### Direction-flag group
//!
//! * `CLD` — DF ← 0. String ops use forward direction (SI/DI increment).
//! * `STD` — DF ← 1. String ops use backward direction (SI/DI decrement).
//!
//! ### Interrupt-flag group
//!
//! * `CLI` — IF ← 0. Requires CPL ≤ IOPL; emitted as intrinsic for system modelling.
//! * `STI` — IF ← 1. Same privilege semantics.
//!
//! ### LAHF / SAHF
//!
//! `LAHF` packs the low byte of EFLAGS into AH:
//!
//! ```text
//!   AH[7] = SF, AH[6] = ZF, AH[5] = 0, AH[4] = AF,
//!   AH[3] = 0,  AH[2] = PF, AH[1] = 1, AH[0] = CF
//! ```
//!
//! `SAHF` reverses this: unpacks AH into the low EFLAGS byte, setting
//! SF, ZF, AF, PF, CF from the corresponding bit positions.  OF is **not**
//! affected by either instruction.
//!
//! ### PUSHF / POPF family
//!
//! `PUSHF` pushes the low 16 bits of EFLAGS; `PUSHFD` pushes all 32 bits of
//! EFLAGS; `PUSHFQ` pushes all 64 bits of RFLAGS. The VM/RF bits are treated
//! as reserved in user mode. `POPF`/`POPFD`/`POPFQ` restore the corresponding
//! widths; some bits (VM, IOPL) are only writable at CPL=0.
//!
//! In the IL we model push/pop of EFLAGS via a pack/unpack intrinsic pair so
//! that passes which understand EFLAGS can reconstruct the field values, while
//! passes that don't can treat the operand as an opaque 16/32/64-bit value.
//!
//! ### SALC (Set AL on Carry)
//!
//! Undocumented 8086 instruction (opcode `0xD6`), removed in x86-64.
//! Sets AL ← 0xFF if CF = 1, else AL ← 0x00. Equivalent to `SBB AL, AL`
//! without affecting flags.
//!
//! ### `SETcc`
//!
//! Writes an 8-bit 0 or 1 to a register or memory operand depending on the
//! boolean evaluation of the condition code (see [`cond_expr`]).  Flags are
//! **not** modified.
//!
//! ### `CMOVcc`
//!
//! Conditionally copies a 16/32/64-bit source to a register if the condition
//! holds.  The destination is **always read** (even if the move does not
//! happen) per SDM (the read is architecturally required).  Flags are
//! **not** modified.  In 32-bit mode the upper 32 bits of the destination are
//! zero-extended when the move occurs (standard 32-bit register write rule).
//!
//! ### CLAC / STAC
//!
//! SMAP (Supervisor Mode Access Prevention) control instructions.
//! * `CLAC` — AC flag in EFLAGS ← 0.
//! * `STAC` — AC flag in EFLAGS ← 1.
//!
//! These are privileged instructions (CPL = 0) and are modelled as intrinsics
//! that additionally set the `ac` pseudo-register.
//!
//! ### CLTS
//!
//! Clears the TS (Task Switched) bit in CR0. Privileged. Modelled as an
//! intrinsic.
//!
//! ## Operand-size rules for PUSHF / POPF
//!
//! | Mnemonic | Default width | 66h prefix | 64-bit mode |
//! |----------|---------------|------------|-------------|
//! | PUSHF    | 16 bits       | —          | 64-bit (PUSHFQ effective) |
//! | PUSHFD   | 32 bits       | —          | N/A in 64-bit |
//! | PUSHFQ   | 64 bits       | —          | 64-bit only |
//!
//! ## IR representation
//!
//! All effects follow the `X86LiftCtx::emit_*` discipline:
//!
//! * Flag bits are written via `emit_flagset(FlagId, IrExpr)`.
//! * Pack/unpack of the full EFLAGS byte uses named intrinsics
//!   `x86.lahf.pack`, `x86.sahf.unpack`, `x86.pushf.pack`, `x86.popf.unpack`
//!   so downstream passes can reconstruct individual flag values.
//! * System operations (CLI, STI, CLAC, STAC, CLTS) always emit both the
//!   flag write **and** an intrinsic that captures the privileged side-effect.
//! * `SETcc` emits `x86.setcc.<CC>` followed by a write to the destination.
//! * `CMOVcc` emits `x86.cmovcc.<CC>` followed by a conditional `RegWrite`.

// ─── Standard library & crate imports ────────────────────────────────────────

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_flags::{ConditionCode, cond_expr};
use crate::x86_operand::{operand_size, read_operand, write_operand};
use crate::{IrExpr, LiftError};
use iced_x86::{Instruction, Mnemonic};

// ─────────────────────────────────────────────────────────────────────────────
// Section 1 — Carry flag: CLC, STC, CMC
// ─────────────────────────────────────────────────────────────────────────────

/// `CLC` — Clear Carry Flag.
///
/// Operation: `CF ← 0`
///
/// Encoding: single-byte opcode `F8`. No prefixes affect this instruction.
/// No operands. All other flags unaffected.
///
/// This is used at the start of arithmetic sequences that rely on a known
/// carry state, and as part of multi-precision shift emulation.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | CF   | 0      |
/// | PF   | Unchanged |
/// | AF   | Unchanged |
/// | ZF   | Unchanged |
/// | SF   | Unchanged |
/// | OF   | Unchanged |
/// | DF   | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clc(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // CF := 0 — single μOp.
    ctx.emit_flagset(FlagId::Cf, IrExpr::Const(0));
    Ok(())
}

/// `STC` — Set Carry Flag.
///
/// Operation: `CF ← 1`
///
/// Encoding: single-byte opcode `F9`. No prefixes affect this instruction.
/// No operands. All other flags unaffected.
///
/// Commonly used before multi-precision right-shift sequences (RCR chains)
/// that need an initial carry of 1, or to set CF before a conditional branch.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | CF   | 1      |
/// | PF   | Unchanged |
/// | AF   | Unchanged |
/// | ZF   | Unchanged |
/// | SF   | Unchanged |
/// | OF   | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_stc(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // CF := 1 — single μOp.
    ctx.emit_flagset(FlagId::Cf, IrExpr::Const(1));
    Ok(())
}

/// `CMC` — Complement Carry Flag.
///
/// Operation: `CF ← NOT CF`
///
/// Encoding: single-byte opcode `F5`. No prefixes affect this instruction.
/// No operands. All other flags unaffected.
///
/// Used in some bitwise complement / multi-precision negate sequences to flip
/// the carry once without a full arithmetic operation.
///
/// # IR representation
/// `IrExpr::Not(Box::new(IrExpr::Reg("cf")))` — direct logical complement
/// on the 0/1 flag register.  Because `Not` is bitwise, and CF is always
/// exactly 0 or 1, `!0 = 0xFFFF…FFE` would be wrong; instead we use
/// `IrExpr::CmpEqZero` to produce a boolean flip: `cf == 0`.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | CF   | NOT(old CF) |
/// | PF   | Unchanged |
/// | AF   | Unchanged |
/// | ZF   | Unchanged |
/// | SF   | Unchanged |
/// | OF   | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmc(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // CF := (CF == 0) — logical complement of the 0/1 flag value.
    // IrExpr::Not is bitwise; use CmpEqZero which evaluates to 1 iff cf==0.
    ctx.emit_flagset(
        FlagId::Cf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg("cf".into()))),
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2 — Direction flag: CLD, STD
// ─────────────────────────────────────────────────────────────────────────────

/// `CLD` — Clear Direction Flag.
///
/// Operation: `DF ← 0`
///
/// Encoding: single-byte opcode `FC`. No operands.
/// When DF = 0 string operations (MOVS, LODS, STOS, SCAS, CMPS) increment
/// their pointer registers (SI/DI, ESI/EDI, RSI/RDI) after each iteration.
///
/// Under the System V ABI the direction flag must be clear (= 0) on function
/// entry and exit. Compiler-inserted `cld` at the start of a block is a
/// frequent pattern the lifter will encounter.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | DF   | 0      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cld(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_flagset(FlagId::Df, IrExpr::Const(0));
    Ok(())
}

/// `STD` — Set Direction Flag.
///
/// Operation: `DF ← 1`
///
/// Encoding: single-byte opcode `FD`. No operands.
/// When DF = 1 string operations decrement their pointer registers after each
/// iteration, allowing reverse-direction string processing.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | DF   | 1      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_std(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_flagset(FlagId::Df, IrExpr::Const(1));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3 — Interrupt flag: CLI, STI
// ─────────────────────────────────────────────────────────────────────────────

/// `CLI` — Clear Interrupt Flag.
///
/// Operation: `IF ← 0`
///
/// Encoding: single-byte opcode `FA`. No operands.
/// Disables maskable hardware interrupts.  Requires CPL ≤ IOPL or CR4.VME=1
/// in virtual-8086 mode.  In user-mode analysis contexts this is an unusual
/// but legal instruction (via IOPL=3 grant in some OS environments).
///
/// The lifter emits:
///   1. A `RegWrite` on the `if` pseudo-register (IF ← 0).
///   2. An `x86.cli` intrinsic so system-model passes know a privilege
///      gate was crossed.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | IF   | 0      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cli(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Emit flag update first, then the privilege intrinsic.
    ctx.emit_flagset(FlagId::If, IrExpr::Const(0));
    ctx.emit_intrinsic("x86.cli", vec![]);
    Ok(())
}

/// `STI` — Set Interrupt Flag.
///
/// Operation: `IF ← 1`
///
/// Encoding: single-byte opcode `FB`. No operands.
/// Re-enables maskable hardware interrupts.  Same privilege requirements as
/// CLI.  Note that on x86 the effect of STI is delayed by one instruction —
/// the instruction immediately following STI still executes with interrupts
/// disabled.  This is not modelled in the IL (it requires pipeline semantics).
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | IF   | 1      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sti(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_flagset(FlagId::If, IrExpr::Const(1));
    ctx.emit_intrinsic("x86.sti", vec![]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4 — LAHF / SAHF
// ─────────────────────────────────────────────────────────────────────────────

/// `LAHF` — Load Status Flags into AH.
///
/// Operation (Intel SDM Vol. 1 §7.3.6):
/// ```text
///   AH ← EFLAGS(SF:ZF:0:AF:0:PF:1:CF)
///       Bit positions: 7  6  5  4  3  2  1  0
/// ```
///
/// The bit layout is:
/// * Bit 7 = SF (sign flag)
/// * Bit 6 = ZF (zero flag)
/// * Bit 5 = 0  (reserved, always 0)
/// * Bit 4 = AF (auxiliary carry flag)
/// * Bit 3 = 0  (reserved, always 0)
/// * Bit 2 = PF (parity flag)
/// * Bit 1 = 1  (reserved, always 1)
/// * Bit 0 = CF (carry flag)
///
/// Encoding: opcode `9F`. Available in 64-bit mode on CPUs that advertise
/// LAHF64 support (CPUID.80000001h:ECX.LAHF[bit 0]=1).
///
/// OF is **not** included in AH — this differs from PUSHF which saves the
/// full EFLAGS.
///
/// # IR representation
/// The AH value is computed as:
/// ```text
///   AH = (SF << 7) | (ZF << 6) | (AF << 4) | (PF << 2) | 2 | CF
/// ```
/// where `2` accounts for the always-1 bit at position 1.
///
/// We materialise this expression into a temporary, then write it to AH.
/// The `x86.lahf.pack` intrinsic records the flag sources for passes that
/// want to pattern-match LAHF without re-reading the expression tree.
///
/// # EFLAGS
/// No flags are modified by LAHF. (Read-only from EFLAGS perspective.)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lahf(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let sf = IrExpr::Reg("sf".into());
    let zf = IrExpr::Reg("zf".into());
    let af = IrExpr::Reg("af".into());
    let pf = IrExpr::Reg("pf".into());
    let cf = IrExpr::Reg("cf".into());

    // Build AH = (SF<<7) | (ZF<<6) | (AF<<4) | (PF<<2) | 2 | CF
    let sf_shifted = IrExpr::Shl(Box::new(sf.clone()), Box::new(IrExpr::Const(7)));
    let zf_shifted = IrExpr::Shl(Box::new(zf.clone()), Box::new(IrExpr::Const(6)));
    let af_shifted = IrExpr::Shl(Box::new(af.clone()), Box::new(IrExpr::Const(4)));
    let pf_shifted = IrExpr::Shl(Box::new(pf.clone()), Box::new(IrExpr::Const(2)));

    // Combine: start with CF, OR in each shifted flag and the reserved 1 at bit 1.
    let step0 = cf.clone();
    let step1 = IrExpr::Or(Box::new(step0), Box::new(IrExpr::Const(2))); // always-1 at bit 1
    let step2 = IrExpr::Or(Box::new(step1), Box::new(pf_shifted));
    let step3 = IrExpr::Or(Box::new(step2), Box::new(af_shifted));
    let step4 = IrExpr::Or(Box::new(step3), Box::new(zf_shifted));
    let ah_val = IrExpr::Or(Box::new(step4), Box::new(sf_shifted));

    // Emit the pack intrinsic for pattern-matching passes.
    ctx.emit_intrinsic("x86.lahf.pack", vec![sf, zf, af, pf, cf]);

    // Write the computed value into AH.
    ctx.emit_reg_write("ah", ah_val);
    Ok(())
}

/// `SAHF` — Store AH into Flags.
///
/// Operation (Intel SDM Vol. 1 §7.3.6):
/// ```text
///   EFLAGS(SF:ZF:0:AF:0:PF:1:CF) ← AH
/// ```
///
/// Extracts individual flags from AH:
/// * SF ← AH[7]
/// * ZF ← AH[6]
/// * AF ← AH[4]
/// * PF ← AH[2]
/// * CF ← AH[0]
///
/// OF is **not** modified.
///
/// Encoding: opcode `9E`. Same 64-bit availability note as LAHF.
///
/// # IR representation
/// Each flag is extracted by a shift and AND-with-1 expression. The
/// `x86.sahf.unpack` intrinsic records the AH source register for passes
/// that want to pattern-match SAHF.
///
/// In the IL we additionally emit `IrExpr::Undef` for each extracted flag
/// when the AH value at this point is unknown — the intrinsic allows passes
/// to recover the concrete bit once AH is resolved.  When AH is a known
/// constant we can constant-fold these extractions, but that is left to the
/// optimiser.
///
/// # EFLAGS
/// | Flag | Result       |
/// |------|--------------|
/// | SF   | AH[7]        |
/// | ZF   | AH[6]        |
/// | AF   | AH[4]        |
/// | PF   | AH[2]        |
/// | CF   | AH[0]        |
/// | OF   | Unchanged    |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sahf(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ah = IrExpr::Reg("ah".into());

    // Emit unpack intrinsic first.
    ctx.emit_intrinsic("x86.sahf.unpack", vec![ah.clone()]);

    // SF = (AH >> 7) & 1
    let sf_val = IrExpr::And(
        Box::new(IrExpr::Shr(
            Box::new(ah.clone()),
            Box::new(IrExpr::Const(7)),
        )),
        Box::new(IrExpr::Const(1)),
    );
    // ZF = (AH >> 6) & 1
    let zf_val = IrExpr::And(
        Box::new(IrExpr::Shr(
            Box::new(ah.clone()),
            Box::new(IrExpr::Const(6)),
        )),
        Box::new(IrExpr::Const(1)),
    );
    // AF = (AH >> 4) & 1
    let af_val = IrExpr::And(
        Box::new(IrExpr::Shr(
            Box::new(ah.clone()),
            Box::new(IrExpr::Const(4)),
        )),
        Box::new(IrExpr::Const(1)),
    );
    // PF = (AH >> 2) & 1
    let pf_val = IrExpr::And(
        Box::new(IrExpr::Shr(
            Box::new(ah.clone()),
            Box::new(IrExpr::Const(2)),
        )),
        Box::new(IrExpr::Const(1)),
    );
    // CF = AH & 1
    let cf_val = IrExpr::And(Box::new(ah), Box::new(IrExpr::Const(1)));

    ctx.emit_flagset(FlagId::Sf, sf_val);
    ctx.emit_flagset(FlagId::Zf, zf_val);
    ctx.emit_flagset(FlagId::Af, af_val);
    ctx.emit_flagset(FlagId::Pf, pf_val);
    ctx.emit_flagset(FlagId::Cf, cf_val);
    // OF is explicitly NOT modified by SAHF.
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5 — PUSHF / PUSHFD / PUSHFQ
// ─────────────────────────────────────────────────────────────────────────────

/// EFLAGS register field definitions (bit positions in the 32-bit EFLAGS register).
///
/// Used by PUSHF/POPF pack/unpack intrinsics.
///
/// ```text
/// Bit  31-22  21   20   19   18   17   16   15  14   13-12  11
///      Resv  ID   VIP  VIF  AC  VM   RF  Resv  NT   IOPL   OF
///
/// Bit  10    9    8    7    6    5    4    3    2    1    0
///      DF    IF   TF   SF   ZF  Resv  AF  Resv  PF  Resv  CF
/// ```
///
/// The constants below give the bit position of each observable flag within
/// the 32-bit EFLAGS value.
pub mod eflags_bits {
    /// Carry Flag — EFLAGS bit 0.
    pub const CF: u64 = 0;
    /// Reserved (always 1) — EFLAGS bit 1.
    pub const RESERVED_1: u64 = 1;
    /// Parity Flag — EFLAGS bit 2.
    pub const PF: u64 = 2;
    /// Reserved (always 0) — EFLAGS bit 3.
    pub const RESERVED_3: u64 = 3;
    /// Auxiliary Carry Flag — EFLAGS bit 4.
    pub const AF: u64 = 4;
    /// Reserved (always 0) — EFLAGS bit 5.
    pub const RESERVED_5: u64 = 5;
    /// Zero Flag — EFLAGS bit 6.
    pub const ZF: u64 = 6;
    /// Sign Flag — EFLAGS bit 7.
    pub const SF: u64 = 7;
    /// Trap Flag — EFLAGS bit 8.
    pub const TF: u64 = 8;
    /// Interrupt Enable Flag — EFLAGS bit 9.
    pub const IF: u64 = 9;
    /// Direction Flag — EFLAGS bit 10.
    pub const DF: u64 = 10;
    /// Overflow Flag — EFLAGS bit 11.
    pub const OF: u64 = 11;
    /// I/O Privilege Level (2 bits) — EFLAGS bits 12-13.
    pub const IOPL: u64 = 12;
    /// Nested Task — EFLAGS bit 14.
    pub const NT: u64 = 14;
    /// Resume Flag — EFLAGS bit 16.
    pub const RF: u64 = 16;
    /// Virtual-8086 Mode — EFLAGS bit 17.
    pub const VM: u64 = 17;
    /// Alignment Check / SMAP Enable — EFLAGS bit 18.
    pub const AC: u64 = 18;
    /// Virtual Interrupt Flag — EFLAGS bit 19.
    pub const VIF: u64 = 19;
    /// Virtual Interrupt Pending — EFLAGS bit 20.
    pub const VIP: u64 = 20;
    /// CPUID-capable indicator — EFLAGS bit 21.
    pub const ID: u64 = 21;
}

/// Build an `IrExpr` that packs the modelled EFLAGS bits into a single integer
/// value of the specified `width` in bytes.
///
/// The expression form is:
/// ```text
///   (CF<<0) | 2 | (PF<<2) | (AF<<4) | (ZF<<6) | (SF<<7) | (IF<<9) | (DF<<10) | (OF<<11)
/// ```
///
/// System bits (TF, IOPL, NT, RF, VM, AC, VIF, VIP, ID) are not modelled in
/// the IL flag registers and are set to 0 in the packed value, except for the
/// always-1 reserved bit 1.  Passes that need system-bit values must consult
/// the `x86.pushf.pack` intrinsic arguments.
///
/// # Parameters
/// * `width` — the byte-width of the EFLAGS to pack (2 = PUSHF 16-bit,
///   4 = PUSHFD 32-bit, 8 = PUSHFQ 64-bit).
#[must_use]
fn build_eflags_expr(_width: u8) -> IrExpr {
    use eflags_bits as B;

    let flag = |name: &'static str| IrExpr::Reg(name.into());
    let shl = |e: IrExpr, n: u64| IrExpr::Shl(Box::new(e), Box::new(IrExpr::Const(n)));
    let or = |l: IrExpr, r: IrExpr| IrExpr::Or(Box::new(l), Box::new(r));

    // Always-1 bit at position 1.
    let base = IrExpr::Const(1 << B::RESERVED_1);

    [
        flag("cf"),
        shl(flag("pf"), B::PF),
        shl(flag("af"), B::AF),
        shl(flag("zf"), B::ZF),
        shl(flag("sf"), B::SF),
        shl(flag("if"), B::IF),
        shl(flag("df"), B::DF),
        shl(flag("of"), B::OF),
    ]
    .into_iter()
    .fold(base, or)
}

/// `PUSHF` / `PUSHFD` / `PUSHFQ` — Push EFLAGS / EFLAGS / RFLAGS onto stack.
///
/// Operations:
/// * `PUSHF`  — push 16-bit low EFLAGS; SP ← SP − 2.
/// * `PUSHFD` — push 32-bit EFLAGS; ESP ← ESP − 4.
/// * `PUSHFQ` — push 64-bit RFLAGS; RSP ← RSP − 8.
///
/// In 64-bit mode `PUSHF` is actually `PUSHFQ` by default (the operand-size
/// prefix can force 16-bit form). The `ModeHint::op_size_override` field
/// carries the 66h prefix state.
///
/// Modelled effects:
///   1. `x86.pushf.pack` intrinsic records the full flag state.
///   2. The packed EFLAGS value is computed and materialised into a temp.
///   3. RSP / ESP / SP is decremented by the operand width.
///   4. The EFLAGS value is written to [RSP].
///
/// No flag registers are modified by PUSHF (the write is to memory, not to
/// the flags themselves).
///
/// # EFLAGS
/// Unchanged.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushf(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Determine the push width from the mnemonic, not the mode prefix,
    // because iced-x86 already resolved the effective operand size in the
    // mnemonic (PUSHF vs PUSHFD vs PUSHFQ).
    let width_bytes: u8 = match instr.mnemonic() {
        Mnemonic::Pushf => 2,
        Mnemonic::Pushfd => 4,
        Mnemonic::Pushfq => 8,
        // In 64-bit mode "PUSHF" is PUSHFQ; iced reports Pushfq.
        _ => ctx.default_op_size(),
    };

    let sp = ctx.stack_ptr();
    let sp_size = ctx.stack_ptr_size();

    // Emit the pack intrinsic so passes can see all flag inputs.
    ctx.emit_intrinsic(
        "x86.pushf.pack",
        vec![
            IrExpr::Reg("cf".into()),
            IrExpr::Reg("pf".into()),
            IrExpr::Reg("af".into()),
            IrExpr::Reg("zf".into()),
            IrExpr::Reg("sf".into()),
            IrExpr::Reg("if".into()),
            IrExpr::Reg("df".into()),
            IrExpr::Reg("of".into()),
        ],
    );

    // Build and materialise the EFLAGS value.
    let eflags_val = build_eflags_expr(width_bytes);
    let eflags_tmp = ctx.materialise(eflags_val);

    // Decrement the stack pointer: SP ← SP − width_bytes.
    let new_sp = IrExpr::Sub(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(u64::from(width_bytes))),
    );
    ctx.emit_reg_write(sp, new_sp.clone());

    // Write EFLAGS to [new_sp].
    ctx.emit_mem_write(new_sp, IrExpr::Reg(eflags_tmp), width_bytes * 8);

    let _ = sp_size; // used implicitly via sp string selection
    Ok(())
}

/// `POPF` / `POPFD` / `POPFQ` — Pop EFLAGS / EFLAGS / RFLAGS from stack.
///
/// Operations:
/// * `POPF`  — pop 16-bit value into low EFLAGS; SP ← SP + 2.
/// * `POPFD` — pop 32-bit value into EFLAGS; ESP ← ESP + 4.
/// * `POPFQ` — pop 64-bit value into RFLAGS; RSP ← RSP + 8.
///
/// Modelled effects:
///   1. The value at [RSP] is read into a temporary.
///   2. `x86.popf.unpack` intrinsic records the source for pattern-matching.
///   3. Each modelled flag register is written by extracting its bit from
///      the popped value.
///   4. RSP is incremented by the operand width.
///
/// Some EFLAGS bits (IOPL, VM) can only be written by CPL=0 code; they are
/// modelled as `Undef` in user-mode analysis.
///
/// # EFLAGS
/// | Flag | Result      |
/// |------|-------------|
/// | CF   | popped[0]   |
/// | PF   | popped[2]   |
/// | AF   | popped[4]   |
/// | ZF   | popped[6]   |
/// | SF   | popped[7]   |
/// | IF   | popped[9]   |
/// | DF   | popped[10]  |
/// | OF   | popped[11]  |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popf(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use eflags_bits as B;
    let width_bytes: u8 = match instr.mnemonic() {
        Mnemonic::Popf => 2,
        Mnemonic::Popfd => 4,
        Mnemonic::Popfq => 8,
        _ => ctx.default_op_size(),
    };

    let sp = ctx.stack_ptr();

    // Read the EFLAGS value from [RSP].
    let sp_val = IrExpr::Reg(sp.into());
    let mem_tmp = ctx.fresh_temp();
    ctx.emit_mem_read(sp_val.clone(), mem_tmp.clone(), width_bytes * 8);

    let mem = IrExpr::Reg(mem_tmp);

    // Emit the unpack intrinsic.
    ctx.emit_intrinsic("x86.popf.unpack", vec![mem.clone()]);

    // Increment the stack pointer.
    let new_sp = IrExpr::Add(
        Box::new(sp_val),
        Box::new(IrExpr::Const(u64::from(width_bytes))),
    );
    ctx.emit_reg_write(sp, new_sp);

    // Extract each flag bit from the popped value.
    let extract = |val: &IrExpr, bit: u64| -> IrExpr {
        IrExpr::And(
            Box::new(IrExpr::Shr(
                Box::new(val.clone()),
                Box::new(IrExpr::Const(bit)),
            )),
            Box::new(IrExpr::Const(1)),
        )
    };

    ctx.emit_flagset(FlagId::Cf, extract(&mem, B::CF));
    ctx.emit_flagset(FlagId::Pf, extract(&mem, B::PF));
    ctx.emit_flagset(FlagId::Af, extract(&mem, B::AF));
    ctx.emit_flagset(FlagId::Zf, extract(&mem, B::ZF));
    ctx.emit_flagset(FlagId::Sf, extract(&mem, B::SF));
    ctx.emit_flagset(FlagId::If, extract(&mem, B::IF));
    ctx.emit_flagset(FlagId::Df, extract(&mem, B::DF));
    ctx.emit_flagset(FlagId::Of, extract(&mem, B::OF));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 6 — SALC (undocumented, 8086 / 32-bit only)
// ─────────────────────────────────────────────────────────────────────────────

/// `SALC` / `SETALC` — Set AL on Carry (undocumented).
///
/// Operation: `AL ← 0xFF if CF = 1, else AL ← 0x00`
///
/// Encoding: single-byte opcode `D6` (undefined on i486 and earlier,
/// documented as "Set AL on Carry" in the FPU/CPU manuals for the 8086 /
/// 8088 / 80286 / 80386 / 80486). The instruction is **not valid in 64-bit
/// mode** — the `D6` opcode is #UD there.
///
/// Equivalent effect to `SBB AL, AL` but **without modifying any flags**.
/// The AL register gets 0xFF when CF=1 (since 0−0−1 = −1 = 0xFF in 8-bit),
/// or 0x00 when CF=0 (since 0−0−0 = 0).
///
/// # IR representation
/// ```text
///   __t0 = cf              ; read current carry
///   __t1 = 0 - __t0       ; arithmetic negate: 0 when CF=0, 0xFF when CF=1
///   al = __t1 & 0xFF       ; truncate to 8 bits (the Sub produces a 64-bit value)
/// ```
///
/// An `x86.salc` intrinsic is also emitted to let system passes identify this
/// undocumented instruction.
///
/// # EFLAGS
/// None modified (unlike SBB AL, AL).
///
/// # Availability
/// Not valid in 64-bit mode. In 32-bit / 16-bit mode only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_salc(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Emit identifier intrinsic.
    ctx.emit_intrinsic("x86.salc", vec![IrExpr::Reg("cf".into())]);

    // AL = 0 - CF (arithmetic: CF==0 → AL=0, CF==1 → AL=0xFF in 8-bit).
    let cf_tmp = ctx.materialise(IrExpr::Reg("cf".into()));
    let neg_cf = IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(IrExpr::Reg(cf_tmp)));
    // Mask to 8 bits.
    let al_val = IrExpr::And(Box::new(neg_cf), Box::new(IrExpr::Const(0xFF)));
    ctx.emit_reg_write("al", al_val);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 7 — SETcc (16 conditions)
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: map an iced-x86 mnemonic to a `ConditionCode`.
///
/// Used internally by `lift_setcc` and `lift_cmovcc` to avoid going through
/// iced's `condition_code()` accessor which may return `None` for some forms.
#[must_use]
const fn mnemonic_to_cc_setcc(m: Mnemonic) -> Option<ConditionCode> {
    Some(match m {
        Mnemonic::Seto => ConditionCode::O,
        Mnemonic::Setno => ConditionCode::No,
        Mnemonic::Setb => ConditionCode::B,
        Mnemonic::Setae => ConditionCode::Ae,
        Mnemonic::Sete => ConditionCode::E,
        Mnemonic::Setne => ConditionCode::Ne,
        Mnemonic::Setbe => ConditionCode::Be,
        Mnemonic::Seta => ConditionCode::A,
        Mnemonic::Sets => ConditionCode::S,
        Mnemonic::Setns => ConditionCode::Ns,
        Mnemonic::Setp => ConditionCode::P,
        Mnemonic::Setnp => ConditionCode::Np,
        Mnemonic::Setl => ConditionCode::L,
        Mnemonic::Setge => ConditionCode::Ge,
        Mnemonic::Setle => ConditionCode::Le,
        Mnemonic::Setg => ConditionCode::G,
        _ => return None,
    })
}

/// `SETcc` — Set byte on condition.
///
/// Operation: `dst ← ZeroExtend(CONDITION, 8)`
///
/// All 16 condition codes are handled by a single function; the specific
/// condition is decoded from the instruction mnemonic.
///
/// ## All 16 condition codes and their EFLAGS expressions
///
/// | CC | Mnemonic | EFLAGS expression                          | Aliases   |
/// |----|----------|--------------------------------------------|-----------|
/// |  0 | SETO     | OF = 1                                     |           |
/// |  1 | SETNO    | OF = 0                                     |           |
/// |  2 | SETB     | CF = 1                                     | SETC/SETNAE |
/// |  3 | SETAE    | CF = 0                                     | SETNB/SETNC |
/// |  4 | SETE     | ZF = 1                                     | SETZ      |
/// |  5 | SETNE    | ZF = 0                                     | SETNZ     |
/// |  6 | SETBE    | CF = 1 OR ZF = 1                           | SETNA     |
/// |  7 | SETA     | CF = 0 AND ZF = 0                          | SETNBE    |
/// |  8 | SETS     | SF = 1                                     |           |
/// |  9 | SETNS    | SF = 0                                     |           |
/// | 10 | SETP     | PF = 1                                     | SETPE     |
/// | 11 | SETNP    | PF = 0                                     | SETPO     |
/// | 12 | SETL     | SF ≠ OF                                    | SETNGE    |
/// | 13 | SETGE    | SF = OF                                    | SETNL     |
/// | 14 | SETLE    | ZF = 1 OR SF ≠ OF                          | SETNG     |
/// | 15 | SETG     | ZF = 0 AND SF = OF                         | SETNLE    |
///
/// ## Encodings
///
/// All `SETcc` instructions use the two-byte opcode `0F 9X` where the low
/// nibble of the second byte encodes the condition code (0–15).  The
/// destination is always an 8-bit register or memory operand; there is no
/// 16/32/64-bit form (unlike `CMOVcc`).
///
/// In 64-bit mode the `REX.R` prefix extends the destination register to
/// the R8L–R15L range.
///
/// ## IR representation
///
/// The condition expression (from [`cond_expr`]) is already a boolean 0/1
/// value by construction.  We:
/// 1. Emit `x86.setcc.<CC>` intrinsic to label the operation for pattern
///    matching passes.
/// 2. Write the condition expression directly to the destination operand.
///
/// The destination operand is always 8 bits; `write_operand` handles the
/// size constraint.
///
/// ## EFLAGS
/// No flags are modified by `SETcc` instructions.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setcc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Resolve condition code from the mnemonic for exhaustive coverage.
    let cc = mnemonic_to_cc_setcc(instr.mnemonic())
        .or_else(|| ConditionCode::from_iced(instr.condition_code()))
        .ok_or_else(|| {
            LiftError::LiftFailed(
                ctx.addr,
                format!(
                    "SETcc: unknown condition code for mnemonic {:?}",
                    instr.mnemonic()
                ),
            )
        })?;

    let cond = cond_expr(cc);

    // Emit the identifying intrinsic.
    ctx.emit_intrinsic(format!("x86.setcc.{cc:?}"), vec![cond.clone()]);

    // Write the boolean (0 or 1) to the 8-bit destination.
    write_operand(instr, 0, cond, ctx);
    Ok(())
}

// Detailed per-condition wrapper functions for completeness and documentation.
// These call the unified lift_setcc above; they exist so callers can dispatch
// to a specific mnemonic for testing or for future specialised analysis passes.

/// `SETO` — Set if Overflow (OF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_seto(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETNO` — Set if Not Overflow (OF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setno(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETB` / `SETC` / `SETNAE` — Set if Below / Carry (CF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setb(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETAE` / `SETNB` / `SETNC` — Set if Above or Equal / Not Carry (CF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setae(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETE` / `SETZ` — Set if Equal / Zero (ZF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sete(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETNE` / `SETNZ` — Set if Not Equal / Not Zero (ZF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setne(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETBE` / `SETNA` — Set if Below or Equal / Not Above (CF = 1 OR ZF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setbe(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETA` / `SETNBE` — Set if Above / Not Below or Equal (CF = 0 AND ZF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_seta(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETS` — Set if Sign (SF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sets(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETNS` — Set if Not Sign (SF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setns(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETP` / `SETPE` — Set if Parity / Parity Even (PF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETNP` / `SETPO` — Set if Not Parity / Parity Odd (PF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setnp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETL` / `SETNGE` — Set if Less / Not Greater or Equal (SF ≠ OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETGE` / `SETNL` — Set if Greater or Equal / Not Less (SF = OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setge(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETLE` / `SETNG` — Set if Less or Equal / Not Greater (ZF = 1 OR SF ≠ OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setle(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

/// `SETG` / `SETNLE` — Set if Greater / Not Less or Equal (ZF = 0 AND SF = OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 8 — CMOVcc (16 conditions)
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: map a `CMOVcc` mnemonic to a `ConditionCode`.
#[must_use]
const fn mnemonic_to_cc_cmov(m: Mnemonic) -> Option<ConditionCode> {
    Some(match m {
        Mnemonic::Cmovo => ConditionCode::O,
        Mnemonic::Cmovno => ConditionCode::No,
        Mnemonic::Cmovb => ConditionCode::B,
        Mnemonic::Cmovae => ConditionCode::Ae,
        Mnemonic::Cmove => ConditionCode::E,
        Mnemonic::Cmovne => ConditionCode::Ne,
        Mnemonic::Cmovbe => ConditionCode::Be,
        Mnemonic::Cmova => ConditionCode::A,
        Mnemonic::Cmovs => ConditionCode::S,
        Mnemonic::Cmovns => ConditionCode::Ns,
        Mnemonic::Cmovp => ConditionCode::P,
        Mnemonic::Cmovnp => ConditionCode::Np,
        Mnemonic::Cmovl => ConditionCode::L,
        Mnemonic::Cmovge => ConditionCode::Ge,
        Mnemonic::Cmovle => ConditionCode::Le,
        Mnemonic::Cmovg => ConditionCode::G,
        _ => return None,
    })
}

/// `CMOVcc` — Conditional Move.
///
/// Operation: `if (CONDITION) dst ← src`
///
/// All 16 condition codes share this handler; the specific condition is
/// decoded from the instruction mnemonic.
///
/// ## Condition code table
///
/// | CC | Mnemonic  | EFLAGS expression              |
/// |----|-----------|-------------------------------|
/// |  0 | CMOVO     | OF = 1                        |
/// |  1 | CMOVNO    | OF = 0                        |
/// |  2 | CMOVB     | CF = 1                        |
/// |  3 | CMOVAE    | CF = 0                        |
/// |  4 | CMOVE     | ZF = 1                        |
/// |  5 | CMOVNE    | ZF = 0                        |
/// |  6 | CMOVBE    | CF = 1 OR ZF = 1              |
/// |  7 | CMOVA     | CF = 0 AND ZF = 0             |
/// |  8 | CMOVS     | SF = 1                        |
/// |  9 | CMOVNS    | SF = 0                        |
/// | 10 | CMOVP     | PF = 1                        |
/// | 11 | CMOVNP    | PF = 0                        |
/// | 12 | CMOVL     | SF ≠ OF                       |
/// | 13 | CMOVGE    | SF = OF                       |
/// | 14 | CMOVLE    | ZF = 1 OR SF ≠ OF             |
/// | 15 | CMOVG     | ZF = 0 AND SF = OF            |
///
/// ## Operand sizes
///
/// `CMOVcc` is available only in 32/64-bit mode (requires P6 / Pentium Pro or
/// later).  Operand sizes:
///
/// | Mode    | No prefix | 66h prefix |
/// |---------|-----------|------------|
/// | 32-bit  | 32-bit    | 16-bit     |
/// | 64-bit  | 32-bit    | 16-bit     |
/// | 64-bit + REX.W | 64-bit | —     |
///
/// In 64-bit mode a 32-bit CMOV **zero-extends** the result to 64 bits even
/// when the condition is false (because the destination register always sees
/// the 64-bit write). However the SDM specifies that the destination is
/// _not_ modified when the condition is false; we faithfully model this by
/// reading the destination register as the "false" branch.
///
/// ## IR representation
///
/// The IR lacks a `Select` (ternary) primitive.  We model `CMOVcc` as:
///
/// ```text
///   __src = read_operand(src)               ; always read source
///   __dst_old = read_operand(dst)           ; always read destination
///   // condition expression c ∈ {0, 1}
///   // c * src + (1 - c) * dst_old
///   __c_minus_1 = c - 1                    ; 0 when c=1, 0xFFFF…FF when c=0
///   __masked_src = src & ~(c - 1)          ; zero when c=0
///   __masked_dst = dst_old & (c - 1)       ; zero when c=1
///   dst = __masked_src | __masked_dst
/// ```
///
/// This branchless formulation avoids introducing a Branch effect into the
/// IL (which would split the basic block) and keeps the instruction as a
/// single basic-block entity.  The `x86.cmovcc.<CC>` intrinsic records the
/// full semantics for passes that prefer the branch form.
///
/// ## EFLAGS
/// No flags are modified by `CMOVcc`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovcc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cc = mnemonic_to_cc_cmov(instr.mnemonic())
        .or_else(|| ConditionCode::from_iced(instr.condition_code()))
        .ok_or_else(|| {
            LiftError::LiftFailed(
                ctx.addr,
                format!(
                    "CMOVcc: unknown condition for mnemonic {:?}",
                    instr.mnemonic()
                ),
            )
        })?;

    let bits = operand_size(instr, 0, ctx);
    let cond = cond_expr(cc);

    // Always read the source operand (architectural requirement).
    let src_expr = read_operand(instr, 1, ctx);
    let src_tmp = ctx.materialise(src_expr);

    // Always read the current destination value.
    let dst_expr = read_operand(instr, 0, ctx);
    let dst_tmp = ctx.materialise(dst_expr);

    // Emit the identifying intrinsic.
    ctx.emit_intrinsic(
        format!("x86.cmovcc.{cc:?}"),
        vec![
            cond.clone(),
            IrExpr::Reg(src_tmp.clone()),
            IrExpr::Reg(dst_tmp.clone()),
        ],
    );

    // Branchless select:
    //   c is a 0/1 boolean.
    //   mask = 0 - c  →  0x00…00 when c=0, 0xFF…FF when c=1.
    //   result = (src & mask) | (dst_old & ~mask)
    //
    // We need the mask to cover `bits` bits.  Since IrExpr arithmetic is
    // 64-bit we AND with a width mask afterward.
    let cond_tmp = ctx.materialise(cond);
    let mask = IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(IrExpr::Reg(cond_tmp)));
    let mask_tmp = ctx.materialise(mask);

    // Width mask for the operand size.
    let width_mask: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };

    let src_masked = IrExpr::And(
        Box::new(IrExpr::Reg(src_tmp)),
        Box::new(IrExpr::And(
            Box::new(IrExpr::Reg(mask_tmp.clone())),
            Box::new(IrExpr::Const(width_mask)),
        )),
    );
    let not_mask = IrExpr::And(
        Box::new(IrExpr::Not(Box::new(IrExpr::Reg(mask_tmp)))),
        Box::new(IrExpr::Const(width_mask)),
    );
    let dst_masked = IrExpr::And(Box::new(IrExpr::Reg(dst_tmp)), Box::new(not_mask));
    let result = IrExpr::Or(Box::new(src_masked), Box::new(dst_masked));

    // Write result back to the destination operand.
    write_operand(instr, 0, result, ctx);
    Ok(())
}

// Per-condition wrapper functions — delegate to the unified handler.

/// `CMOVO` — Conditional move if Overflow (OF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovo(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVNO` — Conditional move if Not Overflow (OF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovno(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVB` / `CMOVC` / `CMOVNAE` — Conditional move if Below / Carry (CF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovb(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVAE` / `CMOVNB` / `CMOVNC` — Conditional move if Above or Equal (CF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovae(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVE` / `CMOVZ` — Conditional move if Equal / Zero (ZF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmove(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVNE` / `CMOVNZ` — Conditional move if Not Equal / Not Zero (ZF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovne(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVBE` / `CMOVNA` — Conditional move if Below or Equal (CF = 1 OR ZF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovbe(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVA` / `CMOVNBE` — Conditional move if Above (CF = 0 AND ZF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmova(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVS` — Conditional move if Sign (SF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVNS` — Conditional move if Not Sign (SF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovns(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVP` / `CMOVPE` — Conditional move if Parity Even (PF = 1).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVNP` / `CMOVPO` — Conditional move if Parity Odd (PF = 0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovnp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVL` / `CMOVNGE` — Conditional move if Less (SF ≠ OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVGE` / `CMOVNL` — Conditional move if Greater or Equal (SF = OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovge(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVLE` / `CMOVNG` — Conditional move if Less or Equal (ZF = 1 OR SF ≠ OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovle(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

/// `CMOVG` / `CMOVNLE` — Conditional move if Greater (ZF = 0 AND SF = OF).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_cmovcc(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 9 — CLAC / STAC (SMAP AC flag control)
// ─────────────────────────────────────────────────────────────────────────────

/// `CLAC` — Clear AC Flag (SMAP).
///
/// Operation: `EFLAGS.AC ← 0`
///
/// Encoding: `0F 01 CA` (three-byte). Privileged instruction (CPL = 0).
/// Introduced with Intel Broadwell (SMAP feature). When AC = 0, the CPU
/// will raise a protection fault if supervisor-mode code attempts to access
/// user-mode pages (SMAP enforcement).
///
/// The AC bit is at EFLAGS bit 18 (`eflags_bits::AC`).
///
/// # IR representation
/// Emits:
/// 1. `x86.clac` intrinsic — records the privileged operation.
/// 2. `RegWrite { reg: "ac", value: Const(0) }` — clears the pseudo AC register.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | AC   | 0      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clac(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.clac", vec![]);
    // Write to pseudo-register "ac" representing EFLAGS.AC.
    ctx.emit_reg_write("ac", IrExpr::Const(0));
    Ok(())
}

/// `STAC` — Set AC Flag (SMAP).
///
/// Operation: `EFLAGS.AC ← 1`
///
/// Encoding: `0F 01 CB` (three-byte). Privileged instruction (CPL = 0).
/// When AC = 1, SMAP protection is temporarily disabled, allowing
/// supervisor-mode code to access user-mode pages.  OS kernels use this
/// pattern:
///
/// ```asm
/// stac          ; disable SMAP
/// mov rax, [user_ptr]  ; safe to access user memory now
/// clac          ; re-enable SMAP
/// ```
///
/// # IR representation
/// Emits:
/// 1. `x86.stac` intrinsic.
/// 2. `RegWrite { reg: "ac", value: Const(1) }`.
///
/// # EFLAGS
/// | Flag | Result |
/// |------|--------|
/// | AC   | 1      |
/// | All others | Unchanged |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_stac(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.stac", vec![]);
    ctx.emit_reg_write("ac", IrExpr::Const(1));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 10 — CLTS (CR0.TS flag control)
// ─────────────────────────────────────────────────────────────────────────────

/// `CLTS` — Clear Task-Switched Flag in CR0.
///
/// Operation: `CR0.TS ← 0`
///
/// Encoding: `0F 06` (two-byte). Privileged instruction (CPL = 0).
/// The TS (Task-Switched) bit in CR0 is set by the CPU when a task switch
/// occurs and causes `#NM` (Device Not Available) on the next x87 FPU or SSE
/// instruction.  The OS task-switch handler must execute `CLTS` before
/// restoring the FPU context for the new task.
///
/// Unlike CLAC/STAC this instruction affects a control register (CR0), not
/// EFLAGS.  It is modelled as a pure intrinsic with a CR0.TS pseudo-register
/// update.
///
/// # IR representation
/// Emits:
/// 1. `x86.clts` intrinsic — records the privileged CR0 write.
/// 2. `RegWrite { reg: "cr0_ts", value: Const(0) }` — pseudo-register for
///    the TS bit.
///
/// # EFLAGS / Flags
/// No EFLAGS bits are modified.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clts(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.clts", vec![]);
    // Pseudo-register cr0_ts models the TS bit of CR0 for data-flow.
    ctx.emit_reg_write("cr0_ts", IrExpr::Const(0));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 11 — Conditional prefix / REP prefix effects on EFLAGS
// ─────────────────────────────────────────────────────────────────────────────

/// Emit the EFLAGS dependency declaration for a REP-prefixed string operation.
///
/// REP-prefixed instructions (REPE/REPZ, REPNE/REPNZ) read ZF (and in some
/// cases CF) to determine loop continuation.  This helper emits an intrinsic
/// that tells downstream analyses which flags are consumed by the prefix.
///
/// This function is called from the string-ops handler after it emits the
/// per-iteration effects but before the REP loop model is closed.
///
/// # Arguments
/// * `prefix_kind` — one of `"rep"`, `"repe"` / `"repz"`, `"repne"` / `"repnz"`.
/// * `ctx` — current lifting context.
pub fn emit_rep_prefix_flags_dep(prefix_kind: &str, ctx: &mut X86LiftCtx) {
    match prefix_kind {
        "repe" | "repz" => {
            // REPE/REPZ terminates when ZF = 0.
            ctx.emit_intrinsic("x86.rep.flags_read.zf", vec![IrExpr::Reg("zf".into())]);
        }
        "repne" | "repnz" => {
            // REPNE/REPNZ terminates when ZF = 1.
            ctx.emit_intrinsic("x86.repne.flags_read.zf", vec![IrExpr::Reg("zf".into())]);
        }
        _ => {
            // Plain REP — only reads ECX/RCX, no flags.
            ctx.emit_intrinsic("x86.rep.flags_read.none", vec![]);
        }
    }
}

/// Declare the EFLAGS read set for a given `ConditionCode`.
///
/// This is used by the analysis layer to compute flag liveness: for each
/// conditional instruction (Jcc, `SETcc`, `CMOVcc`) we can determine exactly
/// which flags are live at the use site without evaluating the full expression
/// tree.
///
/// Returns a `&'static [&'static str]` slice of the canonical flag register
/// names read by the given condition code.
///
/// # Condition flag read table
///
/// | CC  | Flags read         |
/// |-----|--------------------|
/// | O   | of                 |
/// | No  | of                 |
/// | B   | cf                 |
/// | Ae  | cf                 |
/// | E   | zf                 |
/// | Ne  | zf                 |
/// | Be  | cf, zf             |
/// | A   | cf, zf             |
/// | S   | sf                 |
/// | Ns  | sf                 |
/// | P   | pf                 |
/// | Np  | pf                 |
/// | L   | sf, of             |
/// | Ge  | sf, of             |
/// | Le  | zf, sf, of         |
/// | G   | zf, sf, of         |
#[must_use]
pub const fn flags_read_by_cc(cc: ConditionCode) -> &'static [&'static str] {
    match cc {
        ConditionCode::O | ConditionCode::No => &["of"],
        ConditionCode::B | ConditionCode::Ae => &["cf"],
        ConditionCode::E | ConditionCode::Ne => &["zf"],
        ConditionCode::Be | ConditionCode::A => &["cf", "zf"],
        ConditionCode::S | ConditionCode::Ns => &["sf"],
        ConditionCode::P | ConditionCode::Np => &["pf"],
        ConditionCode::L | ConditionCode::Ge => &["sf", "of"],
        ConditionCode::Le | ConditionCode::G => &["zf", "sf", "of"],
    }
}

/// Emit a flag-liveness annotation intrinsic for a conditional instruction.
///
/// Emits `x86.flags_read.<cc>` with the set of flags read by the condition.
/// This is a zero-cost metadata emission: downstream dead-flag-elimination
/// passes consume this intrinsic but it does not affect data-flow.
pub fn emit_flags_read_annotation(cc: ConditionCode, ctx: &mut X86LiftCtx) {
    let flags = flags_read_by_cc(cc)
        .iter()
        .map(|&f| IrExpr::Reg(f.into()))
        .collect::<Vec<_>>();
    ctx.emit_intrinsic(format!("x86.flags_read.{cc:?}"), flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 12 — Utilities: eflags snapshot / restore helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a complete EFLAGS snapshot into a named temporary register.
///
/// Used by handlers that need to capture the full EFLAGS state at a particular
/// point (e.g. before a POPF clears flags, or for IRET modelling).
///
/// Returns the name of the temporary register holding the packed EFLAGS value.
pub fn emit_eflags_snapshot(ctx: &mut X86LiftCtx, width_bytes: u8) -> String {
    let val = build_eflags_expr(width_bytes);
    ctx.materialise(val)
}

/// Emit a full EFLAGS restore from a packed integer expression.
///
/// Extracts each modelled flag bit from `packed` and writes it to the
/// corresponding flag pseudo-register.  Mirrors the pop half of POPF.
pub fn emit_eflags_restore(ctx: &mut X86LiftCtx, packed: &IrExpr) {
    use eflags_bits as B;
    let extract = |val: &IrExpr, bit: u64| -> IrExpr {
        IrExpr::And(
            Box::new(IrExpr::Shr(
                Box::new(val.clone()),
                Box::new(IrExpr::Const(bit)),
            )),
            Box::new(IrExpr::Const(1)),
        )
    };
    ctx.emit_flagset(FlagId::Cf, extract(packed, B::CF));
    ctx.emit_flagset(FlagId::Pf, extract(packed, B::PF));
    ctx.emit_flagset(FlagId::Af, extract(packed, B::AF));
    ctx.emit_flagset(FlagId::Zf, extract(packed, B::ZF));
    ctx.emit_flagset(FlagId::Sf, extract(packed, B::SF));
    ctx.emit_flagset(FlagId::If, extract(packed, B::IF));
    ctx.emit_flagset(FlagId::Df, extract(packed, B::DF));
    ctx.emit_flagset(FlagId::Of, extract(packed, B::OF));
}

/// Emit all flag registers as `Undef` — used when a callee might have
/// clobbered any subset of flags (e.g. after an indirect CALL).
pub fn emit_all_flags_undef(ctx: &mut X86LiftCtx) {
    for f in [
        FlagId::Cf,
        FlagId::Pf,
        FlagId::Af,
        FlagId::Zf,
        FlagId::Sf,
        FlagId::Of,
        FlagId::Df,
        FlagId::If,
    ] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

/// Emit ARITH flags (CF, PF, AF, ZF, SF, OF) as `Undef`.  Does not clobber
/// DF or IF (which are not changed by most arithmetic instructions).
pub fn emit_arith_flags_undef(ctx: &mut X86LiftCtx) {
    for f in [
        FlagId::Cf,
        FlagId::Pf,
        FlagId::Af,
        FlagId::Zf,
        FlagId::Sf,
        FlagId::Of,
    ] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 13 — IRET / IRETD / IRETQ (partial — flag restore component)
// ─────────────────────────────────────────────────────────────────────────────

/// Emit the EFLAGS-restore component of IRET / IRETD / IRETQ.
///
/// IRET pops `{RIP, CS, RFLAGS, RSP, SS}` from the kernel stack.  The
/// RFLAGS component is at offset `2 * ptr_size` from the current RSP at the
/// time of the IRET.  This function emits:
///
/// 1. A memory read of the RFLAGS slot.
/// 2. The unpack intrinsic.
/// 3. Each individual flag restore.
///
/// The caller (the `control_flow` handler) is responsible for emitting the
/// CS / RIP / RSP / SS restores.
///
/// # Arguments
/// * `rsp_at_iret` — the RSP value at the moment IRET begins execution.
/// * `ptr_size` — byte-width of a stack slot (4 for 32-bit, 8 for 64-bit).
pub fn emit_iret_eflags_restore(ctx: &mut X86LiftCtx, rsp_at_iret: IrExpr, ptr_size: u8) {
    // RFLAGS is at rsp_at_iret + 2 * ptr_size (after RIP and CS).
    let rflags_addr = IrExpr::Add(
        Box::new(rsp_at_iret),
        Box::new(IrExpr::Const(2 * u64::from(ptr_size))),
    );
    let rflags_tmp = ctx.fresh_temp();
    ctx.emit_mem_read(rflags_addr, rflags_tmp.clone(), ptr_size * 8);
    let rflags_expr = IrExpr::Reg(rflags_tmp);

    ctx.emit_intrinsic("x86.iret.flags_restore", vec![rflags_expr.clone()]);
    emit_eflags_restore(ctx, &rflags_expr);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_flags::ConditionCode;
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Helpers ────────────────────────────────────────────────────────────────

    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    fn ctx32() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, ModeHint::default())
    }

    /// Count RegWrite effects targeting the given register name.
    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    /// Return the value written to `reg` if exactly one RegWrite exists.
    fn value_of<'a>(effects: &'a [Effect], reg: &str) -> Option<&'a IrExpr> {
        for e in effects {
            if let Effect::RegWrite { reg: r, value } = e && r == reg {
                return Some(value);
            }
        }
        None
    }

    /// Check whether an Intrinsic effect with a name containing `substr` exists.
    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    fn has_mem_write(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }))
    }

    fn has_mem_read(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemRead { .. }))
    }

    // ── Section 1: CLC / STC / CMC ─────────────────────────────────────────────

    #[test]
    fn clc_sets_cf_to_zero() {
        let instr = decode64(&[0xF8]); // CLC
        let mut ctx = ctx64();
        lift_clc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cf"), 1, "CLC must write CF");
        assert_eq!(
            value_of(&ctx.effects, "cf"),
            Some(&IrExpr::Const(0)),
            "CLC must set CF := 0"
        );
        // CLC must not touch any other flags.
        assert_eq!(ctx.effects.len(), 1, "CLC must emit exactly 1 effect");
    }

    #[test]
    fn stc_sets_cf_to_one() {
        let instr = decode64(&[0xF9]); // STC
        let mut ctx = ctx64();
        lift_stc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cf"), 1, "STC must write CF");
        assert_eq!(
            value_of(&ctx.effects, "cf"),
            Some(&IrExpr::Const(1)),
            "STC must set CF := 1"
        );
        assert_eq!(ctx.effects.len(), 1, "STC must emit exactly 1 effect");
    }

    #[test]
    fn cmc_emits_cmp_eq_zero_of_cf() {
        let instr = decode64(&[0xF5]); // CMC
        let mut ctx = ctx64();
        lift_cmc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cf"), 1, "CMC must write CF");
        // The value must be CmpEqZero(Reg("cf")) — logical NOT of a boolean flag.
        assert!(
            matches!(value_of(&ctx.effects, "cf"), Some(IrExpr::CmpEqZero(_))),
            "CMC must write CF := (cf == 0)"
        );
        assert_eq!(ctx.effects.len(), 1, "CMC must emit exactly 1 effect");
    }

    #[test]
    fn cmc_does_not_use_bitwise_not() {
        // Bitwise NOT of a 64-bit 0/1 flag would produce 0xFFFFFFFFFFFFFFFE,
        // which evaluates as true (non-zero), breaking all negated conditions.
        let instr = decode64(&[0xF5]); // CMC
        let mut ctx = ctx64();
        lift_cmc(&instr, &mut ctx).unwrap();
        assert!(
            !matches!(value_of(&ctx.effects, "cf"), Some(IrExpr::Not(_))),
            "CMC must NOT use IrExpr::Not for the flag complement"
        );
    }

    // ── Section 2: CLD / STD ───────────────────────────────────────────────────

    #[test]
    fn cld_sets_df_to_zero() {
        let instr = decode64(&[0xFC]); // CLD
        let mut ctx = ctx64();
        lift_cld(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "df"), 1);
        assert_eq!(value_of(&ctx.effects, "df"), Some(&IrExpr::Const(0)));
        assert_eq!(ctx.effects.len(), 1);
    }

    #[test]
    fn std_sets_df_to_one() {
        let instr = decode64(&[0xFD]); // STD
        let mut ctx = ctx64();
        lift_std(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "df"), 1);
        assert_eq!(value_of(&ctx.effects, "df"), Some(&IrExpr::Const(1)));
        assert_eq!(ctx.effects.len(), 1);
    }

    // ── Section 3: CLI / STI ───────────────────────────────────────────────────

    #[test]
    fn cli_clears_if_and_emits_intrinsic() {
        let instr = decode64(&[0xFA]); // CLI
        let mut ctx = ctx64();
        lift_cli(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "if"), 1, "CLI must write IF");
        assert_eq!(value_of(&ctx.effects, "if"), Some(&IrExpr::Const(0)));
        assert!(
            has_intrinsic(&ctx.effects, "x86.cli"),
            "CLI must emit x86.cli intrinsic"
        );
    }

    #[test]
    fn sti_sets_if_and_emits_intrinsic() {
        let instr = decode64(&[0xFB]); // STI
        let mut ctx = ctx64();
        lift_sti(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "if"), 1, "STI must write IF");
        assert_eq!(value_of(&ctx.effects, "if"), Some(&IrExpr::Const(1)));
        assert!(
            has_intrinsic(&ctx.effects, "x86.sti"),
            "STI must emit x86.sti intrinsic"
        );
    }

    // ── Section 4: LAHF / SAHF ─────────────────────────────────────────────────

    #[test]
    fn lahf_writes_ah_register() {
        let instr = decode64(&[0x9F]); // LAHF
        let mut ctx = ctx64();
        lift_lahf(&instr, &mut ctx).unwrap();
        assert!(
            writes_to(&ctx.effects, "ah") >= 1,
            "LAHF must write the AH register"
        );
    }

    #[test]
    fn lahf_emits_pack_intrinsic() {
        let instr = decode64(&[0x9F]); // LAHF
        let mut ctx = ctx64();
        lift_lahf(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.lahf.pack"));
    }

    #[test]
    fn lahf_does_not_write_flags() {
        // LAHF reads flags but must not write any of them.
        let instr = decode64(&[0x9F]); // LAHF
        let mut ctx = ctx64();
        lift_lahf(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "LAHF must not write flag '{flag}'"
            );
        }
    }

    #[test]
    fn lahf_bit1_always_one() {
        // The AH value must include the constant 2 (bit 1 = always 1 per SDM).
        let instr = decode64(&[0x9F]); // LAHF
        let mut ctx = ctx64();
        lift_lahf(&instr, &mut ctx).unwrap();
        // We can't fully evaluate without a CPU state, but we verify the
        // expression tree for AH contains a Const(2) node somewhere.
        fn contains_const_2(expr: &IrExpr) -> bool {
            match expr {
                IrExpr::Const(2) => true,
                IrExpr::Or(l, r)
                | IrExpr::And(l, r)
                | IrExpr::Shl(l, r)
                | IrExpr::Shr(l, r)
                | IrExpr::Add(l, r)
                | IrExpr::Sub(l, r) => contains_const_2(l) || contains_const_2(r),
                _ => false,
            }
        }
        let ah_val = value_of(&ctx.effects, "ah").expect("LAHF must write ah");
        assert!(
            contains_const_2(ah_val),
            "LAHF AH expression must include Const(2) for bit 1"
        );
    }

    #[test]
    fn sahf_writes_five_flags() {
        let instr = decode64(&[0x9E]); // SAHF
        let mut ctx = ctx64();
        lift_sahf(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                1,
                "SAHF must write flag '{flag}'"
            );
        }
        // OF must NOT be written.
        assert_eq!(writes_to(&ctx.effects, "of"), 0, "SAHF must NOT write OF");
    }

    #[test]
    fn sahf_emits_unpack_intrinsic() {
        let instr = decode64(&[0x9E]); // SAHF
        let mut ctx = ctx64();
        lift_sahf(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.sahf.unpack"));
    }

    #[test]
    fn sahf_cf_is_bit0_of_ah() {
        // CF should be (AH >> 0) & 1 = AH & 1.
        let instr = decode64(&[0x9E]); // SAHF
        let mut ctx = ctx64();
        lift_sahf(&instr, &mut ctx).unwrap();
        let cf_expr = value_of(&ctx.effects, "cf").expect("SAHF must write cf");
        // Should be And(Shr(Reg("ah"), Const(0)), Const(1)) or And(Reg("ah"), Const(1))
        assert!(
            matches!(cf_expr, IrExpr::And(_, _)),
            "SAHF CF extraction must be an AND expression"
        );
    }

    #[test]
    fn sahf_sf_is_bit7_of_ah() {
        let instr = decode64(&[0x9E]); // SAHF
        let mut ctx = ctx64();
        lift_sahf(&instr, &mut ctx).unwrap();
        let sf_expr = value_of(&ctx.effects, "sf").expect("SAHF must write sf");
        // Should be And(Shr(Reg("ah"), Const(7)), Const(1))
        fn has_shr_by_7(expr: &IrExpr) -> bool {
            match expr {
                IrExpr::Shr(_, shift) => matches!(shift.as_ref(), IrExpr::Const(7)),
                IrExpr::And(l, r) => has_shr_by_7(l) || has_shr_by_7(r),
                _ => false,
            }
        }
        assert!(has_shr_by_7(sf_expr), "SAHF SF must shift AH right by 7");
    }

    // ── Section 5: PUSHF / POPF ────────────────────────────────────────────────

    #[test]
    fn pushfq_decrements_rsp() {
        // PUSHFQ = opcode 9C in 64-bit mode (no prefix needed; iced decodes it as Pushfq).
        let instr = decode64(&[0x9C]); // PUSHF / PUSHFQ in 64-bit mode
        let mut ctx = ctx64();
        lift_pushf(&instr, &mut ctx).unwrap();
        // RSP must be written.
        assert!(
            writes_to(&ctx.effects, "rsp") >= 1,
            "PUSHF in 64-bit must decrement RSP"
        );
    }

    #[test]
    fn pushfq_writes_to_memory() {
        let instr = decode64(&[0x9C]);
        let mut ctx = ctx64();
        lift_pushf(&instr, &mut ctx).unwrap();
        assert!(
            has_mem_write(&ctx.effects),
            "PUSHF must write EFLAGS to stack memory"
        );
    }

    #[test]
    fn pushfq_emits_pack_intrinsic() {
        let instr = decode64(&[0x9C]);
        let mut ctx = ctx64();
        lift_pushf(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.pushf.pack"));
    }

    #[test]
    fn popfq_increments_rsp() {
        let instr = decode64(&[0x9D]); // POPF / POPFQ in 64-bit mode
        let mut ctx = ctx64();
        lift_popf(&instr, &mut ctx).unwrap();
        assert!(
            writes_to(&ctx.effects, "rsp") >= 1,
            "POPF in 64-bit must increment RSP"
        );
    }

    #[test]
    fn popfq_reads_from_memory() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        lift_popf(&instr, &mut ctx).unwrap();
        assert!(
            has_mem_read(&ctx.effects),
            "POPF must read EFLAGS from stack memory"
        );
    }

    #[test]
    fn popfq_restores_all_modelled_flags() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        lift_popf(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "if", "df", "of"] {
            assert!(
                writes_to(&ctx.effects, flag) >= 1,
                "POPF must restore flag '{flag}'"
            );
        }
    }

    #[test]
    fn popfq_emits_unpack_intrinsic() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        lift_popf(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.popf.unpack"));
    }

    // ── Section 6: SALC ────────────────────────────────────────────────────────

    #[test]
    fn salc_writes_al_register() {
        // SALC opcode 0xD6 is only valid in 32-bit mode; we use a 32-bit decoder.
        let instr = decode32(&[0xD6]); // SALC
        let mut ctx = ctx32();
        lift_salc(&instr, &mut ctx).unwrap();
        assert!(
            writes_to(&ctx.effects, "al") >= 1,
            "SALC must write the AL register"
        );
    }

    #[test]
    fn salc_does_not_modify_flags() {
        let instr = decode32(&[0xD6]); // SALC
        let mut ctx = ctx32();
        lift_salc(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of", "df"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "SALC must not modify flag '{flag}'"
            );
        }
    }

    #[test]
    fn salc_emits_salc_intrinsic() {
        let instr = decode32(&[0xD6]);
        let mut ctx = ctx32();
        lift_salc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.salc"));
    }

    #[test]
    fn salc_reads_cf() {
        // The AL value expression must reference the CF register.
        let instr = decode32(&[0xD6]);
        let mut ctx = ctx32();
        lift_salc(&instr, &mut ctx).unwrap();
        // CF should appear in the effects (at minimum in the intrinsic arguments).
        let reads_cf = ctx
            .effects
            .iter()
            .any(|e| e.read_registers().iter().any(|r| r == "cf"));
        assert!(reads_cf, "SALC must read CF to determine AL value");
    }

    // ── Section 7: SETcc ───────────────────────────────────────────────────────

    #[test]
    fn sete_emits_setcc_intrinsic() {
        // SETE AL: 0F 94 C0
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.setcc"),
            "SETE must emit setcc intrinsic"
        );
    }

    #[test]
    fn sete_writes_one_destination() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]); // SETE AL
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        // Should write to AL (the destination of SETE AL).
        assert!(
            writes_to(&ctx.effects, "al") >= 1,
            "SETE AL must write to AL"
        );
    }

    #[test]
    fn setne_reads_only_zf() {
        // SETNE reads ZF; it must not emit any flag writes.
        let instr = decode64(&[0x0F, 0x95, 0xC0]); // SETNE AL
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "sf", "of", "df"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "SETNE must not write flag '{flag}'"
            );
        }
    }

    #[test]
    fn setcc_condition_codes_all_resolved() {
        // Verify that all 16 condition codes map without error when decoded from
        // their canonical encoding.  We use SETCC AL for each condition.
        // SETcc opcodes: 0F 90+cc C0
        // CC 0..=15.
        let base_opcode: u8 = 0x90;
        for cc_nibble in 0u8..16u8 {
            let opcode = base_opcode + cc_nibble;
            let bytes = [0x0Fu8, opcode, 0xC0u8];
            let instr = decode64(&bytes);
            let mut ctx = ctx64();
            let result = lift_setcc(&instr, &mut ctx);
            assert!(
                result.is_ok(),
                "SETcc with CC nibble {cc_nibble} (opcode 0F {opcode:02X} C0) failed: {result:?}"
            );
        }
    }

    #[test]
    fn setcc_does_not_modify_eflags() {
        // SETcc must never write any flag register.
        let instr = decode64(&[0x0F, 0x94, 0xC0]); // SETE AL
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of", "df", "if"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "SETE must not write EFLAGS flag '{flag}'"
            );
        }
    }

    // ── Section 8: CMOVcc ──────────────────────────────────────────────────────

    #[test]
    fn cmove_emits_cmovcc_intrinsic() {
        // CMOVE EAX, ECX: 0F 44 C1
        let instr = decode64(&[0x0F, 0x44, 0xC1]);
        let mut ctx = ctx64();
        lift_cmovcc(&instr, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.cmovcc"),
            "CMOVE must emit cmovcc intrinsic"
        );
    }

    #[test]
    fn cmove_writes_destination() {
        // CMOVE EAX, ECX: 0F 44 C1
        let instr = decode64(&[0x0F, 0x44, 0xC1]);
        let mut ctx = ctx64();
        lift_cmovcc(&instr, &mut ctx).unwrap();
        assert!(
            writes_to(&ctx.effects, "eax") >= 1,
            "CMOVE must write destination register"
        );
    }

    #[test]
    fn cmovcc_does_not_modify_eflags() {
        // CMOVNE EAX, ECX: 0F 45 C1
        let instr = decode64(&[0x0F, 0x45, 0xC1]);
        let mut ctx = ctx64();
        lift_cmovcc(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of", "df"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "CMOVcc must not write EFLAGS flag '{flag}'"
            );
        }
    }

    #[test]
    fn cmovcc_all_16_conditions_succeed() {
        // CMOVcc EAX, ECX: 0F 40+cc C1
        let base: u8 = 0x40;
        for cc in 0u8..16u8 {
            let bytes = [0x0Fu8, base + cc, 0xC1u8];
            let instr = decode64(&bytes);
            let mut ctx = ctx64();
            let result = lift_cmovcc(&instr, &mut ctx);
            assert!(
                result.is_ok(),
                "CMOVcc with CC nibble {cc} failed: {result:?}"
            );
        }
    }

    // ── Section 9: CLAC / STAC ─────────────────────────────────────────────────

    #[test]
    fn clac_writes_ac_to_zero() {
        let instr = decode64(&[0x0F, 0x01, 0xCA]); // CLAC
        let mut ctx = ctx64();
        lift_clac(&instr, &mut ctx).unwrap();
        assert_eq!(
            value_of(&ctx.effects, "ac"),
            Some(&IrExpr::Const(0)),
            "CLAC must set AC pseudo-register to 0"
        );
        assert!(has_intrinsic(&ctx.effects, "x86.clac"));
    }

    #[test]
    fn stac_writes_ac_to_one() {
        let instr = decode64(&[0x0F, 0x01, 0xCB]); // STAC
        let mut ctx = ctx64();
        lift_stac(&instr, &mut ctx).unwrap();
        assert_eq!(
            value_of(&ctx.effects, "ac"),
            Some(&IrExpr::Const(1)),
            "STAC must set AC pseudo-register to 1"
        );
        assert!(has_intrinsic(&ctx.effects, "x86.stac"));
    }

    #[test]
    fn clac_does_not_touch_arithmetic_flags() {
        let instr = decode64(&[0x0F, 0x01, 0xCA]); // CLAC
        let mut ctx = ctx64();
        lift_clac(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "CLAC must not write arithmetic flag '{flag}'"
            );
        }
    }

    // ── Section 10: CLTS ───────────────────────────────────────────────────────

    #[test]
    fn clts_writes_cr0_ts_pseudo_register() {
        let instr = decode64(&[0x0F, 0x06]); // CLTS
        let mut ctx = ctx64();
        lift_clts(&instr, &mut ctx).unwrap();
        assert_eq!(
            value_of(&ctx.effects, "cr0_ts"),
            Some(&IrExpr::Const(0)),
            "CLTS must write cr0_ts to 0"
        );
    }

    #[test]
    fn clts_emits_clts_intrinsic() {
        let instr = decode64(&[0x0F, 0x06]); // CLTS
        let mut ctx = ctx64();
        lift_clts(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.clts"));
    }

    #[test]
    fn clts_does_not_touch_eflags() {
        let instr = decode64(&[0x0F, 0x06]); // CLTS
        let mut ctx = ctx64();
        lift_clts(&instr, &mut ctx).unwrap();
        for flag in ["cf", "pf", "af", "zf", "sf", "of", "df", "if"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "CLTS must not write EFLAGS flag '{flag}'"
            );
        }
    }

    // ── Section 11: Utility functions ─────────────────────────────────────────

    #[test]
    fn emit_all_flags_undef_writes_all_flags() {
        let mut ctx = ctx64();
        emit_all_flags_undef(&mut ctx);
        for flag in ["cf", "pf", "af", "zf", "sf", "of", "df", "if"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                1,
                "emit_all_flags_undef must write '{flag}' exactly once"
            );
        }
    }

    #[test]
    fn emit_arith_flags_undef_does_not_touch_df_if() {
        let mut ctx = ctx64();
        emit_arith_flags_undef(&mut ctx);
        // DF and IF must not be clobbered.
        assert_eq!(writes_to(&ctx.effects, "df"), 0);
        assert_eq!(writes_to(&ctx.effects, "if"), 0);
        // Arithmetic flags must be written.
        for flag in ["cf", "pf", "af", "zf", "sf", "of"] {
            assert_eq!(writes_to(&ctx.effects, flag), 1);
        }
    }

    #[test]
    fn flags_read_by_cc_o_returns_of_only() {
        assert_eq!(flags_read_by_cc(ConditionCode::O), &["of"]);
        assert_eq!(flags_read_by_cc(ConditionCode::No), &["of"]);
    }

    #[test]
    fn flags_read_by_cc_b_returns_cf_only() {
        assert_eq!(flags_read_by_cc(ConditionCode::B), &["cf"]);
        assert_eq!(flags_read_by_cc(ConditionCode::Ae), &["cf"]);
    }

    #[test]
    fn flags_read_by_cc_e_returns_zf_only() {
        assert_eq!(flags_read_by_cc(ConditionCode::E), &["zf"]);
        assert_eq!(flags_read_by_cc(ConditionCode::Ne), &["zf"]);
    }

    #[test]
    fn flags_read_by_cc_be_returns_cf_and_zf() {
        let r = flags_read_by_cc(ConditionCode::Be);
        assert!(r.contains(&"cf") && r.contains(&"zf"));
    }

    #[test]
    fn flags_read_by_cc_l_returns_sf_and_of() {
        let r = flags_read_by_cc(ConditionCode::L);
        assert!(r.contains(&"sf") && r.contains(&"of"));
        assert!(!r.contains(&"zf"), "ConditionCode::L must NOT include ZF");
    }

    #[test]
    fn flags_read_by_cc_g_returns_zf_sf_of() {
        let r = flags_read_by_cc(ConditionCode::G);
        assert!(r.contains(&"zf") && r.contains(&"sf") && r.contains(&"of"));
    }

    #[test]
    fn emit_flags_read_annotation_emits_intrinsic() {
        let mut ctx = ctx64();
        emit_flags_read_annotation(ConditionCode::E, &mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.flags_read"));
    }

    #[test]
    fn emit_eflags_snapshot_materialises_temp() {
        let mut ctx = ctx64();
        let tmp = emit_eflags_snapshot(&mut ctx, 8);
        assert!(!tmp.is_empty(), "snapshot temp name must not be empty");
        assert!(
            writes_to(&ctx.effects, &tmp) >= 1,
            "snapshot must materialise a temporary"
        );
    }

    #[test]
    fn emit_eflags_restore_writes_all_flags() {
        let mut ctx = ctx64();
        emit_eflags_restore(&mut ctx, &IrExpr::Const(0b1100_0000)); // SF=1 ZF=1
        for flag in ["cf", "pf", "af", "zf", "sf", "if", "df", "of"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                1,
                "emit_eflags_restore must write '{flag}'"
            );
        }
    }

    #[test]
    fn fresh_temp_counter_increments() {
        let mut ctx = ctx64();
        let t0 = ctx.fresh_temp();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        assert_ne!(t0, t1);
        assert_ne!(t1, t2);
        assert_ne!(t0, t2);
    }

    #[test]
    fn build_eflags_expr_is_or_tree() {
        // The packed EFLAGS expression must be an Or tree (not a single constant).
        let expr = build_eflags_expr(4);
        assert!(
            matches!(expr, IrExpr::Or(_, _)),
            "build_eflags_expr must return an Or-tree IrExpr"
        );
    }

    #[test]
    fn eflags_bits_constants_are_correct() {
        // Verify selected bit positions match Intel SDM Table 2-3.
        assert_eq!(eflags_bits::CF, 0);
        assert_eq!(eflags_bits::PF, 2);
        assert_eq!(eflags_bits::AF, 4);
        assert_eq!(eflags_bits::ZF, 6);
        assert_eq!(eflags_bits::SF, 7);
        assert_eq!(eflags_bits::IF, 9);
        assert_eq!(eflags_bits::DF, 10);
        assert_eq!(eflags_bits::OF, 11);
        assert_eq!(eflags_bits::AC, 18);
    }

    #[test]
    fn rep_prefix_flags_dep_repe_emits_zf_dep() {
        let mut ctx = ctx64();
        emit_rep_prefix_flags_dep("repe", &mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.rep.flags_read.zf"));
    }

    #[test]
    fn rep_prefix_flags_dep_repne_emits_zf_dep() {
        let mut ctx = ctx64();
        emit_rep_prefix_flags_dep("repne", &mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.repne.flags_read.zf"));
    }

    #[test]
    fn rep_prefix_plain_emits_no_flags_dep() {
        let mut ctx = ctx64();
        emit_rep_prefix_flags_dep("rep", &mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.rep.flags_read.none"));
    }
}
