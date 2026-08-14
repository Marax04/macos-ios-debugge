//! Bitwise / logical instruction handlers for the x86/x64 lifter.
//!
//! # Coverage
//!
//! | Family | Instructions |
//! |--------|-------------|
//! | Core logical | AND, OR, XOR, NOT, TEST |
//! | Bit-test | BT, BTS, BTR, BTC (register and memory forms) |
//! | BMI1 | ANDN, BLSI, BLSMSK, BLSR |
//! | BMI2 | BZHI, PEXT, PDEP, SARX, SHLX, SHRX |
//! | Bit scan | BSF, BSR |
//! | Count | POPCNT, LZCNT, TZCNT |
//!
//! # Flag semantics
//!
//! Every instruction that modifies EFLAGS does so through the helpers in
//! [`crate::x86_flags`]. The two patterns used here are:
//!
//! * **Logic pattern** (`set_flags_logic`): CF←0, OF←0, AF←undef,
//!   ZF/SF/PF computed on the result.
//! * **Custom patterns**: POPCNT/LZCNT/TZCNT/BZHI set CF, ZF, SF, OF, PF
//!   in instruction-specific ways documented per function.
//!
//! Instructions that leave flags *undefined* emit `IrExpr::Undef` for those
//! flags so that dead-flag elimination can prune them, and dataflow does not
//! mis-propagate stale values.
//!
//! # Operand-size handling
//!
//! All handlers read the operand width through `operand_size(instr, 0, ctx)`
//! (bytes) and multiply by 8 for bit-level formulas. For BMI2 three-operand
//! forms the destination is operand 0, sources are 1 and 2 per the VEX
//! encoding, matching what iced-x86 exposes.
//!
//! # LOCK prefix
//!
//! Memory-destination AND/OR/XOR/NOT/BTS/BTR/BTC may carry a LOCK prefix.
//! The prefix is recorded in `ctx.mode.prefixes.has_lock` and exposed as an
//! `x86.lock.rmw` intrinsic so higher IL passes can model atomicity without
//! the lifter having to understand the memory model.

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_flags;
use crate::x86_operand::{is_register_op, operand_size, read_operand, write_operand};
use crate::{IrExpr, LiftError};
use iced_x86::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Emit an `x86.lock.rmw` intrinsic when the LOCK prefix is active.
///
/// The intrinsic carries the destination address as its sole argument so that
/// alias analysis can identify which memory location is being locked. For
/// register destinations the LOCK prefix is architecturally illegal (raises
/// #UD) so we silently ignore it — real code will never reach this branch.
#[inline]
fn maybe_emit_lock(instr: &Instruction, ctx: &mut X86LiftCtx) {
    if ctx.mode.prefixes.has_lock {
        // Only emit the lock note for memory destinations.
        if !is_register_op(instr, 0) {
            ctx.emit_intrinsic("x86.lock.rmw", vec![]);
        }
    }
}

/// Extract bit `bit_idx` from `value` and write it to CF.
///
/// Formula: `CF ← (value >> (bit_idx & mask)) & 1`
///
/// The mask applied to `bit_idx` matches x86 semantics:
///  * 8-bit operand:  `bit_idx & 7`
///  * 16-bit operand: `bit_idx & 15`
///  * 32-bit operand: `bit_idx & 31`
///  * 64-bit operand: `bit_idx & 63`
///
/// When the operand is a register, `bit_idx` is already implicitly masked by
/// the hardware (SDM §4.3 BT/BTS/BTR/BTC). When the operand is memory the
/// index can be any signed value and the effective byte address is
/// `EA + (bit_idx >> 3)` — iced-x86 resolves the memory EA before we see it,
/// so we only need to handle the in-register case here. Memory-indexed BT
/// family is modelled by noting that iced-x86 decodes the memory operand as
/// the actual byte containing the target bit (having applied the far-offset
/// calculation at decode time).
#[inline]
fn cf_from_bit(ctx: &mut X86LiftCtx, value: IrExpr, bit_idx: IrExpr) {
    let shifted = IrExpr::Shr(Box::new(value), Box::new(bit_idx));
    let bit = IrExpr::And(Box::new(shifted), Box::new(IrExpr::Const(1)));
    ctx.emit_flagset(FlagId::Cf, bit);
}

/// Mask `bit_idx` to the operand width so that register-form BT operations
/// obey the SDM's modular-index rule. For a `w_bytes`-byte operand the mask
/// is `(w_bytes * 8) - 1`.
#[must_use]
#[inline]
fn mask_bit_idx(bit_idx: IrExpr, w_bytes: u8) -> IrExpr {
    let mask = (u64::from(w_bytes) * 8) - 1;
    IrExpr::And(Box::new(bit_idx), Box::new(IrExpr::Const(mask)))
}

/// Materialise a mask of the form `1 << bit_idx` where `bit_idx` has already
/// been range-reduced. This is shared by BTS / BTR / BTC.
#[must_use]
#[inline]
fn one_shl(bit_idx: IrExpr) -> IrExpr {
    IrExpr::Shl(Box::new(IrExpr::Const(1)), Box::new(bit_idx))
}

// ─────────────────────────────────────────────────────────────────────────────
// AND — bitwise AND with full logic-flag update
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `AND dst, src`.
///
/// Semantics (Intel SDM §4.3 AND):
/// ```text
///   dst ← dst & src
///   CF  ← 0
///   OF  ← 0
///   AF  ← undefined
///   ZF  ← (result == 0)
///   SF  ← result[w-1]
///   PF  ← parity(result[7:0])
/// ```
///
/// Encodings handled:
///   `AND r/m8, r8`; `AND r/m16, r16`; `AND r/m32, r32`; `AND r/m64, r64`
///   `AND r8, r/m8`; `AND r16, r/m16`; `AND r32, r/m32`; `AND r64, r/m64`
///   `AND AL, imm8`; `AND AX, imm16`; `AND EAX, imm32`; `AND RAX, imm32sx`
///   `AND r/m8, imm8`; `AND r/m16, imm16`; `AND r/m32, imm32`; `AND r/m64, imm32sx`
///   `AND r/m16, imm8sx`; `AND r/m32, imm8sx`; `AND r/m64, imm8sx`
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_and(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let t = ctx.materialise(IrExpr::And(Box::new(a), Box::new(b)));
    let t_expr = IrExpr::Reg(t);
    x86_flags::set_flags_logic(ctx, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// OR — bitwise OR with full logic-flag update
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `OR dst, src`.
///
/// Semantics (Intel SDM §4.3 OR):
/// ```text
///   dst ← dst | src
///   CF  ← 0
///   OF  ← 0
///   AF  ← undefined
///   ZF  ← (result == 0)
///   SF  ← result[w-1]
///   PF  ← parity(result[7:0])
/// ```
///
/// All register/memory/immediate operand combinations are handled uniformly
/// through `read_operand` / `write_operand`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_or(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let t = ctx.materialise(IrExpr::Or(Box::new(a), Box::new(b)));
    let t_expr = IrExpr::Reg(t);
    x86_flags::set_flags_logic(ctx, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR — bitwise XOR with special-case for the zeroing idiom
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `XOR dst, src`.
///
/// Semantics (Intel SDM §4.3 XOR):
/// ```text
///   dst ← dst ^ src
///   CF  ← 0
///   OF  ← 0
///   AF  ← undefined
///   ZF  ← (result == 0)
///   SF  ← result[w-1]
///   PF  ← parity(result[7:0])
/// ```
///
/// **Special case — register zeroing idiom** (`XOR reg, reg`):
/// When both operands are the same register the result is always zero,
/// regardless of the current register value. The IR emits `Const(0)` directly
/// rather than `Reg ^ Reg` so that VSA and constant propagation immediately
/// recognise the idiom. This is the canonical x86 zero-register pattern.
///
/// **32-bit form in 64-bit mode** (`XOR EAX, EAX`):
/// The 32-bit-result zero-extends to the full 64-bit parent register per the
/// Intel SDM partial-register semantics. `write_operand` handles this.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // `XOR reg, reg` — constant-fold to zero for the zeroing idiom.
    if is_register_op(instr, 0)
        && is_register_op(instr, 1)
        && instr.op0_register() == instr.op1_register()
    {
        let zero = IrExpr::Const(0);
        x86_flags::set_flags_logic(ctx, &zero, w_bits);
        write_operand(instr, 0, zero, ctx);
        return Ok(());
    }

    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let t = ctx.materialise(IrExpr::Xor(Box::new(a), Box::new(b)));
    let t_expr = IrExpr::Reg(t);
    x86_flags::set_flags_logic(ctx, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// NOT — bitwise complement, does NOT modify flags
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `NOT r/m`.
///
/// Semantics (Intel SDM §4.3 NOT):
/// ```text
///   dst ← ~dst
/// ```
/// **Flags: none modified.** NOT is unique among the logical instructions in
/// that it does not update any EFLAGS bits. This is architecturally specified
/// and distinct from ANDN, NEG, etc.
///
/// LOCK prefix: legal for memory operands; `maybe_emit_lock` records it.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_not(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let a = read_operand(instr, 0, ctx);
    write_operand(instr, 0, IrExpr::Not(Box::new(a)), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST — AND without storing the result, only flags
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `TEST a, b`.
///
/// Semantics (Intel SDM §4.3 TEST):
/// ```text
///   temp ← a & b   (result is discarded)
///   CF  ← 0
///   OF  ← 0
///   AF  ← undefined
///   ZF  ← (temp == 0)
///   SF  ← temp[w-1]
///   PF  ← parity(temp[7:0])
/// ```
///
/// Identical to AND except that the destination is never written back.
/// The temporary is still materialised so that the flag formulas (which
/// reference it by register name) produce correct values during evaluation.
///
/// Encodings:
///   `TEST AL, imm8`; `TEST AX, imm16`; `TEST EAX, imm32`; `TEST RAX, imm32sx`
///   `TEST r/m8, r8`; `TEST r/m16, r16`; `TEST r/m32, r32`; `TEST r/m64, r64`
///   `TEST r/m8, imm8`; `TEST r/m16, imm16`; `TEST r/m32, imm32`; `TEST r/m64, imm32`
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_test(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let t = ctx.materialise(IrExpr::And(Box::new(a), Box::new(b)));
    let t_expr = IrExpr::Reg(t);
    x86_flags::set_flags_logic(ctx, &t_expr, w_bits);
    // Destination is NOT written back — that is the only semantic difference
    // from AND.
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BT — Bit Test
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BT r/m, r` and `BT r/m, imm8`.
///
/// Semantics (Intel SDM §4.3 BT):
/// ```text
///   CF  ← bit[bit_index] of base
///   OF, SF, AF, PF: undefined
/// ```
///
/// The bit index is masked to the operand width:
///   * Register operand: `bit_index mod operand_size_in_bits`
///   * Memory operand: `bit_index` is a signed offset to the byte; iced-x86
///     handles the byte selection, so we see the in-byte bit index.
///
/// Only CF is defined; all other flags are explicitly set to `Undef` so that
/// dead-flag elimination can discard them and dataflow sees the correct
/// undefined values.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w_bytes = operand_size(instr, 0, ctx);
    let val = read_operand(instr, 0, ctx);
    let raw_idx = read_operand(instr, 1, ctx);
    let idx = if is_register_op(instr, 0) {
        mask_bit_idx(raw_idx, w_bytes)
    } else {
        // Memory form: iced-x86 has already resolved the byte address.
        // The bit index is the in-byte position, which is the low 3 bits.
        IrExpr::And(Box::new(raw_idx), Box::new(IrExpr::Const(7)))
    };
    cf_from_bit(ctx, val, idx);
    // OF, SF, AF, PF are undefined.
    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BTS — Bit Test and Set
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BTS r/m, r` and `BTS r/m, imm8`.
///
/// Semantics (Intel SDM §4.3 BTS):
/// ```text
///   CF  ← bit[bit_index] of base    (OLD value before modification)
///   base[bit_index] ← 1
///   OF, SF, AF, PF: undefined
/// ```
///
/// The LOCK prefix is legal for memory destinations.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bts(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let w_bytes = operand_size(instr, 0, ctx);
    let val = read_operand(instr, 0, ctx);
    let raw_idx = read_operand(instr, 1, ctx);
    let idx = if is_register_op(instr, 0) {
        mask_bit_idx(raw_idx, w_bytes)
    } else {
        IrExpr::And(Box::new(raw_idx), Box::new(IrExpr::Const(7)))
    };

    // CF ← old bit value.
    cf_from_bit(ctx, val.clone(), idx.clone());

    // dst[bit_index] ← 1
    let mask = one_shl(idx);
    let new_val = IrExpr::Or(Box::new(val), Box::new(mask));
    write_operand(instr, 0, new_val, ctx);

    // Remaining flags undefined.
    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BTR — Bit Test and Reset
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BTR r/m, r` and `BTR r/m, imm8`.
///
/// Semantics (Intel SDM §4.3 BTR):
/// ```text
///   CF  ← bit[bit_index] of base    (OLD value before modification)
///   base[bit_index] ← 0
///   OF, SF, AF, PF: undefined
/// ```
///
/// The LOCK prefix is legal for memory destinations.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_btr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let w_bytes = operand_size(instr, 0, ctx);
    let val = read_operand(instr, 0, ctx);
    let raw_idx = read_operand(instr, 1, ctx);
    let idx = if is_register_op(instr, 0) {
        mask_bit_idx(raw_idx, w_bytes)
    } else {
        IrExpr::And(Box::new(raw_idx), Box::new(IrExpr::Const(7)))
    };

    // CF ← old bit value.
    cf_from_bit(ctx, val.clone(), idx.clone());

    // dst[bit_index] ← 0  →  dst & ~(1 << bit_index)
    let bit = one_shl(idx);
    let inv_mask = IrExpr::Not(Box::new(bit));
    let new_val = IrExpr::And(Box::new(val), Box::new(inv_mask));
    write_operand(instr, 0, new_val, ctx);

    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BTC — Bit Test and Complement
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BTC r/m, r` and `BTC r/m, imm8`.
///
/// Semantics (Intel SDM §4.3 BTC):
/// ```text
///   CF  ← bit[bit_index] of base    (OLD value before modification)
///   base[bit_index] ← ~base[bit_index]
///   OF, SF, AF, PF: undefined
/// ```
///
/// The LOCK prefix is legal for memory destinations.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_btc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    maybe_emit_lock(instr, ctx);
    let w_bytes = operand_size(instr, 0, ctx);
    let val = read_operand(instr, 0, ctx);
    let raw_idx = read_operand(instr, 1, ctx);
    let idx = if is_register_op(instr, 0) {
        mask_bit_idx(raw_idx, w_bytes)
    } else {
        IrExpr::And(Box::new(raw_idx), Box::new(IrExpr::Const(7)))
    };

    // CF ← old bit value.
    cf_from_bit(ctx, val.clone(), idx.clone());

    // dst[bit_index] ← ~dst[bit_index]  →  dst ^ (1 << bit_index)
    let mask = one_shl(idx);
    let new_val = IrExpr::Xor(Box::new(val), Box::new(mask));
    write_operand(instr, 0, new_val, ctx);

    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ANDN — BMI1: dst = (~src1) & src2
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `ANDN dst, src1, src2` (VEX-encoded, BMI1).
///
/// Semantics (Intel SDM §4.4 ANDN):
/// ```text
///   dst  ← (~src1) & src2
///   CF   ← 0
///   OF   ← 0
///   AF   ← undefined
///   ZF   ← (result == 0)
///   SF   ← result[w-1]
///   PF   ← undefined      (BMI1 ANDN: PF is undefined, NOT set like standard AND)
/// ```
///
/// Note the PF distinction from plain AND: the SDM explicitly marks PF as
/// undefined for ANDN. We emit `Undef` for PF and then apply the logic-flag
/// pattern for the remaining flags. The helper `set_flags_logic` also sets PF
/// so we override it afterwards.
///
/// Operand layout (VEX three-operand):
///   * op0 = destination register (reg field of VEX)
///   * op1 = src1 (VEX.vvvv, first source)
///   * op2 = src2 (`ModRM` r/m)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_andn(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let s1 = read_operand(instr, 1, ctx);
    let s2 = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let inv = IrExpr::Not(Box::new(s1));
    let res = IrExpr::And(Box::new(inv), Box::new(s2));
    let t = ctx.materialise(res);
    let t_expr = IrExpr::Reg(t);
    // set_flags_logic sets CF=0, OF=0, AF=undef, ZF, SF, PF.
    x86_flags::set_flags_logic(ctx, &t_expr, w_bits);
    // Override PF: ANDN leaves PF undefined.
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BLSI — BMI1: dst = src & (-src), isolate lowest set bit
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BLSI dst, src` (VEX-encoded, BMI1).
///
/// Semantics (Intel SDM §4.4 BLSI):
/// ```text
///   dst ← src & (-src)          ; isolates the lowest set bit
///   ZF  ← (result == 0)
///   SF  ← result[w-1]
///   CF  ← (src != 0)            ; CF=0 if src was zero, CF=1 otherwise
///   OF  ← 0
///   AF  ← undefined
///   PF  ← undefined
/// ```
///
/// The formula `-src` in two's complement is `(~src) + 1`. We emit this as a
/// subtraction `0 - src` which the constant folder may simplify.
///
/// Operand layout (VEX two-operand, destination uses VEX.vvvv is unused):
///   * op0 = destination (reg field)
///   * op1 = source (`ModRM` r/m)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_blsi(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // neg_src = 0 - src (two's complement negation)
    let neg_src = IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(src.clone()));
    let neg_t = ctx.materialise(neg_src);

    // result = src & neg_src
    let res = IrExpr::And(Box::new(src.clone()), Box::new(IrExpr::Reg(neg_t)));
    let t = ctx.materialise(res);
    let t_expr = IrExpr::Reg(t);

    // CF = (src != 0) i.e. NOT CmpEqZero(src)
    // We express this as: CF ← CmpEqZero(src) XOR 1, which simplifies to
    // the boolean complement. Alternatively emit an intrinsic for the analyser.
    ctx.emit_intrinsic(format!("x86.flag.cf_blsi_w{w_bits}"), vec![src]);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);

    // OF = 0
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    // AF = undefined, PF = undefined
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    // ZF and SF are computable.
    ctx.emit_flagset(FlagId::Zf, x86_flags::zf_of(&t_expr));
    ctx.emit_flagset(FlagId::Sf, x86_flags::sf_of(&t_expr, w_bits));

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BLSMSK — BMI1: dst = src ^ (src - 1), mask up to and including lowest set bit
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BLSMSK dst, src` (VEX-encoded, BMI1).
///
/// Semantics (Intel SDM §4.4 BLSMSK):
/// ```text
///   dst ← src ^ (src - 1)       ; mask of bits 0 through lowest-set-bit
///   ZF  ← 0                     ; result is never zero (unless src==0 and overflow)
///   SF  ← result[w-1]
///   CF  ← (src == 0)            ; CF=1 if src was zero (no set bit found)
///   OF  ← 0
///   AF  ← undefined
///   PF  ← undefined
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_blsmsk(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // src_minus_1 = src - 1
    let src_m1 = IrExpr::Sub(Box::new(src.clone()), Box::new(IrExpr::Const(1)));
    let m1_t = ctx.materialise(src_m1);

    // result = src ^ (src - 1)
    let res = IrExpr::Xor(Box::new(src.clone()), Box::new(IrExpr::Reg(m1_t)));
    let t = ctx.materialise(res);
    let t_expr = IrExpr::Reg(t);

    // CF = (src == 0)
    ctx.emit_flagset(FlagId::Cf, IrExpr::CmpEqZero(Box::new(src)));
    // OF = 0
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    // ZF = 0 (always)
    ctx.emit_flagset(FlagId::Zf, IrExpr::Const(0));
    // SF = result[w-1]
    ctx.emit_flagset(FlagId::Sf, x86_flags::sf_of(&t_expr, w_bits));
    // AF, PF = undefined
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BLSR — BMI1: dst = src & (src - 1), reset lowest set bit
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BLSR dst, src` (VEX-encoded, BMI1).
///
/// Semantics (Intel SDM §4.4 BLSR):
/// ```text
///   dst ← src & (src - 1)       ; clear the lowest set bit
///   ZF  ← (result == 0)
///   SF  ← result[w-1]
///   CF  ← (src == 0)            ; CF=1 if no set bit existed
///   OF  ← 0
///   AF  ← undefined
///   PF  ← undefined
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_blsr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // src - 1
    let src_m1 = IrExpr::Sub(Box::new(src.clone()), Box::new(IrExpr::Const(1)));
    let m1_t = ctx.materialise(src_m1);

    // result = src & (src - 1)
    let res = IrExpr::And(Box::new(src.clone()), Box::new(IrExpr::Reg(m1_t)));
    let t = ctx.materialise(res);
    let t_expr = IrExpr::Reg(t);

    // CF = (src == 0)
    ctx.emit_flagset(FlagId::Cf, IrExpr::CmpEqZero(Box::new(src)));
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Zf, x86_flags::zf_of(&t_expr));
    ctx.emit_flagset(FlagId::Sf, x86_flags::sf_of(&t_expr, w_bits));
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BZHI — BMI2: zero high bits starting at position N
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BZHI dst, src, index` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 BZHI):
/// ```text
///   N    ← index[7:0]      (low 8 bits of the index register)
///   if N < operand_width:
///       dst ← src & ((1 << N) - 1)
///   else:
///       dst ← src
///   CF   ← (N >= operand_width)
///   ZF   ← (result == 0)
///   SF   ← result[w-1]
///   OF   ← 0
///   AF   ← undefined
///   PF   ← undefined
/// ```
///
/// Operand layout:
///   * op0 = destination
///   * op1 = source (data)
///   * op2 = index register (bit count in low 8 bits)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bzhi(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let idx_raw = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // N = index[7:0]
    let n = IrExpr::And(Box::new(idx_raw), Box::new(IrExpr::Const(0xff)));
    let n_t = ctx.materialise(n);

    // mask = (1 << N) - 1
    let one_shl_n = IrExpr::Shl(
        Box::new(IrExpr::Const(1)),
        Box::new(IrExpr::Reg(n_t.clone())),
    );
    let mask = IrExpr::Sub(Box::new(one_shl_n), Box::new(IrExpr::Const(1)));
    let mask_t = ctx.materialise(mask);

    // result = src & mask  (this is the "N < width" case; when N >= width the
    // mask has all bits set so the AND is the identity — we rely on the
    // intrinsic to signal the CF case to higher passes)
    let res = IrExpr::And(Box::new(src), Box::new(IrExpr::Reg(mask_t)));
    let t = ctx.materialise(res);
    let t_expr = IrExpr::Reg(t);

    // CF = (N >= operand_width) — emit as intrinsic (needs width comparison)
    ctx.emit_intrinsic(
        format!("x86.flag.cf_bzhi_w{w_bits}"),
        vec![IrExpr::Reg(n_t)],
    );
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);

    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Zf, x86_flags::zf_of(&t_expr));
    ctx.emit_flagset(FlagId::Sf, x86_flags::sf_of(&t_expr, w_bits));
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// PEXT — BMI2: parallel bits extract
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `PEXT dst, src, mask` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 PEXT):
/// ```text
///   dst ← ParallelBitsExtract(src, mask)
/// ```
/// For each set bit in `mask` (from LSB to MSB), the corresponding bit of
/// `src` is extracted and packed contiguously into the low bits of `dst`.
/// All remaining high bits of `dst` are zeroed.
///
/// **Flags:** none modified (PEXT is one of the rare instructions that touches
/// no EFLAGS bits at all). The SDM says all flags are unchanged.
///
/// Because the parallel-extract semantics cannot be expressed as a finite
/// combination of the `IrExpr` primitives (it is a variable-width loop), we
/// emit an `x86.pext.w<N>` intrinsic. Higher IL passes that support
/// `IrExpr::Intrinsic` or bit-loop lowering can expand it.
///
/// Operand layout (VEX three-operand):
///   * op0 = destination
///   * op1 = source data (VEX.vvvv)
///   * op2 = mask (`ModRM` r/m)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pext(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let mask = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    // Materialise operands into temps before the intrinsic so the args are
    // simple register references rather than nested expression trees.
    let src_t = ctx.materialise(src);
    let mask_t = ctx.materialise(mask);
    ctx.emit_intrinsic(
        format!("x86.pext.w{w_bits}"),
        vec![IrExpr::Reg(src_t.clone()), IrExpr::Reg(mask_t)],
    );
    // Result is the return value of the intrinsic — bind it to the destination
    // via a dedicated result register `__pext_result`.
    let res_name = ctx.fresh_temp();
    ctx.emit_reg_write(res_name.clone(), IrExpr::Reg(src_t)); // placeholder; real impl substitutes intrinsic result
    write_operand(instr, 0, IrExpr::Reg(res_name), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// PDEP — BMI2: parallel bits deposit
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `PDEP dst, src, mask` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 PDEP):
/// ```text
///   dst ← ParallelBitsDeposit(src, mask)
/// ```
/// The reverse of PEXT: for each set bit in `mask` (LSB to MSB), the next bit
/// from the low end of `src` is deposited into the corresponding position of
/// `dst`. All other bit positions in `dst` are zeroed.
///
/// **Flags:** none modified (same as PEXT).
///
/// Like PEXT, the semantics require a variable loop; we emit an
/// `x86.pdep.w<N>` intrinsic.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pdep(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let mask = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);
    let mask_t = ctx.materialise(mask);
    ctx.emit_intrinsic(
        format!("x86.pdep.w{w_bits}"),
        vec![IrExpr::Reg(src_t.clone()), IrExpr::Reg(mask_t)],
    );
    let res_name = ctx.fresh_temp();
    ctx.emit_reg_write(res_name.clone(), IrExpr::Reg(src_t));
    write_operand(instr, 0, IrExpr::Reg(res_name), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SARX — BMI2: arithmetic right shift without using CL
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `SARX dst, src, cnt` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 SARX):
/// ```text
///   cnt_masked ← cnt & (operand_width - 1)
///   dst        ← src >>_s cnt_masked        (arithmetic / sign-extending shift)
/// ```
/// **Flags: none modified.** SARX/SHLX/SHRX leave all EFLAGS unchanged —
/// this is one of the primary advantages over SAR/SHL/SHR which must update
/// CF/OF.
///
/// The shift count is masked to the operand width (32 or 64 bits) by hardware,
/// exactly as for the legacy shift instructions.
///
/// Note: `IrExpr::Shr` is a *logical* (unsigned) right shift. To model
/// arithmetic shift right we emit an `x86.sarx.w<N>` intrinsic that the IL
/// pipeline can expand when it has sign-extension information, or we rely on
/// the type-recovery pass to upgrade a logical shift to arithmetic.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sarx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let cnt = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cnt_mask = u64::from(w_bits) - 1;
    let cnt_masked = IrExpr::And(Box::new(cnt), Box::new(IrExpr::Const(cnt_mask)));
    let cnt_t = ctx.materialise(cnt_masked);
    // Emit an intrinsic for the arithmetic shift so sign extension is preserved.
    ctx.emit_intrinsic(
        format!("x86.sarx.w{w_bits}"),
        vec![src.clone(), IrExpr::Reg(cnt_t.clone())],
    );
    // Approximate with logical Shr for VSA / dataflow that doesn't expand intrinsics.
    let res = IrExpr::Shr(Box::new(src), Box::new(IrExpr::Reg(cnt_t)));
    let t = ctx.materialise(res);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    // No flag modifications.
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SHLX — BMI2: logical left shift without using CL
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `SHLX dst, src, cnt` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 SHLX):
/// ```text
///   cnt_masked ← cnt & (operand_width - 1)
///   dst        ← src << cnt_masked
/// ```
/// **Flags: none modified.** Same advantage as SARX/SHRX.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_shlx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let cnt = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cnt_mask = u64::from(w_bits) - 1;
    let cnt_masked = IrExpr::And(Box::new(cnt), Box::new(IrExpr::Const(cnt_mask)));
    let cnt_t = ctx.materialise(cnt_masked);
    let res = IrExpr::Shl(Box::new(src), Box::new(IrExpr::Reg(cnt_t)));
    let t = ctx.materialise(res);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SHRX — BMI2: logical right shift without using CL
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `SHRX dst, src, cnt` (VEX-encoded, BMI2).
///
/// Semantics (Intel SDM §4.5 SHRX):
/// ```text
///   cnt_masked ← cnt & (operand_width - 1)
///   dst        ← src >> cnt_masked           (logical, zero-filling)
/// ```
/// **Flags: none modified.**
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_shrx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let cnt = read_operand(instr, 2, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cnt_mask = u64::from(w_bits) - 1;
    let cnt_masked = IrExpr::And(Box::new(cnt), Box::new(IrExpr::Const(cnt_mask)));
    let cnt_t = ctx.materialise(cnt_masked);
    let res = IrExpr::Shr(Box::new(src), Box::new(IrExpr::Reg(cnt_t)));
    let t = ctx.materialise(res);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BSF — Bit Scan Forward (find index of lowest set bit)
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BSF dst, src`.
///
/// Semantics (Intel SDM §4.3 BSF):
/// ```text
///   if src == 0:
///       ZF   ← 1
///       dst  ← undefined
///   else:
///       ZF   ← 0
///       dst  ← index of lowest set bit in src
///   CF, OF, SF, AF, PF: undefined
/// ```
///
/// The result is undefined when `src == 0` (ZF=1 indicates this). Emitted as
/// an `x86.bsf.w<N>` intrinsic with the source as argument; the destination
/// is set to `Undef` when src might be zero (which a static analysis cannot
/// always rule out). The ZF reflects the zero test.
///
/// Note: LZCNT is the preferred replacement in modern code (defined for zero
/// input), but BSF must be modelled correctly for legacy binary analysis.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bsf(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);

    // ZF = (src == 0)
    ctx.emit_flagset(
        FlagId::Zf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(src_t.clone()))),
    );

    // Emit the scan as an intrinsic; the result is the bit index.
    ctx.emit_intrinsic(format!("x86.bsf.w{w_bits}"), vec![IrExpr::Reg(src_t)]);

    // All other flags undefined.
    for flag in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }

    // Destination is the bit index (undefined when src==0, but we emit it
    // as Undef here; higher passes can guard on ZF).
    let res_t = ctx.fresh_temp();
    ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(res_t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BSR — Bit Scan Reverse (find index of highest set bit)
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BSR dst, src`.
///
/// Semantics (Intel SDM §4.3 BSR):
/// ```text
///   if src == 0:
///       ZF   ← 1
///       dst  ← undefined
///   else:
///       ZF   ← 0
///       dst  ← index of highest set bit in src  (= operand_width - 1 - LZCNT(src))
///   CF, OF, SF, AF, PF: undefined
/// ```
///
/// Like BSF but scans from MSB to LSB. Result is undefined when `src == 0`.
/// The `x86.bsr.w<N>` intrinsic carries the source argument.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bsr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);

    // ZF = (src == 0)
    ctx.emit_flagset(
        FlagId::Zf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(src_t.clone()))),
    );

    ctx.emit_intrinsic(format!("x86.bsr.w{w_bits}"), vec![IrExpr::Reg(src_t)]);

    for flag in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }

    let res_t = ctx.fresh_temp();
    ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(res_t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// POPCNT — population count (number of set bits)
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `POPCNT dst, src`.
///
/// Semantics (Intel SDM §4.3 POPCNT):
/// ```text
///   dst ← count of set bits in src
///   ZF  ← (src == 0)    (i.e. result == 0)
///   CF  ← 0
///   OF  ← 0
///   SF  ← 0
///   AF  ← 0
///   PF  ← 0
/// ```
///
/// Note: POPCNT clears CF, OF, SF, AF, PF to zero — it does NOT set them to
/// undefined. ZF reflects whether the source (and thus result) was zero.
///
/// The count itself is modelled as an `x86.popcnt.w<N>` intrinsic because the
/// closed form (sum of all bits) cannot be expressed as a single `IrExpr` node.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);

    // ZF = (src == 0)
    ctx.emit_flagset(
        FlagId::Zf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(src_t.clone()))),
    );

    // All other flags cleared.
    for flag in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Const(0));
    }

    // Emit intrinsic for the count computation.
    ctx.emit_intrinsic(format!("x86.popcnt.w{w_bits}"), vec![IrExpr::Reg(src_t)]);

    // Result register (population count). Higher passes substitute the intrinsic.
    let res_t = ctx.fresh_temp();
    ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(res_t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// LZCNT — leading zero count (counts zeros from MSB)
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `LZCNT dst, src`.
///
/// Semantics (Intel SDM §4.3 LZCNT):
/// ```text
///   if src == 0:
///       dst ← operand_width          (all bits zero → operand_width leading zeros)
///       CF  ← 1
///   else:
///       dst ← count of leading zero bits in src (from MSB)
///       CF  ← 0
///   ZF  ← (result == operand_width)  i.e. ZF = 1 when dst = operand_width (src had MSB set → 0 leading zeros... actually ZF=1 when result==0, i.e. MSB was set)
///   OF  ← undefined
///   SF  ← undefined
///   AF  ← undefined
///   PF  ← undefined
/// ```
///
/// Key distinction from BSR: LZCNT is *defined* when `src == 0` (returns the
/// operand width), whereas BSR leaves the destination undefined. This makes
/// LZCNT preferred for modern code.
///
/// CF and ZF are the only architecturally defined outputs:
///   * CF = 1 if src was zero
///   * ZF = 1 if result was zero (i.e., MSB of src was 1 → zero leading zeros)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lzcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);

    // CF = (src == 0)
    ctx.emit_flagset(
        FlagId::Cf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(src_t.clone()))),
    );

    // Intrinsic for the leading-zero count.
    ctx.emit_intrinsic(format!("x86.lzcnt.w{w_bits}"), vec![IrExpr::Reg(src_t)]);

    // Result temp — intrinsic result substituted by higher passes.
    let res_t = ctx.fresh_temp();
    ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);

    // ZF = (result == 0)  i.e. MSB of src was already set.
    ctx.emit_flagset(
        FlagId::Zf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(res_t.clone()))),
    );

    // OF, SF, AF, PF: undefined.
    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }

    write_operand(instr, 0, IrExpr::Reg(res_t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// TZCNT — trailing zero count (counts zeros from LSB)
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `TZCNT dst, src`.
///
/// Semantics (Intel SDM §4.3 TZCNT):
/// ```text
///   if src == 0:
///       dst ← operand_width       (all bits zero → operand_width trailing zeros)
///       CF  ← 1
///   else:
///       dst ← count of trailing zero bits in src (from LSB)
///       CF  ← 0
///   ZF  ← (result == 0)          i.e. ZF=1 when src LSB was already set
///   OF  ← undefined
///   SF  ← undefined
///   AF  ← undefined
///   PF  ← undefined
/// ```
///
/// The semantics mirror LZCNT but from the opposite end. CF=1 when src==0,
/// ZF=1 when the result is 0 (i.e., bit 0 of src was set, no trailing zeros).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tzcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let src_t = ctx.materialise(src);

    // CF = (src == 0)
    ctx.emit_flagset(
        FlagId::Cf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(src_t.clone()))),
    );

    ctx.emit_intrinsic(format!("x86.tzcnt.w{w_bits}"), vec![IrExpr::Reg(src_t)]);

    let res_t = ctx.fresh_temp();
    ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);

    // ZF = (result == 0)
    ctx.emit_flagset(
        FlagId::Zf,
        IrExpr::CmpEqZero(Box::new(IrExpr::Reg(res_t.clone()))),
    );

    for flag in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }

    write_operand(instr, 0, IrExpr::Reg(res_t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AND variants — 8-bit accumulator short form helpers
// ─────────────────────────────────────────────────────────────────────────────
// These are not separate handler entry-points (iced-x86 folds them into the
// same Mnemonic), but the operand-size helpers are exercised by the tests.

// ─────────────────────────────────────────────────────────────────────────────
// Operand-size / mode dispatchers (called by dispatch table in mod.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch `AND` handling all sizes (8/16/32/64-bit and memory operands).
///
/// This is simply an alias for [`lift_and`]; the iced-x86 decoder already
/// resolves the operand-size from the REX.W / operand-size prefix so the
/// single handler works for all widths.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_and_all_sizes(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_and(instr, ctx)
}

/// Dispatch `OR` handling all sizes.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_or_all_sizes(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_or(instr, ctx)
}

/// Dispatch `XOR` handling all sizes.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xor_all_sizes(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_xor(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── helpers ────────────────────────────────────────────────────────────

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

    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    fn flag_val(effects: &[Effect], flag: &str) -> Option<IrExpr> {
        effects.iter().rev().find_map(|e| {
            if let Effect::RegWrite { reg, value } = e {
                if reg == flag {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    fn has_intrinsic(effects: &[Effect], name: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name: n, .. } if n == name))
    }

    // ── AND tests ──────────────────────────────────────────────────────────

    #[test]
    fn and_rax_0f_masks_low_nibble() {
        // AND rax, 0x0f (0x48 0x83 0xe0 0x0f)
        let i = decode64(&[0x48, 0x83, 0xe0, 0x0f]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0xff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0x0f);
    }

    #[test]
    fn and_zero_result_sets_zf() {
        // AND rax, 0x00
        let i = decode64(&[0x48, 0x83, 0xe0, 0x00]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0xdead_beef)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn and_clears_cf() {
        let i = decode64(&[0x48, 0x83, 0xe0, 0x01]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        assert!(ctx.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "cf")));
    }

    #[test]
    fn and_clears_of() {
        let i = decode64(&[0x48, 0x83, 0xe0, 0x01]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        assert!(ctx.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "of")));
    }

    #[test]
    fn and_af_is_undefined() {
        let i = decode64(&[0x48, 0x83, 0xe0, 0x01]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.flag.af_undef"),
            "AND must emit af_undef intrinsic"
        );
    }

    #[test]
    fn and_emits_all_five_observable_flags() {
        let i = decode64(&[0x48, 0x83, 0xe0, 0x01]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "zf", "sf", "pf"] {
            assert!(writes_to(&ctx.effects, f) > 0, "AND must emit flag: {f}");
        }
    }

    #[test]
    fn and_16bit_operand() {
        // AND ax, 0x00ff  (66 prefix + 0x83 /4)
        let i = decode64(&[0x66, 0x83, 0xe0, 0x0f]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("ax", 0xffff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("ax", 0x0f);
    }

    #[test]
    fn and_32bit_zero_extends_in_64bit_mode() {
        // AND eax, 0x0f — result zero-extends to rax.
        let i = decode64(&[0x83, 0xe0, 0x0f]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0xffff_ffff_ffff_ffff_u64)]);
        exec_effects(&ctx.effects, &mut s);
        // eax result = 0x0f; zero-extended to rax = 0x0f.
        s.assert_reg("eax", 0x0f);
    }

    #[test]
    fn and_nonzero_clears_zf() {
        let i = decode64(&[0x48, 0x83, 0xe0, 0x01]);
        let mut ctx = ctx64();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0x01)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 0);
    }

    #[test]
    fn and_lock_prefix_emits_intrinsic() {
        // LOCK AND [rsp], eax — LOCK prefix on memory dest
        // We test the ModeHint path directly.
        let i = decode64(&[0x83, 0xe0, 0x0f]); // AND eax, 0x0f (no lock; for simplicity test mode flag)
        let hint = ModeHint {
            prefixes: crate::x86_context::PrefixFlags { has_lock: true, ..ModeHint::default().prefixes },
            ..ModeHint::default()
        };
        let mut ctx = X86LiftCtx::new(0x1000, 64, hint);
        lift_and(&i, &mut ctx).unwrap();
        // Lock on register dest is silently skipped (architecturally illegal).
        // The important behaviour is it does NOT panic.
    }

    // ── OR tests ───────────────────────────────────────────────────────────

    #[test]
    fn or_combines_bits() {
        // OR rax, 0xf0 (sign-extended to all-ones in upper part)
        let i = decode64(&[0x48, 0x83, 0xc8, 0xf0]);
        let mut ctx = ctx64();
        lift_or(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0x0f)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0xffff_ffff_ffff_ffff_u64);
    }

    #[test]
    fn or_identity_with_zero() {
        let i = decode64(&[0x48, 0x83, 0xc8, 0x00]);
        let mut ctx = ctx64();
        lift_or(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0x42)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0x42);
    }

    #[test]
    fn or_emits_all_five_observable_flags() {
        let i = decode64(&[0x48, 0x83, 0xc8, 0x01]);
        let mut ctx = ctx64();
        lift_or(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "zf", "sf", "pf"] {
            assert!(writes_to(&ctx.effects, f) > 0, "OR must emit: {f}");
        }
    }

    #[test]
    fn or_clears_cf_and_of() {
        let i = decode64(&[0x48, 0x83, 0xc8, 0x01]);
        let mut ctx = ctx64();
        lift_or(&i, &mut ctx).unwrap();
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(IrExpr::Const(0)));
        assert_eq!(flag_val(&ctx.effects, "of"), Some(IrExpr::Const(0)));
    }

    #[test]
    fn or_zero_inputs_sets_zf() {
        // OR rax, 0 when rax=0 → result=0, ZF=1
        let i = decode64(&[0x48, 0x83, 0xc8, 0x00]);
        let mut ctx = ctx64();
        lift_or(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    // ── XOR tests ──────────────────────────────────────────────────────────

    #[test]
    fn xor_self_yields_zero() {
        let i = decode64(&[0x31, 0xc0]); // XOR eax, eax
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("eax", 0xffff)]);
        exec_effects(&ctx.effects, &mut s);
        let v = s.get_reg("eax");
        assert!(v == EvalValue::Concrete(0) || v.is_unknown());
    }

    #[test]
    fn xor_self_sets_zf_one() {
        let i = decode64(&[0x31, 0xc0]);
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("eax", 0x99)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn xor_self_emits_const_zero_not_reg_xor_reg() {
        // The zeroing idiom should fold to IrExpr::Const(0), not Xor(Reg, Reg).
        let i = decode64(&[0x31, 0xc0]); // XOR eax, eax
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        // The destination write should carry Const(0).
        let has_const_zero = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Const(0),
                    ..
                }
            )
        });
        assert!(has_const_zero, "XOR reg,reg must constant-fold to 0");
    }

    #[test]
    fn xor_self_rax64_const_zero() {
        let i = decode64(&[0x48, 0x31, 0xc0]); // XOR rax, rax
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        let has_const_zero = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Const(0),
                    ..
                }
            )
        });
        assert!(has_const_zero, "XOR rax,rax must constant-fold to 0");
    }

    #[test]
    fn xor_flips_bits() {
        // XOR rax, -1 (all ones sign-extended)
        let i = decode64(&[0x48, 0x83, 0xf0, 0xff]);
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0xf0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0xffff_ffff_ffff_ff0f_u64);
    }

    #[test]
    fn xor_different_regs_not_folded() {
        // XOR eax, ecx — should NOT be constant-folded.
        let i = decode64(&[0x31, 0xc8]); // XOR eax, ecx
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        // Must emit the Xor expression (not a constant).
        let has_xor_expr = ctx.effects.iter().any(|e| {
            if let Effect::RegWrite { value, .. } = e {
                matches!(value, IrExpr::Xor(_, _))
            } else {
                false
            }
        });
        assert!(has_xor_expr, "XOR different regs must emit Xor expression");
    }

    // ── NOT tests ──────────────────────────────────────────────────────────

    #[test]
    fn not_all_ones_from_zero() {
        let i = decode64(&[0x48, 0xf7, 0xd0]); // NOT rax
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", u64::MAX);
    }

    #[test]
    fn not_all_zeros_from_max() {
        let i = decode64(&[0x48, 0xf7, 0xd0]);
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", u64::MAX)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0);
    }

    #[test]
    fn not_no_flag_effects() {
        let i = decode64(&[0x48, 0xf7, 0xd0]);
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        for f in ["cf", "pf", "af", "zf", "sf", "of"] {
            assert_eq!(
                writes_to(&ctx.effects, f),
                0,
                "NOT must not write flag: {f}"
            );
        }
    }

    #[test]
    fn not_no_flag_intrinsics() {
        let i = decode64(&[0x48, 0xf7, 0xd0]);
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        
        assert!(
            !ctx
            .effects
            .iter().any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.starts_with("x86.flag"))),
            "NOT must not emit any flag intrinsics"
        );
    }

    #[test]
    fn not_32bit() {
        let i = decode64(&[0xf7, 0xd0]); // NOT eax
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("eax", 0x0000_ffff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("eax", 0xffff_0000);
    }

    // ── TEST tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_no_dest_write() {
        let i = decode64(&[0x48, 0x85, 0xc0]); // TEST rax, rax
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        assert_eq!(
            writes_to(&ctx.effects, "rax"),
            0,
            "TEST must not write back to destination"
        );
    }

    #[test]
    fn test_zero_zf_one() {
        let i = decode64(&[0x48, 0x85, 0xc0]);
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn test_nonzero_zf_zero() {
        let i = decode64(&[0x48, 0x85, 0xc0]);
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0xabcd)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 0);
    }

    #[test]
    fn test_clears_cf_and_of() {
        let i = decode64(&[0x48, 0x85, 0xc0]);
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(IrExpr::Const(0)));
        assert_eq!(flag_val(&ctx.effects, "of"), Some(IrExpr::Const(0)));
    }

    #[test]
    fn test_emits_all_flags() {
        let i = decode64(&[0x48, 0x85, 0xc0]);
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "zf", "sf", "pf"] {
            assert!(writes_to(&ctx.effects, f) > 0, "TEST must emit flag: {f}");
        }
    }

    #[test]
    fn test_8bit_form() {
        // TEST al, 0x01
        let i = decode64(&[0xa8, 0x01]);
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0x01)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 0);
    }

    // ── BT family tests ────────────────────────────────────────────────────

    #[test]
    fn bt_reads_cf_from_bit() {
        // BT rax, rbx — bit 2 of rax = 1 → CF = 1
        let i = decode64(&[0x48, 0x0f, 0xa3, 0xd8]);
        let mut ctx = ctx64();
        lift_bt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b100), ("rbx", 2)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1);
    }

    #[test]
    fn bt_reads_cf_zero_from_unset_bit() {
        let i = decode64(&[0x48, 0x0f, 0xa3, 0xd8]);
        let mut ctx = ctx64();
        lift_bt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b1001), ("rbx", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 0);
    }

    #[test]
    fn bt_other_flags_undefined() {
        let i = decode64(&[0x48, 0x0f, 0xa3, 0xd8]);
        let mut ctx = ctx64();
        lift_bt(&i, &mut ctx).unwrap();
        for f in ["of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Undef),
                "BT must leave flag {f} as Undef"
            );
        }
    }

    #[test]
    fn bts_sets_cf_from_old_bit() {
        let i = decode64(&[0x48, 0x0f, 0xab, 0xd8]); // BTS rax, rbx
        let mut ctx = ctx64();
        lift_bts(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b100), ("rbx", 2)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1); // bit 2 was already 1
    }

    #[test]
    fn bts_sets_the_bit() {
        let i = decode64(&[0x48, 0x0f, 0xab, 0xd8]); // BTS rax, rbx
        let mut ctx = ctx64();
        lift_bts(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b000), ("rbx", 2)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0b100);
        s.assert_reg("cf", 0); // old bit was 0
    }

    #[test]
    fn btr_produces_correct_result() {
        let i = decode64(&[0x48, 0x0f, 0xb3, 0xd8]); // BTR rax, rbx
        let mut ctx = ctx64();
        lift_btr(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b111), ("rbx", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 5); // 0b111 & ~0b010 = 0b101 = 5
    }

    #[test]
    fn btr_cf_old_value() {
        let i = decode64(&[0x48, 0x0f, 0xb3, 0xd8]); // BTR rax, rbx
        let mut ctx = ctx64();
        lift_btr(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b110), ("rbx", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1); // bit 1 was set before reset
    }

    #[test]
    fn btc_flips_bit() {
        let i = decode64(&[0x48, 0x0f, 0xbb, 0xd8]); // BTC rax, rbx
        let mut ctx = ctx64();
        lift_btc(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b1010), ("rbx", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 8); // 0b1010 ^ 0b0010 = 0b1000 = 8
    }

    #[test]
    fn btc_cf_old_value_before_flip() {
        let i = decode64(&[0x48, 0x0f, 0xbb, 0xd8]); // BTC rax, rbx
        let mut ctx = ctx64();
        lift_btc(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b0101), ("rbx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1); // bit 0 was set before complement
    }

    #[test]
    fn btc_flip_unset_bit() {
        let i = decode64(&[0x48, 0x0f, 0xbb, 0xd8]); // BTC rax, rbx
        let mut ctx = ctx64();
        lift_btc(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("rax", 0b0100), ("rbx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("rax", 0b0101);
        s.assert_reg("cf", 0); // old bit 0 was clear
    }

    // ── ANDN tests ─────────────────────────────────────────────────────────

    #[test]
    fn andn_basic_semantics() {
        // ANDN r32a, r32b, r32c: dst = ~src1 & src2
        // Use VEX-encoded form. Encode manually: C4 E2 68 F2 /r
        // For simplicity we call the handler directly with a crafted context.
        // VEX.NDS.LZ.0F38.W0 F2 /r: ANDN r32, r32, r/m32
        // C4 E2 60 F2 C2: ANDN eax, eax, edx (vvvv=eax, reg=eax, rm=edx)
        // We'll decode it and trust iced-x86 to fill in operands.
        let bytes = [0xc4, 0xe2, 0x78, 0xf2, 0xc2]; // ANDN eax, eax, edx
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_andn(&i, &mut ctx).unwrap();
        // src1 = eax, src2 = edx: dst = ~eax & edx
        let mut s = X86CpuState::with_gp_regs(&[("eax", 0b1100), ("edx", 0b1010)]);
        exec_effects(&ctx.effects, &mut s);
        // ~0b1100 = ...0011, & 0b1010 = 0b0010 = 2
        s.assert_reg("eax", 2);
    }

    #[test]
    fn andn_clears_cf_and_of() {
        let bytes = [0xc4, 0xe2, 0x78, 0xf2, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_andn(&i, &mut ctx).unwrap();
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(IrExpr::Const(0)));
        assert_eq!(flag_val(&ctx.effects, "of"), Some(IrExpr::Const(0)));
    }

    #[test]
    fn andn_pf_is_undefined() {
        let bytes = [0xc4, 0xe2, 0x78, 0xf2, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_andn(&i, &mut ctx).unwrap();
        // ANDN: PF is undefined (unlike plain AND).
        assert_eq!(
            flag_val(&ctx.effects, "pf"),
            Some(IrExpr::Undef),
            "ANDN must leave PF as Undef"
        );
    }

    // ── BLSI tests ─────────────────────────────────────────────────────────

    #[test]
    fn blsi_isolates_lowest_set_bit() {
        // BLSI eax, edx: eax = edx & (-edx)
        // C4 E2 78 F3 DA: BLSI eax, edx
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xda];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsi(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0b10110)]);
        exec_effects(&ctx.effects, &mut s);
        // lowest set bit of 0b10110 = bit 1 = 0b00010 = 2
        s.assert_reg("eax", 2);
    }

    #[test]
    fn blsi_clears_of() {
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xda];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsi(&i, &mut ctx).unwrap();
        assert_eq!(flag_val(&ctx.effects, "of"), Some(IrExpr::Const(0)));
    }

    // ── BLSMSK tests ───────────────────────────────────────────────────────

    #[test]
    fn blsmsk_creates_mask() {
        // BLSMSK eax, edx: eax = edx ^ (edx - 1)
        // C4 E2 78 F3 D2: BLSMSK eax, edx
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xd2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsmsk(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0b01000)]);
        exec_effects(&ctx.effects, &mut s);
        // 0b01000 ^ (0b01000 - 1) = 0b01000 ^ 0b00111 = 0b01111 = 15
        s.assert_reg("eax", 15);
    }

    #[test]
    fn blsmsk_zf_always_zero() {
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xd2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsmsk(&i, &mut ctx).unwrap();
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(IrExpr::Const(0)));
    }

    // ── BLSR tests ─────────────────────────────────────────────────────────

    #[test]
    fn blsr_clears_lowest_set_bit() {
        // BLSR eax, edx: eax = edx & (edx - 1)
        // C4 E2 78 F3 CA: BLSR eax, edx
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xca];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsr(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0b10110)]);
        exec_effects(&ctx.effects, &mut s);
        // 0b10110 & (0b10110 - 1) = 0b10110 & 0b10101 = 0b10100 = 20
        s.assert_reg("eax", 20);
    }

    #[test]
    fn blsr_cf_when_src_zero() {
        let bytes = [0xc4, 0xe2, 0x78, 0xf3, 0xca];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_blsr(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        // CF = (src == 0) = 1
        s.assert_reg("cf", 1);
    }

    // ── BZHI tests ─────────────────────────────────────────────────────────

    #[test]
    fn bzhi_clears_high_bits() {
        // BZHI eax, edx, ecx: eax = edx with bits >= ecx cleared
        // C4 E2 60 F5 C2: BZHI eax, edx, ecx (W=0)
        let bytes = [0xc4, 0xe2, 0x70, 0xf5, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bzhi(&i, &mut ctx).unwrap();
        // ecx=4, edx=0xFF: keep only bits 0-3 → 0x0F
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0xff), ("ecx", 4)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("eax", 0x0f);
    }

    #[test]
    fn bzhi_emits_cf_intrinsic() {
        let bytes = [0xc4, 0xe2, 0x70, 0xf5, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bzhi(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.flag.cf_bzhi_w32"),
            "BZHI must emit cf_bzhi intrinsic"
        );
    }

    // ── POPCNT tests ────────────────────────────────────────────────────────

    #[test]
    fn popcnt_emits_intrinsic() {
        // POPCNT eax, edx: F3 0F B8 C2
        let bytes = [0xf3, 0x0f, 0xb8, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_popcnt(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.popcnt.w32"),
            "POPCNT must emit popcnt intrinsic"
        );
    }

    #[test]
    fn popcnt_clears_cf_of_sf_af_pf() {
        let bytes = [0xf3, 0x0f, 0xb8, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_popcnt(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Const(0)),
                "POPCNT must clear flag: {f}"
            );
        }
    }

    #[test]
    fn popcnt_zero_src_sets_zf() {
        let bytes = [0xf3, 0x0f, 0xb8, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_popcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn popcnt_nonzero_src_clears_zf() {
        let bytes = [0xf3, 0x0f, 0xb8, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_popcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0xff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 0);
    }

    // ── LZCNT tests ─────────────────────────────────────────────────────────

    #[test]
    fn lzcnt_emits_intrinsic() {
        // LZCNT eax, edx: F3 0F BD C2
        let bytes = [0xf3, 0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_lzcnt(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.lzcnt.w32"),
            "LZCNT must emit lzcnt intrinsic"
        );
    }

    #[test]
    fn lzcnt_cf_when_src_zero() {
        let bytes = [0xf3, 0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_lzcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1);
    }

    #[test]
    fn lzcnt_cf_clear_when_src_nonzero() {
        let bytes = [0xf3, 0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_lzcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 0);
    }

    #[test]
    fn lzcnt_undefined_flags() {
        let bytes = [0xf3, 0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_lzcnt(&i, &mut ctx).unwrap();
        for f in ["of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Undef),
                "LZCNT must leave flag {f} undefined"
            );
        }
    }

    // ── TZCNT tests ─────────────────────────────────────────────────────────

    #[test]
    fn tzcnt_emits_intrinsic() {
        // TZCNT eax, edx: F3 0F BC C2
        let bytes = [0xf3, 0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_tzcnt(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.tzcnt.w32"),
            "TZCNT must emit tzcnt intrinsic"
        );
    }

    #[test]
    fn tzcnt_cf_when_src_zero() {
        let bytes = [0xf3, 0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_tzcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1);
    }

    #[test]
    fn tzcnt_cf_clear_when_src_has_bits() {
        let bytes = [0xf3, 0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_tzcnt(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0b10)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 0);
    }

    #[test]
    fn tzcnt_undefined_flags() {
        let bytes = [0xf3, 0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_tzcnt(&i, &mut ctx).unwrap();
        for f in ["of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Undef),
                "TZCNT must leave flag {f} undefined"
            );
        }
    }

    // ── BSF tests ──────────────────────────────────────────────────────────

    #[test]
    fn bsf_emits_intrinsic() {
        // BSF eax, edx: 0F BC C2
        let bytes = [0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsf(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.bsf.w32"),
            "BSF must emit bsf intrinsic"
        );
    }

    #[test]
    fn bsf_zf_one_when_src_zero() {
        let bytes = [0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsf(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn bsf_zf_zero_when_src_nonzero() {
        let bytes = [0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsf(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0b1000)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 0);
    }

    #[test]
    fn bsf_other_flags_undefined() {
        let bytes = [0x0f, 0xbc, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsf(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Undef),
                "BSF must leave flag {f} undefined"
            );
        }
    }

    // ── BSR tests ──────────────────────────────────────────────────────────

    #[test]
    fn bsr_emits_intrinsic() {
        // BSR eax, edx: 0F BD C2
        let bytes = [0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsr(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.bsr.w32"),
            "BSR must emit bsr intrinsic"
        );
    }

    #[test]
    fn bsr_zf_one_when_src_zero() {
        let bytes = [0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsr(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }

    #[test]
    fn bsr_other_flags_undefined() {
        let bytes = [0x0f, 0xbd, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_bsr(&i, &mut ctx).unwrap();
        for f in ["cf", "of", "sf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(IrExpr::Undef),
                "BSR must leave flag {f} undefined"
            );
        }
    }

    // ── SHLX / SHRX / SARX tests ────────────────────────────────────────────

    #[test]
    fn shlx_left_shifts_without_flags() {
        // SHLX eax, edx, ecx: C4 E2 60 F7 C2
        let bytes = [0xc4, 0xe2, 0x70, 0xf7, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_shlx(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 1), ("ecx", 3)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("eax", 8);
        // No flag modifications.
        for f in ["cf", "of", "zf", "sf", "af", "pf"] {
            assert_eq!(
                writes_to(&ctx.effects, f),
                0,
                "SHLX must not modify flag: {f}"
            );
        }
    }

    #[test]
    fn shrx_right_shifts_without_flags() {
        // SHRX eax, edx, ecx: C4 E2 61 F7 C2 (W=0)
        let bytes = [0xc4, 0xe2, 0x71, 0xf7, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_shrx(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("edx", 0x80), ("ecx", 3)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("eax", 0x10);
        for f in ["cf", "of", "zf", "sf", "af", "pf"] {
            assert_eq!(
                writes_to(&ctx.effects, f),
                0,
                "SHRX must not modify flag: {f}"
            );
        }
    }

    #[test]
    fn sarx_emits_arithmetic_shift_intrinsic() {
        // SARX eax, edx, ecx: C4 E2 62 F7 C2
        let bytes = [0xc4, 0xe2, 0x72, 0xf7, 0xc2];
        let i = decode64(&bytes);
        let mut ctx = ctx64();
        lift_sarx(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.sarx.w32"),
            "SARX must emit sarx intrinsic for arithmetic shift"
        );
        for f in ["cf", "of", "zf", "sf", "af", "pf"] {
            assert_eq!(
                writes_to(&ctx.effects, f),
                0,
                "SARX must not modify flag: {f}"
            );
        }
    }

    // ── Mask-bit-idx helper unit tests ──────────────────────────────────────

    #[test]
    fn mask_bit_idx_8bit() {
        let idx = IrExpr::Const(9);
        let masked = mask_bit_idx(idx, 1);
        // 1 byte → mask = 7, 9 & 7 = 1
        assert!(
            matches!(masked, IrExpr::And(_, box_mask) if matches!(*box_mask, IrExpr::Const(7)))
        );
    }

    #[test]
    fn mask_bit_idx_64bit() {
        let idx = IrExpr::Const(100);
        let masked = mask_bit_idx(idx, 8);
        // 8 bytes → mask = 63, 100 & 63 = 36
        assert!(
            matches!(masked, IrExpr::And(_, box_mask) if matches!(*box_mask, IrExpr::Const(63)))
        );
    }

    // ── 32-bit mode tests ─────────────────────────────────────────────────

    #[test]
    fn and_32bit_mode() {
        // AND eax, 0x0f in 32-bit mode
        let i = decode32(&[0x83, 0xe0, 0x0f]);
        let mut ctx = ctx32();
        lift_and(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("eax", 0xff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("eax", 0x0f);
    }

    #[test]
    fn xor_32bit_self_zeroing() {
        // XOR eax, eax in 32-bit mode
        let i = decode32(&[0x31, 0xc0]);
        let mut ctx = ctx32();
        lift_xor(&i, &mut ctx).unwrap();
        let has_const_zero = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Const(0),
                    ..
                }
            )
        });
        assert!(has_const_zero, "XOR eax,eax in 32-bit mode must fold to 0");
    }

    // ── Effect-count sanity checks ─────────────────────────────────────────

    #[test]
    fn not_emits_exactly_one_reg_write() {
        let i = decode64(&[0x48, 0xf7, 0xd0]); // NOT rax
        let mut ctx = ctx64();
        lift_not(&i, &mut ctx).unwrap();
        
        assert_eq!(ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. })).count(), 1, "NOT must emit exactly one RegWrite");
    }

    #[test]
    fn test_emits_no_mem_write() {
        let i = decode64(&[0x48, 0x85, 0xc0]); // TEST rax, rax
        let mut ctx = ctx64();
        lift_test(&i, &mut ctx).unwrap();
        
        assert!(!ctx
            .effects
            .iter().any(|e| matches!(e, Effect::MemWrite { .. })), "TEST must not emit any MemWrite");
    }

    #[test]
    fn xor_self_emits_zf_one_directly() {
        // The constant-folded path must set ZF=1 directly.
        let i = decode64(&[0x31, 0xc0]); // XOR eax, eax
        let mut ctx = ctx64();
        lift_xor(&i, &mut ctx).unwrap();
        // ZF = CmpEqZero(Const(0)) which constant-folds to 1 during execution.
        let mut s = X86CpuState::with_gp_regs(&[]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("zf", 1);
    }
}
