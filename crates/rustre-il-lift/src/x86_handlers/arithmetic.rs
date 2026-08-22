//! Arithmetic instruction handlers for the x86/x64 lifter.
//!
//! ## Instruction coverage
//!
//! | Group | Instructions |
//! |-------|-------------|
//! | Binary add/sub | ADD, ADC, SUB, SBB, CMP |
//! | Unary | INC, DEC, NEG |
//! | Multiply | MUL, IMUL (1/2/3-operand), MULX |
//! | Divide | DIV, IDIV |
//! | Exchange-add | XADD |
//! | Compare-exchange | CMPXCHG, CMPXCHG8B, CMPXCHG16B |
//! | BMI2 carry-less | ADCX, ADOX |
//! | Legacy BCD | AAA, AAS, DAA, DAS |
//! | Legacy ASCII | AAM, AAD |
//!
//! ## μOp discipline
//!
//! Every handler follows the same five-step pattern:
//!
//! 1. **Read** source operands as `IrExpr` (no side-effects yet).
//! 2. **Compute** the result as a single `IrExpr` tree.
//! 3. **Materialise** the result into a fresh temporary via
//!    `ctx.materialise_sized(expr, w_bits)` so flag formulas and the
//!    destination commit share one canonical name.
//! 4. **Flag updates** through `x86_flags::set_flags_*`.
//! 5. **Commit** the temporary into the destination operand via
//!    `write_operand`.
//!
//! ## Flag semantics summary (Intel SDM Vol. 1 §3.4.3)
//!
//! | Instruction | CF | OF | SF | ZF | AF | PF |
//! |-------------|----|----|----|----|----|----|
//! | ADD         | U  | U  | R  | R  | U  | R  |
//! | ADC         | U  | U  | R  | R  | U  | R  |
//! | SUB/CMP     | U  | U  | R  | R  | U  | R  |
//! | SBB         | U  | U  | R  | R  | U  | R  |
//! | INC         | -  | U  | R  | R  | U  | R  |
//! | DEC         | -  | U  | R  | R  | U  | R  |
//! | NEG         | U  | U  | R  | R  | U  | R  |
//! | MUL         | U  | U  | ?  | ?  | ?  | ?  |
//! | IMUL(1-op)  | U  | U  | ?  | ?  | ?  | ?  |
//! | IMUL(2/3-op)| U  | U  | ?  | ?  | ?  | ?  |
//! | DIV/IDIV    | ?  | ?  | ?  | ?  | ?  | ?  |
//! | XADD        | U  | U  | R  | R  | U  | R  |
//! | CMPXCHG     | (via CMP semantics) |
//! | ADCX        | U  | -  | -  | -  | -  | -  |
//! | ADOX        | -  | U  | -  | -  | -  | -  |
//! | AAA/AAS     | U  | ?  | ?  | ?  | U  | ?  |
//! | DAA/DAS     | U  | ?  | R  | R  | U  | R  |
//!
//! Legend: U=updated (lazy intrinsic), R=computed (closed-form), -=preserved,
//! ?=undefined (`IrExpr::Undef`).

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_flags;
use crate::x86_operand::{operand_size, read_operand, write_operand};
use crate::{Effect, IrExpr, LiftError};
use iced_x86::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mark all six EFLAGS as architecturally undefined (used by DIV/IDIV and the
/// BCD group where the SDM says "undefined").
#[inline]
fn set_all_flags_undef(ctx: &mut X86LiftCtx) {
    for f in [
        FlagId::Cf,
        FlagId::Of,
        FlagId::Sf,
        FlagId::Zf,
        FlagId::Af,
        FlagId::Pf,
    ] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

/// Mark SF/ZF/PF/AF as undefined, leaving CF and OF untouched.
/// Used by MUL/IMUL where only CF and OF carry information.
#[inline]
pub fn set_szpaf_undef(ctx: &mut X86LiftCtx) {
    for f in [FlagId::Sf, FlagId::Zf, FlagId::Pf, FlagId::Af] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

/// Emit a lazy-flag intrinsic followed by `IrExpr::Undef` into `flag`.
/// Shorthand used throughout this module.
#[inline]
fn lazy_flag(ctx: &mut X86LiftCtx, flag: FlagId, name: &str, args: Vec<IrExpr>) {
    ctx.emit_flag_intrinsic(flag, name, args);
}

/// Resolve the implicit accumulator register name pair for MUL/IMUL/DIV/IDIV.
///
/// Returns `(acc_lo, acc_hi, result_lo, result_hi)` where `acc_lo` is the
/// implicit source (e.g. `rax`) and `result_lo`/`result_hi` are the
/// destination halves (`rax`/`rdx`).  For 8-bit operations `result_hi` is
/// `""` (no high half — result goes entirely in `ax`).
const fn mul_regs(w_bits: u8) -> (&'static str, &'static str, &'static str, &'static str) {
    match w_bits {
        8 => ("al", "", "ax", ""),
        16 => ("ax", "dx", "ax", "dx"),
        32 => ("eax", "edx", "eax", "edx"),
        _ => ("rax", "rdx", "rax", "rdx"),
    }
}

/// Resolve the implicit dividend register pair for DIV/IDIV.
///
/// Returns `(lo, hi, quot, rem)` where the dividend is `hi:lo` and the
/// quotient/remainder land in `quot`/`rem`.
const fn div_regs(w_bits: u8) -> (&'static str, &'static str, &'static str, &'static str) {
    match w_bits {
        8 => ("ax", "", "al", "ah"),
        16 => ("ax", "dx", "ax", "dx"),
        32 => ("eax", "edx", "eax", "edx"),
        _ => ("rax", "rdx", "rax", "rdx"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADD — Unsigned integer addition
// ─────────────────────────────────────────────────────────────────────────────

/// `ADD dst, src` — Add `src` to `dst` and store in `dst`.
///
/// Opcode encodings covered (representative selection; iced dispatches all):
/// * `00 /r`  — ADD r/m8, r8
/// * `01 /r`  — ADD r/m16/32/64, r16/32/64
/// * `02 /r`  — ADD r8, r/m8
/// * `03 /r`  — ADD r16/32/64, r/m16/32/64
/// * `04 ib`  — ADD AL, imm8
/// * `05 i`   — ADD rAX, imm16/32
/// * `80 /0`  — ADD r/m8, imm8
/// * `81 /0`  — ADD r/m16/32/64, imm16/32
/// * `83 /0`  — ADD r/m16/32/64, imm8 (sign-extended)
/// * REX.W variants for 64-bit operand size.
///
/// Flags: CF, OF, AF updated (lazy intrinsics); SF, ZF, PF computed from result.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_add(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // a + b may overflow; truncation to operand width is done by materialise_sized.
    let result_expr = IrExpr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let t = ctx.materialise_sized(result_expr, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_add(ctx, &a, &b, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ADC — Add with carry
// ─────────────────────────────────────────────────────────────────────────────

/// `ADC dst, src` — Add `src` + CF to `dst`.
///
/// The Intel SDM specifies: `DEST ← DEST + SRC + CF`.
/// The two-stage computation mirrors the hardware: first `a + b`, then
/// `+ CF`, so that the carry formula can reference the incoming CF register.
///
/// Opcode encodings covered:
/// * `10 /r` — ADC r/m8, r8
/// * `11 /r` — ADC r/m16/32/64, r16/32/64
/// * `12 /r` — ADC r8, r/m8
/// * `13 /r` — ADC r16/32/64, r/m16/32/64
/// * `14 ib` — ADC AL, imm8
/// * `15 i`  — ADC rAX, imm16/32
/// * `80 /2` — ADC r/m8, imm8
/// * `81 /2` — ADC r/m16/32/64, imm16/32
/// * `83 /2` — ADC r/m16/32/64, imm8 (sign-extended)
///
/// Flags: CF, OF, AF updated (lazy); SF, ZF, PF computed.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_adc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cf_in = IrExpr::Reg("cf".into());

    // Two-stage: (a + b) + CF mirrors SDM.
    let stage1 = IrExpr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let result_expr = IrExpr::Add(Box::new(stage1), Box::new(cf_in.clone()));
    let t = ctx.materialise_sized(result_expr, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_adc(ctx, &a, &b, &cf_in, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SUB — Integer subtraction
// ─────────────────────────────────────────────────────────────────────────────

/// `SUB dst, src` — Subtract `src` from `dst`, store in `dst`.
///
/// Opcode encodings covered:
/// * `28 /r` — SUB r/m8, r8
/// * `29 /r` — SUB r/m16/32/64, r16/32/64
/// * `2A /r` — SUB r8, r/m8
/// * `2B /r` — SUB r16/32/64, r/m16/32/64
/// * `2C ib` — SUB AL, imm8
/// * `2D i`  — SUB rAX, imm16/32
/// * `80 /5` — SUB r/m8, imm8
/// * `81 /5` — SUB r/m16/32/64, imm16/32
/// * `83 /5` — SUB r/m16/32/64, imm8 (sign-extended)
///
/// Flags: CF set when unsigned borrow; OF set on signed overflow; AF, SF, ZF, PF
/// from result.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sub(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    let result_expr = IrExpr::Sub(Box::new(a.clone()), Box::new(b.clone()));
    let t = ctx.materialise_sized(result_expr, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_sub(ctx, &a, &b, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SBB — Subtract with borrow
// ─────────────────────────────────────────────────────────────────────────────

/// `SBB dst, src` — Subtract `src` + CF from `dst`.
///
/// SDM: `DEST ← DEST − (SRC + CF)`. Implementation uses two Sub stages so the
/// incoming CF value is visible in the borrow-chain formula.
///
/// Opcode encodings covered:
/// * `18 /r` — SBB r/m8, r8
/// * `19 /r` — SBB r/m16/32/64, r16/32/64
/// * `1A /r` — SBB r8, r/m8
/// * `1B /r` — SBB r16/32/64, r/m16/32/64
/// * `1C ib` — SBB AL, imm8
/// * `1D i`  — SBB rAX, imm16/32
/// * `80 /3` — SBB r/m8, imm8
/// * `81 /3` — SBB r/m16/32/64, imm16/32
/// * `83 /3` — SBB r/m16/32/64, imm8 (sign-extended)
///
/// Flags: CF (new borrow), OF, AF updated lazy; SF, ZF, PF computed.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sbb(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cf_in = IrExpr::Reg("cf".into());

    // a - (b + CF) in two stages.
    let borrow_src = IrExpr::Add(Box::new(b.clone()), Box::new(cf_in.clone()));
    let result_expr = IrExpr::Sub(Box::new(a.clone()), Box::new(borrow_src));
    let t = ctx.materialise_sized(result_expr, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_sbb(ctx, &a, &b, &cf_in, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// CMP — Compare (SUB without write-back)
// ─────────────────────────────────────────────────────────────────────────────

/// `CMP op1, op2` — Compute `op1 − op2`, update flags, **discard result**.
///
/// Architecturally identical to SUB except the destination operand is never
/// written. All six flags are updated exactly as SUB.
///
/// Opcode encodings covered:
/// * `38 /r` — CMP r/m8, r8
/// * `39 /r` — CMP r/m16/32/64, r16/32/64
/// * `3A /r` — CMP r8, r/m8
/// * `3B /r` — CMP r16/32/64, r/m16/32/64
/// * `3C ib` — CMP AL, imm8
/// * `3D i`  — CMP rAX, imm16/32
/// * `80 /7` — CMP r/m8, imm8
/// * `81 /7` — CMP r/m16/32/64, imm16/32
/// * `83 /7` — CMP r/m16/32/64, imm8 (sign-extended)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    let result_expr = IrExpr::Sub(Box::new(a.clone()), Box::new(b.clone()));
    let t = ctx.materialise_sized(result_expr, w_bits);
    let t_expr = IrExpr::Reg(t);
    // No write_operand — CMP only updates flags.
    x86_flags::set_flags_sub(ctx, &a, &b, &t_expr, w_bits);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// INC — Increment by 1
// ─────────────────────────────────────────────────────────────────────────────

/// `INC dst` — Add 1 to `dst` **without modifying CF**.
///
/// INC is NOT equivalent to `ADD dst, 1` with respect to CF: the carry flag
/// is explicitly preserved. The overflow flag (signed overflow) and all other
/// flags are updated exactly as ADD would update them.
///
/// Opcode encodings covered:
/// * `FE /0`     — INC r/m8
/// * `FF /0`     — INC r/m16/32/64
/// * `40+r` (16/32-bit mode only, REX prefix in 64-bit mode)
///
/// Flags: CF **preserved**; OF, AF, SF, ZF, PF updated.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_inc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    let result = IrExpr::Add(Box::new(a.clone()), Box::new(IrExpr::Const(1)));
    let t = ctx.materialise_sized(result, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_inc(ctx, &a, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DEC — Decrement by 1
// ─────────────────────────────────────────────────────────────────────────────

/// `DEC dst` — Subtract 1 from `dst` **without modifying CF**.
///
/// DEC is NOT equivalent to `SUB dst, 1` with respect to CF.
///
/// Opcode encodings covered:
/// * `FE /1`     — DEC r/m8
/// * `FF /1`     — DEC r/m16/32/64
/// * `48+r` (16/32-bit mode only)
///
/// Flags: CF **preserved**; OF, AF, SF, ZF, PF updated.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_dec(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    let result = IrExpr::Sub(Box::new(a.clone()), Box::new(IrExpr::Const(1)));
    let t = ctx.materialise_sized(result, w_bits);
    let t_expr = IrExpr::Reg(t);

    x86_flags::set_flags_dec(ctx, &a, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// NEG — Two's complement negation
// ─────────────────────────────────────────────────────────────────────────────

/// `NEG dst` — Replace `dst` with its two's complement negation (`0 − dst`).
///
/// CF is set if the original operand was non-zero (equivalently, if the result
/// wraps). This is the only case where CF semantics differ from CMP 0, src.
///
/// Opcode encodings covered:
/// * `F6 /3` — NEG r/m8
/// * `F7 /3` — NEG r/m16/32/64
///
/// Flags: CF set iff src ≠ 0 (via lazy intrinsic); OF set iff src = `INT_MIN`;
/// AF, SF, ZF, PF computed from result.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_neg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;

    // 0 - a
    let result = IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(a.clone()));
    let t = ctx.materialise_sized(result, w_bits);
    let t_expr = IrExpr::Reg(t);

    // set_flags_neg delegates to set_flags_sub(0, a, result, bits).
    x86_flags::set_flags_neg(ctx, &a, &t_expr, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// MUL — Unsigned multiply (implicit-accumulator form only)
// ─────────────────────────────────────────────────────────────────────────────

/// `MUL src` — Unsigned multiply of the implicit accumulator by `src`.
///
/// The result width is always double the operand width. The high half lands in
/// a separate register (DX, EDX, RDX) while the low half overwrites the
/// accumulator. For the 8-bit form the entire 16-bit result is placed in AX.
///
/// | Operand width | Implicit acc | Result lo | Result hi |
/// |---------------|-------------|-----------|-----------|
/// | 8             | AL          | AX        | (none)    |
/// | 16            | AX          | AX        | DX        |
/// | 32            | EAX         | EAX       | EDX       |
/// | 64            | RAX         | RAX       | RDX       |
///
/// The high half of the product is modelled by an opaque intrinsic
/// `x86.mul.hi_w<N>` because `IrExpr` has no integer-width-aware unsigned
/// double-width multiply. CF and OF are set when the high half is non-zero.
///
/// Opcode encodings covered:
/// * `F6 /4` — MUL r/m8
/// * `F7 /4` — MUL r/m16/32/64
///
/// Flags: CF/OF set iff upper half non-zero; SF/ZF/AF/PF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mul(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let (acc_lo, _acc_hi, dst_lo, dst_hi) = mul_regs(w_bits);

    // Low half: lo = acc * src (truncated to operand width).
    let prod_lo = IrExpr::Mul(Box::new(IrExpr::Reg(acc_lo.into())), Box::new(src.clone()));
    let t_lo = ctx.materialise_sized(prod_lo, w_bits);
    ctx.emit_reg_write(dst_lo, IrExpr::Reg(t_lo.clone()));

    // High half via intrinsic (no IrExpr primitive for double-width mul).
    if !dst_hi.is_empty() {
        let t_hi = ctx.fresh_temp();
        ctx.emit(Effect::Intrinsic {
            name: format!("x86.mul.hi_w{w_bits}"),
            args: vec![IrExpr::Reg(acc_lo.into()), src.clone()],
        });
        // Emit the hi-half RegWrite as Undef; the intrinsic preceding it
        // carries the semantic value for data-flow.
        ctx.emit_reg_write(dst_hi, IrExpr::Reg(t_hi));
    }

    // CF/OF are set iff the upper half of the product is non-zero (APM p.254).
    // Pass the multiplicands, not `t_lo`: `t_lo` is truncated to `w_bits`, so
    // the upper half is not recoverable from it.
    x86_flags::set_flags_mul(ctx, &IrExpr::Reg(acc_lo.into()), &src, w_bits);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// IMUL — Signed multiply (1-, 2-, and 3-operand forms)
// ─────────────────────────────────────────────────────────────────────────────

/// `IMUL` — Signed integer multiply, three forms.
///
/// **1-operand form** (`IMUL src`):
/// Multiplies the implicit accumulator (AL/AX/EAX/RAX) by `src`. The
/// double-width signed product lands in `DX:AX`, `EDX:EAX`, or `RDX:RAX`.
/// Identical layout to MUL but signed.
///
/// **2-operand form** (`IMUL dst, src`):
/// Multiplies `dst` by `src` and stores the lower half in `dst`. The upper
/// (sign-extended) half is discarded; CF/OF indicate whether it was significant.
///
/// **3-operand form** (`IMUL dst, src, imm`):
/// Multiplies `src` by `imm` and stores the lower half in `dst`.
///
/// Opcode encodings covered:
/// * `F6 /5` — IMUL r/m8  (1-op)
/// * `F7 /5` — IMUL r/m16/32/64  (1-op)
/// * `0F AF /r` — IMUL r16/32/64, r/m16/32/64  (2-op)
/// * `6B /r ib` — IMUL r16/32/64, r/m16/32/64, imm8 (3-op)
/// * `69 /r i`  — IMUL r16/32/64, r/m16/32/64, imm16/32 (3-op)
///
/// Flags: CF/OF set when result does not fit in lower half; SF/ZF/AF/PF
/// **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_imul(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let op_count = instr.op_count();

    match op_count {
        1 => {
            lift_imul_one(instr, ctx, w_bits);
            Ok(())
        },
        2 => {
            lift_imul_two(instr, ctx, w_bits);
            Ok(())
        },
        3 => {
            lift_imul_three(instr, ctx, w_bits);
            Ok(())
        },
        n => Err(LiftError::LiftFailed(
            ctx.addr,
            format!("IMUL with {n} operands — unexpected encoding"),
        )),
    }
}

/// 1-operand IMUL: accumulator × src → double-width signed product in DX:AX
/// (or equivalent pair).
fn lift_imul_one(instr: &Instruction, ctx: &mut X86LiftCtx, w_bits: u8) {
    let src = read_operand(instr, 0, ctx);
    let (acc_lo, _acc_hi, dst_lo, dst_hi) = mul_regs(w_bits);

    // Low half.
    let prod_lo = IrExpr::Mul(Box::new(IrExpr::Reg(acc_lo.into())), Box::new(src.clone()));
    let t_lo = ctx.materialise_sized(prod_lo, w_bits);
    ctx.emit_reg_write(dst_lo, IrExpr::Reg(t_lo));

    // High half via intrinsic.
    if !dst_hi.is_empty() {
        ctx.emit(Effect::Intrinsic {
            name: format!("x86.imul.hi_w{w_bits}"),
            args: vec![IrExpr::Reg(acc_lo.into()), src],
        });
        ctx.emit_reg_write(dst_hi, IrExpr::Undef);
    }

    // IMUL's CF/OF are NOT the MUL rule (upper-half-non-zero); they are set
    // iff the full product differs from the sign-extension of the low half.
    // Passing Undef keeps them soundly Unknown rather than silently wrong.
    x86_flags::set_flags_mul(ctx, &IrExpr::Undef, &IrExpr::Undef, w_bits);
    
}

/// 2-operand IMUL: dst ← dst × src (lower half only).
fn lift_imul_two(instr: &Instruction, ctx: &mut X86LiftCtx, w_bits: u8) {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);

    let prod = IrExpr::Mul(Box::new(a.clone()), Box::new(b.clone()));
    let t = ctx.materialise_sized(prod, w_bits);
    let t_expr = IrExpr::Reg(t);

    // Emit high-half intrinsic for CF/OF computation by peephole passes.
    ctx.emit(Effect::Intrinsic {
        name: format!("x86.imul.hi_w{w_bits}"),
        args: vec![a, b],
    });
    // IMUL's CF/OF are NOT the MUL rule (upper-half-non-zero); they are set
    // iff the full product differs from the sign-extension of the low half.
    // Passing Undef keeps them soundly Unknown rather than silently wrong.
    x86_flags::set_flags_mul(ctx, &IrExpr::Undef, &IrExpr::Undef, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    
}

/// 3-operand IMUL: dst ← src1 × imm (lower half only).
fn lift_imul_three(instr: &Instruction, ctx: &mut X86LiftCtx, w_bits: u8) {
    let b = read_operand(instr, 1, ctx);
    let c = read_operand(instr, 2, ctx);

    let prod = IrExpr::Mul(Box::new(b.clone()), Box::new(c.clone()));
    let t = ctx.materialise_sized(prod, w_bits);
    let t_expr = IrExpr::Reg(t);

    ctx.emit(Effect::Intrinsic {
        name: format!("x86.imul.hi_w{w_bits}"),
        args: vec![b, c],
    });
    // IMUL's CF/OF are NOT the MUL rule (upper-half-non-zero); they are set
    // iff the full product differs from the sign-extension of the low half.
    // Passing Undef keeps them soundly Unknown rather than silently wrong.
    x86_flags::set_flags_mul(ctx, &IrExpr::Undef, &IrExpr::Undef, w_bits);
    write_operand(instr, 0, t_expr, ctx);
    
}

// ─────────────────────────────────────────────────────────────────────────────
// MULX — Unsigned multiply without flags (BMI2)
// ─────────────────────────────────────────────────────────────────────────────

/// `MULX dst_hi, dst_lo, src` — Unsigned multiply of EDX/RDX by `src` into
/// two separate destination registers.
///
/// BMI2 instruction. Unlike MUL/IMUL this does **not** modify any flags,
/// making it safe to use inside carry-save arithmetic without disturbing the
/// flag chain.
///
/// SDM: `(dst_hi, dst_lo) ← EDX/RDX * src` (unsigned double-width product).
///
/// Opcode encoding:
/// * VEX.LZ.F2.0F38.W0 F6 /r — MULX r32a, r32b, r/m32
/// * VEX.LZ.F2.0F38.W1 F6 /r — MULX r64a, r64b, r/m64
///
/// Flags: **none modified**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mulx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w_bits = operand_size(instr, 0, ctx) * 8;
    // operand 2 = explicit source; operand 0 = dst_hi; operand 1 = dst_lo.
    let src = read_operand(instr, 2, ctx);
    let rdx = if w_bits == 64 { "rdx" } else { "edx" };

    // Low half of the double-width product.
    let prod_lo = IrExpr::Mul(Box::new(IrExpr::Reg(rdx.into())), Box::new(src.clone()));
    let t_lo = ctx.materialise_sized(prod_lo, w_bits);
    write_operand(instr, 1, IrExpr::Reg(t_lo), ctx); // dst_lo

    // High half via intrinsic.
    ctx.emit(Effect::Intrinsic {
        name: format!("x86.mulx.hi_w{w_bits}"),
        args: vec![IrExpr::Reg(rdx.into()), src],
    });
    // dst_hi is Undef at IR level; peepholes expand the intrinsic.
    write_operand(instr, 0, IrExpr::Undef, ctx); // dst_hi

    // No flag modifications.
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DIV — Unsigned division
// ─────────────────────────────────────────────────────────────────────────────

/// `DIV src` — Unsigned divide the implicit double-width dividend by `src`.
///
/// The dividend is `DX:AX` / `EDX:EAX` / `RDX:RAX` (or just `AX` for 8-bit).
/// Quotient lands in `AL`/`AX`/`EAX`/`RAX`; remainder in `AH`/`DX`/`EDX`/`RDX`.
///
/// A divide-by-zero or quotient overflow raises a #DE fault; the lifter models
/// this as an opaque intrinsic because the precise fault condition depends on
/// the full double-width dividend which `IrExpr` cannot represent without
/// dedicated primitives.
///
/// Opcode encodings covered:
/// * `F6 /6` — DIV r/m8
/// * `F7 /6` — DIV r/m16/32/64
///
/// Flags: CF/OF/SF/ZF/AF/PF all **undefined** (SDM Vol.1 §3.4.3).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_div(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let divisor = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let (lo, hi, quot, rem) = div_regs(w_bits);

    // Emit the intrinsic that models the full division.
    let dividend_lo = IrExpr::Reg(lo.into());
    let dividend_hi = if hi.is_empty() {
        IrExpr::Const(0)
    } else {
        IrExpr::Reg(hi.into())
    };
    ctx.emit(Effect::Intrinsic {
        name: format!("x86.div.unsigned_w{w_bits}"),
        args: vec![dividend_hi, dividend_lo, divisor],
    });
    // Quotient and remainder are opaque.
    ctx.emit_reg_write(quot, IrExpr::Undef);
    if !rem.is_empty() {
        ctx.emit_reg_write(rem, IrExpr::Undef);
    }
    set_all_flags_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// IDIV — Signed division
// ─────────────────────────────────────────────────────────────────────────────

/// `IDIV src` — Signed divide the implicit double-width dividend by `src`.
///
/// Identical layout to DIV but the operation is signed (two's-complement). A
/// #DE fault is raised on divide-by-zero or if the quotient does not fit in
/// the destination operand width.
///
/// Opcode encodings covered:
/// * `F6 /7` — IDIV r/m8
/// * `F7 /7` — IDIV r/m16/32/64
///
/// Flags: all **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_idiv(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let divisor = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let (lo, hi, quot, rem) = div_regs(w_bits);

    let dividend_lo = IrExpr::Reg(lo.into());
    let dividend_hi = if hi.is_empty() {
        IrExpr::Const(0)
    } else {
        IrExpr::Reg(hi.into())
    };
    ctx.emit(Effect::Intrinsic {
        name: format!("x86.div.signed_w{w_bits}"),
        args: vec![dividend_hi, dividend_lo, divisor],
    });
    ctx.emit_reg_write(quot, IrExpr::Undef);
    if !rem.is_empty() {
        ctx.emit_reg_write(rem, IrExpr::Undef);
    }
    set_all_flags_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// XADD — Exchange and Add
// ─────────────────────────────────────────────────────────────────────────────

/// `XADD dst, src` — Atomically exchange `dst` and `src`, then add them and
/// store the sum in `dst`.
///
/// Operation:
/// ```text
/// tmp ← dst
/// dst ← dst + src
/// src ← tmp
/// ```
///
/// The LOCK prefix is legal here and implies an atomic RMW on memory operands.
/// The lifter emits a LOCK intrinsic when `ctx.mode.prefixes.has_lock` is set.
///
/// Opcode encodings covered:
/// * `0F C0 /r` — XADD r/m8, r8
/// * `0F C1 /r` — XADD r/m16/32/64, r16/32/64
///
/// Flags: CF, OF, AF updated (lazy); SF, ZF, PF computed from result.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xadd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx); // dst (before exchange)
    let b = read_operand(instr, 1, ctx); // src
    let w_bits = operand_size(instr, 0, ctx) * 8;

    if ctx.mode.prefixes.has_lock {
        ctx.emit(Effect::Intrinsic {
            name: "x86.lock".to_string(),
            args: vec![],
        });
    }

    // sum = a + b
    let sum = IrExpr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let t_sum = ctx.materialise_sized(sum, w_bits);
    let sum_expr = IrExpr::Reg(t_sum);

    // src ← old dst  (the exchange half)
    write_operand(instr, 1, a.clone(), ctx);
    // dst ← sum
    write_operand(instr, 0, sum_expr.clone(), ctx);

    x86_flags::set_flags_add(ctx, &a, &b, &sum_expr, w_bits);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// CMPXCHG — Compare and Exchange
// ─────────────────────────────────────────────────────────────────────────────

/// `CMPXCHG dst, src` — Compare accumulator with `dst`; if equal, store `src`
/// in `dst`; else load `dst` into accumulator.
///
/// Operation (8/16/32/64-bit form):
/// ```text
/// if acc == dst {
///     ZF ← 1; dst ← src;
/// } else {
///     ZF ← 0; acc ← dst;
/// }
/// // CF, OF, SF, AF, PF set as CMP (acc, dst).
/// ```
///
/// The conditional write is modelled as an intrinsic because `IrExpr` has no
/// conditional-select primitive; peephole passes expand it into a conditional
/// branch + two `RegWrite` μOps when needed.
///
/// Opcode encodings covered:
/// * `0F B0 /r` — CMPXCHG r/m8, r8
/// * `0F B1 /r` — CMPXCHG r/m16/32/64, r16/32/64
///
/// Also covers CMPXCHG8B and CMPXCHG16B via separate handler below.
///
/// Flags: updated as CMP (acc, dst); ZF indicates equality.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmpxchg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic;
    match instr.mnemonic() {
        Mnemonic::Cmpxchg => {
            lift_cmpxchg_standard(instr, ctx);
            Ok(())
        },
        Mnemonic::Cmpxchg8b => {
            lift_cmpxchg8b(instr, ctx);
            Ok(())
        },
        Mnemonic::Cmpxchg16b => {
            lift_cmpxchg16b(instr, ctx);
            Ok(())
        },
        _ => Err(LiftError::LiftFailed(
            ctx.addr,
            "lift_cmpxchg: unexpected mnemonic".to_string(),
        )),
    }
}

/// Standard `CMPXCHG r/m, r` (8/16/32/64-bit).
fn lift_cmpxchg_standard(instr: &Instruction, ctx: &mut X86LiftCtx) {
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let dst = read_operand(instr, 0, ctx); // r/m
    let src = read_operand(instr, 1, ctx); // r (the new value)

    // Accumulator register for this operand width.
    let acc_name: &str = match w_bits {
        8 => "al",
        16 => "ax",
        32 => "eax",
        _ => "rax",
    };
    let acc = IrExpr::Reg(acc_name.into());

    if ctx.mode.prefixes.has_lock {
        ctx.emit(Effect::Intrinsic {
            name: "x86.lock".to_string(),
            args: vec![],
        });
    }

    // Compare acc - dst to set flags.
    let diff = IrExpr::Sub(Box::new(acc.clone()), Box::new(dst.clone()));
    let t_diff = ctx.materialise_sized(diff, w_bits);
    let diff_expr = IrExpr::Reg(t_diff);
    x86_flags::set_flags_sub(ctx, &acc, &dst, &diff_expr, w_bits);

    // The conditional select is opaque at the IrExpr level.
    ctx.emit(Effect::Intrinsic {
        name: format!("x86.cmpxchg.select_w{w_bits}"),
        args: vec![acc.clone(), dst.clone(), src],
    });
    // Conservative model: dst and acc may both be written.
    write_operand(instr, 0, IrExpr::Undef, ctx);
    ctx.emit_reg_write(acc_name, IrExpr::Undef);
    
}

/// `CMPXCHG8B m64` — Compare EDX:EAX with a 64-bit memory operand; if equal
/// load ECX:EBX into memory, else load memory into EDX:EAX.
///
/// Opcode: `0F C7 /1`
///
/// Flags: ZF set if equal, all others undefined.
fn lift_cmpxchg8b(instr: &Instruction, ctx: &mut X86LiftCtx) {
    if ctx.mode.prefixes.has_lock {
        ctx.emit(Effect::Intrinsic {
            name: "x86.lock".to_string(),
            args: vec![],
        });
    }
    let mem = read_operand(instr, 0, ctx);
    ctx.emit(Effect::Intrinsic {
        name: "x86.cmpxchg8b".to_string(),
        args: vec![
            mem,
            IrExpr::Reg("edx".into()),
            IrExpr::Reg("eax".into()),
            IrExpr::Reg("ecx".into()),
            IrExpr::Reg("ebx".into()),
        ],
    });
    // ZF is the only architecturally defined flag output.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Undef, ctx);
    ctx.emit_reg_write("edx", IrExpr::Undef);
    ctx.emit_reg_write("eax", IrExpr::Undef);
    
}

/// `CMPXCHG16B m128` — Compare RDX:RAX with a 128-bit memory operand; if equal
/// load RCX:RBX into memory, else load memory into RDX:RAX.
///
/// Opcode: REX.W `0F C7 /1` (64-bit mode only).
///
/// Flags: ZF set if equal, all others undefined.
fn lift_cmpxchg16b(instr: &Instruction, ctx: &mut X86LiftCtx) {
    if ctx.mode.prefixes.has_lock {
        ctx.emit(Effect::Intrinsic {
            name: "x86.lock".to_string(),
            args: vec![],
        });
    }
    let mem = read_operand(instr, 0, ctx);
    ctx.emit(Effect::Intrinsic {
        name: "x86.cmpxchg16b".to_string(),
        args: vec![
            mem,
            IrExpr::Reg("rdx".into()),
            IrExpr::Reg("rax".into()),
            IrExpr::Reg("rcx".into()),
            IrExpr::Reg("rbx".into()),
        ],
    });
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Undef, ctx);
    ctx.emit_reg_write("rdx", IrExpr::Undef);
    ctx.emit_reg_write("rax", IrExpr::Undef);
    
}

// ─────────────────────────────────────────────────────────────────────────────
// ADCX — Add with CF carry chain (ADX extension)
// ─────────────────────────────────────────────────────────────────────────────

/// `ADCX dst, src` — Add `dst + src + CF`, storing result in `dst`.
///
/// Part of the Intel ADX (Multi-Precision Add-Carry Instruction Extensions)
/// introduced with Broadwell. ADCX updates **only CF** (not OF); this allows
/// parallel carry-chain arithmetic where one chain updates CF (via ADCX) and
/// another updates OF (via ADOX), with no interference between chains.
///
/// Opcode encoding:
/// * `66 0F 38 F6 /r` — ADCX r32, r/m32
/// * `66 REX.W 0F 38 F6 /r` — ADCX r64, r/m64
///
/// Flags: **CF only** (updated); OF, SF, ZF, AF, PF **preserved**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_adcx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let cf_in = IrExpr::Reg("cf".into());

    // dst + src + CF
    let stage1 = IrExpr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let result = IrExpr::Add(Box::new(stage1), Box::new(cf_in.clone()));
    let t = ctx.materialise_sized(result, w_bits);
    let t_expr = IrExpr::Reg(t);

    // Only CF is updated — use the ADC carry formula.
    lazy_flag(
        ctx,
        FlagId::Cf,
        &format!("x86.flag.cf_adc_w{w_bits}"),
        vec![a, b, cf_in],
    );
    // OF, SF, ZF, AF, PF are not modified (no emission = preserved).

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ADOX — Add with OF carry chain (ADX extension)
// ─────────────────────────────────────────────────────────────────────────────

/// `ADOX dst, src` — Add `dst + src + OF`, storing result in `dst`.
///
/// Symmetric counterpart to ADCX: uses OF as the carry-in and updates OF as
/// the carry-out. All other flags are preserved.
///
/// Opcode encoding:
/// * `F3 0F 38 F6 /r` — ADOX r32, r/m32
/// * `F3 REX.W 0F 38 F6 /r` — ADOX r64, r/m64
///
/// Flags: **OF only** (updated); CF, SF, ZF, AF, PF **preserved**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_adox(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    let of_in = IrExpr::Reg("of".into());

    let stage1 = IrExpr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let result = IrExpr::Add(Box::new(stage1), Box::new(of_in.clone()));
    let t = ctx.materialise_sized(result, w_bits);
    let t_expr = IrExpr::Reg(t);

    // OF is updated using the same carry formula (reuse cf_adc semantically;
    // the intrinsic name encodes the difference for peephole passes).
    lazy_flag(
        ctx,
        FlagId::Of,
        &format!("x86.flag.of_adox_w{w_bits}"),
        vec![a, b, of_in],
    );

    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy BCD/ASCII adjusters
// ─────────────────────────────────────────────────────────────────────────────

/// `DAA` — Decimal Adjust AL After Addition.
///
/// Adjusts AL after a packed-BCD addition. Operates on AL and the AF/CF flags.
/// Only valid in 32-bit (and earlier) mode — the 64-bit ISA removed it.
///
/// SDM algorithm (condensed):
/// ```text
/// old_AL ← AL; old_CF ← CF;
/// CF ← 0;
/// if (AL[3:0] > 9) or (AF == 1) {
///     AL ← AL + 6; CF ← old_CF | carry_from_addition;
///     AF ← 1;
/// } else { AF ← 0; }
/// if (old_AL > 0x99) or (old_CF == 1) {
///     AL ← AL + 0x60; CF ← 1;
/// }
/// // SF, ZF, PF set on new AL; OF undefined.
/// ```
///
/// Opcode: `27` (no operands, implicit AL).
///
/// Flags: CF updated; AF updated; SF, ZF, PF computed; OF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_daa(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let _ = instr;
    ctx.emit(Effect::Intrinsic {
        name: "x86.bcd.daa".to_string(),
        args: vec![
            IrExpr::Reg("al".into()),
            IrExpr::Reg("cf".into()),
            IrExpr::Reg("af".into()),
        ],
    });
    // AL is written; flags are computed inside the intrinsic model.
    ctx.emit_reg_write("al", IrExpr::Undef);
    lazy_flag(
        ctx,
        FlagId::Cf,
        "x86.flag.cf_daa",
        vec![IrExpr::Reg("al".into()), IrExpr::Reg("cf".into())],
    );
    lazy_flag(
        ctx,
        FlagId::Af,
        "x86.flag.af_daa",
        vec![IrExpr::Reg("al".into()), IrExpr::Reg("af".into())],
    );
    // SF/ZF/PF are defined on the adjusted AL but AL is Undef at this point;
    // model them as Undef too (the intrinsic carries the semantic payload).
    ctx.emit_flagset(FlagId::Sf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    Ok(())
}

/// `DAS` — Decimal Adjust AL After Subtraction.
///
/// Adjusts AL after a packed-BCD subtraction. Symmetric to DAA.
///
/// Opcode: `2F` (no operands, implicit AL).
///
/// Flags: CF updated; AF updated; SF, ZF, PF computed; OF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_das(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let _ = instr;
    ctx.emit(Effect::Intrinsic {
        name: "x86.bcd.das".to_string(),
        args: vec![
            IrExpr::Reg("al".into()),
            IrExpr::Reg("cf".into()),
            IrExpr::Reg("af".into()),
        ],
    });
    ctx.emit_reg_write("al", IrExpr::Undef);
    lazy_flag(
        ctx,
        FlagId::Cf,
        "x86.flag.cf_das",
        vec![IrExpr::Reg("al".into()), IrExpr::Reg("cf".into())],
    );
    lazy_flag(
        ctx,
        FlagId::Af,
        "x86.flag.af_das",
        vec![IrExpr::Reg("al".into()), IrExpr::Reg("af".into())],
    );
    ctx.emit_flagset(FlagId::Sf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    Ok(())
}

/// `AAA` — ASCII Adjust AL After Addition.
///
/// Adjusts the result of an ASCII (unpacked-BCD) addition. Operates on AL and
/// the low nibble of AH.
///
/// SDM algorithm:
/// ```text
/// if (AL[3:0] > 9) or (AF == 1) {
///     AX ← AX + 0x0106; AF ← 1; CF ← 1;
/// } else { AF ← 0; CF ← 0; }
/// AL ← AL & 0x0F;
/// ```
///
/// Opcode: `37` (no explicit operands, implicit AX).
///
/// Flags: AF, CF updated; OF, SF, ZF, PF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_aaa(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let _ = instr;
    ctx.emit(Effect::Intrinsic {
        name: "x86.bcd.aaa".to_string(),
        args: vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    });
    ctx.emit_reg_write("ax", IrExpr::Undef);
    lazy_flag(
        ctx,
        FlagId::Af,
        "x86.flag.af_aaa",
        vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    );
    lazy_flag(
        ctx,
        FlagId::Cf,
        "x86.flag.cf_aaa",
        vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    );
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Sf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    Ok(())
}

/// `AAS` — ASCII Adjust AL After Subtraction.
///
/// Adjusts the result of an ASCII (unpacked-BCD) subtraction.
///
/// SDM algorithm:
/// ```text
/// if (AL[3:0] > 9) or (AF == 1) {
///     AX ← AX − 6; AH ← AH − 1; AF ← 1; CF ← 1;
/// } else { AF ← 0; CF ← 0; }
/// AL ← AL & 0x0F;
/// ```
///
/// Opcode: `3F` (no explicit operands, implicit AX).
///
/// Flags: AF, CF updated; OF, SF, ZF, PF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_aas(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let _ = instr;
    ctx.emit(Effect::Intrinsic {
        name: "x86.bcd.aas".to_string(),
        args: vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    });
    ctx.emit_reg_write("ax", IrExpr::Undef);
    lazy_flag(
        ctx,
        FlagId::Af,
        "x86.flag.af_aas",
        vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    );
    lazy_flag(
        ctx,
        FlagId::Cf,
        "x86.flag.cf_aas",
        vec![IrExpr::Reg("ax".into()), IrExpr::Reg("af".into())],
    );
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Sf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    Ok(())
}

/// `AAM ib` — ASCII Adjust AX After Multiply.
///
/// Divides AL by the immediate operand (typically 10), places the quotient in
/// AH and the remainder in AL. Used after an unpacked-BCD multiply to produce
/// two BCD digits.
///
/// SDM:
/// ```text
/// AH ← AL / imm8;
/// AL ← AL mod imm8;
/// ```
///
/// Opcode: `D4 ib` (8-bit immediate, usually 0x0A).
///
/// Flags: SF, ZF, PF computed from AL; CF, OF, AF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_aam(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let imm = read_operand(instr, 0, ctx);
    ctx.emit(Effect::Intrinsic {
        name: "x86.bcd.aam".to_string(),
        args: vec![IrExpr::Reg("al".into()), imm],
    });
    ctx.emit_reg_write("ah", IrExpr::Undef);
    ctx.emit_reg_write("al", IrExpr::Undef);
    // SF/ZF/PF on the new AL — but AL is Undef so we keep all as Undef.
    ctx.emit_flagset(FlagId::Sf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    Ok(())
}

/// `AAD ib` — ASCII Adjust AX Before Division.
///
/// Prepares unpacked-BCD digits in AH:AL for division. The result is
/// `AL ← AH * imm8 + AL; AH ← 0`.
///
/// Opcode: `D5 ib` (8-bit immediate, usually 0x0A).
///
/// Flags: SF, ZF, PF computed on new AL; CF, OF, AF **undefined**.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_aad(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let imm = read_operand(instr, 0, ctx);
    // al ← ah * imm + al
    let ah_times_imm = IrExpr::Mul(Box::new(IrExpr::Reg("ah".into())), Box::new(imm));
    let new_al = IrExpr::Add(Box::new(ah_times_imm), Box::new(IrExpr::Reg("al".into())));
    let t = ctx.materialise_sized(new_al, 8);
    let t_expr = IrExpr::Reg(t);
    ctx.emit_reg_write("al", t_expr.clone());
    ctx.emit_reg_write("ah", IrExpr::Const(0));
    // Flags on the new AL.
    ctx.emit_flagset(FlagId::Zf, x86_flags::zf_of(&t_expr));
    ctx.emit_flagset(FlagId::Sf, x86_flags::sf_of(&t_expr, 8));
    ctx.emit_flagset(FlagId::Pf, x86_flags::pf_of(&t_expr));
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Of, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Af, IrExpr::Undef);
    Ok(())
}

/// Unified dispatcher for the four legacy BCD instructions that share the same
/// opaque-intrinsic model: AAA, AAS, DAA, DAS.
///
/// This function is called from `mod.rs` for `Mnemonic::Aaa | Mnemonic::Aas |
/// Mnemonic::Daa | Mnemonic::Das`.  The per-instruction functions (`lift_daa`,
/// `lift_das`, `lift_aaa`, `lift_aas`) are the canonical implementations; this
/// is a convenience shim.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bcd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic;
    match instr.mnemonic() {
        Mnemonic::Daa => lift_daa(instr, ctx),
        Mnemonic::Das => lift_das(instr, ctx),
        Mnemonic::Aaa => lift_aaa(instr, ctx),
        Mnemonic::Aas => lift_aas(instr, ctx),
        Mnemonic::Aam => lift_aam(instr, ctx),
        Mnemonic::Aad => lift_aad(instr, ctx),
        m => Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_bcd called with non-BCD mnemonic {m:?}"),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Test helpers ─────────────────────────────────────────────────────────

    /// Decode a byte slice at address 0x1000 in 64-bit mode and return the
    /// first instruction.
    fn decode(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    /// Decode in 32-bit mode.
    fn decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    /// Create a 64-bit lifting context at 0x1000.
    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    /// Create a 32-bit lifting context at 0x1000.
    fn ctx32() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, ModeHint::default())
    }

    /// Count `RegWrite` effects to a specific register name.
    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    /// True if there is a `RegWrite` to `reg` with `IrExpr::Undef` as value.
    fn writes_undef(effects: &[Effect], reg: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg: r, value: IrExpr::Undef } if r == reg))
    }

    /// True if any effect in the stream is an `Intrinsic` whose name contains
    /// the given substring.
    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    // ── ADD ──────────────────────────────────────────────────────────────────

    /// ADD rax, rbx (48 01 D8) must produce an `IrExpr::Add` and write rax.
    #[test]
    fn add_rax_rbx_emits_add_and_writes_rax() {
        let i = decode(&[0x48, 0x01, 0xd8]);
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0);
        let has_add = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Add(_, _),
                    ..
                }
            )
        });
        assert!(has_add, "expected materialised Add expression");
    }

    /// ADD must emit all six flag effects.
    #[test]
    fn add_emits_six_flag_effects() {
        let i = decode(&[0x48, 0x01, 0xd8]); // ADD rax, rbx
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        for f in ["zf", "sf", "pf", "cf", "of", "af"] {
            assert!(writes_to(&ctx.effects, f) > 0, "missing flag: {f}");
        }
    }

    /// ADD rax, 10 with rax=5 → rax=15.
    #[test]
    fn add_rax_imm_concrete_eval() {
        let i = decode(&[0x48, 0x83, 0xc0, 0x0a]); // ADD rax, 10
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 5)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 15);
    }

    /// ADD rax, 0 must leave rax unchanged.
    #[test]
    fn add_zero_identity() {
        let i = decode(&[0x48, 0x83, 0xc0, 0x00]); // ADD rax, 0
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 0xdead_beef)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 0xdead_beef);
    }

    /// ADD rax, 0 when rax=0 → ZF=1.
    #[test]
    fn add_zero_result_sets_zf() {
        let i = decode(&[0x48, 0x83, 0xc0, 0x00]);
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 0)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 1);
    }

    /// ADD rax, 1 when rax=1 → ZF=0.
    #[test]
    fn add_nonzero_result_clears_zf() {
        let i = decode(&[0x48, 0x83, 0xc0, 0x01]);
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 1)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 0);
    }

    /// ADD AL, 0x7F with AL=0x01 → 0x80: OF=1 (signed overflow), CF=0, AF=1.
    #[test]
    fn add_byte_signed_overflow_sets_of() {
        let i = decode(&[0x04, 0x7f]); // ADD AL, 7Fh
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0x01)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0x80);
        s.assert_reg("cf", 0);
        s.assert_reg("of", 1);
        s.assert_reg("af", 1);
        s.assert_reg("zf", 0);
        s.assert_reg("sf", 1);
    }

    /// ADD AL, 1 with AL=0xFF → 0x00: CF=1, OF=0, ZF=1, AF=1.
    #[test]
    fn add_byte_unsigned_wrap_sets_cf_zf() {
        let i = decode(&[0x04, 0x01]); // ADD AL, 1
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0xff)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0x00);
        s.assert_reg("cf", 1);
        s.assert_reg("of", 0);
        s.assert_reg("zf", 1);
        s.assert_reg("af", 1);
        s.assert_reg("sf", 0);
    }

    // ── SUB ──────────────────────────────────────────────────────────────────

    /// SUB rax, rbx must produce a `Sub` expression and write rax.
    #[test]
    fn sub_emits_sub_and_writes_rax() {
        let i = decode(&[0x48, 0x29, 0xd8]); // SUB rax, rbx
        let mut ctx = ctx64();
        super::lift_sub(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0);
        let has_sub = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Sub(_, _),
                    ..
                }
            )
        });
        assert!(has_sub);
    }

    /// SUB rax, 3 with rax=10 → rax=7.
    #[test]
    fn sub_concrete_eval() {
        let i = decode(&[0x48, 0x83, 0xe8, 0x03]); // SUB rax, 3
        let mut ctx = ctx64();
        super::lift_sub(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 7);
    }

    /// SUB rax, 5 when rax=5 → ZF=1.
    #[test]
    fn sub_equal_sets_zf() {
        let i = decode(&[0x48, 0x83, 0xe8, 0x05]); // SUB rax, 5
        let mut ctx = ctx64();
        super::lift_sub(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 5)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 1);
    }

    /// SUB must emit all six flag effects.
    #[test]
    fn sub_emits_six_flags() {
        let i = decode(&[0x48, 0x29, 0xd8]); // SUB rax, rbx
        let mut ctx = ctx64();
        super::lift_sub(&i, &mut ctx).unwrap();
        for f in ["zf", "sf", "pf", "cf", "of", "af"] {
            assert!(writes_to(&ctx.effects, f) > 0, "missing flag: {f}");
        }
    }

    // ── CMP ──────────────────────────────────────────────────────────────────

    /// CMP must NOT write the first operand.
    #[test]
    fn cmp_does_not_write_dst() {
        let i = decode(&[0x48, 0x3b, 0xc3]); // CMP rax, rbx
        let mut ctx = ctx64();
        super::lift_cmp(&i, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "rax"), 0, "CMP must not modify rax");
    }

    /// CMP must still emit flag effects.
    #[test]
    fn cmp_emits_flags() {
        let i = decode(&[0x48, 0x3b, 0xc3]);
        let mut ctx = ctx64();
        super::lift_cmp(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    /// CMP rax, 10 with rax=10 → ZF=1.
    #[test]
    fn cmp_equal_sets_zf() {
        let i = decode(&[0x48, 0x83, 0xf8, 0x0a]); // CMP rax, 10
        let mut ctx = ctx64();
        super::lift_cmp(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 1);
    }

    /// CMP AL, 6 with AL=5 → CF=1, AF=1, SF=1 (borrow).
    #[test]
    fn cmp_byte_borrow_flags() {
        let i = decode(&[0x3c, 0x06]); // CMP AL, 6
        let mut ctx = ctx64();
        super::lift_cmp(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0x05)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("cf", 1);
        s.assert_reg("af", 1);
        s.assert_reg("sf", 1);
        s.assert_reg("zf", 0);
        // AL must not be modified by CMP.
        s.assert_reg("al", 0x05);
    }

    // ── ADC ──────────────────────────────────────────────────────────────────

    /// ADC must reference CF in the expression tree.
    #[test]
    fn adc_reads_cf() {
        let i = decode(&[0x48, 0x11, 0xd8]); // ADC rax, rbx
        let mut ctx = ctx64();
        super::lift_adc(&i, &mut ctx).unwrap();
        let reads_cf = ctx
            .effects
            .iter()
            .any(|e| e.read_registers().iter().any(|r| r == "cf"));
        assert!(reads_cf, "ADC must read CF");
    }

    /// ADC rax, 5 with CF=0 equals ADD rax, 5.
    #[test]
    fn adc_with_cf_zero_behaves_like_add() {
        let i = decode(&[0x48, 0x83, 0xd0, 0x05]); // ADC rax, 5
        let mut ctx = ctx64();
        super::lift_adc(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10), ("cf", 0)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 15);
    }

    /// ADC rax, 5 with CF=1 → rax + 5 + 1 = 16.
    #[test]
    fn adc_with_cf_one_adds_carry() {
        let i = decode(&[0x48, 0x83, 0xd0, 0x05]); // ADC rax, 5
        let mut ctx = ctx64();
        super::lift_adc(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10), ("cf", 1)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 16);
    }

    /// ADC AL, 0 with AL=0xFF, CF=1 → 0x00 with carry out (CF=1, ZF=1).
    #[test]
    fn adc_byte_carry_through() {
        let i = decode(&[0x14, 0x00]); // ADC AL, 0
        let mut ctx = ctx64();
        super::lift_adc(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0xff), ("cf", 1)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0x00);
        s.assert_reg("cf", 1);
        s.assert_reg("zf", 1);
    }

    // ── SBB ──────────────────────────────────────────────────────────────────

    /// SBB must reference CF in its expression tree.
    #[test]
    fn sbb_reads_cf() {
        let i = decode(&[0x48, 0x19, 0xd8]); // SBB rax, rbx
        let mut ctx = ctx64();
        super::lift_sbb(&i, &mut ctx).unwrap();
        let reads_cf = ctx
            .effects
            .iter()
            .any(|e| e.read_registers().iter().any(|r| r == "cf"));
        assert!(reads_cf, "SBB must read CF");
    }

    /// SBB rax, 3 with rax=10, CF=0 → rax=7 (same as SUB).
    #[test]
    fn sbb_with_cf_zero_behaves_like_sub() {
        let i = decode(&[0x48, 0x83, 0xd8, 0x03]); // SBB rax, 3
        let mut ctx = ctx64();
        super::lift_sbb(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10), ("cf", 0)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 7);
    }

    /// SBB rax, 3 with rax=10, CF=1 → 10 - 3 - 1 = 6.
    #[test]
    fn sbb_with_cf_one_borrows() {
        let i = decode(&[0x48, 0x83, 0xd8, 0x03]); // SBB rax, 3
        let mut ctx = ctx64();
        super::lift_sbb(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 10), ("cf", 1)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 6);
    }

    // ── INC ──────────────────────────────────────────────────────────────────

    /// INC rax with rax=41 → rax=42.
    #[test]
    fn inc_rax_adds_one() {
        let i = decode(&[0x48, 0xff, 0xc0]); // INC rax
        let mut ctx = ctx64();
        super::lift_inc(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 41)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 42);
    }

    /// INC must NOT emit a CF update.
    #[test]
    fn inc_does_not_emit_cf() {
        let i = decode(&[0x48, 0xff, 0xc0]); // INC rax
        let mut ctx = ctx64();
        super::lift_inc(&i, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cf"), 0, "INC must preserve CF");
    }

    /// INC eax with eax=0xFFFFFFFF → eax wraps to 0, ZF=1.
    #[test]
    fn inc_eax_wraps_to_zero_sets_zf() {
        let i = decode32(&[0xff, 0xc0]); // INC eax (32-bit mode)
        let mut ctx = ctx32();
        super::lift_inc(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("eax", u64::from(u32::MAX))]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 1);
    }

    /// INC rax with rax=0x7FFFFFFFFFFFFFFF → OF=1 (signed overflow).
    #[test]
    fn inc_rax_at_signed_max_sets_of() {
        let i = decode(&[0x48, 0xff, 0xc0]); // INC rax
        let mut ctx = ctx64();
        super::lift_inc(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", i64::MAX as u64)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("of", 1);
    }

    // ── DEC ──────────────────────────────────────────────────────────────────

    /// DEC rax with rax=43 → rax=42.
    #[test]
    fn dec_rax_subtracts_one() {
        let i = decode(&[0x48, 0xff, 0xc8]); // DEC rax
        let mut ctx = ctx64();
        super::lift_dec(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 43)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 42);
    }

    /// DEC must NOT emit a CF update.
    #[test]
    fn dec_does_not_emit_cf() {
        let i = decode(&[0x48, 0xff, 0xc8]); // DEC rax
        let mut ctx = ctx64();
        super::lift_dec(&i, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cf"), 0, "DEC must preserve CF");
    }

    /// DEC rax with rax=1 → rax=0, ZF=1.
    #[test]
    fn dec_to_zero_sets_zf() {
        let i = decode(&[0x48, 0xff, 0xc8]); // DEC rax
        let mut ctx = ctx64();
        super::lift_dec(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 1)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 0);
        state.assert_reg("zf", 1);
    }

    // ── NEG ──────────────────────────────────────────────────────────────────

    /// NEG rax with rax=5 → rax = 0-5 = `u64::MAX-4`.
    #[test]
    fn neg_rax_negates_value() {
        let i = decode(&[0x48, 0xf7, 0xd8]); // NEG rax
        let mut ctx = ctx64();
        super::lift_neg(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 5)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 0u64.wrapping_sub(5));
    }

    /// NEG rax with rax=0 → ZF=1 (and CF=0 per SDM).
    #[test]
    fn neg_zero_sets_zf() {
        let i = decode(&[0x48, 0xf7, 0xd8]); // NEG rax
        let mut ctx = ctx64();
        super::lift_neg(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 0)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("zf", 1);
    }

    /// NEG emits all six flag effects.
    #[test]
    fn neg_emits_six_flags() {
        let i = decode(&[0x48, 0xf7, 0xd8]); // NEG rax
        let mut ctx = ctx64();
        super::lift_neg(&i, &mut ctx).unwrap();
        for f in ["zf", "sf", "pf", "cf", "of", "af"] {
            assert!(writes_to(&ctx.effects, f) > 0, "missing flag: {f}");
        }
    }

    // ── MUL ──────────────────────────────────────────────────────────────────

    /// MUL rbx must produce a `Mul` expression.
    #[test]
    fn mul_emits_mul_expr() {
        let i = decode(&[0x48, 0xf7, 0xe3]); // MUL rbx
        let mut ctx = ctx64();
        super::lift_mul(&i, &mut ctx).unwrap();
        let has_mul = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Mul(_, _),
                    ..
                }
            )
        });
        assert!(has_mul, "MUL should produce Mul expression");
    }

    /// MUL rbx must write rax.
    #[test]
    fn mul_writes_rax() {
        let i = decode(&[0x48, 0xf7, 0xe3]); // MUL rbx
        let mut ctx = ctx64();
        super::lift_mul(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0, "MUL must write rax");
    }

    /// MUL must emit CF and OF lazy updates.
    #[test]
    fn mul_emits_cf_of_flags() {
        let i = decode(&[0x48, 0xf7, 0xe3]); // MUL rbx
        let mut ctx = ctx64();
        super::lift_mul(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "cf") > 0, "MUL must emit CF");
        assert!(writes_to(&ctx.effects, "of") > 0, "MUL must emit OF");
    }

    /// MUL must mark SF/ZF/AF/PF as undefined.
    #[test]
    fn mul_sets_szap_undef() {
        let i = decode(&[0x48, 0xf7, 0xe3]); // MUL rbx
        let mut ctx = ctx64();
        super::lift_mul(&i, &mut ctx).unwrap();
        for f in ["sf", "zf", "af", "pf"] {
            assert!(writes_undef(&ctx.effects, f), "MUL: {f} must be Undef");
        }
    }

    /// MUL rbx should also write rdx (the high half) for 64-bit form.
    #[test]
    fn mul_64bit_emits_hi_half_intrinsic() {
        let i = decode(&[0x48, 0xf7, 0xe3]); // MUL rbx
        let mut ctx = ctx64();
        super::lift_mul(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.mul.hi_w64"),
            "MUL 64 should emit high-half intrinsic"
        );
    }

    // ── IMUL ─────────────────────────────────────────────────────────────────

    /// IMUL rax, rbx (2-op) must write rax.
    #[test]
    fn imul_two_op_writes_dst() {
        let i = decode(&[0x48, 0x0f, 0xaf, 0xc3]); // IMUL rax, rbx
        let mut ctx = ctx64();
        super::lift_imul(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0);
    }

    /// IMUL rax, rbx, 4 (3-op) must write rax.
    #[test]
    fn imul_three_op_writes_dst() {
        let i = decode(&[0x48, 0x6b, 0xc3, 0x04]); // IMUL rax, rbx, 4
        let mut ctx = ctx64();
        super::lift_imul(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0);
    }

    /// IMUL 1-op must emit the imul1 intrinsic.
    #[test]
    fn imul_one_op_emits_hi_intrinsic() {
        let i = decode(&[0x48, 0xf7, 0xeb]); // IMUL rbx (1-op)
        let mut ctx = ctx64();
        super::lift_imul(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.imul.hi_w64"),
            "IMUL 1-op must emit high-half intrinsic"
        );
    }

    /// IMUL 3-op must emit hi intrinsic.
    #[test]
    fn imul_three_op_emits_hi_intrinsic() {
        let i = decode(&[0x48, 0x6b, 0xc3, 0x04]); // IMUL rax, rbx, 4
        let mut ctx = ctx64();
        super::lift_imul(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.imul.hi_w64"));
    }

    // ── DIV ──────────────────────────────────────────────────────────────────

    /// DIV must emit the unsigned division intrinsic.
    #[test]
    fn div_emits_unsigned_intrinsic() {
        let i = decode(&[0x48, 0xf7, 0xf3]); // DIV rbx
        let mut ctx = ctx64();
        super::lift_div(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.div.unsigned"),
            "DIV should emit unsigned intrinsic"
        );
    }

    /// DIV must set all 6 flags to Undef.
    #[test]
    fn div_all_flags_undef() {
        let i = decode(&[0x48, 0xf7, 0xf3]); // DIV rbx
        let mut ctx = ctx64();
        super::lift_div(&i, &mut ctx).unwrap();
        let undef_count = ctx
            .effects
            .iter()
            .filter(|e| {
                matches!(e, Effect::RegWrite { value: IrExpr::Undef, reg }
                     if ["cf","pf","af","zf","sf","of"].contains(&reg.as_str()))
            })
            .count();
        assert_eq!(undef_count, 6, "DIV must set all 6 flags to Undef");
    }

    // ── IDIV ─────────────────────────────────────────────────────────────────

    /// IDIV must emit the signed division intrinsic.
    #[test]
    fn idiv_emits_signed_intrinsic() {
        let i = decode(&[0x48, 0xf7, 0xfb]); // IDIV rbx
        let mut ctx = ctx64();
        super::lift_idiv(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx.effects, "x86.div.signed"),
            "IDIV must emit signed intrinsic"
        );
    }

    /// IDIV must set all 6 flags to Undef.
    #[test]
    fn idiv_all_flags_undef() {
        let i = decode(&[0x48, 0xf7, 0xfb]); // IDIV rbx
        let mut ctx = ctx64();
        super::lift_idiv(&i, &mut ctx).unwrap();
        let undef_count = ctx
            .effects
            .iter()
            .filter(|e| {
                matches!(e, Effect::RegWrite { value: IrExpr::Undef, reg }
                     if ["cf","pf","af","zf","sf","of"].contains(&reg.as_str()))
            })
            .count();
        assert_eq!(undef_count, 6);
    }

    // ── XADD ─────────────────────────────────────────────────────────────────

    /// XADD rax, rbx: sum must be written to rax, old rax written to rbx.
    #[test]
    fn xadd_writes_sum_to_dst_and_old_to_src() {
        // 0F C1 D8 — XADD rax, rbx (48 prefix for REX.W)
        let i = decode(&[0x48, 0x0f, 0xc1, 0xd8]); // XADD rax, rbx
        let mut ctx = ctx64();
        super::lift_xadd(&i, &mut ctx).unwrap();
        // rax should be written (with the sum).
        assert!(writes_to(&ctx.effects, "rax") > 0, "XADD must write rax");
        // rbx should be written (with the old rax).
        assert!(writes_to(&ctx.effects, "rbx") > 0, "XADD must write rbx");
    }

    /// XADD concrete evaluation: rax=5, rbx=3 → rax=8, rbx=5.
    #[test]
    fn xadd_concrete_eval() {
        let i = decode(&[0x48, 0x0f, 0xc1, 0xd8]); // XADD rax, rbx
        let mut ctx = ctx64();
        super::lift_xadd(&i, &mut ctx).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 5), ("rbx", 3)]);
        exec_effects(&ctx.effects, &mut state);
        state.assert_reg("rax", 8);
        state.assert_reg("rbx", 5);
    }

    /// XADD must emit all six flag effects.
    #[test]
    fn xadd_emits_six_flags() {
        let i = decode(&[0x48, 0x0f, 0xc1, 0xd8]); // XADD rax, rbx
        let mut ctx = ctx64();
        super::lift_xadd(&i, &mut ctx).unwrap();
        for f in ["zf", "sf", "pf", "cf", "of", "af"] {
            assert!(writes_to(&ctx.effects, f) > 0, "XADD missing flag: {f}");
        }
    }

    // ── CMPXCHG ──────────────────────────────────────────────────────────────

    /// CMPXCHG must emit the comparison flags and the select intrinsic.
    #[test]
    fn cmpxchg_emits_select_intrinsic_and_flags() {
        let i = decode(&[0x48, 0x0f, 0xb1, 0xd8]); // CMPXCHG rax, rbx
        let mut ctx = ctx64();
        super::lift_cmpxchg_standard(&i, &mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.cmpxchg.select"));
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    // ── ADCX ─────────────────────────────────────────────────────────────────

    /// ADCX must emit CF but NOT OF, SF, ZF, AF, PF.
    #[test]
    fn adcx_only_updates_cf() {
        // 66 0F 38 F6 C3 — ADCX eax, ebx (no REX.W → 32-bit)
        let i = decode(&[0x66, 0x0f, 0x38, 0xf6, 0xc3]);
        let mut ctx = ctx64();
        super::lift_adcx(&i, &mut ctx).unwrap();
        // CF must be written.
        assert!(writes_to(&ctx.effects, "cf") > 0, "ADCX must update CF");
        // OF, SF, ZF, AF, PF must NOT be written.
        for f in ["of", "sf", "zf", "af", "pf"] {
            assert_eq!(writes_to(&ctx.effects, f), 0, "ADCX must not modify {f}");
        }
    }

    // ── ADOX ─────────────────────────────────────────────────────────────────

    /// ADOX must emit OF but NOT CF, SF, ZF, AF, PF.
    #[test]
    fn adox_only_updates_of() {
        // F3 0F 38 F6 C3 — ADOX eax, ebx
        let i = decode(&[0xf3, 0x0f, 0x38, 0xf6, 0xc3]);
        let mut ctx = ctx64();
        super::lift_adox(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "of") > 0, "ADOX must update OF");
        for f in ["cf", "sf", "zf", "af", "pf"] {
            assert_eq!(writes_to(&ctx.effects, f), 0, "ADOX must not modify {f}");
        }
    }

    // ── BCD / Legacy adjusters ────────────────────────────────────────────────

    /// DAA must emit the BCD intrinsic and update CF/AF flags.
    #[test]
    fn daa_emits_intrinsic_and_cf_af() {
        let i = decode32(&[0x27]); // DAA
        let mut ctx = ctx32();
        super::lift_daa(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.bcd.daa"));
        assert!(writes_to(&ctx.effects, "cf") > 0, "DAA must write CF");
        assert!(writes_to(&ctx.effects, "af") > 0, "DAA must write AF");
    }

    /// DAS must emit the BCD intrinsic.
    #[test]
    fn das_emits_intrinsic() {
        let i = decode32(&[0x2f]); // DAS
        let mut ctx = ctx32();
        super::lift_das(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.bcd.das"));
    }

    /// AAA must emit the intrinsic and update AF/CF.
    #[test]
    fn aaa_emits_intrinsic_and_flags() {
        let i = decode32(&[0x37]); // AAA
        let mut ctx = ctx32();
        super::lift_aaa(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.bcd.aaa"));
        assert!(writes_to(&ctx.effects, "af") > 0);
        assert!(writes_to(&ctx.effects, "cf") > 0);
    }

    /// AAS must emit the intrinsic.
    #[test]
    fn aas_emits_intrinsic() {
        let i = decode32(&[0x3f]); // AAS
        let mut ctx = ctx32();
        super::lift_aas(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.bcd.aas"));
    }

    /// AAD must compute the new AL value as AH * imm + AL.
    #[test]
    fn aad_computes_new_al() {
        let i = decode32(&[0xd5, 0x0a]); // AAD 10
        let mut ctx = ctx32();
        super::lift_aad(&i, &mut ctx).unwrap();
        // Should write AL and AH.
        assert!(writes_to(&ctx.effects, "al") > 0, "AAD must write AL");
        assert!(writes_to(&ctx.effects, "ah") > 0, "AAD must write AH");
        // AH ← 0.
        let ah_zero = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "ah"));
        assert!(ah_zero, "AAD must clear AH");
    }

    // ── Multi-instruction integration tests ───────────────────────────────────

    /// ADD rax, 5 then SUB rax, 5 leaves rax unchanged.
    #[test]
    fn add_then_sub_cancels() {
        let i_add = decode(&[0x48, 0x83, 0xc0, 0x05]); // ADD rax, 5
        let i_sub = decode(&[0x48, 0x83, 0xe8, 0x05]); // SUB rax, 5

        let mut ctx_a = ctx64();
        super::lift_add(&i_add, &mut ctx_a).unwrap();
        let mut ctx_s = ctx64();
        super::lift_sub(&i_sub, &mut ctx_s).unwrap();

        let mut state = X86CpuState::with_gp_regs(&[("rax", 100)]);
        exec_effects(&ctx_a.effects, &mut state);
        exec_effects(&ctx_s.effects, &mut state);
        state.assert_reg("rax", 100);
    }

    /// INC then DEC leaves rax unchanged.
    #[test]
    fn inc_then_dec_cancels() {
        let i_inc = decode(&[0x48, 0xff, 0xc0]); // INC rax
        let i_dec = decode(&[0x48, 0xff, 0xc8]); // DEC rax
        let mut ctx_i = ctx64();
        let mut ctx_d = ctx64();
        super::lift_inc(&i_inc, &mut ctx_i).unwrap();
        super::lift_dec(&i_dec, &mut ctx_d).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 42)]);
        exec_effects(&ctx_i.effects, &mut state);
        exec_effects(&ctx_d.effects, &mut state);
        state.assert_reg("rax", 42);
    }

    /// NEG applied twice is identity.
    #[test]
    fn double_neg_is_identity() {
        let i = decode(&[0x48, 0xf7, 0xd8]); // NEG rax
        let mut ctx1 = ctx64();
        let mut ctx2 = ctx64();
        super::lift_neg(&i, &mut ctx1).unwrap();
        super::lift_neg(&i, &mut ctx2).unwrap();
        let mut state = X86CpuState::with_gp_regs(&[("rax", 42)]);
        exec_effects(&ctx1.effects, &mut state);
        exec_effects(&ctx2.effects, &mut state);
        state.assert_reg("rax", 42);
    }

    /// ADC chains: two 64-bit halves correctly accumulate carry.
    #[test]
    fn adc_two_word_chain() {
        // First: ADD rax, 0xFF  (will not overflow for small values)
        // Second: ADC rdx, 0    (should propagate carry from ADD)
        // For this test we set rax = u64::MAX so ADD wraps.
        let i_add = decode(&[0x48, 0x83, 0xc0, 0x01]); // ADD rax, 1
        let instr_adc = decode(&[0x48, 0x83, 0xd2, 0x00]); // ADC rdx, 0

        let mut ctx_add = ctx64();
        super::lift_add(&i_add, &mut ctx_add).unwrap();
        let mut adc_ctx = ctx64();
        super::lift_adc(&instr_adc, &mut adc_ctx).unwrap();

        let mut state = X86CpuState::with_gp_regs(&[("rax", u64::MAX), ("rdx", 0)]);
        exec_effects(&ctx_add.effects, &mut state);
        // rax should wrap to 0 and CF=1.
        state.assert_reg("rax", 0);
        state.assert_reg("cf", 1);
        exec_effects(&adc_ctx.effects, &mut state);
        // rdx = 0 + 0 + CF(1) = 1.
        state.assert_reg("rdx", 1);
    }

    /// SF is correct for a negative result (high bit set).
    #[test]
    fn add_negative_result_sets_sf() {
        let i = decode(&[0x48, 0x83, 0xc0, 0x01]); // ADD rax, 1
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        // rax = i64::MAX (high bit will flip on +1).
        let mut state = X86CpuState::with_gp_regs(&[("rax", i64::MAX as u64)]);
        exec_effects(&ctx.effects, &mut state);
        // Result = i64::MIN = 0x8000…, SF=1.
        state.assert_reg("sf", 1);
    }

    /// PF: even number of set bits in low byte → PF=1.
    #[test]
    fn add_even_parity_sets_pf() {
        // 0x01 + 0x02 = 0x03 (binary 0b00000011): 2 bits set → PF=1.
        let i = decode(&[0x04, 0x02]); // ADD AL, 2
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0x01)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0x03);
        s.assert_reg("pf", 1);
    }

    /// PF: odd number of set bits → PF=0.
    #[test]
    fn add_odd_parity_clears_pf() {
        // 0x01 + 0x01 = 0x02 (binary 0b00000010): 1 bit set → PF=0.
        let i = decode(&[0x04, 0x01]); // ADD AL, 1
        let mut ctx = ctx64();
        super::lift_add(&i, &mut ctx).unwrap();
        let mut s = X86CpuState::with_gp_regs(&[("al", 0x01)]);
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0x02);
        s.assert_reg("pf", 0);
    }
}
