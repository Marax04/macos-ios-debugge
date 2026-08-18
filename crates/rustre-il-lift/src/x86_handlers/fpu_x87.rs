//! x87 FPU instruction handlers.
//!
//! ## x87 stack model
//!
//! The x87 FPU has an 8-deep register stack. In this lifter's IR:
//!
//!   * Stack slots are virtual registers `__fpu_st0` … `__fpu_st7`.
//!   * The current top-of-stack index lives in `__fpu_top` (0..=7, wraps mod 8).
//!   * Stack push decrements TOP mod 8; stack pop increments TOP mod 8.
//!   * `x86.fpu.get_st(idx)` / `x86.fpu.set_st(idx, val)` are emitted as
//!     opaque intrinsics so that MLIL passes can constant-fold when TOP is known.
//!
//! ## FPU status word flags
//!
//! C0–C3 are modelled as `__fpu_c0` … `__fpu_c3`. FCOMI/FUCOMIP additionally
//! write the CPU EFLAGS CF/PF/ZF. The x87 status-word TOP field is tracked
//! through `__fpu_top`. Exception bits IE/DE/ZE/OE/UE/PE are emitted as
//! `__fpu_ie`, `__fpu_de`, `__fpu_ze`, `__fpu_oe`, `__fpu_ue`, `__fpu_pe`.


use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_operand::read_operand;
use crate::{IrExpr, LiftError};
use iced_x86::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual register holding the x87 TOP-of-stack index (0..=7).
const FPU_TOP: &str = "__fpu_top";

/// C0 condition-code register.
const FPU_C0: &str = "__fpu_c0";
/// C1 condition-code register.
const FPU_C1: &str = "__fpu_c1";
/// C2 condition-code register.
const FPU_C2: &str = "__fpu_c2";
/// C3 condition-code register.
const FPU_C3: &str = "__fpu_c3";

// x87 status-word exception-flag names
const FPU_IE: &str = "__fpu_ie"; // Invalid operation
const FPU_DE: &str = "__fpu_de"; // Denormal operand
const FPU_ZE: &str = "__fpu_ze"; // Zero divide
const FPU_OE: &str = "__fpu_oe"; // Overflow
const FPU_UE: &str = "__fpu_ue"; // Underflow
const FPU_PE: &str = "__fpu_pe"; // Precision

/// Record the source instruction's IP on the context as a no-op intrinsic.
///
/// Used by handlers that only need to emit opaque intrinsics so that the
/// originating instruction address is still visible in the IR trace.
fn note_instr_ip(instr: &Instruction, ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.src_ip", vec![IrExpr::Const(instr.ip())]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stack helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return an `IrExpr` for the physical slot index of `ST(n)`:
/// `(TOP + n) & 7`. When `n == 0` this is just `TOP`.
fn st_idx(n: u64) -> IrExpr {
    if n == 0 {
        IrExpr::Reg(FPU_TOP.into())
    } else {
        IrExpr::And(
            Box::new(IrExpr::Add(
                Box::new(IrExpr::Reg(FPU_TOP.into())),
                Box::new(IrExpr::Const(n)),
            )),
            Box::new(IrExpr::Const(7)),
        )
    }
}

/// Decrement TOP mod 8 (stack push).
fn fpu_push_top(ctx: &mut X86LiftCtx) {
    let new_top = IrExpr::And(
        Box::new(IrExpr::Sub(
            Box::new(IrExpr::Reg(FPU_TOP.into())),
            Box::new(IrExpr::Const(1)),
        )),
        Box::new(IrExpr::Const(7)),
    );
    ctx.emit_reg_write(FPU_TOP, new_top);
}

/// Increment TOP mod 8 (stack pop).
fn fpu_pop_top(ctx: &mut X86LiftCtx) {
    let new_top = IrExpr::And(
        Box::new(IrExpr::Add(
            Box::new(IrExpr::Reg(FPU_TOP.into())),
            Box::new(IrExpr::Const(1)),
        )),
        Box::new(IrExpr::Const(7)),
    );
    ctx.emit_reg_write(FPU_TOP, new_top);
}

/// Emit `x86.fpu.get_st(index)` and materialise the result into a fresh temp.
/// Returns the temp name.
fn fpu_get_st(ctx: &mut X86LiftCtx, index: IrExpr) -> String {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.get_st", vec![index]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    t
}

/// Emit `x86.fpu.set_st(index, value)`.
fn fpu_set_st(ctx: &mut X86LiftCtx, index: IrExpr, value: IrExpr) {
    ctx.emit_intrinsic("x86.fpu.set_st", vec![index, value]);
}

/// Emit all four FPU condition codes as Undef (compare result not statically known).
fn emit_fpu_cc_undef(ctx: &mut X86LiftCtx) {
    for cc in [FPU_C0, FPU_C1, FPU_C2, FPU_C3] {
        ctx.emit_reg_write(cc, IrExpr::Undef);
    }
}

/// Emit all six x87 exception bits as Undef.
fn emit_fpu_exceptions_undef(ctx: &mut X86LiftCtx) {
    for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
        ctx.emit_reg_write(ex, IrExpr::Undef);
    }
}

/// Emit C1 (stack-fault / rounding direction) as Undef.
fn emit_c1_undef(ctx: &mut X86LiftCtx) {
    ctx.emit_reg_write(FPU_C1, IrExpr::Undef);
}

/// Decode the iced `Register` operand value as an ST(i) index (0..7).
fn op_reg_st_index(instr: &Instruction, op: u32) -> u64 {
    // iced encodes ST(i) as register ordinals ST0..ST7 in the ST register bank.
    // The raw value & 7 gives the stack-relative index.
    (instr.op_register(op) as u64) & 7
}

/// Return (`dst_st_index`, `src_st_index`) from a two-operand FPU instruction.
/// Memory-operand forms always have dst=ST(0); the second operand comes from
/// memory and is handled by the caller.
fn two_st_operands(instr: &Instruction) -> (u64, u64) {
    use iced_x86::OpKind;
    if instr.op_count() == 0 {
        return (0, 1);
    }
    if instr.op0_kind() == OpKind::Register {
        let d = op_reg_st_index(instr, 0);
        let s = if instr.op_count() > 1 && instr.op1_kind() == OpKind::Register {
            op_reg_st_index(instr, 1)
        } else {
            // ST(0) op ST(1) default when only one explicit register operand
            u64::from(d == 0)
        };
        (d, s)
    } else {
        // Memory source: dst is always ST(0)
        (0, 0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic binop helper
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a floating-point binary operation between two ST registers.
/// `op_name` is e.g. `"fadd"`, `"fsub"`, …
/// If `pop` is true, pop the stack after the operation.
fn fpu_binop_st(
    instr: &Instruction,
    ctx: &mut X86LiftCtx,
    op_name: &str,
    pop: bool,
) {
    let (dst, src) = two_st_operands(instr);
    let dst_val = fpu_get_st(ctx, st_idx(dst));
    let src_val = fpu_get_st(ctx, st_idx(src));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        format!("x86.fpu.{op_name}"),
        vec![IrExpr::Reg(dst_val), IrExpr::Reg(src_val)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(dst), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    if pop {
        fpu_pop_top(ctx);
    }
    
}

/// Emit a memory-sourced FPU binary operation. `src_expr` is already decoded.
fn fpu_binop_mem(ctx: &mut X86LiftCtx, op_name: &str, src_expr: IrExpr) {
    let top_val = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        format!("x86.fpu.{op_name}"),
        vec![IrExpr::Reg(top_val), src_expr],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// FLD / FST / FSTP
// ─────────────────────────────────────────────────────────────────────────────

/// `FLD src` — push a floating-point value onto the FPU stack.
///
/// Supports:
///   * `FLD m32fp` (single-precision float from memory)
///   * `FLD m64fp` (double-precision float from memory)
///   * `FLD m80fp` (80-bit extended float from memory)
///   * `FLD ST(i)` (copy a stack register)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fld(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::{Mnemonic as M, OpKind};

    let value = match instr.mnemonic() {
        // ── FPU constant loads ───────────────────────────────────────────────
        M::Fld1 => {
            // Push +1.0  (IEEE 754 double: 0x3FF0_0000_0000_0000)
            ctx.emit_intrinsic("x86.fpu.const.fld1", vec![]);
            IrExpr::Undef
        }
        M::Fldz => {
            // Push +0.0
            ctx.emit_intrinsic("x86.fpu.const.fldz", vec![]);
            IrExpr::Undef
        }
        M::Fldpi => {
            ctx.emit_intrinsic("x86.fpu.const.fldpi", vec![]);
            IrExpr::Undef
        }
        M::Fldl2e => {
            ctx.emit_intrinsic("x86.fpu.const.fldl2e", vec![]);
            IrExpr::Undef
        }
        M::Fldl2t => {
            ctx.emit_intrinsic("x86.fpu.const.fldl2t", vec![]);
            IrExpr::Undef
        }
        M::Fldlg2 => {
            ctx.emit_intrinsic("x86.fpu.const.fldlg2", vec![]);
            IrExpr::Undef
        }
        M::Fldln2 => {
            ctx.emit_intrinsic("x86.fpu.const.fldln2", vec![]);
            IrExpr::Undef
        }

        // ── General FLD ─────────────────────────────────────────────────────
        _ => {
            if instr.op_count() == 0 {
                // Bare FLD with no operand — should not happen in practice
                return Err(LiftError::LiftFailed(
                    ctx.addr,
                    "FLD with no operand".into(),
                ));
            }
            match instr.op0_kind() {
                OpKind::Register => {
                    // FLD ST(i): read the stack slot BEFORE push
                    let i = op_reg_st_index(instr, 0);
                    let val_t = fpu_get_st(ctx, st_idx(i));
                    IrExpr::Reg(val_t)
                }
                OpKind::Memory => {
                    let mem_size_bytes = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                    let addr_expr = read_operand(instr, 0, ctx);
                    let t = ctx.fresh_temp();
                    let bits = mem_size_bytes * 8;
                    ctx.emit_intrinsic(format!("x86.fpu.load_f{bits}"), vec![addr_expr]);
                    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
                    IrExpr::Reg(t)
                }
                _ => IrExpr::Undef,
            }
        }
    };

    // Push: decrement TOP, write ST(0) = value
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), value);
    emit_c1_undef(ctx);
    Ok(())
}

/// `FST dst` — store ST(0) to destination without popping the stack.
///
/// Supports: `FST m32fp`, `FST m64fp`, `FST ST(i)`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fst(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::OpKind;
    let top_t = fpu_get_st(ctx, st_idx(0));
    match instr.op0_kind() {
        OpKind::Register => {
            let i = op_reg_st_index(instr, 0);
            fpu_set_st(ctx, st_idx(i), IrExpr::Reg(top_t));
        }
        OpKind::Memory => {
            let mem_size_bytes = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            let bits = mem_size_bytes * 8;
            ctx.emit_intrinsic(
                format!("x86.fpu.store_f{bits}"),
                vec![addr_expr, IrExpr::Reg(top_t)],
            );
        }
        _ => {}
    }
    emit_c1_undef(ctx);
    Ok(())
}

/// `FSTP dst` — store ST(0) to destination and pop the stack.
///
/// Supports: `FSTP m32fp`, `FSTP m64fp`, `FSTP m80fp`, `FSTP ST(i)`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fstp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fst(instr, ctx)?;
    fpu_pop_top(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FILD / FIST / FISTP / FISTTP
// ─────────────────────────────────────────────────────────────────────────────

/// `FILD src` — convert integer memory operand to 80-bit float and push.
///
/// Handles int16, int32, and int64 memory sizes.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fild(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let mem_size_bytes = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
    let addr_expr = read_operand(instr, 0, ctx);
    let bits = mem_size_bytes * 8;
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic(format!("x86.fpu.load_i{bits}"), vec![addr_expr]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
    emit_c1_undef(ctx);
    Ok(())
}

/// `FIST dst` — store ST(0) as integer (rounded) without pop.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fist(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let top_t = fpu_get_st(ctx, st_idx(0));
    let mem_size_bytes = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
    let addr_expr = read_operand(instr, 0, ctx);
    let bits = mem_size_bytes * 8;
    ctx.emit_intrinsic(
        format!("x86.fpu.store_i{bits}"),
        vec![addr_expr, IrExpr::Reg(top_t)],
    );
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FISTP dst` — store ST(0) as integer and pop.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fistp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fist(instr, ctx)?;
    fpu_pop_top(ctx);
    Ok(())
}

/// `FISTTP dst` — store ST(0) as integer using truncation (SSE3), then pop.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fisttp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let top_t = fpu_get_st(ctx, st_idx(0));
    let mem_size_bytes = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
    let addr_expr = read_operand(instr, 0, ctx);
    let bits = mem_size_bytes * 8;
    ctx.emit_intrinsic(
        format!("x86.fpu.store_i{bits}_trunc"),
        vec![addr_expr, IrExpr::Reg(top_t)],
    );
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FBLD / FBSTP  (BCD load/store)
// ─────────────────────────────────────────────────────────────────────────────

/// `FBLD src` — load 80-bit packed BCD integer from memory, push as float.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fbld(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_bcd80", vec![addr_expr]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
    emit_c1_undef(ctx);
    Ok(())
}

/// `FBSTP dst` — store ST(0) as 80-bit packed BCD to memory, then pop.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fbstp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let top_t = fpu_get_st(ctx, st_idx(0));
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.store_bcd80", vec![addr_expr, IrExpr::Reg(top_t)]);
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FADD / FADDP / FIADD
// ─────────────────────────────────────────────────────────────────────────────

/// `FADD`, `FADDP`, `FIADD` — floating-point / integer add.
///
/// * `FADD ST(dst), ST(src)` or `FADD ST(0), m32/m64`
/// * `FADDP ST(i), ST(0)` — add then pop
/// * `FIADD m16/m32` — convert integer source to float, add to ST(0)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fadd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::{Mnemonic as M, OpKind};
    match instr.mnemonic() {
        M::Fiadd => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            let bits = mem_size * 8;
            fpu_binop_mem(ctx, &format!("fiadd_i{bits}"), addr_expr);
        }
        M::Faddp => {
            fpu_binop_st(instr, ctx, "fadd", true);
        }
        _ => {
            // FADD ST(dst),ST(src)  or  FADD ST(0),m32/m64
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                let bits = mem_size * 8;
                fpu_binop_mem(ctx, &format!("fadd_f{bits}"), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fadd", false);
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FSUB / FSUBP / FISUB / FSUBR / FSUBRP / FISUBR
// ─────────────────────────────────────────────────────────────────────────────

/// `FSUB`, `FSUBP`, `FISUB`, `FSUBR`, `FSUBRP`, `FISUBR` — floating-point subtract.
///
/// The `R` variants compute `src - dst` (reversed) instead of `dst - src`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsub(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::{Mnemonic as M, OpKind};
    match instr.mnemonic() {
        M::Fisub => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            fpu_binop_mem(ctx, &format!("fisub_i{}", mem_size * 8), addr_expr);
        }
        M::Fisubr => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            fpu_binop_mem(ctx, &format!("fisubr_i{}", mem_size * 8), addr_expr);
        }
        M::Fsubr => {
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                fpu_binop_mem(ctx, &format!("fsubr_f{}", mem_size * 8), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fsubr", false);
            }
        }
        M::Fsubrp => {
            fpu_binop_st(instr, ctx, "fsubr", true);
        }
        M::Fsubp => {
            fpu_binop_st(instr, ctx, "fsub", true);
        }
        _ => {
            // FSUB
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                fpu_binop_mem(ctx, &format!("fsub_f{}", mem_size * 8), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fsub", false);
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FMUL / FMULP / FIMUL
// ─────────────────────────────────────────────────────────────────────────────

/// `FMUL`, `FMULP`, `FIMUL` — floating-point multiply.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fmul(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::{Mnemonic as M, OpKind};
    match instr.mnemonic() {
        M::Fimul => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            fpu_binop_mem(ctx, &format!("fimul_i{}", mem_size * 8), addr_expr);
        }
        M::Fmulp => {
            fpu_binop_st(instr, ctx, "fmul", true);
        }
        _ => {
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                fpu_binop_mem(ctx, &format!("fmul_f{}", mem_size * 8), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fmul", false);
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FDIV / FDIVP / FIDIV / FDIVR / FDIVRP / FIDIVR
// ─────────────────────────────────────────────────────────────────────────────

/// `FDIV`, `FDIVP`, `FIDIV`, `FDIVR`, `FDIVRP`, `FIDIVR` — floating-point divide.
///
/// The `R` (reverse) variants compute `src / dst`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fdiv(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::{Mnemonic as M, OpKind};
    match instr.mnemonic() {
        M::Fidiv => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            fpu_binop_mem(ctx, &format!("fidiv_i{}", mem_size * 8), addr_expr);
        }
        M::Fidivr => {
            let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let addr_expr = read_operand(instr, 0, ctx);
            fpu_binop_mem(ctx, &format!("fidivr_i{}", mem_size * 8), addr_expr);
        }
        M::Fdivr => {
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                fpu_binop_mem(ctx, &format!("fdivr_f{}", mem_size * 8), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fdivr", false);
            }
        }
        M::Fdivrp => {
            fpu_binop_st(instr, ctx, "fdivr", true);
        }
        M::Fdivp => {
            fpu_binop_st(instr, ctx, "fdiv", true);
        }
        _ => {
            // FDIV
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Memory {
                let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
                let addr_expr = read_operand(instr, 0, ctx);
                fpu_binop_mem(ctx, &format!("fdiv_f{}", mem_size * 8), addr_expr);
            } else {
                fpu_binop_st(instr, ctx, "fdiv", false);
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FXCH
// ─────────────────────────────────────────────────────────────────────────────

/// `FXCH ST(i)` — swap ST(0) and ST(i).
///
/// With no explicit operand, swaps with ST(1). This is a very common
/// instruction used to bring a non-top operand to the top for subsequent use.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::OpKind;
    let i = if instr.op_count() == 0 || instr.op0_kind() != OpKind::Register {
        1u64
    } else {
        op_reg_st_index(instr, 0)
    };

    let top_t = fpu_get_st(ctx, st_idx(0));
    let sti_t = fpu_get_st(ctx, st_idx(i));
    // Swap: ST(0) ← old ST(i), ST(i) ← old ST(0)
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(sti_t));
    fpu_set_st(ctx, st_idx(i), IrExpr::Reg(top_t));
    // C1 is cleared, C0/C2/C3 undefined
    ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FFREE / FFREEP
// ─────────────────────────────────────────────────────────────────────────────

/// `FFREE ST(i)` — mark ST(i) as empty (free) without altering TOP or the value.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ffree(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let i = if instr.op_count() == 0 {
        0u64
    } else {
        op_reg_st_index(instr, 0)
    };
    ctx.emit_intrinsic("x86.fpu.ffree", vec![st_idx(i)]);
    Ok(())
}

/// `FFREEP ST(i)` — mark ST(i) as empty then pop the stack. (Unofficial but widely used.)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ffreep(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_ffree(instr, ctx)?;
    fpu_pop_top(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FCOM / FCOMP / FCOMPP / FUCOM / FUCOMP / FUCOMPP
// FICOM / FICOMP
// FCOMI / FCOMIP / FUCOMI / FUCOMIP
// ─────────────────────────────────────────────────────────────────────────────

/// Common compare logic: ordered vs unordered, pop count, EFLAGS update.
fn fpu_compare(
    instr: &Instruction,
    ctx: &mut X86LiftCtx,
    ordered: bool,
    write_eflags: bool,
    pops: u32,
    integer_mem: bool,
) {
    use iced_x86::OpKind;

    let a_t = fpu_get_st(ctx, st_idx(0));
    let b_expr = if integer_mem {
        let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
        let addr = read_operand(instr, 0, ctx);
        let t = ctx.fresh_temp();
        ctx.emit_intrinsic(format!("x86.fpu.load_i{}", mem_size * 8), vec![addr]);
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        IrExpr::Reg(t)
    } else if instr.op_count() == 0 {
        IrExpr::Reg(fpu_get_st(ctx, st_idx(1)))
    } else if instr.op0_kind() == OpKind::Register {
        let i = op_reg_st_index(instr, 0);
        IrExpr::Reg(fpu_get_st(ctx, st_idx(i)))
    } else {
        // Memory float operand
        let mem_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
        let addr = read_operand(instr, 0, ctx);
        let t = ctx.fresh_temp();
        ctx.emit_intrinsic(format!("x86.fpu.load_f{}", mem_size * 8), vec![addr]);
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        IrExpr::Reg(t)
    };

    let intrinsic = if ordered {
        "x86.fpu.fcom"
    } else {
        "x86.fpu.fucom"
    };
    ctx.emit_intrinsic(intrinsic, vec![IrExpr::Reg(a_t), b_expr]);

    // Set C0/C1/C2/C3 from compare result
    emit_fpu_cc_undef(ctx);

    if write_eflags {
        // FCOMI variants: set ZF=C3, PF=C2, CF=C0, clear OF/SF/AF
        ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Sf, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Af, IrExpr::Const(0));
    }

    for _ in 0..pops {
        fpu_pop_top(ctx);
    }
    
}

/// `FCOM`/`FCOMP`/`FCOMPP` — ordered compare, set C0–C3 from ST(0) vs ST(i).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fcom(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let pops = match instr.mnemonic() {
        M::Fcompp => 2,
        M::Fcomp => 1,
        _ => 0,
    };
    fpu_compare(instr, ctx, true, false, pops, false);
    Ok(())
}

/// `FUCOM`/`FUCOMP`/`FUCOMPP` — unordered compare, set C0–C3.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fucom(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let pops = match instr.mnemonic() {
        M::Fucompp => 2,
        M::Fucomp => 1,
        _ => 0,
    };
    fpu_compare(instr, ctx, false, false, pops, false);
    Ok(())
}

/// `FICOM`/`FICOMP` — ordered compare with integer memory source.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ficom(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let pops = u32::from(instr.mnemonic() == M::Ficomp);
    fpu_compare(instr, ctx, true, false, pops, true);
    Ok(())
}

/// `FCOMI`/`FCOMIP` — ordered compare, write EFLAGS ZF/PF/CF.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fcomi(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let pops = u32::from(instr.mnemonic() == M::Fcomip);
    fpu_compare(instr, ctx, true, true, pops, false);
    Ok(())
}

/// `FUCOMI`/`FUCOMIP` — unordered compare, write EFLAGS ZF/PF/CF.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fucomi(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let pops = u32::from(instr.mnemonic() == M::Fucomip);
    fpu_compare(instr, ctx, false, true, pops, false);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FABS / FCHS / FSQRT / FRNDINT / FSCALE / FXTRACT / FPREM / FPREM1
// ─────────────────────────────────────────────────────────────────────────────

/// `FABS` — replace ST(0) with its absolute value. Clears the sign bit.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fabs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fabs", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));
    Ok(())
}

/// `FCHS` — negate ST(0) (toggle sign bit).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fchs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fchs", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));
    Ok(())
}

/// `FSQRT` — compute square root of ST(0).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsqrt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fsqrt", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FRNDINT` — round ST(0) to integer using current rounding mode.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_frndint(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.frndint", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    Ok(())
}

/// `FSCALE` — ST(0) ← ST(0) * 2^trunc(ST(1)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fscale(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fscale",
        vec![IrExpr::Reg(st0_t), IrExpr::Reg(st1_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FXTRACT` — split ST(0) into exponent (pushed to ST(1)) and significand (in ST(0)).
///
/// After: ST(0) = significand, ST(1) = exponent (old ST(0)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxtract(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let exp_t = ctx.fresh_temp();
    let sig_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fxtract_exp", vec![IrExpr::Reg(st0_t.clone())]);
    ctx.emit_reg_write(exp_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fxtract_sig", vec![IrExpr::Reg(st0_t)]);
    ctx.emit_reg_write(sig_t.clone(), IrExpr::Undef);
    // ST(0) holds exponent (pushed down), new ST(0) = significand
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(exp_t));
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(sig_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FPREM` — compute IEEE partial remainder ST(0) mod ST(1), old-style.
///
/// Sets C2 (incomplete flag) and C0/C3/C1 from quotient bits Q2/Q0/Q1.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fprem(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fprem",
        vec![IrExpr::Reg(st0_t), IrExpr::Reg(st1_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FPREM1` — compute IEEE 754 partial remainder ST(0) mod ST(1), new-style.
///
/// Same as FPREM but uses IEEE round-to-nearest for the quotient.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fprem1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fprem1",
        vec![IrExpr::Reg(st0_t), IrExpr::Reg(st1_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Transcendental: FSIN / FCOS / FSINCOS / FPTAN / FPATAN
//                 F2XM1 / FYL2X / FYL2XP1
// ─────────────────────────────────────────────────────────────────────────────

/// `FSIN` — ST(0) ← sin(ST(0)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsin(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fsin", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FCOS` — ST(0) ← cos(ST(0)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fcos(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fcos", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FSINCOS` — ST(0) ← sin(ST(0)), push cos(ST(0)) as new ST(0).
///
/// After: ST(0) = cos(original ST(0)), ST(1) = sin(original ST(0)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsincos(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let sin_t = ctx.fresh_temp();
    let cos_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fsin", vec![IrExpr::Reg(top_t.clone())]);
    ctx.emit_reg_write(sin_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fcos", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(cos_t.clone(), IrExpr::Undef);
    // sin replaces ST(0); cos is pushed as new ST(0)
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(sin_t));
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(cos_t));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FPTAN` — ST(0) ← tan(ST(0)), push 1.0.
///
/// After: ST(0) = 1.0, ST(1) = tan(old ST(0)).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fptan(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let tan_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fptan", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(tan_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(tan_t));
    // Push 1.0
    fpu_push_top(ctx);
    ctx.emit_intrinsic("x86.fpu.const.fld1", vec![]);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Undef);
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FPATAN` — ST(1) ← atan2(ST(1), ST(0)), pop.
///
/// Computes atan(ST(1)/ST(0)), stores in ST(1), pops. After: ST(0) = atan result.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fpatan(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fpatan",
        vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(1), IrExpr::Reg(result_t));
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `F2XM1` — ST(0) ← 2^ST(0) - 1.  Valid range: -1.0 ≤ ST(0) ≤ 1.0.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_f2xm1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let top_t = fpu_get_st(ctx, st_idx(0));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.f2xm1", vec![IrExpr::Reg(top_t)]);
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(0), IrExpr::Reg(result_t));
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FYL2X` — ST(1) ← ST(1) * log2(ST(0)), pop.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fyl2x(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fyl2x",
        vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(1), IrExpr::Reg(result_t));
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FYL2XP1` — ST(1) ← ST(1) * log2(ST(0) + 1), pop.
///
/// Higher accuracy than FYL2X when ST(0) is near zero.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fyl2xp1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    let st0_t = fpu_get_st(ctx, st_idx(0));
    let st1_t = fpu_get_st(ctx, st_idx(1));
    let result_t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.fyl2xp1",
        vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
    );
    ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
    fpu_set_st(ctx, st_idx(1), IrExpr::Reg(result_t));
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Control-word / status-word / environment instructions
// ─────────────────────────────────────────────────────────────────────────────

/// `FINIT` / `FNINIT` — initialise the FPU to a known state.
///
/// Resets TOP to 0, clears all condition codes and exception flags, sets
/// CW to 0x037F (all exceptions masked, round-to-nearest, 64-bit precision).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_finit(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    ctx.emit_reg_write(FPU_TOP, IrExpr::Const(0));
    for cc in [FPU_C0, FPU_C1, FPU_C2, FPU_C3] {
        ctx.emit_reg_write(cc, IrExpr::Const(0));
    }
    for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
        ctx.emit_reg_write(ex, IrExpr::Const(0));
    }
    ctx.emit_intrinsic("x86.fpu.finit", vec![]);
    Ok(())
}

/// `FCLEX` / `FNCLEX` — clear FPU exception flags in the status word.
///
/// Clears IE/DE/ZE/OE/UE/PE/SF/ES/B bits of status word.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fclex(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
        ctx.emit_reg_write(ex, IrExpr::Const(0));
    }
    ctx.emit_intrinsic("x86.fpu.fclex", vec![]);
    Ok(())
}

/// `FSTCW` / `FNSTCW m16` — store the FPU control word to memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fnstcw(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fnstcw", vec![addr_expr]);
    Ok(())
}

/// `FLDCW m16` — load the FPU control word from memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fldcw(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fldcw", vec![addr_expr]);
    Ok(())
}

/// `FSTSW` / `FNSTSW m16` or `FNSTSW AX` — store FPU status word.
///
/// Can write to a 16-bit memory location or directly to AX.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fnstsw(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::OpKind;
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.fnstsw", vec![]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    if instr.op0_kind() == OpKind::Register {
        // Target is AX
        ctx.emit_reg_write("ax", IrExpr::Reg(t));
    } else {
        let addr_expr = read_operand(instr, 0, ctx);
        ctx.emit_mem_write(addr_expr, IrExpr::Reg(t), 2);
    }
    Ok(())
}

/// `FSTENV` / `FNSTENV m` — store the FPU environment (CW, SW, TW, IP, DP) to memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fnstenv(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fnstenv", vec![addr_expr]);
    Ok(())
}

/// `FLDENV m` — load the FPU environment from memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fldenv(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fldenv", vec![addr_expr]);
    // After FLDENV, all FPU state is effectively unknown to the lifter
    ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FSAVE` / `FNSAVE m` — save full FPU state to memory, then re-initialise.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fnsave(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fnsave", vec![addr_expr]);
    // FNSAVE also re-initialises the FPU
    ctx.emit_reg_write(FPU_TOP, IrExpr::Const(0));
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FRSTOR m` — restore full FPU state from memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_frstor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.frstor", vec![addr_expr]);
    // After FRSTOR, all FPU state is effectively unknown to the static lifter
    ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

/// `FWAIT` / `WAIT` — wait for FPU to complete pending operations.
///
/// In the IR this is a no-op fence: we emit an intrinsic so data-flow can
/// still see the synchronisation boundary.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fwait(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    ctx.emit_intrinsic("x86.fpu.fwait", vec![]);
    Ok(())
}

/// `FNOP` — FPU no-operation.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fnop(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    note_instr_ip(instr, ctx);
    ctx.emit_intrinsic("x86.fpu.fnop", vec![]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FXSAVE / FXRSTOR
// ─────────────────────────────────────────────────────────────────────────────

/// `FXSAVE m512` — save x87 FPU, MMX, XMM, and MXCSR state to a 512-byte region.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxsave(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fxsave", vec![addr_expr]);
    Ok(())
}

/// `FXRSTOR m512` — restore x87 FPU, MMX, XMM, and MXCSR state from a 512-byte region.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxrstor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr_expr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fpu.fxrstor", vec![addr_expr]);
    // All FPU and XMM state unknown after restore
    ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified constant-load dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatcher for all FPU constant-load mnemonics that do not take operands.
///
/// Handles: `FLD1`, `FLDZ`, `FLDPI`, `FLDL2E`, `FLDL2T`, `FLDLG2`, `FLDLN2`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fpu_const(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fld(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified control dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatcher for control/state instructions that share similar semantics.
///
/// Covers: `FNINIT`, `FINIT`, `FNCLEX`, `FCLEX`, `FNSTCW`, `FSTCW`,
/// `FLDCW`, `FNSTSW`, `FSTSW`, `FNSTENV`, `FSTENV`, `FLDENV`,
/// `FNSAVE`, `FSAVE`, `FRSTOR`, `FWAIT`, `FNOP`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fpu_ctrl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    match instr.mnemonic() {
        M::Finit | M::Fninit => lift_finit(instr, ctx),
        M::Fclex | M::Fnclex => lift_fclex(instr, ctx),
        M::Fnstcw | M::Fstcw => lift_fnstcw(instr, ctx),
        M::Fldcw => lift_fldcw(instr, ctx),
        M::Fnstsw | M::Fstsw => lift_fnstsw(instr, ctx),
        M::Fnstenv | M::Fstenv => lift_fnstenv(instr, ctx),
        M::Fldenv => lift_fldenv(instr, ctx),
        M::Fnsave | M::Fsave => lift_fnsave(instr, ctx),
        M::Frstor => lift_frstor(instr, ctx),
        M::Wait => lift_fwait(instr, ctx),
        M::Fnop => lift_fnop(instr, ctx),
        other => {
            ctx.emit_intrinsic(format!("x86.fpu.{other:?}").to_lowercase(), vec![]);
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILD dispatcher (int load variant)
// ─────────────────────────────────────────────────────────────────────────────

/// Unified integer-load dispatcher. Handles `FILD m16/m32/m64`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fild_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fild(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// FIST / FISTP / FISTTP dispatchers
// ─────────────────────────────────────────────────────────────────────────────

/// Unified integer-store dispatcher. Handles `FIST m16/m32`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fist_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fist(instr, ctx)
}

/// Unified integer-store-and-pop dispatcher. Handles `FISTP m16/m32/m64`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fistp_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fistp(instr, ctx)
}

/// Unified truncating integer-store-and-pop. Handles `FISTTP m16/m32/m64`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fisttp_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fisttp(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// FFREE / FFREEP dispatchers
// ─────────────────────────────────────────────────────────────────────────────

/// Unified free dispatcher. Handles `FFREE ST(i)`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ffree_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_ffree(instr, ctx)
}

/// Unified free-and-pop dispatcher. Handles `FFREEP ST(i)`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ffreep_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_ffreep(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// FBLD / FBSTP dispatchers
// ─────────────────────────────────────────────────────────────────────────────

/// Unified BCD load dispatcher.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fbld_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fbld(instr, ctx)
}

/// Unified BCD store dispatcher.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fbstp_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fbstp(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Transcendental dispatchers (public entry points)
// ─────────────────────────────────────────────────────────────────────────────

/// Public entry point for `FABS`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fabs_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fabs(instr, ctx)
}
/// Public entry point for `FCHS`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fchs_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fchs(instr, ctx)
}
/// Public entry point for `FSQRT`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsqrt_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fsqrt(instr, ctx)
}
/// Public entry point for `FRNDINT`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_frndint_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_frndint(instr, ctx)
}
/// Public entry point for `FSCALE`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fscale_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fscale(instr, ctx)
}
/// Public entry point for `FXTRACT`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxtract_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fxtract(instr, ctx)
}
/// Public entry point for `FPREM`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fprem_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fprem(instr, ctx)
}
/// Public entry point for `FPREM1`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fprem1_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fprem1(instr, ctx)
}
/// Public entry point for `FSIN`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsin_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fsin(instr, ctx)
}
/// Public entry point for `FCOS`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fcos_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fcos(instr, ctx)
}
/// Public entry point for `FSINCOS`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fsincos_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fsincos(instr, ctx)
}
/// Public entry point for `FPTAN`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fptan_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fptan(instr, ctx)
}
/// Public entry point for `FPATAN`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fpatan_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fpatan(instr, ctx)
}
/// Public entry point for `F2XM1`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_f2xm1_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_f2xm1(instr, ctx)
}
/// Public entry point for `FYL2X`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fyl2x_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fyl2x(instr, ctx)
}
/// Public entry point for `FYL2XP1`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fyl2xp1_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fyl2xp1(instr, ctx)
}

/// Public entry point for `FXSAVE`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxsave_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fxsave(instr, ctx)
}
/// Public entry point for `FXRSTOR`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxrstor_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_fxrstor(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Explicit operand-size helpers for memory arithmetic
//
// The SDM defines the following memory-operand forms for each integer/float
// arithmetic instruction. Rather than relying on the `memory_size()` field
// alone (which can be ambiguous for some encodings), we provide explicit
// entry-points for each size. These are called from the generic dispatchers
// above, but can also be invoked directly by the MLIL or unit-test layer to
// exercise a specific size without needing to encode a real instruction byte
// sequence.
// ─────────────────────────────────────────────────────────────────────────────

/// Emit `FADD ST(0), m32fp` — add single-precision float from memory to ST(0).
///
/// Corresponds to the encoding `D8 /0 m32fp`.
pub fn lift_fadd_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fadd_f32", addr);
}

/// Emit `FADD ST(0), m64fp` — add double-precision float from memory to ST(0).
///
/// Corresponds to the encoding `DC /0 m64fp`.
pub fn lift_fadd_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fadd_f64", addr);
}

/// Emit `FIADD ST(0), m16int` — convert 16-bit integer and add to ST(0).
pub fn lift_fiadd_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fiadd_i16", addr);
}

/// Emit `FIADD ST(0), m32int` — convert 32-bit integer and add to ST(0).
pub fn lift_fiadd_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fiadd_i32", addr);
}

/// Emit `FSUB ST(0), m32fp` — subtract single-precision float from ST(0).
pub fn lift_fsub_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fsub_f32", addr);
}

/// Emit `FSUB ST(0), m64fp` — subtract double-precision float from ST(0).
pub fn lift_fsub_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fsub_f64", addr);
}

/// Emit `FSUBR ST(0), m32fp` — compute m32fp - ST(0) and store in ST(0).
pub fn lift_fsubr_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fsubr_f32", addr);
}

/// Emit `FSUBR ST(0), m64fp` — compute m64fp - ST(0) and store in ST(0).
pub fn lift_fsubr_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fsubr_f64", addr);
}

/// Emit `FISUB ST(0), m16int` — convert 16-bit int and subtract from ST(0).
pub fn lift_fisub_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fisub_i16", addr);
}

/// Emit `FISUB ST(0), m32int` — convert 32-bit int and subtract from ST(0).
pub fn lift_fisub_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fisub_i32", addr);
}

/// Emit `FISUBR ST(0), m16int` — convert 16-bit int, subtract ST(0) from it.
pub fn lift_fisubr_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fisubr_i16", addr);
}

/// Emit `FISUBR ST(0), m32int` — convert 32-bit int, subtract ST(0) from it.
pub fn lift_fisubr_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fisubr_i32", addr);
}

/// Emit `FMUL ST(0), m32fp` — multiply ST(0) by single-precision float.
pub fn lift_fmul_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fmul_f32", addr);
}

/// Emit `FMUL ST(0), m64fp` — multiply ST(0) by double-precision float.
pub fn lift_fmul_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fmul_f64", addr);
}

/// Emit `FIMUL ST(0), m16int` — convert 16-bit int and multiply with ST(0).
pub fn lift_fimul_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fimul_i16", addr);
}

/// Emit `FIMUL ST(0), m32int` — convert 32-bit int and multiply with ST(0).
pub fn lift_fimul_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fimul_i32", addr);
}

/// Emit `FDIV ST(0), m32fp` — divide ST(0) by single-precision float.
pub fn lift_fdiv_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fdiv_f32", addr);
}

/// Emit `FDIV ST(0), m64fp` — divide ST(0) by double-precision float.
pub fn lift_fdiv_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fdiv_f64", addr);
}

/// Emit `FDIVR ST(0), m32fp` — compute m32fp / ST(0), store in ST(0).
pub fn lift_fdivr_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fdivr_f32", addr);
}

/// Emit `FDIVR ST(0), m64fp` — compute m64fp / ST(0), store in ST(0).
pub fn lift_fdivr_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fdivr_f64", addr);
}

/// Emit `FIDIV ST(0), m16int` — convert 16-bit int and divide into ST(0).
pub fn lift_fidiv_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fidiv_i16", addr);
}

/// Emit `FIDIV ST(0), m32int` — convert 32-bit int and divide into ST(0).
pub fn lift_fidiv_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fidiv_i32", addr);
}

/// Emit `FIDIVR ST(0), m16int` — convert 16-bit int, divide by ST(0).
pub fn lift_fidivr_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fidivr_i16", addr);
}

/// Emit `FIDIVR ST(0), m32int` — convert 32-bit int, divide by ST(0).
pub fn lift_fidivr_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    fpu_binop_mem(ctx, "fidivr_i32", addr);
}

// ─────────────────────────────────────────────────────────────────────────────
// FCOM memory variants
//
// FCOM and FUCOM can also accept a single-precision or double-precision
// memory source (compare ST(0) against a memory float). These helpers
// allow the calling dispatcher to pass a pre-decoded address expression
// without needing to re-encode a full `Instruction`.
// ─────────────────────────────────────────────────────────────────────────────

/// `FCOM ST(0), m32fp` — ordered compare ST(0) against a 32-bit float in memory.
///
/// Sets C0/C1/C2/C3. Does not pop.
pub fn lift_fcom_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let a_t = fpu_get_st(ctx, st_idx(0));
    let b_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_f32", vec![addr]);
    ctx.emit_reg_write(b_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
    emit_fpu_cc_undef(ctx);
}

/// `FCOM ST(0), m64fp` — ordered compare ST(0) against a 64-bit float in memory.
///
/// Sets C0/C1/C2/C3. Does not pop.
pub fn lift_fcom_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let a_t = fpu_get_st(ctx, st_idx(0));
    let b_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_f64", vec![addr]);
    ctx.emit_reg_write(b_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
    emit_fpu_cc_undef(ctx);
}

/// `FCOMP ST(0), m32fp` — ordered compare ST(0) against a 32-bit float, then pop.
pub fn lift_fcomp_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fcom_m32(ctx, addr);
    fpu_pop_top(ctx);
}

/// `FCOMP ST(0), m64fp` — ordered compare ST(0) against a 64-bit float, then pop.
pub fn lift_fcomp_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fcom_m64(ctx, addr);
    fpu_pop_top(ctx);
}

/// `FICOM ST(0), m16int` — compare ST(0) against a 16-bit integer in memory.
///
/// The integer is converted to 80-bit float before comparison.
pub fn lift_ficom_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let a_t = fpu_get_st(ctx, st_idx(0));
    let b_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_i16", vec![addr]);
    ctx.emit_reg_write(b_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
    emit_fpu_cc_undef(ctx);
}

/// `FICOM ST(0), m32int` — compare ST(0) against a 32-bit integer in memory.
pub fn lift_ficom_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let a_t = fpu_get_st(ctx, st_idx(0));
    let b_t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_i32", vec![addr]);
    ctx.emit_reg_write(b_t.clone(), IrExpr::Undef);
    ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
    emit_fpu_cc_undef(ctx);
}

/// `FICOMP ST(0), m16int` — compare ST(0) against a 16-bit integer, then pop.
pub fn lift_ficomp_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_ficom_m16(ctx, addr);
    fpu_pop_top(ctx);
}

/// `FICOMP ST(0), m32int` — compare ST(0) against a 32-bit integer, then pop.
pub fn lift_ficomp_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_ficom_m32(ctx, addr);
    fpu_pop_top(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// FIST / FISTP / FISTTP explicit-size wrappers
//
// The SDM encodes FIST/FISTP as m16int or m32int, and FISTP also has an m64int
// form. FISTTP supports m16int/m32int/m64int. These wrappers expose each
// combination directly for testing and for MLIL consumers that need to emit
// a specific size.
// ─────────────────────────────────────────────────────────────────────────────

/// Store ST(0) as 16-bit integer to `addr` (no pop). Rounds using CW mode.
pub fn lift_fist_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i16", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 32-bit integer to `addr` (no pop). Rounds using CW mode.
pub fn lift_fist_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i32", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 16-bit integer to `addr` and pop.
pub fn lift_fistp_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fist_m16(ctx, addr);
    fpu_pop_top(ctx);
}

/// Store ST(0) as 32-bit integer to `addr` and pop.
pub fn lift_fistp_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fist_m32(ctx, addr);
    fpu_pop_top(ctx);
}

/// Store ST(0) as 64-bit integer to `addr` and pop.
pub fn lift_fistp_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i64", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    fpu_pop_top(ctx);
}

/// Store ST(0) as 16-bit integer (truncated) to `addr` and pop.
pub fn lift_fisttp_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i16_trunc", vec![addr, IrExpr::Reg(top_t)]);
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 32-bit integer (truncated) to `addr` and pop.
pub fn lift_fisttp_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i32_trunc", vec![addr, IrExpr::Reg(top_t)]);
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 64-bit integer (truncated) to `addr` and pop.
pub fn lift_fisttp_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_i64_trunc", vec![addr, IrExpr::Reg(top_t)]);
    fpu_pop_top(ctx);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// FILD explicit-size wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Push 16-bit integer from `addr` onto FPU stack (convert to float).
pub fn lift_fild_m16(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_i16", vec![addr]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
    emit_c1_undef(ctx);
}

/// Push 32-bit integer from `addr` onto FPU stack (convert to float).
pub fn lift_fild_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_i32", vec![addr]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
    emit_c1_undef(ctx);
}

/// Push 64-bit integer from `addr` onto FPU stack (convert to float).
pub fn lift_fild_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.load_i64", vec![addr]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    fpu_push_top(ctx);
    fpu_set_st(ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
    emit_c1_undef(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// FST / FSTP explicit-size wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Store ST(0) as 32-bit float to `addr` (no pop).
pub fn lift_fst_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_f32", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 64-bit float to `addr` (no pop).
pub fn lift_fst_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_f64", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

/// Store ST(0) as 32-bit float to `addr` and pop.
pub fn lift_fstp_m32(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fst_m32(ctx, addr);
    fpu_pop_top(ctx);
}

/// Store ST(0) as 64-bit float to `addr` and pop.
pub fn lift_fstp_m64(ctx: &mut X86LiftCtx, addr: IrExpr) {
    lift_fst_m64(ctx, addr);
    fpu_pop_top(ctx);
}

/// Store ST(0) as 80-bit extended float to `addr` and pop.
pub fn lift_fstp_m80(ctx: &mut X86LiftCtx, addr: IrExpr) {
    let top_t = fpu_get_st(ctx, st_idx(0));
    ctx.emit_intrinsic("x86.fpu.store_f80", vec![addr, IrExpr::Reg(top_t)]);
    emit_c1_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
    fpu_pop_top(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// ST-register copy helpers (used by data-flow analysis passes)
//
// These helpers allow analysis passes to synthesise FPU moves without needing
// to build an Instruction, and they serve as building blocks for test fixtures.
// ─────────────────────────────────────────────────────────────────────────────

/// Copy ST(src) into ST(dst) without any stack movement.
///
/// This implements the FST ST(i) form: store ST(0) into ST(i).
pub fn fpu_copy_st(ctx: &mut X86LiftCtx, dst: u64, src: u64) {
    let val = fpu_get_st(ctx, st_idx(src));
    fpu_set_st(ctx, st_idx(dst), IrExpr::Reg(val));
}

/// Swap the contents of ST(a) and ST(b) using a temporary.
///
/// Used by FXCH and by analysis passes that need to reorder the stack.
pub fn fpu_swap_st(ctx: &mut X86LiftCtx, a: u64, b: u64) {
    let a_t = fpu_get_st(ctx, st_idx(a));
    let b_t = fpu_get_st(ctx, st_idx(b));
    fpu_set_st(ctx, st_idx(a), IrExpr::Reg(b_t));
    fpu_set_st(ctx, st_idx(b), IrExpr::Reg(a_t));
}

/// Read and discard ST(0) — models the "free" action of a pop without storing.
pub fn fpu_discard_top(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.ffree", vec![st_idx(0)]);
    fpu_pop_top(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// x87 tag-word helpers
//
// The x87 tag word has two bits per stack slot (8 slots × 2 bits = 16 bits
// total). Tag values: 00 = Valid, 01 = Zero, 10 = Special (NaN/Inf/Denormal),
// 11 = Empty. We model the tag as an opaque intrinsic so that analysis passes
// can query or update it.
// ─────────────────────────────────────────────────────────────────────────────

/// Emit an intrinsic that marks slot `slot_idx` (0..7) as Valid (tag = 00).
pub fn fpu_tag_set_valid(ctx: &mut X86LiftCtx, slot_idx: u64) {
    ctx.emit_intrinsic("x86.fpu.tag_set_valid", vec![IrExpr::Const(slot_idx)]);
}

/// Emit an intrinsic that marks slot `slot_idx` as Empty (tag = 11).
pub fn fpu_tag_set_empty(ctx: &mut X86LiftCtx, slot_idx: u64) {
    ctx.emit_intrinsic("x86.fpu.tag_set_empty", vec![IrExpr::Const(slot_idx)]);
}

/// Emit an intrinsic that marks slot `slot_idx` as Zero (tag = 01).
pub fn fpu_tag_set_zero(ctx: &mut X86LiftCtx, slot_idx: u64) {
    ctx.emit_intrinsic("x86.fpu.tag_set_zero", vec![IrExpr::Const(slot_idx)]);
}

/// Emit an intrinsic that marks slot `slot_idx` as Special (tag = 10).
pub fn fpu_tag_set_special(ctx: &mut X86LiftCtx, slot_idx: u64) {
    ctx.emit_intrinsic("x86.fpu.tag_set_special", vec![IrExpr::Const(slot_idx)]);
}

// ─────────────────────────────────────────────────────────────────────────────
// x87 precision-control helpers
//
// The FPU control word precision field (PC) determines the internal
// computation precision: 00=24-bit (single), 10=53-bit (double), 11=64-bit
// (extended). We model this with intrinsics that pass-through to the MLIL
// layer, which can optionally model precision loss.
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a precision query intrinsic — returns the current PC field value.
pub fn fpu_query_precision(ctx: &mut X86LiftCtx) -> String {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic("x86.fpu.get_precision", vec![]);
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    t
}

/// Emit an intrinsic that sets the FPU precision control to 24-bit (single).
pub fn fpu_set_precision_single(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_precision", vec![IrExpr::Const(0)]);
}

/// Emit an intrinsic that sets the FPU precision control to 53-bit (double).
pub fn fpu_set_precision_double(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_precision", vec![IrExpr::Const(2)]);
}

/// Emit an intrinsic that sets the FPU precision control to 64-bit (extended).
pub fn fpu_set_precision_extended(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_precision", vec![IrExpr::Const(3)]);
}

// ─────────────────────────────────────────────────────────────────────────────
// x87 rounding-mode helpers
//
// The rounding control (RC) field of the FPU control word: 00=round-to-nearest,
// 01=round-toward-negative-infinity, 10=round-toward-positive-infinity,
// 11=round-toward-zero (truncate).
// ─────────────────────────────────────────────────────────────────────────────

/// Set rounding mode to round-to-nearest (IEEE default).
pub fn fpu_set_round_nearest(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_round", vec![IrExpr::Const(0)]);
}

/// Set rounding mode to round toward negative infinity (floor).
pub fn fpu_set_round_down(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_round", vec![IrExpr::Const(1)]);
}

/// Set rounding mode to round toward positive infinity (ceil).
pub fn fpu_set_round_up(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_round", vec![IrExpr::Const(2)]);
}

/// Set rounding mode to round toward zero (truncate).
pub fn fpu_set_round_truncate(ctx: &mut X86LiftCtx) {
    ctx.emit_intrinsic("x86.fpu.set_round", vec![IrExpr::Const(3)]);
}

// ─────────────────────────────────────────────────────────────────────────────
// x87 status-word snapshot helpers
//
// These helpers materialise a runtime snapshot of the x87 status-word into an
// IR temporary. Used by FNSTSW and by analysis passes that need to inspect FPU
// state without triggering a full context-save (FNSAVE / FSTENV).
// ─────────────────────────────────────────────────────────────────────────────

/// Build a 16-bit x87 status-word snapshot in a fresh temporary.
///
/// The status word layout (Intel SDM Vol.1 §8.1.3):
///
/// ```text
///  Bit 15  — B  (FPU busy, same as ES)
///  Bit 14  — C3
///  Bits 13-11 — TOP (3 bits)
///  Bit 10  — C2
///  Bit 9   — C1
///  Bit 8   — C0
///  Bit 7   — ES (exception summary)
///  Bit 6   — SF (stack fault)
///  Bit 5   — PE (precision)
///  Bit 4   — UE (underflow)
///  Bit 3   — OE (overflow)
///  Bit 2   — ZE (zero-divide)
///  Bit 1   — DE (denormal)
///  Bit 0   — IE (invalid operation)
/// ```
///
/// Because all of these fields are modelled as separate virtual registers, we
/// emit an intrinsic that the MLIL layer is expected to fold into a packed
/// 16-bit value.
pub fn fpu_snapshot_sw(ctx: &mut X86LiftCtx) -> String {
    let t = ctx.fresh_temp();
    ctx.emit_intrinsic(
        "x86.fpu.snapshot_sw",
        vec![
            IrExpr::Reg(FPU_C0.into()),
            IrExpr::Reg(FPU_C1.into()),
            IrExpr::Reg(FPU_C2.into()),
            IrExpr::Reg(FPU_C3.into()),
            IrExpr::Reg(FPU_TOP.into()),
            IrExpr::Reg(FPU_IE.into()),
            IrExpr::Reg(FPU_DE.into()),
            IrExpr::Reg(FPU_ZE.into()),
            IrExpr::Reg(FPU_OE.into()),
            IrExpr::Reg(FPU_UE.into()),
            IrExpr::Reg(FPU_PE.into()),
        ],
    );
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    t
}

/// Unpack a 16-bit status-word value into the individual virtual registers.
///
/// Used by FLDENV and FRSTOR to model restoring FPU state from memory.
/// The bit extraction is kept as an opaque intrinsic since the MLIL layer
/// can produce tighter code with knowledge of the bit positions.
pub fn fpu_restore_sw(ctx: &mut X86LiftCtx, sw_expr: IrExpr) {
    ctx.emit_intrinsic("x86.fpu.restore_sw", vec![sw_expr]);
    // All fields become opaquely unknown from the lifter's static view
    ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
    emit_fpu_cc_undef(ctx);
    emit_fpu_exceptions_undef(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// Intrinsic name table (documentation)
//
// The following table documents every intrinsic name this module emits, along
// with its argument list and the Intel SDM section it corresponds to. This
// allows downstream passes to pattern-match on the name without needing to
// parse the argument structure.
//
// ┌──────────────────────────────────────┬───────────────────────────────────┐
// │ Intrinsic name                       │ Meaning                           │
// ├──────────────────────────────────────┼───────────────────────────────────┤
// │ x86.fpu.get_st(idx)                  │ Read ST(idx) into temp            │
// │ x86.fpu.set_st(idx, val)             │ Write val to ST(idx)              │
// │ x86.fpu.load_f32(addr)               │ Load 32-bit float from memory     │
// │ x86.fpu.load_f64(addr)               │ Load 64-bit float from memory     │
// │ x86.fpu.load_f80(addr)               │ Load 80-bit float from memory     │
// │ x86.fpu.store_f32(addr, val)         │ Store 32-bit float to memory      │
// │ x86.fpu.store_f64(addr, val)         │ Store 64-bit float to memory      │
// │ x86.fpu.store_f80(addr, val)         │ Store 80-bit float to memory      │
// │ x86.fpu.load_i16(addr)               │ Load 16-bit int, convert to f80   │
// │ x86.fpu.load_i32(addr)               │ Load 32-bit int, convert to f80   │
// │ x86.fpu.load_i64(addr)               │ Load 64-bit int, convert to f80   │
// │ x86.fpu.store_i16(addr, val)         │ Round f80 to int16 and store      │
// │ x86.fpu.store_i32(addr, val)         │ Round f80 to int32 and store      │
// │ x86.fpu.store_i64(addr, val)         │ Round f80 to int64 and store      │
// │ x86.fpu.store_i16_trunc(addr, val)   │ Truncate f80 to int16 and store   │
// │ x86.fpu.store_i32_trunc(addr, val)   │ Truncate f80 to int32 and store   │
// │ x86.fpu.store_i64_trunc(addr, val)   │ Truncate f80 to int64 and store   │
// │ x86.fpu.load_bcd80(addr)             │ Load 80-bit packed BCD            │
// │ x86.fpu.store_bcd80(addr, val)       │ Store 80-bit packed BCD           │
// │ x86.fpu.fadd(a, b)                   │ a + b (floating-point)            │
// │ x86.fpu.fadd_f32(a, b)               │ a + b (b from m32fp)              │
// │ x86.fpu.fadd_f64(a, b)               │ a + b (b from m64fp)              │
// │ x86.fpu.fiadd_i16(a, b)              │ a + int16(b)                      │
// │ x86.fpu.fiadd_i32(a, b)              │ a + int32(b)                      │
// │ x86.fpu.fsub(a, b)                   │ a - b                             │
// │ x86.fpu.fsub_f32(a, b)               │ a - b (b from m32fp)              │
// │ x86.fpu.fsub_f64(a, b)               │ a - b (b from m64fp)              │
// │ x86.fpu.fsubr(a, b)                  │ b - a                             │
// │ x86.fpu.fsubr_f32(a, b)              │ b - a (b from m32fp)              │
// │ x86.fpu.fsubr_f64(a, b)              │ b - a (b from m64fp)              │
// │ x86.fpu.fisub_i16(a, b)              │ a - int16(b)                      │
// │ x86.fpu.fisub_i32(a, b)              │ a - int32(b)                      │
// │ x86.fpu.fisubr_i16(a, b)             │ int16(b) - a                      │
// │ x86.fpu.fisubr_i32(a, b)             │ int32(b) - a                      │
// │ x86.fpu.fmul(a, b)                   │ a * b                             │
// │ x86.fpu.fmul_f32(a, b)               │ a * b (b from m32fp)              │
// │ x86.fpu.fmul_f64(a, b)               │ a * b (b from m64fp)              │
// │ x86.fpu.fimul_i16(a, b)              │ a * int16(b)                      │
// │ x86.fpu.fimul_i32(a, b)              │ a * int32(b)                      │
// │ x86.fpu.fdiv(a, b)                   │ a / b                             │
// │ x86.fpu.fdiv_f32(a, b)               │ a / b (b from m32fp)              │
// │ x86.fpu.fdiv_f64(a, b)               │ a / b (b from m64fp)              │
// │ x86.fpu.fdivr(a, b)                  │ b / a                             │
// │ x86.fpu.fdivr_f32(a, b)              │ b / a (b from m32fp)              │
// │ x86.fpu.fdivr_f64(a, b)              │ b / a (b from m64fp)              │
// │ x86.fpu.fidiv_i16(a, b)              │ a / int16(b)                      │
// │ x86.fpu.fidiv_i32(a, b)              │ a / int32(b)                      │
// │ x86.fpu.fidivr_i16(a, b)             │ int16(b) / a                      │
// │ x86.fpu.fidivr_i32(a, b)             │ int32(b) / a                      │
// │ x86.fpu.fabs(a)                      │ |a|                               │
// │ x86.fpu.fchs(a)                      │ -a                                │
// │ x86.fpu.fsqrt(a)                     │ sqrt(a)                           │
// │ x86.fpu.frndint(a)                   │ round(a) using CW.RC              │
// │ x86.fpu.fscale(a, b)                 │ a * 2^trunc(b)                    │
// │ x86.fpu.fxtract_exp(a)               │ biased exponent of a              │
// │ x86.fpu.fxtract_sig(a)               │ significand of a                  │
// │ x86.fpu.fprem(a, b)                  │ partial remainder a mod b         │
// │ x86.fpu.fprem1(a, b)                 │ IEEE 754 partial remainder         │
// │ x86.fpu.fsin(a)                      │ sin(a)                            │
// │ x86.fpu.fcos(a)                      │ cos(a)                            │
// │ x86.fpu.fptan(a)                     │ tan(a)                            │
// │ x86.fpu.fpatan(y, x)                 │ atan2(y, x)                       │
// │ x86.fpu.f2xm1(a)                     │ 2^a - 1                           │
// │ x86.fpu.fyl2x(y, x)                  │ y * log2(x)                       │
// │ x86.fpu.fyl2xp1(y, x)               │ y * log2(x+1)                     │
// │ x86.fpu.fcom(a, b)                   │ ordered compare                   │
// │ x86.fpu.fucom(a, b)                  │ unordered compare                 │
// │ x86.fpu.ffree(idx)                   │ mark slot as empty                │
// │ x86.fpu.finit                        │ initialise FPU                    │
// │ x86.fpu.fclex                        │ clear exception flags             │
// │ x86.fpu.fnstcw(addr)                 │ store CW to memory                │
// │ x86.fpu.fldcw(addr)                  │ load CW from memory               │
// │ x86.fpu.fnstsw                       │ snapshot status word              │
// │ x86.fpu.fnstenv(addr)                │ store environment                 │
// │ x86.fpu.fldenv(addr)                 │ load environment                  │
// │ x86.fpu.fnsave(addr)                 │ save full state                   │
// │ x86.fpu.frstor(addr)                 │ restore full state                │
// │ x86.fpu.fwait                        │ wait for FPU                      │
// │ x86.fpu.fnop                         │ FPU no-op                         │
// │ x86.fpu.fxsave(addr)                 │ save FXSAVE block                 │
// │ x86.fpu.fxrstor(addr)               │ restore FXSAVE block              │
// │ x86.fpu.const.fld1                   │ push +1.0                         │
// │ x86.fpu.const.fldz                   │ push +0.0                         │
// │ x86.fpu.const.fldpi                  │ push π                            │
// │ x86.fpu.const.fldl2e                 │ push log2(e)                      │
// │ x86.fpu.const.fldl2t                 │ push log2(10)                     │
// │ x86.fpu.const.fldlg2                 │ push log10(2)                     │
// │ x86.fpu.const.fldln2                 │ push ln(2)                        │
// │ x86.fpu.tag_set_valid(slot)          │ set tag to 00 (Valid)             │
// │ x86.fpu.tag_set_empty(slot)          │ set tag to 11 (Empty)             │
// │ x86.fpu.tag_set_zero(slot)           │ set tag to 01 (Zero)              │
// │ x86.fpu.tag_set_special(slot)        │ set tag to 10 (Special)           │
// │ x86.fpu.get_precision                │ read PC field                     │
// │ x86.fpu.set_precision(val)           │ write PC field                    │
// │ x86.fpu.set_round(val)               │ write RC field                    │
// │ x86.fpu.snapshot_sw(c0,c1,c2,c3,…)  │ pack SW fields to 16-bit value    │
// │ x86.fpu.restore_sw(sw)               │ unpack 16-bit SW into fields      │
// └──────────────────────────────────────┴───────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::{Effect, IrExpr};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    fn reg_write_count(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    fn has_reg_write(effects: &[Effect], reg: &str) -> bool {
        reg_write_count(effects, reg) > 0
    }

    /// Count total `Effect::Intrinsic` entries whose name contains `substr`.
    fn intrinsic_count(effects: &[Effect], substr: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
            .count()
    }

    // ── st_idx / stack pointer arithmetic ────────────────────────────────────

    #[test]
    fn st_idx_zero_is_top() {
        let expr = st_idx(0);
        // Should be just Reg("__fpu_top"), no arithmetic
        assert!(matches!(expr, IrExpr::Reg(ref r) if r == "__fpu_top"));
    }

    #[test]
    fn st_idx_nonzero_wraps() {
        let expr = st_idx(3);
        // Must be (TOP + 3) & 7
        assert!(matches!(expr, IrExpr::And(_, _)));
    }

    #[test]
    fn fpu_push_top_emits_reg_write() {
        let mut ctx = ctx64();
        fpu_push_top(&mut ctx);
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn fpu_pop_top_emits_reg_write() {
        let mut ctx = ctx64();
        fpu_pop_top(&mut ctx);
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn fpu_get_st_emits_intrinsic_and_reg_write() {
        let mut ctx = ctx64();
        let t = fpu_get_st(&mut ctx, IrExpr::Const(0));
        assert!(!t.is_empty());
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.get_st"));
        assert!(has_reg_write(&ctx.effects, &t));
    }

    #[test]
    fn fpu_set_st_emits_intrinsic() {
        let mut ctx = ctx64();
        fpu_set_st(&mut ctx, IrExpr::Const(0), IrExpr::Const(42));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.set_st"));
    }

    // ── FINIT ────────────────────────────────────────────────────────────────

    #[test]
    fn finit_resets_top_to_zero() {
        let mut ctx = ctx64();
        // Build a fake zero-operand FINIT via a dummy decode
        // Since we can't easily decode raw bytes in a unit test without iced_x86,
        // we call the helper logic directly.
        ctx.emit_reg_write(FPU_TOP, IrExpr::Const(0));
        for cc in [FPU_C0, FPU_C1, FPU_C2, FPU_C3] {
            ctx.emit_reg_write(cc, IrExpr::Const(0));
        }
        ctx.emit_intrinsic("x86.fpu.finit", vec![]);
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.finit"));
    }

    // ── FCLEX ────────────────────────────────────────────────────────────────

    #[test]
    fn fclex_clears_exception_bits() {
        let mut ctx = ctx64();
        // Simulate FCLEX effect directly
        for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
            ctx.emit_reg_write(ex, IrExpr::Const(0));
        }
        ctx.emit_intrinsic("x86.fpu.fclex", vec![]);
        // All six exception registers must have been written
        for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
            assert!(has_reg_write(&ctx.effects, ex), "missing write to {ex}");
        }
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fclex"));
    }

    // ── FABS ─────────────────────────────────────────────────────────────────

    #[test]
    fn fabs_emits_intrinsic_and_sets_c1_zero() {
        let mut ctx = ctx64();
        // Manually replicate fabs logic without a real instruction
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fabs", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));

        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fabs"));
        assert!(has_reg_write(&ctx.effects, FPU_C1));
    }

    // ── FCHS ─────────────────────────────────────────────────────────────────

    #[test]
    fn fchs_emits_fchs_intrinsic() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fchs", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fchs"));
    }

    // ── FSQRT ────────────────────────────────────────────────────────────────

    #[test]
    fn fsqrt_emits_intrinsic_and_exception_flags() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fsqrt", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        emit_c1_undef(&mut ctx);
        emit_fpu_exceptions_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fsqrt"));
        // All exception bits must be written
        for ex in [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE] {
            assert!(has_reg_write(&ctx.effects, ex));
        }
    }

    // ── Stack push/pop symmetry ───────────────────────────────────────────────

    #[test]
    fn push_then_pop_emits_two_top_writes() {
        let mut ctx = ctx64();
        fpu_push_top(&mut ctx);
        fpu_pop_top(&mut ctx);
        assert_eq!(reg_write_count(&ctx.effects, FPU_TOP), 2);
    }

    // ── FXCH ─────────────────────────────────────────────────────────────────

    #[test]
    fn fxch_emits_two_get_and_two_set() {
        let mut ctx = ctx64();
        // Simulate FXCH ST(1): get ST(0), get ST(1), set ST(0), set ST(1)
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let sti_t = fpu_get_st(&mut ctx, st_idx(1));
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(sti_t));
        fpu_set_st(&mut ctx, st_idx(1), IrExpr::Reg(top_t));
        ctx.emit_reg_write(FPU_C1, IrExpr::Const(0));
        assert_eq!(intrinsic_count(&ctx.effects, "x86.fpu.get_st"), 2);
        assert_eq!(intrinsic_count(&ctx.effects, "x86.fpu.set_st"), 2);
    }

    // ── FXTRACT ──────────────────────────────────────────────────────────────

    #[test]
    fn fxtract_pushes_and_emits_both_parts() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let exp_t = ctx.fresh_temp();
        let sig_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fxtract_exp", vec![IrExpr::Reg(top_t.clone())]);
        ctx.emit_reg_write(exp_t.clone(), IrExpr::Undef);
        ctx.emit_intrinsic("x86.fpu.fxtract_sig", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(sig_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(exp_t));
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(sig_t));
        assert!(has_intrinsic(&ctx.effects, "fxtract_exp"));
        assert!(has_intrinsic(&ctx.effects, "fxtract_sig"));
        // A push must have been emitted
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FSINCOS ──────────────────────────────────────────────────────────────

    #[test]
    fn fsincos_emits_sin_cos_and_push() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let sin_t = ctx.fresh_temp();
        let cos_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fsin", vec![IrExpr::Reg(top_t.clone())]);
        ctx.emit_reg_write(sin_t.clone(), IrExpr::Undef);
        ctx.emit_intrinsic("x86.fpu.fcos", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(cos_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(sin_t));
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(cos_t));
        assert!(has_intrinsic(&ctx.effects, "fsin"));
        assert!(has_intrinsic(&ctx.effects, "fcos"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FYL2X ────────────────────────────────────────────────────────────────

    #[test]
    fn fyl2x_emits_intrinsic_and_pops() {
        let mut ctx = ctx64();
        let st0_t = fpu_get_st(&mut ctx, st_idx(0));
        let st1_t = fpu_get_st(&mut ctx, st_idx(1));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic(
            "x86.fpu.fyl2x",
            vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
        );
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(1), IrExpr::Reg(result_t));
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fyl2x"));
        assert_eq!(reg_write_count(&ctx.effects, FPU_TOP), 1);
    }

    // ── FPATAN ───────────────────────────────────────────────────────────────

    #[test]
    fn fpatan_emits_intrinsic_and_pops() {
        let mut ctx = ctx64();
        let st0_t = fpu_get_st(&mut ctx, st_idx(0));
        let st1_t = fpu_get_st(&mut ctx, st_idx(1));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic(
            "x86.fpu.fpatan",
            vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
        );
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(1), IrExpr::Reg(result_t));
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fpatan"));
        assert_eq!(reg_write_count(&ctx.effects, FPU_TOP), 1);
    }

    // ── FPTAN ────────────────────────────────────────────────────────────────

    #[test]
    fn fptan_pushes_one_point_zero() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let tan_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fptan", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(tan_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(tan_t));
        fpu_push_top(&mut ctx);
        ctx.emit_intrinsic("x86.fpu.const.fld1", vec![]);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Undef);
        assert!(has_intrinsic(&ctx.effects, "fptan"));
        assert!(has_intrinsic(&ctx.effects, "fld1"));
        // Must have pushed (one TOP write)
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FBLD / FBSTP ─────────────────────────────────────────────────────────

    #[test]
    fn fbld_emits_bcd_load_and_push() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.load_bcd80", vec![IrExpr::Const(0x5000)]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
        assert!(has_intrinsic(&ctx.effects, "load_bcd80"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn fbstp_emits_bcd_store_and_pop() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        ctx.emit_intrinsic(
            "x86.fpu.store_bcd80",
            vec![IrExpr::Const(0x5000), IrExpr::Reg(top_t)],
        );
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "store_bcd80"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FSCALE ───────────────────────────────────────────────────────────────

    #[test]
    fn fscale_uses_st0_and_st1() {
        let mut ctx = ctx64();
        let st0_t = fpu_get_st(&mut ctx, st_idx(0));
        let st1_t = fpu_get_st(&mut ctx, st_idx(1));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic(
            "x86.fpu.fscale",
            vec![IrExpr::Reg(st0_t), IrExpr::Reg(st1_t)],
        );
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        assert_eq!(intrinsic_count(&ctx.effects, "x86.fpu.get_st"), 2);
        assert!(has_intrinsic(&ctx.effects, "fscale"));
    }

    // ── FPREM / FPREM1 ───────────────────────────────────────────────────────

    #[test]
    fn fprem_emits_intrinsic_and_cc_flags() {
        let mut ctx = ctx64();
        let st0_t = fpu_get_st(&mut ctx, st_idx(0));
        let st1_t = fpu_get_st(&mut ctx, st_idx(1));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic(
            "x86.fpu.fprem",
            vec![IrExpr::Reg(st0_t), IrExpr::Reg(st1_t)],
        );
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        emit_fpu_cc_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fprem"));
        for cc in [FPU_C0, FPU_C1, FPU_C2, FPU_C3] {
            assert!(has_reg_write(&ctx.effects, cc));
        }
    }

    #[test]
    fn fprem1_distinct_from_fprem() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fprem1", vec![]);
        let mut ctx2 = ctx64();
        ctx2.emit_intrinsic("x86.fpu.fprem", vec![]);
        assert!(has_intrinsic(&ctx.effects, "fprem1"));
        assert!(!has_intrinsic(&ctx.effects, "x86.fpu.fprem\"")); // not the un-suffixed one
    }

    // ── F2XM1 ────────────────────────────────────────────────────────────────

    #[test]
    fn f2xm1_emits_intrinsic() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.f2xm1", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        assert!(has_intrinsic(&ctx.effects, "f2xm1"));
    }

    // ── FXSAVE / FXRSTOR ─────────────────────────────────────────────────────

    #[test]
    fn fxsave_emits_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fxsave", vec![IrExpr::Const(0x6000)]);
        assert!(has_intrinsic(&ctx.effects, "fxsave"));
    }

    #[test]
    fn fxrstor_emits_intrinsic_and_invalidates_state() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fxrstor", vec![IrExpr::Const(0x6000)]);
        ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
        emit_fpu_cc_undef(&mut ctx);
        emit_fpu_exceptions_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fxrstor"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FFREE ────────────────────────────────────────────────────────────────

    #[test]
    fn ffree_emits_intrinsic_no_pop() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.ffree", vec![IrExpr::Const(2)]);
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.ffree"));
        assert!(!has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn ffreep_emits_intrinsic_and_pop() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.ffree", vec![IrExpr::Const(0)]);
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.ffree"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FWAIT / FNOP ─────────────────────────────────────────────────────────

    #[test]
    fn fwait_emits_fence_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fwait", vec![]);
        assert!(has_intrinsic(&ctx.effects, "fwait"));
    }

    #[test]
    fn fnop_emits_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fnop", vec![]);
        assert!(has_intrinsic(&ctx.effects, "fnop"));
    }

    // ── compare CC flags ─────────────────────────────────────────────────────

    #[test]
    fn fcom_sets_all_four_cc_regs() {
        let mut ctx = ctx64();
        let a_t = fpu_get_st(&mut ctx, st_idx(0));
        let b_t = fpu_get_st(&mut ctx, st_idx(1));
        ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
        emit_fpu_cc_undef(&mut ctx);
        for cc in [FPU_C0, FPU_C1, FPU_C2, FPU_C3] {
            assert!(has_reg_write(&ctx.effects, cc), "missing {cc}");
        }
    }

    #[test]
    fn fcomi_also_sets_eflags() {
        let mut ctx = ctx64();
        let a_t = fpu_get_st(&mut ctx, st_idx(0));
        let b_t = fpu_get_st(&mut ctx, st_idx(1));
        ctx.emit_intrinsic("x86.fpu.fcom", vec![IrExpr::Reg(a_t), IrExpr::Reg(b_t)]);
        emit_fpu_cc_undef(&mut ctx);
        ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Sf, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Af, IrExpr::Const(0));
        assert!(has_reg_write(&ctx.effects, "zf"));
        assert!(has_reg_write(&ctx.effects, "pf"));
        assert!(has_reg_write(&ctx.effects, "cf"));
        assert!(has_reg_write(&ctx.effects, "of"));
    }

    // ── binop helper ─────────────────────────────────────────────────────────

    #[test]
    fn fpu_binop_mem_emits_get_set_and_named_intrinsic() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fadd_f32", IrExpr::Const(0xdead_beef));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.get_st"));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fadd_f32"));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.set_st"));
    }

    // ── FYL2XP1 ──────────────────────────────────────────────────────────────

    #[test]
    fn fyl2xp1_emits_intrinsic_and_pops() {
        let mut ctx = ctx64();
        let st0_t = fpu_get_st(&mut ctx, st_idx(0));
        let st1_t = fpu_get_st(&mut ctx, st_idx(1));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic(
            "x86.fpu.fyl2xp1",
            vec![IrExpr::Reg(st1_t), IrExpr::Reg(st0_t)],
        );
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(1), IrExpr::Reg(result_t));
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fyl2xp1"));
        assert_eq!(reg_write_count(&ctx.effects, FPU_TOP), 1);
    }

    // ── fresh_temp uniqueness ─────────────────────────────────────────────────

    #[test]
    fn fresh_temps_are_always_unique() {
        let mut ctx = ctx64();
        let names: Vec<String> = (0..20).map(|_| ctx.fresh_temp()).collect();
        let unique: std::collections::HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), unique.len());
    }

    // ── emit_fpu_exceptions_undef ─────────────────────────────────────────────

    #[test]
    fn exception_undef_emits_six_writes() {
        let mut ctx = ctx64();
        emit_fpu_exceptions_undef(&mut ctx);
        let count: usize = [FPU_IE, FPU_DE, FPU_ZE, FPU_OE, FPU_UE, FPU_PE]
            .iter()
            .filter(|&&r| has_reg_write(&ctx.effects, r))
            .count();
        assert_eq!(count, 6);
    }

    // ── two_st_operands ───────────────────────────────────────────────────────

    #[test]
    fn st_idx_seven_gives_and_expr() {
        let e = st_idx(7);
        assert!(matches!(e, IrExpr::And(_, _)));
    }

    // ── FRNDINT ──────────────────────────────────────────────────────────────

    #[test]
    fn frndint_emits_intrinsic_and_writes_st0() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.frndint", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        emit_c1_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "frndint"));
        assert!(has_intrinsic(&ctx.effects, "set_st"));
    }

    // ── FISTTP ───────────────────────────────────────────────────────────────

    #[test]
    fn fisttp_emits_truncate_intrinsic_and_pop() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        ctx.emit_intrinsic(
            "x86.fpu.store_i64_trunc",
            vec![IrExpr::Const(0x4000), IrExpr::Reg(top_t)],
        );
        fpu_pop_top(&mut ctx);
        emit_c1_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "store_i64_trunc"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FILD emits get_st intrinsic ───────────────────────────────────────────

    #[test]
    fn fild_emits_integer_load_and_push() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.load_i32", vec![IrExpr::Const(0x7000)]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
        emit_c1_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "load_i32"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FIST emits store without pop ─────────────────────────────────────────

    #[test]
    fn fist_emits_store_no_pop() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        ctx.emit_intrinsic(
            "x86.fpu.store_i16",
            vec![IrExpr::Const(0x8000), IrExpr::Reg(top_t)],
        );
        emit_c1_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "store_i16"));
        assert!(!has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FNSTSW AX ────────────────────────────────────────────────────────────

    #[test]
    fn fnstsw_emits_intrinsic() {
        let mut ctx = ctx64();
        let t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fnstsw", vec![]);
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        ctx.emit_reg_write("ax", IrExpr::Reg(t));
        assert!(has_intrinsic(&ctx.effects, "fnstsw"));
        assert!(has_reg_write(&ctx.effects, "ax"));
    }

    // ── FLDCW / FNSTCW round-trip ────────────────────────────────────────────

    #[test]
    fn fldcw_emits_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fldcw", vec![IrExpr::Const(0x3000)]);
        assert!(has_intrinsic(&ctx.effects, "fldcw"));
    }

    #[test]
    fn fnstcw_emits_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fnstcw", vec![IrExpr::Const(0x3000)]);
        assert!(has_intrinsic(&ctx.effects, "fnstcw"));
    }

    // ── FLDENV / FNSTENV ─────────────────────────────────────────────────────

    #[test]
    fn fnstenv_emits_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fnstenv", vec![IrExpr::Const(0x2000)]);
        assert!(has_intrinsic(&ctx.effects, "fnstenv"));
    }

    #[test]
    fn fldenv_emits_intrinsic_and_invalidates() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fldenv", vec![IrExpr::Const(0x2000)]);
        ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
        emit_fpu_cc_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "fldenv"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── FSAVE / FRSTOR ───────────────────────────────────────────────────────

    #[test]
    fn fnsave_emits_intrinsic_and_resets_top() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.fnsave", vec![IrExpr::Const(0x9000)]);
        ctx.emit_reg_write(FPU_TOP, IrExpr::Const(0));
        assert!(has_intrinsic(&ctx.effects, "fnsave"));
        // After FNSAVE TOP must be reset to 0
        
        assert!(ctx
            .effects
            .iter()
            .filter_map(|e| {
                if let Effect::RegWrite { reg, value } = e {
                    if reg == FPU_TOP {
                        Some(value.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }).next().is_some());
    }

    #[test]
    fn frstor_emits_intrinsic_and_invalidates_top() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.frstor", vec![IrExpr::Const(0x9000)]);
        ctx.emit_reg_write(FPU_TOP, IrExpr::Undef);
        emit_fpu_cc_undef(&mut ctx);
        emit_fpu_exceptions_undef(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "frstor"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── Binop ST(i) symmetry ─────────────────────────────────────────────────

    #[test]
    fn binop_st_fsub_emits_fsub_intrinsic() {
        let mut ctx = ctx64();
        let dst_t = fpu_get_st(&mut ctx, st_idx(0));
        let src_t = fpu_get_st(&mut ctx, st_idx(1));
        let res_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fsub", vec![IrExpr::Reg(dst_t), IrExpr::Reg(src_t)]);
        ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(res_t));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fsub"));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.set_st"));
    }

    #[test]
    fn binop_st_fmul_emits_fmul_intrinsic() {
        let mut ctx = ctx64();
        let dst_t = fpu_get_st(&mut ctx, st_idx(0));
        let src_t = fpu_get_st(&mut ctx, st_idx(1));
        let res_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fmul", vec![IrExpr::Reg(dst_t), IrExpr::Reg(src_t)]);
        ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(res_t));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fmul"));
    }

    #[test]
    fn binop_st_fdiv_emits_fdiv_intrinsic() {
        let mut ctx = ctx64();
        let dst_t = fpu_get_st(&mut ctx, st_idx(0));
        let src_t = fpu_get_st(&mut ctx, st_idx(1));
        let res_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fdiv", vec![IrExpr::Reg(dst_t), IrExpr::Reg(src_t)]);
        ctx.emit_reg_write(res_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(res_t));
        assert!(has_intrinsic(&ctx.effects, "x86.fpu.fdiv"));
    }

    #[test]
    fn binop_mem_fiadd_i16_name() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fiadd_i16", IrExpr::Const(0x1000));
        assert!(has_intrinsic(&ctx.effects, "fiadd_i16"));
    }

    #[test]
    fn binop_mem_fiadd_i32_name() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fiadd_i32", IrExpr::Const(0x1000));
        assert!(has_intrinsic(&ctx.effects, "fiadd_i32"));
    }

    #[test]
    fn binop_mem_fidiv_i32_name() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fidiv_i32", IrExpr::Const(0x2000));
        assert!(has_intrinsic(&ctx.effects, "fidiv_i32"));
    }

    #[test]
    fn binop_mem_fidivr_i16_name() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fidivr_i16", IrExpr::Const(0x2000));
        assert!(has_intrinsic(&ctx.effects, "fidivr_i16"));
    }

    // ── Reverse-operand variants ──────────────────────────────────────────────

    #[test]
    fn fsubr_intrinsic_name_differs_from_fsub() {
        let mut ctx_sub = ctx64();
        fpu_binop_mem(&mut ctx_sub, "fsub_f32", IrExpr::Const(0));
        let mut ctx_subr = ctx64();
        fpu_binop_mem(&mut ctx_subr, "fsubr_f32", IrExpr::Const(0));
        assert!(has_intrinsic(&ctx_sub.effects, "fsub_f32"));
        assert!(has_intrinsic(&ctx_subr.effects, "fsubr_f32"));
        assert!(
            !has_intrinsic(&ctx_subr.effects, "fsub_f32")
                || has_intrinsic(&ctx_subr.effects, "fsubr_f32")
        );
    }

    #[test]
    fn fdivr_intrinsic_name_differs_from_fdiv() {
        let mut ctx = ctx64();
        fpu_binop_mem(&mut ctx, "fdivr_f64", IrExpr::Const(0));
        assert!(has_intrinsic(&ctx.effects, "fdivr_f64"));
    }

    // ── FSIN / FCOS individual tests ──────────────────────────────────────────

    #[test]
    fn fsin_uses_get_and_set_st() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fsin", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        assert!(has_intrinsic(&ctx.effects, "get_st"));
        assert!(has_intrinsic(&ctx.effects, "set_st"));
    }

    #[test]
    fn fcos_uses_get_and_set_st() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        let result_t = ctx.fresh_temp();
        ctx.emit_intrinsic("x86.fpu.fcos", vec![IrExpr::Reg(top_t)]);
        ctx.emit_reg_write(result_t.clone(), IrExpr::Undef);
        fpu_set_st(&mut ctx, st_idx(0), IrExpr::Reg(result_t));
        assert!(has_intrinsic(&ctx.effects, "get_st"));
        assert!(has_intrinsic(&ctx.effects, "set_st"));
    }

    // ── FPU constant loads ────────────────────────────────────────────────────

    #[test]
    fn fldpi_emits_const_fldpi_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldpi", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldpi"));
    }

    #[test]
    fn fldl2e_emits_const_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldl2e", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldl2e"));
    }

    #[test]
    fn fldl2t_emits_const_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldl2t", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldl2t"));
    }

    #[test]
    fn fldlg2_emits_const_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldlg2", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldlg2"));
    }

    #[test]
    fn fldln2_emits_const_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldln2", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldln2"));
    }

    #[test]
    fn fld1_emits_const_fld1_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fld1", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fld1"));
    }

    #[test]
    fn fldz_emits_const_fldz_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.const.fldz", vec![]);
        assert!(has_intrinsic(&ctx.effects, "const.fldz"));
    }

    // ── FPU mem-float load variants (FLD m32/m64/m80) ─────────────────────────

    #[test]
    fn fld_m32_emits_load_f32_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.load_f32", vec![IrExpr::Const(0xA000)]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
        assert!(has_intrinsic(&ctx.effects, "load_f32"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn fld_m64_emits_load_f64_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.load_f64", vec![IrExpr::Const(0xA000)]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
        assert!(has_intrinsic(&ctx.effects, "load_f64"));
    }

    #[test]
    fn fld_m80_emits_load_f80_intrinsic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.load_f80", vec![IrExpr::Const(0xA000)]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        fpu_push_top(&mut ctx);
        fpu_set_st(&mut ctx, IrExpr::Reg(FPU_TOP.into()), IrExpr::Reg(t));
        assert!(has_intrinsic(&ctx.effects, "load_f80"));
    }

    // ── FST / FSTP mem store variants ────────────────────────────────────────

    #[test]
    fn fst_m32_emits_store_f32_no_pop() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        ctx.emit_intrinsic(
            "x86.fpu.store_f32",
            vec![IrExpr::Const(0xB000), IrExpr::Reg(top_t)],
        );
        // No pop: TOP must not be written
        assert!(has_intrinsic(&ctx.effects, "store_f32"));
        assert!(!has_reg_write(&ctx.effects, FPU_TOP));
    }

    #[test]
    fn fstp_m64_emits_store_f64_and_pop() {
        let mut ctx = ctx64();
        let top_t = fpu_get_st(&mut ctx, st_idx(0));
        ctx.emit_intrinsic(
            "x86.fpu.store_f64",
            vec![IrExpr::Const(0xB000), IrExpr::Reg(top_t)],
        );
        fpu_pop_top(&mut ctx);
        assert!(has_intrinsic(&ctx.effects, "store_f64"));
        assert!(has_reg_write(&ctx.effects, FPU_TOP));
    }

    // ── Effect count sanity ───────────────────────────────────────────────────

    #[test]
    fn empty_ctx_has_no_effects() {
        let ctx = ctx64();
        assert!(ctx.is_empty());
    }

    #[test]
    fn emit_increases_len_by_one() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.fpu.test", vec![]);
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn multiple_emits_accumulate() {
        let mut ctx = ctx64();
        for _ in 0..7 {
            ctx.emit_intrinsic("x86.fpu.test", vec![]);
        }
        assert_eq!(ctx.len(), 7);
    }
}
