//! AVX / AVX2 handlers: VMOV*, VADDP*/VSUBP*/VMULP*/VDIVP*, VPADDX/VPSUBX,
//! VANDP*/VORP*/VXORP*, shuffles (VPSHUFB, VPSHUFD, VPERMD, VPERMQ),
//! VZEROUPPER, VZEROALL.
//!
//! AVX extends SSE with:
//!   * 256-bit YMM registers (YMM0–YMM15).
//!   * Non-destructive three-operand form: `VADDPS dst, src1, src2`.
//!   * VEX prefix that zeros the upper 128 bits of YMM on 128-bit writes
//!     (VEX.128 form), preventing "false dependency" issues.
//!
//! All operations are modelled as named intrinsics.

use crate::x86_context::X86LiftCtx;
use crate::x86_operand::{read_operand, write_operand};
use crate::{IrExpr, LiftError};
use iced_x86::Instruction;

fn vop2(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let src1 = read_operand(instr, 1, ctx);
    let src2 = read_operand(instr, 2, ctx);
    ctx.emit_intrinsic(name, vec![src1, src2]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    
}

fn vop1(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(name, vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    
}

// ─────────────────────────────────────────────────────────────────────────────
// Moves
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_vmov(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    write_operand(instr, 0, src, ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Floating-point arithmetic (three-operand form)
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_vfp_arith(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let name = match instr.mnemonic() {
        M::Vaddps => "x86.avx.vaddps",
        M::Vaddpd => "x86.avx.vaddpd",
        M::Vsubps => "x86.avx.vsubps",
        M::Vsubpd => "x86.avx.vsubpd",
        M::Vmulps => "x86.avx.vmulps",
        M::Vmulpd => "x86.avx.vmulpd",
        M::Vdivps => "x86.avx.vdivps",
        M::Vdivpd => "x86.avx.vdivpd",
        M::Vsqrtps => "x86.avx.vsqrtps",
        M::Vsqrtpd => "x86.avx.vsqrtpd",
        _ => "x86.avx.fp_arith_unknown",
    };
    if instr.op_count() == 3 {
        vop2(instr, ctx, name);
    } else {
        vop1(instr, ctx, name);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer SIMD (PADDX / PSUBX)
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_vp_int_arith(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = format!("x86.avx.{:?}", instr.mnemonic()).to_lowercase();
    vop2(instr, ctx, &name);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Logical
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_v_logic(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = format!("x86.avx.{:?}", instr.mnemonic()).to_lowercase();
    vop2(instr, ctx, &name);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Shuffles & permutations
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_v_shuffle(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = format!("x86.avx.{:?}", instr.mnemonic()).to_lowercase();
    if instr.op_count() >= 3 {
        vop2(instr, ctx, &name);
    } else {
        vop1(instr, ctx, &name);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// VZEROUPPER / VZEROALL
// ─────────────────────────────────────────────────────────────────────────────

/// `VZEROUPPER` — zero the upper 128 bits of all YMM registers.
/// `VZEROALL` — zero all bits of all YMM registers.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_vzero(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    if matches!(instr.mnemonic(), M::Vzeroall) {
        for i in 0u64..16 {
            ctx.emit_intrinsic("x86.avx.vzeroall.ymm", vec![IrExpr::Const(i)]);
            let name = format!("ymm{i}");
            ctx.emit_reg_write(&name, IrExpr::Const(0));
        }
    } else {
        for i in 0u64..16 {
            ctx.emit_intrinsic("x86.avx.vzeroupper.ymm_hi", vec![IrExpr::Const(i)]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    fn _decode(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }
    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }
    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }
    fn _writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    // Generic smoke tests that all handler modules share.
    #[test]
    fn ctx_emits_correctly() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        });
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn fresh_temps_are_unique() {
        let mut ctx = ctx64();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        assert_ne!(t1, t2);
    }

    #[test]
    fn eval_constant_through_effects() {
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0x42),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rax", 0x42);
    }

    #[test]
    fn intrinsic_does_not_panic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("test.handler_smoke", vec![]);
        assert!(has_intrinsic(&ctx.effects, "test.handler_smoke"));
    }

    #[test]
    fn materialise_returns_unique_temp() {
        let mut ctx = ctx64();
        let t = ctx.materialise(IrExpr::Const(7));
        assert!(!t.is_empty());
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn unknown_propagates_in_eval() {
        let effects = vec![Effect::RegWrite {
            reg: "rbx".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rax".into())),
                Box::new(IrExpr::Const(1)),
            ),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        assert_eq!(s.get_reg("rbx"), EvalValue::Unknown);
    }

    #[test]
    fn mem_write_stored_and_readable() {
        let effects = vec![Effect::MemWrite {
            addr: IrExpr::Const(0x5000),
            value: IrExpr::Const(0xdead_beef),
            size: 4,
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        assert_eq!(s.read_mem(0x5000, 4), EvalValue::Concrete(0xdead_beef));
    }
}
