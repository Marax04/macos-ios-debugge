//! AVX-512 handlers: EVEX-encoded floating-point arithmetic and k-register ops.
//!
//! ## AVX-512 model
//!
//! AVX-512 introduces three new concepts that the lifter must handle:
//!
//! **ZMM registers (512-bit)**: modelled as IR register names `zmm0`–`zmm31`.
//! They cannot be represented as a single `IrExpr::Reg` value because the
//! lifter's IR is scalar; instead each ZMM operation is wrapped in an
//! intrinsic that the MLIL pass will expand into per-lane micro-ops when
//! needed.
//!
//! **k-registers (k0–k7)**: 64-bit mask registers. k0 is architecturally
//! all-ones (always-active). Masking semantics — merge `{k1}` or zeroing
//! `{k1}{z}` — are recorded as intrinsic arguments. The IR calls these
//! registers `__avx512_k0` … `__avx512_k7`.
//!
//! **EVEX masking expansion**: per the spec, the correct expansion of
//! `VADDPS ZMM0{k1}, ZMM1, ZMM2` is:
//!
//! ```text
//! for lane in 0..16:
//!   active  = extract_bit(k1, lane)
//!   sum     = fadd(ZMM1.lane[lane], ZMM2.lane[lane])
//!   result  = select(active, sum, ZMM0.lane[lane])   // merge masking
//!   ZMM0.lane[lane] = result
//! ```
//!
//! Emitting 16+ intrinsics per instruction is intentional; the MLIL pass
//! can re-vectorise them when the mask is statically all-ones.

use crate::x86_context::X86LiftCtx;
use crate::x86_operand::read_operand;
use crate::{IrExpr, LiftError};
use iced_x86::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical name for AVX-512 mask register `ki`.
fn k_reg(i: u8) -> String {
    format!("__avx512_k{i}")
}

/// Number of lanes and bits-per-lane for the given EVEX FP instruction.
/// Returns (`lane_count`, `lane_bits`). The `ps`/`pd` suffix fixes the lane width
/// (32 vs 64 bit); the total vector width is taken from the destination
/// register size, so the same handler covers the XMM/YMM/ZMM EVEX forms.
fn evex_lanes(instr: &Instruction) -> (u64, u64) {
    use iced_x86::Mnemonic as M;
    let lane_bits: u64 = match instr.mnemonic() {
        M::Vaddpd | M::Vsubpd | M::Vmulpd => 64,
        _ => 32, // ps and the default
    };
    let total_bits = (instr.op0_register().size() as u64).saturating_mul(8);
    let total_bits = if total_bits == 0 { 512 } else { total_bits };
    (total_bits / lane_bits, lane_bits)
}

/// True when this `Vaddps`/… instruction is the EVEX (AVX-512) encoding rather
/// than the VEX (AVX/AVX2) one: the destination is a ZMM register or an opmask
/// (`{k1}`) is attached.
#[must_use]
pub fn uses_evex512(instr: &Instruction) -> bool {
    use iced_x86::Register as R;
    instr.op0_register().is_zmm() || instr.op_mask() != R::None
}

/// True when the EVEX.z bit is set (zeroing masking vs merge masking).
/// iced-x86 exposes this as `zeroing_masking()`.
const fn is_zeroing(instr: &Instruction) -> bool {
    instr.zeroing_masking()
}

/// AVX-512 mask register index from the instruction's mask register field.
fn mask_reg_idx(instr: &Instruction) -> u8 {
    use iced_x86::Register as R;
    match instr.op_mask() {
        R::K1 => 1,
        R::K2 => 2,
        R::K3 => 3,
        R::K4 => 4,
        R::K5 => 5,
        R::K6 => 6,
        R::K7 => 7,
        _ => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-lane EVEX FP arithmetic expansion
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_evex_fp_arith(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let op_name = match instr.mnemonic() {
        M::Vaddps | M::Vaddpd => "fadd",
        M::Vsubps | M::Vsubpd => "fsub",
        M::Vmulps | M::Vmulpd => "fmul",
        _ => "fp_arith",
    };
    let (lanes, lane_bits) = evex_lanes(instr);
    let k_idx = mask_reg_idx(instr);
    let zeroing = is_zeroing(instr);

    let dst = read_operand(instr, 0, ctx);
    let src1 = read_operand(instr, 1, ctx);
    let src2 = read_operand(instr, 2, ctx);
    let mask = IrExpr::Reg(k_reg(k_idx));

    // Emit one group of intrinsics per lane. The lifter emits them statically;
    // the MLIL pass compresses them back into a vector op when possible.
    for lane in 0..lanes {
        // Extract source lanes.
        ctx.emit_intrinsic(
            format!("x86.avx512.extract_lane_f{lane_bits}"),
            vec![src1.clone(), IrExpr::Const(lane)],
        );
        let a = ctx.materialise(IrExpr::Undef);

        ctx.emit_intrinsic(
            format!("x86.avx512.extract_lane_f{lane_bits}"),
            vec![src2.clone(), IrExpr::Const(lane)],
        );
        let b = ctx.materialise(IrExpr::Undef);

        // Compute the operation result.
        ctx.emit_intrinsic(
            format!("x86.avx512.{op_name}_f{lane_bits}"),
            vec![IrExpr::Reg(a), IrExpr::Reg(b)],
        );
        let result = ctx.materialise(IrExpr::Undef);

        // Extract the mask bit for this lane.
        let mask_bit = IrExpr::And(
            Box::new(IrExpr::Shr(
                Box::new(mask.clone()),
                Box::new(IrExpr::Const(lane)),
            )),
            Box::new(IrExpr::Const(1)),
        );

        // Select: if active, use result; otherwise use dst lane (or 0 if zeroing).
        let fallback = if zeroing {
            IrExpr::Const(0)
        } else {
            ctx.emit_intrinsic(
                format!("x86.avx512.extract_lane_f{lane_bits}"),
                vec![dst.clone(), IrExpr::Const(lane)],
            );
            IrExpr::Undef // will be materialised by the intrinsic
        };
        let fallback_t = if zeroing {
            ctx.materialise(fallback)
        } else {
            ctx.materialise(IrExpr::Undef)
        };

        ctx.emit_intrinsic(
            "x86.avx512.select",
            vec![mask_bit, IrExpr::Reg(result), IrExpr::Reg(fallback_t)],
        );
        let lane_result = ctx.materialise(IrExpr::Undef);

        // Write the lane back into the destination.
        ctx.emit_intrinsic(
            format!("x86.avx512.insert_lane_f{lane_bits}"),
            vec![dst.clone(), IrExpr::Const(lane), IrExpr::Reg(lane_result)],
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// k-register operations
// ─────────────────────────────────────────────────────────────────────────────

/// KMOV*, KAND*, KOR*, KXOR*, KNOT* — operations on predicate masks.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_k_op(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic as M;
    let is_unary = matches!(instr.mnemonic(), M::Knotb | M::Knotw | M::Knotd | M::Knotq);
    if is_unary {
        let src = read_operand(instr, 1, ctx);
        let t = ctx.materialise(IrExpr::Not(Box::new(src)));
        // k-register destination
        let dst_name = k_reg(instr.op0_register() as u8 & 7);
        ctx.emit_reg_write(dst_name, IrExpr::Reg(t));
    } else {
        let src1 = read_operand(instr, 1, ctx);
        let src2 = read_operand(instr, 2, ctx);
        let result = match instr.mnemonic() {
            M::Kmovb | M::Kmovw | M::Kmovd | M::Kmovq => src1,
            M::Kandb | M::Kandw | M::Kandd | M::Kandq => {
                IrExpr::And(Box::new(src1), Box::new(src2))
            }
            M::Korb | M::Korw | M::Kord | M::Korq => IrExpr::Or(Box::new(src1), Box::new(src2)),
            M::Kxorb | M::Kxorw | M::Kxord | M::Kxorq => {
                IrExpr::Xor(Box::new(src1), Box::new(src2))
            }
            _ => IrExpr::Undef,
        };
        let dst_name = k_reg(instr.op0_register() as u8 & 7);
        let t = ctx.materialise(result);
        ctx.emit_reg_write(dst_name, IrExpr::Reg(t));
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
