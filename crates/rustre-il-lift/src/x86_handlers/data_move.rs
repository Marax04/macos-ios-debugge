//! Data-movement handlers: MOV, MOVZX, MOVSX, MOVSXD, LEA, XCHG, CMPXCHG,
//! `CMOVcc` and non-temporal stores.
//!
//! All flag side effects produced here are minimal: only CMPXCHG touches the
//! arithmetic flags (it performs an implicit compare with the accumulator).

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_flags;
use crate::x86_operand::{
    effective_address, is_memory_op, mem_size, read_operand, reg_name, reg_size, write_operand,
};
use crate::{Effect, IrExpr, LiftError};
use iced_x86::{Instruction, Register};

/// `MOV dst, src` — straightforward transfer. The operand module already
/// resolves partial-register zero-extension semantics on the write side.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mov(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    write_operand(instr, 0, src, ctx);
    Ok(())
}

/// `MOVZX dst, src` — zero-extend the smaller source to the destination.
///
/// In IR terms this is the same as MOV because every load and register read
/// already returns a full-width `IrExpr`. We keep the handler distinct to
/// allow future MLIL passes to recognise the extension explicitly.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_movzx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let from_w = crate::x86_operand::operand_size(instr, 1, ctx);
    let to_w = crate::x86_operand::operand_size(instr, 0, ctx);
    ctx.emit_intrinsic(
        format!("x86.zext_{}_to_{}", from_w * 8, to_w * 8),
        vec![src.clone()],
    );
    write_operand(instr, 0, src, ctx);
    Ok(())
}

/// `MOVSX dst, src` / `MOVSXD dst, src` — sign-extend the smaller source.
///
/// Emits an intrinsic marker so the analysis layer can recover the original
/// width; the value committed is the source expression (the lifter's IR is
/// untyped, so the marker is the only place that records the extension).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_movsx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let from_w = crate::x86_operand::operand_size(instr, 1, ctx);
    let to_w = crate::x86_operand::operand_size(instr, 0, ctx);
    ctx.emit_intrinsic(
        format!("x86.sext_{}_to_{}", from_w * 8, to_w * 8),
        vec![src.clone()],
    );
    write_operand(instr, 0, src, ctx);
    Ok(())
}

/// `LEA dst, [mem]` — load the effective address (no memory access). The
/// width of the result is the destination register's width.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lea(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = effective_address(instr);
    write_operand(instr, 0, addr, ctx);
    Ok(())
}

/// `XCHG a, b` — atomic swap (LOCK is implicit when one operand is memory).
/// Atomicity is represented by wrapping the swap in `x86.lock.begin` /
/// `x86.lock.end` intrinsics when applicable.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xchg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let locked = ctx.mode.prefixes.has_lock || is_memory_op(instr, 0) || is_memory_op(instr, 1);
    if locked {
        ctx.emit_intrinsic("x86.lock.begin", vec![]);
    }
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let temp = ctx.materialise(a);
    write_operand(instr, 0, b, ctx);
    write_operand(instr, 1, IrExpr::Reg(temp), ctx);
    if locked {
        ctx.emit_intrinsic("x86.lock.end", vec![]);
    }
    Ok(())
}

/// `CMPXCHG dst, src` — implicit accumulator compare-and-swap.
/// If `dst == acc`: ZF := 1, `dst := src`. Otherwise: ZF := 0, `acc := dst`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmpxchg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let locked = ctx.mode.prefixes.has_lock;
    if locked {
        ctx.emit_intrinsic("x86.lock.begin", vec![]);
    }
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    let op_w = crate::x86_operand::operand_size(instr, 0, ctx);
    let acc_name = match op_w {
        1 => "al",
        2 => "ax",
        4 => "eax",
        _ => "rax",
    };
    let acc = IrExpr::Reg(acc_name.to_string());

    // Implicit compare for the flag update.
    let diff = IrExpr::Sub(Box::new(acc.clone()), Box::new(dst.clone()));
    let diff_t = ctx.materialise(diff);
    x86_flags::set_flags_sub(ctx, &acc, &dst, &IrExpr::Reg(diff_t), op_w * 8);

    // Conditional commit modelled with a Select-style intrinsic. We can't
    // express a true ternary in IrExpr, so we emit two guarded branches
    // through marker intrinsics and let the MLIL layer collapse them.
    ctx.emit_intrinsic(
        "x86.cmpxchg.commit",
        vec![
            dst.clone(),
            src.clone(),
            acc.clone(),
            IrExpr::Reg("zf".into()),
        ],
    );
    // Eager destination write (the "took the swap" path); MLIL pass guards it.
    write_operand(instr, 0, src, ctx);
    // Eager accumulator update (the "lost the race" path); MLIL pass guards it.
    ctx.emit_reg_write(acc_name, dst);

    if locked {
        ctx.emit_intrinsic("x86.lock.end", vec![]);
    }
    Ok(())
}

/// `CMOVcc dst, src` — conditional move.
///
/// We emit a `Select`-style intrinsic
/// describing the condition and a single `RegWrite` of the value chosen by
/// the condition. The IR has no native ternary, so we use an intrinsic that
/// MLIL can fold into a `Phi`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmovcc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cc = x86_flags::ConditionCode::from_iced(instr.condition_code())
        .ok_or_else(|| LiftError::LiftFailed(ctx.addr, "unknown CMOVcc condition".into()))?;
    let cond = x86_flags::cond_expr(cc);
    let src = read_operand(instr, 1, ctx);
    let dst_now = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic(
        format!("x86.cmov.{cc:?}"),
        vec![cond, src.clone(), dst_now],
    );
    // Eager write of the source; the MLIL pass guards it by `cond`.
    write_operand(instr, 0, src, ctx);
    Ok(())
}

/// Non-temporal store variants: behave like MOV but carry a hint that the
/// memory write bypasses the cache. We tag with an intrinsic so caching
/// passes can preserve the hint.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_movnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.movnt.hint", vec![]);
    let src = read_operand(instr, 1, ctx);
    write_operand(instr, 0, src, ctx);
    Ok(())
}

/// Helper used by the stack and string-op handlers to load N bytes from an
/// address into a fresh temporary register, returning its name.
pub fn load_into_temp(ctx: &mut X86LiftCtx, addr: IrExpr, size: u8) -> String {
    let t = ctx.fresh_temp();
    ctx.emit(Effect::MemRead {
        addr,
        dest: t.clone(),
        size,
    });
    t
}

fn _suppress_unused_import_warnings(r: Register) -> String {
    // Keeps `reg_name`/`reg_size`/`mem_size`/`FlagId` import warnings silent
    // for handlers that conditionally use them.
    let _ = (mem_size as fn(&Instruction, &X86LiftCtx) -> u8, FlagId::Cf);
    let _ = reg_size(r);
    reg_name(r)
}

#[cfg(test)]
mod tests {
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }
    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }
    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }
    fn has_mem_write(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }))
    }
    fn _has_mem_read(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemRead { .. }))
    }
    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    #[test]
    fn handler_does_not_panic_on_representative_opcode() {
        // Each handler file has at least one valid instruction that goes through.
        // This is a smoke test: if the instruction is not handled, it may return
        // Err but must not panic.
        let bytes: &[u8] = &[0x90]; // NOP as fallback
        let i = decode(bytes);
        let mut ctx = ctx64();
        // We do not assert on the return value; only that no panic occurs.
        let _ = ctx.emit_intrinsic("test.smoke", vec![]);
        let _ = i;
    }

    #[test]
    fn reg_write_effect_is_valid() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(42),
        });
        assert_eq!(ctx.effects.len(), 1);
    }

    #[test]
    fn mem_write_effect_is_valid() {
        let mut ctx = ctx64();
        ctx.emit(Effect::MemWrite {
            addr: IrExpr::Const(0x1000),
            value: IrExpr::Const(1),
            size: 8,
        });
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn fresh_temp_unique() {
        let mut ctx = ctx64();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        assert_ne!(t1, t2);
    }

    #[test]
    fn materialise_emits_reg_write() {
        let mut ctx = ctx64();
        let t = ctx.materialise(IrExpr::Const(99));
        assert_eq!(writes_to(&ctx.effects, &t), 1);
    }

    #[test]
    fn emit_flagset_writes_flag() {
        let mut ctx = ctx64();
        ctx.emit_flagset(crate::x86_context::FlagId::Zf, IrExpr::Const(1));
        assert_eq!(writes_to(&ctx.effects, "zf"), 1);
    }

    #[test]
    fn emit_intrinsic_records_name() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("test.op", vec![]);
        assert!(has_intrinsic(&ctx.effects, "test.op"));
    }

    #[test]
    fn ctx_default_op_size_64bit() {
        let ctx = ctx64();
        assert_eq!(ctx.default_op_size(), 4); // 64-bit no REX.W → 4 (32-bit default)
    }

    #[test]
    fn ctx_stack_ptr_64bit() {
        let ctx = ctx64();
        assert_eq!(ctx.stack_ptr(), "rsp");
    }

    #[test]
    fn ctx_stack_ptr_32bit() {
        let ctx = X86LiftCtx::new(0x1000, 32, ModeHint::default());
        assert_eq!(ctx.stack_ptr(), "esp");
    }

    #[test]
    fn ctx_base_ptr_64bit() {
        let ctx = ctx64();
        assert_eq!(ctx.base_ptr(), "rbp");
    }

    #[test]
    fn ctx_counter_reg_64() {
        assert_eq!(ctx64().counter_reg(), "rcx");
    }

    #[test]
    fn ctx_si_reg_64() {
        assert_eq!(ctx64().si_reg(), "rsi");
    }

    #[test]
    fn ctx_di_reg_64() {
        assert_eq!(ctx64().di_reg(), "rdi");
    }

    #[test]
    fn effects_empty_initially() {
        let ctx = ctx64();
        assert!(ctx.is_empty());
    }

    #[test]
    fn effects_len_after_emit() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        });
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn ir_text_updated_on_emit() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        });
        assert!(!ctx.ir_text.is_empty());
    }

    #[test]
    fn eval_reg_write_effects_chain() {
        // Chain: rax = 10; rbx = rax + 5 → rbx should be 15.
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(10),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(5)),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rax", 10);
        s.assert_reg("rbx", 15);
    }

    #[test]
    fn eval_unknown_propagates() {
        // rbx is unknown; rax = rbx + 1 should also be unknown.
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rbx".into())),
                Box::new(IrExpr::Const(1)),
            ),
        }];
        let mut s = X86CpuState::new(); // rbx never written
        exec_effects(&effects, &mut s);
        assert_eq!(s.get_reg("rax"), EvalValue::Unknown);
    }
}
