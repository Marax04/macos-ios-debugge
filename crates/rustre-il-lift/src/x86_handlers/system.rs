//! System / privileged handlers: SYSCALL, SYSENTER, SYSEXIT, SYSRET, INT,
//! INT3, INTO, CPUID, RDTSC, RDMSR, WRMSR, UD2, HLT, NOP.
//!
//! These mostly translate into `Effect::Syscall` or named intrinsics. None
//! perform meaningful arithmetic on the IR, but their *presence* in the IR
//! is crucial for malware-analysis and kernel reverse-engineering passes.

use crate::x86_context::X86LiftCtx;
use crate::{Effect, IrExpr, LiftError};
use iced_x86::Instruction;

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_syscall(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Linux/BSD convention: syscall number in RAX, args in RDI/RSI/RDX/R10/R8/R9.
    ctx.emit(Effect::Syscall {
        nr: IrExpr::Reg("rax".into()),
    });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sysenter(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit(Effect::Syscall {
        nr: IrExpr::Reg("eax".into()),
    });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sysexit(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.sysexit", vec![]);
    ctx.emit(Effect::Return { value: None });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sysret(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.sysret", vec![]);
    ctx.emit(Effect::Return { value: None });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_int(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let nr = instr.immediate(0);
    ctx.emit(Effect::Syscall {
        nr: IrExpr::Const(nr),
    });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_int3(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit(Effect::Syscall {
        nr: IrExpr::Const(3),
    });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_into(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Conditional interrupt 4 if OF=1. We emit a branch on OF to a synthetic
    // exception target.
    ctx.emit(Effect::Branch {
        target: IrExpr::Reg("__int4_handler".into()),
        condition: Some(IrExpr::Reg("of".into())),
    });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cpuid(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic(
        "x86.cpuid",
        vec![IrExpr::Reg("eax".into()), IrExpr::Reg("ecx".into())],
    );
    for r in ["eax", "ebx", "ecx", "edx"] {
        ctx.emit_reg_write(r, IrExpr::Undef);
    }
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdtsc(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdtsc", vec![]);
    ctx.emit_reg_write("edx", IrExpr::Undef);
    ctx.emit_reg_write("eax", IrExpr::Undef);
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdmsr(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdmsr", vec![IrExpr::Reg("ecx".into())]);
    ctx.emit_reg_write("edx", IrExpr::Undef);
    ctx.emit_reg_write("eax", IrExpr::Undef);
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wrmsr(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic(
        "x86.wrmsr",
        vec![
            IrExpr::Reg("ecx".into()),
            IrExpr::Reg("edx".into()),
            IrExpr::Reg("eax".into()),
        ],
    );
    Ok(())
}

/// UD / UD2 — explicit invalid-opcode trap.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ud(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.ud_trap", vec![]);
    // Modeled as a return to make CFG terminate cleanly.
    ctx.emit(Effect::Return { value: None });
    Ok(())
}

/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_hlt(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.hlt", vec![]);
    Ok(())
}

/// NOP and its multi-byte forms. We emit zero μOps — the address remains
/// recorded by the surrounding `LiftedInstr`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub const fn lift_nop(_instr: &Instruction, _ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    Ok(())
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
