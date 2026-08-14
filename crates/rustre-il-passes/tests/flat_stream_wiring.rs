//! Low-level contract test: every pass in `PassManager::standard()` iterates
//! `func.blocks` and IGNORES the flat `LlilFunction::instructions` field.
//!
//! History: `rustre-decompiler::optimize_lifted_llil` originally fed the
//! lifted stream into `instructions` only, which made the whole opt-in
//! pipeline a provable no-op — this test was the proof. The decompiler
//! wiring has since been fixed to build `func.blocks` (splitting at branch
//! targets / after terminators) before running the passes, but the fact this
//! test pins is still true and load-bearing: any caller that populates only
//! `instructions` gets NO optimization. If a future pass starts consuming
//! `instructions`, this test must be revisited together with
//! `optimize_lifted_llil`'s flatten/regroup step.

use rustre_core::address::Address;
use rustre_il_llil::{
    LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size,
};
use rustre_il_passes::PassManager;

fn ai(addr: u64, instr: LlilInstruction) -> LlilAnnotatedInstr {
    LlilAnnotatedInstr { address: Address::new(addr), size: 8, length: 4, instr }
}

fn reg(name: &str) -> LlilRegister {
    LlilRegister::Concrete(name.to_string())
}

fn regref(name: &str) -> LlilExpr {
    LlilExpr::RegisterRef { reg: reg(name), size: Size::QWord }
}

/// A do/while-shaped flat stream: body, compare feeding a backward CondJump.
/// This is the shape whose loop condition the corpus diff shows being lost.
fn dowhile_flat_stream() -> Vec<LlilAnnotatedInstr> {
    vec![
        // 0x1000: rsi = rsi + 8   (induction)
        ai(
            0x1000,
            LlilInstruction::SetReg {
                dest: reg("rsi"),
                size: Size::QWord,
                value: LlilExpr::AddT(
                    Box::new(regref("rsi")),
                    Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
                    Size::QWord,
                ),
            },
        ),
        // 0x1004: tmp0 = rsi <= rdi (the comparison the condition needs)
        ai(
            0x1004,
            LlilInstruction::SetReg {
                dest: reg("tmp0"),
                size: Size::QWord,
                value: LlilExpr::CmpUle(Box::new(regref("rsi")), Box::new(regref("rdi"))),
            },
        ),
        // 0x1007: if (tmp0) goto 0x1000 else 0x1009
        ai(
            0x1007,
            LlilInstruction::CondJump {
                cond: regref("tmp0"),
                true_dest: Address::new(0x1000),
                false_dest: Address::new(0x1009),
            },
        ),
        ai(0x1009, LlilInstruction::Ret),
    ]
}

/// The standard pipeline run over `instructions` (blocks empty — the exact
/// decompiler wiring shape) must either optimize that stream or leave it
/// alone; it must never report "changed" without touching it, and must never
/// drop the comparison that feeds the CondJump.
#[test]
fn standard_pipeline_on_flat_instruction_stream_is_a_noop() {
    let mut func = LlilFunction::new(Address::new(0x1000));
    func.instructions = dowhile_flat_stream();
    let before = func.instructions.clone();

    let ctx = PassManager::standard().run(&mut func);

    assert_eq!(
        format!("{:?}", func.instructions),
        format!("{before:?}"),
        "flat instruction stream was modified"
    );
    assert!(
        !ctx.changed,
        "pipeline reported changed=true on a function whose blocks are empty"
    );
}
