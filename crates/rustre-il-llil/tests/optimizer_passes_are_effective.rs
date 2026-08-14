//! Do `LlilOptimizer`'s passes fire on the IR the REAL lifter produces?
//!
//! # The finding this test exists to pin
//!
//! `LlilInstruction` has two register-write variants: `SetReg { dest:
//! LlilRegister }` and `SetRegister { dest: u32 }`.
//!
//! * `rustre-arch-x86`'s lifter emits `SetReg` **228 times** and `SetRegister`
//!   **zero** times.
//! * `ConstantPropagation` and `StrengthReduction` match on `SetRegister`
//!   **only**.
//! * Every existing test for those passes constructs `SetRegister` inputs.
//!
//! So the passes are green against a shape the real producer never emits. If
//! `LlilOptimizer` were wired into the pipeline, both would silently do nothing
//! on every real function, and their unit tests would keep passing — a
//! self-confirming test, testing the pass against the pass's own assumption
//! rather than against the IR that exists.
//!
//! This is the same class as the defects found in `rustre-arch-x86` this
//! session: ONE fact — "how a register write is represented" — described in two
//! places, and the two do not agree.
//!
//! # Status of the subject
//!
//! `LlilOptimizer` is referenced nowhere outside its own module: it is UNWIRED.
//! That is why this is pinned as a measurement rather than repaired in place —
//! teaching three passes a second IR shape, on a pipeline nothing calls, would
//! be building on sand. Wiring it or deleting it is the real decision, and this
//! test makes it an informed one instead of a guess.

use rustre_il_llil::llil_optimizer::{
    CommonSubexprElimination, ConstantPropagation, DeadCodeElimination, OptimizationPass,
    PeepholeOptimizer, RedundantLoadElimination, StrengthReduction,
};
use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size};

fn reg(n: &str) -> LlilRegister {
    LlilRegister::Concrete(n.to_string())
}

fn annotate(instrs: Vec<LlilInstruction>) -> LlilFunction {
    let mut f = LlilFunction::default();
    f.instructions = instrs
        .into_iter()
        .map(|instr| LlilAnnotatedInstr { instr, ..Default::default() })
        .collect();
    f
}

/// The shape the REAL x86 lifter emits: `SetReg` with a named register.
/// Contains a NOP to eliminate, a constant to propagate, and `rax * 2` to
/// strength-reduce — material for every pass under test.
fn real_shape() -> LlilFunction {
    annotate(vec![
        LlilInstruction::Nop,
        LlilInstruction::SetReg {
            dest: reg("rax"),
            size: Size::QWord,
            value: LlilExpr::Const { value: 7, size: Size::QWord },
        },
        LlilInstruction::SetReg {
            dest: reg("rbx"),
            size: Size::QWord,
            value: LlilExpr::Mul {
                left: Box::new(LlilExpr::RegisterRef { reg: reg("rax"), size: Size::QWord }),
                right: Box::new(LlilExpr::Const { value: 2, size: Size::QWord }),
                size: Size::QWord,
            },
        },
    ])
}

/// The shape the optimizer's own tests use: `SetRegister` with a numeric id.
fn tested_shape() -> LlilFunction {
    annotate(vec![
        LlilInstruction::Nop,
        LlilInstruction::SetRegister {
            dest: 0,
            size: Size::QWord,
            value: LlilExpr::Const { value: 7, size: Size::QWord },
        },
        LlilInstruction::SetRegister {
            dest: 1,
            size: Size::QWord,
            value: LlilExpr::Mul {
                left: Box::new(LlilExpr::RegisterRef { reg: reg("rax"), size: Size::QWord }),
                right: Box::new(LlilExpr::Const { value: 2, size: Size::QWord }),
                size: Size::QWord,
            },
        },
    ])
}

/// Did the pass change the function, or report a change? Structural comparison,
/// so a pass that rewrites without incrementing a counter still counts as
/// effective — the question is "did anything happen", not "was a counter bumped".
fn effective_on(pass: &mut dyn OptimizationPass, mut f: LlilFunction) -> bool {
    let before = format!("{:?}", f.instructions);
    let reported = pass.run(&mut f);
    before != format!("{:?}", f.instructions) || reported > 0
}

#[test]
fn optimizer_passes_fire_on_the_ir_the_real_lifter_emits() {
    let probe = |on_real: bool| -> Vec<(&'static str, bool)> {
        let make = || if on_real { real_shape() } else { tested_shape() };
        vec![
            ("dead_code_elimination", effective_on(&mut DeadCodeElimination::new(), make())),
            ("constant_propagation", effective_on(&mut ConstantPropagation::new(), make())),
            ("strength_reduction", effective_on(&mut StrengthReduction::new(), make())),
            ("peephole", effective_on(&mut PeepholeOptimizer::new(), make())),
            (
                "redundant_load_elimination",
                effective_on(&mut RedundantLoadElimination::new(), make()),
            ),
            (
                "common_subexpression_elimination",
                effective_on(&mut CommonSubexprElimination::new(), make()),
            ),
        ]
    };

    let on_real = probe(true);
    let on_tested = probe(false);

    // PINNED as measured on 2026-07-29.
    //
    // `false` on the REAL shape while `true` on the TESTED shape is the defect
    // this file documents: the pass works only on IR the lifter never produces.
    //
    // The three passes that are false in BOTH columns are registered stubs:
    //   * `constant_propagation` fills an internal map and never writes back;
    //   * `redundant_load_elimination`'s own comment says "no loads eliminated
    //     yet in this stub";
    //   * `common_subexpression_elimination` takes `_func` and returns 0.
    //
    // Any entry flipping to `true` is GOOD NEWS and fails on purpose: update
    // the pin when you implement or re-target a pass.
    let expected_real: &[(&str, bool)] = &[
        ("dead_code_elimination", true),
        ("constant_propagation", false),
        ("strength_reduction", false),
        ("peephole", true),
        ("redundant_load_elimination", false),
        ("common_subexpression_elimination", false),
    ];
    let expected_tested: &[(&str, bool)] = &[
        ("dead_code_elimination", true),
        ("constant_propagation", false),
        ("strength_reduction", true),
        ("peephole", true),
        ("redundant_load_elimination", false),
        ("common_subexpression_elimination", false),
    ];

    assert_eq!(
        on_real, expected_real,
        "effectiveness on the REAL (`SetReg`) IR changed — see the module comment"
    );
    assert_eq!(
        on_tested, expected_tested,
        "effectiveness on the TESTED (`SetRegister`) IR changed — see the module comment"
    );

    // The gap between the two columns IS the finding. Asserting it explicitly
    // means the day someone re-targets a pass, this line stops being true and
    // the test says so, instead of the divergence quietly disappearing.
    let diverging: Vec<&str> = on_real
        .iter()
        .zip(&on_tested)
        .filter(|((_, r), (_, t))| r != t)
        .map(|((n, _), _)| *n)
        .collect();
    assert_eq!(
        diverging,
        vec!["strength_reduction"],
        "the set of passes that work on the tested IR but NOT on the real IR changed"
    );
}
