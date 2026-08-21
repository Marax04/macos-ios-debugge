//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_deobf_opaque::dead_branch_eliminator::{
    Cfg, CfgBlock, CfgInstr, DeadBranch, DeadBranchEliminator,
};

/// ```text
///   0: CondBr(cond, true=1, false=2)
///   1: Jump(2)
///   2: Ret
/// ```
/// The branch in block 0 is always true, so the edge `0 -> 2` dies. Block 2
/// itself does NOT: it is still reached through `0 -> 1 -> 2`.
fn diamond() -> Cfg {
    let mut cfg = Cfg::new(0);

    let mut b0 = CfgBlock::new(0);
    b0.add_instr(CfgInstr::CondBr {
        cond_var: 9,
        true_block: 1,
        false_block: 2,
    });
    cfg.add_block(b0);

    let mut b1 = CfgBlock::new(1);
    b1.add_instr(CfgInstr::Jump(2));
    cfg.add_block(b1);

    let mut b2 = CfgBlock::new(2);
    b2.add_instr(CfgInstr::Ret);
    cfg.add_block(b2);

    cfg.rebuild_edges();
    cfg
}

const fn always_true_branch() -> DeadBranch {
    DeadBranch {
        block_id: 0,
        instr_idx: usize::MAX,
        always_true: true,
        live_target: 1,
        dead_target: 2,
        address_hint: None,
        confidence: 1.0,
    }
}

// ── removing a still-reachable block corrupts the CFG ──────────────────────

/// `initially_dead.insert(db.dead_target)` seeds the dead set unconditionally,
/// so block 2 enters it as "initially dead" and is never re-examined after
/// `rebuild_edges()` — even though it then has `preds == [1]`.
///
/// The result is not merely a wrong answer: block 2 is REMOVED while block 1
/// still jumps to it, leaving the CFG referring to a block that no longer
/// exists. Only the EDGE `0 -> 2` dies here, never the block.
#[test]
fn a_block_still_reachable_by_another_path_is_kept() {
    let mut cfg = diamond();
    let result = DeadBranchEliminator::new().eliminate(&mut cfg, &[always_true_branch()]);

    assert!(
        cfg.blocks.iter().any(|b| b.id == 2),
        "block 2 is reachable via 0 -> 1 -> 2 and must survive; it was removed \
         ({} blocks removed)",
        result.blocks_removed
    );
}

/// The CFG must stay internally consistent: every successor named by a
/// surviving block must exist. This is the property the removal broke.
#[test]
fn no_surviving_block_jumps_to_a_missing_block() {
    let mut cfg = diamond();
    DeadBranchEliminator::new().eliminate(&mut cfg, &[always_true_branch()]);

    let ids: Vec<u32> = cfg.blocks.iter().map(|b| b.id).collect();
    for block in &cfg.blocks {
        for instr in &block.instrs {
            for succ in instr.successors() {
                assert!(
                    ids.contains(&succ),
                    "block {} jumps to block {succ}, which is not in the CFG \
                     (blocks present: {ids:?})",
                    block.id
                );
            }
        }
    }
}

/// The dead EDGE must still be gone: block 0 is now an unconditional jump to 1.
#[test]
fn the_dead_edge_is_still_removed() {
    let mut cfg = diamond();
    let result = DeadBranchEliminator::new().eliminate(&mut cfg, &[always_true_branch()]);

    assert_eq!(result.branches_patched, 1);
    let b0 = cfg.blocks.iter().find(|b| b.id == 0).expect("entry survives");
    assert!(
        matches!(b0.instrs.last(), Some(CfgInstr::Jump(1))),
        "the conditional became an unconditional jump to the live target"
    );
}

/// A genuinely unreachable block must still be removed — the fix must not
/// disable the pass.
#[test]
fn a_genuinely_unreachable_block_is_still_removed() {
    let mut cfg = Cfg::new(0);

    let mut b0 = CfgBlock::new(0);
    b0.add_instr(CfgInstr::CondBr {
        cond_var: 9,
        true_block: 1,
        false_block: 2,
    });
    cfg.add_block(b0);

    let mut b1 = CfgBlock::new(1);
    b1.add_instr(CfgInstr::Ret);
    cfg.add_block(b1);

    // Block 2 is reached ONLY through the dead edge.
    let mut b2 = CfgBlock::new(2);
    b2.add_instr(CfgInstr::Ret);
    cfg.add_block(b2);

    cfg.rebuild_edges();
    DeadBranchEliminator::new().eliminate(&mut cfg, &[always_true_branch()]);

    assert!(
        !cfg.blocks.iter().any(|b| b.id == 2),
        "block 2 had no other predecessor and must go"
    );
}

// ── an "always true" predicate that is false for negative x ───────────────

use rustre_deobf_opaque::{build_known_patterns, OpaqueExpr, PredicateValue};

fn b(e: OpaqueExpr) -> Box<OpaqueExpr> {
    Box::new(e)
}

/// `(x | 1) % 2 == 1`.
fn or_one_mod_two() -> OpaqueExpr {
    OpaqueExpr::Eq(
        b(OpaqueExpr::Mod(
            b(OpaqueExpr::Or(
                b(OpaqueExpr::Var("x".to_string())),
                b(OpaqueExpr::Const(1)),
            )),
            b(OpaqueExpr::Const(2)),
        )),
        b(OpaqueExpr::Const(1)),
    )
}

/// `(x | 1) & 1 == 1`.
fn or_one_and_one() -> OpaqueExpr {
    OpaqueExpr::Eq(
        b(OpaqueExpr::And(
            b(OpaqueExpr::Or(
                b(OpaqueExpr::Var("x".to_string())),
                b(OpaqueExpr::Const(1)),
            )),
            b(OpaqueExpr::Const(1)),
        )),
        b(OpaqueExpr::Const(1)),
    )
}

fn classify(e: &OpaqueExpr) -> Option<PredicateValue> {
    build_known_patterns()
        .iter()
        .find_map(|p| (p.check)(e))
}

/// The pattern treats `(x|1)%2==1` and `(x|1)&1==1` as the same fact. They are
/// not: `%` follows the SIGN of its left operand in Rust (and C), so for
/// x = -3 we get `-3 | 1 == -3` and `-3 % 2 == -1`, which is not 1.
///
/// Declaring it `AlwaysTrue` lets a deobfuscator delete a branch that really is
/// taken whenever the variable is negative — it does not merely mislabel the
/// predicate, it removes live code.
#[test]
fn the_modulo_form_is_not_always_true() {
    // The claim, checked directly on the arithmetic it is about.
    let x: i64 = -3;
    assert_eq!(x | 1, -3);
    assert_eq!((x | 1) % 2, -1, "the remainder follows the sign of x");

    assert_ne!(
        classify(&or_one_mod_two()),
        Some(PredicateValue::AlwaysTrue),
        "(x|1)%2==1 is false for every negative odd x, so it is not a tautology"
    );
}

/// The bitwise form IS a tautology for every x, signed or not: `| 1` sets bit
/// 0 and `& 1` reads it back. The fix must not throw this one away.
#[test]
fn the_bitwise_form_is_still_always_true() {
    assert_eq!(
        classify(&or_one_and_one()),
        Some(PredicateValue::AlwaysTrue),
        "(x|1)&1==1 holds for every x, including negative ones"
    );
    for x in [-3i64, -1, 0, 1, 7, i64::MIN, i64::MAX] {
        assert_eq!((x | 1) & 1, 1, "bit 0 of x|1 is set for x = {x}");
    }
}

// ── two distinct unknowns are not "equal" ─────────────────────────────────

use rustre_deobf_opaque::constant_propagator::{
    CmpKind, ConstLattice, ConstPropPass, FoldResult, IrInstr, PropState,
};

/// `fold_cmp`'s self-comparison shortcut guards on `lhs == rhs`, comparing the
/// LATTICE VALUES rather than the variables. Two DISTINCT variables that are
/// both unknown are both `Top`, so the guard fires and `Eq` folds to 1 —
/// "these two unknowns are equal", which is false in general.
///
/// The comment says "self-comparisons", i.e. `x == x`, but by the time
/// `fold_cmp` runs it only has lattice values and cannot tell "the same
/// variable" from "two variables that happen to both be unknown".
#[test]
fn two_distinct_unknowns_do_not_compare_equal() {
    let mut state = PropState::new();
    state.set(1, ConstLattice::Top);
    state.set(2, ConstLattice::Top);

    let cmp = IrInstr::Cmp {
        dst: 3,
        op: CmpKind::Eq,
        lhs: 1,
        rhs: 2,
    };

    let r = ConstPropPass::new().fold_instruction(&cmp, &state);
    assert!(
        matches!(r, FoldResult::NotFolded),
        "vars 1 and 2 are different unknowns; their equality is data-dependent,          got {r:?}"
    );
}

/// A genuine self-comparison `x == x` must still fold to true.
#[test]
fn a_variable_compared_with_itself_still_folds() {
    let mut state = PropState::new();
    state.set(1, ConstLattice::Top);

    let cmp = IrInstr::Cmp {
        dst: 3,
        op: CmpKind::Eq,
        lhs: 1,
        rhs: 1,
    };

    let r = ConstPropPass::new().fold_instruction(&cmp, &state);
    assert!(
        matches!(r, FoldResult::Folded(1)),
        "x == x is true whatever x is, got {r:?}"
    );
}

/// And `x != x` must still fold to false.
#[test]
fn a_variable_differs_from_itself_never() {
    let mut state = PropState::new();
    state.set(1, ConstLattice::Top);

    let cmp = IrInstr::Cmp {
        dst: 3,
        op: CmpKind::Ne,
        lhs: 1,
        rhs: 1,
    };

    let r = ConstPropPass::new().fold_instruction(&cmp, &state);
    assert!(matches!(r, FoldResult::Folded(0)), "got {r:?}");
}

/// Two known constants must still be compared normally.
#[test]
fn two_known_constants_still_compare() {
    let mut state = PropState::new();
    state.set(1, ConstLattice::Const(7));
    state.set(2, ConstLattice::Const(7));

    let cmp = IrInstr::Cmp {
        dst: 3,
        op: CmpKind::Eq,
        lhs: 1,
        rhs: 2,
    };

    let r = ConstPropPass::new().fold_instruction(&cmp, &state);
    assert!(matches!(r, FoldResult::Folded(1)), "got {r:?}");
}
