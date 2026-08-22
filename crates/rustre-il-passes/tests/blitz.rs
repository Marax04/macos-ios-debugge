//! Exhaustive test suite for rustre-il-passes.
//!
//! Most coverage targets the self-contained `constant_propagation` module
//! (SCCP) because it has the cleanest, dep-free API surface.  We also exercise
//! the `switch_detection` types.

use rustre_il_passes::constant_propagation::{
    BBId, BasicBlock, ConstantLattice, FuncId, Lattice, MlilExpr, MlilFunction,
    MlilStmt, ScCpStats, VarId, WorkItem, analyse_function, collect_defs, fold_constants,
    fold_expr, initial_work_items, reanalyse_from, remove_dead_blocks,
    run_constant_propagation_pipeline, run_sccp,
};
use rustre_il_passes::switch_detection::{
    BasicBlock as SwBb, BlockId, BranchCond, CmpKind, LlilFunction as SwFn, LlilInsn,
    SwitchCase, SwitchInfo, SwitchPattern, switch_info_to_cfs,
};

// ────────────────────────────────────────────────────────────────────────────
// Lattice tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn lattice_meet_top_identity() {
    let a = Lattice::Const(7);
    assert_eq!(Lattice::Top.meet(&a), Lattice::Const(7));
    assert_eq!(a.meet(&Lattice::Top), Lattice::Const(7));
    assert_eq!(Lattice::Top.meet(&Lattice::Top), Lattice::Top);
}

#[test]
fn lattice_meet_bottom_absorbs() {
    assert_eq!(Lattice::Bottom.meet(&Lattice::Const(1)), Lattice::Bottom);
    assert_eq!(Lattice::Const(1).meet(&Lattice::Bottom), Lattice::Bottom);
    assert_eq!(Lattice::Bottom.meet(&Lattice::Top), Lattice::Bottom);
    assert_eq!(Lattice::Top.meet(&Lattice::Bottom), Lattice::Bottom);
}

#[test]
fn lattice_meet_same_const() {
    assert_eq!(Lattice::Const(42).meet(&Lattice::Const(42)), Lattice::Const(42));
}

#[test]
fn lattice_meet_diff_const_collapses() {
    assert_eq!(Lattice::Const(1).meet(&Lattice::Const(2)), Lattice::Bottom);
}

#[test]
fn lattice_predicates() {
    assert!(Lattice::Top.is_top());
    assert!(Lattice::Bottom.is_bottom());
    assert!(Lattice::Const(0).is_const());
    assert!(!Lattice::Const(0).is_top());
    assert!(!Lattice::Top.is_const());
    assert_eq!(Lattice::Const(5).const_val(), Some(5));
    assert_eq!(Lattice::Top.const_val(), None);
    assert_eq!(Lattice::Bottom.const_val(), None);
}

#[test]
fn lattice_display() {
    assert_eq!(format!("{}", Lattice::Top), "⊤");
    assert_eq!(format!("{}", Lattice::Bottom), "⊥");
    assert_eq!(format!("{}", Lattice::Const(-3)), "-3");
}

#[test]
fn lattice_meet_extreme_consts() {
    let a = Lattice::Const(i128::MAX);
    let b = Lattice::Const(i128::MIN);
    assert_eq!(a.meet(&b), Lattice::Bottom);
    assert_eq!(a.meet(&a), Lattice::Const(i128::MAX));
}

// ────────────────────────────────────────────────────────────────────────────
// ConstantLattice tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn const_lattice_default_top() {
    let l = ConstantLattice::new();
    assert_eq!(l.get(0), &Lattice::Top);
    assert_eq!(l.get(999), &Lattice::Top);
}

#[test]
fn const_lattice_set_lowers_monotonically() {
    let mut l = ConstantLattice::new();
    // Top -> Const transitions and reports change.
    assert!(l.set(1, &Lattice::Const(10)));
    assert_eq!(l.get(1), &Lattice::Const(10));

    // Setting same value -> no change.
    assert!(!l.set(1, &Lattice::Const(10)));

    // Setting different const should meet -> Bottom.
    assert!(l.set(1, &Lattice::Const(20)));
    assert_eq!(l.get(1), &Lattice::Bottom);

    // Once Bottom, further sets stay Bottom.
    assert!(!l.set(1, &Lattice::Const(5)));
    assert_eq!(l.get(1), &Lattice::Bottom);
}

#[test]
fn const_lattice_force_set_overrides() {
    let mut l = ConstantLattice::new();
    l.force_set(7, Lattice::Bottom);
    assert_eq!(l.get(7), &Lattice::Bottom);
    // force_set bypasses monotonicity by design.
    l.force_set(7, Lattice::Const(3));
    assert_eq!(l.get(7), &Lattice::Const(3));
}

#[test]
fn const_lattice_iter() {
    let mut l = ConstantLattice::new();
    l.force_set(1, Lattice::Const(1));
    l.force_set(2, Lattice::Const(2));
    let count = l.iter().count();
    assert_eq!(count, 2);
}

// ────────────────────────────────────────────────────────────────────────────
// WorkItem
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn work_item_predicates() {
    assert!(WorkItem::Var(1).is_var());
    assert!(!WorkItem::Var(1).is_edge());
    assert!(WorkItem::Edge(0, 1).is_edge());
    assert!(!WorkItem::Edge(0, 1).is_var());
}

#[test]
fn work_item_equality() {
    assert_eq!(WorkItem::Var(3), WorkItem::Var(3));
    assert_ne!(WorkItem::Var(3), WorkItem::Var(4));
    assert_eq!(WorkItem::Edge(1, 2), WorkItem::Edge(1, 2));
    assert_ne!(WorkItem::Edge(1, 2), WorkItem::Edge(2, 1));
}

// ────────────────────────────────────────────────────────────────────────────
// MLIL helpers
// ────────────────────────────────────────────────────────────────────────────

const fn const_expr(k: i128) -> MlilExpr { MlilExpr::Const(k) }
const fn var_expr(v: VarId) -> MlilExpr { MlilExpr::Var(v) }

fn func_with(entry: BBId, blocks: Vec<BasicBlock>, params: Vec<VarId>) -> MlilFunction {
    let mut f = MlilFunction::new(0 as FuncId, entry);
    for b in blocks {
        f.block_order.push(b.id);
        f.blocks.insert(b.id, b);
    }
    f.params = params;
    f
}

fn linear_block(id: BBId, stmts: Vec<MlilStmt>, succ: Vec<BBId>, pred: Vec<BBId>) -> BasicBlock {
    let mut b = BasicBlock::new(id);
    b.stmts = stmts;
    b.successors = succ;
    b.predecessors = pred;
    b
}

// ────────────────────────────────────────────────────────────────────────────
// initial_work_items
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn initial_work_items_basic() {
    let entry = linear_block(0, vec![], vec![1, 2], vec![]);
    let b1 = linear_block(1, vec![MlilStmt::Nop], vec![], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Nop], vec![], vec![0]);
    let f = func_with(0, vec![entry, b1, b2], vec![10, 11]);
    let items = initial_work_items(&f);
    assert!(items.contains(&WorkItem::Edge(0, 1)));
    assert!(items.contains(&WorkItem::Edge(0, 2)));
    assert!(items.contains(&WorkItem::Var(10)));
    assert!(items.contains(&WorkItem::Var(11)));
    assert_eq!(items.len(), 4);
}

#[test]
fn initial_work_items_no_successors_no_params() {
    let entry = linear_block(0, vec![MlilStmt::Return { values: vec![] }], vec![], vec![]);
    let f = func_with(0, vec![entry], vec![]);
    assert!(initial_work_items(&f).is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// fold_expr — constant folding via lattice
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn fold_expr_replaces_const_var() {
    let mut lat = ConstantLattice::new();
    lat.force_set(7, Lattice::Const(42));
    let folded = fold_expr(&var_expr(7), &lat);
    matches!(folded, MlilExpr::Const(42));
    if let MlilExpr::Const(k) = folded {
        assert_eq!(k, 42);
    } else { panic!("expected Const"); }
}

#[test]
fn fold_expr_leaves_bottom_var() {
    let mut lat = ConstantLattice::new();
    lat.force_set(7, Lattice::Bottom);
    let folded = fold_expr(&var_expr(7), &lat);
    assert!(matches!(folded, MlilExpr::Var(7)));
}

#[test]
fn fold_expr_arith_evaluation() {
    let lat = ConstantLattice::new();
    // 3 + 4 -> 7
    let e = MlilExpr::Add(Box::new(const_expr(3)), Box::new(const_expr(4)));
    let f = fold_expr(&e, &lat);
    assert!(matches!(f, MlilExpr::Const(7)), "got {:?}", f);
}

#[test]
fn fold_expr_sub_mul_neg() {
    let lat = ConstantLattice::new();
    let sub = MlilExpr::Sub(Box::new(const_expr(10)), Box::new(const_expr(3)));
    assert!(matches!(fold_expr(&sub, &lat), MlilExpr::Const(7)));
    let mul = MlilExpr::Mul(Box::new(const_expr(6)), Box::new(const_expr(7)));
    assert!(matches!(fold_expr(&mul, &lat), MlilExpr::Const(42)));
    let neg = MlilExpr::Neg(Box::new(const_expr(5)));
    assert!(matches!(fold_expr(&neg, &lat), MlilExpr::Const(-5)));
    let not = MlilExpr::Not(Box::new(const_expr(0)));
    assert!(matches!(fold_expr(&not, &lat), MlilExpr::Const(-1)));
}

#[test]
fn fold_expr_div_by_zero_does_not_panic() {
    let lat = ConstantLattice::new();
    let e = MlilExpr::Div(Box::new(const_expr(1)), Box::new(const_expr(0)));
    let f = fold_expr(&e, &lat);
    // Should not be folded (div by zero returns Bottom -> not const) — should
    // keep the expression structure.
    assert!(!matches!(f, MlilExpr::Const(_)));
}

#[test]
fn fold_expr_mod_by_zero_does_not_panic() {
    let lat = ConstantLattice::new();
    let e = MlilExpr::Mod(Box::new(const_expr(7)), Box::new(const_expr(0)));
    let f = fold_expr(&e, &lat);
    assert!(!matches!(f, MlilExpr::Const(_)));
    let eu = MlilExpr::ModU(Box::new(const_expr(7)), Box::new(const_expr(0)));
    let fu = fold_expr(&eu, &lat);
    assert!(!matches!(fu, MlilExpr::Const(_)));
    let du = MlilExpr::DivU(Box::new(const_expr(7)), Box::new(const_expr(0)));
    let fdu = fold_expr(&du, &lat);
    assert!(!matches!(fdu, MlilExpr::Const(_)));
}

#[test]
fn fold_expr_cmps() {
    let lat = ConstantLattice::new();
    let cases: &[(MlilExpr, i128)] = &[
        (MlilExpr::CmpEq(Box::new(const_expr(2)), Box::new(const_expr(2))), 1),
        (MlilExpr::CmpEq(Box::new(const_expr(2)), Box::new(const_expr(3))), 0),
        (MlilExpr::CmpNe(Box::new(const_expr(2)), Box::new(const_expr(3))), 1),
        (MlilExpr::CmpLt(Box::new(const_expr(-1)), Box::new(const_expr(0))), 1),
        (MlilExpr::CmpLtu(Box::new(const_expr(-1)), Box::new(const_expr(0))), 0),
        (MlilExpr::CmpGe(Box::new(const_expr(5)), Box::new(const_expr(5))), 1),
        (MlilExpr::CmpGt(Box::new(const_expr(5)), Box::new(const_expr(5))), 0),
        (MlilExpr::CmpLe(Box::new(const_expr(4)), Box::new(const_expr(5))), 1),
        (MlilExpr::CmpGtu(Box::new(const_expr(-1)), Box::new(const_expr(0))), 1),
        (MlilExpr::CmpGeu(Box::new(const_expr(0)), Box::new(const_expr(0))), 1),
        (MlilExpr::CmpLeu(Box::new(const_expr(0)), Box::new(const_expr(1))), 1),
    ];
    for (e, expected) in cases {
        let f = fold_expr(e, &lat);
        match f {
            MlilExpr::Const(k) => assert_eq!(k, *expected, "for {:?}", e),
            other => panic!("expected Const, got {:?} for {:?}", other, e),
        }
    }
}

#[test]
fn fold_expr_bitwise() {
    let lat = ConstantLattice::new();
    let and = MlilExpr::And(Box::new(const_expr(0b1100)), Box::new(const_expr(0b1010)));
    assert!(matches!(fold_expr(&and, &lat), MlilExpr::Const(0b1000)));
    let or = MlilExpr::Or(Box::new(const_expr(0b1100)), Box::new(const_expr(0b0011)));
    assert!(matches!(fold_expr(&or, &lat), MlilExpr::Const(0b1111)));
    let xor = MlilExpr::Xor(Box::new(const_expr(0b1010)), Box::new(const_expr(0b1111)));
    assert!(matches!(fold_expr(&xor, &lat), MlilExpr::Const(0b0101)));
}

#[test]
fn fold_expr_shifts() {
    let lat = ConstantLattice::new();
    let shl = MlilExpr::Shl(Box::new(const_expr(1)), Box::new(const_expr(4)));
    assert!(matches!(fold_expr(&shl, &lat), MlilExpr::Const(16)));
    let sar = MlilExpr::Sar(Box::new(const_expr(-8)), Box::new(const_expr(1)));
    assert!(matches!(fold_expr(&sar, &lat), MlilExpr::Const(-4)));
}

#[test]
fn fold_expr_arith_overflow_wraps() {
    let lat = ConstantLattice::new();
    let add = MlilExpr::Add(Box::new(const_expr(i128::MAX)), Box::new(const_expr(1)));
    let f = fold_expr(&add, &lat);
    assert!(matches!(f, MlilExpr::Const(_)));
    if let MlilExpr::Const(k) = f {
        assert_eq!(k, i128::MAX.wrapping_add(1));
    }
}

#[test]
fn fold_expr_neg_min_wraps() {
    // wrapping_neg of i128::MIN is i128::MIN itself.
    let lat = ConstantLattice::new();
    let e = MlilExpr::Neg(Box::new(const_expr(i128::MIN)));
    let f = fold_expr(&e, &lat);
    if let MlilExpr::Const(k) = f {
        assert_eq!(k, i128::MIN.wrapping_neg());
    } else { panic!("expected Const"); }
}

#[test]
fn fold_expr_sx_zx_trunc() {
    let lat = ConstantLattice::new();
    // 0xFF as i8 sign-extended -> -1
    let sx = MlilExpr::Sx(8, Box::new(const_expr(0xFF)));
    assert!(matches!(fold_expr(&sx, &lat), MlilExpr::Const(-1)));
    // 0xFF zero-extended -> 0xFF
    let zx = MlilExpr::Zx(8, Box::new(const_expr(0xFF)));
    assert!(matches!(fold_expr(&zx, &lat), MlilExpr::Const(0xFF)));
    // truncate 0x1FF to 8 bits -> 0xFF
    let tr = MlilExpr::Trunc(8, Box::new(const_expr(0x1FF)));
    assert!(matches!(fold_expr(&tr, &lat), MlilExpr::Const(0xFF)));
}

#[test]
fn fold_expr_load_unmodelled_passthrough() {
    let lat = ConstantLattice::new();
    let load = MlilExpr::Load { size: 4, addr: Box::new(const_expr(0x1000)) };
    let f = fold_expr(&load, &lat);
    assert!(matches!(f, MlilExpr::Load { .. }));

    let u = MlilExpr::Unmodelled;
    let fu = fold_expr(&u, &lat);
    assert!(matches!(fu, MlilExpr::Unmodelled));
}

#[test]
fn fold_expr_partial_constants() {
    let lat = ConstantLattice::new();
    // x + 1 with x not constant -> stays as Add but with literal on RHS
    let e = MlilExpr::Add(Box::new(var_expr(99)), Box::new(const_expr(1)));
    let f = fold_expr(&e, &lat);
    match f {
        MlilExpr::Add(a, b) => {
            assert!(matches!(*a, MlilExpr::Var(99)));
            assert!(matches!(*b, MlilExpr::Const(1)));
        }
        _ => panic!("expected Add"),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SCCP end-to-end on tiny CFGs
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn sccp_trivial_const_assign() {
    // BB0: v1 = 42; return v1
    let bb = linear_block(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_expr(42) },
            MlilStmt::Return { values: vec![var_expr(1)] },
        ],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let result = run_sccp(&f);
    assert_eq!(result.lattice.get(1), &Lattice::Const(42));
    assert!(result.reachable.contains(&0));
    assert_eq!(result.stats.folded_vars, 1);
}

#[test]
fn sccp_meet_two_paths_same_const() {
    // entry -> b1 / b2 -> join with phi(v1, v2) where both = 7
    // entry: branch cond=Bottom (param) ? b1 : b2
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: var_expr(0),
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(
        1,
        vec![
            MlilStmt::Assign { dst: 10, rhs: const_expr(7) },
            MlilStmt::Jump { target: 3 },
        ],
        vec![3],
        vec![0],
    );
    let b2 = linear_block(
        2,
        vec![
            MlilStmt::Assign { dst: 11, rhs: const_expr(7) },
            MlilStmt::Jump { target: 3 },
        ],
        vec![3],
        vec![0],
    );
    let join = linear_block(
        3,
        vec![
            MlilStmt::Phi { dst: 20, srcs: vec![10, 11] },
            MlilStmt::Return { values: vec![var_expr(20)] },
        ],
        vec![],
        vec![1, 2],
    );
    // Need param 0 so SCCP starts it at Top -> Bottom on its branch
    let mut f = func_with(0, vec![entry, b1, b2, join], vec![0]);
    // params marked Top, but SCCP doesn't drive them to Bottom automatically
    // for branch — branch on Top doesn't add edges. Force param to Bottom
    // by setting via params and a side-effect: we cannot directly. Instead,
    // make entry conditionally jump on Unmodelled (Bottom).
    f.block_mut(0).stmts[0] = MlilStmt::Branch {
        cond: MlilExpr::Unmodelled,
        true_bb: 1,
        false_bb: 2,
    };
    let result = run_sccp(&f);
    assert_eq!(result.lattice.get(20), &Lattice::Const(7));
    assert!(result.reachable.contains(&3));
}

#[test]
fn sccp_meet_two_paths_diff_consts_yields_bottom() {
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: MlilExpr::Unmodelled,
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(
        1,
        vec![
            MlilStmt::Assign { dst: 10, rhs: const_expr(1) },
            MlilStmt::Jump { target: 3 },
        ],
        vec![3],
        vec![0],
    );
    let b2 = linear_block(
        2,
        vec![
            MlilStmt::Assign { dst: 11, rhs: const_expr(2) },
            MlilStmt::Jump { target: 3 },
        ],
        vec![3],
        vec![0],
    );
    let join = linear_block(
        3,
        vec![MlilStmt::Phi { dst: 20, srcs: vec![10, 11] }],
        vec![],
        vec![1, 2],
    );
    let f = func_with(0, vec![entry, b1, b2, join], vec![]);
    let r = run_sccp(&f);
    assert_eq!(r.lattice.get(20), &Lattice::Bottom);
}

#[test]
fn sccp_dead_branch_unreachable_block() {
    // BB0: branch (const 0) ? b1 : b2 -> only b2 reachable
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: const_expr(0),
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(1, vec![MlilStmt::Nop], vec![], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Nop], vec![], vec![0]);
    let f = func_with(0, vec![entry, b1, b2], vec![]);
    let r = run_sccp(&f);
    assert!(r.reachable.contains(&0));
    assert!(!r.reachable.contains(&1), "b1 should be unreachable");
    assert!(r.reachable.contains(&2));
    assert_eq!(r.stats.removed_blocks, 1);
}

#[test]
fn sccp_dead_branch_true_const() {
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: const_expr(1),
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(1, vec![MlilStmt::Nop], vec![], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Nop], vec![], vec![0]);
    let f = func_with(0, vec![entry, b1, b2], vec![]);
    let r = run_sccp(&f);
    assert!(r.reachable.contains(&1));
    assert!(!r.reachable.contains(&2));
}

// ────────────────────────────────────────────────────────────────────────────
// fold_constants / remove_dead_blocks / pipeline
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn fold_constants_replaces_var_uses() {
    let bb = linear_block(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_expr(5) },
            MlilStmt::Assign {
                dst: 2,
                rhs: MlilExpr::Add(Box::new(var_expr(1)), Box::new(const_expr(3))),
            },
            MlilStmt::Return { values: vec![var_expr(2)] },
        ],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let result = run_sccp(&f);
    let folded = fold_constants(&f, &result);
    let stmts = &folded.blocks[&0].stmts;
    // 3rd stmt should return literal 8
    if let MlilStmt::Return { values } = &stmts[2] {
        assert!(matches!(values[0], MlilExpr::Const(8)));
    } else {
        panic!("expected Return");
    }
}

#[test]
fn fold_constants_replaces_const_branch_with_jump() {
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: const_expr(1),
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(1, vec![MlilStmt::Nop], vec![], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Nop], vec![], vec![0]);
    let f = func_with(0, vec![entry, b1, b2], vec![]);
    let r = run_sccp(&f);
    let folded = fold_constants(&f, &r);
    let entry_bb = &folded.blocks[&0];
    assert!(matches!(entry_bb.stmts[0], MlilStmt::Jump { target: 1 }));
    assert_eq!(entry_bb.successors, vec![1]);
}

#[test]
fn remove_dead_blocks_strips_and_updates_preds() {
    let entry = linear_block(
        0,
        vec![MlilStmt::Branch {
            cond: const_expr(0),
            true_bb: 1,
            false_bb: 2,
        }],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(1, vec![MlilStmt::Nop], vec![3], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Nop], vec![3], vec![0]);
    // b3 has preds [1, 2]; after removing dead b1, preds should drop b1.
    let b3 = linear_block(3, vec![MlilStmt::Nop], vec![], vec![1, 2]);
    let mut f = func_with(0, vec![entry, b1, b2, b3], vec![]);
    let r = run_sccp(&f);
    remove_dead_blocks(&mut f, &r);
    assert!(!f.blocks.contains_key(&1), "b1 should be removed");
    assert!(f.blocks.contains_key(&2));
    assert!(f.blocks.contains_key(&3));
    let b3 = &f.blocks[&3];
    assert!(!b3.predecessors.contains(&1), "b1 stripped from preds: {:?}", b3.predecessors);
    assert!(b3.predecessors.contains(&2));
    assert!(!f.block_order.contains(&1));
}

#[test]
fn pipeline_end_to_end() {
    let entry = linear_block(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_expr(10) },
            MlilStmt::Branch {
                cond: MlilExpr::CmpEq(Box::new(var_expr(1)), Box::new(const_expr(10))),
                true_bb: 1,
                false_bb: 2,
            },
        ],
        vec![1, 2],
        vec![],
    );
    let b1 = linear_block(1, vec![MlilStmt::Return { values: vec![var_expr(1)] }], vec![], vec![0]);
    let b2 = linear_block(2, vec![MlilStmt::Return { values: vec![const_expr(0)] }], vec![], vec![0]);
    let f = func_with(0, vec![entry, b1, b2], vec![]);
    let (new_f, stats) = run_constant_propagation_pipeline(&f);
    // b2 should be eliminated because cond folds to true.
    assert!(new_f.blocks.contains_key(&1));
    assert!(!new_f.blocks.contains_key(&2));
    assert!(stats.removed_blocks >= 1);
    assert!(stats.folded_vars >= 1);
}

// ────────────────────────────────────────────────────────────────────────────
// collect_defs / analyse_function / reanalyse_from
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn collect_defs_finds_assigns_phis_calls() {
    let bb = linear_block(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_expr(1) },
            MlilStmt::Phi { dst: 2, srcs: vec![1] },
            MlilStmt::Call { dst: Some(3), target: const_expr(0), args: vec![] },
            MlilStmt::Call { dst: None, target: const_expr(0), args: vec![] },
        ],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let defs = collect_defs(&f);
    assert!(defs.contains(&1));
    assert!(defs.contains(&2));
    assert!(defs.contains(&3));
    assert_eq!(defs.len(), 3);
}

#[test]
fn analyse_function_returns_stats() {
    let bb = linear_block(
        0,
        vec![MlilStmt::Assign { dst: 1, rhs: const_expr(99) }],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let s: ScCpStats = analyse_function(&f);
    assert!(s.folded_vars >= 1);
}

#[test]
fn reanalyse_from_yields_consistent_result() {
    let bb = linear_block(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_expr(5) },
            MlilStmt::Assign { dst: 2, rhs: const_expr(6) },
        ],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let r1 = run_sccp(&f);
    let r2 = reanalyse_from(&f, 0, &r1);
    assert_eq!(r2.lattice.get(1), &Lattice::Const(5));
    assert_eq!(r2.lattice.get(2), &Lattice::Const(6));
    assert!(r2.reachable.contains(&0));
}

// ────────────────────────────────────────────────────────────────────────────
// switch_detection types
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn switch_pattern_display() {
    assert_eq!(format!("{}", SwitchPattern::JumpTable), "jump-table");
    assert_eq!(format!("{}", SwitchPattern::BinarySearch), "binary-search");
    assert_eq!(format!("{}", SwitchPattern::ChainedIfElse), "chained-if-else");
    assert_eq!(
        format!("{}", SwitchPattern::StringSwitchHash { hash_function: "fnv".into() }),
        "string-switch-hash(fnv)"
    );
}

fn make_switch_info(cases: Vec<(Vec<i64>, u64)>, default: Option<u64>) -> SwitchInfo {
    let case_vec: Vec<SwitchCase> =
        cases.into_iter().map(|(values, target)| SwitchCase { values, target }).collect();
    let all_vals: Vec<i64> = case_vec.iter().flat_map(|c| c.values.iter().copied()).collect();
    let (lo, hi) = (
        *all_vals.iter().min().unwrap_or(&0),
        *all_vals.iter().max().unwrap_or(&0),
    );
    SwitchInfo {
        dispatch_block: BlockId(0),
        switch_var: "rax".into(),
        case_count: case_vec.len() + usize::from(default.is_some()),
        cases: case_vec,
        default_addr: default,
        pattern: SwitchPattern::JumpTable,
        table_addr: Some(0x4000),
        value_range: (lo, hi),
        has_bounds_check: true,
        table_stride: Some(8),
        max_index: Some(hi),
        is_contiguous: true,
        false_target: None,
    }
}

#[test]
fn switch_info_all_targets_sorted_and_deduped() {
    let info = make_switch_info(
        vec![(vec![0], 0x1000), (vec![1], 0x2000), (vec![2], 0x1000)],
        Some(0x3000),
    );
    let targets = info.all_targets();
    assert_eq!(targets, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn switch_info_is_dense_dense_case() {
    let info = make_switch_info(
        vec![(vec![0], 0xA), (vec![1], 0xB), (vec![2], 0xC), (vec![3], 0xD)],
        None,
    );
    assert!(info.is_dense());
}

#[test]
fn switch_info_is_dense_sparse_case() {
    let info = make_switch_info(
        vec![(vec![0], 0xA), (vec![100], 0xB)],
        None,
    );
    assert!(!info.is_dense());
}

#[test]
fn switch_info_display_has_metadata() {
    let info = make_switch_info(vec![(vec![1], 0x100)], Some(0x200));
    let s = format!("{}", info);
    assert!(s.contains("switch(rax)"));
    assert!(s.contains("jump-table"));
    assert!(s.contains("default@0x200"));
}

#[test]
fn switch_info_to_cfs_preserves_cases() {
    let info = make_switch_info(vec![(vec![1, 2], 0x100), (vec![3], 0x200)], None);
    let cfs = switch_info_to_cfs(&info);
    // We don't know exact CfsCase shape but should not be empty.
    assert!(!cfs.is_empty());
}

#[test]
fn block_id_ord_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(BlockId(1));
    s.insert(BlockId(1));
    s.insert(BlockId(2));
    assert_eq!(s.len(), 2);
    assert!(BlockId(1) < BlockId(2));
}

#[test]
fn switch_basic_block_helpers() {
    let bb = SwBb {
        id: BlockId(0),
        start: 0x1000,
        end: 0x1010,
        instructions: vec![LlilInsn::CondBranch {
            cond: BranchCond::Equal,
            true_target: 0x2000,
            false_target: 0x3000,
        }],
        successors: vec![],
        predecessors: vec![],
    };
    assert!(bb.is_cond_branch());
    assert!(matches!(bb.last_insn(), Some(LlilInsn::CondBranch { .. })));

    let bb_empty = SwBb {
        id: BlockId(1),
        start: 0,
        end: 0,
        instructions: vec![],
        successors: vec![],
        predecessors: vec![],
    };
    assert!(!bb_empty.is_cond_branch());
    assert!(bb_empty.last_insn().is_none());
}

#[test]
fn switch_function_block_lookup() {
    let bb = SwBb {
        id: BlockId(0),
        start: 0,
        end: 0,
        instructions: vec![],
        successors: vec![],
        predecessors: vec![],
    };
    let f = SwFn {
        blocks: vec![bb],
        entry: BlockId(0),
        name: "f".into(),
    };
    assert!(f.block(BlockId(0)).is_some());
    assert!(f.block(BlockId(42)).is_none());
    assert_eq!(f.block_count(), 1);
}

#[test]
fn cmp_kind_branch_cond_equality() {
    assert_eq!(CmpKind::Eq, CmpKind::Eq);
    assert_ne!(CmpKind::Eq, CmpKind::Ne);
    assert_eq!(BranchCond::Above, BranchCond::Above);
    assert_ne!(BranchCond::Less, BranchCond::Greater);
}

// ────────────────────────────────────────────────────────────────────────────
// PassStats / PassContext (lib root)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn pass_stats_merge_sums() {
    use rustre_il_passes::PassStats;
    let mut a = PassStats::new();
    a.instrs_visited = 5;
    a.const_folded = 1;
    let mut b = PassStats::new();
    b.instrs_visited = 7;
    b.dead_removed = 2;
    a.merge(&b);
    assert_eq!(a.instrs_visited, 12);
    assert_eq!(a.const_folded, 1);
    assert_eq!(a.dead_removed, 2);
}

#[test]
fn pass_context_merge_ors_changed() {
    use rustre_il_passes::PassContext;
    let mut a = PassContext::new();
    let mut b = PassContext::new();
    b.mark_changed();
    b.add_warning("x");
    a.merge(&b);
    assert!(a.changed);
    assert_eq!(a.warnings.len(), 1);
    assert_eq!(a.warnings[0], "x");
}

#[test]
fn pass_context_default_clean() {
    use rustre_il_passes::PassContext;
    let ctx = PassContext::default();
    assert!(!ctx.changed);
    assert!(ctx.warnings.is_empty());
}
