//! blitz2 — deep adversarial coverage for rustre-il-passes.
//!
//! Complements `blitz.rs`: focuses on seeded LCG fuzz, inverse / round-trip
//! properties, integer-overflow paths, hash/Eq consistency, Display/FromStr-like
//! round-trips for available conversions, and Send/Sync threaded stress.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use rustre_il_passes::constant_propagation::{
    self as cp, BBId, BasicBlock, ConstantLattice, Lattice, MlilExpr, MlilFunction, MlilStmt,
    VarId, WorkItem, analyse_function, collect_defs, fold_constants, fold_expr, initial_work_items,
    reanalyse_from, remove_dead_blocks, run_constant_propagation_pipeline, run_sccp,
};
use rustre_il_passes::switch_detection::{
    BasicBlock as SwBb, BinaryImage, BlockId, BranchCond, CfsCase, CmpKind, DetectionResult,
    JumpTableConfig, LlilFunction as SwFn, LlilInsn, SwitchCase, SwitchDetector,
    SwitchDetectorConfig, SwitchInfo, SwitchPattern, switch_info_to_cfs,
};
use rustre_il_passes::{PassContext, PassStats};

// ---------------------------------------------------------------------------
// Seeded LCG (deterministic, no rand crate, no std::time)
// ---------------------------------------------------------------------------

fn lcg_new() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}
fn lcg_step(s: &mut u64) -> u64 {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *s
}

// ---------------------------------------------------------------------------
// Helpers (mirror those in blitz.rs)
// ---------------------------------------------------------------------------

fn const_e(k: i128) -> MlilExpr { MlilExpr::Const(k) }
fn var_e(v: VarId) -> MlilExpr { MlilExpr::Var(v) }

fn func_with(entry: BBId, blocks: Vec<BasicBlock>, params: Vec<VarId>) -> MlilFunction {
    let mut f = MlilFunction::new(0, entry);
    for b in blocks {
        f.block_order.push(b.id);
        f.blocks.insert(b.id, b);
    }
    f.params = params;
    f
}

fn linear(id: BBId, stmts: Vec<MlilStmt>, succ: Vec<BBId>, pred: Vec<BBId>) -> BasicBlock {
    let mut b = BasicBlock::new(id);
    b.stmts = stmts;
    b.successors = succ;
    b.predecessors = pred;
    b
}

// ---------------------------------------------------------------------------
// Lattice algebraic laws — 50+ deterministic inputs
// ---------------------------------------------------------------------------

#[test]
fn lattice_meet_idempotent_lcg() {
    let mut s = lcg_new();
    for _ in 0..60 {
        let v = lcg_step(&mut s) as i128;
        let a = Lattice::Const(v);
        assert_eq!(a.meet(&a), Lattice::Const(v));
    }
}

#[test]
fn lattice_meet_commutative_lcg() {
    let mut s = lcg_new();
    for _ in 0..60 {
        let x = lcg_step(&mut s) as i128;
        let y = lcg_step(&mut s) as i128;
        let a = Lattice::Const(x);
        let b = Lattice::Const(y);
        assert_eq!(a.meet(&b), b.meet(&a));
    }
}

#[test]
fn lattice_meet_associative_lcg() {
    let mut s = lcg_new();
    let lattices = [Lattice::Top, Lattice::Bottom];
    for _ in 0..50 {
        let xs = [
            Lattice::Const(lcg_step(&mut s) as i128),
            Lattice::Const(lcg_step(&mut s) as i128),
            lattices[(lcg_step(&mut s) as usize) & 1].clone(),
        ];
        let l = xs[0].meet(&xs[1]).meet(&xs[2]);
        let r = xs[0].meet(&xs[1].meet(&xs[2]));
        assert_eq!(l, r);
    }
}

#[test]
fn lattice_top_identity_lcg() {
    let mut s = lcg_new();
    for _ in 0..50 {
        let v = lcg_step(&mut s) as i128;
        let a = Lattice::Const(v);
        assert_eq!(Lattice::Top.meet(&a), a);
        assert_eq!(a.meet(&Lattice::Top), a);
    }
}

#[test]
fn lattice_bottom_absorbs_lcg() {
    let mut s = lcg_new();
    for _ in 0..50 {
        let v = lcg_step(&mut s) as i128;
        let a = Lattice::Const(v);
        assert_eq!(Lattice::Bottom.meet(&a), Lattice::Bottom);
        assert_eq!(a.meet(&Lattice::Bottom), Lattice::Bottom);
    }
}

#[test]
fn lattice_diff_const_collapses_lcg() {
    let mut s = lcg_new();
    for _ in 0..50 {
        let x = lcg_step(&mut s) as i128;
        let y = x.wrapping_add(1); // guaranteed different
        let a = Lattice::Const(x);
        let b = Lattice::Const(y);
        assert_eq!(a.meet(&b), Lattice::Bottom);
    }
}

#[test]
fn lattice_predicates_partition() {
    // Every Lattice is exactly one of: Top, Const, Bottom.
    let xs = [Lattice::Top, Lattice::Bottom, Lattice::Const(0), Lattice::Const(i128::MAX)];
    for x in &xs {
        let bits = [x.is_top(), x.is_const(), x.is_bottom()];
        let count: usize = bits.iter().filter(|b| **b).count();
        assert_eq!(count, 1, "{x:?} must satisfy exactly one predicate");
    }
}

#[test]
fn lattice_const_val_boundary() {
    assert_eq!(Lattice::Const(0).const_val(), Some(0));
    assert_eq!(Lattice::Const(i128::MIN).const_val(), Some(i128::MIN));
    assert_eq!(Lattice::Const(i128::MAX).const_val(), Some(i128::MAX));
    assert_eq!(Lattice::Top.const_val(), None);
    assert_eq!(Lattice::Bottom.const_val(), None);
}

#[test]
fn lattice_display_round_trip_const() {
    // Display of Const is just the decimal value; check a few:
    let mut s = lcg_new();
    for _ in 0..30 {
        let v = (lcg_step(&mut s) as i64) as i128; // narrow to i64 range
        let d = format!("{}", Lattice::Const(v));
        assert_eq!(d.parse::<i128>().ok(), Some(v));
    }
}

// ---------------------------------------------------------------------------
// ConstantLattice monotonicity stress
// ---------------------------------------------------------------------------

#[test]
fn const_lattice_monotonic_descent_lcg() {
    // Once a var goes Top -> Const -> Bottom, it never climbs back.
    let mut s = lcg_new();
    let mut l = ConstantLattice::new();
    for i in 0..80u32 {
        let v = lcg_step(&mut s) as i128;
        let _ = l.set(i % 8, &Lattice::Const(v));
        // After enough mixed sets, observe Bottom for some vars.
        match l.get(i % 8) {
            Lattice::Top | Lattice::Const(_) | Lattice::Bottom => {}
        }
    }
    // No Top values should remain among the 8 vars we touched repeatedly with
    // distinct constants — all should have settled at Const(first) or Bottom.
    for v in 0..8u32 {
        assert!(!l.get(v).is_top(), "var {v} should not still be Top");
    }
}

#[test]
fn const_lattice_set_returns_change_flag() {
    let mut l = ConstantLattice::new();
    assert!(l.set(0, &Lattice::Const(1))); // Top -> Const = change
    assert!(!l.set(0, &Lattice::Const(1))); // same -> no change
    assert!(l.set(0, &Lattice::Const(2))); // Const(1) meet Const(2) -> Bottom = change
    assert!(!l.set(0, &Lattice::Const(3))); // already Bottom = no further change
    assert!(!l.set(0, &Lattice::Top)); // Top meet Bottom = Bottom (no change)
}

#[test]
fn const_lattice_default_top_for_unseen() {
    let l = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..40 {
        let v = (lcg_step(&mut s) as u32) % 10_000;
        assert!(l.get(v).is_top());
    }
}

#[test]
fn const_lattice_default_impl_matches_new() {
    let a = ConstantLattice::new();
    let b: ConstantLattice = Default::default();
    // Both empty -> same defaults for queries.
    assert_eq!(a.get(0), b.get(0));
    assert_eq!(a.get(42), b.get(42));
}

// ---------------------------------------------------------------------------
// fold_expr — inverse / round-trip properties on 50+ inputs
// ---------------------------------------------------------------------------

#[test]
fn fold_expr_add_sub_inverse_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..60 {
        let x = (lcg_step(&mut s) as i64) as i128;
        let y = (lcg_step(&mut s) as i64) as i128;
        // (x + y) - y == x  (mod 2^128 wrap)
        let add = MlilExpr::Add(Box::new(const_e(x)), Box::new(const_e(y)));
        let sub = MlilExpr::Sub(Box::new(add), Box::new(const_e(y)));
        match fold_expr(&sub, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, x.wrapping_add(y).wrapping_sub(y)),
            other => panic!("expected Const, got {other:?}"),
        }
    }
}

#[test]
fn fold_expr_xor_self_inverse_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..60 {
        let x = lcg_step(&mut s) as i128;
        let y = lcg_step(&mut s) as i128;
        // (x ^ y) ^ y == x
        let inner = MlilExpr::Xor(Box::new(const_e(x)), Box::new(const_e(y)));
        let outer = MlilExpr::Xor(Box::new(inner), Box::new(const_e(y)));
        let k = match fold_expr(&outer, &lat) {
            MlilExpr::Const(k) => k,
            other => panic!("{other:?}"),
        };
        assert_eq!(k, x);
    }
}

#[test]
fn fold_expr_not_involution_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let x = lcg_step(&mut s) as i128;
        // !!x == x
        let e = MlilExpr::Not(Box::new(MlilExpr::Not(Box::new(const_e(x)))));
        match fold_expr(&e, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, x),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fold_expr_neg_involution_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let x = lcg_step(&mut s) as i128;
        // --x == x   (wrapping_neg is its own inverse)
        let e = MlilExpr::Neg(Box::new(MlilExpr::Neg(Box::new(const_e(x)))));
        match fold_expr(&e, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, x.wrapping_neg().wrapping_neg()),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fold_expr_zx_then_trunc_round_trip_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let raw = lcg_step(&mut s) as i128;
        let bits: u8 = 8 + ((lcg_step(&mut s) as u8) % 56); // 8..=63
        // trunc_n(zx_n(x)) == x mod 2^n
        let e = MlilExpr::Trunc(bits, Box::new(MlilExpr::Zx(bits, Box::new(const_e(raw)))));
        let mask: u128 = if bits >= 128 { !0 } else { (1u128 << bits) - 1 };
        let expected = (raw as u128 & mask) as i128;
        match fold_expr(&e, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, expected, "bits={bits}, raw={raw}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fold_expr_sx_idempotent_within_width_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let bits: u8 = 8 + ((lcg_step(&mut s) as u8) % 56);
        // start from a value that already fits sign-extended at `bits` width
        let raw = (lcg_step(&mut s) as i64) >> (64 - bits as i64 % 64).max(1);
        let outer = MlilExpr::Sx(bits, Box::new(MlilExpr::Sx(bits, Box::new(const_e(raw as i128)))));
        let single = MlilExpr::Sx(bits, Box::new(const_e(raw as i128)));
        assert_eq!(fold_expr(&outer, &lat).clone_to_const(), fold_expr(&single, &lat).clone_to_const());
    }
}

#[test]
fn fold_expr_div_by_zero_never_panics_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let n = lcg_step(&mut s) as i128;
        for ctor in [
            MlilExpr::Div as fn(_, _) -> _,
            MlilExpr::DivU as fn(_, _) -> _,
            MlilExpr::Mod as fn(_, _) -> _,
            MlilExpr::ModU as fn(_, _) -> _,
        ] {
            let e = ctor(Box::new(const_e(n)), Box::new(const_e(0)));
            // Must not panic. Result must NOT be a constant (Bottom → keeps shape).
            let f = fold_expr(&e, &lat);
            assert!(!matches!(f, MlilExpr::Const(_)));
        }
    }
}

#[test]
fn fold_expr_shift_large_amount_does_not_panic_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..50 {
        let v = lcg_step(&mut s) as i128;
        let shift = (lcg_step(&mut s) as i128) | 1; // any nonzero
        let shl = MlilExpr::Shl(Box::new(const_e(v)), Box::new(const_e(shift)));
        let shr = MlilExpr::Shr(Box::new(const_e(v)), Box::new(const_e(shift)));
        let sar = MlilExpr::Sar(Box::new(const_e(v)), Box::new(const_e(shift)));
        // Each call must not panic and must produce some Const result.
        for e in [shl, shr, sar] {
            let f = fold_expr(&e, &lat);
            assert!(matches!(f, MlilExpr::Const(_)));
        }
    }
}

#[test]
fn fold_expr_cmp_signed_unsigned_disagree_on_neg_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..30 {
        let neg = -((lcg_step(&mut s) as i64 & 0x7FFF_FFFF) as i128) - 1; // < 0
        // signed: -1 < 0 == 1
        let signed_lt = MlilExpr::CmpLt(Box::new(const_e(neg)), Box::new(const_e(0)));
        // unsigned: huge u128 < 0 == 0
        let unsigned_lt = MlilExpr::CmpLtu(Box::new(const_e(neg)), Box::new(const_e(0)));
        match (fold_expr(&signed_lt, &lat), fold_expr(&unsigned_lt, &lat)) {
            (MlilExpr::Const(a), MlilExpr::Const(b)) => {
                assert_eq!(a, 1);
                assert_eq!(b, 0);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fold_expr_add_zero_identity_lcg() {
    // Note: SCCP fold doesn't simplify x+0 algebraically (no rewrite rule),
    // but if x is constant the fold should still yield x.
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..30 {
        let x = lcg_step(&mut s) as i128;
        let e = MlilExpr::Add(Box::new(const_e(x)), Box::new(const_e(0)));
        match fold_expr(&e, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, x),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fold_expr_mul_by_zero_lcg() {
    let lat = ConstantLattice::new();
    let mut s = lcg_new();
    for _ in 0..30 {
        let x = lcg_step(&mut s) as i128;
        let e = MlilExpr::Mul(Box::new(const_e(x)), Box::new(const_e(0)));
        match fold_expr(&e, &lat) {
            MlilExpr::Const(0) => {}
            other => panic!("expected Const(0), got {other:?}"),
        }
    }
}

#[test]
fn fold_expr_load_addr_folded_but_result_not_const() {
    let mut lat = ConstantLattice::new();
    lat.force_set(5, Lattice::Const(0x4000));
    let e = MlilExpr::Load { size: 4, addr: Box::new(var_e(5)) };
    match fold_expr(&e, &lat) {
        MlilExpr::Load { size, addr } => {
            assert_eq!(size, 4);
            assert!(matches!(*addr, MlilExpr::Const(0x4000)));
        }
        other => panic!("{other:?}"),
    }
}

// Helper trait for the comparison above
trait CloneToConst {
    fn clone_to_const(&self) -> Option<i128>;
}
impl CloneToConst for MlilExpr {
    fn clone_to_const(&self) -> Option<i128> {
        match self {
            MlilExpr::Const(k) => Some(*k),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SCCP fuzz — never panic on weird / malformed inputs
// ---------------------------------------------------------------------------

#[test]
fn sccp_empty_function_does_not_panic() {
    let f = func_with(0, vec![], vec![]);
    // run_sccp seeds from entry block; if entry doesn't exist, process_block
    // bails via try_block. Must not panic.
    let r = run_sccp(&f);
    assert_eq!(r.stats.folded_vars, 0);
    assert!(r.reachable.contains(&0)); // entry always pre-marked reachable
}

#[test]
fn sccp_entry_with_no_blocks_initial_work_items_empty() {
    let f = func_with(7, vec![], vec![]);
    let items = initial_work_items(&f);
    assert!(items.is_empty(), "{items:?}");
}

#[test]
fn sccp_self_loop_terminates() {
    // BB0 jumps back to BB0 -> tight loop.
    let bb = linear(0, vec![MlilStmt::Jump { target: 0 }], vec![0], vec![0]);
    let f = func_with(0, vec![bb], vec![]);
    let r = run_sccp(&f);
    assert!(r.reachable.contains(&0));
}

#[test]
fn sccp_fuzz_random_two_block_cfgs_lcg() {
    let mut s = lcg_new();
    for _ in 0..50 {
        let rv = lcg_step(&mut s) as i128;
        let cond_const = (lcg_step(&mut s) & 1) as i128;
        let entry = linear(
            0,
            vec![
                MlilStmt::Assign { dst: 1, rhs: const_e(rv) },
                MlilStmt::Branch { cond: const_e(cond_const), true_bb: 1, false_bb: 2 },
            ],
            vec![1, 2],
            vec![],
        );
        let b1 = linear(1, vec![MlilStmt::Nop], vec![], vec![0]);
        let b2 = linear(2, vec![MlilStmt::Nop], vec![], vec![0]);
        let f = func_with(0, vec![entry, b1, b2], vec![]);
        let r = run_sccp(&f);
        // Exactly one branch must be reachable when cond is constant.
        let reach_1 = r.reachable.contains(&1);
        let reach_2 = r.reachable.contains(&2);
        if cond_const == 0 {
            assert!(!reach_1 && reach_2, "rv={rv} cond=0");
        } else {
            assert!(reach_1 && !reach_2, "rv={rv} cond=1");
        }
        // v1 should be folded to rv.
        assert_eq!(r.lattice.get(1), &Lattice::Const(rv));
    }
}

#[test]
fn sccp_pipeline_idempotent_on_const_only_function() {
    let bb = linear(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_e(10) },
            MlilStmt::Assign { dst: 2, rhs: const_e(20) },
            MlilStmt::Return { values: vec![var_e(1), var_e(2)] },
        ],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let (folded1, _) = run_constant_propagation_pipeline(&f);
    let (folded2, _) = run_constant_propagation_pipeline(&folded1);
    // Second run shouldn't change anything: stats consistent.
    assert_eq!(folded1.blocks.len(), folded2.blocks.len());
}

// ---------------------------------------------------------------------------
// reanalyse_from consistency with full re-run
// ---------------------------------------------------------------------------

#[test]
fn reanalyse_from_matches_fresh_run_lcg() {
    let mut s = lcg_new();
    for _ in 0..15 {
        let a = lcg_step(&mut s) as i128;
        let b = lcg_step(&mut s) as i128;
        let bb = linear(
            0,
            vec![
                MlilStmt::Assign { dst: 1, rhs: const_e(a) },
                MlilStmt::Assign { dst: 2, rhs: const_e(b) },
            ],
            vec![],
            vec![],
        );
        let f = func_with(0, vec![bb], vec![]);
        let r1 = run_sccp(&f);
        let r2 = reanalyse_from(&f, 0, &r1);
        assert_eq!(r2.lattice.get(1), &Lattice::Const(a));
        assert_eq!(r2.lattice.get(2), &Lattice::Const(b));
    }
}

// ---------------------------------------------------------------------------
// WorkItem — Hash/Eq consistency on 30+ pairs
// ---------------------------------------------------------------------------

#[test]
fn work_item_eq_consistency_lcg() {
    let mut s = lcg_new();
    for _ in 0..35 {
        let a = lcg_step(&mut s) as u32;
        let b = lcg_step(&mut s) as u32;
        let x = WorkItem::Var(a);
        let y = WorkItem::Var(a);
        assert_eq!(x, y);
        let e1 = WorkItem::Edge(a, b);
        let e2 = WorkItem::Edge(a, b);
        assert_eq!(e1, e2);
        if a != b {
            assert_ne!(WorkItem::Edge(a, b), WorkItem::Edge(b, a));
        }
        assert!(x.is_var() ^ x.is_edge());
        assert!(e1.is_edge() ^ e1.is_var());
    }
}

#[test]
fn work_item_clone_equality_lcg() {
    let mut s = lcg_new();
    for _ in 0..30 {
        let a = lcg_step(&mut s) as u32;
        let b = lcg_step(&mut s) as u32;
        let w = if (a & 1) == 0 { WorkItem::Var(a) } else { WorkItem::Edge(a, b) };
        assert_eq!(w.clone(), w);
    }
}

// ---------------------------------------------------------------------------
// PassStats / PassContext — properties
// ---------------------------------------------------------------------------

#[test]
fn pass_stats_merge_is_associative_lcg() {
    let mut s = lcg_new();
    for _ in 0..40 {
        let mut a = PassStats::new();
        a.instrs_visited = (lcg_step(&mut s) as usize) % 1000;
        a.const_folded = (lcg_step(&mut s) as usize) % 1000;
        let mut b = PassStats::new();
        b.instrs_visited = (lcg_step(&mut s) as usize) % 1000;
        b.dead_removed = (lcg_step(&mut s) as usize) % 1000;
        let mut c = PassStats::new();
        c.exprs_simplified = (lcg_step(&mut s) as usize) % 1000;

        let mut left = a.clone();
        left.merge(&b);
        left.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut right = a.clone();
        right.merge(&bc);

        assert_eq!(left.instrs_visited, right.instrs_visited);
        assert_eq!(left.const_folded, right.const_folded);
        assert_eq!(left.dead_removed, right.dead_removed);
        assert_eq!(left.exprs_simplified, right.exprs_simplified);
    }
}

#[test]
fn pass_stats_merge_with_zero_identity() {
    let mut a = PassStats::new();
    a.instrs_visited = 10;
    a.const_folded = 3;
    let zero = PassStats::new();
    let mut copy = a.clone();
    copy.merge(&zero);
    assert_eq!(copy.instrs_visited, a.instrs_visited);
    assert_eq!(copy.const_folded, a.const_folded);
}

#[test]
fn pass_context_warning_order_preserved() {
    let mut ctx = PassContext::new();
    for i in 0..20 {
        ctx.add_warning(format!("w{i}"));
    }
    assert_eq!(ctx.warnings.len(), 20);
    for (i, w) in ctx.warnings.iter().enumerate() {
        assert_eq!(w, &format!("w{i}"));
    }
}

#[test]
fn pass_context_merge_appends_warnings() {
    let mut a = PassContext::new();
    a.add_warning("a1");
    let mut b = PassContext::new();
    b.add_warning("b1");
    b.add_warning("b2");
    a.merge(&b);
    assert_eq!(a.warnings, vec!["a1".to_string(), "b1".into(), "b2".into()]);
}

// ---------------------------------------------------------------------------
// SwitchPattern Display round-trip (only forward — no FromStr available)
// ---------------------------------------------------------------------------

#[test]
fn switch_pattern_display_distinct() {
    let xs = [
        SwitchPattern::JumpTable,
        SwitchPattern::BinarySearch,
        SwitchPattern::ChainedIfElse,
        SwitchPattern::StringSwitchHash { hash_function: "fnv1a".into() },
    ];
    let mut seen = HashSet::new();
    for x in &xs {
        let s = format!("{x}");
        assert!(seen.insert(s.clone()), "duplicate display for {s}");
    }
}

#[test]
fn switch_pattern_eq_reflexive_lcg() {
    let names = ["fnv", "djb2", "sdbm", "murmur"];
    let mut s = lcg_new();
    for _ in 0..30 {
        let i = (lcg_step(&mut s) as usize) % names.len();
        let p = SwitchPattern::StringSwitchHash { hash_function: names[i].into() };
        assert_eq!(p, p.clone());
    }
}

// ---------------------------------------------------------------------------
// SwitchCase / BlockId basic invariants
// ---------------------------------------------------------------------------

#[test]
fn switch_case_eq_lcg() {
    let mut s = lcg_new();
    for _ in 0..30 {
        let target = lcg_step(&mut s);
        let n = ((lcg_step(&mut s) as usize) % 5) + 1;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            values.push(lcg_step(&mut s) as i64);
        }
        let a = SwitchCase { values: values.clone(), target };
        let b = SwitchCase { values, target };
        assert_eq!(a, b);
    }
}

#[test]
fn block_id_total_order_lcg() {
    let mut s = lcg_new();
    let mut ids: Vec<BlockId> = (0..20).map(|_| BlockId(lcg_step(&mut s) as u32)).collect();
    ids.sort();
    for w in ids.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
}

// ---------------------------------------------------------------------------
// BranchCond / CmpKind enum equality
// ---------------------------------------------------------------------------

#[test]
fn branch_cond_cmp_kind_distinct_values() {
    let bcs = [
        BranchCond::Equal,
        BranchCond::NotEqual,
        BranchCond::Less,
        BranchCond::LessEqual,
        BranchCond::Greater,
        BranchCond::GreaterEqual,
        BranchCond::Above,
        BranchCond::AboveEq,
    ];
    for (i, a) in bcs.iter().enumerate() {
        for (j, b) in bcs.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
    let cks = [CmpKind::Eq, CmpKind::Ne, CmpKind::Lt, CmpKind::Le, CmpKind::Gt, CmpKind::Ge];
    for (i, a) in cks.iter().enumerate() {
        for (j, b) in cks.iter().enumerate() {
            if i == j { assert_eq!(a, b); } else { assert_ne!(a, b); }
        }
    }
}

// ---------------------------------------------------------------------------
// switch_info_to_cfs invariants
// ---------------------------------------------------------------------------

fn make_info(cases: Vec<(Vec<i64>, u64)>, default: Option<u64>) -> SwitchInfo {
    let case_vec: Vec<SwitchCase> = cases.into_iter()
        .map(|(values, target)| SwitchCase { values, target }).collect();
    let all_vals: Vec<i64> = case_vec.iter().flat_map(|c| c.values.iter().copied()).collect();
    let lo = *all_vals.iter().min().unwrap_or(&0);
    let hi = *all_vals.iter().max().unwrap_or(&0);
    SwitchInfo {
        dispatch_block: BlockId(0),
        switch_var: "r".into(),
        case_count: case_vec.len() + default.is_some() as usize,
        cases: case_vec,
        default_addr: default,
        pattern: SwitchPattern::JumpTable,
        table_addr: Some(0x4000),
        value_range: (lo, hi),
        has_bounds_check: true,
        table_stride: Some(8),
        max_index: Some(hi),
        is_contiguous: false,
        false_target: None,
    }
}

#[test]
fn switch_info_to_cfs_default_marked() {
    let info = make_info(vec![(vec![1], 0x100)], Some(0x200));
    let cfs = switch_info_to_cfs(&info);
    let n_def = cfs.iter().filter(|c| c.is_default).count();
    assert_eq!(n_def, 1);
    let def = cfs.iter().find(|c| c.is_default).unwrap();
    assert_eq!(def.target, 0x200);
    assert!(def.values.is_empty());
}

#[test]
fn switch_info_to_cfs_no_default_preserves_count() {
    let info = make_info(vec![(vec![1], 0x100), (vec![2, 3], 0x200)], None);
    let cfs = switch_info_to_cfs(&info);
    assert_eq!(cfs.len(), 2);
    assert!(cfs.iter().all(|c| !c.is_default));
}

#[test]
fn switch_info_all_targets_dedup_lcg() {
    let mut s = lcg_new();
    for _ in 0..20 {
        let t1 = lcg_step(&mut s) & 0xFFFF;
        let info = make_info(
            vec![(vec![0], t1), (vec![1], t1), (vec![2], t1.wrapping_add(0x10))],
            Some(t1),
        );
        let targets = info.all_targets();
        // Sorted ascending, deduplicated.
        for w in targets.windows(2) {
            assert!(w[0] < w[1]);
        }
        assert_eq!(targets.iter().copied().collect::<HashSet<_>>().len(), targets.len());
    }
}

// ---------------------------------------------------------------------------
// SwitchDetector with a trivial BinaryImage — no detection but must not panic
// ---------------------------------------------------------------------------

struct EmptyImage;
impl BinaryImage for EmptyImage {
    fn read_u32_le(&self, _addr: u64) -> Option<u32> { None }
    fn read_u64_le(&self, _addr: u64) -> Option<u64> { None }
    fn is_executable(&self, _addr: u64) -> bool { false }
    fn is_readable(&self, _addr: u64) -> bool { false }
    fn section_range(&self, _name: &str) -> Option<(u64, u64)> { None }
}

#[test]
fn switch_detector_default_on_empty_func() {
    let func = SwFn { blocks: vec![], entry: BlockId(0), name: "empty".into() };
    let det = SwitchDetector::default_config();
    let results = det.detect_all(&func, &EmptyImage);
    assert!(results.is_empty());
}

#[test]
fn switch_detector_with_explicit_config() {
    let cfg = SwitchDetectorConfig {
        jump_table: JumpTableConfig {
            max_entries: 16,
            min_entries: 2,
            require_executable: false,
            element_size: 4,
            allow_out_of_function: true,
        },
        min_chain_len: 4,
        detect_hash: false,
    };
    let det = SwitchDetector::new(cfg);
    let func = SwFn { blocks: vec![], entry: BlockId(0), name: "x".into() };
    let r = det.detect_all(&func, &EmptyImage);
    assert!(r.is_empty());
}

#[test]
fn switch_detector_single_nontrivial_block_no_panic() {
    let bb = SwBb {
        id: BlockId(0),
        start: 0x1000,
        end: 0x1010,
        instructions: vec![
            LlilInsn::Compare { reg: "rax".into(), value: 1, kind: CmpKind::Eq },
            LlilInsn::CondBranch { cond: BranchCond::Equal, true_target: 0x2000, false_target: 0x3000 },
        ],
        successors: vec![],
        predecessors: vec![],
    };
    let func = SwFn { blocks: vec![bb], entry: BlockId(0), name: "f".into() };
    let det = SwitchDetector::default_config();
    let _ = det.detect_all(&func, &EmptyImage);
}

// ---------------------------------------------------------------------------
// Send/Sync threaded stress on documented Send+Sync types (analysis passes)
// We use the value types Lattice/PassStats/etc., which are Send+Sync.
// ---------------------------------------------------------------------------

#[test]
fn threaded_lattice_meet_4x100() {
    // Lattice values shared across threads — purely value semantics.
    let consts: Arc<Vec<Lattice>> = Arc::new(
        (0..16).map(|i| Lattice::Const(i as i128 * 7)).collect()
    );
    let mut handles = Vec::new();
    for t in 0..4 {
        let cs = Arc::clone(&consts);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xA5A5_5A5A_DEAD_BEEF ^ (t as u64);
            for _ in 0..100 {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let i = (s as usize) % cs.len();
                let j = ((s >> 11) as usize) % cs.len();
                let m = cs[i].meet(&cs[j]);
                // Result is well-defined and equals either Const(k) when i == j
                // or Bottom when i != j (since all constants are distinct).
                if i == j {
                    assert_eq!(m, cs[i]);
                } else {
                    assert_eq!(m, Lattice::Bottom);
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_sccp_4x100() {
    // run_sccp takes &MlilFunction and returns owned data — safe to share.
    let bb = linear(
        0,
        vec![
            MlilStmt::Assign { dst: 1, rhs: const_e(7) },
            MlilStmt::Assign {
                dst: 2,
                rhs: MlilExpr::Add(Box::new(var_e(1)), Box::new(const_e(3))),
            },
            MlilStmt::Return { values: vec![var_e(2)] },
        ],
        vec![],
        vec![],
    );
    let f = Arc::new(func_with(0, vec![bb], vec![]));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let fc = Arc::clone(&f);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = run_sccp(&fc);
                assert_eq!(r.lattice.get(1), &Lattice::Const(7));
                assert_eq!(r.lattice.get(2), &Lattice::Const(10));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_fold_expr_4x100() {
    let lat = Arc::new(ConstantLattice::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let lc = Arc::clone(&lat);
        handles.push(thread::spawn(move || {
            let mut s = 0xC0FFEE_u64 ^ (t as u64);
            for _ in 0..100 {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let x = s as i128;
                let e = MlilExpr::Add(Box::new(const_e(x)), Box::new(const_e(1)));
                match fold_expr(&e, &lc) {
                    MlilExpr::Const(k) => assert_eq!(k, x.wrapping_add(1)),
                    other => panic!("{other:?}"),
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ---------------------------------------------------------------------------
// collect_defs / fold_constants invariants
// ---------------------------------------------------------------------------

#[test]
fn collect_defs_no_duplicates_for_unique_assigns_lcg() {
    let mut s = lcg_new();
    let mut stmts = Vec::new();
    let mut ids = Vec::new();
    for i in 0..30u32 {
        let v = lcg_step(&mut s) as i128;
        stmts.push(MlilStmt::Assign { dst: i, rhs: const_e(v) });
        ids.push(i);
    }
    let bb = linear(0, stmts, vec![], vec![]);
    let f = func_with(0, vec![bb], vec![]);
    let defs = collect_defs(&f);
    assert_eq!(defs.len(), 30);
    let set: HashSet<u32> = defs.iter().copied().collect();
    assert_eq!(set.len(), 30);
}

#[test]
fn analyse_function_consistent_with_run_sccp_lcg() {
    let mut s = lcg_new();
    for _ in 0..15 {
        let v = lcg_step(&mut s) as i128;
        let bb = linear(
            0,
            vec![MlilStmt::Assign { dst: 1, rhs: const_e(v) }],
            vec![],
            vec![],
        );
        let f = func_with(0, vec![bb], vec![]);
        let stats_from_pass = analyse_function(&f);
        let r = run_sccp(&f);
        assert_eq!(stats_from_pass.folded_vars, r.stats.folded_vars);
    }
}

#[test]
fn fold_constants_does_not_invent_blocks() {
    let bb = linear(
        0,
        vec![MlilStmt::Assign { dst: 1, rhs: const_e(5) }],
        vec![],
        vec![],
    );
    let f = func_with(0, vec![bb], vec![]);
    let r = run_sccp(&f);
    let nf = fold_constants(&f, &r);
    assert_eq!(nf.blocks.len(), f.blocks.len());
    assert!(nf.blocks.contains_key(&0));
}

#[test]
fn remove_dead_blocks_keeps_entry_lcg() {
    // Even with weird configurations, entry block must remain.
    let mut s = lcg_new();
    for _ in 0..10 {
        let cond = (lcg_step(&mut s) & 1) as i128;
        let entry = linear(
            0,
            vec![MlilStmt::Branch { cond: const_e(cond), true_bb: 1, false_bb: 2 }],
            vec![1, 2],
            vec![],
        );
        let b1 = linear(1, vec![MlilStmt::Nop], vec![], vec![0]);
        let b2 = linear(2, vec![MlilStmt::Nop], vec![], vec![0]);
        let mut f = func_with(0, vec![entry, b1, b2], vec![]);
        let r = run_sccp(&f);
        remove_dead_blocks(&mut f, &r);
        assert!(f.blocks.contains_key(&0), "entry must remain");
    }
}

// ---------------------------------------------------------------------------
// Boundary tests: 0, 1, max-of-type
// ---------------------------------------------------------------------------

#[test]
fn fold_expr_boundary_constants() {
    let lat = ConstantLattice::new();
    let boundaries = [0i128, 1, -1, i128::MIN, i128::MAX, i64::MAX as i128, i64::MIN as i128];
    for &v in &boundaries {
        let e = MlilExpr::Add(Box::new(const_e(v)), Box::new(const_e(0)));
        match fold_expr(&e, &lat) {
            MlilExpr::Const(k) => assert_eq!(k, v.wrapping_add(0)),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn lattice_meet_boundary_pairs() {
    let bs = [0i128, 1, -1, i128::MIN, i128::MAX];
    for &x in &bs {
        for &y in &bs {
            let r = Lattice::Const(x).meet(&Lattice::Const(y));
            if x == y {
                assert_eq!(r, Lattice::Const(x));
            } else {
                assert_eq!(r, Lattice::Bottom);
            }
        }
    }
}

// Touch the remaining re-exports so the test crate uses every imported type.
#[test]
fn touch_unused_imports() {
    let _: cp::FuncId = 0;
    // CfsCase struct construction
    let c = CfsCase { values: vec![1, 2], target: 0x100, is_default: false };
    assert_eq!(c.target, 0x100);
    // DetectionResult is internally-constructed by the detector; we only
    // exercise that the type is in scope and round-trips through detect_all.
    let func = SwFn { blocks: vec![], entry: BlockId(0), name: "z".into() };
    let det = SwitchDetector::default_config();
    let results: Vec<DetectionResult> = det.detect_all(&func, &EmptyImage);
    assert!(results.is_empty());
}
