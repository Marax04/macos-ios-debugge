//! Blitz2 — deep adversarial coverage of `rustre-deobf-opaque` public API.

use rustre_core::address::Address;
use rustre_deobf_opaque::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

// ── helpers ──────────────────────────────────────────────────────────────────

fn v(name: &str) -> OpaqueExpr {
    OpaqueExpr::Var(name.to_string())
}
const fn c(n: i64) -> OpaqueExpr {
    OpaqueExpr::Const(n)
}
fn bx(e: OpaqueExpr) -> Box<OpaqueExpr> {
    Box::new(e)
}
fn env(name: &str, val: i64) -> HashMap<String, i64> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), val);
    m
}

/// Seeded LCG for deterministic adversarial fuzz.
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn i64(&mut self) -> i64 {
        self.next() as i64
    }
    const fn small_i64(&mut self) -> i64 {
        // small magnitude so multiplication doesn't always saturate
        (self.next() % 257) as i64 - 128
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OpaqueExpr::eval — boundary + fuzz
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn eval_const_boundary_values() {
    assert_eq!(c(0).eval(&HashMap::new()), Some(0));
    assert_eq!(c(i64::MAX).eval(&HashMap::new()), Some(i64::MAX));
    assert_eq!(c(i64::MIN).eval(&HashMap::new()), Some(i64::MIN));
    assert_eq!(c(-1).eval(&HashMap::new()), Some(-1));
}

#[test]
fn eval_var_unbound_returns_none() {
    assert_eq!(v("z").eval(&HashMap::new()), None);
}

#[test]
fn eval_div_by_zero_var_returns_none() {
    let e = OpaqueExpr::Div(bx(v("x")), bx(c(0)));
    assert_eq!(e.eval(&env("x", 42)), None);
}

#[test]
fn eval_mod_by_zero_returns_none() {
    let e = OpaqueExpr::Mod(bx(c(7)), bx(c(0)));
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_shl_overflow_shift_returns_none() {
    let e = OpaqueExpr::Shl(bx(c(1)), 64);
    assert_eq!(e.eval(&HashMap::new()), None);
    let e2 = OpaqueExpr::Shl(bx(c(1)), 200);
    assert_eq!(e2.eval(&HashMap::new()), None);
}

#[test]
fn eval_shr_overflow_shift_returns_none() {
    let e = OpaqueExpr::Shr(bx(c(1)), 64);
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_abs_imin_returns_none() {
    // i64::MIN has no positive representation → checked_abs returns None.
    let e = OpaqueExpr::Abs(bx(c(i64::MIN)));
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_neg_imin_wraps_to_imin() {
    // wrapping_neg of i64::MIN is i64::MIN.
    let e = OpaqueExpr::Neg(bx(c(i64::MIN)));
    assert_eq!(e.eval(&HashMap::new()), Some(i64::MIN));
}

#[test]
fn eval_square_self_consistent() {
    for x in [-1000_i64, -1, 0, 1, 7, 1000] {
        let e = OpaqueExpr::Square(bx(c(x)));
        assert_eq!(e.eval(&HashMap::new()), Some(x.wrapping_mul(x)));
    }
}

#[test]
fn eval_bitcount_known() {
    assert_eq!(
        OpaqueExpr::BitCount(bx(c(0))).eval(&HashMap::new()),
        Some(0)
    );
    assert_eq!(
        OpaqueExpr::BitCount(bx(c(-1))).eval(&HashMap::new()),
        Some(64)
    );
    assert_eq!(
        OpaqueExpr::BitCount(bx(c(0xFF))).eval(&HashMap::new()),
        Some(8)
    );
}

#[test]
fn eval_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let x = lcg.i64();
        let y = lcg.i64();
        let env = {
            let mut m = HashMap::new();
            m.insert("x".to_string(), x);
            m.insert("y".to_string(), y);
            m
        };
        // Build a small random tree of ops.
        let ops = [
            OpaqueExpr::Add(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Sub(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Mul(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Xor(bx(v("x")), bx(v("y"))),
            OpaqueExpr::And(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Or(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Shl(bx(v("x")), (lcg.next() % 70) as u8),
            OpaqueExpr::Shr(bx(v("x")), (lcg.next() % 70) as u8),
            OpaqueExpr::Div(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Mod(bx(v("x")), bx(v("y"))),
            OpaqueExpr::Abs(bx(v("x"))),
        ];
        for e in &ops {
            // Must never panic; result is Some or None.
            let _ = e.eval(&env);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OpaqueExpr::simplify — round-trip / soundness with eval
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn simplify_preserves_semantics_arithmetic_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let x = lcg.small_i64();
        let env = env("x", x);
        let exprs = [
            OpaqueExpr::Add(bx(v("x")), bx(c(0))),
            OpaqueExpr::Mul(bx(v("x")), bx(c(1))),
            OpaqueExpr::Sub(bx(v("x")), bx(v("x"))),
            OpaqueExpr::Xor(bx(v("x")), bx(v("x"))),
            OpaqueExpr::Or(bx(v("x")), bx(c(0))),
            OpaqueExpr::And(bx(v("x")), bx(c(-1))),
        ];
        for e in &exprs {
            let a = e.eval(&env);
            let b = e.simplify().eval(&env);
            assert_eq!(a, b, "semantic mismatch for {e}");
        }
    }
}

#[test]
fn simplify_const_fold_div_safe() {
    let e = OpaqueExpr::Div(bx(c(100)), bx(c(7)));
    assert_eq!(e.simplify(), c(100 / 7));
}

#[test]
fn simplify_const_fold_div_by_zero_unfolded() {
    // Should not panic and should not produce a bogus const.
    let e = OpaqueExpr::Div(bx(c(100)), bx(c(0)));
    let s = e.simplify();
    // Result should still evaluate to None.
    assert_eq!(s.eval(&HashMap::new()), None);
}

#[test]
fn simplify_mul_by_zero_yields_const_zero() {
    let e = OpaqueExpr::Mul(bx(v("x")), bx(c(0)));
    assert_eq!(e.simplify(), c(0));
}

#[test]
fn simplify_neg_const_folds() {
    assert_eq!(OpaqueExpr::Neg(bx(c(5))).simplify(), c(-5));
}

#[test]
fn simplify_not_const_folds() {
    assert_eq!(OpaqueExpr::Not(bx(c(0))).simplify(), c(-1));
}

#[test]
fn simplify_abs_imin_does_not_fold() {
    // Since checked_abs is None for i64::MIN, simplify must not fabricate a const.
    let e = OpaqueExpr::Abs(bx(c(i64::MIN)));
    let s = e.simplify();
    assert_ne!(s, c(i64::MIN.wrapping_neg()));
    // The simplified form should still evaluate to None like eval does.
    assert_eq!(s.eval(&HashMap::new()), None);
}

#[test]
fn simplify_eq_self_folds_to_one() {
    let e = OpaqueExpr::Eq(bx(v("a")), bx(v("a")));
    assert_eq!(e.simplify(), c(1));
}

#[test]
fn simplify_ne_self_folds_to_zero() {
    let e = OpaqueExpr::Ne(bx(v("a")), bx(v("a")));
    assert_eq!(e.simplify(), c(0));
}

// ════════════════════════════════════════════════════════════════════════════
// OpaqueExpr::is_const / vars / is_trivially_equal
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn is_const_recursive() {
    let e = OpaqueExpr::Add(bx(c(3)), bx(OpaqueExpr::Mul(bx(c(2)), bx(c(5)))));
    assert_eq!(e.is_const(), Some(13));
}

#[test]
fn is_const_returns_none_with_var() {
    let e = OpaqueExpr::Add(bx(c(3)), bx(v("z")));
    assert_eq!(e.is_const(), None);
}

#[test]
fn vars_sorted_dedup() {
    let e = OpaqueExpr::Add(
        bx(OpaqueExpr::Mul(bx(v("z")), bx(v("a")))),
        bx(v("z")),
    );
    assert_eq!(e.vars(), vec!["a".to_string(), "z".to_string()]);
}

#[test]
fn trivially_equal_reflexive_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = lcg.i64();
        let e = OpaqueExpr::Add(bx(v("x")), bx(c(n)));
        assert!(e.is_trivially_equal(&e));
    }
}

#[test]
fn trivially_equal_different_vars_false() {
    assert!(!v("x").is_trivially_equal(&v("y")));
}

#[test]
fn trivially_equal_shift_amount_matters() {
    let a = OpaqueExpr::Shl(bx(v("x")), 3);
    let b = OpaqueExpr::Shl(bx(v("x")), 4);
    assert!(!a.is_trivially_equal(&b));
}

// ════════════════════════════════════════════════════════════════════════════
// PredicateValue / OpaqueKind round-trips
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn opaque_kind_from_predicate_value_round_trip() {
    assert_eq!(OpaqueKind::from(PredicateValue::AlwaysTrue), OpaqueKind::AlwaysTrue);
    assert_eq!(OpaqueKind::from(PredicateValue::AlwaysFalse), OpaqueKind::AlwaysFalse);
    assert_eq!(OpaqueKind::from(PredicateValue::Unknown), OpaqueKind::DataDependent);
}

#[test]
fn predicate_value_display_strings() {
    assert_eq!(PredicateValue::AlwaysTrue.to_string(), "AlwaysTrue");
    assert_eq!(PredicateValue::Unknown.to_string(), "Unknown");
    assert_eq!(OpaqueKind::DataDependent.to_string(), "DataDependent");
}

#[test]
fn opaque_predicate_kind_display() {
    let kinds = [
        OpaquePredicateKind::TrivialIdentity,
        OpaquePredicateKind::ConstantExpr,
        OpaquePredicateKind::MathematicalInvariant,
        OpaquePredicateKind::DeadBranch,
        OpaquePredicateKind::KnownPattern,
        OpaquePredicateKind::Symbolic,
    ];
    for k in kinds {
        let s = k.to_string();
        assert!(!s.is_empty());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Known patterns — sweep
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn known_patterns_has_at_least_24() {
    let pats = build_known_patterns();
    assert!(pats.len() >= 24, "expected ≥24 patterns, got {}", pats.len());
}

#[test]
fn known_pattern_lt_self_false() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Lt(bx(v("x")), bx(v("x")));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysFalse)
    );
}

#[test]
fn known_pattern_le_self_true() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Le(bx(v("y")), bx(v("y")));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_x_and_not_x_zero() {
    let det = OpaqueDetector::new();
    let inner = OpaqueExpr::And(bx(v("x")), bx(OpaqueExpr::Not(bx(v("x")))));
    let e = OpaqueExpr::Eq(bx(inner), bx(c(0)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_x_or_not_x_minus_one() {
    let det = OpaqueDetector::new();
    let inner = OpaqueExpr::Or(bx(v("x")), bx(OpaqueExpr::Not(bx(v("x")))));
    let e = OpaqueExpr::Eq(bx(inner), bx(c(-1)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_abs_ge_zero() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Ge(bx(OpaqueExpr::Abs(bx(v("q")))), bx(c(0)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_popcount_ge_zero() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Ge(bx(OpaqueExpr::BitCount(bx(v("q")))), bx(c(0)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_const_const_eq_true() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(bx(c(7)), bx(c(7)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysTrue)
    );
}

#[test]
fn known_pattern_const_const_eq_false() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(bx(c(7)), bx(c(8)));
    assert_eq!(
        det.check_known_patterns(&e).map(|(pv, _)| pv),
        Some(PredicateValue::AlwaysFalse)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TruthTableChecker
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ttc_with_bits_with_samples_builders() {
    let t = TruthTableChecker::new().with_bits(4).with_samples(16);
    assert_eq!(t.bits, 4);
    assert_eq!(t.sample_count, 16);
}

#[test]
fn ttc_classify_constant_expr_true() {
    let t = TruthTableChecker::new();
    let e = OpaqueExpr::Eq(bx(c(5)), bx(c(5)));
    assert_eq!(t.classify(&e), PredicateValue::AlwaysTrue);
}

#[test]
fn ttc_classify_constant_expr_false() {
    let t = TruthTableChecker::new();
    let e = OpaqueExpr::Eq(bx(c(5)), bx(c(6)));
    assert_eq!(t.classify(&e), PredicateValue::AlwaysFalse);
}

#[test]
fn ttc_classify_unevaluable_no_vars_unknown() {
    // 10 / 0 — no vars, but unevaluable.
    let t = TruthTableChecker::new();
    let e = OpaqueExpr::Div(bx(c(10)), bx(c(0)));
    assert_eq!(t.classify(&e), PredicateValue::Unknown);
}

#[test]
fn ttc_enumerate_values_no_vars_yields_one_empty() {
    let m = TruthTableChecker::enumerate_values(&[], 4);
    assert_eq!(m.len(), 1);
    assert!(m[0].is_empty());
}

#[test]
fn ttc_enumerate_values_capped() {
    // With 4 bits and 2 vars → 256 combos.
    let m = TruthTableChecker::enumerate_values(&["x".to_string(), "y".to_string()], 4);
    assert_eq!(m.len(), 256);
}

// ════════════════════════════════════════════════════════════════════════════
// OpaqueDetector — full pipeline
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn detector_classify_with_kind_eq_self() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(bx(v("x")), bx(v("x")));
    assert_eq!(det.classify_with_kind(&e), OpaqueKind::AlwaysTrue);
}

#[test]
fn detector_classify_with_kind_data_dep() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Gt(bx(v("x")), bx(c(0)));
    assert_eq!(det.classify_with_kind(&e), OpaqueKind::DataDependent);
}

#[test]
fn detector_min_confidence_filters() {
    // With min_confidence=1.01, even constant-expr (1.0) gets filtered.
    let det = OpaqueDetector::new().with_min_confidence(1.01);
    let e = OpaqueExpr::Eq(bx(v("x")), bx(v("x")));
    assert_eq!(det.classify_with_kind(&e), OpaqueKind::DataDependent);
}

#[test]
fn detector_check_trivial_identity_all_self_relations() {
    let det = OpaqueDetector::new();
    let x = v("foo");
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Eq(bx(x.clone()), bx(x.clone()))),
        Some(PredicateValue::AlwaysTrue)
    );
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Ne(bx(x.clone()), bx(x.clone()))),
        Some(PredicateValue::AlwaysFalse)
    );
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Le(bx(x.clone()), bx(x.clone()))),
        Some(PredicateValue::AlwaysTrue)
    );
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Ge(bx(x.clone()), bx(x.clone()))),
        Some(PredicateValue::AlwaysTrue)
    );
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Lt(bx(x.clone()), bx(x.clone()))),
        Some(PredicateValue::AlwaysFalse)
    );
    assert_eq!(
        det.check_trivial_identity(&OpaqueExpr::Gt(bx(x.clone()), bx(x))),
        Some(PredicateValue::AlwaysFalse)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// OpaqueEliminator + SimpleBranchCfg
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn cfg_add_branch_and_block_size() {
    let mut cfg = SimpleBranchCfg::new(Address::new(0x100));
    cfg.add_branch(SimpleBranch {
        address: Address::new(0x100),
        condition: OpaqueExpr::Eq(bx(v("x")), bx(v("x"))),
        true_target: Address::new(0x110),
        false_target: Address::new(0x120),
    });
    cfg.add_block_size(Address::new(0x100), 5);
    assert_eq!(cfg.branches.len(), 1);
    assert_eq!(cfg.block_sizes.get(&0x100u64), Some(&5));
}

#[test]
fn eliminator_only_eliminates_opaque_keeps_real() {
    let mut cfg = SimpleBranchCfg::new(Address::new(0x1000));
    cfg.add_branch(SimpleBranch {
        address: Address::new(0x1000),
        condition: OpaqueExpr::Eq(bx(v("x")), bx(v("x"))),
        true_target: Address::new(0x10),
        false_target: Address::new(0x20),
    });
    cfg.add_branch(SimpleBranch {
        address: Address::new(0x1100),
        condition: OpaqueExpr::Gt(bx(v("a")), bx(v("b"))),
        true_target: Address::new(0x30),
        false_target: Address::new(0x40),
    });
    let res = OpaqueEliminator::new().eliminate(&mut cfg);
    assert_eq!(res.branches_eliminated, 1);
    // Real branch left intact.
    assert_eq!(cfg.branches[1].true_target, Address::new(0x30));
    assert_eq!(cfg.branches[1].false_target, Address::new(0x40));
}

#[test]
fn make_unconditional_sets_const_one() {
    let mut br = SimpleBranch {
        address: Address::new(0),
        condition: OpaqueExpr::Gt(bx(v("a")), bx(c(0))),
        true_target: Address::new(0x10),
        false_target: Address::new(0x20),
    };
    OpaqueEliminator::make_unconditional(&mut br, Address::new(0xABCD));
    assert_eq!(br.condition, OpaqueExpr::Const(1));
    assert_eq!(br.true_target, Address::new(0xABCD));
    assert_eq!(br.false_target, Address::new(0xABCD));
}

// ════════════════════════════════════════════════════════════════════════════
// ConstantPropagator
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn const_propagator_extracts_eq_facts() {
    let mut prop = ConstantPropagator::new();
    prop.add_fact(ConstFact {
        var: "seed".to_string(),
        value: 1,
        at: Address::new(0),
    });
    let finding = OpaqueBranch {
        address: Address::new(0x100),
        predicate: OpaqueExpr::Eq(bx(v("k")), bx(c(42))),
        value: PredicateValue::AlwaysTrue,
        kind: OpaquePredicateKind::KnownPattern,
        dead_target: None,
        live_target: None,
        confidence: 1.0,
    };
    let res = prop.propagate(&[finding]);
    // seed fact + extracted k=42
    assert_eq!(res.facts.len(), 2);
    assert!(res.facts.iter().any(|f| f.var == "k" && f.value == 42));
    assert_eq!(res.branches_simplified, 1);
}

#[test]
fn const_propagator_handles_always_false() {
    let prop = ConstantPropagator::new();
    let finding = OpaqueBranch {
        address: Address::new(0x100),
        predicate: OpaqueExpr::Ne(bx(v("x")), bx(v("x"))),
        value: PredicateValue::AlwaysFalse,
        kind: OpaquePredicateKind::TrivialIdentity,
        dead_target: None,
        live_target: None,
        confidence: 1.0,
    };
    let res = prop.propagate(&[finding]);
    assert_eq!(res.branches_simplified, 1);
    assert_eq!(res.simplifications, 0);
}

// ════════════════════════════════════════════════════════════════════════════
// MbaOpaqueDetector
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn mba_check_identity_constant_no_vars() {
    let mba = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Add(bx(c(3)), bx(c(4)));
    assert_eq!(mba.check_identity(&e), Some(7));
}

#[test]
fn mba_check_identity_x_xor_x_is_zero() {
    let mba = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Xor(bx(v("x")), bx(v("x")));
    assert_eq!(mba.check_identity(&e), Some(0));
}

#[test]
fn mba_check_identity_data_dependent_none() {
    let mba = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Add(bx(v("x")), bx(v("y")));
    assert_eq!(mba.check_identity(&e), None);
}

#[test]
fn mba_known_pattern_x_xor_0_eq_x() {
    let mba = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        bx(OpaqueExpr::Xor(bx(v("x")), bx(c(0)))),
        bx(v("x")),
    );
    let id = mba.check_known_mba_patterns(&e);
    assert!(id.is_some());
}

// ════════════════════════════════════════════════════════════════════════════
// StatisticalOpaqueDetector + BranchFrequency
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn branch_frequency_total_zero_unknown() {
    let bf = BranchFrequency::new(Address::new(0), 0, 0);
    assert_eq!(bf.total(), 0);
    assert_eq!(bf.true_fraction(), 0.0);
    assert_eq!(bf.hypothesis(), PredicateValue::Unknown);
}

#[test]
fn branch_frequency_always_true_hypothesis() {
    let bf = BranchFrequency::new(Address::new(0), 100, 0);
    assert_eq!(bf.hypothesis(), PredicateValue::AlwaysTrue);
    assert!(bf.is_opaque_suspicious(10));
    assert!(!bf.is_opaque_suspicious(1000));
}

#[test]
fn branch_frequency_always_false_hypothesis() {
    let bf = BranchFrequency::new(Address::new(0), 0, 50);
    assert_eq!(bf.hypothesis(), PredicateValue::AlwaysFalse);
    assert!((bf.false_fraction() - 1.0).abs() < 1e-9);
}

#[test]
fn statistical_detector_filters_below_min_samples() {
    let det = StatisticalOpaqueDetector::new(100);
    let freqs = vec![
        BranchFrequency::new(Address::new(0x1), 5, 0),     // total < 100 → filtered
        BranchFrequency::new(Address::new(0x2), 200, 0),   // always-true, kept
        BranchFrequency::new(Address::new(0x3), 100, 100), // balanced, filtered
    ];
    let res = det.classify(&freqs);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, Address::new(0x2));
    assert_eq!(res[0].1, PredicateValue::AlwaysTrue);
}

// ════════════════════════════════════════════════════════════════════════════
// OpaquePredicateDatabase
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn db_empty_then_add() {
    let mut db = OpaquePredicateDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    let id = db.add(OpaqueCategory::Mba, PredicateValue::AlwaysTrue, "demo", 80);
    assert_eq!(id, 0);
    let id2 = db.add(OpaqueCategory::Mba, PredicateValue::AlwaysTrue, "demo2", 90);
    assert_eq!(id2, 1);
    assert_eq!(db.len(), 2);
}

#[test]
fn db_with_builtins_non_empty_and_queryable() {
    let db = OpaquePredicateDatabase::with_builtins();
    assert!(!db.is_empty());
    let math = db.by_category(OpaqueCategory::Mathematical);
    assert!(!math.is_empty());
    let alw_true = db.by_value(PredicateValue::AlwaysTrue);
    assert!(!alw_true.is_empty());
    let high = db.high_confidence(99);
    assert!(high.iter().all(|e| e.confidence >= 99));
}

#[test]
fn opaque_category_display_all_variants_nonempty() {
    for c in [
        OpaqueCategory::Mathematical,
        OpaqueCategory::Mba,
        OpaqueCategory::Aliasing,
        OpaqueCategory::Environmental,
        OpaqueCategory::Ollvm,
        OpaqueCategory::DeadComputation,
    ] {
        assert!(!c.to_string().is_empty());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Send/Sync threaded stress
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn threaded_truth_table_checker_stress() {
    // TruthTableChecker has no interior mutability; Arc share across threads.
    let checker = Arc::new(TruthTableChecker::new().with_bits(4).with_samples(64));
    let expr = Arc::new(OpaqueExpr::Eq(bx(v("x")), bx(v("x"))));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = checker.clone();
        let e = expr.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(c.classify(&e), PredicateValue::AlwaysTrue);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_database_query_stress() {
    let db = Arc::new(OpaquePredicateDatabase::with_builtins());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = db.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = d.by_value(PredicateValue::AlwaysTrue);
                let _ = d.high_confidence(80);
                assert!(!d.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
