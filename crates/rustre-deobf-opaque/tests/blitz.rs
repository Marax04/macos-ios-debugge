//! Blitz test suite for `rustre-deobf-opaque`.
//!
//! Exercises the public API surface from `lib.rs`: `OpaqueExpr` evaluation,
//! simplification, pattern matching, `TruthTableChecker`, detection,
//! elimination, MBA, statistical, database, and reporting.

use rustre_core::address::Address;
use rustre_deobf_opaque::*;
use std::collections::HashMap;

// ── helpers ──────────────────────────────────────────────────────────────────

fn v(name: &str) -> OpaqueExpr {
    OpaqueExpr::Var(name.to_string())
}
const fn c(n: i64) -> OpaqueExpr {
    OpaqueExpr::Const(n)
}
fn b(e: OpaqueExpr) -> Box<OpaqueExpr> {
    Box::new(e)
}
const fn addr(a: u64) -> Address {
    Address::new(a)
}
fn env1(name: &str, val: i64) -> HashMap<String, i64> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), val);
    m
}

// ── eval: arithmetic edge cases ──────────────────────────────────────────────

#[test]
fn eval_add_wrapping_overflow() {
    let e = OpaqueExpr::Add(b(c(i64::MAX)), b(c(1)));
    assert_eq!(e.eval(&HashMap::new()), Some(i64::MIN));
}

#[test]
fn eval_sub_wrapping_overflow() {
    let e = OpaqueExpr::Sub(b(c(i64::MIN)), b(c(1)));
    assert_eq!(e.eval(&HashMap::new()), Some(i64::MAX));
}

#[test]
fn eval_mul_wrapping_overflow() {
    let e = OpaqueExpr::Mul(b(c(i64::MAX)), b(c(2)));
    assert_eq!(e.eval(&HashMap::new()), Some(i64::MAX.wrapping_mul(2)));
}

#[test]
fn eval_div_by_zero_var() {
    let e = OpaqueExpr::Div(b(c(10)), b(v("z")));
    assert_eq!(e.eval(&env1("z", 0)), None);
    assert_eq!(e.eval(&env1("z", 2)), Some(5));
}

#[test]
fn eval_mod_by_zero() {
    let e = OpaqueExpr::Mod(b(c(10)), b(c(0)));
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_unbound_var_returns_none() {
    let e = v("y");
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_shl_at_boundary_64_is_none() {
    let e = OpaqueExpr::Shl(b(c(1)), 64);
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_shl_at_boundary_63_ok() {
    let e = OpaqueExpr::Shl(b(c(1)), 63);
    assert_eq!(e.eval(&HashMap::new()), Some(1i64.wrapping_shl(63)));
}

#[test]
fn eval_shr_at_boundary_64_is_none() {
    let e = OpaqueExpr::Shr(b(c(-1)), 64);
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_abs_i64_min_returns_none() {
    // checked_abs(i64::MIN) overflows.
    let e = OpaqueExpr::Abs(b(c(i64::MIN)));
    assert_eq!(e.eval(&HashMap::new()), None);
}

#[test]
fn eval_neg_i64_min_wraps_to_self() {
    let e = OpaqueExpr::Neg(b(c(i64::MIN)));
    assert_eq!(e.eval(&HashMap::new()), Some(i64::MIN));
}

#[test]
fn eval_square_negative_is_positive() {
    let e = OpaqueExpr::Square(b(v("x")));
    assert_eq!(e.eval(&env1("x", -7)), Some(49));
}

#[test]
fn eval_bitcount_all_ones() {
    let e = OpaqueExpr::BitCount(b(c(-1)));
    assert_eq!(e.eval(&HashMap::new()), Some(64));
}

#[test]
fn eval_bitcount_zero() {
    assert_eq!(OpaqueExpr::BitCount(b(c(0))).eval(&HashMap::new()), Some(0));
}

#[test]
fn eval_not_zero_is_all_ones() {
    assert_eq!(OpaqueExpr::Not(b(c(0))).eval(&HashMap::new()), Some(-1));
}

#[test]
fn eval_comparisons_yield_zero_or_one() {
    let e = OpaqueExpr::Lt(b(c(1)), b(c(2)));
    assert_eq!(e.eval(&HashMap::new()), Some(1));
    let e = OpaqueExpr::Lt(b(c(2)), b(c(1)));
    assert_eq!(e.eval(&HashMap::new()), Some(0));
}

// ── vars / is_const ──────────────────────────────────────────────────────────

#[test]
fn vars_sorted_and_deduped() {
    let e = OpaqueExpr::Add(
        b(OpaqueExpr::Add(b(v("z")), b(v("a")))),
        b(OpaqueExpr::Add(b(v("z")), b(v("m")))),
    );
    let got = e.vars();
    assert_eq!(got, vec!["a".to_string(), "m".to_string(), "z".to_string()]);
}

#[test]
fn is_const_returns_value_for_pure_const() {
    let e = OpaqueExpr::Mul(b(c(6)), b(c(7)));
    assert_eq!(e.is_const(), Some(42));
}

#[test]
fn is_const_none_when_var_present() {
    let e = OpaqueExpr::Mul(b(c(6)), b(v("x")));
    assert_eq!(e.is_const(), None);
}

#[test]
fn is_const_none_when_div_by_zero_constant() {
    // No variables but eval fails: is_const should be None.
    let e = OpaqueExpr::Div(b(c(1)), b(c(0)));
    assert_eq!(e.is_const(), None);
}

// ── simplify ─────────────────────────────────────────────────────────────────

#[test]
fn simplify_add_zero_left_identity() {
    let e = OpaqueExpr::Add(b(c(0)), b(v("x")));
    assert_eq!(e.simplify(), v("x"));
}

#[test]
fn simplify_add_zero_right_identity() {
    let e = OpaqueExpr::Add(b(v("x")), b(c(0)));
    assert_eq!(e.simplify(), v("x"));
}

#[test]
fn simplify_mul_by_zero_yields_zero() {
    let e = OpaqueExpr::Mul(b(v("x")), b(c(0)));
    assert_eq!(e.simplify(), c(0));
}

#[test]
fn simplify_mul_by_one_identity() {
    let e = OpaqueExpr::Mul(b(c(1)), b(v("x")));
    assert_eq!(e.simplify(), v("x"));
}

#[test]
fn simplify_and_with_neg_one_identity() {
    let e = OpaqueExpr::And(b(v("x")), b(c(-1)));
    assert_eq!(e.simplify(), v("x"));
}

#[test]
fn simplify_or_with_neg_one_saturates() {
    let e = OpaqueExpr::Or(b(v("x")), b(c(-1)));
    assert_eq!(e.simplify(), c(-1));
}

#[test]
fn simplify_eq_trivial_self_is_one() {
    let e = OpaqueExpr::Eq(b(v("x")), b(v("x")));
    assert_eq!(e.simplify(), c(1));
}

#[test]
fn simplify_lt_self_is_zero() {
    let e = OpaqueExpr::Lt(b(v("x")), b(v("x")));
    assert_eq!(e.simplify(), c(0));
}

#[test]
fn simplify_le_self_is_one() {
    let e = OpaqueExpr::Le(b(v("x")), b(v("x")));
    assert_eq!(e.simplify(), c(1));
}

#[test]
fn simplify_abs_i64_min_is_not_folded() {
    // abs(i64::MIN) overflows; simplify must leave node intact.
    let e = OpaqueExpr::Abs(b(c(i64::MIN)));
    let s = e.simplify();
    // Should still be Abs, not a const.
    assert!(matches!(s, OpaqueExpr::Abs(_)), "got {s:?}");
}

#[test]
fn simplify_shl_zero_returns_inner() {
    let e = OpaqueExpr::Shl(b(v("x")), 0);
    assert_eq!(e.simplify(), v("x"));
}

#[test]
fn simplify_div_by_one_identity() {
    let e = OpaqueExpr::Div(b(v("x")), b(c(1)));
    assert_eq!(e.simplify(), v("x"));
}

// ── is_trivially_equal ───────────────────────────────────────────────────────

#[test]
fn trivially_equal_consts() {
    assert!(c(42).is_trivially_equal(&c(42)));
    assert!(!c(42).is_trivially_equal(&c(43)));
}

#[test]
fn trivially_equal_different_variants_false() {
    assert!(!c(0).is_trivially_equal(&v("x")));
}

#[test]
fn trivially_equal_shl_distinguishes_shift_amount() {
    let a = OpaqueExpr::Shl(b(v("x")), 1);
    let b1 = OpaqueExpr::Shl(b(v("x")), 2);
    assert!(!a.is_trivially_equal(&b1));
}

// ── Display ──────────────────────────────────────────────────────────────────

#[test]
fn display_predicate_kind() {
    assert_eq!(OpaquePredicateKind::TrivialIdentity.to_string(), "TrivialIdentity");
    assert_eq!(OpaquePredicateKind::Symbolic.to_string(), "Symbolic");
}

#[test]
fn display_opaque_kind() {
    assert_eq!(OpaqueKind::AlwaysTrue.to_string(), "AlwaysTrue");
    assert_eq!(OpaqueKind::DataDependent.to_string(), "DataDependent");
}

#[test]
fn opaque_kind_from_predicate_value() {
    assert_eq!(OpaqueKind::from(PredicateValue::AlwaysTrue), OpaqueKind::AlwaysTrue);
    assert_eq!(OpaqueKind::from(PredicateValue::AlwaysFalse), OpaqueKind::AlwaysFalse);
    assert_eq!(OpaqueKind::from(PredicateValue::Unknown), OpaqueKind::DataDependent);
}

#[test]
fn display_category_all_variants() {
    assert_eq!(OpaqueCategory::Aliasing.to_string(), "aliasing");
    assert_eq!(OpaqueCategory::Environmental.to_string(), "environmental");
    assert_eq!(OpaqueCategory::DeadComputation.to_string(), "dead-computation");
}

// ── Known patterns ───────────────────────────────────────────────────────────

#[test]
fn known_patterns_count_is_at_least_24() {
    let p = build_known_patterns();
    assert!(p.len() >= 24, "got {}", p.len());
}

#[test]
fn pattern_sub_self_eq_zero_matches() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        b(OpaqueExpr::Sub(b(v("x")), b(v("x")))),
        b(c(0)),
    );
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_consec_succ_product_even_matches() {
    let det = OpaqueDetector::new();
    // (x * (x+1)) % 2 == 0
    let prod = OpaqueExpr::Mul(b(v("x")), b(OpaqueExpr::Add(b(v("x")), b(c(1)))));
    let e = OpaqueExpr::Eq(b(OpaqueExpr::Mod(b(prod), b(c(2)))), b(c(0)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_x_or_not_x_eq_minus_one() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        b(OpaqueExpr::Or(b(v("x")), b(OpaqueExpr::Not(b(v("x")))))),
        b(c(-1)),
    );
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_x_and_not_x_eq_zero() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        b(OpaqueExpr::And(b(v("x")), b(OpaqueExpr::Not(b(v("x")))))),
        b(c(0)),
    );
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_lt_self_always_false() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Lt(b(v("x")), b(v("x")));
    // Trivial identity should catch this even before pattern db.
    let r = det.check_trivial_identity(&e);
    assert_eq!(r, Some(PredicateValue::AlwaysFalse));
}

#[test]
fn pattern_le_self_always_true() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Le(b(v("x")), b(v("x")));
    assert_eq!(det.check_trivial_identity(&e), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_const_const_cmp_true() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(b(c(5)), b(c(5)));
    // Constant expr fast-path classifies this.
    assert_eq!(det.check_constant_expr(&e), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_abs_ge_zero() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Ge(b(OpaqueExpr::Abs(b(v("x")))), b(c(0)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_popcount_ge_zero() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Ge(b(OpaqueExpr::BitCount(b(v("x")))), b(c(0)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_mul_zero_ne_zero_always_false() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Ne(b(OpaqueExpr::Mul(b(v("x")), b(c(0)))), b(c(0)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysFalse));
}

#[test]
fn pattern_and_self_eq_self_idempotent() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        b(OpaqueExpr::And(b(v("x")), b(v("x")))),
        b(v("x")),
    );
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_twos_complement_negation() {
    let det = OpaqueDetector::new();
    // x + (~x + 1) == 0
    let neg = OpaqueExpr::Add(b(OpaqueExpr::Not(b(v("x")))), b(c(1)));
    let e = OpaqueExpr::Eq(b(OpaqueExpr::Add(b(v("x")), b(neg))), b(c(0)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

#[test]
fn pattern_or_with_one_is_odd() {
    let det = OpaqueDetector::new();
    // (x | 1) & 1 == 1
    let inner = OpaqueExpr::Or(b(v("x")), b(c(1)));
    let e = OpaqueExpr::Eq(b(OpaqueExpr::And(b(inner), b(c(1)))), b(c(1)));
    let r = det.check_known_patterns(&e);
    assert_eq!(r.map(|(p, _)| p), Some(PredicateValue::AlwaysTrue));
}

// ── TruthTableChecker ────────────────────────────────────────────────────────

#[test]
fn truth_table_constant_classified_via_fast_path() {
    let checker = TruthTableChecker::new();
    assert_eq!(checker.classify(&c(7)), PredicateValue::AlwaysTrue);
    assert_eq!(checker.classify(&c(0)), PredicateValue::AlwaysFalse);
}

#[test]
fn truth_table_div_by_zero_constant_unknown() {
    let checker = TruthTableChecker::new();
    let e = OpaqueExpr::Div(b(c(1)), b(c(0)));
    assert_eq!(checker.classify(&e), PredicateValue::Unknown);
}

#[test]
fn truth_table_is_always_false_div_by_zero_does_not_lie() {
    // Regression test: div-by-zero must not be claimed AlwaysFalse since it is
    // not evaluable.
    let checker = TruthTableChecker::new();
    let e = OpaqueExpr::Div(b(c(1)), b(c(0)));
    assert!(!checker.is_always_false(&e),
        "div/0 should NOT be reported as always false");
}

#[test]
fn truth_table_builder_with_bits_with_samples() {
    let checker = TruthTableChecker::new()
        .with_bits(4)
        .with_samples(16);
    assert_eq!(checker.bits, 4);
    assert_eq!(checker.sample_count, 16);
}

#[test]
fn truth_table_enumerate_zero_vars_yields_one_empty_map() {
    let r = TruthTableChecker::enumerate_values(&[], 8);
    assert_eq!(r.len(), 1);
    assert!(r[0].is_empty());
}

#[test]
fn truth_table_enumerate_one_var_count_matches_range() {
    let r = TruthTableChecker::enumerate_values(&["x".to_string()], 4);
    // 2^4 = 16
    assert_eq!(r.len(), 16);
}

#[test]
fn truth_table_enumerate_capped_at_max() {
    // 2 vars at 16 bits = 4 billion combos -> must be capped at 65_536.
    let r = TruthTableChecker::enumerate_values(
        &["a".to_string(), "b".to_string()],
        16,
    );
    assert!(r.len() <= 65_536);
}

#[test]
fn truth_table_classify_square_is_always_true() {
    let checker = TruthTableChecker::new();
    // x*x >= 0 always over the tested domain.
    let e = OpaqueExpr::Ge(b(OpaqueExpr::Square(b(v("x")))), b(c(0)));
    assert_eq!(checker.classify(&e), PredicateValue::AlwaysTrue);
}

// ── SimpleBranchCfg ──────────────────────────────────────────────────────────

#[test]
fn cfg_new_is_empty() {
    let cfg = SimpleBranchCfg::new(addr(0x1000));
    assert!(cfg.branches.is_empty());
    assert!(cfg.block_sizes.is_empty());
    assert_eq!(cfg.function_start, addr(0x1000));
}

#[test]
fn cfg_add_block_size_uses_address_key() {
    let mut cfg = SimpleBranchCfg::new(addr(0));
    cfg.add_block_size(addr(0x2000), 7);
    assert_eq!(cfg.block_sizes.get(&0x2000u64), Some(&7));
}

// ── OpaqueDetector ───────────────────────────────────────────────────────────

#[test]
fn detector_classify_with_kind_below_confidence_is_data_dependent() {
    let det = OpaqueDetector::new().with_min_confidence(0.99);
    // Symbolic-classified predicate has confidence 0.80 (< 0.99) so should map
    // to DataDependent.
    let e = OpaqueExpr::Ge(b(OpaqueExpr::Square(b(v("x")))), b(c(0)));
    assert_eq!(det.classify_with_kind(&e), OpaqueKind::DataDependent);
}

#[test]
fn detector_classify_with_kind_eq_self_is_always_true() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(b(v("x")), b(v("x")));
    assert_eq!(det.classify_with_kind(&e), OpaqueKind::AlwaysTrue);
}

#[test]
fn detector_classify_data_dependent() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Lt(b(v("x")), b(v("y")));
    // x < y is genuinely data-dependent.
    let (pv, _, _) = det.classify_condition(&e);
    assert_eq!(pv, PredicateValue::Unknown);
}

#[test]
fn detector_classify_const_expr_full_confidence() {
    let det = OpaqueDetector::new();
    let e = OpaqueExpr::Eq(b(c(1)), b(c(1)));
    let (_pv, kind, conf) = det.classify_condition(&e);
    assert_eq!(kind, OpaquePredicateKind::ConstantExpr);
    assert!((conf - 1.0).abs() < f32::EPSILON);
}

#[test]
fn detector_no_detection_when_below_min_confidence() {
    let det = OpaqueDetector::new().with_min_confidence(1.01); // unreachable
    let mut cfg = SimpleBranchCfg::new(addr(0));
    cfg.add_branch(SimpleBranch {
        address: addr(0x1000),
        condition: OpaqueExpr::Eq(b(v("x")), b(v("x"))),
        true_target: addr(0x1010),
        false_target: addr(0x1020),
    });
    assert!(det.detect(&cfg).is_empty());
}

// ── OpaqueEliminator ─────────────────────────────────────────────────────────

#[test]
fn eliminator_makes_branch_unconditional() {
    let mut branch = SimpleBranch {
        address: addr(0x1000),
        condition: OpaqueExpr::Eq(b(v("x")), b(c(1))),
        true_target: addr(0x1010),
        false_target: addr(0x1020),
    };
    OpaqueEliminator::make_unconditional(&mut branch, addr(0x9999));
    assert_eq!(branch.true_target, addr(0x9999));
    assert_eq!(branch.false_target, addr(0x9999));
    assert_eq!(branch.condition, c(1));
}

#[test]
fn eliminator_handles_empty_cfg() {
    let mut cfg = SimpleBranchCfg::new(addr(0));
    let res = OpaqueEliminator::new().eliminate(&mut cfg);
    assert_eq!(res.branches_eliminated, 0);
    assert!(res.errors.is_empty());
}

// ── OpaqueDeobfPass ──────────────────────────────────────────────────────────

#[test]
fn pass_empty_cfg_produces_zero_results() {
    let mut cfg = SimpleBranchCfg::new(addr(0));
    let res = OpaqueDeobfPass::new().run(&mut cfg);
    assert_eq!(res.candidates_found, 0);
    assert_eq!(res.eliminated, 0);
    assert!(res.dead_blocks.is_empty());
    assert!(res.confidence_scores.is_empty());
}

#[test]
fn pass_data_dependent_branch_not_eliminated() {
    let mut cfg = SimpleBranchCfg::new(addr(0));
    cfg.add_branch(SimpleBranch {
        address: addr(0x1000),
        condition: OpaqueExpr::Gt(b(v("x")), b(c(0))),
        true_target: addr(0x1010),
        false_target: addr(0x1020),
    });
    let res = OpaqueDeobfPass::new().run(&mut cfg);
    assert_eq!(res.candidates_found, 0);
    assert_eq!(res.eliminated, 0);
}

// ── ConstantPropagator ───────────────────────────────────────────────────────

#[test]
fn propagator_default_empty() {
    let p = ConstantPropagator::new();
    let r = p.propagate(&[]);
    assert_eq!(r.branches_simplified, 0);
    assert!(r.facts.is_empty());
}

#[test]
fn propagator_extracts_const_eq_var() {
    let p = ConstantPropagator::new();
    let f = OpaqueBranch {
        address: addr(0x1000),
        predicate: OpaqueExpr::Eq(b(c(7)), b(v("y"))),
        value: PredicateValue::AlwaysTrue,
        kind: OpaquePredicateKind::KnownPattern,
        live_target: None,
        dead_target: None,
        confidence: 0.9,
    };
    let r = p.propagate(&[f]);
    assert_eq!(r.simplifications, 1);
    assert_eq!(r.facts.len(), 1);
    assert_eq!(r.facts[0].var, "y");
    assert_eq!(r.facts[0].value, 7);
}

// ── MbaOpaqueDetector ────────────────────────────────────────────────────────

#[test]
fn mba_with_custom_domain() {
    let det = MbaOpaqueDetector::with_domain(vec![0, 1]);
    let e = OpaqueExpr::Xor(b(v("x")), b(v("x")));
    assert_eq!(det.check_identity(&e), Some(0));
}

#[test]
fn mba_three_variable_non_constant() {
    // Regression: a 3-variable non-constant must NOT be reported as constant.
    let det = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Add(b(v("a")), b(OpaqueExpr::Add(b(v("b")), b(v("c")))));
    assert_eq!(det.check_identity(&e), None);
}

#[test]
fn mba_known_pattern_x_and_x_eq_x() {
    let det = MbaOpaqueDetector::new();
    let e = OpaqueExpr::Eq(
        b(OpaqueExpr::And(b(v("x")), b(v("x")))),
        b(v("x")),
    );
    let r = det.check_known_mba_patterns(&e);
    assert!(r.is_some());
}

// ── BranchFrequency ──────────────────────────────────────────────────────────

#[test]
fn branch_frequency_total() {
    let f = BranchFrequency::new(addr(0), 7, 3);
    assert_eq!(f.total(), 10);
}

#[test]
fn branch_frequency_is_opaque_suspicious_threshold() {
    let f = BranchFrequency::new(addr(0), 100, 0);
    assert!(f.is_opaque_suspicious(50));
    assert!(!f.is_opaque_suspicious(200)); // below threshold
}

#[test]
fn branch_frequency_genuine_not_suspicious() {
    let f = BranchFrequency::new(addr(0), 50, 50);
    assert!(!f.is_opaque_suspicious(10));
}

// ── StatisticalOpaqueDetector ────────────────────────────────────────────────

#[test]
fn statistical_empty_input_empty_output() {
    let det = StatisticalOpaqueDetector::new(1);
    assert!(det.classify(&[]).is_empty());
}

// ── OpaquePredicateDatabase ──────────────────────────────────────────────────

#[test]
fn database_new_is_empty() {
    let db = OpaquePredicateDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
}

#[test]
fn database_add_returns_incrementing_ids() {
    let mut db = OpaquePredicateDatabase::new();
    let id0 = db.add(OpaqueCategory::Mba, PredicateValue::AlwaysTrue, "a", 50);
    let id1 = db.add(OpaqueCategory::Mba, PredicateValue::AlwaysTrue, "b", 50);
    assert_eq!(id1, id0 + 1);
}

#[test]
fn database_by_value_partitions_correctly() {
    let db = OpaquePredicateDatabase::with_builtins();
    let t = db.by_value(PredicateValue::AlwaysTrue).len();
    let f = db.by_value(PredicateValue::AlwaysFalse).len();
    assert!(t > 0 && f > 0);
    assert_eq!(t + f, db.len(), "DB only contains AT/AF entries");
}

// ── DetailedFinding / OpaquePredicateReport ──────────────────────────────────

#[test]
fn detailed_finding_unknown_value_yields_no_fix_text() {
    let f = OpaqueBranch {
        address: addr(0xDEAD),
        predicate: OpaqueExpr::Gt(b(v("x")), b(c(0))),
        value: PredicateValue::Unknown,
        kind: OpaquePredicateKind::Symbolic,
        live_target: None,
        dead_target: None,
        confidence: 0.0,
    };
    let df = DetailedFinding::from_finding(f);
    assert!(df.suggested_fix.contains("No fix"), "got: {}", df.suggested_fix);
}

#[test]
fn report_average_confidence_is_zero_when_empty() {
    let elim = EliminationResult {
        branches_eliminated: 0,
        dead_blocks_identified: vec![],
        always_taken_edges: vec![],
        errors: vec![],
    };
    let r = OpaquePredicateReport::new(vec![], &elim);
    assert_eq!(r.total_findings(), 0);
    assert_eq!(r.average_confidence, 0.0);
}

#[test]
fn report_high_confidence_filter() {
    let mk = |conf: f32, kind: OpaquePredicateKind, val: PredicateValue| OpaqueBranch {
        address: addr(0),
        predicate: c(0),
        value: val,
        kind,
        live_target: None,
        dead_target: None,
        confidence: conf,
    };
    let findings = vec![
        DetailedFinding::from_finding(mk(1.0, OpaquePredicateKind::TrivialIdentity,
            PredicateValue::AlwaysTrue)),
        DetailedFinding::from_finding(mk(0.7, OpaquePredicateKind::DeadBranch,
            PredicateValue::AlwaysFalse)),
    ];
    let elim = EliminationResult {
        branches_eliminated: 0,
        dead_blocks_identified: vec![],
        always_taken_edges: vec![],
        errors: vec![],
    };
    let report = OpaquePredicateReport::new(findings, &elim);
    let high = report.high_confidence_findings();
    assert_eq!(high.len(), 1);
}

// ── BranchSimplifier ─────────────────────────────────────────────────────────

#[test]
fn branch_simplifier_overwrites_existing() {
    let mut s = BranchSimplifier::new();
    s.set_outcome(addr(1), BranchOutcome::AlwaysTaken);
    s.set_outcome(addr(1), BranchOutcome::NeverTaken);
    assert_eq!(s.count(), 1);
    assert_eq!(s.get_outcome(addr(1)), Some(BranchOutcome::NeverTaken));
}

#[test]
fn branch_outcome_copy_semantics() {
    let a = BranchOutcome::DataDependent;
    let b = a;
    assert_eq!(a, b);
}

// ── PredicateValue serde ─────────────────────────────────────────────────────

#[test]
fn predicate_value_eq_works() {
    assert_eq!(PredicateValue::AlwaysTrue, PredicateValue::AlwaysTrue);
    assert_ne!(PredicateValue::AlwaysTrue, PredicateValue::AlwaysFalse);
    let v = PredicateValue::Unknown;
    let copy = v; // Copy semantics
    assert_eq!(v, copy);
}

// ── Integration: full pipeline with mixed branches ───────────────────────────

#[test]
fn pipeline_eliminates_only_opaque_branches() {
    let mut cfg = SimpleBranchCfg::new(addr(0));
    // Opaque
    cfg.add_branch(SimpleBranch {
        address: addr(0x1000),
        condition: OpaqueExpr::Eq(b(v("a")), b(v("a"))),
        true_target: addr(0x1010),
        false_target: addr(0x1020),
    });
    // Genuine
    cfg.add_branch(SimpleBranch {
        address: addr(0x1100),
        condition: OpaqueExpr::Lt(b(v("a")), b(v("b"))),
        true_target: addr(0x1110),
        false_target: addr(0x1120),
    });
    let pass = OpaqueDeobfPass::new();
    let res = pass.run(&mut cfg);
    assert_eq!(res.candidates_found, 1);
    assert_eq!(res.eliminated, 1);
    // Opaque branch rewritten.
    assert_eq!(cfg.branches[0].true_target, addr(0x1010));
    assert_eq!(cfg.branches[0].false_target, addr(0x1010));
    // Genuine branch untouched.
    assert_eq!(cfg.branches[1].true_target, addr(0x1110));
    assert_eq!(cfg.branches[1].false_target, addr(0x1120));
}
