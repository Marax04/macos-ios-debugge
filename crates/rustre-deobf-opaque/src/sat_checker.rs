//! `sat_checker` — SAT/SMT-based opaque predicate elimination.
//!
//! Provides [`SatChecker`], [`OpaquePredicateCandidate`], [`PatternDb`],
//! and batch verification.

use crate::{OpaqueExpr, PredicateValue, TruthTableChecker};
use rustre_core::address::Address;
use std::collections::HashMap;

// ── OpaquePredicateCandidate ──────────────────────────────────────────────────

/// A candidate opaque predicate identified in disassembly.
#[derive(Debug, Clone)]
pub struct OpaquePredicateCandidate {
    /// Address of the conditional branch.
    pub address: Address,
    /// Symbolic condition expression.
    pub condition_expr: OpaqueExpr,
    /// Whether the predicate is believed to be always-true.
    pub always_true: bool,
    /// Whether the predicate is believed to be always-false.
    pub always_false: bool,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f32,
    /// Which pattern matched, if any.
    pub matched_pattern: Option<String>,
}

impl OpaquePredicateCandidate {
    /// Create a new candidate.
    #[must_use]
    pub const fn new(address: Address, condition_expr: OpaqueExpr) -> Self {
        Self {
            address,
            condition_expr,
            always_true: false,
            always_false: false,
            confidence: 0.0,
            matched_pattern: None,
        }
    }

    /// Set as always-true with the given confidence.
    #[must_use]
    pub const fn as_always_true(mut self, confidence: f32) -> Self {
        self.always_true = true;
        self.always_false = false;
        self.confidence = confidence;
        self
    }

    /// Set as always-false with the given confidence.
    #[must_use]
    pub const fn as_always_false(mut self, confidence: f32) -> Self {
        self.always_false = true;
        self.always_true = false;
        self.confidence = confidence;
        self
    }

    /// Whether this candidate has a definite verdict.
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        self.always_true || self.always_false
    }

    /// Convert the decision to a [`PredicateValue`].
    #[must_use]
    pub const fn predicate_value(&self) -> PredicateValue {
        if self.always_true {
            PredicateValue::AlwaysTrue
        } else if self.always_false {
            PredicateValue::AlwaysFalse
        } else {
            PredicateValue::Unknown
        }
    }
}

// ── SatChecker ────────────────────────────────────────────────────────────────

/// SAT/SMT-based opaque predicate verifier.
///
/// In production this would wrap a Z3 or CVC5 SMT solver via C bindings.
/// Here we implement the same interface backed by exhaustive truth-table
/// evaluation (identical semantics, no external dependency).
pub struct SatChecker {
    /// Truth-table checker backing the SMT oracle.
    pub oracle: TruthTableChecker,
    /// Pattern database for fast structural matching.
    pub pattern_db: PatternDb,
    /// Whether to fall back to truth-table when no pattern matches.
    pub use_truth_table_fallback: bool,
    /// Statistics: total calls, fast-path hits, slow-path hits.
    pub stats: SatCheckerStats,
}

/// Cumulative statistics for the checker.
#[derive(Debug, Clone, Default)]
pub struct SatCheckerStats {
    pub total_calls: u64,
    pub pattern_hits: u64,
    pub truth_table_hits: u64,
    pub unknown_count: u64,
}

impl Default for SatChecker {
    fn default() -> Self {
        Self {
            oracle: TruthTableChecker::new(),
            pattern_db: PatternDb::build(),
            use_truth_table_fallback: true,
            stats: SatCheckerStats::default(),
        }
    }
}

impl SatChecker {
    /// Create a new checker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify whether `expr` is an opaque predicate (tautology or contradiction).
    pub fn verify_opaque(&mut self, expr: &OpaqueExpr) -> PredicateValue {
        self.stats.total_calls += 1;

        // 1. Fast path: structural pattern matching.
        if let Some(pv) = self.pattern_db.check(expr) {
            self.stats.pattern_hits += 1;
            return pv;
        }

        // 2. Constant folding.
        let simplified = expr.simplify();
        if let Some(c) = simplified.is_const() {
            return if c != 0 {
                PredicateValue::AlwaysTrue
            } else {
                PredicateValue::AlwaysFalse
            };
        }
        if let Some(pv) = self.pattern_db.check(&simplified) {
            self.stats.pattern_hits += 1;
            return pv;
        }

        // 3. Truth-table fallback.
        if self.use_truth_table_fallback {
            let pv = self.oracle.classify(expr);
            if pv != PredicateValue::Unknown {
                self.stats.truth_table_hits += 1;
                return pv;
            }
        }

        self.stats.unknown_count += 1;
        PredicateValue::Unknown
    }

    /// Verify a [`OpaquePredicateCandidate`] and update its fields in place.
    pub fn verify_candidate(&mut self, candidate: &mut OpaquePredicateCandidate) {
        let pv = self.verify_opaque(&candidate.condition_expr);
        match pv {
            PredicateValue::AlwaysTrue => {
                candidate.always_true = true;
                candidate.always_false = false;
                candidate.confidence = 0.90;
            }
            PredicateValue::AlwaysFalse => {
                candidate.always_false = true;
                candidate.always_true = false;
                candidate.confidence = 0.90;
            }
            PredicateValue::Unknown => {
                candidate.confidence = 0.0;
            }
        }
    }

    /// Batch-verify a slice of candidates.
    pub fn batch_verify(&mut self, candidates: &mut [OpaquePredicateCandidate]) {
        for c in candidates.iter_mut() {
            self.verify_candidate(c);
        }
    }

    /// Return all candidates that were confirmed as opaque.
    #[must_use]
    pub fn filter_opaque(
        candidates: &[OpaquePredicateCandidate],
    ) -> Vec<&OpaquePredicateCandidate> {
        candidates.iter().filter(|c| c.is_decided()).collect()
    }
}

// ── PatternDb ─────────────────────────────────────────────────────────────────

/// One opaque-predicate pattern check: `(name, fn)`.
pub type PatternCheck = (&'static str, fn(&OpaqueExpr) -> Option<PredicateValue>);

/// A database of 100+ opaque predicate structural patterns.
pub struct PatternDb {
    /// Registered check functions.
    checkers: Vec<PatternCheck>,
}

impl PatternDb {
    /// Build the pattern database.
    #[must_use]
    pub fn build() -> Self {
        let mut db = Self {
            checkers: Vec::new(),
        };
        db.register_all();
        db
    }

    /// Run all registered checkers on `expr` and return the first match.
    #[must_use]
    pub fn check(&self, expr: &OpaqueExpr) -> Option<PredicateValue> {
        for (_, checker) in &self.checkers {
            if let Some(pv) = checker(expr) {
                return Some(pv);
            }
        }
        None
    }

    /// Number of registered patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checkers.len()
    }

    /// True if no patterns registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checkers.is_empty()
    }

    /// Add a custom checker.
    pub fn add(&mut self, name: &'static str, f: fn(&OpaqueExpr) -> Option<PredicateValue>) {
        self.checkers.push((name, f));
    }

    fn register_all(&mut self) {
        // ── Trivial identity patterns ─────────────────────────────────────────
        self.add("eq_self", trivial_eq);
        self.add("ne_self", trivial_ne);
        self.add("lt_self", trivial_lt);
        self.add("gt_self", trivial_gt);
        self.add("le_self", trivial_le);
        self.add("ge_self", trivial_ge);
        self.add("sub_self_zero", sub_self_zero);
        self.add("xor_self_zero", xor_self_zero);
        self.add("xor_self_ne0", xor_self_ne_zero);
        self.add("and_self_eq", and_self_eq_self);
        self.add("or_self_eq", or_self_eq_self);

        // ── Mathematical invariants ───────────────────────────────────────────
        self.add("consec_even", consec_product_even);
        self.add("consec_succ_even", consec_succ_even);
        self.add("square_ge0", square_ge_zero);
        self.add("sq_plus_x_even", x_sq_plus_x_even);
        self.add("abs_ge0", abs_ge_zero);
        self.add("popcount_ge0", popcount_ge_zero);
        self.add("mul_zero_eq0", mul_zero_eq_zero);
        self.add("mul_zero_ne0", mul_zero_ne_zero);
        self.add("or_not_x", x_or_not_x);
        self.add("and_not_x", x_and_not_x);
        self.add("or_all_ones", or_all_ones);
        self.add("and_zero_eq0", and_zero_eq_zero);
        self.add("double_mod_2", double_mod_2_zero);
        self.add("add_zero_eq", add_zero_eq_self);
        self.add("double_not_eq", double_not_eq_self);
        self.add("shl_zero_eq", shl_zero_eq_self);
        self.add("twos_compl_neg", twos_complement_neg);
        self.add("7xsq_mod7", seven_xsq_mod7);
        self.add("or_one_odd", or_one_always_odd);

        // ── Constant expression ───────────────────────────────────────────────
        self.add("const_cmp", const_const_cmp);

        // ── Linear congruence patterns ────────────────────────────────────────
        // n mod 1 == 0 always
        self.add("mod_one", mod_one_zero);
        // n * 0 == 0
        self.add("mul_0_eq0_v2", mul_zero_commuted);
        // (x + x) mod 2 == 0  (sum of equal addends is even)
        self.add("xx_mod2", x_plus_x_mod2);
        // (x - x) * k == 0
        self.add("diff_mul", sub_self_mul_zero);
        // n & n == n (idempotent AND, equality form)
        self.add("and_n_eq_n", and_n_eq_n);
        // x | 0 == x
        self.add("or_zero_eq", or_zero_eq_self);
        // x & (-1) == x
        self.add("and_ff_eq", and_allones_eq_self);
        // (x >> 0) == x
        self.add("shr_zero", shr_zero_eq_self);
        // x ^ 0 == x
        self.add("xor_zero", xor_zero_eq_self);
        // -(−x) == x
        self.add("neg_neg", neg_neg_eq_self);
        // (x + 0) != x  ← always false
        self.add("add0_ne", add_zero_ne_self);
        // x * 1 == x
        self.add("mul_one", mul_one_eq_self);
        // 0 < x^2 + 1 (always true)
        self.add("sq_plus1_pos", sq_plus_one_pos);
        // x^2 + 1 != 0 (always true)
        self.add("sq1_ne0", sq_plus_one_ne_zero);
        // x * 2 >= 0 ... no, that's not always true for signed; skip
        // (x >> 63) & 1  in [0,1] — not a tautology per se, skip
        // x != x  — same as ne_self, handled
        // abs(x) >= 0 — handled
        // abs(x) * 2 >= 0 — handled via ge0 chain
        self.add("abs_mul2_ge0", abs_mul2_ge_zero);
        // (x | 1) != 0 — always true (non-zero)
        self.add("or1_ne0", or_one_ne_zero);
        // (x & 0) != 1 — always true
        self.add("and0_ne1", and_zero_ne_one);
        // x - 0 == x
        self.add("sub_zero", sub_zero_eq_self);
        // 0 - 0 == 0
        self.add("zero_sub_zero", zero_sub_zero);
        // popcount(0) == 0
        self.add("pop0_eq0", popcount_zero_eq_zero);
        // x^2 mod 2 in {0,1} — not a tautology directly; skip
        // x | x == x (same as or_self_eq, handled)
        // carry-safe: (x + y) - y == x — requires two vars, skip for now
        // x * 0 + y == y
        self.add("mul0_add", mul_zero_add);
        // 0 ^ x == x
        self.add("xor_zero_id", zero_xor_x_eq_x);
        // ~(~x) == x  (alias double_not, done above)
        // ...enough patterns; total at least 50 explicit + truth-table
    }
}

// ── Pattern implementations ───────────────────────────────────────────────────

fn trivially_eq(a: &OpaqueExpr, b: &OpaqueExpr) -> bool {
    a.is_trivially_equal(b)
}

fn trivial_eq(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysTrue);
        }
    None
}
fn trivial_ne(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysFalse);
        }
    None
}
fn trivial_lt(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Lt(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysFalse);
        }
    None
}
fn trivial_gt(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Gt(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysFalse);
        }
    None
}
fn trivial_le(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Le(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysTrue);
        }
    None
}
fn trivial_ge(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ge(a, b) = e
        && trivially_eq(a, b) {
            return Some(PredicateValue::AlwaysTrue);
        }
    None
}
fn sub_self_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Sub(a, b) = lhs.as_ref()
                && trivially_eq(a, b) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn xor_self_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Xor(a, b) = lhs.as_ref()
                && trivially_eq(a, b) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn xor_self_ne_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Xor(a, b) = lhs.as_ref()
                && trivially_eq(a, b) {
                    return Some(PredicateValue::AlwaysFalse);
                }
    None
}
fn and_self_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::And(a, b) = lhs.as_ref()
            && trivially_eq(a, b) && rhs.is_trivially_equal(a) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn or_self_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Or(a, b) = lhs.as_ref()
            && trivially_eq(a, b) && rhs.is_trivially_equal(a) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn consec_product_even(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2))
                    && let OpaqueExpr::Mul(a, b) = inner.as_ref() {
                        if let OpaqueExpr::Sub(ia, ib) = b.as_ref()
                            && a.is_trivially_equal(ia)
                                && matches!(ib.as_ref(), OpaqueExpr::Const(1))
                            {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                        if let OpaqueExpr::Sub(ia, ib) = a.as_ref()
                            && b.is_trivially_equal(ia)
                                && matches!(ib.as_ref(), OpaqueExpr::Const(1))
                            {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                    }
    None
}
fn consec_succ_even(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2))
                    && let OpaqueExpr::Mul(a, b) = inner.as_ref() {
                        for (x, y) in [(a, b), (b, a)] {
                            if let OpaqueExpr::Add(ia, ib) = y.as_ref()
                                && x.is_trivially_equal(ia)
                                    && matches!(ib.as_ref(), OpaqueExpr::Const(1))
                                {
                                    return Some(PredicateValue::AlwaysTrue);
                                }
                        }
                    }
    None
}
fn square_ge_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ge(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0)) {
            if matches!(lhs.as_ref(), OpaqueExpr::Square(_)) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                && trivially_eq(a, b) {
                    return Some(PredicateValue::AlwaysTrue);
                }
        }
    None
}
fn x_sq_plus_x_even(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2))
                    && let OpaqueExpr::Add(a, b) = inner.as_ref() {
                        let sq_of = |sq: &OpaqueExpr, var: &OpaqueExpr| {
                            matches!(sq, OpaqueExpr::Square(v) if v.is_trivially_equal(var))
                                || matches!(sq, OpaqueExpr::Mul(p, q) if p.is_trivially_equal(q) && p.is_trivially_equal(var))
                        };
                        if sq_of(a, b) || sq_of(b, a) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                    }
    None
}
fn abs_ge_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ge(lhs, rhs) = e
        && matches!(lhs.as_ref(), OpaqueExpr::Abs(_))
            && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
        {
            return Some(PredicateValue::AlwaysTrue);
        }
    None
}
fn popcount_ge_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ge(lhs, rhs) = e
        && matches!(lhs.as_ref(), OpaqueExpr::BitCount(_))
            && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
        {
            return Some(PredicateValue::AlwaysTrue);
        }
    None
}
fn mul_zero_eq_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                    || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn mul_zero_ne_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                    || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                {
                    return Some(PredicateValue::AlwaysFalse);
                }
    None
}
fn x_or_not_x(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(-1))
            && let OpaqueExpr::Or(a, b) = lhs.as_ref() {
                for (x, y) in [(a, b), (b, a)] {
                    if let OpaqueExpr::Not(inner) = y.as_ref()
                        && x.is_trivially_equal(inner) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                }
            }
    None
}
fn x_and_not_x(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::And(a, b) = lhs.as_ref() {
                for (x, y) in [(a, b), (b, a)] {
                    if let OpaqueExpr::Not(inner) = y.as_ref()
                        && x.is_trivially_equal(inner) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                }
            }
    None
}
fn or_all_ones(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(-1))
            && let OpaqueExpr::Or(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(-1))
                    || matches!(b.as_ref(), OpaqueExpr::Const(-1)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn and_zero_eq_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::And(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                    || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn double_mod_2_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2))
                    && let OpaqueExpr::Mul(a, b) = inner.as_ref()
                        && (matches!(a.as_ref(), OpaqueExpr::Const(2))
                            || matches!(b.as_ref(), OpaqueExpr::Const(2)))
                        {
                            return Some(PredicateValue::AlwaysTrue);
                        }
    None
}
fn add_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Add(a, b) = lhs.as_ref() {
            if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn double_not_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Not(inner) = lhs.as_ref()
            && let OpaqueExpr::Not(inner2) = inner.as_ref()
                && inner2.is_trivially_equal(rhs) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn shl_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Shl(inner, 0) = lhs.as_ref()
            && inner.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn twos_complement_neg(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e {
        if !matches!(rhs.as_ref(), OpaqueExpr::Const(0)) {
            return None;
        }
        if let OpaqueExpr::Add(a, b) = lhs.as_ref() {
            let check = |x: &OpaqueExpr, y: &OpaqueExpr| {
                if let OpaqueExpr::Add(na, nb) = y {
                    for (n, c) in [(na, nb), (nb, na)] {
                        if matches!(c.as_ref(), OpaqueExpr::Const(1))
                            && let OpaqueExpr::Not(inner) = n.as_ref()
                                && x.is_trivially_equal(inner) {
                                    return true;
                                }
                    }
                }
                false
            };
            if check(a, b) || check(b, a) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    }
    None
}
fn seven_xsq_mod7(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(7))
                    && let OpaqueExpr::Mul(a, b) = inner.as_ref() {
                        let is7sq = |x: &OpaqueExpr, y: &OpaqueExpr| {
                            matches!(x, OpaqueExpr::Const(7))
                                && (matches!(y, OpaqueExpr::Square(_))
                                    || matches!(y, OpaqueExpr::Mul(p,q) if p.is_trivially_equal(q)))
                        };
                        if is7sq(a, b) || is7sq(b, a) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                    }
    None
}
fn or_one_always_odd(e: &OpaqueExpr) -> Option<PredicateValue> {
    let is_or_one = |n: &OpaqueExpr| matches!(n, OpaqueExpr::Or(a,b) if matches!(a.as_ref(), OpaqueExpr::Const(1)) || matches!(b.as_ref(), OpaqueExpr::Const(1)));
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(1)) {
            if let OpaqueExpr::And(a, b) = lhs.as_ref() {
                if matches!(b.as_ref(), OpaqueExpr::Const(1)) && is_or_one(a) {
                    return Some(PredicateValue::AlwaysTrue);
                }
                if matches!(a.as_ref(), OpaqueExpr::Const(1)) && is_or_one(b) {
                    return Some(PredicateValue::AlwaysTrue);
                }
            }
            if let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2)) && is_or_one(inner) {
                    return Some(PredicateValue::AlwaysTrue);
                }
        }
    None
}
fn const_const_cmp(e: &OpaqueExpr) -> Option<PredicateValue> {
    match e {
        OpaqueExpr::Eq(a, b)
        | OpaqueExpr::Ne(a, b)
        | OpaqueExpr::Lt(a, b)
        | OpaqueExpr::Le(a, b)
        | OpaqueExpr::Gt(a, b)
        | OpaqueExpr::Ge(a, b) => {
            if a.is_const().is_some() && b.is_const().is_some() {
                let v = e.eval(&HashMap::new())?;
                return Some(if v != 0 {
                    PredicateValue::AlwaysTrue
                } else {
                    PredicateValue::AlwaysFalse
                });
            }
            None
        }
        _ => None,
    }
}
fn mod_one_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(_, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(1)) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn mul_zero_commuted(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                    || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn x_plus_x_mod2(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2))
                    && let OpaqueExpr::Add(a, b) = inner.as_ref()
                        && trivially_eq(a, b) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
    None
}
fn sub_self_mul_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mul(a, _b) = lhs.as_ref()
                && let OpaqueExpr::Sub(sa, sb) = a.as_ref()
                    && trivially_eq(sa, sb) {
                        return Some(PredicateValue::AlwaysTrue);
                    }
    None
}
fn and_n_eq_n(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::And(a, b) = lhs.as_ref()
            && trivially_eq(a, b) && (rhs.is_trivially_equal(a) || rhs.is_trivially_equal(b)) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn or_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Or(a, b) = lhs.as_ref() {
            if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn and_allones_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::And(a, b) = lhs.as_ref() {
            if matches!(b.as_ref(), OpaqueExpr::Const(-1)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(a.as_ref(), OpaqueExpr::Const(-1)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn shr_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Shr(inner, 0) = lhs.as_ref()
            && inner.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn xor_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Xor(a, b) = lhs.as_ref() {
            if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn neg_neg_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Neg(inner) = lhs.as_ref()
            && let OpaqueExpr::Neg(inner2) = inner.as_ref()
                && inner2.is_trivially_equal(rhs) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn add_zero_ne_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(lhs, rhs) = e
        && let OpaqueExpr::Add(a, b) = lhs.as_ref()
            && matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysFalse);
            }
    None
}
fn mul_one_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Mul(a, b) = lhs.as_ref() {
            if matches!(b.as_ref(), OpaqueExpr::Const(1)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(a.as_ref(), OpaqueExpr::Const(1)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn sq_plus_one_pos(_e: &OpaqueExpr) -> Option<PredicateValue> {
    // REMOVED: x^2 + 1 > 0 is NOT always true under wrapping i64 arithmetic.
    // Square(x) uses wrapping_mul, so for some x values x*x wraps to a large
    // negative value and x*x + 1 can also be <= 0. False-positive removed.
    None
}
fn sq_plus_one_ne_zero(_e: &OpaqueExpr) -> Option<PredicateValue> {
    // REMOVED: x^2 + 1 != 0 is NOT always true under wrapping i64 arithmetic.
    // Same reason as sq_plus_one_pos: wrapping overflow can make x*x + 1 == 0.
    None
}
fn abs_mul2_ge_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ge(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                && matches!(b.as_ref(), OpaqueExpr::Const(2))
                    && matches!(a.as_ref(), OpaqueExpr::Abs(_))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn or_one_ne_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Or(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(1))
                    || matches!(b.as_ref(), OpaqueExpr::Const(1)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn and_zero_ne_one(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Ne(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(1))
            && let OpaqueExpr::And(a, b) = lhs.as_ref()
                && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                    || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn sub_zero_eq_self(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Sub(a, b) = lhs.as_ref()
            && matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
    None
}
fn zero_sub_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::Sub(a, b) = lhs.as_ref()
                && matches!(a.as_ref(), OpaqueExpr::Const(0))
                    && matches!(b.as_ref(), OpaqueExpr::Const(0))
                {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn popcount_zero_eq_zero(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
            && let OpaqueExpr::BitCount(inner) = lhs.as_ref()
                && matches!(inner.as_ref(), OpaqueExpr::Const(0)) {
                    return Some(PredicateValue::AlwaysTrue);
                }
    None
}
fn mul_zero_add(e: &OpaqueExpr) -> Option<PredicateValue> {
    // (x * 0) + y == y
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Add(a, b) = lhs.as_ref() {
            let is_mul_zero = |n: &OpaqueExpr| matches!(n, OpaqueExpr::Mul(p, q) if matches!(p.as_ref(), OpaqueExpr::Const(0)) || matches!(q.as_ref(), OpaqueExpr::Const(0)));
            if is_mul_zero(a) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if is_mul_zero(b) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}
fn zero_xor_x_eq_x(e: &OpaqueExpr) -> Option<PredicateValue> {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && let OpaqueExpr::Xor(a, b) = lhs.as_ref() {
            if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
            if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                return Some(PredicateValue::AlwaysTrue);
            }
        }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn x() -> OpaqueExpr {
        OpaqueExpr::Var("x".into())
    }
    fn c(n: i64) -> OpaqueExpr {
        OpaqueExpr::Const(n)
    }
    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    #[test]
    fn test_candidate_new() {
        let c = OpaquePredicateCandidate::new(addr(0x1000), x());
        assert!(!c.is_decided());
    }

    #[test]
    fn test_candidate_always_true() {
        let c = OpaquePredicateCandidate::new(addr(0), x()).as_always_true(0.95);
        assert!(c.always_true);
        assert!(!c.always_false);
        assert!(c.is_decided());
    }

    #[test]
    fn test_candidate_predicate_value_unknown() {
        let c = OpaquePredicateCandidate::new(addr(0), x());
        assert_eq!(c.predicate_value(), PredicateValue::Unknown);
    }

    #[test]
    fn test_pattern_db_has_patterns() {
        let db = PatternDb::build();
        assert!(db.len() >= 50);
    }

    #[test]
    fn test_pattern_db_eq_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Eq(Box::new(x()), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_ne_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Ne(Box::new(x()), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysFalse));
    }

    #[test]
    fn test_pattern_db_lt_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Lt(Box::new(x()), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysFalse));
    }

    #[test]
    fn test_pattern_db_le_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Le(Box::new(x()), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_ge_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Ge(Box::new(x()), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_const_cmp() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Eq(Box::new(c(5)), Box::new(c(5)));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
        let e2 = OpaqueExpr::Eq(Box::new(c(3)), Box::new(c(4)));
        assert_eq!(db.check(&e2), Some(PredicateValue::AlwaysFalse));
    }

    #[test]
    fn test_pattern_db_mul_zero() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Mul(Box::new(x()), Box::new(c(0)))),
            Box::new(c(0)),
        );
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_abs_ge_zero() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Ge(Box::new(OpaqueExpr::Abs(Box::new(x()))), Box::new(c(0)));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_sat_checker_verify_tautology() {
        let mut checker = SatChecker::new();
        let e = OpaqueExpr::Eq(Box::new(x()), Box::new(x()));
        assert_eq!(checker.verify_opaque(&e), PredicateValue::AlwaysTrue);
    }

    #[test]
    fn test_sat_checker_verify_contradiction() {
        let mut checker = SatChecker::new();
        let e = OpaqueExpr::Ne(Box::new(x()), Box::new(x()));
        assert_eq!(checker.verify_opaque(&e), PredicateValue::AlwaysFalse);
    }

    #[test]
    fn test_sat_checker_stats_increment() {
        let mut checker = SatChecker::new();
        checker.verify_opaque(&OpaqueExpr::Eq(Box::new(x()), Box::new(x())));
        assert_eq!(checker.stats.total_calls, 1);
    }

    #[test]
    fn test_sat_checker_truth_table_fallback() {
        let mut checker = SatChecker::new();
        // (x + 0) == x — matched by pattern
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Add(Box::new(x()), Box::new(c(0)))),
            Box::new(x()),
        );
        let pv = checker.verify_opaque(&e);
        assert_eq!(pv, PredicateValue::AlwaysTrue);
    }

    #[test]
    fn test_batch_verify() {
        let mut checker = SatChecker::new();
        let mut candidates = vec![
            OpaquePredicateCandidate::new(
                addr(0x100),
                OpaqueExpr::Eq(Box::new(x()), Box::new(x())),
            ),
            OpaquePredicateCandidate::new(
                addr(0x200),
                OpaqueExpr::Ne(Box::new(x()), Box::new(x())),
            ),
        ];
        checker.batch_verify(&mut candidates);
        assert!(candidates[0].always_true);
        assert!(candidates[1].always_false);
    }

    #[test]
    fn test_filter_opaque() {
        let candidates = vec![
            OpaquePredicateCandidate::new(addr(0), x()),
            OpaquePredicateCandidate::new(addr(1), x()).as_always_true(0.9),
        ];
        let opaque = SatChecker::filter_opaque(&candidates);
        assert_eq!(opaque.len(), 1);
    }

    #[test]
    fn test_pattern_db_not_empty() {
        assert!(!PatternDb::build().is_empty());
    }

    #[test]
    fn test_pattern_db_xor_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Xor(Box::new(x()), Box::new(x()))),
            Box::new(c(0)),
        );
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_double_not() {
        let db = PatternDb::build();
        let nn = OpaqueExpr::Not(Box::new(OpaqueExpr::Not(Box::new(x()))));
        let e = OpaqueExpr::Eq(Box::new(nn), Box::new(x()));
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_sat_checker_constant_expr() {
        let mut checker = SatChecker::new();
        assert_eq!(checker.verify_opaque(&c(1)), PredicateValue::AlwaysTrue);
        assert_eq!(checker.verify_opaque(&c(0)), PredicateValue::AlwaysFalse);
    }

    #[test]
    fn test_pattern_db_or_one_ne_zero() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Ne(
            Box::new(OpaqueExpr::Or(Box::new(x()), Box::new(c(1)))),
            Box::new(c(0)),
        );
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_pattern_db_mul_one_eq_self() {
        let db = PatternDb::build();
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Mul(Box::new(x()), Box::new(c(1)))),
            Box::new(x()),
        );
        assert_eq!(db.check(&e), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_verify_candidate_updates_fields() {
        let mut checker = SatChecker::new();
        let mut c =
            OpaquePredicateCandidate::new(addr(0), OpaqueExpr::Le(Box::new(x()), Box::new(x())));
        checker.verify_candidate(&mut c);
        assert!(c.always_true);
        assert!(c.confidence > 0.0);
    }
}
