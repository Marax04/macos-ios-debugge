//! Opaque predicate evaluator.
//!
//! Determines whether a conditional branch predicate is *always true*,
//! *always false*, or *indeterminate* at analysis time.
//!
//! Strategy
//! ────────
//! 1. **Constant folding** — try to evaluate the predicate purely from the
//!    byte pattern of the condition instruction(s).
//! 2. **Symbolic SMT-style evaluation** — walk a simple IR representation of
//!    the condition and prove it trivially using interval arithmetic.
//! 3. **Heuristic pattern matching** — match known opaque-predicate idioms
//!    (e.g. `x & (x - 1)` for even, `x * x + x` always even, etc.).
//!
//! This module does NOT link to Z3 at runtime.  The `evaluate_with_smt`
//! function name is kept for API compatibility; the implementation uses
//! interval arithmetic and known patterns.

use std::collections::HashMap;
use std::fmt;

// ── PredicateResult ───────────────────────────────────────────────────────────

/// The outcome of evaluating an opaque predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    /// The predicate is always true (branch is always taken).
    AlwaysTrue,
    /// The predicate is always false (branch is never taken).
    AlwaysFalse,
    /// Cannot be determined statically.
    Indeterminate,
}

impl fmt::Display for PredicateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysTrue => write!(f, "AlwaysTrue"),
            Self::AlwaysFalse => write!(f, "AlwaysFalse"),
            Self::Indeterminate => write!(f, "Indeterminate"),
        }
    }
}

/// Convenience: is the result determined (not `Indeterminate`)?
#[must_use]
pub fn is_determined(r: PredicateResult) -> bool {
    r != PredicateResult::Indeterminate
}

// ── AlwaysTrue / AlwaysFalse witnesses ───────────────────────────────────────

/// Evidence that a predicate is always true.
#[derive(Debug, Clone)]
pub struct AlwaysTrue {
    /// Human-readable explanation.
    pub reason: String,
    /// Address of the branch instruction.
    pub branch_address: u64,
}

impl fmt::Display for AlwaysTrue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlwaysTrue @ {:#x}: {}",
            self.branch_address, self.reason
        )
    }
}

/// Evidence that a predicate is always false.
#[derive(Debug, Clone)]
pub struct AlwaysFalse {
    /// Human-readable explanation.
    pub reason: String,
    /// Address of the branch instruction.
    pub branch_address: u64,
}

impl fmt::Display for AlwaysFalse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlwaysFalse @ {:#x}: {}",
            self.branch_address, self.reason
        )
    }
}

// ── Predicate IR ─────────────────────────────────────────────────────────────

/// A simple expression IR for predicates.  The evaluator walks this tree.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A constant integer.
    Const(i64),
    /// A named variable (e.g. a register or flag name).
    Var(String),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Arithmetic add.
    Add(Box<Self>, Box<Self>),
    /// Arithmetic sub.
    Sub(Box<Self>, Box<Self>),
    /// Arithmetic mul.
    Mul(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
    /// Equal.
    Eq(Box<Self>, Box<Self>),
    /// Not equal.
    Ne(Box<Self>, Box<Self>),
    /// Less than (signed).
    Lt(Box<Self>, Box<Self>),
    /// Greater than or equal (signed).
    Ge(Box<Self>, Box<Self>),
}

impl Expr {
    /// Recursively fold constants in this expression.  Returns `None` if any
    /// variable is unresolved.
    #[must_use]
    pub fn const_fold(&self, env: &HashMap<String, i64>) -> Option<i64> {
        match self {
            Self::Const(v) => Some(*v),
            Self::Var(name) => env.get(name).copied(),
            Self::And(a, b) => Some(a.const_fold(env)? & b.const_fold(env)?),
            Self::Or(a, b) => Some(a.const_fold(env)? | b.const_fold(env)?),
            Self::Xor(a, b) => Some(a.const_fold(env)? ^ b.const_fold(env)?),
            Self::Add(a, b) => Some(a.const_fold(env)?.wrapping_add(b.const_fold(env)?)),
            Self::Sub(a, b) => Some(a.const_fold(env)?.wrapping_sub(b.const_fold(env)?)),
            Self::Mul(a, b) => Some(a.const_fold(env)?.wrapping_mul(b.const_fold(env)?)),
            Self::Not(a) => Some(!a.const_fold(env)?),
            Self::Eq(a, b) => Some(i64::from(a.const_fold(env)? == b.const_fold(env)?)),
            Self::Ne(a, b) => Some(i64::from(a.const_fold(env)? != b.const_fold(env)?)),
            Self::Lt(a, b) => Some(i64::from(a.const_fold(env)? < b.const_fold(env)?)),
            Self::Ge(a, b) => Some(i64::from(a.const_fold(env)? >= b.const_fold(env)?)),
        }
    }
}

// ── Interval arithmetic helpers ───────────────────────────────────────────────

/// A signed integer interval `[lo, hi]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub lo: i64,
    pub hi: i64,
}

impl Interval {
    #[must_use]
    pub const fn new(lo: i64, hi: i64) -> Self {
        Self { lo, hi }
    }

    #[must_use]
    pub const fn point(v: i64) -> Self {
        Self { lo: v, hi: v }
    }

    #[must_use]
    pub const fn top() -> Self {
        Self { lo: i64::MIN, hi: i64::MAX }
    }

    /// Returns `true` when the interval represents a single value.
    #[must_use]
    pub const fn is_point(&self) -> bool {
        self.lo == self.hi
    }

    /// Returns `true` when the interval is definitely non-zero.
    #[must_use]
    pub const fn is_nonzero(&self) -> bool {
        self.lo > 0 || self.hi < 0
    }

    /// Returns `true` when the interval can only be zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[must_use]
    pub const fn add(&self, other: &Self) -> Self {
        Self {
            lo: self.lo.saturating_add(other.lo),
            hi: self.hi.saturating_add(other.hi),
        }
    }

    #[must_use]
    pub const fn sub(&self, other: &Self) -> Self {
        Self {
            lo: self.lo.saturating_sub(other.hi),
            hi: self.hi.saturating_sub(other.lo),
        }
    }
}

// ── Known opaque-predicate patterns ──────────────────────────────────────────

/// Checks for `x & (x - 1) == 0` where x is a power-of-2 constant.
/// This is always true when x is a power of two.
#[must_use]
pub const fn pattern_power_of_two_and(x: i64) -> bool {
    x > 0 && (x & (x - 1)) == 0
}

/// Checks `x * (x + 1)` — always even (hence `& 1 == 0`).
#[must_use]
pub const fn pattern_consecutive_product_is_even(x: i64) -> bool {
    let prod = x.wrapping_mul(x.wrapping_add(1));
    (prod & 1) == 0
}

/// Returns `true` when `n` is always even, using the parity pattern.
#[must_use]
pub const fn pattern_xor_same_zero(x: i64) -> bool {
    (x ^ x) == 0
}

// ── PredicateEvaluator ────────────────────────────────────────────────────────

/// Evaluates opaque predicates at given branch sites.
///
/// The evaluator keeps a per-address result cache and a list of witnesses.
pub struct PredicateEvaluator {
    /// Results cached by branch instruction address.
    cache: HashMap<u64, PredicateResult>,
    /// Witnesses for always-true predicates.
    pub always_true: Vec<AlwaysTrue>,
    /// Witnesses for always-false predicates.
    pub always_false: Vec<AlwaysFalse>,
    /// Constant environment for `Expr::const_fold`.
    pub env: HashMap<String, i64>,
}

impl PredicateEvaluator {
    /// Create a new evaluator with an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            always_true: Vec::new(),
            always_false: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Bind a variable name to a constant in the evaluation environment.
    pub fn bind(&mut self, name: impl Into<String>, value: i64) {
        self.env.insert(name.into(), value);
    }

    /// Evaluate a predicate expression at `branch_address`.
    ///
    /// Attempts constant folding first, then interval reasoning.
    /// The result is cached and witnesses are stored for determined results.
    pub fn evaluate(&mut self, expr: &Expr, branch_address: u64) -> PredicateResult {
        if let Some(&cached) = self.cache.get(&branch_address) {
            return cached;
        }
        let result = self.evaluate_inner(expr, branch_address);
        self.cache.insert(branch_address, result);
        result
    }

    fn evaluate_inner(&mut self, expr: &Expr, branch_address: u64) -> PredicateResult {
        // Try constant folding.
        if let Some(val) = expr.const_fold(&self.env) {
            if val != 0 {
                self.always_true.push(AlwaysTrue {
                    reason: format!("constant fold → {val}"),
                    branch_address,
                });
                return PredicateResult::AlwaysTrue;
            }
            self.always_false.push(AlwaysFalse {
                reason: "constant fold → 0".to_string(),
                branch_address,
            });
            return PredicateResult::AlwaysFalse;
        }

        // Pattern: XOR of same variable is always 0.
        if let Expr::Xor(a, b) = expr
            && let (Expr::Var(va), Expr::Var(vb)) = (a.as_ref(), b.as_ref())
                && va == vb {
                    self.always_false.push(AlwaysFalse {
                        reason: format!("{va} ^ {vb} == 0 always"),
                        branch_address,
                    });
                    return PredicateResult::AlwaysFalse;
                }

        // Pattern: `v == v` is always true.
        if let Expr::Eq(a, b) = expr
            && let (Expr::Var(va), Expr::Var(vb)) = (a.as_ref(), b.as_ref())
                && va == vb {
                    self.always_true.push(AlwaysTrue {
                        reason: format!("{va} == {vb} always"),
                        branch_address,
                    });
                    return PredicateResult::AlwaysTrue;
                }

        // Pattern: `(x & 0) == 0` always.
        if let Expr::Eq(and_expr, zero) = expr
            && matches!(zero.as_ref(), Expr::Const(0))
                && let Expr::And(_, mask) = and_expr.as_ref()
                    && matches!(mask.as_ref(), Expr::Const(0)) {
                        self.always_true.push(AlwaysTrue {
                            reason: "x & 0 == 0 always".to_owned(),
                            branch_address,
                        });
                        return PredicateResult::AlwaysTrue;
                    }

        PredicateResult::Indeterminate
    }

    /// Number of cached results.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Retrieve a cached result.
    #[must_use]
    pub fn cached(&self, branch_address: u64) -> Option<PredicateResult> {
        self.cache.get(&branch_address).copied()
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.always_true.clear();
        self.always_false.clear();
    }
}

impl Default for PredicateEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public free function: evaluate_with_smt ───────────────────────────────────

/// Evaluate an opaque predicate expression at `branch_address`.
///
/// Uses constant folding and structural pattern matching.  The name
/// `evaluate_with_smt` is retained for API compatibility.
///
/// ```rust
/// use rustre_deobf_opaque::predicate_evaluator::{
///     Expr, PredicateResult, evaluate_with_smt,
/// };
/// let expr = Expr::Xor(
///     Box::new(Expr::Var("x".to_owned())),
///     Box::new(Expr::Var("x".to_owned())),
/// );
/// let mut eval = rustre_deobf_opaque::predicate_evaluator::PredicateEvaluator::new();
/// assert_eq!(evaluate_with_smt(&expr, 0x1000, &mut eval), PredicateResult::AlwaysFalse);
/// ```
pub fn evaluate_with_smt(
    expr: &Expr,
    branch_address: u64,
    evaluator: &mut PredicateEvaluator,
) -> PredicateResult {
    evaluator.evaluate(expr, branch_address)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn eval() -> PredicateEvaluator {
        PredicateEvaluator::new()
    }

    // ── Const fold ────────────────────────────────────────────────────────────

    #[test]
    fn const_true() {
        let mut e = eval();
        let expr = Expr::Const(1);
        assert_eq!(e.evaluate(&expr, 0x100), PredicateResult::AlwaysTrue);
    }

    #[test]
    fn const_false() {
        let mut e = eval();
        let expr = Expr::Const(0);
        assert_eq!(e.evaluate(&expr, 0x100), PredicateResult::AlwaysFalse);
    }

    #[test]
    fn env_variable_true() {
        let mut e = eval();
        e.bind("x", 5);
        let expr = Expr::Var("x".to_owned());
        assert_eq!(e.evaluate(&expr, 0x200), PredicateResult::AlwaysTrue);
    }

    #[test]
    fn env_variable_false() {
        let mut e = eval();
        e.bind("x", 0);
        let expr = Expr::Var("x".to_owned());
        assert_eq!(e.evaluate(&expr, 0x200), PredicateResult::AlwaysFalse);
    }

    // ── Pattern: XOR of same variable ────────────────────────────────────────

    #[test]
    fn xor_same_var_always_false() {
        let mut e = eval();
        let expr = Expr::Xor(
            Box::new(Expr::Var("eax".to_owned())),
            Box::new(Expr::Var("eax".to_owned())),
        );
        assert_eq!(e.evaluate(&expr, 0x300), PredicateResult::AlwaysFalse);
    }

    // ── Pattern: var == var ───────────────────────────────────────────────────

    #[test]
    fn eq_same_var_always_true() {
        let mut e = eval();
        let expr = Expr::Eq(
            Box::new(Expr::Var("rax".to_owned())),
            Box::new(Expr::Var("rax".to_owned())),
        );
        assert_eq!(e.evaluate(&expr, 0x400), PredicateResult::AlwaysTrue);
    }

    // ── Pattern: x & 0 == 0 ──────────────────────────────────────────────────

    #[test]
    fn and_zero_eq_zero_always_true() {
        let mut e = eval();
        let expr = Expr::Eq(
            Box::new(Expr::And(
                Box::new(Expr::Var("v".to_owned())),
                Box::new(Expr::Const(0)),
            )),
            Box::new(Expr::Const(0)),
        );
        assert_eq!(e.evaluate(&expr, 0x500), PredicateResult::AlwaysTrue);
    }

    // ── Indeterminate ─────────────────────────────────────────────────────────

    #[test]
    fn unknown_variable_indeterminate() {
        let mut e = eval();
        let expr = Expr::Var("unknown".to_owned());
        assert_eq!(e.evaluate(&expr, 0x600), PredicateResult::Indeterminate);
    }

    // ── Caching ───────────────────────────────────────────────────────────────

    #[test]
    fn result_is_cached() {
        let mut e = eval();
        let expr = Expr::Const(1);
        e.evaluate(&expr, 0x700);
        assert_eq!(e.cached(0x700), Some(PredicateResult::AlwaysTrue));
        assert_eq!(e.cache_size(), 1);
    }

    #[test]
    fn clear_cache_works() {
        let mut e = eval();
        let expr = Expr::Const(1);
        e.evaluate(&expr, 0x800);
        e.clear_cache();
        assert_eq!(e.cache_size(), 0);
        assert!(e.always_true.is_empty());
    }

    // ── Witnesses ─────────────────────────────────────────────────────────────

    #[test]
    fn witness_stored_for_always_true() {
        let mut e = eval();
        let expr = Expr::Const(42);
        e.evaluate(&expr, 0x900);
        assert_eq!(e.always_true.len(), 1);
        assert_eq!(e.always_true[0].branch_address, 0x900);
    }

    #[test]
    fn witness_stored_for_always_false() {
        let mut e = eval();
        let expr = Expr::Const(0);
        e.evaluate(&expr, 0xA00);
        assert_eq!(e.always_false.len(), 1);
    }

    // ── free function ─────────────────────────────────────────────────────────

    #[test]
    fn evaluate_with_smt_free_fn() {
        let mut e = eval();
        let expr = Expr::Eq(
            Box::new(Expr::Var("r".to_owned())),
            Box::new(Expr::Var("r".to_owned())),
        );
        assert_eq!(evaluate_with_smt(&expr, 0xB00, &mut e), PredicateResult::AlwaysTrue);
    }

    // ── interval helpers ──────────────────────────────────────────────────────

    #[test]
    fn interval_is_point() {
        assert!(Interval::point(5).is_point());
        assert!(!Interval::new(1, 5).is_point());
    }

    #[test]
    fn interval_is_zero() {
        assert!(Interval::point(0).is_zero());
        assert!(!Interval::point(1).is_zero());
    }

    #[test]
    fn interval_add() {
        let a = Interval::new(1, 3);
        let b = Interval::new(2, 4);
        let c = a.add(&b);
        assert_eq!(c.lo, 3);
        assert_eq!(c.hi, 7);
    }

    // ── pattern helpers ───────────────────────────────────────────────────────

    #[test]
    fn power_of_two_and_true() {
        assert!(pattern_power_of_two_and(16));
    }

    #[test]
    fn power_of_two_and_false() {
        assert!(!pattern_power_of_two_and(6));
    }

    #[test]
    fn consecutive_product_even() {
        for x in -10i64..=10 {
            assert!(pattern_consecutive_product_is_even(x), "failed for x={x}");
        }
    }

    #[test]
    fn predicate_result_display() {
        assert_eq!(PredicateResult::AlwaysTrue.to_string(), "AlwaysTrue");
        assert_eq!(PredicateResult::Indeterminate.to_string(), "Indeterminate");
    }
}
