//! Boolean algebra simplification for Mixed Boolean Arithmetic expressions.
//!
//! This module provides a simplifier for pure boolean (bitwise) expressions
//! using De Morgan's laws, absorption, idempotency, complementation, and
//! normal-form conversion (Disjunctive Normal Form / Conjunctive Normal Form).
//!
//! The simplifier operates on [`BoolExpr`], a dedicated boolean expression
//! tree that is simpler than [`MbaExpr`] and supports direct normalisation
//! into DNF or CNF.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// BoolExpr
// ---------------------------------------------------------------------------

/// A pure boolean expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BoolExpr {
    /// A boolean variable (bit slice of a variable, e.g. `x`).
    Var(String),
    /// Boolean constant `true` (all bits 1).
    True,
    /// Boolean constant `false` (all bits 0).
    False,
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
}

impl BoolExpr {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Build a NOT node.
    #[must_use]
    pub fn not(e: Self) -> Self { Self::Not(Box::new(e)) }

    /// Build an AND node.
    #[must_use]
    pub fn and(l: Self, r: Self) -> Self { Self::And(Box::new(l), Box::new(r)) }

    /// Build an OR node.
    #[must_use]
    pub fn or(l: Self, r: Self) -> Self { Self::Or(Box::new(l), Box::new(r)) }

    /// Build a XOR node.
    #[must_use]
    pub fn xor(l: Self, r: Self) -> Self { Self::Xor(Box::new(l), Box::new(r)) }

    /// Build a variable node.
    #[must_use]
    pub fn var(name: impl Into<String>) -> Self { Self::Var(name.into()) }

    // ── Metrics ───────────────────────────────────────────────────────────

    /// Number of nodes in the tree.
    #[must_use]
    pub fn complexity(&self) -> usize {
        match self {
            Self::Var(_) | Self::True | Self::False => 1,
            Self::Not(e) => 1 + e.complexity(),
            Self::And(l, r) | Self::Or(l, r) | Self::Xor(l, r) => {
                1 + l.complexity() + r.complexity()
            }
        }
    }

    /// Collect all unique variable names.
    #[must_use]
    pub fn vars(&self) -> Vec<String> {
        let mut seen = Vec::new();
        self.collect_vars(&mut seen);
        seen
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Var(n) => { if !out.contains(n) { out.push(n.clone()); } }
            Self::True | Self::False => {}
            Self::Not(e) => e.collect_vars(out),
            Self::And(l, r) | Self::Or(l, r) | Self::Xor(l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
        }
    }

    /// Evaluate the expression with the given boolean variable assignments.
    #[must_use]
    pub fn eval(&self, vars: &HashMap<String, bool>) -> Option<bool> {
        match self {
            Self::True => Some(true),
            Self::False => Some(false),
            Self::Var(n) => vars.get(n).copied(),
            Self::Not(e) => Some(!e.eval(vars)?),
            Self::And(l, r) => Some(l.eval(vars)? && r.eval(vars)?),
            Self::Or(l, r) => Some(l.eval(vars)? || r.eval(vars)?),
            Self::Xor(l, r) => Some(l.eval(vars)? ^ r.eval(vars)?),
        }
    }
}

impl fmt::Display for BoolExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(n) => write!(f, "{n}"),
            Self::True => f.write_str("1"),
            Self::False => f.write_str("0"),
            Self::Not(e) => write!(f, "~{e}"),
            Self::And(l, r) => write!(f, "({l} & {r})"),
            Self::Or(l, r) => write!(f, "({l} | {r})"),
            Self::Xor(l, r) => write!(f, "({l} ^ {r})"),
        }
    }
}

// ---------------------------------------------------------------------------
// NormalForm
// ---------------------------------------------------------------------------

/// The target normal form for conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalForm {
    /// Disjunctive Normal Form: OR of AND clauses.
    Dnf,
    /// Conjunctive Normal Form: AND of OR clauses.
    Cnf,
    /// Negation Normal Form: NOT pushed to leaves.
    Nnf,
}

impl fmt::Display for NormalForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dnf => f.write_str("DNF"),
            Self::Cnf => f.write_str("CNF"),
            Self::Nnf => f.write_str("NNF"),
        }
    }
}

// ---------------------------------------------------------------------------
// SimplificationStep
// ---------------------------------------------------------------------------

/// One recorded step in the boolean simplification trace.
#[derive(Debug, Clone)]
pub struct BoolSimplStep {
    /// Name of the law/rule applied.
    pub law: &'static str,
    /// Expression before.
    pub before: BoolExpr,
    /// Expression after.
    pub after: BoolExpr,
}

// ---------------------------------------------------------------------------
// BooleanAlgebraSimplifier
// ---------------------------------------------------------------------------

/// Configuration for the boolean simplifier.
#[derive(Debug, Clone)]
pub struct BoolSimplConfig {
    /// Maximum simplification iterations.
    pub max_iterations: usize,
    /// Apply De Morgan's laws to push NOT inward.
    pub apply_de_morgan: bool,
    /// Apply absorption: `x & (x | y) → x`.
    pub apply_absorption: bool,
    /// Target normal form (or `None` to skip conversion).
    pub target_form: Option<NormalForm>,
    /// Record a trace of each step.
    pub trace: bool,
}

impl Default for BoolSimplConfig {
    fn default() -> Self {
        Self {
            max_iterations: 64,
            apply_de_morgan: true,
            apply_absorption: true,
            target_form: None,
            trace: false,
        }
    }
}

/// Result of boolean algebra simplification.
#[derive(Debug, Clone)]
pub struct BoolSimplResult {
    /// The simplified expression.
    pub simplified: BoolExpr,
    /// Complexity before simplification.
    pub original_complexity: usize,
    /// Complexity after simplification.
    pub final_complexity: usize,
    /// Number of iterations performed.
    pub iterations: usize,
    /// Trace of applied rules (only populated when `trace: true`).
    pub steps: Vec<BoolSimplStep>,
}

impl BoolSimplResult {
    /// Complexity reduction.
    #[must_use]
    pub const fn reduction(&self) -> usize {
        self.original_complexity.saturating_sub(self.final_complexity)
    }
}

/// Boolean algebra simplifier using classic algebraic laws.
///
/// Laws applied:
/// - Idempotency: `x & x → x`, `x | x → x`
/// - Complement: `x & ~x → 0`, `x | ~x → 1`
/// - Double negation: `~~x → x`
/// - De Morgan: `~(x & y) → ~x | ~y`, `~(x | y) → ~x & ~y`
/// - Absorption: `x & (x | y) → x`, `x | (x & y) → x`
/// - Identity: `x & 1 → x`, `x & 0 → 0`, `x | 0 → x`, `x | 1 → 1`
/// - XOR self: `x ^ x → 0`
/// - XOR identity: `x ^ 0 → x`
#[derive(Debug, Clone)]
pub struct BooleanAlgebraSimplifier {
    config: BoolSimplConfig,
}

impl BooleanAlgebraSimplifier {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: BoolSimplConfig::default() }
    }

    /// Create with a custom configuration.
    #[must_use]
    pub const fn with_config(config: BoolSimplConfig) -> Self {
        Self { config }
    }

    /// Simplify `expr` and return a `BoolSimplResult`.
    #[must_use]
    pub fn simplify(&self, expr: BoolExpr) -> BoolSimplResult {
        let original_complexity = expr.complexity();
        let mut current = expr;
        let mut iterations = 0;
        let mut steps = Vec::new();

        for _ in 0..self.config.max_iterations {
            let (next, fired) = self.simplify_once(&current);
            iterations += 1;
            // When tracing, track steps and use fired.is_empty() to detect fixed point.
            // When not tracing, fired is always empty (fire! skips the push), so we
            // rely solely on structural equality to detect fixed point.
            if self.config.trace {
                let is_empty = fired.is_empty();
                for (law, before, after) in fired {
                    steps.push(BoolSimplStep { law, before, after });
                }
                if is_empty {
                    break;
                }
            }
            if next == current {
                break;
            }
            current = next;
        }

        // Optionally convert to a normal form
        if let Some(form) = self.config.target_form {
            current = convert_to_normal_form(current, form);
        }

        let final_complexity = current.complexity();
        BoolSimplResult { simplified: current, original_complexity, final_complexity, iterations, steps }
    }

    /// Run one bottom-up simplification pass.
    #[must_use]
    pub fn simplify_once(
        &self,
        expr: &BoolExpr,
    ) -> (BoolExpr, Vec<(&'static str, BoolExpr, BoolExpr)>) {
        let mut fired: Vec<(&'static str, BoolExpr, BoolExpr)> = Vec::new();
        let result = self.simplify_node(expr, &mut fired);
        (result, fired)
    }

    fn simplify_node(
        &self,
        expr: &BoolExpr,
        fired: &mut Vec<(&'static str, BoolExpr, BoolExpr)>,
    ) -> BoolExpr {
        let rebuilt = self.rebuild_children(expr, fired);
        self.apply_laws(&rebuilt, fired)
    }

    fn rebuild_children(
        &self,
        expr: &BoolExpr,
        fired: &mut Vec<(&'static str, BoolExpr, BoolExpr)>,
    ) -> BoolExpr {
        match expr {
            BoolExpr::Var(_) | BoolExpr::True | BoolExpr::False => expr.clone(),
            BoolExpr::Not(e) => BoolExpr::not(self.simplify_node(e, fired)),
            BoolExpr::And(l, r) => BoolExpr::and(
                self.simplify_node(l, fired),
                self.simplify_node(r, fired),
            ),
            BoolExpr::Or(l, r) => BoolExpr::or(
                self.simplify_node(l, fired),
                self.simplify_node(r, fired),
            ),
            BoolExpr::Xor(l, r) => BoolExpr::xor(
                self.simplify_node(l, fired),
                self.simplify_node(r, fired),
            ),
        }
    }

    fn apply_laws(
        &self,
        expr: &BoolExpr,
        fired: &mut Vec<(&'static str, BoolExpr, BoolExpr)>,
    ) -> BoolExpr {
        macro_rules! fire {
            ($law:expr, $result:expr) => {{
                let result = $result;
                if self.config.trace {
                    fired.push(($law, expr.clone(), result.clone()));
                }
                return result;
            }};
        }

        match expr {
            // Double negation: ~~x → x
            BoolExpr::Not(inner) => {
                if let BoolExpr::Not(inner2) = inner.as_ref() {
                    fire!("double-negation", *inner2.clone());
                }
                // De Morgan: ~(x & y) → ~x | ~y
                if self.config.apply_de_morgan {
                    if let BoolExpr::And(l, r) = inner.as_ref() {
                        fire!("de-morgan-and", BoolExpr::or(BoolExpr::not(*l.clone()), BoolExpr::not(*r.clone())));
                    }
                    if let BoolExpr::Or(l, r) = inner.as_ref() {
                        fire!("de-morgan-or", BoolExpr::and(BoolExpr::not(*l.clone()), BoolExpr::not(*r.clone())));
                    }
                }
                expr.clone()
            }

            BoolExpr::And(l, r) => {
                // Idempotency: x & x → x
                if l == r { fire!("idempotency-and", *l.clone()); }
                // Complement: x & ~x → 0
                if is_complement(l, r) || is_complement(r, l) { fire!("complement-and", BoolExpr::False); }
                // Identity: x & 1 → x, 1 & x → x
                if **r == BoolExpr::True { fire!("identity-and-r", *l.clone()); }
                if **l == BoolExpr::True { fire!("identity-and-l", *r.clone()); }
                // Annihilator: x & 0 → 0
                if **l == BoolExpr::False || **r == BoolExpr::False { fire!("annihilator-and", BoolExpr::False); }
                // Absorption: x & (x | y) → x
                if self.config.apply_absorption
                    && (absorption_and(l, r) || absorption_and(r, l)) {
                        let base = if absorption_and(l, r) { *l.clone() } else { *r.clone() };
                        fire!("absorption-and", base);
                    }
                expr.clone()
            }

            BoolExpr::Or(l, r) => {
                // Idempotency: x | x → x
                if l == r { fire!("idempotency-or", *l.clone()); }
                // Complement: x | ~x → 1
                if is_complement(l, r) || is_complement(r, l) { fire!("complement-or", BoolExpr::True); }
                // Identity: x | 0 → x
                if **r == BoolExpr::False { fire!("identity-or-r", *l.clone()); }
                if **l == BoolExpr::False { fire!("identity-or-l", *r.clone()); }
                // Annihilator: x | 1 → 1
                if **l == BoolExpr::True || **r == BoolExpr::True { fire!("annihilator-or", BoolExpr::True); }
                // Absorption: x | (x & y) → x
                if self.config.apply_absorption
                    && (absorption_or(l, r) || absorption_or(r, l)) {
                        let base = if absorption_or(l, r) { *l.clone() } else { *r.clone() };
                        fire!("absorption-or", base);
                    }
                expr.clone()
            }

            BoolExpr::Xor(l, r) => {
                // x ^ x → 0
                if l == r { fire!("xor-self", BoolExpr::False); }
                // x ^ 0 → x
                if **r == BoolExpr::False { fire!("xor-identity-r", *l.clone()); }
                if **l == BoolExpr::False { fire!("xor-identity-l", *r.clone()); }
                // x ^ 1 → ~x
                if **r == BoolExpr::True { fire!("xor-not-r", BoolExpr::not(*l.clone())); }
                if **l == BoolExpr::True { fire!("xor-not-l", BoolExpr::not(*r.clone())); }
                expr.clone()
            }

            _ => expr.clone(),
        }
    }
}

impl Default for BooleanAlgebraSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper predicates
// ---------------------------------------------------------------------------

fn is_complement(a: &BoolExpr, b: &BoolExpr) -> bool {
    match b {
        BoolExpr::Not(inner) => inner.as_ref() == a,
        _ => false,
    }
}

fn absorption_and(x: &BoolExpr, y: &BoolExpr) -> bool {
    // x & (x | y) → x: check if y is (x | something)
    if let BoolExpr::Or(ol, or_r) = y {
        return ol.as_ref() == x || or_r.as_ref() == x;
    }
    false
}

fn absorption_or(x: &BoolExpr, y: &BoolExpr) -> bool {
    // x | (x & y) → x: check if y is (x & something)
    if let BoolExpr::And(al, ar) = y {
        return al.as_ref() == x || ar.as_ref() == x;
    }
    false
}

// ---------------------------------------------------------------------------
// Normal form conversion
// ---------------------------------------------------------------------------

/// Convert a `BoolExpr` to the requested [`NormalForm`].
#[must_use]
pub fn convert_to_normal_form(expr: BoolExpr, form: NormalForm) -> BoolExpr {
    match form {
        NormalForm::Nnf => to_nnf(expr),
        NormalForm::Dnf => to_dnf(expr),
        NormalForm::Cnf => to_cnf(expr),
    }
}

/// Push all NOT operators to the leaves (Negation Normal Form).
#[must_use]
pub fn to_nnf(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::Var(_) | BoolExpr::True | BoolExpr::False => expr,
        BoolExpr::Not(inner) => push_not_inward(*inner),
        BoolExpr::And(l, r) => BoolExpr::and(to_nnf(*l), to_nnf(*r)),
        BoolExpr::Or(l, r) => BoolExpr::or(to_nnf(*l), to_nnf(*r)),
        // XOR has no standard NNF; expand as (l & ~r) | (~l & r)
        BoolExpr::Xor(l, r) => {
            let l = to_nnf(*l);
            let r = to_nnf(*r);
            BoolExpr::or(
                BoolExpr::and(l.clone(), BoolExpr::not(r.clone())),
                BoolExpr::and(BoolExpr::not(l), r),
            )
        }
    }
}

fn push_not_inward(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::Not(inner) => to_nnf(*inner), // double negation
        BoolExpr::And(l, r) => BoolExpr::or(push_not_inward(*l), push_not_inward(*r)), // De Morgan
        BoolExpr::Or(l, r) => BoolExpr::and(push_not_inward(*l), push_not_inward(*r)),  // De Morgan
        BoolExpr::True => BoolExpr::False,
        BoolExpr::False => BoolExpr::True,
        leaf @ BoolExpr::Var(_) => BoolExpr::not(leaf),
        BoolExpr::Xor(l, r) => {
            // ~(l ^ r) = (l & r) | (~l & ~r)
            let l = to_nnf(*l);
            let r = to_nnf(*r);
            BoolExpr::or(
                BoolExpr::and(l.clone(), r.clone()),
                BoolExpr::and(BoolExpr::not(l), BoolExpr::not(r)),
            )
        }
    }
}

/// Convert to Disjunctive Normal Form (OR of AND clauses).
///
/// First converts to NNF, then distributes AND over OR.
#[must_use]
pub fn to_dnf(expr: BoolExpr) -> BoolExpr {
    let nnf = to_nnf(expr);
    distribute_and_over_or(nnf)
}

fn distribute_and_over_or(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::And(l, r) => {
            let l = distribute_and_over_or(*l);
            let r = distribute_and_over_or(*r);
            // Distribute: (a | b) & c → (a & c) | (b & c)
            if let BoolExpr::Or(la, lb) = l.clone() {
                return BoolExpr::or(
                    distribute_and_over_or(BoolExpr::and(*la, r.clone())),
                    distribute_and_over_or(BoolExpr::and(*lb, r)),
                );
            }
            if let BoolExpr::Or(ra, rb) = r.clone() {
                return BoolExpr::or(
                    distribute_and_over_or(BoolExpr::and(l.clone(), *ra)),
                    distribute_and_over_or(BoolExpr::and(l, *rb)),
                );
            }
            BoolExpr::and(l, r)
        }
        BoolExpr::Or(l, r) => BoolExpr::or(
            distribute_and_over_or(*l),
            distribute_and_over_or(*r),
        ),
        other => other,
    }
}

/// Convert to Conjunctive Normal Form (AND of OR clauses).
///
/// First converts to NNF, then distributes OR over AND.
#[must_use]
pub fn to_cnf(expr: BoolExpr) -> BoolExpr {
    let nnf = to_nnf(expr);
    distribute_or_over_and(nnf)
}

fn distribute_or_over_and(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::Or(l, r) => {
            let l = distribute_or_over_and(*l);
            let r = distribute_or_over_and(*r);
            // Distribute: (a & b) | c → (a | c) & (b | c)
            if let BoolExpr::And(la, lb) = l.clone() {
                return BoolExpr::and(
                    distribute_or_over_and(BoolExpr::or(*la, r.clone())),
                    distribute_or_over_and(BoolExpr::or(*lb, r)),
                );
            }
            if let BoolExpr::And(ra, rb) = r.clone() {
                return BoolExpr::and(
                    distribute_or_over_and(BoolExpr::or(l.clone(), *ra)),
                    distribute_or_over_and(BoolExpr::or(l, *rb)),
                );
            }
            BoolExpr::or(l, r)
        }
        BoolExpr::And(l, r) => BoolExpr::and(
            distribute_or_over_and(*l),
            distribute_or_over_and(*r),
        ),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Equivalence checker
// ---------------------------------------------------------------------------

/// Check whether two `BoolExpr`s are semantically equivalent by exhaustive
/// truth-table evaluation over all variable combinations.
/// Result of a boolean-expression equivalence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoolEquivResult {
    /// The expressions are equivalent over all enumerated assignments.
    Equivalent,
    /// The expressions differ for at least one assignment.
    NotEquivalent,
    /// The variable count exceeds the enumeration limit (> 20); result is
    /// inconclusive.  Callers should treat this as "unknown" rather than
    /// "equivalent".
    Inconclusive { variable_count: usize },
}

/// Check whether two boolean expressions are semantically equivalent by
/// exhaustive truth-table enumeration.
///
/// Returns [`BoolEquivResult::Inconclusive`] when the combined variable count
/// exceeds 20, avoiding the silent false-"equivalent" result that would occur
/// if extra variables were simply omitted from assignments.
#[must_use] 
pub fn bool_exprs_equivalent(a: &BoolExpr, b: &BoolExpr) -> BoolEquivResult {
    let mut all_vars: Vec<String> = a.vars();
    for v in b.vars() {
        if !all_vars.contains(&v) {
            all_vars.push(v);
        }
    }
    let n = all_vars.len();
    if n > 20 {
        return BoolEquivResult::Inconclusive { variable_count: n };
    }
    // Enumerate all 2^n assignments
    for mask in 0..(1u32 << n) {
        let mut assignment = HashMap::new();
        for (i, var) in all_vars.iter().enumerate() {
            assignment.insert(var.clone(), (mask >> i) & 1 == 1);
        }
        let va = a.eval(&assignment);
        let vb = b.eval(&assignment);
        if va != vb {
            return BoolEquivResult::NotEquivalent;
        }
    }
    BoolEquivResult::Equivalent
}

/// Convenience wrapper that returns `true` only when equivalence is confirmed.
/// Returns `false` for both `NotEquivalent` and `Inconclusive` results.
#[must_use]
pub fn bool_exprs_equivalent_strict(a: &BoolExpr, b: &BoolExpr) -> bool {
    bool_exprs_equivalent(a, b) == BoolEquivResult::Equivalent
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> BoolExpr { BoolExpr::var(s) }

    #[test]
    fn idempotency_and() {
        let expr = BoolExpr::and(v("x"), v("x"));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, v("x"));
    }

    #[test]
    fn complement_and_to_false() {
        let expr = BoolExpr::and(v("x"), BoolExpr::not(v("x")));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, BoolExpr::False);
    }

    #[test]
    fn complement_or_to_true() {
        let expr = BoolExpr::or(v("x"), BoolExpr::not(v("x")));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, BoolExpr::True);
    }

    #[test]
    fn double_negation_removed() {
        let expr = BoolExpr::not(BoolExpr::not(v("x")));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, v("x"));
    }

    #[test]
    fn de_morgan_and() {
        let expr = BoolExpr::not(BoolExpr::and(v("x"), v("y")));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        // ~(x & y) → ~x | ~y
        assert_eq!(s.simplified, BoolExpr::or(BoolExpr::not(v("x")), BoolExpr::not(v("y"))));
    }

    #[test]
    fn xor_self_to_false() {
        let expr = BoolExpr::xor(v("x"), v("x"));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, BoolExpr::False);
    }

    #[test]
    fn to_nnf_pushes_not_inside() {
        let expr = BoolExpr::not(BoolExpr::and(v("x"), v("y")));
        let nnf = to_nnf(expr);
        // Should be ~x | ~y
        assert_eq!(nnf, BoolExpr::or(BoolExpr::not(v("x")), BoolExpr::not(v("y"))));
    }

    #[test]
    fn bool_exprs_equivalent_self() {
        let e = BoolExpr::and(v("x"), v("y"));
        assert_eq!(bool_exprs_equivalent(&e, &e), BoolEquivResult::Equivalent);
    }

    #[test]
    fn bool_exprs_not_equivalent_different() {
        let a = BoolExpr::and(v("x"), v("y"));
        let b = BoolExpr::or(v("x"), v("y"));
        assert_eq!(bool_exprs_equivalent(&a, &b), BoolEquivResult::NotEquivalent);
    }

    #[test]
    fn absorption_and_simplifies() {
        // x & (x | y) → x
        let expr = BoolExpr::and(v("x"), BoolExpr::or(v("x"), v("y")));
        let s = BooleanAlgebraSimplifier::new().simplify(expr);
        assert_eq!(s.simplified, v("x"));
    }
}
