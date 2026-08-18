//! `predicate_detector.rs` — Opaque predicate detection engine.
//!
//! Detects opaque predicates: patterns like `x*x >= 0`, `(x&1) == (x&1)`,
//! `a*(a-1) % 2 == 0`, `y == y`, constant XOR patterns, always-true/always-false
//! conditions. Scores confidence using SMT-like reasoning.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// BoolValue
// ─────────────────────────────────────────────────────────────────────────────

/// The determined boolean outcome of a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoolValue {
    /// Predicate is always true regardless of variable values.
    AlwaysTrue,
    /// Predicate is always false regardless of variable values.
    AlwaysFalse,
    /// Predicate depends on runtime variable values.
    Unknown,
}

impl fmt::Display for BoolValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysTrue => write!(f, "AlwaysTrue"),
            Self::AlwaysFalse => write!(f, "AlwaysFalse"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PredicateKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of why/how the predicate is opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateKind {
    /// Trivial identity: `x == x`, `x <= x`, etc.
    TrivialIdentity,
    /// Mathematical invariant: `x*x >= 0`, `x*(x-1) % 2 == 0`, etc.
    MathInvariant,
    /// Constant-folded expression with no live variables.
    ConstantFold,
    /// XOR self-cancellation: `x ^ x == 0`.
    XorSelf,
    /// Bitwise identity: `x & x == x`, `x | x == x`.
    BitwiseIdempotency,
    /// Consecutive integer product is always even.
    ConsecutiveProduct,
    /// Square is always non-negative.
    SquareNonNeg,
    /// Population count is always non-negative.
    PopcountNonNeg,
    /// Absolute value is always non-negative.
    AbsNonNeg,
    /// Two's complement negation identity.
    TwosComplementNeg,
    /// OR with 1 produces always-odd value.
    OrOneOdd,
    /// Unknown/unclassified opaque predicate pattern.
    Other,
}

impl fmt::Display for PredicateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TrivialIdentity => "TrivialIdentity",
            Self::MathInvariant => "MathInvariant",
            Self::ConstantFold => "ConstantFold",
            Self::XorSelf => "XorSelf",
            Self::BitwiseIdempotency => "BitwiseIdempotency",
            Self::ConsecutiveProduct => "ConsecutiveProduct",
            Self::SquareNonNeg => "SquareNonNeg",
            Self::PopcountNonNeg => "PopcountNonNeg",
            Self::AbsNonNeg => "AbsNonNeg",
            Self::TwosComplementNeg => "TwosComplementNeg",
            Self::OrOneOdd => "OrOneOdd",
            Self::Other => "Other",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PredicatePattern
// ─────────────────────────────────────────────────────────────────────────────

/// A named detection pattern: combines a matcher function with metadata.
pub struct PredicatePattern {
    /// Short identifier for the pattern.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// The expected boolean outcome when the pattern matches.
    pub outcome: BoolValue,
    /// Semantic classification of the pattern.
    pub kind: PredicateKind,
    /// Detection function. Receives the expression AST and returns the outcome
    /// if the pattern matches, or `None` otherwise.
    pub matcher: fn(&PredicateExpr) -> Option<BoolValue>,
}

impl fmt::Debug for PredicatePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PredicatePattern({:?})", self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PredicateExpr — expression AST for predicate analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic expression tree used by the detector.
/// All arithmetic uses wrapping `i64` semantics.
#[derive(Debug, Clone, PartialEq)]
pub enum PredicateExpr {
    /// Integer constant.
    Const(i64),
    /// Symbolic variable (by name).
    Var(String),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Neg(Box<Self>),
    Shl(Box<Self>, u8),
    Shr(Box<Self>, u8),
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    /// `popcnt(x)`
    BitCount(Box<Self>),
    /// `abs(x)`
    Abs(Box<Self>),
    /// `x * x`
    Square(Box<Self>),
}

impl PredicateExpr {
    fn bx(e: Self) -> Box<Self> { Box::new(e) }

    /// Collect all variable names (sorted, deduped).
    #[must_use]
    pub fn variables(&self) -> Vec<String> {
        let mut v = Vec::new();
        self.collect_vars(&mut v);
        v.sort_unstable();
        v.dedup();
        v
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Const(_) => {}
            Self::Var(n) => out.push(n.clone()),
            Self::Add(a, b) | Self::Sub(a, b) | Self::Mul(a, b) | Self::Div(a, b)
            | Self::Mod(a, b) | Self::And(a, b) | Self::Or(a, b) | Self::Xor(a, b)
            | Self::Eq(a, b) | Self::Ne(a, b) | Self::Lt(a, b) | Self::Le(a, b)
            | Self::Gt(a, b) | Self::Ge(a, b) => {
                a.collect_vars(out);
                b.collect_vars(out);
            }
            Self::Not(a) | Self::Neg(a) | Self::BitCount(a)
            | Self::Abs(a) | Self::Square(a) => a.collect_vars(out),
            Self::Shl(a, _) | Self::Shr(a, _) => a.collect_vars(out),
        }
    }

    /// Evaluate with variable bindings.
    #[must_use]
    pub fn eval(&self, vars: &HashMap<String, i64>) -> Option<i64> {
        match self {
            Self::Const(c) => Some(*c),
            Self::Var(n) => vars.get(n).copied(),
            Self::Add(a, b) => Some(a.eval(vars)?.wrapping_add(b.eval(vars)?)),
            Self::Sub(a, b) => Some(a.eval(vars)?.wrapping_sub(b.eval(vars)?)),
            Self::Mul(a, b) => Some(a.eval(vars)?.wrapping_mul(b.eval(vars)?)),
            Self::Div(a, b) => {
                let d = b.eval(vars)?;
                if d == 0 { return None; }
                Some(a.eval(vars)?.wrapping_div(d))
            }
            Self::Mod(a, b) => {
                let d = b.eval(vars)?;
                if d == 0 { return None; }
                Some(a.eval(vars)?.wrapping_rem(d))
            }
            Self::And(a, b) => Some(a.eval(vars)? & b.eval(vars)?),
            Self::Or(a, b)  => Some(a.eval(vars)? | b.eval(vars)?),
            Self::Xor(a, b) => Some(a.eval(vars)? ^ b.eval(vars)?),
            Self::Not(a)    => Some(!a.eval(vars)?),
            Self::Neg(a)    => Some(a.eval(vars)?.wrapping_neg()),
            Self::Shl(a, n) => {
                if *n >= 64 { return None; }
                Some(a.eval(vars)?.wrapping_shl(u32::from(*n)))
            }
            Self::Shr(a, n) => {
                if *n >= 64 { return None; }
                Some(a.eval(vars)?.wrapping_shr(u32::from(*n)))
            }
            Self::Eq(a, b)  => Some(i64::from(a.eval(vars)? == b.eval(vars)?)),
            Self::Ne(a, b)  => Some(i64::from(a.eval(vars)? != b.eval(vars)?)),
            Self::Lt(a, b)  => Some(i64::from(a.eval(vars)? < b.eval(vars)?)),
            Self::Le(a, b)  => Some(i64::from(a.eval(vars)? <= b.eval(vars)?)),
            Self::Gt(a, b)  => Some(i64::from(a.eval(vars)? > b.eval(vars)?)),
            Self::Ge(a, b)  => Some(i64::from(a.eval(vars)? >= b.eval(vars)?)),
            Self::BitCount(a) => Some(i64::from(a.eval(vars)?.count_ones())),
            Self::Abs(a)    => a.eval(vars)?.checked_abs(),
            Self::Square(a) => {
                let v = a.eval(vars)?;
                Some(v.wrapping_mul(v))
            }
        }
    }

    /// Structural equality check.
    #[must_use]
    pub fn structurally_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Const(a), Self::Const(b)) => a == b,
            (Self::Var(a), Self::Var(b)) => a == b,
            (Self::Add(a1,b1), Self::Add(a2,b2))
            | (Self::Sub(a1,b1), Self::Sub(a2,b2))
            | (Self::Mul(a1,b1), Self::Mul(a2,b2))
            | (Self::Div(a1,b1), Self::Div(a2,b2))
            | (Self::Mod(a1,b1), Self::Mod(a2,b2))
            | (Self::And(a1,b1), Self::And(a2,b2))
            | (Self::Or(a1,b1),  Self::Or(a2,b2))
            | (Self::Xor(a1,b1), Self::Xor(a2,b2))
            | (Self::Eq(a1,b1),  Self::Eq(a2,b2))
            | (Self::Ne(a1,b1),  Self::Ne(a2,b2))
            | (Self::Lt(a1,b1),  Self::Lt(a2,b2))
            | (Self::Le(a1,b1),  Self::Le(a2,b2))
            | (Self::Gt(a1,b1),  Self::Gt(a2,b2))
            | (Self::Ge(a1,b1),  Self::Ge(a2,b2))
                => a1.structurally_equal(a2) && b1.structurally_equal(b2),
            (Self::Not(a), Self::Not(b))
            | (Self::Neg(a), Self::Neg(b))
            | (Self::BitCount(a), Self::BitCount(b))
            | (Self::Abs(a), Self::Abs(b))
            | (Self::Square(a), Self::Square(b))
                => a.structurally_equal(b),
            (Self::Shl(a,n1), Self::Shl(b,n2))
            | (Self::Shr(a,n1), Self::Shr(b,n2))
                => n1 == n2 && a.structurally_equal(b),
            _ => false,
        }
    }

    /// Return Some(c) if the expression is constant (no variables).
    #[must_use]
    pub fn as_const(&self) -> Option<i64> {
        if self.variables().is_empty() {
            self.eval(&HashMap::new())
        } else {
            None
        }
    }

    /// Light constant-folding simplification pass.
    #[must_use]
    pub fn simplify(&self) -> Self {
        match self {
            Self::Const(_) | Self::Var(_) => self.clone(),
            Self::Neg(a) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(c.wrapping_neg()); }
                Self::Neg(Self::bx(a))
            }
            Self::Not(a) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(!c); }
                Self::Not(Self::bx(a))
            }
            Self::Abs(a) => {
                let a = a.simplify();
                // Use checked_abs to preserve the same semantics as eval(),
                // which also uses checked_abs. For i64::MIN, checked_abs
                // returns None so we leave the node unsimplified.
                if let Some(c) = a.as_const() {
                    if let Some(abs_val) = c.checked_abs() {
                        return Self::Const(abs_val);
                    }
                }
                Self::Abs(Self::bx(a))
            }
            Self::Square(a) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(c.wrapping_mul(c)); }
                Self::Square(Self::bx(a))
            }
            Self::BitCount(a) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(i64::from(c.count_ones())); }
                Self::BitCount(Self::bx(a))
            }
            Self::Sub(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(ca.wrapping_sub(cb));
                }
                if a.structurally_equal(&b) { return Self::Const(0); }
                Self::Sub(Self::bx(a), Self::bx(b))
            }
            Self::Xor(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(ca ^ cb);
                }
                if a.structurally_equal(&b) { return Self::Const(0); }
                Self::Xor(Self::bx(a), Self::bx(b))
            }
            Self::Add(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(ca.wrapping_add(cb));
                }
                Self::Add(Self::bx(a), Self::bx(b))
            }
            Self::Mul(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (a.as_const(), b.as_const()) {
                    (Some(ca), Some(cb)) => Self::Const(ca.wrapping_mul(cb)),
                    (Some(0), _) | (_, Some(0)) => Self::Const(0),
                    _ => Self::Mul(Self::bx(a), Self::bx(b)),
                }
            }
            Self::Eq(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca == cb));
                }
                if a.structurally_equal(&b) { return Self::Const(1); }
                Self::Eq(Self::bx(a), Self::bx(b))
            }
            Self::Ne(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca != cb));
                }
                if a.structurally_equal(&b) { return Self::Const(0); }
                Self::Ne(Self::bx(a), Self::bx(b))
            }
            Self::Lt(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca < cb));
                }
                if a.structurally_equal(&b) { return Self::Const(0); }
                Self::Lt(Self::bx(a), Self::bx(b))
            }
            Self::Le(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca <= cb));
                }
                if a.structurally_equal(&b) { return Self::Const(1); }
                Self::Le(Self::bx(a), Self::bx(b))
            }
            Self::Gt(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca > cb));
                }
                if a.structurally_equal(&b) { return Self::Const(0); }
                Self::Gt(Self::bx(a), Self::bx(b))
            }
            Self::Ge(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(i64::from(ca >= cb));
                }
                if a.structurally_equal(&b) { return Self::Const(1); }
                Self::Ge(Self::bx(a), Self::bx(b))
            }
            Self::And(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(ca & cb);
                }
                Self::And(Self::bx(a), Self::bx(b))
            }
            Self::Or(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    return Self::Const(ca | cb);
                }
                Self::Or(Self::bx(a), Self::bx(b))
            }
            Self::Mod(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    if cb != 0 { return Self::Const(ca.wrapping_rem(cb)); }
                }
                Self::Mod(Self::bx(a), Self::bx(b))
            }
            Self::Div(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const()) {
                    if cb != 0 { return Self::Const(ca.wrapping_div(cb)); }
                }
                Self::Div(Self::bx(a), Self::bx(b))
            }
            Self::Shl(a, n) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(c.wrapping_shl(u32::from(*n))); }
                Self::Shl(Self::bx(a), *n)
            }
            Self::Shr(a, n) => {
                let a = a.simplify();
                if let Some(c) = a.as_const() { return Self::Const(c.wrapping_shr(u32::from(*n))); }
                Self::Shr(Self::bx(a), *n)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicate — a detected opaque predicate instance
// ─────────────────────────────────────────────────────────────────────────────

/// A detected opaque predicate at a specific location.
#[derive(Debug, Clone)]
pub struct OpaquePredicate {
    /// Address of the conditional branch instruction.
    pub address: u64,
    /// The symbolic condition expression.
    pub expr: PredicateExpr,
    /// Determined outcome.
    pub outcome: BoolValue,
    /// Classification of the opaque predicate type.
    pub kind: PredicateKind,
    /// Confidence score 0.0–1.0.
    pub confidence: f64,
    /// Name of the pattern that matched (if any).
    pub pattern_name: Option<String>,
}

impl fmt::Display for OpaquePredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OpaquePredicate@{:#x} outcome={} kind={} conf={:.2}",
            self.address, self.outcome, self.kind, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running the detector over a set of branch expressions.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// All detected opaque predicates.
    pub predicates: Vec<OpaquePredicate>,
    /// Number of branches that could not be classified.
    pub unknown_count: usize,
    /// Number of branches examined.
    pub total_examined: usize,
}

impl DetectionResult {
    /// Create an empty result.
    #[must_use]
    pub const fn new() -> Self {
        Self { predicates: Vec::new(), unknown_count: 0, total_examined: 0 }
    }

    /// Number of always-true opaque predicates found.
    #[must_use]
    pub fn always_true_count(&self) -> usize {
        self.predicates.iter().filter(|p| p.outcome == BoolValue::AlwaysTrue).count()
    }

    /// Number of always-false opaque predicates found.
    #[must_use]
    pub fn always_false_count(&self) -> usize {
        self.predicates.iter().filter(|p| p.outcome == BoolValue::AlwaysFalse).count()
    }

    /// Filter predicates by minimum confidence.
    #[must_use]
    pub fn with_min_confidence(&self, min: f64) -> Vec<&OpaquePredicate> {
        self.predicates.iter().filter(|p| p.confidence >= min).collect()
    }
}

impl Default for DetectionResult {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern-matching helpers
// ─────────────────────────────────────────────────────────────────────────────

fn is_xor_self(e: &PredicateExpr) -> bool {
    matches!(e, PredicateExpr::Xor(a, b) if a.structurally_equal(b))
}

fn is_sub_self(e: &PredicateExpr) -> bool {
    matches!(e, PredicateExpr::Sub(a, b) if a.structurally_equal(b))
}

fn is_square_expr(e: &PredicateExpr, var: &PredicateExpr) -> bool {
    match e {
        PredicateExpr::Square(inner) => inner.structurally_equal(var),
        PredicateExpr::Mul(a, b) => a.structurally_equal(b) && a.structurally_equal(var),
        _ => false,
    }
}

fn is_x_times_x_minus_1(e: &PredicateExpr) -> bool {
    if let PredicateExpr::Mul(a, b) = e {
        if let PredicateExpr::Sub(inner_a, inner_b) = b.as_ref() {
            if a.structurally_equal(inner_a) && matches!(inner_b.as_ref(), PredicateExpr::Const(1)) {
                return true;
            }
        }
        if let PredicateExpr::Sub(inner_a, inner_b) = a.as_ref() {
            if b.structurally_equal(inner_a) && matches!(inner_b.as_ref(), PredicateExpr::Const(1)) {
                return true;
            }
        }
    }
    false
}

fn is_x_times_x_plus_1(e: &PredicateExpr) -> bool {
    if let PredicateExpr::Mul(a, b) = e {
        if let PredicateExpr::Add(inner_a, inner_b) = b.as_ref() {
            if a.structurally_equal(inner_a) && matches!(inner_b.as_ref(), PredicateExpr::Const(1)) {
                return true;
            }
        }
        if let PredicateExpr::Add(inner_a, inner_b) = a.as_ref() {
            if b.structurally_equal(inner_a) && matches!(inner_b.as_ref(), PredicateExpr::Const(1)) {
                return true;
            }
        }
    }
    false
}

fn is_x_sq_plus_x(e: &PredicateExpr) -> bool {
    if let PredicateExpr::Add(a, b) = e {
        return is_square_expr(a, b) || is_square_expr(b, a);
    }
    false
}

fn is_or_one(e: &PredicateExpr) -> bool {
    if let PredicateExpr::Or(a, b) = e {
        if matches!(a.as_ref(), PredicateExpr::Const(1)) || matches!(b.as_ref(), PredicateExpr::Const(1)) {
            return true;
        }
    }
    false
}

/// Build the built-in pattern library.
#[must_use]
pub fn build_patterns() -> Vec<PredicatePattern> {
    vec![
        PredicatePattern {
            name: "eq_self",
            description: "x == x is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Eq(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysTrue)
                } else { None }
            },
        },
        PredicatePattern {
            name: "ne_self",
            description: "x != x is always false",
            outcome: BoolValue::AlwaysFalse,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Ne(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysFalse)
                } else { None }
            },
        },
        PredicatePattern {
            name: "le_self",
            description: "x <= x is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Le(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysTrue)
                } else { None }
            },
        },
        PredicatePattern {
            name: "ge_self",
            description: "x >= x is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Ge(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysTrue)
                } else { None }
            },
        },
        PredicatePattern {
            name: "lt_self",
            description: "x < x is always false",
            outcome: BoolValue::AlwaysFalse,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Lt(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysFalse)
                } else { None }
            },
        },
        PredicatePattern {
            name: "gt_self",
            description: "x > x is always false",
            outcome: BoolValue::AlwaysFalse,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if matches!(e, PredicateExpr::Gt(a, b) if a.structurally_equal(b)) {
                    Some(BoolValue::AlwaysFalse)
                } else { None }
            },
        },
        PredicatePattern {
            name: "xor_self_false",
            description: "x ^ x is always 0 (false)",
            outcome: BoolValue::AlwaysFalse,
            kind: PredicateKind::XorSelf,
            matcher: |e| {
                if is_xor_self(e) { Some(BoolValue::AlwaysFalse) } else { None }
            },
        },
        PredicatePattern {
            name: "xor_self_eq_zero",
            description: "(x ^ x) == 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::XorSelf,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if is_xor_self(lhs) && matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        return Some(BoolValue::AlwaysTrue);
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "sub_self_eq_zero",
            description: "(x - x) == 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::TrivialIdentity,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if is_sub_self(lhs) && matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        return Some(BoolValue::AlwaysTrue);
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "square_ge_zero",
            description: "x*x >= 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::SquareNonNeg,
            matcher: |e| {
                if let PredicateExpr::Ge(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        if matches!(lhs.as_ref(), PredicateExpr::Square(_)) {
                            return Some(BoolValue::AlwaysTrue);
                        }
                        if let PredicateExpr::Mul(a, b) = lhs.as_ref() {
                            if a.structurally_equal(b) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "consec_prod_even",
            description: "x*(x-1) % 2 == 0: product of consecutive integers is always even",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::ConsecutiveProduct,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        if let PredicateExpr::Mod(inner, div) = lhs.as_ref() {
                            if matches!(div.as_ref(), PredicateExpr::Const(2)) && is_x_times_x_minus_1(inner) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "consec_succ_even",
            description: "x*(x+1) % 2 == 0: product of consecutive integers is always even",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::ConsecutiveProduct,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        if let PredicateExpr::Mod(inner, div) = lhs.as_ref() {
                            if matches!(div.as_ref(), PredicateExpr::Const(2)) && is_x_times_x_plus_1(inner) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "x_sq_plus_x_even",
            description: "(x^2 + x) % 2 == 0: always even (consecutive product)",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::ConsecutiveProduct,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        if let PredicateExpr::Mod(inner, div) = lhs.as_ref() {
                            if matches!(div.as_ref(), PredicateExpr::Const(2)) && is_x_sq_plus_x(inner) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "popcount_ge_zero",
            description: "popcount(x) >= 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::PopcountNonNeg,
            matcher: |e| {
                if let PredicateExpr::Ge(lhs, rhs) = e {
                    if matches!(lhs.as_ref(), PredicateExpr::BitCount(_))
                        && matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        return Some(BoolValue::AlwaysTrue);
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "abs_ge_zero",
            description: "abs(x) >= 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::AbsNonNeg,
            matcher: |e| {
                if let PredicateExpr::Ge(lhs, rhs) = e {
                    if matches!(lhs.as_ref(), PredicateExpr::Abs(_))
                        && matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        return Some(BoolValue::AlwaysTrue);
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "x_or_notx_eq_minus1",
            description: "x | ~x == -1 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::MathInvariant,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(-1)) {
                        if let PredicateExpr::Or(a, b) = lhs.as_ref() {
                            let check = |x: &PredicateExpr, y: &PredicateExpr| {
                                if let PredicateExpr::Not(inner) = y {
                                    return x.structurally_equal(inner);
                                }
                                false
                            };
                            if check(a, b) || check(b, a) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "x_and_notx_eq_zero",
            description: "x & ~x == 0 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::MathInvariant,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(0)) {
                        if let PredicateExpr::And(a, b) = lhs.as_ref() {
                            let check = |x: &PredicateExpr, y: &PredicateExpr| {
                                if let PredicateExpr::Not(inner) = y {
                                    return x.structurally_equal(inner);
                                }
                                false
                            };
                            if check(a, b) || check(b, a) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "or_one_always_odd",
            description: "(x | 1) & 1 == 1 is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::OrOneOdd,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if matches!(rhs.as_ref(), PredicateExpr::Const(1)) {
                        if let PredicateExpr::And(a, b) = lhs.as_ref() {
                            let check = |x: &PredicateExpr, c: &PredicateExpr| {
                                matches!(c, PredicateExpr::Const(1)) && is_or_one(x)
                            };
                            if check(a, b) || check(b, a) {
                                return Some(BoolValue::AlwaysTrue);
                            }
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "twos_comp_zero",
            description: "x + (~x + 1) == 0 is always true (two's complement)",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::TwosComplementNeg,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if !matches!(rhs.as_ref(), PredicateExpr::Const(0)) { return None; }
                    if let PredicateExpr::Add(a, b) = lhs.as_ref() {
                        let check_pair = |x: &PredicateExpr, y: &PredicateExpr| {
                            if let PredicateExpr::Add(na, nb) = y {
                                let check_not_plus1 = |n: &PredicateExpr, one: &PredicateExpr| {
                                    matches!(one, PredicateExpr::Const(1))
                                    && if let PredicateExpr::Not(inner) = n {
                                        x.structurally_equal(inner)
                                    } else { false }
                                };
                                return check_not_plus1(na, nb) || check_not_plus1(nb, na);
                            }
                            false
                        };
                        if check_pair(a, b) || check_pair(b, a) {
                            return Some(BoolValue::AlwaysTrue);
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "const_const_eq",
            description: "Comparison of two constants always has a fixed result",
            outcome: BoolValue::Unknown,
            kind: PredicateKind::ConstantFold,
            matcher: |e| {
                let (lhs, rhs) = match e {
                    PredicateExpr::Eq(a, b) | PredicateExpr::Ne(a, b)
                    | PredicateExpr::Lt(a, b) | PredicateExpr::Le(a, b)
                    | PredicateExpr::Gt(a, b) | PredicateExpr::Ge(a, b) => (a, b),
                    _ => return None,
                };
                if lhs.as_const().is_some() && rhs.as_const().is_some() {
                    let val = e.eval(&HashMap::new())?;
                    if val != 0 { Some(BoolValue::AlwaysTrue) } else { Some(BoolValue::AlwaysFalse) }
                } else { None }
            },
        },
        PredicatePattern {
            name: "and_idempotent",
            description: "x & x == x is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::BitwiseIdempotency,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if let PredicateExpr::And(a, b) = lhs.as_ref() {
                        if a.structurally_equal(b) && rhs.structurally_equal(a) {
                            return Some(BoolValue::AlwaysTrue);
                        }
                    }
                }
                None
            },
        },
        PredicatePattern {
            name: "or_idempotent",
            description: "x | x == x is always true",
            outcome: BoolValue::AlwaysTrue,
            kind: PredicateKind::BitwiseIdempotency,
            matcher: |e| {
                if let PredicateExpr::Eq(lhs, rhs) = e {
                    if let PredicateExpr::Or(a, b) = lhs.as_ref() {
                        if a.structurally_equal(b) && rhs.structurally_equal(a) {
                            return Some(BoolValue::AlwaysTrue);
                        }
                    }
                }
                None
            },
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Truth-table sampler
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate a predicate over a sampled domain to determine its truth value.
pub struct TruthSampler {
    /// Number of bits per variable for enumeration (capped at 16).
    pub bits: u32,
    /// Maximum number of samples to check.
    pub max_samples: usize,
}

impl TruthSampler {
    #[must_use]
    pub const fn new() -> Self { Self { bits: 8, max_samples: 1024 } }

    #[must_use]
    pub const fn with_bits(mut self, b: u32) -> Self { self.bits = b; self }
    #[must_use]
    pub const fn with_max_samples(mut self, n: usize) -> Self { self.max_samples = n; self }

    /// Check all variable assignments and return `AlwaysTrue`, `AlwaysFalse`, or `Unknown`.
    #[must_use]
    pub fn classify(&self, expr: &PredicateExpr) -> BoolValue {
        let vars = expr.variables();
        if vars.is_empty() {
            return match expr.eval(&HashMap::new()) {
                Some(0) => BoolValue::AlwaysFalse,
                Some(_) => BoolValue::AlwaysTrue,
                None => BoolValue::Unknown,
            };
        }
        let range = 1u64 << self.bits.min(16);
        let n = vars.len();
        let mut saw_true = false;
        let mut saw_false = false;
        let mut count = 0usize;

        // Enumerate all combinations with an early exit.
        let mut indices = vec![0u64; n];
        loop {
            let mut map = HashMap::with_capacity(n);
            for (i, name) in vars.iter().enumerate() {
                let width = self.bits.min(16);
                let shift = 64 - width;
                let raw = ((indices[i] as i64) << shift) >> shift;
                map.insert(name.clone(), raw);
            }

            match expr.eval(&map) {
                Some(0) => saw_false = true,
                Some(_) => saw_true = true,
                None => {}
            }

            if saw_true && saw_false { return BoolValue::Unknown; }
            count += 1;
            if count >= self.max_samples { break; }

            let mut carry = true;
            for idx in &mut indices {
                if carry {
                    *idx += 1;
                    if *idx >= range { *idx = 0; } else { carry = false; }
                }
            }
            if carry { break; }
        }

        match (saw_true, saw_false) {
            (true, false) => BoolValue::AlwaysTrue,
            (false, true) => BoolValue::AlwaysFalse,
            _ => BoolValue::Unknown,
        }
    }
}

impl Default for TruthSampler {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// PredicateDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Main opaque predicate detection engine.
pub struct PredicateDetector {
    /// Pattern library for fast structural matching.
    pub patterns: Vec<PredicatePattern>,
    /// Truth-table sampler for symbolic verification.
    pub sampler: TruthSampler,
    /// Minimum confidence threshold (0.0–1.0).
    pub min_confidence: f64,
    /// Whether to use pattern matching.
    pub use_patterns: bool,
    /// Whether to use truth-table sampling.
    pub use_sampler: bool,
}

impl PredicateDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: build_patterns(),
            sampler: TruthSampler::new(),
            min_confidence: 0.7,
            use_patterns: true,
            use_sampler: true,
        }
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: f64) -> Self { self.min_confidence = c; self }
    #[must_use]
    pub const fn without_sampler(mut self) -> Self { self.use_sampler = false; self }
    #[must_use]
    pub const fn without_patterns(mut self) -> Self { self.use_patterns = false; self }

    /// Classify a single expression, returning (outcome, kind, confidence, `pattern_name`).
    #[must_use]
    pub fn classify_expr(&self, expr: &PredicateExpr) -> (BoolValue, PredicateKind, f64, Option<String>) {
        // 1. Constant fold first.
        let simplified = expr.simplify();
        if let Some(c) = simplified.as_const() {
            let bv = if c != 0 { BoolValue::AlwaysTrue } else { BoolValue::AlwaysFalse };
            return (bv, PredicateKind::ConstantFold, 1.0, Some("const_fold".to_string()));
        }

        // 2. Pattern matching.
        if self.use_patterns {
            for pat in &self.patterns {
                if let Some(bv) = (pat.matcher)(expr) {
                    return (bv, pat.kind, 0.95, Some(pat.name.to_string()));
                }
                if let Some(bv) = (pat.matcher)(&simplified) {
                    return (bv, pat.kind, 0.93, Some(pat.name.to_string()));
                }
            }
        }

        // 3. Truth-table sampler.
        if self.use_sampler {
            let bv = self.sampler.classify(&simplified);
            if bv != BoolValue::Unknown {
                return (bv, PredicateKind::Other, 0.80, None);
            }
        }

        (BoolValue::Unknown, PredicateKind::Other, 0.0, None)
    }

    /// Detect opaque predicates in a list of (address, condition) pairs.
    #[must_use]
    pub fn detect(&self, branches: &[(u64, PredicateExpr)]) -> DetectionResult {
        let mut result = DetectionResult::new();
        result.total_examined = branches.len();

        for (addr, expr) in branches {
            let (outcome, kind, confidence, pattern_name) = self.classify_expr(expr);
            if outcome == BoolValue::Unknown || confidence < self.min_confidence {
                result.unknown_count += 1;
                continue;
            }
            result.predicates.push(OpaquePredicate {
                address: *addr,
                expr: expr.clone(),
                outcome,
                kind,
                confidence,
                pattern_name,
            });
        }

        result
    }

    /// Detect and return only high-confidence predicates (>= 0.9).
    #[must_use]
    pub fn detect_high_confidence(&self, branches: &[(u64, PredicateExpr)]) -> Vec<OpaquePredicate> {
        self.detect(branches).predicates.into_iter().filter(|p| p.confidence >= 0.9).collect()
    }
}

impl Default for PredicateDetector {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(n: &str) -> PredicateExpr { PredicateExpr::Var(n.to_string()) }
    fn c(n: i64) -> PredicateExpr { PredicateExpr::Const(n) }

    #[test]
    fn test_eq_self_detected() {
        let detector = PredicateDetector::new();
        let expr = PredicateExpr::Eq(Box::new(var("x")), Box::new(var("x")));
        let (bv, _, conf, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysTrue);
        assert!(conf >= 0.9);
    }

    #[test]
    fn test_ne_self_always_false() {
        let detector = PredicateDetector::new();
        let expr = PredicateExpr::Ne(Box::new(var("x")), Box::new(var("x")));
        let (bv, _, _, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysFalse);
    }

    #[test]
    fn test_square_ge_zero() {
        let detector = PredicateDetector::new();
        let sq = PredicateExpr::Square(Box::new(var("x")));
        let expr = PredicateExpr::Ge(Box::new(sq), Box::new(c(0)));
        let (bv, kind, _, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysTrue);
        assert_eq!(kind, PredicateKind::SquareNonNeg);
    }

    #[test]
    fn test_xor_self_false() {
        let detector = PredicateDetector::new();
        let expr = PredicateExpr::Xor(Box::new(var("y")), Box::new(var("y")));
        let (bv, _, _, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysFalse);
    }

    #[test]
    fn test_constant_fold() {
        let detector = PredicateDetector::new();
        let expr = PredicateExpr::Eq(Box::new(c(5)), Box::new(c(5)));
        let (bv, kind, conf, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysTrue);
        assert_eq!(kind, PredicateKind::ConstantFold);
        assert_eq!(conf, 1.0);
    }

    #[test]
    fn test_truth_sampler_classify() {
        let sampler = TruthSampler::new();
        let expr = PredicateExpr::Le(Box::new(var("a")), Box::new(var("a")));
        let bv = sampler.classify(&expr);
        assert_eq!(bv, BoolValue::AlwaysTrue);
    }

    #[test]
    fn test_detect_batch() {
        let detector = PredicateDetector::new();
        let branches = vec![
            (0x1000, PredicateExpr::Eq(Box::new(var("x")), Box::new(var("x")))),
            (0x1010, PredicateExpr::Add(Box::new(var("x")), Box::new(c(1)))),
        ];
        let result = detector.detect(&branches);
        assert_eq!(result.total_examined, 2);
        assert_eq!(result.always_true_count(), 1);
    }

    #[test]
    fn test_consec_product() {
        let detector = PredicateDetector::new();
        // x * (x - 1) % 2 == 0
        let x = var("x");
        let prod = PredicateExpr::Mul(
            Box::new(x.clone()),
            Box::new(PredicateExpr::Sub(Box::new(x), Box::new(c(1)))),
        );
        let modulo = PredicateExpr::Mod(Box::new(prod), Box::new(c(2)));
        let expr = PredicateExpr::Eq(Box::new(modulo), Box::new(c(0)));
        let (bv, kind, _, _) = detector.classify_expr(&expr);
        assert_eq!(bv, BoolValue::AlwaysTrue);
        assert_eq!(kind, PredicateKind::ConsecutiveProduct);
    }
}
