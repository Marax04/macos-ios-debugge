//! `rustre-deobf-opaque`
//!
//! Production-grade opaque predicate detection and elimination pass for the `RustRE` Suite.
//!
//! An **opaque predicate** is a conditional branch whose outcome is always known at compile time
//! (always-taken or never-taken) but appears non-trivial to a static analyser or decompiler.
//! Obfuscators inject them to confuse CFG reconstruction, insert dead code and waste analyst time.
//!
//! This crate provides:
//! * [`OpaqueExpr`] — a symbolic expression tree for predicate analysis
//! * [`TruthTableChecker`] — exhaustive / sampled evaluation across variable domains
//! * [`KnownOpaquePattern`] / [`build_known_patterns`] — a static database of 24+ patterns
//! * [`OpaqueDetector`] — combines pattern matching and truth-table checks
//! * [`OpaqueEliminator`] — rewrites the CFG, removing dead edges
//! * [`OpaqueDeobfPass`] — high-level one-shot pass

pub mod constant_propagator;
pub mod dead_branch_eliminator;
pub mod opaque_cfg_cleaner;
pub mod opaque_rewriter;
pub mod pattern_library;
pub mod polynomial_check;
pub mod predicate_simplifier;
pub mod sat_checker;
pub mod smt_prover;
pub mod predicate_detector;
pub mod tautology_db;
pub mod predicate_evaluator;
pub mod conditional_simplifier;
pub mod junk_code_remover;

use rustre_core::address::Address;
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PredicateValue
// ─────────────────────────────────────────────────────────────────────────────

/// The constant outcome of an opaque predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PredicateValue {
    /// The condition is true for every possible variable assignment.
    AlwaysTrue,
    /// The condition is false for every possible variable assignment.
    AlwaysFalse,
    /// The condition is genuinely data-dependent — not an opaque predicate.
    Unknown,
}

impl fmt::Display for PredicateValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysTrue => write!(f, "AlwaysTrue"),
            Self::AlwaysFalse => write!(f, "AlwaysFalse"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicateKind
// ─────────────────────────────────────────────────────────────────────────────

/// How the predicate was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaquePredicateKind {
    /// `x == x` style — trivial structural identity.
    TrivialIdentity,
    /// Constant expression with no variables.
    ConstantExpr,
    /// Mathematical invariant, e.g. `x*(x-1) % 2 == 0`.
    MathematicalInvariant,
    /// A dead branch (code that can never be reached).
    DeadBranch,
    /// Matched against the built-in pattern database.
    KnownPattern,
    /// Verified by symbolic / truth-table evaluation.
    Symbolic,
}

impl fmt::Display for OpaquePredicateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrivialIdentity => write!(f, "TrivialIdentity"),
            Self::ConstantExpr => write!(f, "ConstantExpr"),
            Self::MathematicalInvariant => write!(f, "MathematicalInvariant"),
            Self::DeadBranch => write!(f, "DeadBranch"),
            Self::KnownPattern => write!(f, "KnownPattern"),
            Self::Symbolic => write!(f, "Symbolic"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueKind  — fine-grained classification for opaque predicates
// ─────────────────────────────────────────────────────────────────────────────

/// Fine-grained classification for a detected opaque predicate.
///
/// Where [`OpaquePredicateKind`] describes the *detection method*,
/// [`OpaqueKind`] describes the *mathematical reason* the predicate is opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OpaqueKind {
    /// The predicate is always true for all variable assignments.
    AlwaysTrue,
    /// The predicate is always false for all variable assignments.
    AlwaysFalse,
    /// The predicate's outcome depends on the run-time value of at least one
    /// variable — it is a genuine conditional, not an opaque predicate.
    DataDependent,
}

impl fmt::Display for OpaqueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysTrue => write!(f, "AlwaysTrue"),
            Self::AlwaysFalse => write!(f, "AlwaysFalse"),
            Self::DataDependent => write!(f, "DataDependent"),
        }
    }
}

impl From<PredicateValue> for OpaqueKind {
    fn from(pv: PredicateValue) -> Self {
        match pv {
            PredicateValue::AlwaysTrue => Self::AlwaysTrue,
            PredicateValue::AlwaysFalse => Self::AlwaysFalse,
            PredicateValue::Unknown => Self::DataDependent,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueExpr
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified expression tree used for predicate analysis.
///
/// All arithmetic is performed with wrapping `i64` semantics to match typical
/// machine-word behaviour.  Boolean results are represented as `0` (false) or
/// `1` (true).
#[derive(Debug, Clone, PartialEq)]
pub enum OpaqueExpr {
    /// Literal integer constant.
    Const(i64),
    /// Symbolic variable identified by name.
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
    /// Equality comparison — evaluates to 1 or 0.
    Eq(Box<Self>, Box<Self>),
    /// Inequality comparison.
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    /// Population count (`popcnt`) of a value.
    BitCount(Box<Self>),
    /// Absolute value.
    Abs(Box<Self>),
    /// Squaring shorthand: `x^2 == x * x`.
    Square(Box<Self>),
}

impl OpaqueExpr {
    // ── helpers ────────────────────────────────────────────────────────────

    fn bx(e: Self) -> Box<Self> {
        Box::new(e)
    }

    /// Maximum AST depth before `eval` / `collect_vars` bail out.
    /// Protects against stack exhaustion from adversarially deep expression trees.
    const MAX_EVAL_DEPTH: u32 = 512;

    // ── public API ─────────────────────────────────────────────────────────

    /// Evaluate the expression given a mapping from variable names to values.
    /// Returns `None` if a variable is unbound, integer overflow occurs in a
    /// division/modulo, or the expression tree exceeds [`Self::MAX_EVAL_DEPTH`]
    /// nodes deep (dos-unbounded-recursion guard).
    #[must_use]
    pub fn eval(&self, vars: &HashMap<String, i64>) -> Option<i64> {
        self.eval_depth(vars, 0)
    }

    fn eval_depth(&self, vars: &HashMap<String, i64>, depth: u32) -> Option<i64> {
        if depth >= Self::MAX_EVAL_DEPTH {
            return None; // dos-unbounded-recursion: bail rather than stack-overflow
        }
        let d = depth + 1;
        match self {
            Self::Const(c) => Some(*c),
            Self::Var(name) => vars.get(name).copied(),
            Self::Add(a, b) => Some(a.eval_depth(vars, d)?.wrapping_add(b.eval_depth(vars, d)?)),
            Self::Sub(a, b) => Some(a.eval_depth(vars, d)?.wrapping_sub(b.eval_depth(vars, d)?)),
            Self::Mul(a, b) => Some(a.eval_depth(vars, d)?.wrapping_mul(b.eval_depth(vars, d)?)),
            Self::Div(a, b) => {
                let dv = b.eval_depth(vars, d)?;
                if dv == 0 {
                    return None;
                }
                Some(a.eval_depth(vars, d)?.wrapping_div(dv))
            }
            Self::Mod(a, b) => {
                let dv = b.eval_depth(vars, d)?;
                if dv == 0 {
                    return None;
                }
                Some(a.eval_depth(vars, d)?.wrapping_rem(dv))
            }
            Self::And(a, b) => Some(a.eval_depth(vars, d)? & b.eval_depth(vars, d)?),
            Self::Or(a, b) => Some(a.eval_depth(vars, d)? | b.eval_depth(vars, d)?),
            Self::Xor(a, b) => Some(a.eval_depth(vars, d)? ^ b.eval_depth(vars, d)?),
            Self::Not(a) => Some(!a.eval_depth(vars, d)?),
            Self::Neg(a) => Some(a.eval_depth(vars, d)?.wrapping_neg()),
            Self::Shl(a, n) => {
                if *n >= 64 {
                    return None;
                }
                Some(a.eval_depth(vars, d)?.wrapping_shl(u32::from(*n)))
            }
            Self::Shr(a, n) => {
                if *n >= 64 {
                    return None;
                }
                Some(a.eval_depth(vars, d)?.wrapping_shr(u32::from(*n)))
            }
            Self::Eq(a, b) => Some(i64::from(a.eval_depth(vars, d)? == b.eval_depth(vars, d)?)),
            Self::Ne(a, b) => Some(i64::from(a.eval_depth(vars, d)? != b.eval_depth(vars, d)?)),
            Self::Lt(a, b) => Some(i64::from(a.eval_depth(vars, d)? < b.eval_depth(vars, d)?)),
            Self::Le(a, b) => Some(i64::from(a.eval_depth(vars, d)? <= b.eval_depth(vars, d)?)),
            Self::Gt(a, b) => Some(i64::from(a.eval_depth(vars, d)? > b.eval_depth(vars, d)?)),
            Self::Ge(a, b) => Some(i64::from(a.eval_depth(vars, d)? >= b.eval_depth(vars, d)?)),
            Self::BitCount(a) => Some(i64::from(a.eval_depth(vars, d)?.count_ones())),
            Self::Abs(a) => a.eval_depth(vars, d)?.checked_abs(),
            Self::Square(a) => {
                let v = a.eval_depth(vars, d)?;
                Some(v.wrapping_mul(v))
            }
        }
    }

    /// If the expression is constant (contains no variables) return its value.
    #[must_use] 
    pub fn is_const(&self) -> Option<i64> {
        if self.vars().is_empty() {
            self.eval(&HashMap::new())
        } else {
            None
        }
    }

    /// Return the names of all variables referenced in this expression.
    #[must_use] 
    pub fn vars(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_vars(&mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Const(_) => {}
            Self::Var(n) => out.push(n.clone()),
            Self::Add(a, b)
            | Self::Sub(a, b)
            | Self::Mul(a, b)
            | Self::Div(a, b)
            | Self::Mod(a, b)
            | Self::And(a, b)
            | Self::Or(a, b)
            | Self::Xor(a, b)
            | Self::Eq(a, b)
            | Self::Ne(a, b)
            | Self::Lt(a, b)
            | Self::Le(a, b)
            | Self::Gt(a, b)
            | Self::Ge(a, b) => {
                a.collect_vars(out);
                b.collect_vars(out);
            }
            Self::Not(a) | Self::Neg(a) | Self::BitCount(a) | Self::Abs(a) | Self::Square(a) => {
                a.collect_vars(out);
            }
            Self::Shl(a, _) | Self::Shr(a, _) => {
                a.collect_vars(out);
            }
        }
    }

    /// Light-weight constant folding / algebraic simplification.
    ///
    /// A single pass — callers should loop until a fixed-point if they need
    /// deep reduction, but for opaque-predicate purposes one pass suffices.
    #[must_use] 
    pub fn simplify(&self) -> Self {
        match self {
            // Already atomic.
            Self::Const(_) | Self::Var(_) => self.clone(),

            Self::Neg(a) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(c.wrapping_neg());
                }
                Self::Neg(Self::bx(a))
            }
            Self::Not(a) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(!c);
                }
                Self::Not(Self::bx(a))
            }
            Self::Abs(a) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    // Use checked_abs to preserve the same semantics as eval(),
                    // which also uses checked_abs. For i64::MIN, checked_abs
                    // returns None so we leave the node unsimplified.
                    if let Some(abs_val) = c.checked_abs() {
                        return Self::Const(abs_val);
                    }
                }
                Self::Abs(Self::bx(a))
            }
            Self::Square(a) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(c.wrapping_mul(c));
                }
                Self::Square(Self::bx(a))
            }
            Self::BitCount(a) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(i64::from(c.count_ones()));
                }
                Self::BitCount(Self::bx(a))
            }
            Self::Shl(a, n) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(c.wrapping_shl(u32::from(*n)));
                }
                if *n == 0 {
                    return a;
                }
                Self::Shl(Self::bx(a), *n)
            }
            Self::Shr(a, n) => {
                let a = a.simplify();
                if let Some(c) = a.is_const() {
                    return Self::Const(c.wrapping_shr(u32::from(*n)));
                }
                if *n == 0 {
                    return a;
                }
                Self::Shr(Self::bx(a), *n)
            }
            Self::Add(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (&a, &b) {
                    _ if a.is_const().is_some() && b.is_const().is_some() => {
                        Self::Const(a.is_const().unwrap().wrapping_add(b.is_const().unwrap()))
                    }
                    (_, Self::Const(0)) | (Self::Const(0), _) => {
                        if matches!(b, Self::Const(0)) {
                            a
                        } else {
                            b
                        }
                    }
                    _ => Self::Add(Self::bx(a), Self::bx(b)),
                }
            }
            Self::Sub(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if a.is_const().is_some() && b.is_const().is_some() {
                    return Self::Const(a.is_const().unwrap().wrapping_sub(b.is_const().unwrap()));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(0);
                }
                if matches!(b, Self::Const(0)) {
                    return a;
                }
                Self::Sub(Self::bx(a), Self::bx(b))
            }
            Self::Mul(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (a.is_const(), b.is_const()) {
                    (Some(ca), Some(cb)) => Self::Const(ca.wrapping_mul(cb)),
                    (Some(0), _) | (_, Some(0)) => Self::Const(0),
                    (Some(1), _) => b,
                    (_, Some(1)) => a,
                    _ => Self::Mul(Self::bx(a), Self::bx(b)),
                }
            }
            Self::Div(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const())
                    && cb != 0 {
                        return Self::Const(ca.wrapping_div(cb));
                    }
                if matches!(b, Self::Const(1)) {
                    return a;
                }
                Self::Div(Self::bx(a), Self::bx(b))
            }
            Self::Mod(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const())
                    && cb != 0 {
                        return Self::Const(ca.wrapping_rem(cb));
                    }
                Self::Mod(Self::bx(a), Self::bx(b))
            }
            Self::And(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(ca & cb);
                }
                if matches!(b, Self::Const(0)) || matches!(a, Self::Const(0)) {
                    return Self::Const(0);
                }
                if matches!(b, Self::Const(-1)) {
                    return a;
                }
                if matches!(a, Self::Const(-1)) {
                    return b;
                }
                Self::And(Self::bx(a), Self::bx(b))
            }
            Self::Or(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(ca | cb);
                }
                if matches!(a, Self::Const(-1)) || matches!(b, Self::Const(-1)) {
                    return Self::Const(-1);
                }
                if matches!(a, Self::Const(0)) {
                    return b;
                }
                if matches!(b, Self::Const(0)) {
                    return a;
                }
                Self::Or(Self::bx(a), Self::bx(b))
            }
            Self::Xor(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(ca ^ cb);
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(0);
                }
                Self::Xor(Self::bx(a), Self::bx(b))
            }
            Self::Eq(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca == cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(1);
                }
                Self::Eq(Self::bx(a), Self::bx(b))
            }
            Self::Ne(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca != cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(0);
                }
                Self::Ne(Self::bx(a), Self::bx(b))
            }
            Self::Lt(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca < cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(0);
                }
                Self::Lt(Self::bx(a), Self::bx(b))
            }
            Self::Le(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca <= cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(1);
                }
                Self::Le(Self::bx(a), Self::bx(b))
            }
            Self::Gt(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca > cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(0);
                }
                Self::Gt(Self::bx(a), Self::bx(b))
            }
            Self::Ge(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
                    return Self::Const(i64::from(ca >= cb));
                }
                if a.is_trivially_equal(&b) {
                    return Self::Const(1);
                }
                Self::Ge(Self::bx(a), Self::bx(b))
            }
        }
    }

    /// Returns `true` if `self` and `other` are structurally identical —
    /// i.e. the same AST shape with the same variable names and constants.
    #[must_use] 
    pub fn is_trivially_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Const(a), Self::Const(b)) => a == b,
            (Self::Var(a), Self::Var(b)) => a == b,
            (Self::Add(a1, b1), Self::Add(a2, b2))
            | (Self::Sub(a1, b1), Self::Sub(a2, b2))
            | (Self::Mul(a1, b1), Self::Mul(a2, b2))
            | (Self::Div(a1, b1), Self::Div(a2, b2))
            | (Self::Mod(a1, b1), Self::Mod(a2, b2))
            | (Self::And(a1, b1), Self::And(a2, b2))
            | (Self::Or(a1, b1), Self::Or(a2, b2))
            | (Self::Xor(a1, b1), Self::Xor(a2, b2))
            | (Self::Eq(a1, b1), Self::Eq(a2, b2))
            | (Self::Ne(a1, b1), Self::Ne(a2, b2))
            | (Self::Lt(a1, b1), Self::Lt(a2, b2))
            | (Self::Le(a1, b1), Self::Le(a2, b2))
            | (Self::Gt(a1, b1), Self::Gt(a2, b2))
            | (Self::Ge(a1, b1), Self::Ge(a2, b2)) => {
                a1.is_trivially_equal(a2) && b1.is_trivially_equal(b2)
            }
            (Self::Not(a), Self::Not(b))
            | (Self::Neg(a), Self::Neg(b))
            | (Self::Abs(a), Self::Abs(b))
            | (Self::Square(a), Self::Square(b))
            | (Self::BitCount(a), Self::BitCount(b)) => a.is_trivially_equal(b),
            (Self::Shl(a, n1), Self::Shl(b, n2)) | (Self::Shr(a, n1), Self::Shr(b, n2)) => {
                n1 == n2 && a.is_trivially_equal(b)
            }
            _ => false,
        }
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl fmt::Display for OpaqueExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(c) => write!(f, "{c}"),
            Self::Var(n) => write!(f, "{n}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::Mul(a, b) => write!(f, "({a} * {b})"),
            Self::Div(a, b) => write!(f, "({a} / {b})"),
            Self::Mod(a, b) => write!(f, "({a} % {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Or(a, b) => write!(f, "({a} | {b})"),
            Self::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Self::Not(a) => write!(f, "~{a}"),
            Self::Neg(a) => write!(f, "-{a}"),
            Self::Shl(a, n) => write!(f, "({a} << {n})"),
            Self::Shr(a, n) => write!(f, "({a} >> {n})"),
            Self::Eq(a, b) => write!(f, "({a} == {b})"),
            Self::Ne(a, b) => write!(f, "({a} != {b})"),
            Self::Lt(a, b) => write!(f, "({a} < {b})"),
            Self::Le(a, b) => write!(f, "({a} <= {b})"),
            Self::Gt(a, b) => write!(f, "({a} > {b})"),
            Self::Ge(a, b) => write!(f, "({a} >= {b})"),
            Self::BitCount(a) => write!(f, "popcount({a})"),
            Self::Abs(a) => write!(f, "abs({a})"),
            Self::Square(a) => write!(f, "({a})^2"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KnownOpaquePattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the opaque-predicate pattern database.
pub struct KnownOpaquePattern {
    pub name: &'static str,
    pub description: &'static str,
    pub value: PredicateValue,
    pub kind: OpaquePredicateKind,
    /// Returns `Some(value)` if the expression matches this pattern.
    pub check: fn(&OpaqueExpr) -> Option<PredicateValue>,
}

// ── Pattern helpers ───────────────────────────────────────────────────────────

/// Is this node an `Eq(X, X)` where both sides are structurally identical?
fn is_eq_self(e: &OpaqueExpr) -> bool {
    matches!(e, OpaqueExpr::Eq(a, b) if a.is_trivially_equal(b))
}

/// Is this node a `Ne(X, X)`?
fn is_ne_self(e: &OpaqueExpr) -> bool {
    matches!(e, OpaqueExpr::Ne(a, b) if a.is_trivially_equal(b))
}

/// Is this node a `Sub(X, X)` (== 0)?
fn is_sub_self(e: &OpaqueExpr) -> bool {
    matches!(e, OpaqueExpr::Sub(a, b) if a.is_trivially_equal(b))
}

/// Is this expression structurally of the form `Xor(X, X)`?
fn is_xor_self(e: &OpaqueExpr) -> bool {
    matches!(e, OpaqueExpr::Xor(a, b) if a.is_trivially_equal(b))
}

/// Match `X * (X - 1)`.
fn is_x_times_x_minus_1(e: &OpaqueExpr) -> bool {
    if let OpaqueExpr::Mul(a, b) = e {
        if let OpaqueExpr::Sub(inner_a, inner_b) = b.as_ref()
            && a.is_trivially_equal(inner_a) && matches!(inner_b.as_ref(), OpaqueExpr::Const(1)) {
                return true;
            }
        // Also accept reversed operand order: (X-1) * X
        if let OpaqueExpr::Sub(inner_a, inner_b) = a.as_ref()
            && b.is_trivially_equal(inner_a) && matches!(inner_b.as_ref(), OpaqueExpr::Const(1)) {
                return true;
            }
    }
    false
}

/// Match `X * (X + 1)`.
fn is_x_times_x_plus_1(e: &OpaqueExpr) -> bool {
    if let OpaqueExpr::Mul(a, b) = e {
        if let OpaqueExpr::Add(inner_a, inner_b) = b.as_ref()
            && a.is_trivially_equal(inner_a) && matches!(inner_b.as_ref(), OpaqueExpr::Const(1)) {
                return true;
            }
        if let OpaqueExpr::Add(inner_a, inner_b) = a.as_ref()
            && b.is_trivially_equal(inner_a) && matches!(inner_b.as_ref(), OpaqueExpr::Const(1)) {
                return true;
            }
    }
    false
}

/// Match `(x | 1)` — result is always odd (i.e. bit-0 is set → odd).
/// Returns true if `e` is `Or(x, Const(1))` or `Or(Const(1), x)`.
fn is_or_with_one(e: &OpaqueExpr) -> bool {
    if let OpaqueExpr::Or(a, b) = e {
        if matches!(b.as_ref(), OpaqueExpr::Const(1)) {
            return true;
        }
        if matches!(a.as_ref(), OpaqueExpr::Const(1)) {
            return true;
        }
    }
    false
}

/// Match `X^2 + X` i.e. `x*x + x` or `Square(x) + x` or commuted forms.
fn is_x_squared_plus_x(e: &OpaqueExpr) -> bool {
    let (add_l, add_r) = if let OpaqueExpr::Add(a, b) = e {
        (a, b)
    } else {
        return false;
    };
    // Check: add_l is x^2 (or x*x) and add_r is x, or vice versa.
    let is_square_of = |sq: &OpaqueExpr, var: &OpaqueExpr| -> bool {
        match sq {
            OpaqueExpr::Square(inner) => inner.is_trivially_equal(var),
            OpaqueExpr::Mul(a, b) => a.is_trivially_equal(b) && a.is_trivially_equal(var),
            _ => false,
        }
    };
    is_square_of(add_l, add_r) || is_square_of(add_r, add_l)
}

/// Match `(x | 1) & 1 == 1` — a genuine tautology for EVERY `x`.
///
/// `| 1` sets bit 0 and `& 1` reads it back, so the result is 1 whatever the
/// sign or width of `x`.
///
/// The sibling form `(x | 1) % 2 == 1` looks equivalent and is NOT: see
/// [`is_or1_mod_odd_predicate`].
fn is_or1_odd_predicate(e: &OpaqueExpr) -> bool {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(1))
            && let OpaqueExpr::And(a, b) = lhs.as_ref() {
                if matches!(b.as_ref(), OpaqueExpr::Const(1)) && is_or_with_one(a) {
                    return true;
                }
                if matches!(a.as_ref(), OpaqueExpr::Const(1)) && is_or_with_one(b) {
                    return true;
                }
            }
    false
}

/// Match `(x | 1) % 2 == 1`, which is true only for NON-NEGATIVE `x`.
///
/// `%` follows the sign of its left operand in Rust (and in C): for `x = -3`,
/// `-3 | 1 == -3` and `-3 % 2 == -1`, which is not 1. Treating this as a
/// tautology — as it was, sharing a matcher with the bitwise form — makes a
/// deobfuscator delete a branch that really is taken whenever the variable is
/// negative: live code removed, not merely a mislabelled predicate.
///
/// Reported as `Unknown` unless the sign of `x` is known, which this
/// syntactic matcher cannot establish.
fn is_or1_mod_odd_predicate(e: &OpaqueExpr) -> bool {
    if let OpaqueExpr::Eq(lhs, rhs) = e
        && matches!(rhs.as_ref(), OpaqueExpr::Const(1))
            && let OpaqueExpr::Mod(inner, div) = lhs.as_ref()
                && matches!(div.as_ref(), OpaqueExpr::Const(2)) && is_or_with_one(inner) {
                    return true;
                }
    false
}

/// Patterns 1-24.
#[must_use] 
pub fn build_known_patterns() -> Vec<KnownOpaquePattern> {
    vec![
        // ── Pattern 1: x == x → AlwaysTrue ──────────────────────────────
        KnownOpaquePattern {
            name: "eq_self",
            description: "x == x is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if is_eq_self(e) {
                    Some(PredicateValue::AlwaysTrue)
                } else {
                    None
                }
            },
        },
        // ── Pattern 2: x != x → AlwaysFalse ─────────────────────────────
        KnownOpaquePattern {
            name: "ne_self",
            description: "x != x is always false",
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if is_ne_self(e) {
                    Some(PredicateValue::AlwaysFalse)
                } else {
                    None
                }
            },
        },
        // ── Pattern 3: x - x == 0 → AlwaysTrue ──────────────────────────
        KnownOpaquePattern {
            name: "sub_self_eq_zero",
            description: "(x - x) == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e {
                    if is_sub_self(lhs) && matches!(rhs.as_ref(), OpaqueExpr::Const(0)) {
                        return Some(PredicateValue::AlwaysTrue);
                    }
                    if is_sub_self(rhs) && matches!(lhs.as_ref(), OpaqueExpr::Const(0)) {
                        return Some(PredicateValue::AlwaysTrue);
                    }
                }
                None
            },
        },
        // ── Pattern 4: (x*(x-1)) % 2 == 0 → AlwaysTrue ──────────────────
        KnownOpaquePattern {
            name: "consec_product_even",
            description: "Product of consecutive integers x*(x-1) is always even",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && let OpaqueExpr::Mod(inner, divisor) = lhs.as_ref()
                        && matches!(divisor.as_ref(), OpaqueExpr::Const(2))
                            && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                            && is_x_times_x_minus_1(inner)
                        {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                None
            },
        },
        // ── Pattern 5: x^2 >= 0 → AlwaysTrue ────────────────────────────
        KnownOpaquePattern {
            name: "square_ge_zero",
            description: "x^2 >= 0 is always true for signed integers",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Ge(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0)) {
                        if matches!(lhs.as_ref(), OpaqueExpr::Square(_)) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                        // Also accept Mul(X, X)
                        if let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                            && a.is_trivially_equal(b) {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                    }
                None
            },
        },
        // ── Pattern 6: (x*(x+1)) % 2 == 0 → AlwaysTrue ──────────────────
        KnownOpaquePattern {
            name: "consec_succ_product_even",
            description: "Product of consecutive integers x*(x+1) is always even",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && let OpaqueExpr::Mod(inner, divisor) = lhs.as_ref()
                        && matches!(divisor.as_ref(), OpaqueExpr::Const(2))
                            && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                            && is_x_times_x_plus_1(inner)
                        {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                None
            },
        },
        // ── Pattern 7: x | ~x == -1 → AlwaysTrue ────────────────────────
        KnownOpaquePattern {
            name: "x_or_not_x",
            description: "x | ~x == -1 (all ones) is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(-1))
                        && let OpaqueExpr::Or(a, b) = lhs.as_ref() {
                            if let OpaqueExpr::Not(inner) = b.as_ref()
                                && a.is_trivially_equal(inner) {
                                    return Some(PredicateValue::AlwaysTrue);
                                }
                            if let OpaqueExpr::Not(inner) = a.as_ref()
                                && b.is_trivially_equal(inner) {
                                    return Some(PredicateValue::AlwaysTrue);
                                }
                        }
                None
            },
        },
        // ── Pattern 8: x & ~x == 0 → AlwaysTrue ─────────────────────────
        KnownOpaquePattern {
            name: "x_and_not_x",
            description: "x & ~x == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::And(a, b) = lhs.as_ref() {
                            if let OpaqueExpr::Not(inner) = b.as_ref()
                                && a.is_trivially_equal(inner) {
                                    return Some(PredicateValue::AlwaysTrue);
                                }
                            if let OpaqueExpr::Not(inner) = a.as_ref()
                                && b.is_trivially_equal(inner) {
                                    return Some(PredicateValue::AlwaysTrue);
                                }
                        }
                None
            },
        },
        // ── Pattern 9: x XOR x == 0 → AlwaysTrue ────────────────────────
        KnownOpaquePattern {
            name: "xor_self_zero",
            description: "x XOR x == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0)) && is_xor_self(lhs) {
                        return Some(PredicateValue::AlwaysTrue);
                    }
                // Also accept a bare Xor(x,x) used as a condition (always 0 == false)
                if is_xor_self(e) {
                    return Some(PredicateValue::AlwaysFalse);
                }
                None
            },
        },
        // ── Pattern 10: constant == constant ─────────────────────────────
        KnownOpaquePattern {
            name: "const_const_cmp",
            description: "Comparison of two constants always has a fixed result",
            value: PredicateValue::Unknown,
            kind: OpaquePredicateKind::ConstantExpr,
            check: |e| match e {
                OpaqueExpr::Eq(a, b)
                | OpaqueExpr::Ne(a, b)
                | OpaqueExpr::Lt(a, b)
                | OpaqueExpr::Le(a, b)
                | OpaqueExpr::Gt(a, b)
                | OpaqueExpr::Ge(a, b) => {
                    if let (Some(_), Some(_)) = (a.is_const(), b.is_const()) {
                        let result = e.eval(&HashMap::new())?;
                        if result != 0 {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                        return Some(PredicateValue::AlwaysFalse);
                    }
                    None
                }
                _ => None,
            },
        },
        // ── Pattern 11: x < x → AlwaysFalse ─────────────────────────────
        KnownOpaquePattern {
            name: "lt_self",
            description: "x < x is always false",
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if matches!(e, OpaqueExpr::Lt(a, b) if a.is_trivially_equal(b)) {
                    Some(PredicateValue::AlwaysFalse)
                } else {
                    None
                }
            },
        },
        // ── Pattern 12: x > x → AlwaysFalse ─────────────────────────────
        KnownOpaquePattern {
            name: "gt_self",
            description: "x > x is always false",
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if matches!(e, OpaqueExpr::Gt(a, b) if a.is_trivially_equal(b)) {
                    Some(PredicateValue::AlwaysFalse)
                } else {
                    None
                }
            },
        },
        // ── Pattern 13: x <= x → AlwaysTrue ─────────────────────────────
        KnownOpaquePattern {
            name: "le_self",
            description: "x <= x is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if matches!(e, OpaqueExpr::Le(a, b) if a.is_trivially_equal(b)) {
                    Some(PredicateValue::AlwaysTrue)
                } else {
                    None
                }
            },
        },
        // ── Pattern 14: x >= x → AlwaysTrue ─────────────────────────────
        KnownOpaquePattern {
            name: "ge_self",
            description: "x >= x is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if matches!(e, OpaqueExpr::Ge(a, b) if a.is_trivially_equal(b)) {
                    Some(PredicateValue::AlwaysTrue)
                } else {
                    None
                }
            },
        },
        // ── Pattern 15: x & 0 == 0 → AlwaysTrue ─────────────────────────
        KnownOpaquePattern {
            name: "and_zero_eq_zero",
            description: "(x & 0) == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::And(a, b) = lhs.as_ref()
                            && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                                || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                            {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                None
            },
        },
        // ── Pattern 16: x | (-1) == -1 → AlwaysTrue ─────────────────────
        KnownOpaquePattern {
            name: "or_all_ones",
            description: "(x | -1) == -1 is always true (bitwise OR with all ones)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(-1))
                        && let OpaqueExpr::Or(a, b) = lhs.as_ref()
                            && (matches!(a.as_ref(), OpaqueExpr::Const(-1))
                                || matches!(b.as_ref(), OpaqueExpr::Const(-1)))
                            {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                None
            },
        },
        // ── Pattern 17: (x * 2) % 2 == 0 → AlwaysTrue ───────────────────
        KnownOpaquePattern {
            name: "double_mod_2_zero",
            description: "(x * 2) % 2 == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::Mod(inner, divisor) = lhs.as_ref()
                            && matches!(divisor.as_ref(), OpaqueExpr::Const(2))
                                && let OpaqueExpr::Mul(a, b) = inner.as_ref()
                                    && (matches!(a.as_ref(), OpaqueExpr::Const(2))
                                        || matches!(b.as_ref(), OpaqueExpr::Const(2)))
                                    {
                                        return Some(PredicateValue::AlwaysTrue);
                                    }
                None
            },
        },
        // ── Pattern 18: x + 0 == x → AlwaysTrue ─────────────────────────
        KnownOpaquePattern {
            name: "add_zero_eq_self",
            description: "x + 0 == x is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e {
                    // (x + 0) == x
                    if let OpaqueExpr::Add(a, b) = lhs.as_ref() {
                        if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(rhs) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                        if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(rhs) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                    }
                }
                None
            },
        },
        // ── Pattern 19: ~~x == x → AlwaysTrue ───────────────────────────
        KnownOpaquePattern {
            name: "double_not_eq_self",
            description: "~~x == x is always true (double bitwise NOT)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e {
                    if let OpaqueExpr::Not(inner) = lhs.as_ref()
                        && let OpaqueExpr::Not(inner2) = inner.as_ref()
                            && inner2.is_trivially_equal(rhs) {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                    // Also rhs side
                    if let OpaqueExpr::Not(inner) = rhs.as_ref()
                        && let OpaqueExpr::Not(inner2) = inner.as_ref()
                            && inner2.is_trivially_equal(lhs) {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                }
                None
            },
        },
        // ── Pattern 20: (x << 0) == x → AlwaysTrue ──────────────────────
        KnownOpaquePattern {
            name: "shl_zero_eq_self",
            description: "(x << 0) == x is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e {
                    if let OpaqueExpr::Shl(inner, 0) = lhs.as_ref()
                        && inner.is_trivially_equal(rhs) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                    if let OpaqueExpr::Shl(inner, 0) = rhs.as_ref()
                        && inner.is_trivially_equal(lhs) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                }
                None
            },
        },
        // ── Pattern 21: abs(x) >= 0 → AlwaysTrue ────────────────────────
        KnownOpaquePattern {
            name: "abs_ge_zero",
            description: "abs(x) >= 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Ge(lhs, rhs) = e
                    && matches!(lhs.as_ref(), OpaqueExpr::Abs(_))
                        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                    {
                        return Some(PredicateValue::AlwaysTrue);
                    }
                None
            },
        },
        // ── Pattern 22: popcount(x) >= 0 → AlwaysTrue ───────────────────
        KnownOpaquePattern {
            name: "popcount_ge_zero",
            description: "popcount(x) >= 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Ge(lhs, rhs) = e
                    && matches!(lhs.as_ref(), OpaqueExpr::BitCount(_))
                        && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                    {
                        return Some(PredicateValue::AlwaysTrue);
                    }
                None
            },
        },
        // ── Pattern 23: x * 0 == 0 → AlwaysTrue ─────────────────────────
        KnownOpaquePattern {
            name: "mul_zero_eq_zero",
            description: "x * 0 == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                            && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                                || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                            {
                                return Some(PredicateValue::AlwaysTrue);
                            }
                None
            },
        },
        // ── Pattern 24: x XOR x != 0 → AlwaysFalse ──────────────────────
        KnownOpaquePattern {
            name: "xor_self_ne_zero",
            description: "x XOR x != 0 is always false",
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if let OpaqueExpr::Ne(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0)) && is_xor_self(lhs) {
                        return Some(PredicateValue::AlwaysFalse);
                    }
                None
            },
        },
        // ── Pattern 25: x^2 + x is always even → (x^2 + x) % 2 == 0 ────
        // Proof: x*(x+1) is a product of consecutive integers, always even.
        KnownOpaquePattern {
            name: "x_sq_plus_x_even",
            description: "x^2 + x is always even (consecutive product)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && let OpaqueExpr::Mod(inner, divisor) = lhs.as_ref()
                        && matches!(divisor.as_ref(), OpaqueExpr::Const(2))
                            && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                            && is_x_squared_plus_x(inner)
                        {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                None
            },
        },
        // ── Pattern 26: (x | 1) is always odd ─────────────────────────────
        // (x | 1) forces bit 0 to 1, so the result is always odd.
        // Detected as: (x | 1) % 2 == 1  or  (x | 1) & 1 == 1
        KnownOpaquePattern {
            name: "or_one_always_odd",
            description: "(x | 1) is always odd: (x|1)%2==1 or (x|1)&1==1",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if is_or1_odd_predicate(e) {
                    return Some(PredicateValue::AlwaysTrue);
                }
                // The `% 2` form is NOT a tautology: it fails for every
                // negative odd x. Report it as data-dependent rather than
                // letting a caller delete the branch.
                if is_or1_mod_odd_predicate(e) {
                    return Some(PredicateValue::Unknown);
                }
                None
            },
        },
        // ── Pattern 27: 7*x*x.is_multiple_of(7) → AlwaysTrue ─────────────────────
        // 7*x^2 is a multiple of 7 for all x.
        KnownOpaquePattern {
            name: "seven_x_sq_mod7",
            description: "7*x^2 % 7 == 0 is always true",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::Mod(inner, divisor) = lhs.as_ref()
                            && matches!(divisor.as_ref(), OpaqueExpr::Const(7)) {
                                // Accept 7 * (x * x), 7 * x^2, (x * x) * 7, x^2 * 7
                                let is_7_times_sq = |a: &OpaqueExpr, b: &OpaqueExpr| -> bool {
                                    if !matches!(a, OpaqueExpr::Const(7)) {
                                        return false;
                                    }
                                    matches!(b, OpaqueExpr::Square(_))
                                        || matches!(b, OpaqueExpr::Mul(p, q)
                                            if p.is_trivially_equal(q))
                                };
                                if let OpaqueExpr::Mul(a, b) = inner.as_ref()
                                    && (is_7_times_sq(a, b) || is_7_times_sq(b, a)) {
                                        return Some(PredicateValue::AlwaysTrue);
                                    }
                            }
                None
            },
        },
        // ── Pattern 28: x * 0 != 0 → AlwaysFalse ────────────────────────
        KnownOpaquePattern {
            name: "mul_zero_ne_zero",
            description: "x * 0 != 0 is always false",
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Ne(lhs, rhs) = e
                    && matches!(rhs.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::Mul(a, b) = lhs.as_ref()
                            && (matches!(a.as_ref(), OpaqueExpr::Const(0))
                                || matches!(b.as_ref(), OpaqueExpr::Const(0)))
                            {
                                return Some(PredicateValue::AlwaysFalse);
                            }
                None
            },
        },
        // ── Pattern 29: x & x == x → AlwaysTrue (idempotency) ────────────
        KnownOpaquePattern {
            name: "and_self_eq_self",
            description: "x & x == x is always true (AND idempotency)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && let OpaqueExpr::And(a, b) = lhs.as_ref()
                        && a.is_trivially_equal(b) && rhs.is_trivially_equal(a) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                None
            },
        },
        // ── Pattern 30: x | x == x → AlwaysTrue (idempotency) ────────────
        KnownOpaquePattern {
            name: "or_self_eq_self",
            description: "x | x == x is always true (OR idempotency)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e
                    && let OpaqueExpr::Or(a, b) = lhs.as_ref()
                        && a.is_trivially_equal(b) && rhs.is_trivially_equal(a) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                None
            },
        },
        // ── Pattern 31: x + (~x + 1) == 0 → AlwaysTrue (two's complement) ─
        // ~x + 1 = -x in two's complement, so x + (-x) = 0.
        KnownOpaquePattern {
            name: "twos_complement_negation",
            description: "x + (~x + 1) == 0 is always true (two's complement negation)",
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::MathematicalInvariant,
            check: |e| {
                if let OpaqueExpr::Eq(lhs, rhs) = e {
                    if !matches!(rhs.as_ref(), OpaqueExpr::Const(0)) {
                        return None;
                    }
                    // lhs = x + (~x + 1)  or  (~x + 1) + x
                    if let OpaqueExpr::Add(a, b) = lhs.as_ref() {
                        let check_pair = |x: &OpaqueExpr, rhs_add: &OpaqueExpr| -> bool {
                            // rhs_add should be (~x + 1)
                            if let OpaqueExpr::Add(na, nb) = rhs_add {
                                if matches!(nb.as_ref(), OpaqueExpr::Const(1))
                                    && let OpaqueExpr::Not(inner) = na.as_ref() {
                                        return x.is_trivially_equal(inner);
                                    }
                                if matches!(na.as_ref(), OpaqueExpr::Const(1))
                                    && let OpaqueExpr::Not(inner) = nb.as_ref() {
                                        return x.is_trivially_equal(inner);
                                    }
                            }
                            false
                        };
                        if check_pair(a, b) || check_pair(b, a) {
                            return Some(PredicateValue::AlwaysTrue);
                        }
                    }
                }
                None
            },
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// TruthTableChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a predicate by systematic or sampled evaluation over the variable domain.
pub struct TruthTableChecker {
    /// Bit-width used for the enumeration domain (default 8 → 256 values per variable).
    pub bits: u32,
    /// Maximum number of samples when `use_random` is false and enumeration is
    /// too expensive (more than this many combinations).
    pub sample_count: usize,
    /// When `false`, enumerate systematically; when `true`, use a fixed
    /// pseudo-random seed for reproducible sampling.
    pub use_random: bool,
}

impl Default for TruthTableChecker {
    fn default() -> Self {
        Self {
            bits: 8,
            sample_count: 1024,
            use_random: false,
        }
    }
}

impl TruthTableChecker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_bits(mut self, bits: u32) -> Self {
        self.bits = bits;
        self
    }

    #[must_use] 
    pub const fn with_samples(mut self, n: usize) -> Self {
        self.sample_count = n;
        self
    }

    /// Return `true` if the expression is non-zero for *every* tested assignment.
    #[must_use] 
    pub fn is_always_true(&self, expr: &OpaqueExpr) -> bool {
        let vars = expr.vars();
        for assignment in self.assignments(&vars) {
            match expr.eval(&assignment) {
                Some(0) | None => return false,
                _ => {}
            }
        }
        true
    }

    /// Return `true` if the expression is zero for *every* tested assignment.
    #[must_use]
    pub fn is_always_false(&self, expr: &OpaqueExpr) -> bool {
        let vars = expr.vars();
        let mut any_evaluated = false;
        for assignment in self.assignments(&vars) {
            match expr.eval(&assignment) {
                None => {}
                Some(0) => { any_evaluated = true; }
                _ => return false,
            }
        }
        // If no assignment produced Some(_), the expression is unevaluable
        // (e.g., constant division by zero). Return false (unknown) rather than
        // incorrectly claiming it is always false.
        any_evaluated
    }

    /// Return the predicate's constant value, or `Unknown` if it varies.
    #[must_use] 
    pub fn classify(&self, expr: &OpaqueExpr) -> PredicateValue {
        // Fast path for constant expressions.
        if let Some(c) = expr.is_const() {
            return if c != 0 {
                PredicateValue::AlwaysTrue
            } else {
                PredicateValue::AlwaysFalse
            };
        }
        let vars = expr.vars();
        if vars.is_empty() {
            // No variables but is_const returned None → unevaluable (div by zero etc.)
            return PredicateValue::Unknown;
        }
        let mut saw_true = false;
        let mut saw_false = false;
        for assignment in self.assignments(&vars) {
            match expr.eval(&assignment) {
                Some(0) => saw_false = true,
                Some(_) => saw_true = true,
                None => {
                    // Unevaluable for this input (div/0) — skip and continue.
                }
            }
            if saw_true && saw_false {
                return PredicateValue::Unknown;
            }
        }
        match (saw_true, saw_false) {
            (true, false) => PredicateValue::AlwaysTrue,
            (false, true) => PredicateValue::AlwaysFalse,
            _ => PredicateValue::Unknown,
        }
    }

    /// Find an assignment that makes `expr` non-zero (`true`).
    /// Returns `None` if the expression is always false over all tested inputs.
    #[must_use] 
    pub fn counterexample_true(&self, expr: &OpaqueExpr) -> Option<HashMap<String, i64>> {
        let vars = expr.vars();
        for assignment in self.assignments(&vars) {
            if let Some(v) = expr.eval(&assignment)
                && v != 0 {
                    return Some(assignment);
                }
        }
        None
    }

    /// Find an assignment that makes `expr` zero (`false`).
    /// Returns `None` if the expression is always true over all tested inputs.
    #[must_use] 
    pub fn counterexample_false(&self, expr: &OpaqueExpr) -> Option<HashMap<String, i64>> {
        let vars = expr.vars();
        for assignment in self.assignments(&vars) {
            if let Some(v) = expr.eval(&assignment)
                && v == 0 {
                    return Some(assignment);
                }
        }
        None
    }

    /// Generate all combinations of variable values for the configured bit width.
    ///
    /// If the total number of combinations (`(2^bits)^num_vars`) exceeds
    /// `sample_count`, the enumeration is cut off at `sample_count` entries so
    /// that compilation and testing remain fast.
    #[must_use] 
    pub fn enumerate_values(vars: &[String], bits: u32) -> Vec<HashMap<String, i64>> {
        if bits > 16 {
            eprintln!(
                "warning: TruthTableChecker configured with {bits}-bit variables; \
                 enumeration capped at 16 bits per variable to keep search tractable. \
                 Predicates classified as AlwaysTrue/AlwaysFalse hold only over the \
                 16-bit subset, not the full {bits}-bit domain."
            );
        }
        let range = 1u64 << bits.min(16); // cap at 16 bits per variable
        let n = vars.len();
        if n == 0 {
            return vec![HashMap::new()];
        }

        // Total combinations: range^n — can be huge.  Cap via iteration.
        const MAX_ENUMERATION: usize = 65_536;
        let total = (range as u128).checked_pow(n as u32).unwrap_or(u128::MAX);
        let cap = (total.min(MAX_ENUMERATION as u128)) as usize;
        let mut result = Vec::with_capacity(cap);
        let mut indices: Vec<u64> = vec![0; n];
        loop {
            let mut map = HashMap::with_capacity(n);
            for (i, name) in vars.iter().enumerate() {
                // Sign-extend so negative values are tested too.
                let width = bits.min(16);
                let shift = 64 - width;
                let raw = ((indices[i] as i64) << shift) >> shift;
                map.insert(name.clone(), raw);
            }
            result.push(map);

            if result.len() >= MAX_ENUMERATION {
                break;
            }

            // Increment indices (little-endian carry).
            let mut carry = true;
            for idx in &mut indices {
                if carry {
                    *idx += 1;
                    if *idx >= range {
                        *idx = 0;
                    } else {
                        carry = false;
                    }
                }
            }
            if carry {
                break; // wrapped all the way around
            }
        }
        result
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn assignments(&self, vars: &[String]) -> Vec<HashMap<String, i64>> {
        let all = Self::enumerate_values(vars, self.bits);
        if all.len() > self.sample_count {
            // Deterministic sub-sample: take every k-th element.
            let step = (all.len() / self.sample_count).max(1);
            all.into_iter()
                .step_by(step)
                .take(self.sample_count)
                .collect()
        } else {
            all
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueBranch
// ─────────────────────────────────────────────────────────────────────────────

/// A conditional branch that has been identified as an opaque predicate.
#[derive(Debug, Clone)]
pub struct OpaqueBranch {
    /// Address of the conditional jump instruction.
    pub address: Address,
    /// The symbolic condition expression.
    pub predicate: OpaqueExpr,
    /// Constant outcome of the predicate.
    pub value: PredicateValue,
    /// How the predicate was classified.
    pub kind: OpaquePredicateKind,
    /// Address of the dead (never-executed) branch target, if known.
    pub dead_target: Option<Address>,
    /// Address of the live (always-executed) branch target, if known.
    pub live_target: Option<Address>,
    /// Confidence in the classification (0.0 – 1.0).
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// SimpleBranchCfg
// ─────────────────────────────────────────────────────────────────────────────

/// A single conditional branch in the simplified CFG.
#[derive(Debug, Clone)]
pub struct SimpleBranch {
    pub address: Address,
    pub condition: OpaqueExpr,
    pub true_target: Address,
    pub false_target: Address,
}

/// A lightweight CFG representation used as input to the opaque-predicate pass.
pub struct SimpleBranchCfg {
    pub function_start: Address,
    pub branches: Vec<SimpleBranch>,
    /// Maps the start address of a basic block to its instruction count.
    pub block_sizes: HashMap<u64, usize>,
}

impl SimpleBranchCfg {
    #[must_use] 
    pub fn new(start: Address) -> Self {
        Self {
            function_start: start,
            branches: Vec::new(),
            block_sizes: HashMap::new(),
        }
    }

    pub fn add_branch(&mut self, branch: SimpleBranch) {
        self.branches.push(branch);
    }

    pub fn add_block_size(&mut self, addr: Address, size: usize) {
        self.block_sizes.insert(addr.as_u64(), size);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects opaque predicates in a CFG using pattern matching and truth-table
/// verification.
pub struct OpaqueDetector {
    pub known_patterns: Vec<KnownOpaquePattern>,
    pub checker: TruthTableChecker,
    /// Minimum confidence threshold for reporting a branch as opaque.
    pub min_confidence: f32,
    /// Enable pattern-database matching.
    pub use_patterns: bool,
    /// Enable truth-table / symbolic evaluation.
    pub use_truth_table: bool,
}

impl Default for OpaqueDetector {
    fn default() -> Self {
        Self {
            known_patterns: build_known_patterns(),
            checker: TruthTableChecker::new(),
            min_confidence: 0.7,
            use_patterns: true,
            use_truth_table: true,
        }
    }
}

impl OpaqueDetector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = c;
        self
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Detect all opaque predicates in `cfg` and return them as a list of
    /// [`OpaqueBranch`] records.
    #[must_use] 
    pub fn detect(&self, cfg: &SimpleBranchCfg) -> Vec<OpaqueBranch> {
        let mut out = Vec::new();
        for branch in &cfg.branches {
            let (value, kind, confidence) = self.classify_condition(&branch.condition);
            if value == PredicateValue::Unknown || confidence < self.min_confidence {
                continue;
            }
            let (dead_target, live_target) = match value {
                PredicateValue::AlwaysTrue => (Some(branch.false_target), Some(branch.true_target)),
                PredicateValue::AlwaysFalse => {
                    (Some(branch.true_target), Some(branch.false_target))
                }
                PredicateValue::Unknown => (None, None),
            };
            out.push(OpaqueBranch {
                address: branch.address,
                predicate: branch.condition.clone(),
                value,
                kind,
                dead_target,
                live_target,
                confidence,
            });
        }
        out
    }

    /// Classify a single condition expression and return
    /// `(value, kind, confidence)`.
    #[must_use] 
    pub fn classify_condition(
        &self,
        expr: &OpaqueExpr,
    ) -> (PredicateValue, OpaquePredicateKind, f32) {
        // 1. Constant expression (no variables) — highest confidence.
        if let Some(pv) = self.check_constant_expr(expr) {
            return (pv, OpaquePredicateKind::ConstantExpr, 1.0);
        }

        // 2. Trivial identity (structural).
        if let Some(pv) = self.check_trivial_identity(expr) {
            return (pv, OpaquePredicateKind::TrivialIdentity, 1.0);
        }

        // 3. Pattern database.
        if self.use_patterns
            && let Some((pv, kind)) = self.check_known_patterns(expr) {
                return (pv, kind, 0.95);
            }

        // 4. Truth-table / symbolic evaluation.
        if self.use_truth_table {
            let pv = self.checker.classify(expr);
            if pv != PredicateValue::Unknown {
                return (pv, OpaquePredicateKind::Symbolic, 0.80);
            }
        }

        (PredicateValue::Unknown, OpaquePredicateKind::Symbolic, 0.0)
    }

    /// Classify a single condition expression and return an [`OpaqueKind`]
    /// that indicates whether the predicate is always true, always false, or
    /// genuinely data-dependent.
    ///
    /// This is a convenience wrapper around [`classify_condition`] that maps
    /// the [`PredicateValue`] to the richer [`OpaqueKind`] type and filters
    /// results below `min_confidence`.
    ///
    /// # Example
    ///
    /// ```
    /// use rustre_deobf_opaque::{OpaqueDetector, OpaqueExpr, OpaqueKind};
    ///
    /// let detector = OpaqueDetector::new();
    /// let expr = OpaqueExpr::Eq(
    ///     Box::new(OpaqueExpr::Var("x".into())),
    ///     Box::new(OpaqueExpr::Var("x".into())),
    /// );
    /// assert_eq!(detector.classify_with_kind(&expr), OpaqueKind::AlwaysTrue);
    /// ```
    #[must_use] 
    pub fn classify_with_kind(&self, expr: &OpaqueExpr) -> OpaqueKind {
        let (pv, _kind, confidence) = self.classify_condition(expr);
        if confidence < self.min_confidence {
            return OpaqueKind::DataDependent;
        }
        OpaqueKind::from(pv)
    }

    /// Try to match `expr` against every pattern in the database.
    #[must_use] 
    pub fn check_known_patterns(
        &self,
        expr: &OpaqueExpr,
    ) -> Option<(PredicateValue, OpaquePredicateKind)> {
        for pat in &self.known_patterns {
            if let Some(pv) = (pat.check)(expr) {
                return Some((pv, pat.kind));
            }
        }
        // Also try on a simplified form.
        let simplified = expr.simplify();
        if !simplified.is_trivially_equal(expr) {
            for pat in &self.known_patterns {
                if let Some(pv) = (pat.check)(&simplified) {
                    return Some((pv, pat.kind));
                }
            }
        }
        None
    }

    /// Check whether `expr` is a trivial self-comparison (`x == x`, `x != x`,
    /// `x <= x`, `x >= x`, `x < x`, `x > x`).
    #[must_use] 
    pub fn check_trivial_identity(&self, expr: &OpaqueExpr) -> Option<PredicateValue> {
        match expr {
            OpaqueExpr::Eq(a, b) if a.is_trivially_equal(b) => Some(PredicateValue::AlwaysTrue),
            OpaqueExpr::Ne(a, b) if a.is_trivially_equal(b) => Some(PredicateValue::AlwaysFalse),
            OpaqueExpr::Le(a, b) | OpaqueExpr::Ge(a, b) if a.is_trivially_equal(b) => {
                Some(PredicateValue::AlwaysTrue)
            }
            OpaqueExpr::Lt(a, b) | OpaqueExpr::Gt(a, b) if a.is_trivially_equal(b) => {
                Some(PredicateValue::AlwaysFalse)
            }
            _ => None,
        }
    }

    /// Check whether `expr` is a constant expression (contains no variables)
    /// and return its fixed truth value.
    #[must_use] 
    pub fn check_constant_expr(&self, expr: &OpaqueExpr) -> Option<PredicateValue> {
        let c = expr.is_const()?;
        if c != 0 {
            Some(PredicateValue::AlwaysTrue)
        } else {
            Some(PredicateValue::AlwaysFalse)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Result of one elimination pass.
pub struct EliminationResult {
    pub branches_eliminated: usize,
    pub dead_blocks_identified: Vec<Address>,
    pub always_taken_edges: Vec<(Address, Address)>,
    pub errors: Vec<String>,
}

/// Eliminates opaque predicates from a [`SimpleBranchCfg`] by converting
/// always-true or always-false branches to unconditional jumps and recording
/// the dead targets.
pub struct OpaqueEliminator {
    pub detector: OpaqueDetector,
}

impl Default for OpaqueEliminator {
    fn default() -> Self {
        Self {
            detector: OpaqueDetector::new(),
        }
    }
}

impl OpaqueEliminator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run detection and rewrite all identified opaque branches.
    pub fn eliminate(&self, cfg: &mut SimpleBranchCfg) -> EliminationResult {
        let opaque_branches = self.detector.detect(cfg);
        let mut result = EliminationResult {
            branches_eliminated: 0,
            dead_blocks_identified: Vec::new(),
            always_taken_edges: Vec::new(),
            errors: Vec::new(),
        };

        for ob in &opaque_branches {
            // Find the matching branch in the CFG and rewrite it.
            let found = cfg.branches.iter_mut().find(|b| b.address == ob.address);
            match found {
                None => {
                    result
                        .errors
                        .push(format!("Branch at {} not found in CFG", ob.address));
                }
                Some(branch) => {
                    if let Some(live) = ob.live_target {
                        Self::make_unconditional(branch, live);
                        result.branches_eliminated += 1;
                        result.always_taken_edges.push((ob.address, live));
                    }
                    if let Some(dead) = ob.dead_target {
                        result.dead_blocks_identified.push(dead);
                    }
                }
            }
        }

        result
    }

    /// Rewrite `branch` so it unconditionally jumps to `target`.
    ///
    /// The condition is replaced with `Const(1)` (always true) and both
    /// targets are set to `target`, making this an effectively unconditional
    /// edge.
    pub fn make_unconditional(branch: &mut SimpleBranch, target: Address) {
        branch.condition = OpaqueExpr::Const(1);
        branch.true_target = target;
        branch.false_target = target;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueDeobfPass
// ─────────────────────────────────────────────────────────────────────────────

/// Summary produced by [`OpaqueDeobfPass::run`].
pub struct OpaquePassResult {
    /// Total number of opaque predicate candidates found (before confidence filter).
    pub candidates_found: usize,
    /// How many branches were actually eliminated.
    pub eliminated: usize,
    /// Addresses of dead basic blocks identified.
    pub dead_blocks: Vec<Address>,
    /// Per-branch confidence scores for all detected opaques.
    pub confidence_scores: Vec<(Address, f32)>,
}

/// High-level, one-shot deobfuscation pass that detects and eliminates all
/// opaque predicates in a function CFG.
pub struct OpaqueDeobfPass {
    pub eliminator: OpaqueEliminator,
}

impl Default for OpaqueDeobfPass {
    fn default() -> Self {
        Self {
            eliminator: OpaqueEliminator::new(),
        }
    }
}

impl OpaqueDeobfPass {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the full detection + elimination pipeline and return a summary.
    pub fn run(&self, cfg: &mut SimpleBranchCfg) -> OpaquePassResult {
        // First pass: collect candidates and confidence scores.
        let candidates = self.eliminator.detector.detect(cfg);
        let candidates_found = candidates.len();
        let confidence_scores: Vec<(Address, f32)> = candidates
            .iter()
            .map(|ob| (ob.address, ob.confidence))
            .collect();

        // Second pass: eliminate.
        let elim_result = self.eliminator.eliminate(cfg);

        OpaquePassResult {
            candidates_found,
            eliminated: elim_result.branches_eliminated,
            dead_blocks: elim_result.dead_blocks_identified,
            confidence_scores,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str) -> OpaqueExpr {
        OpaqueExpr::Var(name.to_string())
    }
    fn c(v: i64) -> OpaqueExpr {
        OpaqueExpr::Const(v)
    }
    fn vars1(name: &str, val: i64) -> HashMap<String, i64> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), val);
        m
    }

    // ── OpaqueExpr::eval ──────────────────────────────────────────────────────

    #[test]
    fn eval_eq_var_self_always_one() {
        let expr = OpaqueExpr::Eq(Box::new(var("x")), Box::new(var("x")));
        for x in -10_i64..=10 {
            assert_eq!(expr.eval(&vars1("x", x)), Some(1));
        }
    }

    #[test]
    fn eval_ne_var_self_always_zero() {
        let expr = OpaqueExpr::Ne(Box::new(var("x")), Box::new(var("x")));
        for x in -10_i64..=10 {
            assert_eq!(expr.eval(&vars1("x", x)), Some(0));
        }
    }

    #[test]
    fn eval_constant_arithmetic() {
        // (3 + 4) * 2 == 14
        let expr = OpaqueExpr::Mul(
            Box::new(OpaqueExpr::Add(Box::new(c(3)), Box::new(c(4)))),
            Box::new(c(2)),
        );
        assert_eq!(expr.eval(&HashMap::new()), Some(14));
    }

    #[test]
    fn eval_div_by_zero_returns_none() {
        let expr = OpaqueExpr::Div(Box::new(c(10)), Box::new(c(0)));
        assert_eq!(expr.eval(&HashMap::new()), None);
    }

    #[test]
    fn eval_square_nonneg() {
        let expr = OpaqueExpr::Square(Box::new(var("x")));
        for x in -5_i64..=5 {
            let v = expr.eval(&vars1("x", x)).unwrap();
            assert!(v >= 0, "x={x} gave {v}");
        }
    }

    // ── OpaqueExpr::vars ──────────────────────────────────────────────────────

    #[test]
    fn vars_returns_all_unique_names() {
        let expr = OpaqueExpr::Add(
            Box::new(OpaqueExpr::Mul(Box::new(var("x")), Box::new(var("y")))),
            Box::new(OpaqueExpr::Sub(Box::new(var("x")), Box::new(c(1)))),
        );
        let v = expr.vars();
        assert_eq!(v, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn vars_empty_for_constant() {
        assert!(c(42).vars().is_empty());
    }

    // ── OpaqueExpr::Display ───────────────────────────────────────────────────

    #[test]
    fn display_nested_expr() {
        let expr = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Add(Box::new(var("x")), Box::new(c(0)))),
            Box::new(var("x")),
        );
        let s = expr.to_string();
        assert!(s.contains("=="), "Display: {s}");
        assert!(s.contains('x'), "Display: {s}");
    }

    #[test]
    fn display_const() {
        assert_eq!(c(-7).to_string(), "-7");
    }

    // ── Known patterns ────────────────────────────────────────────────────────

    #[test]
    fn known_pattern_eq_self_always_true() {
        let detector = OpaqueDetector::new();
        let expr = OpaqueExpr::Eq(Box::new(var("x")), Box::new(var("x")));
        let res = detector.check_known_patterns(&expr);
        assert_eq!(res.map(|(pv, _)| pv), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn known_pattern_ne_self_always_false() {
        let detector = OpaqueDetector::new();
        let expr = OpaqueExpr::Ne(Box::new(var("x")), Box::new(var("x")));
        let res = detector.check_known_patterns(&expr);
        assert_eq!(res.map(|(pv, _)| pv), Some(PredicateValue::AlwaysFalse));
    }

    #[test]
    fn known_pattern_square_ge_zero() {
        let detector = OpaqueDetector::new();
        let expr = OpaqueExpr::Ge(
            Box::new(OpaqueExpr::Square(Box::new(var("x")))),
            Box::new(c(0)),
        );
        let res = detector.check_known_patterns(&expr);
        assert_eq!(res.map(|(pv, _)| pv), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn known_pattern_consec_product_even() {
        let detector = OpaqueDetector::new();
        // (x * (x - 1)) % 2 == 0
        let product = OpaqueExpr::Mul(
            Box::new(var("x")),
            Box::new(OpaqueExpr::Sub(Box::new(var("x")), Box::new(c(1)))),
        );
        let expr = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Mod(Box::new(product), Box::new(c(2)))),
            Box::new(c(0)),
        );
        let res = detector.check_known_patterns(&expr);
        assert_eq!(res.map(|(pv, _)| pv), Some(PredicateValue::AlwaysTrue));
    }

    // ── TruthTableChecker ─────────────────────────────────────────────────────

    #[test]
    fn truth_table_is_always_true_eq_self() {
        let checker = TruthTableChecker::new();
        let expr = OpaqueExpr::Eq(Box::new(var("x")), Box::new(var("x")));
        assert!(checker.is_always_true(&expr));
    }

    #[test]
    fn truth_table_is_always_false_ne_self() {
        let checker = TruthTableChecker::new();
        let expr = OpaqueExpr::Ne(Box::new(var("x")), Box::new(var("x")));
        assert!(checker.is_always_false(&expr));
    }

    #[test]
    fn truth_table_classify_unknown_for_data_dep() {
        let checker = TruthTableChecker::new();
        // x > 0 is not always true or always false
        let expr = OpaqueExpr::Gt(Box::new(var("x")), Box::new(c(0)));
        assert_eq!(checker.classify(&expr), PredicateValue::Unknown);
    }

    #[test]
    fn truth_table_counterexample_false_on_always_true_is_none() {
        let checker = TruthTableChecker::new();
        let expr = OpaqueExpr::Eq(Box::new(var("x")), Box::new(var("x")));
        // There should be no assignment that makes x==x false.
        assert!(checker.counterexample_false(&expr).is_none());
    }

    #[test]
    fn truth_table_counterexample_true_finds_witness() {
        let checker = TruthTableChecker::new();
        // x > 5: there exist values where this is true.
        let expr = OpaqueExpr::Gt(Box::new(var("x")), Box::new(c(5)));
        let ce = checker.counterexample_true(&expr);
        assert!(ce.is_some(), "Expected a witness for x > 5");
        let m = ce.unwrap();
        assert!(m["x"] > 5);
    }

    // ── OpaqueDetector ────────────────────────────────────────────────────────

    #[test]
    fn detector_check_constant_expr_gt() {
        let detector = OpaqueDetector::new();
        // 5 > 3 → AlwaysTrue
        let expr = OpaqueExpr::Gt(Box::new(c(5)), Box::new(c(3)));
        assert_eq!(
            detector.check_constant_expr(&expr),
            Some(PredicateValue::AlwaysTrue)
        );
        // 1 > 3 → AlwaysFalse
        let expr2 = OpaqueExpr::Gt(Box::new(c(1)), Box::new(c(3)));
        assert_eq!(
            detector.check_constant_expr(&expr2),
            Some(PredicateValue::AlwaysFalse)
        );
    }

    #[test]
    fn detector_detects_opaque_in_cfg() {
        let mut cfg = SimpleBranchCfg::new(Address::new(0x1000));
        // Branch at 0x1000: condition `x == x` (always true).
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x1000),
            condition: OpaqueExpr::Eq(Box::new(var("x")), Box::new(var("x"))),
            true_target: Address::new(0x1010),
            false_target: Address::new(0x1020),
        });
        let detector = OpaqueDetector::new();
        let found = detector.detect(&cfg);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, PredicateValue::AlwaysTrue);
        assert_eq!(found[0].dead_target, Some(Address::new(0x1020)));
        assert_eq!(found[0].live_target, Some(Address::new(0x1010)));
    }

    // ── OpaqueEliminator ──────────────────────────────────────────────────────

    #[test]
    fn eliminator_converts_to_unconditional_edge() {
        let mut cfg = SimpleBranchCfg::new(Address::new(0x2000));
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x2000),
            condition: OpaqueExpr::Ne(Box::new(var("y")), Box::new(var("y"))),
            true_target: Address::new(0x2010),
            false_target: Address::new(0x2020),
        });
        let elim = OpaqueEliminator::new();
        let result = elim.eliminate(&mut cfg);

        assert_eq!(result.branches_eliminated, 1);
        // For AlwaysFalse the live target is false_target (0x2020).
        assert_eq!(
            result.always_taken_edges,
            vec![(Address::new(0x2000), Address::new(0x2020))]
        );
        assert_eq!(result.dead_blocks_identified, vec![Address::new(0x2010)]);
        // The branch in the CFG should now be unconditional.
        assert_eq!(cfg.branches[0].true_target, Address::new(0x2020));
        assert_eq!(cfg.branches[0].false_target, Address::new(0x2020));
    }

    #[test]
    fn elimination_result_statistics_correct() {
        let mut cfg = SimpleBranchCfg::new(Address::new(0x3000));
        // Two opaque branches + one real branch.
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x3000),
            condition: OpaqueExpr::Eq(Box::new(var("a")), Box::new(var("a"))),
            true_target: Address::new(0x3010),
            false_target: Address::new(0x3020),
        });
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x3030),
            condition: OpaqueExpr::Gt(Box::new(c(5)), Box::new(c(2))),
            true_target: Address::new(0x3040),
            false_target: Address::new(0x3050),
        });
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x3060),
            condition: OpaqueExpr::Gt(Box::new(var("z")), Box::new(c(100))),
            true_target: Address::new(0x3070),
            false_target: Address::new(0x3080),
        });
        let pass = OpaqueDeobfPass::new();
        let res = pass.run(&mut cfg);

        assert_eq!(res.candidates_found, 2, "Expected 2 opaque candidates");
        assert_eq!(res.eliminated, 2, "Expected 2 eliminations");
        assert_eq!(res.dead_blocks.len(), 2);
        assert_eq!(res.confidence_scores.len(), 2);
    }

    // ── simplify ──────────────────────────────────────────────────────────────

    #[test]
    fn simplify_sub_self_gives_zero() {
        let expr = OpaqueExpr::Sub(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(expr.simplify(), c(0));
    }

    #[test]
    fn simplify_xor_self_gives_zero() {
        let expr = OpaqueExpr::Xor(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(expr.simplify(), c(0));
    }

    #[test]
    fn simplify_constant_folds() {
        let expr = OpaqueExpr::Mul(
            Box::new(OpaqueExpr::Add(Box::new(c(3)), Box::new(c(4)))),
            Box::new(c(2)),
        );
        assert_eq!(expr.simplify(), c(14));
    }

    // ── PredicateValue Display ────────────────────────────────────────────────

    #[test]
    fn predicate_value_display() {
        assert_eq!(PredicateValue::AlwaysTrue.to_string(), "AlwaysTrue");
        assert_eq!(PredicateValue::AlwaysFalse.to_string(), "AlwaysFalse");
        assert_eq!(PredicateValue::Unknown.to_string(), "Unknown");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantPropagator — propagate opaque predicate results through the CFG
// ─────────────────────────────────────────────────────────────────────────────

/// A single constant fact: a variable is always equal to a known value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstFact {
    /// The variable name.
    pub var: String,
    /// The known constant value.
    pub value: i64,
    /// The address at which this fact holds.
    pub at: Address,
}

/// Result of a constant propagation pass over a CFG.
#[derive(Debug, Clone, Default)]
pub struct PropagationResult {
    /// Facts derived from opaque predicates.
    pub facts: Vec<ConstFact>,
    /// Number of expressions simplified by constant substitution.
    pub simplifications: usize,
    /// Branches that became unconditional after propagation.
    pub branches_simplified: usize,
}

/// Propagates constants derived from opaque predicates through a CFG.
///
/// After an always-taken branch (`cond == true`), variables constrained by
/// `cond` are known to be equal to certain values and can be substituted in
/// downstream expressions.
#[derive(Debug, Clone, Default)]
pub struct ConstantPropagator {
    /// Initial set of known facts (e.g., from prior analyses).
    seed_facts: Vec<ConstFact>,
}

impl ConstantPropagator {
    /// Create a new propagator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the propagator with a known fact.
    pub fn add_fact(&mut self, fact: ConstFact) {
        self.seed_facts.push(fact);
    }

    /// Run constant propagation given a list of opaque findings.
    ///
    /// For each `AlwaysTrue` finding `x == K`, we record the fact `x = K` and
    /// count any branch that could be simplified.
    #[must_use]
    pub fn propagate(&self, findings: &[OpaqueBranch]) -> PropagationResult {
        let mut result = PropagationResult::default();
        result.facts.extend(self.seed_facts.iter().cloned());

        for finding in findings {
            if finding.value == PredicateValue::AlwaysTrue {
                // Extract equality facts from `x == K` patterns.
                if let Some(facts) = extract_eq_facts(&finding.predicate, finding.address) {
                    result.simplifications += facts.len();
                    result.facts.extend(facts);
                }
                result.branches_simplified += 1;
            } else if finding.value == PredicateValue::AlwaysFalse {
                result.branches_simplified += 1;
            }
        }
        result
    }
}

fn extract_eq_facts(expr: &OpaqueExpr, at: Address) -> Option<Vec<ConstFact>> {
    if let OpaqueExpr::Eq(lhs, rhs) = expr {
        if let (OpaqueExpr::Var(name), OpaqueExpr::Const(val)) = (lhs.as_ref(), rhs.as_ref()) {
            return Some(vec![ConstFact {
                var: name.clone(),
                value: *val,
                at,
            }]);
        }
        if let (OpaqueExpr::Const(val), OpaqueExpr::Var(name)) = (lhs.as_ref(), rhs.as_ref()) {
            return Some(vec![ConstFact {
                var: name.clone(),
                value: *val,
                at,
            }]);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// MbaOpaqueDetector — Mixed Boolean-Arithmetic opaque predicate detection
// ─────────────────────────────────────────────────────────────────────────────

/// A verified MBA identity pattern (always equal to `result` regardless of inputs).
#[derive(Debug, Clone)]
pub struct MbaIdentity {
    /// Human-readable name of the identity.
    pub name: &'static str,
    /// Expression that should evaluate to `value` for all inputs.
    pub value: i64,
}

/// Detect Mixed Boolean-Arithmetic (MBA) based opaque predicates.
///
/// MBA predicates use identities like `(x & ~y) + (x | y) == x + y` to
/// create apparently complex conditions that are structurally constant.
#[derive(Debug, Clone, Default)]
pub struct MbaOpaqueDetector {
    /// Sample domain for verification (set of integer test values).
    pub sample_domain: Vec<i64>,
}

impl MbaOpaqueDetector {
    /// Create a new detector with a default sample domain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sample_domain: vec![-3, -2, -1, 0, 1, 2, 3, 127, -128, 255, i64::MAX, i64::MIN],
        }
    }

    /// Create a detector with a custom sample domain.
    #[must_use]
    pub const fn with_domain(domain: Vec<i64>) -> Self {
        Self {
            sample_domain: domain,
        }
    }

    /// Check if `expr` is an MBA identity (always evaluates to the same value).
    ///
    /// Returns `Some(value)` if the expression is constant over the sample domain,
    /// `None` otherwise.
    #[must_use]
    pub fn check_identity(&self, expr: &OpaqueExpr) -> Option<i64> {
        let vars = expr.vars();
        if vars.is_empty() {
            return expr.eval(&HashMap::new());
        }

        // Try all combinations from the sample domain using a full Cartesian
        // product over every distinct variable. This avoids the bug where extra
        // variables (neither "x" nor "y") were aliased to the x loop variable,
        // which could hide non-constant expressions in 3+-variable expressions.
        let vars_vec: Vec<String> = vars.iter().cloned().collect();
        let n = vars_vec.len();
        let domain_len = self.sample_domain.len();
        // Total iterations = domain_len ^ n — cap to prevent usize overflow and
        // CPU/memory exhaustion when an attacker-controlled expression has many
        // distinct variable names.
        const MAX_MBA_ITERATIONS: usize = 65_536;
        let total: usize = domain_len
            .checked_pow(n as u32)
            .unwrap_or(usize::MAX)
            .min(MAX_MBA_ITERATIONS);
        let mut constant_val: Option<i64> = None;
        for idx in 0..total {
            let mut m: HashMap<String, i64> = HashMap::new();
            let mut remaining = idx;
            for v in &vars_vec {
                let slot = remaining % domain_len;
                remaining /= domain_len;
                m.insert(v.clone(), self.sample_domain[slot]);
            }
            let val = expr.eval(&m)?;
            if let Some(cv) = constant_val {
                if cv != val {
                    return None; // not constant
                }
            } else {
                constant_val = Some(val);
            }
        }
        constant_val
    }

    /// Check if `expr` corresponds to a known MBA identity pattern.
    ///
    /// Returns `Some(identity)` if the expression always evaluates to a constant.
    /// Uses `check_identity` for full verification.
    #[must_use]
    pub fn check_known_mba_patterns(&self, expr: &OpaqueExpr) -> Option<MbaIdentity> {
        // First try cheap structural pattern matching.
        if let Some(id) = check_structural_mba_pattern(expr) {
            return Some(id);
        }
        // Fall back to exhaustive evaluation.
        let val = self.check_identity(expr)?;
        Some(MbaIdentity {
            name: "computed-identity",
            value: val,
        })
    }
}

/// Structural pattern matching for common MBA patterns (no variable capture required).
fn check_structural_mba_pattern(expr: &OpaqueExpr) -> Option<MbaIdentity> {
    use OpaqueExpr::{And, Const, Eq, Mod, Mul, Not, Or, Var, Xor};

    fn x() -> OpaqueExpr {
        Var("x".to_string())
    }
    fn y() -> OpaqueExpr {
        Var("y".to_string())
    }

    // x XOR 0 == x
    let pat1 = Eq(
        Box::new(Xor(Box::new(x()), Box::new(Const(0)))),
        Box::new(x()),
    );
    if expr == &pat1 {
        return Some(MbaIdentity {
            name: "x_xor_0_eq_x",
            value: 1,
        });
    }
    // x | 0 == x
    let pat2 = Eq(
        Box::new(Or(Box::new(x()), Box::new(Const(0)))),
        Box::new(x()),
    );
    if expr == &pat2 {
        return Some(MbaIdentity {
            name: "x_or_0_eq_x",
            value: 1,
        });
    }
    // x & x == x
    let pat3 = Eq(Box::new(And(Box::new(x()), Box::new(x()))), Box::new(x()));
    if expr == &pat3 {
        return Some(MbaIdentity {
            name: "x_and_x_eq_x",
            value: 1,
        });
    }
    // x * 1 == x
    let pat4 = Eq(
        Box::new(Mul(Box::new(x()), Box::new(Const(1)))),
        Box::new(x()),
    );
    if expr == &pat4 {
        return Some(MbaIdentity {
            name: "x_mul_1_eq_x",
            value: 1,
        });
    }
    // x & 0 == 0
    let pat5 = Eq(
        Box::new(And(Box::new(x()), Box::new(Const(0)))),
        Box::new(Const(0)),
    );
    if expr == &pat5 {
        return Some(MbaIdentity {
            name: "x_and_0_eq_0",
            value: 1,
        });
    }
    // x.is_multiple_of(1)
    let pat6 = Eq(
        Box::new(Mod(Box::new(x()), Box::new(Const(1)))),
        Box::new(Const(0)),
    );
    if expr == &pat6 {
        return Some(MbaIdentity {
            name: "x_mod_1_eq_0",
            value: 1,
        });
    }
    // NOT(NOT(x)) == x
    let pat7 = Eq(Box::new(Not(Box::new(Not(Box::new(x()))))), Box::new(x()));
    if expr == &pat7 {
        return Some(MbaIdentity {
            name: "double_not_eq_x",
            value: 1,
        });
    }
    // (x XOR x) == 0
    let pat8 = Eq(
        Box::new(Xor(Box::new(x()), Box::new(x()))),
        Box::new(Const(0)),
    );
    if expr == &pat8 {
        return Some(MbaIdentity {
            name: "x_xor_x_eq_0",
            value: 1,
        });
    }
    // (x + y) - y == x
    let pat9 = Eq(
        Box::new(OpaqueExpr::Sub(
            Box::new(OpaqueExpr::Add(Box::new(x()), Box::new(y()))),
            Box::new(y()),
        )),
        Box::new(x()),
    );
    if expr == &pat9 {
        return Some(MbaIdentity {
            name: "x_plus_y_minus_y_eq_x",
            value: 1,
        });
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// StatisticalOpaqueDetector — branch frequency analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A branch execution frequency record collected from dynamic analysis.
#[derive(Debug, Clone, Copy)]
pub struct BranchFrequency {
    /// The address of the branch instruction.
    pub address: Address,
    /// Number of times the true (taken) edge was followed.
    pub true_count: u64,
    /// Number of times the false (not-taken) edge was followed.
    pub false_count: u64,
}

impl BranchFrequency {
    /// Create a new frequency record.
    #[must_use]
    pub const fn new(address: Address, true_count: u64, false_count: u64) -> Self {
        Self {
            address,
            true_count,
            false_count,
        }
    }

    /// Total number of times this branch was executed.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.true_count + self.false_count
    }

    /// True-direction fraction (0.0–1.0).
    #[must_use]
    pub fn true_fraction(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        self.true_count as f64 / self.total() as f64
    }

    /// False-direction fraction (0.0–1.0).
    #[must_use]
    pub fn false_fraction(&self) -> f64 {
        1.0 - self.true_fraction()
    }

    /// Whether this branch is suspicious (always/never taken in this run).
    #[must_use]
    pub const fn is_opaque_suspicious(&self, min_samples: u64) -> bool {
        self.total() >= min_samples && (self.true_count == 0 || self.false_count == 0)
    }

    /// Opaque type hypothesis based on frequency.
    #[must_use]
    pub const fn hypothesis(&self) -> PredicateValue {
        if self.total() == 0 {
            return PredicateValue::Unknown;
        }
        if self.true_count == 0 {
            PredicateValue::AlwaysFalse
        } else if self.false_count == 0 {
            PredicateValue::AlwaysTrue
        } else {
            PredicateValue::Unknown
        }
    }
}

/// Statistical opaque predicate detector based on dynamic branch frequency.
#[derive(Debug, Clone, Default)]
pub struct StatisticalOpaqueDetector {
    /// Minimum number of samples required to raise a suspicion.
    pub min_samples: u64,
}

impl StatisticalOpaqueDetector {
    /// Create a new detector requiring at least `min_samples` executions.
    #[must_use]
    pub const fn new(min_samples: u64) -> Self {
        Self { min_samples }
    }

    /// Classify a list of branch frequencies and return suspected opaques.
    #[must_use]
    pub fn classify(&self, frequencies: &[BranchFrequency]) -> Vec<(Address, PredicateValue)> {
        frequencies
            .iter()
            .filter(|f| f.is_opaque_suspicious(self.min_samples))
            .map(|f| (f.address, f.hypothesis()))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicateDatabase — stores and queries known patterns
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the opaque predicate database.
#[derive(Debug, Clone)]
pub struct OpaqueDbEntry {
    /// Unique identifier.
    pub id: u32,
    /// Source / category of the pattern.
    pub category: OpaqueCategory,
    /// Predicted value.
    pub value: PredicateValue,
    /// Brief description.
    pub description: &'static str,
    /// Confidence level (0–100).
    pub confidence: u8,
}

/// Category of an opaque predicate pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueCategory {
    /// Mathematical identity (number theory).
    Mathematical,
    /// Mixed Boolean-Arithmetic.
    Mba,
    /// Aliasing / pointer comparison.
    Aliasing,
    /// Environment-based (time, process ID, etc.).
    Environmental,
    /// OLLVM-specific pattern.
    Ollvm,
    /// Dead computation.
    DeadComputation,
}

impl fmt::Display for OpaqueCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mathematical => write!(f, "mathematical"),
            Self::Mba => write!(f, "mba"),
            Self::Aliasing => write!(f, "aliasing"),
            Self::Environmental => write!(f, "environmental"),
            Self::Ollvm => write!(f, "ollvm"),
            Self::DeadComputation => write!(f, "dead-computation"),
        }
    }
}

/// A searchable database of known opaque predicate patterns.
#[derive(Debug, Clone, Default)]
pub struct OpaquePredicateDatabase {
    entries: Vec<OpaqueDbEntry>,
    next_id: u32,
}

impl OpaquePredicateDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a database pre-populated with the built-in patterns.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut db = Self::new();
        db.add_builtin_patterns();
        db
    }

    /// Add a new entry and return its assigned ID.
    pub fn add(
        &mut self,
        category: OpaqueCategory,
        value: PredicateValue,
        description: &'static str,
        confidence: u8,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(OpaqueDbEntry {
            id,
            category,
            value,
            description,
            confidence,
        });
        id
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Query entries by category.
    #[must_use]
    pub fn by_category(&self, cat: OpaqueCategory) -> Vec<&OpaqueDbEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Query entries by predicted value.
    #[must_use]
    pub fn by_value(&self, value: PredicateValue) -> Vec<&OpaqueDbEntry> {
        self.entries.iter().filter(|e| e.value == value).collect()
    }

    /// Query entries with confidence above threshold.
    #[must_use]
    pub fn high_confidence(&self, threshold: u8) -> Vec<&OpaqueDbEntry> {
        self.entries
            .iter()
            .filter(|e| e.confidence >= threshold)
            .collect()
    }

    fn add_builtin_patterns(&mut self) {
        // Mathematical
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x*x >= 0 (square is non-negative)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x*(x+1) % 2 == 0 (consecutive product even)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x*(x-1) % 2 == 0 (consecutive product even)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "|x| >= 0 (absolute value >= 0)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x == x (trivial identity)",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysFalse,
            "x != x (trivial contradiction)",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x XOR x == 0",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x - x == 0",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "NOT(NOT(x)) == x",
            99,
        );
        // MBA
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "(x & ~y) + (x | y) == x + (x & ~y ^ (x | y))",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "(x XOR y) + 2*(x AND y) == x + y",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "(x | y) - (x & y) == x XOR y",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "x + y - (x AND y) - (x XOR y) / 2... identity",
            85,
        );
        // Environment
        self.add(
            OpaqueCategory::Environmental,
            PredicateValue::AlwaysTrue,
            "time() > 0 (in normal execution)",
            70,
        );
        self.add(
            OpaqueCategory::Environmental,
            PredicateValue::AlwaysTrue,
            "getpid() != 0 (always a valid PID)",
            80,
        );
        // Aliasing
        self.add(
            OpaqueCategory::Aliasing,
            PredicateValue::AlwaysFalse,
            "two fresh stack allocations never alias",
            75,
        );
        // Dead computation
        self.add(
            OpaqueCategory::DeadComputation,
            PredicateValue::AlwaysTrue,
            "large dead loop result used as opaque",
            65,
        );
        // OLLVM
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysTrue,
            "OLLVM: (y ^ (y - 1)) == 2*y - 1 (power of 2)",
            85,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysTrue,
            "OLLVM: state var never equals bogus value",
            90,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysFalse,
            "OLLVM: reachability of dead dispatcher case",
            95,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysTrue,
            "OLLVM: ((x & 1) ^ (x >> 1) & 1) style parity",
            80,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysTrue,
            "OLLVM: bogus block guarded by impossible cond",
            90,
        );
        // Additional hash-based
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x & 0xFF <= 255 (byte fits in u8)",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysFalse,
            "x & 0xFF > 255 (impossible byte value)",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "((x*x + x) & 1) == 0 (x^2+x always even)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x + (-x) == 0",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x | ~x == -1 (all bits set)",
            99,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysFalse,
            "x & ~x == 0... → false branch",
            99,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: (x + y) ^ (x ^ y) == 2*(x & y)",
            85,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: (x - y) + (x ^ y) == 2*(x & ~y)",
            85,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: (x ^ y) ^ y == x",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: (x & y) | (x & ~y) == x",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: ~(x & y) == ~x | ~y (DeMorgan)",
            95,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: ~(x | y) == ~x & ~y (DeMorgan)",
            95,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "Fermat: (a^2 + b^2 != c^2 for small ints)",
            60,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x * 0 == 0",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "0 / x == 0 (for x != 0)",
            90,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: count_ones(x | ~x) == 64",
            90,
        );
        self.add(
            OpaqueCategory::Environmental,
            PredicateValue::AlwaysTrue,
            "sizeof(ptr) > 0",
            100,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysTrue,
            "OLLVM: CRC of known constant equals expected",
            80,
        );
        self.add(
            OpaqueCategory::Aliasing,
            PredicateValue::AlwaysFalse,
            "stack_var != heap_var (different regions)",
            70,
        );
        self.add(
            OpaqueCategory::DeadComputation,
            PredicateValue::AlwaysFalse,
            "dead loop: loop executes 0 times → false guard",
            60,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x OR x == x",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x AND x == x",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x + 0 == x",
            100,
        );
        self.add(
            OpaqueCategory::Mathematical,
            PredicateValue::AlwaysTrue,
            "x - 0 == x",
            100,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: ~(~x) == x (double complement)",
            99,
        );
        self.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysFalse,
            "OLLVM: control flow token can never reach dead case",
            88,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: x - (x & y) == x & ~y",
            88,
        );
        self.add(
            OpaqueCategory::Mba,
            PredicateValue::AlwaysTrue,
            "MBA: (x | y) + (x & y) == x + y",
            88,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicateReport — comprehensive report for a deobfuscation run
// ─────────────────────────────────────────────────────────────────────────────

/// A finding from the opaque predicate analysis, augmented with context.
#[derive(Debug, Clone)]
pub struct DetailedFinding {
    /// The underlying finding.
    pub finding: OpaqueBranch,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Suggested fix description.
    pub suggested_fix: String,
    /// Whether the finding was statistically confirmed.
    pub statistically_confirmed: bool,
}

impl DetailedFinding {
    /// Create a detailed finding from a base finding.
    #[must_use]
    pub fn from_finding(finding: OpaqueBranch) -> Self {
        let confidence = match finding.kind {
            OpaquePredicateKind::TrivialIdentity => 1.0,
            OpaquePredicateKind::ConstantExpr => 0.99,
            OpaquePredicateKind::MathematicalInvariant => 0.95,
            OpaquePredicateKind::KnownPattern => 0.90,
            OpaquePredicateKind::Symbolic => 0.85,
            OpaquePredicateKind::DeadBranch => 0.70,
        };
        let fix = match finding.value {
            PredicateValue::AlwaysTrue => format!(
                "Replace conditional branch at 0x{:x} with unconditional jump to 0x{:x}",
                finding.address.0,
                finding.live_target.map_or(0, |a| a.0)
            ),
            PredicateValue::AlwaysFalse => format!(
                "Remove branch at 0x{:x}; fall through to 0x{:x}",
                finding.address.0,
                finding.live_target.map_or(0, |a| a.0)
            ),
            PredicateValue::Unknown => format!("No fix available at 0x{:x}", finding.address.0),
        };
        Self {
            finding,
            confidence,
            suggested_fix: fix,
            statistically_confirmed: false,
        }
    }

    /// Mark as statistically confirmed.
    #[must_use]
    pub fn with_statistical_confirmation(mut self) -> Self {
        self.statistically_confirmed = true;
        self.confidence = (self.confidence + 0.1).min(1.0);
        self
    }
}

/// Comprehensive report of all opaque predicates found in a binary.
#[derive(Debug, Clone, Default)]
pub struct OpaquePredicateReport {
    /// All detailed findings.
    pub findings: Vec<DetailedFinding>,
    /// Number of branches fully eliminated.
    pub branches_eliminated: usize,
    /// Number of dead blocks identified.
    pub dead_blocks: usize,
    /// Average confidence score.
    pub average_confidence: f64,
}

impl OpaquePredicateReport {
    /// Build a report from detailed findings and an elimination result.
    #[must_use]
    pub fn new(findings: Vec<DetailedFinding>, elim_result: &EliminationResult) -> Self {
        let avg = if findings.is_empty() {
            0.0
        } else {
            findings.iter().map(|f| f.confidence).sum::<f64>() / findings.len() as f64
        };
        Self {
            findings,
            branches_eliminated: elim_result.branches_eliminated,
            dead_blocks: elim_result.dead_blocks_identified.len(),
            average_confidence: avg,
        }
    }

    /// Total number of findings.
    #[must_use]
    pub const fn total_findings(&self) -> usize {
        self.findings.len()
    }

    /// High-confidence findings (>= 0.9).
    #[must_use]
    pub fn high_confidence_findings(&self) -> Vec<&DetailedFinding> {
        self.findings
            .iter()
            .filter(|f| f.confidence >= 0.9)
            .collect()
    }

    /// Findings for always-true predicates.
    #[must_use]
    pub fn always_true_findings(&self) -> Vec<&DetailedFinding> {
        self.findings
            .iter()
            .filter(|f| f.finding.value == PredicateValue::AlwaysTrue)
            .collect()
    }

    /// Findings for always-false predicates.
    #[must_use]
    pub fn always_false_findings(&self) -> Vec<&DetailedFinding> {
        self.findings
            .iter()
            .filter(|f| f.finding.value == PredicateValue::AlwaysFalse)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchSimplifier — rewrite branches after opaque predicate elimination
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified branch outcome after opaque predicate detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchOutcome {
    /// The branch was determined to always be taken.
    AlwaysTaken,
    /// The branch was determined to never be taken.
    NeverTaken,
    /// The branch outcome is data-dependent.
    DataDependent,
}

/// Simplifies a CFG by replacing opaque conditional branches with unconditional
/// jumps and removing dead code.
#[derive(Debug, Clone, Default)]
pub struct BranchSimplifier {
    /// Cache of address → branch outcome from prior analysis.
    outcomes: HashMap<Address, BranchOutcome>,
}

impl BranchSimplifier {
    /// Create a new simplifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a branch outcome.
    pub fn set_outcome(&mut self, addr: Address, outcome: BranchOutcome) {
        self.outcomes.insert(addr, outcome);
    }

    /// Get the outcome for a branch, if known.
    #[must_use]
    pub fn get_outcome(&self, addr: Address) -> Option<BranchOutcome> {
        self.outcomes.get(&addr).copied()
    }

    /// Load outcomes from an `EliminationResult`.
    pub fn load_from_elimination(&mut self, result: &EliminationResult) {
        for &(addr, _) in &result.always_taken_edges {
            self.outcomes.insert(addr, BranchOutcome::AlwaysTaken);
        }
        for &addr in &result.dead_blocks_identified {
            // Mark dead block entries as dead.
            self.outcomes.insert(addr, BranchOutcome::NeverTaken);
        }
    }

    /// Return all addresses for which outcomes are known.
    #[must_use]
    pub fn known_addresses(&self) -> Vec<Address> {
        self.outcomes.keys().copied().collect()
    }

    /// Number of registered outcomes.
    #[must_use]
    pub fn count(&self) -> usize {
        self.outcomes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }
    fn v(n: &str) -> OpaqueExpr {
        OpaqueExpr::Var(n.to_string())
    }
    fn c(n: i64) -> OpaqueExpr {
        OpaqueExpr::Const(n)
    }

    // ── ConstantPropagator ────────────────────────────────────────────────────

    #[test]
    fn propagator_extracts_eq_fact() {
        let mut propagator = ConstantPropagator::new();
        propagator.add_fact(ConstFact {
            var: "x".to_string(),
            value: 42,
            at: addr(0),
        });

        let finding = OpaqueBranch {
            address: addr(0x1000),
            predicate: OpaqueExpr::Eq(Box::new(v("y")), Box::new(c(7))),
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::KnownPattern,
            live_target: Some(addr(0x1010)),
            dead_target: Some(addr(0x1020)),
            confidence: 0.9,
        };
        let result = propagator.propagate(&[finding]);
        assert_eq!(result.branches_simplified, 1);
        // seed fact plus the new fact extracted from y==7
        assert!(!result.facts.is_empty());
    }

    #[test]
    fn propagator_no_facts_for_unknown() {
        let propagator = ConstantPropagator::new();
        let finding = OpaqueBranch {
            address: addr(0x2000),
            predicate: OpaqueExpr::Gt(Box::new(v("x")), Box::new(c(0))),
            value: PredicateValue::Unknown,
            kind: OpaquePredicateKind::Symbolic,
            live_target: None,
            dead_target: None,
            confidence: 0.0,
        };
        let result = propagator.propagate(&[finding]);
        assert_eq!(result.branches_simplified, 0);
    }

    // ── MbaOpaqueDetector ────────────────────────────────────────────────────

    #[test]
    fn mba_x_xor_zero_is_identity() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Xor(Box::new(v("x")), Box::new(c(0)))),
            Box::new(v("x")),
        );
        let result = det.check_identity(&expr);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn mba_x_plus_neg_x_is_zero() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Add(
            Box::new(v("x")),
            Box::new(OpaqueExpr::Neg(Box::new(v("x")))),
        );
        let result = det.check_identity(&expr);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn mba_data_dependent_returns_none() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Add(Box::new(v("x")), Box::new(v("y")));
        assert!(det.check_identity(&expr).is_none());
    }

    #[test]
    fn mba_const_expr_detected() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Mul(Box::new(c(6)), Box::new(c(7)));
        assert_eq!(det.check_identity(&expr), Some(42));
    }

    // ── StatisticalOpaqueDetector ─────────────────────────────────────────────

    #[test]
    fn statistical_always_true_detected() {
        let det = StatisticalOpaqueDetector::new(10);
        let freqs = vec![
            BranchFrequency::new(addr(0x1000), 1000, 0), // always taken
            BranchFrequency::new(addr(0x2000), 500, 500), // genuine branch
        ];
        let suspected = det.classify(&freqs);
        assert_eq!(suspected.len(), 1);
        assert_eq!(suspected[0].0, addr(0x1000));
        assert_eq!(suspected[0].1, PredicateValue::AlwaysTrue);
    }

    #[test]
    fn statistical_always_false_detected() {
        let det = StatisticalOpaqueDetector::new(5);
        let freqs = vec![BranchFrequency::new(addr(0x3000), 0, 200)];
        let suspected = det.classify(&freqs);
        assert_eq!(suspected.len(), 1);
        assert_eq!(suspected[0].1, PredicateValue::AlwaysFalse);
    }

    #[test]
    fn statistical_below_min_samples_ignored() {
        let det = StatisticalOpaqueDetector::new(100);
        let freqs = vec![BranchFrequency::new(addr(0x4000), 5, 0)]; // only 5 samples
        assert!(det.classify(&freqs).is_empty());
    }

    #[test]
    fn branch_frequency_fractions() {
        let f = BranchFrequency::new(addr(0), 3, 1);
        assert!((f.true_fraction() - 0.75).abs() < 1e-9);
        assert!((f.false_fraction() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn branch_frequency_total_zero() {
        let f = BranchFrequency::new(addr(0), 0, 0);
        assert_eq!(f.true_fraction(), 0.0);
        assert_eq!(f.hypothesis(), PredicateValue::Unknown);
    }

    // ── OpaquePredicateDatabase ───────────────────────────────────────────────

    #[test]
    fn database_builtins_exceed_50() {
        let db = OpaquePredicateDatabase::with_builtins();
        assert!(db.len() >= 50, "Expected >= 50 patterns, got {}", db.len());
    }

    #[test]
    fn database_by_category() {
        let db = OpaquePredicateDatabase::with_builtins();
        let math = db.by_category(OpaqueCategory::Mathematical);
        assert!(!math.is_empty());
        let mba = db.by_category(OpaqueCategory::Mba);
        assert!(!mba.is_empty());
    }

    #[test]
    fn database_high_confidence() {
        let db = OpaquePredicateDatabase::with_builtins();
        let high = db.high_confidence(95);
        assert!(!high.is_empty());
        for e in &high {
            assert!(e.confidence >= 95);
        }
    }

    #[test]
    fn database_by_value_always_true() {
        let db = OpaquePredicateDatabase::with_builtins();
        let always_true = db.by_value(PredicateValue::AlwaysTrue);
        assert!(!always_true.is_empty());
    }

    #[test]
    fn database_add_custom_entry() {
        let mut db = OpaquePredicateDatabase::new();
        let id = db.add(
            OpaqueCategory::Ollvm,
            PredicateValue::AlwaysFalse,
            "custom",
            80,
        );
        assert_eq!(db.len(), 1);
        assert_eq!(db.entries[0].id, id);
    }

    // ── DetailedFinding / OpaquePredicateReport ───────────────────────────────

    #[test]
    fn detailed_finding_confidence_trivial_identity() {
        let f = OpaqueBranch {
            address: addr(0x1000),
            predicate: OpaqueExpr::Eq(Box::new(v("x")), Box::new(v("x"))),
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
            live_target: Some(addr(0x1010)),
            dead_target: Some(addr(0x1020)),
            confidence: 1.0,
        };
        let df = DetailedFinding::from_finding(f);
        assert_eq!(df.confidence, 1.0);
    }

    #[test]
    fn detailed_finding_confidence_increases_with_statistical_confirmation() {
        let f = OpaqueBranch {
            address: addr(0x2000),
            predicate: OpaqueExpr::Const(1),
            value: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::Symbolic,
            live_target: None,
            dead_target: None,
            confidence: 0.8,
        };
        let df = DetailedFinding::from_finding(f).with_statistical_confirmation();
        assert!(df.confidence > 0.85);
        assert!(df.statistically_confirmed);
    }

    #[test]
    fn report_total_findings_and_categories() {
        let mut cfg = SimpleBranchCfg::new(addr(0));
        cfg.add_branch(SimpleBranch {
            address: addr(0x1000),
            condition: OpaqueExpr::Eq(Box::new(v("x")), Box::new(v("x"))),
            true_target: addr(0x1010),
            false_target: addr(0x1020),
        });
        let detector = OpaqueDetector::new();
        let findings: Vec<_> = detector
            .detect(&cfg)
            .into_iter()
            .map(DetailedFinding::from_finding)
            .collect();

        let elim_result = EliminationResult {
            branches_eliminated: 0,
            dead_blocks_identified: vec![],
            always_taken_edges: vec![],
            errors: vec![],
        };
        let report = OpaquePredicateReport::new(findings, &elim_result);
        assert_eq!(report.total_findings(), 1);
        assert_eq!(report.always_true_findings().len(), 1);
        assert!(report.always_false_findings().is_empty());
    }

    // ── BranchSimplifier ─────────────────────────────────────────────────────

    #[test]
    fn branch_simplifier_set_get() {
        let mut simplifier = BranchSimplifier::new();
        simplifier.set_outcome(addr(0x1000), BranchOutcome::AlwaysTaken);
        assert_eq!(
            simplifier.get_outcome(addr(0x1000)),
            Some(BranchOutcome::AlwaysTaken)
        );
        assert!(simplifier.get_outcome(addr(0x2000)).is_none());
    }

    #[test]
    fn branch_simplifier_load_from_elimination() {
        let elim_result = EliminationResult {
            branches_eliminated: 2,
            always_taken_edges: vec![(addr(0x1000), addr(0x1010)), (addr(0x2000), addr(0x2010))],
            dead_blocks_identified: vec![addr(0x1020), addr(0x2020)],
            errors: vec![],
        };
        let mut simplifier = BranchSimplifier::new();
        simplifier.load_from_elimination(&elim_result);
        assert_eq!(simplifier.count(), 4);
    }

    #[test]
    fn branch_simplifier_known_addresses() {
        let mut simplifier = BranchSimplifier::new();
        simplifier.set_outcome(addr(0xABC), BranchOutcome::NeverTaken);
        simplifier.set_outcome(addr(0xDEF), BranchOutcome::DataDependent);
        let addrs = simplifier.known_addresses();
        assert_eq!(addrs.len(), 2);
    }

    // ── OpaqueCategory Display ────────────────────────────────────────────────

    #[test]
    fn opaque_category_display() {
        assert_eq!(OpaqueCategory::Mathematical.to_string(), "mathematical");
        assert_eq!(OpaqueCategory::Mba.to_string(), "mba");
        assert_eq!(OpaqueCategory::Ollvm.to_string(), "ollvm");
    }

    // ── BranchOutcome ─────────────────────────────────────────────────────────

    #[test]
    fn branch_outcome_equality() {
        assert_eq!(BranchOutcome::AlwaysTaken, BranchOutcome::AlwaysTaken);
        assert_ne!(BranchOutcome::AlwaysTaken, BranchOutcome::NeverTaken);
    }

    // ── MbaOpaqueDetector additional patterns ─────────────────────────────────

    #[test]
    fn mba_known_pattern_xor_x_x_is_zero() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Xor(Box::new(v("x")), Box::new(v("x")));
        assert_eq!(det.check_identity(&expr), Some(0));
    }

    #[test]
    fn mba_x_and_not_x_is_zero() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::And(
            Box::new(v("x")),
            Box::new(OpaqueExpr::Not(Box::new(v("x")))),
        );
        // x & ~x == 0 for all x.
        assert_eq!(det.check_identity(&expr), Some(0));
    }

    #[test]
    fn mba_check_known_mba_pattern_double_not() {
        let det = MbaOpaqueDetector::new();
        let expr = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Not(Box::new(OpaqueExpr::Not(Box::new(v("x")))))),
            Box::new(v("x")),
        );
        let result = det.check_known_mba_patterns(&expr);
        assert!(result.is_some(), "double NOT should match a known pattern");
    }

    // ── ConstantPropagator additional ─────────────────────────────────────────

    #[test]
    fn propagator_handles_always_false_branch() {
        let propagator = ConstantPropagator::new();
        let finding = OpaqueBranch {
            address: addr(0x5000),
            predicate: OpaqueExpr::Const(0),
            value: PredicateValue::AlwaysFalse,
            kind: OpaquePredicateKind::ConstantExpr,
            live_target: Some(addr(0x5020)),
            dead_target: Some(addr(0x5010)),
            confidence: 0.99,
        };
        let result = propagator.propagate(&[finding]);
        assert_eq!(result.branches_simplified, 1);
    }
}
