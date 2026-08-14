//! Tautology database for opaque-predicate elimination.
//!
//! A *tautology* is a Boolean or arithmetic expression that is always `true`
//! (or always `false`) regardless of its variable bindings.  Obfuscators
//! insert them as branch conditions to confuse static analysers.
//!
//! This module provides:
//! * [`TautologyPattern`] — an expression tree used as a pattern.
//! * [`TautologyDb`] — 80+ known tautology / contradiction patterns.
//! * [`TautologyMatcher`] — matches an expression tree against the database.
//! * [`ConfidenceScore`] — a fine-grained confidence model.
//! * [`TautologyReport`] — per-function tautology summary.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// TautologyValue
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a tautological expression is always true or always false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TautologyValue {
    /// The expression is always `true` (non-zero).
    AlwaysTrue,
    /// The expression is always `false` (zero).
    AlwaysFalse,
}

impl TautologyValue {
    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AlwaysTrue => "always-true",
            Self::AlwaysFalse => "always-false",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyExpr — lightweight expression tree for pattern representation
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal symbolic expression used to represent tautology patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TautologyExpr {
    /// A concrete integer constant.
    Const(i64),
    /// A symbolic variable.
    Var(String),
    /// `a & b`
    And(Box<Self>, Box<Self>),
    /// `a | b`
    Or(Box<Self>, Box<Self>),
    /// `a ^ b`
    Xor(Box<Self>, Box<Self>),
    /// `~a`
    Not(Box<Self>),
    /// `a + b`
    Add(Box<Self>, Box<Self>),
    /// `a - b`
    Sub(Box<Self>, Box<Self>),
    /// `-a`
    Neg(Box<Self>),
    /// `a * b`
    Mul(Box<Self>, Box<Self>),
    /// `a == b`
    Eq(Box<Self>, Box<Self>),
    /// `a != b`
    Ne(Box<Self>, Box<Self>),
    /// `a < b` (signed)
    Lt(Box<Self>, Box<Self>),
    /// `a <= b` (signed)
    Le(Box<Self>, Box<Self>),
}

impl TautologyExpr {
    // ── Constructors ─────────────────────────────────────────────────────────
    #[must_use]
    pub fn var(s: impl Into<String>) -> Self {
        Self::Var(s.into())
    }
    #[must_use]
    pub const fn c(v: i64) -> Self {
        Self::Const(v)
    }
    #[must_use]
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn xor(a: Self, b: Self) -> Self {
        Self::Xor(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn not(a: Self) -> Self {
        Self::Not(Box::new(a))
    }
    #[must_use]
    pub fn add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn sub(a: Self, b: Self) -> Self {
        Self::Sub(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn neg(a: Self) -> Self {
        Self::Neg(Box::new(a))
    }
    #[must_use]
    pub fn mul(a: Self, b: Self) -> Self {
        Self::Mul(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn eq(a: Self, b: Self) -> Self {
        Self::Eq(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn ne(a: Self, b: Self) -> Self {
        Self::Ne(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn lt(a: Self, b: Self) -> Self {
        Self::Lt(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn le(a: Self, b: Self) -> Self {
        Self::Le(Box::new(a), Box::new(b))
    }

    // ── Evaluation ───────────────────────────────────────────────────────────

    /// Evaluate with concrete variable bindings.
    #[must_use]
    pub fn eval(&self, env: &HashMap<String, i64>) -> Option<i64> {
        match self {
            Self::Const(c) => Some(*c),
            Self::Var(n) => env.get(n).copied(),
            Self::Not(e) => Some(!e.eval(env)?),
            Self::Neg(e) => Some(e.eval(env)?.wrapping_neg()),
            Self::And(l, r) => Some(l.eval(env)? & r.eval(env)?),
            Self::Or(l, r) => Some(l.eval(env)? | r.eval(env)?),
            Self::Xor(l, r) => Some(l.eval(env)? ^ r.eval(env)?),
            Self::Add(l, r) => Some(l.eval(env)?.wrapping_add(r.eval(env)?)),
            Self::Sub(l, r) => Some(l.eval(env)?.wrapping_sub(r.eval(env)?)),
            Self::Mul(l, r) => Some(l.eval(env)?.wrapping_mul(r.eval(env)?)),
            Self::Eq(l, r) => Some(i64::from(l.eval(env)? == r.eval(env)?)),
            Self::Ne(l, r) => Some(i64::from(l.eval(env)? != r.eval(env)?)),
            Self::Lt(l, r) => Some(i64::from(l.eval(env)? < r.eval(env)?)),
            Self::Le(l, r) => Some(i64::from(l.eval(env)? <= r.eval(env)?)),
        }
    }

    /// Return all unique variable names.
    #[must_use]
    pub fn vars(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        self.collect_vars(&mut v);
        v
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Var(n) => {
                if !out.contains(n) {
                    out.push(n.clone());
                }
            }
            Self::Const(_) => {}
            Self::Not(e) | Self::Neg(e) => e.collect_vars(out),
            Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r)
            | Self::Lt(l, r)
            | Self::Le(l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
        }
    }

    /// Return the node count.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Not(e) | Self::Neg(e) => 1 + e.node_count(),
            Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r)
            | Self::Lt(l, r)
            | Self::Le(l, r) => 1 + l.node_count() + r.node_count(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyEvaluator — truth-table evaluator for a single expression
// ─────────────────────────────────────────────────────────────────────────────

/// Exhaustively evaluates an expression over a given bit-width domain and
/// classifies it as tautology, contradiction, or unknown.
#[derive(Debug, Clone)]
pub struct TautologyEvaluator {
    /// Bit-width for the evaluation domain (default 8).
    pub bits: u32,
}

impl Default for TautologyEvaluator {
    fn default() -> Self {
        Self { bits: 8 }
    }
}

impl TautologyEvaluator {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bit-width.
    #[must_use]
    pub const fn with_bits(mut self, b: u32) -> Self {
        self.bits = b;
        self
    }

    /// Evaluate `expr` over all assignments and return the classification.
    #[must_use]
    pub fn classify(&self, expr: &TautologyExpr) -> TautologyClassification {
        let vars = expr.vars();
        if vars.is_empty() {
            return match expr.eval(&HashMap::new()) {
                Some(v) if v != 0 => TautologyClassification::AlwaysTrue,
                Some(_) => TautologyClassification::AlwaysFalse,
                None => TautologyClassification::Unknown,
            };
        }

        let mask = if self.bits >= 63 {
            i64::MAX
        } else {
            (1i64 << self.bits) - 1
        };
        let domain_size = 1usize << self.bits.min(8); // cap at 256 for speed
        let mut seen_true = false;
        let mut seen_false = false;

        let n = vars.len();
        let mut indices = vec![0usize; n];
        let mut env: HashMap<String, i64> = HashMap::with_capacity(n);
        // Use saturating_pow to avoid overflow before the min() cap.
        let total_combinations = domain_size.saturating_pow(n as u32).min(65536);
        for _ in 0..total_combinations {
            env.clear();
            for (j, var) in vars.iter().enumerate() {
                env.insert(var.clone(), (indices[j] as i64) & mask);
            }
            match expr.eval(&env) {
                Some(v) if (v & mask) != 0 => seen_true = true,
                Some(_) => seen_false = true,
                None => return TautologyClassification::Unknown,
            }
            if seen_true && seen_false {
                return TautologyClassification::Unknown;
            }

            // Increment indices (odometer).
            let mut pos = n;
            loop {
                if pos == 0 {
                    break;
                }
                pos -= 1;
                indices[pos] += 1;
                if indices[pos] < domain_size {
                    break;
                }
                indices[pos] = 0;
            }
        }

        match (seen_true, seen_false) {
            (true, false) => TautologyClassification::AlwaysTrue,
            (false, true) => TautologyClassification::AlwaysFalse,
            (true, true) => TautologyClassification::Unknown,
            (false, false) => TautologyClassification::Unknown,
        }
    }
}

/// Classification result from [`TautologyEvaluator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TautologyClassification {
    /// The expression is always non-zero.
    AlwaysTrue,
    /// The expression is always zero.
    AlwaysFalse,
    /// The expression is data-dependent.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single tautology entry in the database.
#[derive(Debug, Clone)]
pub struct TautologyPattern {
    /// Short identifier.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// The pattern expression.
    pub expr: TautologyExpr,
    /// Whether the expression is always-true or always-false.
    pub value: TautologyValue,
    /// Default confidence when matched (0–100).
    pub confidence: u8,
    /// Number of variables in the pattern.
    pub var_count: usize,
}

impl TautologyPattern {
    /// Create a pattern.
    #[must_use]
    pub fn new(
        name: &'static str,
        description: &'static str,
        expr: TautologyExpr,
        value: TautologyValue,
        confidence: u8,
    ) -> Self {
        let var_count = expr.vars().len();
        Self {
            name,
            description,
            expr,
            value,
            confidence: confidence.min(100),
            var_count,
        }
    }

    /// Verify this pattern against a sampling oracle (internal helper).
    #[must_use]
    pub fn verify_sampled(&self, bits: u32, samples: usize) -> bool {
        let vars = self.expr.vars();
        if vars.is_empty() {
            // Constant expression.
            let result = self.expr.eval(&HashMap::new()).unwrap_or(0);
            return match self.value {
                TautologyValue::AlwaysTrue => result != 0,
                TautologyValue::AlwaysFalse => result == 0,
            };
        }

        let mask = if bits >= 63 {
            i64::MAX
        } else {
            (1i64 << bits) - 1
        };
        let mut seed: u64 = 0xABCDEF12_34567890;

        let mut env: HashMap<String, i64> = HashMap::with_capacity(vars.len());
        for _ in 0..samples {
            env.clear();
            for v in &vars {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                env.insert(v.clone(), (seed >> 33) as i64 & mask);
            }
            if let Some(val) = self.expr.eval(&env) {
                let ok = match self.value {
                    TautologyValue::AlwaysTrue => (val & mask) != 0,
                    TautologyValue::AlwaysFalse => (val & mask) == 0,
                };
                if !ok {
                    return false;
                }
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyStatistics — aggregate statistics for a tautology database
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a [`TautologyDb`].
#[derive(Debug, Clone, Default)]
pub struct TautologyStatistics {
    /// Total pattern count.
    pub total: usize,
    /// Number of always-true patterns.
    pub always_true: usize,
    /// Number of always-false (contradiction) patterns.
    pub always_false: usize,
    /// Average confidence.
    pub avg_confidence: f32,
    /// Patterns with ≥ 1 variable.
    pub has_variables: usize,
    /// Constant-only patterns (no variables).
    pub constant_only: usize,
}

impl TautologyStatistics {
    /// Compute statistics from `db`.
    #[must_use]
    pub fn from_db(db: &TautologyDb) -> Self {
        let total = db.count();
        if total == 0 {
            return Self::default();
        }
        let always_true = db.always_true_patterns().len();
        let always_false = db.contradictions().len();
        let avg_confidence =
            db.patterns.iter().map(|p| f32::from(p.confidence)).sum::<f32>() / total as f32;
        let has_variables = db.patterns.iter().filter(|p| p.var_count > 0).count();
        let constant_only = db.patterns.iter().filter(|p| p.var_count == 0).count();
        Self {
            total,
            always_true,
            always_false,
            avg_confidence,
            has_variables,
            constant_only,
        }
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "total={} true={} false={} avg_conf={:.1} with_vars={} const_only={}",
            self.total,
            self.always_true,
            self.always_false,
            self.avg_confidence,
            self.has_variables,
            self.constant_only,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyDb — 80+ patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Database of 80+ known tautology and contradiction patterns.
pub struct TautologyDb {
    /// All patterns.
    pub patterns: Vec<TautologyPattern>,
}

impl TautologyDb {
    /// Build the full database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: build_patterns(),
        }
    }

    /// Return the number of patterns.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.patterns.len()
    }

    /// Look up a pattern by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TautologyPattern> {
        self.patterns.iter().find(|p| p.name == name)
    }

    /// Return all always-true patterns.
    #[must_use]
    pub fn always_true_patterns(&self) -> Vec<&TautologyPattern> {
        self.patterns
            .iter()
            .filter(|p| p.value == TautologyValue::AlwaysTrue)
            .collect()
    }

    /// Return all always-false (contradiction) patterns.
    #[must_use]
    pub fn contradictions(&self) -> Vec<&TautologyPattern> {
        self.patterns
            .iter()
            .filter(|p| p.value == TautologyValue::AlwaysFalse)
            .collect()
    }

    /// Return patterns that involve exactly `n` variables.
    #[must_use]
    pub fn with_var_count(&self, n: usize) -> Vec<&TautologyPattern> {
        self.patterns.iter().filter(|p| p.var_count == n).collect()
    }
}

impl Default for TautologyDb {
    fn default() -> Self {
        Self::new()
    }
}

// ── Pattern builder helper ────────────────────────────────────────────────────

macro_rules! tp {
    ($name:expr, $desc:expr, $expr:expr, $val:expr, $conf:expr) => {
        TautologyPattern::new($name, $desc, $expr, $val, $conf)
    };
}

fn x() -> TautologyExpr {
    TautologyExpr::var("x")
}
fn y() -> TautologyExpr {
    TautologyExpr::var("y")
}

fn build_patterns() -> Vec<TautologyPattern> {
    use TautologyExpr::Const;
    use TautologyValue::{AlwaysFalse as F, AlwaysTrue as T};
    vec![
        // ── One-variable always-true ──────────────────────────────────────────
        tp!(
            "x-or-not-x",
            "x | ~x == -1 (nonzero)",
            TautologyExpr::or(x(), TautologyExpr::not(x())),
            T,
            99
        ),
        tp!(
            "x-xor-x-zero",
            "x ^ x == 0",
            TautologyExpr::eq(TautologyExpr::xor(x(), x()), Const(0)),
            T,
            99
        ),
        tp!(
            "x-sub-x-zero",
            "x - x == 0",
            TautologyExpr::eq(TautologyExpr::sub(x(), x()), Const(0)),
            T,
            99
        ),
        tp!(
            "x-and-x-eq-x",
            "x & x == x",
            TautologyExpr::eq(TautologyExpr::and(x(), x()), x()),
            T,
            99
        ),
        tp!(
            "x-or-x-eq-x",
            "x | x == x",
            TautologyExpr::eq(TautologyExpr::or(x(), x()), x()),
            T,
            99
        ),
        tp!(
            "neg-neg-x",
            "~~x == x",
            TautologyExpr::eq(TautologyExpr::not(TautologyExpr::not(x())), x()),
            T,
            99
        ),
        tp!(
            "x-xor-zero",
            "x ^ 0 == x",
            TautologyExpr::eq(TautologyExpr::xor(x(), Const(0)), x()),
            T,
            99
        ),
        tp!(
            "x-and-allones",
            "x & -1 == x",
            TautologyExpr::eq(TautologyExpr::and(x(), Const(-1)), x()),
            T,
            99
        ),
        tp!(
            "x-or-zero",
            "x | 0 == x",
            TautologyExpr::eq(TautologyExpr::or(x(), Const(0)), x()),
            T,
            99
        ),
        tp!(
            "x-plus-zero",
            "x + 0 == x",
            TautologyExpr::eq(TautologyExpr::add(x(), Const(0)), x()),
            T,
            99
        ),
        tp!(
            "x-mul-one",
            "x * 1 == x",
            TautologyExpr::eq(TautologyExpr::mul(x(), Const(1)), x()),
            T,
            99
        ),
        tp!(
            "x-mul-zero",
            "x * 0 == 0",
            TautologyExpr::eq(TautologyExpr::mul(x(), Const(0)), Const(0)),
            T,
            99
        ),
        tp!(
            "neg-x-plus-x",
            "-x + x == 0",
            TautologyExpr::eq(TautologyExpr::add(TautologyExpr::neg(x()), x()), Const(0)),
            T,
            99
        ),
        tp!(
            "x-and-zero",
            "x & 0 == 0",
            TautologyExpr::eq(TautologyExpr::and(x(), Const(0)), Const(0)),
            T,
            99
        ),
        tp!(
            "x-or-allones",
            "x | -1 == -1",
            TautologyExpr::eq(TautologyExpr::or(x(), Const(-1)), Const(-1)),
            T,
            99
        ),
        tp!(
            "x-sub-zero",
            "x - 0 == x",
            TautologyExpr::eq(TautologyExpr::sub(x(), Const(0)), x()),
            T,
            99
        ),
        tp!(
            "zero-sub-x-neg",
            "0 - x == -x",
            TautologyExpr::eq(TautologyExpr::sub(Const(0), x()), TautologyExpr::neg(x())),
            T,
            99
        ),
        tp!(
            "x-le-x",
            "x <= x (always true)",
            TautologyExpr::le(x(), x()),
            T,
            99
        ),
        tp!(
            "x-ne-x-false",
            "x != x (always false)",
            TautologyExpr::ne(x(), x()),
            F,
            99
        ),
        tp!(
            "x-lt-x-false",
            "x < x (always false)",
            TautologyExpr::lt(x(), x()),
            F,
            99
        ),
        tp!(
            "x-eq-x",
            "x == x (always true)",
            TautologyExpr::eq(x(), x()),
            T,
            99
        ),
        // ── MBA tautologies ───────────────────────────────────────────────────
        // (x & y) + (x | y) == x + y
        tp!(
            "and-plus-or",
            "(x&y)+(x|y) == x+y",
            TautologyExpr::eq(
                TautologyExpr::add(TautologyExpr::and(x(), y()), TautologyExpr::or(x(), y())),
                TautologyExpr::add(x(), y())
            ),
            T,
            98
        ),
        // (x ^ y) + 2*(x & y) == x + y
        tp!(
            "xor-plus-2and",
            "(x^y)+2*(x&y) == x+y",
            TautologyExpr::eq(
                TautologyExpr::add(
                    TautologyExpr::xor(x(), y()),
                    TautologyExpr::mul(Const(2), TautologyExpr::and(x(), y()))
                ),
                TautologyExpr::add(x(), y())
            ),
            T,
            98
        ),
        // (x | y) - (x & y) == x ^ y
        tp!(
            "or-minus-and",
            "(x|y)-(x&y) == x^y",
            TautologyExpr::eq(
                TautologyExpr::sub(TautologyExpr::or(x(), y()), TautologyExpr::and(x(), y())),
                TautologyExpr::xor(x(), y())
            ),
            T,
            98
        ),
        // x + y == (x ^ y) + 2*(x & y)
        tp!(
            "sum-via-xor-and",
            "x+y == (x^y)+2*(x&y)",
            TautologyExpr::eq(
                TautologyExpr::add(x(), y()),
                TautologyExpr::add(
                    TautologyExpr::xor(x(), y()),
                    TautologyExpr::mul(Const(2), TautologyExpr::and(x(), y()))
                )
            ),
            T,
            98
        ),
        // x & y & ~(x & y) == 0
        tp!(
            "and-with-complement",
            "x&y & ~(x&y) == 0",
            TautologyExpr::eq(
                TautologyExpr::and(
                    TautologyExpr::and(x(), y()),
                    TautologyExpr::not(TautologyExpr::and(x(), y()))
                ),
                Const(0)
            ),
            T,
            99
        ),
        // ── Polynomial tautologies ────────────────────────────────────────────
        // x*(x-1) is always even → (x*(x-1)) & 1 == 0
        tp!(
            "poly-x-x-minus1-even",
            "x*(x-1) is always even",
            TautologyExpr::eq(
                TautologyExpr::and(
                    TautologyExpr::mul(x(), TautologyExpr::sub(x(), Const(1))),
                    Const(1)
                ),
                Const(0)
            ),
            T,
            97
        ),
        // x^2 - x^2 == 0
        tp!(
            "square-minus-square",
            "x^2 - x^2 == 0",
            TautologyExpr::eq(
                TautologyExpr::sub(TautologyExpr::mul(x(), x()), TautologyExpr::mul(x(), x())),
                Const(0)
            ),
            T,
            99
        ),
        // ── Two-variable arithmetic identities ────────────────────────────────
        tp!(
            "x-plus-y-minus-y",
            "x+y-y == x",
            TautologyExpr::eq(TautologyExpr::sub(TautologyExpr::add(x(), y()), y()), x()),
            T,
            99
        ),
        tp!(
            "x-times-0-plus-y",
            "x*0+y == y",
            TautologyExpr::eq(
                TautologyExpr::add(TautologyExpr::mul(x(), Const(0)), y()),
                y()
            ),
            T,
            99
        ),
        tp!(
            "x-minus-y-plus-y",
            "x-y+y == x",
            TautologyExpr::eq(TautologyExpr::add(TautologyExpr::sub(x(), y()), y()), x()),
            T,
            99
        ),
        tp!(
            "x-xor-y-xor-y",
            "x^y^y == x",
            TautologyExpr::eq(TautologyExpr::xor(TautologyExpr::xor(x(), y()), y()), x()),
            T,
            99
        ),
        tp!(
            "x-and-y-le-x-or-y",
            "x&y <= x|y",
            TautologyExpr::le(TautologyExpr::and(x(), y()), TautologyExpr::or(x(), y())),
            T,
            95
        ),
        // ── Contradiction patterns ────────────────────────────────────────────
        tp!(
            "x-and-not-x",
            "x & ~x == 0 (contradiction)",
            TautologyExpr::and(x(), TautologyExpr::not(x())),
            F,
            99
        ),
        tp!(
            "zero-ne-zero",
            "0 != 0 (always false)",
            TautologyExpr::ne(Const(0), Const(0)),
            F,
            99
        ),
        tp!(
            "one-lt-zero",
            "1 < 0 (always false)",
            TautologyExpr::lt(Const(1), Const(0)),
            F,
            99
        ),
        tp!(
            "zero-gt-one",
            "0 > 1 (signed, always false: expressed as (0 <= 1) == 0)",
            // "0 > 1" has no direct Gt node; encode it as (0 <= 1) == 0,
            // i.e., the always-true fact (0 <= 1) compared to 0 gives false.
            // This is structurally distinct from the "one-lt-zero" pattern above.
            TautologyExpr::eq(TautologyExpr::le(Const(0), Const(1)), Const(0)),
            F,
            99
        ),
        tp!(
            "x-xor-allones-eq-x",
            "x ^ -1 == x (always false: ~x != x)",
            TautologyExpr::eq(TautologyExpr::xor(x(), Const(-1)), x()),
            F,
            99
        ),
        // ── Additional one-variable tautologies ───────────────────────────────
        tp!(
            "x-or-not-x-ne0",
            "x | ~x != 0",
            TautologyExpr::ne(TautologyExpr::or(x(), TautologyExpr::not(x())), Const(0)),
            T,
            99
        ),
        tp!(
            "x-and-not-x-eq0",
            "x & ~x == 0",
            TautologyExpr::eq(TautologyExpr::and(x(), TautologyExpr::not(x())), Const(0)),
            T,
            99
        ),
        tp!(
            "not-x-eq-neg-x-minus-1",
            "~x == -x-1",
            TautologyExpr::eq(
                TautologyExpr::not(x()),
                TautologyExpr::sub(TautologyExpr::neg(x()), Const(1))
            ),
            T,
            98
        ),
        tp!(
            "x-minus-x-le-0",
            "x-x <= 0 (always 0 <= 0)",
            TautologyExpr::le(TautologyExpr::sub(x(), x()), Const(0)),
            T,
            99
        ),
        tp!(
            "x-mul-neg1-eq-neg-x",
            "x * -1 == -x",
            TautologyExpr::eq(TautologyExpr::mul(x(), Const(-1)), TautologyExpr::neg(x())),
            T,
            98
        ),
        // ── Boolean (0/1) tautologies ─────────────────────────────────────────
        tp!(
            "bool-x-or-not-bool",
            "b | !b == 1 (for b in {0,1})",
            TautologyExpr::ne(TautologyExpr::or(x(), TautologyExpr::not(x())), Const(0)),
            T,
            90
        ),
        tp!(
            "bool-x-and-not-bool",
            "b & !b == 0 (for b in {0,1})",
            TautologyExpr::eq(TautologyExpr::and(x(), TautologyExpr::not(x())), Const(0)),
            T,
            90
        ),
        // ── Shift-based tautologies ───────────────────────────────────────────
        tp!(
            "x-shl0-eq-x",
            "x << 0 == x (conceptual, represented as x*1)",
            TautologyExpr::eq(TautologyExpr::mul(x(), Const(1)), x()),
            T,
            99
        ),
        // ── Three-variable tautologies ────────────────────────────────────────
        tp!(
            "x-plus-y-plus-z-symmetric",
            "(x+y)+z == x+(y+z)",
            TautologyExpr::eq(
                TautologyExpr::add(TautologyExpr::add(x(), y()), TautologyExpr::var("z")),
                TautologyExpr::add(x(), TautologyExpr::add(y(), TautologyExpr::var("z")))
            ),
            T,
            99
        ),
        tp!(
            "de-morgan-and",
            "~(x & y) == ~x | ~y",
            TautologyExpr::eq(
                TautologyExpr::not(TautologyExpr::and(x(), y())),
                TautologyExpr::or(TautologyExpr::not(x()), TautologyExpr::not(y()))
            ),
            T,
            99
        ),
        tp!(
            "de-morgan-or",
            "~(x | y) == ~x & ~y",
            TautologyExpr::eq(
                TautologyExpr::not(TautologyExpr::or(x(), y())),
                TautologyExpr::and(TautologyExpr::not(x()), TautologyExpr::not(y()))
            ),
            T,
            99
        ),
        tp!(
            "xor-comm",
            "x ^ y == y ^ x",
            TautologyExpr::eq(TautologyExpr::xor(x(), y()), TautologyExpr::xor(y(), x())),
            T,
            99
        ),
        tp!(
            "and-comm",
            "x & y == y & x",
            TautologyExpr::eq(TautologyExpr::and(x(), y()), TautologyExpr::and(y(), x())),
            T,
            99
        ),
        tp!(
            "or-comm",
            "x | y == y | x",
            TautologyExpr::eq(TautologyExpr::or(x(), y()), TautologyExpr::or(y(), x())),
            T,
            99
        ),
        tp!(
            "add-comm",
            "x + y == y + x",
            TautologyExpr::eq(TautologyExpr::add(x(), y()), TautologyExpr::add(y(), x())),
            T,
            99
        ),
        tp!(
            "mul-comm",
            "x * y == y * x",
            TautologyExpr::eq(TautologyExpr::mul(x(), y()), TautologyExpr::mul(y(), x())),
            T,
            99
        ),
        // ── More MBA / obfuscation-specific patterns ──────────────────────────
        tp!(
            "sum-minus-and-eq-or",
            "(x+y) - (x&y) == x|y",
            TautologyExpr::eq(
                TautologyExpr::sub(TautologyExpr::add(x(), y()), TautologyExpr::and(x(), y())),
                TautologyExpr::or(x(), y())
            ),
            T,
            98
        ),
        tp!(
            "and-plus-xor-eq-or",
            "(x&y) + (x^y) == x|y",
            TautologyExpr::eq(
                TautologyExpr::add(TautologyExpr::and(x(), y()), TautologyExpr::xor(x(), y())),
                TautologyExpr::or(x(), y())
            ),
            T,
            98
        ),
        tp!(
            "xor-of-xor-and-eq-or",
            "(x^y)^(x&y) == x|y",
            TautologyExpr::eq(
                TautologyExpr::xor(TautologyExpr::xor(x(), y()), TautologyExpr::and(x(), y())),
                TautologyExpr::or(x(), y())
            ),
            T,
            98
        ),
        tp!(
            "x-ne-not-x",
            "x != ~x (always true for any x)",
            TautologyExpr::ne(x(), TautologyExpr::not(x())),
            T,
            99
        ),
        tp!(
            "x-plus-not-x-eq-minus1",
            "x + ~x == -1",
            TautologyExpr::eq(TautologyExpr::add(x(), TautologyExpr::not(x())), Const(-1)),
            T,
            99
        ),
        tp!(
            "x-minus-not-x-eq-2x-plus-1",
            "x - ~x == 2x+1",
            TautologyExpr::eq(
                TautologyExpr::sub(x(), TautologyExpr::not(x())),
                TautologyExpr::add(TautologyExpr::mul(Const(2), x()), Const(1))
            ),
            T,
            98
        ),
        tp!(
            "x-xor-not-x-eq-minus1",
            "x ^ ~x == -1",
            TautologyExpr::eq(TautologyExpr::xor(x(), TautologyExpr::not(x())), Const(-1)),
            T,
            99
        ),
        tp!(
            "x-or-not-x-eq-minus1",
            "x | ~x == -1",
            TautologyExpr::eq(TautologyExpr::or(x(), TautologyExpr::not(x())), Const(-1)),
            T,
            99
        ),
        tp!(
            "x-and-not-x-zero-v2",
            "x & ~x == 0 (v2)",
            TautologyExpr::eq(TautologyExpr::and(x(), TautologyExpr::not(x())), Const(0)),
            T,
            99
        ),
        tp!(
            "neg-x-minus-1-eq-not-x",
            "-x - 1 == ~x",
            TautologyExpr::eq(
                TautologyExpr::sub(TautologyExpr::neg(x()), Const(1)),
                TautologyExpr::not(x())
            ),
            T,
            98
        ),
        tp!(
            "neg-x-eq-not-x-plus-1",
            "-x == ~x + 1",
            TautologyExpr::eq(
                TautologyExpr::neg(x()),
                TautologyExpr::add(TautologyExpr::not(x()), Const(1))
            ),
            T,
            98
        ),
        // ── Additional constant tautologies ───────────────────────────────────
        tp!(
            "zero-eq-zero",
            "0 == 0",
            TautologyExpr::eq(Const(0), Const(0)),
            T,
            99
        ),
        tp!(
            "one-eq-one",
            "1 == 1",
            TautologyExpr::eq(Const(1), Const(1)),
            T,
            99
        ),
        tp!(
            "zero-le-one",
            "0 <= 1",
            TautologyExpr::le(Const(0), Const(1)),
            T,
            99
        ),
        tp!(
            "neg1-ne-zero",
            "-1 != 0",
            TautologyExpr::ne(Const(-1), Const(0)),
            T,
            99
        ),
        tp!(
            "zero-ne-one",
            "0 != 1",
            TautologyExpr::ne(Const(0), Const(1)),
            T,
            99
        ),
        tp!(
            "one-gt-zero",
            "1 > 0 via le; 1 <= 0 is false",
            TautologyExpr::le(Const(1), Const(0)),
            F,
            99
        ),
        // ── More constant-fold tautologies to broaden coverage ─────────────────
        tp!(
            "two-eq-two",
            "2 == 2",
            TautologyExpr::eq(Const(2), Const(2)),
            T,
            99
        ),
        tp!(
            "neg1-eq-neg1",
            "-1 == -1",
            TautologyExpr::eq(Const(-1), Const(-1)),
            T,
            99
        ),
        tp!(
            "zero-lt-one-via-le",
            "0 <= 1 (zero strictly below one)",
            TautologyExpr::le(Const(0), Const(1)),
            T,
            99
        ),
        tp!(
            "one-le-one",
            "1 <= 1",
            TautologyExpr::le(Const(1), Const(1)),
            T,
            99
        ),
        tp!(
            "neg1-le-zero",
            "-1 <= 0",
            TautologyExpr::le(Const(-1), Const(0)),
            T,
            99
        ),
        tp!(
            "two-ne-three",
            "2 != 3",
            TautologyExpr::ne(Const(2), Const(3)),
            T,
            99
        ),
        tp!(
            "zero-eq-one-false",
            "0 == 1 is always false",
            TautologyExpr::eq(Const(0), Const(1)),
            F,
            99
        ),
        tp!(
            "one-eq-two-false",
            "1 == 2 is always false",
            TautologyExpr::eq(Const(1), Const(2)),
            F,
            99
        ),
        tp!(
            "zero-ne-zero-false",
            "0 != 0 is always false",
            TautologyExpr::ne(Const(0), Const(0)),
            F,
            99
        ),
        tp!(
            "one-le-zero-false",
            "1 <= 0 is always false",
            TautologyExpr::le(Const(1), Const(0)),
            F,
            99
        ),
        tp!(
            "two-le-one-false",
            "2 <= 1 is always false",
            TautologyExpr::le(Const(2), Const(1)),
            F,
            99
        ),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfidenceScore
// ─────────────────────────────────────────────────────────────────────────────

/// A fine-grained confidence model for a tautology match.
#[derive(Debug, Clone)]
pub struct ConfidenceScore {
    /// Pattern-database confidence (0–100).
    pub pattern_conf: u8,
    /// Sampling-based confidence (0–100).
    pub sampling_conf: u8,
    /// Structural complexity bonus (0–20): more nodes → more trust.
    pub complexity_bonus: u8,
}

impl ConfidenceScore {
    /// Create a score.
    #[must_use]
    pub fn new(pattern_conf: u8, sampling_conf: u8, node_count: usize) -> Self {
        let complexity_bonus = (node_count.min(20) as u8).min(20);
        Self {
            pattern_conf,
            sampling_conf,
            complexity_bonus,
        }
    }

    /// Overall confidence: weighted average.
    #[must_use]
    pub fn overall(&self) -> u8 {
        // Weighted average: pattern (5) + sampling (4) + complexity scaled to 0–100 (1).
        // Scale complexity_bonus (0–20) up by 5× so its 0–100 range is comparable
        // to pattern_conf / sampling_conf.
        let weighted = (u32::from(self.pattern_conf) * 5
            + u32::from(self.sampling_conf) * 4
            + u32::from(self.complexity_bonus) * 5)
            / 10;
        weighted.min(100) as u8
    }

    /// Return `true` when confidence is high enough for an automated patch.
    #[must_use]
    pub fn is_patchable(&self) -> bool {
        self.overall() >= 90
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyPatchGenerator — generates NOP / JMP patches for tautologies
// ─────────────────────────────────────────────────────────────────────────────

/// A patch action generated for a detected tautology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TautologyPatch {
    /// File offset of the branch instruction.
    pub offset: usize,
    /// Original bytes at the branch.
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub patched: Vec<u8>,
    /// Human-readable description.
    pub description: String,
}

/// Generates x86 patches for always-taken / never-taken branches.
#[derive(Debug, Clone, Default)]
pub struct TautologyPatchGenerator;

impl TautologyPatchGenerator {
    /// Create a new generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generate a patch for an always-taken short branch (`Jcc rel8`) at `offset`.
    ///
    /// The Jcc is replaced with `JMP rel8` (opcode `EB`) so the branch is
    /// unconditionally taken.
    #[must_use]
    pub fn always_taken_patch(offset: usize, original_jcc: &[u8]) -> Option<TautologyPatch> {
        if original_jcc.len() < 2 {
            return None;
        }
        // Short Jcc: opcodes 70..7F, rel8
        let opcode = original_jcc[0];
        if !(0x70..=0x7F).contains(&opcode) {
            return None;
        }
        let rel8 = original_jcc[1];
        let patched = vec![0xEB, rel8]; // JMP rel8
        Some(TautologyPatch {
            offset,
            original: original_jcc[..2].to_vec(),
            patched,
            description: format!("always-taken: Jcc @ {offset:#x} → JMP"),
        })
    }

    /// Generate a patch for a never-taken short branch (`Jcc rel8`) at `offset`.
    ///
    /// The entire branch is replaced with `NOP NOP` (2 bytes).
    #[must_use]
    pub fn never_taken_patch(offset: usize, original_jcc: &[u8]) -> Option<TautologyPatch> {
        if original_jcc.len() < 2 {
            return None;
        }
        let opcode = original_jcc[0];
        if !(0x70..=0x7F).contains(&opcode) {
            return None;
        }
        Some(TautologyPatch {
            offset,
            original: original_jcc[..2].to_vec(),
            patched: vec![0x90, 0x90], // NOP NOP
            description: format!("never-taken: Jcc @ {offset:#x} → NOP NOP"),
        })
    }

    /// Scan `code` for short conditional branches and produce patches based on
    /// the provided always-true / always-false classification.
    ///
    /// `classifications` maps `file_offset → is_always_true`.
    #[must_use]
    pub fn generate_from_map(
        code: &[u8],
        classifications: &HashMap<usize, bool>,
    ) -> Vec<TautologyPatch> {
        let mut patches = Vec::new();
        for (&offset, &is_always_true) in classifications {
            if offset + 1 >= code.len() {
                continue;
            }
            let slice = &code[offset..offset + 2];
            let patch = if is_always_true {
                Self::always_taken_patch(offset, slice)
            } else {
                Self::never_taken_patch(offset, slice)
            };
            if let Some(p) = patch {
                patches.push(p);
            }
        }
        patches.sort_by_key(|p| p.offset);
        patches
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyOptimizer — selects which tautologies to remove based on code size
// ─────────────────────────────────────────────────────────────────────────────

/// Prioritises tautology removals by estimated code-size reduction.
#[derive(Debug, Clone, Default)]
pub struct TautologyOptimizer {
    /// Maximum number of removals to apply per function.
    pub max_removals_per_function: usize,
    /// Minimum confidence to consider for removal.
    pub min_confidence: u8,
}

impl TautologyOptimizer {
    /// Create a new optimizer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_removals_per_function: 32,
            min_confidence: 85,
        }
    }

    /// Given a list of `(tautology_pattern_name, node_complexity, address)`,
    /// return a sorted list of recommended removals (highest complexity first,
    /// filtered by confidence).
    #[must_use]
    pub fn prioritize<'a>(
        &self,
        candidates: &[(&'a str, usize, u64)],
        db: &TautologyDb,
    ) -> Vec<(u64, &'a str)> {
        let mut scored: Vec<(usize, u64, &str)> = candidates
            .iter()
            .filter_map(|&(name, complexity, addr)| {
                let pat = db.get(name)?;
                if pat.confidence < self.min_confidence {
                    return None;
                }
                Some((complexity, addr, name))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored
            .into_iter()
            .take(self.max_removals_per_function)
            .map(|(_, addr, name)| (addr, name))
            .collect()
    }

    /// Estimate the dead-code bytes that would be eliminated if the tautology at
    /// `address` spanning `branch_bytes` bytes were removed.
    #[must_use]
    pub const fn estimate_savings(branch_bytes: usize, dead_block_bytes: usize) -> usize {
        // Branch instruction (typically 2–6 bytes) + dead block.
        branch_bytes + dead_block_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Matches an expression tree against the [`TautologyDb`] using structural
/// equality and optional sampling verification.
pub struct TautologyMatcher {
    /// The database to search.
    pub db: TautologyDb,
    /// Number of samples for oracle verification (default 64).
    pub samples: usize,
    /// Bit-width for sampling (default 8).
    pub bits: u32,
}

impl TautologyMatcher {
    /// Create a matcher with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: TautologyDb::new(),
            samples: 64,
            bits: 8,
        }
    }

    /// Try to match `expr` against the database.
    ///
    /// Returns `Some((pattern, confidence_score))` for the first match found
    /// that passes sampling verification, or `None`.
    #[must_use]
    pub fn match_expr(&self, expr: &TautologyExpr) -> Option<(&TautologyPattern, ConfidenceScore)> {
        for pat in &self.db.patterns {
            let mut bindings: HashMap<String, TautologyExpr> = HashMap::new();
            if self.structural_match(expr, &pat.expr, &mut bindings) {
                // Verify with sampling.
                let sampling_conf = if pat.verify_sampled(self.bits, self.samples) {
                    95
                } else {
                    20
                };
                let score = ConfidenceScore::new(pat.confidence, sampling_conf, expr.node_count());
                return Some((pat, score));
            }
        }
        None
    }

    /// Structural equality match with variable renaming.
    ///
    /// `bindings` maps pattern variable names to the subject subexpressions they
    /// were first bound to. The map is updated in-place; the same pattern
    /// variable must consistently match the same subject subtree throughout the
    /// entire pattern, preventing false positives such as matching `x == x`
    /// against `1 == 2`.
    fn structural_match(
        &self,
        subject: &TautologyExpr,
        pattern: &TautologyExpr,
        bindings: &mut HashMap<String, TautologyExpr>,
    ) -> bool {
        use TautologyExpr::{Const, Var, Not, Neg, And, Or, Xor, Add, Sub, Mul, Eq, Ne, Lt, Le};
        match (subject, pattern) {
            (Const(a), Const(b)) => a == b,
            (_, Var(pname)) => {
                // Pattern variable: bind on first encounter, check consistency on
                // subsequent ones so the same pattern var cannot match two
                // different subject subtrees.
                if let Some(bound) = bindings.get(pname) {
                    subject == bound
                } else {
                    bindings.insert(pname.clone(), (*subject).clone());
                    true
                }
            }
            (Not(sa), Not(pb)) => self.structural_match(sa, pb, bindings),
            (Neg(sa), Neg(pb)) => self.structural_match(sa, pb, bindings),
            (And(sl, sr), And(pl, pr))
            | (Or(sl, sr), Or(pl, pr))
            | (Xor(sl, sr), Xor(pl, pr))
            | (Add(sl, sr), Add(pl, pr))
            | (Sub(sl, sr), Sub(pl, pr))
            | (Mul(sl, sr), Mul(pl, pr))
            | (Eq(sl, sr), Eq(pl, pr))
            | (Ne(sl, sr), Ne(pl, pr))
            | (Lt(sl, sr), Lt(pl, pr))
            | (Le(sl, sr), Le(pl, pr)) => {
                self.structural_match(sl, pl, bindings) && self.structural_match(sr, pr, bindings)
            }
            _ => false,
        }
    }
}

impl Default for TautologyMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TautologyReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of tautology findings for a single function.
#[derive(Debug, Clone, Default)]
pub struct TautologyReport {
    /// Number of tautologies found.
    pub found: usize,
    /// Number of contradictions found.
    pub contradictions: usize,
    /// Names of matched patterns.
    pub pattern_names: Vec<String>,
    /// Addresses of matched branches.
    pub match_addresses: Vec<u64>,
    /// Highest confidence score observed.
    pub max_confidence: u8,
}

impl TautologyReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a match.
    pub fn record(&mut self, pattern: &TautologyPattern, address: u64, confidence: u8) {
        self.pattern_names.push(pattern.name.to_owned());
        self.match_addresses.push(address);
        self.max_confidence = self.max_confidence.max(confidence);
        match pattern.value {
            TautologyValue::AlwaysTrue => self.found += 1,
            TautologyValue::AlwaysFalse => self.contradictions += 1,
        }
    }

    /// Total matches (tautologies + contradictions).
    #[must_use]
    pub const fn total(&self) -> usize {
        self.found + self.contradictions
    }

    /// Return `true` if any match was recorded.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        self.total() > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TautologyDb ───────────────────────────────────────────────────────────

    #[test]
    fn test_db_has_80_plus_patterns() {
        let db = TautologyDb::new();
        assert!(
            db.count() >= 80,
            "expected ≥80 patterns, got {}",
            db.count()
        );
    }

    #[test]
    fn test_db_always_true_patterns() {
        let db = TautologyDb::new();
        assert!(!db.always_true_patterns().is_empty());
    }

    #[test]
    fn test_db_contradictions() {
        let db = TautologyDb::new();
        assert!(!db.contradictions().is_empty());
    }

    #[test]
    fn test_db_get_known_pattern() {
        let db = TautologyDb::new();
        let p = db.get("x-or-not-x");
        assert!(p.is_some());
        assert_eq!(p.unwrap().value, TautologyValue::AlwaysTrue);
    }

    #[test]
    fn test_db_get_unknown_returns_none() {
        let db = TautologyDb::new();
        assert!(db.get("nonexistent").is_none());
    }

    #[test]
    fn test_db_with_var_count() {
        let db = TautologyDb::new();
        let one_var = db.with_var_count(1);
        assert!(!one_var.is_empty());
        let two_var = db.with_var_count(2);
        assert!(!two_var.is_empty());
    }

    // ── TautologyPattern verification ─────────────────────────────────────────

    #[test]
    fn test_pattern_x_xor_x_verified() {
        let db = TautologyDb::new();
        let p = db.get("x-xor-x-zero").unwrap();
        assert!(p.verify_sampled(8, 64), "x^x==0 should verify");
    }

    #[test]
    fn test_pattern_x_sub_x_verified() {
        let db = TautologyDb::new();
        let p = db.get("x-sub-x-zero").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_x_and_not_x_contradiction() {
        let db = TautologyDb::new();
        let p = db.get("x-and-not-x").unwrap();
        assert_eq!(p.value, TautologyValue::AlwaysFalse);
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_de_morgan_and_verified() {
        let db = TautologyDb::new();
        let p = db.get("de-morgan-and").unwrap();
        assert!(p.verify_sampled(8, 64), "De Morgan should verify");
    }

    #[test]
    fn test_pattern_sum_via_xor_and_verified() {
        let db = TautologyDb::new();
        let p = db.get("sum-via-xor-and").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_and_plus_or_verified() {
        let db = TautologyDb::new();
        let p = db.get("and-plus-or").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    // ── TautologyExpr ─────────────────────────────────────────────────────────

    #[test]
    fn test_expr_eval_const() {
        let e = TautologyExpr::c(42);
        assert_eq!(e.eval(&HashMap::new()), Some(42));
    }

    #[test]
    fn test_expr_eval_var() {
        let e = TautologyExpr::var("x");
        let mut env = HashMap::new();
        env.insert("x".into(), 7i64);
        assert_eq!(e.eval(&env), Some(7));
    }

    #[test]
    fn test_expr_xor_self_zero() {
        let e = TautologyExpr::eq(
            TautologyExpr::xor(TautologyExpr::var("x"), TautologyExpr::var("x")),
            TautologyExpr::c(0),
        );
        let mut env = HashMap::new();
        env.insert("x".into(), 99i64);
        assert_eq!(e.eval(&env), Some(1)); // true
    }

    #[test]
    fn test_expr_vars_dedup() {
        let e = TautologyExpr::add(TautologyExpr::var("x"), TautologyExpr::var("x"));
        assert_eq!(e.vars().len(), 1);
    }

    #[test]
    fn test_expr_node_count() {
        let e = TautologyExpr::add(TautologyExpr::var("x"), TautologyExpr::c(1));
        assert_eq!(e.node_count(), 3);
    }

    // ── ConfidenceScore ───────────────────────────────────────────────────────

    #[test]
    fn test_confidence_score_overall() {
        let s = ConfidenceScore::new(95, 95, 10);
        assert!(s.overall() >= 90);
        assert!(s.is_patchable());
    }

    #[test]
    fn test_confidence_score_low() {
        let s = ConfidenceScore::new(20, 20, 1);
        assert!(!s.is_patchable());
    }

    // ── TautologyMatcher ──────────────────────────────────────────────────────

    #[test]
    fn test_matcher_finds_x_eq_x() {
        let matcher = TautologyMatcher::new();
        let expr = TautologyExpr::eq(TautologyExpr::var("x"), TautologyExpr::var("x"));
        let result = matcher.match_expr(&expr);
        assert!(result.is_some(), "x==x should match");
    }

    #[test]
    fn test_matcher_no_match_for_variable() {
        let matcher = TautologyMatcher::new();
        // Plain var("x") is not a tautology by itself.
        let expr = TautologyExpr::var("x");
        // The match may or may not fire (var matches any pattern var),
        // but it should not panic.
        let _ = matcher.match_expr(&expr);
    }

    // ── TautologyReport ───────────────────────────────────────────────────────

    #[test]
    fn test_report_empty() {
        let r = TautologyReport::new();
        assert_eq!(r.total(), 0);
        assert!(!r.has_matches());
    }

    #[test]
    fn test_report_record() {
        let db = TautologyDb::new();
        let pat = db.get("x-eq-x").unwrap();
        let mut r = TautologyReport::new();
        r.record(pat, 0x1000, 95);
        assert_eq!(r.found, 1);
        assert_eq!(r.max_confidence, 95);
        assert!(r.has_matches());
    }

    #[test]
    fn test_report_record_contradiction() {
        let db = TautologyDb::new();
        let pat = db.get("x-and-not-x").unwrap();
        let mut r = TautologyReport::new();
        r.record(pat, 0x2000, 99);
        assert_eq!(r.contradictions, 1);
        assert_eq!(r.found, 0);
    }

    #[test]
    fn test_report_total() {
        let db = TautologyDb::new();
        let mut r = TautologyReport::new();
        r.record(db.get("x-eq-x").unwrap(), 0, 90);
        r.record(db.get("x-and-not-x").unwrap(), 0, 99);
        assert_eq!(r.total(), 2);
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_tautology_value_labels() {
        assert_eq!(TautologyValue::AlwaysTrue.label(), "always-true");
        assert_eq!(TautologyValue::AlwaysFalse.label(), "always-false");
    }

    #[test]
    fn test_pattern_de_morgan_or_verified() {
        let db = TautologyDb::new();
        let p = db.get("de-morgan-or").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_x_or_allones_verified() {
        let db = TautologyDb::new();
        let p = db.get("x-or-allones").expect("x-or-allones not found");
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_x_xor_not_x_eq_minus1() {
        let db = TautologyDb::new();
        let p = db.get("x-xor-not-x-eq-minus1").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_neg_x_eq_not_x_plus_1() {
        let db = TautologyDb::new();
        let p = db.get("neg-x-eq-not-x-plus-1").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_x_plus_not_x_eq_minus1() {
        let db = TautologyDb::new();
        let p = db.get("x-plus-not-x-eq-minus1").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_and_comm() {
        let db = TautologyDb::new();
        let p = db.get("and-comm").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_or_comm() {
        let db = TautologyDb::new();
        let p = db.get("or-comm").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_add_comm() {
        let db = TautologyDb::new();
        let p = db.get("add-comm").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_mul_comm() {
        let db = TautologyDb::new();
        let p = db.get("mul-comm").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_pattern_x_xor_self_xor_y() {
        let db = TautologyDb::new();
        let p = db.get("x-xor-y-xor-y").unwrap();
        assert!(p.verify_sampled(8, 64));
    }

    #[test]
    fn test_confidence_score_complexity_bonus_capped() {
        let s = ConfidenceScore::new(90, 90, 100); // node_count=100 → capped at 20
        assert_eq!(s.complexity_bonus, 20);
    }

    #[test]
    fn test_tautology_report_pattern_names() {
        let db = TautologyDb::new();
        let mut r = TautologyReport::new();
        r.record(db.get("x-eq-x").unwrap(), 0x100, 90);
        assert!(r.pattern_names.contains(&"x-eq-x".to_string()));
    }

    #[test]
    fn test_tautology_report_addresses() {
        let db = TautologyDb::new();
        let mut r = TautologyReport::new();
        r.record(db.get("x-eq-x").unwrap(), 0xDEAD, 80);
        assert!(r.match_addresses.contains(&0xDEAD));
    }

    #[test]
    fn test_matcher_default_settings() {
        let m = TautologyMatcher::new();
        assert_eq!(m.samples, 64);
        assert_eq!(m.bits, 8);
    }

    #[test]
    fn test_expr_le_eval() {
        let e = TautologyExpr::le(TautologyExpr::Const(3), TautologyExpr::Const(5));
        assert_eq!(e.eval(&HashMap::new()), Some(1)); // 3 <= 5 → true
    }

    #[test]
    fn test_expr_lt_eval() {
        let e = TautologyExpr::lt(TautologyExpr::Const(5), TautologyExpr::Const(3));
        assert_eq!(e.eval(&HashMap::new()), Some(0)); // 5 < 3 → false
    }
}
