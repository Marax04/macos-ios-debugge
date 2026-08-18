//! `hlil_expression_normalizer` — Expression normalization passes for HLIL.
//!
//! Implements a series of algebraic and structural simplification passes that
//! reduce complex HLIL expression trees to canonical form: constant folding,
//! identity elimination, double-negation removal, de Morgan's law, strength
//! reduction, and trivial dead-code removal at the expression level.

use std::fmt;

// ── NormalizationPass ─────────────────────────────────────────────────────────

/// Identifies a single normalization transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizationPass {
    /// Fold constant arithmetic: `2 + 3` → `5`.
    ConstantFolding,
    /// Remove identity operations: `x + 0`, `x * 1`, `x | 0`, `x & ~0`.
    IdentityElimination,
    /// Collapse double negation: `- -x` → `x`, `!!x` → `x`, `~~x` → `x`.
    DoubleNegation,
    /// Apply de Morgan's law: `!(a && b)` → `!a || !b`.
    DeMorgan,
    /// Strength reduction: `x * 2` → `x << 1`, `x * 4` → `x << 2`.
    StrengthReduction,
    /// Simplify comparisons: `x != 0` in boolean context → `x`.
    CompareNormalize,
    /// Merge consecutive casts: `(int32_t)(int8_t)x` → `(int8_t)x`.
    CastMerge,
    /// Remove redundant parentheses from the display representation.
    ParenthesisReduction,
    /// Commute operands so constants appear on the right: `1 + x` → `x + 1`.
    ConstantSink,
    /// Distribute NOT over AND/OR (partial de Morgan).
    NotDistribution,
}

impl fmt::Display for NormalizationPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstantFolding => write!(f, "constant-folding"),
            Self::IdentityElimination => write!(f, "identity-elimination"),
            Self::DoubleNegation => write!(f, "double-negation"),
            Self::DeMorgan => write!(f, "de-morgan"),
            Self::StrengthReduction => write!(f, "strength-reduction"),
            Self::CompareNormalize => write!(f, "compare-normalize"),
            Self::CastMerge => write!(f, "cast-merge"),
            Self::ParenthesisReduction => write!(f, "paren-reduction"),
            Self::ConstantSink => write!(f, "constant-sink"),
            Self::NotDistribution => write!(f, "not-distribution"),
        }
    }
}

// ── SimpleExpr ────────────────────────────────────────────────────────────────

/// A simple self-contained expression tree used by the normalizer.
///
/// This mirrors a subset of `HlilExpr` so the normalizer can be tested and
/// used independently without importing the full HLIL type graph.
#[derive(Debug, Clone, PartialEq)]
pub enum SimpleExpr {
    Const(i64),
    Var(String),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    Not(Box<Self>),
    LogicalNot(Box<Self>),
    LogicalAnd(Box<Self>, Box<Self>),
    LogicalOr(Box<Self>, Box<Self>),
    CmpEq(Box<Self>, Box<Self>),
    CmpNe(Box<Self>, Box<Self>),
    CmpLt(Box<Self>, Box<Self>),
    CmpGt(Box<Self>, Box<Self>),
    CmpLe(Box<Self>, Box<Self>),
    CmpGe(Box<Self>, Box<Self>),
    Cast(Box<Self>, u8),  // byte-width
    Deref(Box<Self>),
}

impl SimpleExpr {
    /// Returns the constant value if this is a `Const` variant.
    #[must_use]
    pub const fn const_val(&self) -> Option<i64> {
        if let Self::Const(v) = self { Some(*v) } else { None }
    }

    /// Returns `true` if this expression has no side effects and is pure.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        match self {
            Self::Const(_) | Self::Var(_) => true,
            Self::Deref(_) => false,
            Self::Add(a, b)
            | Self::Sub(a, b)
            | Self::Mul(a, b)
            | Self::Div(a, b)
            | Self::And(a, b)
            | Self::Or(a, b)
            | Self::Xor(a, b)
            | Self::Shl(a, b)
            | Self::Shr(a, b)
            | Self::LogicalAnd(a, b)
            | Self::LogicalOr(a, b)
            | Self::CmpEq(a, b)
            | Self::CmpNe(a, b)
            | Self::CmpLt(a, b)
            | Self::CmpGt(a, b)
            | Self::CmpLe(a, b)
            | Self::CmpGe(a, b) => a.is_pure() && b.is_pure(),
            Self::Neg(e)
            | Self::Not(e)
            | Self::LogicalNot(e)
            | Self::Cast(e, _) => e.is_pure(),
        }
    }

    /// Compute a complexity metric (node count).
    #[must_use]
    pub fn complexity(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Neg(e) | Self::Not(e) | Self::LogicalNot(e) | Self::Cast(e, _) | Self::Deref(e) => {
                1 + e.complexity()
            }
            Self::Add(a, b)
            | Self::Sub(a, b)
            | Self::Mul(a, b)
            | Self::Div(a, b)
            | Self::And(a, b)
            | Self::Or(a, b)
            | Self::Xor(a, b)
            | Self::Shl(a, b)
            | Self::Shr(a, b)
            | Self::LogicalAnd(a, b)
            | Self::LogicalOr(a, b)
            | Self::CmpEq(a, b)
            | Self::CmpNe(a, b)
            | Self::CmpLt(a, b)
            | Self::CmpGt(a, b)
            | Self::CmpLe(a, b)
            | Self::CmpGe(a, b) => 1 + a.complexity() + b.complexity(),
        }
    }
}

impl fmt::Display for SimpleExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v}"),
            Self::Var(n) => write!(f, "{n}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::Mul(a, b) => write!(f, "({a} * {b})"),
            Self::Div(a, b) => write!(f, "({a} / {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Or(a, b) => write!(f, "({a} | {b})"),
            Self::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Self::Shl(a, b) => write!(f, "({a} << {b})"),
            Self::Shr(a, b) => write!(f, "({a} >> {b})"),
            Self::Neg(e) => write!(f, "-{e}"),
            Self::Not(e) => write!(f, "~{e}"),
            Self::LogicalAnd(a, b) => write!(f, "({a} && {b})"),
            Self::LogicalOr(a, b) => write!(f, "({a} || {b})"),
            Self::LogicalNot(e) => write!(f, "!{e}"),
            Self::CmpEq(a, b) => write!(f, "({a} == {b})"),
            Self::CmpNe(a, b) => write!(f, "({a} != {b})"),
            Self::CmpLt(a, b) => write!(f, "({a} < {b})"),
            Self::CmpGt(a, b) => write!(f, "({a} > {b})"),
            Self::CmpLe(a, b) => write!(f, "({a} <= {b})"),
            Self::CmpGe(a, b) => write!(f, "({a} >= {b})"),
            Self::Cast(e, w) => write!(f, "(i{w}){e}"),
            Self::Deref(e) => write!(f, "*{e}"),
        }
    }
}

// ── NormalizationResult ───────────────────────────────────────────────────────

/// Diagnostic information from a normalization pass.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// Which pass produced this transformation.
    pub pass: NormalizationPass,
    /// Before complexity.
    pub before_complexity: usize,
    /// After complexity.
    pub after_complexity: usize,
    /// Human-readable description of what changed.
    pub description: String,
}

impl NormalizationResult {
    /// Returns `true` if the complexity was actually reduced.
    #[must_use]
    pub const fn reduced(&self) -> bool {
        self.after_complexity < self.before_complexity
    }
}

impl fmt::Display for NormalizationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} -> {} nodes: {}",
            self.pass, self.before_complexity, self.after_complexity, self.description
        )
    }
}

// ── HlilExpressionNormalizer ──────────────────────────────────────────────────

/// Applies a configurable set of normalization passes to HLIL expression trees.
///
/// Each pass is applied bottom-up (leaf to root), repeatedly until a fixed
/// point is reached or the maximum iteration limit is hit.
pub struct HlilExpressionNormalizer {
    /// Passes to apply, in order.
    pub passes: Vec<NormalizationPass>,
    /// Maximum number of full-pass iterations.
    pub max_iterations: usize,
    /// Diagnostics collected during the last [`normalize_function`] call.
    pub diagnostics: Vec<NormalizationResult>,
}

impl HlilExpressionNormalizer {
    /// Create a normalizer with all passes enabled.
    #[must_use]
    pub fn full() -> Self {
        Self {
            passes: vec![
                NormalizationPass::ConstantFolding,
                NormalizationPass::IdentityElimination,
                NormalizationPass::DoubleNegation,
                NormalizationPass::DeMorgan,
                NormalizationPass::StrengthReduction,
                NormalizationPass::CompareNormalize,
                NormalizationPass::CastMerge,
                NormalizationPass::ConstantSink,
            ],
            max_iterations: 8,
            diagnostics: Vec::new(),
        }
    }

    /// Create a lightweight normalizer with only constant folding and identity elimination.
    #[must_use]
    pub fn lightweight() -> Self {
        Self {
            passes: vec![
                NormalizationPass::ConstantFolding,
                NormalizationPass::IdentityElimination,
            ],
            max_iterations: 4,
            diagnostics: Vec::new(),
        }
    }

    /// Normalize a single expression, returning the simplified form.
    #[must_use]
    pub fn normalize_expr(&mut self, expr: SimpleExpr) -> SimpleExpr {
        let mut current = expr;
        for _iter in 0..self.max_iterations {
            let before = current.complexity();
            let next = self.apply_all_passes(current.clone());
            let after = next.complexity();
            if after >= before {
                current = next;
                break;
            }
            current = next;
        }
        current
    }

    /// Normalize all expressions in a flat list (e.g., all assignments in a
    /// function), returning the transformed list and populating `self.diagnostics`.
    pub fn normalize_function(&mut self, exprs: Vec<SimpleExpr>) -> Vec<SimpleExpr> {
        self.diagnostics.clear();
        exprs
            .into_iter()
            .map(|e| {
                let before_complexity = e.complexity();
                let before_repr = e.to_string();
                let normalized = self.normalize_expr(e);
                let after_complexity = normalized.complexity();
                if after_complexity < before_complexity {
                    self.diagnostics.push(NormalizationResult {
                        pass: NormalizationPass::ConstantFolding, // representative
                        before_complexity,
                        after_complexity,
                        description: format!("{before_repr} → {normalized}"),
                    });
                }
                normalized
            })
            .collect()
    }

    // ── Internal: apply all passes to one expression ──────────────────────────

    /// Maximum expression tree depth before recursion is cut off to prevent stack overflow.
    const MAX_DEPTH: usize = 256;

    fn apply_all_passes(&self, expr: SimpleExpr) -> SimpleExpr {
        // Delegate through recurse (depth 0) to apply passes bottom-up with depth tracking.
        let after_recurse = self.recurse(expr);
        let mut result = after_recurse;
        for &pass in &self.passes {
            result = self.apply_pass(result, pass);
        }
        result
    }

    fn apply_all_passes_depth(&self, expr: SimpleExpr, depth: usize) -> SimpleExpr {
        if depth >= Self::MAX_DEPTH {
            // Abort recursion on pathologically deep trees to prevent stack overflow.
            return expr;
        }
        // First recurse into children, then apply each pass bottom-up.
        let after_recurse = self.recurse_depth(expr, depth);
        let mut result = after_recurse;
        for &pass in &self.passes {
            result = self.apply_pass(result, pass);
        }
        result
    }

    fn recurse(&self, expr: SimpleExpr) -> SimpleExpr {
        self.recurse_depth(expr, 0)
    }

    fn recurse_depth(&self, expr: SimpleExpr, depth: usize) -> SimpleExpr {
        match expr {
            SimpleExpr::Neg(e) => SimpleExpr::Neg(Box::new(self.apply_all_passes_depth(*e, depth + 1))),
            SimpleExpr::Not(e) => SimpleExpr::Not(Box::new(self.apply_all_passes_depth(*e, depth + 1))),
            SimpleExpr::LogicalNot(e) => SimpleExpr::LogicalNot(Box::new(self.apply_all_passes_depth(*e, depth + 1))),
            SimpleExpr::Cast(e, w) => SimpleExpr::Cast(Box::new(self.apply_all_passes_depth(*e, depth + 1)), w),
            SimpleExpr::Deref(e) => SimpleExpr::Deref(Box::new(self.apply_all_passes_depth(*e, depth + 1))),
            SimpleExpr::Add(a, b) => SimpleExpr::Add(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Sub(a, b) => SimpleExpr::Sub(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Mul(a, b) => SimpleExpr::Mul(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Div(a, b) => SimpleExpr::Div(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::And(a, b) => SimpleExpr::And(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Or(a, b) => SimpleExpr::Or(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Xor(a, b) => SimpleExpr::Xor(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Shl(a, b) => SimpleExpr::Shl(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::Shr(a, b) => SimpleExpr::Shr(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::LogicalAnd(a, b) => SimpleExpr::LogicalAnd(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::LogicalOr(a, b) => SimpleExpr::LogicalOr(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpEq(a, b) => SimpleExpr::CmpEq(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpNe(a, b) => SimpleExpr::CmpNe(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpLt(a, b) => SimpleExpr::CmpLt(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpGt(a, b) => SimpleExpr::CmpGt(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpLe(a, b) => SimpleExpr::CmpLe(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            SimpleExpr::CmpGe(a, b) => SimpleExpr::CmpGe(
                Box::new(self.apply_all_passes_depth(*a, depth + 1)),
                Box::new(self.apply_all_passes_depth(*b, depth + 1)),
            ),
            leaf => leaf,
        }
    }

    fn apply_pass(&self, expr: SimpleExpr, pass: NormalizationPass) -> SimpleExpr {
        match pass {
            NormalizationPass::ConstantFolding => self.pass_const_fold(expr),
            NormalizationPass::IdentityElimination => self.pass_identity(expr),
            NormalizationPass::DoubleNegation => self.pass_double_neg(expr),
            NormalizationPass::DeMorgan => self.pass_de_morgan(expr),
            NormalizationPass::StrengthReduction => self.pass_strength(expr),
            NormalizationPass::CompareNormalize => self.pass_compare(expr),
            NormalizationPass::CastMerge => self.pass_cast_merge(expr),
            NormalizationPass::ConstantSink => self.pass_const_sink(expr),
            NormalizationPass::NotDistribution => self.pass_not_dist(expr),
            NormalizationPass::ParenthesisReduction => expr, // display-level only
        }
    }

    // ── Constant folding ──────────────────────────────────────────────────────

    fn pass_const_fold(&self, expr: SimpleExpr) -> SimpleExpr {
        match &expr {
            SimpleExpr::Add(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x.wrapping_add(y)) },
            SimpleExpr::Sub(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x.wrapping_sub(y)) },
            SimpleExpr::Mul(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x.wrapping_mul(y)) },
            SimpleExpr::Div(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { if y != 0 { return SimpleExpr::Const(x.wrapping_div(y)); } },
            SimpleExpr::And(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x & y) },
            SimpleExpr::Or(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x | y) },
            SimpleExpr::Xor(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(x ^ y) },
            SimpleExpr::Shl(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { if (0..64).contains(&y) { return SimpleExpr::Const(x.wrapping_shl(y as u32)); } },
            SimpleExpr::Shr(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { if (0..64).contains(&y) { return SimpleExpr::Const(x.wrapping_shr(y as u32)); } },
            SimpleExpr::Neg(e) => {
                if let Some(v) = e.const_val() {
                    return SimpleExpr::Const(v.wrapping_neg());
                }
            }
            SimpleExpr::Not(e) => {
                if let Some(v) = e.const_val() {
                    return SimpleExpr::Const(!v);
                }
            }
            SimpleExpr::CmpEq(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x == y)) },
            SimpleExpr::CmpNe(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x != y)) },
            SimpleExpr::CmpLt(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x < y)) },
            SimpleExpr::CmpGt(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x > y)) },
            SimpleExpr::CmpLe(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x <= y)) },
            SimpleExpr::CmpGe(a, b) => if let (Some(x), Some(y)) = (a.const_val(), b.const_val()) { return SimpleExpr::Const(i64::from(x >= y)) },
            _ => {}
        }
        expr
    }

    // ── Identity elimination ──────────────────────────────────────────────────

    fn pass_identity(&self, expr: SimpleExpr) -> SimpleExpr {
        match &expr {
            SimpleExpr::Add(a, b) => {
                if b.const_val() == Some(0) { return *a.clone(); }
                if a.const_val() == Some(0) { return *b.clone(); }
            }
            SimpleExpr::Sub(a, b) => {
                if b.const_val() == Some(0) { return *a.clone(); }
                if a == b && a.is_pure() { return SimpleExpr::Const(0); }
            }
            SimpleExpr::Mul(a, b) => {
                if b.const_val() == Some(1) { return *a.clone(); }
                if a.const_val() == Some(1) { return *b.clone(); }
                if b.const_val() == Some(0) { return SimpleExpr::Const(0); }
                if a.const_val() == Some(0) { return SimpleExpr::Const(0); }
            }
            SimpleExpr::Div(a, b) => {
                if b.const_val() == Some(1) { return *a.clone(); }
            }
            SimpleExpr::Or(a, b) => {
                if b.const_val() == Some(0) { return *a.clone(); }
                if a.const_val() == Some(0) { return *b.clone(); }
                if a == b && a.is_pure() { return *a.clone(); }
            }
            SimpleExpr::And(a, b) => {
                if b.const_val() == Some(-1) { return *a.clone(); }
                if a.const_val() == Some(-1) { return *b.clone(); }
                if b.const_val() == Some(0) { return SimpleExpr::Const(0); }
                if a.const_val() == Some(0) { return SimpleExpr::Const(0); }
                if a == b && a.is_pure() { return *a.clone(); }
            }
            SimpleExpr::Xor(a, b) => {
                if b.const_val() == Some(0) { return *a.clone(); }
                if a == b && a.is_pure() { return SimpleExpr::Const(0); }
            }
            SimpleExpr::Shl(a, b) | SimpleExpr::Shr(a, b) => {
                if b.const_val() == Some(0) { return *a.clone(); }
            }
            _ => {}
        }
        expr
    }

    // ── Double negation ───────────────────────────────────────────────────────

    fn pass_double_neg(&self, expr: SimpleExpr) -> SimpleExpr {
        match &expr {
            SimpleExpr::Neg(e) => {
                if let SimpleExpr::Neg(inner) = e.as_ref() {
                    return *inner.clone();
                }
            }
            SimpleExpr::Not(e) => {
                if let SimpleExpr::Not(inner) = e.as_ref() {
                    return *inner.clone();
                }
            }
            SimpleExpr::LogicalNot(e) => {
                if let SimpleExpr::LogicalNot(inner) = e.as_ref() {
                    return *inner.clone();
                }
            }
            _ => {}
        }
        expr
    }

    // ── de Morgan ─────────────────────────────────────────────────────────────

    fn pass_de_morgan(&self, expr: SimpleExpr) -> SimpleExpr {
        if let SimpleExpr::LogicalNot(inner) = &expr {
            match inner.as_ref() {
                SimpleExpr::LogicalAnd(a, b) => {
                    return SimpleExpr::LogicalOr(
                        Box::new(SimpleExpr::LogicalNot(a.clone())),
                        Box::new(SimpleExpr::LogicalNot(b.clone())),
                    );
                }
                SimpleExpr::LogicalOr(a, b) => {
                    return SimpleExpr::LogicalAnd(
                        Box::new(SimpleExpr::LogicalNot(a.clone())),
                        Box::new(SimpleExpr::LogicalNot(b.clone())),
                    );
                }
                _ => {}
            }
        }
        expr
    }

    // ── Strength reduction ────────────────────────────────────────────────────

    fn pass_strength(&self, expr: SimpleExpr) -> SimpleExpr {
        match &expr {
            SimpleExpr::Mul(a, b) => {
                if let Some(k) = b.const_val()
                    && k > 0 && k.count_ones() == 1 {
                        let shift = i64::from(k.trailing_zeros());
                        return SimpleExpr::Shl(
                            a.clone(),
                            Box::new(SimpleExpr::Const(shift)),
                        );
                    }
                if let Some(k) = a.const_val()
                    && k > 0 && k.count_ones() == 1 {
                        let shift = i64::from(k.trailing_zeros());
                        return SimpleExpr::Shl(
                            b.clone(),
                            Box::new(SimpleExpr::Const(shift)),
                        );
                    }
            }
            // NOTE: `Div(a, 2^k)` is deliberately NOT rewritten to
            // `Shr(a, k)`. Division here is signed and truncates toward
            // zero (`i64::wrapping_div` in `pass_const_fold`), while a
            // shift rounds toward negative infinity: -7 / 2 == -3 but
            // -7 >> 1 == -4. The rewrite is only valid for provably
            // non-negative dividends, which this context-free pass cannot
            // establish, so the rule was removed. (`Mul(a, 2^k)` → `Shl` is
            // fine: shifting matches signed multiplication exactly.)
            _ => {}
        }
        expr
    }

    // ── Compare normalization ─────────────────────────────────────────────────

    fn pass_compare(&self, expr: SimpleExpr) -> SimpleExpr {
        // NOTE: the former `x != 0` → `x` rewrite was removed. It is only
        // valid in boolean positions (if/while conditions, logical
        // operands), but this pass is applied to *every* subexpression via
        // `apply_all_passes`, including arithmetic contexts where the
        // comparison materializes a 0/1 value: for x = 7, `(x != 0) + 1`
        // is 2, but after the rewrite it became `x + 1` == 8. MBA-style
        // obfuscation constantly materializes booleans into integers, so
        // the unconditional rewrite miscomputed real deobfuscation output.
        // Reinstating it would require threading a boolean-context flag
        // through the recursion.
        //
        // `x == x` → 1 and `x < x` → 0 below are value-correct in every
        // context (they fold to the exact 0/1 integer the compare yields).
        // `x == x` → 1
        if let SimpleExpr::CmpEq(a, b) = &expr
            && a == b && a.is_pure() {
                return SimpleExpr::Const(1);
            }
        // `x < x` → 0
        if let SimpleExpr::CmpLt(a, b) = &expr
            && a == b && a.is_pure() {
                return SimpleExpr::Const(0);
            }
        expr
    }

    // ── Cast merging ──────────────────────────────────────────────────────────

    fn pass_cast_merge(&self, expr: SimpleExpr) -> SimpleExpr {
        if let SimpleExpr::Cast(inner, outer_w) = &expr
            && let SimpleExpr::Cast(innermost, inner_w) = inner.as_ref() {
                // If the outer cast is widening and the inner is narrowing
                // (or they are the same width), the outer is redundant.
                if *outer_w >= *inner_w {
                    return SimpleExpr::Cast(innermost.clone(), *inner_w);
                }
            }
        expr
    }

    // ── Constant sink ─────────────────────────────────────────────────────

    fn pass_const_sink(&self, expr: SimpleExpr) -> SimpleExpr {
        // Commute binary ops so constants are on the right (canonical form).
        match expr {
            SimpleExpr::Add(a, b) if a.const_val().is_some() && b.const_val().is_none() => {
                SimpleExpr::Add(b, a)
            }
            SimpleExpr::Mul(a, b) if a.const_val().is_some() && b.const_val().is_none() => {
                SimpleExpr::Mul(b, a)
            }
            SimpleExpr::And(a, b) if a.const_val().is_some() && b.const_val().is_none() => {
                SimpleExpr::And(b, a)
            }
            SimpleExpr::Or(a, b) if a.const_val().is_some() && b.const_val().is_none() => {
                SimpleExpr::Or(b, a)
            }
            SimpleExpr::Xor(a, b) if a.const_val().is_some() && b.const_val().is_none() => {
                SimpleExpr::Xor(b, a)
            }
            other => other,
        }
    }

    // ── NOT distribution ──────────────────────────────────────────────────────

    fn pass_not_dist(&self, expr: SimpleExpr) -> SimpleExpr {
        if let SimpleExpr::Not(inner) = &expr {
            match inner.as_ref() {
                SimpleExpr::And(a, b) => {
                    return SimpleExpr::Or(
                        Box::new(SimpleExpr::Not(a.clone())),
                        Box::new(SimpleExpr::Not(b.clone())),
                    );
                }
                SimpleExpr::Or(a, b) => {
                    return SimpleExpr::And(
                        Box::new(SimpleExpr::Not(a.clone())),
                        Box::new(SimpleExpr::Not(b.clone())),
                    );
                }
                _ => {}
            }
        }
        expr
    }
}

// ── normalize_function (free function) ───────────────────────────────────────

/// Convenience function: normalize all expressions in `exprs` using the full
/// normalizer and return the simplified list.
#[must_use]
pub fn normalize_function(exprs: Vec<SimpleExpr>) -> Vec<SimpleExpr> {
    HlilExpressionNormalizer::full().normalize_function(exprs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_folding_add() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Add(Box::new(SimpleExpr::Const(3)), Box::new(SimpleExpr::Const(4)));
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Const(7));
    }

    #[test]
    fn test_identity_add_zero() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Add(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(0)),
        );
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Var("x".into()));
    }

    #[test]
    fn test_identity_mul_one() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Mul(
            Box::new(SimpleExpr::Var("y".into())),
            Box::new(SimpleExpr::Const(1)),
        );
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Var("y".into()));
    }

    #[test]
    fn test_strength_reduction_mul2() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Mul(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(4)),
        );
        let result = n.normalize_expr(e);
        // Should become x << 2.
        assert!(
            matches!(result, SimpleExpr::Shl(_, _)),
            "expected Shl, got {result}"
        );
    }

    #[test]
    fn test_double_negation_removal() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Neg(Box::new(SimpleExpr::Neg(Box::new(SimpleExpr::Var("z".into())))));
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Var("z".into()));
    }

    #[test]
    fn test_xor_self_is_zero() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Xor(
            Box::new(SimpleExpr::Var("a".into())),
            Box::new(SimpleExpr::Var("a".into())),
        );
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Const(0));
    }

    #[test]
    fn test_constant_sink() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Add(
            Box::new(SimpleExpr::Const(5)),
            Box::new(SimpleExpr::Var("x".into())),
        );
        let result = n.normalize_expr(e);
        // After sinking, constant should be on the right (and with x + 5, identity won't fire).
        if let SimpleExpr::Add(a, b) = &result {
            // Either already simplified or commuted.
            assert!(
                a.const_val().is_none() || b.const_val().is_some()
            );
        }
    }

    #[test]
    fn test_normalize_function_batch() {
        let exprs = vec![
            SimpleExpr::Add(Box::new(SimpleExpr::Const(1)), Box::new(SimpleExpr::Const(2))),
            SimpleExpr::Mul(Box::new(SimpleExpr::Var("n".into())), Box::new(SimpleExpr::Const(0))),
        ];
        let results = normalize_function(exprs);
        assert_eq!(results[0], SimpleExpr::Const(3));
        assert_eq!(results[1], SimpleExpr::Const(0));
    }

    #[test]
    fn cmp_ne_zero_is_preserved_outside_boolean_context() {
        // Regression test: `x != 0` must NOT be rewritten to `x` by the
        // context-free normalizer. The comparison yields exactly 0 or 1;
        // when used arithmetically (`(x != 0) + 1`), replacing it with `x`
        // changes the computed value (2 vs 8 for x = 7).
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::CmpNe(
            Box::new(SimpleExpr::Var("flag".into())),
            Box::new(SimpleExpr::Const(0)),
        );
        let result = n.normalize_expr(e.clone());
        assert_eq!(result, e, "x != 0 must survive normalization unchanged");
    }

    #[test]
    fn cmp_ne_zero_in_arithmetic_context_not_miscomputed() {
        // `(x != 0) + 1` must keep the comparison; folding it away would
        // change the value from (0|1)+1 to x+1.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Add(
            Box::new(SimpleExpr::CmpNe(
                Box::new(SimpleExpr::Var("x".into())),
                Box::new(SimpleExpr::Const(0)),
            )),
            Box::new(SimpleExpr::Const(1)),
        );
        let result = n.normalize_expr(e);
        // The CmpNe node must still be present somewhere in the result.
        fn contains_cmp_ne(e: &SimpleExpr) -> bool {
            match e {
                SimpleExpr::CmpNe(..) => true,
                SimpleExpr::Add(a, b)
                | SimpleExpr::Sub(a, b)
                | SimpleExpr::Mul(a, b)
                | SimpleExpr::Div(a, b)
                | SimpleExpr::And(a, b)
                | SimpleExpr::Or(a, b)
                | SimpleExpr::Xor(a, b)
                | SimpleExpr::Shl(a, b)
                | SimpleExpr::Shr(a, b) => contains_cmp_ne(a) || contains_cmp_ne(b),
                _ => false,
            }
        }
        assert!(
            contains_cmp_ne(&result),
            "(x != 0) + 1 lost its comparison: {result}"
        );
    }

    #[test]
    fn signed_div_pow2_not_strength_reduced_to_shift() {
        // Regression test: -7 / 2 == -3 (truncating) but -7 >> 1 == -4
        // (arithmetic shift), so Div-by-power-of-two must NOT become Shr.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Div(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(2)),
        );
        let result = n.normalize_expr(e.clone());
        assert!(
            !matches!(result, SimpleExpr::Shr(..)),
            "signed division must not be rewritten to a shift: {result}"
        );
        assert_eq!(result, e);
    }

    #[test]
    fn mul_pow2_strength_reduction_still_fires() {
        // The Mul → Shl rewrite is exact for signed values and must be kept.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Mul(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(8)),
        );
        let result = n.normalize_expr(e);
        assert!(matches!(result, SimpleExpr::Shl(..)), "got {result}");
    }

    #[test]
    fn test_cast_merge() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Cast(
            Box::new(SimpleExpr::Cast(
                Box::new(SimpleExpr::Var("v".into())),
                1, // inner: i8
            )),
            8, // outer: i64
        );
        let result = n.normalize_expr(e);
        // Outer widening cast should be eliminated; only inner i8 cast remains.
        assert!(matches!(result, SimpleExpr::Cast(_, 1)));
    }

    // ── Additional edge-case coverage ────────────────────────────────────────

    #[test]
    fn empty_function_normalization() {
        // Empty input must produce empty output and no diagnostics.
        let mut n = HlilExpressionNormalizer::full();
        let out = n.normalize_function(vec![]);
        assert!(out.is_empty());
        assert!(n.diagnostics.is_empty());
    }

    #[test]
    fn const_folding_overflow_uses_wrapping_semantics() {
        // i64::MAX + 1 must wrap to i64::MIN (not panic).
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Add(
            Box::new(SimpleExpr::Const(i64::MAX)),
            Box::new(SimpleExpr::Const(1)),
        );
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Const(i64::MIN));
    }

    #[test]
    fn const_folding_negation_of_min_does_not_panic() {
        // -(i64::MIN) wraps back to i64::MIN under wrapping_neg.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Neg(Box::new(SimpleExpr::Const(i64::MIN)));
        let result = n.normalize_expr(e);
        assert_eq!(result, SimpleExpr::Const(i64::MIN));
    }

    #[test]
    fn const_folding_div_by_zero_left_unfolded() {
        // x/0 must NOT be folded (would panic) — the original Div must remain.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Div(
            Box::new(SimpleExpr::Const(10)),
            Box::new(SimpleExpr::Const(0)),
        );
        let result = n.normalize_expr(e);
        assert!(matches!(result, SimpleExpr::Div(_, _)),
                "div by zero must not fold, got {result}");
    }

    #[test]
    fn shl_out_of_range_is_not_folded() {
        // Shifts ≥ 64 bits are unspecified — the folder must leave them alone.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Shl(
            Box::new(SimpleExpr::Const(1)),
            Box::new(SimpleExpr::Const(64)),
        );
        let result = n.normalize_expr(e);
        assert!(matches!(result, SimpleExpr::Shl(_, _)),
                "shl ≥ 64 must not fold");
        // Negative shift also must not fold.
        let e_neg = SimpleExpr::Shl(
            Box::new(SimpleExpr::Const(1)),
            Box::new(SimpleExpr::Const(-1)),
        );
        let result_neg = n.normalize_expr(e_neg);
        assert!(matches!(result_neg, SimpleExpr::Shl(_, _)));
    }

    #[test]
    fn mul_by_zero_folds_to_zero() {
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::Mul(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(0)),
        );
        assert_eq!(n.normalize_expr(e), SimpleExpr::Const(0));
        // Symmetric: 0 * x.
        let e2 = SimpleExpr::Mul(
            Box::new(SimpleExpr::Const(0)),
            Box::new(SimpleExpr::Var("x".into())),
        );
        assert_eq!(n.normalize_expr(e2), SimpleExpr::Const(0));
    }

    #[test]
    fn and_with_minus_one_is_identity() {
        // x & -1 (all ones) → x.
        let mut n = HlilExpressionNormalizer::full();
        let e = SimpleExpr::And(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(-1)),
        );
        assert_eq!(n.normalize_expr(e), SimpleExpr::Var("x".into()));
    }

    #[test]
    fn lightweight_normalizer_does_not_apply_strength_reduction() {
        // Lightweight has no StrengthReduction — `x * 4` must remain a Mul.
        let mut n = HlilExpressionNormalizer::lightweight();
        let e = SimpleExpr::Mul(
            Box::new(SimpleExpr::Var("x".into())),
            Box::new(SimpleExpr::Const(4)),
        );
        let result = n.normalize_expr(e);
        // Either Mul preserved or Const if folded — but NOT a Shl since
        // strength reduction isn't enabled.
        assert!(!matches!(result, SimpleExpr::Shl(_, _)));
    }

    #[test]
    fn deeply_nested_expression_does_not_stack_overflow() {
        // Build a chain of 1000 nested Adds — exceeds MAX_DEPTH=256.
        // Must not panic / overflow.
        let mut expr = SimpleExpr::Const(0);
        for _ in 0..1000 {
            expr = SimpleExpr::Add(Box::new(expr), Box::new(SimpleExpr::Const(1)));
        }
        let mut n = HlilExpressionNormalizer::full();
        // The result is some expression; we only care that it completed.
        let _ = n.normalize_expr(expr);
    }

    #[test]
    fn normalize_function_records_diagnostics_only_on_reduction() {
        let mut n = HlilExpressionNormalizer::full();
        // First expr reduces (1+2 → 3); second is an opaque variable that doesn't.
        let exprs = vec![
            SimpleExpr::Add(Box::new(SimpleExpr::Const(1)), Box::new(SimpleExpr::Const(2))),
            SimpleExpr::Var("opaque".into()),
        ];
        let out = n.normalize_function(exprs);
        assert_eq!(out[0], SimpleExpr::Const(3));
        assert_eq!(out[1], SimpleExpr::Var("opaque".into()));
        // Exactly one diagnostic — only the reducing expression.
        assert_eq!(n.diagnostics.len(), 1);
        assert!(n.diagnostics[0].reduced());
    }

    #[test]
    fn normalization_result_reduced_helper() {
        let r = NormalizationResult {
            pass: NormalizationPass::ConstantFolding,
            before_complexity: 5,
            after_complexity: 2,
            description: String::new(),
        };
        assert!(r.reduced());
        let r2 = NormalizationResult {
            pass: NormalizationPass::ConstantFolding,
            before_complexity: 3,
            after_complexity: 3,
            description: String::new(),
        };
        assert!(!r2.reduced());
    }

    #[test]
    fn const_folding_compare_eq_true_and_false() {
        let mut n = HlilExpressionNormalizer::full();
        let eq_true = SimpleExpr::CmpEq(
            Box::new(SimpleExpr::Const(7)),
            Box::new(SimpleExpr::Const(7)),
        );
        assert_eq!(n.normalize_expr(eq_true), SimpleExpr::Const(1));
        let eq_false = SimpleExpr::CmpEq(
            Box::new(SimpleExpr::Const(7)),
            Box::new(SimpleExpr::Const(8)),
        );
        assert_eq!(n.normalize_expr(eq_false), SimpleExpr::Const(0));
    }
}
