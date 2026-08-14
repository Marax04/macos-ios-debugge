//! MBA expression complexity scoring.
//!
//! Provides multi-dimensional complexity metrics for Mixed Boolean Arithmetic
//! expressions: structural depth, operator diversity, boolean/arithmetic
//! operator mixing ratio, and an overall obfuscation score.
//!
//! These scores are used by the deobfuscation pipeline to prioritise which
//! expressions to simplify first, and to measure how much an expression has
//! been reduced after simplification.

use std::collections::HashMap;
use std::fmt;

use crate::MbaExpr;

// ---------------------------------------------------------------------------
// ExprDepth
// ---------------------------------------------------------------------------

/// Measures the structural depth of an [`MbaExpr`] tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExprDepth(pub usize);

impl ExprDepth {
    /// Compute the maximum depth of `expr`.
    #[must_use]
    pub fn of(expr: &MbaExpr) -> Self {
        Self(max_depth(expr))
    }

    /// Return the raw depth value.
    #[must_use]
    pub const fn value(self) -> usize {
        self.0
    }

    /// Returns `true` if depth exceeds `threshold`.
    #[must_use]
    pub const fn exceeds(self, threshold: usize) -> bool {
        self.0 > threshold
    }
}

impl fmt::Display for ExprDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "depth={}", self.0)
    }
}

fn max_depth(expr: &MbaExpr) -> usize {
    match expr {
        MbaExpr::Const(_) | MbaExpr::Var(_) => 0,
        MbaExpr::Neg(e) | MbaExpr::Not(e) | MbaExpr::Shl(e, _) | MbaExpr::Shr(e, _) | MbaExpr::Sar(e, _) => {
            1 + max_depth(e)
        }
        MbaExpr::Add(l, r)
        | MbaExpr::Sub(l, r)
        | MbaExpr::Mul(l, r)
        | MbaExpr::And(l, r)
        | MbaExpr::Or(l, r)
        | MbaExpr::Xor(l, r) => 1 + max_depth(l).max(max_depth(r)),
    }
}

// ---------------------------------------------------------------------------
// OperatorCounts
// ---------------------------------------------------------------------------

/// Counts of each operator kind in an expression tree.
#[derive(Debug, Clone, Default)]
pub struct OperatorCounts {
    /// Number of Add nodes.
    pub add: usize,
    /// Number of Sub nodes.
    pub sub: usize,
    /// Number of Mul nodes.
    pub mul: usize,
    /// Number of Neg nodes.
    pub neg: usize,
    /// Number of And nodes.
    pub and: usize,
    /// Number of Or nodes.
    pub or: usize,
    /// Number of Xor nodes.
    pub xor: usize,
    /// Number of Not nodes.
    pub not: usize,
    /// Number of Shl/Shr/Sar shift nodes.
    pub shift: usize,
    /// Number of Const leaves.
    pub consts: usize,
    /// Number of Var leaves.
    pub vars: usize,
}

impl OperatorCounts {
    /// Count all operators in `expr`.
    #[must_use]
    pub fn of(expr: &MbaExpr) -> Self {
        let mut c = Self::default();
        count_ops(expr, &mut c);
        c
    }

    /// Total arithmetic operators (Add + Sub + Mul + Neg).
    #[must_use]
    pub const fn arithmetic(&self) -> usize {
        self.add + self.sub + self.mul + self.neg
    }

    /// Total bitwise operators (And + Or + Xor + Not + Shift).
    #[must_use]
    pub const fn bitwise(&self) -> usize {
        self.and + self.or + self.xor + self.not + self.shift
    }

    /// Total operator nodes (excludes leaves).
    #[must_use]
    pub const fn total_ops(&self) -> usize {
        self.arithmetic() + self.bitwise()
    }

    /// Number of distinct operator types used.
    #[must_use]
    pub fn distinct_ops(&self) -> usize {
        [
            self.add > 0,
            self.sub > 0,
            self.mul > 0,
            self.neg > 0,
            self.and > 0,
            self.or > 0,
            self.xor > 0,
            self.not > 0,
            self.shift > 0,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }

    /// Mixing ratio: fraction of operators that cross the arithmetic/bitwise
    /// boundary.  Range: 0.0 (pure arithmetic or pure bitwise) to 1.0 (fully
    /// mixed).
    #[must_use]
    pub fn mixing_ratio(&self) -> f64 {
        let arith = self.arithmetic();
        let bitw = self.bitwise();
        let total = arith + bitw;
        if total == 0 {
            return 0.0;
        }
        let min = arith.min(bitw);
        let max = arith.max(bitw);
        if max == 0 {
            0.0
        } else {
            2.0 * min as f64 / total as f64
        }
    }
}

fn count_ops(expr: &MbaExpr, c: &mut OperatorCounts) {
    match expr {
        MbaExpr::Const(_) => c.consts += 1,
        MbaExpr::Var(_) => c.vars += 1,
        MbaExpr::Add(l, r) => { c.add += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::Sub(l, r) => { c.sub += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::Mul(l, r) => { c.mul += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::And(l, r) => { c.and += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::Or(l, r) => { c.or += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::Xor(l, r) => { c.xor += 1; count_ops(l, c); count_ops(r, c); }
        MbaExpr::Neg(e) => { c.neg += 1; count_ops(e, c); }
        MbaExpr::Not(e) => { c.not += 1; count_ops(e, c); }
        MbaExpr::Shl(e, _) | MbaExpr::Shr(e, _) | MbaExpr::Sar(e, _) => {
            c.shift += 1;
            count_ops(e, c);
        }
    }
}

// ---------------------------------------------------------------------------
// ComplexityScore
// ---------------------------------------------------------------------------

/// A multi-dimensional complexity score for an MBA expression.
#[derive(Debug, Clone)]
pub struct ComplexityScore {
    /// Total number of nodes (size).
    pub node_count: usize,
    /// Maximum tree depth.
    pub depth: usize,
    /// Number of arithmetic operators.
    pub arithmetic_ops: usize,
    /// Number of bitwise operators.
    pub bitwise_ops: usize,
    /// Number of distinct operator types.
    pub distinct_op_types: usize,
    /// Mixing ratio in [0.0, 1.0].
    pub mixing_ratio: f64,
    /// Number of unique variables.
    pub variable_count: usize,
    /// Weighted obfuscation score (see [`ComplexityScore::obfuscation_score`]).
    pub obfuscation_score: f64,
}

impl ComplexityScore {
    /// Compute the score for `expr`.
    #[must_use]
    pub fn compute(expr: &MbaExpr) -> Self {
        let node_count = expr.complexity();
        let depth = ExprDepth::of(expr).value();
        let ops = OperatorCounts::of(expr);
        let arithmetic_ops = ops.arithmetic();
        let bitwise_ops = ops.bitwise();
        let distinct_op_types = ops.distinct_ops();
        let mixing_ratio = ops.mixing_ratio();
        let variable_count = expr.vars().len();
        let obfuscation_score = compute_obfuscation_score(
            node_count, depth, arithmetic_ops, bitwise_ops,
            distinct_op_types, mixing_ratio, variable_count,
        );
        Self {
            node_count,
            depth,
            arithmetic_ops,
            bitwise_ops,
            distinct_op_types,
            mixing_ratio,
            variable_count,
            obfuscation_score,
        }
    }

    /// Returns `true` if this expression is likely MBA-obfuscated.
    ///
    /// An expression is flagged as MBA-obfuscated when:
    /// - The mixing ratio is ≥ 0.2 (both arithmetic and bitwise ops present), and
    /// - The total node count is ≥ 5, and
    /// - At least 2 distinct operator types are used.
    #[must_use]
    pub fn is_likely_mba(&self) -> bool {
        self.mixing_ratio >= 0.2 && self.node_count >= 5 && self.distinct_op_types >= 2
    }

    /// Relative complexity compared to `other`.  Returns > 1.0 if `self` is
    /// more complex, < 1.0 if less complex.
    #[must_use]
    pub fn relative_to(&self, other: &Self) -> f64 {
        if other.obfuscation_score == 0.0 {
            return 1.0;
        }
        self.obfuscation_score / other.obfuscation_score
    }
}

fn compute_obfuscation_score(
    node_count: usize,
    depth: usize,
    arith: usize,
    bitwise: usize,
    distinct: usize,
    mixing: f64,
    vars: usize,
) -> f64 {
    // Weighted formula:
    // - Size contributes logarithmically (base 2)
    // - Depth contributes linearly
    // - Mixing is the strongest signal
    // - Distinct operator diversity contributes
    let size_score = if node_count <= 1 {
        0.0
    } else {
        (node_count as f64).log2()
    };
    let depth_score = depth as f64 * 0.5;
    let mixing_score = mixing * 10.0;
    let diversity_score = distinct as f64 * 0.8;
    let var_score = vars as f64 * 0.3;
    let arith_score = arith as f64 * 0.2;
    let bitwise_score = bitwise as f64 * 0.2;

    size_score + depth_score + mixing_score + diversity_score + var_score + arith_score + bitwise_score
}

impl fmt::Display for ComplexityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "score={:.2} nodes={} depth={} arith={} bitwise={} mixing={:.2} vars={}",
            self.obfuscation_score,
            self.node_count,
            self.depth,
            self.arithmetic_ops,
            self.bitwise_ops,
            self.mixing_ratio,
            self.variable_count,
        )
    }
}

// ---------------------------------------------------------------------------
// MbaComplexityScorer
// ---------------------------------------------------------------------------

/// Configuration for the complexity scorer.
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// Minimum obfuscation score to flag an expression as needing simplification.
    pub min_score_threshold: f64,
    /// Maximum tree depth before flagging as deeply nested.
    pub deep_nesting_threshold: usize,
    /// Minimum node count to consider an expression non-trivial.
    pub min_node_count: usize,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            min_score_threshold: 5.0,
            deep_nesting_threshold: 8,
            min_node_count: 4,
        }
    }
}

/// Per-expression scoring result from the `MbaComplexityScorer`.
#[derive(Debug, Clone)]
pub struct ExprScoringResult {
    /// The expression that was scored.
    pub expr: MbaExpr,
    /// The computed complexity score.
    pub score: ComplexityScore,
    /// Whether the scorer flagged this expression for simplification.
    pub needs_simplification: bool,
    /// Whether the expression is likely MBA-obfuscated.
    pub is_mba: bool,
    /// Priority hint (higher = should be simplified first).
    pub priority: u32,
}

impl ExprScoringResult {
    /// Returns `true` if this expression was flagged as deeply nested.
    #[must_use]
    pub const fn is_deep(&self) -> bool {
        self.score.depth > 8
    }
}

/// The primary complexity scoring engine.
///
/// Scores a batch of expressions, ranks them by obfuscation score, and
/// returns the prioritised list for the deobfuscation pipeline.
#[derive(Debug, Clone)]
pub struct MbaComplexityScorer {
    config: ScorerConfig,
}

impl MbaComplexityScorer {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: ScorerConfig::default() }
    }

    /// Create with custom configuration.
    #[must_use]
    pub const fn with_config(config: ScorerConfig) -> Self {
        Self { config }
    }

    /// Score a single expression.
    #[must_use]
    pub fn score(&self, expr: MbaExpr) -> ExprScoringResult {
        let cs = ComplexityScore::compute(&expr);
        let needs_simplification = cs.obfuscation_score >= self.config.min_score_threshold
            && cs.node_count >= self.config.min_node_count;
        let is_mba = cs.is_likely_mba();
        let priority = priority_from_score(&cs);
        ExprScoringResult { expr, score: cs, needs_simplification, is_mba, priority }
    }

    /// Score a batch of expressions and return them sorted by descending priority.
    #[must_use]
    pub fn score_batch(&self, exprs: Vec<MbaExpr>) -> Vec<ExprScoringResult> {
        let mut results: Vec<ExprScoringResult> = exprs.into_iter().map(|e| self.score(e)).collect();
        results.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));
        results
    }

    /// Score a function by evaluating all sub-expressions under a given address.
    ///
    /// Returns a `ProfileResult` that aggregates scores across the function.
    #[must_use]
    pub fn score_function(
        &self,
        function_address: u64,
        exprs: Vec<MbaExpr>,
    ) -> ProfileResult {
        score_function(self, function_address, exprs)
    }

    /// Return all expressions whose obfuscation score exceeds the threshold.
    #[must_use]
    pub fn filter_mba(&self, exprs: Vec<MbaExpr>) -> Vec<ExprScoringResult> {
        self.score_batch(exprs)
            .into_iter()
            .filter(|r| r.is_mba)
            .collect()
    }
}

impl Default for MbaComplexityScorer {
    fn default() -> Self {
        Self::new()
    }
}

fn priority_from_score(cs: &ComplexityScore) -> u32 {
    // Truncate the float score to an integer priority in 0..u32::MAX.
    let raw = cs.obfuscation_score * 100.0;
    raw.clamp(0.0, f64::from(u32::MAX)) as u32
}

// ---------------------------------------------------------------------------
// score_function — free function
// ---------------------------------------------------------------------------

/// Compute aggregate MBA complexity metrics for a function.
///
/// Used by pass infrastructure to get a quick complexity profile without
/// constructing a full `MbaComplexityScorer`.
#[must_use]
pub fn score_function(
    scorer: &MbaComplexityScorer,
    function_address: u64,
    exprs: Vec<MbaExpr>,
) -> ProfileResult {
    let total = exprs.len();
    let results = scorer.score_batch(exprs);
    let mba_count = results.iter().filter(|r| r.is_mba).count();
    let max_score = results.iter().map(|r| r.score.obfuscation_score).fold(0.0f64, f64::max);
    let avg_score = if total == 0 {
        0.0
    } else {
        results.iter().map(|r| r.score.obfuscation_score).sum::<f64>() / total as f64
    };
    let needs_simplification_count = results.iter().filter(|r| r.needs_simplification).count();
    ProfileResult {
        function_address,
        total_expressions: total,
        mba_expression_count: mba_count,
        max_obfuscation_score: max_score,
        avg_obfuscation_score: avg_score,
        needs_simplification_count,
        results,
    }
}

// ---------------------------------------------------------------------------
// ProfileResult
// ---------------------------------------------------------------------------

/// Aggregated complexity profile for a function.
#[derive(Debug, Clone)]
pub struct ProfileResult {
    /// Function start address.
    pub function_address: u64,
    /// Total expressions scored.
    pub total_expressions: usize,
    /// Expressions identified as MBA-obfuscated.
    pub mba_expression_count: usize,
    /// Maximum single-expression obfuscation score.
    pub max_obfuscation_score: f64,
    /// Average obfuscation score across all expressions.
    pub avg_obfuscation_score: f64,
    /// Expressions that need simplification.
    pub needs_simplification_count: usize,
    /// Per-expression results, sorted by descending priority.
    pub results: Vec<ExprScoringResult>,
}

impl ProfileResult {
    /// Returns `true` if the function contains any MBA-obfuscated expressions.
    #[must_use]
    pub const fn has_mba(&self) -> bool {
        self.mba_expression_count > 0
    }

    /// Returns `true` if more than half the expressions are MBA.
    #[must_use]
    pub const fn is_heavily_obfuscated(&self) -> bool {
        self.total_expressions > 0
            && self.mba_expression_count * 2 > self.total_expressions
    }

    /// Obfuscation density: fraction of expressions that are MBA (0.0–1.0).
    #[must_use]
    pub fn obfuscation_density(&self) -> f64 {
        if self.total_expressions == 0 {
            return 0.0;
        }
        self.mba_expression_count as f64 / self.total_expressions as f64
    }
}

impl fmt::Display for ProfileResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Function {:#010x}:", self.function_address)?;
        writeln!(f, "  Total expressions   : {}", self.total_expressions)?;
        writeln!(f, "  MBA expressions     : {}", self.mba_expression_count)?;
        writeln!(f, "  Obfuscation density : {:.1}%", self.obfuscation_density() * 100.0)?;
        writeln!(f, "  Max score           : {:.2}", self.max_obfuscation_score)?;
        writeln!(f, "  Avg score           : {:.2}", self.avg_obfuscation_score)?;
        write!(f, "  Needs simplification: {}", self.needs_simplification_count)
    }
}

// ---------------------------------------------------------------------------
// Histogram helper
// ---------------------------------------------------------------------------

/// Build a histogram of complexity scores bucketed by integer range.
#[must_use]
pub fn score_histogram(results: &[ExprScoringResult], bucket_size: u32) -> HashMap<u32, usize> {
    let mut hist = HashMap::new();
    for r in results {
        let bucket = (r.priority / bucket_size.max(1)) * bucket_size.max(1);
        *hist.entry(bucket).or_insert(0) += 1;
    }
    hist
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MbaExpr;

    fn var(s: &str) -> MbaExpr { MbaExpr::Var(s.to_string()) }
    fn con(v: i64) -> MbaExpr { MbaExpr::Const(v) }

    #[test]
    fn const_complexity_is_1() {
        let score = ComplexityScore::compute(&con(42));
        assert_eq!(score.node_count, 1);
    }

    #[test]
    fn simple_add_not_mba() {
        let expr = MbaExpr::mk_add(var("x"), var("y"));
        let score = ComplexityScore::compute(&expr);
        assert!(!score.is_likely_mba());
    }

    #[test]
    fn mixed_expr_is_mba() {
        // (x & y) + (x | y) — mix of arithmetic and bitwise
        let x = var("x");
        let y = var("y");
        let expr = MbaExpr::mk_add(
            MbaExpr::mk_and(x.clone(), y.clone()),
            MbaExpr::mk_or(x, y),
        );
        let score = ComplexityScore::compute(&expr);
        assert!(score.mixing_ratio > 0.0);
        assert!(score.is_likely_mba());
    }

    #[test]
    fn expr_depth_of_chain() {
        // ((x + y) + z) + w  → depth 3
        let x = var("x");
        let y = var("y");
        let z = var("z");
        let w = var("w");
        let expr = MbaExpr::mk_add(MbaExpr::mk_add(MbaExpr::mk_add(x, y), z), w);
        assert_eq!(ExprDepth::of(&expr).value(), 3);
    }

    #[test]
    fn scorer_flags_mba() {
        let x = var("x");
        let y = var("y");
        let expr = MbaExpr::mk_add(
            MbaExpr::mk_and(x.clone(), y.clone()),
            MbaExpr::mk_or(x, y),
        );
        let scorer = MbaComplexityScorer::new();
        let result = scorer.score(expr);
        assert!(result.is_mba);
    }

    #[test]
    fn profile_result_density() {
        let x = var("x");
        let y = var("y");
        let mba_expr = MbaExpr::mk_add(
            MbaExpr::mk_and(x.clone(), y.clone()),
            MbaExpr::mk_or(x, y),
        );
        let plain_expr = MbaExpr::mk_add(var("a"), con(1));
        let scorer = MbaComplexityScorer::new();
        let profile = scorer.score_function(0x1000, vec![mba_expr, plain_expr]);
        assert!(profile.total_expressions == 2);
        assert!(profile.obfuscation_density() > 0.0);
    }

    #[test]
    fn score_batch_sorted_by_priority() {
        let simple = MbaExpr::mk_add(var("a"), con(1));
        let x = var("x");
        let y = var("y");
        let complex = MbaExpr::mk_add(MbaExpr::mk_and(x.clone(), y.clone()), MbaExpr::mk_or(x, y));
        let scorer = MbaComplexityScorer::new();
        let batch = scorer.score_batch(vec![simple, complex]);
        // Complex expr should come first (higher priority)
        assert!(batch[0].priority >= batch[1].priority);
    }
}
