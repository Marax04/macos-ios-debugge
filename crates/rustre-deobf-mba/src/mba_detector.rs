//! MBA (Mixed Boolean-Arithmetic) expression detector.
//!
//! Detects MBA obfuscation in IR expression trees by recognizing patterns
//! like `x+y = (x XOR y) + 2*(x AND y)`, measuring tree complexity,
//! and scoring MBA likelihood.

use std::collections::HashMap;
use std::fmt;

use crate::MbaExpr;

// ─── MbaPatternKind ───────────────────────────────────────────────────────────

/// The kind of MBA pattern detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MbaPatternKind {
    /// x + y = (x ^ y) + 2*(x & y)
    AddAsXorAnd,
    /// x - y = x + (~y + 1)
    SubAsAddNot,
    /// NOT x = (-1) ^ x
    NotAsXorMinusOne,
    /// x | y = (x ^ y) + (x & y)
    OrAsXorAnd,
    /// x & y = (x + y - (x | y))
    AndAsAddSubOr,
    /// x ^ y = (x | y) - (x & y)
    XorAsOrMinusAnd,
    /// x = x & -1  (identity with mask)
    IdentityMask,
    /// 0 = x ^ x
    XorSelf,
    /// 0 = x & ~x
    AndNot,
    /// -1 = x | ~x
    OrNot,
    /// Nested MBA (MBA inside MBA)
    NestedMba,
    /// Unknown / uncategorized pattern
    Unknown,
}

impl fmt::Display for MbaPatternKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AddAsXorAnd => "add_as_xor_and",
            Self::SubAsAddNot => "sub_as_add_not",
            Self::NotAsXorMinusOne => "not_as_xor_minus_one",
            Self::OrAsXorAnd => "or_as_xor_and",
            Self::AndAsAddSubOr => "and_as_add_sub_or",
            Self::XorAsOrMinusAnd => "xor_as_or_minus_and",
            Self::IdentityMask => "identity_mask",
            Self::XorSelf => "xor_self",
            Self::AndNot => "and_not",
            Self::OrNot => "or_not",
            Self::NestedMba => "nested_mba",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ─── MbaPattern ───────────────────────────────────────────────────────────────

/// A single detected MBA pattern within an expression tree.
#[derive(Debug, Clone)]
pub struct MbaPattern {
    /// The pattern kind.
    pub kind: MbaPatternKind,
    /// The sub-expression where the pattern was found.
    pub expr: MbaExpr,
    /// Depth in the original tree where the pattern was found.
    pub depth: usize,
    /// The variables involved in this pattern.
    pub vars: Vec<String>,
    /// Complexity of the matched sub-expression.
    pub complexity: usize,
}

impl MbaPattern {
    fn new(kind: MbaPatternKind, expr: MbaExpr, depth: usize) -> Self {
        let vars = expr.vars();
        let complexity = expr.complexity();
        Self { kind, expr, depth, vars, complexity }
    }
}

// ─── ExprTree helpers ─────────────────────────────────────────────────────────

/// Lightweight representation of the structure of an expression tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExprTreeNodeKind {
    Const, Var,
    Add, Sub, Mul, Neg,
    And, Or, Xor, Not,
    Shl, Shr, Sar,
}

impl ExprTreeNodeKind {
    #[must_use] 
    pub const fn from_expr(e: &MbaExpr) -> Self {
        match e {
            MbaExpr::Const(_) => Self::Const,
            MbaExpr::Var(_)   => Self::Var,
            MbaExpr::Add(_,_) => Self::Add,
            MbaExpr::Sub(_,_) => Self::Sub,
            MbaExpr::Mul(_,_) => Self::Mul,
            MbaExpr::Neg(_)   => Self::Neg,
            MbaExpr::And(_,_) => Self::And,
            MbaExpr::Or(_,_)  => Self::Or,
            MbaExpr::Xor(_,_) => Self::Xor,
            MbaExpr::Not(_)   => Self::Not,
            MbaExpr::Shl(_,_) => Self::Shl,
            MbaExpr::Shr(_,_) => Self::Shr,
            MbaExpr::Sar(_,_) => Self::Sar,
        }
    }

    /// Returns true if this is an arithmetic operator.
    #[must_use] 
    pub const fn is_arithmetic(self) -> bool {
        matches!(self, Self::Add | Self::Sub | Self::Mul | Self::Neg)
    }

    /// Returns true if this is a bitwise operator.
    #[must_use] 
    pub const fn is_bitwise(self) -> bool {
        matches!(self, Self::And | Self::Or | Self::Xor | Self::Not | Self::Shl | Self::Shr | Self::Sar)
    }
}

/// Summary tree structure for an expression.
#[derive(Debug, Clone, Copy)]
pub struct ExprTree {
    /// Root node kind.
    pub root: ExprTreeNodeKind,
    /// Total node count.
    pub size: usize,
    /// Maximum depth.
    pub depth: usize,
    /// Count of arithmetic operators.
    pub arith_count: usize,
    /// Count of bitwise operators.
    pub bitwise_count: usize,
    /// Distinct variable count.
    pub var_count: usize,
    /// Number of MBA-indicative operator transitions (arith→bitwise or bitwise→arith).
    pub transitions: usize,
}

impl ExprTree {
    /// Compute the `ExprTree` summary of an `MbaExpr`.
    #[must_use] 
    pub fn analyze(expr: &MbaExpr) -> Self {
        let mut arith = 0usize;
        let mut bitwise = 0usize;
        let mut size = 0usize;
        let mut depth = 0usize;
        let mut transitions = 0usize;
        let mut vars: Vec<String> = Vec::new();
        count_nodes(expr, 0, &mut size, &mut depth, &mut arith, &mut bitwise, &mut transitions, &mut vars, ExprTreeNodeKind::Const);
        vars.dedup();
        Self {
            root: ExprTreeNodeKind::from_expr(expr),
            size,
            depth,
            arith_count: arith,
            bitwise_count: bitwise,
            var_count: vars.len(),
            transitions,
        }
    }

    /// Whether the tree has MBA-like mixing (both arith and bitwise operators).
    #[must_use] 
    pub const fn has_mixing(self) -> bool {
        self.arith_count > 0 && self.bitwise_count > 0
    }
}

fn count_nodes(
    expr: &MbaExpr,
    current_depth: usize,
    size: &mut usize,
    max_depth: &mut usize,
    arith: &mut usize,
    bitwise: &mut usize,
    transitions: &mut usize,
    vars: &mut Vec<String>,
    parent_kind: ExprTreeNodeKind,
) {
    // Guard against stack overflow from adversarially deep expression trees.
    const MAX_TREE_DEPTH: usize = 512;
    if current_depth >= MAX_TREE_DEPTH {
        return;
    }
    *size += 1;
    if current_depth > *max_depth { *max_depth = current_depth; }
    let kind = ExprTreeNodeKind::from_expr(expr);
    if kind.is_arithmetic() { *arith += 1; }
    if kind.is_bitwise() { *bitwise += 1; }
    // Transition check.
    if (parent_kind.is_arithmetic() && kind.is_bitwise()) ||
       (parent_kind.is_bitwise() && kind.is_arithmetic()) {
        *transitions += 1;
    }
    if let MbaExpr::Var(n) = expr
        && !vars.contains(n) { vars.push(n.clone()); }
    match expr {
        MbaExpr::Const(_) | MbaExpr::Var(_) => {}
        MbaExpr::Neg(e) | MbaExpr::Not(e) |
        MbaExpr::Shl(e,_) | MbaExpr::Shr(e,_) | MbaExpr::Sar(e,_) => {
            count_nodes(e, current_depth+1, size, max_depth, arith, bitwise, transitions, vars, kind);
        }
        MbaExpr::Add(l,r) | MbaExpr::Sub(l,r) | MbaExpr::Mul(l,r) |
        MbaExpr::And(l,r) | MbaExpr::Or(l,r) | MbaExpr::Xor(l,r) => {
            count_nodes(l, current_depth+1, size, max_depth, arith, bitwise, transitions, vars, kind);
            count_nodes(r, current_depth+1, size, max_depth, arith, bitwise, transitions, vars, kind);
        }
    }
}

// ─── MbaScore ─────────────────────────────────────────────────────────────────

/// MBA obfuscation likelihood score.
#[derive(Debug, Clone)]
pub struct MbaScore {
    /// Score in range 0..=100.
    pub score: u8,
    /// Explanation of what contributed to the score.
    pub reasons: Vec<String>,
    /// The patterns that were found.
    pub patterns: Vec<MbaPattern>,
    /// Tree analysis summary.
    pub tree: ExprTree,
}

impl MbaScore {
    /// Whether the expression is likely obfuscated (score >= 60).
    #[must_use] 
    pub const fn is_likely_obfuscated(&self) -> bool {
        self.score >= 60
    }

    /// Whether the expression is highly likely obfuscated (score >= 80).
    #[must_use] 
    pub const fn is_highly_obfuscated(&self) -> bool {
        self.score >= 80
    }
}

impl fmt::Display for MbaScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MbaScore({}/100", self.score)?;
        if !self.patterns.is_empty() {
            write!(f, ", {} patterns", self.patterns.len())?;
        }
        write!(f, ")")
    }
}

// ─── PatternLibrary ───────────────────────────────────────────────────────────

/// Library of structural pattern matchers.
pub struct PatternLibrary {
    /// Named patterns with associated matchers.
    matchers: Vec<(&'static str, MbaPatternKind, fn(&MbaExpr) -> bool)>,
}

impl PatternLibrary {
    /// Build the default pattern library.
    #[must_use] 
    pub fn default_library() -> Self {
        Self {
            matchers: vec![
                ("add_as_xor_and", MbaPatternKind::AddAsXorAnd, match_add_as_xor_and),
                ("sub_as_add_not", MbaPatternKind::SubAsAddNot, match_sub_as_add_not),
                ("not_as_xor",    MbaPatternKind::NotAsXorMinusOne, match_not_as_xor),
                ("or_as_xor_and", MbaPatternKind::OrAsXorAnd, match_or_as_xor_and),
                ("xor_self",      MbaPatternKind::XorSelf, match_xor_self),
                ("and_not",       MbaPatternKind::AndNot, match_and_not),
                ("or_not",        MbaPatternKind::OrNot, match_or_not),
            ],
        }
    }

    /// Try to match all patterns against `expr`.  Returns matched patterns.
    #[must_use] 
    pub fn match_patterns(&self, expr: &MbaExpr, depth: usize) -> Vec<MbaPattern> {
        self.matchers.iter()
            .filter_map(|(_, kind, matcher)| {
                if matcher(expr) {
                    Some(MbaPattern::new(*kind, expr.clone(), depth))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── Pattern matching predicates ─────────────────────────────────────────────

fn match_add_as_xor_and(e: &MbaExpr) -> bool {
    // (x ^ y) + 2*(x & y) or (x ^ y) + (x & y) + (x & y)
    if let MbaExpr::Add(l, r) = e {
        // Check left = XOR, right = Mul(2, AND) or AND
        if matches!(l.as_ref(), MbaExpr::Xor(_,_))
            && let MbaExpr::Mul(ml, mr) = r.as_ref() {
                if matches!(ml.as_ref(), MbaExpr::Const(2)) && matches!(mr.as_ref(), MbaExpr::And(_,_)) {
                    return true;
                }
                if matches!(mr.as_ref(), MbaExpr::Const(2)) && matches!(ml.as_ref(), MbaExpr::And(_,_)) {
                    return true;
                }
            }
        // Also commuted: right = XOR, left = Mul(2, AND).
        //
        // Both operand orders of the multiply, exactly like the branch above:
        // this used to accept only `Mul(Const(2), And)`, so the semantically
        // identical `(x & y) * 2 + (x ^ y)` missed the pattern bonus and the
        // verdict flipped (score 45 / not-obfuscated instead of 70 / obfuscated).
        // `lib.rs::try_xor_plus_2and` checks both sides on every operand.
        if matches!(r.as_ref(), MbaExpr::Xor(_,_))
            && let MbaExpr::Mul(ml, mr) = l.as_ref() {
                if matches!(ml.as_ref(), MbaExpr::Const(2)) && matches!(mr.as_ref(), MbaExpr::And(_,_)) {
                    return true;
                }
                if matches!(mr.as_ref(), MbaExpr::Const(2)) && matches!(ml.as_ref(), MbaExpr::And(_,_)) {
                    return true;
                }
            }
    }
    false
}

fn match_sub_as_add_not(e: &MbaExpr) -> bool {
    // x + (~y + 1)
    if let MbaExpr::Add(_, r) = e
        && let MbaExpr::Add(rr, rc) = r.as_ref() {
            return matches!(rr.as_ref(), MbaExpr::Not(_)) && matches!(rc.as_ref(), MbaExpr::Const(1));
        }
    false
}

fn match_not_as_xor(e: &MbaExpr) -> bool {
    // (-1) ^ x  or  x ^ (-1)
    if let MbaExpr::Xor(l, r) = e {
        return matches!(l.as_ref(), MbaExpr::Const(-1)) || matches!(r.as_ref(), MbaExpr::Const(-1));
    }
    false
}

fn match_or_as_xor_and(e: &MbaExpr) -> bool {
    // (x ^ y) + (x & y)
    if let MbaExpr::Add(l, r) = e {
        let left_xor = matches!(l.as_ref(), MbaExpr::Xor(_,_));
        let right_and = matches!(r.as_ref(), MbaExpr::And(_,_));
        let left_and = matches!(l.as_ref(), MbaExpr::And(_,_));
        let right_xor = matches!(r.as_ref(), MbaExpr::Xor(_,_));
        return (left_xor && right_and) || (left_and && right_xor);
    }
    false
}

fn match_xor_self(e: &MbaExpr) -> bool {
    if let MbaExpr::Xor(l, r) = e { return l == r; }
    false
}

fn match_and_not(e: &MbaExpr) -> bool {
    // x & ~x  or  ~x & x
    if let MbaExpr::And(l, r) = e {
        if let MbaExpr::Not(inner) = r.as_ref() { return inner.as_ref() == l.as_ref(); }
        if let MbaExpr::Not(inner) = l.as_ref() { return inner.as_ref() == r.as_ref(); }
    }
    false
}

fn match_or_not(e: &MbaExpr) -> bool {
    // x | ~x  or  ~x | x
    if let MbaExpr::Or(l, r) = e {
        if let MbaExpr::Not(inner) = r.as_ref() { return inner.as_ref() == l.as_ref(); }
        if let MbaExpr::Not(inner) = l.as_ref() { return inner.as_ref() == r.as_ref(); }
    }
    false
}

// ─── MbaDetector ─────────────────────────────────────────────────────────────

/// Main MBA detection engine.
pub struct MbaDetector {
    /// Pattern library used for matching.
    pub library: PatternLibrary,
    /// Minimum complexity to consider an expression for MBA detection.
    pub min_complexity: usize,
    /// Minimum tree depth to apply deeper heuristics.
    pub min_depth: usize,
}

impl Default for MbaDetector {
    fn default() -> Self {
        Self {
            library: PatternLibrary::default_library(),
            min_complexity: 5,
            min_depth: 2,
        }
    }
}

impl MbaDetector {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Analyze `expr` and return an [`MbaScore`].
    #[must_use] 
    pub fn score(&self, expr: &MbaExpr) -> MbaScore {
        let tree = ExprTree::analyze(expr);
        let mut reasons = Vec::new();
        let mut raw_score = 0u32;

        // Collect all patterns recursively.
        let patterns = self.collect_patterns(expr, 0);

        // Scoring heuristics.
        if tree.has_mixing() {
            raw_score += 30;
            reasons.push(format!("arith/bitwise mixing (a={}, b={})", tree.arith_count, tree.bitwise_count));
        }
        if tree.transitions >= 2 {
            raw_score += 15;
            reasons.push(format!("{} operator-domain transitions", tree.transitions));
        }
        if tree.size >= 10 {
            raw_score += 10;
            reasons.push(format!("large expression ({} nodes)", tree.size));
        }
        if tree.depth >= 5 {
            raw_score += 10;
            reasons.push(format!("deep tree (depth {})", tree.depth));
        }
        for p in &patterns {
            match p.kind {
                MbaPatternKind::AddAsXorAnd => { raw_score += 25; reasons.push("add_as_xor_and".to_owned()); }
                MbaPatternKind::SubAsAddNot => { raw_score += 20; reasons.push("sub_as_add_not".to_owned()); }
                MbaPatternKind::OrAsXorAnd  => { raw_score += 20; reasons.push("or_as_xor_and".to_owned()); }
                MbaPatternKind::NotAsXorMinusOne => { raw_score += 15; reasons.push("not_as_xor".to_owned()); }
                MbaPatternKind::XorSelf     => { raw_score += 10; reasons.push("xor_self".to_owned()); }
                MbaPatternKind::AndNot      => { raw_score += 10; reasons.push("and_not".to_owned()); }
                MbaPatternKind::OrNot       => { raw_score += 10; reasons.push("or_not".to_owned()); }
                _ => { raw_score += 5; }
            }
        }

        // Nested MBA bonus.
        if patterns.iter().any(|p| p.depth > 2) {
            raw_score += 10;
            reasons.push("deeply nested patterns".to_owned());
        }

        let score = raw_score.min(100) as u8;
        MbaScore { score, reasons, patterns, tree }
    }

    fn collect_patterns(&self, expr: &MbaExpr, depth: usize) -> Vec<MbaPattern> {
        // Guard against stack overflow from adversarially deep expression trees.
        const MAX_PATTERN_DEPTH: usize = 512;
        if depth >= MAX_PATTERN_DEPTH {
            return Vec::new();
        }
        let mut all = self.library.match_patterns(expr, depth);
        match expr {
            MbaExpr::Const(_) | MbaExpr::Var(_) => {}
            MbaExpr::Neg(e) | MbaExpr::Not(e) |
            MbaExpr::Shl(e,_) | MbaExpr::Shr(e,_) | MbaExpr::Sar(e,_) => {
                all.extend(self.collect_patterns(e, depth+1));
            }
            MbaExpr::Add(l,r) | MbaExpr::Sub(l,r) | MbaExpr::Mul(l,r) |
            MbaExpr::And(l,r) | MbaExpr::Or(l,r) | MbaExpr::Xor(l,r) => {
                all.extend(self.collect_patterns(l, depth+1));
                all.extend(self.collect_patterns(r, depth+1));
            }
        }
        all
    }

    /// Batch-analyze many expressions and return a summary map.
    #[must_use] 
    pub fn batch_score(&self, exprs: &[MbaExpr]) -> Vec<MbaScore> {
        exprs.iter().map(|e| self.score(e)).collect()
    }

    /// Return the top `n` most obfuscated expressions from a batch.
    #[must_use] 
    pub fn top_obfuscated<'a>(&self, exprs: &'a [MbaExpr], n: usize) -> Vec<(&'a MbaExpr, MbaScore)> {
        let mut scored: Vec<(&'a MbaExpr, MbaScore)> = exprs.iter().map(|e| (e, self.score(e))).collect();
        scored.sort_unstable_by_key(|b| std::cmp::Reverse(b.1.score));
        scored.truncate(n);
        scored
    }
}

// ─── Statistics ───────────────────────────────────────────────────────────────

/// Aggregate detection statistics over a batch of expressions.
#[derive(Debug, Clone, Default)]
pub struct DetectionStats {
    pub total: usize,
    pub likely_obfuscated: usize,
    pub highly_obfuscated: usize,
    pub pattern_counts: HashMap<String, usize>,
    pub avg_score: f64,
}

impl DetectionStats {
    #[must_use] 
    pub fn compute(scores: &[MbaScore]) -> Self {
        let mut stats = Self { total: scores.len(), ..Default::default() };
        let mut score_sum = 0u64;
        for s in scores {
            score_sum += u64::from(s.score);
            if s.is_likely_obfuscated() { stats.likely_obfuscated += 1; }
            if s.is_highly_obfuscated() { stats.highly_obfuscated += 1; }
            for p in &s.patterns {
                *stats.pattern_counts.entry(p.kind.to_string()).or_insert(0) += 1;
            }
        }
        if stats.total > 0 {
            stats.avg_score = score_sum as f64 / stats.total as f64;
        }
        stats
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MbaExpr;

    fn x() -> MbaExpr { MbaExpr::Var("x".to_owned()) }
    fn y() -> MbaExpr { MbaExpr::Var("y".to_owned()) }

    #[test]
    fn test_xor_self_detected() {
        let expr = MbaExpr::mk_xor(x(), x());
        assert!(match_xor_self(&expr));
    }

    #[test]
    fn test_and_not_detected() {
        let expr = MbaExpr::And(Box::new(x()), Box::new(MbaExpr::Not(Box::new(x()))));
        assert!(match_and_not(&expr));
    }

    #[test]
    fn test_or_not_detected() {
        let expr = MbaExpr::Or(Box::new(x()), Box::new(MbaExpr::Not(Box::new(x()))));
        assert!(match_or_not(&expr));
    }

    #[test]
    fn test_add_as_xor_and_detected() {
        // (x ^ y) + 2*(x & y)
        let xor = MbaExpr::mk_xor(x(), y());
        let and = MbaExpr::mk_and(x(), y());
        let mul = MbaExpr::mk_mul(MbaExpr::Const(2), and);
        let expr = MbaExpr::mk_add(xor, mul);
        assert!(match_add_as_xor_and(&expr));
    }

    #[test]
    fn test_detector_score_xor_self() {
        let det = MbaDetector::new();
        let expr = MbaExpr::mk_xor(x(), x());
        let score = det.score(&expr);
        assert!(score.score > 0);
    }

    #[test]
    fn test_detector_score_complex_mba() {
        let det = MbaDetector::new();
        // (x ^ y) + 2*(x & y) — classic MBA for x + y
        let xor = MbaExpr::mk_xor(x(), y());
        let and = MbaExpr::mk_and(x(), y());
        let mul = MbaExpr::mk_mul(MbaExpr::Const(2), and);
        let expr = MbaExpr::mk_add(xor, mul);
        let score = det.score(&expr);
        assert!(score.is_likely_obfuscated(), "score was {}", score.score);
    }

    #[test]
    fn test_detector_score_simple_var() {
        let det = MbaDetector::new();
        let score = det.score(&x());
        assert!(!score.is_likely_obfuscated());
    }

    #[test]
    fn test_expr_tree_mixing() {
        let expr = MbaExpr::mk_add(MbaExpr::mk_and(x(), y()), MbaExpr::Const(1));
        let tree = ExprTree::analyze(&expr);
        assert!(tree.has_mixing());
    }

    #[test]
    fn test_expr_tree_no_mixing() {
        let expr = MbaExpr::mk_add(x(), y());
        let tree = ExprTree::analyze(&expr);
        assert!(!tree.has_mixing());
    }

    #[test]
    fn test_detection_stats() {
        let det = MbaDetector::new();
        let exprs = vec![
            MbaExpr::mk_xor(x(), x()),
            MbaExpr::Var("z".to_owned()),
        ];
        let scores = det.batch_score(&exprs);
        let stats = DetectionStats::compute(&scores);
        assert_eq!(stats.total, 2);
    }

    #[test]
    fn test_mba_score_display() {
        let tree = ExprTree { root: ExprTreeNodeKind::Add, size: 5, depth: 2,
            arith_count: 2, bitwise_count: 1, var_count: 2, transitions: 1 };
        let s = MbaScore { score: 75, reasons: vec![], patterns: vec![], tree };
        assert!(s.to_string().contains("75"));
        assert!(s.is_likely_obfuscated());
        assert!(!s.is_highly_obfuscated());
    }

    #[test]
    fn test_pattern_kind_display() {
        assert_eq!(MbaPatternKind::AddAsXorAnd.to_string(), "add_as_xor_and");
        assert_eq!(MbaPatternKind::XorSelf.to_string(), "xor_self");
    }
}
