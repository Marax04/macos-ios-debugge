//! MBA expression rewriter.
//!
//! Provides a rule-driven rewrite engine for Mixed Boolean Arithmetic
//! expressions.  Unlike the simplifier (which applies rules bottom-up until
//! convergence), the rewriter applies a ranked list of [`RewriteRule`]s in
//! order, stopping after the first match at each node.  This makes it
//! suitable for targeted transformations (e.g. converting a known MBA idiom
//! to a canonical form) without the overhead of exhaustive simplification.

use std::collections::HashMap;
use std::fmt;

use crate::MbaExpr;

// ---------------------------------------------------------------------------
// SimplifiedExpr
// ---------------------------------------------------------------------------

/// An expression that has been confirmed simplified by a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SimplifiedExpr {
    /// The rewritten expression tree.
    pub expr: MbaExpr,
    /// Name of the rule that produced this form.
    pub rule_name: String,
    /// Complexity of the expression before rewriting.
    pub original_complexity: usize,
    /// Complexity of the expression after rewriting.
    pub simplified_complexity: usize,
}

impl SimplifiedExpr {
    /// Create a new `SimplifiedExpr`.
    #[must_use]
    pub fn new(
        expr: MbaExpr,
        rule_name: impl Into<String>,
        original_complexity: usize,
    ) -> Self {
        let simplified_complexity = expr.complexity();
        Self {
            expr,
            rule_name: rule_name.into(),
            original_complexity,
            simplified_complexity,
        }
    }

    /// Returns the complexity reduction achieved.
    #[must_use]
    pub const fn reduction(&self) -> usize {
        self.original_complexity.saturating_sub(self.simplified_complexity)
    }

    /// Returns `true` if the rewrite actually reduced complexity.
    #[must_use]
    pub const fn is_improvement(&self) -> bool {
        self.simplified_complexity < self.original_complexity
    }
}

impl fmt::Display for SimplifiedExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [rule={}, Δ=-{}]",
            self.expr,
            self.rule_name,
            self.reduction()
        )
    }
}

// ---------------------------------------------------------------------------
// RewriteRule
// ---------------------------------------------------------------------------

/// A single named rewrite rule.
///
/// The `matcher` function receives an [`MbaExpr`] and returns `Some(rewritten)`
/// if the rule applies, or `None` otherwise.
pub struct RewriteRule {
    /// Short unique name for this rule (e.g. `"xor-to-zero"`).
    pub name: &'static str,
    /// Human-readable description of the transformation.
    pub description: &'static str,
    /// Priority: rules with higher priority are tried first.
    pub priority: i32,
    /// The matching and rewriting function.
    pub matcher: fn(&MbaExpr) -> Option<MbaExpr>,
}

impl fmt::Debug for RewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RewriteRule")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

impl RewriteRule {
    /// Try to apply this rule to `expr`, returning `Some` on success.
    #[must_use]
    pub fn apply(&self, expr: &MbaExpr) -> Option<MbaExpr> {
        (self.matcher)(expr)
    }
}

// ---------------------------------------------------------------------------
// Standard rewrite rule definitions
// ---------------------------------------------------------------------------

/// Build the standard set of rewrite rules included with the engine.
#[must_use]
pub fn standard_rewrite_rules() -> Vec<RewriteRule> {
    let mut rules = constant_folding_rewrites();
    rules.extend(identity_rewrites());
    rules.extend(mba_idiom_rewrites());
    rules.extend(normalization_rewrites());
    rules.sort_unstable_by_key(|b| std::cmp::Reverse(b.priority));
    rules
}

fn constant_folding_rewrites() -> Vec<RewriteRule> {
    vec![
        RewriteRule {
            name: "const-add",
            description: "Const(a) + Const(b) → Const(a+b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Add(l, r) => {
                    Some(MbaExpr::Const(l.is_const()?.wrapping_add(r.is_const()?)))
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "const-sub",
            description: "Const(a) - Const(b) → Const(a-b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Sub(l, r) => {
                    Some(MbaExpr::Const(l.is_const()?.wrapping_sub(r.is_const()?)))
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "const-mul",
            description: "Const(a) * Const(b) → Const(a*b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Mul(l, r) => {
                    Some(MbaExpr::Const(l.is_const()?.wrapping_mul(r.is_const()?)))
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "const-and",
            description: "Const(a) & Const(b) → Const(a&b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::And(l, r) => Some(MbaExpr::Const(l.is_const()? & r.is_const()?)),
                _ => None,
            },
        },
        RewriteRule {
            name: "const-or",
            description: "Const(a) | Const(b) → Const(a|b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Or(l, r) => Some(MbaExpr::Const(l.is_const()? | r.is_const()?)),
                _ => None,
            },
        },
        RewriteRule {
            name: "const-xor",
            description: "Const(a) ^ Const(b) → Const(a^b)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Xor(l, r) => Some(MbaExpr::Const(l.is_const()? ^ r.is_const()?)),
                _ => None,
            },
        },
        RewriteRule {
            name: "const-neg",
            description: "-(Const(a)) → Const(-a)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Neg(inner) => Some(MbaExpr::Const(inner.is_const()?.wrapping_neg())),
                _ => None,
            },
        },
        RewriteRule {
            name: "const-not",
            description: "~Const(a) → Const(~a)",
            priority: 100,
            matcher: |e| match e {
                MbaExpr::Not(inner) => Some(MbaExpr::Const(!inner.is_const()?)),
                _ => None,
            },
        },
    ]
}

fn identity_rewrites() -> Vec<RewriteRule> {
    vec![
        RewriteRule {
            name: "add-zero",
            description: "x + 0 → x  or  0 + x → x",
            priority: 80,
            matcher: |e| match e {
                MbaExpr::Add(l, r) => {
                    if r.is_zero() { Some(*l.clone()) }
                    else if l.is_zero() { Some(*r.clone()) }
                    else { None }
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "mul-one",
            description: "x * 1 → x  or  1 * x → x",
            priority: 80,
            matcher: |e| match e {
                MbaExpr::Mul(l, r) => {
                    if r.is_one() { Some(*l.clone()) }
                    else if l.is_one() { Some(*r.clone()) }
                    else { None }
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "mul-zero",
            description: "x * 0 → 0  or  0 * x → 0",
            priority: 80,
            matcher: |e| match e {
                MbaExpr::Mul(l, r) => {
                    if l.is_zero() || r.is_zero() { Some(MbaExpr::Const(0)) }
                    else { None }
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "xor-self",
            description: "x ^ x → 0",
            priority: 90,
            matcher: |e| match e {
                MbaExpr::Xor(l, r) if l == r => Some(MbaExpr::Const(0)),
                _ => None,
            },
        },
        RewriteRule {
            name: "and-self",
            description: "x & x → x",
            priority: 90,
            matcher: |e| match e {
                MbaExpr::And(l, r) if l == r => Some(*l.clone()),
                _ => None,
            },
        },
        RewriteRule {
            name: "or-self",
            description: "x | x → x",
            priority: 90,
            matcher: |e| match e {
                MbaExpr::Or(l, r) if l == r => Some(*l.clone()),
                _ => None,
            },
        },
        RewriteRule {
            name: "sub-self",
            description: "x - x → 0",
            priority: 90,
            matcher: |e| match e {
                MbaExpr::Sub(l, r) if l == r => Some(MbaExpr::Const(0)),
                _ => None,
            },
        },
        RewriteRule {
            name: "double-neg",
            description: "-(-x) → x",
            priority: 85,
            matcher: |e| match e {
                MbaExpr::Neg(inner) => match inner.as_ref() {
                    MbaExpr::Neg(inner2) => Some(*inner2.clone()),
                    _ => None,
                },
                _ => None,
            },
        },
        RewriteRule {
            name: "double-not",
            description: "~~x → x",
            priority: 85,
            matcher: |e| match e {
                MbaExpr::Not(inner) => match inner.as_ref() {
                    MbaExpr::Not(inner2) => Some(*inner2.clone()),
                    _ => None,
                },
                _ => None,
            },
        },
        RewriteRule {
            name: "and-allones",
            description: "x & (-1) → x",
            priority: 75,
            matcher: |e| match e {
                MbaExpr::And(l, r) => {
                    if r.is_const() == Some(-1) { Some(*l.clone()) }
                    else if l.is_const() == Some(-1) { Some(*r.clone()) }
                    else { None }
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "or-allones",
            description: "x | (-1) → -1",
            priority: 75,
            matcher: |e| match e {
                MbaExpr::Or(l, r) => {
                    if l.is_const() == Some(-1) || r.is_const() == Some(-1) {
                        Some(MbaExpr::Const(-1))
                    } else {
                        None
                    }
                }
                _ => None,
            },
        },
    ]
}

fn mba_idiom_rewrites() -> Vec<RewriteRule> {
    vec![
        RewriteRule {
            name: "and-plus-or",
            description: "(x & y) + (x | y) → x + y",
            priority: 95,
            matcher: |e| match e {
                MbaExpr::Add(l, r) => {
                    try_and_or_pair(l, r).or_else(|| try_and_or_pair(r, l))
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "or-minus-and",
            description: "(x | y) - (x & y) → x ^ y",
            priority: 95,
            matcher: |e| match e {
                MbaExpr::Sub(l, r) => {
                    if let (MbaExpr::Or(ol, or_r), MbaExpr::And(al, ar)) =
                        (l.as_ref(), r.as_ref())
                        && ((ol == al && or_r == ar) || (ol == ar && or_r == al)) {
                            return Some(MbaExpr::mk_xor(*ol.clone(), *or_r.clone()));
                        }
                    None
                }
                _ => None,
            },
        },
        RewriteRule {
            name: "sum-minus-and",
            description: "(x + y) - (x & y) → x | y",
            priority: 95,
            matcher: |e| match e {
                MbaExpr::Sub(l, r) => {
                    if let (MbaExpr::Add(sl, sr), MbaExpr::And(al, ar)) =
                        (l.as_ref(), r.as_ref())
                        && ((sl == al && sr == ar) || (sl == ar && sr == al)) {
                            return Some(MbaExpr::mk_or(*sl.clone(), *sr.clone()));
                        }
                    None
                }
                _ => None,
            },
        },
    ]
}

fn try_and_or_pair(lhs: &MbaExpr, rhs: &MbaExpr) -> Option<MbaExpr> {
    if let (MbaExpr::And(al, ar), MbaExpr::Or(ol, or_r)) = (lhs, rhs)
        && ((al == ol && ar == or_r) || (al == or_r && ar == ol)) {
            return Some(MbaExpr::mk_add(*al.clone(), *ar.clone()));
        }
    None
}

fn normalization_rewrites() -> Vec<RewriteRule> {
    vec![
        RewriteRule {
            name: "not-to-neg-minus1",
            description: "~x → -x - 1  (normalise NOT to arithmetic)",
            priority: 20,
            matcher: |e| match e {
                MbaExpr::Not(inner) => {
                    // Only normalise if inner is a Var or Add/Sub — not Const (would
                    // already be folded) and not another Not (handled by double-not).
                    match inner.as_ref() {
                        MbaExpr::Var(_) | MbaExpr::Add(_, _) | MbaExpr::Sub(_, _) => {
                            Some(MbaExpr::mk_sub(
                                MbaExpr::mk_neg(*inner.clone()),
                                MbaExpr::Const(1),
                            ))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        },
    ]
}

// ---------------------------------------------------------------------------
// MbaRewriter — the main engine
// ---------------------------------------------------------------------------

/// Configuration for the [`MbaRewriter`] engine.
#[derive(Debug, Clone)]
pub struct RewriterConfig {
    /// Maximum number of bottom-up passes.
    pub max_passes: usize,
    /// Stop early if complexity does not decrease.
    pub stop_on_no_progress: bool,
    /// Collect a trace of every rewrite applied.
    pub trace: bool,
}

impl Default for RewriterConfig {
    fn default() -> Self {
        Self {
            max_passes: 64,
            stop_on_no_progress: true,
            trace: false,
        }
    }
}

/// One recorded rewrite step in a trace.
#[derive(Debug, Clone)]
pub struct RewriteStep {
    /// Rule that was applied.
    pub rule_name: String,
    /// Expression before the rewrite.
    pub before: MbaExpr,
    /// Expression after the rewrite.
    pub after: MbaExpr,
}

/// The result of running the rewriter over an expression.
#[derive(Debug, Clone)]
pub struct RewriteResult {
    /// The final expression.
    pub expr: MbaExpr,
    /// Complexity before all rewrites.
    pub original_complexity: usize,
    /// Complexity after all rewrites.
    pub final_complexity: usize,
    /// Number of passes executed.
    pub passes: usize,
    /// Whether any rule fired.
    pub changed: bool,
    /// Names of rules that fired (in order), if tracing was enabled.
    pub trace: Vec<RewriteStep>,
}

impl RewriteResult {
    /// Complexity reduction achieved.
    #[must_use]
    pub const fn reduction(&self) -> usize {
        self.original_complexity.saturating_sub(self.final_complexity)
    }
}

/// Rule-driven MBA expression rewriter.
///
/// Rules are sorted by descending priority. At each node in the tree the
/// engine tries rules in priority order and applies the first that matches.
#[derive(Debug)]
pub struct MbaRewriter {
    rules: Vec<RewriteRule>,
    config: RewriterConfig,
}

impl MbaRewriter {
    /// Create a rewriter with the standard rule set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: standard_rewrite_rules(),
            config: RewriterConfig::default(),
        }
    }

    /// Create a rewriter with custom rules.
    #[must_use]
    pub fn with_rules(rules: Vec<RewriteRule>) -> Self {
        let mut r = rules;
        r.sort_unstable_by_key(|b| std::cmp::Reverse(b.priority));
        Self { rules: r, config: RewriterConfig::default() }
    }

    /// Override the configuration.
    #[must_use]
    pub const fn with_config(mut self, config: RewriterConfig) -> Self {
        self.config = config;
        self
    }

    /// Rewrite `expr` and return a full [`RewriteResult`].
    #[must_use]
    pub fn rewrite(&self, expr: MbaExpr) -> RewriteResult {
        let original_complexity = expr.complexity();
        let mut current = expr;
        let mut passes = 0;
        let mut changed = false;
        let mut trace = Vec::new();

        for _ in 0..self.config.max_passes {
            let (next, steps) = self.single_pass(&current);
            passes += 1;
            let pass_changed = next != current;
            if !pass_changed {
                break;
            }
            changed = true;
            if self.config.trace {
                trace.extend(steps);
            }
            let progress = next.complexity() < current.complexity();
            current = next;
            if self.config.stop_on_no_progress && !progress {
                break;
            }
        }

        let final_complexity = current.complexity();
        RewriteResult { expr: current, original_complexity, final_complexity, passes, changed, trace }
    }

    /// Apply one bottom-up pass and return the rewritten expression plus fired
    /// rule steps.
    #[must_use]
    pub fn single_pass(&self, expr: &MbaExpr) -> (MbaExpr, Vec<RewriteStep>) {
        let mut steps = Vec::new();
        let result = self.rewrite_node(expr, &mut steps);
        (result, steps)
    }

    /// Recursively rewrite a node bottom-up.
    fn rewrite_node(&self, expr: &MbaExpr, steps: &mut Vec<RewriteStep>) -> MbaExpr {
        // First rewrite children
        let rebuilt = self.rebuild_children(expr, steps);
        // Then try rules on the rebuilt node
        for rule in &self.rules {
            if let Some(rewritten) = rule.apply(&rebuilt) {
                if self.config.trace {
                    steps.push(RewriteStep {
                        rule_name: rule.name.to_string(),
                        before: rebuilt.clone(),
                        after: rewritten.clone(),
                    });
                }
                return rewritten;
            }
        }
        rebuilt
    }

    fn rebuild_children(&self, expr: &MbaExpr, steps: &mut Vec<RewriteStep>) -> MbaExpr {
        match expr {
            MbaExpr::Const(_) | MbaExpr::Var(_) => expr.clone(),
            MbaExpr::Neg(e) => MbaExpr::mk_neg(self.rewrite_node(e, steps)),
            MbaExpr::Not(e) => MbaExpr::mk_not(self.rewrite_node(e, steps)),
            MbaExpr::Shl(e, n) => MbaExpr::Shl(Box::new(self.rewrite_node(e, steps)), *n),
            MbaExpr::Shr(e, n) => MbaExpr::Shr(Box::new(self.rewrite_node(e, steps)), *n),
            MbaExpr::Sar(e, n) => MbaExpr::Sar(Box::new(self.rewrite_node(e, steps)), *n),
            MbaExpr::Add(l, r) => MbaExpr::mk_add(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
            MbaExpr::Sub(l, r) => MbaExpr::mk_sub(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
            MbaExpr::Mul(l, r) => MbaExpr::mk_mul(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
            MbaExpr::And(l, r) => MbaExpr::mk_and(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
            MbaExpr::Or(l, r) => MbaExpr::mk_or(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
            MbaExpr::Xor(l, r) => MbaExpr::mk_xor(
                self.rewrite_node(l, steps), self.rewrite_node(r, steps)),
        }
    }

    /// Apply rewrites using a cache to avoid redundant work on shared sub-trees.
    #[must_use]
    pub fn rewrite_cached(&self, expr: MbaExpr) -> MbaExpr {
        let mut cache: HashMap<MbaExpr, MbaExpr> = HashMap::new();
        self.rewrite_with_cache(&expr, &mut cache)
    }

    fn rewrite_with_cache(
        &self,
        expr: &MbaExpr,
        cache: &mut HashMap<MbaExpr, MbaExpr>,
    ) -> MbaExpr {
        if let Some(cached) = cache.get(expr) {
            return cached.clone();
        }
        let mut steps = Vec::new();
        let result = self.rewrite_node(expr, &mut steps);
        cache.insert(expr.clone(), result.clone());
        result
    }

    /// Number of rules loaded.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Apply a single named rule to `expr`, returning the result or `None`.
    #[must_use]
    pub fn apply_rule(&self, name: &str, expr: &MbaExpr) -> Option<MbaExpr> {
        self.rules.iter().find(|r| r.name == name)?.apply(expr)
    }
}

impl Default for MbaRewriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// apply_rewrite — convenience free function
// ---------------------------------------------------------------------------

/// Apply all standard rewrite rules to `expr` in a single pass.
///
/// Returns a [`SimplifiedExpr`] describing the best rewrite found, or `None`
/// if no rule fired.
#[must_use]
pub fn apply_rewrite(expr: &MbaExpr) -> Option<SimplifiedExpr> {
    let rules = standard_rewrite_rules();
    let orig = expr.complexity();
    for rule in &rules {
        if let Some(rewritten) = rule.apply(expr) {
            return Some(SimplifiedExpr::new(rewritten, rule.name, orig));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MbaExpr;

    fn var(name: &str) -> MbaExpr { MbaExpr::Var(name.to_string()) }
    fn con(v: i64) -> MbaExpr { MbaExpr::Const(v) }

    #[test]
    fn const_add_folds() {
        let expr = MbaExpr::mk_add(con(3), con(4));
        let r = MbaRewriter::new().rewrite(expr);
        assert_eq!(r.expr, con(7));
    }

    #[test]
    fn xor_self_to_zero() {
        let x = var("x");
        let expr = MbaExpr::mk_xor(x.clone(), x);
        let r = MbaRewriter::new().rewrite(expr);
        assert_eq!(r.expr, con(0));
    }

    #[test]
    fn and_plus_or_simplifies() {
        let x = var("x");
        let y = var("y");
        let and = MbaExpr::mk_and(x.clone(), y.clone());
        let or = MbaExpr::mk_or(x.clone(), y.clone());
        let expr = MbaExpr::mk_add(and, or);
        let r = MbaRewriter::new().rewrite(expr);
        assert_eq!(r.expr, MbaExpr::mk_add(x, y));
    }

    #[test]
    fn double_neg_eliminated() {
        let x = var("x");
        let expr = MbaExpr::mk_neg(MbaExpr::mk_neg(x.clone()));
        let r = MbaRewriter::new().rewrite(expr);
        assert_eq!(r.expr, x);
    }

    #[test]
    fn apply_rewrite_returns_some_for_xor_self() {
        let x = var("x");
        let expr = MbaExpr::mk_xor(x.clone(), x);
        assert!(apply_rewrite(&expr).is_some());
    }

    #[test]
    fn apply_rewrite_returns_none_for_var() {
        let expr = var("x");
        assert!(apply_rewrite(&expr).is_none());
    }

    #[test]
    fn rewrite_cached_agrees_with_rewrite() {
        let x = var("x");
        let expr = MbaExpr::mk_add(MbaExpr::mk_xor(x.clone(), x), con(5));
        let rw = MbaRewriter::new();
        let a = rw.rewrite(expr.clone()).expr;
        let b = rw.rewrite_cached(expr);
        assert_eq!(a, b);
    }
}
