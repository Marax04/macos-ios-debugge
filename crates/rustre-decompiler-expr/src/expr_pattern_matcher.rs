//! Pattern matching and rewriting for the decompiler expression tree.
//!
//! Provides a simple pattern language that can bind sub-expressions to
//! named capture slots, and a rewrite engine that replaces matched patterns
//! with a template expression.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{BinOp, Expr, IntWidth, UnOp};

// ─── ExprPat ─────────────────────────────────────────────────────────────────

/// A pattern that can match against an `Expr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExprPat {
    /// Match any expression and bind it to `name`.
    Capture(String),
    /// Match a specific constant.
    Const(i64),
    /// Match any constant (binding its value to `name`).
    AnyConst(String),
    /// Match a specific variable.
    Var(String),
    /// Match any variable (binding its name to `name`).
    AnyVar(String),
    /// Match a binary operation with the given patterns for each operand.
    BinOp(BinOp, Box<Self>, Box<Self>),
    /// Match any binary operation of the given op, capturing both sides.
    BinOpAny(BinOp, String, String),
    /// Match a unary operation with the given inner pattern.
    UnOp(UnOp, Box<Self>),
    /// Match any expression (wildcard).
    Any,
    /// Match a load with any pointer and the given size.
    Load(u8),
}

// ─── Captures ─────────────────────────────────────────────────────────────────

/// Named sub-expression captures produced by a successful match.
#[derive(Debug, Clone, Default)]
pub struct Captures {
    pub exprs: HashMap<String, Expr>,
    pub ints: HashMap<String, i64>,
    pub names: HashMap<String, String>,
}

impl Captures {
    /// Get a captured expression.
    #[must_use]
    pub fn get_expr(&self, name: &str) -> Option<&Expr> {
        self.exprs.get(name)
    }

    /// Get a captured constant value.
    #[must_use]
    pub fn get_int(&self, name: &str) -> Option<i64> {
        self.ints.get(name).copied()
    }

    /// Get a captured variable name.
    #[must_use]
    pub fn get_name(&self, name: &str) -> Option<&str> {
        self.names.get(name).map(String::as_str)
    }
}

// ─── Pattern matching ─────────────────────────────────────────────────────────

/// Try to match `pat` against `expr`, filling `captures`.
///
/// Returns `true` on success.
pub fn match_pattern(pat: &ExprPat, expr: &Expr, captures: &mut Captures) -> bool {
    match (pat, expr) {
        (ExprPat::Any, _) => true,

        (ExprPat::Capture(name), _) => {
            captures.exprs.insert(name.clone(), expr.clone());
            true
        }

        (ExprPat::Const(v), Expr::Const(ev, _)) => *v == *ev,

        (ExprPat::AnyConst(name), Expr::Const(v, _)) => {
            captures.ints.insert(name.clone(), *v);
            true
        }

        (ExprPat::Var(name), Expr::Var(ename)) => name == ename,

        (ExprPat::AnyVar(slot), Expr::Var(name)) => {
            captures.names.insert(slot.clone(), name.clone());
            true
        }

        (ExprPat::BinOp(pop, lp, rp), Expr::BinOp(eop, lhs, rhs)) => {
            pop == eop
                && match_pattern(lp, lhs, captures)
                && match_pattern(rp, rhs, captures)
        }

        (ExprPat::BinOpAny(pop, lslot, rslot), Expr::BinOp(eop, lhs, rhs)) => {
            if pop != eop { return false; }
            captures.exprs.insert(lslot.clone(), *lhs.clone());
            captures.exprs.insert(rslot.clone(), *rhs.clone());
            true
        }

        (ExprPat::UnOp(pop, inner_pat), Expr::UnOp(eop, inner)) => {
            pop == eop && match_pattern(inner_pat, inner, captures)
        }

        (ExprPat::Load(size), Expr::Load { size: esize, .. }) => *size == *esize,

        _ => false,
    }
}

// ─── ExprTemplate ─────────────────────────────────────────────────────────────

/// Template for constructing an expression from captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExprTemplate {
    /// Substitute a captured expression by slot name.
    Captured(String),
    /// A constant (i64 value).
    Const(i64, IntWidth),
    /// A variable.
    Var(String),
    /// Build a binary operation from two templates.
    BinOp(BinOp, Box<Self>, Box<Self>),
    /// Build a unary operation from a template.
    UnOp(UnOp, Box<Self>),
    /// Substitute with the constant 0 of the default width.
    Zero,
    /// Substitute with the constant 1 of the default width.
    One,
}

/// Expand an `ExprTemplate` with given captures.
///
/// Returns `None` if a required capture is missing.
#[must_use]
pub fn expand_template(tmpl: &ExprTemplate, captures: &Captures) -> Option<Expr> {
    match tmpl {
        ExprTemplate::Captured(name) => captures.exprs.get(name).cloned(),
        ExprTemplate::Const(v, w) => Some(Expr::Const(*v, *w)),
        ExprTemplate::Var(name) => Some(Expr::Var(name.clone())),
        ExprTemplate::Zero => Some(Expr::Const(0, IntWidth::I32)),
        ExprTemplate::One => Some(Expr::Const(1, IntWidth::I32)),
        ExprTemplate::BinOp(op, lhs, rhs) => {
            let l = expand_template(lhs, captures)?;
            let r = expand_template(rhs, captures)?;
            Some(Expr::BinOp(*op, Box::new(l), Box::new(r)))
        }
        ExprTemplate::UnOp(op, inner) => {
            let i = expand_template(inner, captures)?;
            Some(Expr::UnOp(*op, Box::new(i)))
        }
    }
}

// ─── RewriteRule ──────────────────────────────────────────────────────────────

/// A rewrite rule: if `pattern` matches, replace with `template`.
#[derive(Debug, Clone)]
pub struct RewriteRule {
    /// Human-readable name.
    pub name: String,
    /// The pattern to match.
    pub pattern: ExprPat,
    /// The template to expand on a successful match.
    pub template: ExprTemplate,
}

impl RewriteRule {
    /// Create a new rule.
    pub fn new(name: impl Into<String>, pattern: ExprPat, template: ExprTemplate) -> Self {
        Self { name: name.into(), pattern, template }
    }

    /// Try to apply this rule to `expr`.
    ///
    /// Returns `Some(replacement)` on success.
    #[must_use]
    pub fn try_apply(&self, expr: &Expr) -> Option<Expr> {
        let mut captures = Captures::default();
        if match_pattern(&self.pattern, expr, &mut captures) {
            expand_template(&self.template, &captures)
        } else {
            None
        }
    }
}

// ─── MatchResult ──────────────────────────────────────────────────────────────

/// Result of applying an `ExprPatternMatcher` to an expression.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The rewritten expression (may equal the input if no rule matched).
    pub expr: Expr,
    /// Names of the rules that fired.
    pub fired_rules: Vec<String>,
    /// Total rewrites applied.
    pub total_rewrites: usize,
}

// ─── ExprPatternMatcher ──────────────────────────────────────────────────────

/// Applies a set of rewrite rules to an expression tree.
pub struct ExprPatternMatcher {
    rules: Vec<RewriteRule>,
    /// Maximum recursive passes over the tree.
    pub max_passes: usize,
}

impl ExprPatternMatcher {
    /// Create with an empty rule set.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new(), max_passes: 16 }
    }

    /// Add a rule to the matcher.
    pub fn add_rule(&mut self, rule: RewriteRule) {
        self.rules.push(rule);
    }

    /// Apply all rules top-down until no more rules fire or `max_passes` reached.
    #[must_use]
    pub fn apply(&self, expr: Expr) -> MatchResult {
        let mut current = expr;
        let mut fired_rules = Vec::new();
        let mut total = 0usize;

        for _ in 0..self.max_passes {
            let (new_expr, fired, rewrites) = self.apply_once(current.clone());
            total += rewrites;
            if rewrites == 0 {
                current = new_expr;
                break;
            }
            fired_rules.extend(fired);
            current = new_expr;
        }

        MatchResult {
            expr: current,
            fired_rules,
            total_rewrites: total,
        }
    }

    fn apply_once(&self, expr: Expr) -> (Expr, Vec<String>, usize) {
        let mut fired = Vec::new();
        let mut rewrites = 0usize;

        // Try all rules at this node first.
        let mut current = expr;
        for rule in &self.rules {
            if let Some(replacement) = rule.try_apply(&current) {
                fired.push(rule.name.clone());
                rewrites += 1;
                current = replacement;
                break; // only one rule per node per pass
            }
        }

        // Then recurse into children.
        let current = match current {
            Expr::BinOp(op, lhs, rhs) => {
                let (l, lf, lr) = self.apply_once(*lhs);
                let (r, rf, rr) = self.apply_once(*rhs);
                fired.extend(lf);
                fired.extend(rf);
                rewrites += lr + rr;
                Expr::BinOp(op, Box::new(l), Box::new(r))
            }
            Expr::UnOp(op, inner) => {
                let (i, inf, ir) = self.apply_once(*inner);
                fired.extend(inf);
                rewrites += ir;
                Expr::UnOp(op, Box::new(i))
            }
            Expr::Ternary { cond, then_expr, else_expr } => {
                let (c, cf, cr) = self.apply_once(*cond);
                let (t, tf, tr) = self.apply_once(*then_expr);
                let (e, ef, er) = self.apply_once(*else_expr);
                fired.extend(cf);
                fired.extend(tf);
                fired.extend(ef);
                rewrites += cr + tr + er;
                Expr::Ternary { cond: Box::new(c), then_expr: Box::new(t), else_expr: Box::new(e) }
            }
            other => other,
        };

        (current, fired, rewrites)
    }

    /// Standard library of algebraic rewrite rules.
    #[must_use]
    pub fn standard_rules() -> Vec<RewriteRule> {
        vec![
            // x + 0 → x
            RewriteRule::new(
                "add_zero",
                ExprPat::BinOp(BinOp::Add, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
                ExprTemplate::Captured("x".into()),
            ),
            // 0 + x → x
            RewriteRule::new(
                "zero_add",
                ExprPat::BinOp(BinOp::Add, Box::new(ExprPat::Const(0)), Box::new(ExprPat::Capture("x".into()))),
                ExprTemplate::Captured("x".into()),
            ),
            // x * 1 → x
            RewriteRule::new(
                "mul_one",
                ExprPat::BinOp(BinOp::Mul, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(1))),
                ExprTemplate::Captured("x".into()),
            ),
            // x * 0 → 0
            RewriteRule::new(
                "mul_zero",
                ExprPat::BinOp(BinOp::Mul, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
                ExprTemplate::Zero,
            ),
            // x ^ 0 → x
            RewriteRule::new(
                "xor_zero",
                ExprPat::BinOp(BinOp::Xor, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
                ExprTemplate::Captured("x".into()),
            ),
            // x - 0 → x
            RewriteRule::new(
                "sub_zero",
                ExprPat::BinOp(BinOp::Sub, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
                ExprTemplate::Captured("x".into()),
            ),
            // x & 0 → 0
            RewriteRule::new(
                "and_zero",
                ExprPat::BinOp(BinOp::And, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
                ExprTemplate::Zero,
            ),
            // !!x → x (double logical not)
            RewriteRule::new(
                "double_lnot",
                ExprPat::UnOp(UnOp::LNot, Box::new(ExprPat::UnOp(UnOp::LNot, Box::new(ExprPat::Capture("x".into()))))),
                ExprTemplate::Captured("x".into()),
            ),
            // --x → x
            RewriteRule::new(
                "double_neg",
                ExprPat::UnOp(UnOp::Neg, Box::new(ExprPat::UnOp(UnOp::Neg, Box::new(ExprPat::Capture("x".into()))))),
                ExprTemplate::Captured("x".into()),
            ),
            // x | x → x (idempotent or)
            RewriteRule::new(
                "or_self",
                ExprPat::BinOpAny(BinOp::Or, "x".into(), "y".into()),
                ExprTemplate::Captured("x".into()),
            ),
        ]
    }
}

impl Default for ExprPatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Replace all occurrences of `pattern` in `expr` with `replacement`.
///
/// Returns the number of replacements made.
pub fn replace_pattern(expr: &mut Expr, pattern: &ExprPat, replacement: &Expr) -> usize {
    let mut count = 0usize;

    let mut captures = Captures::default();
    if match_pattern(pattern, expr, &mut captures) {
        *expr = replacement.clone();
        return 1;
    }

    match expr {
        Expr::BinOp(_, lhs, rhs) => {
            count += replace_pattern(lhs, pattern, replacement);
            count += replace_pattern(rhs, pattern, replacement);
        }
        Expr::UnOp(_, inner) => {
            count += replace_pattern(inner, pattern, replacement);
        }
        Expr::Ternary { cond, then_expr, else_expr } => {
            count += replace_pattern(cond, pattern, replacement);
            count += replace_pattern(then_expr, pattern, replacement);
            count += replace_pattern(else_expr, pattern, replacement);
        }
        Expr::Call { callee, args } => {
            count += replace_pattern(callee, pattern, replacement);
            for a in args {
                count += replace_pattern(a, pattern, replacement);
            }
        }
        Expr::Load { ptr, .. } => {
            count += replace_pattern(ptr, pattern, replacement);
        }
        _ => {}
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntWidth;

    fn c(v: i64) -> Expr { Expr::Const(v, IntWidth::I32) }
    fn var(n: &str) -> Expr { Expr::Var(n.to_string()) }
    fn binop(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::BinOp(op, Box::new(l), Box::new(r))
    }

    #[test]
    fn match_constant() {
        let pat = ExprPat::Const(42);
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &c(42), &mut caps));
        assert!(!match_pattern(&pat, &c(0), &mut Captures::default()));
    }

    #[test]
    fn match_capture() {
        let pat = ExprPat::Capture("x".into());
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &var("foo"), &mut caps));
        assert!(caps.exprs.contains_key("x"));
    }

    #[test]
    fn match_binop() {
        let pat = ExprPat::BinOp(
            BinOp::Add,
            Box::new(ExprPat::Capture("l".into())),
            Box::new(ExprPat::Const(0)),
        );
        let expr = binop(BinOp::Add, var("x"), c(0));
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &expr, &mut caps));
        assert_eq!(caps.exprs["l"], var("x"));
    }

    #[test]
    fn rule_add_zero() {
        let rule = RewriteRule::new(
            "add_zero",
            ExprPat::BinOp(BinOp::Add, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
            ExprTemplate::Captured("x".into()),
        );
        let expr = binop(BinOp::Add, var("y"), c(0));
        let result = rule.try_apply(&expr).unwrap();
        assert_eq!(result, var("y"));
    }

    #[test]
    fn matcher_fires_standard() {
        let mut matcher = ExprPatternMatcher::new();
        for r in ExprPatternMatcher::standard_rules() {
            matcher.add_rule(r);
        }
        let expr = binop(BinOp::Add, var("n"), c(0));
        let result = matcher.apply(expr);
        assert_eq!(result.expr, var("n"));
        assert!(result.total_rewrites > 0);
    }

    #[test]
    fn double_neg_rule() {
        let mut matcher = ExprPatternMatcher::new();
        for r in ExprPatternMatcher::standard_rules() {
            matcher.add_rule(r);
        }
        let expr = Expr::UnOp(
            UnOp::Neg,
            Box::new(Expr::UnOp(UnOp::Neg, Box::new(var("x")))),
        );
        let result = matcher.apply(expr);
        assert_eq!(result.expr, var("x"));
    }

    #[test]
    fn replace_pattern_in_subtree() {
        let zero_pat = ExprPat::Const(0);
        let mut expr = binop(BinOp::Add, c(0), var("y"));
        let count = replace_pattern(&mut expr, &zero_pat, &c(99));
        assert_eq!(count, 1);
    }

    #[test]
    fn match_any() {
        let pat = ExprPat::Any;
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &c(42), &mut caps));
        assert!(match_pattern(&pat, &var("anything"), &mut Captures::default()));
    }

    #[test]
    fn expand_zero_template() {
        let tmpl = ExprTemplate::Zero;
        let caps = Captures::default();
        let result = expand_template(&tmpl, &caps).unwrap();
        assert_eq!(result, Expr::Const(0, IntWidth::I32));
    }

    // ── Added comprehensive tests ─────────────────────────────────────────────

    #[test]
    fn match_specific_var_mismatch_fails() {
        let pat = ExprPat::Var("foo".into());
        let mut caps = Captures::default();
        assert!(!match_pattern(&pat, &var("bar"), &mut caps));
        // Must still succeed on the exact name.
        assert!(match_pattern(&pat, &var("foo"), &mut Captures::default()));
    }

    #[test]
    fn match_any_const_captures_value() {
        let pat = ExprPat::AnyConst("k".into());
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &c(7), &mut caps));
        assert_eq!(caps.get_int("k"), Some(7));
        // Non-constant should fail.
        assert!(!match_pattern(&pat, &var("v"), &mut Captures::default()));
    }

    #[test]
    fn match_any_var_captures_name() {
        let pat = ExprPat::AnyVar("n".into());
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &var("hello"), &mut caps));
        assert_eq!(caps.get_name("n"), Some("hello"));
    }

    #[test]
    fn match_binop_op_mismatch_fails() {
        let pat = ExprPat::BinOp(
            BinOp::Add,
            Box::new(ExprPat::Any),
            Box::new(ExprPat::Any),
        );
        let mismatched = binop(BinOp::Sub, var("a"), var("b"));
        assert!(!match_pattern(&pat, &mismatched, &mut Captures::default()));
    }

    #[test]
    fn match_binop_any_captures_both_operands() {
        let pat = ExprPat::BinOpAny(BinOp::Mul, "lhs".into(), "rhs".into());
        let mut caps = Captures::default();
        let expr = binop(BinOp::Mul, var("a"), c(7));
        assert!(match_pattern(&pat, &expr, &mut caps));
        assert_eq!(caps.get_expr("lhs"), Some(&var("a")));
        assert_eq!(caps.get_expr("rhs"), Some(&c(7)));
    }

    #[test]
    fn match_unop_inner_must_match() {
        let pat = ExprPat::UnOp(UnOp::Neg, Box::new(ExprPat::Var("x".into())));
        let ok = Expr::UnOp(UnOp::Neg, Box::new(var("x")));
        let bad_op = Expr::UnOp(UnOp::Not, Box::new(var("x")));
        let bad_inner = Expr::UnOp(UnOp::Neg, Box::new(var("y")));
        assert!(match_pattern(&pat, &ok, &mut Captures::default()));
        assert!(!match_pattern(&pat, &bad_op, &mut Captures::default()));
        assert!(!match_pattern(&pat, &bad_inner, &mut Captures::default()));
    }

    #[test]
    fn match_load_size_matters() {
        let pat = ExprPat::Load(4);
        let l4 = Expr::Load { ptr: Box::new(var("p")), size: 4 };
        let l8 = Expr::Load { ptr: Box::new(var("p")), size: 8 };
        assert!(match_pattern(&pat, &l4, &mut Captures::default()));
        assert!(!match_pattern(&pat, &l8, &mut Captures::default()));
    }

    #[test]
    fn captures_round_trip_via_template_expansion() {
        let pat = ExprPat::BinOp(
            BinOp::Add,
            Box::new(ExprPat::Capture("lhs".into())),
            Box::new(ExprPat::AnyConst("k".into())),
        );
        let expr = binop(BinOp::Add, var("x"), c(99));
        let mut caps = Captures::default();
        assert!(match_pattern(&pat, &expr, &mut caps));
        // Build a Sub(lhs, 1) template.
        let tmpl = ExprTemplate::BinOp(
            BinOp::Sub,
            Box::new(ExprTemplate::Captured("lhs".into())),
            Box::new(ExprTemplate::One),
        );
        let built = expand_template(&tmpl, &caps).unwrap();
        assert_eq!(built, binop(BinOp::Sub, var("x"), Expr::Const(1, IntWidth::I32)));
    }

    #[test]
    fn expand_template_missing_capture_returns_none() {
        let tmpl = ExprTemplate::Captured("missing".into());
        assert!(expand_template(&tmpl, &Captures::default()).is_none());
        // A nested missing capture also fails.
        let nested = ExprTemplate::BinOp(
            BinOp::Add,
            Box::new(ExprTemplate::Captured("missing".into())),
            Box::new(ExprTemplate::Zero),
        );
        assert!(expand_template(&nested, &Captures::default()).is_none());
    }

    #[test]
    fn standard_rules_chain_in_single_pass() {
        // ((y + 0) * 1) + 0 → y after multiple rule firings.
        let matcher = {
            let mut m = ExprPatternMatcher::new();
            for r in ExprPatternMatcher::standard_rules() { m.add_rule(r); }
            m
        };
        let expr = binop(
            BinOp::Add,
            binop(BinOp::Mul, binop(BinOp::Add, var("y"), c(0)), c(1)),
            c(0),
        );
        let result = matcher.apply(expr);
        assert_eq!(result.expr, var("y"));
        assert!(result.total_rewrites >= 3);
    }

    #[test]
    fn matcher_terminates_when_no_rules_match() {
        let mut matcher = ExprPatternMatcher::new();
        matcher.add_rule(RewriteRule::new(
            "add_zero",
            ExprPat::BinOp(BinOp::Add, Box::new(ExprPat::Capture("x".into())), Box::new(ExprPat::Const(0))),
            ExprTemplate::Captured("x".into()),
        ));
        let expr = binop(BinOp::Sub, var("a"), var("b"));
        let r = matcher.apply(expr.clone());
        assert_eq!(r.expr, expr);
        assert_eq!(r.total_rewrites, 0);
        assert!(r.fired_rules.is_empty());
    }

    #[test]
    fn matcher_respects_max_passes() {
        // A pathological rule that keeps firing forever (x → x).  max_passes
        // must bound the loop.
        let mut matcher = ExprPatternMatcher::new();
        matcher.max_passes = 3;
        matcher.add_rule(RewriteRule::new(
            "identity",
            ExprPat::AnyVar("n".into()),
            ExprTemplate::Var("z".into()),
        ));
        let expr = var("x");
        let r = matcher.apply(expr);
        // After the first round, var becomes "z" but the rule then keeps
        // matching.  The bound ensures we exit cleanly.
        assert!(r.total_rewrites <= 100);
    }

    #[test]
    fn xor_zero_and_sub_zero_compose() {
        let mut matcher = ExprPatternMatcher::new();
        for r in ExprPatternMatcher::standard_rules() { matcher.add_rule(r); }
        let expr = binop(BinOp::Xor, binop(BinOp::Sub, var("q"), c(0)), c(0));
        let r = matcher.apply(expr);
        assert_eq!(r.expr, var("q"));
    }

    #[test]
    fn replace_pattern_at_root_fires_once() {
        // Root matches → exactly one replacement and the rest isn't walked.
        let pat = ExprPat::AnyVar("_".into());
        let mut expr = var("x");
        let n = replace_pattern(&mut expr, &pat, &c(7));
        assert_eq!(n, 1);
        assert_eq!(expr, c(7));
    }

    #[test]
    fn replace_pattern_recursive_count_in_call_args() {
        let zero_pat = ExprPat::Const(0);
        let mut expr = Expr::Call {
            callee: Box::new(var("f")),
            args: vec![c(0), c(1), c(0), binop(BinOp::Add, c(0), var("q"))],
        };
        let count = replace_pattern(&mut expr, &zero_pat, &c(42));
        // 3 zero constants in the args (incl. the one nested in the add).
        assert_eq!(count, 3);
    }

    #[test]
    fn replace_pattern_zero_when_no_match() {
        let pat = ExprPat::Const(999);
        let mut expr = binop(BinOp::Add, var("a"), var("b"));
        let count = replace_pattern(&mut expr, &pat, &c(0));
        assert_eq!(count, 0);
    }

    #[test]
    fn captures_helpers_return_none_for_missing_keys() {
        let caps = Captures::default();
        assert!(caps.get_expr("x").is_none());
        assert!(caps.get_int("x").is_none());
        assert!(caps.get_name("x").is_none());
    }

    #[test]
    fn const_pattern_with_extreme_values() {
        let pat_max = ExprPat::Const(i64::MAX);
        let pat_min = ExprPat::Const(i64::MIN);
        assert!(match_pattern(&pat_max, &Expr::Const(i64::MAX, IntWidth::I64), &mut Captures::default()));
        assert!(match_pattern(&pat_min, &Expr::Const(i64::MIN, IntWidth::I64), &mut Captures::default()));
        assert!(!match_pattern(&pat_max, &Expr::Const(i64::MAX - 1, IntWidth::I64), &mut Captures::default()));
    }
}
