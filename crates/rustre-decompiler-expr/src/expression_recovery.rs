//! `expression_recovery` — higher-level expression reconstruction passes.
//!
//! Builds on the core [`Expr`] infrastructure to provide advanced recovery
//! transformations: CSE factoring, distributivity, shift-to-multiply, bitfield
//! extraction, and conditional expression synthesis.

use crate::{BinOp, Expr, IntWidth, UnOp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ExprComplexity
// ─────────────────────────────────────────────────────────────────────────────

/// Measures complexity metrics for an expression tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExprComplexity {
    pub depth: usize,
    pub node_count: usize,
    pub call_count: usize,
    pub load_count: usize,
    pub var_count: usize,
    pub const_count: usize,
    pub operator_count: usize,
}

impl ExprComplexity {
    /// Compute complexity metrics for an expression.
    #[must_use]
    pub fn compute(expr: &Expr) -> Self {
        let mut c = Self::default();
        c.measure(expr, 0);
        c
    }

    fn measure(&mut self, expr: &Expr, depth: usize) {
        // Guard against stack overflow on attacker-supplied deeply-nested expressions.
        const MAX_MEASURE_DEPTH: usize = 512;
        if depth >= MAX_MEASURE_DEPTH {
            // Still count the truncated node but do not recurse further.
            self.node_count += 1;
            return;
        }
        if depth > self.depth {
            self.depth = depth;
        }
        self.node_count += 1;
        match expr {
            Expr::Const(_, _) => self.const_count += 1,
            Expr::Var(_) => self.var_count += 1,
            Expr::BinOp(_, a, b) => {
                self.operator_count += 1;
                self.measure(a, depth + 1);
                self.measure(b, depth + 1);
            }
            Expr::UnOp(_, e) => {
                self.operator_count += 1;
                self.measure(e, depth + 1);
            }
            Expr::Call { callee, args } => {
                self.call_count += 1;
                self.measure(callee, depth + 1);
                for a in args {
                    self.measure(a, depth + 1);
                }
            }
            Expr::Load { ptr, .. } => {
                self.load_count += 1;
                self.measure(ptr, depth + 1);
            }
            Expr::FieldAccess { base, .. } => self.measure(base, depth + 1),
            Expr::Index { base, index, .. } => {
                self.measure(base, depth + 1);
                self.measure(index, depth + 1);
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.measure(cond, depth + 1);
                self.measure(then_expr, depth + 1);
                self.measure(else_expr, depth + 1);
            }
            Expr::Phi(exprs) => {
                for e in exprs {
                    self.measure(e, depth + 1);
                }
            }
        }
    }

    /// Return a simple complexity score (higher = more complex).
    #[must_use]
    pub const fn score(&self) -> usize {
        self.node_count + self.call_count * 3 + self.load_count * 2 + self.depth
    }

    /// Return whether the expression is "simple" (low complexity).
    #[must_use]
    pub const fn is_simple(&self) -> bool {
        self.score() <= 5
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FactorOutCommonSubexpr — CSE factoring
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies common subexpressions and factors them out into temporaries.
#[derive(Debug, Default)]
pub struct FactorOutCommonSubexpr {
    /// CSE table: serialized expression string → temporary name.
    pub cse_map: HashMap<String, String>,
    /// Generated bindings: `temp_name` → expression.
    pub bindings: Vec<(String, Expr)>,
    counter: usize,
}

impl FactorOutCommonSubexpr {
    /// Create a new CSE pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run CSE over a list of expressions.
    ///
    /// Returns new expressions with CSE applied, and populates `self.bindings`
    /// with the introduced temporaries.
    #[must_use]
    pub fn apply(&mut self, exprs: Vec<Expr>) -> Vec<Expr> {
        // Count subexpression occurrences.
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &exprs {
            Self::count_subexprs(e, &mut counts);
        }
        // Mark those that appear more than once as CSE candidates.
        let candidates: HashMap<String, usize> =
            counts.into_iter().filter(|(_, c)| *c > 1).collect();
        // Transform.
        exprs
            .into_iter()
            .map(|e| self.transform(e, &candidates))
            .collect()
    }

    fn count_subexprs(expr: &Expr, counts: &mut HashMap<String, usize>) {
        if expr.is_leaf() {
            return;
        }
        let key = Self::expr_key(expr);
        *counts.entry(key).or_insert(0) += 1;
        match expr {
            Expr::BinOp(_, a, b) => {
                Self::count_subexprs(a, counts);
                Self::count_subexprs(b, counts);
            }
            Expr::UnOp(_, e) => Self::count_subexprs(e, counts),
            _ => {}
        }
    }

    fn transform(&mut self, expr: Expr, candidates: &HashMap<String, usize>) -> Expr {
        let key = Self::expr_key(&expr);
        if candidates.contains_key(&key) {
            if let Some(tmp) = self.cse_map.get(&key) {
                return Expr::Var(tmp.clone());
            }
            let tmp = format!("cse_{}", self.counter);
            self.counter += 1;
            self.cse_map.insert(key, tmp.clone());
            self.bindings.push((tmp.clone(), expr));
            return Expr::Var(tmp);
        }
        match expr {
            Expr::BinOp(op, a, b) => Expr::BinOp(
                op,
                Box::new(self.transform(*a, candidates)),
                Box::new(self.transform(*b, candidates)),
            ),
            Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(self.transform(*e, candidates))),
            other => other,
        }
    }

    fn expr_key(expr: &Expr) -> String {
        format!("{expr:?}")
    }

    /// Return the number of CSE bindings introduced.
    #[must_use]
    pub const fn binding_count(&self) -> usize {
        self.bindings.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DistributivityOpt — algebraic distribution
// ─────────────────────────────────────────────────────────────────────────────

/// Applies distributivity transformations to simplify expressions.
///
/// Example: `(a + b) * c → a*c + b*c` (expand) or the reverse (factor).
#[derive(Debug, Default)]
pub struct DistributivityOpt {
    pub expand: bool,
    pub factor: bool,
}

impl DistributivityOpt {
    /// Create a new distributivity optimizer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expand: true,
            factor: true,
        }
    }

    /// Apply distributivity transformations.
    #[must_use]
    pub fn optimize(&self, expr: Expr) -> Expr {
        match expr {
            Expr::BinOp(outer, a, b) => {
                let a = self.optimize(*a);
                let b = self.optimize(*b);
                self.try_distribute(outer, a, b)
            }
            Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(self.optimize(*e))),
            other => other,
        }
    }

    fn try_distribute(&self, outer: BinOp, a: Expr, b: Expr) -> Expr {
        // Factor: a*c + b*c → (a+b)*c
        if self.factor && outer == BinOp::Add
            && let (Expr::BinOp(BinOp::Mul, a1, c1), Expr::BinOp(BinOp::Mul, a2, c2)) = (&a, &b)
                && c1 == c2 {
                    let sum = Expr::BinOp(BinOp::Add, a1.clone(), a2.clone());
                    return Expr::BinOp(BinOp::Mul, Box::new(sum), c1.clone());
                }
        // Expand: (a+b)*c → a*c + b*c
        if self.expand && outer == BinOp::Mul
            && let Expr::BinOp(BinOp::Add, a1, b1) = &a {
                let left = Expr::BinOp(BinOp::Mul, a1.clone(), Box::new(b.clone()));
                let right = Expr::BinOp(BinOp::Mul, b1.clone(), Box::new(b));
                return Expr::BinOp(BinOp::Add, Box::new(left), Box::new(right));
            }
        Expr::BinOp(outer, Box::new(a), Box::new(b))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShiftToMul — recognize multiplication patterns from shifts
// ─────────────────────────────────────────────────────────────────────────────

/// Recognizes `x << N` as `x * (1 << N)` and vice-versa, depending on context.
#[derive(Debug, Default)]
pub struct ShiftToMul {
    /// Convert `x << N` to `x * power_of_2` when `N` is a small constant.
    pub normalize_shifts: bool,
    /// Convert `x * power_of_2` back to `x << N`.
    pub strength_reduce: bool,
}

impl ShiftToMul {
    /// Create a new shift-to-mul pass.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            normalize_shifts: false,
            strength_reduce: true,
        }
    }

    /// Transform an expression.
    #[must_use]
    pub fn transform(&self, expr: Expr) -> Expr {
        match expr {
            Expr::BinOp(op, a, b) => {
                let a = self.transform(*a);
                let b = self.transform(*b);
                // x << N → x * (1<<N) if normalize_shifts is on.
                if self.normalize_shifts && op == BinOp::Shl
                    && let Some(n) = b.as_const()
                        && (0..64).contains(&n) {
                            let factor = 1i64 << n;
                            return Expr::BinOp(
                                BinOp::Mul,
                                Box::new(a),
                                Box::new(Expr::Const(factor, IntWidth::I64)),
                            );
                        }
                // x * N → x << log2(N) if N is a power of 2 and strength_reduce is on.
                if self.strength_reduce && op == BinOp::Mul
                    && let Some(n) = b.as_const()
                        && n > 0 && n.count_ones() == 1 {
                            let shift = n.trailing_zeros();
                            return Expr::BinOp(
                                BinOp::Shl,
                                Box::new(a),
                                Box::new(Expr::Const(i64::from(shift), IntWidth::I32)),
                            );
                        }
                Expr::BinOp(op, Box::new(a), Box::new(b))
            }
            Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(self.transform(*e))),
            other => other,
        }
    }

    /// Check whether a multiplication by a power-of-2 can be strength-reduced.
    #[must_use]
    pub const fn can_strength_reduce(value: i64) -> bool {
        value > 0 && value.count_ones() == 1
    }

    /// Return the shift amount for a power-of-2.
    #[must_use]
    pub const fn shift_for(value: i64) -> Option<u32> {
        if Self::can_strength_reduce(value) {
            Some(value.trailing_zeros())
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitFieldRecovery — extract named bit fields
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers named bit fields from mask-and-shift patterns.
#[derive(Debug, Default)]
pub struct BitFieldRecovery {
    /// Named fields: name → (mask, shift).
    pub fields: HashMap<String, (u64, u32)>,
}

impl BitFieldRecovery {
    /// Create a new bitfield recovery context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named bit field.
    pub fn register(&mut self, name: impl Into<String>, mask: u64, shift: u32) {
        self.fields.insert(name.into(), (mask, shift));
    }

    /// Try to rewrite `(expr & mask) >> shift` into a named field access.
    #[must_use]
    pub fn try_rewrite(&self, expr: &Expr) -> Option<String> {
        // Pattern: (base & mask) >> shift
        if let Expr::BinOp(BinOp::Shr | BinOp::Sar, inner, shift_expr) = expr
            && let Some(shift) = shift_expr.as_const()
                && let Expr::BinOp(BinOp::And, _base, mask_expr) = inner.as_ref()
                    && let Some(mask) = mask_expr.as_const() {
                        for (name, (fmask, fshift)) in &self.fields {
                            if *fmask == crate::casts::i64_as_u64(mask) && *fshift == crate::casts::i64_to_u32(shift) {
                                return Some(name.clone());
                            }
                        }
                    }
        None
    }

    /// Extract the bit field value from an integer.
    #[must_use]
    pub fn extract(&self, name: &str, value: u64) -> Option<u64> {
        let (mask, shift) = self.fields.get(name)?;
        Some((value & mask) >> shift)
    }

    /// Return the field count.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConditionalExpr — synthesis of ternary / conditional expressions
// ─────────────────────────────────────────────────────────────────────────────

/// Synthesizes `(cond ? then : else)` expressions from conditional assignments.
#[derive(Debug, Default)]
pub struct ConditionalExpr;

impl ConditionalExpr {
    /// Create a new conditional expression synthesizer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build a ternary from three expressions.
    #[must_use]
    pub fn build(cond: Expr, then: Expr, else_: Expr) -> Expr {
        Expr::Ternary {
            cond: Box::new(cond),
            then_expr: Box::new(then),
            else_expr: Box::new(else_),
        }
    }

    /// Try to fold `(cond ? 1 : 0)` into just `cond`.
    #[must_use]
    pub fn try_fold_bool_ternary(expr: &Expr) -> Option<Expr> {
        if let Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } = expr
        {
            if then_expr.as_const() == Some(1) && else_expr.as_const() == Some(0) {
                return Some(*cond.clone());
            }
            if then_expr.as_const() == Some(0) && else_expr.as_const() == Some(1) {
                return Some(Expr::UnOp(UnOp::LNot, cond.clone()));
            }
        }
        None
    }

    /// Try to fold `(cond ? x : x)` into just `x`.
    #[must_use]
    pub fn try_fold_same_branches(expr: &Expr) -> Option<Expr> {
        if let Expr::Ternary {
            then_expr,
            else_expr,
            ..
        } = expr
            && then_expr == else_expr {
                return Some(*then_expr.clone());
            }
        None
    }

    /// Negate a conditional: `(cond ? a : b)` → `(!cond ? b : a)`.
    #[must_use]
    pub fn negate_condition(expr: Expr) -> Expr {
        if let Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } = expr
        {
            Expr::Ternary {
                cond: Box::new(Expr::UnOp(UnOp::LNot, cond)),
                then_expr: else_expr,
                else_expr: then_expr,
            }
        } else {
            expr
        }
    }

    /// Apply all conditional folding optimizations.
    #[must_use]
    pub fn optimize(expr: Expr) -> Expr {
        if let Some(folded) = Self::try_fold_bool_ternary(&expr) {
            return folded;
        }
        if let Some(folded) = Self::try_fold_same_branches(&expr) {
            return folded;
        }
        expr
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionRecovery — top-level recovery pass
// ─────────────────────────────────────────────────────────────────────────────

/// Options for the expression recovery pass.
///
/// Boolean toggles are packed into a `u8` bitfield to avoid
/// `clippy::struct_excessive_bools`. Access them through the accessor methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOptions {
    flags: u8,
}

impl RecoveryOptions {
    const CSE: u8 = 1 << 0;
    const DISTRIBUTIVITY: u8 = 1 << 1;
    const STRENGTH_REDUCTION: u8 = 1 << 2;
    const BITFIELD_RECOVERY: u8 = 1 << 3;
    const CONDITIONAL_FOLDING: u8 = 1 << 4;

    #[must_use] pub const fn cse(&self) -> bool { self.flags & Self::CSE != 0 }
    #[must_use] pub const fn distributivity(&self) -> bool { self.flags & Self::DISTRIBUTIVITY != 0 }
    #[must_use] pub const fn strength_reduction(&self) -> bool { self.flags & Self::STRENGTH_REDUCTION != 0 }
    #[must_use] pub const fn bitfield_recovery(&self) -> bool { self.flags & Self::BITFIELD_RECOVERY != 0 }
    #[must_use] pub const fn conditional_folding(&self) -> bool { self.flags & Self::CONDITIONAL_FOLDING != 0 }

    pub const fn set_cse(&mut self, on: bool) { Self::set_bit(&mut self.flags, Self::CSE, on); }
    pub const fn set_distributivity(&mut self, on: bool) { Self::set_bit(&mut self.flags, Self::DISTRIBUTIVITY, on); }
    pub const fn set_strength_reduction(&mut self, on: bool) { Self::set_bit(&mut self.flags, Self::STRENGTH_REDUCTION, on); }
    pub const fn set_bitfield_recovery(&mut self, on: bool) { Self::set_bit(&mut self.flags, Self::BITFIELD_RECOVERY, on); }
    pub const fn set_conditional_folding(&mut self, on: bool) { Self::set_bit(&mut self.flags, Self::CONDITIONAL_FOLDING, on); }

    const fn set_bit(flags: &mut u8, mask: u8, on: bool) {
        if on { *flags |= mask; } else { *flags &= !mask; }
    }
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            flags: Self::CSE | Self::DISTRIBUTIVITY | Self::STRENGTH_REDUCTION
                | Self::BITFIELD_RECOVERY | Self::CONDITIONAL_FOLDING,
        }
    }
}

/// Top-level expression recovery pass.
#[derive(Debug)]
pub struct ExpressionRecovery {
    pub options: RecoveryOptions,
    pub cse: FactorOutCommonSubexpr,
    pub dist: DistributivityOpt,
    pub shift: ShiftToMul,
    pub bitfield: BitFieldRecovery,
}

impl Default for ExpressionRecovery {
    fn default() -> Self {
        Self::new(RecoveryOptions::default())
    }
}

impl ExpressionRecovery {
    /// Create a new expression recovery pass.
    #[must_use]
    pub fn new(options: RecoveryOptions) -> Self {
        Self {
            options,
            cse: FactorOutCommonSubexpr::new(),
            dist: DistributivityOpt::new(),
            shift: ShiftToMul::new(),
            bitfield: BitFieldRecovery::new(),
        }
    }

    /// Recover and optimize a list of expressions.
    #[must_use]
    pub fn recover(&mut self, exprs: Vec<Expr>) -> Vec<Expr> {
        let mut result = exprs;
        if self.options.cse() {
            result = self.cse.apply(result);
        }
        result = result
            .into_iter()
            .map(|e| {
                let mut e = e;
                if self.options.distributivity() {
                    e = self.dist.optimize(e);
                }
                if self.options.strength_reduction() {
                    e = self.shift.transform(e);
                }
                if self.options.conditional_folding() {
                    e = ConditionalExpr::optimize(e);
                }
                e
            })
            .collect();
        result
    }

    /// Recover a single expression.
    #[must_use]
    pub fn recover_one(&mut self, expr: Expr) -> Expr {
        let mut result = self.recover(vec![expr]);
        result.pop().unwrap_or(Expr::Const(0, IntWidth::I32))
    }

    /// Return the number of CSE bindings introduced.
    #[must_use]
    pub const fn cse_binding_count(&self) -> usize {
        self.cse.binding_count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn add(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Add, Box::new(a), Box::new(b))
    }
    fn mul(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Mul, Box::new(a), Box::new(b))
    }
    fn shl(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Shl, Box::new(a), Box::new(b))
    }
    fn and(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::And, Box::new(a), Box::new(b))
    }
    fn shr(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Shr, Box::new(a), Box::new(b))
    }

    // ── ExprComplexity ────────────────────────────────────────────────────────

    #[test]
    fn test_complexity_constant() {
        let c_metric = ExprComplexity::compute(&c(42));
        assert_eq!(c_metric.const_count, 1);
        assert_eq!(c_metric.depth, 0);
        assert!(c_metric.is_simple());
    }

    #[test]
    fn test_complexity_var() {
        let m = ExprComplexity::compute(&var("x"));
        assert_eq!(m.var_count, 1);
    }

    #[test]
    fn test_complexity_binop() {
        let m = ExprComplexity::compute(&add(var("x"), c(1)));
        assert_eq!(m.operator_count, 1);
        assert_eq!(m.var_count, 1);
        assert_eq!(m.const_count, 1);
    }

    #[test]
    fn test_complexity_deep() {
        // ((a + b) * c) + d — depth 2
        let deep = add(mul(add(var("a"), var("b")), var("c")), var("d"));
        let m = ExprComplexity::compute(&deep);
        assert!(m.depth >= 2);
        assert!(m.node_count >= 7);
    }

    #[test]
    fn test_complexity_call() {
        let call = Expr::Call {
            callee: Box::new(var("fn")),
            args: vec![c(1)],
        };
        let m = ExprComplexity::compute(&call);
        assert_eq!(m.call_count, 1);
        assert!(!m.is_simple()); // calls bump score significantly
    }

    #[test]
    fn test_complexity_score() {
        let simple = ExprComplexity::compute(&c(1));
        let complex = ExprComplexity::compute(&add(mul(var("a"), var("b")), c(3)));
        assert!(simple.score() < complex.score());
    }

    // ── FactorOutCommonSubexpr ─────────────────────────────────────────────

    #[test]
    fn test_cse_no_common() {
        let mut cse = FactorOutCommonSubexpr::new();
        let exprs = vec![add(var("x"), c(1)), add(var("y"), c(2))];
        let result = cse.apply(exprs);
        assert_eq!(result.len(), 2);
        assert_eq!(cse.binding_count(), 0);
    }

    #[test]
    fn test_cse_with_common() {
        let mut cse = FactorOutCommonSubexpr::new();
        let common = add(var("a"), var("b"));
        let exprs = vec![common.clone(), common];
        let result = cse.apply(exprs);
        // Both should now reference the same CSE temp.
        assert_eq!(result.len(), 2);
        assert_eq!(cse.binding_count(), 1);
    }

    #[test]
    fn test_cse_binding_names_unique() {
        let mut cse = FactorOutCommonSubexpr::new();
        let e1 = add(var("a"), var("b"));
        let e2 = mul(var("c"), var("d"));
        let exprs = vec![e1.clone(), e1, e2.clone(), e2];
        let _ = cse.apply(exprs);
        let names: std::collections::HashSet<&str> =
            cse.bindings.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names.len(), cse.binding_count());
    }

    // ── DistributivityOpt ─────────────────────────────────────────────────

    #[test]
    fn test_dist_expand_mul_sum() {
        let dist = DistributivityOpt::new();
        // (a + b) * c → a*c + b*c
        let e = mul(add(var("a"), var("b")), var("c"));
        let r = dist.optimize(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Add, _, _)));
    }

    #[test]
    fn test_dist_factor_add_mul() {
        let dist = DistributivityOpt::new();
        // a*c + b*c → (a+b)*c
        let e = add(mul(var("a"), var("c")), mul(var("b"), var("c")));
        let r = dist.optimize(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Mul, _, _)));
    }

    #[test]
    fn test_dist_no_change_when_no_pattern() {
        let dist = DistributivityOpt::new();
        let e = add(var("x"), c(1));
        let r = dist.optimize(e.clone());
        assert_eq!(r, e);
    }

    #[test]
    fn test_dist_expand_disabled() {
        let dist = DistributivityOpt {
            expand: false,
            factor: true,
        };
        let e = mul(add(var("a"), var("b")), var("c"));
        let r = dist.optimize(e);
        // Should NOT expand when expand is disabled.
        assert!(matches!(r, Expr::BinOp(BinOp::Mul, _, _)));
    }

    // ── ShiftToMul ────────────────────────────────────────────────────────

    #[test]
    fn test_shift_to_mul_strength_reduce_mul4() {
        let st = ShiftToMul::new();
        // x * 4 → x << 2
        let e = mul(var("x"), c(4));
        let r = st.transform(e);
        if let Expr::BinOp(BinOp::Shl, _, shift) = r {
            assert_eq!(shift.as_const(), Some(2));
        } else {
            panic!("expected shl");
        }
    }

    #[test]
    fn test_shift_to_mul_no_reduce_non_power() {
        let st = ShiftToMul::new();
        let e = mul(var("x"), c(3));
        let r = st.transform(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Mul, _, _)));
    }

    #[test]
    fn test_shift_to_mul_normalize() {
        let st = ShiftToMul {
            normalize_shifts: true,
            strength_reduce: false,
        };
        // x << 3 → x * 8
        let e = shl(var("x"), c(3));
        let r = st.transform(e);
        if let Expr::BinOp(BinOp::Mul, _, factor) = r {
            assert_eq!(factor.as_const(), Some(8));
        } else {
            panic!("expected mul");
        }
    }

    #[test]
    fn test_shift_can_strength_reduce() {
        assert!(ShiftToMul::can_strength_reduce(1));
        assert!(ShiftToMul::can_strength_reduce(2));
        assert!(ShiftToMul::can_strength_reduce(4));
        assert!(ShiftToMul::can_strength_reduce(1024));
        assert!(!ShiftToMul::can_strength_reduce(3));
        assert!(!ShiftToMul::can_strength_reduce(6));
    }

    #[test]
    fn test_shift_for_power_of_2() {
        assert_eq!(ShiftToMul::shift_for(1), Some(0));
        assert_eq!(ShiftToMul::shift_for(8), Some(3));
        assert_eq!(ShiftToMul::shift_for(256), Some(8));
        assert_eq!(ShiftToMul::shift_for(3), None);
    }

    #[test]
    fn test_shift_mul1_no_reduce() {
        let st = ShiftToMul::new();
        // x * 1 → identity, no shift needed
        let e = mul(var("x"), c(1));
        let r = st.transform(e);
        // x * 1 with power-of-2: 1 = 1 << 0
        assert!(matches!(r, Expr::BinOp(BinOp::Shl, _, _)));
    }

    // ── BitFieldRecovery ───────────────────────────────────────────────────

    #[test]
    fn test_bitfield_register() {
        let mut bf = BitFieldRecovery::new();
        bf.register("status_flag", 0x1, 0);
        bf.register("error_code", 0x1E, 1);
        assert_eq!(bf.field_count(), 2);
    }

    #[test]
    fn test_bitfield_extract() {
        let mut bf = BitFieldRecovery::new();
        bf.register("flag", 0b0110, 1);
        let value = 0b1010u64;
        let extracted = bf.extract("flag", value).unwrap();
        // value=0b1010=10, mask=0b0110=6, shift=1. (10 & 6)=2, 2>>1=1 (first assertion was a test-author typo)
        assert_eq!(extracted, 1);
    }

    #[test]
    fn test_bitfield_extract_missing() {
        let bf = BitFieldRecovery::new();
        assert!(bf.extract("missing", 0).is_none());
    }

    #[test]
    fn test_bitfield_try_rewrite() {
        let mut bf = BitFieldRecovery::new();
        bf.register("field0", 0xFF, 0);
        // Build (base & 0xFF) >> 0
        let base_and_mask = and(var("base"), c(0xFF));
        let shifted = shr(base_and_mask, c(0));
        let result = bf.try_rewrite(&shifted);
        assert_eq!(result, Some("field0".to_string()));
    }

    #[test]
    fn test_bitfield_try_rewrite_no_match() {
        let bf = BitFieldRecovery::new();
        let e = add(var("x"), c(1));
        assert!(bf.try_rewrite(&e).is_none());
    }

    // ── ConditionalExpr ────────────────────────────────────────────────────

    #[test]
    fn test_conditional_build() {
        let ternary = ConditionalExpr::build(var("cond"), c(1), c(0));
        assert!(matches!(ternary, Expr::Ternary { .. }));
    }

    #[test]
    fn test_conditional_fold_bool_1_0() {
        let ternary = ConditionalExpr::build(var("cond"), c(1), c(0));
        let folded = ConditionalExpr::try_fold_bool_ternary(&ternary).unwrap();
        assert_eq!(folded, var("cond"));
    }

    #[test]
    fn test_conditional_fold_bool_0_1() {
        let ternary = ConditionalExpr::build(var("cond"), c(0), c(1));
        let folded = ConditionalExpr::try_fold_bool_ternary(&ternary).unwrap();
        assert!(matches!(folded, Expr::UnOp(UnOp::LNot, _)));
    }

    #[test]
    fn test_conditional_fold_same_branches() {
        let ternary = ConditionalExpr::build(var("cond"), c(42), c(42));
        let folded = ConditionalExpr::try_fold_same_branches(&ternary).unwrap();
        assert_eq!(folded, c(42));
    }

    #[test]
    fn test_conditional_negate() {
        let ternary = ConditionalExpr::build(var("x"), c(1), c(2));
        let negated = ConditionalExpr::negate_condition(ternary);
        if let Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } = negated
        {
            assert!(matches!(cond.as_ref(), Expr::UnOp(UnOp::LNot, _)));
            assert_eq!(then_expr.as_const(), Some(2));
            assert_eq!(else_expr.as_const(), Some(1));
        } else {
            panic!("expected ternary");
        }
    }

    #[test]
    fn test_conditional_optimize_no_change() {
        let ternary = ConditionalExpr::build(var("x"), var("a"), var("b"));
        let r = ConditionalExpr::optimize(ternary.clone());
        assert_eq!(r, ternary);
    }

    // ── ExpressionRecovery ─────────────────────────────────────────────────

    #[test]
    fn test_recovery_default_options() {
        let rec = ExpressionRecovery::default();
        assert!(rec.options.cse());
        assert!(rec.options.strength_reduction());
    }

    #[test]
    fn test_recovery_strength_reduce() {
        let mut rec = ExpressionRecovery::default();
        let e = mul(var("x"), c(8));
        let r = rec.recover_one(e);
        // Should be strength-reduced to x << 3.
        assert!(matches!(r, Expr::BinOp(BinOp::Shl, _, _)));
    }

    #[test]
    fn test_recovery_cse_bindings() {
        let mut rec = ExpressionRecovery::default();
        let common = add(var("a"), var("b"));
        let exprs = vec![common.clone(), common, c(1)];
        let _ = rec.recover(exprs);
        assert_eq!(rec.cse_binding_count(), 1);
    }

    #[test]
    fn test_recovery_conditional_folding() {
        let mut rec = ExpressionRecovery::default();
        let e = ConditionalExpr::build(var("f"), c(1), c(0));
        let r = rec.recover_one(e);
        assert_eq!(r, var("f"));
    }

    #[test]
    fn test_recovery_multiple_exprs() {
        let mut rec = ExpressionRecovery::default();
        let exprs = vec![mul(var("x"), c(4)), mul(var("y"), c(2))];
        let result = rec.recover(exprs);
        assert_eq!(result.len(), 2);
        // Both should be strength-reduced.
        assert!(matches!(result[0], Expr::BinOp(BinOp::Shl, _, _)));
        assert!(matches!(result[1], Expr::BinOp(BinOp::Shl, _, _)));
    }

    #[test]
    fn test_recovery_empty_list() {
        let mut rec = ExpressionRecovery::default();
        let result = rec.recover(vec![]);
        assert!(result.is_empty());
    }
}
