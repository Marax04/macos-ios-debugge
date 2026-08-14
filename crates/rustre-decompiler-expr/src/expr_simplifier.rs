//! Algebraic expression simplifier for the decompiler expression tree.
//!
//! Applies constant folding, identity element elimination, double-negation
//! removal, dead-branch elimination in ternary expressions, and a handful of
//! well-known bitwise/arithmetic identities.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{BinOp, Expr, IntWidth, UnOp};

// ─── SimplifyPass ─────────────────────────────────────────────────────────────

/// A single named simplification pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimplifyPass {
    /// Fold operations over two constant operands.
    ConstantFold,
    /// Eliminate identity elements (x+0, x*1, x|0, x^0, …).
    IdentityElim,
    /// Eliminate annihilator elements (x*0, x&0, …).
    AnnihilatorElim,
    /// Remove double negation (--x → x, ~~x → x, !!x → x).
    DoubleNegElim,
    /// Fold ternary expressions with constant conditions.
    TernaryFold,
    /// Normalise comparison with zero (x != 0 → (bool)x).
    CompareZeroNorm,
    /// Pull constants to the right of commutative operators.
    CommutativeNorm,
    /// Simplify shifts by zero.
    ShiftByZero,
    /// Simplify x - x → 0, x ^ x → 0, x & x → x, x | x → x.
    SelfOpElim,
}

impl SimplifyPass {
    /// All standard passes in the recommended application order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ConstantFold,
            Self::IdentityElim,
            Self::AnnihilatorElim,
            Self::DoubleNegElim,
            Self::TernaryFold,
            Self::CompareZeroNorm,
            Self::CommutativeNorm,
            Self::ShiftByZero,
            Self::SelfOpElim,
        ]
    }
}

// ─── SimplifyStats ────────────────────────────────────────────────────────────

/// Counts rewrites applied per pass.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimplifyStats {
    pub rewrites: HashMap<String, usize>,
    pub total_rewrites: usize,
    pub iterations: usize,
}

impl SimplifyStats {
    fn record(&mut self, pass: &str) {
        *self.rewrites.entry(pass.to_string()).or_insert(0) += 1;
        self.total_rewrites += 1;
    }
}

// ─── ExprSimplifier ──────────────────────────────────────────────────────────

/// Algebraic simplifier for `Expr` trees.
///
/// Applies passes repeatedly until a fixed point is reached (no more rewrites).
pub struct ExprSimplifier {
    /// Maximum number of full-tree iterations before giving up.
    pub max_iterations: usize,
    /// Which passes to enable (default: all).
    pub enabled_passes: Vec<SimplifyPass>,
}

impl Default for ExprSimplifier {
    fn default() -> Self {
        Self {
            max_iterations: 32,
            enabled_passes: SimplifyPass::all().to_vec(),
        }
    }
}

impl ExprSimplifier {
    /// Create a simplifier with all passes enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a specific set of passes.
    #[must_use]
    pub const fn with_passes(passes: Vec<SimplifyPass>) -> Self {
        Self {
            max_iterations: 32,
            enabled_passes: passes,
        }
    }

    /// Simplify `expr` to a fixed point and return statistics.
    #[must_use]
    pub fn simplify(&self, expr: Expr) -> (Expr, SimplifyStats) {
        let mut stats = SimplifyStats::default();
        let mut current = expr;
        for _iter in 0..self.max_iterations {
            stats.iterations += 1;
            let before = rewrites_before(&current);
            let simplified = self.simplify_once(current.clone(), &mut stats);
            let after = rewrites_before(&simplified);
            current = simplified;
            if after == before {
                break;
            }
        }
        (current, stats)
    }

    fn simplify_once(&self, expr: Expr, stats: &mut SimplifyStats) -> Expr {
        // Recurse first (bottom-up).
        let expr = self.descend(expr, stats);
        // Then apply passes at this node.
        self.apply_passes(expr, stats)
    }

    fn descend(&self, expr: Expr, stats: &mut SimplifyStats) -> Expr {
        match expr {
            Expr::BinOp(op, lhs, rhs) => Expr::BinOp(
                op,
                Box::new(self.simplify_once(*lhs, stats)),
                Box::new(self.simplify_once(*rhs, stats)),
            ),
            Expr::UnOp(op, inner) => Expr::UnOp(op, Box::new(self.simplify_once(*inner, stats))),
            Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
                cond: Box::new(self.simplify_once(*cond, stats)),
                then_expr: Box::new(self.simplify_once(*then_expr, stats)),
                else_expr: Box::new(self.simplify_once(*else_expr, stats)),
            },
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(self.simplify_once(*callee, stats)),
                args: args.into_iter().map(|a| self.simplify_once(a, stats)).collect(),
            },
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(self.simplify_once(*ptr, stats)),
                size,
            },
            other => other,
        }
    }

    fn apply_passes(&self, expr: Expr, stats: &mut SimplifyStats) -> Expr {
        let mut current = expr;
        for &pass in &self.enabled_passes {
            current = Self::apply_pass(pass, current, stats);
        }
        current
    }

    fn apply_pass(pass: SimplifyPass, expr: Expr, stats: &mut SimplifyStats) -> Expr {
        match pass {
            SimplifyPass::ConstantFold => constant_fold(expr, stats),
            SimplifyPass::IdentityElim => identity_elim(expr, stats),
            SimplifyPass::AnnihilatorElim => annihilator_elim(expr, stats),
            SimplifyPass::DoubleNegElim => double_neg_elim(expr, stats),
            SimplifyPass::TernaryFold => ternary_fold(expr, stats),
            SimplifyPass::CompareZeroNorm => compare_zero_norm(expr, stats),
            SimplifyPass::CommutativeNorm => commutative_norm(expr, stats),
            SimplifyPass::ShiftByZero => shift_by_zero(expr, stats),
            SimplifyPass::SelfOpElim => self_op_elim(expr, stats),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns a structural "fingerprint" of an expression that increases each
/// time a rewrite is possible; used as a fixed-point check.
fn rewrites_before(expr: &Expr) -> usize {
    // Just count nodes — a rewrite reduces the node count.
    count_nodes(expr)
}

fn count_nodes(expr: &Expr) -> usize {
    match expr {
        Expr::Const(_, _) | Expr::Var(_) => 1,
        Expr::BinOp(_, l, r) => 1 + count_nodes(l) + count_nodes(r),
        Expr::UnOp(_, inner) => 1 + count_nodes(inner),
        Expr::Ternary { cond, then_expr, else_expr } => {
            1 + count_nodes(cond) + count_nodes(then_expr) + count_nodes(else_expr)
        }
        Expr::Call { callee, args } => {
            1 + count_nodes(callee) + args.iter().map(count_nodes).sum::<usize>()
        }
        Expr::Load { ptr, .. } => 1 + count_nodes(ptr),
        Expr::FieldAccess { base, .. } => 1 + count_nodes(base),
        Expr::Index { base, index, .. } => 1 + count_nodes(base) + count_nodes(index),
        Expr::Phi(exprs) => 1 + exprs.iter().map(count_nodes).sum::<usize>(),
    }
}

const fn as_const(expr: &Expr) -> Option<(i64, IntWidth)> {
    if let Expr::Const(v, w) = expr { Some((*v, *w)) } else { None }
}

// ─── Passes ──────────────────────────────────────────────────────────────────

fn constant_fold(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op, lhs, rhs) = &expr
        && let (Some((lv, lw)), Some((rv, _rw))) = (as_const(lhs), as_const(rhs)) {
            let result = match op {
                BinOp::Add => Some(lv.wrapping_add(rv)),
                BinOp::Sub => Some(lv.wrapping_sub(rv)),
                BinOp::Mul => Some(lv.wrapping_mul(rv)),
                BinOp::Div if rv != 0 => Some(lv.wrapping_div(rv)),
                BinOp::Mod if rv != 0 => Some(lv.wrapping_rem(rv)),
                BinOp::And => Some(lv & rv),
                BinOp::Or => Some(lv | rv),
                BinOp::Xor => Some(lv ^ rv),
                BinOp::Shl => Some(lv.wrapping_shl(crate::casts::i64_to_u32(rv) & 63)),
                BinOp::Shr => Some(crate::casts::u64_as_i64(
                    crate::casts::i64_as_u64(lv).wrapping_shr(crate::casts::i64_to_u32(rv) & 63),
                )),
                BinOp::Sar => Some(lv.wrapping_shr(crate::casts::i64_to_u32(rv) & 63)),
                BinOp::Eq => Some(i64::from(lv == rv)),
                BinOp::Ne => Some(i64::from(lv != rv)),
                BinOp::Lt => Some(i64::from(lv < rv)),
                BinOp::Le => Some(i64::from(lv <= rv)),
                BinOp::Gt => Some(i64::from(lv > rv)),
                BinOp::Ge => Some(i64::from(lv >= rv)),
                _ => None,
            };
            if let Some(v) = result {
                stats.record("constant_fold");
                return Expr::Const(v, lw);
            }
        }
    if let Expr::UnOp(op, inner) = &expr
        && let Some((v, w)) = as_const(inner) {
            let result = match op {
                UnOp::Neg => Some(v.wrapping_neg()),
                UnOp::Not => Some(!v),
                UnOp::LNot => Some(i64::from(v == 0)),
                UnOp::Cast(new_w) => Some(mask_to_width(v, *new_w)),
                _ => None,
            };
            if let Some(new_v) = result {
                stats.record("constant_fold_unary");
                return Expr::Const(new_v, w);
            }
        }
    expr
}

fn mask_to_width(v: i64, w: IntWidth) -> i64 {
    use crate::casts;
    match w {
        IntWidth::U8 => i64::from(casts::i64_to_u8(v)),
        IntWidth::U16 => i64::from(casts::i64_to_u16(v)),
        IntWidth::U32 => i64::from(casts::i64_to_u32(v)),
        IntWidth::U64 | IntWidth::I64 => v,
        IntWidth::I8 => i64::from(casts::i64_to_i8(v)),
        IntWidth::I16 => i64::from(casts::i64_to_i16(v)),
        IntWidth::I32 => i64::from(casts::i64_to_i32(v)),
    }
}

fn identity_elim(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op, lhs, rhs) = &expr {
        match op {
            BinOp::Add | BinOp::Or | BinOp::Xor | BinOp::Sub => {
                if as_const(rhs).is_some_and(|(v, _)| v == 0) {
                    stats.record("identity_elim_rhs");
                    return *lhs.clone();
                }
                if matches!(op, BinOp::Add | BinOp::Or | BinOp::Xor)
                    && as_const(lhs).is_some_and(|(v, _)| v == 0)
                {
                    stats.record("identity_elim_lhs");
                    return *rhs.clone();
                }
            }
            BinOp::Mul => {
                if as_const(rhs).is_some_and(|(v, _)| v == 1) {
                    stats.record("identity_mul_rhs");
                    return *lhs.clone();
                }
                if as_const(lhs).is_some_and(|(v, _)| v == 1) {
                    stats.record("identity_mul_lhs");
                    return *rhs.clone();
                }
            }
            BinOp::Div => {
                if as_const(rhs).is_some_and(|(v, _)| v == 1) {
                    stats.record("identity_div");
                    return *lhs.clone();
                }
            }
            BinOp::Shl | BinOp::Shr | BinOp::Sar
                if as_const(rhs).is_some_and(|(v, _)| v == 0) => {
                    stats.record("identity_shift");
                    return *lhs.clone();
                }
            _ => {}
        }
    }
    expr
}

fn annihilator_elim(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op, lhs, rhs) = &expr {
        let zero_rhs = as_const(rhs).is_some_and(|(v, _)| v == 0);
        let zero_lhs = as_const(lhs).is_some_and(|(v, _)| v == 0);
        let width = guess_width(lhs).or_else(|| guess_width(rhs)).unwrap_or(IntWidth::I64);
        match op {
            BinOp::Mul | BinOp::And => {
                if zero_rhs {
                    stats.record("annihilator_rhs");
                    return Expr::Const(0, width);
                }
                if zero_lhs {
                    stats.record("annihilator_lhs");
                    return Expr::Const(0, width);
                }
            }
            _ => {}
        }
    }
    expr
}

const fn guess_width(expr: &Expr) -> Option<IntWidth> {
    match expr {
        Expr::Const(_, w) => Some(*w),
        _ => None,
    }
}

fn double_neg_elim(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::UnOp(outer_op, inner) = &expr
        && let Expr::UnOp(inner_op, innermost) = inner.as_ref() {
            let cancel = matches!((outer_op, inner_op),
                (UnOp::Neg, UnOp::Neg) | (UnOp::Not, UnOp::Not) | (UnOp::LNot, UnOp::LNot));
            if cancel {
                stats.record("double_neg_elim");
                return *innermost.clone();
            }
        }
    expr
}

fn ternary_fold(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::Ternary { cond, then_expr, else_expr } = &expr {
        if let Some((v, _)) = as_const(cond) {
            stats.record("ternary_fold");
            return if v != 0 { *then_expr.clone() } else { *else_expr.clone() };
        }
        // ternary where both branches are equal
        if then_expr == else_expr {
            stats.record("ternary_same_branch");
            return *then_expr.clone();
        }
    }
    expr
}

fn compare_zero_norm(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(BinOp::Ne, lhs, rhs) = &expr
        && as_const(rhs).is_some_and(|(v, _)| v == 0) {
            // x != 0 → (bool)x — leave as-is but mark as simplified for stats
            stats.record("compare_zero_norm");
            return Expr::UnOp(UnOp::LNot, Box::new(Expr::UnOp(UnOp::LNot, lhs.clone())));
        }
    expr
}

fn commutative_norm(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op, lhs, rhs) = &expr
        && op.is_commutative() {
            // If lhs is a constant and rhs is not, swap them.
            if as_const(lhs).is_some() && as_const(rhs).is_none() {
                stats.record("commutative_norm");
                return Expr::BinOp(*op, rhs.clone(), lhs.clone());
            }
        }
    expr
}

fn shift_by_zero(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op @ (BinOp::Shl | BinOp::Shr | BinOp::Sar), lhs, rhs) = &expr {
        if as_const(rhs).is_some_and(|(v, _)| v == 0) {
            stats.record("shift_by_zero");
            return *lhs.clone();
        }
        let _ = op;
    }
    expr
}

fn self_op_elim(expr: Expr, stats: &mut SimplifyStats) -> Expr {
    if let Expr::BinOp(op, lhs, rhs) = &expr
        && lhs == rhs {
            let width = guess_width(lhs).or_else(|| guess_width(rhs)).unwrap_or(IntWidth::I32);
            match op {
                BinOp::Sub | BinOp::Xor => {
                    stats.record("self_sub_xor");
                    return Expr::Const(0, width);
                }
                BinOp::And | BinOp::Or => {
                    stats.record("self_and_or");
                    return *lhs.clone();
                }
                _ => {}
            }
        }
    expr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntWidth;

    fn c(v: i64) -> Expr { Expr::Const(v, IntWidth::I32) }
    fn v(name: &str) -> Expr { Expr::Var(name.to_string()) }
    fn binop(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::BinOp(op, Box::new(l), Box::new(r))
    }

    #[test]
    fn constant_fold_add() {
        let s = ExprSimplifier::new();
        let expr = binop(BinOp::Add, c(3), c(4));
        let (result, stats) = s.simplify(expr);
        assert_eq!(result, c(7));
        assert!(stats.total_rewrites > 0);
    }

    #[test]
    fn constant_fold_mul() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Mul, c(6), c(7)));
        assert_eq!(result, c(42));
    }

    #[test]
    fn identity_add_zero() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Add, v("x"), c(0)));
        assert_eq!(result, v("x"));
    }

    #[test]
    fn identity_mul_one() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Mul, v("x"), c(1)));
        assert_eq!(result, v("x"));
    }

    #[test]
    fn annihilator_mul_zero() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Mul, v("x"), c(0)));
        assert_eq!(result, c(0));
    }

    #[test]
    fn double_neg_elim() {
        let s = ExprSimplifier::new();
        let expr = Expr::UnOp(UnOp::Neg, Box::new(Expr::UnOp(UnOp::Neg, Box::new(v("x")))));
        let (result, _) = s.simplify(expr);
        assert_eq!(result, v("x"));
    }

    #[test]
    fn ternary_fold_true() {
        let s = ExprSimplifier::new();
        let expr = Expr::Ternary {
            cond: Box::new(c(1)),
            then_expr: Box::new(v("a")),
            else_expr: Box::new(v("b")),
        };
        let (result, _) = s.simplify(expr);
        assert_eq!(result, v("a"));
    }

    #[test]
    fn ternary_fold_false() {
        let s = ExprSimplifier::new();
        let expr = Expr::Ternary {
            cond: Box::new(c(0)),
            then_expr: Box::new(v("a")),
            else_expr: Box::new(v("b")),
        };
        let (result, _) = s.simplify(expr);
        assert_eq!(result, v("b"));
    }

    #[test]
    fn self_xor_zero() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Xor, v("x"), v("x")));
        assert_eq!(result, c(0));
    }

    #[test]
    fn nested_simplify() {
        let s = ExprSimplifier::new();
        // (3 + 4) * 1 → 7
        let expr = binop(BinOp::Mul, binop(BinOp::Add, c(3), c(4)), c(1));
        let (result, _) = s.simplify(expr);
        assert_eq!(result, c(7));
    }

    #[test]
    fn shift_zero() {
        let s = ExprSimplifier::new();
        let (result, _) = s.simplify(binop(BinOp::Shl, v("x"), c(0)));
        assert_eq!(result, v("x"));
    }
}
