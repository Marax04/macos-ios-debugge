//! `formula_simplifier` — SMT formula simplification before Z3.
//!
//! Performs lightweight algebraic rewrites on [`SymExpr`] trees so that fewer
//! (and simpler) formulas need to be sent to a heavyweight SMT solver.
//!
//! Provides:
//! * [`FormulaSimplifier`] — top-level simplification pass, applies all rules.
//! * [`BitwidthPropagation`] — infer and propagate bitvector widths.
//! * [`ConstantFolding`] — evaluate fully-concrete sub-expressions.
//! * [`DeMorganRewrite`] — apply De Morgan's laws to Boolean/bitwise expressions.
//! * [`ArithmeticIdentity`] — remove identity operations (x+0, x*1, x XOR 0 …).
//! * [`ExtractMerge`] — merge adjacent Extract/Concat operations.

use std::collections::HashMap;
use std::fmt;

use crate::SymExpr;
pub use crate::SymType;

// ─── Width helpers ────────────────────────────────────────────────────────────

const fn width_mask(w: u32) -> u64 {
    if w >= 64 {
        u64::MAX
    } else {
        (1u64 << w).wrapping_sub(1)
    }
}

const fn sign_extend(v: u64, w: u32) -> u64 {
    if w == 0 || w >= 64 {
        return v;
    }
    let bit = 1u64 << (w - 1);
    if v & bit != 0 {
        v | !width_mask(w)
    } else {
        v & width_mask(w)
    }
}

fn expr_width(e: &SymExpr) -> u32 {
    match e {
        SymExpr::ConstBv { width, .. } => *width,
        SymExpr::Var { ty, .. } => ty.width().unwrap_or(64),
        _ => 64,
    }
}

// ─── BitwidthPropagation ──────────────────────────────────────────────────────

/// Infers and propagates bitvector widths through expression trees.
///
/// Useful for catching width mismatches before sending formulas to Z3.
#[derive(Debug, Default, Clone)]
pub struct BitwidthPropagation {
    /// Known variable widths.
    var_widths: HashMap<String, u32>,
}

impl BitwidthPropagation {
    /// Create a new instance with no initial knowledge.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare that variable `name` has bitvector width `width`.
    pub fn declare(&mut self, name: impl Into<String>, width: u32) {
        self.var_widths.insert(name.into(), width);
    }

    /// Infer the output width of `expr`.
    ///
    /// Returns `None` when the width cannot be determined without more context.
    #[must_use]
    pub fn infer_width(&self, expr: &SymExpr) -> Option<u32> {
        match expr {
            SymExpr::ConstBv { width, .. } => Some(*width),
            SymExpr::Var { name, ty } => ty
                .width()
                .or_else(|| self.var_widths.get(name.as_str()).copied()),
            SymExpr::Add(l, r)
            | SymExpr::Sub(l, r)
            | SymExpr::Mul(l, r)
            | SymExpr::And(l, r)
            | SymExpr::Or(l, r)
            | SymExpr::Xor(l, r)
            | SymExpr::Shl(l, r)
            | SymExpr::LShr(l, r)
            | SymExpr::AShr(l, r) => self.infer_width(l).or_else(|| self.infer_width(r)),
            SymExpr::Not(e) | SymExpr::Neg(e) => self.infer_width(e),
            SymExpr::ZExt { target_width, .. } | SymExpr::SExt { target_width, .. } => {
                Some(*target_width)
            }
            SymExpr::Extract { hi, lo, .. } => Some(hi - lo + 1),
            SymExpr::Concat(hi, lo) => {
                let wh = self.infer_width(hi)?;
                let wl = self.infer_width(lo)?;
                Some(wh + wl)
            }
            SymExpr::ConstBool(_)
            | SymExpr::Eq(..)
            | SymExpr::Ne(..)
            | SymExpr::ULt(..)
            | SymExpr::ULe(..)
            | SymExpr::UGt(..)
            | SymExpr::UGe(..)
            | SymExpr::SLt(..)
            | SymExpr::SLe(..)
            | SymExpr::SGt(..)
            | SymExpr::SGe(..)
            | SymExpr::BoolAnd(..)
            | SymExpr::BoolOr(..)
            | SymExpr::BoolNot(..) => Some(1),
            SymExpr::Ite { then_, .. } => self.infer_width(then_),
            SymExpr::Load { size, .. } => Some(u32::from(*size) * 8),
            SymExpr::UDiv(l, _)
            | SymExpr::SDiv(l, _)
            | SymExpr::URem(l, _)
            | SymExpr::SRem(l, _) => self.infer_width(l),
            SymExpr::Store { .. } => None,
        }
    }

    /// Check whether `expr` is well-typed (all operands have compatible widths).
    ///
    /// Returns a list of error descriptions.
    #[must_use]
    pub fn check(&self, expr: &SymExpr) -> Vec<String> {
        let mut errors = Vec::new();
        self.check_inner(expr, &mut errors);
        errors
    }

    fn check_inner(&self, expr: &SymExpr, errors: &mut Vec<String>) {
        match expr {
            SymExpr::Add(l, r) | SymExpr::Sub(l, r) | SymExpr::And(l, r) | SymExpr::Or(l, r) => {
                if let (Some(wl), Some(wr)) = (self.infer_width(l), self.infer_width(r))
                    && wl != wr
                {
                    errors.push(format!("width mismatch: {wl} vs {wr}"));
                }
                self.check_inner(l, errors);
                self.check_inner(r, errors);
            }
            SymExpr::ZExt {
                expr: inner,
                target_width,
            } => {
                if let Some(w) = self.infer_width(inner)
                    && w > *target_width
                {
                    errors.push(format!("ZExt: source width {w} > target {target_width}"));
                }
                self.check_inner(inner, errors);
            }
            SymExpr::Extract {
                expr: inner,
                hi,
                lo,
            } => {
                if hi < lo {
                    errors.push(format!("Extract: hi={hi} < lo={lo}"));
                }
                self.check_inner(inner, errors);
            }
            _ => {}
        }
    }
}

// ─── ConstantFolding ──────────────────────────────────────────────────────────

/// Evaluates fully-concrete sub-expressions to their constant values.
///
/// Differs from [`crate::SymExprSimplifier`] in that it focuses exclusively on
/// numeric evaluation and is intended to run as a pre-pass before De Morgan and
/// identity rewrites.
#[derive(Debug, Default)]
pub struct ConstantFolding;

impl ConstantFolding {
    /// Create a new `ConstantFolding` pass.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Fold `expr` bottom-up.
    #[must_use]
    pub fn fold(&self, expr: SymExpr) -> SymExpr {
        match expr {
            // ── Terminals ─────────────────────────────────────────────────
            SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) | SymExpr::Var { .. } => expr,

            // ── Unary ─────────────────────────────────────────────────────
            SymExpr::Not(inner) => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBv { val, width } = s {
                    SymExpr::ConstBv {
                        val: (!val) & width_mask(width),
                        width,
                    }
                } else {
                    SymExpr::Not(Box::new(s))
                }
            }
            SymExpr::Neg(inner) => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBv { val, width } = s {
                    SymExpr::ConstBv {
                        val: val.wrapping_neg() & width_mask(width),
                        width,
                    }
                } else {
                    SymExpr::Neg(Box::new(s))
                }
            }
            SymExpr::BoolNot(inner) => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBool(b) = s {
                    SymExpr::ConstBool(!b)
                } else {
                    SymExpr::BoolNot(Box::new(s))
                }
            }
            SymExpr::ZExt {
                expr: inner,
                target_width,
            } => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBv { val, .. } = s {
                    SymExpr::ConstBv {
                        val,
                        width: target_width,
                    }
                } else {
                    SymExpr::ZExt {
                        expr: Box::new(s),
                        target_width,
                    }
                }
            }
            SymExpr::SExt {
                expr: inner,
                target_width,
            } => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBv { val, width } = s {
                    SymExpr::ConstBv {
                        val: sign_extend(val, width) & width_mask(target_width),
                        width: target_width,
                    }
                } else {
                    SymExpr::SExt {
                        expr: Box::new(s),
                        target_width,
                    }
                }
            }
            SymExpr::Extract {
                expr: inner,
                hi,
                lo,
            } => {
                let s = self.fold(*inner);
                if let SymExpr::ConstBv { val, .. } = s {
                    let w = hi - lo + 1;
                    SymExpr::ConstBv {
                        val: (val >> lo) & width_mask(w),
                        width: w,
                    }
                } else {
                    SymExpr::Extract {
                        expr: Box::new(s),
                        hi,
                        lo,
                    }
                }
            }

            // ── Binary arithmetic ─────────────────────────────────────────
            SymExpr::Add(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| (a.wrapping_add(b)) & width_mask(w),
                SymExpr::Add,
            ),
            SymExpr::Sub(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| (a.wrapping_sub(b)) & width_mask(w),
                SymExpr::Sub,
            ),
            SymExpr::Mul(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                // Absorbing zero: 0 * x = 0 and x * 0 = 0.
                if let SymExpr::ConstBv { val: 0, width } = ls {
                    return SymExpr::ConstBv { val: 0, width };
                }
                if let SymExpr::ConstBv { val: 0, width } = rs {
                    return SymExpr::ConstBv { val: 0, width };
                }
                if let (
                    SymExpr::ConstBv { val: a, width: w },
                    SymExpr::ConstBv { val: b, .. },
                ) = (&ls, &rs)
                {
                    SymExpr::ConstBv {
                        val: a.wrapping_mul(*b) & width_mask(*w),
                        width: *w,
                    }
                } else {
                    SymExpr::Mul(Box::new(ls), Box::new(rs))
                }
            }
            SymExpr::And(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| (a & b) & width_mask(w),
                SymExpr::And,
            ),
            SymExpr::Or(l, r) => {
                fold_bin2(self, *l, *r, |a, b, w| (a | b) & width_mask(w), SymExpr::Or)
            }
            SymExpr::Xor(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| (a ^ b) & width_mask(w),
                SymExpr::Xor,
            ),
            SymExpr::Shl(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| a.wrapping_shl(b.min(63) as u32) & width_mask(w),
                SymExpr::Shl,
            ),
            SymExpr::LShr(l, r) => fold_bin2(
                self,
                *l,
                *r,
                |a, b, w| a.wrapping_shr(b.min(63) as u32) & width_mask(w),
                SymExpr::LShr,
            ),
            SymExpr::AShr(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                if let (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, .. }) =
                    (&ls, &rs)
                {
                    let shift = u32::try_from((*rv).min(63)).unwrap_or(0);
                    let v = sign_extend(*lv, *lw)
                        .cast_signed()
                        .wrapping_shr(shift)
                        .cast_unsigned()
                        & width_mask(*lw);
                    SymExpr::ConstBv { val: v, width: *lw }
                } else {
                    SymExpr::AShr(Box::new(ls), Box::new(rs))
                }
            }
            SymExpr::Concat(hi, lo) => {
                let hs = self.fold(*hi);
                let ls = self.fold(*lo);
                if let (
                    SymExpr::ConstBv { val: hv, width: hw },
                    SymExpr::ConstBv { val: lv, width: lw },
                ) = (&hs, &ls)
                {
                    SymExpr::ConstBv {
                        // Guard shift-by-≥64: if lo width ≥ 64 the high part is lost.
                        val: if *lw >= 64 { *lv } else { (hv << lw) | lv },
                        width: hw + lw,
                    }
                } else {
                    SymExpr::Concat(Box::new(hs), Box::new(ls))
                }
            }

            // ── Division / remainder ──────────────────────────────────────
            SymExpr::UDiv(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, .. })
                        if *rv != 0 =>
                    {
                        SymExpr::ConstBv {
                            val: lv / rv,
                            width: *lw,
                        }
                    }
                    _ => SymExpr::UDiv(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::SDiv(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if *rv != 0 => {
                        let a = sign_extend(*lv, *lw).cast_signed();
                        let b = sign_extend(*rv, *rw).cast_signed();
                        SymExpr::ConstBv {
                            val: a.wrapping_div(b).cast_unsigned() & width_mask(*lw),
                            width: *lw,
                        }
                    }
                    _ => SymExpr::SDiv(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::URem(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, .. })
                        if *rv != 0 =>
                    {
                        SymExpr::ConstBv {
                            val: lv % rv,
                            width: *lw,
                        }
                    }
                    _ => SymExpr::URem(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::SRem(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if *rv != 0 => {
                        let a = sign_extend(*lv, *lw).cast_signed();
                        let b = sign_extend(*rv, *rw).cast_signed();
                        SymExpr::ConstBv {
                            val: a.wrapping_rem(b).cast_unsigned() & width_mask(*lw),
                            width: *lw,
                        }
                    }
                    _ => SymExpr::SRem(Box::new(ls), Box::new(rs)),
                }
            }

            // ── Comparisons ───────────────────────────────────────────────
            SymExpr::Eq(l, r) => fold_cmp(self, *l, *r, |a, b| a == b, SymExpr::Eq),
            SymExpr::Ne(l, r) => fold_cmp(self, *l, *r, |a, b| a != b, SymExpr::Ne),
            SymExpr::ULt(l, r) => fold_cmp(self, *l, *r, |a, b| a < b, SymExpr::ULt),
            SymExpr::ULe(l, r) => fold_cmp(self, *l, *r, |a, b| a <= b, SymExpr::ULe),
            SymExpr::UGt(l, r) => fold_cmp(self, *l, *r, |a, b| a > b, SymExpr::UGt),
            SymExpr::UGe(l, r) => fold_cmp(self, *l, *r, |a, b| a >= b, SymExpr::UGe),
            SymExpr::SLt(l, r) => fold_scmp(self, *l, *r, |a, b| a < b, SymExpr::SLt),
            SymExpr::SLe(l, r) => fold_scmp(self, *l, *r, |a, b| a <= b, SymExpr::SLe),
            SymExpr::SGt(l, r) => fold_scmp(self, *l, *r, |a, b| a > b, SymExpr::SGt),
            SymExpr::SGe(l, r) => fold_scmp(self, *l, *r, |a, b| a >= b, SymExpr::SGe),

            // ── Bool ──────────────────────────────────────────────────────
            SymExpr::BoolAnd(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBool(false), _) | (_, SymExpr::ConstBool(false)) => {
                        SymExpr::ConstBool(false)
                    }
                    (SymExpr::ConstBool(true), _) => rs,
                    (_, SymExpr::ConstBool(true)) => ls,
                    _ => SymExpr::BoolAnd(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::BoolOr(l, r) => {
                let ls = self.fold(*l);
                let rs = self.fold(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBool(true), _) | (_, SymExpr::ConstBool(true)) => {
                        SymExpr::ConstBool(true)
                    }
                    (SymExpr::ConstBool(false), _) => rs,
                    (_, SymExpr::ConstBool(false)) => ls,
                    _ => SymExpr::BoolOr(Box::new(ls), Box::new(rs)),
                }
            }

            // ── ITE ───────────────────────────────────────────────────────
            SymExpr::Ite { cond, then_, else_ } => {
                let cs = self.fold(*cond);
                match cs {
                    SymExpr::ConstBool(true) => self.fold(*then_),
                    SymExpr::ConstBool(false) => self.fold(*else_),
                    other => SymExpr::Ite {
                        cond: Box::new(other),
                        then_: Box::new(self.fold(*then_)),
                        else_: Box::new(self.fold(*else_)),
                    },
                }
            }

            // ── Memory ────────────────────────────────────────────────────
            SymExpr::Load { addr, size } => SymExpr::Load {
                addr: Box::new(self.fold(*addr)),
                size,
            },
            SymExpr::Store { mem, addr, val } => SymExpr::Store {
                mem: Box::new(self.fold(*mem)),
                addr: Box::new(self.fold(*addr)),
                val: Box::new(self.fold(*val)),
            },
        }
    }
}

fn fold_bin2<C>(
    cf: &ConstantFolding,
    l: SymExpr,
    r: SymExpr,
    op: impl Fn(u64, u64, u32) -> u64,
    cons: C,
) -> SymExpr
where
    C: Fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr,
{
    let ls = cf.fold(l);
    let rs = cf.fold(r);
    match (&ls, &rs) {
        (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, width: rw })
            if lw == rw =>
        {
            SymExpr::ConstBv {
                val: op(*lv, *rv, *lw),
                width: *lw,
            }
        }
        _ => cons(Box::new(ls), Box::new(rs)),
    }
}

fn fold_cmp<F, C>(cf: &ConstantFolding, l: SymExpr, r: SymExpr, op: F, cons: C) -> SymExpr
where
    F: Fn(u64, u64) -> bool,
    C: Fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr,
{
    let ls = cf.fold(l);
    let rs = cf.fold(r);
    match (&ls, &rs) {
        (SymExpr::ConstBv { val: lv, .. }, SymExpr::ConstBv { val: rv, .. }) => {
            SymExpr::ConstBool(op(*lv, *rv))
        }
        _ => cons(Box::new(ls), Box::new(rs)),
    }
}

fn fold_scmp<F, C>(cf: &ConstantFolding, l: SymExpr, r: SymExpr, op: F, cons: C) -> SymExpr
where
    F: Fn(i64, i64) -> bool,
    C: Fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr,
{
    let ls = cf.fold(l);
    let rs = cf.fold(r);
    match (&ls, &rs) {
        (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, width: rw }) => {
            SymExpr::ConstBool(op(
                sign_extend(*lv, *lw).cast_signed(),
                sign_extend(*rv, *rw).cast_signed(),
            ))
        }
        _ => cons(Box::new(ls), Box::new(rs)),
    }
}

// ─── DeMorganRewrite ─────────────────────────────────────────────────────────

/// Applies De Morgan's laws to Boolean and bitwise expressions:
///
/// * `NOT(A AND B)` → `(NOT A) OR  (NOT B)`
/// * `NOT(A OR  B)` → `(NOT A) AND (NOT B)`
/// * `BOOL_NOT(A AND B)` → `(BOOL_NOT A) OR  (BOOL_NOT B)`
/// * `BOOL_NOT(A OR  B)` → `(BOOL_NOT A) AND (BOOL_NOT B)`
#[derive(Debug, Clone)]
pub struct DeMorganRewrite {
    /// Maximum recursion depth; rewrites beyond this point return the input
    /// unchanged. Defaults to a generous bound that effectively means
    /// "no limit" for normal usage.
    pub max_depth: u32,
}

impl Default for DeMorganRewrite {
    fn default() -> Self {
        Self::new()
    }
}

impl DeMorganRewrite {
    /// Create a new `DeMorganRewrite` pass with the default depth limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: u32::MAX,
        }
    }

    /// Apply De Morgan rewrites recursively.
    #[must_use]
    pub fn rewrite(&self, expr: SymExpr) -> SymExpr {
        self.rewrite_inner(expr, self.max_depth)
    }

    fn rewrite_inner(&self, expr: SymExpr, depth: u32) -> SymExpr {
        if depth == 0 {
            return expr;
        }
        let next = depth - 1;
        match expr {
            SymExpr::Not(inner) => {
                let s = self.rewrite_inner(*inner, next);
                match s {
                    SymExpr::And(l, r) => {
                        // NOT(A AND B) → (NOT A) OR (NOT B)
                        SymExpr::Or(
                            Box::new(self.rewrite_inner(SymExpr::Not(l), next)),
                            Box::new(self.rewrite_inner(SymExpr::Not(r), next)),
                        )
                    }
                    SymExpr::Or(l, r) => {
                        // NOT(A OR B) → (NOT A) AND (NOT B)
                        SymExpr::And(
                            Box::new(self.rewrite_inner(SymExpr::Not(l), next)),
                            Box::new(self.rewrite_inner(SymExpr::Not(r), next)),
                        )
                    }
                    SymExpr::Not(inner2) => *inner2, // double negation
                    other => SymExpr::Not(Box::new(other)),
                }
            }
            SymExpr::BoolNot(inner) => {
                let s = self.rewrite_inner(*inner, next);
                match s {
                    SymExpr::BoolAnd(l, r) => SymExpr::BoolOr(
                        Box::new(self.rewrite_inner(SymExpr::BoolNot(l), next)),
                        Box::new(self.rewrite_inner(SymExpr::BoolNot(r), next)),
                    ),
                    SymExpr::BoolOr(l, r) => SymExpr::BoolAnd(
                        Box::new(self.rewrite_inner(SymExpr::BoolNot(l), next)),
                        Box::new(self.rewrite_inner(SymExpr::BoolNot(r), next)),
                    ),
                    SymExpr::BoolNot(inner2) => *inner2,
                    other => SymExpr::BoolNot(Box::new(other)),
                }
            }
            // Recurse into sub-expressions.
            SymExpr::BoolAnd(l, r) => {
                SymExpr::BoolAnd(Box::new(self.rewrite_inner(*l, next)), Box::new(self.rewrite_inner(*r, next)))
            }
            SymExpr::BoolOr(l, r) => {
                SymExpr::BoolOr(Box::new(self.rewrite_inner(*l, next)), Box::new(self.rewrite_inner(*r, next)))
            }
            SymExpr::And(l, r) => {
                SymExpr::And(Box::new(self.rewrite_inner(*l, next)), Box::new(self.rewrite_inner(*r, next)))
            }
            SymExpr::Or(l, r) => {
                SymExpr::Or(Box::new(self.rewrite_inner(*l, next)), Box::new(self.rewrite_inner(*r, next)))
            }
            SymExpr::Ite { cond, then_, else_ } => SymExpr::Ite {
                cond: Box::new(self.rewrite_inner(*cond, next)),
                then_: Box::new(self.rewrite_inner(*then_, next)),
                else_: Box::new(self.rewrite_inner(*else_, next)),
            },
            other => other,
        }
    }
}

// ─── ArithmeticIdentity ───────────────────────────────────────────────────────

/// Removes identity operations that are provably no-ops:
///
/// * `x + 0 = x`, `0 + x = x`
/// * `x - 0 = x`, `x - x = 0`
/// * `x * 1 = x`, `1 * x = x`, `x * 0 = 0`
/// * `x AND ALL_ONES = x`, `x AND 0 = 0`
/// * `x OR  0 = x`, `x OR ALL_ONES = ALL_ONES`
/// * `x XOR 0 = x`, `x XOR x = 0`
/// * `x SHL 0 = x`, `x SHR 0 = x`
#[derive(Debug, Clone)]
pub struct ArithmeticIdentity {
    /// Maximum recursion depth; rewrites beyond this point return the input
    /// unchanged. Defaults to a generous bound that effectively means
    /// "no limit" for normal usage.
    pub max_depth: u32,
}

impl Default for ArithmeticIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl ArithmeticIdentity {
    /// Create a new `ArithmeticIdentity` pass with the default depth limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: u32::MAX,
        }
    }

    /// Apply identity rewrites recursively.
    #[must_use]
    pub fn rewrite(&self, expr: SymExpr) -> SymExpr {
        self.rewrite_inner(expr, self.max_depth)
    }

    fn rewrite_inner(&self, expr: SymExpr, depth: u32) -> SymExpr {
        if depth == 0 {
            return expr;
        }
        let next = depth - 1;
        match expr {
            SymExpr::Add(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                match (&ls, &rs) {
                    (_, SymExpr::ConstBv { val: 0, .. }) => ls,
                    (SymExpr::ConstBv { val: 0, .. }, _) => rs,
                    _ => SymExpr::Add(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::Sub(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                match (&ls, &rs) {
                    (_, SymExpr::ConstBv { val: 0, .. }) => ls,
                    _ if ls == rs => SymExpr::ConstBv {
                        val: 0,
                        width: expr_width(&ls),
                    },
                    _ => SymExpr::Sub(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::Mul(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                match (&ls, &rs) {
                    (_, SymExpr::ConstBv { val: 0, width })
                    | (SymExpr::ConstBv { val: 0, width }, _) => SymExpr::ConstBv {
                        val: 0,
                        width: *width,
                    },
                    (_, SymExpr::ConstBv { val: 1, .. }) => ls,
                    (SymExpr::ConstBv { val: 1, .. }, _) => rs,
                    _ => SymExpr::Mul(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::And(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                let w = expr_width(&ls);
                match (&ls, &rs) {
                    (SymExpr::ConstBv { val: 0, width }, _)
                    | (_, SymExpr::ConstBv { val: 0, width }) => SymExpr::ConstBv {
                        val: 0,
                        width: *width,
                    },
                    (SymExpr::ConstBv { val, .. }, _) if *val == width_mask(w) => rs,
                    (_, SymExpr::ConstBv { val, .. }) if *val == width_mask(w) => ls,
                    _ if ls == rs => ls,
                    _ => SymExpr::And(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::Or(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                let w = expr_width(&ls);
                match (&ls, &rs) {
                    (_, SymExpr::ConstBv { val: 0, .. }) => ls,
                    (SymExpr::ConstBv { val: 0, .. }, _) => rs,
                    (SymExpr::ConstBv { val, .. }, _) if *val == width_mask(w) => ls,
                    (_, SymExpr::ConstBv { val, .. }) if *val == width_mask(w) => rs,
                    _ if ls == rs => ls,
                    _ => SymExpr::Or(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::Xor(l, r) => {
                let ls = self.rewrite_inner(*l, next);
                let rs = self.rewrite_inner(*r, next);
                match (&ls, &rs) {
                    (_, SymExpr::ConstBv { val: 0, .. }) => ls,
                    (SymExpr::ConstBv { val: 0, .. }, _) => rs,
                    _ if ls == rs => SymExpr::ConstBv {
                        val: 0,
                        width: expr_width(&ls),
                    },
                    _ => SymExpr::Xor(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::Shl(ref l, ref r)
            | SymExpr::LShr(ref l, ref r)
            | SymExpr::AShr(ref l, ref r) => {
                let ls = self.rewrite_inner((**l).clone(), next);
                let rs = self.rewrite_inner((**r).clone(), next);
                let cons: fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr = match &expr {
                    SymExpr::Shl(..) => SymExpr::Shl,
                    SymExpr::LShr(..) => SymExpr::LShr,
                    _ => SymExpr::AShr,
                };
                // Rust borrow issue: use discriminant instead of re-matching `expr`
                match &rs {
                    SymExpr::ConstBv { val: 0, .. } => ls,
                    _ => cons(Box::new(ls), Box::new(rs)),
                }
            }
            // Recurse into other nodes.
            SymExpr::Not(e) => SymExpr::Not(Box::new(self.rewrite_inner(*e, next))),
            SymExpr::Neg(e) => SymExpr::Neg(Box::new(self.rewrite_inner(*e, next))),
            SymExpr::Ite { cond, then_, else_ } => SymExpr::Ite {
                cond: Box::new(self.rewrite_inner(*cond, next)),
                then_: Box::new(self.rewrite_inner(*then_, next)),
                else_: Box::new(self.rewrite_inner(*else_, next)),
            },
            other => other,
        }
    }
}

// ─── ExtractMerge ─────────────────────────────────────────────────────────────

/// Merges adjacent `Extract` and `Concat` operations where possible.
///
/// Rules:
/// * `Concat(Extract(x, hi1, lo1+1), Extract(x, lo1, lo2)) = Extract(x, hi1, lo2)`
///   (two adjacent extracts from the same expression).
/// * `Extract(x, n-1, 0)` where `n == width(x)` → `x` (full-width extract).
/// * `Extract(ZExt(x, w), hi, lo)` where `hi < width(x)` → `Extract(x, hi, lo)`.
#[derive(Debug, Clone)]
pub struct ExtractMerge {
    /// Maximum recursion depth; rewrites beyond this point return the input
    /// unchanged. Defaults to a generous bound that effectively means
    /// "no limit" for normal usage.
    pub max_depth: u32,
}

impl Default for ExtractMerge {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtractMerge {
    /// Create a new `ExtractMerge` pass with the default depth limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: u32::MAX,
        }
    }

    /// Apply extract/concat merging recursively.
    #[must_use]
    pub fn rewrite(&self, expr: SymExpr) -> SymExpr {
        self.rewrite_inner(expr, self.max_depth)
    }

    fn rewrite_inner(&self, expr: SymExpr, depth: u32) -> SymExpr {
        if depth == 0 {
            return expr;
        }
        let next = depth - 1;
        match expr {
            // Extract simplification: ZExt propagation, then full-width removal.
            SymExpr::Extract {
                expr: inner,
                hi,
                lo,
            } => {
                let s = self.rewrite_inner(*inner, next);
                // ZExt propagation through extract: if the extracted range fits
                // entirely within the original (pre-ZExt) value, drop the ZExt.
                if let SymExpr::ZExt { expr: inner2, .. } = &s {
                    let src_w = expr_width(inner2);
                    if hi < src_w {
                        // Recurse so a resulting full-width extract collapses.
                        return self.rewrite_inner(
                            SymExpr::Extract {
                                expr: inner2.clone(),
                                hi,
                                lo,
                            },
                            next,
                        );
                    }
                }
                // Full-width extract: Extract(x, w-1, 0) → x
                let w = expr_width(&s);
                if lo == 0 && hi == w.saturating_sub(1) && w > 0 {
                    s
                } else {
                    SymExpr::Extract {
                        expr: Box::new(s),
                        hi,
                        lo,
                    }
                }
            }
            // Concat of adjacent extracts from the same source.
            SymExpr::Concat(hi_e, lo_e) => {
                let hs = self.rewrite_inner(*hi_e, next);
                let ls = self.rewrite_inner(*lo_e, next);
                if let (
                    SymExpr::Extract {
                        expr: hi_src,
                        hi: hi1,
                        lo: lo1,
                    },
                    SymExpr::Extract {
                        expr: lo_src,
                        hi: hi2,
                        lo: lo2,
                    },
                ) = (&hs, &ls)
                {
                    // Adjacent when lo1 == hi2 + 1 and same source.
                    if hi_src == lo_src && *lo1 == hi2.saturating_add(1) {
                        // Recurse so a resulting full-width extract collapses to the source.
                        return self.rewrite_inner(
                            SymExpr::Extract {
                                expr: hi_src.clone(),
                                hi: *hi1,
                                lo: *lo2,
                            },
                            next,
                        );
                    }
                }
                SymExpr::Concat(Box::new(hs), Box::new(ls))
            }
            // Recurse.
            SymExpr::Add(l, r) => {
                SymExpr::Add(Box::new(self.rewrite_inner(*l, next)), Box::new(self.rewrite_inner(*r, next)))
            }
            SymExpr::Ite { cond, then_, else_ } => SymExpr::Ite {
                cond: Box::new(self.rewrite_inner(*cond, next)),
                then_: Box::new(self.rewrite_inner(*then_, next)),
                else_: Box::new(self.rewrite_inner(*else_, next)),
            },
            other => other,
        }
    }
}

// ─── FormulaSimplifier ────────────────────────────────────────────────────────

/// Top-level simplifier that applies all sub-passes in order:
///
/// 1. [`ConstantFolding`]
/// 2. [`ArithmeticIdentity`]
/// 3. [`DeMorganRewrite`]
/// 4. [`ExtractMerge`]
///
/// Multiple passes are run until a fixed point is reached (or the iteration
/// limit is hit).
#[derive(Debug, Default)]
pub struct FormulaSimplifier {
    /// Maximum number of full-pass iterations.
    pub max_iterations: u32,
    /// Statistics: total nodes simplified.
    simplified_count: u64,
    /// Number of iterations actually performed.
    iterations_used: u32,
}

impl FormulaSimplifier {
    /// Create a simplifier with `max_iterations` passes.
    #[must_use]
    pub fn new(max_iterations: u32) -> Self {
        Self {
            max_iterations,
            ..Self::default()
        }
    }

    /// Simplify `expr` to a fixed point.
    #[must_use]
    pub fn simplify(&mut self, expr: SymExpr) -> SymExpr {
        let cf = ConstantFolding::new();
        let ai = ArithmeticIdentity::new();
        let dm = DeMorganRewrite::new();
        let em = ExtractMerge::new();

        let mut current = expr;
        for i in 0..self.max_iterations {
            let prev_hash = quick_hash(&current);
            current = cf.fold(current);
            current = ai.rewrite(current);
            current = dm.rewrite(current);
            current = em.rewrite(current);
            self.simplified_count += 1;
            self.iterations_used = i + 1;
            if quick_hash(&current) == prev_hash {
                break; // fixed point
            }
        }
        current
    }

    /// Return the total number of simplifications applied.
    #[must_use]
    pub const fn simplified_count(&self) -> u64 {
        self.simplified_count
    }

    /// Return the number of iterations used in the last [`Self::simplify`] call.
    #[must_use]
    pub const fn iterations_used(&self) -> u32 {
        self.iterations_used
    }

    /// Simplify a path condition vector.
    #[must_use]
    pub fn simplify_path(&mut self, path: Vec<SymExpr>) -> Vec<SymExpr> {
        path.into_iter().map(|e| self.simplify(e)).collect()
    }
}

impl fmt::Display for FormulaSimplifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FormulaSimplifier {{ simplified={} }}",
            self.simplified_count
        )
    }
}

/// A very cheap hash used only to detect fixed-point convergence.
fn quick_hash(expr: &SymExpr) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    // Hash the discriminant name as a simple proxy.
    format!("{expr:?}").hash(&mut h);
    h.finish()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(v: u64, w: u32) -> SymExpr {
        SymExpr::ConstBv { val: v, width: w }
    }
    fn var(n: &str, w: u32) -> SymExpr {
        SymExpr::Var {
            name: n.to_string(),
            ty: SymType::BitVec(w),
        }
    }

    // ── BitwidthPropagation ──────────────────────────────────────────────

    #[test]
    fn test_bwp_const_width() {
        let b = BitwidthPropagation::new();
        assert_eq!(b.infer_width(&bv(0xFF, 8)), Some(8));
    }

    #[test]
    fn test_bwp_var_declared() {
        let mut b = BitwidthPropagation::new();
        b.declare("x", 32);
        let v = SymExpr::Var {
            name: "x".into(),
            ty: SymType::Bool,
        };
        // Bool has no bitwidth but declared override provides 32.
        assert_eq!(b.infer_width(&v), Some(32));
    }

    #[test]
    fn test_bwp_extract_width() {
        let b = BitwidthPropagation::new();
        let e = SymExpr::Extract {
            expr: Box::new(bv(0xFFFF, 16)),
            hi: 7,
            lo: 0,
        };
        assert_eq!(b.infer_width(&e), Some(8));
    }

    #[test]
    fn test_bwp_concat_width() {
        let b = BitwidthPropagation::new();
        let c = SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8)));
        assert_eq!(b.infer_width(&c), Some(16));
    }

    #[test]
    fn test_bwp_check_mismatch() {
        let b = BitwidthPropagation::new();
        let e = SymExpr::Add(Box::new(bv(1, 8)), Box::new(bv(1, 16)));
        let errors = b.check(&e);
        assert!(!errors.is_empty());
    }

    // ── ConstantFolding ──────────────────────────────────────────────────

    #[test]
    fn test_cf_add_consts() {
        let cf = ConstantFolding::new();
        let e = SymExpr::Add(Box::new(bv(3, 32)), Box::new(bv(4, 32)));
        assert_eq!(cf.fold(e), bv(7, 32));
    }

    #[test]
    fn test_cf_mul_by_zero() {
        let cf = ConstantFolding::new();
        let e = SymExpr::Mul(Box::new(bv(0, 64)), Box::new(var("x", 64)));
        let result = cf.fold(e);
        assert_eq!(result, bv(0, 64));
    }

    #[test]
    fn test_cf_extract_const() {
        let cf = ConstantFolding::new();
        let e = SymExpr::Extract {
            expr: Box::new(bv(0xABCD, 16)),
            hi: 7,
            lo: 0,
        };
        assert_eq!(cf.fold(e), bv(0xCD, 8));
    }

    #[test]
    fn test_cf_ite_true() {
        let cf = ConstantFolding::new();
        let e = SymExpr::Ite {
            cond: Box::new(SymExpr::ConstBool(true)),
            then_: Box::new(bv(42, 64)),
            else_: Box::new(bv(0, 64)),
        };
        assert_eq!(cf.fold(e), bv(42, 64));
    }

    #[test]
    fn test_cf_signed_cmp() {
        let cf = ConstantFolding::new();
        // -1 as i8 (0xFF in 8-bit) < 0: SLt(0xFF:8, 0:8)
        let e = SymExpr::SLt(Box::new(bv(0xFF, 8)), Box::new(bv(0, 8)));
        assert_eq!(cf.fold(e), SymExpr::ConstBool(true)); // -1 < 0
    }

    #[test]
    fn test_cf_concat_consts() {
        let cf = ConstantFolding::new();
        let e = SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8)));
        assert_eq!(cf.fold(e), bv(0xABCD, 16));
    }

    #[test]
    fn test_cf_ashr_negative() {
        let cf = ConstantFolding::new();
        // AShr(0x80:8, 1:8) should sign-extend → 0xC0
        let e = SymExpr::AShr(Box::new(bv(0x80, 8)), Box::new(bv(1, 8)));
        if let SymExpr::ConstBv { val, width: 8 } = cf.fold(e) {
            assert_eq!(val, 0xC0, "expected arithmetic right-shift with sign fill");
        } else {
            panic!("expected constant fold");
        }
    }

    // ── DeMorganRewrite ──────────────────────────────────────────────────

    #[test]
    fn test_demorgan_not_and() {
        let dm = DeMorganRewrite::new();
        let e = SymExpr::Not(Box::new(SymExpr::And(
            Box::new(var("a", 8)),
            Box::new(var("b", 8)),
        )));
        let r = dm.rewrite(e);
        // Should become Or(Not(a), Not(b))
        assert!(matches!(r, SymExpr::Or(_, _)));
    }

    #[test]
    fn test_demorgan_not_or() {
        let dm = DeMorganRewrite::new();
        let e = SymExpr::Not(Box::new(SymExpr::Or(
            Box::new(bv(0xF, 4)),
            Box::new(var("b", 4)),
        )));
        let r = dm.rewrite(e);
        assert!(matches!(r, SymExpr::And(_, _)));
    }

    #[test]
    fn test_demorgan_bool_not_and() {
        let dm = DeMorganRewrite::new();
        let e = SymExpr::BoolNot(Box::new(SymExpr::BoolAnd(
            Box::new(SymExpr::ConstBool(true)),
            Box::new(SymExpr::ConstBool(false)),
        )));
        let r = dm.rewrite(e);
        assert!(matches!(r, SymExpr::BoolOr(_, _)));
    }

    #[test]
    fn test_demorgan_double_not() {
        let dm = DeMorganRewrite::new();
        let e = SymExpr::Not(Box::new(SymExpr::Not(Box::new(var("x", 32)))));
        assert_eq!(dm.rewrite(e), var("x", 32));
    }

    // ── ArithmeticIdentity ───────────────────────────────────────────────

    #[test]
    fn test_ai_add_zero() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Add(Box::new(var("x", 64)), Box::new(bv(0, 64)));
        assert_eq!(ai.rewrite(e), var("x", 64));
    }

    #[test]
    fn test_ai_sub_self() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Sub(Box::new(bv(5, 32)), Box::new(bv(5, 32)));
        assert_eq!(ai.rewrite(e), bv(0, 32));
    }

    #[test]
    fn test_ai_mul_one() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Mul(Box::new(bv(1, 64)), Box::new(var("y", 64)));
        assert_eq!(ai.rewrite(e), var("y", 64));
    }

    #[test]
    fn test_ai_mul_zero() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Mul(Box::new(var("x", 32)), Box::new(bv(0, 32)));
        assert_eq!(ai.rewrite(e), bv(0, 32));
    }

    #[test]
    fn test_ai_xor_self() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Xor(Box::new(bv(42, 16)), Box::new(bv(42, 16)));
        assert_eq!(ai.rewrite(e), bv(0, 16));
    }

    #[test]
    fn test_ai_shl_zero() {
        let ai = ArithmeticIdentity::new();
        let e = SymExpr::Shl(Box::new(var("x", 64)), Box::new(bv(0, 64)));
        assert_eq!(ai.rewrite(e), var("x", 64));
    }

    #[test]
    fn test_ai_and_all_ones() {
        let ai = ArithmeticIdentity::new();
        // AND with all-ones (0xFF) for 8-bit should return x.
        let e = SymExpr::And(Box::new(var("x", 8)), Box::new(bv(0xFF, 8)));
        assert_eq!(ai.rewrite(e), var("x", 8));
    }

    // ── ExtractMerge ─────────────────────────────────────────────────────

    #[test]
    fn test_em_full_width_extract_removed() {
        let em = ExtractMerge::new();
        let inner = bv(0xABCD, 16);
        let e = SymExpr::Extract {
            expr: Box::new(inner.clone()),
            hi: 15,
            lo: 0,
        };
        assert_eq!(em.rewrite(e), inner);
    }

    #[test]
    fn test_em_zext_propagation() {
        let em = ExtractMerge::new();
        let x = bv(0xAB, 8);
        let zext = SymExpr::ZExt {
            expr: Box::new(x.clone()),
            target_width: 16,
        };
        // Extract bits [7:0] from ZExt(x, 16) → Extract(x, 7, 0) = x
        let e = SymExpr::Extract {
            expr: Box::new(zext),
            hi: 7,
            lo: 0,
        };
        let result = em.rewrite(e);
        // Should reduce to Extract(x, 7, 0) — full width → x
        assert_eq!(result, x);
    }

    #[test]
    fn test_em_adjacent_concat_merge() {
        let em = ExtractMerge::new();
        let src = bv(0xABCD, 16);
        // Concat(Extract(src, 15, 8), Extract(src, 7, 0)) → Extract(src, 15, 0) → src
        let hi_ext = SymExpr::Extract {
            expr: Box::new(src.clone()),
            hi: 15,
            lo: 8,
        };
        let lo_ext = SymExpr::Extract {
            expr: Box::new(src.clone()),
            hi: 7,
            lo: 0,
        };
        let concat = SymExpr::Concat(Box::new(hi_ext), Box::new(lo_ext));
        let result = em.rewrite(concat);
        // merged extract should become src (full width)
        assert_eq!(result, src);
    }

    // ── FormulaSimplifier ────────────────────────────────────────────────

    #[test]
    fn test_formula_simplifier_runs() {
        let mut s = FormulaSimplifier::new(5);
        let e = SymExpr::Add(Box::new(bv(10, 32)), Box::new(bv(20, 32)));
        let result = s.simplify(e);
        assert_eq!(result, bv(30, 32));
        assert!(s.simplified_count() > 0);
    }

    #[test]
    fn test_formula_simplifier_fixed_point() {
        let mut s = FormulaSimplifier::new(10);
        let e = var("x", 64);
        let result = s.simplify(e.clone());
        assert_eq!(result, e); // variable is already at fixed point
    }

    #[test]
    fn test_formula_simplifier_path() {
        let mut s = FormulaSimplifier::new(3);
        let path = vec![
            SymExpr::Add(Box::new(bv(1, 64)), Box::new(bv(2, 64))),
            SymExpr::Mul(Box::new(bv(3, 32)), Box::new(bv(0, 32))),
        ];
        let simplified = s.simplify_path(path);
        assert_eq!(simplified[0], bv(3, 64));
        assert_eq!(simplified[1], bv(0, 32));
    }

    #[test]
    fn test_formula_simplifier_display() {
        let s = FormulaSimplifier::new(5);
        assert!(s.to_string().contains("FormulaSimplifier"));
    }
}
