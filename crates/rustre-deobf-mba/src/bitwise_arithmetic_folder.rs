//! Bitwise-arithmetic identity folder.
//!
//! Folds identities like `x & 0 = 0`, `x | ~x = -1`, `x ^ x = 0`,
//! `x + 0 = x`, `x * 1 = x`, `x * 0 = 0`, `x >> 0 = x`, `0 - x = -x`, etc.
//! Handles 32-bit and 64-bit overflow semantics and iterates to a fixed point.

use std::fmt;
use crate::MbaExpr;

// ─── BitWidth ─────────────────────────────────────────────────────────────────

/// Arithmetic bit-width context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWidth {
    B32,
    B64,
}

impl BitWidth {
    #[must_use] 
    pub const fn mask(self) -> i64 {
        match self {
            Self::B32 => 0x0000_0000_FFFF_FFFFi64,
            Self::B64 => -1i64,
        }
    }

    #[must_use] 
    pub const fn wrap(self, v: i64) -> i64 {
        match self {
            Self::B32 => (v as i32) as i64,
            Self::B64 => v,
        }
    }

    #[must_use] 
    pub const fn wrap_u(self, v: i64) -> i64 {
        match self {
            Self::B32 => (v as u32) as i64,
            Self::B64 => v,
        }
    }
}

// ─── ConstantExpr ─────────────────────────────────────────────────────────────

/// A folded constant result with associated bit width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstantExpr {
    pub value: i64,
    pub width: BitWidth,
}

impl ConstantExpr {
    #[must_use] 
    pub const fn new(value: i64, width: BitWidth) -> Self {
        Self { value: width.wrap(value), width }
    }

    #[must_use] 
    pub const fn as_zero(width: BitWidth) -> Self { Self { value: 0, width } }
    #[must_use] 
    pub const fn as_neg_one(width: BitWidth) -> Self { Self { value: -1, width } }

    #[must_use] 
    pub const fn to_expr(self) -> MbaExpr {
        MbaExpr::Const(self.value)
    }
}

// ─── FoldRule ─────────────────────────────────────────────────────────────────

/// A single folding rule.
pub struct FoldRule {
    pub name: &'static str,
    pub description: &'static str,
    pub apply: fn(&MbaExpr, BitWidth) -> Option<MbaExpr>,
}

impl fmt::Debug for FoldRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FoldRule({})", self.name)
    }
}

// ─── Individual fold rules ────────────────────────────────────────────────────

fn fold_const_add(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Add(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a.wrapping_add(b))));
        }
    None
}
fn fold_const_sub(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Sub(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a.wrapping_sub(b))));
        }
    None
}
fn fold_const_mul(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a.wrapping_mul(b))));
        }
    None
}
fn fold_const_and(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a & b)));
        }
    None
}
fn fold_const_or(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a | b)));
        }
    None
}
fn fold_const_xor(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Xor(l, r) = e
        && let (Some(a), Some(b)) = (l.is_const(), r.is_const()) {
            return Some(MbaExpr::Const(w.wrap(a ^ b)));
        }
    None
}
fn fold_const_not(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Not(inner) = e
        && let Some(a) = inner.is_const() { return Some(MbaExpr::Const(w.wrap(!a))); }
    None
}
fn fold_const_neg(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Neg(inner) = e
        && let Some(a) = inner.is_const() { return Some(MbaExpr::Const(w.wrap(a.wrapping_neg()))); }
    None
}
fn fold_const_shl(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Shl(inner, n) = e
        && let Some(a) = inner.is_const() { return Some(MbaExpr::Const(w.wrap(a.wrapping_shl(u32::from(*n))))); }
    None
}
fn fold_const_shr(e: &MbaExpr, w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Shr(inner, n) = e
        && let Some(a) = inner.is_const() {
            let v = (a as u64) >> u32::from(*n);
            return Some(MbaExpr::Const(w.wrap(v as i64)));
        }
    None
}
fn fold_and_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e
        && (matches!(l.as_ref(), MbaExpr::Const(0)) || matches!(r.as_ref(), MbaExpr::Const(0))) {
            return Some(MbaExpr::Const(0));
        }
    None
}
fn fold_and_neg_one(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(-1)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(-1)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn fold_and_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e && l == r { return Some(l.as_ref().clone()); }
    None
}
fn fold_or_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn fold_or_neg_one(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e
        && (matches!(l.as_ref(), MbaExpr::Const(-1)) || matches!(r.as_ref(), MbaExpr::Const(-1))) {
            return Some(MbaExpr::Const(-1));
        }
    None
}
fn fold_or_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e && l == r { return Some(l.as_ref().clone()); }
    None
}
fn fold_or_not_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    // x | ~x = -1
    if let MbaExpr::Or(l, r) = e {
        if let MbaExpr::Not(inner) = r.as_ref() && inner.as_ref() == l.as_ref() { return Some(MbaExpr::Const(-1)); }
        if let MbaExpr::Not(inner) = l.as_ref() && inner.as_ref() == r.as_ref() { return Some(MbaExpr::Const(-1)); }
    }
    None
}
fn fold_and_not_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    // x & ~x = 0
    if let MbaExpr::And(l, r) = e {
        if let MbaExpr::Not(inner) = r.as_ref() && inner.as_ref() == l.as_ref() { return Some(MbaExpr::Const(0)); }
        if let MbaExpr::Not(inner) = l.as_ref() && inner.as_ref() == r.as_ref() { return Some(MbaExpr::Const(0)); }
    }
    None
}
fn fold_xor_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Xor(l, r) = e && l == r { return Some(MbaExpr::Const(0)); }
    None
}
fn fold_xor_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Xor(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn fold_xor_neg_one(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    // x ^ (-1) = ~x
    if let MbaExpr::Xor(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(-1)) { return Some(MbaExpr::mk_not(r.as_ref().clone())); }
        if matches!(r.as_ref(), MbaExpr::Const(-1)) { return Some(MbaExpr::mk_not(l.as_ref().clone())); }
    }
    None
}
fn fold_add_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Add(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn fold_sub_self(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Sub(l, r) = e && l == r { return Some(MbaExpr::Const(0)); }
    None
}
fn fold_sub_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Sub(l, r) = e
        && matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    None
}
fn fold_zero_sub(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Sub(l, r) = e
        && matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(MbaExpr::mk_neg(r.as_ref().clone())); }
    None
}
fn fold_mul_one(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(1)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(1)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn fold_mul_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e
        && (matches!(l.as_ref(), MbaExpr::Const(0)) || matches!(r.as_ref(), MbaExpr::Const(0))) {
            return Some(MbaExpr::Const(0));
        }
    None
}
fn fold_mul_neg_one(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(-1)) { return Some(MbaExpr::mk_neg(r.as_ref().clone())); }
        if matches!(r.as_ref(), MbaExpr::Const(-1)) { return Some(MbaExpr::mk_neg(l.as_ref().clone())); }
    }
    None
}
fn fold_shl_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Shl(inner, 0) = e { return Some(inner.as_ref().clone()); }
    None
}
fn fold_shr_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Shr(inner, 0) = e { return Some(inner.as_ref().clone()); }
    None
}
fn fold_sar_zero(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Sar(inner, 0) = e { return Some(inner.as_ref().clone()); }
    None
}
fn fold_double_not(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Not(inner) = e
        && let MbaExpr::Not(ii) = inner.as_ref() { return Some(ii.as_ref().clone()); }
    None
}
fn fold_double_neg(e: &MbaExpr, _w: BitWidth) -> Option<MbaExpr> {
    if let MbaExpr::Neg(inner) = e
        && let MbaExpr::Neg(ii) = inner.as_ref() { return Some(ii.as_ref().clone()); }
    None
}

/// Build the complete fold rule set.
#[must_use] 
pub fn all_fold_rules() -> Vec<FoldRule> {
    vec![
        FoldRule { name: "const-add",      description: "Const(a)+Const(b)→Const(a+b)",  apply: fold_const_add },
        FoldRule { name: "const-sub",      description: "Const(a)-Const(b)→Const(a-b)",  apply: fold_const_sub },
        FoldRule { name: "const-mul",      description: "Const(a)*Const(b)→Const(a*b)",  apply: fold_const_mul },
        FoldRule { name: "const-and",      description: "Const(a)&Const(b)→Const(a&b)",  apply: fold_const_and },
        FoldRule { name: "const-or",       description: "Const(a)|Const(b)→Const(a|b)",  apply: fold_const_or },
        FoldRule { name: "const-xor",      description: "Const(a)^Const(b)→Const(a^b)",  apply: fold_const_xor },
        FoldRule { name: "const-not",      description: "~Const(a)→Const(!a)",            apply: fold_const_not },
        FoldRule { name: "const-neg",      description: "-Const(a)→Const(-a)",            apply: fold_const_neg },
        FoldRule { name: "const-shl",      description: "Const(a)<<n→Const(a<<n)",        apply: fold_const_shl },
        FoldRule { name: "const-shr",      description: "Const(a)>>n→Const(a>>n)",        apply: fold_const_shr },
        FoldRule { name: "and-zero",       description: "x&0→0",                          apply: fold_and_zero },
        FoldRule { name: "and-neg-one",    description: "x&(-1)→x",                       apply: fold_and_neg_one },
        FoldRule { name: "and-self",       description: "x&x→x",                          apply: fold_and_self },
        FoldRule { name: "and-not-self",   description: "x&~x→0",                         apply: fold_and_not_self },
        FoldRule { name: "or-zero",        description: "x|0→x",                          apply: fold_or_zero },
        FoldRule { name: "or-neg-one",     description: "x|(-1)→-1",                      apply: fold_or_neg_one },
        FoldRule { name: "or-self",        description: "x|x→x",                          apply: fold_or_self },
        FoldRule { name: "or-not-self",    description: "x|~x→-1",                        apply: fold_or_not_self },
        FoldRule { name: "xor-self",       description: "x^x→0",                          apply: fold_xor_self },
        FoldRule { name: "xor-zero",       description: "x^0→x",                          apply: fold_xor_zero },
        FoldRule { name: "xor-neg-one",    description: "x^(-1)→~x",                      apply: fold_xor_neg_one },
        FoldRule { name: "add-zero",       description: "x+0→x",                          apply: fold_add_zero },
        FoldRule { name: "sub-self",       description: "x-x→0",                          apply: fold_sub_self },
        FoldRule { name: "sub-zero",       description: "x-0→x",                          apply: fold_sub_zero },
        FoldRule { name: "zero-sub",       description: "0-x→-x",                         apply: fold_zero_sub },
        FoldRule { name: "mul-one",        description: "x*1→x",                          apply: fold_mul_one },
        FoldRule { name: "mul-zero",       description: "x*0→0",                          apply: fold_mul_zero },
        FoldRule { name: "mul-neg-one",    description: "x*(-1)→-x",                      apply: fold_mul_neg_one },
        FoldRule { name: "shl-zero",       description: "x<<0→x",                         apply: fold_shl_zero },
        FoldRule { name: "shr-zero",       description: "x>>0→x",                         apply: fold_shr_zero },
        FoldRule { name: "sar-zero",       description: "x>>>0→x",                        apply: fold_sar_zero },
        FoldRule { name: "double-not",     description: "~~x→x",                          apply: fold_double_not },
        FoldRule { name: "double-neg",     description: "-(-x)→x",                        apply: fold_double_neg },
    ]
}

// ─── FoldResult ───────────────────────────────────────────────────────────────

/// Result of a fold pass over an expression.
#[derive(Debug, Clone)]
pub struct FoldResult {
    pub original: MbaExpr,
    pub folded: MbaExpr,
    pub rules_fired: Vec<String>,
    pub complexity_before: usize,
    pub complexity_after: usize,
    pub passes: usize,
}

impl FoldResult {
    #[must_use] 
    pub const fn was_folded(&self) -> bool {
        self.complexity_after < self.complexity_before
    }
    #[must_use] 
    pub const fn reduction(&self) -> usize {
        self.complexity_before.saturating_sub(self.complexity_after)
    }
}

impl fmt::Display for FoldResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FoldResult({} → {}, passes={})", self.original, self.folded, self.passes)
    }
}

// ─── FoldPass ─────────────────────────────────────────────────────────────────

/// Configuration for a single fold pass.
#[derive(Debug, Clone)]
pub struct FoldPass {
    pub max_passes: usize,
    pub width: BitWidth,
}

impl Default for FoldPass {
    fn default() -> Self {
        Self { max_passes: 64, width: BitWidth::B64 }
    }
}

impl FoldPass {
    #[must_use] 
    pub const fn new(max_passes: usize, width: BitWidth) -> Self {
        Self { max_passes, width }
    }
}

// ─── ArithFolder ─────────────────────────────────────────────────────────────

/// The main bitwise-arithmetic identity folder.
pub struct ArithFolder {
    pub rules: Vec<FoldRule>,
    pub pass_config: FoldPass,
}

impl Default for ArithFolder {
    fn default() -> Self {
        Self { rules: all_fold_rules(), pass_config: FoldPass::default() }
    }
}

impl ArithFolder {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub const fn with_width(mut self, w: BitWidth) -> Self {
        self.pass_config.width = w;
        self
    }

    /// Fold `expr` to a fixed point and return the full result.
    #[must_use] 
    pub fn fold(&self, expr: MbaExpr) -> FoldResult {
        let original = expr.clone();
        let complexity_before = expr.complexity();
        let mut current = expr;
        let mut all_fired = Vec::new();
        let mut passes = 0;

        for _ in 0..self.pass_config.max_passes {
            let (next, fired) = self.fold_pass(&current);
            passes += 1;
            if fired.is_empty() { break; }
            all_fired.extend(fired);
            current = next;
        }

        FoldResult {
            original,
            folded: current.clone(),
            rules_fired: all_fired,
            complexity_before,
            complexity_after: current.complexity(),
            passes,
        }
    }

    /// Apply one bottom-up fold pass.  Returns `(new_expr, fired_rule_names)`.
    #[must_use] 
    pub fn fold_pass(&self, expr: &MbaExpr) -> (MbaExpr, Vec<String>) {
        let mut fired = Vec::new();
        let rebuilt = self.rebuild(expr, &mut fired);
        let w = self.pass_config.width;
        for rule in &self.rules {
            if let Some(result) = (rule.apply)(&rebuilt, w) {
                fired.push(rule.name.to_owned());
                return (result, fired);
            }
        }
        (rebuilt, fired)
    }

    fn rebuild(&self, expr: &MbaExpr, fired: &mut Vec<String>) -> MbaExpr {
        match expr {
            MbaExpr::Const(_) | MbaExpr::Var(_) => expr.clone(),
            MbaExpr::Neg(e) => { let (ne, nf) = self.fold_pass(e); fired.extend(nf); MbaExpr::Neg(Box::new(ne)) }
            MbaExpr::Not(e) => { let (ne, nf) = self.fold_pass(e); fired.extend(nf); MbaExpr::Not(Box::new(ne)) }
            MbaExpr::Shl(e, n) => { let (ne, nf) = self.fold_pass(e); fired.extend(nf); MbaExpr::Shl(Box::new(ne), *n) }
            MbaExpr::Shr(e, n) => { let (ne, nf) = self.fold_pass(e); fired.extend(nf); MbaExpr::Shr(Box::new(ne), *n) }
            MbaExpr::Sar(e, n) => { let (ne, nf) = self.fold_pass(e); fired.extend(nf); MbaExpr::Sar(Box::new(ne), *n) }
            MbaExpr::Add(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_add),
            MbaExpr::Sub(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_sub),
            MbaExpr::Mul(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_mul),
            MbaExpr::And(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_and),
            MbaExpr::Or(l, r)  => self.rebuild_bin(l, r, fired, MbaExpr::mk_or),
            MbaExpr::Xor(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_xor),
        }
    }

    fn rebuild_bin(&self, l: &MbaExpr, r: &MbaExpr, fired: &mut Vec<String>, ctor: fn(MbaExpr,MbaExpr)->MbaExpr) -> MbaExpr {
        let (nl, lf) = self.fold_pass(l);
        let (nr, rf) = self.fold_pass(r);
        fired.extend(lf);
        fired.extend(rf);
        ctor(nl, nr)
    }

    /// Fold only constant sub-expressions (no structural rewrites).
    #[must_use] 
    pub fn fold_constants_only(&self, expr: MbaExpr) -> MbaExpr {
        let const_rules: Vec<&FoldRule> = self.rules.iter()
            .filter(|r| r.name.starts_with("const-"))
            .collect();
        let mut current = expr;
        for _ in 0..self.pass_config.max_passes {
            let w = self.pass_config.width;
            let (next, fired) = self.fold_with_rules(&current, &const_rules, w);
            if fired.is_empty() { break; }
            current = next;
        }
        current
    }

    fn fold_with_rules(&self, expr: &MbaExpr, rules: &[&FoldRule], w: BitWidth) -> (MbaExpr, Vec<String>) {
        let mut fired = Vec::new();
        let rebuilt = self.rebuild(expr, &mut fired);
        for rule in rules {
            if let Some(result) = (rule.apply)(&rebuilt, w) {
                fired.push(rule.name.to_owned());
                return (result, fired);
            }
        }
        (rebuilt, fired)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MbaExpr;

    fn x() -> MbaExpr { MbaExpr::Var("x".to_owned()) }

    #[test]
    fn test_fold_and_zero() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_and(x(), MbaExpr::Const(0));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_fold_and_neg_one() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_and(x(), MbaExpr::Const(-1));
        let r = f.fold(expr);
        assert_eq!(r.folded, x());
    }

    #[test]
    fn test_fold_or_neg_one() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_or(x(), MbaExpr::Const(-1));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(-1));
    }

    #[test]
    fn test_fold_xor_self() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_xor(x(), x());
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_fold_add_zero() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_add(MbaExpr::Const(0), x());
        let r = f.fold(expr);
        assert_eq!(r.folded, x());
    }

    #[test]
    fn test_fold_mul_one() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_mul(x(), MbaExpr::Const(1));
        let r = f.fold(expr);
        assert_eq!(r.folded, x());
    }

    #[test]
    fn test_fold_mul_zero() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_mul(x(), MbaExpr::Const(0));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_fold_shl_zero() {
        let f = ArithFolder::new();
        let expr = MbaExpr::Shl(Box::new(x()), 0);
        let r = f.fold(expr);
        assert_eq!(r.folded, x());
    }

    #[test]
    fn test_fold_double_not() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_not(MbaExpr::mk_not(x()));
        let r = f.fold(expr);
        assert_eq!(r.folded, x());
    }

    #[test]
    fn test_fold_const_add() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_add(MbaExpr::Const(3), MbaExpr::Const(4));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(7));
    }

    #[test]
    fn test_fold_const_mul_32bit() {
        let f = ArithFolder::new().with_width(BitWidth::B32);
        // 0x80000000 + 0x80000000 would overflow in 32-bit: should give 0 (wrapping).
        let expr = MbaExpr::mk_add(MbaExpr::Const(0x8000_0000), MbaExpr::Const(0x8000_0000));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_fold_or_not_self() {
        let f = ArithFolder::new();
        let expr = MbaExpr::Or(Box::new(x()), Box::new(MbaExpr::Not(Box::new(x()))));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(-1));
    }

    #[test]
    fn test_fold_and_not_self() {
        let f = ArithFolder::new();
        let expr = MbaExpr::And(Box::new(x()), Box::new(MbaExpr::Not(Box::new(x()))));
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_fold_sub_self() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_sub(x(), x());
        let r = f.fold(expr);
        assert_eq!(r.folded, MbaExpr::Const(0));
    }

    #[test]
    fn test_bit_width_mask() {
        assert_eq!(BitWidth::B32.mask(), 0xFFFF_FFFF);
        assert_eq!(BitWidth::B64.mask(), -1);
    }

    #[test]
    fn test_fold_result_display() {
        let f = ArithFolder::new();
        let expr = MbaExpr::mk_and(x(), MbaExpr::Const(0));
        let r = f.fold(expr);
        assert!(r.to_string().contains("→"));
        assert!(r.was_folded());
    }
}
