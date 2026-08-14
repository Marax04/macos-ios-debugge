//! MBA expression simplifier via truth-table and rewrite rules.
//!
//! Implements truth-table-based simplification for 1–2 variable expressions
//! (enumerates all 2^4 = 16 combinations), pattern rewriting, and correctness
//! verification by evaluating both the original and simplified form.

use std::collections::HashMap;
use std::fmt;

use crate::MbaExpr;

// ─── TruthTable ───────────────────────────────────────────────────────────────

/// A truth-table for an expression with at most 2 variables evaluated at
/// all 4 combinations of single-bit inputs (0/1).
///
/// The table stores 4 output bits for (x=0,y=0), (x=0,y=1), (x=1,y=0), (x=1,y=1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TruthTable(pub [i64; 4]);

impl TruthTable {
    /// The identity truth-table used for constant 0.
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    /// All-ones (constant -1).
    pub const ALL_ONES: Self = Self([-1, -1, -1, -1]);

    /// Evaluate `expr` at all 4 bit-patterns of `(x, y)` and build a truth-table.
    /// Variable names come from `var_names[0]` and `var_names[1]`.
    #[must_use] 
    pub fn build(expr: &MbaExpr, var_names: &[&str]) -> Self {
        let inputs: [(i64, i64); 4] = [(0, 0), (0, 1), (1, 0), (1, 1)];
        let mut table = [0i64; 4];
        for (i, (a, b)) in inputs.iter().enumerate() {
            let mut vars = HashMap::new();
            if let Some(n) = var_names.first() { vars.insert(n.to_string(), *a); }
            if let Some(n) = var_names.get(1) { vars.insert(n.to_string(), *b); }
            table[i] = expr.eval(&vars).unwrap_or(0) & 1;
        }
        Self(table)
    }

    /// Build a truth-table using a fixed-width mask.
    #[must_use] 
    pub fn build_masked(expr: &MbaExpr, var_names: &[&str], mask: i64) -> Self {
        let inputs: [(i64, i64); 4] = [(0, 0), (0, mask), (mask, 0), (mask, mask)];
        let mut table = [0i64; 4];
        for (i, (a, b)) in inputs.iter().enumerate() {
            let mut vars = HashMap::new();
            if let Some(n) = var_names.first() { vars.insert(n.to_string(), *a); }
            if let Some(n) = var_names.get(1) { vars.insert(n.to_string(), *b); }
            table[i] = expr.eval(&vars).unwrap_or(0) & mask;
        }
        Self(table)
    }

    /// Check whether two truth-tables are equal.
    #[must_use] 
    pub fn matches(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Encode the truth-table as a 4-bit key for fast lookup.
    #[must_use] 
    pub fn as_u8_key(&self) -> u8 {
        let mut k = 0u8;
        for (i, &v) in self.0.iter().enumerate() {
            if v != 0 { k |= 1 << i; }
        }
        k
    }
}

impl fmt::Display for TruthTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{},{},{},{}]", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

// ─── RewriteRule ─────────────────────────────────────────────────────────────

/// A named expression rewrite rule.
pub struct RewriteRule {
    pub name: &'static str,
    pub description: &'static str,
    pub apply: fn(&MbaExpr) -> Option<MbaExpr>,
}

impl fmt::Debug for RewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RewriteRule({})", self.name)
    }
}

// ─── Standard rewrite rules ───────────────────────────────────────────────────

fn rule_xor_self(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Xor(l, r) = e && l == r { return Some(MbaExpr::Const(0)); }
    None
}
fn rule_and_self(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e && l == r { return Some(l.as_ref().clone()); }
    None
}
fn rule_or_self(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e && l == r { return Some(l.as_ref().clone()); }
    None
}
fn rule_and_zero(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::And(l, r) = e
        && (matches!(l.as_ref(), MbaExpr::Const(0)) || matches!(r.as_ref(), MbaExpr::Const(0))) {
            return Some(MbaExpr::Const(0));
        }
    None
}
fn rule_or_zero(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Or(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn rule_xor_zero(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Xor(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn rule_add_zero(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Add(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(0)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(0)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn rule_mul_one(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e {
        if matches!(l.as_ref(), MbaExpr::Const(1)) { return Some(r.as_ref().clone()); }
        if matches!(r.as_ref(), MbaExpr::Const(1)) { return Some(l.as_ref().clone()); }
    }
    None
}
fn rule_mul_zero(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Mul(l, r) = e
        && (matches!(l.as_ref(), MbaExpr::Const(0)) || matches!(r.as_ref(), MbaExpr::Const(0))) {
            return Some(MbaExpr::Const(0));
        }
    None
}
fn rule_double_not(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Not(inner) = e
        && let MbaExpr::Not(ii) = inner.as_ref() { return Some(ii.as_ref().clone()); }
    None
}
fn rule_double_neg(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Neg(inner) = e
        && let MbaExpr::Neg(ii) = inner.as_ref() { return Some(ii.as_ref().clone()); }
    None
}
fn rule_sub_self(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Sub(l, r) = e && l == r { return Some(MbaExpr::Const(0)); }
    None
}
fn rule_and_plus_or(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Add(l, r) = e {
        if let (MbaExpr::And(al, ar), MbaExpr::Or(ol, or_r)) = (l.as_ref(), r.as_ref())
            && ((al == ol && ar == or_r) || (al == or_r && ar == ol)) {
                return Some(MbaExpr::mk_add(al.as_ref().clone(), ar.as_ref().clone()));
            }
        if let (MbaExpr::Or(ol, or_r), MbaExpr::And(al, ar)) = (l.as_ref(), r.as_ref())
            && ((ol == al && or_r == ar) || (ol == ar && or_r == al)) {
                return Some(MbaExpr::mk_add(ol.as_ref().clone(), or_r.as_ref().clone()));
            }
    }
    None
}
fn rule_xor_plus_2and(e: &MbaExpr) -> Option<MbaExpr> {
    if let MbaExpr::Add(l, r) = e {
        let try_match = |xor_side: &MbaExpr, mul_side: &MbaExpr| -> Option<MbaExpr> {
            let (xl, xr) = match xor_side { MbaExpr::Xor(a,b) => (a.as_ref(), b.as_ref()), _ => return None };
            let and_side = match mul_side {
                MbaExpr::Mul(ml, mr) => {
                    if matches!(ml.as_ref(), MbaExpr::Const(2)) { mr.as_ref() }
                    else if matches!(mr.as_ref(), MbaExpr::Const(2)) { ml.as_ref() }
                    else { return None; }
                }
                _ => return None,
            };
            if let MbaExpr::And(al, ar) = and_side
                && ((al.as_ref() == xl && ar.as_ref() == xr) || (al.as_ref() == xr && ar.as_ref() == xl)) {
                    return Some(MbaExpr::mk_add(xl.clone(), xr.clone()));
                }
            None
        };
        if let Some(res) = try_match(l, r) { return Some(res); }
        if let Some(res) = try_match(r, l) { return Some(res); }
    }
    None
}

/// Build the full set of standard rewrite rules.
#[must_use] 
pub fn standard_rules() -> Vec<RewriteRule> {
    vec![
        RewriteRule { name: "xor-self",    description: "x ^ x → 0",    apply: rule_xor_self },
        RewriteRule { name: "and-self",    description: "x & x → x",    apply: rule_and_self },
        RewriteRule { name: "or-self",     description: "x | x → x",    apply: rule_or_self },
        RewriteRule { name: "and-zero",    description: "x & 0 → 0",    apply: rule_and_zero },
        RewriteRule { name: "or-zero",     description: "0 | x → x",    apply: rule_or_zero },
        RewriteRule { name: "xor-zero",    description: "0 ^ x → x",    apply: rule_xor_zero },
        RewriteRule { name: "add-zero",    description: "0 + x → x",    apply: rule_add_zero },
        RewriteRule { name: "mul-one",     description: "1 * x → x",    apply: rule_mul_one },
        RewriteRule { name: "mul-zero",    description: "0 * x → 0",    apply: rule_mul_zero },
        RewriteRule { name: "double-not",  description: "~~x → x",      apply: rule_double_not },
        RewriteRule { name: "double-neg",  description: "-(-x) → x",    apply: rule_double_neg },
        RewriteRule { name: "sub-self",    description: "x - x → 0",    apply: rule_sub_self },
        RewriteRule { name: "and-plus-or", description: "(x&y)+(x|y)→x+y", apply: rule_and_plus_or },
        RewriteRule { name: "xor-plus-2and", description: "(x^y)+2(x&y)→x+y", apply: rule_xor_plus_2and },
    ]
}

// ─── SamplingCheck ────────────────────────────────────────────────────────────

/// Check equivalence of two expressions by random sampling over a range.
#[derive(Debug, Clone)]
pub struct SamplingCheck {
    pub num_samples: usize,
    pub bits: u8,
}

impl Default for SamplingCheck {
    fn default() -> Self {
        Self { num_samples: 64, bits: 8 }
    }
}

impl SamplingCheck {
    #[must_use] 
    pub const fn new(num_samples: usize, bits: u8) -> Self {
        Self { num_samples, bits }
    }

    /// Check if `a ≡ b` by evaluating at `num_samples` deterministic points.
    #[must_use] 
    pub fn check(&self, a: &MbaExpr, b: &MbaExpr) -> bool {
        let vars_a = a.vars();
        let vars_b = b.vars();
        let mut all_vars: Vec<String> = vars_a;
        for v in vars_b { if !all_vars.contains(&v) { all_vars.push(v); } }

        // For bits >= 64 use all-bits-set mask (-1); for bits == 63 the shift
        // 1i64 << 63 would produce i64::MIN so we special-case it.
        let mask: i64 = if self.bits >= 64 {
            -1i64
        } else if self.bits == 63 {
            i64::MAX
        } else {
            (1i64 << self.bits) - 1
        };
        let mut state = 0xDEAD_BEEF_1234_5678u64;

        for _ in 0..self.num_samples {
            let mut vars = HashMap::new();
            for v in &all_vars {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                vars.insert(v.clone(), (state as i64) & mask);
            }
            let va = a.eval(&vars);
            let vb = b.eval(&vars);
            if let (Some(av), Some(bv)) = (va, vb)
                && (av & mask) != (bv & mask) { return false; }
        }
        true
    }
}

// ─── SimplifyResult ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimplifyResult {
    pub original: MbaExpr,
    pub simplified: MbaExpr,
    pub rules_applied: Vec<String>,
    pub complexity_before: usize,
    pub complexity_after: usize,
    pub verified: bool,
    pub passes: usize,
}

impl SimplifyResult {
    #[must_use] 
    pub const fn reduction(&self) -> usize {
        self.complexity_before.saturating_sub(self.complexity_after)
    }
    #[must_use] 
    pub const fn was_simplified(&self) -> bool {
        self.complexity_after < self.complexity_before
    }
}

impl fmt::Display for SimplifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} → {} (complexity {} → {}, {} rules, verified={})",
            self.original, self.simplified,
            self.complexity_before, self.complexity_after,
            self.rules_applied.len(), self.verified)
    }
}

// ─── MbaSimplifier ────────────────────────────────────────────────────────────

/// MBA expression simplifier using rewrite rules and truth-table verification.
pub struct MbaSimplifier {
    pub rules: Vec<RewriteRule>,
    pub max_passes: usize,
    pub sampler: SamplingCheck,
}

impl Default for MbaSimplifier {
    fn default() -> Self {
        Self {
            rules: standard_rules(),
            max_passes: 50,
            sampler: SamplingCheck::default(),
        }
    }
}

impl MbaSimplifier {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub fn simplify(&self, expr: MbaExpr) -> SimplifyResult {
        let original = expr.clone();
        let complexity_before = expr.complexity();
        let mut current = expr;
        let mut all_rules = Vec::new();
        let mut passes = 0;

        for _ in 0..self.max_passes {
            let (next, fired) = self.apply_rules_once(&current);
            passes += 1;
            if fired.is_empty() { break; }
            all_rules.extend(fired);
            current = next;
        }

        let complexity_after = current.complexity();
        let verified = self.sampler.check(&original, &current);

        SimplifyResult {
            original,
            simplified: current,
            rules_applied: all_rules,
            complexity_before,
            complexity_after,
            verified,
            passes,
        }
    }

    #[must_use] 
    pub fn apply_rules_once(&self, expr: &MbaExpr) -> (MbaExpr, Vec<String>) {
        let mut fired = Vec::new();
        let rebuilt = self.rebuild(expr, &mut fired);
        for rule in &self.rules {
            if let Some(result) = (rule.apply)(&rebuilt) {
                fired.push(rule.name.to_owned());
                return (result, fired);
            }
        }
        (rebuilt, fired)
    }

    fn rebuild(&self, expr: &MbaExpr, fired: &mut Vec<String>) -> MbaExpr {
        match expr {
            MbaExpr::Const(_) | MbaExpr::Var(_) => expr.clone(),
            MbaExpr::Neg(e) => { let (ne, nf) = self.apply_rules_once(e); fired.extend(nf); MbaExpr::Neg(Box::new(ne)) }
            MbaExpr::Not(e) => { let (ne, nf) = self.apply_rules_once(e); fired.extend(nf); MbaExpr::Not(Box::new(ne)) }
            MbaExpr::Shl(e, n) => { let (ne, nf) = self.apply_rules_once(e); fired.extend(nf); MbaExpr::Shl(Box::new(ne), *n) }
            MbaExpr::Shr(e, n) => { let (ne, nf) = self.apply_rules_once(e); fired.extend(nf); MbaExpr::Shr(Box::new(ne), *n) }
            MbaExpr::Sar(e, n) => { let (ne, nf) = self.apply_rules_once(e); fired.extend(nf); MbaExpr::Sar(Box::new(ne), *n) }
            MbaExpr::Add(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_add),
            MbaExpr::Sub(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_sub),
            MbaExpr::Mul(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_mul),
            MbaExpr::And(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_and),
            MbaExpr::Or(l, r)  => self.rebuild_bin(l, r, fired, MbaExpr::mk_or),
            MbaExpr::Xor(l, r) => self.rebuild_bin(l, r, fired, MbaExpr::mk_xor),
        }
    }

    fn rebuild_bin(&self, l: &MbaExpr, r: &MbaExpr, fired: &mut Vec<String>, ctor: fn(MbaExpr,MbaExpr)->MbaExpr) -> MbaExpr {
        let (nl, lf) = self.apply_rules_once(l);
        let (nr, rf) = self.apply_rules_once(r);
        fired.extend(lf);
        fired.extend(rf);
        ctor(nl, nr)
    }

    /// Truth-table simplify a 1–2 variable expression by matching against canonical forms.
    pub fn truth_table_simplify(&self, expr: &MbaExpr) -> Option<MbaExpr> {
        let vars = expr.vars();
        let var_refs: Vec<&str> = vars.iter().map(String::as_str).collect();
        if var_refs.len() > 2 { return None; }
        let input_tt = TruthTable::build_masked(expr, &var_refs, 0xFF);
        let candidates = self.canonical_forms(&var_refs);
        let mut best: Option<(usize, MbaExpr)> = None;
        for cand in candidates {
            let cand_tt = TruthTable::build_masked(&cand, &var_refs, 0xFF);
            if cand_tt.matches(&input_tt) {
                let complexity = cand.complexity();
                if best.as_ref().is_none_or(|(c, _)| complexity < *c) {
                    best = Some((complexity, cand));
                }
            }
        }
        best.map(|(_, e)| e)
    }

    fn canonical_forms(&self, var_refs: &[&str]) -> Vec<MbaExpr> {
        let mut forms = Vec::new();
        forms.push(MbaExpr::Const(0));
        forms.push(MbaExpr::Const(-1));
        if let Some(&xn) = var_refs.first() {
            let x = MbaExpr::Var(xn.to_owned());
            forms.push(x.clone());
            forms.push(MbaExpr::mk_not(x.clone()));
            forms.push(MbaExpr::mk_neg(x.clone()));
            if let Some(&yn) = var_refs.get(1) {
                let y = MbaExpr::Var(yn.to_owned());
                forms.push(y.clone());
                forms.push(MbaExpr::mk_not(y.clone()));
                forms.push(MbaExpr::mk_and(x.clone(), y.clone()));
                forms.push(MbaExpr::mk_or(x.clone(), y.clone()));
                forms.push(MbaExpr::mk_xor(x.clone(), y.clone()));
                forms.push(MbaExpr::mk_add(x.clone(), y.clone()));
                forms.push(MbaExpr::mk_sub(x.clone(), y.clone()));
                forms.push(MbaExpr::mk_and(MbaExpr::mk_not(x.clone()), y.clone()));
                forms.push(MbaExpr::mk_and(x.clone(), MbaExpr::mk_not(y.clone())));
                forms.push(MbaExpr::mk_or(MbaExpr::mk_not(x.clone()), y.clone()));
                forms.push(MbaExpr::mk_or(x, MbaExpr::mk_not(y)));
            }
        }
        forms
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
    fn test_xor_self_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_xor(x(), x());
        let r = s.simplify(expr);
        assert_eq!(r.simplified, MbaExpr::Const(0));
        assert!(r.was_simplified());
    }

    #[test]
    fn test_and_zero_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_and(x(), MbaExpr::Const(0));
        let r = s.simplify(expr);
        assert_eq!(r.simplified, MbaExpr::Const(0));
    }

    #[test]
    fn test_add_zero_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_add(x(), MbaExpr::Const(0));
        let r = s.simplify(expr);
        assert_eq!(r.simplified, x());
    }

    #[test]
    fn test_mul_one_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_mul(MbaExpr::Const(1), x());
        let r = s.simplify(expr);
        assert_eq!(r.simplified, x());
    }

    #[test]
    fn test_double_not_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_not(MbaExpr::mk_not(x()));
        let r = s.simplify(expr);
        assert_eq!(r.simplified, x());
    }

    #[test]
    fn test_and_plus_or_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_add(MbaExpr::mk_and(x(), y()), MbaExpr::mk_or(x(), y()));
        let r = s.simplify(expr);
        assert!(r.was_simplified());
    }

    #[test]
    fn test_truth_table_build_and() {
        let expr = MbaExpr::mk_and(x(), y());
        let tt = TruthTable::build(&expr, &["x", "y"]);
        assert_eq!(tt.0, [0, 0, 0, 1]);
    }

    #[test]
    fn test_truth_table_or() {
        let expr = MbaExpr::mk_or(x(), y());
        let tt = TruthTable::build(&expr, &["x", "y"]);
        assert_eq!(tt.0, [0, 1, 1, 1]);
    }

    #[test]
    fn test_truth_table_xor() {
        let expr = MbaExpr::mk_xor(x(), y());
        let tt = TruthTable::build(&expr, &["x", "y"]);
        assert_eq!(tt.0, [0, 1, 1, 0]);
    }

    #[test]
    fn test_sampling_check_identical() {
        let sc = SamplingCheck::default();
        let a = MbaExpr::mk_add(x(), y());
        let b = MbaExpr::mk_add(x(), y());
        assert!(sc.check(&a, &b));
    }

    #[test]
    fn test_sampling_check_different() {
        let sc = SamplingCheck::default();
        let a = MbaExpr::mk_and(x(), y());
        let b = MbaExpr::mk_or(x(), y());
        assert!(!sc.check(&a, &b));
    }

    #[test]
    fn test_simplify_result_display() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_xor(x(), x());
        let r = s.simplify(expr);
        assert!(r.to_string().contains("→"));
    }

    #[test]
    fn test_simplify_verified() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_add(x(), MbaExpr::Const(0));
        let r = s.simplify(expr);
        assert!(r.verified);
    }

    #[test]
    fn test_truth_table_simplify_xor_self() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_xor(x(), x());
        let simplified = s.truth_table_simplify(&expr);
        assert_eq!(simplified, Some(MbaExpr::Const(0)));
    }

    #[test]
    fn test_truth_table_key() {
        let tt = TruthTable([0, 1, 1, 1]); // OR
        assert_eq!(tt.as_u8_key(), 0b1110);
    }

    #[test]
    fn test_sub_self_simplify() {
        let s = MbaSimplifier::new();
        let expr = MbaExpr::mk_sub(x(), x());
        let r = s.simplify(expr);
        assert_eq!(r.simplified, MbaExpr::Const(0));
    }
}
