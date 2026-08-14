//! MBA normalisation — expression trees, algebraic simplification, constant
//! propagation, normal-form reduction, and a verification oracle.
//!
//! Complements the existing rule-based [`crate::MbaSimplifier`] with a
//! higher-level API:
//!
//! * [`MbaExprTree`] — richer expression tree with a `depth` metric.
//! * [`AlgebraicSimplification`] — 30+ standalone simplification rules.
//! * [`ConstantPropagation`] — inlines known variable values and folds constants.
//! * [`NormalForm`] — canonical representation of a simplified MBA expression.
//! * [`VerificationOracle`] — random-sampling equivalence checker.
//! * [`MbaNormalizer`] — orchestrates all the above.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// MbaExprTree
// ─────────────────────────────────────────────────────────────────────────────

/// A slightly richer symbolic expression tree that also tracks subtree depth.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MbaExprTree {
    /// Concrete 64-bit constant.
    Const(i64),
    /// Named variable.
    Var(String),
    /// Addition.
    Add(Box<Self>, Box<Self>),
    /// Subtraction.
    Sub(Box<Self>, Box<Self>),
    /// Multiplication.
    Mul(Box<Self>, Box<Self>),
    /// Arithmetic negation.
    Neg(Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Left shift by constant.
    Shl(Box<Self>, u8),
    /// Logical right shift by constant.
    Shr(Box<Self>, u8),
}

impl MbaExprTree {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// `a + b`
    #[must_use]
    pub fn add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }
    /// `a - b`
    #[must_use]
    pub fn sub(a: Self, b: Self) -> Self {
        Self::Sub(Box::new(a), Box::new(b))
    }
    /// `a * b`
    #[must_use]
    pub fn mul(a: Self, b: Self) -> Self {
        Self::Mul(Box::new(a), Box::new(b))
    }
    /// `-a`
    #[must_use]
    pub fn neg(a: Self) -> Self {
        Self::Neg(Box::new(a))
    }
    /// `a & b`
    #[must_use]
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    /// `a | b`
    #[must_use]
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    /// `a ^ b`
    #[must_use]
    pub fn xor(a: Self, b: Self) -> Self {
        Self::Xor(Box::new(a), Box::new(b))
    }
    /// `~a`
    #[must_use]
    pub fn not(a: Self) -> Self {
        Self::Not(Box::new(a))
    }

    // ── Metrics ──────────────────────────────────────────────────────────────

    /// Total node count (complexity proxy).
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Neg(e) | Self::Not(e) | Self::Shl(e, _) | Self::Shr(e, _) => 1 + e.node_count(),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r) => 1 + l.node_count() + r.node_count(),
        }
    }

    /// Maximum depth (longest root-to-leaf path).
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 0,
            Self::Neg(e) | Self::Not(e) | Self::Shl(e, _) | Self::Shr(e, _) => 1 + e.depth(),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r) => 1 + l.depth().max(r.depth()),
        }
    }

    /// Collect all unique variable names.
    #[must_use]
    pub fn vars(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        self.collect_vars(&mut v);
        v
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Var(n) => {
                if !out.contains(n) {
                    out.push(n.clone());
                }
            }
            Self::Const(_) => {}
            Self::Neg(e) | Self::Not(e) | Self::Shl(e, _) | Self::Shr(e, _) => e.collect_vars(out),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
        }
    }

    /// Evaluate with concrete variable bindings.
    #[must_use]
    pub fn eval(&self, env: &HashMap<String, i64>) -> Option<i64> {
        match self {
            Self::Const(c) => Some(*c),
            Self::Var(n) => env.get(n).copied(),
            Self::Neg(e) => Some(e.eval(env)?.wrapping_neg()),
            Self::Not(e) => Some(!e.eval(env)?),
            Self::Add(l, r) => Some(l.eval(env)?.wrapping_add(r.eval(env)?)),
            Self::Sub(l, r) => Some(l.eval(env)?.wrapping_sub(r.eval(env)?)),
            Self::Mul(l, r) => Some(l.eval(env)?.wrapping_mul(r.eval(env)?)),
            Self::And(l, r) => Some(l.eval(env)? & r.eval(env)?),
            Self::Or(l, r) => Some(l.eval(env)? | r.eval(env)?),
            Self::Xor(l, r) => Some(l.eval(env)? ^ r.eval(env)?),
            Self::Shl(e, n) => Some(e.eval(env)?.wrapping_shl(u32::from(*n))),
            Self::Shr(e, n) => {
                let v = e.eval(env)? as u64;
                Some((v >> *n) as i64)
            }
        }
    }

    /// Return the contained constant if `self` is `Const`.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(c) = self {
            Some(*c)
        } else {
            None
        }
    }

    /// Return `true` if `self` is `Const(0)`.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        matches!(self, Self::Const(0))
    }

    /// Return `true` if `self` is `Const(1)`.
    #[must_use]
    pub const fn is_one(&self) -> bool {
        matches!(self, Self::Const(1))
    }
}

impl std::fmt::Display for MbaExprTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Const(c) => write!(f, "{c}"),
            Self::Var(n) => write!(f, "{n}"),
            Self::Neg(e) => write!(f, "(-{e})"),
            Self::Not(e) => write!(f, "(~{e})"),
            Self::Shl(e, n) => write!(f, "({e} << {n})"),
            Self::Shr(e, n) => write!(f, "({e} >> {n})"),
            Self::Add(l, r) => write!(f, "({l} + {r})"),
            Self::Sub(l, r) => write!(f, "({l} - {r})"),
            Self::Mul(l, r) => write!(f, "({l} * {r})"),
            Self::And(l, r) => write!(f, "({l} & {r})"),
            Self::Or(l, r) => write!(f, "({l} | {r})"),
            Self::Xor(l, r) => write!(f, "({l} ^ {r})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AlgebraicSimplification — 30+ rules
// ─────────────────────────────────────────────────────────────────────────────

/// A single algebraic simplification rule.
pub struct AlgRule {
    /// Short name.
    pub name: &'static str,
    /// The transformation function: returns `Some(simplified)` or `None`.
    pub apply: fn(&MbaExprTree) -> Option<MbaExprTree>,
}

impl std::fmt::Debug for AlgRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AlgRule({})", self.name)
    }
}

/// Holder for all algebraic rules.
#[derive(Debug)]
pub struct AlgebraicSimplification {
    rules: Vec<AlgRule>,
}

impl AlgebraicSimplification {
    /// Build the rule database (30+ rules).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: build_alg_rules(),
        }
    }

    /// Return number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Apply all rules once to `expr`, returning the first successful rewrite.
    #[must_use]
    pub fn apply_once(&self, expr: &MbaExprTree) -> Option<(MbaExprTree, &str)> {
        for rule in &self.rules {
            if let Some(result) = (rule.apply)(expr) {
                return Some((result, rule.name));
            }
        }
        None
    }

    /// Repeatedly apply rules bottom-up until convergence.
    #[must_use]
    pub fn simplify(&self, expr: MbaExprTree) -> (MbaExprTree, Vec<String>) {
        let mut current = expr;
        let mut fired: Vec<String> = Vec::new();
        for _ in 0..200 {
            let (next, new_fired) = self.simplify_once(current.clone());
            if new_fired.is_empty() {
                break;
            }
            fired.extend(new_fired);
            current = next;
        }
        (current, fired)
    }

    /// One bottom-up pass.
    fn simplify_once(&self, expr: MbaExprTree) -> (MbaExprTree, Vec<String>) {
        let mut fired = Vec::new();
        let rebuilt = self.rebuild(&expr, &mut fired);
        if let Some((result, name)) = self.apply_once(&rebuilt) {
            fired.push(name.to_owned());
            (result, fired)
        } else {
            (rebuilt, fired)
        }
    }

    fn rebuild(&self, expr: &MbaExprTree, fired: &mut Vec<String>) -> MbaExprTree {
        match expr {
            MbaExprTree::Const(_) | MbaExprTree::Var(_) => expr.clone(),
            MbaExprTree::Neg(e) => {
                let (n, f) = self.simplify_once(*e.clone());
                fired.extend(f);
                MbaExprTree::neg(n)
            }
            MbaExprTree::Not(e) => {
                let (n, f) = self.simplify_once(*e.clone());
                fired.extend(f);
                MbaExprTree::not(n)
            }
            MbaExprTree::Shl(e, n) => {
                let (ne, f) = self.simplify_once(*e.clone());
                fired.extend(f);
                MbaExprTree::Shl(Box::new(ne), *n)
            }
            MbaExprTree::Shr(e, n) => {
                let (ne, f) = self.simplify_once(*e.clone());
                fired.extend(f);
                MbaExprTree::Shr(Box::new(ne), *n)
            }
            MbaExprTree::Add(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::add(nl, nr)
            }
            MbaExprTree::Sub(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::sub(nl, nr)
            }
            MbaExprTree::Mul(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::mul(nl, nr)
            }
            MbaExprTree::And(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::and(nl, nr)
            }
            MbaExprTree::Or(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::or(nl, nr)
            }
            MbaExprTree::Xor(l, r) => {
                let (nl, lf) = self.simplify_once(*l.clone());
                let (nr, rf) = self.simplify_once(*r.clone());
                fired.extend(lf);
                fired.extend(rf);
                MbaExprTree::xor(nl, nr)
            }
        }
    }
}

impl Default for AlgebraicSimplification {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rule helpers ──────────────────────────────────────────────────────────────

fn as_add(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::Add(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_sub(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::Sub(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_mul(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::Mul(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_and(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::And(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_or(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::Or(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_xor(e: &MbaExprTree) -> Option<(&MbaExprTree, &MbaExprTree)> {
    if let MbaExprTree::Xor(l, r) = e {
        Some((l, r))
    } else {
        None
    }
}
fn as_neg(e: &MbaExprTree) -> Option<&MbaExprTree> {
    if let MbaExprTree::Neg(inner) = e {
        Some(inner)
    } else {
        None
    }
}
fn as_not(e: &MbaExprTree) -> Option<&MbaExprTree> {
    if let MbaExprTree::Not(inner) = e {
        Some(inner)
    } else {
        None
    }
}
fn eq(a: &MbaExprTree, b: &MbaExprTree) -> bool {
    a == b
}

fn build_alg_rules() -> Vec<AlgRule> {
    vec![
        // ── Constant folding ──────────────────────────────────────────────────
        AlgRule {
            name: "cf-add",
            apply: |e| {
                let (l, r) = as_add(e)?;
                Some(MbaExprTree::Const(
                    l.as_const()?.wrapping_add(r.as_const()?),
                ))
            },
        },
        AlgRule {
            name: "cf-sub",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                Some(MbaExprTree::Const(
                    l.as_const()?.wrapping_sub(r.as_const()?),
                ))
            },
        },
        AlgRule {
            name: "cf-mul",
            apply: |e| {
                let (l, r) = as_mul(e)?;
                Some(MbaExprTree::Const(
                    l.as_const()?.wrapping_mul(r.as_const()?),
                ))
            },
        },
        AlgRule {
            name: "cf-and",
            apply: |e| {
                let (l, r) = as_and(e)?;
                Some(MbaExprTree::Const(l.as_const()? & r.as_const()?))
            },
        },
        AlgRule {
            name: "cf-or",
            apply: |e| {
                let (l, r) = as_or(e)?;
                Some(MbaExprTree::Const(l.as_const()? | r.as_const()?))
            },
        },
        AlgRule {
            name: "cf-xor",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                Some(MbaExprTree::Const(l.as_const()? ^ r.as_const()?))
            },
        },
        AlgRule {
            name: "cf-neg",
            apply: |e| {
                let i = as_neg(e)?;
                Some(MbaExprTree::Const(i.as_const()?.wrapping_neg()))
            },
        },
        AlgRule {
            name: "cf-not",
            apply: |e| {
                let i = as_not(e)?;
                Some(MbaExprTree::Const(!i.as_const()?))
            },
        },
        // ── Additive identities ───────────────────────────────────────────────
        AlgRule {
            name: "add-zero-r",
            apply: |e| {
                let (l, r) = as_add(e)?;
                if r.is_zero() { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "add-zero-l",
            apply: |e| {
                let (l, r) = as_add(e)?;
                if l.is_zero() { Some(r.clone()) } else { None }
            },
        },
        AlgRule {
            name: "add-neg-self",
            apply: |e| {
                let (l, r) = as_add(e)?;
                let i = as_neg(r)?;
                if eq(l, i) {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "add-neg-self-rev",
            apply: |e| {
                let (l, r) = as_add(e)?;
                let i = as_neg(l)?;
                if eq(i, r) {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        // ── Subtractive identities ────────────────────────────────────────────
        AlgRule {
            name: "sub-zero",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                if r.is_zero() { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "sub-self",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                if eq(l, r) {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "zero-sub",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                if l.is_zero() {
                    Some(MbaExprTree::neg(r.clone()))
                } else {
                    None
                }
            },
        },
        // ── Multiplicative identities ─────────────────────────────────────────
        AlgRule {
            name: "mul-one-r",
            apply: |e| {
                let (l, r) = as_mul(e)?;
                if r.is_one() { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "mul-one-l",
            apply: |e| {
                let (l, r) = as_mul(e)?;
                if l.is_one() { Some(r.clone()) } else { None }
            },
        },
        AlgRule {
            name: "mul-zero-r",
            apply: |e| {
                let (_, r) = as_mul(e)?;
                if r.is_zero() {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "mul-zero-l",
            apply: |e| {
                let (l, _) = as_mul(e)?;
                if l.is_zero() {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        // ── XOR identities ────────────────────────────────────────────────────
        AlgRule {
            name: "xor-self",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                if eq(l, r) {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "xor-zero-r",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                if r.is_zero() { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "xor-zero-l",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                if l.is_zero() { Some(r.clone()) } else { None }
            },
        },
        AlgRule {
            name: "xor-allones-r",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                if r.as_const() == Some(-1) {
                    Some(MbaExprTree::not(l.clone()))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "xor-allones-l",
            apply: |e| {
                let (l, r) = as_xor(e)?;
                if l.as_const() == Some(-1) {
                    Some(MbaExprTree::not(r.clone()))
                } else {
                    None
                }
            },
        },
        // ── AND identities ────────────────────────────────────────────────────
        AlgRule {
            name: "and-self",
            apply: |e| {
                let (l, r) = as_and(e)?;
                if eq(l, r) { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "and-zero-r",
            apply: |e| {
                let (_, r) = as_and(e)?;
                if r.is_zero() {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "and-zero-l",
            apply: |e| {
                let (l, _) = as_and(e)?;
                if l.is_zero() {
                    Some(MbaExprTree::Const(0))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "and-allones-r",
            apply: |e| {
                let (l, r) = as_and(e)?;
                if r.as_const() == Some(-1) {
                    Some(l.clone())
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "and-allones-l",
            apply: |e| {
                let (l, r) = as_and(e)?;
                if l.as_const() == Some(-1) {
                    Some(r.clone())
                } else {
                    None
                }
            },
        },
        // ── OR identities ─────────────────────────────────────────────────────
        AlgRule {
            name: "or-self",
            apply: |e| {
                let (l, r) = as_or(e)?;
                if eq(l, r) { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "or-zero-r",
            apply: |e| {
                let (l, r) = as_or(e)?;
                if r.is_zero() { Some(l.clone()) } else { None }
            },
        },
        AlgRule {
            name: "or-zero-l",
            apply: |e| {
                let (l, r) = as_or(e)?;
                if l.is_zero() { Some(r.clone()) } else { None }
            },
        },
        AlgRule {
            name: "or-allones-r",
            apply: |e| {
                let (_, r) = as_or(e)?;
                if r.as_const() == Some(-1) {
                    Some(MbaExprTree::Const(-1))
                } else {
                    None
                }
            },
        },
        AlgRule {
            name: "or-allones-l",
            apply: |e| {
                let (l, _) = as_or(e)?;
                if l.as_const() == Some(-1) {
                    Some(MbaExprTree::Const(-1))
                } else {
                    None
                }
            },
        },
        // ── NOT / NEG identities ──────────────────────────────────────────────
        AlgRule {
            name: "double-not",
            apply: |e| {
                let i = as_not(e)?;
                let j = as_not(i)?;
                Some(j.clone())
            },
        },
        AlgRule {
            name: "double-neg",
            apply: |e| {
                let i = as_neg(e)?;
                let j = as_neg(i)?;
                Some(j.clone())
            },
        },
        AlgRule {
            name: "neg-of-not",
            apply: |e| {
                let i = as_neg(e)?;
                let j = as_not(i)?;
                Some(MbaExprTree::add(j.clone(), MbaExprTree::Const(1)))
            },
        },
        // ── MBA core rules ────────────────────────────────────────────────────
        // (x & y) + (x | y) → x + y
        AlgRule {
            name: "and-plus-or",
            apply: |e| {
                let (l, r) = as_add(e)?;
                let try_it = |a: &MbaExprTree, b: &MbaExprTree| -> Option<MbaExprTree> {
                    let (al, ar) = as_and(a)?;
                    let (ol, or_r) = as_or(b)?;
                    if (eq(al, ol) && eq(ar, or_r)) || (eq(al, or_r) && eq(ar, ol)) {
                        Some(MbaExprTree::add(al.clone(), ar.clone()))
                    } else {
                        None
                    }
                };
                try_it(l, r).or_else(|| try_it(r, l))
            },
        },
        // (x | y) - (x & y) → x ^ y
        AlgRule {
            name: "or-minus-and",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                let (ol, or_r) = as_or(l)?;
                let (al, ar) = as_and(r)?;
                if (eq(ol, al) && eq(or_r, ar)) || (eq(ol, ar) && eq(or_r, al)) {
                    Some(MbaExprTree::xor(ol.clone(), or_r.clone()))
                } else {
                    None
                }
            },
        },
        // (x ^ y) + 2*(x & y) → x + y
        // why: Knuth's identity — XOR is sum-without-carry, AND tracks carry bits;
        // adding the carry bits twice recovers the true sum.
        AlgRule {
            name: "xor-plus-2and",
            apply: |e| {
                let (l, r) = as_add(e)?;
                let try_it = |xor_side: &MbaExprTree, mul_side: &MbaExprTree| -> Option<MbaExprTree> {
                    let (xl, xr) = as_xor(xor_side)?;
                    let (ml, mr) = as_mul(mul_side)?;
                    let and_matches = |c: &MbaExprTree| -> bool {
                        if let MbaExprTree::And(al, ar) = c {
                            (eq(al, xl) && eq(ar, xr)) || (eq(al, xr) && eq(ar, xl))
                        } else {
                            false
                        }
                    };
                    let two_then_and = ml.as_const() == Some(2) && and_matches(mr);
                    let and_then_two = mr.as_const() == Some(2) && and_matches(ml);
                    if two_then_and || and_then_two {
                        Some(MbaExprTree::add(xl.clone(), xr.clone()))
                    } else {
                        None
                    }
                };
                try_it(l, r).or_else(|| try_it(r, l))
            },
        },
        // (x + y) - (x & y) → x | y
        AlgRule {
            name: "sum-minus-and",
            apply: |e| {
                let (l, r) = as_sub(e)?;
                let (sl, sr) = as_add(l)?;
                let (al, ar) = as_and(r)?;
                if (eq(sl, al) && eq(sr, ar)) || (eq(sl, ar) && eq(sr, al)) {
                    Some(MbaExprTree::or(sl.clone(), sr.clone()))
                } else {
                    None
                }
            },
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantPropagation
// ─────────────────────────────────────────────────────────────────────────────

/// Inlines known variable values and folds constants.
#[derive(Debug, Clone, Default)]
pub struct ConstantPropagation {
    /// Known variable values.
    pub env: HashMap<String, i64>,
}

impl ConstantPropagation {
    /// Create an empty constant-propagation context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `var` to `value`.
    pub fn bind(&mut self, var: impl Into<String>, value: i64) {
        self.env.insert(var.into(), value);
    }

    /// Substitute all known bindings into `expr` and constant-fold leaf nodes.
    #[must_use]
    pub fn propagate(&self, expr: &MbaExprTree) -> MbaExprTree {
        match expr {
            MbaExprTree::Const(_) => expr.clone(),
            MbaExprTree::Var(n) => {
                if let Some(&v) = self.env.get(n) {
                    MbaExprTree::Const(v)
                } else {
                    expr.clone()
                }
            }
            MbaExprTree::Neg(e) => {
                let ne = self.propagate(e);
                if let Some(v) = ne.as_const() {
                    MbaExprTree::Const(v.wrapping_neg())
                } else {
                    MbaExprTree::neg(ne)
                }
            }
            MbaExprTree::Not(e) => {
                let ne = self.propagate(e);
                if let Some(v) = ne.as_const() {
                    MbaExprTree::Const(!v)
                } else {
                    MbaExprTree::not(ne)
                }
            }
            MbaExprTree::Shl(e, n) => {
                let ne = self.propagate(e);
                if let Some(v) = ne.as_const() {
                    MbaExprTree::Const(v.wrapping_shl(u32::from(*n)))
                } else {
                    MbaExprTree::Shl(Box::new(ne), *n)
                }
            }
            MbaExprTree::Shr(e, n) => {
                let ne = self.propagate(e);
                if let Some(v) = ne.as_const() {
                    MbaExprTree::Const((v as u64 >> *n) as i64)
                } else {
                    MbaExprTree::Shr(Box::new(ne), *n)
                }
            }
            MbaExprTree::Add(l, r) => self.prop2(l, r, i64::wrapping_add, MbaExprTree::add),
            MbaExprTree::Sub(l, r) => self.prop2(l, r, i64::wrapping_sub, MbaExprTree::sub),
            MbaExprTree::Mul(l, r) => self.prop2(l, r, i64::wrapping_mul, MbaExprTree::mul),
            MbaExprTree::And(l, r) => self.prop2(l, r, |a, b| a & b, MbaExprTree::and),
            MbaExprTree::Or(l, r) => self.prop2(l, r, |a, b| a | b, MbaExprTree::or),
            MbaExprTree::Xor(l, r) => self.prop2(l, r, |a, b| a ^ b, MbaExprTree::xor),
        }
    }

    fn prop2(
        &self,
        l: &MbaExprTree,
        r: &MbaExprTree,
        fold: fn(i64, i64) -> i64,
        ctor: fn(MbaExprTree, MbaExprTree) -> MbaExprTree,
    ) -> MbaExprTree {
        let nl = self.propagate(l);
        let nr = self.propagate(r);
        if let (Some(lv), Some(rv)) = (nl.as_const(), nr.as_const()) {
            MbaExprTree::Const(fold(lv, rv))
        } else {
            ctor(nl, nr)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalForm
// ─────────────────────────────────────────────────────────────────────────────

/// The canonical (simplified) form of an MBA expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalForm {
    /// The simplified expression.
    pub expr: MbaExprTree,
    /// Node count of the simplified expression.
    pub complexity: usize,
    /// Variable names appearing in the normal form.
    pub vars: Vec<String>,
    /// Whether the expression reduced to a constant.
    pub is_constant: bool,
}

impl NormalForm {
    /// Derive the normal form from a simplified expression.
    #[must_use]
    pub fn from_expr(expr: MbaExprTree) -> Self {
        let complexity = expr.node_count();
        let vars = expr.vars();
        let is_constant = matches!(expr, MbaExprTree::Const(_));
        Self {
            expr,
            complexity,
            vars,
            is_constant,
        }
    }

    /// Return the constant value if the normal form is a constant.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        self.expr.as_const()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VerificationOracle
// ─────────────────────────────────────────────────────────────────────────────

/// Checks equivalence between two expressions by random-sampling variable values.
#[derive(Debug, Clone)]
pub struct VerificationOracle {
    /// Number of random samples per variable (default 64).
    pub samples: usize,
    /// Bit-width of sample values (default 8).
    pub bits: u32,
}

impl Default for VerificationOracle {
    fn default() -> Self {
        Self {
            samples: 64,
            bits: 8,
        }
    }
}

impl VerificationOracle {
    /// Create a default oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `a` and `b` are equivalent under `samples` random assignments.
    ///
    /// Returns `(equivalent, Option<counterexample_assignment>)`.
    #[must_use]
    pub fn check_equivalent(
        &self,
        a: &MbaExprTree,
        b: &MbaExprTree,
    ) -> (bool, Option<HashMap<String, i64>>) {
        let mut all_vars: Vec<String> = a.vars();
        for v in b.vars() {
            if !all_vars.contains(&v) {
                all_vars.push(v);
            }
        }

        let mask = if self.bits >= 64 {
            i64::MAX
        } else {
            (1i64 << self.bits) - 1
        };
        let domain: Vec<i64> = (0..(1i64 << self.bits)).collect();

        // Use a simple LCG-like deterministic sequence as a pseudo-random source.
        let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
        let mut env: HashMap<String, i64> = HashMap::with_capacity(all_vars.len());
        for _ in 0..self.samples {
            env.clear();
            for var in &all_vars {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let idx = (seed >> 33) as usize % domain.len();
                env.insert(var.clone(), domain[idx] & mask);
            }
            let va = a.eval(&env).map(|v| v & mask);
            let vb = b.eval(&env).map(|v| v & mask);
            if va != vb {
                return (false, Some(env));
            }
        }
        (true, None)
    }

    /// Return `true` if `expr` evaluates to the same constant for all samples.
    #[must_use]
    pub fn is_constant(&self, expr: &MbaExprTree) -> bool {
        let vars = expr.vars();
        if vars.is_empty() {
            return true;
        }
        let mask = if self.bits >= 64 {
            i64::MAX
        } else {
            (1i64 << self.bits) - 1
        };
        let mut first: Option<i64> = None;
        let mut seed: u64 = 0xFEDCBA9876543210;
        let mut env: HashMap<String, i64> = HashMap::with_capacity(vars.len());
        for _ in 0..self.samples {
            env.clear();
            for var in &vars {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                env.insert(var.clone(), (seed >> 33) as i64 & mask);
            }
            if let Some(v) = expr.eval(&env) {
                let v = v & mask;
                match first {
                    None => first = Some(v),
                    Some(f) if f != v => return false,
                    _ => {}
                }
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionMetrics — complexity and depth metrics for expression trees
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics computed from an [`MbaExprTree`].
#[derive(Debug, Clone)]
pub struct ExpressionMetrics {
    /// Total node count.
    pub node_count: usize,
    /// Maximum depth.
    pub depth: usize,
    /// Number of unique variables.
    pub var_count: usize,
    /// Number of binary operators.
    pub binary_op_count: usize,
    /// Number of unary operators.
    pub unary_op_count: usize,
    /// Whether the expression is a constant.
    pub is_constant: bool,
}

impl ExpressionMetrics {
    /// Compute metrics for `expr`.
    #[must_use]
    pub fn compute(expr: &MbaExprTree) -> Self {
        Self {
            node_count: expr.node_count(),
            depth: expr.depth(),
            var_count: expr.vars().len(),
            binary_op_count: count_binary_ops(expr),
            unary_op_count: count_unary_ops(expr),
            is_constant: matches!(expr, MbaExprTree::Const(_)),
        }
    }

    /// Normalised complexity score in [0.0, 1.0] (larger = more complex).
    #[must_use]
    pub fn complexity_score(&self) -> f64 {
        // Logarithmic scaling: a node_count of 100 maps to ~1.0.
        let base = (self.node_count as f64).ln_1p() / 100_f64.ln_1p();
        base.clamp(0.0, 1.0)
    }
}

fn count_binary_ops(expr: &MbaExprTree) -> usize {
    match expr {
        MbaExprTree::Const(_) | MbaExprTree::Var(_) => 0,
        MbaExprTree::Neg(e)
        | MbaExprTree::Not(e)
        | MbaExprTree::Shl(e, _)
        | MbaExprTree::Shr(e, _) => count_binary_ops(e),
        MbaExprTree::Add(l, r)
        | MbaExprTree::Sub(l, r)
        | MbaExprTree::Mul(l, r)
        | MbaExprTree::And(l, r)
        | MbaExprTree::Or(l, r)
        | MbaExprTree::Xor(l, r) => 1 + count_binary_ops(l) + count_binary_ops(r),
    }
}

fn count_unary_ops(expr: &MbaExprTree) -> usize {
    match expr {
        MbaExprTree::Const(_) | MbaExprTree::Var(_) => 0,
        MbaExprTree::Neg(e)
        | MbaExprTree::Not(e)
        | MbaExprTree::Shl(e, _)
        | MbaExprTree::Shr(e, _) => 1 + count_unary_ops(e),
        MbaExprTree::Add(l, r)
        | MbaExprTree::Sub(l, r)
        | MbaExprTree::Mul(l, r)
        | MbaExprTree::And(l, r)
        | MbaExprTree::Or(l, r)
        | MbaExprTree::Xor(l, r) => count_unary_ops(l) + count_unary_ops(r),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MbaNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates constant propagation, algebraic simplification, and oracle
/// verification to produce a fully normalised MBA expression.
#[derive(Debug)]
pub struct MbaNormalizer {
    /// Algebraic simplification engine.
    pub simplifier: AlgebraicSimplification,
    /// Constant-propagation context.
    pub cp: ConstantPropagation,
    /// Equivalence oracle.
    pub oracle: VerificationOracle,
    /// Maximum simplification iterations (default 50).
    pub max_iters: usize,
}

impl Default for MbaNormalizer {
    fn default() -> Self {
        Self {
            simplifier: AlgebraicSimplification::new(),
            cp: ConstantPropagation::new(),
            oracle: VerificationOracle::new(),
            max_iters: 50,
        }
    }
}

impl MbaNormalizer {
    /// Create a default normalizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a variable to a constant for constant propagation.
    pub fn bind(&mut self, var: impl Into<String>, value: i64) {
        self.cp.bind(var, value);
    }

    /// Normalise `expr` and return `(NormalForm, verified, rules_applied)`.
    #[must_use]
    pub fn normalize(&self, expr: MbaExprTree) -> (NormalForm, bool, Vec<String>) {
        // Phase 1: constant propagation.
        let after_cp = self.cp.propagate(&expr);

        // Phase 2: algebraic simplification.
        let (simplified, rules) = self.simplifier.simplify(after_cp);

        // Phase 3: oracle verification.
        let verified = if simplified.vars().is_empty() {
            true
        } else {
            let (eq, _) = self.oracle.check_equivalent(&expr, &simplified);
            eq
        };

        let nf = NormalForm::from_expr(simplified);
        (nf, verified, rules)
    }

    /// Reduce complexity score: `node_count(simplified) / node_count(original)`.
    #[must_use]
    pub fn complexity_ratio(&self, original: &MbaExprTree, simplified: &MbaExprTree) -> f32 {
        let orig = original.node_count().max(1) as f32;
        simplified.node_count() as f32 / orig
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MbaExprTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_expr_const_eval() {
        let e = MbaExprTree::Const(42);
        assert_eq!(e.eval(&HashMap::new()), Some(42));
    }

    #[test]
    fn test_expr_var_eval() {
        let e = MbaExprTree::Var("x".into());
        let mut env = HashMap::new();
        env.insert("x".into(), 10i64);
        assert_eq!(e.eval(&env), Some(10));
    }

    #[test]
    fn test_expr_add_eval() {
        let e = MbaExprTree::add(MbaExprTree::Const(3), MbaExprTree::Const(4));
        assert_eq!(e.eval(&HashMap::new()), Some(7));
    }

    #[test]
    fn test_expr_node_count() {
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(1));
        assert_eq!(e.node_count(), 3); // add + var + const
    }

    #[test]
    fn test_expr_depth() {
        let e = MbaExprTree::add(
            MbaExprTree::add(MbaExprTree::Const(1), MbaExprTree::Const(2)),
            MbaExprTree::Const(3),
        );
        assert_eq!(e.depth(), 2);
    }

    #[test]
    fn test_expr_vars() {
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Var("y".into()));
        let vars = e.vars();
        assert!(vars.contains(&"x".to_string()));
        assert!(vars.contains(&"y".to_string()));
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_expr_vars_dedup() {
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Var("x".into()));
        assert_eq!(e.vars().len(), 1);
    }

    #[test]
    fn test_expr_is_zero_one() {
        assert!(MbaExprTree::Const(0).is_zero());
        assert!(MbaExprTree::Const(1).is_one());
        assert!(!MbaExprTree::Const(2).is_zero());
    }

    #[test]
    fn test_expr_display_add() {
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(1));
        assert_eq!(e.to_string(), "(x + 1)");
    }

    #[test]
    fn test_expr_neg_eval() {
        let e = MbaExprTree::neg(MbaExprTree::Const(5));
        assert_eq!(e.eval(&HashMap::new()), Some(-5));
    }

    #[test]
    fn test_expr_not_eval() {
        let e = MbaExprTree::not(MbaExprTree::Const(0));
        assert_eq!(e.eval(&HashMap::new()), Some(-1));
    }

    #[test]
    fn test_expr_xor_self_zero() {
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::xor(x.clone(), x);
        let mut env = HashMap::new();
        env.insert("x".into(), 99i64);
        assert_eq!(e.eval(&env), Some(0));
    }

    // ── AlgebraicSimplification ───────────────────────────────────────────────

    #[test]
    fn test_alg_rule_count() {
        let alg = AlgebraicSimplification::new();
        assert!(
            alg.rule_count() >= 30,
            "expected ≥30 rules, got {}",
            alg.rule_count()
        );
    }

    #[test]
    fn test_alg_const_fold_add() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::add(MbaExprTree::Const(3), MbaExprTree::Const(4));
        let (result, rules) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(7));
        assert!(rules.contains(&"cf-add".to_string()));
    }

    #[test]
    fn test_alg_add_zero() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Var("x".into()));
    }

    #[test]
    fn test_alg_xor_self() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::xor(x.clone(), x);
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(0));
    }

    #[test]
    fn test_alg_and_self() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::and(x.clone(), x.clone());
        let (result, _) = alg.simplify(e);
        assert_eq!(result, x);
    }

    #[test]
    fn test_alg_double_neg() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::neg(MbaExprTree::neg(x.clone()));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, x);
    }

    #[test]
    fn test_alg_and_zero() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::and(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(0));
    }

    #[test]
    fn test_alg_or_allones() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::or(MbaExprTree::Var("x".into()), MbaExprTree::Const(-1));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(-1));
    }

    #[test]
    fn test_alg_sub_self() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::sub(x.clone(), x);
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(0));
    }

    // ── ConstantPropagation ───────────────────────────────────────────────────

    #[test]
    fn test_cp_bind_and_propagate() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 10);
        let e = MbaExprTree::Var("x".into());
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Const(10));
    }

    #[test]
    fn test_cp_unknown_var_unchanged() {
        let cp = ConstantPropagation::new();
        let e = MbaExprTree::Var("y".into());
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Var("y".into()));
    }

    #[test]
    fn test_cp_fold_after_substitution() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 3);
        cp.bind("y", 4);
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Var("y".into()));
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Const(7));
    }

    #[test]
    fn test_cp_partial_propagation() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 5);
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Var("y".into()));
        let result = cp.propagate(&e);
        // Should be (5 + y), not fully folded.
        match result {
            MbaExprTree::Add(l, r) => {
                assert_eq!(*l, MbaExprTree::Const(5));
                assert_eq!(*r, MbaExprTree::Var("y".into()));
            }
            other => panic!("unexpected: {other}"),
        }
    }

    // ── NormalForm ────────────────────────────────────────────────────────────

    #[test]
    fn test_normal_form_constant() {
        let nf = NormalForm::from_expr(MbaExprTree::Const(42));
        assert!(nf.is_constant);
        assert_eq!(nf.as_const(), Some(42));
    }

    #[test]
    fn test_normal_form_variable() {
        let nf = NormalForm::from_expr(MbaExprTree::Var("x".into()));
        assert!(!nf.is_constant);
        assert!(nf.vars.contains(&"x".to_string()));
    }

    #[test]
    fn test_normal_form_complexity() {
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(1));
        let nf = NormalForm::from_expr(e);
        assert_eq!(nf.complexity, 3);
    }

    // ── VerificationOracle ────────────────────────────────────────────────────

    #[test]
    fn test_oracle_equivalent_constants() {
        let oracle = VerificationOracle::new();
        let a = MbaExprTree::Const(7);
        let b = MbaExprTree::Const(7);
        let (eq, ce) = oracle.check_equivalent(&a, &b);
        assert!(eq);
        assert!(ce.is_none());
    }

    #[test]
    fn test_oracle_different_constants() {
        let oracle = VerificationOracle::new();
        let a = MbaExprTree::Const(1);
        let b = MbaExprTree::Const(2);
        let (eq, ce) = oracle.check_equivalent(&a, &b);
        assert!(!eq);
        assert!(ce.is_some());
    }

    #[test]
    fn test_oracle_identity_rule_add_zero() {
        let oracle = VerificationOracle::new();
        let a = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let b = MbaExprTree::Var("x".into());
        let (eq, _) = oracle.check_equivalent(&a, &b);
        assert!(eq);
    }

    #[test]
    fn test_oracle_is_constant_true() {
        let oracle = VerificationOracle::new();
        let e = MbaExprTree::Const(99);
        assert!(oracle.is_constant(&e));
    }

    #[test]
    fn test_oracle_is_constant_false() {
        let oracle = VerificationOracle::new();
        let e = MbaExprTree::Var("x".into());
        assert!(!oracle.is_constant(&e));
    }

    // ── MbaNormalizer ─────────────────────────────────────────────────────────

    #[test]
    fn test_normalizer_constant_expression() {
        let norm = MbaNormalizer::new();
        let e = MbaExprTree::add(MbaExprTree::Const(3), MbaExprTree::Const(4));
        let (nf, verified, _) = norm.normalize(e);
        assert_eq!(nf.as_const(), Some(7));
        assert!(verified);
    }

    #[test]
    fn test_normalizer_with_cp() {
        let mut norm = MbaNormalizer::new();
        norm.bind("x", 10);
        let e = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(5));
        let (nf, _, _) = norm.normalize(e);
        assert_eq!(nf.as_const(), Some(15));
    }

    #[test]
    fn test_normalizer_xor_self() {
        let norm = MbaNormalizer::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::xor(x.clone(), x);
        let (nf, verified, _) = norm.normalize(e);
        assert_eq!(nf.as_const(), Some(0));
        assert!(verified);
    }

    #[test]
    fn test_normalizer_complexity_ratio() {
        let norm = MbaNormalizer::new();
        let orig = MbaExprTree::add(MbaExprTree::Const(1), MbaExprTree::Const(2));
        let simplified = MbaExprTree::Const(3);
        let ratio = norm.complexity_ratio(&orig, &simplified);
        assert!(ratio < 1.0);
    }

    #[test]
    fn test_normalizer_preserves_semantics() {
        let norm = MbaNormalizer::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::add(x.clone(), MbaExprTree::Const(0));
        let (nf, verified, _) = norm.normalize(e);
        assert_eq!(nf.expr, x);
        assert!(verified);
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_alg_sub_zero() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::sub(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Var("x".into()));
    }

    #[test]
    fn test_alg_mul_zero_left() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::mul(MbaExprTree::Const(0), MbaExprTree::Var("x".into()));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(0));
    }

    #[test]
    fn test_alg_mul_zero_right() {
        let alg = AlgebraicSimplification::new();
        let e = MbaExprTree::mul(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::Const(0));
    }

    #[test]
    fn test_alg_or_self() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::or(x.clone(), x.clone());
        let (result, _) = alg.simplify(e);
        assert_eq!(result, x);
    }

    #[test]
    fn test_alg_neg_of_not_produces_add1() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::neg(MbaExprTree::not(x.clone()));
        let (result, rules) = alg.simplify(e);
        assert!(rules.contains(&"neg-of-not".to_string()));
        // result should be x + 1
        match result {
            MbaExprTree::Add(l, r) => {
                assert_eq!(*l, x);
                assert_eq!(*r, MbaExprTree::Const(1));
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn test_alg_xor_allones_right() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let e = MbaExprTree::xor(x.clone(), MbaExprTree::Const(-1));
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::not(x));
    }

    #[test]
    fn test_oracle_with_more_bits() {
        let oracle = VerificationOracle {
            bits: 16,
            samples: 32,
        };
        let a = MbaExprTree::add(MbaExprTree::Var("x".into()), MbaExprTree::Const(0));
        let b = MbaExprTree::Var("x".into());
        let (eq, _) = oracle.check_equivalent(&a, &b);
        assert!(eq);
    }

    #[test]
    fn test_normal_form_vars() {
        let e = MbaExprTree::add(MbaExprTree::Var("a".into()), MbaExprTree::Var("b".into()));
        let nf = NormalForm::from_expr(e);
        assert!(nf.vars.contains(&"a".to_string()));
        assert!(nf.vars.contains(&"b".to_string()));
    }

    #[test]
    fn test_cp_neg_propagation() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 5);
        let e = MbaExprTree::neg(MbaExprTree::Var("x".into()));
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Const(-5));
    }

    #[test]
    fn test_cp_not_propagation() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 0);
        let e = MbaExprTree::not(MbaExprTree::Var("x".into()));
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Const(-1));
    }

    #[test]
    fn test_cp_shl_propagation() {
        let mut cp = ConstantPropagation::new();
        cp.bind("x", 1);
        let e = MbaExprTree::Shl(Box::new(MbaExprTree::Var("x".into())), 3);
        let result = cp.propagate(&e);
        assert_eq!(result, MbaExprTree::Const(8)); // 1 << 3 = 8
    }

    #[test]
    fn test_alg_or_minus_and() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::sub(
            MbaExprTree::or(x.clone(), y.clone()),
            MbaExprTree::and(x.clone(), y.clone()),
        );
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::xor(x, y));
    }

    #[test]
    fn test_alg_sum_minus_and_eq_or() {
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::sub(
            MbaExprTree::add(x.clone(), y.clone()),
            MbaExprTree::and(x.clone(), y.clone()),
        );
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::or(x, y));
    }

    #[test]
    fn test_expr_and_eval() {
        let mut env = HashMap::new();
        env.insert("x".into(), 0b1010i64);
        env.insert("y".into(), 0b1100i64);
        let e = MbaExprTree::and(MbaExprTree::Var("x".into()), MbaExprTree::Var("y".into()));
        assert_eq!(e.eval(&env), Some(0b1000));
    }

    #[test]
    fn test_alg_and_plus_or_eq_add() {
        // (x & y) + (x | y) → x + y
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::add(
            MbaExprTree::and(x.clone(), y.clone()),
            MbaExprTree::or(x.clone(), y.clone()),
        );
        let (result, rules) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::add(x, y));
        assert!(rules.contains(&"and-plus-or".to_string()));
    }

    #[test]
    fn test_alg_xor_plus_2and_eq_add() {
        // (x ^ y) + 2*(x & y) → x + y
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::add(
            MbaExprTree::xor(x.clone(), y.clone()),
            MbaExprTree::mul(
                MbaExprTree::Const(2),
                MbaExprTree::and(x.clone(), y.clone()),
            ),
        );
        let (result, rules) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::add(x, y));
        assert!(rules.contains(&"xor-plus-2and".to_string()));
    }

    #[test]
    fn test_alg_xor_plus_2and_commuted() {
        // 2*(x & y) + (x ^ y) → x + y
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::add(
            MbaExprTree::mul(
                MbaExprTree::and(x.clone(), y.clone()),
                MbaExprTree::Const(2),
            ),
            MbaExprTree::xor(x.clone(), y.clone()),
        );
        let (result, _) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::add(x, y));
    }

    #[test]
    fn test_alg_or_minus_and_eq_xor_identity() {
        // (x | y) - (x & y) → x ^ y
        let alg = AlgebraicSimplification::new();
        let x = MbaExprTree::Var("x".into());
        let y = MbaExprTree::Var("y".into());
        let e = MbaExprTree::sub(
            MbaExprTree::or(x.clone(), y.clone()),
            MbaExprTree::and(x.clone(), y.clone()),
        );
        let (result, rules) = alg.simplify(e);
        assert_eq!(result, MbaExprTree::xor(x, y));
        assert!(rules.contains(&"or-minus-and".to_string()));
    }

    #[test]
    fn test_normalizer_depth_bound() {
        // A deeply nested constant expression should converge.
        let norm = MbaNormalizer::new();
        let mut e = MbaExprTree::Const(1);
        for _ in 0..5 {
            e = MbaExprTree::add(e, MbaExprTree::Const(0));
        }
        let (nf, _, _) = norm.normalize(e);
        assert_eq!(nf.as_const(), Some(1));
    }
}
