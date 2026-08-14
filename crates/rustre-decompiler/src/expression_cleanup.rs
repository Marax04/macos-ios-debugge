//! `expression_cleanup` — Expression cleanup for C output.
//!
//! Transforms decompiler expression trees into idiomatic C-style strings:
//!
//! * [`CastElimination`] — removes redundant type casts.
//! * [`RedundantOp`] — removes no-op operations (x | 0, x * 1, etc.).
//! * [`CanonicalForm`] — normalises commutative/associative expressions.
//! * [`AssociativityRewrite`] — reassociates nested additions/multiplications.
//! * [`DeMorganApplication`] — pushes negations inward using De Morgan.
//! * [`PointerArithmetic`] — simplifies `(T*)((char*)ptr + N)` patterns.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Expr AST ─────────────────────────────────────────────────────────────────

/// A simplified C expression tree used for cleanup passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    /// A constant integer literal.
    Const(i64),
    /// A named variable.
    Var(String),
    /// A unary operation.
    Unary { op: UnaryOp, expr: Box<Self> },
    /// A binary operation.
    Binary {
        op: BinaryOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// A type cast.
    Cast { ty: String, expr: Box<Self> },
    /// Pointer dereference `*expr`.
    Deref(Box<Self>),
    /// Address-of `&expr`.
    AddrOf(Box<Self>),
    /// Array subscript `base[index]`.
    Index { base: Box<Self>, index: Box<Self> },
    /// Function call `name(args)`.
    Call { name: String, args: Vec<Self> },
    /// Raw string (fallback).
    Raw(String),
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg,     // `-`
    Not,     // `~`
    BoolNot, // `!`
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "-"),
            Self::Not => write!(f, "~"),
            Self::BoolNot => write!(f, "!"),
        }
    }
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    BoolAnd,
    BoolOr,
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "+"),
            Self::Sub => write!(f, "-"),
            Self::Mul => write!(f, "*"),
            Self::Div => write!(f, "/"),
            Self::Mod => write!(f, "%"),
            Self::And => write!(f, "&"),
            Self::Or => write!(f, "|"),
            Self::Xor => write!(f, "^"),
            Self::Shl => write!(f, "<<"),
            Self::Shr => write!(f, ">>"),
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
            Self::BoolAnd => write!(f, "&&"),
            Self::BoolOr => write!(f, "||"),
        }
    }
}

impl Expr {
    /// Return `true` if this expression is a constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Return the constant value if this is a `Const`.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// C operator precedence for this expression node (higher binds tighter).
    ///
    /// Used by [`Self::emit`] to add parentheses only where they are needed,
    /// so output reads like hand-written C (`(x + 1) * y`) rather than the
    /// fully-parenthesised `((x + 1) * (y))` machine form.
    const fn precedence(&self) -> u8 {
        match self {
            Self::Const(_) | Self::Var(_) | Self::Call { .. } | Self::Index { .. } | Self::Raw(_) => {
                15
            }
            Self::Unary { .. } | Self::Cast { .. } | Self::Deref(_) | Self::AddrOf(_) => 14,
            Self::Binary { op, .. } => match op {
                BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => 13,
                BinaryOp::Add | BinaryOp::Sub => 12,
                BinaryOp::Shl | BinaryOp::Shr => 11,
                BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => 10,
                BinaryOp::Eq | BinaryOp::Ne => 9,
                BinaryOp::And => 8,
                BinaryOp::Xor => 7,
                BinaryOp::Or => 6,
                BinaryOp::BoolAnd => 5,
                BinaryOp::BoolOr => 4,
            },
        }
    }

    /// Emit this expression, wrapping it in parentheses only when its
    /// precedence is below `parent_prec`.
    fn emit_prec(&self, parent_prec: u8) -> String {
        let s = self.emit();
        if self.precedence() < parent_prec {
            format!("({s})")
        } else {
            s
        }
    }

    /// Emit a C-style string for this expression.
    #[must_use]
    pub fn emit(&self) -> String {
        match self {
            Self::Const(v) => {
                if *v < 0 {
                    format!("-{:#x}", -v)
                } else {
                    format!("{v:#x}")
                }
            }
            Self::Var(n) => n.clone(),
            Self::Unary { op, expr } => format!("{op}{}", expr.emit_prec(14)),
            Self::Binary { op, lhs, rhs } => {
                let p = self.precedence();
                // Right operand parenthesised at `p + 1` so left-associative
                // chains keep the same-precedence rhs bracketed: `a - (b - c)`.
                format!("{} {op} {}", lhs.emit_prec(p), rhs.emit_prec(p + 1))
            }
            Self::Cast { ty, expr } => format!("({ty}){}", expr.emit_prec(14)),
            Self::Deref(e) => format!("*{}", e.emit_prec(14)),
            Self::AddrOf(e) => format!("&{}", e.emit_prec(14)),
            Self::Index { base, index } => format!("{}[{}]", base.emit_prec(15), index.emit()),
            Self::Call { name, args } => {
                let arg_strs = args.iter().map(Self::emit).collect::<Vec<_>>().join(", ");
                format!("{name}({arg_strs})")
            }
            Self::Raw(s) => s.clone(),
        }
    }

    /// Build an add expression.
    #[must_use]
    pub fn make_add(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::Add,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a sub expression.
    #[must_use]
    pub fn make_sub(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::Sub,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a mul expression.
    #[must_use]
    pub fn make_mul(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::Mul,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a bitwise AND.
    #[must_use]
    pub fn make_bitand(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::And,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a bitwise OR.
    #[must_use]
    pub fn make_bitor(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::Or,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a bitwise XOR.
    #[must_use]
    pub fn make_bitxor(lhs: Self, rhs: Self) -> Self {
        Self::Binary {
            op: BinaryOp::Xor,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Build a negation.
    #[must_use]
    pub fn make_neg(e: Self) -> Self {
        Self::Unary {
            op: UnaryOp::Neg,
            expr: Box::new(e),
        }
    }

    /// Build a bitwise NOT.
    #[must_use]
    pub fn bitnot(e: Self) -> Self {
        Self::Unary {
            op: UnaryOp::Not,
            expr: Box::new(e),
        }
    }
}

impl std::ops::Add for Expr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::make_add(self, rhs)
    }
}

impl std::ops::Sub for Expr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::make_sub(self, rhs)
    }
}

impl std::ops::Mul for Expr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::make_mul(self, rhs)
    }
}

impl std::ops::BitAnd for Expr {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self::make_bitand(self, rhs)
    }
}

impl std::ops::BitOr for Expr {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self::make_bitor(self, rhs)
    }
}

impl std::ops::BitXor for Expr {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self::make_bitxor(self, rhs)
    }
}

impl std::ops::Neg for Expr {
    type Output = Self;
    fn neg(self) -> Self {
        Self::make_neg(self)
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit())
    }
}

// ─── CastElimination ──────────────────────────────────────────────────────────

/// Removes redundant type casts.
///
/// A cast is redundant when:
/// * The inner expression is already of the same type (identity cast).
/// * The cast is to `int` of an expression already known to be an `int`.
/// * The cast wraps a constant that fits in the target type.
#[derive(Debug, Default)]
pub struct CastElimination {
    removed: u32,
}

impl CastElimination {
    /// Create a new `CastElimination` pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recursively eliminate redundant casts from `expr`.
    pub fn eliminate(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Cast { ty, expr: inner } => {
                let inner_simplified = self.eliminate(*inner);
                // Identity cast: cast to the same type as the inner expression.
                if let Expr::Cast { ty: inner_ty, .. } = &inner_simplified
                    && inner_ty == &ty {
                        self.removed += 1;
                        return inner_simplified;
                    }
                // Cast of a constant: always eliminable.
                if inner_simplified.is_const() {
                    self.removed += 1;
                    return inner_simplified;
                }
                Expr::Cast {
                    ty,
                    expr: Box::new(inner_simplified),
                }
            }
            Expr::Binary { op, lhs, rhs } => Expr::Binary {
                op,
                lhs: Box::new(self.eliminate(*lhs)),
                rhs: Box::new(self.eliminate(*rhs)),
            },
            Expr::Unary { op, expr: inner } => Expr::Unary {
                op,
                expr: Box::new(self.eliminate(*inner)),
            },
            Expr::Deref(inner) => Expr::Deref(Box::new(self.eliminate(*inner))),
            Expr::AddrOf(inner) => Expr::AddrOf(Box::new(self.eliminate(*inner))),
            Expr::Index { base, index } => Expr::Index {
                base: Box::new(self.eliminate(*base)),
                index: Box::new(self.eliminate(*index)),
            },
            Expr::Call { name, args } => Expr::Call {
                name,
                args: args.into_iter().map(|a| self.eliminate(a)).collect(),
            },
            other => other,
        }
    }

    /// Return the number of casts removed.
    #[must_use]
    pub const fn removed(&self) -> u32 {
        self.removed
    }
}

// ─── RedundantOp ──────────────────────────────────────────────────────────────

/// Removes no-op operations:
///
/// * `x + 0 = x`
/// * `x - 0 = x`
/// * `x * 1 = x`
/// * `x * 0 = 0`
/// * `x | 0 = x`
/// * `x & -1 = x`  (all-ones mask)
/// * `x ^ 0 = x`
/// * `x ^ x = 0`
/// * `-(-x) = x`
/// * `~(~x) = x`
#[derive(Debug, Default)]
pub struct RedundantOp {
    removed: u32,
}

/// Fold a binary operation applied to two integer constants.
///
/// Returns `None` for division/shift by zero or amounts that would be
/// undefined in C, leaving the expression untouched in those cases.
fn fold_const(op: BinaryOp, a: i64, b: i64) -> Option<i64> {
    let r = match op {
        BinaryOp::Add => a.wrapping_add(b),
        BinaryOp::Sub => a.wrapping_sub(b),
        BinaryOp::Mul => a.wrapping_mul(b),
        BinaryOp::Div => {
            if b == 0 { return None; }
            a.wrapping_div(b)
        }
        BinaryOp::Mod => {
            if b == 0 { return None; }
            a.wrapping_rem(b)
        }
        BinaryOp::And => a & b,
        BinaryOp::Or => a | b,
        BinaryOp::Xor => a ^ b,
        BinaryOp::Shl => {
            let sh = u32::try_from(b).ok().filter(|s| *s < 64)?;
            a.wrapping_shl(sh)
        }
        BinaryOp::Shr => {
            let sh = u32::try_from(b).ok().filter(|s| *s < 64)?;
            a.wrapping_shr(sh)
        }
        BinaryOp::Eq => i64::from(a == b),
        BinaryOp::Ne => i64::from(a != b),
        BinaryOp::Lt => i64::from(a < b),
        BinaryOp::Le => i64::from(a <= b),
        BinaryOp::Gt => i64::from(a > b),
        BinaryOp::Ge => i64::from(a >= b),
        // Boolean connectives over integer constants: treat non-zero as true.
        BinaryOp::BoolAnd => i64::from(a != 0 && b != 0),
        BinaryOp::BoolOr => i64::from(a != 0 || b != 0),
    };
    Some(r)
}

impl RedundantOp {
    /// Create a new `RedundantOp` pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recursively remove redundant operations from `expr`.
    /// Simplify a [`BinaryOp`] expression whose operands have already been
    /// recursively simplified.
    fn simplify_binary(&mut self, op: BinaryOp, ls: Expr, rs: Expr) -> Expr {
        // Fold two constant operands to a single constant, matching IDA.
        if let (Expr::Const(a), Expr::Const(b)) = (&ls, &rs) {
            if let Some(v) = fold_const(op, *a, *b) {
                self.removed += 1;
                return Expr::Const(v);
            }
        }
        // Determine the simplified result by inspecting the operands *by
        // reference* only. The common (no-op) case falls through and rebuilds
        // the node by moving `ls`/`rs` — no clone of either subtree.
        match op {
            BinaryOp::Add => match (&ls, &rs) {
                (_, Expr::Const(0)) | (Expr::Const(0), _) => {
                    self.removed += 1;
                    return if matches!(ls, Expr::Const(0)) { rs } else { ls };
                }
                _ => {}
            },
            BinaryOp::Sub => match (&ls, &rs) {
                (_, Expr::Const(0)) => { self.removed += 1; return ls; }
                _ if ls == rs => { self.removed += 1; return Expr::Const(0); }
                _ => {}
            },
            BinaryOp::Mul => match (&ls, &rs) {
                (_, Expr::Const(0)) | (Expr::Const(0), _) => { self.removed += 1; return Expr::Const(0); }
                (_, Expr::Const(1)) => { self.removed += 1; return ls; }
                (Expr::Const(1), _) => { self.removed += 1; return rs; }
                _ => {}
            },
            BinaryOp::Or => match (&ls, &rs) {
                (_, Expr::Const(0)) => { self.removed += 1; return ls; }
                (Expr::Const(0), _) => { self.removed += 1; return rs; }
                _ if ls == rs => { self.removed += 1; return ls; }
                _ => {}
            },
            BinaryOp::Xor => match (&ls, &rs) {
                (_, Expr::Const(0)) | (Expr::Const(0), _) => {
                    self.removed += 1;
                    return if matches!(ls, Expr::Const(0)) { rs } else { ls };
                }
                _ if ls == rs => { self.removed += 1; return Expr::Const(0); }
                _ => {}
            },
            BinaryOp::And => match (&ls, &rs) {
                (_, Expr::Const(0)) | (Expr::Const(0), _) => { self.removed += 1; return Expr::Const(0); }
                (_, Expr::Const(-1)) => { self.removed += 1; return ls; }
                (Expr::Const(-1), _) => { self.removed += 1; return rs; }
                _ if ls == rs => { self.removed += 1; return ls; }
                _ => {}
            },
            BinaryOp::Div if matches!(&rs, Expr::Const(1)) => {
                self.removed += 1;
                return ls;
            }
            BinaryOp::Mod if matches!(&rs, Expr::Const(1)) => {
                self.removed += 1;
                return Expr::Const(0);
            }
            BinaryOp::Shl | BinaryOp::Shr if matches!(&rs, Expr::Const(0)) => {
                self.removed += 1;
                return ls;
            }
            _ => {}
        }
        // Normalise `x + (-c)` to `x - c` and `x - (-c)` to `x + c` so output
        // reads like hand-written C instead of `x + (-0x4)`.
        match (op, &rs) {
            (BinaryOp::Add, Expr::Const(c)) if *c < 0 && *c != i64::MIN => {
                return Expr::Binary { op: BinaryOp::Sub, lhs: Box::new(ls), rhs: Box::new(Expr::Const(-c)) };
            }
            (BinaryOp::Sub, Expr::Const(c)) if *c < 0 && *c != i64::MIN => {
                return Expr::Binary { op: BinaryOp::Add, lhs: Box::new(ls), rhs: Box::new(Expr::Const(-c)) };
            }
            _ => {}
        }
        Expr::Binary { op, lhs: Box::new(ls), rhs: Box::new(rs) }
    }

    pub fn simplify(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Binary { op, lhs, rhs } => {
                let ls = self.simplify(*lhs);
                let rs = self.simplify(*rhs);
                self.simplify_binary(op, ls, rs)
            }
            Expr::Unary { op, expr: inner } => {
                let s = self.simplify(*inner);
                match (&op, &s) {
                    (UnaryOp::Neg, Expr::Unary { op: UnaryOp::Neg, expr: inner2 })
                    | (UnaryOp::Not, Expr::Unary { op: UnaryOp::Not, expr: inner2 })
                    | (UnaryOp::BoolNot, Expr::Unary { op: UnaryOp::BoolNot, expr: inner2 }) => {
                        self.removed += 1;
                        *inner2.clone()
                    }
                    (UnaryOp::Neg, Expr::Const(c)) => {
                        self.removed += 1;
                        Expr::Const(c.wrapping_neg())
                    }
                    (UnaryOp::Not, Expr::Const(c)) => {
                        self.removed += 1;
                        Expr::Const(!c)
                    }
                    _ => Expr::Unary { op, expr: Box::new(s) },
                }
            }
            Expr::Cast { ty, expr: inner } => Expr::Cast {
                ty,
                expr: Box::new(self.simplify(*inner)),
            },
            other => other,
        }
    }

    /// Return the number of redundant operations removed.
    #[must_use]
    pub const fn removed(&self) -> u32 {
        self.removed
    }
}

// ─── CanonicalForm ────────────────────────────────────────────────────────────

/// Normalises commutative expressions to a canonical form.
///
/// For commutative operators (`+`, `*`, `&`, `|`, `^`), sorts the operands
/// so that constants appear on the right and variables appear on the left.
/// This makes common-subexpression detection and comparison easier.
#[derive(Debug, Default)]
pub struct CanonicalForm {
    rewrites: u32,
}

impl CanonicalForm {
    /// Create a new `CanonicalForm` pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Canonicalise `expr`.
    pub fn canonicalise(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Binary { op, lhs, rhs } => {
                let ls = self.canonicalise(*lhs);
                let rs = self.canonicalise(*rhs);
                if is_commutative(op) && should_swap(&ls, &rs) {
                    self.rewrites += 1;
                    Expr::Binary {
                        op,
                        lhs: Box::new(rs),
                        rhs: Box::new(ls),
                    }
                } else {
                    Expr::Binary {
                        op,
                        lhs: Box::new(ls),
                        rhs: Box::new(rs),
                    }
                }
            }
            Expr::Unary { op, expr: inner } => Expr::Unary {
                op,
                expr: Box::new(self.canonicalise(*inner)),
            },
            Expr::Cast { ty, expr: inner } => Expr::Cast {
                ty,
                expr: Box::new(self.canonicalise(*inner)),
            },
            other => other,
        }
    }

    /// Return the number of rewrite operations performed.
    #[must_use]
    pub const fn rewrites(&self) -> u32 {
        self.rewrites
    }
}

const fn is_commutative(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Add
            | BinaryOp::Mul
            | BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Xor
            | BinaryOp::Eq
            | BinaryOp::Ne
    )
}

/// Returns `true` if lhs and rhs should be swapped (constant on the right).
const fn should_swap(lhs: &Expr, rhs: &Expr) -> bool {
    matches!((lhs, rhs),
        (Expr::Const(_), Expr::Var(_) | Expr::Binary { .. })
    )
}

// ─── AssociativityRewrite ────────────────────────────────────────────────────

/// Reassociates nested addition/multiplication to flatten or balance trees.
///
/// * `(x + y) + z → x + (y + z)` (right-associate chains).
/// * Constant accumulation: `(x + 3) + 4 → x + 7`.
#[derive(Debug, Default)]
pub struct AssociativityRewrite {
    rewrites: u32,
}

impl AssociativityRewrite {
    /// Create a new `AssociativityRewrite` pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rewrite `expr` to accumulate constants and right-associate chains.
    pub fn rewrite(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Binary {
                op: BinaryOp::Add,
                lhs,
                rhs,
            } => {
                let ls = self.rewrite(*lhs);
                let rs = self.rewrite(*rhs);
                // Constant accumulation: (x + C1) + C2 → x + (C1 + C2)
                if let (
                    Expr::Binary {
                        op: BinaryOp::Add,
                        lhs: inner_l,
                        rhs: inner_r,
                    },
                    Expr::Const(c2),
                ) = (&ls, &rs)
                    && let Expr::Const(c1) = inner_r.as_ref() {
                        self.rewrites += 1;
                        return Expr::Binary {
                            op: BinaryOp::Add,
                            lhs: inner_l.clone(),
                            rhs: Box::new(Expr::Const(c1 + c2)),
                        };
                    }
                Expr::Binary {
                    op: BinaryOp::Add,
                    lhs: Box::new(ls),
                    rhs: Box::new(rs),
                }
            }
            Expr::Binary {
                op: BinaryOp::Mul,
                lhs,
                rhs,
            } => {
                let ls = self.rewrite(*lhs);
                let rs = self.rewrite(*rhs);
                // Constant accumulation: (x * C1) * C2 → x * (C1 * C2)
                if let (
                    Expr::Binary {
                        op: BinaryOp::Mul,
                        lhs: inner_l,
                        rhs: inner_r,
                    },
                    Expr::Const(c2),
                ) = (&ls, &rs)
                    && let Expr::Const(c1) = inner_r.as_ref() {
                        self.rewrites += 1;
                        return Expr::Binary {
                            op: BinaryOp::Mul,
                            lhs: inner_l.clone(),
                            rhs: Box::new(Expr::Const(c1 * c2)),
                        };
                    }
                Expr::Binary {
                    op: BinaryOp::Mul,
                    lhs: Box::new(ls),
                    rhs: Box::new(rs),
                }
            }
            Expr::Binary { op, lhs, rhs } => Expr::Binary {
                op,
                lhs: Box::new(self.rewrite(*lhs)),
                rhs: Box::new(self.rewrite(*rhs)),
            },
            Expr::Unary { op, expr: inner } => Expr::Unary {
                op,
                expr: Box::new(self.rewrite(*inner)),
            },
            other => other,
        }
    }

    /// Return the number of rewrites performed.
    #[must_use]
    pub const fn rewrites(&self) -> u32 {
        self.rewrites
    }
}

/// Return the logically-negated comparison operator, if `op` is one.
///
/// Valid for total orders over the integer expressions this AST models.
const fn negate_cmp(op: BinaryOp) -> Option<BinaryOp> {
    Some(match op {
        BinaryOp::Eq => BinaryOp::Ne,
        BinaryOp::Ne => BinaryOp::Eq,
        BinaryOp::Lt => BinaryOp::Ge,
        BinaryOp::Ge => BinaryOp::Lt,
        BinaryOp::Le => BinaryOp::Gt,
        BinaryOp::Gt => BinaryOp::Le,
        _ => return None,
    })
}

// ─── DeMorganApplication ─────────────────────────────────────────────────────

/// Applies De Morgan's laws to Boolean expressions in C:
///
/// * `!(a && b) → (!a || !b)`
/// * `!(a || b) → (!a && !b)`
/// * `!(!a) → a`
#[derive(Debug, Default)]
pub struct DeMorganApplication {
    applied: u32,
}

impl DeMorganApplication {
    /// Create a new `DeMorganApplication` pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply De Morgan's laws recursively.
    pub fn apply(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Unary {
                op: UnaryOp::BoolNot,
                expr: inner,
            } => {
                let s = self.apply(*inner);
                match s {
                    Expr::Binary {
                        op: BinaryOp::BoolAnd,
                        lhs,
                        rhs,
                    } => {
                        self.applied += 1;
                        Expr::Binary {
                            op: BinaryOp::BoolOr,
                            lhs: Box::new(self.apply(Expr::Unary {
                                op: UnaryOp::BoolNot,
                                expr: lhs,
                            })),
                            rhs: Box::new(self.apply(Expr::Unary {
                                op: UnaryOp::BoolNot,
                                expr: rhs,
                            })),
                        }
                    }
                    Expr::Binary {
                        op: BinaryOp::BoolOr,
                        lhs,
                        rhs,
                    } => {
                        self.applied += 1;
                        Expr::Binary {
                            op: BinaryOp::BoolAnd,
                            lhs: Box::new(self.apply(Expr::Unary {
                                op: UnaryOp::BoolNot,
                                expr: lhs,
                            })),
                            rhs: Box::new(self.apply(Expr::Unary {
                                op: UnaryOp::BoolNot,
                                expr: rhs,
                            })),
                        }
                    }
                    Expr::Unary {
                        op: UnaryOp::BoolNot,
                        expr: inner2,
                    } => {
                        self.applied += 1;
                        *inner2 // double negation
                    }
                    // `!(a < b)` → `a >= b`, `!(a == b)` → `a != b`, etc.
                    Expr::Binary { op, lhs, rhs } if negate_cmp(op).is_some() => {
                        self.applied += 1;
                        Expr::Binary {
                            op: negate_cmp(op).unwrap(),
                            lhs,
                            rhs,
                        }
                    }
                    other => Expr::Unary {
                        op: UnaryOp::BoolNot,
                        expr: Box::new(other),
                    },
                }
            }
            Expr::Binary { op, lhs, rhs } => Expr::Binary {
                op,
                lhs: Box::new(self.apply(*lhs)),
                rhs: Box::new(self.apply(*rhs)),
            },
            Expr::Unary { op, expr: inner } => Expr::Unary {
                op,
                expr: Box::new(self.apply(*inner)),
            },
            other => other,
        }
    }

    /// Return the number of De Morgan applications.
    #[must_use]
    pub const fn applied(&self) -> u32 {
        self.applied
    }
}

// ─── PointerArithmetic ────────────────────────────────────────────────────────

/// Simplifies C pointer arithmetic patterns.
///
/// Common patterns:
/// * `(T*)((char*)ptr + N)` → `ptr + N/sizeof(T)` when N is divisible by
///   `sizeof(T)`.
/// * `*(ptr + 0)` → `*ptr`.
/// * `ptr[0]` → `*ptr`.
#[derive(Debug, Default)]
pub struct PointerArithmetic {
    /// Type name → size in bytes.
    type_sizes: HashMap<String, u64>,
    simplified: u32,
}

impl PointerArithmetic {
    /// Create a new `PointerArithmetic` pass with common type sizes.
    #[must_use]
    pub fn new() -> Self {
        let mut pa = Self::default();
        pa.type_sizes.insert("char".into(), 1);
        pa.type_sizes.insert("int".into(), 4);
        pa.type_sizes.insert("long".into(), 8);
        pa.type_sizes.insert("uint8_t".into(), 1);
        pa.type_sizes.insert("uint16_t".into(), 2);
        pa.type_sizes.insert("uint32_t".into(), 4);
        pa.type_sizes.insert("uint64_t".into(), 8);
        pa.type_sizes.insert("float".into(), 4);
        pa.type_sizes.insert("double".into(), 8);
        pa
    }

    /// Register a type size.
    pub fn register_type(&mut self, name: impl Into<String>, size: u64) {
        self.type_sizes.insert(name.into(), size);
    }

    /// Simplify pointer arithmetic in `expr`.
    pub fn simplify(&mut self, expr: Expr) -> Expr {
        match expr {
            // *(ptr + 0) → *ptr
            Expr::Deref(inner) => {
                let s = self.simplify(*inner);
                if let Expr::Binary {
                    op: BinaryOp::Add,
                    lhs,
                    rhs: box_rhs,
                } = &s
                    && matches!(box_rhs.as_ref(), Expr::Const(0)) {
                        self.simplified += 1;
                        return Expr::Deref(lhs.clone());
                    }
                Expr::Deref(Box::new(s))
            }
            // ptr[0] → *ptr
            Expr::Index { base, index } => {
                let bs = self.simplify(*base);
                let is = self.simplify(*index);
                if matches!(is, Expr::Const(0)) {
                    self.simplified += 1;
                    return Expr::Deref(Box::new(bs));
                }
                Expr::Index {
                    base: Box::new(bs),
                    index: Box::new(is),
                }
            }
            // (T*)((char*)ptr + N) → simplified pointer
            Expr::Cast { ty, expr: inner } => {
                let s = self.simplify(*inner);
                // If the inner is a char* cast of (ptr + N), try to simplify.
                if let Expr::Binary {
                    op: BinaryOp::Add,
                    lhs,
                    rhs,
                } = &s
                    && let Expr::Cast { ty: inner_ty, .. } = lhs.as_ref()
                        && (inner_ty == "char*" || inner_ty == "uint8_t*")
                            && let Expr::Const(off) = rhs.as_ref() {
                                // Try to divide by the target type size.
                                let target = ty.trim_end_matches('*');
                                if let Some(&sz) = self.type_sizes.get(target)
                                    && sz > 0
                                    && let Ok(off_u) = u64::try_from(*off)
                                    && off_u.is_multiple_of(sz) {
                                        let idx = off_u / sz;
                                        self.simplified += 1;
                                        return Expr::Binary {
                                            op: BinaryOp::Add,
                                            lhs: lhs.clone(),
                                            rhs: Box::new(Expr::Const(i64::try_from(idx).unwrap_or(i64::MAX))),
                                        };
                                    }
                            }
                Expr::Cast {
                    ty,
                    expr: Box::new(s),
                }
            }
            Expr::Binary { op, lhs, rhs } => Expr::Binary {
                op,
                lhs: Box::new(self.simplify(*lhs)),
                rhs: Box::new(self.simplify(*rhs)),
            },
            Expr::Unary { op, expr: inner } => Expr::Unary {
                op,
                expr: Box::new(self.simplify(*inner)),
            },
            other => other,
        }
    }

    /// Return the number of simplifications applied.
    #[must_use]
    pub const fn simplified(&self) -> u32 {
        self.simplified
    }
}

// ─── ExpressionCleanup ───────────────────────────────────────────────────────

/// Top-level pass that combines all cleanup sub-passes.
#[derive(Debug, Default)]
pub struct ExpressionCleanup {
    pub cast_elim: CastElimination,
    pub redundant: RedundantOp,
    pub canonical: CanonicalForm,
    pub assoc: AssociativityRewrite,
    pub demorgan: DeMorganApplication,
    pub ptr_arith: PointerArithmetic,
}

impl ExpressionCleanup {
    /// Create a new cleanup pass.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ptr_arith: PointerArithmetic::new(),
            ..Self::default()
        }
    }

    /// Run all passes over `expr` in order.
    pub fn run(&mut self, expr: Expr) -> Expr {
        let e = self.cast_elim.eliminate(expr);
        let e = self.redundant.simplify(e);
        let e = self.canonical.canonicalise(e);
        let e = self.assoc.rewrite(e);
        let e = self.demorgan.apply(e);
        self.ptr_arith.simplify(e)
    }

    /// Summary of cleanup statistics.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "cast_elim={}, redundant={}, canonical={}, assoc={}, demorgan={}, ptr={}",
            self.cast_elim.removed(),
            self.redundant.removed(),
            self.canonical.rewrites(),
            self.assoc.rewrites(),
            self.demorgan.applied(),
            self.ptr_arith.simplified(),
        )
    }
}

impl fmt::Display for ExpressionCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExpressionCleanup {{ {} }}", self.summary())
    }
}

// ─── Emitted-line noise cleanup ────────────────────────────────────────────────

/// Callee-saved registers whose `push`/`pop` in the body is pure frame
/// bookkeeping (prologue/epilogue spill), not meaningful C.
fn is_frame_bookkeeping_reg(reg: &str) -> bool {
    matches!(
        reg.trim().to_ascii_lowercase().as_str(),
        "rbp" | "rbx" | "rsi" | "rdi" | "r12" | "r13" | "r14" | "r15"
            | "ebp" | "ebx" | "esi" | "edi"
    )
}

/// Scratch (caller-saved) registers whose push/pop save-restore pairs in
/// straight-line code can be cancelled without losing program meaning.
fn is_scratch_reg(reg: &str) -> bool {
    matches!(
        reg,
        "rax" | "rcx" | "rdx" | "r8" | "r9" | "r10" | "r11" | "eax" | "ecx" | "edx"
    )
}

/// Bare-mnemonic comment fallbacks with no C-visible effect. Deliberately
/// excludes `rep*` string ops (memcpy/memset semantics) and anything that
/// moves data.
fn is_noise_mnemonic(mnem: &str) -> bool {
    matches!(
        mnem,
        "cdq" | "cdqe" | "cqo" | "cwde" | "cbw" | "leave" | "sahf" | "lahf" | "wait" | "fwait"
            | "pause" | "cld" | "std" | "clc" | "stc" | "lock" | "data16" | "lfence" | "sfence"
            | "mfence" | "nop"
    )
}

/// Win64 nonvolatile XMM registers (`xmm6`–`xmm15`). Their prologue save /
/// epilogue restore through a stack slot is pure ABI preservation, not program
/// logic — Hex-Rays elides it, and so should we.
fn is_nonvolatile_xmm(reg: &str) -> bool {
    reg.trim()
        .to_ascii_lowercase()
        .strip_prefix("xmm")
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|n| (6..=15).contains(&n))
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Whether `tok` occurs in `line` as a whole identifier (not as a substring of
/// a longer identifier, e.g. `v_40` must not match inside `v_400`).
fn token_occurs(line: &str, tok: &str) -> bool {
    if tok.is_empty() {
        return false;
    }
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(pos) = line[from..].find(tok) {
        let i = from + pos;
        let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
        let after = i + tok.len();
        let after_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + tok.len();
    }
    false
}

/// Parse `_mm_storeu_si128((__m128i *)&SLOT, REG)` into `(slot, reg)`.
fn parse_xmm_store(t: &str) -> Option<(String, String)> {
    let inner = t
        .strip_prefix("_mm_storeu_si128(")?
        .strip_suffix(')')?;
    let (ptr, reg) = inner.rsplit_once(',')?;
    let slot = ptr.trim().rsplit('&').next()?.trim();
    if slot.is_empty() {
        return None;
    }
    Some((slot.to_string(), reg.trim().to_string()))
}

/// Parse `REG = _mm_loadu_si128((__m128i *)&SLOT)` into `(reg, slot)`.
fn parse_xmm_load(t: &str) -> Option<(String, String)> {
    let (lhs, rhs) = t.split_once('=')?;
    let reg = lhs.trim();
    let slot = rhs
        .trim()
        .strip_prefix("_mm_loadu_si128(")?
        .strip_suffix(')')?
        .trim()
        .rsplit('&')
        .next()?
        .trim();
    if reg.is_empty() || slot.is_empty() {
        return None;
    }
    Some((reg.to_string(), slot.to_string()))
}

/// Whether a trimmed line is the local declaration `<type> SLOT;` for `slot`
/// (a preservation-slot spill declaration to drop alongside its store/load).
fn is_decl_of(t: &str, slot: &str) -> bool {
    let Some(head) = t.strip_suffix(';') else {
        return false;
    };
    if head.contains('=') || head.contains('(') {
        return false;
    }
    head.trim_end().rsplit(|c: char| c.is_whitespace() || c == '*').next() == Some(slot)
}

/// Drop Win64 nonvolatile-XMM preservation spills: a prologue
/// `_mm_storeu_si128((__m128i *)&SLOT, xmmN)` paired with an epilogue
/// `xmmN = _mm_loadu_si128((__m128i *)&SLOT)`, plus SLOT's declaration.
///
/// Sound only when SLOT is a *pure* preservation slot — referenced nowhere but
/// its declaration, that one store, and that one load — and `xmmN` is dead
/// after the restore (never read again). Either gate failing keeps every line,
/// so a slot that also carries real data is never mistaken for boilerplate.
#[must_use]
fn strip_xmm_preservation(lines: &[String]) -> Vec<String> {
    // (line index, slot, reg) for every candidate store / load.
    let mut stores: Vec<(usize, String, String)> = Vec::new();
    let mut loads: Vec<(usize, String, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim().trim_end_matches(';').trim();
        if let Some((slot, reg)) = parse_xmm_store(t) {
            if is_nonvolatile_xmm(&reg) {
                stores.push((idx, slot, reg));
            }
        } else if let Some((reg, slot)) = parse_xmm_load(t) {
            if is_nonvolatile_xmm(&reg) {
                loads.push((idx, slot, reg));
            }
        }
    }

    let mut drop: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (s_idx, slot, reg) in &stores {
        // Matching restore: same slot & reg, strictly after the save.
        let Some((l_idx, _, _)) = loads
            .iter()
            .find(|(l_idx, l_slot, l_reg)| l_slot == slot && l_reg == reg && l_idx > s_idx)
        else {
            continue;
        };
        // Gate A: SLOT appears only on its store, its load, or its decl.
        let slot_pure = lines.iter().enumerate().all(|(i, ln)| {
            i == *s_idx || i == *l_idx || !token_occurs(ln, slot) || is_decl_of(ln.trim(), slot)
        });
        if !slot_pure {
            continue;
        }
        // Gate B: REG is dead after the restore (no later read/write).
        let reg_dead_after = lines
            .iter()
            .enumerate()
            .all(|(i, ln)| i <= *l_idx || !token_occurs(ln, reg));
        if !reg_dead_after {
            continue;
        }
        drop.insert(*s_idx);
        drop.insert(*l_idx);
        // Also drop SLOT's declaration line, if present.
        for (i, ln) in lines.iter().enumerate() {
            if is_decl_of(ln.trim(), slot) {
                drop.insert(i);
            }
        }
    }

    lines
        .iter()
        .enumerate()
        .filter(|(i, _)| !drop.contains(i))
        .map(|(_, l)| l.clone())
        .collect()
}

/// Remove readability noise from emitted pseudo-C body lines.
///
/// Drops `push(<callee-saved>);` / `<callee-saved> = pop();` GP-register spills
/// and Win64 nonvolatile-XMM preservation spills (see
/// [`strip_xmm_preservation`]) — prologue/epilogue bookkeeping with no program
/// meaning.
///
/// This is intentionally conservative: it only touches lines that are
/// unambiguously frame bookkeeping, never a `push`/`pop` of a non-callee-saved
/// register (which may carry a real argument or value), and never a `return`
/// (a bare `return;` in a non-void function must be *rewritten* with its value,
/// not deleted — a separate concern).
#[must_use]
pub fn strip_asm_noise(lines: &[String]) -> Vec<String> {
    let xmm_cleaned = strip_xmm_preservation(lines);
    let lines = &xmm_cleaned;
    // Pass 1: drop frame bookkeeping, cancel scratch push/pop pairs,
    // drop noise-mnemonic comments and zero-padding artifacts.
    let mut out: Vec<Option<String>> = Vec::with_capacity(lines.len());
    // Stack of (index-into-out, reg) for surviving scratch `push(R);` lines.
    let mut push_stack: Vec<(usize, String)> = Vec::new();
    for line in lines {
        let t = line.trim().trim_end_matches(';').trim();
        // push(reg);
        if let Some(inner) = t.strip_prefix("push(").and_then(|s| s.strip_suffix(')')) {
            let reg = inner.trim().to_ascii_lowercase();
            if is_frame_bookkeeping_reg(&reg) {
                continue;
            }
            if is_scratch_reg(&reg) {
                push_stack.push((out.len(), reg));
            }
            out.push(Some(line.clone()));
            continue;
        }
        // reg = pop();
        if let Some(lhs) = t.strip_suffix("= pop()").map(str::trim) {
            let reg = lhs.to_ascii_lowercase();
            if is_frame_bookkeeping_reg(&reg) {
                continue;
            }
            // Cancel with the matching push(R) if it is on top of the
            // pairing stack (LIFO discipline, no invalidation between).
            if push_stack.last().is_some_and(|(_, r)| *r == reg) {
                let (idx, _) = push_stack.pop().expect("checked non-empty");
                out[idx] = None; // erase the matching push(R);
                continue; // and drop this pop line
            }
        }
        // Zero-padding artifact: `[R] = [R] + al;` (lifted `add [reg], al`
        // from 00 00 filler bytes).
        if let Some((lhs, rhs)) = t.split_once(" = ")
            && lhs.starts_with('[')
            && lhs.ends_with(']')
            && rhs == format!("{lhs} + al")
        {
            continue;
        }
        // Bare-mnemonic comment fallback `/* mnem ops */`.
        if let Some(body) = t.strip_prefix("/*").and_then(|s| s.strip_suffix("*/")) {
            let mnem = body.trim().split_whitespace().next().unwrap_or("");
            if is_noise_mnemonic(mnem) {
                continue;
            }
        }
        // Invalidate pending pairs when the reg is written between
        // push and pop (its restored value then differs meaningfully).
        if let Some((lhs, _)) = t.split_once('=') {
            let l = lhs
                .trim()
                .trim_end_matches(['!', '<', '>', '+', '-', '*', '&', '|', '^'])
                .trim()
                .to_ascii_lowercase();
            push_stack.retain(|(_, r)| *r != l);
        }
        // Any call-shaped line clobbers scratch regs: pairing across a
        // call would hide a real save/restore, so clear the stack.
        if t.contains('(') && t.ends_with(')') {
            push_stack.clear();
        }
        out.push(Some(line.clone()));
    }
    let mut result: Vec<String> = out.into_iter().flatten().collect();

    // Pass 2: fold contiguous surviving `push(E);` lines that immediately
    // precede an empty-arg call `name();` into cdecl-style arguments
    // (nearest push = first argument).
    let mut i = 0;
    while i < result.len() {
        let t = result[i].trim();
        if let Some(name) = t.strip_suffix("();")
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        {
            let mut args: Vec<String> = Vec::new();
            let mut j = i;
            while j > 0 {
                let p = result[j - 1].trim();
                if let Some(e) = p.strip_prefix("push(").and_then(|s| s.strip_suffix(");")) {
                    args.push(e.to_string());
                    j -= 1;
                } else {
                    break;
                }
            }
            if !args.is_empty() {
                let indent: String =
                    result[i].chars().take_while(|c| c.is_whitespace()).collect();
                result[i] = format!("{indent}{name}({});", args.join(", "));
                result.drain(j..i);
                i = j;
            }
        }
        i += 1;
    }
    result
}

/// String-level wrapper over [`strip_asm_noise`] for the emitted-body text.
#[must_use]
pub fn strip_asm_noise_text(code: &str) -> String {
    let lines: Vec<String> = code.lines().map(str::to_string).collect();
    strip_asm_noise(&lines).join("\n")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod xmm_tests {
    use super::*;

    #[test]
    fn elides_pure_xmm_preservation_pair_and_decl() {
        let lines: Vec<String> = [
            "    __m128i v_40;",
            "    _mm_storeu_si128((__m128i *)&v_40, xmm6);",
            "    result = a1[2];",
            "    xmm6 = _mm_loadu_si128((__m128i *)&v_40);",
            "    return result;",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(!out.iter().any(|l| l.contains("_mm_storeu_si128")));
        assert!(!out.iter().any(|l| l.contains("_mm_loadu_si128")));
        assert!(!out.iter().any(|l| l.trim() == "__m128i v_40;"));
        assert!(out.iter().any(|l| l.contains("result = a1[2];")));
    }

    #[test]
    fn keeps_pair_when_reg_read_after_restore() {
        // xmm6 is used after the restore -> restore is real, not boilerplate.
        let lines: Vec<String> = [
            "    __m128i v_40;",
            "    _mm_storeu_si128((__m128i *)&v_40, xmm6);",
            "    xmm6 = _mm_loadu_si128((__m128i *)&v_40);",
            "    result = xmm6;",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(out.iter().any(|l| l.contains("_mm_storeu_si128")));
        assert!(out.iter().any(|l| l.contains("_mm_loadu_si128")));
    }

    #[test]
    fn keeps_pair_when_slot_referenced_elsewhere() {
        // Slot is read by real code -> not a pure preservation slot.
        let lines: Vec<String> = [
            "    __m128i v_40;",
            "    _mm_storeu_si128((__m128i *)&v_40, xmm6);",
            "    other = v_40;",
            "    xmm6 = _mm_loadu_si128((__m128i *)&v_40);",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(out.iter().any(|l| l.contains("_mm_storeu_si128")));
    }

    #[test]
    fn keeps_volatile_xmm_spill() {
        // xmm0 is volatile; a store/load through a slot may carry real data.
        let lines: Vec<String> = [
            "    __m128i v_40;",
            "    _mm_storeu_si128((__m128i *)&v_40, xmm0);",
            "    xmm0 = _mm_loadu_si128((__m128i *)&v_40);",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(out.iter().any(|l| l.contains("_mm_storeu_si128")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_frame_bookkeeping_pushpop() {
        let lines: Vec<String> = [
            "push(rbp);",
            "v3 = pop();", // non-callee-saved -> kept
            "rbx = pop();", // callee-saved -> removed
            "x = y + 1;",
            "push(rax);", // rax not callee-saved -> kept
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(!out.iter().any(|l| l.contains("push(rbp)")));
        assert!(!out.iter().any(|l| l == "rbx = pop();"));
        assert!(out.iter().any(|l| l == "v3 = pop();"));
        assert!(out.iter().any(|l| l == "push(rax);"));
        assert!(out.iter().any(|l| l == "x = y + 1;"));
    }

    #[test]
    fn strip_folds_scratch_pairs_call_args_and_noise_comments() {
        let lines: Vec<String> = [
            "push(rax);",
            "x = y + 1;",
            "rax = pop();",
            "push(0x10);",
            "push(v2);",
            "sub_401000();",
            "/* cdqe  */",
            "/* rep movsq  */",
            "[v2] = [v2] + al;",
            "push(rcx);",
            "helper(v1);",
            "rcx = pop();",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = strip_asm_noise(&lines);
        assert!(!out.iter().any(|l| l.contains("push(rax)")));
        assert!(!out.iter().any(|l| l.trim() == "rax = pop();"));
        assert!(out.iter().any(|l| l.trim() == "sub_401000(v2, 0x10);"));
        assert!(!out.iter().any(|l| l.contains("push(0x10)")));
        assert!(!out.iter().any(|l| l.contains("cdqe")));
        assert!(out.iter().any(|l| l.contains("rep movsq")));
        assert!(!out.iter().any(|l| l.contains("+ al")));
        assert!(out.iter().any(|l| l.contains("push(rcx)")));
        assert!(out.iter().any(|l| l.trim() == "rcx = pop();"));
    }

    #[test]
    fn strip_never_touches_returns() {
        // Returns must survive untouched — deleting a bare return would drop a
        // non-void function's only return.
        let lines: Vec<String> = ["x = 1;", "return;", "return v0;"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let out = strip_asm_noise(&lines);
        assert!(out.iter().any(|l| l == "return;"));
        assert!(out.iter().any(|l| l == "return v0;"));
    }

    #[test]
    fn strip_text_wrapper_roundtrips() {
        let code = "void f() {\n  push(rbp);\n  x = 1;\n}";
        let out = strip_asm_noise_text(code);
        assert!(!out.contains("push(rbp)"));
        assert!(out.contains("x = 1;"));
        assert!(out.contains("void f()"));
    }

    fn c(v: i64) -> Expr {
        Expr::Const(v)
    }
    fn v(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }

    // ── Expr basics ──────────────────────────────────────────────────────

    #[test]
    fn test_expr_add_emit() {
        let e = Expr::make_add(v("x"), c(5));
        assert!(e.emit().contains('+'));
    }

    #[test]
    fn test_expr_cast_emit() {
        let e = Expr::Cast {
            ty: "int*".into(),
            expr: Box::new(v("ptr")),
        };
        assert!(e.emit().contains("int*"));
    }

    #[test]
    fn test_expr_call_emit() {
        let e = Expr::Call {
            name: "foo".into(),
            args: vec![c(1), v("x")],
        };
        assert!(e.emit().contains("foo("));
    }

    // ── CastElimination ──────────────────────────────────────────────────

    #[test]
    fn test_cast_elim_const() {
        let mut elim = CastElimination::new();
        let e = Expr::Cast {
            ty: "int".into(),
            expr: Box::new(c(42)),
        };
        let result = elim.eliminate(e);
        assert_eq!(result, c(42));
        assert_eq!(elim.removed(), 1);
    }

    #[test]
    fn test_cast_elim_identity() {
        let mut elim = CastElimination::new();
        let inner = Expr::Cast {
            ty: "int".into(),
            expr: Box::new(v("x")),
        };
        let outer = Expr::Cast {
            ty: "int".into(),
            expr: Box::new(inner),
        };
        let result = elim.eliminate(outer);
        // Outer cast is removed because inner has same type.
        assert!(elim.removed() > 0);
        assert_eq!(
            result,
            Expr::Cast {
                ty: "int".into(),
                expr: Box::new(v("x"))
            }
        );
    }

    #[test]
    fn test_cast_elim_no_remove() {
        let mut elim = CastElimination::new();
        let e = Expr::Cast {
            ty: "uint64_t".into(),
            expr: Box::new(v("x")),
        };
        let result = elim.eliminate(e.clone());
        assert_eq!(elim.removed(), 0);
        assert_eq!(result, e);
    }

    // ── RedundantOp ──────────────────────────────────────────────────────

    #[test]
    fn test_redundant_add_zero() {
        let mut r = RedundantOp::new();
        let e = Expr::make_add(v("x"), c(0));
        assert_eq!(r.simplify(e), v("x"));
        assert_eq!(r.removed(), 1);
    }

    #[test]
    fn test_redundant_sub_self() {
        let mut r = RedundantOp::new();
        let e = Expr::make_sub(v("x"), v("x"));
        assert_eq!(r.simplify(e), c(0));
    }

    #[test]
    fn test_redundant_mul_one() {
        let mut r = RedundantOp::new();
        let e = Expr::make_mul(v("x"), c(1));
        assert_eq!(r.simplify(e), v("x"));
    }

    #[test]
    fn test_redundant_mul_zero() {
        let mut r = RedundantOp::new();
        let e = Expr::make_mul(v("x"), c(0));
        assert_eq!(r.simplify(e), c(0));
    }

    #[test]
    fn test_redundant_xor_self() {
        let mut r = RedundantOp::new();
        let e = Expr::make_bitxor(v("x"), v("x"));
        assert_eq!(r.simplify(e), c(0));
    }

    #[test]
    fn test_redundant_or_zero() {
        let mut r = RedundantOp::new();
        let e = Expr::make_bitor(v("x"), c(0));
        assert_eq!(r.simplify(e), v("x"));
    }

    #[test]
    fn test_redundant_double_neg() {
        let mut r = RedundantOp::new();
        let e = Expr::make_neg(Expr::make_neg(v("x")));
        assert_eq!(r.simplify(e), v("x"));
    }

    // ── CanonicalForm ────────────────────────────────────────────────────

    #[test]
    fn test_canonical_const_to_right() {
        let mut cf = CanonicalForm::new();
        // c(5) + v("x") → v("x") + c(5)
        let e = Expr::make_add(c(5), v("x"));
        let result = cf.canonicalise(e);
        match result {
            Expr::Binary { lhs, rhs, .. } => {
                assert!(matches!(*lhs, Expr::Var(_)));
                assert!(matches!(*rhs, Expr::Const(_)));
            }
            _ => panic!("expected binary"),
        }
        assert_eq!(cf.rewrites(), 1);
    }

    #[test]
    fn test_canonical_no_swap_var_const() {
        let mut cf = CanonicalForm::new();
        // v("x") + c(5) — already canonical
        let e = Expr::make_add(v("x"), c(5));
        let result = cf.canonicalise(e);
        assert_eq!(cf.rewrites(), 0);
        assert!(matches!(result, Expr::Binary { .. }));
    }

    // ── AssociativityRewrite ─────────────────────────────────────────────

    #[test]
    fn test_assoc_const_accumulation() {
        let mut ar = AssociativityRewrite::new();
        // (x + 3) + 4 → x + 7
        let inner = Expr::make_add(v("x"), c(3));
        let e = Expr::make_add(inner, c(4));
        let result = ar.rewrite(e);
        match result {
            Expr::Binary {
                op: BinaryOp::Add,
                rhs,
                ..
            } => {
                assert_eq!(*rhs, c(7));
            }
            _ => panic!("expected add"),
        }
        assert_eq!(ar.rewrites(), 1);
    }

    #[test]
    fn test_assoc_mul_const_accumulation() {
        let mut ar = AssociativityRewrite::new();
        // (x * 2) * 3 → x * 6
        let inner = Expr::make_mul(v("x"), c(2));
        let e = Expr::make_mul(inner, c(3));
        let result = ar.rewrite(e);
        match result {
            Expr::Binary {
                op: BinaryOp::Mul,
                rhs,
                ..
            } => {
                assert_eq!(*rhs, c(6));
            }
            _ => panic!("expected mul"),
        }
    }

    // ── DeMorganApplication ──────────────────────────────────────────────

    #[test]
    fn test_demorgan_not_and() {
        let mut dm = DeMorganApplication::new();
        let e = Expr::Unary {
            op: UnaryOp::BoolNot,
            expr: Box::new(Expr::Binary {
                op: BinaryOp::BoolAnd,
                lhs: Box::new(v("a")),
                rhs: Box::new(v("b")),
            }),
        };
        let result = dm.apply(e);
        assert!(matches!(
            result,
            Expr::Binary {
                op: BinaryOp::BoolOr,
                ..
            }
        ));
        assert_eq!(dm.applied(), 1);
    }

    #[test]
    fn test_demorgan_not_or() {
        let mut dm = DeMorganApplication::new();
        let e = Expr::Unary {
            op: UnaryOp::BoolNot,
            expr: Box::new(Expr::Binary {
                op: BinaryOp::BoolOr,
                lhs: Box::new(v("a")),
                rhs: Box::new(v("b")),
            }),
        };
        let result = dm.apply(e);
        assert!(matches!(
            result,
            Expr::Binary {
                op: BinaryOp::BoolAnd,
                ..
            }
        ));
    }

    #[test]
    fn test_demorgan_double_not() {
        let mut dm = DeMorganApplication::new();
        let e = Expr::Unary {
            op: UnaryOp::BoolNot,
            expr: Box::new(Expr::Unary {
                op: UnaryOp::BoolNot,
                expr: Box::new(v("x")),
            }),
        };
        assert_eq!(dm.apply(e), v("x"));
    }

    // ── PointerArithmetic ────────────────────────────────────────────────

    #[test]
    fn test_ptr_deref_plus_zero() {
        let mut pa = PointerArithmetic::new();
        let e = Expr::Deref(Box::new(Expr::make_add(v("ptr"), c(0))));
        let result = pa.simplify(e);
        assert!(matches!(result, Expr::Deref(_)));
        assert_eq!(pa.simplified(), 1);
    }

    #[test]
    fn test_ptr_index_zero() {
        let mut pa = PointerArithmetic::new();
        let e = Expr::Index {
            base: Box::new(v("arr")),
            index: Box::new(c(0)),
        };
        let result = pa.simplify(e);
        assert!(matches!(result, Expr::Deref(_)));
        assert_eq!(pa.simplified(), 1);
    }

    #[test]
    fn test_ptr_index_nonzero_kept() {
        let mut pa = PointerArithmetic::new();
        let e = Expr::Index {
            base: Box::new(v("arr")),
            index: Box::new(c(3)),
        };
        let result = pa.simplify(e);
        assert!(matches!(result, Expr::Index { .. }));
        assert_eq!(pa.simplified(), 0);
    }

    // ── ExpressionCleanup ────────────────────────────────────────────────

    #[test]
    fn test_cleanup_run_combined() {
        let mut ec = ExpressionCleanup::new();
        // (x + 0) * 1 → x
        let e = Expr::make_mul(Expr::make_add(v("x"), c(0)), c(1));
        let result = ec.run(e);
        assert_eq!(result, v("x"));
    }

    #[test]
    fn test_cleanup_summary() {
        let ec = ExpressionCleanup::new();
        let s = ec.summary();
        assert!(s.contains("cast_elim="));
    }

    #[test]
    fn test_cleanup_display() {
        let ec = ExpressionCleanup::new();
        assert!(ec.to_string().contains("ExpressionCleanup"));
    }

    #[test]
    fn test_redundant_and_all_ones() {
        let mut r = RedundantOp::new();
        let e = Expr::make_bitand(v("x"), c(-1));
        assert_eq!(r.simplify(e), v("x"));
    }

    #[test]
    fn test_cleanup_cast_then_redundant() {
        let mut ec = ExpressionCleanup::new();
        let e = Expr::make_add(
            Expr::Cast {
                ty: "int".into(),
                expr: Box::new(c(3)),
            },
            c(4),
        );
        let result = ec.run(e);
        // Cast is eliminated to c(3), then 3 + 4 is constant (handled by further
        // passes if needed) — at minimum it should not contain a Cast node.
        fn has_cast(e: &Expr) -> bool {
            match e {
                Expr::Cast { .. } => true,
                Expr::Binary { lhs, rhs, .. } => has_cast(lhs) || has_cast(rhs),
                _ => false,
            }
        }
        assert!(!has_cast(&result));
    }
}
