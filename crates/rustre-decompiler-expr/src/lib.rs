//! `rustre-decompiler-expr`
//!
//! Expression reconstruction from SSA-like intermediate form.
//!
//! # Key components
//!
//! * [`Expr`] — an expression tree with typed leaves (constants, variables,
//!   binary/unary ops, calls, memory accesses …).
//! * [`ExprFolder`] — collapses single-use temporaries into their use sites,
//!   reducing the number of variables in the output.
//! * [`ExprSimplifier`] — algebraic simplification: constant folding, identity
//!   elimination, double-negation removal, etc.
//! * [`DefUseChain`] — tracks definition and use counts per variable so the
//!   folder knows what is safe to inline.
//! * [`ExprNormalizer`] — brings expressions into a canonical form so structural
//!   comparison is reliable (e.g. commutative operand sorting, redundant-cast
//!   removal).
//! * [`ExprPrinter`] — emits a C-like string representation of an expression tree.
//! * [`ExprComparator`] — structural / semantic comparison utilities.
//! * [`ExprPattern`] — pattern matching helpers for rewrite rules.
//! * [`peephole_optimizer`] — 40+ targeted peephole rewrite rules.

pub mod casts;
pub mod dag_simplifier;
pub mod expr_precedence;
pub mod expr_reconstruction;
pub mod expr_simplification;
pub mod expression_recovery;
pub mod pattern_library;
pub mod peephole_optimizer;
pub mod expr_simplifier;
pub mod expr_type_propagator;
pub mod expr_pattern_matcher;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Cast helpers — deliberate truncation/sign boundaries (isolated so clippy
// pedantic cast lints stop emitting at every call site)
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
pub(crate) fn shift_amount(b: i64) -> u32 {
    // b & 63 is always 0..=63; fits in u32 — deliberate bit extraction
    u32::try_from((b & 63).cast_unsigned()).unwrap_or(0)
}

#[inline]
pub(crate) const fn i64_as_u64(v: i64) -> u64 {
    v.cast_unsigned()
}

#[inline]
pub(crate) const fn u64_as_i64(v: u64) -> i64 {
    v.cast_signed()
}

#[inline]
pub(crate) fn i64_trunc_u32(v: i64) -> u32 {
    // Deliberate low-32-bit extraction
    u32::try_from(v.cast_unsigned() & u64::from(u32::MAX)).unwrap_or(0)
}

#[inline]
pub(crate) fn i64_trunc_i8(v: i64) -> i8 {
    i8::from_ne_bytes([u8::try_from(v & 0xFF).unwrap_or(0)])
}
#[inline]
pub(crate) fn i64_trunc_i16(v: i64) -> i16 {
    i16::from_ne_bytes(u16::try_from(v & 0xFFFF).unwrap_or(0).to_ne_bytes())
}
#[inline]
pub(crate) fn i64_trunc_i32(v: i64) -> i32 {
    i32::from_ne_bytes(
        u32::try_from(v.cast_unsigned() & u64::from(u32::MAX))
            .unwrap_or(0)
            .to_ne_bytes(),
    )
}
#[inline]
pub(crate) fn i64_trunc_u8(v: i64) -> u8 {
    u8::try_from(v & 0xFF).unwrap_or(0)
}
#[inline]
pub(crate) fn i64_trunc_u16(v: i64) -> u16 {
    u16::try_from(v & 0xFFFF).unwrap_or(0)
}

#[inline]
pub(crate) fn u128_trunc_u64(v: u128) -> u64 {
    u64::try_from(v & u128::from(u64::MAX)).unwrap_or(0)
}

#[inline]
pub(crate) fn usize_as_f64(v: usize) -> f64 {
    // Cap at u32::MAX via try_from (no lossy cast) so the final f64::from
    // conversion is always lossless (u32::MAX = 2^32-1 < 2^52).
    f64::from(u32::try_from(v).unwrap_or(u32::MAX))
}

#[inline]
pub(crate) fn u32_trunc_u8(v: u32) -> u8 {
    u8::try_from(v & 0xFF_u32).unwrap_or(0)
}

#[inline]
pub(crate) fn usize_trunc_u32(v: usize) -> u32 {
    u32::try_from(v & 0xFFFF_FFFFusize).unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression tree
// ─────────────────────────────────────────────────────────────────────────────

/// Width of an integer operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntWidth {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
}

impl IntWidth {
    /// Return the bit-width of this integer type.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::I8 | Self::U8 => 8,
            Self::I16 | Self::U16 => 16,
            Self::I32 | Self::U32 => 32,
            Self::I64 | Self::U64 => 64,
        }
    }

    /// Return the byte-width of this integer type.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bits() / 8
    }

    /// Is this a signed integer type?
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }

    /// Return the unsigned counterpart.
    #[must_use]
    pub const fn to_unsigned(self) -> Self {
        match self {
            Self::I8 => Self::U8,
            Self::I16 => Self::U16,
            Self::I32 => Self::U32,
            Self::I64 => Self::U64,
            other => other,
        }
    }

    /// Return the signed counterpart.
    #[must_use]
    pub const fn to_signed(self) -> Self {
        match self {
            Self::U8 => Self::I8,
            Self::U16 => Self::I16,
            Self::U32 => Self::I32,
            Self::U64 => Self::I64,
            other => other,
        }
    }

    /// Maximum value that fits in this type (as a positive i64).
    ///
    /// Note: for `U64` this returns `i64::MAX` because u64's true maximum
    /// (18446744073709551615) is not representable as `i64`. Use
    /// [`max_value_u64`](Self::max_value_u64) when you need the exact value.
    #[must_use]
    pub fn max_value(self) -> i64 {
        match self {
            Self::I8 => i64::from(i8::MAX),
            Self::I16 => i64::from(i16::MAX),
            Self::I32 => i64::from(i32::MAX),
            Self::I64 | Self::U64 => i64::MAX, // U64 clamped — use max_value_u64() for the exact value
            Self::U8 => i64::from(u8::MAX),
            Self::U16 => i64::from(u16::MAX),
            Self::U32 => i64::from(u32::MAX),
        }
    }

    /// Maximum value that fits in this type as a `u64`.
    ///
    /// Unlike [`max_value`](Self::max_value), this correctly returns
    /// `u64::MAX` for `U64` instead of clamping to `i64::MAX`.
    #[must_use]
    pub fn max_value_u64(self) -> u64 {
        match self {
            Self::I8 => i8::MAX as u64,
            Self::I16 => i16::MAX as u64,
            Self::I32 => i32::MAX as u64,
            Self::I64 => i64::MAX as u64,
            Self::U8 => u64::from(u8::MAX),
            Self::U16 => u64::from(u16::MAX),
            Self::U32 => u64::from(u32::MAX),
            Self::U64 => u64::MAX,
        }
    }

    /// Minimum value that fits in this type.
    #[must_use]
    pub fn min_value(self) -> i64 {
        match self {
            Self::I8 => i64::from(i8::MIN),
            Self::I16 => i64::from(i16::MIN),
            Self::I32 => i64::from(i32::MIN),
            Self::I64 => i64::MIN,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 => 0,
        }
    }
}

impl fmt::Display for IntWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", int_width_cname(*self))
    }
}

/// Binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOp {
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
    Sar,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LAnd,
    LOr,
}

impl BinOp {
    /// C-like operator string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Sar => "a>>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::LAnd => "&&",
            Self::LOr => "||",
        }
    }

    /// Is this a comparison operator (result is boolean)?
    #[must_use]
    pub const fn is_comparison(self) -> bool {
        matches!(
            self,
            Self::Eq | Self::Ne | Self::Lt | Self::Le | Self::Gt | Self::Ge
        )
    }

    /// Is this a commutative operator?
    #[must_use]
    pub const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor | Self::Eq | Self::Ne
        )
    }

    /// Is this an arithmetic operator?
    #[must_use]
    pub const fn is_arithmetic(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod
        )
    }

    /// Is this a bitwise operator?
    #[must_use]
    pub const fn is_bitwise(self) -> bool {
        matches!(
            self,
            Self::And | Self::Or | Self::Xor | Self::Shl | Self::Shr | Self::Sar
        )
    }

    /// Is this a logical (boolean) operator?
    #[must_use]
    pub const fn is_logical(self) -> bool {
        matches!(self, Self::LAnd | Self::LOr)
    }

    /// Return the operator with swapped operands (for canonicalisation of
    /// non-commutative comparisons). `None` if no swap is meaningful.
    #[must_use]
    pub const fn swapped(self) -> Option<Self> {
        Some(match self {
            Self::Lt => Self::Gt,
            Self::Le => Self::Ge,
            Self::Gt => Self::Lt,
            Self::Ge => Self::Le,
            _ => return None,
        })
    }

    /// Return the logical negation of a comparison, e.g. `Eq → Ne`.
    #[must_use]
    pub const fn negated(self) -> Option<Self> {
        Some(match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
            _ => return None,
        })
    }

    /// Operator precedence (higher = binds tighter).
    #[must_use]
    pub const fn precedence(self) -> u8 {
        match self {
            Self::LOr => 1,
            Self::LAnd => 2,
            Self::Or => 3,
            Self::Xor => 4,
            Self::And => 5,
            Self::Eq | Self::Ne => 6,
            Self::Lt | Self::Le | Self::Gt | Self::Ge => 7,
            Self::Shl | Self::Shr | Self::Sar => 8,
            Self::Add | Self::Sub => 9,
            Self::Mul | Self::Div | Self::Mod => 10,
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    LNot,
    Deref,
    AddrOf,
    Cast(IntWidth),
}

impl UnOp {
    /// Return the C representation of this unary operator.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Neg => "-".to_string(),
            Self::Not => "~".to_string(),
            Self::LNot => "!".to_string(),
            Self::Deref => "*".to_string(),
            Self::AddrOf => "&".to_string(),
            Self::Cast(w) => format!("({})", int_width_cname(*w)),
        }
    }
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Map an [`IntWidth`] to a C type name string.
#[must_use] 
pub const fn int_width_cname(w: IntWidth) -> &'static str {
    match w {
        IntWidth::I8 => "int8_t",
        IntWidth::I16 => "int16_t",
        IntWidth::I32 => "int32_t",
        IntWidth::I64 => "int64_t",
        IntWidth::U8 => "uint8_t",
        IntWidth::U16 => "uint16_t",
        IntWidth::U32 => "uint32_t",
        IntWidth::U64 => "uint64_t",
    }
}

/// The expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    /// Integer constant.
    Const(i64, IntWidth),
    /// Variable reference (SSA name or renamed var).
    Var(String),
    /// Binary operation.
    BinOp(BinOp, Box<Self>, Box<Self>),
    /// Unary operation.
    UnOp(UnOp, Box<Self>),
    /// Function/intrinsic call.
    Call { callee: Box<Self>, args: Vec<Self> },
    /// Memory load: `*ptr` with an optional byte size.
    Load { ptr: Box<Self>, size: u8 },
    /// Conditional expression `cond ? t : f`.
    Ternary {
        cond: Box<Self>,
        then_expr: Box<Self>,
        else_expr: Box<Self>,
    },
    /// Field access via offset (pre-type-recovery).
    FieldAccess { base: Box<Self>, offset: u64 },
    /// Array / indexed access.
    Index {
        base: Box<Self>,
        index: Box<Self>,
        elem_size: u32,
    },
    /// A phi-node (should be eliminated before expression folding).
    Phi(Vec<Self>),
}

impl Expr {
    /// Returns `true` if this expression is a simple constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_, _))
    }

    /// Returns `true` if this expression is a variable reference.
    #[must_use]
    pub const fn is_var(&self) -> bool {
        matches!(self, Self::Var(_))
    }

    /// Returns `true` if this expression is a binary operation.
    #[must_use]
    pub const fn is_binop(&self) -> bool {
        matches!(self, Self::BinOp(_, _, _))
    }

    /// Returns `true` if this is a leaf (const or var).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        matches!(self, Self::Const(_, _) | Self::Var(_))
    }

    /// Returns `true` if this is a zero constant.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        matches!(self, Self::Const(0, _))
    }

    /// Returns `true` if this is a one constant.
    #[must_use]
    pub const fn is_one(&self) -> bool {
        matches!(self, Self::Const(1, _))
    }

    /// Returns the constant value if this is `Expr::Const`.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(v, _) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Returns the integer width if this is `Expr::Const`.
    #[must_use]
    pub const fn const_width(&self) -> Option<IntWidth> {
        if let Self::Const(_, w) = self {
            Some(*w)
        } else {
            None
        }
    }

    /// Returns the variable name if this is `Expr::Var`.
    #[must_use]
    pub const fn as_var(&self) -> Option<&str> {
        if let Self::Var(n) = self {
            Some(n.as_str())
        } else {
            None
        }
    }

    /// Structural depth (for heuristic inlining cost).
    ///
    /// Recursion is capped at 512 levels to prevent stack overflow on
    /// attacker-supplied deeply-nested expressions deserialized from binary
    /// input (dos-unbounded-recursion).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth_inner(0)
    }

    fn depth_inner(&self, cur_depth: usize) -> usize {
        const MAX_DEPTH: usize = 512;
        if cur_depth >= MAX_DEPTH {
            return cur_depth;
        }
        match self {
            Self::Const(_, _) | Self::Var(_) => cur_depth + 1,
            Self::UnOp(_, e) | Self::Load { ptr: e, .. } => e.depth_inner(cur_depth + 1),
            Self::BinOp(_, a, b) => {
                a.depth_inner(cur_depth + 1).max(b.depth_inner(cur_depth + 1))
            }
            Self::FieldAccess { base, .. } => base.depth_inner(cur_depth + 1),
            Self::Index { base, index, .. } => {
                base.depth_inner(cur_depth + 1).max(index.depth_inner(cur_depth + 1))
            }
            Self::Call { callee, args } => {
                let callee_d = callee.depth_inner(cur_depth + 1);
                args.iter()
                    .map(|a| a.depth_inner(cur_depth + 1))
                    .max()
                    .unwrap_or(cur_depth + 1)
                    .max(callee_d)
            }
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => cond
                .depth_inner(cur_depth + 1)
                .max(then_expr.depth_inner(cur_depth + 1))
                .max(else_expr.depth_inner(cur_depth + 1)),
            Self::Phi(exprs) => exprs
                .iter()
                .map(|e| e.depth_inner(cur_depth + 1))
                .max()
                .unwrap_or(cur_depth + 1),
        }
    }

    /// Count the total number of AST nodes.
    ///
    /// Recursion is capped at 512 levels to prevent stack overflow on
    /// attacker-supplied deeply-nested expressions (dos-unbounded-recursion).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.node_count_inner(0)
    }

    fn node_count_inner(&self, depth: usize) -> usize {
        const MAX_DEPTH: usize = 512;
        if depth >= MAX_DEPTH {
            return 1;
        }
        match self {
            Self::Const(_, _) | Self::Var(_) => 1,
            Self::UnOp(_, e) | Self::Load { ptr: e, .. } => 1 + e.node_count_inner(depth + 1),
            Self::BinOp(_, a, b) => {
                1 + a.node_count_inner(depth + 1) + b.node_count_inner(depth + 1)
            }
            Self::FieldAccess { base, .. } => 1 + base.node_count_inner(depth + 1),
            Self::Index { base, index, .. } => {
                1 + base.node_count_inner(depth + 1) + index.node_count_inner(depth + 1)
            }
            Self::Call { callee, args } => {
                1 + callee.node_count_inner(depth + 1)
                    + args
                        .iter()
                        .map(|a| a.node_count_inner(depth + 1))
                        .sum::<usize>()
            }
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                1 + cond.node_count_inner(depth + 1)
                    + then_expr.node_count_inner(depth + 1)
                    + else_expr.node_count_inner(depth + 1)
            }
            Self::Phi(exprs) => {
                1 + exprs
                    .iter()
                    .map(|e| e.node_count_inner(depth + 1))
                    .sum::<usize>()
            }
        }
    }

    /// Collect all variable names referenced by this expression.
    #[must_use]
    pub fn referenced_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        self.collect_vars(&mut vars);
        vars
    }

    fn collect_vars(&self, acc: &mut Vec<String>) {
        self.collect_vars_depth(acc, 0);
    }

    fn collect_vars_depth(&self, acc: &mut Vec<String>, depth: usize) {
        const MAX_DEPTH: usize = 512;
        if depth >= MAX_DEPTH {
            return;
        }
        match self {
            Self::Var(n) => acc.push(n.clone()),
            Self::Const(_, _) => {}
            Self::BinOp(_, a, b) => {
                a.collect_vars_depth(acc, depth + 1);
                b.collect_vars_depth(acc, depth + 1);
            }
            Self::UnOp(_, e) | Self::Load { ptr: e, .. } => e.collect_vars_depth(acc, depth + 1),
            Self::FieldAccess { base, .. } => base.collect_vars_depth(acc, depth + 1),
            Self::Index { base, index, .. } => {
                base.collect_vars_depth(acc, depth + 1);
                index.collect_vars_depth(acc, depth + 1);
            }
            Self::Call { callee, args } => {
                callee.collect_vars_depth(acc, depth + 1);
                for a in args {
                    a.collect_vars_depth(acc, depth + 1);
                }
            }
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                cond.collect_vars_depth(acc, depth + 1);
                then_expr.collect_vars_depth(acc, depth + 1);
                else_expr.collect_vars_depth(acc, depth + 1);
            }
            Self::Phi(exprs) => {
                for e in exprs {
                    e.collect_vars_depth(acc, depth + 1);
                }
            }
        }
    }

    /// Apply a substitution: replace all occurrences of `var` with `replacement`.
    #[must_use]
    pub fn substitute(self, var: &str, replacement: &Self) -> Self {
        match self {
            Self::Var(ref n) if n == var => replacement.clone(),
            Self::BinOp(op, a, b) => Self::BinOp(
                op,
                Box::new(a.substitute(var, replacement)),
                Box::new(b.substitute(var, replacement)),
            ),
            Self::UnOp(op, e) => Self::UnOp(op, Box::new(e.substitute(var, replacement))),
            Self::Load { ptr, size } => Self::Load {
                ptr: Box::new(ptr.substitute(var, replacement)),
                size,
            },
            Self::FieldAccess { base, offset } => Self::FieldAccess {
                base: Box::new(base.substitute(var, replacement)),
                offset,
            },
            Self::Index {
                base,
                index,
                elem_size,
            } => Self::Index {
                base: Box::new(base.substitute(var, replacement)),
                index: Box::new(index.substitute(var, replacement)),
                elem_size,
            },
            Self::Call { callee, args } => Self::Call {
                callee: Box::new(callee.substitute(var, replacement)),
                args: args
                    .into_iter()
                    .map(|a| a.substitute(var, replacement))
                    .collect(),
            },
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Self::Ternary {
                cond: Box::new(cond.substitute(var, replacement)),
                then_expr: Box::new(then_expr.substitute(var, replacement)),
                else_expr: Box::new(else_expr.substitute(var, replacement)),
            },
            Self::Phi(exprs) => Self::Phi(
                exprs
                    .into_iter()
                    .map(|e| e.substitute(var, replacement))
                    .collect(),
            ),
            other => other,
        }
    }

    /// Returns `true` if `var` appears anywhere in this expression.
    #[must_use]
    pub fn contains_var(&self, var: &str) -> bool {
        self.referenced_vars().iter().any(|v| v == var)
    }

    /// Returns `true` if this expression has no variable references.
    #[must_use]
    pub fn is_constant_expr(&self) -> bool {
        self.referenced_vars().is_empty()
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printer = ExprPrinter::default();
        write!(f, "{}", printer.print(self))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA assignment
// ─────────────────────────────────────────────────────────────────────────────

/// A single SSA assignment `name = expr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsaAssign {
    pub name: String,
    pub expr: Expr,
}

impl SsaAssign {
    /// Create a new SSA assignment.
    #[must_use]
    pub fn new(name: impl Into<String>, expr: Expr) -> Self {
        Self {
            name: name.into(),
            expr,
        }
    }

    /// Return the number of variables referenced in the RHS.
    #[must_use]
    pub fn rhs_var_count(&self) -> usize {
        self.expr.referenced_vars().len()
    }
}

impl fmt::Display for SsaAssign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.expr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Def-use chain
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks how many times each SSA variable is defined and used.
#[derive(Debug, Default, Clone)]
pub struct DefUseChain {
    pub def_count: HashMap<String, usize>,
    pub use_count: HashMap<String, usize>,
    pub def_expr: HashMap<String, Expr>,
}

impl DefUseChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a def-use chain from a list of assignments.
    #[must_use]
    pub fn from_assignments(assigns: &[SsaAssign]) -> Self {
        let mut chain = Self::new();
        for a in assigns {
            *chain.def_count.entry(a.name.clone()).or_insert(0) += 1;
            chain.def_expr.insert(a.name.clone(), a.expr.clone());
            for v in a.expr.referenced_vars() {
                *chain.use_count.entry(v).or_insert(0) += 1;
            }
        }
        chain
    }

    /// How many times is `name` defined?
    #[must_use]
    pub fn def_count(&self, name: &str) -> usize {
        self.def_count.get(name).copied().unwrap_or(0)
    }

    /// How many times is `name` used?
    #[must_use]
    pub fn use_count(&self, name: &str) -> usize {
        self.use_count.get(name).copied().unwrap_or(0)
    }

    /// Is `name` dead (defined but never used)?
    #[must_use]
    pub fn is_dead(&self, name: &str) -> bool {
        self.def_count(name) > 0 && self.use_count(name) == 0
    }

    /// Is `name` a single-def single-use variable?
    #[must_use]
    pub fn is_single_def_use(&self, name: &str) -> bool {
        self.def_count(name) == 1 && self.use_count(name) == 1
    }

    /// Return all dead variables.
    #[must_use]
    pub fn dead_vars(&self) -> Vec<&str> {
        self.def_count
            .keys()
            .filter(|k| self.is_dead(k))
            .map(String::as_str)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Side-effect / safety helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `expr` has observable side-effects (calls, stores …).
#[must_use]
pub fn has_side_effects(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_, _) | Expr::Var(_) | Expr::Phi(_) => false,
        Expr::BinOp(_, a, b) => has_side_effects(a) || has_side_effects(b),
        Expr::UnOp(_, e) => has_side_effects(e),
        Expr::Load { .. } | Expr::Call { .. } => true,
        Expr::FieldAccess { base, .. } => has_side_effects(base),
        Expr::Index { base, index, .. } => has_side_effects(base) || has_side_effects(index),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => has_side_effects(cond) || has_side_effects(then_expr) || has_side_effects(else_expr),
    }
}

/// Returns `true` if it is safe to inline `expr` at a use site without
/// changing program semantics.
#[must_use]
pub fn is_safe_to_inline(expr: &Expr, name: &str, chain: &DefUseChain) -> bool {
    if chain.def_count(name) != 1 {
        return false;
    }
    let uses = chain.use_count(name);
    if uses == 0 {
        return true;
    }
    if uses == 1 {
        return true;
    }
    !has_side_effects(expr) && expr.depth() <= 3
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprFolder — inline single-use temporaries
// ─────────────────────────────────────────────────────────────────────────────

/// Error type for expression operations.
#[derive(Debug, Error)]
pub enum ExprError {
    #[error("undefined variable '{0}'")]
    UndefinedVar(String),
    #[error("phi node not eliminated before folding")]
    PhiNotEliminated,
    #[error("empty expression list")]
    EmptyList,
    #[error("expression depth limit exceeded")]
    DepthLimitExceeded,
    #[error("division by zero")]
    DivisionByZero,
}

/// Folds (inlines) single-use temporaries into their use sites, reducing the
/// number of intermediate variables.
#[derive(Debug, Default)]
pub struct ExprFolder {
    chain: DefUseChain,
}

impl ExprFolder {
    /// Create a new empty folder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute def-use information from `assigns` and prepare for folding.
    #[must_use]
    pub fn with_assignments(assigns: &[SsaAssign]) -> Self {
        Self {
            chain: DefUseChain::from_assignments(assigns),
        }
    }

    /// Fold all assignments.
    ///
    /// Runs multiple passes until a fixed point is reached so that inlined
    /// variables whose definitions themselves contain inlineable temporaries
    /// are fully substituted (avoiding dangling `Var` references in the
    /// output).
    ///
    /// # Errors
    ///
    /// Returns `ExprError::PhiNotEliminated` if a phi node is encountered.
    pub fn fold_expressions(&self, assigns: &[SsaAssign]) -> Result<Vec<SsaAssign>, ExprError> {
        let mut current: Vec<SsaAssign> = assigns.to_vec();
        loop {
            let mut next = Vec::with_capacity(current.len());
            // Rebuild def-use chain from the current iteration's assignments so
            // that use/def counts reflect the state after previous inlining passes.
            let iter_chain = DefUseChain::from_assignments(&current);
            let iter_folder = Self { chain: iter_chain };
            for a in &current {
                if matches!(a.expr, Expr::Phi(_)) {
                    return Err(ExprError::PhiNotEliminated);
                }
                let use_count = iter_folder.chain.use_count(&a.name);
                if use_count == 1
                    && iter_folder.chain.def_count(&a.name) == 1
                    && is_safe_to_inline(&a.expr, &a.name, &iter_folder.chain)
                {
                    continue;
                }
                let folded_expr = iter_folder.fold_expr(a.expr.clone())?;
                next.push(SsaAssign::new(a.name.clone(), folded_expr));
            }
            if next.len() == current.len() {
                // No assignment was eliminated in this pass — fixed point reached.
                return Ok(next);
            }
            current = next;
        }
    }

    /// Fold a single expression, substituting inlineable variable refs.
    ///
    /// # Errors
    ///
    /// Returns `ExprError::PhiNotEliminated` for phi nodes.
    /// Returns `ExprError::DepthLimitExceeded` when inlining loops (self-referential defs).
    pub fn fold_expr(&self, expr: Expr) -> Result<Expr, ExprError> {
        self.fold_expr_depth(expr, 0)
    }

    fn fold_expr_depth(&self, expr: Expr, depth: usize) -> Result<Expr, ExprError> {
        if depth > 256 {
            return Err(ExprError::DepthLimitExceeded);
        }
        match expr {
            Expr::Var(ref name) => {
                if let Some(def) = self.chain.def_expr.get(name)
                    && is_safe_to_inline(def, name, &self.chain) {
                        return self.fold_expr_depth(def.clone(), depth + 1);
                    }
                Ok(expr)
            }
            Expr::BinOp(op, a, b) => Ok(Expr::BinOp(
                op,
                Box::new(self.fold_expr_depth(*a, depth + 1)?),
                Box::new(self.fold_expr_depth(*b, depth + 1)?),
            )),
            Expr::UnOp(op, e) => Ok(Expr::UnOp(op, Box::new(self.fold_expr_depth(*e, depth + 1)?))),
            Expr::Load { ptr, size } => Ok(Expr::Load {
                ptr: Box::new(self.fold_expr_depth(*ptr, depth + 1)?),
                size,
            }),
            Expr::FieldAccess { base, offset } => Ok(Expr::FieldAccess {
                base: Box::new(self.fold_expr_depth(*base, depth + 1)?),
                offset,
            }),
            Expr::Index {
                base,
                index,
                elem_size,
            } => Ok(Expr::Index {
                base: Box::new(self.fold_expr_depth(*base, depth + 1)?),
                index: Box::new(self.fold_expr_depth(*index, depth + 1)?),
                elem_size,
            }),
            Expr::Call { callee, args } => {
                let folded_callee = self.fold_expr_depth(*callee, depth + 1)?;
                let d = depth + 1;
                let folded_args: Result<Vec<_>, _> =
                    args.into_iter().map(|a| self.fold_expr_depth(a, d)).collect();
                Ok(Expr::Call {
                    callee: Box::new(folded_callee),
                    args: folded_args?,
                })
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Ok(Expr::Ternary {
                cond: Box::new(self.fold_expr_depth(*cond, depth + 1)?),
                then_expr: Box::new(self.fold_expr_depth(*then_expr, depth + 1)?),
                else_expr: Box::new(self.fold_expr_depth(*else_expr, depth + 1)?),
            }),
            Expr::Phi(_) => Err(ExprError::PhiNotEliminated),
            Expr::Const(_, _) => Ok(expr),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// simplify_binop helpers (free functions to keep ExprSimplifier methods short)
// ─────────────────────────────────────────────────────────────────────────────

/// Identity / annihilator rules for arithmetic and bitwise operators.
/// Returns `Ok(simplified)` if a rule matched, or `Err((a, b))` to return ownership.
fn simplify_binop_arith_bitwise(op: BinOp, a: Expr, b: Expr) -> Result<Expr, (Expr, Expr)> {
    match op {
        BinOp::Add => {
            if b.as_const() == Some(0) { return Ok(a); }
            if a.as_const() == Some(0) { return Ok(b); }
        }
        BinOp::Sub => {
            if b.as_const() == Some(0) { return Ok(a); }
            if a == b && !has_side_effects(&a) {
                return Ok(Expr::Const(0, IntWidth::I64));
            }
        }
        BinOp::Mul => {
            if (b.as_const() == Some(0) && !has_side_effects(&a))
                || (a.as_const() == Some(0) && !has_side_effects(&b))
            {
                return Ok(Expr::Const(0, IntWidth::I64));
            }
            if b.as_const() == Some(1) { return Ok(a); }
            if a.as_const() == Some(1) { return Ok(b); }
        }
        BinOp::Div => {
            if b.as_const() == Some(1) { return Ok(a); }
            if a == b && !has_side_effects(&a) {
                return Ok(Expr::Const(1, IntWidth::I64));
            }
        }
        BinOp::Mod => {
            if b.as_const() == Some(1) { return Ok(Expr::Const(0, IntWidth::I64)); }
            if a == b && !has_side_effects(&a) {
                return Ok(Expr::Const(0, IntWidth::I64));
            }
        }
        BinOp::And => {
            if (a.as_const() == Some(0) && !has_side_effects(&b))
                || (b.as_const() == Some(0) && !has_side_effects(&a))
            {
                return Ok(Expr::Const(0, IntWidth::I64));
            }
            if a.as_const() == Some(-1) { return Ok(b); }
            if b.as_const() == Some(-1) { return Ok(a); }
            if a == b && !has_side_effects(&a) { return Ok(a); }
        }
        BinOp::Or => {
            if a.as_const() == Some(0) { return Ok(b); }
            if b.as_const() == Some(0) { return Ok(a); }
            if a.as_const() == Some(-1) || b.as_const() == Some(-1) {
                return Ok(Expr::Const(-1, IntWidth::I64));
            }
            if a == b && !has_side_effects(&a) { return Ok(a); }
        }
        BinOp::Xor => {
            if a.as_const() == Some(0) { return Ok(b); }
            if b.as_const() == Some(0) { return Ok(a); }
            if a == b && !has_side_effects(&a) {
                return Ok(Expr::Const(0, IntWidth::I64));
            }
            if b.as_const() == Some(-1) {
                return Ok(Expr::UnOp(UnOp::Not, Box::new(a)));
            }
        }
        _ => {}
    }
    Err((a, b))
}

/// Identity / annihilator rules for shift, comparison, and logical operators.
/// Returns `Ok(simplified)` if a rule matched, or `Err((a, b))` to return ownership.
fn simplify_binop_shift_cmp_logic(op: BinOp, a: Expr, b: Expr) -> Result<Expr, (Expr, Expr)> {
    match op {
        BinOp::Shl | BinOp::Shr | BinOp::Sar => {
            if b.as_const() == Some(0) { return Ok(a); }
            if a.as_const() == Some(0) { return Ok(Expr::Const(0, IntWidth::I64)); }
        }
        BinOp::Eq => {
            if a == b { return Ok(Expr::Const(1, IntWidth::I32)); }
        }
        BinOp::Ne => {
            if a == b { return Ok(Expr::Const(0, IntWidth::I32)); }
        }
        BinOp::LAnd => {
            if a.as_const() == Some(0) || b.as_const() == Some(0) {
                return Ok(Expr::Const(0, IntWidth::I32));
            }
            if a.as_const().is_some_and(|v| v != 0) { return Ok(b); }
            if b.as_const().is_some_and(|v| v != 0) { return Ok(a); }
        }
        BinOp::LOr => {
            if a.as_const().is_some_and(|v| v != 0) || b.as_const().is_some_and(|v| v != 0) {
                return Ok(Expr::Const(1, IntWidth::I32));
            }
            if a.as_const() == Some(0) { return Ok(b); }
            if b.as_const() == Some(0) { return Ok(a); }
        }
        _ => {}
    }
    Err((a, b))
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprSimplifier — algebraic simplification
// ─────────────────────────────────────────────────────────────────────────────

/// Performs local algebraic simplifications on expression trees.
#[derive(Debug, Clone)]
pub struct ExprSimplifier {
    /// Apply De Morgan transformations.
    pub demorgan: bool,
    /// Maximum number of simplification passes.
    pub max_passes: usize,
    /// Whether to fold constants through casts.
    pub fold_casts: bool,
}

impl Default for ExprSimplifier {
    fn default() -> Self {
        Self {
            demorgan: true,
            max_passes: 8,
            fold_casts: true,
        }
    }
}

impl ExprSimplifier {
    /// Create a new simplifier with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a simplifier with De Morgan disabled.
    #[must_use]
    pub fn without_demorgan() -> Self {
        Self {
            demorgan: false,
            ..Self::default()
        }
    }

    /// Simplify until fixed-point or `max_passes` reached.
    #[must_use]
    pub fn simplify(&self, expr: Expr) -> Expr {
        let mut current = expr;
        for _ in 0..self.max_passes {
            let next = self.simplify_once(current.clone());
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    /// Simplify a list of SSA assignments.
    #[must_use]
    pub fn simplify_assignments(&self, assigns: Vec<SsaAssign>) -> Vec<SsaAssign> {
        assigns
            .into_iter()
            .map(|a| SsaAssign::new(a.name, self.simplify(a.expr)))
            .collect()
    }

    fn simplify_once(&self, expr: Expr) -> Expr {
        match expr {
            Expr::BinOp(op, a, b) => {
                let a = self.simplify_once(*a);
                let b = self.simplify_once(*b);
                self.simplify_binop(op, a, b)
            }
            Expr::UnOp(op, e) => {
                let e = self.simplify_once(*e);
                self.simplify_unop(op, e)
            }
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(self.simplify_once(*ptr)),
                size,
            },
            Expr::FieldAccess { base, offset } => Expr::FieldAccess {
                base: Box::new(self.simplify_once(*base)),
                offset,
            },
            Expr::Index {
                base,
                index,
                elem_size,
            } => Expr::Index {
                base: Box::new(self.simplify_once(*base)),
                index: Box::new(self.simplify_once(*index)),
                elem_size,
            },
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(self.simplify_once(*callee)),
                args: args.into_iter().map(|a| self.simplify_once(a)).collect(),
            },
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond_s = self.simplify_once(*cond);
                if let Some(v) = cond_s.as_const() {
                    if v != 0 {
                        return self.simplify_once(*then_expr);
                    }
                    return self.simplify_once(*else_expr);
                }
                Expr::Ternary {
                    cond: Box::new(cond_s),
                    then_expr: Box::new(self.simplify_once(*then_expr)),
                    else_expr: Box::new(self.simplify_once(*else_expr)),
                }
            }
            other => other,
        }
    }

    fn simplify_binop(&self, op: BinOp, a: Expr, b: Expr) -> Expr {
        // Constant folding.
        if let (Some(ca), Some(cb)) = (a.as_const(), b.as_const())
            && let Some(result) = fold_const_binop(op, ca, cb) {
                let width = a.const_width().unwrap_or(IntWidth::I64);
                return Expr::Const(result, width);
            }
        // Identity / annihilator rules — split across two helpers to stay <100 lines each.
        let (a, b) = match simplify_binop_arith_bitwise(op, a, b) {
            Ok(e) => return e,
            Err(pair) => pair,
        };
        let (a, b) = match simplify_binop_shift_cmp_logic(op, a, b) {
            Ok(e) => return e,
            Err(pair) => pair,
        };
        // De Morgan.
        if self.demorgan
            && let Some(e) = demorgan(op, &a, &b) {
                return e;
            }
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }

    fn simplify_unop(&self, op: UnOp, e: Expr) -> Expr {
        // Constant folding.
        if let Some(c) = e.as_const() {
            let width = e.const_width().unwrap_or(IntWidth::I64);
            match op {
                UnOp::Neg => return Expr::Const(c.wrapping_neg(), width),
                UnOp::Not => return Expr::Const(!c, width),
                UnOp::LNot => return Expr::Const(i64::from(c == 0), IntWidth::I32),
                UnOp::Cast(w)
                    if self.fold_casts => {
                        let bits = w.bits();
                        let truncated = if bits >= 64 {
                            c
                        } else {
                            let mask = (1i64 << bits) - 1;
                            let masked = c & mask;
                            if w.is_signed() {
                                let shift = 64 - bits;
                                (masked << shift) >> shift
                            } else {
                                masked
                            }
                        };
                        return Expr::Const(truncated, w);
                    }
                _ => {}
            }
        }

        // Double-negation / double-not.
        match (&op, &e) {
            (UnOp::Neg, Expr::UnOp(UnOp::Neg, inner))
            | (UnOp::Not, Expr::UnOp(UnOp::Not, inner))
            | (UnOp::LNot, Expr::UnOp(UnOp::LNot, inner)) => return *inner.clone(),
            // Comparison negation.
            (UnOp::LNot, Expr::BinOp(cmp_op, a, b)) => {
                if let Some(neg) = cmp_op.negated() {
                    return Expr::BinOp(neg, a.clone(), b.clone());
                }
            }
            _ => {}
        }

        Expr::UnOp(op, Box::new(e))
    }
}

fn fold_const_binop(op: BinOp, a: i64, b: i64) -> Option<i64> {
    Some(match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Div => {
            if b == 0 {
                return None;
            }
            a.wrapping_div(b)
        }
        BinOp::Mod => {
            if b == 0 {
                return None;
            }
            a.wrapping_rem(b)
        }
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => {
            if !(0..64).contains(&b) {
                return None;
            }
            a.wrapping_shl(shift_amount(b))
        }
        BinOp::Shr => {
            if !(0..64).contains(&b) {
                return None;
            }
            u64_as_i64(i64_as_u64(a).wrapping_shr(shift_amount(b)))
        }
        BinOp::Sar => {
            if !(0..64).contains(&b) {
                return None;
            }
            a.wrapping_shr(shift_amount(b))
        }
        BinOp::Eq => i64::from(a == b),
        BinOp::Ne => i64::from(a != b),
        BinOp::Lt => i64::from(a < b),
        BinOp::Le => i64::from(a <= b),
        BinOp::Gt => i64::from(a > b),
        BinOp::Ge => i64::from(a >= b),
        BinOp::LAnd => i64::from(a != 0 && b != 0),
        BinOp::LOr => i64::from(a != 0 || b != 0),
    })
}

fn demorgan(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    if op == BinOp::LOr
        && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::LNot,
                Box::new(Expr::BinOp(BinOp::LAnd, ia.clone(), ib.clone())),
            ));
        }
    if op == BinOp::LAnd
        && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::LNot,
                Box::new(Expr::BinOp(BinOp::LOr, ia.clone(), ib.clone())),
            ));
        }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprNormalizer — canonical form
// ─────────────────────────────────────────────────────────────────────────────

/// Brings expressions into canonical form for reliable structural comparison.
///
/// Normalizations applied:
/// - Sort commutative operands so constants come last (e.g. `42 + x → x + 42`).
/// - Merge double casts: `(T2)(T1)x → (T2)x` when T2 is wider or same.
/// - Canonicalize `x > y → y < x` (always use `<` / `<=`).
/// - Replace `(x != 0)` booleans with just `x` in boolean contexts.
#[derive(Debug, Default, Clone)]
pub struct ExprNormalizer;

impl ExprNormalizer {
    /// Create a new normalizer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Normalize the expression into canonical form.
    #[must_use]
    pub fn normalize(&self, expr: Expr) -> Expr {
        let mut current = expr;
        for _ in 0..4 {
            let next = Self::normalize_once(current.clone());
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn normalize_once(expr: Expr) -> Expr {
        match expr {
            Expr::BinOp(op, a, b) => {
                let a = Self::normalize_once(*a);
                let b = Self::normalize_once(*b);
                Self::normalize_binop(op, a, b)
            }
            Expr::UnOp(op, e) => {
                let e = Self::normalize_once(*e);
                Self::normalize_unop(op, e)
            }
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(Self::normalize_once(*callee)),
                args: args.into_iter().map(Self::normalize_once).collect(),
            },
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Expr::Ternary {
                cond: Box::new(Self::normalize_once(*cond)),
                then_expr: Box::new(Self::normalize_once(*then_expr)),
                else_expr: Box::new(Self::normalize_once(*else_expr)),
            },
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(Self::normalize_once(*ptr)),
                size,
            },
            Expr::FieldAccess { base, offset } => Expr::FieldAccess {
                base: Box::new(Self::normalize_once(*base)),
                offset,
            },
            Expr::Index {
                base,
                index,
                elem_size,
            } => Expr::Index {
                base: Box::new(Self::normalize_once(*base)),
                index: Box::new(Self::normalize_once(*index)),
                elem_size,
            },
            other => other,
        }
    }

    fn normalize_binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        // For commutative ops, move constants to the right.
        if op.is_commutative() && a.is_const() && !b.is_const() {
            return Expr::BinOp(op, Box::new(b), Box::new(a));
        }

        // Canonicalize `x > y → y < x`, `x >= y → y <= x`.
        match op {
            BinOp::Gt => {
                return Expr::BinOp(BinOp::Lt, Box::new(b), Box::new(a));
            }
            BinOp::Ge => {
                return Expr::BinOp(BinOp::Le, Box::new(b), Box::new(a));
            }
            _ => {}
        }

        Expr::BinOp(op, Box::new(a), Box::new(b))
    }

    fn normalize_unop(op: UnOp, e: Expr) -> Expr {
        // Merge double casts: (T2)(T1)x → (T2)x
        if let (UnOp::Cast(outer), Expr::UnOp(UnOp::Cast(_inner), inner_e)) = (&op, &e) {
            return Expr::UnOp(UnOp::Cast(*outer), inner_e.clone());
        }
        Expr::UnOp(op, Box::new(e))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprComparator — structural / semantic comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Compares two expressions for structural or semantic equivalence.
#[derive(Debug, Default)]
pub struct ExprComparator {
    normalizer: ExprNormalizer,
    simplifier: ExprSimplifier,
}

impl ExprComparator {
    /// Create a new comparator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if `a` and `b` are structurally identical after
    /// normalization and simplification.
    #[must_use]
    pub fn equivalent(&self, a: &Expr, b: &Expr) -> bool {
        let na = self
            .normalizer
            .normalize(self.simplifier.simplify(a.clone()));
        let nb = self
            .normalizer
            .normalize(self.simplifier.simplify(b.clone()));
        na == nb
    }

    /// Return `true` if `a` and `b` are syntactically identical (no
    /// simplification applied).
    #[must_use]
    pub fn syntactically_equal(&self, a: &Expr, b: &Expr) -> bool {
        a == b
    }

    /// Estimate how similar `a` and `b` are on a 0.0–1.0 scale.
    ///
    /// Uses tree-edit-distance heuristic: score = 2 * `shared_nodes` /
    /// (`nodes_a` + `nodes_b`).
    #[must_use]
    pub fn similarity(&self, a: &Expr, b: &Expr) -> f64 {
        let na = a.node_count();
        let nb = b.node_count();
        if na + nb == 0 {
            return 1.0;
        }
        let shared = Self::count_shared(a, b);
        2.0 * usize_as_f64(shared) / usize_as_f64(na + nb)
    }

    fn count_shared(a: &Expr, b: &Expr) -> usize {
        if a == b {
            return a.node_count();
        }
        match (a, b) {
            (Expr::BinOp(op_a, l_a, r_a), Expr::BinOp(op_b, l_b, r_b)) if op_a == op_b => {
                1 + Self::count_shared(l_a, l_b) + Self::count_shared(r_a, r_b)
            }
            (Expr::UnOp(op_a, e_a), Expr::UnOp(op_b, e_b)) if op_a == op_b => {
                1 + Self::count_shared(e_a, e_b)
            }
            _ => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprPrinter — C-like text representation
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the expression printer.
#[derive(Debug, Clone)]
pub struct ExprPrintOptions {
    /// Whether to parenthesize all binary operations.
    pub full_parens: bool,
    /// Whether to emit casts.
    pub emit_casts: bool,
}

impl Default for ExprPrintOptions {
    fn default() -> Self {
        Self {
            full_parens: false,
            emit_casts: true,
        }
    }
}

/// Converts an [`Expr`] tree to a C-like string.
#[derive(Debug, Default)]
pub struct ExprPrinter {
    /// Configuration.
    pub options: ExprPrintOptions,
}

impl ExprPrinter {
    /// Create a printer with default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a printer with custom options.
    #[must_use]
    pub const fn with_options(options: ExprPrintOptions) -> Self {
        Self { options }
    }

    /// Print `expr` to a string.
    #[must_use]
    pub fn print(&self, expr: &Expr) -> String {
        self.print_inner(expr, 0)
    }

    fn print_inner(&self, expr: &Expr, parent_prec: u8) -> String {
        match expr {
            Expr::Const(v, w) => Self::print_const(*v, *w),
            Expr::Var(n) => n.clone(),
            Expr::BinOp(op, a, b) => {
                let prec = op.precedence();
                let left = self.print_inner(a, prec);
                let right = self.print_inner(b, prec + 1);
                let s = format!("{left} {op} {right}");
                if self.options.full_parens || (prec < parent_prec) {
                    format!("({s})")
                } else {
                    s
                }
            }
            Expr::UnOp(op, e) => {
                let inner = self.print_inner(e, 15); // highest prec
                match op {
                    UnOp::Cast(w) => {
                        if self.options.emit_casts {
                            format!("({}){inner}", int_width_cname(*w))
                        } else {
                            inner
                        }
                    }
                    UnOp::Deref => format!("*{inner}"),
                    UnOp::AddrOf => format!("&{inner}"),
                    UnOp::Neg => format!("-{inner}"),
                    UnOp::Not => format!("~{inner}"),
                    UnOp::LNot => format!("!{inner}"),
                }
            }
            Expr::Load { ptr, size } => {
                let inner = self.print_inner(ptr, 15);
                format!("*(uint{}_t *){inner}", size * 8)
            }
            Expr::FieldAccess { base, offset } => {
                let inner = self.print_inner(base, 15);
                format!("FIELD({inner}, {offset:#x})")
            }
            Expr::Index { base, index, .. } => {
                let b = self.print_inner(base, 0);
                let i = self.print_inner(index, 0);
                format!("{b}[{i}]")
            }
            Expr::Call { callee, args } => {
                let callee_s = self.print_inner(callee, 0);
                let args_s: Vec<String> = args.iter().map(|a| self.print_inner(a, 0)).collect();
                format!("{}({})", callee_s, args_s.join(", "))
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let c = self.print_inner(cond, 0);
                let t = self.print_inner(then_expr, 0);
                let e = self.print_inner(else_expr, 0);
                format!("({c} ? {t} : {e})")
            }
            Expr::Phi(exprs) => {
                let parts: Vec<String> = exprs.iter().map(|e| self.print_inner(e, 0)).collect();
                format!("phi({})", parts.join(", "))
            }
        }
    }

    fn print_const(v: i64, w: IntWidth) -> String {
        if (-1000..1000).contains(&v) {
            return format!("{v}");
        }
        match w {
            IntWidth::U8 | IntWidth::U16 | IntWidth::U32 => format!("0x{:X}U", i64_as_u64(v)),
            IntWidth::U64 => format!("0x{:X}ULL", i64_as_u64(v)),
            IntWidth::I64 => {
                if v < 0 {
                    format!("-0x{:X}LL", v.unsigned_abs())
                } else {
                    format!("0x{v:X}LL")
                }
            }
            _ => format!("0x{v:X}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprPattern — pattern matching and rewrite rules
// ─────────────────────────────────────────────────────────────────────────────

/// Checks whether an expression matches a specific pattern, capturing sub-trees.
pub struct ExprPattern;

impl ExprPattern {
    /// Return `true` if `expr` is of the form `var op const`.
    #[must_use]
    pub fn is_binop_var_const(expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::BinOp(_, a, b)
            if matches!(a.as_ref(), Expr::Var(_)) && matches!(b.as_ref(), Expr::Const(_, _))
        )
    }

    /// Return `true` if `expr` is a comparison between two variables.
    #[must_use]
    pub fn is_var_comparison(expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::BinOp(op, a, b)
            if op.is_comparison()
                && matches!(a.as_ref(), Expr::Var(_))
                && matches!(b.as_ref(), Expr::Var(_))
        )
    }

    /// Return `true` if `expr` matches `ptr + index * scale` (array indexing).
    #[must_use]
    pub fn is_array_index(expr: &Expr) -> bool {
        if let Expr::BinOp(BinOp::Add, base, offset) = expr
            && base.is_var() {
                // Check for `index * scale` pattern.
                return matches!(
                    offset.as_ref(),
                    Expr::BinOp(BinOp::Mul | BinOp::Shl, _, _)
                );
            }
        false
    }

    /// Extract `(base, index, scale)` from an array-index expression.
    #[must_use]
    pub fn extract_array_index(expr: &Expr) -> Option<(&Expr, &Expr, u64)> {
        if let Expr::BinOp(BinOp::Add, base, offset) = expr {
            match offset.as_ref() {
                Expr::BinOp(BinOp::Mul, index, scale) => {
                    return scale
                        .as_const()
                        .map(|s| (base.as_ref(), index.as_ref(), i64_as_u64(s)));
                }
                Expr::BinOp(BinOp::Shl, index, shift) => {
                    return shift.as_const().and_then(|s| {
                        if (0..64).contains(&s) {
                            Some((base.as_ref(), index.as_ref(), 1u64 << s))
                        } else {
                            None
                        }
                    });
                }
                _ => {}
            }
        }
        None
    }

    /// Return `true` if `expr` is a pointer dereference.
    #[must_use]
    pub const fn is_deref(expr: &Expr) -> bool {
        matches!(expr, Expr::UnOp(UnOp::Deref, _) | Expr::Load { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprRewriter — rule-based rewriting
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a set of rewrite rules to an expression tree.
///
/// Rules are `(pattern, rewrite)` pairs where pattern is a closure that
/// returns `Option<Expr>` — `Some(e)` means "rewrite to e", `None` means
/// "no match".
/// Boxed rewrite rule used by `ExprRewriter`.
pub type ExprRewriteRule = Box<dyn Fn(&Expr) -> Option<Expr> + Send + Sync>;

pub struct ExprRewriter {
    rules: Vec<ExprRewriteRule>,
}

impl ExprRewriter {
    /// Create a new rewriter with no rules.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rewrite rule.
    pub fn add_rule<F: Fn(&Expr) -> Option<Expr> + Send + Sync + 'static>(&mut self, rule: F) {
        self.rules.push(Box::new(rule));
    }

    /// Apply all rules to `expr`, returning the rewritten tree.
    #[must_use]
    pub fn rewrite(&self, expr: Expr) -> Expr {
        let rewritten = self.apply_rules(expr);
        // Recurse into children.
        match rewritten {
            Expr::BinOp(op, a, b) => {
                Expr::BinOp(op, Box::new(self.rewrite(*a)), Box::new(self.rewrite(*b)))
            }
            Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(self.rewrite(*e))),
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(self.rewrite(*callee)),
                args: args.into_iter().map(|a| self.rewrite(a)).collect(),
            },
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(self.rewrite(*ptr)),
                size,
            },
            Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
                cond: Box::new(self.rewrite(*cond)),
                then_expr: Box::new(self.rewrite(*then_expr)),
                else_expr: Box::new(self.rewrite(*else_expr)),
            },
            Expr::FieldAccess { base, offset } => Expr::FieldAccess {
                base: Box::new(self.rewrite(*base)),
                offset,
            },
            Expr::Index { base, index, elem_size } => Expr::Index {
                base: Box::new(self.rewrite(*base)),
                index: Box::new(self.rewrite(*index)),
                elem_size,
            },
            Expr::Phi(exprs) => Expr::Phi(exprs.into_iter().map(|e| self.rewrite(e)).collect()),
            other => other,
        }
    }

    fn apply_rules(&self, expr: Expr) -> Expr {
        for rule in &self.rules {
            if let Some(rewritten) = rule(&expr) {
                return rewritten;
            }
        }
        expr
    }

    /// Return the number of registered rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for ExprRewriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ExprRewriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExprRewriter {{ rules: {} }}", self.rules.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprEvaluator — concrete evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates an expression tree to a concrete `i64` value given a variable
/// binding environment.
#[derive(Debug, Default)]
pub struct ExprEvaluator;

impl ExprEvaluator {
    /// Create a new evaluator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate `expr` in the given environment.
    ///
    /// # Errors
    ///
    /// Returns `ExprError::UndefinedVar` if a variable is not bound.
    pub fn eval(&self, expr: &Expr, env: &HashMap<String, i64>) -> Result<i64, ExprError> {
        Self::eval_impl(expr, env)
    }

    fn eval_impl(expr: &Expr, env: &HashMap<String, i64>) -> Result<i64, ExprError> {
        match expr {
            Expr::Const(v, _) => Ok(*v),
            Expr::Var(n) => env
                .get(n)
                .copied()
                .ok_or_else(|| ExprError::UndefinedVar(n.clone())),
            Expr::BinOp(op, a, b) => {
                let va = Self::eval_impl(a, env)?;
                let vb = Self::eval_impl(b, env)?;
                fold_const_binop(*op, va, vb).ok_or(ExprError::DivisionByZero)
            }
            Expr::UnOp(op, e) => {
                let v = Self::eval_impl(e, env)?;
                Ok(match op {
                    UnOp::Neg => v.wrapping_neg(),
                    UnOp::Not => !v,
                    UnOp::LNot => i64::from(v == 0),
                    UnOp::Cast(w) => match w {
                        IntWidth::I8 => i64::from(i64_trunc_i8(v)),
                        IntWidth::I16 => i64::from(i64_trunc_i16(v)),
                        IntWidth::I32 => i64::from(i64_trunc_i32(v)),
                        IntWidth::U8 => i64::from(i64_trunc_u8(v)),
                        IntWidth::U16 => i64::from(i64_trunc_u16(v)),
                        IntWidth::U32 => i64::from(i64_trunc_u32(v)),
                        _ => v,
                    },
                    _ => v,
                })
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let c = Self::eval_impl(cond, env)?;
                if c != 0 {
                    Self::eval_impl(then_expr, env)
                } else {
                    Self::eval_impl(else_expr, env)
                }
            }
            _ => Err(ExprError::UndefinedVar(
                "non-evaluable expression".to_string(),
            )),
        }
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

    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }

    fn unop(op: UnOp, e: Expr) -> Expr {
        Expr::UnOp(op, Box::new(e))
    }

    fn simp() -> ExprSimplifier {
        ExprSimplifier::new()
    }

    // ── IntWidth ──────────────────────────────────────────────────────────────

    #[test]
    fn test_int_width_bits() {
        assert_eq!(IntWidth::I32.bits(), 32);
        assert_eq!(IntWidth::U64.bits(), 64);
    }

    #[test]
    fn test_int_width_bytes() {
        assert_eq!(IntWidth::I32.bytes(), 4);
        assert_eq!(IntWidth::U64.bytes(), 8);
    }

    #[test]
    fn test_int_width_signed() {
        assert!(IntWidth::I32.is_signed());
        assert!(!IntWidth::U32.is_signed());
    }

    #[test]
    fn test_int_width_to_unsigned() {
        assert_eq!(IntWidth::I32.to_unsigned(), IntWidth::U32);
        assert_eq!(IntWidth::U32.to_unsigned(), IntWidth::U32);
    }

    #[test]
    fn test_int_width_to_signed() {
        assert_eq!(IntWidth::U64.to_signed(), IntWidth::I64);
    }

    #[test]
    fn test_int_width_max_value() {
        assert_eq!(IntWidth::I8.max_value(), 127);
        assert_eq!(IntWidth::U8.max_value(), 255);
    }

    #[test]
    fn test_int_width_min_value() {
        assert_eq!(IntWidth::I8.min_value(), -128);
        assert_eq!(IntWidth::U8.min_value(), 0);
    }

    #[test]
    fn test_int_width_display() {
        assert_eq!(IntWidth::I32.to_string(), "int32_t");
        assert_eq!(IntWidth::U64.to_string(), "uint64_t");
    }

    // ── BinOp ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_binop_is_comparison() {
        assert!(BinOp::Eq.is_comparison());
        assert!(!BinOp::Add.is_comparison());
    }

    #[test]
    fn test_binop_is_commutative() {
        assert!(BinOp::Add.is_commutative());
        assert!(!BinOp::Sub.is_commutative());
    }

    #[test]
    fn test_binop_is_arithmetic() {
        assert!(BinOp::Mul.is_arithmetic());
        assert!(!BinOp::And.is_arithmetic());
    }

    #[test]
    fn test_binop_is_bitwise() {
        assert!(BinOp::And.is_bitwise());
        assert!(!BinOp::Add.is_bitwise());
    }

    #[test]
    fn test_binop_is_logical() {
        assert!(BinOp::LAnd.is_logical());
        assert!(!BinOp::And.is_logical());
    }

    #[test]
    fn test_binop_swapped() {
        assert_eq!(BinOp::Lt.swapped(), Some(BinOp::Gt));
        assert_eq!(BinOp::Add.swapped(), None);
    }

    #[test]
    fn test_binop_negated() {
        assert_eq!(BinOp::Eq.negated(), Some(BinOp::Ne));
        assert_eq!(BinOp::Lt.negated(), Some(BinOp::Ge));
    }

    #[test]
    fn test_binop_precedence() {
        assert!(BinOp::Mul.precedence() > BinOp::Add.precedence());
        assert!(BinOp::Add.precedence() > BinOp::LOr.precedence());
    }

    // ── Constant folding ──────────────────────────────────────────────────────

    #[test]
    fn test_const_fold_add() {
        let e = binop(BinOp::Add, c(3), c(4));
        assert_eq!(simp().simplify(e), c(7));
    }

    #[test]
    fn test_const_fold_sub() {
        assert_eq!(simp().simplify(binop(BinOp::Sub, c(10), c(3))), c(7));
    }

    #[test]
    fn test_const_fold_mul() {
        assert_eq!(simp().simplify(binop(BinOp::Mul, c(6), c(7))), c(42));
    }

    #[test]
    fn test_const_fold_div() {
        assert_eq!(simp().simplify(binop(BinOp::Div, c(10), c(2))), c(5));
    }

    #[test]
    fn test_const_fold_shl() {
        assert_eq!(simp().simplify(binop(BinOp::Shl, c(1), c(3))), c(8));
    }

    #[test]
    fn test_const_fold_comparison() {
        // Comparison result uses the width of the left operand (I64 here).
        let r1 = simp().simplify(binop(BinOp::Lt, c(1), c(2)));
        assert_eq!(r1.as_const(), Some(1));
        let r2 = simp().simplify(binop(BinOp::Gt, c(1), c(2)));
        assert_eq!(r2.as_const(), Some(0));
    }

    #[test]
    fn test_const_fold_mod() {
        assert_eq!(simp().simplify(binop(BinOp::Mod, c(10), c(3))), c(1));
    }

    #[test]
    fn test_const_fold_and() {
        assert_eq!(
            simp().simplify(binop(BinOp::And, c(0b1111), c(0b1010))),
            c(0b1010)
        );
    }

    // ── Identity rules ────────────────────────────────────────────────────────

    #[test]
    fn test_add_zero() {
        let e = binop(BinOp::Add, var("x"), c(0));
        assert_eq!(simp().simplify(e), var("x"));
    }

    #[test]
    fn test_mul_one() {
        let e = binop(BinOp::Mul, var("x"), c(1));
        assert_eq!(simp().simplify(e), var("x"));
    }

    #[test]
    fn test_mul_zero() {
        let e = binop(BinOp::Mul, var("x"), c(0));
        assert_eq!(simp().simplify(e), c(0));
    }

    #[test]
    fn test_sub_self() {
        let e = binop(BinOp::Sub, var("x"), var("x"));
        assert_eq!(simp().simplify(e), c(0));
    }

    #[test]
    fn test_and_zero() {
        let e = binop(BinOp::And, var("x"), c(0));
        assert_eq!(simp().simplify(e), c(0));
    }

    #[test]
    fn test_xor_self() {
        let e = binop(BinOp::Xor, var("x"), var("x"));
        assert_eq!(simp().simplify(e), c(0));
    }

    #[test]
    fn test_or_self() {
        let e = binop(BinOp::Or, var("x"), var("x"));
        assert_eq!(simp().simplify(e), var("x"));
    }

    #[test]
    fn test_mod_one() {
        let e = binop(BinOp::Mod, var("x"), c(1));
        assert_eq!(simp().simplify(e), c(0));
    }

    // ── Double-negation ───────────────────────────────────────────────────────

    #[test]
    fn test_double_lnot() {
        let e = unop(UnOp::LNot, unop(UnOp::LNot, var("x")));
        assert_eq!(simp().simplify(e), var("x"));
    }

    #[test]
    fn test_double_neg() {
        let e = unop(UnOp::Neg, unop(UnOp::Neg, var("x")));
        assert_eq!(simp().simplify(e), var("x"));
    }

    #[test]
    fn test_lnot_eq_becomes_ne() {
        let e = unop(UnOp::LNot, binop(BinOp::Eq, var("a"), var("b")));
        assert_eq!(simp().simplify(e), binop(BinOp::Ne, var("a"), var("b")));
    }

    #[test]
    fn test_lnot_lt_becomes_ge() {
        let e = unop(UnOp::LNot, binop(BinOp::Lt, var("a"), var("b")));
        assert_eq!(simp().simplify(e), binop(BinOp::Ge, var("a"), var("b")));
    }

    // ── De Morgan ─────────────────────────────────────────────────────────────

    #[test]
    fn test_demorgan_or() {
        let e = binop(
            BinOp::LOr,
            unop(UnOp::LNot, var("a")),
            unop(UnOp::LNot, var("b")),
        );
        let simplified = simp().simplify(e);
        assert!(matches!(simplified, Expr::UnOp(UnOp::LNot, _)));
    }

    // ── ExprFolder ────────────────────────────────────────────────────────────

    #[test]
    fn test_folder_inlines_single_use() {
        let assigns = vec![
            SsaAssign::new("t0", c(42)),
            SsaAssign::new("result", var("t0")),
            SsaAssign::new("retval", binop(BinOp::Add, var("result"), c(0))),
        ];
        let fold_engine = ExprFolder::with_assignments(&assigns);
        let result = fold_engine.fold_expressions(&assigns).unwrap();
        let retval = result.iter().find(|a| a.name == "retval");
        assert!(retval.is_some());
    }

    #[test]
    fn test_folder_phi_error() {
        let assigns = vec![SsaAssign::new("x", Expr::Phi(vec![c(0), c(1)]))];
        let folder = ExprFolder::with_assignments(&assigns);
        let result = folder.fold_expressions(&assigns);
        assert!(matches!(result, Err(ExprError::PhiNotEliminated)));
    }

    // ── has_side_effects ──────────────────────────────────────────────────────

    #[test]
    fn test_no_side_effects_const() {
        assert!(!has_side_effects(&c(42)));
    }

    #[test]
    fn test_no_side_effects_var() {
        assert!(!has_side_effects(&var("x")));
    }

    #[test]
    fn test_call_has_side_effects() {
        let e = Expr::Call {
            callee: Box::new(var("f")),
            args: vec![],
        };
        assert!(has_side_effects(&e));
    }

    #[test]
    fn test_load_has_side_effects() {
        let e = Expr::Load {
            ptr: Box::new(var("p")),
            size: 8,
        };
        assert!(has_side_effects(&e));
    }

    // ── Expr helpers ──────────────────────────────────────────────────────────

    #[test]
    fn test_expr_depth() {
        let e = binop(BinOp::Add, c(1), binop(BinOp::Mul, c(2), c(3)));
        assert_eq!(e.depth(), 3);
    }

    #[test]
    fn test_expr_node_count() {
        let e = binop(BinOp::Add, var("x"), c(1));
        assert_eq!(e.node_count(), 3);
    }

    #[test]
    fn test_expr_referenced_vars() {
        let e = binop(BinOp::Add, var("x"), var("y"));
        let vars = e.referenced_vars();
        assert!(vars.contains(&"x".to_string()));
        assert!(vars.contains(&"y".to_string()));
    }

    #[test]
    fn test_expr_is_zero() {
        assert!(c(0).is_zero());
        assert!(!c(1).is_zero());
    }

    #[test]
    fn test_expr_is_one() {
        assert!(c(1).is_one());
        assert!(!c(0).is_one());
    }

    #[test]
    fn test_expr_is_leaf() {
        assert!(var("x").is_leaf());
        assert!(c(1).is_leaf());
        assert!(!binop(BinOp::Add, var("x"), c(1)).is_leaf());
    }

    #[test]
    fn test_expr_contains_var() {
        let e = binop(BinOp::Add, var("x"), var("y"));
        assert!(e.contains_var("x"));
        assert!(!e.contains_var("z"));
    }

    #[test]
    fn test_expr_is_constant_expr() {
        let e = binop(BinOp::Add, c(1), c(2));
        assert!(e.is_constant_expr());
        let e2 = binop(BinOp::Add, var("x"), c(2));
        assert!(!e2.is_constant_expr());
    }

    #[test]
    fn test_expr_substitute() {
        let e = binop(BinOp::Add, var("x"), c(1));
        let result = e.substitute("x", &c(5));
        assert_eq!(result, binop(BinOp::Add, c(5), c(1)));
    }

    // ── Ternary constant folding ───────────────────────────────────────────────

    #[test]
    fn test_ternary_const_true() {
        let e = Expr::Ternary {
            cond: Box::new(c(1)),
            then_expr: Box::new(var("a")),
            else_expr: Box::new(var("b")),
        };
        assert_eq!(simp().simplify(e), var("a"));
    }

    #[test]
    fn test_ternary_const_false() {
        let e = Expr::Ternary {
            cond: Box::new(c(0)),
            then_expr: Box::new(var("a")),
            else_expr: Box::new(var("b")),
        };
        assert_eq!(simp().simplify(e), var("b"));
    }

    // ── ExprNormalizer ────────────────────────────────────────────────────────

    #[test]
    fn test_normalize_commutative_const_right() {
        let norm = ExprNormalizer::new();
        let e = binop(BinOp::Add, c(5), var("x"));
        let normalized = norm.normalize(e);
        // const should go to the right
        assert_eq!(normalized, binop(BinOp::Add, var("x"), c(5)));
    }

    #[test]
    fn test_normalize_gt_to_lt() {
        let norm = ExprNormalizer::new();
        let e = binop(BinOp::Gt, var("x"), var("y"));
        let normalized = norm.normalize(e);
        assert_eq!(normalized, binop(BinOp::Lt, var("y"), var("x")));
    }

    #[test]
    fn test_normalize_double_cast() {
        let norm = ExprNormalizer::new();
        let inner = unop(UnOp::Cast(IntWidth::I32), var("x"));
        let outer = unop(UnOp::Cast(IntWidth::I64), inner);
        let normalized = norm.normalize(outer);
        assert_eq!(normalized, unop(UnOp::Cast(IntWidth::I64), var("x")));
    }

    // ── ExprComparator ────────────────────────────────────────────────────────

    #[test]
    fn test_comparator_syntactically_equal() {
        let cmp = ExprComparator::new();
        assert!(cmp.syntactically_equal(&c(42), &c(42)));
        assert!(!cmp.syntactically_equal(&c(42), &c(43)));
    }

    #[test]
    fn test_comparator_equivalent_after_simplification() {
        let cmp = ExprComparator::new();
        let a = binop(BinOp::Add, var("x"), c(0));
        let b = var("x");
        assert!(cmp.equivalent(&a, &b));
    }

    #[test]
    fn test_comparator_similarity_identical() {
        let cmp = ExprComparator::new();
        let e = binop(BinOp::Add, var("x"), c(1));
        assert!((cmp.similarity(&e, &e) - 1.0).abs() < 1e-9);
    }

    // ── ExprPrinter ───────────────────────────────────────────────────────────

    #[test]
    fn test_printer_const_small() {
        let p = ExprPrinter::new();
        assert_eq!(p.print(&c(42)), "42");
    }

    #[test]
    fn test_printer_const_large() {
        let p = ExprPrinter::new();
        let s = p.print(&c(0x1000));
        assert!(s.starts_with("0x"));
    }

    #[test]
    fn test_printer_var() {
        let p = ExprPrinter::new();
        assert_eq!(p.print(&var("foo")), "foo");
    }

    #[test]
    fn test_printer_binop() {
        let p = ExprPrinter::new();
        let e = binop(BinOp::Add, var("x"), c(1));
        assert_eq!(p.print(&e), "x + 1");
    }

    #[test]
    fn test_printer_call() {
        let p = ExprPrinter::new();
        let e = Expr::Call {
            callee: Box::new(var("f")),
            args: vec![c(1), var("y")],
        };
        assert_eq!(p.print(&e), "f(1, y)");
    }

    #[test]
    fn test_printer_display_impl() {
        let e = binop(BinOp::Add, var("a"), var("b"));
        let s = e.to_string();
        assert!(s.contains('+'));
    }

    // ── ExprPattern ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_binop_var_const() {
        let e = binop(BinOp::Add, var("x"), c(1));
        assert!(ExprPattern::is_binop_var_const(&e));
    }

    #[test]
    fn test_pattern_var_comparison() {
        let e = binop(BinOp::Lt, var("a"), var("b"));
        assert!(ExprPattern::is_var_comparison(&e));
    }

    #[test]
    fn test_pattern_array_index() {
        let e = binop(BinOp::Add, var("arr"), binop(BinOp::Mul, var("i"), c(4)));
        assert!(ExprPattern::is_array_index(&e));
    }

    #[test]
    fn test_pattern_extract_array_index() {
        let e = binop(BinOp::Add, var("arr"), binop(BinOp::Mul, var("i"), c(4)));
        let result = ExprPattern::extract_array_index(&e);
        assert!(result.is_some());
        let (_, _, scale) = result.unwrap();
        assert_eq!(scale, 4);
    }

    #[test]
    fn test_pattern_is_deref() {
        let e = unop(UnOp::Deref, var("p"));
        assert!(ExprPattern::is_deref(&e));
    }

    // ── DefUseChain ───────────────────────────────────────────────────────────

    #[test]
    fn test_def_use_counts() {
        let assigns = vec![
            SsaAssign::new("t0", c(1)),
            SsaAssign::new("t1", binop(BinOp::Add, var("t0"), var("t0"))),
        ];
        let chain = DefUseChain::from_assignments(&assigns);
        assert_eq!(chain.def_count("t0"), 1);
        assert_eq!(chain.use_count("t0"), 2);
    }

    #[test]
    fn test_def_use_is_dead() {
        let assigns = vec![SsaAssign::new("dead", c(99))];
        let chain = DefUseChain::from_assignments(&assigns);
        assert!(chain.is_dead("dead"));
    }

    #[test]
    fn test_def_use_is_single_def_use() {
        let assigns = vec![SsaAssign::new("a", c(1)), SsaAssign::new("b", var("a"))];
        let chain = DefUseChain::from_assignments(&assigns);
        assert!(chain.is_single_def_use("a"));
    }

    #[test]
    fn test_def_use_dead_vars() {
        let assigns = vec![
            SsaAssign::new("dead", c(0)),
            SsaAssign::new("live", var("x")),
        ];
        let chain = DefUseChain::from_assignments(&assigns);
        let dead = chain.dead_vars();
        assert!(dead.contains(&"dead"));
    }

    // ── ExprEvaluator ─────────────────────────────────────────────────────────

    #[test]
    fn test_evaluator_const() {
        let ev = ExprEvaluator::new();
        assert_eq!(ev.eval(&c(42), &HashMap::new()).unwrap(), 42);
    }

    #[test]
    fn test_evaluator_var() {
        let ev = ExprEvaluator::new();
        let mut env = HashMap::new();
        env.insert("x".to_string(), 10i64);
        assert_eq!(ev.eval(&var("x"), &env).unwrap(), 10);
    }

    #[test]
    fn test_evaluator_binop() {
        let ev = ExprEvaluator::new();
        let e = binop(BinOp::Add, c(3), c(4));
        assert_eq!(ev.eval(&e, &HashMap::new()).unwrap(), 7);
    }

    #[test]
    fn test_evaluator_undefined_var() {
        let ev = ExprEvaluator::new();
        let result = ev.eval(&var("undefined"), &HashMap::new());
        assert!(matches!(result, Err(ExprError::UndefinedVar(_))));
    }

    #[test]
    fn test_evaluator_ternary() {
        let ev = ExprEvaluator::new();
        let e = Expr::Ternary {
            cond: Box::new(c(1)),
            then_expr: Box::new(c(10)),
            else_expr: Box::new(c(20)),
        };
        assert_eq!(ev.eval(&e, &HashMap::new()).unwrap(), 10);
    }

    // ── ExprRewriter ──────────────────────────────────────────────────────────

    #[test]
    fn test_rewriter_no_rules() {
        let rw = ExprRewriter::new();
        let e = binop(BinOp::Add, var("x"), c(0));
        assert_eq!(rw.rewrite(e.clone()), e);
    }

    #[test]
    fn test_rewriter_add_zero_rule() {
        let mut rw = ExprRewriter::new();
        rw.add_rule(|e| {
            if let Expr::BinOp(BinOp::Add, a, b) = e
                && b.as_const() == Some(0)
            {
                return Some(*a.clone());
            }
            None
        });
        let e = binop(BinOp::Add, var("x"), c(0));
        assert_eq!(rw.rewrite(e), var("x"));
    }

    #[test]
    fn test_rewriter_rule_count() {
        let mut rw = ExprRewriter::new();
        rw.add_rule(|_| None);
        rw.add_rule(|_| None);
        assert_eq!(rw.rule_count(), 2);
    }

    // ── SsaAssign ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ssa_assign_display() {
        let a = SsaAssign::new("x", c(42));
        let s = a.to_string();
        assert!(s.contains('x'));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_ssa_assign_rhs_var_count() {
        let a = SsaAssign::new("out", binop(BinOp::Add, var("a"), var("b")));
        assert_eq!(a.rhs_var_count(), 2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free helper functions used by ConstantFolder, StrengthReducer, etc.
// ─────────────────────────────────────────────────────────────────────────────

fn simplify_binop(op: BinOp, a: Expr, b: Expr) -> Expr {
    match op {
        BinOp::Add => {
            if b.as_const() == Some(0) {
                return a;
            }
            if a.as_const() == Some(0) {
                return b;
            }
        }
        BinOp::Sub => {
            if b.as_const() == Some(0) {
                return a;
            }
            if let (Some(av), Some(bv)) = (a.as_const(), b.as_const()) {
                return Expr::Const(av.wrapping_sub(bv), IntWidth::I64);
            }
        }
        BinOp::Mul => {
            if a.as_const() == Some(0) || b.as_const() == Some(0) {
                return Expr::Const(0, IntWidth::I64);
            }
            if b.as_const() == Some(1) {
                return a;
            }
            if a.as_const() == Some(1) {
                return b;
            }
        }
        BinOp::Div => {
            if b.as_const() == Some(1) {
                return a;
            }
        }
        BinOp::And => {
            if a.as_const() == Some(0) || b.as_const() == Some(0) {
                return Expr::Const(0, IntWidth::I64);
            }
            if a == b {
                return a;
            }
        }
        BinOp::Or => {
            if a.as_const() == Some(0) {
                return b;
            }
            if b.as_const() == Some(0) {
                return a;
            }
            if a == b {
                return a;
            }
        }
        BinOp::Xor => {
            if a == b {
                return Expr::Const(0, IntWidth::I64);
            }
            if b.as_const() == Some(0) {
                return a;
            }
        }
        _ => {}
    }
    if let (Some(av), Some(bv)) = (a.as_const(), b.as_const()) {
        return fold_binop_to_expr(op, av, bv);
    }
    Expr::BinOp(op, Box::new(a), Box::new(b))
}

fn fold_binop_to_expr(op: BinOp, a: i64, b: i64) -> Expr {
    let v = match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Div => {
            if b != 0 {
                a / b
            } else {
                0
            }
        }
        BinOp::Mod => {
            if b != 0 {
                a % b
            } else {
                0
            }
        }
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => a.wrapping_shl(shift_amount(b)),
        BinOp::Shr => u64_as_i64(i64_as_u64(a).wrapping_shr(shift_amount(b))),
        BinOp::Sar => a.wrapping_shr(shift_amount(b)),
        BinOp::Eq => {
            i64::from(a == b)
        }
        BinOp::Ne => {
            i64::from(a != b)
        }
        BinOp::Lt => {
            i64::from(a < b)
        }
        BinOp::Le => {
            i64::from(a <= b)
        }
        BinOp::Gt => {
            i64::from(a > b)
        }
        BinOp::Ge => {
            i64::from(a >= b)
        }
        BinOp::LAnd => {
            i64::from(a != 0 && b != 0)
        }
        BinOp::LOr => {
            i64::from(a != 0 || b != 0)
        }
    };
    Expr::Const(v, IntWidth::I64)
}

fn simplify_unop(op: UnOp, inner: Expr) -> Expr {
    match op {
        UnOp::Neg => {
            if let Some(v) = inner.as_const() {
                return Expr::Const(-v, IntWidth::I64);
            }
            // --x = x
            if let Expr::UnOp(UnOp::Neg, inner2) = inner.clone() {
                return *inner2;
            }
        }
        UnOp::Not => {
            if let Some(v) = inner.as_const() {
                return Expr::Const(!v, IntWidth::I64);
            }
            // ~~x = x
            if let Expr::UnOp(UnOp::Not, inner2) = inner.clone() {
                return *inner2;
            }
        }
        UnOp::LNot => {
            if let Some(v) = inner.as_const() {
                return Expr::Const(i64::from(v == 0), IntWidth::I64);
            }
        }
        _ => {}
    }
    Expr::UnOp(op, Box::new(inner))
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantFolder
// ─────────────────────────────────────────────────────────────────────────────

/// Folds constant sub-expressions.
#[derive(Debug, Default)]
pub struct ConstantFolder {
    fold_count: usize,
}

impl ConstantFolder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fold(&mut self, e: Expr) -> Expr {
        match e {
            Expr::BinOp(op, a, b) => {
                let a = self.fold(*a);
                let b = self.fold(*b);
                let was_const = a.as_const().is_some() && b.as_const().is_some();
                let r = simplify_binop(op, a, b);
                if was_const {
                    self.fold_count += 1;
                }
                r
            }
            Expr::UnOp(op, inner) => {
                let inner = self.fold(*inner);
                simplify_unop(op, inner)
            }
            other => other,
        }
    }

    #[must_use]
    pub const fn fold_count(&self) -> usize {
        self.fold_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrengthReducer
// ─────────────────────────────────────────────────────────────────────────────

/// Replaces expensive operations with cheaper equivalents.
#[derive(Debug, Default)]
pub struct StrengthReducer {
    reductions: usize,
}

impl StrengthReducer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reduce(&mut self, e: Expr) -> Expr {
        match e {
            Expr::BinOp(BinOp::Mul, a, b) => {
                // x * 2^n → x << n
                if let Some(bv) = b.as_const()
                    && bv > 0 && i64_as_u64(bv).is_power_of_two() {
                        let shift = i64_as_u64(bv).trailing_zeros();
                        self.reductions += 1;
                        return Expr::BinOp(
                            BinOp::Shl,
                            a,
                            Box::new(Expr::Const(i64::from(shift), IntWidth::U8)),
                        );
                    }
                Expr::BinOp(BinOp::Mul, a, b)
            }
            Expr::BinOp(BinOp::Div, a, b) => {
                // x / 2^n → x >> n (for unsigned)
                if let Some(bv) = b.as_const()
                    && bv > 0 && i64_as_u64(bv).is_power_of_two() {
                        let shift = i64_as_u64(bv).trailing_zeros();
                        self.reductions += 1;
                        return Expr::BinOp(
                            BinOp::Shr,
                            a,
                            Box::new(Expr::Const(i64::from(shift), IntWidth::U8)),
                        );
                    }
                Expr::BinOp(BinOp::Div, a, b)
            }
            Expr::BinOp(BinOp::Mod, a, b) => {
                // x % 2^n → x & (2^n - 1)
                if let Some(bv) = b.as_const()
                    && bv > 0 && i64_as_u64(bv).is_power_of_two() {
                        self.reductions += 1;
                        return Expr::BinOp(
                            BinOp::And,
                            a,
                            Box::new(Expr::Const(bv - 1, IntWidth::I64)),
                        );
                    }
                Expr::BinOp(BinOp::Mod, a, b)
            }
            Expr::BinOp(op, a, b) => {
                let a = self.reduce(*a);
                let b = self.reduce(*b);
                Expr::BinOp(op, Box::new(a), Box::new(b))
            }
            other => other,
        }
    }

    #[must_use]
    pub const fn reductions(&self) -> usize {
        self.reductions
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitwidthAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses the effective bit-width of an expression.
#[derive(Debug, Default)]
pub struct BitwidthAnalyzer;

impl BitwidthAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the minimum number of bits needed to represent the value.
    #[must_use]
    pub fn min_bits(&self, e: &Expr) -> u32 {
        Self::min_bits_impl(e)
    }

    fn min_bits_impl(e: &Expr) -> u32 {
        match e {
            Expr::Const(v, _) => {
                if *v == 0 {
                    return 1;
                }
                64 - v.unsigned_abs().leading_zeros()
            }
            Expr::BinOp(BinOp::And, _, b) => {
                b.as_const().map_or(64, |mask| 64 - i64_as_u64(mask).leading_zeros())
            }
            Expr::BinOp(BinOp::Shr | BinOp::Sar, a, b) => {
                let parent_bits = Self::min_bits_impl(a);
                let shift = i64_trunc_u32(b.as_const().unwrap_or(0));
                parent_bits.saturating_sub(shift)
            }
            _ => 64,
        }
    }

    /// Infer the `IntWidth` that fits the expression.
    #[must_use]
    pub fn infer_width(&self, e: &Expr) -> IntWidth {
        match self.min_bits(e) {
            0..=8 => IntWidth::U8,
            9..=16 => IntWidth::U16,
            17..=32 => IntWidth::U32,
            _ => IntWidth::U64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignednessInference
// ─────────────────────────────────────────────────────────────────────────────

/// Infers whether an expression is signed or unsigned.
#[derive(Debug, Default)]
pub struct SignednessInference;

impl SignednessInference {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn is_likely_signed(&self, e: &Expr) -> bool {
        match e {
            Expr::Const(v, _) => *v < 0,
            Expr::BinOp(BinOp::Sar, _, _) | Expr::UnOp(UnOp::Neg, _) => true,
            _ => false,
        }
    }

    #[must_use]
    pub fn infer_signedness(&self, e: &Expr) -> IntWidth {
        let bwa = BitwidthAnalyzer::new();
        let width = bwa.infer_width(e);
        if self.is_likely_signed(e) {
            width.to_signed()
        } else {
            width.to_unsigned()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommonSubexprElim
// ─────────────────────────────────────────────────────────────────────────────

/// Common Subexpression Elimination (CSE).
#[derive(Debug, Default)]
pub struct CommonSubexprElim {
    cse_map: HashMap<String, String>,
    next_tmp: usize,
    substitutions: usize,
}

impl CommonSubexprElim {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an expression as a common subexpression, returning its temp variable name.
    pub fn register(&mut self, e: &Expr) -> String {
        let key = format!("{e}");
        if let Some(name) = self.cse_map.get(&key) {
            self.substitutions += 1;
            return name.clone();
        }
        let name = format!("cse_{}", self.next_tmp);
        self.next_tmp += 1;
        self.cse_map.insert(key, name.clone());
        name
    }

    #[must_use]
    pub const fn substitutions(&self) -> usize {
        self.substitutions
    }

    #[must_use]
    pub fn cse_count(&self) -> usize {
        self.cse_map.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CopyPropagation
// ─────────────────────────────────────────────────────────────────────────────

/// Propagates copy assignments: `x = y` → replaces uses of `x` with `y`.
#[derive(Debug, Default)]
pub struct CopyPropagation {
    copy_map: HashMap<String, Expr>,
}

impl CopyPropagation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_copy(&mut self, dst: impl Into<String>, src: Expr) {
        self.copy_map.insert(dst.into(), src);
    }

    #[must_use] 
    pub fn propagate(&self, e: Expr) -> Expr {
        match e {
            Expr::Var(ref name) => {
                if let Some(replacement) = self.copy_map.get(name) {
                    return replacement.clone();
                }
                e
            }
            Expr::BinOp(op, a, b) => Expr::BinOp(
                op,
                Box::new(self.propagate(*a)),
                Box::new(self.propagate(*b)),
            ),
            Expr::UnOp(op, inner) => Expr::UnOp(op, Box::new(self.propagate(*inner))),
            other => other,
        }
    }

    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.copy_map.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprCanonicalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Brings expressions into a canonical form for reliable comparison.
/// Sorts commutative operands so that constants appear on the right.
#[derive(Debug, Default)]
pub struct ExprCanonicalizer;

impl ExprCanonicalizer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn canonicalize(&self, e: Expr) -> Expr {
        Self::canonicalize_impl(e)
    }

    fn canonicalize_impl(e: Expr) -> Expr {
        match e {
            Expr::BinOp(op, a, b) => {
                let a = Self::canonicalize_impl(*a);
                let b = Self::canonicalize_impl(*b);
                // For commutative ops, put constants on the right.
                if op.is_commutative() {
                    if a.as_const().is_some() && b.as_const().is_none() {
                        return Expr::BinOp(op, Box::new(b), Box::new(a));
                    }
                    // Sort vars alphabetically for determinism.
                    if let (Expr::Var(va), Expr::Var(vb)) = (&a, &b)
                        && va > vb {
                            return Expr::BinOp(
                                op,
                                Box::new(Expr::Var(vb.clone())),
                                Box::new(Expr::Var(va.clone())),
                            );
                        }
                }
                Expr::BinOp(op, Box::new(a), Box::new(b))
            }
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BooleanSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Simplifies boolean/logical expressions.
#[derive(Debug, Default)]
pub struct BooleanSimplifier;

impl BooleanSimplifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn simplify(&self, e: Expr) -> Expr {
        Self::simplify_impl(e)
    }

    fn simplify_impl(e: Expr) -> Expr {
        match e {
            Expr::BinOp(BinOp::LAnd, a, b) => {
                if a.as_const() == Some(0) || b.as_const() == Some(0) {
                    return Expr::Const(0, IntWidth::U8);
                }
                if a.as_const() == Some(1) {
                    return Self::simplify_impl(*b);
                }
                if b.as_const() == Some(1) {
                    return Self::simplify_impl(*a);
                }
                Expr::BinOp(
                    BinOp::LAnd,
                    Box::new(Self::simplify_impl(*a)),
                    Box::new(Self::simplify_impl(*b)),
                )
            }
            Expr::BinOp(BinOp::LOr, a, b) => {
                if a.as_const() == Some(1) || b.as_const() == Some(1) {
                    return Expr::Const(1, IntWidth::U8);
                }
                if a.as_const() == Some(0) {
                    return Self::simplify_impl(*b);
                }
                if b.as_const() == Some(0) {
                    return Self::simplify_impl(*a);
                }
                Expr::BinOp(
                    BinOp::LOr,
                    Box::new(Self::simplify_impl(*a)),
                    Box::new(Self::simplify_impl(*b)),
                )
            }
            Expr::UnOp(UnOp::LNot, inner) => {
                if let Some(v) = inner.as_const() {
                    return Expr::Const(i64::from(v == 0), IntWidth::U8);
                }
                Expr::UnOp(UnOp::LNot, Box::new(Self::simplify_impl(*inner)))
            }
            Expr::BinOp(op, a, b) => {
                Expr::BinOp(op, Box::new(Self::simplify_impl(*a)), Box::new(Self::simplify_impl(*b)))
            }
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComparisonNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Normalizes comparison expressions to a canonical form.
#[derive(Debug, Default)]
pub struct ComparisonNormalizer;

impl ComparisonNormalizer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Normalize `a > b` → `b < a`, etc.
    #[must_use]
    pub const fn normalize(&self, op: BinOp, a: Expr, b: Expr) -> (BinOp, Expr, Expr) {
        match op {
            BinOp::Gt => (BinOp::Lt, b, a),
            BinOp::Ge => (BinOp::Le, b, a),
            _ => (op, a, b),
        }
    }

    #[must_use] 
    pub fn normalize_expr(&self, e: Expr) -> Expr {
        match e {
            Expr::BinOp(op, a, b) if matches!(op, BinOp::Gt | BinOp::Ge) => {
                let (nop, na, nb) = self.normalize(op, *a, *b);
                Expr::BinOp(nop, Box::new(na), Box::new(nb))
            }
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AffineExprRecognizer
// ─────────────────────────────────────────────────────────────────────────────

/// Recognizes affine expressions: `a*x + b`.
#[derive(Debug, Clone)]
pub struct AffineForm {
    pub var: String,
    pub coefficient: i64,
    pub constant: i64,
}

/// Recognizes affine expressions in a variable.
#[must_use] 
pub fn recognize_affine(e: &Expr) -> Option<AffineForm> {
    match e {
        Expr::Var(v) => Some(AffineForm {
            var: v.clone(),
            coefficient: 1,
            constant: 0,
        }),
        Expr::BinOp(BinOp::Add, a, b) => {
            let af = recognize_affine(a)?;
            let c = b.as_const()?;
            Some(AffineForm {
                var: af.var,
                coefficient: af.coefficient,
                constant: af.constant + c,
            })
        }
        Expr::BinOp(BinOp::Sub, a, b) => {
            let af = recognize_affine(a)?;
            let c = b.as_const()?;
            Some(AffineForm {
                var: af.var,
                coefficient: af.coefficient,
                constant: af.constant - c,
            })
        }
        Expr::BinOp(BinOp::Mul, a, b) => {
            let af = recognize_affine(a)?;
            let c = b.as_const()?;
            Some(AffineForm {
                var: af.var,
                coefficient: af.coefficient * c,
                constant: af.constant * c,
            })
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerArithmeticRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers high-level pointer arithmetic from raw add/sub operations.
#[derive(Debug, Default)]
pub struct PointerArithmeticRecovery {
    pointer_vars: std::collections::HashSet<String>,
}

impl PointerArithmeticRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_pointer(&mut self, var: impl Into<String>) {
        self.pointer_vars.insert(var.into());
    }

    #[must_use]
    pub fn is_pointer(&self, var: &str) -> bool {
        self.pointer_vars.contains(var)
    }

    /// Try to recover `ptr[i]` or `ptr->field` pattern.
    #[must_use]
    pub fn recover(&self, e: &Expr) -> Option<String> {
        match e {
            Expr::BinOp(BinOp::Add, a, b) => {
                if let Expr::Var(v) = a.as_ref()
                    && self.is_pointer(v) {
                        if let Some(offset) = b.as_const() {
                            return Some(format!("{v}[{offset}]"));
                        }
                        if let Expr::BinOp(BinOp::Mul, idx, scale) = b.as_ref()
                            && let Some(s) = scale.as_const() {
                                let idx_str = match idx.as_ref() {
                                    Expr::Var(iv) => iv.clone(),
                                    _ => "idx".to_string(),
                                };
                                return Some(format!("{v}[{idx_str}] /* stride={s} */"));
                            }
                    }
                None
            }
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringLiteralDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects string literal accesses in expressions.
#[derive(Debug, Default)]
pub struct StringLiteralDetector {
    known_strings: HashMap<u64, String>,
}

impl StringLiteralDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, addr: u64, value: impl Into<String>) {
        self.known_strings.insert(addr, value.into());
    }

    /// If this expression is a load from a known string address, return the string.
    #[must_use]
    pub fn detect<'a>(&'a self, e: &'a Expr) -> Option<&'a str> {
        match e {
            Expr::Const(addr, _) => self.known_strings.get(&i64_as_u64(*addr)).map(String::as_str),
            Expr::Var(v) => {
                // Check if var name looks like a string literal (str_XXXX).
                if v.starts_with("str_") {
                    return Some(v.as_str());
                }
                None
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn known_count(&self) -> usize {
        self.known_strings.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableCallDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects virtual function table (vtable) calls.
#[derive(Debug, Default)]
pub struct VtableCallDetector {
    known_vtables: HashMap<u64, String>,
}

impl VtableCallDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_vtable(&mut self, addr: u64, class_name: impl Into<String>) {
        self.known_vtables.insert(addr, class_name.into());
    }

    /// Detect a vtable call pattern: `(**(obj + slot))(obj, ...)`.
    #[must_use]
    pub fn detect_vtable_call(&self, callee: &Expr) -> Option<String> {
        // Pattern: Load(Load(base + offset))
        match callee {
            Expr::Load { ptr, .. } => match ptr.as_ref() {
                Expr::BinOp(BinOp::Add, base, offset) => {
                    if let (Expr::Var(cls), Some(slot)) = (base.as_ref(), offset.as_const()) {
                        return Some(format!("{cls}::vfunc[{slot}]"));
                    }
                    None
                }
                _ => None,
            },
            _ => None,
        }
    }

    #[must_use]
    pub fn vtable_count(&self) -> usize {
        self.known_vtables.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NullCheckEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminates redundant null pointer checks.
#[derive(Debug, Default)]
pub struct NullCheckEliminator {
    non_null_vars: std::collections::HashSet<String>,
    eliminated: usize,
}

impl NullCheckEliminator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_non_null(&mut self, var: impl Into<String>) {
        self.non_null_vars.insert(var.into());
    }

    /// Try to eliminate a null check expression.
    /// `expr != 0` where expr is known non-null → `1`.
    pub fn eliminate(&mut self, e: Expr) -> Expr {
        match &e {
            Expr::BinOp(BinOp::Ne, a, b) => {
                if b.as_const() == Some(0)
                    && let Expr::Var(v) = a.as_ref()
                        && self.non_null_vars.contains(v) {
                            self.eliminated += 1;
                            return Expr::Const(1, IntWidth::U8);
                        }
            }
            Expr::BinOp(BinOp::Eq, a, b) => {
                if b.as_const() == Some(0)
                    && let Expr::Var(v) = a.as_ref()
                        && self.non_null_vars.contains(v) {
                            self.eliminated += 1;
                            return Expr::Const(0, IntWidth::U8);
                        }
            }
            _ => {}
        }
        e
    }

    #[must_use]
    pub const fn eliminated(&self) -> usize {
        self.eliminated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadExprElim
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminates dead (unused) expressions from an expression list.
#[derive(Debug, Default)]
pub struct DeadExprElim {
    used_vars: std::collections::HashSet<String>,
    eliminated: usize,
}

impl DeadExprElim {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_used(&mut self, var: impl Into<String>) {
        self.used_vars.insert(var.into());
    }

    #[must_use]
    pub fn is_used(&self, var: &str) -> bool {
        self.used_vars.contains(var)
    }

    /// Filter out assignments where the LHS is never used.
    pub fn filter_assignments(&mut self, assigns: Vec<SsaAssign>) -> Vec<SsaAssign> {
        let orig = assigns.len();
        let result: Vec<_> = assigns
            .into_iter()
            .filter(|a| self.is_used(&a.name))
            .collect();
        self.eliminated += orig - result.len();
        result
    }

    #[must_use]
    pub const fn eliminated(&self) -> usize {
        self.eliminated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitwiseSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Simplifies bitwise expressions.
#[derive(Debug, Default)]
pub struct BitwiseSimplifier;

impl BitwiseSimplifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn simplify(&self, e: Expr) -> Expr {
        Self::simplify_impl(e)
    }

    fn simplify_impl(e: Expr) -> Expr {
        match e {
            // x & 0xFF & 0xFF → x & 0xFF
            Expr::BinOp(BinOp::And, outer_a, outer_b) => {
                let a = Self::simplify_impl(*outer_a);
                let b = Self::simplify_impl(*outer_b);
                if let (Expr::BinOp(BinOp::And, inner_a, inner_b), Some(bv)) = (&a, b.as_const())
                    && let Some(ibv) = inner_b.as_const() {
                        let combined = ibv & bv;
                        return Expr::BinOp(
                            BinOp::And,
                            inner_a.clone(),
                            Box::new(Expr::Const(combined, IntWidth::I64)),
                        );
                    }
                // All-ones mask: x & 0xFFFFFFFF → x
                if let Some(mask) = b.as_const()
                    && (mask == -1i64 || i64_as_u64(mask) == u64::MAX) {
                        return a;
                    }
                Expr::BinOp(BinOp::And, Box::new(a), Box::new(b))
            }
            Expr::BinOp(BinOp::Or, a, b) => {
                let a = Self::simplify_impl(*a);
                let b = Self::simplify_impl(*b);
                // x | 0 → x
                if b.as_const() == Some(0) { return a; }
                if a.as_const() == Some(0) { return b; }
                Expr::BinOp(BinOp::Or, Box::new(a), Box::new(b))
            }
            Expr::BinOp(BinOp::Xor, a, b) => {
                let a = Self::simplify_impl(*a);
                let b = Self::simplify_impl(*b);
                // x ^ x → 0
                if a == b { return Expr::Const(0, IntWidth::I64); }
                // x ^ 0 → x
                if b.as_const() == Some(0) { return a; }
                Expr::BinOp(BinOp::Xor, Box::new(a), Box::new(b))
            }
            Expr::BinOp(op, a, b) => {
                Expr::BinOp(op, Box::new(Self::simplify_impl(*a)), Box::new(Self::simplify_impl(*b)))
            }
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_expr_tests {
    use super::*;

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }

    // ── ExprSimplifier ───────────────────────────────────────────────────────

    #[test]
    fn test_simplifier_add_zero() {
        let s = ExprSimplifier::new();
        let e = binop(BinOp::Add, var("x"), c(0));
        assert_eq!(s.simplify(e), var("x"));
    }

    #[test]
    fn test_simplifier_mul_by_one() {
        let s = ExprSimplifier::new();
        let e = binop(BinOp::Mul, var("x"), c(1));
        assert_eq!(s.simplify(e), var("x"));
    }

    #[test]
    fn test_simplifier_xor_self_is_zero() {
        let s = ExprSimplifier::new();
        let e = binop(BinOp::Xor, var("x"), var("x"));
        assert_eq!(s.simplify(e), c(0));
    }

    #[test]
    fn test_simplifier_double_negation() {
        let s = ExprSimplifier::new();
        let e = Expr::UnOp(
            UnOp::Neg,
            Box::new(Expr::UnOp(UnOp::Neg, Box::new(var("x")))),
        );
        assert_eq!(s.simplify(e), var("x"));
    }

    #[test]
    fn test_simplifier_const_fold_add() {
        let s = ExprSimplifier::new();
        let e = binop(BinOp::Add, c(3), c(4));
        assert_eq!(s.simplify(e), c(7));
    }

    #[test]
    fn test_simplifier_ternary_const_cond() {
        let s = ExprSimplifier::new();
        let e = Expr::Ternary {
            cond: Box::new(c(1)),
            then_expr: Box::new(c(10)),
            else_expr: Box::new(c(20)),
        };
        assert_eq!(s.simplify(e), c(10));
    }

    #[test]
    fn test_simplifier_ternary_false_cond() {
        let s = ExprSimplifier::new();
        let e = Expr::Ternary {
            cond: Box::new(c(0)),
            then_expr: Box::new(c(10)),
            else_expr: Box::new(c(20)),
        };
        assert_eq!(s.simplify(e), c(20));
    }

    // ── ConstantFolder ───────────────────────────────────────────────────────

    #[test]
    fn test_constant_folder_counts() {
        let mut cf = ConstantFolder::new();
        cf.fold(binop(BinOp::Add, c(1), c(2)));
        assert_eq!(cf.fold_count(), 1);
    }

    #[test]
    fn test_constant_folder_nested() {
        let mut cf = ConstantFolder::new();
        let e = binop(BinOp::Mul, binop(BinOp::Add, c(2), c(3)), c(4));
        let result = cf.fold(e);
        assert_eq!(result, c(20));
    }

    // ── StrengthReducer ──────────────────────────────────────────────────────

    #[test]
    fn test_strength_reducer_mul_to_shift() {
        let mut sr = StrengthReducer::new();
        let e = binop(BinOp::Mul, var("x"), c(4));
        let r = sr.reduce(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Shl, _, _)));
        assert_eq!(sr.reductions(), 1);
    }

    #[test]
    fn test_strength_reducer_div_to_shift() {
        let mut sr = StrengthReducer::new();
        let e = binop(BinOp::Div, var("x"), c(8));
        let r = sr.reduce(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Shr, _, _)));
    }

    #[test]
    fn test_strength_reducer_rem_to_and() {
        let mut sr = StrengthReducer::new();
        let e = binop(BinOp::Mod, var("x"), c(16));
        let r = sr.reduce(e);
        assert!(matches!(r, Expr::BinOp(BinOp::And, _, _)));
    }

    // ── BitwidthAnalyzer ─────────────────────────────────────────────────────

    #[test]
    fn test_bitwidth_small_const() {
        let bwa = BitwidthAnalyzer::new();
        assert!(bwa.min_bits(&c(255)) <= 8);
    }

    #[test]
    fn test_bitwidth_zero() {
        let bwa = BitwidthAnalyzer::new();
        assert_eq!(bwa.min_bits(&c(0)), 1);
    }

    #[test]
    fn test_bitwidth_infer_width_small() {
        let bwa = BitwidthAnalyzer::new();
        let w = bwa.infer_width(&c(200));
        assert_eq!(w, IntWidth::U8);
    }

    // ── SignednessInference ──────────────────────────────────────────────────

    #[test]
    fn test_signedness_neg_const() {
        let si = SignednessInference::new();
        assert!(si.is_likely_signed(&c(-1)));
    }

    #[test]
    fn test_signedness_pos_const() {
        let si = SignednessInference::new();
        assert!(!si.is_likely_signed(&c(42)));
    }

    // ── CommonSubexprElim ────────────────────────────────────────────────────

    #[test]
    fn test_cse_register_and_reuse() {
        let mut cse = CommonSubexprElim::new();
        let e = binop(BinOp::Add, var("a"), var("b"));
        let name1 = cse.register(&e);
        let name2 = cse.register(&e);
        assert_eq!(name1, name2);
        assert_eq!(cse.substitutions(), 1);
    }

    // ── CopyPropagation ──────────────────────────────────────────────────────

    #[test]
    fn test_copy_prop_var() {
        let mut cp = CopyPropagation::new();
        cp.record_copy("x", var("y"));
        let e = var("x");
        assert_eq!(cp.propagate(e), var("y"));
    }

    #[test]
    fn test_copy_prop_no_match() {
        let cp = CopyPropagation::new();
        let e = var("z");
        assert_eq!(cp.propagate(e.clone()), e);
    }

    // ── ExprCanonicalizer ────────────────────────────────────────────────────

    #[test]
    fn test_canonicalizer_const_to_right() {
        let canon = ExprCanonicalizer::new();
        let e = binop(BinOp::Add, c(5), var("x"));
        let r = canon.canonicalize(e);
        assert!(matches!(&r, Expr::BinOp(BinOp::Add, l, rhs)
            if matches!(l.as_ref(), Expr::Var(_)) && matches!(rhs.as_ref(), Expr::Const(_, _))));
    }

    // ── BooleanSimplifier ────────────────────────────────────────────────────

    #[test]
    fn test_bool_simplifier_and_zero() {
        let bs = BooleanSimplifier::new();
        let e = binop(BinOp::LAnd, c(0), var("x"));
        assert_eq!(bs.simplify(e), Expr::Const(0, IntWidth::U8));
    }

    #[test]
    fn test_bool_simplifier_or_one() {
        let bs = BooleanSimplifier::new();
        let e = binop(BinOp::LOr, c(1), var("x"));
        assert_eq!(bs.simplify(e), Expr::Const(1, IntWidth::U8));
    }

    // ── ComparisonNormalizer ─────────────────────────────────────────────────

    #[test]
    fn test_comparison_gt_to_lt() {
        let cn = ComparisonNormalizer::new();
        let (op, _, _) = cn.normalize(BinOp::Gt, var("a"), var("b"));
        assert_eq!(op, BinOp::Lt);
    }

    // ── AffineExprRecognizer ─────────────────────────────────────────────────

    #[test]
    fn test_recognize_affine_var() {
        let af = recognize_affine(&var("x")).unwrap();
        assert_eq!(af.var, "x");
        assert_eq!(af.coefficient, 1);
        assert_eq!(af.constant, 0);
    }

    #[test]
    fn test_recognize_affine_add_const() {
        let e = binop(BinOp::Add, var("x"), c(5));
        let af = recognize_affine(&e).unwrap();
        assert_eq!(af.constant, 5);
    }

    #[test]
    fn test_recognize_affine_mul_const() {
        let e = binop(BinOp::Mul, var("x"), c(3));
        let af = recognize_affine(&e).unwrap();
        assert_eq!(af.coefficient, 3);
    }

    // ── PointerArithmeticRecovery ────────────────────────────────────────────

    #[test]
    fn test_ptr_arith_recovery_offset() {
        let mut par = PointerArithmeticRecovery::new();
        par.mark_pointer("buf");
        let e = binop(BinOp::Add, var("buf"), c(4));
        let r = par.recover(&e).unwrap();
        assert!(r.contains("buf"));
        assert!(r.contains('4'));
    }

    #[test]
    fn test_ptr_arith_not_pointer() {
        let par = PointerArithmeticRecovery::new();
        let e = binop(BinOp::Add, var("x"), c(4));
        assert!(par.recover(&e).is_none());
    }

    // ── StringLiteralDetector ────────────────────────────────────────────────

    #[test]
    fn test_string_literal_detector() {
        let mut sld = StringLiteralDetector::new();
        sld.register(0x4000, "hello");
        let e = c(0x4000);
        assert_eq!(sld.detect(&e), Some("hello"));
    }

    #[test]
    fn test_string_literal_var_prefix() {
        let sld = StringLiteralDetector::new();
        let e = var("str_hello");
        assert!(sld.detect(&e).is_some());
    }

    // ── VtableCallDetector ───────────────────────────────────────────────────

    #[test]
    fn test_vtable_call_detector() {
        let vtd = VtableCallDetector::new();
        let callee = Expr::Load {
            ptr: Box::new(binop(BinOp::Add, var("obj"), c(8))),
            size: 8,
        };
        let r = vtd.detect_vtable_call(&callee);
        assert!(r.is_some());
        assert!(r.unwrap().contains("obj"));
    }

    // ── NullCheckEliminator ──────────────────────────────────────────────────

    #[test]
    fn test_null_check_eliminator() {
        let mut nce = NullCheckEliminator::new();
        nce.mark_non_null("p");
        let e = binop(BinOp::Ne, var("p"), c(0));
        let r = nce.eliminate(e);
        assert_eq!(r, Expr::Const(1, IntWidth::U8));
        assert_eq!(nce.eliminated(), 1);
    }

    // ── DeadExprElim ─────────────────────────────────────────────────────────

    #[test]
    fn test_dead_expr_elim() {
        let mut dee = DeadExprElim::new();
        dee.mark_used("x");
        let assigns = vec![
            SsaAssign::new("x", c(1)),
            SsaAssign::new("y", c(2)), // dead
        ];
        let result = dee.filter_assignments(assigns);
        assert_eq!(result.len(), 1);
        assert_eq!(dee.eliminated(), 1);
    }

    // ── BitwiseSimplifier ────────────────────────────────────────────────────

    #[test]
    fn test_bitwise_simplifier_xor_self() {
        let bs = BitwiseSimplifier::new();
        let e = binop(BinOp::Xor, var("x"), var("x"));
        assert_eq!(bs.simplify(e), c(0));
    }

    #[test]
    fn test_bitwise_simplifier_and_ones() {
        let bs = BitwiseSimplifier::new();
        let e = binop(BinOp::And, var("x"), c(-1i64));
        assert_eq!(bs.simplify(e), var("x"));
    }

    #[test]
    fn test_bitwise_simplifier_or_zero() {
        let bs = BitwiseSimplifier::new();
        let e = binop(BinOp::Or, var("x"), c(0));
        assert_eq!(bs.simplify(e), var("x"));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Ordering-aware expression reconstruction with strict side-effect safety.
//
// The existing `ExprFolder` works on an unordered assignment list. This module
// adds a *sequential* statement model so that a single-use temporary is only
// inlined into its use site when nothing between the definition and the use can
// observe or invalidate it — i.e. never across a memory write, a function call,
// a loop boundary, or a definition of a variable the temp depends on.
//
// All of this is purely additive.
// ═════════════════════════════════════════════════════════════════════════════

/// A single statement in a straight-line (basic-block) sequence, retaining the
/// program order so the folder can reason about side-effect barriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// `name = expr;` — an SSA-style definition.
    Assign { name: String, expr: Expr },
    /// `*addr = value;` — a memory write (an ordering barrier).
    Store { addr: Expr, value: Expr },
    /// A bare expression used for its side effects (e.g. a call).
    Effect(Expr),
    /// `return expr;`
    Return(Option<Expr>),
    /// A loop/branch boundary marker — nothing folds across it.
    Barrier,
}

impl Stmt {
    /// Does this statement write to memory or otherwise have a side effect that
    /// later loads/calls might observe?
    #[must_use]
    pub fn is_barrier(&self) -> bool {
        match self {
            Self::Barrier | Self::Store { .. } => true,
            Self::Effect(e) | Self::Return(Some(e)) => has_side_effects(e),
            Self::Assign { expr, .. } => has_side_effects(expr),
            Self::Return(None) => false,
        }
    }

    /// The variable defined by this statement, if any.
    #[must_use]
    pub const fn defined_var(&self) -> Option<&str> {
        match self {
            Self::Assign { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    /// All variables read by this statement.
    #[must_use]
    pub fn read_vars(&self) -> Vec<String> {
        match self {
            Self::Assign { expr, .. } | Self::Effect(expr) => expr.referenced_vars(),
            Self::Store { addr, value } => {
                let mut v = addr.referenced_vars();
                v.extend(value.referenced_vars());
                v
            }
            Self::Return(Some(e)) => e.referenced_vars(),
            Self::Return(None) | Self::Barrier => Vec::new(),
        }
    }
}

/// Whether an expression performs a memory load (which a later store could
/// invalidate if reordered).
#[must_use]
pub fn contains_load(expr: &Expr) -> bool {
    match expr {
        Expr::Load { .. } | Expr::UnOp(UnOp::Deref, _) => true,
        Expr::Const(_, _) | Expr::Var(_) => false,
        Expr::UnOp(_, e) => contains_load(e),
        Expr::BinOp(_, a, b) => contains_load(a) || contains_load(b),
        Expr::FieldAccess { base, .. } => contains_load(base),
        Expr::Index { base, index, .. } => contains_load(base) || contains_load(index),
        Expr::Call { callee, args } => contains_load(callee) || args.iter().any(contains_load),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => contains_load(cond) || contains_load(then_expr) || contains_load(else_expr),
        Expr::Phi(es) => es.iter().any(contains_load),
    }
}

/// Whether an expression contains a function call.
#[must_use]
pub fn contains_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } => true,
        Expr::Const(_, _) | Expr::Var(_) => false,
        Expr::UnOp(_, e) | Expr::Load { ptr: e, .. } => contains_call(e),
        Expr::BinOp(_, a, b) => contains_call(a) || contains_call(b),
        Expr::FieldAccess { base, .. } => contains_call(base),
        Expr::Index { base, index, .. } => contains_call(base) || contains_call(index),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => contains_call(cond) || contains_call(then_expr) || contains_call(else_expr),
        Expr::Phi(es) => es.iter().any(contains_call),
    }
}

/// Configuration for the sequential folder.
#[derive(Debug, Clone)]
pub struct FoldConfig {
    /// Maximum depth of an expression that may be inlined when the temp has
    /// more than one use (single-use temps are always candidates).
    pub max_inline_depth: usize,
    /// If `true`, never inline an expression that loads memory across any
    /// barrier (the default, for correctness).
    pub conservative_loads: bool,
    /// If `true`, never inline expressions containing calls when there is more
    /// than one use (calls must execute exactly once).
    pub protect_calls: bool,
}

impl Default for FoldConfig {
    fn default() -> Self {
        Self {
            max_inline_depth: 4,
            conservative_loads: true,
            protect_calls: true,
        }
    }
}

/// Folds single-use temporaries into their use sites while respecting program
/// order and side-effect barriers.
#[derive(Debug)]
#[derive(Default)]
pub struct SequentialFolder {
    config: FoldConfig,
    inlined: usize,
}


impl SequentialFolder {
    /// New folder with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// New folder with a custom config.
    #[must_use]
    pub const fn with_config(config: FoldConfig) -> Self {
        Self { config, inlined: 0 }
    }

    /// How many temporaries were inlined by the last `fold` call.
    #[must_use]
    pub const fn inlined_count(&self) -> usize {
        self.inlined
    }

    /// Count uses of every variable across the whole sequence.
    fn count_uses(stmts: &[Stmt]) -> HashMap<String, usize> {
        let mut uses: HashMap<String, usize> = HashMap::new();
        for s in stmts {
            for v in s.read_vars() {
                *uses.entry(v).or_insert(0) += 1;
            }
        }
        uses
    }

    /// Fold the sequence. Returns a new statement list with single-use temps
    /// inlined wherever it is provably safe.
    #[must_use]
    pub fn fold(&mut self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        self.inlined = 0;
        let uses = Self::count_uses(&stmts);

        // Ordered list of deferred inlinable definitions: (name, expr).
        // A deferred def is "consumed" when its single use is rewritten, or
        // "flushed" (emitted as a real statement) when a barrier, redefinition,
        // or aliasing event would make inlining unsafe.
        let mut deferred: Vec<(String, Expr)> = Vec::new();
        // Remaining uses of each deferred temp; when it reaches zero the temp
        // is dropped from `deferred` (fully inlined).
        let mut remaining: HashMap<String, usize> = HashMap::new();
        let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());

        for stmt in stmts {
            // Rewrite this statement, consuming any deferred temps it uses.
            let rewritten = Self::rewrite_stmt(stmt, &mut deferred, &mut remaining);

            match &rewritten {
                Stmt::Assign { name, expr } => {
                    // Redefinition of `name` makes any deferred def reading it
                    // stale: flush those defs before recording the new one.
                    self.inlined -=
                        Self::flush_if(&mut deferred, &mut out, |e| e.contains_var(name));

                    let use_count = uses.get(name).copied().unwrap_or(0);
                    if self.is_inlinable(name, expr, use_count) {
                        deferred.push((name.clone(), expr.clone()));
                        remaining.insert(name.clone(), use_count);
                        self.inlined += 1;
                        continue;
                    }
                    out.push(rewritten);
                }
                Stmt::Store { .. } => {
                    // A store may alias any pending load: flush load-bearing defs
                    // before emitting the store.
                    if self.config.conservative_loads {
                        self.inlined -= Self::flush_if(&mut deferred, &mut out, contains_load);
                    } else {
                        self.inlined -= Self::flush_all(&mut deferred, &mut out);
                    }
                    out.push(rewritten);
                }
                Stmt::Effect(e) | Stmt::Return(Some(e)) => {
                    if contains_call(e) {
                        self.inlined -= Self::flush_if(&mut deferred, &mut out, contains_load);
                    }
                    out.push(rewritten);
                }
                Stmt::Barrier => {
                    self.inlined -= Self::flush_all(&mut deferred, &mut out);
                    out.push(rewritten);
                }
                Stmt::Return(None) => {
                    out.push(rewritten);
                }
            }
        }

        // Flush anything still pending (e.g. dead temps, or multi-use temps
        // that were partially consumed).
        self.inlined -= Self::flush_all(&mut deferred, &mut out);
        out
    }

    /// Emit (as real `Assign` statements) every deferred def matching `pred`,
    /// preserving order. Returns the number flushed (so the inline count can be
    /// corrected).
    fn flush_if<F: Fn(&Expr) -> bool>(
        deferred: &mut Vec<(String, Expr)>,
        out: &mut Vec<Stmt>,
        pred: F,
    ) -> usize {
        let mut kept = Vec::with_capacity(deferred.len());
        let mut flushed = 0;
        for (name, expr) in std::mem::take(deferred) {
            if pred(&expr) {
                out.push(Stmt::Assign { name, expr });
                flushed += 1;
            } else {
                kept.push((name, expr));
            }
        }
        *deferred = kept;
        flushed
    }

    /// Emit all deferred defs in order. Returns the number flushed.
    fn flush_all(deferred: &mut Vec<(String, Expr)>, out: &mut Vec<Stmt>) -> usize {
        let drained = std::mem::take(deferred);
        let n = drained.len();
        for (name, expr) in drained {
            out.push(Stmt::Assign { name, expr });
        }
        n
    }

    /// Whether `name = expr` may be inlined given its total use count.
    fn is_inlinable(&self, name: &str, expr: &Expr, use_count: usize) -> bool {
        // Never inline a phi (must be eliminated first).
        if matches!(expr, Expr::Phi(_)) {
            return false;
        }
        // A self-referential definition cannot be inlined.
        if expr.contains_var(name) {
            return false;
        }
        match use_count {
            0 => false, // dead — leave it for DCE rather than silently dropping
            1 => {
                // Single use: safe unless it contains a call we must order and
                // the call would move. Single-use is the canonical fold case,
                // and we already guard barriers between def and use, so allow.
                true
            }
            _ => {
                // Multiple uses: only inline pure, shallow expressions.
                if self.config.protect_calls && contains_call(expr) {
                    return false;
                }
                if self.config.conservative_loads && contains_load(expr) {
                    return false;
                }
                !has_side_effects(expr) && expr.depth() <= self.config.max_inline_depth
            }
        }
    }

    /// Rewrite a statement by substituting any deferred inlinable temps.
    fn rewrite_stmt(
        stmt: Stmt,
        deferred: &mut Vec<(String, Expr)>,
        remaining: &mut HashMap<String, usize>,
    ) -> Stmt {
        match stmt {
            Stmt::Assign { name, expr } => Stmt::Assign {
                name,
                expr: Self::rewrite_expr(expr, deferred, remaining),
            },
            Stmt::Store { addr, value } => Stmt::Store {
                addr: Self::rewrite_expr(addr, deferred, remaining),
                value: Self::rewrite_expr(value, deferred, remaining),
            },
            Stmt::Effect(e) => Stmt::Effect(Self::rewrite_expr(e, deferred, remaining)),
            Stmt::Return(Some(e)) => Stmt::Return(Some(Self::rewrite_expr(e, deferred, remaining))),
            Stmt::Return(None) => Stmt::Return(None),
            Stmt::Barrier => Stmt::Barrier,
        }
    }

    /// Substitute deferred temps into an expression. A temp is dropped from
    /// `deferred` only once all of its uses have been consumed; multi-use temps
    /// stay available so every use is inlined consistently.
    fn rewrite_expr(
        expr: Expr,
        deferred: &mut Vec<(String, Expr)>,
        remaining: &mut HashMap<String, usize>,
    ) -> Expr {
        match expr {
            Expr::Var(ref name) => {
                deferred.iter().position(|(n, _)| n == name).map_or_else(|| expr.clone(), |idx| {
                    let def = deferred[idx].1.clone();
                    // Decrement remaining uses; drop when exhausted.
                    let left = remaining.get(name).copied().unwrap_or(1).saturating_sub(1);
                    if left == 0 {
                        deferred.remove(idx);
                        remaining.remove(name);
                    } else {
                        remaining.insert(name.clone(), left);
                    }
                    // Recursively rewrite the inlined definition too.
                    Self::rewrite_expr(def, deferred, remaining)
                })
            }
            Expr::BinOp(op, a, b) => {
                let a = Self::rewrite_expr(*a, deferred, remaining);
                let b = Self::rewrite_expr(*b, deferred, remaining);
                Expr::BinOp(op, Box::new(a), Box::new(b))
            }
            Expr::UnOp(op, e) => {
                Expr::UnOp(op, Box::new(Self::rewrite_expr(*e, deferred, remaining)))
            }
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(Self::rewrite_expr(*ptr, deferred, remaining)),
                size,
            },
            Expr::FieldAccess { base, offset } => Expr::FieldAccess {
                base: Box::new(Self::rewrite_expr(*base, deferred, remaining)),
                offset,
            },
            Expr::Index {
                base,
                index,
                elem_size,
            } => Expr::Index {
                base: Box::new(Self::rewrite_expr(*base, deferred, remaining)),
                index: Box::new(Self::rewrite_expr(*index, deferred, remaining)),
                elem_size,
            },
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(Self::rewrite_expr(*callee, deferred, remaining)),
                args: args
                    .into_iter()
                    .map(|a| Self::rewrite_expr(a, deferred, remaining))
                    .collect(),
            },
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Expr::Ternary {
                cond: Box::new(Self::rewrite_expr(*cond, deferred, remaining)),
                then_expr: Box::new(Self::rewrite_expr(*then_expr, deferred, remaining)),
                else_expr: Box::new(Self::rewrite_expr(*else_expr, deferred, remaining)),
            },
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Precedence-aware C expression printer (full operator coverage)
// ─────────────────────────────────────────────────────────────────────────────

/// C precedence levels matching the standard grammar (higher binds tighter).
#[must_use]
pub const fn c_binop_precedence(op: BinOp) -> u8 {
    match op {
        BinOp::LOr => 4,
        BinOp::LAnd => 5,
        BinOp::Or => 6,
        BinOp::Xor => 7,
        BinOp::And => 8,
        BinOp::Eq | BinOp::Ne => 9,
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => 10,
        BinOp::Shl | BinOp::Shr | BinOp::Sar => 11,
        BinOp::Add | BinOp::Sub => 12,
        BinOp::Mul | BinOp::Div | BinOp::Mod => 13,
    }
}

/// Unary precedence (binds tighter than any binary op).
pub const C_UNARY_PRECEDENCE: u8 = 14;
/// Postfix / primary precedence (calls, indexing, member access).
pub const C_POSTFIX_PRECEDENCE: u8 = 15;

/// A precedence-correct, minimally-parenthesised C rebuilder for [`Expr`].
#[derive(Debug, Clone)]
pub struct CExprRebuilder {
    /// Render constants in hex when their magnitude exceeds this threshold.
    pub hex_threshold: i64,
    /// Whether right operands of left-associative ops get a +1 precedence bump
    /// (so `a - (b - c)` keeps its parentheses).
    pub respect_associativity: bool,
}

impl Default for CExprRebuilder {
    fn default() -> Self {
        Self {
            hex_threshold: 256,
            respect_associativity: true,
        }
    }
}

impl CExprRebuilder {
    /// New rebuilder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Render `expr` to a minimally-parenthesised C string.
    #[must_use]
    pub fn rebuild(&self, expr: &Expr) -> String {
        self.go(expr, 0)
    }

    fn go(&self, expr: &Expr, parent_prec: u8) -> String {
        match expr {
            Expr::Const(v, w) => self.constant(*v, *w),
            Expr::Var(n) => n.clone(),
            Expr::BinOp(op, a, b) => {
                let prec = c_binop_precedence(*op);
                let right_bump = u8::from(self.respect_associativity && !op.is_commutative());
                let left = self.go(a, prec);
                let right = self.go(b, prec + right_bump);
                let s = format!("{left} {} {right}", op.as_str());
                if prec < parent_prec {
                    format!("({s})")
                } else {
                    s
                }
            }
            Expr::UnOp(op, e) => {
                let inner = self.go(e, C_UNARY_PRECEDENCE);
                let s = match op {
                    UnOp::Cast(w) => format!("({}){inner}", int_width_cname(*w)),
                    UnOp::Deref => format!("*{inner}"),
                    UnOp::AddrOf => format!("&{inner}"),
                    UnOp::Neg => format!("-{inner}"),
                    UnOp::Not => format!("~{inner}"),
                    UnOp::LNot => format!("!{inner}"),
                };
                if C_UNARY_PRECEDENCE < parent_prec {
                    format!("({s})")
                } else {
                    s
                }
            }
            Expr::Load { ptr, size } => {
                let inner = self.go(ptr, C_UNARY_PRECEDENCE);
                format!("*({}*){inner}", load_cast(*size))
            }
            Expr::FieldAccess { base, offset } => {
                let b = self.go(base, C_POSTFIX_PRECEDENCE);
                format!("{b}->field_{offset:x}")
            }
            Expr::Index { base, index, .. } => {
                let b = self.go(base, C_POSTFIX_PRECEDENCE);
                let i = self.go(index, 0);
                format!("{b}[{i}]")
            }
            Expr::Call { callee, args } => {
                let c = self.go(callee, C_POSTFIX_PRECEDENCE);
                let a: Vec<String> = args.iter().map(|x| self.go(x, 1)).collect();
                format!("{c}({})", a.join(", "))
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                // Ternary has precedence 3 (just above assignment).
                let cc = self.go(cond, 4);
                let t = self.go(then_expr, 0);
                let e = self.go(else_expr, 3);
                let s = format!("{cc} ? {t} : {e}");
                if parent_prec > 3 { format!("({s})") } else { s }
            }
            Expr::Phi(es) => {
                let parts: Vec<String> = es.iter().map(|x| self.go(x, 0)).collect();
                format!("phi({})", parts.join(", "))
            }
        }
    }

    fn constant(&self, v: i64, w: IntWidth) -> String {
        if v.abs() < self.hex_threshold {
            return format!("{v}");
        }
        let suffix = match w {
            IntWidth::U32 => "U",
            IntWidth::U64 => "ULL",
            IntWidth::I64 => "LL",
            _ => "",
        };
        if v < 0 {
            format!("-0x{:X}{suffix}", v.unsigned_abs())
        } else {
            format!("0x{v:X}{suffix}")
        }
    }
}

/// The C type to cast through for a load of the given byte size.
#[must_use]
const fn load_cast(size: u8) -> &'static str {
    match size {
        1 => "uint8_t ",
        2 => "uint16_t ",
        4 => "uint32_t ",
        _ => "uint64_t ",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the ordering-aware folder and rebuilder
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod sequential_fold_tests {
    use super::*;

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }
    fn load(ptr: Expr) -> Expr {
        Expr::Load {
            ptr: Box::new(ptr),
            size: 8,
        }
    }
    fn call(name: &str, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Box::new(var(name)),
            args,
        }
    }

    // ── basic folding ──────────────────────────────────────────────────────

    #[test]
    fn test_fold_single_use_temp() {
        // t = a + b; r = t * 2;  →  r = (a + b) * 2;
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: binop(BinOp::Add, var("a"), var("b")),
            },
            Stmt::Assign {
                name: "r".into(),
                expr: binop(BinOp::Mul, var("t"), c(2)),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert_eq!(out.len(), 1);
        assert_eq!(folder.inlined_count(), 1);
        if let Stmt::Assign { expr, .. } = &out[0] {
            assert_eq!(
                *expr,
                binop(BinOp::Mul, binop(BinOp::Add, var("a"), var("b")), c(2))
            );
        } else {
            panic!("expected assign");
        }
    }

    #[test]
    fn test_fold_chain() {
        // t0 = a + 1; t1 = t0 * 2; r = t1 - 3;
        let stmts = vec![
            Stmt::Assign {
                name: "t0".into(),
                expr: binop(BinOp::Add, var("a"), c(1)),
            },
            Stmt::Assign {
                name: "t1".into(),
                expr: binop(BinOp::Mul, var("t0"), c(2)),
            },
            Stmt::Assign {
                name: "r".into(),
                expr: binop(BinOp::Sub, var("t1"), c(3)),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert_eq!(out.len(), 1);
        assert_eq!(folder.inlined_count(), 2);
    }

    // ── side-effect safety: the critical requirement ──────────────────────────

    #[test]
    fn test_load_not_folded_across_store() {
        // t = *p;  *q = 5;  r = t;
        // The load temp MUST NOT be inlined past the store (aliasing).
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: load(var("p")),
            },
            Stmt::Store {
                addr: var("q"),
                value: c(5),
            },
            Stmt::Assign {
                name: "r".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        // t's definition must survive (not inlined into r past the store).
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
        assert_eq!(folder.inlined_count(), 0);
    }

    #[test]
    fn test_load_folded_when_no_store_between() {
        // t = *p; r = t + 1;  (no barrier) → fold
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: load(var("p")),
            },
            Stmt::Assign {
                name: "r".into(),
                expr: binop(BinOp::Add, var("t"), c(1)),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert_eq!(out.len(), 1);
        assert_eq!(folder.inlined_count(), 1);
    }

    #[test]
    fn test_load_not_folded_across_call() {
        // t = *p; foo(); r = t;  → t survives (call may write memory)
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: load(var("p")),
            },
            Stmt::Effect(call("foo", vec![])),
            Stmt::Assign {
                name: "r".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
        assert_eq!(folder.inlined_count(), 0);
    }

    #[test]
    fn test_not_folded_across_barrier() {
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: binop(BinOp::Add, var("a"), var("b")),
            },
            Stmt::Barrier,
            Stmt::Assign {
                name: "r".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
        assert_eq!(folder.inlined_count(), 0);
    }

    #[test]
    fn test_not_folded_when_source_var_redefined() {
        // t = a + 1; a = 99; r = t;  → t must NOT capture the new a.
        // Because t was defined before a was redefined, inlining t into r is
        // still correct (t = old a + 1). But the folder must not let the new a
        // leak. Here single-use t with no barrier between → inlined, and it
        // already captured `a` at def time, so result references `a`.
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: binop(BinOp::Add, var("a"), c(1)),
            },
            Stmt::Assign {
                name: "a".into(),
                expr: c(99),
            },
            Stmt::Assign {
                name: "r".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        // The redefinition of `a` invalidates the available `t` (which reads a),
        // so t is emitted, not inlined.
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
    }

    #[test]
    fn test_multi_use_pure_shallow_inlined() {
        // t = a + b (pure, shallow); used twice → inlined into both.
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: binop(BinOp::Add, var("a"), var("b")),
            },
            Stmt::Assign {
                name: "x".into(),
                expr: var("t"),
            },
            Stmt::Assign {
                name: "y".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        // t inlined into both x and y.
        assert!(!out.iter().any(|s| s.defined_var() == Some("t")));
        for s in &out {
            if let Stmt::Assign { name, expr } = s
                && (name == "x" || name == "y")
            {
                assert!(expr.contains_var("a"));
            }
        }
    }

    #[test]
    fn test_multi_use_call_not_inlined() {
        // t = foo(); used twice → must NOT inline (would call foo twice).
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: call("foo", vec![]),
            },
            Stmt::Assign {
                name: "x".into(),
                expr: var("t"),
            },
            Stmt::Assign {
                name: "y".into(),
                expr: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
    }

    #[test]
    fn test_dead_temp_preserved() {
        // t never used → preserved (for a later DCE pass), not silently dropped.
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: c(5),
            },
            Stmt::Return(Some(c(0))),
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert!(out.iter().any(|s| s.defined_var() == Some("t")));
    }

    #[test]
    fn test_fold_into_store_value() {
        // t = a + b; *p = t;  → *p = a + b;
        let stmts = vec![
            Stmt::Assign {
                name: "t".into(),
                expr: binop(BinOp::Add, var("a"), var("b")),
            },
            Stmt::Store {
                addr: var("p"),
                value: var("t"),
            },
        ];
        let mut folder = SequentialFolder::new();
        let out = folder.fold(stmts);
        assert_eq!(out.len(), 1);
        if let Stmt::Store { value, .. } = &out[0] {
            assert!(value.contains_var("a"));
        } else {
            panic!("expected store");
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    #[test]
    fn test_contains_load() {
        assert!(contains_load(&load(var("p"))));
        assert!(!contains_load(&binop(BinOp::Add, var("a"), c(1))));
        assert!(contains_load(&binop(BinOp::Add, load(var("p")), c(1))));
    }

    #[test]
    fn test_contains_call() {
        assert!(contains_call(&call("f", vec![])));
        assert!(!contains_call(&var("x")));
    }

    #[test]
    fn test_stmt_barrier_classification() {
        assert!(Stmt::Barrier.is_barrier());
        assert!(
            Stmt::Store {
                addr: var("p"),
                value: c(1)
            }
            .is_barrier()
        );
        assert!(
            !Stmt::Assign {
                name: "x".into(),
                expr: c(1)
            }
            .is_barrier()
        );
        assert!(Stmt::Effect(call("f", vec![])).is_barrier());
    }

    // ── CExprRebuilder ──────────────────────────────────────────────────────

    #[test]
    fn test_rebuild_simple() {
        let r = CExprRebuilder::new();
        let e = binop(BinOp::Add, var("a"), var("b"));
        assert_eq!(r.rebuild(&e), "a + b");
    }

    #[test]
    fn test_rebuild_precedence_mul_over_add() {
        let r = CExprRebuilder::new();
        // a + b * c  → no parens around b*c
        let e = binop(BinOp::Add, var("a"), binop(BinOp::Mul, var("b"), var("c")));
        assert_eq!(r.rebuild(&e), "a + b * c");
    }

    #[test]
    fn test_rebuild_precedence_needs_parens() {
        let r = CExprRebuilder::new();
        // (a + b) * c  → parens around a+b
        let e = binop(BinOp::Mul, binop(BinOp::Add, var("a"), var("b")), var("c"));
        assert_eq!(r.rebuild(&e), "(a + b) * c");
    }

    #[test]
    fn test_rebuild_left_assoc_subtraction() {
        let r = CExprRebuilder::new();
        // a - (b - c) keeps parens; (a - b) - c does not
        let nested_right = binop(BinOp::Sub, var("a"), binop(BinOp::Sub, var("b"), var("c")));
        assert_eq!(r.rebuild(&nested_right), "a - (b - c)");
        let nested_left = binop(BinOp::Sub, binop(BinOp::Sub, var("a"), var("b")), var("c"));
        assert_eq!(r.rebuild(&nested_left), "a - b - c");
    }

    #[test]
    fn test_rebuild_unary() {
        let r = CExprRebuilder::new();
        let e = Expr::UnOp(UnOp::Neg, Box::new(binop(BinOp::Add, var("a"), var("b"))));
        // -(a + b)
        assert_eq!(r.rebuild(&e), "-(a + b)");
    }

    #[test]
    fn test_rebuild_call_and_index() {
        let r = CExprRebuilder::new();
        let e = Expr::Index {
            base: Box::new(var("arr")),
            index: Box::new(binop(BinOp::Add, var("i"), c(1))),
            elem_size: 4,
        };
        assert_eq!(r.rebuild(&e), "arr[i + 1]");
    }

    #[test]
    fn test_rebuild_const_hex() {
        let r = CExprRebuilder::new();
        assert_eq!(r.rebuild(&c(10)), "10");
        let big = Expr::Const(0x1000, IntWidth::U32);
        assert_eq!(r.rebuild(&big), "0x1000U");
    }

    #[test]
    fn test_rebuild_logical_precedence() {
        let r = CExprRebuilder::new();
        // a || b && c  → no parens (&& binds tighter)
        let e = binop(BinOp::LOr, var("a"), binop(BinOp::LAnd, var("b"), var("c")));
        assert_eq!(r.rebuild(&e), "a || b && c");
        // (a || b) && c  → parens
        let e2 = binop(BinOp::LAnd, binop(BinOp::LOr, var("a"), var("b")), var("c"));
        assert_eq!(r.rebuild(&e2), "(a || b) && c");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprComplexityAnalyzer — complexity metrics for an expression tree
// ─────────────────────────────────────────────────────────────────────────────

/// Complexity metrics computed over an [`Expr`] tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprComplexity {
    /// Maximum nesting depth of the expression tree.
    pub depth: u32,
    /// Number of leaf nodes (constants and variable references).
    pub leaf_count: u32,
    /// Number of operator nodes (binary + unary, including casts).
    pub op_count: u32,
    /// Whether the expression is free of observable side-effects.
    pub is_pure: bool,
}

impl ExprComplexity {
    /// Compute the scalar complexity score: `op_count * 2 + depth`.
    ///
    /// Higher scores indicate expressions that are harder to read at a glance.
    #[must_use]
    pub const fn complexity_score(&self) -> u32 {
        self.op_count * 2 + self.depth
    }
}

/// Analyses an [`Expr`] tree and produces an [`ExprComplexity`] report.
#[derive(Debug, Default, Clone)]
pub struct ExprComplexityAnalyzer;

impl ExprComplexityAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `expr` and return the full [`ExprComplexity`] breakdown.
    #[must_use]
    pub fn analyze(&self, expr: &Expr) -> ExprComplexity {
        let (depth, leaf_count, op_count) = Self::walk(expr);
        ExprComplexity {
            depth,
            leaf_count,
            op_count,
            is_pure: !has_side_effects(expr),
        }
    }

    /// Returns `(depth, leaf_count, op_count)`.
    fn walk(expr: &Expr) -> (u32, u32, u32) {
        match expr {
            Expr::Const(_, _) | Expr::Var(_) => (1, 1, 0),
            Expr::UnOp(_, inner) => {
                let (d, l, o) = Self::walk(inner);
                (d + 1, l, o + 1)
            }
            Expr::BinOp(_, a, b) => {
                let (da, la, oa) = Self::walk(a);
                let (db, lb, ob) = Self::walk(b);
                (da.max(db) + 1, la + lb, oa + ob + 1)
            }
            Expr::Load { ptr, .. } => {
                let (d, l, o) = Self::walk(ptr);
                (d + 1, l, o + 1)
            }
            Expr::FieldAccess { base, .. } => {
                let (d, l, o) = Self::walk(base);
                (d + 1, l, o + 1)
            }
            Expr::Index { base, index, .. } => {
                let (db, lb, ob) = Self::walk(base);
                let (di, li, oi) = Self::walk(index);
                (db.max(di) + 1, lb + li, ob + oi + 1)
            }
            Expr::Call { callee, args } => {
                let (dc, lc, oc) = Self::walk(callee);
                let (dargs, largs, oargs) =
                    args.iter().fold((0u32, 0u32, 0u32), |(da, la, oa), a| {
                        let (d, l, o) = Self::walk(a);
                        (da.max(d), la + l, oa + o)
                    });
                (dc.max(dargs) + 1, lc + largs, oc + oargs + 1)
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let (dc, lc, oc) = Self::walk(cond);
                let (dt, lt, ot) = Self::walk(then_expr);
                let (de, le, oe) = Self::walk(else_expr);
                (dc.max(dt).max(de) + 1, lc + lt + le, oc + ot + oe + 1)
            }
            Expr::Phi(exprs) => {
                let (dmax, ltot, otot) =
                    exprs.iter().fold((0u32, 0u32, 0u32), |(da, la, oa), e| {
                        let (d, l, o) = Self::walk(e);
                        (da.max(d), la + l, oa + o)
                    });
                (dmax + 1, ltot, otot)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprToC — precedence-aware C string emission for Expr trees
// ─────────────────────────────────────────────────────────────────────────────

/// Converts an [`Expr`] tree to a C-like string representation.
///
/// Uses operator precedence to insert parentheses only where needed, producing
/// output that matches standard C conventions.
#[derive(Debug, Default, Clone)]
pub struct ExprToC;

impl ExprToC {
    /// Create a new converter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert `expr` to its C string representation.
    #[must_use]
    pub fn to_c_string(&self, expr: &Expr) -> String {
        Self::emit(expr, 0)
    }

    /// Emit with a minimum outer precedence: wrap in parens when the
    /// expression's own precedence is lower than `min_prec`.
    fn emit(expr: &Expr, min_prec: u8) -> String {
        match expr {
            Expr::Const(v, w) => Self::emit_const(*v, *w),
            Expr::Var(n) => n.clone(),

            Expr::BinOp(op, lhs, rhs) => {
                let prec = op.precedence();
                // Right operand uses prec+1 so that same-precedence right
                // sub-trees are parenthesised (left-associativity).
                let ls = Self::emit(lhs, prec);
                let rs = Self::emit(rhs, prec + 1);
                let s = format!("{ls} {} {rs}", op.as_str());
                if prec < min_prec { format!("({s})") } else { s }
            }

            Expr::UnOp(op, inner) => {
                // Unary operators bind very tightly; use precedence 15.
                let inner_s = Self::emit(inner, 15);
                match op {
                    UnOp::Deref => format!("*{inner_s}"),
                    UnOp::AddrOf => format!("&{inner_s}"),
                    UnOp::Neg => format!("-{inner_s}"),
                    UnOp::Not => format!("~{inner_s}"),
                    UnOp::LNot => format!("!{inner_s}"),
                    UnOp::Cast(w) => format!("({}){inner_s}", int_width_cname(*w)),
                }
            }

            Expr::Load { ptr, size } => {
                let inner_s = Self::emit(ptr, 15);
                // Emit as a typed dereference: *(uintN_t *)ptr
                format!("*(uint{}_t *){inner_s}", size * 8)
            }

            Expr::FieldAccess { base, offset } => {
                let base_s = Self::emit(base, 15);
                format!("FIELD({base_s}, {offset:#x})")
            }

            Expr::Index { base, index, .. } => {
                let base_s = Self::emit(base, 0);
                let idx_s = Self::emit(index, 0);
                format!("{base_s}[{idx_s}]")
            }

            Expr::Call { callee, args } => {
                let callee_s = Self::emit(callee, 0);
                let args_s: Vec<String> = args.iter().map(|a| Self::emit(a, 0)).collect();
                format!("{callee_s}({})", args_s.join(", "))
            }

            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let c = Self::emit(cond, 0);
                let t = Self::emit(then_expr, 0);
                let e = Self::emit(else_expr, 0);
                let s = format!("{c} ? {t} : {e}");
                if 3 < min_prec {
                    // Ternary has very low precedence (3).
                    format!("({s})")
                } else {
                    s
                }
            }

            Expr::Phi(exprs) => {
                let parts: Vec<String> = exprs.iter().map(|e| Self::emit(e, 0)).collect();
                format!("phi({})", parts.join(", "))
            }
        }
    }

    fn emit_const(v: i64, w: IntWidth) -> String {
        if (0..1000).contains(&v) {
            return format!("{v}");
        }
        match w {
            IntWidth::U8 | IntWidth::U16 | IntWidth::U32 => format!("0x{:X}U", i64_as_u64(v)),
            IntWidth::U64 => format!("0x{:X}ULL", i64_as_u64(v)),
            IntWidth::I64 => {
                if v < 0 {
                    format!("-0x{:X}LL", v.unsigned_abs())
                } else {
                    format!("0x{v:X}LL")
                }
            }
            _ => format!("0x{v:X}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprTypeChecker — infer expression types from operand information
// ─────────────────────────────────────────────────────────────────────────────

/// A simple inferred type for an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// Integer with a given bit-width and signedness.
    Int { bits: u8, signed: bool },
    /// Floating-point with a given bit-width (32 or 64).
    Float { bits: u8 },
    /// Pointer to an inner type.
    Pointer(Box<Self>),
    /// Type could not be determined.
    Unknown,
}

impl InferredType {
    /// Return the bit-width if this is an integer or float type.
    #[must_use]
    pub const fn bits(&self) -> Option<u8> {
        match self {
            Self::Int { bits, .. } | Self::Float { bits } => Some(*bits),
            _ => None,
        }
    }

    /// Is this a signed integer type?
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        matches!(self, Self::Int { signed: true, .. })
    }

    /// Is this a pointer type?
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }
}

impl fmt::Display for InferredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int { bits, signed } => {
                let prefix = if *signed { "int" } else { "uint" };
                write!(f, "{prefix}{bits}_t")
            }
            Self::Float { bits } => {
                write!(f, "{}", if *bits == 32 { "float" } else { "double" })
            }
            Self::Pointer(inner) => write!(f, "{inner} *"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// Infers the type of an [`Expr`] tree based on its structure and operand
/// widths.  This is a best-effort analysis: unknown sub-trees produce
/// [`InferredType::Unknown`].
#[derive(Debug, Default, Clone)]
pub struct ExprTypeChecker;

impl ExprTypeChecker {
    /// Create a new type checker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Infer the type of `expr`.
    #[must_use]
    pub fn infer_type(&self, expr: &Expr) -> InferredType {
        match expr {
            Expr::Const(_, w) => Self::from_int_width(*w),

            // Variables, field accesses, and calls: unknown target type.
            Expr::Var(_) | Expr::FieldAccess { .. } | Expr::Call { .. } => InferredType::Unknown,

            Expr::BinOp(op, lhs, rhs) => self.infer_binop(*op, lhs, rhs),

            Expr::UnOp(op, inner) => self.infer_unop(*op, inner),

            // A memory load produces an integer of the loaded width.
            Expr::Load { size, .. } => InferredType::Int {
                bits: size.saturating_mul(8),
                signed: false,
            },

            Expr::Index { base, .. } => {
                // If base is a pointer, the result is the pointed-to type.
                match self.infer_type(base) {
                    InferredType::Pointer(inner) => *inner,
                    _ => InferredType::Unknown,
                }
            }

            // Ternary: both arms should agree; take the first non-Unknown one.
            Expr::Ternary {
                then_expr,
                else_expr,
                ..
            } => {
                let t = self.infer_type(then_expr);
                if t != InferredType::Unknown {
                    return t;
                }
                self.infer_type(else_expr)
            }

            Expr::Phi(exprs) => {
                for e in exprs {
                    let t = self.infer_type(e);
                    if t != InferredType::Unknown {
                        return t;
                    }
                }
                InferredType::Unknown
            }
        }
    }

    fn infer_binop(&self, op: BinOp, lhs: &Expr, rhs: &Expr) -> InferredType {
        // Comparisons always produce a 32-bit int (boolean).
        if op.is_comparison() || op.is_logical() {
            return InferredType::Int {
                bits: 32,
                signed: false,
            };
        }

        let lt = self.infer_type(lhs);
        let rt = self.infer_type(rhs);

        // Pointer arithmetic: ptr + int → ptr.
        match (&lt, &rt) {
            (InferredType::Pointer(_), InferredType::Int { .. }) => return lt,
            (InferredType::Int { .. }, InferredType::Pointer(_)) => return rt,
            _ => {}
        }

        // Prefer the wider / more-informative operand type.
        match (&lt, &rt) {
            (InferredType::Unknown, _) => rt,
            (_, InferredType::Unknown) => lt,
            (InferredType::Int { bits: ba, .. }, InferredType::Int { bits: bb, .. }) => {
                if ba >= bb { lt } else { rt }
            }
            (InferredType::Float { .. }, _) | (_, InferredType::Float { .. }) => {
                // Any float contaminates the result.
                if matches!(lt, InferredType::Float { .. }) {
                    lt
                } else {
                    rt
                }
            }
            _ => lt,
        }
    }

    fn infer_unop(&self, op: UnOp, inner: &Expr) -> InferredType {
        match op {
            // Cast to a specific width — the result type is fully determined.
            UnOp::Cast(w) => Self::from_int_width(w),

            // Address-of: wraps whatever inner type we infer.
            UnOp::AddrOf => {
                let inner_t = self.infer_type(inner);
                InferredType::Pointer(Box::new(inner_t))
            }

            // Dereference: unwraps the pointer's inner type.
            UnOp::Deref => match self.infer_type(inner) {
                InferredType::Pointer(t) => *t,
                _ => InferredType::Unknown,
            },

            // Logical NOT always returns int.
            UnOp::LNot => InferredType::Int {
                bits: 32,
                signed: false,
            },

            // Bitwise NOT / arithmetic negation: preserve operand type.
            UnOp::Not | UnOp::Neg => self.infer_type(inner),
        }
    }

    fn from_int_width(w: IntWidth) -> InferredType {
        InferredType::Int {
            bits: u32_trunc_u8(w.bits()),
            signed: w.is_signed(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the three new analysers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod new_expr_tests {
    use super::*;

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn cu32(v: i64) -> Expr {
        Expr::Const(v, IntWidth::U32)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }
    fn unop(op: UnOp, e: Expr) -> Expr {
        Expr::UnOp(op, Box::new(e))
    }

    // ── ExprComplexityAnalyzer ────────────────────────────────────────────────

    #[test]
    fn test_complexity_leaf_const() {
        let a = ExprComplexityAnalyzer::new();
        let m = a.analyze(&c(42));
        assert_eq!(m.depth, 1);
        assert_eq!(m.leaf_count, 1);
        assert_eq!(m.op_count, 0);
        assert!(m.is_pure);
        assert_eq!(m.complexity_score(), 1); // 0*2 + 1
    }

    #[test]
    fn test_complexity_leaf_var() {
        let a = ExprComplexityAnalyzer::new();
        let m = a.analyze(&var("x"));
        assert_eq!(m.depth, 1);
        assert_eq!(m.leaf_count, 1);
        assert_eq!(m.op_count, 0);
        assert!(m.is_pure);
    }

    #[test]
    fn test_complexity_binop() {
        let a = ExprComplexityAnalyzer::new();
        let e = binop(BinOp::Add, var("x"), c(1));
        let m = a.analyze(&e);
        assert_eq!(m.depth, 2);
        assert_eq!(m.leaf_count, 2);
        assert_eq!(m.op_count, 1);
        assert!(m.is_pure);
        assert_eq!(m.complexity_score(), 4); // 1*2 + 2
    }

    #[test]
    fn test_complexity_nested() {
        let a = ExprComplexityAnalyzer::new();
        // (x + 1) * (y - 2)  →  depth=3, 4 leaves, 3 ops
        let e = binop(
            BinOp::Mul,
            binop(BinOp::Add, var("x"), c(1)),
            binop(BinOp::Sub, var("y"), c(2)),
        );
        let m = a.analyze(&e);
        assert_eq!(m.depth, 3);
        assert_eq!(m.leaf_count, 4);
        assert_eq!(m.op_count, 3);
        assert!(m.is_pure);
    }

    #[test]
    fn test_complexity_call_not_pure() {
        let a = ExprComplexityAnalyzer::new();
        let e = Expr::Call {
            callee: Box::new(var("f")),
            args: vec![],
        };
        let m = a.analyze(&e);
        assert!(!m.is_pure);
    }

    #[test]
    fn test_complexity_load_not_pure() {
        let a = ExprComplexityAnalyzer::new();
        let e = Expr::Load {
            ptr: Box::new(var("p")),
            size: 8,
        };
        let m = a.analyze(&e);
        assert!(!m.is_pure);
    }

    #[test]
    fn test_complexity_score_formula() {
        let a = ExprComplexityAnalyzer::new();
        let e = binop(BinOp::Add, var("x"), c(1));
        let m = a.analyze(&e);
        assert_eq!(m.complexity_score(), m.op_count * 2 + m.depth);
    }

    // ── ExprToC ───────────────────────────────────────────────────────────────

    #[test]
    fn test_to_c_const_small() {
        let tc = ExprToC::new();
        assert_eq!(tc.to_c_string(&c(0)), "0");
        assert_eq!(tc.to_c_string(&c(999)), "999");
    }

    #[test]
    fn test_to_c_const_large() {
        let tc = ExprToC::new();
        let s = tc.to_c_string(&c(0x1000));
        assert!(s.starts_with("0x"));
    }

    #[test]
    fn test_to_c_var() {
        let tc = ExprToC::new();
        assert_eq!(tc.to_c_string(&var("myVar")), "myVar");
    }

    #[test]
    fn test_to_c_binop_add() {
        let tc = ExprToC::new();
        let e = binop(BinOp::Add, var("a"), var("b"));
        assert_eq!(tc.to_c_string(&e), "a + b");
    }

    #[test]
    fn test_to_c_precedence_no_parens() {
        // a * b + c  → mul binds tighter, no parens needed
        let tc = ExprToC::new();
        let e = binop(BinOp::Add, binop(BinOp::Mul, var("a"), var("b")), var("c"));
        let s = tc.to_c_string(&e);
        assert!(!s.contains('('));
        assert_eq!(s, "a * b + c");
    }

    #[test]
    fn test_to_c_precedence_parens_required() {
        // (a + b) * c  → add has lower prec than mul, needs parens
        let tc = ExprToC::new();
        let e = binop(BinOp::Mul, binop(BinOp::Add, var("a"), var("b")), var("c"));
        let s = tc.to_c_string(&e);
        assert!(s.contains('('));
        assert_eq!(s, "(a + b) * c");
    }

    #[test]
    fn test_to_c_unop_neg() {
        let tc = ExprToC::new();
        let e = unop(UnOp::Neg, var("x"));
        assert_eq!(tc.to_c_string(&e), "-x");
    }

    #[test]
    fn test_to_c_unop_bitnot() {
        let tc = ExprToC::new();
        let e = unop(UnOp::Not, var("x"));
        assert_eq!(tc.to_c_string(&e), "~x");
    }

    #[test]
    fn test_to_c_unop_lnot() {
        let tc = ExprToC::new();
        let e = unop(UnOp::LNot, var("x"));
        assert_eq!(tc.to_c_string(&e), "!x");
    }

    #[test]
    fn test_to_c_deref() {
        let tc = ExprToC::new();
        let e = unop(UnOp::Deref, var("ptr"));
        assert_eq!(tc.to_c_string(&e), "*ptr");
    }

    #[test]
    fn test_to_c_deref_typed_load() {
        let tc = ExprToC::new();
        let e = Expr::Load {
            ptr: Box::new(var("ptr")),
            size: 4,
        };
        let s = tc.to_c_string(&e);
        assert!(s.contains("uint32_t"));
        assert!(s.contains("ptr"));
    }

    #[test]
    fn test_to_c_cast() {
        let tc = ExprToC::new();
        let e = unop(UnOp::Cast(IntWidth::U32), var("x"));
        let s = tc.to_c_string(&e);
        assert!(s.contains("uint32_t"));
        assert!(s.contains('x'));
    }

    #[test]
    fn test_to_c_comparison_ops() {
        let tc = ExprToC::new();
        for (op, expected) in [
            (BinOp::Eq, "=="),
            (BinOp::Ne, "!="),
            (BinOp::Lt, "<"),
            (BinOp::Le, "<="),
            (BinOp::Gt, ">"),
            (BinOp::Ge, ">="),
        ] {
            let e = binop(op, var("a"), var("b"));
            assert!(tc.to_c_string(&e).contains(expected), "op {expected}");
        }
    }

    #[test]
    fn test_to_c_bitwise_ops() {
        let tc = ExprToC::new();
        for (op, sym) in [
            (BinOp::And, "&"),
            (BinOp::Or, "|"),
            (BinOp::Xor, "^"),
            (BinOp::Shl, "<<"),
            (BinOp::Shr, ">>"),
        ] {
            let e = binop(op, var("a"), var("b"));
            assert!(tc.to_c_string(&e).contains(sym), "op {sym}");
        }
    }

    #[test]
    fn test_to_c_call() {
        let tc = ExprToC::new();
        let e = Expr::Call {
            callee: Box::new(var("foo")),
            args: vec![var("x"), c(1)],
        };
        let s = tc.to_c_string(&e);
        assert_eq!(s, "foo(x, 1)");
    }

    #[test]
    fn test_to_c_index() {
        let tc = ExprToC::new();
        let e = Expr::Index {
            base: Box::new(var("arr")),
            index: Box::new(var("i")),
            elem_size: 4,
        };
        assert_eq!(tc.to_c_string(&e), "arr[i]");
    }

    #[test]
    fn test_to_c_ternary() {
        let tc = ExprToC::new();
        let e = Expr::Ternary {
            cond: Box::new(var("cond")),
            then_expr: Box::new(c(1)),
            else_expr: Box::new(c(0)),
        };
        let s = tc.to_c_string(&e);
        assert!(s.contains('?'));
        assert!(s.contains(':'));
        assert!(s.contains("cond"));
    }

    // ── ExprTypeChecker ───────────────────────────────────────────────────────

    #[test]
    fn test_type_const_i64() {
        let tc = ExprTypeChecker::new();
        let t = tc.infer_type(&c(42));
        assert_eq!(
            t,
            InferredType::Int {
                bits: 64,
                signed: true
            }
        );
    }

    #[test]
    fn test_type_const_u32() {
        let tc = ExprTypeChecker::new();
        let t = tc.infer_type(&cu32(42));
        assert_eq!(
            t,
            InferredType::Int {
                bits: 32,
                signed: false
            }
        );
    }

    #[test]
    fn test_type_var_unknown() {
        let tc = ExprTypeChecker::new();
        assert_eq!(tc.infer_type(&var("x")), InferredType::Unknown);
    }

    #[test]
    fn test_type_comparison_is_int32() {
        let tc = ExprTypeChecker::new();
        let e = binop(BinOp::Eq, var("a"), var("b"));
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 32,
                signed: false
            }
        );
    }

    #[test]
    fn test_type_binop_uses_wider_operand() {
        let tc = ExprTypeChecker::new();
        // i64 + u32 → i64 (wider wins)
        let e = binop(BinOp::Add, c(1), cu32(2));
        let t = tc.infer_type(&e);
        assert_eq!(
            t,
            InferredType::Int {
                bits: 64,
                signed: true
            }
        );
    }

    #[test]
    fn test_type_cast_determines_result() {
        let tc = ExprTypeChecker::new();
        let e = unop(UnOp::Cast(IntWidth::U8), var("x"));
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 8,
                signed: false
            }
        );
    }

    #[test]
    fn test_type_addrof_is_pointer() {
        let tc = ExprTypeChecker::new();
        let e = unop(UnOp::AddrOf, var("x"));
        assert!(tc.infer_type(&e).is_pointer());
    }

    #[test]
    fn test_type_deref_unwraps() {
        let tc = ExprTypeChecker::new();
        // &x has type Pointer(Unknown); *(&x) → Unknown
        let addr = unop(UnOp::AddrOf, var("x"));
        let deref = unop(UnOp::Deref, addr);
        assert_eq!(tc.infer_type(&deref), InferredType::Unknown);
    }

    #[test]
    fn test_type_load_width() {
        let tc = ExprTypeChecker::new();
        let e = Expr::Load {
            ptr: Box::new(var("p")),
            size: 4,
        };
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 32,
                signed: false
            }
        );
    }

    #[test]
    fn test_type_lnot_is_int32() {
        let tc = ExprTypeChecker::new();
        let e = unop(UnOp::LNot, var("x"));
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 32,
                signed: false
            }
        );
    }

    #[test]
    fn test_type_neg_preserves() {
        let tc = ExprTypeChecker::new();
        let e = unop(UnOp::Neg, Expr::Const(1, IntWidth::I32));
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 32,
                signed: true
            }
        );
    }

    #[test]
    fn test_type_ternary_first_arm() {
        let tc = ExprTypeChecker::new();
        let e = Expr::Ternary {
            cond: Box::new(var("c")),
            then_expr: Box::new(Expr::Const(0, IntWidth::U8)),
            else_expr: Box::new(var("x")),
        };
        assert_eq!(
            tc.infer_type(&e),
            InferredType::Int {
                bits: 8,
                signed: false
            }
        );
    }

    #[test]
    fn test_inferred_type_display_int() {
        let t = InferredType::Int {
            bits: 32,
            signed: true,
        };
        assert_eq!(t.to_string(), "int32_t");
    }

    #[test]
    fn test_inferred_type_display_uint() {
        let t = InferredType::Int {
            bits: 64,
            signed: false,
        };
        assert_eq!(t.to_string(), "uint64_t");
    }

    #[test]
    fn test_inferred_type_display_float() {
        let t = InferredType::Float { bits: 32 };
        assert_eq!(t.to_string(), "float");
        let t64 = InferredType::Float { bits: 64 };
        assert_eq!(t64.to_string(), "double");
    }

    #[test]
    fn test_inferred_type_display_pointer() {
        let t = InferredType::Pointer(Box::new(InferredType::Int {
            bits: 32,
            signed: false,
        }));
        assert!(t.to_string().contains("uint32_t"));
        assert!(t.to_string().contains('*'));
    }
}
