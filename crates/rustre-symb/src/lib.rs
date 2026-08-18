//! `rustre-symb` — Symbolic execution core types, expressions, and state.
//!
//! Provides the fundamental data structures for symbolic execution:
//! - [`SymbolicValue`]: a named symbolic value with a type and expression
//! - [`SymType`]: the type system for symbolic values
//! - [`SymExpr`]: full expression AST including bitvector, logic, and memory ops
//! - [`SymbolicState`]: execution state (registers, memory, path condition)
//! - [`SymEngine`]: trait for stepping through instructions symbolically
//! - [`SymExprSimplifier`]: algebraic simplifications
//! - [`path_explosion`]: mitigation strategies for path explosion
//! - [`smt_formula`]: SMT-LIB 2.6 formula generation

pub mod symbolic_memory_model;
pub mod concolic;
pub mod concolic_execution;
pub mod concolic_executor;
pub mod constraint_propagator;
pub mod explosion_mitigation;
pub mod formula_simplifier;
pub mod memory_model;
pub mod path_explorer;
pub mod path_explosion;
pub mod smt_formula;
pub mod vulnerability_finder;
pub mod summary_cache;
pub mod symbolic_execution_engine;
pub mod symbolic_value;
pub mod symbolic_state;
pub mod constraint_solver;

#[cfg(feature = "subcrates")]
pub mod registry {
    //! Re-exports and instance factory for all `rustre-symb-*` backend crates.

    pub use rustre_symb_engine::SymbolicExecutor;
    pub use rustre_symb_taint::TaintState;
    pub use rustre_symb_z3::Z3Solver;
}

use std::collections::HashMap;

use rustre_core::arch::Instruction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Returned when a constraint makes the path condition unsatisfiable.
#[derive(Debug, Error)]
#[error("constraint is unsatisfiable: the path condition became contradictory")]
pub struct Unsat;

#[derive(Debug, Error)]
pub enum SymbolicError {
    #[error("unrecognised instruction: {0}")]
    UnknownInstruction(String),
    #[error("unsupported expression type for operation")]
    TypeMismatch,
    #[error("expression width mismatch: expected {expected}, got {got}")]
    WidthMismatch { expected: u32, got: u32 },
    #[error("invalid extract indices: hi={hi} lo={lo}")]
    InvalidExtract { hi: u32, lo: u32 },
    #[error("division by zero in symbolic expression")]
    DivisionByZero,
    #[error("state explosion: too many states ({0})")]
    StateExplosion(usize),
    #[error("path condition is unsatisfiable")]
    UnsatisfiablePath,
    #[error("memory access out of bounds at address {0:#x}")]
    MemoryOutOfBounds(u64),
    #[error("constraint is unsatisfiable")]
    Unsat,
    #[error("solver error: {0}")]
    SolverError(String),
    #[error("type error in symbolic expression: {0}")]
    TypeError(String),
    #[error("undefined variable in expression: {0}")]
    UndefinedVariable(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ─── SymType ──────────────────────────────────────────────────────────────────

/// Type of a symbolic value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymType {
    Bool,
    BitVec(u32),
    Pointer,
    Array {
        elem_ty: Box<Self>,
        len: Option<usize>,
    },
}

impl SymType {
    /// Return the bitwidth if this is a [`SymType::BitVec`], else `None`.
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        match self {
            Self::BitVec(w) => Some(*w),
            Self::Pointer => Some(64),
            _ => None,
        }
    }
}

// ─── SymExpr ─────────────────────────────────────────────────────────────────

/// Full symbolic expression AST.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymExpr {
    // ── Literals ──────────────────────────────────────────────────────────
    /// A concrete bitvector constant with explicit width.
    ConstBv {
        val: u64,
        width: u32,
    },
    /// A concrete boolean constant.
    ConstBool(bool),

    // ── Variables ─────────────────────────────────────────────────────────
    /// A symbolic input variable.
    Var {
        name: String,
        ty: SymType,
    },

    // ── Bitvector arithmetic ───────────────────────────────────────────────
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    /// Unsigned division.
    UDiv(Box<Self>, Box<Self>),
    /// Signed division.
    SDiv(Box<Self>, Box<Self>),
    /// Unsigned remainder.
    URem(Box<Self>, Box<Self>),
    /// Signed remainder.
    SRem(Box<Self>, Box<Self>),

    // ── Bitwise ───────────────────────────────────────────────────────────
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Arithmetic negation (two's complement).
    Neg(Box<Self>),
    /// Logical shift left.
    Shl(Box<Self>, Box<Self>),
    /// Logical shift right (zero-fill).
    LShr(Box<Self>, Box<Self>),
    /// Arithmetic shift right (sign-fill).
    AShr(Box<Self>, Box<Self>),
    /// Concatenate two bitvectors (hi ++ lo).
    Concat(Box<Self>, Box<Self>),
    /// Extract bits [hi:lo] inclusive.
    Extract {
        expr: Box<Self>,
        hi: u32,
        lo: u32,
    },
    /// Zero-extend to `target_width` bits.
    ZExt {
        expr: Box<Self>,
        target_width: u32,
    },
    /// Sign-extend to `target_width` bits.
    SExt {
        expr: Box<Self>,
        target_width: u32,
    },

    // ── Comparison (return Bool) ───────────────────────────────────────────
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    ULt(Box<Self>, Box<Self>),
    ULe(Box<Self>, Box<Self>),
    UGt(Box<Self>, Box<Self>),
    UGe(Box<Self>, Box<Self>),
    SLt(Box<Self>, Box<Self>),
    SLe(Box<Self>, Box<Self>),
    SGt(Box<Self>, Box<Self>),
    SGe(Box<Self>, Box<Self>),

    // ── Boolean logic ─────────────────────────────────────────────────────
    BoolAnd(Box<Self>, Box<Self>),
    BoolOr(Box<Self>, Box<Self>),
    BoolNot(Box<Self>),
    /// If-then-else: `cond ? then_ : else_`.
    Ite {
        cond: Box<Self>,
        then_: Box<Self>,
        else_: Box<Self>,
    },

    // ── Memory ────────────────────────────────────────────────────────────
    /// Load `size` bytes from symbolic memory at `addr`.
    Load {
        addr: Box<Self>,
        size: u8,
    },
    /// Functional update: write `val` to `mem` at `addr`.
    Store {
        mem: Box<Self>,
        addr: Box<Self>,
        val: Box<Self>,
    },
}

impl SymExpr {
    // ── Convenience constructors ──────────────────────────────────────────

    #[must_use]
    pub const fn bv(val: u64, width: u32) -> Self {
        Self::ConstBv { val, width }
    }

    /// Alias of [`SymExpr::bv`]: build a bitvector constant.
    ///
    /// `width` is the bit-width and matches [`ConstBv::width`].
    #[must_use]
    #[allow(non_snake_case)]
    pub const fn Const(val: u64, width: u32) -> Self {
        Self::ConstBv { val, width }
    }

    /// Build a fresh symbolic variable named `path_<id>_<name>` of the given
    /// width. This is an ergonomic constructor used by callers that don't
    /// need to build a [`SymType`] explicitly.
    #[must_use]
    #[allow(non_snake_case)]
    pub fn Symbol(id: u64, width: u32, name: impl Into<String>) -> Self {
        let n = name.into();
        Self::Var {
            name: format!("{n}_{id}"),
            ty: SymType::BitVec(width),
        }
    }

    /// Tuple-style constructor for the `Ite` struct variant.
    #[must_use]
    #[allow(non_snake_case)]
    pub const fn Ite(cond: Box<Self>, then_: Box<Self>, else_: Box<Self>) -> Self {
        Self::Ite { cond, then_, else_ }
    }

    #[must_use]
    pub fn var(name: impl Into<String>, ty: SymType) -> Self {
        Self::Var {
            name: name.into(),
            ty,
        }
    }

    #[must_use]
    pub fn add_expr(lhs: Self, rhs: Self) -> Self {
        Self::Add(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn sub_expr(lhs: Self, rhs: Self) -> Self {
        Self::Sub(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn and(lhs: Self, rhs: Self) -> Self {
        Self::And(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn or(lhs: Self, rhs: Self) -> Self {
        Self::Or(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn xor(lhs: Self, rhs: Self) -> Self {
        Self::Xor(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn eq(lhs: Self, rhs: Self) -> Self {
        Self::Eq(Box::new(lhs), Box::new(rhs))
    }

    #[must_use]
    pub fn ite(cond: Self, then_: Self, else_: Self) -> Self {
        Self::Ite {
            cond: Box::new(cond),
            then_: Box::new(then_),
            else_: Box::new(else_),
        }
    }

    /// Build a bitvector constant. Mirror of [`SymExpr::bv`] with the more
    /// conventional `constant(width, value)` signature used by some callers.
    #[must_use]
    pub const fn constant(width: u32, val: u64) -> Self {
        Self::ConstBv { val, width }
    }

    /// Unsigned greater-than comparison: `lhs > rhs`.
    #[must_use]
    pub fn ugt(lhs: Self, rhs: Self) -> Self {
        Self::UGt(Box::new(lhs), Box::new(rhs))
    }

    /// Unsigned greater-or-equal comparison: `lhs >= rhs`.
    #[must_use]
    pub fn uge(lhs: Self, rhs: Self) -> Self {
        Self::UGe(Box::new(lhs), Box::new(rhs))
    }

    /// Extract bits `[hi:lo]` (inclusive) from `expr`.
    #[must_use]
    pub fn extract(expr: Self, lo: u32, hi: u32) -> Self {
        Self::Extract {
            expr: Box::new(expr),
            hi,
            lo,
        }
    }

    /// Best-effort bit-width estimate for this expression. Returns `64` when
    /// the width is not statically known.
    #[must_use]
    pub fn bit_width(&self) -> u32 {
        match self {
            Self::ConstBv { width, .. } => *width,
            Self::Var { ty, .. } => match ty {
                SymType::BitVec(w) => *w,
                SymType::Bool => 1,
                _ => 64,
            },
            Self::Extract { hi, lo, .. } => hi.saturating_sub(*lo) + 1,
            Self::ZExt { target_width, .. } | Self::SExt { target_width, .. } => *target_width,
            Self::Concat(a, b) => a.bit_width() + b.bit_width(),
            Self::ConstBool(_)
            | Self::Eq(_, _)
            | Self::Ne(_, _)
            | Self::ULt(_, _)
            | Self::ULe(_, _)
            | Self::UGt(_, _)
            | Self::UGe(_, _)
            | Self::SLt(_, _)
            | Self::SLe(_, _)
            | Self::SGt(_, _)
            | Self::SGe(_, _)
            | Self::BoolAnd(_, _)
            | Self::BoolOr(_, _)
            | Self::BoolNot(_) => 1,
            Self::Add(a, _)
            | Self::Sub(a, _)
            | Self::Mul(a, _)
            | Self::UDiv(a, _)
            | Self::SDiv(a, _)
            | Self::URem(a, _)
            | Self::SRem(a, _)
            | Self::And(a, _)
            | Self::Or(a, _)
            | Self::Xor(a, _)
            | Self::Shl(a, _)
            | Self::LShr(a, _)
            | Self::AShr(a, _) => a.bit_width(),
            Self::Not(e) | Self::Neg(e) => e.bit_width(),
            Self::Ite { then_, .. } => then_.bit_width(),
            Self::Load { size, .. } => u32::from(*size) * 8,
            Self::Store { val, .. } => val.bit_width(),
        }
    }
}

impl std::ops::Add for SymExpr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl std::ops::Sub for SymExpr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

/// Numeric identifier for a [`SymExpr::Var`].
pub type SymId = u64;

/// Evaluate `expr` against the given concrete environment keyed by [`SymId`].
///
/// Returns `Some(value)` when the expression collapses to a single concrete bit-vector
/// value, or `None` otherwise. This is a best-effort interpreter for the common
/// arithmetic / logical opcodes.
///
/// # Variable lookup
///
/// This function only resolves variables whose names encode a numeric [`SymId`]:
/// either the `"<name>_<id>"` form produced by [`SymExpr::Symbol`], or a name that
/// parses directly as a decimal [`SymId`]. Variables built via
/// [`SymExpr::var`] with an arbitrary string name (e.g. `"x"`, `"rax"`) will
/// **always miss** here and the surrounding expression will evaluate to `None`.
///
/// For string-keyed evaluation (including the model returned by
/// [`SymbolicState::get_model`]) use [`SymExpr::evaluate`] instead.
#[must_use]
pub fn eval_concrete<S: std::hash::BuildHasher>(
    expr: &SymExpr,
    env: &std::collections::HashMap<SymId, u64, S>,
) -> Option<u64> {
    fn lookup<S: std::hash::BuildHasher>(
        name: &str,
        env: &std::collections::HashMap<SymId, u64, S>,
    ) -> Option<u64> {
        // Names encoded as `<name>_<id>` by `SymExpr::Symbol`; recover the id.
        if let Some((_, suffix)) = name.rsplit_once('_')
            && let Ok(id) = suffix.parse::<SymId>()
                && let Some(v) = env.get(&id).copied() {
                    return Some(v);
                }
        // Also try the raw name parsed as a numeric id, to handle variables
        // created via `SymExpr::var(name, ty)` where name itself is a plain
        // decimal id string.
        if let Ok(id) = name.parse::<SymId>() {
            return env.get(&id).copied();
        }
        None
    }
    Some(match expr {
        SymExpr::ConstBv { val, .. } => *val,
        SymExpr::ConstBool(b) => u64::from(*b),
        SymExpr::Var { name, .. } => lookup(name, env)?,
        SymExpr::Add(a, b) => eval_concrete(a, env)?.wrapping_add(eval_concrete(b, env)?),
        SymExpr::Sub(a, b) => eval_concrete(a, env)?.wrapping_sub(eval_concrete(b, env)?),
        SymExpr::Mul(a, b) => eval_concrete(a, env)?.wrapping_mul(eval_concrete(b, env)?),
        SymExpr::And(a, b) | SymExpr::BoolAnd(a, b) => {
            eval_concrete(a, env)? & eval_concrete(b, env)?
        }
        SymExpr::Or(a, b) | SymExpr::BoolOr(a, b) => {
            eval_concrete(a, env)? | eval_concrete(b, env)?
        }
        SymExpr::Xor(a, b) => eval_concrete(a, env)? ^ eval_concrete(b, env)?,
        SymExpr::Not(e) => !eval_concrete(e, env)?,
        SymExpr::Neg(e) => eval_concrete(e, env)?
            .cast_signed()
            .wrapping_neg()
            .cast_unsigned(),
        SymExpr::Shl(a, b) => eval_concrete(a, env)?
            .checked_shl(u32::try_from(eval_concrete(b, env)?).unwrap_or(0))
            .unwrap_or(0),
        SymExpr::LShr(a, b) => eval_concrete(a, env)?
            .checked_shr(u32::try_from(eval_concrete(b, env)?).unwrap_or(0))
            .unwrap_or(0),
        SymExpr::AShr(a, b) => eval_concrete(a, env)?
            .cast_signed()
            .checked_shr(u32::try_from(eval_concrete(b, env)?).unwrap_or(0))
            .unwrap_or(0)
            .cast_unsigned(),
        SymExpr::Eq(a, b) => u64::from(eval_concrete(a, env)? == eval_concrete(b, env)?),
        SymExpr::Ne(a, b) => u64::from(eval_concrete(a, env)? != eval_concrete(b, env)?),
        SymExpr::ULt(a, b) => u64::from(eval_concrete(a, env)? < eval_concrete(b, env)?),
        SymExpr::ULe(a, b) => u64::from(eval_concrete(a, env)? <= eval_concrete(b, env)?),
        SymExpr::UGt(a, b) => u64::from(eval_concrete(a, env)? > eval_concrete(b, env)?),
        SymExpr::UGe(a, b) => u64::from(eval_concrete(a, env)? >= eval_concrete(b, env)?),
        SymExpr::SLt(a, b) => {
            u64::from(eval_concrete(a, env)?.cast_signed() < eval_concrete(b, env)?.cast_signed())
        }
        SymExpr::SLe(a, b) => {
            u64::from(eval_concrete(a, env)?.cast_signed() <= eval_concrete(b, env)?.cast_signed())
        }
        SymExpr::SGt(a, b) => {
            u64::from(eval_concrete(a, env)?.cast_signed() > eval_concrete(b, env)?.cast_signed())
        }
        SymExpr::SGe(a, b) => {
            u64::from(eval_concrete(a, env)?.cast_signed() >= eval_concrete(b, env)?.cast_signed())
        }
        SymExpr::BoolNot(e) => u64::from(eval_concrete(e, env)? == 0),
        SymExpr::Ite { cond, then_, else_ } => {
            if eval_concrete(cond, env)? != 0 {
                eval_concrete(then_, env)?
            } else {
                eval_concrete(else_, env)?
            }
        }
        _ => return None,
    })
}

impl SymExpr {
    // (dummy trailing impl to keep parser balance with the doc-comment block above)

    /// Return `true` if this expression is syntactically a constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::ConstBv { .. } | Self::ConstBool(_))
    }

    /// Attempt to evaluate to a concrete `u64` value (only for `ConstBv`).
    #[must_use]
    pub const fn as_const_u64(&self) -> Option<u64> {
        match self {
            Self::ConstBv { val, .. } => Some(*val),
            _ => None,
        }
    }

    /// Attempt to evaluate to a concrete `bool` value (only for `ConstBool`).
    #[must_use]
    pub const fn as_const_bool(&self) -> Option<bool> {
        match self {
            Self::ConstBool(b) => Some(*b),
            _ => None,
        }
    }

    /// Perform basic constant-folding simplification on this expression.
    ///
    /// Delegates to [`SymExprSimplifier`] for the full rule set.
    #[must_use]
    pub fn simplify(&self) -> Self {
        SymExprSimplifier::new().simplify(self.clone())
    }

    /// Evaluate this expression to a concrete `u64` given variable bindings.
    ///
    /// Returns `None` if any symbolic variable is not present in `env` or if
    /// the expression contains a memory operation (which requires a memory
    /// model not captured here).
    /// Results are masked to the expression's own `bit_width()`.
    ///
    /// This is a second interpreter for semantics that `SymExprSimplifier` and
    /// `formula_simplifier::ConstantFolding` also implement, and both of those
    /// mask every folded result. Computing in full 64 bits here meant an
    /// 8/16/32-bit wraparound was silently reported as a non-wrapping value —
    /// `0xFF + 1` at width 8 came out as `0x100`, and `!0u8` as 64 ones. The
    /// divergence is reachable from production: `ConcolicState::eval_concrete`
    /// and the model checking in `constraint_solver` both call this, so a model
    /// could be scored satisfiable or unsatisfiable on a wrong number.
    #[must_use]
    pub fn evaluate(&self, env: &HashMap<String, u64>) -> Option<u64> {
        match self {
            Self::ConstBv { val, .. } => Some(*val),
            Self::ConstBool(b) => Some(u64::from(*b)),
            Self::Var { name, .. } => env.get(name).copied(),
            Self::Add(l, r) => Some(
                l.evaluate(env)?.wrapping_add(r.evaluate(env)?) & width_mask(self.bit_width()),
            ),
            Self::Sub(l, r) => Some(
                l.evaluate(env)?.wrapping_sub(r.evaluate(env)?) & width_mask(self.bit_width()),
            ),
            Self::Mul(l, r) => Some(
                l.evaluate(env)?.wrapping_mul(r.evaluate(env)?) & width_mask(self.bit_width()),
            ),
            Self::UDiv(l, r) => {
                let rv = r.evaluate(env)?;
                if rv == 0 {
                    None
                } else {
                    Some(l.evaluate(env)? / rv)
                }
            }
            Self::SDiv(l, r) => {
                let rv = r.evaluate(env)?;
                if rv == 0 {
                    return None;
                }
                let lv = l.evaluate(env)?.cast_signed();
                let rv = rv.cast_signed();
                Some(lv.wrapping_div(rv).cast_unsigned())
            }
            Self::URem(l, r) => {
                let rv = r.evaluate(env)?;
                if rv == 0 {
                    None
                } else {
                    Some(l.evaluate(env)? % rv)
                }
            }
            Self::SRem(l, r) => {
                let rv = r.evaluate(env)?;
                if rv == 0 {
                    return None;
                }
                let lv = l.evaluate(env)?.cast_signed();
                let rv = rv.cast_signed();
                Some(lv.wrapping_rem(rv).cast_unsigned())
            }
            Self::And(l, r) => Some(l.evaluate(env)? & r.evaluate(env)?),
            Self::Or(l, r) => Some(l.evaluate(env)? | r.evaluate(env)?),
            Self::Xor(l, r) => Some(l.evaluate(env)? ^ r.evaluate(env)?),
            Self::Not(e) => Some(!e.evaluate(env)? & width_mask(self.bit_width())),
            Self::Neg(e) => Some(e.evaluate(env)?.wrapping_neg() & width_mask(self.bit_width())),
            Self::Shl(l, r) => {
                let s = u32::try_from(r.evaluate(env)?.min(63)).unwrap_or(0);
                Some(l.evaluate(env)?.wrapping_shl(s) & width_mask(self.bit_width()))
            }
            Self::LShr(l, r) => {
                let s = u32::try_from(r.evaluate(env)?.min(63)).unwrap_or(0);
                Some(l.evaluate(env)?.wrapping_shr(s))
            }
            Self::AShr(l, r) => {
                let s = u32::try_from(r.evaluate(env)?.min(63)).unwrap_or(0);
                Some(
                    l.evaluate(env)?
                        .cast_signed()
                        .wrapping_shr(s)
                        .cast_unsigned(),
                )
            }
            Self::Concat(hi, lo) => {
                let lo_w = match lo.as_ref() {
                    Self::ConstBv { width, .. } => *width,
                    Self::Var { ty, .. } => ty.width().unwrap_or(64),
                    _ => 64,
                };
                // Guard against shift-by-≥64 which panics in debug / is UB in release.
                let hi_val = hi.evaluate(env)?;
                let lo_val = lo.evaluate(env)?;
                let shifted = if lo_w >= 64 { 0u64 } else { hi_val << lo_w };
                Some(shifted | lo_val)
            }
            Self::Extract { expr, hi, lo } => {
                // Guard against lo > hi (underflow) from deserialized input.
                if lo > hi {
                    return None;
                }
                let v = expr.evaluate(env)?;
                let width = hi - lo + 1;
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                Some((v >> lo) & mask)
            }
            Self::ZExt { expr, .. } => expr.evaluate(env),
            Self::SExt { expr, target_width } => {
                let v = expr.evaluate(env)?;
                let src_width = match expr.as_ref() {
                    Self::ConstBv { width, .. } => *width,
                    Self::Var { ty, .. } => ty.width().unwrap_or(64),
                    _ => 64,
                };
                Some(sign_extend(v, src_width) & width_mask(*target_width))
            }
            Self::Eq(l, r) => Some(u64::from(l.evaluate(env)? == r.evaluate(env)?)),
            Self::Ne(l, r) => Some(u64::from(l.evaluate(env)? != r.evaluate(env)?)),
            Self::ULt(l, r) => Some(u64::from(l.evaluate(env)? < r.evaluate(env)?)),
            Self::ULe(l, r) => Some(u64::from(l.evaluate(env)? <= r.evaluate(env)?)),
            Self::UGt(l, r) => Some(u64::from(l.evaluate(env)? > r.evaluate(env)?)),
            Self::UGe(l, r) => Some(u64::from(l.evaluate(env)? >= r.evaluate(env)?)),
            Self::SLt(l, r) => Some(u64::from(
                l.evaluate(env)?.cast_signed() < r.evaluate(env)?.cast_signed(),
            )),
            Self::SLe(l, r) => Some(u64::from(
                l.evaluate(env)?.cast_signed() <= r.evaluate(env)?.cast_signed(),
            )),
            Self::SGt(l, r) => Some(u64::from(
                l.evaluate(env)?.cast_signed() > r.evaluate(env)?.cast_signed(),
            )),
            Self::SGe(l, r) => Some(u64::from(
                l.evaluate(env)?.cast_signed() >= r.evaluate(env)?.cast_signed(),
            )),
            Self::BoolAnd(l, r) => Some(u64::from(
                (l.evaluate(env)? != 0) && (r.evaluate(env)? != 0),
            )),
            Self::BoolOr(l, r) => Some(u64::from(
                (l.evaluate(env)? != 0) || (r.evaluate(env)? != 0),
            )),
            Self::BoolNot(e) => Some(u64::from(e.evaluate(env)? == 0)),
            Self::Ite { cond, then_, else_ } => {
                if cond.evaluate(env)? != 0 {
                    then_.evaluate(env)
                } else {
                    else_.evaluate(env)
                }
            }
            // Memory ops require a memory model — not evaluable here.
            Self::Load { .. } | Self::Store { .. } => None,
        }
    }
}

// ─── SymbolicValue ────────────────────────────────────────────────────────────

/// A named symbolic value with an associated type and expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicValue {
    /// Unique identifier within a symbolic execution session.
    pub id: u64,
    pub ty: SymType,
    pub expr: SymExpr,
}

impl SymbolicValue {
    #[must_use]
    pub const fn new(id: u64, ty: SymType, expr: SymExpr) -> Self {
        Self { id, ty, expr }
    }
}

// ─── SymMemory ────────────────────────────────────────────────────────────────

/// Symbolic memory model.
///
/// `base` stores concrete-address → expression mappings.
/// `symbolic` stores symbolic-address mappings keyed by an expression id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymMemory {
    /// Concrete address → value at that address.
    pub base: HashMap<u64, SymExpr>,
    /// Symbolic address id → value (keyed by `SymbolicValue::id`).
    pub symbolic: HashMap<u64, SymExpr>,
}

impl SymMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a concrete-addressed value.
    pub fn store_concrete(&mut self, addr: u64, val: SymExpr) {
        self.base.insert(addr, val);
    }

    /// Load from a concrete address; returns a fresh symbolic variable if unknown.
    #[must_use]
    pub fn load_concrete(&self, addr: u64) -> SymExpr {
        self.base
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| SymExpr::Var {
                name: format!("mem_{addr:#x}"),
                ty: SymType::BitVec(8),
            })
    }

    /// Store a value at a symbolic address (keyed by a `SymbolicValue` id).
    pub fn store_symbolic(&mut self, sym_id: u64, val: SymExpr) {
        self.symbolic.insert(sym_id, val);
    }

    /// Load from a symbolic address by its id.
    #[must_use]
    pub fn load_symbolic(&self, sym_id: u64) -> Option<&SymExpr> {
        self.symbolic.get(&sym_id)
    }
}

// ─── PathConstraint ───────────────────────────────────────────────────────────

/// A path constraint is a conjunction of symbolic boolean expressions that must
/// all be satisfiable for the execution path to be reachable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathConstraint {
    pub terms: Vec<SymExpr>,
}

impl PathConstraint {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, expr: SymExpr) {
        self.terms.push(expr);
    }

    /// Combine all terms into a single conjunction `SymExpr`.
    /// Returns `ConstBool(true)` for the empty conjunction.
    #[must_use]
    pub fn as_conjunction(&self) -> SymExpr {
        self.terms
            .iter()
            .cloned()
            .reduce(|acc, e| SymExpr::BoolAnd(Box::new(acc), Box::new(e)))
            .unwrap_or(SymExpr::ConstBool(true))
    }

    /// Return `true` if the conjunction is trivially false (contains `ConstBool(false)`).
    #[must_use]
    pub fn is_trivially_false(&self) -> bool {
        self.terms.contains(&SymExpr::ConstBool(false))
    }
}

// ─── SymbolicState ────────────────────────────────────────────────────────────

/// Full symbolic execution state at a single program point.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolicState {
    /// Register file: register name → symbolic expression.
    pub registers: HashMap<String, SymExpr>,
    /// Memory model.
    pub memory: SymMemory,
    /// Accumulated path condition (must hold for this path to be reachable).
    pub path_condition: Vec<SymExpr>,
    /// Additional solver assertions (loop invariants, user-supplied constraints).
    pub constraints: Vec<SymExpr>,
    /// Current program counter.
    pub pc: u64,
    /// Depth in the exploration tree.
    pub depth: u32,
    /// Optional concrete model produced by a solver: variable id → value.
    /// Empty when no concrete model has been computed for this state.
    #[serde(default)]
    pub model: HashMap<SymId, u64>,
}

impl SymbolicState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new state forked from `self`, adding `branch_cond` to the path.
    #[must_use]
    pub fn fork(&self, branch_cond: SymExpr) -> Self {
        let mut child = self.clone();
        child.path_condition.push(branch_cond);
        child.depth += 1;
        child
    }

    /// Read a register, returning a fresh symbolic variable if not yet defined.
    #[must_use]
    pub fn read_register(&self, name: &str) -> SymExpr {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymExpr::Var {
                name: name.to_string(),
                ty: SymType::BitVec(64),
            })
    }

    /// Write to a register.
    pub fn write_register(&mut self, name: impl Into<String>, val: SymExpr) {
        self.registers.insert(name.into(), val);
    }

    /// Push a constraint to the path condition.
    pub fn add_path_condition(&mut self, cond: SymExpr) {
        self.path_condition.push(cond);
    }

    /// Push an additional assertion.
    pub fn add_constraint(&mut self, cond: SymExpr) {
        self.constraints.push(cond);
    }

    /// Return `true` if the path condition is trivially unsatisfiable.
    #[must_use]
    pub fn is_path_infeasible(&self) -> bool {
        self.path_condition.contains(&SymExpr::ConstBool(false))
    }

    /// Collect all path + extra constraints.
    #[must_use]
    pub fn all_constraints(&self) -> Vec<SymExpr> {
        let mut v = self.path_condition.clone();
        v.extend(self.constraints.clone());
        v
    }

    /// Add a constraint and check satisfiability.
    ///
    /// The constraint is simplified first. If it trivially reduces to
    /// `ConstBool(false)` the constraint is rejected and [`Unsat`] is returned.
    /// The state is only mutated on success.
    ///
    /// Note: full SMT solving is not performed here; only syntactic / constant-
    /// folding checks are done. For complete satisfiability use an external
    /// solver on the SMT-LIB formula produced by [`smt_formula`].
    ///
    /// # Errors
    ///
    /// Returns [`Unsat`] when the simplified constraint is the constant
    /// boolean `false`, indicating an infeasible path.
    pub fn assume(&mut self, constraint: &SymExpr) -> Result<(), Unsat> {
        let simplified = constraint.simplify();
        if simplified == SymExpr::ConstBool(false) {
            return Err(Unsat);
        }
        self.path_condition.push(simplified);
        Ok(())
    }

    /// Check whether the current path condition is (likely) satisfiable.
    ///
    /// Uses Z3 when the `z3` feature is enabled; otherwise falls back to
    /// constant-folding: returns `false` only when the path condition is
    /// *syntactically* contradictory (contains `ConstBool(false)` or the
    /// conjunction simplifies to `false`).
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        // Constant-folding fast path: look for trivial `false` terms.
        if self.is_path_infeasible() {
            return false;
        }
        // Check whether the full conjunction simplifies to false.
        let conj = self
            .all_constraints()
            .into_iter()
            .reduce(|acc, e| SymExpr::BoolAnd(Box::new(acc), Box::new(e)))
            .unwrap_or(SymExpr::ConstBool(true));
        let simplified = conj.simplify();
        simplified != SymExpr::ConstBool(false)
    }

    /// Return a concrete model (variable → value) for the current path.
    ///
    /// For fully concrete paths (all registers are `ConstBv`) this returns
    /// exact values. For symbolic variables the model assigns 0 as a default
    /// witness (a sound under-approximation that satisfies no constraints).
    ///
    /// When Z3 is available (future `z3` feature) this will invoke the solver.
    #[must_use]
    pub fn get_model(&self) -> HashMap<String, u64> {
        // Local helper declared before any statements to satisfy the
        // `items_after_statements` lint.
        fn collect_vars(e: &SymExpr, out: &mut HashMap<String, u64>) {
            match e {
                SymExpr::Var { name, .. } => {
                    out.entry(name.clone()).or_insert(0);
                }
                SymExpr::Add(l, r)
                | SymExpr::Sub(l, r)
                | SymExpr::Mul(l, r)
                | SymExpr::UDiv(l, r)
                | SymExpr::SDiv(l, r)
                | SymExpr::URem(l, r)
                | SymExpr::SRem(l, r)
                | SymExpr::And(l, r)
                | SymExpr::Or(l, r)
                | SymExpr::Xor(l, r)
                | SymExpr::Shl(l, r)
                | SymExpr::LShr(l, r)
                | SymExpr::AShr(l, r)
                | SymExpr::Concat(l, r)
                | SymExpr::Eq(l, r)
                | SymExpr::Ne(l, r)
                | SymExpr::ULt(l, r)
                | SymExpr::ULe(l, r)
                | SymExpr::UGt(l, r)
                | SymExpr::UGe(l, r)
                | SymExpr::SLt(l, r)
                | SymExpr::SLe(l, r)
                | SymExpr::SGt(l, r)
                | SymExpr::SGe(l, r)
                | SymExpr::BoolAnd(l, r)
                | SymExpr::BoolOr(l, r) => {
                    collect_vars(l, out);
                    collect_vars(r, out);
                }
                SymExpr::Not(e)
                | SymExpr::Neg(e)
                | SymExpr::BoolNot(e)
                | SymExpr::ZExt { expr: e, .. }
                | SymExpr::SExt { expr: e, .. }
                | SymExpr::Extract { expr: e, .. }
                | SymExpr::Load { addr: e, .. } => {
                    collect_vars(e, out);
                }
                SymExpr::Ite { cond, then_, else_ } => {
                    collect_vars(cond, out);
                    collect_vars(then_, out);
                    collect_vars(else_, out);
                }
                SymExpr::Store { mem, addr, val } => {
                    collect_vars(mem, out);
                    collect_vars(addr, out);
                    collect_vars(val, out);
                }
                SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) => {}
            }
        }
        let mut model: HashMap<String, u64> = HashMap::new();
        // Seed from concrete register values.
        for (name, expr) in &self.registers {
            if let Some(v) = expr.as_const_u64() {
                model.insert(name.clone(), v);
            }
        }
        // Collect all symbolic variable names from path constraints and seed
        // them with 0 if not already known.
        for e in &self.path_condition {
            collect_vars(e, &mut model);
        }
        for e in &self.constraints {
            collect_vars(e, &mut model);
        }
        model
    }

    /// Fork the state into a true-branch / false-branch pair for path splits.
    ///
    /// The `branch_cond` is added to the first state's path condition and its
    /// negation is added to the second's. Both states increment their depth.
    #[must_use]
    pub fn fork_pair(&self, branch_cond: SymExpr) -> (Self, Self) {
        let mut true_state = self.clone();
        true_state.path_condition.push(branch_cond.clone());
        true_state.depth += 1;

        let mut false_state = self.clone();
        false_state
            .path_condition
            .push(SymExpr::BoolNot(Box::new(branch_cond)));
        false_state.depth += 1;

        (true_state, false_state)
    }

    /// Merge two symbolic states that reconverge after a conditional branch.
    ///
    /// Registers present in only one state are wrapped in an ITE on `cond`.
    /// Path conditions and constraints from both branches are joined with
    /// `BoolOr` on the path conditions (i.e. the merged state is reachable from
    /// either branch).
    ///
    /// The returned state's depth is `max(a.depth, b.depth)`.
    #[must_use]
    pub fn merge(a: Self, b: Self, cond: &SymExpr) -> Self {
        let mut merged = Self::new();
        merged.pc = a.pc; // use first branch's PC
        merged.depth = a.depth.max(b.depth);

        // Merge registers: for each key present in either state, build an ITE.
        let all_keys: std::collections::HashSet<String> = a
            .registers
            .keys()
            .chain(b.registers.keys())
            .cloned()
            .collect();
        for key in all_keys {
            let av = a.read_register(&key);
            let bv = b.read_register(&key);
            let merged_val = if av == bv {
                av
            } else {
                SymExpr::Ite {
                    cond: Box::new(cond.clone()),
                    then_: Box::new(av),
                    else_: Box::new(bv),
                }
            };
            merged.registers.insert(key, merged_val);
        }

        // Merge path conditions: (pc_a) OR (pc_b).
        let pc_a = a
            .path_condition
            .into_iter()
            .reduce(|l, r| SymExpr::BoolAnd(Box::new(l), Box::new(r)))
            .unwrap_or(SymExpr::ConstBool(true));
        let pc_b = b
            .path_condition
            .into_iter()
            .reduce(|l, r| SymExpr::BoolAnd(Box::new(l), Box::new(r)))
            .unwrap_or(SymExpr::ConstBool(true));
        merged
            .path_condition
            .push(SymExpr::BoolOr(Box::new(pc_a), Box::new(pc_b)));

        // Merge extra constraints from both branches.
        merged.constraints.extend(a.constraints);
        merged.constraints.extend(b.constraints);

        merged
    }
}

// ─── Symbolic operation helpers ───────────────────────────────────────────────

/// Build `lhs + rhs` with constant folding.
#[must_use]
pub fn sym_add(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Add(Box::new(lhs), Box::new(rhs)))
}

/// Build `lhs - rhs` with constant folding.
#[must_use]
pub fn sym_sub(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Sub(Box::new(lhs), Box::new(rhs)))
}

/// Build `lhs * rhs` with constant folding.
#[must_use]
pub fn sym_mul(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Mul(Box::new(lhs), Box::new(rhs)))
}

/// Build `lhs & rhs` (bitwise AND) with constant folding.
#[must_use]
pub fn sym_and(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::And(Box::new(lhs), Box::new(rhs)))
}

/// Build `lhs | rhs` (bitwise OR) with constant folding.
#[must_use]
pub fn sym_or(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Or(Box::new(lhs), Box::new(rhs)))
}

/// Build `lhs ^ rhs` (bitwise XOR) with constant folding.
#[must_use]
pub fn sym_xor(lhs: SymExpr, rhs: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Xor(Box::new(lhs), Box::new(rhs)))
}

/// Build `~expr` (bitwise NOT) with constant folding.
#[must_use]
pub fn sym_not(expr: SymExpr) -> SymExpr {
    SymExprSimplifier::new().simplify(SymExpr::Not(Box::new(expr)))
}

// ─── SymEngine trait ──────────────────────────────────────────────────────────

/// Core symbolic execution engine interface.
///
/// Implementors step through a single instruction and may return multiple
/// successor states (forking on conditional branches).
pub trait SymEngine: Send + Sync {
    /// Step through `instr` starting from `state`.
    ///
    /// Returns a `Vec` of successor states:
    /// - Exactly one for non-branching instructions.
    /// - Two (or more) for conditional branches.
    /// - Zero if execution terminates or is infeasible.
    ///
    /// # Errors
    /// Returns [`SymbolicError`] on type mismatches or unsupported instructions.
    fn step(
        &mut self,
        instr: &Instruction,
        state: &mut SymbolicState,
    ) -> Result<Vec<SymbolicState>, SymbolicError>;
}

// ─── SymExprSimplifier ────────────────────────────────────────────────────────

/// Performs structural algebraic simplifications on [`SymExpr`] trees.
///
/// Rules implemented:
/// - `x XOR x = 0`
/// - `x AND 0 = 0`
/// - `x AND x = x`
/// - `x OR 0 = x`
/// - `x OR x = x`
/// - `x + 0 = x`
/// - `x - 0 = x`
/// - `x - x = 0`
/// - `x * 0 = 0`
/// - `x * 1 = x`
/// - `NOT (NOT x) = x`
/// - `NEG (NEG x) = x`
/// - Constant folding for all operators
/// - `ITE(true, t, _) = t`, `ITE(false, _, e) = e`
/// - `BOOL_NOT(true) = false`, `BOOL_NOT(false) = true`
/// - `BOOL_AND(false, _) = false`, `BOOL_OR(true, _) = true`
/// - `ZExt(ConstBv) = folded constant`
/// - `SExt(ConstBv) = folded constant`
/// - `Extract(ConstBv, hi, lo) = folded constant`
#[derive(Debug, Default)]
pub struct SymExprSimplifier;

impl SymExprSimplifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Recursively simplify `expr`.
    #[must_use]
    pub fn simplify(&self, expr: SymExpr) -> SymExpr {
        match expr {
            // ── Terminal nodes ────────────────────────────────────────────
            SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) | SymExpr::Var { .. } => expr,

            // ── NOT ───────────────────────────────────────────────────────
            SymExpr::Not(inner) => self.simplify_not(*inner),
            // ── NEG ───────────────────────────────────────────────────────
            SymExpr::Neg(inner) => self.simplify_neg(*inner),
            // ── Binary arithmetic / bitwise / shift ───────────────────────
            SymExpr::Add(l, r) => self.simplify_add(*l, *r),
            SymExpr::Sub(l, r) => self.simplify_sub(*l, *r),
            SymExpr::Mul(l, r) => self.simplify_mul(*l, *r),
            SymExpr::And(l, r) => self.simplify_and(*l, *r),
            SymExpr::Or(l, r) => self.simplify_or(*l, *r),
            SymExpr::Xor(l, r) => self.simplify_xor(*l, *r),
            SymExpr::Shl(l, r) => self.simplify_shl(*l, *r),
            SymExpr::LShr(l, r) => self.simplify_lshr(*l, *r),
            SymExpr::AShr(l, r) => self.simplify_ashr(*l, *r),

            // ── CONCAT ────────────────────────────────────────────────────
            SymExpr::Concat(hi, lo) => {
                let hs = self.simplify(*hi);
                let ls = self.simplify(*lo);
                match (&hs, &ls) {
                    (
                        SymExpr::ConstBv { val: hv, width: hw },
                        SymExpr::ConstBv { val: lv, width: lw },
                    ) => SymExpr::ConstBv {
                        // Guard shift-by-≥64: if lo width ≥ 64 the high part is lost.
                        val: if *lw >= 64 { *lv } else { (hv << lw) | lv },
                        width: hw + lw,
                    },
                    _ => SymExpr::Concat(Box::new(hs), Box::new(ls)),
                }
            }

            // ── EXTRACT ───────────────────────────────────────────────────
            SymExpr::Extract {
                expr: inner,
                hi,
                lo,
            } => {
                let s = self.simplify(*inner);
                match &s {
                    SymExpr::ConstBv { val, .. } => {
                        let mask = width_mask(hi - lo + 1);
                        SymExpr::ConstBv {
                            val: (val >> lo) & mask,
                            width: hi - lo + 1,
                        }
                    }
                    _ => SymExpr::Extract {
                        expr: Box::new(s),
                        hi,
                        lo,
                    },
                }
            }

            // ── ZEXT ──────────────────────────────────────────────────────
            SymExpr::ZExt {
                expr: inner,
                target_width,
            } => {
                let s = self.simplify(*inner);
                match &s {
                    SymExpr::ConstBv { val, .. } => SymExpr::ConstBv {
                        val: *val,
                        width: target_width,
                    },
                    _ => SymExpr::ZExt {
                        expr: Box::new(s),
                        target_width,
                    },
                }
            }

            // ── SEXT ──────────────────────────────────────────────────────
            SymExpr::SExt {
                expr: inner,
                target_width,
            } => {
                let s = self.simplify(*inner);
                match &s {
                    SymExpr::ConstBv { val, width } => SymExpr::ConstBv {
                        val: sign_extend(*val, *width) & width_mask(target_width),
                        width: target_width,
                    },
                    _ => SymExpr::SExt {
                        expr: Box::new(s),
                        target_width,
                    },
                }
            }

            // ── COMPARISONS ───────────────────────────────────────────────
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

            // ── UDIV / SDIV / UREM / SREM ─────────────────────────────────
            SymExpr::UDiv(l, r) => {
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if lw == rw && *rv != 0 => SymExpr::ConstBv {
                        val: lv / rv,
                        width: *lw,
                    },
                    _ => SymExpr::UDiv(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::SDiv(l, r) => {
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if lw == rw && *rv != 0 => {
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
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if lw == rw && *rv != 0 => SymExpr::ConstBv {
                        val: lv % rv,
                        width: *lw,
                    },
                    _ => SymExpr::URem(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::SRem(l, r) => {
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (
                        SymExpr::ConstBv { val: lv, width: lw },
                        SymExpr::ConstBv { val: rv, width: rw },
                    ) if lw == rw && *rv != 0 => {
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

            // ── BOOL OPS ──────────────────────────────────────────────────
            SymExpr::BoolAnd(l, r) => {
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBool(false), _) | (_, SymExpr::ConstBool(false)) => {
                        SymExpr::ConstBool(false)
                    }
                    (SymExpr::ConstBool(true), _) => rs,
                    (_, SymExpr::ConstBool(true)) => ls,
                    _ if ls == rs => ls,
                    _ => SymExpr::BoolAnd(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::BoolOr(l, r) => {
                let ls = self.simplify(*l);
                let rs = self.simplify(*r);
                match (&ls, &rs) {
                    (SymExpr::ConstBool(true), _) | (_, SymExpr::ConstBool(true)) => {
                        SymExpr::ConstBool(true)
                    }
                    (SymExpr::ConstBool(false), _) => rs,
                    (_, SymExpr::ConstBool(false)) => ls,
                    _ if ls == rs => ls,
                    _ => SymExpr::BoolOr(Box::new(ls), Box::new(rs)),
                }
            }
            SymExpr::BoolNot(inner) => {
                let s = self.simplify(*inner);
                match s {
                    SymExpr::ConstBool(b) => SymExpr::ConstBool(!b),
                    SymExpr::BoolNot(inner2) => *inner2, // !!x = x
                    other => SymExpr::BoolNot(Box::new(other)),
                }
            }

            // ── ITE ───────────────────────────────────────────────────────
            SymExpr::Ite { cond, then_, else_ } => {
                let cs = self.simplify(*cond);
                match cs {
                    SymExpr::ConstBool(true) => self.simplify(*then_),
                    SymExpr::ConstBool(false) => self.simplify(*else_),
                    other => {
                        let ts = self.simplify(*then_);
                        let es = self.simplify(*else_);
                        if ts == es {
                            ts
                        } else {
                            SymExpr::Ite {
                                cond: Box::new(other),
                                then_: Box::new(ts),
                                else_: Box::new(es),
                            }
                        }
                    }
                }
            }

            // ── MEMORY ────────────────────────────────────────────────────
            SymExpr::Load { addr, size } => SymExpr::Load {
                addr: Box::new(self.simplify(*addr)),
                size,
            },
            SymExpr::Store { mem, addr, val } => SymExpr::Store {
                mem: Box::new(self.simplify(*mem)),
                addr: Box::new(self.simplify(*addr)),
                val: Box::new(self.simplify(*val)),
            },
        }
    }

    fn simplify_not(&self, inner: SymExpr) -> SymExpr {
        let s = self.simplify(inner);
        match s {
            SymExpr::ConstBool(b) => SymExpr::ConstBool(!b),
            SymExpr::ConstBv { val, width } => SymExpr::ConstBv {
                val: (!val) & width_mask(width),
                width,
            },
            // NOT (NOT x) = x
            SymExpr::Not(inner2) => *inner2,
            other => SymExpr::Not(Box::new(other)),
        }
    }

    fn simplify_neg(&self, inner: SymExpr) -> SymExpr {
        let s = self.simplify(inner);
        match s {
            SymExpr::ConstBv { val, width } => SymExpr::ConstBv {
                val: (val.wrapping_neg()) & width_mask(width),
                width,
            },
            // NEG (NEG x) = x
            SymExpr::Neg(inner2) => *inner2,
            other => SymExpr::Neg(Box::new(other)),
        }
    }

    fn simplify_add(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: aa.wrapping_add(*bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x + 0 = x
            (_, SymExpr::ConstBv { val: 0, .. }) => ls,
            // 0 + x = x
            (SymExpr::ConstBv { val: 0, .. }, _) => rs,
            _ => SymExpr::Add(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_sub(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: aa.wrapping_sub(*bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x - 0 = x
            (_, SymExpr::ConstBv { val: 0, .. }) => ls,
            // x - x = 0
            _ if ls == rs => SymExpr::ConstBv {
                val: 0,
                width: ls.bit_width(),
            },
            _ => SymExpr::Sub(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_mul(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: aa.wrapping_mul(*bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x * 0 = 0
            (_, SymExpr::ConstBv { val: 0, width: ww }) => SymExpr::ConstBv {
                val: 0,
                width: *ww,
            },
            (SymExpr::ConstBv { val: 0, width: ww }, _) => SymExpr::ConstBv {
                val: 0,
                width: *ww,
            },
            // x * 1 = x
            (_, SymExpr::ConstBv { val: 1, .. }) => ls,
            (SymExpr::ConstBv { val: 1, .. }, _) => rs,
            _ => SymExpr::Mul(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_and(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: (aa & bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x AND 0 = 0
            (_, SymExpr::ConstBv { val: 0, width: ww }) => SymExpr::ConstBv {
                val: 0,
                width: *ww,
            },
            (SymExpr::ConstBv { val: 0, width: ww }, _) => SymExpr::ConstBv {
                val: 0,
                width: *ww,
            },
            // x AND x = x
            _ if ls == rs => ls,
            _ => SymExpr::And(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_or(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: (aa | bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x OR 0 = x
            (_, SymExpr::ConstBv { val: 0, .. }) => ls,
            (SymExpr::ConstBv { val: 0, .. }, _) => rs,
            // x OR x = x
            _ if ls == rs => ls,
            _ => SymExpr::Or(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_xor(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: (aa ^ bb) & width_mask(*ww),
                    width: *ww,
                }
            }
            // x XOR x = 0
            _ if ls == rs => SymExpr::ConstBv {
                val: 0,
                width: ls.bit_width(),
            },
            _ => SymExpr::Xor(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_shl(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: aa.wrapping_shl(*bb as u32) & width_mask(*ww),
                    width: *ww,
                }
            }
            _ => SymExpr::Shl(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_lshr(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                SymExpr::ConstBv {
                    val: aa.wrapping_shr(*bb as u32) & width_mask(*ww),
                    width: *ww,
                }
            }
            _ => SymExpr::LShr(Box::new(ls), Box::new(rs)),
        }
    }

    fn simplify_ashr(&self, lhs: SymExpr, rhs: SymExpr) -> SymExpr {
        let ls = self.simplify(lhs);
        let rs = self.simplify(rhs);
        match (&ls, &rs) {
            (SymExpr::ConstBv { val: aa, width: ww }, SymExpr::ConstBv { val: bb, .. }) => {
                let shift = (*bb as u32).min(63);
                let signed = sign_extend(*aa, *ww) as i64;
                SymExpr::ConstBv {
                    val: ((signed >> shift) as u64) & width_mask(*ww),
                    width: *ww,
                }
            }
            _ => SymExpr::AShr(Box::new(ls), Box::new(rs)),
        }
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Return a bitmask for `width` least-significant bits (width ≤ 64).
#[must_use]
const fn width_mask(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width).wrapping_sub(1)
    }
}

/// Sign-extend a `width`-bit value to 64 bits.
#[must_use]
const fn sign_extend(val: u64, width: u32) -> u64 {
    if width == 0 || width >= 64 {
        return val;
    }
    let sign_bit = 1u64 << (width - 1);
    if val & sign_bit != 0 {
        val | !width_mask(width)
    } else {
        val & width_mask(width)
    }
}

/// Return an approximate width for an expression (used when width info is implicit).
#[must_use]
pub fn expr_width(expr: &SymExpr) -> u32 {
    match expr {
        SymExpr::ConstBv { width, .. } => *width,
        SymExpr::Var { ty, .. } => match ty {
            SymType::Bool => 1,
            _ => ty.width().unwrap_or(64),
        },
        _ => 64,
    }
}

/// Fold an unsigned comparison with constant folding, falling back to `cons`.
fn fold_cmp<F, C>(simp: &SymExprSimplifier, l: SymExpr, r: SymExpr, op: F, cons: C) -> SymExpr
where
    F: Fn(u64, u64) -> bool,
    C: Fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr,
{
    let ls = simp.simplify(l);
    let rs = simp.simplify(r);
    match (&ls, &rs) {
        (SymExpr::ConstBv { val: lv, .. }, SymExpr::ConstBv { val: rv, .. }) => {
            SymExpr::ConstBool(op(*lv, *rv))
        }
        _ => cons(Box::new(ls), Box::new(rs)),
    }
}

/// Fold a signed comparison with constant folding.
fn fold_scmp<F, C>(simp: &SymExprSimplifier, l: SymExpr, r: SymExpr, op: F, cons: C) -> SymExpr
where
    F: Fn(i64, i64) -> bool,
    C: Fn(Box<SymExpr>, Box<SymExpr>) -> SymExpr,
{
    let ls = simp.simplify(l);
    let rs = simp.simplify(r);
    match (&ls, &rs) {
        (SymExpr::ConstBv { val: lv, width: lw }, SymExpr::ConstBv { val: rv, width: rw }) => {
            let a = sign_extend(*lv, *lw).cast_signed();
            let b = sign_extend(*rv, *rw).cast_signed();
            SymExpr::ConstBool(op(a, b))
        }
        _ => cons(Box::new(ls), Box::new(rs)),
    }
}

// ─── Spec-required types ──────────────────────────────────────────────────────

/// Width of a symbolic bitvector (spec: `SymWidth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymWidth {
    W8,
    W16,
    W32,
    W64,
}

impl SymWidth {
    /// Return the bit-width as a `u32`.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    /// Return the byte-width as a `u32`.
    #[must_use]
    pub const fn bytes(&self) -> u32 {
        self.bits() / 8
    }
}

impl std::fmt::Display for SymWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bits())
    }
}

/// Recursive symbolic expression (spec: `SymExpr` — separate from the existing `SymExpr`).
/// Named `SpecSymExpr` internally to avoid a name clash; re-exported as `SymExpr2` for tests.
#[derive(Debug, Clone)]
pub enum SpecSymExpr {
    Const { val: u64, width: SymWidth },
    Var { name: String, width: SymWidth },
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Eq(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    ITE(Box<Self>, Box<Self>, Box<Self>),
    Load { addr: Box<Self>, width: SymWidth },
    Concat(Box<Self>, Box<Self>),
    Extract { expr: Box<Self>, hi: u8, lo: u8 },
}

impl SpecSymExpr {
    /// Return the width of this expression if determinable.
    #[must_use]
    pub fn width(&self) -> Option<SymWidth> {
        match self {
            Self::Const { width, .. } | Self::Var { width, .. } | Self::Load { width, .. } => {
                Some(*width)
            }
            Self::Extract { hi, lo, .. } => {
                let bits = u32::from(hi - lo + 1);
                match bits {
                    8 => Some(SymWidth::W8),
                    16 => Some(SymWidth::W16),
                    32 => Some(SymWidth::W32),
                    64 => Some(SymWidth::W64),
                    _ => None,
                }
            }
            Self::Not(e) | Self::ITE(_, e, _) => e.width(),
            Self::Add(l, _)
            | Self::Sub(l, _)
            | Self::Mul(l, _)
            | Self::Div(l, _)
            | Self::And(l, _)
            | Self::Or(l, _)
            | Self::Xor(l, _)
            | Self::Shl(l, _)
            | Self::Shr(l, _) => l.width(),
            // A concatenation is as wide as BOTH operands together, not as
            // wide as the left one. `SymWidth` only has 8/16/32/64, so a sum
            // it cannot express (24 bits, or anything over 64) is reported as
            // unknown rather than as a plausible-looking wrong width.
            Self::Concat(l, r) => match l.width()?.bits() + r.width()?.bits() {
                8 => Some(SymWidth::W8),
                16 => Some(SymWidth::W16),
                32 => Some(SymWidth::W32),
                64 => Some(SymWidth::W64),
                _ => None,
            },
            // Comparisons yield a boolean. `SymWidth` has no 1-bit variant, so
            // the honest answer is "unknown" — returning the operand width
            // claimed a 64-bit result for what is a single bit.
            Self::Eq(..) | Self::Lt(..) => None,
        }
    }

    /// Return `true` if all leaves are `Const`.
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        match self {
            Self::Const { .. } => true,
            Self::Var { .. } => false,
            Self::Not(e) => e.is_concrete(),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Div(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Concat(l, r)
            | Self::Eq(l, r)
            | Self::Lt(l, r) => l.is_concrete() && r.is_concrete(),
            Self::ITE(c, t, e) => c.is_concrete() && t.is_concrete() && e.is_concrete(),
            Self::Load { addr, .. } => addr.is_concrete(),
            Self::Extract { expr, .. } => expr.is_concrete(),
        }
    }

    /// Constant-fold fully concrete expressions to a `u64` value.
    #[must_use]
    pub fn eval_concrete(&self) -> Option<u64> {
        match self {
            Self::Const { val, .. } => Some(*val),
            Self::Var { .. } | Self::Load { .. } => None,
            Self::Add(l, r) => Some(l.eval_concrete()?.wrapping_add(r.eval_concrete()?)),
            Self::Sub(l, r) => Some(l.eval_concrete()?.wrapping_sub(r.eval_concrete()?)),
            Self::Mul(l, r) => Some(l.eval_concrete()?.wrapping_mul(r.eval_concrete()?)),
            Self::Div(l, r) => {
                let rv = r.eval_concrete()?;
                if rv == 0 {
                    None
                } else {
                    Some(l.eval_concrete()? / rv)
                }
            }
            Self::And(l, r) => Some(l.eval_concrete()? & r.eval_concrete()?),
            Self::Or(l, r) => Some(l.eval_concrete()? | r.eval_concrete()?),
            Self::Xor(l, r) => Some(l.eval_concrete()? ^ r.eval_concrete()?),
            Self::Shl(l, r) => Some(
                l.eval_concrete()?
                    .wrapping_shl(u32::try_from(r.eval_concrete()?).unwrap_or(0)),
            ),
            Self::Shr(l, r) => Some(
                l.eval_concrete()?
                    .wrapping_shr(u32::try_from(r.eval_concrete()?).unwrap_or(0)),
            ),
            Self::Not(e) => Some(!e.eval_concrete()?),
            Self::Eq(l, r) => Some(u64::from(l.eval_concrete()? == r.eval_concrete()?)),
            Self::Lt(l, r) => Some(u64::from(l.eval_concrete()? < r.eval_concrete()?)),
            Self::ITE(c, t, e) => {
                if c.eval_concrete()? != 0 {
                    t.eval_concrete()
                } else {
                    e.eval_concrete()
                }
            }
            Self::Concat(hi, lo) => {
                // `hi ++ lo` — shift by the width of the LOW operand, which is
                // the one being sat on top of. Shifting by `hi`'s own width
                // dropped the high part into the low bits, where it was simply
                // OR-ed away: `1 ++ 0xFFFF` came out as 0xFFFF instead of
                // 0x1_FFFF.
                let lw = lo.width()?.bits();
                Some((hi.eval_concrete()? << lw) | lo.eval_concrete()?)
            }
            Self::Extract { expr, hi, lo } => {
                let v = expr.eval_concrete()?;
                let mask = if (hi - lo + 1) >= 64 {
                    u64::MAX
                } else {
                    (1u64 << (hi - lo + 1)) - 1
                };
                Some((v >> lo) & mask)
            }
        }
    }

    /// Substitute all occurrences of variable `var` with `val`.
    #[must_use]
    pub fn substitute(&self, var: &str, val: &Self) -> Self {
        match self {
            Self::Var { name, .. } if name == var => val.clone(),
            Self::Const { .. } | Self::Var { .. } => self.clone(),
            Self::Not(e) => Self::Not(Box::new(e.substitute(var, val))),
            Self::Add(l, r) => Self::Add(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Sub(l, r) => Self::Sub(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Mul(l, r) => Self::Mul(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Div(l, r) => Self::Div(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::And(l, r) => Self::And(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Or(l, r) => Self::Or(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Xor(l, r) => Self::Xor(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Shl(l, r) => Self::Shl(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Shr(l, r) => Self::Shr(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Eq(l, r) => Self::Eq(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Lt(l, r) => Self::Lt(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::Concat(l, r) => Self::Concat(
                Box::new(l.substitute(var, val)),
                Box::new(r.substitute(var, val)),
            ),
            Self::ITE(c, t, e) => Self::ITE(
                Box::new(c.substitute(var, val)),
                Box::new(t.substitute(var, val)),
                Box::new(e.substitute(var, val)),
            ),
            Self::Load { addr, width } => Self::Load {
                addr: Box::new(addr.substitute(var, val)),
                width: *width,
            },
            Self::Extract { expr, hi, lo } => Self::Extract {
                expr: Box::new(expr.substitute(var, val)),
                hi: *hi,
                lo: *lo,
            },
        }
    }
}

/// A symbolic constraint (spec: `SymConstraint`).
#[derive(Debug, Clone)]
pub struct SymConstraint {
    pub expr: SpecSymExpr,
    pub is_negated: bool,
}

impl SymConstraint {
    /// Assert that `e` must hold.
    #[must_use]
    pub const fn assert(e: SpecSymExpr) -> Self {
        Self {
            expr: e,
            is_negated: false,
        }
    }

    /// Deny: `e` must NOT hold.
    #[must_use]
    pub const fn deny(e: SpecSymExpr) -> Self {
        Self {
            expr: e,
            is_negated: true,
        }
    }
}

/// Symbolic execution state (spec: `SymState`).
#[derive(Debug, Clone, Default)]
pub struct SymState {
    pub vars: std::collections::HashMap<String, SpecSymExpr>,
    pub constraints: Vec<SymConstraint>,
    pub mem: std::collections::HashMap<u64, SpecSymExpr>,
}

impl SymState {
    /// Create a new, empty symbolic state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a variable to a symbolic expression.
    pub fn set_var(&mut self, name: impl Into<String>, val: SpecSymExpr) {
        self.vars.insert(name.into(), val);
    }

    /// Look up a variable.
    #[must_use]
    pub fn get_var(&self, name: &str) -> Option<&SpecSymExpr> {
        self.vars.get(name)
    }

    /// Add a path constraint.
    pub fn add_constraint(&mut self, c: SymConstraint) {
        self.constraints.push(c);
    }

    /// Store a value in symbolic memory at a concrete address.
    pub fn store_mem(&mut self, addr: u64, val: SpecSymExpr) {
        self.mem.insert(addr, val);
    }

    /// Load from symbolic memory at a concrete address.
    #[must_use]
    pub fn load_mem(&self, addr: u64) -> Option<&SpecSymExpr> {
        self.mem.get(&addr)
    }

    /// Clone this state.
    #[must_use]
    pub fn clone_state(&self) -> Self {
        self.clone()
    }
}

/// Symbolic execution errors (spec: `SymError`).
#[derive(Debug, thiserror::Error)]
pub enum SymError {
    #[error("unsupported operation: {0}")]
    UnsupportedOp(String),
    #[error("width mismatch: got {got}, expected {expected}")]
    WidthMismatch { got: u32, expected: u32 },
    #[error("unbound variable: {0}")]
    UnboundVar(String),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(val: u64, w: u32) -> SymExpr {
        SymExpr::ConstBv { val, width: w }
    }
    fn var(n: &str) -> SymExpr {
        SymExpr::var(n, SymType::BitVec(64))
    }
    fn s() -> SymExprSimplifier {
        SymExprSimplifier::new()
    }

    // ── SymType ───────────────────────────────────────────────────────────

    #[test]
    fn test_sym_type_width() {
        assert_eq!(SymType::BitVec(32).width(), Some(32));
        assert_eq!(SymType::Bool.width(), None);
        assert_eq!(SymType::Pointer.width(), Some(64));
    }

    // ── SymbolicState ─────────────────────────────────────────────────────

    #[test]
    fn test_state_register_roundtrip() {
        let mut st = SymbolicState::new();
        st.write_register("rax", bv(42, 64));
        assert_eq!(st.read_register("rax"), bv(42, 64));
    }

    #[test]
    fn test_state_undefined_register_returns_var() {
        let st = SymbolicState::new();
        let v = st.read_register("rbx");
        assert!(matches!(v, SymExpr::Var { name, .. } if name == "rbx"));
    }

    #[test]
    fn test_state_fork_increments_depth() {
        let st = SymbolicState::new();
        let child = st.fork(SymExpr::ConstBool(true));
        assert_eq!(child.depth, 1);
        assert_eq!(child.path_condition, vec![SymExpr::ConstBool(true)]);
    }

    #[test]
    fn test_state_infeasible_path() {
        let mut st = SymbolicState::new();
        st.add_path_condition(SymExpr::ConstBool(false));
        assert!(st.is_path_infeasible());
    }

    #[test]
    fn test_state_memory_roundtrip() {
        let mut st = SymbolicState::new();
        st.memory.store_concrete(0x1000, bv(0xdeadbeef, 32));
        assert_eq!(st.memory.load_concrete(0x1000), bv(0xdeadbeef, 32));
    }

    #[test]
    fn test_state_undefined_memory_returns_var() {
        let st = SymbolicState::new();
        let v = st.memory.load_concrete(0xdead);
        assert!(matches!(v, SymExpr::Var { .. }));
    }

    // ── PathConstraint ────────────────────────────────────────────────────

    #[test]
    fn test_path_constraint_empty_is_true() {
        let pc = PathConstraint::new();
        assert_eq!(pc.as_conjunction(), SymExpr::ConstBool(true));
    }

    #[test]
    fn test_path_constraint_single() {
        let mut pc = PathConstraint::new();
        pc.add(SymExpr::ConstBool(true));
        assert_eq!(pc.as_conjunction(), SymExpr::ConstBool(true));
    }

    #[test]
    fn test_path_constraint_trivially_false() {
        let mut pc = PathConstraint::new();
        pc.add(SymExpr::ConstBool(false));
        assert!(pc.is_trivially_false());
    }

    // ── Simplifier: constant folding ──────────────────────────────────────

    #[test]
    fn test_simp_add_constants() {
        let e = SymExpr::Add(Box::new(bv(10, 32)), Box::new(bv(20, 32)));
        assert_eq!(s().simplify(e), bv(30, 32));
    }

    #[test]
    fn test_simp_add_zero_identity() {
        let e = SymExpr::Add(Box::new(var("x")), Box::new(bv(0, 64)));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_sub_self_is_zero() {
        let e = SymExpr::Sub(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(s().simplify(e), bv(0, 64));
    }

    #[test]
    fn test_simp_mul_zero_is_zero() {
        let e = SymExpr::Mul(Box::new(var("x")), Box::new(bv(0, 64)));
        assert_eq!(s().simplify(e), bv(0, 64));
    }

    #[test]
    fn test_simp_mul_one_identity() {
        let e = SymExpr::Mul(Box::new(var("x")), Box::new(bv(1, 64)));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_xor_self_is_zero() {
        let e = SymExpr::Xor(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(s().simplify(e), bv(0, 64));
    }

    #[test]
    fn test_simp_and_zero_is_zero() {
        let e = SymExpr::And(Box::new(var("x")), Box::new(bv(0, 64)));
        assert_eq!(s().simplify(e), bv(0, 64));
    }

    #[test]
    fn test_simp_and_self_identity() {
        let e = SymExpr::And(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_or_self_identity() {
        let e = SymExpr::Or(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_not_not_is_identity() {
        let e = SymExpr::Not(Box::new(SymExpr::Not(Box::new(var("x")))));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_neg_neg_is_identity() {
        let e = SymExpr::Neg(Box::new(SymExpr::Neg(Box::new(var("x")))));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_simp_ite_true() {
        let e = SymExpr::Ite {
            cond: Box::new(SymExpr::ConstBool(true)),
            then_: Box::new(bv(1, 32)),
            else_: Box::new(bv(2, 32)),
        };
        assert_eq!(s().simplify(e), bv(1, 32));
    }

    #[test]
    fn test_simp_ite_false() {
        let e = SymExpr::Ite {
            cond: Box::new(SymExpr::ConstBool(false)),
            then_: Box::new(bv(1, 32)),
            else_: Box::new(bv(2, 32)),
        };
        assert_eq!(s().simplify(e), bv(2, 32));
    }

    #[test]
    fn test_simp_extract_const() {
        // Extract bits [7:0] from 0xABCD => 0xCD
        let e = SymExpr::Extract {
            expr: Box::new(bv(0xABCD, 16)),
            hi: 7,
            lo: 0,
        };
        assert_eq!(s().simplify(e), bv(0xCD, 8));
    }

    #[test]
    fn test_simp_zext_const() {
        let e = SymExpr::ZExt {
            expr: Box::new(bv(0xFF, 8)),
            target_width: 32,
        };
        assert_eq!(s().simplify(e), bv(0xFF, 32));
    }

    #[test]
    fn test_simp_sext_const_positive() {
        let e = SymExpr::SExt {
            expr: Box::new(bv(0x7F, 8)),
            target_width: 16,
        };
        assert_eq!(s().simplify(e), bv(0x007F, 16));
    }

    #[test]
    fn test_simp_sext_const_negative() {
        // 0xFF in 8-bit is -1, sign-extended to 16-bit is 0xFFFF
        let e = SymExpr::SExt {
            expr: Box::new(bv(0xFF, 8)),
            target_width: 16,
        };
        assert_eq!(s().simplify(e), bv(0xFFFF, 16));
    }

    #[test]
    fn test_simp_bool_and_false_short_circuit() {
        let e = SymExpr::BoolAnd(Box::new(SymExpr::ConstBool(false)), Box::new(var("x")));
        assert_eq!(s().simplify(e), SymExpr::ConstBool(false));
    }

    #[test]
    fn test_simp_bool_or_true_short_circuit() {
        let e = SymExpr::BoolOr(Box::new(SymExpr::ConstBool(true)), Box::new(var("x")));
        assert_eq!(s().simplify(e), SymExpr::ConstBool(true));
    }

    #[test]
    fn test_simp_comparison_eq_constants() {
        let e = SymExpr::Eq(Box::new(bv(5, 32)), Box::new(bv(5, 32)));
        assert_eq!(s().simplify(e), SymExpr::ConstBool(true));
    }

    #[test]
    fn test_simp_comparison_ne_constants() {
        let e = SymExpr::Ne(Box::new(bv(5, 32)), Box::new(bv(6, 32)));
        assert_eq!(s().simplify(e), SymExpr::ConstBool(true));
    }

    #[test]
    fn test_sym_memory_symbolic_store_load() {
        let mut m = SymMemory::new();
        m.store_symbolic(42, bv(0xDEAD, 16));
        assert_eq!(m.load_symbolic(42), Some(&bv(0xDEAD, 16)));
        assert_eq!(m.load_symbolic(99), None);
    }

    #[test]
    fn test_symbolic_value_new() {
        let v = SymbolicValue::new(1, SymType::BitVec(32), bv(0, 32));
        assert_eq!(v.id, 1);
        assert_eq!(v.ty, SymType::BitVec(32));
    }

    // ── SymWidth ──────────────────────────────────────────────────────────────

    #[test]
    fn test_symwidth_bits() {
        assert_eq!(SymWidth::W8.bits(), 8);
        assert_eq!(SymWidth::W16.bits(), 16);
        assert_eq!(SymWidth::W32.bits(), 32);
        assert_eq!(SymWidth::W64.bits(), 64);
    }

    #[test]
    fn test_symwidth_bytes() {
        assert_eq!(SymWidth::W8.bytes(), 1);
        assert_eq!(SymWidth::W16.bytes(), 2);
        assert_eq!(SymWidth::W32.bytes(), 4);
        assert_eq!(SymWidth::W64.bytes(), 8);
    }

    #[test]
    fn test_symwidth_display() {
        assert_eq!(SymWidth::W8.to_string(), "8");
        assert_eq!(SymWidth::W16.to_string(), "16");
        assert_eq!(SymWidth::W32.to_string(), "32");
        assert_eq!(SymWidth::W64.to_string(), "64");
    }

    // ── SpecSymExpr ───────────────────────────────────────────────────────────

    #[test]
    fn test_spec_symexpr_const_is_concrete() {
        let e = SpecSymExpr::Const {
            val: 42,
            width: SymWidth::W32,
        };
        assert!(e.is_concrete());
        assert_eq!(e.eval_concrete(), Some(42));
    }

    #[test]
    fn test_spec_symexpr_var_not_concrete() {
        let e = SpecSymExpr::Var {
            name: "x".to_string(),
            width: SymWidth::W64,
        };
        assert!(!e.is_concrete());
        assert_eq!(e.eval_concrete(), None);
    }

    #[test]
    fn test_spec_symexpr_add_concrete() {
        let l = SpecSymExpr::Const {
            val: 3,
            width: SymWidth::W32,
        };
        let r = SpecSymExpr::Const {
            val: 7,
            width: SymWidth::W32,
        };
        let e = SpecSymExpr::Add(Box::new(l), Box::new(r));
        assert_eq!(e.eval_concrete(), Some(10));
    }

    #[test]
    fn test_spec_symexpr_width() {
        let e = SpecSymExpr::Const {
            val: 0,
            width: SymWidth::W16,
        };
        assert_eq!(e.width(), Some(SymWidth::W16));
    }

    #[test]
    fn test_spec_symexpr_substitute() {
        let e = SpecSymExpr::Add(
            Box::new(SpecSymExpr::Var {
                name: "x".to_string(),
                width: SymWidth::W64,
            }),
            Box::new(SpecSymExpr::Const {
                val: 1,
                width: SymWidth::W64,
            }),
        );
        let sub = SpecSymExpr::Const {
            val: 10,
            width: SymWidth::W64,
        };
        let result = e.substitute("x", &sub);
        assert_eq!(result.eval_concrete(), Some(11));
    }

    #[test]
    fn test_spec_symexpr_not() {
        let e = SpecSymExpr::Not(Box::new(SpecSymExpr::Const {
            val: 0xFF,
            width: SymWidth::W8,
        }));
        // !0xFF = ~0xFF = wrapping not
        assert!(e.eval_concrete().is_some());
    }

    #[test]
    fn test_spec_symexpr_ite_true_branch() {
        let cond = SpecSymExpr::Const {
            val: 1,
            width: SymWidth::W8,
        };
        let t = SpecSymExpr::Const {
            val: 42,
            width: SymWidth::W32,
        };
        let f = SpecSymExpr::Const {
            val: 99,
            width: SymWidth::W32,
        };
        let e = SpecSymExpr::ITE(Box::new(cond), Box::new(t), Box::new(f));
        assert_eq!(e.eval_concrete(), Some(42));
    }

    #[test]
    fn test_spec_symexpr_ite_false_branch() {
        let cond = SpecSymExpr::Const {
            val: 0,
            width: SymWidth::W8,
        };
        let t = SpecSymExpr::Const {
            val: 42,
            width: SymWidth::W32,
        };
        let f = SpecSymExpr::Const {
            val: 99,
            width: SymWidth::W32,
        };
        let e = SpecSymExpr::ITE(Box::new(cond), Box::new(t), Box::new(f));
        assert_eq!(e.eval_concrete(), Some(99));
    }

    #[test]
    fn test_spec_symexpr_extract() {
        let e = SpecSymExpr::Extract {
            expr: Box::new(SpecSymExpr::Const {
                val: 0xABCD,
                width: SymWidth::W16,
            }),
            hi: 7,
            lo: 0,
        };
        assert_eq!(e.eval_concrete(), Some(0xCD));
    }

    // ── SymConstraint ─────────────────────────────────────────────────────────

    #[test]
    fn test_sym_constraint_assert() {
        let e = SpecSymExpr::Const {
            val: 1,
            width: SymWidth::W8,
        };
        let c = SymConstraint::assert(e);
        assert!(!c.is_negated);
    }

    #[test]
    fn test_sym_constraint_deny() {
        let e = SpecSymExpr::Const {
            val: 0,
            width: SymWidth::W8,
        };
        let c = SymConstraint::deny(e);
        assert!(c.is_negated);
    }

    // ── SymState ──────────────────────────────────────────────────────────────

    #[test]
    fn test_sym_state_set_get_var() {
        let mut st = SymState::new();
        st.set_var(
            "rax",
            SpecSymExpr::Const {
                val: 42,
                width: SymWidth::W64,
            },
        );
        assert!(st.get_var("rax").is_some());
        assert!(st.get_var("rbx").is_none());
    }

    #[test]
    fn test_sym_state_store_load_mem() {
        let mut st = SymState::new();
        st.store_mem(
            0x1000,
            SpecSymExpr::Const {
                val: 0xde,
                width: SymWidth::W8,
            },
        );
        assert!(st.load_mem(0x1000).is_some());
        assert!(st.load_mem(0x2000).is_none());
    }

    #[test]
    fn test_sym_state_add_constraint() {
        let mut st = SymState::new();
        let e = SpecSymExpr::Const {
            val: 1,
            width: SymWidth::W8,
        };
        st.add_constraint(SymConstraint::assert(e));
        assert_eq!(st.constraints.len(), 1);
    }

    #[test]
    fn test_sym_state_clone_state() {
        let mut st = SymState::new();
        st.set_var(
            "x",
            SpecSymExpr::Const {
                val: 5,
                width: SymWidth::W32,
            },
        );
        let cloned = st.clone_state();
        assert!(cloned.get_var("x").is_some());
    }

    // ── SymExpr::simplify / evaluate ─────────────────────────────────────────

    #[test]
    fn test_symexpr_simplify_method() {
        let e = SymExpr::Add(Box::new(bv(3, 32)), Box::new(bv(7, 32)));
        assert_eq!(e.simplify(), bv(10, 32));
    }

    #[test]
    fn test_symexpr_evaluate_const() {
        let e = bv(42, 64);
        let env = HashMap::new();
        assert_eq!(e.evaluate(&env), Some(42));
    }

    #[test]
    fn test_symexpr_evaluate_var_known() {
        let e = var("x");
        let mut env = HashMap::new();
        env.insert("x".to_string(), 99u64);
        assert_eq!(e.evaluate(&env), Some(99));
    }

    #[test]
    fn test_symexpr_evaluate_var_unknown() {
        let e = var("x");
        let env = HashMap::new();
        assert_eq!(e.evaluate(&env), None);
    }

    #[test]
    fn test_symexpr_evaluate_add() {
        let e = SymExpr::Add(Box::new(var("a")), Box::new(var("b")));
        let mut env = HashMap::new();
        env.insert("a".to_string(), 10u64);
        env.insert("b".to_string(), 20u64);
        assert_eq!(e.evaluate(&env), Some(30));
    }

    #[test]
    fn test_symexpr_evaluate_ite() {
        let e = SymExpr::Ite {
            cond: Box::new(var("flag")),
            then_: Box::new(bv(1, 64)),
            else_: Box::new(bv(0, 64)),
        };
        let mut env = HashMap::new();
        env.insert("flag".to_string(), 1u64);
        assert_eq!(e.evaluate(&env), Some(1));
        env.insert("flag".to_string(), 0u64);
        assert_eq!(e.evaluate(&env), Some(0));
    }

    // ── SymbolicState::assume ─────────────────────────────────────────────────

    #[test]
    fn test_assume_accepts_true() {
        let mut st = SymbolicState::new();
        assert!(st.assume(&SymExpr::ConstBool(true)).is_ok());
        assert_eq!(st.path_condition.len(), 1);
    }

    #[test]
    fn test_assume_rejects_false() {
        let mut st = SymbolicState::new();
        assert!(st.assume(&SymExpr::ConstBool(false)).is_err());
        // State must be unchanged on rejection.
        assert_eq!(st.path_condition.len(), 0);
    }

    #[test]
    fn test_assume_folds_constant() {
        let mut st = SymbolicState::new();
        // (true AND false) simplifies to false → Unsat
        let e = SymExpr::BoolAnd(
            Box::new(SymExpr::ConstBool(true)),
            Box::new(SymExpr::ConstBool(false)),
        );
        assert!(st.assume(&e).is_err());
    }

    // ── SymbolicState::is_satisfiable ─────────────────────────────────────────

    #[test]
    fn test_is_satisfiable_empty() {
        assert!(SymbolicState::new().is_satisfiable());
    }

    #[test]
    fn test_is_satisfiable_false_constraint() {
        let mut st = SymbolicState::new();
        st.path_condition.push(SymExpr::ConstBool(false));
        assert!(!st.is_satisfiable());
    }

    // ── SymbolicState::get_model ──────────────────────────────────────────────

    #[test]
    fn test_get_model_concrete_registers() {
        let mut st = SymbolicState::new();
        st.write_register("rax", bv(0xdead, 64));
        let model = st.get_model();
        assert_eq!(model.get("rax"), Some(&0xdead));
    }

    #[test]
    fn test_get_model_symbolic_var_defaults_to_zero() {
        let mut st = SymbolicState::new();
        st.path_condition.push(var("sym_input"));
        let model = st.get_model();
        assert_eq!(model.get("sym_input"), Some(&0u64));
    }

    // ── SymbolicState::fork_pair ──────────────────────────────────────────────

    #[test]
    fn test_fork_pair_conditions() {
        let st = SymbolicState::new();
        let (t, f) = st.fork_pair(SymExpr::ConstBool(true));
        assert_eq!(t.path_condition.last(), Some(&SymExpr::ConstBool(true)));
        assert!(matches!(f.path_condition.last(), Some(SymExpr::BoolNot(_))));
        assert_eq!(t.depth, 1);
        assert_eq!(f.depth, 1);
    }

    // ── SymbolicState::merge ──────────────────────────────────────────────────

    #[test]
    fn test_merge_same_register_no_ite() {
        let mut a = SymbolicState::new();
        let mut b = SymbolicState::new();
        a.write_register("rax", bv(5, 64));
        b.write_register("rax", bv(5, 64));
        let merged = SymbolicState::merge(a, b, &SymExpr::ConstBool(true));
        assert_eq!(merged.read_register("rax"), bv(5, 64));
    }

    #[test]
    fn test_merge_different_register_ite() {
        let mut a = SymbolicState::new();
        let mut b = SymbolicState::new();
        a.write_register("rax", bv(1, 64));
        b.write_register("rax", bv(2, 64));
        let cond = var("flag");
        let merged = SymbolicState::merge(a, b, &cond);
        let v = merged.read_register("rax");
        assert!(matches!(v, SymExpr::Ite { .. }));
    }

    // ── sym_add / sym_sub / sym_mul / sym_and / sym_or / sym_xor / sym_not ───

    #[test]
    fn test_sym_ops_fold_constants() {
        assert_eq!(sym_add(bv(3, 32), bv(4, 32)), bv(7, 32));
        assert_eq!(sym_sub(bv(10, 32), bv(3, 32)), bv(7, 32));
        assert_eq!(sym_mul(bv(3, 32), bv(4, 32)), bv(12, 32));
        assert_eq!(sym_and(bv(0xFF, 8), bv(0x0F, 8)), bv(0x0F, 8));
        assert_eq!(sym_or(bv(0xF0, 8), bv(0x0F, 8)), bv(0xFF, 8));
        assert_eq!(sym_xor(bv(0xFF, 8), bv(0xFF, 8)), bv(0, 8));
        assert_eq!(sym_not(bv(0x00, 8)), bv(0xFF, 8));
    }

    #[test]
    fn test_sym_add_symbolic_no_fold() {
        let result = sym_add(var("x"), bv(0, 64));
        // x + 0 simplifies to x
        assert_eq!(result, var("x"));
    }

    // ── Unsat / SymbolicError ─────────────────────────────────────────────────

    #[test]
    fn test_unsat_error_display() {
        let e = Unsat;
        assert!(e.to_string().contains("unsatisfiable"));
    }

    #[test]
    fn test_symbolic_error_new_variants() {
        let e = SymbolicError::SolverError("z3 timeout".to_string());
        assert!(e.to_string().contains("z3 timeout"));
        let e2 = SymbolicError::TypeError("bool vs bv".to_string());
        assert!(e2.to_string().contains("bool vs bv"));
        let e3 = SymbolicError::UndefinedVariable("rip".to_string());
        assert!(e3.to_string().contains("rip"));
        let _e4 = SymbolicError::Unsat; // compiles
    }

    // ── SymError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_sym_error_display() {
        let e = SymError::UnsupportedOp("rotate".to_string());
        assert!(e.to_string().contains("rotate"));
        let e2 = SymError::WidthMismatch {
            got: 32,
            expected: 64,
        };
        assert!(e2.to_string().contains("32"));
        let e3 = SymError::UnboundVar("foo".to_string());
        assert!(e3.to_string().contains("foo"));
    }
}
