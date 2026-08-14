//! Symbolic values: `SymbolicValue`, `ValueKind`, `ValueWidth`,
//! `symbolic_add()`, `symbolic_and()`.
//!
//! This module provides a self-contained symbolic-value abstraction used by
//! the symbolic execution engine to track computation across registers and
//! memory. Every value carries its *kind* (concrete, symbolic, or an
//! operation applied to prior values), its *width* in bits, and a compact
//! textual identity that can be turned into an SMT assertion.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

// ── Global symbolic-variable counter ─────────────────────────────────────────

static NEXT_SYM_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique symbolic-variable ID.
#[inline]
pub fn fresh_sym_id() -> u64 {
    NEXT_SYM_ID.fetch_add(1, Ordering::Relaxed)
}

// ── ValueWidth ────────────────────────────────────────────────────────────────

/// Bit-width of a symbolic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueWidth {
    W1,
    W8,
    W16,
    W32,
    W64,
    W128,
    /// Arbitrary bit-width (used for MSP430 20-bit addresses, SIMD, etc.).
    Custom(u32),
}

impl ValueWidth {
    /// Return the bit-width as a plain `u32`.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W1 => 1,
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
            Self::W128 => 128,
            Self::Custom(n) => n,
        }
    }

    /// Return the byte-width (rounded up).
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bits().div_ceil(8)
    }

    /// Maximum unsigned value representable in this width.
    #[must_use]
    pub const fn max_unsigned(self) -> u128 {
        let b = self.bits();
        if b >= 128 {
            u128::MAX
        } else {
            (1u128 << b).wrapping_sub(1)
        }
    }

    /// Return the bitmask for this width (fits in u64 for widths ≤ 64).
    #[must_use]
    pub const fn mask64(self) -> u64 {
        let b = self.bits();
        if b >= 64 {
            u64::MAX
        } else {
            (1u64 << b).wrapping_sub(1)
        }
    }

    /// Attempt to build a `ValueWidth` from a raw bit count.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        match bits {
            1 => Self::W1,
            8 => Self::W8,
            16 => Self::W16,
            32 => Self::W32,
            64 => Self::W64,
            128 => Self::W128,
            n => Self::Custom(n),
        }
    }
}

impl fmt::Display for ValueWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i{}", self.bits())
    }
}

// ── ValueKind ─────────────────────────────────────────────────────────────────

/// Describes the provenance and structure of a [`SymbolicValue`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueKind {
    /// A fully concrete integer constant.
    Concrete(u64),
    /// A symbolic input variable (e.g. an unconstrained register or memory
    /// cell at the start of analysis).
    Symbolic {
        /// Unique ID for this variable in the current execution session.
        id: u64,
        /// Human-readable origin hint (e.g. `"rax_entry"`, `"mem_0x1000"`).
        name: String,
    },
    /// Addition: `lhs + rhs`.
    Add(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Subtraction: `lhs - rhs`.
    Sub(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Multiplication: `lhs * rhs`.
    Mul(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Unsigned division: `lhs / rhs`.
    UDiv(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Bitwise AND: `lhs & rhs`.
    And(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Bitwise OR: `lhs | rhs`.
    Or(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Bitwise XOR: `lhs ^ rhs`.
    Xor(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Bitwise NOT: `~operand`.
    Not(Box<SymbolicValue>),
    /// Left shift: `lhs << amount`.
    Shl(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Logical right shift: `lhs >> amount`.
    Shr(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Zero-extension to `target_width`.
    ZExt {
        inner: Box<SymbolicValue>,
        target: ValueWidth,
    },
    /// Sign-extension to `target_width`.
    SExt {
        inner: Box<SymbolicValue>,
        target: ValueWidth,
    },
    /// Bit extraction `[hi:lo]` inclusive.
    Extract {
        inner: Box<SymbolicValue>,
        hi: u32,
        lo: u32,
    },
    /// If-then-else: `cond ? then_val : else_val`.
    Ite {
        cond: Box<SymbolicValue>,
        then_val: Box<SymbolicValue>,
        else_val: Box<SymbolicValue>,
    },
    /// Symbolic memory load.
    Load {
        addr: Box<SymbolicValue>,
        width: ValueWidth,
    },
    /// Equality predicate (returns W1).
    Eq(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Unsigned less-than (returns W1).
    ULt(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Signed less-than (returns W1).
    SLt(Box<SymbolicValue>, Box<SymbolicValue>),
}

// ── SymbolicValue ─────────────────────────────────────────────────────────────

/// A symbolic value: width + provenance kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicValue {
    pub width: ValueWidth,
    pub kind: ValueKind,
}

impl SymbolicValue {
    // ── Constructors ────────────────────────────────────────────────────────

    /// Build a concrete constant of the given width.
    #[must_use]
    pub const fn constant(val: u64, width: ValueWidth) -> Self {
        Self { width, kind: ValueKind::Concrete(val) }
    }

    /// Build a fresh symbolic variable with an auto-assigned ID.
    #[must_use]
    pub fn fresh_var(name: impl Into<String>, width: ValueWidth) -> Self {
        let id = fresh_sym_id();
        Self {
            width,
            kind: ValueKind::Symbolic { id, name: name.into() },
        }
    }

    /// Build a symbolic variable with a pre-assigned ID.
    #[must_use]
    pub fn var_with_id(id: u64, name: impl Into<String>, width: ValueWidth) -> Self {
        Self {
            width,
            kind: ValueKind::Symbolic { id, name: name.into() },
        }
    }

    /// Boolean false (W1 concrete 0).
    #[must_use]
    pub const fn bool_false() -> Self {
        Self::constant(0, ValueWidth::W1)
    }

    /// Boolean true (W1 concrete 1).
    #[must_use]
    pub const fn bool_true() -> Self {
        Self::constant(1, ValueWidth::W1)
    }

    // ── Predicates ──────────────────────────────────────────────────────────

    /// Return `true` if this value is a concrete constant.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self.kind, ValueKind::Concrete(_))
    }

    /// Return `true` if this value is a leaf symbolic variable.
    #[must_use]
    pub const fn is_symbolic_var(&self) -> bool {
        matches!(self.kind, ValueKind::Symbolic { .. })
    }

    /// Return the concrete value if it is one.
    #[must_use]
    pub const fn as_concrete(&self) -> Option<u64> {
        match &self.kind {
            ValueKind::Concrete(v) => Some(*v),
            _ => None,
        }
    }

    // ── Arithmetic operations (constant-folding variants) ───────────────────

    /// Wrapping addition with constant folding.
    #[must_use]
    pub fn add(self, rhs: Self) -> Self {
        let w = self.width;
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => {
                Self::constant(a.wrapping_add(*b) & w.mask64(), w)
            }
            _ => Self { width: w, kind: ValueKind::Add(Box::new(self), Box::new(rhs)) },
        }
    }

    /// Wrapping subtraction with constant folding.
    #[must_use]
    pub fn sub(self, rhs: Self) -> Self {
        let w = self.width;
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => {
                Self::constant(a.wrapping_sub(*b) & w.mask64(), w)
            }
            _ => Self { width: w, kind: ValueKind::Sub(Box::new(self), Box::new(rhs)) },
        }
    }

    /// Bitwise AND with constant folding.
    #[must_use]
    pub fn bitwise_and(self, rhs: Self) -> Self {
        let w = self.width;
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => Self::constant(a & b, w),
            _ => Self { width: w, kind: ValueKind::And(Box::new(self), Box::new(rhs)) },
        }
    }

    /// Bitwise OR with constant folding.
    #[must_use]
    pub fn bitwise_or(self, rhs: Self) -> Self {
        let w = self.width;
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => Self::constant(a | b, w),
            _ => Self { width: w, kind: ValueKind::Or(Box::new(self), Box::new(rhs)) },
        }
    }

    /// Bitwise XOR with constant folding.
    #[must_use]
    pub fn bitwise_xor(self, rhs: Self) -> Self {
        let w = self.width;
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => Self::constant(a ^ b, w),
            _ => Self { width: w, kind: ValueKind::Xor(Box::new(self), Box::new(rhs)) },
        }
    }

    /// Bitwise NOT with constant folding.
    #[must_use]
    pub fn bitwise_not(self) -> Self {
        let w = self.width;
        match &self.kind {
            ValueKind::Concrete(v) => Self::constant(!v & w.mask64(), w),
            _ => Self { width: w, kind: ValueKind::Not(Box::new(self)) },
        }
    }

    /// Logical left shift.
    #[must_use]
    pub fn shl(self, amount: Self) -> Self {
        let w = self.width;
        match (&self.kind, &amount.kind) {
            (ValueKind::Concrete(v), ValueKind::Concrete(s)) => {
                let shift = u32::try_from(*s).unwrap_or(63).min(63);
                Self::constant(v.wrapping_shl(shift) & w.mask64(), w)
            }
            _ => Self { width: w, kind: ValueKind::Shl(Box::new(self), Box::new(amount)) },
        }
    }

    /// Logical right shift.
    #[must_use]
    pub fn shr(self, amount: Self) -> Self {
        let w = self.width;
        match (&self.kind, &amount.kind) {
            (ValueKind::Concrete(v), ValueKind::Concrete(s)) => {
                let shift = u32::try_from(*s).unwrap_or(63).min(63);
                Self::constant(v.wrapping_shr(shift), w)
            }
            _ => Self { width: w, kind: ValueKind::Shr(Box::new(self), Box::new(amount)) },
        }
    }

    /// Zero-extend to `target`.
    #[must_use]
    pub fn zero_extend(self, target: ValueWidth) -> Self {
        match &self.kind {
            ValueKind::Concrete(v) => Self::constant(*v & target.mask64(), target),
            _ => Self { width: target, kind: ValueKind::ZExt { inner: Box::new(self), target } },
        }
    }

    /// Sign-extend to `target`.
    #[must_use]
    pub fn sign_extend(self, target: ValueWidth) -> Self {
        match &self.kind {
            ValueKind::Concrete(v) => {
                let src_bits = self.width.bits();
                let extended = if src_bits < 64 {
                    let sign_bit = 1u64 << (src_bits - 1);
                    if v & sign_bit != 0 {
                        v | !self.width.mask64()
                    } else {
                        *v
                    }
                } else {
                    *v
                };
                Self::constant(extended & target.mask64(), target)
            }
            _ => Self { width: target, kind: ValueKind::SExt { inner: Box::new(self), target } },
        }
    }

    /// Extract bits `[lo, hi]` inclusive.
    #[must_use]
    pub fn extract(self, lo: u32, hi: u32) -> Self {
        let result_width = ValueWidth::from_bits(hi.saturating_sub(lo).saturating_add(1));
        match &self.kind {
            ValueKind::Concrete(v) => {
                let mask = result_width.mask64();
                Self::constant((v >> lo) & mask, result_width)
            }
            _ => Self {
                width: result_width,
                kind: ValueKind::Extract { inner: Box::new(self), hi, lo },
            },
        }
    }

    /// ITE (if-then-else).
    #[must_use]
    pub fn ite(cond: Self, then_val: Self, else_val: Self) -> Self {
        let w = then_val.width;
        if let ValueKind::Concrete(c) = &cond.kind {
            if *c != 0 { then_val } else { else_val }
        } else {
            Self {
                width: w,
                kind: ValueKind::Ite {
                    cond: Box::new(cond),
                    then_val: Box::new(then_val),
                    else_val: Box::new(else_val),
                },
            }
        }
    }

    // ── Comparison operations ────────────────────────────────────────────────

    /// Unsigned less-than comparison (result is W1).
    #[must_use]
    pub fn ult(self, rhs: Self) -> Self {
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => {
                Self::constant(u64::from(a < b), ValueWidth::W1)
            }
            _ => Self {
                width: ValueWidth::W1,
                kind: ValueKind::ULt(Box::new(self), Box::new(rhs)),
            },
        }
    }

    /// Equality comparison (result is W1).
    #[must_use]
    pub fn eq_cmp(self, rhs: Self) -> Self {
        match (&self.kind, &rhs.kind) {
            (ValueKind::Concrete(a), ValueKind::Concrete(b)) => {
                Self::constant(u64::from(a == b), ValueWidth::W1)
            }
            _ => Self {
                width: ValueWidth::W1,
                kind: ValueKind::Eq(Box::new(self), Box::new(rhs)),
            },
        }
    }

    // ── Evaluation ───────────────────────────────────────────────────────────

    /// Attempt to evaluate this value to a concrete `u64` given a variable
    /// binding map (id → concrete value).
    #[must_use]
    pub fn evaluate(&self, env: &HashMap<u64, u64>) -> Option<u64> {
        match &self.kind {
            ValueKind::Concrete(v) => Some(*v),
            ValueKind::Symbolic { id, .. } => env.get(id).copied(),
            ValueKind::Add(l, r) => Some(l.evaluate(env)?.wrapping_add(r.evaluate(env)?)),
            ValueKind::Sub(l, r) => Some(l.evaluate(env)?.wrapping_sub(r.evaluate(env)?)),
            ValueKind::Mul(l, r) => Some(l.evaluate(env)?.wrapping_mul(r.evaluate(env)?)),
            ValueKind::UDiv(l, r) => {
                let rv = r.evaluate(env)?;
                if rv == 0 { None } else { Some(l.evaluate(env)? / rv) }
            }
            ValueKind::And(l, r) => Some(l.evaluate(env)? & r.evaluate(env)?),
            ValueKind::Or(l, r) => Some(l.evaluate(env)? | r.evaluate(env)?),
            ValueKind::Xor(l, r) => Some(l.evaluate(env)? ^ r.evaluate(env)?),
            ValueKind::Not(e) => Some(!e.evaluate(env)? & self.width.mask64()),
            ValueKind::Shl(v, s) => {
                let shift = u32::try_from(s.evaluate(env)?).ok()?.min(63);
                Some(v.evaluate(env)?.wrapping_shl(shift) & self.width.mask64())
            }
            ValueKind::Shr(v, s) => {
                let shift = u32::try_from(s.evaluate(env)?).ok()?.min(63);
                Some(v.evaluate(env)?.wrapping_shr(shift))
            }
            ValueKind::ZExt { inner, .. } => inner.evaluate(env),
            ValueKind::SExt { inner, target } => {
                let v = inner.evaluate(env)?;
                let src_bits = inner.width.bits();
                let extended = if src_bits < 64 {
                    let sign_bit = 1u64 << (src_bits - 1);
                    if v & sign_bit != 0 { v | !inner.width.mask64() } else { v }
                } else {
                    v
                };
                Some(extended & target.mask64())
            }
            ValueKind::Extract { inner, hi, lo } => {
                let v = inner.evaluate(env)?;
                // Mask is derived from the explicit bit range [lo, hi] so that
                // callers requesting an extract narrower than `self.width`
                // still get a correctly truncated value (defends against a
                // mismatched container width).
                let span_bits = hi.saturating_sub(*lo).saturating_add(1);
                let range_mask: u64 = if span_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << span_bits) - 1
                };
                let result_mask = self.width.mask64() & range_mask;
                Some((v >> lo) & result_mask)
            }
            ValueKind::Ite { cond, then_val, else_val } => {
                if cond.evaluate(env)? != 0 { then_val.evaluate(env) } else { else_val.evaluate(env) }
            }
            ValueKind::Eq(l, r) => Some(u64::from(l.evaluate(env)? == r.evaluate(env)?)),
            ValueKind::ULt(l, r) => Some(u64::from(l.evaluate(env)? < r.evaluate(env)?)),
            ValueKind::SLt(l, r) => {
                let a = l.evaluate(env)? as i64;
                let b = r.evaluate(env)? as i64;
                Some(u64::from(a < b))
            }
            ValueKind::Load { .. } => None,
        }
    }

    // ── SMT-LIB emission ────────────────────────────────────────────────────

    /// Emit a SMT-LIB 2.6 s-expression for this value.
    #[must_use]
    pub fn to_smt(&self) -> String {
        let width = self.width.bits();
        match &self.kind {
            ValueKind::Concrete(v) => format!("(_ bv{v} {width})"),
            ValueKind::Symbolic { name, .. } => name.clone(),
            ValueKind::Add(l, r) => format!("(bvadd {} {})", l.to_smt(), r.to_smt()),
            ValueKind::Sub(l, r) => format!("(bvsub {} {})", l.to_smt(), r.to_smt()),
            ValueKind::Mul(l, r) => format!("(bvmul {} {})", l.to_smt(), r.to_smt()),
            ValueKind::UDiv(l, r) => format!("(bvudiv {} {})", l.to_smt(), r.to_smt()),
            ValueKind::And(l, r) => format!("(bvand {} {})", l.to_smt(), r.to_smt()),
            ValueKind::Or(l, r) => format!("(bvor {} {})", l.to_smt(), r.to_smt()),
            ValueKind::Xor(l, r) => format!("(bvxor {} {})", l.to_smt(), r.to_smt()),
            ValueKind::Not(e) => format!("(bvnot {})", e.to_smt()),
            ValueKind::Shl(v, s) => format!("(bvshl {} {})", v.to_smt(), s.to_smt()),
            ValueKind::Shr(v, s) => format!("(bvlshr {} {})", v.to_smt(), s.to_smt()),
            ValueKind::ZExt { inner, target } => {
                let ext = target.bits() - inner.width.bits();
                format!("((_ zero_extend {ext}) {})", inner.to_smt())
            }
            ValueKind::SExt { inner, target } => {
                let ext = target.bits() - inner.width.bits();
                format!("((_ sign_extend {ext}) {})", inner.to_smt())
            }
            ValueKind::Extract { inner, hi, lo } => {
                format!("((_ extract {hi} {lo}) {})", inner.to_smt())
            }
            ValueKind::Ite { cond, then_val, else_val } => {
                format!("(ite (= {} (_ bv1 1)) {} {})", cond.to_smt(), then_val.to_smt(), else_val.to_smt())
            }
            ValueKind::Load { addr, .. } => format!("(select MEM {})", addr.to_smt()),
            ValueKind::Eq(l, r) => format!("(ite (= {} {}) (_ bv1 1) (_ bv0 1))", l.to_smt(), r.to_smt()),
            ValueKind::ULt(l, r) => format!("(ite (bvult {} {}) (_ bv1 1) (_ bv0 1))", l.to_smt(), r.to_smt()),
            ValueKind::SLt(l, r) => format!("(ite (bvslt {} {}) (_ bv1 1) (_ bv0 1))", l.to_smt(), r.to_smt()),
        }
    }

    /// Collect all symbolic variable IDs in this expression tree.
    pub fn collect_vars(&self, out: &mut HashMap<u64, String>) {
        match &self.kind {
            ValueKind::Symbolic { id, name } => { out.insert(*id, name.clone()); }
            ValueKind::Concrete(_) => {}
            ValueKind::Add(l, r) | ValueKind::Sub(l, r) | ValueKind::Mul(l, r)
            | ValueKind::UDiv(l, r) | ValueKind::And(l, r) | ValueKind::Or(l, r)
            | ValueKind::Xor(l, r) | ValueKind::Shl(l, r) | ValueKind::Shr(l, r)
            | ValueKind::Eq(l, r) | ValueKind::ULt(l, r) | ValueKind::SLt(l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
            ValueKind::Not(e) | ValueKind::ZExt { inner: e, .. }
            | ValueKind::SExt { inner: e, .. } | ValueKind::Extract { inner: e, .. }
            | ValueKind::Load { addr: e, .. } => {
                e.collect_vars(out);
            }
            ValueKind::Ite { cond, then_val, else_val } => {
                cond.collect_vars(out);
                then_val.collect_vars(out);
                else_val.collect_vars(out);
            }
        }
    }
}

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ValueKind::Concrete(v) => write!(f, "{v:#x}:{}", self.width),
            ValueKind::Symbolic { name, .. } => write!(f, "{name}:{}", self.width),
            ValueKind::Add(l, r) => write!(f, "({l} + {r})"),
            ValueKind::Sub(l, r) => write!(f, "({l} - {r})"),
            ValueKind::Mul(l, r) => write!(f, "({l} * {r})"),
            ValueKind::UDiv(l, r) => write!(f, "({l} /u {r})"),
            ValueKind::And(l, r) => write!(f, "({l} & {r})"),
            ValueKind::Or(l, r) => write!(f, "({l} | {r})"),
            ValueKind::Xor(l, r) => write!(f, "({l} ^ {r})"),
            ValueKind::Not(e) => write!(f, "~{e}"),
            ValueKind::Shl(v, s) => write!(f, "({v} << {s})"),
            ValueKind::Shr(v, s) => write!(f, "({v} >> {s})"),
            ValueKind::ZExt { inner, target } => write!(f, "zext({inner}, {target})"),
            ValueKind::SExt { inner, target } => write!(f, "sext({inner}, {target})"),
            ValueKind::Extract { inner, hi, lo } => write!(f, "{inner}[{hi}:{lo}]"),
            ValueKind::Ite { cond, then_val, else_val } => {
                write!(f, "({cond} ? {then_val} : {else_val})")
            }
            ValueKind::Load { addr, width } => write!(f, "load({addr}, {width})"),
            ValueKind::Eq(l, r) => write!(f, "({l} == {r})"),
            ValueKind::ULt(l, r) => write!(f, "({l} <u {r})"),
            ValueKind::SLt(l, r) => write!(f, "({l} <s {r})"),
        }
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Build `lhs + rhs` with constant folding and width propagation.
#[must_use]
pub fn symbolic_add(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    lhs.add(rhs)
}

/// Build `lhs & rhs` with constant folding and width propagation.
#[must_use]
pub fn symbolic_and(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    lhs.bitwise_and(rhs)
}

/// Build `lhs | rhs`.
#[must_use]
pub fn symbolic_or(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    lhs.bitwise_or(rhs)
}

/// Build `lhs ^ rhs`.
#[must_use]
pub fn symbolic_xor(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    lhs.bitwise_xor(rhs)
}

/// Build `lhs - rhs`.
#[must_use]
pub fn symbolic_sub(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    lhs.sub(rhs)
}

/// Build `~expr`.
#[must_use]
pub fn symbolic_not(expr: SymbolicValue) -> SymbolicValue {
    expr.bitwise_not()
}

// ── ValueBuilder — fluent builder API ─────────────────────────────────────────

/// Fluent builder for constructing symbolic values without the full
/// `SymbolicValue` type being visible at the call site.
#[derive(Debug, Default)]
pub struct ValueBuilder {
    width: Option<ValueWidth>,
}

impl ValueBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self { width: None }
    }

    #[must_use]
    pub const fn with_width(mut self, w: ValueWidth) -> Self {
        self.width = Some(w);
        self
    }

    #[must_use]
    pub fn constant(self, val: u64) -> SymbolicValue {
        let w = self.width.unwrap_or(ValueWidth::W64);
        SymbolicValue::constant(val, w)
    }

    #[must_use]
    pub fn fresh_var(self, name: impl Into<String>) -> SymbolicValue {
        let w = self.width.unwrap_or(ValueWidth::W64);
        SymbolicValue::fresh_var(name, w)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_width_bits() {
        assert_eq!(ValueWidth::W8.bits(), 8);
        assert_eq!(ValueWidth::W64.bits(), 64);
        assert_eq!(ValueWidth::Custom(20).bits(), 20);
    }

    #[test]
    fn test_constant_folding_add() {
        let a = SymbolicValue::constant(10, ValueWidth::W32);
        let b = SymbolicValue::constant(20, ValueWidth::W32);
        let c = symbolic_add(a, b);
        assert_eq!(c.as_concrete(), Some(30));
    }

    #[test]
    fn test_constant_folding_and() {
        let a = SymbolicValue::constant(0xFF00, ValueWidth::W16);
        let b = SymbolicValue::constant(0x0F0F, ValueWidth::W16);
        let c = symbolic_and(a, b);
        assert_eq!(c.as_concrete(), Some(0x0F00));
    }

    #[test]
    fn test_symbolic_add_stays_symbolic() {
        let a = SymbolicValue::fresh_var("x", ValueWidth::W64);
        let b = SymbolicValue::constant(1, ValueWidth::W64);
        let c = symbolic_add(a, b);
        assert!(!c.is_concrete());
    }

    #[test]
    fn test_evaluate_symbolic() {
        let a = SymbolicValue::var_with_id(42, "x", ValueWidth::W32);
        let b = SymbolicValue::constant(5, ValueWidth::W32);
        let c = symbolic_add(a, b);
        let env: HashMap<u64, u64> = [(42, 10)].into();
        assert_eq!(c.evaluate(&env), Some(15));
    }

    #[test]
    fn test_smt_concrete() {
        let v = SymbolicValue::constant(42, ValueWidth::W32);
        assert_eq!(v.to_smt(), "(_ bv42 32)");
    }

    #[test]
    fn test_extract_concrete() {
        let v = SymbolicValue::constant(0xABCD, ValueWidth::W16);
        let lo = v.extract(0, 7);
        assert_eq!(lo.as_concrete(), Some(0xCD));
    }

    #[test]
    fn test_ite_concrete_true() {
        let cond = SymbolicValue::constant(1, ValueWidth::W1);
        let t = SymbolicValue::constant(100, ValueWidth::W32);
        let e = SymbolicValue::constant(200, ValueWidth::W32);
        let result = SymbolicValue::ite(cond, t, e);
        assert_eq!(result.as_concrete(), Some(100));
    }

    #[test]
    fn test_ite_concrete_false() {
        let cond = SymbolicValue::constant(0, ValueWidth::W1);
        let t = SymbolicValue::constant(100, ValueWidth::W32);
        let e = SymbolicValue::constant(200, ValueWidth::W32);
        let result = SymbolicValue::ite(cond, t, e);
        assert_eq!(result.as_concrete(), Some(200));
    }

    #[test]
    fn test_zero_extend() {
        let v = SymbolicValue::constant(0xFF, ValueWidth::W8);
        let z = v.zero_extend(ValueWidth::W32);
        assert_eq!(z.as_concrete(), Some(0xFF));
    }

    #[test]
    fn test_sign_extend() {
        let v = SymbolicValue::constant(0x80, ValueWidth::W8);
        let s = v.sign_extend(ValueWidth::W16);
        assert_eq!(s.as_concrete(), Some(0xFF80));
    }

    #[test]
    fn test_fresh_sym_id_unique() {
        let id1 = fresh_sym_id();
        let id2 = fresh_sym_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_collect_vars() {
        let a = SymbolicValue::var_with_id(1, "a", ValueWidth::W32);
        let b = SymbolicValue::var_with_id(2, "b", ValueWidth::W32);
        let sum = symbolic_add(a, b);
        let mut vars = HashMap::new();
        sum.collect_vars(&mut vars);
        assert!(vars.contains_key(&1));
        assert!(vars.contains_key(&2));
    }

    #[test]
    fn test_builder() {
        let v = ValueBuilder::new().with_width(ValueWidth::W16).constant(0xBEEF);
        assert_eq!(v.as_concrete(), Some(0xBEEF));
        assert_eq!(v.width, ValueWidth::W16);
    }
}
