//! x86 IR evaluator — symbolic / concrete execution of `IrExpr` / `Effect`.
//!
//! This module provides a lightweight interpreter that can execute a
//! `Vec<Effect>` (the output of the lifter) against a concrete CPU state
//! (`X86CpuState`). Its primary uses are:
//!
//!   * **Semantic equivalence testing**: run the same bytes through
//!     `iced-x86` → lifter → `X86Eval`, compare the resulting register file
//!     with the state produced by a real emulator (unicorn-engine) or the
//!     native CPU.
//!   * **Constant folding / partial evaluation**: statically evaluate
//!     sub-trees of `IrExpr` that only reference constants, enabling later
//!     MLIL passes to simplify flag expressions whose inputs are known.
//!   * **Unit testing without a real CPU**: construct an `X86CpuState` with
//!     synthetic register values, execute a lifted instruction's effects, and
//!     assert on the resulting state.
//!
//! The evaluator is **intentionally unsound for unknown values**: any
//! `IrExpr::Undef` propagates as `EvalValue::Unknown` through the entire
//! expression tree.  This is correct for testing purposes — if the lifter
//! emits `Undef` for CF on ADD, the evaluator surfaces that as a gap rather
//! than hiding it with a random bit.

use crate::{Effect, IrExpr};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// EvalValue
// ─────────────────────────────────────────────────────────────────────────────

/// The result type for the evaluator.
///
/// An `EvalValue` is either a concrete 64-bit word or `Unknown` (propagated
/// from `IrExpr::Undef` and from unresolved register reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalValue {
    /// Concrete unsigned 64-bit value.
    Concrete(u64),
    /// Value not statically determinable (e.g., came from `IrExpr::Undef` or
    /// a register that was never written in this evaluation context).
    Unknown,
}

impl EvalValue {
    /// Unwrap the concrete value, panicking if `Unknown`.
    /// Use only in tests where you know the value is concrete.
    #[must_use]
    #[track_caller]
    /// Lifts this instruction into the IL.
    ///
    /// # Panics
    ///
    /// Panics if internal state is inconsistent.
    pub fn unwrap(self) -> u64 {
        match self {
            Self::Concrete(v) => v,
            Self::Unknown => panic!("EvalValue::Unknown: expected concrete"),
        }
    }

    /// Unwrap or return a default.
    #[must_use]
    pub const fn unwrap_or(self, default: u64) -> u64 {
        match self {
            Self::Concrete(v) => v,
            Self::Unknown => default,
        }
    }

    /// Map over the concrete value, leaving `Unknown` as `Unknown`.
    #[must_use]
    pub fn map<F: FnOnce(u64) -> u64>(self, f: F) -> Self {
        match self {
            Self::Concrete(v) => Self::Concrete(f(v)),
            Self::Unknown => Self::Unknown,
        }
    }

    /// Combine two values with a binary operation. If either is `Unknown`
    /// the result is `Unknown`.
    #[must_use]
    pub fn binop<F: FnOnce(u64, u64) -> u64>(self, rhs: Self, f: F) -> Self {
        match (self, rhs) {
            (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(f(a, b)),
            _ => Self::Unknown,
        }
    }

    /// `true` if the value is concrete zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        matches!(self, Self::Concrete(0))
    }

    /// `true` if the value is concretely non-zero.
    #[must_use]
    pub const fn is_nonzero(self) -> bool {
        matches!(self, Self::Concrete(v) if v != 0)
    }

    /// `true` iff the value is `Unknown`.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// The concrete value, or `None` if `Unknown`.
    #[must_use]
    pub const fn as_concrete(self) -> Option<u64> {
        match self {
            Self::Concrete(v) => Some(v),
            Self::Unknown => None,
        }
    }
}

impl fmt::Display for EvalValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#x}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl From<u64> for EvalValue {
    fn from(v: u64) -> Self {
        Self::Concrete(v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86CpuState
// ─────────────────────────────────────────────────────────────────────────────

/// Concrete CPU state used by the evaluator.
///
/// Registers are stored by canonical lower-case name (`rax`, `rbx`, …,
/// `cf`, `zf`, …). Memory is stored as a flat address → byte map; reads of
/// un-written addresses return `EvalValue::Unknown`.
#[derive(Debug, Clone)]
pub struct X86CpuState {
    /// Register file: name → 64-bit value (concrete or unknown).
    pub regs: HashMap<String, EvalValue>,
    /// Memory: virtual address → byte value.
    pub mem: HashMap<u64, u8>,
    /// Number of instructions evaluated on this state.
    pub step_count: u64,
    /// Flag values computed by a preceding `x86.flag.*` intrinsic, consumed by
    /// the immediately-following `RegWrite { reg: <flag>, value: Undef }`. This
    /// realises the lazy-flag idiom: the intrinsic carries the formula, the
    /// `RegWrite` commits the bit. Keyed by flag name (`cf`, `of`, `af`, …).
    pub pending_flags: HashMap<String, EvalValue>,
}

impl X86CpuState {
    /// Create an empty state (all registers unknown, no memory).
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: HashMap::new(),
            mem: HashMap::new(),
            step_count: 0,
            pending_flags: HashMap::new(),
        }
    }

    /// Create a state with all general-purpose registers set to the given
    /// concrete values. Useful for synthetic unit tests.
    #[must_use]
    pub fn with_gp_regs(values: &[(&str, u64)]) -> Self {
        let mut s = Self::new();
        for &(name, val) in values {
            s.set_reg(name, EvalValue::Concrete(val));
        }
        s
    }

    /// Read a register, returning `Unknown` if it was never written.
    #[must_use]
    pub fn get_reg(&self, name: &str) -> EvalValue {
        if let Some((parent, bits, offset)) = gpr_info(name) {
            match self.regs.get(parent).copied().unwrap_or(EvalValue::Unknown) {
                EvalValue::Concrete(val) => {
                    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                    EvalValue::Concrete((val >> offset) & mask)
                }
                EvalValue::Unknown => {
                    *self.regs.get(name).unwrap_or(&EvalValue::Unknown)
                }
            }
        } else {
            *self.regs.get(name).unwrap_or(&EvalValue::Unknown)
        }
    }

    /// Read a register as a concrete u64, returning 0 if it is `Unknown`.
    /// Convenience for tests that compare numerically.
    #[must_use]
    pub fn read_reg(&self, name: &str) -> u64 {
        match self.get_reg(name) {
            EvalValue::Concrete(v) => v,
            EvalValue::Unknown => 0,
        }
    }

    /// Write a register.
    pub fn set_reg(&mut self, name: &str, val: EvalValue) {
        if let Some((parent, bits, offset)) = gpr_info(name) {
            match val {
                EvalValue::Concrete(new_val) => {
                    let current_parent_val = match self.regs.get(parent).copied().unwrap_or(EvalValue::Unknown) {
                        EvalValue::Concrete(v) => v,
                        EvalValue::Unknown => 0,
                    };
                    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                    let clean_new_val = new_val & mask;
                    let parent_mask = !(mask << offset);
                    let updated_parent_val = (current_parent_val & parent_mask) | (clean_new_val << offset);
                    self.regs.insert(parent.to_string(), EvalValue::Concrete(updated_parent_val));
                }
                EvalValue::Unknown => {
                    self.regs.insert(parent.to_string(), EvalValue::Unknown);
                }
            }
        } else {
            self.regs.insert(name.to_string(), val);
        }
    }
}

fn gpr_info(name: &str) -> Option<(&'static str, u32, u32)> {
    let res = match name {
        "rax" => ("rax", 64, 0),
        "eax" => ("rax", 32, 0),
        "ax"  => ("rax", 16, 0),
        "al"  => ("rax", 8, 0),
        "ah"  => ("rax", 8, 8),

        "rbx" => ("rbx", 64, 0),
        "ebx" => ("rbx", 32, 0),
        "bx"  => ("rbx", 16, 0),
        "bl"  => ("rbx", 8, 0),
        "bh"  => ("rbx", 8, 8),

        "rcx" => ("rcx", 64, 0),
        "ecx" => ("rcx", 32, 0),
        "cx"  => ("rcx", 16, 0),
        "cl"  => ("rcx", 8, 0),
        "ch"  => ("rcx", 8, 8),

        "rdx" => ("rdx", 64, 0),
        "edx" => ("rdx", 32, 0),
        "dx"  => ("rdx", 16, 0),
        "dl"  => ("rdx", 8, 0),
        "dh"  => ("rdx", 8, 8),

        "rsi" => ("rsi", 64, 0),
        "esi" => ("rsi", 32, 0),
        "si"  => ("rsi", 16, 0),
        "sil" => ("rsi", 8, 0),

        "rdi" => ("rdi", 64, 0),
        "edi" => ("rdi", 32, 0),
        "di"  => ("rdi", 16, 0),
        "dil" => ("rdi", 8, 0),

        "rsp" => ("rsp", 64, 0),
        "esp" => ("rsp", 32, 0),
        "sp"  => ("rsp", 16, 0),
        "spl" => ("rsp", 8, 0),

        "rbp" => ("rbp", 64, 0),
        "ebp" => ("rbp", 32, 0),
        "bp"  => ("rbp", 16, 0),
        "bpl" => ("rbp", 8, 0),

        "r8"  => ("r8", 64, 0),
        "r8d" => ("r8", 32, 0),
        "r8w" => ("r8", 16, 0),
        "r8l" => ("r8", 8, 0),

        "r9"  => ("r9", 64, 0),
        "r9d" => ("r9", 32, 0),
        "r9w" => ("r9", 16, 0),
        "r9l" => ("r9", 8, 0),

        "r10"  => ("r10", 64, 0),
        "r10d" => ("r10", 32, 0),
        "r10w" => ("r10", 16, 0),
        "r10l" => ("r10", 8, 0),

        "r11"  => ("r11", 64, 0),
        "r11d" => ("r11", 32, 0),
        "r11w" => ("r11", 16, 0),
        "r11l" => ("r11", 8, 0),

        "r12"  => ("r12", 64, 0),
        "r12d" => ("r12", 32, 0),
        "r12w" => ("r12", 16, 0),
        "r12l" => ("r12", 8, 0),

        "r13"  => ("r13", 64, 0),
        "r13d" => ("r13", 32, 0),
        "r13w" => ("r13", 16, 0),
        "r13l" => ("r13", 8, 0),

        "r14"  => ("r14", 64, 0),
        "r14d" => ("r14", 32, 0),
        "r14w" => ("r14", 16, 0),
        "r14l" => ("r14", 8, 0),

        "r15"  => ("r15", 64, 0),
        "r15d" => ("r15", 32, 0),
        "r15w" => ("r15", 16, 0),
        "r15l" => ("r15", 8, 0),

        "rip"  => ("rip", 64, 0),
        "eip"  => ("rip", 32, 0),
        "ip"   => ("rip", 16, 0),

        _ => return None,
    };
    Some(res)
}

impl X86CpuState {
    /// Read `size` bytes from memory starting at `addr`.
    ///
    /// Returns `Unknown` if any byte in the range was never written.
    #[must_use]
    pub fn read_mem(&self, addr: u64, size: u8) -> EvalValue {
        let mut result = 0u64;
        for i in 0..u64::from(size) {
            match self.mem.get(&(addr + i)) {
                Some(&b) => result |= u64::from(b) << (i * 8),
                None => return EvalValue::Unknown,
            }
        }
        EvalValue::Concrete(result)
    }

    /// Write `size` bytes of `value` to memory at `addr`.
    /// If `value` is `Unknown`, marks all bytes as unknown by removing them.
    ///
    /// The memory map is capped at 65536 entries to prevent denial-of-service
    /// via unbounded memory growth when processing untrusted binary input.
    pub fn write_mem(&mut self, addr: u64, val: EvalValue, size: u8) {
        const MEM_CAP: usize = 65536;
        match val {
            EvalValue::Concrete(v) => {
                for i in 0..u64::from(size) {
                    if self.mem.len() >= MEM_CAP && !self.mem.contains_key(&(addr + i)) {
                        break;
                    }
                    let byte = ((v >> (i * 8)) & 0xff) as u8;
                    self.mem.insert(addr + i, byte);
                }
            }
            EvalValue::Unknown => {
                for i in 0..u64::from(size) {
                    self.mem.remove(&(addr + i));
                }
            }
        }
    }

    /// Assert that register `name` has a concrete value equal to `expected`.
    /// Panics with a detailed message if not.
    #[track_caller]
    /// Lifts this instruction into the IL.
    ///
    /// # Panics
    ///
    /// Panics if internal state is inconsistent.
    pub fn assert_reg(&self, name: &str, expected: u64) {
        let got = self.get_reg(name);
        assert_eq!(
            got,
            EvalValue::Concrete(expected),
            "register {name}: expected {expected:#x}, got {got}"
        );
    }

    /// Assert that register `name` is concretely zero.
    #[track_caller]
    pub fn assert_zero(&self, name: &str) {
        self.assert_reg(name, 0);
    }

    /// Assert that register `name` is concretely non-zero.
    #[track_caller]
    /// Lifts this instruction into the IL.
    ///
    /// # Panics
    ///
    /// Panics if internal state is inconsistent.
    pub fn assert_nonzero(&self, name: &str) {
        let got = self.get_reg(name);
        assert!(
            got.is_nonzero(),
            "register {name}: expected non-zero, got {got}"
        );
    }

    /// Dump the state to a human-readable string (for test failure messages).
    #[must_use]
    pub fn dump(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let mut names: Vec<_> = self.regs.keys().collect();
        names.sort();
        for n in names {
            let v = self.regs[n];
            let _ = writeln!(out, "  {n:8} = {v}");
        }
        out
    }
}

impl Default for X86CpuState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrExpr evaluator
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate an `IrExpr` against a CPU state, returning a concrete value or
/// `Unknown`.
///
/// Recursion depth is capped at 1024 to prevent stack overflow on
/// adversarially deep expression trees sourced from untrusted binary input.
#[must_use]
pub fn eval_expr(expr: &IrExpr, state: &X86CpuState) -> EvalValue {
    eval_expr_inner(expr, state, 1024)
}

fn eval_expr_inner(expr: &IrExpr, state: &X86CpuState, depth_remaining: usize) -> EvalValue {
    if depth_remaining == 0 {
        return EvalValue::Unknown;
    }
    let rec = |e: &IrExpr| eval_expr_inner(e, state, depth_remaining - 1);
    match expr {
        IrExpr::Const(v) => EvalValue::Concrete(*v),
        IrExpr::Reg(name) => state.get_reg(name),
        IrExpr::Undef => EvalValue::Unknown,

        IrExpr::Add(a, b) => {
            rec(a).binop(rec(b), u64::wrapping_add)
        }
        IrExpr::Sub(a, b) => {
            rec(a).binop(rec(b), u64::wrapping_sub)
        }
        IrExpr::Mul(a, b) => {
            rec(a).binop(rec(b), u64::wrapping_mul)
        }
        IrExpr::And(a, b) => rec(a).binop(rec(b), |x, y| x & y),
        IrExpr::Or(a, b) => rec(a).binop(rec(b), |x, y| x | y),
        IrExpr::Xor(a, b) => rec(a).binop(rec(b), |x, y| x ^ y),
        IrExpr::Shl(a, b) => {
            rec(a).binop(rec(b), |x, y| if y >= 64 { 0 } else { x << y })
        }
        IrExpr::Shr(a, b) => {
            rec(a).binop(rec(b), |x, y| if y >= 64 { 0 } else { x >> y })
        }
        // ARITHMETIC shift: cast through `i64` so the sign bit fills from the
        // left. An out-of-range count saturates to the sign extension (all
        // ones for a negative value), NOT to zero — that is the whole
        // difference from the logical shift above.
        IrExpr::Sar(a, b) => rec(a).binop(rec(b), |x, y| {
            let sx = x as i64;
            (if y >= 64 { sx >> 63 } else { sx >> y }) as u64
        }),
        IrExpr::Not(a) => rec(a).map(|x| !x),

        IrExpr::Deref(addr, size) => match rec(addr) {
            EvalValue::Concrete(a) => state.read_mem(a, *size),
            EvalValue::Unknown => EvalValue::Unknown,
        },

        IrExpr::CmpEqZero(a) => rec(a).map(|x| u64::from(x == 0)),

        IrExpr::Parity(a) => {
            rec(a).map(|x| {
                let byte = x & 0xff;
                // Even parity of the low byte: 1 if even number of set bits.
                let ones = byte.count_ones();
                u64::from(ones.is_multiple_of(2))
            })
        }
        IrExpr::CmpEq(a, b) => {
            rec(a).binop(rec(b), |x, y| u64::from(x == y))
        }
        IrExpr::CmpLt(a, b) => rec(a).binop(rec(b), |x, y| {
            u64::from(x.cast_signed() < y.cast_signed())
        }),
        // Unsigned counterpart: compare the raw values, no sign cast.
        IrExpr::CmpLtU(a, b) => rec(a).binop(rec(b), |x, y| u64::from(x < y)),
        IrExpr::CmpGt(a, b) => rec(a).binop(rec(b), |x, y| {
            u64::from(x.cast_signed() > y.cast_signed())
        }),
        IrExpr::Eq(a, b) => {
            rec(a).binop(rec(b), |x, y| u64::from(x == y))
        }
        IrExpr::Ne(a, b) => {
            rec(a).binop(rec(b), |x, y| u64::from(x != y))
        }
        IrExpr::IfThenElse(c, t, e) => {
            let cv = rec(c);
            if cv.is_unknown() {
                EvalValue::Unknown
            } else if cv.is_nonzero() {
                rec(t)
            } else {
                rec(e)
            }
        }
    }
}

/// Attempt to reduce an `IrExpr` to a simpler form by constant-folding.
///
/// Returns a new `IrExpr` with all constant sub-trees collapsed.
/// This is a best-effort pass — `Undef` and `Reg` nodes that cannot be
/// resolved remain unchanged.
#[must_use]
pub fn fold_expr(expr: &IrExpr) -> IrExpr {
    fold_expr_inner(expr, 1024)
}

fn fold_expr_inner(expr: &IrExpr, depth_remaining: usize) -> IrExpr {
    if depth_remaining == 0 {
        return expr.clone();
    }
    let fold = |e: &IrExpr| fold_expr_inner(e, depth_remaining - 1);
    let fold_bin = |a: &IrExpr, b: &IrExpr, op: fn(u64, u64) -> u64, ctor: fn(Box<IrExpr>, Box<IrExpr>) -> IrExpr| -> IrExpr {
        let fa = fold(a);
        let fb = fold(b);
        if let (IrExpr::Const(x), IrExpr::Const(y)) = (&fa, &fb) {
            IrExpr::Const(op(*x, *y))
        } else {
            ctor(Box::new(fa), Box::new(fb))
        }
    };
    match expr {
        IrExpr::Const(_) | IrExpr::Undef | IrExpr::Reg(_) => expr.clone(),
        IrExpr::Not(inner) => {
            let fi = fold(inner);
            if let IrExpr::Const(v) = fi {
                IrExpr::Const(!v)
            } else {
                IrExpr::Not(Box::new(fi))
            }
        }
        IrExpr::CmpEqZero(inner) => {
            let fi = fold(inner);
            if let IrExpr::Const(v) = fi {
                IrExpr::Const(u64::from(v == 0))
            } else {
                IrExpr::CmpEqZero(Box::new(fi))
            }
        }
        IrExpr::Parity(inner) => {
            let fi = fold(inner);
            if let IrExpr::Const(v) = fi {
                let ones = (v & 0xff).count_ones();
                IrExpr::Const(u64::from(ones.is_multiple_of(2)))
            } else {
                IrExpr::Parity(Box::new(fi))
            }
        }
        IrExpr::Deref(addr, sz) => IrExpr::Deref(Box::new(fold(addr)), *sz),
        // Binary ops — fold both sides, then try to reduce.
        IrExpr::Add(a, b) => fold_bin(a, b, u64::wrapping_add, IrExpr::Add),
        IrExpr::Sub(a, b) => fold_bin(a, b, u64::wrapping_sub, IrExpr::Sub),
        IrExpr::Mul(a, b) => fold_bin(a, b, u64::wrapping_mul, IrExpr::Mul),
        IrExpr::And(a, b) => fold_bin(a, b, |x, y| x & y, IrExpr::And),
        IrExpr::Or(a, b) => fold_bin(a, b, |x, y| x | y, IrExpr::Or),
        IrExpr::Xor(a, b) => fold_bin(a, b, |x, y| x ^ y, IrExpr::Xor),
        IrExpr::Shl(a, b) => {
            fold_bin(a, b, |x, y| if y < 64 { x << y } else { 0 }, IrExpr::Shl)
        }
        IrExpr::Shr(a, b) => {
            fold_bin(a, b, |x, y| if y < 64 { x >> y } else { 0 }, IrExpr::Shr)
        }
        // Sign-filling counterpart of the fold above.
        IrExpr::Sar(a, b) => fold_bin(
            a,
            b,
            |x, y| {
                let sx = x as i64;
                (if y < 64 { sx >> y } else { sx >> 63 }) as u64
            },
            IrExpr::Sar,
        ),
        IrExpr::CmpEq(a, b) => fold_bin(a, b, |x, y| u64::from(x == y), IrExpr::CmpEq),
        IrExpr::CmpLt(a, b) => fold_bin(
            a,
            b,
            |x, y| u64::from(x.cast_signed() < y.cast_signed()),
            IrExpr::CmpLt,
        ),
        IrExpr::CmpLtU(a, b) => fold_bin(a, b, |x, y| u64::from(x < y), IrExpr::CmpLtU),
        IrExpr::CmpGt(a, b) => fold_bin(
            a,
            b,
            |x, y| u64::from(x.cast_signed() > y.cast_signed()),
            IrExpr::CmpGt,
        ),
        IrExpr::Eq(a, b) => fold_bin(a, b, |x, y| u64::from(x == y), IrExpr::Eq),
        IrExpr::Ne(a, b) => fold_bin(a, b, |x, y| u64::from(x != y), IrExpr::Ne),
        IrExpr::IfThenElse(c, t, el) => {
            let fc = fold(c);
            if let IrExpr::Const(v) = fc {
                if v != 0 { fold(t) } else { fold(el) }
            } else {
                IrExpr::IfThenElse(Box::new(fc), Box::new(fold(t)), Box::new(fold(el)))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lazy-flag intrinsic evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the concrete value of an `x86.flag.*` lazy-flag intrinsic from its
/// arguments, returning `(flag_name, value)` ready to be committed to the
/// `RegWrite` that immediately follows it.
///
/// Returns `None` when `name` is not a recognised flag formula, so the caller
/// treats it as an ordinary opaque intrinsic. When a required argument is
/// `Unknown` the value is `Unknown`, preserving the evaluator's soundness
/// contract. The `_w<bits>` suffix selects the operand width; AF is always
/// nibble-based and ignores it.
///
/// Implementing these here — rather than inlining 10-node bit-twiddling trees
/// into every arithmetic instruction — is the whole point of the lazy-flag
/// design: the lifter stays compact, and CF/OF/AF become *concretely
/// evaluable* (no longer `Unknown`) exactly when their inputs are known.
#[must_use]
pub fn eval_flag_intrinsic_a(
    name: &str,
    args: &[IrExpr],
    state: &X86CpuState,
) -> Option<(String, EvalValue)> {
    let (flag, op, width) = if let Some(rest) = name.strip_prefix("x86.flag.") {
        let mut parts = rest.split('_');
        let flag = parts.next()?;
        let op = parts.next()?;
        let width: u32 = match parts.next() {
            Some(w) if w.starts_with('w') => w[1..].parse().unwrap_or(64),
            _ => 64,
        };
        (flag, op, width)
    } else if let Some(rest) = name.strip_prefix("x86.") {
        let mut parts = rest.split('_');
        let op = parts.next()?;
        let flag = parts.next()?;
        let width: u32 = match parts.next() {
            Some(w) if w.starts_with('w') => w[1..].parse().unwrap_or(64),
            _ => 64,
        };
        (flag, op, width)
    } else {
        return None;
    };

    // NOTE: this set must exactly match the `computed` arms below — a
    // combination listed here but not handled by an arm falls through to
    // `_ => None`, which this function turns into `Some((flag, Unknown))`.
    // Since `eval_flag_intrinsic` is `eval_flag_intrinsic_a(..).or_else(||
    // eval_flag_intrinsic_b(..))`, returning `Some(Unknown)` here instead of
    // `None` SHORT-CIRCUITS `_b` and permanently masks its (correct)
    // computation for that op — this was the root cause of the SAR/SHR CF
    // flag bug (`_a` claimed "cf"/"shr" and "cf"/"sar" as recognised without
    // implementing them, silently shadowing `_b`'s real shr/sar logic).
    let recognised = matches!(
        (flag, op),
        ("cf", "add" | "sub" | "adc" | "sbb" | "shl") | ("of", "add" | "sub") | ("af", "add" | "sub")
    );
    if !recognised {
        return None;
    }

    let w = width.clamp(1, 64);
    let mask: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let msb = w - 1;
    let arg =
        |i: usize| -> Option<u64> { args.get(i).and_then(|e| eval_expr(e, state).as_concrete()) };

    // Returns `None` if a required argument is `Unknown` (or the flag is
    // architecturally undefined), which surfaces as `EvalValue::Unknown`.
    let computed: Option<u64> = (|| {
        let bit = |x: u64, n: u32| (x >> n) & 1;
            match (flag, op) {
            ("af", "add") => {
                let (a, b) = (arg(0)? & 0xf, arg(1)? & 0xf);
                Some(u64::from(a + b > 0xf))
            }
            ("af", "sub") => {
                let (a, b) = (arg(0)? & 0xf, arg(1)? & 0xf);
                Some(u64::from(a < b))
            }
            ("cf", "add") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                Some(u64::from((u128::from(a) + u128::from(b)) >> w != 0))
            }
            ("cf", "adc") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                let c = u64::from(arg(2)? != 0);
                Some(u64::from(
                    (u128::from(a) + u128::from(b) + u128::from(c)) >> w != 0,
                ))
            }
            ("cf", "sub") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                Some(u64::from(a < b))
            }
            ("cf", "sbb") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                let c = u64::from(arg(2)? != 0);
                Some(u64::from(u128::from(a) < u128::from(b) + u128::from(c)))
            }
            ("of", "add") => {
                let (a, b, r) = (arg(0)? & mask, arg(1)? & mask, arg(2)? & mask);
                Some(bit((!(a ^ b)) & (a ^ r), msb))
            }
            ("of", "sub") => {
                let (a, b, r) = (arg(0)? & mask, arg(1)? & mask, arg(2)? & mask);
                Some(bit((a ^ b) & (a ^ r), msb))
            }
            ("cf", "shl") => {
                let v = arg(0)? & mask;
                let n = u32::try_from(arg(1)? & 0x3f).unwrap_or(0);
                if n == 0 || n > w {
                    None
                } else {
                    Some(bit(v, w - n))
                }
            }
                _ => None,
            }
    })();
    let flag_name = flag.to_string();
    Some((flag_name, computed.map_or(EvalValue::Unknown, EvalValue::Concrete)))
}
pub fn eval_flag_intrinsic_b(
    name: &str,
    args: &[IrExpr],
    state: &X86CpuState,
) -> Option<(String, EvalValue)> {
    let (flag, op, width) = if let Some(rest) = name.strip_prefix("x86.flag.") {
        let mut parts = rest.split('_');
        let flag = parts.next()?;
        let op = parts.next()?;
        let width: u32 = match parts.next() {
            Some(w) if w.starts_with('w') => w[1..].parse().unwrap_or(64),
            _ => 64,
        };
        (flag, op, width)
    } else if let Some(rest) = name.strip_prefix("x86.") {
        let mut parts = rest.split('_');
        let op = parts.next()?;
        let flag = parts.next()?;
        let width: u32 = match parts.next() {
            Some(w) if w.starts_with('w') => w[1..].parse().unwrap_or(64),
            _ => 64,
        };
        (flag, op, width)
    } else {
        return None;
    };

    let recognised = matches!(
        (flag, op),
        ("cf", "add" | "sub" | "adc" | "sbb" | "shl" | "shr" | "sar" | "rol" | "ror" | "mul")
            | ("of", "add" | "sub" | "shl1" | "shr1" | "rol1" | "ror1" | "mul" | "adox")
            | ("af", "add" | "sub" | "undef")
    );
    if !recognised {
        return None;
    }

    let w = width.clamp(1, 64);
    let mask: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let msb = w - 1;
    let arg =
        |i: usize| -> Option<u64> { args.get(i).and_then(|e| eval_expr(e, state).as_concrete()) };

    // Returns `None` if a required argument is `Unknown` (or the flag is
    // architecturally undefined), which surfaces as `EvalValue::Unknown`.
    let computed: Option<u64> = (|| {
        let bit = |x: u64, n: u32| (x >> n) & 1;
            match (flag, op) {
            ("cf", "shr" | "sar") => {
                let v = arg(0)? & mask;
                let n = u32::try_from(arg(1)? & 0x3f).unwrap_or(0);
                if n == 0 { None } else { Some(bit(v, n - 1)) }
            }
            ("of", "shl1" | "rol1") => {
                let v = arg(0)? & mask;
                Some(bit(v, msb) ^ bit(v, msb.saturating_sub(1)))
            }
            ("of", "shr1") => Some(bit(arg(0)? & mask, msb)),
            ("cf", "rol") => {
                let v = arg(0)? & mask;
                let n = u32::try_from(arg(1)? % u64::from(w)).unwrap_or(0);
                if n == 0 { None } else { Some(bit(v, w - n)) }
            }
            ("cf", "ror") => {
                let v = arg(0)? & mask;
                let n = u32::try_from(arg(1)? % u64::from(w)).unwrap_or(0);
                if n == 0 {
                    None
                } else {
                    Some(bit(v, (n + w - 1) % w))
                }
            }
            ("of", "ror1") => {
                let v = arg(0)? & mask;
                Some(bit(v, 0) ^ bit(v, msb))
            }
            // MUL — AMD APM vol.3 (24594 rev 3.34) p.254: "If the upper half
            // of the product is non-zero, the instruction sets the carry flag
            // (CF) and overflow flag (OF) both to 1. Otherwise, it clears CF
            // and OF to 0."
            //
            // args = [a, b] — the two multiplicands, NOT a pre-computed half.
            // The full 2*w-bit product is formed here in u128, so w == 64 is
            // evaluable like every other width.
            ("cf" | "of", "mul") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                let product = u128::from(a) * u128::from(b);
                Some(u64::from((product >> w) != 0))
            }
            // ADOX — AMD APM vol.3 (24594 rev 3.34): "This instruction sets
            // the OF based on the unsigned addition and whether there is a
            // carry out." That is exactly the ADC carry-out formula, with OF
            // (not CF) serving as both the carry-in and the carry-out.
            ("of", "adox") => {
                let (a, b) = (arg(0)? & mask, arg(1)? & mask);
                let c = u64::from(arg(2)? != 0);
                Some(u64::from(
                    (u128::from(a) + u128::from(b) + u128::from(c)) >> w != 0,
                ))
            }
            _ => None,
        }
    })();
    let flag_name = flag.to_string();
    Some((flag_name, computed.map_or(EvalValue::Unknown, EvalValue::Concrete)))
}

#[must_use]
pub fn eval_flag_intrinsic(
    name: &str,
    args: &[IrExpr],
    state: &X86CpuState,
) -> Option<(String, EvalValue)> {
    eval_flag_intrinsic_a(name, args, state)
        .or_else(|| eval_flag_intrinsic_b(name, args, state))
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect executor
// ─────────────────────────────────────────────────────────────────────────────

/// Result of executing a single `Effect`.
#[derive(Debug, Clone)]
pub enum ExecResult {
    /// Effect executed normally; state was updated.
    Ok,
    /// Effect was an intrinsic (opaque to the evaluator); state unchanged.
    Intrinsic(String),
    /// Effect involved unknown / unresolvable values; state may be incomplete.
    PartialUnknown,
    /// Effect was a branch; returns the target address if concrete.
    Branch {
        target: Option<u64>,
        conditional: bool,
    },
    /// Function call; returns the concrete target if known.
    Call { target: Option<u64> },
    /// Function return.
    Return,
    /// Syscall with the given number (concrete or unknown).
    Syscall { nr: EvalValue },
}

/// Execute a single `Effect` against a mutable CPU state.
pub fn exec_effect(effect: &Effect, state: &mut X86CpuState) -> ExecResult {
    match effect {
        Effect::RegWrite { reg, value } => {
            // A flag commit (`RegWrite { reg: "cf"/"of"/"af", value: Undef }`)
            // consumes the value computed by the preceding flag intrinsic.
            let v = if matches!(value, IrExpr::Undef) {
                state
                    .pending_flags
                    .remove(reg)
                    .unwrap_or(EvalValue::Unknown)
            } else {
                eval_expr(value, state)
            };
            state.set_reg(reg, v);
            ExecResult::Ok
        }
        Effect::MemRead { addr, dest, size } => {
            let addr_v = eval_expr(addr, state);
            let v = match addr_v {
                EvalValue::Concrete(a) => state.read_mem(a, *size),
                EvalValue::Unknown => EvalValue::Unknown,
            };
            state.set_reg(dest, v);
            if v.is_unknown() {
                ExecResult::PartialUnknown
            } else {
                ExecResult::Ok
            }
        }
        Effect::MemWrite { addr, value, size } => {
            let addr_v = eval_expr(addr, state);
            let val_v = eval_expr(value, state);
            match addr_v {
                EvalValue::Concrete(a) => state.write_mem(a, val_v, *size),
                EvalValue::Unknown => {} // Can't store to unknown address; ignore.
            }
            if addr_v.is_unknown() || val_v.is_unknown() {
                ExecResult::PartialUnknown
            } else {
                ExecResult::Ok
            }
        }
        Effect::Branch { target, condition } => {
            let cond_taken = condition.as_ref().map_or(EvalValue::Concrete(1), |c| eval_expr(c, state));
            let target_v = eval_expr(target, state);
            let concrete_target = if let EvalValue::Concrete(t) = target_v {
                Some(t)
            } else {
                None
            };
            ExecResult::Branch {
                target: if cond_taken.is_nonzero() || condition.is_none() {
                    concrete_target
                } else {
                    None
                },
                conditional: condition.is_some(),
            }
        }
        Effect::Call { target } => {
            let t = eval_expr(target, state);
            ExecResult::Call {
                target: if let EvalValue::Concrete(v) = t {
                    Some(v)
                } else {
                    None
                },
            }
        }
        Effect::Return { .. } | Effect::NoReturn => ExecResult::Return,
        Effect::Syscall { nr } => {
            let nr_v = eval_expr(nr, state);
            ExecResult::Syscall { nr: nr_v }
        }
        Effect::Intrinsic { name, args } => {
            // Recognise lazy-flag formulas and stage their concrete value for
            // the following flag `RegWrite`; all other intrinsics stay opaque.
            if let Some((flag, val)) = eval_flag_intrinsic(name, args, state) {
                state.pending_flags.insert(flag, val);
            }
            ExecResult::Intrinsic(name.clone())
        }
        Effect::Trap { vector } => ExecResult::Intrinsic(format!("trap({vector})")),
        Effect::ConditionalTrap { condition, vector } => {
            let cond_v = eval_expr(condition, state);
            if cond_v.is_nonzero() {
                ExecResult::Intrinsic(format!("trap({vector})"))
            } else if cond_v.is_unknown() {
                ExecResult::PartialUnknown
            } else {
                ExecResult::Ok
            }
        }
        }
}

/// Execute a slice of effects, returning a per-effect result vector and the
/// final CPU state. Execution stops at the first `Return` or `Branch` effect.
pub fn exec_effects(effects: &[Effect], state: &mut X86CpuState) -> Vec<ExecResult> {
    state.step_count += 1;
    let mut results = Vec::with_capacity(effects.len());
    for i in 0..effects.len() {
        let e = &effects[i];
        let r = exec_effect(e, state);

        if let Effect::Intrinsic { name, args } = e
            && i + 1 < effects.len()
                && let Effect::RegWrite { reg, value: IrExpr::Undef } = &effects[i + 1]
                    && let Some((_flag, val)) = eval_flag_intrinsic(name, args, state) {
                        state.pending_flags.insert(reg.clone(), val);
                    }

        let done = matches!(
            r,
            ExecResult::Return | ExecResult::Branch { .. } | ExecResult::Call { .. }
        );
        results.push(r);
        if done {
            break;
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// StateComparison — diff two CPU states (for semantic equivalence tests)
// ─────────────────────────────────────────────────────────────────────────────

/// A single register whose values differ between two states.
#[derive(Debug, Clone)]
pub struct RegDiff {
    pub name: String,
    pub expected: EvalValue,
    pub actual: EvalValue,
}

/// Compare an expected and an actual CPU state.
///
/// Only registers present in `expected` are checked; extra registers in
/// `actual` are ignored (they may be temporaries generated by the lifter).
#[must_use]
pub fn diff_states(expected: &X86CpuState, actual: &X86CpuState) -> Vec<RegDiff> {
    let mut diffs = Vec::with_capacity(expected.regs.len());
    for (name, &exp_val) in &expected.regs {
        // Skip temporaries (names starting with `__t`) — they are internal.
        if name.starts_with("__t") {
            continue;
        }
        let act_val = actual.get_reg(name);
        if exp_val != act_val {
            diffs.push(RegDiff {
                name: name.clone(),
                expected: exp_val,
                actual: act_val,
            });
        }
    }
    diffs
}

/// Format a list of diffs as a human-readable string for test failure output.
#[must_use]
pub fn format_diffs(diffs: &[RegDiff]) -> String {
    if diffs.is_empty() {
        return "no differences".into();
    }
    diffs
        .iter()
        .map(|d| format!("  {}: expected {} got {}", d.name, d.expected, d.actual))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(regs: &[(&str, u64)]) -> X86CpuState {
        X86CpuState::with_gp_regs(regs)
    }

    // ── EvalValue ───────────────────────────────────────────────────────────

    #[test]
    fn eval_const_zero() {
        assert_eq!(
            eval_expr(&IrExpr::Const(0), &X86CpuState::new()),
            EvalValue::Concrete(0)
        );
    }

    #[test]
    fn eval_undef_is_unknown() {
        assert_eq!(
            eval_expr(&IrExpr::Undef, &X86CpuState::new()),
            EvalValue::Unknown
        );
    }

    #[test]
    fn eval_reg_present() {
        let s = state_with(&[("rax", 42)]);
        assert_eq!(
            eval_expr(&IrExpr::Reg("rax".into()), &s),
            EvalValue::Concrete(42)
        );
    }

    #[test]
    fn eval_reg_absent() {
        assert_eq!(
            eval_expr(&IrExpr::Reg("rbx".into()), &X86CpuState::new()),
            EvalValue::Unknown
        );
    }

    #[test]
    fn eval_add_concrete() {
        let s = state_with(&[("rax", 10), ("rbx", 20)]);
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Reg("rbx".into())),
        );
        assert_eq!(eval_expr(&e, &s), EvalValue::Concrete(30));
    }

    #[test]
    fn eval_add_wraps() {
        let s = state_with(&[("rax", u64::MAX)]);
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Const(1)),
        );
        assert_eq!(eval_expr(&e, &s), EvalValue::Concrete(0));
    }

    #[test]
    fn eval_add_unknown_propagates() {
        let s = X86CpuState::new(); // rbx absent → unknown
        let e = IrExpr::Add(
            Box::new(IrExpr::Const(5)),
            Box::new(IrExpr::Reg("rbx".into())),
        );
        assert_eq!(eval_expr(&e, &s), EvalValue::Unknown);
    }

    #[test]
    fn eval_sub_concrete() {
        let s = state_with(&[("rax", 50), ("rbx", 8)]);
        let e = IrExpr::Sub(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Reg("rbx".into())),
        );
        assert_eq!(eval_expr(&e, &s), EvalValue::Concrete(42));
    }

    #[test]
    fn eval_cmp_eq_zero_true() {
        let e = IrExpr::CmpEqZero(Box::new(IrExpr::Const(0)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(1));
    }

    #[test]
    fn eval_cmp_eq_zero_false() {
        let e = IrExpr::CmpEqZero(Box::new(IrExpr::Const(7)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(0));
    }

    #[test]
    fn eval_parity_even() {
        // 0b0000_0011 has 2 set bits → even parity → result 1
        let e = IrExpr::Parity(Box::new(IrExpr::Const(0b0000_0011)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(1));
    }

    #[test]
    fn eval_parity_odd() {
        // 0b0000_0001 has 1 set bit → odd parity → result 0
        let e = IrExpr::Parity(Box::new(IrExpr::Const(0b0000_0001)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(0));
    }

    #[test]
    fn eval_and_concrete() {
        let e = IrExpr::And(Box::new(IrExpr::Const(0xff)), Box::new(IrExpr::Const(0x0f)));
        assert_eq!(
            eval_expr(&e, &X86CpuState::new()),
            EvalValue::Concrete(0x0f)
        );
    }

    #[test]
    fn eval_or_concrete() {
        let e = IrExpr::Or(Box::new(IrExpr::Const(0xf0)), Box::new(IrExpr::Const(0x0f)));
        assert_eq!(
            eval_expr(&e, &X86CpuState::new()),
            EvalValue::Concrete(0xff)
        );
    }

    #[test]
    fn eval_xor_concrete() {
        let e = IrExpr::Xor(Box::new(IrExpr::Const(0xff)), Box::new(IrExpr::Const(0xff)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(0));
    }

    #[test]
    fn eval_shl_concrete() {
        let e = IrExpr::Shl(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(4)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(16));
    }

    #[test]
    fn eval_shr_concrete() {
        let e = IrExpr::Shr(Box::new(IrExpr::Const(16)), Box::new(IrExpr::Const(4)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(1));
    }

    #[test]
    fn eval_shl_overflow() {
        let e = IrExpr::Shl(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(64)));
        assert_eq!(eval_expr(&e, &X86CpuState::new()), EvalValue::Concrete(0));
    }

    #[test]
    fn eval_not_concrete() {
        let e = IrExpr::Not(Box::new(IrExpr::Const(0)));
        assert_eq!(
            eval_expr(&e, &X86CpuState::new()),
            EvalValue::Concrete(!0u64)
        );
    }

    #[test]
    fn eval_deref_concrete() {
        let mut s = X86CpuState::new();
        s.write_mem(0x1000, EvalValue::Concrete(0xdead_beef_cafe_babe), 8);
        let e = IrExpr::Deref(Box::new(IrExpr::Const(0x1000)), 8);
        assert_eq!(eval_expr(&e, &s), EvalValue::Concrete(0xdead_beef_cafe_babe));
    }

    #[test]
    fn eval_deref_unknown_addr() {
        let s = X86CpuState::new();
        let e = IrExpr::Deref(Box::new(IrExpr::Reg("rax".into())), 8);
        assert_eq!(eval_expr(&e, &s), EvalValue::Unknown);
    }

    // ── Constant folding ────────────────────────────────────────────────────

    #[test]
    fn fold_add_consts() {
        let e = IrExpr::Add(Box::new(IrExpr::Const(3)), Box::new(IrExpr::Const(4)));
        assert_eq!(fold_expr(&e), IrExpr::Const(7));
    }

    #[test]
    fn fold_keeps_reg() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Const(1)),
        );
        let folded = fold_expr(&e);
        // Can't fold because rax is unknown — structure should be preserved.
        assert!(matches!(folded, IrExpr::Add(_, _)));
    }

    #[test]
    fn fold_nested_consts() {
        // (2 + 3) * 4 = 20
        let inner = IrExpr::Add(Box::new(IrExpr::Const(2)), Box::new(IrExpr::Const(3)));
        let outer = IrExpr::Mul(Box::new(inner), Box::new(IrExpr::Const(4)));
        assert_eq!(fold_expr(&outer), IrExpr::Const(20));
    }

    #[test]
    fn fold_cmp_eq_zero_const() {
        let e = IrExpr::CmpEqZero(Box::new(IrExpr::Const(0)));
        assert_eq!(fold_expr(&e), IrExpr::Const(1));
    }

    // ── Effect execution ────────────────────────────────────────────────────

    #[test]
    fn exec_reg_write() {
        let mut s = X86CpuState::new();
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0x42),
        };
        exec_effect(&e, &mut s);
        s.assert_reg("rax", 0x42);
    }

    #[test]
    fn exec_mem_write_read() {
        let mut s = X86CpuState::new();
        let w = Effect::MemWrite {
            addr: IrExpr::Const(0x2000),
            value: IrExpr::Const(0xfeed),
            size: 2,
        };
        exec_effect(&w, &mut s);
        let r = Effect::MemRead {
            addr: IrExpr::Const(0x2000),
            dest: "ax".into(),
            size: 2,
        };
        exec_effect(&r, &mut s);
        s.assert_reg("ax", 0xfeed);
    }

    #[test]
    fn exec_unconditional_branch() {
        let mut s = X86CpuState::new();
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: None,
        };
        match exec_effect(&e, &mut s) {
            ExecResult::Branch {
                target: Some(t),
                conditional: false,
            } => assert_eq!(t, 0x0040_1000),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn exec_conditional_branch_taken() {
        let mut s = state_with(&[("zf", 1)]);
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: Some(IrExpr::Reg("zf".into())),
        };
        match exec_effect(&e, &mut s) {
            ExecResult::Branch {
                target: Some(0x0040_1000),
                conditional: true,
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn exec_conditional_branch_not_taken() {
        let mut s = state_with(&[("zf", 0)]);
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: Some(IrExpr::Reg("zf".into())),
        };
        match exec_effect(&e, &mut s) {
            ExecResult::Branch {
                target: None,
                conditional: true,
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn exec_syscall() {
        let mut s = state_with(&[("rax", 60)]); // SYS_exit
        let e = Effect::Syscall {
            nr: IrExpr::Reg("rax".into()),
        };
        match exec_effect(&e, &mut s) {
            ExecResult::Syscall {
                nr: EvalValue::Concrete(60),
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn exec_intrinsic_is_opaque() {
        let mut s = X86CpuState::new();
        let e = Effect::Intrinsic {
            name: "x86.cpuid".into(),
            args: vec![],
        };
        match exec_effect(&e, &mut s) {
            ExecResult::Intrinsic(n) => assert_eq!(n, "x86.cpuid"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── State diff ──────────────────────────────────────────────────────────

    #[test]
    fn diff_identical_states() {
        let s = state_with(&[("rax", 1), ("rbx", 2)]);
        assert!(diff_states(&s, &s).is_empty());
    }

    #[test]
    fn diff_detects_mismatch() {
        let expected = state_with(&[("rax", 1)]);
        let actual = state_with(&[("rax", 2)]);
        let diffs = diff_states(&expected, &actual);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].name, "rax");
    }

    #[test]
    fn diff_ignores_temporaries() {
        let mut expected = state_with(&[("rax", 1)]);
        let mut actual = state_with(&[("rax", 1)]);
        // Temporaries should be ignored.
        expected.set_reg("__t0", EvalValue::Concrete(99));
        actual.set_reg("__t0", EvalValue::Concrete(0));
        assert!(diff_states(&expected, &actual).is_empty());
    }

    // ── exec_effects slice ───────────────────────────────────────────────────

    #[test]
    fn exec_effects_stops_at_return() {
        let mut s = X86CpuState::new();
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            },
            Effect::Return { value: None },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Const(2),
            },
        ];
        let results = exec_effects(&effects, &mut s);
        assert_eq!(results.len(), 2); // stops after Return
        s.assert_reg("rax", 1);
        assert_eq!(s.get_reg("rbx"), EvalValue::Unknown); // not reached
    }

    #[test]
    fn exec_effects_full_sequence() {
        let mut s = state_with(&[("rax", 10), ("rbx", 20)]);
        let effects = vec![Effect::RegWrite {
            reg: "rcx".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rax".into())),
                Box::new(IrExpr::Reg("rbx".into())),
            ),
        }];
        exec_effects(&effects, &mut s);
        s.assert_reg("rcx", 30);
    }

    // ── Memory round-trips ──────────────────────────────────────────────────

    #[test]
    fn memory_write_read_1_byte() {
        let mut s = X86CpuState::new();
        s.write_mem(0x500, EvalValue::Concrete(0xab), 1);
        assert_eq!(s.read_mem(0x500, 1), EvalValue::Concrete(0xab));
    }

    #[test]
    fn memory_write_read_8_bytes() {
        let mut s = X86CpuState::new();
        s.write_mem(0x1000, EvalValue::Concrete(0x0102_0304_0506_0708), 8);
        assert_eq!(
            s.read_mem(0x1000, 8),
            EvalValue::Concrete(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn memory_unknown_clears() {
        let mut s = X86CpuState::new();
        s.write_mem(0x800, EvalValue::Concrete(0xff), 1);
        s.write_mem(0x800, EvalValue::Unknown, 1);
        assert_eq!(s.read_mem(0x800, 1), EvalValue::Unknown);
    }

    #[test]
    fn memory_partial_unknown() {
        let mut s = X86CpuState::new();
        // Write only 1 byte of a 2-byte range.
        s.write_mem(0x200, EvalValue::Concrete(0xaa), 1);
        // Reading 2 bytes at 0x200 should be Unknown (byte 0x201 missing).
        assert_eq!(s.read_mem(0x200, 2), EvalValue::Unknown);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (per the standing enterprise-hardening mandate's
    // request for deeper rustre-il test coverage — extended into
    // rustre-il-lift, previously deprioritized as lower-relative-value but
    // not skipped; scoped to `eval_expr`, the self-contained expression
    // evaluator used by the test-only x86 interpreter).
    // ─────────────────────────────────────────────────────────────────────
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn ir_expr() -> impl Strategy<Value = IrExpr> {
            let leaf = prop_oneof![
                any::<u32>().prop_map(|v| IrExpr::Const(u64::from(v))),
                prop_oneof![Just("eax"), Just("ebx"), Just("cf"), Just("zf")]
                    .prop_map(|r| IrExpr::Reg(r.to_string())),
                Just(IrExpr::Undef),
            ];
            leaf.prop_recursive(6, 128, 6, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Add(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Sub(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Mul(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Shl(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Shr(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::CmpLt(Box::new(a), Box::new(b))),
                    inner.clone().prop_map(|a| IrExpr::Deref(Box::new(a), 4)),
                    inner.clone().prop_map(|a| IrExpr::Not(Box::new(a))),
                    (inner.clone(), inner.clone(), inner)
                        .prop_map(|(c, t, e)| IrExpr::IfThenElse(Box::new(c), Box::new(t), Box::new(e))),
                ]
            })
        }

        proptest! {
            /// `eval_expr` must never panic on an arbitrary well-formed
            /// expression tree — including unknown register names, deref
            /// chains into an empty memory model, and mixed shift/compare
            /// nesting up to depth 6. The function's own `depth_remaining`
            /// guard is exercised by the recursive generator's max depth,
            /// not bypassed by it.
            #[test]
            fn eval_expr_never_panics(expr in ir_expr()) {
                let state = X86CpuState::new();
                let _ = eval_expr(&expr, &state);
            }

            /// A `Const(v)` expression must always evaluate to exactly `v`,
            /// regardless of what state it's evaluated against — a minimal
            /// but genuine semantic invariant (constants aren't state-
            /// dependent), not just no-panic.
            #[test]
            fn const_expr_is_state_independent(v in any::<u64>()) {
                let state = X86CpuState::new();
                let result = eval_expr(&IrExpr::Const(v), &state);
                prop_assert_eq!(result, EvalValue::Concrete(v));
            }
        }
    }

    // ── Lazy-flag producer/consumer contract ────────────────────────────────
    // These lock the contract between the flag *emitters* (`x86_flags.rs`,
    // `x86_handlers/`) and this evaluator: an emitted intrinsic name must be
    // recognised here, and its arg list must mean what the formula assumes.

    /// AMD APM vol.3 (24594 rev 3.34) p.254, MUL: "If the upper half of the
    /// product is non-zero, the instruction sets the carry flag (CF) and
    /// overflow flag (OF) both to 1. Otherwise, it clears CF and OF to 0."
    /// 0x10000 * 0x10000 = 0x1_0000_0000 — upper 32 bits are 1, so CF = 1.
    #[test]
    fn cf_mul_set_when_upper_half_nonzero() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic("x86.flag.cf_mul_w32", &[IrExpr::Const(0x10000), IrExpr::Const(0x10000)], &s),
            Some(("cf".to_string(), EvalValue::Concrete(1)))
        );
    }

    /// Same product, OF — APM sets CF and OF together.
    #[test]
    fn of_mul_set_when_upper_half_nonzero() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic("x86.flag.of_mul_w32", &[IrExpr::Const(0x10000), IrExpr::Const(0x10000)], &s),
            Some(("of".to_string(), EvalValue::Concrete(1)))
        );
    }

    /// 0xFFFF * 0xFFFF = 0xFFFE0001 — fits in 32 bits, upper half zero, CF = 0.
    #[test]
    fn cf_mul_clear_when_upper_half_zero() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic("x86.flag.cf_mul_w32", &[IrExpr::Const(0xFFFF), IrExpr::Const(0xFFFF)], &s),
            Some(("cf".to_string(), EvalValue::Concrete(0)))
        );
    }

    /// 64-bit MUL must be evaluable too (the full product is computed in u128).
    #[test]
    fn cf_mul_w64_uses_u128_product() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic("x86.flag.cf_mul_w64", &[IrExpr::Const(1 << 32), IrExpr::Const(1 << 32)], &s),
            Some(("cf".to_string(), EvalValue::Concrete(1)))
        );
        assert_eq!(
            eval_flag_intrinsic("x86.flag.cf_mul_w64", &[IrExpr::Const(0xFFFF_FFFF), IrExpr::Const(2)], &s),
            Some(("cf".to_string(), EvalValue::Concrete(0)))
        );
    }

    /// AMD APM vol.3 (24594 rev 3.34), ADOX: "This instruction sets the OF
    /// based on the unsigned addition and whether there is a carry out."
    /// 0xFFFF_FFFF + 1 + 0 carries out of 32 bits, so OF = 1.
    #[test]
    fn of_adox_is_unsigned_carry_out() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic(
                "x86.flag.of_adox_w32",
                &[IrExpr::Const(0xFFFF_FFFF), IrExpr::Const(1), IrExpr::Const(0)],
                &s
            ),
            Some(("of".to_string(), EvalValue::Concrete(1)))
        );
    }

    /// ADOX carry-in participates: 0xFFFF_FFFE + 1 + OF(1) carries out.
    #[test]
    fn of_adox_honours_carry_in() {
        let s = X86CpuState::new();
        assert_eq!(
            eval_flag_intrinsic(
                "x86.flag.of_adox_w32",
                &[IrExpr::Const(0xFFFF_FFFE), IrExpr::Const(1), IrExpr::Const(1)],
                &s
            ),
            Some(("of".to_string(), EvalValue::Concrete(1)))
        );
        // ...and without it, no carry out.
        assert_eq!(
            eval_flag_intrinsic(
                "x86.flag.of_adox_w32",
                &[IrExpr::Const(0xFFFF_FFFE), IrExpr::Const(1), IrExpr::Const(0)],
                &s
            ),
            Some(("of".to_string(), EvalValue::Concrete(0)))
        );
    }

    /// Class-level guard: every lazy-flag intrinsic name any emitter can
    /// produce must be recognised by `eval_flag_intrinsic`. An emitter adding
    /// a name with no evaluator arm silently degrades that flag to an opaque
    /// intrinsic forever — this catches it at test time instead.
    #[test]
    fn every_emitted_flag_intrinsic_name_is_recognised() {
        let s = X86CpuState::new();
        // Args are all-Unknown on purpose: this asserts *recognition* (Some),
        // not any particular value.
        let args = [IrExpr::Undef, IrExpr::Undef, IrExpr::Undef];
        let mut missing = Vec::new();
        for base in [
            "cf_add", "cf_sub", "cf_adc", "cf_sbb", "of_add", "of_sub",
            "cf_shl", "cf_shr", "cf_sar", "of_shl1", "of_shr1",
            "cf_rol", "cf_ror", "of_rol1", "of_ror1",
            "cf_mul", "of_mul", "of_adox",
        ] {
            for bits in [8u32, 16, 32, 64] {
                let name = format!("x86.flag.{base}_w{bits}");
                if eval_flag_intrinsic(&name, &args, &s).is_none() {
                    missing.push(name);
                }
            }
        }
        for name in ["x86.flag.af_add", "x86.flag.af_sub", "x86.flag.af_undef"] {
            if eval_flag_intrinsic(name, &args, &s).is_none() {
                missing.push(name.to_string());
            }
        }
        assert!(missing.is_empty(), "emitted but unrecognised by the evaluator: {missing:?}");
    }

    /// Locked-in probe for the `or_else` short-circuit hazard.
    ///
    /// `eval_flag_intrinsic` is `_a(..).or_else(|| _b(..))`. If `_a`'s
    /// `recognised` set claims a (flag, op) it has no match arm for, it returns
    /// `Some(Unknown)` — which is *not* `None`, so it permanently shadows
    /// `_b`'s real computation for that op. That was the historical SAR/SHR CF
    /// bug. This probe pins the invariant directly: for every combination `_a`
    /// claims, given fully-concrete args, `_a` must yield a Concrete value.
    /// A claim added without an arm fails here instead of silently masking `_b`.
    #[test]
    fn eval_flag_intrinsic_a_computes_everything_it_claims() {
        let s = X86CpuState::new();
        // Concrete, in-range args: shift/rotate counts must be non-zero (a zero
        // count leaves the flag architecturally unmodified -> legitimately None).
        let args = [IrExpr::Const(3), IrExpr::Const(1), IrExpr::Const(1)];
        let mut shadowing = Vec::new();
        for flag in ["cf", "of", "af", "sf", "zf", "pf"] {
            for op in [
                "add", "sub", "adc", "sbb", "shl", "shr", "sar", "rol", "ror",
                "mul", "adox", "shl1", "shr1", "rol1", "ror1", "undef",
            ] {
                for bits in [8u32, 16, 32, 64] {
                    let name = format!("x86.flag.{flag}_{op}_w{bits}");
                    // Only combinations `_a` claims are at issue.
                    if let Some((_, v)) = eval_flag_intrinsic_a(&name, &args, &s)
                        && v == EvalValue::Unknown
                    {
                        shadowing.push(name);
                    }
                }
            }
        }
        assert!(
            shadowing.is_empty(),
            "`_a` claims these but returns Some(Unknown), shadowing `_b`: {shadowing:?}"
        );
    }
}
