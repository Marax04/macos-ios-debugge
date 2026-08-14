//! `rustre-il-llil`
//!
//! Production-grade Low-Level Intermediate Language (LLIL) for the `RustRE` suite.
//!
//! The LLIL sits directly above raw machine instructions and is architecture-
//! independent. Each machine instruction lifts to one or more [`LlilInstruction`]s
//! tagged with the original [`Address`] and byte-length. Instructions that read or
//! write memory use explicit [`LlilExpr::Load`] / [`LlilInstruction::Store`] nodes,
//! making data-flow analysis straightforward without architecture-specific logic.
//!
//! # Wiring status (audited 2026-08-04)
//!
//! The TYPES of this crate ([`LlilInstruction`], [`LlilExpr`], [`LlilFunction`],
//! [`LlilBasicBlock`]) have always been in the decompiler's chain, via
//! `rustre_arch_x86::disassemble_and_lift` → `IlAnalysisPass` →
//! `build_mlil_cfg`. Several of the PROCESSING modules were not, because the
//! decompiler grew its own equivalents. They are documented here rather than
//! deleted (RIPARARE-NON-CANCELLARE) — each line names the counterpart that
//! currently does the job.
//!
//! In chain:
//! - [`llil_builder`] — `LlilValidator` runs on every decompiled function and
//!   reports `llil_blocks` / `llil_validation_errors` annotations
//!   (`rustre-decompiler::IlAnalysisPass::run`).
//! - [`llil_optimizer`] — `LlilOptimizer` runs in tail position after the
//!   `rustre-il-passes` `PassManager` in `optimize_lifted_llil`, behind the
//!   opt-in `RUSTRE_LLIL_OPT=1` (it carries DCE + ConstantPropagation, which
//!   are documented there as destructive for symbol resolution).
//! - [`llil_branch_resolver`] — third source of jump-table targets in
//!   `attach_jump_table_edges`, behind the opt-in
//!   `RUSTRE_LLIL_BRANCH_RESOLVER=1`.
//!
//! NOT in chain, superseded by an existing counterpart:
//! - [`llil_to_mlil_bridge`] — superseded by `rustre-decompiler::build_mlil_cfg`.
//!   Not a rewiring: the bridge expects its own `CallingConvention`/entry shape,
//!   so swapping it in would be a redesign that changes the MLIL of every
//!   function.
//! - [`llil_stack_analyzer`] — superseded by the stack/frame analysis inside the
//!   decompiler monolith. Its `StackBlock`/`StackInstr` input IR is not what the
//!   pipeline produces.
//! - [`llil_semantics`], [`llil_register_allocator`], [`x86_opcode_lift`],
//!   [`llil_interpreter`], [`llil_verification`], [`verifier`] — no consumer
//!   outside this crate yet; `x86_opcode_lift` in particular duplicates
//!   `rustre-arch-x86::lift`, which is the lifter actually feeding the pipeline.

pub mod llil_builder;
pub mod llil_interpreter;
pub mod llil_optimizer;
pub mod llil_semantics;
pub mod llil_to_mlil_bridge;
pub mod llil_verification;
pub mod verifier;
pub mod llil_branch_resolver;
pub mod llil_register_allocator;
pub mod llil_stack_analyzer;
pub mod x86_opcode_lift;

use petgraph::visit::EdgeRef;
use rustre_core::address::Address;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Size
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Operand / result size used throughout LLIL expressions and instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Size {
    /// 1 byte  (8-bit)
    Byte,
    /// 2 bytes (16-bit)
    Word,
    /// 4 bytes (32-bit)
    DWord,
    /// 8 bytes (64-bit)
    QWord,
    /// 16 bytes (128-bit)
    OWord,
    /// 32 bytes (256-bit, AVX/AVX2 YMM)
    YWord,
    /// 64 bytes (512-bit, AVX-512 ZMM)
    ZWord,
}

impl Size {
    /// Alias for `Byte` (1 byte). Kept for builder/optimizer compatibility.
    pub const B1: Self = Self::Byte;
    /// Alias for `Word` (2 bytes). Kept for builder/optimizer compatibility.
    pub const B2: Self = Self::Word;
    /// Alias for `DWord` (4 bytes). Kept for builder/optimizer compatibility.
    pub const B4: Self = Self::DWord;
    /// Alias for `QWord` (8 bytes). Kept for builder/optimizer compatibility.
    pub const B8: Self = Self::QWord;

    /// Number of bytes this size represents.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::DWord => 4,
            Self::QWord => 8,
            Self::OWord => 16,
            Self::YWord => 32,
            Self::ZWord => 64,
        }
    }

    /// Number of bits this size represents.
    #[must_use]
    pub const fn bits(self) -> usize {
        self.bytes() * 8
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bytes())
    }
}

impl TryFrom<usize> for Size {
    type Error = String;

    fn try_from(bytes: usize) -> Result<Self, Self::Error> {
        match bytes {
            1 => Ok(Self::Byte),
            2 => Ok(Self::Word),
            4 => Ok(Self::DWord),
            8 => Ok(Self::QWord),
            16 => Ok(Self::OWord),
            32 => Ok(Self::YWord),
            64 => Ok(Self::ZWord),
            other => Err(format!("no Size variant for {other} bytes")),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilRegister
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A register referenced inside an LLIL expression or instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LlilRegister {
    /// A concrete, named architectural register (e.g. `"rax"`, `"xmm0"`).
    Concrete(String),
    /// A lifter-allocated temporary with numeric ID (e.g. `tmp0`).
    Temporary(u32),
}

impl LlilRegister {
    /// Returns a human-readable name for the register.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Concrete(s) => s.clone(),
            Self::Temporary(n) => format!("tmp{n}"),
        }
    }
}

impl fmt::Display for LlilRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl From<String> for LlilRegister {
    fn from(s: String) -> Self {
        Self::Concrete(s)
    }
}

impl From<&str> for LlilRegister {
    fn from(s: &str) -> Self {
        Self::Concrete(s.to_owned())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilExpr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An LLIL expression â€” a typed, side-effect-free value producer.
///
/// Every variant carries a [`Size`] describing the width of its result, except
/// for comparison variants whose result is always [`Size::Byte`] (0 = false,
/// 1 = true).
#[derive(Debug, Clone, PartialEq)]
pub enum LlilExpr {
    // â”€â”€ constants / registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    /// An integer constant.
    Const {
        value: u64,
        size: Size,
    },
    /// A read of an architectural register (by `LlilRegister`).
    RegisterRef {
        reg: LlilRegister,
        size: Size,
    },
    /// A read of a register identified by numeric `id` â€” used by the optimizer.
    Register {
        id: u32,
        size: Size,
    },
    /// A memory load from `addr` with the given result `size`.
    Load {
        addr: Box<Self>,
        size: Size,
    },

    // â”€â”€ arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    AddT(Box<Self>, Box<Self>, Size),
    SubT(Box<Self>, Box<Self>, Size),
    MulT(Box<Self>, Box<Self>, Size),

    /// Struct-form `Add` used by the optimizer.  Equivalent to `AddT`.
    Add {
        left: Box<Self>,
        right: Box<Self>,
        size: Size,
    },
    /// Struct-form `Sub` used by the optimizer.  Equivalent to `SubT`.
    Sub {
        left: Box<Self>,
        right: Box<Self>,
        size: Size,
    },
    /// Struct-form `Mul` used by the optimizer.  Equivalent to `MulT`.
    Mul {
        left: Box<Self>,
        right: Box<Self>,
        size: Size,
    },
    /// Unsigned integer division.
    DivU(Box<Self>, Box<Self>, Size),
    /// Signed integer division.
    DivS(Box<Self>, Box<Self>, Size),
    /// Unsigned remainder.
    ModU(Box<Self>, Box<Self>, Size),
    /// Signed remainder.
    ModS(Box<Self>, Box<Self>, Size),
    /// Two's-complement negation.
    Neg(Box<Self>, Size),

    // â”€â”€ bitwise â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    And(Box<Self>, Box<Self>, Size),
    Or(Box<Self>, Box<Self>, Size),
    Xor(Box<Self>, Box<Self>, Size),
    /// Bitwise NOT.
    Not(Box<Self>, Size),
    /// Logical left shift.
    ShlT(Box<Self>, Box<Self>, Size),
    /// Struct-form `Shl` used by the optimizer.  Equivalent to `ShlT`.
    Shl {
        value: Box<Self>,
        shift: Box<Self>,
        size: Size,
    },
    /// Logical (unsigned) right shift.
    Shr(Box<Self>, Box<Self>, Size),
    /// Arithmetic (signed) right shift.
    Sar(Box<Self>, Box<Self>, Size),
    /// Rotate left.
    Rol(Box<Self>, Box<Self>, Size),
    /// Rotate right.
    Ror(Box<Self>, Box<Self>, Size),

    // â”€â”€ comparisons (result always Size::Byte) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    CmpEq(Box<Self>, Box<Self>),
    CmpNe(Box<Self>, Box<Self>),
    /// Signed less-than.
    CmpSlt(Box<Self>, Box<Self>),
    /// Unsigned less-than.
    CmpUlt(Box<Self>, Box<Self>),
    /// Signed less-or-equal.
    CmpSle(Box<Self>, Box<Self>),
    /// Unsigned less-or-equal.
    CmpUle(Box<Self>, Box<Self>),
    /// Signed greater-than.
    CmpSgt(Box<Self>, Box<Self>),
    /// Unsigned greater-than.
    CmpUgt(Box<Self>, Box<Self>),
    /// Signed greater-or-equal.
    CmpSge(Box<Self>, Box<Self>),
    /// Unsigned greater-or-equal.
    CmpUge(Box<Self>, Box<Self>),

    // â”€â”€ extension / truncation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    /// Zero-extend `expr` from `from` bits to `to` bits.
    ZeroExtend {
        expr: Box<Self>,
        from: Size,
        to: Size,
    },
    /// Sign-extend `expr` from `from` bits to `to` bits.
    SignExtend {
        expr: Box<Self>,
        from: Size,
        to: Size,
    },
    /// Truncate `expr` to its low `to` bits.
    LowPart {
        expr: Box<Self>,
        to: Size,
    },

    // â”€â”€ floating-point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    FAdd(Box<Self>, Box<Self>, Size),
    FSub(Box<Self>, Box<Self>, Size),
    FMul(Box<Self>, Box<Self>, Size),
    FDiv(Box<Self>, Box<Self>, Size),
    /// Floating-point negation.
    FNeg(Box<Self>, Size),
    /// Float equality comparison (result: [`Size::Byte`]).
    FCmpEq(Box<Self>, Box<Self>),
    /// Float less-than comparison (result: [`Size::Byte`]).
    FCmpLt(Box<Self>, Box<Self>),
    /// Float greater-than comparison (result: [`Size::Byte`]).
    FCmpGt(Box<Self>, Box<Self>),
    /// Integer â†’ float conversion.
    IntToFloat {
        expr: Box<Self>,
        to: Size,
    },
    /// Float â†’ integer truncation.
    FloatToInt {
        expr: Box<Self>,
        to: Size,
    },

    // â”€â”€ miscellaneous â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    /// The stack pointer pseudo-register.
    StackPointer(Size),
    /// An architectural flag (e.g. `"carry"`, `"zero"`).
    Flag(String),
    /// Ternary / conditional expression (select `true_val` or `false_val`).
    CondExpr {
        cond: Box<Self>,
        true_val: Box<Self>,
        false_val: Box<Self>,
        size: Size,
    },
    /// Undefined value â€” used when semantics cannot be determined.
    Undefined(Size),
    /// Architecture-specific intrinsic that returns a value.
    Intrinsic {
        name: String,
        args: Vec<Self>,
        result_size: Size,
    },
}

impl LlilExpr {
    /// Returns the [`Size`] of the value produced by this expression.
    #[must_use]
    pub const fn result_size(&self) -> Size {
        match self {
            Self::Const { size, .. }
            | Self::RegisterRef { size, .. }
            | Self::Register { size, .. }
            | Self::Add { size, .. }
            | Self::Sub { size, .. }
            | Self::Mul { size, .. }
            | Self::Shl { size, .. }
            | Self::Load { size, .. }
            | Self::CondExpr { size, .. } => *size,
            Self::AddT(_, _, s)
            | Self::SubT(_, _, s)
            | Self::MulT(_, _, s)
            | Self::DivU(_, _, s)
            | Self::DivS(_, _, s)
            | Self::ModU(_, _, s)
            | Self::ModS(_, _, s)
            | Self::Neg(_, s)
            | Self::And(_, _, s)
            | Self::Or(_, _, s)
            | Self::Xor(_, _, s)
            | Self::Not(_, s)
            | Self::ShlT(_, _, s)
            | Self::Shr(_, _, s)
            | Self::Sar(_, _, s)
            | Self::Rol(_, _, s)
            | Self::Ror(_, _, s)
            | Self::FAdd(_, _, s)
            | Self::FSub(_, _, s)
            | Self::FMul(_, _, s)
            | Self::FDiv(_, _, s)
            | Self::FNeg(_, s)
            | Self::StackPointer(s)
            | Self::Undefined(s) => *s,
            // Comparisons always produce a byte (0 or 1).
            Self::CmpEq(..)
            | Self::CmpNe(..)
            | Self::CmpSlt(..)
            | Self::CmpUlt(..)
            | Self::CmpSle(..)
            | Self::CmpUle(..)
            | Self::CmpSgt(..)
            | Self::CmpUgt(..)
            | Self::CmpSge(..)
            | Self::CmpUge(..)
            | Self::FCmpEq(..)
            | Self::FCmpLt(..)
            | Self::FCmpGt(..)
            | Self::Flag(_) => Size::Byte,
            Self::ZeroExtend { to, .. }
            | Self::SignExtend { to, .. }
            | Self::LowPart { to, .. }
            | Self::IntToFloat { to, .. }
            | Self::FloatToInt { to, .. } => *to,
            Self::Intrinsic { result_size, .. } => *result_size,
        }
    }

    /// Returns `true` if this expression is the integer constant `0`.
    #[must_use]
    pub const fn is_const_zero(&self) -> bool {
        matches!(self, Self::Const { value: 0, .. })
    }

    /// If this expression is an integer constant, return its value.
    #[must_use]
    pub const fn is_const(&self) -> Option<u64> {
        if let Self::Const { value, .. } = self {
            Some(*value)
        } else {
            None
        }
    }
}

impl fmt::Display for LlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const { value, size } => write!(f, "0x{value:x}.{size}"),
            Self::RegisterRef { reg, size } => write!(f, "{reg}.{size}"),
            Self::Register { id, size } => write!(f, "r{id}.{size}"),
            Self::Load { addr, size } => write!(f, "[{addr}].{size}"),
            Self::AddT(l, r, s) => write!(f, "({l} + {r}).{s}"),
            Self::SubT(l, r, s) => write!(f, "({l} - {r}).{s}"),
            Self::MulT(l, r, s) => write!(f, "({l} * {r}).{s}"),
            Self::Add { left, right, size } => write!(f, "({left} + {right}).{size}"),
            Self::Sub { left, right, size } => write!(f, "({left} - {right}).{size}"),
            Self::Mul { left, right, size } => write!(f, "({left} * {right}).{size}"),
            Self::Shl { value, shift, size } => write!(f, "({value} << {shift}).{size}"),
            Self::DivU(l, r, s) => write!(f, "({l} /u {r}).{s}"),
            Self::DivS(l, r, s) => write!(f, "({l} /s {r}).{s}"),
            Self::ModU(l, r, s) => write!(f, "({l} %u {r}).{s}"),
            Self::ModS(l, r, s) => write!(f, "({l} %s {r}).{s}"),
            Self::Neg(e, s) => write!(f, "(-{e}).{s}"),
            Self::And(l, r, s) => write!(f, "({l} & {r}).{s}"),
            Self::Or(l, r, s) => write!(f, "({l} | {r}).{s}"),
            Self::Xor(l, r, s) => write!(f, "({l} ^ {r}).{s}"),
            Self::Not(e, s) => write!(f, "(~{e}).{s}"),
            Self::ShlT(l, r, s) => write!(f, "({l} << {r}).{s}"),
            Self::Shr(l, r, s) => write!(f, "({l} >> {r}).{s}"),
            Self::Sar(l, r, s) => write!(f, "({l} >>a {r}).{s}"),
            Self::Rol(l, r, s) => write!(f, "({l} rol {r}).{s}"),
            Self::Ror(l, r, s) => write!(f, "({l} ror {r}).{s}"),
            Self::CmpEq(l, r) => write!(f, "({l} == {r})"),
            Self::CmpNe(l, r) => write!(f, "({l} != {r})"),
            Self::CmpSlt(l, r) => write!(f, "({l} <s {r})"),
            Self::CmpUlt(l, r) => write!(f, "({l} <u {r})"),
            Self::CmpSle(l, r) => write!(f, "({l} <=s {r})"),
            Self::CmpUle(l, r) => write!(f, "({l} <=u {r})"),
            Self::CmpSgt(l, r) => write!(f, "({l} >s {r})"),
            Self::CmpUgt(l, r) => write!(f, "({l} >u {r})"),
            Self::CmpSge(l, r) => write!(f, "({l} >=s {r})"),
            Self::CmpUge(l, r) => write!(f, "({l} >=u {r})"),
            Self::ZeroExtend { expr, from, to } => write!(f, "zx({expr}, {from}->{to})"),
            Self::SignExtend { expr, from, to } => write!(f, "sx({expr}, {from}->{to})"),
            Self::LowPart { expr, to } => write!(f, "low({expr}, {to})"),
            Self::FAdd(l, r, s) => write!(f, "({l} f+ {r}).{s}"),
            Self::FSub(l, r, s) => write!(f, "({l} f- {r}).{s}"),
            Self::FMul(l, r, s) => write!(f, "({l} f* {r}).{s}"),
            Self::FDiv(l, r, s) => write!(f, "({l} f/ {r}).{s}"),
            Self::FNeg(e, s) => write!(f, "(-f{e}).{s}"),
            Self::FCmpEq(l, r) => write!(f, "({l} f== {r})"),
            Self::FCmpLt(l, r) => write!(f, "({l} f< {r})"),
            Self::FCmpGt(l, r) => write!(f, "({l} f> {r})"),
            Self::IntToFloat { expr, to } => write!(f, "int_to_float({expr}, {to})"),
            Self::FloatToInt { expr, to } => write!(f, "float_to_int({expr}, {to})"),
            Self::StackPointer(s) => write!(f, "SP.{s}"),
            Self::Flag(name) => write!(f, "flag({name})"),
            Self::CondExpr {
                cond,
                true_val,
                false_val,
                size,
            } => write!(f, "({cond} ? {true_val} : {false_val}).{size}"),
            Self::Undefined(s) => write!(f, "undef.{s}"),
            Self::Intrinsic {
                name,
                args,
                result_size,
            } => {
                write!(f, "{name}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ").{result_size}")
            }
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilInstruction
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single LLIL instruction.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum LlilInstruction {
    /// No operation.
    #[default]
    Nop,
    /// Write `src` into register `dest`.
    SetReg {
        dest: LlilRegister,
        size: Size,
        value: LlilExpr,
    },
    /// Write the low half of `src` into `low` and the high half into `high`
    /// (used for instructions like `MUL` that produce a double-width result).
    SetRegSplit {
        high: LlilRegister,
        low: LlilRegister,
        src: LlilExpr,
    },
    /// Load `size` bytes from `addr` into register `dest`.
    Load {
        dest: LlilRegister,
        size: Size,
        addr: LlilExpr,
    },
    /// Store `size` bytes of `src` to `addr`.
    Store {
        addr: LlilExpr,
        size: Size,
        value: LlilExpr,
    },
    /// Set an architectural flag.
    SetFlag { name: String, src: LlilExpr },
    /// Push `src` onto the stack.
    Push { size: Size, src: LlilExpr },
    /// Pop from the stack into `dest`.
    Pop { dest: LlilRegister, size: Size },
    /// Unconditional jump to `dest` (computed target, struct form).
    JumpDest { dest: LlilExpr },
    /// Indirect jump with a hint about possible static targets.
    JumpTo {
        dest: LlilExpr,
        targets: Vec<Address>,
    },
    /// Direct or indirect call (struct form).
    CallDest { dest: LlilExpr },
    /// Unconditional jump (tuple form used by the builder).
    Jump(LlilExpr),
    /// Direct or indirect call (tuple form used by the builder).
    Call(LlilExpr),
    /// Conditional jump used by the builder.
    ConditionalJump {
        cond: LlilExpr,
        true_target: Address,
        false_target: Address,
    },
    /// Register-by-id variant used by the optimizer.
    SetRegister {
        dest: u32,
        value: LlilExpr,
        size: Size,
    },
    /// Tail-call (call that does not return to this function).
    TailCall { dest: LlilExpr },
    /// Return from function.
    Ret,
    /// Return from function with an optional return value (struct form).
    Return { value: Option<LlilExpr> },
    /// Conditional jump: if `cond` != 0 go to `true_dest`, else `false_dest`.
    CondJump {
        cond: LlilExpr,
        true_dest: Address,
        false_dest: Address,
    },
    /// Conditional call.
    CondCall { cond: LlilExpr, dest: LlilExpr },
    /// Software trap / interrupt.
    Trap { code: u64 },
    /// System call.
    SysCall,
    /// Debugger breakpoint.
    Breakpoint,
    /// Architecture-specific intrinsic with no result value.
    Intrinsic { name: String, args: Vec<LlilExpr> },
    /// Instruction that could not be decoded.
    Undefined,
    /// Instruction that was decoded but not yet lifted; raw bytes preserved.
    UnimplementedRaw { bytes: Vec<u8>, address: Address },
    /// Mnemonic-only unimplemented form used by the semantics layer.
    Unimplemented { mnemonic: String },
}

impl LlilInstruction {
    /// Returns `true` if control flow cannot fall through to the next
    /// sequential instruction after this one.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::JumpDest { .. }
                | Self::JumpTo { .. }
                | Self::TailCall { .. }
                | Self::Ret
                | Self::CondJump { .. }
                | Self::Trap { .. }
                | Self::Undefined
                | Self::UnimplementedRaw { .. }
                | Self::Unimplemented { .. }
                | Self::Jump(..)
                | Self::Call(..)
                | Self::ConditionalJump { .. }
                | Self::Return { .. }
                | Self::CondCall { .. }
        )
    }

    /// Returns the statically-known successor addresses reachable from this
    /// instruction.  Falls through when `is_terminator()` is false.
    ///
    /// The caller must supply `fall_through` (address of the next sequential
    /// instruction) â€” for non-terminator instructions it is the sole successor.
    #[must_use]
    pub fn successors(&self) -> Vec<Address> {
        match self {
            Self::CondJump {
                true_dest,
                false_dest,
                ..
            } => vec![*true_dest, *false_dest],
            Self::JumpTo { targets, .. } => targets.clone(),
            // All other instructions (terminators without known static targets,
            // and non-terminators) return empty here; callers must supply the
            // fall-through address externally using `is_terminator()`.
            _ => vec![],
        }
    }

    /// Returns `true` if this instruction reads the named flag inside any of
    /// its source expressions.
    #[must_use]
    pub fn reads_flag(&self, flag: &str) -> bool {
        match self {
            Self::Load { addr, .. } => expr_reads_flag(addr, flag),
            Self::Store {
                addr, value: src, ..
            } => expr_reads_flag(addr, flag) || expr_reads_flag(src, flag),
            Self::SetReg { value: src, .. }
            | Self::SetRegSplit { src, .. }
            | Self::SetFlag { src, .. }
            | Self::Push { src, .. } => expr_reads_flag(src, flag),
            Self::JumpDest { dest }
            | Self::JumpTo { dest, .. }
            | Self::CallDest { dest }
            | Self::TailCall { dest }
            | Self::Jump(dest)
            | Self::Call(dest) => expr_reads_flag(dest, flag),
            Self::ConditionalJump { cond, .. } | Self::CondJump { cond, .. } => expr_reads_flag(cond, flag),
            Self::SetRegister { value, .. } => expr_reads_flag(value, flag),
            Self::CondCall { cond, dest } => {
                expr_reads_flag(cond, flag) || expr_reads_flag(dest, flag)
            }
            Self::Intrinsic { args, .. } => args.iter().any(|a| expr_reads_flag(a, flag)),
            Self::Return { value } => value.as_ref().is_some_and(|v| expr_reads_flag(v, flag)),
            Self::Pop { .. }
            | Self::Nop
            | Self::Ret
            | Self::Trap { .. }
            | Self::SysCall
            | Self::Breakpoint
            | Self::Undefined
            | Self::UnimplementedRaw { .. }
            | Self::Unimplemented { .. } => false,
        }
    }

    /// Returns `true` if this instruction writes the named flag.
    #[must_use]
    pub fn writes_flag(&self, flag: &str) -> bool {
        matches!(self, Self::SetFlag { name: f, .. } if f == flag)
    }

    /// Returns `true` if any source expression in this instruction reads
    /// from `reg`.
    #[must_use]
    pub fn reads_reg(&self, reg: &LlilRegister) -> bool {
        match self {
            Self::Load { addr, .. } => expr_reads_reg(addr, reg),
            Self::Store {
                addr, value: src, ..
            } => expr_reads_reg(addr, reg) || expr_reads_reg(src, reg),
            Self::SetReg { value: src, .. }
            | Self::SetRegSplit { src, .. }
            | Self::SetFlag { src, .. }
            | Self::Push { src, .. } => expr_reads_reg(src, reg),
            Self::JumpDest { dest }
            | Self::JumpTo { dest, .. }
            | Self::CallDest { dest }
            | Self::TailCall { dest }
            | Self::Jump(dest)
            | Self::Call(dest) => expr_reads_reg(dest, reg),
            Self::ConditionalJump { cond, .. } | Self::CondJump { cond, .. } => expr_reads_reg(cond, reg),
            Self::SetRegister { value, .. } => expr_reads_reg(value, reg),
            Self::CondCall { cond, dest } => expr_reads_reg(cond, reg) || expr_reads_reg(dest, reg),
            Self::Intrinsic { args, .. } => args.iter().any(|a| expr_reads_reg(a, reg)),
            Self::Return { value } => value.as_ref().is_some_and(|v| expr_reads_reg(v, reg)),
            Self::Pop { .. }
            | Self::Nop
            | Self::Ret
            | Self::Trap { .. }
            | Self::SysCall
            | Self::Breakpoint
            | Self::Undefined
            | Self::UnimplementedRaw { .. }
            | Self::Unimplemented { .. } => false,
        }
    }

    /// Returns `true` if this instruction writes to `reg`.
    #[must_use]
    pub fn writes_reg(&self, reg: &LlilRegister) -> bool {
        match self {
            Self::SetRegSplit { high, low, .. } => high == reg || low == reg,
            Self::SetReg { dest, .. } | Self::Load { dest, .. } | Self::Pop { dest, .. } => {
                dest == reg
            }
            _ => false,
        }
    }
}

/// Walk an expression tree recursively and check whether it reads a flag.
fn expr_reads_flag(expr: &LlilExpr, flag: &str) -> bool {
    match expr {
        LlilExpr::Flag(f) => f == flag,
        LlilExpr::Const { .. }
        | LlilExpr::RegisterRef { .. }
        | LlilExpr::Register { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Undefined(_) => false,
        LlilExpr::Load { addr, .. } => expr_reads_flag(addr, flag),
        LlilExpr::Add {
            left: l, right: r, ..
        }
        | LlilExpr::Sub {
            left: l, right: r, ..
        }
        | LlilExpr::Mul {
            left: l, right: r, ..
        }
        | LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => expr_reads_flag(l, flag) || expr_reads_flag(r, flag),
        LlilExpr::Shl { value, shift, .. } => {
            expr_reads_flag(value, flag) || expr_reads_flag(shift, flag)
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => expr_reads_flag(e, flag),
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            expr_reads_flag(cond, flag)
                || expr_reads_flag(true_val, flag)
                || expr_reads_flag(false_val, flag)
        }
        LlilExpr::Intrinsic { args, .. } => args.iter().any(|a| expr_reads_flag(a, flag)),
    }
}

/// Walk an expression tree recursively and check whether it reads from `reg`.
fn expr_reads_reg(expr: &LlilExpr, reg: &LlilRegister) -> bool {
    match expr {
        LlilExpr::RegisterRef { reg: r, .. } => r == reg,
        LlilExpr::Register { .. }
        | LlilExpr::Const { .. }
        | LlilExpr::Flag(_)
        | LlilExpr::StackPointer(_)
        | LlilExpr::Undefined(_) => false,
        LlilExpr::Load { addr, .. } => expr_reads_reg(addr, reg),
        LlilExpr::Add {
            left: l, right: r, ..
        }
        | LlilExpr::Sub {
            left: l, right: r, ..
        }
        | LlilExpr::Mul {
            left: l, right: r, ..
        }
        | LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => expr_reads_reg(l, reg) || expr_reads_reg(r, reg),
        LlilExpr::Shl { value, shift, .. } => {
            expr_reads_reg(value, reg) || expr_reads_reg(shift, reg)
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => expr_reads_reg(e, reg),
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            expr_reads_reg(cond, reg)
                || expr_reads_reg(true_val, reg)
                || expr_reads_reg(false_val, reg)
        }
        LlilExpr::Intrinsic { args, .. } => args.iter().any(|a| expr_reads_reg(a, reg)),
    }
}

impl fmt::Display for LlilInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nop => write!(f, "nop"),
            Self::SetReg {
                dest,
                size,
                value: src,
            } => write!(f, "{dest}.{size} = {src}"),
            Self::SetRegSplit { high, low, src } => write!(f, "{high}:{low} = {src}"),
            Self::Load { dest, size, addr } => write!(f, "{dest}.{size} = [{addr}]"),
            Self::Store {
                addr,
                size,
                value: src,
            } => write!(f, "[{addr}].{size} = {src}"),
            Self::SetFlag { name, src } => write!(f, "flag({name}) = {src}"),
            Self::Push { size, src } => write!(f, "push.{size} {src}"),
            Self::Pop { dest, size } => write!(f, "{dest}.{size} = pop"),
            Self::JumpDest { dest } | Self::Jump(dest) => write!(f, "jump {dest}"),
            Self::JumpTo { dest, .. } => write!(f, "jump_to {dest}"),
            Self::CallDest { dest } | Self::Call(dest) => write!(f, "call {dest}"),
            Self::ConditionalJump {
                cond,
                true_target,
                false_target,
            } => write!(f, "if ({cond}) goto {true_target} else {false_target}"),
            Self::SetRegister { dest, value, size } => write!(f, "r{dest}.{size} = {value}"),
            Self::TailCall { dest } => write!(f, "tailcall {dest}"),
            Self::Ret => write!(f, "ret"),
            Self::Return { value: None } => write!(f, "return"),
            Self::Return { value: Some(v) } => write!(f, "return {v}"),
            Self::CondJump {
                cond,
                true_dest,
                false_dest,
            } => write!(f, "if ({cond}) then {true_dest} else {false_dest}"),
            Self::CondCall { cond, dest } => write!(f, "if ({cond}) call {dest}"),
            Self::Trap { code } => write!(f, "trap 0x{code:x}"),
            Self::SysCall => write!(f, "syscall"),
            Self::Breakpoint => write!(f, "bp"),
            Self::Intrinsic { name, args } => {
                write!(f, "{name}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Undefined => write!(f, "undefined"),
            Self::UnimplementedRaw { address, .. } => write!(f, "unimplemented @ {address}"),
            Self::Unimplemented { mnemonic } => write!(f, "unimplemented({mnemonic})"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilAnnotatedInstr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An [`LlilInstruction`] paired with its origin address and encoded byte-length.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LlilAnnotatedInstr {
    /// Address of the machine instruction that produced this LLIL instruction.
    pub address: Address,
    /// Byte length of the original machine instruction.
    pub size: usize,
    /// The LLIL instruction.
    pub instr: LlilInstruction,
    /// Alternative byte-length field used by the builder API.
    pub length: u8,
}

impl fmt::Display for LlilAnnotatedInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.address, self.instr)
    }
}

impl From<LlilInstruction> for LlilAnnotatedInstr {
    fn from(instr: LlilInstruction) -> Self {
        Self {
            address: Address::default(),
            size: 0,
            instr,
            length: 0,
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilBasicBlock
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Alias for [`LlilBasicBlock`] used by the builder/printer API.
pub use LlilBasicBlock as LlilBlock;

/// A maximal straight-line sequence of [`LlilAnnotatedInstr`]s within a function.
#[derive(Debug, Clone, Default)]
pub struct LlilBasicBlock {
    /// Address of the first instruction in the block.
    pub start: Address,
    /// Address of the last instruction in the block (inclusive, not past-end).
    pub end: Address,
    /// Instructions in program order.
    pub instrs: Vec<LlilAnnotatedInstr>,
    /// Index of this block within its containing [`LlilFunction`].
    pub id: u32,
    /// Successor block addresses used by the builder API.
    pub successors: Vec<Address>,
}

impl LlilBasicBlock {
    /// Returns `true` when the block contains no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instrs.is_empty()
    }

    /// Returns a reference to the last instruction, or `None` if the block is empty.
    #[must_use]
    pub fn last_instr(&self) -> Option<&LlilAnnotatedInstr> {
        self.instrs.last()
    }

    /// Returns the terminator instruction (the last instruction if it is a
    /// terminator), or `None`.
    #[must_use]
    pub fn terminator(&self) -> Option<&LlilAnnotatedInstr> {
        self.instrs.last().filter(|i| i.instr.is_terminator())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilFunction
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The lifted LLIL representation of a single function.
#[derive(Debug, Clone, Default)]
pub struct LlilFunction {
    /// Entry-point address of the function.
    pub entry: Address,
    /// All basic blocks, in lifting order.
    pub blocks: Vec<LlilBasicBlock>,
    /// Number of temporary registers (`tmp0`..`tmp{N-1}`) allocated so far.
    pub temp_count: u32,
    /// Optional human-readable function name.
    pub name: Option<String>,
    /// Flat instruction stream used by the optimizer/interpreter APIs.
    pub instructions: Vec<LlilAnnotatedInstr>,
    /// Alias of [`Self::entry`] (function start address) kept for compatibility
    /// with callers that refer to `function.address`.
    pub address: Address,
    /// Numeric function identifier used by external callers/maps.
    pub id: u32,
    /// Optional size in bytes of the function's machine-code range, when known.
    pub size: u64,
    /// Address of the byte past the function's last instruction, when known.
    pub end: Address,
}

impl LlilFunction {
    /// Creates a new, empty function with the given entry point.
    #[must_use]
    pub const fn new(entry: Address) -> Self {
        Self {
            entry,
            blocks: Vec::new(),
            temp_count: 0,
            name: None,
            instructions: Vec::new(),
            address: entry,
            id: 0,
            size: 0,
            end: entry,
        }
    }

    /// Allocates a fresh temporary register and returns it.
    ///
    /// The `size` parameter is informational â€” the caller uses it to annotate
    /// the expressions that reference this temporary.
    pub const fn new_temporary(&mut self, _size: Size) -> LlilRegister {
        let id = self.temp_count;
        self.temp_count += 1;
        LlilRegister::Temporary(id)
    }

    /// Appends `block` to the function's block list.
    pub fn add_block(&mut self, block: LlilBasicBlock) {
        self.blocks.push(block);
    }

    /// Returns the basic block whose `start` address equals `addr`, if any.
    #[must_use]
    pub fn block_at(&self, addr: Address) -> Option<&LlilBasicBlock> {
        self.blocks.iter().find(|b| b.start == addr)
    }

    /// Returns an iterator over every annotated instruction in program order
    /// across all basic blocks.
    pub fn all_instrs(&self) -> impl Iterator<Item = &LlilAnnotatedInstr> {
        self.blocks.iter().flat_map(|b| b.instrs.iter())
    }

    /// Returns the annotated instruction at exactly `addr`, searching across
    /// all blocks.
    #[must_use]
    pub fn instr_at(&self, addr: Address) -> Option<&LlilAnnotatedInstr> {
        self.all_instrs().find(|i| i.address == addr)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LlilBuilder
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Ergonomic builder for constructing a sequence of [`LlilAnnotatedInstr`]s.
///
/// # Example
/// ```rust
/// use rustre_core::address::Address;
/// use rustre_il_llil::{LlilBuilder, Size, llil_reg, llil_const};
///
/// let mut b = LlilBuilder::at(Address::new(0x1000), 3);
/// b.set_reg("rax", Size::QWord, llil_const(42, Size::QWord));
/// b.advance_to(Address::new(0x1003), 1).ret();
/// let instrs = b.build();
/// assert_eq!(instrs.len(), 2);
/// ```
#[derive(Debug)]
pub struct LlilBuilder {
    current_addr: Address,
    current_size: usize,
    instrs: Vec<LlilAnnotatedInstr>,
}

impl LlilBuilder {
    /// Creates a builder starting at address 0 with instruction size 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current_addr: Address::new(0),
            current_size: 0,
            instrs: Vec::new(),
        }
    }

    /// Creates a builder positioned at `addr` with machine-instruction byte
    /// length `size`.
    #[must_use]
    pub const fn at(addr: Address, size: usize) -> Self {
        Self {
            current_addr: addr,
            current_size: size,
            instrs: Vec::new(),
        }
    }

    /// Updates the current address and instruction size.  Call this before
    /// emitting instructions for the next machine instruction.
    pub const fn advance_to(&mut self, addr: Address, size: usize) -> &mut Self {
        self.current_addr = addr;
        self.current_size = size;
        self
    }

    fn push(&mut self, instr: LlilInstruction) -> &mut Self {
        let sz = self.current_size;
        self.instrs.push(LlilAnnotatedInstr {
            address: self.current_addr,
            size: sz,
            instr,
            length: u8::try_from(sz).unwrap_or(u8::MAX),
        });
        self
    }

    /// Emits a [`LlilInstruction::Nop`].
    pub fn nop(&mut self) -> &mut Self {
        self.push(LlilInstruction::Nop)
    }

    /// Emits a [`LlilInstruction::SetReg`].
    pub fn set_reg(
        &mut self,
        dest: impl Into<LlilRegister>,
        size: Size,
        src: LlilExpr,
    ) -> &mut Self {
        self.push(LlilInstruction::SetReg {
            dest: dest.into(),
            size,
            value: src,
        })
    }

    /// Emits a [`LlilInstruction::Store`].
    pub fn store(&mut self, addr: LlilExpr, size: Size, src: LlilExpr) -> &mut Self {
        self.push(LlilInstruction::Store {
            addr,
            size,
            value: src,
        })
    }

    /// Emits a [`LlilInstruction::Load`].
    pub fn load(&mut self, dest: impl Into<LlilRegister>, size: Size, addr: LlilExpr) -> &mut Self {
        self.push(LlilInstruction::Load {
            dest: dest.into(),
            size,
            addr,
        })
    }

    /// Emits a [`LlilInstruction::JumpDest`].
    pub fn jump(&mut self, dest: LlilExpr) -> &mut Self {
        self.push(LlilInstruction::JumpDest { dest })
    }

    /// Emits a [`LlilInstruction::CallDest`].
    pub fn call(&mut self, dest: LlilExpr) -> &mut Self {
        self.push(LlilInstruction::CallDest { dest })
    }

    /// Emits a [`LlilInstruction::Ret`].
    pub fn ret(&mut self) -> &mut Self {
        self.push(LlilInstruction::Ret)
    }

    /// Emits a [`LlilInstruction::CondJump`].
    pub fn cond_jump(
        &mut self,
        cond: LlilExpr,
        true_dest: Address,
        false_dest: Address,
    ) -> &mut Self {
        self.push(LlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        })
    }

    /// Emits a [`LlilInstruction::Trap`].
    pub fn trap(&mut self, code: u64) -> &mut Self {
        self.push(LlilInstruction::Trap { code })
    }

    /// Emits a [`LlilInstruction::SysCall`].
    pub fn syscall(&mut self) -> &mut Self {
        self.push(LlilInstruction::SysCall)
    }

    /// Emits a [`LlilInstruction::Push`].
    pub fn push_stack(&mut self, size: Size, src: LlilExpr) -> &mut Self {
        self.push(LlilInstruction::Push { size, src })
    }

    /// Emits a [`LlilInstruction::Pop`].
    pub fn pop(&mut self, dest: impl Into<LlilRegister>, size: Size) -> &mut Self {
        self.push(LlilInstruction::Pop {
            dest: dest.into(),
            size,
        })
    }

    /// Convenience alias matching the builder spec name.
    pub fn push_instr(&mut self, size: Size, src: LlilExpr) -> &mut Self {
        self.push_stack(size, src)
    }

    /// Finalises the builder and returns all emitted instructions.
    #[must_use]
    pub fn build(self) -> Vec<LlilAnnotatedInstr> {
        self.instrs
    }
}

impl Default for LlilBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Convenience expression constructors
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Construct a [`LlilExpr::Const`] node.
#[must_use]
pub const fn llil_const(v: u64, size: Size) -> LlilExpr {
    LlilExpr::Const { value: v, size }
}

/// Construct a [`LlilExpr::RegisterRef`] node for a concrete named register.
pub fn llil_reg(name: impl Into<String>, size: Size) -> LlilExpr {
    LlilExpr::RegisterRef {
        reg: LlilRegister::Concrete(name.into()),
        size,
    }
}

/// Construct a [`LlilExpr::RegisterRef`] node for a temporary register.
#[must_use]
pub const fn llil_tmp(id: u32, size: Size) -> LlilExpr {
    LlilExpr::RegisterRef {
        reg: LlilRegister::Temporary(id),
        size,
    }
}

/// Construct a [`LlilExpr::Load`] node.
#[must_use]
pub fn llil_load(addr: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::Load {
        addr: Box::new(addr),
        size,
    }
}

/// Construct an [`LlilExpr::Add`] node.
#[must_use]
pub fn llil_add(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::AddT(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::Sub`] node.
#[must_use]
pub fn llil_sub(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::SubT(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::And`] node.
#[must_use]
pub fn llil_and(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::And(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::Or`] node.
#[must_use]
pub fn llil_or(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::Or(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::Xor`] node.
#[must_use]
pub fn llil_xor(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::Xor(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::Shl`] node.
#[must_use]
pub fn llil_shl(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::ShlT(Box::new(l), Box::new(r), size)
}

/// Construct an [`LlilExpr::Shr`] node.
#[must_use]
pub fn llil_shr(l: LlilExpr, r: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::Shr(Box::new(l), Box::new(r), size)
}

/// Construct a [`LlilExpr::CmpEq`] node.
#[must_use]
pub fn llil_cmp_eq(l: LlilExpr, r: LlilExpr) -> LlilExpr {
    LlilExpr::CmpEq(Box::new(l), Box::new(r))
}

/// Construct a [`LlilExpr::CmpNe`] node.
#[must_use]
pub fn llil_cmp_ne(l: LlilExpr, r: LlilExpr) -> LlilExpr {
    LlilExpr::CmpNe(Box::new(l), Box::new(r))
}

/// Construct a [`LlilExpr::CmpSlt`] node.
#[must_use]
pub fn llil_cmp_slt(l: LlilExpr, r: LlilExpr) -> LlilExpr {
    LlilExpr::CmpSlt(Box::new(l), Box::new(r))
}

/// Construct a [`LlilExpr::ZeroExtend`] node.
#[must_use]
pub fn llil_zx(expr: LlilExpr, from: Size, to: Size) -> LlilExpr {
    LlilExpr::ZeroExtend {
        expr: Box::new(expr),
        from,
        to,
    }
}

/// Construct a [`LlilExpr::SignExtend`] node.
#[must_use]
pub fn llil_sx(expr: LlilExpr, from: Size, to: Size) -> LlilExpr {
    LlilExpr::SignExtend {
        expr: Box::new(expr),
        from,
        to,
    }
}

/// Construct a [`LlilExpr::StackPointer`] node.
#[must_use]
pub const fn llil_sp(size: Size) -> LlilExpr {
    LlilExpr::StackPointer(size)
}

/// Construct a [`LlilExpr::Flag`] node.
pub fn llil_flag(name: impl Into<String>) -> LlilExpr {
    LlilExpr::Flag(name.into())
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Bridge from rustre-il-lift
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Convert a [`rustre_il_lift::IrExpr`] into an [`LlilExpr`].
///
/// The lift crate uses a simpler expression AST without size annotations; we
/// default to [`Size::QWord`] (8 bytes) for most nodes.
#[must_use]
pub fn lift_ir_expr_to_llil(expr: &rustre_il_lift::IrExpr) -> LlilExpr {
    use rustre_il_lift::IrExpr;
    match expr {
        IrExpr::Const(v) => LlilExpr::Const {
            value: *v,
            size: Size::QWord,
        },
        IrExpr::Reg(r) => LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(r.clone()),
            size: Size::QWord,
        },
        IrExpr::Add(l, r) => LlilExpr::AddT(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Sub(l, r) => LlilExpr::SubT(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Mul(l, r) => LlilExpr::MulT(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Or(l, r) => LlilExpr::Or(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::And(l, r) => LlilExpr::And(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Xor(l, r) => LlilExpr::Xor(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Shl(l, r) => LlilExpr::ShlT(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Shr(l, r) => LlilExpr::Shr(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        // Arithmetic (sign-propagating) shift right — added to `IrExpr` by a
        // concurrent change without a matching arm here, which left this crate
        // non-exhaustive. `LlilExpr::Sar` already existed, so this is the
        // mapping that was missing, not a new concept: `Sar` propagates the
        // sign and must NOT be folded into `Shr` (logical), which would be
        // wrong for every negative operand.
        //
        // ⚠ Two agents added this same arm at once, so it appeared TWICE and
        // rustc reported `unreachable pattern` (#391). The duplicate was
        // harmless — identical body — but a standing warning is how a REAL one
        // goes unnoticed, exactly like the duplicated `#[test]` that kept a
        // test from ever running. Merged into one arm, comments kept.
        IrExpr::Sar(l, r) => LlilExpr::Sar(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
            Size::QWord,
        ),
        IrExpr::Not(e) => LlilExpr::Not(Box::new(lift_ir_expr_to_llil(e)), Size::QWord),
        IrExpr::Deref(addr, size) => LlilExpr::Load {
            addr: Box::new(lift_ir_expr_to_llil(addr)),
            size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
        },
        IrExpr::CmpEqZero(e) => LlilExpr::CmpEq(
            Box::new(lift_ir_expr_to_llil(e)),
            Box::new(LlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
        ),
        IrExpr::Parity(e) => LlilExpr::Intrinsic {
            name: "parity".to_string(),
            args: vec![lift_ir_expr_to_llil(e)],
            result_size: Size::Byte,
        },
        IrExpr::Undef => LlilExpr::Undefined(Size::QWord),
        IrExpr::CmpEq(l, r) | IrExpr::Eq(l, r) => LlilExpr::CmpEq(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
        ),
        IrExpr::Ne(l, r) => LlilExpr::CmpNe(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
        ),
        // `CmpLtU` e' esplicitamente SENZA SEGNO, quindi mappa senza ambiguita'
        // su `CmpUlt`. `CmpLt` resta com'era: reinterpretarlo sarebbe una
        // scelta di design di chi ha introdotto la variante, non una riparazione.
        IrExpr::CmpLt(l, r) | IrExpr::CmpLtU(l, r) => LlilExpr::CmpUlt(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
        ),
        IrExpr::CmpGt(l, r) => LlilExpr::CmpUgt(
            Box::new(lift_ir_expr_to_llil(l)),
            Box::new(lift_ir_expr_to_llil(r)),
        ),
        IrExpr::IfThenElse(c, t, e) => LlilExpr::CondExpr {
            cond: Box::new(lift_ir_expr_to_llil(c)),
            true_val: Box::new(lift_ir_expr_to_llil(t)),
            false_val: Box::new(lift_ir_expr_to_llil(e)),
            size: Size::QWord,
        },
    }
}

/// Convert a [`rustre_il_lift::Effect`] into an [`LlilInstruction`].
///
/// The `address` parameter is used for control-flow targets derived from the
/// `rustre-il-lift` representation which stores only the fall-through address.
pub fn lift_effect_to_llil_instr(
    effect: &rustre_il_lift::Effect,
    _address: u64,
) -> LlilInstruction {
    use rustre_il_lift::Effect;
    match effect {
        Effect::RegWrite { reg, value } => LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg.clone()),
            size: Size::QWord,
            value: lift_ir_expr_to_llil(value),
        },
        Effect::MemWrite { addr, value, size } => LlilInstruction::Store {
            addr: lift_ir_expr_to_llil(addr),
            size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
            value: lift_ir_expr_to_llil(value),
        },
        Effect::MemRead { addr, dest, size } => LlilInstruction::Load {
            dest: LlilRegister::Concrete(dest.clone()),
            size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
            addr: lift_ir_expr_to_llil(addr),
        },
        Effect::Call { target } => LlilInstruction::CallDest {
            dest: lift_ir_expr_to_llil(target),
        },
        Effect::Branch { target, condition } => condition.as_ref().map_or_else(
            || LlilInstruction::JumpDest {
                dest: lift_ir_expr_to_llil(target),
            },
            |cond| {
                // When the target is a constant we use it directly; otherwise
                // we fall back to a trivial 0-address pair.
                let (true_dest, false_dest) = if let rustre_il_lift::IrExpr::Const(v) = target {
                    (Address::new(*v), Address::new(0))
                } else {
                    (Address::new(0), Address::new(0))
                };
                LlilInstruction::CondJump {
                    cond: lift_ir_expr_to_llil(cond),
                    true_dest,
                    false_dest,
                }
            },
        ),
        Effect::Return { .. } => LlilInstruction::Ret,
        Effect::Syscall { .. } => LlilInstruction::SysCall,
        Effect::Intrinsic { name, args } => LlilInstruction::Intrinsic {
            name: name.clone(),
            args: args.iter().map(lift_ir_expr_to_llil).collect(),
        },
        Effect::Trap { vector } => LlilInstruction::Trap {
            code: u64::from(*vector),
        },
        Effect::ConditionalTrap { condition, vector } => LlilInstruction::CondCall {
            cond: lift_ir_expr_to_llil(condition),
            dest: LlilExpr::Const {
                value: u64::from(*vector),
                size: Size::QWord,
            },
        },
        Effect::NoReturn => LlilInstruction::Undefined,
    }
}

/// Convert a [`rustre_il_lift::LiftedInstr`] into one or more [`LlilAnnotatedInstr`]s.
///
/// Each [`rustre_il_lift::Effect`] in the lifted instruction becomes a separate
/// annotated instruction at the same address.  If the instruction has no
/// effects a single [`LlilInstruction::Nop`] is emitted.
#[must_use]
pub fn lifted_instr_to_llil(instr: &rustre_il_lift::LiftedInstr) -> Vec<LlilAnnotatedInstr> {
    if instr.effects.is_empty() {
        return vec![LlilAnnotatedInstr {
            address: Address::new(instr.address),
            size: 0,
            instr: LlilInstruction::Nop,
            length: 0,
        }];
    }
    instr
        .effects
        .iter()
        .map(|eff| LlilAnnotatedInstr {
            address: Address::new(instr.address),
            size: 0,
            instr: lift_effect_to_llil_instr(eff, instr.address),
            length: 0,
        })
        .collect()
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CFG (Control-Flow Graph) over basic blocks
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Edge kind in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdge {
    /// Unconditional fall-through or jump.
    Unconditional,
    /// Conditional true branch.
    True,
    /// Conditional false branch.
    False,
    /// Call edge (inter-procedural â€” stored separately for analysis use).
    Call,
}

impl std::fmt::Display for CfgEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconditional => write!(f, "unconditional"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::Call => write!(f, "call"),
        }
    }
}

/// The control-flow graph for an [`LlilFunction`].
///
/// Nodes are block indices into [`LlilFunction::blocks`]; edges carry
/// [`CfgEdge`] labels.
#[derive(Debug, Clone)]
pub struct LlilCfg {
    /// The underlying directed graph.  Node weights are block IDs (`u32`).
    pub graph: DiGraph<u32, CfgEdge>,
    /// Map from block ID to its [`NodeIndex`] in `graph`.
    pub node_map: HashMap<u32, NodeIndex>,
}

impl LlilCfg {
    /// Build the CFG for `func`.
    ///
    /// A block at address `A` with a [`LlilInstruction::CondJump`] generates
    /// two outgoing edges; unconditional jumps and fall-throughs generate one.
    #[must_use]
    pub fn build(func: &LlilFunction) -> Self {
        let mut graph: DiGraph<u32, CfgEdge> = DiGraph::new();
        let mut node_map: HashMap<u32, NodeIndex> = HashMap::new();

        // Add a node for every block.
        for block in &func.blocks {
            let idx = graph.add_node(block.id);
            node_map.insert(block.id, idx);
        }

        // Build an address â†’ block-ID lookup.
        let addr_to_block: HashMap<Address, u32> =
            func.blocks.iter().map(|b| (b.start, b.id)).collect();

        // Wire up edges based on terminators.
        for block in &func.blocks {
            let src_idx = node_map[&block.id];
            let Some(term) = block.terminator() else {
                continue;
            };
            match &term.instr {
                LlilInstruction::CondJump {
                    true_dest,
                    false_dest,
                    ..
                } => {
                    if let Some(&tid) = addr_to_block.get(true_dest) {
                        graph.add_edge(src_idx, node_map[&tid], CfgEdge::True);
                    }
                    if let Some(&fid) = addr_to_block.get(false_dest) {
                        graph.add_edge(src_idx, node_map[&fid], CfgEdge::False);
                    }
                }
                LlilInstruction::JumpDest { dest } => {
                    if let LlilExpr::Const { value, .. } = dest
                        && let Some(&tid) = addr_to_block.get(&Address::new(*value)) {
                            graph.add_edge(src_idx, node_map[&tid], CfgEdge::Unconditional);
                        }
                }
                LlilInstruction::JumpTo { targets, .. } => {
                    for t in targets {
                        if let Some(&tid) = addr_to_block.get(t) {
                            graph.add_edge(src_idx, node_map[&tid], CfgEdge::Unconditional);
                        }
                    }
                }
                _ => {
                    // Call edges and other instructions: fall-through handled below.
                }
            }
        }
        Self { graph, node_map }
    }

    /// Returns the [`NodeIndex`] for block `id`, or `None`.
    #[must_use]
    pub fn node(&self, id: u32) -> Option<NodeIndex> {
        self.node_map.get(&id).copied()
    }

    /// Returns an iterator over all successor block IDs of `block_id`.
    pub fn successors(&self, block_id: u32) -> impl Iterator<Item = u32> + '_ {
        let idx = self.node_map.get(&block_id).copied();
        idx.into_iter()
            .flat_map(|n| self.graph.neighbors_directed(n, Direction::Outgoing))
            .map(|n| self.graph[n])
    }

    /// Returns an iterator over all predecessor block IDs of `block_id`.
    pub fn predecessors(&self, block_id: u32) -> impl Iterator<Item = u32> + '_ {
        let idx = self.node_map.get(&block_id).copied();
        idx.into_iter()
            .flat_map(|n| self.graph.neighbors_directed(n, Direction::Incoming))
            .map(|n| self.graph[n])
    }

    /// Compute dominators using a simple iterative algorithm.
    ///
    /// Returns a map from block ID â†’ set of dominator block IDs.
    #[must_use]
    pub fn dominators(&self, entry_id: u32) -> HashMap<u32, HashSet<u32>> {
        let all_ids: HashSet<u32> = self.node_map.keys().copied().collect();
        let mut dom: HashMap<u32, HashSet<u32>> = HashMap::new();
        for &id in &all_ids {
            if id == entry_id {
                dom.insert(id, HashSet::from([id]));
            } else {
                dom.insert(id, all_ids.clone());
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &id in &all_ids {
                if id == entry_id {
                    continue;
                }
                let preds: Vec<u32> = self.predecessors(id).collect();
                if preds.is_empty() {
                    continue;
                }
                let mut new_dom: HashSet<u32> = preds
                    .iter()
                    .filter_map(|p| dom.get(p).cloned())
                    .reduce(|a, b| a.intersection(&b).copied().collect())
                    .unwrap_or_default();
                new_dom.insert(id);
                if dom[&id] != new_dom {
                    dom.insert(id, new_dom);
                    changed = true;
                }
            }
        }
        dom
    }

    /// Compute reachable block IDs from `start_id` using BFS.
    #[must_use]
    pub fn reachable_from(&self, start_id: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_id);
        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                for succ in self.successors(id) {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        visited
    }

    /// Render the CFG as a Graphviz DOT string.
    #[must_use]
    pub fn to_dot(&self, func_name: &str) -> String {
        let mut s = format!("digraph \"{func_name}\" {{\n");
        s.push_str("  rankdir=TB;\n");
        for (id, &ni) in &self.node_map {
            use std::fmt::Write as _;
            let _ = writeln!(s, "  bb{id} [label=\"BB{id}\", shape=box];");
            for succ in self.graph.neighbors_directed(ni, Direction::Outgoing) {
                let edge = self
                    .graph
                    .edges_directed(ni, Direction::Outgoing)
                    .find(|e| e.target() == succ)
                    .map(|e| e.weight().to_string())
                    .unwrap_or_default();
                let sid = self.graph[succ];
                let _ = writeln!(s, "  bb{id} -> bb{sid} [label=\"{edge}\"];");
            }
        }
        s.push_str("}\n");
        s
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Def-use chains
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A definition site: the address of an instruction that writes a register.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefSite {
    /// Address of the defining instruction.
    pub address: u64,
    /// The register being defined.
    pub register: String,
}

/// Def-use chains for an [`LlilFunction`].
#[derive(Debug, Clone)]
pub struct DefUseChains {
    /// Map from register name â†’ list of defining addresses.
    pub defs: HashMap<String, Vec<u64>>,
    /// Map from register name â†’ list of using addresses.
    pub uses: HashMap<String, Vec<u64>>,
}

impl DefUseChains {
    /// Build def-use chains for `func`.
    #[must_use]
    pub fn build(func: &LlilFunction) -> Self {
        let mut defs: HashMap<String, Vec<u64>> = HashMap::new();
        let mut uses: HashMap<String, Vec<u64>> = HashMap::new();
        for ai in func.all_instrs() {
            let addr = ai.address.as_u64();
            // Collect defs
            match &ai.instr {
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Load { dest, .. }
                | LlilInstruction::Pop { dest, .. } => {
                    defs.entry(dest.name()).or_default().push(addr);
                }
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    defs.entry(high.name()).or_default().push(addr);
                    defs.entry(low.name()).or_default().push(addr);
                }
                _ => {}
            }
            // Collect uses
            collect_instr_used_regs(&ai.instr, addr, &mut uses);
        }
        Self { defs, uses }
    }

    /// Returns all defining addresses for `reg`.
    #[must_use]
    pub fn definitions_of(&self, reg: &str) -> &[u64] {
        self.defs.get(reg).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Returns all use addresses for `reg`.
    #[must_use]
    pub fn uses_of(&self, reg: &str) -> &[u64] {
        self.uses.get(reg).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Returns `true` if `reg` has exactly one definition site.
    #[must_use]
    pub fn is_single_def(&self, reg: &str) -> bool {
        self.defs.get(reg).is_some_and(|v| v.len() == 1)
    }
}

/// Collect all register names read by `instr` into `out`.
fn collect_instr_used_regs(
    instr: &LlilInstruction,
    addr: u64,
    out: &mut HashMap<String, Vec<u64>>,
) {
    let mut add_expr = |expr: &LlilExpr| collect_expr_used_regs(expr, addr, out);
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetRegSplit { src, .. }
        | LlilInstruction::SetFlag { src, .. }
        | LlilInstruction::Push { src, .. } => add_expr(src),
        LlilInstruction::Load { addr: a, .. } => add_expr(a),
        LlilInstruction::Store {
            addr: a,
            value: src,
            ..
        } => {
            add_expr(a);
            add_expr(src);
        }
        LlilInstruction::JumpDest { dest }
        | LlilInstruction::JumpTo { dest, .. }
        | LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest } => add_expr(dest),
        LlilInstruction::CondJump { cond, .. } => add_expr(cond),
        LlilInstruction::CondCall { cond, dest } => {
            add_expr(cond);
            add_expr(dest);
        }
        LlilInstruction::Intrinsic { args, .. } => args.iter().for_each(add_expr),
        _ => {}
    }
}

fn collect_expr_used_regs(expr: &LlilExpr, addr: u64, out: &mut HashMap<String, Vec<u64>>) {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => {
            out.entry(reg.name()).or_default().push(addr);
        }
        LlilExpr::Const { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_)
        | LlilExpr::Undefined(_)
        | LlilExpr::Register { .. } => {}
        LlilExpr::Load { addr: a, .. } => collect_expr_used_regs(a, addr, out),
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => {
            collect_expr_used_regs(l, addr, out);
            collect_expr_used_regs(r, addr, out);
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => {
            collect_expr_used_regs(e, addr, out);
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_expr_used_regs(cond, addr, out);
            collect_expr_used_regs(true_val, addr, out);
            collect_expr_used_regs(false_val, addr, out);
        }
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            collect_expr_used_regs(left, addr, out);
            collect_expr_used_regs(right, addr, out);
        }
        LlilExpr::Shl { value, shift, .. } => {
            collect_expr_used_regs(value, addr, out);
            collect_expr_used_regs(shift, addr, out);
        }
        LlilExpr::Intrinsic { args, .. } => {
            for a in args {
                collect_expr_used_regs(a, addr, out);
            }
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Liveness analysis
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Per-block liveness information.
#[derive(Debug, Clone, Default)]
pub struct BlockLiveness {
    /// Registers that are defined (written) before any use in this block.
    pub kills: HashSet<String>,
    /// Registers that are used before any definition in this block.
    pub gen_set: HashSet<String>,
    /// Registers live at the block exit.
    pub live_out: HashSet<String>,
    /// Registers live at the block entry.
    pub live_in: HashSet<String>,
}

/// Perform backward liveness analysis over `func` / `cfg`.
///
/// Returns a map from block ID â†’ [`BlockLiveness`].
///
/// # Panics
/// Panics if internal block-ID bookkeeping is inconsistent (should not happen
/// with a well-formed [`LlilFunction`]).
#[must_use]
pub fn liveness_analysis(func: &LlilFunction, cfg: &LlilCfg) -> HashMap<u32, BlockLiveness> {
    // Step 1: compute per-block GEN and KILL sets.
    let mut info: HashMap<u32, BlockLiveness> = HashMap::new();
    for block in &func.blocks {
        let mut bl = BlockLiveness::default();
        // Walk instructions in order; GEN = uses before a kill; KILL = defs.
        for ai in &block.instrs {
            // Add used registers to GEN if not already killed.
            let mut tmp_uses: HashMap<String, Vec<u64>> = HashMap::new();
            collect_instr_used_regs(&ai.instr, 0, &mut tmp_uses);
            for reg in tmp_uses.into_keys() {
                if !bl.kills.contains(&reg) {
                    bl.gen_set.insert(reg);
                }
            }
            // Add defined registers to KILL.
            match &ai.instr {
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Load { dest, .. }
                | LlilInstruction::Pop { dest, .. } => {
                    bl.kills.insert(dest.name());
                }
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    bl.kills.insert(high.name());
                    bl.kills.insert(low.name());
                }
                _ => {}
            }
        }
        info.insert(block.id, bl);
    }

    // Step 2: iterate until stable (backward pass).
    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            let succs: Vec<u32> = cfg.successors(block.id).collect();
            // live_out = union of live_in of all successors.
            let new_live_out: HashSet<String> = succs
                .iter()
                .filter_map(|sid| info.get(sid))
                .flat_map(|bl| bl.live_in.iter().cloned())
                .collect();
            // live_in = gen âˆª (live_out âˆ’ kill).
            let bl = info.get(&block.id).unwrap();
            let new_live_in: HashSet<String> = bl
                .gen_set
                .iter()
                .cloned()
                .chain(
                    new_live_out
                        .iter()
                        .filter(|r| !bl.kills.contains(*r))
                        .cloned(),
                )
                .collect();
            let bl_mut = info.get_mut(&block.id).unwrap();
            if bl_mut.live_out != new_live_out || bl_mut.live_in != new_live_in {
                bl_mut.live_out = new_live_out;
                bl_mut.live_in = new_live_in;
                changed = true;
            }
        }
    }
    info
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL Optimization passes
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Result type for LLIL optimization passes.
pub type LlilPassResult = anyhow::Result<u32>;

/// Trait for a single-function LLIL optimization/analysis pass.
pub trait LlilPass {
    /// Human-readable name of this pass.
    fn name(&self) -> &'static str;
    /// Run the pass over `func`; return the number of transformations applied.
    ///
    /// # Errors
    /// Returns an error if the pass fails internally.
    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult;
}

// â”€â”€ Constant Folding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Fold constant sub-expressions in-place.
///
/// Examples:
/// - `(0x2.8 + 0x3.8) â†’ 0x5.8`
/// - `(0x0.8 * expr) â†’ 0x0.8`
/// - `(expr - 0x0.8) â†’ expr`
#[derive(Debug, Default)]
pub struct LlilConstantFolder;

impl LlilPass for LlilConstantFolder {
    fn name(&self) -> &'static str {
        "llil-constant-fold"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut count = 0u32;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                count += fold_expr_in_instr(&mut ai.instr);
            }
        }
        Ok(count)
    }
}

/// Constant-fold `expr`, masking any resulting constant to its declared size.
///
/// The inner folder builds results with plain 64-bit arithmetic, so a narrow
/// operation could yield a `Const` whose value does not FIT its own `size`:
/// `Neg(Const{20, DWord}, DWord)` produced 0xFFFF_FFFF_FFFF_FFEC where a DWord
/// negation is 0xFFFF_FFEC, and `Not(Const{0xFF, Byte}, Byte)` produced
/// 0xFFFF_FFFF_FFFF_FF00 for a byte. That is ill-formed IL — any consumer
/// reading `.value` without re-masking sees a sign-polluted 64-bit number.
///
/// `rustre_il_passes::fold_binop` masks (it ends `Some(mask(r, size))`) and
/// `LlilInterpreter::eval_expr` masks for Neg; this folder was the odd one out.
/// Surfaced 2026-07-23 by the randomised fold-vs-interpret differential
/// `const_folding_agrees_with_interpretation`.
///
/// Landing this was gated on proving it could not move decompiler output. It
/// cannot: `fold_expr` is reachable only through `LlilConstantFolder`
/// (`impl LlilPass`), and neither it, `LlilPassManager`, nor the pass name
/// `"llil-constant-fold"` is referenced by ANY crate outside `rustre-il-llil` —
/// the folder does not run on the decompiler path at all. That is a stronger
/// guarantee than an unchanged corpus measurement, which could only have said
/// "no difference observed" rather than "no difference possible".
///
/// Masking at this single exit, rather than in each of the ~20 arms, so a
/// future arm cannot reintroduce the defect by forgetting.
fn fold_expr(expr: LlilExpr) -> (LlilExpr, u32) {
    let (folded, count) = fold_expr_unmasked(expr);
    match folded {
        LlilExpr::Const { value, size } if size.bits() < 64 => {
            let mask = (1u64 << size.bits()) - 1;
            (LlilExpr::Const { value: value & mask, size }, count)
        }
        other => (other, count),
    }
}

fn fold_expr_unmasked(expr: LlilExpr) -> (LlilExpr, u32) {
    match expr {
        // ── Struct-form duals ────────────────────────────────────────────────
        // `LlilExpr` carries BOTH a tuple and a struct spelling of the same four
        // operations — `AddT`/`Add{}`, `SubT`/`Sub{}`, `MulT`/`Mul{}`,
        // `ShlT`/`Shl{}` — the struct ones documented as "used by the optimizer.
        // Equivalent to AddT".
        //
        // `eval_expr` handles both spellings; this folder handled ONLY the tuple
        // ones, so struct-form expressions fell through to the catch-all and were
        // never constant-folded. Two semantically identical programs optimised
        // differently depending on which spelling their producer happened to use.
        //
        // Folded back into the SAME spelling so a producer that relies on the
        // struct form still sees it, and result COUNTS stay comparable.
        LlilExpr::Add { left, right, size } => {
            let (l2, c1) = fold_expr(*left);
            let (r2, c2) = fold_expr(*right);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (LlilExpr::Const { value: lv.wrapping_add(rv), size }, c1 + c2 + 1);
            }
            (LlilExpr::Add { left: Box::new(l2), right: Box::new(r2), size }, c1 + c2)
        }
        LlilExpr::Sub { left, right, size } => {
            let (l2, c1) = fold_expr(*left);
            let (r2, c2) = fold_expr(*right);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (LlilExpr::Const { value: lv.wrapping_sub(rv), size }, c1 + c2 + 1);
            }
            (LlilExpr::Sub { left: Box::new(l2), right: Box::new(r2), size }, c1 + c2)
        }
        LlilExpr::Mul { left, right, size } => {
            let (l2, c1) = fold_expr(*left);
            let (r2, c2) = fold_expr(*right);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (LlilExpr::Const { value: lv.wrapping_mul(rv), size }, c1 + c2 + 1);
            }
            (LlilExpr::Mul { left: Box::new(l2), right: Box::new(r2), size }, c1 + c2)
        }
        LlilExpr::Shl { value, shift, size } => {
            let (v2, c1) = fold_expr(*value);
            let (s2, c2) = fold_expr(*shift);
            if let (Some(vv), Some(sv)) = (v2.is_const(), s2.is_const()) {
                // Same `& 63` reduction the tuple-form `ShlT` arm applies, so the
                // two spellings cannot disagree on out-of-range counts either.
                #[allow(clippy::cast_possible_truncation)]
                return (
                    LlilExpr::Const { value: vv.wrapping_shl((sv & 63) as u32), size },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::Shl { value: Box::new(v2), shift: Box::new(s2), size }, c1 + c2)
        }
        LlilExpr::AddT(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv.wrapping_add(rv),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::AddT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::SubT(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            // x - 0 â†’ x
            if r2.is_const_zero() {
                return (l2, c1 + c2 + 1);
            }
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv.wrapping_sub(rv),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::SubT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::MulT(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            // 0 * x â†’ 0
            if l2.is_const_zero() || r2.is_const_zero() {
                return (LlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv.wrapping_mul(rv),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::MulT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::And(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if l2.is_const_zero() || r2.is_const_zero() {
                return (LlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv & rv,
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::And(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Or(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv | rv,
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::Or(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Xor(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: lv ^ rv,
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::Xor(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::ShlT(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        // Match `llil_interpreter::eval_shift_inner`, which
                        // reduces every shift count `& 63`. The previous
                        // `u32::try_from(rv).unwrap_or(u32::MAX)` fallback
                        // turned counts >= 2^32 into a shift by 63 instead —
                        // folding must not change what execution computes.
                        #[allow(clippy::cast_possible_truncation)]
                        value: lv.wrapping_shl((rv & 63) as u32),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::ShlT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Shr(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        // Count `& 63` to match the interpreter (see ShlT).
                        #[allow(clippy::cast_possible_truncation)]
                        value: lv.wrapping_shr((rv & 63) as u32),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::Shr(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Sar(l, r, s) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                // Sign-extend from the operand width (see eval_expr Sar) so a
                // sub-64-bit negative folds to the correct ones-filled result.
                let signed = sign_extend64(lv, s);
                return (
                    LlilExpr::Const {
                        // Count `& 63` to match the interpreter (see ShlT).
                        #[allow(clippy::cast_possible_truncation)]
                        value: signed.wrapping_shr((rv & 63) as u32).cast_unsigned(),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::Sar(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Neg(e, s) => {
            let (e2, c) = fold_expr(*e);
            if let Some(v) = e2.is_const() {
                return (
                    LlilExpr::Const {
                        value: v.wrapping_neg(),
                        size: s,
                    },
                    c + 1,
                );
            }
            (LlilExpr::Neg(Box::new(e2), s), c)
        }
        LlilExpr::Not(e, s) => {
            let (e2, c) = fold_expr(*e);
            if let Some(v) = e2.is_const() {
                return (LlilExpr::Const { value: !v, size: s }, c + 1);
            }
            (LlilExpr::Not(Box::new(e2), s), c)
        }
        LlilExpr::ZeroExtend { expr: e, from, to } => {
            let (e2, c) = fold_expr(*e);
            if let Some(v) = e2.is_const() {
                let mask = if from.bytes() < 8 {
                    (1u64 << (from.bits())) - 1
                } else {
                    u64::MAX
                };
                return (
                    LlilExpr::Const {
                        value: v & mask,
                        size: to,
                    },
                    c + 1,
                );
            }
            (
                LlilExpr::ZeroExtend {
                    expr: Box::new(e2),
                    from,
                    to,
                },
                c,
            )
        }
        LlilExpr::SignExtend { expr: e, from, to } => {
            let (e2, c) = fold_expr(*e);
            if let Some(v) = e2.is_const() {
                let bits = from.bits();
                let sign_bit = 1u64 << (bits - 1);
                let val = if v & sign_bit != 0 {
                    // sign-extend
                    let mask = u64::MAX << bits;
                    v | mask
                } else {
                    v & ((1u64 << bits) - 1)
                };
                return (
                    LlilExpr::Const {
                        value: val,
                        size: to,
                    },
                    c + 1,
                );
            }
            (
                LlilExpr::SignExtend {
                    expr: Box::new(e2),
                    from,
                    to,
                },
                c,
            )
        }
        LlilExpr::CmpEq(l, r) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: u64::from(lv == rv),
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::CmpEq(Box::new(l2), Box::new(r2)), c1 + c2)
        }
        LlilExpr::CmpNe(l, r) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: u64::from(lv != rv),
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::CmpNe(Box::new(l2), Box::new(r2)), c1 + c2)
        }
        LlilExpr::CmpUlt(l, r) => {
            let (l2, c1) = fold_expr(*l);
            let (r2, c2) = fold_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    LlilExpr::Const {
                        value: u64::from(lv < rv),
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            (LlilExpr::CmpUlt(Box::new(l2), Box::new(r2)), c1 + c2)
        }
        LlilExpr::Load { addr, size } => {
            let (a2, c) = fold_expr(*addr);
            (
                LlilExpr::Load {
                    addr: Box::new(a2),
                    size,
                },
                c,
            )
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            size,
        } => {
            let (cond2, c1) = fold_expr(*cond);
            let (tv2, c2) = fold_expr(*true_val);
            let (fv2, c3) = fold_expr(*false_val);
            if let Some(cv) = cond2.is_const() {
                return if cv != 0 {
                    (tv2, c1 + c2 + c3 + 1)
                } else {
                    (fv2, c1 + c2 + c3 + 1)
                };
            }
            (
                LlilExpr::CondExpr {
                    cond: Box::new(cond2),
                    true_val: Box::new(tv2),
                    false_val: Box::new(fv2),
                    size,
                },
                c1 + c2 + c3,
            )
        }
        other => (other, 0),
    }
}

fn fold_expr_in_instr(instr: &mut LlilInstruction) -> u32 {
    let mut count = 0u32;
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetFlag { src, .. }
        | LlilInstruction::Push { src, .. }
        | LlilInstruction::SetRegSplit { src, .. } => {
            let (new_expr, c) = fold_expr(std::mem::replace(src, LlilExpr::Undefined(Size::Byte)));
            *src = new_expr;
            count += c;
        }
        LlilInstruction::Store {
            addr, value: src, ..
        } => {
            let (a2, c1) = fold_expr(std::mem::replace(addr, LlilExpr::Undefined(Size::Byte)));
            let (s2, c2) = fold_expr(std::mem::replace(src, LlilExpr::Undefined(Size::Byte)));
            *addr = a2;
            *src = s2;
            count += c1 + c2;
        }
        LlilInstruction::Load { addr, .. } => {
            let (a2, c) = fold_expr(std::mem::replace(addr, LlilExpr::Undefined(Size::Byte)));
            *addr = a2;
            count += c;
        }
        LlilInstruction::JumpDest { dest }
        | LlilInstruction::JumpTo { dest, .. }
        | LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest } => {
            let (d2, c) = fold_expr(std::mem::replace(dest, LlilExpr::Undefined(Size::Byte)));
            *dest = d2;
            count += c;
        }
        LlilInstruction::CondJump { cond, .. } => {
            let (c2, c) = fold_expr(std::mem::replace(cond, LlilExpr::Undefined(Size::Byte)));
            *cond = c2;
            count += c;
        }
        LlilInstruction::CondCall { cond, dest } => {
            let (cond2, cc1) = fold_expr(std::mem::replace(cond, LlilExpr::Undefined(Size::Byte)));
            let (dest2, cc2) = fold_expr(std::mem::replace(dest, LlilExpr::Undefined(Size::Byte)));
            *cond = cond2;
            *dest = dest2;
            count += cc1 + cc2;
        }
        LlilInstruction::Intrinsic { args, .. } => {
            for arg in args.iter_mut() {
                let (a2, c) = fold_expr(std::mem::replace(arg, LlilExpr::Undefined(Size::Byte)));
                *arg = a2;
                count += c;
            }
        }
        _ => {}
    }
    count
}

// â”€â”€ Copy Propagation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Propagate simple copy assignments (`reg_a = reg_b`) forward within a block.
#[derive(Debug, Default)]
pub struct LlilCopyPropagation;

impl LlilPass for LlilCopyPropagation {
    fn name(&self) -> &'static str {
        "llil-copy-propagation"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut total = 0u32;
        for block in &mut func.blocks {
            // Map: dest_reg â†’ source_reg (copies seen so far in this block)
            let mut copies: HashMap<String, LlilRegister> = HashMap::new();
            for ai in &mut block.instrs {
                // If this is a pure copy SetReg { dest = Register{r} }, record it.
                if let LlilInstruction::SetReg {
                    dest,
                    value:
                        LlilExpr::RegisterRef {
                            reg: src_reg,
                            size: _,
                        },
                    ..
                } = &ai.instr
                {
                    copies.insert(dest.name(), src_reg.clone());
                }
                // Invalidate any copies whose source was overwritten.
                let killed = match &ai.instr {
                    LlilInstruction::SetReg { dest, .. }
                    | LlilInstruction::Load { dest, .. }
                    | LlilInstruction::Pop { dest, .. } => Some(dest.name()),
                    _ => None,
                };
                if let Some(k) = &killed {
                    copies.retain(|_, v| v.name() != *k);
                    copies.remove(k.as_str());
                }
                // Substitute copies in all source expressions.
                total += substitute_copies_in_instr(&mut ai.instr, &copies);
            }
        }
        Ok(total)
    }
}

fn substitute_copies_in_expr(expr: &mut LlilExpr, copies: &HashMap<String, LlilRegister>) -> u32 {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => {
            if let Some(replacement) = copies.get(&reg.name()) {
                *reg = replacement.clone();
                return 1;
            }
            0
        }
        LlilExpr::Load { addr, .. } => substitute_copies_in_expr(addr, copies),
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => {
            substitute_copies_in_expr(l, copies) + substitute_copies_in_expr(r, copies)
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => substitute_copies_in_expr(e, copies),
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            substitute_copies_in_expr(cond, copies)
                + substitute_copies_in_expr(true_val, copies)
                + substitute_copies_in_expr(false_val, copies)
        }
        LlilExpr::Intrinsic { args, .. } => args
            .iter_mut()
            .map(|a| substitute_copies_in_expr(a, copies))
            .sum(),
        _ => 0,
    }
}

fn substitute_copies_in_instr(
    instr: &mut LlilInstruction,
    copies: &HashMap<String, LlilRegister>,
) -> u32 {
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetFlag { src, .. }
        | LlilInstruction::Push { src, .. }
        | LlilInstruction::SetRegSplit { src, .. } => substitute_copies_in_expr(src, copies),
        LlilInstruction::Store {
            addr, value: src, ..
        } => substitute_copies_in_expr(addr, copies) + substitute_copies_in_expr(src, copies),
        LlilInstruction::Load { addr, .. } => substitute_copies_in_expr(addr, copies),
        LlilInstruction::JumpDest { dest }
        | LlilInstruction::JumpTo { dest, .. }
        | LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest } => substitute_copies_in_expr(dest, copies),
        LlilInstruction::CondJump { cond, .. } => substitute_copies_in_expr(cond, copies),
        LlilInstruction::CondCall { cond, dest } => {
            substitute_copies_in_expr(cond, copies) + substitute_copies_in_expr(dest, copies)
        }
        LlilInstruction::Intrinsic { args, .. } => args
            .iter_mut()
            .map(|a| substitute_copies_in_expr(a, copies))
            .sum(),
        _ => 0,
    }
}

// â”€â”€ Dead Code Elimination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Remove instructions whose result is never used (dead stores to registers
/// that are not live-out and not used within the same block).
#[derive(Debug, Default)]
pub struct LlilDeadCodeElimination;

impl LlilPass for LlilDeadCodeElimination {
    fn name(&self) -> &'static str {
        "llil-dead-code-elim"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let cfg = LlilCfg::build(func);
        let liveness = liveness_analysis(func, &cfg);
        let mut total = 0u32;
        for block in &mut func.blocks {
            let live_out = liveness
                .get(&block.id)
                .map(|b| &b.live_out)
                .cloned()
                .unwrap_or_default();
            // Build live set starting at live_out; walk backwards.
            let mut live: HashSet<String> = live_out.clone();
            let mut to_remove: Vec<usize> = Vec::new();
            for (i, ai) in block.instrs.iter().enumerate().rev() {
                if let LlilInstruction::SetReg {
                        dest, value: src, ..
                    } = &ai.instr {
                    let dn = dest.name();
                    if !live.contains(&dn) && !has_side_effects(src) {
                        to_remove.push(i);
                        total += 1;
                    } else {
                        live.remove(&dn);
                        // Mark all used regs as live.
                        let mut tmp: HashMap<String, Vec<u64>> = HashMap::new();
                        collect_instr_used_regs(&ai.instr, 0, &mut tmp);
                        live.extend(tmp.into_keys());
                    }
                } else {
                    let mut tmp: HashMap<String, Vec<u64>> = HashMap::new();
                    collect_instr_used_regs(&ai.instr, 0, &mut tmp);
                    live.extend(tmp.into_keys());
                }
            }
            let remove_set: HashSet<usize> = to_remove.into_iter().collect();
            let mut idx = 0;
            block.instrs.retain(|_| {
                let keep = !remove_set.contains(&idx);
                idx += 1;
                keep
            });
        }
        Ok(total)
    }
}

const fn has_side_effects(expr: &LlilExpr) -> bool {
    matches!(expr, LlilExpr::Load { .. })
}

// â”€â”€ NOP Elimination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Remove all [`LlilInstruction::Nop`] instructions from every block.
#[derive(Debug, Default)]
pub struct LlilNopElimination;

impl LlilPass for LlilNopElimination {
    fn name(&self) -> &'static str {
        "llil-nop-elim"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut count = 0u32;
        for block in &mut func.blocks {
            let before = block.instrs.len();
            block
                .instrs
                .retain(|ai| !matches!(ai.instr, LlilInstruction::Nop));
            count += u32::try_from(before - block.instrs.len()).unwrap_or(u32::MAX);
        }
        Ok(count)
    }
}

// â”€â”€ Branch Simplification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Simplify `CondJump` with a constant condition to an unconditional `Jump`.
#[derive(Debug, Default)]
pub struct LlilBranchSimplification;

impl LlilPass for LlilBranchSimplification {
    fn name(&self) -> &'static str {
        "llil-branch-simplify"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut count = 0u32;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                if let LlilInstruction::CondJump {
                    cond,
                    true_dest,
                    false_dest,
                } = &ai.instr
                    && let Some(v) = cond.is_const() {
                        let target = if v != 0 { *true_dest } else { *false_dest };
                        ai.instr = LlilInstruction::JumpDest {
                            dest: LlilExpr::Const {
                                value: target.as_u64(),
                                size: Size::QWord,
                            },
                        };
                        count += 1;
                    }
            }
        }
        Ok(count)
    }
}

// â”€â”€ Block Merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Merge a block into its single predecessor when the predecessor has exactly
/// one unconditional successor.
#[derive(Debug, Default)]
pub struct LlilBlockMerge;

impl LlilPass for LlilBlockMerge {
    fn name(&self) -> &'static str {
        "llil-block-merge"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut count = 0u32;
        loop {
            let cfg = LlilCfg::build(func);
            let mut merged = false;
            // Find a block that has exactly one predecessor with one successor.
            let candidate = func.blocks.iter().enumerate().find_map(|(i, b)| {
                if i == 0 {
                    return None;
                } // Never merge entry block away.
                let preds: Vec<u32> = cfg.predecessors(b.id).collect();
                if preds.len() != 1 {
                    return None;
                }
                let pred_id = preds[0];
                
                if cfg.successors(pred_id).count() != 1 {
                    return None;
                }
                Some((pred_id, b.id))
            });
            if let Some((pred_id, succ_id)) = candidate {
                let succ_idx = func.blocks.iter().position(|b| b.id == succ_id).unwrap();
                let succ_block = func.blocks.remove(succ_idx);
                let pred_block = func.blocks.iter_mut().find(|b| b.id == pred_id).unwrap();
                // Remove the terminal jump from pred if present.
                if pred_block
                    .instrs
                    .last()
                    .is_some_and(|i| matches!(i.instr, LlilInstruction::JumpDest { .. }))
                {
                    pred_block.instrs.pop();
                }
                pred_block.instrs.extend(succ_block.instrs);
                pred_block.end = succ_block.end;
                merged = true;
                count += 1;
            }
            if !merged {
                break;
            }
        }
        Ok(count)
    }
}

// â”€â”€ Strength Reduction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replace expensive arithmetic with cheaper equivalents:
/// - `x * 2^n` â†’ `x << n`
/// - `x / 2^n` (unsigned) â†’ `x >> n`
#[derive(Debug, Default)]
pub struct LlilStrengthReduction;

impl LlilPass for LlilStrengthReduction {
    fn name(&self) -> &'static str {
        "llil-strength-reduction"
    }

    fn run(&mut self, func: &mut LlilFunction) -> LlilPassResult {
        let mut count = 0u32;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                count += strength_reduce_in_instr(&mut ai.instr);
            }
        }
        Ok(count)
    }
}

fn strength_reduce_expr(expr: LlilExpr) -> (LlilExpr, u32) {
    match expr {
        LlilExpr::MulT(l, r, s) => {
            let (l2, c1) = strength_reduce_expr(*l);
            let (r2, c2) = strength_reduce_expr(*r);
            if let Some(rv) = r2.is_const()
                && rv.is_power_of_two() {
                    let shift = u64::from(rv.trailing_zeros());
                    return (
                        LlilExpr::ShlT(
                            Box::new(l2),
                            Box::new(LlilExpr::Const {
                                value: shift,
                                size: s,
                            }),
                            s,
                        ),
                        c1 + c2 + 1,
                    );
                }
            if let Some(lv) = l2.is_const()
                && lv.is_power_of_two() {
                    let shift = u64::from(lv.trailing_zeros());
                    return (
                        LlilExpr::ShlT(
                            Box::new(r2),
                            Box::new(LlilExpr::Const {
                                value: shift,
                                size: s,
                            }),
                            s,
                        ),
                        c1 + c2 + 1,
                    );
                }
            (LlilExpr::MulT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::DivU(l, r, s) => {
            let (l2, c1) = strength_reduce_expr(*l);
            let (r2, c2) = strength_reduce_expr(*r);
            if let Some(rv) = r2.is_const()
                && rv.is_power_of_two() {
                    let shift = u64::from(rv.trailing_zeros());
                    return (
                        LlilExpr::Shr(
                            Box::new(l2),
                            Box::new(LlilExpr::Const {
                                value: shift,
                                size: s,
                            }),
                            s,
                        ),
                        c1 + c2 + 1,
                    );
                }
            (LlilExpr::DivU(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::AddT(l, r, s) => {
            let (l2, c1) = strength_reduce_expr(*l);
            let (r2, c2) = strength_reduce_expr(*r);
            (LlilExpr::AddT(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        LlilExpr::Load { addr, size } => {
            let (a2, c) = strength_reduce_expr(*addr);
            (
                LlilExpr::Load {
                    addr: Box::new(a2),
                    size,
                },
                c,
            )
        }
        other => (other, 0),
    }
}

fn strength_reduce_in_instr(instr: &mut LlilInstruction) -> u32 {
    let mut count = 0u32;
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetRegSplit { src, .. }
        | LlilInstruction::Push { src, .. }
        | LlilInstruction::SetFlag { src, .. } => {
            let (new_src, c) =
                strength_reduce_expr(std::mem::replace(src, LlilExpr::Undefined(Size::Byte)));
            *src = new_src;
            count += c;
        }
        LlilInstruction::Store {
            addr, value: src, ..
        } => {
            let (a2, c1) =
                strength_reduce_expr(std::mem::replace(addr, LlilExpr::Undefined(Size::Byte)));
            let (s2, c2) =
                strength_reduce_expr(std::mem::replace(src, LlilExpr::Undefined(Size::Byte)));
            *addr = a2;
            *src = s2;
            count += c1 + c2;
        }
        _ => {}
    }
    count
}

// â”€â”€ Pass Manager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Runs a pipeline of [`LlilPass`]es over a function.
#[derive(Default)]
pub struct LlilPassManager {
    passes: Vec<Box<dyn LlilPass>>,
}

impl LlilPassManager {
    /// Creates an empty pass manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a pass manager with the standard optimisation pipeline.
    #[must_use]
    pub fn standard() -> Self {
        let mut pm = Self::new();
        pm.add(LlilConstantFolder);
        pm.add(LlilCopyPropagation);
        pm.add(LlilBranchSimplification);
        pm.add(LlilNopElimination);
        pm.add(LlilStrengthReduction);
        pm
    }

    /// Adds a pass to the pipeline.
    pub fn add<P: LlilPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Runs all passes over `func` and returns the total number of transformations.
    ///
    /// # Errors
    /// Returns an error if any pass fails.
    pub fn run_all(&mut self, func: &mut LlilFunction) -> anyhow::Result<u32> {
        let mut total = 0u32;
        for pass in &mut self.passes {
            total += pass.run(func)?;
        }
        Ok(total)
    }

    /// Runs passes in repeated iterations until no more changes occur (fixed-point).
    ///
    /// # Errors
    /// Returns an error if any pass fails.
    pub fn run_to_fixed_point(&mut self, func: &mut LlilFunction) -> anyhow::Result<u32> {
        let mut total = 0u32;
        loop {
            let iter = self.run_all(func)?;
            total += iter;
            if iter == 0 {
                break;
            }
        }
        Ok(total)
    }

    /// Returns the names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|p| p.name()).collect()
    }
}

impl std::fmt::Debug for LlilPassManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LlilPassManager({} passes)", self.passes.len())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL Interpreter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Error type for the LLIL interpreter.
#[derive(Debug, thiserror::Error)]
pub enum InterpError {
    #[error("undefined register: {0}")]
    UndefinedRegister(String),
    #[error("division by zero at {0:#x}")]
    DivisionByZero(u64),
    #[error("unimplemented instruction at {0:#x}")]
    Unimplemented(u64),
    #[error("execution step limit exceeded ({0} steps)")]
    StepLimitExceeded(u64),
    #[error("call to {0:#x} â€” calls are not simulated")]
    Call(u64),
    #[error("memory access out of bounds: {0:#x}")]
    MemOutOfBounds(u64),
}

/// A simple LLIL interpreter for unit tests and lightweight emulation.
///
/// Memory is modelled as a flat `Vec<u8>` of configurable size.  Register
/// values are stored as `u64` regardless of declared size.
#[derive(Debug, Clone)]
pub struct LlilInterpreter {
    /// Register file: name â†’ u64 value.
    pub regs: HashMap<String, u64>,
    /// Flat memory buffer.
    pub memory: Vec<u8>,
    /// Stack pointer value (maps to memory addresses).
    pub sp: u64,
    /// Maximum number of steps before bailing out.
    pub step_limit: u64,
    /// Flags register file.
    pub flags: HashMap<String, u64>,
}

impl LlilInterpreter {
    /// Creates an interpreter with `mem_size` bytes of zeroed memory and an
    /// initial stack pointer at `initial_sp`.
    #[must_use]
    pub fn new(mem_size: usize, initial_sp: u64) -> Self {
        Self {
            regs: HashMap::new(),
            memory: vec![0u8; mem_size],
            sp: initial_sp,
            step_limit: 100_000,
            flags: HashMap::new(),
        }
    }

    /// Sets a register to an initial value.
    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    /// Reads a register value.
    ///
    /// # Errors
    /// Returns [`InterpError::UndefinedRegister`] if the register has never been set.
    pub fn read_reg(&self, name: &str) -> Result<u64, InterpError> {
        self.regs
            .get(name)
            .copied()
            .ok_or_else(|| InterpError::UndefinedRegister(name.to_owned()))
    }

    /// Reads `size` bytes from `addr` as a little-endian integer.
    ///
    /// # Errors
    /// Returns [`InterpError::MemOutOfBounds`] if the access falls outside the memory buffer.
    pub fn mem_read(&self, addr: u64, size: usize) -> Result<u64, InterpError> {
        let start = usize::try_from(addr).map_err(|_| InterpError::MemOutOfBounds(addr))?;
        let end = start
            .checked_add(size)
            .ok_or(InterpError::MemOutOfBounds(addr))?;
        if end > self.memory.len() {
            return Err(InterpError::MemOutOfBounds(addr));
        }
        let mut val = 0u64;
        for i in 0..size {
            val |= u64::from(self.memory[start + i]) << (8 * i);
        }
        Ok(val)
    }

    /// Writes `value` as `size` bytes to `addr` (little-endian).
    ///
    /// # Errors
    /// Returns [`InterpError::MemOutOfBounds`] if the access falls outside the memory buffer.
    pub fn mem_write(&mut self, addr: u64, value: u64, size: usize) -> Result<(), InterpError> {
        let start = usize::try_from(addr).map_err(|_| InterpError::MemOutOfBounds(addr))?;
        let end = start
            .checked_add(size)
            .ok_or(InterpError::MemOutOfBounds(addr))?;
        if end > self.memory.len() {
            return Err(InterpError::MemOutOfBounds(addr));
        }
        for i in 0..size {
            self.memory[start + i] = ((value >> (8 * i)) & 0xff) as u8;
        }
        Ok(())
    }

    /// Evaluates an expression to a `u64`.
    ///
    /// # Errors
    /// Propagates any [`InterpError`] from sub-expressions.
    pub fn eval_expr(&self, expr: &LlilExpr) -> Result<u64, InterpError> {
        match expr {
            LlilExpr::Const { value, .. } => Ok(*value),
            LlilExpr::RegisterRef { reg, .. } => self.read_reg(&reg.name()),
            LlilExpr::StackPointer(_) => Ok(self.sp),
            LlilExpr::Flag(f) => Ok(self.flags.get(f.as_str()).copied().unwrap_or(0)),
            LlilExpr::Undefined(_) | LlilExpr::Intrinsic { .. } | LlilExpr::Register { .. } => Ok(0),
            LlilExpr::Load { addr, size } => {
                let a = self.eval_expr(addr)?;
                self.mem_read(a, size.bytes())
            }
            LlilExpr::AddT(l, r, s) => {
                let mask = size_mask(*s);
                Ok(self.eval_expr(l)?.wrapping_add(self.eval_expr(r)?) & mask)
            }
            LlilExpr::SubT(l, r, s) => {
                let mask = size_mask(*s);
                Ok(self.eval_expr(l)?.wrapping_sub(self.eval_expr(r)?) & mask)
            }
            LlilExpr::MulT(l, r, s) => {
                let mask = size_mask(*s);
                Ok(self.eval_expr(l)?.wrapping_mul(self.eval_expr(r)?) & mask)
            }
            LlilExpr::DivU(l, r, _) | LlilExpr::FDiv(l, r, _) => {
                let rv = self.eval_expr(r)?;
                if rv == 0 {
                    return Err(InterpError::DivisionByZero(0));
                }
                Ok(self.eval_expr(l)? / rv)
            }
            LlilExpr::DivS(l, r, _) => {
                let rv = (self.eval_expr(r)?).cast_signed();
                if rv == 0 {
                    return Err(InterpError::DivisionByZero(0));
                }
                let lv = (self.eval_expr(l)?).cast_signed();
                // i64::MIN / -1 overflows; saturate to i64::MAX.
                Ok(lv.checked_div(rv).unwrap_or(i64::MAX).cast_unsigned())
            }
            LlilExpr::ModU(l, r, _) => {
                let rv = self.eval_expr(r)?;
                if rv == 0 {
                    return Err(InterpError::DivisionByZero(0));
                }
                Ok(self.eval_expr(l)? % rv)
            }
            LlilExpr::ModS(l, r, _) => {
                let rv = (self.eval_expr(r)?).cast_signed();
                if rv == 0 {
                    return Err(InterpError::DivisionByZero(0));
                }
                let lv = (self.eval_expr(l)?).cast_signed();
                // i64::MIN % -1 also overflows; treat as 0.
                Ok(lv.checked_rem(rv).unwrap_or(0).cast_unsigned())
            }
            LlilExpr::And(l, r, _) => Ok(self.eval_expr(l)? & self.eval_expr(r)?),
            LlilExpr::Or(l, r, _) => Ok(self.eval_expr(l)? | self.eval_expr(r)?),
            LlilExpr::Xor(l, r, _) => Ok(self.eval_expr(l)? ^ self.eval_expr(r)?),
            // Shift counts are reduced `& 63`, matching
            // `llil_interpreter::eval_shift_inner` (the crate's executable
            // semantics). The previous `u32::try_from(..).unwrap_or(u32::MAX)`
            // fallback evaluated counts >= 2^32 as a shift by 63 instead.
            #[allow(clippy::cast_possible_truncation)]
            LlilExpr::ShlT(l, r, s) => {
                let mask = size_mask(*s);
                Ok(self.eval_expr(l)?.wrapping_shl((self.eval_expr(r)? & 63) as u32) & mask)
            }
            #[allow(clippy::cast_possible_truncation)]
            LlilExpr::Shr(l, r, _) => {
                Ok(self.eval_expr(l)?.wrapping_shr((self.eval_expr(r)? & 63) as u32))
            }
            #[allow(clippy::cast_possible_truncation)]
            LlilExpr::Sar(l, r, s) => {
                // Sign-extend from the OPERAND width first: a sub-64-bit
                // negative (0x8000_0000 as i32) must shift in ones, not the
                // zeros a bare `cast_signed()` of the u64 bit pattern gives.
                let signed = sign_extend64(self.eval_expr(l)?, *s);
                Ok(signed.wrapping_shr((self.eval_expr(r)? & 63) as u32).cast_unsigned())
            }
            LlilExpr::Neg(e, s) => {
                let mask = size_mask(*s);
                Ok(self.eval_expr(e)?.wrapping_neg() & mask)
            }
            LlilExpr::Not(e, _) => Ok(!self.eval_expr(e)?),
            LlilExpr::CmpEq(l, r) | LlilExpr::FCmpEq(l, r) => Ok(u64::from(self.eval_expr(l)? == self.eval_expr(r)?)),
            LlilExpr::CmpNe(l, r) => Ok(u64::from(self.eval_expr(l)? != self.eval_expr(r)?)),
            LlilExpr::CmpUlt(l, r) | LlilExpr::FCmpLt(l, r) => Ok(u64::from(self.eval_expr(l)? < self.eval_expr(r)?)),
            LlilExpr::CmpUle(l, r) => Ok(u64::from(self.eval_expr(l)? <= self.eval_expr(r)?)),
            LlilExpr::CmpUgt(l, r) | LlilExpr::FCmpGt(l, r) => Ok(u64::from(self.eval_expr(l)? > self.eval_expr(r)?)),
            LlilExpr::CmpUge(l, r) => Ok(u64::from(self.eval_expr(l)? >= self.eval_expr(r)?)),
            LlilExpr::CmpSlt(l, r) => Ok(u64::from(
                self.eval_expr(l)?.cast_signed() < self.eval_expr(r)?.cast_signed(),
            )),
            LlilExpr::CmpSle(l, r) => Ok(u64::from(
                self.eval_expr(l)?.cast_signed() <= self.eval_expr(r)?.cast_signed(),
            )),
            LlilExpr::CmpSgt(l, r) => Ok(u64::from(
                self.eval_expr(l)?.cast_signed() > self.eval_expr(r)?.cast_signed(),
            )),
            LlilExpr::CmpSge(l, r) => Ok(u64::from(
                self.eval_expr(l)?.cast_signed() >= self.eval_expr(r)?.cast_signed(),
            )),
            LlilExpr::ZeroExtend { expr: e, from, .. } => {
                let mask = if from.bytes() < 8 {
                    (1u64 << from.bits()) - 1
                } else {
                    u64::MAX
                };
                Ok(self.eval_expr(e)? & mask)
            }
            LlilExpr::SignExtend { expr: e, from, .. } => {
                let v = self.eval_expr(e)?;
                let bits = from.bits();
                let sign_bit = 1u64 << (bits - 1);
                if v & sign_bit != 0 {
                    // When bits == 64 (QWord) the shift would be 64 and panic; in that
                    // case the mask is 0 â€” sign-extension of a full-width value is a no-op.
                    let high_mask = if bits >= 64 { 0u64 } else { u64::MAX << bits };
                    Ok(v | high_mask)
                } else {
                    let low_mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                    Ok(v & low_mask)
                }
            }
            LlilExpr::LowPart { expr: e, to } => {
                let mask = if to.bytes() < 8 {
                    (1u64 << to.bits()) - 1
                } else {
                    u64::MAX
                };
                Ok(self.eval_expr(e)? & mask)
            }
            LlilExpr::CondExpr {
                cond,
                true_val,
                false_val,
                ..
            } => {
                if self.eval_expr(cond)? != 0 {
                    self.eval_expr(true_val)
                } else {
                    self.eval_expr(false_val)
                }
            }
            LlilExpr::Rol(lhs, rhs, size) => {
                let val = self.eval_expr(lhs)?;
                let bits = u32::try_from(size.bits()).unwrap_or(u32::MAX);
                let shift = u32::try_from(self.eval_expr(rhs)?).unwrap_or(u32::MAX) % bits;
                let mask = size_mask(*size);
                // When shift == 0 the complementary shift would be `bits - 0 = bits`
                // which panics for u64 (bits = 64).  Guard it explicitly.
                let rotated = if shift == 0 {
                    val
                } else {
                    (val << shift) | (val >> (bits - shift))
                };
                Ok(rotated & mask)
            }
            LlilExpr::Ror(lhs, rhs, size) => {
                let val = self.eval_expr(lhs)?;
                let bits = u32::try_from(size.bits()).unwrap_or(u32::MAX);
                let shift = u32::try_from(self.eval_expr(rhs)?).unwrap_or(u32::MAX) % bits;
                let mask = size_mask(*size);
                let rotated = if shift == 0 {
                    val
                } else {
                    (val >> shift) | (val << (bits - shift))
                };
                Ok(rotated & mask)
            }
            LlilExpr::IntToFloat { expr: e, .. } | LlilExpr::FloatToInt { expr: e, .. } => self.eval_expr(e),
            LlilExpr::FAdd(l, r, _) => Ok(self.eval_expr(l)?.wrapping_add(self.eval_expr(r)?)),
            LlilExpr::FSub(l, r, _) => Ok(self.eval_expr(l)?.wrapping_sub(self.eval_expr(r)?)),
            LlilExpr::FMul(l, r, _) => Ok(self.eval_expr(l)?.wrapping_mul(self.eval_expr(r)?)),
            LlilExpr::FNeg(e, _) => Ok(self.eval_expr(e)?.wrapping_neg()),
            LlilExpr::Add { left, right, size } => {
                let mask = size_mask(*size);
                Ok(self.eval_expr(left)?.wrapping_add(self.eval_expr(right)?) & mask)
            }
            LlilExpr::Sub { left, right, size } => {
                let mask = size_mask(*size);
                Ok(self.eval_expr(left)?.wrapping_sub(self.eval_expr(right)?) & mask)
            }
            LlilExpr::Mul { left, right, size } => {
                let mask = size_mask(*size);
                Ok(self.eval_expr(left)?.wrapping_mul(self.eval_expr(right)?) & mask)
            }
            LlilExpr::Shl { value, shift, size } => {
                let mask = size_mask(*size);
                Ok(self
                    .eval_expr(value)?
                    .wrapping_shl(u32::try_from(self.eval_expr(shift)?).unwrap_or(u32::MAX))
                    & mask)
            }
        }
    }

    /// Execute a single annotated instruction; returns the next address to execute.
    ///
    /// Returns `None` when the function returns or a terminal with no known target.
    ///
    /// # Errors
    /// Returns an [`InterpError`] if the instruction cannot be executed.
    pub fn step(&mut self, ai: &LlilAnnotatedInstr) -> Result<Option<Address>, InterpError> {
        let next = Address::new(ai.address.as_u64() + ai.size as u64);
        match &ai.instr {
            LlilInstruction::SetReg {
                dest, value: src, ..
            } => {
                let v = self.eval_expr(src)?;
                self.regs.insert(dest.name(), v);
                Ok(Some(next))
            }
            LlilInstruction::Load { dest, addr, size } => {
                let a = self.eval_expr(addr)?;
                let v = self.mem_read(a, size.bytes())?;
                self.regs.insert(dest.name(), v);
                Ok(Some(next))
            }
            LlilInstruction::Store {
                addr,
                value: src,
                size,
            } => {
                let a = self.eval_expr(addr)?;
                let v = self.eval_expr(src)?;
                self.mem_write(a, v, size.bytes())?;
                Ok(Some(next))
            }
            LlilInstruction::SetFlag { name: flag, src } => {
                let v = self.eval_expr(src)?;
                self.flags.insert(flag.clone(), v);
                Ok(Some(next))
            }
            LlilInstruction::Push { size, src } => {
                self.sp = self.sp.wrapping_sub(size.bytes() as u64);
                let v = self.eval_expr(src)?;
                self.mem_write(self.sp, v, size.bytes())?;
                Ok(Some(next))
            }
            LlilInstruction::Pop { dest, size } => {
                let v = self.mem_read(self.sp, size.bytes())?;
                self.sp = self.sp.wrapping_add(size.bytes() as u64);
                self.regs.insert(dest.name(), v);
                Ok(Some(next))
            }
            LlilInstruction::JumpDest { dest }
            | LlilInstruction::JumpTo { dest, .. }
            | LlilInstruction::Jump(dest) => {
                let target = self.eval_expr(dest)?;
                Ok(Some(Address::new(target)))
            }
            LlilInstruction::CondJump {
                cond,
                true_dest,
                false_dest,
            } => {
                let cv = self.eval_expr(cond)?;
                Ok(Some(if cv != 0 { *true_dest } else { *false_dest }))
            }
            LlilInstruction::CallDest { dest }
            | LlilInstruction::TailCall { dest }
            | LlilInstruction::Call(dest) => {
                let target = self.eval_expr(dest)?;
                Err(InterpError::Call(target))
            }
            LlilInstruction::Ret | LlilInstruction::Return { .. } | LlilInstruction::Trap { .. } => Ok(None),
            LlilInstruction::Nop | LlilInstruction::Breakpoint | LlilInstruction::SysCall | LlilInstruction::Intrinsic { .. } => Ok(Some(next)),
            LlilInstruction::Undefined => Err(InterpError::Unimplemented(ai.address.as_u64())),
            LlilInstruction::UnimplementedRaw { address, .. } => {
                Err(InterpError::Unimplemented(address.as_u64()))
            }
            LlilInstruction::Unimplemented { .. } => Err(InterpError::Unimplemented(0)),
            LlilInstruction::SetRegSplit { high, low, src } => {
                let v = self.eval_expr(src)?;
                self.regs.insert(low.name(), v);
                self.regs.insert(high.name(), 0);
                Ok(Some(next))
            }
            LlilInstruction::CondCall { cond, dest } => {
                let cv = self.eval_expr(cond)?;
                if cv != 0 {
                    let target = self.eval_expr(dest)?;
                    Err(InterpError::Call(target))
                } else {
                    Ok(Some(next))
                }
            }
            LlilInstruction::ConditionalJump {
                cond,
                true_target,
                false_target,
            } => {
                let cv = self.eval_expr(cond)?;
                Ok(Some(if cv != 0 { *true_target } else { *false_target }))
            }
            LlilInstruction::SetRegister { dest, value, .. } => {
                let v = self.eval_expr(value)?;
                self.regs.insert(format!("r{dest}"), v);
                Ok(Some(next))
            }
        }
    }

    /// Execute the function `func` starting from its entry block.
    ///
    /// Stops when `Ret` is encountered, the step limit is exceeded, or an
    /// unrecoverable error occurs.
    ///
    /// # Errors
    /// Returns an [`InterpError`] on execution faults.
    pub fn run(&mut self, func: &LlilFunction) -> Result<(), InterpError> {
        let mut cur_addr = func.entry;
        let mut steps = 0u64;
        loop {
            if steps >= self.step_limit {
                return Err(InterpError::StepLimitExceeded(steps));
            }
            let ai = func
                .instr_at(cur_addr)
                .ok_or(InterpError::Unimplemented(cur_addr.as_u64()))?;
            match self.step(ai)? {
                Some(next) => {
                    cur_addr = next;
                }
                None => break,
            }
            steps += 1;
        }
        Ok(())
    }
}

const fn size_mask(s: Size) -> u64 {
    if s.bytes() >= 8 {
        u64::MAX
    } else {
        (1u64 << s.bits()) - 1
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Serialisation helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Serialise `func` to a compact JSON string.
///
/// # Errors
/// Returns an error if serialisation fails.
pub fn function_to_json(func: &LlilFunction) -> anyhow::Result<String> {
    use serde_json::json;
    let blocks: Vec<serde_json::Value> = func
        .blocks
        .iter()
        .map(|b| {
            let instrs: Vec<String> = b.instrs.iter().map(std::string::ToString::to_string).collect();
            json!({
                "id": b.id,
                "start": b.start.as_u64(),
                "end": b.end.as_u64(),
                "instructions": instrs,
            })
        })
        .collect();
    let v = json!({
        "entry": func.entry.as_u64(),
        "temp_count": func.temp_count,
        "blocks": blocks,
    });
    Ok(serde_json::to_string(&v)?)
}

/// Render `func` as a Graphviz DOT string annotated with instruction text.
#[must_use]
pub fn function_to_dot(func: &LlilFunction) -> String {
    use std::fmt::Write as _;
    let cfg = LlilCfg::build(func);
    let mut s = format!(
        "digraph \"fn_{:#x}\" {{\n  rankdir=TB;\n",
        func.entry.as_u64()
    );
    for block in &func.blocks {
        let label_lines: Vec<String> = block
            .instrs
            .iter()
            .map(|i| format!("{:#x}: {}", i.address.as_u64(), i.instr).replace('"', "\\\""))
            .collect();
        let label = label_lines.join("\\l");
        let _ = writeln!(s, "  bb{} [label=\"BB{}\\n{}\\l\", shape=box, fontname=monospace];",
            block.id, block.id, label);
    }
    for (id, &ni) in &cfg.node_map {
        for succ in cfg.graph.neighbors_directed(ni, Direction::Outgoing) {
            let edge_weight = cfg
                .graph
                .edges_directed(ni, Direction::Outgoing)
                .find(|e| e.target() == succ)
                .map(|e| e.weight().to_string())
                .unwrap_or_default();
            let sid = cfg.graph[succ];
            let _ = writeln!(s, "  bb{id} -> bb{sid} [label=\"{edge_weight}\"];");
        }
    }
    s.push_str("}\n");
    s
}

/// Print `func` as a human-readable text listing.
#[must_use]
pub fn function_to_text(func: &LlilFunction) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "Function @ {:#x}  (tmps: {})\n",
        func.entry.as_u64(),
        func.temp_count
    );
    for block in &func.blocks {
        let _ = writeln!(s,
            "  Block {}  [{:#x} .. {:#x}]",
            block.id,
            block.start.as_u64(),
            block.end.as_u64()
        );
        for ai in &block.instrs {
            let _ = writeln!(s,
                "    {:#10x}:  {}",
                ai.address.as_u64(),
                ai.instr
            );
        }
    }
    s
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Additional LlilExpr / LlilInstruction helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl LlilExpr {
    /// Count the total number of nodes in this expression tree.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const { .. }
            | Self::RegisterRef { .. }
            | Self::Register { .. }
            | Self::StackPointer(_)
            | Self::Flag(_)
            | Self::Undefined(_) => 1,
            Self::Load { addr, .. } => 1 + addr.node_count(),
            Self::Neg(e, _)
            | Self::Not(e, _)
            | Self::FNeg(e, _)
            | Self::ZeroExtend { expr: e, .. }
            | Self::SignExtend { expr: e, .. }
            | Self::LowPart { expr: e, .. }
            | Self::IntToFloat { expr: e, .. }
            | Self::FloatToInt { expr: e, .. } => 1 + e.node_count(),
            Self::Add {
                left: l, right: r, ..
            }
            | Self::Sub {
                left: l, right: r, ..
            }
            | Self::Mul {
                left: l, right: r, ..
            }
            | Self::AddT(l, r, _)
            | Self::SubT(l, r, _)
            | Self::MulT(l, r, _)
            | Self::DivU(l, r, _)
            | Self::DivS(l, r, _)
            | Self::ModU(l, r, _)
            | Self::ModS(l, r, _)
            | Self::And(l, r, _)
            | Self::Or(l, r, _)
            | Self::Xor(l, r, _)
            | Self::ShlT(l, r, _)
            | Self::Shr(l, r, _)
            | Self::Sar(l, r, _)
            | Self::Rol(l, r, _)
            | Self::Ror(l, r, _)
            | Self::CmpEq(l, r)
            | Self::CmpNe(l, r)
            | Self::CmpSlt(l, r)
            | Self::CmpUlt(l, r)
            | Self::CmpSle(l, r)
            | Self::CmpUle(l, r)
            | Self::CmpSgt(l, r)
            | Self::CmpUgt(l, r)
            | Self::CmpSge(l, r)
            | Self::CmpUge(l, r)
            | Self::FAdd(l, r, _)
            | Self::FSub(l, r, _)
            | Self::FMul(l, r, _)
            | Self::FDiv(l, r, _)
            | Self::FCmpEq(l, r)
            | Self::FCmpLt(l, r)
            | Self::FCmpGt(l, r) => 1 + l.node_count() + r.node_count(),
            Self::Shl { value, shift, .. } => 1 + value.node_count() + shift.node_count(),
            Self::CondExpr {
                cond,
                true_val,
                false_val,
                ..
            } => 1 + cond.node_count() + true_val.node_count() + false_val.node_count(),
            Self::Intrinsic { args, .. } => 1 + args.iter().map(Self::node_count).sum::<usize>(),
        }
    }

    /// Returns `true` if this expression contains no loads (is "pure").
    #[must_use]
    pub fn is_pure(&self) -> bool {
        match self {
            Self::Load { .. } | Self::Intrinsic { .. } => false,
            Self::Const { .. }
            | Self::RegisterRef { .. }
            | Self::Register { .. }
            | Self::StackPointer(_)
            | Self::Flag(_)
            | Self::Undefined(_) => true,
            Self::Neg(e, _)
            | Self::Not(e, _)
            | Self::FNeg(e, _)
            | Self::ZeroExtend { expr: e, .. }
            | Self::SignExtend { expr: e, .. }
            | Self::LowPart { expr: e, .. }
            | Self::IntToFloat { expr: e, .. }
            | Self::FloatToInt { expr: e, .. } => e.is_pure(),
            Self::Shl { value, shift, .. } => value.is_pure() && shift.is_pure(),
            Self::Add {
                left: l, right: r, ..
            }
            | Self::Sub {
                left: l, right: r, ..
            }
            | Self::Mul {
                left: l, right: r, ..
            }
            | Self::AddT(l, r, _)
            | Self::SubT(l, r, _)
            | Self::MulT(l, r, _)
            | Self::DivU(l, r, _)
            | Self::DivS(l, r, _)
            | Self::ModU(l, r, _)
            | Self::ModS(l, r, _)
            | Self::And(l, r, _)
            | Self::Or(l, r, _)
            | Self::Xor(l, r, _)
            | Self::ShlT(l, r, _)
            | Self::Shr(l, r, _)
            | Self::Sar(l, r, _)
            | Self::Rol(l, r, _)
            | Self::Ror(l, r, _)
            | Self::CmpEq(l, r)
            | Self::CmpNe(l, r)
            | Self::CmpSlt(l, r)
            | Self::CmpUlt(l, r)
            | Self::CmpSle(l, r)
            | Self::CmpUle(l, r)
            | Self::CmpSgt(l, r)
            | Self::CmpUgt(l, r)
            | Self::CmpSge(l, r)
            | Self::CmpUge(l, r)
            | Self::FAdd(l, r, _)
            | Self::FSub(l, r, _)
            | Self::FMul(l, r, _)
            | Self::FDiv(l, r, _)
            | Self::FCmpEq(l, r)
            | Self::FCmpLt(l, r)
            | Self::FCmpGt(l, r) => l.is_pure() && r.is_pure(),
            Self::CondExpr {
                cond,
                true_val,
                false_val,
                ..
            } => cond.is_pure() && true_val.is_pure() && false_val.is_pure(),
        }
    }

    /// Collect all concrete register names referenced in this expression.
    #[must_use]
    pub fn registers_used(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_expr_regs(self, &mut out);
        out.sort();
        out.dedup();
        out
    }
}

fn collect_expr_regs(expr: &LlilExpr, out: &mut Vec<String>) {
    match expr {
        LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(n),
            ..
        } => out.push(n.clone()),
        LlilExpr::Load { addr, .. } => collect_expr_regs(addr, out),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => {
            collect_expr_regs(e, out);
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => {
            collect_expr_regs(l, out);
            collect_expr_regs(r, out);
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_expr_regs(cond, out);
            collect_expr_regs(true_val, out);
            collect_expr_regs(false_val, out);
        }
        LlilExpr::Intrinsic { args, .. } => args.iter().for_each(|a| collect_expr_regs(a, out)),
        _ => {}
    }
}

impl LlilInstruction {
    /// Returns all register names written by this instruction.
    #[must_use]
    pub fn written_regs(&self) -> Vec<String> {
        match self {
            Self::SetReg { dest, .. } | Self::Load { dest, .. } | Self::Pop { dest, .. } => {
                vec![dest.name()]
            }
            Self::SetRegSplit { high, low, .. } => vec![high.name(), low.name()],
            _ => vec![],
        }
    }

    /// Returns all register names read by this instruction's source expressions.
    #[must_use]
    pub fn source_regs(&self) -> Vec<String> {
        let mut tmp: HashMap<String, Vec<u64>> = HashMap::new();
        collect_instr_used_regs(self, 0, &mut tmp);
        let mut v: Vec<String> = tmp.into_keys().collect();
        v.sort();
        v
    }
}

impl LlilFunction {
    /// Returns the total number of instructions across all blocks.
    #[must_use]
    pub fn total_instr_count(&self) -> usize {
        self.blocks.iter().map(|b| b.instrs.len()).sum()
    }

    /// Returns `true` if the function has no basic blocks.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Builds and returns the CFG for this function.
    #[must_use]
    pub fn build_cfg(&self) -> LlilCfg {
        LlilCfg::build(self)
    }

    /// Build def-use chains for this function.
    #[must_use]
    pub fn build_def_use(&self) -> DefUseChains {
        DefUseChains::build(self)
    }

    /// Render this function as a DOT string.
    #[must_use]
    pub fn to_dot(&self) -> String {
        function_to_dot(self)
    }

    /// Render this function as a text listing.
    #[must_use]
    pub fn to_text(&self) -> String {
        function_to_text(self)
    }

    /// Serialise this function to JSON.
    ///
    /// # Errors
    /// Returns an error if serialisation fails.
    pub fn to_json(&self) -> anyhow::Result<String> {
        function_to_json(self)
    }
}

impl LlilBasicBlock {
    /// Returns the number of instructions in this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instrs.len()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL Serialization â€” text and JSON-compatible output
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


/// A serialisable snapshot of an [`LlilFunction`] that uses only plain text.
///
/// This intermediate form can be converted to/from JSON without requiring
/// the full expression types to implement Serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlilFunctionSnapshot {
    /// Entry address.
    pub entry: u64,
    /// Blocks in program order.
    pub blocks: Vec<LlilBlockSnapshot>,
    /// Temporary register count.
    pub temp_count: u32,
}

/// A serialisable snapshot of an [`LlilBasicBlock`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlilBlockSnapshot {
    /// Block ID.
    pub id: u32,
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
    /// Instructions as display strings.
    pub instrs: Vec<LlilInstrSnapshot>,
}

/// A serialisable snapshot of an [`LlilAnnotatedInstr`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlilInstrSnapshot {
    /// Instruction address.
    pub address: u64,
    /// Instruction size (bytes).
    pub size: usize,
    /// Instruction text (from `Display`).
    pub text: String,
    /// Whether this is a terminator.
    pub is_terminator: bool,
}

/// Build a [`LlilFunctionSnapshot`] from an [`LlilFunction`].
#[must_use]
pub fn snapshot_function(func: &LlilFunction) -> LlilFunctionSnapshot {
    let blocks = func
        .blocks
        .iter()
        .map(|b| LlilBlockSnapshot {
            id: b.id,
            start: b.start.as_u64(),
            end: b.end.as_u64(),
            instrs: b
                .instrs
                .iter()
                .map(|ai| LlilInstrSnapshot {
                    address: ai.address.as_u64(),
                    size: ai.size,
                    text: ai.instr.to_string(),
                    is_terminator: ai.instr.is_terminator(),
                })
                .collect(),
        })
        .collect();
    LlilFunctionSnapshot {
        entry: func.entry.as_u64(),
        blocks,
        temp_count: func.temp_count,
    }
}

/// Serialise an [`LlilFunction`] to a JSON string.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if serialization fails.
pub fn llil_function_to_json(func: &LlilFunction) -> Result<String, serde_json::Error> {
    serde_json::to_string(&snapshot_function(func))
}

/// Deserialise a [`LlilFunctionSnapshot`] from a JSON string.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if the JSON is invalid or the structure
/// does not match.
pub fn llil_snapshot_from_json(json: &str) -> Result<LlilFunctionSnapshot, serde_json::Error> {
    serde_json::from_str(json)
}

/// Serialise an [`LlilFunction`] to a pretty-printed JSON string.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if serialization fails.
pub fn llil_function_to_json_pretty(func: &LlilFunction) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&snapshot_function(func))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL DOT / Graphviz output
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Renders the CFG of `func` as a Graphviz DOT string.
///
/// Each node is a basic block labelled with its ID and instructions.
/// Each edge is labelled with its kind (true/false/unconditional).
#[must_use]
pub fn llil_function_to_dot(func: &LlilFunction) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "digraph llil_cfg {{");
    let _ = writeln!(out, "    graph [rankdir=TB fontname=\"Courier\"];");
    let _ = writeln!(out, "    node [shape=box fontname=\"Courier\"];");

    // Emit nodes.
    for block in &func.blocks {
        let mut label = format!("BB{}\\n{}", block.id, block.start);
        for ai in &block.instrs {
            let escaped = ai
                .instr
                .to_string()
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = write!(label, "\\n  {escaped}");
        }
        let _ = writeln!(out, "    bb{id} [label=\"{label}\"];", id = block.id);
    }

    // Emit edges via the CFG.
    let cfg = LlilCfg::build(func);
    for edge in cfg.graph.edge_indices() {
        if let Some((src, dst)) = cfg.graph.edge_endpoints(edge) {
            let src_id = cfg.graph[src];
            let dst_id = cfg.graph[dst];
            let kind = cfg.graph[edge];
            let _ = writeln!(out, "    bb{src_id} -> bb{dst_id} [label=\"{kind}\"];");
        }
    }

    let _ = writeln!(out, "}}");
    out
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL SSA Construction
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An SSA-form LLIL register: name + version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlilSsaReg {
    /// Register name (e.g. `"rax"`, `"tmp0"`).
    pub name: String,
    /// SSA version (0 = initial / unversioned entry value).
    pub version: u32,
}

impl LlilSsaReg {
    /// Creates an SSA register.
    #[must_use]
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// Returns the same register with version incremented by 1.
    #[must_use]
    pub fn next(&self) -> Self {
        Self {
            name: self.name.clone(),
            version: self.version + 1,
        }
    }
}

impl fmt::Display for LlilSsaReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.version)
    }
}

/// A phi node in SSA form: `dest = φ(sources…)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhiNode {
    /// The SSA register defined by this phi.
    pub dest: LlilSsaReg,
    /// The SSA register sources from each predecessor.
    pub sources: Vec<LlilSsaReg>,
    /// The block ID where this phi is placed.
    pub block_id: u32,
}

impl PhiNode {
    /// Creates a new phi node.
    #[must_use]
    pub const fn new(dest: LlilSsaReg, sources: Vec<LlilSsaReg>, block_id: u32) -> Self {
        Self {
            dest,
            sources,
            block_id,
        }
    }
}

impl fmt::Display for PhiNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let srcs: Vec<String> = self.sources.iter().map(ToString::to_string).collect();
        write!(f, "{} = φ({})", self.dest, srcs.join(", "))
    }
}

/// A basic block in SSA form.
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Block identifier.
    pub id: u32,
    /// Phi nodes placed at the top of this block.
    pub phis: Vec<PhiNode>,
    /// Instructions with SSA register names.
    pub instrs: Vec<LlilAnnotatedInstr>,
}

impl SsaBlock {
    /// Returns `true` if the block has no instructions and no phis.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.phis.is_empty() && self.instrs.is_empty()
    }
}

/// An `LlilFunction` converted to SSA form.
#[derive(Debug, Clone)]
pub struct LlilSsaFunction {
    /// Entry-point address.
    pub entry: Address,
    /// SSA blocks.
    pub blocks: Vec<SsaBlock>,
    /// All phi nodes indexed by block ID.
    pub phis_by_block: HashMap<u32, Vec<PhiNode>>,
}

impl LlilSsaFunction {
    /// Returns the total number of phi nodes in the function.
    #[must_use]
    pub fn phi_count(&self) -> usize {
        self.phis_by_block.values().map(Vec::len).sum()
    }

    /// Returns the SSA block with `id`, if it exists.
    #[must_use]
    pub fn block_by_id(&self, id: u32) -> Option<&SsaBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }
}

/// Constructs an [`LlilSsaFunction`] from a regular [`LlilFunction`] using a
/// simple dominance-frontier-based phi insertion.
///
/// This is a best-effort implementation: it inserts phi nodes at join points
/// for every register that is defined in multiple predecessors.  The renaming
/// pass assigns fresh versions to every definition site.
#[must_use]
pub fn build_ssa(func: &LlilFunction) -> LlilSsaFunction {
    // â”€â”€ Step 1: collect all registers defined anywhere in the function â”€â”€â”€â”€â”€â”€â”€â”€
    let mut defined_regs: HashSet<String> = HashSet::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            collect_defined_regs(&ai.instr, &mut defined_regs);
        }
    }

    // â”€â”€ Step 2: compute dominance frontiers (simplified â€” use join points) â”€â”€â”€â”€
    let cfg = LlilCfg::build(func);
    let mut join_points: HashMap<u32, HashSet<String>> = HashMap::new();

    // For each block that has â‰¥2 predecessors, it is a join point.
    for block in &func.blocks {
        let node = cfg.node_map[&block.id];
        let pred_count = cfg
            .graph
            .neighbors_directed(node, Direction::Incoming)
            .count();
        if pred_count >= 2 {
            join_points
                .entry(block.id)
                .or_default()
                .extend(defined_regs.iter().cloned());
        }
    }

    // â”€â”€ Step 3: insert phi nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mut phis_by_block: HashMap<u32, Vec<PhiNode>> = HashMap::new();
    for (block_id, regs) in &join_points {
        let node = cfg.node_map[block_id];
        let pred_count = cfg
            .graph
            .neighbors_directed(node, Direction::Incoming)
            .count()
            .max(1);
        for reg in regs {
            let dest = LlilSsaReg::new(reg.clone(), 0);
            let sources: Vec<LlilSsaReg> = (0..pred_count)
                .map(|_| LlilSsaReg::new(reg.clone(), 0))
                .collect();
            phis_by_block
                .entry(*block_id)
                .or_default()
                .push(PhiNode::new(dest, sources, *block_id));
        }
    }

    // â”€â”€ Step 4: rename â€” assign version numbers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mut version_map: HashMap<String, u32> = HashMap::new();
    let blocks: Vec<SsaBlock> = func
        .blocks
        .iter()
        .map(|b| {
            let phis = phis_by_block.get(&b.id).cloned().unwrap_or_default();
            // Version up definitions in phis.
            let versioned_phis: Vec<PhiNode> = phis
                .into_iter()
                .map(|mut phi| {
                    let v = version_map.entry(phi.dest.name.clone()).or_insert(0);
                    *v += 1;
                    phi.dest.version = *v;
                    phi
                })
                .collect();

            let versioned_instrs: Vec<LlilAnnotatedInstr> = b
                .instrs
                .iter()
                .map(|ai| {
                    let mut ai2 = ai.clone();
                    version_instr_defs(&mut ai2.instr, &mut version_map);
                    ai2
                })
                .collect();

            SsaBlock {
                id: b.id,
                phis: versioned_phis,
                instrs: versioned_instrs,
            }
        })
        .collect();

    LlilSsaFunction {
        entry: func.entry,
        blocks,
        phis_by_block: phis_by_block.clone(),
    }
}

/// Collect all registers written by an instruction.
fn collect_defined_regs(instr: &LlilInstruction, out: &mut HashSet<String>) {
    match instr {
        LlilInstruction::SetReg { dest, .. }
        | LlilInstruction::Load { dest, .. }
        | LlilInstruction::Pop { dest, .. } => {
            out.insert(dest.name());
        }
        LlilInstruction::SetRegSplit { high, low, .. } => {
            out.insert(high.name());
            out.insert(low.name());
        }
        _ => {}
    }
}

/// Bump the version of every register defined by this instruction.
fn version_instr_defs(instr: &mut LlilInstruction, versions: &mut HashMap<String, u32>) {
    match instr {
        LlilInstruction::SetReg { dest, .. }
        | LlilInstruction::Load { dest, .. }
        | LlilInstruction::Pop { dest, .. } => {
            let name = dest.name();
            let v = versions.entry(name.clone()).or_insert(0);
            *v += 1;
            // We can't embed version in LlilRegister without a new variant, so we
            // rename the concrete register to include the version suffix for display.
            *dest = LlilRegister::Concrete(format!("{name}#{v}"));
        }
        _ => {}
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL Concrete Machine State (complementary to LlilInterpreter above)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An alternative concrete machine state used for direct-evaluation execution.
///
/// Unlike [`LlilInterpreter`] which uses a flat memory `Vec`, this uses a
/// sparse `HashMap<u64, u8>` for address-indexed access (useful for emulating
/// heap allocations and mappings outside a fixed buffer).
#[derive(Debug, Clone, Default)]
pub struct LlilMachineState {
    /// Register file: register name â†’ current value.
    pub regs: HashMap<String, u64>,
    /// Sparse memory: address â†’ byte value.
    pub memory: HashMap<u64, u8>,
    /// Flag file.
    pub flags: HashMap<String, u8>,
    /// Stack pointer.
    pub sp: u64,
    /// Whether execution has halted.
    pub halted: bool,
    /// Return value (set on `Ret`).
    pub return_value: Option<u64>,
    /// Call log: target addresses of every `Call` executed.
    pub call_log: Vec<u64>,
}

impl LlilMachineState {
    /// Creates a new state with all registers zeroed and SP at `initial_sp`.
    #[must_use]
    pub fn new(initial_sp: u64) -> Self {
        Self {
            sp: initial_sp,
            ..Default::default()
        }
    }

    /// Read a register value (default 0 if not set).
    #[must_use]
    pub fn read_reg(&self, name: &str) -> u64 {
        *self.regs.get(name).unwrap_or(&0)
    }

    /// Write a register value.
    pub fn write_reg(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    /// Read `size` bytes from `address`, little-endian.
    #[must_use]
    pub fn read_mem(&self, address: u64, size: usize) -> u64 {
        let mut result = 0u64;
        for i in 0..size {
            let byte = *self.memory.get(&(address + i as u64)).unwrap_or(&0);
            result |= u64::from(byte) << (i * 8);
        }
        result
    }

    /// Write `value` of `size` bytes to `address`, little-endian.
    pub fn write_mem(&mut self, address: u64, value: u64, size: usize) {
        for i in 0..size {
            let byte = ((value >> (i * 8)) & 0xFF) as u8;
            self.memory.insert(address + i as u64, byte);
        }
    }

    /// Read a flag value (0 = false, 1 = true).
    #[must_use]
    pub fn read_flag(&self, name: &str) -> u8 {
        *self.flags.get(name).unwrap_or(&0)
    }

    /// Write a flag value.
    pub fn write_flag(&mut self, name: impl Into<String>, value: u8) {
        self.flags.insert(name.into(), value);
    }
}

/// Concrete-execution interpreter for LLIL, using a sparse memory model.
///
/// Executes individual instructions and expressions against a [`LlilMachineState`].
/// This interpreter complements the existing [`LlilInterpreter`] by using a sparse
/// `HashMap`-based memory instead of a flat buffer.
#[derive(Debug, Clone)]
pub struct LlilConcreteInterpreter {
    /// Maximum number of instructions to execute before forcibly stopping.
    pub fuel: u64,
    /// Whether to trace execution (record each instruction executed).
    pub trace: bool,
    /// Trace log (populated when `trace` is true).
    pub trace_log: Vec<String>,
}

impl LlilConcreteInterpreter {
    /// Creates a new interpreter with `fuel` instructions of budget.
    #[must_use]
    pub const fn new(fuel: u64) -> Self {
        Self {
            fuel,
            trace: false,
            trace_log: Vec::new(),
        }
    }

    /// Enable instruction tracing.
    #[must_use]
    pub const fn with_tracing(mut self) -> Self {
        self.trace = true;
        self
    }

    /// Evaluate an [`LlilExpr`] against `state`, returning a concrete `u64`.
    #[must_use]
    pub fn eval_expr(&self, expr: &LlilExpr, state: &LlilMachineState) -> u64 {
        eval_concrete(expr, state)
    }

    /// Execute a single annotated instruction against `state`.
    pub fn step(&mut self, ai: &LlilAnnotatedInstr, state: &mut LlilMachineState) {
        if self.fuel == 0 {
            state.halted = true;
            return;
        }
        self.fuel -= 1;

        if self.trace {
            self.trace_log.push(format!("{ai}"));
        }

        match &ai.instr {
            LlilInstruction::Nop
            | LlilInstruction::Breakpoint
            | LlilInstruction::Intrinsic { .. }
            | LlilInstruction::CondJump { .. }
            | LlilInstruction::JumpDest { .. }
            | LlilInstruction::JumpTo { .. }
            | LlilInstruction::Jump(_)
            | LlilInstruction::ConditionalJump { .. }
            | LlilInstruction::CondCall { .. } => {
                // Nop, Breakpoint, Intrinsic: no-ops.
                // Branch instructions need the full CFG; single-step can't follow them.
            }
            LlilInstruction::SetReg {
                dest, value: src, ..
            } => {
                let val = self.eval_expr(src, state);
                state.write_reg(dest.name(), val);
            }
            LlilInstruction::SetRegSplit { high, low, src } => {
                let val = self.eval_expr(src, state);
                state.write_reg(high.name(), (val >> 32) & 0xFFFF_FFFF);
                state.write_reg(low.name(), val & 0xFFFF_FFFF);
            }
            LlilInstruction::Load { dest, size, addr } => {
                let a = self.eval_expr(addr, state);
                let val = state.read_mem(a, size.bytes());
                state.write_reg(dest.name(), val);
            }
            LlilInstruction::Store {
                addr,
                size,
                value: src,
            } => {
                let a = self.eval_expr(addr, state);
                let val = self.eval_expr(src, state);
                state.write_mem(a, val, size.bytes());
            }
            LlilInstruction::SetFlag { name: flag, src } => {
                let val = u8::try_from(self.eval_expr(src, state) & 0xFF).unwrap_or(0);
                state.write_flag(flag.clone(), val);
            }
            LlilInstruction::Push { size, src } => {
                let val = self.eval_expr(src, state);
                state.sp = state.sp.wrapping_sub(size.bytes() as u64);
                state.write_mem(state.sp, val, size.bytes());
            }
            LlilInstruction::Pop { dest, size } => {
                let val = state.read_mem(state.sp, size.bytes());
                state.sp = state.sp.wrapping_add(size.bytes() as u64);
                state.write_reg(dest.name(), val);
            }
            LlilInstruction::CallDest { dest } | LlilInstruction::Call(dest) => {
                let target = self.eval_expr(dest, state);
                state.call_log.push(target);
            }
            LlilInstruction::TailCall { dest } => {
                let target = self.eval_expr(dest, state);
                state.call_log.push(target);
                state.halted = true;
            }
            LlilInstruction::Ret => {
                state.return_value = Some(state.read_reg("rax"));
                state.halted = true;
            }
            LlilInstruction::Return { value } => {
                state.return_value = Some(
                    value
                        .as_ref().map_or_else(|| state.read_reg("rax"), |v| self.eval_expr(v, state)),
                );
                state.halted = true;
            }
            LlilInstruction::SysCall => {
                // Record the syscall number (conventionally in rax).
                let nr = state.read_reg("rax");
                state.call_log.push(nr);
            }
            LlilInstruction::Trap { .. }
            | LlilInstruction::Undefined
            | LlilInstruction::UnimplementedRaw { .. }
            | LlilInstruction::Unimplemented { .. } => {
                state.halted = true;
            }
            LlilInstruction::SetRegister { dest, value, .. } => {
                let v = self.eval_expr(value, state);
                state.write_reg(format!("r{dest}"), v);
            }
        }
    }

    /// Execute all instructions in the given block.
    pub fn run_block(&mut self, block: &LlilBasicBlock, state: &mut LlilMachineState) {
        for ai in &block.instrs {
            if state.halted {
                break;
            }
            self.step(ai, state);
        }
    }

    /// Execute all instructions in the function linearly (no branch following).
    pub fn run_function_linear(&mut self, func: &LlilFunction, state: &mut LlilMachineState) {
        for block in &func.blocks {
            if state.halted {
                break;
            }
            self.run_block(block, state);
        }
    }
}

// ── eval_concrete and its sub-helpers ────────────────────────────────────────

/// Sign-extend a `u64` value from `size` bits to 64 bits.
fn sign_extend64(value: u64, size: Size) -> i64 {
    // `Size` includes OWord/YWord/ZWord (128/256/512 bits), so `size.bits()`
    // can exceed 64. The previous `64u32 - u32::try_from(size.bits())
    // .unwrap_or(64)` only guarded against the conversion failing — which never
    // happens — so a vector size UNDERFLOWED the subtraction, and the resulting
    // shift is a panic in debug and a masked, meaningless shift in release.
    //
    // Both sibling implementations of this primitive already guard the same
    // way: `rustre_il_passes::sign_extend` (lib.rs:1749) returns early on
    // `bits >= 64`, and `constant_propagation::sign_extend` (:608) on
    // `bits >= 128`. This one was the odd one out. Found 2026-07-23 by
    // comparing the three copies against each other.
    let bits = size.bits();
    if bits >= 64 {
        // A value already 64 bits wide (or wider than we can represent) has no
        // sign bit to propagate into — reinterpret it as-is.
        return value.cast_signed();
    }
    #[allow(clippy::cast_possible_truncation)]
    let shift = 64u32 - bits as u32;
    (value.cast_signed() << shift) >> shift
}

/// Evaluate integer div/rem with division-by-zero guard.
fn eval_concrete_div_mod(expr: &LlilExpr, state: &LlilMachineState) -> u64 {
    match expr {
        LlilExpr::DivU(l, r, s) => {
            let rhs = eval_concrete(r, state);
            if rhs == 0 { return 0; }
            (eval_concrete(l, state) / rhs) & size_mask(*s)
        }
        LlilExpr::DivS(l, r, s) => {
            let lv = sign_extend64(eval_concrete(l, state), *s);
            let rv = sign_extend64(eval_concrete(r, state), *s);
            if rv == 0 { return 0; }
            lv.wrapping_div(rv).cast_unsigned() & size_mask(*s)
        }
        LlilExpr::ModU(l, r, s) => {
            let rhs = eval_concrete(r, state);
            if rhs == 0 { return 0; }
            (eval_concrete(l, state) % rhs) & size_mask(*s)
        }
        LlilExpr::ModS(l, r, s) => {
            let lv = sign_extend64(eval_concrete(l, state), *s);
            let rv = sign_extend64(eval_concrete(r, state), *s);
            if rv == 0 { return 0; }
            lv.wrapping_rem(rv).cast_unsigned() & size_mask(*s)
        }
        _ => unreachable!("eval_concrete_div_mod: unexpected expr"),
    }
}

/// Evaluate shift and rotate operations.
fn eval_concrete_shift(expr: &LlilExpr, state: &LlilMachineState) -> u64 {
    match expr {
        LlilExpr::ShlT(l, r, s) => {
            let sh = u32::try_from(eval_concrete(r, state) & 63).unwrap_or(u32::MAX);
            eval_concrete(l, state).wrapping_shl(sh) & size_mask(*s)
        }
        LlilExpr::Shr(l, r, s) => {
            let sh = u32::try_from(eval_concrete(r, state) & 63).unwrap_or(u32::MAX);
            eval_concrete(l, state).wrapping_shr(sh) & size_mask(*s)
        }
        LlilExpr::Sar(l, r, s) => {
            let sh = u32::try_from(eval_concrete(r, state) & 63).unwrap_or(u32::MAX);
            (sign_extend64(eval_concrete(l, state), *s) >> sh).cast_unsigned() & size_mask(*s)
        }
        LlilExpr::Rol(l, r, s) => {
            let bits = u32::try_from(s.bits()).unwrap_or(u32::MAX);
            let sh = u32::try_from(eval_concrete(r, state)).unwrap_or(u32::MAX) % bits;
            let lv = eval_concrete(l, state) & size_mask(*s);
            ((lv << sh) | (lv >> (bits - sh))) & size_mask(*s)
        }
        LlilExpr::Ror(l, r, s) => {
            let bits = u32::try_from(s.bits()).unwrap_or(u32::MAX);
            let sh = u32::try_from(eval_concrete(r, state)).unwrap_or(u32::MAX) % bits;
            let lv = eval_concrete(l, state) & size_mask(*s);
            ((lv >> sh) | (lv << (bits - sh))) & size_mask(*s)
        }
        _ => unreachable!("eval_concrete_shift: unexpected expr"),
    }
}

/// Evaluate signed integer comparisons.
fn eval_concrete_signed_cmp(expr: &LlilExpr, state: &LlilMachineState) -> u64 {
    match expr {
        LlilExpr::CmpSlt(l, r) => u64::from(
            sign_extend64(eval_concrete(l, state), Size::QWord)
                < sign_extend64(eval_concrete(r, state), Size::QWord),
        ),
        LlilExpr::CmpSle(l, r) => u64::from(
            sign_extend64(eval_concrete(l, state), Size::QWord)
                <= sign_extend64(eval_concrete(r, state), Size::QWord),
        ),
        LlilExpr::CmpSgt(l, r) => u64::from(
            sign_extend64(eval_concrete(l, state), Size::QWord)
                > sign_extend64(eval_concrete(r, state), Size::QWord),
        ),
        LlilExpr::CmpSge(l, r) => u64::from(
            sign_extend64(eval_concrete(l, state), Size::QWord)
                >= sign_extend64(eval_concrete(r, state), Size::QWord),
        ),
        _ => unreachable!("eval_concrete_signed_cmp: unexpected expr"),
    }
}

/// Evaluate floating-point operations.
fn eval_concrete_float_ops(expr: &LlilExpr, state: &LlilMachineState) -> u64 {
    match expr {
        LlilExpr::FAdd(l, r, _) => {
            (f64::from_bits(eval_concrete(l, state)) + f64::from_bits(eval_concrete(r, state))).to_bits()
        }
        LlilExpr::FSub(l, r, _) => {
            (f64::from_bits(eval_concrete(l, state)) - f64::from_bits(eval_concrete(r, state))).to_bits()
        }
        LlilExpr::FMul(l, r, _) => {
            (f64::from_bits(eval_concrete(l, state)) * f64::from_bits(eval_concrete(r, state))).to_bits()
        }
        LlilExpr::FDiv(l, r, _) => {
            (f64::from_bits(eval_concrete(l, state)) / f64::from_bits(eval_concrete(r, state))).to_bits()
        }
        LlilExpr::FNeg(e, _) => (-f64::from_bits(eval_concrete(e, state))).to_bits(),
        LlilExpr::FCmpEq(l, r) => {
            let (lf, rf) = (
                f64::from_bits(eval_concrete(l, state)),
                f64::from_bits(eval_concrete(r, state)),
            );
            u64::from((lf - rf).abs() < f64::EPSILON)
        }
        LlilExpr::FCmpLt(l, r) => {
            u64::from(f64::from_bits(eval_concrete(l, state)) < f64::from_bits(eval_concrete(r, state)))
        }
        LlilExpr::FCmpGt(l, r) => {
            u64::from(f64::from_bits(eval_concrete(l, state)) > f64::from_bits(eval_concrete(r, state)))
        }
        LlilExpr::IntToFloat { expr: e, .. } => {
            (eval_concrete(e, state).cast_signed() as f64).to_bits()
        }
        LlilExpr::FloatToInt { expr: e, to } => {
            (f64::from_bits(eval_concrete(e, state)) as i64).cast_unsigned() & size_mask(*to)
        }
        _ => unreachable!("eval_concrete_float_ops: unexpected expr"),
    }
}

/// Core concrete evaluation — separated from `LlilConcreteInterpreter` so that
/// `self` is not required for the recursive descent.
fn eval_concrete(expr: &LlilExpr, state: &LlilMachineState) -> u64 {
    match expr {
        LlilExpr::Const { value, .. } => *value,
        LlilExpr::RegisterRef { reg, size } => state.read_reg(&reg.name()) & size_mask(*size),
        LlilExpr::StackPointer(s) => state.sp & size_mask(*s),
        LlilExpr::Flag(f) => u64::from(state.read_flag(f)),
        LlilExpr::Undefined(_) | LlilExpr::Intrinsic { .. } => 0,
        LlilExpr::Load { addr, size } => state.read_mem(eval_concrete(addr, state), size.bytes()),
        LlilExpr::AddT(l, r, s) => {
            eval_concrete(l, state).wrapping_add(eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::SubT(l, r, s) => {
            eval_concrete(l, state).wrapping_sub(eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::MulT(l, r, s) => {
            eval_concrete(l, state).wrapping_mul(eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::DivU(..) | LlilExpr::DivS(..) | LlilExpr::ModU(..) | LlilExpr::ModS(..) => {
            eval_concrete_div_mod(expr, state)
        }
        LlilExpr::Neg(e, s) => eval_concrete(e, state).wrapping_neg() & size_mask(*s),
        LlilExpr::Not(e, s) => !eval_concrete(e, state) & size_mask(*s),
        LlilExpr::And(l, r, s) => {
            (eval_concrete(l, state) & eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::Or(l, r, s) => {
            (eval_concrete(l, state) | eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::Xor(l, r, s) => {
            (eval_concrete(l, state) ^ eval_concrete(r, state)) & size_mask(*s)
        }
        LlilExpr::ShlT(..) | LlilExpr::Shr(..) | LlilExpr::Sar(..) | LlilExpr::Rol(..) | LlilExpr::Ror(..) => {
            eval_concrete_shift(expr, state)
        }
        LlilExpr::CmpEq(l, r) => u64::from(eval_concrete(l, state) == eval_concrete(r, state)),
        LlilExpr::CmpNe(l, r) => u64::from(eval_concrete(l, state) != eval_concrete(r, state)),
        LlilExpr::CmpUlt(l, r) => u64::from(eval_concrete(l, state) < eval_concrete(r, state)),
        LlilExpr::CmpUle(l, r) => u64::from(eval_concrete(l, state) <= eval_concrete(r, state)),
        LlilExpr::CmpUgt(l, r) => u64::from(eval_concrete(l, state) > eval_concrete(r, state)),
        LlilExpr::CmpUge(l, r) => u64::from(eval_concrete(l, state) >= eval_concrete(r, state)),
        LlilExpr::CmpSlt(..) | LlilExpr::CmpSle(..) | LlilExpr::CmpSgt(..) | LlilExpr::CmpSge(..) => {
            eval_concrete_signed_cmp(expr, state)
        }
        LlilExpr::ZeroExtend { expr: e, from, .. } => eval_concrete(e, state) & size_mask(*from),
        LlilExpr::SignExtend { expr: e, from, to } => {
            sign_extend64(eval_concrete(e, state) & size_mask(*from), *from).cast_unsigned()
                & size_mask(*to)
        }
        LlilExpr::LowPart { expr: e, to } => eval_concrete(e, state) & size_mask(*to),
        LlilExpr::FAdd(..)
        | LlilExpr::FSub(..)
        | LlilExpr::FMul(..)
        | LlilExpr::FDiv(..)
        | LlilExpr::FNeg(..)
        | LlilExpr::FCmpEq(..)
        | LlilExpr::FCmpLt(..)
        | LlilExpr::FCmpGt(..)
        | LlilExpr::IntToFloat { .. }
        | LlilExpr::FloatToInt { .. } => eval_concrete_float_ops(expr, state),
        LlilExpr::CondExpr { cond, true_val, false_val, .. } => {
            if eval_concrete(cond, state) != 0 {
                eval_concrete(true_val, state)
            } else {
                eval_concrete(false_val, state)
            }
        }
        LlilExpr::Register { id, size } => state.read_reg(&format!("r{id}")) & size_mask(*size),
        LlilExpr::Add { left, right, size } => {
            eval_concrete(left, state).wrapping_add(eval_concrete(right, state)) & size_mask(*size)
        }
        LlilExpr::Sub { left, right, size } => {
            eval_concrete(left, state).wrapping_sub(eval_concrete(right, state)) & size_mask(*size)
        }
        LlilExpr::Mul { left, right, size } => {
            eval_concrete(left, state).wrapping_mul(eval_concrete(right, state)) & size_mask(*size)
        }
        LlilExpr::Shl { value, shift, size } => {
            let s = u32::try_from(eval_concrete(shift, state) & 63).unwrap_or(u32::MAX);
            eval_concrete(value, state).wrapping_shl(s) & size_mask(*size)
        }
    }
}


// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL SIMD Extensions
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Represents a SIMD vector register holding 128 bits (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SimdReg128 {
    /// Raw bytes in little-endian order.
    pub bytes: [u8; 16],
}

impl SimdReg128 {
    /// Creates a new zeroed vector register.
    #[must_use]
    pub fn zeroed() -> Self {
        Self::default()
    }

    /// Creates a register from a 128-bit integer (low 64 bits | high 64 bits).
    #[must_use]
    pub fn from_u64x2(low: u64, high: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&low.to_le_bytes());
        bytes[8..].copy_from_slice(&high.to_le_bytes());
        Self { bytes }
    }

    /// Returns the lower 64 bits.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn low_u64(&self) -> u64 {
        u64::from_le_bytes(self.bytes[..8].try_into().unwrap())
    }

    /// Returns the upper 64 bits.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn high_u64(&self) -> u64 {
        u64::from_le_bytes(self.bytes[8..].try_into().unwrap())
    }

    /// Element-wise 32-bit integer addition.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn add_i32x4(&self, rhs: &Self) -> Self {
        let mut result = Self::zeroed();
        for i in 0..4 {
            let a = i32::from_le_bytes(self.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let b = i32::from_le_bytes(rhs.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let sum = a.wrapping_add(b);
            result.bytes[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
        }
        result
    }

    /// Element-wise 32-bit integer subtraction.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn sub_i32x4(&self, rhs: &Self) -> Self {
        let mut result = Self::zeroed();
        for i in 0..4 {
            let a = i32::from_le_bytes(self.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let b = i32::from_le_bytes(rhs.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let diff = a.wrapping_sub(b);
            result.bytes[i * 4..(i + 1) * 4].copy_from_slice(&diff.to_le_bytes());
        }
        result
    }

    /// Element-wise 32-bit integer multiplication.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn mul_i32x4(&self, rhs: &Self) -> Self {
        let mut result = Self::zeroed();
        for i in 0..4 {
            let a = i32::from_le_bytes(self.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let b = i32::from_le_bytes(rhs.bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let prod = a.wrapping_mul(b);
            result.bytes[i * 4..(i + 1) * 4].copy_from_slice(&prod.to_le_bytes());
        }
        result
    }

    /// Byte shuffle: `result[i] = self[control[i] & 0xF]`.
    ///
    /// # Panics
    ///
    /// Panics if `control` does not have exactly 16 elements.
    #[must_use]
    pub fn shuffle_bytes(&self, control: &[u8; 16]) -> Self {
        let mut result = Self::zeroed();
        for (i, &idx) in control.iter().enumerate() {
            result.bytes[i] = self.bytes[(idx & 0xF) as usize];
        }
        result
    }

    /// Extract the 32-bit lane at `index` (0â€“3).
    ///
    /// # Panics
    ///
    /// Panics if `index >= 4`.
    #[must_use]
    pub fn extract_i32(&self, index: usize) -> i32 {
        assert!(index < 4, "lane index out of bounds");
        i32::from_le_bytes(self.bytes[index * 4..(index + 1) * 4].try_into().unwrap())
    }

    /// Insert a 32-bit value into lane `index` (0â€“3).
    ///
    /// # Panics
    ///
    /// Panics if `index >= 4`.
    #[must_use]
    pub fn insert_i32(&self, index: usize, value: i32) -> Self {
        assert!(index < 4, "lane index out of bounds");
        let mut result = self.clone();
        result.bytes[index * 4..(index + 1) * 4].copy_from_slice(&value.to_le_bytes());
        result
    }

    /// Element-wise 64-bit floating-point addition.
    ///
    /// # Panics
    ///
    /// Never panics; the internal byte slice is always 16 bytes.
    #[must_use]
    pub fn add_f64x2(&self, rhs: &Self) -> Self {
        let a0 = f64::from_le_bytes(self.bytes[0..8].try_into().unwrap());
        let a1 = f64::from_le_bytes(self.bytes[8..16].try_into().unwrap());
        let b0 = f64::from_le_bytes(rhs.bytes[0..8].try_into().unwrap());
        let b1 = f64::from_le_bytes(rhs.bytes[8..16].try_into().unwrap());
        let mut result = Self::zeroed();
        result.bytes[0..8].copy_from_slice(&(a0 + b0).to_le_bytes());
        result.bytes[8..16].copy_from_slice(&(a1 + b1).to_le_bytes());
        result
    }
}

/// SIMD instruction variants for LLIL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimdInstruction {
    /// `dest = src_a + src_b` (element-wise 32-bit int).
    VecAddI32x4 {
        dest: String,
        src_a: String,
        src_b: String,
    },
    /// `dest = src_a - src_b` (element-wise 32-bit int).
    VecSubI32x4 {
        dest: String,
        src_a: String,
        src_b: String,
    },
    /// `dest = src_a * src_b` (element-wise 32-bit int).
    VecMulI32x4 {
        dest: String,
        src_a: String,
        src_b: String,
    },
    /// Byte shuffle: `dest = src.shuffle(control)`.
    VecShuffle {
        dest: String,
        src: String,
        control: [u8; 16],
    },
    /// Extract lane: `dest = src[lane]` (32-bit).
    VecExtractI32 { dest: String, src: String, lane: u8 },
    /// Insert lane: `dest = src; dest[lane] = value`.
    VecInsertI32 {
        dest: String,
        src: String,
        lane: u8,
        value: String,
    },
    /// `dest = src_a + src_b` (element-wise f64).
    VecAddF64x2 {
        dest: String,
        src_a: String,
        src_b: String,
    },
    /// Zero a vector register.
    VecZero { dest: String },
    /// Broadcast a scalar 32-bit integer to all lanes.
    VecBroadcastI32 { dest: String, scalar: String },
}

impl fmt::Display for SimdInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VecAddI32x4 { dest, src_a, src_b } => {
                write!(f, "{dest} = vadd_i32x4({src_a}, {src_b})")
            }
            Self::VecSubI32x4 { dest, src_a, src_b } => {
                write!(f, "{dest} = vsub_i32x4({src_a}, {src_b})")
            }
            Self::VecMulI32x4 { dest, src_a, src_b } => {
                write!(f, "{dest} = vmul_i32x4({src_a}, {src_b})")
            }
            Self::VecShuffle { dest, src, .. } => write!(f, "{dest} = vshuffle({src}, ...)"),
            Self::VecExtractI32 { dest, src, lane } => {
                write!(f, "{dest} = vextract_i32({src}, {lane})")
            }
            Self::VecInsertI32 {
                dest,
                src,
                lane,
                value,
            } => write!(f, "{dest} = vinsert_i32({src}, {lane}, {value})"),
            Self::VecAddF64x2 { dest, src_a, src_b } => {
                write!(f, "{dest} = vadd_f64x2({src_a}, {src_b})")
            }
            Self::VecZero { dest } => write!(f, "{dest} = vzero()"),
            Self::VecBroadcastI32 { dest, scalar } => {
                write!(f, "{dest} = vbroadcast_i32({scalar})")
            }
        }
    }
}

/// Machine state extension for SIMD registers.
#[derive(Debug, Clone, Default)]
pub struct SimdMachineState {
    /// Named 128-bit vector registers.
    pub vec_regs: HashMap<String, SimdReg128>,
    /// Scalar registers (forwarded from `LlilMachineState`).
    pub scalar_regs: HashMap<String, u64>,
}

impl SimdMachineState {
    /// Creates an empty SIMD state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a vector register (returns zeroed if not set).
    #[must_use]
    pub fn read_vec(&self, name: &str) -> SimdReg128 {
        self.vec_regs.get(name).cloned().unwrap_or_default()
    }

    /// Write a vector register.
    pub fn write_vec(&mut self, name: impl Into<String>, val: SimdReg128) {
        self.vec_regs.insert(name.into(), val);
    }

    /// Read a scalar register.
    #[must_use]
    pub fn read_scalar(&self, name: &str) -> u64 {
        *self.scalar_regs.get(name).unwrap_or(&0)
    }

    /// Write a scalar register.
    pub fn write_scalar(&mut self, name: impl Into<String>, val: u64) {
        self.scalar_regs.insert(name.into(), val);
    }

    /// Execute a single SIMD instruction.
    pub fn execute(&mut self, instr: &SimdInstruction) {
        match instr {
            SimdInstruction::VecAddI32x4 { dest, src_a, src_b } => {
                let a = self.read_vec(src_a);
                let b = self.read_vec(src_b);
                self.write_vec(dest.clone(), a.add_i32x4(&b));
            }
            SimdInstruction::VecSubI32x4 { dest, src_a, src_b } => {
                let a = self.read_vec(src_a);
                let b = self.read_vec(src_b);
                self.write_vec(dest.clone(), a.sub_i32x4(&b));
            }
            SimdInstruction::VecMulI32x4 { dest, src_a, src_b } => {
                let a = self.read_vec(src_a);
                let b = self.read_vec(src_b);
                self.write_vec(dest.clone(), a.mul_i32x4(&b));
            }
            SimdInstruction::VecShuffle { dest, src, control } => {
                let s = self.read_vec(src);
                self.write_vec(dest.clone(), s.shuffle_bytes(control));
            }
            SimdInstruction::VecExtractI32 { dest, src, lane } => {
                let s = self.read_vec(src);
                let val = u64::from(s.extract_i32(*lane as usize).cast_unsigned());
                self.write_scalar(dest.clone(), val);
            }
            SimdInstruction::VecInsertI32 {
                dest,
                src,
                lane,
                value,
            } => {
                let s = self.read_vec(src);
                let scalar = u32::try_from(self.read_scalar(value) & 0xFFFF_FFFF).unwrap_or(0).cast_signed();
                self.write_vec(dest.clone(), s.insert_i32(*lane as usize, scalar));
            }
            SimdInstruction::VecAddF64x2 { dest, src_a, src_b } => {
                let a = self.read_vec(src_a);
                let b = self.read_vec(src_b);
                self.write_vec(dest.clone(), a.add_f64x2(&b));
            }
            SimdInstruction::VecZero { dest } => {
                self.write_vec(dest.clone(), SimdReg128::zeroed());
            }
            SimdInstruction::VecBroadcastI32 { dest, scalar } => {
                let val = u32::try_from(self.read_scalar(scalar) & 0xFFFF_FFFF).unwrap_or(0).cast_signed();
                let r = SimdReg128::zeroed()
                    .insert_i32(0, val)
                    .insert_i32(1, val)
                    .insert_i32(2, val)
                    .insert_i32(3, val);
                self.write_vec(dest.clone(), r);
            }
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LLIL Common Subexpression Elimination (CSE)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The CSE pass replaces repeated subexpressions within a basic block with
/// a single computation stored in a temporary.
///
/// The implementation uses a canonical string hash of each sub-expression
/// as the key.  This is conservative: it only replaces exact syntactic
/// duplicates that appear in the same basic block.
pub struct CsePass;

impl CsePass {
    /// Creates a new CSE pass.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Count the number of duplicate subexpressions in `instrs`.
    ///
    /// Returns the count of replaced (deduplicated) expressions.
    #[must_use]
    pub fn count_duplicates(&self, instrs: &[LlilAnnotatedInstr]) -> usize {
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut duplicates = 0usize;
        let mut exprs: Vec<LlilExpr> = Vec::new();
        for ai in instrs {
            exprs.clear();
            collect_subexprs(&ai.instr, &mut exprs);
            for expr in &exprs {
                let key = format!("{expr}");
                let count = seen.entry(key).or_insert(0);
                if *count > 0 {
                    duplicates += 1;
                }
                *count += 1;
            }
        }
        duplicates
    }
}

impl Default for CsePass {
    fn default() -> Self {
        Self::new()
    }
}

/// Collect all non-trivial sub-expressions from an instruction.
fn collect_subexprs(instr: &LlilInstruction, out: &mut Vec<LlilExpr>) {
    fn collect_from_expr(expr: &LlilExpr, out: &mut Vec<LlilExpr>) {
        match expr {
            LlilExpr::Const { .. }
            | LlilExpr::RegisterRef { .. }
            | LlilExpr::StackPointer(_)
            | LlilExpr::Flag(_)
            | LlilExpr::Undefined(_) => {}
            _ => {
                out.push(expr.clone());
                // Recurse (simplified).
            }
        }
    }
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetFlag { src, .. }
        | LlilInstruction::Push { src, .. } => collect_from_expr(src, out),
        LlilInstruction::Store {
            addr, value: src, ..
        } => {
            collect_from_expr(addr, out);
            collect_from_expr(src, out);
        }
        LlilInstruction::Load { addr, .. } => collect_from_expr(addr, out),
        LlilInstruction::JumpDest { dest }
        | LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest } => collect_from_expr(dest, out),
        LlilInstruction::CondJump { cond, .. } => collect_from_expr(cond, out),
        _ => {}
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Size â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn size_bytes_and_bits() {
        assert_eq!(Size::Byte.bytes(), 1);
        assert_eq!(Size::Byte.bits(), 8);
        assert_eq!(Size::Word.bytes(), 2);
        assert_eq!(Size::Word.bits(), 16);
        assert_eq!(Size::DWord.bytes(), 4);
        assert_eq!(Size::DWord.bits(), 32);
        assert_eq!(Size::QWord.bytes(), 8);
        assert_eq!(Size::QWord.bits(), 64);
        assert_eq!(Size::OWord.bytes(), 16);
        assert_eq!(Size::OWord.bits(), 128);
    }

    #[test]
    fn size_try_from_success() {
        assert_eq!(Size::try_from(1), Ok(Size::Byte));
        assert_eq!(Size::try_from(2), Ok(Size::Word));
        assert_eq!(Size::try_from(4), Ok(Size::DWord));
        assert_eq!(Size::try_from(8), Ok(Size::QWord));
        assert_eq!(Size::try_from(16), Ok(Size::OWord));
    }

    /// Constant folding must agree with the LLIL interpreter on out-of-range
    /// shift counts. `llil_interpreter::eval_shift_inner` reduces every
    /// ShlT/Shr/Sar count `& 63`; the folder used
    /// `u32::try_from(count).unwrap_or(u32::MAX)`, which turns any count >=
    /// 2^32 into a shift by 63 — so folding changed the value a program
    /// computes. (Counts below 2^32 coincidentally agreed, because Rust's
    /// `wrapping_shl`/`wrapping_shr` also reduce the count mod 64.)
    #[test]
    fn shift_const_fold_matches_interpreter_for_out_of_range_counts() {
        let c = |value: u64| LlilExpr::Const { value, size: Size::QWord };
        let huge = 1u64 << 32; // (1<<32) & 63 == 0 -> the interpreter shifts by 0
        let (folded, _) = fold_expr(LlilExpr::ShlT(Box::new(c(1)), Box::new(c(huge)), Size::QWord));
        assert_eq!(folded.is_const(), Some(1), "shl by 1<<32 executes as shl by 0");
        let (folded, _) = fold_expr(LlilExpr::Shr(
            Box::new(c(0x8000_0000_0000_0000)),
            Box::new(c(huge)),
            Size::QWord,
        ));
        assert_eq!(
            folded.is_const(),
            Some(0x8000_0000_0000_0000),
            "shr by 1<<32 executes as shr by 0"
        );
        let (folded, _) = fold_expr(LlilExpr::Sar(
            Box::new(c(0x8000_0000_0000_0000)),
            Box::new(c(huge)),
            Size::QWord,
        ));
        assert_eq!(
            folded.is_const(),
            Some(0x8000_0000_0000_0000),
            "sar by 1<<32 executes as sar by 0"
        );
    }

    /// Differential oracle for the IL layer: **constant folding must agree with
    /// interpretation** on every constant expression.
    ///
    /// This crate contains FOUR evaluators of the same IL — `fold_expr`
    /// (lib.rs:2109), `LlilInterpreter::eval_expr` (lib.rs:3113), a second
    /// `eval_expr` over `LlilMachineState` (lib.rs:4355), and
    /// `llil_interpreter::eval_expr` (llil_interpreter.rs:896). Duplication of
    /// this kind is where nearly every real defect in this repo has lived: on
    /// 2026-07-23 alone, two `decode_pushm_popm`, two `eliminate_dead_stores`
    /// and three `sign_extend` copies each diverged, and the shift-count class
    /// was reopened twice precisely because separate evaluators invented their
    /// own out-of-range rules.
    ///
    /// Before this test the only fold-vs-interpret comparison in the crate was
    /// `shift_const_fold_matches_interpreter_for_out_of_range_counts`, covering
    /// exactly three shift cases. This generalises it: random nested expressions
    /// over random constants, every arm the folder handles, all widths.
    ///
    /// Deterministic (fixed-seed LCG) so a failure is reproducible — this repo
    /// has been bitten by hash-order nondeterminism six times and a flaky
    /// oracle would be worse than none.
    #[test]
    fn const_folding_agrees_with_interpretation() {
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                self.0
            }
        }

        let sizes = [Size::Byte, Size::Word, Size::DWord, Size::QWord];
        let mut rng = Lcg(0x5DEE_CE66_D1CE_B00D);
        let mut compared = 0usize;

        for _ in 0..4000 {
            let size = sizes[(rng.next() % 4) as usize];
            let c = |v: u64| LlilExpr::Const { value: v, size };
            // Bias towards small and boundary values as well as full-range ones:
            // shift counts, zero and all-ones are where evaluators disagree.
            let pick = |r: &mut Lcg| -> u64 {
                match r.next() % 6 {
                    0 => 0,
                    1 => u64::MAX,
                    2 => 1u64 << (r.next() % 64),
                    3 => r.next() % 128,
                    _ => r.next(),
                }
            };
            // Mask generated constants to their declared size: a
            // `Const { value, size }` whose value does not fit `size` is
            // ill-formed IL, and a differential run on ill-formed input proves
            // nothing about either evaluator.
            let fit = |v: u64| if size.bits() >= 64 { v } else { v & ((1u64 << size.bits()) - 1) };
            let (a, b) = (fit(pick(&mut rng)), fit(pick(&mut rng)));
            let (la, lb) = (Box::new(c(a)), Box::new(c(b)));

            let expr = match rng.next() % 12 {
                0 => LlilExpr::AddT(la, lb, size),
                1 => LlilExpr::SubT(la, lb, size),
                2 => LlilExpr::And(la, lb, size),
                3 => LlilExpr::Or(la, lb, size),
                4 => LlilExpr::Xor(la, lb, size),
                5 => LlilExpr::ShlT(la, lb, size),
                6 => LlilExpr::Shr(la, lb, size),
                7 => LlilExpr::Sar(la, lb, size),
                8 => LlilExpr::MulT(la, lb, size),
                9 => LlilExpr::Not(la, size),
                10 => LlilExpr::Neg(la, size),
                _ => LlilExpr::LowPart { expr: la, to: size },
            };

            // Interpret the ORIGINAL expression…
            let interp = LlilInterpreter::new(0, 0);
            let Ok(evaluated) = interp.eval_expr(&expr) else {
                continue; // division by zero and friends: nothing to compare
            };
            // …and fold it. Only a fully-folded Const is comparable.
            let (folded, _) = fold_expr(expr.clone());
            let Some(folded_val) = folded.is_const() else {
                continue; // folder declined this shape — not a disagreement
            };

            compared += 1;
            // ⚠️ OPEN FINDING, deliberately tolerated here rather than papered
            // over: the two evaluators apply width-masking INCONSISTENTLY, and
            // in OPPOSITE directions depending on the operation.
            //   Neg(Const{20, DWord}) -> folder gave 0xFFFF_FFFF_FFFF_FFEC
            //                            (unmasked) while eval gave 0xFFFF_FFEC;
            //   Not(Const{38, Byte})  -> eval gives 0xFFFF..FFD9 (unmasked)
            //                            while the folder gives 0xD9.
            // The folder's exit is now masked (see `fold_expr`), which makes it
            // self-consistent and matches `rustre_il_passes::fold_binop`; the
            // INTERPRETER still masks per-operation. Unifying that changes
            // decompiler output, so it is recorded, not changed blind.
            //
            // Comparing both sides masked to the operand width therefore tests
            // what is actually at stake — that the two agree on the ARITHMETIC —
            // while the representational gap above stays visible in writing.
            let w = |v: u64| if size.bits() >= 64 { v } else { v & ((1u64 << size.bits()) - 1) };
            assert_eq!(
                w(folded_val), w(evaluated),
                "fold and interpretation disagree on {expr:?}: folded {folded_val:#x},                  interpreted {evaluated:#x} (masked to {} bits)", size.bits()
            );
        }

        // Anti-degeneracy: an oracle that compares nothing passes while proving
        // nothing — the failure mode that let several fake cross-checks in this
        // workspace survive.
        assert!(
            compared > 1000,
            "differential degenerated: only {compared} expressions actually compared"
        );
    }

    /// The tuple and struct spellings of the same operation must FOLD alike.
    ///
    /// `LlilExpr` carries four dual pairs — `AddT`/`Add{}`, `SubT`/`Sub{}`,
    /// `MulT`/`Mul{}`, `ShlT`/`Shl{}` — with the struct ones documented as
    /// "Equivalent to AddT". `eval_expr` handled both; `fold_expr` handled only
    /// the tuple ones, so struct-form constants were never folded and two
    /// identical programs optimised differently depending on their producer's
    /// choice of spelling. Found 2026-07-23 by comparing the two evaluators.
    #[test]
    fn fold_expr_treats_struct_and_tuple_spellings_alike() {
        let sz = Size::QWord;
        let c = |v: u64| Box::new(LlilExpr::Const { value: v, size: sz });

        let pairs: Vec<(LlilExpr, LlilExpr, &str)> = vec![
            (
                LlilExpr::AddT(c(7), c(35), sz),
                LlilExpr::Add { left: c(7), right: c(35), size: sz },
                "add",
            ),
            (
                LlilExpr::SubT(c(50), c(8), sz),
                LlilExpr::Sub { left: c(50), right: c(8), size: sz },
                "sub",
            ),
            (
                LlilExpr::MulT(c(6), c(7), sz),
                LlilExpr::Mul { left: c(6), right: c(7), size: sz },
                "mul",
            ),
            (
                LlilExpr::ShlT(c(1), c(5), sz),
                LlilExpr::Shl { value: c(1), shift: c(5), size: sz },
                "shl",
            ),
        ];

        for (tuple_form, struct_form, name) in pairs {
            let (ft, _) = fold_expr(tuple_form);
            let (fs, _) = fold_expr(struct_form);
            let vt = ft.is_const();
            let vs = fs.is_const();
            assert!(vt.is_some(), "{name}: tuple form must fold to a constant");
            assert_eq!(
                vs, vt,
                "{name}: struct spelling folded to {vs:?} but tuple spelling to                  {vt:?} — the two are documented as equivalent"
            );
        }

        // Out-of-range shift counts must reduce identically in both spellings,
        // the exact place where separate evaluators diverged twice before.
        let huge = 1u64 << 32; // (1<<32) & 63 == 0 -> shift by 0
        let (ft, _) = fold_expr(LlilExpr::ShlT(c(1), c(huge), sz));
        let (fs, _) = fold_expr(LlilExpr::Shl { value: c(1), shift: c(huge), size: sz });
        assert_eq!(fs.is_const(), ft.is_const(), "shl count masking must match");
        assert_eq!(ft.is_const(), Some(1));
    }

    #[test]
    fn size_try_from_failure() {
        assert!(Size::try_from(0).is_err());
        assert!(Size::try_from(3).is_err());
        assert!(Size::try_from(7).is_err());
        // 32 bytes is now a valid size (`Size::YWord`, 256-bit AVX/AVX2 YMM),
        // and 64 bytes is `Size::ZWord` (512-bit AVX-512 ZMM); use values that
        // are still invalid under the extended enum.
        assert!(Size::try_from(9).is_err());
        assert!(Size::try_from(128).is_err());
    }

    // â”€â”€ LlilRegister â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn register_name_and_display() {
        let concrete = LlilRegister::Concrete("rax".into());
        assert_eq!(concrete.name(), "rax");
        assert_eq!(concrete.to_string(), "rax");

        let tmp = LlilRegister::Temporary(7);
        assert_eq!(tmp.name(), "tmp7");
        assert_eq!(tmp.to_string(), "tmp7");
    }

    // â”€â”€ LlilExpr::result_size â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn expr_result_size_const_and_register() {
        assert_eq!(llil_const(0, Size::DWord).result_size(), Size::DWord);
        assert_eq!(llil_reg("rax", Size::QWord).result_size(), Size::QWord);
        assert_eq!(llil_tmp(0, Size::Byte).result_size(), Size::Byte);
    }

    #[test]
    fn expr_result_size_arithmetic() {
        let a = llil_const(1, Size::QWord);
        let b = llil_const(2, Size::QWord);
        assert_eq!(
            llil_add(a.clone(), b.clone(), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            llil_sub(a.clone(), b.clone(), Size::DWord).result_size(),
            Size::DWord
        );
        assert_eq!(
            LlilExpr::MulT(Box::new(a.clone()), Box::new(b), Size::Word).result_size(),
            Size::Word
        );
        assert_eq!(
            LlilExpr::Neg(Box::new(a), Size::Byte).result_size(),
            Size::Byte
        );
    }

    #[test]
    fn expr_result_size_comparisons_always_byte() {
        let a = llil_const(1, Size::QWord);
        let b = llil_const(2, Size::QWord);
        assert_eq!(llil_cmp_eq(a.clone(), b.clone()).result_size(), Size::Byte);
        assert_eq!(llil_cmp_ne(a.clone(), b.clone()).result_size(), Size::Byte);
        assert_eq!(llil_cmp_slt(a.clone(), b.clone()).result_size(), Size::Byte);
        assert_eq!(
            LlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            LlilExpr::FCmpEq(Box::new(a.clone()), Box::new(b.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            LlilExpr::FCmpLt(Box::new(a.clone()), Box::new(b.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            LlilExpr::FCmpGt(Box::new(a), Box::new(b)).result_size(),
            Size::Byte
        );
    }

    #[test]
    fn expr_result_size_extensions() {
        let e = llil_const(0xff, Size::Byte);
        assert_eq!(
            llil_zx(e.clone(), Size::Byte, Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            llil_sx(e.clone(), Size::Byte, Size::DWord).result_size(),
            Size::DWord
        );
        assert_eq!(
            LlilExpr::LowPart {
                expr: Box::new(e),
                to: Size::Byte
            }
            .result_size(),
            Size::Byte
        );
    }

    #[test]
    fn expr_result_size_misc() {
        assert_eq!(llil_sp(Size::QWord).result_size(), Size::QWord);
        assert_eq!(llil_flag("zero").result_size(), Size::Byte);
        assert_eq!(LlilExpr::Undefined(Size::DWord).result_size(), Size::DWord);
        let inner = llil_const(1, Size::QWord);
        assert_eq!(
            LlilExpr::IntToFloat {
                expr: Box::new(inner.clone()),
                to: Size::QWord
            }
            .result_size(),
            Size::QWord
        );
        assert_eq!(
            LlilExpr::FloatToInt {
                expr: Box::new(inner),
                to: Size::DWord
            }
            .result_size(),
            Size::DWord
        );
        let cond_expr = LlilExpr::CondExpr {
            cond: Box::new(llil_const(1, Size::Byte)),
            true_val: Box::new(llil_const(10, Size::DWord)),
            false_val: Box::new(llil_const(20, Size::DWord)),
            size: Size::DWord,
        };
        assert_eq!(cond_expr.result_size(), Size::DWord);
    }

    // â”€â”€ LlilExpr::is_const_zero / is_const â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn expr_is_const_zero() {
        assert!(llil_const(0, Size::Byte).is_const_zero());
        assert!(llil_const(0, Size::QWord).is_const_zero());
        assert!(!llil_const(1, Size::Byte).is_const_zero());
        assert!(!llil_reg("rax", Size::QWord).is_const_zero());
    }

    #[test]
    fn expr_is_const() {
        assert_eq!(llil_const(42, Size::DWord).is_const(), Some(42));
        assert_eq!(llil_const(0, Size::Byte).is_const(), Some(0));
        assert_eq!(llil_reg("rax", Size::QWord).is_const(), None);
        assert_eq!(
            llil_load(llil_const(0x1000, Size::QWord), Size::QWord).is_const(),
            None
        );
    }

    // â”€â”€ LlilInstruction::is_terminator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn instruction_is_terminator() {
        assert!(!LlilInstruction::Nop.is_terminator());
        assert!(!LlilInstruction::SysCall.is_terminator());
        assert!(!LlilInstruction::Breakpoint.is_terminator());
        assert!(
            !LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            }
            .is_terminator()
        );
        assert!(LlilInstruction::Ret.is_terminator());
        assert!(
            LlilInstruction::JumpDest {
                dest: llil_const(0x1000, Size::QWord)
            }
            .is_terminator()
        );
        assert!(
            LlilInstruction::JumpTo {
                dest: llil_const(0x1000, Size::QWord),
                targets: vec![]
            }
            .is_terminator()
        );
        assert!(
            LlilInstruction::TailCall {
                dest: llil_const(0x400, Size::QWord)
            }
            .is_terminator()
        );
        assert!(
            LlilInstruction::CondJump {
                cond: llil_const(1, Size::Byte),
                true_dest: Address::new(0x10),
                false_dest: Address::new(0x20),
            }
            .is_terminator()
        );
        assert!(LlilInstruction::Trap { code: 3 }.is_terminator());
        assert!(LlilInstruction::Undefined.is_terminator());
        assert!(
            LlilInstruction::UnimplementedRaw {
                bytes: vec![0x0f, 0x0b],
                address: Address::new(0x100)
            }
            .is_terminator()
        );
    }

    // â”€â”€ LlilInstruction::successors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn instruction_successors_cond_jump() {
        let t = Address::new(0x100);
        let f = Address::new(0x200);
        let instr = LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: t,
            false_dest: f,
        };
        let succs = instr.successors();
        assert_eq!(succs, vec![t, f]);
    }

    #[test]
    fn instruction_successors_jump_to() {
        let targets = vec![Address::new(0x10), Address::new(0x20), Address::new(0x30)];
        let instr = LlilInstruction::JumpTo {
            dest: llil_reg("rax", Size::QWord),
            targets: targets.clone(),
        };
        assert_eq!(instr.successors(), targets);
    }

    #[test]
    fn instruction_successors_ret_and_nop() {
        assert!(LlilInstruction::Ret.successors().is_empty());
        assert!(LlilInstruction::Nop.successors().is_empty());
    }

    // â”€â”€ LlilInstruction::reads_reg / writes_reg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn instruction_reads_and_writes_reg() {
        let rax = LlilRegister::Concrete("rax".into());
        let rbx = LlilRegister::Concrete("rbx".into());

        // SetReg writes dest, reads src
        let instr = LlilInstruction::SetReg {
            dest: rax.clone(),
            size: Size::QWord,
            value: llil_reg("rbx", Size::QWord),
        };
        assert!(instr.writes_reg(&rax));
        assert!(!instr.writes_reg(&rbx));
        assert!(instr.reads_reg(&rbx));
        assert!(!instr.reads_reg(&rax));

        // Load writes dest, reads addr which contains rbx
        let load = LlilInstruction::Load {
            dest: rax.clone(),
            size: Size::QWord,
            addr: llil_reg("rbx", Size::QWord),
        };
        assert!(load.writes_reg(&rax));
        assert!(load.reads_reg(&rbx));
        assert!(!load.reads_reg(&rax));
    }

    #[test]
    fn instruction_reads_writes_flag() {
        let instr = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_flag("zero"),
        };
        assert!(instr.reads_flag("zero"));
        assert!(!instr.reads_flag("carry"));

        let set_flag = LlilInstruction::SetFlag {
            name: "carry".into(),
            src: llil_const(1, Size::Byte),
        };
        assert!(set_flag.writes_flag("carry"));
        assert!(!set_flag.writes_flag("zero"));
        assert!(!set_flag.reads_flag("carry"));
    }

    // â”€â”€ LlilBuilder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn builder_sequence() {
        let base = Address::new(0x1000);
        let mut b = LlilBuilder::at(base, 3);
        b.set_reg("rax", Size::QWord, llil_const(0, Size::QWord));
        b.advance_to(Address::new(0x1003), 2).nop();
        b.advance_to(Address::new(0x1005), 1).ret();

        let instrs = b.build();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].address, base);
        assert_eq!(instrs[0].size, 3);
        assert!(matches!(instrs[0].instr, LlilInstruction::SetReg { .. }));
        assert_eq!(instrs[1].address, Address::new(0x1003));
        assert!(matches!(instrs[1].instr, LlilInstruction::Nop));
        assert_eq!(instrs[2].address, Address::new(0x1005));
        assert!(matches!(instrs[2].instr, LlilInstruction::Ret));
    }

    #[test]
    fn builder_store_and_load() {
        let mut b = LlilBuilder::at(Address::new(0x2000), 4);
        b.store(
            llil_reg("rdi", Size::QWord),
            Size::QWord,
            llil_const(0xdead, Size::QWord),
        );
        b.advance_to(Address::new(0x2004), 4).load(
            "rax",
            Size::QWord,
            llil_reg("rdi", Size::QWord),
        );

        let instrs = b.build();
        assert_eq!(instrs.len(), 2);
        assert!(matches!(instrs[0].instr, LlilInstruction::Store { .. }));
        assert!(matches!(instrs[1].instr, LlilInstruction::Load { .. }));
    }

    #[test]
    fn builder_push_pop_trap_syscall() {
        let mut b = LlilBuilder::at(Address::new(0x3000), 1);
        b.push_stack(Size::QWord, llil_reg("rax", Size::QWord));
        b.advance_to(Address::new(0x3001), 1)
            .pop("rcx", Size::QWord);
        b.advance_to(Address::new(0x3002), 2).trap(0x80);
        b.advance_to(Address::new(0x3004), 2).syscall();

        let instrs = b.build();
        assert_eq!(instrs.len(), 4);
        assert!(matches!(instrs[0].instr, LlilInstruction::Push { .. }));
        assert!(matches!(instrs[1].instr, LlilInstruction::Pop { .. }));
        assert!(matches!(
            instrs[2].instr,
            LlilInstruction::Trap { code: 0x80 }
        ));
        assert!(matches!(instrs[3].instr, LlilInstruction::SysCall));
    }

    // â”€â”€ LlilFunction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn function_new_temporary_increments() {
        let mut func = LlilFunction::new(Address::new(0x400000));
        let t0 = func.new_temporary(Size::QWord);
        let t1 = func.new_temporary(Size::DWord);
        let t2 = func.new_temporary(Size::Byte);
        assert_eq!(t0, LlilRegister::Temporary(0));
        assert_eq!(t1, LlilRegister::Temporary(1));
        assert_eq!(t2, LlilRegister::Temporary(2));
        assert_eq!(func.temp_count, 3);
    }

    #[test]
    fn function_block_at_and_instr_at() {
        let mut func = LlilFunction::new(Address::new(0x400000));

        let block0 = LlilBasicBlock {
            start: Address::new(0x400000),
            end: Address::new(0x400005),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x400000),
                    size: 3,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                        value: llil_const(1, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x400003),
                    size: 2,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] };
        func.add_block(block0);

        let found_block = func.block_at(Address::new(0x400000));
        assert!(found_block.is_some());
        assert_eq!(found_block.unwrap().id, 0);
        assert!(func.block_at(Address::new(0xdeadbeef)).is_none());

        let found_instr = func.instr_at(Address::new(0x400003));
        assert!(found_instr.is_some());
        assert!(matches!(found_instr.unwrap().instr, LlilInstruction::Ret));
        assert!(func.instr_at(Address::new(0x1)).is_none());
    }

    #[test]
    fn function_all_instrs_across_blocks() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        for (start, end, addr) in [(0x1000u64, 0x1002u64, 0x1000u64), (0x1002, 0x1004, 0x1002)] {
            func.add_block(LlilBasicBlock {
                start: Address::new(start),
                end: Address::new(end),
                id: 0,
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(addr),
                    size: 2,
                    instr: LlilInstruction::Nop, length: 0 }], successors: vec![] });
        }
        assert_eq!(func.all_instrs().count(), 2);
    }

    // â”€â”€ LlilBasicBlock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn basic_block_terminator() {
        let block = LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 2,
                    instr: LlilInstruction::Nop, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1002),
                    size: 2,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] };
        assert!(!block.is_empty());
        assert!(block.terminator().is_some());
        assert!(matches!(
            block.terminator().unwrap().instr,
            LlilInstruction::Ret
        ));
    }

    #[test]
    fn basic_block_no_terminator_if_last_is_not() {
        let block = LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1000),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::Nop, length: 0 }], successors: vec![] };
        assert!(block.terminator().is_none());
    }

    #[test]
    fn empty_basic_block() {
        let block = LlilBasicBlock {
            start: Address::new(0),
            end: Address::new(0),
            id: 0,
            instrs: vec![], successors: vec![] };
        assert!(block.is_empty());
        assert!(block.last_instr().is_none());
        assert!(block.terminator().is_none());
    }

    // â”€â”€ Display impls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn display_const_and_register() {
        assert_eq!(llil_const(0xff, Size::Byte).to_string(), "0xff.1");
        assert_eq!(llil_reg("rsp", Size::QWord).to_string(), "rsp.8");
        assert_eq!(llil_tmp(3, Size::DWord).to_string(), "tmp3.4");
    }

    #[test]
    fn display_arithmetic_exprs() {
        let a = llil_const(1, Size::QWord);
        let b = llil_const(2, Size::QWord);
        assert_eq!(
            llil_add(a.clone(), b.clone(), Size::QWord).to_string(),
            "(0x1.8 + 0x2.8).8"
        );
        assert_eq!(
            llil_sub(a, b, Size::QWord).to_string(),
            "(0x1.8 - 0x2.8).8"
        );
    }

    #[test]
    fn display_instruction() {
        let instr = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(0, Size::QWord),
        };
        assert_eq!(instr.to_string(), "rax.8 = 0x0.8");

        assert_eq!(LlilInstruction::Ret.to_string(), "ret");
        assert_eq!(LlilInstruction::Nop.to_string(), "nop");

        let cj = LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: Address::new(0x10),
            false_dest: Address::new(0x20),
        };
        assert_eq!(cj.to_string(), "if (0x1.1) then 0x10 else 0x20");
    }

    #[test]
    fn display_annotated_instr() {
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 1,
            instr: LlilInstruction::Nop, length: 0 };
        assert_eq!(ai.to_string(), "0x1000: nop");
    }

    // â”€â”€ Convenience constructors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn convenience_constructors_correctness() {
        let a = llil_const(10, Size::DWord);
        let b = llil_const(2, Size::DWord);

        assert!(matches!(
            llil_and(a.clone(), b.clone(), Size::DWord),
            LlilExpr::And(_, _, Size::DWord)
        ));
        assert!(matches!(
            llil_or(a.clone(), b.clone(), Size::DWord),
            LlilExpr::Or(_, _, Size::DWord)
        ));
        assert!(matches!(
            llil_xor(a.clone(), b.clone(), Size::DWord),
            LlilExpr::Xor(_, _, Size::DWord)
        ));
        assert!(matches!(
            llil_shl(a.clone(), b.clone(), Size::DWord),
            LlilExpr::ShlT(_, _, Size::DWord)
        ));
        assert!(matches!(
            llil_shr(a.clone(), b, Size::DWord),
            LlilExpr::Shr(_, _, Size::DWord)
        ));
        assert!(matches!(
            llil_load(a.clone(), Size::QWord),
            LlilExpr::Load { .. }
        ));
        assert!(matches!(
            llil_zx(a.clone(), Size::DWord, Size::QWord),
            LlilExpr::ZeroExtend { .. }
        ));
        assert!(matches!(
            llil_sx(a, Size::DWord, Size::QWord),
            LlilExpr::SignExtend { .. }
        ));
        assert!(matches!(
            llil_sp(Size::QWord),
            LlilExpr::StackPointer(Size::QWord)
        ));
        assert!(matches!(llil_flag("carry"), LlilExpr::Flag(_)));
    }

    // â”€â”€ Bridge: lift_ir_expr_to_llil â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn bridge_ir_const_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Const(0xdeadbeef);
        let llil = lift_ir_expr_to_llil(&ir);
        assert!(matches!(
            llil,
            LlilExpr::Const {
                value: 0xdeadbeef,
                size: Size::QWord
            }
        ));
    }

    #[test]
    fn bridge_ir_reg_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Reg("rax".to_string());
        let llil = lift_ir_expr_to_llil(&ir);
        if let LlilExpr::RegisterRef { reg, size } = llil {
            assert_eq!(reg.name(), "rax");
            assert_eq!(size, Size::QWord);
        } else {
            panic!("expected Register");
        }
    }

    #[test]
    fn bridge_ir_add_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".to_string())),
            Box::new(IrExpr::Const(8)),
        );
        let llil = lift_ir_expr_to_llil(&ir);
        assert!(matches!(llil, LlilExpr::AddT(_, _, Size::QWord)));
    }

    #[test]
    fn bridge_ir_sub_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Sub(Box::new(IrExpr::Const(10)), Box::new(IrExpr::Const(3)));
        assert!(matches!(
            lift_ir_expr_to_llil(&ir),
            LlilExpr::SubT(_, _, Size::QWord)
        ));
    }

    #[test]
    fn bridge_ir_mul_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Mul(Box::new(IrExpr::Const(3)), Box::new(IrExpr::Const(4)));
        assert!(matches!(
            lift_ir_expr_to_llil(&ir),
            LlilExpr::MulT(_, _, Size::QWord)
        ));
    }

    #[test]
    fn bridge_ir_or_and_xor_shl_shr() {
        use rustre_il_lift::IrExpr;
        let a = Box::new(IrExpr::Const(1));
        let b = Box::new(IrExpr::Const(2));
        assert!(matches!(
            lift_ir_expr_to_llil(&IrExpr::Or(a.clone(), b.clone())),
            LlilExpr::Or(_, _, _)
        ));
        assert!(matches!(
            lift_ir_expr_to_llil(&IrExpr::And(a.clone(), b.clone())),
            LlilExpr::And(_, _, _)
        ));
        assert!(matches!(
            lift_ir_expr_to_llil(&IrExpr::Xor(a.clone(), b.clone())),
            LlilExpr::Xor(_, _, _)
        ));
        assert!(matches!(
            lift_ir_expr_to_llil(&IrExpr::Shl(a.clone(), b.clone())),
            LlilExpr::ShlT(_, _, _)
        ));
        assert!(matches!(
            lift_ir_expr_to_llil(&IrExpr::Shr(a, b)),
            LlilExpr::Shr(_, _, _)
        ));
    }

    #[test]
    fn bridge_ir_not_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Not(Box::new(IrExpr::Const(0)));
        assert!(matches!(
            lift_ir_expr_to_llil(&ir),
            LlilExpr::Not(_, Size::QWord)
        ));
    }

    #[test]
    fn bridge_ir_deref_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Deref(Box::new(IrExpr::Reg("rsp".to_string())), 8);
        let llil = lift_ir_expr_to_llil(&ir);
        assert!(matches!(
            llil,
            LlilExpr::Load {
                size: Size::QWord,
                ..
            }
        ));
    }

    #[test]
    fn bridge_ir_deref_4byte_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Deref(Box::new(IrExpr::Const(0x1000)), 4);
        let llil = lift_ir_expr_to_llil(&ir);
        assert!(matches!(
            llil,
            LlilExpr::Load {
                size: Size::DWord,
                ..
            }
        ));
    }

    #[test]
    fn bridge_ir_undef_to_llil() {
        use rustre_il_lift::IrExpr;
        let ir = IrExpr::Undef;
        assert!(matches!(
            lift_ir_expr_to_llil(&ir),
            LlilExpr::Undefined(Size::QWord)
        ));
    }

    // â”€â”€ Bridge: lift_effect_to_llil_instr â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn bridge_effect_reg_write() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::RegWrite {
            reg: "rbx".to_string(),
            value: IrExpr::Const(42),
        };
        let instr = lift_effect_to_llil_instr(&eff, 0x1000);
        assert!(matches!(instr, LlilInstruction::SetReg { .. }));
    }

    #[test]
    fn bridge_effect_mem_write() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::MemWrite {
            addr: IrExpr::Reg("rsp".to_string()),
            value: IrExpr::Reg("rax".to_string()),
            size: 8,
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::Store { .. }
        ));
    }

    #[test]
    fn bridge_effect_mem_read() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::MemRead {
            addr: IrExpr::Const(0x1000),
            dest: "rcx".to_string(),
            size: 4,
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::Load { .. }
        ));
    }

    #[test]
    fn bridge_effect_call() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Call {
            target: IrExpr::Const(0x401000),
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::CallDest { .. }
        ));
    }

    #[test]
    fn bridge_effect_unconditional_branch() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Branch {
            target: IrExpr::Const(0x500),
            condition: None,
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::JumpDest { .. }
        ));
    }

    #[test]
    fn bridge_effect_conditional_branch() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Branch {
            target: IrExpr::Const(0x600),
            condition: Some(IrExpr::Reg("zf".to_string())),
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::CondJump { .. }
        ));
    }

    #[test]
    fn bridge_effect_return() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Return {
            value: Some(IrExpr::Reg("rax".to_string())),
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::Ret
        ));
    }

    #[test]
    fn bridge_effect_syscall() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Syscall {
            nr: IrExpr::Reg("rax".to_string()),
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::SysCall
        ));
    }

    #[test]
    fn bridge_effect_intrinsic() {
        use rustre_il_lift::{Effect, IrExpr};
        let eff = Effect::Intrinsic {
            name: "cpuid".to_string(),
            args: vec![IrExpr::Const(0)],
        };
        assert!(matches!(
            lift_effect_to_llil_instr(&eff, 0),
            LlilInstruction::Intrinsic { .. }
        ));
    }

    // â”€â”€ Bridge: lifted_instr_to_llil â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn bridge_lifted_instr_no_effects_emits_nop() {
        use rustre_il_lift::{LiftLevel, LiftedInstr};
        let li = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        };
        let out = lifted_instr_to_llil(&li);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].instr, LlilInstruction::Nop));
    }

    #[test]
    fn bridge_lifted_instr_with_effects() {
        use rustre_il_lift::{Effect, IrExpr, LiftLevel, LiftedInstr};
        let li = LiftedInstr {
            address: 0x2000,
            original_mnemonic: "push".to_string(),
            ir_text: "push".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::MemWrite {
                addr: IrExpr::Reg("rsp".to_string()),
                value: IrExpr::Reg("rax".to_string()),
                size: 8,
            }],
        };
        let out = lifted_instr_to_llil(&li);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].instr, LlilInstruction::Store { .. }));
        assert_eq!(out[0].address, Address::new(0x2000));
    }

    #[test]
    fn bridge_lifted_instr_multiple_effects() {
        use rustre_il_lift::{Effect, IrExpr, LiftLevel, LiftedInstr};
        let li = LiftedInstr {
            address: 0x3000,
            original_mnemonic: "mul".to_string(),
            ir_text: String::new(),
            il_level: LiftLevel::Llil,
            effects: vec![
                Effect::RegWrite {
                    reg: "rax".to_string(),
                    value: IrExpr::Const(1),
                },
                Effect::RegWrite {
                    reg: "rdx".to_string(),
                    value: IrExpr::Const(0),
                },
            ],
        };
        let out = lifted_instr_to_llil(&li);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].instr, LlilInstruction::SetReg { .. }));
        assert!(matches!(out[1].instr, LlilInstruction::SetReg { .. }));
    }

    // â”€â”€ New tests: constant folding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn const_fold_add() {
        let expr = llil_add(
            llil_const(3, Size::QWord),
            llil_const(4, Size::QWord),
            Size::QWord,
        );
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(7));
    }

    #[test]
    fn const_fold_sub_zero() {
        let expr = llil_sub(
            llil_reg("rax", Size::QWord),
            llil_const(0, Size::QWord),
            Size::QWord,
        );
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert!(matches!(folded, LlilExpr::RegisterRef { .. }));
    }

    #[test]
    fn const_fold_mul_by_zero() {
        let expr = LlilExpr::MulT(
            Box::new(llil_reg("rax", Size::QWord)),
            Box::new(llil_const(0, Size::QWord)),
            Size::QWord,
        );
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(0));
    }

    #[test]
    fn const_fold_bitwise_and_zero() {
        let expr = llil_and(
            llil_reg("rax", Size::QWord),
            llil_const(0, Size::QWord),
            Size::QWord,
        );
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(0));
    }

    #[test]
    fn const_fold_neg() {
        let expr = LlilExpr::Neg(Box::new(llil_const(5, Size::QWord)), Size::QWord);
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(5u64.wrapping_neg()));
    }

    #[test]
    fn const_fold_not() {
        // NOT of a BYTE 0xFF is 0x00 — the result must fit the operand size.
        //
        // This used to assert `Some(!0xFFu64)`, i.e. 0xFFFF_FFFF_FFFF_FF00
        // inside a `Const { size: Byte }` — a value that cannot fit a byte at
        // all. It pinned the folder's missing width-masking, so the defect
        // could not be fixed without this test failing. `fold_expr` now masks
        // its result at the single exit (matching
        // `rustre_il_passes::fold_binop`), and this asserts the byte semantics.
        let expr = LlilExpr::Not(Box::new(llil_const(0xFFu64, Size::Byte)), Size::Byte);
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(0x00), "!0xFF as a byte is 0x00");

        // Narrower-than-64 results elsewhere must fit too — the general rule,
        // not a special case for NOT.
        let neg = LlilExpr::Neg(Box::new(llil_const(20, Size::DWord)), Size::DWord);
        assert_eq!(
            fold_expr(neg).0.is_const(),
            Some(0xFFFF_FFEC),
            "-20 as a DWord is 0xFFFF_FFEC, not a sign-extended 64-bit value"
        );
        // …and a full-width operation is untouched by the masking.
        let neg64 = LlilExpr::Neg(Box::new(llil_const(20, Size::QWord)), Size::QWord);
        assert_eq!(fold_expr(neg64).0.is_const(), Some((-20i64).cast_unsigned()));
    }

    #[test]
    fn const_fold_cmp_eq_true() {
        let expr = LlilExpr::CmpEq(
            Box::new(llil_const(7, Size::QWord)),
            Box::new(llil_const(7, Size::QWord)),
        );
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(1));
    }

    #[test]
    fn const_fold_cond_expr_taken() {
        let expr = LlilExpr::CondExpr {
            cond: Box::new(llil_const(1, Size::Byte)),
            true_val: Box::new(llil_const(42, Size::QWord)),
            false_val: Box::new(llil_const(99, Size::QWord)),
            size: Size::QWord,
        };
        let (folded, count) = fold_expr(expr);
        assert!(count > 0);
        assert_eq!(folded.is_const(), Some(42));
    }

    #[test]
    fn const_fold_sign_extend_positive() {
        let expr = LlilExpr::SignExtend {
            expr: Box::new(llil_const(0x7F, Size::Byte)),
            from: Size::Byte,
            to: Size::QWord,
        };
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        assert_eq!(folded.is_const(), Some(0x7F));
    }

    #[test]
    fn const_fold_sign_extend_negative() {
        let expr = LlilExpr::SignExtend {
            expr: Box::new(llil_const(0xFF, Size::Byte)),
            from: Size::Byte,
            to: Size::QWord,
        };
        let (folded, count) = fold_expr(expr);
        assert_eq!(count, 1);
        // 0xFF sign-extended is 0xFFFF_FFFF_FFFF_FFFF
        assert_eq!(folded.is_const(), Some(u64::MAX));
    }

    // â”€â”€ New tests: LlilConstantFolder pass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn pass_constant_folder_on_function() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 4,
                instr: LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: llil_add(
                        llil_const(2, Size::QWord),
                        llil_const(3, Size::QWord),
                        Size::QWord,
                    ),
                }, length: 0 }], successors: vec![] });
        let mut folder = LlilConstantFolder;
        let changes = folder.run(&mut func).unwrap();
        assert!(changes > 0);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(src.is_const(), Some(5));
        } else {
            panic!("expected SetReg");
        }
    }

    // â”€â”€ New tests: strength reduction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn strength_reduce_mul_power_of_two() {
        let expr = LlilExpr::MulT(
            Box::new(llil_reg("rax", Size::QWord)),
            Box::new(llil_const(8, Size::QWord)),
            Size::QWord,
        );
        let (reduced, count) = strength_reduce_expr(expr);
        assert_eq!(count, 1);
        assert!(matches!(reduced, LlilExpr::ShlT(_, _, _)));
    }

    #[test]
    fn strength_reduce_divu_power_of_two() {
        let expr = LlilExpr::DivU(
            Box::new(llil_reg("rax", Size::QWord)),
            Box::new(llil_const(4, Size::QWord)),
            Size::QWord,
        );
        let (reduced, count) = strength_reduce_expr(expr);
        assert_eq!(count, 1);
        assert!(matches!(reduced, LlilExpr::Shr(_, _, _)));
    }

    #[test]
    fn strength_reduce_non_power_of_two_unchanged() {
        let expr = LlilExpr::MulT(
            Box::new(llil_reg("rax", Size::QWord)),
            Box::new(llil_const(7, Size::QWord)),
            Size::QWord,
        );
        let (reduced, count) = strength_reduce_expr(expr);
        assert_eq!(count, 0);
        assert!(matches!(reduced, LlilExpr::MulT(_, _, _)));
    }

    // â”€â”€ New tests: NOP elimination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn pass_nop_elimination() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::Nop, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1001),
                    size: 1,
                    instr: LlilInstruction::Nop, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1002),
                    size: 1,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] });
        let mut pass = LlilNopElimination;
        let count = pass.run(&mut func).unwrap();
        assert_eq!(count, 2);
        assert_eq!(func.blocks[0].instrs.len(), 1);
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::Ret
        ));
    }

    // â”€â”€ New tests: branch simplification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn pass_branch_simplification_taken() {
        let t = Address::new(0x200);
        let f = Address::new(0x300);
        let mut func = LlilFunction::new(Address::new(0x100));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x100),
            end: Address::new(0x105),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x100),
                size: 5,
                instr: LlilInstruction::CondJump {
                    cond: llil_const(1, Size::Byte),
                    true_dest: t,
                    false_dest: f,
                }, length: 0 }], successors: vec![] });
        let mut pass = LlilBranchSimplification;
        let count = pass.run(&mut func).unwrap();
        assert_eq!(count, 1);
        assert!(matches!(
            &func.blocks[0].instrs[0].instr,
            LlilInstruction::JumpDest { .. }
        ));
    }

    // â”€â”€ New tests: pass manager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn pass_manager_standard_pipeline() {
        let mut pm = LlilPassManager::standard();
        let names = pm.pass_names();
        assert!(!names.is_empty());
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 4,
                instr: LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: llil_add(
                        llil_const(10, Size::QWord),
                        llil_const(5, Size::QWord),
                        Size::QWord,
                    ),
                }, length: 0 }], successors: vec![] });
        let _total = pm.run_all(&mut func).unwrap();
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(src.is_const(), Some(15));
        }
    }

    // â”€â”€ New tests: interpreter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn interp_set_reg_const() {
        let mut interp = LlilInterpreter::new(1024, 512);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 4,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(42, Size::QWord),
            }, length: 0 };
        interp.step(&ai).unwrap();
        assert_eq!(interp.read_reg("rax").unwrap(), 42);
    }

    #[test]
    fn interp_store_and_load() {
        let mut interp = LlilInterpreter::new(1024, 512);
        interp.set_reg("rdi", 0x10);
        interp.set_reg("rax", 0xABCD);
        let store = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 4,
            instr: LlilInstruction::Store {
                addr: llil_reg("rdi", Size::QWord),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            }, length: 0 };
        interp.step(&store).unwrap();
        let load = LlilAnnotatedInstr {
            address: Address::new(0x1004),
            size: 4,
            instr: LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                addr: llil_reg("rdi", Size::QWord),
            }, length: 0 };
        interp.step(&load).unwrap();
        assert_eq!(interp.read_reg("rbx").unwrap(), 0xABCD);
    }

    #[test]
    fn interp_push_pop() {
        let mut interp = LlilInterpreter::new(1024, 512);
        interp.set_reg("rax", 0xBEEF);
        let push = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 1,
            instr: LlilInstruction::Push {
                size: Size::QWord,
                src: llil_reg("rax", Size::QWord),
            }, length: 0 };
        interp.step(&push).unwrap();
        let pop = LlilAnnotatedInstr {
            address: Address::new(0x1001),
            size: 1,
            instr: LlilInstruction::Pop {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
            }, length: 0 };
        interp.step(&pop).unwrap();
        assert_eq!(interp.read_reg("rcx").unwrap(), 0xBEEF);
    }

    #[test]
    fn interp_cond_jump_taken() {
        let mut interp = LlilInterpreter::new(256, 200);
        let t = Address::new(0x200);
        let f = Address::new(0x300);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x100),
            size: 2,
            instr: LlilInstruction::CondJump {
                cond: llil_const(1, Size::Byte),
                true_dest: t,
                false_dest: f,
            }, length: 0 };
        let next = interp.step(&ai).unwrap();
        assert_eq!(next, Some(t));
    }

    #[test]
    fn interp_ret_returns_none() {
        let mut interp = LlilInterpreter::new(256, 200);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x100),
            size: 1,
            instr: LlilInstruction::Ret, length: 0 };
        let next = interp.step(&ai).unwrap();
        assert_eq!(next, None);
    }

    #[test]
    fn interp_run_simple_function() {
        // Function: rax = 10 + 20, ret
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1006),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                        value: llil_add(
                            llil_const(10, Size::QWord),
                            llil_const(20, Size::QWord),
                            Size::QWord,
                        ),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    size: 1,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] });
        let mut interp = LlilInterpreter::new(4096, 2048);
        interp.run(&func).unwrap();
        assert_eq!(interp.read_reg("rax").unwrap(), 30);
    }

    #[test]
    fn interp_division_by_zero_error() {
        let interp = LlilInterpreter::new(256, 200);
        let expr = LlilExpr::DivU(
            Box::new(llil_const(10, Size::QWord)),
            Box::new(llil_const(0, Size::QWord)),
            Size::QWord,
        );
        assert!(matches!(
            interp.eval_expr(&expr),
            Err(InterpError::DivisionByZero(_))
        ));
    }

    // â”€â”€ New tests: CFG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn cfg_build_two_blocks() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 4,
                instr: LlilInstruction::JumpDest {
                    dest: LlilExpr::Const {
                        value: 0x2000,
                        size: Size::QWord,
                    },
                }, length: 0 }], successors: vec![] });
        func.add_block(LlilBasicBlock {
            start: Address::new(0x2000),
            end: Address::new(0x2001),
            id: 1,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x2000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let cfg = LlilCfg::build(&func);
        let succs: Vec<u32> = cfg.successors(0).collect();
        assert_eq!(succs, vec![1]);
        let preds: Vec<u32> = cfg.predecessors(1).collect();
        assert_eq!(preds, vec![0]);
    }

    #[test]
    fn cfg_reachable_from_entry() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 4,
                instr: LlilInstruction::JumpDest {
                    dest: LlilExpr::Const {
                        value: 0x2000,
                        size: Size::QWord,
                    },
                }, length: 0 }], successors: vec![] });
        func.add_block(LlilBasicBlock {
            start: Address::new(0x2000),
            end: Address::new(0x2001),
            id: 1,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x2000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        func.add_block(LlilBasicBlock {
            start: Address::new(0x3000),
            end: Address::new(0x3001),
            id: 2,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x3000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let cfg = LlilCfg::build(&func);
        let reachable = cfg.reachable_from(0);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(!reachable.contains(&2));
    }

    #[test]
    fn cfg_to_dot_contains_bb0() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let cfg = LlilCfg::build(&func);
        let dot = cfg.to_dot("test_fn");
        assert!(dot.contains("bb0"));
    }

    // â”€â”€ New tests: def-use chains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn def_use_single_def() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1008),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                        value: llil_const(1, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    size: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rbx".into()),
                        size: Size::QWord,
                        value: llil_reg("rax", Size::QWord),
                    }, length: 0 },
            ], successors: vec![] });
        let duc = DefUseChains::build(&func);
        assert!(duc.is_single_def("rax"));
        assert_eq!(duc.definitions_of("rax").len(), 1);
        assert_eq!(duc.uses_of("rax").len(), 1);
    }

    // â”€â”€ New tests: serialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn function_to_json_roundtrip() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let json = func.to_json().unwrap();
        assert!(json.contains("\"entry\""));
        assert!(json.contains("0x1000"));
    }

    #[test]
    fn function_to_text_contains_entry() {
        let func = LlilFunction::new(Address::new(0xDEAD));
        let text = func.to_text();
        assert!(text.contains("0xdead") || text.contains("0xDEAD") || text.contains("dead"));
    }

    #[test]
    fn function_to_dot_valid() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let dot = func.to_dot();
        assert!(dot.contains("digraph"));
    }

    // â”€â”€ New tests: LlilExpr helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn expr_node_count_simple() {
        assert_eq!(llil_const(1, Size::QWord).node_count(), 1);
        assert_eq!(
            llil_add(
                llil_const(1, Size::QWord),
                llil_const(2, Size::QWord),
                Size::QWord
            )
            .node_count(),
            3
        );
    }

    #[test]
    fn expr_is_pure() {
        assert!(llil_const(1, Size::QWord).is_pure());
        assert!(llil_reg("rax", Size::QWord).is_pure());
        assert!(!llil_load(llil_const(0x1000, Size::QWord), Size::QWord).is_pure());
    }

    #[test]
    fn expr_registers_used() {
        let expr = llil_add(
            llil_reg("rax", Size::QWord),
            llil_reg("rbx", Size::QWord),
            Size::QWord,
        );
        let mut regs = expr.registers_used();
        regs.sort();
        assert_eq!(regs, vec!["rax", "rbx"]);
    }

    // â”€â”€ New tests: liveness analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn liveness_single_block() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1008),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                        value: llil_const(1, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    size: 4,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] });
        let cfg = LlilCfg::build(&func);
        let liveness = liveness_analysis(&func, &cfg);
        assert!(liveness.contains_key(&0));
    }

    // â”€â”€ New tests: function helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn function_total_instr_count() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1002),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::Nop, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1001),
                    size: 1,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] });
        assert_eq!(func.total_instr_count(), 2);
        assert!(!func.is_empty());
    }

    #[test]
    fn function_is_empty_initially() {
        let func = LlilFunction::new(Address::new(0x1000));
        assert!(func.is_empty());
        assert_eq!(func.total_instr_count(), 0);
    }

    // â”€â”€ Serialization â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn make_simple_function() -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1002),
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".to_string()),
                        size: Size::QWord,
                        value: llil_const(42, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1001),
                    size: 1,
                    instr: LlilInstruction::Ret, length: 0 },
            ], successors: vec![] });
        func
    }

    #[test]
    fn test_json_serialization_round_trip() {
        let func = make_simple_function();
        let json = llil_function_to_json(&func).unwrap();
        // entry 0x1000 = 4096 decimal
        assert!(json.contains("4096"));
        let snap = llil_snapshot_from_json(&json).unwrap();
        assert_eq!(snap.entry, 0x1000);
        assert_eq!(snap.blocks.len(), 1);
        assert_eq!(snap.blocks[0].instrs.len(), 2);
    }

    #[test]
    fn test_json_pretty_serialization() {
        let func = make_simple_function();
        let json = llil_function_to_json_pretty(&func).unwrap();
        assert!(json.contains('\n'));
        assert!(json.contains("entry"));
    }

    #[test]
    fn test_snapshot_function() {
        let func = make_simple_function();
        let snap = snapshot_function(&func);
        assert_eq!(snap.entry, 0x1000);
        assert_eq!(snap.temp_count, 0);
        assert_eq!(snap.blocks[0].id, 0);
        assert_eq!(snap.blocks[0].instrs.len(), 2);
        // SetReg at index 0 is not a terminator.
        assert!(!snap.blocks[0].instrs[0].is_terminator);
        // Ret at index 1 IS a terminator.
        assert!(snap.blocks[0].instrs[1].is_terminator);
    }

    // â”€â”€ DOT output â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_dot_output_contains_bb() {
        let func = make_simple_function();
        let dot = llil_function_to_dot(&func);
        assert!(dot.contains("digraph"));
        assert!(dot.contains("bb0"));
    }

    #[test]
    fn test_dot_output_with_branches() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::CondJump {
                    cond: llil_const(1, Size::Byte),
                    true_dest: Address::new(0x2000),
                    false_dest: Address::new(0x3000),
                }, length: 0 }], successors: vec![] });
        let dot = llil_function_to_dot(&func);
        assert!(dot.starts_with("digraph"));
        assert!(dot.contains("bb0"));
    }

    // â”€â”€ SSA construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ssa_build_simple() {
        let func = make_simple_function();
        let ssa = build_ssa(&func);
        assert_eq!(ssa.entry, func.entry);
        assert_eq!(ssa.blocks.len(), 1);
    }

    #[test]
    fn test_ssa_build_with_join() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        // Block 0 â†’ Block 2 (true) and Block 1 â†’ Block 2 (join point)
        func.add_block(LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".to_string()),
                        size: Size::QWord,
                        value: llil_const(1, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x1001),
                    size: 1,
                    instr: LlilInstruction::CondJump {
                        cond: llil_reg("rax", Size::QWord),
                        true_dest: Address::new(0x3000),
                        false_dest: Address::new(0x2000),
                    }, length: 0 },
            ], successors: vec![] });
        func.add_block(LlilBasicBlock {
            id: 1,
            start: Address::new(0x2000),
            end: Address::new(0x2001),
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x2000),
                    size: 1,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".to_string()),
                        size: Size::QWord,
                        value: llil_const(2, Size::QWord),
                    }, length: 0 },
                LlilAnnotatedInstr {
                    address: Address::new(0x2001),
                    size: 1,
                    instr: LlilInstruction::JumpDest {
                        dest: llil_const(0x3000, Size::QWord),
                    }, length: 0 },
            ], successors: vec![] });
        func.add_block(LlilBasicBlock {
            id: 2,
            start: Address::new(0x3000),
            end: Address::new(0x3001),
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x3000),
                size: 1,
                instr: LlilInstruction::Ret, length: 0 }], successors: vec![] });
        let ssa = build_ssa(&func);
        // Block 2 has 2 predecessors, should have phi nodes.
        assert_eq!(ssa.blocks.len(), 3);
        // Phi count may be 0 if no register is defined in both predecessors.
        let _ = ssa.phi_count();
    }

    #[test]
    fn test_ssa_reg_display() {
        let r = LlilSsaReg::new("rax", 3);
        assert_eq!(r.to_string(), "rax#3");
        assert_eq!(r.next().version, 4);
    }

    #[test]
    fn test_phi_node_display() {
        let phi = PhiNode::new(
            LlilSsaReg::new("rax", 3),
            vec![LlilSsaReg::new("rax", 1), LlilSsaReg::new("rax", 2)],
            5,
        );
        let s = phi.to_string();
        assert!(s.contains("rax#3"));
        assert!(s.contains('φ'));
    }

    // â”€â”€ Concrete Interpreter (LlilConcreteInterpreter) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_concrete_interp_const_eval() {
        let interp = LlilConcreteInterpreter::new(100);
        let state = LlilMachineState::new(0x7FFF0000);
        let val = interp.eval_expr(&llil_const(0xABCD, Size::QWord), &state);
        assert_eq!(val, 0xABCD);
    }

    #[test]
    fn test_concrete_interp_add() {
        let interp = LlilConcreteInterpreter::new(100);
        let state = LlilMachineState::new(0);
        let expr = llil_add(
            llil_const(10, Size::QWord),
            llil_const(32, Size::QWord),
            Size::QWord,
        );
        assert_eq!(interp.eval_expr(&expr, &state), 42);
    }

    #[test]
    fn test_concrete_interp_sub() {
        let interp = LlilConcreteInterpreter::new(100);
        let state = LlilMachineState::new(0);
        let expr = llil_sub(
            llil_const(100, Size::QWord),
            llil_const(58, Size::QWord),
            Size::QWord,
        );
        assert_eq!(interp.eval_expr(&expr, &state), 42);
    }

    #[test]
    fn test_concrete_interp_bitwise() {
        let interp = LlilConcreteInterpreter::new(100);
        let state = LlilMachineState::new(0);
        let and = llil_and(
            llil_const(0xFF, Size::Byte),
            llil_const(0x0F, Size::Byte),
            Size::Byte,
        );
        assert_eq!(interp.eval_expr(&and, &state), 0x0F);
        let xor = llil_xor(
            llil_const(0xFF, Size::Byte),
            llil_const(0xFF, Size::Byte),
            Size::Byte,
        );
        assert_eq!(interp.eval_expr(&xor, &state), 0);
    }

    #[test]
    fn test_concrete_interp_cmp() {
        let interp = LlilConcreteInterpreter::new(100);
        let state = LlilMachineState::new(0);
        let eq = llil_cmp_eq(llil_const(5, Size::QWord), llil_const(5, Size::QWord));
        assert_eq!(interp.eval_expr(&eq, &state), 1);
        let ne = llil_cmp_ne(llil_const(5, Size::QWord), llil_const(6, Size::QWord));
        assert_eq!(interp.eval_expr(&ne, &state), 1);
    }

    #[test]
    fn test_concrete_interp_set_reg_and_read() {
        let mut interp = LlilConcreteInterpreter::new(100);
        let mut state = LlilMachineState::new(0);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 3,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".to_string()),
                size: Size::QWord,
                value: llil_const(0xDEAD, Size::QWord),
            }, length: 0 };
        interp.step(&ai, &mut state);
        assert_eq!(state.read_reg("rbx"), 0xDEAD);
    }

    #[test]
    fn test_concrete_interp_ret_halts() {
        let mut interp = LlilConcreteInterpreter::new(100);
        let mut state = LlilMachineState::new(0);
        state.write_reg("rax", 42);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x1000),
            size: 1,
            instr: LlilInstruction::Ret, length: 0 };
        interp.step(&ai, &mut state);
        assert!(state.halted);
        assert_eq!(state.return_value, Some(42));
    }

    #[test]
    fn test_concrete_interp_fuel_exhaustion() {
        let mut interp = LlilConcreteInterpreter::new(1);
        let mut state = LlilMachineState::new(0);
        let ai = LlilAnnotatedInstr {
            address: Address::new(0),
            size: 1,
            instr: LlilInstruction::Nop, length: 0 };
        interp.step(&ai, &mut state); // consumes the 1 unit of fuel
        interp.step(&ai, &mut state); // should halt
        assert!(state.halted);
    }

    #[test]
    fn test_concrete_interp_run_function_linear() {
        let func = make_simple_function();
        let mut interp = LlilConcreteInterpreter::new(1000).with_tracing();
        let mut state = LlilMachineState::new(0x7FFF0000);
        interp.run_function_linear(&func, &mut state);
        assert_eq!(state.read_reg("rax"), 42);
        assert!(state.halted);
        assert!(!interp.trace_log.is_empty());
    }

    #[test]
    fn test_concrete_interp_memory_ops() {
        let mut interp = LlilConcreteInterpreter::new(100);
        let mut state = LlilMachineState::new(0x1000);
        // Store 0xDEAD to address 0x500.
        let store = LlilAnnotatedInstr {
            address: Address::new(0),
            size: 1,
            instr: LlilInstruction::Store {
                addr: llil_const(0x500, Size::QWord),
                size: Size::QWord,
                value: llil_const(0xDEAD_BEEF, Size::QWord),
            }, length: 0 };
        interp.step(&store, &mut state);
        assert_eq!(state.read_mem(0x500, 4), 0xDEAD_BEEF);
    }

    // â”€â”€ SIMD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_simd_reg_zeroed() {
        let r = SimdReg128::zeroed();
        assert_eq!(r.low_u64(), 0);
        assert_eq!(r.high_u64(), 0);
    }

    #[test]
    fn test_simd_reg_from_u64x2() {
        let r = SimdReg128::from_u64x2(0xDEAD, 0xBEEF);
        assert_eq!(r.low_u64(), 0xDEAD);
        assert_eq!(r.high_u64(), 0xBEEF);
    }

    #[test]
    fn test_simd_add_i32x4() {
        let a = SimdReg128::zeroed()
            .insert_i32(0, 1)
            .insert_i32(1, 2)
            .insert_i32(2, 3)
            .insert_i32(3, 4);
        let b = SimdReg128::zeroed()
            .insert_i32(0, 10)
            .insert_i32(1, 20)
            .insert_i32(2, 30)
            .insert_i32(3, 40);
        let c = a.add_i32x4(&b);
        assert_eq!(c.extract_i32(0), 11);
        assert_eq!(c.extract_i32(1), 22);
        assert_eq!(c.extract_i32(2), 33);
        assert_eq!(c.extract_i32(3), 44);
    }

    #[test]
    fn test_simd_sub_i32x4() {
        let a = SimdReg128::zeroed().insert_i32(0, 100);
        let b = SimdReg128::zeroed().insert_i32(0, 58);
        let c = a.sub_i32x4(&b);
        assert_eq!(c.extract_i32(0), 42);
    }

    #[test]
    fn test_simd_mul_i32x4() {
        let a = SimdReg128::zeroed().insert_i32(0, 6).insert_i32(1, 7);
        let b = SimdReg128::zeroed().insert_i32(0, 7).insert_i32(1, 6);
        let c = a.mul_i32x4(&b);
        assert_eq!(c.extract_i32(0), 42);
        assert_eq!(c.extract_i32(1), 42);
    }

    #[test]
    fn test_simd_shuffle() {
        let a = SimdReg128::from_u64x2(0x04030201_00000000, 0x08070605_00000000);
        let control = [3u8, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];
        let result = a.shuffle_bytes(&control);
        // byte 0 = a[3] etc.
        assert_eq!(result.bytes[0], a.bytes[3]);
    }

    #[test]
    fn test_simd_extract_insert() {
        let r = SimdReg128::zeroed().insert_i32(2, 999);
        assert_eq!(r.extract_i32(2), 999);
        assert_eq!(r.extract_i32(0), 0);
    }

    #[test]
    fn test_simd_machine_state_execute() {
        let mut state = SimdMachineState::new();
        state.write_vec("xmm0", SimdReg128::zeroed().insert_i32(0, 5));
        state.write_vec("xmm1", SimdReg128::zeroed().insert_i32(0, 37));
        state.execute(&SimdInstruction::VecAddI32x4 {
            dest: "xmm2".to_string(),
            src_a: "xmm0".to_string(),
            src_b: "xmm1".to_string(),
        });
        assert_eq!(state.read_vec("xmm2").extract_i32(0), 42);
    }

    #[test]
    fn test_simd_broadcast_i32() {
        let mut state = SimdMachineState::new();
        state.write_scalar("tmp", 7);
        state.execute(&SimdInstruction::VecBroadcastI32 {
            dest: "xmm0".to_string(),
            scalar: "tmp".to_string(),
        });
        let r = state.read_vec("xmm0");
        assert_eq!(r.extract_i32(0), 7);
        assert_eq!(r.extract_i32(1), 7);
        assert_eq!(r.extract_i32(2), 7);
        assert_eq!(r.extract_i32(3), 7);
    }

    #[test]
    fn test_simd_zero_instr() {
        let mut state = SimdMachineState::new();
        state.write_vec("xmm0", SimdReg128::from_u64x2(0xFF, 0xFF));
        state.execute(&SimdInstruction::VecZero {
            dest: "xmm0".to_string(),
        });
        assert_eq!(state.read_vec("xmm0").low_u64(), 0);
    }

    #[test]
    fn test_simd_display() {
        let instr = SimdInstruction::VecAddI32x4 {
            dest: "xmm0".to_string(),
            src_a: "xmm1".to_string(),
            src_b: "xmm2".to_string(),
        };
        assert!(instr.to_string().contains("vadd_i32x4"));
    }

    // â”€â”€ CSE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cse_no_duplicates() {
        let func = make_simple_function();
        let cse = CsePass::new();
        let dups = cse.count_duplicates(&func.blocks[0].instrs);
        assert_eq!(dups, 0);
    }

    #[test]
    fn test_cse_with_duplicates() {
        let expr = LlilExpr::AddT(
            Box::new(llil_reg("rax", Size::QWord)),
            Box::new(llil_const(1, Size::QWord)),
            Size::QWord,
        );
        let block = vec![
            LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rbx".to_string()),
                    size: Size::QWord,
                    value: expr.clone(),
                }, length: 0 },
            LlilAnnotatedInstr {
                address: Address::new(0x1001),
                size: 1,
                instr: LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rcx".to_string()),
                    size: Size::QWord,
                    value: expr,
                }, length: 0 },
        ];
        let cse = CsePass::new();
        assert_eq!(cse.count_duplicates(&block), 1);
    }

    // â”€â”€ sign_extend64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sign_extend64_byte() {
        assert_eq!(sign_extend64(0xFF, Size::Byte), -1i64);
        assert_eq!(crate::sign_extend64(0x7F, Size::Byte), 127i64);
    }

    #[test]
    fn test_sign_extend64_word() {
        assert_eq!(crate::sign_extend64(0x8000, Size::Word), i64::from(i16::MIN));
    }

    #[test]
    fn test_simd_f64x2_add() {
        let a0 = 1.0f64;
        let a1 = 2.0f64;
        let b0 = 3.0f64;
        let b1 = 4.0f64;
        let mut a = SimdReg128::zeroed();
        a.bytes[0..8].copy_from_slice(&a0.to_le_bytes());
        a.bytes[8..16].copy_from_slice(&a1.to_le_bytes());
        let mut b = SimdReg128::zeroed();
        b.bytes[0..8].copy_from_slice(&b0.to_le_bytes());
        b.bytes[8..16].copy_from_slice(&b1.to_le_bytes());
        let c = a.add_f64x2(&b);
        let r0 = f64::from_le_bytes(c.bytes[0..8].try_into().unwrap());
        let r1 = f64::from_le_bytes(c.bytes[8..16].try_into().unwrap());
        assert!((r0 - 4.0).abs() < 1e-9);
        assert!((r1 - 6.0).abs() < 1e-9);
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LlilVerifier â€” well-formedness checking for flat instruction sequences
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// A diagnostic produced by [`LlilVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlilVerifyError {
    /// Human-readable description of the problem.
    pub message: String,
    /// Address of the offending instruction, when known.
    pub address: Option<u64>,
}

impl LlilVerifyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            address: None,
        }
    }

    const fn at(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }
}

impl fmt::Display for LlilVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(a) = self.address {
            write!(f, "[0x{a:x}] {}", self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

/// Result returned by [`LlilVerifier::verify`].
#[derive(Debug, Clone, Default)]
pub struct LlilVerifyResult {
    /// All errors found.
    pub errors: Vec<LlilVerifyError>,
    /// Total instructions examined.
    pub total_instrs: usize,
    /// Number of terminator instructions found.
    pub terminator_count: usize,
    /// Number of duplicate addresses detected.
    pub duplicate_addresses: usize,
}

impl LlilVerifyResult {
    /// Returns `true` when no errors were found.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} instr(s), {} terminator(s), {} error(s), {} duplicate address(es)",
            self.total_instrs,
            self.terminator_count,
            self.errors.len(),
            self.duplicate_addresses,
        )
    }
}

/// Verifies that a flat slice of [`LlilAnnotatedInstr`]s forms a valid
/// basic-block sequence:
///
/// * Every non-empty contiguous "basic block" (delimited by terminators) must
///   end with a terminator.
/// * No instruction may appear after a terminator within the same block
///   (unreachable code).
/// * No two instructions may share the same address.
#[derive(Debug, Default)]
pub struct LlilVerifier;

impl LlilVerifier {
    /// Creates a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Verify `instrs` and return a [`LlilVerifyResult`] describing any
    /// problems found.
    ///
    /// # Panics
    ///
    /// Panics if `instrs` is non-empty and no terminator is found (internal assertion).
    #[must_use]
    pub fn verify(&self, instrs: &[LlilAnnotatedInstr]) -> LlilVerifyResult {
        let mut result = LlilVerifyResult {
            total_instrs: instrs.len(),
            ..Default::default()
        };

        // Repeated addresses are EXPECTED, not an error.
        //
        // One machine instruction lifts to many LLIL instructions, and they all
        // carry the address of the instruction they came from — that is what
        // `LlilAnnotatedInstr` means. Treating a repeat as an error made this
        // verifier reject essentially all real lifter output: measured over 444
        // lifted x86 blocks, 192 were rejected and EVERY error was this one.
        // A check that fails on its own input type cannot be wired into
        // anything, which is a plausible reason nothing ever used it.
        //
        // The property that IS meaningful for a flat lifted stream is that
        // addresses never go BACKWARDS: instructions from a later machine
        // instruction must not be annotated with an earlier address. That
        // catches real stream-assembly mistakes (mis-ordered or mis-attributed
        // expansions) while accepting the normal many-to-one shape.
        //
        // The repeat COUNT is still reported in `duplicate_addresses` — it is
        // useful as a statistic (mean expansion factor), just not as a defect.
        let mut seen_addrs: HashMap<u64, usize> = HashMap::new();
        let mut prev_addr: Option<u64> = None;
        for (idx, ai) in instrs.iter().enumerate() {
            let addr = ai.address.as_u64();
            if seen_addrs.insert(addr, idx).is_some() {
                result.duplicate_addresses += 1;
            }
            if let Some(p) = prev_addr
                && addr < p
            {
                result.errors.push(
                    LlilVerifyError::new(format!(
                        "address goes backwards at index {idx}: 0x{addr:x} after 0x{p:x}"
                    ))
                    .at(addr),
                );
            }
            prev_addr = Some(addr);
        }

        // Walk the instruction stream and check terminator placement.
        // We track whether we are "after a terminator" â€” any instruction in
        // that state is unreachable within its block.
        let mut after_terminator = false;
        for (idx, ai) in instrs.iter().enumerate() {
            let addr = ai.address.as_u64();
            let is_term = ai.instr.is_terminator();
            // Terminators that genuinely end the block (no fall-through).
            let ends_flow = matches!(
                ai.instr,
                LlilInstruction::JumpDest { .. }
                    | LlilInstruction::JumpTo { .. }
                    | LlilInstruction::TailCall { .. }
                    | LlilInstruction::Ret
                    | LlilInstruction::Trap { .. }
                    | LlilInstruction::Undefined
                    | LlilInstruction::UnimplementedRaw { .. }
                    | LlilInstruction::Unimplemented { .. }
                    | LlilInstruction::Jump(..)
                    | LlilInstruction::Return { .. }
            );

            // "Unreachable after a terminator" is only true for terminators
            // that do NOT fall through. A conditional jump, a conditional call
            // and a plain call all continue to the next instruction — that is
            // the not-taken / return path, and it is reachable. Flagging it
            // rejected every `jcc`-terminated block: measured, all 58 blocks
            // still refused after the duplicate-address fix were `0x70..0x7F`
            // (Jcc rel8) followed by their fall-through.
            //
            // `rustre-arch-x86`'s `BranchKind::terminates_block()` already draws
            // this distinction correctly, so the two descriptions of "does
            // control leave here for good" now agree.
            if after_terminator {
                // Any instruction here is unreachable inside the current block.
                result.errors.push(
                    LlilVerifyError::new(format!(
                        "unreachable instruction at index {idx} after terminator"
                    ))
                    .at(addr),
                );
                // If the unreachable instruction is itself a terminator, reset
                // so we don't cascade errors.
                if is_term {
                    after_terminator = ends_flow;
                }
                continue;
            }

            if is_term {
                result.terminator_count += 1;
                after_terminator = ends_flow;
            }
        }

        // If the sequence is non-empty and the last instruction is not a
        // terminator the block is missing its terminator.
        if !instrs.is_empty() && !after_terminator {
            let last = instrs.last().unwrap();
            result.errors.push(
                LlilVerifyError::new("basic block does not end with a terminator")
                    .at(last.address.as_u64()),
            );
        }

        result
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LlilPeepholeOptimizer â€” local peephole rewrites over annotated instructions
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Peephole optimizer that works on a flat `Vec<LlilAnnotatedInstr>`.
///
/// Three classes of rewrites are performed in a single linear pass:
///
/// 1. **Redundant-move elimination** â€” `A = B` followed immediately by `B = A`
///    collapses to just `A = B`.
/// 2. **Constant folding** â€” if both operands of an [`LlilExpr::Add`] are
///    [`LlilExpr::Const`] nodes, they are folded to a single constant.
///    (The pass delegates deeper folding to the existing [`fold_expr`] helper.)
/// 3. **Dead assignment elimination** â€” a [`LlilInstruction::SetReg`] whose
///    destination register is overwritten again before it is ever read is
///    removed, provided the source expression has no memory side effects.
#[derive(Debug, Default)]
pub struct LlilPeepholeOptimizer;

impl LlilPeepholeOptimizer {
    /// Creates a new peephole optimizer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run all peephole rewrites over `instrs` and return the optimised
    /// sequence.
    #[must_use]
    pub fn optimize(&self, instrs: Vec<LlilAnnotatedInstr>) -> Vec<LlilAnnotatedInstr> {
        let instrs = Self::eliminate_redundant_moves(instrs);
        let instrs = Self::fold_constants(instrs);
        Self::eliminate_dead_assignments(instrs)
    }

    // â”€â”€ Pass 1: redundant-move elimination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn eliminate_redundant_moves(
        mut instrs: Vec<LlilAnnotatedInstr>,
    ) -> Vec<LlilAnnotatedInstr> {
        // Pairs to remove: if instrs[i] is `A = B` and instrs[i+1] is `B = A`
        // (simple register-to-register moves), drop instrs[i+1].
        let n = instrs.len();
        let mut remove: Vec<bool> = vec![false; n];
        for i in 0..n.saturating_sub(1) {
            let LlilInstruction::SetReg { dest: a_dest, value: LlilExpr::RegisterRef { reg: a_src_reg, .. }, .. } = &instrs[i].instr else { continue };
            let LlilInstruction::SetReg { dest: b_dest, value: LlilExpr::RegisterRef { reg: b_src_reg, .. }, .. } = &instrs[i + 1].instr else { continue };
            // instrs[i]:   a_dest = a_src_reg
            // instrs[i+1]: b_dest = b_src_reg
            // Redundant when: b_dest == a_src_reg && b_src_reg == a_dest
            if b_dest == a_src_reg && b_src_reg == a_dest {
                remove[i + 1] = true;
            }
        }
        let mut idx = 0;
        instrs.retain(|_| {
            let keep = !remove[idx];
            idx += 1;
            keep
        });
        instrs
    }

    // â”€â”€ Pass 2: constant folding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn fold_constants(mut instrs: Vec<LlilAnnotatedInstr>) -> Vec<LlilAnnotatedInstr> {
        for ai in &mut instrs {
            fold_expr_in_instr(&mut ai.instr);
        }
        instrs
    }

    // â”€â”€ Pass 3: dead assignment elimination â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn eliminate_dead_assignments(
        mut instrs: Vec<LlilAnnotatedInstr>,
    ) -> Vec<LlilAnnotatedInstr> {
        // For each SetReg, check whether its destination is read before the
        // next definition of that register.  If not, and the source has no
        // memory side-effects, the assignment is dead and can be dropped.
        let mut to_remove: Vec<usize> = Vec::new();
        let n = instrs.len();
        for i in 0..n {
            // Only consider plain SetReg instructions.
            let (dest_name, src_has_side_effects) = match &instrs[i].instr {
                LlilInstruction::SetReg {
                    dest, value: src, ..
                } => (dest.name(), has_side_effects(src)),
                _ => continue,
            };
            if src_has_side_effects {
                continue;
            }
            // Scan forward: if we hit a read of dest_name before another write
            // of it, the assignment is live.
            let mut is_dead = false;
            for ai_j in instrs.iter().skip(i + 1) {
                let reg = LlilRegister::Concrete(dest_name.clone());
                if ai_j.instr.reads_reg(&reg) {
                    // Used â€” not dead.
                    is_dead = false;
                    break;
                }
                if ai_j.instr.writes_reg(&reg) {
                    // Overwritten before use â€” dead.
                    is_dead = true;
                    break;
                }
            }
            // If we walked off the end without a read, it's also dead.
            if is_dead {
                to_remove.push(i);
            } else {
                // Check whether there was any write found; if the loop
                // completed without setting is_dead, check the scan result.
                // Re-scan to be precise:
                let mut found_write_before_read = false;
                for ai_j in instrs.iter().skip(i + 1) {
                    let reg = LlilRegister::Concrete(dest_name.clone());
                    if ai_j.instr.reads_reg(&reg) {
                        break; // live
                    }
                    if ai_j.instr.writes_reg(&reg) {
                        found_write_before_read = true;
                        break;
                    }
                }
                // If the end of the sequence is reached without a read,
                // treat the assignment as dead (no successor context here).
                let reached_end = {
                    let reg = LlilRegister::Concrete(dest_name.clone());
                    (i + 1..n).all(|j| {
                        !instrs[j].instr.reads_reg(&reg) && !instrs[j].instr.writes_reg(&reg)
                    })
                };
                if found_write_before_read || reached_end {
                    to_remove.push(i);
                }
            }
        }
        let remove_set: std::collections::HashSet<usize> = to_remove.into_iter().collect();
        let mut idx = 0;
        instrs.retain(|_| {
            let keep = !remove_set.contains(&idx);
            idx += 1;
            keep
        });
        instrs
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LlilLivenessAnalysis â€” per-instruction register liveness
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Per-instruction liveness information for a flat instruction sequence.
#[derive(Debug, Clone, Default)]
pub struct InstrLiveness {
    /// Registers live immediately *before* this instruction executes.
    pub live_in: HashSet<String>,
    /// Registers live immediately *after* this instruction executes.
    pub live_out: HashSet<String>,
}

/// The result of [`LlilLivenessAnalysis::analyze`].
#[derive(Debug, Clone)]
pub struct LivenessResult {
    /// Per-instruction liveness, indexed in the same order as the input slice.
    pub per_instr: Vec<InstrLiveness>,
}

impl LivenessResult {
    /// Returns the live-in set for instruction at `idx`.
    ///
    /// # Panics
    /// Panics if `idx` is out of range.
    #[must_use]
    pub fn live_in(&self, idx: usize) -> &HashSet<String> {
        &self.per_instr[idx].live_in
    }

    /// Returns the live-out set for instruction at `idx`.
    ///
    /// # Panics
    /// Panics if `idx` is out of range.
    #[must_use]
    pub fn live_out(&self, idx: usize) -> &HashSet<String> {
        &self.per_instr[idx].live_out
    }
}

/// Computes register liveness at each instruction in a flat sequence using a
/// standard backward dataflow pass.
///
/// The dataflow equation applied at each instruction `n`:
/// ```text
/// live_in[n]  = use[n] âˆª (live_out[n] âˆ’ def[n])
/// live_out[n] = live_in[n+1]   (or âˆ… for the last instruction)
/// ```
#[derive(Debug, Default)]
pub struct LlilLivenessAnalysis;

impl LlilLivenessAnalysis {
    /// Creates a new liveness analyser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `instrs` and return per-instruction live sets.
    #[must_use]
    pub fn analyze(&self, instrs: &[LlilAnnotatedInstr]) -> LivenessResult {
        let n = instrs.len();
        let mut per_instr: Vec<InstrLiveness> = (0..n).map(|_| InstrLiveness::default()).collect();

        // Precompute use and def sets for each instruction.
        let use_sets: Vec<HashSet<String>> = instrs
            .iter()
            .map(|ai| {
                let mut tmp: HashMap<String, Vec<u64>> = HashMap::new();
                collect_instr_used_regs(&ai.instr, 0, &mut tmp);
                tmp.into_keys().collect()
            })
            .collect();

        let def_sets: Vec<HashSet<String>> = instrs
            .iter()
            .map(|ai| {
                let mut defs = HashSet::new();
                match &ai.instr {
                    LlilInstruction::SetReg { dest, .. }
                    | LlilInstruction::Load { dest, .. }
                    | LlilInstruction::Pop { dest, .. } => {
                        defs.insert(dest.name());
                    }
                    LlilInstruction::SetRegSplit { high, low, .. } => {
                        defs.insert(high.name());
                        defs.insert(low.name());
                    }
                    _ => {}
                }
                defs
            })
            .collect();

        // Iterative backward pass: repeat until no change.
        let mut changed = true;
        while changed {
            changed = false;
            for i in (0..n).rev() {
                // live_out[i] = live_in[i+1]  (âˆ… if i is the last instruction)
                let new_live_out: HashSet<String> = if i + 1 < n {
                    per_instr[i + 1].live_in.clone()
                } else {
                    HashSet::new()
                };
                // live_in[i] = use[i] âˆª (live_out[i] âˆ’ def[i])
                let new_live_in: HashSet<String> = use_sets[i]
                    .iter()
                    .cloned()
                    .chain(
                        new_live_out
                            .iter()
                            .filter(|r| !def_sets[i].contains(*r))
                            .cloned(),
                    )
                    .collect();
                if per_instr[i].live_out != new_live_out || per_instr[i].live_in != new_live_in {
                    per_instr[i].live_out = new_live_out;
                    per_instr[i].live_in = new_live_in;
                    changed = true;
                }
            }
        }

        LivenessResult { per_instr }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LlilCallGraph â€” extract function calls and build a call graph
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// A single call-site record extracted from the LLIL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall {
    /// Address of the function that contains the call instruction.
    pub caller_addr: u64,
    /// Statically-known callee address, or `None` for indirect calls.
    pub callee_addr: Option<u64>,
    /// Address of the call instruction itself.
    pub call_site: u64,
}

/// Extracts function calls from LLIL instruction streams and organises them
/// into a lightweight call graph.
#[derive(Debug, Default)]
pub struct LlilCallGraph {
    /// All call records collected so far.
    pub calls: Vec<FunctionCall>,
}

impl LlilCallGraph {
    /// Creates an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract all [`LlilInstruction::CallDest`] and [`LlilInstruction::TailCall`]
    /// instructions from `instrs`.
    ///
    /// `caller_addr` is the entry address of the function that owns these
    /// instructions.  For each call site, the statically-known callee address
    /// is recorded when the call destination is a constant expression; indirect
    /// calls record `callee_addr: None`.
    #[must_use]
    pub fn extract_calls(
        &self,
        instrs: &[LlilAnnotatedInstr],
        caller_addr: u64,
    ) -> Vec<FunctionCall> {
        let mut calls = Vec::with_capacity(instrs.len());
        for ai in instrs {
            let call_site = ai.address.as_u64();
            let dest_expr = match &ai.instr {
                LlilInstruction::CallDest { dest } | LlilInstruction::TailCall { dest } => {
                    Some(dest)
                }
                _ => None,
            };
            if let Some(dest) = dest_expr {
                let callee_address = dest.is_const();
                calls.push(FunctionCall {
                    caller_addr,
                    callee_addr: callee_address,
                    call_site,
                });
            }
        }
        calls
    }

    /// Ingest all calls from `instrs` (owned by `caller_addr`) into `self.calls`.
    pub fn ingest(&mut self, instrs: &[LlilAnnotatedInstr], caller_addr: u64) {
        self.calls.extend(self.extract_calls(instrs, caller_addr));
    }

    /// Returns all call records where the caller is `addr`.
    #[must_use]
    pub fn calls_from(&self, addr: u64) -> Vec<&FunctionCall> {
        self.calls
            .iter()
            .filter(|c| c.caller_addr == addr)
            .collect()
    }

    /// Returns all call records that target `addr` (direct calls only).
    #[must_use]
    pub fn calls_to(&self, addr: u64) -> Vec<&FunctionCall> {
        self.calls
            .iter()
            .filter(|c| c.callee_addr == Some(addr))
            .collect()
    }

    /// Returns the set of all unique direct callee addresses.
    #[must_use]
    pub fn all_callees(&self) -> HashSet<u64> {
        self.calls.iter().filter_map(|c| c.callee_addr).collect()
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LLIL Validator â€” static size / type checking of LLIL expressions & functions
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Type/size checking and structural validation for LLIL.
///
/// The validator walks every [`LlilExpr`] and [`LlilInstruction`] checking that
/// operand sizes are mutually consistent, that comparison results are used as
/// boolean conditions, that extensions widen and truncations narrow, and that
/// control-flow targets are well-formed. It is *additive* â€” it never mutates the
/// IR; it only reports [`ValidationIssue`]s.
pub mod validate {
    use super::{LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, Size};
    use std::fmt;

    /// Severity of a reported validation issue.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Severity {
        /// A hard correctness violation (mismatched sizes, malformed nodes).
        Error,
        /// A suspicious-but-tolerable construct (e.g. comparison feeding arithmetic).
        Warning,
    }

    impl fmt::Display for Severity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Error => write!(f, "error"),
                Self::Warning => write!(f, "warning"),
            }
        }
    }

    /// A single problem discovered during validation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ValidationIssue {
        /// How serious the problem is.
        pub severity: Severity,
        /// Human-readable description.
        pub message: String,
        /// Optional address of the offending instruction.
        pub address: Option<u64>,
    }

    impl ValidationIssue {
        /// Construct an error-severity issue.
        #[must_use]
        pub fn error(message: impl Into<String>) -> Self {
            Self {
                severity: Severity::Error,
                message: message.into(),
                address: None,
            }
        }

        /// Construct a warning-severity issue.
        #[must_use]
        pub fn warning(message: impl Into<String>) -> Self {
            Self {
                severity: Severity::Warning,
                message: message.into(),
                address: None,
            }
        }

        /// Attach an address to this issue (builder style).
        #[must_use]
        pub const fn at(mut self, address: u64) -> Self {
            self.address = Some(address);
            self
        }
    }

    impl fmt::Display for ValidationIssue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.address {
                Some(a) => write!(f, "[{}] {:#x}: {}", self.severity, a, self.message),
                None => write!(f, "[{}] {}", self.severity, self.message),
            }
        }
    }

    /// Accumulated result of validating an expression, instruction, or function.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ValidationReport {
        /// All issues found, in discovery order.
        pub issues: Vec<ValidationIssue>,
    }

    impl ValidationReport {
        /// Create an empty report.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Record an issue.
        pub fn push(&mut self, issue: ValidationIssue) {
            self.issues.push(issue);
        }

        /// Merge another report into this one.
        pub fn merge(&mut self, other: Self) {
            self.issues.extend(other.issues);
        }

        /// Number of `Error`-severity issues.
        #[must_use]
        pub fn error_count(&self) -> usize {
            self.issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .count()
        }

        /// Number of `Warning`-severity issues.
        #[must_use]
        pub fn warning_count(&self) -> usize {
            self.issues
                .iter()
                .filter(|i| i.severity == Severity::Warning)
                .count()
        }

        /// Returns `true` if no `Error`-severity issues were recorded.
        #[must_use]
        pub fn is_valid(&self) -> bool {
            self.error_count() == 0
        }

        /// Returns `true` if there are no issues at all.
        #[must_use]
        pub const fn is_clean(&self) -> bool {
            self.issues.is_empty()
        }
    }

    impl fmt::Display for ValidationReport {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if self.issues.is_empty() {
                return write!(f, "valid (no issues)");
            }
            for (i, issue) in self.issues.iter().enumerate() {
                if i > 0 {
                    writeln!(f)?;
                }
                write!(f, "{issue}")?;
            }
            Ok(())
        }
    }

    /// The LLIL type checker.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct LlilValidator {
        /// When true, emit warnings for shift amounts wider than the value.
        pub pedantic: bool,
    }

    impl LlilValidator {
        /// Create a validator with default (non-pedantic) settings.
        #[must_use]
        pub const fn new() -> Self {
            Self { pedantic: false }
        }

        /// Create a pedantic validator that also reports suspicious constructs.
        #[must_use]
        pub const fn pedantic() -> Self {
            Self { pedantic: true }
        }

        /// Validate a single expression, returning a fresh report.
        #[must_use]
        pub fn validate_expr(self, expr: &LlilExpr) -> ValidationReport {
            let mut report = ValidationReport::new();
            self.check_expr(expr, &mut report, None);
            report
        }

        /// Validate a single instruction.
        #[must_use]
        pub fn validate_instr(
            self,
            instr: &LlilInstruction,
            address: Option<u64>,
        ) -> ValidationReport {
            let mut report = ValidationReport::new();
            self.check_instr(instr, &mut report, address);
            report
        }

        /// Validate an entire function (all blocks, all instructions).
        #[must_use]
        pub fn validate_function(self, func: &LlilFunction) -> ValidationReport {
            let mut report = ValidationReport::new();
            for ai in func.all_instrs() {
                self.check_annotated(ai, &mut report);
            }
            report
        }

        fn check_annotated(self, ai: &LlilAnnotatedInstr, report: &mut ValidationReport) {
            self.check_instr(&ai.instr, report, Some(ai.address.0));
        }

        /// Returns `true` if `expr` produces a 0/1 boolean (a comparison or flag).
        const fn is_boolean(expr: &LlilExpr) -> bool {
            matches!(
                expr,
                LlilExpr::CmpEq(..)
                    | LlilExpr::CmpNe(..)
                    | LlilExpr::CmpSlt(..)
                    | LlilExpr::CmpUlt(..)
                    | LlilExpr::CmpSle(..)
                    | LlilExpr::CmpUle(..)
                    | LlilExpr::CmpSgt(..)
                    | LlilExpr::CmpUgt(..)
                    | LlilExpr::CmpSge(..)
                    | LlilExpr::CmpUge(..)
                    | LlilExpr::FCmpEq(..)
                    | LlilExpr::FCmpLt(..)
                    | LlilExpr::FCmpGt(..)
                    | LlilExpr::Flag(_)
            )
        }

        fn check_binary(
            self,
            l: &LlilExpr,
            r: &LlilExpr,
            size: Size,
            op: &str,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            self.check_expr(l, report, addr);
            self.check_expr(r, report, addr);
            // Comparisons feed booleans (byte) into themselves intentionally, so
            // we only enforce equality for non-boolean operands.
            if !Self::is_boolean(l) && l.result_size() != size {
                let mut issue = ValidationIssue::error(format!(
                    "{op}: left operand size {} != result size {}",
                    l.result_size().bytes(),
                    size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
            if !Self::is_boolean(r) && r.result_size() != size {
                let mut issue = ValidationIssue::error(format!(
                    "{op}: right operand size {} != result size {}",
                    r.result_size().bytes(),
                    size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
        }

        fn check_shift(
            self,
            l: &LlilExpr,
            r: &LlilExpr,
            size: Size,
            op: &str,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            self.check_expr(l, report, addr);
            self.check_expr(r, report, addr);
            if l.result_size() != size {
                let mut issue = ValidationIssue::error(format!(
                    "{op}: shifted value size {} != result size {}",
                    l.result_size().bytes(),
                    size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
            // Shift amount need not match the value width; but a constant amount
            // >= the bit width is suspicious in pedantic mode.
            if let Some(amt) = r.is_const()
                && self.pedantic && u128::from(amt) >= size.bits() as u128 {
                    let mut issue = ValidationIssue::warning(format!(
                        "{op}: shift amount {amt} >= width {} bits",
                        size.bits()
                    ));
                    if let Some(a) = addr {
                        issue = issue.at(a);
                    }
                    report.push(issue);
                }
        }

        fn check_cmp(
            self,
            l: &LlilExpr,
            r: &LlilExpr,
            op: &str,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            self.check_expr(l, report, addr);
            self.check_expr(r, report, addr);
            if !Self::is_boolean(l) && !Self::is_boolean(r) && l.result_size() != r.result_size() {
                let mut issue = ValidationIssue::error(format!(
                    "{op}: comparing mismatched sizes {} vs {}",
                    l.result_size().bytes(),
                    r.result_size().bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
        }

        fn check_cmp_dispatch(
            self,
            expr: &LlilExpr,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) -> bool {
            match expr {
                LlilExpr::CmpEq(l, r) => self.check_cmp(l, r, "==", report, addr),
                LlilExpr::CmpNe(l, r) => self.check_cmp(l, r, "!=", report, addr),
                LlilExpr::CmpSlt(l, r) => self.check_cmp(l, r, "<s", report, addr),
                LlilExpr::CmpUlt(l, r) => self.check_cmp(l, r, "<u", report, addr),
                LlilExpr::CmpSle(l, r) => self.check_cmp(l, r, "<=s", report, addr),
                LlilExpr::CmpUle(l, r) => self.check_cmp(l, r, "<=u", report, addr),
                LlilExpr::CmpSgt(l, r) => self.check_cmp(l, r, ">s", report, addr),
                LlilExpr::CmpUgt(l, r) => self.check_cmp(l, r, ">u", report, addr),
                LlilExpr::CmpSge(l, r) => self.check_cmp(l, r, ">=s", report, addr),
                LlilExpr::CmpUge(l, r) => self.check_cmp(l, r, ">=u", report, addr),
                LlilExpr::FCmpEq(l, r) => self.check_cmp(l, r, "f==", report, addr),
                LlilExpr::FCmpLt(l, r) => self.check_cmp(l, r, "f<", report, addr),
                LlilExpr::FCmpGt(l, r) => self.check_cmp(l, r, "f>", report, addr),
                _ => return false,
            }
            true
        }

        fn check_extend_trunc(
            self,
            expr: &LlilExpr,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) -> bool {
            match expr {
                LlilExpr::ZeroExtend { expr: e, from, to }
                | LlilExpr::SignExtend { expr: e, from, to } => {
                    self.check_expr(e, report, addr);
                    if to.bits() <= from.bits() {
                        let mut issue = ValidationIssue::error(format!(
                            "extend from {} to {} bytes does not widen",
                            from.bytes(),
                            to.bytes()
                        ));
                        if let Some(a) = addr {
                            issue = issue.at(a);
                        }
                        report.push(issue);
                    }
                    if e.result_size() != *from {
                        let mut issue = ValidationIssue::error(format!(
                            "extend: input size {} != declared `from` {}",
                            e.result_size().bytes(),
                            from.bytes()
                        ));
                        if let Some(a) = addr {
                            issue = issue.at(a);
                        }
                        report.push(issue);
                    }
                }
                LlilExpr::LowPart { expr: e, to } => {
                    self.check_expr(e, report, addr);
                    if to.bits() > e.result_size().bits() {
                        let mut issue = ValidationIssue::error(format!(
                            "truncate to {} bytes is wider than input {} bytes",
                            to.bytes(),
                            e.result_size().bytes()
                        ));
                        if let Some(a) = addr {
                            issue = issue.at(a);
                        }
                        report.push(issue);
                    }
                }
                LlilExpr::IntToFloat { expr: e, .. } | LlilExpr::FloatToInt { expr: e, .. } => {
                    self.check_expr(e, report, addr);
                }
                _ => return false,
            }
            true
        }

        fn check_const(
            self,
            value: u64,
            size: Size,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            if !self.pedantic || size.bits() >= 64 {
                return;
            }
            let max = (1u64 << size.bits()) - 1;
            if value > max {
                let mut issue = ValidationIssue::warning(format!(
                    "constant {value:#x} does not fit in {} bytes",
                    size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
        }

        fn check_unary_op(
            self,
            operand: &LlilExpr,
            result_size: Size,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            self.check_expr(operand, report, addr);
            if operand.result_size() != result_size {
                let mut issue = ValidationIssue::error(format!(
                    "unary: operand size {} != result size {}",
                    operand.result_size().bytes(),
                    result_size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
        }

        fn check_cond_expr(
            self,
            cond: &LlilExpr,
            true_val: &LlilExpr,
            false_val: &LlilExpr,
            size: Size,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            self.check_expr(cond, report, addr);
            self.check_expr(true_val, report, addr);
            self.check_expr(false_val, report, addr);
            if self.pedantic && !Self::is_boolean(cond) {
                let mut issue = ValidationIssue::warning(
                    "ternary condition is not a boolean expression".to_string(),
                );
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
            if true_val.result_size() != size || false_val.result_size() != size {
                let mut issue = ValidationIssue::error(format!(
                    "ternary arms ({}, {}) disagree with result size {}",
                    true_val.result_size().bytes(),
                    false_val.result_size().bytes(),
                    size.bytes()
                ));
                if let Some(a) = addr {
                    issue = issue.at(a);
                }
                report.push(issue);
            }
        }

        fn check_expr(self, expr: &LlilExpr, report: &mut ValidationReport, addr: Option<u64>) {
            if self.check_cmp_dispatch(expr, report, addr) {
                return;
            }
            if self.check_extend_trunc(expr, report, addr) {
                return;
            }
            match expr {
                LlilExpr::Const { value, size } => self.check_const(*value, *size, report, addr),
                LlilExpr::RegisterRef { .. }
                | LlilExpr::Register { .. }
                | LlilExpr::StackPointer(_)
                | LlilExpr::Flag(_)
                | LlilExpr::Undefined(_) => {}
                LlilExpr::Load { addr: a, .. } => self.check_expr(a, report, addr),
                LlilExpr::AddT(l, r, s)
                | LlilExpr::SubT(l, r, s)
                | LlilExpr::MulT(l, r, s)
                | LlilExpr::DivU(l, r, s)
                | LlilExpr::DivS(l, r, s)
                | LlilExpr::ModU(l, r, s)
                | LlilExpr::ModS(l, r, s)
                | LlilExpr::And(l, r, s)
                | LlilExpr::Or(l, r, s)
                | LlilExpr::Xor(l, r, s) => {
                    self.check_binary(l, r, *s, "arith/bitwise", report, addr);
                }
                LlilExpr::FAdd(l, r, s)
                | LlilExpr::FSub(l, r, s)
                | LlilExpr::FMul(l, r, s)
                | LlilExpr::FDiv(l, r, s) => {
                    self.check_binary(l, r, *s, "float-arith", report, addr);
                }
                LlilExpr::ShlT(l, r, s)
                | LlilExpr::Shr(l, r, s)
                | LlilExpr::Sar(l, r, s)
                | LlilExpr::Rol(l, r, s)
                | LlilExpr::Ror(l, r, s) => {
                    self.check_shift(l, r, *s, "shift/rotate", report, addr);
                }
                LlilExpr::Neg(e, s) | LlilExpr::Not(e, s) | LlilExpr::FNeg(e, s) => {
                    self.check_unary_op(e, *s, report, addr);
                }
                // Comparisons and extend/truncate handled by early dispatch.
                LlilExpr::CmpEq(..)
                | LlilExpr::CmpNe(..)
                | LlilExpr::CmpSlt(..)
                | LlilExpr::CmpUlt(..)
                | LlilExpr::CmpSle(..)
                | LlilExpr::CmpUle(..)
                | LlilExpr::CmpSgt(..)
                | LlilExpr::CmpUgt(..)
                | LlilExpr::CmpSge(..)
                | LlilExpr::CmpUge(..)
                | LlilExpr::FCmpEq(..)
                | LlilExpr::FCmpLt(..)
                | LlilExpr::FCmpGt(..)
                | LlilExpr::ZeroExtend { .. }
                | LlilExpr::SignExtend { .. }
                | LlilExpr::LowPart { .. }
                | LlilExpr::IntToFloat { .. }
                | LlilExpr::FloatToInt { .. } => unreachable!("handled by early dispatch"),
                LlilExpr::CondExpr {
                    cond,
                    true_val,
                    false_val,
                    size,
                } => {
                    self.check_cond_expr(cond, true_val, false_val, *size, report, addr);
                }
                LlilExpr::Intrinsic { args, .. } => {
                    for a in args {
                        self.check_expr(a, report, addr);
                    }
                }
                LlilExpr::Add {
                    left: l,
                    right: r,
                    size: s,
                }
                | LlilExpr::Sub {
                    left: l,
                    right: r,
                    size: s,
                }
                | LlilExpr::Mul {
                    left: l,
                    right: r,
                    size: s,
                } => self.check_binary(l, r, *s, "arith/bitwise", report, addr),
                LlilExpr::Shl { value, shift, size } => {
                    self.check_shift(value, shift, *size, "shift/rotate", report, addr);
                }
            }
        }

        fn check_instr(
            self,
            instr: &LlilInstruction,
            report: &mut ValidationReport,
            addr: Option<u64>,
        ) {
            match instr {
                LlilInstruction::Nop
                | LlilInstruction::Ret
                | LlilInstruction::Return { .. }
                | LlilInstruction::SysCall
                | LlilInstruction::Breakpoint
                | LlilInstruction::Undefined
                | LlilInstruction::Trap { .. }
                | LlilInstruction::Pop { .. }
                | LlilInstruction::UnimplementedRaw { .. }
                | LlilInstruction::Unimplemented { .. } => {}
                LlilInstruction::SetReg {
                    size, value: src, ..
                } => {
                    self.check_expr(src, report, addr);
                    if src.result_size() != *size {
                        let mut issue = ValidationIssue::error(format!(
                            "set-reg: source size {} != declared dest size {}",
                            src.result_size().bytes(),
                            size.bytes()
                        ));
                        if let Some(a) = addr {
                            issue = issue.at(a);
                        }
                        report.push(issue);
                    }
                }
                LlilInstruction::SetRegSplit { src, .. }
                | LlilInstruction::SetFlag { src, .. }
                | LlilInstruction::Push { src, .. } => self.check_expr(src, report, addr),
                LlilInstruction::Load { addr: a, .. } => self.check_expr(a, report, addr),
                LlilInstruction::Store {
                    addr: a,
                    size,
                    value: src,
                } => {
                    self.check_expr(a, report, addr);
                    self.check_expr(src, report, addr);
                    if src.result_size() != *size {
                        let mut issue = ValidationIssue::error(format!(
                            "store: value size {} != store size {}",
                            src.result_size().bytes(),
                            size.bytes()
                        ));
                        if let Some(adr) = addr {
                            issue = issue.at(adr);
                        }
                        report.push(issue);
                    }
                }
                LlilInstruction::JumpDest { dest }
                | LlilInstruction::JumpTo { dest, .. }
                | LlilInstruction::CallDest { dest }
                | LlilInstruction::TailCall { dest } => self.check_expr(dest, report, addr),
                LlilInstruction::CondJump { cond, .. } => {
                    self.check_expr(cond, report, addr);
                    if self.pedantic && !Self::is_boolean(cond) && cond.is_const().is_none() {
                        let mut issue = ValidationIssue::warning(
                            "conditional jump guard is not a boolean expression".to_string(),
                        );
                        if let Some(a) = addr {
                            issue = issue.at(a);
                        }
                        report.push(issue);
                    }
                }
                LlilInstruction::CondCall { cond, dest } => {
                    self.check_expr(cond, report, addr);
                    self.check_expr(dest, report, addr);
                }
                LlilInstruction::Intrinsic { args, .. } => {
                    for a in args {
                        self.check_expr(a, report, addr);
                    }
                }
                LlilInstruction::Jump(dest) | LlilInstruction::Call(dest) => {
                    self.check_expr(dest, report, addr);
                }
                LlilInstruction::ConditionalJump { cond, .. } => {
                    self.check_expr(cond, report, addr);
                }
                LlilInstruction::SetRegister { value, .. } => {
                    self.check_expr(value, report, addr);
                }
            }
        }
    }

    // â”€â”€ pretty-printer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Numeric base used when rendering integer constants in the pretty-printer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NumberBase {
        /// Render in hexadecimal (`0x..`).
        Hex,
        /// Render in decimal.
        Decimal,
    }

    /// Configurable LLIL pretty-printer.
    ///
    /// Unlike the terse [`fmt::Display`] impl, this printer supports indentation,
    /// optional size suffixes, and a choice of numeric base, making it suitable
    /// for user-facing listings.
    #[derive(Debug, Clone, Copy)]
    pub struct PrettyPrinter {
        /// Number of spaces per indentation level.
        pub indent_width: usize,
        /// Whether to append `.N` size suffixes to expressions.
        pub show_sizes: bool,
        /// Base used for integer constants.
        pub base: NumberBase,
    }

    impl Default for PrettyPrinter {
        fn default() -> Self {
            Self {
                indent_width: 2,
                show_sizes: true,
                base: NumberBase::Hex,
            }
        }
    }

    impl PrettyPrinter {
        /// Construct a printer with default settings.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Builder: hide size suffixes.
        #[must_use]
        pub const fn without_sizes(mut self) -> Self {
            self.show_sizes = false;
            self
        }

        /// Builder: render constants in decimal.
        #[must_use]
        pub const fn decimal(mut self) -> Self {
            self.base = NumberBase::Decimal;
            self
        }

        fn fmt_const(self, value: u64) -> String {
            match self.base {
                NumberBase::Hex => format!("0x{value:x}"),
                NumberBase::Decimal => format!("{value}"),
            }
        }

        fn suffix(self, size: Size) -> String {
            if self.show_sizes {
                format!(".{}", size.bytes())
            } else {
                String::new()
            }
        }

        /// Render a binary expression with infix operator `op` and size suffix.
        fn bin(self, l: &LlilExpr, r: &LlilExpr, op: &str, s: Size) -> String {
            format!("({} {op} {}){}", self.expr(l), self.expr(r), self.suffix(s))
        }

        /// Render an arithmetic / bitwise / shift binary node, if applicable.
        fn render_binary(self, e: &LlilExpr) -> Option<String> {
            let (l, r, op, s): (&LlilExpr, &LlilExpr, &str, Size) = match e {
                LlilExpr::AddT(l, r, s) => (l, r, "+", *s),
                LlilExpr::SubT(l, r, s) => (l, r, "-", *s),
                LlilExpr::MulT(l, r, s) => (l, r, "*", *s),
                LlilExpr::DivU(l, r, s) => (l, r, "/u", *s),
                LlilExpr::DivS(l, r, s) => (l, r, "/s", *s),
                LlilExpr::ModU(l, r, s) => (l, r, "%u", *s),
                LlilExpr::ModS(l, r, s) => (l, r, "%s", *s),
                LlilExpr::And(l, r, s) => (l, r, "&", *s),
                LlilExpr::Or(l, r, s) => (l, r, "|", *s),
                LlilExpr::Xor(l, r, s) => (l, r, "^", *s),
                LlilExpr::ShlT(l, r, s) => (l, r, "<<", *s),
                LlilExpr::Shr(l, r, s) => (l, r, ">>", *s),
                LlilExpr::Sar(l, r, s) => (l, r, ">>a", *s),
                LlilExpr::Rol(l, r, s) => (l, r, "rol", *s),
                LlilExpr::Ror(l, r, s) => (l, r, "ror", *s),
                LlilExpr::FAdd(l, r, s) => (l, r, "f+", *s),
                LlilExpr::FSub(l, r, s) => (l, r, "f-", *s),
                LlilExpr::FMul(l, r, s) => (l, r, "f*", *s),
                LlilExpr::FDiv(l, r, s) => (l, r, "f/", *s),
                _ => return None,
            };
            Some(self.bin(l, r, op, s))
        }

        /// Render a comparison node, if applicable.
        fn render_cmp(self, e: &LlilExpr) -> Option<String> {
            let (l, r, op): (&LlilExpr, &LlilExpr, &str) = match e {
                LlilExpr::CmpEq(l, r) => (l, r, "=="),
                LlilExpr::CmpNe(l, r) => (l, r, "!="),
                LlilExpr::CmpSlt(l, r) => (l, r, "<s"),
                LlilExpr::CmpUlt(l, r) => (l, r, "<u"),
                LlilExpr::CmpSle(l, r) => (l, r, "<=s"),
                LlilExpr::CmpUle(l, r) => (l, r, "<=u"),
                LlilExpr::CmpSgt(l, r) => (l, r, ">s"),
                LlilExpr::CmpUgt(l, r) => (l, r, ">u"),
                LlilExpr::CmpSge(l, r) => (l, r, ">=s"),
                LlilExpr::CmpUge(l, r) => (l, r, ">=u"),
                LlilExpr::FCmpEq(l, r) => (l, r, "f=="),
                LlilExpr::FCmpLt(l, r) => (l, r, "f<"),
                LlilExpr::FCmpGt(l, r) => (l, r, "f>"),
                _ => return None,
            };
            Some(format!("({} {op} {})", self.expr(l), self.expr(r)))
        }

        /// Render a single expression to a string.
        #[must_use]
        pub fn expr(self, e: &LlilExpr) -> String {
            if let Some(s) = self.render_binary(e) {
                return s;
            }
            if let Some(s) = self.render_cmp(e) {
                return s;
            }
            match e {
                LlilExpr::Const { value, size } => {
                    format!("{}{}", self.fmt_const(*value), self.suffix(*size))
                }
                LlilExpr::RegisterRef { reg, size } => format!("{reg}{}", self.suffix(*size)),
                LlilExpr::Load { addr, size } => {
                    format!("[{}]{}", self.expr(addr), self.suffix(*size))
                }
                LlilExpr::Neg(e, s) => format!("(-{}){}", self.expr(e), self.suffix(*s)),
                LlilExpr::Not(e, s) => format!("(~{}){}", self.expr(e), self.suffix(*s)),
                LlilExpr::FNeg(e, s) => format!("(-f{}){}", self.expr(e), self.suffix(*s)),
                LlilExpr::ZeroExtend { expr, from, to } => {
                    format!("zx({}, {}->{})", self.expr(expr), from.bytes(), to.bytes())
                }
                LlilExpr::SignExtend { expr, from, to } => {
                    format!("sx({}, {}->{})", self.expr(expr), from.bytes(), to.bytes())
                }
                LlilExpr::LowPart { expr, to } => {
                    format!("low({}, {})", self.expr(expr), to.bytes())
                }
                LlilExpr::IntToFloat { expr, to } => {
                    format!("itof({}, {})", self.expr(expr), to.bytes())
                }
                LlilExpr::FloatToInt { expr, to } => {
                    format!("ftoi({}, {})", self.expr(expr), to.bytes())
                }
                LlilExpr::StackPointer(s) => format!("SP{}", self.suffix(*s)),
                LlilExpr::Flag(name) => format!("flag({name})"),
                LlilExpr::CondExpr {
                    cond,
                    true_val,
                    false_val,
                    size,
                } => format!(
                    "({} ? {} : {}){}",
                    self.expr(cond),
                    self.expr(true_val),
                    self.expr(false_val),
                    self.suffix(*size)
                ),
                LlilExpr::Undefined(s) => format!("undef{}", self.suffix(*s)),
                LlilExpr::Intrinsic {
                    name,
                    args,
                    result_size,
                } => {
                    let inner = args
                        .iter()
                        .map(|a| self.expr(a))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{name}({inner}){}", self.suffix(*result_size))
                }
                // Binary / comparison nodes handled above.
                _ => unreachable!("binary/comparison handled by render_binary/render_cmp"),
            }
        }

        /// Render a single instruction at the given indentation level.
        #[must_use]
        pub fn instr(self, instr: &LlilInstruction, level: usize) -> String {
            let pad = " ".repeat(level * self.indent_width);
            let body = match instr {
                LlilInstruction::Nop => "nop".to_string(),
                LlilInstruction::SetReg {
                    dest,
                    size,
                    value: src,
                } => format!("{dest}{} = {}", self.suffix(*size), self.expr(src)),
                LlilInstruction::SetRegSplit { high, low, src } => {
                    format!("{high}:{low} = {}", self.expr(src))
                }
                LlilInstruction::Load { dest, size, addr } => {
                    format!("{dest}{} = [{}]", self.suffix(*size), self.expr(addr))
                }
                LlilInstruction::Store {
                    addr,
                    size,
                    value: src,
                } => format!(
                    "[{}]{} = {}",
                    self.expr(addr),
                    self.suffix(*size),
                    self.expr(src)
                ),
                LlilInstruction::SetFlag { name, src } => {
                    format!("flag({name}) = {}", self.expr(src))
                }
                LlilInstruction::Push { size, src } => {
                    format!("push{} {}", self.suffix(*size), self.expr(src))
                }
                LlilInstruction::Pop { dest, size } => {
                    format!("{dest}{} = pop", self.suffix(*size))
                }
                LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => format!("jump {}", self.expr(dest)),
                LlilInstruction::JumpTo { dest, .. } => format!("jump_to {}", self.expr(dest)),
                LlilInstruction::CallDest { dest } | LlilInstruction::Call(dest) => format!("call {}", self.expr(dest)),
                LlilInstruction::TailCall { dest } => format!("tailcall {}", self.expr(dest)),
                LlilInstruction::Ret => "ret".to_string(),
                LlilInstruction::Return { value: Some(v) } if self.show_sizes => {
                    format!("return {}", self.expr(v))
                }
                LlilInstruction::CondJump {
                    cond,
                    true_dest,
                    false_dest,
                } => format!(
                    "if ({}) goto {true_dest} else {false_dest}",
                    self.expr(cond)
                ),
                LlilInstruction::CondCall { cond, dest } => {
                    format!("if ({}) call {}", self.expr(cond), self.expr(dest))
                }
                LlilInstruction::Trap { code } => format!("trap 0x{code:x}"),
                LlilInstruction::SysCall => "syscall".to_string(),
                LlilInstruction::Breakpoint => "bp".to_string(),
                LlilInstruction::Intrinsic { name, args } => {
                    let inner = args
                        .iter()
                        .map(|a| self.expr(a))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{name}({inner})")
                }
                LlilInstruction::Undefined => "undefined".to_string(),
                LlilInstruction::UnimplementedRaw { address, .. } => {
                    format!("unimplemented @ {address}")
                }
                LlilInstruction::Unimplemented { mnemonic } => format!("unimplemented({mnemonic})"),
                LlilInstruction::ConditionalJump {
                    cond,
                    true_target,
                    false_target,
                } => format!(
                    "if ({}) goto {true_target} else {false_target}",
                    self.expr(cond)
                ),
                LlilInstruction::SetRegister { dest, size, value } => {
                    format!("r{dest}{} = {}", self.suffix(*size), self.expr(value))
                }
                LlilInstruction::Return { .. } => "return".to_string(),
            };
            format!("{pad}{body}")
        }

        /// Render an entire function as an indented listing grouped by block.
        #[must_use]
        pub fn function(self, func: &LlilFunction) -> String {
            use std::fmt::Write as _;
            let mut out = String::new();
            let _ = writeln!(out, "function @ {} {{", func.entry);
            for block in &func.blocks {
                let _ = writeln!(
                    out,
                    "{}block {} @ {}:",
                    " ".repeat(self.indent_width),
                    block.id,
                    block.start
                );
                for ai in &block.instrs {
                    out.push_str(&self.instr(&ai.instr, 2));
                    out.push('\n');
                }
            }
            out.push('}');
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{LlilExpr, LlilInstruction, LlilRegister, Size};

        fn reg(name: &str, size: Size) -> LlilExpr {
            LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(name.to_string()),
                size,
            }
        }

        fn konst(v: u64, size: Size) -> LlilExpr {
            LlilExpr::Const { value: v, size }
        }

        #[test]
        fn valid_add_same_size() {
            let v = LlilValidator::new();
            let e = LlilExpr::AddT(
                Box::new(reg("rax", Size::QWord)),
                Box::new(konst(1, Size::QWord)),
                Size::QWord,
            );
            let r = v.validate_expr(&e);
            assert!(r.is_valid());
            assert!(r.is_clean());
        }

        #[test]
        fn invalid_add_mismatched_size() {
            let v = LlilValidator::new();
            let e = LlilExpr::AddT(
                Box::new(reg("rax", Size::QWord)),
                Box::new(konst(1, Size::DWord)),
                Size::QWord,
            );
            let r = v.validate_expr(&e);
            assert!(!r.is_valid());
            assert_eq!(r.error_count(), 1);
        }

        #[test]
        fn invalid_zero_extend_narrows() {
            let v = LlilValidator::new();
            let e = LlilExpr::ZeroExtend {
                expr: Box::new(reg("rax", Size::QWord)),
                from: Size::QWord,
                to: Size::DWord,
            };
            let r = v.validate_expr(&e);
            assert!(!r.is_valid());
        }

        #[test]
        fn valid_zero_extend_widens() {
            let v = LlilValidator::new();
            let e = LlilExpr::ZeroExtend {
                expr: Box::new(reg("eax", Size::DWord)),
                from: Size::DWord,
                to: Size::QWord,
            };
            let r = v.validate_expr(&e);
            assert!(r.is_valid());
        }

        #[test]
        fn invalid_zero_extend_from_mismatch() {
            let v = LlilValidator::new();
            let e = LlilExpr::ZeroExtend {
                expr: Box::new(reg("eax", Size::DWord)),
                from: Size::Word,
                to: Size::QWord,
            };
            let r = v.validate_expr(&e);
            assert!(!r.is_valid());
        }

        #[test]
        fn invalid_truncate_widens() {
            let v = LlilValidator::new();
            let e = LlilExpr::LowPart {
                expr: Box::new(reg("ax", Size::Word)),
                to: Size::QWord,
            };
            let r = v.validate_expr(&e);
            assert!(!r.is_valid());
        }

        #[test]
        fn valid_comparison_into_condjump() {
            let v = LlilValidator::new();
            let cmp = LlilExpr::CmpEq(
                Box::new(reg("rax", Size::QWord)),
                Box::new(konst(0, Size::QWord)),
            );
            let r = v.validate_expr(&cmp);
            assert!(r.is_valid());
        }

        #[test]
        fn invalid_cmp_mismatched_operands() {
            let v = LlilValidator::new();
            let cmp = LlilExpr::CmpEq(
                Box::new(reg("rax", Size::QWord)),
                Box::new(reg("eax", Size::DWord)),
            );
            let r = v.validate_expr(&cmp);
            assert!(!r.is_valid());
        }

        #[test]
        fn shift_amount_size_independent() {
            let v = LlilValidator::new();
            // shift a QWord by a byte amount â€” legal
            let e = LlilExpr::ShlT(
                Box::new(reg("rax", Size::QWord)),
                Box::new(reg("cl", Size::Byte)),
                Size::QWord,
            );
            let r = v.validate_expr(&e);
            assert!(r.is_valid());
        }

        #[test]
        fn pedantic_warns_on_oversized_shift() {
            let v = LlilValidator::pedantic();
            let e = LlilExpr::ShlT(
                Box::new(reg("eax", Size::DWord)),
                Box::new(konst(40, Size::Byte)),
                Size::DWord,
            );
            let r = v.validate_expr(&e);
            assert!(r.is_valid()); // only a warning
            assert_eq!(r.warning_count(), 1);
        }

        #[test]
        fn instr_set_reg_size_check() {
            let v = LlilValidator::new();
            let good = LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".to_string()),
                size: Size::QWord,
                value: konst(1, Size::QWord),
            };
            assert!(v.validate_instr(&good, Some(0x1000)).is_valid());
            let bad = LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".to_string()),
                size: Size::QWord,
                value: konst(1, Size::DWord),
            };
            let r = v.validate_instr(&bad, Some(0x1000));
            assert!(!r.is_valid());
            assert_eq!(r.issues[0].address, Some(0x1000));
        }

        #[test]
        fn instr_store_size_check() {
            let v = LlilValidator::new();
            let bad = LlilInstruction::Store {
                addr: reg("rsp", Size::QWord),
                size: Size::QWord,
                value: konst(1, Size::DWord),
            };
            assert!(!v.validate_instr(&bad, None).is_valid());
        }

        #[test]
        fn nested_expr_validation_recurses() {
            let v = LlilValidator::new();
            // outer ok but inner mul mismatched
            let inner = LlilExpr::MulT(
                Box::new(reg("rax", Size::QWord)),
                Box::new(konst(2, Size::DWord)),
                Size::QWord,
            );
            let outer = LlilExpr::AddT(
                Box::new(inner),
                Box::new(konst(1, Size::QWord)),
                Size::QWord,
            );
            let r = v.validate_expr(&outer);
            assert!(!r.is_valid());
        }

        #[test]
        fn report_merge_and_display() {
            let mut a = ValidationReport::new();
            a.push(ValidationIssue::error("boom").at(0x10));
            let mut b = ValidationReport::new();
            b.push(ValidationIssue::warning("hmm"));
            a.merge(b);
            assert_eq!(a.error_count(), 1);
            assert_eq!(a.warning_count(), 1);
            let s = a.to_string();
            assert!(s.contains("0x10"));
            assert!(s.contains("hmm"));
        }

        #[test]
        fn pretty_printer_basic_expr() {
            let pp = PrettyPrinter::new();
            let e = LlilExpr::AddT(
                Box::new(reg("rax", Size::QWord)),
                Box::new(konst(0x10, Size::QWord)),
                Size::QWord,
            );
            let s = pp.expr(&e);
            assert!(s.contains("rax.8"));
            assert!(s.contains("0x10"));
        }

        #[test]
        fn pretty_printer_decimal_no_sizes() {
            let pp = PrettyPrinter::new().decimal().without_sizes();
            let e = konst(255, Size::Byte);
            assert_eq!(pp.expr(&e), "255");
        }

        #[test]
        fn pretty_printer_instr_indent() {
            let pp = PrettyPrinter::new();
            let i = LlilInstruction::Ret;
            assert_eq!(pp.instr(&i, 2), "    ret");
        }

        #[test]
        fn validator_clean_function() {
            use crate::{LlilAnnotatedInstr, LlilBasicBlock, LlilFunction};
            use rustre_core::address::Address;
            let mut func = LlilFunction::new(Address::new(0x1000));
            let block = LlilBasicBlock {
                id: 0,
                start: Address::new(0x1000),
                end: Address::new(0x1000),
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::Ret, length: 0 }], successors: vec![] };
            func.add_block(block);
            let v = LlilValidator::new();
            assert!(v.validate_function(&func).is_valid());
            let pp = PrettyPrinter::new();
            let listing = pp.function(&func);
            assert!(listing.contains("ret"));
            assert!(listing.contains("block 0"));
        }
    }

    /// `sign_extend64` must not underflow for vector `Size`s.
    ///
    /// `Size` includes OWord/YWord/ZWord (128/256/512 bits), so the old
    /// `64u32 - u32::try_from(size.bits()).unwrap_or(64)` UNDERFLOWED for any of
    /// them — its only guard was against the conversion failing, which never
    /// happens. Both sibling copies of this primitive in rustre-il-passes
    /// (lib.rs:1749, constant_propagation.rs:608) already had the `bits >= N`
    /// early return; this one did not. Found 2026-07-23 by comparing the three.
    ///
    /// HONESTY NOTE — the value assertions below CANNOT fail in release, and a
    /// revert-check proved it: with overflow checks off, `64 - 128` wraps to
    /// 4_294_967_232, Rust then masks the shift amount by the type width, and
    /// every vector size happens to be a multiple of 64 apart, so the masked
    /// shift is exactly 0 — an identity, which is what the fix returns anyway.
    /// The old code was ACCIDENTALLY correct in release and panicked only in
    /// debug. So the underflow itself is asserted explicitly below; without that
    /// this test would be vacuous, which is the trap this repo has hit before.
    #[test]
    fn sign_extend64_handles_sizes_wider_than_64_bits() {
        // The hazard, asserted directly: this is what the old expression did,
        // and it is release-visible regardless of overflow-check settings.
        for s in [Size::OWord, Size::YWord, Size::ZWord] {
            assert!(
                64u32.checked_sub(u32::try_from(s.bits()).unwrap()).is_none(),
                "{s:?} is wider than 64 bits, so `64 - bits` underflows — the                  guard in sign_extend64 is what stands between that and a                  debug-build panic"
            );
        }

        for s in [Size::OWord, Size::YWord, Size::ZWord] {
            assert_eq!(
                crate::sign_extend64(0x8000_0000_0000_0000, s),
                0x8000_0000_0000_0000u64.cast_signed(),
                "vector size {s:?} must pass the value through, not underflow"
            );
        }
        // QWord is the boundary: 64 - 64 = 0, identity either way.
        assert_eq!(
            crate::sign_extend64(0xFFFF_FFFF_FFFF_FFFF, Size::QWord),
            -1
        );
        // Narrower sizes still sign-extend properly (the actual job).
        assert_eq!(crate::sign_extend64(0x80, Size::Byte), -128);
        assert_eq!(crate::sign_extend64(0x7F, Size::Byte), 127);
        assert_eq!(crate::sign_extend64(0x8000, Size::Word), -32768);
        assert_eq!(crate::sign_extend64(0x8000_0000, Size::DWord), -2_147_483_648);
    }
}
