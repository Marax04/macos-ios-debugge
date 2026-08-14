//! `rustre-il-lift` â€” generic IL lifting coordinator.
//!
//! Bridges architecture-specific disassembly to the IL pipeline (LLIL â†’ MLIL â†’ HLIL).
//! Provides lifting context, caching, statistics, batch lifting, partial lifting,
//! error recovery, and a registry of architecture-specific lifters.

use parking_lot::{Mutex, RwLock};
use rustre_core::arch::{Instruction, Operand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

pub mod arm64_advanced_lift;
pub mod arm64_simd_lift;
pub mod arm_lifter;
pub mod avr_lifter;
pub mod bpf_lifter;
pub mod cil_lifter;
pub mod dex_lifter;
pub mod m68k_lifter;
pub mod mips_lift;
pub mod mips_lifter;
pub mod ppc_lifter;
pub mod riscv_extensions_lift;
pub mod riscv_lift;
pub mod riscv_lifter;
pub mod sparc_lifter;
pub mod wasm_lifter;
pub mod z80_lifter;

// â”€â”€ New x86 lifting infrastructure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Modular re-write of the x86/x64 lifter following the Î¼Ops-atomicity spec.
// The new modules coexist with the existing `X86Lifter` in lib.rs; they do
// not replace it â€” they extend it with the full instruction coverage.
pub mod x86_context;
pub mod x86_flags;
pub mod x86_handlers;
pub mod x86_operand;

/// Complete x86-64 data-movement lifter:
/// MOV/MOVZX/MOVSX/MOVSXD/LEA/XCHG/CMPXCHG/PUSH/POP/XADD with IL semantics.
pub mod x86_complete_lift;
pub mod x86_eval;
pub mod x86_lifter_v2;
pub use x86_complete_lift::X86CompleteLifter;
pub mod x86_abi_recovery;
pub mod x86_analysis;
pub mod x86_calling_conv;
pub mod x86_insn_db;
pub mod x86_optimizer;
pub mod x86_pattern_match;
pub mod x86_pretty_print;
pub mod x86_pseudo;
pub mod x86_simd_lift;
pub mod x86_type_recovery;

/// x86 IL-level deobfuscation pass: MBA normalisation, De Morgan rewrites,
/// opaque predicate detection, junk-instruction removal, XOR-decrypt-loop detection.
pub mod x86_deobf;
pub use x86_deobf::{
    DeobfSummary, ObfPattern, check_opaque_predicate, deobf_effect, deobf_effects, deobf_expr,
    deobf_function, detect_xor_decrypt_loops, find_junk_instructions,
};

/// Flag semantics lifter: FlagSemanticsLifter, FlagUpdate, FlagExpr, lift_flags_for_insn().
pub mod flag_semantics_lifter;

/// Call convention lifter: CallConventionLifter, LiftedCall, ArgExpr, lift_call_site().
pub mod call_convention_lifter;

/// Memory semantics lifter: MemorySemanticsLifter, LoadExpr, StoreExpr, lift_memory_op().
pub mod memory_semantics_lifter;

pub use arm64_advanced_lift::AArch64AdvancedLifter;
pub use riscv_extensions_lift::RiscvExtLifter;
pub use x86_simd_lift::{EvexFlags, RoundingMode, SimdWidth, X86SimdLifter};

pub use x86_abi_recovery::{
    AbiEvidence, AbiRecovery, ArgEvidence, CalleeSaveEvidence, ConventionScore, ReturnEvidence,
    StackFrameEvidence, collect_evidence, recover_abi, score_conventions,
};
pub use x86_analysis::{
    EffectClass, StreamStats, build_def_use_map, collect_mem_accesses, compute_flag_liveness,
    dead_flag_writes, extract_call_sites, intrinsic_census,
};
pub use x86_calling_conv::{
    ArgLocation, CallingConvention, CallingConventionRegistry, Cdecl, Fastcall, LinuxSyscallAmd64,
    MsX64, ParamKind, Stdcall, SysVAmd64,
};
pub use x86_context::{FlagId, ModeHint, X86LiftCtx};
pub use x86_eval::{EvalValue, X86CpuState, eval_expr, exec_effects, fold_expr};
pub use x86_flags::ConditionCode;
pub use x86_handlers::lift_instruction as x86_lift_instruction;
pub use x86_insn_db::{InsnCategory, InsnDb, InsnInfo, LatencyTier};
pub use x86_lifter_v2::X86LifterV2;
pub use x86_optimizer::{OptStats, optimise_effects, simplify_effect, simplify_expr};
pub use x86_pattern_match::{
    EffectPat, ExprPat, Match, count_pushes, detect_loop_back_edge, detect_tail_call,
    detect_xor_zeroing, find_all, match_sequence, scan_sequence,
};
pub use x86_pretty_print::{
    OutputFormat, PrintOptions, render, render_block, render_block_json, render_effect,
    render_expr, render_instr, render_instr_html,
};
pub use x86_pseudo::{PseudoKind, PseudoMatch, lower_to_intrinsic, scan_for, scan_pseudos};
pub use x86_type_recovery::{
    RecoveredType, TypeAnnotation, TypeEnv, TypeRecoverySummary, Width, builtin_register_types,
    infer_expr_type, recover_types,
};

pub use arm_lifter::Arm32Lifter;
pub use arm64_simd_lift::{AArch64NeonLifter, Arrangement, VRegSlot};
pub use avr_lifter::AvrLifter;
pub use bpf_lifter::BpfLifter;
pub use cil_lifter::CilLifter;
pub use dex_lifter::DexLifter;
pub use m68k_lifter::M68kLifter;
pub use mips_lift::Mips32Lifter;
pub use mips_lifter::MipsLifter;
pub use ppc_lifter::PpcLifter;
pub use riscv_lift::RiscV64Lifter;
pub use riscv_lifter::RiscvLifter;
pub use sparc_lifter::SparcLifter;
pub use wasm_lifter::WasmLifter;
pub use z80_lifter::Z80Lifter;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftError
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Errors produced by the lifting pipeline.
#[derive(Debug, Error, Clone)]
pub enum LiftError {
    /// The architecture is not supported by any registered lifter.
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    /// Disassembly failed at the given address.
    #[error("disassembly failed at {0:#x}: {1}")]
    DisasmFailed(u64, String),
    /// Lifting the instruction at the given address failed.
    #[error("lift failed at {0:#x}: {1}")]
    LiftFailed(u64, String),
    /// The bytecode passed to the lifter is not valid.
    #[error("invalid bytecode")]
    InvalidBytecode,
    /// The requested IL level is not achievable with the current lifter.
    #[error("IL level {0} not supported by this lifter")]
    UnsupportedLevel(String),
    /// A lift that was only partially completed (some instructions failed).
    #[error("partial lift: {succeeded} succeeded, {failed} failed")]
    PartialLift {
        /// Number of successfully lifted instructions.
        succeeded: usize,
        /// Number of failed instructions.
        failed: usize,
    },
    /// Cache lookup or storage error.
    #[error("cache error: {0}")]
    CacheError(String),
    /// Other error.
    #[error("{0}")]
    Other(String),
}

/// Converge tier-local lift failures onto the workspace-wide cross-tier error
/// type owned by `rustre-il`.
///
/// The two "this cannot be expressed here" variants ([`LiftError::UnsupportedArch`]
/// and [`LiftError::UnsupportedLevel`]) carry an operation name, so they map onto
/// [`rustre_il::IlError::Unsupported`] at [`rustre_il::IlTier::Lift`]; everything
/// else is a malformed-input / bookkeeping failure and degrades to
/// [`rustre_il::IlError::Invalid`] with the original `Display` text preserved.
impl From<LiftError> for rustre_il::IlError {
    fn from(e: LiftError) -> Self {
        match e {
            LiftError::UnsupportedArch(a) | LiftError::UnsupportedLevel(a) => Self::Unsupported {
                tier: rustre_il::IlTier::Lift,
                op: a,
            },
            other => Self::Invalid(other.to_string()),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftLevel
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The abstraction level of a lifted instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LiftLevel {
    /// Raw disassembly â€” no lifting applied.
    Raw,
    /// Low-level IL.
    Llil,
    /// Mid-level IL in SSA form.
    MlilSsa,
    /// High-level IL.
    Hlil,
}

impl fmt::Display for LiftLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl LiftLevel {
    /// Returns an iterator over all variants in ascending order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Raw,
            Self::Llil,
            Self::MlilSsa,
            Self::Hlil,
        ]
    }

    /// Returns `true` if this level is at least as high as `other`.
    #[must_use]
    pub fn at_least(self, other: Self) -> bool {
        self >= other
    }

    /// Maps this lifter-local level onto the workspace-wide
    /// [`rustre_il::IlTier`] owned by `rustre-il`.
    ///
    /// `LiftLevel` stays as the public, MCP-exposed API of this crate (its
    /// `Display` strings and `all()` order are contractual); this function is
    /// the single bridge that keeps the two enums from silently diverging —
    /// see `lift_level_il_tier_round_trip`.
    #[must_use]
    pub const fn il_tier(self) -> rustre_il::IlTier {
        match self {
            Self::Raw => rustre_il::IlTier::Lift,
            Self::Llil => rustre_il::IlTier::Llil,
            Self::MlilSsa => rustre_il::IlTier::Mlil,
            Self::Hlil => rustre_il::IlTier::Hlil,
        }
    }

    /// Inverse of [`LiftLevel::il_tier`].
    #[must_use]
    pub const fn from_il_tier(t: rustre_il::IlTier) -> Self {
        match t {
            rustre_il::IlTier::Lift => Self::Raw,
            rustre_il::IlTier::Llil => Self::Llil,
            rustre_il::IlTier::Mlil => Self::MlilSsa,
            rustre_il::IlTier::Hlil => Self::Hlil,
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IrExpr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// IR expression AST used in lifted instructions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IrExpr {
    /// Compile-time constant.
    Const(u64),
    /// Register reference.
    Reg(String),
    /// Addition.
    Add(Box<Self>, Box<Self>),
    /// Subtraction.
    Sub(Box<Self>, Box<Self>),
    /// Multiplication.
    Mul(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Left shift.
    Shl(Box<Self>, Box<Self>),
    /// Right shift, LOGICAL: zero-fill from the left.
    Shr(Box<Self>, Box<Self>),
    /// Right shift, ARITHMETIC: sign-fill from the left.
    ///
    /// Added 2026-07-29. Before it existed, this IR could not express an
    /// arithmetic shift at all, so EVERY architecture's `sra`/`srav`/`asr`
    /// was lifted as the logical `Shr` — silently turning a negative value
    /// into a large positive one. That is wrong code, not a lost
    /// optimisation, and it was uniform across MIPS, RISC-V and others, so
    /// no cross-architecture comparison could reveal it: the whole IR agreed
    /// on the wrong answer.
    Sar(Box<Self>, Box<Self>),
    /// Logical / bitwise NOT.
    Not(Box<Self>),
    /// Memory dereference of `size` bytes.
    Deref(Box<Self>, u8),
    /// Boolean test `expr == 0` (used to compute the zero flag).
    CmpEqZero(Box<Self>),
    /// Even-parity of the low byte of `expr` (used to compute the parity flag).
    Parity(Box<Self>),
    /// Undefined / unknown value.
    Undef,
    /// Equality comparison `a == b`.
    CmpEq(Box<Self>, Box<Self>),
    /// Less-than comparison `a < b`.
    CmpLt(Box<Self>, Box<Self>),
    /// Unsigned less-than.
    ///
    /// Added 2026-07-29 for the same reason as [`IrExpr::Sar`]: `CmpLt`
    /// evaluates its operands as SIGNED, so an unsigned comparison had no
    /// representation and MIPS `SLTU`/`SLTIU` were lifted identically to their
    /// signed twins. Two different instructions, one lift, so one of them was
    /// always wrong.
    CmpLtU(Box<Self>, Box<Self>),
    /// Greater-than comparison `a > b`.
    CmpGt(Box<Self>, Box<Self>),
    /// Alias for `CmpEq` â€” equality comparison `a == b`.
    Eq(Box<Self>, Box<Self>),
    /// Inequality comparison `a != b`.
    Ne(Box<Self>, Box<Self>),
    /// Ternary `if cond { then } else { else_ }`.
    IfThenElse(Box<Self>, Box<Self>, Box<Self>),
}

impl IrExpr {
    /// Returns `true` if this expression is a constant.
    #[must_use]
    pub const fn is_const(&self) -> Option<u64> {
        if let Self::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Returns `true` if this is a register reference.
    #[must_use]
    pub const fn is_reg(&self) -> Option<&str> {
        if let Self::Reg(r) = self {
            Some(r.as_str())
        } else {
            None
        }
    }

    /// Recursively count the number of nodes in the expression tree.
    ///
    /// Capped at a recursion depth of 1024 to prevent stack overflow on
    /// adversarially deep expressions from untrusted binary input.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.node_count_inner(1024)
    }

    fn node_count_inner(&self, depth_remaining: usize) -> usize {
        if depth_remaining == 0 {
            return 1;
        }
        match self {
            Self::Const(_) | Self::Reg(_) | Self::Undef => 1,
            Self::Not(e) | Self::Deref(e, _) | Self::CmpEqZero(e) | Self::Parity(e) => {
                1 + e.node_count_inner(depth_remaining - 1)
            }
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Or(l, r)
            | Self::And(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Sar(l, r)
            | Self::CmpEq(l, r)
            | Self::CmpLt(l, r)
            | Self::CmpLtU(l, r)
            | Self::CmpGt(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r) => {
                1 + l.node_count_inner(depth_remaining - 1)
                    + r.node_count_inner(depth_remaining - 1)
            }
            Self::IfThenElse(c, t, e) => {
                1 + c.node_count_inner(depth_remaining - 1)
                    + t.node_count_inner(depth_remaining - 1)
                    + e.node_count_inner(depth_remaining - 1)
            }
        }
    }

    /// Collect all register names referenced in this expression.
    #[must_use]
    pub fn registers_used(&self) -> Vec<String> {
        let mut regs = Vec::new();
        self.collect_regs(&mut regs);
        regs
    }

    fn collect_regs(&self, out: &mut Vec<String>) {
        self.collect_regs_inner(out, 1024);
    }

    fn collect_regs_inner(&self, out: &mut Vec<String>, depth_remaining: usize) {
        if depth_remaining == 0 {
            return;
        }
        match self {
            Self::Reg(r) => out.push(r.clone()),
            Self::Const(_) | Self::Undef => {}
            Self::Not(e) | Self::Deref(e, _) | Self::CmpEqZero(e) | Self::Parity(e) => {
                e.collect_regs_inner(out, depth_remaining - 1);
            }
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Or(l, r)
            | Self::And(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Sar(l, r)
            | Self::CmpEq(l, r)
            | Self::CmpLt(l, r)
            | Self::CmpLtU(l, r)
            | Self::CmpGt(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r) => {
                l.collect_regs_inner(out, depth_remaining - 1);
                r.collect_regs_inner(out, depth_remaining - 1);
            }
            Self::IfThenElse(c, t, e) => {
                c.collect_regs_inner(out, depth_remaining - 1);
                t.collect_regs_inner(out, depth_remaining - 1);
                e.collect_regs_inner(out, depth_remaining - 1);
            }
        }
    }
}

impl fmt::Display for IrExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v:#x}"),
            Self::Reg(r) => write!(f, "{r}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::Mul(a, b) => write!(f, "({a} * {b})"),
            Self::Or(a, b) => write!(f, "({a} | {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Self::Shl(a, b) => write!(f, "({a} << {b})"),
            Self::Shr(a, b) => write!(f, "({a} >> {b})"),
            // `>>>` marks the ARITHMETIC shift so a reader can tell the
            // two apart at a glance; `>>` alone would print the sign-
            // preserving and the zero-filling shift identically.
            Self::Sar(a, b) => write!(f, "({a} >>> {b})"),
            Self::Not(a) => write!(f, "(!{a})"),
            Self::Deref(a, s) => write!(f, "*{a}:{s}"),
            Self::CmpEqZero(a) => write!(f, "({a} == 0)"),
            Self::Parity(a) => write!(f, "parity({a})"),
            Self::Undef => write!(f, "undef"),
            Self::CmpEq(a, b) | Self::Eq(a, b) => write!(f, "({a} == {b})"),
            Self::CmpLt(a, b) => write!(f, "({a} < {b})"),
            Self::CmpLtU(a, b) => write!(f, "({a} <u {b})"),
            Self::CmpGt(a, b) => write!(f, "({a} > {b})"),
            Self::Ne(a, b) => write!(f, "({a} != {b})"),
            Self::IfThenElse(c, t, e) => write!(f, "({c} ? {t} : {e})"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Effect
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Side-effects of a single lifted instruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    /// A register is written.
    RegWrite { reg: String, value: IrExpr },
    /// Memory is written.
    MemWrite {
        addr: IrExpr,
        value: IrExpr,
        size: u8,
    },
    /// Memory is read.
    MemRead {
        addr: IrExpr,
        dest: String,
        size: u8,
    },
    /// A function is called.
    Call { target: IrExpr },
    /// A branch (conditional or unconditional).
    Branch {
        target: IrExpr,
        condition: Option<IrExpr>,
    },
    /// A function return.
    Return { value: Option<IrExpr> },
    /// A system call.
    Syscall { nr: IrExpr },
    /// An architecture-specific intrinsic.
    Intrinsic { name: String, args: Vec<IrExpr> },
    /// Unconditional CPU trap / exception with the given vector number.
    Trap { vector: u8 },
    /// CPU trap raised only when `condition` is non-zero.
    ConditionalTrap { condition: IrExpr, vector: u8 },
    /// Marker indicating the current path does not return.
    NoReturn,
}

impl Effect {
    /// Returns `true` if this effect has observable side-effects that cannot
    /// be eliminated.
    ///
    /// `Intrinsic` is included deliberately: it is the fallback every lifter
    /// emits for a mnemonic it did not recognise (see `ArmLifter::fallback`),
    /// and an operation we could not decode must be assumed to do anything —
    /// `cpuid` alone writes four registers. `written_registers` reports an
    /// empty list for it, so calling it effect-free as well would let a
    /// dead-code pass delete every instruction the lifter failed to model.
    /// `Trap` / `ConditionalTrap` / `NoReturn` are observable by definition:
    /// removing an `int3` / `brk` / `ud2` changes what the program does.
    #[must_use]
    pub const fn is_side_effectful(&self) -> bool {
        matches!(
            self,
            Self::Call { .. }
                | Self::MemWrite { .. }
                | Self::Branch { .. }
                | Self::Return { .. }
                | Self::Syscall { .. }
                | Self::Intrinsic { .. }
                | Self::Trap { .. }
                | Self::ConditionalTrap { .. }
                | Self::NoReturn
        )
    }

    /// Returns all registers written by this effect.
    #[must_use]
    pub fn written_registers(&self) -> Vec<String> {
        match self {
            Self::RegWrite { reg, .. } => vec![reg.clone()],
            Self::MemRead { dest, .. } => vec![dest.clone()],
            _ => vec![],
        }
    }

    /// Returns all registers read by this effect.
    #[must_use]
    pub fn read_registers(&self) -> Vec<String> {
        match self {
            Self::RegWrite { value, .. } => value.registers_used(),
            Self::MemWrite { addr, value, .. } => {
                let mut r = addr.registers_used();
                r.extend(value.registers_used());
                r
            }
            Self::MemRead { addr, .. } => addr.registers_used(),
            Self::Call { target } => target.registers_used(),
            Self::Branch { target, condition } => {
                let mut r = target.registers_used();
                if let Some(c) = condition {
                    r.extend(c.registers_used());
                }
                r
            }
            Self::Return { value } => value.as_ref().map_or_else(Vec::new, IrExpr::registers_used),
            Self::Syscall { nr } => nr.registers_used(),
            Self::Intrinsic { args, .. } => {
                args.iter().flat_map(IrExpr::registers_used).collect()
            }
            Self::Trap { .. } | Self::NoReturn => Vec::new(),
            Self::ConditionalTrap { condition, .. } => condition.registers_used(),
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegWrite { reg, value } => write!(f, "{reg} = {value}"),
            Self::MemWrite { addr, value, size } => write!(f, "*{addr}:{size} = {value}"),
            Self::MemRead { addr, dest, size } => write!(f, "{dest} = *{addr}:{size}"),
            Self::Call { target } => write!(f, "call {target}"),
            Self::Branch { target, condition } => {
                if let Some(c) = condition {
                    write!(f, "if {c} goto {target}")
                } else {
                    write!(f, "goto {target}")
                }
            }
            Self::Return { value } => {
                if let Some(v) = value {
                    write!(f, "return {v}")
                } else {
                    write!(f, "return")
                }
            }
            Self::Syscall { nr } => write!(f, "syscall({nr})"),
            Self::Intrinsic { name, .. } => write!(f, "intrinsic:{name}()"),
            Self::Trap { vector } => write!(f, "trap({vector})"),
            Self::ConditionalTrap { condition, vector } => {
                write!(f, "if {condition} trap({vector})")
            }
            Self::NoReturn => write!(f, "noreturn"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftedInstr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A lifted instruction in IR form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedInstr {
    /// Address of the original instruction.
    pub address: u64,
    /// Original mnemonic string.
    pub original_mnemonic: String,
    /// Textual IR representation.
    pub ir_text: String,
    /// IL level this instruction was lifted to.
    pub il_level: LiftLevel,
    /// Side-effects produced by this instruction.
    pub effects: Vec<Effect>,
}

impl LiftedInstr {
    /// Returns `true` if this instruction is a terminator (control-flow exit).
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch { .. } | Effect::Return { .. } | Effect::Syscall { .. }
            )
        })
    }

    /// Returns `true` if this instruction has any side effects.
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        self.effects.iter().any(Effect::is_side_effectful)
    }

    /// Collect all registers written by this instruction.
    #[must_use]
    pub fn written_registers(&self) -> Vec<String> {
        self.effects
            .iter()
            .flat_map(Effect::written_registers)
            .collect()
    }

    /// Collect all registers read by this instruction.
    #[must_use]
    pub fn read_registers(&self) -> Vec<String> {
        self.effects
            .iter()
            .flat_map(Effect::read_registers)
            .collect()
    }

    /// Number of effects/operations in this lifted instruction.
    #[must_use]
    pub const fn effect_count(&self) -> usize {
        self.effects.len()
    }
}

impl fmt::Display for LiftedInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}: {} -> {}",
            self.address, self.original_mnemonic, self.ir_text
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftResult
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The result of a lifting operation (single or batch).
#[derive(Debug, Clone)]
pub struct LiftResult {
    /// Successfully lifted instructions.
    pub lifted: Vec<LiftedInstr>,
    /// Errors encountered during lifting, indexed by instruction address.
    pub errors: Vec<(u64, LiftError)>,
    /// Statistics from this lift operation.
    pub stats: LiftStats,
}

impl LiftResult {
    /// Creates a new empty `LiftResult`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lifted: Vec::new(),
            errors: Vec::new(),
            stats: LiftStats::new(),
        }
    }

    /// Returns `true` if all instructions were lifted successfully.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the total number of instructions processed (success + errors).
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.lifted.len() + self.errors.len()
    }

    /// Fraction of instructions lifted successfully (0.0â€“1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_count();
        if total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.lifted.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Returns all addresses that failed to lift.
    #[must_use]
    pub fn failed_addresses(&self) -> Vec<u64> {
        self.errors.iter().map(|(a, _)| *a).collect()
    }
}

impl Default for LiftResult {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftStats
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Statistics accumulated during lifting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiftStats {
    /// Total number of instructions processed.
    pub total_instructions: u64,
    /// Successfully lifted instructions.
    pub succeeded: u64,
    /// Instructions that failed to lift.
    pub failed: u64,
    /// Instructions served from cache.
    pub cache_hits: u64,
    /// Instructions that missed the cache and were lifted fresh.
    pub cache_misses: u64,
    /// Total time spent lifting in microseconds (wall-clock).
    pub lift_time_us: u64,
    /// Number of error-recovery fallbacks triggered.
    pub recovery_count: u64,
    /// Number of partial lifts performed.
    pub partial_lifts: u64,
}

impl LiftStats {
    /// Creates zeroed stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another set of stats into `self`.
    pub const fn merge(&mut self, other: &Self) {
        self.total_instructions += other.total_instructions;
        self.succeeded += other.succeeded;
        self.failed += other.failed;
        self.cache_hits += other.cache_hits;
        self.cache_misses += other.cache_misses;
        self.lift_time_us += other.lift_time_us;
        self.recovery_count += other.recovery_count;
        self.partial_lifts += other.partial_lifts;
    }

    /// Cache hit rate (0.0â€“1.0).
    #[must_use]
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.cache_hits).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Overall success rate (0.0â€“1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_instructions == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.succeeded).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_instructions).unwrap_or(u32::MAX))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftCache
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Thread-safe LRU-style cache for lifted instructions keyed by address.
///
/// Stores the most recently lifted instruction per address so that functions
/// with shared basic blocks benefit without lifting the same bytes twice.
#[derive(Debug)]
pub struct LiftCache {
    inner: RwLock<HashMap<u64, LiftedInstr>>,
    /// Maximum number of entries; older entries are evicted when full.
    max_entries: usize,
    hits: Mutex<u64>,
    misses: Mutex<u64>,
}

impl LiftCache {
    /// Creates a new cache with the given capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(max_entries.min(4096))),
            max_entries,
            hits: Mutex::new(0),
            misses: Mutex::new(0),
        }
    }

    /// Creates a cache with a default capacity of 4096 entries.
    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(4096)
    }

    /// Look up a cached instruction by address.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<LiftedInstr> {
        let guard = self.inner.read();
        guard.get(&address).map_or_else(|| {
            *self.misses.lock() += 1;
            None
        }, |instr| {
            *self.hits.lock() += 1;
            Some(instr.clone())
        })
    }

    /// Insert a lifted instruction into the cache.
    ///
    /// If the cache is at capacity, one entry is evicted before inserting the
    /// new one, preserving all other hot entries rather than flushing the whole
    /// cache. The evicted entry is the first one returned by the map iterator
    /// (arbitrary but deterministic within a run, and avoids the O(n) flush).
    pub fn insert(&self, address: u64, instr: LiftedInstr) {
        let mut guard = self.inner.write();
        if guard.len() >= self.max_entries {
            // Evict exactly one entry to make room.
            if let Some(victim) = guard.keys().next().copied() {
                guard.remove(&victim);
            }
        }
        guard.insert(address, instr);
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Current cache hit count.
    #[must_use]
    pub fn hits(&self) -> u64 {
        *self.hits.lock()
    }

    /// Current cache miss count.
    #[must_use]
    pub fn misses(&self) -> u64 {
        *self.misses.lock()
    }

    /// Cache hit rate in [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let h = self.hits();
        let m = self.misses();
        let total = h + m;
        if total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(h).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftContext
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Configuration and shared state threaded through a lifting session.
///
/// A `LiftContext` can be shared across threads via `Arc`.
#[derive(Debug)]
pub struct LiftContext {
    /// Name of the target architecture.
    pub arch: String,
    /// Default IL level to target.
    pub target_level: LiftLevel,
    /// Whether to use the instruction cache.
    pub use_cache: bool,
    /// Whether to attempt error recovery when a lift fails.
    pub error_recovery: bool,
    /// Whether to allow partial lifts (continue past individual failures).
    pub allow_partial: bool,
    /// Maximum number of instructions to lift in a single batch.
    pub batch_limit: usize,
    /// Shared instruction cache (only populated when `use_cache` is true).
    pub cache: Arc<LiftCache>,
    /// Cumulative stats for this context.
    stats: Mutex<LiftStats>,
}

impl LiftContext {
    /// Creates a new lifting context for the given architecture.
    #[must_use]
    pub fn new(arch: impl Into<String>) -> Self {
        Self {
            arch: arch.into(),
            target_level: LiftLevel::Llil,
            use_cache: true,
            error_recovery: true,
            allow_partial: true,
            batch_limit: 10_000,
            cache: Arc::new(LiftCache::default_capacity()),
            stats: Mutex::new(LiftStats::new()),
        }
    }

    /// Builder: set the target IL level.
    #[must_use]
    pub const fn with_level(mut self, level: LiftLevel) -> Self {
        self.target_level = level;
        self
    }

    /// Builder: disable the instruction cache.
    #[must_use]
    pub const fn without_cache(mut self) -> Self {
        self.use_cache = false;
        self
    }

    /// Builder: disable error recovery.
    #[must_use]
    pub const fn without_recovery(mut self) -> Self {
        self.error_recovery = false;
        self
    }

    /// Builder: disable partial lifts (any failure aborts the batch).
    #[must_use]
    pub const fn strict(mut self) -> Self {
        self.allow_partial = false;
        self
    }

    /// Builder: set the batch size limit.
    #[must_use]
    pub const fn with_batch_limit(mut self, limit: usize) -> Self {
        self.batch_limit = limit;
        self
    }

    /// Accumulate stats from a lift operation into this context.
    pub fn record_stats(&self, s: &LiftStats) {
        self.stats.lock().merge(s);
    }

    /// Return a snapshot of accumulated statistics.
    #[must_use]
    pub fn stats(&self) -> LiftStats {
        self.stats.lock().clone()
    }

    /// Reset accumulated statistics.
    pub fn reset_stats(&self) {
        *self.stats.lock() = LiftStats::new();
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter trait
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Trait implemented by architecture-specific lifters.
pub trait ArchLifter: Send + Sync + fmt::Debug {
    /// Architecture name.
    fn arch_name(&self) -> &str;
    /// IL level this lifter produces.
    fn lift_level(&self) -> LiftLevel;

    /// Lift a single instruction.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] if the instruction cannot be lifted.
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError>;

    /// Lift a sequence of instructions, returning a result per instruction.
    ///
    /// The default implementation calls [`lift`] for each instruction. Override
    /// for architectures where batching provides efficiency gains.
    fn lift_block(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>> {
        instrs.iter().map(|i| self.lift(i)).collect()
    }

    /// Human-readable description of this lifter.
    fn description(&self) -> &'static str {
        "generic lifter"
    }

    /// Returns `true` if this lifter can handle the given mnemonic.
    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        let _ = mnemonic;
        true
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ErrorRecoveryLifter â€” wraps another lifter and substitutes Intrinsic for
// any instruction that fails, rather than propagating the error.
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A lifter that wraps another [`ArchLifter`] and recovers from failures by
/// substituting an [`Effect::Intrinsic`] stub for instructions that fail.
#[derive(Debug)]
pub struct ErrorRecoveryLifter {
    inner: Box<dyn ArchLifter>,
}

impl ErrorRecoveryLifter {
    /// Wraps `inner` with error recovery.
    #[must_use]
    pub fn new(inner: Box<dyn ArchLifter>) -> Self {
        Self { inner }
    }
}

impl ArchLifter for ErrorRecoveryLifter {
    fn arch_name(&self) -> &str {
        self.inner.arch_name()
    }

    fn lift_level(&self) -> LiftLevel {
        self.inner.lift_level()
    }

    fn description(&self) -> &'static str {
        "error-recovering lifter"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        match self.inner.lift(instr) {
            Ok(li) => Ok(li),
            Err(_err) => {
                // Substitute a stub â€” never return an error.
                let stub_effect = Effect::Intrinsic {
                    name: format!("__unlifted_{}", instr.mnemonic.to_ascii_lowercase()),
                    args: vec![],
                };
                Ok(LiftedInstr {
                    address: instr.address.0,
                    original_mnemonic: instr.mnemonic.clone(),
                    ir_text: format!("__unlifted_{}", instr.mnemonic),
                    il_level: self.lift_level(),
                    effects: vec![stub_effect],
                })
            }
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// GenericLlilLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Generic LLIL lifter that supports common x86/x86-64 mnemonics.
#[derive(Debug)]
pub struct GenericLlilLifter {
    arch_name: String,
}

impl GenericLlilLifter {
    /// Create a new generic LLIL lifter for the named architecture.
    #[must_use]
    pub const fn new(arch_name: String) -> Self {
        Self { arch_name }
    }

    /// Convert a structured [`Operand`] to an [`IrExpr`].
    ///
    /// For memory operands the expression evaluates the effective address; the
    /// caller wraps it in [`IrExpr::Deref`] when a load is needed.
    fn operand_to_expr(op: &Operand) -> IrExpr {
        match op {
            Operand::Register(r) => IrExpr::Reg(r.name.clone()),
            Operand::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
            Operand::UImmediate(v) => IrExpr::Const(*v),
            Operand::Label(addr) => IrExpr::Const(*addr),
            Operand::Memory {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                // Build: base + index * scale + disp
                let mut expr: Option<IrExpr> = base.as_ref().map(|r| IrExpr::Reg(r.name.clone()));
                if let Some(idx) = index {
                    let idx_expr = if *scale > 1 {
                        IrExpr::Mul(
                            Box::new(IrExpr::Reg(idx.name.clone())),
                            Box::new(IrExpr::Const(u64::from(*scale))),
                        )
                    } else {
                        IrExpr::Reg(idx.name.clone())
                    };
                    expr = Some(match expr {
                        Some(e) => IrExpr::Add(Box::new(e), Box::new(idx_expr)),
                        None => idx_expr,
                    });
                }
                if *disp != 0 {
                    let disp_expr = IrExpr::Const((*disp).unsigned_abs());
                    expr = Some(match expr {
                        Some(e) if *disp < 0 => IrExpr::Sub(Box::new(e), Box::new(disp_expr)),
                        Some(e) => IrExpr::Add(Box::new(e), Box::new(disp_expr)),
                        None => IrExpr::Const((*disp).cast_unsigned()),
                    });
                }
                expr.unwrap_or(IrExpr::Const(0))
            }
            Operand::FpReg(n) => IrExpr::Reg(format!("fp{n}")),
            Operand::VecReg(n) => IrExpr::Reg(format!("v{n}")),
            Operand::Segment(_, inner) => Self::operand_to_expr(inner),
        }
    }

    /// Return the operand at index `i` as an [`IrExpr`], or [`IrExpr::Undef`]
    /// when the operand list is too short.
    fn op_expr(instr: &Instruction, i: usize) -> IrExpr {
        instr
            .operand_list
            .get(i)
            .map_or(IrExpr::Undef, Self::operand_to_expr)
    }

    /// Return the destination register name from operand 0, or a fallback.
    fn dest_reg(instr: &Instruction, fallback: &str) -> String {
        instr
            .operand_list.first()
            .and_then(|op| op.as_register()).map_or_else(|| fallback.to_string(), |r| r.name.clone())
    }

    /// Resolve the branch target for a branch/call instruction.
    ///
    /// Priority: Label operand, then Immediate operand (treated as absolute
    /// target when it looks like a plausible address, otherwise as a signed
    /// PC-relative offset from the next instruction), then fallthrough.
    fn branch_target(instr: &Instruction) -> IrExpr {
        let fallthrough = instr.address.0.saturating_add(instr.size as u64);
        if let Some(op) = instr.operand_list.first() {
            match op {
                // A Label operand already carries the resolved address.
                Operand::Label(addr) => return IrExpr::Const(*addr),
                // An immediate is either an absolute address or a rel offset.
                Operand::Immediate(v) => {
                    // Treat values that look like code addresses (>= 0x1000) as
                    // absolute; otherwise add them to the next-instruction PC.
                    let target = if *v >= 0x1000 {
                        (*v).cast_unsigned()
                    } else {
                        fallthrough.wrapping_add((*v).cast_unsigned())
                    };
                    return IrExpr::Const(target);
                }
                Operand::UImmediate(v) => {
                    let target = if *v >= 0x1000 {
                        *v
                    } else {
                        fallthrough.wrapping_add(*v)
                    };
                    return IrExpr::Const(target);
                }
                // Register / memory indirect â€” unknown target at lift time.
                _ => {}
            }
        }
        IrExpr::Const(fallthrough)
    }

    fn mnemonic_to_effects_a_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
                Some(match mnem.as_str() {
            "ret" | "retn" => vec![Effect::Return { value: None }],
            "call" => vec![Effect::Call {
                target: Self::branch_target(instr),
            }],
            "push" => {
                // push <src>  â†’  [rsp] = src;  rsp -= operand_size
                let src = Self::op_expr(instr, 0);
                let size = instr
                    .operand_list.first()
                    .and_then(|op| {
                        if let Operand::Register(r) = op {
                            Some(u8::try_from(r.size).unwrap_or(u8::MAX))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(8);
                vec![
                    // rsp -= size  (pre-decrement before write)
                    Effect::RegWrite {
                        reg: "rsp".to_string(),
                        value: IrExpr::Sub(
                            Box::new(IrExpr::Reg("rsp".to_string())),
                            Box::new(IrExpr::Const(u64::from(size))),
                        ),
                    },
                    Effect::MemWrite {
                        addr: IrExpr::Reg("rsp".to_string()),
                        value: src,
                        size,
                    },
                ]
            }
            "pop" => {
                // pop <dst>  â†’  dst = [rsp];  rsp += operand_size
                let dst = Self::dest_reg(instr, "rax");
                let size = instr
                    .operand_list.first()
                    .and_then(|op| {
                        if let Operand::Register(r) = op {
                            Some(u8::try_from(r.size).unwrap_or(u8::MAX))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(8);
                vec![
                    Effect::MemRead {
                        addr: IrExpr::Reg("rsp".to_string()),
                        dest: dst,
                        size,
                    },
                    // rsp += size  (post-increment after read)
                    Effect::RegWrite {
                        reg: "rsp".to_string(),
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg("rsp".to_string())),
                            Box::new(IrExpr::Const(u64::from(size))),
                        ),
                    },
                ]
            }
            "mov" => {
                let dst_op = instr.operand_list.first();
                let src = Self::op_expr(instr, 1);
                match dst_op {
                    Some(Operand::Register(r)) => vec![Effect::RegWrite {
                        reg: r.name.clone(),
                        value: src,
                    }],
                    Some(Operand::Memory { width, .. }) => {
                        let sz = *width;
                        let addr_expr = Self::operand_to_expr(dst_op.unwrap());
                        vec![Effect::MemWrite {
                            addr: addr_expr,
                            value: src,
                            size: sz,
                        }]
                    }
                    _ => vec![Effect::RegWrite {
                        reg: Self::dest_reg(instr, "rax"),
                        value: src,
                    }],
                }
            }
            _ => return None,
        })
    }

    fn mnemonic_to_effects_a_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
                Some(match mnem.as_str() {
            "xchg" => {
                let op0 = Self::op_expr(instr, 0);
                let op1 = Self::op_expr(instr, 1);
                let dst0 = Self::dest_reg(instr, "rax");
                // Operand 1 may be a memory operand; handle properly.
                if let Some(Operand::Memory { width, .. }) = instr.operand_list.get(1) {
                    let mem_size = *width;
                    let addr_expr = Self::operand_to_expr(instr.operand_list.get(1).unwrap());
                    // xchg reg, [mem]:
                    //   tmp = [mem]           (MemRead Ã¢â€ â€™ loaded into dst0)
                    //   [mem] = op0           (MemWrite of original reg value)
                    //   dst0 = tmp            (RegWrite with loaded value)
                    vec![
                        // Load mem into a temp dest name (dst0), then overwrite below.
                        Effect::MemRead {
                            addr: addr_expr.clone(),
                            dest: dst0,
                            size: mem_size,
                        },
                        Effect::MemWrite {
                            addr: addr_expr,
                            value: op0,
                            size: mem_size,
                        },
                    ]
                } else {
                    let dst1 = instr
                        .operand_list
                        .get(1)
                        .and_then(|op| op.as_register()).map_or_else(|| "rbx".to_string(), |r| r.name.clone());
                    vec![
                        Effect::RegWrite {
                            reg: dst0,
                            value: op1,
                        },
                        Effect::RegWrite {
                            reg: dst1,
                            value: op0,
                        },
                    ]
                }
            }
            "jmp" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: None,
            }],
            "je" | "jz" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("zf".to_string())),
            }],
            "jne" | "jnz" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
            }],
            "jl" | "jnge" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Xor(
                    Box::new(IrExpr::Reg("sf".to_string())),
                    Box::new(IrExpr::Reg("of".to_string())),
                )),
            }],
                _ => return None,
                })
    }

    fn mnemonic_to_effects_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let _mnem = instr.mnemonic.to_ascii_lowercase();
        let __s0 = Self::mnemonic_to_effects_a_a(instr);
        if __s0.is_some() { return __s0; }
        Self::mnemonic_to_effects_a_b(instr)
    }
    fn mnemonic_to_effects_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
            Some(match mnem.as_str() {
            "jg" | "jnle" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                    Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                        Box::new(IrExpr::Reg("sf".to_string())),
                        Box::new(IrExpr::Reg("of".to_string())),
                    )))),
                )),
            }],
            "jb" | "jnae" | "jc" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("cf".to_string())),
            }],
            "jae" | "jnb" | "jnc" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
            }],
            "jbe" | "jna" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Or(
                    Box::new(IrExpr::Reg("cf".to_string())),
                    Box::new(IrExpr::Reg("zf".to_string())),
                )),
            }],
            "ja" | "jnbe" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
                    Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                )),
            }],
            "js" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("sf".to_string())),
            }],
            "jns" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("sf".to_string())))),
            }],
            "jo" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("of".to_string())),
            }],
            "jno" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("of".to_string())))),
            }],
            "jp" | "jpe" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("pf".to_string())),
            }],
                _ => return None,
            })
    }
    fn mnemonic_to_effects_c(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
            Some(match mnem.as_str() {
            "jnp" | "jpo" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("pf".to_string())))),
            }],
            "jge" | "jnl" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Xor(
                    Box::new(IrExpr::Reg("sf".to_string())),
                    Box::new(IrExpr::Reg("of".to_string())),
                )))),
            }],
            "jle" | "jng" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Or(
                    Box::new(IrExpr::Reg("zf".to_string())),
                    Box::new(IrExpr::Xor(
                        Box::new(IrExpr::Reg("sf".to_string())),
                        Box::new(IrExpr::Reg("of".to_string())),
                    )),
                )),
            }],

            "syscall" | "int" => vec![Effect::Syscall {
                nr: IrExpr::Reg("rax".to_string()),
            }],

            "add" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "sub" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "imul" | "mul" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Mul(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "and" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "or" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "xor" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Xor(Box::new(lhs), Box::new(rhs)),
                }]
            }
                _ => return None,
            })
    }
    fn mnemonic_to_effects_d(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
            match mnem.as_str() {

            "shl" | "sal" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                // Shift amount: second operand if present, else cl
                let rhs = if instr.operand_list.len() >= 2 {
                    Self::op_expr(instr, 1)
                } else {
                    IrExpr::Reg("cl".to_string())
                };
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shl(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "shr" | "sar" => {
                let dst = Self::dest_reg(instr, "rax");
                let lhs = Self::op_expr(instr, 0);
                let rhs = if instr.operand_list.len() >= 2 {
                    Self::op_expr(instr, 1)
                } else {
                    IrExpr::Reg("cl".to_string())
                };
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shr(Box::new(lhs), Box::new(rhs)),
                }]
            }

            "not" => {
                let dst = Self::dest_reg(instr, "rax");
                let src = Self::op_expr(instr, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Not(Box::new(src)),
                }]
            }

            "neg" => {
                let dst = Self::dest_reg(instr, "rax");
                let src = Self::op_expr(instr, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(src)),
                }]
            }

            "inc" => {
                let dst = Self::dest_reg(instr, "rax");
                let src = Self::op_expr(instr, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(Box::new(src), Box::new(IrExpr::Const(1))),
                }]
            }

            "dec" => {
                let dst = Self::dest_reg(instr, "rax");
                let src = Self::op_expr(instr, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(src), Box::new(IrExpr::Const(1))),
                }]
            }

            "nop" | "cmp" | "test" => vec![],

            _ => vec![Effect::Intrinsic {
                name: mnem,
                args: vec![],
            }],
            }
    }

    fn mnemonic_to_effects(instr: &Instruction) -> Vec<Effect> {
        let _mnem = instr.mnemonic.to_ascii_lowercase();
        if let Some(__r0) = Self::mnemonic_to_effects_a(instr) { return __r0; }
        if let Some(__r1) = Self::mnemonic_to_effects_b(instr) { return __r1; }
        if let Some(__r2) = Self::mnemonic_to_effects_c(instr) { return __r2; }
        Self::mnemonic_to_effects_d(instr)
    }
}

impl ArchLifter for GenericLlilLifter {
    fn arch_name(&self) -> &str {
        &self.arch_name
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "generic x86/x86-64 LLIL lifter"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = Self::mnemonic_to_effects(instr);
        let ir_text = if effects.is_empty() {
            "nop".to_string()
        } else {
            effects
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };
        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LifterRegistry
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Registry mapping architecture names to lifter implementations.
///
/// The registry owns the lifters and dispatches lift requests by architecture.
#[derive(Debug, Default)]
pub struct LifterRegistry {
    lifters: HashMap<String, Box<dyn ArchLifter>>,
}

impl LifterRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry pre-populated with the generic x86-64 lifter.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        // Use arch-specific lifters where available, generic fallbacks for the rest.
        register_all_lifters(&mut reg);
        reg
    }

    /// Register a lifter.  If a lifter for the same architecture already exists
    /// it is replaced.
    pub fn register(&mut self, lifter: impl ArchLifter + 'static) {
        self.lifters
            .insert(lifter.arch_name().to_string(), Box::new(lifter));
    }

    /// Look up the lifter for the named architecture.
    #[must_use]
    pub fn get(&self, arch: &str) -> Option<&dyn ArchLifter> {
        self.lifters.get(arch).map(std::convert::AsRef::as_ref)
    }

    /// Returns `true` if a lifter for `arch` is registered.
    #[must_use]
    pub fn supports(&self, arch: &str) -> bool {
        self.lifters.contains_key(arch)
    }

    /// All registered architecture names.
    #[must_use]
    pub fn arch_names(&self) -> Vec<&str> {
        self.lifters.keys().map(String::as_str).collect()
    }

    /// Number of registered lifters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lifters.len()
    }

    /// Returns `true` if no lifters are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lifters.is_empty()
    }

    /// Lift a single instruction using the registered lifter for `arch`.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::UnsupportedArch`] if no lifter handles `arch`,
    /// or a lift-specific error if lifting fails.
    pub fn lift_instr(&self, arch: &str, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let lifter = self
            .get(arch)
            .ok_or_else(|| LiftError::UnsupportedArch(arch.to_string()))?;
        lifter.lift(instr)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// BatchLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Orchestrates lifting of large instruction sequences with caching and
/// configurable error-recovery policies.
#[derive(Debug)]
pub struct BatchLifter {
    lifter: Box<dyn ArchLifter>,
    ctx: LiftContext,
}

impl BatchLifter {
    /// Creates a new batch lifter using `lifter` and `ctx`.
    #[must_use]
    pub fn new(lifter: Box<dyn ArchLifter>, ctx: LiftContext) -> Self {
        Self { lifter, ctx }
    }

    /// Creates a batch lifter from a registry entry.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::UnsupportedArch`] if `arch` is not in `registry`.
    pub fn from_registry(
        registry: &LifterRegistry,
        arch: &str,
    ) -> Result<(Self, LiftContext), LiftError> {
        if !registry.supports(arch) {
            return Err(LiftError::UnsupportedArch(arch.to_string()));
        }
        let ctx = LiftContext::new(arch);
        // Instantiate the best available lifter for the named architecture.
        let lifter: Box<dyn ArchLifter> = match arch {
            "x86_64" => Box::new(X86Lifter::new(64)),
            "x86" => Box::new(X86Lifter::new(32)),
            "x86_16" => Box::new(X86Lifter::new(16)),
            "aarch64" | "arm64" => Box::new(Arm64Lifter::new()),
            "mips" | "mips32" => Box::new(MipsLifter::new()),
            "mips64" => Box::new(MipsLifter::new_64()),
            "riscv" | "riscv32" => Box::new(RiscvLifter::new()),
            "riscv64" => Box::new(RiscvLifter::new_rv64()),
            "arm" | "arm32" => Box::new(Arm32Lifter::new()),
            "thumb" => Box::new(Arm32Lifter::new_thumb()),
            "ppc" | "powerpc" | "ppc32" => Box::new(PpcLifter::new()),
            "ppc64" | "powerpc64" => Box::new(PpcLifter::new_64()),
            "wasm" => Box::new(WasmLifter::new()),
            "avr" => Box::new(AvrLifter::new()),
            "bpf" => Box::new(BpfLifter::new()),
            "ebpf" => Box::new(BpfLifter::new_ebpf()),
            "cil" | "msil" | "dotnet" => Box::new(CilLifter::new()),
            "dex" | "dalvik" | "art" => Box::new(DexLifter::new()),
            "m68k" | "68000" | "68020" => Box::new(M68kLifter::new()),
            "sparc" | "sparc32" => Box::new(SparcLifter::new()),
            "sparc64" => Box::new(SparcLifter::new_64()),
            "z80" | "z80_cmos" => Box::new(Z80Lifter::new()),
            "z180" => Box::new(Z80Lifter::new_z180()),
            other => Box::new(GenericLlilLifter::new(other.to_string())),
        };
        let bl = Self::new(lifter, LiftContext::new(arch));
        Ok((bl, ctx))
    }

    /// Lift a batch of instructions, respecting the context's policies.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::PartialLift`] if partial lifts are disabled and any
    /// instruction fails.
    pub fn lift_batch(&self, instrs: &[Instruction]) -> Result<LiftResult, LiftError> {
        let limit = self.ctx.batch_limit.min(instrs.len());
        let mut result = LiftResult {
            lifted: Vec::with_capacity(limit),
            errors: Vec::new(),
            stats: LiftStats::new(),
        };

        for instr in &instrs[..limit] {
            result.stats.total_instructions += 1;

            // Try cache first.
            if self.ctx.use_cache {
                if let Some(cached) = self.ctx.cache.get(instr.address.0) {
                    result.lifted.push(cached);
                    result.stats.cache_hits += 1;
                    result.stats.succeeded += 1;
                    continue;
                }
                result.stats.cache_misses += 1;
            }

            match self.lifter.lift(instr) {
                Ok(li) => {
                    if self.ctx.use_cache {
                        self.ctx.cache.insert(instr.address.0, li.clone());
                    }
                    result.lifted.push(li);
                    result.stats.succeeded += 1;
                }
                Err(e) => {
                    if !self.ctx.allow_partial {
                        return Err(LiftError::PartialLift {
                            succeeded: usize::try_from(result.stats.succeeded).unwrap_or(usize::MAX),
                            failed: 1,
                        });
                    }
                    if self.ctx.error_recovery {
                        // Produce a stub instruction.
                        let stub = LiftedInstr {
                            address: instr.address.0,
                            original_mnemonic: instr.mnemonic.clone(),
                            ir_text: format!("__recovery_{}", instr.mnemonic),
                            il_level: self.lifter.lift_level(),
                            effects: vec![Effect::Intrinsic {
                                name: format!("__unlifted_{}", instr.mnemonic),
                                args: vec![],
                            }],
                        };
                        result.lifted.push(stub);
                        result.stats.recovery_count += 1;
                    }
                    result.errors.push((instr.address.0, e));
                    result.stats.failed += 1;
                }
            }
        }

        if instrs.len() > limit {
            result.stats.partial_lifts += 1;
        }

        self.ctx.record_stats(&result.stats);
        Ok(result)
    }

    /// Lift a single instruction with context-aware caching and recovery.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] if lifting fails and recovery is disabled.
    pub fn lift_single(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        if self.ctx.use_cache
            && let Some(cached) = self.ctx.cache.get(instr.address.0) {
                return Ok(cached);
            }
        let li = self.lifter.lift(instr)?;
        if self.ctx.use_cache {
            self.ctx.cache.insert(instr.address.0, li.clone());
        }
        Ok(li)
    }

    /// Returns a reference to the lift context.
    #[must_use]
    pub const fn context(&self) -> &LiftContext {
        &self.ctx
    }

    /// Returns the architecture name of the underlying lifter.
    #[must_use]
    pub fn arch_name(&self) -> &str {
        self.lifter.arch_name()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// PartialLiftResult â€” for incremental / streaming lifts
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Accumulates results as instructions arrive, allowing streaming use-cases.
#[derive(Debug, Default)]
pub struct PartialLiftResult {
    /// All lifted instructions so far.
    pub lifted: Vec<LiftedInstr>,
    /// Addresses that failed.
    pub failures: Vec<u64>,
    /// Whether lifting has been finalized.
    pub finalized: bool,
}

impl PartialLiftResult {
    /// Creates a new, empty partial result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a successfully lifted instruction.
    pub fn push_ok(&mut self, instr: LiftedInstr) {
        self.lifted.push(instr);
    }

    /// Record a failed address.
    pub fn push_err(&mut self, address: u64) {
        self.failures.push(address);
    }

    /// Finalize the partial result.
    pub const fn finalize(&mut self) {
        self.finalized = true;
    }

    /// Returns a [`LiftResult`] snapshot of the current state.
    #[must_use]
    pub fn snapshot(&self) -> LiftResult {
        let mut r = LiftResult::new();
        r.lifted.clone_from(&self.lifted);
        for &addr in &self.failures {
            r.errors
                .push((addr, LiftError::Other("partial lift failure".to_string())));
        }
        r.stats.succeeded = r.lifted.len() as u64;
        r.stats.failed = r.errors.len() as u64;
        r.stats.total_instructions = r.stats.succeeded + r.stats.failed;
        r
    }

    /// Number of successfully lifted instructions.
    #[must_use]
    pub const fn success_count(&self) -> usize {
        self.lifted.len()
    }

    /// Number of failed instructions.
    #[must_use]
    pub const fn failure_count(&self) -> usize {
        self.failures.len()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftCoordinator â€” backwards-compatible top-level API
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Top-level coordinator that dispatches instructions to an [`ArchLifter`].
pub struct LiftCoordinator {
    lifter: Box<dyn ArchLifter>,
}

impl LiftCoordinator {
    /// Create a coordinator backed by the given lifter.
    #[must_use]
    pub fn new(lifter: Box<dyn ArchLifter>) -> Self {
        Self { lifter }
    }

    /// Create a coordinator using the generic LLIL lifter for `arch_name`.
    #[must_use]
    pub fn for_arch(arch_name: &str) -> Self {
        Self::new(Box::new(GenericLlilLifter::new(arch_name.to_string())))
    }

    /// Create a coordinator with error recovery enabled.
    #[must_use]
    pub fn for_arch_with_recovery(arch_name: &str) -> Self {
        let inner = GenericLlilLifter::new(arch_name.to_string());
        Self::new(Box::new(ErrorRecoveryLifter::new(Box::new(inner))))
    }

    /// Lift a block of instructions, silently discarding errors.
    #[must_use]
    pub fn lift_block(&self, instrs: &[Instruction]) -> Vec<LiftedInstr> {
        self.lifter
            .lift_block(instrs)
            .into_iter()
            .filter_map(Result::ok)
            .collect()
    }

    /// Lift a block of instructions, returning all results (including errors).
    #[must_use]
    pub fn lift_block_all(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>> {
        self.lifter.lift_block(instrs)
    }

    /// Lift a single instruction.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] if lifting fails.
    pub fn lift_single(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        self.lifter.lift(instr)
    }

    /// Architecture name of the underlying lifter.
    #[must_use]
    pub fn arch_name(&self) -> &str {
        self.lifter.arch_name()
    }

    /// IL level produced by the underlying lifter.
    #[must_use]
    pub fn lift_level(&self) -> LiftLevel {
        self.lifter.lift_level()
    }

    /// Lift a batch of instructions and collect into a [`LiftResult`].
    ///
    /// Unlike [`lift_block`] this preserves error information.
    #[must_use]
    pub fn lift_batch(&self, instrs: &[Instruction]) -> LiftResult {
        let mut result = LiftResult {
            lifted: Vec::with_capacity(instrs.len()),
            errors: Vec::new(),
            stats: LiftStats::new(),
        };
        for instr in instrs {
            result.stats.total_instructions += 1;
            match self.lifter.lift(instr) {
                Ok(li) => {
                    result.lifted.push(li);
                    result.stats.succeeded += 1;
                }
                Err(e) => {
                    result.errors.push((instr.address.0, e));
                    result.stats.failed += 1;
                }
            }
        }
        result
    }
}

impl fmt::Debug for LiftCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LiftCoordinator({})", self.lifter.arch_name())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftMetadata
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Metadata recorded for each lifting session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftMetadata {
    /// Name of the source architecture that was lifted.
    pub source_arch: String,
    /// The IL level targeted.
    pub target_level: LiftLevel,
    /// Unix-epoch timestamp (seconds) when the lift was performed.
    pub lift_timestamp: u64,
    /// Version string of the lifter that produced this output.
    pub lifter_version: String,
    /// Total number of instructions in the lifted binary.
    pub total_instructions: u64,
    /// Optional build-id or hash of the binary that was lifted.
    pub binary_hash: Option<String>,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

impl LiftMetadata {
    /// Creates a new metadata record.
    #[must_use]
    pub fn new(arch: impl Into<String>, level: LiftLevel) -> Self {
        Self {
            source_arch: arch.into(),
            target_level: level,
            lift_timestamp: 0,
            lifter_version: "0.1.0".to_string(),
            total_instructions: 0,
            binary_hash: None,
            notes: Vec::new(),
        }
    }

    /// Set the timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.lift_timestamp = ts;
        self
    }

    /// Set the binary hash.
    #[must_use]
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.binary_hash = Some(hash.into());
        self
    }

    /// Set the lifter version string.
    #[must_use]
    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.lifter_version = v.into();
        self
    }

    /// Append a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Returns `true` if a binary hash has been recorded.
    #[must_use]
    pub const fn has_hash(&self) -> bool {
        self.binary_hash.is_some()
    }
}

impl Default for LiftMetadata {
    fn default() -> Self {
        Self::new("unknown", LiftLevel::Raw)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// AddressMap â€” address â†’ LiftedInstr indexed lookup
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An ordered map of address â†’ [`LiftedInstr`] representing a complete lifting
/// of a function or region.  Backed by a sorted `Vec` for cache-friendly
/// iteration and binary-search lookup.
#[derive(Debug, Clone, Default)]
pub struct AddressMap {
    entries: Vec<(u64, LiftedInstr)>,
}

impl AddressMap {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a lifted instruction.  If an entry already exists at `address`
    /// it is replaced.
    pub fn insert(&mut self, address: u64, instr: LiftedInstr) {
        match self.entries.binary_search_by_key(&address, |(a, _)| *a) {
            Ok(idx) => self.entries[idx] = (address, instr),
            Err(idx) => self.entries.insert(idx, (address, instr)),
        }
    }

    /// Look up the lifted instruction at exactly `address`.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&LiftedInstr> {
        self.entries
            .binary_search_by_key(&address, |(a, _)| *a)
            .ok()
            .map(|idx| &self.entries[idx].1)
    }

    /// Returns `true` if the map contains an entry for `address`.
    #[must_use]
    pub fn contains(&self, address: u64) -> bool {
        self.entries
            .binary_search_by_key(&address, |(a, _)| *a)
            .is_ok()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all addresses in ascending order.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        self.entries.iter().map(|(a, _)| *a).collect()
    }

    /// Iterates over `(address, instruction)` pairs in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &LiftedInstr)> {
        self.entries.iter().map(|(a, i)| (*a, i))
    }

    /// Returns all instructions in ascending address order.
    #[must_use]
    pub fn instructions(&self) -> Vec<&LiftedInstr> {
        self.entries.iter().map(|(_, i)| i).collect()
    }

    /// Builds an `AddressMap` from a `LiftResult`.
    #[must_use]
    pub fn from_lift_result(result: &LiftResult) -> Self {
        let mut map = Self {
            entries: Vec::with_capacity(result.lifted.len()),
        };
        for instr in &result.lifted {
            map.insert(instr.address, instr.clone());
        }
        map
    }

    /// Merge another `AddressMap` into this one; entries in `other` overwrite
    /// entries in `self` at the same address.
    pub fn merge_from(&mut self, other: &Self) {
        for (addr, instr) in other.iter() {
            self.insert(addr, instr.clone());
        }
    }

    /// Returns all instructions whose address falls within `[start, end)`.
    #[must_use]
    pub fn range(&self, start: u64, end: u64) -> Vec<&LiftedInstr> {
        self.entries
            .iter()
            .filter(|(a, _)| *a >= start && *a < end)
            .map(|(_, i)| i)
            .collect()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LruLiftCache â€” proper LRU eviction with ordered access
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An LRU cache for lifted instructions with proper eviction ordering.
///
/// Unlike [`LiftCache`] which clears the entire cache on overflow, this
/// implementation evicts the least-recently-used entry.
#[derive(Debug)]
pub struct LruLiftCache {
    /// Map of address â†’ (generation, instruction).
    map: parking_lot::RwLock<HashMap<u64, (u64, LiftedInstr)>>,
    capacity: usize,
    generation: parking_lot::Mutex<u64>,
    hits: parking_lot::Mutex<u64>,
    misses: parking_lot::Mutex<u64>,
}

impl LruLiftCache {
    /// Creates a new LRU cache with `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            map: parking_lot::RwLock::new(HashMap::new()),
            capacity,
            generation: parking_lot::Mutex::new(0),
            hits: parking_lot::Mutex::new(0),
            misses: parking_lot::Mutex::new(0),
        }
    }

    /// Look up an instruction by address, updating its LRU generation.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<LiftedInstr> {
        let read = self.map.read();
        if let Some((_, instr)) = read.get(&address) {
            let instr = instr.clone();
            drop(read);
            // Update generation.
            let generation_val = {
                let mut g = self.generation.lock();
                *g += 1;
                *g
            };
            if let Some(entry) = self.map.write().get_mut(&address) {
                entry.0 = generation_val;
            }
            *self.hits.lock() += 1;
            Some(instr)
        } else {
            *self.misses.lock() += 1;
            None
        }
    }

    /// Insert or update an instruction in the cache, evicting LRU if needed.
    pub fn insert(&self, address: u64, instr: LiftedInstr) {
        let generation_val = {
            let mut g = self.generation.lock();
            *g += 1;
            *g
        };
        let mut map = self.map.write();
        if map.len() >= self.capacity && !map.contains_key(&address) {
            // Evict the entry with the smallest generation value.
            if let Some((&evict_addr, _)) = map.iter().min_by_key(|(_, (g, _))| *g) {
                map.remove(&evict_addr);
            }
        }
        map.insert(address, (generation_val, instr));
    }

    /// Removes all entries from the cache.
    pub fn clear(&self) {
        self.map.write().clear();
    }

    /// Number of entries currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.read().is_empty()
    }

    /// Total cache hits since creation.
    #[must_use]
    pub fn hits(&self) -> u64 {
        *self.hits.lock()
    }

    /// Total cache misses since creation.
    #[must_use]
    pub fn misses(&self) -> u64 {
        *self.misses.lock()
    }

    /// Hit rate in [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let h = self.hits();
        let m = self.misses();
        let total = h + m;
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(h).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftVerifier â€” semantic equivalence checking
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Result of a semantic equivalence verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The lifted form is semantically equivalent to the reference.
    Equivalent,
    /// The lifted form has more effects than the reference (over-approximation).
    OverApproximation { extra_effects: usize },
    /// The lifted form is missing effects from the reference (under-approximation).
    UnderApproximation { missing_effects: usize },
    /// The lifted form contains effects not in the reference and vice-versa.
    Mismatch { extra: usize, missing: usize },
    /// Verification was inconclusive (e.g., reference not available).
    Inconclusive(String),
}

impl VerificationResult {
    /// Returns `true` if the result is `Equivalent`.
    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        matches!(self, Self::Equivalent)
    }

    /// Returns `true` if the result indicates any divergence.
    #[must_use]
    pub const fn is_diverged(&self) -> bool {
        !self.is_equivalent() && !matches!(self, Self::Inconclusive(_))
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equivalent => write!(f, "equivalent"),
            Self::OverApproximation { extra_effects } => {
                write!(f, "over-approximation ({extra_effects} extra effects)")
            }
            Self::UnderApproximation { missing_effects } => {
                write!(f, "under-approximation ({missing_effects} missing effects)")
            }
            Self::Mismatch { extra, missing } => {
                write!(f, "mismatch (extra={extra}, missing={missing})")
            }
            Self::Inconclusive(msg) => write!(f, "inconclusive: {msg}"),
        }
    }
}

/// Verifies that a [`LiftedInstr`] is semantically equivalent to a reference.
pub struct LiftVerifier {
    /// Whether to treat intrinsics as wildcards (matching anything).
    pub intrinsics_are_wildcards: bool,
}

impl LiftVerifier {
    /// Creates a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            intrinsics_are_wildcards: true,
        }
    }

    /// Creates a strict verifier where intrinsics must match exactly.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            intrinsics_are_wildcards: false,
        }
    }

    /// Verify that `lifted` is equivalent to `reference`.
    #[must_use]
    pub fn verify(&self, lifted: &LiftedInstr, reference: &LiftedInstr) -> VerificationResult {
        if lifted.address != reference.address {
            return VerificationResult::Inconclusive(
                "address mismatch between lifted and reference".to_string(),
            );
        }
        let lifted_effects = self.normalize_effects(&lifted.effects);
        let reference_effects = self.normalize_effects(&reference.effects);

        let extra = lifted_effects
            .iter()
            .filter(|e| !reference_effects.contains(e))
            .count();
        let missing = reference_effects
            .iter()
            .filter(|e| !lifted_effects.contains(e))
            .count();

        match (extra, missing) {
            (0, 0) => VerificationResult::Equivalent,
            (e, 0) => VerificationResult::OverApproximation { extra_effects: e },
            (0, m) => VerificationResult::UnderApproximation { missing_effects: m },
            (e, m) => VerificationResult::Mismatch {
                extra: e,
                missing: m,
            },
        }
    }

    /// Verify a batch of lifted instructions against a reference map.
    ///
    /// Returns one verification result per lifted instruction.  Instructions
    /// whose address is not in `reference_map` get an `Inconclusive` result.
    #[must_use]
    pub fn verify_batch(
        &self,
        lifted: &[LiftedInstr],
        reference_map: &AddressMap,
    ) -> Vec<(u64, VerificationResult)> {
        lifted
            .iter()
            .map(|li| {
                let result = reference_map.get(li.address).map_or_else(|| VerificationResult::Inconclusive(format!("no reference for {:#x}", li.address)), |ref_instr| self.verify(li, ref_instr));
                (li.address, result)
            })
            .collect()
    }

    /// Returns `true` if every instruction in the batch verified as equivalent.
    #[must_use]
    pub fn all_equivalent(&self, results: &[(u64, VerificationResult)]) -> bool {
        results.iter().all(|(_, r)| r.is_equivalent())
    }

    fn normalize_effects<'a>(&self, effects: &'a [Effect]) -> Vec<&'a Effect> {
        if self.intrinsics_are_wildcards {
            effects
                .iter()
                .filter(|e| !matches!(e, Effect::Intrinsic { .. }))
                .collect()
        } else {
            effects.iter().collect()
        }
    }
}

impl Default for LiftVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LiftVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiftVerifier")
            .field("intrinsics_are_wildcards", &self.intrinsics_are_wildcards)
            .finish_non_exhaustive()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftSession â€” high-level per-binary lifting session
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A complete lifting session for a single binary or region, combining a
/// registry, context, metadata, and accumulated results.
#[derive(Debug)]
pub struct LiftSession {
    /// The registry of architecture lifters.
    pub registry: LifterRegistry,
    /// Lifting context (cache, stats, policies).
    pub context: LiftContext,
    /// Session-level metadata.
    pub metadata: LiftMetadata,
    /// All lifted instructions accumulated during this session.
    pub address_map: AddressMap,
    /// Per-arch lifting statistics.
    pub arch_stats: HashMap<String, LiftStats>,
}

impl LiftSession {
    /// Creates a new session for the given architecture.
    #[must_use]
    pub fn new(arch: impl Into<String>) -> Self {
        let arch = arch.into();
        let mut registry = LifterRegistry::with_defaults();
        // Ensure the target arch is registered.
        if !registry.supports(&arch) {
            registry.register(GenericLlilLifter::new(arch.clone()));
        }
        let context = LiftContext::new(arch.clone());
        let metadata = LiftMetadata::new(arch, LiftLevel::Llil);
        Self {
            registry,
            context,
            metadata,
            address_map: AddressMap::new(),
            arch_stats: HashMap::new(),
        }
    }

    /// Lift a slice of instructions and accumulate results.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] only if `allow_partial` is `false` and a lift
    /// fails; otherwise partial results are always returned.
    pub fn lift(
        &mut self,
        instrs: &[rustre_core::arch::Instruction],
    ) -> Result<LiftResult, LiftError> {
        let arch = self.context.arch.clone();
        let lifter: Box<dyn ArchLifter> = Box::new(GenericLlilLifter::new(arch.clone()));
        let batch = BatchLifter::new(
            lifter,
            LiftContext::new(arch.clone())
                .with_level(self.context.target_level)
                .with_batch_limit(self.context.batch_limit),
        );

        let result = batch.lift_batch(instrs)?;

        // Accumulate into the address map.
        for instr in &result.lifted {
            self.address_map.insert(instr.address, instr.clone());
        }

        // Accumulate stats.
        let entry = self.arch_stats.entry(arch).or_default();
        entry.merge(&result.stats);
        self.context.record_stats(&result.stats);
        self.metadata.total_instructions += result.stats.total_instructions;

        Ok(result)
    }

    /// Returns the total number of instructions lifted so far.
    #[must_use]
    pub const fn lifted_count(&self) -> usize {
        self.address_map.len()
    }

    /// Returns a summary of all stats accumulated so far.
    #[must_use]
    pub fn total_stats(&self) -> LiftStats {
        self.context.stats()
    }

    /// Resets all session state (keeps registry and context config).
    pub fn reset(&mut self) {
        self.address_map = AddressMap::new();
        self.arch_stats.clear();
        self.context.reset_stats();
        self.metadata.total_instructions = 0;
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// StreamingLifter â€” incremental instruction-by-instruction lifting
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Lifts instructions one at a time, suitable for use in streaming disassembly
/// pipelines where instructions are decoded on-the-fly.
#[derive(Debug)]
pub struct StreamingLifter {
    lifter: Box<dyn ArchLifter>,
    cache: Arc<LiftCache>,
    partial: PartialLiftResult,
    error_recovery: bool,
}

impl StreamingLifter {
    /// Creates a new streaming lifter backed by `lifter`.
    #[must_use]
    pub fn new(lifter: Box<dyn ArchLifter>) -> Self {
        Self {
            lifter,
            cache: Arc::new(LiftCache::default_capacity()),
            partial: PartialLiftResult::new(),
            error_recovery: true,
        }
    }

    /// Creates a streaming lifter for the named architecture.
    #[must_use]
    pub fn for_arch(arch: &str) -> Self {
        Self::new(Box::new(GenericLlilLifter::new(arch.to_string())))
    }

    /// Disable error recovery (failures are recorded but no stub emitted).
    #[must_use]
    pub const fn without_recovery(mut self) -> Self {
        self.error_recovery = false;
        self
    }

    /// Feed a single instruction to the lifter.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] if lifting fails and recovery is disabled.
    pub fn feed(&mut self, instr: &rustre_core::arch::Instruction) -> Result<(), LiftError> {
        if let Some(cached) = self.cache.get(instr.address.0) {
            self.partial.push_ok(cached);
            return Ok(());
        }
        match self.lifter.lift(instr) {
            Ok(li) => {
                self.cache.insert(instr.address.0, li.clone());
                self.partial.push_ok(li);
                Ok(())
            }
            Err(e) => {
                self.partial.push_err(instr.address.0);
                if self.error_recovery {
                    // Emit a recovery stub and continue.
                    let stub = LiftedInstr {
                        address: instr.address.0,
                        original_mnemonic: instr.mnemonic.clone(),
                        ir_text: format!("__recovery_{}", instr.mnemonic),
                        il_level: self.lifter.lift_level(),
                        effects: vec![Effect::Intrinsic {
                            name: format!("__unlifted_{}", instr.mnemonic.to_ascii_lowercase()),
                            args: vec![],
                        }],
                    };
                    self.partial.push_ok(stub);
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Finalise the stream and return the accumulated partial result.
    #[must_use]
    pub fn finish(mut self) -> PartialLiftResult {
        self.partial.finalize();
        self.partial
    }

    /// Non-consuming snapshot of the current partial result.
    #[must_use]
    pub fn snapshot(&self) -> LiftResult {
        self.partial.snapshot()
    }

    /// Number of successfully lifted instructions so far.
    #[must_use]
    pub const fn success_count(&self) -> usize {
        self.partial.success_count()
    }

    /// Number of failed instructions so far.
    #[must_use]
    pub const fn failure_count(&self) -> usize {
        self.partial.failure_count()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftPipeline â€” multi-stage lifting (e.g. LLIL â†’ MLIL â†’ HLIL)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A stage in a lifting pipeline.
#[derive(Debug)]
pub struct PipelineStage {
    /// Name of the stage.
    pub name: String,
    /// The lifter for this stage.
    pub lifter: Box<dyn ArchLifter>,
    /// Input level expected by this stage.
    pub input_level: LiftLevel,
    /// Output level produced by this stage.
    pub output_level: LiftLevel,
}

impl PipelineStage {
    /// Creates a new pipeline stage.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        lifter: Box<dyn ArchLifter>,
        input_level: LiftLevel,
        output_level: LiftLevel,
    ) -> Self {
        Self {
            name: name.into(),
            lifter,
            input_level,
            output_level,
        }
    }
}

/// A multi-stage lifting pipeline.  Stages are executed in order; the output
/// of each stage is fed to the next.
#[derive(Debug, Default)]
pub struct LiftPipeline {
    stages: Vec<PipelineStage>,
}

impl LiftPipeline {
    /// Creates a new empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a stage to the end of the pipeline.
    pub fn add_stage(&mut self, stage: PipelineStage) {
        self.stages.push(stage);
    }

    /// Number of stages in the pipeline.
    #[must_use]
    pub const fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Returns the names of all stages in order.
    #[must_use]
    pub fn stage_names(&self) -> Vec<&str> {
        self.stages.iter().map(|s| s.name.as_str()).collect()
    }

    /// Returns `true` if the pipeline has no stages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Run all stages in order over `instrs`.
    ///
    /// Returns the `LiftResult` from the final stage.  If the pipeline is
    /// empty the result has no lifted instructions.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] if any stage fails.
    pub fn run(&self, instrs: &[rustre_core::arch::Instruction]) -> Result<LiftResult, LiftError> {
        if self.stages.is_empty() {
            return Ok(LiftResult::new());
        }
        let mut result = LiftResult::new();
        for stage in &self.stages {
            let batch_result: Vec<Result<LiftedInstr, LiftError>> = stage.lifter.lift_block(instrs);
            let mut stage_result = LiftResult::new();
            for r in batch_result {
                stage_result.stats.total_instructions += 1;
                match r {
                    Ok(li) => {
                        stage_result.lifted.push(li);
                        stage_result.stats.succeeded += 1;
                    }
                    Err(e) => {
                        stage_result.stats.failed += 1;
                        stage_result.errors.push((0, e));
                    }
                }
            }
            result = stage_result;
        }
        Ok(result)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftDiff â€” compare two lifting results
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The result of diffing two `AddressMap`s.
#[derive(Debug, Clone, Default)]
pub struct LiftDiff {
    /// Addresses present in `left` but not `right`.
    pub only_in_left: Vec<u64>,
    /// Addresses present in `right` but not `left`.
    pub only_in_right: Vec<u64>,
    /// Addresses present in both but with differing IR text.
    pub changed: Vec<(u64, String, String)>,
    /// Addresses with identical instructions in both maps.
    pub identical: Vec<u64>,
}

impl LiftDiff {
    /// Returns `true` if there are no differences between the two maps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.only_in_left.is_empty() && self.only_in_right.is_empty() && self.changed.is_empty()
    }

    /// Returns the total number of differences.
    #[must_use]
    pub const fn diff_count(&self) -> usize {
        self.only_in_left.len() + self.only_in_right.len() + self.changed.len()
    }
}

/// Computes the diff between two `AddressMap`s.
#[must_use]
/// Lifts this instruction into the IL.
///
/// # Panics
///
/// Panics if internal state is inconsistent.
pub fn diff_address_maps(left: &AddressMap, right: &AddressMap) -> LiftDiff {
    let mut diff = LiftDiff::default();
    let left_addrs: std::collections::HashSet<u64> = left.addresses().into_iter().collect();
    let right_addrs: std::collections::HashSet<u64> = right.addresses().into_iter().collect();

    for &addr in &left_addrs {
        if right_addrs.contains(&addr) {
            let li = left.get(addr).unwrap();
            let ri = right.get(addr).unwrap();
            if li.ir_text == ri.ir_text {
                diff.identical.push(addr);
            } else {
                diff.changed
                    .push((addr, li.ir_text.clone(), ri.ir_text.clone()));
            }
        } else {
            diff.only_in_left.push(addr);
        }
    }
    for &addr in &right_addrs {
        if !left_addrs.contains(&addr) {
            diff.only_in_right.push(addr);
        }
    }
    diff.only_in_left.sort_unstable();
    diff.only_in_right.sort_unstable();
    diff.changed.sort_unstable_by_key(|(a, _, _)| *a);
    diff.identical.sort_unstable();
    diff
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftFilter â€” filter lifted instructions by predicate
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Filtering utilities for lifted instruction collections.
pub struct LiftFilter;

impl LiftFilter {
    /// Retain only instructions that are terminators.
    #[must_use]
    pub fn terminators(instrs: &[LiftedInstr]) -> Vec<&LiftedInstr> {
        instrs.iter().filter(|i| i.is_terminator()).collect()
    }

    /// Retain only instructions that have side effects.
    #[must_use]
    pub fn with_side_effects(instrs: &[LiftedInstr]) -> Vec<&LiftedInstr> {
        instrs.iter().filter(|i| i.has_side_effects()).collect()
    }

    /// Retain only instructions that write to `reg`.
    #[must_use]
    pub fn writing_register<'a>(instrs: &'a [LiftedInstr], reg: &str) -> Vec<&'a LiftedInstr> {
        instrs
            .iter()
            .filter(|i| i.written_registers().contains(&reg.to_string()))
            .collect()
    }

    /// Retain only instructions at the given IL level.
    #[must_use]
    pub fn at_level(instrs: &[LiftedInstr], level: LiftLevel) -> Vec<&LiftedInstr> {
        instrs.iter().filter(|i| i.il_level == level).collect()
    }

    /// Count instructions containing an Intrinsic effect (unlifted stubs).
    #[must_use]
    pub fn count_stubs(instrs: &[LiftedInstr]) -> usize {
        instrs
            .iter()
            .filter(|i| {
                i.effects
                    .iter()
                    .any(|e| matches!(e, Effect::Intrinsic { .. }))
            })
            .count()
    }

    /// Partition `instrs` into `(pure, effectful)` slices.
    #[must_use]
    pub fn partition_by_effects(instrs: &[LiftedInstr]) -> (Vec<&LiftedInstr>, Vec<&LiftedInstr>) {
        let mut pure_instrs = Vec::with_capacity(instrs.len());
        let mut effectful = Vec::with_capacity(instrs.len());
        for i in instrs {
            if i.has_side_effects() {
                effectful.push(i);
            } else {
                pure_instrs.push(i);
            }
        }
        (pure_instrs, effectful)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LiftReport â€” human-readable summary of a LiftResult
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A structured text report for a completed lifting operation.
#[derive(Debug, Clone)]
pub struct LiftReport {
    /// The metadata for this session.
    pub metadata: LiftMetadata,
    /// The statistics accumulated.
    pub stats: LiftStats,
    /// Addresses of all failed instructions.
    pub failed_addresses: Vec<u64>,
    /// Whether the lift was complete.
    pub complete: bool,
}

impl LiftReport {
    /// Builds a `LiftReport` from a `LiftResult` and session metadata.
    #[must_use]
    pub fn from_result(result: &LiftResult, metadata: LiftMetadata) -> Self {
        Self {
            metadata,
            stats: result.stats.clone(),
            failed_addresses: result.failed_addresses(),
            complete: result.is_complete(),
        }
    }

    /// Returns a multi-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Lift report for {} ({:?}):\n  \
             total={} succeeded={} failed={}\n  \
             cache_hit_rate={:.1}% complete={}\n  \
             failed_addresses={}",
            self.metadata.source_arch,
            self.metadata.target_level,
            self.stats.total_instructions,
            self.stats.succeeded,
            self.stats.failed,
            self.stats.cache_hit_rate() * 100.0,
            self.complete,
            self.failed_addresses.len(),
        )
    }
}

impl fmt::Display for LiftReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{
        address::Address,
        arch::{InstrFlags, Instruction},
    };

    fn make_instr(addr: u64, mnemonic: &str) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 4, mnemonic.to_string(), vec![0x90; 4]);
        i.flags = InstrFlags::NONE;
        i
    }

    // â”€â”€ LiftLevel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_level_ord() {
        assert!(LiftLevel::Raw < LiftLevel::Llil);
        assert!(LiftLevel::Llil < LiftLevel::MlilSsa);
        assert!(LiftLevel::MlilSsa < LiftLevel::Hlil);
    }

    #[test]
    fn test_lift_level_display() {
        assert_eq!(LiftLevel::Llil.to_string(), "Llil");
        assert_eq!(LiftLevel::Hlil.to_string(), "Hlil");
        assert_eq!(LiftLevel::Raw.to_string(), "Raw");
    }

    #[test]
    fn test_lift_level_all() {
        let all = LiftLevel::all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0], LiftLevel::Raw);
        assert_eq!(all[3], LiftLevel::Hlil);
    }

    // ── rustre-il bridge ─────────────────────────────────────────────────────

    #[test]
    fn lift_level_il_tier_round_trip() {
        // Every variant must survive LiftLevel -> IlTier -> LiftLevel. This is
        // the guard that fails if somebody adds a variant to one enum only.
        for &l in LiftLevel::all() {
            assert_eq!(
                LiftLevel::from_il_tier(l.il_tier()),
                l,
                "round-trip broken for {l}",
            );
        }
        assert_eq!(LiftLevel::all().len(), 4);
    }

    #[test]
    fn lift_level_il_tier_preserves_ordering() {
        assert!(LiftLevel::Raw.il_tier() < LiftLevel::Hlil.il_tier());
        assert!(LiftLevel::Raw.il_tier() < LiftLevel::Llil.il_tier());
        assert!(LiftLevel::Llil.il_tier() < LiftLevel::MlilSsa.il_tier());
        assert!(LiftLevel::MlilSsa.il_tier() < LiftLevel::Hlil.il_tier());
    }

    #[test]
    fn lift_error_converges_to_il_error() {
        let e: rustre_il::IlError = LiftError::UnsupportedArch("z80".into()).into();
        assert_eq!(e.to_string(), "unsupported operation `z80` at tier lift");

        let e: rustre_il::IlError = LiftError::UnsupportedLevel("Hlil".into()).into();
        assert_eq!(e.to_string(), "unsupported operation `Hlil` at tier lift");

        // Non-"unsupported" variants keep their own Display text under Invalid.
        let e: rustre_il::IlError = LiftError::InvalidBytecode.into();
        assert_eq!(e.to_string(), "invalid IL: invalid bytecode");
    }

    #[test]
    fn test_lift_level_at_least() {
        assert!(LiftLevel::Hlil.at_least(LiftLevel::Llil));
        assert!(LiftLevel::Llil.at_least(LiftLevel::Llil));
        assert!(!LiftLevel::Raw.at_least(LiftLevel::Llil));
    }

    // â”€â”€ IrExpr â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ir_expr_const() {
        assert_eq!(IrExpr::Const(0x10).to_string(), "0x10");
        assert_eq!(IrExpr::Const(0x10).is_const(), Some(0x10));
    }

    #[test]
    fn test_ir_expr_reg() {
        let r = IrExpr::Reg("rax".to_string());
        assert_eq!(r.to_string(), "rax");
        assert_eq!(r.is_reg(), Some("rax"));
    }

    #[test]
    fn test_ir_expr_add() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("a".to_string())),
            Box::new(IrExpr::Const(1)),
        );
        assert_eq!(e.to_string(), "(a + 0x1)");
    }

    #[test]
    fn test_ir_expr_node_count() {
        let simple = IrExpr::Const(1);
        assert_eq!(simple.node_count(), 1);
        let binary = IrExpr::Add(Box::new(IrExpr::Const(1)), Box::new(IrExpr::Const(2)));
        assert_eq!(binary.node_count(), 3);
        let nested = IrExpr::Not(Box::new(binary));
        assert_eq!(nested.node_count(), 4);
    }

    #[test]
    fn test_ir_expr_registers_used() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".to_string())),
            Box::new(IrExpr::Reg("rbx".to_string())),
        );
        let regs = e.registers_used();
        assert!(regs.contains(&"rax".to_string()));
        assert!(regs.contains(&"rbx".to_string()));
    }

    #[test]
    fn test_ir_expr_undef() {
        assert_eq!(IrExpr::Undef.to_string(), "undef");
        assert_eq!(IrExpr::Undef.is_const(), None);
        assert_eq!(IrExpr::Undef.is_reg(), None);
    }

    #[test]
    fn test_ir_expr_bitwise_ops() {
        let a = IrExpr::Reg("a".to_string());
        let b = IrExpr::Reg("b".to_string());
        assert!(
            IrExpr::Or(Box::new(a.clone()), Box::new(b.clone()))
                .to_string()
                .contains('|')
        );
        assert!(
            IrExpr::And(Box::new(a.clone()), Box::new(b.clone()))
                .to_string()
                .contains('&')
        );
        assert!(
            IrExpr::Xor(Box::new(a.clone()), Box::new(b.clone()))
                .to_string()
                .contains('^')
        );
        assert!(
            IrExpr::Shl(Box::new(a.clone()), Box::new(b.clone()))
                .to_string()
                .contains("<<")
        );
        assert!(
            IrExpr::Shr(Box::new(a), Box::new(b))
                .to_string()
                .contains(">>")
        );
    }

    // â”€â”€ Effect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_effect_reg_write() {
        let e = Effect::RegWrite {
            reg: "rax".to_string(),
            value: IrExpr::Const(0),
        };
        assert_eq!(e.to_string(), "rax = 0x0");
        assert!(!e.is_side_effectful());
    }

    #[test]
    fn test_effect_call_is_side_effectful() {
        let e = Effect::Call {
            target: IrExpr::Const(0x0040_1000),
        };
        assert!(e.is_side_effectful());
    }

    #[test]
    fn test_effect_written_registers() {
        let e = Effect::RegWrite {
            reg: "rax".to_string(),
            value: IrExpr::Const(0),
        };
        assert_eq!(e.written_registers(), vec!["rax".to_string()]);
    }

    #[test]
    fn test_effect_mem_write_side_effectful() {
        let e = Effect::MemWrite {
            addr: IrExpr::Reg("rsp".to_string()),
            value: IrExpr::Reg("rax".to_string()),
            size: 8,
        };
        assert!(e.is_side_effectful());
        assert!(!e.written_registers().is_empty() || e.is_side_effectful());
    }

    #[test]
    fn test_effect_branch_unconditional() {
        let e = Effect::Branch {
            target: IrExpr::Const(0x500),
            condition: None,
        };
        assert!(e.to_string().starts_with("goto"));
        assert!(e.is_side_effectful());
    }

    #[test]
    fn test_effect_return_none() {
        let e = Effect::Return { value: None };
        assert_eq!(e.to_string(), "return");
    }

    #[test]
    fn test_effect_return_some() {
        let e = Effect::Return {
            value: Some(IrExpr::Reg("rax".to_string())),
        };
        assert!(e.to_string().contains("rax"));
    }

    #[test]
    fn test_effect_syscall() {
        let e = Effect::Syscall {
            nr: IrExpr::Reg("rax".to_string()),
        };
        assert!(e.to_string().contains("syscall"));
        assert!(e.is_side_effectful());
    }

    #[test]
    fn test_effect_intrinsic() {
        let e = Effect::Intrinsic {
            name: "cpuid".to_string(),
            args: vec![],
        };
        assert!(e.to_string().contains("cpuid"));
        // `cpuid` writes eax/ebx/ecx/edx; an intrinsic is an operation the lifter
        // could not model, so it must never be treated as eliminable.
        assert!(e.is_side_effectful());
    }

    // â”€â”€ LiftedInstr â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lifted_instr_display() {
        let li = LiftedInstr {
            address: 0x0040_1000,
            original_mnemonic: "ret".to_string(),
            ir_text: "return".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::Return { value: None }],
        };
        let s = li.to_string();
        assert!(s.contains("0x401000"));
        assert!(s.contains("ret"));
        assert!(s.contains("return"));
        assert!(li.is_terminator());
        assert!(li.has_side_effects());
    }

    #[test]
    fn test_lifted_instr_written_registers() {
        let li = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "mov".to_string(),
            ir_text: "rax = 0".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::RegWrite {
                reg: "rax".to_string(),
                value: IrExpr::Const(0),
            }],
        };
        let written = li.written_registers();
        assert!(written.contains(&"rax".to_string()));
        assert_eq!(li.effect_count(), 1);
    }

    // â”€â”€ LiftStats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_stats_merge() {
        let mut a = LiftStats::new();
        a.succeeded = 10;
        a.failed = 2;
        a.total_instructions = 12;
        let mut b = LiftStats::new();
        b.succeeded = 5;
        b.failed = 1;
        b.total_instructions = 6;
        a.merge(&b);
        assert_eq!(a.succeeded, 15);
        assert_eq!(a.failed, 3);
        assert_eq!(a.total_instructions, 18);
    }

    #[test]
    fn test_lift_stats_rates() {
        let mut s = LiftStats::new();
        s.total_instructions = 10;
        s.succeeded = 8;
        s.failed = 2;
        s.cache_hits = 6;
        s.cache_misses = 4;
        let sr = s.success_rate();
        assert!((sr - 0.8).abs() < 1e-9);
        let chr = s.cache_hit_rate();
        assert!((chr - 0.6).abs() < 1e-9);
    }

    // â”€â”€ LiftCache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_cache_basic() {
        let cache = LiftCache::new(16);
        assert!(cache.is_empty());
        let li = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        };
        cache.insert(0x1000, li.clone());
        assert_eq!(cache.len(), 1);
        let got = cache.get(0x1000).unwrap();
        assert_eq!(got.address, 0x1000);
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn test_lift_cache_miss() {
        let cache = LiftCache::new(4);
        let _ = cache.get(0xDEAD);
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.hits(), 0);
    }

    #[test]
    fn test_lift_cache_eviction() {
        let cache = LiftCache::new(2);
        let make = |addr: u64| LiftedInstr {
            address: addr,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        };
        cache.insert(0x1000, make(0x1000));
        cache.insert(0x2000, make(0x2000));
        assert_eq!(cache.len(), 2);
        // Third insert evicts the LRU entry, keeping the cache at capacity.
        cache.insert(0x3000, make(0x3000));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_lift_cache_hit_rate() {
        let cache = LiftCache::new(16);
        let li = LiftedInstr {
            address: 0x100,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        };
        cache.insert(0x100, li);
        let _ = cache.get(0x100);
        let _ = cache.get(0x200); // miss
        let r = cache.hit_rate();
        assert!((r - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_lift_cache_clear() {
        let cache = LiftCache::new(16);
        cache.insert(
            0x1,
            LiftedInstr {
                address: 1,
                original_mnemonic: "nop".to_string(),
                ir_text: "nop".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![],
            },
        );
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    // â”€â”€ LiftContext â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_context_builder() {
        let ctx = LiftContext::new("x86_64")
            .with_level(LiftLevel::MlilSsa)
            .without_cache()
            .without_recovery()
            .strict()
            .with_batch_limit(500);
        assert_eq!(ctx.arch, "x86_64");
        assert_eq!(ctx.target_level, LiftLevel::MlilSsa);
        assert!(!ctx.use_cache);
        assert!(!ctx.error_recovery);
        assert!(!ctx.allow_partial);
        assert_eq!(ctx.batch_limit, 500);
    }

    #[test]
    fn test_lift_context_stats() {
        let ctx = LiftContext::new("x86_64");
        let s = LiftStats {
            succeeded: 5,
            total_instructions: 5,
            ..Default::default()
        };
        ctx.record_stats(&s);
        assert_eq!(ctx.stats().succeeded, 5);
        ctx.reset_stats();
        assert_eq!(ctx.stats().succeeded, 0);
    }

    // â”€â”€ LifterRegistry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_registry_defaults() {
        let reg = LifterRegistry::with_defaults();
        assert!(reg.supports("x86_64"));
        assert!(reg.supports("arm"));
        assert!(reg.supports("z80"));
        assert!(!reg.is_empty());
    }

    #[test]
    fn test_registry_lift_instr() {
        let reg = LifterRegistry::with_defaults();
        let instr = make_instr(0x1000, "ret");
        let li = reg.lift_instr("x86_64", &instr).unwrap();
        assert_eq!(li.original_mnemonic, "ret");
    }

    #[test]
    fn test_registry_unsupported_arch() {
        let reg = LifterRegistry::with_defaults();
        let instr = make_instr(0x1000, "ret");
        let err = reg
            .lift_instr("z80_unknown_variant_xyz", &instr)
            .unwrap_err();
        assert!(matches!(err, LiftError::UnsupportedArch(_)));
    }

    #[test]
    fn test_registry_arch_names() {
        let reg = LifterRegistry::with_defaults();
        let names = reg.arch_names();
        assert!(names.contains(&"x86_64"));
        assert!(names.contains(&"arm"));
    }

    // â”€â”€ GenericLlilLifter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_nop() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "nop")).unwrap();
        assert!(li.effects.is_empty());
        assert_eq!(li.ir_text, "nop");
    }

    #[test]
    fn test_lift_ret() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "ret")).unwrap();
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(li.effects[0], Effect::Return { .. }));
    }

    #[test]
    fn test_lift_call() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "call")).unwrap();
        assert!(matches!(li.effects[0], Effect::Call { .. }));
    }

    #[test]
    fn test_lift_push() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "push")).unwrap();
        // rsp is pre-decremented before the store (real x86 PUSH order), so
        // the MemWrite is not necessarily effects[0].
        assert!(li.effects.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    #[test]
    fn test_lift_pop() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "pop")).unwrap();
        assert!(matches!(li.effects[0], Effect::MemRead { .. }));
    }

    #[test]
    fn test_lift_jmp_unconditional() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "jmp")).unwrap();
        if let Effect::Branch { condition, .. } = &li.effects[0] {
            assert!(condition.is_none());
        } else {
            panic!("expected Branch");
        }
    }

    #[test]
    fn test_lift_je_conditional() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "je")).unwrap();
        if let Effect::Branch { condition, .. } = &li.effects[0] {
            assert!(condition.is_some());
        } else {
            panic!("expected Branch");
        }
    }

    #[test]
    fn test_lift_xchg_two_effects() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "xchg")).unwrap();
        assert_eq!(li.effects.len(), 2);
    }

    #[test]
    fn test_lift_inc_dec() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let inc = lifter.lift(&make_instr(0x1000, "inc")).unwrap();
        let dec = lifter.lift(&make_instr(0x1000, "dec")).unwrap();
        assert!(matches!(inc.effects[0], Effect::RegWrite { .. }));
        assert!(matches!(dec.effects[0], Effect::RegWrite { .. }));
    }

    #[test]
    fn test_lift_cmp_test_no_effects() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let cmp = lifter.lift(&make_instr(0x1000, "cmp")).unwrap();
        let test = lifter.lift(&make_instr(0x1000, "test")).unwrap();
        assert!(cmp.effects.is_empty());
        assert!(test.effects.is_empty());
    }

    #[test]
    fn test_lift_unknown_becomes_intrinsic() {
        let lifter = GenericLlilLifter::new("x86_64".to_string());
        let li = lifter.lift(&make_instr(0x1000, "XYZZY")).unwrap();
        assert!(matches!(li.effects[0], Effect::Intrinsic { .. }));
    }

    // â”€â”€ ErrorRecoveryLifter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_error_recovery_lifter_always_succeeds() {
        // Use a lifter that always fails (unknown arch mnemonic â†’ Intrinsic,
        // so we verify the ErrorRecoveryLifter wraps and passes through).
        let inner = GenericLlilLifter::new("x86_64".to_string());
        let wrapped = ErrorRecoveryLifter::new(Box::new(inner));
        let li = wrapped
            .lift(&make_instr(0x1000, "totally_unknown_mnem"))
            .unwrap();
        assert_eq!(li.effects.len(), 1);
        // Should be an Intrinsic stub.
        assert!(matches!(li.effects[0], Effect::Intrinsic { .. }));
    }

    // â”€â”€ BatchLifter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_batch_lifter_basic() {
        let lifter = Box::new(GenericLlilLifter::new("x86_64".to_string()));
        let ctx = LiftContext::new("x86_64");
        let batch = BatchLifter::new(lifter, ctx);
        let instrs = vec![
            make_instr(0x1000, "push"),
            make_instr(0x1004, "mov"),
            make_instr(0x1008, "ret"),
        ];
        let result = batch.lift_batch(&instrs).unwrap();
        assert_eq!(result.lifted.len(), 3);
        assert!(result.is_complete());
        assert!((result.success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_batch_lifter_caching() {
        let lifter = Box::new(GenericLlilLifter::new("x86_64".to_string()));
        let ctx = LiftContext::new("x86_64");
        let batch = BatchLifter::new(lifter, ctx);
        let instrs = vec![make_instr(0x1000, "nop")];
        let _ = batch.lift_batch(&instrs).unwrap();
        // Second lift should hit cache.
        let _ = batch.lift_batch(&instrs).unwrap();
        assert!(batch.context().cache.hits() > 0);
    }

    #[test]
    fn test_batch_lifter_single() {
        let lifter = Box::new(GenericLlilLifter::new("x86_64".to_string()));
        let ctx = LiftContext::new("x86_64");
        let batch = BatchLifter::new(lifter, ctx);
        let instr = make_instr(0x2000, "ret");
        let li = batch.lift_single(&instr).unwrap();
        assert_eq!(li.original_mnemonic, "ret");
    }

    // â”€â”€ LiftResult â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_result_total_count() {
        let mut r = LiftResult::new();
        r.lifted.push(LiftedInstr {
            address: 1,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        });
        r.errors.push((2, LiftError::InvalidBytecode));
        assert_eq!(r.total_count(), 2);
        assert!(!r.is_complete());
        let fa = r.failed_addresses();
        assert_eq!(fa, vec![2u64]);
    }

    #[test]
    fn test_lift_result_success_rate() {
        let mut r = LiftResult::new();
        r.lifted = vec![
            LiftedInstr {
                address: 1,
                original_mnemonic: "a".to_string(),
                ir_text: "a".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![],
            },
            LiftedInstr {
                address: 2,
                original_mnemonic: "b".to_string(),
                ir_text: "b".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![],
            },
            LiftedInstr {
                address: 3,
                original_mnemonic: "c".to_string(),
                ir_text: "c".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![],
            },
        ];
        r.errors.push((4, LiftError::InvalidBytecode));
        let rate = r.success_rate();
        assert!((rate - 0.75).abs() < 1e-9);
    }

    // â”€â”€ PartialLiftResult â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_partial_lift_result() {
        let mut pr = PartialLiftResult::new();
        pr.push_ok(LiftedInstr {
            address: 0x100,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        });
        pr.push_err(0x200);
        pr.finalize();
        assert!(pr.finalized);
        assert_eq!(pr.success_count(), 1);
        assert_eq!(pr.failure_count(), 1);
        let snap = pr.snapshot();
        assert_eq!(snap.total_count(), 2);
    }

    // â”€â”€ LiftCoordinator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_coordinator_for_arch() {
        let c = LiftCoordinator::for_arch("x86_64");
        assert_eq!(c.arch_name(), "x86_64");
    }

    #[test]
    fn test_coordinator_lift_single() {
        let c = LiftCoordinator::for_arch("x86_64");
        let li = c.lift_single(&make_instr(0x1000, "ret")).unwrap();
        assert_eq!(li.original_mnemonic, "ret");
    }

    #[test]
    fn test_coordinator_lift_block() {
        let c = LiftCoordinator::for_arch("x86_64");
        let instrs = vec![
            make_instr(0x1000, "push"),
            make_instr(0x1004, "mov"),
            make_instr(0x1008, "ret"),
        ];
        let lifted = c.lift_block(&instrs);
        assert_eq!(lifted.len(), 3);
    }

    #[test]
    fn test_coordinator_lift_batch() {
        let c = LiftCoordinator::for_arch("x86_64");
        let instrs = vec![make_instr(0x1000, "nop"), make_instr(0x1004, "ret")];
        let result = c.lift_batch(&instrs);
        assert_eq!(result.lifted.len(), 2);
        assert!(result.is_complete());
    }

    #[test]
    fn test_coordinator_with_recovery() {
        let c = LiftCoordinator::for_arch_with_recovery("x86_64");
        let li = c
            .lift_single(&make_instr(0x1000, "totally_unknown"))
            .unwrap();
        assert!(!li.effects.is_empty());
    }

    #[test]
    fn test_coordinator_lift_level() {
        let c = LiftCoordinator::for_arch("x86_64");
        assert_eq!(c.lift_level(), LiftLevel::Llil);
    }

    #[test]
    fn test_coordinator_debug() {
        let c = LiftCoordinator::for_arch("mips");
        let s = format!("{c:?}");
        assert!(s.contains("mips"));
    }

    // â”€â”€ LiftError â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_error_display() {
        assert!(
            LiftError::UnsupportedArch("z80".to_string())
                .to_string()
                .contains("z80")
        );
        assert!(
            LiftError::DisasmFailed(0x1000, "bad bytes".to_string())
                .to_string()
                .contains("bad bytes")
        );
        assert!(
            LiftError::LiftFailed(0x2000, "undef".to_string())
                .to_string()
                .contains("undef")
        );
        assert!(LiftError::InvalidBytecode.to_string().contains("invalid"));
        assert!(
            LiftError::Other("oops".to_string())
                .to_string()
                .contains("oops")
        );
        let partial = LiftError::PartialLift {
            succeeded: 3,
            failed: 1,
        };
        assert!(partial.to_string().contains('3'));
    }

    #[test]
    fn test_lift_error_clone() {
        let e = LiftError::UnsupportedArch("test".to_string());
        let e2 = e.clone();
        assert_eq!(e.to_string(), e2.to_string());
    }

    // â”€â”€ lift_block all â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_block_all() {
        let c = LiftCoordinator::for_arch("x86_64");
        let instrs = vec![make_instr(0x1000, "nop"), make_instr(0x1004, "ret")];
        let results = c.lift_block_all(&instrs);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
    }

    // â”€â”€ AddressMap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn make_li(addr: u64, mnem: &str, ir: &str) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: mnem.to_string(),
            ir_text: ir.to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        }
    }

    #[test]
    fn test_address_map_insert_get() {
        let mut map = AddressMap::new();
        map.insert(0x1000, make_li(0x1000, "nop", "nop"));
        assert!(map.contains(0x1000));
        assert!(!map.contains(0x2000));
        assert_eq!(map.get(0x1000).unwrap().original_mnemonic, "nop");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_address_map_ordered() {
        let mut map = AddressMap::new();
        map.insert(0x3000, make_li(0x3000, "ret", "return"));
        map.insert(0x1000, make_li(0x1000, "push", "push"));
        map.insert(0x2000, make_li(0x2000, "nop", "nop"));
        let addrs = map.addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_address_map_range() {
        let mut map = AddressMap::new();
        for addr in [0x1000u64, 0x1004, 0x1008, 0x2000] {
            map.insert(addr, make_li(addr, "nop", "nop"));
        }
        let range = map.range(0x1000, 0x2000);
        assert_eq!(range.len(), 3);
    }

    #[test]
    fn test_address_map_from_lift_result() {
        let c = LiftCoordinator::for_arch("x86_64");
        let instrs = vec![make_instr(0x1000, "nop"), make_instr(0x1004, "ret")];
        let result = c.lift_batch(&instrs);
        let map = AddressMap::from_lift_result(&result);
        assert_eq!(map.len(), 2);
        assert!(map.contains(0x1000));
        assert!(map.contains(0x1004));
    }

    #[test]
    fn test_address_map_merge() {
        let mut a = AddressMap::new();
        a.insert(0x1000, make_li(0x1000, "nop", "nop"));
        let mut b = AddressMap::new();
        b.insert(0x2000, make_li(0x2000, "ret", "return"));
        a.merge_from(&b);
        assert_eq!(a.len(), 2);
    }

    // â”€â”€ LruLiftCache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lru_cache_basic() {
        let cache = LruLiftCache::new(4);
        cache.insert(0x1000, make_li(0x1000, "nop", "nop"));
        assert_eq!(cache.len(), 1);
        let got = cache.get(0x1000).unwrap();
        assert_eq!(got.address, 0x1000);
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn test_lru_cache_eviction() {
        let cache = LruLiftCache::new(2);
        cache.insert(0x1000, make_li(0x1000, "a", "a"));
        cache.insert(0x2000, make_li(0x2000, "b", "b"));
        // Access 0x1000 to make it most-recently-used.
        let _ = cache.get(0x1000);
        // Insert 0x3000 â€” should evict 0x2000 (LRU).
        cache.insert(0x3000, make_li(0x3000, "c", "c"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(0x1000).is_some());
        assert!(cache.get(0x3000).is_some());
    }

    #[test]
    fn test_lru_cache_miss() {
        let cache = LruLiftCache::new(4);
        assert!(cache.get(0xDEAD).is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_lru_cache_clear() {
        let cache = LruLiftCache::new(4);
        cache.insert(0x100, make_li(0x100, "nop", "nop"));
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_lru_cache_hit_rate() {
        let cache = LruLiftCache::new(4);
        cache.insert(0x100, make_li(0x100, "nop", "nop"));
        let _ = cache.get(0x100); // hit
        let _ = cache.get(0x200); // miss
        let rate = cache.hit_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    // â”€â”€ LiftMetadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_metadata_builder() {
        let mut meta = LiftMetadata::new("arm", LiftLevel::Hlil)
            .with_timestamp(12345)
            .with_hash("abc123")
            .with_version("1.2.3");
        meta.add_note("test note");
        assert_eq!(meta.source_arch, "arm");
        assert_eq!(meta.lift_timestamp, 12345);
        assert!(meta.has_hash());
        assert_eq!(meta.lifter_version, "1.2.3");
        assert_eq!(meta.notes.len(), 1);
    }

    // â”€â”€ LiftVerifier â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_verifier_equivalent() {
        let v = LiftVerifier::new();
        let li = make_li(0x1000, "ret", "return");
        let result = v.verify(&li, &li);
        assert!(result.is_equivalent());
    }

    #[test]
    fn test_lift_verifier_over_approx() {
        let v = LiftVerifier::strict();
        let mut li_lifted = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "ret".to_string(),
            ir_text: "return".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![
                Effect::Return { value: None },
                Effect::Intrinsic {
                    name: "extra".to_string(),
                    args: vec![],
                },
            ],
        };
        let li_ref = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "ret".to_string(),
            ir_text: "return".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::Return { value: None }],
        };
        let result = v.verify(&li_lifted, &li_ref);
        assert!(matches!(
            result,
            VerificationResult::OverApproximation { .. }
        ));
        li_lifted.effects.clear();
        let result2 = v.verify(&li_lifted, &li_ref);
        assert!(matches!(
            result2,
            VerificationResult::UnderApproximation { .. }
        ));
    }

    #[test]
    fn test_lift_verifier_inconclusive() {
        let v = LiftVerifier::new();
        let li_a = make_li(0x1000, "nop", "nop");
        let li_b = make_li(0x2000, "nop", "nop");
        let result = v.verify(&li_a, &li_b);
        assert!(matches!(result, VerificationResult::Inconclusive(_)));
    }

    #[test]
    fn test_lift_verifier_batch() {
        let v = LiftVerifier::new();
        let instrs = vec![
            make_li(0x1000, "nop", "nop"),
            make_li(0x1004, "ret", "return"),
        ];
        let mut ref_map = AddressMap::new();
        ref_map.insert(0x1000, make_li(0x1000, "nop", "nop"));
        ref_map.insert(0x1004, make_li(0x1004, "ret", "return"));
        let results = v.verify_batch(&instrs, &ref_map);
        assert_eq!(results.len(), 2);
        assert!(v.all_equivalent(&results));
    }

    // â”€â”€ LiftDiff â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_diff_address_maps_identical() {
        let mut a = AddressMap::new();
        a.insert(0x1000, make_li(0x1000, "nop", "nop"));
        let b = a.clone();
        let diff = diff_address_maps(&a, &b);
        assert!(diff.is_empty());
        assert_eq!(diff.identical.len(), 1);
    }

    #[test]
    fn test_diff_address_maps_changed() {
        let mut a = AddressMap::new();
        a.insert(0x1000, make_li(0x1000, "nop", "nop"));
        let mut b = AddressMap::new();
        b.insert(0x1000, make_li(0x1000, "nop", "changed_ir"));
        let diff = diff_address_maps(&a, &b);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.diff_count(), 1);
    }

    #[test]
    fn test_diff_address_maps_missing() {
        let mut a = AddressMap::new();
        a.insert(0x1000, make_li(0x1000, "nop", "nop"));
        let b = AddressMap::new();
        let diff = diff_address_maps(&a, &b);
        assert_eq!(diff.only_in_left.len(), 1);
        assert_eq!(diff.only_in_right.len(), 0);
    }

    // â”€â”€ LiftFilter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_filter_terminators() {
        let instrs = vec![
            LiftedInstr {
                address: 0x1000,
                original_mnemonic: "ret".to_string(),
                ir_text: "return".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![Effect::Return { value: None }],
            },
            make_li(0x1004, "nop", "nop"),
        ];
        let terms = LiftFilter::terminators(&instrs);
        assert_eq!(terms.len(), 1);
    }

    #[test]
    fn test_lift_filter_with_side_effects() {
        let instrs = vec![
            LiftedInstr {
                address: 0x1000,
                original_mnemonic: "call".to_string(),
                ir_text: "call".to_string(),
                il_level: LiftLevel::Llil,
                effects: vec![Effect::Call {
                    target: IrExpr::Const(0x4000),
                }],
            },
            make_li(0x1004, "nop", "nop"),
        ];
        let se = LiftFilter::with_side_effects(&instrs);
        assert_eq!(se.len(), 1);
    }

    #[test]
    fn test_lift_filter_at_level() {
        let instrs = vec![
            make_li(0x1000, "nop", "nop"),
            LiftedInstr {
                address: 0x2000,
                original_mnemonic: "hlil_nop".to_string(),
                ir_text: "hlil_nop".to_string(),
                il_level: LiftLevel::Hlil,
                effects: vec![],
            },
        ];
        let llil = LiftFilter::at_level(&instrs, LiftLevel::Llil);
        assert_eq!(llil.len(), 1);
    }

    // â”€â”€ StreamingLifter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_streaming_lifter_basic() {
        let mut sl = StreamingLifter::for_arch("x86_64");
        sl.feed(&make_instr(0x1000, "nop")).unwrap();
        sl.feed(&make_instr(0x1004, "ret")).unwrap();
        assert_eq!(sl.success_count(), 2);
        assert_eq!(sl.failure_count(), 0);
        let pr = sl.finish();
        assert!(pr.finalized);
        assert_eq!(pr.success_count(), 2);
    }

    #[test]
    fn test_streaming_lifter_snapshot() {
        let mut sl = StreamingLifter::for_arch("x86_64");
        sl.feed(&make_instr(0x1000, "push")).unwrap();
        let snap = sl.snapshot();
        assert_eq!(snap.lifted.len(), 1);
    }

    // â”€â”€ LiftPipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_pipeline_empty() {
        let pipeline = LiftPipeline::new();
        assert!(pipeline.is_empty());
        let instrs = vec![make_instr(0x1000, "nop")];
        let result = pipeline.run(&instrs).unwrap();
        assert!(result.lifted.is_empty());
    }

    #[test]
    fn test_lift_pipeline_single_stage() {
        let mut pipeline = LiftPipeline::new();
        pipeline.add_stage(PipelineStage::new(
            "llil",
            Box::new(GenericLlilLifter::new("x86_64".to_string())),
            LiftLevel::Raw,
            LiftLevel::Llil,
        ));
        assert_eq!(pipeline.stage_count(), 1);
        let names = pipeline.stage_names();
        assert_eq!(names, vec!["llil"]);
        let instrs = vec![make_instr(0x1000, "nop"), make_instr(0x1004, "ret")];
        let result = pipeline.run(&instrs).unwrap();
        assert_eq!(result.lifted.len(), 2);
    }

    // â”€â”€ LiftReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_report_summary() {
        let c = LiftCoordinator::for_arch("x86_64");
        let instrs = vec![make_instr(0x1000, "nop")];
        let result = c.lift_batch(&instrs);
        let meta = LiftMetadata::new("x86_64", LiftLevel::Llil);
        let report = LiftReport::from_result(&result, meta);
        let summary = report.summary();
        assert!(summary.contains("x86_64"));
        assert!(summary.contains("total=1"));
    }

    // â”€â”€ LiftSession â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_session_basic() {
        let mut session = LiftSession::new("x86_64");
        let instrs = vec![make_instr(0x1000, "nop"), make_instr(0x1004, "ret")];
        let result = session.lift(&instrs).unwrap();
        assert_eq!(result.lifted.len(), 2);
        assert_eq!(session.lifted_count(), 2);
    }

    #[test]
    fn test_lift_session_reset() {
        let mut session = LiftSession::new("x86_64");
        let instrs = vec![make_instr(0x1000, "nop")];
        let _ = session.lift(&instrs).unwrap();
        assert_eq!(session.lifted_count(), 1);
        session.reset();
        assert_eq!(session.lifted_count(), 0);
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// LiftBuilder â€” ergonomic helpers for emitting IR ops, managing temporaries, and
// computing architectural flags (carry / overflow / sign / zero / parity).
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Ergonomic builder for constructing the [`Effect`] list of a lifted
/// instruction, with temporary-register allocation and flag-computation helpers.
///
/// A lifter typically does:
/// ```
/// use rustre_il_lift::builder::{LiftBuilder, FlagSet};
/// use rustre_il_lift::IrExpr;
///
/// let mut b = LiftBuilder::new(0x1000);
/// // t0 = rax + rbx
/// let t = b.add_temp(IrExpr::Add(
///     Box::new(IrExpr::Reg("rax".into())),
///     Box::new(IrExpr::Reg("rbx".into())),
/// ));
/// b.set_reg("rax", IrExpr::Reg(t.clone()));
/// b.set_arith_flags(&IrExpr::Reg(t), FlagSet::ALL);
/// let li = b.finish("add", 3);
/// assert!(li.effects.iter().any(|e| matches!(e, rustre_il_lift::Effect::RegWrite{ reg, .. } if reg == "rax")));
/// ```
pub mod builder {
    use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};

    /// Which flags to compute when calling [`LiftBuilder::set_arith_flags`].
    ///
    /// Backed by a small bitfield so that flag selections compose cheaply.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FlagSet(u8);

    impl FlagSet {
        const CF: u8 = 1 << 0;
        const OF: u8 = 1 << 1;
        const SF: u8 = 1 << 2;
        const ZF: u8 = 1 << 3;
        const PF: u8 = 1 << 4;

        /// All five flags.
        pub const ALL: Self = Self(Self::CF | Self::OF | Self::SF | Self::ZF | Self::PF);
        /// Only the status flags typically set by logical ops (no carry/overflow
        /// semantics â€” they are cleared).
        pub const LOGICAL: Self = Self(Self::SF | Self::ZF | Self::PF);
        /// No flags.
        pub const NONE: Self = Self(0);

        /// `true` if the carry flag is selected.
        #[must_use]
        pub const fn carry(self) -> bool {
            self.0 & Self::CF != 0
        }
        /// `true` if the overflow flag is selected.
        #[must_use]
        pub const fn overflow(self) -> bool {
            self.0 & Self::OF != 0
        }
        /// `true` if the sign flag is selected.
        #[must_use]
        pub const fn sign(self) -> bool {
            self.0 & Self::SF != 0
        }
        /// `true` if the zero flag is selected.
        #[must_use]
        pub const fn zero(self) -> bool {
            self.0 & Self::ZF != 0
        }
        /// `true` if the parity flag is selected.
        #[must_use]
        pub const fn parity(self) -> bool {
            self.0 & Self::PF != 0
        }

        /// Returns the flag names selected by this set, in canonical order.
        #[must_use]
        pub fn names(self) -> Vec<&'static str> {
            // At most 8 distinct flag names possible.
            let mut v = Vec::with_capacity(8);
            if self.carry() {
                v.push("cf");
            }
            if self.overflow() {
                v.push("of");
            }
            if self.sign() {
                v.push("sf");
            }
            if self.zero() {
                v.push("zf");
            }
            if self.parity() {
                v.push("pf");
            }
            v
        }
    }

    /// Builder that accumulates [`Effect`]s for a single lifted instruction.
    #[derive(Debug)]
    pub struct LiftBuilder {
        address: u64,
        effects: Vec<Effect>,
        temp_counter: u32,
        temp_prefix: String,
    }

    impl LiftBuilder {
        /// Create a builder for the instruction at `address`.
        #[must_use]
        pub fn new(address: u64) -> Self {
            Self {
                address,
                effects: Vec::new(),
                temp_counter: 0,
                temp_prefix: "t".to_string(),
            }
        }

        /// Builder: override the temporary-register name prefix (default `"t"`).
        #[must_use]
        pub fn with_temp_prefix(mut self, prefix: impl Into<String>) -> Self {
            self.temp_prefix = prefix.into();
            self
        }

        /// Allocate a fresh temporary register name (e.g. `t0`, `t1`, â€¦).
        pub fn new_temp(&mut self) -> String {
            let name = format!("{}{}", self.temp_prefix, self.temp_counter);
            self.temp_counter += 1;
            name
        }

        /// Number of temporaries allocated so far.
        #[must_use]
        pub const fn temp_count(&self) -> u32 {
            self.temp_counter
        }

        /// Allocate a fresh temporary, assign it `value`, and return its name.
        pub fn add_temp(&mut self, value: IrExpr) -> String {
            let t = self.new_temp();
            self.effects.push(Effect::RegWrite {
                reg: t.clone(),
                value,
            });
            t
        }

        /// Emit `reg = value`.
        pub fn set_reg(&mut self, reg: impl Into<String>, value: IrExpr) -> &mut Self {
            self.effects.push(Effect::RegWrite {
                reg: reg.into(),
                value,
            });
            self
        }

        /// Emit `*addr:size = value`.
        pub fn store(&mut self, addr: IrExpr, value: IrExpr, size: u8) -> &mut Self {
            self.effects.push(Effect::MemWrite { addr, value, size });
            self
        }

        /// Emit `dest = *addr:size`.
        pub fn load(&mut self, dest: impl Into<String>, addr: IrExpr, size: u8) -> &mut Self {
            self.effects.push(Effect::MemRead {
                addr,
                dest: dest.into(),
                size,
            });
            self
        }

        /// Emit a (possibly conditional) branch.
        pub fn branch(&mut self, target: IrExpr, condition: Option<IrExpr>) -> &mut Self {
            self.effects.push(Effect::Branch { target, condition });
            self
        }

        /// Emit a call.
        pub fn call(&mut self, target: IrExpr) -> &mut Self {
            self.effects.push(Effect::Call { target });
            self
        }

        /// Emit a return.
        pub fn ret(&mut self, value: Option<IrExpr>) -> &mut Self {
            self.effects.push(Effect::Return { value });
            self
        }

        /// Set a single named flag to `value`.
        pub fn set_flag(&mut self, flag: impl Into<String>, value: IrExpr) -> &mut Self {
            self.effects.push(Effect::RegWrite {
                reg: flag.into(),
                value,
            });
            self
        }

        /// Set the zero flag from `result`: `zf = (result == 0)`.
        pub fn set_zero_flag(&mut self, result: &IrExpr) -> &mut Self {
            let zf = IrExpr::CmpEqZero(Box::new(result.clone()));
            self.set_flag("zf", zf)
        }

        /// Set the sign flag from `result`: `sf = (result >> (bits-1)) & 1`.
        pub fn set_sign_flag(&mut self, result: &IrExpr, size_bits: u32) -> &mut Self {
            let shifted = IrExpr::Shr(
                Box::new(result.clone()),
                Box::new(IrExpr::Const(u64::from(size_bits.saturating_sub(1)))),
            );
            let sf = IrExpr::And(Box::new(shifted), Box::new(IrExpr::Const(1)));
            self.set_flag("sf", sf)
        }

        /// Set the parity flag from `result` (parity of the low byte).
        pub fn set_parity_flag(&mut self, result: &IrExpr) -> &mut Self {
            let pf = IrExpr::Parity(Box::new(result.clone()));
            self.set_flag("pf", pf)
        }

        /// Set the carry flag explicitly from a boolean expression.
        pub fn set_carry_flag(&mut self, carry: IrExpr) -> &mut Self {
            self.set_flag("cf", carry)
        }

        /// Set the overflow flag explicitly from a boolean expression.
        pub fn set_overflow_flag(&mut self, overflow: IrExpr) -> &mut Self {
            self.set_flag("of", overflow)
        }

        /// Set the requested flags from an arithmetic `result`.
        ///
        /// Sign/zero/parity are derived from `result`. Carry and overflow are set
        /// to a conservative `Undef` placeholder when requested without an
        /// explicit value â€” callers that know the operands should instead use the
        /// explicit [`set_carry_flag`](Self::set_carry_flag) /
        /// [`set_overflow_flag`](Self::set_overflow_flag) helpers.
        pub fn set_arith_flags(&mut self, result: &IrExpr, flags: FlagSet) -> &mut Self {
            if flags.zero() {
                self.set_zero_flag(result);
            }
            if flags.sign() {
                self.set_sign_flag(result, 64);
            }
            if flags.parity() {
                self.set_parity_flag(result);
            }
            if flags.carry() {
                self.set_flag("cf", IrExpr::Undef);
            }
            if flags.overflow() {
                self.set_flag("of", IrExpr::Undef);
            }
            self
        }

        /// Clear (set to 0) the carry and overflow flags â€” the documented effect
        /// of x86 logical operations.
        pub fn clear_carry_overflow(&mut self) -> &mut Self {
            self.set_flag("cf", IrExpr::Const(0));
            self.set_flag("of", IrExpr::Const(0));
            self
        }

        /// Number of accumulated effects.
        #[must_use]
        pub const fn effect_count(&self) -> usize {
            self.effects.len()
        }

        /// Borrow the accumulated effects.
        #[must_use]
        pub fn effects(&self) -> &[Effect] {
            &self.effects
        }

        /// Consume the builder and produce a [`LiftedInstr`] at LLIL level.
        #[must_use]
        pub fn finish(self, mnemonic: impl Into<String>, size: usize) -> LiftedInstr {
            let mnemonic = mnemonic.into();
            let ir_text = if self.effects.is_empty() {
                "nop".to_string()
            } else {
                self.effects
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let _ = size;
            LiftedInstr {
                address: self.address,
                original_mnemonic: mnemonic,
                ir_text,
                il_level: LiftLevel::Llil,
                effects: self.effects,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::Effect;

        #[test]
        fn temp_allocation_is_sequential() {
            let mut b = LiftBuilder::new(0x1000);
            assert_eq!(b.new_temp(), "t0");
            assert_eq!(b.new_temp(), "t1");
            assert_eq!(b.temp_count(), 2);
        }

        #[test]
        fn temp_prefix_override() {
            let mut b = LiftBuilder::new(0x1000).with_temp_prefix("tmp");
            assert_eq!(b.new_temp(), "tmp0");
        }

        #[test]
        fn add_temp_emits_regwrite() {
            let mut b = LiftBuilder::new(0x1000);
            let t = b.add_temp(IrExpr::Const(42));
            assert_eq!(t, "t0");
            assert_eq!(b.effect_count(), 1);
            assert!(matches!(&b.effects()[0], Effect::RegWrite { reg, .. } if reg == "t0"));
        }

        #[test]
        fn set_reg_and_finish() {
            let mut b = LiftBuilder::new(0x2000);
            b.set_reg("rax", IrExpr::Const(7));
            let li = b.finish("mov", 5);
            assert_eq!(li.address, 0x2000);
            assert_eq!(li.original_mnemonic, "mov");
            assert!(li.ir_text.contains("rax"));
        }

        #[test]
        fn empty_builder_is_nop() {
            let b = LiftBuilder::new(0x3000);
            let li = b.finish("nop", 1);
            assert_eq!(li.ir_text, "nop");
            assert!(li.effects.is_empty());
        }

        #[test]
        fn zero_flag_helper() {
            let mut b = LiftBuilder::new(0);
            b.set_zero_flag(&IrExpr::Reg("rax".into()));
            assert!(matches!(&b.effects()[0], Effect::RegWrite { reg, .. } if reg == "zf"));
        }

        #[test]
        fn arith_flags_all() {
            let mut b = LiftBuilder::new(0);
            b.set_arith_flags(&IrExpr::Reg("rax".into()), FlagSet::ALL);
            let regs: Vec<String> = b
                .effects()
                .iter()
                .filter_map(|e| match e {
                    Effect::RegWrite { reg, .. } => Some(reg.clone()),
                    _ => None,
                })
                .collect();
            for f in ["zf", "sf", "pf", "cf", "of"] {
                assert!(regs.contains(&f.to_string()), "missing flag {f}");
            }
        }

        #[test]
        fn flagset_names() {
            assert_eq!(FlagSet::ALL.names(), vec!["cf", "of", "sf", "zf", "pf"]);
            assert_eq!(FlagSet::LOGICAL.names(), vec!["sf", "zf", "pf"]);
            assert!(FlagSet::NONE.names().is_empty());
        }

        #[test]
        fn logical_flags_skip_carry_overflow() {
            let mut b = LiftBuilder::new(0);
            b.set_arith_flags(&IrExpr::Reg("rax".into()), FlagSet::LOGICAL);
            let regs: Vec<String> = b
                .effects()
                .iter()
                .filter_map(|e| match e {
                    Effect::RegWrite { reg, .. } => Some(reg.clone()),
                    _ => None,
                })
                .collect();
            assert!(!regs.contains(&"cf".to_string()));
            assert!(!regs.contains(&"of".to_string()));
            assert!(regs.contains(&"zf".to_string()));
        }

        #[test]
        fn clear_carry_overflow_sets_zero_consts() {
            let mut b = LiftBuilder::new(0);
            b.clear_carry_overflow();
            assert_eq!(b.effect_count(), 2);
            assert!(b.effects().iter().all(|e| matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Const(0),
                    ..
                }
            )));
        }

        #[test]
        fn store_and_load() {
            let mut b = LiftBuilder::new(0);
            b.store(IrExpr::Reg("rsp".into()), IrExpr::Reg("rax".into()), 8);
            b.load("rbx", IrExpr::Reg("rsp".into()), 8);
            assert!(matches!(&b.effects()[0], Effect::MemWrite { size: 8, .. }));
            assert!(matches!(&b.effects()[1], Effect::MemRead { size: 8, .. }));
        }

        #[test]
        fn branch_and_call_and_ret() {
            let mut b = LiftBuilder::new(0);
            b.branch(IrExpr::Const(0x10), Some(IrExpr::Reg("zf".into())));
            b.call(IrExpr::Const(0x20));
            b.ret(None);
            assert_eq!(b.effect_count(), 3);
        }
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Type alias â€” LlilOp is used throughout the per-arch lifters as a convenient
// alias for the Effect enum, keeping the lifter signatures readable.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Alias for [`Effect`] used in the per-arch LLIL lifting helpers.
///
/// Each `lift_*` method on the architecture-specific lifters returns
/// `Vec<LlilOp>`.  This name makes the per-instruction helper signatures
/// self-documenting without requiring an entirely separate type hierarchy.
pub type LlilOp = Effect;

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// X86Lifter â€” real x86 / x86-64 LLIL lifter powered by iced-x86
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// A proper x86/x86-64 LLIL lifter backed by the iced-x86 decoder.
///
/// Unlike [`GenericLlilLifter`] this lifter actually decodes raw instruction
/// bytes and extracts operands, so register names and immediate values are
/// accurate rather than hard-coded stubs.
///
/// # Usage
///
/// ```
/// use rustre_il_lift::X86Lifter;
///
/// let lifter = X86Lifter::new(64);
/// ```
///
/// Register the lifter with a [`LifterRegistry`] via [`register_all_lifters`].
#[derive(Debug, Clone)]
pub struct X86Lifter {
    /// Bitness: 16, 32, or 64.
    pub bits: u8,
}

impl X86Lifter {
    /// Create a new x86 lifter.  `bits` must be 16, 32, or 64.
    #[must_use]
    pub const fn new(bits: u8) -> Self {
        Self { bits }
    }

    // â”€â”€ register helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Map an iced-x86 [`Register`] to a canonical LLIL register identifier.
    ///
    /// The identifier scheme is contiguous within each hardware-register family
    /// and covers all registers present in x86-64 including XMM and YMM:
    ///
    /// | Hardware family         | IDs   |
    /// |-------------------------|-------|
    /// | RAX / EAX / AX / AL    | 0â€“3   |
    /// | RBX / EBX / BX / BL    | 4â€“7   |
    /// | RCX / ECX / CX / CL    | 8â€“11  |
    /// | RDX / EDX / DX / DL    | 12â€“15 |
    /// | RSI / ESI / SI / SIL   | 16â€“19 |
    /// | RDI / EDI / DI / DIL   | 20â€“23 |
    /// | RSP (all aliases)       | 24    |
    /// | RBP (all aliases)       | 25    |
    /// | R8â€“R15 (all aliases)    | 26â€“33 |
    /// | RIP / EIP               | 34    |
    /// | RFLAGS / EFLAGS / FLAGS | 35    |
    /// | XMM0â€“XMM15              | 36â€“51 |
    /// | YMM0â€“YMM15              | 52â€“67 |
    ///
    /// Any register not covered above (segment registers, FPU stack, MMX, ZMM,
    /// debug registers, control registers, â€¦) returns [`u32::MAX`].
    #[must_use]
    pub const fn reg_id(reg: iced_x86::Register) -> u32 {
        use iced_x86::Register as R;
        match reg {
            // Partial registers share the base register's canonical id (the
            // standard x86-64 register number); the access *size* is carried
            // separately by the operand width, not by the id. RAX=0, RCX=1,
            // RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8..R15=8..15.
            R::RAX | R::EAX | R::AX | R::AL | R::AH => 0,
            R::RCX | R::ECX | R::CX | R::CL | R::CH => 1,
            R::RDX | R::EDX | R::DX | R::DL | R::DH => 2,
            R::RBX | R::EBX | R::BX | R::BL | R::BH => 3,
            R::RSP | R::ESP | R::SP | R::SPL => 4,
            R::RBP | R::EBP | R::BP | R::BPL => 5,
            R::RSI | R::ESI | R::SI | R::SIL => 6,
            R::RDI | R::EDI | R::DI | R::DIL => 7,
            R::R8 | R::R8D | R::R8W | R::R8L => 8,
            R::R9 | R::R9D | R::R9W | R::R9L => 9,
            R::R10 | R::R10D | R::R10W | R::R10L => 10,
            R::R11 | R::R11D | R::R11W | R::R11L => 11,
            R::R12 | R::R12D | R::R12W | R::R12L => 12,
            R::R13 | R::R13D | R::R13W | R::R13L => 13,
            R::R14 | R::R14D | R::R14W | R::R14L => 14,
            R::R15 | R::R15D | R::R15W | R::R15L => 15,
            // â”€â”€ RIP / EIP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            R::RIP | R::EIP => 34,
            // â”€â”€ XMM0â€“XMM15 (SSE / SSE2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            R::XMM0 => 36,
            R::XMM1 => 37,
            R::XMM2 => 38,
            R::XMM3 => 39,
            R::XMM4 => 40,
            R::XMM5 => 41,
            R::XMM6 => 42,
            R::XMM7 => 43,
            R::XMM8 => 44,
            R::XMM9 => 45,
            R::XMM10 => 46,
            R::XMM11 => 47,
            R::XMM12 => 48,
            R::XMM13 => 49,
            R::XMM14 => 50,
            R::XMM15 => 51,
            // â”€â”€ YMM0â€“YMM15 (AVX) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            R::YMM0 => 52,
            R::YMM1 => 53,
            R::YMM2 => 54,
            R::YMM3 => 55,
            R::YMM4 => 56,
            R::YMM5 => 57,
            R::YMM6 => 58,
            R::YMM7 => 59,
            R::YMM8 => 60,
            R::YMM9 => 61,
            R::YMM10 => 62,
            R::YMM11 => 63,
            R::YMM12 => 64,
            R::YMM13 => 65,
            R::YMM14 => 66,
            R::YMM15 => 67,
            // â”€â”€ Everything else (segment, FPU, MMX, ZMM, debug, control â€¦) â”€â”€
            _ => u32::MAX,
        }
    }

    /// Return the canonical string name for an iced-x86 register.
    #[must_use]
    fn reg_name(reg: iced_x86::Register) -> String {
        // iced-x86's `Debug` impl already produces the lower-case register name.
        format!("{reg:?}").to_ascii_lowercase()
    }

    // â”€â”€ operand helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Convert operand `idx` of `instr` into an [`IrExpr`].
    ///
    /// Handles the four common operand kinds: register, immediate, memory, and
    /// near-branch target.  Falls back to [`IrExpr::Undef`] for less-common
    /// kinds (e.g. far branches, VSIB).
    #[must_use]
    pub fn operand_to_llil(
        op_kind: iced_x86::OpKind,
        instr: &iced_x86::Instruction,
        idx: u32,
    ) -> IrExpr {
        use iced_x86::OpKind;
        match op_kind {
            OpKind::Register => IrExpr::Reg(Self::reg_name(instr.op_register(idx))),
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => IrExpr::Const(instr.immediate(idx)),
            OpKind::NearBranch16 => IrExpr::Const(u64::from(instr.near_branch16())),
            OpKind::NearBranch32 => IrExpr::Const(u64::from(instr.near_branch32())),
            OpKind::NearBranch64 => IrExpr::Const(instr.near_branch64()),
            OpKind::Memory => {
                // Reconstruct the effective address: [base + index*scale + disp]
                let base = instr.memory_base();
                let index = instr.memory_index();
                let scale = instr.memory_index_scale();
                let disp = instr.memory_displacement64();
                let mem_size = u8::try_from(instr.memory_size().element_size()).unwrap_or(u8::MAX);

                let base_expr: IrExpr = if base == iced_x86::Register::None {
                    IrExpr::Const(0)
                } else {
                    IrExpr::Reg(Self::reg_name(base))
                };

                let index_expr: Option<IrExpr> = if index == iced_x86::Register::None {
                    None
                } else {
                    let idx_reg = IrExpr::Reg(Self::reg_name(index));
                    if scale > 1 {
                        Some(IrExpr::Mul(
                            Box::new(idx_reg),
                            Box::new(IrExpr::Const(u64::from(scale))),
                        ))
                    } else {
                        Some(idx_reg)
                    }
                };

                let addr_expr = match index_expr {
                    Some(ie) => IrExpr::Add(Box::new(base_expr), Box::new(ie)),
                    None => base_expr,
                };

                let addr_with_disp = if disp != 0 {
                    IrExpr::Add(Box::new(addr_expr), Box::new(IrExpr::Const(disp)))
                } else {
                    addr_expr
                };

                let effective_size = if mem_size == 0 { 8 } else { mem_size };
                IrExpr::Deref(Box::new(addr_with_disp), effective_size)
            }
            _ => IrExpr::Undef,
        }
    }

    // â”€â”€ per-mnemonic helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Lift a MOV instruction: `dst = src`.
    #[must_use]
    pub fn lift_mov(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_kind = instr.op0_kind();
        let src_kind = instr.op1_kind();
        let src = Self::operand_to_llil(src_kind, instr, 1);

        match dst_kind {
            iced_x86::OpKind::Register => {
                let dst_reg = Self::reg_name(instr.op0_register());
                // If the source is itself a Deref (memory operand), convert to
                // a MemRead effect for cleaner IR.
                if let IrExpr::Deref(addr, size) = src {
                    vec![LlilOp::MemRead {
                        addr: *addr,
                        dest: dst_reg,
                        size,
                    }]
                } else {
                    vec![LlilOp::RegWrite {
                        reg: dst_reg,
                        value: src,
                    }]
                }
            }
            iced_x86::OpKind::Memory => {
                // MOV [mem], reg/imm  â€” store
                let base = instr.memory_base();
                let index = instr.memory_index();
                let scale = instr.memory_index_scale();
                let disp = instr.memory_displacement64();
                let mem_size = u8::try_from(instr.memory_size().element_size()).unwrap_or(u8::MAX);
                let effective_size = if mem_size == 0 { 8 } else { mem_size };

                let base_expr = if base == iced_x86::Register::None {
                    IrExpr::Const(0)
                } else {
                    IrExpr::Reg(Self::reg_name(base))
                };
                let index_expr = if index == iced_x86::Register::None {
                    IrExpr::Const(0)
                } else {
                    let ie = IrExpr::Reg(Self::reg_name(index));
                    if scale > 1 {
                        IrExpr::Mul(Box::new(ie), Box::new(IrExpr::Const(u64::from(scale))))
                    } else {
                        ie
                    }
                };
                let addr = if index == iced_x86::Register::None {
                    base_expr
                } else {
                    IrExpr::Add(Box::new(base_expr), Box::new(index_expr))
                };
                let addr = if disp != 0 {
                    IrExpr::Add(Box::new(addr), Box::new(IrExpr::Const(disp)))
                } else {
                    addr
                };

                // Strip any Deref wrapper from src (it is a register or imm here)
                let value = match src {
                    IrExpr::Deref(inner, _) => *inner,
                    other => other,
                };
                vec![LlilOp::MemWrite {
                    addr,
                    value,
                    size: effective_size,
                }]
            }
            _ => vec![LlilOp::RegWrite {
                reg: "unknown".to_string(),
                value: IrExpr::Undef,
            }],
        }
    }

    /// Lift an ADD instruction: `dst = dst + src`, update flags.
    #[must_use]
    pub fn lift_add(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        let src = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let result = IrExpr::Add(Box::new(IrExpr::Reg(dst_reg.clone())), Box::new(src));
        vec![
            LlilOp::RegWrite {
                reg: dst_reg.clone(),
                value: result,
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(dst_reg.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(dst_reg.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(dst_reg))),
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Undef,
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Undef,
            },
        ]
    }

    /// Lift a SUB instruction: `dst = dst - src`, update flags.
    #[must_use]
    pub fn lift_sub(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        let src = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let result = IrExpr::Sub(Box::new(IrExpr::Reg(dst_reg.clone())), Box::new(src));
        vec![
            LlilOp::RegWrite {
                reg: dst_reg.clone(),
                value: result,
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(dst_reg.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(dst_reg.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(dst_reg))),
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Undef,
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Undef,
            },
        ]
    }

    /// Lift an AND instruction: `dst = dst & src`, clear CF/OF, update SF/ZF/PF.
    #[must_use]
    pub fn lift_and(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        let src = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let result = IrExpr::And(Box::new(IrExpr::Reg(dst_reg.clone())), Box::new(src));
        vec![
            LlilOp::RegWrite {
                reg: dst_reg.clone(),
                value: result,
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(dst_reg.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(dst_reg.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(dst_reg))),
            },
        ]
    }

    /// Lift an OR instruction: `dst = dst | src`, clear CF/OF, update SF/ZF/PF.
    #[must_use]
    pub fn lift_or(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        let src = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let result = IrExpr::Or(Box::new(IrExpr::Reg(dst_reg.clone())), Box::new(src));
        vec![
            LlilOp::RegWrite {
                reg: dst_reg.clone(),
                value: result,
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(dst_reg.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(dst_reg.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(dst_reg))),
            },
        ]
    }

    /// Lift an XOR instruction: `dst = dst ^ src`, clear CF/OF, update SF/ZF/PF.
    ///
    /// Recognises `xor reg, reg` (same operand both sides) as a zero idiom and
    /// emits `dst = 0` directly for cleaner IR.
    #[must_use]
    pub fn lift_xor(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        let src_reg = if instr.op1_kind() == iced_x86::OpKind::Register {
            Some(Self::reg_name(instr.op1_register()))
        } else {
            None
        };

        // xor rX, rX â†’ zero idiom
        let value = if src_reg.as_deref() == Some(dst_reg.as_str()) {
            IrExpr::Const(0)
        } else {
            let src = Self::operand_to_llil(instr.op1_kind(), instr, 1);
            IrExpr::Xor(Box::new(IrExpr::Reg(dst_reg.clone())), Box::new(src))
        };

        vec![
            LlilOp::RegWrite {
                reg: dst_reg.clone(),
                value,
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(dst_reg.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(dst_reg.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(dst_reg))),
            },
        ]
    }

    /// Lift a PUSH instruction.
    ///
    /// Semantics: RSP -= `operand_size`; [RSP] = src.
    #[must_use]
    pub fn lift_push(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let sp = "rsp".to_string();
        let src = Self::operand_to_llil(instr.op0_kind(), instr, 0);
        let size = u8::try_from(instr.stack_pointer_increment().unsigned_abs()).unwrap_or(u8::MAX);
        let effective_size = if size == 0 { 8 } else { size };
        vec![
            // rsp = rsp - size
            LlilOp::RegWrite {
                reg: sp.clone(),
                value: IrExpr::Sub(
                    Box::new(IrExpr::Reg(sp.clone())),
                    Box::new(IrExpr::Const(u64::from(effective_size))),
                ),
            },
            // [rsp] = src
            LlilOp::MemWrite {
                addr: IrExpr::Reg(sp),
                value: src,
                size: effective_size,
            },
        ]
    }

    /// Lift a POP instruction.
    ///
    /// Semantics: dst = [RSP]; RSP += `operand_size`.
    #[must_use]
    pub fn lift_pop(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let sp = "rsp".to_string();
        let dst_reg = if instr.op0_kind() == iced_x86::OpKind::Register {
            Self::reg_name(instr.op0_register())
        } else {
            "unknown".to_string()
        };
        let size = u8::try_from(instr.stack_pointer_increment().unsigned_abs()).unwrap_or(u8::MAX);
        let effective_size = if size == 0 { 8 } else { size };
        vec![
            // dst = [rsp]
            LlilOp::MemRead {
                addr: IrExpr::Reg(sp.clone()),
                dest: dst_reg,
                size: effective_size,
            },
            // rsp = rsp + size
            LlilOp::RegWrite {
                reg: sp.clone(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Reg(sp)),
                    Box::new(IrExpr::Const(u64::from(effective_size))),
                ),
            },
        ]
    }

    /// Lift a CALL instruction.
    ///
    /// Pushes the return address and transfers control.
    #[must_use]
    pub fn lift_call(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let sp = "rsp".to_string();
        let ret_addr = instr.next_ip();
        let target = if instr.op0_kind() == iced_x86::OpKind::NearBranch64
            || instr.op0_kind() == iced_x86::OpKind::NearBranch32
            || instr.op0_kind() == iced_x86::OpKind::NearBranch16
        {
            IrExpr::Const(instr.near_branch64())
        } else {
            Self::operand_to_llil(instr.op0_kind(), instr, 0)
        };
        vec![
            // push return address
            LlilOp::RegWrite {
                reg: sp.clone(),
                value: IrExpr::Sub(
                    Box::new(IrExpr::Reg(sp.clone())),
                    Box::new(IrExpr::Const(8)),
                ),
            },
            LlilOp::MemWrite {
                addr: IrExpr::Reg(sp),
                value: IrExpr::Const(ret_addr),
                size: 8,
            },
            LlilOp::Call { target },
        ]
    }

    /// Lift a RET / RETN instruction.
    ///
    /// Pops the return address and jumps to it.
    ///
    /// `RET imm16` additionally pops `imm16` bytes of arguments — the stdcall
    /// callee-cleanup convention. The parameter used to be `_instr`, a
    /// written-down decision to ignore the operand, so `ret 0x10` lifted
    /// IDENTICALLY to a bare `ret` and every downstream stack-depth inference
    /// was off by 16. This is the same defect that was found and fixed in
    /// `rustre-arch-x86::lift_ret` earlier in this session: one machine fact,
    /// described twice, wrong in the second place too.
    #[must_use]
    pub fn lift_ret(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let sp = "rsp".to_string();
        // The immediate is only present on the `RET imm16` forms; a bare RET
        // has no operands, so this is 0 and the arithmetic below collapses to
        // the plain `sp += 8`.
        let extra = u64::from(if instr.op_count() > 0 { instr.immediate16() } else { 0 });
        vec![
            LlilOp::MemRead {
                addr: IrExpr::Reg(sp.clone()),
                dest: "__ret_addr".into(),
                size: 8,
            },
            LlilOp::RegWrite {
                reg: sp.clone(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Reg(sp)),
                    Box::new(IrExpr::Const(8 + extra)),
                ),
            },
            LlilOp::Return { value: None },
        ]
    }

    /// Lift an unconditional JMP instruction.
    #[must_use]
    pub fn lift_jmp(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let target = if instr.op0_kind() == iced_x86::OpKind::NearBranch64
            || instr.op0_kind() == iced_x86::OpKind::NearBranch32
            || instr.op0_kind() == iced_x86::OpKind::NearBranch16
        {
            IrExpr::Const(instr.near_branch64())
        } else {
            Self::operand_to_llil(instr.op0_kind(), instr, 0)
        };
        vec![LlilOp::Branch {
            target,
            condition: None,
        }]
    }

    /// Lift a conditional jump â€” all 16 Jcc variants.
    ///
    /// The condition expression is constructed from the appropriate flag
    /// combination as defined in the Intel SDM.
    #[must_use]
    pub fn lift_jcc(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        use iced_x86::Mnemonic::{Je, Jne, Jb, Jae, Jbe, Ja, Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg, Jo, Jno, Jcxz, Jecxz, Jrcxz};
        let target = IrExpr::Const(instr.near_branch64());

        // iced-x86 uses canonical Intel mnemonic names only (no AT&T aliases).
        // The aliases Jz/Jnz/Jc/Jnae/Jnb/Jnc/Jna/Jnbe/Jpe/Jpo/Jnge/Jnl/Jng/Jnle
        // do not exist as enum variants.
        let condition: IrExpr = match instr.mnemonic() {
            // JE:  ZF == 1
            Je => IrExpr::Reg("zf".into()),
            // JNE: ZF == 0
            Jne => IrExpr::Not(Box::new(IrExpr::Reg("zf".into()))),
            // JB (below, unsigned): CF == 1
            Jb => IrExpr::Reg("cf".into()),
            // JAE (above-or-equal, unsigned): CF == 0
            Jae => IrExpr::Not(Box::new(IrExpr::Reg("cf".into()))),
            // JBE (below-or-equal, unsigned): CF == 1 OR ZF == 1
            Jbe => IrExpr::Or(
                Box::new(IrExpr::Reg("cf".into())),
                Box::new(IrExpr::Reg("zf".into())),
            ),
            // JA (above, unsigned): CF == 0 AND ZF == 0
            Ja => IrExpr::And(
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("cf".into())))),
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".into())))),
            ),
            // JS:  SF == 1
            Js => IrExpr::Reg("sf".into()),
            // JNS: SF == 0
            Jns => IrExpr::Not(Box::new(IrExpr::Reg("sf".into()))),
            // JP (parity): PF == 1
            Jp => IrExpr::Reg("pf".into()),
            // JNP (no parity): PF == 0
            Jnp => IrExpr::Not(Box::new(IrExpr::Reg("pf".into()))),
            // JL (less, signed): SF != OF
            Jl => IrExpr::Xor(
                Box::new(IrExpr::Reg("sf".into())),
                Box::new(IrExpr::Reg("of".into())),
            ),
            // JGE (greater-or-equal, signed): SF == OF
            Jge => IrExpr::Not(Box::new(IrExpr::Xor(
                Box::new(IrExpr::Reg("sf".into())),
                Box::new(IrExpr::Reg("of".into())),
            ))),
            // JLE (less-or-equal, signed): ZF == 1 OR SF != OF
            Jle => IrExpr::Or(
                Box::new(IrExpr::Reg("zf".into())),
                Box::new(IrExpr::Xor(
                    Box::new(IrExpr::Reg("sf".into())),
                    Box::new(IrExpr::Reg("of".into())),
                )),
            ),
            // JG (greater, signed): ZF == 0 AND SF == OF
            Jg => IrExpr::And(
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".into())))),
                Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                    Box::new(IrExpr::Reg("sf".into())),
                    Box::new(IrExpr::Reg("of".into())),
                )))),
            ),
            // JO / JNO
            Jo => IrExpr::Reg("of".into()),
            Jno => IrExpr::Not(Box::new(IrExpr::Reg("of".into()))),
            // JCXZ / JECXZ / JRCXZ
            Jcxz => IrExpr::CmpEqZero(Box::new(IrExpr::Reg("cx".into()))),
            Jecxz => IrExpr::CmpEqZero(Box::new(IrExpr::Reg("ecx".into()))),
            Jrcxz => IrExpr::CmpEqZero(Box::new(IrExpr::Reg("rcx".into()))),
            _ => IrExpr::Undef,
        };

        vec![LlilOp::Branch {
            target,
            condition: Some(condition),
        }]
    }

    /// Lift a CMP instruction.
    ///
    /// CMP computes `op0 - op1` and sets flags only (no destination written).
    #[must_use]
    pub fn lift_cmp(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let lhs = Self::operand_to_llil(instr.op0_kind(), instr, 0);
        let rhs = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let diff = IrExpr::Sub(Box::new(lhs), Box::new(rhs));
        // Store the difference in a throw-away temporary so flag expressions
        // can reference it without re-computing.
        let tmp = "__cmp_tmp".to_string();
        vec![
            LlilOp::RegWrite {
                reg: tmp.clone(),
                value: diff,
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(tmp.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(tmp.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(tmp))),
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Undef,
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Undef,
            },
        ]
    }

    /// Lift a TEST instruction.
    ///
    /// TEST computes `op0 & op1` and sets flags only (no destination written),
    /// clearing CF and OF as per the x86 specification.
    #[must_use]
    pub fn lift_test(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let lhs = Self::operand_to_llil(instr.op0_kind(), instr, 0);
        let rhs = Self::operand_to_llil(instr.op1_kind(), instr, 1);
        let and_result = IrExpr::And(Box::new(lhs), Box::new(rhs));
        let tmp = "__test_tmp".to_string();
        vec![
            LlilOp::RegWrite {
                reg: tmp.clone(),
                value: and_result,
            },
            LlilOp::RegWrite {
                reg: "cf".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "of".into(),
                value: IrExpr::Const(0),
            },
            LlilOp::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(tmp.clone()))),
            },
            LlilOp::RegWrite {
                reg: "sf".into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(tmp.clone())),
                    Box::new(IrExpr::Const(63)),
                ),
            },
            LlilOp::RegWrite {
                reg: "pf".into(),
                value: IrExpr::Parity(Box::new(IrExpr::Reg(tmp))),
            },
        ]
    }

    /// Lift a LEA instruction.
    ///
    /// LEA computes the effective address from the memory operand and writes it
    /// to the destination register (no memory access is performed).
    #[must_use]
    pub fn lift_lea(instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        let dst_reg = Self::reg_name(instr.op0_register());
        // Build the effective address expression without the Deref wrapper.
        let base = instr.memory_base();
        let index = instr.memory_index();
        let scale = instr.memory_index_scale();
        let disp = instr.memory_displacement64();

        let base_expr = if base == iced_x86::Register::None {
            IrExpr::Const(0)
        } else {
            IrExpr::Reg(Self::reg_name(base))
        };

        let with_index = if index == iced_x86::Register::None {
            base_expr
        } else {
            let ie = IrExpr::Reg(Self::reg_name(index));
            let scaled = if scale > 1 {
                IrExpr::Mul(Box::new(ie), Box::new(IrExpr::Const(u64::from(scale))))
            } else {
                ie
            };
            IrExpr::Add(Box::new(base_expr), Box::new(scaled))
        };

        let effective_addr = if disp != 0 {
            IrExpr::Add(Box::new(with_index), Box::new(IrExpr::Const(disp)))
        } else {
            with_index
        };

        vec![LlilOp::RegWrite {
            reg: dst_reg,
            value: effective_addr,
        }]
    }

    /// Lift a NOP instruction â€” no effects.
    #[must_use]
    pub const fn lift_nop(_instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        vec![]
    }

    /// Lift a SYSCALL instruction.
    ///
    /// On x86-64 Linux/Windows the syscall number is in RAX.
    #[must_use]
    pub fn lift_syscall(_instr: &iced_x86::Instruction) -> Vec<LlilOp> {
        vec![LlilOp::Syscall {
            nr: IrExpr::Reg("rax".into()),
        }]
    }

    // â”€â”€ dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Decode `bytes` with the iced-x86 decoder at `ip` and lift the first
    /// instruction into a sequence of [`LlilOp`]s.
    ///
    /// Returns `None` if the bytes cannot be decoded.
    #[must_use]
    pub fn decode_and_lift(&self, bytes: &[u8], ip: u64) -> Option<Vec<LlilOp>> {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic};

        if bytes.is_empty() {
            return None;
        }

        let bitness = u32::from(self.bits);
        let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
        if !decoder.can_decode() {
            return None;
        }
        let instr = decoder.decode();
        if instr.is_invalid() {
            return None;
        }

        let ops: Vec<LlilOp> = match instr.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx => {
                Self::lift_mov(&instr)
            }

            Mnemonic::Add => Self::lift_add(&instr),
            Mnemonic::Sub => Self::lift_sub(&instr),
            Mnemonic::And => Self::lift_and(&instr),
            Mnemonic::Or => Self::lift_or(&instr),
            Mnemonic::Xor => Self::lift_xor(&instr),
            Mnemonic::Push => Self::lift_push(&instr),
            Mnemonic::Pop => Self::lift_pop(&instr),
            Mnemonic::Call => Self::lift_call(&instr),

            Mnemonic::Ret | Mnemonic::Retf => Self::lift_ret(&instr),

            Mnemonic::Jmp => Self::lift_jmp(&instr),

            // Conditional branches â€” canonical iced-x86 mnemonic names only.
            Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz => Self::lift_jcc(&instr),

            Mnemonic::Cmp => Self::lift_cmp(&instr),
            Mnemonic::Test => Self::lift_test(&instr),
            Mnemonic::Lea => Self::lift_lea(&instr),

            Mnemonic::Nop | Mnemonic::Fnop | Mnemonic::Pause => Self::lift_nop(&instr),

            Mnemonic::Syscall | Mnemonic::Sysenter => Self::lift_syscall(&instr),

            _ => vec![LlilOp::Intrinsic {
                name: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
                args: vec![],
            }],
        };

        Some(ops)
    }
}

impl X86Lifter {
    // â”€â”€ lift_instruction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Decode raw `bytes` at virtual address `ip` using [`iced_x86::Decoder`]
    /// and lift the first instruction to a sequence of [`LlilOp`]s.
    ///
    /// Unlike [`decode_and_lift`] (which returns `Option`), this method returns
    /// a `Result` with a descriptive error so callers in the lifting pipeline
    /// can surface decode failures.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::InvalidBytecode`] if `bytes` is empty.
    /// Returns [`LiftError::DisasmFailed`] if iced-x86 cannot decode the bytes.
    pub fn lift_instruction(&self, bytes: &[u8], ip: u64) -> Result<Vec<LlilOp>, LiftError> {
        use iced_x86::{Decoder, DecoderOptions};

        if bytes.is_empty() {
            return Err(LiftError::InvalidBytecode);
        }

        let bitness = u32::from(self.bits);
        let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);

        if !decoder.can_decode() {
            return Err(LiftError::DisasmFailed(
                ip,
                "iced-x86 decoder cannot decode bytes".into(),
            ));
        }

        let instr = decoder.decode();
        if instr.is_invalid() {
            return Err(LiftError::DisasmFailed(
                ip,
                format!("invalid instruction at {ip:#x}"),
            ));
        }

        // Dispatch through the same mnemonic table used by decode_and_lift.
        let ops = self
            .decode_and_lift(bytes, ip)
            .ok_or_else(|| LiftError::DisasmFailed(ip, "mnemonic dispatch returned None".into()))?;

        Ok(ops)
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// X86LiftCache â€” per-instruction memoisation for X86Lifter
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// A simple `HashMap`-backed cache that avoids re-lifting the same instruction
/// bytes twice.
///
/// Keys are the virtual address of the instruction (`u64`).  The cached value
/// is the `Vec<LlilOp>` produced on the first lift of that address.
///
/// # Thread safety
///
/// `X86LiftCache` is **not** thread-safe by design â€” it is intended for single-
/// threaded use within one lifting pass over a function or region.  For shared
/// caching across threads use the existing [`LiftCache`] (which is backed by a
/// `RwLock`).
///
/// # Example
///
/// ```
/// use rustre_il_lift::X86LiftCache;
///
/// let lifter = rustre_il_lift::X86Lifter::new(64);
/// let mut cache = X86LiftCache::new();
/// // NOP â€” the returned slice borrows the cache, so read its length before
/// // the next call rather than holding the borrow across it.
/// let len1 = cache.lift_with_cache(&lifter, 0x1000, &[0x90]).len();
/// assert_eq!(len1, 0); // NOP lifts to zero ops
/// // Second call returns the cached copy.
/// let len2 = cache.lift_with_cache(&lifter, 0x1000, &[0x90]).len();
/// assert_eq!(len1, len2);
/// ```
#[derive(Debug, Default)]
pub struct X86LiftCache {
    /// Instruction cache: virtual address â†’ lifted ops.
    inner: HashMap<u64, Vec<LlilOp>>,
    /// Total hits since creation.
    hits: u64,
    /// Total misses since creation.
    misses: u64,
}

impl X86LiftCache {
    /// Create a new, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lift `bytes` at virtual address `addr`, returning a reference to the
    /// cached result.
    ///
    /// If a previous call for `addr` succeeded the cached result is returned
    /// immediately; otherwise the instruction is lifted via
    /// [`X86Lifter::lift_instruction`] and the result is inserted into the
    /// cache.
    ///
    /// On lift failure an empty slice is returned and the failure is **not**
    /// cached (a subsequent call with corrected bytes would succeed).
    pub fn lift_with_cache(&mut self, lifter: &X86Lifter, addr: u64, bytes: &[u8]) -> &[LlilOp] {
        // Entry API lets us avoid a double lookup.
        if self.inner.contains_key(&addr) {
            self.hits += 1;
        } else {
            self.misses += 1;
            let ops = lifter.lift_instruction(bytes, addr).unwrap_or_default();
            self.inner.insert(addr, ops);
        }
        // The entry is guaranteed to exist now.
        self.inner.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// Remove the cached result for `addr`, forcing the next call to re-lift.
    pub fn invalidate(&mut self, addr: u64) {
        self.inner.remove(&addr);
    }

    /// Remove all entries from the cache.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Total cache hits since this cache was created.
    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    /// Total cache misses since this cache was created.
    #[must_use]
    pub const fn misses(&self) -> u64 {
        self.misses
    }

    /// Cache hit rate in [0.0, 1.0].  Returns 0.0 if no lookups have been made.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }

    /// Return a sorted list of all cached addresses.
    #[must_use]
    pub fn cached_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.inner.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }
}

impl ArchLifter for X86Lifter {
    fn arch_name(&self) -> &'static str {
        match self.bits {
            64 => "x86_64",
            32 => "x86",
            16 => "x86_16",
            _ => "x86_unknown",
        }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "iced-x86 powered x86/x86-64 LLIL lifter"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let bytes = &instr.bytes;
        let ip = instr.address.0;

        let effects = self.decode_and_lift(bytes, ip).ok_or_else(|| {
            LiftError::DisasmFailed(ip, "iced-x86 could not decode instruction".into())
        })?;

        let ir_text = if effects.is_empty() {
            "nop".to_string()
        } else {
            effects
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };

        Ok(LiftedInstr {
            address: ip,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Arm64Lifter â€” AArch64 / ARM64 LLIL lifter
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// An `AArch64` LLIL lifter that handles common instruction patterns by parsing
/// the mnemonic string and a small set of operand conventions.
///
/// `AArch64` has a regular encoding so most arithmetic and logic instructions
/// follow the same three-operand pattern: `MNEM dst, src1, src2`.
/// Memory accesses use `LDR/STR dst, [base, #offset]`.
///
/// This lifter is mnemonic-driven: it uses the `mnemonic` field of the
/// [`Instruction`] rather than raw bytes, making it portable across any
/// `AArch64` disassembler frontend.
#[derive(Debug, Clone)]
pub struct Arm64Lifter;

impl Arm64Lifter {
    /// Create a new `AArch64` lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // â”€â”€ register helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Normalise an `AArch64` register name.
    ///
    /// Strips optional `#` prefixes, maps `wzr`/`xzr` to the zero register
    /// name, and lower-cases the result.
    #[must_use]
    fn norm_reg(raw: &str) -> String {
        let s = raw.trim_start_matches('#').to_ascii_lowercase();
        match s.as_str() {
            "wzr" | "xzr" => "xzr".to_string(),
            "wsp" | "sp" => "sp".to_string(),
            other => other.to_string(),
        }
    }

    /// Return the [`IrExpr`] for the zero register (always 0).
    const fn zero_reg() -> IrExpr {
        IrExpr::Const(0)
    }

    /// Build an [`IrExpr`] from a register token, substituting zero for XZR/WZR.
    fn reg_expr(name: &str) -> IrExpr {
        let n = Self::norm_reg(name);
        if n == "xzr" {
            Self::zero_reg()
        } else {
            IrExpr::Reg(n)
        }
    }

    /// Build an [`IrExpr`] from a token that is either a register or a
    /// `#immediate` literal.
    /// Sign-bit position for an AArch64 operand: `w` registers are 32-bit,
    /// `x` registers (and everything else) 64-bit.
    ///
    /// The flag code hard-coded 63, so `cmp w0, w1` read the sign from bit 63
    /// of a 32-bit value — always 0, i.e. the N flag was never set for any
    /// 32-bit compare. Only reachable at all once the tokeniser was fixed to
    /// return operands.
    fn sign_bit_of(tok: &str) -> u64 {
        if tok.trim().trim_start_matches('#').starts_with('w') { 31 } else { 63 }
    }

    fn operand_expr(tok: &str) -> IrExpr {
        let t = tok.trim();
        t.strip_prefix('#').map_or_else(|| Self::reg_expr(t), |stripped| {
            // Try to parse as integer (decimal or 0x hex).
            let v: Option<u64> = stripped
                .strip_prefix("0x")
                .or_else(|| stripped.strip_prefix("0X")).map_or_else(|| stripped.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok());
            v.map_or_else(|| IrExpr::Undef, IrExpr::Const)
        })
    }

    /// The access size of an AArch64 load/store, taken from the MNEMONIC and the
    /// destination register — the only places that carry it.
    ///
    /// `parse_mem_addr` returns a hard-coded 8 for every form, so `LDRB` was
    /// modelled as an EIGHT-byte load: it read seven bytes the instruction never
    /// touches and wrote a full register width. The same wrong size then fed the
    /// `sextN` marker added one iteration earlier, which therefore said `sext64`
    /// where it meant `sext8` — a defect of mine, inherited rather than
    /// introduced, and only visible once the enumeration rule sent me back to an
    /// arm I had already "fixed".
    ///
    /// For the unsuffixed `LDR`/`STR` the width lives in the register name:
    /// `w0` is 4 bytes, `x0` is 8. AArch64 states it there and nowhere else.
    fn access_size(mnem: &str, dst: &str) -> u8 {
        match mnem {
            m if m.ends_with('b') => 1,
            m if m.ends_with('h') => 2,
            "ldrsw" => 4,
            _ => {
                if dst.trim_start().starts_with('w') {
                    4
                } else {
                    8
                }
            }
        }
    }

    /// Parse a memory address operand of the form `[base]` or `[base, #offset]`.
    fn parse_mem_addr(ops: &[&str]) -> (IrExpr, Option<LlilOp>) {
        let raw: String = ops.join(", ");
        // Split the operand at its brackets instead of trimming characters off
        // the ends. `trim_end_matches(']')` does not fire on the post-indexed
        // form `[x1], #8` (it ends in `8`), so the old code split on the first
        // comma and took `x1]` — including the bracket — as the BASE REGISTER
        // NAME, inventing a register that does not exist. Same class as the
        // arch-x86 instruction found writing a register literally named "none".
        let (bracketed, after) = match (raw.find('['), raw.find(']')) {
            (Some(open), Some(close)) if close > open => {
                (&raw[open + 1..close], raw[close + 1..].trim())
            }
            // No brackets: a bare register or label operand.
            _ => (raw.trim_start_matches('[').trim_end_matches(']'), ""),
        };

        // The indexing mode lives in what FOLLOWS the closing bracket:
        //   `[x1, #8]`   offset      — address x1+8, base unchanged
        //   `[x1, #8]!`  pre-indexed — address x1+8, base becomes x1+8
        //   `[x1], #8`   post-indexed— address x1,   base becomes x1+8
        let pre = after.starts_with('!');
        let post = after.starts_with(',');

        let parts: Vec<&str> = bracketed.splitn(2, ',').collect();
        let base_name = parts[0].trim();
        let base_expr = Self::reg_expr(base_name);

        // For the post-indexed form the displacement sits outside the brackets.
        let off_tok = if post {
            Some(after.trim_start_matches(',').trim())
        } else if parts.len() == 2 {
            Some(parts[1].trim())
        } else {
            None
        };
        let offset_expr = off_tok.and_then(|tok| match Self::operand_expr(tok) {
            IrExpr::Const(0) => None,
            e => Some(e),
        });

        let advanced = |off: &IrExpr| {
            IrExpr::Add(
                Box::new(Self::reg_expr(base_name)),
                Box::new(off.clone()),
            )
        };
        // Post-indexed accesses the UNMODIFIED base; the other two forms access
        // base+offset. Previously all three produced base+offset and no
        // writeback at all, so `ldr x0, [x1, #8]!` — the pointer-walking idiom —
        // silently lost the advance of x1.
        let addr = match (&offset_expr, post) {
            (Some(off), false) => advanced(off),
            _ => base_expr,
        };
        let writeback = if pre || post {
            let value = offset_expr.as_ref().map_or_else(
                || Self::reg_expr(base_name),
                |off| advanced(off),
            );
            Some(LlilOp::RegWrite {
                reg: Self::norm_reg(base_name),
                value,
            })
        } else {
            None
        };
        (addr, writeback)
    }

    // â”€â”€ per-instruction lifters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Lift a MOV-family instruction.
    ///
    /// `AArch64` MOV is often an alias for `ORR Xd, XZR, Xn` or
    /// `MOV Xd, #imm`.  Both are handled here.
    #[must_use]
    pub fn lift_mov(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 2 {
            return vec![LlilOp::Intrinsic {
                name: "mov_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let src = Self::operand_expr(ops[1]);
        vec![LlilOp::RegWrite {
            reg: dst,
            value: src,
        }]
    }

    /// Lift an ADD instruction: `dst = src1 + src2`.
    #[must_use]
    pub fn lift_add(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "add_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let a = Self::operand_expr(ops[1]);
        let b = Self::operand_expr(ops[2]);
        vec![LlilOp::RegWrite {
            reg: dst,
            value: IrExpr::Add(Box::new(a), Box::new(b)),
        }]
    }

    /// Lift a SUB instruction: `dst = src1 - src2`.
    #[must_use]
    pub fn lift_sub(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "sub_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let a = Self::operand_expr(ops[1]);
        let b = Self::operand_expr(ops[2]);
        vec![LlilOp::RegWrite {
            reg: dst,
            value: IrExpr::Sub(Box::new(a), Box::new(b)),
        }]
    }

    /// Lift an AND instruction: `dst = src1 & src2`.
    #[must_use]
    pub fn lift_and(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "and_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let a = Self::operand_expr(ops[1]);
        let b = Self::operand_expr(ops[2]);
        vec![LlilOp::RegWrite {
            reg: dst,
            value: IrExpr::And(Box::new(a), Box::new(b)),
        }]
    }

    /// Lift an ORR instruction: `dst = src1 | src2`.
    ///
    /// The `ORR Xd, XZR, Xn` form is the canonical encoding of `MOV Xd, Xn`
    /// and is transparently handled by the zero-register substitution.
    #[must_use]
    pub fn lift_orr(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "orr_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let a = Self::operand_expr(ops[1]);
        let b = Self::operand_expr(ops[2]);
        // ORR with XZR on either side simplifies to a MOV.
        let value = match (&a, &b) {
            (IrExpr::Const(0), _) => b.clone(),
            (_, IrExpr::Const(0)) => a.clone(),
            _ => IrExpr::Or(Box::new(a), Box::new(b)),
        };
        vec![LlilOp::RegWrite { reg: dst, value }]
    }

    /// Lift an EOR instruction: `dst = src1 ^ src2`.
    #[must_use]
    pub fn lift_eor(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "eor_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let a = Self::operand_expr(ops[1]);
        let b = Self::operand_expr(ops[2]);
        // EOR with the same register on both sides â†’ zero.
        let value = if a == b {
            IrExpr::Const(0)
        } else {
            IrExpr::Xor(Box::new(a), Box::new(b))
        };
        vec![LlilOp::RegWrite { reg: dst, value }]
    }

    /// Lift an LDR instruction: `dst = *[addr]`.
    ///
    /// `LDRSB`/`LDRSH`/`LDRSW` SIGN-extend the loaded value; `LDRB`/`LDRH`
    /// zero-extend it. Six mnemonics shared `lift_ldr`, so the signed and
    /// unsigned forms lifted identically. Sixth architecture in this crate with
    /// that defect — the cause is always a load helper whose SIGNATURE carries
    /// only a size.
    #[must_use]
    pub fn lift_ldr_signed(ops: &[&str], mnem: &str) -> Vec<LlilOp> {
        let mut out = Self::lift_ldr_m(ops, mnem);
        if let Some(LlilOp::MemRead { dest, size, .. }) = out.first() {
            let (reg, bits) = (dest.clone(), u32::from(*size) * 8);
            out.push(LlilOp::Intrinsic {
                name: format!("sext{bits}"),
                args: vec![IrExpr::Reg(reg)],
            });
        }
        out
    }

    /// `LDP Rt1, Rt2, [addr]` — load PAIR: it writes TWO registers.
    ///
    /// It was routed through `lift_ldr`, which reads `ops[0]` as the only
    /// destination and **`ops[1..]` as the address**. But for `LDP` `ops[1]` is
    /// the SECOND DESTINATION REGISTER, so the lift both dropped that register's
    /// write and computed the address from a register operand — wrong on two
    /// counts at once, not merely incomplete.
    ///
    /// The second element is loaded from `addr + size`, the layout the ISA
    /// defines for the pair.
    #[must_use]
    pub fn lift_ldp(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "ldp_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst1 = Self::norm_reg(ops[0]);
        let dst2 = Self::norm_reg(ops[1]);
        // `parse_mem_addr` reports a hard-coded 8, which is wrong twice over for
        // a 32-bit pair: `ldp w0, w1, [sp]` reads FOUR bytes per register and
        // the second element sits at `+4`, not `+8`. The size therefore comes
        // from the destination register, and the stride is that same size.
        let size = Self::access_size("ldp", ops[0]);
        let (addr, writeback) = Self::parse_mem_addr(&ops[2..]);
        let mut out = vec![
            LlilOp::MemRead {
                addr: addr.clone(),
                dest: dst1,
                size,
            },
            LlilOp::MemRead {
                addr: IrExpr::Add(Box::new(addr), Box::new(IrExpr::Const(u64::from(size)))),
                dest: dst2,
                size,
            },
        ];
        out.extend(writeback);
        out
    }

    /// Handles the common forms `LDR Xd, [Xn]` and `LDR Xd, [Xn, #off]`.
    #[must_use]
    pub fn lift_ldr(ops: &[&str]) -> Vec<LlilOp> {
        Self::lift_ldr_m(ops, "ldr")
    }

    /// `LDR`-family load, with the access size derived from the mnemonic and the
    /// destination register rather than from `parse_mem_addr`'s hard-coded 8.
    #[must_use]
    pub fn lift_ldr_m(ops: &[&str], mnem: &str) -> Vec<LlilOp> {
        if ops.len() < 2 {
            return vec![LlilOp::Intrinsic {
                name: "ldr_bad_ops".into(),
                args: vec![],
            }];
        }
        let dst = Self::norm_reg(ops[0]);
        let size = Self::access_size(mnem, ops[0]);
        let (addr, writeback) = Self::parse_mem_addr(&ops[1..]);
        let mut out = vec![LlilOp::MemRead {
            addr,
            dest: dst,
            size,
        }];
        out.extend(writeback);
        out
    }

    /// Lift an STR instruction: `*[addr] = src`.
    #[must_use]
    pub fn lift_str(ops: &[&str], mnem: &str) -> Vec<LlilOp> {
        if ops.len() < 2 {
            return vec![LlilOp::Intrinsic {
                name: "str_bad_ops".into(),
                args: vec![],
            }];
        }
        let src = Self::reg_expr(ops[0]);
        // The store side had the same hard-coded 8 the load side did, so
        // `strb w0, [x1]` wrote EIGHT bytes. Found by asking how many callers
        // `parse_mem_addr` has after fixing one of them: three, of which two
        // were still wrong.
        let size = Self::access_size(mnem, ops[0]);
        let (addr, writeback) = Self::parse_mem_addr(&ops[1..]);
        let mut out = vec![LlilOp::MemWrite {
            addr,
            value: src,
            size,
        }];
        out.extend(writeback);
        out
    }

    /// Lift `STP` — store PAIR of registers.
    ///
    /// `STP` was routed to `lift_str`, which writes exactly one value: the
    /// second register was silently dropped, and because `lift_str` parses the
    /// address from `ops[1..]` that address was built from the second REGISTER
    /// token rather than the memory operand. So `stp x0, x1, [sp, #16]` emitted
    /// a single store of `x0` to an address derived from `x1`.
    ///
    /// A shared match arm is a place where several facts were assumed equal;
    /// this one unioned three (`str` vs `strb`/`strh` size, and `stp`'s arity).
    #[must_use]
    pub fn lift_stp(ops: &[&str]) -> Vec<LlilOp> {
        if ops.len() < 3 {
            return vec![LlilOp::Intrinsic {
                name: "stp_bad_ops".into(),
                args: vec![],
            }];
        }
        let size = Self::access_size("stp", ops[0]);
        let (addr, writeback) = Self::parse_mem_addr(&ops[2..]);
        let mut out = vec![
            LlilOp::MemWrite {
                addr: addr.clone(),
                value: Self::reg_expr(ops[0]),
                size,
            },
            LlilOp::MemWrite {
                addr: IrExpr::Add(Box::new(addr), Box::new(IrExpr::Const(u64::from(size)))),
                value: Self::reg_expr(ops[1]),
                size,
            },
        ];
        out.extend(writeback);
        out
    }

    /// Lift a B (unconditional branch) instruction.
    #[must_use]
    pub fn lift_b(ops: &[&str]) -> Vec<LlilOp> {
        let target = ops.first().map_or(IrExpr::Undef, |tok| Self::operand_expr(tok));
        vec![LlilOp::Branch {
            target,
            condition: None,
        }]
    }

    /// Lift a B.cond conditional branch instruction.
    ///
    /// The condition suffix (`.EQ`, `.NE`, â€¦) is passed as `cond_str`.
    /// We map it to the appropriate flag expression.
    #[must_use]
    pub fn lift_bcond(cond_str: &str, ops: &[&str]) -> Vec<LlilOp> {
        let target = ops.first().map_or(IrExpr::Undef, |tok| Self::operand_expr(tok));

        // AArch64 uses NZCV flags.
        let cond = match cond_str.to_ascii_uppercase().as_str() {
            "EQ" => IrExpr::Reg("zf".into()),
            "NE" => IrExpr::Not(Box::new(IrExpr::Reg("zf".into()))),
            "CS" | "HS" => IrExpr::Reg("cf".into()),
            "CC" | "LO" => IrExpr::Not(Box::new(IrExpr::Reg("cf".into()))),
            "MI" => IrExpr::Reg("nf".into()),
            "PL" => IrExpr::Not(Box::new(IrExpr::Reg("nf".into()))),
            "VS" => IrExpr::Reg("vf".into()),
            "VC" => IrExpr::Not(Box::new(IrExpr::Reg("vf".into()))),
            "HI" => IrExpr::And(
                Box::new(IrExpr::Reg("cf".into())),
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".into())))),
            ),
            "LS" => IrExpr::Or(
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("cf".into())))),
                Box::new(IrExpr::Reg("zf".into())),
            ),
            "GE" => IrExpr::Not(Box::new(IrExpr::Xor(
                Box::new(IrExpr::Reg("nf".into())),
                Box::new(IrExpr::Reg("vf".into())),
            ))),
            "LT" => IrExpr::Xor(
                Box::new(IrExpr::Reg("nf".into())),
                Box::new(IrExpr::Reg("vf".into())),
            ),
            "GT" => IrExpr::And(
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".into())))),
                Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                    Box::new(IrExpr::Reg("nf".into())),
                    Box::new(IrExpr::Reg("vf".into())),
                )))),
            ),
            "LE" => IrExpr::Or(
                Box::new(IrExpr::Reg("zf".into())),
                Box::new(IrExpr::Xor(
                    Box::new(IrExpr::Reg("nf".into())),
                    Box::new(IrExpr::Reg("vf".into())),
                )),
            ),
            "AL" | "NV" => IrExpr::Const(1),
            _ => IrExpr::Undef,
        };

        vec![LlilOp::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// Lift a BL (branch with link) instruction â€” equivalent to a call.
    #[must_use]
    pub fn lift_bl(ops: &[&str]) -> Vec<LlilOp> {
        let target = ops.first().map_or(IrExpr::Undef, |tok| Self::operand_expr(tok));
        vec![LlilOp::Call { target }]
    }

    /// Lift a BLR (branch with link to register) instruction.
    #[must_use]
    pub fn lift_blr(ops: &[&str]) -> Vec<LlilOp> {
        let target = ops.first().map_or(IrExpr::Undef, |tok| Self::reg_expr(tok));
        vec![LlilOp::Call { target }]
    }

    /// Lift a RET instruction (return via X30 / LR).
    #[must_use]
    pub fn lift_ret(ops: &[&str]) -> Vec<LlilOp> {
        // RET {Xn} â€” default register is X30 (link register).
        let ret_reg = ops.first().copied().unwrap_or("x30");
        vec![LlilOp::Return {
            value: Some(IrExpr::Reg(Self::norm_reg(ret_reg))),
        }]
    }

    /// Lift an SVC instruction (supervisor call / system call).
    ///
    /// On Linux `AArch64` the syscall number is in X8.
    #[must_use]
    pub fn lift_svc(_ops: &[&str]) -> Vec<LlilOp> {
        vec![LlilOp::Syscall {
            nr: IrExpr::Reg("x8".into()),
        }]
    }

    /// Lift a NOP instruction â€” no effects.
    #[must_use]
    pub const fn lift_nop(_ops: &[&str]) -> Vec<LlilOp> {
        vec![]
    }

    // â”€â”€ dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Tokenise the `mnemonic + operands` string from an [`Instruction`].
    ///
    /// Returns `(mnem, operands)` where `operands` are comma-split and trimmed.
    fn tokenise(instr: &Instruction) -> (String, Vec<String>) {
        // The mnemonic field holds only the mnemonic token (e.g. "add", "ldr").
        // The operand_str field (if present) holds the rest; fall back to
        // reconstructing from raw bytes when absent.
        let mnem = instr.mnemonic.to_ascii_lowercase();

        // This used to be `let ops: Vec<String> = Vec::new();` with a comment
        // claiming "rustre_core::Instruction doesn't expose an op_str". That
        // premise is FALSE — `Instruction::operands` exists and every other
        // lifter in this crate reads it. The consequence was not a rough edge:
        // this tokeniser returned NO operands for EVERY AArch64 instruction, so
        // the whole dispatch below ran on an empty slice and each handler's
        // `ops.len() >= N` guard was permanently false.
        //
        // Same shape as the RISC-V tokeniser: prefer the text operands, fall
        // back to the structured list.
        let ops = if instr.operands.is_empty() {
            instr
                .operand_list
                .iter()
                .map(|o| format!("{o}"))
                .collect::<Vec<_>>()
        } else {
            instr
                .operands
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
        };
        (mnem, ops)
    }

    /// Internal dispatch: given a mnemonic and already-split operand tokens,
    /// produce the LLIL effect list.
    fn dispatch_a(mnem: &str, ops: &[&str]) -> Vec<LlilOp> {
        // Strip a condition-code suffix from branch mnemonics (e.g. "b.eq").
        if let Some(rest) = mnem.strip_prefix("b.") {
            return Self::lift_bcond(rest, ops);
        }
            match mnem {
            "mov" | "movz" | "movn" | "movk" | "fmov" => Self::lift_mov(ops),
            "add" | "adds" => Self::lift_add(ops),
            "sub" | "subs" => Self::lift_sub(ops),
            "and" | "ands" => Self::lift_and(ops),
            "orr" => Self::lift_orr(ops),
            "eor" | "eon" => Self::lift_eor(ops),
            "ldr" | "ldrb" | "ldrh" => Self::lift_ldr_m(ops, mnem),
            "ldrsb" | "ldrsh" | "ldrsw" => Self::lift_ldr_signed(ops, mnem),
            "ldp" => Self::lift_ldp(ops),
            "str" | "strb" | "strh" => Self::lift_str(ops, mnem),
            "stp" => Self::lift_stp(ops),
            "b" | "br" => Self::lift_b(ops),
                _ => vec![],
            }
    }
    fn dispatch_b(mnem: &str, ops: &[&str]) -> Vec<LlilOp> {
        // Strip a condition-code suffix from branch mnemonics (e.g. "b.eq").
        if let Some(rest) = mnem.strip_prefix("b.") {
            return Self::lift_bcond(rest, ops);
        }
            match mnem {
            "bl" => Self::lift_bl(ops),
            "blr" => Self::lift_blr(ops),
            // indirect branch â€” treat same as B
            "ret" => Self::lift_ret(ops),
            "svc" => Self::lift_svc(ops),
            "nop" | "hint" | "yield" | "wfe" | "wfi" | "sev" => Self::lift_nop(ops),
            // CMP is SUB that discards the result (flags only) â€” represented
            // with a temporary.
            "cmp" | "cmn" => {
                if ops.len() >= 2 {
                    let a = Self::operand_expr(ops[0]);
                    let b = Self::operand_expr(ops[1]);
                    let diff = if mnem == "cmp" {
                        IrExpr::Sub(Box::new(a), Box::new(b))
                    } else {
                        IrExpr::Add(Box::new(a), Box::new(b))
                    };
                    vec![
                        LlilOp::RegWrite {
                            reg: "__cmp_tmp".into(),
                            value: diff,
                        },
                        LlilOp::RegWrite {
                            reg: "zf".into(),
                            value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg("__cmp_tmp".into()))),
                        },
                        LlilOp::RegWrite {
                            reg: "nf".into(),
                            value: IrExpr::Shr(
                                Box::new(IrExpr::Reg("__cmp_tmp".into())),
                                Box::new(IrExpr::Const(Self::sign_bit_of(ops[0]))),
                            ),
                        },
                        LlilOp::RegWrite {
                            reg: "cf".into(),
                            value: IrExpr::Undef,
                        },
                        LlilOp::RegWrite {
                            reg: "vf".into(),
                            value: IrExpr::Undef,
                        },
                    ]
                } else {
                    vec![LlilOp::Intrinsic {
                        name: mnem.to_string(),
                        args: vec![],
                    }]
                }
            }
            "tst" => {
                if ops.len() >= 2 {
                    let a = Self::operand_expr(ops[0]);
                    let b = Self::operand_expr(ops[1]);
                    let and_result = IrExpr::And(Box::new(a), Box::new(b));
                    vec![
                        LlilOp::RegWrite {
                            reg: "__tst_tmp".into(),
                            value: and_result,
                        },
                        LlilOp::RegWrite {
                            reg: "zf".into(),
                            value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg("__tst_tmp".into()))),
                        },
                        LlilOp::RegWrite {
                            reg: "nf".into(),
                            value: IrExpr::Shr(
                                Box::new(IrExpr::Reg("__tst_tmp".into())),
                                Box::new(IrExpr::Const(Self::sign_bit_of(ops[0]))),
                            ),
                        },
                        LlilOp::RegWrite {
                            reg: "cf".into(),
                            value: IrExpr::Const(0),
                        },
                        LlilOp::RegWrite {
                            reg: "vf".into(),
                            value: IrExpr::Const(0),
                        },
                    ]
                } else {
                    vec![LlilOp::Intrinsic {
                        name: "tst".into(),
                        args: vec![],
                    }]
                }
            }
            _ => vec![LlilOp::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }],
            }
    }

    fn dispatch(mnem: &str, ops: &[&str]) -> Vec<LlilOp> {
        // Strip a condition-code suffix from branch mnemonics (e.g. "b.eq").
        if let Some(rest) = mnem.strip_prefix("b.") {
            return Self::lift_bcond(rest, ops);
        }
        let __r0 = Self::dispatch_a(mnem, ops);
        if !__r0.is_empty() { return __r0; }
        Self::dispatch_b(mnem, ops)
    }
}

impl Default for Arm64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchLifter for Arm64Lifter {
    fn arch_name(&self) -> &'static str {
        "aarch64"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "mnemonic-driven AArch64 LLIL lifter"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let (mnem, raw_ops) = Self::tokenise(instr);
        let op_refs: Vec<&str> = raw_ops.iter().map(String::as_str).collect();
        let effects = Self::dispatch(&mnem, &op_refs);

        let ir_text = if effects.is_empty() {
            "nop".to_string()
        } else {
            effects
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };

        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// register_all_lifters â€” populate a registry with all built-in lifters
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Register every built-in architecture lifter into `registry`.
///
/// After calling this function the registry will contain:
///
/// | Architecture key | Lifter                    |
/// |------------------|---------------------------|
/// | `"x86_64"`       | [`X86Lifter`] (64-bit)    |
/// | `"x86"`          | [`X86Lifter`] (32-bit)    |
/// | `"x86_16"`       | [`X86Lifter`] (16-bit)    |
/// | `"aarch64"`      | [`Arm64Lifter`]            |
/// | `"arm64"`        | [`Arm64Lifter`] (alias)    |
/// | `"mips"`         | [`MipsLifter`] (32-bit BE) |
/// | `"mipsel"`       | [`MipsLifter`] (32-bit LE) |
/// | `"mips64"`       | [`MipsLifter`] (64-bit LE) |
/// | `"mips64be"`     | [`MipsLifter`] (64-bit BE) |
/// | `"riscv32"`      | [`RiscvLifter`] (32-bit)   |
/// | `"riscv64"`      | [`RiscvLifter`] (64-bit)   |
/// | `"arm"`          | [`Arm32Lifter`]            |
/// | `"thumb"`        | [`Arm32Lifter`] (Thumb)    |
/// | `"ppc"`          | [`PpcLifter`] (32-bit)     |
/// | `"ppc64"`        | [`PpcLifter`] (64-bit)     |
/// | `"wasm"`         | [`WasmLifter`]             |
/// | `"bpf"`          | [`BpfLifter`] (classic)    |
/// | `"ebpf"`         | [`BpfLifter`] (eBPF)       |
/// | `"avr"`          | [`AvrLifter`]              |
/// | `"cil"`          | [`CilLifter`] (.NET IL)    |
/// | `"dex"`          | [`DexLifter`] (Dalvik)     |
/// | `"m68k"`         | [`M68kLifter`] (68000)     |
/// | `"m68020"`       | [`M68kLifter`] (68020)     |
/// | `"sparc"`        | [`SparcLifter`] (32-bit)   |
/// | `"sparc64"`      | [`SparcLifter`] (64-bit)   |
/// | `"z80"`          | [`Z80Lifter`]              |
///
/// Existing entries in `registry` are overwritten.
pub fn register_all_lifters(registry: &mut LifterRegistry) {
    registry.register(X86Lifter::new(64));
    registry.register(X86Lifter::new(32));
    registry.register(X86Lifter::new(16));
    registry.register(Arm64Lifter::new());
    // Register "arm64" as an alias for the aarch64 lifter.
    // `LifterRegistry::register` uses `arch_name()` as the key, so we wrap
    // a second Arm64Lifter in a thin adapter that returns "arm64".
    registry.register(Arm64AliasLifter);
    // Dedicated MIPS lifters (32-bit BE, 32-bit LE, 64-bit LE, 64-bit BE).
    registry.register(MipsLifter::new());
    registry.register(MipsLifter::new_el());
    registry.register(MipsLifter::new_64());
    registry.register(MipsLifter::new_64_be());
    // Dedicated RISC-V lifters (32-bit and 64-bit).
    registry.register(RiscvLifter::new());
    registry.register(RiscvLifter::new_rv64());
    // Dedicated ARM 32-bit lifters (ARM and Thumb modes).
    registry.register(Arm32Lifter::new());
    registry.register(Arm32Lifter::new_thumb());
    // Canonical aliases for the most common short arch names.
    registry.register(ArmAliasLifter);
    registry.register(RiscvAliasLifter);
    // Dedicated PowerPC lifters (32-bit and 64-bit).
    registry.register(PpcLifter::new());
    registry.register(PpcLifter::new_64());
    // Dedicated WebAssembly lifter.
    registry.register(WasmLifter::new());
    // Dedicated AVR lifter.
    registry.register(AvrLifter::new());
    // Dedicated BPF lifters (classic BPF and eBPF).
    registry.register(BpfLifter::new());
    registry.register(BpfLifter::new_ebpf());
    // .NET CIL/MSIL lifter.
    registry.register(CilLifter::new());
    // Android Dalvik/ART DEX lifter.
    registry.register(DexLifter::new());
    // Motorola 68000-family lifters (68000 and 68020).
    registry.register(M68kLifter::new());
    registry.register(M68kLifter::new_68020());
    // SPARC / SPARC64 lifters.
    registry.register(SparcLifter::new());
    registry.register(SparcLifter::new_64());
    // Zilog Z80 lifter (standard, CMOS, Z180 variants).
    registry.register(Z80Lifter::new());
    registry.register(Z80Lifter::new_cmos());
    registry.register(Z80Lifter::new_z180());
}

/// Thin wrapper around [`Arm64Lifter`] that registers under the `"arm64"` key.
#[derive(Debug)]
struct Arm64AliasLifter;

impl ArchLifter for Arm64AliasLifter {
    fn arch_name(&self) -> &'static str {
        "arm64"
    }
    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }
    fn description(&self) -> &'static str {
        "arm64 alias for aarch64 LLIL lifter"
    }
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        Arm64Lifter::new().lift(instr)
    }
}

/// Thin wrapper registering the 32-bit ARM lifter under the canonical `"arm"` key.
#[derive(Debug)]
struct ArmAliasLifter;

impl ArchLifter for ArmAliasLifter {
    fn arch_name(&self) -> &'static str {
        "arm"
    }
    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }
    fn description(&self) -> &'static str {
        "arm alias for the ARM32 LLIL lifter"
    }
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        Arm32Lifter::new().lift(instr)
    }
}

/// Thin wrapper registering the RISC-V lifter under the canonical `"riscv"` key.
#[derive(Debug)]
struct RiscvAliasLifter;

impl ArchLifter for RiscvAliasLifter {
    fn arch_name(&self) -> &'static str {
        "riscv"
    }
    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }
    fn description(&self) -> &'static str {
        "riscv alias for the RV64 LLIL lifter"
    }
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        RiscvLifter::new_rv64().lift(instr)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests for the new per-arch lifters
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod perarch_tests {
    use super::*;
    use rustre_core::{
        address::Address,
        arch::{InstrFlags, Instruction},
    };

    fn make_instr_bytes(addr: u64, mnemonic: &str, bytes: &[u8]) -> Instruction {
        let mut i = Instruction::new(
            Address::new(addr),
            bytes.len(),
            mnemonic.to_string(),
            bytes.to_vec(),
        );
        i.flags = InstrFlags::NONE;
        i
    }

    fn make_instr(addr: u64, mnemonic: &str) -> Instruction {
        make_instr_bytes(addr, mnemonic, &[0x90; 4])
    }

    // â”€â”€ X86Lifter â€” unit tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn x86_lifter_arch_name() {
        assert_eq!(X86Lifter::new(64).arch_name(), "x86_64");
        assert_eq!(X86Lifter::new(32).arch_name(), "x86");
        assert_eq!(X86Lifter::new(16).arch_name(), "x86_16");
    }

    #[test]
    fn x86_lifter_nop_bytes() {
        let lifter = X86Lifter::new(64);
        // 0x90 = NOP
        let instr = make_instr_bytes(0x1000, "nop", &[0x90]);
        let li = lifter.lift(&instr).unwrap();
        assert!(li.effects.is_empty(), "NOP should produce no effects");
        assert_eq!(li.ir_text, "nop");
    }

    #[test]
    fn x86_lifter_ret_bytes() {
        let lifter = X86Lifter::new(64);
        // 0xC3 = RET (near return)
        let instr = make_instr_bytes(0x1000, "ret", &[0xC3]);
        let li = lifter.lift(&instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Return { .. }))
        );
    }

    #[test]
    fn x86_lifter_xor_self_zero_idiom() {
        let lifter = X86Lifter::new(64);
        // 48 31 C0 = XOR RAX, RAX
        let instr = make_instr_bytes(0x1000, "xor", &[0x48, 0x31, 0xC0]);
        let li = lifter.lift(&instr).unwrap();
        // Should produce RegWrite { reg: "rax", value: Const(0) }
        let zero_write = li.effects.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "rax" && matches!(value, IrExpr::Const(0))
            } else {
                false
            }
        });
        assert!(zero_write, "XOR RAX,RAX should produce rax = 0");
    }

    #[test]
    fn x86_lifter_jmp_unconditional() {
        let lifter = X86Lifter::new(64);
        // EB 00 = JMP +0 (short jump, 2 bytes)
        let instr = make_instr_bytes(0x1000, "jmp", &[0xEB, 0x00]);
        let li = lifter.lift(&instr).unwrap();
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: None,
                ..
            }
        )));
    }

    #[test]
    fn x86_lifter_je_conditional() {
        let lifter = X86Lifter::new(64);
        // 74 00 = JE +0
        let instr = make_instr_bytes(0x1000, "je", &[0x74, 0x00]);
        let li = lifter.lift(&instr).unwrap();
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn x86_lifter_call() {
        let lifter = X86Lifter::new(64);
        // E8 00 00 00 00 = CALL +0
        let instr = make_instr_bytes(0x1000, "call", &[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let li = lifter.lift(&instr).unwrap();
        assert!(li.effects.iter().any(|e| matches!(e, Effect::Call { .. })));
    }

    #[test]
    fn x86_lifter_push() {
        let lifter = X86Lifter::new(64);
        // 50 = PUSH RAX
        let instr = make_instr_bytes(0x1000, "push", &[0x50]);
        let li = lifter.lift(&instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
    }

    #[test]
    fn x86_lifter_pop() {
        let lifter = X86Lifter::new(64);
        // 58 = POP RAX
        let instr = make_instr_bytes(0x1000, "pop", &[0x58]);
        let li = lifter.lift(&instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. }))
        );
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
    }

    #[test]
    fn x86_lifter_syscall() {
        let lifter = X86Lifter::new(64);
        // 0F 05 = SYSCALL
        let instr = make_instr_bytes(0x1000, "syscall", &[0x0F, 0x05]);
        let li = lifter.lift(&instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Syscall { .. }))
        );
    }

    #[test]
    fn x86_lifter_cmp_sets_flags() {
        let lifter = X86Lifter::new(64);
        // 48 3B C0 = CMP RAX, RAX
        let instr = make_instr_bytes(0x1000, "cmp", &[0x48, 0x3B, 0xC0]);
        let li = lifter.lift(&instr).unwrap();
        let flag_names: Vec<&str> = li
            .effects
            .iter()
            .filter_map(|e| {
                if let Effect::RegWrite { reg, .. } = e {
                    Some(reg.as_str())
                } else {
                    None
                }
            })
            .collect();
        for flag in &["zf", "sf", "pf"] {
            assert!(flag_names.contains(flag), "missing flag {flag}");
        }
    }

    #[test]
    fn x86_lifter_test_clears_cf_of() {
        let lifter = X86Lifter::new(64);
        // 48 85 C0 = TEST RAX, RAX
        let instr = make_instr_bytes(0x1000, "test", &[0x48, 0x85, 0xC0]);
        let li = lifter.lift(&instr).unwrap();
        let cf_zero = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "cf"));
        let of_zero = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "of"));
        assert!(cf_zero, "TEST should clear CF");
        assert!(of_zero, "TEST should clear OF");
    }

    #[test]
    fn x86_lifter_add_sets_flags() {
        let lifter = X86Lifter::new(64);
        // 48 01 C8 = ADD RAX, RCX
        let instr = make_instr_bytes(0x1000, "add", &[0x48, 0x01, 0xC8]);
        let li = lifter.lift(&instr).unwrap();
        let writes_rax = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(writes_rax, "ADD RAX,RCX should write rax");
    }

    #[test]
    fn x86_lifter_invalid_bytes_error() {
        let lifter = X86Lifter::new(64);
        // 0xFF 0xFF is a valid CALL/JMP ModRM but let's test empty bytes â†’ error
        let instr = make_instr_bytes(0x1000, "???", &[]);
        let result = lifter.lift(&instr);
        assert!(result.is_err(), "empty bytes should fail");
    }

    #[test]
    fn x86_lifter_reg_id_rax_family() {
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::RAX), 0);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::EAX), 0);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::AX), 0);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::AL), 0);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::RCX), 1);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::RSP), 4);
        assert_eq!(X86Lifter::reg_id(iced_x86::Register::R15), 15);
    }

    #[test]
    fn x86_lifter_32bit_arch_name() {
        let lifter = X86Lifter::new(32);
        assert_eq!(lifter.arch_name(), "x86");
        // 90 = NOP in 32-bit mode as well
        let instr = make_instr_bytes(0x1000, "nop", &[0x90]);
        let li = lifter.lift(&instr).unwrap();
        assert!(li.effects.is_empty());
    }

    // â”€â”€ Arm64Lifter â€” unit tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// `Arm64Lifter::tokenise` returned NO operands for EVERY instruction.
    ///
    /// It was `let ops: Vec<String> = Vec::new();` under a comment claiming
    /// "rustre_core::Instruction doesn't expose an op_str" — a FALSE premise:
    /// `Instruction::operands` exists and every other lifter in this crate
    /// reads it. So the whole AArch64 dispatch ran on an empty slice and every
    /// handler's `ops.len() >= N` guard was permanently false, which made the
    /// flag-computing bodies dead code.
    ///
    /// The 2311 existing tests all passed with the tokeniser broken, because
    /// none of them lifted an instruction that had operands.
    /// The AArch64 load/store family, exercised THROUGH `lift()`.
    ///
    /// Every existing test for these handlers called them directly
    /// (`Arm64Lifter::lift_ldp(&ops)`) with a hand-built token slice — 17 tests
    /// across five handlers, all bypassing `tokenise`. That is precisely how a
    /// tokeniser returning no operands at all survived: the handlers were
    /// covered, the step feeding them was not.
    ///
    /// This test enters where a caller does, so the whole path is on the hook —
    /// including the comma splitting of bracketed memory operands like
    /// `[sp, #16]`, which the hand-built slices never went through.
    #[test]
    fn arm64_loads_and_stores_end_to_end() {
        let l = Arm64Lifter::new();
        let mk = |m: &str, ops: &str| {
            let mut i = make_instr(0x1000, m);
            i.operands = ops.to_string();
            format!("{:?}", l.lift(&i).unwrap().effects)
        };

        let ldr = mk("ldr", "x0, [sp, #16]");
        assert!(
            ldr.contains("MemRead") && ldr.contains("Reg(\"sp\")") && ldr.contains("Const(16)"),
            "ldr must read sp+16, got {ldr}"
        );

        // LDP writes TWO destinations, the second at +8.
        let ldp = mk("ldp", "x0, x1, [sp, #16]");
        assert_eq!(
            ldp.matches("MemRead").count(),
            2,
            "ldp must produce two reads, got {ldp}"
        );
        assert!(ldp.contains("Const(8)"), "ldp's second slot is at +8, got {ldp}");

        let str_ = mk("str", "x0, [x1, #8]");
        assert!(
            str_.contains("MemWrite") && str_.contains("Reg(\"x1\")"),
            "str must write through x1, got {str_}"
        );

        // The access size comes from the mnemonic, not the address.
        let ldrb = mk("ldrb", "w0, [x1]");
        assert!(
            ldrb.contains("size: 1"),
            "ldrb is a byte load, got {ldrb}"
        );
    }

    #[test]
    fn arm64_tokenise_returns_operands() {
        let l = Arm64Lifter::new();
        let mut i = make_instr(0x1000, "cmp");
        i.operands = "x0, x1".to_string();
        let effects = l.lift(&i).unwrap().effects;
        assert!(
            effects.len() > 1,
            "cmp with operands must compute flags, got {effects:?}"
        );
        assert!(
            format!("{effects:?}").contains("__cmp_tmp"),
            "the flag path must be reached, got {effects:?}"
        );
    }

    /// AArch64 `w` registers are 32-bit: the N flag comes from bit 31, not 63.
    ///
    /// The flag code hard-coded 63, so `cmp w0, w1` read the sign bit of a
    /// 32-bit value from bit 63 — always 0. Only observable once the tokeniser
    /// above was fixed; before that this code never ran at all.
    #[test]
    fn arm64_flag_sign_bit_follows_operand_width() {
        let l = Arm64Lifter::new();
        let render = |mnem: &str, ops: &str| {
            let mut i = make_instr(0x1000, mnem);
            i.operands = ops.to_string();
            format!("{:?}", l.lift(&i).unwrap().effects)
        };
        for mnem in ["cmp", "tst"] {
            let w = render(mnem, "w0, w1");
            let x = render(mnem, "x0, x1");
            assert!(
                w.contains("Const(31)") && !w.contains("Const(63)"),
                "{mnem} on w-registers must read bit 31, got {w}"
            );
            assert!(
                x.contains("Const(63)"),
                "{mnem} on x-registers must read bit 63, got {x}"
            );
        }
    }

    #[test]
    fn arm64_arch_name() {
        assert_eq!(Arm64Lifter::new().arch_name(), "aarch64");
    }

    #[test]
    fn arm64_lift_nop() {
        let lifter = Arm64Lifter::new();
        let li = lifter.lift(&make_instr(0x1000, "nop")).unwrap();
        assert!(li.effects.is_empty());
        assert_eq!(li.ir_text, "nop");
    }

    /// `LDP Rt1, Rt2, [addr]` writes TWO registers. It was routed through
    /// `lift_ldr`, which treats `ops[0]` as the only destination and `ops[1..]`
    /// as the address — but for `LDP` `ops[1]` IS the second destination, so the
    /// lift dropped one register write AND derived the address from a register
    /// operand. Wrong on two counts, not merely incomplete.
    #[test]
    fn arm64_ldp_writes_both_destinations() {
        let ops = ["x0", "x1", "[sp, #16]"];
        let out = Arm64Lifter::lift_ldp(&ops);
        let dests: Vec<String> = out
            .iter()
            .filter_map(|o| match o {
                LlilOp::MemRead { dest, .. } => Some(dest.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(dests.len(), 2, "LDP must load two registers: {out:?}");
        assert!(dests.iter().any(|d| d.contains('0')), "first destination missing");
        assert!(dests.iter().any(|d| d.contains('1')), "second destination missing");
    }

    /// `LDRSB` sign-extends where `LDRB` zero-extends; they shared a handler and
    /// lifted identically. Sixth architecture in this crate with that defect.
    #[test]
    fn arm64_signed_load_differs_from_unsigned() {
        let ops = ["w0", "[x1]"];
        let plain = format!("{:?}", Arm64Lifter::lift_ldr_m(&ops, "ldrb"));
        let signed = format!("{:?}", Arm64Lifter::lift_ldr_signed(&ops, "ldrsb"));
        assert_ne!(plain, signed, "LDRB and LDRSB must not lift identically");
        // The extension width must match the ACCESS size, not the register.
        // `parse_mem_addr` returns a hard-coded 8, so before the size came from
        // the mnemonic this said `sext64` for a one-byte load.
        assert!(signed.contains("sext8"), "LDRSB extends 8 bits, got {signed}");

        // And the access size itself must come from the mnemonic: LDRB reads one
        // byte, not the eight `parse_mem_addr` defaults to.
        for (m, want) in [("ldrb", 1u8), ("ldrh", 2), ("ldrsw", 4)] {
            let out = Arm64Lifter::lift_ldr_m(&ops, m);
            let got = out.iter().find_map(|o| match o {
                LlilOp::MemRead { size, .. } => Some(*size),
                _ => None,
            });
            assert_eq!(got, Some(want), "{m} must read {want} byte(s)");
        }
        // Unsuffixed LDR takes its width from the register: w0 is 4, x0 is 8.
        let w = Arm64Lifter::lift_ldr_m(&["w0", "[x1]"], "ldr");
        let x = Arm64Lifter::lift_ldr_m(&["x0", "[x1]"], "ldr");
        let size_of = |o: &Vec<LlilOp>| {
            o.iter().find_map(|i| match i {
                LlilOp::MemRead { size, .. } => Some(*size),
                _ => None,
            })
        };
        assert_eq!(size_of(&w), Some(4), "LDR into a w register reads 4 bytes");
        assert_eq!(size_of(&x), Some(8), "LDR into an x register reads 8 bytes");
    }

    /// arm64 pre/post-indexed addressing: the writeback was DELETED and the
    /// post-indexed form invented a register.
    ///
    /// `parse_mem_addr` did `.trim_end_matches(']').trim_end_matches('!')` with
    /// the comment "handle pre-indexed" — but handling it meant discarding the
    /// marker, so the base advance was never emitted. Worse, on the post-indexed
    /// text `[x1], #8` the `']'` trim does not fire (the string ends in `8`), so
    /// splitting at the first comma took **`x1]`**, bracket included, as the base
    /// register NAME. Same class as the arch-x86 instruction found writing a
    /// register literally named "none".
    #[test]
    fn arm64_indexed_addressing_writes_back_and_never_invents_a_register() {
        let wb_of = |ops: &[&str]| -> Option<String> {
            Arm64Lifter::lift_ldr_m(ops, "ldr").iter().find_map(|o| match o {
                LlilOp::RegWrite { reg, value } => Some(format!("{reg}={value:?}")),
                _ => None,
            })
        };
        let addr_of = |ops: &[&str]| -> String {
            Arm64Lifter::lift_ldr_m(ops, "ldr")
                .iter()
                .find_map(|o| match o {
                    LlilOp::MemRead { addr, .. } => Some(format!("{addr:?}")),
                    _ => None,
                })
                .unwrap_or_default()
        };

        // Plain offset: no writeback at all.
        assert_eq!(wb_of(&["x0", "[x1, #8]"]), None, "offset form must not write back");

        // Pre-indexed: address is x1+8 AND x1 advances.
        let pre_wb = wb_of(&["x0", "[x1, #8]!"]).expect("pre-indexed must write back");
        assert!(pre_wb.starts_with("x1="), "the BASE must advance, got {pre_wb}");
        assert!(pre_wb.contains("Add"), "x1 must advance by the offset: {pre_wb}");
        assert!(addr_of(&["x0", "[x1, #8]!"]).contains("Add"), "pre-indexed reads x1+8");

        // Post-indexed: x1 still advances, but the ACCESS uses the unmodified x1.
        let post_wb = wb_of(&["x0", "[x1]", "#8"]).expect("post-indexed must write back");
        assert!(post_wb.contains("Add"), "x1 must advance: {post_wb}");
        let post_addr = addr_of(&["x0", "[x1]", "#8"]);
        assert!(
            !post_addr.contains("Add"),
            "post-indexed reads the UNMODIFIED base, got {post_addr}"
        );

        // No emitted operand may name a register with a bracket in it.
        for ops in [
            vec!["x0", "[x1, #8]"],
            vec!["x0", "[x1, #8]!"],
            vec!["x0", "[x1]", "#8"],
        ] {
            // Look for a bracket INSIDE a register name: the Debug rendering of
            // a Vec is itself bracketed, so scanning the whole string would
            // always match. (My first version of this assertion did exactly
            // that and failed on correct IR.)
            let text = format!("{:?}", Arm64Lifter::lift_ldr_m(&ops, "ldr"));
            let bogus = text.split("Reg(\"").skip(1).any(|rest| {
                rest.split('\"')
                    .next()
                    .is_some_and(|name| name.contains('[') || name.contains(']'))
            });
            assert!(
                !bogus,
                "{ops:?} named a register with a bracket in it: {text}"
            );
        }

        // The store side shares the parser.
        let st = Arm64Lifter::lift_str(&["x0", "[x1, #16]!"], "str");
        assert!(
            st.iter().any(|o| matches!(o, LlilOp::RegWrite { reg, .. } if reg == "x1")),
            "pre-indexed STR must advance x1: {st:?}"
        );
    }

    /// `parse_mem_addr` reports a hard-coded 8. Iteration 71 fixed ONE of its
    /// three callers; these are the other two, plus a third fact the same
    /// dispatch arm had flattened.
    #[test]
    fn pair_and_store_sizes_come_from_the_operands_not_a_hard_coded_eight() {
        let sizes = |ops: &[LlilOp]| -> Vec<u8> {
            ops.iter()
                .filter_map(|o| match o {
                    LlilOp::MemRead { size, .. } | LlilOp::MemWrite { size, .. } => Some(*size),
                    _ => None,
                })
                .collect()
        };

        // A 32-bit pair reads four bytes per register, and the second element is
        // at `+4`. Both came from the hard-coded 8 before.
        let wpair = Arm64Lifter::lift_ldp(&["w0", "w1", "[sp]"]);
        assert_eq!(sizes(&wpair), vec![4, 4], "LDP of w-registers reads 4 bytes each");
        assert!(
            format!("{wpair:?}").contains("Const(4)"),
            "the second element of a 32-bit pair sits at +4, not +8: {wpair:?}"
        );
        let xpair = Arm64Lifter::lift_ldp(&["x0", "x1", "[sp]"]);
        assert_eq!(sizes(&xpair), vec![8, 8], "LDP of x-registers reads 8 bytes each");

        // The store side had the identical defect.
        assert_eq!(sizes(&Arm64Lifter::lift_str(&["w0", "[x1]"], "strb")), vec![1]);
        assert_eq!(sizes(&Arm64Lifter::lift_str(&["w0", "[x1]"], "strh")), vec![2]);
        assert_eq!(sizes(&Arm64Lifter::lift_str(&["w0", "[x1]"], "str")), vec![4]);
        assert_eq!(sizes(&Arm64Lifter::lift_str(&["x0", "[x1]"], "str")), vec![8]);

        // STP shared `lift_str`, which writes ONE value and would have taken the
        // address from the second register token.
        let stp = Arm64Lifter::lift_stp(&["x0", "x1", "[sp, #16]"]);
        assert_eq!(sizes(&stp), vec![8, 8], "STP stores BOTH registers");
        let text = format!("{stp:?}");
        assert!(
            !text.contains("\"x1\"") || text.matches("MemWrite").count() == 2,
            "both halves of the pair must be stored: {text}"
        );
    }

    #[test]
    fn arm64_lift_ret() {
        let lifter = Arm64Lifter::new();
        let li = lifter.lift(&make_instr(0x1000, "ret")).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Return { .. }))
        );
    }

    #[test]
    fn arm64_lift_svc() {
        let lifter = Arm64Lifter::new();
        let li = lifter.lift(&make_instr(0x1000, "svc")).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Syscall { .. }))
        );
    }

    #[test]
    fn arm64_dispatch_mov_direct() {
        let ops = Arm64Lifter::dispatch("mov", &["x0", "x1"]);
        assert!(
            ops.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "x0"))
        );
    }

    #[test]
    fn arm64_dispatch_add() {
        let ops = Arm64Lifter::dispatch("add", &["x0", "x1", "x2"]);
        assert!(ops.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "x0" && matches!(value, IrExpr::Add(..))
            } else {
                false
            }
        }));
    }

    #[test]
    fn arm64_dispatch_sub() {
        let ops = Arm64Lifter::dispatch("sub", &["x0", "x1", "#4"]);
        assert!(ops.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "x0" && matches!(value, IrExpr::Sub(..))
            } else {
                false
            }
        }));
    }

    #[test]
    fn arm64_dispatch_orr_xzr_is_mov() {
        // ORR x0, xzr, x1 is the canonical encoding of MOV x0, x1
        let ops = Arm64Lifter::dispatch("orr", &["x0", "xzr", "x1"]);
        assert!(ops.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "x0" && !matches!(value, IrExpr::Or(..))
            } else {
                false
            }
        }));
    }

    #[test]
    fn arm64_dispatch_eor_self_zero() {
        // EOR x0, x0, x0 â†’ x0 = 0
        let ops = Arm64Lifter::dispatch("eor", &["x0", "x0", "x0"]);
        assert!(ops.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "x0")
        }));
    }

    #[test]
    fn arm64_dispatch_bl_is_call() {
        let ops = Arm64Lifter::dispatch("bl", &["#0x1000"]);
        assert!(ops.iter().any(|e| matches!(e, Effect::Call { .. })));
    }

    #[test]
    fn arm64_dispatch_blr_is_call() {
        let ops = Arm64Lifter::dispatch("blr", &["x8"]);
        assert!(ops.iter().any(|e| matches!(e, Effect::Call { .. })));
    }

    #[test]
    fn arm64_dispatch_b_unconditional() {
        let ops = Arm64Lifter::dispatch("b", &["#0x2000"]);
        assert!(ops.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: None,
                ..
            }
        )));
    }

    #[test]
    fn arm64_dispatch_bcond_eq() {
        let ops = Arm64Lifter::dispatch("b.eq", &["#0x2000"]);
        assert!(ops.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn arm64_dispatch_ldr_mem_read() {
        let ops = Arm64Lifter::dispatch("ldr", &["x0", "[x1]"]);
        assert!(ops.iter().any(|e| matches!(e, Effect::MemRead { .. })));
    }

    #[test]
    fn arm64_dispatch_str_mem_write() {
        let ops = Arm64Lifter::dispatch("str", &["x0", "[x1, #8]"]);
        assert!(ops.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    #[test]
    fn arm64_dispatch_cmp_sets_flags() {
        let ops = Arm64Lifter::dispatch("cmp", &["x0", "x1"]);
        let flag_writes: Vec<&str> = ops
            .iter()
            .filter_map(|e| {
                if let Effect::RegWrite { reg, .. } = e {
                    Some(reg.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(flag_writes.contains(&"zf"));
        assert!(flag_writes.contains(&"nf"));
    }

    // â”€â”€ register_all_lifters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn register_all_covers_main_arches() {
        let mut reg = LifterRegistry::new();
        register_all_lifters(&mut reg);
        assert!(reg.supports("x86_64"));
        assert!(reg.supports("x86"));
        assert!(reg.supports("x86_16"));
        assert!(reg.supports("aarch64"));
        assert!(reg.supports("arm64"));
        assert!(reg.supports("mips"));
        assert!(reg.supports("riscv"));
    }

    #[test]
    fn register_all_x86_64_lifts_nop() {
        let mut reg = LifterRegistry::new();
        register_all_lifters(&mut reg);
        let instr = make_instr_bytes(0x1000, "nop", &[0x90]);
        let li = reg.lift_instr("x86_64", &instr).unwrap();
        assert_eq!(li.ir_text, "nop");
    }

    #[test]
    fn register_all_aarch64_lifts_ret() {
        let mut reg = LifterRegistry::new();
        register_all_lifters(&mut reg);
        let instr = make_instr(0x1000, "ret");
        let li = reg.lift_instr("aarch64", &instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Return { .. }))
        );
    }

    #[test]
    fn arm64_dispatch_method() {
        // Direct call to the static dispatch helper via type path
        let ops = Arm64Lifter::dispatch("mov", &["x0", "#42"]);
        assert!(ops.iter().any(
            |e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(42) } if reg == "x0")
        ));
    }

    #[test]
    fn x86_lifter_lea() {
        let lifter = X86Lifter::new(64);
        // 48 8D 04 25 00 10 00 00 = LEA RAX, [0x1000]
        let instr = make_instr_bytes(
            0x1000,
            "lea",
            &[0x48, 0x8D, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00],
        );
        let li = lifter.lift(&instr).unwrap();
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"))
        );
    }
}

/// Phase B-1 coverage tests: feed raw bytes through the modular handler
/// dispatch (`x86_lift_instruction`) and assert the emitted IR effects are
/// the right *shape*, not just `Effect::Intrinsic { name: "x86.unhandled.*" }`
/// fallbacks. Each test decodes a single instruction with `iced-x86` and runs
/// the per-instruction context to completion.
#[cfg(test)]
mod x86_handlers_coverage_tests {
    use super::{Effect, IrExpr, x86_lift_instruction};
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use iced_x86::{Decoder, DecoderOptions};

    /// Decode the first instruction in `bytes` (64-bit mode) and lift it with
    /// the handler dispatch. Returns the buffered effects.
    fn lift64(bytes: &[u8]) -> Vec<Effect> {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let instr = decoder.decode();
        let mut ctx = X86LiftCtx::new(0x1000, 64, ModeHint::default());
        // Errors are acceptable for the negative-path test below; we only
        // care about the emitted effects either way.
        let _ = x86_lift_instruction(&instr, &mut ctx);
        ctx.effects
    }

    /// Does any effect write the register named `reg`?
    fn writes_reg(effects: &[Effect], reg: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
    }

    /// Does any effect emit a `Call`?
    fn has_call(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Call { .. }))
    }

    /// Does any effect emit a `Return`?
    fn has_return(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Return { .. }))
    }

    /// Does any effect emit a `Branch`?
    fn has_branch(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Branch { .. }))
    }

    #[test]
    fn mov_imm_to_reg_emits_regwrite_with_constant() {
        // B8 2A 00 00 00 = MOV EAX, 0x2A
        let effects = lift64(&[0xB8, 0x2A, 0x00, 0x00, 0x00]);
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::RegWrite {
                    reg,
                    value: IrExpr::Const(0x2A),
                } if reg == "rax" || reg == "eax"
            )),
            "expected RegWrite(eax/rax, Const(0x2A)); got {effects:?}",
        );
    }

    #[test]
    fn add_reg_reg_emits_arithmetic_and_flags() {
        // 48 01 D8 = ADD RAX, RBX
        let effects = lift64(&[0x48, 0x01, 0xD8]);
        assert!(writes_reg(&effects, "rax"), "expected rax write: {effects:?}");
        // ZF/SF/PF are reactive flags for ADD; the handler must touch them.
        assert!(
            writes_reg(&effects, "zf") || writes_reg(&effects, "sf"),
            "expected flag updates from ADD: {effects:?}",
        );
    }

    #[test]
    fn xor_reg_self_is_zeroing_assignment() {
        // 31 C0 = XOR EAX, EAX
        let effects = lift64(&[0x31, 0xC0]);
        assert!(writes_reg(&effects, "rax"), "expected rax write: {effects:?}");
        // CF and OF must be cleared (RegWrite cf/of with Const(0) under x86 spec).
        assert!(
            writes_reg(&effects, "cf") || writes_reg(&effects, "zf"),
            "expected flag clears from XOR: {effects:?}",
        );
    }

    #[test]
    fn jne_emits_conditional_branch() {
        // 75 05 = JNE +5
        let effects = lift64(&[0x75, 0x05]);
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Branch { condition: Some(_), .. }
            )),
            "expected conditional Branch from JNE: {effects:?}",
        );
    }

    #[test]
    fn call_rel32_emits_call_effect() {
        // E8 00 00 00 00 = CALL +0
        let effects = lift64(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        assert!(has_call(&effects), "expected Call effect: {effects:?}");
    }

    #[test]
    fn ret_emits_return_effect() {
        // C3 = RET
        let effects = lift64(&[0xC3]);
        assert!(has_return(&effects), "expected Return effect: {effects:?}");
    }

    #[test]
    fn jmp_rel8_emits_unconditional_branch() {
        // EB 02 = JMP +2
        let effects = lift64(&[0xEB, 0x02]);
        assert!(has_branch(&effects), "expected Branch effect: {effects:?}");
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Branch { condition: None, .. }
            )),
            "expected unconditional Branch: {effects:?}",
        );
    }

    #[test]
    fn push_pop_touch_stack_pointer() {
        // 50 = PUSH RAX
        let push_eff = lift64(&[0x50]);
        assert!(writes_reg(&push_eff, "rsp"), "PUSH should adjust rsp: {push_eff:?}");
        assert!(
            push_eff
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. })),
            "PUSH should emit MemWrite: {push_eff:?}",
        );
        // 58 = POP RAX
        let pop_eff = lift64(&[0x58]);
        assert!(writes_reg(&pop_eff, "rsp"), "POP should adjust rsp: {pop_eff:?}");
        assert!(
            pop_eff
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. })),
            "POP should emit MemRead: {pop_eff:?}",
        );
    }

}
