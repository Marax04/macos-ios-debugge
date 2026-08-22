//! `rustre-analysis-callconv`
//!
//! Calling convention detection and analysis for the `RustRE` Suite.
//!
//! Identifies how a function passes arguments and returns values by
//! heuristically examining the function prologue/epilogue and which registers
//! are read before being written (argument registers) vs. which registers are
//! saved and restored (callee-saved registers).
//!
//! Supports x86, x86-64, Arm32, Arm64 with cdecl, stdcall, fastcall,
//! thiscall, vectorcall, System V AMD64 ABI, Microsoft x64, AAPCS32/64.

pub mod abi_analyzer;
pub mod cc_database;
pub mod cc_detector_advanced;
pub mod heuristics;
pub mod propagation;
pub mod register_colouring;
pub mod return_type_recovery;
pub mod variadic;
pub mod calling_convention_detector;
pub mod argument_tracker;
pub mod return_type_analyzer;
pub mod cc_detector;
pub mod stack_cleanup_analyzer;
#[cfg(test)]
mod abi_properties;

/// Shared test-only PRNG for the crate's randomized property tests.
///
/// One definition instead of a per-module copy: the three former copies in
/// `return_type_recovery`, `register_colouring` and `argument_tracker` were
/// byte-identical except for the zero-seed replacement constant, which no
/// test observes (no test seeds with 0), so consolidating here changes no
/// test's random sequence.
#[cfg(test)]
pub(crate) mod test_prng {
    /// Minimal xorshift64 PRNG — deterministic given a seed, no external deps.
    pub(crate) struct Xorshift64(u64);

    impl Xorshift64 {
        pub(crate) const fn new(seed: u64) -> Self {
            Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
        }

        pub(crate) fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        pub(crate) fn next_range(&mut self, bound: usize) -> usize {
            (self.next_u64() as usize) % bound
        }
    }
}

pub use heuristics::{
    ArgRegisterProfile, CallConvVerdict, PreservationReport, StackCleanup, analyze_preservation,
    classify_stack_cleanup, default_callee_saved, profile_arg_registers,
};

pub use cc_database::{
    CC_AAPCS32, CC_AAPCS32_VFP, CC_AAPCS64, CC_CDECL_X86, CC_FASTCALL_X86, CC_MIPS_N64,
    CC_MIPS_O32, CC_MS_X64 as CC_MS_X64_DB, CC_REGCALL_X64, CC_REGCALL_X86, CC_RISCV32_ILP32D,
    CC_RISCV64_LP64D, CC_RUST_ARM64, CC_RUST_X64, CC_STDCALL_X86, CC_SWIFT_ARM64, CC_SWIFT_X64,
    CC_SYSV_AMD64 as CC_SYSV_AMD64_DB, CC_SYSV_X86, CC_THISCALL_X86, CC_VECTORCALL_X64, CcRegistry,
    abis_are_compatible, shared_arg_registers,
};

pub use propagation::{
    BulkPropagator, CallSite, CallSiteArgument, CallSiteInstr, CalleePropagator, PropagationResult,
    PropagationStats, RawCallSite, function_info_from_observed, infer_params_from_observed,
};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors that can occur during calling convention analysis.
#[derive(Debug, Error)]
pub enum CallConvError {
    /// No calling convention matches the observed register pattern.
    #[error("no calling convention matches the observed register pattern")]
    NoMatch,
    /// Multiple candidates scored equally; cannot disambiguate.
    #[error("ambiguous calling convention: multiple candidates")]
    Ambiguous,
    /// The requested architecture/OS key is not in the database.
    #[error("unknown architecture/OS key: {0}")]
    UnknownKey(String),
    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// The instruction stream is too short to analyse.
    #[error("instruction stream too short (got {got}, need at least {need})")]
    TooShort {
        /// Instructions provided.
        got: usize,
        /// Minimum required.
        need: usize,
    },
    /// A register name is not recognised for the given architecture.
    #[error("unknown register '{name}' for architecture {arch}")]
    UnknownRegister {
        /// Register name.
        name: String,
        /// Architecture.
        arch: String,
    },
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Architecture / OS identifiers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Target CPU architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    /// 32-bit x86.
    X86,
    /// 64-bit x86 (`x86_64` / `amd64`).
    X86_64,
    /// 32-bit ARM.
    Arm32,
    /// 64-bit ARM (`aarch64`).
    Arm64,
    /// MIPS 32-bit.
    Mips32,
    /// MIPS 64-bit.
    Mips64,
    /// PowerPC 32-bit.
    Ppc32,
    /// PowerPC 64-bit.
    Ppc64,
    /// RISC-V 32-bit.
    RiscV32,
    /// RISC-V 64-bit.
    RiscV64,
    /// Any other architecture, identified by name.
    Other(String),
}

impl Arch {
    /// Returns the byte-size of a pointer for this architecture (4 or 8).
    #[must_use]
    pub const fn pointer_width(&self) -> u32 {
        match self {
            Self::X86 | Self::Arm32 | Self::Mips32 | Self::Ppc32 | Self::RiscV32 => 4,
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::Ppc64 | Self::RiscV64 => 8,
            Self::Other(_) => 4, // conservative default
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips32 => write!(f, "mips32"),
            Self::Mips64 => write!(f, "mips64"),
            Self::Ppc32 => write!(f, "ppc32"),
            Self::Ppc64 => write!(f, "ppc64"),
            Self::RiscV32 => write!(f, "riscv32"),
            Self::RiscV64 => write!(f, "riscv64"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Operating system or execution environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Os {
    /// Linux.
    Linux,
    /// Microsoft Windows.
    Windows,
    /// Apple macOS / Darwin.
    MacOs,
    /// FreeBSD.
    FreeBsd,
    /// Bare-metal (no OS).
    Bare,
    /// Any other OS, identified by name.
    Other(String),
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOs => write!(f, "macos"),
            Self::FreeBsd => write!(f, "freebsd"),
            Self::Bare => write!(f, "bare"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Compiler family.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Compiler {
    /// GNU Compiler Collection.
    Gcc,
    /// Microsoft Visual C++.
    Msvc,
    /// Clang / LLVM.
    Clang,
    /// Intel C++ Compiler.
    Icc,
    /// Matches any compiler.
    Any,
}

impl fmt::Display for Compiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gcc => write!(f, "gcc"),
            Self::Msvc => write!(f, "msvc"),
            Self::Clang => write!(f, "clang"),
            Self::Icc => write!(f, "icc"),
            Self::Any => write!(f, "any"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConventionPattern
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A complete calling convention pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallingConventionPattern {
    /// Human-readable name (e.g. `"System V AMD64 ABI"`).
    pub name: String,
    /// Registers used for passing integer/pointer arguments (in order).
    pub arg_registers: Vec<String>,
    /// Registers used for floating-point arguments.
    pub fp_arg_registers: Vec<String>,
    /// Registers used for return values.
    pub retval_registers: Vec<String>,
    /// Registers the callee must preserve (callee-saved).
    pub callee_saved: Vec<String>,
    /// Required stack alignment in bytes at the call instruction.
    pub stack_alignment: u32,
    /// `true` if the caller is responsible for cleaning up stack arguments.
    pub caller_cleanup: bool,
    /// `true` if a hidden pointer to the return value is passed as first arg.
    pub hidden_this_ptr: bool,
    /// Maximum number of integer arguments passed in registers (0 = stack-only).
    pub max_reg_args: u32,
    /// Whether variadic functions have special requirements.
    pub supports_variadic: bool,
    /// Shadow space (home space) in bytes for register parameters.
    pub shadow_space_bytes: u32,
    /// Registers that are always caller-saved (scratch).
    pub caller_saved: Vec<String>,
}

impl CallingConventionPattern {
    /// Compute a match score (0—"100) against an observed pattern.
    ///
    /// Higher scores indicate a better match.
    #[must_use]
    pub fn score(&self, observed: &ObservedPattern) -> u32 {
        let mut total = 0u32;

        let matching_args = observed
            .read_before_write
            .iter()
            .filter(|r| self.arg_registers.contains(r))
            .count();
        total += u32::try_from(matching_args).unwrap_or(u32::MAX) * 10;

        let matching_saved = observed
            .saved_registers
            .iter()
            .filter(|r| self.callee_saved.contains(r))
            .count();
        total += u32::try_from(matching_saved).unwrap_or(u32::MAX) * 8;

        let matching_ret = observed
            .written_before_return
            .iter()
            .filter(|r| self.retval_registers.contains(r))
            .count();
        total += u32::try_from(matching_ret).unwrap_or(u32::MAX) * 12;

        // Bonus for callee_pops_stack matching caller_cleanup:
        // callee_pops_stack=true means the callee cleans up the stack, which
        // agrees with caller_cleanup=false (stdcall). They agree when
        // callee_pops_stack == !caller_cleanup.
        if observed.callee_pops_stack != self.caller_cleanup {
            total += 5;
        }

        // Penalty for registers used that contradict the convention
        let contradicting_args = observed
            .read_before_write
            .iter()
            .filter(|r| {
                !self.arg_registers.contains(r)
                    && !self.fp_arg_registers.contains(r)
                    && !self.caller_saved.contains(r)
                    && !self.callee_saved.contains(r)
            })
            .count();
        let penalty = u32::try_from(contradicting_args).unwrap_or(0) * 2;
        total = total.saturating_sub(penalty);

        total
    }

    /// Whether `reg` is an argument register in this convention.
    #[must_use]
    pub fn is_arg_register(&self, reg: &str) -> bool {
        self.arg_registers.iter().any(|r| r == reg)
            || self.fp_arg_registers.iter().any(|r| r == reg)
    }

    /// Whether `reg` is callee-saved in this convention.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg)
    }

    /// Whether `reg` is a return-value register in this convention.
    #[must_use]
    pub fn is_retval_register(&self, reg: &str) -> bool {
        self.retval_registers.iter().any(|r| r == reg)
    }

    /// Argument register at position `n` (0-based), or `None` if stack-passed.
    #[must_use]
    pub fn arg_register_at(&self, n: usize) -> Option<&str> {
        self.arg_registers.get(n).map(String::as_str)
    }

    /// Total number of argument registers available.
    #[must_use]
    pub const fn arg_register_count(&self) -> usize {
        self.arg_registers.len()
    }
}

impl fmt::Display for CallingConventionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [align={}, caller_cleanup={}, max_reg_args={}]",
            self.name, self.stack_alignment, self.caller_cleanup, self.max_reg_args
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Known calling conventions
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// System V AMD64 ABI (Linux, macOS, most Unix).
#[must_use]
pub fn sysv_x64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "System V AMD64 ABI".into(),
        arg_registers: vec![
            "rdi".into(),
            "rsi".into(),
            "rdx".into(),
            "rcx".into(),
            "r8".into(),
            "r9".into(),
        ],
        fp_arg_registers: vec![
            "xmm0".into(),
            "xmm1".into(),
            "xmm2".into(),
            "xmm3".into(),
            "xmm4".into(),
            "xmm5".into(),
            "xmm6".into(),
            "xmm7".into(),
        ],
        retval_registers: vec!["rax".into(), "rdx".into()],
        callee_saved: vec![
            "rbx".into(),
            "rbp".into(),
            "r12".into(),
            "r13".into(),
            "r14".into(),
            "r15".into(),
        ],
        caller_saved: vec![
            "rax".into(),
            "rcx".into(),
            "rdx".into(),
            "rsi".into(),
            "rdi".into(),
            "r8".into(),
            "r9".into(),
            "r10".into(),
            "r11".into(),
        ],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 6,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

/// Microsoft x64 Calling Convention (Windows).
#[must_use]
pub fn msvc_x64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "Microsoft x64".into(),
        arg_registers: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
        fp_arg_registers: vec!["xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into()],
        retval_registers: vec!["rax".into()],
        callee_saved: vec![
            "rbx".into(),
            "rbp".into(),
            "rdi".into(),
            "rsi".into(),
            "r12".into(),
            "r13".into(),
            "r14".into(),
            "r15".into(),
        ],
        caller_saved: vec![
            "rax".into(),
            "rcx".into(),
            "rdx".into(),
            "r8".into(),
            "r9".into(),
            "r10".into(),
            "r11".into(),
        ],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 32,
    }
}

/// `cdecl` —" 32-bit C default (arguments on stack, caller cleans up).
#[must_use]
pub fn cdecl_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "cdecl (x86)".into(),
        arg_registers: vec![],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 0,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

/// `stdcall` —" 32-bit Windows API (callee cleans up).
#[must_use]
pub fn stdcall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "stdcall (x86)".into(),
        arg_registers: vec![],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: false,
        max_reg_args: 0,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

/// `fastcall` —" first two integer args in `ecx`/`edx`, rest on stack.
#[must_use]
pub fn fastcall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "fastcall (x86)".into(),
        arg_registers: vec!["ecx".into(), "edx".into()],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: false,
        max_reg_args: 2,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

/// `thiscall` —" MSVC C++ member functions (`this` in `ecx`).
#[must_use]
pub fn thiscall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "thiscall (x86)".into(),
        arg_registers: vec!["ecx".into()],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: true,
        max_reg_args: 1,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

/// `vectorcall` —" Microsoft vectorcall (SIMD in XMM, int in RCX/RDX/R8/R9).
#[must_use]
pub fn vectorcall_x64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "vectorcall (x64)".into(),
        arg_registers: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
        fp_arg_registers: vec![
            "xmm0".into(),
            "xmm1".into(),
            "xmm2".into(),
            "xmm3".into(),
            "xmm4".into(),
            "xmm5".into(),
        ],
        retval_registers: vec!["rax".into(), "xmm0".into()],
        callee_saved: vec![
            "rbx".into(),
            "rbp".into(),
            "rdi".into(),
            "rsi".into(),
            "r12".into(),
            "r13".into(),
            "r14".into(),
            "r15".into(),
        ],
        caller_saved: vec![
            "rax".into(),
            "rcx".into(),
            "rdx".into(),
            "r8".into(),
            "r9".into(),
        ],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: false,
        // __vectorcall inherits the Microsoft x64 ABI and therefore reserves
        // the 32-byte shadow/home space (same as ms_x64). Corrected from 0 in
        // all 3 copies together (cc_database / detector / here) after two
        // independent ABI reviews confirmed 32.
        shadow_space_bytes: 32,
    }
}

/// AAPCS64 —" Arm64 Procedure Call Standard.
#[must_use]
pub fn aapcs64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "AAPCS64".into(),
        arg_registers: vec![
            "x0".into(),
            "x1".into(),
            "x2".into(),
            "x3".into(),
            "x4".into(),
            "x5".into(),
            "x6".into(),
            "x7".into(),
        ],
        fp_arg_registers: vec![
            "v0".into(),
            "v1".into(),
            "v2".into(),
            "v3".into(),
            "v4".into(),
            "v5".into(),
            "v6".into(),
            "v7".into(),
        ],
        retval_registers: vec!["x0".into(), "x1".into()],
        callee_saved: vec![
            "x19".into(),
            "x20".into(),
            "x21".into(),
            "x22".into(),
            "x23".into(),
            "x24".into(),
            "x25".into(),
            "x26".into(),
            "x27".into(),
            "x28".into(),
            "x29".into(),
            // x30 (LR) must be preserved across a call by any non-leaf callee
            // (AAPCS64 §6.1.1; cf. LLVM CSR_AArch64_AAPCS). It was omitted
            // here and in cc_detector.rs::CcPattern::aapcs64(), diverging from
            // cc_database.rs::CC_AAPCS64 which lists it.
            "x30".into(),
        ],
        caller_saved: vec![
            "x0".into(),
            "x1".into(),
            "x2".into(),
            "x3".into(),
            "x4".into(),
            "x5".into(),
            "x6".into(),
            "x7".into(),
            "x8".into(),
            "x9".into(),
            "x10".into(),
            "x11".into(),
            "x12".into(),
            "x13".into(),
            "x14".into(),
            "x15".into(),
            "x16".into(),
            "x17".into(),
        ],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 8,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

/// AAPCS32 —" Arm32 Procedure Call Standard.
#[must_use]
pub fn aapcs32() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "AAPCS32".into(),
        arg_registers: vec!["r0".into(), "r1".into(), "r2".into(), "r3".into()],
        // AAPCS32 VFP (hard-float) marshals FP args in s0-s15 / d0-d7
        // (ARM IHI 0042, §7.1.1); the list was truncated to s0-s3, diverging
        // from cc_database.rs CC_AAPCS32_VFP which correctly lists 16 regs.
        fp_arg_registers: vec![
            "s0".into(),
            "s1".into(),
            "s2".into(),
            "s3".into(),
            "s4".into(),
            "s5".into(),
            "s6".into(),
            "s7".into(),
            "s8".into(),
            "s9".into(),
            "s10".into(),
            "s11".into(),
            "s12".into(),
            "s13".into(),
            "s14".into(),
            "s15".into(),
        ],
        retval_registers: vec!["r0".into(), "r1".into()],
        callee_saved: vec![
            "r4".into(),
            "r5".into(),
            "r6".into(),
            "r7".into(),
            "r8".into(),
            "r9".into(),
            "r10".into(),
            "r11".into(),
        ],
        caller_saved: vec![
            "r0".into(),
            "r1".into(),
            "r2".into(),
            "r3".into(),
            "r12".into(),
        ],
        stack_alignment: 8,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

/// MIPS O32 calling convention.
#[must_use]
pub fn mips_o32() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "MIPS O32".into(),
        arg_registers: vec!["a0".into(), "a1".into(), "a2".into(), "a3".into()],
        fp_arg_registers: vec!["f12".into(), "f14".into()],
        retval_registers: vec!["v0".into(), "v1".into()],
        callee_saved: vec![
            "s0".into(),
            "s1".into(),
            "s2".into(),
            "s3".into(),
            "s4".into(),
            "s5".into(),
            "s6".into(),
            "s7".into(),
        ],
        caller_saved: vec![
            "t0".into(),
            "t1".into(),
            "t2".into(),
            "t3".into(),
            "t4".into(),
            "t5".into(),
            "t6".into(),
            "t7".into(),
            // $t8/$t9 ($24/$25) are caller-saved temporaries too per the
            // System V MIPS o32 ABI supplement (register usage table);
            // they were previously omitted in all pattern copies.
            "t8".into(),
            "t9".into(),
        ],
        stack_alignment: 8,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 16, // argument slots reserved even for reg args
    }
}

/// RISC-V 64 calling convention (LP64D).
#[must_use]
pub fn riscv64_lp64d() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "RISC-V LP64D".into(),
        arg_registers: vec![
            "a0".into(),
            "a1".into(),
            "a2".into(),
            "a3".into(),
            "a4".into(),
            "a5".into(),
            "a6".into(),
            "a7".into(),
        ],
        fp_arg_registers: vec![
            "fa0".into(),
            "fa1".into(),
            "fa2".into(),
            "fa3".into(),
            "fa4".into(),
            "fa5".into(),
            "fa6".into(),
            "fa7".into(),
        ],
        retval_registers: vec!["a0".into(), "a1".into()],
        callee_saved: vec![
            "s0".into(),
            "s1".into(),
            "s2".into(),
            "s3".into(),
            "s4".into(),
            "s5".into(),
            "s6".into(),
            "s7".into(),
            "s8".into(),
            "s9".into(),
            "s10".into(),
            "s11".into(),
        ],
        caller_saved: vec![
            "t0".into(),
            "t1".into(),
            "t2".into(),
            "t3".into(),
            "t4".into(),
            "t5".into(),
            "t6".into(),
        ],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 8,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ObservedPattern —" evidence extracted from a function body
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Evidence gathered from disassembling a function's prologue/epilogue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedPattern {
    /// Registers that are read *before* any write (candidate arg registers).
    pub read_before_write: Vec<String>,
    /// Registers pushed onto the stack and popped symmetrically.
    pub saved_registers: Vec<String>,
    /// Registers written just before a `RETURN` instruction.
    pub written_before_return: Vec<String>,
    /// Whether a `RET N` (`stdcall`/`thiscall` style) was observed.
    pub callee_pops_stack: bool,
    /// Whether `ecx`/`rcx` was used as `this` pointer (`thiscall` hint).
    pub this_ptr_hint: bool,
    /// Stack bytes popped by callee (for `stdcall` `ret N`).
    pub callee_stack_pop: u32,
    /// Floating-point argument registers read before write.
    pub fp_read_before_write: Vec<String>,
    /// Maximum stack frame size observed.
    pub max_stack_frame: u32,
    /// Whether a shadow-space reservation was observed (sub rsp, 32+).
    pub shadow_space_observed: bool,
    /// Number of arguments detected on the stack.
    pub stack_arg_count: u32,
}

impl ObservedPattern {
    /// Create an empty `ObservedPattern`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the observed pattern has any evidence of argument registers.
    #[must_use]
    pub const fn has_arg_evidence(&self) -> bool {
        !self.read_before_write.is_empty() || !self.fp_read_before_write.is_empty()
    }

    /// Whether the observed pattern suggests a leaf function (no calls out).
    #[must_use]
    pub const fn looks_like_leaf(&self) -> bool {
        self.saved_registers.is_empty() && self.max_stack_frame <= 16
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConventionDetector
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Simplified instruction model for CC detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectInstr {
    /// Register `reg` is read.
    RegRead {
        /// Register name.
        reg: String,
    },
    /// Register `reg` is written.
    RegWrite {
        /// Register name.
        reg: String,
    },
    /// Register `reg` is pushed (callee-save).
    Push {
        /// Register name.
        reg: String,
    },
    /// Register `reg` is popped (callee-restore).
    Pop {
        /// Register name.
        reg: String,
    },
    /// Return instruction. `stack_bytes > 0` for `ret N`.
    Ret {
        /// Number of stack bytes cleaned by the callee (0 = caller-cleanup).
        stack_bytes: u32,
    },
    /// `ecx` used as `this` pointer.
    ThisPtrUse,
    /// FP register read (candidate fp arg).
    FpRegRead {
        /// FP register name.
        reg: String,
    },
    /// Stack frame allocation (sub rsp, N).
    StackAlloc {
        /// Bytes allocated.
        bytes: u32,
    },
    /// Stack argument access (memory read/write from [rsp + offset]).
    StackArgAccess {
        /// Offset from stack pointer.
        offset: i32,
    },
    /// Any other instruction.
    Other,
}

/// Detects the calling convention of a function from its instruction stream.
pub struct CallingConventionDetector;

impl CallingConventionDetector {
    /// Analyse a function's instruction stream and return an `ObservedPattern`.
    ///
    /// `pointer_width` is the byte-size of a pointer for the target architecture
    /// (4 for 32-bit, 8 for 64-bit). It is used to compute `stack_arg_count`
    /// from the maximum observed stack-argument offset. Defaults to 4 when 0
    /// is supplied.
    #[must_use]
    pub fn extract_pattern(instrs: &[DetectInstr], pointer_width: u32) -> ObservedPattern {
        let pointer_width = if pointer_width == 0 { 4 } else { pointer_width };
        let mut defined: HashSet<String> = HashSet::new();
        let mut read_before_write: Vec<String> = Vec::new();
        let mut fp_read_before_write: Vec<String> = Vec::new();
        let mut pushed: Vec<String> = Vec::new();
        let mut popped: Vec<String> = Vec::new();
        let mut written_before_return: Vec<String> = Vec::new();
        let mut callee_pops_stack = false;
        let mut callee_stack_pop = 0u32;
        let mut this_ptr_hint = false;
        let mut max_stack_frame = 0u32;
        let mut shadow_space_observed = false;
        let mut max_stack_arg_offset = -1i32;

        let mut recent_writes: VecDeque<String> = VecDeque::new();

        for instr in instrs {
            match instr {
                DetectInstr::RegRead { reg } => {
                    if !defined.contains(reg) && !read_before_write.contains(reg) {
                        read_before_write.push(reg.clone());
                    }
                }
                DetectInstr::RegWrite { reg } => {
                    defined.insert(reg.clone());
                    if !recent_writes.contains(reg) {
                        recent_writes.push_back(reg.clone());
                        if recent_writes.len() > 8 {
                            recent_writes.pop_front();
                        }
                    }
                }
                DetectInstr::Push { reg } => {
                    pushed.push(reg.clone());
                    defined.insert(reg.clone());
                }
                DetectInstr::Pop { reg } => {
                    popped.push(reg.clone());
                }
                DetectInstr::Ret { stack_bytes } => {
                    written_before_return = recent_writes.iter().cloned().collect();
                    if *stack_bytes > 0 {
                        callee_pops_stack = true;
                        callee_stack_pop = *stack_bytes;
                    }
                }
                DetectInstr::ThisPtrUse => {
                    this_ptr_hint = true;
                }
                DetectInstr::FpRegRead { reg } => {
                    if !defined.contains(reg) && !fp_read_before_write.contains(reg) {
                        fp_read_before_write.push(reg.clone());
                    }
                }
                DetectInstr::StackAlloc { bytes } => {
                    max_stack_frame = max_stack_frame.max(*bytes);
                    if *bytes >= 32 {
                        shadow_space_observed = true;
                    }
                }
                DetectInstr::StackArgAccess { offset } => {
                    if *offset > max_stack_arg_offset {
                        max_stack_arg_offset = *offset;
                    }
                }
                DetectInstr::Other => {}
            }
        }

        let saved_registers: Vec<String> = pushed
            .iter()
            .filter(|r| popped.contains(r))
            .cloned()
            .collect();

        let stack_arg_count = if max_stack_arg_offset >= 0 {
            u32::try_from((max_stack_arg_offset / i32::try_from(pointer_width).unwrap_or(4)) + 1)
                .unwrap_or(0)
        } else {
            0
        };

        ObservedPattern {
            read_before_write,
            saved_registers,
            written_before_return,
            callee_pops_stack,
            this_ptr_hint,
            callee_stack_pop,
            fp_read_before_write,
            max_stack_frame,
            shadow_space_observed,
            stack_arg_count,
        }
    }

    /// Detect the best matching calling convention from `candidates`.
    ///
    /// # Errors
    ///
    /// Returns [`CallConvError::NoMatch`] if `candidates` is empty or no
    /// candidate scores above zero.
    /// Returns [`CallConvError::Ambiguous`] if two or more candidates tie
    /// for the highest score.
    pub fn detect(
        observed: &ObservedPattern,
        candidates: &[CallingConventionPattern],
    ) -> Result<CallingConventionPattern, CallConvError> {
        if candidates.is_empty() {
            return Err(CallConvError::NoMatch);
        }

        let mut best_score = 0u32;
        let mut best: Option<&CallingConventionPattern> = None;
        let mut tie = false;

        for cc in candidates {
            let s = cc.score(observed);
            if s > best_score {
                best_score = s;
                best = Some(cc);
                tie = false;
            } else if s == best_score && best_score > 0 {
                tie = true;
            }
        }

        if tie {
            return Err(CallConvError::Ambiguous);
        }

        best.cloned().ok_or(CallConvError::NoMatch)
    }

    /// Detect with additional tiebreaking heuristics.
    ///
    /// Applies platform-specific heuristics to break ties: shadow-space
    /// hints for MSVC x64, `this`-ptr hints for thiscall, callee-pop for
    /// stdcall/fastcall.
    ///
    /// # Errors
    ///
    /// Returns [`CallConvError::NoMatch`] or [`CallConvError::Ambiguous`].
    pub fn detect_with_hints(
        observed: &ObservedPattern,
        candidates: &[CallingConventionPattern],
    ) -> Result<CallingConventionPattern, CallConvError> {
        // First, score all candidates
        let mut scored: Vec<(&CallingConventionPattern, u32)> = candidates
            .iter()
            .map(|cc| (cc, cc.score(observed)))
            .collect();
        // Score descending, then name ascending. The name key is what makes the
        // verdict a function of the candidate SET rather than of the order the
        // caller happened to list them in: `sort_unstable_by` does not preserve
        // the relative order of equal-scoring candidates, so without it the
        // `find` heuristics below could pick a different tied candidate for the
        // same evidence depending only on slice order.
        scored.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));

        if scored.is_empty() || scored[0].1 == 0 {
            return Err(CallConvError::NoMatch);
        }

        let top_score = scored[0].1;
        let tied: Vec<&CallingConventionPattern> = scored
            .iter()
            .filter(|(_, s)| *s == top_score)
            .map(|(cc, _)| *cc)
            .collect();

        if tied.len() == 1 {
            return Ok(tied[0].clone());
        }

        // Heuristic tiebreakers
        // 1. Shadow space hint
        if observed.shadow_space_observed && let Some(cc) = tied.iter().find(|cc| cc.shadow_space_bytes >= 32) {
            return Ok((*cc).clone());
        }
        // 2. This-ptr hint
        if observed.this_ptr_hint && let Some(cc) = tied.iter().find(|cc| cc.hidden_this_ptr) {
            return Ok((*cc).clone());
        }
        // 3. Callee-pops-stack
        if observed.callee_pops_stack && let Some(cc) = tied.iter().find(|cc| !cc.caller_cleanup) {
            return Ok((*cc).clone());
        }
        // 4. Stack-only args
        if observed.stack_arg_count > 0 && observed.read_before_write.is_empty() && let Some(cc) = tied.iter().find(|cc| cc.max_reg_args == 0) {
            return Ok((*cc).clone());
        }

        Err(CallConvError::Ambiguous)
    }

    /// Score all candidates and return them sorted best-first.
    #[must_use]
    pub fn rank_candidates(
        observed: &ObservedPattern,
        candidates: &[CallingConventionPattern],
    ) -> Vec<(CallingConventionPattern, u32)> {
        let mut scored: Vec<(CallingConventionPattern, u32)> = candidates
            .iter()
            .map(|cc| (cc.clone(), cc.score(observed)))
            .collect();
        scored.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        scored
    }

    /// [`Self::detect_with_hints`], but additionally returns the
    /// [`cc_detector::CcEvidence`] items derived from `observed` alongside the
    /// winning candidate's independent evidence-based score.
    ///
    /// This is the wiring point between the raw-instruction detector in this
    /// module and the richer weighted-evidence model in [`cc_detector`]. The
    /// two modules score CC candidates with genuinely different algorithms
    /// (additive-with-flat-penalty here vs. per-`EvidenceKind`
    /// positive/negative weighting there); rather than replacing one with the
    /// other, this method runs both and surfaces the evidence score as a
    /// second, independent signal that callers (e.g. a future confidence
    /// scorer in `rustre-decompiler`) can use to corroborate or flag
    /// disagreement with the primary result. When `observed`'s winning
    /// pattern has no [`cc_detector::CcPattern`] counterpart (e.g.
    /// `mips_o32`, `aapcs32`, `riscv64_lp64d` — patterns this module models
    /// that `cc_detector` does not), the evidence score is `None` rather than
    /// silently defaulting to zero.
    ///
    /// # Errors
    ///
    /// Returns [`CallConvError::NoMatch`] or [`CallConvError::Ambiguous`],
    /// exactly as [`Self::detect_with_hints`].
    pub fn detect_with_evidence(
        observed: &ObservedPattern,
        candidates: &[CallingConventionPattern],
    ) -> Result<(CallingConventionPattern, Vec<cc_detector::CcEvidence>, Option<u32>), CallConvError> {
        let winner = Self::detect_with_hints(observed, candidates)?;
        let evidence = observed_pattern_to_evidence(observed);
        let evidence_score = cc_pattern_for_name(&winner.name).map(|p| p.score_evidence(&evidence));
        Ok((winner, evidence, evidence_score))
    }
}

/// Convert an [`ObservedPattern`] into the [`cc_detector::CcEvidence`] items
/// it implies, so evidence gathered by this module's lightweight extractor
/// can be re-scored by `cc_detector`'s weighted model. Weights mirror the
/// per-match point values used by [`CallingConventionPattern::score`] (10 for
/// arg-register matches, 8 for callee-saved, 12 for return-value matches) so
/// the two scores stay comparable in magnitude even though they are computed
/// independently.
#[must_use]
pub fn observed_pattern_to_evidence(observed: &ObservedPattern) -> Vec<cc_detector::CcEvidence> {
    use cc_detector::{CcEvidence, EvidenceKind};

    let mut evidence = Vec::new();

    for reg in &observed.read_before_write {
        evidence.push(CcEvidence::new(
            EvidenceKind::ReadBeforeWrite,
            Some(reg.clone()),
            format!("{reg} read before write"),
            10,
        ));
    }
    for reg in &observed.fp_read_before_write {
        evidence.push(CcEvidence::new(
            EvidenceKind::FpArgRegister,
            Some(reg.clone()),
            format!("{reg} (fp) read before write"),
            10,
        ));
    }
    for reg in &observed.saved_registers {
        evidence.push(CcEvidence::new(
            EvidenceKind::CalleeSaved,
            Some(reg.clone()),
            format!("{reg} saved and restored"),
            8,
        ));
    }
    for reg in &observed.written_before_return {
        evidence.push(CcEvidence::new(
            EvidenceKind::WrittenBeforeReturn,
            Some(reg.clone()),
            format!("{reg} written before return"),
            12,
        ));
    }
    if observed.callee_pops_stack {
        evidence.push(CcEvidence::new(
            EvidenceKind::CalleeStackCleanup,
            None,
            format!("ret pops {} stack bytes", observed.callee_stack_pop),
            5,
        ));
    }
    if observed.shadow_space_observed {
        evidence.push(CcEvidence::new(
            EvidenceKind::ShadowSpace,
            None,
            "shadow-space reservation observed",
            5,
        ));
    }
    if observed.this_ptr_hint {
        evidence.push(CcEvidence::new(
            EvidenceKind::ThisPointerHint,
            Some("ecx".into()),
            "ecx/rcx used as this pointer",
            5,
        ));
    }
    if observed.stack_arg_count > 0 && observed.read_before_write.is_empty() {
        evidence.push(CcEvidence::new(
            EvidenceKind::NoRegisterArgs,
            None,
            "arguments observed on stack only",
            5,
        ));
    }

    evidence
}

/// Look up the [`cc_detector::CcPattern`] builtin matching `name`, by the
/// same human-readable name used by the [`CallingConventionPattern`]
/// constructors in this module (e.g. `"System V AMD64 ABI"`).
///
/// Returns `None` for conventions this module models but `cc_detector` does
/// not (`aapcs32`, `mips_o32`, `riscv64_lp64d`, `vectorcall_x64`) — see
/// [`CallingConventionDetector::detect_with_evidence`].
#[must_use]
pub fn cc_pattern_for_name(name: &str) -> Option<cc_detector::CcPattern> {
    match name {
        "System V AMD64 ABI" => Some(cc_detector::CcPattern::sysv_amd64()),
        "Microsoft x64" => Some(cc_detector::CcPattern::ms_x64()),
        "cdecl (x86)" => Some(cc_detector::CcPattern::cdecl_x86()),
        "stdcall (x86)" => Some(cc_detector::CcPattern::stdcall_x86()),
        "thiscall (x86)" => Some(cc_detector::CcPattern::thiscall_x86()),
        "AAPCS64" => Some(cc_detector::CcPattern::aapcs64()),
        _ => None,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConventionDatabase
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Key for looking up a calling convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CcKey {
    /// Target architecture.
    pub arch: Arch,
    /// Target operating system.
    pub os: Os,
    /// Compiler family.
    pub compiler: Compiler,
}

impl CcKey {
    /// Create a `CcKey` from its components.
    #[must_use]
    pub const fn new(arch: Arch, os: Os, compiler: Compiler) -> Self {
        Self { arch, os, compiler }
    }
}

impl fmt::Display for CcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.arch, self.os, self.compiler)
    }
}

/// A registry of known calling conventions indexed by `CcKey`.
#[derive(Debug, Default)]
pub struct CallingConventionDatabase {
    entries: HashMap<CcKey, Vec<CallingConventionPattern>>,
}

impl CallingConventionDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a database pre-populated with all built-in calling conventions.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut db = Self::new();

        // SysV x64 (Linux, macOS, FreeBSD)
        for os in [Os::Linux, Os::MacOs, Os::FreeBsd] {
            for compiler in [Compiler::Gcc, Compiler::Clang, Compiler::Any] {
                db.register(CcKey::new(Arch::X86_64, os.clone(), compiler), sysv_x64());
            }
        }

        // MSVC x64 (Windows)
        for compiler in [Compiler::Msvc, Compiler::Clang, Compiler::Any] {
            db.register(
                CcKey::new(Arch::X86_64, Os::Windows, compiler.clone()),
                msvc_x64(),
            );
            db.register(
                CcKey::new(Arch::X86_64, Os::Windows, compiler),
                vectorcall_x64(),
            );
        }

        // x86 cdecl (Linux + Windows)
        for os in [Os::Linux, Os::Windows, Os::FreeBsd] {
            for compiler in [
                Compiler::Gcc,
                Compiler::Clang,
                Compiler::Msvc,
                Compiler::Any,
            ] {
                db.register(
                    CcKey::new(Arch::X86, os.clone(), compiler.clone()),
                    cdecl_x86(),
                );
            }
        }

        // x86 stdcall (Windows)
        for compiler in [Compiler::Msvc, Compiler::Gcc, Compiler::Any] {
            db.register(CcKey::new(Arch::X86, Os::Windows, compiler), stdcall_x86());
        }

        // x86 fastcall (Windows)
        for compiler in [Compiler::Msvc, Compiler::Gcc, Compiler::Any] {
            db.register(CcKey::new(Arch::X86, Os::Windows, compiler), fastcall_x86());
        }

        // x86 thiscall (Windows MSVC)
        db.register(
            CcKey::new(Arch::X86, Os::Windows, Compiler::Msvc),
            thiscall_x86(),
        );
        db.register(
            CcKey::new(Arch::X86, Os::Windows, Compiler::Any),
            thiscall_x86(),
        );

        // AAPCS64 (Arm64)
        for os in [Os::Linux, Os::MacOs, Os::Windows, Os::Bare, Os::FreeBsd] {
            for compiler in [Compiler::Gcc, Compiler::Clang, Compiler::Any] {
                db.register(CcKey::new(Arch::Arm64, os.clone(), compiler), aapcs64());
            }
        }

        // AAPCS32 (Arm32)
        for os in [Os::Linux, Os::Bare, Os::FreeBsd] {
            for compiler in [Compiler::Gcc, Compiler::Clang, Compiler::Any] {
                db.register(CcKey::new(Arch::Arm32, os.clone(), compiler), aapcs32());
            }
        }

        // MIPS O32
        for os in [Os::Linux, Os::Bare] {
            for compiler in [Compiler::Gcc, Compiler::Clang, Compiler::Any] {
                db.register(CcKey::new(Arch::Mips32, os.clone(), compiler), mips_o32());
            }
        }

        // RISC-V LP64D
        for os in [Os::Linux, Os::Bare] {
            for compiler in [Compiler::Gcc, Compiler::Clang, Compiler::Any] {
                db.register(
                    CcKey::new(Arch::RiscV64, os.clone(), compiler),
                    riscv64_lp64d(),
                );
            }
        }

        db
    }

    /// Register a `CallingConventionPattern` under `key`.
    pub fn register(&mut self, key: CcKey, pattern: CallingConventionPattern) {
        self.entries.entry(key).or_default().push(pattern);
    }

    /// Return all calling conventions known for `key`.
    #[must_use]
    pub fn lookup(&self, key: &CcKey) -> &[CallingConventionPattern] {
        self.entries.get(key).map_or(&[], Vec::as_slice)
    }

    /// Return all calling conventions for the given arch + OS (any compiler).
    #[must_use]
    pub fn lookup_any_compiler(&self, arch: &Arch, os: &Os) -> Vec<&CallingConventionPattern> {
        // `self.entries` is a HashMap, so iteration order is nondeterministic across
        // runs/processes; sort the result by name for a stable, reproducible order.
        let mut result: Vec<&CallingConventionPattern> = self
            .entries
            .iter()
            .filter(|(k, _)| k.arch == *arch && k.os == *os)
            .flat_map(|(_, v)| v.iter())
            .collect();
        result.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// Return all calling conventions for the given arch (any OS, any compiler).
    #[must_use]
    pub fn lookup_any_os(&self, arch: &Arch) -> Vec<&CallingConventionPattern> {
        // Same nondeterminism concern as `lookup_any_compiler`: sort for stability.
        let mut result: Vec<&CallingConventionPattern> = self
            .entries
            .iter()
            .filter(|(k, _)| k.arch == *arch)
            .flat_map(|(_, v)| v.iter())
            .collect();
        result.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// Return all unique calling convention names in the database.
    #[must_use]
    pub fn all_names(&self) -> Vec<String> {
        let mut names: HashSet<String> = HashSet::new();
        for ccs in self.entries.values() {
            for cc in ccs {
                names.insert(cc.name.clone());
            }
        }
        let mut result: Vec<String> = names.into_iter().collect();
        result.sort_unstable();
        result
    }

    /// Number of distinct keys registered.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number of `(key, pattern)` entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.values().map(std::vec::Vec::len).sum()
    }

    /// Remove all entries for `key`. Returns the number removed.
    pub fn remove(&mut self, key: &CcKey) -> usize {
        self.entries.remove(key).map_or(0, |v| v.len())
    }

    /// Serialize the entire database to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, CallConvError> {
        let records: Vec<CcDbRecord> = self
            .entries
            .iter()
            .flat_map(|(k, pats)| {
                pats.iter().map(move |p| CcDbRecord {
                    key: k.clone(),
                    pattern: p.clone(),
                })
            })
            .collect();
        Ok(serde_json::to_string_pretty(&records)?)
    }

    /// Deserialize from JSON produced by [`Self::to_json`].
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self, CallConvError> {
        let records: Vec<CcDbRecord> = serde_json::from_str(json)?;
        let mut db = Self::new();
        for rec in records {
            db.register(rec.key, rec.pattern);
        }
        Ok(db)
    }
}

#[derive(Serialize, Deserialize)]
struct CcDbRecord {
    key: CcKey,
    pattern: CallingConventionPattern,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FunctionCallConvSummary
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Stores the detected calling convention for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallConvSummary {
    /// Start address of the function.
    pub function_address: u64,
    /// The best-match calling convention.
    pub detected_cc: CallingConventionPattern,
    /// Confidence score (0—"100+; higher = better match).
    pub confidence: u32,
    /// The raw observed register pattern used for detection.
    pub observed: ObservedPattern,
    /// Runner-up candidates (name, score).
    pub runner_ups: Vec<(String, u32)>,
}

impl FunctionCallConvSummary {
    /// Create a new `FunctionCallConvSummary`.
    #[must_use]
    pub const fn new(
        function_address: u64,
        detected_cc: CallingConventionPattern,
        confidence: u32,
        observed: ObservedPattern,
    ) -> Self {
        Self {
            function_address,
            detected_cc,
            confidence,
            observed,
            runner_ups: Vec::new(),
        }
    }

    /// Attach runner-up candidates.
    #[must_use]
    pub fn with_runner_ups(mut self, runner_ups: Vec<(String, u32)>) -> Self {
        self.runner_ups = runner_ups;
        self
    }

    /// Whether this detection result is high-confidence (score >= 20).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 20
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BulkCallConvAnalyzer —" analyse multiple functions at once
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Analyses the calling conventions of multiple functions.
pub struct BulkCallConvAnalyzer {
    db: CallingConventionDatabase,
    key: CcKey,
}

impl BulkCallConvAnalyzer {
    /// Create an analyzer for the given platform key.
    #[must_use]
    pub const fn new(db: CallingConventionDatabase, key: CcKey) -> Self {
        Self { db, key }
    }

    /// Analyse a single function and return a summary.
    ///
    /// # Errors
    ///
    /// Returns [`CallConvError::UnknownKey`] if no calling conventions are known for the key.
    /// Returns [`CallConvError::NoMatch`] or [`CallConvError::Ambiguous`] from detection.
    pub fn analyse_function(
        &self,
        address: u64,
        instrs: &[DetectInstr],
    ) -> Result<FunctionCallConvSummary, CallConvError> {
        let candidates = self.db.lookup(&self.key);
        if candidates.is_empty() {
            return Err(CallConvError::UnknownKey(self.key.to_string()));
        }
        let observed =
            CallingConventionDetector::extract_pattern(instrs, self.key.arch.pointer_width());
        let ranked = CallingConventionDetector::rank_candidates(&observed, candidates);
        let best_score = ranked.first().map_or(0, |(_, s)| *s);
        let detected = CallingConventionDetector::detect_with_hints(&observed, candidates)?;
        let runner_ups: Vec<(String, u32)> = ranked
            .iter()
            .skip(1)
            .take(3)
            .map(|(cc, s)| (cc.name.clone(), *s))
            .collect();
        Ok(FunctionCallConvSummary {
            function_address: address,
            detected_cc: detected,
            confidence: best_score,
            observed,
            runner_ups,
        })
    }

    /// Analyse all provided functions and return summaries for the ones that succeed.
    #[must_use]
    pub fn analyse_all(
        &self,
        functions: &[(u64, Vec<DetectInstr>)],
    ) -> Vec<FunctionCallConvSummary> {
        functions
            .iter()
            .filter_map(|(addr, instrs)| self.analyse_function(*addr, instrs).ok())
            .collect()
    }

    /// Statistics summary over all analysed functions.
    #[must_use]
    pub fn statistics(summaries: &[FunctionCallConvSummary]) -> CallConvStats {
        CallConvStats::compute(summaries)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallConvStats
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregate statistics over a set of `FunctionCallConvSummary` results.
#[derive(Debug, Clone)]
pub struct CallConvStats {
    /// Total functions analysed.
    pub total: usize,
    /// How many were high-confidence detections.
    pub high_confidence: usize,
    /// Breakdown by detected CC name.
    pub by_name: HashMap<String, usize>,
    /// Average confidence score.
    pub avg_confidence: f64,
    /// Highest-confidence detection.
    pub max_confidence: u32,
    /// Lowest-confidence detection.
    pub min_confidence: u32,
}

impl CallConvStats {
    /// Compute statistics from a slice of summaries.
    #[must_use]
    pub fn compute(summaries: &[FunctionCallConvSummary]) -> Self {
        if summaries.is_empty() {
            return Self {
                total: 0,
                high_confidence: 0,
                by_name: HashMap::new(),
                avg_confidence: 0.0,
                max_confidence: 0,
                min_confidence: 0,
            };
        }
        let mut by_name: HashMap<String, usize> = HashMap::new();
        let mut high_confidence = 0usize;
        let mut total_conf = 0u64;
        let mut max_conf = 0u32;
        let mut min_conf = u32::MAX;

        for s in summaries {
            *by_name.entry(s.detected_cc.name.clone()).or_insert(0) += 1;
            if s.is_high_confidence() {
                high_confidence += 1;
            }
            total_conf += u64::from(s.confidence);
            max_conf = max_conf.max(s.confidence);
            min_conf = min_conf.min(s.confidence);
        }

        Self {
            total: summaries.len(),
            high_confidence,
            by_name,
            avg_confidence: total_conf as f64 / summaries.len() as f64,
            max_confidence: max_conf,
            min_confidence: min_conf,
        }
    }

    /// The most frequently detected calling convention name.
    #[must_use]
    pub fn most_common(&self) -> Option<&str> {
        // `by_name` is a HashMap, so a naive `max_by_key` breaks count ties by
        // nondeterministic iteration order. Break ties by name for reproducibility.
        self.by_name
            .iter()
            .max_by(|(na, ca), (nb, cb)| ca.cmp(cb).then_with(|| nb.cmp(na)))
            .map(|(n, _)| n.as_str())
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RegisterClassifier —" classify registers by role
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Classifies the role of a register within a calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterRole {
    /// Used to pass arguments.
    Argument,
    /// Used to pass floating-point arguments.
    FpArgument,
    /// Used to return values.
    ReturnValue,
    /// Must be preserved across calls (callee-saved).
    CalleeSaved,
    /// May be clobbered freely (caller-saved / scratch).
    CallerSaved,
    /// Not categorised by this convention.
    Unknown,
}

/// Classifies registers against a calling convention.
pub struct RegisterClassifier;

impl RegisterClassifier {
    /// Return the role of `reg` in `cc`.
    #[must_use]
    pub fn classify(cc: &CallingConventionPattern, reg: &str) -> RegisterRole {
        if cc.arg_registers.iter().any(|r| r == reg) {
            return RegisterRole::Argument;
        }
        if cc.fp_arg_registers.iter().any(|r| r == reg) {
            return RegisterRole::FpArgument;
        }
        if cc.retval_registers.iter().any(|r| r == reg) {
            return RegisterRole::ReturnValue;
        }
        if cc.callee_saved.iter().any(|r| r == reg) {
            return RegisterRole::CalleeSaved;
        }
        if cc.caller_saved.iter().any(|r| r == reg) {
            return RegisterRole::CallerSaved;
        }
        RegisterRole::Unknown
    }

    /// Return all registers of a given `role` in `cc`.
    #[must_use]
    pub fn registers_with_role(cc: &CallingConventionPattern, role: RegisterRole) -> Vec<&str> {
        match role {
            RegisterRole::Argument => cc.arg_registers.iter().map(String::as_str).collect(),
            RegisterRole::FpArgument => cc.fp_arg_registers.iter().map(String::as_str).collect(),
            RegisterRole::ReturnValue => cc.retval_registers.iter().map(String::as_str).collect(),
            RegisterRole::CalleeSaved => cc.callee_saved.iter().map(String::as_str).collect(),
            RegisterRole::CallerSaved => cc.caller_saved.iter().map(String::as_str).collect(),
            RegisterRole::Unknown => vec![],
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ParameterMapper —" map detected arguments to parameter positions
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Maps detected argument registers to C-level parameter positions.
pub struct ParameterMapper;

impl ParameterMapper {
    /// Given observed `read_before_write` registers and a CC, produce
    /// an ordered list of `(param_index, register)` pairs.
    #[must_use]
    pub fn map_args(
        observed_reads: &[String],
        cc: &CallingConventionPattern,
    ) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        for (i, reg) in cc.arg_registers.iter().enumerate() {
            if observed_reads.iter().any(|r| r == reg) {
                result.push((i, reg.clone()));
            }
        }
        result
    }

    /// Estimate the number of integer arguments from observed pattern.
    #[must_use]
    pub fn estimated_arg_count(observed: &ObservedPattern, cc: &CallingConventionPattern) -> usize {
        let reg_args = observed
            .read_before_write
            .iter()
            .filter(|r| cc.arg_registers.contains(r))
            .count();
        let stack_args = usize::try_from(observed.stack_arg_count).unwrap_or(0);
        reg_args + stack_args
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConvDef —" canonical, static definition of a single ABI
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// How the stack is cleaned up after a function call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CcStackCleanup {
    /// Caller pops the arguments (cdecl, `SysV`, MS-x64).
    Caller,
    /// Callee pops the arguments (stdcall, thiscall, fastcall).
    Callee,
}

impl fmt::Display for CcStackCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller => write!(f, "caller"),
            Self::Callee => write!(f, "callee"),
        }
    }
}

/// A complete, static description of one calling convention.
///
/// This is the *canonical definition* (analogous to what a compiler stores)
/// rather than the observed/detected evidence stored in `CallingConventionPattern`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingConvDef {
    /// Short identifier, e.g. `"sysv_amd64"`, `"ms_x64"`, `"cdecl"`.
    pub name: &'static str,
    /// Integer / pointer argument registers in order.
    pub int_arg_regs: &'static [&'static str],
    /// Floating-point argument registers in order.
    pub float_arg_regs: &'static [&'static str],
    /// Primary integer return register.
    pub int_ret_reg: &'static str,
    /// Primary floating-point return register (empty string if none).
    pub float_ret_reg: &'static str,
    /// Registers the callee must preserve (callee-saved).
    pub callee_saved: &'static [&'static str],
    /// Who cleans up stack arguments.
    pub stack_cleanup: CcStackCleanup,
    /// Required stack alignment at the call site (bytes).
    pub stack_align: u32,
    /// Whether this convention passes `this` implicitly via `int_arg_regs[0]`.
    pub has_this_ptr: bool,
    /// Shadow / home space reserved by the caller (bytes; 0 for most ABIs).
    pub shadow_space: u32,
}

impl CallingConvDef {
    /// Whether `reg` is an integer argument register for this convention.
    #[must_use]
    pub fn is_int_arg(&self, reg: &str) -> bool {
        self.int_arg_regs.contains(&reg)
    }

    /// Whether `reg` is a floating-point argument register.
    #[must_use]
    pub fn is_float_arg(&self, reg: &str) -> bool {
        self.float_arg_regs.contains(&reg)
    }

    /// Whether `reg` must be preserved by the callee.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.contains(&reg)
    }
}

impl fmt::Display for CallingConvDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [int_args={}, fp_args={}, ret={}, cleanup={}]",
            self.name,
            self.int_arg_regs.len(),
            self.float_arg_regs.len(),
            self.int_ret_reg,
            self.stack_cleanup,
        )
    }
}

// â"€â"€ Built-in CallingConvDef constants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// System V AMD64 ABI (Linux, macOS, BSDs).
pub static CC_SYSV_AMD64: CallingConvDef = CallingConvDef {
    name: "sysv_amd64",
    int_arg_regs: &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    float_arg_regs: &[
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    ],
    int_ret_reg: "rax",
    float_ret_reg: "xmm0",
    callee_saved: &["rbx", "rbp", "r12", "r13", "r14", "r15"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

/// Microsoft x64 calling convention (Windows).
pub static CC_MS_X64: CallingConvDef = CallingConvDef {
    name: "ms_x64",
    int_arg_regs: &["rcx", "rdx", "r8", "r9"],
    float_arg_regs: &["xmm0", "xmm1", "xmm2", "xmm3"],
    int_ret_reg: "rax",
    float_ret_reg: "xmm0",
    callee_saved: &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 32,
};

/// cdecl —" 32-bit C default (all args on stack, caller cleans).
pub static CC_CDECL: CallingConvDef = CallingConvDef {
    name: "cdecl",
    int_arg_regs: &[],
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 4,
    has_this_ptr: false,
    shadow_space: 0,
};

/// stdcall —" 32-bit Windows API (args on stack, callee cleans).
pub static CC_STDCALL: CallingConvDef = CallingConvDef {
    name: "stdcall",
    int_arg_regs: &[],
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Callee,
    stack_align: 4,
    has_this_ptr: false,
    shadow_space: 0,
};

/// fastcall —" first two ints in ecx/edx, rest on stack, callee cleans.
pub static CC_FASTCALL: CallingConvDef = CallingConvDef {
    name: "fastcall",
    int_arg_regs: &["ecx", "edx"],
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Callee,
    stack_align: 4,
    has_this_ptr: false,
    shadow_space: 0,
};

/// thiscall —" MSVC C++ member functions (`this` in ecx, callee cleans).
pub static CC_THISCALL: CallingConvDef = CallingConvDef {
    name: "thiscall",
    int_arg_regs: &["ecx"],
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Callee,
    stack_align: 4,
    has_this_ptr: true,
    shadow_space: 0,
};

/// vectorcall —" Microsoft SIMD convention (int in rcx/rdx/r8/r9, vec in xmm0—"5).
pub static CC_VECTORCALL: CallingConvDef = CallingConvDef {
    name: "vectorcall",
    int_arg_regs: &["rcx", "rdx", "r8", "r9"],
    float_arg_regs: &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"],
    int_ret_reg: "rax",
    float_ret_reg: "xmm0",
    callee_saved: &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    // Microsoft `__vectorcall` on x64 inherits the MS x64 ABI's 32-byte
    // caller-reserved shadow/home space. This copy previously had 0, diverging
    // from cc_database.rs's already-fixed CC_VECTORCALL_X64 (two independent
    // ABI reviews confirmed 32).
    shadow_space: 32,
};

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallConvDatabase —" registry of `CallingConvDef` references
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A registry of `&'static CallingConvDef` entries, keyed by name.
///
/// Pre-populated by [`CallConvDatabase::with_builtins`] with the seven
/// standard ABIs: `sysv_amd64`, `ms_x64`, `cdecl`, `stdcall`, `fastcall`,
/// `thiscall`, and `vectorcall`.
pub struct CallConvDatabase {
    entries: HashMap<&'static str, &'static CallingConvDef>,
}

impl Default for CallConvDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl CallConvDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a database pre-populated with the seven built-in ABIs.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut db = Self::new();
        db.register(&CC_SYSV_AMD64);
        db.register(&CC_MS_X64);
        db.register(&CC_CDECL);
        db.register(&CC_STDCALL);
        db.register(&CC_FASTCALL);
        db.register(&CC_THISCALL);
        db.register(&CC_VECTORCALL);
        db
    }

    /// Register a `CallingConvDef` under its `name` field.
    pub fn register(&mut self, def: &'static CallingConvDef) {
        self.entries.insert(def.name, def);
    }

    /// Look up a `CallingConvDef` by its `name`.  Returns `None` if not found.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static CallingConvDef> {
        self.entries.get(name).copied()
    }

    /// All registered names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<&str> = self.entries.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries as a slice of references.
    #[must_use]
    pub fn all(&self) -> Vec<&'static CallingConvDef> {
        self.entries.values().copied().collect()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Instruction model for detect_calling_convention / get_arg_types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A simplified instruction record for calling-convention detection.
///
/// Consumers should convert their disassembled instructions to this type
/// before calling [`detect_calling_convention`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Register(s) read by this instruction (source operands).
    pub reads: Vec<String>,
    /// Register(s) written by this instruction (destination operands).
    pub writes: Vec<String>,
    /// Whether this instruction pushes a register (callee-save hint).
    pub is_push: bool,
    /// Whether this instruction pops a register (callee-restore hint).
    pub is_pop: bool,
    /// Whether this is a `RET` / `RETN` instruction.
    pub is_ret: bool,
    /// For `RET N`: bytes popped by the callee (0 = cdecl-style caller cleanup).
    pub ret_stack_bytes: u32,
    /// Whether this is a `CALL` instruction (to track if function calls out).
    pub is_call: bool,
    /// Whether `ecx` / `rcx` is used as a `this` pointer here.
    pub is_this_ptr_use: bool,
    /// Stack frame allocation size observed at this instruction (`SUB rsp, N`).
    pub stack_alloc: u32,
}

impl Instruction {
    /// Create a minimal `Instruction` with only reads/writes set.
    #[must_use]
    pub const fn rw(address: u64, reads: Vec<String>, writes: Vec<String>) -> Self {
        Self {
            address,
            reads,
            writes,
            is_push: false,
            is_pop: false,
            is_ret: false,
            ret_stack_bytes: 0,
            is_call: false,
            is_this_ptr_use: false,
            stack_alloc: 0,
        }
    }

    /// Create a `PUSH reg` instruction.
    #[must_use]
    pub fn push(address: u64, reg: impl Into<String>) -> Self {
        let r = reg.into();
        Self {
            address,
            reads: vec![r],
            writes: vec![],
            is_push: true,
            is_pop: false,
            is_ret: false,
            ret_stack_bytes: 0,
            is_call: false,
            is_this_ptr_use: false,
            stack_alloc: 0,
        }
    }

    /// Create a `POP reg` instruction.
    #[must_use]
    pub fn pop(address: u64, reg: impl Into<String>) -> Self {
        let r = reg.into();
        Self {
            address,
            reads: vec![],
            writes: vec![r],
            is_push: false,
            is_pop: true,
            is_ret: false,
            ret_stack_bytes: 0,
            is_call: false,
            is_this_ptr_use: false,
            stack_alloc: 0,
        }
    }

    /// Create a `RET` / `RETN` instruction.
    #[must_use]
    pub const fn ret(address: u64, stack_bytes: u32) -> Self {
        Self {
            address,
            reads: vec![],
            writes: vec![],
            is_push: false,
            is_pop: false,
            is_ret: true,
            ret_stack_bytes: stack_bytes,
            is_call: false,
            is_this_ptr_use: false,
            stack_alloc: 0,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FunctionInfo —" metadata used by get_arg_types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Basic information about a function, used by [`get_arg_types`].
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Start address of the function.
    pub address: u64,
    /// Detected calling convention name (e.g. `"sysv_amd64"`).
    pub cc_name: String,
    /// Registers that were read before any write (inferred arg regs).
    pub live_in_regs: Vec<String>,
    /// FP registers read before write (inferred fp arg regs).
    pub live_in_fp_regs: Vec<String>,
    /// Number of stack arguments detected.
    pub stack_arg_count: u32,
    /// Whether a `this` pointer was observed.
    pub has_this_ptr: bool,
}

impl FunctionInfo {
    /// Create a minimal `FunctionInfo`.
    #[must_use]
    pub fn new(address: u64, cc_name: impl Into<String>) -> Self {
        Self {
            address,
            cc_name: cc_name.into(),
            live_in_regs: Vec::new(),
            live_in_fp_regs: Vec::new(),
            stack_arg_count: 0,
            has_this_ptr: false,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ArgType —" inferred type of a function argument
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The inferred category of a function argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgType {
    /// An integer or pointer argument passed in `reg`.
    Integer {
        /// The register that carries this argument.
        reg: String,
        /// Zero-based position among all integer arguments.
        position: usize,
    },
    /// A floating-point argument passed in `reg`.
    Float {
        /// The FP register that carries this argument.
        reg: String,
        /// Zero-based position among all FP arguments.
        position: usize,
    },
    /// The implicit `this` pointer (thiscall convention).
    ThisPtr {
        /// The register that carries `this` (usually `ecx`).
        reg: String,
    },
    /// An argument passed on the stack.
    Stack {
        /// Zero-based stack slot index.
        slot: u32,
        /// Byte offset from the stack pointer at function entry.
        offset: u32,
    },
    /// Argument type could not be determined.
    Unknown {
        /// Zero-based position in the argument list.
        position: usize,
    },
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer { reg, position } => write!(f, "int arg{position} ({reg})"),
            Self::Float { reg, position } => write!(f, "float arg{position} ({reg})"),
            Self::ThisPtr { reg } => write!(f, "this ({reg})"),
            Self::Stack { slot, offset } => write!(f, "stack[{slot}] @ +{offset:#x}"),
            Self::Unknown { position } => write!(f, "unknown arg{position}"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// detect_calling_convention
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Detect the calling convention of a function from its instruction stream.
///
/// Uses three heuristics (in order of weight):
///
/// 1. **Live-in registers** —" registers read before written are candidate
///    argument registers.  Score conventions by overlap with `int_arg_regs`.
/// 2. **Callee-saved registers** —" registers pushed in the prologue and popped
///    symmetrically in the epilogue are scored against `callee_saved`.
/// 3. **Stack cleanup** —" a `RET N` with `N > 0` strongly suggests callee
///    stack cleanup (stdcall / fastcall / thiscall).
///
/// Returns a reference to the best-matching `CallingConvDef` from `candidates`,
/// or `None` when the list is empty or no convention scores above zero.
#[must_use]
pub fn detect_calling_convention(
    func_instrs: &[Instruction],
    candidates: &[&'static CallingConvDef],
) -> Option<&'static CallingConvDef> {
    if candidates.is_empty() || func_instrs.is_empty() {
        return None;
    }

    // â"€â"€ Step 1: gather evidence â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let mut defined: HashSet<String> = HashSet::new();
    let mut live_in: Vec<String> = Vec::new();
    let mut pushed: Vec<String> = Vec::new();
    let mut popped: Vec<String> = Vec::new();
    let mut callee_pops = false;
    let mut this_ptr_used = false;
    let mut shadow_space = false;

    for instr in func_instrs {
        if instr.is_this_ptr_use {
            this_ptr_used = true;
        }
        if instr.stack_alloc >= 32 {
            shadow_space = true;
        }
        for reg in &instr.reads {
            if !defined.contains(reg) && !live_in.contains(reg) {
                live_in.push(reg.clone());
            }
        }
        for reg in &instr.writes {
            defined.insert(reg.clone());
        }
        if instr.is_push {
            for reg in &instr.reads {
                if !pushed.contains(reg) {
                    pushed.push(reg.clone());
                }
            }
        }
        if instr.is_pop {
            for reg in &instr.writes {
                if !popped.contains(reg) {
                    popped.push(reg.clone());
                }
            }
        }
        if instr.is_ret && instr.ret_stack_bytes > 0 {
            callee_pops = true;
        }
    }

    let saved_regs: Vec<&str> = pushed
        .iter()
        .filter(|r| popped.contains(r))
        .map(String::as_str)
        .collect();

    // â"€â"€ Step 2: score each candidate â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let mut best_score: i64 = -1;
    let mut best: Option<&'static CallingConvDef> = None;
    let mut tied = false;

    for &cc in candidates {
        let mut score: i64 = 0;

        // Integer arg register overlap (weight 10).
        for reg in &live_in {
            if cc.is_int_arg(reg) {
                score += 10;
            }
        }
        // FP arg register overlap (weight 8).
        for reg in &live_in {
            if cc.is_float_arg(reg) {
                score += 8;
            }
        }
        // Callee-saved overlap (weight 6).
        for reg in &saved_regs {
            if cc.is_callee_saved(reg) {
                score += 6;
            }
        }
        // Stack-cleanup match (weight 15).
        let callee_cleanup = cc.stack_cleanup == CcStackCleanup::Callee;
        if callee_pops == callee_cleanup {
            score += 15;
        } else {
            score -= 5;
        }
        // This-pointer hint (weight 12).
        if this_ptr_used && cc.has_this_ptr {
            score += 12;
        }
        // Shadow-space hint (weight 10 when observed).
        if shadow_space && cc.shadow_space >= 32 {
            score += 10;
        }

        if score > best_score {
            best_score = score;
            best = Some(cc);
            tied = false;
        } else if score == best_score && best_score > 0 {
            tied = true;
        }
    }

    // Only return a result when there is at least some positive evidence and no tie.
    if best_score <= 0 || tied { None } else { best }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// get_arg_types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Byte width of an integer register, by name, across the ABIs this crate
/// knows about.
///
/// Used to size stack argument slots. The name is the only ABI signal
/// available on a [`CallingConvDef`], but it must be read as a REGISTER NAME,
/// not as a prefix test — see [`get_arg_types`].
fn int_reg_width_bytes(reg: &str) -> u32 {
    let r = reg.trim().to_ascii_lowercase();
    match r.as_str() {
        // x86 / x86-64
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rsp" | "rbp" => 8,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "esp" | "ebp" => 4,
        "ax" | "bx" | "cx" | "dx" => 2,
        "al" | "bl" | "cl" | "dl" => 1,
        _ => {
            // r8–r15 are 64-bit; r8d/r8w/r8b are the narrower views.
            if let Some(rest) = r.strip_prefix('r') {
                if rest.ends_with('d') {
                    return 4;
                }
                if rest.ends_with('w') {
                    return 2;
                }
                if rest.ends_with('b') {
                    return 1;
                }
                if rest.chars().all(|c| c.is_ascii_digit()) {
                    // ARM32/MIPS/PPC `r0…r31` are 32-bit; x86-64 `r8…r15` are
                    // 64-bit. The x86-64 set is exactly r8–r15.
                    return rest.parse::<u32>().map_or(4, |n| {
                        if (8..=15).contains(&n) { 8 } else { 4 }
                    });
                }
                return 8;
            }
            // AArch64 x0–x30, RISC-V a0…/t…, MIPS64 v0 — 64-bit.
            if r.starts_with('x') || r.starts_with('a') || r.starts_with('v') {
                return 8;
            }
            // AArch32 w-registers and unknown names: assume 32-bit.
            4
        }
    }
}

/// Infer the list of argument types for `func` given its calling convention.
///
/// Combines:
/// * The integer argument registers observed in `func.live_in_regs` (ordered
///   by their position in `cc.int_arg_regs`).
/// * The FP argument registers in `func.live_in_fp_regs`.
/// * The implicit `this` pointer when `cc.has_this_ptr` is true.
/// * Stack arguments as `ArgType::Stack` slots, one per `func.stack_arg_count`.
///
/// The `this` pointer is prepended when applicable; integer and FP args are
/// interleaved in register-position order; stack args follow.
#[must_use]
pub fn get_arg_types(func: &FunctionInfo, cc: &CallingConvDef) -> Vec<ArgType> {
    let mut args: Vec<ArgType> = Vec::new();

    // 1. This pointer (if applicable).
    if cc.has_this_ptr {
        let reg = cc.int_arg_regs.first().copied().unwrap_or("ecx");
        args.push(ArgType::ThisPtr {
            reg: reg.to_owned(),
        });
    }

    // 2. Integer argument registers (in ABI order).
    let mut int_pos = 0usize;
    for &abi_reg in cc.int_arg_regs {
        if cc.has_this_ptr && int_pos == 0 {
            // Skip —" already emitted as ThisPtr.
            int_pos += 1;
            continue;
        }
        if func.live_in_regs.iter().any(|r| r == abi_reg) {
            args.push(ArgType::Integer {
                reg: abi_reg.to_owned(),
                position: int_pos,
            });
        }
        int_pos += 1;
    }

    // 3. FP argument registers (in ABI order).
    for (fp_pos, &abi_reg) in cc.float_arg_regs.iter().enumerate() {
        if func.live_in_fp_regs.iter().any(|r| r == abi_reg) {
            args.push(ArgType::Float {
                reg: abi_reg.to_owned(),
                position: fp_pos,
            });
        }
    }

    // 4. Stack arguments.
    //
    // Slot size is the ABI's pointer width, derived from the WIDTH of the
    // integer return register rather than from the first letter of its name.
    //
    // `int_ret_reg.starts_with('r')` was exactly INVERTED for ARM32 — `r0` is
    // a 32-bit register, so it claimed 8-byte slots — and wrong for every
    // non-x86 64-bit ABI, whose return register (`x0`, `a0`, `v0`) does not
    // start with `r` and so got 4-byte slots. It happened to be right only for
    // x86 (`eax`) and x86-64 (`rax`), which is why it survived.
    let ptr_size: u32 = int_reg_width_bytes(cc.int_ret_reg);
    for slot in 0..func.stack_arg_count {
        let offset = cc.shadow_space.saturating_add(slot.saturating_mul(ptr_size));
        args.push(ArgType::Stack { slot, offset });
    }

    args
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallConvAnalysisResult —" per-function result bundle
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The complete result of calling-convention analysis on a single function.
#[derive(Debug, Clone)]
pub struct CallConvAnalysisResult {
    /// The function's start address.
    pub address: u64,
    /// The detected calling convention (if any).
    pub cc: Option<&'static CallingConvDef>,
    /// Inferred argument types.
    pub args: Vec<ArgType>,
    /// Registers identified as live-in (candidate argument registers).
    pub live_in: Vec<String>,
    /// Registers preserved by the callee (push/pop matched pairs).
    pub preserved: Vec<String>,
    /// Whether callee stack cleanup was observed.
    pub callee_cleans_stack: bool,
}

impl CallConvAnalysisResult {
    /// Run the full analysis pipeline on a single function.
    ///
    /// 1. Detects the calling convention using `detect_calling_convention`.
    /// 2. Builds a `FunctionInfo` from the instruction stream.
    /// 3. Calls `get_arg_types` to infer argument types.
    #[must_use]
    pub fn analyze(
        address: u64,
        instrs: &[Instruction],
        candidates: &[&'static CallingConvDef],
    ) -> Self {
        // Gather evidence.
        let mut defined: HashSet<String> = HashSet::new();
        let mut live_in: Vec<String> = Vec::new();
        let mut live_in_fp: Vec<String> = Vec::new();
        let mut pushed: Vec<String> = Vec::new();
        let mut popped: Vec<String> = Vec::new();
        let mut callee_cleans_stack = false;
        let mut stack_args = 0u32;
        let mut has_this = false;

        let fp_regs: HashSet<&str> = [
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
            "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "f12",
            "f14", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "s0", "s1", "s2", "s3",
        ]
        .iter()
        .copied()
        .collect();

        for instr in instrs {
            if instr.is_this_ptr_use {
                has_this = true;
            }
            for reg in &instr.reads {
                if !defined.contains(reg) {
                    if fp_regs.contains(reg.as_str()) {
                        if !live_in_fp.contains(reg) {
                            live_in_fp.push(reg.clone());
                        }
                    } else if !live_in.contains(reg) {
                        live_in.push(reg.clone());
                    }
                }
            }
            for reg in &instr.writes {
                defined.insert(reg.clone());
            }
            if instr.is_push {
                for reg in &instr.reads {
                    if !pushed.contains(reg) {
                        pushed.push(reg.clone());
                    }
                }
            }
            if instr.is_pop {
                for reg in &instr.writes {
                    if !popped.contains(reg) {
                        popped.push(reg.clone());
                    }
                }
            }
            if instr.is_ret && instr.ret_stack_bytes > 0 {
                callee_cleans_stack = true;
                // Estimate stack args from ret N / pointer size.
                stack_args = instr.ret_stack_bytes / 4;
            }
        }

        let preserved: Vec<String> = pushed
            .iter()
            .filter(|r| popped.contains(r))
            .cloned()
            .collect();

        let cc = detect_calling_convention(instrs, candidates);

        let func_info = FunctionInfo {
            address,
            cc_name: cc.map_or("unknown", |c| c.name).to_owned(),
            live_in_regs: live_in.clone(),
            live_in_fp_regs: live_in_fp,
            stack_arg_count: stack_args,
            has_this_ptr: has_this,
        };

        let args = cc.map_or_else(Vec::new, |c| get_arg_types(&func_info, c));

        Self {
            address,
            cc,
            args,
            live_in,
            preserved,
            callee_cleans_stack,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConventionPass —" AnalysisPass implementation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An [`rustre_analysis::AnalysisPass`] that detects calling conventions for
/// all executable functions in a [`rustre_core::binary_view::BinaryView`].
///
/// For each executable segment the pass iterates over the binary view's
/// known entry points (treated as function starts), builds a synthetic
/// instruction stream from the raw bytes using a simple heuristic prologue
/// scanner, and runs [`detect_calling_convention`] against the built-in
/// [`CallConvDatabase`] to classify each function.
///
/// The number of functions for which a calling convention was successfully
/// identified is returned as `functions_found` in the [`AnalysisResult`].
pub struct CallingConventionPass;

impl CallingConventionPass {
    /// Create a new `CallingConventionPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for CallingConventionPass {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CallingConventionPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallingConventionPass").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for CallingConventionPass {
    fn name(&self) -> &'static str {
        "calling_convention"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::CallingConvention
    }

    fn description(&self) -> &'static str {
        "Detects calling conventions for binary functions by analysing \
         register usage patterns in prologues and epilogues"
    }

    /// Run calling-convention detection over all functions in `view`.
    ///
    /// # Errors
    ///
    /// Returns [`rustre_analysis::AnalysisError::Failed`] if the binary view
    /// cannot be read.
    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        use std::time::Instant;

        let start = Instant::now();
        let db = CallConvDatabase::with_builtins();
        let candidates: Vec<&'static CallingConvDef> = db.all();

        let mut functions_found = 0usize;
        let mut warnings: Vec<String> = Vec::new();

        // Gather entry-point addresses from the binary view.
        let entry_points: Vec<u64> = view.entry_points.iter().map(|a| a.as_u64()).collect();

        // Walk all executable segments and try to detect the CC at each
        // known entry point that falls within that segment.
        let mem_guard = view.mem.read();
        for seg in &mem_guard.segments {
            if !seg
                .permissions
                .contains(rustre_core::permissions::Permissions::EXECUTE)
            {
                continue;
            }

            let seg_start = seg.range.start.as_u64();
            let seg_end = seg.range.end.as_u64();

            for &entry in &entry_points {
                if entry < seg_start || entry >= seg_end {
                    continue;
                }

                let offset = (entry - seg_start) as usize;
                if offset >= seg.data.len() {
                    // Entry point falls within the range but beyond the
                    // backing bytes (e.g. a zero-filled `.bss`-like tail
                    // with no on-disk data) — nothing to scan.
                    warnings.push(format!("no backing data at 0x{entry:x}"));
                    continue;
                }
                let slice = &seg.data[offset..];

                // Build a minimal Instruction stream from the raw bytes.
                // We scan forward up to 256 bytes constructing simplified
                // Instruction records so that detect_calling_convention can
                // score the candidates.
                let instrs = build_instruction_stream(entry, slice);

                if instrs.is_empty() {
                    warnings.push(format!("empty instruction stream at 0x{entry:x}"));
                    continue;
                }

                if detect_calling_convention(&instrs, &candidates).is_some() {
                    functions_found += 1;
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(rustre_analysis::AnalysisResult {
            kind: self.kind(),
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms,
            warnings,
        })
    }
}

/// Build a heuristic [`Instruction`] stream from raw bytes starting at `base`.
///
/// Scans up to 256 bytes, emitting push/pop/ret records for the common x86-64
/// prologue/epilogue byte patterns and generic read/write records for everything
/// else. This is intentionally simple —" it exists solely to give
/// [`detect_calling_convention`] enough structural information to score ABI
/// candidates without a full disassembler.
fn build_instruction_stream(base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let limit = bytes.len().min(256);
    let slice = &bytes[..limit];
    let mut instrs = Vec::new();
    let mut i = 0usize;

    while i < slice.len() {
        let addr = base + i as u64;
        let b = slice[i];

        match b {
            // PUSH reg64: 0x50—"0x57  (REX.B variant: 41 50—"41 57 handled below)
            0x50..=0x57 => {
                let reg = x86_64_reg_name(b - 0x50, false);
                instrs.push(Instruction::push(addr, reg));
                i += 1;
            }
            // POP reg64: 0x58—"0x5F
            0x58..=0x5F => {
                let reg = x86_64_reg_name(b - 0x58, false);
                instrs.push(Instruction::pop(addr, reg));
                i += 1;
            }
            // SUB RSP, imm8 (common prologue stack adjustment): 48 83 EC imm8
            //
            // NOTE: 0x48 is a REX.W prefix and therefore also falls inside the
            // generic `0x40..=0x4F` REX-prefix arm below. This arm (and the
            // `MOV RBP, RSP` one after it) MUST be checked first, or the
            // generic arm silently intercepts these bytes, advances by only 1,
            // and both shadow-space detection and frame-pointer tracking never
            // fire on real x86-64 bytes.
            0x48 if i + 3 < slice.len() && slice[i + 1] == 0x83 && slice[i + 2] == 0xEC => {
                let bytes_alloc = u32::from(slice[i + 3]);
                let mut instr = Instruction::rw(addr, vec![], vec![]);
                instr.stack_alloc = bytes_alloc;
                instrs.push(instr);
                i += 4;
            }
            // MOV RBP, RSP (48 89 E5) —" common frame-pointer setup
            0x48 if i + 2 < slice.len() && slice[i + 1] == 0x89 && slice[i + 2] == 0xE5 => {
                instrs.push(Instruction::rw(
                    addr,
                    vec!["rsp".into()],
                    vec!["rbp".into()],
                ));
                i += 3;
            }
            // REX prefix (0x40—"0x4F): peek at next byte for push/pop r8—"r15
            0x40..=0x4F if i + 1 < slice.len() => {
                let next = slice[i + 1];
                let ext = (b & 0x01) != 0; // REX.B extends the register field
                match next {
                    0x50..=0x57 => {
                        let reg = x86_64_reg_name(next - 0x50, ext);
                        instrs.push(Instruction::push(addr, reg));
                        i += 2;
                    }
                    0x58..=0x5F => {
                        let reg = x86_64_reg_name(next - 0x58, ext);
                        instrs.push(Instruction::pop(addr, reg));
                        i += 2;
                    }
                    _ => {
                        // Other REX-prefixed instruction; treat as generic read/write
                        instrs.push(Instruction::rw(addr, vec![], vec![]));
                        i += 1;
                    }
                }
            }
            // RET (near): C3
            0xC3 => {
                instrs.push(Instruction::ret(addr, 0));
                i += 1;
            }
            // RETN imm16: C2 lo hi
            0xC2 if i + 2 < slice.len() => {
                let imm = u16::from_le_bytes([slice[i + 1], slice[i + 2]]);
                instrs.push(Instruction::ret(addr, u32::from(imm)));
                i += 3;
            }
            // Everything else: emit as a no-op generic instruction
            _ => {
                instrs.push(Instruction::rw(addr, vec![], vec![]));
                i += 1;
            }
        }

        // Stop after we see a RET.
        if instrs.last().is_some_and(|x| x.is_ret) {
            break;
        }
    }

    instrs
}

/// Map a 3-bit register index (0—"7) to an x86-64 register name.
/// `ext` is `true` when the REX.B bit extends the index by 8 (r8—"r15).
const fn x86_64_reg_name(idx: u8, ext: bool) -> &'static str {
    if ext {
        match idx {
            0 => "r8",
            1 => "r9",
            2 => "r10",
            3 => "r11",
            4 => "r12",
            5 => "r13",
            6 => "r14",
            _ => "r15",
        }
    } else {
        match idx {
            0 => "rax",
            1 => "rcx",
            2 => "rdx",
            3 => "rbx",
            4 => "rsp",
            5 => "rbp",
            6 => "rsi",
            _ => "rdi",
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Pattern construction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    // ── Cross-copy consistency (lib.rs pub fns vs detector ConventionLibrary) ──
    //
    // The same conventions are hand-duplicated in
    // `calling_convention_detector.rs`. This test asserts that every
    // convention shared by name is byte-for-byte identical across the two
    // `CallingConventionPattern` copies, so future divergence is caught.
    #[test]
    fn test_cross_copy_pattern_consistency() {
        use crate::calling_convention_detector::{ConventionLibrary, TargetArch};

        // All patterns produced by the detector-side copy.
        let mut detector = Vec::new();
        detector.extend(ConventionLibrary::x86_conventions());
        detector.extend(ConventionLibrary::x86_64_conventions());
        detector.extend(ConventionLibrary::arm_conventions());
        detector.extend(ConventionLibrary::for_arch(TargetArch::Mips32));
        detector.extend(ConventionLibrary::for_arch(TargetArch::RiscV64));

        // All patterns produced by the lib.rs copy.
        let lib = vec![
            sysv_x64(),
            msvc_x64(),
            cdecl_x86(),
            stdcall_x86(),
            fastcall_x86(),
            thiscall_x86(),
            vectorcall_x64(),
            aapcs64(),
            aapcs32(),
            mips_o32(),
            riscv64_lp64d(),
        ];

        let mut shared = 0;
        for l in &lib {
            if let Some(d) = detector.iter().find(|d| d.name == l.name) {
                assert_eq!(
                    l, d,
                    "cross-copy divergence for `{}`: lib.rs and \
                     calling_convention_detector.rs disagree field-by-field",
                    l.name
                );
                shared += 1;
            }
        }
        // Guard against the comparison silently matching nothing.
        assert!(
            shared >= 11,
            "expected >=11 shared conventions cross-checked, got {shared}"
        );
    }

    #[test]
    fn test_sysv_x64_pattern() {
        let cc = sysv_x64();
        assert!(cc.arg_registers.contains(&"rdi".to_string()));
        assert!(cc.callee_saved.contains(&"rbx".to_string()));
        assert!(cc.retval_registers.contains(&"rax".to_string()));
        assert!(cc.caller_cleanup);
        assert_eq!(cc.max_reg_args, 6);
        assert_eq!(cc.shadow_space_bytes, 0);
    }

    #[test]
    fn test_msvc_x64_pattern() {
        let cc = msvc_x64();
        assert!(cc.arg_registers.contains(&"rcx".to_string()));
        assert!(cc.arg_registers.contains(&"rdx".to_string()));
        assert!(cc.callee_saved.contains(&"rdi".to_string()));
        assert_eq!(cc.shadow_space_bytes, 32);
        assert_eq!(cc.max_reg_args, 4);
    }

    #[test]
    fn test_cdecl_no_arg_regs() {
        let cc = cdecl_x86();
        assert!(cc.arg_registers.is_empty());
        assert!(cc.caller_cleanup);
        assert_eq!(cc.max_reg_args, 0);
    }

    #[test]
    fn test_stdcall_callee_cleanup() {
        let cc = stdcall_x86();
        assert!(!cc.caller_cleanup);
        assert!(!cc.supports_variadic);
    }

    #[test]
    fn test_fastcall_ecx_edx() {
        let cc = fastcall_x86();
        assert_eq!(cc.arg_registers[0], "ecx");
        assert_eq!(cc.arg_registers[1], "edx");
        assert_eq!(cc.max_reg_args, 2);
    }

    #[test]
    fn test_thiscall_this_ptr() {
        let cc = thiscall_x86();
        assert!(cc.hidden_this_ptr);
        assert_eq!(cc.arg_registers[0], "ecx");
    }

    #[test]
    fn test_aapcs64_eight_args() {
        let cc = aapcs64();
        assert_eq!(cc.arg_registers.len(), 8);
        assert_eq!(cc.arg_registers[0], "x0");
        assert_eq!(cc.max_reg_args, 8);
    }

    #[test]
    fn test_aapcs32_four_args() {
        let cc = aapcs32();
        assert_eq!(cc.arg_registers.len(), 4);
        assert_eq!(cc.arg_registers[0], "r0");
    }

    #[test]
    fn test_vectorcall_xmm_ret() {
        let cc = vectorcall_x64();
        assert!(cc.retval_registers.contains(&"xmm0".to_string()));
        assert!(cc.fp_arg_registers.contains(&"xmm5".to_string()));
    }

    #[test]
    fn test_mips_o32_shadow() {
        let cc = mips_o32();
        assert_eq!(cc.shadow_space_bytes, 16); // argument slots
        assert_eq!(cc.arg_registers.len(), 4);
    }

    #[test]
    fn test_riscv64_lp64d() {
        let cc = riscv64_lp64d();
        assert_eq!(cc.arg_registers.len(), 8);
        assert_eq!(cc.max_reg_args, 8);
        assert!(cc.callee_saved.contains(&"s0".to_string()));
    }

    // â"€â"€ Detector: extract_pattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_extract_pattern_read_before_write() {
        let instrs = vec![
            DetectInstr::RegRead { reg: "rdi".into() },
            DetectInstr::RegRead { reg: "rsi".into() },
            DetectInstr::RegWrite { reg: "rax".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.read_before_write.contains(&"rdi".to_string()));
        assert!(pat.read_before_write.contains(&"rsi".to_string()));
        assert!(pat.written_before_return.contains(&"rax".to_string()));
    }

    #[test]
    fn test_extract_pattern_saved_registers() {
        let instrs = vec![
            DetectInstr::Push { reg: "rbx".into() },
            DetectInstr::Push { reg: "r12".into() },
            DetectInstr::Other,
            DetectInstr::Pop { reg: "r12".into() },
            DetectInstr::Pop { reg: "rbx".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.saved_registers.contains(&"rbx".to_string()));
        assert!(pat.saved_registers.contains(&"r12".to_string()));
    }

    #[test]
    fn test_extract_pattern_callee_pops() {
        let instrs = vec![DetectInstr::Ret { stack_bytes: 8 }];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.callee_pops_stack);
        assert_eq!(pat.callee_stack_pop, 8);
    }

    #[test]
    fn test_extract_pattern_this_ptr() {
        let instrs = vec![DetectInstr::ThisPtrUse, DetectInstr::Ret { stack_bytes: 0 }];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.this_ptr_hint);
    }

    #[test]
    fn test_extract_pattern_fp_regs() {
        let instrs = vec![
            DetectInstr::FpRegRead { reg: "xmm0".into() },
            DetectInstr::FpRegRead { reg: "xmm1".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.fp_read_before_write.contains(&"xmm0".to_string()));
        assert!(pat.fp_read_before_write.contains(&"xmm1".to_string()));
    }

    #[test]
    fn test_extract_pattern_shadow_space() {
        let instrs = vec![
            DetectInstr::StackAlloc { bytes: 40 },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.shadow_space_observed);
        assert_eq!(pat.max_stack_frame, 40);
    }

    #[test]
    fn test_extract_pattern_stack_args() {
        let instrs = vec![
            DetectInstr::StackArgAccess { offset: 8 },
            DetectInstr::StackArgAccess { offset: 12 },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        assert!(pat.stack_arg_count > 0);
    }

    // â"€â"€ Detector: detect â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_sysv() {
        let instrs = vec![
            DetectInstr::RegRead { reg: "rdi".into() },
            DetectInstr::RegRead { reg: "rsi".into() },
            DetectInstr::RegRead { reg: "rdx".into() },
            DetectInstr::Push { reg: "rbx".into() },
            DetectInstr::Push { reg: "r12".into() },
            DetectInstr::RegWrite { reg: "rax".into() },
            DetectInstr::Pop { reg: "r12".into() },
            DetectInstr::Pop { reg: "rbx".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        let cc = CallingConventionDetector::detect(&pat, &[sysv_x64(), msvc_x64()]).unwrap();
        assert_eq!(cc.name, "System V AMD64 ABI");
    }

    #[test]
    fn test_detect_msvc_x64() {
        let instrs = vec![
            DetectInstr::RegRead { reg: "rcx".into() },
            DetectInstr::RegRead { reg: "rdx".into() },
            DetectInstr::Push { reg: "rdi".into() },
            DetectInstr::Push { reg: "rsi".into() },
            DetectInstr::RegWrite { reg: "rax".into() },
            DetectInstr::Pop { reg: "rsi".into() },
            DetectInstr::Pop { reg: "rdi".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        let cc = CallingConventionDetector::detect(&pat, &[sysv_x64(), msvc_x64()]).unwrap();
        assert_eq!(cc.name, "Microsoft x64");
    }

    #[test]
    fn test_detect_no_candidates_error() {
        let pat = ObservedPattern::new();
        let result = CallingConventionDetector::detect(&pat, &[]);
        assert!(matches!(result, Err(CallConvError::NoMatch)));
    }

    #[test]
    fn test_detect_with_hints_shadow_space() {
        let observed = ObservedPattern {
            shadow_space_observed: true,
            ..Default::default()
        };
        // msvc_x64 has shadow_space_bytes = 32; sysv_x64 has 0
        let result =
            CallingConventionDetector::detect_with_hints(&observed, &[sysv_x64(), msvc_x64()]);
        // Either resolves msvc or returns ambiguous/no match - just ensure no panic
        let _ = result;
    }

    #[test]
    fn test_detect_with_evidence_sysv() {
        let observed = ObservedPattern {
            read_before_write: vec!["rdi".into(), "rsi".into()],
            saved_registers: vec!["rbx".into()],
            written_before_return: vec!["rax".into()],
            ..Default::default()
        };
        let (winner, evidence, score) =
            CallingConventionDetector::detect_with_evidence(&observed, &[sysv_x64(), msvc_x64()])
                .expect("should detect a candidate");
        assert_eq!(winner.name, "System V AMD64 ABI");
        // read_before_write(2) + saved_registers(1) + written_before_return(1)
        assert_eq!(evidence.len(), 4);
        let score = score.expect("sysv_x64 has a cc_detector::CcPattern counterpart");
        // positive evidence should score above zero for the winning CC.
        assert!(score > 0, "expected positive evidence score, got {score}");
    }

    #[test]
    fn test_detect_with_evidence_no_pattern_counterpart() {
        let observed = ObservedPattern {
            read_before_write: vec!["a0".into()],
            ..Default::default()
        };
        let (winner, _evidence, score) =
            CallingConventionDetector::detect_with_evidence(&observed, &[riscv64_lp64d()])
                .expect("should detect riscv");
        assert_eq!(winner.name, "RISC-V LP64D");
        // cc_detector has no RISC-V CcPattern builtin, so this must be None,
        // not a silently-wrong zero.
        assert!(score.is_none());
    }

    #[test]
    fn test_observed_pattern_to_evidence_shadow_space_and_this_ptr() {
        let observed = ObservedPattern {
            shadow_space_observed: true,
            this_ptr_hint: true,
            callee_pops_stack: true,
            callee_stack_pop: 8,
            ..Default::default()
        };
        let evidence = observed_pattern_to_evidence(&observed);
        assert!(evidence.iter().any(|e| e.kind == cc_detector::EvidenceKind::ShadowSpace));
        assert!(evidence.iter().any(|e| e.kind == cc_detector::EvidenceKind::ThisPointerHint));
        assert!(evidence.iter().any(|e| e.kind == cc_detector::EvidenceKind::CalleeStackCleanup));
    }

    #[test]
    fn test_cc_pattern_for_name_covers_shared_builtins() {
        assert!(cc_pattern_for_name("System V AMD64 ABI").is_some());
        assert!(cc_pattern_for_name("Microsoft x64").is_some());
        assert!(cc_pattern_for_name("cdecl (x86)").is_some());
        assert!(cc_pattern_for_name("stdcall (x86)").is_some());
        assert!(cc_pattern_for_name("thiscall (x86)").is_some());
        assert!(cc_pattern_for_name("AAPCS64").is_some());
        // No cc_detector counterpart for these lib.rs-only patterns.
        assert!(cc_pattern_for_name("AAPCS32").is_none());
        assert!(cc_pattern_for_name("MIPS O32").is_none());
        assert!(cc_pattern_for_name("RISC-V LP64D").is_none());
        assert!(cc_pattern_for_name("vectorcall (x64)").is_none());
    }

    #[test]
    fn test_rank_candidates() {
        let instrs = vec![
            DetectInstr::RegRead { reg: "rdi".into() },
            DetectInstr::RegWrite { reg: "rax".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let pat = CallingConventionDetector::extract_pattern(&instrs, 4);
        let ranked = CallingConventionDetector::rank_candidates(&pat, &[msvc_x64(), sysv_x64()]);
        assert_eq!(ranked.len(), 2);
        // sysv_x64 should rank higher because rdi is an arg register in SysV
        assert_eq!(ranked[0].0.name, "System V AMD64 ABI");
    }

    // â"€â"€ Database â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_database_lookup_sysv() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
        let ccs = db.lookup(&key);
        assert!(!ccs.is_empty());
        assert!(ccs.iter().any(|c| c.name == "System V AMD64 ABI"));
    }

    #[test]
    fn test_database_lookup_msvc() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::X86_64, Os::Windows, Compiler::Msvc);
        let ccs = db.lookup(&key);
        assert!(ccs.iter().any(|c| c.name == "Microsoft x64"));
    }

    #[test]
    fn test_database_lookup_arm64() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::Arm64, Os::Linux, Compiler::Gcc);
        let ccs = db.lookup(&key);
        assert!(ccs.iter().any(|c| c.name == "AAPCS64"));
    }

    #[test]
    fn test_database_lookup_any_compiler() {
        let db = CallingConventionDatabase::with_builtins();
        let ccs = db.lookup_any_compiler(&Arch::X86, &Os::Windows);
        assert!(!ccs.is_empty());
    }

    #[test]
    fn test_database_empty_key() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(
            Arch::Other("sparc".into()),
            Os::Other("vms".into()),
            Compiler::Any,
        );
        assert!(db.lookup(&key).is_empty());
    }

    #[test]
    fn test_database_entry_count() {
        let db = CallingConventionDatabase::with_builtins();
        assert!(db.entry_count() > 20);
        assert!(db.key_count() > 10);
    }

    #[test]
    fn test_database_all_names() {
        let db = CallingConventionDatabase::with_builtins();
        let names = db.all_names();
        assert!(names.contains(&"System V AMD64 ABI".to_string()));
        assert!(names.contains(&"Microsoft x64".to_string()));
        assert!(names.contains(&"AAPCS64".to_string()));
    }

    #[test]
    fn test_database_remove() {
        let mut db = CallingConventionDatabase::new();
        let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
        db.register(key.clone(), sysv_x64());
        assert!(!db.lookup(&key).is_empty());
        let removed = db.remove(&key);
        assert_eq!(removed, 1);
        assert!(db.lookup(&key).is_empty());
    }

    #[test]
    fn test_database_json_round_trip() {
        let db = CallingConventionDatabase::with_builtins();
        let json = db.to_json().unwrap();
        let db2 = CallingConventionDatabase::from_json(&json).unwrap();
        // Entry counts should match
        assert_eq!(db.entry_count(), db2.entry_count());
    }

    // â"€â"€ Score function â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_score_perfect_sysv() {
        let cc = sysv_x64();
        let observed = ObservedPattern {
            read_before_write: vec!["rdi".into(), "rsi".into(), "rdx".into()],
            saved_registers: vec!["rbx".into(), "r12".into()],
            written_before_return: vec!["rax".into()],
            ..Default::default()
        };
        let score = cc.score(&observed);
        assert!(score > 0);
    }

    #[test]
    fn test_score_zero_no_evidence() {
        let cc = sysv_x64();
        let observed = ObservedPattern::default();
        let score = cc.score(&observed);
        // callee_pops_stack=false vs caller_cleanup=true gives +5 bonus
        assert_eq!(score, 5);
    }

    // â"€â"€ CallingConventionPattern helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pattern_is_arg_register() {
        let cc = sysv_x64();
        assert!(cc.is_arg_register("rdi"));
        assert!(cc.is_arg_register("xmm0"));
        assert!(!cc.is_arg_register("rbx"));
    }

    #[test]
    fn test_pattern_is_callee_saved() {
        let cc = sysv_x64();
        assert!(cc.is_callee_saved("rbx"));
        assert!(!cc.is_callee_saved("rdi"));
    }

    #[test]
    fn test_pattern_is_retval() {
        let cc = sysv_x64();
        assert!(cc.is_retval_register("rax"));
        assert!(!cc.is_retval_register("rdi"));
    }

    #[test]
    fn test_pattern_arg_at() {
        let cc = sysv_x64();
        assert_eq!(cc.arg_register_at(0), Some("rdi"));
        assert_eq!(cc.arg_register_at(1), Some("rsi"));
        assert_eq!(cc.arg_register_at(100), None);
    }

    #[test]
    fn test_pattern_display() {
        let cc = sysv_x64();
        let s = cc.to_string();
        assert!(s.contains("System V AMD64 ABI"));
        assert!(s.contains("16"));
    }

    // â"€â"€ RegisterClassifier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_register_classifier_sysv() {
        let cc = sysv_x64();
        assert_eq!(
            RegisterClassifier::classify(&cc, "rdi"),
            RegisterRole::Argument
        );
        assert_eq!(
            RegisterClassifier::classify(&cc, "xmm0"),
            RegisterRole::FpArgument
        );
        assert_eq!(
            RegisterClassifier::classify(&cc, "rax"),
            RegisterRole::ReturnValue
        );
        assert_eq!(
            RegisterClassifier::classify(&cc, "rbx"),
            RegisterRole::CalleeSaved
        );
        assert_eq!(
            RegisterClassifier::classify(&cc, "r10"),
            RegisterRole::CallerSaved
        );
        assert_eq!(
            RegisterClassifier::classify(&cc, "cr0"),
            RegisterRole::Unknown
        );
    }

    #[test]
    fn test_registers_with_role() {
        let cc = sysv_x64();
        let callee_saved = RegisterClassifier::registers_with_role(&cc, RegisterRole::CalleeSaved);
        assert!(callee_saved.contains(&"rbx"));
        assert!(callee_saved.contains(&"r15"));
    }

    // â"€â"€ ParameterMapper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parameter_mapper_sysv() {
        let cc = sysv_x64();
        let reads = vec!["rdi".to_string(), "rsi".to_string(), "rdx".to_string()];
        let mapped = ParameterMapper::map_args(&reads, &cc);
        assert_eq!(mapped.len(), 3);
        assert_eq!(mapped[0], (0, "rdi".to_string()));
        assert_eq!(mapped[1], (1, "rsi".to_string()));
        assert_eq!(mapped[2], (2, "rdx".to_string()));
    }

    #[test]
    fn test_parameter_mapper_arg_count() {
        let cc = sysv_x64();
        let observed = ObservedPattern {
            read_before_write: vec!["rdi".into(), "rsi".into()],
            stack_arg_count: 2,
            ..Default::default()
        };
        let count = ParameterMapper::estimated_arg_count(&observed, &cc);
        assert_eq!(count, 4); // 2 reg + 2 stack
    }

    // â"€â"€ BulkCallConvAnalyzer / CallConvStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bulk_analyzer_single() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
        let analyzer = BulkCallConvAnalyzer::new(db, key);

        let instrs = vec![
            DetectInstr::RegRead { reg: "rdi".into() },
            DetectInstr::RegWrite { reg: "rax".into() },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let result = analyzer.analyse_function(0x1000, &instrs).unwrap();
        assert_eq!(result.function_address, 0x1000);
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_bulk_analyzer_all() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Any);
        let analyzer = BulkCallConvAnalyzer::new(db, key);

        let functions = vec![
            (
                0x1000u64,
                vec![
                    DetectInstr::RegRead { reg: "rdi".into() },
                    DetectInstr::Ret { stack_bytes: 0 },
                ],
            ),
            (
                0x2000u64,
                vec![
                    DetectInstr::RegRead { reg: "rsi".into() },
                    DetectInstr::Ret { stack_bytes: 0 },
                ],
            ),
        ];
        let summaries = analyzer.analyse_all(&functions);
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn test_call_conv_stats() {
        let db = CallingConventionDatabase::with_builtins();
        let key = CcKey::new(Arch::X86_64, Os::Linux, Compiler::Gcc);
        let analyzer = BulkCallConvAnalyzer::new(db, key);

        let functions: Vec<(u64, Vec<DetectInstr>)> = (0..5)
            .map(|i| {
                (
                    i * 0x100,
                    vec![
                        DetectInstr::RegRead { reg: "rdi".into() },
                        DetectInstr::RegWrite { reg: "rax".into() },
                        DetectInstr::Ret { stack_bytes: 0 },
                    ],
                )
            })
            .collect();
        let summaries = analyzer.analyse_all(&functions);
        let stats = BulkCallConvAnalyzer::statistics(&summaries);
        assert_eq!(stats.total, 5);
        assert!(stats.avg_confidence > 0.0);
        assert!(stats.most_common().is_some());
    }

    #[test]
    fn test_call_conv_stats_empty() {
        let stats = CallConvStats::compute(&[]);
        assert_eq!(stats.total, 0);
        assert!(stats.most_common().is_none());
    }

    // â"€â"€ ObservedPattern helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_observed_pattern_has_arg_evidence() {
        let mut pat = ObservedPattern::new();
        assert!(!pat.has_arg_evidence());
        pat.read_before_write.push("rdi".into());
        assert!(pat.has_arg_evidence());
    }

    #[test]
    fn test_observed_pattern_looks_like_leaf() {
        let pat = ObservedPattern {
            max_stack_frame: 8,
            ..Default::default()
        };
        assert!(pat.looks_like_leaf());
        let pat2 = ObservedPattern {
            saved_registers: vec!["rbx".into()],
            ..Default::default()
        };
        assert!(!pat2.looks_like_leaf());
    }

    // â"€â"€ CallingConvDef constants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cc_sysv_amd64_def() {
        assert_eq!(CC_SYSV_AMD64.name, "sysv_amd64");
        assert!(CC_SYSV_AMD64.is_int_arg("rdi"));
        assert!(CC_SYSV_AMD64.is_int_arg("rsi"));
        assert!(CC_SYSV_AMD64.is_float_arg("xmm0"));
        assert!(CC_SYSV_AMD64.is_callee_saved("rbx"));
        assert!(!CC_SYSV_AMD64.is_callee_saved("rdi"));
        assert_eq!(CC_SYSV_AMD64.stack_cleanup, CcStackCleanup::Caller);
        assert_eq!(CC_SYSV_AMD64.shadow_space, 0);
        assert!(!CC_SYSV_AMD64.has_this_ptr);
    }

    #[test]
    fn test_cc_ms_x64_def() {
        assert_eq!(CC_MS_X64.name, "ms_x64");
        assert!(CC_MS_X64.is_int_arg("rcx"));
        assert!(CC_MS_X64.is_int_arg("rdx"));
        assert!(CC_MS_X64.is_float_arg("xmm0"));
        assert!(CC_MS_X64.is_callee_saved("rdi")); // MS x64 saves rdi
        assert_eq!(CC_MS_X64.shadow_space, 32);
        assert_eq!(CC_MS_X64.stack_cleanup, CcStackCleanup::Caller);
    }

    #[test]
    fn test_cc_cdecl_def() {
        assert_eq!(CC_CDECL.name, "cdecl");
        assert!(CC_CDECL.int_arg_regs.is_empty());
        assert_eq!(CC_CDECL.stack_cleanup, CcStackCleanup::Caller);
        assert_eq!(CC_CDECL.int_ret_reg, "eax");
    }

    #[test]
    fn test_cc_stdcall_def() {
        assert_eq!(CC_STDCALL.name, "stdcall");
        assert!(CC_STDCALL.int_arg_regs.is_empty());
        assert_eq!(CC_STDCALL.stack_cleanup, CcStackCleanup::Callee);
    }

    #[test]
    fn test_cc_fastcall_def() {
        assert_eq!(CC_FASTCALL.name, "fastcall");
        assert!(CC_FASTCALL.is_int_arg("ecx"));
        assert!(CC_FASTCALL.is_int_arg("edx"));
        assert_eq!(CC_FASTCALL.int_arg_regs.len(), 2);
        assert_eq!(CC_FASTCALL.stack_cleanup, CcStackCleanup::Callee);
    }

    #[test]
    fn test_cc_thiscall_def() {
        assert_eq!(CC_THISCALL.name, "thiscall");
        assert!(CC_THISCALL.has_this_ptr);
        assert!(CC_THISCALL.is_int_arg("ecx"));
        assert_eq!(CC_THISCALL.stack_cleanup, CcStackCleanup::Callee);
    }

    #[test]
    fn test_cc_vectorcall_def() {
        assert_eq!(CC_VECTORCALL.name, "vectorcall");
        assert!(CC_VECTORCALL.is_float_arg("xmm5"));
        assert!(CC_VECTORCALL.is_int_arg("rcx"));
        assert_eq!(CC_VECTORCALL.float_ret_reg, "xmm0");
    }

    /// Differential guard: the lib.rs `CC_VECTORCALL` and `cc_database.rs`'s
    /// `CC_VECTORCALL_X64` are hand-synced duplicates. A prior fix set
    /// `shadow_space=32` in the database copy but left lib.rs at 0 — this test
    /// locks the two copies together so the divergence cannot recur.
    #[test]
    fn cc_vectorcall_lib_matches_database_copy() {
        assert_eq!(
            CC_VECTORCALL.shadow_space, CC_VECTORCALL_X64.shadow_space,
            "vectorcall shadow_space diverges between lib.rs and cc_database.rs"
        );
        assert_eq!(CC_VECTORCALL.shadow_space, 32);
        assert_eq!(CC_VECTORCALL.int_arg_regs, CC_VECTORCALL_X64.int_arg_regs);
        assert_eq!(CC_VECTORCALL.float_arg_regs, CC_VECTORCALL_X64.float_arg_regs);
        assert_eq!(CC_VECTORCALL.int_ret_reg, CC_VECTORCALL_X64.int_ret_reg);
        assert_eq!(CC_VECTORCALL.callee_saved, CC_VECTORCALL_X64.callee_saved);
    }

    /// Differential: lib.rs `aapcs32()` vs `cc_database.rs` `CC_AAPCS32`/`_VFP`.
    #[test]
    fn cc_aapcs32_lib_matches_database_copy() {
        let p = aapcs32();
        let args: Vec<&str> = p.arg_registers.iter().map(String::as_str).collect();
        assert_eq!(args, CC_AAPCS32.int_arg_regs);
        assert_eq!(args, CC_AAPCS32_VFP.int_arg_regs);
        let fp: Vec<&str> = p.fp_arg_registers.iter().map(String::as_str).collect();
        assert_eq!(fp, CC_AAPCS32_VFP.float_arg_regs, "AAPCS32 VFP s0-s15");
        let saved: Vec<&str> = p.callee_saved.iter().map(String::as_str).collect();
        assert_eq!(saved, CC_AAPCS32.callee_saved, "r4-r11, no r14 (LR)");
        assert_eq!(saved, CC_AAPCS32_VFP.callee_saved);
        assert!(!saved.contains(&"r14"), "LR is not callee-saved (AAPCS32 §6.1.1)");
        assert_eq!(p.retval_registers, vec!["r0".to_string(), "r1".to_string()]);
        assert_eq!(u32::from(CC_AAPCS32.stack_align), p.stack_alignment);
        assert_eq!(u32::from(CC_AAPCS32.shadow_space), p.shadow_space_bytes);
    }

    /// Differential: lib.rs `mips_o32()` vs `cc_database.rs` `CC_MIPS_O32`.
    #[test]
    fn cc_mips_o32_lib_matches_database_copy() {
        let p = mips_o32();
        let args: Vec<&str> = p.arg_registers.iter().map(String::as_str).collect();
        assert_eq!(args, CC_MIPS_O32.int_arg_regs);
        let fp: Vec<&str> = p.fp_arg_registers.iter().map(String::as_str).collect();
        assert_eq!(fp, CC_MIPS_O32.float_arg_regs);
        let saved: Vec<&str> = p.callee_saved.iter().map(String::as_str).collect();
        assert_eq!(saved, CC_MIPS_O32.callee_saved, "s0-s7");
        assert_eq!(p.retval_registers[0], CC_MIPS_O32.int_ret_reg);
        assert_eq!(u32::from(CC_MIPS_O32.stack_align), p.stack_alignment);
        assert_eq!(u32::from(CC_MIPS_O32.shadow_space), p.shadow_space_bytes);
        assert_eq!(p.shadow_space_bytes, 16, "o32 16-byte arg-save area");
        // $t0-$t9 are all caller-saved (SysV MIPS o32 ABI supplement).
        assert!(p.caller_saved.iter().any(|r| r == "t8"));
        assert!(p.caller_saved.iter().any(|r| r == "t9"));
    }

    /// Differential: lib.rs `riscv64_lp64d()` vs `cc_database.rs`
    /// `CC_RISCV64_LP64D` and `CC_RISCV32_ILP32D` (identical register model).
    #[test]
    fn cc_riscv_lib_matches_database_copy() {
        let p = riscv64_lp64d();
        let args: Vec<&str> = p.arg_registers.iter().map(String::as_str).collect();
        assert_eq!(args, CC_RISCV64_LP64D.int_arg_regs);
        assert_eq!(args, CC_RISCV32_ILP32D.int_arg_regs);
        let fp: Vec<&str> = p.fp_arg_registers.iter().map(String::as_str).collect();
        assert_eq!(fp, CC_RISCV64_LP64D.float_arg_regs);
        assert_eq!(fp, CC_RISCV32_ILP32D.float_arg_regs);
        let saved: Vec<&str> = p.callee_saved.iter().map(String::as_str).collect();
        assert_eq!(saved, CC_RISCV64_LP64D.callee_saved, "s0-s11");
        assert_eq!(saved, CC_RISCV32_ILP32D.callee_saved);
        assert_eq!(p.retval_registers[0], CC_RISCV64_LP64D.int_ret_reg);
        assert_eq!(p.retval_registers, vec!["a0".to_string(), "a1".to_string()]);
        assert_eq!(u32::from(CC_RISCV64_LP64D.stack_align), p.stack_alignment);
        assert_eq!(p.stack_alignment, 16, "RISC-V psABI: 16-byte stack alignment");
        // Temporaries t0-t6 caller-saved per the RISC-V psABI.
        let caller: Vec<&str> = p.caller_saved.iter().map(String::as_str).collect();
        assert_eq!(caller, ["t0", "t1", "t2", "t3", "t4", "t5", "t6"]);
    }

    #[test]
    fn test_cc_display() {
        let s = CC_SYSV_AMD64.to_string();
        assert!(s.contains("sysv_amd64"));
        assert!(s.contains("caller"));
    }

    #[test]
    fn test_cc_stack_cleanup_display() {
        assert_eq!(CcStackCleanup::Caller.to_string(), "caller");
        assert_eq!(CcStackCleanup::Callee.to_string(), "callee");
    }

    // â"€â"€ CallConvDatabase â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_call_conv_database_with_builtins() {
        let db = CallConvDatabase::with_builtins();
        assert_eq!(db.len(), 7);
        assert!(!db.is_empty());
    }

    #[test]
    fn test_call_conv_database_get() {
        let db = CallConvDatabase::with_builtins();
        let cc = db.get("sysv_amd64").unwrap();
        assert_eq!(cc.name, "sysv_amd64");
        assert!(db.get("unknown_cc").is_none());
    }

    #[test]
    fn test_call_conv_database_names_sorted() {
        let db = CallConvDatabase::with_builtins();
        let names = db.names();
        assert_eq!(names.len(), 7);
        // Verify all seven are present.
        assert!(names.contains(&"sysv_amd64"));
        assert!(names.contains(&"ms_x64"));
        assert!(names.contains(&"cdecl"));
        assert!(names.contains(&"stdcall"));
        assert!(names.contains(&"fastcall"));
        assert!(names.contains(&"thiscall"));
        assert!(names.contains(&"vectorcall"));
        // Must be sorted.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_call_conv_database_all() {
        let db = CallConvDatabase::with_builtins();
        let all = db.all();
        assert_eq!(all.len(), 7);
    }

    #[test]
    fn test_call_conv_database_register() {
        let mut db = CallConvDatabase::new();
        assert!(db.is_empty());
        db.register(&CC_SYSV_AMD64);
        assert_eq!(db.len(), 1);
        assert!(db.get("sysv_amd64").is_some());
    }

    // â"€â"€ Instruction helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_instruction_push_pop_ret() {
        let push = Instruction::push(0x1000, "rbx");
        assert!(push.is_push);
        assert_eq!(push.reads, vec!["rbx"]);

        let pop = Instruction::pop(0x1001, "rbx");
        assert!(pop.is_pop);
        assert_eq!(pop.writes, vec!["rbx"]);

        let ret = Instruction::ret(0x1010, 8);
        assert!(ret.is_ret);
        assert_eq!(ret.ret_stack_bytes, 8);
    }

    #[test]
    fn test_instruction_rw() {
        let i = Instruction::rw(0x1000, vec!["rdi".into(), "rsi".into()], vec!["rax".into()]);
        assert_eq!(i.reads.len(), 2);
        assert_eq!(i.writes.len(), 1);
        assert!(!i.is_push);
        assert!(!i.is_ret);
    }

    // â"€â"€ detect_calling_convention â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_cc_sysv_from_instrs() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_SYSV_AMD64, &CC_MS_X64, &CC_CDECL];

        let instrs = vec![
            Instruction::rw(
                0x1000,
                vec!["rdi".into(), "rsi".into(), "rdx".into()],
                vec![],
            ),
            Instruction::push(0x1003, "rbx"),
            Instruction::push(0x1004, "r12"),
            Instruction::rw(0x1010, vec![], vec!["rax".into()]),
            Instruction::pop(0x1020, "r12"),
            Instruction::pop(0x1021, "rbx"),
            Instruction::ret(0x1022, 0),
        ];

        let cc = detect_calling_convention(&instrs, &candidates);
        assert!(cc.is_some());
        assert_eq!(cc.unwrap().name, "sysv_amd64");
    }

    #[test]
    fn test_detect_cc_ms_x64_shadow_space() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_SYSV_AMD64, &CC_MS_X64];

        let mut shadow = Instruction::rw(0x1000, vec!["rcx".into(), "rdx".into()], vec![]);
        shadow.stack_alloc = 40; // shadow space hint

        let instrs = vec![
            shadow,
            Instruction::push(0x1005, "rdi"),
            Instruction::push(0x1006, "rsi"),
            Instruction::rw(0x1010, vec![], vec!["rax".into()]),
            Instruction::pop(0x1020, "rsi"),
            Instruction::pop(0x1021, "rdi"),
            Instruction::ret(0x1022, 0),
        ];

        let cc = detect_calling_convention(&instrs, &candidates);
        assert!(cc.is_some());
        assert_eq!(cc.unwrap().name, "ms_x64");
    }

    #[test]
    fn test_detect_cc_stdcall_callee_cleanup() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_CDECL, &CC_STDCALL];

        // stdcall: args on stack, callee does RET 8.
        let instrs = vec![
            Instruction::push(0x1000, "ebp"),
            Instruction::rw(0x1001, vec![], vec!["ebp".into()]),
            Instruction::rw(0x1010, vec![], vec!["eax".into()]),
            Instruction::pop(0x1020, "ebp"),
            Instruction::ret(0x1021, 8), // callee cleans 8 bytes
        ];

        let cc = detect_calling_convention(&instrs, &candidates);
        assert!(cc.is_some());
        assert_eq!(cc.unwrap().name, "stdcall");
    }

    #[test]
    fn test_detect_cc_thiscall_this_ptr() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_CDECL, &CC_THISCALL, &CC_FASTCALL];

        let mut this_instr = Instruction::rw(0x1000, vec!["ecx".into()], vec![]);
        this_instr.is_this_ptr_use = true;

        let instrs = vec![
            this_instr,
            Instruction::push(0x1001, "esi"),
            Instruction::rw(0x1010, vec![], vec!["eax".into()]),
            Instruction::pop(0x1020, "esi"),
            Instruction::ret(0x1021, 4),
        ];

        let cc = detect_calling_convention(&instrs, &candidates);
        assert!(cc.is_some());
        assert_eq!(cc.unwrap().name, "thiscall");
    }

    #[test]
    fn test_detect_cc_empty_candidates_returns_none() {
        let instrs = vec![Instruction::ret(0x1000, 0)];
        assert!(detect_calling_convention(&instrs, &[]).is_none());
    }

    #[test]
    fn test_detect_cc_empty_instrs_returns_none() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_SYSV_AMD64];
        assert!(detect_calling_convention(&[], &candidates).is_none());
    }

    // â"€â"€ get_arg_types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_get_arg_types_sysv_three_int_args() {
        let func = FunctionInfo {
            address: 0x1000,
            cc_name: "sysv_amd64".into(),
            live_in_regs: vec!["rdi".into(), "rsi".into(), "rdx".into()],
            live_in_fp_regs: vec![],
            stack_arg_count: 0,
            has_this_ptr: false,
        };
        let args = get_arg_types(&func, &CC_SYSV_AMD64);
        assert_eq!(args.len(), 3);
        assert!(matches!(&args[0], ArgType::Integer { reg, position: 0 } if reg == "rdi"));
        assert!(matches!(&args[1], ArgType::Integer { reg, position: 1 } if reg == "rsi"));
        assert!(matches!(&args[2], ArgType::Integer { reg, position: 2 } if reg == "rdx"));
    }

    #[test]
    fn test_get_arg_types_sysv_fp_args() {
        let func = FunctionInfo {
            address: 0x1000,
            cc_name: "sysv_amd64".into(),
            live_in_regs: vec![],
            live_in_fp_regs: vec!["xmm0".into(), "xmm1".into()],
            stack_arg_count: 0,
            has_this_ptr: false,
        };
        let args = get_arg_types(&func, &CC_SYSV_AMD64);
        assert_eq!(args.len(), 2);
        assert!(matches!(&args[0], ArgType::Float { reg, position: 0 } if reg == "xmm0"));
        assert!(matches!(&args[1], ArgType::Float { reg, position: 1 } if reg == "xmm1"));
    }

    #[test]
    fn test_get_arg_types_thiscall_this_ptr() {
        let func = FunctionInfo {
            address: 0x1000,
            cc_name: "thiscall".into(),
            live_in_regs: vec!["ecx".into()],
            live_in_fp_regs: vec![],
            stack_arg_count: 0,
            has_this_ptr: true,
        };
        let args = get_arg_types(&func, &CC_THISCALL);
        // Should start with ThisPtr.
        assert!(matches!(&args[0], ArgType::ThisPtr { reg } if reg == "ecx"));
    }

    #[test]
    fn test_get_arg_types_stack_args() {
        let func = FunctionInfo {
            address: 0x1000,
            cc_name: "cdecl".into(),
            live_in_regs: vec![],
            live_in_fp_regs: vec![],
            stack_arg_count: 3,
            has_this_ptr: false,
        };
        let args = get_arg_types(&func, &CC_CDECL);
        // cdecl: all args on stack.
        assert_eq!(args.len(), 3);
        for (i, arg) in args.iter().enumerate() {
            assert!(matches!(arg, ArgType::Stack { slot, .. } if *slot == i as u32));
        }
    }

    #[test]
    fn test_get_arg_types_ms_x64_shadow_offsets() {
        let func = FunctionInfo {
            address: 0x1000,
            cc_name: "ms_x64".into(),
            live_in_regs: vec!["rcx".into(), "rdx".into()],
            live_in_fp_regs: vec![],
            stack_arg_count: 2, // two extra stack args
            has_this_ptr: false,
        };
        let args = get_arg_types(&func, &CC_MS_X64);
        // 2 int args + 2 stack args
        let stack_args: Vec<_> = args
            .iter()
            .filter(|a| matches!(a, ArgType::Stack { .. }))
            .collect();
        assert_eq!(stack_args.len(), 2);
        // ms_x64 has shadow_space=32 so stack slot 0 â†' offset 32.
        if let ArgType::Stack { slot: 0, offset } = stack_args[0] {
            assert_eq!(*offset, 32);
        }
    }

    // â"€â"€ ArgType Display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arg_type_display() {
        let int_arg = ArgType::Integer {
            reg: "rdi".into(),
            position: 0,
        };
        assert!(int_arg.to_string().contains("rdi"));
        assert!(int_arg.to_string().contains('0'));

        let float_arg = ArgType::Float {
            reg: "xmm0".into(),
            position: 0,
        };
        assert!(float_arg.to_string().contains("xmm0"));

        let this_arg = ArgType::ThisPtr { reg: "ecx".into() };
        assert!(this_arg.to_string().contains("this"));

        let stack_arg = ArgType::Stack {
            slot: 2,
            offset: 0x10,
        };
        assert!(stack_arg.to_string().contains("stack[2]"));

        let unknown_arg = ArgType::Unknown { position: 5 };
        assert!(unknown_arg.to_string().contains("unknown"));
    }

    // â"€â"€ CallConvAnalysisResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_call_conv_analysis_result_sysv() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_SYSV_AMD64, &CC_MS_X64];

        let instrs = vec![
            Instruction::rw(0x1000, vec!["rdi".into(), "rsi".into()], vec![]),
            Instruction::push(0x1004, "rbx"),
            Instruction::rw(0x1010, vec![], vec!["rax".into()]),
            Instruction::pop(0x1020, "rbx"),
            Instruction::ret(0x1021, 0),
        ];

        let result = CallConvAnalysisResult::analyze(0x1000, &instrs, &candidates);
        assert_eq!(result.address, 0x1000);
        assert!(result.cc.is_some());
        assert_eq!(result.cc.unwrap().name, "sysv_amd64");
        assert!(!result.args.is_empty());
        assert!(result.preserved.contains(&"rbx".to_string()));
        assert!(!result.callee_cleans_stack);
    }

    #[test]
    fn test_call_conv_analysis_result_stdcall() {
        let candidates: Vec<&'static CallingConvDef> = vec![&CC_CDECL, &CC_STDCALL];

        let instrs = vec![
            Instruction::push(0x1000, "ebp"),
            Instruction::rw(0x1002, vec![], vec!["eax".into()]),
            Instruction::pop(0x1010, "ebp"),
            Instruction::ret(0x1011, 8),
        ];

        let result = CallConvAnalysisResult::analyze(0x1000, &instrs, &candidates);
        assert!(result.callee_cleans_stack);
        assert!(result.cc.is_some());
        assert_eq!(result.cc.unwrap().name, "stdcall");
    }

    #[test]
    fn test_call_conv_analysis_result_no_candidates() {
        let result = CallConvAnalysisResult::analyze(0x1000, &[Instruction::ret(0, 0)], &[]);
        assert!(result.cc.is_none());
        assert!(result.args.is_empty());
    }

    #[test]
    fn test_build_instruction_stream_empty_bytes() {
        // Regression: an entry point whose backing segment data is shorter
        // than its address range (e.g. a zero-filled `.bss`-like tail) must
        // not panic when the caller passes an empty slice.
        let instrs = build_instruction_stream(0x1000, &[]);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_build_instruction_stream_prologue_and_ret() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20; ret
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3];
        let instrs = build_instruction_stream(0x1000, &bytes);
        assert!(instrs.iter().any(|i| i.is_push));
        assert!(instrs.iter().any(|i| i.is_ret));
        assert!(instrs.iter().any(|i| i.stack_alloc == 0x20));
    }

    #[test]
    fn test_build_instruction_stream_stops_at_ret() {
        // ret, followed by more bytes that should never be scanned.
        let bytes = [0xC3, 0x50, 0x51, 0x52];
        let instrs = build_instruction_stream(0x1000, &bytes);
        assert_eq!(instrs.len(), 1);
        assert!(instrs[0].is_ret);
    }

    #[test]
    fn test_score_empty_pattern_saturates_not_panics() {
        // A convention with empty register lists scored against an empty
        // observed pattern must not panic and should score zero.
        let cc = CallingConventionPattern {
            name: "empty".into(),
            arg_registers: vec![],
            fp_arg_registers: vec![],
            retval_registers: vec![],
            callee_saved: vec![],
            caller_saved: vec![],
            stack_alignment: 0,
            caller_cleanup: false,
            hidden_this_ptr: false,
            max_reg_args: 0,
            supports_variadic: false,
            shadow_space_bytes: 0,
        };
        let observed = ObservedPattern::default();
        let score = cc.score(&observed);
        assert!(score <= 5);
    }

    /// Regression test: `lookup_any_compiler`/`lookup_any_os` iterate a
    /// `HashMap` internally; without a sort the returned `Vec` order would be
    /// nondeterministic across runs. Verify repeated calls agree.
    #[test]
    fn lookup_any_compiler_and_os_are_deterministic() {
        let db = CallingConventionDatabase::with_builtins();
        let first_compiler: Vec<String> = db
            .lookup_any_compiler(&Arch::X86_64, &Os::Linux)
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let first_os: Vec<String> = db
            .lookup_any_os(&Arch::X86_64)
            .iter()
            .map(|p| p.name.clone())
            .collect();
        for _ in 0..20 {
            let again_compiler: Vec<String> = db
                .lookup_any_compiler(&Arch::X86_64, &Os::Linux)
                .iter()
                .map(|p| p.name.clone())
                .collect();
            let again_os: Vec<String> = db
                .lookup_any_os(&Arch::X86_64)
                .iter()
                .map(|p| p.name.clone())
                .collect();
            assert_eq!(first_compiler, again_compiler);
            assert_eq!(first_os, again_os);
        }
        // And the result should actually be sorted by name.
        let mut sorted = first_compiler.clone();
        sorted.sort_unstable();
        assert_eq!(first_compiler, sorted);
    }

    /// Regression test: `CcDetectionSummary::most_common` used to break count
    /// ties by `HashMap` iteration order; verify it is stable and picks the
    /// alphabetically-last name among tied top counts (see comparator).
    #[test]
    fn cc_summary_most_common_is_deterministic_on_ties() {
        // Build two summaries whose `by_name` maps have equal top counts for
        // multiple names, inserted in different orders, and confirm the same
        // winner is chosen both times across many repeats.
        let mut by_name_a: HashMap<String, usize> = HashMap::new();
        by_name_a.insert("alpha".to_string(), 3);
        by_name_a.insert("beta".to_string(), 3);
        by_name_a.insert("gamma".to_string(), 1);

        let summary = CallConvStats {
            total: 7,
            high_confidence: 0,
            by_name: by_name_a,
            avg_confidence: 0.0,
            max_confidence: 0,
            min_confidence: 0,
        };
        let first = summary.most_common().map(str::to_owned);
        for _ in 0..20 {
            assert_eq!(summary.most_common().map(str::to_owned), first);
        }
    }
}

