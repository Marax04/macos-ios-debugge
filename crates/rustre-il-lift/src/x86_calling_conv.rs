//! x86/x64 calling convention models.
//!
//! A calling convention describes how function arguments are passed, where
//! the return value lives, which registers the callee must preserve, and how
//! the stack is managed across a call boundary. This module provides
//! structured types for the most common x86/x64 calling conventions and
//! helpers to:
//!
//!   * annotate `Effect::Call` nodes with argument positions,
//!   * resolve `Effect::Return` nodes to the appropriate return register,
//!   * determine which registers must be saved/restored by the callee
//!     (callee-saved) or the caller (caller-saved).
//!
//! These models feed into `rustre-il-mlil`'s MLIL function type recovery and
//! are also used by the disassembler pretty-printer to render function calls
//! with argument annotations.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ArgLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Where a function argument (or return value) lives at the call boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgLocation {
    /// Argument lives in a register.
    Register(String),
    /// Argument is on the stack at `[rsp + offset]` at the point of the call.
    Stack { offset_bytes: i64 },
    /// Argument is split across multiple locations (e.g. 128-bit value in
    /// two 64-bit registers).
    Pair(Box<Self>, Box<Self>),
    /// Location is not known or not modelled.
    Unknown,
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{r}"),
            Self::Stack { offset_bytes } => write!(f, "[rsp+{offset_bytes}]"),
            Self::Pair(a, b) => write!(f, "{a}:{b}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParamKind
// ─────────────────────────────────────────────────────────────────────────────

/// Broad classification of a parameter's type for calling-convention lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// Integer / pointer (fits in a GPR).
    IntOrPtr,
    /// 32-bit single-precision float.
    Float32,
    /// 64-bit double-precision float.
    Float64,
    /// 128-bit SIMD value (XMM register).
    Vec128,
    /// 256-bit SIMD value (YMM register).
    Vec256,
    /// 512-bit SIMD value (ZMM register).
    Vec512,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention trait
// ─────────────────────────────────────────────────────────────────────────────

/// A calling convention describes the register and stack layout for calls.
pub trait CallingConvention: fmt::Debug + Send + Sync {
    /// Short name (e.g. "`sysv_amd64`", "`ms_x64`", "cdecl").
    fn name(&self) -> &'static str;

    /// Platform description (e.g. "Linux x86-64 System V ABI").
    fn description(&self) -> &'static str;

    /// Location of the `n`th argument (0-indexed) for parameters of `kind`.
    /// Returns `ArgLocation::Unknown` when the convention does not specify
    /// this position (i.e., the argument goes on the stack at a calculated
    /// offset).
    fn arg_location(&self, n: usize, kind: ParamKind) -> ArgLocation;

    /// Location of the primary return value for parameters of `kind`.
    fn return_location(&self, kind: ParamKind) -> ArgLocation;

    /// Registers the callee must preserve (callee-saved / non-volatile).
    fn callee_saved_regs(&self) -> &[&str];

    /// Registers the caller must preserve if it needs them after the call
    /// (caller-saved / volatile).
    fn caller_saved_regs(&self) -> &[&str];

    /// `true` if the callee cleans the stack (e.g. `stdcall`, `fastcall`).
    fn callee_cleans_stack(&self) -> bool;

    /// Number of bytes of "shadow space" (Windows x64 requirement).
    fn shadow_space_bytes(&self) -> u32 {
        0
    }

    /// Stack alignment requirement in bytes at the point of the CALL instruction.
    fn stack_alignment_bytes(&self) -> u32 {
        16
    }

    /// `true` if variadic (varargs) calls are supported by this convention.
    fn supports_varargs(&self) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SysV AMD64 — Linux / macOS / FreeBSD x86-64
// ─────────────────────────────────────────────────────────────────────────────

/// System V AMD64 ABI — used on Linux, macOS, BSD, and most Unix-like systems.
///
/// Integer/pointer arguments: rdi, rsi, rdx, rcx, r8, r9 (then stack).
/// FP arguments: xmm0–xmm7.
/// Return: rax (integer), xmm0 (float).
/// Callee-saved: rbx, rbp, r12–r15.
#[derive(Debug, Clone)]
pub struct SysVAmd64;

const SYSV_INT_ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const SYSV_FP_ARG_REGS: [&str; 8] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
];
const SYSV_CALLEE_SAVED: [&str; 6] = ["rbx", "rbp", "r12", "r13", "r14", "r15"];
const SYSV_CALLER_SAVED: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

impl CallingConvention for SysVAmd64 {
    fn name(&self) -> &'static str {
        "sysv_amd64"
    }
    fn description(&self) -> &'static str {
        "System V AMD64 ABI (Linux/macOS/BSD)"
    }

    fn arg_location(&self, n: usize, kind: ParamKind) -> ArgLocation {
        match kind {
            ParamKind::Float32 | ParamKind::Float64 | ParamKind::Vec128 => {
                if n < SYSV_FP_ARG_REGS.len() {
                    ArgLocation::Register(SYSV_FP_ARG_REGS[n].into())
                } else {
                    ArgLocation::Stack {
                        offset_bytes: i64::try_from((n - SYSV_FP_ARG_REGS.len()) * 8).unwrap_or(i64::MAX),
                    }
                }
            }
            _ => {
                if n < SYSV_INT_ARG_REGS.len() {
                    ArgLocation::Register(SYSV_INT_ARG_REGS[n].into())
                } else {
                    ArgLocation::Stack {
                        offset_bytes: i64::try_from((n - SYSV_INT_ARG_REGS.len()) * 8).unwrap_or(i64::MAX),
                    }
                }
            }
        }
    }

    fn return_location(&self, kind: ParamKind) -> ArgLocation {
        match kind {
            ParamKind::Float32 | ParamKind::Float64 | ParamKind::Vec128 => {
                ArgLocation::Register("xmm0".into())
            }
            _ => ArgLocation::Register("rax".into()),
        }
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &SYSV_CALLEE_SAVED
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &SYSV_CALLER_SAVED
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Microsoft x64 — Windows x86-64
// ─────────────────────────────────────────────────────────────────────────────

/// Microsoft x64 calling convention — used on Windows.
///
/// Integer/pointer arguments: rcx, rdx, r8, r9 (then stack).
/// FP arguments: xmm0–xmm3.
/// Return: rax (integer), xmm0 (float).
/// Callee-saved: rbx, rbp, rdi, rsi, r12–r15, xmm6–xmm15.
/// Shadow space: 32 bytes (4 slots of 8 bytes each).
#[derive(Debug, Clone)]
pub struct MsX64;

const MS_INT_ARG_REGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
const MS_FP_ARG_REGS: [&str; 4] = ["xmm0", "xmm1", "xmm2", "xmm3"];
const MS_CALLEE_SAVED: [&str; 13] = [
    "rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
];
const MS_CALLER_SAVED: [&str; 7] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

impl CallingConvention for MsX64 {
    fn name(&self) -> &'static str {
        "ms_x64"
    }
    fn description(&self) -> &'static str {
        "Microsoft x64 calling convention (Windows)"
    }

    fn arg_location(&self, n: usize, kind: ParamKind) -> ArgLocation {
        // On Windows, the first 4 args use either INT or XMM depending on type,
        // and the slot position is shared (arg 0 is always slot 0 regardless of type).
        let int_reg = if n < MS_INT_ARG_REGS.len() {
            Some(MS_INT_ARG_REGS[n])
        } else {
            None
        };
        let fp_reg = if n < MS_FP_ARG_REGS.len() {
            Some(MS_FP_ARG_REGS[n])
        } else {
            None
        };
        match kind {
            ParamKind::Float32 | ParamKind::Float64 | ParamKind::Vec128 => fp_reg
                .map_or_else(|| ArgLocation::Stack {
                    offset_bytes: i64::try_from(n * 8 + 32).unwrap_or(i64::MAX),
                }, |r| ArgLocation::Register(r.into())),
            _ => int_reg
                .map_or_else(|| ArgLocation::Stack {
                    offset_bytes: i64::try_from(n * 8 + 32).unwrap_or(i64::MAX),
                }, |r| ArgLocation::Register(r.into())),
        }
    }

    fn return_location(&self, kind: ParamKind) -> ArgLocation {
        match kind {
            ParamKind::Float32 | ParamKind::Float64 | ParamKind::Vec128 => {
                ArgLocation::Register("xmm0".into())
            }
            _ => ArgLocation::Register("rax".into()),
        }
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &MS_CALLEE_SAVED
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &MS_CALLER_SAVED
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn shadow_space_bytes(&self) -> u32 {
        32
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// cdecl — 32-bit Linux / GCC
// ─────────────────────────────────────────────────────────────────────────────

/// `cdecl` — all arguments on the stack, caller cleans, 32-bit.
#[derive(Debug, Clone)]
pub struct Cdecl;

const CDECL_CALLEE_SAVED: [&str; 4] = ["ebx", "ebp", "esi", "edi"];
const CDECL_CALLER_SAVED: [&str; 3] = ["eax", "ecx", "edx"];

impl CallingConvention for Cdecl {
    fn name(&self) -> &'static str {
        "cdecl"
    }
    fn description(&self) -> &'static str {
        "C declaration calling convention (32-bit)"
    }

    fn arg_location(&self, n: usize, _kind: ParamKind) -> ArgLocation {
        // cdecl: all args pushed right-to-left; at call boundary
        // arg 0 is at [esp+4], arg 1 at [esp+8], etc.
        ArgLocation::Stack {
            offset_bytes: i64::try_from((n + 1) * 4).unwrap_or(i64::MAX),
        }
    }

    fn return_location(&self, kind: ParamKind) -> ArgLocation {
        match kind {
            ParamKind::Float32 | ParamKind::Float64 => ArgLocation::Register("st0".into()),
            _ => ArgLocation::Register("eax".into()),
        }
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &CDECL_CALLEE_SAVED
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &CDECL_CALLER_SAVED
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn stack_alignment_bytes(&self) -> u32 {
        4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stdcall — 32-bit Windows
// ─────────────────────────────────────────────────────────────────────────────

/// `stdcall` — same as `cdecl` except the callee cleans the stack.
/// Used for most Win32 API functions.
#[derive(Debug, Clone)]
pub struct Stdcall;

impl CallingConvention for Stdcall {
    fn name(&self) -> &'static str {
        "stdcall"
    }
    fn description(&self) -> &'static str {
        "Standard call convention (Win32 API)"
    }

    fn arg_location(&self, n: usize, _kind: ParamKind) -> ArgLocation {
        ArgLocation::Stack {
            offset_bytes: i64::try_from((n + 1) * 4).unwrap_or(i64::MAX),
        }
    }

    fn return_location(&self, kind: ParamKind) -> ArgLocation {
        match kind {
            ParamKind::Float32 | ParamKind::Float64 => ArgLocation::Register("st0".into()),
            _ => ArgLocation::Register("eax".into()),
        }
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &CDECL_CALLEE_SAVED
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &CDECL_CALLER_SAVED
    }
    fn callee_cleans_stack(&self) -> bool {
        true
    }
    fn stack_alignment_bytes(&self) -> u32 {
        4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fastcall — 32-bit MSVC
// ─────────────────────────────────────────────────────────────────────────────

/// `__fastcall` — first two integer args in ecx/edx, rest on stack.
#[derive(Debug, Clone)]
pub struct Fastcall;

const FAST_INT_ARG_REGS: [&str; 2] = ["ecx", "edx"];

impl CallingConvention for Fastcall {
    fn name(&self) -> &'static str {
        "fastcall"
    }
    fn description(&self) -> &'static str {
        "__fastcall (MSVC 32-bit)"
    }

    fn arg_location(&self, n: usize, _kind: ParamKind) -> ArgLocation {
        if n < FAST_INT_ARG_REGS.len() {
            ArgLocation::Register(FAST_INT_ARG_REGS[n].into())
        } else {
            ArgLocation::Stack {
                offset_bytes: i64::try_from((n - 2 + 1) * 4).unwrap_or(i64::MAX),
            }
        }
    }

    fn return_location(&self, _kind: ParamKind) -> ArgLocation {
        ArgLocation::Register("eax".into())
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &CDECL_CALLEE_SAVED
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &CDECL_CALLER_SAVED
    }
    fn callee_cleans_stack(&self) -> bool {
        true
    }
    fn stack_alignment_bytes(&self) -> u32 {
        4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux x86-64 syscall ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Linux x86-64 syscall ABI — used when `SYSCALL` is the mechanism.
/// Syscall number in rax; args in rdi, rsi, rdx, r10, r8, r9.
/// Return value in rax; registers rcx and r11 are clobbered by the kernel.
#[derive(Debug, Clone)]
pub struct LinuxSyscallAmd64;

const SYSCALL_ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

impl CallingConvention for LinuxSyscallAmd64 {
    fn name(&self) -> &'static str {
        "linux_syscall_amd64"
    }
    fn description(&self) -> &'static str {
        "Linux x86-64 syscall ABI"
    }

    fn arg_location(&self, n: usize, _kind: ParamKind) -> ArgLocation {
        if n < SYSCALL_ARG_REGS.len() {
            ArgLocation::Register(SYSCALL_ARG_REGS[n].into())
        } else {
            ArgLocation::Unknown
        }
    }

    fn return_location(&self, _kind: ParamKind) -> ArgLocation {
        ArgLocation::Register("rax".into())
    }

    fn callee_saved_regs(&self) -> &[&str] {
        &[]
    }
    fn caller_saved_regs(&self) -> &[&str] {
        &[]
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn supports_varargs(&self) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry of named calling conventions.
///
/// Call `register_defaults()` to populate with all built-in conventions,
/// then look up by name.
#[derive(Debug, Default)]
pub struct CallingConventionRegistry {
    conventions: HashMap<String, Box<dyn CallingConvention>>,
}

impl CallingConventionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with all built-in conventions.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register_defaults();
        r
    }

    /// Register a custom calling convention.
    pub fn register(&mut self, cc: Box<dyn CallingConvention>) {
        self.conventions.insert(cc.name().to_string(), cc);
    }

    /// Register all built-in conventions.
    pub fn register_defaults(&mut self) {
        self.register(Box::new(SysVAmd64));
        self.register(Box::new(MsX64));
        self.register(Box::new(Cdecl));
        self.register(Box::new(Stdcall));
        self.register(Box::new(Fastcall));
        self.register(Box::new(LinuxSyscallAmd64));
    }

    /// Look up a convention by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn CallingConvention> {
        self.conventions.get(name).map(std::convert::AsRef::as_ref)
    }

    /// All registered names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.conventions.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Guess the calling convention from a binary target descriptor.
    #[must_use]
    pub const fn guess_from_target(bits: u8, is_windows: bool) -> &'static str {
        match (bits, is_windows) {
            (64, false) => "sysv_amd64",
            (64, true) => "ms_x64",
            (32, true) => "stdcall",
            _ => "cdecl",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysv_first_int_arg_in_rdi() {
        let cc = SysVAmd64;
        assert_eq!(
            cc.arg_location(0, ParamKind::IntOrPtr),
            ArgLocation::Register("rdi".into())
        );
    }

    #[test]
    fn sysv_seventh_int_arg_on_stack() {
        let cc = SysVAmd64;
        assert!(matches!(
            cc.arg_location(6, ParamKind::IntOrPtr),
            ArgLocation::Stack { .. }
        ));
    }

    #[test]
    fn sysv_float_arg_in_xmm0() {
        let cc = SysVAmd64;
        assert_eq!(
            cc.arg_location(0, ParamKind::Float64),
            ArgLocation::Register("xmm0".into())
        );
    }

    #[test]
    fn sysv_return_int_in_rax() {
        let cc = SysVAmd64;
        assert_eq!(
            cc.return_location(ParamKind::IntOrPtr),
            ArgLocation::Register("rax".into())
        );
    }

    #[test]
    fn sysv_return_float_in_xmm0() {
        let cc = SysVAmd64;
        assert_eq!(
            cc.return_location(ParamKind::Float64),
            ArgLocation::Register("xmm0".into())
        );
    }

    #[test]
    fn sysv_does_not_clean_stack() {
        assert!(!SysVAmd64.callee_cleans_stack());
    }

    #[test]
    fn sysv_no_shadow_space() {
        assert_eq!(SysVAmd64.shadow_space_bytes(), 0);
    }

    #[test]
    fn ms_x64_first_int_arg_rcx() {
        let cc = MsX64;
        assert_eq!(
            cc.arg_location(0, ParamKind::IntOrPtr),
            ArgLocation::Register("rcx".into())
        );
    }

    #[test]
    fn ms_x64_shadow_space_32() {
        assert_eq!(MsX64.shadow_space_bytes(), 32);
    }

    #[test]
    fn ms_x64_fifth_arg_on_stack() {
        let cc = MsX64;
        assert!(matches!(
            cc.arg_location(4, ParamKind::IntOrPtr),
            ArgLocation::Stack { .. }
        ));
    }

    #[test]
    fn cdecl_all_args_on_stack() {
        let cc = Cdecl;
        for i in 0..5 {
            assert!(matches!(
                cc.arg_location(i, ParamKind::IntOrPtr),
                ArgLocation::Stack { .. }
            ));
        }
    }

    #[test]
    fn stdcall_callee_cleans() {
        assert!(Stdcall.callee_cleans_stack());
    }

    #[test]
    fn fastcall_first_two_in_regs() {
        let cc = Fastcall;
        assert_eq!(
            cc.arg_location(0, ParamKind::IntOrPtr),
            ArgLocation::Register("ecx".into())
        );
        assert_eq!(
            cc.arg_location(1, ParamKind::IntOrPtr),
            ArgLocation::Register("edx".into())
        );
    }

    #[test]
    fn fastcall_third_on_stack() {
        let cc = Fastcall;
        assert!(matches!(
            cc.arg_location(2, ParamKind::IntOrPtr),
            ArgLocation::Stack { .. }
        ));
    }

    #[test]
    fn linux_syscall_arg0_in_rdi() {
        let cc = LinuxSyscallAmd64;
        assert_eq!(
            cc.arg_location(0, ParamKind::IntOrPtr),
            ArgLocation::Register("rdi".into())
        );
    }

    #[test]
    fn linux_syscall_arg3_in_r10() {
        let cc = LinuxSyscallAmd64;
        assert_eq!(
            cc.arg_location(3, ParamKind::IntOrPtr),
            ArgLocation::Register("r10".into())
        );
    }

    #[test]
    fn registry_with_defaults_has_all() {
        let r = CallingConventionRegistry::with_defaults();
        for name in [
            "sysv_amd64",
            "ms_x64",
            "cdecl",
            "stdcall",
            "fastcall",
            "linux_syscall_amd64",
        ] {
            assert!(r.get(name).is_some(), "missing convention: {name}");
        }
    }

    #[test]
    fn registry_lookup_by_name() {
        let r = CallingConventionRegistry::with_defaults();
        let cc = r.get("sysv_amd64").unwrap();
        assert_eq!(cc.name(), "sysv_amd64");
    }

    #[test]
    fn guess_convention_linux_64() {
        assert_eq!(
            CallingConventionRegistry::guess_from_target(64, false),
            "sysv_amd64"
        );
    }

    #[test]
    fn guess_convention_windows_64() {
        assert_eq!(
            CallingConventionRegistry::guess_from_target(64, true),
            "ms_x64"
        );
    }

    #[test]
    fn guess_convention_windows_32() {
        assert_eq!(
            CallingConventionRegistry::guess_from_target(32, true),
            "stdcall"
        );
    }

    #[test]
    fn arg_location_display() {
        assert_eq!(format!("{}", ArgLocation::Register("rax".into())), "rax");
        assert_eq!(
            format!("{}", ArgLocation::Stack { offset_bytes: 8 }),
            "[rsp+8]"
        );
        assert_eq!(format!("{}", ArgLocation::Unknown), "?");
    }
}
