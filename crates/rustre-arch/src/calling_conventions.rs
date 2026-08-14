//! `calling_conventions` — Calling convention database.
//!
//! Defines parameter-passing rules, return-value conventions, callee/caller-saved
//! register sets, and stack alignment requirements for:
//!
//! * x86: cdecl, stdcall, fastcall, thiscall, vectorcall
//! * x86-64: System V AMD64 ABI, Microsoft Win64
//! * ARM 32-bit: AAPCS (Procedure Call Standard)
//! * ARM 64-bit: AAPCS64
//!
//! Each convention is described by a `CallingConvention` value that can be
//! inspected at runtime without depending on any arch backend.

use std::collections::HashMap;
use std::fmt;

// ─── ParamLocation ────────────────────────────────────────────────────────────

/// Where a single function parameter is placed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParamLocation {
    /// Passed in a named register.
    Register(String),
    /// Passed on the stack at a given byte offset from the stack pointer
    /// (positive = toward lower addresses on most ABIs).
    Stack(i32),
    /// Passed as a pointer to a caller-allocated copy (by-reference ABI).
    ByRef { reg_or_stack: Box<Self> },
}

impl fmt::Display for ParamLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::Stack(off) => write!(f, "stack+{off}"),
            Self::ByRef { reg_or_stack } => write!(f, "&({reg_or_stack})"),
        }
    }
}

// ─── RegisterParam ────────────────────────────────────────────────────────────

/// A single register used for parameter passing, with type context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterParam {
    /// Register name (e.g. `"rdi"`, `"xmm0"`, `"r0"`).
    pub reg: String,
    /// Zero-based parameter index (first integer arg = 0).
    pub index: usize,
    /// Whether this register is for floating-point / SIMD arguments.
    pub is_float: bool,
}

impl RegisterParam {
    /// Create an integer register parameter.
    #[must_use]
    pub fn integer(reg: impl Into<String>, index: usize) -> Self {
        Self {
            reg: reg.into(),
            index,
            is_float: false,
        }
    }

    /// Create a floating-point register parameter.
    #[must_use]
    pub fn float(reg: impl Into<String>, index: usize) -> Self {
        Self {
            reg: reg.into(),
            index,
            is_float: true,
        }
    }
}

// ─── StackParam ───────────────────────────────────────────────────────────────

/// A parameter passed on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackParam {
    /// Zero-based parameter index.
    pub index: usize,
    /// Byte offset from the stack pointer at the call site (positive = above SP).
    pub sp_offset: i32,
    /// Size in bytes.
    pub size: u32,
    /// Whether the parameter is right-to-left (typical for C calling conventions).
    pub right_to_left: bool,
}

impl StackParam {
    /// Create a stack parameter.
    #[must_use]
    pub const fn new(index: usize, sp_offset: i32, size: u32, right_to_left: bool) -> Self {
        Self {
            index,
            sp_offset,
            size,
            right_to_left,
        }
    }
}

// ─── ReturnConvention ─────────────────────────────────────────────────────────

/// How return values are passed back to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnConvention {
    /// Returned in a single integer/pointer register.
    Register(String),
    /// Returned in two registers (e.g., RAX:RDX for 128-bit values).
    RegisterPair(String, String),
    /// Returned in a floating-point register.
    FloatRegister(String),
    /// Returned via a hidden pointer parameter (caller allocates, pointer in
    /// the first argument register or a dedicated register like RCX on Win64).
    HiddenPointer { ptr_reg: String },
    /// Returned on the floating-point stack (x87).
    FloatStack,
    /// Void function — no return value.
    Void,
}

impl fmt::Display for ReturnConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::RegisterPair(a, b) => write!(f, "pair:{a}:{b}"),
            Self::FloatRegister(r) => write!(f, "fpreg:{r}"),
            Self::HiddenPointer { ptr_reg } => write!(f, "hidden_ptr:{ptr_reg}"),
            Self::FloatStack => write!(f, "fpu_stack"),
            Self::Void => write!(f, "void"),
        }
    }
}

// ─── StackCleanup ─────────────────────────────────────────────────────────────

/// Who is responsible for cleaning up (removing) stack arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackCleanup {
    /// The caller cleans up the stack (e.g., `cdecl`).
    Caller,
    /// The callee cleans up the stack (e.g., `stdcall`, `thiscall`).
    Callee,
}

impl fmt::Display for StackCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller => write!(f, "caller"),
            Self::Callee => write!(f, "callee"),
        }
    }
}

// ─── CallingConvention ────────────────────────────────────────────────────────

/// A fully described calling convention.
#[derive(Debug, Clone)]
pub struct CallingConvention {
    /// Canonical name (e.g. `"cdecl"`, `"sysv_amd64"`, `"win64"`).
    pub name: String,
    /// Architecture this convention targets.
    pub arch: String,
    /// Integer/pointer argument registers in order.
    pub int_arg_regs: Vec<String>,
    /// Float/SIMD argument registers in order.
    pub float_arg_regs: Vec<String>,
    /// Return value convention for integer/pointer returns.
    pub int_return: ReturnConvention,
    /// Return value convention for floating-point returns.
    pub float_return: ReturnConvention,
    /// Registers preserved (callee-saved) across a call.
    pub callee_saved: Vec<String>,
    /// Registers that may be clobbered (caller-saved) across a call.
    pub caller_saved: Vec<String>,
    /// Who cleans the stack.
    pub stack_cleanup: StackCleanup,
    /// Required stack alignment in bytes at the point of a `call` instruction.
    pub stack_alignment: u32,
    /// Size of the shadow/home space allocated by the caller (e.g., 32 bytes
    /// on Win64), in bytes.
    pub shadow_space: u32,
    /// Whether a `this` pointer is passed in a dedicated register.
    pub this_reg: Option<String>,
    /// Whether varargs (variadic) arguments are supported.
    pub supports_varargs: bool,
    /// Additional key-value notes.
    pub notes: HashMap<String, String>,
}

impl CallingConvention {
    /// Create a new convention with sensible defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arch: arch.into(),
            int_arg_regs: Vec::new(),
            float_arg_regs: Vec::new(),
            int_return: ReturnConvention::Void,
            float_return: ReturnConvention::Void,
            callee_saved: Vec::new(),
            caller_saved: Vec::new(),
            stack_cleanup: StackCleanup::Caller,
            stack_alignment: 16,
            shadow_space: 0,
            this_reg: None,
            supports_varargs: false,
            notes: HashMap::new(),
        }
    }

    /// Return the maximum number of integer arguments passed in registers.
    #[must_use]
    pub const fn max_int_reg_args(&self) -> usize {
        self.int_arg_regs.len()
    }

    /// Return the maximum number of float arguments passed in registers.
    #[must_use]
    pub const fn max_float_reg_args(&self) -> usize {
        self.float_arg_regs.len()
    }

    /// Return `true` if the given register is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg)
    }

    /// Return `true` if the given register is caller-saved.
    #[must_use]
    pub fn is_caller_saved(&self, reg: &str) -> bool {
        self.caller_saved.iter().any(|r| r == reg)
    }

    /// Compute the location of the nth integer argument (0-indexed).
    ///
    /// Returns `Some(ParamLocation::Register(_))` for the first N register
    /// arguments and `Some(ParamLocation::Stack(_))` for spill arguments.
    /// The stack offset is computed assuming `ptr_size`-byte slots.
    #[must_use]
    pub fn int_arg_location(&self, index: usize, ptr_size: u32) -> ParamLocation {
        if index < self.int_arg_regs.len() {
            ParamLocation::Register(self.int_arg_regs[index].clone())
        } else {
            let spill = index - self.int_arg_regs.len();
            ParamLocation::Stack(
                i32::try_from(spill * ptr_size as usize).unwrap_or(i32::MAX),
            )
        }
    }

    /// Compute the location of the nth float argument (0-indexed).
    #[must_use]
    pub fn float_arg_location(&self, index: usize, ptr_size: u32) -> ParamLocation {
        if index < self.float_arg_regs.len() {
            ParamLocation::Register(self.float_arg_regs[index].clone())
        } else {
            let spill = index - self.float_arg_regs.len();
            ParamLocation::Stack(
                i32::try_from(spill * ptr_size as usize).unwrap_or(i32::MAX),
            )
        }
    }

    /// Add a note.
    pub fn add_note(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.notes.insert(key.into(), value.into());
    }
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CC({}/{}, int_args={}, float_args={}, callee_saved={}, cleanup={})",
            self.name,
            self.arch,
            self.int_arg_regs.len(),
            self.float_arg_regs.len(),
            self.callee_saved.len(),
            self.stack_cleanup,
        )
    }
}

// ─── Convention constructors ──────────────────────────────────────────────────

/// Return the `cdecl` 32-bit x86 calling convention.
#[must_use]
pub fn cdecl() -> CallingConvention {
    let mut cc = CallingConvention::new("cdecl", "x86");
    cc.int_arg_regs = Vec::new(); // all on stack
    cc.int_return = ReturnConvention::Register("eax".into());
    cc.float_return = ReturnConvention::FloatStack;
    cc.callee_saved = vec![
        "ebx".into(),
        "esi".into(),
        "edi".into(),
        "ebp".into(),
        "esp".into(),
    ];
    cc.caller_saved = vec!["eax".into(), "ecx".into(), "edx".into()];
    cc.stack_cleanup = StackCleanup::Caller;
    cc.stack_alignment = 4;
    cc.supports_varargs = true;
    cc
}

/// Return the `stdcall` 32-bit x86 calling convention.
#[must_use]
pub fn stdcall() -> CallingConvention {
    let mut cc = cdecl();
    cc.name = "stdcall".into();
    cc.stack_cleanup = StackCleanup::Callee;
    cc.supports_varargs = false;
    cc
}

/// Return the `fastcall` 32-bit x86 calling convention (Microsoft).
///
/// First two integer arguments in ECX and EDX; rest on stack.
#[must_use]
pub fn fastcall() -> CallingConvention {
    let mut cc = CallingConvention::new("fastcall", "x86");
    cc.int_arg_regs = vec!["ecx".into(), "edx".into()];
    cc.int_return = ReturnConvention::Register("eax".into());
    cc.float_return = ReturnConvention::FloatStack;
    cc.callee_saved = vec![
        "ebx".into(),
        "esi".into(),
        "edi".into(),
        "ebp".into(),
        "esp".into(),
    ];
    cc.caller_saved = vec!["eax".into(), "ecx".into(), "edx".into()];
    cc.stack_cleanup = StackCleanup::Callee;
    cc.stack_alignment = 4;
    cc
}

/// Return the `thiscall` 32-bit x86 calling convention (MSVC C++ member functions).
///
/// `this` pointer in ECX; all other args on stack.
#[must_use]
pub fn thiscall() -> CallingConvention {
    let mut cc = CallingConvention::new("thiscall", "x86");
    cc.int_arg_regs = vec!["ecx".into()];
    cc.this_reg = Some("ecx".into());
    cc.int_return = ReturnConvention::Register("eax".into());
    cc.float_return = ReturnConvention::FloatStack;
    cc.callee_saved = vec![
        "ebx".into(),
        "esi".into(),
        "edi".into(),
        "ebp".into(),
        "esp".into(),
    ];
    cc.caller_saved = vec!["eax".into(), "edx".into()];
    cc.stack_cleanup = StackCleanup::Callee;
    cc.stack_alignment = 4;
    cc
}

/// Return the `vectorcall` 32-bit x86 calling convention (MSVC /arch:AVX).
///
/// Integer args in ECX, EDX; first 6 float/vector args in XMM0–XMM5.
#[must_use]
pub fn vectorcall_x86() -> CallingConvention {
    let mut cc = CallingConvention::new("vectorcall_x86", "x86");
    cc.int_arg_regs = vec!["ecx".into(), "edx".into()];
    cc.float_arg_regs = (0..6).map(|i| format!("xmm{i}")).collect();
    cc.int_return = ReturnConvention::Register("eax".into());
    cc.float_return = ReturnConvention::FloatRegister("xmm0".into());
    cc.callee_saved = vec![
        "ebx".into(),
        "esi".into(),
        "edi".into(),
        "ebp".into(),
        "esp".into(),
    ];
    cc.caller_saved = vec!["eax".into(), "ecx".into(), "edx".into()];
    cc.stack_cleanup = StackCleanup::Callee;
    cc.stack_alignment = 4;
    cc
}

/// Return the System V AMD64 ABI (Linux / macOS / BSDs).
#[must_use]
pub fn sysv_amd64() -> CallingConvention {
    let mut cc = CallingConvention::new("sysv_amd64", "x86_64");
    cc.int_arg_regs = vec![
        "rdi".into(),
        "rsi".into(),
        "rdx".into(),
        "rcx".into(),
        "r8".into(),
        "r9".into(),
    ];
    cc.float_arg_regs = (0..8).map(|i| format!("xmm{i}")).collect();
    cc.int_return = ReturnConvention::RegisterPair("rax".into(), "rdx".into());
    cc.float_return = ReturnConvention::FloatRegister("xmm0".into());
    cc.callee_saved = vec![
        "rbx".into(),
        "rbp".into(),
        "r12".into(),
        "r13".into(),
        "r14".into(),
        "r15".into(),
        "rsp".into(),
    ];
    cc.caller_saved = vec![
        "rax".into(),
        "rcx".into(),
        "rdx".into(),
        "rsi".into(),
        "rdi".into(),
        "r8".into(),
        "r9".into(),
        "r10".into(),
        "r11".into(),
    ];
    cc.stack_cleanup = StackCleanup::Caller;
    cc.stack_alignment = 16;
    cc.supports_varargs = true;
    let mut note = String::new();
    note.push_str("128-byte red zone below RSP");
    cc.add_note("red_zone", note);
    cc
}

/// Return the Microsoft x64 (Win64) calling convention.
#[must_use]
pub fn win64() -> CallingConvention {
    let mut cc = CallingConvention::new("win64", "x86_64");
    cc.int_arg_regs = vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()];
    cc.float_arg_regs = (0..4).map(|i| format!("xmm{i}")).collect();
    cc.int_return = ReturnConvention::Register("rax".into());
    cc.float_return = ReturnConvention::FloatRegister("xmm0".into());
    cc.callee_saved = vec![
        "rbx".into(),
        "rbp".into(),
        "rdi".into(),
        "rsi".into(),
        "r12".into(),
        "r13".into(),
        "r14".into(),
        "r15".into(),
        "xmm6".into(),
        "xmm7".into(),
        "xmm8".into(),
        "xmm9".into(),
        "xmm10".into(),
        "xmm11".into(),
        "xmm12".into(),
        "xmm13".into(),
        "xmm14".into(),
        "xmm15".into(),
    ];
    cc.caller_saved = vec![
        "rax".into(),
        "rcx".into(),
        "rdx".into(),
        "r8".into(),
        "r9".into(),
        "r10".into(),
        "r11".into(),
    ];
    cc.stack_cleanup = StackCleanup::Caller;
    cc.stack_alignment = 16;
    cc.shadow_space = 32;
    cc.supports_varargs = true;
    cc
}

/// Return the ARM AAPCS (32-bit) calling convention.
#[must_use]
pub fn aapcs32() -> CallingConvention {
    let mut cc = CallingConvention::new("aapcs32", "arm");
    cc.int_arg_regs = vec!["r0".into(), "r1".into(), "r2".into(), "r3".into()];
    cc.float_arg_regs = (0..8).map(|i| format!("s{i}")).collect();
    cc.int_return = ReturnConvention::RegisterPair("r0".into(), "r1".into());
    cc.float_return = ReturnConvention::FloatRegister("s0".into());
    cc.callee_saved = vec![
        "r4".into(),
        "r5".into(),
        "r6".into(),
        "r7".into(),
        "r8".into(),
        "r9".into(),
        "r10".into(),
        "r11".into(),
        "r12".into(), // IP (scratch in some usages)
        "r13".into(), // SP
        "r14".into(), // LR
    ];
    cc.caller_saved = vec!["r0".into(), "r1".into(), "r2".into(), "r3".into()];
    cc.stack_cleanup = StackCleanup::Caller;
    cc.stack_alignment = 8;
    cc.supports_varargs = true;
    cc
}

/// Return the ARM AAPCS64 calling convention.
#[must_use]
pub fn aapcs64() -> CallingConvention {
    let mut cc = CallingConvention::new("aapcs64", "arm64");
    cc.int_arg_regs = (0..8).map(|i| format!("x{i}")).collect();
    cc.float_arg_regs = (0..8).map(|i| format!("v{i}")).collect();
    cc.int_return = ReturnConvention::RegisterPair("x0".into(), "x1".into());
    cc.float_return = ReturnConvention::FloatRegister("v0".into());
    cc.callee_saved = {
        let mut saved: Vec<String> = (19..=28).map(|i| format!("x{i}")).collect();
        saved.push("x29".into()); // FP
        saved.push("x30".into()); // LR
        saved.extend((8..=15).map(|i| format!("v{i}")));
        saved
    };
    cc.caller_saved = {
        let mut clobbered: Vec<String> = (0..=17).map(|i| format!("x{i}")).collect();
        clobbered.push("x18".into()); // Platform register
        clobbered.extend((0..=7).map(|i| format!("v{i}")));
        clobbered.extend((16..=31).map(|i| format!("v{i}")));
        clobbered
    };
    cc.stack_cleanup = StackCleanup::Caller;
    cc.stack_alignment = 16;
    cc.supports_varargs = true;
    cc
}

// ─── ConventionRegistry ───────────────────────────────────────────────────────

/// Registry of calling conventions indexed by name.
#[derive(Debug, Default)]
pub struct ConventionRegistry {
    by_name: HashMap<String, CallingConvention>,
}

impl ConventionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with all built-in conventions.
    #[must_use]
    pub fn builtin() -> Self {
        let mut r = Self::new();
        r.register(cdecl());
        r.register(stdcall());
        r.register(fastcall());
        r.register(thiscall());
        r.register(vectorcall_x86());
        r.register(sysv_amd64());
        r.register(win64());
        r.register(aapcs32());
        r.register(aapcs64());
        r
    }

    /// Register a convention.
    pub fn register(&mut self, cc: CallingConvention) {
        self.by_name.insert(cc.name.clone(), cc);
    }

    /// Look up a convention by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CallingConvention> {
        self.by_name.get(name)
    }

    /// Return all registered convention names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.by_name.keys().map(String::as_str).collect()
    }

    /// Return all conventions for a given architecture.
    #[must_use]
    pub fn for_arch(&self, arch: &str) -> Vec<&CallingConvention> {
        self.by_name
            .values()
            .filter(|cc| cc.arch == arch)
            .collect()
    }

    /// Number of registered conventions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Return `true` if no conventions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdecl_properties() {
        let cc = cdecl();
        assert_eq!(cc.name, "cdecl");
        assert_eq!(cc.arch, "x86");
        assert_eq!(cc.stack_cleanup, StackCleanup::Caller);
        assert!(cc.int_arg_regs.is_empty());
        assert!(cc.supports_varargs);
        assert!(cc.is_callee_saved("ebx"));
        assert!(!cc.is_callee_saved("eax"));
    }

    #[test]
    fn test_stdcall_callee_cleanup() {
        let cc = stdcall();
        assert_eq!(cc.stack_cleanup, StackCleanup::Callee);
        assert!(!cc.supports_varargs);
    }

    #[test]
    fn test_fastcall_reg_args() {
        let cc = fastcall();
        assert_eq!(cc.int_arg_regs[0], "ecx");
        assert_eq!(cc.int_arg_regs[1], "edx");
        assert_eq!(cc.max_int_reg_args(), 2);
    }

    #[test]
    fn test_thiscall_this_reg() {
        let cc = thiscall();
        assert_eq!(cc.this_reg.as_deref(), Some("ecx"));
    }

    #[test]
    fn test_sysv_amd64_six_int_regs() {
        let cc = sysv_amd64();
        assert_eq!(cc.int_arg_regs.len(), 6);
        assert_eq!(cc.int_arg_regs[0], "rdi");
        assert_eq!(cc.float_arg_regs.len(), 8);
        assert!(cc.is_callee_saved("rbx"));
        assert!(cc.is_callee_saved("r15"));
        assert!(!cc.is_callee_saved("rdi"));
    }

    #[test]
    fn test_win64_shadow_space() {
        let cc = win64();
        assert_eq!(cc.shadow_space, 32);
        assert_eq!(cc.int_arg_regs.len(), 4);
        assert_eq!(cc.int_arg_regs[0], "rcx");
        assert!(cc.is_callee_saved("rdi"));
        assert!(cc.is_callee_saved("xmm6"));
    }

    #[test]
    fn test_aapcs64_int_arg_count() {
        let cc = aapcs64();
        assert_eq!(cc.int_arg_regs.len(), 8);
        assert_eq!(cc.float_arg_regs.len(), 8);
        assert!(cc.is_callee_saved("x19"));
        assert!(cc.is_callee_saved("x29"));
    }

    #[test]
    fn test_aapcs32_int_arg_count() {
        let cc = aapcs32();
        assert_eq!(cc.int_arg_regs.len(), 4);
        assert_eq!(cc.stack_alignment, 8);
    }

    #[test]
    fn test_param_location_register() {
        let cc = sysv_amd64();
        let loc = cc.int_arg_location(0, 8);
        assert_eq!(loc, ParamLocation::Register("rdi".into()));
    }

    #[test]
    fn test_param_location_stack_spill() {
        let cc = sysv_amd64();
        // 7th integer arg (index 6) spills to stack.
        let loc = cc.int_arg_location(6, 8);
        assert_eq!(loc, ParamLocation::Stack(0));
        let loc2 = cc.int_arg_location(7, 8);
        assert_eq!(loc2, ParamLocation::Stack(8));
    }

    #[test]
    fn test_registry_builtin_count() {
        let r = ConventionRegistry::builtin();
        assert!(r.len() >= 9);
    }

    #[test]
    fn test_registry_for_arch() {
        let r = ConventionRegistry::builtin();
        let x86 = r.for_arch("x86");
        assert!(!x86.is_empty());
        let x64 = r.for_arch("x86_64");
        assert!(!x64.is_empty());
    }

    #[test]
    fn test_registry_get() {
        let r = ConventionRegistry::builtin();
        assert!(r.get("cdecl").is_some());
        assert!(r.get("win64").is_some());
        assert!(r.get("not_a_cc").is_none());
    }

    #[test]
    fn test_param_location_display() {
        let loc = ParamLocation::Register("rdi".into());
        assert!(format!("{loc}").contains("rdi"));
        let loc2 = ParamLocation::Stack(16);
        assert!(format!("{loc2}").contains("16"));
    }

    #[test]
    fn test_return_convention_display() {
        assert!(ReturnConvention::Register("rax".into())
            .to_string()
            .contains("rax"));
        assert!(ReturnConvention::Void.to_string().contains("void"));
        assert!(ReturnConvention::FloatStack.to_string().contains("fpu"));
    }

    #[test]
    fn test_calling_convention_display() {
        let cc = sysv_amd64();
        let s = format!("{cc}");
        assert!(s.contains("sysv_amd64"));
    }
}
