//! M68K calling convention models.
//!
//! Covers the most common 68000-family calling conventions:
//!
//! - [`M68kCc::Motorola`]  — The standard Motorola System V 68k ABI
//! - [`M68kCc::AmigaOs`]   — `AmigaOS` register-passing convention
//! - [`M68kCc::Mac`]       — Classic Macintosh convention (Pascal-like stack)
//! - [`M68kCc::Gcc`]       — GCC 68k default (similar to `SysV` but with cdecl details)
//! - [`M68kCc::Custom`]    — Fully user-specified
//!
//! [`M68kCallingConvention`] describes where arguments and return values
//! live, which registers must be preserved, and how the stack is cleaned up.

use std::collections::HashMap;
use std::fmt;

use super::m68k_register_analyzer::M68kReg;

// ─────────────────────────────────────────────────────────────────────────────
// ArgLocation / ReturnLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Where a single argument resides when a function is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgLocation {
    /// Argument is in a data register.
    DataReg(M68kReg),
    /// Argument is in an address register.
    AddrReg(M68kReg),
    /// Argument is on the stack at `sp + offset` (bytes).
    Stack { offset: i32, size: ArgSize },
    /// Argument is passed via a pointer in an address register.
    PtrInAddrReg(M68kReg),
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataReg(r) | Self::AddrReg(r) => write!(f, "{r}"),
            Self::Stack { offset, size } => write!(f, "sp+{offset} ({size})"),
            Self::PtrInAddrReg(r) => write!(f, "({r})"),
        }
    }
}

/// Size of an argument on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgSize {
    Byte,
    Word,
    Long,
    Quad,
}

impl fmt::Display for ArgSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte => write!(f, ".b"),
            Self::Word => write!(f, ".w"),
            Self::Long => write!(f, ".l"),
            Self::Quad => write!(f, ".q"),
        }
    }
}

impl ArgSize {
    /// Size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Long => 4,
            Self::Quad => 8,
        }
    }
}

/// Where the return value of a function resides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnLocation {
    /// Return value in D0 (integer ≤ 32-bit).
    D0,
    /// 64-bit integer return split across D0:D1 (high:low).
    D0D1,
    /// Pointer return in A0.
    A0,
    /// Caller-allocated buffer; pointer passed in A1 (implicit).
    CallerBuffer,
    /// No return value (void).
    Void,
    /// FP0 on 68881/68882 (floating-point).
    Fp0,
    /// Custom register set.
    Custom(Vec<M68kReg>),
}

impl fmt::Display for ReturnLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::D0 => write!(f, "d0"),
            Self::D0D1 => write!(f, "d0:d1"),
            Self::A0 => write!(f, "a0"),
            Self::CallerBuffer => write!(f, "<caller buffer>"),
            Self::Void => write!(f, "void"),
            Self::Fp0 => write!(f, "fp0"),
            Self::Custom(regs) => {
                let names: Vec<&str> = regs.iter().map(|r| r.name()).collect();
                write!(f, "{}", names.join(":"))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackCleanup
// ─────────────────────────────────────────────────────────────────────────────

/// Who removes stack arguments after the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackCleanup {
    /// Caller pops arguments (C default).
    Caller,
    /// Callee pops arguments (Pascal / stdcall).
    Callee,
    /// No stack arguments.
    NoStack,
}

impl fmt::Display for StackCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller => write!(f, "caller-cleans"),
            Self::Callee => write!(f, "callee-cleans"),
            Self::NoStack => write!(f, "no-stack"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M68kCc (convention identifier)
// ─────────────────────────────────────────────────────────────────────────────

/// The name of a calling convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum M68kCc {
    /// Standard Motorola/SysV 68k ABI.
    Motorola,
    /// `AmigaOS` library-call convention (all args in registers).
    AmigaOs,
    /// Classic Macintosh Pascal-style stack convention.
    Mac,
    /// GCC 68k default (cdecl-like).
    Gcc,
    /// A fully user-defined convention.
    Custom(String),
}

impl fmt::Display for M68kCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Motorola => write!(f, "motorola"),
            Self::AmigaOs  => write!(f, "amigaos"),
            Self::Mac      => write!(f, "mac"),
            Self::Gcc      => write!(f, "gcc"),
            Self::Custom(n) => write!(f, "custom:{n}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M68kCallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Full description of a 68K calling convention.
#[derive(Debug, Clone)]
pub struct M68kCallingConvention {
    /// Which convention this is.
    pub id: M68kCc,
    /// Ordered list of argument locations (first arg first).
    pub arg_locations: Vec<ArgLocation>,
    /// Where the primary return value resides.
    pub return_location: ReturnLocation,
    /// Who cleans up stack arguments.
    pub stack_cleanup: StackCleanup,
    /// Registers that the callee must preserve (callee-saved).
    pub preserved_regs: Vec<M68kReg>,
    /// Registers that the callee may freely clobber (caller-saved).
    pub scratch_regs: Vec<M68kReg>,
    /// Whether the frame pointer (A6) is used.
    pub uses_frame_pointer: bool,
    /// Alignment of the stack pointer on entry to the callee (bytes).
    pub stack_alignment: u32,
    /// Human-readable description.
    pub description: &'static str,
}

impl M68kCallingConvention {
    // ── Predefined conventions ──────────────────────────────────────────────

    /// Standard Motorola/SysV 68K ABI.
    ///
    /// - All args passed on the stack (right-to-left).
    /// - Return value in D0 (32-bit) or D0:D1 (64-bit).
    /// - D0–D1, A0–A1 are scratch.
    /// - D2–D7, A2–A6 must be preserved.
    #[must_use]
    pub fn motorola() -> Self {
        Self {
            id: M68kCc::Motorola,
            arg_locations: vec![
                ArgLocation::Stack { offset: 4, size: ArgSize::Long },
                ArgLocation::Stack { offset: 8, size: ArgSize::Long },
                ArgLocation::Stack { offset: 12, size: ArgSize::Long },
                ArgLocation::Stack { offset: 16, size: ArgSize::Long },
            ],
            return_location: ReturnLocation::D0,
            stack_cleanup: StackCleanup::Caller,
            preserved_regs: vec![
                M68kReg::D2, M68kReg::D3, M68kReg::D4, M68kReg::D5, M68kReg::D6, M68kReg::D7,
                M68kReg::A2, M68kReg::A3, M68kReg::A4, M68kReg::A5, M68kReg::A6,
            ],
            scratch_regs: vec![
                M68kReg::D0, M68kReg::D1, M68kReg::A0, M68kReg::A1,
            ],
            uses_frame_pointer: true,
            stack_alignment: 2,
            description: "Motorola/SysV 68K ABI — stack args, caller cleans",
        }
    }

    /// `AmigaOS` register-passing convention.
    ///
    /// - Up to 8 integer args in D0–D7 (or A0–A6 for pointers).
    /// - Library base in A6.
    /// - Return in D0.
    /// - Only A2–A5 are preserved (A6 is library base, not general).
    #[must_use]
    pub fn amigaos() -> Self {
        Self {
            id: M68kCc::AmigaOs,
            arg_locations: vec![
                ArgLocation::DataReg(M68kReg::D0),
                ArgLocation::DataReg(M68kReg::D1),
                ArgLocation::DataReg(M68kReg::D2),
                ArgLocation::DataReg(M68kReg::D3),
                ArgLocation::DataReg(M68kReg::D4),
                ArgLocation::DataReg(M68kReg::D5),
                ArgLocation::DataReg(M68kReg::D6),
                ArgLocation::DataReg(M68kReg::D7),
                ArgLocation::AddrReg(M68kReg::A0),
                ArgLocation::AddrReg(M68kReg::A1),
                ArgLocation::AddrReg(M68kReg::A2),
                ArgLocation::AddrReg(M68kReg::A3),
                ArgLocation::AddrReg(M68kReg::A4),
                ArgLocation::AddrReg(M68kReg::A5),
            ],
            return_location: ReturnLocation::D0,
            stack_cleanup: StackCleanup::NoStack,
            preserved_regs: vec![M68kReg::A2, M68kReg::A3, M68kReg::A4, M68kReg::A5],
            scratch_regs: vec![
                M68kReg::D0, M68kReg::D1, M68kReg::A0, M68kReg::A1,
            ],
            uses_frame_pointer: false,
            stack_alignment: 2,
            description: "AmigaOS register-based convention (library base in A6)",
        }
    }

    /// Classic Macintosh Pascal-style calling convention.
    ///
    /// - Args pushed left-to-right; callee pops.
    /// - Return value on the stack (pushed by caller before args).
    /// - D3–D7, A2–A4 preserved.
    #[must_use]
    pub fn mac() -> Self {
        Self {
            id: M68kCc::Mac,
            arg_locations: vec![
                // Args are pushed L→R; first arg ends up lowest on the stack after call.
                ArgLocation::Stack { offset: 4, size: ArgSize::Long },
                ArgLocation::Stack { offset: 8, size: ArgSize::Long },
                ArgLocation::Stack { offset: 12, size: ArgSize::Long },
            ],
            return_location: ReturnLocation::D0,
            stack_cleanup: StackCleanup::Callee,
            preserved_regs: vec![
                M68kReg::D3, M68kReg::D4, M68kReg::D5, M68kReg::D6, M68kReg::D7,
                M68kReg::A2, M68kReg::A3, M68kReg::A4,
            ],
            scratch_regs: vec![
                M68kReg::D0, M68kReg::D1, M68kReg::D2, M68kReg::A0, M68kReg::A1,
            ],
            uses_frame_pointer: true,
            stack_alignment: 2,
            description: "Classic Mac OS Pascal-style (callee-cleans, L→R push)",
        }
    }

    /// GCC 68K default (cdecl).
    ///
    /// Functionally identical to the Motorola `SysV` ABI for plain C calls.
    #[must_use]
    pub fn gcc() -> Self {
        let mut cc = Self::motorola();
        cc.id = M68kCc::Gcc;
        cc.description = "GCC 68K default (cdecl, stack args, caller cleans)";
        cc
    }

    // ── Queries ─────────────────────────────────────────────────────────────

    /// Return the location for the `n`th argument (0-indexed).
    ///
    /// Returns `None` if `n >= arg_locations.len()`.
    #[must_use]
    pub fn arg_location(&self, n: usize) -> Option<&ArgLocation> {
        self.arg_locations.get(n)
    }

    /// Whether `reg` must be preserved by the callee.
    #[must_use]
    pub fn is_preserved(&self, reg: M68kReg) -> bool {
        self.preserved_regs.contains(&reg)
    }

    /// Whether `reg` is a caller-saved scratch register.
    #[must_use]
    pub fn is_scratch(&self, reg: M68kReg) -> bool {
        self.scratch_regs.contains(&reg)
    }

    /// Classify a register as "preserved", "scratch", or "special".
    #[must_use]
    pub fn classify(&self, reg: M68kReg) -> RegClass {
        if self.is_preserved(reg) {
            RegClass::Preserved
        } else if self.is_scratch(reg) {
            RegClass::Scratch
        } else {
            RegClass::Special
        }
    }
}

/// Classification of a register within a calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegClass {
    /// Callee must preserve this register.
    Preserved,
    /// Callee may freely clobber this register (caller-saved).
    Scratch,
    /// Register has a special role (e.g. SP, library base).
    Special,
}

impl fmt::Display for RegClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preserved => write!(f, "preserved"),
            Self::Scratch   => write!(f, "scratch"),
            Self::Special   => write!(f, "special"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry mapping names to calling conventions.
#[derive(Debug, Default)]
pub struct CallingConventionRegistry {
    map: HashMap<String, M68kCallingConvention>,
}

impl CallingConventionRegistry {
    /// Create a registry pre-populated with all built-in conventions.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self::default();
        for cc in [
            M68kCallingConvention::motorola(),
            M68kCallingConvention::amigaos(),
            M68kCallingConvention::mac(),
            M68kCallingConvention::gcc(),
        ] {
            reg.register(cc);
        }
        reg
    }

    /// Register a calling convention.
    pub fn register(&mut self, cc: M68kCallingConvention) {
        self.map.insert(cc.id.to_string(), cc);
    }

    /// Look up a convention by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&M68kCallingConvention> {
        self.map.get(name)
    }

    /// List all registered convention names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.keys().cloned().collect();
        v.sort();
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_motorola_arg_on_stack() {
        let cc = M68kCallingConvention::motorola();
        assert!(matches!(
            cc.arg_location(0),
            Some(ArgLocation::Stack { offset: 4, .. })
        ));
    }

    #[test]
    fn test_motorola_return_d0() {
        let cc = M68kCallingConvention::motorola();
        assert_eq!(cc.return_location, ReturnLocation::D0);
    }

    #[test]
    fn test_motorola_d2_preserved() {
        let cc = M68kCallingConvention::motorola();
        assert!(cc.is_preserved(M68kReg::D2));
        assert!(!cc.is_preserved(M68kReg::D0));
    }

    #[test]
    fn test_motorola_d0_scratch() {
        let cc = M68kCallingConvention::motorola();
        assert!(cc.is_scratch(M68kReg::D0));
    }

    #[test]
    fn test_amigaos_first_arg_in_d0() {
        let cc = M68kCallingConvention::amigaos();
        assert_eq!(cc.arg_location(0), Some(&ArgLocation::DataReg(M68kReg::D0)));
    }

    #[test]
    fn test_amigaos_no_stack() {
        let cc = M68kCallingConvention::amigaos();
        assert_eq!(cc.stack_cleanup, StackCleanup::NoStack);
    }

    #[test]
    fn test_mac_callee_cleans() {
        let cc = M68kCallingConvention::mac();
        assert_eq!(cc.stack_cleanup, StackCleanup::Callee);
    }

    #[test]
    fn test_gcc_is_like_motorola() {
        let gcc = M68kCallingConvention::gcc();
        let mot = M68kCallingConvention::motorola();
        assert_eq!(gcc.arg_locations.len(), mot.arg_locations.len());
        assert_eq!(gcc.preserved_regs, mot.preserved_regs);
    }

    #[test]
    fn test_classify_preserved() {
        let cc = M68kCallingConvention::motorola();
        assert_eq!(cc.classify(M68kReg::D5), RegClass::Preserved);
    }

    #[test]
    fn test_classify_scratch() {
        let cc = M68kCallingConvention::motorola();
        assert_eq!(cc.classify(M68kReg::A1), RegClass::Scratch);
    }

    #[test]
    fn test_classify_special() {
        let cc = M68kCallingConvention::motorola();
        // A7 (SP) is neither scratch nor preserved in the list.
        assert_eq!(cc.classify(M68kReg::A7), RegClass::Special);
    }

    #[test]
    fn test_arg_size_bytes() {
        assert_eq!(ArgSize::Long.bytes(), 4);
        assert_eq!(ArgSize::Word.bytes(), 2);
        assert_eq!(ArgSize::Byte.bytes(), 1);
        assert_eq!(ArgSize::Quad.bytes(), 8);
    }

    #[test]
    fn test_registry_builtins() {
        let reg = CallingConventionRegistry::with_builtins();
        let names = reg.names();
        assert!(names.contains(&"motorola".to_string()));
        assert!(names.contains(&"amigaos".to_string()));
        assert!(names.contains(&"mac".to_string()));
        assert!(names.contains(&"gcc".to_string()));
    }

    #[test]
    fn test_registry_get() {
        let reg = CallingConventionRegistry::with_builtins();
        let cc = reg.get("amigaos").unwrap();
        assert_eq!(cc.id, M68kCc::AmigaOs);
    }

    #[test]
    fn test_registry_custom() {
        let mut reg = CallingConventionRegistry::with_builtins();
        let mut custom = M68kCallingConvention::motorola();
        custom.id = M68kCc::Custom("my_abi".into());
        reg.register(custom);
        assert!(reg.get("custom:my_abi").is_some());
    }

    #[test]
    fn test_return_location_display() {
        assert_eq!(ReturnLocation::D0.to_string(), "d0");
        assert_eq!(ReturnLocation::D0D1.to_string(), "d0:d1");
        assert_eq!(ReturnLocation::Void.to_string(), "void");
    }

    #[test]
    fn test_arg_location_display() {
        let loc = ArgLocation::Stack { offset: 8, size: ArgSize::Long };
        assert!(loc.to_string().contains("sp+8"));
    }

    #[test]
    fn test_motorola_stack_alignment() {
        let cc = M68kCallingConvention::motorola();
        assert_eq!(cc.stack_alignment, 2);
    }
}
