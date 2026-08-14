//! Comprehensive calling-convention database.
//!
//! This module defines a complete, static database of calling conventions for
//! every major ABI supported by the `RustRE` suite:
//!
//! * **x86 (32-bit):** `SysV` x86, cdecl, stdcall, fastcall, thiscall, regcall.
//! * **x86-64 (64-bit):** `SysV` AMD64, MS x64, vectorcall, regcall.
//! * **ARM 32-bit:** AAPCS (soft-float and VFP).
//! * **ARM 64-bit:** AAPCS64.
//! * **MIPS:** O32.
//! * **RISC-V:** LP64D.
//! * **Rust ABI:** a best-effort description of the Rust calling convention on
//!   x86-64 (SysV-compatible with additional guarantees).
//! * **Swift ABI:** Swift's calling convention on x86-64 / arm64.
//!
//! All entries are exposed as `pub static` items for zero-allocation lookups and
//! can be retrieved via [`CcRegistry`], which supports lookup by ABI name or
//! by (arch, OS) tuple.

use crate::{Arch, CallingConvDef, CcStackCleanup, Os};
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// Global registry — lazily populated, shared across threads via parking_lot
// ─────────────────────────────────────────────────────────────────────────────

/// A global, lazily-initialised, read-write-locked registry of all built-in ABIs.
///
/// Access it via [`global_registry`]. The first call initialises the registry;
/// subsequent calls return the same instance under a `parking_lot::RwLock`
/// read-guard for zero-contention reads.
static GLOBAL_REGISTRY: OnceLock<RwLock<CcRegistry>> = OnceLock::new();

/// Return a reference to the global [`CcRegistry`].
///
/// The registry is initialised on first access with all built-in ABIs.
/// Callers that need to register additional ABIs may obtain a write-guard via
/// `global_registry().write()`.
pub fn global_registry() -> &'static RwLock<CcRegistry> {
    GLOBAL_REGISTRY.get_or_init(|| RwLock::new(CcRegistry::full()))
}

// ─────────────────────────────────────────────────────────────────────────────
// x86 calling conventions
// ─────────────────────────────────────────────────────────────────────────────

/// System V i386 ABI (Linux/macOS/BSDs 32-bit).
pub static CC_SYSV_X86: CallingConvDef = CallingConvDef {
    name: "sysv_x86",
    int_arg_regs: &[], // all args on stack
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "st0",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

/// cdecl — 32-bit C default (arguments on stack, caller cleans up).
pub static CC_CDECL_X86: CallingConvDef = CallingConvDef {
    name: "cdecl",
    int_arg_regs: &[],
    float_arg_regs: &[],
    int_ret_reg: "eax",
    float_ret_reg: "st0",
    callee_saved: &["ebx", "esi", "edi", "ebp"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 4,
    has_this_ptr: false,
    shadow_space: 0,
};

/// stdcall — 32-bit Windows API (callee cleans up).
pub static CC_STDCALL_X86: CallingConvDef = CallingConvDef {
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

/// fastcall — first two integers in ecx/edx, rest on stack, callee cleans.
pub static CC_FASTCALL_X86: CallingConvDef = CallingConvDef {
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

/// thiscall — MSVC member function (`this` in ecx, callee cleans).
pub static CC_THISCALL_X86: CallingConvDef = CallingConvDef {
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

/// Intel regcall (x86) — passes up to 10 integers and 8 XMM floats in registers.
pub static CC_REGCALL_X86: CallingConvDef = CallingConvDef {
    name: "regcall_x86",
    int_arg_regs: &["eax", "edx", "ecx", "esi", "edi"],
    float_arg_regs: &[
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    ],
    int_ret_reg: "eax",
    float_ret_reg: "xmm0",
    callee_saved: &["ebp", "ebx"],
    stack_cleanup: CcStackCleanup::Callee,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// x86-64 calling conventions
// ─────────────────────────────────────────────────────────────────────────────

/// System V AMD64 ABI (Linux, macOS, BSDs 64-bit).
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

/// Microsoft x64 calling convention (Windows 64-bit).
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

/// Microsoft vectorcall (x64) — integer in rcx/rdx/r8/r9, vectors in xmm0–5.
pub static CC_VECTORCALL_X64: CallingConvDef = CallingConvDef {
    name: "vectorcall",
    int_arg_regs: &["rcx", "rdx", "r8", "r9"],
    float_arg_regs: &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"],
    int_ret_reg: "rax",
    float_ret_reg: "xmm0",
    callee_saved: &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    // Microsoft `__vectorcall` on x64 inherits the MS x64 ABI, which mandates
    // 32 bytes of caller-reserved shadow/home space for the register params
    // (rcx/rdx/r8/r9) — the same 32 as MS x64. (Was 0 across all 3 copies; two
    // independent ABI reviews confirmed 32.)
    shadow_space: 32,
};

/// Intel regcall (x86-64) — up to 10 integers, 8 XMM args in registers.
pub static CC_REGCALL_X64: CallingConvDef = CallingConvDef {
    name: "regcall_x64",
    int_arg_regs: &["rax", "rdx", "rcx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
    float_arg_regs: &[
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    ],
    int_ret_reg: "rax",
    float_ret_reg: "xmm0",
    callee_saved: &["rbp", "rbx", "r12", "r13", "r14", "r15"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// ARM calling conventions
// ─────────────────────────────────────────────────────────────────────────────

/// AAPCS (Arm 32-bit Procedure Call Standard) — soft-float variant.
pub static CC_AAPCS32: CallingConvDef = CallingConvDef {
    name: "aapcs32",
    int_arg_regs: &["r0", "r1", "r2", "r3"],
    float_arg_regs: &[],
    int_ret_reg: "r0",
    float_ret_reg: "",
    // r14 (LR) is NOT callee-saved: it is clobbered by every BL/BLX and AAPCS32
    // (ARM IHI 0042, §6.1.1) only requires r4-r8, r10, r11 (and platform-dep.
    // r9) to be preserved. Was "…, r11, r14", diverging from the lib.rs and
    // calling_convention_detector.rs copies which correctly stop at r11.
    callee_saved: &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 8,
    has_this_ptr: false,
    shadow_space: 0,
};

/// AAPCS-VFP — hardware-float ARM 32-bit (VFP registers for float args).
pub static CC_AAPCS32_VFP: CallingConvDef = CallingConvDef {
    name: "aapcs32_vfp",
    int_arg_regs: &["r0", "r1", "r2", "r3"],
    float_arg_regs: &[
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13",
        "s14", "s15",
    ],
    int_ret_reg: "r0",
    float_ret_reg: "s0",
    // r14 (LR) removed for the same AAPCS32 §6.1.1 reason as CC_AAPCS32 above.
    callee_saved: &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 8,
    has_this_ptr: false,
    shadow_space: 0,
};

/// AAPCS64 — `AArch64` (ARM 64-bit) Procedure Call Standard.
pub static CC_AAPCS64: CallingConvDef = CallingConvDef {
    name: "aapcs64",
    int_arg_regs: &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    float_arg_regs: &["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
    int_ret_reg: "x0",
    float_ret_reg: "v0",
    callee_saved: &[
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    ],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// MIPS
// ─────────────────────────────────────────────────────────────────────────────

/// MIPS O32 calling convention (Linux MIPS 32-bit).
pub static CC_MIPS_O32: CallingConvDef = CallingConvDef {
    name: "mips_o32",
    int_arg_regs: &["a0", "a1", "a2", "a3"],
    float_arg_regs: &["f12", "f14"],
    int_ret_reg: "v0",
    float_ret_reg: "f0",
    callee_saved: &["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 8,
    has_this_ptr: false,
    shadow_space: 16, // 16-byte argument area always reserved
};

/// MIPS N64 calling convention (Linux MIPS 64-bit).
pub static CC_MIPS_N64: CallingConvDef = CallingConvDef {
    name: "mips_n64",
    int_arg_regs: &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
    float_arg_regs: &["f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19"],
    int_ret_reg: "v0",
    float_ret_reg: "f0",
    callee_saved: &["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// RISC-V
// ─────────────────────────────────────────────────────────────────────────────

/// RISC-V LP64D calling convention (Linux RISC-V 64-bit).
pub static CC_RISCV64_LP64D: CallingConvDef = CallingConvDef {
    name: "riscv64_lp64d",
    int_arg_regs: &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
    float_arg_regs: &["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"],
    int_ret_reg: "a0",
    float_ret_reg: "fa0",
    callee_saved: &[
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    ],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

/// RISC-V ILP32D calling convention (RISC-V 32-bit).
pub static CC_RISCV32_ILP32D: CallingConvDef = CallingConvDef {
    name: "riscv32_ilp32d",
    int_arg_regs: &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
    float_arg_regs: &["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"],
    int_ret_reg: "a0",
    float_ret_reg: "fa0",
    callee_saved: &[
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    ],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Rust ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Rust ABI on x86-64 (SysV-compatible; this is a best-effort approximation
/// since the Rust ABI is deliberately unspecified).
///
/// Key differences from `SysV`: Rust may pass or return small structs differently,
/// and functions may be inlined or PGO-specialised.  For binary analysis, the
/// `SysV` rules are the safest conservative approximation.
pub static CC_RUST_X64: CallingConvDef = CallingConvDef {
    name: "rust_x64",
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

/// Rust ABI on ARM64 / `AArch64` (AAPCS64-compatible).
pub static CC_RUST_ARM64: CallingConvDef = CallingConvDef {
    name: "rust_arm64",
    int_arg_regs: &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    float_arg_regs: &["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
    int_ret_reg: "x0",
    float_ret_reg: "v0",
    callee_saved: &[
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
    ],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Swift ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Swift calling convention on x86-64.
///
/// Swift uses `SysV` register allocation but reserves `r13` (`$context`) as a
/// closure context register and `r12` (`$error`) as an error-return register.
/// It also uses `rax` to return a single pointer, or `rax`+`rdx` for two-word
/// results.
pub static CC_SWIFT_X64: CallingConvDef = CallingConvDef {
    name: "swift_x64",
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

/// Swift calling convention on ARM64.
pub static CC_SWIFT_ARM64: CallingConvDef = CallingConvDef {
    name: "swift_arm64",
    int_arg_regs: &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    float_arg_regs: &["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
    int_ret_reg: "x0",
    float_ret_reg: "v0",
    callee_saved: &[
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
    ],
    stack_cleanup: CcStackCleanup::Caller,
    stack_align: 16,
    has_this_ptr: false,
    shadow_space: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// CcRegistry — queryable registry of all ABIs
// ─────────────────────────────────────────────────────────────────────────────

/// A registry of `&'static CallingConvDef` entries, queryable by name or by
/// (architecture, OS) tuple.
///
/// Instantiate with [`CcRegistry::full`] to get all ABIs pre-loaded, or build
/// a custom registry with [`CcRegistry::new`] and [`CcRegistry::register`].
pub struct CcRegistry {
    /// Name → definition.
    by_name: FxHashMap<&'static str, &'static CallingConvDef>,
    /// (Arch, Os) → list of definitions relevant for that platform.
    by_platform: FxHashMap<(Arch, Os), Vec<&'static CallingConvDef>>,
}

impl Default for CcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CcRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_name: FxHashMap::default(),
            by_platform: FxHashMap::default(),
        }
    }

    /// Create a registry pre-populated with **all** built-in ABIs.
    #[must_use]
    pub fn full() -> Self {
        let mut r = Self::new();

        // x86 ABIs
        r.register_for(
            &CC_SYSV_X86,
            &[
                (Arch::X86, Os::Linux),
                (Arch::X86, Os::MacOs),
                (Arch::X86, Os::FreeBsd),
            ],
        );
        r.register_for(
            &CC_CDECL_X86,
            &[
                (Arch::X86, Os::Linux),
                (Arch::X86, Os::Windows),
                (Arch::X86, Os::MacOs),
                (Arch::X86, Os::FreeBsd),
            ],
        );
        r.register_for(&CC_STDCALL_X86, &[(Arch::X86, Os::Windows)]);
        r.register_for(&CC_FASTCALL_X86, &[(Arch::X86, Os::Windows)]);
        r.register_for(&CC_THISCALL_X86, &[(Arch::X86, Os::Windows)]);
        r.register_for(
            &CC_REGCALL_X86,
            &[(Arch::X86, Os::Linux), (Arch::X86, Os::Windows)],
        );

        // x86-64 ABIs
        r.register_for(
            &CC_SYSV_AMD64,
            &[
                (Arch::X86_64, Os::Linux),
                (Arch::X86_64, Os::MacOs),
                (Arch::X86_64, Os::FreeBsd),
            ],
        );
        r.register_for(&CC_MS_X64, &[(Arch::X86_64, Os::Windows)]);
        r.register_for(&CC_VECTORCALL_X64, &[(Arch::X86_64, Os::Windows)]);
        r.register_for(
            &CC_REGCALL_X64,
            &[(Arch::X86_64, Os::Linux), (Arch::X86_64, Os::Windows)],
        );

        // ARM ABIs
        r.register_for(
            &CC_AAPCS32,
            &[(Arch::Arm32, Os::Linux), (Arch::Arm32, Os::Bare)],
        );
        r.register_for(
            &CC_AAPCS32_VFP,
            &[(Arch::Arm32, Os::Linux), (Arch::Arm32, Os::Bare)],
        );
        r.register_for(
            &CC_AAPCS64,
            &[
                (Arch::Arm64, Os::Linux),
                (Arch::Arm64, Os::MacOs),
                (Arch::Arm64, Os::Windows),
                (Arch::Arm64, Os::Bare),
            ],
        );

        // MIPS
        r.register_for(&CC_MIPS_O32, &[(Arch::Mips32, Os::Linux)]);
        r.register_for(&CC_MIPS_N64, &[(Arch::Mips64, Os::Linux)]);

        // RISC-V
        r.register_for(
            &CC_RISCV64_LP64D,
            &[(Arch::RiscV64, Os::Linux), (Arch::RiscV64, Os::Bare)],
        );
        r.register_for(
            &CC_RISCV32_ILP32D,
            &[(Arch::RiscV32, Os::Linux), (Arch::RiscV32, Os::Bare)],
        );

        // Rust ABIs
        r.register_for(
            &CC_RUST_X64,
            &[
                (Arch::X86_64, Os::Linux),
                (Arch::X86_64, Os::Windows),
                (Arch::X86_64, Os::MacOs),
            ],
        );
        r.register_for(
            &CC_RUST_ARM64,
            &[(Arch::Arm64, Os::Linux), (Arch::Arm64, Os::MacOs)],
        );

        // Swift ABIs
        r.register_for(
            &CC_SWIFT_X64,
            &[(Arch::X86_64, Os::MacOs), (Arch::X86_64, Os::Linux)],
        );
        r.register_for(
            &CC_SWIFT_ARM64,
            &[(Arch::Arm64, Os::MacOs), (Arch::Arm64, Os::Linux)],
        );

        r
    }

    /// Register a definition without associating it with any platform.
    pub fn register(&mut self, def: &'static CallingConvDef) {
        self.by_name.insert(def.name, def);
    }

    /// Register a definition and associate it with one or more (arch, os) pairs.
    pub fn register_for(&mut self, def: &'static CallingConvDef, platforms: &[(Arch, Os)]) {
        self.by_name.insert(def.name, def);
        for (arch, os) in platforms {
            self.by_platform
                .entry((arch.clone(), os.clone()))
                .or_default()
                .push(def);
        }
    }

    /// Look up a definition by its ABI name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static CallingConvDef> {
        self.by_name.get(name).copied()
    }

    /// Return all ABIs known for the given (arch, os) pair.
    #[must_use]
    pub fn for_platform(&self, arch: &Arch, os: &Os) -> Vec<&'static CallingConvDef> {
        self.by_platform
            .get(&(arch.clone(), os.clone()))
            .map_or_else(Vec::new, std::clone::Clone::clone)
    }

    /// Return all registered ABI names, sorted.
    #[must_use]
    pub fn all_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&str> = self.by_name.keys().copied().collect();
        names.sort_unstable();
        names
    }

    /// Number of registered definitions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Return all registered definitions as a `Vec`.
    #[must_use]
    pub fn all(&self) -> Vec<&'static CallingConvDef> {
        self.by_name.values().copied().collect()
    }

    /// Return the primary (first registered) ABI for a given platform.
    #[must_use]
    pub fn primary_for(&self, arch: &Arch, os: &Os) -> Option<&'static CallingConvDef> {
        self.for_platform(arch, os).into_iter().next()
    }

    /// Find all ABIs whose name contains `substring` (case-insensitive).
    #[must_use]
    pub fn search(&self, substring: &str) -> Vec<&'static CallingConvDef> {
        let lower = substring.to_ascii_lowercase();
        self.by_name
            .iter()
            .filter(|(name, _)| name.to_ascii_lowercase().contains(lower.as_str()))
            .map(|(_, &def)| def)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ABI compatibility checks
// ─────────────────────────────────────────────────────────────────────────────

/// Return `true` if two `CallingConvDef`s are compatible for cross-language
/// calls (same arg registers, same stack cleanup, same stack alignment).
#[must_use]
pub fn abis_are_compatible(a: &CallingConvDef, b: &CallingConvDef) -> bool {
    a.int_arg_regs == b.int_arg_regs
        && a.stack_cleanup == b.stack_cleanup
        && a.stack_align == b.stack_align
}

/// Return the number of argument registers shared between two ABIs.
#[must_use]
pub fn shared_arg_registers<'a>(a: &'a CallingConvDef, b: &'a CallingConvDef) -> Vec<&'a str> {
    a.int_arg_regs
        .iter()
        .filter(|&r| b.int_arg_regs.contains(r))
        .copied()
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Static ABI constants ──────────────────────────────────────────────────

    #[test]
    fn test_sysv_amd64_arg_regs() {
        assert_eq!(CC_SYSV_AMD64.int_arg_regs[0], "rdi");
        assert_eq!(CC_SYSV_AMD64.int_arg_regs[5], "r9");
        assert_eq!(CC_SYSV_AMD64.int_arg_regs.len(), 6);
    }

    #[test]
    fn test_ms_x64_shadow_space() {
        assert_eq!(CC_MS_X64.shadow_space, 32);
        assert_eq!(CC_MS_X64.int_arg_regs.len(), 4);
        assert_eq!(CC_MS_X64.int_arg_regs[0], "rcx");
    }

    #[test]
    fn test_cdecl_x86_no_arg_regs() {
        assert!(CC_CDECL_X86.int_arg_regs.is_empty());
        assert!(matches!(CC_CDECL_X86.stack_cleanup, CcStackCleanup::Caller));
    }

    #[test]
    fn test_stdcall_callee_cleanup() {
        assert!(matches!(
            CC_STDCALL_X86.stack_cleanup,
            CcStackCleanup::Callee
        ));
    }

    #[test]
    fn test_fastcall_two_regs() {
        assert_eq!(CC_FASTCALL_X86.int_arg_regs.len(), 2);
        assert_eq!(CC_FASTCALL_X86.int_arg_regs[0], "ecx");
        assert_eq!(CC_FASTCALL_X86.int_arg_regs[1], "edx");
    }

    #[test]
    fn test_thiscall_has_this_ptr() {
        assert!(CC_THISCALL_X86.has_this_ptr);
        assert_eq!(CC_THISCALL_X86.int_arg_regs[0], "ecx");
    }

    #[test]
    fn test_vectorcall_fp_regs() {
        assert_eq!(CC_VECTORCALL_X64.float_arg_regs.len(), 6);
        assert_eq!(CC_VECTORCALL_X64.float_arg_regs[0], "xmm0");
        assert_eq!(CC_VECTORCALL_X64.float_arg_regs[5], "xmm5");
    }

    #[test]
    fn test_aapcs64_eight_arg_regs() {
        assert_eq!(CC_AAPCS64.int_arg_regs.len(), 8);
        assert_eq!(CC_AAPCS64.int_arg_regs[0], "x0");
        assert_eq!(CC_AAPCS64.int_arg_regs[7], "x7");
    }

    #[test]
    fn test_mips_o32_shadow_space() {
        assert_eq!(CC_MIPS_O32.shadow_space, 16);
    }

    #[test]
    fn test_riscv64_callee_saved() {
        assert!(CC_RISCV64_LP64D.callee_saved.contains(&"s0"));
        assert!(CC_RISCV64_LP64D.callee_saved.contains(&"s11"));
    }

    #[test]
    fn test_rust_x64_same_as_sysv() {
        // Rust x64 uses the same register allocation as SysV AMD64.
        assert_eq!(CC_RUST_X64.int_arg_regs, CC_SYSV_AMD64.int_arg_regs);
        assert_eq!(CC_RUST_X64.callee_saved, CC_SYSV_AMD64.callee_saved);
    }

    #[test]
    fn test_rust_arm64_callee_saved() {
        assert!(CC_RUST_ARM64.callee_saved.contains(&"x19"));
    }

    #[test]
    fn test_swift_x64_no_shadow_space() {
        assert_eq!(CC_SWIFT_X64.shadow_space, 0);
    }

    #[test]
    fn test_regcall_x64_many_arg_regs() {
        assert!(CC_REGCALL_X64.int_arg_regs.len() >= 8);
    }

    // ── CcRegistry ────────────────────────────────────────────────────────────

    #[test]
    fn test_registry_full_not_empty() {
        let r = CcRegistry::full();
        assert!(!r.is_empty());
        assert!(r.len() >= 14); // at least 14 distinct ABIs
    }

    #[test]
    fn test_registry_get_sysv_amd64() {
        let r = CcRegistry::full();
        let def = r.get("sysv_amd64").expect("should find sysv_amd64");
        assert_eq!(def.name, "sysv_amd64");
        assert_eq!(def.int_arg_regs[0], "rdi");
    }

    #[test]
    fn test_registry_get_ms_x64() {
        let r = CcRegistry::full();
        let def = r.get("ms_x64").expect("should find ms_x64");
        assert_eq!(def.shadow_space, 32);
    }

    #[test]
    fn test_registry_get_missing() {
        let r = CcRegistry::full();
        assert!(r.get("no_such_abi").is_none());
    }

    #[test]
    fn test_registry_for_platform_linux_x64() {
        let r = CcRegistry::full();
        let defs = r.for_platform(&Arch::X86_64, &Os::Linux);
        assert!(!defs.is_empty());
        assert!(defs.iter().any(|d| d.name == "sysv_amd64"));
    }

    #[test]
    fn test_registry_for_platform_windows_x86() {
        let r = CcRegistry::full();
        let defs = r.for_platform(&Arch::X86, &Os::Windows);
        assert!(!defs.is_empty());
        let names: Vec<&str> = defs.iter().map(|d| d.name).collect();
        assert!(names.contains(&"cdecl"));
        assert!(names.contains(&"stdcall"));
    }

    #[test]
    fn test_registry_for_platform_unknown() {
        let r = CcRegistry::full();
        let defs = r.for_platform(&Arch::Other("sparc".into()), &Os::Other("vms".into()));
        assert!(defs.is_empty());
    }

    #[test]
    fn test_registry_all_names_sorted() {
        let r = CcRegistry::full();
        let names = r.all_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "all_names() should return sorted names");
    }

    #[test]
    fn test_registry_primary_for_arm64_linux() {
        let r = CcRegistry::full();
        let def = r.primary_for(&Arch::Arm64, &Os::Linux);
        assert!(def.is_some());
    }

    #[test]
    fn test_registry_search_x64() {
        let r = CcRegistry::full();
        let results = r.search("x64");
        assert!(!results.is_empty());
        assert!(results.iter().any(|d| d.name.contains("x64")));
    }

    #[test]
    fn test_registry_search_no_match() {
        let r = CcRegistry::full();
        let results = r.search("ZZZNOMATCH");
        assert!(results.is_empty());
    }

    // ── ABI compatibility ────────────────────────────────────────────────────

    #[test]
    fn test_abis_are_compatible_rust_and_sysv() {
        // Rust x64 is SysV-compatible.
        assert!(abis_are_compatible(&CC_RUST_X64, &CC_SYSV_AMD64));
    }

    #[test]
    fn test_abis_are_not_compatible_ms_x64_and_sysv() {
        // MS x64 uses different arg registers than SysV.
        assert!(!abis_are_compatible(&CC_MS_X64, &CC_SYSV_AMD64));
    }

    #[test]
    fn test_shared_arg_registers_sysv_and_ms() {
        // SysV: rdi, rsi, rdx, rcx, r8, r9
        // MS:   rcx, rdx, r8, r9
        // Shared: rdx, rcx, r8, r9 (but not rdi/rsi)
        let shared = shared_arg_registers(&CC_SYSV_AMD64, &CC_MS_X64);
        assert!(shared.contains(&"rdx"));
        assert!(shared.contains(&"rcx"));
        assert!(!shared.contains(&"rdi"));
    }

    #[test]
    fn test_shared_arg_registers_no_overlap() {
        // MIPS and x86-64 have completely different register names.
        let shared = shared_arg_registers(&CC_SYSV_AMD64, &CC_MIPS_O32);
        assert!(shared.is_empty());
    }

    // ── CallingConvDef helpers ────────────────────────────────────────────────

    #[test]
    fn test_is_int_arg_sysv() {
        assert!(CC_SYSV_AMD64.is_int_arg("rdi"));
        assert!(CC_SYSV_AMD64.is_int_arg("r9"));
        assert!(!CC_SYSV_AMD64.is_int_arg("rax"));
    }

    #[test]
    fn test_is_float_arg_sysv() {
        assert!(CC_SYSV_AMD64.is_float_arg("xmm0"));
        assert!(!CC_SYSV_AMD64.is_float_arg("rdi"));
    }

    #[test]
    fn test_is_callee_saved_ms_x64() {
        assert!(CC_MS_X64.is_callee_saved("rbx"));
        assert!(CC_MS_X64.is_callee_saved("rdi")); // MS x64 differs from SysV here
        assert!(!CC_MS_X64.is_callee_saved("rcx")); // arg register = caller-saved
    }

    #[test]
    fn test_regcall_x86_many_int_regs() {
        assert!(CC_REGCALL_X86.int_arg_regs.len() >= 4);
    }

    #[test]
    fn test_aapcs32_vfp_float_regs() {
        assert_eq!(CC_AAPCS32_VFP.float_arg_regs.len(), 16);
        assert_eq!(CC_AAPCS32_VFP.float_arg_regs[0], "s0");
    }

    #[test]
    fn test_mips_n64_arg_count() {
        assert_eq!(CC_MIPS_N64.int_arg_regs.len(), 8);
    }

    #[test]
    fn test_swift_arm64_callee_saved() {
        assert!(CC_SWIFT_ARM64.callee_saved.contains(&"x19"));
        assert!(CC_SWIFT_ARM64.callee_saved.contains(&"x28"));
    }

    // ── CcRegistry construction / mutation primitives ────────────────────────

    #[test]
    fn test_registry_new_is_empty() {
        let r = CcRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.all_names().is_empty());
        assert!(r.all().is_empty());
    }

    #[test]
    fn test_registry_default_matches_new() {
        let r = CcRegistry::default();
        assert!(r.is_empty());
    }

    #[test]
    fn test_registry_register_without_platform() {
        let mut r = CcRegistry::new();
        r.register(&CC_CDECL_X86);
        assert_eq!(r.len(), 1);
        assert!(r.get("cdecl").is_some());
        // Not associated with any platform.
        assert!(r.for_platform(&Arch::X86, &Os::Windows).is_empty());
    }

    #[test]
    fn test_registry_all_contains_registered() {
        let mut r = CcRegistry::new();
        r.register(&CC_CDECL_X86);
        r.register(&CC_STDCALL_X86);
        let all = r.all();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|d| d.name == "cdecl"));
        assert!(all.iter().any(|d| d.name == "stdcall"));
    }

    #[test]
    fn test_global_registry_prepopulated() {
        let guard = global_registry().read();
        assert!(!guard.is_empty());
        assert!(guard.get("sysv_amd64").is_some());
    }
}
