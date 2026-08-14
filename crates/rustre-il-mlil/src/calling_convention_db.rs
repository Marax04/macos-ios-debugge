// rustre-il-mlil/src/calling_convention_db.rs
//
// Complete calling convention database covering:
//   SysV x86-64, Microsoft x64, AAPCS64, AAPCS, cdecl, stdcall, fastcall,
//   thiscall, vectorcall, Rust ABI notes, Swift ABI.

use ahash::AHashMap as HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Register representation
// ---------------------------------------------------------------------------

/// Architecture family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    X86,
    X86_64,
    Arm32,
    Arm64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86    => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32  => write!(f, "ARM32"),
            Self::Arm64  => write!(f, "ARM64"),
        }
    }
}

/// A named register.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reg(pub &'static str);

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// x86-64 registers
// ---------------------------------------------------------------------------

pub const RAX: Reg = Reg("RAX");
pub const RBX: Reg = Reg("RBX");
pub const RCX: Reg = Reg("RCX");
pub const RDX: Reg = Reg("RDX");
pub const RSI: Reg = Reg("RSI");
pub const RDI: Reg = Reg("RDI");
pub const RBP: Reg = Reg("RBP");
pub const RSP: Reg = Reg("RSP");
pub const R8:  Reg = Reg("R8");
pub const R9:  Reg = Reg("R9");
pub const R10: Reg = Reg("R10");
pub const R11: Reg = Reg("R11");
pub const R12: Reg = Reg("R12");
pub const R13: Reg = Reg("R13");
pub const R14: Reg = Reg("R14");
pub const R15: Reg = Reg("R15");

pub const XMM0:  Reg = Reg("XMM0");
pub const XMM1:  Reg = Reg("XMM1");
pub const XMM2:  Reg = Reg("XMM2");
pub const XMM3:  Reg = Reg("XMM3");
pub const XMM4:  Reg = Reg("XMM4");
pub const XMM5:  Reg = Reg("XMM5");
pub const XMM6:  Reg = Reg("XMM6");
pub const XMM7:  Reg = Reg("XMM7");
pub const XMM8:  Reg = Reg("XMM8");
pub const XMM9:  Reg = Reg("XMM9");
pub const XMM10: Reg = Reg("XMM10");
pub const XMM11: Reg = Reg("XMM11");
pub const XMM12: Reg = Reg("XMM12");
pub const XMM13: Reg = Reg("XMM13");
pub const XMM14: Reg = Reg("XMM14");
pub const XMM15: Reg = Reg("XMM15");

// ---------------------------------------------------------------------------
// x86 (32-bit) registers
// ---------------------------------------------------------------------------

pub const EAX: Reg = Reg("EAX");
pub const EBX: Reg = Reg("EBX");
pub const ECX: Reg = Reg("ECX");
pub const EDX: Reg = Reg("EDX");
pub const ESI: Reg = Reg("ESI");
pub const EDI: Reg = Reg("EDI");
pub const EBP: Reg = Reg("EBP");
pub const ESP: Reg = Reg("ESP");

// ---------------------------------------------------------------------------
// ARM64 (AArch64) registers
// ---------------------------------------------------------------------------

pub const X0:  Reg = Reg("X0");
pub const X1:  Reg = Reg("X1");
pub const X2:  Reg = Reg("X2");
pub const X3:  Reg = Reg("X3");
pub const X4:  Reg = Reg("X4");
pub const X5:  Reg = Reg("X5");
pub const X6:  Reg = Reg("X6");
pub const X7:  Reg = Reg("X7");
pub const X8:  Reg = Reg("X8");   // indirect result / scratch
pub const X9:  Reg = Reg("X9");
pub const X16: Reg = Reg("X16");  // intra-procedure-call scratch
pub const X17: Reg = Reg("X17");
pub const X18: Reg = Reg("X18");  // platform register
pub const X19: Reg = Reg("X19");
pub const X20: Reg = Reg("X20");
pub const X21: Reg = Reg("X21");
pub const X22: Reg = Reg("X22");
pub const X23: Reg = Reg("X23");
pub const X24: Reg = Reg("X24");
pub const X25: Reg = Reg("X25");
pub const X26: Reg = Reg("X26");
pub const X27: Reg = Reg("X27");
pub const X28: Reg = Reg("X28");
pub const X29: Reg = Reg("X29"); // frame pointer
pub const X30: Reg = Reg("X30"); // link register
pub const LR:  Reg = Reg("LR");  // alias for X30

pub const V0:  Reg = Reg("V0");
pub const V1:  Reg = Reg("V1");
pub const V2:  Reg = Reg("V2");
pub const V3:  Reg = Reg("V3");
pub const V4:  Reg = Reg("V4");
pub const V5:  Reg = Reg("V5");
pub const V6:  Reg = Reg("V6");
pub const V7:  Reg = Reg("V7");
pub const V8:  Reg = Reg("V8");
pub const V9:  Reg = Reg("V9");
pub const V10: Reg = Reg("V10");
pub const V11: Reg = Reg("V11");
pub const V12: Reg = Reg("V12");
pub const V13: Reg = Reg("V13");
pub const V14: Reg = Reg("V14");
pub const V15: Reg = Reg("V15");
pub const V16: Reg = Reg("V16");
pub const V17: Reg = Reg("V17");
pub const V18: Reg = Reg("V18");
pub const V19: Reg = Reg("V19");
pub const V20: Reg = Reg("V20");
pub const V21: Reg = Reg("V21");
pub const V22: Reg = Reg("V22");
pub const V23: Reg = Reg("V23");
pub const V24: Reg = Reg("V24");
pub const V25: Reg = Reg("V25");
pub const V26: Reg = Reg("V26");
pub const V27: Reg = Reg("V27");
pub const V28: Reg = Reg("V28");
pub const V29: Reg = Reg("V29");
pub const V30: Reg = Reg("V30");
pub const V31: Reg = Reg("V31");

// ---------------------------------------------------------------------------
// ARM32 registers
// ---------------------------------------------------------------------------

pub const R0:  Reg = Reg("R0");
pub const R1:  Reg = Reg("R1");
pub const R2:  Reg = Reg("R2");
pub const R3:  Reg = Reg("R3");
pub const R4:  Reg = Reg("R4");
pub const R5:  Reg = Reg("R5");
pub const R6:  Reg = Reg("R6");
pub const R7:  Reg = Reg("R7");
pub const R11_ARM: Reg = Reg("R11"); // frame pointer (AAPCS)
pub const R12_ARM: Reg = Reg("R12"); // intra-procedure-call scratch
pub const R13_ARM: Reg = Reg("R13"); // stack pointer
pub const R14_ARM: Reg = Reg("R14"); // link register
pub const R15_PC: Reg = Reg("R15"); // program counter

// ---------------------------------------------------------------------------
// Stack-passing policy
// ---------------------------------------------------------------------------

/// Which direction arguments are pushed onto the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackOrder {
    RightToLeft,
    LeftToRight,
}

/// Who is responsible for cleaning up stack-passed arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackCleanup {
    Caller,
    Callee,
}

// ---------------------------------------------------------------------------
// Argument kind
// ---------------------------------------------------------------------------

/// The high-level kind of a function argument, affecting register assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// Plain integer or pointer.
    Integer,
    /// Floating-point scalar.
    Float,
    /// SIMD / vector type.
    Vector,
    /// Aggregate (struct/array).
    Aggregate { size: usize },
}

// ---------------------------------------------------------------------------
// Return value descriptor
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ReturnInfo {
    /// Primary return register (integer/pointer).
    pub primary: Option<Reg>,
    /// Secondary return register for 128-bit integer or multi-value returns.
    pub secondary: Option<Reg>,
    /// Floating-point / SIMD return register.
    pub fp_primary: Option<Reg>,
    /// If the return value is a large aggregate, a pointer to the caller-allocated
    /// buffer is passed here and the callee returns it in `primary`.
    pub sret_ptr_reg: Option<Reg>,
    /// Maximum size (bytes) for return in register(s); larger → pointer.
    pub max_inreg_size: usize,
}

// ---------------------------------------------------------------------------
// Shadow space (Microsoft x64)
// ---------------------------------------------------------------------------

/// Some conventions reserve a "shadow space" / "home space" on the stack
/// before arguments, into which the callee may spill its register arguments.
#[derive(Clone, Debug)]
pub struct ShadowSpace {
    pub size_bytes: usize,
}

// ---------------------------------------------------------------------------
// Calling convention descriptor
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CallingConvention {
    pub name: &'static str,
    pub arch: Arch,

    // --- Integer argument registers (in order) ---
    pub int_arg_regs: Vec<Reg>,
    /// Maximum number of integer arguments passed in registers (may be < `int_arg_regs.len()`).
    pub max_int_reg_args: usize,

    // --- Floating-point / SIMD argument registers ---
    pub fp_arg_regs: Vec<Reg>,
    pub max_fp_reg_args: usize,

    // --- Return value ---
    pub ret: ReturnInfo,

    // --- Callee-saved registers ---
    pub callee_saved: Vec<Reg>,

    // --- Caller-saved (scratch) registers ---
    pub caller_saved: Vec<Reg>,

    // --- Stack policy ---
    pub stack_order: StackOrder,
    pub stack_cleanup: StackCleanup,
    pub stack_alignment: usize,

    // --- Shadow / home space ---
    pub shadow_space: Option<ShadowSpace>,

    // --- Special registers ---
    /// Register holding `this` pointer (thiscall, Swift self, etc.).
    pub this_reg: Option<Reg>,
    /// Register used for Rust / Swift error / context pointer.
    pub context_reg: Option<Reg>,
    /// Error return register (Swift).
    pub error_reg: Option<Reg>,

    // --- Variadic handling ---
    /// Whether this convention supports variadic arguments (`va_list`).
    pub supports_variadic: bool,
    /// For `SysV` x86-64: AL holds the number of XMM registers used.
    pub variadic_xmm_count_reg: Option<Reg>,

    // --- Aggregate passing rules ---
    /// Max size (bytes) of aggregate that can be passed in registers.
    pub aggregate_max_inreg_size: usize,
    /// Required alignment for stack-passed aggregate arguments.
    pub aggregate_stack_align: usize,

    // --- Notes ---
    pub notes: &'static str,
}

// ---------------------------------------------------------------------------
// SysV x86-64 ABI
// ---------------------------------------------------------------------------

#[must_use] 
pub fn sysv_x86_64() -> CallingConvention {
    CallingConvention {
        name: "sysv_x86_64",
        arch: Arch::X86_64,
        int_arg_regs: vec![RDI, RSI, RDX, RCX, R8, R9],
        max_int_reg_args: 6,
        fp_arg_regs: vec![XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7],
        max_fp_reg_args: 8,
        ret: ReturnInfo {
            primary:   Some(RAX),
            secondary: Some(RDX),
            fp_primary: Some(XMM0),
            sret_ptr_reg: Some(RDI), // hidden first argument when returning large aggregate
            max_inreg_size: 16,
        },
        callee_saved: vec![RBX, RBP, R12, R13, R14, R15],
        caller_saved: vec![RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11,
                           XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
                           XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 16,
        shadow_space:    None,
        this_reg:        None,
        context_reg:     None,
        error_reg:       None,
        supports_variadic: true,
        variadic_xmm_count_reg: Some(RAX), // AL = # XMM registers used
        aggregate_max_inreg_size: 16,
        aggregate_stack_align: 8,
        notes: "AMD64 SysV ABI. Aggregates ≤ 16 bytes are classified per field \
                (INTEGER/SSE/MEMORY). Aggregates > 16 bytes or containing \
                unaligned fields go on the stack.",
    }
}

// ---------------------------------------------------------------------------
// Microsoft x64 ABI
// ---------------------------------------------------------------------------

#[must_use] 
pub fn ms_x64() -> CallingConvention {
    CallingConvention {
        name: "ms_x64",
        arch: Arch::X86_64,
        int_arg_regs: vec![RCX, RDX, R8, R9],
        max_int_reg_args: 4,
        fp_arg_regs: vec![XMM0, XMM1, XMM2, XMM3],
        max_fp_reg_args: 4,
        ret: ReturnInfo {
            primary:   Some(RAX),
            secondary: None,
            fp_primary: Some(XMM0),
            sret_ptr_reg: Some(RCX),
            max_inreg_size: 8,
        },
        callee_saved: vec![RBX, RBP, RDI, RSI, R12, R13, R14, R15,
                           XMM6, XMM7, XMM8, XMM9, XMM10, XMM11,
                           XMM12, XMM13, XMM14, XMM15],
        caller_saved: vec![RAX, RCX, RDX, R8, R9, R10, R11,
                           XMM0, XMM1, XMM2, XMM3, XMM4, XMM5],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 16,
        shadow_space: Some(ShadowSpace { size_bytes: 32 }), // 4 × 8 bytes home space
        this_reg:     None,
        context_reg:  None,
        error_reg:    None,
        supports_variadic: true,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 8,
        aggregate_stack_align: 8,
        notes: "Microsoft x64. Only 4 reg args (int/fp slots are paired: arg0 in \
                RCX or XMM0, arg1 in RDX or XMM1, etc.).  Caller allocates 32-byte \
                shadow space unconditionally.  Aggregates > 8 bytes passed as pointer.",
    }
}

// ---------------------------------------------------------------------------
// AAPCS64 (ARM64 / AArch64)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn aapcs64() -> CallingConvention {
    CallingConvention {
        name: "aapcs64",
        arch: Arch::Arm64,
        int_arg_regs: vec![X0, X1, X2, X3, X4, X5, X6, X7],
        max_int_reg_args: 8,
        fp_arg_regs: vec![V0, V1, V2, V3, V4, V5, V6, V7],
        max_fp_reg_args: 8,
        ret: ReturnInfo {
            primary:   Some(X0),
            secondary: Some(X1), // X0:X1 for 128-bit integers
            fp_primary: Some(V0),
            sret_ptr_reg: Some(X8), // "indirect result location register"
            max_inreg_size: 16,
        },
        callee_saved: vec![
            X19, X20, X21, X22, X23, X24, X25, X26, X27, X28,
            X29, // FP
            LR,  // X30
            V8, V9, V10, V11, V12, V13, V14, V15,
        ],
        caller_saved: vec![
            X0, X1, X2, X3, X4, X5, X6, X7,
            X8, X9,
            X16, X17, X18,
            V0, V1, V2, V3, V4, V5, V6, V7,
            V16, V17, V18, V19, V20, V21, V22, V23,
            V24, V25, V26, V27, V28, V29, V30, V31,
        ],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 16,
        shadow_space:    None,
        this_reg:        None,
        context_reg:     None,
        error_reg:       None,
        supports_variadic: true,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 16,
        aggregate_stack_align: 8,
        notes: "AAPCS64 (Procedure Call Standard for ARM 64-bit).  HFAs \
                (Homogeneous Floating-point Aggregates) with ≤4 members pass in \
                V0-V3. HVAs (Homogeneous Short-Vector Aggregates) similarly.  \
                Aggregates > 16 bytes → stack or X8 indirect.",
    }
}

// ---------------------------------------------------------------------------
// AAPCS (ARM32)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn aapcs_arm32() -> CallingConvention {
    CallingConvention {
        name: "aapcs",
        arch: Arch::Arm32,
        int_arg_regs: vec![R0, R1, R2, R3],
        max_int_reg_args: 4,
        fp_arg_regs: vec![],          // soft-float: fp args go in int regs
        max_fp_reg_args: 0,
        ret: ReturnInfo {
            primary:   Some(R0),
            secondary: Some(R1), // R0:R1 for 64-bit
            fp_primary: None,
            sret_ptr_reg: Some(R0),
            max_inreg_size: 8,
        },
        callee_saved: vec![R4, R5, R6, R7, R8, R9, R10, R11],
        caller_saved: vec![R0, R1, R2, R3, R12_ARM],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 8,
        shadow_space:    None,
        this_reg:        None,
        context_reg:     None,
        error_reg:       None,
        supports_variadic: true,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 8,
        aggregate_stack_align: 4,
        notes: "AAPCS (soft-float variant). Hard-float variant (AAPCS-VFP) uses \
                VFP registers S0-S15 / D0-D7 for float args.  64-bit values in \
                R0:R1 / R2:R3 must be 8-byte aligned (LDRD constraint).",
    }
}

// ---------------------------------------------------------------------------
// SysV x86 cdecl
// ---------------------------------------------------------------------------

#[must_use] 
pub fn cdecl() -> CallingConvention {
    CallingConvention {
        name: "cdecl",
        arch: Arch::X86,
        int_arg_regs: vec![],   // all on stack
        max_int_reg_args: 0,
        fp_arg_regs: vec![],
        max_fp_reg_args: 0,
        ret: ReturnInfo {
            primary:   Some(EAX),
            secondary: Some(EDX), // EDX:EAX for 64-bit
            fp_primary: None, // st(0) / XMM0 on modern CPUs
            sret_ptr_reg: Some(EAX),
            max_inreg_size: 8,
        },
        callee_saved: vec![EBX, ESI, EDI, EBP],
        caller_saved: vec![EAX, ECX, EDX],
        stack_order:   StackOrder::RightToLeft,
        stack_cleanup: StackCleanup::Caller,   // ← cdecl: caller cleans
        stack_alignment: 4,
        shadow_space:    None,
        this_reg:        None,
        context_reg:     None,
        error_reg:       None,
        supports_variadic: true,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 0,
        aggregate_stack_align: 4,
        notes: "System V x86 cdecl. All arguments passed on stack right-to-left. \
                Caller is responsible for cleaning up.  Floating-point returns \
                in x87 st(0) register.",
    }
}

// ---------------------------------------------------------------------------
// x86 stdcall
// ---------------------------------------------------------------------------

#[must_use] 
pub fn stdcall() -> CallingConvention {
    let mut cc = cdecl();
    cc.name = "stdcall";
    cc.stack_cleanup = StackCleanup::Callee;  // callee emits RETN N
    cc.supports_variadic = false;             // callee can't clean variadic
    cc.notes = "x86 stdcall. Arguments right-to-left on stack. Callee cleans \
                the stack (RETN N). No variadic support. Used by Win32 API.";
    cc
}

// ---------------------------------------------------------------------------
// x86 fastcall (MSVC)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn fastcall_msvc() -> CallingConvention {
    CallingConvention {
        name: "fastcall",
        arch: Arch::X86,
        int_arg_regs: vec![ECX, EDX], // first two int args in ECX, EDX
        max_int_reg_args: 2,
        fp_arg_regs: vec![],
        max_fp_reg_args: 0,
        ret: ReturnInfo {
            primary:   Some(EAX),
            secondary: Some(EDX),
            fp_primary: None,
            sret_ptr_reg: None,
            max_inreg_size: 8,
        },
        callee_saved: vec![EBX, ESI, EDI, EBP],
        caller_saved: vec![EAX, ECX, EDX],
        stack_order:   StackOrder::RightToLeft,
        stack_cleanup: StackCleanup::Callee,
        stack_alignment: 4,
        shadow_space:    None,
        this_reg:        None,
        context_reg:     None,
        error_reg:       None,
        supports_variadic: false,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 0,
        aggregate_stack_align: 4,
        notes: "MSVC __fastcall. First two integer/pointer args in ECX, EDX; \
                rest on stack right-to-left. Callee cleans stack.",
    }
}

// ---------------------------------------------------------------------------
// x86 thiscall
// ---------------------------------------------------------------------------

#[must_use] 
pub fn thiscall() -> CallingConvention {
    CallingConvention {
        name: "thiscall",
        arch: Arch::X86,
        int_arg_regs: vec![ECX],   // `this` pointer in ECX
        max_int_reg_args: 1,
        fp_arg_regs: vec![],
        max_fp_reg_args: 0,
        ret: ReturnInfo {
            primary:   Some(EAX),
            secondary: Some(EDX),
            fp_primary: None,
            sret_ptr_reg: None,
            max_inreg_size: 8,
        },
        callee_saved: vec![EBX, ESI, EDI, EBP],
        caller_saved: vec![EAX, ECX, EDX],
        stack_order:   StackOrder::RightToLeft,
        stack_cleanup: StackCleanup::Callee, // callee cleans all stack args
        stack_alignment: 4,
        shadow_space:    None,
        this_reg: Some(ECX), // `this` is always in ECX
        context_reg: None,
        error_reg:   None,
        supports_variadic: false,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 0,
        aggregate_stack_align: 4,
        notes: "MSVC thiscall. 'this' pointer in ECX. All other arguments \
                right-to-left on stack. Callee cleans stack (unlike cdecl). \
                Variadic methods use cdecl instead.",
    }
}

// ---------------------------------------------------------------------------
// x86 vectorcall (MSVC)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn vectorcall() -> CallingConvention {
    CallingConvention {
        name: "vectorcall",
        arch: Arch::X86_64,   // vectorcall exists for both x86 and x64; using x64 here
        int_arg_regs: vec![RCX, RDX, R8, R9],
        max_int_reg_args: 4,
        fp_arg_regs: vec![XMM0, XMM1, XMM2, XMM3, XMM4, XMM5],
        max_fp_reg_args: 6, // first 6 float/vector args in XMM0-XMM5
        ret: ReturnInfo {
            primary:   Some(RAX),
            secondary: None,
            fp_primary: Some(XMM0),
            sret_ptr_reg: Some(RCX),
            max_inreg_size: 16,
        },
        callee_saved: vec![RBX, RBP, RDI, RSI, R12, R13, R14, R15,
                           XMM6, XMM7, XMM8, XMM9, XMM10, XMM11,
                           XMM12, XMM13, XMM14, XMM15],
        caller_saved: vec![RAX, RCX, RDX, R8, R9, R10, R11,
                           XMM0, XMM1, XMM2, XMM3, XMM4, XMM5],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 16,
        shadow_space: Some(ShadowSpace { size_bytes: 32 }),
        this_reg:     None,
        context_reg:  None,
        error_reg:    None,
        supports_variadic: false,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 16,
        aggregate_stack_align: 16,
        notes: "MSVC __vectorcall (x64 variant). First 6 float/SIMD args in \
                XMM0-XMM5 (int args follow ms_x64 slot rules). HVAs \
                (Homogeneous Vector Aggregates) of ≤4 × 128-bit pass in XMM \
                registers. Return HVA in XMM0-XMM3.",
    }
}

// ---------------------------------------------------------------------------
// Rust ABI (unstable)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn rust_abi_note() -> CallingConvention {
    // Rust's 'extern "Rust"' ABI is unstable and platform-specific.
    // On Linux x86-64 it currently matches SysV with some optimizations.
    // On Windows x64 it generally matches ms_x64.
    // These details change between compiler versions.
    let mut base = sysv_x86_64();
    base.name = "rust_unstable";
    base.notes = "Rust 'extern \"Rust\"' ABI.  WARNING: This ABI is UNSTABLE and \
                  changes between compiler versions.  On x86-64 Linux it typically \
                  follows SysV with optimizations (e.g. returning small structs in \
                  RAX:RDX, passing bool in a single byte).  On Windows x64 it \
                  follows ms_x64.  Do NOT rely on this across compiler versions or \
                  crate boundaries unless using #[repr(C)] + extern \"C\".";
    base
}

// ---------------------------------------------------------------------------
// Swift ABI (x86-64 Darwin)
// ---------------------------------------------------------------------------

#[must_use] 
pub fn swift_abi_x86_64() -> CallingConvention {
    // Swift uses a custom calling convention on top of SysV / ms_x64.
    // Key differences: self in a dedicated register, error result in a dedicated
    // register, and the "swiftself" / "swifterror" attributes in LLVM IR.
    CallingConvention {
        name: "swift_x86_64",
        arch: Arch::X86_64,
        // Swift passes most args like SysV, but self and error have dedicated regs.
        int_arg_regs: vec![RDI, RSI, RDX, RCX, R8, R9],
        max_int_reg_args: 6,
        fp_arg_regs: vec![XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7],
        max_fp_reg_args: 8,
        ret: ReturnInfo {
            primary:   Some(RAX),
            secondary: Some(RDX),
            fp_primary: Some(XMM0),
            sret_ptr_reg: Some(RDI),
            max_inreg_size: 32, // Swift can return larger values in multiple regs
        },
        callee_saved: vec![RBX, RBP, R12, R13, R14, R15],
        caller_saved: vec![RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11,
                           XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
                           XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15],
        stack_order:     StackOrder::RightToLeft,
        stack_cleanup:   StackCleanup::Caller,
        stack_alignment: 16,
        shadow_space:    None,
        this_reg:    Some(R13),  // "swiftself" — self pointer in R13
        context_reg: Some(R13),  // same: used as context in closures
        error_reg:   Some(R12),  // "swifterror" — indirect error result in R12
        supports_variadic: false,
        variadic_xmm_count_reg: None,
        aggregate_max_inreg_size: 32,
        aggregate_stack_align: 8,
        notes: "Swift calling convention for x86-64 Darwin.  Extends SysV: \
                'self' (and closure context) go in R13 ('swiftself'); \
                error pointer in R12 ('swifterror', callee sets to non-nil on \
                throw).  Swift's return convention can return up to 4 × 64-bit \
                values in RAX/RDX/XMM0/XMM1 depending on type classification.",
    }
}

// ---------------------------------------------------------------------------
// Calling convention database
// ---------------------------------------------------------------------------

/// Registry of all known calling conventions.
pub struct CallingConventionDb {
    conventions: HashMap<&'static str, CallingConvention>,
}

impl CallingConventionDb {
    /// Build the database with all built-in calling conventions.
    #[must_use] 
    pub fn new() -> Self {
        let mut db = Self { conventions: HashMap::new() };
        let ccs: Vec<CallingConvention> = vec![
            sysv_x86_64(),
            ms_x64(),
            aapcs64(),
            aapcs_arm32(),
            cdecl(),
            stdcall(),
            fastcall_msvc(),
            thiscall(),
            vectorcall(),
            rust_abi_note(),
            swift_abi_x86_64(),
        ];
        for cc in ccs {
            db.conventions.insert(cc.name, cc);
        }
        db
    }

    /// Look up a calling convention by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&CallingConvention> {
        self.conventions.get(name)
    }

    /// All convention names.
    #[must_use] 
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.conventions.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Look up by architecture (returns all matching conventions).
    #[must_use] 
    pub fn by_arch(&self, arch: Arch) -> Vec<&CallingConvention> {
        self.conventions
            .values()
            .filter(|cc| cc.arch == arch)
            .collect()
    }
}

impl Default for CallingConventionDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Register assignment algorithm
// ---------------------------------------------------------------------------

/// Result of assigning a single argument to a location.
#[derive(Clone, Debug)]
pub enum ArgLocation {
    /// Passed in a register.
    Register(Reg),
    /// Passed in multiple consecutive integer registers (e.g. a 16-byte
    /// aggregate split across two registers under SysV x86-64).
    RegisterMulti(Vec<Reg>),
    /// Passed on the stack at a given byte offset from the start of the
    /// argument area (after any shadow space).
    Stack { offset: usize, size: usize },
    /// Passed as a pointer (aggregate too large for registers).
    ByPointer { reg: Option<Reg>, stack_offset: Option<usize> },
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{r}"),
            Self::RegisterMulti(regs) => {
                let names: Vec<String> = regs.iter().map(|r| r.to_string()).collect();
                write!(f, "{}", names.join(":"))
            }
            Self::Stack { offset, size } => write!(f, "stack+{offset}({size}B)"),
            Self::ByPointer { reg, stack_offset } => {
                write!(f, "ptr(")?;
                if let Some(r) = reg { write!(f, "{r}")?; }
                if let Some(off) = stack_offset { write!(f, "stack+{off}")?; }
                write!(f, ")")
            }
        }
    }
}

/// State used while assigning arguments.
pub struct AssignmentState {
    pub int_reg_idx: usize,
    pub fp_reg_idx: usize,
    pub stack_offset: usize,
}

impl AssignmentState {
    #[must_use] 
    pub const fn new() -> Self {
        Self { int_reg_idx: 0, fp_reg_idx: 0, stack_offset: 0 }
    }
}

impl Default for AssignmentState {
    fn default() -> Self { Self::new() }
}

/// Assign one argument to a location under the given calling convention.
pub fn assign_argument(
    cc: &CallingConvention,
    kind: ArgKind,
    arg_size: usize,
    state: &mut AssignmentState,
) -> ArgLocation {
    match kind {
        ArgKind::Integer => {
            if state.int_reg_idx < cc.max_int_reg_args {
                let reg = cc.int_arg_regs[state.int_reg_idx].clone();
                state.int_reg_idx += 1;
                // Microsoft x64: paired slots — skip the corresponding FP slot too.
                if cc.name == "ms_x64" || cc.name == "vectorcall" {
                    state.fp_reg_idx = state.int_reg_idx;
                }
                ArgLocation::Register(reg)
            } else {
                let aligned_offset = align_up(state.stack_offset, 8);
                let size = arg_size.max(8); // min 8-byte slot on x86-64
                state.stack_offset = aligned_offset + size;
                ArgLocation::Stack { offset: aligned_offset, size }
            }
        }
        ArgKind::Float | ArgKind::Vector => {
            if state.fp_reg_idx < cc.max_fp_reg_args {
                let reg = cc.fp_arg_regs[state.fp_reg_idx].clone();
                state.fp_reg_idx += 1;
                if cc.name == "ms_x64" || cc.name == "vectorcall" {
                    state.int_reg_idx = state.fp_reg_idx;
                }
                ArgLocation::Register(reg)
            } else {
                let aligned_offset = align_up(state.stack_offset, 8);
                let size = arg_size.max(8);
                state.stack_offset = aligned_offset + size;
                ArgLocation::Stack { offset: aligned_offset, size }
            }
        }
        ArgKind::Aggregate { size } => {
            if size <= cc.aggregate_max_inreg_size {
                // Try to fit in integer register(s).
                let needed_regs = size.div_ceil(8);
                if state.int_reg_idx + needed_regs <= cc.max_int_reg_args {
                    let regs: Vec<Reg> = cc.int_arg_regs
                        [state.int_reg_idx..state.int_reg_idx + needed_regs]
                        .to_vec();
                    state.int_reg_idx += needed_regs;
                    if needed_regs == 1 {
                        ArgLocation::Register(regs.into_iter().next().unwrap())
                    } else {
                        ArgLocation::RegisterMulti(regs)
                    }
                } else {
                    // Flush remaining regs and go to stack.
                    state.int_reg_idx = cc.max_int_reg_args;
                    let aligned_offset = align_up(state.stack_offset, cc.aggregate_stack_align);
                    state.stack_offset = aligned_offset + align_up(size, cc.aggregate_stack_align);
                    ArgLocation::Stack { offset: aligned_offset, size }
                }
            } else {
                // Too large: pass by pointer.
                if state.int_reg_idx < cc.max_int_reg_args {
                    let reg = cc.int_arg_regs[state.int_reg_idx].clone();
                    state.int_reg_idx += 1;
                    ArgLocation::ByPointer { reg: Some(reg), stack_offset: None }
                } else {
                    let aligned_offset = align_up(state.stack_offset, 8);
                    state.stack_offset = aligned_offset + 8;
                    ArgLocation::ByPointer { reg: None, stack_offset: Some(aligned_offset) }
                }
            }
        }
    }
}

/// Assign all arguments in order.
#[must_use] 
pub fn assign_all_arguments(
    cc: &CallingConvention,
    args: &[(ArgKind, usize)], // (kind, size_in_bytes)
    is_variadic: bool,
) -> Vec<ArgLocation> {
    let mut state = AssignmentState::new();
    // Shadow space is allocated by the caller but doesn't affect register assignment.
    let mut locations = Vec::with_capacity(args.len());
    for &(kind, size) in args {
        // For variadic functions under SysV x86-64, float args after the named
        // parameters still go on the stack (simplified here).
        let effective_kind = if is_variadic && !locations.is_empty() {
            match kind {
                ArgKind::Float | ArgKind::Vector => ArgKind::Integer, // promoted
                other => other,
            }
        } else {
            kind
        };
        locations.push(assign_argument(cc, effective_kind, size, &mut state));
    }
    locations
}

// ---------------------------------------------------------------------------
// Callee-saved / caller-saved queries
// ---------------------------------------------------------------------------

/// True if `reg` must be preserved across a call under `cc`.
#[must_use] 
pub fn is_callee_saved(cc: &CallingConvention, reg: &Reg) -> bool {
    cc.callee_saved.contains(reg)
}

/// True if `reg` may be clobbered by a call under `cc`.
#[must_use] 
pub fn is_caller_saved(cc: &CallingConvention, reg: &Reg) -> bool {
    cc.caller_saved.contains(reg)
}

// ---------------------------------------------------------------------------
// Variadic handling
// ---------------------------------------------------------------------------

/// Information about how to build a `va_list` for the given convention.
#[derive(Debug, Clone)]
pub struct VaListInfo {
    /// Registers used for named arguments before the variadic portion.
    pub named_int_regs: Vec<Reg>,
    pub named_fp_regs: Vec<Reg>,
    /// Stack offset where the variadic portion begins.
    pub va_stack_start: usize,
    /// Extra register (e.g. AL for `SysV` x86-64) that holds a count.
    pub count_reg: Option<Reg>,
}

#[must_use] 
pub fn variadic_va_list_info(
    cc: &CallingConvention,
    named_args: &[(ArgKind, usize)],
) -> Option<VaListInfo> {
    if !cc.supports_variadic {
        return None;
    }
    let mut state = AssignmentState::new();
    for &(kind, size) in named_args {
        assign_argument(cc, kind, size, &mut state);
    }
    Some(VaListInfo {
        named_int_regs: cc.int_arg_regs[..state.int_reg_idx.min(cc.max_int_reg_args)].to_vec(),
        named_fp_regs: cc.fp_arg_regs[..state.fp_reg_idx.min(cc.max_fp_reg_args)].to_vec(),
        va_stack_start: state.stack_offset,
        count_reg: cc.variadic_xmm_count_reg.clone(),
    })
}

// ---------------------------------------------------------------------------
// Stack frame layout helper
// ---------------------------------------------------------------------------

/// A description of the stack frame as laid out by the calling convention.
#[derive(Debug, Clone)]
pub struct StackFrameLayout {
    /// Total size of the argument area (including shadow space if any).
    pub arg_area_size: usize,
    /// Offset of the first actual argument from the start of the arg area.
    pub first_arg_offset: usize,
    /// Return address size.
    pub return_addr_size: usize,
    /// Required alignment of the frame.
    pub frame_alignment: usize,
}

#[must_use] 
pub fn compute_frame_layout(cc: &CallingConvention, stack_arg_bytes: usize) -> StackFrameLayout {
    let shadow = cc.shadow_space.as_ref().map_or(0, |s| s.size_bytes);
    StackFrameLayout {
        arg_area_size: shadow + stack_arg_bytes,
        first_arg_offset: shadow,
        return_addr_size: match cc.arch {
            Arch::X86 => 4,
            Arch::X86_64 => 8,
            Arch::Arm32 => 4,  // LR saved separately
            Arch::Arm64 => 8,  // LR saved separately
        },
        frame_alignment: cc.stack_alignment,
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

const fn align_up(val: usize, align: usize) -> usize {
    if align == 0 { return val; }
    (val + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_contains_all_conventions() {
        let db = CallingConventionDb::new();
        for name in &[
            "sysv_x86_64", "ms_x64", "aapcs64", "aapcs",
            "cdecl", "stdcall", "fastcall", "thiscall",
            "vectorcall", "rust_unstable", "swift_x86_64",
        ] {
            assert!(db.get(name).is_some(), "Missing convention: {}", name);
        }
    }

    #[test]
    fn test_sysv_int_args_in_regs() {
        let cc = sysv_x86_64();
        let args = vec![
            (ArgKind::Integer, 8),
            (ArgKind::Integer, 8),
            (ArgKind::Integer, 8),
        ];
        let locs = assign_all_arguments(&cc, &args, false);
        assert!(matches!(locs[0], ArgLocation::Register(ref r) if r == &RDI));
        assert!(matches!(locs[1], ArgLocation::Register(ref r) if r == &RSI));
        assert!(matches!(locs[2], ArgLocation::Register(ref r) if r == &RDX));
    }

    #[test]
    fn test_sysv_overflow_to_stack() {
        let cc = sysv_x86_64();
        // 6 integer args fill registers, 7th goes to stack.
        let args: Vec<(ArgKind, usize)> = (0..7).map(|_| (ArgKind::Integer, 8)).collect();
        let locs = assign_all_arguments(&cc, &args, false);
        assert!(matches!(locs[6], ArgLocation::Stack { .. }));
    }

    #[test]
    fn test_ms_x64_paired_slots() {
        let cc = ms_x64();
        let args = vec![
            (ArgKind::Float,   8),
            (ArgKind::Integer, 8),
        ];
        let locs = assign_all_arguments(&cc, &args, false);
        // arg0 (float) → XMM0
        assert!(matches!(locs[0], ArgLocation::Register(ref r) if r == &XMM0));
        // arg1 (int) → RDX (slot 1), because XMM0 used slot 0
        assert!(matches!(locs[1], ArgLocation::Register(ref r) if r == &RDX));
    }

    #[test]
    fn test_cdecl_all_stack() {
        let cc = cdecl();
        let args = vec![(ArgKind::Integer, 4), (ArgKind::Integer, 4)];
        let locs = assign_all_arguments(&cc, &args, false);
        assert!(matches!(locs[0], ArgLocation::Stack { .. }));
        assert!(matches!(locs[1], ArgLocation::Stack { .. }));
    }

    #[test]
    fn test_callee_saved_sysv() {
        let cc = sysv_x86_64();
        assert!(is_callee_saved(&cc, &RBX));
        assert!(is_callee_saved(&cc, &R12));
        assert!(!is_callee_saved(&cc, &RAX));
        assert!(!is_callee_saved(&cc, &RDI));
    }

    #[test]
    fn test_callee_saved_ms_x64() {
        let cc = ms_x64();
        assert!(is_callee_saved(&cc, &RBX));
        assert!(is_callee_saved(&cc, &RDI));
        assert!(is_callee_saved(&cc, &RSI));
        assert!(is_callee_saved(&cc, &XMM6));
        assert!(!is_callee_saved(&cc, &XMM0));
    }

    #[test]
    fn test_aapcs64_args() {
        let cc = aapcs64();
        let args: Vec<(ArgKind, usize)> = (0..8).map(|_| (ArgKind::Integer, 8)).collect();
        let locs = assign_all_arguments(&cc, &args, false);
        // All 8 go in X0-X7
        for loc in &locs {
            assert!(matches!(loc, ArgLocation::Register(_)));
        }
    }

    #[test]
    fn test_aggregate_large_by_pointer() {
        let cc = sysv_x86_64();
        let args = vec![(ArgKind::Aggregate { size: 64 }, 64)];
        let locs = assign_all_arguments(&cc, &args, false);
        assert!(matches!(locs[0], ArgLocation::ByPointer { .. }));
    }

    #[test]
    fn test_aggregate_small_in_register() {
        let cc = sysv_x86_64();
        let args = vec![(ArgKind::Aggregate { size: 8 }, 8)];
        let locs = assign_all_arguments(&cc, &args, false);
        assert!(matches!(locs[0], ArgLocation::Register(_)));
    }

    #[test]
    fn test_aggregate_two_reg_sysv() {
        // A 16-byte aggregate under SysV x86-64 is split across RDI:RSI,
        // and the next integer argument goes in RDX.
        let cc = sysv_x86_64();
        let args = vec![
            (ArgKind::Aggregate { size: 16 }, 16),
            (ArgKind::Integer, 8),
        ];
        let locs = assign_all_arguments(&cc, &args, false);
        match &locs[0] {
            ArgLocation::RegisterMulti(regs) => {
                assert_eq!(regs.len(), 2);
                assert_eq!(regs[0], RDI);
                assert_eq!(regs[1], RSI);
            }
            other => panic!("expected RegisterMulti, got {other:?}"),
        }
        assert!(matches!(locs[1], ArgLocation::Register(ref r) if r == &RDX));
    }

    #[test]
    fn test_shadow_space_ms_x64() {
        let cc = ms_x64();
        assert!(cc.shadow_space.is_some());
        assert_eq!(cc.shadow_space.as_ref().unwrap().size_bytes, 32);
    }

    #[test]
    fn test_this_reg_thiscall() {
        let cc = thiscall();
        assert_eq!(cc.this_reg, Some(ECX));
    }

    #[test]
    fn test_swift_special_regs() {
        let cc = swift_abi_x86_64();
        assert_eq!(cc.this_reg, Some(R13));
        assert_eq!(cc.error_reg, Some(R12));
    }

    #[test]
    fn test_variadic_va_list_sysv() {
        let cc = sysv_x86_64();
        let named = vec![(ArgKind::Integer, 8), (ArgKind::Float, 8)];
        let va = variadic_va_list_info(&cc, &named);
        assert!(va.is_some());
        let va = va.unwrap();
        assert_eq!(va.named_int_regs.len(), 1); // one int arg used RDI
        assert_eq!(va.named_fp_regs.len(), 1);  // one fp arg used XMM0
        assert!(va.count_reg.is_some());        // AL
    }

    #[test]
    fn test_variadic_not_supported_stdcall() {
        let cc = stdcall();
        let va = variadic_va_list_info(&cc, &[]);
        assert!(va.is_none());
    }

    #[test]
    fn test_frame_layout_ms_x64() {
        let cc = ms_x64();
        let layout = compute_frame_layout(&cc, 0);
        assert_eq!(layout.arg_area_size, 32); // only shadow space
        assert_eq!(layout.first_arg_offset, 32);
        assert_eq!(layout.return_addr_size, 8);
        assert_eq!(layout.frame_alignment, 16);
    }

    #[test]
    fn test_frame_layout_cdecl() {
        let cc = cdecl();
        let layout = compute_frame_layout(&cc, 16);
        assert_eq!(layout.arg_area_size, 16);
        assert_eq!(layout.first_arg_offset, 0);
        assert_eq!(layout.return_addr_size, 4);
    }

    #[test]
    fn test_by_arch_filter() {
        let db = CallingConventionDb::new();
        let x64 = db.by_arch(Arch::X86_64);
        assert!(!x64.is_empty());
        for cc in &x64 {
            assert_eq!(cc.arch, Arch::X86_64);
        }
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
    }
}
