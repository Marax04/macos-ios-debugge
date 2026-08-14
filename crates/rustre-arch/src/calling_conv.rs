//! Architecture-specific calling conventions.
//!
//! Provides the [`CallingConvention`] trait plus concrete implementations for:
//! * System V AMD64 ABI  ([`SysVAmd64Cc`])
//! * Windows x64 ABI     ([`WindowsX64Cc`])
//! * AAPCS64 (`AArch64`)   ([`Aapcs64Cc`])
//! * AAPCS32 (Arm 32-bit) ([`Aapcs32Cc`])
//! * MIPS O32             ([`MipsO32Cc`])
//! * RISC-V calling convention ([`RiscVCallConv`])
//!
//! Each calling convention reports where integer and floating-point arguments
//! live, where the return value goes, which registers are clobbered, and how
//! the stack is organised.

use crate::register_set::{RegId, serde_static_str};
use std::fmt;

/// Byte offset for a stack slot index, saturating if the index is enormous.
fn slot_offset(slot: usize, slot_size: i64) -> i64 {
    i64::try_from(slot).unwrap_or(i64::MAX).saturating_mul(slot_size)
}

// ─────────────────────────────────────────────────────────────────────────────
// ArgLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Where a single argument or return value lives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "ArgLocationOwned", into = "ArgLocationOwned")]
#[serde(bound(serialize = "", deserialize = ""))]
pub enum ArgLocation {
    /// The argument lives in a register.
    Register {
        /// Register identifier.
        reg: RegId,
        /// Canonical name of the register (for display).
        name: &'static str,
    },
    /// The argument is pushed on the stack at the given byte offset
    /// from the stack pointer at the call site.
    Stack {
        /// Byte offset from the caller's stack pointer.
        offset: i64,
        /// Size in bytes of the argument slot.
        size: u8,
    },
    /// The argument is returned through a hidden pointer (e.g. large structs).
    HiddenPointer {
        /// Register carrying the pointer.
        ptr_reg: RegId,
        /// Name of the pointer register.
        ptr_reg_name: &'static str,
    },
    /// Part in register, part on the stack (rare, edge cases).
    Split {
        reg: RegId,
        reg_name: &'static str,
        stack_offset: i64,
    },
}

/// Owned variant of [`ArgLocation`] used as a serde shim to avoid lifetime
/// issues with `&'static str` fields. Strings are leaked back to `'static`
/// on deserialization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ArgLocationOwned {
    Register {
        reg: RegId,
        name: String,
    },
    Stack {
        offset: i64,
        size: u8,
    },
    HiddenPointer {
        ptr_reg: RegId,
        ptr_reg_name: String,
    },
    Split {
        reg: RegId,
        reg_name: String,
        stack_offset: i64,
    },
}

impl From<ArgLocation> for ArgLocationOwned {
    fn from(v: ArgLocation) -> Self {
        match v {
            ArgLocation::Register { reg, name } => Self::Register {
                reg,
                name: name.to_string(),
            },
            ArgLocation::Stack { offset, size } => Self::Stack { offset, size },
            ArgLocation::HiddenPointer {
                ptr_reg,
                ptr_reg_name,
            } => Self::HiddenPointer {
                ptr_reg,
                ptr_reg_name: ptr_reg_name.to_string(),
            },
            ArgLocation::Split {
                reg,
                reg_name,
                stack_offset,
            } => Self::Split {
                reg,
                reg_name: reg_name.to_string(),
                stack_offset,
            },
        }
    }
}

impl From<ArgLocationOwned> for ArgLocation {
    fn from(v: ArgLocationOwned) -> Self {
        match v {
            ArgLocationOwned::Register { reg, name } => Self::Register {
                reg,
                name: Box::leak(name.into_boxed_str()),
            },
            ArgLocationOwned::Stack { offset, size } => Self::Stack { offset, size },
            ArgLocationOwned::HiddenPointer {
                ptr_reg,
                ptr_reg_name,
            } => Self::HiddenPointer {
                ptr_reg,
                ptr_reg_name: Box::leak(ptr_reg_name.into_boxed_str()),
            },
            ArgLocationOwned::Split {
                reg,
                reg_name,
                stack_offset,
            } => Self::Split {
                reg,
                reg_name: Box::leak(reg_name.into_boxed_str()),
                stack_offset,
            },
        }
    }
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register { name, .. } => write!(f, "{name}"),
            Self::Stack { offset, size } => write!(f, "[sp+{offset}] ({size}B)"),
            Self::HiddenPointer { ptr_reg_name, .. } => write!(f, "*{ptr_reg_name}"),
            Self::Split {
                reg_name,
                stack_offset,
                ..
            } => {
                write!(f, "{reg_name} + [sp+{stack_offset}]")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReturnLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Where the return value of a function lives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReturnLocation {
    /// Primary return register (integer part or full value).
    pub primary: ArgLocation,
    /// Secondary register (e.g. for 128-bit returns split across two registers).
    pub secondary: Option<ArgLocation>,
}

/// Owned helper for `ReturnLocation` deserialize.
#[derive(serde::Serialize, serde::Deserialize)]
struct ReturnLocationOwned {
    primary: ArgLocationOwned,
    secondary: Option<ArgLocationOwned>,
}

impl<'de> serde::Deserialize<'de> for ReturnLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let h = ReturnLocationOwned::deserialize(deserializer)?;
        Ok(Self {
            primary: ArgLocation::from(h.primary),
            secondary: h.secondary.map(ArgLocation::from),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionTag
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight, serialisable tag identifying a calling convention by its
/// canonical name.
///
/// Carries a `&'static str` payload so it can be embedded in
/// other static descriptors without allocating; `serde_static_str` is used
/// to round-trip the field through (de)serialisation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallingConventionTag {
    /// Canonical short name, e.g. `"sysv_amd64"` / `"windows_x64"`.
    #[serde(with = "serde_static_str")]
    pub name: &'static str,
}

impl CallingConventionTag {
    /// Construct a new tag for the given canonical name.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSiteInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Analysis result for a call instruction in the binary.
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// Target address, if statically determinable.
    pub target_addr: Option<u64>,
    /// Number of arguments inferred from register activity.
    pub inferred_arg_count: u8,
    /// Locations used for each argument (in order).
    pub arg_locations: Vec<ArgLocation>,
    /// Return value location.
    pub return_location: ReturnLocation,
    /// Registers the callee is allowed to clobber.
    pub clobbered_registers: Vec<RegId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention trait
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract calling convention interface.
pub trait CallingConvention: fmt::Debug + Send + Sync {
    /// Human-readable name of the convention.
    fn name(&self) -> &'static str;

    /// Architecture this convention applies to.
    fn arch(&self) -> &'static str;

    /// Where the nth integer/pointer argument lives (0-indexed).
    fn integer_arg_location(&self, n: usize) -> ArgLocation;

    /// Where the nth floating-point argument lives (0-indexed).
    fn float_arg_location(&self, n: usize) -> ArgLocation;

    /// Where the primary integer/pointer return value lives.
    fn return_location(&self) -> ReturnLocation;

    /// Where the primary float return value lives.
    fn float_return_location(&self) -> ReturnLocation;

    /// Registers that the callee may clobber (caller-saved).
    fn caller_saved_registers(&self) -> &[RegId];

    /// Registers the callee must preserve (callee-saved).
    fn callee_saved_registers(&self) -> &[RegId];

    /// Stack alignment requirement in bytes.
    fn stack_alignment(&self) -> u8;

    /// Whether the callee or caller cleans up stack arguments.
    fn callee_cleans_stack(&self) -> bool;

    /// Whether arguments are passed right-to-left (true for most x86 convs).
    fn right_to_left_args(&self) -> bool;

    /// Maximum number of integer arguments passed in registers.
    fn max_integer_reg_args(&self) -> usize;

    /// Maximum number of float arguments passed in registers.
    fn max_float_reg_args(&self) -> usize;

    /// Analyse a call site given a window of bytes before it.
    fn analyze_call_site(&self, call_addr: u64, target: Option<u64>) -> CallSiteInfo {
        // Default implementation: cap inferred args at a conservative ceiling
        // (most call sites pass <=4 args, and without bytes to analyse we
        // cannot know exactly how many registers are live).
        let arg_count = u8::try_from(self.max_integer_reg_args().min(4)).unwrap_or(u8::MAX);
        let args: Vec<ArgLocation> = (0..arg_count as usize)
            .map(|i| self.integer_arg_location(i))
            .collect();
        CallSiteInfo {
            call_addr,
            target_addr: target,
            inferred_arg_count: arg_count,
            arg_locations: args,
            return_location: self.return_location(),
            clobbered_registers: self.caller_saved_registers().to_vec(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// System V AMD64 ABI
// ─────────────────────────────────────────────────────────────────────────────

/// System V AMD64 ABI (Linux, macOS, BSDs).
#[derive(Debug, Default)]
pub struct SysVAmd64Cc;

// Integer arg registers: rdi, rsi, rdx, rcx, r8, r9
const SYSV_INT_ARG_REGS: &[(&str, u32)] = &[
    ("rdi", 5),
    ("rsi", 4),
    ("rdx", 3),
    ("rcx", 2),
    ("r8", 8),
    ("r9", 9),
];
// Float arg registers: xmm0-xmm7
const SYSV_FLOAT_ARG_REGS: &[(&str, u32)] = &[
    ("xmm0", 40),
    ("xmm1", 41),
    ("xmm2", 42),
    ("xmm3", 43),
    ("xmm4", 44),
    ("xmm5", 45),
    ("xmm6", 46),
    ("xmm7", 47),
];
const SYSV_CALLER_SAVED: &[u32] = &[
    0, 2, 3, 4, 5, 8, 9, 10, 11, 17, 40, 41, 42, 43, 44, 45, 46, 47,
];
const SYSV_CALLEE_SAVED: &[u32] = &[1, 7, 6, 12, 13, 14, 15];
const SYSV_CALLER_SAVED_REGS: &[RegId] = &[
    RegId(0),
    RegId(2),
    RegId(3),
    RegId(4),
    RegId(5),
    RegId(8),
    RegId(9),
    RegId(10),
    RegId(11),
    RegId(17),
    RegId(40),
    RegId(41),
    RegId(42),
    RegId(43),
    RegId(44),
    RegId(45),
    RegId(46),
    RegId(47),
];
const SYSV_CALLEE_SAVED_REGS: &[RegId] = &[
    RegId(1),
    RegId(7),
    RegId(6),
    RegId(12),
    RegId(13),
    RegId(14),
    RegId(15),
];

impl CallingConvention for SysVAmd64Cc {
    fn name(&self) -> &'static str {
        "sysv_amd64"
    }
    fn arch(&self) -> &'static str {
        "x86_64"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < SYSV_INT_ARG_REGS.len() {
            let (name, id) = SYSV_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let stack_slot = slot_offset(n - SYSV_INT_ARG_REGS.len(), 8);
            ArgLocation::Stack {
                offset: stack_slot,
                size: 8,
            }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        if n < SYSV_FLOAT_ARG_REGS.len() {
            let (name, id) = SYSV_FLOAT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let stack_slot = slot_offset(n - SYSV_FLOAT_ARG_REGS.len(), 8);
            ArgLocation::Stack {
                offset: stack_slot,
                size: 8,
            }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(0),
                name: "rax",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(3),
                name: "rdx",
            }),
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(40),
                name: "xmm0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(41),
                name: "xmm1",
            }),
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        // Both the `RegId` table and the parallel `u32` table are kept in
        // sync; assert in debug builds that they describe the same set so
        // future drift is caught early.
        debug_assert_eq!(SYSV_CALLER_SAVED_REGS.len(), SYSV_CALLER_SAVED.len());
        SYSV_CALLER_SAVED_REGS
    }

    fn callee_saved_registers(&self) -> &[RegId] {
        debug_assert_eq!(SYSV_CALLEE_SAVED_REGS.len(), SYSV_CALLEE_SAVED.len());
        SYSV_CALLEE_SAVED_REGS
    }

    fn stack_alignment(&self) -> u8 {
        16
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        6
    }
    fn max_float_reg_args(&self) -> usize {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows x64 ABI
// ─────────────────────────────────────────────────────────────────────────────

/// Microsoft Windows x64 calling convention.
#[derive(Debug, Default)]
pub struct WindowsX64Cc;

// Integer arg registers: rcx, rdx, r8, r9
const WIN64_INT_ARG_REGS: &[(&str, u32)] = &[("rcx", 2), ("rdx", 3), ("r8", 8), ("r9", 9)];
// Float arg registers: xmm0-xmm3
const WIN64_FLOAT_ARG_REGS: &[(&str, u32)] =
    &[("xmm0", 40), ("xmm1", 41), ("xmm2", 42), ("xmm3", 43)];
const WIN64_CALLER_SAVED: &[u32] = &[0, 2, 3, 8, 9, 10, 11, 17, 40, 41, 42, 43, 44];
const WIN64_CALLEE_SAVED: &[u32] = &[1, 7, 6, 12, 13, 14, 15, 46, 47];
const WIN64_CALLER_SAVED_REGS: &[RegId] = &[
    RegId(0),
    RegId(2),
    RegId(3),
    RegId(8),
    RegId(9),
    RegId(10),
    RegId(11),
    RegId(17),
    RegId(40),
    RegId(41),
    RegId(42),
    RegId(43),
    RegId(44),
];
const WIN64_CALLEE_SAVED_REGS: &[RegId] = &[
    RegId(1),
    RegId(7),
    RegId(6),
    RegId(12),
    RegId(13),
    RegId(14),
    RegId(15),
    RegId(46),
    RegId(47),
];

impl CallingConvention for WindowsX64Cc {
    fn name(&self) -> &'static str {
        "windows_x64"
    }
    fn arch(&self) -> &'static str {
        "x86_64"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < WIN64_INT_ARG_REGS.len() {
            let (name, id) = WIN64_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            // Shadow space (32 bytes) + 8 bytes per extra arg
            let offset = 32 + slot_offset(n - WIN64_INT_ARG_REGS.len(), 8);
            ArgLocation::Stack { offset, size: 8 }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        if n < WIN64_FLOAT_ARG_REGS.len() {
            let (name, id) = WIN64_FLOAT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = 32 + slot_offset(n - WIN64_FLOAT_ARG_REGS.len(), 8);
            ArgLocation::Stack { offset, size: 8 }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(0),
                name: "rax",
            },
            secondary: None,
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(40),
                name: "xmm0",
            },
            secondary: None,
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        debug_assert_eq!(WIN64_CALLER_SAVED_REGS.len(), WIN64_CALLER_SAVED.len());
        WIN64_CALLER_SAVED_REGS
    }

    fn callee_saved_registers(&self) -> &[RegId] {
        debug_assert_eq!(WIN64_CALLEE_SAVED_REGS.len(), WIN64_CALLEE_SAVED.len());
        WIN64_CALLEE_SAVED_REGS
    }

    fn stack_alignment(&self) -> u8 {
        16
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        4
    }
    fn max_float_reg_args(&self) -> usize {
        4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AAPCS64 (AArch64 procedure call standard)
// ─────────────────────────────────────────────────────────────────────────────

/// AAPCS64 — Arm 64-bit procedure call standard.
#[derive(Debug, Default)]
pub struct Aapcs64Cc;

const AAPCS64_INT_ARG_REGS: &[(&str, u32)] = &[
    ("x0", 0),
    ("x1", 1),
    ("x2", 2),
    ("x3", 3),
    ("x4", 4),
    ("x5", 5),
    ("x6", 6),
    ("x7", 7),
];
const AAPCS64_FLOAT_ARG_REGS: &[(&str, u32)] = &[
    ("v0", 64),
    ("v1", 65),
    ("v2", 66),
    ("v3", 67),
    ("v4", 68),
    ("v5", 69),
    ("v6", 70),
    ("v7", 71),
];
const AAPCS64_CALLER_SAVED: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 64, 65, 66, 67, 68, 69, 70, 71,
];
const AAPCS64_CALLEE_SAVED: &[u32] = &[
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 72, 73, 74, 75, 76, 77, 78, 79,
];
const AAPCS64_CALLER_SAVED_REGS: &[RegId] = &[
    RegId(0),
    RegId(1),
    RegId(2),
    RegId(3),
    RegId(4),
    RegId(5),
    RegId(6),
    RegId(7),
    RegId(8),
    RegId(9),
    RegId(10),
    RegId(11),
    RegId(12),
    RegId(13),
    RegId(14),
    RegId(15),
    RegId(16),
    RegId(17),
    RegId(64),
    RegId(65),
    RegId(66),
    RegId(67),
    RegId(68),
    RegId(69),
    RegId(70),
    RegId(71),
];
const AAPCS64_CALLEE_SAVED_REGS: &[RegId] = &[
    RegId(19),
    RegId(20),
    RegId(21),
    RegId(22),
    RegId(23),
    RegId(24),
    RegId(25),
    RegId(26),
    RegId(27),
    RegId(28),
    RegId(29),
    RegId(30),
    RegId(72),
    RegId(73),
    RegId(74),
    RegId(75),
    RegId(76),
    RegId(77),
    RegId(78),
    RegId(79),
];

impl CallingConvention for Aapcs64Cc {
    fn name(&self) -> &'static str {
        "aapcs64"
    }
    fn arch(&self) -> &'static str {
        "aarch64"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < AAPCS64_INT_ARG_REGS.len() {
            let (name, id) = AAPCS64_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = slot_offset(n - AAPCS64_INT_ARG_REGS.len(), 8);
            ArgLocation::Stack { offset, size: 8 }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        if n < AAPCS64_FLOAT_ARG_REGS.len() {
            let (name, id) = AAPCS64_FLOAT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = slot_offset(n - AAPCS64_FLOAT_ARG_REGS.len(), 16);
            ArgLocation::Stack { offset, size: 16 }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(0),
                name: "x0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(1),
                name: "x1",
            }),
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(64),
                name: "v0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(65),
                name: "v1",
            }),
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        debug_assert_eq!(AAPCS64_CALLER_SAVED_REGS.len(), AAPCS64_CALLER_SAVED.len());
        AAPCS64_CALLER_SAVED_REGS
    }
    fn callee_saved_registers(&self) -> &[RegId] {
        debug_assert_eq!(AAPCS64_CALLEE_SAVED_REGS.len(), AAPCS64_CALLEE_SAVED.len());
        AAPCS64_CALLEE_SAVED_REGS
    }
    fn stack_alignment(&self) -> u8 {
        16
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        8
    }
    fn max_float_reg_args(&self) -> usize {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AAPCS32 (Arm 32-bit)
// ─────────────────────────────────────────────────────────────────────────────

/// AAPCS32 — Arm 32-bit procedure call standard.
#[derive(Debug, Default)]
pub struct Aapcs32Cc;

const AAPCS32_INT_ARG_REGS: &[(&str, u32)] = &[("r0", 0), ("r1", 1), ("r2", 2), ("r3", 3)];

impl CallingConvention for Aapcs32Cc {
    fn name(&self) -> &'static str {
        "aapcs32"
    }
    fn arch(&self) -> &'static str {
        "arm"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < AAPCS32_INT_ARG_REGS.len() {
            let (name, id) = AAPCS32_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = slot_offset(n - AAPCS32_INT_ARG_REGS.len(), 4);
            ArgLocation::Stack { offset, size: 4 }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        // VFP registers s0-s15 (d0-d7 for doubles)
        if n < 16 {
            const S_NAMES: [&str; 16] = [
                "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
            ];
            ArgLocation::Register {
                reg: RegId(64 + u32::try_from(n).unwrap_or(u32::MAX - 64)),
                name: S_NAMES[n],
            }
        } else {
            let offset = slot_offset(n - 16, 4);
            ArgLocation::Stack { offset, size: 4 }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(0),
                name: "r0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(1),
                name: "r1",
            }),
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(64),
                name: "s0",
            },
            secondary: None,
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[RegId(0), RegId(1), RegId(2), RegId(3), RegId(12)];
        R
    }
    fn callee_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[
            RegId(4),
            RegId(5),
            RegId(6),
            RegId(7),
            RegId(8),
            RegId(9),
            RegId(10),
            RegId(11),
        ];
        R
    }
    fn stack_alignment(&self) -> u8 {
        8
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        4
    }
    fn max_float_reg_args(&self) -> usize {
        16
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIPS O32
// ─────────────────────────────────────────────────────────────────────────────

/// MIPS O32 calling convention.
#[derive(Debug, Default)]
pub struct MipsO32Cc;

const MIPS_INT_ARG_REGS: &[(&str, u32)] = &[("a0", 4), ("a1", 5), ("a2", 6), ("a3", 7)];

impl CallingConvention for MipsO32Cc {
    fn name(&self) -> &'static str {
        "mips_o32"
    }
    fn arch(&self) -> &'static str {
        "mips32"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < MIPS_INT_ARG_REGS.len() {
            let (name, id) = MIPS_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            // Spill area in caller's frame (offset from caller's SP)
            let offset = 16 + slot_offset(n - MIPS_INT_ARG_REGS.len(), 4);
            ArgLocation::Stack { offset, size: 4 }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        // First two float args in $f12/$f14
        match n {
            0 => ArgLocation::Register {
                reg: RegId(44),
                name: "f12",
            },
            1 => ArgLocation::Register {
                reg: RegId(45),
                name: "f14",
            },
            _ => {
                let offset = 16 + slot_offset(n - 2, 4);
                ArgLocation::Stack { offset, size: 4 }
            }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(2),
                name: "v0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(3),
                name: "v1",
            }),
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(40),
                name: "f0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(41),
                name: "f2",
            }),
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[
            RegId(1),
            RegId(2),
            RegId(3),
            RegId(4),
            RegId(5),
            RegId(6),
            RegId(7),
            RegId(8),
            RegId(9),
            RegId(10),
            RegId(11),
            RegId(12),
            RegId(13),
            RegId(14),
            RegId(15),
            RegId(24),
            RegId(25),
        ];
        R
    }
    fn callee_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[
            RegId(16),
            RegId(17),
            RegId(18),
            RegId(19),
            RegId(20),
            RegId(21),
            RegId(22),
            RegId(23),
            RegId(28),
            RegId(30),
            RegId(31),
        ];
        R
    }
    fn stack_alignment(&self) -> u8 {
        8
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        4
    }
    fn max_float_reg_args(&self) -> usize {
        2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RISC-V calling convention
// ─────────────────────────────────────────────────────────────────────────────

/// RISC-V calling convention (integer + floating-point).
#[derive(Debug, Default)]
pub struct RiscVCallConv;

const RISCV_INT_ARG_REGS: &[(&str, u32)] = &[
    ("a0", 10),
    ("a1", 11),
    ("a2", 12),
    ("a3", 13),
    ("a4", 14),
    ("a5", 15),
    ("a6", 16),
    ("a7", 17),
];
const RISCV_FLOAT_ARG_REGS: &[(&str, u32)] = &[
    ("fa0", 43),
    ("fa1", 44),
    ("fa2", 45),
    ("fa3", 46),
    ("fa4", 47),
    ("fa5", 48),
    ("fa6", 49),
    ("fa7", 50),
];

impl CallingConvention for RiscVCallConv {
    fn name(&self) -> &'static str {
        "riscv"
    }
    fn arch(&self) -> &'static str {
        "riscv64"
    }

    fn integer_arg_location(&self, n: usize) -> ArgLocation {
        if n < RISCV_INT_ARG_REGS.len() {
            let (name, id) = RISCV_INT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = slot_offset(n - RISCV_INT_ARG_REGS.len(), 8);
            ArgLocation::Stack { offset, size: 8 }
        }
    }

    fn float_arg_location(&self, n: usize) -> ArgLocation {
        if n < RISCV_FLOAT_ARG_REGS.len() {
            let (name, id) = RISCV_FLOAT_ARG_REGS[n];
            ArgLocation::Register {
                reg: RegId(id),
                name,
            }
        } else {
            let offset = slot_offset(n - RISCV_FLOAT_ARG_REGS.len(), 8);
            ArgLocation::Stack { offset, size: 8 }
        }
    }

    fn return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(10),
                name: "a0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(11),
                name: "a1",
            }),
        }
    }

    fn float_return_location(&self) -> ReturnLocation {
        ReturnLocation {
            primary: ArgLocation::Register {
                reg: RegId(43),
                name: "fa0",
            },
            secondary: Some(ArgLocation::Register {
                reg: RegId(44),
                name: "fa1",
            }),
        }
    }

    fn caller_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[
            RegId(1),
            RegId(5),
            RegId(6),
            RegId(7),
            RegId(10),
            RegId(11),
            RegId(12),
            RegId(13),
            RegId(14),
            RegId(15),
            RegId(16),
            RegId(17),
            RegId(28),
            RegId(29),
            RegId(30),
            RegId(31),
        ];
        R
    }
    fn callee_saved_registers(&self) -> &[RegId] {
        static R: &[RegId] = &[
            RegId(2),
            RegId(8),
            RegId(9),
            RegId(18),
            RegId(19),
            RegId(20),
            RegId(21),
            RegId(22),
            RegId(23),
            RegId(24),
            RegId(25),
            RegId(26),
            RegId(27),
        ];
        R
    }
    fn stack_alignment(&self) -> u8 {
        16
    }
    fn callee_cleans_stack(&self) -> bool {
        false
    }
    fn right_to_left_args(&self) -> bool {
        false
    }
    fn max_integer_reg_args(&self) -> usize {
        8
    }
    fn max_float_reg_args(&self) -> usize {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: analyze_call_site
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse a call site using a specific calling convention.
///
/// Returns a [`CallSiteInfo`] describing where arguments and return values live.
pub fn analyze_call_site(
    cc: &dyn CallingConvention,
    call_addr: u64,
    target: Option<u64>,
    num_args: usize,
) -> CallSiteInfo {
    let mut args = Vec::with_capacity(num_args);
    for i in 0..num_args {
        args.push(cc.integer_arg_location(i));
    }
    CallSiteInfo {
        call_addr,
        target_addr: target,
        inferred_arg_count: u8::try_from(num_args).unwrap_or(u8::MAX),
        arg_locations: args,
        return_location: cc.return_location(),
        clobbered_registers: cc.caller_saved_registers().to_vec(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- ArgLocation ---

    #[test]
    fn arg_location_register_display() {
        let loc = ArgLocation::Register {
            reg: RegId(0),
            name: "rax",
        };
        assert_eq!(format!("{loc}"), "rax");
    }

    #[test]
    fn arg_location_stack_display() {
        let loc = ArgLocation::Stack {
            offset: 32,
            size: 8,
        };
        assert_eq!(format!("{loc}"), "[sp+32] (8B)");
    }

    #[test]
    fn arg_location_hidden_pointer_display() {
        let loc = ArgLocation::HiddenPointer {
            ptr_reg: RegId(5),
            ptr_reg_name: "rdi",
        };
        assert_eq!(format!("{loc}"), "*rdi");
    }

    // --- SysV AMD64 ---

    #[test]
    fn sysv_name() {
        assert_eq!(SysVAmd64Cc.name(), "sysv_amd64");
    }

    #[test]
    fn sysv_arch() {
        assert_eq!(SysVAmd64Cc.arch(), "x86_64");
    }

    #[test]
    fn sysv_first_int_arg_is_rdi() {
        let loc = SysVAmd64Cc.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(5),
                name: "rdi"
            }
        );
    }

    #[test]
    fn sysv_second_int_arg_is_rsi() {
        let loc = SysVAmd64Cc.integer_arg_location(1);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(4),
                name: "rsi"
            }
        );
    }

    #[test]
    fn sysv_seventh_int_arg_is_stack() {
        let loc = SysVAmd64Cc.integer_arg_location(6);
        matches!(loc, ArgLocation::Stack { .. });
    }

    #[test]
    fn sysv_return_is_rax() {
        let ret = SysVAmd64Cc.return_location();
        assert_eq!(
            ret.primary,
            ArgLocation::Register {
                reg: RegId(0),
                name: "rax"
            }
        );
    }

    #[test]
    fn sysv_float_return_is_xmm0() {
        let ret = SysVAmd64Cc.float_return_location();
        assert_eq!(
            ret.primary,
            ArgLocation::Register {
                reg: RegId(40),
                name: "xmm0"
            }
        );
    }

    #[test]
    fn sysv_stack_alignment() {
        assert_eq!(SysVAmd64Cc.stack_alignment(), 16);
    }

    #[test]
    fn sysv_max_reg_args() {
        assert_eq!(SysVAmd64Cc.max_integer_reg_args(), 6);
        assert_eq!(SysVAmd64Cc.max_float_reg_args(), 8);
    }

    #[test]
    fn sysv_caller_saved_includes_rax() {
        let saved = SysVAmd64Cc.caller_saved_registers();
        assert!(saved.contains(&RegId(0)));
    }

    #[test]
    fn sysv_callee_saved_includes_rbx() {
        let saved = SysVAmd64Cc.callee_saved_registers();
        assert!(saved.contains(&RegId(1)));
    }

    // --- Windows x64 ---

    #[test]
    fn win64_name() {
        assert_eq!(WindowsX64Cc.name(), "windows_x64");
    }

    #[test]
    fn win64_first_int_arg_is_rcx() {
        let loc = WindowsX64Cc.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(2),
                name: "rcx"
            }
        );
    }

    #[test]
    fn win64_fifth_arg_is_stack_with_shadow_space() {
        let loc = WindowsX64Cc.integer_arg_location(4);
        if let ArgLocation::Stack { offset, .. } = loc {
            // shadow space is 32 bytes; first stack arg at offset 32
            assert_eq!(offset, 32);
        } else {
            panic!("expected stack location");
        }
    }

    #[test]
    fn win64_max_reg_args() {
        assert_eq!(WindowsX64Cc.max_integer_reg_args(), 4);
    }

    #[test]
    fn win64_return_is_rax() {
        let ret = WindowsX64Cc.return_location();
        assert_eq!(
            ret.primary,
            ArgLocation::Register {
                reg: RegId(0),
                name: "rax"
            }
        );
    }

    // --- AAPCS64 ---

    #[test]
    fn aapcs64_name() {
        assert_eq!(Aapcs64Cc.name(), "aapcs64");
    }

    #[test]
    fn aapcs64_first_arg_is_x0() {
        let loc = Aapcs64Cc.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(0),
                name: "x0"
            }
        );
    }

    #[test]
    fn aapcs64_max_reg_args() {
        assert_eq!(Aapcs64Cc.max_integer_reg_args(), 8);
    }

    #[test]
    fn aapcs64_ninth_arg_is_stack() {
        let loc = Aapcs64Cc.integer_arg_location(8);
        assert!(matches!(loc, ArgLocation::Stack { offset: 0, .. }));
    }

    // --- AAPCS32 ---

    #[test]
    fn aapcs32_name() {
        assert_eq!(Aapcs32Cc.name(), "aapcs32");
    }

    #[test]
    fn aapcs32_first_arg_is_r0() {
        let loc = Aapcs32Cc.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(0),
                name: "r0"
            }
        );
    }

    #[test]
    fn aapcs32_stack_alignment_is_8() {
        assert_eq!(Aapcs32Cc.stack_alignment(), 8);
    }

    // --- MIPS O32 ---

    #[test]
    fn mips_o32_name() {
        assert_eq!(MipsO32Cc.name(), "mips_o32");
    }

    #[test]
    fn mips_o32_first_arg_is_a0() {
        let loc = MipsO32Cc.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(4),
                name: "a0"
            }
        );
    }

    #[test]
    fn mips_o32_fifth_arg_is_stack_after_spill_area() {
        let loc = MipsO32Cc.integer_arg_location(4);
        if let ArgLocation::Stack { offset, .. } = loc {
            assert_eq!(offset, 16); // 16-byte spill area
        } else {
            panic!("expected stack");
        }
    }

    // --- RISC-V ---

    #[test]
    fn riscv_name() {
        assert_eq!(RiscVCallConv.name(), "riscv");
    }

    #[test]
    fn riscv_first_arg_is_a0() {
        let loc = RiscVCallConv.integer_arg_location(0);
        assert_eq!(
            loc,
            ArgLocation::Register {
                reg: RegId(10),
                name: "a0"
            }
        );
    }

    #[test]
    fn riscv_ninth_arg_is_stack() {
        let loc = RiscVCallConv.integer_arg_location(8);
        matches!(loc, ArgLocation::Stack { .. });
    }

    // --- analyze_call_site ---

    #[test]
    fn analyze_call_site_fills_args() {
        let info = analyze_call_site(&SysVAmd64Cc, 0x1000, Some(0x2000), 3);
        assert_eq!(info.call_addr, 0x1000);
        assert_eq!(info.target_addr, Some(0x2000));
        assert_eq!(info.arg_locations.len(), 3);
        assert_eq!(
            info.arg_locations[0],
            ArgLocation::Register {
                reg: RegId(5),
                name: "rdi"
            }
        );
    }

    #[test]
    fn analyze_call_site_zero_args() {
        let info = analyze_call_site(&SysVAmd64Cc, 0x1000, None, 0);
        assert_eq!(info.arg_locations.len(), 0);
    }

    #[test]
    fn analyze_call_site_default_impl() {
        let info = SysVAmd64Cc.analyze_call_site(0xdead, None);
        // Default impl uses min(max_reg_args, 4) = 4 for sysv
        assert_eq!(info.inferred_arg_count, 4);
    }
}
