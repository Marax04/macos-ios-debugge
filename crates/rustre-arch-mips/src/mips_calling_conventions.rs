//! MIPS calling conventions: O32, N32, and N64.
//!
//! The three standard MIPS ABI calling conventions differ primarily in how
//! integer arguments are passed (word width), how many registers are used for
//! argument passing, and how the stack frame is laid out.
//!
//! References:
//! - MIPS32 ABI Supplement (O32)
//! - MIPS64 ABI Supplement (N32 / N64)
//! - System V ABI MIPS Supplement

use std::fmt;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Register numbers (MIPS architectural numbering)
// ---------------------------------------------------------------------------

/// MIPS general-purpose register number (0–31).
pub type RegNum = u8;

/// Named MIPS general-purpose registers used in calling conventions.
pub mod regs {
    use super::RegNum;
    pub const ZERO: RegNum = 0;
    pub const AT: RegNum = 1;
    pub const V0: RegNum = 2;
    pub const V1: RegNum = 3;
    pub const A0: RegNum = 4;
    pub const A1: RegNum = 5;
    pub const A2: RegNum = 6;
    pub const A3: RegNum = 7;
    // N32/N64 extended argument registers
    pub const A4: RegNum = 8;
    pub const A5: RegNum = 9;
    pub const A6: RegNum = 10;
    pub const A7: RegNum = 11;
    pub const T0: RegNum = 8;   // O32 temporaries overlap N32/N64 a4..a7
    pub const T1: RegNum = 9;
    pub const T2: RegNum = 10;
    pub const T3: RegNum = 11;
    pub const T4: RegNum = 12;
    pub const T5: RegNum = 13;
    pub const T6: RegNum = 14;
    pub const T7: RegNum = 15;
    pub const S0: RegNum = 16;
    pub const S1: RegNum = 17;
    pub const S2: RegNum = 18;
    pub const S3: RegNum = 19;
    pub const S4: RegNum = 20;
    pub const S5: RegNum = 21;
    pub const S6: RegNum = 22;
    pub const S7: RegNum = 23;
    pub const T8: RegNum = 24;
    pub const T9: RegNum = 25;
    pub const K0: RegNum = 26;
    pub const K1: RegNum = 27;
    pub const GP: RegNum = 28;
    pub const SP: RegNum = 29;
    pub const FP: RegNum = 30; // also S8
    pub const RA: RegNum = 31;

    // FPU registers used for floating-point argument passing
    pub const F0: RegNum = 0;   // float return value
    pub const F1: RegNum = 1;
    pub const F12: RegNum = 12; // O32 first fp arg
    pub const F13: RegNum = 13;
    pub const F14: RegNum = 14; // O32 second fp arg
    pub const F15: RegNum = 15;
}

// ---------------------------------------------------------------------------
// ArgRegister
// ---------------------------------------------------------------------------

/// Describes a single argument register in a calling convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgRegister {
    /// Architectural register number.
    pub number: RegNum,
    /// Human-readable name (e.g. `"$a0"`).
    pub name: &'static str,
    /// Width in bytes (4 for O32, 8 for N32/N64).
    pub width_bytes: u8,
    /// Whether this register passes floating-point arguments.
    pub is_fpu: bool,
}

impl ArgRegister {
    /// Create a new integer argument register.
    #[must_use]
    pub const fn gpr(number: RegNum, name: &'static str, width_bytes: u8) -> Self {
        Self { number, name, width_bytes, is_fpu: false }
    }

    /// Create a new FPU argument register.
    #[must_use]
    pub const fn fpu(number: RegNum, name: &'static str, width_bytes: u8) -> Self {
        Self { number, name, width_bytes, is_fpu: true }
    }
}

impl fmt::Display for ArgRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, if self.is_fpu { "fpu" } else { "gpr" })
    }
}

// ---------------------------------------------------------------------------
// StackSlot
// ---------------------------------------------------------------------------

/// A stack-based argument slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    /// Byte offset from the stack pointer at the call site.
    pub offset: i32,
    /// Size of the slot in bytes.
    pub size: u8,
    /// Index of the argument (0-based).
    pub arg_index: usize,
}

impl StackSlot {
    /// Create a new `StackSlot`.
    #[must_use]
    pub const fn new(offset: i32, size: u8, arg_index: usize) -> Self {
        Self { offset, size, arg_index }
    }
}

// ---------------------------------------------------------------------------
// ArgLocation
// ---------------------------------------------------------------------------

/// Where a single argument lives — in a register or on the stack.
#[derive(Debug, Clone)]
pub enum ArgLocation {
    /// Argument is passed in an integer/pointer register.
    Register(ArgRegister),
    /// Argument is passed on the stack.
    Stack(StackSlot),
    /// Argument is split: part in a register, part on the stack (O32 edge cases).
    SplitRegStack {
        /// The high part in a register.
        reg: ArgRegister,
        /// The low part on the stack.
        stack: StackSlot,
    },
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{r}"),
            Self::Stack(s) => write!(f, "sp+{}", s.offset),
            Self::SplitRegStack { reg, stack } => {
                write!(f, "{}+sp+{}", reg.name, stack.offset)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MipsCallingConvention
// ---------------------------------------------------------------------------

/// The three standard MIPS calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsCallingConvention {
    /// Original 32-bit ABI: 4 argument registers ($a0–$a3), 32-bit GPR width.
    O32,
    /// New 32-bit ABI: 8 argument registers ($a0–$a7), 64-bit GPR width but
    /// 32-bit addressing.
    N32,
    /// New 64-bit ABI: 8 argument registers ($a0–$a7), 64-bit GPR and
    /// pointer width.
    N64,
}

impl Default for MipsCallingConvention {
    /// O32 is the most widely-used MIPS calling convention and is the
    /// sensible default when no ABI has been explicitly selected.
    fn default() -> Self {
        Self::O32
    }
}

impl fmt::Display for MipsCallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::O32 => f.write_str("O32"),
            Self::N32 => f.write_str("N32"),
            Self::N64 => f.write_str("N64"),
        }
    }
}

impl MipsCallingConvention {
    /// Width of a general-purpose integer register in bytes.
    #[must_use]
    pub const fn gpr_width(self) -> u8 {
        match self {
            Self::O32 => 4,
            Self::N32 | Self::N64 => 8,
        }
    }

    /// Width of a pointer in bytes.
    #[must_use]
    pub const fn pointer_width(self) -> u8 {
        match self {
            Self::O32 | Self::N32 => 4,
            Self::N64 => 8,
        }
    }

    /// Number of integer argument registers.
    #[must_use]
    pub const fn arg_reg_count(self) -> u8 {
        match self {
            Self::O32 => 4,
            Self::N32 | Self::N64 => 8,
        }
    }

    /// The integer argument registers for this convention.
    #[must_use]
    pub fn arg_registers(self) -> Vec<ArgRegister> {
        let w = self.gpr_width();
        match self {
            Self::O32 => vec![
                ArgRegister::gpr(regs::A0, "$a0", w),
                ArgRegister::gpr(regs::A1, "$a1", w),
                ArgRegister::gpr(regs::A2, "$a2", w),
                ArgRegister::gpr(regs::A3, "$a3", w),
            ],
            Self::N32 | Self::N64 => vec![
                ArgRegister::gpr(regs::A0, "$a0", w),
                ArgRegister::gpr(regs::A1, "$a1", w),
                ArgRegister::gpr(regs::A2, "$a2", w),
                ArgRegister::gpr(regs::A3, "$a3", w),
                ArgRegister::gpr(regs::A4, "$a4", w),
                ArgRegister::gpr(regs::A5, "$a5", w),
                ArgRegister::gpr(regs::A6, "$a6", w),
                ArgRegister::gpr(regs::A7, "$a7", w),
            ],
        }
    }

    /// The return-value registers (integer).
    #[must_use]
    pub fn return_registers(self) -> Vec<ArgRegister> {
        let w = self.gpr_width();
        vec![
            ArgRegister::gpr(regs::V0, "$v0", w),
            ArgRegister::gpr(regs::V1, "$v1", w),
        ]
    }

    /// Callee-saved (non-volatile) GPRs.
    #[must_use]
    pub fn callee_saved_regs(self) -> Vec<RegNum> {
        let mut regs = vec![
            regs::S0, regs::S1, regs::S2, regs::S3,
            regs::S4, regs::S5, regs::S6, regs::S7,
            regs::FP, regs::RA, regs::GP,
        ];
        // O32 also saves SP implicitly; all ABIs treat SP as callee-saved
        regs.push(regs::SP);
        regs
    }

    /// Caller-saved (volatile) GPRs.
    #[must_use]
    pub fn caller_saved_regs(self) -> Vec<RegNum> {
        match self {
            Self::O32 => vec![
                regs::AT,
                regs::V0, regs::V1,
                regs::A0, regs::A1, regs::A2, regs::A3,
                regs::T0, regs::T1, regs::T2, regs::T3,
                regs::T4, regs::T5, regs::T6, regs::T7,
                regs::T8, regs::T9,
            ],
            Self::N32 | Self::N64 => vec![
                regs::AT,
                regs::V0, regs::V1,
                regs::A0, regs::A1, regs::A2, regs::A3,
                regs::A4, regs::A5, regs::A6, regs::A7,
                regs::T8, regs::T9,
            ],
        }
    }

    /// Byte alignment of the stack at a call site.
    #[must_use]
    pub const fn stack_alignment(self) -> u32 {
        match self {
            Self::O32 => 8,
            Self::N32 | Self::N64 => 16,
        }
    }

    /// O32 allocates a 16-byte "home area" (argument save area) even when all
    /// arguments fit in registers.  N32/N64 do not.
    #[must_use]
    pub const fn has_home_area(self) -> bool {
        matches!(self, Self::O32)
    }

    /// Size of the home area (argument save area) on O32, or 0.
    #[must_use]
    pub const fn home_area_size(self) -> u32 {
        if self.has_home_area() { 16 } else { 0 }
    }

    /// Compute the stack offset of argument `arg_index` (0-based) given that
    /// the first `n_reg_args` arguments are passed in registers.
    ///
    /// Returns `None` if the argument is passed in a register.
    #[must_use]
    pub const fn stack_arg_offset(self, arg_index: usize) -> Option<i32> {
        stack_arg_offset(self, arg_index)
    }
}

// ---------------------------------------------------------------------------
// stack_arg_offset — core calculation
// ---------------------------------------------------------------------------

/// Compute the stack offset (from SP at callee entry) of the `arg_index`-th
/// argument (0-based) under `conv`.
///
/// Returns `None` if the argument is passed in a register.
///
/// # Details
///
/// - **O32**: Arguments 0–3 are in `$a0`–`$a3`.  The caller allocates 16 bytes
///   of home area below its saved RA; argument 4 is at `sp+16`, argument 5 at
///   `sp+20`, etc.
/// - **N32/N64**: Arguments 0–7 are in `$a0`–`$a7`.  Argument 8 is at `sp+0`,
///   argument 9 at `sp+8`, etc. (no home area).
#[must_use]
pub const fn stack_arg_offset(conv: MipsCallingConvention, arg_index: usize) -> Option<i32> {
    let reg_count = conv.arg_reg_count() as usize;
    if arg_index < reg_count {
        return None; // register-passed
    }
    let stack_index = arg_index - reg_count;
    let slot_size = match conv {
        MipsCallingConvention::O32 => 4i32,
        MipsCallingConvention::N32 | MipsCallingConvention::N64 => 8i32,
    };
    let base = conv.home_area_size().cast_signed();
    // `stack_index` counts the stack arguments of one call, so it is far
    // below `i32::MAX`; the mask makes that provable. Rebuilding the value
    // from its four low little-endian bytes is exact for any masked value
    // (the discarded bytes are all zero) and needs no `as`, so it can neither
    // truncate nor wrap on a 32-bit or a 64-bit `usize`.
    let masked = stack_index & 0x7FFF_FFFF;
    let b = masked.to_le_bytes();
    let index = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    Some(base + index * slot_size)
}

// ---------------------------------------------------------------------------
// CallSiteLayout — compute argument locations for a call
// ---------------------------------------------------------------------------

/// Describes the size and type of a single call argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// A machine-word-sized integer or pointer.
    Integer,
    /// A 32-bit float (passed in FPU reg on O32 if it is the first/second arg).
    Float32,
    /// A 64-bit double (passed in FPU reg pair on O32, or single FPU reg on N32/N64).
    Float64,
}

/// Input descriptor for a single argument at a call site.
#[derive(Debug, Clone)]
pub struct ArgDesc {
    /// Argument index (0-based).
    pub index: usize,
    /// Kind of the argument.
    pub kind: ArgKind,
}

impl ArgDesc {
    /// Create an integer/pointer argument descriptor.
    #[must_use]
    pub const fn int(index: usize) -> Self {
        Self { index, kind: ArgKind::Integer }
    }

    /// Create a float32 argument descriptor.
    #[must_use]
    pub const fn f32(index: usize) -> Self {
        Self { index, kind: ArgKind::Float32 }
    }

    /// Create a float64 argument descriptor.
    #[must_use]
    pub const fn f64(index: usize) -> Self {
        Self { index, kind: ArgKind::Float64 }
    }
}

/// The computed layout (register or stack slot) for every argument in a call.
#[derive(Debug, Clone)]
pub struct CallSiteLayout {
    /// Calling convention used.
    pub convention: MipsCallingConvention,
    /// Computed location for each argument.
    pub locations: Vec<ArgLocation>,
    /// Total stack space required for stack-passed arguments.
    pub stack_bytes: u32,
}

impl CallSiteLayout {
    /// Compute the argument layout for `args` under `conv`.
    #[must_use]
    pub fn compute(conv: MipsCallingConvention, args: &[ArgDesc]) -> Self {
        let gpr_regs = conv.arg_registers();
        let mut gpr_idx = 0usize;
        let mut stack_bytes = conv.home_area_size();
        let mut locations = Vec::with_capacity(args.len());

        for arg in args {
            // O32: first two FP args go in $f12/$f14 (f32) or $f12/$f13 (f64).
            // N32/N64: FP args go in $f12–$f19 paired with GPR slot consumption.
            // For simplicity we model O32 FPU only for the first two FP args.
            if conv == MipsCallingConvention::O32 {
                match arg.kind {
                    ArgKind::Float32 if gpr_idx < 2 => {
                        let fpu_num = if gpr_idx == 0 { regs::F12 } else { regs::F14 };
                        let fpu_name = if gpr_idx == 0 { "$f12" } else { "$f14" };
                        locations.push(ArgLocation::Register(ArgRegister::fpu(fpu_num, fpu_name, 4)));
                        gpr_idx += 1; // consumes one GPR slot
                        continue;
                    }
                    ArgKind::Float64 if gpr_idx < 2 => {
                        let fpu_num = if gpr_idx == 0 { regs::F12 } else { regs::F14 };
                        let fpu_name = if gpr_idx == 0 { "$f12" } else { "$f14" };
                        locations.push(ArgLocation::Register(ArgRegister::fpu(fpu_num, fpu_name, 8)));
                        gpr_idx += 2; // consumes two GPR slots
                        continue;
                    }
                    _ => {}
                }
            }

            if gpr_idx < gpr_regs.len() {
                locations.push(ArgLocation::Register(gpr_regs[gpr_idx].clone()));
                gpr_idx += 1;
            } else {
                let slot_size = match conv {
                    MipsCallingConvention::O32 => 4u8,
                    MipsCallingConvention::N32 | MipsCallingConvention::N64 => 8u8,
                };
                let offset = stack_bytes.cast_signed();
                locations.push(ArgLocation::Stack(StackSlot::new(offset, slot_size, arg.index)));
                stack_bytes += u32::from(slot_size);
            }
        }

        Self { convention: conv, locations, stack_bytes }
    }

    /// Return the argument location for `arg_index`, if it was computed.
    #[must_use]
    pub fn location_for(&self, arg_index: usize) -> Option<&ArgLocation> {
        self.locations.get(arg_index)
    }
}

// ---------------------------------------------------------------------------
// CallingConventionDb
// ---------------------------------------------------------------------------

/// A database mapping function names to their calling convention overrides.
///
/// Most functions use the ABI default, but a few (e.g. kernel syscall stubs)
/// use custom conventions.
#[derive(Debug, Default)]
pub struct CallingConventionDb {
    overrides: HashMap<String, MipsCallingConvention>,
    default: MipsCallingConvention,
}

impl CallingConventionDb {
    /// Create a database with the given default convention.
    #[must_use]
    pub fn new(default: MipsCallingConvention) -> Self {
        Self { overrides: HashMap::new(), default }
    }

    /// Register an override for a named function.
    pub fn add_override(&mut self, name: impl Into<String>, conv: MipsCallingConvention) {
        self.overrides.insert(name.into(), conv);
    }

    /// Look up the calling convention for a function by name.
    #[must_use]
    pub fn convention_for(&self, name: &str) -> MipsCallingConvention {
        self.overrides.get(name).copied().unwrap_or(self.default)
    }

    /// The default convention for this database.
    #[must_use]
    pub const fn default_convention(&self) -> MipsCallingConvention {
        self.default
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o32_has_four_arg_regs() {
        assert_eq!(MipsCallingConvention::O32.arg_reg_count(), 4);
        assert_eq!(MipsCallingConvention::O32.arg_registers().len(), 4);
    }

    #[test]
    fn n64_has_eight_arg_regs() {
        assert_eq!(MipsCallingConvention::N64.arg_reg_count(), 8);
        assert_eq!(MipsCallingConvention::N64.arg_registers().len(), 8);
    }

    #[test]
    fn o32_first_four_args_in_regs() {
        for i in 0..4usize {
            assert!(MipsCallingConvention::O32.stack_arg_offset(i).is_none());
        }
    }

    #[test]
    fn o32_fifth_arg_on_stack_at_16() {
        assert_eq!(MipsCallingConvention::O32.stack_arg_offset(4), Some(16));
    }

    #[test]
    fn n64_ninth_arg_on_stack_at_0() {
        assert_eq!(MipsCallingConvention::N64.stack_arg_offset(8), Some(0));
    }

    #[test]
    fn n64_tenth_arg_on_stack_at_8() {
        assert_eq!(MipsCallingConvention::N64.stack_arg_offset(9), Some(8));
    }

    #[test]
    fn o32_gpr_width_is_4() {
        assert_eq!(MipsCallingConvention::O32.gpr_width(), 4);
    }

    #[test]
    fn n64_gpr_width_is_8() {
        assert_eq!(MipsCallingConvention::N64.gpr_width(), 8);
    }

    #[test]
    fn call_site_layout_o32_six_ints() {
        let args: Vec<ArgDesc> = (0..6).map(ArgDesc::int).collect();
        let layout = CallSiteLayout::compute(MipsCallingConvention::O32, &args);
        // Args 0-3 in registers
        for i in 0..4 {
            assert!(matches!(layout.locations[i], ArgLocation::Register(_)));
        }
        // Args 4-5 on stack
        assert!(matches!(layout.locations[4], ArgLocation::Stack(_)));
        assert!(matches!(layout.locations[5], ArgLocation::Stack(_)));
    }

    #[test]
    fn calling_convention_db_override() {
        let mut db = CallingConventionDb::new(MipsCallingConvention::O32);
        db.add_override("__syscall", MipsCallingConvention::N64);
        assert_eq!(db.convention_for("main"), MipsCallingConvention::O32);
        assert_eq!(db.convention_for("__syscall"), MipsCallingConvention::N64);
    }

    #[test]
    fn stack_alignment_values() {
        assert_eq!(MipsCallingConvention::O32.stack_alignment(), 8);
        assert_eq!(MipsCallingConvention::N64.stack_alignment(), 16);
    }
}
