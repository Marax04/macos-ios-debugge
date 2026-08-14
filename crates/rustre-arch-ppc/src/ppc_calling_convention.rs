//! PowerPC ABI / calling convention — argument classification, register
//! assignments, stack frame layout for SysV32/64 and EABI variants.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ABI variant
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpcAbi {
    SysV32,
    SysV64,
    EabiHard,
    EabiSoft,
    DarwinPpc32,
    DarwinPpc64,
}

impl fmt::Display for PpcAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SysV32      => "SysV-PPC32",
            Self::SysV64      => "SysV-PPC64",
            Self::EabiHard    => "EABI-hard-float",
            Self::EabiSoft    => "EABI-soft-float",
            Self::DarwinPpc32 => "Darwin-PPC32",
            Self::DarwinPpc64 => "Darwin-PPC64",
        };
        f.write_str(s)
    }
}

impl PpcAbi {
    #[must_use]
    pub const fn pointer_size(self) -> u32 {
        match self {
            Self::SysV64 | Self::DarwinPpc64 => 8,
            _ => 4,
        }
    }

    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.pointer_size() == 8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Types used for argument classification
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpcType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    F128,
    Ptr,
    Struct { size: u32, align: u32 },
    Vector128,
}

impl PpcType {
    #[must_use]
    pub const fn size(self) -> u32 {
        match self {
            Self::I8 | Self::U8             => 1,
            Self::I16 | Self::U16           => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 | Self::Ptr => 8,
            Self::F128 | Self::Vector128    => 16,
            Self::Struct { size, .. }       => size,
        }
    }

    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64 | Self::F128)
    }

    #[must_use]
    pub const fn is_vector(self) -> bool {
        matches!(self, Self::Vector128)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument classification
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgClass {
    /// Passed in a general-purpose register.
    Gpr,
    /// Passed in a floating-point register.
    Fpr,
    /// Passed by reference (pointer in GPR).
    ByRef,
    /// Passed on stack.
    Stack,
    /// Passed in an AltiVec/VMX register.
    VecReg,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stack frame layout
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Offset of the back-chain pointer (always 0).
    pub back_chain_offset: i32,
    /// Offset at which the caller's LR is saved.
    pub lr_save_offset: i32,
    /// Start of the parameter area (where outgoing args spill).
    pub parameter_area_start: i32,
    /// Start of the local variable area.
    pub local_area_start: i32,
}

impl StackFrame {
    const fn for_abi(abi: PpcAbi) -> Self {
        if abi.is_64bit() {
            Self {
                back_chain_offset: 0,
                lr_save_offset: 16,
                parameter_area_start: 48,
                local_area_start: 112, // 48 + 8 GPR args * 8 bytes
            }
        } else {
            Self {
                back_chain_offset: 0,
                lr_save_offset: 4,
                parameter_area_start: 8,
                local_area_start: 56, // 8 + 8 GPR args * 4 + linkage extras
            }
        }
    }
}

/// Linkage area layout (offsets from SP at function entry).
#[derive(Debug, Clone)]
pub struct LinkageArea {
    pub back_chain: i32,
    pub lr_save: i32,
    pub cr_save: i32,
    pub reserved: i32,
}

impl LinkageArea {
    const fn for_abi(abi: PpcAbi) -> Self {
        if abi.is_64bit() {
            Self { back_chain: 0, lr_save: 16, cr_save: 8, reserved: 24 }
        } else {
            Self { back_chain: 0, lr_save: 4, cr_save: 8, reserved: 0 }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Register lists
// ─────────────────────────────────────────────────────────────────────────────

/// GPRs used for integer/pointer arguments: r3..r10
const INT_ARG_REGS: &[u8] = &[3, 4, 5, 6, 7, 8, 9, 10];

/// FPRs used for float arguments: f1..f13
const FLOAT_ARG_REGS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Callee-saved GPRs: r13..r31 (`SysV` / EABI)
const CALLEE_SAVED_GPRS: &[u8] = &[
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// Callee-saved FPRs: f14..f31
const CALLEE_SAVED_FPRS: &[u8] = &[
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// Caller-saved GPRs: r0, r3-r12
const CALLER_SAVED_GPRS: &[u8] = &[0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// Caller-saved FPRs: f0..f13
const CALLER_SAVED_FPRS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

// ─────────────────────────────────────────────────────────────────────────────
// PpcCallingConvention
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PpcCallingConvention {
    pub abi: PpcAbi,
}

impl PpcCallingConvention {
    #[must_use]
    pub const fn new(abi: PpcAbi) -> Self {
        Self { abi }
    }

    // ── Register queries ───────────────────────────────────────────────────

    #[must_use]
    pub const fn int_arg_regs(&self) -> &'static [u8] {
        INT_ARG_REGS
    }

    #[must_use]
    pub const fn float_arg_regs(&self) -> &'static [u8] {
        FLOAT_ARG_REGS
    }

    /// Return registers for the integer return value.
    /// 64-bit ABIs use r3 only for values ≤ 64 bits; 32-bit uses r3:r4 for
    /// 64-bit returns.
    #[must_use]
    pub fn return_regs(&self) -> Vec<u8> {
        if self.abi.is_64bit() {
            vec![3]
        } else {
            vec![3, 4] // r4 holds high word for 64-bit return on 32-bit ABI
        }
    }

    #[must_use]
    pub const fn float_return_reg(&self) -> u8 {
        1 // f1
    }

    #[must_use]
    pub const fn callee_saved_regs(&self) -> &'static [u8] {
        CALLEE_SAVED_GPRS
    }

    #[must_use]
    pub const fn callee_saved_fprs(&self) -> &'static [u8] {
        CALLEE_SAVED_FPRS
    }

    #[must_use]
    pub const fn caller_saved_regs(&self) -> &'static [u8] {
        CALLER_SAVED_GPRS
    }

    #[must_use]
    pub const fn caller_saved_fprs(&self) -> &'static [u8] {
        CALLER_SAVED_FPRS
    }

    // ── Layout queries ─────────────────────────────────────────────────────

    #[must_use]
    pub const fn stack_frame_layout(&self) -> StackFrame {
        StackFrame::for_abi(self.abi)
    }

    #[must_use]
    pub const fn linkage_area(&self) -> LinkageArea {
        LinkageArea::for_abi(self.abi)
    }

    /// Stack alignment requirement in bytes.
    #[must_use]
    pub const fn stack_alignment(&self) -> u32 {
        if self.abi.is_64bit() { 16 } else { 8 }
    }

    // ── Argument classification ────────────────────────────────────────────

    #[must_use]
    pub const fn classify_arg(&self, ty: PpcType) -> ArgClass {
        if ty.is_vector() {
            return ArgClass::VecReg;
        }
        if ty.is_float() {
            match self.abi {
                PpcAbi::EabiSoft => ArgClass::Gpr, // soft-float: floats in GPRs
                _ => ArgClass::Fpr,
            }
        } else if let PpcType::Struct { size, .. } = ty {
            // Structs larger than 2 words (or pointer_size*2) are passed by ref
            let threshold = self.abi.pointer_size() * 2;
            if size > threshold {
                ArgClass::ByRef
            } else {
                ArgClass::Gpr
            }
        } else {
            ArgClass::Gpr
        }
    }

    // ── Frame size computation ─────────────────────────────────────────────

    /// Compute total stack frame size, respecting alignment.
    #[must_use]
    pub fn compute_frame_size(&self, locals_bytes: u32, saved_regs: &[u8]) -> u32 {
        let layout = self.stack_frame_layout();
        let linkage_size = layout.parameter_area_start.cast_unsigned();
        // Parameter area: 8 slots of pointer_size each.
        let param_area = 8 * self.abi.pointer_size();
        let saved_regs_size = u32::try_from(saved_regs.len()).unwrap_or(u32::MAX) * self.abi.pointer_size();
        let total = linkage_size + param_area + saved_regs_size + locals_bytes;
        align_up(total, self.stack_alignment())
    }

    // ── Argument allocation ────────────────────────────────────────────────

    /// Assign registers/stack slots to a list of argument types.
    /// Returns a `Vec` of (`ArgClass`, `register_or_stack_offset`).
    #[must_use]
    pub fn allocate_args(&self, types: &[PpcType]) -> Vec<(ArgClass, u32)> {
        let mut gpr_idx = 0usize;
        let mut fpr_idx = 0usize;
        let mut vec_idx = 0usize;
        let mut stack_offset = self.stack_frame_layout().parameter_area_start.cast_unsigned();
        let ptr = self.abi.pointer_size();
        let mut result = Vec::new();

        for &ty in types {
            let cls = self.classify_arg(ty);
            match cls {
                ArgClass::Gpr | ArgClass::ByRef => {
                    if gpr_idx < INT_ARG_REGS.len() {
                        result.push((cls, u32::from(INT_ARG_REGS[gpr_idx])));
                        gpr_idx += 1;
                        // 64-bit values on 32-bit ABI consume two GPR slots
                        if !self.abi.is_64bit() && ty.size() == 8 {
                            gpr_idx += 1;
                        }
                    } else {
                        result.push((ArgClass::Stack, stack_offset));
                        stack_offset += align_up(ty.size(), ptr);
                    }
                }
                ArgClass::Fpr => {
                    if fpr_idx < FLOAT_ARG_REGS.len() {
                        result.push((ArgClass::Fpr, u32::from(FLOAT_ARG_REGS[fpr_idx])));
                        fpr_idx += 1;
                        // In SysV32, a float arg also consumes a GPR shadow slot
                        if !self.abi.is_64bit() {
                            gpr_idx += if ty == PpcType::F64 { 2 } else { 1 };
                        }
                    } else {
                        result.push((ArgClass::Stack, stack_offset));
                        stack_offset += align_up(ty.size(), ptr);
                    }
                }
                ArgClass::VecReg => {
                    // AltiVec: v2..v13 (12 arg regs)
                    if vec_idx < 12 {
                        result.push((ArgClass::VecReg, u32::try_from(2 + vec_idx).unwrap_or(u32::MAX)));
                        vec_idx += 1;
                    } else {
                        result.push((ArgClass::Stack, stack_offset));
                        stack_offset += 16;
                    }
                }
                ArgClass::Stack => {
                    result.push((ArgClass::Stack, stack_offset));
                    stack_offset += align_up(ty.size(), ptr);
                }
            }
        }
        result
    }
}

const fn align_up(v: u32, align: u32) -> u32 {
    (v + align - 1) & !(align - 1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sysv32() -> PpcCallingConvention { PpcCallingConvention::new(PpcAbi::SysV32) }
    fn sysv64() -> PpcCallingConvention { PpcCallingConvention::new(PpcAbi::SysV64) }
    fn eabi_soft() -> PpcCallingConvention { PpcCallingConvention::new(PpcAbi::EabiSoft) }

    #[test]
    fn test_int_arg_regs_count() {
        assert_eq!(sysv32().int_arg_regs().len(), 8);
        assert_eq!(sysv32().int_arg_regs()[0], 3);
        assert_eq!(sysv32().int_arg_regs()[7], 10);
    }

    #[test]
    fn test_float_arg_regs_count() {
        assert_eq!(sysv32().float_arg_regs().len(), 13);
        assert_eq!(sysv32().float_arg_regs()[0], 1);
        assert_eq!(sysv32().float_arg_regs()[12], 13);
    }

    #[test]
    fn test_return_regs_32bit() {
        let regs = sysv32().return_regs();
        assert_eq!(regs.len(), 2); // r3 + r4 for 64-bit return value
    }

    #[test]
    fn test_return_regs_64bit() {
        let regs = sysv64().return_regs();
        assert_eq!(regs.len(), 1); // only r3
    }

    #[test]
    fn test_callee_saved_includes_r31() {
        assert!(sysv32().callee_saved_regs().contains(&31));
    }

    #[test]
    fn test_caller_saved_includes_r0() {
        assert!(sysv32().caller_saved_regs().contains(&0));
    }

    #[test]
    fn test_stack_frame_32() {
        let f = sysv32().stack_frame_layout();
        assert_eq!(f.back_chain_offset, 0);
        assert_eq!(f.lr_save_offset, 4);
        assert_eq!(f.parameter_area_start, 8);
    }

    #[test]
    fn test_stack_frame_64() {
        let f = sysv64().stack_frame_layout();
        assert_eq!(f.lr_save_offset, 16);
        assert_eq!(f.parameter_area_start, 48);
    }

    #[test]
    fn test_classify_int_arg() {
        assert_eq!(sysv32().classify_arg(PpcType::I32), ArgClass::Gpr);
    }

    #[test]
    fn test_classify_float_sysv() {
        assert_eq!(sysv32().classify_arg(PpcType::F64), ArgClass::Fpr);
    }

    #[test]
    fn test_classify_float_soft() {
        assert_eq!(eabi_soft().classify_arg(PpcType::F64), ArgClass::Gpr);
    }

    #[test]
    fn test_classify_large_struct() {
        // Struct > 8 bytes on 32-bit → ByRef
        let ty = PpcType::Struct { size: 32, align: 4 };
        assert_eq!(sysv32().classify_arg(ty), ArgClass::ByRef);
    }

    #[test]
    fn test_classify_small_struct() {
        let ty = PpcType::Struct { size: 4, align: 4 };
        assert_eq!(sysv32().classify_arg(ty), ArgClass::Gpr);
    }

    #[test]
    fn test_compute_frame_size_aligned() {
        let size = sysv32().compute_frame_size(64, &[14, 15, 16]);
        // Must be a multiple of 8
        assert_eq!(size % 8, 0);
        assert!(size > 64);
    }

    #[test]
    fn test_allocate_args_first_in_regs() {
        let alloc = sysv64().allocate_args(&[PpcType::I32, PpcType::I32, PpcType::F64]);
        assert_eq!(alloc[0].0, ArgClass::Gpr);
        assert_eq!(alloc[0].1, 3); // r3
        assert_eq!(alloc[1].0, ArgClass::Gpr);
        assert_eq!(alloc[2].0, ArgClass::Fpr);
    }

    #[test]
    fn test_allocate_args_spill_to_stack() {
        // 9 GPR args → first 8 in registers, 9th on stack
        let types = vec![PpcType::I32; 9];
        let alloc = sysv32().allocate_args(&types);
        assert_eq!(alloc[8].0, ArgClass::Stack);
    }

    #[test]
    fn test_abi_display() {
        assert_eq!(format!("{}", PpcAbi::SysV64), "SysV-PPC64");
        assert_eq!(format!("{}", PpcAbi::EabiHard), "EABI-hard-float");
    }
}
