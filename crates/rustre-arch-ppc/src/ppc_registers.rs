//! PowerPC register file: GPRs, FPRs, CRs, SPRs, VSX registers.

// â”€â”€ General-purpose registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A PowerPC general-purpose register (r0â€“r31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpcGpr(pub u8);

impl PpcGpr {
    /// Stack pointer (r1).
    pub const SP: Self = Self(1);
    /// First integer argument / return register (r3).
    pub const R3: Self = Self(3);
    /// Table of Contents pointer in 64-bit ELF ABI (r2).
    pub const TOC: Self = Self(2);

    /// Return the register number (0-31).
    #[must_use]
    pub const fn index(self) -> u8 { self.0 }

    /// Return the ABI name (r0â€“r31, with aliases for well-known roles).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "r0", 1 => "sp",  2 => "r2",  3 => "r3",
            4 => "r4", 5 => "r5",  6 => "r6",  7 => "r7",
            8 => "r8", 9 => "r9",  10 => "r10", 11 => "r11",
            12 => "r12", 13 => "r13", 14 => "r14", 15 => "r15",
            16 => "r16", 17 => "r17", 18 => "r18", 19 => "r19",
            20 => "r20", 21 => "r21", 22 => "r22", 23 => "r23",
            24 => "r24", 25 => "r25", 26 => "r26", 27 => "r27",
            28 => "r28", 29 => "r29", 30 => "r30", 31 => "r31",
            _ => "r?",
        }
    }

    /// Return `true` if this register is a parameter register in `SysV` PPC32.
    #[must_use]
    pub const fn is_param_sysv32(self) -> bool {
        matches!(self.0, 3..=10)
    }

    /// Return `true` if this register is callee-saved in `SysV` PPC32.
    #[must_use]
    pub const fn is_callee_saved_sysv32(self) -> bool {
        matches!(self.0, 13..=31)
    }

    /// Return `true` if this is the stack pointer.
    #[must_use]
    pub const fn is_stack_pointer(self) -> bool { self.0 == 1 }

    /// Iterate all 32 GPRs.
    pub fn all() -> impl Iterator<Item = Self> {
        (0u8..32).map(Self)
    }
}

impl std::fmt::Display for PpcGpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// â”€â”€ Floating-point registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A PowerPC floating-point register (f0â€“f31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpcFpr(pub u8);

impl PpcFpr {
    /// Return the register number (0-31).
    #[must_use]
    pub const fn index(self) -> u8 { self.0 }

    /// Return the ABI name.
    #[must_use]
    pub fn name(self) -> String { format!("f{}", self.0) }

    /// Return `true` if this FPR is a float parameter in `SysV` PPC32.
    #[must_use]
    pub const fn is_param_sysv32(self) -> bool {
        matches!(self.0, 1..=8)
    }

    /// Return `true` if this FPR is callee-saved in `SysV` PPC32.
    #[must_use]
    pub const fn is_callee_saved_sysv32(self) -> bool {
        matches!(self.0, 14..=31)
    }

    /// Iterate all 32 FPRs.
    pub fn all() -> impl Iterator<Item = Self> {
        (0u8..32).map(Self)
    }
}

impl std::fmt::Display for PpcFpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "f{}", self.0)
    }
}

// â”€â”€ Condition register â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// One field of the PowerPC Condition Register (CR0â€“CR7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpcCr(pub u8);

impl PpcCr {
    /// CR field 0 â€” used by default integer comparisons.
    pub const CR0: Self = Self(0);
    /// CR field 1 â€” used by floating-point exception bits.
    pub const CR1: Self = Self(1);

    /// Return the field number (0-7).
    #[must_use]
    pub const fn field(self) -> u8 { self.0 }

    /// Return the register name.
    #[must_use]
    pub fn name(self) -> String { format!("cr{}", self.0) }

    /// Bits that belong to this field in the full 32-bit CR register.
    #[must_use]
    pub const fn bit_mask(self) -> u32 {
        0xF000_0000_u32 >> (self.0 * 4)
    }

    /// Return the names of the four condition bits for this field:
    /// (LT, GT, EQ, SO).
    #[must_use]
    pub fn bit_names(self) -> [String; 4] {
        let base = (7 - self.0) * 4;
        [
            format!("4*cr{}+lt", self.0),
            format!("4*cr{}+gt", self.0),
            format!("4*cr{}+eq", self.0),
            format!("4*cr{}+so ({})", self.0, base),
        ]
    }

    /// Iterate all 8 CR fields.
    pub fn all() -> impl Iterator<Item = Self> {
        (0u8..8).map(Self)
    }
}

/// The four condition bits within one CR field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrBit {
    /// Less-than.
    Lt = 0,
    /// Greater-than.
    Gt = 1,
    /// Equal.
    Eq = 2,
    /// Summary overflow.
    So = 3,
}

impl CrBit {
    /// Return the bit index within the CR field.
    #[must_use]
    pub const fn index(self) -> u8 { self as u8 }
}

// â”€â”€ Special-purpose registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Well-known PowerPC Special-Purpose Registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PpcSpr {
    /// Fixed-Point Exception Register (SPR 1).
    Xer,
    /// Link Register (SPR 8).
    Lr,
    /// Count Register (SPR 9).
    Ctr,
    /// Decrementer (SPR 22).
    Dec,
    /// Data Address Register (`BookE`, SPR 61).
    Dar,
    /// Machine Status Save/Restore 1 (`BookE`, SPR 62).
    Msr,
    /// Data Storage Interrupt Status Register (`BookE`, SPR 63).
    Dsrr0,
    /// Processor Version Register (SPR 287, read-only).
    Pvr,
    /// User-defined SPR (arbitrary number).
    Custom(u16),
}

impl PpcSpr {
    /// Decode a raw 10-bit SPR number (as used in MFSPR/MTSPR).
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        // SPR encoding in instruction: bits[5:9] || bits[0:4]
        let n = ((raw & 0x1F) << 5) | (raw >> 5);
        match n {
            1 => Self::Xer,
            8 => Self::Lr,
            9 => Self::Ctr,
            22 => Self::Dec,
            61 => Self::Dar,
            62 => Self::Msr,
            63 => Self::Dsrr0,
            287 => Self::Pvr,
            other => Self::Custom(other),
        }
    }

    /// Return the canonical SPR number.
    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            Self::Xer => 1,
            Self::Lr => 8,
            Self::Ctr => 9,
            Self::Dec => 22,
            Self::Dar => 61,
            Self::Msr => 62,
            Self::Dsrr0 => 63,
            Self::Pvr => 287,
            Self::Custom(n) => n,
        }
    }

    /// Return the name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Xer => "XER",
            Self::Lr => "LR",
            Self::Ctr => "CTR",
            Self::Dec => "DEC",
            Self::Dar => "DAR",
            Self::Msr => "MSR",
            Self::Dsrr0 => "DSRR0",
            Self::Pvr => "PVR",
            Self::Custom(_) => "SPR",
        }
    }
}

// â”€â”€ VSX registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A PowerPC VSX vector-scalar register (vs0â€“vs63).
///
/// VSX registers overlap: vs0â€“vs31 share encoding with the 32 FPRs; vs32â€“vs63
/// are the additional 32 VMX/Altivec vector registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpcVsr(pub u8);

impl PpcVsr {
    /// Return the VSR number (0-63).
    #[must_use]
    pub const fn index(self) -> u8 { self.0 }

    /// Return the name.
    #[must_use]
    pub fn name(self) -> String { format!("vs{}", self.0) }

    /// Return `true` if this VSR overlaps with an FPR (vs0-vs31).
    #[must_use]
    pub const fn is_fpr_mapped(self) -> bool { self.0 < 32 }

    /// Return `true` if this VSR overlaps with a VMX VR (vs32-vs63).
    #[must_use]
    pub const fn is_vmx_mapped(self) -> bool { self.0 >= 32 }

    /// The overlapping FPR, if any.
    #[must_use]
    pub const fn as_fpr(self) -> Option<PpcFpr> {
        if self.is_fpr_mapped() { Some(PpcFpr(self.0)) } else { None }
    }

    /// Iterate all 64 VSRs.
    pub fn all() -> impl Iterator<Item = Self> {
        (0u8..64).map(Self)
    }
}

// â”€â”€ XER fields â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Bit positions within the XER register.
pub mod xer_bits {
    /// Summary overflow (bit 32 in 64-bit, bit 0 in 32-bit view).
    pub const SO: u32 = 1 << 31;
    /// Overflow (bit 33).
    pub const OV: u32 = 1 << 30;
    /// Carry (bit 34).
    pub const CA: u32 = 1 << 29;
    /// String byte count (bits 57-63).
    pub const BYTE_COUNT_MASK: u32 = 0x7F;
}

/// XER register state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XerState {
    pub raw: u32,
}

impl XerState {
    /// Return `true` if the summary-overflow bit is set.
    #[must_use]
    pub const fn so(self) -> bool { self.raw & xer_bits::SO != 0 }
    /// Return `true` if the overflow bit is set.
    #[must_use]
    pub const fn ov(self) -> bool { self.raw & xer_bits::OV != 0 }
    /// Return `true` if the carry bit is set.
    #[must_use]
    pub const fn ca(self) -> bool { self.raw & xer_bits::CA != 0 }
    /// Return the string-operation byte count.
    #[must_use]
    pub const fn byte_count(self) -> u8 { (self.raw & xer_bits::BYTE_COUNT_MASK) as u8 }
}

// â”€â”€ Machine State Register â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Key MSR bit positions for PPC32.
pub mod msr_bits {
    /// External interrupt enable (EE).
    pub const EE: u32 = 1 << 15;
    /// Problem state / user mode (PR).
    pub const PR: u32 = 1 << 14;
    /// Floating-point available (FP).
    pub const FP: u32 = 1 << 13;
    /// Machine check enable (ME).
    pub const ME: u32 = 1 << 12;
    /// Data relocate (DR).
    pub const DR: u32 = 1 << 4;
    /// Instruction relocate (IR).
    pub const IR: u32 = 1 << 5;
    /// Little-endian mode (LE).
    pub const LE: u32 = 1;
}

/// MSR register state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsrState {
    pub raw: u32,
}

impl MsrState {
    /// Return `true` if external interrupts are enabled.
    #[must_use]
    pub const fn ee(self) -> bool { self.raw & msr_bits::EE != 0 }
    /// Return `true` if in problem state (user mode).
    #[must_use]
    pub const fn pr(self) -> bool { self.raw & msr_bits::PR != 0 }
    /// Return `true` if floating-point is available.
    #[must_use]
    pub const fn fp(self) -> bool { self.raw & msr_bits::FP != 0 }
    /// Return `true` if in little-endian mode.
    #[must_use]
    pub const fn le(self) -> bool { self.raw & msr_bits::LE != 0 }
}

// â”€â”€ Complete register file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Snapshot of the full PowerPC register file state.
#[derive(Debug, Clone)]
pub struct PpcRegFile {
    /// 32 General-purpose registers.
    pub gprs: [u64; 32],
    /// 32 Floating-point registers.
    pub fprs: [f64; 32],
    /// Condition Register (32-bit, split into 8 4-bit fields).
    pub cr: u32,
    /// Fixed-Point Exception Register.
    pub xer: XerState,
    /// Link Register.
    pub lr: u64,
    /// Count Register.
    pub ctr: u64,
    /// Program Counter.
    pub pc: u64,
    /// Machine State Register.
    pub msr: MsrState,
    /// 64 VSX registers (128-bit each, stored as two u64 halves).
    pub vsrs: [[u64; 2]; 64],
}

impl Default for PpcRegFile {
    fn default() -> Self {
        Self {
            gprs: [0u64; 32],
            fprs: [0.0f64; 32],
            cr: 0,
            xer: XerState::default(),
            lr: 0,
            ctr: 0,
            pc: 0,
            msr: MsrState::default(),
            vsrs: [[0u64; 2]; 64],
        }
    }
}

impl PpcRegFile {
    /// Read a GPR value.
    #[must_use]
    pub const fn gpr(&self, r: PpcGpr) -> u64 { self.gprs[r.0 as usize] }
    /// Write a GPR value.
    pub const fn set_gpr(&mut self, r: PpcGpr, v: u64) { self.gprs[r.0 as usize] = v; }
    /// Read the stack pointer (r1).
    #[must_use]
    pub const fn sp(&self) -> u64 { self.gprs[1] }
    /// Read a CR field (0-7); returns 4-bit value.
    #[must_use]
    pub const fn cr_field(&self, field: u8) -> u8 {
        ((self.cr >> ((7 - (field & 7)) * 4)) & 0xF) as u8
    }
    /// Write a 4-bit value into a CR field.
    pub fn set_cr_field(&mut self, field: u8, val: u8) {
        let shift = (7 - (field & 7)) * 4;
        self.cr = (self.cr & !(0xF << shift)) | ((u32::from(val) & 0xF) << shift);
    }
    /// Read the LT bit from CR0.
    #[must_use]
    pub const fn cr0_lt(&self) -> bool { self.cr & 0x8000_0000 != 0 }
    /// Read the GT bit from CR0.
    #[must_use]
    pub const fn cr0_gt(&self) -> bool { self.cr & 0x4000_0000 != 0 }
    /// Read the EQ bit from CR0.
    #[must_use]
    pub const fn cr0_eq(&self) -> bool { self.cr & 0x2000_0000 != 0 }
    /// Read the SO bit from CR0.
    #[must_use]
    pub const fn cr0_so(&self) -> bool { self.cr & 0x1000_0000 != 0 }
    /// Read an FPR value.
    #[must_use]
    pub const fn fpr(&self, r: PpcFpr) -> f64 { self.fprs[r.0 as usize] }
    /// Write an FPR value.
    pub const fn set_fpr(&mut self, r: PpcFpr, v: f64) { self.fprs[r.0 as usize] = v; }
}

// â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpr_names() {
        assert_eq!(PpcGpr(0).name(), "r0");
        assert_eq!(PpcGpr(1).name(), "sp");
        assert_eq!(PpcGpr(31).name(), "r31");
    }

    #[test]
    fn test_gpr_roles() {
        assert!(PpcGpr(3).is_param_sysv32());
        assert!(PpcGpr(10).is_param_sysv32());
        assert!(!PpcGpr(11).is_param_sysv32());
        assert!(PpcGpr(14).is_callee_saved_sysv32());
        assert!(PpcGpr(1).is_stack_pointer());
    }

    #[test]
    fn test_fpr_param() {
        assert!(PpcFpr(1).is_param_sysv32());
        assert!(!PpcFpr(9).is_param_sysv32());
        assert!(PpcFpr(14).is_callee_saved_sysv32());
    }

    #[test]
    fn test_cr_mask() {
        assert_eq!(PpcCr(0).bit_mask(), 0xF000_0000);
        assert_eq!(PpcCr(7).bit_mask(), 0x0000_000F);
    }

    #[test]
    fn test_spr_names() {
        assert_eq!(PpcSpr::Lr.name(), "LR");
        assert_eq!(PpcSpr::Ctr.name(), "CTR");
        assert_eq!(PpcSpr::from_raw(8 << 5).name(), "LR"); // encoded SPR 8
    }

    #[test]
    fn test_vsr_mapping() {
        assert!(PpcVsr(0).is_fpr_mapped());
        assert!(PpcVsr(31).is_fpr_mapped());
        assert!(PpcVsr(32).is_vmx_mapped());
        assert!(PpcVsr(63).is_vmx_mapped());
        assert_eq!(PpcVsr(5).as_fpr(), Some(PpcFpr(5)));
        assert_eq!(PpcVsr(32).as_fpr(), None);
    }

    #[test]
    fn test_xer_bits() {
        let x = XerState { raw: xer_bits::SO | xer_bits::CA };
        assert!(x.so());
        assert!(!x.ov());
        assert!(x.ca());
    }

    #[test]
    fn test_msr_bits() {
        let m = MsrState { raw: msr_bits::EE | msr_bits::FP };
        assert!(m.ee());
        assert!(m.fp());
        assert!(!m.pr());
    }

    #[test]
    fn test_reg_file_cr() {
        let mut rf = PpcRegFile::default();
        rf.set_cr_field(0, 0b1010); // LT=1, GT=0, EQ=1, SO=0
        assert!(rf.cr0_lt());
        assert!(!rf.cr0_gt());
        assert!(rf.cr0_eq());
        assert_eq!(rf.cr_field(0), 0b1010);
    }

    #[test]
    fn test_reg_file_gpr() {
        let mut rf = PpcRegFile::default();
        rf.set_gpr(PpcGpr(3), 0xDEAD_BEEF);
        assert_eq!(rf.gpr(PpcGpr(3)), 0xDEAD_BEEF);
    }

    #[test]
    fn test_all_gprs() {
        assert_eq!(PpcGpr::all().count(), 32);
    }

    #[test]
    fn test_all_fprs() {
        assert_eq!(PpcFpr::all().count(), 32);
    }

    #[test]
    fn test_all_vsrs() {
        assert_eq!(PpcVsr::all().count(), 64);
    }

    #[test]
    fn test_all_cr_fields() {
        assert_eq!(PpcCr::all().count(), 8);
    }
}

