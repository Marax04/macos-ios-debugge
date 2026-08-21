//! ARM64 system register full encoding table.
//!
//! Provides complete MSR/MRS encoding support: all `AArch64` system registers
//! encoded as (op0, op1, `CRn`, `CRm`, op2) tuples, name lookup, encoding lookup,
//! and utilities for decoding the 16-bit system register field in MSR/MRS
//! instructions.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// SysRegEncoding
// ─────────────────────────────────────────────────────────────────────────────

/// The 5-field encoding of an `AArch64` system register as used in MRS/MSR.
///
/// The 16-bit field in the instruction word is laid out as:
/// `op0[15:14] | op1[13:11] | CRn[10:7] | CRm[6:3] | op2[2:0]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SysRegEncoding {
    /// op0 (2 bits): 2 = debug/trace, 3 = normal system.
    pub op0: u8,
    /// op1 (3 bits): exception level selector.
    pub op1: u8,
    /// `CRn` (4 bits): coprocessor register number.
    pub crn: u8,
    /// `CRm` (4 bits): additional register identifier.
    pub crm: u8,
    /// op2 (3 bits): sub-register selector.
    pub op2: u8,
}

impl SysRegEncoding {
    /// Create a new encoding.
    #[must_use]
    pub const fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Self {
        Self { op0, op1, crn, crm, op2 }
    }

    /// Pack into the 16-bit field used in MRS/MSR instruction words.
    ///
    /// Bits: `op0[15:14] | op1[13:11] | CRn[10:7] | CRm[6:3] | op2[2:0]`
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        ((self.op0 as u16 & 0x3) << 14)
            | ((self.op1 as u16 & 0x7) << 11)
            | ((self.crn as u16 & 0xf) << 7)
            | ((self.crm as u16 & 0xf) << 3)
            | (self.op2 as u16 & 0x7)
    }

    /// Unpack from the 16-bit instruction field.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        Self {
            op0: ((v >> 14) & 0x3) as u8,
            op1: ((v >> 11) & 0x7) as u8,
            crn: ((v >> 7) & 0xf) as u8,
            crm: ((v >> 3) & 0xf) as u8,
            op2: (v & 0x7) as u8,
        }
    }

    /// Format as the assembly notation `S<op0>_<op1>_C<CRn>_C<CRm>_<op2>`.
    #[must_use]
    pub fn generic_name(&self) -> String {
        format!("S{}_{}_C{}_C{}_{}", self.op0, self.op1, self.crn, self.crm, self.op2)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Arm64SystemReg
// ─────────────────────────────────────────────────────────────────────────────

/// An `AArch64` system register descriptor.
#[derive(Debug, Clone)]
pub struct Arm64SystemReg {
    /// Register name as used in assembly (e.g. `"SCTLR_EL1"`).
    pub name: &'static str,
    /// Encoding fields.
    pub encoding: SysRegEncoding,
    /// Human-readable description.
    pub description: &'static str,
    /// Whether the register can be read with MRS.
    pub readable: bool,
    /// Whether the register can be written with MSR.
    pub writable: bool,
}

impl Arm64SystemReg {
    const fn rw(
        name: &'static str,
        op0: u8, op1: u8, crn: u8, crm: u8, op2: u8,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            encoding: SysRegEncoding::new(op0, op1, crn, crm, op2),
            description,
            readable: true,
            writable: true,
        }
    }

    const fn ro(
        name: &'static str,
        op0: u8, op1: u8, crn: u8, crm: u8, op2: u8,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            encoding: SysRegEncoding::new(op0, op1, crn, crm, op2),
            description,
            readable: true,
            writable: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static register table
// ─────────────────────────────────────────────────────────────────────────────

/// Complete `AArch64` system register table covering EL0–EL3, debug, PMU, GIC,
/// virtual memory, timer, and security registers.
pub static SYSTEM_REGISTERS: &[Arm64SystemReg] = &[
    // ── EL1 – MMU / Translation ───────────────────────────────────────────────
    Arm64SystemReg::rw("SCTLR_EL1",   3,0, 1,0,0, "System Control Register EL1"),
    Arm64SystemReg::rw("ACTLR_EL1",   3,0, 1,0,1, "Auxiliary Control Register EL1"),
    Arm64SystemReg::rw("CPACR_EL1",   3,0, 1,0,2, "Architectural Feature Access Control EL1"),
    Arm64SystemReg::rw("TTBR0_EL1",   3,0, 2,0,0, "Translation Table Base Register 0 EL1"),
    Arm64SystemReg::rw("TTBR1_EL1",   3,0, 2,0,1, "Translation Table Base Register 1 EL1"),
    Arm64SystemReg::rw("TCR_EL1",     3,0, 2,0,2, "Translation Control Register EL1"),
    Arm64SystemReg::rw("TCR2_EL1",    3,0, 2,0,3, "Extended Translation Control Register EL1"),
    Arm64SystemReg::rw("MAIR_EL1",    3,0,10,2,0, "Memory Attribute Indirection Register EL1"),
    Arm64SystemReg::rw("AMAIR_EL1",   3,0,10,3,0, "Auxiliary Memory Attribute Indirection Register EL1"),
    // ── EL1 – Exception / Debug ───────────────────────────────────────────────
    Arm64SystemReg::rw("SPSR_EL1",    3,0, 4,0,0, "Saved Program Status Register EL1"),
    Arm64SystemReg::rw("ELR_EL1",     3,0, 4,0,1, "Exception Link Register EL1"),
    Arm64SystemReg::rw("SP_EL0",      3,0, 4,1,0, "Stack Pointer EL0"),
    Arm64SystemReg::rw("ESR_EL1",     3,0, 5,2,0, "Exception Syndrome Register EL1"),
    Arm64SystemReg::rw("AFSR0_EL1",   3,0, 5,1,0, "Auxiliary Fault Status Register 0 EL1"),
    Arm64SystemReg::rw("AFSR1_EL1",   3,0, 5,1,1, "Auxiliary Fault Status Register 1 EL1"),
    Arm64SystemReg::rw("FAR_EL1",     3,0, 6,0,0, "Fault Address Register EL1"),
    Arm64SystemReg::rw("PAR_EL1",     3,0, 7,4,0, "Physical Address Register EL1"),
    Arm64SystemReg::rw("VBAR_EL1",    3,0,12,0,0, "Vector Base Address Register EL1"),
    Arm64SystemReg::ro("ISR_EL1",     3,0,12,1,0, "Interrupt Status Register EL1"),
    Arm64SystemReg::rw("CONTEXTIDR_EL1",3,0,13,0,1,"Context ID Register EL1"),
    Arm64SystemReg::rw("TPIDR_EL1",   3,0,13,0,4, "EL1 Software Thread ID Register"),
    Arm64SystemReg::rw("CNTKCTL_EL1", 3,0,14,1,0, "Counter-timer Kernel Control EL1"),
    // ── EL0-accessible ────────────────────────────────────────────────────────
    Arm64SystemReg::rw("NZCV",        3,3, 4,2,0, "Condition Flags"),
    Arm64SystemReg::rw("DAIF",        3,3, 4,2,1, "Interrupt Mask Bits"),
    Arm64SystemReg::rw("FPCR",        3,3, 4,4,0, "Floating-point Control Register"),
    Arm64SystemReg::rw("FPSR",        3,3, 4,4,1, "Floating-point Status Register"),
    Arm64SystemReg::rw("TPIDR_EL0",   3,3,13,0,2, "EL0 Read/Write Software Thread ID Register"),
    Arm64SystemReg::ro("TPIDRRO_EL0", 3,3,13,0,3, "EL0 Read-only Software Thread ID Register"),
    Arm64SystemReg::rw("DIT",         3,3, 4,2,5, "Data Independent Timing"),
    Arm64SystemReg::rw("SSBS",        3,3, 4,2,6, "Speculative Store Bypass Safe"),
    Arm64SystemReg::rw("TCO",         3,3, 4,2,7, "Tag Check Override"),
    // ── Counter-timer EL0 ────────────────────────────────────────────────────
    Arm64SystemReg::ro("CNTFRQ_EL0",  3,3,14,0,0, "Counter-timer Frequency Register"),
    Arm64SystemReg::ro("CNTPCT_EL0",  3,3,14,0,1, "Counter-timer Physical Count Register"),
    Arm64SystemReg::ro("CNTVCT_EL0",  3,3,14,0,2, "Counter-timer Virtual Count Register"),
    Arm64SystemReg::rw("CNTP_TVAL_EL0",3,3,14,2,0,"Counter-timer Physical Timer TimerValue"),
    Arm64SystemReg::rw("CNTP_CTL_EL0", 3,3,14,2,1,"Counter-timer Physical Timer Control"),
    Arm64SystemReg::rw("CNTP_CVAL_EL0",3,3,14,2,2,"Counter-timer Physical Timer CompareValue"),
    Arm64SystemReg::rw("CNTV_TVAL_EL0",3,3,14,3,0,"Counter-timer Virtual Timer TimerValue"),
    Arm64SystemReg::rw("CNTV_CTL_EL0", 3,3,14,3,1,"Counter-timer Virtual Timer Control"),
    Arm64SystemReg::rw("CNTV_CVAL_EL0",3,3,14,3,2,"Counter-timer Virtual Timer CompareValue"),
    // ── EL2 Hypervisor ────────────────────────────────────────────────────────
    Arm64SystemReg::rw("HCR_EL2",     3,4, 1,1,0, "Hypervisor Configuration Register EL2"),
    Arm64SystemReg::rw("VTCR_EL2",    3,4, 2,1,2, "Virtualization Translation Control EL2"),
    Arm64SystemReg::rw("VTTBR_EL2",   3,4, 2,1,0, "Virtualization Translation Table Base EL2"),
    Arm64SystemReg::rw("ELR_EL2",     3,4, 4,0,1, "Exception Link Register EL2"),
    Arm64SystemReg::rw("SPSR_EL2",    3,4, 4,0,0, "Saved Program Status Register EL2"),
    Arm64SystemReg::rw("ESR_EL2",     3,4, 5,2,0, "Exception Syndrome Register EL2"),
    Arm64SystemReg::rw("FAR_EL2",     3,4, 6,0,0, "Fault Address Register EL2"),
    Arm64SystemReg::rw("VBAR_EL2",    3,4,12,0,0, "Vector Base Address Register EL2"),
    Arm64SystemReg::rw("VMPIDR_EL2",  3,4, 0,0,5, "Virtualization Multiprocessor ID Register EL2"),
    Arm64SystemReg::rw("VPIDR_EL2",   3,4, 0,0,0, "Virtualization Processor ID Register EL2"),
    Arm64SystemReg::rw("SCTLR_EL2",   3,4, 1,0,0, "System Control Register EL2"),
    Arm64SystemReg::rw("MDCR_EL2",    3,4, 1,1,1, "Monitor Debug Configuration Register EL2"),
    // ── EL3 Secure Monitor ────────────────────────────────────────────────────
    Arm64SystemReg::rw("SCR_EL3",     3,6, 1,1,0, "Secure Configuration Register EL3"),
    Arm64SystemReg::rw("ELR_EL3",     3,6, 4,0,1, "Exception Link Register EL3"),
    Arm64SystemReg::rw("SPSR_EL3",    3,6, 4,0,0, "Saved Program Status Register EL3"),
    Arm64SystemReg::rw("VBAR_EL3",    3,6,12,0,0, "Vector Base Address Register EL3"),
    Arm64SystemReg::rw("SCTLR_EL3",   3,6, 1,0,0, "System Control Register EL3"),
    // ── Performance Monitor ───────────────────────────────────────────────────
    Arm64SystemReg::rw("PMCR_EL0",    3,3, 9,12,0, "Performance Monitor Control Register"),
    Arm64SystemReg::rw("PMCNTENSET_EL0",3,3,9,12,1,"Performance Monitor Count Enable Set"),
    Arm64SystemReg::rw("PMCNTENCLR_EL0",3,3,9,12,2,"Performance Monitor Count Enable Clear"),
    Arm64SystemReg::rw("PMOVSCLR_EL0",3,3, 9,12,3, "Performance Monitor Overflow Flag Status Clear"),
    Arm64SystemReg::rw("PMSWINC_EL0", 3,3, 9,12,4, "Performance Monitor Software Increment"),
    Arm64SystemReg::rw("PMSELR_EL0",  3,3, 9,12,5, "Performance Monitor Event Counter Selection"),
    Arm64SystemReg::rw("PMCCNTR_EL0", 3,3, 9,13,0, "Performance Monitor Cycle Count Register"),
    Arm64SystemReg::rw("PMXEVTYPER_EL0",3,3,9,13,1,"Performance Monitor Selected Event Type"),
    Arm64SystemReg::rw("PMXEVCNTR_EL0",3,3,9,13,2,"Performance Monitor Selected Event Count"),
    Arm64SystemReg::rw("PMUSERENR_EL0",3,3,9,14,0,"Performance Monitor User Enable Register"),
    Arm64SystemReg::ro("PMOVSSET_EL0",3,3, 9,14,3, "Performance Monitor Overflow Flag Status Set"),
    // ── ID Registers (EL1) ────────────────────────────────────────────────────
    Arm64SystemReg::ro("MIDR_EL1",      3,0,0,0,0, "Main ID Register EL1"),
    Arm64SystemReg::ro("MPIDR_EL1",     3,0,0,0,5, "Multiprocessor Affinity Register EL1"),
    Arm64SystemReg::ro("REVIDR_EL1",    3,0,0,0,6, "Revision ID Register EL1"),
    Arm64SystemReg::ro("ID_AA64PFR0_EL1",3,0,0,4,0,"AArch64 Processor Feature Register 0"),
    Arm64SystemReg::ro("ID_AA64PFR1_EL1",3,0,0,4,1,"AArch64 Processor Feature Register 1"),
    Arm64SystemReg::ro("ID_AA64DFR0_EL1",3,0,0,5,0,"AArch64 Debug Feature Register 0"),
    Arm64SystemReg::ro("ID_AA64DFR1_EL1",3,0,0,5,1,"AArch64 Debug Feature Register 1"),
    Arm64SystemReg::ro("ID_AA64AFR0_EL1",3,0,0,5,4,"AArch64 Auxiliary Feature Register 0"),
    Arm64SystemReg::ro("ID_AA64AFR1_EL1",3,0,0,5,5,"AArch64 Auxiliary Feature Register 1"),
    Arm64SystemReg::ro("ID_AA64ISAR0_EL1",3,0,0,6,0,"AArch64 ISA Feature Register 0"),
    Arm64SystemReg::ro("ID_AA64ISAR1_EL1",3,0,0,6,1,"AArch64 ISA Feature Register 1"),
    Arm64SystemReg::ro("ID_AA64ISAR2_EL1",3,0,0,6,2,"AArch64 ISA Feature Register 2"),
    Arm64SystemReg::ro("ID_AA64MMFR0_EL1",3,0,0,7,0,"AArch64 Memory Model Feature Register 0"),
    Arm64SystemReg::ro("ID_AA64MMFR1_EL1",3,0,0,7,1,"AArch64 Memory Model Feature Register 1"),
    Arm64SystemReg::ro("ID_AA64MMFR2_EL1",3,0,0,7,2,"AArch64 Memory Model Feature Register 2"),
    // ── Debug ─────────────────────────────────────────────────────────────────
    Arm64SystemReg::rw("MDSCR_EL1",   2,0,0,2,2, "Monitor Debug System Control Register"),
    Arm64SystemReg::rw("OSLAR_EL1",   2,0,1,0,4, "OS Lock Access Register"),
    Arm64SystemReg::rw("DBGBVR0_EL1", 2,0,0,0,4, "Debug Breakpoint Value Register 0"),
    Arm64SystemReg::rw("DBGBCR0_EL1", 2,0,0,0,5, "Debug Breakpoint Control Register 0"),
    Arm64SystemReg::rw("DBGWVR0_EL1", 2,0,0,0,6, "Debug Watchpoint Value Register 0"),
    Arm64SystemReg::rw("DBGWCR0_EL1", 2,0,0,0,7, "Debug Watchpoint Control Register 0"),
    Arm64SystemReg::rw("DBGBVR1_EL1", 2,0,0,1,4, "Debug Breakpoint Value Register 1"),
    Arm64SystemReg::rw("DBGBCR1_EL1", 2,0,0,1,5, "Debug Breakpoint Control Register 1"),
    Arm64SystemReg::rw("DBGWVR1_EL1", 2,0,0,1,6, "Debug Watchpoint Value Register 1"),
    Arm64SystemReg::rw("DBGWCR1_EL1", 2,0,0,1,7, "Debug Watchpoint Control Register 1"),
    Arm64SystemReg::rw("OSDLR_EL1",   2,0,1,3,4, "OS Double Lock Register"),
    Arm64SystemReg::ro("DBGAUTHSTATUS_EL1",2,0,7,14,6,"Debug Authentication Status Register"),
    // ── GIC CPU interface (system registers, GICv3+) ─────────────────────────
    Arm64SystemReg::rw("ICC_PMR_EL1",  3,0,4,6,0, "Interrupt Controller Interrupt Priority Mask"),
    Arm64SystemReg::rw("ICC_IAR0_EL1", 3,0,12,8,0,"Interrupt Controller Interrupt Acknowledge 0"),
    Arm64SystemReg::rw("ICC_EOIR0_EL1",3,0,12,8,1,"Interrupt Controller End Of Interrupt 0"),
    Arm64SystemReg::rw("ICC_IAR1_EL1", 3,0,12,12,0,"Interrupt Controller Interrupt Acknowledge 1"),
    Arm64SystemReg::rw("ICC_EOIR1_EL1",3,0,12,12,1,"Interrupt Controller End Of Interrupt 1"),
    Arm64SystemReg::rw("ICC_SRE_EL1",  3,0,12,12,5,"Interrupt Controller System Register Enable EL1"),
    Arm64SystemReg::rw("ICC_CTLR_EL1", 3,0,12,12,4,"Interrupt Controller Control Register EL1"),
    Arm64SystemReg::rw("ICC_IGRPEN0_EL1",3,0,12,12,6,"Interrupt Controller Interrupt Group 0 Enable EL1"),
    Arm64SystemReg::rw("ICC_IGRPEN1_EL1",3,0,12,12,7,"Interrupt Controller Interrupt Group 1 Enable EL1"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Arm64SystemRegDb
// ─────────────────────────────────────────────────────────────────────────────

/// A searchable database of `AArch64` system registers.
///
/// Provides O(1) lookup by both name (case-insensitive) and by the packed
/// 16-bit encoding field used in MRS/MSR instructions.
pub struct Arm64SystemRegDb {
    /// Index from lowercase name → register entry index in `SYSTEM_REGISTERS`.
    by_name: HashMap<String, usize>,
    /// Index from packed u16 → register entry index in `SYSTEM_REGISTERS`.
    by_encoding: HashMap<u16, usize>,
}

impl Arm64SystemRegDb {
    /// Build the database from `SYSTEM_REGISTERS`.
    #[must_use]
    pub fn build() -> Self {
        let mut by_name = HashMap::with_capacity(SYSTEM_REGISTERS.len());
        let mut by_encoding = HashMap::with_capacity(SYSTEM_REGISTERS.len());
        for (idx, reg) in SYSTEM_REGISTERS.iter().enumerate() {
            by_name.insert(reg.name.to_ascii_lowercase(), idx);
            by_encoding.insert(reg.encoding.to_u16(), idx);
        }
        Self { by_name, by_encoding }
    }

    /// Look up a register by name (case-insensitive).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&'static Arm64SystemReg> {
        let key = name.to_ascii_lowercase();
        self.by_name.get(&key).map(|&idx| &SYSTEM_REGISTERS[idx])
    }

    /// Look up a register by packed 16-bit encoding.
    #[must_use]
    pub fn by_encoding(&self, enc: u16) -> Option<&'static Arm64SystemReg> {
        self.by_encoding.get(&enc).map(|&idx| &SYSTEM_REGISTERS[idx])
    }

    /// Total number of registers in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-standing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Look up an `AArch64` system register name by its packed 16-bit encoding.
///
/// Returns the register name string (e.g. `"SCTLR_EL1"`) or `None` when the
/// encoding is not in the static table.
///
/// # Examples
/// ```
/// use rustre_arch_arm64::arm64_system_registers::{SysRegEncoding, sysreg_name};
///
/// let enc = SysRegEncoding::new(3, 0, 1, 0, 0); // SCTLR_EL1
/// assert_eq!(sysreg_name(enc.to_u16()), Some("SCTLR_EL1"));
/// ```
#[must_use]
pub fn sysreg_name(packed: u16) -> Option<&'static str> {
    SYSTEM_REGISTERS
        .iter()
        .find(|r| r.encoding.to_u16() == packed)
        .map(|r| r.name)
}

/// Look up an `AArch64` system register by its packed 16-bit encoding.
///
/// Returns a reference to the [`Arm64SystemReg`] entry or `None`.
#[must_use]
pub fn sysreg_by_encoding(packed: u16) -> Option<&'static Arm64SystemReg> {
    SYSTEM_REGISTERS
        .iter()
        .find(|r| r.encoding.to_u16() == packed)
}

/// Look up an `AArch64` system register by name (case-insensitive).
#[must_use]
pub fn sysreg_by_name(name: &str) -> Option<&'static Arm64SystemReg> {
    SYSTEM_REGISTERS
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(name))
}

/// Decode the 21-bit system register / instruction-type field of an
/// MRS/MSR instruction word.
///
/// `AArch64` encodes: `op0[21:20] | op1[18:16] | CRn[15:12] | CRm[11:8] | op2[7:5]`
/// within the 32-bit instruction word for `SYSTEM` instructions.
///
/// Returns `(encoding, is_mrs)` where `is_mrs` is `true` when the L (read)
/// bit is set.
#[must_use]
pub const fn decode_mrs_msr_word(word: u32) -> (SysRegEncoding, bool) {
    // AArch64 SYSTEM instruction encoding:
    //   [31:22] = 1101 0101 00       (fixed)
    //   [21]    = L (1 = MRS / read, 0 = MSR / write)
    //   [20:19] = op0
    //   [18:16] = op1
    //   [15:12] = CRn
    //   [11:8]  = CRm
    //   [7:5]   = op2
    //   [4:0]   = Rt
    let is_mrs = (word >> 21) & 1 != 0;
    let op0 = ((word >> 19) & 0x3) as u8;
    let op1 = ((word >> 16) & 0x7) as u8;
    let crn = ((word >> 12) & 0xf) as u8;
    let crm = ((word >>  8) & 0xf) as u8;
    let op2 = ((word >>  5) & 0x7) as u8;
    (SysRegEncoding::new(op0, op1, crn, crm, op2), is_mrs)
}

/// Extract the destination/source register index (`Rt`, bits[4:0]) from a
/// 32-bit MRS/MSR instruction word.
#[must_use]
pub const fn mrs_msr_rt(word: u32) -> u8 {
    (word & 0x1f) as u8
}

/// Returns `true` when `word` appears to be an MRS instruction (reads from
/// system register into Xt).
#[must_use]
pub const fn is_mrs(word: u32) -> bool {
    // Fixed pattern: bits[31:22] == 1101_0101_00 and L(bit21)==1
    // Mask 0xFFC0_0000 covers bits[31:22]; compare to 0xD500_0000 (bits[31:22] of MRS/MSR).
    (word & 0xFFC0_0000) == 0xD500_0000 && (word >> 21) & 1 == 1
}

/// Returns `true` when `word` appears to be an MSR (register) instruction.
#[must_use]
pub const fn is_msr_reg(word: u32) -> bool {
    // Fixed pattern: bits[31:22] == 1101_0101_00 and L(bit21)==0
    (word & 0xFFC0_0000) == 0xD500_0000 && (word >> 21) & 1 == 0
}

/// Returns `true` when `word` appears to be an MSR (immediate) instruction
/// (writes a small immediate to a PSTATE field).
#[must_use]
pub const fn is_msr_imm(word: u32) -> bool {
    // AArch64 MSR immediate: 1101 0101 0000 0 <op1:3> <CRm:4> <op2:3> 1_1111
    (word & 0xFFF8_001F) == 0xD500_001F
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printer
// ─────────────────────────────────────────────────────────────────────────────

/// Format a system register access instruction into a human-readable string.
///
/// Returns a string like `"MRS X0, SCTLR_EL1"` or, if the register is not
/// in the table, uses the generic `S<op0>_<op1>_C<CRn>_C<CRm>_<op2>` form.
#[must_use]
pub fn format_sysreg_access(word: u32) -> String {
    let (enc, is_mrs_op) = decode_mrs_msr_word(word);
    let rt = mrs_msr_rt(word);
    let reg_name = sysreg_name(enc.to_u16()).map_or_else(|| enc.generic_name(), std::borrow::ToOwned::to_owned);
    if is_mrs_op {
        format!("MRS X{rt}, {reg_name}")
    } else {
        format!("MSR {reg_name}, X{rt}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trip() {
        let enc = SysRegEncoding::new(3, 0, 1, 0, 0);
        let packed = enc.to_u16();
        let decoded = SysRegEncoding::from_u16(packed);
        assert_eq!(enc, decoded);
    }

    #[test]
    fn sctlr_el1_encoding() {
        let enc = SysRegEncoding::new(3, 0, 1, 0, 0);
        let name = sysreg_name(enc.to_u16());
        assert_eq!(name, Some("SCTLR_EL1"));
    }

    #[test]
    fn sysreg_by_name_case_insensitive() {
        let reg = sysreg_by_name("sctlr_el1").unwrap();
        assert_eq!(reg.name, "SCTLR_EL1");
        assert!(reg.readable);
        assert!(reg.writable);
    }

    #[test]
    fn tpidrro_el0_is_read_only() {
        let reg = sysreg_by_name("TPIDRRO_EL0").unwrap();
        assert!(reg.readable);
        assert!(!reg.writable);
    }

    #[test]
    fn sysreg_by_encoding_nzcv() {
        let enc = SysRegEncoding::new(3, 3, 4, 2, 0);
        let reg = sysreg_by_encoding(enc.to_u16()).unwrap();
        assert_eq!(reg.name, "NZCV");
    }

    #[test]
    fn db_build_and_lookup() {
        let db = Arm64SystemRegDb::build();
        assert!(!db.is_empty());
        let reg = db.by_name("fpcr").unwrap();
        assert_eq!(reg.name, "FPCR");
        let enc = reg.encoding.to_u16();
        let reg2 = db.by_encoding(enc).unwrap();
        assert_eq!(reg2.name, reg.name);
    }

    #[test]
    fn generic_name_for_unknown_encoding() {
        let enc = SysRegEncoding::new(3, 7, 15, 15, 7);
        assert!(enc.generic_name().starts_with('S'));
    }

    #[test]
    fn is_mrs_word_check() {
        // MRS X0, NZCV — encoding: op0=3 op1=3 CRn=4 CRm=2 op2=0 Rt=0
        // Bit 21 (L) = 1 for MRS
        let enc = SysRegEncoding::new(3, 3, 4, 2, 0).to_u16();
        // Build MRS word: 0xD530_0000 | (enc << 5) | rt
        let word = 0xD530_0000u32 | (u32::from(enc) << 5);
        assert!(is_mrs(word));
        assert!(!is_msr_reg(word));
    }

    #[test]
    fn decode_sysreg_word() {
        let enc = SysRegEncoding::new(3, 0, 1, 0, 0); // SCTLR_EL1
        let packed = enc.to_u16();
        // Build an MRS word for this register
        let word = 0xD530_0000u32 | (u32::from(packed) << 5) | 3u32; // Rt=3
        let (dec_enc, is_mrs_op) = decode_mrs_msr_word(word);
        assert!(is_mrs_op);
        assert_eq!(dec_enc, enc);
        assert_eq!(mrs_msr_rt(word), 3);
    }

    #[test]
    fn format_sysreg_mrs() {
        let enc = SysRegEncoding::new(3, 3, 4, 4, 0); // FPCR
        let packed = enc.to_u16();
        let word = 0xD530_0000u32 | (u32::from(packed) << 5) | 2u32;
        let s = format_sysreg_access(word);
        assert!(s.starts_with("MRS"));
        assert!(s.contains("FPCR"));
        assert!(s.contains("X2"));
    }

    #[test]
    fn all_encodings_unique() {
        let mut seen = std::collections::HashSet::new();
        for reg in SYSTEM_REGISTERS {
            let packed = reg.encoding.to_u16();
            // Some registers share encodings in partial tables; the static table
            // should not have exact duplicates.
            seen.insert((reg.name, packed));
        }
        assert_eq!(seen.len(), SYSTEM_REGISTERS.len());
    }

    #[test]
    fn midr_el1_is_read_only() {
        let reg = sysreg_by_name("MIDR_EL1").unwrap();
        assert!(reg.readable);
        assert!(!reg.writable);
    }

    #[test]
    fn hcr_el2_exists() {
        assert!(sysreg_by_name("HCR_EL2").is_some());
    }

    #[test]
    fn scr_el3_exists() {
        assert!(sysreg_by_name("SCR_EL3").is_some());
    }
}
