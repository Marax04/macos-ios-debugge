//! `AArch64` exception-level modelling for the `RustRE` analysis platform.
//!
//! Provides [`Arm64ExceptionLevel`], the [`ElEntry`] descriptor, helper
//! functions [`el_name`] and [`sysreg_for_el`], and an [`ElTable`] that maps
//! exception-vector entry points found during disassembly to their owning EL.

use ahash::AHashMap;
use std::fmt;

// ── exception levels ──────────────────────────────────────────────────────────

/// `AArch64` exception levels as defined by the Arm Architecture Reference Manual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arm64ExceptionLevel {
    /// EL0 — unprivileged application code.
    El0,
    /// EL1 — OS kernel / hypervisor guest.
    El1,
    /// EL2 — hypervisor.
    El2,
    /// EL3 — secure monitor (`TrustZone`).
    El3,
}

impl Arm64ExceptionLevel {
    /// Numeric level (0–3).
    #[must_use] 
    pub const fn level(self) -> u8 {
        match self {
            Self::El0 => 0,
            Self::El1 => 1,
            Self::El2 => 2,
            Self::El3 => 3,
        }
    }

    /// Construct from a numeric level.  Returns `None` for values > 3.
    #[must_use] 
    pub const fn from_level(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::El0),
            1 => Some(Self::El1),
            2 => Some(Self::El2),
            3 => Some(Self::El3),
            _ => None,
        }
    }

    /// True if this level can execute in `AArch64` state (all levels can; EL0
    /// can be `AArch32` on some implementations — this returns `true` for the
    /// 64-bit variant).
    #[must_use] 
    pub const fn is_aarch64_capable(self) -> bool { true }

    /// True if this level is considered privileged (EL1+).
    #[must_use] 
    pub fn is_privileged(self) -> bool { self != Self::El0 }

    /// True if transition to this level is from a lower level (exception entry).
    #[must_use] 
    pub fn is_exception_target(self) -> bool { self != Self::El0 }
}

impl fmt::Display for Arm64ExceptionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(el_name(*self))
    }
}

/// Return the conventional name string for an exception level.
#[must_use] 
pub const fn el_name(el: Arm64ExceptionLevel) -> &'static str {
    match el {
        Arm64ExceptionLevel::El0 => "EL0",
        Arm64ExceptionLevel::El1 => "EL1",
        Arm64ExceptionLevel::El2 => "EL2",
        Arm64ExceptionLevel::El3 => "EL3",
    }
}

// ── key system registers per EL ───────────────────────────────────────────────

/// A system register relevant to a particular exception level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElSysReg {
    /// Mnemonic as in the ARM ARM (e.g. `"SCTLR_EL1"`).
    pub mnemonic: &'static str,
    /// Brief description.
    pub description: &'static str,
    /// Encoded as `op0:op1:CRn:CRm:op2` packed into a u32.
    pub encoding: u32,
}

impl ElSysReg {
    const fn new(mnemonic: &'static str, description: &'static str, encoding: u32) -> Self {
        Self { mnemonic, description, encoding }
    }
}

/// Return the primary system registers associated with `el`.
///
/// This covers the most commonly encountered registers in kernel/hypervisor
/// analysis; it is not exhaustive.
#[must_use] 
pub fn sysreg_for_el(el: Arm64ExceptionLevel) -> &'static [ElSysReg] {
    match el {
        Arm64ExceptionLevel::El0 => EL0_REGS,
        Arm64ExceptionLevel::El1 => EL1_REGS,
        Arm64ExceptionLevel::El2 => EL2_REGS,
        Arm64ExceptionLevel::El3 => EL3_REGS,
    }
}

// Encoding helper: pack op0:op1:CRn:CRm:op2 the same way Linux kernel macros do.
const fn enc(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    (op0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5)
}

static EL0_REGS: &[ElSysReg] = &[
    ElSysReg::new("TPIDR_EL0",  "EL0 Read/Write Software Thread ID Register", enc(3,3,13,0,2)),
    ElSysReg::new("TPIDRRO_EL0","EL0 Read-Only Software Thread ID Register",  enc(3,3,13,0,3)),
    ElSysReg::new("FPCR",       "Floating-Point Control Register",             enc(3,3,4,4,0)),
    ElSysReg::new("FPSR",       "Floating-Point Status Register",              enc(3,3,4,4,1)),
    ElSysReg::new("CTR_EL0",    "Cache Type Register",                         enc(3,3,0,0,1)),
    ElSysReg::new("DCZID_EL0",  "Data Cache Zero ID Register",                 enc(3,3,0,0,7)),
    ElSysReg::new("CNTVCT_EL0", "Counter-timer Virtual Count Register",        enc(3,3,14,0,2)),
];

static EL1_REGS: &[ElSysReg] = &[
    ElSysReg::new("SCTLR_EL1",  "System Control Register (EL1)",               enc(3,0,1,0,0)),
    ElSysReg::new("TTBR0_EL1",  "Translation Table Base Register 0 (EL1)",     enc(3,0,2,0,0)),
    ElSysReg::new("TTBR1_EL1",  "Translation Table Base Register 1 (EL1)",     enc(3,0,2,0,1)),
    ElSysReg::new("TCR_EL1",    "Translation Control Register (EL1)",           enc(3,0,2,0,2)),
    ElSysReg::new("MAIR_EL1",   "Memory Attribute Indirection Register (EL1)", enc(3,0,10,2,0)),
    ElSysReg::new("ESR_EL1",    "Exception Syndrome Register (EL1)",            enc(3,0,5,2,0)),
    ElSysReg::new("FAR_EL1",    "Fault Address Register (EL1)",                 enc(3,0,6,0,0)),
    ElSysReg::new("ELR_EL1",    "Exception Link Register (EL1)",                enc(3,0,4,0,1)),
    ElSysReg::new("SPSR_EL1",   "Saved Program Status Register (EL1)",          enc(3,0,4,0,0)),
    ElSysReg::new("SP_EL0",     "Stack Pointer (EL0)",                          enc(3,0,4,1,0)),
    ElSysReg::new("TPIDR_EL1",  "EL1 Software Thread ID Register",              enc(3,0,13,0,4)),
    ElSysReg::new("VBAR_EL1",   "Vector Base Address Register (EL1)",           enc(3,0,12,0,0)),
    ElSysReg::new("CPACR_EL1",  "Architectural Feature Access Control Register",enc(3,0,1,0,2)),
    ElSysReg::new("CONTEXTIDR_EL1","Context ID Register (EL1)",                 enc(3,0,13,0,1)),
];

static EL2_REGS: &[ElSysReg] = &[
    ElSysReg::new("SCTLR_EL2",  "System Control Register (EL2)",               enc(3,4,1,0,0)),
    ElSysReg::new("HCR_EL2",    "Hypervisor Configuration Register",            enc(3,4,1,1,0)),
    ElSysReg::new("VTTBR_EL2",  "Virtualization Translation Table Base Register",enc(3,4,2,1,0)),
    ElSysReg::new("VTCR_EL2",   "Virtualization Translation Control Register",  enc(3,4,2,1,2)),
    ElSysReg::new("VMPIDR_EL2", "Virtualization Multiprocessor ID Register",    enc(3,4,0,0,5)),
    ElSysReg::new("ESR_EL2",    "Exception Syndrome Register (EL2)",            enc(3,4,5,2,0)),
    ElSysReg::new("FAR_EL2",    "Fault Address Register (EL2)",                 enc(3,4,6,0,0)),
    ElSysReg::new("ELR_EL2",    "Exception Link Register (EL2)",                enc(3,4,4,0,1)),
    ElSysReg::new("SPSR_EL2",   "Saved Program Status Register (EL2)",          enc(3,4,4,0,0)),
    ElSysReg::new("VBAR_EL2",   "Vector Base Address Register (EL2)",           enc(3,4,12,0,0)),
    ElSysReg::new("HPFAR_EL2",  "Hypervisor IPA Fault Address Register",        enc(3,4,6,0,4)),
    ElSysReg::new("TPIDR_EL2",  "EL2 Software Thread ID Register",              enc(3,4,13,0,2)),
];

static EL3_REGS: &[ElSysReg] = &[
    ElSysReg::new("SCTLR_EL3",  "System Control Register (EL3)",               enc(3,6,1,0,0)),
    ElSysReg::new("SCR_EL3",    "Secure Configuration Register",                enc(3,6,1,1,0)),
    ElSysReg::new("TTBR0_EL3",  "Translation Table Base Register 0 (EL3)",     enc(3,6,2,0,0)),
    ElSysReg::new("TCR_EL3",    "Translation Control Register (EL3)",           enc(3,6,2,0,2)),
    ElSysReg::new("MAIR_EL3",   "Memory Attribute Indirection Register (EL3)", enc(3,6,10,2,0)),
    ElSysReg::new("ESR_EL3",    "Exception Syndrome Register (EL3)",            enc(3,6,5,2,0)),
    ElSysReg::new("FAR_EL3",    "Fault Address Register (EL3)",                 enc(3,6,6,0,0)),
    ElSysReg::new("ELR_EL3",    "Exception Link Register (EL3)",                enc(3,6,4,0,1)),
    ElSysReg::new("SPSR_EL3",   "Saved Program Status Register (EL3)",          enc(3,6,4,0,0)),
    ElSysReg::new("VBAR_EL3",   "Vector Base Address Register (EL3)",           enc(3,6,12,0,0)),
    ElSysReg::new("CPTR_EL3",   "Architectural Feature Trap Register (EL3)",    enc(3,6,1,1,2)),
];

// ── exception vector entry ─────────────────────────────────────────────────────

/// Entry type within an `AArch64` exception vector table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VectorKind {
    /// Synchronous exception (instruction abort, SVC, etc.)
    Synchronous,
    /// IRQ (normal interrupt)
    Irq,
    /// FIQ (fast interrupt)
    Fiq,
    /// `SError` (system error / async abort)
    SError,
}

impl VectorKind {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Synchronous => "Sync",
            Self::Irq         => "IRQ",
            Self::Fiq         => "FIQ",
            Self::SError      => "SError",
        }
    }
}

/// Exception source (which stack pointer / privilege level the exception came from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionSource {
    /// Current EL with `SP_EL0` (t0 suffix in ARM ARM)
    CurrentElSp0,
    /// Current EL with `SP_ELx` (tx suffix)
    CurrentElSpx,
    /// Lower EL using `AArch64`
    LowerElAArch64,
    /// Lower EL using `AArch32`
    LowerElAArch32,
}

impl ExceptionSource {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::CurrentElSp0      => "CurrentEL+SP0",
            Self::CurrentElSpx      => "CurrentEL+SPx",
            Self::LowerElAArch64    => "LowerEL/AArch64",
            Self::LowerElAArch32    => "LowerEL/AArch32",
        }
    }

    /// Byte offset of this source block within the vector table (each block is 0x200 bytes).
    #[must_use] 
    pub const fn table_offset(self) -> u64 {
        match self {
            Self::CurrentElSp0   => 0x000,
            Self::CurrentElSpx   => 0x200,
            Self::LowerElAArch64 => 0x400,
            Self::LowerElAArch32 => 0x600,
        }
    }
}

/// Offset within a source block for each vector kind (each slot is 0x80 bytes).
impl VectorKind {
    #[must_use] 
    pub const fn slot_offset(self) -> u64 {
        match self {
            Self::Synchronous => 0x00,
            Self::Irq         => 0x80,
            Self::Fiq         => 0x100,
            Self::SError      => 0x180,
        }
    }
}

/// A fully resolved exception vector entry point.
#[derive(Debug, Clone)]
pub struct ElEntry {
    /// The exception level this vector table belongs to.
    pub el: Arm64ExceptionLevel,
    /// Which source block.
    pub source: ExceptionSource,
    /// Which vector kind (slot within the block).
    pub kind: VectorKind,
    /// Virtual address of the vector table base (`VBAR_ELn`).
    pub vbar: u64,
    /// Virtual address of this specific entry (vbar + `source_offset` + `kind_offset`).
    pub entry_address: u64,
    /// Optional resolved symbol name.
    pub symbol: Option<String>,
}

impl ElEntry {
    /// Compute an entry from a VBAR base address.
    #[must_use] 
    pub const fn from_vbar(
        el: Arm64ExceptionLevel,
        vbar: u64,
        source: ExceptionSource,
        kind: VectorKind,
    ) -> Self {
        let entry_address = vbar
            .wrapping_add(source.table_offset())
            .wrapping_add(kind.slot_offset());
        Self { el, source, kind, vbar, entry_address, symbol: None }
    }

    /// Human-readable label.
    #[must_use] 
    pub fn label(&self) -> String {
        format!(
            "{}/{}/{}",
            el_name(self.el),
            self.source.name(),
            self.kind.name()
        )
    }
}

// ── EL table ──────────────────────────────────────────────────────────────────

/// Maps virtual addresses to [`ElEntry`] descriptors.
///
/// Populated by scanning for `MSR VBAR_ELn, Xm` instructions or by reading
/// the `VBAR_ELn` register value from a live debug session.
#[derive(Debug, Default)]
pub struct ElTable {
    /// `entry_address` -> `ElEntry`
    entries: AHashMap<u64, ElEntry>,
    /// vbar -> el
    vbar_map: AHashMap<u64, Arm64ExceptionLevel>,
}

impl ElTable {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Register all 16 entries for a given EL+VBAR combination.
    pub fn register_vbar(&mut self, el: Arm64ExceptionLevel, vbar: u64) {
        use ExceptionSource::{CurrentElSp0, CurrentElSpx, LowerElAArch64, LowerElAArch32};
        use VectorKind::{Synchronous, Irq, Fiq, SError};
        let sources = [CurrentElSp0, CurrentElSpx, LowerElAArch64, LowerElAArch32];
        let kinds   = [Synchronous, Irq, Fiq, SError];
        for &source in &sources {
            for &kind in &kinds {
                let entry = ElEntry::from_vbar(el, vbar, source, kind);
                self.entries.insert(entry.entry_address, entry);
            }
        }
        self.vbar_map.insert(vbar, el);
    }

    /// Look up an entry by its virtual address.
    #[must_use] 
    pub fn lookup(&self, addr: u64) -> Option<&ElEntry> {
        self.entries.get(&addr)
    }

    /// Find the closest entry at or before `addr` (to handle code that jumps
    /// into the middle of a slot).
    #[must_use] 
    pub fn lookup_nearest(&self, addr: u64) -> Option<&ElEntry> {
        self.entries
            .iter()
            .filter(|(ea, _)| **ea <= addr && (**ea).checked_add(0x80).is_some_and(|end| addr < end))
            .min_by_key(|(ea, _)| addr - **ea)
            .map(|(_, e)| e)
    }

    /// All known VBAR values, sorted ascending.
    #[must_use] 
    pub fn vbar_bases(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.vbar_map.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// All entries for a given EL.
    #[must_use] 
    pub fn entries_for_el(&self, el: Arm64ExceptionLevel) -> Vec<&ElEntry> {
        let mut v: Vec<&ElEntry> = self.entries.values().filter(|e| e.el == el).collect();
        v.sort_by_key(|e| e.entry_address);
        v
    }

    /// Annotate an entry with a symbol name.
    pub fn set_symbol(&mut self, addr: u64, symbol: impl Into<String>) -> bool {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.symbol = Some(symbol.into());
            true
        } else {
            false
        }
    }

    #[must_use] 
    pub fn len(&self) -> usize { self.entries.len() }
    #[must_use] 
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ── ESR_ELn decoder ──────────────────────────────────────────────────────────

/// Exception class extracted from `ESR_ELn`[31:26].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClass {
    Unknown,
    WfxTrap,
    AArch32Cp15,
    AArch32Cp14,
    FpAccess,
    IllegalState,
    AArch32Svc,
    AArch64Svc,
    AArch64Hvc,
    AArch64Smc,
    MsrMrsTrap,
    PacFail,
    InsnAbortLower,
    InsnAbortSame,
    PcAlignment,
    DataAbortLower,
    DataAbortSame,
    SpAlignment,
    AArch32Fpe,
    AArch64Fpe,
    Serror,
    BreakpointLower,
    BreakpointSame,
    SoftwareStep,
    WatchpointLower,
    WatchpointSame,
    AArch32Bkpt,
    VectorCatch,
    AArch64Brk,
    Other(u8),
}

impl ExceptionClass {
    #[must_use] 
    pub const fn from_esr(esr: u64) -> Self {
        let ec = ((esr >> 26) & 0x3f) as u8;
        match ec {
            0x00 => Self::Unknown,
            0x01 => Self::WfxTrap,
            0x03 => Self::AArch32Cp15,
            0x04 => Self::AArch32Cp14,
            0x07 => Self::FpAccess,
            0x0e => Self::IllegalState,
            0x11 => Self::AArch32Svc,
            0x15 => Self::AArch64Svc,
            0x16 => Self::AArch64Hvc,
            0x17 => Self::AArch64Smc,
            0x18 => Self::MsrMrsTrap,
            0x1c => Self::PacFail,
            0x20 => Self::InsnAbortLower,
            0x21 => Self::InsnAbortSame,
            0x22 => Self::PcAlignment,
            0x24 => Self::DataAbortLower,
            0x25 => Self::DataAbortSame,
            0x26 => Self::SpAlignment,
            0x28 => Self::AArch32Fpe,
            0x2c => Self::AArch64Fpe,
            0x2f => Self::Serror,
            0x30 => Self::BreakpointLower,
            0x31 => Self::BreakpointSame,
            0x32 => Self::SoftwareStep,
            0x34 => Self::WatchpointLower,
            0x35 => Self::WatchpointSame,
            0x38 => Self::AArch32Bkpt,
            0x3a => Self::VectorCatch,
            0x3c => Self::AArch64Brk,
            other => Self::Other(other),
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown           => "Unknown",
            Self::WfxTrap           => "WFx trap",
            Self::AArch32Cp15       => "AArch32 CP15 trap",
            Self::AArch32Cp14       => "AArch32 CP14 trap",
            Self::FpAccess          => "FP access",
            Self::IllegalState      => "Illegal state",
            Self::AArch32Svc        => "AArch32 SVC",
            Self::AArch64Svc        => "AArch64 SVC",
            Self::AArch64Hvc        => "AArch64 HVC",
            Self::AArch64Smc        => "AArch64 SMC",
            Self::MsrMrsTrap        => "MSR/MRS trap",
            Self::PacFail           => "PAC failure",
            Self::InsnAbortLower    => "Insn abort (lower EL)",
            Self::InsnAbortSame     => "Insn abort (same EL)",
            Self::PcAlignment       => "PC alignment fault",
            Self::DataAbortLower    => "Data abort (lower EL)",
            Self::DataAbortSame     => "Data abort (same EL)",
            Self::SpAlignment       => "SP alignment fault",
            Self::AArch32Fpe        => "AArch32 FP exception",
            Self::AArch64Fpe        => "AArch64 FP exception",
            Self::Serror            => "SError",
            Self::BreakpointLower   => "Breakpoint (lower EL)",
            Self::BreakpointSame    => "Breakpoint (same EL)",
            Self::SoftwareStep      => "Software step",
            Self::WatchpointLower   => "Watchpoint (lower EL)",
            Self::WatchpointSame    => "Watchpoint (same EL)",
            Self::AArch32Bkpt       => "AArch32 BKPT",
            Self::VectorCatch       => "Vector catch",
            Self::AArch64Brk        => "AArch64 BRK",
            Self::Other(_)          => "Other",
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_name_values() {
        assert_eq!(el_name(Arm64ExceptionLevel::El0), "EL0");
        assert_eq!(el_name(Arm64ExceptionLevel::El1), "EL1");
        assert_eq!(el_name(Arm64ExceptionLevel::El2), "EL2");
        assert_eq!(el_name(Arm64ExceptionLevel::El3), "EL3");
    }

    #[test]
    fn el_level() {
        assert_eq!(Arm64ExceptionLevel::El0.level(), 0);
        assert_eq!(Arm64ExceptionLevel::El3.level(), 3);
    }

    #[test]
    fn el_from_level_roundtrip() {
        for n in 0u8..=3 {
            let el = Arm64ExceptionLevel::from_level(n).unwrap();
            assert_eq!(el.level(), n);
        }
        assert!(Arm64ExceptionLevel::from_level(4).is_none());
    }

    #[test]
    fn el_privileged() {
        assert!(!Arm64ExceptionLevel::El0.is_privileged());
        assert!(Arm64ExceptionLevel::El1.is_privileged());
        assert!(Arm64ExceptionLevel::El2.is_privileged());
        assert!(Arm64ExceptionLevel::El3.is_privileged());
    }

    #[test]
    fn sysreg_for_el_nonempty() {
        for el in [
            Arm64ExceptionLevel::El0,
            Arm64ExceptionLevel::El1,
            Arm64ExceptionLevel::El2,
            Arm64ExceptionLevel::El3,
        ] {
            assert!(!sysreg_for_el(el).is_empty(), "no regs for {}", el_name(el));
        }
    }

    #[test]
    fn el1_has_sctlr() {
        let regs = sysreg_for_el(Arm64ExceptionLevel::El1);
        assert!(regs.iter().any(|r| r.mnemonic == "SCTLR_EL1"));
    }

    #[test]
    fn el_table_register_vbar() {
        let mut table = ElTable::new();
        table.register_vbar(Arm64ExceptionLevel::El1, 0xffff_0000_0000_0000);
        // 4 sources × 4 kinds = 16 entries
        assert_eq!(table.len(), 16);
    }

    #[test]
    fn el_table_lookup_exact() {
        let vbar = 0xffff_8000_0000_0000u64;
        let mut table = ElTable::new();
        table.register_vbar(Arm64ExceptionLevel::El1, vbar);
        // CurrentElSp0 Sync is at vbar + 0
        let entry = table.lookup(vbar).unwrap();
        assert_eq!(entry.el, Arm64ExceptionLevel::El1);
        assert_eq!(entry.kind, VectorKind::Synchronous);
        assert_eq!(entry.source, ExceptionSource::CurrentElSp0);
    }

    #[test]
    fn el_table_lookup_nearest() {
        let vbar = 0x1000u64;
        let mut table = ElTable::new();
        table.register_vbar(Arm64ExceptionLevel::El1, vbar);
        // Address in the middle of the Sync slot
        let entry = table.lookup_nearest(vbar + 0x10).unwrap();
        assert_eq!(entry.entry_address, vbar);
    }

    #[test]
    fn entries_for_el() {
        let mut table = ElTable::new();
        table.register_vbar(Arm64ExceptionLevel::El1, 0x1000);
        table.register_vbar(Arm64ExceptionLevel::El2, 0x2000);
        assert_eq!(table.entries_for_el(Arm64ExceptionLevel::El1).len(), 16);
        assert_eq!(table.entries_for_el(Arm64ExceptionLevel::El2).len(), 16);
    }

    #[test]
    fn esr_decode_svc() {
        // ESR_EL1 for AArch64 SVC #0: EC=0x15, IL=1, ISS=0
        let esr: u64 = (0x15u64 << 26) | (1 << 25);
        let ec = ExceptionClass::from_esr(esr);
        assert_eq!(ec, ExceptionClass::AArch64Svc);
        assert_eq!(ec.name(), "AArch64 SVC");
    }

    #[test]
    fn esr_decode_data_abort_same() {
        let esr: u64 = 0x25u64 << 26;
        assert_eq!(ExceptionClass::from_esr(esr), ExceptionClass::DataAbortSame);
    }

    #[test]
    fn vector_kind_slot_offsets() {
        assert_eq!(VectorKind::Synchronous.slot_offset(), 0x00);
        assert_eq!(VectorKind::Irq.slot_offset(),         0x80);
        assert_eq!(VectorKind::Fiq.slot_offset(),         0x100);
        assert_eq!(VectorKind::SError.slot_offset(),      0x180);
    }

    #[test]
    fn entry_label() {
        let e = ElEntry::from_vbar(
            Arm64ExceptionLevel::El1,
            0x1000,
            ExceptionSource::LowerElAArch64,
            VectorKind::Irq,
        );
        assert_eq!(e.label(), "EL1/LowerEL/AArch64/IRQ");
    }
}
