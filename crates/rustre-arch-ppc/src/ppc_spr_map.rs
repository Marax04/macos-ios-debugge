//! PowerPC Special-Purpose Register (SPR) map.
//!
//! Provides a complete lookup table and query API for all PowerPC SPRs defined
//! in the IBM PowerPC Architecture and POWER ISA specifications.
//!
//! SPR numbers used in MFSPR/MTSPR are *bit-reversed*: the field in the
//! instruction is split `{spr[4:0], spr[9:5]}`, so this module works with
//! the logical SPR number (as used in SPR manuals), not the raw field.

use std::fmt;
use ahash::AHashMap;

// ── Access flags ──────────────────────────────────────────────────────────────

/// Read/write accessibility of an SPR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SprAccess {
    /// Readable via MFSPR.
    Read,
    /// Writable via MTSPR.
    Write,
    /// Both MFSPR and MTSPR.
    ReadWrite,
    /// Privileged — only accessible in supervisor mode.
    Privileged,
}

impl SprAccess {
    /// True if MFSPR is permitted.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite | Self::Privileged)
    }

    /// True if MTSPR is permitted.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite | Self::Privileged)
    }
}

impl fmt::Display for SprAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read       => "R",
            Self::Write      => "W",
            Self::ReadWrite  => "RW",
            Self::Privileged => "RW(priv)",
        })
    }
}

// ── Category ──────────────────────────────────────────────────────────────────

/// Functional category of an SPR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SprCategory {
    /// Integer unit (XER, DSISR, etc.).
    Integer,
    /// Branch / condition (LR, CTR, CR).
    Branch,
    /// Timer / decrementer.
    Timer,
    /// Segment registers / MMU.
    Mmu,
    /// Debug registers (DABR, IABR, etc.).
    Debug,
    /// Performance monitor.
    Performance,
    /// `BookE` / embedded controller.
    BookE,
    /// `AltiVec` / VMX control.
    Vector,
    /// System control (MSR shadow, PIR, etc.).
    System,
    /// POWER9/POWER10 specific.
    Power9,
    /// Hypervisor.
    Hypervisor,
    /// VSX / floating-point.
    Vsx,
    /// Unknown or reserved.
    Unknown,
}

impl fmt::Display for SprCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Integer     => "Integer",
            Self::Branch      => "Branch",
            Self::Timer       => "Timer",
            Self::Mmu         => "MMU",
            Self::Debug       => "Debug",
            Self::Performance => "Perf",
            Self::BookE       => "BookE",
            Self::Vector      => "Vector",
            Self::System      => "System",
            Self::Power9      => "POWER9",
            Self::Hypervisor  => "Hypervisor",
            Self::Vsx         => "VSX",
            Self::Unknown     => "Unknown",
        })
    }
}

// ── SPR entry ─────────────────────────────────────────────────────────────────

/// A single PowerPC SPR table entry.
#[derive(Debug, Clone)]
pub struct SprEntry {
    /// Logical SPR number (as used in SPR field of MFSPR/MTSPR).
    pub number: u16,
    /// Canonical name.
    pub name: &'static str,
    /// Access type.
    pub access: SprAccess,
    /// Functional category.
    pub category: SprCategory,
    /// Brief description.
    pub description: &'static str,
}

impl SprEntry {
    const fn new(
        number: u16,
        name: &'static str,
        access: SprAccess,
        category: SprCategory,
        description: &'static str,
    ) -> Self {
        Self { number, name, access, category, description }
    }
}

impl fmt::Display for SprEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SPR {:4}  {:16}  {}  {:12}  {}",
            self.number, self.name, self.access, self.category, self.description
        )
    }
}

// ── Static table ──────────────────────────────────────────────────────────────

static STANDARD_SPRS: &[SprEntry] = &[
    // ── User-level integer ─────────────────────────────────────────────────
    SprEntry::new(1,   "XER",     SprAccess::ReadWrite,  SprCategory::Integer,  "Fixed-Point Exception Register"),
    SprEntry::new(8,   "LR",      SprAccess::ReadWrite,  SprCategory::Branch,   "Link Register"),
    SprEntry::new(9,   "CTR",     SprAccess::ReadWrite,  SprCategory::Branch,   "Count Register"),
    SprEntry::new(268, "TBL",     SprAccess::Read,       SprCategory::Timer,    "Time Base Lower (user read)"),
    SprEntry::new(269, "TBU",     SprAccess::Read,       SprCategory::Timer,    "Time Base Upper (user read)"),
    // ── Supervisor integer ────────────────────────────────────────────────
    SprEntry::new(18,  "DSISR",   SprAccess::Privileged, SprCategory::Integer,  "Data Storage Interrupt Status Register"),
    SprEntry::new(19,  "DAR",     SprAccess::Privileged, SprCategory::Integer,  "Data Address Register"),
    SprEntry::new(22,  "DEC",     SprAccess::Privileged, SprCategory::Timer,    "Decrementer"),
    SprEntry::new(25,  "SDR1",    SprAccess::Privileged, SprCategory::Mmu,      "Storage Description Register 1 (classic PPC)"),
    SprEntry::new(26,  "SRR0",    SprAccess::Privileged, SprCategory::System,   "Machine Status Save/Restore Register 0"),
    SprEntry::new(27,  "SRR1",    SprAccess::Privileged, SprCategory::System,   "Machine Status Save/Restore Register 1"),
    SprEntry::new(48,  "PID",     SprAccess::Privileged, SprCategory::Mmu,      "Process Identification Register"),
    SprEntry::new(256, "VRSAVE",  SprAccess::ReadWrite,  SprCategory::Vector,   "AltiVec VRSAVE"),
    SprEntry::new(259, "SPRG3",   SprAccess::Read,       SprCategory::System,   "Software-use SPR 3 (user read)"),
    SprEntry::new(272, "SPRG0",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 0"),
    SprEntry::new(273, "SPRG1",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 1"),
    SprEntry::new(274, "SPRG2",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 2"),
    SprEntry::new(275, "SPRG3_S", SprAccess::Privileged, SprCategory::System,   "Software-use SPR 3 (supervisor)"),
    SprEntry::new(276, "SPRG4",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 4"),
    SprEntry::new(277, "SPRG5",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 5"),
    SprEntry::new(278, "SPRG6",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 6"),
    SprEntry::new(279, "SPRG7",   SprAccess::Privileged, SprCategory::System,   "Software-use SPR 7"),
    SprEntry::new(280, "TBL_W",   SprAccess::Write,      SprCategory::Timer,    "Time Base Lower (supervisor write)"),
    SprEntry::new(281, "TBU_W",   SprAccess::Write,      SprCategory::Timer,    "Time Base Upper (supervisor write)"),
    SprEntry::new(282, "EAR",     SprAccess::Privileged, SprCategory::System,   "External Access Register"),
    SprEntry::new(284, "TBL",     SprAccess::Privileged, SprCategory::Timer,    "Time Base Lower (supervisor)"),
    SprEntry::new(285, "TBU",     SprAccess::Privileged, SprCategory::Timer,    "Time Base Upper (supervisor)"),
    SprEntry::new(287, "PVR",     SprAccess::Read,       SprCategory::System,   "Processor Version Register"),
    // ── Debug / trace ─────────────────────────────────────────────────────
    SprEntry::new(310, "DBSR",    SprAccess::Privileged, SprCategory::Debug,    "Debug Status Register"),
    SprEntry::new(316, "DBCR0",   SprAccess::Privileged, SprCategory::Debug,    "Debug Control Register 0"),
    SprEntry::new(317, "DBCR1",   SprAccess::Privileged, SprCategory::Debug,    "Debug Control Register 1"),
    SprEntry::new(318, "DBCR2",   SprAccess::Privileged, SprCategory::Debug,    "Debug Control Register 2"),
    SprEntry::new(1008,"DABR",    SprAccess::Privileged, SprCategory::Debug,    "Data Address Breakpoint Register"),
    SprEntry::new(1013,"DABRX",   SprAccess::Privileged, SprCategory::Debug,    "DABR Extension"),
    // ── Timer ─────────────────────────────────────────────────────────────
    SprEntry::new(340, "TCR",     SprAccess::Privileged, SprCategory::Timer,    "Timer Control Register"),
    SprEntry::new(336, "TSR",     SprAccess::Privileged, SprCategory::Timer,    "Timer Status Register"),
    SprEntry::new(284, "TBLO",    SprAccess::Privileged, SprCategory::Timer,    "Time Base Lower (alias)"),
    SprEntry::new(285, "TBHI",    SprAccess::Privileged, SprCategory::Timer,    "Time Base Upper (alias)"),
    // ── MMU (classic) ─────────────────────────────────────────────────────
    SprEntry::new(528, "IBAT0U",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 0 Upper"),
    SprEntry::new(529, "IBAT0L",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 0 Lower"),
    SprEntry::new(530, "IBAT1U",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 1 Upper"),
    SprEntry::new(531, "IBAT1L",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 1 Lower"),
    SprEntry::new(532, "IBAT2U",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 2 Upper"),
    SprEntry::new(533, "IBAT2L",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 2 Lower"),
    SprEntry::new(534, "IBAT3U",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 3 Upper"),
    SprEntry::new(535, "IBAT3L",  SprAccess::Privileged, SprCategory::Mmu,      "Instruction BAT 3 Lower"),
    SprEntry::new(536, "DBAT0U",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 0 Upper"),
    SprEntry::new(537, "DBAT0L",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 0 Lower"),
    SprEntry::new(538, "DBAT1U",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 1 Upper"),
    SprEntry::new(539, "DBAT1L",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 1 Lower"),
    SprEntry::new(540, "DBAT2U",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 2 Upper"),
    SprEntry::new(541, "DBAT2L",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 2 Lower"),
    SprEntry::new(542, "DBAT3U",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 3 Upper"),
    SprEntry::new(543, "DBAT3L",  SprAccess::Privileged, SprCategory::Mmu,      "Data BAT 3 Lower"),
    // ── Performance monitor ───────────────────────────────────────────────
    SprEntry::new(771, "PMC1",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 1"),
    SprEntry::new(772, "PMC2",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 2"),
    SprEntry::new(773, "PMC3",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 3"),
    SprEntry::new(774, "PMC4",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 4"),
    SprEntry::new(775, "PMC5",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 5"),
    SprEntry::new(776, "PMC6",    SprAccess::Privileged, SprCategory::Performance, "Performance Monitor Counter 6"),
    SprEntry::new(779, "MMCR0",   SprAccess::Privileged, SprCategory::Performance, "Monitor Mode Control Register 0"),
    SprEntry::new(780, "MMCR1",   SprAccess::Privileged, SprCategory::Performance, "Monitor Mode Control Register 1"),
    SprEntry::new(769, "MMCR2",   SprAccess::Privileged, SprCategory::Performance, "Monitor Mode Control Register 2"),
    SprEntry::new(770, "MMCRA",   SprAccess::Privileged, SprCategory::Performance, "Monitor Mode Control Register A"),
    // ── BookE / embedded ──────────────────────────────────────────────────
    SprEntry::new(512, "SPEFSCR", SprAccess::ReadWrite,  SprCategory::BookE,    "Signal Processing/Embedded FP Status and Control"),
    SprEntry::new(351, "L1CSR0",  SprAccess::Privileged, SprCategory::BookE,    "L1 Cache Control/Status Register 0"),
    SprEntry::new(352, "L1CSR1",  SprAccess::Privileged, SprCategory::BookE,    "L1 Cache Control/Status Register 1"),
    SprEntry::new(400, "IVOR0",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 0 (Critical Input)"),
    SprEntry::new(401, "IVOR1",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 1 (Machine Check)"),
    SprEntry::new(402, "IVOR2",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 2 (Data Storage)"),
    SprEntry::new(403, "IVOR3",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 3 (Instruction Storage)"),
    SprEntry::new(404, "IVOR4",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 4 (External Input)"),
    SprEntry::new(405, "IVOR5",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 5 (Alignment)"),
    SprEntry::new(406, "IVOR6",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 6 (Program)"),
    SprEntry::new(407, "IVOR7",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 7 (FP Unavailable)"),
    SprEntry::new(408, "IVOR8",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 8 (System Call)"),
    SprEntry::new(409, "IVOR9",   SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 9 (Aux Proc Unavailable)"),
    SprEntry::new(410, "IVOR10",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 10 (Decrementer)"),
    SprEntry::new(411, "IVOR11",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 11 (Fixed-Interval Timer)"),
    SprEntry::new(412, "IVOR12",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 12 (Watchdog Timer)"),
    SprEntry::new(413, "IVOR13",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 13 (Data TLB Error)"),
    SprEntry::new(414, "IVOR14",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 14 (Instruction TLB Error)"),
    SprEntry::new(415, "IVOR15",  SprAccess::Privileged, SprCategory::BookE,    "Interrupt Vector Offset Register 15 (Debug)"),
    SprEntry::new(340, "DECAR",   SprAccess::Write,      SprCategory::BookE,    "Decrementer Auto-Reload"),
    // ── System / identification ────────────────────────────────────────────
    SprEntry::new(1023,"PIR",     SprAccess::Read,       SprCategory::System,   "Processor Identification Register"),
    SprEntry::new(1022,"HID1",    SprAccess::Privileged, SprCategory::System,   "Hardware Implementation Register 1"),
    SprEntry::new(1008,"HID0",    SprAccess::Privileged, SprCategory::System,   "Hardware Implementation Register 0"),
    // ── Hypervisor ────────────────────────────────────────────────────────
    SprEntry::new(314, "HSRR0",   SprAccess::Privileged, SprCategory::Hypervisor, "Hypervisor Save/Restore Register 0"),
    SprEntry::new(315, "HSRR1",   SprAccess::Privileged, SprCategory::Hypervisor, "Hypervisor Save/Restore Register 1"),
    SprEntry::new(306, "HSPRG0",  SprAccess::Privileged, SprCategory::Hypervisor, "Hypervisor Software-use SPR 0"),
    SprEntry::new(307, "HSPRG1",  SprAccess::Privileged, SprCategory::Hypervisor, "Hypervisor Software-use SPR 1"),
    // ── POWER9 / POWER10 ──────────────────────────────────────────────────
    SprEntry::new(815, "LPCR",    SprAccess::Privileged, SprCategory::Power9,   "Logical Partitioning Control Register"),
    SprEntry::new(799, "PSSCR",   SprAccess::Privileged, SprCategory::Power9,   "Processor Stop Status and Control Register"),
    SprEntry::new(780, "TAR",     SprAccess::ReadWrite,  SprCategory::Power9,   "Target Address Register"),
    SprEntry::new(13,  "AMR",     SprAccess::ReadWrite,  SprCategory::Power9,   "Authority Mask Register"),
    SprEntry::new(29,  "AMR_S",   SprAccess::Privileged, SprCategory::Power9,   "Authority Mask Register (privileged)"),
];

// ── SPR map ───────────────────────────────────────────────────────────────────

/// Lookup map for PowerPC SPRs, keyed by SPR number.
///
/// Uses `AHashMap` (randomised hasher) so that an adversary who can craft
/// MFSPR/MTSPR SPR numbers in a binary cannot trigger pathological O(n²)
/// hash-collision behaviour during map construction or lookup.
pub struct PpcSprMap {
    by_number: AHashMap<u16, &'static SprEntry>,
    by_name:   AHashMap<&'static str, &'static SprEntry>,
}

impl PpcSprMap {
    /// Build the standard SPR map.
    #[must_use]
    pub fn standard() -> Self {
        let mut by_number = AHashMap::with_capacity(STANDARD_SPRS.len());
        let mut by_name   = AHashMap::with_capacity(STANDARD_SPRS.len());
        for entry in STANDARD_SPRS {
            // Use the first entry for each number (some have aliases)
            by_number.entry(entry.number).or_insert(entry);
            by_name.entry(entry.name).or_insert(entry);
        }
        Self { by_number, by_name }
    }

    /// Look up by SPR number.
    #[must_use]
    pub fn lookup(&self, number: u16) -> Option<&'static SprEntry> {
        self.by_number.get(&number).copied()
    }

    /// Look up by name (case-sensitive).
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<&'static SprEntry> {
        self.by_name.get(name).copied()
    }

    /// List all SPRs in a category.
    #[must_use]
    pub fn list_category(&self, cat: SprCategory) -> Vec<&'static SprEntry> {
        STANDARD_SPRS.iter().filter(|e| e.category == cat).collect()
    }

    /// Total number of known SPRs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Return the name for an SPR number, or a formatted fallback.
#[must_use]
pub fn spr_name(number: u16) -> String {
    for entry in STANDARD_SPRS {
        if entry.number == number {
            return entry.name.to_string();
        }
    }
    format!("spr{number}")
}

/// Return the SPR number for a well-known name, or `None`.
#[must_use]
pub fn spr_number(name: &str) -> Option<u16> {
    STANDARD_SPRS
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
        .map(|e| e.number)
}

/// Decode the raw MFSPR/MTSPR field to a logical SPR number.
///
/// The instruction encodes SPR as `{spr[4:0], spr[9:5]}` (bit-reversed halves).
#[must_use]
pub const fn spr_field_to_number(field: u16) -> u16 {
    let lo = field & 0x1F;
    let hi = (field >> 5) & 0x1F;
    (lo << 5) | hi
}

/// Encode a logical SPR number to the MFSPR/MTSPR instruction field.
#[must_use]
pub const fn spr_number_to_field(number: u16) -> u16 {
    let lo = (number >> 5) & 0x1F;
    let hi = number & 0x1F;
    (hi << 5) | lo
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> PpcSprMap { PpcSprMap::standard() }

    #[test]
    fn test_lookup_xer() {
        let e = map().lookup(1).unwrap();
        assert_eq!(e.name, "XER");
        assert_eq!(e.category, SprCategory::Integer);
    }

    #[test]
    fn test_lookup_lr() {
        let e = map().lookup(8).unwrap();
        assert_eq!(e.name, "LR");
    }

    #[test]
    fn test_lookup_ctr() {
        let e = map().lookup(9).unwrap();
        assert_eq!(e.name, "CTR");
    }

    #[test]
    fn test_lookup_missing() {
        assert!(map().lookup(0xFFFF).is_none());
    }

    #[test]
    fn test_spr_name_known() {
        assert_eq!(spr_name(1), "XER");
        assert_eq!(spr_name(8), "LR");
        assert_eq!(spr_name(9), "CTR");
    }

    #[test]
    fn test_spr_name_unknown() {
        let n = spr_name(0xFFFF);
        assert!(n.starts_with("spr"));
    }

    #[test]
    fn test_spr_number_lr() {
        assert_eq!(spr_number("LR"), Some(8));
    }

    #[test]
    fn test_spr_number_xer() {
        assert_eq!(spr_number("XER"), Some(1));
    }

    #[test]
    fn test_spr_number_unknown() {
        assert!(spr_number("NOTASPR").is_none());
    }

    #[test]
    fn test_field_encoding_roundtrip() {
        for n in [1u16, 8, 9, 18, 256, 512, 1008] {
            let field = spr_number_to_field(n);
            let back  = spr_field_to_number(field);
            assert_eq!(back, n, "roundtrip failed for SPR {n}");
        }
    }

    #[test]
    fn test_field_mflr() {
        // MFLR: spr field in instruction = {spr[4:0]=01000, spr[9:5]=00000}
        // = 0b0_1000_0_0000 = 0x100 in the raw 10-bit field
        // spr_field_to_number(0x100): lo = 0x100 & 0x1F = 0, hi = (0x100 >> 5) & 0x1F = 8
        // result = (0 << 5) | 8 = 8 ✓
        let field: u16 = 0x100;
        assert_eq!(spr_field_to_number(field), 8);
    }

    #[test]
    fn test_list_category_branch() {
        let entries = map().list_category(SprCategory::Branch);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "LR"));
        assert!(entries.iter().any(|e| e.name == "CTR"));
    }

    #[test]
    fn test_list_category_debug() {
        let entries = map().list_category(SprCategory::Debug);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "DABR" || e.name == "DBSR"));
    }

    #[test]
    fn test_list_category_booke() {
        let entries = map().list_category(SprCategory::BookE);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "IVOR0"));
    }

    #[test]
    fn test_access_readable() {
        assert!(SprAccess::Read.is_readable());
        assert!(SprAccess::ReadWrite.is_readable());
        assert!(!SprAccess::Write.is_readable());
    }

    #[test]
    fn test_access_writable() {
        assert!(SprAccess::Write.is_writable());
        assert!(SprAccess::ReadWrite.is_writable());
        assert!(!SprAccess::Read.is_writable());
    }

    #[test]
    fn test_lookup_by_name() {
        let m = map();
        let e = m.lookup_name("VRSAVE").unwrap();
        assert_eq!(e.number, 256);
        assert_eq!(e.category, SprCategory::Vector);
    }

    #[test]
    fn test_spr_entry_display() {
        let e = map().lookup(8).unwrap();
        let s = format!("{e}");
        assert!(s.contains("LR"));
        assert!(s.contains("Branch"));
    }

    #[test]
    fn test_spr_category_display() {
        assert_eq!(SprCategory::Integer.to_string(), "Integer");
        assert_eq!(SprCategory::Mmu.to_string(), "MMU");
    }

    #[test]
    fn test_map_not_empty() {
        assert!(!map().is_empty());
        assert!(map().len() > 20);
    }

    #[test]
    fn test_spr_access_display() {
        assert_eq!(SprAccess::ReadWrite.to_string(), "RW");
        assert_eq!(SprAccess::Read.to_string(), "R");
        assert_eq!(SprAccess::Write.to_string(), "W");
    }

    #[test]
    fn test_pvr() {
        let e = map().lookup(287).unwrap();
        assert_eq!(e.name, "PVR");
        assert_eq!(e.access, SprAccess::Read);
    }

    #[test]
    fn test_hypervisor_sprs() {
        let entries = map().list_category(SprCategory::Hypervisor);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "HSRR0"));
    }

    #[test]
    fn test_performance_sprs() {
        let entries = map().list_category(SprCategory::Performance);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "PMC1"));
    }

    #[test]
    fn test_ivor_sprs_range() {
        let m = map();
        for ivor in 0u16..=15 {
            let num = 400 + ivor;
            let e = m.lookup(num).unwrap();
            assert!(e.name.starts_with("IVOR"));
        }
    }
}
