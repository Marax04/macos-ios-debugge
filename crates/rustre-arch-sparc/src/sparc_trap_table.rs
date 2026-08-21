//! `sparc_trap_table` — SPARC trap (exception) table database.
//!
//! The SPARC Trap Base Register (TBR) points to a table of 16-instruction
//! (64-byte) slots.  Each trap type maps to an offset into this table.  This
//! module provides a typed database of SPARC v8 and v9 trap entries, lookup
//! utilities, and a heuristic binary scanner that locates trap handlers.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// TrapKind — classification of a trap
// ─────────────────────────────────────────────────────────────────────────────

/// High-level category of a SPARC trap.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrapKind {
    /// Hardware reset (trap 0).
    Reset,
    /// Instruction-access exception (bad PC, bus error, etc.).
    InstructionAccess,
    /// Illegal instruction (reserved encoding).
    IllegalInstruction,
    /// Privileged instruction executed in user mode.
    PrivilegedInstruction,
    /// FPU disabled or absent.
    FpDisabled,
    /// Co-processor disabled or absent.
    CpDisabled,
    /// Unimplemented flush instruction.
    UnimplementedFlush,
    /// Watchpoint detected.
    Watchpoint,
    /// Window overflow (register window spill).
    WindowOverflow,
    /// Window underflow (register window fill).
    WindowUnderflow,
    /// Memory address alignment error.
    MemAddressNotAligned,
    /// FPU exception.
    FpException,
    /// Data-access exception (MMU fault on load/store).
    DataAccess,
    /// Tag overflow (`taddcc`/`tsubcc` tag bits set).
    TagOverflow,
    /// Clean windows trap (v9+).
    CleanWindows,
    /// Division by zero.
    DivisionByZero,
    /// Data-access protection (v9+).
    DataAccessProtection,
    /// Software trap (Ticc instruction).
    SoftwareTrap(u8),
    /// Interrupt level 1–15.
    Interrupt(u8),
    /// Implementation-defined trap.
    ImplementationDefined(u8),
    /// Spare / unassigned.
    Spare,
}

impl TrapKind {
    /// Return a short string label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Reset => "reset".into(),
            Self::InstructionAccess => "inst_access".into(),
            Self::IllegalInstruction => "illegal_instr".into(),
            Self::PrivilegedInstruction => "priv_instr".into(),
            Self::FpDisabled => "fp_disabled".into(),
            Self::CpDisabled => "cp_disabled".into(),
            Self::UnimplementedFlush => "unimp_flush".into(),
            Self::Watchpoint => "watchpoint".into(),
            Self::WindowOverflow => "win_overflow".into(),
            Self::WindowUnderflow => "win_underflow".into(),
            Self::MemAddressNotAligned => "mem_align".into(),
            Self::FpException => "fp_exception".into(),
            Self::DataAccess => "data_access".into(),
            Self::TagOverflow => "tag_overflow".into(),
            Self::CleanWindows => "clean_windows".into(),
            Self::DivisionByZero => "div_by_zero".into(),
            Self::DataAccessProtection => "data_prot".into(),
            Self::SoftwareTrap(n) => format!("swt_{n}"),
            Self::Interrupt(n) => format!("irq_{n}"),
            Self::ImplementationDefined(n) => format!("impl_{n:#04x}"),
            Self::Spare => "spare".into(),
        }
    }

    /// Returns `true` if this is a synchronous hardware trap.
    #[must_use]
    pub const fn is_synchronous(&self) -> bool {
        !matches!(self, Self::Interrupt(_) | Self::Reset)
    }

    /// Returns `true` if this is an interrupt trap (asynchronous).
    #[must_use]
    pub const fn is_interrupt(&self) -> bool {
        matches!(self, Self::Interrupt(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TrapEntry — one entry in the database
// ─────────────────────────────────────────────────────────────────────────────

/// A single SPARC trap table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapEntry {
    /// Trap type number (tt field), 0x00–0xFF.
    pub tt: u8,
    /// Canonical trap name (e.g. `"window_overflow"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Classification.
    pub kind: TrapKind,
    /// Byte offset into the trap table (`tt * 0x10` for SPARC v8).
    pub table_offset: u16,
    /// Priority (lower number = higher priority; 1 = highest).
    pub priority: u8,
    /// Whether this trap can be deferred (v9+).
    pub deferrable: bool,
    /// SPARC version: `8` or `9`.
    pub sparc_version: u8,
}

impl TrapEntry {
    /// Byte address of this trap handler given the trap base address.
    #[must_use]
    pub const fn handler_addr(&self, tbr: u32) -> u32 {
        (tbr & 0xFFFF_F000) | (self.table_offset as u32)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SparcTrapTable — the full typed table
// ─────────────────────────────────────────────────────────────────────────────

/// The SPARC trap table, backed by a sorted list of [`TrapEntry`] values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcTrapTable {
    pub entries: Vec<TrapEntry>,
    /// `8` for SPARC v8, `9` for v9.
    pub version: u8,
}

impl SparcTrapTable {
    /// Look up a trap entry by type number.
    #[must_use]
    pub fn by_tt(&self, tt: u8) -> Option<&TrapEntry> {
        self.entries.iter().find(|e| e.tt == tt)
    }

    /// Look up by name (exact, case-insensitive).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&TrapEntry> {
        let lower = name.to_lowercase();
        self.entries.iter().find(|e| e.name.to_lowercase() == lower)
    }

    /// All interrupt-level traps.
    #[must_use]
    pub fn interrupts(&self) -> Vec<&TrapEntry> {
        self.entries.iter().filter(|e| e.kind.is_interrupt()).collect()
    }

    /// All synchronous hardware traps.
    #[must_use]
    pub fn synchronous(&self) -> Vec<&TrapEntry> {
        self.entries.iter().filter(|e| e.kind.is_synchronous()).collect()
    }

    /// All software trap entries.
    #[must_use]
    pub fn software_traps(&self) -> Vec<&TrapEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.kind, TrapKind::SoftwareTrap(_)))
            .collect()
    }

    /// Total number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database builders
// ─────────────────────────────────────────────────────────────────────────────

fn e(tt: u8, name: &str, desc: &str, kind: TrapKind, priority: u8, sparc_version: u8) -> TrapEntry {
    TrapEntry {
        tt,
        name: name.to_owned(),
        description: desc.to_owned(),
        kind,
        table_offset: u16::from(tt) * 0x10,
        priority,
        deferrable: false,
        sparc_version,
    }
}

/// Build the SPARC v8 trap table.
#[must_use]
pub fn sparc_v8_trap_table() -> SparcTrapTable {
    use TrapKind::{Reset, InstructionAccess, IllegalInstruction, PrivilegedInstruction, FpDisabled, WindowOverflow, WindowUnderflow, MemAddressNotAligned, FpException, DataAccess, TagOverflow, Watchpoint, DivisionByZero, Interrupt, CpDisabled, UnimplementedFlush, SoftwareTrap, Spare};
    let v = 8u8;
    let mut entries = vec![
        e(0x00, "reset",                "Power-on/reset trap",                         Reset,                  1, v),
        e(0x01, "inst_access_except",   "Instruction access exception",                InstructionAccess,      5, v),
        e(0x02, "illegal_instruction",  "Illegal instruction",                         IllegalInstruction,     7, v),
        e(0x03, "priv_instruction",     "Privileged instruction",                      PrivilegedInstruction,  6, v),
        e(0x04, "fp_disabled",          "Floating-point disabled",                     FpDisabled,             8, v),
        e(0x05, "window_overflow",      "Register window overflow",                    WindowOverflow,         9, v),
        e(0x06, "window_underflow",     "Register window underflow",                   WindowUnderflow,        9, v),
        e(0x07, "mem_address_not_aligned","Memory address not aligned",                MemAddressNotAligned,   10, v),
        e(0x08, "fp_exception",         "Floating-point exception",                    FpException,            11, v),
        e(0x09, "data_access_except",   "Data access exception",                       DataAccess,             13, v),
        e(0x0A, "tag_overflow",         "Tag overflow",                                TagOverflow,            14, v),
        e(0x0B, "watchpoint_detected",  "Watchpoint detected",                         Watchpoint,             15, v),
        e(0x0C, "div_by_zero",          "Division by zero (reserved v8; impl-defined)",DivisionByZero,        15, v),
    ];

    // Interrupt levels 1–15 (tt = 0x11..0x1F)
    for lvl in 1u8..=15 {
        let tt = 0x10 + lvl;
        entries.push(e(tt, &format!("irq_level_{lvl}"), &format!("Interrupt Level {lvl}"), Interrupt(lvl), 16 - lvl, v));
    }

    // CP disabled (0x24)
    entries.push(e(0x24, "cp_disabled", "Coprocessor disabled", CpDisabled, 8, v));

    // Unimplemented FLUSH (0x25)
    entries.push(e(0x25, "unimp_flush", "Unimplemented FLUSH instruction", UnimplementedFlush, 7, v));

    // Software traps 0x80..0xFF
    for n in 0x00u8..=0x7Fu8 {
        let tt = 0x80u8.wrapping_add(n);
        let name = format!("swt_{n:#04x}");
        let desc = format!("Software trap (Ticc) 0x{n:02X}");
        entries.push(e(tt, &name, &desc, SoftwareTrap(n), 16, v));
    }

    // Spare entries 0x0D..0x0F, 0x20..0x23, 0x26..0x7F
    for tt in [0x0Du8, 0x0Eu8, 0x0Fu8] {
        entries.push(e(tt, "spare", "Spare / Reserved", Spare, 255, v));
    }

    entries.sort_by_key(|e| e.tt);
    SparcTrapTable { entries, version: 8 }
}

/// Build the SPARC v9 trap table (extends v8 with additional traps).
#[must_use]
pub fn sparc_v9_trap_table() -> SparcTrapTable {
    use TrapKind::{CleanWindows, InstructionAccess, IllegalInstruction, CpDisabled, DataAccessProtection, MemAddressNotAligned, DivisionByZero};
    let v = 9u8;
    let mut base = sparc_v8_trap_table().entries;

    // Additional v9 traps
    let extra = vec![
        e(0x0C, "clean_windows",           "Clean windows",                CleanWindows,       10, v),
        e(0x21, "instruction_access_err",  "Instruction access error",     InstructionAccess,   5, v),
        e(0x22, "illegal_instruction",     "Illegal instruction (v9)",     IllegalInstruction,  7, v),
        e(0x24, "cp_disabled",             "CP disabled",                  CpDisabled,          8, v),
        e(0x28, "data_access_prot",        "Data access protection",       DataAccessProtection,13, v),
        e(0x29, "mem_address_not_aligned", "Mem addr not aligned (v9)",    MemAddressNotAligned,10, v),
        e(0x2A, "lddf_mem_not_aligned",    "LDDF mem addr not aligned",    MemAddressNotAligned,10, v),
        e(0x2B, "stdf_mem_not_aligned",    "STDF mem addr not aligned",    MemAddressNotAligned,10, v),
        e(0x2C, "div_by_zero",             "Division by zero",             DivisionByZero,     15, v),
    ];

    for ex in extra {
        if let Some(existing) = base.iter_mut().find(|e| e.tt == ex.tt) {
            *existing = ex; // Override with v9 definition
        } else {
            base.push(ex);
        }
    }

    base.sort_by_key(|e| e.tt);
    SparcTrapTable { entries: base, version: 9 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public lookup API
// ─────────────────────────────────────────────────────────────────────────────

/// Return the name of a SPARC v8 trap given its `tt` value.
///
/// Returns `None` if the `tt` is not in the database.
#[must_use]
pub fn trap_name(tt: u8) -> Option<String> {
    sparc_v8_trap_table().by_tt(tt).map(|e| e.name.clone())
}

/// Return the name of a SPARC v9 trap given its `tt` value.
#[must_use]
pub fn trap_name_v9(tt: u8) -> Option<String> {
    sparc_v9_trap_table().by_tt(tt).map(|e| e.name.clone())
}

/// Build a fast `tt → TrapEntry` map for v8.
#[must_use]
pub fn sparc_v8_trap_map() -> HashMap<u8, TrapEntry> {
    sparc_v8_trap_table()
        .entries
        .into_iter()
        .map(|e| (e.tt, e))
        .collect()
}

/// Build a fast `tt → TrapEntry` map for v9.
#[must_use]
pub fn sparc_v9_trap_map() -> HashMap<u8, TrapEntry> {
    sparc_v9_trap_table()
        .entries
        .into_iter()
        .map(|e| (e.tt, e))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// TrapHandlerScanner — locate potential trap handlers in a binary
// ─────────────────────────────────────────────────────────────────────────────

/// A potential trap handler location found by heuristic scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapHandlerHit {
    /// Byte offset in the image.
    pub offset: usize,
    /// Address if base address is known.
    pub address: Option<u32>,
    /// Trap entry if TBR pattern matched.
    pub trap_entry: Option<TrapEntry>,
    /// Instruction word at the hit.
    pub instr_word: u32,
}

/// Scans a binary for SPARC trap table patterns.
///
/// Looks for sequences of 4 instructions that match the typical trap-handler
/// prologue (`sethi %hi(handler), %l3` / `jmpl %l3+%lo(handler), %g0` pattern,
/// or the "trivial" `ta 0 / nop` pattern).
#[derive(Debug, Clone, Default)]
pub struct TrapHandlerScanner {
    pub tbr: Option<u32>,
}

impl TrapHandlerScanner {
    /// Create a scanner.  If `tbr` is known, results will include resolved addresses.
    #[must_use]
    pub const fn new(tbr: Option<u32>) -> Self {
        Self { tbr }
    }

    /// Scan `data` (big-endian SPARC words) for trap handler prologues.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_addr: u32) -> Vec<TrapHandlerHit> {
        let table = sparc_v8_trap_table();
        let mut hits = Vec::new();

        let n = data.len() / 4;
        for i in 0..n {
            let off = i * 4;
            if off + 4 > data.len() { break; }
            let w = u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let pc = base_addr + crate::sparc_narrow::low_u32_of_usize(off);

            // Heuristic 1: `sethi` followed by `jmpl` is a typical 2-instr handler jump
            let is_sethi = (w >> 30) == 0 && (w >> 22) & 0x7 == 0x4; // op=00, op2=100 = SETHI
            if is_sethi {
                // Check if this is at a 16-instruction (0x40-byte) aligned offset
                // that matches a trap table slot.
                if let Some(tbr) = self.tbr {
                    let tbr_base = tbr & 0xFFFF_F000;
                    if pc >= tbr_base {
                        let slot_off = pc - tbr_base;
                        if slot_off.trailing_zeros() >= 6 {
                            let tt = crate::sparc_narrow::low_u8_of_u32(slot_off >> 4);
                            let entry = table.by_tt(tt).cloned();
                            hits.push(TrapHandlerHit {
                                offset: off,
                                address: Some(pc),
                                trap_entry: entry,
                                instr_word: w,
                            });
                        }
                    }
                } else {
                    hits.push(TrapHandlerHit {
                        offset: off,
                        address: Some(pc),
                        trap_entry: None,
                        instr_word: w,
                    });
                }
            }
        }
        hits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v8_table_non_empty() {
        let t = sparc_v8_trap_table();
        assert!(!t.is_empty());
    }

    #[test]
    fn test_reset_trap() {
        let t = sparc_v8_trap_table();
        let r = t.by_tt(0x00).unwrap();
        assert_eq!(r.name, "reset");
        assert_eq!(r.kind, TrapKind::Reset);
    }

    #[test]
    fn test_window_overflow_tt05() {
        let t = sparc_v8_trap_table();
        let e = t.by_tt(0x05).unwrap();
        assert_eq!(e.kind, TrapKind::WindowOverflow);
    }

    #[test]
    fn test_window_underflow_tt06() {
        let t = sparc_v8_trap_table();
        let e = t.by_tt(0x06).unwrap();
        assert_eq!(e.kind, TrapKind::WindowUnderflow);
    }

    #[test]
    fn test_interrupt_traps() {
        let t = sparc_v8_trap_table();
        let irqs = t.interrupts();
        assert_eq!(irqs.len(), 15); // IRQ levels 1..=15
    }

    #[test]
    fn test_software_traps() {
        let t = sparc_v8_trap_table();
        let swt = t.software_traps();
        assert_eq!(swt.len(), 128); // 0x80..0xFF
    }

    #[test]
    fn test_trap_name_lookup() {
        assert_eq!(trap_name(0x00).as_deref(), Some("reset"));
        assert_eq!(trap_name(0x05).as_deref(), Some("window_overflow"));
    }

    #[test]
    fn test_trap_by_name() {
        let t = sparc_v8_trap_table();
        assert!(t.by_name("reset").is_some());
        assert!(t.by_name("nonexistent").is_none());
    }

    #[test]
    fn test_table_offset_calculation() {
        let t = sparc_v8_trap_table();
        let e = t.by_tt(0x05).unwrap();
        assert_eq!(e.table_offset, 0x05 * 0x10);
    }

    #[test]
    fn test_handler_addr() {
        let t = sparc_v8_trap_table();
        let e = t.by_tt(0x05).unwrap();
        let tbr = 0x1000_0000u32;
        assert_eq!(e.handler_addr(tbr), tbr | (0x05u32 * 0x10));
    }

    #[test]
    fn test_v9_table_has_clean_windows() {
        let t = sparc_v9_trap_table();
        let e = t.by_tt(0x0C).unwrap();
        assert_eq!(e.kind, TrapKind::CleanWindows);
    }

    #[test]
    fn test_v9_map_contains_data_access_prot() {
        let m = sparc_v9_trap_map();
        assert!(m.contains_key(&0x28));
    }

    #[test]
    fn test_synchronous_traps() {
        let t = sparc_v8_trap_table();
        let sync = t.synchronous();
        assert!(!sync.is_empty());
        // Interrupts should not be in synchronous list
        assert!(sync.iter().all(|e| !e.kind.is_interrupt()));
    }

    #[test]
    fn test_trap_kind_label() {
        assert_eq!(TrapKind::Reset.label(), "reset");
        assert_eq!(TrapKind::WindowOverflow.label(), "win_overflow");
        assert_eq!(TrapKind::SoftwareTrap(5).label(), "swt_5");
        assert_eq!(TrapKind::Interrupt(3).label(), "irq_3");
    }

    #[test]
    fn test_scanner_empty() {
        let scanner = TrapHandlerScanner::new(None);
        assert!(scanner.scan(&[], 0).is_empty());
    }

    #[test]
    fn test_v8_map_non_empty() {
        let m = sparc_v8_trap_map();
        assert!(!m.is_empty());
        assert!(m.contains_key(&0x00));
    }

    #[test]
    fn test_trap_priority_order() {
        let t = sparc_v8_trap_table();
        let reset = t.by_tt(0x00).unwrap();
        let irq1 = t.by_tt(0x11).unwrap();
        assert!(reset.priority < irq1.priority, "reset has higher priority than IRQ1");
    }
}
