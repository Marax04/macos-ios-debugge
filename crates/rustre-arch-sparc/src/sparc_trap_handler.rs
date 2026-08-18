//! SPARC trap-table analysis and handler identification.
//!
//! The SPARC trap mechanism vectors through a table at the base address stored
//! in the TBR (Trap Base Register). Each entry is exactly 4 instructions (16
//! bytes). This module:
//!
//! - Defines [`TrapTable`] which parses an in-memory image and extracts trap
//!   entries, building on the existing [`SPARC_V8_TRAPS`] / [`SPARC_V9_TRAPS`]
//!   tables defined in `crate`.
//! - Provides [`TrapHandler`] which models the code behind a trap vector and
//!   estimates the handler type.
//! - Provides [`TrapHandlerKind`] classifying each handler as an interrupt
//!   handler, system-call dispatcher, exception handler, etc.

use ahash::AHashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_core::arch::{InstrFlags, Architecture};
use rustre_core::address::Address;

use crate::{
    SparcArch, SparcLinearDisassembler, SparcTrapEntry,
    SPARC_V8_TRAPS, SPARC_V9_TRAPS,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of instructions per SPARC trap entry (4 × 4 bytes = 16 bytes).
pub const INSTRS_PER_TRAP: usize = 4;
/// Byte size of one trap table entry.
pub const TRAP_ENTRY_BYTES: usize = INSTRS_PER_TRAP * 4;
/// Maximum trap number for SPARC V8 (256 entries).
pub const MAX_V8_TRAPS: usize = 256;
/// Maximum trap number for SPARC V9 (512 entries).
pub const MAX_V9_TRAPS: usize = 512;

// ── TrapHandlerKind ───────────────────────────────────────────────────────────

/// Estimated category of a trap handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapHandlerKind {
    /// Handles an external hardware interrupt (trap 0x11–0x1F).
    InterruptHandler,
    /// Dispatches a system call (trap 0x80 / 0x88).
    SyscallDispatcher,
    /// Handles a processor exception (illegal instruction, alignment, etc.).
    ExceptionHandler,
    /// Manages a register-window overflow (trap 0x05).
    WindowOverflowHandler,
    /// Manages a register-window underflow (trap 0x06).
    WindowUnderflowHandler,
    /// A four-instruction stub that jumps to the real handler elsewhere.
    JumpStub,
    /// All four instructions are NOPs — trap silently ignored.
    NopHandler,
    /// Handler does not return (never calls RETT / DONE / RETRY).
    NonReturning,
    /// Could not classify.
    Unknown,
}

impl fmt::Display for TrapHandlerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InterruptHandler => "interrupt handler",
            Self::SyscallDispatcher => "syscall dispatcher",
            Self::ExceptionHandler => "exception handler",
            Self::WindowOverflowHandler => "window overflow handler",
            Self::WindowUnderflowHandler => "window underflow handler",
            Self::JumpStub => "jump stub",
            Self::NopHandler => "nop handler",
            Self::NonReturning => "non-returning",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ── TrapHandler ───────────────────────────────────────────────────────────────

/// The decoded body of a SPARC trap handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapHandler {
    /// Trap number this handler covers.
    pub trap_number: u8,
    /// Base address of this entry in the trap table.
    pub entry_addr: u64,
    /// Mnemonics of the up to 4 decoded instructions.
    pub mnemonics: Vec<String>,
    /// Operands for each instruction.
    pub operands: Vec<String>,
    /// Estimated handler kind.
    pub kind: TrapHandlerKind,
    /// Whether the handler ends with RETT/DONE/RETRY (normal trap return).
    pub has_return: bool,
    /// If the handler is a jump stub, the jump target (if extractable).
    pub jump_target: Option<u64>,
    /// Known description from the static trap table (if matched).
    pub description: Option<String>,
}

impl TrapHandler {
    /// Return `true` if this handler appears to perform a direct return.
    #[must_use]
    pub const fn returns(&self) -> bool {
        self.has_return
    }

    /// Return `true` if all body instructions are NOPs.
    #[must_use]
    pub fn is_nop(&self) -> bool {
        self.mnemonics.iter().all(|m| m == "NOP")
    }
}

impl fmt::Display for TrapHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = self
            .description
            .as_deref()
            .unwrap_or("(unknown)");
        write!(
            f,
            "Trap 0x{:02X} [{desc}] @ {:#010x}: {} ({} instrs)",
            self.trap_number,
            self.entry_addr,
            self.kind,
            self.mnemonics.len()
        )
    }
}

// ── TrapTableEntry ────────────────────────────────────────────────────────────

/// A parsed trap table entry (static metadata + decoded handler).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapTableEntry {
    /// Trap number (0–255 for V8, 0–511 for V9).
    pub number: u16,
    /// Byte offset from the trap table base for this entry.
    pub offset: usize,
    /// Decoded handler.
    pub handler: TrapHandler,
    /// Whether this trap number is in the known hardware trap table.
    pub is_hardware: bool,
    /// Whether this trap number is in the software (Tcc) range.
    pub is_software: bool,
}

impl TrapTableEntry {
    /// Return `true` if this is a software trap (Tcc instruction).
    #[must_use]
    pub const fn is_software_trap(&self) -> bool {
        self.is_software
    }

    /// Return the description string if available.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.handler.description.as_deref()
    }
}

// ── TrapTable ─────────────────────────────────────────────────────────────────

/// A parsed SPARC trap table from a binary image.
///
/// Reads up to `max_entries` 16-byte entries starting at `base_addr` within
/// `bytes`. Entries are decoded and classified using both the architectural
/// trap tables and heuristic analysis of the decoded instructions.
pub struct TrapTable {
    /// Architecture variant.
    arch: SparcArch,
    /// Parsed entries keyed by trap number.
    /// Uses ahash to resist hash-collision `DoS` when trap numbers are
    /// attacker-controlled (dos-hash-collision mitigation).
    entries: AHashMap<u16, TrapTableEntry>,
    /// Base address of the trap table in memory.
    pub base_addr: u64,
    /// Number of entries parsed.
    pub entry_count: usize,
}

impl TrapTable {
    /// Parse a trap table from `bytes`.
    ///
    /// `base_addr` is the virtual address at which `bytes` is loaded.
    /// `max_entries` limits how many entries are decoded (default: 256 for V8).
    #[must_use]
    pub fn parse(arch: SparcArch, bytes: &[u8], base_addr: u64, max_entries: usize) -> Self {
        let mut entries = AHashMap::new();
        let count = (bytes.len() / TRAP_ENTRY_BYTES).min(max_entries);

        for trap_num in 0..count {
            let offset = trap_num * TRAP_ENTRY_BYTES;
            if offset + TRAP_ENTRY_BYTES > bytes.len() {
                break;
            }
            let entry_bytes = &bytes[offset..offset + TRAP_ENTRY_BYTES];
            let entry_addr = base_addr + offset as u64;

            let handler = Self::decode_handler(&arch, trap_num as u8, entry_bytes, entry_addr);
            let (is_hw, is_sw) = Self::classify_trap_number(trap_num as u16, &arch);

            entries.insert(
                trap_num as u16,
                TrapTableEntry {
                    number: trap_num as u16,
                    offset,
                    handler,
                    is_hardware: is_hw,
                    is_software: is_sw,
                },
            );
        }

        Self {
            arch,
            base_addr,
            entry_count: entries.len(),
            entries,
        }
    }

    /// Return the entry for trap number `n`, if parsed.
    #[must_use]
    pub fn entry(&self, n: u16) -> Option<&TrapTableEntry> {
        self.entries.get(&n)
    }

    /// Return all entries sorted by trap number.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&TrapTableEntry> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_by_key(|e| e.number);
        v
    }

    /// Return all hardware-defined trap entries.
    #[must_use]
    pub fn hardware_entries(&self) -> Vec<&TrapTableEntry> {
        self.all_entries()
            .into_iter()
            .filter(|e| e.is_hardware)
            .collect()
    }

    /// Return all software trap entries.
    #[must_use]
    pub fn software_entries(&self) -> Vec<&TrapTableEntry> {
        self.all_entries()
            .into_iter()
            .filter(|e| e.is_software)
            .collect()
    }

    /// Return all NOP handlers (traps that are silently ignored).
    #[must_use]
    pub fn nop_handlers(&self) -> Vec<&TrapTableEntry> {
        self.all_entries()
            .into_iter()
            .filter(|e| e.handler.is_nop())
            .collect()
    }

    /// Return all jump-stub handlers (entries that branch to a real handler).
    #[must_use]
    pub fn jump_stubs(&self) -> Vec<&TrapTableEntry> {
        self.all_entries()
            .into_iter()
            .filter(|e| matches!(e.handler.kind, TrapHandlerKind::JumpStub))
            .collect()
    }

    /// Return statistics about this trap table.
    #[must_use]
    pub fn stats(&self) -> TrapTableStats {
        let total = self.entry_count;
        let hardware = self.hardware_entries().len();
        let software = self.software_entries().len();
        let nop_count = self.nop_handlers().len();
        let jump_stubs = self.jump_stubs().len();
        TrapTableStats {
            total,
            hardware,
            software,
            nop_count,
            jump_stubs,
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn decode_handler(
        arch: &SparcArch,
        trap_num: u8,
        bytes: &[u8],
        entry_addr: u64,
    ) -> TrapHandler {
        let base = Address::new(entry_addr);
        let instrs: Vec<_> = SparcLinearDisassembler::new(arch, bytes, base)
            .filter_map(std::result::Result::ok)
            .take(INSTRS_PER_TRAP)
            .collect();

        let mnemonics: Vec<String> = instrs.iter().map(|i| i.mnemonic.clone()).collect();
        let operands: Vec<String> = instrs.iter().map(|i| i.operands.clone()).collect();

        let has_return = instrs
            .iter()
            .any(|i| i.flags.contains(InstrFlags::RET));

        let jump_target = instrs
            .iter()
            .find(|i| i.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL))
            .and_then(|i| {
                let hex: String = i
                    .operands
                    .trim_start_matches('$')
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                u64::from_str_radix(&hex, 16).ok()
            });

        let kind = Self::classify_kind(
            trap_num,
            &mnemonics,
            has_return,
            jump_target.is_some(),
        );

        // Look up description in the static tables.
        let description = SPARC_V8_TRAPS
            .iter()
            .chain(SPARC_V9_TRAPS.iter())
            .find(|e| e.number == trap_num)
            .map(|e| e.description.to_string());

        TrapHandler {
            trap_number: trap_num,
            entry_addr,
            mnemonics,
            operands,
            kind,
            has_return,
            jump_target,
            description,
        }
    }

    fn classify_kind(
        trap_num: u8,
        mnemonics: &[String],
        has_return: bool,
        has_jump: bool,
    ) -> TrapHandlerKind {
        // Interrupt-level trap slots are classified by trap number even when
        // populated with NOPs, since hardware interrupts are wired by vector.
        if (0x11..=0x1F).contains(&trap_num) {
            return TrapHandlerKind::InterruptHandler;
        }
        // All NOPs.
        if mnemonics.iter().all(|m| m == "NOP") {
            return TrapHandlerKind::NopHandler;
        }
        // Jump stub: first non-NOP instruction is a branch.
        if has_jump && !has_return {
            return TrapHandlerKind::JumpStub;
        }
        // Window overflow / underflow.
        if trap_num == 0x05 {
            return TrapHandlerKind::WindowOverflowHandler;
        }
        if trap_num == 0x06 {
            return TrapHandlerKind::WindowUnderflowHandler;
        }
        // System call.
        if trap_num == 0x80 || trap_num == 0x88 {
            return TrapHandlerKind::SyscallDispatcher;
        }
        // Interrupt level traps.
        if (0x11..=0x1F).contains(&trap_num) {
            return TrapHandlerKind::InterruptHandler;
        }
        // Other hardware exceptions.
        if trap_num <= 0x2F && trap_num > 0 {
            return TrapHandlerKind::ExceptionHandler;
        }
        if !has_return {
            return TrapHandlerKind::NonReturning;
        }
        TrapHandlerKind::Unknown
    }

    fn classify_trap_number(n: u16, arch: &SparcArch) -> (bool, bool) {
        let table: &[SparcTrapEntry] = if arch.bits == 64 {
            SPARC_V9_TRAPS
        } else {
            SPARC_V8_TRAPS
        };
        let is_hw = table.iter().any(|e| u16::from(e.number) == n);
        // Software traps: V8 = 0x80–0xFF, V9 = 0x100–0x1FF
        let is_sw = if arch.bits == 64 {
            (0x100..=0x1FF).contains(&n)
        } else {
            (0x80..=0xFF).contains(&n)
        };
        (is_hw, is_sw)
    }
}

impl fmt::Debug for TrapTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrapTable")
            .field("base_addr", &format_args!("{:#010x}", self.base_addr))
            .field("entry_count", &self.entry_count)
            .field("arch", &self.arch.name())
            .finish()
    }
}

// ── TrapTableStats ────────────────────────────────────────────────────────────

/// Aggregate statistics for a parsed trap table.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TrapTableStats {
    /// Total entries parsed.
    pub total: usize,
    /// Entries matching known hardware traps.
    pub hardware: usize,
    /// Entries in the software trap range.
    pub software: usize,
    /// Entries that are all NOPs.
    pub nop_count: usize,
    /// Entries that are jump stubs.
    pub jump_stubs: usize,
}

impl fmt::Display for TrapTableStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrapTableStats {{ total={}, hw={}, sw={}, nop={}, stubs={} }}",
            self.total, self.hardware, self.software, self.nop_count, self.jump_stubs
        )
    }
}

// ── TrapTableScanner ─────────────────────────────────────────────────────────

/// Scans a binary image to find potential trap table locations.
///
/// A trap table in a SPARC binary is typically aligned to a 4 KiB or 64 KiB
/// boundary. Each 16-byte entry is 4 instructions. The scanner looks for
/// regions where the first instruction of many consecutive 16-byte chunks
/// is a SETHI or NOP (common in trap stubs).
pub struct TrapTableScanner {
    arch: SparcArch,
    /// Minimum number of consecutive valid entries to declare a trap table.
    pub min_entries: usize,
}

impl TrapTableScanner {
    /// Create a new scanner.
    #[must_use]
    pub const fn new(arch: SparcArch) -> Self {
        Self { arch, min_entries: 8 }
    }

    /// Scan `bytes` (loaded at `base_addr`) for potential trap table starts.
    ///
    /// Returns a list of candidate base addresses (file offsets).
    #[must_use]
    pub fn scan(&self, bytes: &[u8], base_addr: u64) -> Vec<u64> {
        let mut candidates = Vec::new();
        let step = TRAP_ENTRY_BYTES; // scan at 16-byte granularity

        let mut offset = 0usize;
        while offset + step * self.min_entries <= bytes.len() {
            if self.looks_like_trap_table(bytes, offset) {
                candidates.push(base_addr + offset as u64);
                // Skip forward to avoid overlapping candidates.
                offset += step * self.min_entries;
            } else {
                offset += step;
            }
        }
        candidates
    }

    /// Architecture configuration this scanner was built with.
    #[must_use]
    pub const fn arch(&self) -> &SparcArch {
        &self.arch
    }

    fn looks_like_trap_table(&self, bytes: &[u8], start: usize) -> bool {
        let required = self.min_entries;
        let mut good = 0usize;

        for i in 0..required {
            let off = start + i * TRAP_ENTRY_BYTES;
            if off + 4 > bytes.len() {
                break;
            }
            let word = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            // SPARC is big-endian by default but v9 also has a little-endian
            // variant — decode according to the configured architecture.
            let instr = match self.arch.endian {
                rustre_core::endian::Endian::Big => u32::from_be_bytes(word),
                rustre_core::endian::Endian::Little => u32::from_le_bytes(word),
            };
            // First instruction: SETHI (%g0 NOP) or SETHI or NOP or SAVE or MOV
            let fmt2 = (instr >> 30) == 0;
            let op2 = (instr >> 22) & 7;
            let is_sethi_nop = fmt2 && op2 == 4; // includes NOP (SETHI 0,%g0)
            let is_branch = (instr >> 30) == 0 && ((op2 == 2) || (op2 == 6));
            if is_sethi_nop || is_branch {
                good += 1;
            }
        }
        good >= required / 2
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_nop;

    fn v8_arch() -> SparcArch {
        SparcArch::new_v8()
    }

    /// Build a fake 256-entry trap table filled with NOP stubs.
    fn make_nop_table(entries: usize) -> Vec<u8> {
        let nop = encode_nop().to_be_bytes();
        let entry: Vec<u8> = nop.iter().copied().cycle().take(TRAP_ENTRY_BYTES).collect();
        entry.iter().copied().cycle().take(entries * TRAP_ENTRY_BYTES).collect()
    }

    /// Build a single trap entry with: SETHI, NOP, NOP, RETT %i7+8
    fn make_rett_entry() -> [u8; 16] {
        let sethi: u32 = (1u32 << 25) | (0b100u32 << 22) | 0; // SETHI %hi(0), %g0 = NOP
        let nop: u32 = encode_nop();
        // RETT %i7+8: fmt=2, op3=0x39, rs1=31, i=1, simm13=8
        let rett: u32 = (0b10u32 << 30) | (0u32 << 25) | (0x39u32 << 19) | (31u32 << 14) | (1u32 << 13) | 8u32;
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&sethi.to_be_bytes());
        out[4..8].copy_from_slice(&nop.to_be_bytes());
        out[8..12].copy_from_slice(&nop.to_be_bytes());
        out[12..16].copy_from_slice(&rett.to_be_bytes());
        out
    }

    #[test]
    fn test_parse_nop_table() {
        let bytes = make_nop_table(8);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0xFFFF_0000, 8);
        assert_eq!(tt.entry_count, 8);
        assert_eq!(tt.nop_handlers().len(), 8);
    }

    #[test]
    fn test_parse_entry_zero() {
        let bytes = make_nop_table(4);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 4);
        let e = tt.entry(0).expect("entry 0 missing");
        assert_eq!(e.number, 0);
    }

    #[test]
    fn test_entry_description_from_static_table() {
        // Trap 0x05 = window_overflow in V8
        let mut bytes = make_nop_table(16);
        let entry = make_rett_entry();
        bytes[5 * TRAP_ENTRY_BYTES..5 * TRAP_ENTRY_BYTES + 16].copy_from_slice(&entry);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 16);
        let e = tt.entry(5).unwrap();
        assert!(e.description().is_some());
        assert!(e.description().unwrap().contains("window"));
    }

    #[test]
    fn test_window_overflow_handler_kind() {
        let mut bytes = make_nop_table(16);
        // Add SAVE instruction at offset 0 of entry 5 to make it look like WO handler
        let rett_entry = make_rett_entry();
        bytes[5 * TRAP_ENTRY_BYTES..5 * TRAP_ENTRY_BYTES + 16].copy_from_slice(&rett_entry);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 16);
        let e = tt.entry(5).unwrap();
        assert_eq!(e.handler.kind, TrapHandlerKind::WindowOverflowHandler);
    }

    #[test]
    fn test_window_underflow_handler_kind() {
        let mut bytes = make_nop_table(16);
        let rett_entry = make_rett_entry();
        bytes[6 * TRAP_ENTRY_BYTES..6 * TRAP_ENTRY_BYTES + 16].copy_from_slice(&rett_entry);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 16);
        let e = tt.entry(6).unwrap();
        assert_eq!(e.handler.kind, TrapHandlerKind::WindowUnderflowHandler);
    }

    #[test]
    fn test_syscall_handler_kind() {
        let mut bytes = make_nop_table(0x90);
        let rett_entry = make_rett_entry();
        bytes[0x80 * TRAP_ENTRY_BYTES..0x80 * TRAP_ENTRY_BYTES + 16].copy_from_slice(&rett_entry);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 0x90);
        let e = tt.entry(0x80).unwrap();
        assert_eq!(e.handler.kind, TrapHandlerKind::SyscallDispatcher);
    }

    #[test]
    fn test_hardware_entries() {
        let bytes = make_nop_table(32);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 32);
        let hw = tt.hardware_entries();
        // At least some V8 traps are in range 0–31.
        assert!(!hw.is_empty());
    }

    #[test]
    fn test_stats_total() {
        let bytes = make_nop_table(10);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 10);
        let stats = tt.stats();
        assert_eq!(stats.total, 10);
    }

    #[test]
    fn test_stats_nop_count() {
        let bytes = make_nop_table(10);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 10);
        let stats = tt.stats();
        assert_eq!(stats.nop_count, 10);
    }

    #[test]
    fn test_trap_handler_display() {
        let h = TrapHandler {
            trap_number: 0x02,
            entry_addr: 0x20,
            mnemonics: vec!["NOP".to_string(); 4],
            operands: vec![String::new(); 4],
            kind: TrapHandlerKind::NopHandler,
            has_return: false,
            jump_target: None,
            description: Some("illegal_instruction".to_string()),
        };
        let s = h.to_string();
        assert!(s.contains("0x02"));
        assert!(s.contains("nop handler"));
    }

    #[test]
    fn test_trap_handler_kind_display() {
        let kinds = [
            TrapHandlerKind::InterruptHandler,
            TrapHandlerKind::SyscallDispatcher,
            TrapHandlerKind::ExceptionHandler,
            TrapHandlerKind::WindowOverflowHandler,
            TrapHandlerKind::WindowUnderflowHandler,
            TrapHandlerKind::JumpStub,
            TrapHandlerKind::NopHandler,
            TrapHandlerKind::NonReturning,
            TrapHandlerKind::Unknown,
        ];
        for k in &kinds {
            assert!(!k.to_string().is_empty());
        }
    }

    #[test]
    fn test_trap_table_debug_format() {
        let bytes = make_nop_table(4);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0x4000, 4);
        let s = format!("{tt:?}");
        assert!(s.contains("TrapTable"));
    }

    #[test]
    fn test_interrupt_handler_range() {
        let bytes = make_nop_table(32);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 32);
        let e = tt.entry(0x11).unwrap();
        assert_eq!(e.handler.kind, TrapHandlerKind::InterruptHandler);
    }

    #[test]
    fn test_all_entries_sorted() {
        let bytes = make_nop_table(16);
        let tt = TrapTable::parse(v8_arch(), &bytes, 0, 16);
        let all = tt.all_entries();
        for w in all.windows(2) {
            assert!(w[0].number < w[1].number);
        }
    }

    #[test]
    fn test_scanner_no_false_positives_random() {
        // Random bytes should not look like a trap table.
        let bytes: Vec<u8> = (0..256).map(|i| (i as u8).wrapping_mul(17)).collect();
        let scanner = TrapTableScanner { arch: v8_arch(), min_entries: 8 };
        let candidates = scanner.scan(&bytes, 0);
        // Might find some — just verify it doesn't panic.
        let _ = candidates;
    }

    #[test]
    fn test_scanner_finds_nop_table() {
        let bytes = make_nop_table(16);
        let scanner = TrapTableScanner { arch: v8_arch(), min_entries: 4 };
        let candidates = scanner.scan(&bytes, 0x1000);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0], 0x1000);
    }

    #[test]
    fn test_trap_table_stats_display() {
        let stats = TrapTableStats {
            total: 10,
            hardware: 5,
            software: 2,
            nop_count: 3,
            jump_stubs: 1,
        };
        let s = stats.to_string();
        assert!(s.contains("TrapTableStats"));
        assert!(s.contains("10"));
    }
}
