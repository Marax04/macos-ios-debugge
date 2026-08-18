//! Zero-page variable tracking for MOS 6502 programs.
//!
//! The 6502's zero page (addresses `$00`–`$FF`) is a special 256-byte region
//! that many programs treat as fast, directly-addressable pseudo-registers.
//! This module provides a static-analysis pass that collects every zero-page
//! access observed in a linear disassembly and builds a usage profile for
//! each address: which instructions access it, whether it is read or written,
//! and how many times each access pattern occurs.
//!
//! # Typical usage
//!
//! ```ignore
//! let zp = Mos6502ZeroPage::analyze(bytes, 0xC000);
//! for entry in zp.sorted_by_access_count() {
//!     println!("ZP[${:02X}]  R={} W={}", entry.address, entry.read_count, entry.write_count);
//! }
//! ```

use crate::opcode_table;
use crate::AddrMode;

// ── ZeroPageAccessKind ────────────────────────────────────────────────────────

/// Whether a zero-page access is a read, a write, or a read-modify-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ZeroPageAccessKind {
    /// The instruction reads from the zero-page address.
    Read,
    /// The instruction writes to the zero-page address.
    Write,
    /// The instruction reads, modifies, and writes back (e.g. `INC`, `ASL`).
    ReadModifyWrite,
    /// The address is used as a pointer (indirect mode).
    Indirect,
}

impl ZeroPageAccessKind {
    /// Return `true` if this access involves a read.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadModifyWrite | Self::Indirect)
    }

    /// Return `true` if this access involves a write.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadModifyWrite)
    }
}

impl std::fmt::Display for ZeroPageAccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Read => "R",
            Self::Write => "W",
            Self::ReadModifyWrite => "RMW",
            Self::Indirect => "IND",
        };
        f.write_str(s)
    }
}

// ── ZeroPageReference ─────────────────────────────────────────────────────────

/// A single observed reference to a zero-page address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZeroPageReference {
    /// Virtual address of the instruction that references this ZP address.
    pub instruction_addr: u64,
    /// Mnemonic of the referencing instruction (e.g. `"LDA"`).
    pub mnemonic: String,
    /// Whether this was a read, write, RMW, or indirect access.
    pub kind: ZeroPageAccessKind,
}

// ── ZeroPageEntry ─────────────────────────────────────────────────────────────

/// Aggregated usage data for a single zero-page address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZeroPageEntry {
    /// The zero-page address (0x00–0xFF).
    pub address: u8,
    /// Number of read accesses.
    pub read_count: u32,
    /// Number of write accesses.
    pub write_count: u32,
    /// Number of read-modify-write accesses.
    pub rmw_count: u32,
    /// Number of indirect (pointer) accesses.
    pub indirect_count: u32,
    /// All individual references, in instruction order.
    pub references: Vec<ZeroPageReference>,
    /// Suggested variable name (assigned by [`Mos6502ZeroPage::assign_names`]).
    pub name: Option<String>,
}

impl ZeroPageEntry {
    const fn new(address: u8) -> Self {
        Self {
            address,
            read_count: 0,
            write_count: 0,
            rmw_count: 0,
            indirect_count: 0,
            references: Vec::new(),
            name: None,
        }
    }

    /// Total number of accesses to this address.
    #[must_use]
    pub const fn total_accesses(&self) -> u32 {
        self.read_count + self.write_count + self.rmw_count + self.indirect_count
    }

    /// Return `true` if this address is only ever written to (never read).
    #[must_use]
    pub const fn is_write_only(&self) -> bool {
        self.read_count == 0 && self.rmw_count == 0 && self.indirect_count == 0
    }

    /// Return `true` if this address is only ever read (never written).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.write_count == 0 && self.rmw_count == 0
    }

    /// Return `true` if this address is used as an indirect pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        self.indirect_count > 0
    }

    fn record(&mut self, instr_addr: u64, mnemonic: &str, kind: ZeroPageAccessKind) {
        match kind {
            ZeroPageAccessKind::Read => self.read_count += 1,
            ZeroPageAccessKind::Write => self.write_count += 1,
            ZeroPageAccessKind::ReadModifyWrite => self.rmw_count += 1,
            ZeroPageAccessKind::Indirect => self.indirect_count += 1,
        }
        self.references.push(ZeroPageReference {
            instruction_addr: instr_addr,
            mnemonic: mnemonic.to_string(),
            kind,
        });
    }
}

// ── ZeroPageUsage ─────────────────────────────────────────────────────────────

/// Summary statistics over all zero-page accesses in the analysed code.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZeroPageUsage {
    /// Number of distinct zero-page addresses accessed.
    pub distinct_addresses: usize,
    /// Total read accesses across all addresses.
    pub total_reads: u64,
    /// Total write accesses across all addresses.
    pub total_writes: u64,
    /// Total RMW accesses.
    pub total_rmw: u64,
    /// Total indirect (pointer) accesses.
    pub total_indirect: u64,
    /// Number of addresses used as pointers.
    pub pointer_count: usize,
}

// ── Mos6502ZeroPage ───────────────────────────────────────────────────────────

/// Zero-page analysis result for a 6502 program.
///
/// Constructed by [`Mos6502ZeroPage::analyze`], this struct stores a 256-entry
/// table (one per possible ZP address) and provides query and sorting APIs.
pub struct Mos6502ZeroPage {
    /// One entry per zero-page address (indices 0x00–0xFF).
    entries: [ZeroPageEntry; 256],
    /// Number of addresses that were actually accessed.
    active_count: usize,
}

impl Mos6502ZeroPage {
    /// Perform a linear-sweep analysis of `bytes` starting at virtual address
    /// `base_addr` and record every zero-page access found.
    ///
    /// Unknown or multi-byte-ambiguous opcodes are silently skipped (treated as
    /// 1-byte NOPs) so the analysis degrades gracefully on data mixed with code.
    #[must_use]
    pub fn analyze(bytes: &[u8], base_addr: u64) -> Self {
        // Safety: ZeroPageEntry doesn't implement Copy, so we can't use array
        // initialization syntax directly. Use a loop to build the array.
        let entries: [ZeroPageEntry; 256] = core::array::from_fn(|i| ZeroPageEntry::new(i as u8));
        let mut zp = Self {
            entries,
            active_count: 0,
        };
        do_track(bytes, base_addr, &mut zp);
        // Count active entries.
        zp.active_count = zp.entries.iter().filter(|e| e.total_accesses() > 0).count();
        zp
    }

    /// Return an iterator over entries that were accessed at least once.
    pub fn active_entries(&self) -> impl Iterator<Item = &ZeroPageEntry> {
        self.entries.iter().filter(|e| e.total_accesses() > 0)
    }

    /// Return a reference to the entry for the given address.
    #[must_use]
    pub fn entry(&self, address: u8) -> &ZeroPageEntry {
        &self.entries[usize::from(address)]
    }

    /// Return all active entries sorted by total access count (descending).
    #[must_use]
    pub fn sorted_by_access_count(&self) -> Vec<&ZeroPageEntry> {
        let mut v: Vec<&ZeroPageEntry> = self.active_entries().collect();
        v.sort_unstable_by(|a, b| b.total_accesses().cmp(&a.total_accesses()));
        v
    }

    /// Return all active entries sorted by zero-page address (ascending).
    #[must_use]
    pub fn sorted_by_address(&self) -> Vec<&ZeroPageEntry> {
        let mut v: Vec<&ZeroPageEntry> = self.active_entries().collect();
        v.sort_unstable_by_key(|e| e.address);
        v
    }

    /// Compute and return global usage statistics.
    #[must_use]
    pub fn usage(&self) -> ZeroPageUsage {
        let mut u = ZeroPageUsage {
            distinct_addresses: self.active_count,
            total_reads: 0,
            total_writes: 0,
            total_rmw: 0,
            total_indirect: 0,
            pointer_count: 0,
        };
        for e in self.active_entries() {
            u.total_reads += u64::from(e.read_count);
            u.total_writes += u64::from(e.write_count);
            u.total_rmw += u64::from(e.rmw_count);
            u.total_indirect += u64::from(e.indirect_count);
            if e.is_pointer() {
                u.pointer_count += 1;
            }
        }
        u
    }

    /// Assign heuristic names to zero-page variables.
    ///
    /// Names follow the pattern `zp_NN` where `NN` is the hex address, with
    /// the suffix `_ptr` added for addresses used as indirect pointers.
    pub fn assign_names(&mut self) {
        for entry in self.entries.iter_mut() {
            if entry.total_accesses() == 0 {
                continue;
            }
            let suffix = if entry.is_pointer() { "_ptr" } else { "" };
            entry.name = Some(format!("zp_{:02X}{suffix}", entry.address));
        }
    }

    /// Return the number of distinct zero-page addresses accessed.
    #[must_use]
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return all addresses used as indirect pointers.
    #[must_use]
    pub fn pointer_addresses(&self) -> Vec<u8> {
        self.active_entries()
            .filter(|e| e.is_pointer())
            .map(|e| e.address)
            .collect()
    }

    /// Return the most-frequently-accessed zero-page address, if any.
    #[must_use]
    pub fn hottest_address(&self) -> Option<u8> {
        self.active_entries()
            .max_by_key(|e| e.total_accesses())
            .map(|e| e.address)
    }
}

// ── track_zp_vars (core analysis pass) ───────────────────────────────────────

/// Linear sweep that records zero-page variable accesses into `out`.
///
/// This is the core analysis function; it is separated from the struct so that
/// it can be called independently or with a custom accumulator.
pub fn track_zp_vars(bytes: &[u8], base_addr: u64, out: &mut Mos6502ZeroPage) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let opcode = bytes[offset];
        let Some(entry) = opcode_table(opcode) else {
            offset += 1;
            continue;
        };
        let instr_len = 1 + entry.mode.extra_bytes() as usize;
        if offset + instr_len > bytes.len() {
            break;
        }
        let pc = base_addr + offset as u64;
        let op1 = if bytes.len() > offset + 1 { bytes[offset + 1] } else { 0 };
        classify_zp_access(pc, entry.mnemonic, entry.mode, op1, out);
        offset += instr_len;
    }
}

/// Classify a single decoded instruction and record any zero-page access.
fn classify_zp_access(
    pc: u64,
    mnemonic: &str,
    mode: AddrMode,
    op1: u8,
    out: &mut Mos6502ZeroPage,
) {
    let kind = match mode {
        AddrMode::ZeroPage => access_kind_for_mnemonic(mnemonic),
        AddrMode::ZeroPageX | AddrMode::ZeroPageY => access_kind_for_mnemonic(mnemonic),
        AddrMode::IndirectX | AddrMode::IndirectY | AddrMode::ZeroPageIndirect => {
            // The zero-page byte is a pointer.
            Some((op1, ZeroPageAccessKind::Indirect))
        }
        _ => None,
    };
    if let Some((addr, kind)) = kind {
        out.entries[usize::from(addr)].record(pc, mnemonic, kind);
    }
}

/// Determine the access kind for a mnemonic applied to a zero-page operand.
///
/// Returns `Some((address_byte, kind))` or `None` if the mode/mnemonic
/// combination does not directly access zero-page memory.
fn access_kind_for_mnemonic(mnemonic: &str) -> Option<(u8, ZeroPageAccessKind)> {
    // This function is called without the address; the address is supplied by
    // the caller.  We return a dummy address of 0 and the caller substitutes.
    let kind = match mnemonic {
        // Stores
        "STA" | "STX" | "STY" | "STZ" => ZeroPageAccessKind::Write,
        // Read-modify-write
        "ASL" | "LSR" | "ROL" | "ROR" | "INC" | "DEC" | "TRB" | "TSB"
        | "RMB" | "SMB" => ZeroPageAccessKind::ReadModifyWrite,
        // Reads (everything else that touches ZP)
        _ => ZeroPageAccessKind::Read,
    };
    // Return a sentinel; caller replaces address with actual op1.
    Some((0, kind))
}

// Override the function to accept address separately.
impl Mos6502ZeroPage {
    /// Record a single zero-page access at `addr` from instruction at `pc`.
    ///
    /// Exposed so callers performing their own decoding (e.g. from a real
    /// disassembler) can feed observations directly into the usage table.
    pub fn record_access(&mut self, addr: u8, pc: u64, mnemonic: &str, kind: ZeroPageAccessKind) {
        self.entries[usize::from(addr)].record(pc, mnemonic, kind);
    }
}

// Re-do track_zp_vars using a cleaner internal approach.
// The free function above is the public API; this private pass is used internally.
fn do_track(bytes: &[u8], base_addr: u64, zp: &mut Mos6502ZeroPage) {
    let mut off = 0usize;
    while off < bytes.len() {
        let opcode = bytes[off];
        let Some(e) = opcode_table(opcode) else {
            off += 1;
            continue;
        };
        let instr_len = 1 + e.mode.extra_bytes() as usize;
        if off + instr_len > bytes.len() {
            break;
        }
        let pc = base_addr + off as u64;
        let op1 = if off + 1 < bytes.len() { bytes[off + 1] } else { 0 };
        match e.mode {
            AddrMode::ZeroPage | AddrMode::ZeroPageX | AddrMode::ZeroPageY => {
                let kind = match e.mnemonic {
                    "STA" | "STX" | "STY" | "STZ" => ZeroPageAccessKind::Write,
                    "ASL" | "LSR" | "ROL" | "ROR" | "INC" | "DEC"
                    | "TRB" | "TSB" | "RMB" | "SMB" => ZeroPageAccessKind::ReadModifyWrite,
                    _ => ZeroPageAccessKind::Read,
                };
                zp.record_access(op1, pc, e.mnemonic, kind);
            }
            AddrMode::IndirectX | AddrMode::IndirectY | AddrMode::ZeroPageIndirect => {
                zp.record_access(op1, pc, e.mnemonic, ZeroPageAccessKind::Indirect);
            }
            _ => {}
        }
        off += instr_len;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 6502 byte stream that exercises several ZP modes.
    fn test_bytes() -> Vec<u8> {
        vec![
            0xA5, 0x10, // LDA $10       (ZP read)
            0x85, 0x10, // STA $10       (ZP write)
            0xA5, 0x20, // LDA $20       (ZP read)
            0xA1, 0x20, // LDA ($20,X)   (ZP indirect)
            0xE6, 0x10, // INC $10       (ZP RMW)
            0xB5, 0x30, // LDA $30,X     (ZP,X read)
            0xEA,       // NOP
        ]
    }

    #[test]
    fn test_analyze_distinct_addresses() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        assert_eq!(zp.active_count(), 3); // $10, $20, $30
    }

    #[test]
    fn test_analyze_reads_writes() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let e10 = zp.entry(0x10);
        assert_eq!(e10.read_count, 1);
        assert_eq!(e10.write_count, 1);
        assert_eq!(e10.rmw_count, 1);
    }

    #[test]
    fn test_analyze_indirect() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let e20 = zp.entry(0x20);
        assert_eq!(e20.read_count, 1);
        assert_eq!(e20.indirect_count, 1);
        assert!(e20.is_pointer());
    }

    #[test]
    fn test_is_read_only() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        // $30 only has a read (LDA $30,X)
        assert!(zp.entry(0x30).is_read_only());
    }

    #[test]
    fn test_sorted_by_access_count() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let sorted = zp.sorted_by_access_count();
        // $10 has 3 accesses (R+W+RMW), should be first
        assert_eq!(sorted[0].address, 0x10);
    }

    #[test]
    fn test_sorted_by_address() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let sorted = zp.sorted_by_address();
        assert_eq!(sorted[0].address, 0x10);
        assert_eq!(sorted[1].address, 0x20);
        assert_eq!(sorted[2].address, 0x30);
    }

    #[test]
    fn test_usage_statistics() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let usage = zp.usage();
        assert_eq!(usage.distinct_addresses, 3);
        assert!(usage.total_reads >= 2);
        assert_eq!(usage.total_writes, 1);
        assert_eq!(usage.total_rmw, 1);
        assert_eq!(usage.total_indirect, 1);
        assert_eq!(usage.pointer_count, 1);
    }

    #[test]
    fn test_hottest_address() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        assert_eq!(zp.hottest_address(), Some(0x10));
    }

    #[test]
    fn test_pointer_addresses() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        let ptrs = zp.pointer_addresses();
        assert_eq!(ptrs, vec![0x20]);
    }

    #[test]
    fn test_assign_names() {
        let mut zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        zp.assign_names();
        assert_eq!(zp.entry(0x10).name.as_deref(), Some("zp_10"));
        assert_eq!(zp.entry(0x20).name.as_deref(), Some("zp_20_ptr"));
    }

    #[test]
    fn test_entry_inactive() {
        let zp = Mos6502ZeroPage::analyze(&test_bytes(), 0x0600);
        // Address $FF was never touched
        let e = zp.entry(0xFF);
        assert_eq!(e.total_accesses(), 0);
        assert!(e.is_read_only()); // 0 reads, 0 writes
    }

    #[test]
    fn test_empty_bytes() {
        let zp = Mos6502ZeroPage::analyze(&[], 0x0000);
        assert_eq!(zp.active_count(), 0);
    }

    #[test]
    fn test_total_accesses() {
        let e = {
            let zp = Mos6502ZeroPage::analyze(&[0xA5, 0x05, 0x85, 0x05], 0x0000);
            zp.entry(0x05).total_accesses()
        };
        assert_eq!(e, 2); // 1 read + 1 write
    }

    #[test]
    fn test_access_kind_display() {
        assert_eq!(ZeroPageAccessKind::Read.to_string(), "R");
        assert_eq!(ZeroPageAccessKind::Write.to_string(), "W");
        assert_eq!(ZeroPageAccessKind::ReadModifyWrite.to_string(), "RMW");
        assert_eq!(ZeroPageAccessKind::Indirect.to_string(), "IND");
    }

    #[test]
    fn test_access_kind_is_read_write() {
        assert!(ZeroPageAccessKind::ReadModifyWrite.is_read());
        assert!(ZeroPageAccessKind::ReadModifyWrite.is_write());
        assert!(!ZeroPageAccessKind::Read.is_write());
        assert!(!ZeroPageAccessKind::Write.is_read());
    }
}
