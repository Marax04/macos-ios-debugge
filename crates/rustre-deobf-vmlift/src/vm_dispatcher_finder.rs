//! VM dispatcher discovery — find the central dispatch loop in a virtualized binary.
//!
//! # Relation to `dispatcher_detector`
//! [`crate::dispatcher_detector`] is a simpler imperative scanner that returns
//! [`crate::dispatcher_detector::VmDispatcher`] structs with virtual-register
//! context and description strings.  This module uses a pluggable
//! [`PatternMatcher`] bank, a [`ByteScanner`] helper, and returns
//! [`DispatchTable`] / [`DispatchSite`] values with deduplication, grouping,
//! and summary utilities.
//!
//! Both are used in [`crate::VmLifterPipeline::detect_and_report`] because they
//! cover complementary pattern families.  Keep them separate.
//!
//! The dispatcher is the heart of any stack-based or register-based VM: it reads
//! the next opcode from the virtual instruction pointer and jumps to the
//! corresponding handler.  [`VmDispatcherFinder`] scans a binary for the most
//! common dispatch patterns and returns a list of [`DispatchTable`] descriptors.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DispatchPattern — the recognisable shape of a dispatch loop
// ---------------------------------------------------------------------------

/// The structural pattern used by the dispatcher to route execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DispatchPattern {
    /// `jmp [reg*8 + table_base]` — scaled-index jump table (x86-64 style).
    ScaledIndexJmp,
    /// `jmp [table_base + reg*4]` — 32-bit scaled-index jump table.
    ScaledIndexJmp32,
    /// `call [table_base + reg*8]` — call through a handler pointer table.
    TableCall,
    /// Computed `jmp rax/rcx/rdx` after loading from a pointer table.
    ComputedJmp,
    /// Linear scan: `cmp opcode, N; je handler_N` repeated per opcode.
    LinearScan,
    /// Nested `if`/`switch` tree — detected via repeated CMP + JZ pairs.
    SwitchTree,
    /// `jmp [interpreter_pc]` — dispatch via indirect IP load.
    InterpreterLoop,
    /// Pattern could not be classified.
    Unknown,
}

impl fmt::Display for DispatchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ScaledIndexJmp   => "scaled-index-jmp*8",
            Self::ScaledIndexJmp32 => "scaled-index-jmp*4",
            Self::TableCall        => "table-call",
            Self::ComputedJmp      => "computed-jmp",
            Self::LinearScan       => "linear-scan-cmp/je",
            Self::SwitchTree       => "switch-tree",
            Self::InterpreterLoop  => "interpreter-loop",
            Self::Unknown          => "unknown",
        };
        f.write_str(s)
    }
}

impl DispatchPattern {
    /// Returns `true` if this pattern uses a jump table.
    #[must_use]
    pub const fn uses_jump_table(&self) -> bool {
        matches!(
            self,
            Self::ScaledIndexJmp | Self::ScaledIndexJmp32 | Self::TableCall | Self::ComputedJmp
        )
    }

    /// Heuristic estimate of the maximum number of handlers this pattern supports.
    #[must_use]
    pub const fn max_handlers(&self) -> usize {
        match self {
            Self::ScaledIndexJmp | Self::ScaledIndexJmp32 | Self::TableCall => 256,
            Self::ComputedJmp => 256,
            Self::LinearScan | Self::SwitchTree => 64,
            Self::InterpreterLoop => 256,
            Self::Unknown => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchTable — one dispatcher site
// ---------------------------------------------------------------------------

/// A dispatcher site found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchTable {
    /// Byte offset of the dispatch instruction within the scanned buffer.
    pub offset: usize,
    /// Virtual address of the dispatch instruction.
    pub virtual_address: u64,
    /// Pattern used at this site.
    pub pattern: DispatchPattern,
    /// Confidence in the detection, 0–100.
    pub confidence: u8,
    /// Virtual addresses of the handler entries (may be empty for indirect patterns).
    pub handler_entries: Vec<u64>,
    /// Estimated number of handlers (may exceed `handler_entries.len()`).
    pub handler_count: usize,
    /// Free-form notes.
    pub notes: Vec<String>,
}

impl DispatchTable {
    /// Create a new dispatch table descriptor.
    #[must_use]
    pub const fn new(offset: usize, virtual_address: u64, pattern: DispatchPattern, confidence: u8) -> Self {
        Self {
            offset,
            virtual_address,
            pattern,
            confidence,
            handler_entries: Vec::new(),
            handler_count: 0,
            notes: Vec::new(),
        }
    }

    /// Add a handler entry address.
    pub fn add_entry(&mut self, addr: u64) {
        self.handler_entries.push(addr);
        self.handler_count = self.handler_entries.len();
    }

    /// Set the estimated handler count directly (when addresses are unavailable).
    pub const fn set_handler_count(&mut self, n: usize) {
        self.handler_count = n;
    }

    /// Add a diagnostic note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Returns `true` if this site meets the given confidence threshold.
    #[must_use]
    pub const fn is_confident(&self, min: u8) -> bool {
        self.confidence >= min
    }
}

impl fmt::Display for DispatchTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#010x}] {} handlers={} conf={}",
            self.virtual_address, self.pattern, self.handler_count, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// ByteScanner — internal helper for pattern-matching a buffer
// ---------------------------------------------------------------------------

/// Internal sliding-window byte scanner.
struct ByteScanner<'a> {
    data: &'a [u8],
    base: u64,
}

impl<'a> ByteScanner<'a> {
    const fn new(data: &'a [u8], base: u64) -> Self {
        Self { data, base }
    }

    /// Returns `true` when `pattern[i] == None || data[offset+i] == pattern[i]`.
    fn matches_at(&self, offset: usize, pattern: &[Option<u8>]) -> bool {
        if offset + pattern.len() > self.data.len() {
            return false;
        }
        pattern.iter().enumerate().all(|(i, p)| {
            p.map_or(true, |expected| self.data[offset + i] == expected)
        })
    }

    /// Read a 32-bit LE integer.
    fn read_u32(&self, offset: usize) -> Option<u32> {
        self.data.get(offset..offset + 4).map(|s| {
            u32::from_le_bytes([s[0], s[1], s[2], s[3]])
        })
    }

    /// Read a 64-bit LE integer.
    fn _read_u64(&self, offset: usize) -> Option<u64> {
        self.data.get(offset..offset + 8).map(|s| {
            u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        })
    }

    /// Address at offset `i`.
    const fn addr_of(&self, offset: usize) -> u64 {
        self.base + offset as u64
    }
}

// ---------------------------------------------------------------------------
// PatternMatcher — recognizer for a single dispatch pattern
// ---------------------------------------------------------------------------

type MatchFn = fn(&ByteScanner<'_>, usize) -> Option<DispatchTable>;

struct PatternMatcher {
    name: &'static str,
    min_len: usize,
    match_fn: MatchFn,
}

impl PatternMatcher {
    fn try_match(&self, scanner: &ByteScanner<'_>, offset: usize) -> Option<DispatchTable> {
        let _ = self.name;
        if scanner.data.len() < self.min_len || offset + self.min_len > scanner.data.len() {
            return None;
        }
        (self.match_fn)(scanner, offset)
    }
}

// ---------------------------------------------------------------------------
// VmDispatcherFinder
// ---------------------------------------------------------------------------

/// Finds VM dispatcher sites in a binary by applying a bank of pattern matchers.
pub struct VmDispatcherFinder {
    matchers: Vec<PatternMatcher>,
    min_confidence: u8,
    base: u64,
}

impl Default for VmDispatcherFinder {
    fn default() -> Self {
        Self::new()
    }
}

impl VmDispatcherFinder {
    /// Create a new finder with built-in pattern matchers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            matchers: Self::default_matchers(),
            min_confidence: 50,
            base: 0,
        }
    }

    /// Set the virtual base address of the buffer.
    #[must_use]
    pub const fn with_base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    /// Override the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Scan `code` for dispatcher patterns and return all hits above the confidence threshold.
    ///
    /// Results are sorted by confidence (descending), then offset.
    #[must_use]
    pub fn find(&self, code: &[u8]) -> Vec<DispatchTable> {
        let scanner = ByteScanner::new(code, self.base);
        let mut results: Vec<DispatchTable> = Vec::new();

        for offset in 0..code.len() {
            for matcher in &self.matchers {
                if let Some(dt) = matcher.try_match(&scanner, offset) {
                    if dt.confidence >= self.min_confidence {
                        results.push(dt);
                    }
                }
            }
        }

        // Deduplicate: keep the highest-confidence result within a 16-byte window.
        results.sort_by(|a, b| {
            b.confidence.cmp(&a.confidence).then(a.offset.cmp(&b.offset))
        });
        let mut deduped: Vec<DispatchTable> = Vec::new();
        for dt in results {
            let close = deduped.iter().any(|existing: &DispatchTable| {
                existing.offset.abs_diff(dt.offset) < 16
            });
            if !close {
                deduped.push(dt);
            }
        }
        deduped.sort_by_key(|d| d.offset);
        deduped
    }

    /// Group dispatch tables by their pattern kind.
    #[must_use]
    pub fn group_by_pattern(tables: &[DispatchTable]) -> HashMap<String, Vec<&DispatchTable>> {
        let mut map: HashMap<String, Vec<&DispatchTable>> = HashMap::new();
        for dt in tables {
            map.entry(dt.pattern.to_string()).or_default().push(dt);
        }
        map
    }

    /// Summarise dispatch table stats: (pattern, count, `avg_confidence`).
    #[must_use]
    pub fn summarize(tables: &[DispatchTable]) -> Vec<(DispatchPattern, usize, u8)> {
        let mut map: HashMap<String, (DispatchPattern, Vec<u8>)> = HashMap::new();
        for dt in tables {
            let e = map.entry(dt.pattern.to_string()).or_insert_with(|| (dt.pattern.clone(), Vec::new()));
            e.1.push(dt.confidence);
        }
        let mut result: Vec<(DispatchPattern, usize, u8)> = map
            .into_values()
            .map(|(pat, confs)| {
                let avg = confs.iter().map(|&c| u32::from(c)).sum::<u32>() / confs.len() as u32;
                (pat, confs.len(), avg as u8)
            })
            .collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    // -----------------------------------------------------------------------
    // Pattern matcher bank
    // -----------------------------------------------------------------------

    fn default_matchers() -> Vec<PatternMatcher> {
        vec![
            // Pattern A: FF 24 CD xx xx xx xx  (jmp [rcx*8 + disp32])
            PatternMatcher {
                name: "scaled_index_jmp8",
                min_len: 7,
                match_fn: |scanner, offset| {
                    if !scanner.matches_at(offset, &[Some(0xFF), Some(0x24), Some(0xCD)]) {
                        return None;
                    }
                    let disp = scanner.read_u32(offset + 3)?;
                    let table_va = u64::from(disp);
                    let entries = extract_pointer_table(scanner.data, table_va, scanner.base, 8, 256);
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::ScaledIndexJmp,
                        85,
                    );
                    dt.set_handler_count(entries.len().max(1));
                    for e in entries {
                        dt.add_entry(e);
                    }
                    dt.add_note(format!("FF 24 CD dispatch; table_va={table_va:#x}"));
                    Some(dt)
                },
            },
            // Pattern B: FF 24 85 xx xx xx xx  (jmp [rax*4 + disp32])
            PatternMatcher {
                name: "scaled_index_jmp4",
                min_len: 7,
                match_fn: |scanner, offset| {
                    if !scanner.matches_at(offset, &[Some(0xFF), Some(0x24), Some(0x85)]) {
                        return None;
                    }
                    let disp = scanner.read_u32(offset + 3)?;
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::ScaledIndexJmp32,
                        80,
                    );
                    dt.set_handler_count(256);
                    dt.add_note(format!("FF 24 85 dispatch; table_va={disp:#x}"));
                    Some(dt)
                },
            },
            // Pattern C: FF E0 (jmp rax) — computed jump after table load
            PatternMatcher {
                name: "computed_jmp_rax",
                min_len: 2,
                match_fn: |scanner, offset| {
                    if !scanner.matches_at(offset, &[Some(0xFF), Some(0xE0)]) {
                        return None;
                    }
                    // Look-back for REX.W MOV or LEA within 32 bytes
                    let lb = offset.saturating_sub(32);
                    let has_load = scanner.data[lb..offset].windows(2).any(|w| {
                        (w[0] == 0x48 && (w[1] == 0x8B || w[1] == 0x8D)) || w[0] == 0x8B
                    });
                    let conf = if has_load { 78 } else { 55 };
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::ComputedJmp,
                        conf,
                    );
                    dt.set_handler_count(256);
                    dt.add_note("FF E0 jmp rax computed dispatch".to_string());
                    Some(dt)
                },
            },
            // Pattern D: FF E1 (jmp rcx)
            PatternMatcher {
                name: "computed_jmp_rcx",
                min_len: 2,
                match_fn: |scanner, offset| {
                    if !scanner.matches_at(offset, &[Some(0xFF), Some(0xE1)]) {
                        return None;
                    }
                    let lb = offset.saturating_sub(32);
                    let has_load = scanner.data[lb..offset].windows(2).any(|w| {
                        w[0] == 0x48 && (w[1] == 0x8B || w[1] == 0x8D)
                    });
                    let conf = if has_load { 76 } else { 52 };
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::ComputedJmp,
                        conf,
                    );
                    dt.set_handler_count(256);
                    dt.add_note("FF E1 jmp rcx computed dispatch".to_string());
                    Some(dt)
                },
            },
            // Pattern E: call $+5 ; pop reg ; add reg, imm32 — interpreter IP fixup
            PatternMatcher {
                name: "call_pop_add_chain",
                min_len: 13,
                match_fn: |scanner, offset| {
                    // E8 00 00 00 00 = call $+5
                    if !scanner.matches_at(offset, &[Some(0xE8), Some(0x00), Some(0x00), Some(0x00), Some(0x00)]) {
                        return None;
                    }
                    // pop r64: 58..5F
                    let pop_byte = *scanner.data.get(offset + 5)?;
                    if !(0x58..=0x5F).contains(&pop_byte) {
                        return None;
                    }
                    // REX.W ADD r64, imm32: 48 81 C0..C7 imm32
                    if !scanner.matches_at(offset + 6, &[Some(0x48), Some(0x81)]) {
                        return None;
                    }
                    let modrm = *scanner.data.get(offset + 8)?;
                    if (modrm & 0xF8) != 0xC0 {
                        return None;
                    }
                    let addend = scanner.read_u32(offset + 9)?;
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::InterpreterLoop,
                        82,
                    );
                    dt.set_handler_count(0);
                    dt.add_note(format!("call+pop+add chain; pop r{} add {:#x}", pop_byte - 0x58, addend));
                    Some(dt)
                },
            },
            // Pattern F: dense CMP/JE sequence — linear-scan dispatcher
            PatternMatcher {
                name: "linear_scan_cmp_je",
                min_len: 8,
                match_fn: |scanner, offset| {
                    // 3C imm8 (CMP AL, imm8) ; 74 rel8 (JE rel8)
                    if !scanner.matches_at(offset, &[Some(0x3C), None, Some(0x74), None]) {
                        return None;
                    }
                    // Count consecutive CMP/JE pairs
                    let mut count = 0usize;
                    let mut i = offset;
                    while i + 4 <= scanner.data.len()
                        && scanner.data[i] == 0x3C
                        && scanner.data[i + 2] == 0x74
                    {
                        count += 1;
                        i += 4;
                    }
                    if count < 2 {
                        return None;
                    }
                    let conf = (50 + count * 5).min(90) as u8;
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::LinearScan,
                        conf,
                    );
                    dt.set_handler_count(count);
                    dt.add_note(format!("linear CMP/JE chain of {count} handlers"));
                    Some(dt)
                },
            },
            // Pattern G: 83 F? xx (CMP reg/m, imm8) ; 74 rel8 — switch-tree node
            PatternMatcher {
                name: "switch_tree_cmp",
                min_len: 8,
                match_fn: |scanner, offset| {
                    if !scanner.matches_at(offset, &[Some(0x83), None, None, Some(0x74), None]) {
                        return None;
                    }
                    // Check that byte[1] is a CMP variant: (ModRM & 0x38) == 0x38
                    let modrm = scanner.data[offset + 1];
                    if (modrm & 0x38) != 0x38 {
                        return None;
                    }
                    // Look for more CMP/JE pairs in the next 64 bytes
                    let mut count = 1usize;
                    let mut i = offset + 5;
                    while i + 5 <= scanner.data.len().min(offset + 64) {
                        if scanner.data[i] == 0x83 && scanner.data[i + 3] == 0x74 {
                            count += 1;
                            i += 5;
                        } else {
                            break;
                        }
                    }
                    if count < 2 {
                        return None;
                    }
                    let conf = (55 + count * 4).min(88) as u8;
                    let mut dt = DispatchTable::new(
                        offset,
                        scanner.addr_of(offset),
                        DispatchPattern::SwitchTree,
                        conf,
                    );
                    dt.set_handler_count(count);
                    dt.add_note(format!("switch-tree CMP r/m8 chain; {count} nodes"));
                    Some(dt)
                },
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// extract_pointer_table — helper
// ---------------------------------------------------------------------------

/// Try to extract pointer-table entries from `data` at a given virtual address.
fn extract_pointer_table(
    data: &[u8],
    table_va: u64,
    base: u64,
    entry_size: usize,
    max_entries: usize,
) -> Vec<u64> {
    let Some(table_offset) = table_va.checked_sub(base) else {
        return Vec::new();
    };
    let table_offset = table_offset as usize;
    let mut entries = Vec::new();
    if data.len() < entry_size {
        return entries;
    }

    for i in 0..max_entries {
        let off = table_offset + i * entry_size;
        if off + entry_size > data.len() {
            break;
        }
        let addr: u64 = match entry_size {
            4 => {
                let v = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
                u64::from(v)
            }
            8 => u64::from_le_bytes([
                data[off], data[off+1], data[off+2], data[off+3],
                data[off+4], data[off+5], data[off+6], data[off+7],
            ]),
            _ => break,
        };
        // Plausibility: non-zero, within a 4 GiB window of base
        if addr == 0 || addr == u64::MAX {
            break;
        }
        let data_len = data.len() as u64;
        if addr < base || addr > base + data_len.max(0x1_0000_0000) {
            break;
        }
        entries.push(addr);
    }
    entries
}

// ---------------------------------------------------------------------------
// DispatchSite — analysis result for a confirmed dispatcher
// ---------------------------------------------------------------------------

/// High-level analysis result combining a [`DispatchTable`] with additional
/// derived information.
#[derive(Debug, Clone)]
pub struct DispatchSite {
    /// The raw detection result.
    pub table: DispatchTable,
    /// Whether the table appears to be the primary (highest-confidence) dispatcher.
    pub is_primary: bool,
    /// Estimated bytecode operand width inferred from the table size.
    pub inferred_operand_bits: u8,
}

impl DispatchSite {
    /// Wrap a dispatch table in a site descriptor.
    #[must_use]
    pub const fn from_table(table: DispatchTable, is_primary: bool) -> Self {
        let bits = match table.handler_count {
            0..=15   => 4,
            16..=255 => 8,
            _        => 16,
        };
        Self {
            table,
            is_primary,
            inferred_operand_bits: bits,
        }
    }
}

impl fmt::Display for DispatchSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} primary={} operand_bits={}",
            self.table, self.is_primary, self.inferred_operand_bits
        )
    }
}

/// Promote the highest-confidence [`DispatchTable`] entries into [`DispatchSite`]s.
#[must_use]
pub fn promote_to_sites(tables: Vec<DispatchTable>) -> Vec<DispatchSite> {
    if tables.is_empty() {
        return Vec::new();
    }
    let max_conf = tables.iter().map(|t| t.confidence).max().unwrap_or(0);
    tables
        .into_iter()
        .map(|t| {
            let is_primary = t.confidence == max_conf;
            DispatchSite::from_table(t, is_primary)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn finder() -> VmDispatcherFinder {
        VmDispatcherFinder::new().with_base(0x0000)
    }

    #[test]
    fn test_dispatch_pattern_display() {
        assert_eq!(DispatchPattern::ScaledIndexJmp.to_string(), "scaled-index-jmp*8");
        assert_eq!(DispatchPattern::LinearScan.to_string(), "linear-scan-cmp/je");
    }

    #[test]
    fn test_dispatch_pattern_uses_jump_table() {
        assert!(DispatchPattern::ScaledIndexJmp.uses_jump_table());
        assert!(!DispatchPattern::LinearScan.uses_jump_table());
    }

    #[test]
    fn test_dispatch_table_display() {
        let dt = DispatchTable::new(0x100, 0x1000, DispatchPattern::ComputedJmp, 80);
        let s = dt.to_string();
        assert!(s.contains("0x00001000"));
        assert!(s.contains("computed-jmp"));
    }

    #[test]
    fn test_dispatch_table_is_confident() {
        let dt = DispatchTable::new(0, 0, DispatchPattern::Unknown, 60);
        assert!(dt.is_confident(60));
        assert!(!dt.is_confident(61));
    }

    #[test]
    fn test_find_empty() {
        let result = finder().find(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_computed_jmp_rax() {
        // REX.W MOV + FF E0
        let mut code = vec![0x48u8, 0x8B, 0x04, 0xC5, 0x00, 0x10, 0x00, 0x00];
        code.extend_from_slice(&[0xFF, 0xE0]);
        let results = finder().find(&code);
        assert!(!results.is_empty());
        assert!(results.iter().any(|d| d.pattern == DispatchPattern::ComputedJmp));
    }

    #[test]
    fn test_find_call_pop_add_chain() {
        let code = [
            0xE8u8, 0x00, 0x00, 0x00, 0x00, // call $+5
            0x58,                             // pop rax
            0x48, 0x81, 0xC0, 0x00, 0x10, 0x00, 0x00, // add rax, 0x1000
        ];
        let results = finder().find(&code);
        assert!(!results.is_empty());
        assert!(results.iter().any(|d| d.pattern == DispatchPattern::InterpreterLoop));
    }

    #[test]
    fn test_find_linear_scan() {
        // Two CMP AL, imm8 / JE rel8 pairs
        let code = [
            0x3Cu8, 0x01, 0x74, 0x10,  // CMP AL, 1 ; JE +16
            0x3Cu8, 0x02, 0x74, 0x20,  // CMP AL, 2 ; JE +32
        ];
        let results = finder().find(&code);
        assert!(!results.is_empty());
        assert!(results.iter().any(|d| d.pattern == DispatchPattern::LinearScan));
    }

    #[test]
    fn test_find_scaled_index_jmp() {
        let mut code = vec![0xFF, 0x24, 0xCD];
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // table at 0
        let results = VmDispatcherFinder::new().with_base(0).with_min_confidence(0).find(&code);
        assert!(results.iter().any(|d| d.pattern == DispatchPattern::ScaledIndexJmp));
    }

    #[test]
    fn test_group_by_pattern() {
        let mut t1 = DispatchTable::new(0, 0, DispatchPattern::ComputedJmp, 80);
        let t2 = DispatchTable::new(10, 10, DispatchPattern::ComputedJmp, 75);
        let t3 = DispatchTable::new(20, 20, DispatchPattern::LinearScan, 70);
        t1.set_handler_count(256);
        let tables = vec![t1, t2, t3];
        let groups = VmDispatcherFinder::group_by_pattern(&tables);
        assert_eq!(groups.get("computed-jmp").map(|v| v.len()), Some(2));
        assert_eq!(groups.get("linear-scan-cmp/je").map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_summarize() {
        let t1 = DispatchTable::new(0, 0, DispatchPattern::ComputedJmp, 80);
        let t2 = DispatchTable::new(10, 10, DispatchPattern::ComputedJmp, 60);
        let tables = vec![t1, t2];
        let summary = VmDispatcherFinder::summarize(&tables);
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].0, DispatchPattern::ComputedJmp);
        assert_eq!(summary[0].1, 2);
        assert_eq!(summary[0].2, 70); // avg(80,60)=70
    }

    #[test]
    fn test_promote_to_sites() {
        let t1 = DispatchTable::new(0, 0, DispatchPattern::ComputedJmp, 90);
        let t2 = DispatchTable::new(10, 10, DispatchPattern::LinearScan, 60);
        let sites = promote_to_sites(vec![t1, t2]);
        assert_eq!(sites.len(), 2);
        let primary = sites.iter().find(|s| s.is_primary).unwrap();
        assert_eq!(primary.table.pattern, DispatchPattern::ComputedJmp);
    }

    #[test]
    fn test_dispatch_site_display() {
        let dt = DispatchTable::new(0, 0x2000, DispatchPattern::InterpreterLoop, 82);
        let site = DispatchSite::from_table(dt, true);
        let s = site.to_string();
        assert!(s.contains("primary=true"));
    }

    #[test]
    fn test_promote_empty() {
        let sites = promote_to_sites(vec![]);
        assert!(sites.is_empty());
    }

    #[test]
    fn test_with_min_confidence_filters() {
        // Code that produces only low-confidence hits
        let code = [0xFF, 0xE0]; // computed jmp — no look-back load → conf=55
        let results = VmDispatcherFinder::new().with_min_confidence(80).find(&code);
        assert!(results.is_empty());
    }
}
