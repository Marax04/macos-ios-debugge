//! Stack string reconstruction: find sequential MOV [rsp+N], imm8 sequences,
//! group by base address and contiguous offsets, assemble strings in offset order.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ByteStore — a single byte store to the stack
// ─────────────────────────────────────────────────────────────────────────────

/// A single observed byte store to a stack location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteStore {
    /// The virtual address of the store instruction.
    pub insn_addr: u64,
    /// Stack frame offset (relative to RSP or RBP; negative for RBP-relative).
    pub stack_offset: i64,
    /// The value being stored.
    pub value: u8,
    /// Width of the store in bytes (1, 2, or 4).
    pub width: u8,
    /// The base register used (0 = RSP/ESP, 1 = RBP/EBP).
    pub base_reg: u8,
}

impl ByteStore {
    /// Create a single-byte store.
    #[must_use]
    pub const fn new(insn_addr: u64, stack_offset: i64, value: u8, base_reg: u8) -> Self {
        Self {
            insn_addr,
            stack_offset,
            value,
            width: 1,
            base_reg,
        }
    }

    /// Create a multi-byte store (width 2 or 4) with the given raw value.
    #[must_use]
    pub const fn new_wide(insn_addr: u64, stack_offset: i64, value: u8, width: u8, base_reg: u8) -> Self {
        Self {
            insn_addr,
            stack_offset,
            value,
            width,
            base_reg,
        }
    }
}

impl fmt::Display for ByteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = if self.base_reg == 0 { "rsp" } else { "rbp" };
        write!(
            f,
            "ByteStore@{:#x} [{base}{:+}] = {:#04x}",
            self.insn_addr, self.stack_offset, self.value
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackRegion — a group of byte stores at contiguous offsets
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous region of byte stores on the stack that form a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackRegion {
    /// Stack frame offset of the first byte in this region.
    pub base_offset: i64,
    /// Ordered list of byte stores (sorted by offset ascending).
    pub stores: Vec<ByteStore>,
    /// Base register (0 = RSP/ESP, 1 = RBP/EBP).
    pub base_reg: u8,
}

impl StackRegion {
    /// Create a new empty region starting at `base_offset`.
    #[must_use]
    pub const fn new(base_offset: i64, base_reg: u8) -> Self {
        Self {
            base_offset,
            stores: Vec::new(),
            base_reg,
        }
    }

    /// Number of bytes stored into this region.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.stores.iter().map(|s| s.width as usize).sum()
    }

    /// Assemble the byte sequence in ascending offset order.
    #[must_use]
    pub fn assemble_bytes(&self) -> Vec<u8> {
        let mut sorted = self.stores.clone();
        sorted.sort_by_key(|s| s.stack_offset);
        sorted.iter().map(|s| s.value).collect()
    }

    /// Try to interpret as a null-terminated ASCII string.
    #[must_use]
    pub fn as_cstr(&self) -> Option<String> {
        let bytes = self.assemble_bytes();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).ok().map(std::borrow::ToOwned::to_owned)
    }

    /// Virtual address span: (min_insn_addr, max_insn_addr).
    #[must_use]
    pub fn insn_addr_range(&self) -> (u64, u64) {
        let min = self.stores.iter().map(|s| s.insn_addr).min().unwrap_or(0);
        let max = self.stores.iter().map(|s| s.insn_addr).max().unwrap_or(0);
        (min, max)
    }
}

impl fmt::Display for StackRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = if self.base_reg == 0 { "rsp" } else { "rbp" };
        write!(
            f,
            "StackRegion [{base}{:+}..{}] {} bytes",
            self.base_offset,
            self.base_offset + self.byte_count() as i64,
            self.byte_count()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackString — a fully reconstructed stack string
// ─────────────────────────────────────────────────────────────────────────────

/// A fully reconstructed ASCII/UTF-8 stack string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackString {
    /// Virtual address of the first store instruction that contributed to this string.
    pub start_addr: u64,
    /// Virtual address of the last store instruction.
    pub end_addr: u64,
    /// Stack frame base offset of the string buffer.
    pub stack_offset: i64,
    /// The assembled raw bytes (may include trailing null).
    pub raw_bytes: Vec<u8>,
    /// Decoded string value (null stripped).
    pub value: String,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Whether this string was assembled from wide (2-byte) stores.
    pub is_wide: bool,
}

impl StackString {
    /// Create a new `StackString` from a `StackRegion`.
    #[must_use]
    pub fn from_region(region: &StackRegion) -> Option<Self> {
        if region.stores.len() < 2 {
            return None;
        }
        let raw_bytes = region.assemble_bytes();
        let end = raw_bytes.iter().position(|&b| b == 0).unwrap_or(raw_bytes.len());
        let value_bytes = &raw_bytes[..end];
        if value_bytes.len() < 2 {
            return None;
        }
        let value = std::str::from_utf8(value_bytes).ok()?.to_owned();
        let pr = printable_ratio(value_bytes);
        if pr < 0.70 {
            return None;
        }
        let (start_addr, end_addr) = region.insn_addr_range();
        let confidence = (pr * 90.0).min(100.0) as u8;
        let is_wide = region.stores.iter().any(|s| s.width >= 2);
        Some(Self {
            start_addr,
            end_addr,
            stack_offset: region.base_offset,
            raw_bytes,
            value,
            confidence,
            is_wide,
        })
    }

    /// Length of the string value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns `true` if the string value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns `true` if confidence is at or above 75.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

impl fmt::Display for StackString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackString@{:#x} [rsp{:+}] {:?} (conf={})",
            self.start_addr, self.stack_offset, self.value, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utf16String — a reconstructed UTF-16 string from 2-byte stack stores
// ─────────────────────────────────────────────────────────────────────────────

/// A UTF-16 string assembled from 2-byte (or paired 1-byte) stack stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utf16String {
    /// Virtual address of the first contributing store instruction.
    pub start_addr: u64,
    /// Stack frame base offset.
    pub stack_offset: i64,
    /// Raw UTF-16 LE bytes.
    pub raw_bytes: Vec<u8>,
    /// Decoded string value.
    pub value: String,
    /// Confidence score (0–100).
    pub confidence: u8,
}

impl Utf16String {
    /// Attempt to decode a UTF-16 LE string from raw bytes.
    #[must_use]
    pub fn from_bytes(start_addr: u64, stack_offset: i64, raw_bytes: Vec<u8>) -> Option<Self> {
        if raw_bytes.len() < 4 || raw_bytes.len() % 2 != 0 {
            return None;
        }
        let u16_chars: Vec<u16> = raw_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        if u16_chars.len() < 2 {
            return None;
        }
        let value = String::from_utf16(&u16_chars).ok()?;
        let pr = printable_ratio(value.as_bytes());
        if pr < 0.70 {
            return None;
        }
        let confidence = (pr * 85.0).min(100.0) as u8;
        Some(Self {
            start_addr,
            stack_offset,
            raw_bytes,
            value,
            confidence,
        })
    }

    /// Length of the decoded string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns `true` if the decoded string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Display for Utf16String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Utf16String@{:#x} [rsp{:+}] {:?} (conf={})",
            self.start_addr, self.stack_offset, self.value, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackStringRecon — the main reconstruction engine
// ─────────────────────────────────────────────────────────────────────────────

/// Options for the stack string reconstructor.
#[derive(Debug, Clone)]
pub struct StackStringReconConfig {
    /// Maximum gap between two consecutive stores to still group them together.
    pub max_offset_gap: i64,
    /// Minimum number of stores to form a valid string region.
    pub min_store_count: usize,
    /// Minimum printable ratio required to accept a candidate.
    pub min_printable_ratio: f64,
    /// Whether to attempt UTF-16 reconstruction from 2-byte stores.
    pub try_utf16: bool,
    /// Whether to track RBP-relative stores in addition to RSP-relative.
    pub track_rbp: bool,
}

impl Default for StackStringReconConfig {
    fn default() -> Self {
        Self {
            max_offset_gap: 4,
            min_store_count: 2,
            min_printable_ratio: 0.70,
            try_utf16: true,
            track_rbp: true,
        }
    }
}

/// Stack string reconstruction engine.
///
/// Accepts a list of [`ByteStore`] records (extracted from IL or disassembly),
/// groups them into contiguous stack regions, and assembles string values.
#[derive(Debug, Clone)]
pub struct StackStringRecon {
    config: StackStringReconConfig,
    /// All byte stores registered for analysis.
    stores: Vec<ByteStore>,
}

impl StackStringRecon {
    /// Create a new reconstructor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: StackStringReconConfig::default(),
            stores: Vec::new(),
        }
    }

    /// Create a reconstructor with a custom configuration.
    #[must_use]
    pub fn with_config(config: StackStringReconConfig) -> Self {
        Self {
            config,
            stores: Vec::new(),
        }
    }

    /// Register a byte store for analysis.
    pub fn add_store(&mut self, store: ByteStore) {
        self.stores.push(store);
    }

    /// Register a list of byte stores at once.
    pub fn add_stores(&mut self, stores: impl IntoIterator<Item = ByteStore>) {
        self.stores.extend(stores);
    }

    /// Clear all registered stores.
    pub fn clear(&mut self) {
        self.stores.clear();
    }

    /// Number of registered stores.
    #[must_use]
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    // ── Region grouping ───────────────────────────────────────────────────────

    /// Group stores into contiguous stack regions.
    ///
    /// Stores are keyed by (base_reg, rough_base_offset / gap_size).
    #[must_use]
    pub fn group_into_regions(&self) -> Vec<StackRegion> {
        if self.stores.is_empty() {
            return Vec::new();
        }

        // Sort by (base_reg, stack_offset) to group contiguous sequences.
        let mut sorted = self.stores.clone();
        sorted.sort_by(|a, b| {
            a.base_reg
                .cmp(&b.base_reg)
                .then(a.stack_offset.cmp(&b.stack_offset))
        });

        let mut regions: Vec<StackRegion> = Vec::new();
        let mut current: Option<StackRegion> = None;

        for store in &sorted {
            if !self.config.track_rbp && store.base_reg != 0 {
                continue;
            }
            match current {
                None => {
                    let mut r = StackRegion::new(store.stack_offset, store.base_reg);
                    r.stores.push(store.clone());
                    current = Some(r);
                }
                Some(ref mut r) => {
                    let last_off = r.stores.last().map(|s| s.stack_offset).unwrap_or(r.base_offset);
                    let gap = store.stack_offset - last_off;
                    if store.base_reg == r.base_reg && gap >= 1 && gap <= self.config.max_offset_gap {
                        r.stores.push(store.clone());
                    } else {
                        if r.stores.len() >= self.config.min_store_count {
                            regions.push(current.take().unwrap());
                        } else {
                            current.take();
                        }
                        let mut new_r = StackRegion::new(store.stack_offset, store.base_reg);
                        new_r.stores.push(store.clone());
                        current = Some(new_r);
                    }
                }
            }
        }
        if let Some(r) = current {
            if r.stores.len() >= self.config.min_store_count {
                regions.push(r);
            }
        }
        regions
    }

    // ── Main reconstruction pass ──────────────────────────────────────────────

    /// Run the full reconstruction pass and return all recovered stack strings.
    #[must_use]
    pub fn reconstruct(&self) -> Vec<StackString> {
        let regions = self.group_into_regions();
        let mut results = Vec::new();
        for region in &regions {
            if let Some(ss) = StackString::from_region(region) {
                if ss.confidence as f64 / 100.0 >= self.config.min_printable_ratio {
                    results.push(ss);
                }
            }
        }
        results.sort_by(|a, b| a.start_addr.cmp(&b.start_addr));
        results
    }

    /// Run reconstruction and also attempt UTF-16 recovery.
    #[must_use]
    pub fn reconstruct_all(&self) -> ReconResult {
        let strings = self.reconstruct();
        let mut utf16 = Vec::new();
        if self.config.try_utf16 {
            utf16 = self.reconstruct_utf16();
        }
        let regions = self.group_into_regions();
        ReconResult {
            stack_strings: strings,
            utf16_strings: utf16,
            regions_found: regions.len(),
            stores_processed: self.stores.len(),
        }
    }

    /// Attempt to reconstruct UTF-16 strings from regions containing 2-byte stores.
    #[must_use]
    pub fn reconstruct_utf16(&self) -> Vec<Utf16String> {
        let regions = self.group_into_regions();
        let mut results = Vec::new();
        for region in &regions {
            let raw = region.assemble_bytes();
            // Heuristic: if every other byte is 0x00, likely UTF-16 LE.
            if raw.len() >= 4 {
                let null_even = raw.iter().enumerate().filter(|(i, _)| i % 2 != 0).all(|(_, &b)| b == 0);
                if null_even {
                    if let Some(utf16) = Utf16String::from_bytes(
                        region.insn_addr_range().0,
                        region.base_offset,
                        raw,
                    ) {
                        results.push(utf16);
                    }
                }
            }
        }
        results
    }

    /// Parse byte stores from a raw byte sequence of x86 MOV instructions.
    ///
    /// This is a simplified heuristic: looks for `C6 44 24 NN VV` patterns
    /// (MOV BYTE PTR [RSP+N], V) and `C7 44 24 NN VV VV VV VV` (MOV DWORD).
    #[must_use]
    pub fn parse_from_code(code: &[u8], base_addr: u64) -> Vec<ByteStore> {
        let mut stores = Vec::new();
        let mut i = 0usize;
        while i + 4 < code.len() {
            // MOV BYTE PTR [RSP+disp8], imm8  — C6 44 24 NN VV
            if code[i] == 0xC6 && code[i + 1] == 0x44 && code[i + 2] == 0x24 && i + 4 < code.len() {
                let disp = code[i + 3] as i64;
                let val = code[i + 4];
                stores.push(ByteStore::new(base_addr + i as u64, disp, val, 0));
                i += 5;
                continue;
            }
            // MOV BYTE PTR [RBP+disp8], imm8  — C6 45 NN VV
            if code[i] == 0xC6 && code[i + 1] == 0x45 && i + 3 < code.len() {
                let disp = code[i + 2] as i8 as i64;
                let val = code[i + 3];
                stores.push(ByteStore::new(base_addr + i as u64, disp, val, 1));
                i += 4;
                continue;
            }
            // MOV DWORD PTR [RSP+disp8], imm32  — C7 44 24 NN VV VV VV VV
            if code[i] == 0xC7 && code[i + 1] == 0x44 && code[i + 2] == 0x24 && i + 7 < code.len() {
                let disp = code[i + 3] as i64;
                let bytes = [code[i + 4], code[i + 5], code[i + 6], code[i + 7]];
                for (j, &b) in bytes.iter().enumerate() {
                    stores.push(ByteStore::new_wide(
                        base_addr + i as u64,
                        disp + j as i64,
                        b,
                        4,
                        0,
                    ));
                }
                i += 8;
                continue;
            }
            i += 1;
        }
        stores
    }

    /// Reference to the current configuration.
    #[must_use]
    pub const fn config(&self) -> &StackStringReconConfig {
        &self.config
    }
}

impl Default for StackStringRecon {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconResult — aggregate output of the reconstruction pass
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate output of the stack string reconstruction pass.
#[derive(Debug, Clone)]
pub struct ReconResult {
    /// ASCII/UTF-8 stack strings recovered.
    pub stack_strings: Vec<StackString>,
    /// UTF-16 strings recovered.
    pub utf16_strings: Vec<Utf16String>,
    /// Number of contiguous store regions identified.
    pub regions_found: usize,
    /// Total number of byte stores processed.
    pub stores_processed: usize,
}

impl ReconResult {
    /// Total number of strings recovered (ASCII + UTF-16).
    #[must_use]
    pub fn total_strings(&self) -> usize {
        self.stack_strings.len() + self.utf16_strings.len()
    }

    /// Returns `true` if no strings were recovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack_strings.is_empty() && self.utf16_strings.is_empty()
    }

    /// All ASCII string values, sorted by start address.
    #[must_use]
    pub fn string_values(&self) -> Vec<&str> {
        self.stack_strings.iter().map(|s| s.value.as_str()).collect()
    }
}

impl fmt::Display for ReconResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReconResult: {} ASCII + {} UTF-16 strings from {} regions ({} stores)",
            self.stack_strings.len(),
            self.utf16_strings.len(),
            self.regions_found,
            self.stores_processed
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: stack string deduplication
// ─────────────────────────────────────────────────────────────────────────────

/// Deduplicate a list of stack strings by value (keep highest confidence).
#[must_use]
pub fn dedup_stack_strings(mut strings: Vec<StackString>) -> Vec<StackString> {
    strings.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then(b.confidence.cmp(&a.confidence))
    });
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut result = Vec::new();
    for s in strings {
        if seen.contains_key(&s.value) {
            continue;
        }
        seen.insert(s.value.clone(), result.len());
        result.push(s);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count() as f64
        / data.len() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hello_stores() -> Vec<ByteStore> {
        // H e l l o \0
        let chars = b"Hello\0";
        chars
            .iter()
            .enumerate()
            .map(|(i, &b)| ByteStore::new(0x1000 + i as u64, i as i64, b, 0))
            .collect()
    }

    #[test]
    fn reconstruct_hello() {
        let mut recon = StackStringRecon::new();
        recon.add_stores(make_hello_stores());
        let result = recon.reconstruct();
        assert!(!result.is_empty());
        assert!(result.iter().any(|s| s.value == "Hello"));
    }

    #[test]
    fn parse_from_code_mov_byte() {
        // C6 44 24 04 41  — MOV BYTE PTR [RSP+4], 'A'
        let code = [0xC6u8, 0x44, 0x24, 0x04, 0x41];
        let stores = StackStringRecon::parse_from_code(&code, 0x2000);
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].value, b'A');
        assert_eq!(stores[0].stack_offset, 4);
    }

    #[test]
    fn parse_from_code_mov_dword() {
        // C7 44 24 00 41 42 43 44 — MOV DWORD PTR [RSP], 'ABCD'
        let code = [0xC7u8, 0x44, 0x24, 0x00, 0x41, 0x42, 0x43, 0x44];
        let stores = StackStringRecon::parse_from_code(&code, 0);
        assert_eq!(stores.len(), 4);
        assert_eq!(stores[0].value, b'A');
        assert_eq!(stores[3].value, b'D');
    }

    #[test]
    fn stack_region_assemble_sorted() {
        let mut region = StackRegion::new(0, 0);
        region.stores.push(ByteStore::new(0, 2, b'l', 0));
        region.stores.push(ByteStore::new(0, 0, b'H', 0));
        region.stores.push(ByteStore::new(0, 1, b'i', 0));
        let bytes = region.assemble_bytes();
        assert_eq!(bytes, b"Hil");
    }

    #[test]
    fn dedup_keeps_high_confidence() {
        let a = StackString {
            start_addr: 0, end_addr: 0, stack_offset: 0,
            raw_bytes: vec![], value: "test".into(), confidence: 80, is_wide: false,
        };
        let b = StackString {
            start_addr: 0, end_addr: 0, stack_offset: 0,
            raw_bytes: vec![], value: "test".into(), confidence: 60, is_wide: false,
        };
        let deduped = dedup_stack_strings(vec![a, b]);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn utf16_from_bytes_basic() {
        // "Hi" in UTF-16 LE
        let raw = vec![b'H', 0, b'i', 0, 0, 0];
        let s = Utf16String::from_bytes(0, 0, raw);
        assert!(s.is_some());
        assert_eq!(s.unwrap().value, "Hi");
    }

    #[test]
    fn recon_result_total_strings() {
        let r = ReconResult {
            stack_strings: vec![],
            utf16_strings: vec![],
            regions_found: 2,
            stores_processed: 10,
        };
        assert_eq!(r.total_strings(), 0);
        assert!(r.is_empty());
    }
}
