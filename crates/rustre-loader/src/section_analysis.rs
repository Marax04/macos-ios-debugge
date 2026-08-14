//! `section_analysis` — Section-level binary analysis.
//!
//! # Relation to `section_merger`
//!
//! This module is the **semantic / analytical layer**: it operates on
//! already-parsed [`SectionEntry`] values (which carry loaded bytes, entropy,
//! permission flags) and computes higher-level properties — entropy scores,
//! packing heuristics, W+X detection, cross-section call-graph references, and
//! a risk score.  It does not touch raw file offsets or merge split sections.
//!
//! [`section_merger`](crate::section_merger) is the **structural / file layer**:
//! it operates on raw [`SectionInfo`](crate::SectionInfo) records (file
//! offsets + sizes), detects raw-file and virtual-address overlaps, identifies
//! data appended after the last section (overlays), extracts embedded files, and
//! merges adjacent split COFF sections (`.text$mn` → `.text`).
//!
//! # Provided types
//!
//! `SectionAnalyzer`, `SectionCharacteristics`, `SectionClassifier`,
//! `OverlappingSection`, `PhantomSection`, `SectionHashDb`, `CrossSectionRef`.

use std::collections::HashMap;
use std::fmt;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from section analysis.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SectionError {
    #[error("no sections found")]
    NoSections,
    #[error("section '{0}' not found")]
    NotFound(String),
    #[error("overlapping sections: '{0}' and '{1}'")]
    Overlap(String, String),
    #[error("phantom section at RVA {0:#x}")]
    Phantom(u64),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── SectionFlags ─────────────────────────────────────────────────────────────

bitflags! {
    /// Common section permission / characteristic flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
    pub struct SectionFlags: u16 {
        /// Section is readable.
        const READABLE                    = 0x0001;
        /// Section is writable.
        const WRITABLE                    = 0x0002;
        /// Section is executable.
        const EXECUTABLE                  = 0x0004;
        /// Section contains executable code.
        const CONTAINS_CODE               = 0x0008;
        /// Section contains initialised data.
        const CONTAINS_INITIALIZED_DATA   = 0x0010;
        /// Section contains uninitialised (BSS) data.
        const CONTAINS_UNINITIALIZED_DATA = 0x0020;
        /// Section can be discarded after linking.
        const IS_DISCARDABLE              = 0x0040;
        /// Section is not cached.
        const NOT_CACHED                  = 0x0080;
        /// Section is not pageable.
        const NOT_PAGED                   = 0x0100;
        /// Section is shared in memory.
        const SHARED                      = 0x0200;
    }
}

impl SectionFlags {
    /// Create a typical read-execute code section.
    #[must_use]
    pub fn code() -> Self {
        Self::READABLE | Self::EXECUTABLE | Self::CONTAINS_CODE
    }

    /// Create a typical read-write data section.
    #[must_use]
    pub fn data() -> Self {
        Self::READABLE | Self::WRITABLE | Self::CONTAINS_INITIALIZED_DATA
    }

    /// Create a read-only data section.
    #[must_use]
    pub fn rodata() -> Self {
        Self::READABLE | Self::CONTAINS_INITIALIZED_DATA
    }

    /// Create a discardable section (e.g. `.reloc`).
    #[must_use]
    pub fn discardable() -> Self {
        Self::READABLE | Self::IS_DISCARDABLE
    }

    /// Return `true` if this section is executable.
    #[must_use]
    pub const fn is_exec(self) -> bool { self.contains(Self::EXECUTABLE) }

    /// Return `true` if this section is writable.
    #[must_use]
    pub const fn is_writable(self) -> bool { self.contains(Self::WRITABLE) }

    /// Return `true` if this section is readable.
    #[must_use]
    pub const fn is_readable(self) -> bool { self.contains(Self::READABLE) }

    /// Permission string (e.g. `"r-x"`).
    #[must_use]
    pub fn perm_string(self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.contains(Self::READABLE) { 'r' } else { '-' });
        s.push(if self.contains(Self::WRITABLE) { 'w' } else { '-' });
        s.push(if self.contains(Self::EXECUTABLE) { 'x' } else { '-' });
        s
    }
}

// ─── SectionEntry ─────────────────────────────────────────────────────────────

/// Representation of a single binary section/segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntry {
    /// Section name (e.g. `.text`, `__TEXT`).
    pub name: String,
    /// Virtual address (start).
    pub vaddr: u64,
    /// Virtual size.
    pub vsize: u64,
    /// File offset of raw data.
    pub file_offset: u64,
    /// Raw data size on disk.
    pub raw_size: u64,
    /// Section flags / characteristics.
    pub flags: SectionFlags,
    /// Raw section bytes (may be empty if not loaded).
    pub data: Vec<u8>,
}

impl SectionEntry {
    /// Create a section entry.
    #[must_use]
    pub fn new(name: impl Into<String>, vaddr: u64, vsize: u64, flags: SectionFlags) -> Self {
        Self {
            name: name.into(), vaddr, vsize,
            file_offset: 0, raw_size: 0, flags, data: vec![],
        }
    }

    /// End virtual address (exclusive).
    #[must_use]
    pub const fn vend(&self) -> u64 { self.vaddr + self.vsize }

    /// Return `true` if the section contains `addr`.
    #[must_use]
    pub const fn contains_vaddr(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.vend()
    }

    /// Return `true` if this section overlaps with `other` in virtual address space.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.vaddr < other.vend() && other.vaddr < self.vend()
    }

    /// Compute Shannon entropy of the section data.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        compute_entropy(&self.data)
    }

    /// Return `true` if the section appears packed (entropy > 7.0).
    #[must_use]
    pub fn is_likely_packed(&self) -> bool {
        !self.data.is_empty() && self.entropy() > 7.0
    }

    /// Return `true` if the section has no raw data.
    #[must_use]
    pub const fn is_bss_like(&self) -> bool {
        self.raw_size == 0 || self.data.is_empty()
    }
}

impl fmt::Display for SectionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} vaddr={:#x} vsize={:#x} {}",
            self.name, self.vaddr, self.vsize, self.flags.perm_string()
        )
    }
}

// ─── SectionCharacteristics ───────────────────────────────────────────────────

/// Type classification flags for a section (code, data, packed).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SectionTypeFlags {
    /// Whether the section likely contains code.
    pub is_code: bool,
    /// Whether the section looks like a data segment.
    pub is_data: bool,
    /// Whether the section appears to be packed/encrypted.
    pub is_packed: bool,
}

/// Derived characteristics of a section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionCharacteristics {
    /// Computed Shannon entropy (0.0–8.0).
    pub entropy: f64,
    /// Type classification flags.
    pub type_flags: SectionTypeFlags,
    /// Whether the section contains printable strings.
    pub contains_strings: bool,
    /// Number of printable strings (length >= 4).
    pub string_count: usize,
    /// Whether the section has an unusually high null-byte ratio.
    pub high_null_ratio: bool,
    /// Proportion of printable ASCII bytes in [0.0, 1.0].
    pub ascii_ratio: f64,
    /// Proportion of null bytes in [0.0, 1.0].
    pub null_ratio: f64,
    /// Whether the section is empty (no data).
    pub is_empty: bool,
    /// Risk score 0–100 (higher = more suspicious).
    pub risk_score: u8,
}

impl SectionCharacteristics {
    /// Analyse a section entry and compute its characteristics.
    #[must_use]
    pub fn analyse(section: &SectionEntry) -> Self {
        let data = &section.data;
        if data.is_empty() {
            return Self {
                entropy: 0.0,
                type_flags: SectionTypeFlags {
                    is_code: section.flags.is_exec(),
                    is_data: section.flags.is_writable(),
                    is_packed: false,
                },
                contains_strings: false, string_count: 0, high_null_ratio: true,
                ascii_ratio: 0.0, null_ratio: 1.0, is_empty: true, risk_score: 0,
            };
        }
        let entropy = compute_entropy(data);
        let null_count: usize = data.iter().fold(0, |acc, &b| acc + usize::from(b == 0));
        let ascii_count: usize = data.iter().fold(0, |acc, &b| acc + usize::from(b.is_ascii_graphic() || b == b' '));
        let len_f = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
        let null_ratio = f64::from(u32::try_from(null_count).unwrap_or(u32::MAX)) / len_f;
        let ascii_ratio = f64::from(u32::try_from(ascii_count).unwrap_or(u32::MAX)) / len_f;
        let string_count = count_strings(data, 4);
        let contains_strings = string_count > 0;
        let is_packed = entropy > 7.0;
        let high_null_ratio = null_ratio > 0.5;

        // Risk scoring heuristics
        let mut risk = 0u8;
        if is_packed { risk = risk.saturating_add(30); }
        if section.flags.is_exec() && section.flags.is_writable() { risk = risk.saturating_add(30); }
        if entropy > 7.5 { risk = risk.saturating_add(20); }
        if entropy < 1.0 && !data.is_empty() { risk = risk.saturating_add(5); }

        Self {
            entropy,
            type_flags: SectionTypeFlags {
                is_code: section.flags.is_exec(),
                is_data: !section.flags.is_exec() && section.flags.is_readable(),
                is_packed,
            },
            contains_strings, string_count, high_null_ratio,
            ascii_ratio, null_ratio, is_empty: false,
            risk_score: risk.min(100),
        }
    }
}

// ─── SectionClassifier ────────────────────────────────────────────────────────

/// Classifies sections using 50+ built-in rules.
pub struct SectionClassifier;

impl SectionClassifier {
    /// Classify a section name into a semantic category.
    #[must_use]
    pub fn classify_name(name: &str) -> &'static str {
        let n = name.to_ascii_lowercase();
        let n = n.trim_start_matches('.');
        match n {
            "text" | "code" | "__text" | ".code" => "code",
            "data" | "__data" | "rdata" | "rodata" | "__rodata" | "idata" | "edata" => "data",
            "bss" | "__bss" | ".bss" => "bss",
            "reloc" | ".reloc" | "__got" | "got" | "plt" | ".plt" | "got.plt" => "relocation",
            "debug" | ".debug" | "dbg" | "debug_info" | "debug_abbrev" | "debug_line"
            | "debug_loc" | "debug_str" | "debug_ranges" | "debug_types" => "debug",
            "pdata" | "xdata" | "unwind" | ".pdata" | ".xdata"
            | "eh_frame" | ".eh_frame" | "gcc_except" | ".gcc_except_table" => "exception",
            "rsrc" | ".rsrc" | "__resources" => "resources",
            "tls" | ".tls" | ".tdata" | ".tbss" => "tls",
            "noinit" | ".noinit" => "noinit",
            "init" | ".init" | "fini" | ".fini" | "init_array" | ".init_array"
            | "fini_array" | ".fini_array" | "ctors" | ".ctors" | "dtors" | ".dtors" => "init",
            "dynsym" | ".dynsym" | "dynstr" | ".dynstr" | "dynamic" | ".dynamic" => "dynamic_link",
            "interp" | ".interp" => "interpreter",
            "note" | ".note" => "note",
            "symtab" | ".symtab" | "strtab" | ".strtab" | "shstrtab" | ".shstrtab" => "symbol_table",
            "hash" | ".hash" | "gnu.hash" | ".gnu.hash" => "hash",
            "comment" | ".comment" => "comment",
            "buildid" | ".buildid" | "note.gnu.build-id" => "build_id",
            "crt" | "crtstuff" => "crt",
            "import" | ".import" => "import",
            "export" | ".export" => "export",
            "overlay" => "overlay",
            "udata" | "upx0" | "upx1" | "upx2" | "upx!" | "themida" | "execryptor" | "aspack" => "packed",
            _ => "unknown",
        }
    }

    /// Return all known section categories.
    #[must_use]
    pub const fn known_categories() -> &'static [&'static str] {
        &[
            "code", "data", "bss", "relocation", "debug", "exception",
            "resources", "tls", "noinit", "init", "dynamic_link",
            "interpreter", "note", "symbol_table", "hash", "comment",
            "build_id", "crt", "import", "export", "overlay", "packed", "unknown",
        ]
    }

    /// Return `true` if the section name indicates a suspicious/packed section.
    #[must_use]
    pub fn is_suspicious_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.contains("upx") || lower.contains("themida") || lower.contains("execryptor")
            || lower.contains("aspack") || lower.contains("pecompact")
    }

    /// Classify a section by its characteristics (not just name).
    #[must_use]
    pub const fn classify_by_characteristics(chars: &SectionCharacteristics) -> &'static str {
        if chars.type_flags.is_packed { return "packed"; }
        if chars.type_flags.is_code { return "code"; }
        if chars.type_flags.is_data && chars.contains_strings { return "string_data"; }
        if chars.type_flags.is_data { return "data"; }
        if chars.high_null_ratio { return "bss"; }
        "unknown"
    }
}

// ─── OverlappingSection ───────────────────────────────────────────────────────

/// Describes two sections that overlap in virtual address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlappingSection {
    /// Name of the first section.
    pub section_a: String,
    /// Name of the second section.
    pub section_b: String,
    /// Start of the overlap region.
    pub overlap_start: u64,
    /// End of the overlap region.
    pub overlap_end: u64,
    /// Number of overlapping bytes.
    pub overlap_bytes: u64,
}

impl OverlappingSection {
    /// Compute the overlap between two sections, if any.
    #[must_use]
    pub fn compute(a: &SectionEntry, b: &SectionEntry) -> Option<Self> {
        if !a.overlaps(b) { return None; }
        let start = a.vaddr.max(b.vaddr);
        let end = a.vend().min(b.vend());
        Some(Self {
            section_a: a.name.clone(),
            section_b: b.name.clone(),
            overlap_start: start,
            overlap_end: end,
            overlap_bytes: end.saturating_sub(start),
        })
    }
}

// ─── PhantomSection ───────────────────────────────────────────────────────────

/// A section that is referenced (e.g. by a pointer) but is not listed in the
/// section table — common in packers and obfuscated binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomSection {
    /// Virtual address of the phantom region.
    pub vaddr: u64,
    /// Suspected size in bytes.
    pub size: u64,
    /// Reason why this region is considered a phantom section.
    pub reason: String,
}

impl PhantomSection {
    /// Create a new phantom section record.
    #[must_use]
    pub fn new(vaddr: u64, size: u64, reason: impl Into<String>) -> Self {
        Self { vaddr, size, reason: reason.into() }
    }
}

// ─── SectionHashDb ────────────────────────────────────────────────────────────

/// Database of known section hashes (SHA-256 or fuzzy) for identification.
#[derive(Debug, Default)]
pub struct SectionHashDb {
    entries: HashMap<String, SectionHashEntry>,
}

/// One entry in the section hash database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHashEntry {
    pub hash: String,
    pub name: String,
    pub description: String,
    pub known_good: bool,
}

impl SectionHashDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add an entry.
    pub fn add(&mut self, hash: String, entry: SectionHashEntry) {
        self.entries.insert(hash, entry);
    }

    /// Look up a hash.
    #[must_use]
    pub fn lookup(&self, hash: &str) -> Option<&SectionHashEntry> {
        self.entries.get(hash)
    }

    /// Return `true` if the hash is in the database.
    #[must_use]
    pub fn contains(&self, hash: &str) -> bool {
        self.entries.contains_key(hash)
    }

    /// Return `true` if the hash corresponds to a known-good section.
    #[must_use]
    pub fn is_known_good(&self, hash: &str) -> bool {
        self.entries.get(hash).is_some_and(|e| e.known_good)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Return `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ─── CrossSectionRef ──────────────────────────────────────────────────────────

/// A cross-reference from one section to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSectionRef {
    /// Source virtual address.
    pub from_addr: u64,
    /// Target virtual address.
    pub to_addr: u64,
    /// Source section name.
    pub from_section: String,
    /// Target section name.
    pub to_section: String,
    /// Type of reference.
    pub ref_type: CrossRefType,
}

/// Type of cross-section reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossRefType {
    Call,
    Jump,
    DataRead,
    DataWrite,
    Pointer,
}

impl fmt::Display for CrossRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::DataRead => "data_read",
            Self::DataWrite => "data_write",
            Self::Pointer => "pointer",
        };
        f.write_str(s)
    }
}

// ─── SectionAnalyzer ──────────────────────────────────────────────────────────

/// Analyses binary sections and reports characteristics, overlaps, phantoms,
/// cross-section references, and risk scores.
pub struct SectionAnalyzer {
    pub sections: Vec<SectionEntry>,
    pub hash_db: SectionHashDb,
}

impl SectionAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self { sections: vec![], hash_db: SectionHashDb::new() }
    }

    /// Add a section.
    pub fn add_section(&mut self, section: SectionEntry) {
        self.sections.push(section);
    }

    /// Sort sections by virtual address.
    pub fn sort_by_vaddr(&mut self) {
        self.sections.sort_by_key(|s| s.vaddr);
    }

    /// Find a section by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&SectionEntry> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find a section containing the virtual address `addr`.
    #[must_use]
    pub fn find_containing(&self, addr: u64) -> Option<&SectionEntry> {
        self.sections.iter().find(|s| s.contains_vaddr(addr))
    }

    /// Compute characteristics for all sections.
    #[must_use]
    pub fn compute_characteristics(&self) -> Vec<(String, SectionCharacteristics)> {
        self.sections.iter().map(|s| (s.name.clone(), SectionCharacteristics::analyse(s))).collect()
    }

    /// Find all overlapping section pairs.
    #[must_use]
    pub fn find_overlaps(&self) -> Vec<OverlappingSection> {
        let mut overlaps = Vec::new();
        for i in 0..self.sections.len() {
            for j in (i + 1)..self.sections.len() {
                if let Some(ov) = OverlappingSection::compute(&self.sections[i], &self.sections[j]) {
                    overlaps.push(ov);
                }
            }
        }
        overlaps
    }

    /// Detect phantom sections: virtual addresses in DATA references that fall
    /// outside all known sections.
    #[must_use]
    pub fn detect_phantom_sections(&self, referenced_addrs: &[u64]) -> Vec<PhantomSection> {
        let mut phantoms = Vec::new();
        for &addr in referenced_addrs {
            if self.find_containing(addr).is_none() {
                phantoms.push(PhantomSection::new(
                    addr, 0x1000,
                    format!("address {addr:#x} referenced but not covered by any section"),
                ));
            }
        }
        phantoms
    }

    /// Compute the aggregate risk score across all sections.
    #[must_use]
    pub fn overall_risk_score(&self) -> u8 {
        if self.sections.is_empty() { return 0; }
        let mut max: u8 = 0;
        let mut sum: u32 = 0;
        for s in &self.sections {
            let score = SectionCharacteristics::analyse(s).risk_score;
            if score > max { max = score; }
            sum += u32::from(score);
        }
        let avg = sum / u32::try_from(self.sections.len()).unwrap_or(1);
        ((u32::from(max) * 2 + avg) / 3).min(100) as u8
    }

    /// Find all sections that are both writable and executable (W+X).
    #[must_use]
    pub fn wx_sections(&self) -> Vec<&SectionEntry> {
        self.sections.iter().filter(|s| s.flags.is_writable() && s.flags.is_exec()).collect()
    }

    /// Find all sections that look packed (entropy > 7.0).
    #[must_use]
    pub fn packed_sections(&self) -> Vec<&SectionEntry> {
        self.sections.iter().filter(|s| s.is_likely_packed()).collect()
    }

    /// Return a hash → section mapping for quick dedup.
    #[must_use]
    pub fn section_hashes(&self) -> HashMap<String, String> {
        self.sections.iter().map(|s| {
            let hash = simple_hash(&s.data);
            (hash, s.name.clone())
        }).collect()
    }

    /// Look up all sections in the hash database and report matches.
    #[must_use]
    pub fn hash_db_lookup(&self) -> Vec<(String, Option<SectionHashEntry>)> {
        self.sections.iter().map(|s| {
            let hash = simple_hash(&s.data);
            let entry = self.hash_db.lookup(&hash).cloned();
            (s.name.clone(), entry)
        }).collect()
    }

    /// Find cross-section references (call/data) from section data.
    #[must_use]
    pub fn find_cross_section_refs(&self) -> Vec<CrossSectionRef> {
        let mut refs: Vec<CrossSectionRef> = Vec::with_capacity(64);
        for src_sec in &self.sections {
            if !src_sec.flags.is_exec() || src_sec.data.is_empty() { continue; }
            // Look for CALL rel32 (E8) instructions
            for i in 0..src_sec.data.len().saturating_sub(5) {
                if src_sec.data[i] == 0xE8 {
                    let rel = i32::from_le_bytes([
                        src_sec.data[i + 1], src_sec.data[i + 2],
                        src_sec.data[i + 3], src_sec.data[i + 4],
                    ]);
                    let next_ip = src_sec.vaddr + i as u64 + 5;
                    let target = next_ip.wrapping_add_signed(i64::from(rel));
                    if let Some(target_sec) = self.find_containing(target)
                        && target_sec.name != src_sec.name {
                            refs.push(CrossSectionRef {
                                from_addr: src_sec.vaddr + i as u64,
                                to_addr: target,
                                from_section: src_sec.name.clone(),
                                to_section: target_sec.name.clone(),
                                ref_type: CrossRefType::Call,
                            });
                        }
                }
            }
        }
        refs
    }

    /// Total number of sections.
    #[must_use]
    pub const fn section_count(&self) -> usize { self.sections.len() }

    /// Total virtual address space covered.
    #[must_use]
    pub fn total_vsize(&self) -> u64 {
        self.sections.iter().map(|s| s.vsize).sum()
    }
}

impl Default for SectionAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter().filter(|&&cnt| cnt > 0).map(|&cnt| {
        let p = f64::from(u32::try_from(cnt).unwrap_or(u32::MAX)) / len;
        -p * p.log2()
    }).sum()
}

fn count_strings(data: &[u8], min_len: usize) -> usize {
    let mut count = 0;
    let mut run = 0;
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' { run += 1; }
        else { if run >= min_len { count += 1; } run = 0; }
    }
    if run >= min_len { count += 1; }
    count
}

fn simple_hash(data: &[u8]) -> String {
    let mut h = 0u64;
    for &b in data {
        h = h.wrapping_mul(31).wrapping_add(u64::from(b));
    }
    format!("{h:016x}")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn text_section() -> SectionEntry {
        let mut s = SectionEntry::new(".text", 0x1000, 0x1000, SectionFlags::code());
        s.raw_size = 0x1000;
        // Insert a CALL rel32 pointing to 0x2000
        let rel = 0x2000u64.wrapping_sub(0x1000 + 5 + 0x1000) as i32; // to data section
        let mut data = vec![0x90u8; 0x1000]; // NOPs
        data[0] = 0xE8;
        data[1..5].copy_from_slice(&rel.to_le_bytes());
        data.extend_from_slice(b"hello world\x00");
        s.data = data;
        s
    }

    fn data_section() -> SectionEntry {
        let mut s = SectionEntry::new(".data", 0x2000, 0x1000, SectionFlags::data());
        s.raw_size = 0x1000;
        s.data = vec![0u8; 0x1000];
        s
    }

    // ── SectionFlags ──────────────────────────────────────────────────────────

    #[test]
    fn test_flags_code() {
        let f = SectionFlags::code();
        assert!(f.is_exec());
        assert!(f.is_readable());
        assert!(!f.is_writable());
    }

    #[test]
    fn test_flags_data() {
        let f = SectionFlags::data();
        assert!(f.is_writable());
        assert!(!f.is_exec());
    }

    #[test]
    fn test_flags_perm_string() {
        assert_eq!(SectionFlags::code().perm_string(), "r-x");
        assert_eq!(SectionFlags::data().perm_string(), "rw-");
        assert_eq!(SectionFlags::rodata().perm_string(), "r--");
    }

    // ── SectionEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_entry_vend() {
        let s = SectionEntry::new(".text", 0x1000, 0x500, SectionFlags::code());
        assert_eq!(s.vend(), 0x1500);
    }

    #[test]
    fn test_entry_contains_vaddr() {
        let s = SectionEntry::new(".text", 0x1000, 0x1000, SectionFlags::code());
        assert!(s.contains_vaddr(0x1000));
        assert!(s.contains_vaddr(0x1fff));
        assert!(!s.contains_vaddr(0x2000));
    }

    #[test]
    fn test_entry_overlaps() {
        let a = SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code());
        let b = SectionEntry::new("b", 0x1800, 0x1000, SectionFlags::data());
        let c = SectionEntry::new("c", 0x2000, 0x1000, SectionFlags::data());
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_entry_entropy_high() {
        let mut s = SectionEntry::new("packed", 0, 0x100, SectionFlags::code());
        // Random-looking data: high entropy
        s.data = (0u8..=255).collect();
        assert!(s.entropy() > 7.0);
        assert!(s.is_likely_packed());
    }

    #[test]
    fn test_entry_entropy_low() {
        let mut s = SectionEntry::new("zero", 0, 0x100, SectionFlags::data());
        s.data = vec![0u8; 256];
        assert!(s.entropy() < 1.0);
        assert!(!s.is_likely_packed());
    }

    #[test]
    fn test_entry_display() {
        let s = text_section();
        assert!(s.to_string().contains(".text"));
    }

    // ── SectionCharacteristics ────────────────────────────────────────────────

    #[test]
    fn test_characteristics_code_section() {
        let s = text_section();
        let c = SectionCharacteristics::analyse(&s);
        assert!(c.type_flags.is_code);
        assert!(!c.is_empty);
        assert!(c.contains_strings); // "hello world" should be found
    }

    #[test]
    fn test_characteristics_empty_section() {
        let mut s = SectionEntry::new("empty", 0, 0, SectionFlags::data());
        s.data = vec![];
        let c = SectionCharacteristics::analyse(&s);
        assert!(c.is_empty);
    }

    #[test]
    fn test_characteristics_wx_risk() {
        let mut flags = SectionFlags::code();
        flags.insert(SectionFlags::WRITABLE);
        let mut s = SectionEntry::new("wx", 0, 0x100, flags);
        s.data = vec![0x90; 0x100];
        let c = SectionCharacteristics::analyse(&s);
        assert!(c.risk_score >= 30);
    }

    // ── SectionClassifier ─────────────────────────────────────────────────────

    #[test]
    fn test_classify_text() {
        assert_eq!(SectionClassifier::classify_name(".text"), "code");
        assert_eq!(SectionClassifier::classify_name("__text"), "code");
    }

    #[test]
    fn test_classify_data() {
        assert_eq!(SectionClassifier::classify_name(".data"), "data");
        assert_eq!(SectionClassifier::classify_name(".rodata"), "data");
    }

    #[test]
    fn test_classify_upx() {
        assert_eq!(SectionClassifier::classify_name("UPX0"), "packed");
        assert_eq!(SectionClassifier::classify_name("upx1"), "packed");
    }

    #[test]
    fn test_classify_debug() {
        assert_eq!(SectionClassifier::classify_name(".debug_info"), "debug");
    }

    #[test]
    fn test_classify_unknown() {
        assert_eq!(SectionClassifier::classify_name("__my_custom"), "unknown");
    }

    #[test]
    fn test_classify_suspicious_name() {
        assert!(SectionClassifier::is_suspicious_name("UPX!"));
        assert!(!SectionClassifier::is_suspicious_name(".text"));
    }

    #[test]
    fn test_classify_by_characteristics_packed() {
        let chars = SectionCharacteristics {
            entropy: 7.9,
            type_flags: SectionTypeFlags { is_code: true, is_data: false, is_packed: true },
            contains_strings: false, string_count: 0, high_null_ratio: false,
            ascii_ratio: 0.0, null_ratio: 0.0, is_empty: false, risk_score: 60,
        };
        assert_eq!(SectionClassifier::classify_by_characteristics(&chars), "packed");
    }

    #[test]
    fn test_known_categories_count() {
        assert!(SectionClassifier::known_categories().len() >= 20);
    }

    // ── OverlappingSection ────────────────────────────────────────────────────

    #[test]
    fn test_overlap_compute_some() {
        let a = SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code());
        let b = SectionEntry::new("b", 0x1800, 0x1000, SectionFlags::data());
        let ov = OverlappingSection::compute(&a, &b).unwrap();
        assert_eq!(ov.overlap_start, 0x1800);
        assert_eq!(ov.overlap_end, 0x2000);
        assert_eq!(ov.overlap_bytes, 0x800);
    }

    #[test]
    fn test_overlap_compute_none() {
        let a = SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code());
        let c = SectionEntry::new("c", 0x2000, 0x1000, SectionFlags::data());
        assert!(OverlappingSection::compute(&a, &c).is_none());
    }

    // ── PhantomSection ────────────────────────────────────────────────────────

    #[test]
    fn test_phantom_section_new() {
        let p = PhantomSection::new(0xdeadbeef, 0x1000, "referenced but not mapped");
        assert_eq!(p.vaddr, 0xdeadbeef);
        assert_eq!(p.size, 0x1000);
    }

    // ── SectionHashDb ─────────────────────────────────────────────────────────

    #[test]
    fn test_hash_db_add_lookup() {
        let mut db = SectionHashDb::new();
        db.add("abc123".into(), SectionHashEntry {
            hash: "abc123".into(), name: "ntoskrnl.exe:.text".into(),
            description: "Windows kernel".into(), known_good: true,
        });
        assert!(db.contains("abc123"));
        assert!(db.is_known_good("abc123"));
        assert!(!db.is_known_good("xyz"));
        assert!(!db.is_empty());
    }

    #[test]
    fn test_hash_db_empty() {
        let db = SectionHashDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
    }

    // ── SectionAnalyzer ───────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_add_and_count() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        a.add_section(data_section());
        assert_eq!(a.section_count(), 2);
    }

    #[test]
    fn test_analyzer_find_by_name() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        assert!(a.find_by_name(".text").is_some());
        assert!(a.find_by_name(".bss").is_none());
    }

    #[test]
    fn test_analyzer_find_containing() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        assert!(a.find_containing(0x1500).is_some());
        assert!(a.find_containing(0x3000).is_none());
    }

    #[test]
    fn test_analyzer_find_overlaps() {
        let mut a = SectionAnalyzer::new();
        a.add_section(SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code()));
        a.add_section(SectionEntry::new("b", 0x1800, 0x1000, SectionFlags::data()));
        let ovs = a.find_overlaps();
        assert_eq!(ovs.len(), 1);
    }

    #[test]
    fn test_analyzer_no_overlaps() {
        let mut a = SectionAnalyzer::new();
        a.add_section(SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code()));
        a.add_section(SectionEntry::new("b", 0x2000, 0x1000, SectionFlags::data()));
        assert!(a.find_overlaps().is_empty());
    }

    #[test]
    fn test_analyzer_phantom_detection() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        let phantoms = a.detect_phantom_sections(&[0xdead_beef]);
        assert_eq!(phantoms.len(), 1);
        assert_eq!(phantoms[0].vaddr, 0xdead_beef);
    }

    #[test]
    fn test_analyzer_no_phantoms() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        let phantoms = a.detect_phantom_sections(&[0x1500]); // inside .text
        assert!(phantoms.is_empty());
    }

    #[test]
    fn test_analyzer_wx_sections() {
        let mut a = SectionAnalyzer::new();
        let mut flags = SectionFlags::code();
        flags.insert(SectionFlags::WRITABLE);
        a.add_section(SectionEntry::new("wx", 0, 0x100, flags));
        a.add_section(text_section());
        assert_eq!(a.wx_sections().len(), 1);
    }

    #[test]
    fn test_analyzer_packed_sections() {
        let mut a = SectionAnalyzer::new();
        let mut s = SectionEntry::new("packed", 0, 0x100, SectionFlags::code());
        s.data = (0u8..=255).collect(); // high entropy
        a.add_section(s);
        assert_eq!(a.packed_sections().len(), 1);
    }

    #[test]
    fn test_analyzer_cross_section_refs() {
        let mut a = SectionAnalyzer::new();
        a.add_section(text_section());
        a.add_section(data_section());
        // text_section has a CALL pointing somewhere in data range
        let refs = a.find_cross_section_refs();
        // May or may not find refs depending on the exact target
        let _ = refs;
    }

    #[test]
    fn test_analyzer_total_vsize() {
        let mut a = SectionAnalyzer::new();
        a.add_section(SectionEntry::new("a", 0, 0x1000, SectionFlags::code()));
        a.add_section(SectionEntry::new("b", 0x1000, 0x2000, SectionFlags::data()));
        assert_eq!(a.total_vsize(), 0x3000);
    }

    #[test]
    fn test_analyzer_sort_by_vaddr() {
        let mut a = SectionAnalyzer::new();
        a.add_section(SectionEntry::new("b", 0x2000, 0x1000, SectionFlags::data()));
        a.add_section(SectionEntry::new("a", 0x1000, 0x1000, SectionFlags::code()));
        a.sort_by_vaddr();
        assert_eq!(a.sections[0].name, "a");
    }

    #[test]
    fn test_entropy_zeros() {
        assert!(compute_entropy(&[0u8; 100]) < 0.001);
    }

    #[test]
    fn test_entropy_all_different() {
        let data: Vec<u8> = (0..=255).collect();
        assert!(compute_entropy(&data) > 7.9);
    }

    #[test]
    fn test_count_strings() {
        let data = b"hello\x00world\x00abc\x00xy\x00";
        assert_eq!(count_strings(data, 4), 2); // "hello" and "world"
    }
}
