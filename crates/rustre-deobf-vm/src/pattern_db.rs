//! VM Handler Pattern Database
//!
//! A database of 50+ VM handler byte patterns from major protectors.
//! Supports fuzzy matching, hash-based lookup, and confidence scoring.
//!
//! - [`PatternEntry`] — a single handler pattern with metadata
//! - [`PatternDb`] — the database with lookup / match APIs
//! - [`FuzzyMatchResult`] — result of a fuzzy pattern search
//! - [`HashLookupTable`] — fast hash-based exact matching


use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vm_handler_analysis::HandlerSemantic;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from pattern database operations.
#[derive(Debug, Error)]
pub enum PatternDbError {
    #[error("duplicate pattern ID '{id}'")]
    DuplicateId { id: String },

    #[error("pattern bytes slice is empty")]
    EmptyPattern,

    #[error("mask length {mask_len} does not match pattern length {pattern_len}")]
    MaskLengthMismatch { mask_len: usize, pattern_len: usize },

    #[error("database is empty; cannot perform lookup")]
    EmptyDatabase,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternByte — a single byte in a pattern, with optional mask
// ─────────────────────────────────────────────────────────────────────────────

/// A single byte in a pattern, optionally masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternByte {
    /// The expected byte value.
    pub value: u8,
    /// Mask applied before comparison (0xFF = exact, 0x00 = wildcard).
    pub mask: u8,
}

impl PatternByte {
    /// Exact match: byte must equal `value`.
    #[must_use]
    pub const fn exact(value: u8) -> Self {
        Self { value, mask: 0xFF }
    }
    /// Wildcard: any byte matches.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            value: 0x00,
            mask: 0x00,
        }
    }
    /// Nibble mask: match only the upper nibble.
    #[must_use]
    pub const fn upper_nibble(value: u8) -> Self {
        Self {
            value: value & 0xF0,
            mask: 0xF0,
        }
    }
    /// Nibble mask: match only the lower nibble.
    #[must_use]
    pub const fn lower_nibble(value: u8) -> Self {
        Self {
            value: value & 0x0F,
            mask: 0x0F,
        }
    }

    /// Test whether `byte` matches this pattern byte.
    #[must_use]
    pub const fn matches(self, byte: u8) -> bool {
        (byte & self.mask) == (self.value & self.mask)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single pattern entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    /// Unique identifier for this pattern.
    pub id: String,
    /// Human-readable name (e.g. `VMProtect2_PUSH_EAX`).
    pub name: String,
    /// Protector this pattern was observed in.
    pub protector: String,
    /// Semantic meaning of the handler.
    pub semantic: HandlerSemantic,
    /// The byte pattern to match.
    pub bytes: Vec<PatternByte>,
    /// Confidence bonus when this pattern matches [0.0, 1.0].
    pub confidence: f32,
    /// Architecture this pattern applies to (`"x86"`, `"x86_64"`, `"any"`).
    pub arch: String,
    /// Free-text description.
    pub description: String,
    /// Tags for filtering (e.g. [`"anti-debug"`, `"timing"`, `"stack"`]).
    pub tags: Vec<String>,
    /// FNV-1a hash of the exact bytes in the pattern (for fast lookup).
    pub hash: u64,
}

impl PatternEntry {
    /// Build a new pattern entry. The `arch` field defaults to `"any"` and can
    /// be overridden by assigning to [`PatternEntry::arch`] after construction.
    ///
    /// # Errors
    /// Returns [`PatternDbError::EmptyPattern`] if `bytes` is empty.
    pub fn build(
        id: impl Into<String>,
        name: impl Into<String>,
        protector: impl Into<String>,
        semantic: HandlerSemantic,
        bytes: Vec<PatternByte>,
        confidence: f32,
        description: impl Into<String>,
    ) -> Result<Self, PatternDbError> {
        if bytes.is_empty() {
            return Err(PatternDbError::EmptyPattern);
        }
        let hash = fnv1a_pattern(&bytes);
        Ok(Self {
            id: id.into(),
            name: name.into(),
            protector: protector.into(),
            semantic,
            bytes,
            confidence,
            arch: "any".to_owned(),
            description: description.into(),
            tags: Vec::new(),
            hash,
        })
    }

    /// Convenience: build from a raw bytes slice (all exact matches).
    ///
    /// # Errors
    /// Returns [`PatternDbError::EmptyPattern`] if `raw` is empty.
    pub fn from_exact_bytes(
        id: impl Into<String>,
        name: impl Into<String>,
        protector: impl Into<String>,
        semantic: HandlerSemantic,
        raw: &[u8],
        confidence: f32,
    ) -> Result<Self, PatternDbError> {
        let mut bytes: Vec<PatternByte> = Vec::with_capacity(raw.len());
        bytes.extend(raw.iter().map(|&b| PatternByte::exact(b)));
        Self::build(id, name, protector, semantic, bytes, confidence, "")
    }

    /// Number of bytes in the pattern.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if `haystack` contains this pattern starting at `offset`.
    #[must_use]
    pub fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > haystack.len() {
            return false;
        }
        self.bytes
            .iter()
            .enumerate()
            .all(|(i, pb)| pb.matches(haystack[offset + i]))
    }

    /// Find the first occurrence of this pattern in `haystack`.
    #[must_use]
    pub fn find(&self, haystack: &[u8]) -> Option<usize> {
        if self.bytes.len() > haystack.len() {
            return None;
        }
        (0..=(haystack.len() - self.bytes.len())).find(|&i| self.matches_at(haystack, i))
    }

    /// Count all non-overlapping matches in `haystack`.
    #[must_use]
    pub fn count_matches(&self, haystack: &[u8]) -> usize {
        let mut count = 0;
        let mut pos = 0;
        while pos + self.bytes.len() <= haystack.len() {
            if self.matches_at(haystack, pos) {
                count += 1;
                pos += self.bytes.len();
            } else {
                pos += 1;
            }
        }
        count
    }

    /// Returns `true` if this pattern has a tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzyMatchResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a fuzzy pattern search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyMatchResult {
    /// The pattern that matched.
    pub pattern_id: String,
    /// Pattern name.
    pub pattern_name: String,
    /// Semantic of the matched pattern.
    pub semantic: HandlerSemantic,
    /// Byte offset in the haystack where the match begins.
    pub offset: usize,
    /// Number of bytes that matched exactly (vs. wildcards).
    pub exact_byte_count: usize,
    /// Total pattern length.
    pub pattern_length: usize,
    /// Combined confidence score.
    pub confidence: f32,
}

impl FuzzyMatchResult {
    /// Ratio of exactly-matched bytes to total pattern length.
    #[must_use]
    pub fn exact_ratio(&self) -> f32 {
        if self.pattern_length == 0 {
            return 0.0;
        }
        f32::from(u16::try_from(self.exact_byte_count).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.pattern_length).unwrap_or(u16::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HashLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Fast hash-based exact-pattern lookup table.
///
/// Hashes every `window_size`-byte window of the input and looks it up in
/// the pattern hash map in O(n) time.
#[derive(Debug, Clone, Default)]
pub struct HashLookupTable {
    /// Map from pattern hash → list of pattern IDs.
    pub hash_to_ids: HashMap<u64, Vec<String>>,
    /// Window size used for hashing.
    pub window_size: usize,
}

impl HashLookupTable {
    /// Create a new lookup table with the given window size.
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            hash_to_ids: HashMap::new(),
            window_size,
        }
    }

    /// Insert a pattern hash → ID mapping.
    pub fn insert(&mut self, hash: u64, id: impl Into<String>) {
        self.hash_to_ids.entry(hash).or_default().push(id.into());
    }

    /// Look up pattern IDs whose hash matches a `window` of bytes.
    #[must_use]
    pub fn lookup(&self, window: &[u8]) -> &[String] {
        let h = fnv1a_bytes(window);
        self.hash_to_ids
            .get(&h)
            .map_or(&[] as &[String], Vec::as_slice)
    }

    /// Scan `haystack` and return all (offset, `pattern_id`) hits.
    #[must_use]
    pub fn scan(&self, haystack: &[u8]) -> Vec<(usize, &String)> {
        if self.window_size == 0 || haystack.len() < self.window_size {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for i in 0..=(haystack.len() - self.window_size) {
            let window = &haystack[i..i + self.window_size];
            let ids = self.lookup(window);
            for id in ids {
                hits.push((i, id));
            }
        }
        hits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDb
// ─────────────────────────────────────────────────────────────────────────────

/// The pattern database: a collection of [`PatternEntry`] instances with
/// efficient lookup, fuzzy matching, and hash-based scanning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternDb {
    /// All patterns indexed by ID.
    pub entries: HashMap<String, PatternEntry>,
    /// Protector → list of pattern IDs.
    pub by_protector: HashMap<String, Vec<String>>,
    /// Semantic → list of pattern IDs.
    pub by_semantic: HashMap<String, Vec<String>>,
}

impl PatternDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a pattern entry.
    ///
    /// # Errors
    /// Returns [`PatternDbError::DuplicateId`] if the entry ID is already in the database.
    pub fn insert(&mut self, entry: PatternEntry) -> Result<(), PatternDbError> {
        if self.entries.contains_key(&entry.id) {
            return Err(PatternDbError::DuplicateId { id: entry.id });
        }
        self.by_protector
            .entry(entry.protector.clone())
            .or_default()
            .push(entry.id.clone());
        self.by_semantic
            .entry(format!("{:?}", entry.semantic))
            .or_default()
            .push(entry.id.clone());
        self.entries.insert(entry.id.clone(), entry);
        Ok(())
    }

    /// Number of patterns in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a pattern by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&PatternEntry> {
        self.entries.get(id)
    }

    /// Return all patterns for a given protector.
    #[must_use]
    pub fn for_protector(&self, protector: &str) -> Vec<&PatternEntry> {
        self.by_protector
            .get(protector)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Return all patterns with a given semantic.
    #[must_use]
    pub fn for_semantic(&self, semantic: HandlerSemantic) -> Vec<&PatternEntry> {
        let key = format!("{semantic:?}");
        self.by_semantic
            .get(&key)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Scan `haystack` for all pattern matches.
    ///
    /// Returns matches sorted by confidence descending.
    #[must_use]
    pub fn scan(&self, haystack: &[u8]) -> Vec<FuzzyMatchResult> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut results = Vec::new();
        for entry in self.entries.values() {
            if let Some(offset) = entry.find(haystack) {
                let exact_count = entry.bytes.iter().filter(|pb| pb.mask == 0xFF).count();
                results.push(FuzzyMatchResult {
                    pattern_id: entry.id.clone(),
                    pattern_name: entry.name.clone(),
                    semantic: entry.semantic,
                    offset,
                    exact_byte_count: exact_count,
                    pattern_length: entry.len(),
                    confidence: entry.confidence,
                });
            }
        }
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Fuzzy scan: allow up to `max_mismatches` byte differences.
    ///
    /// Returns matches sorted by (confidence × [`FuzzyMatchResult::exact_ratio`]) descending.
    #[must_use]
    pub fn fuzzy_scan(&self, haystack: &[u8], max_mismatches: usize) -> Vec<FuzzyMatchResult> {
        let mut results = Vec::new();
        for entry in self.entries.values() {
            let plen = entry.len();
            if plen > haystack.len() {
                continue;
            }
            for offset in 0..=(haystack.len() - plen) {
                let mismatches = entry
                    .bytes
                    .iter()
                    .enumerate()
                    .filter(|(i, pb)| !pb.matches(haystack[offset + i]))
                    .count();
                if mismatches <= max_mismatches {
                    let exact_count = entry
                        .bytes
                        .iter()
                        .enumerate()
                        .filter(|(i, pb)| pb.mask == 0xFF && pb.matches(haystack[offset + i]))
                        .count();
                    let penalty = f32::from(u16::try_from(mismatches).unwrap_or(u16::MAX))
                        / f32::from(u16::try_from(plen).unwrap_or(u16::MAX));
                    let adj_conf = (entry.confidence * (1.0 - penalty)).max(0.0);
                    results.push(FuzzyMatchResult {
                        pattern_id: entry.id.clone(),
                        pattern_name: entry.name.clone(),
                        semantic: entry.semantic,
                        offset,
                        exact_byte_count: exact_count,
                        pattern_length: plen,
                        confidence: adj_conf,
                    });
                }
            }
        }
        results.sort_by(|a, b| {
            let sa = a.confidence * a.exact_ratio();
            let sb = b.confidence * b.exact_ratio();
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Build a [`HashLookupTable`] from all exact-byte patterns for fast scanning.
    #[must_use]
    pub fn build_hash_table(&self, window_size: usize) -> HashLookupTable {
        let mut table = HashLookupTable::new(window_size);
        for entry in self.entries.values() {
            // Only index patterns whose first `window_size` bytes are all exact.
            if entry.len() >= window_size
                && entry.bytes[..window_size].iter().all(|pb| pb.mask == 0xFF)
            {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for pb in &entry.bytes[..window_size] {
                    h ^= u64::from(pb.value);
                    h = h.wrapping_mul(0x0100_0000_01b3);
                }
                table.insert(h, entry.id.clone());
            }
        }
        table
    }

    /// Load the built-in 50+ pattern library.
    #[must_use]
    pub fn with_builtin_patterns() -> Self {
        let mut db = Self::new();
        for entry in builtin_patterns() {
            let _ = db.insert(entry); // ignore duplicates from test code
        }
        db
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in pattern library (50+ entries)
// ─────────────────────────────────────────────────────────────────────────────

fn e(
    id: &str,
    name: &str,
    prot: &str,
    semantic: HandlerSemantic,
    raw: &[u8],
    conf: f32,
) -> PatternEntry {
    PatternEntry::from_exact_bytes(id, name, prot, semantic, raw, conf)
        .expect("built-in pattern must be valid")
}

fn w(
    id: &str,
    name: &str,
    prot: &str,
    semantic: HandlerSemantic,
    bytes: Vec<PatternByte>,
    conf: f32,
) -> PatternEntry {
    PatternEntry::build(id, name, prot, semantic, bytes, conf, "")
        .expect("built-in pattern must be valid")
}

/// Returns all built-in patterns.
#[must_use]
pub fn builtin_patterns() -> Vec<PatternEntry> {
    vec![
        // ── VMProtect 2.x ────────────────────────────────────────────────────
        e("vmp2_push_eax",   "VMP2 PUSH EAX handler",   "VMProtect2", HandlerSemantic::Push,      &[0x60, 0x9C, 0x50],             0.80),
        e("vmp2_push_ecx",   "VMP2 PUSH ECX handler",   "VMProtect2", HandlerSemantic::Push,      &[0x60, 0x9C, 0x51],             0.80),
        e("vmp2_push_edx",   "VMP2 PUSH EDX handler",   "VMProtect2", HandlerSemantic::Push,      &[0x60, 0x9C, 0x52],             0.80),
        e("vmp2_push_ebx",   "VMP2 PUSH EBX handler",   "VMProtect2", HandlerSemantic::Push,      &[0x60, 0x9C, 0x53],             0.80),
        e("vmp2_pop_eax",    "VMP2 POP EAX handler",    "VMProtect2", HandlerSemantic::Pop,       &[0x58, 0x9D, 0x61],             0.80),
        e("vmp2_add",        "VMP2 ADD handler",        "VMProtect2", HandlerSemantic::Add,       &[0x03, 0x04, 0x24],             0.85),
        e("vmp2_sub",        "VMP2 SUB handler",        "VMProtect2", HandlerSemantic::Sub,       &[0x2B, 0x04, 0x24],             0.85),
        e("vmp2_mul",        "VMP2 MUL handler",        "VMProtect2", HandlerSemantic::Mul,       &[0xF7, 0x24, 0x24],             0.82),
        e("vmp2_and",        "VMP2 AND handler",        "VMProtect2", HandlerSemantic::And,       &[0x23, 0x04, 0x24],             0.83),
        e("vmp2_or",         "VMP2 OR handler",         "VMProtect2", HandlerSemantic::Or,        &[0x0B, 0x04, 0x24],             0.83),
        e("vmp2_xor",        "VMP2 XOR handler",        "VMProtect2", HandlerSemantic::Xor,       &[0x33, 0x04, 0x24],             0.83),
        e("vmp2_not",        "VMP2 NOT handler",        "VMProtect2", HandlerSemantic::Not,       &[0xF7, 0x14, 0x24],             0.78),
        e("vmp2_neg",        "VMP2 NEG handler",        "VMProtect2", HandlerSemantic::Neg,       &[0xF7, 0x1C, 0x24],             0.78),
        e("vmp2_shl",        "VMP2 SHL handler",        "VMProtect2", HandlerSemantic::Shl,       &[0xD3, 0x24, 0x24],             0.80),
        e("vmp2_shr",        "VMP2 SHR handler",        "VMProtect2", HandlerSemantic::Shr,       &[0xD3, 0x2C, 0x24],             0.80),
        e("vmp2_sar",        "VMP2 SAR handler",        "VMProtect2", HandlerSemantic::Sar,       &[0xD3, 0x3C, 0x24],             0.80),
        e("vmp2_rol",        "VMP2 ROL handler",        "VMProtect2", HandlerSemantic::Rol,       &[0xD3, 0x04, 0x24],             0.78),
        e("vmp2_ror",        "VMP2 ROR handler",        "VMProtect2", HandlerSemantic::Ror,       &[0xD3, 0x0C, 0x24],             0.78),
        e("vmp2_jmp",        "VMP2 JMP handler",        "VMProtect2", HandlerSemantic::Jmp,       &[0x8B, 0x34, 0x24, 0xFF, 0xE6], 0.85),
        e("vmp2_jcc_jz",     "VMP2 JCC (JZ) handler",   "VMProtect2", HandlerSemantic::Jcc,       &[0x74, 0x05, 0xFF, 0xE6],       0.78),
        e("vmp2_call",       "VMP2 CALL handler",       "VMProtect2", HandlerSemantic::Call,      &[0xFF, 0x14, 0x24],             0.82),
        e("vmp2_ret",        "VMP2 RET handler",        "VMProtect2", HandlerSemantic::Ret,       &[0x5E, 0x9D, 0x61, 0xC3],       0.85),
        e("vmp2_load32",     "VMP2 LOAD32 handler",     "VMProtect2", HandlerSemantic::Load,      &[0x8B, 0x00, 0x89, 0x04, 0x24], 0.82),
        e("vmp2_store32",    "VMP2 STORE32 handler",    "VMProtect2", HandlerSemantic::Store,     &[0x58, 0x59, 0x89, 0x08],       0.80),
        e("vmp2_pushflags",  "VMP2 PUSHFLAGS handler",  "VMProtect2", HandlerSemantic::PushFlags, &[0x9C, 0x50],                   0.78),
        e("vmp2_popflags",   "VMP2 POPFLAGS handler",   "VMProtect2", HandlerSemantic::PopFlags,  &[0x58, 0x9D],                   0.78),
        e("vmp2_vmexit",     "VMP2 VM_EXIT handler",    "VMProtect2", HandlerSemantic::VmExit,    &[0x9D, 0x61, 0xC3],             0.90),
        e("vmp2_vmenter",    "VMP2 VM_ENTER stub",      "VMProtect2", HandlerSemantic::VmEnter,   &[0x68, 0x00, 0x00, 0x00, 0x00, 0xE8], 0.85),
        e("vmp2_cmp",        "VMP2 CMP handler",        "VMProtect2", HandlerSemantic::Cmp,       &[0x3B, 0x04, 0x24],             0.78),
        e("vmp2_div",        "VMP2 DIV handler",        "VMProtect2", HandlerSemantic::Div,       &[0x31, 0xD2, 0xF7, 0x34, 0x24], 0.75),
        e("vmp2_nop",        "VMP2 NOP handler",        "VMProtect2", HandlerSemantic::Nop,       &[0x90, 0x9D, 0x61, 0xFF, 0xE0], 0.70),
        // ── VMProtect 3.x ────────────────────────────────────────────────────
        e("vmp3_cpuid_stub",  "VMP3 CPUID anti-detect",   "VMProtect3", HandlerSemantic::Unknown,   &[0x0F, 0xA2],             0.72),
        e("vmp3_rdtsc_stub",  "VMP3 RDTSC timing",         "VMProtect3", HandlerSemantic::Unknown,   &[0x0F, 0x31],             0.68),
        w("vmp3_movzx_fetch", "VMP3 MOVZX opcode fetch",   "VMProtect3", HandlerSemantic::Unknown,
            vec![PatternByte::exact(0x0F), PatternByte::exact(0xB6), PatternByte::any()], 0.70),
        e("vmp3_jmp_table",   "VMP3 JMP handler table",    "VMProtect3", HandlerSemantic::Jmp,       &[0xFF, 0x24, 0xC5],       0.80),
        e("vmp3_pushf_enc",   "VMP3 encoded PUSHF",        "VMProtect3", HandlerSemantic::PushFlags, &[0x9C, 0x81, 0x34, 0x24], 0.72),
        // ── Themida / WinLicense ──────────────────────────────────────────────
        e("thm_xor_decrypt1", "Themida XOR decrypt loop",    "Themida", HandlerSemantic::Xor,     &[0x33, 0xC0, 0x33, 0xC9, 0x33, 0xD2], 0.75),
        e("thm_rdtsc_check",  "Themida RDTSC anti-debug",    "Themida", HandlerSemantic::Unknown,  &[0x0F, 0x31, 0x89, 0x45],             0.72),
        e("thm_isbp_hook",    "Themida IsDbgPresent hook",   "Themida", HandlerSemantic::Unknown,  &[0x33, 0xC0, 0xC3],                   0.68),
        e("thm_vmexit_large", "Themida VM_EXIT (large)",     "Themida", HandlerSemantic::VmExit,   &[0x61, 0x9D, 0xC3],                   0.80),
        e("thm_pushad_enter", "Themida PUSHAD VM enter",     "Themida", HandlerSemantic::VmEnter,  &[0x60, 0x9C, 0xE8],                   0.80),
        // ── Code Virtualizer ──────────────────────────────────────────────────
        e("cv_push_short", "CV short PUSH handler", "CodeVirtualizer", HandlerSemantic::Push, &[0x50, 0xFF, 0x24, 0x85],             0.80),
        e("cv_pop_short",  "CV short POP handler",  "CodeVirtualizer", HandlerSemantic::Pop,  &[0x58, 0xFF, 0x24, 0x85],             0.80),
        e("cv_add_short",  "CV short ADD handler",  "CodeVirtualizer", HandlerSemantic::Add,  &[0x01, 0x04, 0x24, 0xFF, 0x24, 0x85], 0.82),
        e("cv_xor_short",  "CV short XOR handler",  "CodeVirtualizer", HandlerSemantic::Xor,  &[0x31, 0x04, 0x24, 0xFF, 0x24, 0x85], 0.82),
        e("cv_jmp_short",  "CV short JMP handler",  "CodeVirtualizer", HandlerSemantic::Jmp,  &[0x8B, 0x04, 0x24, 0xFF, 0xE0],       0.85),
        e("cv_ret_short",  "CV short RET handler",  "CodeVirtualizer", HandlerSemantic::Ret,  &[0x58, 0xC3],                         0.80),
        // ── Enigma Protector ──────────────────────────────────────────────────
        e("enig_shl_index", "Enigma SHL index scale",  "Enigma", HandlerSemantic::Shl,  &[0xC1, 0xE0, 0x02],             0.72),
        e("enig_push_imm",  "Enigma PUSH imm32",       "Enigma", HandlerSemantic::Push, &[0x68, 0x00, 0x00, 0x00, 0x00], 0.68),
        e("enig_call_ind",  "Enigma CALL indirect",    "Enigma", HandlerSemantic::Call, &[0xFF, 0x14, 0x85],             0.70),
        e("enig_ret",       "Enigma RET",              "Enigma", HandlerSemantic::Ret,  &[0x5E, 0xC3],                   0.75),
        // ── Obsidium ──────────────────────────────────────────────────────────
        e("obs_pushfd_pop",   "Obsidium PUSHFD/POPFD",      "Obsidium", HandlerSemantic::PushFlags, &[0x9C, 0x8B, 0x04, 0x24, 0x9D], 0.78),
        e("obs_int3_trap",    "Obsidium INT3 anti-debug",   "Obsidium", HandlerSemantic::Unknown,   &[0xCC],                         0.50),
        e("obs_pushad_enter", "Obsidium PUSHAD VM enter",   "Obsidium", HandlerSemantic::VmEnter,   &[0x60, 0x9C, 0xBE],             0.78),
        e("obs_add_flags",    "Obsidium ADD with flags",    "Obsidium", HandlerSemantic::Add,       &[0x9C, 0x03, 0x04, 0x24, 0x9D], 0.75),
        e("obs_xor_flags",    "Obsidium XOR with flags",    "Obsidium", HandlerSemantic::Xor,       &[0x9C, 0x31, 0x04, 0x24, 0x9D], 0.75),
        e("obs_vmexit",       "Obsidium VM_EXIT",           "Obsidium", HandlerSemantic::VmExit,    &[0x9D, 0x61, 0xCF],             0.80),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of a byte slice.
#[inline]
fn fnv1a_bytes(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// FNV-1a hash of just the exact bytes in a pattern (mask==0xFF bytes).
fn fnv1a_pattern(bytes: &[PatternByte]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for pb in bytes {
        hash ^= u64::from(pb.value);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_byte_exact() {
        let pb = PatternByte::exact(0xAB);
        assert!(pb.matches(0xAB));
        assert!(!pb.matches(0xAC));
    }

    #[test]
    fn test_pattern_byte_wildcard() {
        let pb = PatternByte::any();
        for b in 0u8..=255 {
            assert!(pb.matches(b));
        }
    }

    #[test]
    fn test_pattern_byte_upper_nibble() {
        let pb = PatternByte::upper_nibble(0xA0);
        assert!(pb.matches(0xA0));
        assert!(pb.matches(0xAF));
        assert!(!pb.matches(0xBF));
    }

    #[test]
    fn test_pattern_entry_find_exact() {
        let entry = PatternEntry::from_exact_bytes(
            "test",
            "test",
            "any",
            HandlerSemantic::Nop,
            &[0x90, 0x90, 0xFF, 0xE0],
            0.8,
        )
        .unwrap();
        let data = &[0x00, 0x90, 0x90, 0xFF, 0xE0, 0x00];
        assert_eq!(entry.find(data), Some(1));
    }

    #[test]
    fn test_pattern_entry_find_none() {
        let entry = PatternEntry::from_exact_bytes(
            "test2",
            "test2",
            "any",
            HandlerSemantic::Nop,
            &[0xFF, 0xFF, 0xFF],
            0.8,
        )
        .unwrap();
        let data = &[0x00u8; 16];
        assert_eq!(entry.find(data), None);
    }

    #[test]
    fn test_pattern_entry_count_matches() {
        let entry =
            PatternEntry::from_exact_bytes("rep", "rep", "any", HandlerSemantic::Nop, &[0x90], 0.5)
                .unwrap();
        let data = &[0x90, 0x90, 0x00, 0x90];
        assert_eq!(entry.count_matches(data), 3);
    }

    #[test]
    fn test_pattern_entry_empty_returns_error() {
        let result =
            PatternEntry::from_exact_bytes("e", "e", "any", HandlerSemantic::Nop, &[], 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_db_insert_and_get() {
        let mut db = PatternDb::new();
        let entry = e("id1", "Test", "test", HandlerSemantic::Nop, &[0x90], 0.5);
        db.insert(entry).unwrap();
        assert_eq!(db.len(), 1);
        assert!(db.get("id1").is_some());
    }

    #[test]
    fn test_pattern_db_duplicate_id_errors() {
        let mut db = PatternDb::new();
        let e1 = e("dup", "A", "x", HandlerSemantic::Nop, &[0x90], 0.5);
        let e2 = e("dup", "B", "x", HandlerSemantic::Nop, &[0x91], 0.5);
        db.insert(e1).unwrap();
        assert!(db.insert(e2).is_err());
    }

    #[test]
    fn test_pattern_db_scan() {
        let mut db = PatternDb::new();
        db.insert(e(
            "s1",
            "S1",
            "vmp2",
            HandlerSemantic::Add,
            &[0x03, 0x04, 0x24],
            0.85,
        ))
        .unwrap();
        let data = &[0x00, 0x03, 0x04, 0x24, 0x00];
        let results = db.scan(data);
        assert!(!results.is_empty());
        assert_eq!(results[0].pattern_id, "s1");
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_pattern_db_fuzzy_scan_with_mismatch() {
        let mut db = PatternDb::new();
        db.insert(e(
            "f1",
            "F1",
            "vmp2",
            HandlerSemantic::Xor,
            &[0x33, 0x04, 0x24],
            0.83,
        ))
        .unwrap();
        // Data has 1 mismatch (0x04 → 0x05).
        let data = &[0x33, 0x05, 0x24];
        let results = db.fuzzy_scan(data, 1);
        assert!(!results.is_empty());
        assert!(results[0].confidence < 0.83);
    }

    #[test]
    fn test_pattern_db_builtin_count() {
        let db = PatternDb::with_builtin_patterns();
        assert!(
            db.len() >= 50,
            "Expected at least 50 builtin patterns, got {}",
            db.len()
        );
    }

    #[test]
    fn test_pattern_db_for_protector() {
        let db = PatternDb::with_builtin_patterns();
        let vmp2 = db.for_protector("VMProtect2");
        assert!(!vmp2.is_empty());
        assert!(vmp2.iter().all(|e| e.protector == "VMProtect2"));
    }

    #[test]
    fn test_pattern_db_for_semantic() {
        let db = PatternDb::with_builtin_patterns();
        let pushes = db.for_semantic(HandlerSemantic::Push);
        assert!(!pushes.is_empty());
    }

    #[test]
    fn test_hash_lookup_table_scan() {
        let mut db = PatternDb::new();
        db.insert(e(
            "ht1",
            "HT1",
            "any",
            HandlerSemantic::Nop,
            &[0x90, 0x91, 0x92],
            0.7,
        ))
        .unwrap();
        let table = db.build_hash_table(3);
        let data = &[0x00, 0x90, 0x91, 0x92, 0x00];
        let hits = table.scan(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].0, 1);
        assert_eq!(hits[0].1, "ht1");
    }

    #[test]
    fn test_fuzzy_match_result_exact_ratio() {
        let r = FuzzyMatchResult {
            pattern_id: "x".into(),
            pattern_name: "x".into(),
            semantic: HandlerSemantic::Nop,
            offset: 0,
            exact_byte_count: 3,
            pattern_length: 4,
            confidence: 0.8,
        };
        assert!((r.exact_ratio() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_fnv1a_consistency() {
        let h1 = fnv1a_bytes(b"test_pattern");
        let h2 = fnv1a_bytes(b"test_pattern");
        assert_eq!(h1, h2);
        assert_ne!(fnv1a_bytes(b"a"), fnv1a_bytes(b"b"));
    }

    #[test]
    fn test_pattern_entry_has_tag() {
        let mut entry = e("tag_test", "T", "x", HandlerSemantic::Nop, &[0x90], 0.5);
        assert!(!entry.has_tag("anti-debug"));
        entry.tags.push("anti-debug".to_owned());
        assert!(entry.has_tag("anti-debug"));
    }
}
