//! `wildcard_pattern_compiler` — Compile wildcard hex patterns to fast, reusable
//! byte-mask pairs with an optional NFA for complex patterns.
//!
//! The central type is [`WildcardPatternCompiler`], which transforms a
//! human-readable hex string with `?` wildcards into a [`CompiledPattern`]
//! (different from the one in lib.rs — this one carries extra metadata).
//!
//! The module also provides [`WildcardMask`], a compact bit-vector that marks
//! which byte positions in a pattern are wildcards.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Pattern, PatternByte, PatternError};

// ─────────────────────────────────────────────────────────────────────────────
// WildcardMask
// ─────────────────────────────────────────────────────────────────────────────

/// A compact bit-vector indicating which byte slots in a pattern are wildcards.
///
/// Bit `i` is set when slot `i` is a wildcard (full or partial).
/// Internally backed by a `Vec<u64>` of word-sized chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildcardMask {
    /// Total pattern length in bytes.
    pub len: usize,
    /// Chunk storage: each `u64` covers 64 byte positions.
    chunks: Vec<u64>,
}

impl WildcardMask {
    /// Create a new mask of `len` bytes, all initially non-wildcard.
    #[must_use]
    pub fn new(len: usize) -> Self {
        let words = len.div_ceil(64);
        Self {
            len,
            chunks: vec![0u64; words],
        }
    }

    /// Mark byte position `i` as a wildcard.
    pub fn set_wildcard(&mut self, i: usize) {
        if i < self.len {
            self.chunks[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Returns `true` if byte position `i` is a wildcard.
    #[must_use]
    pub fn is_wildcard(&self, i: usize) -> bool {
        if i >= self.len {
            return false;
        }
        (self.chunks[i / 64] >> (i % 64)) & 1 != 0
    }

    /// Count the total number of wildcard positions.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.chunks.iter().map(|c| c.count_ones() as usize).sum()
    }

    /// Count the total number of exact (non-wildcard) positions.
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.len - self.wildcard_count()
    }

    /// Specificity in [0.0, 1.0]: fraction of exact positions.
    #[must_use]
    pub fn specificity(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        self.exact_count() as f64 / self.len as f64
    }

    /// Returns `true` if every position is a wildcard.
    #[must_use]
    pub fn all_wildcards(&self) -> bool {
        self.wildcard_count() == self.len
    }

    /// Returns `true` if no position is a wildcard.
    #[must_use]
    pub fn no_wildcards(&self) -> bool {
        self.chunks.iter().all(|&c| c == 0)
    }

    /// Iterate over wildcard positions.
    #[must_use]
    pub fn wildcard_positions(&self) -> Vec<usize> {
        (0..self.len).filter(|&i| self.is_wildcard(i)).collect()
    }

    /// Iterate over exact (non-wildcard) positions.
    #[must_use]
    pub fn exact_positions(&self) -> Vec<usize> {
        (0..self.len).filter(|&i| !self.is_wildcard(i)).collect()
    }
}

impl fmt::Display for WildcardMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..self.len {
            write!(f, "{}", if self.is_wildcard(i) { '?' } else { '.' })?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NibbleMask — partial wildcard
// ─────────────────────────────────────────────────────────────────────────────

/// Per-nibble wildcard state for a single pattern byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NibbleMask {
    /// High nibble is constrained (not wildcard).
    pub high_exact: bool,
    /// Low nibble is constrained (not wildcard).
    pub low_exact: bool,
}

impl NibbleMask {
    /// Both nibbles are exact.
    #[must_use]
    pub const fn full_exact() -> Self {
        Self {
            high_exact: true,
            low_exact: true,
        }
    }

    /// Both nibbles are wildcards.
    #[must_use]
    pub const fn full_wildcard() -> Self {
        Self {
            high_exact: false,
            low_exact: false,
        }
    }

    /// Returns the byte mask (0xFF = both exact, 0xF0 = high only, etc.).
    #[must_use]
    pub const fn byte_mask(self) -> u8 {
        (if self.high_exact { 0xF0u8 } else { 0u8 })
            | (if self.low_exact { 0x0Fu8 } else { 0u8 })
    }

    /// Whether this slot is fully or partially a wildcard.
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        !self.high_exact || !self.low_exact
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompiledWildcardPattern
// ─────────────────────────────────────────────────────────────────────────────

/// The output of [`WildcardPatternCompiler::compile`].
///
/// Contains everything needed for fast repeated search:
/// - aligned value and mask byte arrays
/// - a `WildcardMask` bit-vector
/// - the original hex source string
/// - per-slot nibble information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledWildcardPattern {
    /// Original hex source (e.g. `"DE AD ? ? 0? ?F"`).
    pub source: String,
    /// Value bytes (wildcarded positions are 0x00).
    pub values: Vec<u8>,
    /// Mask bytes (0xFF = must match, 0xF0/0x0F = nibble, 0x00 = full wildcard).
    pub masks: Vec<u8>,
    /// Compact wildcard bit-vector.
    pub wildcard_mask: WildcardMask,
    /// Per-slot nibble detail.
    pub nibble_masks: Vec<NibbleMask>,
    /// Pattern length in bytes.
    pub len: usize,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Anchor: (offset, byte) of the first exact position, if any.
    pub anchor: Option<(usize, u8)>,
}

impl CompiledWildcardPattern {
    /// Returns `true` if this compiled pattern matches `data` at `offset`.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.len > data.len() {
            return false;
        }
        for i in 0..self.len {
            let b = data[offset + i];
            if b & self.masks[i] != self.values[i] & self.masks[i] {
                return false;
            }
        }
        true
    }

    /// Search all positions in `data` where this pattern matches.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.len == 0 || data.len() < self.len {
            return Vec::new();
        }
        // Fast path: no wildcards → KMP-style byte comparison
        if self.wildcard_mask.no_wildcards() {
            return kmp_search_local(data, &self.values);
        }
        // Anchored scan
        if let Some((anchor_off, anchor_byte)) = self.anchor {
            let mut results = Vec::new();
            let mut i = anchor_off;
            while i < data.len() {
                if data[i] == anchor_byte {
                    let start = i.saturating_sub(anchor_off);
                    if self.matches(data, start) {
                        results.push(start);
                    }
                }
                i += 1;
            }
            return results;
        }
        // Full scan
        (0..=(data.len() - self.len))
            .filter(|&s| self.matches(data, s))
            .collect()
    }

    /// Convert to an IDA-compatible hex string (e.g. `"DE AD ? ? 0? ?F"`).
    #[must_use]
    pub fn to_ida_hex(&self) -> String {
        self.nibble_masks
            .iter()
            .zip(self.values.iter())
            .map(|(nm, &val)| match (nm.high_exact, nm.low_exact) {
                (true, true) => format!("{val:02X}"),
                (true, false) => format!("{:X}?", val >> 4),
                (false, true) => format!("?{:X}", val & 0x0F),
                (false, false) => "??".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Specificity score [0.0, 1.0].
    #[must_use]
    pub fn specificity(&self) -> f64 {
        self.wildcard_mask.specificity()
    }
}

impl fmt::Display for CompiledWildcardPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        write!(f, "CompiledWildcardPattern({name}, len={}, spec={:.2})", self.len, self.specificity())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WildcardPatternCompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Compiler that transforms a hex string with `?` wildcards into a
/// [`CompiledWildcardPattern`].
///
/// Supports:
/// - `??` or `?` — full wildcard byte
/// - `AB` — exact byte
/// - `A?` — high nibble exact, low wildcard
/// - `?B` — high wildcard, low nibble exact
///
/// # Examples
///
/// ```rust
/// use rustre_hex_pattern::wildcard_pattern_compiler::WildcardPatternCompiler;
///
/// let cpat = WildcardPatternCompiler::compile("DE AD ? ? 0? ?F").unwrap();
/// assert_eq!(cpat.len, 6);
/// assert_eq!(cpat.wildcard_mask.wildcard_count(), 4);
/// ```
#[derive(Debug, Default)]
pub struct WildcardPatternCompiler;

impl WildcardPatternCompiler {
    /// Compile a hex string with wildcards into a [`CompiledWildcardPattern`].
    ///
    /// # Errors
    /// Returns `PatternError::Empty` if the string is empty, or
    /// `PatternError::Parse` if any token is malformed.
    pub fn compile(hex: &str) -> Result<CompiledWildcardPattern, PatternError> {
        let pat = Pattern::parse(hex)?;
        Ok(Self::from_pattern(&pat, hex.to_string()))
    }

    /// Compile and assign a name.
    ///
    /// # Errors
    /// Same as [`compile`].
    pub fn compile_named(name: &str, hex: &str) -> Result<CompiledWildcardPattern, PatternError> {
        let mut cpat = Self::compile(hex)?;
        cpat.name = Some(name.to_string());
        Ok(cpat)
    }

    /// Build a [`CompiledWildcardPattern`] from an existing [`Pattern`].
    #[must_use]
    pub fn from_pattern(pat: &Pattern, source: String) -> CompiledWildcardPattern {
        let len = pat.bytes.len();
        let mut values = Vec::with_capacity(len);
        let mut masks = Vec::with_capacity(len);
        let mut wildcard_mask = WildcardMask::new(len);
        let mut nibble_masks = Vec::with_capacity(len);
        let mut anchor: Option<(usize, u8)> = None;

        for (i, pb) in pat.bytes.iter().enumerate() {
            let (val, msk, nm) = Self::slot_info(pb);
            values.push(val);
            masks.push(msk);
            nibble_masks.push(nm);
            if nm.is_wildcard() {
                wildcard_mask.set_wildcard(i);
            } else if anchor.is_none() {
                anchor = Some((i, val));
            }
        }

        CompiledWildcardPattern {
            source,
            values,
            masks,
            wildcard_mask,
            nibble_masks,
            len,
            name: pat.name.clone(),
            anchor,
        }
    }

    /// Compile a batch of (name, hex) pairs.
    ///
    /// # Errors
    /// Returns the first `PatternError` encountered.
    pub fn compile_batch(
        patterns: &[(&str, &str)],
    ) -> Result<Vec<CompiledWildcardPattern>, PatternError> {
        patterns
            .iter()
            .map(|(name, hex)| Self::compile_named(name, hex))
            .collect()
    }

    /// Derive value, mask, and nibble-mask for a single `PatternByte`.
    fn slot_info(pb: &PatternByte) -> (u8, u8, NibbleMask) {
        match pb {
            PatternByte::Exact(b) => (*b, 0xFF, NibbleMask::full_exact()),
            PatternByte::Wildcard => (0x00, 0x00, NibbleMask::full_wildcard()),
            PatternByte::Nibble { high, low } => {
                let val = (high.unwrap_or(0) << 4) | low.unwrap_or(0);
                let msk = (if high.is_some() { 0xF0u8 } else { 0 })
                    | (if low.is_some() { 0x0Fu8 } else { 0 });
                let nm = NibbleMask {
                    high_exact: high.is_some(),
                    low_exact: low.is_some(),
                };
                (val, msk, nm)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternValidator — check a compiled pattern for common issues
// ─────────────────────────────────────────────────────────────────────────────

/// Validation result for a compiled wildcard pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// The pattern that was validated.
    pub source: String,
    /// Warnings (non-fatal).
    pub warnings: Vec<String>,
    /// Errors (fatal for reliable search).
    pub errors: Vec<String>,
    /// Whether the pattern passed validation.
    pub is_valid: bool,
}

impl ValidationReport {
    /// Check a compiled pattern for potential issues.
    #[must_use]
    pub fn validate(cpat: &CompiledWildcardPattern) -> Self {
        let mut warnings: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        if cpat.len == 0 {
            errors.push("Pattern is empty".to_string());
        }
        if cpat.len < 3 {
            warnings.push(format!(
                "Pattern is very short ({} bytes) — may produce many false positives",
                cpat.len
            ));
        }
        if cpat.wildcard_mask.all_wildcards() {
            errors.push("All bytes are wildcards — will match everything".to_string());
        }
        let spec = cpat.specificity();
        if spec < 0.3 {
            warnings.push(format!(
                "Low specificity ({:.1}%) — consider adding more exact bytes",
                spec * 100.0
            ));
        }
        // Warn if first and last bytes are both wildcards (hard to anchor)
        let first_wc = cpat.wildcard_mask.is_wildcard(0);
        let last_wc = cpat.len > 0 && cpat.wildcard_mask.is_wildcard(cpat.len - 1);
        if first_wc && last_wc && cpat.len > 4 {
            warnings.push("Pattern starts and ends with wildcards — anchoring may be slow".to_string());
        }

        let is_valid = errors.is_empty();
        Self {
            source: cpat.source.clone(),
            warnings,
            errors,
            is_valid,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDifferentiator — find the byte that best distinguishes two patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Find the first position where two compiled wildcard patterns differ.
///
/// Returns `None` if the patterns have different lengths or no differing
/// non-wildcard position exists.
#[must_use]
pub fn first_differing_byte(
    a: &CompiledWildcardPattern,
    b: &CompiledWildcardPattern,
) -> Option<usize> {
    if a.len != b.len {
        return None;
    }
    for i in 0..a.len {
        if !a.wildcard_mask.is_wildcard(i) && !b.wildcard_mask.is_wildcard(i) {
            let av = a.values[i] & a.masks[i];
            let bv = b.values[i] & b.masks[i];
            if av != bv {
                return Some(i);
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Local KMP helper (to avoid cross-module dependency issues)
// ─────────────────────────────────────────────────────────────────────────────

fn kmp_search_local(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    // Build failure function
    let m = needle.len();
    let mut fail = vec![0usize; m];
    let mut k = 0usize;
    for q in 1..m {
        while k > 0 && needle[k] != needle[q] {
            k = fail[k - 1];
        }
        if needle[k] == needle[q] {
            k += 1;
        }
        fail[q] = k;
    }
    // Search
    let mut results = Vec::new();
    let mut q = 0usize;
    for (i, &b) in haystack.iter().enumerate() {
        while q > 0 && needle[q] != b {
            q = fail[q - 1];
        }
        if needle[q] == b {
            q += 1;
        }
        if q == m {
            results.push(i + 1 - m);
            q = fail[q - 1];
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_exact() {
        let cpat = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        assert_eq!(cpat.len, 4);
        assert!(cpat.wildcard_mask.no_wildcards());
        assert_eq!(cpat.values, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cpat.masks, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_compile_full_wildcard() {
        let cpat = WildcardPatternCompiler::compile("? ?").unwrap();
        assert_eq!(cpat.len, 2);
        assert!(cpat.wildcard_mask.all_wildcards());
        assert!(cpat.anchor.is_none());
    }

    #[test]
    fn test_compile_mixed() {
        let cpat = WildcardPatternCompiler::compile("DE ? BE EF").unwrap();
        assert_eq!(cpat.len, 4);
        assert_eq!(cpat.wildcard_mask.wildcard_count(), 1);
        assert!(cpat.wildcard_mask.is_wildcard(1));
        assert!(!cpat.wildcard_mask.is_wildcard(0));
        assert_eq!(cpat.anchor, Some((0, 0xDE)));
    }

    #[test]
    fn test_compile_nibble_high() {
        let cpat = WildcardPatternCompiler::compile("D?").unwrap();
        assert_eq!(cpat.masks[0], 0xF0);
        assert_eq!(cpat.values[0], 0xD0);
        assert!(cpat.wildcard_mask.is_wildcard(0));
    }

    #[test]
    fn test_compile_nibble_low() {
        let cpat = WildcardPatternCompiler::compile("?F").unwrap();
        assert_eq!(cpat.masks[0], 0x0F);
        assert_eq!(cpat.values[0], 0x0F);
        assert!(cpat.wildcard_mask.is_wildcard(0));
    }

    #[test]
    fn test_search_exact() {
        let cpat = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        let data = [0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(cpat.search(&data), vec![1, 6]);
    }

    #[test]
    fn test_search_wildcard() {
        let cpat = WildcardPatternCompiler::compile("DE ? EF").unwrap();
        let data = [0xDE, 0x99, 0xEF, 0x00, 0xDE, 0xAB, 0xEF];
        assert_eq!(cpat.search(&data), vec![0, 4]);
    }

    #[test]
    fn test_matches_true() {
        let cpat = WildcardPatternCompiler::compile("DE ? EF").unwrap();
        let data = [0xDE, 0x00, 0xEF];
        assert!(cpat.matches(&data, 0));
    }

    #[test]
    fn test_matches_false() {
        let cpat = WildcardPatternCompiler::compile("DE AD EF").unwrap();
        let data = [0xDE, 0xFF, 0xEF];
        assert!(!cpat.matches(&data, 0));
    }

    #[test]
    fn test_to_ida_hex_exact() {
        let cpat = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        assert_eq!(cpat.to_ida_hex(), "DE AD BE EF");
    }

    #[test]
    fn test_to_ida_hex_wildcard() {
        let cpat = WildcardPatternCompiler::compile("DE ??").unwrap();
        assert!(cpat.to_ida_hex().contains("??"));
    }

    #[test]
    fn test_specificity() {
        let cpat = WildcardPatternCompiler::compile("AA ? BB").unwrap();
        let spec = cpat.specificity();
        assert!((spec - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_wildcard_mask_display() {
        let cpat = WildcardPatternCompiler::compile("DE ? EF").unwrap();
        let s = cpat.wildcard_mask.to_string();
        assert_eq!(s, ".?."); // 3 bytes, middle is wildcard
    }

    #[test]
    fn test_wildcard_positions() {
        let cpat = WildcardPatternCompiler::compile("AA ?? BB ?? CC").unwrap();
        let wc = cpat.wildcard_mask.wildcard_positions();
        assert_eq!(wc, vec![1, 3]);
    }

    #[test]
    fn test_exact_positions() {
        let cpat = WildcardPatternCompiler::compile("AA ?? BB").unwrap();
        let ep = cpat.wildcard_mask.exact_positions();
        assert_eq!(ep, vec![0, 2]);
    }

    #[test]
    fn test_validation_pass() {
        let cpat = WildcardPatternCompiler::compile("DE AD BE EF 00 11 22 33").unwrap();
        let report = ValidationReport::validate(&cpat);
        assert!(report.is_valid);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_validation_all_wildcards() {
        let cpat = WildcardPatternCompiler::compile("? ? ? ?").unwrap();
        let report = ValidationReport::validate(&cpat);
        assert!(!report.is_valid);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn test_first_differing_byte() {
        let a = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        let b = WildcardPatternCompiler::compile("DE FF BE EF").unwrap();
        assert_eq!(first_differing_byte(&a, &b), Some(1));
    }

    #[test]
    fn test_first_differing_byte_none() {
        let a = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        let b = WildcardPatternCompiler::compile("DE AD BE EF").unwrap();
        assert_eq!(first_differing_byte(&a, &b), None);
    }

    #[test]
    fn test_compile_batch() {
        let batch = WildcardPatternCompiler::compile_batch(&[
            ("dos", "4D 5A"),
            ("elf", "7F 45 4C 46"),
        ])
        .unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].name.as_deref(), Some("dos"));
        assert_eq!(batch[1].len, 4);
    }

    #[test]
    fn test_nibble_mask_byte_mask() {
        let nm = NibbleMask {
            high_exact: true,
            low_exact: false,
        };
        assert_eq!(nm.byte_mask(), 0xF0);
        assert!(nm.is_wildcard());
    }

    #[test]
    fn test_kmp_local() {
        let results = kmp_search_local(b"\x00\xDE\xAD\x00\xDE\xAD", b"\xDE\xAD");
        assert_eq!(results, vec![1, 4]);
    }

    #[test]
    fn test_compile_named() {
        let cpat = WildcardPatternCompiler::compile_named("my_pattern", "AA BB CC").unwrap();
        assert_eq!(cpat.name.as_deref(), Some("my_pattern"));
    }

    #[test]
    fn test_display() {
        let cpat = WildcardPatternCompiler::compile_named("test", "DE AD").unwrap();
        let s = format!("{cpat}");
        assert!(s.contains("test"));
        assert!(s.contains("len=2"));
    }
}
