//! `stack_string_decoder` — Decode stack-allocated strings built by sequential
//! single-byte stores on the stack.
//!
//! Stack strings are a common anti-disassembly / anti-emulation technique where
//! a string is never stored as a contiguous literal; instead it is assembled
//! byte-by-byte into a stack buffer at runtime.  This module reconstructs those
//! strings from a stream of (`stack_offset`, `byte_value`) observations.
//!
//! # Layer distinction — three stack-string modules
//! The crate contains three modules that all deal with stack strings, each at a
//! different level of abstraction:
//!
//! | Module | Focus |
//! |--------|-------|
//! | **`stack_string_decoder`** (this module) | Lowest-level: accepts raw `(offset, byte)` pairs via [`CharPush`], groups them in a [`BTreeMap`], and emits [`StackString`] runs.  Portable, no IL dependency. |
//! | [`crate::stack_string_reconstructor`] | Mid-level: adds x86 MOV-pattern parsing from raw code bytes, multi-byte (DWORD) stores, UTF-16 reconstruction, and configurable gap tolerance via [`crate::stack_string_reconstructor::StackStringRecon`]. |
//! | [`crate::stack_string_recovery`] | High-level: accepts abstract [`crate::stack_string_recovery::ByteAssignment`] records from lifted IL, groups by frame-register region, and provides a [`crate::stack_string_recovery::PseudocodeRewriter`] that substitutes recovered strings back into pseudocode. |

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── CharPush ─────────────────────────────────────────────────────────────────

/// One observed byte-store into a stack buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharPush {
    /// Stack offset (relative to the frame base or RSP) in bytes.
    pub offset: i64,
    /// The byte value being written.
    pub byte: u8,
}

impl CharPush {
    /// Create a new `CharPush`.
    #[must_use]
    pub const fn new(offset: i64, byte: u8) -> Self {
        Self { offset, byte }
    }

    /// Returns `true` when this is a null-terminator write.
    #[must_use]
    pub const fn is_null_terminator(&self) -> bool {
        self.byte == 0
    }
}

impl fmt::Display for CharPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:+}] = 0x{:02X} ('{}')", self.offset, self.byte, {
            let c = char::from(self.byte);
            if c.is_ascii_graphic() || c == ' ' { c } else { '.' }
        })
    }
}

// ─── StackString ──────────────────────────────────────────────────────────────

/// A stack string reconstructed from a sequence of [`CharPush`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackString {
    /// Base stack offset where the string starts.
    pub base_offset: i64,
    /// Raw bytes in order (null-terminator stripped if present).
    pub bytes: Vec<u8>,
    /// UTF-8 decoded value, if the bytes are valid UTF-8.
    pub text: Option<String>,
    /// Whether a null-terminator write was observed at the end.
    pub null_terminated: bool,
}

impl StackString {
    /// Build from a sorted, contiguous run of [`CharPush`]s.
    ///
    /// The first push defines `base_offset`.  If the last byte written is 0 it
    /// is treated as a null-terminator and excluded from `bytes`.
    #[must_use]
    pub fn from_pushes(pushes: &[CharPush]) -> Option<Self> {
        if pushes.is_empty() {
            return None;
        }
        let base_offset = pushes[0].offset;
        let null_terminated = pushes.last().map_or(false, |p| p.is_null_terminator());
        let raw: Vec<u8> = pushes
            .iter()
            .filter(|p| !p.is_null_terminator())
            .map(|p| p.byte)
            .collect();
        if raw.is_empty() {
            return None;
        }
        let text = String::from_utf8(raw.clone()).ok();
        Some(Self {
            base_offset,
            bytes: raw,
            text,
            null_terminated,
        })
    }

    /// Byte length of the reconstructed string (not counting null-terminator).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when no bytes were reconstructed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Printable ratio of the reconstructed bytes.
    #[must_use]
    pub fn printable_ratio(&self) -> f64 {
        if self.bytes.is_empty() {
            return 0.0;
        }
        let printable = self
            .bytes
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        printable as f64 / self.bytes.len() as f64
    }

    /// Returns `true` when the text looks like a genuine ASCII string (>= 80 %
    /// printable, >= 4 characters).
    #[must_use]
    pub fn is_plausible_string(&self) -> bool {
        self.bytes.len() >= 4 && self.printable_ratio() >= 0.80
    }

    /// Hex representation of the bytes.
    #[must_use]
    pub fn hex(&self) -> String {
        self.bytes
            .iter()
            .fold(String::new(), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{b:02x}"); s })
    }
}

impl fmt::Display for StackString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(text) = &self.text {
            write!(f, "{text:?}")
        } else {
            write!(f, "<bytes: {}>", self.hex())
        }
    }
}

// ─── StackStringDecoder ───────────────────────────────────────────────────────

/// Reconstructs stack strings from a stream of observed [`CharPush`]s.
///
/// # Algorithm
/// 1. All pushes are accumulated in a `BTreeMap<offset, byte>`.
/// 2. On `decode()`, the map is scanned for *contiguous runs* of offsets.
/// 3. Any run of ≥ `min_length` bytes is emitted as a [`StackString`].
#[derive(Debug, Clone)]
pub struct StackStringDecoder {
    /// Minimum string length in bytes (default: 4).
    pub min_length: usize,
    /// Maximum gap between two consecutive offsets allowed within one string.
    /// Zero means strictly consecutive (default).
    pub max_gap: u32,
    /// Minimum printable ratio required (default: 0.0 = accept any).
    pub min_printable_ratio: f64,
    /// Accumulated byte store observations.
    stores: BTreeMap<i64, u8>,
}

impl Default for StackStringDecoder {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_gap: 0,
            min_printable_ratio: 0.0,
            stores: BTreeMap::new(),
        }
    }
}

impl StackStringDecoder {
    /// Create a decoder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum string length.
    #[must_use]
    pub const fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    /// Allow small gaps within a string (useful for struct padding).
    #[must_use]
    pub const fn with_max_gap(mut self, gap: u32) -> Self {
        self.max_gap = gap;
        self
    }

    /// Set the minimum printable ratio.
    #[must_use]
    pub const fn with_min_printable_ratio(mut self, ratio: f64) -> Self {
        // `clamp` propagates NaN; a NaN ratio rejects every candidate in
        // silence, because all comparisons against NaN are false.
        self.min_printable_ratio = if ratio.is_nan() { 0.0 } else { ratio.clamp(0.0, 1.0) };
        self
    }

    /// Record a single byte store observation.
    pub fn push(&mut self, cp: CharPush) {
        self.stores.insert(cp.offset, cp.byte);
    }

    /// Record multiple observations at once.
    pub fn push_all(&mut self, pushes: &[CharPush]) {
        for &p in pushes {
            self.push(p);
        }
    }

    /// Clear all accumulated observations.
    pub fn reset(&mut self) {
        self.stores.clear();
    }

    /// Number of accumulated observations.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.stores.len()
    }

    /// Decode accumulated observations into [`StackString`]s.
    ///
    /// Observations are processed in offset order; contiguous runs (within
    /// `max_gap`) are grouped into candidate strings.
    #[must_use]
    pub fn decode(&self) -> Vec<StackString> {
        decode_stack_string(&self.stores, self.min_length, self.max_gap, self.min_printable_ratio)
    }

    /// Decode a *provided* set of [`CharPush`]s without storing them.
    #[must_use]
    pub fn decode_pushes(&self, pushes: &[CharPush]) -> Vec<StackString> {
        let mut map: BTreeMap<i64, u8> = BTreeMap::new();
        for &p in pushes {
            map.insert(p.offset, p.byte);
        }
        decode_stack_string(&map, self.min_length, self.max_gap, self.min_printable_ratio)
    }

    /// Decode and filter to only plausible strings.
    #[must_use]
    pub fn decode_plausible(&self) -> Vec<StackString> {
        self.decode()
            .into_iter()
            .filter(StackString::is_plausible_string)
            .collect()
    }
}

/// Core decoding algorithm: split a `BTreeMap<offset, byte>` into contiguous
/// runs and convert each qualifying run into a [`StackString`].
///
/// This is the primary free function exposed by the module per the spec.
#[must_use]
pub fn decode_stack_string(
    stores: &BTreeMap<i64, u8>,
    min_length: usize,
    max_gap: u32,
    min_printable_ratio: f64,
) -> Vec<StackString> {
    if stores.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut run: Vec<CharPush> = Vec::new();
    let mut prev_offset: Option<i64> = None;

    for (&offset, &byte) in stores {
        let contiguous = match prev_offset {
            None => true,
            Some(prev) => {
                let gap = offset.saturating_sub(prev + 1);
                gap >= 0 && gap <= i64::from(max_gap)
            }
        };

        if !contiguous {
            // Flush the current run.
            if run.len() >= min_length {
                if let Some(ss) = StackString::from_pushes(&run) {
                    if ss.printable_ratio() >= min_printable_ratio {
                        results.push(ss);
                    }
                }
            }
            run.clear();
        }

        run.push(CharPush::new(offset, byte));
        prev_offset = Some(offset);
    }

    // Flush final run.
    if run.len() >= min_length {
        if let Some(ss) = StackString::from_pushes(&run) {
            if ss.printable_ratio() >= min_printable_ratio {
                results.push(ss);
            }
        }
    }

    results
}

// ─── Batch helpers ────────────────────────────────────────────────────────────

/// Run a batch of independent decoder sessions — one per provided push list.
///
/// Useful when a function has multiple independent stack-string buffers.
#[must_use]
pub fn batch_decode(
    push_groups: &[Vec<CharPush>],
    min_length: usize,
    max_gap: u32,
) -> Vec<Vec<StackString>> {
    let decoder = StackStringDecoder::new()
        .with_min_length(min_length)
        .with_max_gap(max_gap);
    push_groups
        .iter()
        .map(|group| decoder.decode_pushes(group))
        .collect()
}

/// Detect whether a set of pushes likely constructs a stack string:
/// requires ≥ `min_count` consecutive byte writes with printable values.
#[must_use]
pub fn is_likely_stack_string(pushes: &[CharPush], min_count: usize) -> bool {
    if pushes.len() < min_count {
        return false;
    }
    let printable = pushes
        .iter()
        .filter(|p| p.byte.is_ascii_graphic() || p.byte == b' ' || p.byte == 0)
        .count();
    printable >= min_count && {
        // Verify contiguousness.
        let mut sorted = pushes.to_vec();
        sorted.sort_by_key(|p| p.offset);
        sorted
            .windows(2)
            .all(|w| w[1].offset == w[0].offset + 1)
    }
}

/// Reconstruct a string from a sorted, contiguous slice of byte values (no
/// offsets required — the caller guarantees ordering).
#[must_use]
pub fn reconstruct_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    // Strip null terminator if present.
    let stripped = if bytes.last().copied() == Some(0) {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    String::from_utf8(stripped.to_vec()).ok()
}

/// Estimate the number of characters in a stack string by counting non-null
/// byte writes at consecutive offsets starting from `base_offset`.
#[must_use]
pub fn count_chars_from(pushes: &[CharPush], base_offset: i64) -> usize {
    let mut count = 0usize;
    let mut expected = base_offset;
    for p in pushes.iter().filter(|p| p.offset >= base_offset) {
        if p.offset == expected && p.byte != 0 {
            count += 1;
            expected += 1;
        } else if p.offset > expected {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pushes(data: &[(i64, u8)]) -> Vec<CharPush> {
        data.iter().map(|&(o, b)| CharPush::new(o, b)).collect()
    }

    #[test]
    fn test_char_push_display() {
        let p = CharPush::new(4, b'A');
        assert!(p.to_string().contains("0x41"));
    }

    #[test]
    fn test_char_push_null_terminator() {
        assert!(CharPush::new(0, 0).is_null_terminator());
        assert!(!CharPush::new(0, b'a').is_null_terminator());
    }

    #[test]
    fn test_decode_simple_hello() {
        let ps = pushes(&[(0, b'h'), (1, b'e'), (2, b'l'), (3, b'l'), (4, b'o'), (5, 0)]);
        let decoder = StackStringDecoder::new().with_min_length(4);
        let results = decoder.decode_pushes(&ps);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text.as_deref(), Some("hello"));
        assert!(results[0].null_terminated);
    }

    #[test]
    fn test_decode_no_null_terminator() {
        let ps = pushes(&[(0, b'f'), (1, b'o'), (2, b'o'), (3, b'!')]);
        let decoder = StackStringDecoder::new().with_min_length(4);
        let results = decoder.decode_pushes(&ps);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text.as_deref(), Some("foo!"));
        assert!(!results[0].null_terminated);
    }

    #[test]
    fn test_decode_two_strings() {
        // Two separate strings with a gap.
        let ps = pushes(&[
            (0, b'a'), (1, b'b'), (2, b'c'), (3, b'd'),
            (20, b'x'), (21, b'y'), (22, b'z'), (23, b'!'),
        ]);
        let decoder = StackStringDecoder::new().with_min_length(4);
        let results = decoder.decode_pushes(&ps);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_decode_too_short() {
        let ps = pushes(&[(0, b'h'), (1, b'i')]);
        let decoder = StackStringDecoder::new().with_min_length(4);
        let results = decoder.decode_pushes(&ps);
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_with_gap() {
        let ps = pushes(&[
            (0, b't'), (1, b'e'), (2, b's'), (3, b't'),
            (5, b'i'), (6, b'n'), (7, b'g'), // gap of 1 at offset 4
        ]);
        let decoder = StackStringDecoder::new()
            .with_min_length(4)
            .with_max_gap(1);
        let results = decoder.decode_pushes(&ps);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_decode_accumulate() {
        let mut decoder = StackStringDecoder::new().with_min_length(4);
        decoder.push(CharPush::new(0, b's'));
        decoder.push(CharPush::new(1, b'e'));
        decoder.push(CharPush::new(2, b'c'));
        decoder.push(CharPush::new(3, b'r'));
        decoder.push(CharPush::new(4, b'e'));
        decoder.push(CharPush::new(5, b't'));
        let results = decoder.decode();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text.as_deref(), Some("secret"));
    }

    #[test]
    fn test_stack_string_plausible() {
        let ps = pushes(&[(0, b'p'), (1, b'a'), (2, b's'), (3, b's'), (4, b'w'), (5, b'd')]);
        let decoder = StackStringDecoder::new().with_min_length(4);
        let results = decoder.decode_pushes(&ps);
        assert!(results[0].is_plausible_string());
    }

    #[test]
    fn test_stack_string_hex() {
        let ss = StackString {
            base_offset: 0,
            bytes: vec![0xDE, 0xAD],
            text: None,
            null_terminated: false,
        };
        assert_eq!(ss.hex(), "dead");
    }

    #[test]
    fn test_is_likely_stack_string_true() {
        let ps = pushes(&[(0, b'h'), (1, b'e'), (2, b'l'), (3, b'l'), (4, b'o')]);
        assert!(is_likely_stack_string(&ps, 4));
    }

    #[test]
    fn test_is_likely_stack_string_false_gaps() {
        let ps = pushes(&[(0, b'a'), (2, b'b'), (4, b'c'), (6, b'd')]);
        assert!(!is_likely_stack_string(&ps, 4));
    }

    #[test]
    fn test_reconstruct_from_bytes_basic() {
        let bytes = b"hello\0";
        assert_eq!(reconstruct_from_bytes(bytes), Some("hello".to_string()));
    }

    #[test]
    fn test_reconstruct_from_bytes_no_null() {
        let bytes = b"world";
        assert_eq!(reconstruct_from_bytes(bytes), Some("world".to_string()));
    }

    #[test]
    fn test_reconstruct_from_bytes_empty() {
        assert!(reconstruct_from_bytes(&[]).is_none());
    }

    #[test]
    fn test_count_chars_from() {
        let ps = pushes(&[(0, b'a'), (1, b'b'), (2, b'c'), (3, 0), (4, b'd')]);
        assert_eq!(count_chars_from(&ps, 0), 3);
    }

    #[test]
    fn test_batch_decode() {
        let group1 = pushes(&[(0, b'f'), (1, b'o'), (2, b'o'), (3, b'!')]);
        let group2 = pushes(&[(0, b'b'), (1, b'a'), (2, b'r'), (3, b'?')]);
        let results = batch_decode(&[group1, group2], 4, 0);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0][0].text.as_deref(), Some("foo!"));
        assert_eq!(results[1][0].text.as_deref(), Some("bar?"));
    }

    #[test]
    fn test_decode_plausible_filters_binary() {
        let mut decoder = StackStringDecoder::new()
            .with_min_length(4)
            .with_min_printable_ratio(0.8);
        // Binary garbage
        decoder.push_all(&pushes(&[(0, 0xFF), (1, 0xFE), (2, 0xFD), (3, 0xFC)]));
        // ASCII string
        decoder.push_all(&pushes(&[(10, b't'), (11, b'e'), (12, b's'), (13, b't')]));
        let results = decoder.decode_plausible();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text.as_deref(), Some("test"));
    }

    #[test]
    fn test_decoder_reset() {
        let mut decoder = StackStringDecoder::new().with_min_length(4);
        decoder.push_all(&pushes(&[(0, b'a'), (1, b'b'), (2, b'c'), (3, b'd')]));
        assert_eq!(decoder.observation_count(), 4);
        decoder.reset();
        assert_eq!(decoder.observation_count(), 0);
    }
}
