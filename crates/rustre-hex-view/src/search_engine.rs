//! `search_engine` — Binary search engine for hex view.
//!
//! Provides multiple search strategies over raw byte buffers:
//! - Exact byte pattern search (Boyer-Moore-Horspool)
//! - Hex pattern with wildcards (`xx ?? xx`)
//! - ASCII and UTF-16 string search
//! - XOR-encoded pattern search (tries all 256 XOR keys)
//! - Shift-OR approximate matching

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SearchResult
// ─────────────────────────────────────────────────────────────────────────────

/// A single search hit in the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Byte offset of the match.
    pub offset: usize,
    /// Length of the matched region in bytes.
    pub length: usize,
    /// Which search strategy produced this result.
    pub kind: MatchKind,
    /// Optional XOR key used (for XOR-pattern results).
    pub xor_key: Option<u8>,
}

impl SearchResult {
    /// Create a basic match.
    #[must_use]
    pub const fn new(offset: usize, length: usize, kind: MatchKind) -> Self {
        Self {
            offset,
            length,
            kind,
            xor_key: None,
        }
    }

    /// Create an XOR match.
    #[must_use]
    pub const fn xor(offset: usize, length: usize, key: u8) -> Self {
        Self {
            offset,
            length,
            kind: MatchKind::XorPattern,
            xor_key: Some(key),
        }
    }

    /// Return the byte range as `offset..offset+length`.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.length
    }
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(key) = self.xor_key {
            write!(
                f,
                "{:?} @ {:#010x} len={} xor={:#04x}",
                self.kind, self.offset, self.length, key
            )
        } else {
            write!(
                f,
                "{:?} @ {:#010x} len={}",
                self.kind, self.offset, self.length
            )
        }
    }
}

/// The kind of match strategy that found this result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchKind {
    /// Exact byte sequence.
    Exact,
    /// Wildcard hex pattern (`xx ?? xx`).
    WildcardHex,
    /// ASCII string.
    AsciiString,
    /// UTF-16LE string.
    Utf16String,
    /// XOR-encoded byte pattern.
    XorPattern,
    /// Shift-OR approximate match.
    Approximate,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of pattern the caller wants to search for.
#[derive(Debug, Clone)]
pub enum PatternKind {
    /// Raw byte sequence — exact match.
    Exact(Vec<u8>),
    /// Hex-string with optional `??` wildcards, e.g. `"DE AD ?? EF"`.
    WildcardHex(String),
    /// ASCII string.
    AsciiStr(String),
    /// UTF-16LE string.
    Utf16Str(String),
    /// XOR-encoded exact pattern (tries all 256 single-byte XOR keys).
    XorEncoded(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchPattern — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled search pattern ready for matching.
pub struct SearchPattern {
    inner: PatternKind,
}

impl SearchPattern {
    /// Build from a raw byte slice.
    #[must_use]
    pub fn exact(bytes: &[u8]) -> Self {
        Self {
            inner: PatternKind::Exact(bytes.to_vec()),
        }
    }

    /// Build from a hex-string with optional `??` wildcards.
    /// Accepts `"DE AD ?? EF"` or `"DEAD??EF"` (spaces optional).
    #[must_use]
    pub fn wildcard_hex(pattern: &str) -> Self {
        Self {
            inner: PatternKind::WildcardHex(pattern.to_string()),
        }
    }

    /// Build from an ASCII string.
    #[must_use]
    pub fn ascii(s: &str) -> Self {
        Self {
            inner: PatternKind::AsciiStr(s.to_string()),
        }
    }

    /// Build from a UTF-16LE string.
    #[must_use]
    pub fn utf16(s: &str) -> Self {
        Self {
            inner: PatternKind::Utf16Str(s.to_string()),
        }
    }

    /// Build an XOR-encoded search from a plaintext byte pattern.
    /// All 256 single-byte XOR keys will be tried.
    #[must_use]
    pub fn xor_encoded(bytes: &[u8]) -> Self {
        Self {
            inner: PatternKind::XorEncoded(bytes.to_vec()),
        }
    }

    /// Find all occurrences in `haystack`.
    #[must_use]
    pub fn find_all(&self, haystack: &[u8]) -> Vec<SearchResult> {
        match &self.inner {
            PatternKind::Exact(pat) => bmh_search(haystack, pat),
            PatternKind::WildcardHex(pat) => {
                let parsed = parse_wildcard_hex(pat);
                wildcard_search(haystack, &parsed)
            }
            PatternKind::AsciiStr(s) => {
                let bytes = s.as_bytes();
                let mut results = bmh_search(haystack, bytes);
                for r in &mut results {
                    r.kind = MatchKind::AsciiString;
                }
                results
            }
            PatternKind::Utf16Str(s) => utf16_search(haystack, s),
            PatternKind::XorEncoded(pat) => xor_search(haystack, pat),
        }
    }

    /// Find first occurrence.
    #[must_use]
    pub fn find_first(&self, haystack: &[u8]) -> Option<SearchResult> {
        self.find_all(haystack).into_iter().next()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Boyer-Moore-Horspool
// ─────────────────────────────────────────────────────────────────────────────

/// Boyer-Moore-Horspool search — O(n/m) average case.
/// Returns all occurrences as `SearchResult::Exact`.
#[must_use]
pub fn bmh_search(haystack: &[u8], needle: &[u8]) -> Vec<SearchResult> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return vec![];
    }
    let m = needle.len();
    let n = haystack.len();

    // Build bad-character shift table (256 entries).
    let mut bad_char = [m; 256];
    for (i, &b) in needle[..m - 1].iter().enumerate() {
        bad_char[b as usize] = m - 1 - i;
    }

    let mut results = Vec::new();
    let mut pos = 0usize;

    while pos + m <= n {
        let mut j = m - 1;
        while j > 0 && haystack[pos + j] == needle[j] {
            j -= 1;
        }
        if j == 0 && haystack[pos] == needle[0] {
            results.push(SearchResult::new(pos, m, MatchKind::Exact));
            pos += 1; // allow overlapping matches
        } else {
            let shift = bad_char[haystack[pos + m - 1] as usize];
            pos += shift.max(1);
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Wildcard pattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single token in a wildcard pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WildcardToken {
    /// Exact byte value.
    Byte(u8),
    /// Wildcard (matches any byte).
    Any,
}

/// Parse a hex pattern string with optional `??` wildcards.
/// Ignores whitespace.  Returns a vec of `WildcardToken`.
///
/// If the input has an odd number of nibbles after whitespace removal, the
/// trailing nibble is padded with a low-nibble zero (e.g. `"DE A"` → `[0xDE,
/// 0xA0]`).  Previously the trailing nibble was silently discarded, which
/// caused the returned pattern to be shorter than the caller expected and led
/// to missed or false matches.
#[must_use]
pub fn parse_wildcard_hex(s: &str) -> Vec<WildcardToken> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let mut tokens = Vec::new();
    let chars: Vec<char> = cleaned.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let hi = chars[i];
        // If there is no low nibble, pad with '0' rather than silently
        // dropping the trailing nibble (parser-trailing-data-ignored fix).
        let lo = if i + 1 < chars.len() { chars[i + 1] } else { '0' };
        i += 2;
        if hi == '?' && lo == '?' {
            tokens.push(WildcardToken::Any);
        } else {
            let h = hi.to_digit(16).unwrap_or(0) as u8;
            let l = lo.to_digit(16).unwrap_or(0) as u8;
            tokens.push(WildcardToken::Byte((h << 4) | l));
        }
    }
    tokens
}

/// Search for a wildcard pattern in `haystack`.
/// Returns all matching positions.
#[must_use]
pub fn wildcard_search(haystack: &[u8], pattern: &[WildcardToken]) -> Vec<SearchResult> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return vec![];
    }
    let m = pattern.len();
    let n = haystack.len();
    let mut results = Vec::new();

    'outer: for start in 0..=n - m {
        for (j, &tok) in pattern.iter().enumerate() {
            match tok {
                WildcardToken::Byte(b) if haystack[start + j] != b => continue 'outer,
                _ => {}
            }
        }
        results.push(SearchResult::new(start, m, MatchKind::WildcardHex));
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// WildcardMatcher — compiled for repeated use
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled wildcard pattern matcher for reuse across multiple buffers.
pub struct WildcardMatcher {
    tokens: Vec<WildcardToken>,
}

impl WildcardMatcher {
    /// Compile a wildcard pattern from a hex string.
    #[must_use]
    pub fn compile(pattern: &str) -> Self {
        Self {
            tokens: parse_wildcard_hex(pattern),
        }
    }

    /// Returns `true` if `data` (slice of exact length) matches.
    #[must_use]
    pub fn matches_slice(&self, data: &[u8]) -> bool {
        if data.len() != self.tokens.len() {
            return false;
        }
        for (i, &tok) in self.tokens.iter().enumerate() {
            if let WildcardToken::Byte(b) = tok
                && data[i] != b {
                    return false;
                }
        }
        true
    }

    /// Find all occurrences of this pattern in `haystack`.
    #[must_use]
    pub fn find_all(&self, haystack: &[u8]) -> Vec<SearchResult> {
        wildcard_search(haystack, &self.tokens)
    }

    /// Return the pattern length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTF-16LE string search
// ─────────────────────────────────────────────────────────────────────────────

/// Search for a UTF-16LE encoded string in `haystack`.
#[must_use]
pub fn utf16_search(haystack: &[u8], s: &str) -> Vec<SearchResult> {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    if utf16.is_empty() {
        return vec![];
    }
    let raw = bmh_search(haystack, &utf16);
    raw.into_iter()
        .map(|mut r| {
            r.kind = MatchKind::Utf16String;
            r
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// XorSearch — tries all 256 single-byte XOR keys
// ─────────────────────────────────────────────────────────────────────────────

/// XOR-encoded pattern search: for each key 0x00–0xFF, XOR-decode the pattern
/// and search for it.  Key 0x00 is the unencoded (plaintext) case.
pub struct XorSearch {
    plaintext: Vec<u8>,
}

impl XorSearch {
    /// Create from a plaintext pattern.
    #[must_use]
    pub fn new(plaintext: &[u8]) -> Self {
        Self {
            plaintext: plaintext.to_vec(),
        }
    }

    /// Find all occurrences trying all 256 XOR keys.
    #[must_use]
    pub fn find_all(&self, haystack: &[u8]) -> Vec<SearchResult> {
        xor_search(haystack, &self.plaintext)
    }

    /// Find all occurrences for a specific XOR key.
    #[must_use]
    pub fn find_with_key(&self, haystack: &[u8], key: u8) -> Vec<SearchResult> {
        let encoded: Vec<u8> = self.plaintext.iter().map(|&b| b ^ key).collect();
        let raw = bmh_search(haystack, &encoded);
        raw.into_iter().map(|r| SearchResult::xor(r.offset, r.length, key)).collect()
    }
}

/// Inner function: search for all XOR-encoded occurrences of `plaintext` in `haystack`.
///
/// To prevent memory exhaustion when scanning large buffers with short patterns
/// (up to 256 keys × `haystack_len` hits), the total number of results is capped
/// at `MAX_XOR_RESULTS`.  Callers that need more results should iterate keys
/// themselves and apply a per-key limit.
#[must_use]
pub fn xor_search(haystack: &[u8], plaintext: &[u8]) -> Vec<SearchResult> {
    if plaintext.is_empty() {
        return vec![];
    }
    // Safety cap: 256 keys × up to ~4M haystack positions = potential GBs of
    // allocations.  Cap prevents DoS when the caller does not supply max_hits.
    const MAX_XOR_RESULTS: usize = 65_536;
    let mut results = Vec::new();
    'outer: for key in 0u8..=255 {
        let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        for hit in bmh_search(haystack, &encoded) {
            results.push(SearchResult::xor(hit.offset, hit.length, key));
            if results.len() >= MAX_XOR_RESULTS {
                break 'outer;
            }
        }
    }
    // Sort by offset, then by key for determinism.
    results.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.xor_key.cmp(&b.xor_key)));
    // Deduplicate: keep only unique (offset, key) pairs.
    results.dedup_by(|a, b| a.offset == b.offset && a.xor_key == b.xor_key);
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// ASCII string scanner (all printable runs ≥ min_len)
// ─────────────────────────────────────────────────────────────────────────────

/// Find all contiguous printable-ASCII runs of at least `min_len` bytes.
#[must_use]
pub fn scan_ascii_strings(haystack: &[u8], min_len: usize) -> Vec<SearchResult> {
    if min_len == 0 {
        return vec![];
    }
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in haystack.iter().enumerate() {
        let printable = b.is_ascii_graphic() || b == b' ' || b == b'\t';
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                let len = i - s;
                if len >= min_len {
                    results.push(SearchResult::new(s, len, MatchKind::AsciiString));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let len = haystack.len() - s;
        if len >= min_len {
            results.push(SearchResult::new(s, len, MatchKind::AsciiString));
        }
    }

    results
}

/// Find all contiguous UTF-16LE printable runs of at least `min_chars` characters.
#[must_use]
pub fn scan_utf16_strings(haystack: &[u8], min_chars: usize) -> Vec<SearchResult> {
    if min_chars == 0 || haystack.len() < 2 {
        return vec![];
    }
    let mut results = Vec::new();
    let mut start: Option<usize> = None;
    let mut count = 0usize;

    let mut i = 0;
    while i + 1 < haystack.len() {
        let lo = haystack[i];
        let hi = haystack[i + 1];
        let cp = u16::from_le_bytes([lo, hi]);
        let printable = (0x20..0x7F).contains(&cp);
        match (printable, start) {
            (true, None) => {
                start = Some(i);
                count = 1;
            }
            (true, Some(_)) => count += 1,
            (false, Some(s)) => {
                if count >= min_chars {
                    results.push(SearchResult::new(s, count * 2, MatchKind::Utf16String));
                }
                start = None;
                count = 0;
            }
            _ => {}
        }
        i += 2;
    }
    if let Some(s) = start
        && count >= min_chars {
            results.push(SearchResult::new(s, count * 2, MatchKind::Utf16String));
        }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Shift-OR approximate matcher
// ─────────────────────────────────────────────────────────────────────────────

/// Shift-OR (Baeza-Yates/Gonnet) exact pattern matcher.
/// Efficient for patterns up to 64 bytes (uses u64 bitmask).
/// Returns all starting offsets.
#[must_use]
pub fn shift_or_search(haystack: &[u8], needle: &[u8]) -> Vec<SearchResult> {
    let m = needle.len();
    if m == 0 || m > 64 || haystack.len() < m {
        return vec![];
    }

    // Build the character mask table using the inverted-mask Shift-OR convention:
    // mask[c] has bit i CLEAR when needle[i] == c, and SET otherwise.
    let mut mask = [!0u64; 256];
    for (i, &b) in needle.iter().enumerate() {
        mask[b as usize] &= !(1u64 << i);
    }

    // accept bit is at position (m-1); a match is detected when that bit is 0.
    let accept = 1u64 << (m - 1);
    // d starts as all-ones (no bits active).
    let mut d = !0u64;
    let mut results = Vec::new();

    for (i, &b) in haystack.iter().enumerate() {
        // Standard Shift-OR update: shift active bits left (introducing a 1 at bit 0),
        // then mask against the character class (clearing bits where needle[j] != b).
        d = (d << 1) | 1;
        d &= mask[b as usize];
        if (d & accept) == 0 {
            let start = i + 1 - m;
            results.push(SearchResult::new(start, m, MatchKind::Approximate));
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Frequency-indexed search (fast rejection by byte frequency)
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-computed byte frequency index for a buffer.
/// Used to accelerate searches by skipping positions that cannot match.
pub struct FrequencyIndex {
    /// Maps byte value → list of offsets where it appears.
    offsets: HashMap<u8, Vec<usize>>,
}

impl FrequencyIndex {
    /// Build the index from a buffer.
    #[must_use]
    pub fn build(data: &[u8]) -> Self {
        let mut offsets: HashMap<u8, Vec<usize>> = HashMap::new();
        for (i, &b) in data.iter().enumerate() {
            offsets.entry(b).or_default().push(i);
        }
        Self { offsets }
    }

    /// Return all offsets where `byte` appears.
    #[must_use]
    pub fn positions_of(&self, byte: u8) -> &[usize] {
        self.offsets.get(&byte).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Count occurrences of `byte`.
    #[must_use]
    pub fn count(&self, byte: u8) -> usize {
        self.offsets.get(&byte).map_or(0, Vec::len)
    }

    /// Returns `true` if `byte` appears in the indexed buffer.
    #[must_use]
    pub fn contains(&self, byte: u8) -> bool {
        self.offsets.contains_key(&byte)
    }

    /// Fast exact search using the rarest byte in `needle` as a pre-filter.
    /// Falls back to BMH if index does not contain any byte of the needle.
    #[must_use]
    pub fn search_exact(&self, haystack: &[u8], needle: &[u8]) -> Vec<SearchResult> {
        if needle.is_empty() {
            return vec![];
        }

        // Find the rarest byte in the needle.
        let (rare_idx, rare_byte) = needle
            .iter()
            .enumerate()
            .min_by_key(|&(_, &b)| self.count(b))
            .map(|(i, &b)| (i, b))
            .unwrap();

        let candidate_positions = self.positions_of(rare_byte);
        let m = needle.len();
        let mut results = Vec::new();

        for &pos in candidate_positions {
            if pos < rare_idx {
                continue;
            }
            let start = pos - rare_idx;
            if start + m > haystack.len() {
                continue;
            }
            if haystack[start..start + m] == *needle {
                results.push(SearchResult::new(start, m, MatchKind::Exact));
            }
        }

        results.sort_by_key(|r| r.offset);
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex pattern builder helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a byte slice as a wildcard hex pattern string (no wildcards).
#[must_use]
pub fn bytes_to_hex_pattern(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a wildcard token slice as a human-readable string.
#[must_use]
pub fn tokens_to_string(tokens: &[WildcardToken]) -> String {
    tokens
        .iter()
        .map(|t| match t {
            WildcardToken::Byte(b) => format!("{b:02X}"),
            WildcardToken::Any => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BMH ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_bmh_basic() {
        let hay = b"ABCDEFABCABC";
        let results = bmh_search(hay, b"ABC");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 6);
        assert_eq!(results[2].offset, 9);
    }

    #[test]
    fn test_bmh_not_found() {
        let results = bmh_search(b"AAAAAA", b"BB");
        assert!(results.is_empty());
    }

    #[test]
    fn test_bmh_needle_longer_than_hay() {
        let results = bmh_search(b"AB", b"ABCDE");
        assert!(results.is_empty());
    }

    #[test]
    fn test_bmh_single_byte() {
        let hay = b"ABCABC";
        let results = bmh_search(hay, b"A");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_bmh_overlapping() {
        let hay = b"AAAA";
        let results = bmh_search(hay, b"AA");
        assert_eq!(results.len(), 3); // positions 0, 1, 2
    }

    // ── Wildcard ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_wildcard_basic() {
        let tokens = parse_wildcard_hex("DE AD ?? EF");
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], WildcardToken::Byte(0xDE));
        assert_eq!(tokens[1], WildcardToken::Byte(0xAD));
        assert_eq!(tokens[2], WildcardToken::Any);
        assert_eq!(tokens[3], WildcardToken::Byte(0xEF));
    }

    #[test]
    fn test_wildcard_search_match() {
        let hay = [0xDE, 0xAD, 0x42, 0xEF, 0x00];
        let tokens = parse_wildcard_hex("DE AD ?? EF");
        let results = wildcard_search(&hay, &tokens);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_wildcard_search_no_match() {
        let hay = [0xDE, 0xAD, 0x42, 0xFF, 0x00];
        let tokens = parse_wildcard_hex("DE AD ?? EF");
        let results = wildcard_search(&hay, &tokens);
        assert!(results.is_empty());
    }

    #[test]
    fn test_wildcard_matcher_matches_slice() {
        let m = WildcardMatcher::compile("CA FE ?? BA");
        assert!(m.matches_slice(&[0xCA, 0xFE, 0x99, 0xBA]));
        assert!(!m.matches_slice(&[0xCA, 0xFE, 0x99, 0xFF]));
    }

    // ── UTF-16 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_utf16_search_basic() {
        let text = "Hello";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let hay = [&[0x00u8, 0x00][..], &utf16[..], &[0x00, 0x00][..]].concat();
        let results = utf16_search(&hay, "Hello");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, MatchKind::Utf16String);
        assert_eq!(results[0].length, 10); // 5 chars × 2 bytes
    }

    #[test]
    fn test_utf16_search_not_found() {
        let results = utf16_search(b"Hello World", "XY");
        assert!(results.is_empty());
    }

    // ── XOR search ───────────────────────────────────────────────────────────

    #[test]
    fn test_xor_search_key_zero_is_plaintext() {
        let plain = b"MZ";
        let hay = b"XXMZXX";
        let results = xor_search(hay, plain);
        // Key 0x00 should find position 2
        let key0: Vec<_> = results.iter().filter(|r| r.xor_key == Some(0)).collect();
        assert!(!key0.is_empty());
        assert_eq!(key0[0].offset, 2);
    }

    #[test]
    fn test_xor_search_encoded() {
        let plain = &[0x41u8, 0x42]; // "AB"
        // Encode with key 0x10: [0x51, 0x52]
        let hay = &[0x00u8, 0x51, 0x52, 0xFF];
        let results = xor_search(hay, plain);
        let k10: Vec<_> = results.iter().filter(|r| r.xor_key == Some(0x10)).collect();
        assert!(!k10.is_empty());
        assert_eq!(k10[0].offset, 1);
    }

    #[test]
    fn test_xor_search_with_key() {
        let xs = XorSearch::new(b"AB");
        // Encode with key 0x05: A^5=D(0x44), B^5=G(0x47)
        let hay = &[0x00u8, 0x44, 0x47, 0xFF];
        let results = xs.find_with_key(hay, 0x05);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[0].xor_key, Some(0x05));
    }

    // ── ASCII scanner ─────────────────────────────────────────────────────────

    #[test]
    fn test_scan_ascii_strings_basic() {
        let data = b"\x00Hello World\x00\x01AB\x00";
        let results = scan_ascii_strings(data, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[0].length, 11); // "Hello World"
    }

    #[test]
    fn test_scan_ascii_strings_min_len_filter() {
        let data = b"\x00AB\x00Hello\x00";
        let results = scan_ascii_strings(data, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].length, 5); // "Hello"
    }

    #[test]
    fn test_scan_utf16_strings() {
        let text = "Hi";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let hay = [&[0x00u8, 0x00][..], &utf16, &[0x00u8, 0x00][..]].concat();
        let results = scan_utf16_strings(&hay, 2);
        assert_eq!(results.len(), 1);
    }

    // ── Shift-OR ─────────────────────────────────────────────────────────────

    #[test]
    fn test_shift_or_basic() {
        let hay = b"ABCDEABCDE";
        let results = shift_or_search(hay, b"BCD");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[1].offset, 6);
    }

    #[test]
    fn test_shift_or_not_found() {
        let results = shift_or_search(b"AAAAAA", b"B");
        assert!(results.is_empty());
    }

    #[test]
    fn test_shift_or_too_long() {
        let needle = vec![0u8; 65];
        let hay = vec![0u8; 100];
        let results = shift_or_search(&hay, &needle);
        assert!(results.is_empty());
    }

    // ── FrequencyIndex ────────────────────────────────────────────────────────

    #[test]
    fn test_freq_index_count() {
        let data = b"AABABC";
        let idx = FrequencyIndex::build(data);
        assert_eq!(idx.count(b'A'), 3);
        assert_eq!(idx.count(b'B'), 2);
        assert_eq!(idx.count(b'C'), 1);
        assert_eq!(idx.count(b'Z'), 0);
    }

    #[test]
    fn test_freq_index_search_exact() {
        let data = b"ABCABCABC";
        let idx = FrequencyIndex::build(data);
        let results = idx.search_exact(data, b"ABC");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_freq_index_search_not_found() {
        let data = b"AAABBB";
        let idx = FrequencyIndex::build(data);
        let results = idx.search_exact(data, b"CC");
        assert!(results.is_empty());
    }

    // ── SearchPattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_search_pattern_exact() {
        // SearchPattern::exact takes raw bytes; b"DE" is ASCII 0x44 0x45, so use the literal 0xDE byte.
        let pat = SearchPattern::exact(&[0xDEu8]);
        let hay = [0xDE, 0xAD, 0xDE, 0xEF];
        let results = pat.find_all(&hay);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 2);
    }

    #[test]
    fn test_search_pattern_ascii() {
        let pat = SearchPattern::ascii("MZ");
        let hay = b"MZheaderMZend";
        let results = pat.find_all(hay);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].kind, MatchKind::AsciiString);
    }

    #[test]
    fn test_search_pattern_wildcard() {
        let pat = SearchPattern::wildcard_hex("CA ?? BA BE");
        let hay = [0xCA, 0xFE, 0xBA, 0xBE, 0xFF];
        let results = pat.find_all(&hay);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, MatchKind::WildcardHex);
    }

    #[test]
    fn test_search_pattern_find_first() {
        let pat = SearchPattern::exact(b"PE");
        let hay = b"\x00\x00PE\x00PE";
        let result = pat.find_first(hay).unwrap();
        assert_eq!(result.offset, 2);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn test_bytes_to_hex_pattern() {
        let s = bytes_to_hex_pattern(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(s, "DE AD BE EF");
    }

    #[test]
    fn test_tokens_to_string() {
        let tokens = vec![
            WildcardToken::Byte(0xDE),
            WildcardToken::Any,
            WildcardToken::Byte(0xEF),
        ];
        assert_eq!(tokens_to_string(&tokens), "DE ?? EF");
    }
}
