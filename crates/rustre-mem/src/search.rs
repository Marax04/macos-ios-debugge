//! Memory search: pattern matching, string search, regex-like wildcard matching,
//! and Boyer-Moore-Horspool acceleration for byte-pattern scanning.

use crate::memory_provider::{MemError, MemoryProvider};
use rustre_core::address::{Address, AddressRange};

// ─────────────────────────────────────────────────────────────────────────────
// PatternByte — one byte in a search pattern
// ─────────────────────────────────────────────────────────────────────────────

/// One element in a byte-pattern search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    /// Match this exact byte value.
    Exact(u8),
    /// Match any byte (wildcard, the `??` idiom in IDApython-style patterns).
    Wild,
    /// Match `byte & mask == value & mask`.
    Masked { value: u8, mask: u8 },
}

impl PatternByte {
    /// Returns `true` if `byte` satisfies this pattern element.
    #[must_use]
    #[inline]
    pub const fn matches(self, byte: u8) -> bool {
        match self {
            Self::Exact(v) => byte == v,
            Self::Wild => true,
            Self::Masked { value, mask } => (byte & mask) == (value & mask),
        }
    }

    /// Returns `true` when this element will match any byte.
    #[must_use]
    pub const fn is_wild(self) -> bool {
        matches!(self, Self::Wild)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BytePattern — a sequence of `PatternByte`s
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled byte pattern ready for scanning.
#[derive(Debug, Clone)]
pub struct BytePattern {
    bytes: Vec<PatternByte>,
    /// Bad-character skip table (only valid if `has_exact_bytes == true`).
    skip: [usize; 256],
    /// Whether any non-wild element exists (determines skip-table usefulness).
    has_exact_bytes: bool,
}

impl BytePattern {
    /// Build a pattern from a slice of `PatternByte` values.
    ///
    /// # Panics
    /// Panics if `bytes` is empty.
    #[must_use]
    pub fn new(bytes: Vec<PatternByte>) -> Self {
        assert!(!bytes.is_empty(), "BytePattern cannot be empty");
        let n = bytes.len();
        let has_exact_bytes = bytes.iter().any(|b| !b.is_wild());

        // Build a simplified Boyer-Moore-Horspool bad-character table using the
        // last non-wild byte position as the shift.  For wild-only patterns the
        // table is ignored.
        let mut skip = [n; 256];
        if has_exact_bytes {
            for (i, &pb) in bytes.iter().enumerate().take(n - 1) {
                if let PatternByte::Exact(v) = pb {
                    skip[v as usize] = n - 1 - i;
                } else if let PatternByte::Masked { value, mask } = pb {
                    for b in 0u16..=255 {
                        let b = b as u8;
                        if b & mask == value & mask {
                            skip[b as usize] = n - 1 - i;
                        }
                    }
                }
            }
        }

        Self {
            bytes,
            skip,
            has_exact_bytes,
        }
    }

    /// Parse an IDA-style hex pattern string, e.g. `"DE AD ?? BE EF"`.
    ///
    /// - `??` or `?` → wildcard
    /// - `0A`  → exact byte
    ///
    /// # Errors
    /// Returns `Err(String)` if a token is not a valid hex byte or wildcard.
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let mut bytes = Vec::with_capacity(pattern.len() / 3 + 1);
        for token in pattern.split_whitespace() {
            if token == "??" || token == "?" {
                bytes.push(PatternByte::Wild);
            } else if token.len() == 2 {
                let val = u8::from_str_radix(token, 16)
                    .map_err(|_| format!("invalid hex token: {token}"))?;
                bytes.push(PatternByte::Exact(val));
            } else {
                return Err(format!("invalid pattern token: {token}"));
            }
        }
        if bytes.is_empty() {
            return Err("pattern is empty".to_string());
        }
        Ok(Self::new(bytes))
    }

    /// The length of the pattern in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the pattern is entirely wildcards.
    #[must_use]
    pub const fn is_all_wild(&self) -> bool {
        !self.has_exact_bytes
    }

    /// Returns `true` if `data` (starting at index 0) matches the pattern.
    ///
    /// # Panics
    /// Panics if `data.len() < self.len()`.
    #[must_use]
    #[inline]
    pub fn matches_at(&self, data: &[u8]) -> bool {
        for (i, &pb) in self.bytes.iter().enumerate() {
            if !pb.matches(data[i]) {
                return false;
            }
        }
        true
    }

    /// Return the skip-table shift for the last byte of a window.
    #[inline]
    const fn bm_skip(&self, byte: u8) -> usize {
        if self.has_exact_bytes {
            self.skip[byte as usize]
        } else {
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySearcher
// ─────────────────────────────────────────────────────────────────────────────

/// High-level memory searcher that operates on a `MemoryProvider`.
pub struct MemorySearcher<'p, P: MemoryProvider> {
    provider: &'p P,
}

impl<'p, P: MemoryProvider + Send + Sync> MemorySearcher<'p, P> {
    /// Create a new searcher wrapping `provider`.
    #[must_use]
    pub const fn new(provider: &'p P) -> Self {
        Self { provider }
    }

    /// Search for all occurrences of `pattern` within `range`.
    ///
    /// Returns a `Vec` of addresses where the pattern was found.
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn find_pattern(
        &self,
        pattern: &BytePattern,
        range: AddressRange,
    ) -> Result<Vec<Address>, MemError> {
        let range_len = usize::try_from(range.len())
            .map_err(|_| MemError::OutOfBounds(range.start, usize::MAX))?;
        if pattern.len() > range_len {
            return Ok(Vec::new());
        }
        let data = self.provider.read(range.start, range_len)?;
        Ok(search_pattern_in_slice(pattern, &data, range.start))
    }

    /// Search for all occurrences of a raw byte slice `needle` within `range`.
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn find_bytes(&self, needle: &[u8], range: AddressRange) -> Result<Vec<Address>, MemError> {
        let range_len_bytes = usize::try_from(range.len()).unwrap_or(usize::MAX);
        if needle.is_empty() || needle.len() > range_len_bytes {
            return Ok(Vec::new());
        }
        let pattern = BytePattern::new(needle.iter().map(|&b| PatternByte::Exact(b)).collect());
        self.find_pattern(&pattern, range)
    }

    /// Search for all occurrences of a UTF-8 string within `range`.
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn find_string(&self, s: &str, range: AddressRange) -> Result<Vec<Address>, MemError> {
        self.find_bytes(s.as_bytes(), range)
    }

    /// Search for all null-terminated C strings starting at each aligned
    /// candidate within `range`.  Returns `(address, string)` pairs for strings
    /// of length `[min_len, max_len]` bytes (not counting the terminator).
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn find_cstrings(
        &self,
        range: AddressRange,
        min_len: usize,
        max_len: usize,
    ) -> Result<Vec<(Address, String)>, MemError> {
        let cstr_range_len = usize::try_from(range.len())
            .map_err(|_| MemError::OutOfBounds(range.start, usize::MAX))?;
        let data = self.provider.read(range.start, cstr_range_len)?;
        let mut results = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if is_printable_ascii(data[i]) {
                let start = i;
                while i < data.len() && is_printable_ascii(data[i]) {
                    i += 1;
                }
                // Check NUL terminator.
                if i < data.len() && data[i] == 0 {
                    let slen = i - start;
                    if slen >= min_len && slen <= max_len
                        && let Ok(s) = std::str::from_utf8(&data[start..i]) {
                            let addr = Address::new(range.start.0 + start as u64);
                            results.push((addr, s.to_string()));
                        }
                }
                i += 1; // skip the NUL or the non-printable character
            } else {
                i += 1;
            }
        }
        Ok(results)
    }

    /// Search for UTF-16LE null-terminated strings within `range`.
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn find_utf16le_strings(
        &self,
        range: AddressRange,
        min_len: usize,
        max_len: usize,
    ) -> Result<Vec<(Address, String)>, MemError> {
        let utf16_range_len = usize::try_from(range.len())
            .map_err(|_| MemError::OutOfBounds(range.start, usize::MAX))?;
        let data = self.provider.read(range.start, utf16_range_len)?;
        let mut results = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() {
            let wchar = u16::from_le_bytes([data[i], data[i + 1]]);
            if wchar != 0 && wchar < 0x0100 && is_printable_ascii(wchar as u8) {
                // Candidate start of a UTF-16LE ASCII-printable string.
                let start = i;
                let mut s = String::new();
                let mut aborted = false;
                while i + 1 < data.len() {
                    let wc = u16::from_le_bytes([data[i], data[i + 1]]);
                    if wc == 0 {
                        break;
                    }
                    if wc < 0x0100 && is_printable_ascii(wc as u8) {
                        s.push(wc as u8 as char);
                    } else {
                        aborted = true;
                        break;
                    }
                    i += 2;
                }
                if !aborted && !s.is_empty() {
                    let slen = s.len();
                    if slen >= min_len && slen <= max_len {
                        let addr = Address::new(range.start.0 + start as u64);
                        results.push((addr, s));
                    }
                    i += 2; // skip the null terminator
                } else {
                    i = start + 2;
                }
            } else {
                i += 2;
            }
        }
        Ok(results)
    }

    /// Count occurrences of `pattern` in `range` without collecting addresses.
    ///
    /// # Errors
    /// Returns `MemError` if the memory range cannot be read.
    pub fn count_pattern(
        &self,
        pattern: &BytePattern,
        range: AddressRange,
    ) -> Result<usize, MemError> {
        Ok(self.find_pattern(pattern, range)?.len())
    }

    /// Scan all mapped regions of the provider for `pattern`.
    ///
    /// Returns addresses from all regions.
    #[must_use]
    pub fn scan_all_regions(&self, pattern: &BytePattern) -> Vec<Address> {
        let mut results = Vec::new();
        for region in self.provider.regions() {
            if let Ok(addrs) = self.find_pattern(pattern, region.range) {
                results.extend(addrs);
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// Search `data` for all occurrences of `pattern` using a simplified
/// Boyer-Moore-Horspool algorithm.
#[must_use]
fn search_pattern_in_slice(pattern: &BytePattern, data: &[u8], base: Address) -> Vec<Address> {
    let pat_len = pattern.len();
    if pat_len > data.len() {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut i = 0usize;
    let limit = data.len() - pat_len;

    while i <= limit {
        if pattern.matches_at(&data[i..]) {
            results.push(Address::new(base.0 + i as u64));
            i += 1;
        } else if i < limit {
            // Use the skip table on the last byte of the window.
            let skip = pattern.bm_skip(data[i + pat_len - 1]);
            i += skip.max(1);
        } else {
            break;
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchResult — structured output of a search operation
// ─────────────────────────────────────────────────────────────────────────────

/// One search hit, including context bytes before and after the match.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Address of the first matching byte.
    pub addr: Address,
    /// The matched bytes.
    pub matched: Vec<u8>,
    /// Up to `context_size` bytes before the match.
    pub context_before: Vec<u8>,
    /// Up to `context_size` bytes after the match.
    pub context_after: Vec<u8>,
}

impl SearchResult {
    /// Human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut hex = String::with_capacity(self.matched.len() * 3);
        for (i, b) in self.matched.iter().enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{b:02X}");
        }
        format!("0x{:x}: {hex}", self.addr.0)
    }
}

/// Collect search results with context bytes from a provider.
///
/// # Errors
/// Returns `MemError` if any range read fails.
pub fn search_with_context<P: MemoryProvider + Send + Sync>(
    provider: &P,
    pattern: &BytePattern,
    range: AddressRange,
    context_size: usize,
) -> Result<Vec<SearchResult>, MemError> {
    let searcher = MemorySearcher::new(provider);
    let addrs = searcher.find_pattern(pattern, range)?;
    let pat_len = pattern.len();

    let mut results = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let matched = provider.read(addr, pat_len).unwrap_or_default();

        let before_start = addr.0.saturating_sub(context_size as u64);
        let before_len = (addr.0 - before_start) as usize;
        let context_before = provider
            .read(Address::new(before_start), before_len)
            .unwrap_or_default();

        let after_addr = Address::new(addr.0.saturating_add(pat_len as u64));
        let context_after = provider.read(after_addr, context_size).unwrap_or_default();

        results.push(SearchResult {
            addr,
            matched,
            context_before,
            context_after,
        });
    }
    Ok(results)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;
    use rustre_core::permissions::Permissions;

    fn make_provider(data: Vec<u8>) -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(data, Address::new(0x1000), Permissions::READ)
    }

    fn rng(start: u64, end: u64) -> AddressRange {
        AddressRange::new(Address::new(start), Address::new(end))
    }

    // ── PatternByte ──────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_byte_exact_match() {
        assert!(PatternByte::Exact(0xAB).matches(0xAB));
        assert!(!PatternByte::Exact(0xAB).matches(0xAC));
    }

    #[test]
    fn test_pattern_byte_wild_matches_all() {
        assert!(PatternByte::Wild.matches(0x00));
        assert!(PatternByte::Wild.matches(0xFF));
        assert!(PatternByte::Wild.is_wild());
    }

    #[test]
    fn test_pattern_byte_masked() {
        let pb = PatternByte::Masked {
            value: 0xF0,
            mask: 0xF0,
        };
        assert!(pb.matches(0xFF)); // 0xFF & 0xF0 == 0xF0 == 0xF0 & 0xF0
        assert!(pb.matches(0xF0));
        assert!(!pb.matches(0x0F));
    }

    // ── BytePattern::parse ───────────────────────────────────────────────────

    #[test]
    fn test_parse_pattern_exact() {
        let p = BytePattern::parse("DE AD BE EF").unwrap();
        assert_eq!(p.len(), 4);
        assert!(!p.is_all_wild());
    }

    #[test]
    fn test_parse_pattern_wildcard() {
        let p = BytePattern::parse("DE ?? BE ??").unwrap();
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn test_parse_pattern_all_wild() {
        let p = BytePattern::parse("?? ??").unwrap();
        assert!(p.is_all_wild());
    }

    #[test]
    fn test_parse_pattern_invalid_token() {
        assert!(BytePattern::parse("GG").is_err());
        assert!(BytePattern::parse("").is_err());
    }

    #[test]
    fn test_parse_single_question_mark() {
        let p = BytePattern::parse("AA ? BB").unwrap();
        assert_eq!(p.len(), 3);
    }

    // ── BytePattern::matches_at ──────────────────────────────────────────────

    #[test]
    fn test_matches_at_exact() {
        let p = BytePattern::parse("AA BB CC").unwrap();
        assert!(p.matches_at(&[0xAA, 0xBB, 0xCC, 0xDD]));
        assert!(!p.matches_at(&[0xAA, 0xFF, 0xCC, 0xDD]));
    }

    #[test]
    fn test_matches_at_with_wildcards() {
        let p = BytePattern::parse("AA ?? CC").unwrap();
        assert!(p.matches_at(&[0xAA, 0x00, 0xCC]));
        assert!(p.matches_at(&[0xAA, 0xFF, 0xCC]));
        assert!(!p.matches_at(&[0xBB, 0x00, 0xCC]));
    }

    // ── search_pattern_in_slice ──────────────────────────────────────────────

    #[test]
    fn test_search_single_occurrence() {
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let p = BytePattern::parse("DE AD BE EF").unwrap();
        let hits = search_pattern_in_slice(&p, &data, Address::new(0x1000));
        assert_eq!(hits, vec![Address::new(0x1001)]);
    }

    #[test]
    fn test_search_multiple_occurrences() {
        let data = vec![0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0x00];
        let p = BytePattern::parse("AA BB").unwrap();
        let hits = search_pattern_in_slice(&p, &data, Address::new(0));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 0);
        assert_eq!(hits[1].0, 3);
    }

    #[test]
    fn test_search_no_match() {
        let data = vec![0x00; 64];
        let p = BytePattern::parse("DE AD").unwrap();
        let hits = search_pattern_in_slice(&p, &data, Address::new(0));
        assert!(hits.is_empty());
    }

    #[test]
    fn test_search_wildcard_pattern() {
        let data = vec![0xAA, 0x00, 0xBB, 0xAA, 0xFF, 0xBB];
        let p = BytePattern::parse("AA ?? BB").unwrap();
        let hits = search_pattern_in_slice(&p, &data, Address::new(0));
        assert_eq!(hits.len(), 2);
    }

    // ── MemorySearcher ───────────────────────────────────────────────────────

    #[test]
    fn test_searcher_find_bytes() {
        let data = vec![
            0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00,
        ];
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let hits = s
            .find_bytes(&[0xDE, 0xAD, 0xBE, 0xEF], rng(0x1000, 0x100B))
            .unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_searcher_find_string() {
        let mut data = b"hello world".to_vec();
        data.extend_from_slice(b"hello world");
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let hits = s.find_string("hello", rng(0x1000, 0x1016)).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_searcher_empty_range_returns_empty() {
        let p = make_provider(vec![0xAA; 16]);
        let s = MemorySearcher::new(&p);
        let r = s
            .find_bytes(
                &[0xAA],
                AddressRange::new(Address::new(0x1000), Address::new(0x1000)),
            )
            .unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_searcher_count_pattern() {
        let data = vec![0x90u8; 100]; // 100 NOPs
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let pat = BytePattern::parse("90 90 90").unwrap();
        let count = s.count_pattern(&pat, rng(0x1000, 0x1064)).unwrap();
        assert_eq!(count, 98); // overlapping matches
    }

    #[test]
    fn test_searcher_find_cstrings() {
        // "hello\0world\0"
        let mut data = b"hello\0world\0junk".to_vec();
        // pad with non-printable to end
        data.push(0x01);
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let strings = s.find_cstrings(rng(0x1000, 0x1010), 3, 20).unwrap();
        let names: Vec<&str> = strings.iter().map(|(_, s)| s.as_str()).collect();
        assert!(names.contains(&"hello"));
        assert!(names.contains(&"world"));
    }

    #[test]
    fn test_searcher_find_cstrings_min_len_filter() {
        let data = b"hi\0a\0hello\0".to_vec();
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let strings = s.find_cstrings(rng(0x1000, 0x100B), 3, 20).unwrap();
        // "hi" is 2 chars → filtered out; "a" is 1 char → filtered; "hello" passes
        assert!(!strings.iter().any(|(_, s)| s == "hi"));
        assert!(strings.iter().any(|(_, s)| s == "hello"));
    }

    #[test]
    fn test_scan_all_regions() {
        let data = vec![0xCC, 0xCC, 0xAA, 0xCC, 0xCC];
        let p = make_provider(data);
        let pat = BytePattern::parse("CC CC").unwrap();
        let s = MemorySearcher::new(&p);
        let hits = s.scan_all_regions(&pat);
        // at offsets 0 and 3 relative to 0x1000
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_search_with_context() {
        let data = vec![0x01, 0x02, 0xAA, 0xBB, 0x03, 0x04];
        let p = make_provider(data);
        let pat = BytePattern::parse("AA BB").unwrap();
        let results = search_with_context(&p, &pat, rng(0x1000, 0x1006), 2).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.matched, vec![0xAA, 0xBB]);
        assert_eq!(r.context_before, vec![0x01, 0x02]);
        assert_eq!(r.context_after, vec![0x03, 0x04]);
    }

    #[test]
    fn test_search_result_summary() {
        let r = SearchResult {
            addr: Address::new(0xDEAD),
            matched: vec![0xDE, 0xAD],
            context_before: vec![],
            context_after: vec![],
        };
        let s = r.summary();
        assert!(s.contains("dead"));
        assert!(s.contains("DE AD"));
    }

    #[test]
    fn test_pattern_needle_longer_than_range_returns_empty() {
        let p = make_provider(vec![0xAA; 4]);
        let s = MemorySearcher::new(&p);
        let r = s.find_bytes(&[0xAA; 8], rng(0x1000, 0x1004)).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_find_utf16le_strings() {
        // Build "hi\0" in UTF-16LE: h=0x0068 i=0x0069 \0=0x0000
        let data: Vec<u8> = vec![
            0x68, 0x00, // 'h'
            0x65, 0x00, // 'e'
            0x6C, 0x00, // 'l'
            0x6C, 0x00, // 'l'
            0x6F, 0x00, // 'o'
            0x00, 0x00, // \0
        ];
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let found = s.find_utf16le_strings(rng(0x1000, 0x100C), 3, 20).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "hello");
    }

    #[test]
    fn test_pattern_byte_exact_not_wild() {
        assert!(!PatternByte::Exact(0xAA).is_wild());
    }

    #[test]
    fn test_search_at_boundary() {
        // Pattern at the very end of the buffer
        let data = vec![0x00, 0x00, 0xDE, 0xAD];
        let p = make_provider(data);
        let s = MemorySearcher::new(&p);
        let hits = s.find_bytes(&[0xDE, 0xAD], rng(0x1000, 0x1004)).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0x1002);
    }

    #[test]
    fn test_byte_pattern_new_panics_on_empty() {
        let result = std::panic::catch_unwind(|| BytePattern::new(vec![]));
        assert!(result.is_err());
    }
}
