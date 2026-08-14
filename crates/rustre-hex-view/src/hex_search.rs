//! `hex_search` — Byte-pattern and string search over hex buffers.
//!
//! Provides [`HexSearch`], [`SearchQuery`], and [`SearchHit`] together with the
//! free functions [`find_pattern`] and [`find_string`].

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SearchEncoding
// ─────────────────────────────────────────────────────────────────────────────

/// Text encoding used when searching for a string pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchEncoding {
    /// Plain ASCII / UTF-8 bytes.
    Utf8,
    /// UTF-16 little-endian (each code unit is 2 bytes).
    Utf16Le,
    /// UTF-16 big-endian.
    Utf16Be,
}

impl fmt::Display for SearchEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 => write!(f, "UTF-8"),
            Self::Utf16Le => write!(f, "UTF-16-LE"),
            Self::Utf16Be => write!(f, "UTF-16-BE"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchQuery
// ─────────────────────────────────────────────────────────────────────────────

/// A search query describing what to look for and how.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Raw byte pattern to match; for string queries this is the encoded form.
    pub pattern: Vec<u8>,
    /// Optional per-byte mask: `0xFF` means "must match", `0x00` means "any".
    /// If `None`, all bytes must match exactly.
    pub mask: Option<Vec<u8>>,
    /// If `true`, perform a case-insensitive ASCII comparison.
    pub case_insensitive: bool,
    /// Maximum number of hits to return (0 = unlimited).
    pub max_hits: usize,
    /// Restrict search to `[start, end)` within the buffer.  If both are 0,
    /// the entire buffer is searched.
    pub range_start: usize,
    pub range_end: usize,
}

impl SearchQuery {
    /// Create a simple exact byte-pattern query.
    #[must_use]
    pub const fn exact(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            mask: None,
            case_insensitive: false,
            max_hits: 0,
            range_start: 0,
            range_end: 0,
        }
    }

    /// Create a masked pattern query (e.g. for wildcard bytes).
    ///
    /// `mask` must have the same length as `pattern`; bytes in the mask equal
    /// to `0x00` are treated as don't-care.
    ///
    /// # Panics
    ///
    /// Panics if `mask.len() != pattern.len()`.
    #[must_use]
    pub fn masked(pattern: Vec<u8>, mask: Vec<u8>) -> Self {
        assert_eq!(
            pattern.len(),
            mask.len(),
            "mask length must equal pattern length"
        );
        Self {
            pattern,
            mask: Some(mask),
            case_insensitive: false,
            max_hits: 0,
            range_start: 0,
            range_end: 0,
        }
    }

    /// Create a case-insensitive ASCII string query.
    #[must_use]
    pub const fn case_insensitive(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            mask: None,
            case_insensitive: true,
            max_hits: 0,
            range_start: 0,
            range_end: 0,
        }
    }

    /// Restrict the search to `[start, end)`.
    #[must_use]
    pub const fn with_range(mut self, start: usize, end: usize) -> Self {
        self.range_start = start;
        self.range_end = end;
        self
    }

    /// Limit the number of hits returned.
    #[must_use]
    pub const fn with_max_hits(mut self, max: usize) -> Self {
        self.max_hits = max;
        self
    }

    /// Return the effective search window `(start, end)` given a buffer of
    /// length `buf_len`.
    #[must_use]
    pub fn effective_range(&self, buf_len: usize) -> (usize, usize) {
        let end = if self.range_end == 0 {
            buf_len
        } else {
            self.range_end.min(buf_len)
        };
        let start = self.range_start.min(end);
        (start, end)
    }

    /// Return `true` if this query can produce any matches (non-empty pattern,
    /// sensible range).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.pattern.is_empty()
    }

    /// Encode a UTF-8 string as a `SearchQuery` in the given encoding.
    #[must_use]
    pub fn from_string(s: &str, enc: SearchEncoding) -> Self {
        let pattern = match enc {
            SearchEncoding::Utf8 => s.as_bytes().to_vec(),
            SearchEncoding::Utf16Le => s
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
            SearchEncoding::Utf16Be => s
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect(),
        };
        Self::exact(pattern)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchHit
// ─────────────────────────────────────────────────────────────────────────────

/// A single match found by the search engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Byte offset of the match within the searched buffer.
    pub offset: usize,
    /// Length of the matched region (equal to `pattern.len()`).
    pub len: usize,
    /// A copy of the matched bytes for inspection.
    pub matched_bytes: Vec<u8>,
}

impl SearchHit {
    /// Create a new search hit.
    #[must_use]
    pub const fn new(offset: usize, matched_bytes: Vec<u8>) -> Self {
        let len = matched_bytes.len();
        Self {
            offset,
            len,
            matched_bytes,
        }
    }

    /// Return the byte range `[offset, offset + len)` of this hit.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.len
    }

    /// Return `true` if the matched bytes are valid printable ASCII.
    #[must_use]
    pub fn is_printable_ascii(&self) -> bool {
        self.matched_bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ')
    }
}

impl fmt::Display for SearchHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SearchHit(offset={:#x}, len={})",
            self.offset, self.len
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core matching primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `window` matches `pattern` under `query` options.
fn window_matches(window: &[u8], query: &SearchQuery) -> bool {
    let pattern = &query.pattern;
    if window.len() != pattern.len() {
        return false;
    }
    match &query.mask {
        Some(mask) => {
            for i in 0..pattern.len() {
                let m = mask[i];
                if m == 0x00 {
                    continue; // wildcard
                }
                let a = window[i] & m;
                let b = pattern[i] & m;
                if query.case_insensitive {
                    if !a.eq_ignore_ascii_case(&b) {
                        return false;
                    }
                } else if a != b {
                    return false;
                }
            }
            true
        }
        None => {
            if query.case_insensitive {
                window
                    .iter()
                    .zip(pattern.iter())
                    .all(|(&a, &b)| a.eq_ignore_ascii_case(&b))
            } else {
                window == pattern.as_slice()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// find_pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Search `data` for all occurrences of the byte pattern described by `query`.
///
/// Returns a `Vec<SearchHit>` with all non-overlapping matches found within
/// the query's effective range.  If `query.max_hits > 0`, at most that many
/// hits are returned.
#[must_use]
pub fn find_pattern(data: &[u8], query: &SearchQuery) -> Vec<SearchHit> {
    if !query.is_valid() || data.is_empty() {
        return Vec::new();
    }
    let (start, end) = query.effective_range(data.len());
    let plen = query.pattern.len();
    if plen == 0 || start + plen > end {
        return Vec::new();
    }

    let mut hits = Vec::new();
    let mut pos = start;
    while pos + plen <= end {
        let window = &data[pos..pos + plen];
        if window_matches(window, query) {
            hits.push(SearchHit::new(pos, window.to_vec()));
            if query.max_hits > 0 && hits.len() >= query.max_hits {
                break;
            }
            pos += plen; // non-overlapping
        } else {
            pos += 1;
        }
    }
    hits
}

// ─────────────────────────────────────────────────────────────────────────────
// find_string
// ─────────────────────────────────────────────────────────────────────────────

/// Search `data` for all occurrences of `s` in the given `encoding`.
///
/// This is a convenience wrapper around [`find_pattern`] with a
/// [`SearchQuery`] built from the string.
#[must_use]
pub fn find_string(data: &[u8], s: &str, encoding: SearchEncoding) -> Vec<SearchHit> {
    if s.is_empty() {
        return Vec::new();
    }
    let query = SearchQuery::from_string(s, encoding);
    find_pattern(data, &query)
}

// ─────────────────────────────────────────────────────────────────────────────
// HexSearch
// ─────────────────────────────────────────────────────────────────────────────

/// High-level stateful hex search engine.
///
/// Stores the last query and its results, and allows stepping through hits.
pub struct HexSearch {
    /// The data being searched (shared reference or owned copy).
    data: Vec<u8>,
    /// The most recently executed query.
    pub last_query: Option<SearchQuery>,
    /// All hits from the last search.
    pub hits: Vec<SearchHit>,
    /// Index of the "current" hit for navigation.
    pub current: usize,
}

impl HexSearch {
    /// Create a new search engine over `data`.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            last_query: None,
            hits: Vec::new(),
            current: 0,
        }
    }

    /// Return the number of bytes in the searched buffer.
    #[must_use]
    pub const fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Execute a search and store the results.  Returns a slice of all hits.
    pub fn search(&mut self, query: SearchQuery) -> &[SearchHit] {
        self.hits = find_pattern(&self.data, &query);
        self.current = 0;
        self.last_query = Some(query);
        &self.hits
    }

    /// Search for a byte pattern given as a hex string like `"DE AD BE EF"`.
    ///
    /// Bytes separated by spaces; `??` is a wildcard.
    pub fn search_hex(&mut self, hex: &str) -> &[SearchHit] {
        let (pattern, mask) = parse_hex_pattern(hex);
        if pattern.is_empty() {
            self.hits.clear();
            self.current = 0;
            return &self.hits;
        }
        let has_wildcards = mask.contains(&0x00);
        let query = if has_wildcards {
            SearchQuery::masked(pattern, mask)
        } else {
            SearchQuery::exact(pattern)
        };
        self.search(query)
    }

    /// Search for a UTF-8 string.
    pub fn search_string(&mut self, s: &str) -> &[SearchHit] {
        let query = SearchQuery::from_string(s, SearchEncoding::Utf8);
        self.search(query)
    }

    /// Return the current hit, if any.
    #[must_use]
    pub fn current_hit(&self) -> Option<&SearchHit> {
        self.hits.get(self.current)
    }

    /// Move to the next hit.  Wraps around to the first hit.
    pub fn next_hit(&mut self) -> Option<&SearchHit> {
        if self.hits.is_empty() {
            return None;
        }
        self.current = (self.current + 1) % self.hits.len();
        self.hits.get(self.current)
    }

    /// Move to the previous hit.  Wraps around to the last hit.
    pub fn prev_hit(&mut self) -> Option<&SearchHit> {
        if self.hits.is_empty() {
            return None;
        }
        if self.current == 0 {
            self.current = self.hits.len() - 1;
        } else {
            self.current -= 1;
        }
        self.hits.get(self.current)
    }

    /// Move to the first hit.
    pub fn first_hit(&mut self) -> Option<&SearchHit> {
        self.current = 0;
        self.hits.first()
    }

    /// Move to the last hit.
    pub fn last_hit(&mut self) -> Option<&SearchHit> {
        if self.hits.is_empty() {
            return None;
        }
        self.current = self.hits.len() - 1;
        self.hits.last()
    }

    /// Return all hits within the address range `[start, end)`.
    #[must_use]
    pub fn hits_in_range(&self, start: usize, end: usize) -> Vec<&SearchHit> {
        self.hits
            .iter()
            .filter(|h| h.offset >= start && h.offset < end)
            .collect()
    }

    /// Return `true` if the last search produced at least one hit.
    #[must_use]
    pub const fn has_hits(&self) -> bool {
        !self.hits.is_empty()
    }

    /// Clear stored hits and reset the engine.
    pub fn clear(&mut self) {
        self.hits.clear();
        self.current = 0;
        self.last_query = None;
    }

    /// Replace the data buffer and clear all stored hits.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
        self.clear();
    }

    /// Repeat the last query (useful after editing the buffer).
    pub fn repeat_search(&mut self) -> &[SearchHit] {
        if let Some(q) = self.last_query.clone() {
            self.hits = find_pattern(&self.data, &q);
            self.current = 0;
        }
        &self.hits
    }
}

impl fmt::Debug for HexSearch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HexSearch")
            .field("data_len", &self.data.len())
            .field("hits", &self.hits.len())
            .field("current", &self.current)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_hex_pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a hex pattern string into `(pattern, mask)`.
///
/// Each token is either a two-hex-digit byte or `??` for a wildcard.
/// Tokens are separated by whitespace.
#[must_use]
pub fn parse_hex_pattern(hex: &str) -> (Vec<u8>, Vec<u8>) {
    let mut pattern = Vec::new();
    let mut mask = Vec::new();
    for token in hex.split_whitespace() {
        if token == "??" || token == "?" {
            pattern.push(0x00);
            mask.push(0x00); // wildcard
        } else if token.len() == 2
            && let Ok(b) = u8::from_str_radix(token, 16) {
                pattern.push(b);
                mask.push(0xFF);
            }
    }
    (pattern, mask)
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a completed search.
#[derive(Debug, Clone, Default)]
pub struct SearchStats {
    /// Number of hits found.
    pub hit_count: usize,
    /// Number of bytes scanned.
    pub bytes_scanned: usize,
    /// Whether the hit limit was reached.
    pub limit_reached: bool,
}

impl SearchStats {
    /// Compute stats from a set of hits and the scanned range size.
    #[must_use]
    pub const fn from_hits(hits: &[SearchHit], bytes_scanned: usize, max_hits: usize) -> Self {
        Self {
            hit_count: hits.len(),
            bytes_scanned,
            limit_reached: max_hits > 0 && hits.len() >= max_hits,
        }
    }
}

impl fmt::Display for SearchStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SearchStats(hits={}, scanned={}, capped={})",
            self.hit_count, self.bytes_scanned, self.limit_reached
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchHistory
// ─────────────────────────────────────────────────────────────────────────────

/// A bounded ring of previous search patterns for recall.
#[derive(Debug, Clone, Default)]
pub struct SearchHistory {
    /// Pattern strings in most-recent-first order.
    entries: Vec<String>,
    /// Maximum number of entries.
    capacity: usize,
}

impl SearchHistory {
    /// Create a history with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(64)),
            capacity: capacity.max(1),
        }
    }

    /// Push a new search term.  Removes duplicates and enforces capacity.
    pub fn push(&mut self, term: impl Into<String>) {
        let term = term.into();
        self.entries.retain(|e| e != &term);
        self.entries.insert(0, term);
        if self.entries.len() > self.capacity {
            self.entries.truncate(self.capacity);
        }
    }

    /// Return the most recent search term.
    #[must_use]
    pub fn latest(&self) -> Option<&str> {
        self.entries.first().map(String::as_str)
    }

    /// Return all entries in most-recent-first order.
    #[must_use]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no entries are recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        b"Hello, World! Hello, Rust!".to_vec()
    }

    #[test]
    fn find_pattern_exact() {
        let data = sample();
        let q = SearchQuery::exact(b"Hello".to_vec());
        let hits = find_pattern(&data, &q);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].offset, 14);
    }

    #[test]
    fn find_pattern_case_insensitive() {
        let data = b"aBcAbcABC".to_vec();
        let q = SearchQuery::case_insensitive(b"abc".to_vec());
        let hits = find_pattern(&data, &q);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn find_pattern_masked_wildcard() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xCC, 0xBE, 0xEF];
        let pat = vec![0xDE, 0x00, 0xBE, 0xEF];
        let mask = vec![0xFF, 0x00, 0xFF, 0xFF];
        let q = SearchQuery::masked(pat, mask);
        let hits = find_pattern(&data, &q);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn find_pattern_max_hits() {
        let data = vec![0xAA; 100];
        let q = SearchQuery::exact(vec![0xAA]).with_max_hits(5);
        let hits = find_pattern(&data, &q);
        assert_eq!(hits.len(), 5);
    }

    #[test]
    fn find_pattern_range_restricted() {
        let data = b"xyzHello!xyz".to_vec();
        let q = SearchQuery::exact(b"Hello".to_vec()).with_range(3, 8);
        let hits = find_pattern(&data, &q);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 3);
    }

    #[test]
    fn find_pattern_empty_pattern_returns_none() {
        let data = sample();
        let q = SearchQuery::exact(vec![]);
        let hits = find_pattern(&data, &q);
        assert!(hits.is_empty());
    }

    #[test]
    fn find_string_utf8() {
        let data = b"find me here and find me again".to_vec();
        let hits = find_string(&data, "find me", SearchEncoding::Utf8);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn find_string_utf16le() {
        let s = "Hi";
        let mut data: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0, 0, 0]);
        let hits = find_string(&data, "Hi", SearchEncoding::Utf16Le);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn search_hit_range() {
        let hit = SearchHit::new(10, vec![0xDE, 0xAD]);
        assert_eq!(hit.range(), 10..12);
    }

    #[test]
    fn search_hit_is_printable_ascii() {
        let hit = SearchHit::new(0, b"Hello".to_vec());
        assert!(hit.is_printable_ascii());
        let hit2 = SearchHit::new(0, vec![0x00, 0xFF]);
        assert!(!hit2.is_printable_ascii());
    }

    #[test]
    fn hex_search_navigation() {
        // search_hex parses tokens as hex bytes (0xAA, 0xBB), so data is raw bytes not ASCII.
        let data = vec![0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut hs = HexSearch::new(data);
        hs.search_hex("AA BB");
        assert_eq!(hs.hits.len(), 2);
        assert_eq!(hs.current_hit().unwrap().offset, 0);
        hs.next_hit();
        assert_eq!(hs.current_hit().unwrap().offset, 6);
        hs.next_hit(); // wrap
        assert_eq!(hs.current_hit().unwrap().offset, 0);
        hs.prev_hit(); // wrap back
        assert_eq!(hs.current_hit().unwrap().offset, 6);
    }

    #[test]
    fn hex_search_wildcard() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xFF, 0xBE, 0xEF];
        let mut hs = HexSearch::new(data);
        hs.search_hex("DE ?? BE EF");
        assert_eq!(hs.hits.len(), 2);
    }

    #[test]
    fn hex_search_clear() {
        let data = b"test data".to_vec();
        let mut hs = HexSearch::new(data);
        hs.search_string("test");
        assert!(!hs.hits.is_empty());
        hs.clear();
        assert!(hs.hits.is_empty());
        assert!(hs.last_query.is_none());
    }

    #[test]
    fn parse_hex_pattern_wildcards() {
        let (pat, mask) = parse_hex_pattern("DE ?? BE EF");
        assert_eq!(pat.len(), 4);
        assert_eq!(mask[0], 0xFF);
        assert_eq!(mask[1], 0x00);
        assert_eq!(mask[3], 0xFF);
    }

    #[test]
    fn search_history_push_and_dedup() {
        let mut hist = SearchHistory::new(5);
        hist.push("first");
        hist.push("second");
        hist.push("first");
        assert_eq!(hist.len(), 2);
        assert_eq!(hist.latest(), Some("first"));
    }

    #[test]
    fn search_history_capacity() {
        let mut hist = SearchHistory::new(3);
        for i in 0..5 {
            hist.push(i.to_string());
        }
        assert_eq!(hist.len(), 3);
        assert_eq!(hist.latest(), Some("4"));
    }

    #[test]
    fn search_stats_display() {
        let stats = SearchStats {
            hit_count: 7,
            bytes_scanned: 1024,
            limit_reached: false,
        };
        let s = stats.to_string();
        assert!(s.contains("7"));
        assert!(s.contains("1024"));
    }

    #[test]
    fn query_from_string_utf16le() {
        let q = SearchQuery::from_string("AB", SearchEncoding::Utf16Le);
        assert_eq!(q.pattern.len(), 4);
        assert_eq!(q.pattern[0], b'A');
        assert_eq!(q.pattern[1], 0x00);
    }
}
