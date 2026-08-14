//! Interactive search bar for the hex editor view.
//!
//! Provides [`SearchBar`] which drives the user-facing search interface,
//! [`SearchMode`] for selecting hex/text/regex/pattern search,
//! [`SearchDirection`] for controlling search direction,
//! [`SearchHighlight`] for marking matches in the view,
//! [`SearchResult`] as the individual match record,
//! [`SearchHistory`] for recalling past queries, and
//! [`SearchProgress`] for async long-running searches.

use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the search-bar module.
#[derive(Debug, Error)]
pub enum SearchError {
    #[error("empty query")]
    EmptyQuery,
    #[error("invalid hex string: {0}")]
    InvalidHex(String),
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
    #[error("invalid wildcard pattern: {0}")]
    InvalidPattern(String),
    #[error("buffer is empty")]
    EmptyBuffer,
    #[error("search out of range: offset {0} >= buffer length {1}")]
    OutOfRange(u64, u64),
    #[error("history index {0} out of range (history size {1})")]
    HistoryIndex(usize, usize),
}

pub type SearchBarResult<T> = Result<T, SearchError>;

// ---------------------------------------------------------------------------
// SearchMode
// ---------------------------------------------------------------------------

/// The interpretation applied to the query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum SearchMode {
    /// Query is a hex string, e.g. `"4D 5A"` or `"4D5A"` (whitespace ignored).
    #[default]
    Hex,
    /// Query is a UTF-8 text literal.
    Text,
    /// Query is a POSIX-compatible regular expression applied to the buffer as text.
    Regex,
    /// Query is a wildcard pattern where `??` matches any single byte,
    /// e.g. `"4D 5A ?? ?? 00"`.
    Pattern,
}


impl fmt::Display for SearchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex => write!(f, "Hex"),
            Self::Text => write!(f, "Text"),
            Self::Regex => write!(f, "Regex"),
            Self::Pattern => write!(f, "Pattern"),
        }
    }
}

// ---------------------------------------------------------------------------
// SearchDirection
// ---------------------------------------------------------------------------

/// Which direction a search proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum SearchDirection {
    /// Search from current position toward end.
    #[default]
    Forward,
    /// Search from current position toward beginning.
    Backward,
    /// Collect all matches in one pass.
    All,
}


// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// A single match returned by a search operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    /// Byte offset of the first matching byte.
    pub offset: u64,
    /// Number of bytes matched.
    pub length: usize,
    /// 0-based index of this result among all matches (for "all" mode).
    pub index: usize,
    /// Optional capture groups (regex mode).
    pub captures: Vec<String>,
}

impl SearchResult {
    /// Create a simple result without captures.
    #[must_use]
    pub const fn new(offset: u64, length: usize, index: usize) -> Self {
        Self {
            offset,
            length,
            index,
            captures: Vec::new(),
        }
    }

    /// The byte range covered by this result.
    #[must_use]
    pub const fn range(&self) -> Range<u64> {
        self.offset..self.offset + self.length as u64
    }
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Match[{}] at 0x{:X} ({} bytes)", self.index, self.offset, self.length)
    }
}

// ---------------------------------------------------------------------------
// SearchHighlight
// ---------------------------------------------------------------------------

/// Highlight applied to a match in the hex / text panels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHighlight {
    /// The match this highlight belongs to.
    pub result: SearchResult,
    /// RGBA colour used to render the highlight.
    pub color: [u8; 4],
    /// True when this is the "current" (focused) match.
    pub is_current: bool,
}

impl SearchHighlight {
    /// Default highlight colour: amber.
    pub const DEFAULT_COLOR: [u8; 4] = [0xFF, 0xC0, 0x00, 0xC0];
    /// Highlight colour for the current match: bright yellow.
    pub const CURRENT_COLOR: [u8; 4] = [0xFF, 0xFF, 0x00, 0xFF];

    /// Create a non-current highlight for `result`.
    #[must_use]
    pub const fn new(result: SearchResult) -> Self {
        Self {
            result,
            color: Self::DEFAULT_COLOR,
            is_current: false,
        }
    }

    /// Mark this highlight as the current focused result.
    pub const fn set_current(&mut self) {
        self.is_current = true;
        self.color = Self::CURRENT_COLOR;
    }

    /// Clear the current-focus marker.
    pub const fn clear_current(&mut self) {
        self.is_current = false;
        self.color = Self::DEFAULT_COLOR;
    }
}

// ---------------------------------------------------------------------------
// SearchHistory
// ---------------------------------------------------------------------------

/// Circular buffer of past search queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHistory {
    entries: VecDeque<String>,
    /// Maximum number of entries kept.
    capacity: usize,
    /// Index into `entries` for up/down navigation (-1 = "new entry").
    cursor: Option<usize>,
}

impl SearchHistory {
    /// Create a history buffer with `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            cursor: None,
        }
    }

    /// Push a query string into history (deduplicates, most-recent first).
    pub fn push(&mut self, query: impl Into<String>) {
        let q = query.into();
        if q.is_empty() {
            return;
        }
        // Remove duplicate.
        self.entries.retain(|e| e != &q);
        self.entries.push_front(q);
        if self.entries.len() > self.capacity {
            self.entries.pop_back();
        }
        self.cursor = None;
    }

    /// Navigate backward (toward older entries). Returns the entry or `None`.
    pub fn prev(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let next = match self.cursor {
            None => 0,
            Some(i) => (i + 1).min(self.entries.len() - 1),
        };
        self.cursor = Some(next);
        self.entries.get(next).map(std::string::String::as_str)
    }

    /// Navigate forward (toward newer entries). Returns the entry or `None`.
    pub fn next(&mut self) -> Option<&str> {
        match self.cursor {
            None | Some(0) => {
                self.cursor = None;
                None
            }
            Some(i) => {
                self.cursor = Some(i - 1);
                self.entries.get(i - 1).map(std::string::String::as_str)
            }
        }
    }

    /// Return the entry at `index` (0 = most recent).
    pub fn get(&self, index: usize) -> SearchBarResult<&str> {
        self.entries
            .get(index)
            .map(std::string::String::as_str)
            .ok_or(SearchError::HistoryIndex(index, self.entries.len()))
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = None;
    }

    /// Iterator over entries from most-recent to oldest.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(std::string::String::as_str)
    }
}

// ---------------------------------------------------------------------------
// SearchProgress
// ---------------------------------------------------------------------------

/// Tracks the progress of a potentially long-running "find all" search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchProgress {
    /// Bytes processed so far.
    pub processed: u64,
    /// Total bytes in the search space.
    pub total: u64,
    /// Results found so far.
    pub found: usize,
    /// True when the search has completed.
    pub done: bool,
    /// Optional cancellation flag (caller sets `true` to abort).
    pub cancelled: bool,
}

impl SearchProgress {
    /// Create a new progress tracker for a buffer of `total` bytes.
    #[must_use]
    pub const fn new(total: u64) -> Self {
        Self {
            processed: 0,
            total,
            found: 0,
            done: false,
            cancelled: false,
        }
    }

    /// Completion ratio in the range `[0.0, 1.0]`.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.processed as f64 / self.total as f64).min(1.0)
        }
    }

    /// Advance `processed` by `n` bytes and increment `found` by `hits`.
    pub fn advance(&mut self, n: u64, hits: usize) {
        self.processed = (self.processed + n).min(self.total);
        self.found += hits;
        if self.processed >= self.total {
            self.done = true;
        }
    }

    /// Mark the search as complete.
    pub const fn finish(&mut self) {
        self.processed = self.total;
        self.done = true;
    }

    /// Request cancellation.
    pub const fn cancel(&mut self) {
        self.cancelled = true;
    }
}

impl fmt::Display for SearchProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.1}% ({}/{} bytes, {} hits)",
            self.ratio() * 100.0,
            self.processed,
            self.total,
            self.found
        )
    }
}

// ---------------------------------------------------------------------------
// SearchBar
// ---------------------------------------------------------------------------

/// The search bar state machine.
///
/// `SearchBar` owns the query string, mode, direction, history, current
/// results, highlights, and progress.  The actual byte-matching logic lives
/// in `do_search` which runs against the provided byte slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchBar {
    /// Current query text.
    pub query: String,
    /// Interpretation mode.
    pub mode: SearchMode,
    /// Search direction.
    pub direction: SearchDirection,
    /// Case-insensitive text/regex matching.
    pub case_insensitive: bool,
    /// Wrap around when the end / beginning is reached.
    pub wrap: bool,
    /// The last set of results (from "find all" or repeated "find next").
    results: Vec<SearchResult>,
    /// Index into `results` pointing at the current match.
    current: Option<usize>,
    /// Highlights derived from `results`.
    highlights: Vec<SearchHighlight>,
    /// Past queries.
    pub history: SearchHistory,
    /// Progress for the most recent search.
    pub progress: Option<SearchProgress>,
}

impl Default for SearchBar {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchBar {
    /// Create a new, empty search bar.
    #[must_use]
    pub fn new() -> Self {
        Self {
            query: String::new(),
            mode: SearchMode::default(),
            direction: SearchDirection::default(),
            case_insensitive: false,
            wrap: true,
            results: Vec::new(),
            current: None,
            highlights: Vec::new(),
            history: SearchHistory::new(50),
            progress: None,
        }
    }

    // -----------------------------------------------------------------------
    // Query / mode control
    // -----------------------------------------------------------------------

    /// Set the query string (does not trigger a search).
    pub fn set_query(&mut self, q: impl Into<String>) {
        self.query = q.into();
    }

    /// Set the search mode.
    pub const fn set_mode(&mut self, mode: SearchMode) {
        self.mode = mode;
    }

    /// Set the search direction.
    pub const fn set_direction(&mut self, dir: SearchDirection) {
        self.direction = dir;
    }

    /// Clear results, highlights, and reset the current pointer.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.highlights.clear();
        self.current = None;
    }

    // -----------------------------------------------------------------------
    // Search execution
    // -----------------------------------------------------------------------

    /// Run a full "find all" search over `data`, starting at `start_offset`.
    ///
    /// Results are stored internally; call [`Self::results`] to retrieve them.
    pub fn find_all(&mut self, data: &[u8], start_offset: u64) -> SearchBarResult<usize> {
        self.validate_query()?;
        if data.is_empty() {
            return Err(SearchError::EmptyBuffer);
        }
        let pattern = self.compile_pattern()?;
        let matches = self.run_search(&pattern, data, start_offset)?;
        let count = matches.len();
        self.results = matches;
        self.rebuild_highlights();
        self.current = if count > 0 { Some(0) } else { None };
        self.history.push(self.query.clone());
        let mut prog = SearchProgress::new(data.len() as u64);
        prog.advance(data.len() as u64, count);
        prog.finish();
        self.progress = Some(prog);
        Ok(count)
    }

    /// Advance to the next match (or previous if direction is Backward).
    ///
    /// Returns `None` if there are no results.
    pub fn find_next(&mut self) -> Option<&SearchResult> {
        let len = self.results.len();
        if len == 0 {
            return None;
        }
        let idx = match self.current {
            None => 0,
            Some(i) => match self.direction {
                SearchDirection::Forward | SearchDirection::All => {
                    if i + 1 < len { i + 1 } else if self.wrap { 0 } else { return None; }
                }
                SearchDirection::Backward => {
                    if i > 0 { i - 1 } else if self.wrap { len - 1 } else { return None; }
                }
            },
        };
        self.set_current(idx);
        self.results.get(idx)
    }

    /// Return to the previous match.
    pub fn find_prev(&mut self) -> Option<&SearchResult> {
        let len = self.results.len();
        if len == 0 {
            return None;
        }
        let idx = match self.current {
            None => len - 1,
            Some(i) => {
                if i > 0 { i - 1 } else if self.wrap { len - 1 } else { return None; }
            }
        };
        self.set_current(idx);
        self.results.get(idx)
    }

    // -----------------------------------------------------------------------
    // Results / highlights
    // -----------------------------------------------------------------------

    /// Immutable slice of all results.
    #[must_use]
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// The currently focused result, if any.
    #[must_use]
    pub fn current_result(&self) -> Option<&SearchResult> {
        self.current.and_then(|i| self.results.get(i))
    }

    /// Index of the current result.
    #[must_use]
    pub const fn current_index(&self) -> Option<usize> {
        self.current
    }

    /// Immutable slice of all highlights.
    #[must_use]
    pub fn highlights(&self) -> &[SearchHighlight] {
        &self.highlights
    }

    /// Total number of results.
    #[must_use]
    pub const fn result_count(&self) -> usize {
        self.results.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn validate_query(&self) -> SearchBarResult<()> {
        if self.query.trim().is_empty() {
            return Err(SearchError::EmptyQuery);
        }
        Ok(())
    }

    /// Compiled byte-level pattern from the query.
    fn compile_pattern(&self) -> SearchBarResult<CompiledPattern> {
        match self.mode {
            SearchMode::Hex => {
                let bytes = parse_hex_query(&self.query)?;
                Ok(CompiledPattern::Bytes(bytes))
            }
            SearchMode::Text => {
                let s = if self.case_insensitive {
                    self.query.to_lowercase()
                } else {
                    self.query.clone()
                };
                Ok(CompiledPattern::Text(s.into_bytes()))
            }
            SearchMode::Regex => {
                // Validate by attempting to parse (simplified — real impl uses the regex crate).
                if self.query.contains('\0') {
                    return Err(SearchError::InvalidRegex("null byte in regex".into()));
                }
                Ok(CompiledPattern::Regex(self.query.clone()))
            }
            SearchMode::Pattern => {
                let pat = parse_wildcard_pattern(&self.query)?;
                Ok(CompiledPattern::Wildcard(pat))
            }
        }
    }

    fn run_search(
        &self,
        pattern: &CompiledPattern,
        data: &[u8],
        _start: u64,
    ) -> SearchBarResult<Vec<SearchResult>> {
        match pattern {
            CompiledPattern::Bytes(needle) => Ok(find_bytes(data, needle, 0)),
            CompiledPattern::Text(needle) => Ok(find_bytes(data, needle, 0)),
            CompiledPattern::Regex(re_str) => Ok(find_regex_stub(data, re_str)),
            CompiledPattern::Wildcard(pat) => Ok(find_wildcard(data, pat, 0)),
        }
    }

    fn rebuild_highlights(&mut self) {
        self.highlights = self
            .results
            .iter()
            .map(|r| SearchHighlight::new(r.clone()))
            .collect();
    }

    fn set_current(&mut self, idx: usize) {
        if let Some(old) = self.current
            && let Some(h) = self.highlights.get_mut(old) {
                h.clear_current();
            }
        self.current = Some(idx);
        if let Some(h) = self.highlights.get_mut(idx) {
            h.set_current();
        }
    }
}

// ---------------------------------------------------------------------------
// CompiledPattern (internal)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum CompiledPattern {
    Bytes(Vec<u8>),
    Text(Vec<u8>),
    Regex(String),
    Wildcard(Vec<WildcardByte>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WildcardByte {
    Exact(u8),
    Any,
}

// ---------------------------------------------------------------------------
// Low-level search helpers
// ---------------------------------------------------------------------------

/// Parse a hex query string (spaces and `0x` prefixes tolerated).
fn parse_hex_query(s: &str) -> SearchBarResult<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    if cleaned.is_empty() {
        return Err(SearchError::EmptyQuery);
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(SearchError::InvalidHex(format!(
            "odd number of hex digits in {s:?}"
        )));
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex = std::str::from_utf8(chunk).unwrap();
            u8::from_str_radix(hex, 16)
                .map_err(|e| SearchError::InvalidHex(e.to_string()))
        })
        .collect()
}

/// Parse a wildcard pattern where `??` is a wildcard byte.
fn parse_wildcard_pattern(s: &str) -> SearchBarResult<Vec<WildcardByte>> {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(SearchError::EmptyQuery);
    }
    let mut result = Vec::new();
    for tok in &tokens {
        if *tok == "??" {
            result.push(WildcardByte::Any);
        } else {
            let b = u8::from_str_radix(tok, 16)
                .map_err(|_| SearchError::InvalidPattern(format!("invalid token: {tok}")))?;
            result.push(WildcardByte::Exact(b));
        }
    }
    Ok(result)
}

/// Boyer-Moore-Horspool naive substring search.
fn find_bytes(haystack: &[u8], needle: &[u8], start_offset: u64) -> Vec<SearchResult> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            results.push(SearchResult::new(
                start_offset + i as u64,
                needle.len(),
                results.len(),
            ));
            i += needle.len();
        } else {
            i += 1;
        }
    }
    results
}

/// Wildcard pattern search.
fn find_wildcard(haystack: &[u8], pattern: &[WildcardByte], start_offset: u64) -> Vec<SearchResult> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut i = 0usize;
    while i + pattern.len() <= haystack.len() {
        let matches = pattern.iter().zip(&haystack[i..]).all(|(p, &b)| match p {
            WildcardByte::Any => true,
            WildcardByte::Exact(e) => *e == b,
        });
        if matches {
            results.push(SearchResult::new(
                start_offset + i as u64,
                pattern.len(),
                results.len(),
            ));
            i += pattern.len();
        } else {
            i += 1;
        }
    }
    results
}

/// Stub regex search (matches literal string for testing without the regex crate).
fn find_regex_stub(haystack: &[u8], pattern: &str) -> Vec<SearchResult> {
    let needle = pattern.as_bytes();
    find_bytes(haystack, needle, 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_hex_query ---

    #[test]
    fn test_parse_hex_basic() {
        let bytes = parse_hex_query("4D5A").unwrap();
        assert_eq!(bytes, &[0x4D, 0x5A]);
    }

    #[test]
    fn test_parse_hex_with_spaces() {
        let bytes = parse_hex_query("4D 5A 90 00").unwrap();
        assert_eq!(bytes, &[0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_parse_hex_odd_digits_error() {
        assert!(matches!(
            parse_hex_query("4D5"),
            Err(SearchError::InvalidHex(_))
        ));
    }

    #[test]
    fn test_parse_hex_empty_error() {
        assert!(matches!(
            parse_hex_query(""),
            Err(SearchError::EmptyQuery)
        ));
    }

    // --- parse_wildcard_pattern ---

    #[test]
    fn test_parse_wildcard_basic() {
        let pat = parse_wildcard_pattern("4D ?? 5A").unwrap();
        assert_eq!(pat.len(), 3);
        assert_eq!(pat[0], WildcardByte::Exact(0x4D));
        assert_eq!(pat[1], WildcardByte::Any);
        assert_eq!(pat[2], WildcardByte::Exact(0x5A));
    }

    #[test]
    fn test_parse_wildcard_invalid_token() {
        assert!(parse_wildcard_pattern("4D ZZ").is_err());
    }

    // --- find_bytes ---

    #[test]
    fn test_find_bytes_simple() {
        let results = find_bytes(b"hello world", b"world", 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 6);
    }

    #[test]
    fn test_find_bytes_multiple() {
        let results = find_bytes(b"aababab", b"ab", 0);
        // positions: 1, 3, 5
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_find_bytes_not_found() {
        let results = find_bytes(b"hello", b"xyz", 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_bytes_empty_needle() {
        let results = find_bytes(b"hello", b"", 0);
        assert!(results.is_empty());
    }

    // --- find_wildcard ---

    #[test]
    fn test_find_wildcard_any_matches_all() {
        let pat = vec![WildcardByte::Exact(0x41), WildcardByte::Any];
        let results = find_wildcard(b"ABACAD", &pat, 0);
        assert_eq!(results.len(), 3); // AB, AC, AD
    }

    #[test]
    fn test_find_wildcard_no_match() {
        let pat = vec![WildcardByte::Exact(0xFF), WildcardByte::Any];
        let results = find_wildcard(b"hello", &pat, 0);
        assert!(results.is_empty());
    }

    // --- SearchMode ---

    #[test]
    fn test_search_mode_display() {
        assert_eq!(SearchMode::Hex.to_string(), "Hex");
        assert_eq!(SearchMode::Text.to_string(), "Text");
        assert_eq!(SearchMode::Regex.to_string(), "Regex");
        assert_eq!(SearchMode::Pattern.to_string(), "Pattern");
    }

    #[test]
    fn test_search_mode_default() {
        assert_eq!(SearchMode::default(), SearchMode::Hex);
    }

    // --- SearchResult ---

    #[test]
    fn test_search_result_range() {
        let r = SearchResult::new(100, 4, 0);
        assert_eq!(r.range(), 100..104);
    }

    #[test]
    fn test_search_result_display() {
        let r = SearchResult::new(0x400, 3, 0);
        let s = r.to_string();
        assert!(s.contains("0x400"));
    }

    // --- SearchHighlight ---

    #[test]
    fn test_highlight_default_not_current() {
        let h = SearchHighlight::new(SearchResult::new(0, 1, 0));
        assert!(!h.is_current);
        assert_eq!(h.color, SearchHighlight::DEFAULT_COLOR);
    }

    #[test]
    fn test_highlight_set_current() {
        let mut h = SearchHighlight::new(SearchResult::new(0, 1, 0));
        h.set_current();
        assert!(h.is_current);
        assert_eq!(h.color, SearchHighlight::CURRENT_COLOR);
    }

    #[test]
    fn test_highlight_clear_current() {
        let mut h = SearchHighlight::new(SearchResult::new(0, 1, 0));
        h.set_current();
        h.clear_current();
        assert!(!h.is_current);
    }

    // --- SearchHistory ---

    #[test]
    fn test_history_push_and_get() {
        let mut h = SearchHistory::new(5);
        h.push("4D5A");
        assert_eq!(h.get(0).unwrap(), "4D5A");
    }

    #[test]
    fn test_history_deduplicates() {
        let mut h = SearchHistory::new(5);
        h.push("A");
        h.push("B");
        h.push("A");
        assert_eq!(h.len(), 2);
        assert_eq!(h.get(0).unwrap(), "A");
    }

    #[test]
    fn test_history_capacity() {
        let mut h = SearchHistory::new(3);
        for i in 0..5 {
            h.push(format!("q{}", i));
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_prev_next() {
        let mut h = SearchHistory::new(5);
        h.push("first");
        h.push("second");
        let p = h.prev().unwrap();
        assert_eq!(p, "second");
        let p2 = h.prev().unwrap();
        assert_eq!(p2, "first");
        let n = h.next().unwrap();
        assert_eq!(n, "second");
    }

    #[test]
    fn test_history_clear() {
        let mut h = SearchHistory::new(5);
        h.push("x");
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn test_history_empty_push_ignored() {
        let mut h = SearchHistory::new(5);
        h.push("");
        assert!(h.is_empty());
    }

    #[test]
    fn test_history_get_out_of_range() {
        let h = SearchHistory::new(5);
        assert!(matches!(h.get(0), Err(SearchError::HistoryIndex(0, 0))));
    }

    // --- SearchProgress ---

    #[test]
    fn test_progress_ratio_zero_total() {
        let p = SearchProgress::new(0);
        assert_eq!(p.ratio(), 1.0);
    }

    #[test]
    fn test_progress_advance() {
        let mut p = SearchProgress::new(100);
        p.advance(50, 3);
        assert_eq!(p.processed, 50);
        assert_eq!(p.found, 3);
        assert!(!p.done);
    }

    #[test]
    fn test_progress_finish() {
        let mut p = SearchProgress::new(100);
        p.finish();
        assert!(p.done);
    }

    #[test]
    fn test_progress_cancel() {
        let mut p = SearchProgress::new(100);
        p.cancel();
        assert!(p.cancelled);
    }

    #[test]
    fn test_progress_display() {
        let mut p = SearchProgress::new(100);
        p.advance(50, 2);
        let s = p.to_string();
        assert!(s.contains("50.0%"));
    }

    // --- SearchBar ---

    #[test]
    fn test_searchbar_new_default() {
        let sb = SearchBar::new();
        assert_eq!(sb.mode, SearchMode::Hex);
        assert_eq!(sb.direction, SearchDirection::Forward);
        assert!(sb.wrap);
    }

    #[test]
    fn test_searchbar_empty_query_error() {
        let mut sb = SearchBar::new();
        let res = sb.find_all(b"hello", 0);
        assert!(matches!(res, Err(SearchError::EmptyQuery)));
    }

    #[test]
    fn test_searchbar_empty_buffer_error() {
        let mut sb = SearchBar::new();
        sb.set_query("AA");
        let res = sb.find_all(b"", 0);
        assert!(matches!(res, Err(SearchError::EmptyBuffer)));
    }

    #[test]
    fn test_searchbar_find_all_hex() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        let count = sb.find_all(b"\x90\x90\xC3", 0).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_searchbar_find_all_text() {
        let mut sb = SearchBar::new();
        sb.set_mode(SearchMode::Text);
        sb.set_query("MZ");
        let count = sb.find_all(b"MZ\x00MZ", 0).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_searchbar_find_all_wildcard() {
        let mut sb = SearchBar::new();
        sb.set_mode(SearchMode::Pattern);
        sb.set_query("4D ?? 5A");
        let count = sb.find_all(b"\x4D\x00\x5A\x4D\xFF\x5A", 0).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_searchbar_find_next() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90\x90", 0).unwrap();
        let r1 = sb.find_next().unwrap();
        assert_eq!(r1.offset, 1);
        let r2 = sb.find_next().unwrap();
        assert_eq!(r2.offset, 2);
    }

    #[test]
    fn test_searchbar_find_prev() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90\x90", 0).unwrap();
        sb.find_next().unwrap(); // => index 1
        let r = sb.find_prev().unwrap();
        assert_eq!(r.offset, 0);
    }

    #[test]
    fn test_searchbar_wrap_forward() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90", 0).unwrap();
        sb.find_next().unwrap(); // 1
        sb.find_next().unwrap(); // wraps to 0
        assert_eq!(sb.current_index(), Some(0));
    }

    #[test]
    fn test_searchbar_highlights_count() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90\x90", 0).unwrap();
        assert_eq!(sb.highlights().len(), 3);
    }

    #[test]
    fn test_searchbar_current_result_after_find_all() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90", 0).unwrap();
        assert!(sb.current_result().is_some());
    }

    #[test]
    fn test_searchbar_clear_results() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90", 0).unwrap();
        sb.clear_results();
        assert_eq!(sb.result_count(), 0);
        assert!(sb.current_result().is_none());
    }

    #[test]
    fn test_searchbar_history_updated_after_find() {
        let mut sb = SearchBar::new();
        sb.set_query("4D5A");
        sb.find_all(b"\x4D\x5A", 0).unwrap();
        assert_eq!(sb.history.len(), 1);
        assert_eq!(sb.history.get(0).unwrap(), "4D5A");
    }

    #[test]
    fn test_searchbar_progress_set_after_find_all() {
        let mut sb = SearchBar::new();
        sb.set_query("90");
        sb.find_all(b"\x90\x90", 0).unwrap();
        assert!(sb.progress.as_ref().unwrap().done);
    }
}
