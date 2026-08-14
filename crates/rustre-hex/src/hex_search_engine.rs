//! Hex pattern search engine for `rustre-hex`.
//!
//! Provides:
//! - [`SearchPattern`]: exact/wildcard/regex search patterns.
//! - [`BoyerMoore`]: Boyer-Moore-Horspool hex search.
//! - [`AhoCorasick`]: Aho-Corasick multi-pattern search.
//! - [`SearchResult`]: `offset/length/pattern_name` per match.
//! - [`SearchSession`]: incremental search over large files (chunked).
//! - [`PatternHighlighter`]: maps search results to color highlights.
//! - [`HexSearchEngine`]: high-level facade.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SearchPattern
// ---------------------------------------------------------------------------

/// The matching mode for a hex search pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternKind {
    /// Exact sequence of bytes — no wildcards.
    Exact(Vec<u8>),
    /// Byte sequence with wildcards (`None` = any byte).
    Wildcard(Vec<Option<u8>>),
    /// ASCII regex applied to the raw bytes.
    Regex(String),
}

impl PatternKind {
    /// Try to parse a hex string with optional `??` wildcards into a
    /// `Wildcard` pattern.  Returns `None` on parse error.
    ///
    /// Input: `"DE AD ?? BE EF"` → `[Some(0xDE), Some(0xAD), None, Some(0xBE), Some(0xEF)]`
    ///
    /// # Panics
    ///
    /// Panics if internal logic produces an unexpected `None` in an all-`Some` byte list
    /// (this is unreachable in practice).
    #[must_use]
    pub fn from_hex_str(s: &str) -> Option<Self> {
        let mut bytes: Vec<Option<u8>> = Vec::new();
        for token in s.split_whitespace() {
            if token == "??" || token == "?" || token == ".." {
                bytes.push(None);
            } else {
                let b = u8::from_str_radix(token, 16).ok()?;
                bytes.push(Some(b));
            }
        }
        if bytes.is_empty() {
            return None;
        }
        if bytes.iter().all(std::option::Option::is_some) {
            Some(Self::Exact(bytes.into_iter().map(|b| b.unwrap()).collect()))
        } else {
            Some(Self::Wildcard(bytes))
        }
    }

    /// Pattern length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Exact(b) => b.len(),
            Self::Wildcard(b) => b.len(),
            Self::Regex(_) => 0,
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A named search pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPattern {
    pub name: String,
    pub kind: PatternKind,
    /// Color hint for highlighting (HTML hex color like `#FF0000`).
    pub color: String,
}

impl SearchPattern {
    /// Create an exact-bytes pattern from a hex string.
    ///
    /// # Errors
    /// Returns `None` if the hex string is invalid.
    #[must_use]
    pub fn from_hex(name: impl Into<String>, hex: &str) -> Option<Self> {
        let kind = PatternKind::from_hex_str(hex)?;
        Some(Self {
            name: name.into(),
            kind,
            color: "#FF0000".to_string(),
        })
    }

    /// Create a pattern from raw bytes (no wildcards).
    #[must_use]
    pub fn from_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            kind: PatternKind::Exact(bytes),
            color: "#FF0000".to_string(),
        }
    }

    /// Create a regex pattern.
    #[must_use]
    pub fn regex(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: PatternKind::Regex(pattern.into()),
            color: "#0000FF".to_string(),
        }
    }

    /// Set the highlight color.
    #[must_use]
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = color.into();
        self
    }
}

// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// A single match found in the data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Byte offset of the match.
    pub offset: u64,
    /// Length of the match in bytes.
    pub length: usize,
    /// Name of the pattern that matched.
    pub pattern_name: String,
    /// The matched bytes (if the length ≤ 64, otherwise empty).
    pub matched_bytes: Vec<u8>,
}

impl SearchResult {
    #[must_use]
    pub fn new(
        offset: u64,
        length: usize,
        pattern_name: impl Into<String>,
        matched: Vec<u8>,
    ) -> Self {
        Self {
            offset,
            length,
            pattern_name: pattern_name.into(),
            matched_bytes: matched,
        }
    }

    /// End offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset + self.length as u64
    }
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Match[{}] @ {:#010x} len={}",
            self.pattern_name, self.offset, self.length
        )
    }
}

// ---------------------------------------------------------------------------
// BoyerMoore
// ---------------------------------------------------------------------------

/// Boyer-Moore-Horspool single-pattern search.
pub struct BoyerMoore {
    pattern: Vec<u8>,
    bad_char: [usize; 256],
}

impl BoyerMoore {
    /// Build the search automaton for `pattern`.
    ///
    /// # Panics
    /// Panics if `pattern` is empty.
    #[must_use]
    pub fn new(pattern: Vec<u8>) -> Self {
        assert!(!pattern.is_empty(), "pattern must be non-empty");
        let m = pattern.len();
        let mut bad_char = [m; 256];
        for i in 0..m - 1 {
            bad_char[pattern[i] as usize] = m - 1 - i;
        }
        Self { pattern, bad_char }
    }

    /// Search `data` and return all match offsets.
    #[must_use]
    pub fn search_all(&self, data: &[u8]) -> Vec<usize> {
        let m = self.pattern.len();
        if data.len() < m {
            return Vec::new();
        }
        let mut matches = Vec::new();
        let mut i = m - 1;
        while i < data.len() {
            let mut j = m - 1;
            let mut k = i;
            while data[k] == self.pattern[j] {
                if j == 0 {
                    matches.push(k);
                    break;
                }
                k -= 1;
                j -= 1;
            }
            i += self.bad_char[data[i] as usize];
        }
        matches
    }

    /// Pattern length.
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        self.pattern.len()
    }
}

// ---------------------------------------------------------------------------
// AhoCorasick (simplified)
// ---------------------------------------------------------------------------

/// Simplified Aho-Corasick node.
#[derive(Debug, Clone)]
struct AcNode {
    children: [Option<usize>; 256],
    fail: usize,
    output: Vec<usize>, // pattern indices
}

impl Default for AcNode {
    fn default() -> Self {
        Self {
            children: [None; 256],
            fail: 0,
            output: Vec::new(),
        }
    }
}

/// Aho-Corasick multi-pattern search (exact bytes only).
pub struct AhoCorasick {
    nodes: Vec<AcNode>,
    patterns: Vec<Vec<u8>>,
}

impl AhoCorasick {
    /// Build automaton from `patterns`.
    ///
    /// # Panics
    ///
    /// Panics if the automaton's internal node index is `None` after insertion
    /// (this is unreachable in correct usage).
    #[must_use]
    pub fn build(patterns: Vec<Vec<u8>>) -> Self {
        let mut nodes = vec![AcNode::default()];
        // Insert all patterns.
        for (idx, pat) in patterns.iter().enumerate() {
            let mut cur = 0;
            for &b in pat {
                let b = b as usize;
                if nodes[cur].children[b].is_none() {
                    nodes[cur].children[b] = Some(nodes.len());
                    nodes.push(AcNode::default());
                }
                cur = nodes[cur].children[b].unwrap();
            }
            nodes[cur].output.push(idx);
        }

        // BFS to set fail links.
        let mut queue = std::collections::VecDeque::new();
        for b in 0..256 {
            if let Some(child) = nodes[0].children[b] {
                nodes[child].fail = 0;
                queue.push_back(child);
            }
        }
        while let Some(u) = queue.pop_front() {
            let fail_u = nodes[u].fail;
            let out: Vec<usize> = nodes[fail_u].output.clone();
            nodes[u].output.extend(out);
            for b in 0..256usize {
                if let Some(v) = nodes[u].children[b] {
                    let mut f = fail_u;
                    while f != 0 && nodes[f].children[b].is_none() {
                        f = nodes[f].fail;
                    }
                    nodes[v].fail = nodes[f].children[b].unwrap_or(0);
                    if nodes[v].fail == v {
                        nodes[v].fail = 0;
                    }
                    let out: Vec<usize> = nodes[nodes[v].fail].output.clone();
                    nodes[v].output.extend(out);
                    nodes[v].output.dedup();
                    queue.push_back(v);
                }
            }
        }

        Self { nodes, patterns }
    }

    /// Search `data` for all pattern occurrences.
    /// Returns `(offset, pattern_index)` pairs.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut cur = 0;
        let mut results = Vec::new();
        for (i, &b) in data.iter().enumerate() {
            let b = b as usize;
            while cur != 0 && self.nodes[cur].children[b].is_none() {
                cur = self.nodes[cur].fail;
            }
            if let Some(next) = self.nodes[cur].children[b] {
                cur = next;
            }
            for &pat_idx in &self.nodes[cur].output {
                let pat_len = self.patterns[pat_idx].len();
                let offset = (i + 1).saturating_sub(pat_len);
                results.push((offset, pat_idx));
            }
        }
        results
    }

    /// Number of patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ---------------------------------------------------------------------------
// SearchSession (incremental / large file)
// ---------------------------------------------------------------------------

/// State for an incremental search session over a large file.
pub struct SearchSession {
    patterns: Vec<SearchPattern>,
    pub results: Vec<SearchResult>,
    /// Bytes processed so far.
    pub bytes_processed: u64,
    /// Chunk size for processing.
    pub chunk_size: usize,
    /// Overlap between chunks (to catch patterns spanning chunk boundaries).
    pub overlap: usize,
}

impl SearchSession {
    #[must_use]
    pub fn new(patterns: Vec<SearchPattern>) -> Self {
        let max_pat_len = patterns.iter().map(|p| p.kind.len()).max().unwrap_or(0);
        Self {
            patterns,
            results: Vec::new(),
            bytes_processed: 0,
            chunk_size: 64 * 1024,
            overlap: max_pat_len.max(1),
        }
    }

    /// Process a chunk of data starting at `base_offset`.
    pub fn process_chunk(&mut self, data: &[u8], base_offset: u64) {
        let engine = HexSearchEngine::new(self.patterns.clone());
        let chunk_results = engine.search(data, base_offset);
        // Deduplicate (overlap may produce duplicate results) using a HashSet
        // keyed on (offset, pattern_name) to avoid quadratic scans.
        let mut seen: std::collections::HashSet<(u64, String)> = self
            .results
            .iter()
            .map(|r| (r.offset, r.pattern_name.clone()))
            .collect();
        self.results.reserve(chunk_results.len());
        for r in chunk_results {
            if r.offset >= base_offset
                && seen.insert((r.offset, r.pattern_name.clone()))
            {
                self.results.push(r);
            }
        }
        self.bytes_processed += data.len() as u64;
    }

    /// Sort results by offset.
    pub fn sort_results(&mut self) {
        self.results.sort_by_key(|r| r.offset);
    }

    /// Number of results found.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// PatternHighlighter
// ---------------------------------------------------------------------------

/// A highlighted span in the hex view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Highlight {
    pub offset: u64,
    pub length: usize,
    pub color: String,
    pub tooltip: String,
}

/// Maps search results to highlight spans.
#[derive(Debug, Default)]
pub struct PatternHighlighter {
    pub highlights: Vec<Highlight>,
}

impl PatternHighlighter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate highlights from search results and a pattern color map.
    pub fn highlight_results(
        &mut self,
        results: &[SearchResult],
        color_map: &HashMap<String, String>,
    ) {
        for r in results {
            let color = color_map
                .get(&r.pattern_name).cloned()
                .unwrap_or_else(|| "#FFFF00".to_string());
            self.highlights.push(Highlight {
                offset: r.offset,
                length: r.length,
                color,
                tooltip: format!("{} @ {:#x}", r.pattern_name, r.offset),
            });
        }
    }

    /// Return highlights overlapping with `[start, end)`.
    #[must_use]
    pub fn in_range(&self, start: u64, end: u64) -> Vec<&Highlight> {
        self.highlights
            .iter()
            .filter(|h| h.offset < end && h.offset + h.length as u64 > start)
            .collect()
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }
}

// ---------------------------------------------------------------------------
// HexSearchEngine
// ---------------------------------------------------------------------------

/// High-level hex pattern search engine.
pub struct HexSearchEngine {
    pub patterns: Vec<SearchPattern>,
}

impl HexSearchEngine {
    /// Create a new engine with the given patterns.
    #[must_use]
    pub const fn new(patterns: Vec<SearchPattern>) -> Self {
        Self { patterns }
    }

    /// Add a pattern.
    pub fn add_pattern(&mut self, pat: SearchPattern) {
        self.patterns.push(pat);
    }

    /// Number of patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Search `data` starting at `base_offset` and return all matches.
    #[must_use]
    pub fn search(&self, data: &[u8], base_offset: u64) -> Vec<SearchResult> {
        let mut results = Vec::new();
        for pat in &self.patterns {
            match &pat.kind {
                PatternKind::Exact(bytes) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    let bm = BoyerMoore::new(bytes.clone());
                    for off in bm.search_all(data) {
                        let matched = data[off..off + bytes.len()].to_vec();
                        results.push(SearchResult::new(
                            base_offset + off as u64,
                            bytes.len(),
                            &pat.name,
                            matched,
                        ));
                    }
                }
                PatternKind::Wildcard(bytes) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    let len = bytes.len();
                    for off in 0..data.len().saturating_sub(len - 1) {
                        if bytes
                            .iter()
                            .enumerate()
                            .all(|(i, b)| b.is_none_or(|v| data[off + i] == v))
                        {
                            let matched = if len <= 64 {
                                data[off..off + len].to_vec()
                            } else {
                                Vec::new()
                            };
                            results.push(SearchResult::new(
                                base_offset + off as u64,
                                len,
                                &pat.name,
                                matched,
                            ));
                        }
                    }
                }
                PatternKind::Regex(re_str) => {
                    // Simple ASCII regex: search for literal string.
                    let pat_bytes = re_str.as_bytes();
                    if pat_bytes.is_empty() {
                        continue;
                    }
                    // Naive search.
                    for off in 0..data.len().saturating_sub(pat_bytes.len() - 1) {
                        if &data[off..off + pat_bytes.len()] == pat_bytes {
                            let matched = data[off..off + pat_bytes.len()].to_vec();
                            results.push(SearchResult::new(
                                base_offset + off as u64,
                                pat_bytes.len(),
                                &pat.name,
                                matched,
                            ));
                        }
                    }
                }
            }
        }
        results.sort_by_key(|r| r.offset);
        results
    }

    /// Search using Aho-Corasick for multiple exact patterns simultaneously.
    #[must_use]
    pub fn search_multi_exact(&self, data: &[u8], base_offset: u64) -> Vec<SearchResult> {
        let exact_pats: Vec<(usize, &SearchPattern)> = self
            .patterns
            .iter()
            .enumerate()
            .filter(|(_, p)| matches!(p.kind, PatternKind::Exact(_)))
            .collect();
        if exact_pats.is_empty() {
            return Vec::new();
        }

        let bytes_list: Vec<Vec<u8>> = exact_pats
            .iter()
            .map(|(_, p)| {
                if let PatternKind::Exact(b) = &p.kind {
                    b.clone()
                } else {
                    Vec::new()
                }
            })
            .collect();

        let ac = AhoCorasick::build(bytes_list);
        let ac_results = ac.search(data);
        ac_results
            .into_iter()
            .map(|(off, pat_idx)| {
                let pat = exact_pats[pat_idx].1;
                let len = if let PatternKind::Exact(b) = &pat.kind {
                    b.len()
                } else {
                    0
                };
                let matched = if len <= 64 {
                    data[off..off + len].to_vec()
                } else {
                    Vec::new()
                };
                SearchResult::new(base_offset + off as u64, len, &pat.name, matched)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> HexSearchEngine {
        HexSearchEngine::new(vec![])
    }

    // ── PatternKind ───────────────────────────────────────────────────────

    #[test]
    fn pattern_kind_from_hex_exact() {
        let k = PatternKind::from_hex_str("DE AD BE EF").unwrap();
        assert!(matches!(k, PatternKind::Exact(_)));
        assert_eq!(k.len(), 4);
    }

    #[test]
    fn pattern_kind_from_hex_wildcard() {
        let k = PatternKind::from_hex_str("DE ?? BE EF").unwrap();
        assert!(matches!(k, PatternKind::Wildcard(_)));
        if let PatternKind::Wildcard(b) = &k {
            assert_eq!(b[1], None);
        }
    }

    #[test]
    fn pattern_kind_from_hex_invalid() {
        assert!(PatternKind::from_hex_str("ZZ").is_none());
    }

    #[test]
    fn pattern_kind_empty() {
        assert!(PatternKind::from_hex_str("").is_none());
    }

    // ── SearchPattern ─────────────────────────────────────────────────────

    #[test]
    fn search_pattern_from_hex() {
        let p = SearchPattern::from_hex("test", "55 8B EC").unwrap();
        assert_eq!(p.name, "test");
        assert_eq!(p.kind.len(), 3);
    }

    #[test]
    fn search_pattern_from_bytes() {
        let p = SearchPattern::from_bytes("raw", vec![1, 2, 3]);
        assert!(matches!(p.kind, PatternKind::Exact(_)));
    }

    #[test]
    fn search_pattern_regex() {
        let p = SearchPattern::regex("re_pattern", "MZ");
        assert!(matches!(p.kind, PatternKind::Regex(_)));
    }

    #[test]
    fn search_pattern_with_color() {
        let p = SearchPattern::from_bytes("p", vec![]).with_color("#00FF00");
        assert_eq!(p.color, "#00FF00");
    }

    // ── BoyerMoore ────────────────────────────────────────────────────────

    #[test]
    fn bm_finds_single_match() {
        let bm = BoyerMoore::new(b"AB".to_vec());
        let data = b"XYZABWWW";
        let matches = bm.search_all(data);
        assert_eq!(matches, vec![3]);
    }

    #[test]
    fn bm_finds_multiple_matches() {
        let bm = BoyerMoore::new(b"AA".to_vec());
        let data = b"AAXAAYZAA";
        let matches = bm.search_all(data);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn bm_no_match() {
        let bm = BoyerMoore::new(b"ZZ".to_vec());
        let data = b"ABCDEF";
        assert!(bm.search_all(data).is_empty());
    }

    #[test]
    fn bm_pattern_len() {
        let bm = BoyerMoore::new(b"HELLO".to_vec());
        assert_eq!(bm.pattern_len(), 5);
    }

    // ── AhoCorasick ───────────────────────────────────────────────────────

    #[test]
    fn ac_single_pattern() {
        let ac = AhoCorasick::build(vec![b"AB".to_vec()]);
        let results = ac.search(b"XABX");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (1, 0));
    }

    #[test]
    fn ac_multiple_patterns() {
        let ac = AhoCorasick::build(vec![b"AB".to_vec(), b"CD".to_vec()]);
        let results = ac.search(b"ABCD");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn ac_no_match() {
        let ac = AhoCorasick::build(vec![b"ZZ".to_vec()]);
        assert!(ac.search(b"ABCDEF").is_empty());
    }

    #[test]
    fn ac_pattern_count() {
        let ac = AhoCorasick::build(vec![b"A".to_vec(), b"B".to_vec()]);
        assert_eq!(ac.pattern_count(), 2);
    }

    // ── HexSearchEngine ───────────────────────────────────────────────────

    #[test]
    fn engine_exact_search() {
        let mut e = make_engine();
        e.add_pattern(SearchPattern::from_bytes("MZ", vec![0x4D, 0x5A]));
        let data = vec![0x00u8, 0x4D, 0x5A, 0xFF];
        let results = e.search(&data, 0x1000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0x1001);
        assert_eq!(results[0].pattern_name, "MZ");
    }

    #[test]
    fn engine_wildcard_search() {
        let mut e = make_engine();
        let pat = SearchPattern::from_hex("prologue", "55 ?? EC").unwrap();
        e.add_pattern(pat);
        let data = vec![0x55u8, 0x8B, 0xEC, 0x00];
        let results = e.search(&data, 0);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn engine_no_match() {
        let mut e = make_engine();
        e.add_pattern(SearchPattern::from_bytes("xx", vec![0xAA, 0xBB]));
        let data = vec![0x00u8; 16];
        assert!(e.search(&data, 0).is_empty());
    }

    #[test]
    fn engine_multi_exact() {
        let mut e = make_engine();
        e.add_pattern(SearchPattern::from_bytes("A", b"HELLO".to_vec()));
        e.add_pattern(SearchPattern::from_bytes("B", b"WORLD".to_vec()));
        let data = b"HELLO WORLD";
        let results = e.search_multi_exact(data, 0);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn engine_pattern_count() {
        let mut e = make_engine();
        assert_eq!(e.pattern_count(), 0);
        e.add_pattern(SearchPattern::from_bytes("x", vec![]));
        assert_eq!(e.pattern_count(), 1);
    }

    // ── SearchResult ──────────────────────────────────────────────────────

    #[test]
    fn search_result_end() {
        let r = SearchResult::new(0x1000, 8, "p", vec![]);
        assert_eq!(r.end(), 0x1008);
    }

    #[test]
    fn search_result_display() {
        let r = SearchResult::new(0x1000, 4, "test", vec![]);
        let s = r.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("1000"));
    }

    // ── SearchSession ─────────────────────────────────────────────────────

    #[test]
    fn search_session_process_chunk() {
        let patterns = vec![SearchPattern::from_bytes("X", b"HELLO".to_vec())];
        let mut session = SearchSession::new(patterns);
        let data = b"GET HELLO WORLD";
        session.process_chunk(data, 0x1000);
        assert!(session.match_count() >= 1);
    }

    #[test]
    fn search_session_bytes_processed() {
        let patterns = vec![];
        let mut session = SearchSession::new(patterns);
        session.process_chunk(b"ABCDEF", 0);
        assert_eq!(session.bytes_processed, 6);
    }

    // ── PatternHighlighter ────────────────────────────────────────────────

    #[test]
    fn highlighter_in_range() {
        let mut h = PatternHighlighter::new();
        let results = vec![SearchResult::new(0x100, 4, "p", vec![])];
        let mut color_map = HashMap::new();
        color_map.insert("p".to_string(), "#FF0000".to_string());
        h.highlight_results(&results, &color_map);
        let in_range = h.in_range(0x100, 0x104);
        assert_eq!(in_range.len(), 1);
    }

    #[test]
    fn highlighter_out_of_range() {
        let mut h = PatternHighlighter::new();
        let results = vec![SearchResult::new(0x200, 4, "p", vec![])];
        let color_map = HashMap::new();
        h.highlight_results(&results, &color_map);
        let in_range = h.in_range(0x100, 0x104);
        assert!(in_range.is_empty());
    }

    #[test]
    fn highlighter_clear() {
        let mut h = PatternHighlighter::new();
        let results = vec![SearchResult::new(0, 1, "p", vec![])];
        h.highlight_results(&results, &HashMap::new());
        h.clear();
        assert!(h.highlights.is_empty());
    }
}
