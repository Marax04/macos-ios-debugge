//! Multi-pattern scanner using an Aho-Corasick automaton for simultaneous
//! matching of many hex patterns against a byte buffer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Pattern, PatternByte};

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A single match produced by [`MultiPatternScanner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Index of the pattern that matched (into the original pattern list).
    pub pattern_index: usize,
    /// Optional name of the matched pattern.
    pub pattern_name: Option<String>,
    /// Byte offset in the input where the match starts.
    pub offset: usize,
    /// Length of the matched region in bytes.
    pub length: usize,
}

impl PatternMatch {
    /// Create a new match record.
    #[must_use]
    pub const fn new(
        pattern_index: usize,
        pattern_name: Option<String>,
        offset: usize,
        length: usize,
    ) -> Self {
        Self {
            pattern_index,
            pattern_name,
            offset,
            length,
        }
    }

    /// Return the exclusive end offset of this match.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset + self.length
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanResult
// ─────────────────────────────────────────────────────────────────────────────

/// The complete output of a [`MultiPatternScanner::scan`] call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// All matches found, in offset order.
    pub matches: Vec<PatternMatch>,
    /// Number of input bytes scanned.
    pub bytes_scanned: usize,
    /// Number of patterns registered in the scanner.
    pub pattern_count: usize,
}

impl ScanResult {
    /// Returns `true` if no matches were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Returns the total number of matches found.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Return all matches for a specific pattern index.
    #[must_use]
    pub fn matches_for(&self, pattern_index: usize) -> Vec<&PatternMatch> {
        self.matches
            .iter()
            .filter(|m| m.pattern_index == pattern_index)
            .collect()
    }

    /// Return all matches for a pattern with a given name.
    #[must_use]
    pub fn matches_by_name(&self, name: &str) -> Vec<&PatternMatch> {
        self.matches
            .iter()
            .filter(|m| m.pattern_name.as_deref() == Some(name))
            .collect()
    }

    /// Return matches sorted by pattern index, then by offset.
    #[must_use]
    pub fn sorted_by_pattern(&self) -> Vec<&PatternMatch> {
        let mut v: Vec<&PatternMatch> = self.matches.iter().collect();
        v.sort_unstable_by(|a, b| {
            a.pattern_index
                .cmp(&b.pattern_index)
                .then(a.offset.cmp(&b.offset))
        });
        v
    }

    /// Deduplicate overlapping matches (keep the longest at each offset).
    #[must_use]
    pub fn deduplicated(&self) -> ScanResult {
        let mut by_offset: HashMap<usize, &PatternMatch> = HashMap::new();
        for m in &self.matches {
            let entry = by_offset.entry(m.offset).or_insert(m);
            if m.length > entry.length {
                *entry = m;
            }
        }
        let mut matches: Vec<PatternMatch> = by_offset.values().map(|&m| m.clone()).collect();
        matches.sort_unstable_by_key(|m| m.offset);
        ScanResult {
            matches,
            bytes_scanned: self.bytes_scanned,
            pattern_count: self.pattern_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aho-Corasick state machine (for exact-byte patterns only)
// ─────────────────────────────────────────────────────────────────────────────

/// Internal Aho-Corasick node.
#[derive(Debug)]
struct AcNode {
    /// Transition table: children[byte] = next state index.
    children: [u32; 256],
    /// Failure link.
    fail: u32,
    /// Output: (`pattern_index`, `pattern_length`, name) for any patterns that end here.
    output: Vec<(usize, usize, Option<String>)>,
}

impl AcNode {
    const fn new() -> Self {
        Self {
            children: [u32::MAX; 256],
            fail: 0,
            output: Vec::new(),
        }
    }
}

/// Aho-Corasick automaton for multi-pattern exact-byte matching.
struct AhoCorasick {
    nodes: Vec<AcNode>,
}

impl AhoCorasick {
    /// Build the automaton from a list of `(bytes, pattern_index, name)` triples.
    fn build(patterns: &[(Vec<u8>, usize, Option<String>)]) -> Self {
        let mut nodes: Vec<AcNode> = vec![AcNode::new()]; // root = 0

        // Insert all patterns into the trie.
        for (bytes, idx, name) in patterns {
            let mut cur = 0u32;
            for &b in bytes {
                let b_usize = b as usize;
                if nodes[cur as usize].children[b_usize] == u32::MAX {
                    let next = nodes.len() as u32;
                    nodes[cur as usize].children[b_usize] = next;
                    nodes.push(AcNode::new());
                }
                cur = nodes[cur as usize].children[b_usize];
            }
            nodes[cur as usize]
                .output
                .push((*idx, bytes.len(), name.clone()));
        }

        // BFS to compute failure links and propagate outputs.
        let mut queue: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
        // Root's immediate children: fail = root.
        for b in 0..256u32 {
            let child = nodes[0].children[b as usize];
            if child != u32::MAX {
                nodes[child as usize].fail = 0;
                queue.push_back(child);
            } else {
                nodes[0].children[b as usize] = 0; // loop back to root
            }
        }

        while let Some(r) = queue.pop_front() {
            let r_usize = r as usize;
            for b in 0..256u32 {
                let child = nodes[r_usize].children[b as usize];
                if child != u32::MAX {
                    // Follow fail links to find child's fail state.
                    let mut fail = nodes[r_usize].fail;
                    while fail != 0 && nodes[fail as usize].children[b as usize] == u32::MAX {
                        fail = nodes[fail as usize].fail;
                    }
                    let fail_child = if nodes[fail as usize].children[b as usize] == u32::MAX {
                        0
                    } else {
                        nodes[fail as usize].children[b as usize]
                    };
                    let actual_fail = if fail_child == child { 0 } else { fail_child };
                    nodes[child as usize].fail = actual_fail;

                    // Propagate output from fail state.
                    let fail_out = nodes[actual_fail as usize].output.clone();
                    nodes[child as usize].output.extend(fail_out);

                    queue.push_back(child);
                } else {
                    // Fill in shortcut: missing transition goes to fail's child.
                    let mut fail = nodes[r_usize].fail;
                    while fail != 0 && nodes[fail as usize].children[b as usize] == u32::MAX {
                        fail = nodes[fail as usize].fail;
                    }
                    nodes[r_usize].children[b as usize] =
                        if nodes[fail as usize].children[b as usize] == u32::MAX {
                            0
                        } else {
                            nodes[fail as usize].children[b as usize]
                        };
                }
            }
        }

        Self { nodes }
    }

    /// Search `data` and return `(offset, pattern_index, pattern_len, name)` tuples.
    fn search<'a>(
        &'a self,
        data: &[u8],
    ) -> Vec<(usize, usize, usize, Option<String>)> {
        let mut result = Vec::new();
        let mut state = 0u32;
        for (i, &b) in data.iter().enumerate() {
            state = self.nodes[state as usize].children[b as usize];
            for (pat_idx, pat_len, name) in &self.nodes[state as usize].output {
                // i + 1 is the exclusive end of the match; pat_len comes from a
                // user-supplied pattern, so guard against underflow.
                let end = i + 1;
                if *pat_len > end {
                    // Pattern longer than bytes seen so far — skip (shouldn't
                    // happen in a correct AC automaton, but be safe).
                    continue;
                }
                let start = end - pat_len;
                result.push((start, *pat_idx, *pat_len, name.clone()));
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiPatternScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scan for multiple hex patterns simultaneously.
///
/// Patterns that consist entirely of exact bytes are accelerated using an
/// Aho-Corasick automaton.  Patterns that contain wildcards fall back to a
/// per-pattern linear scan (which is still correct, just slower).
///
/// # Example
/// ```
/// # use rustre_hex_pattern::{Pattern, multi_pattern_scanner::MultiPatternScanner};
/// let mut scanner = MultiPatternScanner::new();
/// scanner.add_pattern(Pattern::parse("DE AD").unwrap());
/// scanner.add_pattern(Pattern::parse("BE EF").unwrap());
/// let result = scanner.scan(&[0xDE, 0xAD, 0xBE, 0xEF]);
/// assert_eq!(result.match_count(), 2);
/// ```
pub struct MultiPatternScanner {
    /// All registered patterns.
    patterns: Vec<Pattern>,
    /// Indices of exact-only patterns (fed to Aho-Corasick).
    exact_indices: Vec<usize>,
    /// Indices of patterns containing wildcards (brute-force fallback).
    wildcard_indices: Vec<usize>,
    /// Pre-built Aho-Corasick automaton for exact patterns (built lazily).
    ac: Option<AhoCorasick>,
    /// Whether the automaton needs to be rebuilt.
    dirty: bool,
}

impl MultiPatternScanner {
    /// Create an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
            exact_indices: Vec::new(),
            wildcard_indices: Vec::new(),
            ac: None,
            dirty: false,
        }
    }

    /// Add a pattern to the scanner.
    ///
    /// Call [`scan`](Self::scan) afterwards; it will rebuild the automaton if needed.
    pub fn add_pattern(&mut self, pattern: Pattern) {
        let idx = self.patterns.len();
        let is_exact = pattern.bytes.iter().all(|b| matches!(b, PatternByte::Exact(_)));
        if is_exact {
            self.exact_indices.push(idx);
        } else {
            self.wildcard_indices.push(idx);
        }
        self.patterns.push(pattern);
        self.dirty = true;
    }

    /// Add multiple patterns at once.
    pub fn add_patterns(&mut self, patterns: impl IntoIterator<Item = Pattern>) {
        for p in patterns {
            self.add_pattern(p);
        }
    }

    /// Remove all patterns and reset the automaton.
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.exact_indices.clear();
        self.wildcard_indices.clear();
        self.ac = None;
        self.dirty = false;
    }

    /// Return the number of registered patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Rebuild the Aho-Corasick automaton from the current exact patterns.
    fn rebuild(&mut self) {
        if !self.dirty {
            return;
        }
        let triples: Vec<(Vec<u8>, usize, Option<String>)> = self
            .exact_indices
            .iter()
            .map(|&idx| {
                let p = &self.patterns[idx];
                let bytes: Vec<u8> = p
                    .bytes
                    .iter()
                    .map(|b| match b {
                        PatternByte::Exact(v) => *v,
                        _ => 0,
                    })
                    .collect();
                (bytes, idx, p.name.clone())
            })
            .collect();

        self.ac = if triples.is_empty() {
            None
        } else {
            Some(AhoCorasick::build(&triples))
        };
        self.dirty = false;
    }

    /// Scan `data` for all registered patterns and return a [`ScanResult`].
    pub fn scan(&mut self, data: &[u8]) -> ScanResult {
        self.rebuild();

        let mut matches: Vec<PatternMatch> = Vec::new();

        // Aho-Corasick pass for exact patterns.
        if let Some(ref ac) = self.ac {
            for (offset, pat_idx, pat_len, name) in ac.search(data) {
                matches.push(PatternMatch::new(pat_idx, name, offset, pat_len));
            }
        }

        // Brute-force pass for wildcard patterns.
        for &idx in &self.wildcard_indices {
            let p = &self.patterns[idx];
            for offset in p.search(data) {
                matches.push(PatternMatch::new(idx, p.name.clone(), offset, p.len()));
            }
        }

        // Sort by offset, then by pattern index for determinism.
        matches.sort_unstable_by(|a, b| a.offset.cmp(&b.offset).then(a.pattern_index.cmp(&b.pattern_index)));

        ScanResult {
            matches,
            bytes_scanned: data.len(),
            pattern_count: self.patterns.len(),
        }
    }

    /// Scan `data` in parallel chunks using rayon, merging results.
    ///
    /// Note: Aho-Corasick is not thread-safe during construction so this method
    /// rebuilds the automaton first in the calling thread, then fans out read-only
    /// scanning across chunks.
    pub fn scan_parallel(&mut self, data: &[u8], chunk_size: usize) -> ScanResult {
        use rayon::prelude::*;

        self.rebuild();

        let chunk_size = chunk_size.max(64);
        let pat_count = self.patterns.len();

        // Clone the pieces we need per-thread.
        let patterns: Vec<Pattern> = self.patterns.clone();
        let wildcard_indices: Vec<usize> = self.wildcard_indices.clone();
        let ac_ref = &self.ac;

        // Chunks must OVERLAP by `max_pattern_len - 1` bytes, otherwise a match
        // straddling a boundary belongs to no chunk and is silently lost — the
        // sequential `scan` finds it and this one did not.
        //
        // Each chunk still reports only the matches that START inside its own
        // `chunk_size` window, so the overlap cannot produce duplicates.
        let overlap = patterns
            .iter()
            .map(Pattern::len)
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        let chunks: Vec<(usize, &[u8], usize)> = (0..data.len())
            .step_by(chunk_size)
            .map(|base| {
                let end = base
                    .saturating_add(chunk_size)
                    .saturating_add(overlap)
                    .min(data.len());
                // How many bytes of this slice belong to the chunk proper.
                let own = chunk_size.min(data.len().saturating_sub(base));
                (base, &data[base..end], own)
            })
            .collect();

        let mut all_matches: Vec<PatternMatch> = chunks
            .par_iter()
            .flat_map(|(base_off, chunk, own_len)| {
                let mut local: Vec<PatternMatch> = Vec::new();
                // AC pass.
                if let Some(ac) = ac_ref {
                    for (off, pat_idx, pat_len, name) in ac.search(chunk) {
                        if off < *own_len {
                            local.push(PatternMatch::new(pat_idx, name, base_off + off, pat_len));
                        }
                    }
                }
                // Wildcard pass.
                for &idx in &wildcard_indices {
                    let p = &patterns[idx];
                    for off in p.search(chunk) {
                        if off < *own_len {
                            local.push(PatternMatch::new(idx, p.name.clone(), base_off + off, p.len()));
                        }
                    }
                }
                local
            })
            .collect();

        all_matches.sort_unstable_by(|a, b| {
            a.offset.cmp(&b.offset).then(a.pattern_index.cmp(&b.pattern_index))
        });
        all_matches.dedup_by(|a, b| a.offset == b.offset && a.pattern_index == b.pattern_index);

        ScanResult {
            matches: all_matches,
            bytes_scanned: data.len(),
            pattern_count: pat_count,
        }
    }

    /// Return an iterator over all registered patterns.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Look up a pattern by index.
    #[must_use]
    pub fn get_pattern(&self, idx: usize) -> Option<&Pattern> {
        self.patterns.get(idx)
    }
}

impl Default for MultiPatternScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> Pattern {
        Pattern::parse(s).unwrap()
    }

    fn scanner_with(patterns: &[&str]) -> MultiPatternScanner {
        let mut s = MultiPatternScanner::new();
        for &p in patterns {
            s.add_pattern(pat(p));
        }
        s
    }

    #[test]
    fn test_single_exact_pattern() {
        let mut sc = scanner_with(&["DE AD"]);
        let data = [0x00, 0xDE, 0xAD, 0x00];
        let result = sc.scan(&data);
        assert_eq!(result.match_count(), 1);
        assert_eq!(result.matches[0].offset, 1);
    }

    #[test]
    fn test_two_exact_patterns() {
        let mut sc = scanner_with(&["DE AD", "BE EF"]);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = sc.scan(&data);
        assert_eq!(result.match_count(), 2);
        let offsets: Vec<usize> = result.matches.iter().map(|m| m.offset).collect();
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&2));
    }

    #[test]
    fn test_wildcard_pattern() {
        let mut sc = scanner_with(&["DE ?? EF"]);
        let data = [0xDE, 0xAA, 0xEF, 0xFF, 0xDE, 0xBB, 0xEF];
        let result = sc.scan(&data);
        assert_eq!(result.match_count(), 2);
        assert_eq!(result.matches[0].offset, 0);
        assert_eq!(result.matches[1].offset, 4);
    }

    #[test]
    fn test_mixed_exact_and_wildcard() {
        let mut sc = scanner_with(&["AA BB", "CC ?? DD"]);
        let data = [0xCC, 0x11, 0xDD, 0x00, 0xAA, 0xBB];
        let result = sc.scan(&data);
        assert_eq!(result.match_count(), 2);
    }

    #[test]
    fn test_no_matches() {
        let mut sc = scanner_with(&["FF FF FF"]);
        let data = [0x00; 8];
        let result = sc.scan(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn test_pattern_count() {
        let sc = scanner_with(&["AA", "BB CC", "?? DD"]);
        assert_eq!(sc.pattern_count(), 3);
    }

    #[test]
    fn test_matches_for_index() {
        let mut sc = scanner_with(&["AA", "BB"]);
        let data = [0xAA, 0xBB, 0xAA];
        let result = sc.scan(&data);
        let aa_matches = result.matches_for(0);
        assert_eq!(aa_matches.len(), 2);
    }

    #[test]
    fn test_pattern_name_propagated() {
        let mut sc = MultiPatternScanner::new();
        sc.add_pattern(pat("DE AD").with_name("deadbeef"));
        let data = [0xDE, 0xAD];
        let result = sc.scan(&data);
        assert_eq!(result.matches[0].pattern_name.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_scan_result_sorted_by_offset() {
        let mut sc = scanner_with(&["EE", "AA", "BB"]);
        let data = [0xAA, 0xBB, 0xEE];
        let result = sc.scan(&data);
        let offsets: Vec<usize> = result.matches.iter().map(|m| m.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn test_deduplicated() {
        let mut sc = scanner_with(&["AA", "AA BB"]);
        let data = [0xAA, 0xBB];
        let result = sc.scan(&data);
        // Both patterns match at offset 0; deduplicated keeps the longer one.
        let dedup = result.deduplicated();
        assert_eq!(dedup.matches_for(0).len() + dedup.matches_for(1).len(), 1);
    }

    #[test]
    fn test_scan_result_bytes_scanned() {
        let mut sc = scanner_with(&["AA"]);
        let data = [0x00; 100];
        let result = sc.scan(&data);
        assert_eq!(result.bytes_scanned, 100);
    }

    #[test]
    fn test_clear() {
        let mut sc = scanner_with(&["AA BB"]);
        sc.clear();
        assert_eq!(sc.pattern_count(), 0);
        let result = sc.scan(&[0xAA, 0xBB]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_matches_by_name() {
        let mut sc = MultiPatternScanner::new();
        sc.add_pattern(pat("AA").with_name("alpha"));
        sc.add_pattern(pat("BB").with_name("beta"));
        let data = [0xAA, 0xBB, 0xAA];
        let result = sc.scan(&data);
        assert_eq!(result.matches_by_name("alpha").len(), 2);
        assert_eq!(result.matches_by_name("beta").len(), 1);
    }

    #[test]
    fn test_pattern_match_end() {
        let m = PatternMatch::new(0, None, 5, 3);
        assert_eq!(m.end(), 8);
    }

    #[test]
    fn test_sorted_by_pattern() {
        let mut sc = scanner_with(&["EE", "AA"]);
        let data = [0xAA, 0xEE];
        let result = sc.scan(&data);
        let sorted = result.sorted_by_pattern();
        // Pattern 0 (EE) at offset 1, pattern 1 (AA) at offset 0.
        assert_eq!(sorted[0].pattern_index, 0);
        assert_eq!(sorted[1].pattern_index, 1);
    }
}
