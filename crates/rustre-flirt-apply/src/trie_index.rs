//! Prefix trie for fast FLIRT pattern lookup.
//!
//! A [`PatternTrie`] indexes [`crate::FlirtPattern`]s by their leading bytes
//! so that a search over `n` patterns can often be completed in O(k) time
//! rather than O(n·k), where k is the pattern length.

use ahash::AHashMap;

use crate::FlirtPattern;
use crate::casts::usize_to_f64;

// ── TrieNodeData ──────────────────────────────────────────────────────────────

/// One node in the flat-arena trie.
///
/// Keys 0–255 represent concrete byte values; key 256 represents a wildcard
/// edge that matches any byte.
///
/// Uses `AHashMap` (randomised hash) instead of `std::collections::HashMap` to
/// prevent an adversarial `.sig` / `.pat` file from triggering hash-collision
/// `DoS` through crafted byte-key sequences.
#[derive(Debug, Default)]
pub struct TrieNodeData {
    /// Children of this node: key → child node index in the arena.
    pub children: AHashMap<u16, usize>,
    /// Indices (into the original pattern slice) of patterns that terminate here.
    pub pattern_indices: Vec<usize>,
}

// ── PatternTrie ───────────────────────────────────────────────────────────────

/// An arena-based prefix trie over `Vec<Option<u8>>` patterns.
///
/// - `None` bytes are routed through the wildcard edge (key 256).
/// - `Some(b)` bytes are routed through the exact byte edge (key `b as u16`).
pub struct PatternTrie {
    nodes: Vec<TrieNodeData>,
    pattern_indices: Vec<Vec<usize>>,
}

impl PatternTrie {
    /// Create an empty trie (just a root node).
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: vec![TrieNodeData::default()],
            pattern_indices: Vec::new(),
        }
    }

    /// Insert a pattern into the trie.
    ///
    /// `pattern_idx` is the index that will be returned when this pattern is
    /// found during a search.
    pub fn insert(&mut self, pattern: &[Option<u8>], pattern_idx: usize) {
        let mut node_idx = 0usize; // start at root
        for opt_byte in pattern {
            let key: u16 = opt_byte.as_ref().map_or(256, |b| u16::from(*b));

            let next_idx = if let Some(&child) = self.nodes[node_idx].children.get(&key) {
                child
            } else {
                let new_idx = self.nodes.len();
                self.nodes.push(TrieNodeData::default());
                self.nodes[node_idx].children.insert(key, new_idx);
                new_idx
            };
            node_idx = next_idx;
        }
        self.nodes[node_idx].pattern_indices.push(pattern_idx);
    }

    /// Search `data` for all positions where any indexed pattern matches.
    ///
    /// Returns a list of `(byte_offset_in_data, pattern_idx)` pairs.
    /// For each start position in `data`, the trie is traversed depth-first
    /// following exact-byte and wildcard edges simultaneously.
    ///
    /// **Note:** this method scans every start offset — for production use,
    /// prefer [`ApplyEngine::scan_buffer`] which restricts to known function
    /// starts.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();

        for start in 0..data.len() {
            self.search_at(data, start, &mut results);
        }

        results
    }

    /// Collect all patterns that match `data` starting at `offset`.
    #[must_use]
    pub fn search_at_offset(&self, data: &[u8], offset: usize) -> Vec<usize> {
        let mut results = Vec::new();
        self.search_at(data, offset, &mut results);
        results.into_iter().map(|(_, idx)| idx).collect()
    }

    fn search_at(&self, data: &[u8], start: usize, results: &mut Vec<(usize, usize)>) {
        // Stack: (node_index, data_cursor)
        let mut stack: Vec<(usize, usize)> = vec![(0, start)];

        while let Some((node_idx, cursor)) = stack.pop() {
            let node = &self.nodes[node_idx];

            // Emit patterns that end at this node.
            for &pat_idx in &node.pattern_indices {
                results.push((start, pat_idx));
            }

            if cursor >= data.len() {
                continue;
            }

            let byte = data[cursor];

            // Follow exact edge.
            if let Some(&child_idx) = node.children.get(&(u16::from(byte))) {
                stack.push((child_idx, cursor + 1));
            }

            // Follow wildcard edge.
            if let Some(&child_idx) = node.children.get(&256u16) {
                stack.push((child_idx, cursor + 1));
            }
        }
    }

    /// Build a trie from a slice of patterns.
    ///
    /// Each pattern's `bytes` field is used as the key sequence.
    #[must_use]
    pub fn build_from_patterns(patterns: &[FlirtPattern]) -> Self {
        let mut trie = Self::new();
        for (idx, pat) in patterns.iter().enumerate() {
            trie.insert(&pat.bytes, idx);
        }
        trie.pattern_indices = (0..patterns.len()).map(|i| vec![i]).collect();
        trie
    }

    /// Return statistics about this trie.
    #[must_use]
    pub fn stats(&self) -> TrieStats {
        let node_count = self.nodes.len();
        let pattern_count: usize = self.nodes.iter().map(|n| n.pattern_indices.len()).sum();

        // Compute average depth by traversing all patterns.
        let total_depth: usize = self
            .nodes
            .iter()
            .enumerate()
            .flat_map(|(idx, n)| {
                let depth = self.node_depth(idx);
                n.pattern_indices.iter().map(move |_| depth)
            })
            .sum();

        let avg_depth = if pattern_count == 0 {
            0.0
        } else {
            usize_to_f64(total_depth) / usize_to_f64(pattern_count)
        };

        TrieStats {
            node_count,
            pattern_count,
            avg_depth,
        }
    }

    /// Compute the depth of a node by searching backwards from root.
    fn node_depth(&self, target: usize) -> usize {
        if target == 0 {
            return 0;
        }
        // BFS from root to find depth
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((0usize, 0usize));
        while let Some((node_idx, depth)) = queue.pop_front() {
            for &child_idx in self.nodes[node_idx].children.values() {
                if child_idx == target {
                    return depth + 1;
                }
                queue.push_back((child_idx, depth + 1));
            }
        }
        0
    }
}

impl Default for PatternTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ── TrieStats ─────────────────────────────────────────────────────────────────

/// Statistics about a [`PatternTrie`].
#[derive(Debug, Clone)]
pub struct TrieStats {
    /// Total number of nodes in the trie.
    pub node_count: usize,
    /// Total number of patterns indexed.
    pub pattern_count: usize,
    /// Average depth at which patterns terminate.
    pub avg_depth: f64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn p(bytes: &[Option<u8>]) -> FlirtPattern {
        FlirtPattern::new("f".to_string(), bytes.to_vec())
    }

    // ── Insert / search_at_offset ─────────────────────────────────────────────

    #[test]
    fn test_insert_and_find_exact() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0x55), Some(0x8B), Some(0xEC)], 0);
        let data = [0x55u8, 0x8B, 0xEC, 0x00];
        let hits = trie.search_at_offset(&data, 0);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn test_insert_and_miss() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0xAA), Some(0xBB)], 0);
        let data = [0x55u8, 0x8B, 0xEC];
        let hits = trie.search_at_offset(&data, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_wildcard_edge_matches_any_byte() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0x55), None, Some(0xEC)], 0);
        let data1 = [0x55u8, 0x00, 0xEC];
        let data2 = [0x55u8, 0xFF, 0xEC];
        assert!(!trie.search_at_offset(&data1, 0).is_empty());
        assert!(!trie.search_at_offset(&data2, 0).is_empty());
    }

    #[test]
    fn test_two_patterns_same_prefix() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0x55), Some(0x8B)], 0);
        trie.insert(&[Some(0x55), Some(0x89)], 1);

        let data1 = [0x55u8, 0x8B];
        let data2 = [0x55u8, 0x89];
        let h1 = trie.search_at_offset(&data1, 0);
        let h2 = trie.search_at_offset(&data2, 0);
        assert!(h1.contains(&0));
        assert!(!h1.contains(&1));
        assert!(!h2.contains(&0));
        assert!(h2.contains(&1));
    }

    #[test]
    fn test_all_wildcard_pattern() {
        let mut trie = PatternTrie::new();
        trie.insert(&[None, None, None], 0);
        let data = [0x11u8, 0x22, 0x33];
        let hits = trie.search_at_offset(&data, 0);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn test_search_all_offsets() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0xAA), Some(0xBB)], 0);
        let data = [0x00u8, 0xAA, 0xBB, 0xAA, 0xBB];
        let hits = trie.search(&data);
        let offsets: Vec<usize> = hits.iter().map(|(o, _)| *o).collect();
        assert!(offsets.contains(&1));
        assert!(offsets.contains(&3));
        assert!(!offsets.contains(&0));
    }

    // ── build_from_patterns ───────────────────────────────────────────────────

    #[test]
    fn test_build_from_patterns_single() {
        let pats = vec![p(&[Some(0x55), Some(0x8B)])];
        let trie = PatternTrie::build_from_patterns(&pats);
        let hits = trie.search_at_offset(&[0x55u8, 0x8B], 0);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn test_build_from_patterns_multiple() {
        let pats = vec![
            p(&[Some(0x55), Some(0x8B), Some(0xEC)]),
            p(&[Some(0x48), Some(0x89), Some(0xE5)]),
        ];
        let trie = PatternTrie::build_from_patterns(&pats);
        assert!(!trie.search_at_offset(&[0x55u8, 0x8B, 0xEC], 0).is_empty());
        assert!(!trie.search_at_offset(&[0x48u8, 0x89, 0xE5], 0).is_empty());
    }

    #[test]
    fn test_build_from_empty_patterns() {
        let pats: Vec<FlirtPattern> = vec![];
        let trie = PatternTrie::build_from_patterns(&pats);
        let stats = trie.stats();
        assert_eq!(stats.pattern_count, 0);
    }

    // ── TrieStats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_node_count_grows_with_patterns() {
        let mut trie = PatternTrie::new();
        let before = trie.stats().node_count;
        trie.insert(&[Some(0x55), Some(0x8B), Some(0xEC)], 0);
        let after = trie.stats().node_count;
        assert!(after > before);
    }

    #[test]
    fn test_stats_pattern_count() {
        let pats = vec![p(&[Some(0x55)]), p(&[Some(0x8B)]), p(&[Some(0xEC)])];
        let trie = PatternTrie::build_from_patterns(&pats);
        assert_eq!(trie.stats().pattern_count, 3);
    }

    #[test]
    fn test_stats_avg_depth_zero_for_empty() {
        let trie = PatternTrie::new();
        let s = trie.stats();
        assert_eq!(s.avg_depth, 0.0);
    }

    // ── Default ───────────────────────────────────────────────────────────────

    #[test]
    fn test_default_creates_valid_trie() {
        let trie = PatternTrie::default();
        assert_eq!(trie.nodes.len(), 1); // just root
    }

    // ── Shared prefix paths ───────────────────────────────────────────────────

    #[test]
    fn test_shared_prefix_reuses_nodes() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0x55), Some(0x8B)], 0);
        trie.insert(&[Some(0x55), Some(0x89)], 1);
        // root -> [0x55] should be shared
        let root_child_count = trie.nodes[0].children.len();
        assert_eq!(
            root_child_count, 1,
            "shared prefix should produce one child of root"
        );
    }
}
