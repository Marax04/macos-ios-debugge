//! Byte-keyed trie structure for FLIRT signature storage and search.
//!
//! Provides:
//! - `TrieNode` — a single node with a `HashMap<u8, TrieNode>` of children and
//!   an attached list of signature IDs (pattern identifiers).
//! - `FlirtTrie` — the trie root with `insert_pattern()` and `search()`.
//! - `TrieStats` — statistics (node count, depth, pattern count).
//! - `serialize_to_pat()` — serialize matched signatures in IDA `.pat` format.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TrieNode
// ---------------------------------------------------------------------------

/// A single node in the byte-keyed trie.
#[derive(Debug, Clone, Default)]
pub struct TrieNode {
    /// Child nodes keyed by the next byte of the pattern.
    pub children: HashMap<u8, Self>,
    /// Signature identifiers (e.g. function names) stored at this node.
    /// A non-empty list means at least one pattern ends here.
    pub signatures: Vec<String>,
    /// Depth of this node within the trie (root = 0).
    pub depth: usize,
}

impl TrieNode {
    /// Create a new node at the given depth.
    #[must_use]
    pub fn at_depth(depth: usize) -> Self {
        Self {
            children: HashMap::new(),
            signatures: Vec::new(),
            depth,
        }
    }

    /// Whether this node is a terminal (has at least one attached signature).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Whether this node is a leaf (no children).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Total number of nodes in this subtree (including self).
    #[must_use]
    pub fn subtree_size(&self) -> usize {
        1 + self
            .children
            .values()
            .map(Self::subtree_size)
            .sum::<usize>()
    }

    /// Maximum depth in this subtree.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        if self.children.is_empty() {
            self.depth
        } else {
            self.children
                .values()
                .map(Self::max_depth)
                .max()
                .unwrap_or(self.depth)
        }
    }

    /// Count all terminal nodes in this subtree.
    #[must_use]
    pub fn terminal_count(&self) -> usize {
        let own = usize::from(self.is_terminal());
        own + self
            .children
            .values()
            .map(Self::terminal_count)
            .sum::<usize>()
    }

    /// Total number of signature strings across all terminals in this subtree.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.signatures.len()
            + self
                .children
                .values()
                .map(Self::pattern_count)
                .sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// TrieStats
// ---------------------------------------------------------------------------

/// Statistics collected from a `FlirtTrie`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieStats {
    /// Total number of nodes (including root).
    pub node_count: usize,
    /// Maximum depth reached by any node.
    pub max_depth: usize,
    /// Total number of signature strings stored.
    pub pattern_count: usize,
    /// Number of terminal nodes (nodes with ≥ 1 signature).
    pub terminal_count: usize,
}

impl TrieStats {
    /// Average patterns per terminal node.
    #[must_use]
    pub fn avg_patterns_per_terminal(&self) -> f64 {
        if self.terminal_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.pattern_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.terminal_count).unwrap_or(u32::MAX))
        }
    }
}

impl std::fmt::Display for TrieStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TrieStats {{ nodes: {}, depth: {}, patterns: {}, terminals: {} }}",
            self.node_count, self.max_depth, self.pattern_count, self.terminal_count
        )
    }
}

// ---------------------------------------------------------------------------
// SearchMatch
// ---------------------------------------------------------------------------

/// A match returned by `FlirtTrie::search`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// The signature name(s) attached to the matched node.
    pub signatures: Vec<String>,
    /// The number of bytes consumed (length of the matching prefix).
    pub prefix_len: usize,
    /// The byte sequence that was matched.
    pub matched_bytes: Vec<u8>,
}

impl SearchMatch {
    /// Return all signature names as a flat `Vec<&str>`.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.signatures.iter().map(std::string::String::as_str).collect()
    }
}

impl std::fmt::Display for SearchMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SearchMatch {{ names: {:?}, prefix_len: {} }}",
            self.signatures, self.prefix_len
        )
    }
}

// ---------------------------------------------------------------------------
// FlirtTrie
// ---------------------------------------------------------------------------

/// Byte-keyed trie for FLIRT signature lookup.
///
/// Each pattern is stored as a sequence of concrete bytes (wildcards are
/// represented by `0xff` and stored normally — callers may choose to mask
/// them before insertion if they want wildcard-insensitive matching).
pub struct FlirtTrie {
    root: TrieNode,
    /// Total patterns inserted.
    pattern_count: usize,
}

/// Maximum depth (pattern length) accepted by [`FlirtTrie::insert_pattern`].
///
/// Recursive traversal methods (`subtree_size`, `max_depth`, etc.) would
/// overflow the stack for arbitrarily deep tries; this cap ensures the
/// recursion depth stays well within safe limits.
const MAX_TRIE_DEPTH: usize = 512;

impl FlirtTrie {
    /// Create an empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: TrieNode::at_depth(0),
            pattern_count: 0,
        }
    }

    /// Insert a pattern (byte sequence + signature name) into the trie.
    ///
    /// `pattern` must be non-empty and at most [`MAX_TRIE_DEPTH`] bytes.
    /// Longer patterns are silently truncated to that limit so that recursive
    /// traversal methods cannot overflow the stack.
    /// Returns `true` if the pattern was new,
    /// `false` if the same `(pattern, sig_name)` pair already existed.
    pub fn insert_pattern(&mut self, pattern: &[u8], sig_name: impl Into<String>) -> bool {
        if pattern.is_empty() {
            return false;
        }
        let pattern = &pattern[..pattern.len().min(MAX_TRIE_DEPTH)];
        let sig = sig_name.into();
        let mut node = &mut self.root;
        for (i, &byte) in pattern.iter().enumerate() {
            let depth = i + 1;
            node = node
                .children
                .entry(byte)
                .or_insert_with(|| TrieNode::at_depth(depth));
        }
        if node.signatures.contains(&sig) {
            return false; // duplicate
        }
        node.signatures.push(sig);
        self.pattern_count += 1;
        true
    }

    /// Insert a pattern expressed as a hex string (e.g. `"5548 89e5 ??"`).
    ///
    /// `??` tokens are treated as wildcard byte `0xff`.
    /// Spaces are ignored.
    ///
    /// Returns the number of concrete bytes inserted, or 0 on parse failure.
    pub fn insert_hex_pattern(&mut self, hex: &str, sig_name: impl Into<String>) -> usize {
        let bytes = Self::parse_hex_pattern(hex);
        if bytes.is_empty() {
            return 0;
        }
        let len = bytes.len();
        self.insert_pattern(&bytes, sig_name);
        len
    }

    /// Parse a hex pattern string into bytes.
    #[must_use]
    pub fn parse_hex_pattern(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 3 + 1);
        for tok in hex.split_whitespace() {
            if tok == "??" || tok == "**" {
                out.push(0xffu8);
            } else if let Ok(b) = u8::from_str_radix(tok, 16) {
                out.push(b);
            } else {
                return Vec::new(); // parse error
            }
        }
        out
    }

    /// Search for all signatures whose stored pattern is a prefix of `bytes`.
    ///
    /// Returns every terminal node encountered while traversing `bytes`, ordered
    /// from shortest to longest match.
    #[must_use]
    pub fn search(&self, bytes: &[u8]) -> Vec<SearchMatch> {
        let mut results = Vec::new();
        let mut node = &self.root;
        let mut matched = Vec::with_capacity(bytes.len());

        for &byte in bytes {
            match node.children.get(&byte) {
                Some(child) => {
                    matched.push(byte);
                    node = child;
                    if node.is_terminal() {
                        results.push(SearchMatch {
                            signatures: node.signatures.clone(),
                            prefix_len: matched.len(),
                            matched_bytes: matched.clone(),
                        });
                    }
                }
                None => break,
            }
        }
        results
    }

    /// Search for an exact-length match: traverse `bytes` exactly and return
    /// the terminal node's signatures if the traversal consumed all of `bytes`.
    #[must_use]
    pub fn exact_search(&self, bytes: &[u8]) -> Option<Vec<String>> {
        let mut node = &self.root;
        for &byte in bytes {
            node = node.children.get(&byte)?;
        }
        if node.is_terminal() {
            Some(node.signatures.clone())
        } else {
            None
        }
    }

    /// Whether the trie contains any pattern that is a prefix of `bytes`.
    #[must_use]
    pub fn has_prefix_match(&self, bytes: &[u8]) -> bool {
        !self.search(bytes).is_empty()
    }

    /// Remove all patterns with the given `sig_name`.
    /// Returns the number of occurrences removed.
    pub fn remove_pattern(&mut self, sig_name: &str) -> usize {
        let removed = Self::remove_from_node(&mut self.root, sig_name);
        self.pattern_count = self.pattern_count.saturating_sub(removed);
        removed
    }

    fn remove_from_node(node: &mut TrieNode, sig: &str) -> usize {
        let before = node.signatures.len();
        node.signatures.retain(|s| s != sig);
        let removed = before - node.signatures.len();
        let child_removed: usize = node
            .children
            .values_mut()
            .map(|c| Self::remove_from_node(c, sig))
            .sum();
        removed + child_removed
    }

    /// Total patterns stored.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Whether the trie is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pattern_count == 0
    }

    /// Compute statistics.
    #[must_use]
    pub fn stats(&self) -> TrieStats {
        TrieStats {
            node_count: self.root.subtree_size(),
            max_depth: self.root.max_depth(),
            pattern_count: self.root.pattern_count(),
            terminal_count: self.root.terminal_count(),
        }
    }

    // ── serialize_to_pat ─────────────────────────────────────────────────────

    /// Serialize all signatures stored in the trie to a simplified IDA `.pat`
    /// text format.
    ///
    /// Format per line (simplified, not full IDA PAT):
    /// ```text
    /// <hex_bytes> 00 0000 0000 :0000 <sig_name>
    /// ```
    ///
    /// Only terminal nodes are serialized.  Each signature stored at a terminal
    /// produces one line, with the matched bytes expressed as uppercase hex.
    #[must_use]
    pub fn serialize_to_pat(&self) -> String {
        let mut lines = Vec::new();
        Self::collect_pat_lines(&self.root, &mut Vec::new(), &mut lines);
        lines.sort();
        let mut out = lines.join("\n");
        if !out.is_empty() {
            out.push('\n');
            out.push_str("---\n");
        }
        out
    }

    fn collect_pat_lines(node: &TrieNode, path: &mut Vec<u8>, lines: &mut Vec<String>) {
        if node.is_terminal() {
            let hex_bytes: String = path
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            for sig in &node.signatures {
                lines.push(format!("{hex_bytes} 00 0000 0000 :0000 {sig}"));
            }
        }
        // Sort children for deterministic output
        let mut child_bytes: Vec<u8> = node.children.keys().copied().collect();
        child_bytes.sort_unstable();
        for byte in child_bytes {
            if let Some(child) = node.children.get(&byte) {
                path.push(byte);
                Self::collect_pat_lines(child, path, lines);
                path.pop();
            }
        }
    }

    /// Collect all signature names stored in the trie.
    #[must_use]
    pub fn all_signatures(&self) -> Vec<String> {
        let mut sigs = Vec::new();
        Self::collect_sigs(&self.root, &mut sigs);
        sigs.sort();
        sigs.dedup();
        sigs
    }

    fn collect_sigs(node: &TrieNode, out: &mut Vec<String>) {
        out.extend(node.signatures.iter().cloned());
        for child in node.children.values() {
            Self::collect_sigs(child, out);
        }
    }
}

impl Default for FlirtTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FlirtTrie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlirtTrie {{ patterns: {} }}", self.pattern_count)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_trie() -> FlirtTrie {
        let mut t = FlirtTrie::new();
        t.insert_pattern(&[0x55, 0x48, 0x89, 0xe5], "func_a");
        t.insert_pattern(&[0x55, 0x48, 0x89, 0xe5, 0xc3], "func_b");
        t.insert_pattern(&[0x56, 0x48, 0x89, 0xe5], "func_c");
        t
    }

    #[test]
    fn test_insert_and_count() {
        let t = build_trie();
        assert_eq!(t.pattern_count(), 3);
    }

    #[test]
    fn test_insert_duplicate_returns_false() {
        let mut t = FlirtTrie::new();
        assert!(t.insert_pattern(&[0x55, 0x48], "foo"));
        assert!(!t.insert_pattern(&[0x55, 0x48], "foo")); // duplicate
        assert_eq!(t.pattern_count(), 1);
    }

    #[test]
    fn test_exact_search_hit() {
        let t = build_trie();
        let sigs = t.exact_search(&[0x55, 0x48, 0x89, 0xe5]).unwrap();
        assert_eq!(sigs, vec!["func_a"]);
    }

    #[test]
    fn test_exact_search_miss() {
        let t = build_trie();
        assert!(t.exact_search(&[0x55, 0x48, 0x89]).is_none());
    }

    #[test]
    fn test_search_prefix_shortest() {
        let t = build_trie();
        let matches = t.search(&[0x55, 0x48, 0x89, 0xe5, 0xc3, 0x90]);
        // Both func_a (4 bytes) and func_b (5 bytes) match
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].prefix_len, 4);
        assert_eq!(matches[0].signatures[0], "func_a");
        assert_eq!(matches[1].prefix_len, 5);
        assert_eq!(matches[1].signatures[0], "func_b");
    }

    #[test]
    fn test_search_no_match() {
        let t = build_trie();
        let matches = t.search(&[0xcc, 0xcc, 0xcc]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_has_prefix_match() {
        let t = build_trie();
        assert!(t.has_prefix_match(&[0x55, 0x48, 0x89, 0xe5, 0x00]));
        assert!(!t.has_prefix_match(&[0xff, 0xff]));
    }

    #[test]
    fn test_trie_stats() {
        let t = build_trie();
        let s = t.stats();
        assert!(s.node_count > 3);
        assert_eq!(s.pattern_count, 3);
        assert!(s.max_depth >= 4);
    }

    #[test]
    fn test_trie_stats_display() {
        let t = build_trie();
        let s = t.stats().to_string();
        assert!(s.contains("patterns: 3"));
    }

    #[test]
    fn test_serialize_to_pat_contains_sigs() {
        let t = build_trie();
        let pat = t.serialize_to_pat();
        assert!(pat.contains("func_a"));
        assert!(pat.contains("func_b"));
        assert!(pat.contains("func_c"));
        assert!(pat.contains("---"));
    }

    #[test]
    fn test_serialize_to_pat_hex_format() {
        let mut t = FlirtTrie::new();
        t.insert_pattern(&[0x55, 0x48], "push_rbp");
        let pat = t.serialize_to_pat();
        assert!(pat.contains("55 48"));
        assert!(pat.contains("push_rbp"));
    }

    #[test]
    fn test_remove_pattern() {
        let mut t = build_trie();
        let removed = t.remove_pattern("func_a");
        assert_eq!(removed, 1);
        assert_eq!(t.pattern_count(), 2);
        assert!(t.exact_search(&[0x55, 0x48, 0x89, 0xe5]).is_none());
    }

    #[test]
    fn test_remove_non_existent() {
        let mut t = build_trie();
        let removed = t.remove_pattern("ghost");
        assert_eq!(removed, 0);
        assert_eq!(t.pattern_count(), 3);
    }

    #[test]
    fn test_insert_hex_pattern() {
        let mut t = FlirtTrie::new();
        let n = t.insert_hex_pattern("55 48 89 e5", "hex_func");
        assert_eq!(n, 4);
        assert_eq!(t.pattern_count(), 1);
    }

    #[test]
    fn test_insert_hex_pattern_wildcard() {
        let mut t = FlirtTrie::new();
        let n = t.insert_hex_pattern("55 48 ?? e5", "wild_func");
        assert_eq!(n, 4);
        // wildcard stored as 0xff
        let sigs = t.exact_search(&[0x55, 0x48, 0xff, 0xe5]).unwrap();
        assert!(sigs.contains(&"wild_func".to_string()));
    }

    #[test]
    fn test_insert_hex_bad_token_returns_zero() {
        let mut t = FlirtTrie::new();
        let n = t.insert_hex_pattern("ZZ YY", "bad");
        assert_eq!(n, 0);
        assert_eq!(t.pattern_count(), 0);
    }

    #[test]
    fn test_trie_node_is_terminal() {
        let mut n = TrieNode::at_depth(0);
        assert!(!n.is_terminal());
        n.signatures.push("s".into());
        assert!(n.is_terminal());
    }

    #[test]
    fn test_trie_node_is_leaf() {
        let n = TrieNode::at_depth(0);
        assert!(n.is_leaf());
    }

    #[test]
    fn test_all_signatures() {
        let t = build_trie();
        let sigs = t.all_signatures();
        assert_eq!(sigs.len(), 3);
        assert!(sigs.contains(&"func_a".to_string()));
    }

    #[test]
    fn test_empty_trie_is_empty() {
        let t = FlirtTrie::new();
        assert!(t.is_empty());
    }

    #[test]
    fn test_empty_pattern_insert_returns_false() {
        let mut t = FlirtTrie::new();
        assert!(!t.insert_pattern(&[], "empty"));
        assert!(t.is_empty());
    }

    #[test]
    fn test_search_match_display() {
        let sm = SearchMatch {
            signatures: vec!["foo".to_string()],
            prefix_len: 4,
            matched_bytes: vec![0x55, 0x48, 0x89, 0xe5],
        };
        let s = sm.to_string();
        assert!(s.contains("foo"));
        assert!(s.contains('4'));
    }

    #[test]
    fn test_trie_debug_format() {
        let t = build_trie();
        let s = format!("{t:?}");
        assert!(s.contains("FlirtTrie"));
        assert!(s.contains('3'));
    }

    #[test]
    fn test_stats_avg_patterns_per_terminal() {
        let t = build_trie();
        let s = t.stats();
        assert!(s.avg_patterns_per_terminal() > 0.0);
    }
}
