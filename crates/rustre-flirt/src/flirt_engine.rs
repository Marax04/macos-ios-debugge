//! `flirt_engine` — Full FLIRT signature matching engine.
//!
//! Provides:
//! * [`FlirtEngine`] — top-level matching engine
//! * [`PatternNode`] — trie node holding byte pattern data
//! * [`PatternTrie`] — Patricia-style trie for fast byte prefix lookup
//! * [`BytePattern`] — a concrete sequence of pattern bytes
//! * [`VariableByte`] — a wildcard / variable byte position
//! * [`CrcCheck`] — CRC-16/CCITT check for disambiguation
//! * [`ModuleRef`] — a module (library) reference attached to a match
//! * [`NameApplier`] — applies matched symbol names back to analysis context

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::FlirtError;

// ─── VariableByte ─────────────────────────────────────────────────────────────

/// A wildcard / variable byte in a FLIRT pattern.
///
/// Variable bytes appear as `..` in IDA `.pat` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableByte {
    /// Offset of this variable byte within the pattern.
    pub offset: u16,
}

impl VariableByte {
    /// Create a new variable byte at the given offset.
    #[must_use]
    pub const fn new(offset: u16) -> Self {
        Self { offset }
    }
}

// ─── BytePattern ─────────────────────────────────────────────────────────────

/// A concrete byte pattern with optional wildcard positions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePattern {
    /// Fixed bytes (wildcards are stored as 0x00).
    pub bytes: Vec<u8>,
    /// Positions that are wildcards (masked out during matching).
    pub wildcards: Vec<u16>,
    /// Name associated with this pattern.
    pub name: String,
    /// Offset within the function this pattern starts at.
    pub func_offset: u32,
}

impl BytePattern {
    /// Create a new byte pattern.
    #[must_use]
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wildcards: Vec::new(),
            name: name.into(),
            func_offset: 0,
        }
    }

    /// Add a wildcard at the given offset.
    #[must_use]
    pub fn with_wildcard(mut self, offset: u16) -> Self {
        self.wildcards.push(offset);
        self
    }

    /// Returns `true` if the given offset is a wildcard.
    #[must_use]
    #[inline]
    pub fn is_wildcard(&self, offset: u16) -> bool {
        self.wildcards.contains(&offset)
    }

    /// Returns the length of the pattern in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Match this pattern against a byte slice at offset 0.
    ///
    /// Returns `true` if all non-wildcard bytes match.
    #[must_use]
    #[inline]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        if self.wildcards.is_empty() {
            return data[..self.bytes.len()] == self.bytes[..];
        }
        for (i, &b) in self.bytes.iter().enumerate() {
            if self.is_wildcard(u16::try_from(i).unwrap_or(u16::MAX)) {
                continue;
            }
            if data[i] != b {
                return false;
            }
        }
        true
    }
}

// ─── CrcCheck ────────────────────────────────────────────────────────────────

/// CRC-16/CCITT check for disambiguating patterns with the same prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrcCheck {
    /// Length of the byte range to CRC over (from the end of the prefix).
    pub crc_len: u16,
    /// Expected CRC-16/CCITT value.
    pub crc_value: u16,
}

impl CrcCheck {
    /// Create a new CRC check.
    #[must_use]
    pub const fn new(crc_len: u16, crc_value: u16) -> Self {
        Self { crc_len, crc_value }
    }

    /// Verify this CRC check against a byte slice (starting after the pattern prefix).
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        if data.len() < self.crc_len as usize {
            return false;
        }
        let computed = crc16_flirt(&data[..self.crc_len as usize]);
        computed == self.crc_value
    }
}

/// The FLIRT tail CRC. Delegates to [`crate::crc::flirt_tail`].
///
/// BUG FIX: the doc comment here used to say "MCRF4XX ... final XOR 0xFFFF",
/// which is self-contradictory (MCRF4XX has no final XOR), and the body applied
/// the XOR — so this was X-25. `CrcCheck::verify` therefore validated matches
/// with X-25 while `rustre_flirt_apply::match_validator` validated them with
/// MCRF4XX: two halves of the same stack disagreeing on every single input.
#[must_use]
pub fn crc16_flirt(data: &[u8]) -> u16 {
    crate::crc::flirt_tail(data)
}

// ─── ModuleRef ────────────────────────────────────────────────────────────────

/// A reference to a module (library) that a matched function belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRef {
    /// Library name, e.g. `"libssl.a"`.
    pub library: String,
    /// Object file within the library, e.g. `"rsa.o"`.
    pub object: String,
}

impl ModuleRef {
    /// Create a module reference.
    #[must_use]
    pub fn new(library: impl Into<String>, object: impl Into<String>) -> Self {
        Self {
            library: library.into(),
            object: object.into(),
        }
    }

    /// Returns a display string `library(object)`.
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}({})", self.library, self.object)
    }
}

// ─── PatternNode ─────────────────────────────────────────────────────────────

/// A node in the [`PatternTrie`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternNode {
    /// The byte value at this node (0 if this is the root).
    pub byte: u8,
    /// Children indexed by next byte value.
    pub children: HashMap<u8, usize>,
    /// Patterns that terminate at this node.
    pub patterns: Vec<BytePattern>,
    /// CRC checks for disambiguation at this node.
    pub crc_checks: Vec<CrcCheck>,
    /// Module references for patterns terminating here.
    pub modules: Vec<ModuleRef>,
}

impl PatternNode {
    /// Create a new empty node with the given byte.
    #[must_use]
    pub fn new(byte: u8) -> Self {
        Self {
            byte,
            ..Default::default()
        }
    }

    /// Returns `true` if this node has any terminating patterns.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Returns the number of child edges.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

// ─── PatternTrie ─────────────────────────────────────────────────────────────

/// Patricia-style trie for fast FLIRT prefix matching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternTrie {
    /// All nodes, root at index 0.
    nodes: Vec<PatternNode>,
    /// Total number of patterns stored.
    pattern_count: usize,
}

impl PatternTrie {
    /// Create an empty trie (root node at index 0).
    #[must_use]
    pub fn new() -> Self {
        let root = PatternNode::new(0);
        Self {
            nodes: vec![root],
            pattern_count: 0,
        }
    }

    /// Insert a byte pattern into the trie.
    pub fn insert(&mut self, pattern: BytePattern) {
        let mut cur = 0usize;

        for i in 0..pattern.bytes.len() {
            if pattern.is_wildcard(u16::try_from(i).unwrap_or(u16::MAX)) {
                // Wildcards break the prefix: store at current node.
                break;
            }
            let b = pattern.bytes[i];
            let child_idx = if let Some(&idx) = self.nodes[cur].children.get(&b) {
                idx
            } else {
                let new_idx = self.nodes.len();
                self.nodes.push(PatternNode::new(b));
                self.nodes[cur].children.insert(b, new_idx);
                new_idx
            };
            cur = child_idx;
        }

        self.nodes[cur].patterns.push(pattern);
        self.pattern_count += 1;
    }

    /// Look up all patterns whose prefix matches `data`.
    ///
    /// Returns a list of `(node_index, &BytePattern)` pairs.
    #[must_use]
    pub fn lookup<'a>(&'a self, data: &[u8]) -> Vec<(usize, &'a BytePattern)> {
        let mut results = Vec::with_capacity(4);
        let mut cur = 0usize;

        for &b in data {
            // Collect patterns at this intermediate node.
            for pat in &self.nodes[cur].patterns {
                if pat.matches(data) {
                    results.push((cur, pat));
                }
            }
            let Some(&next) = self.nodes[cur].children.get(&b) else {
                break;
            };
            cur = next;
        }
        // Terminal node patterns
        for pat in &self.nodes[cur].patterns {
            if pat.matches(data) {
                results.push((cur, pat));
            }
        }
        results
    }

    /// Number of patterns stored in the trie.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Number of nodes in the trie.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ─── MatchResult ─────────────────────────────────────────────────────────────

/// A single FLIRT match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Virtual address of the function that was matched.
    pub address: u64,
    /// Symbol name recovered from the pattern.
    pub name: String,
    /// Library module reference, if known.
    pub module: Option<ModuleRef>,
    /// CRC check passed (higher confidence).
    pub crc_verified: bool,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
}

impl MatchResult {
    /// Returns `true` if this is a high-confidence match (CRC verified, confidence ≥ 0.8).
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.crc_verified && self.confidence >= 0.8
    }
}

// ─── NameApplier ─────────────────────────────────────────────────────────────

/// Applies matched symbol names to an analysis context.
#[derive(Debug, Default, Clone)]
pub struct NameApplier {
    /// Map of `address → applied_name`.
    pub applied: HashMap<u64, String>,
    /// Names that were not applied due to conflicts.
    pub conflicts: Vec<(u64, String, String)>,
}

impl NameApplier {
    /// Create a new applier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a match result.  If the address already has a different name, records a conflict.
    pub fn apply(&mut self, result: &MatchResult) {
        if let Some(existing) = self.applied.get(&result.address) {
            if existing != &result.name {
                self.conflicts
                    .push((result.address, existing.clone(), result.name.clone()));
            }
        } else {
            self.applied.insert(result.address, result.name.clone());
        }
    }

    /// Apply a batch of match results.
    pub fn apply_all(&mut self, results: &[MatchResult]) {
        for r in results {
            self.apply(r);
        }
    }

    /// Returns the number of applied names.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Returns `true` if there are no conflicts.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }

    /// Look up the applied name for a given address.
    #[must_use]
    pub fn name_at(&self, address: u64) -> Option<&str> {
        self.applied.get(&address).map(std::string::String::as_str)
    }
}

// ─── FlirtEngine ─────────────────────────────────────────────────────────────

/// Top-level FLIRT signature matching engine.
///
/// Maintains a [`PatternTrie`] and a [`NameApplier`], and matches binary
/// byte buffers against the loaded pattern database.
#[derive(Debug, Clone)]
pub struct FlirtEngine {
    /// Pattern storage.
    trie: PatternTrie,
    /// Name applier.
    pub applier: NameApplier,
    /// Loaded module references by pattern name.
    module_map: HashMap<String, ModuleRef>,
    /// Minimum pattern length to add (shorter patterns rejected).
    pub min_pattern_len: usize,
}

/// Delegates to [`FlirtEngine::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `min_pattern_len` to 0 while `new()` sets it to 4. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for FlirtEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FlirtEngine {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trie: PatternTrie::new(),
            applier: NameApplier::new(),
            module_map: HashMap::new(),
            min_pattern_len: 4,
        }
    }

    /// Add a byte pattern to the database.
    ///
    /// # Errors
    /// Returns [`FlirtError::InvalidPattern`] if the pattern is shorter than `min_pattern_len`.
    pub fn add_pattern(&mut self, pattern: BytePattern) -> Result<(), FlirtError> {
        if pattern.len() < self.min_pattern_len {
            return Err(FlirtError::InvalidPattern(format!(
                "pattern '{}' too short ({} < {})",
                pattern.name,
                pattern.len(),
                self.min_pattern_len
            )));
        }
        self.trie.insert(pattern);
        Ok(())
    }

    /// Register a module reference for a pattern name.
    pub fn register_module(&mut self, pattern_name: impl Into<String>, module: ModuleRef) {
        self.module_map.insert(pattern_name.into(), module);
    }

    /// Scan a byte buffer starting at `base_address` and collect all matches.
    ///
    /// The scan slides a window over the buffer at each byte offset.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_address: u64) -> Vec<MatchResult> {
        let mut results = Vec::new();
        let mut seen: std::collections::HashSet<(u64, String)> = std::collections::HashSet::new();

        for offset in 0..data.len() {
            let slice = &data[offset..];
            let matches = self.trie.lookup(slice);
            for (_, pat) in matches {
                let addr = base_address + offset as u64;
                if seen.insert((addr, pat.name.clone())) {
                    let module = self.module_map.get(&pat.name).cloned();
                    let crc_verified = false;
                    results.push(MatchResult {
                        address: addr,
                        name: pat.name.clone(),
                        module,
                        crc_verified,
                        confidence: if crc_verified { 0.95 } else { 0.7 },
                    });
                }
            }
        }
        results
    }

    /// Apply all scan results via the [`NameApplier`].
    pub fn scan_and_apply(&mut self, data: &[u8], base_address: u64) {
        let results = self.scan(data, base_address);
        let applier = &mut self.applier;
        for r in &results {
            applier.apply(r);
        }
    }

    /// Returns the number of patterns loaded.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.trie.pattern_count()
    }

    /// Returns the number of trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.trie.node_count()
    }

    /// Clear all patterns and reset the engine.
    pub fn reset(&mut self) {
        self.trie = PatternTrie::new();
        self.applier = NameApplier::new();
        self.module_map.clear();
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VariableByte ──────────────────────────────────────────────────────────

    #[test]
    fn test_variable_byte_new() {
        let vb = VariableByte::new(5);
        assert_eq!(vb.offset, 5);
    }

    // ── BytePattern ───────────────────────────────────────────────────────────

    #[test]
    fn test_byte_pattern_new() {
        let p = BytePattern::new("foo", vec![0x55, 0x89, 0xE5]);
        assert_eq!(p.name, "foo");
        assert_eq!(p.len(), 3);
        assert!(!p.is_empty());
    }

    #[test]
    fn test_byte_pattern_is_wildcard() {
        let p = BytePattern::new("bar", vec![0x55, 0x00, 0xE5]).with_wildcard(1);
        assert!(p.is_wildcard(1));
        assert!(!p.is_wildcard(0));
    }

    #[test]
    fn test_byte_pattern_matches_exact() {
        let p = BytePattern::new("test", vec![0x55, 0x89, 0xE5]);
        assert!(p.matches(&[0x55, 0x89, 0xE5, 0x00]));
    }

    #[test]
    fn test_byte_pattern_matches_with_wildcard() {
        let p = BytePattern::new("test", vec![0x55, 0x00, 0xE5]).with_wildcard(1);
        assert!(p.matches(&[0x55, 0xFF, 0xE5]));
    }

    #[test]
    fn test_byte_pattern_no_match() {
        let p = BytePattern::new("test", vec![0x55, 0x89, 0xE5]);
        assert!(!p.matches(&[0x56, 0x89, 0xE5]));
    }

    #[test]
    fn test_byte_pattern_too_short() {
        let p = BytePattern::new("test", vec![0x55, 0x89, 0xE5]);
        assert!(!p.matches(&[0x55, 0x89]));
    }

    #[test]
    fn test_byte_pattern_empty() {
        let p = BytePattern::new("empty", vec![]);
        assert!(p.is_empty());
    }

    // ── CrcCheck ──────────────────────────────────────────────────────────────

    #[test]
    fn test_crc16_known_empty() {
        // The engine validator must use the one canonical FLIRT tail CRC
        // (MCRF4XX: init 0xFFFF, no xorout), the same one the writer and the
        // apply-side validator use. It previously asserted the X-25 value here,
        // which is exactly how the two halves of the stack drifted apart.
        assert_eq!(crc16_flirt(&[]), 0xFFFF);
        assert_eq!(crc16_flirt(b"123456789"), 0x6F91);
    }

    #[test]
    fn test_crc16_nonempty() {
        let crc = crc16_flirt(&[0x55, 0x89, 0xE5]);
        assert_ne!(crc, 0x0000);
    }

    #[test]
    fn test_crc_check_verify_ok() {
        let data = &[0xAA, 0xBB, 0xCC, 0xDD];
        let expected = crc16_flirt(&data[..2]);
        let c = CrcCheck::new(2, expected);
        assert!(c.verify(data));
    }

    #[test]
    fn test_crc_check_verify_fail() {
        let c = CrcCheck::new(2, 0x1234);
        assert!(!c.verify(&[0x55, 0x89])); // very unlikely to equal 0x1234
    }

    #[test]
    fn test_crc_check_verify_too_short() {
        let c = CrcCheck::new(10, 0xABCD);
        assert!(!c.verify(&[0x01, 0x02]));
    }

    // ── ModuleRef ─────────────────────────────────────────────────────────────

    #[test]
    fn test_module_ref_display() {
        let m = ModuleRef::new("libssl.a", "rsa.o");
        assert_eq!(m.display(), "libssl.a(rsa.o)");
    }

    #[test]
    fn test_module_ref_fields() {
        let m = ModuleRef::new("lib.a", "obj.o");
        assert_eq!(m.library, "lib.a");
        assert_eq!(m.object, "obj.o");
    }

    // ── PatternNode ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_node_new() {
        let n = PatternNode::new(0x55);
        assert_eq!(n.byte, 0x55);
        assert!(!n.is_terminal());
        assert_eq!(n.child_count(), 0);
    }

    #[test]
    fn test_pattern_node_is_terminal_after_pattern() {
        let mut n = PatternNode::new(0);
        n.patterns.push(BytePattern::new("f", vec![0x55]));
        assert!(n.is_terminal());
    }

    // ── PatternTrie ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_trie_new() {
        let t = PatternTrie::new();
        assert_eq!(t.node_count(), 1);
        assert_eq!(t.pattern_count(), 0);
    }

    #[test]
    fn test_pattern_trie_insert_one() {
        let mut t = PatternTrie::new();
        t.insert(BytePattern::new("foo", vec![0x55, 0x89, 0xE5]));
        assert_eq!(t.pattern_count(), 1);
    }

    #[test]
    fn test_pattern_trie_lookup_found() {
        let mut t = PatternTrie::new();
        t.insert(BytePattern::new("foo", vec![0x55, 0x89, 0xE5]));
        let results = t.lookup(&[0x55, 0x89, 0xE5, 0x00]);
        assert!(!results.is_empty());
        assert_eq!(results[0].1.name, "foo");
    }

    #[test]
    fn test_pattern_trie_lookup_not_found() {
        let mut t = PatternTrie::new();
        t.insert(BytePattern::new("foo", vec![0x55, 0x89, 0xE5]));
        let results = t.lookup(&[0x56, 0x89, 0xE5]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_pattern_trie_multiple_patterns() {
        let mut t = PatternTrie::new();
        t.insert(BytePattern::new("a", vec![0x55, 0x89]));
        t.insert(BytePattern::new("b", vec![0x55, 0x8B]));
        assert_eq!(t.pattern_count(), 2);
    }

    // ── MatchResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_match_result_is_confident() {
        let r = MatchResult {
            address: 0x1000,
            name: "foo".into(),
            module: None,
            crc_verified: true,
            confidence: 0.95,
        };
        assert!(r.is_confident());
    }

    #[test]
    fn test_match_result_not_confident_low_score() {
        let r = MatchResult {
            address: 0x1000,
            name: "foo".into(),
            module: None,
            crc_verified: true,
            confidence: 0.5,
        };
        assert!(!r.is_confident());
    }

    #[test]
    fn test_match_result_not_confident_no_crc() {
        let r = MatchResult {
            address: 0x1000,
            name: "foo".into(),
            module: None,
            crc_verified: false,
            confidence: 0.9,
        };
        assert!(!r.is_confident());
    }

    // ── NameApplier ───────────────────────────────────────────────────────────

    #[test]
    fn test_name_applier_apply() {
        let mut a = NameApplier::new();
        let r = MatchResult {
            address: 0x1000,
            name: "malloc".into(),
            module: None,
            crc_verified: true,
            confidence: 0.9,
        };
        a.apply(&r);
        assert_eq!(a.name_at(0x1000), Some("malloc"));
        assert_eq!(a.applied_count(), 1);
        assert!(a.is_clean());
    }

    #[test]
    fn test_name_applier_conflict() {
        let mut a = NameApplier::new();
        a.apply(&MatchResult {
            address: 0x1000,
            name: "malloc".into(),
            module: None,
            crc_verified: true,
            confidence: 0.9,
        });
        a.apply(&MatchResult {
            address: 0x1000,
            name: "free".into(),
            module: None,
            crc_verified: true,
            confidence: 0.8,
        });
        assert!(!a.is_clean());
        assert_eq!(a.conflicts.len(), 1);
    }

    #[test]
    fn test_name_applier_apply_all() {
        let mut a = NameApplier::new();
        let results = vec![
            MatchResult {
                address: 0x1000,
                name: "malloc".into(),
                module: None,
                crc_verified: true,
                confidence: 0.9,
            },
            MatchResult {
                address: 0x2000,
                name: "free".into(),
                module: None,
                crc_verified: true,
                confidence: 0.9,
            },
        ];
        a.apply_all(&results);
        assert_eq!(a.applied_count(), 2);
    }

    // ── FlirtEngine ───────────────────────────────────────────────────────────

    #[test]
    fn test_engine_new() {
        let e = FlirtEngine::new();
        assert_eq!(e.pattern_count(), 0);
    }

    #[test]
    fn test_engine_add_pattern_ok() {
        let mut e = FlirtEngine::new();
        let p = BytePattern::new("malloc", vec![0x55, 0x89, 0xE5, 0x53]);
        assert!(e.add_pattern(p).is_ok());
        assert_eq!(e.pattern_count(), 1);
    }

    #[test]
    fn test_engine_add_pattern_too_short() {
        let mut e = FlirtEngine::new();
        let p = BytePattern::new("tiny", vec![0x55]);
        assert!(e.add_pattern(p).is_err());
    }

    #[test]
    fn test_engine_scan_found() {
        let mut e = FlirtEngine::new();
        e.add_pattern(BytePattern::new("foo", vec![0x55, 0x89, 0xE5, 0x83]))
            .unwrap();
        let data = &[0x90, 0x55, 0x89, 0xE5, 0x83, 0xEC];
        let results = e.scan(data, 0x1000);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "foo");
        assert_eq!(results[0].address, 0x1001);
    }

    #[test]
    fn test_engine_scan_not_found() {
        let mut e = FlirtEngine::new();
        e.add_pattern(BytePattern::new("foo", vec![0x55, 0x89, 0xE5, 0x83]))
            .unwrap();
        let data = &[0x90, 0x91, 0x92, 0x93];
        assert!(e.scan(data, 0).is_empty());
    }

    #[test]
    fn test_engine_scan_and_apply() {
        let mut e = FlirtEngine::new();
        e.add_pattern(BytePattern::new("bar", vec![0xCC, 0xDD, 0xEE, 0xFF]))
            .unwrap();
        e.scan_and_apply(&[0xCC, 0xDD, 0xEE, 0xFF], 0x2000);
        assert_eq!(e.applier.applied_count(), 1);
    }

    #[test]
    fn test_engine_register_module() {
        let mut e = FlirtEngine::new();
        e.register_module("malloc", ModuleRef::new("libc.a", "malloc.o"));
        e.add_pattern(BytePattern::new("malloc", vec![0x55, 0x89, 0xE5, 0x53]))
            .unwrap();
        let results = e.scan(&[0x55, 0x89, 0xE5, 0x53], 0);
        assert!(results[0].module.is_some());
    }

    #[test]
    fn test_engine_reset() {
        let mut e = FlirtEngine::new();
        e.add_pattern(BytePattern::new("f", vec![0x55, 0x89, 0xE5, 0x83]))
            .unwrap();
        e.reset();
        assert_eq!(e.pattern_count(), 0);
    }

    #[test]
    fn test_engine_node_count_grows() {
        let mut e = FlirtEngine::new();
        let before = e.node_count();
        e.add_pattern(BytePattern::new("g", vec![0x55, 0x89, 0xE5, 0x83]))
            .unwrap();
        assert!(e.node_count() > before);
    }
}
