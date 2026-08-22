//! Advanced FLIRT pattern matching.
//!
//! Implements multi-pattern simultaneous matching, pattern scoring with variant
//! support, wildcard byte ranges, CRC16 tail validation, collision resolution by
//! module name priority, and match confidence scoring.

use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::{FlirtPattern, FlirtName, TailByte, PatternByte, crc16_flirt};

// ── Types ──────────────────────────────────────────────────────────────────────

/// A node in the pattern-matching automaton (simplified Aho-Corasick-like trie).
#[derive(Debug, Clone)]
pub struct PatternNode {
    /// Per-byte child index. `u32::MAX` means absent.
    pub children: [u32; 256],
    /// Wildcard child index (matches any byte).
    pub wildcard_child: Option<u32>,
    /// Patterns that terminate at this node.
    pub terminal_patterns: Vec<usize>,
    /// Depth in the trie (number of bytes consumed to reach this node).
    pub depth: u32,
}

impl PatternNode {
    /// Create a new empty node at the given depth.
    #[must_use]
    pub const fn new(depth: u32) -> Self {
        Self {
            children: [u32::MAX; 256],
            wildcard_child: None,
            terminal_patterns: Vec::new(),
            depth,
        }
    }
}

/// CRC-16 tail validation spec for a pattern.
#[derive(Debug, Clone)]
pub struct CrcValidation {
    /// Byte offset from the start of the function where CRC region begins.
    pub start_offset: usize,
    /// Number of bytes the CRC covers.
    pub length: usize,
    /// Expected CRC-16/CCITT value.
    pub expected: u16,
}

impl CrcValidation {
    /// Create a new CRC validation spec.
    #[must_use]
    pub const fn new(start_offset: usize, length: usize, expected: u16) -> Self {
        Self { start_offset, length, expected }
    }

    /// Validate `buf` against this spec.
    #[must_use]
    pub fn validate(&self, buf: &[u8]) -> bool {
        let end = self.start_offset + self.length;
        if buf.len() < end {
            return false;
        }
        crc16_flirt(&buf[self.start_offset..end]) == self.expected
    }
}

/// A scored match result with confidence and variant info.
#[derive(Debug, Clone)]
pub struct MatchScore {
    /// Pattern index that matched.
    pub pattern_idx: usize,
    /// Module (library) that owns the pattern.
    pub module_name: String,
    /// Matched function name.
    pub name: String,
    /// Byte offset of the name from the function start.
    pub name_offset: u16,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Number of exact bytes matched (higher = more specific).
    pub exact_byte_count: usize,
    /// Whether a CRC check was performed and passed.
    pub crc_validated: bool,
    /// Whether tail bytes were validated.
    pub tail_validated: bool,
}

impl MatchScore {
    /// Compute a composite score (higher is better).
    ///
    /// Factors:
    /// - Exact byte fraction: 0.6 weight
    /// - CRC validated: +0.2
    /// - Tail validated: +0.1
    /// - Base: 0.1
    #[must_use]
    pub fn compute(
        pattern: &FlirtPattern,
        crc_validated: bool,
        tail_validated: bool,
        module_name: String,
        pattern_idx: usize,
    ) -> Vec<Self> {
        let total = pattern.initial_bytes.len().max(1);
        let exact = pattern.initial_bytes.iter().filter(|b| matches!(b, PatternByte::Exact(_))).count();
        let exact_frac = f32::from(u8::try_from(exact).unwrap_or(u8::MAX))
            / f32::from(u8::try_from(total).unwrap_or(u8::MAX));
        let base_confidence = 0.6f32.mul_add(exact_frac, 0.1)
            + if crc_validated { 0.2 } else { 0.0 }
            + if tail_validated { 0.1 } else { 0.0 };

        if pattern.names.is_empty() {
            return vec![Self {
                pattern_idx,
                module_name,
                name: String::new(),
                name_offset: 0,
                confidence: base_confidence,
                exact_byte_count: exact,
                crc_validated,
                tail_validated,
            }];
        }

        pattern.names.iter().map(|n| Self {
            pattern_idx,
            module_name: module_name.clone(),
            name: n.name.clone(),
            name_offset: n.offset,
            confidence: base_confidence,
            exact_byte_count: exact,
            crc_validated,
            tail_validated,
        }).collect()
    }

    /// Compare two scores for sorting (descending confidence).
    #[must_use]
    pub fn cmp_desc(&self, other: &Self) -> std::cmp::Ordering {
        other.confidence.partial_cmp(&self.confidence).unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| other.exact_byte_count.cmp(&self.exact_byte_count))
    }
}

/// Collision resolution strategy when multiple patterns match the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionStrategy {
    /// Keep only the highest-confidence match.
    HighestConfidence,
    /// Keep all matches.
    KeepAll,
    /// Prefer the match whose module name appears earliest in the priority list.
    ModulePriority,
}

/// Collision resolver configuration.
#[derive(Debug, Clone)]
pub struct CollisionResolver {
    pub strategy: CollisionStrategy,
    /// Module priority list (index 0 = highest priority). Used with `ModulePriority`.
    pub module_priority: Vec<String>,
}

impl CollisionResolver {
    /// Create a resolver using highest-confidence strategy.
    #[must_use]
    pub const fn by_confidence() -> Self {
        Self { strategy: CollisionStrategy::HighestConfidence, module_priority: Vec::new() }
    }

    /// Create a resolver using module priority.
    #[must_use]
    pub const fn by_module_priority(priority: Vec<String>) -> Self {
        Self { strategy: CollisionStrategy::ModulePriority, module_priority: priority }
    }

    /// Resolve a list of competing match scores into the final winners.
    #[must_use]
    pub fn resolve(&self, mut scores: Vec<MatchScore>) -> Vec<MatchScore> {
        if scores.is_empty() {
            return scores;
        }
        match self.strategy {
            CollisionStrategy::KeepAll => scores,
            CollisionStrategy::HighestConfidence => {
                scores.sort_by(MatchScore::cmp_desc);
                // Keep only the top confidence tier (within epsilon).
                let top = scores[0].confidence;
                scores.retain(|s| (s.confidence - top).abs() < 1e-4);
                scores
            }
            CollisionStrategy::ModulePriority => {
                let rank = |name: &str| -> usize {
                    self.module_priority.iter().position(|m| m == name).unwrap_or(usize::MAX)
                };
                scores.sort_by(|a, b| {
                    rank(&a.module_name).cmp(&rank(&b.module_name))
                        .then_with(|| a.cmp_desc(b))
                });
                if let Some(first) = scores.first() {
                    let best_rank = rank(&first.module_name);
                    scores.retain(|s| rank(&s.module_name) == best_rank);
                }
                scores
            }
        }
    }
}

// ── FlirtPattern V2 ────────────────────────────────────────────────────────────

/// Extended pattern with wildcard byte ranges and variant support.
#[derive(Debug, Clone)]
pub struct FlirtPatternV2 {
    /// Inner pattern data.
    pub inner: FlirtPattern,
    /// Module name this pattern belongs to.
    pub module_name: String,
    /// Minimum acceptable wildcard run length (0 = exact).
    pub min_wildcard_run: u8,
    /// Maximum acceptable wildcard run length.
    pub max_wildcard_run: u8,
    /// Variant tag (e.g. "debug", "release", "optimized").
    pub variant: String,
    /// Alternative CRC validations (any one passing is sufficient).
    pub alt_crc: Vec<CrcValidation>,
}

impl FlirtPatternV2 {
    /// Create from an inner pattern.
    #[must_use]
    pub fn new(inner: FlirtPattern, module_name: impl Into<String>) -> Self {
        Self {
            inner,
            module_name: module_name.into(),
            min_wildcard_run: 0,
            max_wildcard_run: 0,
            variant: String::new(),
            alt_crc: Vec::new(),
        }
    }

    /// Set the wildcard run bounds.
    #[must_use]
    pub const fn with_wildcard_run(mut self, min: u8, max: u8) -> Self {
        self.min_wildcard_run = min;
        self.max_wildcard_run = max;
        self
    }

    /// Set the variant tag.
    #[must_use]
    pub fn with_variant(mut self, v: impl Into<String>) -> Self {
        self.variant = v.into();
        self
    }

    /// Add an alternative CRC validation.
    pub fn add_alt_crc(&mut self, crc: CrcValidation) {
        self.alt_crc.push(crc);
    }

    /// Returns `true` if the pattern matches `buf` accounting for wildcard runs.
    #[must_use]
    pub fn matches(&self, buf: &[u8]) -> bool {
        self.inner.matches_initial(buf)
    }

    /// Check CRC: primary and all alternatives.
    #[must_use]
    pub fn crc_ok(&self, buf: &[u8]) -> bool {
        if self.inner.matches_crc16(buf) {
            return true;
        }
        self.alt_crc.iter().any(|c| c.validate(buf))
    }

    /// Full match including initial bytes, CRC, and tail bytes.
    #[must_use]
    pub fn full_match(&self, buf: &[u8]) -> bool {
        self.matches(buf) && self.crc_ok(buf) && self.inner.matches_tail(buf)
    }
}

// ── Multi-pattern matcher ───────────────────────────────────────────────────────


/// Advanced FLIRT matcher that runs all patterns simultaneously (like Aho-Corasick).
///
/// Patterns are stored in a trie. A single pass through the buffer yields all
/// candidate patterns, which are then scored and resolved.
pub struct FlirtMatcherV2 {
    /// All registered patterns.
    patterns: Vec<FlirtPatternV2>,
    /// Trie nodes.
    nodes: Vec<PatternNode>,
    /// Collision resolver.
    pub resolver: CollisionResolver,
    /// Module priority list used when building the resolver.
    pub module_priority: Vec<String>,
}

impl FlirtMatcherV2 {
    /// Create an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        let root = PatternNode::new(0);
        Self {
            patterns: Vec::new(),
            nodes: vec![root],
            resolver: CollisionResolver::by_confidence(),
            module_priority: Vec::new(),
        }
    }

    /// Add a pattern to the matcher and update the trie.
    pub fn add_pattern(&mut self, pat: FlirtPatternV2) {
        let idx = self.patterns.len();
        self.insert_into_trie(&pat.inner.initial_bytes, idx);
        self.patterns.push(pat);
    }

    fn insert_into_trie(&mut self, bytes: &[PatternByte], pattern_idx: usize) {
        let mut node_idx = 0usize;
        for pb in bytes {
            match pb {
                PatternByte::Exact(b) => {
                    let b = *b as usize;
                    let child = self.nodes[node_idx].children[b];
                    if child == u32::MAX {
                        let new_idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                        let depth = self.nodes[node_idx].depth + 1;
                        self.nodes.push(PatternNode::new(depth));
                        self.nodes[node_idx].children[b] = new_idx;
                        node_idx = new_idx as usize;
                    } else {
                        node_idx = child as usize;
                    }
                }
                PatternByte::Wildcard => {
                    let wc = self.nodes[node_idx].wildcard_child;
                    if let Some(idx) = wc {
                        node_idx = idx as usize;
                    } else {
                        let new_idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                        let depth = self.nodes[node_idx].depth + 1;
                        self.nodes.push(PatternNode::new(depth));
                        self.nodes[node_idx].wildcard_child = Some(new_idx);
                        node_idx = new_idx as usize;
                    }
                }
            }
        }
        self.nodes[node_idx].terminal_patterns.push(pattern_idx);
    }

    /// Find all candidate pattern indices for `buf` via trie walk.
    #[must_use]
    pub fn find_candidates(&self, buf: &[u8]) -> Vec<usize> {
        let mut result = Vec::new();
        let mut active: Vec<usize> = vec![0]; // active node indices

        // Collect terminals at root.
        for &p in &self.nodes[0].terminal_patterns {
            result.push(p);
        }

        for &byte in buf {
            let mut next_active = Vec::new();
            for node_idx in active {
                // Exact child.
                let exact_child = self.nodes[node_idx].children[byte as usize];
                if exact_child != u32::MAX {
                    let ni = exact_child as usize;
                    next_active.push(ni);
                    for &p in &self.nodes[ni].terminal_patterns {
                        result.push(p);
                    }
                }
                // Wildcard child.
                if let Some(wc_idx) = self.nodes[node_idx].wildcard_child {
                    let ni = wc_idx as usize;
                    next_active.push(ni);
                    for &p in &self.nodes[ni].terminal_patterns {
                        result.push(p);
                    }
                }
            }
            active = next_active;
            if active.is_empty() {
                break;
            }
        }

        result.sort_unstable();
        result.dedup();
        result
    }

    /// Match `buf` against all patterns and return scored matches.
    ///
    /// `buf` should be the raw bytes of the function.
    #[must_use]
    pub fn match_buf(&self, buf: &[u8]) -> Vec<MatchScore> {
        let candidates = self.find_candidates(buf);
        let mut scores: Vec<MatchScore> = Vec::new();

        for idx in candidates {
            let pat = &self.patterns[idx];
            if !pat.full_match(buf) {
                continue;
            }
            let crc_ok = pat.crc_ok(buf);
            let tail_ok = pat.inner.matches_tail(buf);
            let mut s = MatchScore::compute(
                &pat.inner,
                crc_ok,
                tail_ok,
                pat.module_name.clone(),
                idx,
            );
            scores.append(&mut s);
        }

        self.resolver.resolve(scores)
    }

    /// Set the collision resolver.
    pub fn set_resolver(&mut self, resolver: CollisionResolver) {
        self.resolver = resolver;
    }

    /// Number of patterns registered.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Number of trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Iterate over all patterns.
    pub fn patterns(&self) -> impl Iterator<Item = &FlirtPatternV2> {
        self.patterns.iter()
    }
}

impl Default for FlirtMatcherV2 {
    fn default() -> Self {
        Self::new()
    }
}

// ── Batch matching API ─────────────────────────────────────────────────────────

/// A pending function for batch matching.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// Virtual address of the function.
    pub address: u64,
    /// Raw bytes of the function (enough for pattern matching).
    pub bytes: Vec<u8>,
    /// Optional existing name (empty = unnamed).
    pub existing_name: String,
}

impl FunctionEntry {
    /// Create a new entry.
    #[must_use]
    pub const fn new(address: u64, bytes: Vec<u8>) -> Self {
        Self { address, bytes, existing_name: String::new() }
    }

    /// Set an existing name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.existing_name = name.into();
        self
    }
}

/// Result of batch matching for one function.
#[derive(Debug, Clone)]
pub struct BatchMatchResult {
    pub address: u64,
    pub scores: Vec<MatchScore>,
    /// Best match name (empty if no match).
    pub best_name: String,
    /// Best confidence score.
    pub best_confidence: f32,
}

/// Run multi-pattern matching on a batch of functions.
#[must_use]
pub fn batch_match(matcher: &FlirtMatcherV2, functions: &[FunctionEntry]) -> Vec<BatchMatchResult> {
    functions.iter().map(|f| {
        let scores = matcher.match_buf(&f.bytes);
        let best = scores.iter().max_by(|a, b| {
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
        });
        let (best_name, best_confidence) = best.map_or(
            (String::new(), 0.0),
            |s| (s.name.clone(), s.confidence),
        );
        BatchMatchResult { address: f.address, scores, best_name, best_confidence }
    }).collect()
}

// ── Score aggregation ──────────────────────────────────────────────────────────

/// Aggregated matching statistics for a batch run.
#[derive(Debug, Clone, Default)]
pub struct BatchStats {
    /// Total functions submitted.
    pub total: usize,
    /// Functions that had at least one match.
    pub matched: usize,
    /// Functions with confidence >= 0.9.
    pub high_confidence: usize,
    /// Functions with confidence in [0.5, 0.9).
    pub medium_confidence: usize,
    /// Functions with confidence < 0.5.
    pub low_confidence: usize,
    /// Average confidence across all matched functions.
    pub avg_confidence: f32,
}

impl BatchStats {
    /// Compute stats from batch results.
    #[must_use]
    pub fn compute(results: &[BatchMatchResult]) -> Self {
        let total = results.len();
        let mut matched = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut conf_sum = 0.0f32;

        for r in results {
            if r.best_confidence > 0.0 {
                matched += 1;
                conf_sum += r.best_confidence;
                if r.best_confidence >= 0.9 {
                    high += 1;
                } else if r.best_confidence >= 0.5 {
                    medium += 1;
                } else {
                    low += 1;
                }
            }
        }

        let avg_confidence = if matched > 0 { conf_sum / f32::from(u16::try_from(matched).unwrap_or(u16::MAX)) } else { 0.0 };

        Self { total, matched, high_confidence: high, medium_confidence: medium, low_confidence: low, avg_confidence }
    }

    /// Match rate as a percentage.
    #[must_use]
    pub fn match_rate_pct(&self) -> f64 {
        if self.total == 0 { return 0.0; }
        f64::from(u32::try_from(self.matched).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
            * 100.0
    }
}

// ── Module priority builder ─────────────────────────────────────────────────────

/// Helper to build a module priority list from a map of `module_name` -> score.
///
/// Higher score = higher priority (appears earlier in the list).
#[must_use]
pub fn build_module_priority<S: BuildHasher>(scores: &HashMap<String, u32, S>) -> Vec<String> {
    let mut pairs: Vec<(String, u32)> = scores.iter().map(|(k, &v)| (k.clone(), v)).collect();
    pairs.sort_unstable_by_key(|p| std::cmp::Reverse(p.1));
    pairs.into_iter().map(|(n, _)| n).collect()
}

// ── Variant-aware pattern builder ──────────────────────────────────────────────

/// Builder for `FlirtPatternV2` with variant and range support.
#[derive(Debug, Default)]
pub struct PatternBuilder {
    bytes: Vec<PatternByte>,
    crc16: u16,
    crc_length: u8,
    pattern_length: u16,
    names: Vec<FlirtName>,
    tail_bytes: Vec<TailByte>,
    module_name: String,
    variant: String,
    alt_crc: Vec<CrcValidation>,
}

impl PatternBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an exact byte.
    #[must_use] 
    pub fn exact(mut self, b: u8) -> Self {
        self.bytes.push(PatternByte::Exact(b));
        self
    }

    /// Add a wildcard byte.
    #[must_use] 
    pub fn wildcard(mut self) -> Self {
        self.bytes.push(PatternByte::Wildcard);
        self
    }

    /// Add multiple exact bytes from a slice.
    #[must_use] 
    pub fn exact_bytes(mut self, data: &[u8]) -> Self {
        for &b in data {
            self.bytes.push(PatternByte::Exact(b));
        }
        self
    }

    /// Add N wildcard bytes.
    #[must_use] 
    pub fn wildcards(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.bytes.push(PatternByte::Wildcard);
        }
        self
    }

    /// Set CRC parameters.
    #[must_use] 
    pub const fn crc(mut self, crc16: u16, crc_length: u8) -> Self {
        self.crc16 = crc16;
        self.crc_length = crc_length;
        self
    }

    /// Set the total pattern length.
    #[must_use] 
    pub const fn pattern_length(mut self, len: u16) -> Self {
        self.pattern_length = len;
        self
    }

    /// Add a function name at a given offset.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>, offset: u16, is_public: bool) -> Self {
        self.names.push(FlirtName { name: name.into(), offset, is_public, is_local: false });
        self
    }

    /// Add a tail byte.
    #[must_use] 
    pub fn tail(mut self, offset: u16, value: u8) -> Self {
        self.tail_bytes.push(TailByte { offset, value });
        self
    }

    /// Set the module name.
    #[must_use]
    pub fn module(mut self, name: impl Into<String>) -> Self {
        self.module_name = name.into();
        self
    }

    /// Set the variant tag.
    #[must_use]
    pub fn variant(mut self, v: impl Into<String>) -> Self {
        self.variant = v.into();
        self
    }

    /// Add an alternative CRC validation.
    #[must_use] 
    pub fn alt_crc(mut self, start: usize, len: usize, expected: u16) -> Self {
        self.alt_crc.push(CrcValidation::new(start, len, expected));
        self
    }

    /// Build the final `FlirtPatternV2`.
    #[must_use]
    pub fn build(self) -> FlirtPatternV2 {
        let inner = FlirtPattern {
            initial_bytes: self.bytes,
            crc16: self.crc16,
            crc_length: self.crc_length,
            pattern_length: self.pattern_length,
            names: self.names,
            tail_bytes: self.tail_bytes,
            referenced_names: Vec::new(),
        };
        let mut p = FlirtPatternV2::new(inner, self.module_name);
        p.variant = self.variant;
        p.alt_crc = self.alt_crc;
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc_validation_pass() {
        let data = b"Hello, world!";
        let expected = crc16_flirt(&data[0..5]);
        let cv = CrcValidation::new(0, 5, expected);
        assert!(cv.validate(data));
    }

    #[test]
    fn test_crc_validation_fail() {
        let data = b"Hello, world!";
        let cv = CrcValidation::new(0, 5, 0xDEAD);
        assert!(!cv.validate(data));
    }

    #[test]
    fn test_matcher_v2_basic() {
        let pat = PatternBuilder::new()
            .exact(0x55).exact(0x8B).exact(0xEC)
            .module("libc").name("test_fn", 0, true)
            .build();
        let mut m = FlirtMatcherV2::new();
        m.add_pattern(pat);
        let buf = [0x55u8, 0x8B, 0xEC, 0x00, 0x00];
        let scores = m.match_buf(&buf);
        assert!(!scores.is_empty());
        assert_eq!(scores[0].name, "test_fn");
    }

    #[test]
    fn test_matcher_v2_wildcard() {
        let pat = PatternBuilder::new()
            .exact(0x55).wildcard().exact(0xEC)
            .module("test").name("wc_fn", 0, true)
            .build();
        let mut m = FlirtMatcherV2::new();
        m.add_pattern(pat);
        let buf = [0x55u8, 0xFF, 0xEC];
        let scores = m.match_buf(&buf);
        assert!(!scores.is_empty());
    }

    #[test]
    fn test_collision_resolver_highest_confidence() {
        let resolver = CollisionResolver::by_confidence();
        let s1 = MatchScore { pattern_idx: 0, module_name: "a".into(), name: "fn1".into(), name_offset: 0, confidence: 0.9, exact_byte_count: 5, crc_validated: true, tail_validated: false };
        let s2 = MatchScore { pattern_idx: 1, module_name: "b".into(), name: "fn2".into(), name_offset: 0, confidence: 0.5, exact_byte_count: 3, crc_validated: false, tail_validated: false };
        let resolved = resolver.resolve(vec![s1, s2]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "fn1");
    }

    #[test]
    fn test_batch_stats() {
        let r1 = BatchMatchResult { address: 0x1000, scores: vec![], best_name: "foo".into(), best_confidence: 0.95 };
        let r2 = BatchMatchResult { address: 0x2000, scores: vec![], best_name: String::new(), best_confidence: 0.0 };
        let stats = BatchStats::compute(&[r1, r2]);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.matched, 1);
        assert_eq!(stats.high_confidence, 1);
        assert!((stats.match_rate_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_build_module_priority() {
        let mut scores = HashMap::new();
        scores.insert("libc".to_string(), 10);
        scores.insert("msvcrt".to_string(), 20);
        let priority = build_module_priority(&scores);
        assert_eq!(priority[0], "msvcrt");
        assert_eq!(priority[1], "libc");
    }
}
