//! `pattern_search_engine` — Multi-strategy binary pattern search engine.
//!
//! Provides [`PatternSearchEngine`], which orchestrates several search strategies
//! (exact KMP, masked scan, anchored scan) and returns rich [`SearchResult`]
//! values including captures and strategy metadata.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{CaptureResult, CompiledPattern, Pattern, PatternByte, PatternError};

// ─────────────────────────────────────────────────────────────────────────────
// SearchStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// The internal algorithm used by the engine for a given pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchStrategy {
    /// Full KMP on exact (no-wildcard) patterns.
    KmpExact,
    /// Anchor on first exact byte, then verify.
    AnchoredScan,
    /// Linear masked scan (all-wildcard or nibble patterns).
    MaskedScan,
    /// Single-byte trivial pattern.
    ByteScan,
}

impl SearchStrategy {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::KmpExact => "kmp-exact",
            Self::AnchoredScan => "anchored-scan",
            Self::MaskedScan => "masked-scan",
            Self::ByteScan => "byte-scan",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A named pattern registered with the engine, with a pre-selected strategy.
#[derive(Debug, Clone)]
pub struct SearchPattern {
    /// User-supplied label for this pattern.
    pub name: String,
    /// Compiled pattern for fast search.
    compiled: CompiledPattern,
    /// The strategy the engine selected at registration time.
    pub strategy: SearchStrategy,
    /// Whether to report all matches or stop after the first.
    pub stop_after_first: bool,
    /// Optional context note stored with the pattern (e.g., "CVE-2023-1234").
    pub note: String,
}

impl SearchPattern {
    /// Create and register a new `SearchPattern` from a raw `Pattern`.
    ///
    /// The strategy is chosen automatically based on the pattern structure.
    #[must_use]
    pub fn new(name: impl Into<String>, pattern: &Pattern) -> Self {
        let compiled = CompiledPattern::compile(pattern);
        let strategy = Self::select_strategy(pattern);
        Self {
            name: name.into(),
            compiled,
            strategy,
            stop_after_first: false,
            note: String::new(),
        }
    }

    /// Parse a hex-pattern string and wrap it.
    ///
    /// # Errors
    /// Returns `PatternError::Parse` on malformed input.
    pub fn from_hex(name: impl Into<String>, hex: &str) -> Result<Self, PatternError> {
        let pat = Pattern::parse(hex)?;
        Ok(Self::new(name, &pat))
    }

    /// Stop after the first match is found.
    #[must_use]
    pub fn with_stop_after_first(mut self) -> Self {
        self.stop_after_first = true;
        self
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// Pattern length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.compiled.len
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.compiled.len == 0
    }

    /// Choose the best search strategy for a pattern.
    fn select_strategy(pat: &Pattern) -> SearchStrategy {
        if pat.bytes.is_empty() {
            return SearchStrategy::MaskedScan;
        }
        if pat.bytes.len() == 1 {
            return SearchStrategy::ByteScan;
        }
        let all_exact = pat.bytes.iter().all(|b| matches!(b, PatternByte::Exact(_)));
        if all_exact {
            return SearchStrategy::KmpExact;
        }
        let has_exact = pat.bytes.iter().any(|b| matches!(b, PatternByte::Exact(_)));
        if has_exact {
            SearchStrategy::AnchoredScan
        } else {
            SearchStrategy::MaskedScan
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchResult
// ─────────────────────────────────────────────────────────────────────────────

/// A single match produced by [`PatternSearchEngine::find_all`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Name of the pattern that produced this match.
    pub pattern_name: String,
    /// Byte offset in the searched data.
    pub offset: usize,
    /// Length of the match in bytes.
    pub match_len: usize,
    /// Strategy that was used.
    pub strategy: SearchStrategy,
    /// Captured named groups (may be empty).
    pub captures: Vec<CaptureResult>,
    /// Optional context bytes surrounding the match (configurable window).
    pub context: Vec<u8>,
}

impl SearchResult {
    /// Convenience: return the matched slice from `data`.
    #[must_use]
    pub fn matched_bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let end = (self.offset + self.match_len).min(data.len());
        &data[self.offset..end]
    }

    /// Return a hex string of the matched bytes.
    #[must_use]
    pub fn hex_string(&self, data: &[u8]) -> String {
        self.matched_bytes(data)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the search engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Number of context bytes to capture around each match.
    pub context_window: usize,
    /// Maximum number of total results to collect (0 = unlimited).
    pub max_results: usize,
    /// Whether to de-duplicate overlapping matches from the same pattern.
    pub dedup_overlapping: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            context_window: 8,
            max_results: 0,
            dedup_overlapping: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternSearchEngine
// ─────────────────────────────────────────────────────────────────────────────

/// A multi-pattern search engine that applies registered patterns to binary data.
///
/// # Example
///
/// ```rust
/// use rustre_hex_pattern::pattern_search_engine::{PatternSearchEngine, SearchPattern};
///
/// let mut engine = PatternSearchEngine::new();
/// engine.register(SearchPattern::from_hex("dos_magic", "4D 5A").unwrap());
/// let data = b"\x00MZ\x90\x00";
/// let results = engine.find_all(data);
/// assert_eq!(results.len(), 1);
/// assert_eq!(results[0].offset, 1);
/// ```
#[derive(Debug, Default)]
pub struct PatternSearchEngine {
    /// Registered search patterns, keyed by name.
    patterns: Vec<SearchPattern>,
    /// Configuration.
    config: EngineConfig,
    /// Hit statistics per pattern name.
    stats: HashMap<String, usize>,
}

impl PatternSearchEngine {
    /// Create a new engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new engine with a custom configuration.
    #[must_use]
    pub fn with_config(config: EngineConfig) -> Self {
        Self {
            patterns: Vec::new(),
            config,
            stats: HashMap::new(),
        }
    }

    /// Register a [`SearchPattern`] with the engine.
    pub fn register(&mut self, sp: SearchPattern) {
        self.stats.entry(sp.name.clone()).or_insert(0);
        self.patterns.push(sp);
    }

    /// Register from a hex string directly.
    ///
    /// # Errors
    /// Returns `PatternError::Parse` on a bad hex string.
    pub fn register_hex(&mut self, name: &str, hex: &str) -> Result<(), PatternError> {
        let sp = SearchPattern::from_hex(name, hex)?;
        self.register(sp);
        Ok(())
    }

    /// Remove all registered patterns.
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.stats.clear();
    }

    /// Number of registered patterns.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Return the hit count for a named pattern (0 if not registered).
    #[must_use]
    pub fn hit_count(&self, name: &str) -> usize {
        self.stats.get(name).copied().unwrap_or(0)
    }

    /// Reset all hit counters.
    pub fn reset_stats(&mut self) {
        for v in self.stats.values_mut() {
            *v = 0;
        }
    }

    /// Search `data` against all registered patterns and return every match.
    ///
    /// Results are sorted by (offset, pattern_index).
    #[must_use]
    pub fn find_all(&mut self, data: &[u8]) -> Vec<SearchResult> {
        let mut results: Vec<SearchResult> = Vec::new();

        for sp in &self.patterns {
            let offsets = self.run_pattern(sp, data);
            for offset in offsets {
                let ctx = self.extract_context(data, offset, sp.len());
                let result = SearchResult {
                    pattern_name: sp.name.clone(),
                    offset,
                    match_len: sp.len(),
                    strategy: sp.strategy,
                    captures: Vec::new(),
                    context: ctx,
                };
                results.push(result);
                *self.stats.entry(sp.name.clone()).or_insert(0) += 1;

                if sp.stop_after_first {
                    break;
                }
                if self.config.max_results > 0 && results.len() >= self.config.max_results {
                    results.sort_by_key(|r| r.offset);
                    return results;
                }
            }
        }

        if self.config.dedup_overlapping {
            results.dedup_by(|a, b| a.offset == b.offset && a.pattern_name == b.pattern_name);
        }

        results.sort_by_key(|r| r.offset);
        results
    }

    /// Search data and return only the first match across all patterns.
    #[must_use]
    pub fn find_first(&mut self, data: &[u8]) -> Option<SearchResult> {
        let mut best: Option<SearchResult> = None;
        for sp in &self.patterns {
            let offsets = self.run_pattern(sp, data);
            if let Some(&offset) = offsets.first() {
                let ctx = self.extract_context(data, offset, sp.len());
                let result = SearchResult {
                    pattern_name: sp.name.clone(),
                    offset,
                    match_len: sp.len(),
                    strategy: sp.strategy,
                    captures: Vec::new(),
                    context: ctx,
                };
                if best.as_ref().is_none_or(|b| offset < b.offset) {
                    best = Some(result);
                }
            }
        }
        best
    }

    /// Run a single pattern against `data`, returning match offsets.
    fn run_pattern(&self, sp: &SearchPattern, data: &[u8]) -> Vec<usize> {
        sp.compiled.search(data)
    }

    /// Extract a context window around a match.
    fn extract_context(&self, data: &[u8], offset: usize, match_len: usize) -> Vec<u8> {
        if self.config.context_window == 0 {
            return Vec::new();
        }
        let start = offset.saturating_sub(self.config.context_window);
        let end = (offset + match_len + self.config.context_window).min(data.len());
        data[start..end].to_vec()
    }

    /// Return a summary of all patterns and their hit counts.
    #[must_use]
    pub fn summary(&self) -> Vec<(&str, usize)> {
        self.patterns
            .iter()
            .map(|sp| (sp.name.as_str(), self.stats.get(&sp.name).copied().unwrap_or(0)))
            .collect()
    }

    /// Scan a block of data and return byte offsets for each pattern by name.
    ///
    /// This variant does not update statistics and is suitable for dry-run
    /// analysis.
    #[must_use]
    pub fn scan_dry(&self, data: &[u8]) -> HashMap<String, Vec<usize>> {
        let mut out: HashMap<String, Vec<usize>> = HashMap::new();
        for sp in &self.patterns {
            let offsets = sp.compiled.search(data);
            out.insert(sp.name.clone(), offsets);
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience top-level function
// ─────────────────────────────────────────────────────────────────────────────

/// Search `data` for all occurrences of `pattern`, returning rich results.
///
/// This is a one-shot convenience wrapper around [`PatternSearchEngine`].
///
/// # Errors
/// Returns `PatternError::Parse` if `hex` cannot be parsed.
pub fn find_all(hex: &str, data: &[u8]) -> Result<Vec<SearchResult>, PatternError> {
    let mut engine = PatternSearchEngine::new();
    engine.register_hex("search", hex)?;
    Ok(engine.find_all(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiPatternBatch — run many named hex patterns in one call
// ─────────────────────────────────────────────────────────────────────────────

/// A batch of named patterns to search simultaneously.
///
/// Useful when the caller has a list of `(name, hex_string)` pairs.
#[derive(Debug, Default)]
pub struct MultiPatternBatch {
    engine: PatternSearchEngine,
}

impl MultiPatternBatch {
    /// Create an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a named hex pattern to the batch.
    ///
    /// # Errors
    /// Returns `PatternError::Parse` on bad hex.
    pub fn add(&mut self, name: &str, hex: &str) -> Result<&mut Self, PatternError> {
        self.engine.register_hex(name, hex)?;
        Ok(self)
    }

    /// Run the batch against `data` and return all results.
    #[must_use]
    pub fn run(&mut self, data: &[u8]) -> Vec<SearchResult> {
        self.engine.find_all(data)
    }

    /// Return the number of patterns in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.engine.pattern_count()
    }

    /// Returns `true` if no patterns are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.engine.pattern_count() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OffsetFilter — post-process results by address range
// ─────────────────────────────────────────────────────────────────────────────

/// Filter a list of `SearchResult` values to those within an address range.
#[must_use]
pub fn filter_by_range(results: &[SearchResult], base: usize, limit: usize) -> Vec<&SearchResult> {
    results
        .iter()
        .filter(|r| r.offset >= base && r.offset < base + limit)
        .collect()
}

/// Filter results to those produced by a specific pattern name.
#[must_use]
pub fn filter_by_pattern<'a>(results: &'a [SearchResult], name: &str) -> Vec<&'a SearchResult> {
    results.iter().filter(|r| r.pattern_name == name).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> &'static [u8] {
        b"\x00\xDE\xAD\xBE\xEF\x00\xDE\xAD\xBE\xEF\xFF"
    }

    #[test]
    fn test_strategy_selection_exact() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let sp = SearchPattern::new("t", &pat);
        assert_eq!(sp.strategy, SearchStrategy::KmpExact);
    }

    #[test]
    fn test_strategy_selection_anchored() {
        let pat = Pattern::parse("DE ? BE EF").unwrap();
        let sp = SearchPattern::new("t", &pat);
        assert_eq!(sp.strategy, SearchStrategy::AnchoredScan);
    }

    #[test]
    fn test_strategy_selection_masked() {
        let pat = Pattern::parse("? ?").unwrap();
        let sp = SearchPattern::new("t", &pat);
        assert_eq!(sp.strategy, SearchStrategy::MaskedScan);
    }

    #[test]
    fn test_strategy_selection_byte() {
        let pat = Pattern::parse("DE").unwrap();
        let sp = SearchPattern::new("t", &pat);
        assert_eq!(sp.strategy, SearchStrategy::ByteScan);
    }

    #[test]
    fn test_find_all_exact() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("pat", "DE AD BE EF").unwrap();
        let results = engine.find_all(data());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[1].offset, 6);
    }

    #[test]
    fn test_find_all_wildcard() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("wc", "DE ? BE EF").unwrap();
        let results = engine.find_all(data());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_first() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE AD").unwrap();
        let r = engine.find_first(data()).unwrap();
        assert_eq!(r.offset, 1);
    }

    #[test]
    fn test_stop_after_first() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let sp = SearchPattern::new("p", &pat).with_stop_after_first();
        let mut engine = PatternSearchEngine::new();
        engine.register(sp);
        let results = engine.find_all(data());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_hit_count() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE AD").unwrap();
        let _ = engine.find_all(data());
        assert_eq!(engine.hit_count("p"), 2);
    }

    #[test]
    fn test_reset_stats() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE AD").unwrap();
        let _ = engine.find_all(data());
        engine.reset_stats();
        assert_eq!(engine.hit_count("p"), 0);
    }

    #[test]
    fn test_scan_dry_does_not_update_stats() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE AD").unwrap();
        let dry = engine.scan_dry(data());
        assert_eq!(dry["p"].len(), 2);
        assert_eq!(engine.hit_count("p"), 0);
    }

    #[test]
    fn test_context_window() {
        let config = EngineConfig {
            context_window: 2,
            ..Default::default()
        };
        let mut engine = PatternSearchEngine::with_config(config);
        engine.register_hex("p", "DE AD").unwrap();
        let results = engine.find_all(data());
        assert!(!results[0].context.is_empty());
    }

    #[test]
    fn test_filter_by_range() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE AD BE EF").unwrap();
        let results = engine.find_all(data());
        let filtered = filter_by_range(&results, 5, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].offset, 6);
    }

    #[test]
    fn test_filter_by_pattern() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("a", "DE AD").unwrap();
        engine.register_hex("b", "FF").unwrap();
        let results = engine.find_all(data());
        let a_results = filter_by_pattern(&results, "a");
        assert_eq!(a_results.len(), 2);
        let b_results = filter_by_pattern(&results, "b");
        assert_eq!(b_results.len(), 1);
    }

    #[test]
    fn test_multi_pattern_batch() {
        let mut batch = MultiPatternBatch::new();
        batch.add("dos", "4D 5A").unwrap();
        batch.add("elf", "7F 45 4C 46").unwrap();
        let data = b"MZ\x90\x00\x7fELF";
        let results = batch.run(data);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_all_convenience() {
        let data = b"\x00\xDE\xAD\x00";
        let results = find_all("DE AD", data).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_summary() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "DE").unwrap();
        let _ = engine.find_all(data());
        let s = engine.summary();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0, "p");
        assert_eq!(s[0].1, 2);
    }

    #[test]
    fn test_pattern_count() {
        let mut engine = PatternSearchEngine::new();
        assert_eq!(engine.pattern_count(), 0);
        engine.register_hex("a", "AA").unwrap();
        engine.register_hex("b", "BB").unwrap();
        assert_eq!(engine.pattern_count(), 2);
        engine.clear();
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn test_no_match() {
        let mut engine = PatternSearchEngine::new();
        engine.register_hex("p", "FF FF FF FF").unwrap();
        let results = engine.find_all(&[0x00u8; 16]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_strategy_labels() {
        assert_eq!(SearchStrategy::KmpExact.label(), "kmp-exact");
        assert_eq!(SearchStrategy::AnchoredScan.label(), "anchored-scan");
        assert_eq!(SearchStrategy::MaskedScan.label(), "masked-scan");
        assert_eq!(SearchStrategy::ByteScan.label(), "byte-scan");
    }
}
