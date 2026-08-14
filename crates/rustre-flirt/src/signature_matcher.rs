//! FLIRT signature matching engine.
//!
//! Matches FLIRT signatures against binary data, computes confidence scores,
//! and applies results by renaming functions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::FlirtPattern;

// Re-export shared FLIRT types so downstream callers can refer to them
// through `signature_matcher::` without an extra import.
pub use crate::{FlirtError, FlirtName};

// ─── MatchStrategy ───────────────────────────────────────────────────────────

/// Strategy that controls which addresses are tested during matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchStrategy {
    /// Only test the binary entry point.
    EntryPointOnly,
    /// Scan the entire file byte-by-byte.
    FullFile,
    /// Scan only executable sections.
    ExecutableSections,
    /// Scan at known function-start addresses (provided by analysis).
    KnownFunctions,
}

// ─── MatchCandidate ──────────────────────────────────────────────────────────

/// A single match candidate produced by the signature engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCandidate {
    /// Address where the function begins.
    pub function_addr: u64,
    /// Matched signature name.
    pub signature_name: String,
    /// Confidence in the range [0.0, 1.0].
    pub confidence: f64,
    /// Whether a tail-byte check also passed.
    pub tail_check_passed: bool,
    /// Whether the CRC check passed.
    pub crc_check_passed: bool,
    /// The library this signature belongs to.
    pub library_name: String,
    /// Library version string.
    pub library_version: String,
    /// Alternative names at offsets (if the signature covers multiple functions).
    pub alt_names: Vec<(u16, String)>,
}

impl MatchCandidate {
    /// Compute a composite score (0.0–100.0) for ranking candidates.
    #[must_use]
    pub fn score(&self) -> f64 {
        let mut s = self.confidence * 80.0;
        if self.crc_check_passed {
            s += 15.0;
        }
        if self.tail_check_passed {
            s += 5.0;
        }
        s.min(100.0)
    }

    /// Return true if this is a high-quality match.
    #[must_use]
    pub fn is_high_quality(&self) -> bool {
        self.score() >= 90.0
    }
}

// ─── MatchStats ──────────────────────────────────────────────────────────────

/// Statistics collected during a signature matching run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchStats {
    /// Total addresses tested.
    pub addresses_tested: u64,
    /// Number of first-pass pattern matches (before CRC/tail).
    pub first_pass_matches: u64,
    /// Number of matches that passed CRC verification.
    pub crc_verified: u64,
    /// Number of matches that passed tail-byte verification.
    pub tail_verified: u64,
    /// Final number of accepted matches.
    pub accepted_matches: u64,
    /// Time taken in milliseconds.
    pub time_ms: u64,
}

impl MatchStats {
    /// Return the acceptance rate as a percentage.
    #[must_use]
    pub fn acceptance_rate(&self) -> f64 {
        if self.first_pass_matches == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.accepted_matches).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.first_pass_matches).unwrap_or(u32::MAX))
                * 100.0
        }
    }
}

// ─── ApplyResult ─────────────────────────────────────────────────────────────

/// Result of applying matches to a binary analysis database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyResult {
    /// Functions that were renamed.
    pub renamed: Vec<RenameRecord>,
    /// Matches that were skipped because the function was already named.
    pub skipped: Vec<MatchCandidate>,
    /// Matches that conflicted (two signatures wanted to name the same function).
    pub conflicts: Vec<ConflictRecord>,
}

impl ApplyResult {
    /// Return the number of successful renames.
    #[must_use]
    pub const fn rename_count(&self) -> usize {
        self.renamed.len()
    }

    /// Return the total number of applied matches (renamed + skipped).
    #[must_use]
    pub const fn total_matches(&self) -> usize {
        self.renamed.len() + self.skipped.len() + self.conflicts.len()
    }
}

/// A record of a function rename.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRecord {
    /// Address of the renamed function.
    pub address: u64,
    /// Previous name.
    pub old_name: String,
    /// New name from the signature.
    pub new_name: String,
    /// Confidence of the match.
    pub confidence: f64,
    /// Library name.
    pub library: String,
}

/// A conflict record when two signatures match the same address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// Address of the conflict.
    pub address: u64,
    /// All candidates that matched at this address.
    pub candidates: Vec<MatchCandidate>,
}

// ─── PatternMatcher ──────────────────────────────────────────────────────────

/// Core pattern matching against a byte slice.
pub struct PatternMatcher;

impl PatternMatcher {
    /// Test whether a FLIRT pattern matches at the given offset in `data`.
    #[must_use]
    #[inline]
    pub fn matches_at(pattern: &[crate::PatternByte], data: &[u8], offset: usize) -> bool {
        if offset + pattern.len() > data.len() {
            return false;
        }
        for (i, pb) in pattern.iter().enumerate() {
            match pb {
                crate::PatternByte::Exact(b) => {
                    if data[offset + i] != *b {
                        return false;
                    }
                }
                crate::PatternByte::Wildcard => {}
            }
        }
        true
    }

    /// Scan `data` for all offsets where `pattern` matches.
    #[must_use]
    pub fn find_all(pattern: &[crate::PatternByte], data: &[u8]) -> Vec<usize> {
        if data.len() < pattern.len() {
            return Vec::new();
        }
        let end = data.len() - pattern.len();
        let mut results: Vec<usize> = Vec::with_capacity(8);
        for offset in 0..=end {
            if Self::matches_at(pattern, data, offset) {
                results.push(offset);
            }
        }
        results
    }

    /// Compute the FLIRT tail CRC for a byte slice.
    ///
    /// BUG FIX: this was CRC-16/CCITT-FALSE (forward poly 0x1021) and is used
    /// by the pattern matcher to verify a signature's stored tail CRC — the
    /// same field the rest of the stack computes with the reflected FLIRT CRC.
    /// A third algorithm competing for one field; now routed through
    /// [`crate::crc::flirt_tail`] like every other producer and consumer.
    #[must_use]
    pub fn crc16(data: &[u8]) -> u16 {
        crate::crc::flirt_tail(data)
    }

}

// ─── SignatureMatcher ─────────────────────────────────────────────────────────

/// High-level FLIRT signature matching engine.
///
/// Holds a library of [`FlirtPattern`]s and matches them against binary data.
pub struct SignatureMatcher {
    /// All loaded patterns.
    patterns: Vec<FlirtPattern>,
    /// Matching strategy.
    pub strategy: MatchStrategy,
    /// Minimum confidence to accept a match.
    pub min_confidence: f64,
    /// Whether to require CRC verification.
    pub require_crc: bool,
    /// Whether to apply tail-byte checks.
    pub check_tail_bytes: bool,
}

impl SignatureMatcher {
    /// Create a new matcher with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
            strategy: MatchStrategy::ExecutableSections,
            min_confidence: 0.7,
            require_crc: true,
            check_tail_bytes: true,
        }
    }

    /// Add patterns from a FLIRT library.
    pub fn load_patterns(&mut self, patterns: impl IntoIterator<Item = FlirtPattern>) {
        self.patterns.extend(patterns);
    }

    /// Return the number of loaded patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Match signatures against `data` at the given set of candidate addresses.
    /// `base_address` is the virtual address of `data[0]`.
    #[must_use] 
    pub fn match_at_addresses(
        &self,
        data: &[u8],
        base_address: u64,
        candidate_addresses: &[u64],
    ) -> (Vec<MatchCandidate>, MatchStats) {
        let mut stats = MatchStats::default();
        let mut candidates: Vec<MatchCandidate> = Vec::with_capacity(candidate_addresses.len());

        stats.addresses_tested = candidate_addresses.len() as u64;

        for &addr in candidate_addresses {
            let offset = match addr.checked_sub(base_address) {
                Some(o) => usize::try_from(o).unwrap_or(usize::MAX),
                None => continue,
            };

            for pat in &self.patterns {
                // First-pass: pattern match
                if !PatternMatcher::matches_at(&pat.initial_bytes, data, offset) {
                    continue;
                }
                stats.first_pass_matches += 1;

                // CRC check
                let crc_ok = if self.require_crc && pat.crc16 != 0 {
                    let crc_start = offset + pat.initial_bytes.len();
                    let Some(crc_end) = crc_start.checked_add(pat.crc_length as usize) else { continue };
                    if crc_end > crc_start && crc_end <= data.len() {
                        let computed = PatternMatcher::crc16(&data[crc_start..crc_end]);
                        let ok = computed == pat.crc16;
                        if ok {
                            stats.crc_verified += 1;
                        }
                        ok
                    } else {
                        false
                    }
                } else {
                    stats.crc_verified += 1;
                    true
                };

                if !crc_ok {
                    continue;
                }

                // Tail bytes check
                let tail_ok = if self.check_tail_bytes && !pat.tail_bytes.is_empty() {
                    let mut all_ok = true;
                    for tb in &pat.tail_bytes {
                        let tb_off = offset + tb.offset as usize;
                        if tb_off >= data.len() || data[tb_off] != tb.value {
                            all_ok = false;
                            break;
                        }
                    }
                    if all_ok {
                        stats.tail_verified += 1;
                    }
                    all_ok
                } else {
                    stats.tail_verified += 1;
                    true
                };

                // Compute confidence
                let mut confidence = 0.85;
                if crc_ok {
                    confidence += 0.10;
                }
                if tail_ok {
                    confidence += 0.05;
                }
                confidence = f64::min(confidence, 1.0);

                if confidence < self.min_confidence {
                    continue;
                }

                // Extract primary name
                let primary = pat.names.iter().find(|n| n.offset == 0 && n.is_public);
                let sig_name = primary.map_or_else(|| "unknown".to_owned(), |n| n.name.clone());
                let alt_names: Vec<(u16, String)> = pat
                    .names
                    .iter()
                    .filter(|n| n.offset != 0)
                    .map(|n| (n.offset, n.name.clone()))
                    .collect();

                let mc = MatchCandidate {
                    function_addr: addr,
                    signature_name: sig_name,
                    confidence,
                    tail_check_passed: tail_ok,
                    crc_check_passed: crc_ok,
                    library_name: String::new(),
                    library_version: String::new(),
                    alt_names,
                };

                stats.accepted_matches += 1;
                candidates.push(mc);
            }
        }

        candidates.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        (candidates, stats)
    }

    /// Apply match candidates to a name database, returning rename records.
    #[must_use] 
    pub fn apply_matches(
        &self,
        candidates: Vec<MatchCandidate>,
        existing_names: &HashMap<u64, String>,
    ) -> ApplyResult {
        let mut result = ApplyResult::default();
        let mut claimed: HashMap<u64, MatchCandidate> = HashMap::new();

        for mc in candidates {
            let addr = mc.function_addr;

            if let Some(prev) = claimed.get(&addr) {
                // Conflict: two signatures want to name the same function
                result.conflicts.push(ConflictRecord {
                    address: addr,
                    candidates: vec![prev.clone(), mc],
                });
                continue;
            }

            let old_name = existing_names
                .get(&addr)
                .cloned()
                .unwrap_or_else(|| format!("sub_{addr:08X}"));
            let is_auto_name = old_name.starts_with("sub_") || old_name.starts_with("loc_");

            if !is_auto_name {
                result.skipped.push(mc);
                continue;
            }

            result.renamed.push(RenameRecord {
                address: addr,
                old_name,
                new_name: mc.signature_name.clone(),
                confidence: mc.confidence,
                library: mc.library_name.clone(),
            });
            claimed.insert(addr, mc);
        }

        result
    }
}

impl Default for SignatureMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PatternByte;

    fn make_exact_pattern(bytes: &[u8]) -> Vec<PatternByte> {
        bytes.iter().map(|&b| PatternByte::Exact(b)).collect()
    }

    fn make_test_pattern(name: &str, first_bytes: &[u8]) -> FlirtPattern {
        let mut pat = FlirtPattern::new(make_exact_pattern(first_bytes));
        pat.names.push(FlirtName {
            name: name.to_owned(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        pat
    }

    #[test]
    fn test_pattern_matcher_exact() {
        let pattern = make_exact_pattern(&[0x55, 0x48, 0x89, 0xE5]);
        let data = [0x55u8, 0x48, 0x89, 0xE5, 0x90];
        assert!(PatternMatcher::matches_at(&pattern, &data, 0));
        assert!(!PatternMatcher::matches_at(&pattern, &data, 1));
    }

    #[test]
    fn test_pattern_matcher_wildcard() {
        let pattern = vec![
            PatternByte::Exact(0x55),
            PatternByte::Wildcard,
            PatternByte::Exact(0xE5),
        ];
        let data = [0x55u8, 0xFF, 0xE5];
        assert!(PatternMatcher::matches_at(&pattern, &data, 0));
    }

    #[test]
    fn test_find_all_basic() {
        let pattern = make_exact_pattern(&[0x90, 0x90]);
        let data = [0x90u8, 0x90, 0x00, 0x90, 0x90];
        let matches = PatternMatcher::find_all(&pattern, &data);
        assert_eq!(matches, vec![0, 3]);
    }

    #[test]
    fn test_crc16_known_value() {
        let data = b"123456789";
        let crc = PatternMatcher::crc16(data);
        // The matcher verifies tail CRCs, so it must use the FLIRT CRC
        // (MCRF4XX check value 0x6F91), not CCITT-FALSE's 0x29B1.
        assert_eq!(crc, 0x6F91);
        assert_eq!(crc, crate::crc::flirt_tail(data));
    }

    #[test]
    fn test_match_candidate_score_all_true() {
        let mc = MatchCandidate {
            function_addr: 0x1000,
            signature_name: "foo".to_owned(),
            confidence: 1.0,
            tail_check_passed: true,
            crc_check_passed: true,
            library_name: "lib".to_owned(),
            library_version: "1.0".to_owned(),
            alt_names: vec![],
        };
        assert_eq!(mc.score(), 100.0);
    }

    #[test]
    fn test_match_candidate_is_high_quality() {
        let mc = MatchCandidate {
            function_addr: 0x1000,
            signature_name: "bar".to_owned(),
            confidence: 0.95,
            tail_check_passed: true,
            crc_check_passed: true,
            library_name: "lib".to_owned(),
            library_version: "1.0".to_owned(),
            alt_names: vec![],
        };
        assert!(mc.is_high_quality());
    }

    #[test]
    fn test_match_stats_acceptance_rate_zero() {
        let stats = MatchStats::default();
        assert_eq!(stats.acceptance_rate(), 0.0);
    }

    #[test]
    fn test_match_stats_acceptance_rate() {
        let stats = MatchStats {
            first_pass_matches: 100,
            accepted_matches: 75,
            ..MatchStats::default()
        };
        assert!((stats.acceptance_rate() - 75.0).abs() < 1e-10);
    }

    #[test]
    fn test_signature_matcher_pattern_count() {
        let mut sm = SignatureMatcher::new();
        sm.load_patterns(vec![
            make_test_pattern("fn_a", &[0x55, 0x48]),
            make_test_pattern("fn_b", &[0x41, 0x57]),
        ]);
        assert_eq!(sm.pattern_count(), 2);
    }

    #[test]
    fn test_signature_matcher_basic_match() {
        let mut sm = SignatureMatcher::new();
        sm.require_crc = false;
        sm.check_tail_bytes = false;
        sm.load_patterns(vec![make_test_pattern(
            "my_function",
            &[0x55, 0x48, 0x89, 0xE5],
        )]);

        let data = vec![0x55u8, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let addresses = vec![0x1000u64];
        let (candidates, stats) = sm.match_at_addresses(&data, 0x1000, &addresses);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].signature_name, "my_function");
        assert!(stats.accepted_matches > 0);
    }

    #[test]
    fn test_signature_matcher_no_match_wrong_bytes() {
        let mut sm = SignatureMatcher::new();
        sm.require_crc = false;
        sm.load_patterns(vec![make_test_pattern("fn", &[0xFF, 0xAA])]);
        let data = vec![0x55u8, 0x48, 0x89, 0xE5];
        let (candidates, _) = sm.match_at_addresses(&data, 0x1000, &[0x1000]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_apply_matches_renames_auto_named() {
        let sm = SignatureMatcher::new();
        let mc = MatchCandidate {
            function_addr: 0x1000,
            signature_name: "real_name".to_owned(),
            confidence: 0.95,
            tail_check_passed: true,
            crc_check_passed: true,
            library_name: "libc".to_owned(),
            library_version: "2.31".to_owned(),
            alt_names: vec![],
        };
        let existing = HashMap::new();
        let result = sm.apply_matches(vec![mc], &existing);
        assert_eq!(result.rename_count(), 1);
        assert_eq!(result.renamed[0].new_name, "real_name");
    }

    #[test]
    fn test_apply_matches_skips_named_function() {
        let sm = SignatureMatcher::new();
        let mc = MatchCandidate {
            function_addr: 0x1000,
            signature_name: "lib_fn".to_owned(),
            confidence: 0.95,
            tail_check_passed: true,
            crc_check_passed: true,
            library_name: "lib".to_owned(),
            library_version: "1.0".to_owned(),
            alt_names: vec![],
        };
        let mut existing = HashMap::new();
        existing.insert(0x1000u64, "user_defined_name".to_owned());
        let result = sm.apply_matches(vec![mc], &existing);
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.rename_count(), 0);
    }

    #[test]
    fn test_apply_result_total_matches() {
        let result = ApplyResult {
            renamed: vec![RenameRecord {
                address: 0x1000,
                old_name: "sub_1000".to_owned(),
                new_name: "foo".to_owned(),
                confidence: 0.9,
                library: "lib".to_owned(),
            }],
            skipped: vec![],
            conflicts: vec![],
        };
        assert_eq!(result.total_matches(), 1);
    }

    #[test]
    fn test_crc16_empty() {
        let crc = PatternMatcher::crc16(&[]);
        assert_eq!(crc, 0xFFFF);
    }

    #[test]
    fn test_match_strategy_variants() {
        let strategies = [
            MatchStrategy::EntryPointOnly,
            MatchStrategy::FullFile,
            MatchStrategy::ExecutableSections,
            MatchStrategy::KnownFunctions,
        ];
        assert_eq!(strategies.len(), 4);
    }

    #[test]
    fn test_pattern_matcher_out_of_bounds() {
        let pattern = make_exact_pattern(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        let data = [0x01u8, 0x02, 0x03];
        assert!(!PatternMatcher::matches_at(&pattern, &data, 0));
    }
}
