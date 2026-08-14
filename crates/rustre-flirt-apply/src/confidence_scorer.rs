//! FLIRT match confidence scoring.
//!
//! The confidence scorer combines multiple evidence signals — pattern byte
//! density, CRC verification results, name uniqueness, and cross-reference
//! corroboration — into a single normalised score in `[0, 100]`.

// Use AHashMap (randomised hash) for maps keyed by attacker-controlled data
// (function names and addresses from untrusted .sig/.pat files) to prevent
// hash-collision DoS.
use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};

use crate::casts::{f64_to_u8, usize_to_f64};

// ---------------------------------------------------------------------------
// ScoringSignal
// ---------------------------------------------------------------------------

/// An individual evidence signal contributing to a match confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringSignal {
    /// Human-readable name of the signal.
    pub name: &'static str,
    /// Raw value of the signal (semantics depend on `name`).
    pub raw: f64,
    /// Weight of this signal in the final score (0.0 – 1.0).
    pub weight: f64,
    /// Normalised contribution (raw clamped/scaled to [0, 100] × weight).
    pub contribution: f64,
}

impl ScoringSignal {
    /// Create a new signal and compute `contribution` immediately.
    #[must_use]
    pub fn new(name: &'static str, raw: f64, weight: f64) -> Self {
        let normalised = raw.clamp(0.0, 100.0);
        Self {
            name,
            raw,
            weight,
            contribution: normalised * weight,
        }
    }
}

// ---------------------------------------------------------------------------
// MatchScore
// ---------------------------------------------------------------------------

/// The full scored result for one FLIRT candidate match.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct MatchScore {
    /// Virtual address of the candidate function.
    pub address: u64,
    /// Candidate function name.
    pub name: String,
    /// Final normalised confidence score (0–100).
    pub score: u8,
    /// Individual signals that produced `score`.
    pub signals: Vec<ScoringSignal>,
    /// Whether the CRC check (if present) passed.
    pub crc_passed: bool,
    /// Whether there was a naming conflict at this address.
    pub has_conflict: bool,
}

impl MatchScore {
    /// Returns `true` if the score meets the given threshold.
    #[must_use]
    pub const fn meets_threshold(&self, threshold: u8) -> bool {
        self.score >= threshold
    }

    /// Summary string for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{:#010x} {} score={} crc={} conflict={}",
            self.address, self.name, self.score, self.crc_passed, self.has_conflict
        )
    }
}

// ---------------------------------------------------------------------------
// ConflictResolver
// ---------------------------------------------------------------------------

/// Resolves address-level naming conflicts among a set of scored matches.
///
/// When multiple names compete for the same address, the resolver keeps the
/// highest-scoring candidate and records the rest as conflicts.
#[derive(Debug, Default)]
pub struct ConflictResolver {
    /// address → list of candidates at that address.
    groups: HashMap<u64, Vec<MatchScore>>,
}

impl ConflictResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate match.
    pub fn add(&mut self, m: MatchScore) {
        self.groups.entry(m.address).or_default().push(m);
    }

    /// Add all candidates from a slice.
    pub fn add_all(&mut self, matches: Vec<MatchScore>) {
        for m in matches {
            self.add(m);
        }
    }

    /// Resolve all conflicts.
    ///
    /// Returns `(winners, losers)` where winners has at most one entry per
    /// address and losers holds the discarded lower-confidence candidates.
    #[must_use]
    pub fn resolve(mut self) -> (Vec<MatchScore>, Vec<MatchScore>) {
        let mut winners = Vec::new();
        let mut losers = Vec::new();

        for (_addr, mut candidates) in self.groups.drain() {
            if candidates.len() == 1 {
                winners.push(candidates.remove(0));
            } else {
                // Sort descending by score, then by name length (longer = more specific),
                // then alphabetically.
                candidates.sort_by(|a, b| {
                    b.score
                        .cmp(&a.score)
                        .then(b.name.len().cmp(&a.name.len()))
                        .then(a.name.cmp(&b.name))
                });
                let mut winner = candidates.remove(0);
                winner.has_conflict = true;
                for mut loser in candidates {
                    loser.has_conflict = true;
                    losers.push(loser);
                }
                winners.push(winner);
            }
        }

        (winners, losers)
    }

    /// Number of addresses with more than one candidate.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.groups.values().filter(|v| v.len() > 1).count()
    }
}

// ---------------------------------------------------------------------------
// ScoreArgs
// ---------------------------------------------------------------------------

/// Per-candidate arguments for [`ConfidenceScorer::score`], bundled to keep
/// the method signature within the 7-argument limit.
#[derive(Debug, Clone, Copy)]
pub struct ScoreArgs<'a> {
    /// Virtual address of the match.
    pub address: u64,
    /// Function name from the FLIRT pattern.
    pub name: &'a str,
    /// Total bytes in the pattern.
    pub total_bytes: usize,
    /// Number of non-wildcard bytes.
    pub concrete_bytes: usize,
    /// Whether the pattern has a CRC field.
    pub crc_present: bool,
    /// Whether the CRC check passed (ignored when `!crc_present`).
    pub crc_passed: bool,
    /// Whether at least one known call-site corroborates the match.
    pub xref_known: bool,
}

// ---------------------------------------------------------------------------
// ConfidenceScorer
// ---------------------------------------------------------------------------

/// Scores FLIRT match candidates using a weighted multi-signal model.
///
/// # Signals
///
/// | Signal                  | Weight | Description                                      |
/// |-------------------------|--------|--------------------------------------------------|
/// | `byte_density`          | 0.35   | Fraction of non-wildcard bytes in the pattern    |
/// | `pattern_length`        | 0.20   | Pattern length bonus (saturates at 32 bytes)     |
/// | `crc_verification`      | 0.25   | 100 if CRC passed (or absent), 0 if it failed    |
/// | `name_uniqueness`       | 0.10   | 100 if name appears once in DB, lower otherwise  |
/// | `xref_corroboration`    | 0.10   | Bonus when a known call-site matches             |
pub struct ConfidenceScorer {
    /// Name → occurrence count in the loaded signature database.
    name_frequency: HashMap<String, usize>,
    /// Minimum pattern length for a full length bonus.
    max_pattern_len: usize,
}

impl ConfidenceScorer {
    /// Create a scorer with default weights.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name_frequency: HashMap::new(),
            max_pattern_len: 32,
        }
    }

    /// Register the names of all patterns in the loaded signature database so
    /// that name uniqueness can be scored.
    pub fn register_names(&mut self, names: &[String]) {
        self.name_frequency.clear();
        for n in names {
            *self.name_frequency.entry(n.clone()).or_insert(0) += 1;
        }
    }

    /// Score a single candidate match.
    #[must_use]
    pub fn score(&self, args: ScoreArgs<'_>) -> MatchScore {
        let ScoreArgs { address, name, total_bytes, concrete_bytes, crc_present, crc_passed, xref_known } = args;
        // Signal 1: byte density (percentage of non-wildcard bytes).
        let density = if total_bytes == 0 {
            0.0
        } else {
            usize_to_f64(concrete_bytes) / usize_to_f64(total_bytes) * 100.0
        };
        let s_density = ScoringSignal::new("byte_density", density, 0.35);

        // Signal 2: pattern length bonus.
        let len_bonus = usize_to_f64(total_bytes.min(self.max_pattern_len))
            / usize_to_f64(self.max_pattern_len)
            * 100.0;
        let s_length = ScoringSignal::new("pattern_length", len_bonus, 0.20);

        // Signal 3: CRC verification (100 if passed or absent, 0 if failed).
        let crc_score = if !crc_present || crc_passed { 100.0 } else { 0.0 };
        let s_crc = ScoringSignal::new("crc_verification", crc_score, 0.25);

        // Signal 4: name uniqueness (higher frequency = lower uniqueness score).
        let freq = self.name_frequency.get(name).copied().unwrap_or(1);
        let uniqueness = if freq <= 1 {
            100.0
        } else {
            (100.0 / usize_to_f64(freq)).max(10.0)
        };
        let s_unique = ScoringSignal::new("name_uniqueness", uniqueness, 0.10);

        // Signal 5: xref corroboration.
        let xref_score = if xref_known { 100.0 } else { 0.0 };
        let s_xref = ScoringSignal::new("xref_corroboration", xref_score, 0.10);

        let total: f64 = s_density.contribution
            + s_length.contribution
            + s_crc.contribution
            + s_unique.contribution
            + s_xref.contribution;

        let final_score = f64_to_u8(total.clamp(0.0, 100.0).round());

        MatchScore {
            address,
            name: name.to_string(),
            score: final_score,
            signals: vec![s_density, s_length, s_crc, s_unique, s_xref],
            crc_passed: !crc_present || crc_passed,
            has_conflict: false,
        }
    }

    /// Score a batch of raw match tuples.
    ///
    /// Each tuple is `(address, name, total_bytes, concrete_bytes, crc_present, crc_passed)`.
    #[must_use]
    pub fn score_batch(
        &self,
        matches: &[(u64, &str, usize, usize, bool, bool)],
    ) -> Vec<MatchScore> {
        matches
            .iter()
            .map(|&(addr, name, total, concrete, crc_p, crc_ok)| {
                self.score(ScoreArgs {
                    address: addr,
                    name,
                    total_bytes: total,
                    concrete_bytes: concrete,
                    crc_present: crc_p,
                    crc_passed: crc_ok,
                    xref_known: false,
                })
            })
            .collect()
    }

    /// Filter `matches` to only those meeting `threshold` confidence.
    #[must_use]
    pub fn filter_by_threshold<'a>(&self, matches: &'a [MatchScore], threshold: u8) -> Vec<&'a MatchScore> {
        matches
            .iter()
            .filter(|m| m.meets_threshold(threshold))
            .collect()
    }

    /// Produce a human-readable report for a scored set.
    #[must_use]
    pub fn report(matches: &[MatchScore]) -> String {
        let mut lines = Vec::new();
        lines.push(format!("FLIRT Score Report ({} matches)", matches.len()));
        lines.push("-".repeat(60));
        for m in matches {
            lines.push(m.summary());
            for sig in &m.signals {
                lines.push(format!(
                    "  {:25} raw={:6.1} w={:.2} contrib={:5.1}",
                    sig.name, sig.raw, sig.weight, sig.contribution
                ));
            }
        }
        lines.join("\n")
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ByteMatchAnalyzer
// ---------------------------------------------------------------------------

/// Analyses the byte-level quality of a FLIRT pattern match.
///
/// Computes the ratio of matching concrete bytes, flags patterns with very
/// short leading runs (weak anchors), and estimates the collision probability.
#[derive(Debug, Default)]
pub struct ByteMatchAnalyzer;

impl ByteMatchAnalyzer {
    /// Analyse a pattern described by `total_bytes` and `concrete_bytes`.
    ///
    /// Returns `(density_score, anchor_penalty)` where `density_score` is 0–100
    /// and `anchor_penalty` is subtracted for very short leading concrete runs.
    #[must_use]
    pub fn analyse(total_bytes: usize, concrete_bytes: usize, leading_run: usize) -> (f64, f64) {
        let density = if total_bytes == 0 {
            0.0
        } else {
            usize_to_f64(concrete_bytes) / usize_to_f64(total_bytes) * 100.0
        };

        // Short leading runs are weaker anchors.
        let anchor_penalty = if leading_run < 4 {
            usize_to_f64(4 - leading_run) * 5.0
        } else {
            0.0
        };

        (density, anchor_penalty)
    }

    /// Estimate the collision probability for a concrete prefix of `len` bytes.
    ///
    /// The collision probability per position in a 1 MiB binary is roughly
    /// `256^-len`.  We cap the value at 1.0 and scale to a 0–100 danger score
    /// (higher = more dangerous / more collisions expected).
    #[must_use]
    pub fn collision_risk(prefix_len: usize) -> f64 {
        if prefix_len == 0 {
            return 100.0;
        }
        // Expected collisions in 1 MiB (1 048 576 bytes).
        let binary_size: f64 = 1_048_576.0;
        let p_per_pos = (1.0_f64 / 256.0_f64).powi(i32::try_from(prefix_len).unwrap_or(i32::MAX));
        let expected = binary_size * p_per_pos;
        // Scale: expected >= 10 → 100, expected <= 0.001 → 0.
        (expected * 10.0).clamp(0.0, 100.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scorer() -> ConfidenceScorer {
        let mut s = ConfidenceScorer::new();
        s.register_names(&[
            "strlen".to_string(),
            "strcpy".to_string(),
            "strlen".to_string(), // duplicate → freq = 2
        ]);
        s
    }

    #[test]
    fn test_score_full_concrete_with_crc() {
        let scorer = make_scorer();
        let m = scorer.score(ScoreArgs { address: 0x1000, name: "strcpy", total_bytes: 12, concrete_bytes: 12, crc_present: true, crc_passed: true, xref_known: false });
        assert!(m.score > 60);
        assert!(m.crc_passed);
    }

    #[test]
    fn test_score_crc_failure() {
        let scorer = make_scorer();
        let m = scorer.score(ScoreArgs { address: 0x1000, name: "strlen", total_bytes: 12, concrete_bytes: 12, crc_present: true, crc_passed: false, xref_known: false });
        // CRC fail should suppress score.
        assert!(m.score < 80);
        assert!(!m.crc_passed);
    }

    #[test]
    fn test_score_xref_corroboration() {
        let scorer = make_scorer();
        let m_no_xref = scorer.score(ScoreArgs { address: 0x1000, name: "strlen", total_bytes: 12, concrete_bytes: 10, crc_present: false, crc_passed: false, xref_known: false });
        let m_xref = scorer.score(ScoreArgs { address: 0x1000, name: "strlen", total_bytes: 12, concrete_bytes: 10, crc_present: false, crc_passed: false, xref_known: true });
        assert!(m_xref.score > m_no_xref.score);
    }

    #[test]
    fn test_score_name_duplicates_lower_score() {
        let scorer = make_scorer();
        let m_unique = scorer.score(ScoreArgs { address: 0x1000, name: "strcpy", total_bytes: 12, concrete_bytes: 12, crc_present: false, crc_passed: false, xref_known: false });
        let m_dup = scorer.score(ScoreArgs { address: 0x2000, name: "strlen", total_bytes: 12, concrete_bytes: 12, crc_present: false, crc_passed: false, xref_known: false });
        // strlen has freq=2, strcpy has freq=1, so strcpy should score higher.
        assert!(m_unique.score >= m_dup.score);
    }

    #[test]
    fn test_match_score_meets_threshold() {
        let m = MatchScore {
            address: 0x1000,
            name: "f".to_string(),
            score: 75,
            signals: vec![],
            crc_passed: true,
            has_conflict: false,
        };
        assert!(m.meets_threshold(70));
        assert!(!m.meets_threshold(80));
    }

    #[test]
    fn test_conflict_resolver_single() {
        let mut r = ConflictResolver::new();
        let m = MatchScore {
            address: 0x1000,
            name: "f".to_string(),
            score: 80,
            signals: vec![],
            crc_passed: true,
            has_conflict: false,
        };
        r.add(m);
        let (winners, losers) = r.resolve();
        assert_eq!(winners.len(), 1);
        assert!(losers.is_empty());
        assert!(!winners[0].has_conflict);
    }

    #[test]
    fn test_conflict_resolver_picks_higher() {
        let mut r = ConflictResolver::new();
        r.add(MatchScore {
            address: 0x1000,
            name: "memcpy".to_string(),
            score: 70,
            signals: vec![],
            crc_passed: true,
            has_conflict: false,
        });
        r.add(MatchScore {
            address: 0x1000,
            name: "memmove".to_string(),
            score: 85,
            signals: vec![],
            crc_passed: true,
            has_conflict: false,
        });
        assert_eq!(r.conflict_count(), 1);
        let (winners, losers) = r.resolve();
        assert_eq!(winners[0].name, "memmove");
        assert_eq!(losers[0].name, "memcpy");
    }

    #[test]
    fn test_conflict_resolver_conflict_count() {
        let mut r = ConflictResolver::new();
        r.add(MatchScore {
            address: 0x2000,
            name: "A".to_string(),
            score: 50,
            signals: vec![],
            crc_passed: false,
            has_conflict: false,
        });
        r.add(MatchScore {
            address: 0x2000,
            name: "B".to_string(),
            score: 60,
            signals: vec![],
            crc_passed: false,
            has_conflict: false,
        });
        assert_eq!(r.conflict_count(), 1);
    }

    #[test]
    fn test_byte_match_analyzer_full() {
        let (density, penalty) = ByteMatchAnalyzer::analyse(16, 16, 16);
        assert!((density - 100.0).abs() < f64::EPSILON);
        assert_eq!(penalty, 0.0);
    }

    #[test]
    fn test_byte_match_analyzer_short_leading() {
        let (_density, penalty) = ByteMatchAnalyzer::analyse(16, 12, 2);
        assert!(penalty > 0.0);
    }

    #[test]
    fn test_collision_risk_short() {
        let risk = ByteMatchAnalyzer::collision_risk(2);
        assert!(risk > 0.0);
    }

    #[test]
    fn test_collision_risk_long() {
        let risk = ByteMatchAnalyzer::collision_risk(16);
        // 256^-16 × 1M ≈ effectively 0.
        assert!(risk < 1.0);
    }

    #[test]
    fn test_scoring_signal() {
        let s = ScoringSignal::new("test", 75.0, 0.5);
        assert!((s.contribution - 37.5).abs() < 0.01);
    }

    #[test]
    fn test_score_batch() {
        let scorer = ConfidenceScorer::new();
        let input = vec![
            (0x1000u64, "strlen", 12usize, 12usize, false, false),
            (0x2000u64, "memcpy", 14usize, 10usize, true, true),
        ];
        let scores = scorer.score_batch(&input);
        assert_eq!(scores.len(), 2);
    }

    #[test]
    fn test_filter_by_threshold() {
        let scorer = ConfidenceScorer::new();
        let matches = vec![
            MatchScore {
                address: 0x1000,
                name: "a".to_string(),
                score: 90,
                signals: vec![],
                crc_passed: true,
                has_conflict: false,
            },
            MatchScore {
                address: 0x2000,
                name: "b".to_string(),
                score: 40,
                signals: vec![],
                crc_passed: false,
                has_conflict: false,
            },
        ];
        let filtered = scorer.filter_by_threshold(&matches, 70);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "a");
    }

    #[test]
    fn test_report_not_empty() {
        let scorer = ConfidenceScorer::new();
        let m = scorer.score(ScoreArgs { address: 0x1000, name: "f", total_bytes: 8, concrete_bytes: 8, crc_present: false, crc_passed: false, xref_known: false });
        let report = ConfidenceScorer::report(&[m]);
        assert!(report.contains("FLIRT Score Report"));
    }
}
