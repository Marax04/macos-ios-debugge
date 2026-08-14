//! Match confidence scoring for FLIRT pattern application.
//!
//! Computes a numerical confidence score for each candidate match based on
//! multiple independent evidence signals:
//!
//! 1. **Pattern length** — longer matches are more reliable.
//! 2. **CRC check** — CRC-16 agreement adds high confidence.
//! 3. **Symbolic reference consistency** — referenced names point to already-
//!    identified functions.
//! 4. **Calling-convention coherence** — function prologue matches expected CC.
//! 5. **Neighbourhood check** — nearby functions already identified and consistent.

// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names/addresses from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use crate::casts::usize_to_f32;

// ─────────────────────────────────────────────────────────────────────────────
// ScoreWeights
// ─────────────────────────────────────────────────────────────────────────────

/// Per-signal weights used by the scorer.
///
/// All values should be non-negative; the total score is bounded to [0.0, 1.0]
/// by the normaliser.
#[derive(Debug, Clone)]
pub struct ScoreWeights {
    /// Weight for pattern length signal (per byte above `MIN_RELIABLE`).
    pub length_weight: f32,
    /// Bonus when CRC-16 passes.
    pub crc_match_bonus: f32,
    /// Penalty when CRC-16 fails but matching was forced.
    pub crc_fail_penalty: f32,
    /// Bonus per symbolic reference that resolves correctly.
    pub xref_resolve_bonus: f32,
    /// Penalty per unresolved symbolic reference.
    pub xref_unresolved_penalty: f32,
    /// Bonus for matching calling convention.
    pub cc_match_bonus: f32,
    /// Penalty for mismatched calling convention.
    pub cc_mismatch_penalty: f32,
    /// Bonus per neighbouring already-matched function consistent with this one.
    pub neighbour_bonus: f32,
    /// Penalty if a collision exists (another pattern matched the same offset).
    pub collision_penalty: f32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            length_weight: 0.015,
            crc_match_bonus: 0.30,
            crc_fail_penalty: 0.10,
            xref_resolve_bonus: 0.08,
            xref_unresolved_penalty: 0.04,
            cc_match_bonus: 0.10,
            cc_mismatch_penalty: 0.15,
            neighbour_bonus: 0.05,
            collision_penalty: 0.20,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Calling convention enum (local copy to avoid cross-crate dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    Cdecl,
    Stdcall,
    Fastcall,
    MsX64,
    SysVX64,
    Unknown,
}

/// Infer calling convention from the prologue bytes of a buffer.
#[must_use]
pub fn infer_call_conv(data: &[u8]) -> CallConv {
    if data.len() < 4 {
        return CallConv::Unknown;
    }
    // x64 Microsoft ABI: mov [rsp+8], rcx  →  48 89 4C 24 08
    if data.starts_with(&[0x48, 0x89, 0x4C, 0x24, 0x08]) {
        return CallConv::MsX64;
    }
    // x64 sysv: push rbp / mov rbp,rsp  →  55 48 89 E5
    if data.starts_with(&[0x55, 0x48, 0x89, 0xE5]) {
        return CallConv::SysVX64;
    }
    // sub rsp, N  →  48 83 EC xx
    if data.len() >= 4 && data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC {
        return CallConv::MsX64;
    }
    // x86 cdecl/stdcall: push ebp / mov ebp,esp  →  55 8B EC
    if data.starts_with(&[0x55, 0x8B, 0xEC]) {
        return CallConv::Cdecl;
    }
    // x86 fastcall: push ecx / push edx prologue variants
    if data.starts_with(&[0x51, 0x52]) {
        return CallConv::Fastcall;
    }
    CallConv::Unknown
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchEvidence
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence signals for a single match candidate.
#[derive(Debug, Clone)]
pub struct MatchEvidence {
    /// Number of concrete (non-wildcard) bytes matched.
    pub matched_bytes: usize,
    /// Whether the CRC-16 passed.
    pub crc_passed: bool,
    /// Whether a CRC check was performed at all.
    pub crc_available: bool,
    /// Number of symbolic references that resolved correctly.
    pub xrefs_resolved: usize,
    /// Number of symbolic references that could not be resolved.
    pub xrefs_unresolved: usize,
    /// Expected calling convention (from the pattern / sig file).
    pub expected_cc: CallConv,
    /// Observed calling convention (from the binary bytes).
    pub observed_cc: CallConv,
    /// Number of neighbouring already-matched functions consistent with this.
    pub consistent_neighbours: usize,
    /// Whether a collision (other pattern at same offset) exists.
    pub has_collision: bool,
    /// Raw pattern length (including wildcards).
    pub pattern_len: usize,
}

impl MatchEvidence {
    /// Minimum reliable pattern length for full length score.
    const MIN_RELIABLE_LEN: usize = 16;

    /// Compute a normalised confidence score in `[0.0, 1.0]`.
    #[must_use]
    pub fn confidence(&self, weights: &ScoreWeights) -> f32 {
        let mut score = 0.0f32;

        // Length signal: scales linearly with concrete bytes above minimum.
        let effective_len = self.matched_bytes.min(64);
        if effective_len >= Self::MIN_RELIABLE_LEN {
            score += usize_to_f32(effective_len - Self::MIN_RELIABLE_LEN) * weights.length_weight;
        } else {
            // Under minimum: small starting penalty.
            score -= usize_to_f32(Self::MIN_RELIABLE_LEN - effective_len) * 0.005;
        }

        // CRC signal.
        if self.crc_available {
            if self.crc_passed {
                score += weights.crc_match_bonus;
            } else {
                score -= weights.crc_fail_penalty;
            }
        }

        // Xref signals.
        score = usize_to_f32(self.xrefs_resolved).mul_add(weights.xref_resolve_bonus, score);
        score = usize_to_f32(self.xrefs_unresolved).mul_add(-weights.xref_unresolved_penalty, score);

        // Calling convention.
        if self.expected_cc != CallConv::Unknown && self.observed_cc != CallConv::Unknown {
            if self.expected_cc == self.observed_cc {
                score += weights.cc_match_bonus;
            } else {
                score -= weights.cc_mismatch_penalty;
            }
        }

        // Neighbour signal.
        score = usize_to_f32(self.consistent_neighbours).mul_add(weights.neighbour_bonus, score);

        // Collision penalty.
        if self.has_collision {
            score -= weights.collision_penalty;
        }

        score.clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScoredMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A match candidate together with its computed confidence score.
#[derive(Debug, Clone)]
pub struct ScoredMatch {
    /// Byte offset in the binary.
    pub offset: usize,
    /// Matched function name.
    pub name: String,
    /// Library this function comes from.
    pub library: String,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
    /// The evidence used to compute the score.
    pub evidence: MatchEvidence,
}

impl ScoredMatch {
    /// `true` if the confidence is high enough to auto-rename.
    #[must_use]
    pub fn is_high_confidence(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScoreCandidateArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Input bundle for [`MatchScorer::score_candidate`].
///
/// Groups all per-candidate parameters into a single struct to keep the method
/// signature within the 7-argument limit required by `clippy::too_many_arguments`.
#[derive(Clone, Copy)]
pub struct ScoreCandidateArgs<'a> {
    /// Byte offset of the candidate in the binary.
    pub offset: usize,
    /// Function name associated with the pattern.
    pub name: &'a str,
    /// Library or signature-file tag.
    pub library: &'a str,
    /// Pattern bytes (wildcard-aware).
    pub pattern: &'a [Option<u8>],
    /// CRC-16 expected from the signature.
    pub crc_expected: Option<u16>,
    /// CRC-16 computed from the binary.
    pub crc_computed: Option<u16>,
    /// Number of cross-references already resolved.
    pub xrefs_resolved: usize,
    /// Number of cross-references that remain unresolved.
    pub xrefs_unresolved: usize,
    /// Expected calling convention per the signature.
    pub expected_cc: CallConv,
    /// Raw bytes at the candidate offset.
    pub binary_slice: &'a [u8],
    /// Whether another candidate also matched at this offset.
    pub has_collision: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchScorer
// ─────────────────────────────────────────────────────────────────────────────

/// Scores a collection of raw candidates and produces ranked [`ScoredMatch`]es.
pub struct MatchScorer {
    pub weights: ScoreWeights,
    /// Threshold above which a match is considered "high confidence".
    pub high_confidence_threshold: f32,
    /// Already-identified names in the binary: offset → name.
    pub known_names: HashMap<usize, String>,
    /// Neighbour search radius in bytes.
    pub neighbour_radius: usize,
}

impl Default for MatchScorer {
    fn default() -> Self {
        Self {
            weights: ScoreWeights::default(),
            high_confidence_threshold: 0.70,
            known_names: HashMap::new(),
            neighbour_radius: 256,
        }
    }
}

impl MatchScorer {
    /// Create a scorer with default weights.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an already-known function name at an offset.
    pub fn add_known(&mut self, offset: usize, name: impl Into<String>) {
        self.known_names.insert(offset, name.into());
    }

    /// Count consistent neighbours within `radius` bytes of `offset`.
    fn count_neighbours(&self, offset: usize, radius: usize) -> usize {
        let lo = offset.saturating_sub(radius);
        let hi = offset + radius;
        self.known_names.keys().filter(|&&k| k >= lo && k <= hi && k != offset).count()
    }

    /// Score a single candidate given the binary slice at `offset`.
    #[must_use]
    pub fn score_candidate(&self, args: ScoreCandidateArgs<'_>) -> ScoredMatch {
        let ScoreCandidateArgs {
            offset, name, library, pattern,
            crc_expected, crc_computed,
            xrefs_resolved, xrefs_unresolved,
            expected_cc, binary_slice, has_collision,
        } = args;
        let matched_bytes = pattern.iter().filter(|b| b.is_some()).count();
        let crc_available = crc_expected.is_some() && crc_computed.is_some();
        let crc_passed = crc_available && crc_expected == crc_computed;
        let observed_cc = infer_call_conv(binary_slice);
        let consistent_neighbours = self.count_neighbours(offset, self.neighbour_radius);

        let evidence = MatchEvidence {
            matched_bytes,
            crc_passed,
            crc_available,
            xrefs_resolved,
            xrefs_unresolved,
            expected_cc,
            observed_cc,
            consistent_neighbours,
            has_collision,
            pattern_len: pattern.len(),
        };

        let confidence = evidence.confidence(&self.weights);

        ScoredMatch {
            offset,
            name: name.to_string(),
            library: library.to_string(),
            confidence,
            evidence,
        }
    }

    /// Score multiple candidates at the same offset and return them ranked.
    #[must_use]
    pub fn rank_candidates(&self, mut candidates: Vec<ScoredMatch>) -> Vec<ScoredMatch> {
        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    /// Return the best match for an offset (highest score), if any.
    #[must_use]
    pub fn best(&self, candidates: Vec<ScoredMatch>) -> Option<ScoredMatch> {
        self.rank_candidates(candidates).into_iter().next()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfidenceLevel
// ─────────────────────────────────────────────────────────────────────────────

/// Discrete confidence level for human-readable reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    /// Very low confidence — likely a false positive.
    VeryLow,
    /// Low confidence.
    Low,
    /// Moderate — worth reviewing manually.
    Medium,
    /// High — can auto-apply.
    High,
    /// Certain — CRC + full length + xrefs all agree.
    Certain,
}

impl ConfidenceLevel {
    /// Classify a raw confidence score.
    #[must_use]
    pub fn classify(score: f32) -> Self {
        match score {
            s if s >= 0.92 => Self::Certain,
            s if s >= 0.75 => Self::High,
            s if s >= 0.55 => Self::Medium,
            s if s >= 0.30 => Self::Low,
            _ => Self::VeryLow,
        }
    }

    /// Return the display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VeryLow => "VERY_LOW",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Certain => "CERTAIN",
        }
    }
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScorerStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics from a scoring run.
#[derive(Debug, Clone, Default)]
pub struct ScorerStats {
    pub total_candidates: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub avg_confidence: f32,
}

impl ScorerStats {
    /// Compute stats from a slice of scored matches.
    #[must_use]
    pub fn compute(matches: &[ScoredMatch]) -> Self {
        if matches.is_empty() {
            return Self::default();
        }
        let mut s = Self { total_candidates: matches.len(), ..Default::default() };
        let total: f32 = matches.iter().map(|m| m.confidence).sum();
        s.avg_confidence = total / usize_to_f32(matches.len());
        for m in matches {
            match ConfidenceLevel::classify(m.confidence) {
                ConfidenceLevel::High | ConfidenceLevel::Certain => s.high_confidence += 1,
                ConfidenceLevel::Medium => s.medium_confidence += 1,
                _ => s.low_confidence += 1,
            }
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(matched: usize, crc_ok: bool, xref_ok: usize) -> MatchEvidence {
        MatchEvidence {
            matched_bytes: matched,
            crc_passed: crc_ok,
            crc_available: true,
            xrefs_resolved: xref_ok,
            xrefs_unresolved: 0,
            expected_cc: CallConv::SysVX64,
            observed_cc: CallConv::SysVX64,
            consistent_neighbours: 0,
            has_collision: false,
            pattern_len: matched,
        }
    }

    #[test]
    fn test_high_confidence_evidence() {
        let w = ScoreWeights::default();
        let e = make_evidence(32, true, 2);
        let s = e.confidence(&w);
        assert!(s > 0.7, "expected high confidence, got {s}");
    }

    #[test]
    fn test_low_confidence_evidence() {
        let w = ScoreWeights::default();
        let e = MatchEvidence {
            matched_bytes: 4,
            crc_passed: false,
            crc_available: true,
            xrefs_resolved: 0,
            xrefs_unresolved: 2,
            expected_cc: CallConv::MsX64,
            observed_cc: CallConv::SysVX64,
            consistent_neighbours: 0,
            has_collision: true,
            pattern_len: 4,
        };
        let s = e.confidence(&w);
        assert!(s < 0.4, "expected low confidence, got {s}");
    }

    #[test]
    fn test_infer_call_conv_sysv() {
        let data = &[0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        assert_eq!(infer_call_conv(data), CallConv::SysVX64);
    }

    #[test]
    fn test_infer_call_conv_ms_x64() {
        let data = &[0x48u8, 0x89, 0x4C, 0x24, 0x08];
        assert_eq!(infer_call_conv(data), CallConv::MsX64);
    }

    #[test]
    fn test_rank_candidates() {
        let scorer = MatchScorer::new();
        let make = |name: &str, conf: f32| ScoredMatch {
            offset: 0x1000,
            name: name.into(),
            library: "lib".into(),
            confidence: conf,
            evidence: make_evidence(16, true, 0),
        };
        let cands = vec![make("low", 0.3), make("high", 0.9), make("mid", 0.6)];
        let ranked = scorer.rank_candidates(cands);
        assert_eq!(ranked[0].name, "high");
        assert_eq!(ranked[2].name, "low");
    }

    #[test]
    fn test_confidence_level_classify() {
        assert_eq!(ConfidenceLevel::classify(0.95), ConfidenceLevel::Certain);
        assert_eq!(ConfidenceLevel::classify(0.80), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::classify(0.60), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::classify(0.10), ConfidenceLevel::VeryLow);
    }

    #[test]
    fn test_scorer_stats() {
        let make_sm = |conf: f32| ScoredMatch {
            offset: 0,
            name: "f".into(),
            library: "l".into(),
            confidence: conf,
            evidence: make_evidence(16, true, 0),
        };
        let matches = vec![make_sm(0.95), make_sm(0.80), make_sm(0.40)];
        let stats = ScorerStats::compute(&matches);
        assert_eq!(stats.total_candidates, 3);
        assert_eq!(stats.high_confidence, 2);
    }
}
