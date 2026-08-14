//! `feature_extractor` — obfuscation feature extraction from binary data.
//!
//! [`FeatureExtractor`] computes a [`FeatureVector`] from a binary blob.
//! Each feature is a normalised float in `[0.0, 1.0]` derived from byte-level
//! or instruction-pattern heuristics:
//!
//! | Feature | Source |
//! |---------|--------|
//! | `byte_entropy` | Shannon entropy / 8.0 |
//! | `instruction_diversity` | Unique first-byte opcode count / 256.0 |
//! | `cfg_complexity` | Heuristic branch density |
//! | `call_to_junk_ratio` | CALL density vs NOP density |
//! | `string_coverage` | Printable-ASCII run coverage |
//! | `loop_density` | Loop-pattern count / block count |
//! | `api_hash_score` | Suspected hash-constant density |

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// FeatureVector
// ─────────────────────────────────────────────────────────────────────────────

/// Normalised feature vector extracted from a binary region.
///
/// All fields are in `[0.0, 1.0]` unless otherwise noted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Normalised Shannon entropy (entropy / 8.0).
    pub byte_entropy: f64,
    /// Unique first-byte opcode count / 256.0.
    pub instruction_diversity: f64,
    /// Heuristic CFG complexity (branch density, normalised).
    pub cfg_complexity: f64,
    /// CALL instruction density vs NOP density.
    pub call_to_junk_ratio: f64,
    /// Fraction of bytes covered by printable-ASCII runs (≥ 4 chars).
    pub string_coverage: f64,
    /// Density of loop instructions (LOOP, LOOPNE, LOOPE, short backward JMP).
    pub loop_density: f64,
    /// Density of suspected API-hash constants in 4-byte windows.
    pub api_hash_score: f64,
    /// Raw binary size in bytes (not normalised).
    pub binary_size: usize,
}

impl FeatureVector {
    /// L2 distance between this vector and `other`.
    #[must_use]
    pub fn distance(&self, other: &Self) -> f64 {
        let diff = [
            self.byte_entropy - other.byte_entropy,
            self.instruction_diversity - other.instruction_diversity,
            self.cfg_complexity - other.cfg_complexity,
            self.call_to_junk_ratio - other.call_to_junk_ratio,
            self.string_coverage - other.string_coverage,
            self.loop_density - other.loop_density,
            self.api_hash_score - other.api_hash_score,
        ];
        diff.iter().map(|d| d * d).sum::<f64>().sqrt()
    }

    /// Cosine similarity in `[0.0, 1.0]` (1.0 = identical direction).
    #[must_use]
    pub fn cosine_similarity(&self, other: &Self) -> f64 {
        let a = self.as_array();
        let b = other.as_array();
        let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
        let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
        if na < 1e-12 || nb < 1e-12 {
            return 0.0;
        }
        (dot / (na * nb)).clamp(0.0, 1.0)
    }

    const fn as_array(&self) -> [f64; 7] {
        [
            self.byte_entropy,
            self.instruction_diversity,
            self.cfg_complexity,
            self.call_to_junk_ratio,
            self.string_coverage,
            self.loop_density,
            self.api_hash_score,
        ]
    }

    /// Weighted obfuscation indicator score (higher → more likely obfuscated).
    ///
    /// Weights are empirically chosen:
    /// - entropy 30%, `instruction_diversity` 20%, `cfg_complexity` 20%,
    ///   `string_coverage` (inverted) 15%, `loop_density` 10%, `api_hash` 5%.
    #[must_use]
    pub fn obfuscation_score(&self) -> f64 {
        let string_inv = 1.0 - self.string_coverage;
        self.api_hash_score.mul_add(0.05, self.loop_density.mul_add(0.10, self.cfg_complexity.mul_add(0.20, self.byte_entropy.mul_add(0.30, self.instruction_diversity * 0.20)) + string_inv * 0.15))
            .clamp(0.0, 1.0)
    }

    /// Pretty-print feature names and values.
    #[must_use]
    pub fn to_table(&self) -> String {
        format!(
            "byte_entropy:        {:.4}\n\
             instruction_div:     {:.4}\n\
             cfg_complexity:      {:.4}\n\
             call_to_junk_ratio:  {:.4}\n\
             string_coverage:     {:.4}\n\
             loop_density:        {:.4}\n\
             api_hash_score:      {:.4}\n\
             binary_size:         {}",
            self.byte_entropy,
            self.instruction_diversity,
            self.cfg_complexity,
            self.call_to_junk_ratio,
            self.string_coverage,
            self.loop_density,
            self.api_hash_score,
            self.binary_size,
        )
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self {
            byte_entropy: 0.0,
            instruction_diversity: 0.0,
            cfg_complexity: 0.0,
            call_to_junk_ratio: 0.0,
            string_coverage: 0.0,
            loop_density: 0.0,
            api_hash_score: 0.0,
            binary_size: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Normalises a [`FeatureVector`] using per-feature min/max bounds.
///
/// Each bound is learned from a corpus or set manually.  Bounds are clamped
/// to `[0.0, 1.0]` after linear scaling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureNormalizer {
    pub entropy_max: f64,
    pub diversity_max: f64,
    pub cfg_max: f64,
    pub call_junk_max: f64,
    pub string_max: f64,
    pub loop_max: f64,
    pub api_hash_max: f64,
}

impl Default for FeatureNormalizer {
    fn default() -> Self {
        Self {
            entropy_max: 1.0,
            diversity_max: 1.0,
            cfg_max: 1.0,
            call_junk_max: 1.0,
            string_max: 1.0,
            loop_max: 1.0,
            api_hash_max: 1.0,
        }
    }
}

impl FeatureNormalizer {
    /// Create a normalizer with all maxima set to 1.0 (identity normalisation).
    #[must_use]
    pub fn identity() -> Self {
        Self::default()
    }

    /// Normalize `v` element-wise by dividing each feature by its maximum.
    #[must_use]
    pub fn normalize(&self, v: &FeatureVector) -> FeatureVector {
        FeatureVector {
            byte_entropy: (v.byte_entropy / self.entropy_max.max(1e-12)).clamp(0.0, 1.0),
            instruction_diversity: (v.instruction_diversity / self.diversity_max.max(1e-12))
                .clamp(0.0, 1.0),
            cfg_complexity: (v.cfg_complexity / self.cfg_max.max(1e-12)).clamp(0.0, 1.0),
            call_to_junk_ratio: (v.call_to_junk_ratio / self.call_junk_max.max(1e-12))
                .clamp(0.0, 1.0),
            string_coverage: (v.string_coverage / self.string_max.max(1e-12)).clamp(0.0, 1.0),
            loop_density: (v.loop_density / self.loop_max.max(1e-12)).clamp(0.0, 1.0),
            api_hash_score: (v.api_hash_score / self.api_hash_max.max(1e-12)).clamp(0.0, 1.0),
            binary_size: v.binary_size,
        }
    }

    /// Learn normalizer bounds from a slice of raw (un-normalised) vectors.
    #[must_use]
    pub fn fit(vectors: &[FeatureVector]) -> Self {
        if vectors.is_empty() {
            return Self::default();
        }
        macro_rules! max_field {
            ($field:ident) => {
                vectors
                    .iter()
                    .map(|v| v.$field)
                    .fold(0.0f64, f64::max)
                    .max(1e-12)
            };
        }
        Self {
            entropy_max: max_field!(byte_entropy),
            diversity_max: max_field!(instruction_diversity),
            cfg_max: max_field!(cfg_complexity),
            call_junk_max: max_field!(call_to_junk_ratio),
            string_max: max_field!(string_coverage),
            loop_max: max_field!(loop_density),
            api_hash_max: max_field!(api_hash_score),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts a [`FeatureVector`] from raw binary data.
///
/// All computations are O(n) over the input bytes and produce normalised
/// `[0.0, 1.0]` values suitable for feeding into the hypothesis engine.
#[derive(Debug, Clone, Default)]
pub struct FeatureExtractor {
    /// If set, the extractor will normalise the output vector.
    pub normalizer: Option<FeatureNormalizer>,
}

impl FeatureExtractor {
    /// Create a new extractor without normalisation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an extractor that normalises using `normalizer`.
    #[must_use]
    pub const fn with_normalizer(normalizer: FeatureNormalizer) -> Self {
        Self {
            normalizer: Some(normalizer),
        }
    }

    /// Extract a [`FeatureVector`] from `data`.
    ///
    /// All features are derived in a single pass (or close to it) for efficiency.
    #[must_use]
    pub fn extract(&self, data: &[u8]) -> FeatureVector {
        let raw = Self::extract_raw(data);
        match &self.normalizer {
            Some(n) => n.normalize(&raw),
            None => raw,
        }
    }

    /// Extract a raw (un-normalised) feature vector.
    #[must_use]
    pub fn extract_raw(data: &[u8]) -> FeatureVector {
        if data.is_empty() {
            return FeatureVector::default();
        }

        let binary_size = data.len();

        // ── Byte entropy ──────────────────────────────────────────────────
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = binary_size as f64;
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        let byte_entropy = (entropy / 8.0).clamp(0.0, 1.0);

        // ── Instruction diversity (unique first-byte opcodes) ─────────────
        let unique_opcodes: HashSet<u8> = data.iter().copied().collect();
        let instruction_diversity = unique_opcodes.len() as f64 / 256.0;

        // ── CFG complexity (branch opcode density) ────────────────────────
        let mut branch_count = 0usize;
        let mut call_count = 0usize;
        let mut nop_count = 0usize;
        let mut loop_count = 0usize;
        let mut indirect_count = 0usize;

        let mut i = 0usize;
        while i < data.len() {
            match data[i] {
                0x90 => {
                    nop_count += 1;
                    i += 1;
                }
                0xE8 => {
                    call_count += 1;
                    i += 1;
                }
                0xEB | 0xE9 => {
                    branch_count += 1;
                    i += 1;
                }
                0x74..=0x7F => {
                    branch_count += 1;
                    i += 1;
                }
                0xE0..=0xE2 => {
                    loop_count += 1;
                    branch_count += 1;
                    i += 1;
                }
                0xE3 => {
                    loop_count += 1;
                    branch_count += 1;
                    i += 1;
                }
                0xFF if i + 1 < data.len() && matches!(data[i + 1], 0xE0..=0xE3 | 0x24 | 0x25) => {
                    indirect_count += 1;
                    branch_count += 1;
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }

        let cfg_complexity = {
            let branch_ratio = branch_count as f64 / n;
            let indirect_ratio = if branch_count == 0 {
                0.0
            } else {
                indirect_count as f64 / branch_count as f64
            };
            branch_ratio.mul_add(4.0, indirect_ratio).min(1.0)
        };

        // ── Call-to-junk ratio ────────────────────────────────────────────
        let call_to_junk_ratio = if nop_count == 0 && call_count == 0 {
            0.5 // neutral
        } else if nop_count == 0 {
            1.0
        } else {
            (call_count as f64 / (call_count + nop_count) as f64).clamp(0.0, 1.0)
        };

        // ── String coverage (printable-ASCII runs ≥ 4) ────────────────────
        let mut printable_bytes = 0usize;
        let mut run = 0usize;
        for &b in data {
            if b.is_ascii_graphic() || b == b' ' {
                run += 1;
                if run >= 4 {
                    printable_bytes += 1;
                }
            } else {
                run = 0;
            }
        }
        let string_coverage = (printable_bytes as f64 / n).clamp(0.0, 1.0);

        // ── Loop density ──────────────────────────────────────────────────
        // Count backward short JMPs (EB with negative rel8) as implicit loops.
        let mut backward_jmp = 0usize;
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0xEB && (data[i + 1] as i8) < 0 {
                backward_jmp += 1;
            }
        }
        let total_loops = loop_count + backward_jmp;
        let loop_density = (total_loops as f64 / (n / 32.0).max(1.0)).min(1.0);

        // ── API hash score ────────────────────────────────────────────────
        let mut hash_candidates = 0usize;
        let mut j = 0;
        while j + 4 <= data.len() {
            let word = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            if word != 0 && word != 0xFFFF_FFFF && word.count_ones() >= 8 && word.count_ones() <= 24
            {
                hash_candidates += 1;
            }
            j += 4;
        }
        let four_byte_windows = data.len() / 4;
        let api_hash_score = if four_byte_windows == 0 {
            0.0
        } else {
            (hash_candidates as f64 / four_byte_windows as f64).min(1.0)
        };

        FeatureVector {
            byte_entropy,
            instruction_diversity,
            cfg_complexity,
            call_to_junk_ratio,
            string_coverage,
            loop_density,
            api_hash_score,
            binary_size,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch extraction utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Extract features from multiple binary windows and return as a vector.
#[must_use]
pub fn extract_windows(data: &[u8], window_size: usize, step: usize) -> Vec<FeatureVector> {
    if data.len() < window_size || window_size == 0 {
        return vec![FeatureExtractor::extract_raw(data)];
    }
    let extractor = FeatureExtractor::new();
    let step_eff = step.max(1);
    let est = (data.len().saturating_sub(window_size) / step_eff) + 1;
    let mut results = Vec::with_capacity(est);
    let mut offset = 0;
    while offset + window_size <= data.len() {
        results.push(extractor.extract(&data[offset..offset + window_size]));
        offset += step_eff;
    }
    results
}

/// Compute the mean feature vector across a set of windows.
#[must_use]
pub fn mean_feature_vector(vectors: &[FeatureVector]) -> FeatureVector {
    if vectors.is_empty() {
        return FeatureVector::default();
    }
    let n = vectors.len() as f64;
    let mut acc = FeatureVector::default();
    for v in vectors {
        acc.byte_entropy += v.byte_entropy;
        acc.instruction_diversity += v.instruction_diversity;
        acc.cfg_complexity += v.cfg_complexity;
        acc.call_to_junk_ratio += v.call_to_junk_ratio;
        acc.string_coverage += v.string_coverage;
        acc.loop_density += v.loop_density;
        acc.api_hash_score += v.api_hash_score;
        acc.binary_size += v.binary_size;
    }
    FeatureVector {
        byte_entropy: acc.byte_entropy / n,
        instruction_diversity: acc.instruction_diversity / n,
        cfg_complexity: acc.cfg_complexity / n,
        call_to_junk_ratio: acc.call_to_junk_ratio / n,
        string_coverage: acc.string_coverage / n,
        loop_density: acc.loop_density / n,
        api_hash_score: acc.api_hash_score / n,
        binary_size: acc.binary_size,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_sled_entropy_low() {
        let data = vec![0x90u8; 512];
        let fv = FeatureExtractor::extract_raw(&data);
        // All same byte → entropy = 0
        assert!(
            fv.byte_entropy < 0.01,
            "entropy of NOP sled should be near 0"
        );
    }

    #[test]
    fn test_uniform_bytes_high_entropy() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let fv = FeatureExtractor::extract_raw(&data);
        assert!(
            fv.byte_entropy > 0.95,
            "uniform distribution should be near max entropy"
        );
    }

    #[test]
    fn test_nop_sled_low_call_to_junk() {
        let data = vec![0x90u8; 256];
        let fv = FeatureExtractor::extract_raw(&data);
        assert!(
            fv.call_to_junk_ratio < 0.1,
            "NOP sled should have low call-to-junk ratio"
        );
    }

    #[test]
    fn test_string_coverage_ascii() {
        let mut data = b"Hello, World! This is a test string.".to_vec();
        data.extend_from_slice(&[0x00u8; 8]);
        let fv = FeatureExtractor::extract_raw(&data);
        assert!(
            fv.string_coverage > 0.5,
            "ASCII text should have high string coverage"
        );
    }

    #[test]
    fn test_instruction_diversity() {
        // Single opcode → diversity near 0
        let data = vec![0x90u8; 128];
        let fv = FeatureExtractor::extract_raw(&data);
        assert!(fv.instruction_diversity < 0.05);
        // Many different opcodes
        let rich: Vec<u8> = (0u8..=127).collect();
        let fv2 = FeatureExtractor::extract_raw(&rich);
        assert!(fv2.instruction_diversity > 0.4);
    }

    #[test]
    fn test_obfuscation_score_all_nop() {
        let data = vec![0x90u8; 256];
        let fv = FeatureExtractor::extract_raw(&data);
        // Low entropy → low obfuscation score (might be padding, not encrypted)
        assert!(fv.obfuscation_score() < 0.5);
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let data = vec![0xABu8; 128];
        let fv = FeatureExtractor::extract_raw(&data);
        assert!((fv.cosine_similarity(&fv) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_distance_zero_self() {
        let data = vec![0x55u8; 64];
        let fv = FeatureExtractor::extract_raw(&data);
        assert!(fv.distance(&fv) < 1e-12);
    }

    #[test]
    fn test_extract_windows() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let windows = extract_windows(&data, 256, 128);
        assert!(windows.len() >= 3);
    }

    #[test]
    fn test_normalizer_fit() {
        let vectors: Vec<FeatureVector> = vec![
            FeatureExtractor::extract_raw(&vec![0x90u8; 256]),
            FeatureExtractor::extract_raw(&(0u8..=255).cycle().take(1024).collect::<Vec<_>>()),
        ];
        let norm = FeatureNormalizer::fit(&vectors);
        let normalized = norm.normalize(&vectors[0]);
        assert!(normalized.byte_entropy <= 1.0);
        assert!(normalized.instruction_diversity <= 1.0);
    }

    #[test]
    fn test_mean_feature_vector() {
        let v1 = FeatureVector {
            byte_entropy: 0.4,
            ..Default::default()
        };
        let v2 = FeatureVector {
            byte_entropy: 0.8,
            ..Default::default()
        };
        let mean = mean_feature_vector(&[v1, v2]);
        assert!((mean.byte_entropy - 0.6).abs() < 1e-9);
    }
}
