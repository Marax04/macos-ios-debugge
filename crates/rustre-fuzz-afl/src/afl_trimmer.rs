/// AFL input trimmer: reduce a seed to its minimal size while preserving coverage.
///
/// AFL uses binary search to find the smallest input that still triggers the
/// same set of edges. This module provides:
///
/// - `AflTrimmer` — orchestrates trim rounds via a callback
/// - `TrimStrategy` — binary-chop vs sequential block removal
/// - `TrimResult` — outcome of one trim round
/// - `EffectivenessMap` — tracks which byte offsets contribute to coverage
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrimmerError {
    #[error("input is empty")]
    EmptyInput,
    #[error("oracle returned an error on step {0}: {1}")]
    OracleError(usize, String),
    #[error("maximum rounds ({0}) reached without converging")]
    MaxRoundsExceeded(usize),
    #[error("block size is zero")]
    ZeroBlockSize,
}

// ---------------------------------------------------------------------------
// TrimStrategy
// ---------------------------------------------------------------------------

/// Strategy controlling how blocks are selected for removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum TrimStrategy {
    /// Binary-chop: try removing half the input each time (fast).
    BinaryChop,
    /// Sequential block removal: scan from start to end removing `block_size` bytes
    /// at each position (slow but thorough).
    SequentialBlock {
        /// Number of bytes to remove per attempt.
        block_size: usize,
    },
    /// Cascade: start with `BinaryChop`, finish with `SequentialBlock { block_size: 1 }`.
    #[default]
    Cascade,
}


// ---------------------------------------------------------------------------
// TrimResult — outcome of one oracle call
// ---------------------------------------------------------------------------

/// Result from one oracle invocation during trimming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrimResult {
    /// The trimmed input still triggers the same coverage — keep it.
    Interesting,
    /// The trimmed input lost coverage — restore and try something else.
    Uninteresting,
    /// The oracle crashed or timed out — treat as uninteresting.
    Timeout,
}

// ---------------------------------------------------------------------------
// TrimOracle — trait for the coverage callback
// ---------------------------------------------------------------------------

/// A closure or object that runs the target with `input` and reports whether
/// coverage was preserved. Implementors must be deterministic given the same input.
pub trait TrimOracle {
    fn run(&mut self, input: &[u8]) -> TrimResult;
}

/// Blanket implementation for `FnMut(&[u8]) -> TrimResult` closures.
impl<F: FnMut(&[u8]) -> TrimResult> TrimOracle for F {
    fn run(&mut self, input: &[u8]) -> TrimResult {
        self(input)
    }
}

// ---------------------------------------------------------------------------
// TrimmerConfig
// ---------------------------------------------------------------------------

/// Configuration for `AflTrimmer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrimmerConfig {
    /// Maximum number of trim rounds before giving up.
    pub max_rounds: usize,
    /// Minimum input size (in bytes) — trimming stops when this is reached.
    pub min_size: usize,
    /// Strategy to use.
    pub strategy: TrimStrategy,
    /// For `SequentialBlock` and `Cascade` finish pass: starting block size.
    pub initial_block_size: usize,
}

impl Default for TrimmerConfig {
    fn default() -> Self {
        Self {
            max_rounds: 1024,
            min_size: 1,
            strategy: TrimStrategy::Cascade,
            initial_block_size: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// TrimmerStats
// ---------------------------------------------------------------------------

/// Statistics from a trim run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrimmerStats {
    pub rounds: usize,
    pub oracle_calls: usize,
    pub bytes_removed: usize,
    pub reductions: usize,
    pub timeouts: usize,
}

// ---------------------------------------------------------------------------
// EffectivenessMap — byte-level contribution tracking
// ---------------------------------------------------------------------------

/// Tracks which byte offsets in the *original* input were found to be
/// necessary for coverage. Built by running the oracle with individual bytes
/// zeroed out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessMap {
    /// For each byte offset: `true` = the byte is effective (its removal loses coverage).
    pub effective: Vec<bool>,
    /// Original input length.
    pub input_len: usize,
    /// Number of oracle calls made.
    pub oracle_calls: usize,
}

impl EffectivenessMap {
    /// Build the effectiveness map for `input` using `oracle`.
    ///
    /// For each byte position, the byte is zeroed and the oracle is called.
    /// If coverage is lost, the byte is marked effective.
    pub fn build<O: TrimOracle>(input: &[u8], oracle: &mut O) -> Self {
        let n = input.len();
        let mut effective = vec![false; n];
        let mut oracle_calls = 0;

        for i in 0..n {
            let mut candidate = input.to_vec();
            candidate[i] = 0;
            oracle_calls += 1;
            if oracle.run(&candidate) != TrimResult::Interesting {
                // Removing/zeroing this byte breaks coverage → it is effective.
                effective[i] = true;
            }
        }

        Self { effective, input_len: n, oracle_calls }
    }

    /// Count of effective (necessary) bytes.
    #[must_use] 
    pub fn effective_count(&self) -> usize {
        self.effective.iter().filter(|&&e| e).count()
    }

    /// Produce a minimal candidate by keeping only effective bytes.
    #[must_use] 
    pub fn minimal_input(&self, original: &[u8]) -> Vec<u8> {
        original
            .iter()
            .zip(self.effective.iter())
            .filter_map(|(&b, &eff)| if eff { Some(b) } else { None })
            .collect()
    }

    /// Coverage ratio: effective bytes / total bytes.
    #[must_use] 
    pub fn effectiveness_ratio(&self) -> f64 {
        if self.input_len == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.effective_count()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.input_len).unwrap_or(u32::MAX))
    }
}

// ---------------------------------------------------------------------------
// AflTrimmer — main engine
// ---------------------------------------------------------------------------

/// Reduces an input to its minimal size preserving coverage.
///
/// Usage:
/// ```rust,ignore
/// let mut trimmer = AflTrimmer::new(TrimmerConfig::default());
/// let minimal = trimmer.trim(original_input, &mut oracle)?;
/// ```
pub struct AflTrimmer {
    config: TrimmerConfig,
    stats: TrimmerStats,
}

impl AflTrimmer {
    #[must_use] 
    pub fn new(config: TrimmerConfig) -> Self {
        Self { config, stats: TrimmerStats::default() }
    }

    /// Run the trim procedure on `input`. Returns the minimal input that preserves
    /// coverage according to `oracle`.
    ///
    /// # Errors
    /// Returns [`TrimmerError`] on empty input or if the oracle fails.
    pub fn trim<O: TrimOracle>(
        &mut self,
        input: Vec<u8>,
        oracle: &mut O,
    ) -> Result<Vec<u8>, TrimmerError> {
        if input.is_empty() {
            return Err(TrimmerError::EmptyInput);
        }
        self.stats = TrimmerStats::default();

        let result = match self.config.strategy {
            TrimStrategy::BinaryChop => self.trim_binary_chop(input, oracle)?,
            TrimStrategy::SequentialBlock { block_size } => {
                self.trim_sequential(input, block_size, oracle)?
            }
            TrimStrategy::Cascade => {
                let after_chop = self.trim_binary_chop(input, oracle)?;
                self.trim_sequential(after_chop, 1, oracle)?
            }
        };

        Ok(result)
    }

    fn trim_binary_chop<O: TrimOracle>(
        &mut self,
        mut current: Vec<u8>,
        oracle: &mut O,
    ) -> Result<Vec<u8>, TrimmerError> {
        let mut rounds = 0;

        loop {
            if current.len() <= self.config.min_size {
                break;
            }
            if rounds >= self.config.max_rounds {
                return Err(TrimmerError::MaxRoundsExceeded(self.config.max_rounds));
            }
            rounds += 1;
            self.stats.rounds += 1;

            let half = current.len() / 2;
            if half == 0 {
                break;
            }

            // Try keeping the first half.
            let candidate = current[..half].to_vec();
            self.stats.oracle_calls += 1;
            match oracle.run(&candidate) {
                TrimResult::Interesting => {
                    let removed = current.len() - candidate.len();
                    self.stats.bytes_removed += removed;
                    self.stats.reductions += 1;
                    current = candidate;
                    continue;
                }
                TrimResult::Timeout => {
                    self.stats.timeouts += 1;
                }
                TrimResult::Uninteresting => {}
            }

            // Try keeping the second half.
            let candidate = current[half..].to_vec();
            self.stats.oracle_calls += 1;
            match oracle.run(&candidate) {
                TrimResult::Interesting => {
                    let removed = current.len() - candidate.len();
                    self.stats.bytes_removed += removed;
                    self.stats.reductions += 1;
                    current = candidate;
                    continue;
                }
                TrimResult::Timeout => {
                    self.stats.timeouts += 1;
                }
                TrimResult::Uninteresting => {}
            }

            // Neither half worked — binary chop can't reduce further.
            break;
        }

        Ok(current)
    }

    fn trim_sequential<O: TrimOracle>(
        &mut self,
        input: Vec<u8>,
        block_size: usize,
        oracle: &mut O,
    ) -> Result<Vec<u8>, TrimmerError> {
        if block_size == 0 {
            return Err(TrimmerError::ZeroBlockSize);
        }
        let mut current = input;
        let mut block_sz = self.config.initial_block_size.max(block_size);

        // Progressively halve block size down to `block_size`.
        loop {
            if current.len() <= self.config.min_size {
                break;
            }
            if self.stats.rounds >= self.config.max_rounds {
                return Err(TrimmerError::MaxRoundsExceeded(self.config.max_rounds));
            }

            let mut made_progress = false;
            let mut pos = 0usize;

            while pos + block_sz <= current.len() {
                if self.stats.rounds >= self.config.max_rounds {
                    break;
                }
                // Try removing bytes [pos .. pos+block_sz].
                let candidate: Vec<u8> = current[..pos]
                    .iter()
                    .chain(current[pos + block_sz..].iter())
                    .copied()
                    .collect();

                self.stats.oracle_calls += 1;
                self.stats.rounds += 1;

                match oracle.run(&candidate) {
                    TrimResult::Interesting => {
                        let removed = current.len() - candidate.len();
                        self.stats.bytes_removed += removed;
                        self.stats.reductions += 1;
                        current = candidate;
                        made_progress = true;
                        // Do NOT advance pos — the bytes at pos..pos+block_sz are now
                        // different (shifted), so re-check from same position.
                    }
                    TrimResult::Timeout => {
                        self.stats.timeouts += 1;
                        pos += block_sz;
                    }
                    TrimResult::Uninteresting => {
                        pos += block_sz;
                    }
                }

                if current.len() <= self.config.min_size {
                    break;
                }
            }

            // Halve block size.
            if block_sz <= block_size {
                if !made_progress {
                    break;
                }
                // Restart at the same block size if we made progress.
            } else {
                block_sz /= 2;
                if block_sz < block_size {
                    block_sz = block_size;
                }
            }
        }

        Ok(current)
    }

    /// Return accumulated statistics.
    #[must_use] 
    pub const fn stats(&self) -> &TrimmerStats {
        &self.stats
    }
}

// ---------------------------------------------------------------------------
// ByteFrequencyProfile — statistical profile of byte values in an input
// ---------------------------------------------------------------------------

/// Frequency profile of byte values in an input. Useful for seeding mutations
/// after trimming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteFrequencyProfile {
    pub counts: HashMap<u8, usize>,
    pub total: usize,
    pub entropy_bits: f64,
}

impl ByteFrequencyProfile {
    #[must_use] 
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut counts: HashMap<u8, usize> = HashMap::new();
        for &b in data {
            *counts.entry(b).or_insert(0) += 1;
        }
        let total = data.len();
        let entropy_bits = if total == 0 {
            0.0
        } else {
            -counts
                .values()
                .map(|&c| {
                    let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX))
                        / f64::from(u32::try_from(total).unwrap_or(u32::MAX));
                    p * p.log2()
                })
                .sum::<f64>()
        };
        Self { counts, total, entropy_bits }
    }

    /// Return the most frequent byte value.
    #[must_use] 
    pub fn most_common(&self) -> Option<(u8, usize)> {
        self.counts.iter().max_by_key(|&(_, &c)| c).map(|(&b, &c)| (b, c))
    }

    /// Fraction of distinct byte values used (0.0 – 1.0).
    #[must_use] 
    pub fn diversity(&self) -> f64 {
        f64::from(u32::try_from(self.counts.len()).unwrap_or(u32::MAX)) / 256.0
    }
}

// ---------------------------------------------------------------------------
// Minimal-corpus deduplication helper
// ---------------------------------------------------------------------------

/// Given a set of inputs and their coverage hashes, select the minimal subset
/// that collectively covers all unique hash values.
///
/// Returns the indices of the selected inputs.
///
/// # Panics
/// Panics if `inputs.len() != coverage_hashes.len()`.
#[must_use]
pub fn minimal_covering_set(inputs: &[Vec<u8>], coverage_hashes: &[u32]) -> Vec<usize> {
    assert_eq!(inputs.len(), coverage_hashes.len());

    // Group indices by their coverage hash.
    let mut hash_to_indices: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, &h) in coverage_hashes.iter().enumerate() {
        hash_to_indices.entry(h).or_default().push(i);
    }

    // For each unique hash, pick the smallest input.
    let mut selected: HashMap<u32, usize> = HashMap::new();
    for (&h, indices) in &hash_to_indices {
        let best = indices
            .iter()
            .copied()
            .min_by_key(|&i| inputs[i].len())
            .unwrap();
        selected.insert(h, best);
    }

    let mut result: Vec<usize> = selected.values().copied().collect();
    result.sort_unstable();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle that considers any input "interesting" if it contains the byte 0xAB.
    struct ContainsByte(u8);
    impl TrimOracle for ContainsByte {
        fn run(&mut self, input: &[u8]) -> TrimResult {
            if input.contains(&self.0) {
                TrimResult::Interesting
            } else {
                TrimResult::Uninteresting
            }
        }
    }

    #[test]
    fn test_trim_binary_chop_removes_padding() {
        let mut input = vec![0u8; 512];
        input[256] = 0xAB; // needle near the middle
        let mut oracle = ContainsByte(0xAB);
        let mut trimmer = AflTrimmer::new(TrimmerConfig {
            strategy: TrimStrategy::BinaryChop,
            ..Default::default()
        });
        let result = trimmer.trim(input, &mut oracle).unwrap();
        assert!(result.contains(&0xAB));
        assert!(result.len() < 512);
    }

    #[test]
    fn test_trim_sequential_removes_prefix() {
        let mut input = vec![0u8; 100];
        input[99] = 0xAB; // needle at the end
        let mut oracle = ContainsByte(0xAB);
        let mut trimmer = AflTrimmer::new(TrimmerConfig {
            strategy: TrimStrategy::SequentialBlock { block_size: 1 },
            initial_block_size: 1,
            ..Default::default()
        });
        let result = trimmer.trim(input, &mut oracle).unwrap();
        assert!(result.contains(&0xAB));
        assert!(result.len() <= 10);
    }

    #[test]
    fn test_trim_cascade() {
        let mut input = vec![0xCCu8; 200];
        input[100] = 0xAB;
        let mut oracle = ContainsByte(0xAB);
        let mut trimmer = AflTrimmer::new(TrimmerConfig::default());
        let result = trimmer.trim(input, &mut oracle).unwrap();
        assert!(result.contains(&0xAB));
        assert!(result.len() < 200);
    }

    #[test]
    fn test_empty_input_error() {
        let mut oracle = ContainsByte(0);
        let mut trimmer = AflTrimmer::new(TrimmerConfig::default());
        assert!(matches!(trimmer.trim(vec![], &mut oracle), Err(TrimmerError::EmptyInput)));
    }

    #[test]
    fn test_effectiveness_map_marks_effective() {
        let input = vec![0x00u8, 0xAB, 0x00];
        let mut oracle = ContainsByte(0xAB);
        let map = EffectivenessMap::build(&input, &mut oracle);
        // Only byte at index 1 is effective.
        assert!(!map.effective[0]);
        assert!(map.effective[1]);
        assert!(!map.effective[2]);
        assert_eq!(map.effective_count(), 1);
    }

    #[test]
    fn test_minimal_input_from_effectiveness() {
        let input = vec![0xDE, 0xAD, 0xAB, 0xEF];
        let map = EffectivenessMap {
            effective: vec![false, false, true, false],
            input_len: 4,
            oracle_calls: 4,
        };
        let minimal = map.minimal_input(&input);
        assert_eq!(minimal, vec![0xAB]);
    }

    #[test]
    fn test_byte_frequency_profile() {
        let data = vec![0xAA, 0xAA, 0xBB, 0xCC];
        let profile = ByteFrequencyProfile::from_bytes(&data);
        let (most, count) = profile.most_common().unwrap();
        assert_eq!(most, 0xAA);
        assert_eq!(count, 2);
        assert!(profile.entropy_bits > 0.0);
    }

    #[test]
    fn test_minimal_covering_set() {
        let inputs = vec![
            vec![0u8; 100], // hash A, large
            vec![0u8; 10],  // hash A, small
            vec![1u8; 50],  // hash B
        ];
        let hashes = vec![0xAA, 0xAA, 0xBB];
        let selected = minimal_covering_set(&inputs, &hashes);
        // Should select index 1 (smallest for hash A) and index 2 (hash B).
        assert!(selected.contains(&1));
        assert!(selected.contains(&2));
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_stats_track_reductions() {
        let mut input = vec![0u8; 64];
        input[32] = 0xAB;
        let mut oracle = ContainsByte(0xAB);
        let mut trimmer = AflTrimmer::new(TrimmerConfig {
            strategy: TrimStrategy::BinaryChop,
            ..Default::default()
        });
        trimmer.trim(input, &mut oracle).unwrap();
        assert!(trimmer.stats().reductions > 0);
        assert!(trimmer.stats().bytes_removed > 0);
    }
}
