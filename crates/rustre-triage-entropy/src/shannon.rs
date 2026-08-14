//! Shannon entropy analysis primitives.
//!
//! Re-exports and extends [`crate::shannon_entropy`] with block-level,
//! section-level, and sliding-window analysis.

use serde::{Deserialize, Serialize};
use crate::casts;

// ─────────────────────────────────────────────────────────────────────────────
// byte_entropy (alias for lib-level shannon_entropy)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Shannon entropy of `data` in bits per byte (0.0 – 8.0).
///
/// Identical to [`crate::shannon_entropy`] — re-exported here for convenience
/// when working with this module directly.
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    crate::shannon_entropy(data)
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockClass
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a block based on its entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockClass {
    /// Mostly-zero or constant data (entropy < 1.0).
    Zeroed,
    /// Typical plaintext / code (entropy 1.0 – 5.5).
    Normal,
    /// Compressed, encrypted, or random data (entropy > 5.5 – 7.0).
    HighEntropy,
    /// Very likely packed, encrypted, or random data (entropy > 7.0).
    Packed,
}

impl BlockClass {
    /// Classify based on a raw entropy value.
    #[must_use]
    pub fn from_entropy(h: f64) -> Self {
        if h < 1.0 {
            Self::Zeroed
        } else if h <= 5.5 {
            Self::Normal
        } else if h <= 7.0 {
            Self::HighEntropy
        } else {
            Self::Packed
        }
    }
}

impl std::fmt::Display for BlockClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zeroed => write!(f, "Zeroed"),
            Self::Normal => write!(f, "Normal"),
            Self::HighEntropy => write!(f, "HighEntropy"),
            Self::Packed => write!(f, "Packed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockEntropy
// ─────────────────────────────────────────────────────────────────────────────

/// Entropy measurement for a single fixed-size block within a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntropy {
    /// Byte offset of the block start.
    pub offset: usize,
    /// Number of bytes in this block.
    pub size: usize,
    /// Shannon entropy of this block.
    pub entropy: f64,
    /// Block classification.
    pub class: BlockClass,
}

impl BlockEntropy {
    /// Compute a [`BlockEntropy`] for `data` at `offset`.
    #[must_use]
    pub fn new(data: &[u8], offset: usize) -> Self {
        let entropy = byte_entropy(data);
        Self {
            offset,
            size: data.len(),
            entropy,
            class: BlockClass::from_entropy(entropy),
        }
    }

    /// Returns `true` if this block is likely packed.
    #[must_use]
    pub fn is_packed(&self) -> bool {
        self.entropy > 7.0
    }

    /// Returns `true` if this block is high-entropy.
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 5.5
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Complete entropy analysis result from a block-level scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    /// Overall Shannon entropy of the entire input.
    pub overall_entropy: f64,
    /// Block-level entropy measurements.
    pub blocks: Vec<BlockEntropy>,
    /// Ratio of packed-class blocks to total blocks.
    pub packed_ratio: f64,
    /// Ratio of high-entropy-or-above blocks to total blocks.
    pub high_entropy_ratio: f64,
    /// Maximum single-block entropy.
    pub max_block_entropy: f64,
    /// Minimum single-block entropy.
    pub min_block_entropy: f64,
    /// Mean block entropy.
    pub mean_block_entropy: f64,
}

impl EntropyAnalysis {
    /// `true` if the overall file is likely packed (> 7.0 overall or > 50 % of
    /// blocks classified as [`BlockClass::Packed`]).
    #[must_use]
    pub fn is_packed(&self) -> bool {
        self.overall_entropy > 7.0 || self.packed_ratio > 0.5
    }

    /// All blocks classified as [`BlockClass::Packed`].
    #[must_use]
    pub fn packed_blocks(&self) -> Vec<&BlockEntropy> {
        self.blocks
            .iter()
            .filter(|b| b.class == BlockClass::Packed)
            .collect()
    }

    /// All blocks classified as [`BlockClass::HighEntropy`] or above.
    #[must_use]
    pub fn anomalous_blocks(&self) -> Vec<&BlockEntropy> {
        self.blocks.iter().filter(|b| b.entropy > 5.5).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// entropy_per_block
// ─────────────────────────────────────────────────────────────────────────────

/// Split `data` into non-overlapping blocks of `block_size` bytes and compute
/// the Shannon entropy of each block.
///
/// The last block may be smaller than `block_size`.
///
/// # Panics
/// Does not panic; if `block_size` is 0, returns an empty `Vec`.
#[must_use]
pub fn entropy_per_block(data: &[u8], block_size: usize) -> EntropyAnalysis {
    if data.is_empty() || block_size == 0 {
        return EntropyAnalysis {
            overall_entropy: 0.0,
            blocks: Vec::new(),
            packed_ratio: 0.0,
            high_entropy_ratio: 0.0,
            max_block_entropy: 0.0,
            min_block_entropy: 0.0,
            mean_block_entropy: 0.0,
        };
    }

    let overall_entropy = byte_entropy(data);
    let blocks: Vec<BlockEntropy> = data
        .chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| BlockEntropy::new(chunk, i * block_size))
        .collect();

    compute_analysis(overall_entropy, blocks)
}

// ─────────────────────────────────────────────────────────────────────────────
// entropy_per_section
// ─────────────────────────────────────────────────────────────────────────────

/// Compute entropy for a set of named byte-range sections within `data`.
///
/// Each section is `(offset, size)`. Out-of-range sections are clamped.
/// Returns an [`EntropyAnalysis`] where each block corresponds to one section.
#[must_use]
pub fn entropy_per_section(data: &[u8], sections: &[(usize, usize)]) -> EntropyAnalysis {
    if data.is_empty() {
        return EntropyAnalysis {
            overall_entropy: 0.0,
            blocks: Vec::new(),
            packed_ratio: 0.0,
            high_entropy_ratio: 0.0,
            max_block_entropy: 0.0,
            min_block_entropy: 0.0,
            mean_block_entropy: 0.0,
        };
    }

    let overall_entropy = byte_entropy(data);
    let blocks: Vec<BlockEntropy> = sections
        .iter()
        .map(|&(off, size)| {
            let end = (off + size).min(data.len());
            let slice = if off < data.len() {
                &data[off..end]
            } else {
                &[]
            };
            BlockEntropy::new(slice, off)
        })
        .collect();

    compute_analysis(overall_entropy, blocks)
}

// ─────────────────────────────────────────────────────────────────────────────
// sliding_window_entropy
// ─────────────────────────────────────────────────────────────────────────────

/// Compute entropy over a sliding window of `window_size` bytes, stepping by
/// `step` bytes.
///
/// Returns a `Vec<(offset, entropy)>` pair for each window position.
///
/// # Notes
/// For large files this can be expensive — prefer [`entropy_per_block`] for
/// coarse analysis.
///
/// # Panics
/// Does not panic; returns empty if `window_size` is 0 or `step` is 0.
#[must_use]
pub fn sliding_window_entropy(data: &[u8], window_size: usize, step: usize) -> Vec<(usize, f64)> {
    if data.len() < window_size || window_size == 0 || step == 0 {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut offset = 0;
    while offset + window_size <= data.len() {
        let window = &data[offset..offset + window_size];
        results.push((offset, byte_entropy(window)));
        offset += step;
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn compute_analysis(overall_entropy: f64, blocks: Vec<BlockEntropy>) -> EntropyAnalysis {
    if blocks.is_empty() {
        return EntropyAnalysis {
            overall_entropy,
            blocks,
            packed_ratio: 0.0,
            high_entropy_ratio: 0.0,
            max_block_entropy: 0.0,
            min_block_entropy: 0.0,
            mean_block_entropy: 0.0,
        };
    }

    let n = casts::usize_to_f64(blocks.len());
    let packed_count = blocks
        .iter()
        .filter(|b| b.class == BlockClass::Packed)
        .count();
    let high_count = blocks.iter().filter(|b| b.entropy > 5.5).count();
    let max_e = blocks
        .iter()
        .map(|b| b.entropy)
        .fold(f64::NEG_INFINITY, f64::max);
    let min_e = blocks
        .iter()
        .map(|b| b.entropy)
        .fold(f64::INFINITY, f64::min);
    let sum_e: f64 = blocks.iter().map(|b| b.entropy).sum();

    EntropyAnalysis {
        overall_entropy,
        packed_ratio: casts::usize_to_f64(packed_count) / n,
        high_entropy_ratio: casts::usize_to_f64(high_count) / n,
        max_block_entropy: max_e,
        min_block_entropy: min_e,
        mean_block_entropy: sum_e / n,
        blocks,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── byte_entropy ──────────────────────────────────────────────────────

    #[test]
    fn test_byte_entropy_empty() {
        assert!((byte_entropy(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_byte_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = byte_entropy(&data);
        assert!((h - 8.0).abs() < 1e-9);
    }

    #[test]
    fn test_byte_entropy_constant() {
        assert!((byte_entropy(&[0x41u8; 100]) - (0.0)).abs() < f64::EPSILON);
    }

    // ── BlockClass ────────────────────────────────────────────────────────

    #[test]
    fn test_block_class_from_entropy() {
        assert_eq!(BlockClass::from_entropy(0.0), BlockClass::Zeroed);
        assert_eq!(BlockClass::from_entropy(3.0), BlockClass::Normal);
        assert_eq!(BlockClass::from_entropy(6.0), BlockClass::HighEntropy);
        assert_eq!(BlockClass::from_entropy(7.5), BlockClass::Packed);
    }

    #[test]
    fn test_block_class_boundary_5_5() {
        assert_eq!(BlockClass::from_entropy(5.5), BlockClass::Normal);
        assert_eq!(BlockClass::from_entropy(5.51), BlockClass::HighEntropy);
    }

    #[test]
    fn test_block_class_display() {
        assert_eq!(BlockClass::Zeroed.to_string(), "Zeroed");
        assert_eq!(BlockClass::Packed.to_string(), "Packed");
    }

    // ── BlockEntropy ──────────────────────────────────────────────────────

    #[test]
    fn test_block_entropy_new_zeros() {
        let be = BlockEntropy::new(&[0u8; 256], 0x1000);
        assert!((be.entropy - (0.0)).abs() < f64::EPSILON);
        assert_eq!(be.class, BlockClass::Zeroed);
        assert_eq!(be.offset, 0x1000);
        assert_eq!(be.size, 256);
        assert!(!be.is_packed());
        assert!(!be.is_high_entropy());
    }

    #[test]
    fn test_block_entropy_new_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let be = BlockEntropy::new(&data, 0);
        assert!((be.entropy - 8.0).abs() < 1e-9);
        assert_eq!(be.class, BlockClass::Packed);
        assert!(be.is_packed());
        assert!(be.is_high_entropy());
    }

    // ── entropy_per_block ─────────────────────────────────────────────────

    #[test]
    fn test_entropy_per_block_empty() {
        let a = entropy_per_block(&[], 256);
        assert!(a.blocks.is_empty());
        assert!((a.overall_entropy - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_per_block_zero_block_size() {
        let a = entropy_per_block(&[1, 2, 3], 0);
        assert!(a.blocks.is_empty());
    }

    #[test]
    fn test_entropy_per_block_two_blocks() {
        let mut data = vec![0u8; 256];
        data.extend(0u8..=255u8);
        let a = entropy_per_block(&data, 256);
        assert_eq!(a.blocks.len(), 2);
        assert!((a.blocks[0].entropy - (0.0)).abs() < f64::EPSILON);
        assert!((a.blocks[1].entropy - 8.0).abs() < 1e-9);
    }

    #[test]
    fn test_entropy_per_block_stats() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let a = entropy_per_block(&data, 256);
        assert!((a.max_block_entropy - 8.0).abs() < 1e-9);
        assert!((a.min_block_entropy - 8.0).abs() < 1e-9);
        assert!((a.mean_block_entropy - 8.0).abs() < 1e-9);
        assert!((a.packed_ratio - (1.0)).abs() < f64::EPSILON);
        assert!(a.is_packed());
    }

    #[test]
    fn test_packed_blocks() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let a = entropy_per_block(&data, 256);
        assert_eq!(a.packed_blocks().len(), 2);
    }

    // ── entropy_per_section ───────────────────────────────────────────────

    #[test]
    fn test_entropy_per_section_empty_data() {
        let a = entropy_per_section(&[], &[(0, 100)]);
        assert!(a.blocks.is_empty());
    }

    #[test]
    fn test_entropy_per_section_two_sections() {
        let mut data = vec![0u8; 256];
        data.extend(0u8..=255u8);
        let a = entropy_per_section(&data, &[(0, 256), (256, 256)]);
        assert_eq!(a.blocks.len(), 2);
        assert!((a.blocks[0].entropy - (0.0)).abs() < f64::EPSILON);
        assert!((a.blocks[1].entropy - 8.0).abs() < 1e-9);
    }

    #[test]
    fn test_entropy_per_section_clamp() {
        let data = vec![0u8; 10];
        // Section goes beyond data length
        let a = entropy_per_section(&data, &[(5, 100)]);
        assert_eq!(a.blocks[0].size, 5); // clamped
    }

    // ── sliding_window_entropy ────────────────────────────────────────────

    #[test]
    fn test_sliding_window_empty() {
        let r = sliding_window_entropy(&[], 256, 128);
        assert!(r.is_empty());
    }

    #[test]
    fn test_sliding_window_too_small() {
        let r = sliding_window_entropy(&[0u8; 10], 256, 128);
        assert!(r.is_empty());
    }

    #[test]
    fn test_sliding_window_zero_step() {
        let r = sliding_window_entropy(&[0u8; 1024], 256, 0);
        assert!(r.is_empty());
    }

    #[test]
    fn test_sliding_window_positions() {
        let data = vec![0u8; 1024];
        let r = sliding_window_entropy(&data, 256, 256);
        // positions: 0, 256, 512, 768
        assert_eq!(r.len(), 4);
        assert!(r.iter().all(|(_, h)| *h == 0.0));
    }

    #[test]
    fn test_sliding_window_overlapping() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let r = sliding_window_entropy(&data, 256, 64);
        // Each window is 256 bytes of uniform data → all entropy ~= 8.0
        assert!(!r.is_empty());
        for (_, h) in &r {
            assert!((h - 8.0).abs() < 1e-9, "h={h}");
        }
    }

    // ── EntropyAnalysis helpers ───────────────────────────────────────────

    #[test]
    fn test_anomalous_blocks() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let a = entropy_per_block(&data, 256);
        assert_eq!(a.anomalous_blocks().len(), 2);
    }

    #[test]
    fn test_is_packed_low_entropy() {
        let a = entropy_per_block(&[0u8; 1024], 256);
        assert!(!a.is_packed());
    }
}
