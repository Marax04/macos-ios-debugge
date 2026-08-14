//! Shannon entropy analysis for memory regions.
//!
//! This module provides:
//! - [`shannon_entropy`] — entropy of a raw byte slice (bits per byte, 0.0–8.0).
//! - [`entropy_blocks`] — compute per-block entropy over all readable regions of
//!   a [`MemoryProvider`].
//! - [`EntropyBlock`] — a `(address, entropy)` pair.
//!
//! # Interpretation
//!
//! | Entropy (bits/byte) | Typical content |
//! |---------------------|-----------------|
//! | 0.0 – 1.0 | All-zero fill, very sparse data |
//! | 1.0 – 4.0 | ASCII text, code |
//! | 4.0 – 6.0 | Binary code with some structure |
//! | 6.0 – 7.5 | Compressed data, crypto keys |
//! | 7.5 – 8.0 | Encrypted / random data |

use crate::memory_provider::MemoryProvider;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// EntropyBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A single block's entropy measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyBlock {
    /// Start address of the block.
    pub address: Address,
    /// Number of bytes in the block.
    pub size: usize,
    /// Shannon entropy of the block (bits per byte, 0.0–8.0).
    pub entropy: f64,
}

impl EntropyBlock {
    /// Classify the block's entropy into a human-readable string.
    #[must_use]
    pub const fn classification(&self) -> &'static str {
        match self.entropy as u32 {
            0 => "zero",
            1..=3 => "low (likely text/code)",
            4..=6 => "medium (binary code)",
            7 => "high (compressed/encrypted)",
            _ => "maximum (random/encrypted)",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// shannon_entropy — core algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Shannon entropy (bits per byte) of `data`.
///
/// The result lies in `[0.0, 8.0]`:
/// - `0.0` means all bytes are identical.
/// - `8.0` means all 256 byte values are equally distributed.
///
/// Returns `0.0` for an empty slice.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count occurrences of each byte value.
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = f64::from(count) / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ─────────────────────────────────────────────────────────────────────────────
// entropy_blocks — per-block entropy over a MemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Compute per-block entropy for all readable regions of `provider`.
///
/// `block_size` must be at least 1.  The last block of a region may be shorter
/// than `block_size` if the region length is not a multiple.
///
/// # Panics
/// Panics if `block_size == 0`.
#[must_use]
pub fn entropy_blocks(provider: &dyn MemoryProvider, block_size: usize) -> Vec<EntropyBlock> {
    assert!(block_size > 0, "block_size must be > 0");

    let mut blocks = Vec::new();

    for region in provider.regions() {
        if !region.perms.is_readable() {
            continue;
        }
        let region_len_u64 = region.range.len();
        if region_len_u64 == 0 {
            continue;
        }
        let region_len = match usize::try_from(region_len_u64) {
            Ok(n) => n,
            Err(_) => continue, // region too large for this platform; skip
        };

        let Ok(region_data) = provider.read(region.range.start, region_len) else {
            continue;
        };

        let mut offset = 0usize;
        while offset < region_data.len() {
            let end = (offset + block_size).min(region_data.len());
            let block_data = &region_data[offset..end];
            let entropy = shannon_entropy(block_data);
            blocks.push(EntropyBlock {
                address: region.range.start + offset as u64,
                size: block_data.len(),
                entropy,
            });
            offset = end;
        }
    }

    blocks
}

// ─────────────────────────────────────────────────────────────────────────────
// high_entropy_spans — find consecutive high-entropy blocks
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous run of blocks all with entropy above `threshold`.
#[derive(Debug, Clone)]
pub struct HighEntropySpan {
    /// Start address of the span.
    pub start: Address,
    /// Exclusive end address of the span.
    pub end: Address,
    /// Mean entropy across the span's blocks.
    pub mean_entropy: f64,
    /// Number of blocks in the span.
    pub block_count: usize,
}

impl HighEntropySpan {
    /// Byte length of the span.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }

    /// Return `true` if the span is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Find contiguous spans of high-entropy blocks (entropy ≥ `threshold`).
#[must_use]
pub fn high_entropy_spans(blocks: &[EntropyBlock], threshold: f64) -> Vec<HighEntropySpan> {
    let mut spans: Vec<HighEntropySpan> = Vec::new();
    let mut in_span = false;
    let mut span_start = Address::new(0);
    let mut span_entropy_sum = 0.0f64;
    let mut span_blocks = 0usize;
    let mut span_end = Address::new(0);

    let flush = |spans: &mut Vec<HighEntropySpan>, start, end, entropy_sum, n_blocks| {
        if n_blocks > 0 {
            spans.push(HighEntropySpan {
                start,
                end,
                mean_entropy: entropy_sum / n_blocks as f64,
                block_count: n_blocks,
            });
        }
    };

    for block in blocks {
        if block.entropy >= threshold {
            if !in_span {
                in_span = true;
                span_start = block.address;
                span_entropy_sum = 0.0;
                span_blocks = 0;
            }
            span_entropy_sum += block.entropy;
            span_blocks += 1;
            span_end = block.address + block.size as u64;
        } else if in_span {
            in_span = false;
            flush(
                &mut spans,
                span_start,
                span_end,
                span_entropy_sum,
                span_blocks,
            );
        }
    }
    if in_span {
        flush(
            &mut spans,
            span_start,
            span_end,
            span_entropy_sum,
            span_blocks,
        );
    }

    spans
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_memory::VirtualMemoryProvider;
    use rustre_core::permissions::Permissions;

    // ── shannon_entropy ───────────────────────────────────────────────────────

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_single_value() {
        let data = vec![0x42u8; 1024];
        assert!((shannon_entropy(&data) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn entropy_two_equal_values() {
        let data: Vec<u8> = (0u8..2).cycle().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "e={e}");
    }

    #[test]
    fn entropy_uniform_all_256() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "e={e}");
    }

    #[test]
    fn entropy_text_lower_than_random() {
        let text: Vec<u8> = b"hello world this is a test ".repeat(100);
        let rand: Vec<u8> = (0u8..=255).cycle().take(text.len()).collect();
        assert!(shannon_entropy(&text) < shannon_entropy(&rand));
    }

    #[test]
    fn entropy_range_0_to_8() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((0.0..=8.0).contains(&e));
    }

    // ── entropy_blocks ────────────────────────────────────────────────────────

    #[test]
    fn entropy_blocks_no_regions() {
        let p = VirtualMemoryProvider::new();
        assert!(entropy_blocks(&p, 256).is_empty());
    }

    #[test]
    fn entropy_blocks_zero_region() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 256],
            Permissions::READ | Permissions::WRITE,
        );
        let blocks = entropy_blocks(&p, 256);
        assert_eq!(blocks.len(), 1);
        assert!((blocks[0].entropy - 0.0).abs() < 1e-10);
        assert_eq!(blocks[0].address, Address::new(0x1000));
    }

    #[test]
    fn entropy_blocks_uniform_region() {
        let data: Vec<u8> = (0u8..=255).collect();
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x2000),
            data,
            Permissions::READ | Permissions::WRITE,
        );
        let blocks = entropy_blocks(&p, 256);
        assert_eq!(blocks.len(), 1);
        assert!((blocks[0].entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn entropy_blocks_multiple_blocks() {
        let data: Vec<u8> = vec![0u8; 512]; // two 256-byte blocks
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            data,
            Permissions::READ | Permissions::WRITE,
        );
        let blocks = entropy_blocks(&p, 256);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].address, Address::new(0x1000));
        assert_eq!(blocks[1].address, Address::new(0x1100));
    }

    #[test]
    fn entropy_blocks_partial_last_block() {
        let data = vec![0u8; 300];
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            data,
            Permissions::READ | Permissions::WRITE,
        );
        let blocks = entropy_blocks(&p, 256);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].size, 256);
        assert_eq!(blocks[1].size, 44);
    }

    #[test]
    fn entropy_blocks_skips_non_readable() {
        let mut p = VirtualMemoryProvider::new();
        // No READ permission → should be skipped.
        p.map(Address::new(0x1000), vec![0u8; 256], Permissions::WRITE);
        let blocks = entropy_blocks(&p, 256);
        assert!(blocks.is_empty());
    }

    // ── high_entropy_spans ────────────────────────────────────────────────────

    #[test]
    fn high_entropy_spans_empty() {
        let spans = high_entropy_spans(&[], 7.0);
        assert!(spans.is_empty());
    }

    #[test]
    fn high_entropy_spans_all_low() {
        let blocks: Vec<EntropyBlock> = (0..10)
            .map(|i| EntropyBlock {
                address: Address::new(i * 256),
                size: 256,
                entropy: 1.0,
            })
            .collect();
        let spans = high_entropy_spans(&blocks, 7.0);
        assert!(spans.is_empty());
    }

    #[test]
    fn high_entropy_spans_all_high() {
        let blocks: Vec<EntropyBlock> = (0..5)
            .map(|i| EntropyBlock {
                address: Address::new(i * 256),
                size: 256,
                entropy: 7.5,
            })
            .collect();
        let spans = high_entropy_spans(&blocks, 7.0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].block_count, 5);
        assert_eq!(spans[0].len(), 5 * 256);
    }

    #[test]
    fn high_entropy_spans_mixed() {
        let entropies = [1.0, 7.5, 7.9, 1.0, 7.2, 7.8, 1.0];
        let blocks: Vec<EntropyBlock> = entropies
            .iter()
            .enumerate()
            .map(|(i, &e)| EntropyBlock {
                address: Address::new(i as u64 * 256),
                size: 256,
                entropy: e,
            })
            .collect();
        let spans = high_entropy_spans(&blocks, 7.0);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].block_count, 2); // indices 1,2
        assert_eq!(spans[1].block_count, 2); // indices 4,5
    }

    #[test]
    fn entropy_block_classification() {
        let low = EntropyBlock {
            address: Address::new(0),
            size: 256,
            entropy: 2.5,
        };
        let high = EntropyBlock {
            address: Address::new(0),
            size: 256,
            entropy: 7.8,
        };
        assert!(low.classification().contains("low"));
        assert!(high.classification().contains("high") || high.classification().contains("max"));
    }
}
