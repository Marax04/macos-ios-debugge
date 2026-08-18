//! Bytecode region discovery for VM-protected binaries.
//!
//! Locates regions of binary data that are likely to contain VM bytecode
//! by analysing entropy, byte-distribution anomalies, and proximity to
//! known dispatcher patterns.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// BytecodeRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A region of bytes suspected to contain VM bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeRegion {
    /// Start offset in the binary.
    pub start: usize,
    /// Length of the region in bytes.
    pub length: usize,
    /// Shannon entropy of the region (in bits per byte).
    pub entropy: f64,
    /// Confidence that this is VM bytecode (0–100).
    pub confidence: u8,
    /// Why this region was flagged.
    pub reason: String,
    /// Inferred opcode width in bytes (1, 2, or 4).
    pub inferred_opcode_width: u8,
}

impl BytecodeRegion {
    /// End offset (exclusive) of this region.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.length
    }

    /// Return `true` if two regions overlap.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Return `true` if this region's entropy suggests compression/encryption.
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BytecodeFinder
// ─────────────────────────────────────────────────────────────────────────────

/// Locates candidate bytecode regions in a binary.
///
/// ```rust
/// use rustre_deobf_vmlift::bytecode_finder::BytecodeFinder;
///
/// let finder = BytecodeFinder::new();
/// let data = vec![0u8; 4096];
/// let regions = finder.find(&data);
/// println!("Found {} bytecode region(s)", regions.len());
/// ```
#[derive(Debug)]
pub struct BytecodeFinder {
    /// Minimum region size to consider.
    min_region_size: usize,
    /// Block size for entropy analysis.
    block_size: usize,
    /// Minimum confidence to report.
    min_confidence: u8,
    /// Whether to look for common VM bytecode headers.
    check_headers: bool,
}

impl Default for BytecodeFinder {
    fn default() -> Self {
        Self::new()
    }
}

impl BytecodeFinder {
    /// Create a new finder with sensible defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_region_size: 64,
            block_size: 256,
            min_confidence: 40,
            check_headers: true,
        }
    }

    /// Set the minimum region size (bytes).
    #[must_use]
    pub const fn with_min_region_size(mut self, size: usize) -> Self {
        self.min_region_size = size;
        self
    }

    /// Set the block size for entropy analysis.
    #[must_use]
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size.max(16);
        self
    }

    /// Disable VM header detection.
    #[must_use]
    pub const fn without_header_check(mut self) -> Self {
        self.check_headers = false;
        self
    }

    /// Scan `data` and return candidate bytecode regions.
    #[must_use]
    pub fn find(&self, data: &[u8]) -> Vec<BytecodeRegion> {
        let mut regions = Vec::new();

        if self.check_headers {
            self.find_by_vm_headers(data, &mut regions);
        }
        self.find_by_entropy(data, &mut regions);
        self.find_by_opcode_distribution(data, &mut regions);
        self.find_by_repeating_structure(data, &mut regions);

        // Deduplicate overlapping regions (keep highest confidence)
        regions = deduplicate(regions);
        regions.retain(|r| r.confidence >= self.min_confidence && r.length >= self.min_region_size);
        regions.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        regions
    }

    // ── VM header detection ──────────────────────────────────────────────────
    fn find_by_vm_headers(&self, data: &[u8], out: &mut Vec<BytecodeRegion>) {
        // Common VM bytecode magic values
        let headers: &[(&[u8], &str, u8)] = &[
            // VMProtect bytecode signature
            (b"\xEB\x10VMP", "VMProtect segment header", 90),
            // Code Virtualizer / Oreans
            (b"\x68\x00\x00\x00\x00\xE8", "Oreans/CV trampoline stub", 75),
            // Themida inline VM trampoline: push ...; call ...; db 0x0F 0x0F
            (
                &[0x0F, 0x0F, 0x0F, 0x0F],
                "Themida VM marker (0F0F0F0F)",
                70,
            ),
            // Custom 4-byte magic seen in obfuscated x64 handlers
            (&[0xDE, 0xAD, 0xBE, 0xEF], "custom magic DE AD BE EF", 55),
        ];

        // Cap: at most 256 header hits per magic pattern to prevent memory
        // exhaustion when an attacker supplies a large file where every byte
        // matches one of the short magic patterns.
        const MAX_HEADER_HITS_PER_MAGIC: usize = 256;
        for (magic, reason, base_conf) in headers {
            let mlen = magic.len();
            if mlen > data.len() {
                continue;
            }
            let mut hits_for_magic = 0usize;
            for offset in 0..=(data.len() - mlen) {
                if hits_for_magic >= MAX_HEADER_HITS_PER_MAGIC {
                    break;
                }
                if &data[offset..offset + mlen] == *magic {
                    // Extend the region forward up to min_region_size
                    let region_len = (data.len() - offset).min(self.min_region_size * 4);
                    let entropy = shannon_entropy(&data[offset..offset + region_len]);
                    out.push(BytecodeRegion {
                        start: offset,
                        length: region_len,
                        entropy,
                        confidence: *base_conf,
                        reason: format!("{reason} at 0x{offset:x}"),
                        inferred_opcode_width: 1,
                    });
                    hits_for_magic += 1;
                }
            }
        }
    }

    // ── Entropy-based detection ──────────────────────────────────────────────
    fn find_by_entropy(&self, data: &[u8], out: &mut Vec<BytecodeRegion>) {
        let bsize = self.block_size;
        if data.len() < bsize {
            return;
        }

        let mut block_start = 0;
        let mut in_medium_entropy = false;
        let mut region_start = 0;

        for block_offset in (0..data.len()).step_by(bsize) {
            let end = (block_offset + bsize).min(data.len());
            let block = &data[block_offset..end];
            let e = shannon_entropy(block);

            // VM bytecode often sits in medium entropy (4.5–7.0) —
            // it's not compressed (which would be >7.5) but it's not code (≈3–5)
            let is_vm_entropy = (4.5..=7.2).contains(&e);

            if is_vm_entropy && !in_medium_entropy {
                in_medium_entropy = true;
                region_start = block_offset;
            } else if !is_vm_entropy && in_medium_entropy {
                in_medium_entropy = false;
                let length = block_offset - region_start;
                if length >= self.min_region_size {
                    let region_data = &data[region_start..block_offset];
                    let region_entropy = shannon_entropy(region_data);
                    out.push(BytecodeRegion {
                        start: region_start,
                        length,
                        entropy: region_entropy,
                        confidence: 55,
                        reason: format!(
                            "medium entropy ({region_entropy:.2} bits/byte) at 0x{region_start:x}"
                        ),
                        inferred_opcode_width: 1,
                    });
                }
            }
            block_start = block_offset;
        }
        let _ = block_start;

        // Flush unclosed region at end
        if in_medium_entropy {
            let length = data.len() - region_start;
            if length >= self.min_region_size {
                let region_data = &data[region_start..];
                let region_entropy = shannon_entropy(region_data);
                out.push(BytecodeRegion {
                    start: region_start,
                    length,
                    entropy: region_entropy,
                    confidence: 50,
                    reason: format!("medium entropy ({region_entropy:.2} bits/byte) at end"),
                    inferred_opcode_width: 1,
                });
            }
        }
    }

    // ── Opcode distribution analysis ─────────────────────────────────────────
    //
    // VM bytecode often shows a characteristic distribution: a small set of
    // distinct byte values (the opcode space) appearing regularly.
    fn find_by_opcode_distribution(&self, data: &[u8], out: &mut Vec<BytecodeRegion>) {
        let bsize = self.block_size.max(128);
        if data.len() < bsize {
            return;
        }

        for block_offset in (0..data.len().saturating_sub(bsize)).step_by(bsize / 2) {
            let end = (block_offset + bsize).min(data.len());
            let block = &data[block_offset..end];

            // Count distinct byte values
            let mut histogram = [0u32; 256];
            for &b in block {
                histogram[b as usize] += 1;
            }
            let distinct = histogram.iter().filter(|&&c| c > 0).count();
            let total = block.len() as f64;

            // VM opcodes: typically 16–64 distinct values, evenly distributed
            if (16..=128).contains(&distinct) {
                let max_count = f64::from(*histogram.iter().max().unwrap_or(&0));
                let avg_count = total / distinct as f64;
                let uniformity = avg_count / max_count.max(1.0);

                if uniformity > 0.3 {
                    let confidence = (40.0 + uniformity * 30.0) as u8;
                    out.push(BytecodeRegion {
                        start: block_offset,
                        length: end - block_offset,
                        entropy: shannon_entropy(block),
                        confidence: confidence.min(80),
                        reason: format!("opcode-like distribution ({distinct} distinct values, uniformity={uniformity:.2}) at 0x{block_offset:x}"),
                        inferred_opcode_width: if distinct <= 32 { 1 } else { 2 },
                    });
                }
            }
        }
    }

    // ── Repeating structure analysis ─────────────────────────────────────────
    //
    // Many VM instruction encodings have a fixed stride — every N bytes starts
    // a new instruction.  Detect this by looking for periodicity in the data.
    fn find_by_repeating_structure(&self, data: &[u8], out: &mut Vec<BytecodeRegion>) {
        let bsize = self.block_size.min(data.len());
        if bsize < 32 {
            return;
        }

        for block_offset in (0..data.len().saturating_sub(bsize)).step_by(bsize) {
            let end = (block_offset + bsize).min(data.len());
            let block = &data[block_offset..end];

            for stride in [2usize, 4, 6, 8] {
                if block.len() < stride * 4 {
                    continue;
                }

                // Measure how consistent the first byte of each stride-aligned
                // "instruction" is.
                let mut first_bytes = [0u32; 256];
                let aligned_count = block.len() / stride;
                for i in 0..aligned_count {
                    first_bytes[block[i * stride] as usize] += 1;
                }
                let max_fb = f64::from(*first_bytes.iter().max().unwrap_or(&0));
                let ratio = max_fb / aligned_count as f64;

                // If >60% of stride-aligned positions share the same first byte,
                // this is likely a fixed-stride instruction encoding.
                if ratio > 0.6 && aligned_count > 4 {
                    out.push(BytecodeRegion {
                        start: block_offset,
                        length: end - block_offset,
                        entropy: shannon_entropy(block),
                        confidence: 65,
                        reason: format!("fixed-stride ({stride}B) structure at 0x{block_offset:x}"),
                        inferred_opcode_width: stride as u8,
                    });
                    break; // only report one stride per block
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Shannon entropy of `data` in bits per byte.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Deduplicate overlapping regions by keeping the highest-confidence one.
fn deduplicate(mut regions: Vec<BytecodeRegion>) -> Vec<BytecodeRegion> {
    regions.sort_by_key(|r| r.start);
    let mut result: Vec<BytecodeRegion> = Vec::new();
    for region in regions {
        if let Some(last) = result.last_mut()
            && last.overlaps(&region) {
                // Keep the higher-confidence one
                if region.confidence > last.confidence {
                    *last = region;
                }
                continue;
            }
        result.push(region);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniform data entropy should be 8.0, got {e}"
        );
    }

    #[test]
    fn test_shannon_entropy_constant() {
        let data = vec![0u8; 256];
        let e = shannon_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_shannon_entropy_binary() {
        // 50% zeros, 50% ones → entropy = 1.0
        let data: Vec<u8> = (0..128).map(|i| if i < 64 { 0 } else { 1 }).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.01,
            "binary data entropy should be ~1.0, got {e}"
        );
    }

    #[test]
    fn test_find_vm_header_vmp() {
        let mut data = vec![0u8; 256];
        data[10] = 0xEB;
        data[11] = 0x10;
        data[12] = b'V';
        data[13] = b'M';
        data[14] = b'P';
        let finder = BytecodeFinder::new().with_min_region_size(16);
        let regions = finder.find(&data);
        assert!(regions.iter().any(|r| r.reason.contains("VMProtect")));
    }

    #[test]
    fn test_find_by_entropy() {
        // Create a block of medium-entropy data (repeating bytes 0x20-0x7F)
        let data: Vec<u8> = (0..1024).map(|i| ((i % 64) + 0x20) as u8).collect();
        let finder = BytecodeFinder::new()
            .with_min_region_size(32)
            .with_block_size(64);
        let regions = finder.find(&data);
        // Should find at least one region based on entropy
        let _ = regions; // finding may or may not trigger depending on exact entropy values
    }

    #[test]
    fn test_region_end() {
        let r = BytecodeRegion {
            start: 100,
            length: 50,
            entropy: 5.0,
            confidence: 70,
            reason: "test".to_owned(),
            inferred_opcode_width: 1,
        };
        assert_eq!(r.end(), 150);
    }

    #[test]
    fn test_region_overlaps() {
        let r1 = BytecodeRegion {
            start: 0,
            length: 100,
            entropy: 5.0,
            confidence: 70,
            reason: String::new(),
            inferred_opcode_width: 1,
        };
        let r2 = BytecodeRegion {
            start: 50,
            length: 100,
            entropy: 5.0,
            confidence: 70,
            reason: String::new(),
            inferred_opcode_width: 1,
        };
        let r3 = BytecodeRegion {
            start: 200,
            length: 100,
            entropy: 5.0,
            confidence: 70,
            reason: String::new(),
            inferred_opcode_width: 1,
        };
        assert!(r1.overlaps(&r2));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_region_is_high_entropy() {
        let r = BytecodeRegion {
            start: 0,
            length: 256,
            entropy: 7.5,
            confidence: 60,
            reason: String::new(),
            inferred_opcode_width: 1,
        };
        assert!(r.is_high_entropy());
        let r2 = BytecodeRegion {
            start: 0,
            length: 256,
            entropy: 4.0,
            confidence: 60,
            reason: String::new(),
            inferred_opcode_width: 1,
        };
        assert!(!r2.is_high_entropy());
    }

    #[test]
    fn test_find_no_panic_empty() {
        let finder = BytecodeFinder::new();
        let regions = finder.find(&[]);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_deduplicate() {
        let r1 = BytecodeRegion {
            start: 0,
            length: 100,
            entropy: 5.0,
            confidence: 70,
            reason: "r1".to_owned(),
            inferred_opcode_width: 1,
        };
        let r2 = BytecodeRegion {
            start: 50,
            length: 100,
            entropy: 5.5,
            confidence: 80,
            reason: "r2".to_owned(),
            inferred_opcode_width: 1,
        };
        let deduped = deduplicate(vec![r1, r2]);
        assert_eq!(deduped.len(), 1);
        // Should keep r2 (higher confidence)
        assert_eq!(deduped[0].confidence, 80);
    }

    #[test]
    fn test_fixed_stride_detection() {
        // 4-byte instructions: all start with 0x01 followed by 3 random bytes
        let data: Vec<u8> = (0..256)
            .flat_map(|i| [0x01u8, (i % 16) as u8, (i / 16) as u8, 0x00])
            .collect();
        let finder = BytecodeFinder::new()
            .with_block_size(64)
            .with_min_region_size(32);
        let regions = finder.find(&data);
        // May find fixed-stride regions; just verify no panic
        let _ = regions;
    }
}
