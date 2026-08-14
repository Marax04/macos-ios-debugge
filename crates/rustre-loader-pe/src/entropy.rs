//! Section entropy analysis for PE files.
//!
//! High entropy (>7.2 bits/byte) is a strong indicator of packed or encrypted
//! sections. Shannon entropy is computed per section and for the whole file.

use crate::casts::usize_to_f64;
use crate::imports::RvaSection;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Entropy threshold above which a section is considered packed/encrypted.
pub const PACKED_ENTROPY_THRESHOLD: f64 = 7.2;

/// Entropy threshold above which a section is almost certainly compressed or
/// encrypted (not just high-entropy data like compiled resources).
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.8;

/// Below this entropy, a section is likely all-zero or repetitive fill.
pub const LOW_ENTROPY_THRESHOLD: f64 = 1.0;

// ---------------------------------------------------------------------------
// Entropy computation
// ---------------------------------------------------------------------------

/// Calculate Shannon entropy of a byte slice.
///
/// Returns a value in [0.0, 8.0] where 8.0 is maximum entropy.
/// Returns 0.0 for empty slices.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = usize_to_f64(data.len());
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

/// Compute the byte frequency histogram of `data`.
#[must_use]
pub fn byte_histogram(data: &[u8]) -> [u32; 256] {
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
}

/// Return the most common byte value in `data` and its count.
/// Returns `(0, 0)` for empty slices.
#[must_use]
pub fn most_common_byte(data: &[u8]) -> (u8, u32) {
    if data.is_empty() {
        return (0, 0);
    }
    let hist = byte_histogram(data);
    hist.iter()
        .enumerate()
        .max_by_key(|&(_, &c)| c)
        .map_or((0, 0), |(b, &c)| (u8::try_from(b).unwrap_or(u8::MAX), c))
}

// ---------------------------------------------------------------------------
// Packing heuristics
// ---------------------------------------------------------------------------

/// Chi-squared statistic for uniform distribution test.
///
/// Low chi-squared = close to uniform = high entropy / encrypted.
/// High chi-squared = far from uniform = natural byte distribution.
#[must_use]
pub fn chi_squared(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let hist = byte_histogram(data);
    let expected = usize_to_f64(data.len()) / 256.0;
    hist.iter()
        .map(|&c| {
            let diff = f64::from(c) - expected;
            diff * diff / expected
        })
        .sum()
}

/// Returns `true` if `data` looks like packed / encrypted content.
///
/// Uses a combination of entropy and chi-squared tests.
#[must_use]
pub fn looks_packed(data: &[u8]) -> bool {
    if data.len() < 256 {
        return false; // too small to be meaningful
    }
    let e = shannon_entropy(data);
    if e >= PACKED_ENTROPY_THRESHOLD {
        return true;
    }
    // Low chi-squared (< 250) also suggests uniformity / encryption
    if e >= 6.5 && chi_squared(data) < 250.0 {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Per-section entropy analysis
// ---------------------------------------------------------------------------

/// Entropy analysis result for a single PE section.
#[derive(Debug, Clone)]
pub struct SectionEntropy {
    /// Section name (up to 8 chars).
    pub name: String,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw size in file.
    pub raw_size: u32,
    /// Shannon entropy in [0.0, 8.0].
    pub entropy: f64,
    /// Most common byte value and its count.
    pub most_common_byte: u8,
    /// Count of the most common byte.
    pub most_common_byte_count: u32,
    /// `true` if entropy exceeds the packing threshold.
    pub is_packed: bool,
    /// Chi-squared statistic.
    pub chi_squared: f64,
}

impl SectionEntropy {
    /// Return `true` if the section has suspiciously high entropy.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.entropy >= HIGH_ENTROPY_THRESHOLD
    }

    /// Return `true` if this looks like a zero-fill / BSS section.
    #[must_use]
    pub fn is_likely_bss(&self) -> bool {
        self.entropy <= LOW_ENTROPY_THRESHOLD && self.most_common_byte == 0
    }
}

/// Extended section record with a name field, used by `analyze_sections`.
#[derive(Debug, Clone)]
pub struct SectionWithName {
    pub section: RvaSection,
    pub name: String,
}

/// Compute entropy for each PE section from raw file bytes.
#[must_use]
pub fn analyze_sections(data: &[u8], sections: &[SectionWithName]) -> Vec<SectionEntropy> {
    sections
        .iter()
        .map(|sw| {
            let s = &sw.section;
            let start = s.raw_offset as usize;
            let end = (start + s.raw_size as usize).min(data.len());
            let slice = if start < end { &data[start..end] } else { &[] };

            let entropy = shannon_entropy(slice);
            let (mcb, mcbc) = most_common_byte(slice);
            let cs = chi_squared(slice);
            let is_packed = looks_packed(slice);

            SectionEntropy {
                name: sw.name.clone(),
                virtual_address: s.virtual_address,
                raw_size: s.raw_size,
                entropy,
                most_common_byte: mcb,
                most_common_byte_count: mcbc,
                is_packed,
                chi_squared: cs,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Whole-file entropy summary
// ---------------------------------------------------------------------------

/// Overall entropy summary for a PE file.
#[derive(Debug, Clone)]
pub struct EntropySummary {
    /// Entropy of the entire file.
    pub file_entropy: f64,
    /// Per-section entropy results.
    pub sections: Vec<SectionEntropy>,
    /// Number of sections exceeding the packed threshold.
    pub packed_section_count: usize,
    /// Highest entropy found across all sections.
    pub max_section_entropy: f64,
    /// Average section entropy.
    pub avg_section_entropy: f64,
    /// Packing verdict: `true` if the file looks packed/protected.
    pub verdict_packed: bool,
}

impl EntropySummary {
    /// Analyse a PE file and return an overall entropy report.
    pub fn analyze(data: &[u8], sections: &[SectionWithName]) -> Self {
        let file_entropy = shannon_entropy(data);
        let section_results = analyze_sections(data, sections);

        let packed_section_count = section_results.iter().filter(|s| s.is_packed).count();
        let max_section_entropy = section_results
            .iter()
            .map(|s| s.entropy)
            .fold(0.0f64, f64::max);
        let avg_section_entropy = if section_results.is_empty() {
            0.0
        } else {
            section_results.iter().map(|s| s.entropy).sum::<f64>() / usize_to_f64(section_results.len())
        };

        // Verdict: ≥1 packed section or file entropy > threshold
        let verdict_packed = packed_section_count > 0 || file_entropy >= PACKED_ENTROPY_THRESHOLD;

        Self {
            file_entropy,
            sections: section_results,
            packed_section_count,
            max_section_entropy,
            avg_section_entropy,
            verdict_packed,
        }
    }

    /// Return sections with entropy above `threshold`, sorted descending.
    #[must_use]
    pub fn high_entropy_sections(&self, threshold: f64) -> Vec<&SectionEntropy> {
        let mut v: Vec<&SectionEntropy> = self
            .sections
            .iter()
            .filter(|s| s.entropy >= threshold)
            .collect();
        v.sort_by(|a, b| {
            b.entropy
                .partial_cmp(&a.entropy)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert!(shannon_entropy(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_single_byte() {
        // All same byte → entropy = 0
        let data = vec![0x41u8; 1000];
        let e = shannon_entropy(&data);
        assert!(e < 0.001, "entropy of constant data should be ~0, got {e}");
    }

    #[test]
    fn test_entropy_uniform() {
        // Perfect uniform distribution → entropy ≈ 8.0
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.99, "entropy of uniform data should be ~8.0, got {e}");
    }

    #[test]
    fn test_entropy_half_alphabet() {
        // 128 distinct values → entropy ≈ 7.0
        let data: Vec<u8> = (0..=127u8).cycle().take(2048).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 7.0).abs() < 0.05,
            "entropy of 128-symbol alphabet should be ~7.0, got {e}"
        );
    }

    #[test]
    fn test_looks_packed_random() {
        // Use a repeating but high-entropy-looking pattern
        let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        assert!(looks_packed(&data));
    }

    #[test]
    fn test_looks_packed_zeros() {
        let data = vec![0u8; 8192];
        assert!(!looks_packed(&data));
    }

    #[test]
    fn test_looks_packed_too_small() {
        let data: Vec<u8> = (0..=255u8).cycle().take(100).collect();
        assert!(!looks_packed(&data));
    }

    #[test]
    fn test_most_common_byte_empty() {
        assert_eq!(most_common_byte(&[]), (0, 0));
    }

    #[test]
    fn test_most_common_byte() {
        let data = vec![0xABu8; 50]
            .into_iter()
            .chain(vec![0x00u8; 10])
            .collect::<Vec<_>>();
        let (b, c) = most_common_byte(&data);
        assert_eq!(b, 0xAB);
        assert_eq!(c, 50);
    }

    #[test]
    fn test_chi_squared_uniform() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2560).collect();
        let cs = chi_squared(&data);
        // Perfect uniform → chi-squared ≈ 0
        assert!(
            cs < 1.0,
            "chi_squared of uniform data should be ~0, got {cs}"
        );
    }

    #[test]
    fn test_chi_squared_skewed() {
        let data = vec![0x00u8; 2048];
        let cs = chi_squared(&data);
        // All same byte → extremely skewed
        assert!(
            cs > 100_000.0,
            "chi_squared of constant data should be very high, got {cs}"
        );
    }

    #[test]
    fn test_section_entropy_packed_verdict() {
        let uniform_data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let sections = vec![SectionWithName {
            section: RvaSection {
                virtual_address: 0x1000,
                virtual_size: 4096,
                raw_size: 4096,
                raw_offset: 0,
            },
            name: ".text".into(),
        }];
        let result = analyze_sections(&uniform_data, &sections);
        assert_eq!(result.len(), 1);
        assert!(result[0].entropy > 7.9);
        assert!(result[0].is_packed);
        assert!(!result[0].is_likely_bss());
    }

    #[test]
    fn test_section_entropy_bss() {
        let zero_data = vec![0u8; 4096];
        let sections = vec![SectionWithName {
            section: RvaSection {
                virtual_address: 0x2000,
                virtual_size: 4096,
                raw_size: 4096,
                raw_offset: 0,
            },
            name: ".bss".into(),
        }];
        let result = analyze_sections(&zero_data, &sections);
        assert_eq!(result.len(), 1);
        assert!(result[0].entropy < 0.001);
        assert!(result[0].is_likely_bss());
        assert!(!result[0].is_packed);
    }

    #[test]
    fn test_entropy_summary() {
        let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        let sections = vec![SectionWithName {
            section: RvaSection {
                virtual_address: 0x1000,
                virtual_size: 4096,
                raw_size: 4096,
                raw_offset: 0,
            },
            name: ".packed".into(),
        }];
        let summary = EntropySummary::analyze(&data, &sections);
        assert!(summary.verdict_packed);
        assert_eq!(summary.packed_section_count, 1);
        assert!(summary.max_section_entropy > 7.9);

        let high = summary.high_entropy_sections(7.0);
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn test_entropy_summary_empty_sections() {
        let data = vec![0u8; 100];
        let summary = EntropySummary::analyze(&data, &[]);
        assert!(!summary.verdict_packed);
        assert_eq!(summary.packed_section_count, 0);
        assert!(summary.avg_section_entropy.abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_is_suspicious() {
        let se = SectionEntropy {
            name: ".x".into(),
            virtual_address: 0x1000,
            raw_size: 4096,
            entropy: 7.9,
            most_common_byte: 0,
            most_common_byte_count: 10,
            is_packed: true,
            chi_squared: 5.0,
        };
        assert!(se.is_suspicious());
        assert!(!se.is_likely_bss());
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_entropy_single_byte_input() {
        // A 1-byte slice has entropy 0 (probability of that byte = 1).
        let e = shannon_entropy(&[0x42]);
        assert!(e < 0.001);
    }

    #[test]
    fn test_entropy_two_symbols_equal() {
        // Two equally likely symbols → entropy = 1.0
        let data: Vec<u8> = [0u8, 1u8].iter().cycle().take(2048).copied().collect();
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_byte_histogram_sum_equals_len() {
        let data = vec![3u8, 7, 3, 9, 9, 9, 0];
        let hist = byte_histogram(&data);
        let sum: u32 = hist.iter().sum();
        assert_eq!(sum as usize, data.len());
        assert_eq!(hist[9], 3);
        assert_eq!(hist[3], 2);
    }

    #[test]
    fn test_chi_squared_empty_returns_zero() {
        assert!(chi_squared(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analyze_sections_offset_out_of_bounds() {
        // raw_offset is past the end of data → empty slice → 0 entropy.
        let data = vec![0xAAu8; 32];
        let sections = vec![SectionWithName {
            section: RvaSection {
                virtual_address: 0x1000,
                virtual_size: 64,
                raw_size: 64,
                raw_offset: 1000, // far beyond data
            },
            name: ".oob".into(),
        }];
        let r = analyze_sections(&data, &sections);
        assert_eq!(r.len(), 1);
        assert!(r[0].entropy.abs() < f64::EPSILON);
        assert!(!r[0].is_packed);
    }

    #[test]
    fn test_analyze_sections_partial_overlap_clamped() {
        // raw_size extends past EOF → clamped to data length.
        let data = vec![0u8; 16];
        let sections = vec![SectionWithName {
            section: RvaSection {
                virtual_address: 0x1000,
                virtual_size: 1024,
                raw_size: 1024,
                raw_offset: 0,
            },
            name: ".clamp".into(),
        }];
        let r = analyze_sections(&data, &sections);
        // Clamped slice is all zeros → entropy 0.
        assert!(r[0].entropy < 0.001);
    }

    #[test]
    fn test_high_entropy_sections_sorted_desc() {
        let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        let sections = vec![
            SectionWithName {
                section: RvaSection {
                    virtual_address: 0x1000,
                    virtual_size: 4096,
                    raw_size: 4096,
                    raw_offset: 0,
                },
                name: ".a".into(),
            },
            SectionWithName {
                section: RvaSection {
                    virtual_address: 0x2000,
                    virtual_size: 4096,
                    raw_size: 4096,
                    raw_offset: 4096,
                },
                name: ".b".into(),
            },
        ];
        let summary = EntropySummary::analyze(&data, &sections);
        let high = summary.high_entropy_sections(0.0);
        assert_eq!(high.len(), 2);
        // Sorted descending by entropy.
        assert!(high[0].entropy >= high[1].entropy);
    }
}
