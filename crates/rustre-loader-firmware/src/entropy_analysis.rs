//! `entropy_analysis` — Shannon entropy-based firmware region analysis.
//!
//! Provides:
//! - Sliding-window Shannon entropy calculation.
//! - [`EntropyClass`] classification of entropy values into meaningful tiers.
//! - [`EntropyRegion`] — a contiguous block with a uniform classification.
//! - [`EntropyHeatmap`] — a compact numeric representation of entropy across
//!   a firmware image, suitable for visualization or further analysis.
//! - Block classification helpers used by the extraction engine.
//!
//! # Entropy interpretation
//! | Range       | Class       | Typical cause                    |
//! |-------------|-------------|----------------------------------|
//! | 0.0 – 0.99  | `Sparse`    | Flash erased, zero-filled buffers |
//! | 1.0 – 3.49  | `Low`       | Executable/config with structure  |
//! | 3.5 – 5.49  | `Medium`    | Text, mixed binary                |
//! | 5.5 – 6.99  | `High`      | Compressed data, dense binaries   |
//! | 7.0 – 7.79  | `Compressed`| Highly compressed streams         |
//! | 7.8 – 8.0   | `Encrypted` | Encrypted data / TRNG noise       |
//!
//! # Usage
//! ```rust
//! use rustre_loader_firmware::entropy_analysis::{EntropyAnalyzer, EntropyClass};
//! let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
//! let analyzer = EntropyAnalyzer::default();
//! let regions = analyzer.find_regions(&data);
//! assert!(!regions.is_empty());
//! ```

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// EntropyClass
// ─────────────────────────────────────────────────────────────────────────────

/// Qualitative classification of a block's Shannon entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntropyClass {
    /// 0.0 – 0.99 bits/byte: nearly empty or zero-filled.
    Sparse,
    /// 1.0 – 3.49 bits/byte: structured binary (code, headers).
    Low,
    /// 3.5 – 5.49 bits/byte: mixed content, plain text with binary.
    Medium,
    /// 5.5 – 6.99 bits/byte: dense binary, partially compressed.
    High,
    /// 7.0 – 7.79 bits/byte: compressed data stream.
    Compressed,
    /// 7.8 – 8.0 bits/byte: encrypted data or true random noise.
    Encrypted,
}

impl EntropyClass {
    /// Classify an entropy value in bits/byte.
    #[must_use]
    pub fn from_entropy(e: f64) -> Self {
        if e < 1.0 {
            Self::Sparse
        } else if e < 3.5 {
            Self::Low
        } else if e < 5.5 {
            Self::Medium
        } else if e < 7.0 {
            Self::High
        } else if e < 7.8 {
            Self::Compressed
        } else {
            Self::Encrypted
        }
    }

    /// Return `true` if this class is likely compressed or encrypted.
    #[must_use]
    pub const fn is_high(self) -> bool {
        matches!(self, Self::Compressed | Self::Encrypted | Self::High)
    }

    /// Return a short label string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sparse => "sparse",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Compressed => "compressed",
            Self::Encrypted => "encrypted",
        }
    }

    /// Typical entropy midpoint for this class (useful for thresholding).
    #[must_use]
    pub const fn typical_entropy(self) -> f64 {
        match self {
            Self::Sparse => 0.5,
            Self::Low => 2.0,
            Self::Medium => 4.5,
            Self::High => 6.2,
            Self::Compressed => 7.4,
            Self::Encrypted => 7.95,
        }
    }
}

impl fmt::Display for EntropyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous span of firmware with a stable [`EntropyClass`].
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    /// Byte offset of the start of this region.
    pub offset: usize,
    /// Length of this region in bytes.
    pub size: usize,
    /// Classification of this region.
    pub class: EntropyClass,
    /// Average Shannon entropy within this region.
    pub avg_entropy: f64,
    /// Minimum entropy window value within this region.
    pub min_entropy: f64,
    /// Maximum entropy window value within this region.
    pub max_entropy: f64,
}

impl EntropyRegion {
    /// Byte offset of the first byte past this region.
    #[must_use]
    pub const fn end_offset(&self) -> usize {
        self.offset + self.size
    }

    /// Return `true` if this region overlaps with `[other_start, other_end)`.
    #[must_use]
    pub fn overlaps(&self, other_start: usize, other_end: usize) -> bool {
        self.offset < other_end && self.end_offset() > other_start
    }
}

impl fmt::Display for EntropyRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#010x}..{:#010x}] {:10}  avg={:.3}  min={:.3}  max={:.3}",
            self.offset,
            self.end_offset(),
            self.class,
            self.avg_entropy,
            self.min_entropy,
            self.max_entropy,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyHeatmap
// ─────────────────────────────────────────────────────────────────────────────

/// A compact representation of entropy values sampled across the firmware.
///
/// Each entry stores `(offset, entropy)` from the sliding window scan.
#[derive(Debug, Clone)]
pub struct EntropyHeatmap {
    /// Sampled `(offset, entropy)` pairs.
    pub samples: Vec<(usize, f64)>,
    /// Window size used to produce each sample.
    pub window_size: usize,
    /// Step size between windows.
    pub step_size: usize,
}

impl EntropyHeatmap {
    /// Return the sample with the highest entropy.
    #[must_use]
    pub fn peak(&self) -> Option<(usize, f64)> {
        self.samples
            .iter()
            .copied()
            .reduce(|a, b| if b.1 > a.1 { b } else { a })
    }

    /// Return the sample with the lowest entropy.
    #[must_use]
    pub fn trough(&self) -> Option<(usize, f64)> {
        self.samples
            .iter()
            .copied()
            .reduce(|a, b| if b.1 < a.1 { b } else { a })
    }

    /// Average entropy across all samples.
    #[must_use]
    pub fn average(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().map(|(_, e)| e).sum::<f64>() / self.samples.len() as f64
    }

    /// Fraction of samples with entropy above `threshold`.
    #[must_use]
    pub fn fraction_above(&self, threshold: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let above = self.samples.iter().filter(|(_, e)| *e >= threshold).count();
        above as f64 / self.samples.len() as f64
    }

    /// Return all samples classified as `class`.
    #[must_use]
    pub fn samples_of_class(&self, class: EntropyClass) -> Vec<(usize, f64)> {
        self.samples
            .iter()
            .filter(|(_, e)| EntropyClass::from_entropy(*e) == class)
            .copied()
            .collect()
    }

    /// Render a one-line ASCII entropy bar chart.
    ///
    /// Width is clamped to at most 80 characters.
    #[must_use]
    pub fn ascii_bar(&self, width: usize) -> String {
        let width = width.min(80).max(1);
        if self.samples.is_empty() {
            return " ".repeat(width);
        }
        let chars: Vec<char> = vec![' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let per_col = (self.samples.len() as f64 / width as f64).max(1.0);
        (0..width)
            .map(|col| {
                let start = (col as f64 * per_col) as usize;
                let end = (((col + 1) as f64) * per_col).ceil() as usize;
                let end = end.min(self.samples.len());
                if start >= self.samples.len() {
                    return ' ';
                }
                let avg = self.samples[start..end].iter().map(|(_, e)| e).sum::<f64>()
                    / (end - start) as f64;
                // Map [0..8] to [0..8]
                let idx = ((avg / 8.0) * (chars.len() - 1) as f64).round() as usize;
                chars[idx.min(chars.len() - 1)]
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration and methods for entropy analysis.
#[derive(Debug, Clone)]
pub struct EntropyAnalyzer {
    /// Window size in bytes for sliding scan.
    pub window_size: usize,
    /// Step size in bytes between windows.
    pub step_size: usize,
    /// Minimum region size (in bytes) to emit.
    pub min_region_bytes: usize,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self {
            window_size: 512,
            step_size: 256,
            min_region_bytes: 256,
        }
    }
}

impl EntropyAnalyzer {
    /// Create with custom parameters.
    #[must_use]
    pub const fn new(window_size: usize, step_size: usize, min_region_bytes: usize) -> Self {
        Self {
            window_size,
            step_size,
            min_region_bytes,
        }
    }

    /// Compute Shannon entropy of `data` in bits/byte (range 0.0–8.0).
    #[must_use]
    pub fn block_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let n = data.len() as f64;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Classify a scalar entropy value.
    #[must_use]
    pub fn classify(e: f64) -> EntropyClass {
        EntropyClass::from_entropy(e)
    }

    /// Classify a block of data.
    #[must_use]
    pub fn classify_block(&self, data: &[u8]) -> EntropyClass {
        EntropyClass::from_entropy(Self::block_entropy(data))
    }

    /// Produce a sliding-window entropy scan.
    /// Returns vec of `(offset, entropy)` pairs.
    #[must_use]
    pub fn sliding_entropy(&self, data: &[u8]) -> Vec<(usize, f64)> {
        if self.window_size == 0 || self.step_size == 0 || data.len() < self.window_size {
            return vec![];
        }
        let mut results = Vec::new();
        let mut off = 0usize;
        while off + self.window_size <= data.len() {
            let e = Self::block_entropy(&data[off..off + self.window_size]);
            results.push((off, e));
            off += self.step_size;
        }
        results
    }

    /// Build an [`EntropyHeatmap`] from `data`.
    #[must_use]
    pub fn heatmap(&self, data: &[u8]) -> EntropyHeatmap {
        EntropyHeatmap {
            samples: self.sliding_entropy(data),
            window_size: self.window_size,
            step_size: self.step_size,
        }
    }

    /// Segment `data` into contiguous [`EntropyRegion`]s of stable class.
    ///
    /// Regions smaller than `min_region_bytes` are merged into their neighbour.
    #[must_use]
    pub fn find_regions(&self, data: &[u8]) -> Vec<EntropyRegion> {
        let windows = self.sliding_entropy(data);
        if windows.is_empty() {
            return vec![];
        }

        // Build raw segments
        let mut raw: Vec<EntropyRegion> = Vec::new();
        let mut seg_class = EntropyClass::from_entropy(windows[0].1);
        let mut seg_start = windows[0].0;
        let mut entropies: Vec<f64> = vec![windows[0].1];

        for &(off, e) in &windows[1..] {
            let cls = EntropyClass::from_entropy(e);
            if cls == seg_class {
                entropies.push(e);
            } else {
                let size = off - seg_start;
                if size >= self.min_region_bytes || raw.is_empty() {
                    raw.push(make_region(seg_start, size, seg_class, &entropies));
                }
                seg_start = off;
                seg_class = cls;
                entropies = vec![e];
            }
        }
        // Close last segment
        let last_off = windows.last().map(|(o, _)| *o).unwrap_or(0);
        let size = (last_off + self.window_size).min(data.len()) - seg_start;
        if size >= self.min_region_bytes || raw.is_empty() {
            raw.push(make_region(seg_start, size, seg_class, &entropies));
        }

        raw
    }

    /// Count how many bytes (approximately, based on windows) belong to each
    /// [`EntropyClass`].  Returns an array indexed by class ordinal.
    #[must_use]
    pub fn class_distribution(&self, data: &[u8]) -> [usize; 6] {
        let mut dist = [0usize; 6];
        for (_, e) in self.sliding_entropy(data) {
            let idx = match EntropyClass::from_entropy(e) {
                EntropyClass::Sparse => 0,
                EntropyClass::Low => 1,
                EntropyClass::Medium => 2,
                EntropyClass::High => 3,
                EntropyClass::Compressed => 4,
                EntropyClass::Encrypted => 5,
            };
            dist[idx] += self.window_size;
        }
        dist
    }

    /// Return the fraction of the image estimated to be compressed/encrypted.
    #[must_use]
    pub fn compressed_fraction(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let windows = self.sliding_entropy(data);
        if windows.is_empty() {
            return 0.0;
        }
        let high = windows.iter().filter(|(_, e)| *e >= 7.0).count();
        high as f64 / windows.len() as f64
    }

    /// Find the byte offset with the highest local entropy in `data`.
    #[must_use]
    pub fn highest_entropy_offset(&self, data: &[u8]) -> Option<usize> {
        self.sliding_entropy(data)
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(off, _)| off)
    }

    /// Find the byte offset with the lowest local entropy in `data`.
    #[must_use]
    pub fn lowest_entropy_offset(&self, data: &[u8]) -> Option<usize> {
        self.sliding_entropy(data)
            .into_iter()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(off, _)| off)
    }

    /// Return `true` if the overall entropy of `data` suggests it is encrypted
    /// or already compressed.
    #[must_use]
    pub fn is_high_entropy_blob(data: &[u8]) -> bool {
        Self::block_entropy(data) >= 7.0
    }
}

fn make_region(start: usize, size: usize, class: EntropyClass, entropies: &[f64]) -> EntropyRegion {
    let avg = if entropies.is_empty() {
        0.0
    } else {
        entropies.iter().copied().sum::<f64>() / entropies.len() as f64
    };
    let min = entropies.iter().copied().fold(f64::INFINITY, f64::min);
    let max = entropies.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    EntropyRegion {
        offset: start,
        size,
        class,
        avg_entropy: avg,
        min_entropy: if min.is_finite() { min } else { avg },
        max_entropy: if max.is_finite() { max } else { avg },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyProfile — whole-image summary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level entropy profile of a firmware image.
#[derive(Debug, Clone)]
pub struct EntropyProfile {
    /// Overall Shannon entropy of the entire image.
    pub overall_entropy: f64,
    /// Classification of the overall entropy.
    pub overall_class: EntropyClass,
    /// Number of distinct entropy regions found.
    pub region_count: usize,
    /// Approximate percentage of the image that is compressed/encrypted.
    pub compressed_pct: f64,
    /// Peak entropy value and the offset where it was found.
    pub peak: Option<(usize, f64)>,
    /// List of entropy regions.
    pub regions: Vec<EntropyRegion>,
}

impl EntropyProfile {
    /// Analyse `data` and produce a full [`EntropyProfile`].
    #[must_use]
    pub fn analyse(data: &[u8]) -> Self {
        let analyzer = EntropyAnalyzer::default();
        let overall_entropy = EntropyAnalyzer::block_entropy(data);
        let overall_class = EntropyClass::from_entropy(overall_entropy);
        let compressed_pct = analyzer.compressed_fraction(data) * 100.0;
        let heatmap = analyzer.heatmap(data);
        let peak = heatmap.peak();
        let regions = analyzer.find_regions(data);
        Self {
            overall_entropy,
            overall_class,
            region_count: regions.len(),
            compressed_pct,
            peak,
            regions,
        }
    }
}

impl fmt::Display for EntropyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "entropy={:.3} class={} regions={} compressed={:.1}%",
            self.overall_entropy, self.overall_class, self.region_count, self.compressed_pct,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> EntropyAnalyzer {
        EntropyAnalyzer::default()
    }

    // ── block_entropy ─────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_empty() {
        assert_eq!(EntropyAnalyzer::block_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_all_same() {
        let data = vec![0xAA_u8; 256];
        assert_eq!(EntropyAnalyzer::block_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_max() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = EntropyAnalyzer::block_entropy(&data);
        assert!((e - 8.0).abs() < 1e-9, "max entropy should be 8.0, got {e}");
    }

    #[test]
    fn test_entropy_two_symbols_equal() {
        // Half 0x00, half 0xFF → entropy = 1.0
        let mut data = vec![0u8; 128];
        data.extend(vec![0xFF_u8; 128]);
        let e = EntropyAnalyzer::block_entropy(&data);
        assert!((e - 1.0).abs() < 1e-9, "got {e}");
    }

    #[test]
    fn test_entropy_single_byte() {
        assert_eq!(EntropyAnalyzer::block_entropy(&[0x42]), 0.0);
    }

    // ── EntropyClass ──────────────────────────────────────────────────────────

    #[test]
    fn test_class_sparse() {
        assert_eq!(EntropyClass::from_entropy(0.0), EntropyClass::Sparse);
        assert_eq!(EntropyClass::from_entropy(0.99), EntropyClass::Sparse);
    }

    #[test]
    fn test_class_low() {
        assert_eq!(EntropyClass::from_entropy(1.0), EntropyClass::Low);
        assert_eq!(EntropyClass::from_entropy(3.49), EntropyClass::Low);
    }

    #[test]
    fn test_class_medium() {
        assert_eq!(EntropyClass::from_entropy(3.5), EntropyClass::Medium);
        assert_eq!(EntropyClass::from_entropy(5.49), EntropyClass::Medium);
    }

    #[test]
    fn test_class_high() {
        assert_eq!(EntropyClass::from_entropy(5.5), EntropyClass::High);
        assert_eq!(EntropyClass::from_entropy(6.99), EntropyClass::High);
    }

    #[test]
    fn test_class_compressed() {
        assert_eq!(EntropyClass::from_entropy(7.0), EntropyClass::Compressed);
        assert_eq!(EntropyClass::from_entropy(7.79), EntropyClass::Compressed);
    }

    #[test]
    fn test_class_encrypted() {
        assert_eq!(EntropyClass::from_entropy(7.8), EntropyClass::Encrypted);
        assert_eq!(EntropyClass::from_entropy(8.0), EntropyClass::Encrypted);
    }

    #[test]
    fn test_class_is_high() {
        assert!(EntropyClass::Compressed.is_high());
        assert!(EntropyClass::Encrypted.is_high());
        assert!(EntropyClass::High.is_high());
        assert!(!EntropyClass::Sparse.is_high());
        assert!(!EntropyClass::Low.is_high());
    }

    #[test]
    fn test_class_ordering() {
        assert!(EntropyClass::Sparse < EntropyClass::Low);
        assert!(EntropyClass::Low < EntropyClass::Encrypted);
    }

    #[test]
    fn test_class_display() {
        assert_eq!(EntropyClass::Encrypted.to_string(), "encrypted");
        assert_eq!(EntropyClass::Compressed.to_string(), "compressed");
        assert_eq!(EntropyClass::Sparse.to_string(), "sparse");
    }

    #[test]
    fn test_class_typical_entropy() {
        assert!(EntropyClass::Sparse.typical_entropy() < 1.0);
        assert!(EntropyClass::Encrypted.typical_entropy() > 7.5);
    }

    // ── sliding_entropy ───────────────────────────────────────────────────────

    #[test]
    fn test_sliding_entropy_empty() {
        assert!(analyzer().sliding_entropy(&[]).is_empty());
    }

    #[test]
    fn test_sliding_entropy_too_small() {
        let a = EntropyAnalyzer::new(512, 256, 256);
        assert!(a.sliding_entropy(&[0u8; 100]).is_empty());
    }

    #[test]
    fn test_sliding_entropy_count() {
        let a = EntropyAnalyzer::new(256, 256, 64);
        let data = vec![0u8; 1024];
        let windows = a.sliding_entropy(&data);
        // (1024 - 256) / 256 + 1 = 4
        assert_eq!(windows.len(), 4);
    }

    #[test]
    fn test_sliding_entropy_offsets_increasing() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(2048).collect();
        let windows = analyzer().sliding_entropy(&data);
        assert!(windows.windows(2).all(|w| w[0].0 < w[1].0));
    }

    // ── find_regions ──────────────────────────────────────────────────────────

    #[test]
    fn test_find_regions_uniform_data() {
        let data = vec![0u8; 4096];
        let a = EntropyAnalyzer::new(256, 128, 128);
        let regions = a.find_regions(&data);
        assert!(!regions.is_empty());
        assert!(regions.iter().all(|r| r.class == EntropyClass::Sparse));
    }

    #[test]
    fn test_find_regions_high_entropy_section() {
        let mut data = vec![0u8; 8192];
        // Fill middle with high-entropy bytes
        for i in 2048..6144 {
            data[i] = ((i * 167 + 13) & 0xFF) as u8;
        }
        let a = EntropyAnalyzer::new(256, 128, 128);
        let regions = a.find_regions(&data);
        assert!(regions.iter().any(|r| r.class.is_high()));
    }

    #[test]
    fn test_find_regions_avg_entropy_in_range() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(4096).collect();
        let a = EntropyAnalyzer::new(256, 128, 128);
        let regions = a.find_regions(&data);
        for r in &regions {
            assert!(r.avg_entropy >= 0.0 && r.avg_entropy <= 8.0);
        }
    }

    // ── EntropyHeatmap ────────────────────────────────────────────────────────

    #[test]
    fn test_heatmap_peak_trough() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        let hm = a.heatmap(&data);
        assert!(hm.peak().is_some());
        assert!(hm.trough().is_some());
    }

    #[test]
    fn test_heatmap_average() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        let hm = a.heatmap(&data);
        let avg = hm.average();
        assert!(avg > 0.0 && avg <= 8.0);
    }

    #[test]
    fn test_heatmap_fraction_above() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        let hm = a.heatmap(&data);
        // All windows should have entropy ≈ 8.0
        assert!(hm.fraction_above(7.9) > 0.9);
    }

    #[test]
    fn test_heatmap_empty() {
        let a = EntropyAnalyzer::new(512, 256, 64);
        let hm = a.heatmap(&[]);
        assert!(hm.peak().is_none());
        assert_eq!(hm.average(), 0.0);
    }

    #[test]
    fn test_heatmap_ascii_bar_length() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        let hm = a.heatmap(&data);
        let bar = hm.ascii_bar(40);
        assert_eq!(bar.chars().count(), 40);
    }

    #[test]
    fn test_heatmap_samples_of_class() {
        let data = vec![0u8; 2048]; // all zeros → Sparse
        let a = EntropyAnalyzer::new(256, 128, 64);
        let hm = a.heatmap(&data);
        let sparse = hm.samples_of_class(EntropyClass::Sparse);
        assert!(!sparse.is_empty());
    }

    // ── compressed_fraction ───────────────────────────────────────────────────

    #[test]
    fn test_compressed_fraction_all_high() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        assert!(a.compressed_fraction(&data) > 0.9);
    }

    #[test]
    fn test_compressed_fraction_all_zero() {
        let data = vec![0u8; 4096];
        let a = EntropyAnalyzer::new(256, 128, 64);
        assert_eq!(a.compressed_fraction(&data), 0.0);
    }

    // ── offsets ───────────────────────────────────────────────────────────────

    #[test]
    fn test_highest_entropy_offset() {
        let mut data = vec![0u8; 2048];
        // Put high-entropy block at offset 1024
        for i in 1024..1280 {
            data[i] = ((i * 251) & 0xFF) as u8;
        }
        let a = EntropyAnalyzer::new(256, 128, 64);
        let off = a.highest_entropy_offset(&data);
        assert!(off.is_some());
    }

    #[test]
    fn test_lowest_entropy_offset() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        // All windows ≈ same entropy, should still return Some
        assert!(a.lowest_entropy_offset(&data).is_some());
    }

    // ── is_high_entropy_blob ──────────────────────────────────────────────────

    #[test]
    fn test_is_high_entropy_blob_true() {
        let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        assert!(EntropyAnalyzer::is_high_entropy_blob(&data));
    }

    #[test]
    fn test_is_high_entropy_blob_false() {
        let data = vec![0u8; 256];
        assert!(!EntropyAnalyzer::is_high_entropy_blob(&data));
    }

    // ── class_distribution ────────────────────────────────────────────────────

    #[test]
    fn test_class_distribution_sums_to_something() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let a = EntropyAnalyzer::new(256, 128, 64);
        let dist = a.class_distribution(&data);
        let total: usize = dist.iter().sum();
        assert!(total > 0);
    }

    // ── EntropyProfile ────────────────────────────────────────────────────────

    #[test]
    fn test_profile_all_zeros() {
        let data = vec![0u8; 4096];
        let p = EntropyProfile::analyse(&data);
        assert_eq!(p.overall_class, EntropyClass::Sparse);
        assert!(p.overall_entropy < 1.0);
    }

    #[test]
    fn test_profile_high_entropy() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let p = EntropyProfile::analyse(&data);
        assert!(p.overall_entropy > 7.9);
        assert!(p.compressed_pct > 0.0);
    }

    #[test]
    fn test_profile_display() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let p = EntropyProfile::analyse(&data);
        let s = p.to_string();
        assert!(s.contains("entropy="));
        assert!(s.contains("class="));
    }

    // ── EntropyRegion helpers ──────────────────────────────────────────────────

    #[test]
    fn test_entropy_region_end_offset() {
        let r = EntropyRegion {
            offset: 100,
            size: 200,
            class: EntropyClass::Low,
            avg_entropy: 2.0,
            min_entropy: 1.5,
            max_entropy: 2.5,
        };
        assert_eq!(r.end_offset(), 300);
    }

    #[test]
    fn test_entropy_region_overlaps() {
        let r = EntropyRegion {
            offset: 100,
            size: 100,
            class: EntropyClass::Low,
            avg_entropy: 2.0,
            min_entropy: 1.5,
            max_entropy: 2.5,
        };
        assert!(r.overlaps(150, 250));
        assert!(!r.overlaps(200, 300));
    }

    #[test]
    fn test_entropy_region_display() {
        let r = EntropyRegion {
            offset: 0x1000,
            size: 0x100,
            class: EntropyClass::High,
            avg_entropy: 6.5,
            min_entropy: 6.0,
            max_entropy: 6.9,
        };
        let s = r.to_string();
        assert!(s.contains("high"));
        assert!(s.contains("0x00001000"));
    }
}
