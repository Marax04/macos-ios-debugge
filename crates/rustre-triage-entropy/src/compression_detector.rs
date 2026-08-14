//! Compression and encoding detector for binary sections.
//!
//! Uses chi-square uniformity tests and entropy profiling to detect compressed
//! data and distinguish between common formats: DEFLATE, ZLIB, LZ4, LZMA,
//! Brotli, Zstandard, and BZ2.

use crate::{shannon_entropy_f32, ByteHistogram, casts};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── CompressionFormat ────────────────────────────────────────────────────────

/// Known compression/encoding formats that can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionFormat {
    /// Raw DEFLATE stream (RFC 1951) — no wrapper.
    Deflate,
    /// ZLIB-wrapped DEFLATE (RFC 1950): magic 0x78 + second byte.
    Zlib,
    /// GZIP-wrapped DEFLATE (RFC 1952): magic 0x1F 0x8B.
    Gzip,
    /// LZ4 frame format: magic 0x04 0x22 0x4D 0x18.
    Lz4,
    /// LZ4 legacy frame: magic 0x02 0x21 0x4C 0x18.
    Lz4Legacy,
    /// LZMA stream: properties byte 0x5D and high entropy.
    Lzma,
    /// XZ container for LZMA2: magic 0xFD 0x37 0x7A 0x58 0x5A 0x00.
    Xz,
    /// Brotli compressed (no universal magic — detected via entropy profile).
    Brotli,
    /// Zstandard: magic 0xFD 0x2F 0xB5 0x28.
    Zstd,
    /// `BZip2`: magic "`BZh`".
    Bzip2,
    /// LZOP: magic 0x89 0x4C 0x5A 0x4F 0x00 0x0D 0x0A 0x1A 0x0A.
    Lzop,
    /// Snappy framing: magic 0xFF 0x06 0x00 0x00 0x73 0x4E 0x61 0x50 0x70 0x59.
    Snappy,
    /// Data does not appear compressed (entropy too low or bytes too non-uniform).
    NotCompressed,
    /// High entropy but no matching magic — likely encrypted or otherwise random.
    HighEntropyUnknown,
}

impl CompressionFormat {
    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Deflate => "DEFLATE",
            Self::Zlib => "ZLIB",
            Self::Gzip => "GZIP",
            Self::Lz4 => "LZ4",
            Self::Lz4Legacy => "LZ4-Legacy",
            Self::Lzma => "LZMA",
            Self::Xz => "XZ/LZMA2",
            Self::Brotli => "Brotli",
            Self::Zstd => "Zstandard",
            Self::Bzip2 => "BZip2",
            Self::Lzop => "LZOP",
            Self::Snappy => "Snappy",
            Self::NotCompressed => "NotCompressed",
            Self::HighEntropyUnknown => "HighEntropyUnknown",
        }
    }

    /// Whether this format indicates compressed (or high-entropy) content.
    #[must_use]
    pub const fn is_compressed_or_encrypted(&self) -> bool {
        !matches!(self, Self::NotCompressed)
    }
}

impl fmt::Display for CompressionFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── CompressionDetectionResult ──────────────────────────────────────────────

/// Full result of detecting compression in a data slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionDetectionResult {
    /// Detected format.
    pub format: CompressionFormat,
    /// Shannon entropy of the slice (0.0 – 8.0).
    pub entropy: f32,
    /// Chi-square statistic (lower = less uniform = less compressed/encrypted).
    pub chi_square: f64,
    /// Whether the data passes the chi-square uniformity threshold.
    pub is_chi_square_uniform: bool,
    /// Offset into the original buffer this result refers to.
    pub offset: usize,
    /// Number of bytes analysed.
    pub size: usize,
    /// Confidence score 0–100 (higher = more certain).
    pub confidence: u8,
    /// Human-readable explanation of the detection logic used.
    pub reason: String,
}

impl CompressionDetectionResult {
    /// Returns `true` if the data is likely compressed.
    #[must_use]
    pub const fn likely_compressed(&self) -> bool {
        self.format.is_compressed_or_encrypted() && self.confidence >= 60
    }
}

impl fmt::Display for CompressionDetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompressionDetection {{ format={}, entropy={:.3}, chi2={:.1}, confidence={}, reason='{}' }}",
            self.format, self.entropy, self.chi_square, self.confidence, self.reason
        )
    }
}

// ─── CompressionDetector ─────────────────────────────────────────────────────

/// Detects compression format via magic-byte matching and entropy analysis.
pub struct CompressionDetector {
    /// Entropy threshold above which data is considered "likely compressed / encrypted".
    /// Default: 6.5
    pub entropy_threshold: f32,
    /// Minimum data length required for chi-square to be meaningful.
    /// Default: 256
    pub min_chi_square_len: usize,
}

impl Default for CompressionDetector {
    fn default() -> Self {
        Self {
            entropy_threshold: 6.5,
            min_chi_square_len: 256,
        }
    }
}

impl CompressionDetector {
    /// Create a new detector with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom entropy threshold.
    #[must_use]
    pub fn with_threshold(entropy_threshold: f32) -> Self {
        Self {
            entropy_threshold,
            ..Default::default()
        }
    }

    /// Detect the compression format of `data` starting at `offset`.
    ///
    /// Checks magic bytes first; falls back to entropy + chi-square heuristics.
    #[must_use]
    pub fn detect(&self, data: &[u8], offset: usize) -> CompressionDetectionResult {
        let entropy = shannon_entropy_f32(data);
        let hist = ByteHistogram::new(data);
        let chi_square = hist.chi_square_statistic();
        let is_uniform = hist.is_likely_random();

        // Magic-byte identification takes precedence.
        if let Some((fmt, conf, reason)) = Self::detect_by_magic(data) {
            return CompressionDetectionResult {
                format: fmt,
                entropy,
                chi_square,
                is_chi_square_uniform: is_uniform,
                offset,
                size: data.len(),
                confidence: conf,
                reason,
            };
        }

        // Entropy-based fallback.
        let (format, confidence, reason) = self.classify_by_entropy(entropy, chi_square);
        CompressionDetectionResult {
            format,
            entropy,
            chi_square,
            is_chi_square_uniform: is_uniform,
            offset,
            size: data.len(),
            confidence,
            reason,
        }
    }

    /// Scan `data` in `chunk_size`-byte windows and return detections for each chunk.
    #[must_use]
    pub fn scan_chunks(&self, data: &[u8], chunk_size: usize) -> Vec<CompressionDetectionResult> {
        if chunk_size == 0 || data.is_empty() {
            return vec![];
        }
        data.chunks(chunk_size)
            .enumerate()
            .map(|(i, chunk)| self.detect(chunk, i * chunk_size))
            .collect()
    }

    /// Identify compressed chunks — only returns entries that are likely compressed.
    #[must_use]
    pub fn find_compressed_regions(
        &self,
        data: &[u8],
        chunk_size: usize,
    ) -> Vec<CompressionDetectionResult> {
        self.scan_chunks(data, chunk_size)
            .into_iter()
            .filter(CompressionDetectionResult::likely_compressed)
            .collect()
    }

    /// Detect by magic bytes only. Returns `(format, confidence, reason)` or `None`.
    #[must_use]
    fn detect_by_magic(data: &[u8]) -> Option<(CompressionFormat, u8, String)> {
        if data.len() < 2 {
            return None;
        }

        // GZIP: 0x1F 0x8B
        if data.starts_with(&[0x1F, 0x8B]) {
            return Some((
                CompressionFormat::Gzip,
                98,
                "GZIP magic bytes 0x1F 0x8B at offset 0".into(),
            ));
        }

        // XZ: 0xFD 0x37 0x7A 0x58 0x5A 0x00
        if data.len() >= 6 && data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
            return Some((
                CompressionFormat::Xz,
                99,
                "XZ/LZMA2 magic 0xFD377A585A00".into(),
            ));
        }

        // Zstandard: 0x28 0xB5 0x2F 0xFD (little-endian magic 0xFD2FB528)
        if data.len() >= 4 && data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            return Some((
                CompressionFormat::Zstd,
                99,
                "Zstandard magic 0x28B52FFD".into(),
            ));
        }

        // LZ4 frame: 0x04 0x22 0x4D 0x18
        if data.len() >= 4 && data.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
            return Some((
                CompressionFormat::Lz4,
                99,
                "LZ4 frame magic 0x04224D18".into(),
            ));
        }

        // LZ4 legacy: 0x02 0x21 0x4C 0x18
        if data.len() >= 4 && data.starts_with(&[0x02, 0x21, 0x4C, 0x18]) {
            return Some((
                CompressionFormat::Lz4Legacy,
                98,
                "LZ4 legacy frame magic 0x02214C18".into(),
            ));
        }

        // BZip2: "BZh"
        if data.len() >= 3 && data.starts_with(b"BZh") {
            return Some((CompressionFormat::Bzip2, 99, "BZip2 magic 'BZh'".into()));
        }

        // LZOP: 0x89 "LZO\0\r\n\x1A\n"
        if data.len() >= 9
            && data.starts_with(&[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A])
        {
            return Some((
                CompressionFormat::Lzop,
                99,
                "LZOP magic 0x894C5A4F000D0A1A0A".into(),
            ));
        }

        // Snappy framing: 0xFF 0x06 0x00 0x00 "sNaP"
        if data.len() >= 10
            && data.starts_with(&[0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59])
        {
            return Some((
                CompressionFormat::Snappy,
                99,
                "Snappy framing magic".into(),
            ));
        }

        // ZLIB: 0x78 followed by specific second bytes
        if data.len() >= 2 && data[0] == 0x78 {
            let second = data[1];
            // Valid ZLIB second bytes: 0x01, 0x9C, 0xDA, 0x5E (various compression levels)
            if matches!(second, 0x01 | 0x5E | 0x9C | 0xDA) {
                return Some((
                    CompressionFormat::Zlib,
                    90,
                    format!("ZLIB header 0x78{second:02X}"),
                ));
            }
        }

        // LZMA: check properties byte pattern 0x5D (most common LZMA stream)
        if data.len() >= 5 && data[0] == 0x5D {
            // LZMA: properties byte 0x5D, dict size bytes, and 8-byte size field
            // Verify the dict size is a power of 2 or sum
            let dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            if dict_size.is_power_of_two() || (dict_size > 0 && dict_size.is_multiple_of(1 << 12)) {
                return Some((
                    CompressionFormat::Lzma,
                    80,
                    format!("LZMA properties byte 0x5D, dict_size=0x{dict_size:08X}"),
                ));
            }
        }

        None
    }

    /// Classify by entropy and chi-square when no magic bytes match.
    fn classify_by_entropy(
        &self,
        entropy: f32,
        chi_square: f64,
    ) -> (CompressionFormat, u8, String) {
        if entropy >= 7.9 {
            // Near-maximum entropy with high chi-square uniformity → likely encrypted or truly random
            let conf = if chi_square > 200.0 && chi_square < 310.0 {
                95_u8
            } else {
                80
            };
            return (
                CompressionFormat::HighEntropyUnknown,
                conf,
                format!(
                    "Entropy={entropy:.3} (very high), chi2={chi_square:.1} — encrypted or CSPRNG output"
                ),
            );
        }

        if entropy >= 7.0 {
            // High entropy, possibly Brotli or another format without clear magic
            let conf = if chi_square > 180.0 { 75_u8 } else { 60 };
            return (
                CompressionFormat::Brotli,
                conf,
                format!(
                    "Entropy={entropy:.3} in [7.0,7.9) — possible Brotli (no magic bytes)"
                ),
            );
        }

        if entropy >= self.entropy_threshold {
            // Moderate-high entropy — likely compressed but format unknown
            let conf = casts::f64_to_u8(f64::from((entropy - self.entropy_threshold) / (7.0 - self.entropy_threshold))
                * 60.0);
            return (
                CompressionFormat::HighEntropyUnknown,
                conf.clamp(30, 70),
                format!(
                    "Entropy={entropy:.3} above threshold={:.1}, no magic matched",
                    self.entropy_threshold
                ),
            );
        }

        // Low entropy — not compressed
        (
            CompressionFormat::NotCompressed,
            95,
            format!("Entropy={entropy:.3} below threshold={:.1}", self.entropy_threshold),
        )
    }
}

// ─── Chi-Square Test ──────────────────────────────────────────────────────────

/// Perform a chi-square goodness-of-fit test for uniformity.
///
/// Returns `(chi2_statistic, p_value_approx)`.
/// The approximated p-value uses Wilson–Hilferty transform for df=255.
#[must_use]
pub fn chi_square_uniformity_test(data: &[u8]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0);
    }
    let hist = ByteHistogram::new(data);
    let chi2 = hist.chi_square_statistic();
    // Wilson-Hilferty approximation for chi2 CDF with df=255.
    let df = 255.0_f64;
    let z = ((chi2 / df).cbrt() - (1.0 - 2.0 / (9.0 * df)))
        / (2.0 / (9.0 * df)).sqrt();
    // Normal CDF approximation.
    let p_approx = normal_cdf(z);
    (chi2, 1.0 - p_approx)
}

/// Approximate the standard normal CDF using the Abramowitz and Stegun method.
fn normal_cdf(z: f64) -> f64 {
    if z < -8.0 {
        return 0.0;
    }
    if z > 8.0 {
        return 1.0;
    }
    let t = 1.0 / 0.231_641_9_f64.mul_add(z.abs(), 1.0);
    let poly = t * (0.319_381_53
        + t * (-0.356_563_782
            + t * (1.781_477_937 + t * (-1.821_255_978 + t * 1.330_274_429))));
    let phi = 1.0 / (2.0 * std::f64::consts::PI).sqrt() * (-z * z / 2.0).exp() * poly;
    if z >= 0.0 { 1.0 - phi } else { phi }
}

// ─── EntropyProfile ──────────────────────────────────────────────────────────

/// Entropy profile for a buffer: overall, per-chunk, min/max/stddev.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyProfile {
    /// Overall entropy of the buffer.
    pub overall: f32,
    /// Entropy of each fixed-size chunk.
    pub chunk_entropies: Vec<f32>,
    /// Minimum chunk entropy.
    pub min_chunk: f32,
    /// Maximum chunk entropy.
    pub max_chunk: f32,
    /// Mean chunk entropy.
    pub mean_chunk: f32,
    /// Standard deviation of chunk entropies.
    pub stddev_chunk: f32,
    /// Number of chunks with entropy >= 6.5.
    pub high_entropy_chunks: usize,
    /// Chunk size used.
    pub chunk_size: usize,
}

impl EntropyProfile {
    /// Build an entropy profile from `data` using `chunk_size`-byte chunks.
    #[must_use]
    pub fn build(data: &[u8], chunk_size: usize) -> Self {
        let overall = shannon_entropy_f32(data);
        let chunk_size = chunk_size.max(1);
        let chunk_entropies: Vec<f32> = data
            .chunks(chunk_size)
            .map(shannon_entropy_f32)
            .collect();

        let (min_chunk, max_chunk) = chunk_entropies
            .iter()
            .copied()
            .fold((f32::MAX, f32::MIN), |(mn, mx), e| (mn.min(e), mx.max(e)));

        let min_chunk = if chunk_entropies.is_empty() { 0.0 } else { min_chunk };
        let max_chunk = if chunk_entropies.is_empty() { 0.0 } else { max_chunk };

        let mean_chunk = if chunk_entropies.is_empty() {
            0.0
        } else {
            chunk_entropies.iter().sum::<f32>() / casts::usize_to_f32(chunk_entropies.len())
        };

        let stddev_chunk = if chunk_entropies.len() < 2 {
            0.0
        } else {
            let variance = chunk_entropies
                .iter()
                .map(|&e| (e - mean_chunk).powi(2))
                .sum::<f32>()
                / casts::usize_to_f32(chunk_entropies.len() - 1);
            variance.sqrt()
        };

        let high_entropy_chunks = chunk_entropies.iter().filter(|&&e| e >= 6.5).count();

        Self {
            overall,
            chunk_entropies,
            min_chunk,
            max_chunk,
            mean_chunk,
            stddev_chunk,
            high_entropy_chunks,
            chunk_size,
        }
    }

    /// Fraction of chunks with entropy >= 6.5.
    #[must_use]
    pub fn high_entropy_fraction(&self) -> f32 {
        if self.chunk_entropies.is_empty() {
            return 0.0;
        }
        casts::usize_to_f32(self.high_entropy_chunks) / casts::usize_to_f32(self.chunk_entropies.len())
    }

    /// Returns `true` if more than half the chunks have entropy >= 6.5.
    #[must_use]
    pub fn is_predominantly_compressed(&self) -> bool {
        self.high_entropy_fraction() > 0.5
    }

    /// Compare this profile with another and return a similarity score 0-100.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> u8 {
        let d_overall = (self.overall - other.overall).abs();
        let d_mean = (self.mean_chunk - other.mean_chunk).abs();
        let d_std = (self.stddev_chunk - other.stddev_chunk).abs();
        let d_hi = (self.high_entropy_fraction() - other.high_entropy_fraction()).abs();

        let score = 100.0
            - d_hi.mul_add(20.0, d_std.mul_add(5.0, d_overall.mul_add(10.0, d_mean * 10.0)))
                .clamp(0.0, 100.0);
        casts::f32_to_u8(score)
    }
}

// ─── Section-level compression analysis ──────────────────────────────────────

/// Describes the compression analysis result for one named section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionCompressionAnalysis {
    /// Section name.
    pub name: String,
    /// Byte offset in the file.
    pub offset: usize,
    /// Section size.
    pub size: usize,
    /// Entropy profile.
    pub profile: EntropyProfile,
    /// Format detection result.
    pub detection: CompressionDetectionResult,
}

/// Analyse named sections for compression.
///
/// `sections` is a list of `(name, offset, size)` tuples referencing `data`.
#[must_use]
pub fn analyse_sections(
    data: &[u8],
    sections: &[(&str, usize, usize)],
    chunk_size: usize,
) -> Vec<SectionCompressionAnalysis> {
    let detector = CompressionDetector::new();
    sections
        .iter()
        .map(|&(name, offset, size)| {
            let end = (offset + size).min(data.len());
            let slice = if offset < data.len() {
                &data[offset..end]
            } else {
                &[]
            };
            let profile = EntropyProfile::build(slice, chunk_size);
            let detection = detector.detect(slice, offset);
            SectionCompressionAnalysis {
                name: name.to_string(),
                offset,
                size,
                profile,
                detection,
            }
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    fn uniform(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }

    // ── Magic detection ───────────────────────────────────────────────────

    #[test]
    fn test_detect_gzip() {
        let data: Vec<u8> = [0x1F, 0x8B, 0x08, 0x00].into_iter().chain(zeros(100)).collect();
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Gzip);
        assert!(d.confidence >= 90);
    }

    #[test]
    fn test_detect_zstd() {
        let data: Vec<u8> = [0x28, 0xB5, 0x2F, 0xFD].into_iter().chain(zeros(100)).collect();
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Zstd);
    }

    #[test]
    fn test_detect_lz4() {
        let data: Vec<u8> = [0x04, 0x22, 0x4D, 0x18].into_iter().chain(zeros(100)).collect();
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Lz4);
    }

    #[test]
    fn test_detect_bzip2() {
        let mut data = b"BZh9".to_vec();
        data.extend(zeros(100));
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Bzip2);
    }

    #[test]
    fn test_detect_zlib_9c() {
        let mut data = vec![0x78, 0x9C];
        data.extend(zeros(100));
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Zlib);
    }

    #[test]
    fn test_detect_xz() {
        let data: Vec<u8> = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00].into_iter().chain(zeros(100)).collect();
        let d = CompressionDetector::new().detect(&data, 0);
        assert_eq!(d.format, CompressionFormat::Xz);
    }

    // ── Entropy-based fallback ────────────────────────────────────────────

    #[test]
    fn test_detect_not_compressed_zeros() {
        let d = CompressionDetector::new().detect(&zeros(512), 0);
        assert_eq!(d.format, CompressionFormat::NotCompressed);
        assert!((d.entropy - (0.0)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_high_entropy_uniform() {
        let d = CompressionDetector::new().detect(&uniform(1024), 0);
        assert!(d.format == CompressionFormat::HighEntropyUnknown || d.format == CompressionFormat::Brotli);
        assert!(d.entropy > 7.9);
    }

    // ── scan_chunks ───────────────────────────────────────────────────────

    #[test]
    fn test_scan_chunks_count() {
        let data = zeros(1024);
        let results = CompressionDetector::new().scan_chunks(&data, 256);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_scan_chunks_offsets() {
        let data = zeros(512);
        let results = CompressionDetector::new().scan_chunks(&data, 256);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 256);
    }

    #[test]
    fn test_find_compressed_regions_none() {
        let data = zeros(1024);
        let regions = CompressionDetector::new().find_compressed_regions(&data, 256);
        assert!(regions.is_empty());
    }

    // ── Chi-square test ───────────────────────────────────────────────────

    #[test]
    fn test_chi_square_zeros() {
        let (chi2, _p) = chi_square_uniformity_test(&zeros(1024));
        // All counts in one bin → huge chi-square
        assert!(chi2 > 10000.0);
    }

    #[test]
    fn test_chi_square_uniform() {
        // One of each byte → perfect uniform → chi2 == 0
        let data: Vec<u8> = (0u8..=255).collect();
        let (chi2, _p) = chi_square_uniformity_test(&data);
        assert!(chi2 < 1.0);
    }

    #[test]
    fn test_chi_square_empty() {
        let (chi2, p) = chi_square_uniformity_test(&[]);
        assert!((chi2 - (0.0)).abs() < f64::EPSILON);
        assert!((p - 1.0).abs() < 1e-6);
    }

    // ── EntropyProfile ────────────────────────────────────────────────────

    #[test]
    fn test_entropy_profile_zeros() {
        let p = EntropyProfile::build(&zeros(1024), 256);
        assert!((p.overall - (0.0)).abs() < f32::EPSILON);
        assert!((p.min_chunk - (0.0)).abs() < f32::EPSILON);
        assert!((p.max_chunk - (0.0)).abs() < f32::EPSILON);
        assert_eq!(p.high_entropy_chunks, 0);
    }

    #[test]
    fn test_entropy_profile_uniform() {
        let p = EntropyProfile::build(&uniform(1024), 256);
        assert!(p.overall > 7.9);
        assert_eq!(p.high_entropy_chunks, p.chunk_entropies.len());
    }

    #[test]
    fn test_entropy_profile_similarity_same() {
        let p1 = EntropyProfile::build(&uniform(512), 128);
        let p2 = EntropyProfile::build(&uniform(512), 128);
        assert_eq!(p1.similarity(&p2), 100);
    }

    #[test]
    fn test_entropy_profile_is_predominantly_compressed() {
        let p = EntropyProfile::build(&uniform(1024), 256);
        assert!(p.is_predominantly_compressed());
        let p2 = EntropyProfile::build(&zeros(1024), 256);
        assert!(!p2.is_predominantly_compressed());
    }

    // ── Section analysis ──────────────────────────────────────────────────

    #[test]
    fn test_analyse_sections() {
        let data: Vec<u8> = zeros(256).into_iter().chain(uniform(256)).collect();
        let sections = [(".bss", 0usize, 256usize), (".data", 256, 256)];
        let results = analyse_sections(&data, &sections, 64);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].detection.format, CompressionFormat::NotCompressed);
    }

    // ── CompressionFormat ─────────────────────────────────────────────────

    #[test]
    fn test_format_label() {
        assert_eq!(CompressionFormat::Gzip.label(), "GZIP");
        assert_eq!(CompressionFormat::NotCompressed.label(), "NotCompressed");
    }

    #[test]
    fn test_format_is_compressed_or_encrypted() {
        assert!(CompressionFormat::Lz4.is_compressed_or_encrypted());
        assert!(!CompressionFormat::NotCompressed.is_compressed_or_encrypted());
    }

    #[test]
    fn test_format_display() {
        assert_eq!(CompressionFormat::Zstd.to_string(), "Zstandard");
    }

    // ── CompressionDetectionResult ────────────────────────────────────────

    #[test]
    fn test_detection_result_likely_compressed_high_confidence() {
        let r = CompressionDetectionResult {
            format: CompressionFormat::Gzip,
            entropy: 7.8,
            chi_square: 255.0,
            is_chi_square_uniform: true,
            offset: 0,
            size: 1024,
            confidence: 98,
            reason: "magic".into(),
        };
        assert!(r.likely_compressed());
    }

    #[test]
    fn test_detection_result_not_compressed() {
        let r = CompressionDetectionResult {
            format: CompressionFormat::NotCompressed,
            entropy: 0.0,
            chi_square: 0.0,
            is_chi_square_uniform: false,
            offset: 0,
            size: 256,
            confidence: 95,
            reason: "zero entropy".into(),
        };
        assert!(!r.likely_compressed());
    }

    #[test]
    fn test_detection_result_display() {
        let r = CompressionDetectionResult {
            format: CompressionFormat::Zlib,
            entropy: 7.5,
            chi_square: 260.0,
            is_chi_square_uniform: true,
            offset: 0,
            size: 512,
            confidence: 90,
            reason: "ZLIB header".into(),
        };
        let s = r.to_string();
        assert!(s.contains("ZLIB"));
        assert!(s.contains("7.5"));
    }
}
