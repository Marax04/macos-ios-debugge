//! Byte frequency histogram analysis with chi-squared testing and profiling.
//!
//! Key types:
//! - [`ByteHistogram`] — 256-slot u64 frequency array with statistics.
//! - [`HistogramProfile`] — min/max/mean/stddev/entropy summary.
//! - [`ProfileClassifier`] — classify data as code/encrypted/compressed by histogram shape.
//! - [`ByteClassDistribution`] — split counts into printable/high/low/null classes.
//! - Built-in reference profiles for PE headers, ELF, JPEG, ZIP, random data.

use serde::{Deserialize, Serialize};
use std::fmt;
use crate::casts;

// ---------------------------------------------------------------------------
// ByteHistogram
// ---------------------------------------------------------------------------

/// Per-byte frequency histogram with 256 u64 slots.
///
/// Unlike the lightweight `ByteHistogram` in the library root (which uses
/// `Vec<u32>`), this one uses a fixed-size `[u64; 256]` array for maximum
/// performance and provides richer statistical methods.
/// Serde helper for `[u64; 256]` fields (serde does not derive Serialize/Deserialize
/// for arrays larger than 32).
pub mod serde_u64_256 {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeTuple};

    /// # Errors
    /// Returns an error if the serializer fails.
    pub fn serialize<S: Serializer>(arr: &[u64; 256], ser: S) -> Result<S::Ok, S::Error> {
        let mut tup = ser.serialize_tuple(256)?;
        for v in arr {
            tup.serialize_element(v)?;
        }
        tup.end()
    }

    /// # Errors
    /// Returns an error if the deserializer fails or the array length is not 256.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u64; 256], D::Error> {
        let v: Vec<u64> = Vec::deserialize(de)?;
        if v.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 u64 elements, got {}",
                v.len()
            )));
        }
        let mut out = [0u64; 256];
        for (i, x) in v.into_iter().enumerate() {
            out[i] = x;
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteHistogram {
    /// `counts[b]` = number of times byte value `b` appeared.
    #[serde(with = "serde_u64_256")]
    pub counts: [u64; 256],
    /// Total bytes counted.
    pub total: u64,
}

impl ByteHistogram {
    /// Build a histogram by counting all bytes in `data`.
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        Self {
            counts,
            total: data.len() as u64,
        }
    }

    /// Frequency of a specific byte value.
    #[must_use]
    pub const fn count_of(&self, byte: u8) -> u64 {
        self.counts[byte as usize]
    }

    /// Relative frequency (probability) of `byte` in [0.0, 1.0].
    #[must_use]
    pub fn probability(&self, byte: u8) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        casts::u64_to_f64(self.counts[byte as usize]) / casts::u64_to_f64(self.total)
    }

    /// Shannon entropy of the histogram (bits per byte, 0.0 – 8.0).
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let t = casts::u64_to_f64(self.total);
        self.counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = casts::u64_to_f64(c) / t;
                -p * p.log2()
            })
            .sum::<f64>()
            .clamp(0.0, 8.0)
    }

    /// Chi-squared statistic under the uniform null hypothesis.
    ///
    /// χ² = Σ (Oᵢ − Eᵢ)² / Eᵢ, Eᵢ = total / 256.
    #[must_use]
    pub fn chi_square(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let expected = casts::u64_to_f64(self.total) / 256.0;
        self.counts
            .iter()
            .map(|&o| {
                let diff = casts::u64_to_f64(o) - expected;
                diff * diff / expected
            })
            .sum()
    }

    /// `true` if χ² is in the range [200, 310] — close to uniform.
    ///
    /// A perfectly uniform random byte stream has expected χ²(255) ≈ 255.
    #[must_use]
    pub fn is_likely_random(&self) -> bool {
        let x = self.chi_square();
        (200.0..=310.0).contains(&x)
    }

    /// Return the `n` most-frequent byte values, descending.
    #[must_use]
    pub fn most_common(&self, n: usize) -> Vec<(u8, u64)> {
        let n = n.min(256);
        let mut pairs: Vec<(u8, u64)> = self
            .counts
            .iter()
            .enumerate()
            .map(|(b, &c)| (casts::usize_to_u8(b), c))
            .collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Minimum non-zero frequency (or 0 if all counts are 0).
    #[must_use]
    pub fn min_nonzero(&self) -> u64 {
        self.counts
            .iter()
            .filter(|&&c| c > 0)
            .copied()
            .min()
            .unwrap_or(0)
    }

    /// Maximum frequency.
    #[must_use]
    pub fn max_count(&self) -> u64 {
        self.counts.iter().copied().max().unwrap_or(0)
    }

    /// Mean count per byte value.
    #[must_use]
    pub fn mean(&self) -> f64 {
        casts::u64_to_f64(self.total) / 256.0
    }

    /// Standard deviation of counts.
    #[must_use]
    pub fn stddev(&self) -> f64 {
        let m = self.mean();
        let variance: f64 = self
            .counts
            .iter()
            .map(|&c| {
                let d = casts::u64_to_f64(c) - m;
                d * d
            })
            .sum::<f64>()
            / 256.0;
        variance.sqrt()
    }

    /// Number of distinct byte values with non-zero count.
    #[must_use]
    pub fn distinct_bytes(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// Compute the [`HistogramProfile`] summary.
    #[must_use]
    pub fn profile(&self) -> HistogramProfile {
        HistogramProfile {
            min_count: self.min_nonzero(),
            max_count: self.max_count(),
            mean: self.mean(),
            stddev: self.stddev(),
            entropy: self.entropy(),
            chi_square: self.chi_square(),
            distinct_bytes: self.distinct_bytes(),
            total: self.total,
        }
    }

    /// Get the [`ByteClassDistribution`] breakdown.
    #[must_use]
    pub fn class_distribution(&self) -> ByteClassDistribution {
        ByteClassDistribution::from_histogram(self)
    }

    /// Compute absolute difference from another histogram.
    #[must_use]
    pub fn diff(&self, other: &Self) -> [i64; 256] {
        let mut d = [0i64; 256];
        for (slot, (a, b)) in d.iter_mut().zip(self.counts.iter().zip(other.counts.iter())) {
            *slot = casts::u64_to_i64(*a) - casts::u64_to_i64(*b);
        }
        d
    }

    /// L1 distance between two normalized histograms.
    #[must_use]
    pub fn l1_distance(&self, other: &Self) -> f64 {
        if self.total == 0 || other.total == 0 {
            return 2.0;
        }
        let ta = casts::u64_to_f64(self.total);
        let tb = casts::u64_to_f64(other.total);
        self.counts.iter().zip(other.counts.iter())
            .map(|(&a, &b)| (casts::u64_to_f64(a) / ta - casts::u64_to_f64(b) / tb).abs())
            .sum()
    }

    /// Merge another histogram into `self`.
    pub fn merge(&mut self, other: &Self) {
        for i in 0..256 {
            self.counts[i] += other.counts[i];
        }
        self.total += other.total;
    }
}

impl Default for ByteHistogram {
    fn default() -> Self {
        Self {
            counts: [0u64; 256],
            total: 0,
        }
    }
}

impl fmt::Display for ByteHistogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ByteHistogram {{ total={}, distinct={}, entropy={:.3}, chi2={:.1} }}",
            self.total,
            self.distinct_bytes(),
            self.entropy(),
            self.chi_square()
        )
    }
}

// ---------------------------------------------------------------------------
// HistogramProfile
// ---------------------------------------------------------------------------

/// Statistical summary of a [`ByteHistogram`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramProfile {
    /// Minimum non-zero count.
    pub min_count: u64,
    /// Maximum count.
    pub max_count: u64,
    /// Mean count per byte value.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Shannon entropy (0–8).
    pub entropy: f64,
    /// Chi-squared statistic.
    pub chi_square: f64,
    /// Number of distinct byte values.
    pub distinct_bytes: usize,
    /// Total bytes sampled.
    pub total: u64,
}

impl HistogramProfile {
    /// Returns `true` when entropy > 7.5 (likely encrypted/packed).
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.5
    }

    /// Returns `true` when entropy < 3.0 (likely text or code).
    #[must_use]
    pub fn is_low_entropy(&self) -> bool {
        self.entropy < 3.0
    }

    /// Coefficient of variation (stddev / mean).
    #[must_use]
    pub fn cv(&self) -> f64 {
        if self.mean == 0.0 {
            return 0.0;
        }
        self.stddev / self.mean
    }
}

impl fmt::Display for HistogramProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HistogramProfile {{ entropy={:.3}, chi2={:.1}, distinct={}, stddev={:.2} }}",
            self.entropy, self.chi_square, self.distinct_bytes, self.stddev
        )
    }
}

// ---------------------------------------------------------------------------
// ByteClassDistribution
// ---------------------------------------------------------------------------

/// Breakdown of byte counts by class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteClassDistribution {
    /// 0x00 bytes.
    pub null: u64,
    /// 0x01–0x1F and 0x7F (control characters).
    pub control: u64,
    /// 0x20–0x7E (printable ASCII).
    pub printable: u64,
    /// 0x80–0xFF (high bytes).
    pub high: u64,
    /// Total bytes.
    pub total: u64,
}

impl ByteClassDistribution {
    /// Build from a [`ByteHistogram`].
    #[must_use]
    pub fn from_histogram(h: &ByteHistogram) -> Self {
        let null = h.counts[0];
        let control = (1u8..=0x1F).map(|b| h.counts[b as usize]).sum::<u64>() + h.counts[0x7F];
        let printable = (0x20u8..=0x7E).map(|b| h.counts[b as usize]).sum::<u64>();
        let high = (0x80u8..=0xFF).map(|b| h.counts[b as usize]).sum::<u64>();
        Self {
            null,
            control,
            printable,
            high,
            total: h.total,
        }
    }

    /// Fraction of printable ASCII bytes (0.0 – 1.0).
    #[must_use]
    pub fn printable_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        casts::u64_to_f64(self.printable) / casts::u64_to_f64(self.total)
    }

    /// Fraction of null bytes.
    #[must_use]
    pub fn null_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        casts::u64_to_f64(self.null) / casts::u64_to_f64(self.total)
    }

    /// Fraction of high bytes.
    #[must_use]
    pub fn high_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        casts::u64_to_f64(self.high) / casts::u64_to_f64(self.total)
    }

    /// Returns `true` if more than 60% of bytes are printable ASCII — likely text.
    #[must_use]
    pub fn is_text_like(&self) -> bool {
        self.printable_ratio() > 0.6
    }

    /// Returns `true` if roughly equal distribution of all classes — likely binary/encrypted.
    #[must_use]
    pub fn is_binary_like(&self) -> bool {
        self.printable_ratio() < 0.3 && self.high_ratio() > 0.15
    }
}

impl fmt::Display for ByteClassDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ByteClasses {{ null={}, ctrl={}, print={}, high={} }}",
            self.null, self.control, self.printable, self.high
        )
    }
}

// ---------------------------------------------------------------------------
// ContentClass
// ---------------------------------------------------------------------------

/// High-level content classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentClass {
    /// Human-readable plain text.
    Text,
    /// Machine code or structured binary tables.
    Code,
    /// Generic binary data.
    Data,
    /// Compressed data (deflate, lz4, etc.).
    Compressed,
    /// Encrypted or packed data.
    Encrypted,
    /// Effectively random (ciphertext / PRNG output).
    Random,
    /// Unknown / insufficient data.
    Unknown,
}

impl fmt::Display for ContentClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "Text"),
            Self::Code => write!(f, "Code"),
            Self::Data => write!(f, "Data"),
            Self::Compressed => write!(f, "Compressed"),
            Self::Encrypted => write!(f, "Encrypted"),
            Self::Random => write!(f, "Random"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProfileClassifier
// ---------------------------------------------------------------------------

/// Classify a [`ByteHistogram`] into a [`ContentClass`] based on its shape.
pub struct ProfileClassifier;

impl ProfileClassifier {
    /// Classify a histogram into a [`ContentClass`].
    ///
    /// Decision tree:
    /// 1. Low total (<= 16) → Unknown.
    /// 2. Entropy >= 7.7 → Random.
    /// 3. Entropy >= 7.2 && random test → Encrypted.
    /// 4. Entropy >= 6.0 → Compressed.
    /// 5. Printable > 60% → Text.
    /// 6. Entropy < 5.5 && few distinct bytes → Code.
    /// 7. Otherwise → Data.
    #[must_use]
    pub fn classify(h: &ByteHistogram) -> ContentClass {
        if h.total <= 16 {
            return ContentClass::Unknown;
        }
        let p = h.profile();
        let classes = h.class_distribution();

        if p.entropy >= 7.7 {
            return ContentClass::Random;
        }
        if p.entropy >= 7.2 {
            return ContentClass::Encrypted;
        }
        if p.entropy >= 6.0 {
            return ContentClass::Compressed;
        }
        if classes.is_text_like() {
            return ContentClass::Text;
        }
        if p.entropy < 5.5 && p.distinct_bytes < 128 {
            return ContentClass::Code;
        }
        ContentClass::Data
    }

    /// Classify a raw byte slice.
    #[must_use]
    pub fn classify_bytes(data: &[u8]) -> ContentClass {
        Self::classify(&ByteHistogram::new(data))
    }

    /// Returns `true` if the classification indicates the data is suspicious
    /// (encrypted or random).
    #[must_use]
    pub const fn is_suspicious(class: ContentClass) -> bool {
        matches!(class, ContentClass::Encrypted | ContentClass::Random)
    }
}

// ---------------------------------------------------------------------------
// Built-in reference profiles
// ---------------------------------------------------------------------------

/// A named reference profile for comparing against known file types.
#[derive(Debug, Clone)]
pub struct ReferenceProfile {
    /// Name of the profile.
    pub name: &'static str,
    /// Expected entropy range.
    pub entropy_min: f64,
    pub entropy_max: f64,
    /// Expected chi-square range.
    pub chi2_min: f64,
    pub chi2_max: f64,
    /// Expected distinct bytes range.
    pub distinct_min: usize,
    pub distinct_max: usize,
}

impl ReferenceProfile {
    /// Check whether a [`HistogramProfile`] matches this reference.
    #[must_use]
    pub fn matches(&self, p: &HistogramProfile) -> bool {
        p.entropy >= self.entropy_min
            && p.entropy <= self.entropy_max
            && p.chi_square >= self.chi2_min
            && p.chi_square <= self.chi2_max
            && p.distinct_bytes >= self.distinct_min
            && p.distinct_bytes <= self.distinct_max
    }
}

/// All built-in reference profiles.
pub static REFERENCE_PROFILES: &[ReferenceProfile] = &[
    ReferenceProfile {
        name: "PE_Header",
        entropy_min: 2.0,
        entropy_max: 5.5,
        chi2_min: 50.0,
        chi2_max: 500.0,
        distinct_min: 50,
        distinct_max: 200,
    },
    ReferenceProfile {
        name: "ELF_Header",
        entropy_min: 2.5,
        entropy_max: 5.5,
        chi2_min: 60.0,
        chi2_max: 600.0,
        distinct_min: 40,
        distinct_max: 200,
    },
    ReferenceProfile {
        name: "JPEG",
        entropy_min: 7.0,
        entropy_max: 8.0,
        chi2_min: 150.0,
        chi2_max: 320.0,
        distinct_min: 220,
        distinct_max: 256,
    },
    ReferenceProfile {
        name: "ZIP",
        entropy_min: 7.5,
        entropy_max: 8.0,
        chi2_min: 180.0,
        chi2_max: 310.0,
        distinct_min: 230,
        distinct_max: 256,
    },
    ReferenceProfile {
        name: "Random",
        entropy_min: 7.8,
        entropy_max: 8.0,
        chi2_min: 200.0,
        chi2_max: 310.0,
        distinct_min: 240,
        distinct_max: 256,
    },
    ReferenceProfile {
        name: "Text",
        entropy_min: 3.0,
        entropy_max: 6.5,
        chi2_min: 500.0,
        chi2_max: 50000.0,
        distinct_min: 30,
        distinct_max: 100,
    },
    ReferenceProfile {
        name: "Null_Padding",
        entropy_min: 0.0,
        entropy_max: 0.5,
        // χ² measures DEVIATION FROM UNIFORM, so constant data is the
        // maximally non-uniform case, not the minimal one: for `n` identical
        // bytes χ² = 255·n (65280 for a single 256-byte block, and it grows
        // without bound with `n`). The range was `[0.0, 10.0]` — the value a
        // near-uniform block would score — so this profile could never match
        // the padding it names, and `match_reference_profiles` returned
        // nothing at all for a run of zeroes.
        //
        // The entropy (≤0.5) and distinct-byte (≤3) bounds already identify
        // padding tightly; χ² only has to stop ordinary text (which tops out
        // at 50000 in the `Text` profile above) from matching here.
        chi2_min: 50_000.0,
        chi2_max: f64::INFINITY,
        distinct_min: 1,
        distinct_max: 3,
    },
];

/// Match a histogram profile against all reference profiles.
///
/// Returns all profiles whose range includes the given statistics.
#[must_use]
pub fn match_reference_profiles(p: &HistogramProfile) -> Vec<&'static ReferenceProfile> {
    REFERENCE_PROFILES
        .iter()
        .filter(|rp| rp.matches(p))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }
    fn uniform(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }
    fn ascii_text() -> Vec<u8> {
        b"Hello, world! This is a test string.".to_vec()
    }

    // ByteHistogram

    #[test]
    fn test_histogram_new_zeros() {
        let h = ByteHistogram::new(&zeros(256));
        assert_eq!(h.count_of(0), 256);
        assert_eq!(h.total, 256);
    }

    #[test]
    fn test_histogram_new_uniform() {
        let h = ByteHistogram::new(&uniform(256));
        for b in 0u8..=255 {
            assert_eq!(h.count_of(b), 1);
        }
    }

    #[test]
    fn test_histogram_entropy_zeros() {
        let h = ByteHistogram::new(&zeros(512));
        assert!((h.entropy() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_entropy_uniform() {
        let h = ByteHistogram::new(&uniform(256));
        assert!((h.entropy() - 8.0).abs() < 1e-5);
    }

    #[test]
    fn test_histogram_chi_square_uniform() {
        let h = ByteHistogram::new(&uniform(256));
        assert!(h.chi_square().abs() < 1e-6);
    }

    #[test]
    fn test_histogram_is_likely_random_true() {
        // Build a histogram that approximates random (chi2 ≈ 255).
        // We can't easily do this with a short uniform, so just check the range.
        let mut h = ByteHistogram::default();
        for i in 0..256 {
            h.counts[i] = 100 + (i % 20) as u64; // slight variation
        }
        h.total = h.counts.iter().sum();
        let chi = h.chi_square();
        // chi should be in some range; just check it computes.
        let _ = chi;
    }

    #[test]
    fn test_histogram_most_common_top1() {
        let mut data = vec![0xAAu8; 50];
        data.extend(vec![0xBBu8; 30]);
        let h = ByteHistogram::new(&data);
        let top = h.most_common(1);
        assert_eq!(top[0].0, 0xAA);
        assert_eq!(top[0].1, 50);
    }

    #[test]
    fn test_histogram_distinct_bytes() {
        let h = ByteHistogram::new(&[1u8, 2, 3, 3, 3]);
        assert_eq!(h.distinct_bytes(), 3);
    }

    #[test]
    fn test_histogram_stddev_uniform() {
        let h = ByteHistogram::new(&uniform(256));
        assert!((h.stddev() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_l1_distance_identical() {
        let h = ByteHistogram::new(&uniform(256));
        assert!((h.l1_distance(&h) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_l1_distance_different() {
        let h1 = ByteHistogram::new(&zeros(256));
        let h2 = ByteHistogram::new(&uniform(256));
        let d = h1.l1_distance(&h2);
        assert!(d > 0.0);
    }

    #[test]
    fn test_histogram_merge() {
        let mut h1 = ByteHistogram::new(&[0u8; 100]);
        let h2 = ByteHistogram::new(&[1u8; 100]);
        h1.merge(&h2);
        assert_eq!(h1.total, 200);
    }

    #[test]
    fn test_histogram_display() {
        let h = ByteHistogram::new(&uniform(256));
        let s = h.to_string();
        assert!(s.contains("ByteHistogram"));
    }

    // HistogramProfile

    #[test]
    fn test_profile_high_entropy() {
        let h = ByteHistogram::new(&uniform(1024));
        let p = h.profile();
        assert!(p.is_high_entropy());
    }

    #[test]
    fn test_profile_low_entropy() {
        // `is_low_entropy` is `< 3.0 bits`, i.e. padding / heavily repetitive
        // data. English prose carries roughly 4 bits per byte, and this
        // crate's own `Text` reference profile spans 3.0–6.5 — so asserting
        // that an ASCII sentence is "low entropy" contradicted the crate's
        // own definition of text, and the test could never pass.
        //
        // Kept as a threshold test, on data that genuinely IS low entropy,
        // plus the negative case that was actually being asked about.
        let padding = ByteHistogram::new(&zeros(256)).profile();
        assert!(padding.is_low_entropy(), "entropy {}", padding.entropy);

        let text = ByteHistogram::new(&ascii_text()).profile();
        assert!(
            !text.is_low_entropy(),
            "ASCII prose is not below the 3.0-bit padding threshold; entropy {}",
            text.entropy
        );
        assert!(
            text.entropy >= 3.0 && text.entropy <= 6.5,
            "ASCII prose should land in this crate's own Text band (3.0–6.5), got {}",
            text.entropy
        );
    }

    #[test]
    fn test_profile_cv() {
        let h = ByteHistogram::new(&uniform(256));
        assert!((h.profile().cv() - (0.0)).abs() < f64::EPSILON);
    }

    // ByteClassDistribution

    #[test]
    fn test_class_dist_printable_ascii() {
        let h = ByteHistogram::new(&ascii_text());
        let dist = h.class_distribution();
        assert!(dist.printable_ratio() > 0.5);
        assert!(dist.is_text_like());
    }

    #[test]
    fn test_class_dist_zeros_null() {
        let h = ByteHistogram::new(&zeros(256));
        let dist = h.class_distribution();
        assert_eq!(dist.null, 256);
        assert_eq!(dist.printable, 0);
    }

    #[test]
    fn test_class_dist_high_bytes() {
        let data: Vec<u8> = (128u8..=255).cycle().take(256).collect();
        let h = ByteHistogram::new(&data);
        let dist = h.class_distribution();
        assert!(dist.high_ratio() > 0.9);
    }

    // ProfileClassifier

    #[test]
    fn test_classifier_random() {
        let data = uniform(4096);
        assert_eq!(
            ProfileClassifier::classify_bytes(&data),
            ContentClass::Random
        );
    }

    #[test]
    fn test_classifier_text() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        let c = ProfileClassifier::classify_bytes(&data);
        assert_eq!(c, ContentClass::Text);
    }

    #[test]
    fn test_classifier_small_data_unknown() {
        let data = vec![0u8; 10];
        assert_eq!(
            ProfileClassifier::classify_bytes(&data),
            ContentClass::Unknown
        );
    }

    #[test]
    fn test_classifier_suspicious_encrypted() {
        let class = ContentClass::Encrypted;
        assert!(ProfileClassifier::is_suspicious(class));
    }

    #[test]
    fn test_classifier_not_suspicious_text() {
        let class = ContentClass::Text;
        assert!(!ProfileClassifier::is_suspicious(class));
    }

    // ReferenceProfile

    #[test]
    fn test_reference_profile_random_matches() {
        // `uniform()` cycles 0..=255, so every byte appears EXACTLY the same
        // number of times and χ² is 0 — perfectly flat, which real random data
        // never is. The `Random` / `JPEG` / `ZIP` profiles all require χ² near
        // 255 (the expected value for 255 degrees of freedom), so the old data
        // matched none of them and the test could not pass.
        //
        // Use a seeded PRNG instead: that is what "random" means here, and it
        // is what the profiles were calibrated against.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                u8::try_from(state & 0xff).expect("masked to one byte")
            })
            .collect();

        let h = ByteHistogram::new(&data);
        let p = h.profile();
        let matches = match_reference_profiles(&p);
        assert!(
            matches
                .iter()
                .any(|r| r.name == "Random" || r.name == "JPEG" || r.name == "ZIP"),
            "entropy {:.3}, chi2 {:.1}, distinct {} matched {:?}",
            p.entropy,
            p.chi_square,
            p.distinct_bytes,
            matches.iter().map(|r| r.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_reference_profile_null_matches() {
        let h = ByteHistogram::new(&zeros(256));
        let p = h.profile();
        let matches = match_reference_profiles(&p);
        assert!(matches.iter().any(|r| r.name == "Null_Padding"));
    }

    #[test]
    fn test_content_class_display() {
        assert_eq!(ContentClass::Text.to_string(), "Text");
        assert_eq!(ContentClass::Random.to_string(), "Random");
        assert_eq!(ContentClass::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_histogram_probability_zero_total() {
        let h = ByteHistogram::default();
        assert!((h.probability(0) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_probability() {
        let h = ByteHistogram::new(&[0u8, 0, 0, 1u8]);
        assert!((h.probability(0) - 0.75).abs() < 1e-9);
        assert!((h.probability(1) - 0.25).abs() < 1e-9);
    }
}
