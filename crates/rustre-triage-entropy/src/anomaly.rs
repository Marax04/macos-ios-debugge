//! Anomaly detection for binary files using entropy and byte-histogram analysis.
//!
//! The main entry point is [`detect_anomalies`], which combines Shannon entropy
//! and chi-squared tests to flag suspicious regions within binary data.

use serde::{Deserialize, Serialize};

use crate::byte_histogram::ByteHistogram;
use crate::shannon::{BlockClass, entropy_per_block};
use crate::casts;

// ─────────────────────────────────────────────────────────────────────────────
// AnomalyKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// A region with very high Shannon entropy, indicative of packed or
    /// encrypted content.
    HighEntropy,
    /// A region with very low entropy (near-zero), indicative of zeroed-out
    /// data, padding, or partially wiped sections.
    LowEntropy,
    /// Chi-squared test passed with a low statistic — byte distribution is
    /// too uniform, suggesting encrypted/random content.
    UniformDistribution,
    /// Chi-squared test produced a very high statistic — byte distribution is
    /// extremely biased or structured in an unusual way.
    BiasedDistribution,
    /// An unusually high proportion of null bytes, common in shellcode stubs
    /// or encrypted sections with NULL key bytes.
    HighNullDensity,
    /// An unusually low proportion of printable ASCII bytes for a region
    /// claimed or expected to contain text.
    LowPrintability,
    /// A combination of entropy and chi-squared signals strongly suggests
    /// an encrypted payload.
    LikelyEncrypted,
    /// A combination of entropy and chi-squared signals strongly suggests
    /// a compressed payload.
    LikelyCompressed,
    /// Overall file-level entropy anomaly (applied to the whole file).
    FileEntropy,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighEntropy => write!(f, "HighEntropy"),
            Self::LowEntropy => write!(f, "LowEntropy"),
            Self::UniformDistribution => write!(f, "UniformDistribution"),
            Self::BiasedDistribution => write!(f, "BiasedDistribution"),
            Self::HighNullDensity => write!(f, "HighNullDensity"),
            Self::LowPrintability => write!(f, "LowPrintability"),
            Self::LikelyEncrypted => write!(f, "LikelyEncrypted"),
            Self::LikelyCompressed => write!(f, "LikelyCompressed"),
            Self::FileEntropy => write!(f, "FileEntropy"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anomaly
// ─────────────────────────────────────────────────────────────────────────────

/// A single detected anomaly in binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Classification of this anomaly.
    pub kind: AnomalyKind,
    /// Byte offset of the anomalous region (or `0` for file-level anomalies).
    pub offset: usize,
    /// Length of the anomalous region in bytes.
    pub length: usize,
    /// Shannon entropy of the anomalous region.
    pub entropy: f64,
    /// Chi-squared statistic of the byte distribution in this region.
    pub chi_squared: f64,
    /// Confidence score from 0 to 100.
    pub confidence: u8,
    /// Human-readable explanation.
    pub description: String,
}

impl Anomaly {
    /// Returns `true` if this anomaly indicates likely malicious or obfuscated content.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        matches!(
            self.kind,
            AnomalyKind::HighEntropy
                | AnomalyKind::UniformDistribution
                | AnomalyKind::LikelyEncrypted
                | AnomalyKind::LikelyCompressed
        )
    }

    /// Returns `true` if this anomaly is file-level (not region-specific).
    #[must_use]
    pub fn is_file_level(&self) -> bool {
        self.kind == AnomalyKind::FileEntropy
    }
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] +0x{:08X} len={} entropy={:.3} chi²={:.1} conf={}% — {}",
            self.kind,
            self.offset,
            self.length,
            self.entropy,
            self.chi_squared,
            self.confidence,
            self.description,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for anomaly detection thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Block size for per-block analysis (default: 4096).
    pub block_size: usize,
    /// Entropy above this is flagged `HighEntropy` (default: 7.0).
    pub high_entropy_threshold: f64,
    /// Entropy below this is flagged `LowEntropy` (default: 0.5).
    pub low_entropy_threshold: f64,
    /// Chi-squared normalised below this → `UniformDistribution` (default: 0.1).
    pub uniform_chi2_threshold: f64,
    /// Chi-squared normalised above this → `BiasedDistribution` (default: 100.0).
    pub biased_chi2_threshold: f64,
    /// Null byte ratio above this → `HighNullDensity` (default: 0.60).
    pub high_null_threshold: f64,
    /// Printable ratio below this → `LowPrintability` (default: 0.10).
    pub low_printable_threshold: f64,
    /// Minimum confidence (0–100) for a block anomaly to be emitted (default: 50).
    pub min_confidence: u8,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            high_entropy_threshold: 7.0,
            low_entropy_threshold: 0.5,
            uniform_chi2_threshold: 0.1,
            biased_chi2_threshold: 100.0,
            high_null_threshold: 0.60,
            low_printable_threshold: 0.10,
            min_confidence: 50,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_anomalies
// ─────────────────────────────────────────────────────────────────────────────

/// Run anomaly detection on `data` using the provided `config`.
///
/// Analysis proceeds in three phases:
/// 1. **File-level** — overall entropy and histogram.
/// 2. **Block-level** — per-block entropy and histogram (`config.block_size`).
/// 3. **Classification** — rule-based classification combining entropy and
///    chi-squared into specific [`AnomalyKind`] labels.
///
/// Returns a (possibly empty) list of detected [`Anomaly`] entries.
#[must_use]
pub fn detect_anomalies(data: &[u8], config: &DetectionConfig) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if data.is_empty() {
        return anomalies;
    }

    // ── Phase 1: file-level ────────────────────────────────────────────────

    let file_hist = ByteHistogram::from_bytes(data);
    let file_entropy = crate::shannon_entropy(data);
    let file_chi2_norm = file_hist.chi_squared_normalised();

    // File-level high entropy
    if file_entropy >= config.high_entropy_threshold {
        let kind = if file_chi2_norm < config.uniform_chi2_threshold {
            AnomalyKind::LikelyEncrypted
        } else {
            AnomalyKind::FileEntropy
        };
        let confidence = entropy_confidence(file_entropy, config.high_entropy_threshold, 8.0);
        if confidence >= config.min_confidence {
            anomalies.push(Anomaly {
                kind,
                offset: 0,
                length: data.len(),
                entropy: file_entropy,
                chi_squared: file_hist.chi_squared(),
                confidence,
                description: format!(
                    "File-level entropy {file_entropy:.3} bits (threshold {:.1})",
                    config.high_entropy_threshold
                ),
            });
        }
    }

    // ── Phase 2: block-level ───────────────────────────────────────────────

    let block_analysis = entropy_per_block(data, config.block_size);
    detect_block_anomalies(data, &block_analysis.blocks, config, &mut anomalies);

    // Sort by offset then by confidence descending
    anomalies.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(b.confidence.cmp(&a.confidence))
    });

    anomalies
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn detect_block_anomalies(
    data: &[u8],
    blocks: &[crate::shannon::BlockEntropy],
    config: &DetectionConfig,
    anomalies: &mut Vec<Anomaly>,
) {
    for block in blocks {
        let block_data = {
            let end = (block.offset + block.size).min(data.len());
            &data[block.offset..end]
        };
        if block_data.is_empty() {
            continue;
        }
        let hist = ByteHistogram::from_bytes(block_data);
        let chi2_norm = hist.chi_squared_normalised();
        let null_ratio = hist.null_ratio();
        let printable = hist.printable_ratio();

        if block.entropy >= config.high_entropy_threshold {
            let kind = classify_high_entropy_block(block.entropy, chi2_norm, config);
            let confidence = entropy_confidence(block.entropy, config.high_entropy_threshold, 8.0);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind, offset: block.offset, length: block.size, entropy: block.entropy,
                    chi_squared: hist.chi_squared(), confidence,
                    description: format!("Block entropy {:.3} bits at offset 0x{:X}", block.entropy, block.offset),
                });
            }
        }
        if block.entropy < config.low_entropy_threshold && block.class == BlockClass::Zeroed {
            let confidence = low_entropy_confidence(block.entropy, config.low_entropy_threshold);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::LowEntropy, offset: block.offset, length: block.size,
                    entropy: block.entropy, chi_squared: hist.chi_squared(), confidence,
                    description: format!("Very low entropy {:.3} bits (likely zeroed/padding) at offset 0x{:X}", block.entropy, block.offset),
                });
            }
        }
        if chi2_norm < config.uniform_chi2_threshold && block.entropy > 5.0 {
            let confidence = casts::f64_to_u8((1.0 - chi2_norm / config.uniform_chi2_threshold) * 80.0);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::UniformDistribution, offset: block.offset, length: block.size,
                    entropy: block.entropy, chi_squared: hist.chi_squared(), confidence,
                    description: format!("Uniform byte distribution (chi²_norm={chi2_norm:.4}) at offset 0x{:X}", block.offset),
                });
            }
        }
        if chi2_norm > config.biased_chi2_threshold {
            let confidence = casts::f64_to_u8((chi2_norm / (config.biased_chi2_threshold * 2.0)).min(1.0) * 70.0);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::BiasedDistribution, offset: block.offset, length: block.size,
                    entropy: block.entropy, chi_squared: hist.chi_squared(), confidence,
                    description: format!("Extremely biased byte distribution (chi²_norm={chi2_norm:.1}) at offset 0x{:X}", block.offset),
                });
            }
        }
        if null_ratio >= config.high_null_threshold {
            let confidence = casts::f64_to_u8((null_ratio - config.high_null_threshold) / (1.0 - config.high_null_threshold) * 80.0);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::HighNullDensity, offset: block.offset, length: block.size,
                    entropy: block.entropy, chi_squared: hist.chi_squared(), confidence,
                    description: format!("High null density {:.1}% at offset 0x{:X}", null_ratio * 100.0, block.offset),
                });
            }
        }
        if printable < config.low_printable_threshold && block.entropy > 3.0 {
            let confidence = casts::f64_to_u8((1.0 - printable / config.low_printable_threshold) * 60.0);
            if confidence >= config.min_confidence {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::LowPrintability, offset: block.offset, length: block.size,
                    entropy: block.entropy, chi_squared: hist.chi_squared(), confidence,
                    description: format!("Very low printable ratio {:.1}% at offset 0x{:X}", printable * 100.0, block.offset),
                });
            }
        }
    }
}

fn classify_high_entropy_block(entropy: f64, chi2_norm: f64, cfg: &DetectionConfig) -> AnomalyKind {
    if chi2_norm < cfg.uniform_chi2_threshold {
        // Very uniform → encrypted
        AnomalyKind::LikelyEncrypted
    } else if entropy > 7.5 {
        // Extremely high — random or encrypted
        AnomalyKind::LikelyEncrypted
    } else if entropy > 6.5 {
        // High but not quite random — could be compressed
        AnomalyKind::LikelyCompressed
    } else {
        AnomalyKind::HighEntropy
    }
}

fn entropy_confidence(entropy: f64, threshold: f64, max: f64) -> u8 {
    if max <= threshold {
        return 0;
    }
    let ratio = (entropy - threshold) / (max - threshold);
    casts::f64_to_u8(ratio.clamp(0.0, 1.0) * 100.0)
}

fn low_entropy_confidence(entropy: f64, threshold: f64) -> u8 {
    if threshold <= 0.0 {
        return 0;
    }
    let ratio = 1.0 - entropy / threshold;
    casts::f64_to_u8(ratio.clamp(0.0, 1.0) * 80.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// AnomalySummary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics from a [`detect_anomalies`] run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalySummary {
    /// Total anomalies detected.
    pub total: usize,
    /// Number of suspicious anomalies (see [`Anomaly::is_suspicious`]).
    pub suspicious_count: usize,
    /// Number of file-level anomalies.
    pub file_level_count: usize,
    /// Average confidence of all anomalies.
    pub avg_confidence: f64,
    /// Highest confidence anomaly kind, if any.
    pub highest_confidence_kind: Option<AnomalyKind>,
}

impl AnomalySummary {
    /// Build a summary from a slice of anomalies.
    #[must_use]
    pub fn from_anomalies(anomalies: &[Anomaly]) -> Self {
        let total = anomalies.len();
        let suspicious_count = anomalies.iter().filter(|a| a.is_suspicious()).count();
        let file_level_count = anomalies.iter().filter(|a| a.is_file_level()).count();
        let avg_confidence = if total > 0 {
            anomalies.iter().map(|a| f64::from(a.confidence)).sum::<f64>() / casts::usize_to_f64(total)
        } else {
            0.0
        };
        let highest_confidence_kind = anomalies
            .iter()
            .max_by_key(|a| a.confidence)
            .map(|a| a.kind);
        Self {
            total,
            suspicious_count,
            file_level_count,
            avg_confidence,
            highest_confidence_kind,
        }
    }

    /// `true` if any suspicious anomaly was detected.
    #[must_use]
    pub const fn has_suspicious(&self) -> bool {
        self.suspicious_count > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DetectionConfig {
        DetectionConfig::default()
    }

    fn uniform_data(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }

    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    // ── AnomalyKind ───────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_kind_display() {
        assert_eq!(AnomalyKind::HighEntropy.to_string(), "HighEntropy");
        assert_eq!(AnomalyKind::LikelyEncrypted.to_string(), "LikelyEncrypted");
        assert_eq!(AnomalyKind::FileEntropy.to_string(), "FileEntropy");
    }

    // ── Anomaly ───────────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_is_suspicious() {
        let a = Anomaly {
            kind: AnomalyKind::LikelyEncrypted,
            offset: 0,
            length: 256,
            entropy: 7.9,
            chi_squared: 0.0,
            confidence: 90,
            description: "test".into(),
        };
        assert!(a.is_suspicious());
    }

    #[test]
    fn test_anomaly_not_suspicious() {
        let a = Anomaly {
            kind: AnomalyKind::LowEntropy,
            offset: 0,
            length: 256,
            entropy: 0.1,
            chi_squared: 9999.0,
            confidence: 80,
            description: "test".into(),
        };
        assert!(!a.is_suspicious());
    }

    #[test]
    fn test_anomaly_is_file_level() {
        let a = Anomaly {
            kind: AnomalyKind::FileEntropy,
            offset: 0,
            length: 1024,
            entropy: 7.5,
            chi_squared: 1.0,
            confidence: 70,
            description: "test".into(),
        };
        assert!(a.is_file_level());
    }

    #[test]
    fn test_anomaly_display() {
        let a = Anomaly {
            kind: AnomalyKind::HighEntropy,
            offset: 0x1000,
            length: 4096,
            entropy: 7.9,
            chi_squared: 12.3,
            confidence: 85,
            description: "high entropy region".into(),
        };
        let s = a.to_string();
        assert!(s.contains("HighEntropy"));
        assert!(s.contains("7.900"));
        assert!(s.contains("85%"));
    }

    // ── detect_anomalies — empty data ─────────────────────────────────────

    #[test]
    fn test_detect_empty() {
        let r = detect_anomalies(&[], &cfg());
        assert!(r.is_empty());
    }

    // ── detect_anomalies — high entropy ───────────────────────────────────

    #[test]
    fn test_detect_high_entropy_file() {
        // 8× 4096-byte blocks of uniform data → entropy ≈ 8.0 overall
        let data = uniform_data(32768);
        let r = detect_anomalies(&data, &cfg());
        assert!(!r.is_empty(), "should detect high entropy");
        assert!(r.iter().any(super::Anomaly::is_suspicious));
    }

    #[test]
    fn test_detect_no_anomaly_zeros() {
        let data = zeros(8192);
        let r = detect_anomalies(
            &data,
            &DetectionConfig {
                min_confidence: 90,
                ..Default::default()
            },
        );
        // Zeros have entropy 0.0, which is < high_entropy_threshold — no high-entropy anomaly
        // LowEntropy might fire but with the default threshold 0.5 and confidence
        // filter at 90 it may or may not appear; we just assert no HighEntropy.
        assert!(!r.iter().any(|a| a.kind == AnomalyKind::HighEntropy));
    }

    // ── detect_anomalies — null density ───────────────────────────────────

    #[test]
    fn test_detect_high_null_density() {
        let mut data = vec![0u8; 3700]; // 90% nulls
        data.extend(vec![0xAAu8; 400]);
        let r = detect_anomalies(&data, &cfg());
        // Should detect high null density in the mostly-null block
        assert!(r.iter().any(|a| a.kind == AnomalyKind::HighNullDensity));
    }

    // ── DetectionConfig ───────────────────────────────────────────────────

    #[test]
    fn test_detection_config_default() {
        let c = DetectionConfig::default();
        assert_eq!(c.block_size, 4096);
        assert!((c.high_entropy_threshold - (7.0)).abs() < f64::EPSILON);
        assert_eq!(c.min_confidence, 50);
    }

    // ── AnomalySummary ────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_summary_empty() {
        let s = AnomalySummary::from_anomalies(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.suspicious_count, 0);
        assert!(!s.has_suspicious());
        assert!(s.highest_confidence_kind.is_none());
    }

    #[test]
    fn test_anomaly_summary_with_data() {
        let anomalies = vec![
            Anomaly {
                kind: AnomalyKind::LikelyEncrypted,
                offset: 0,
                length: 256,
                entropy: 7.9,
                chi_squared: 0.0,
                confidence: 90,
                description: "a".into(),
            },
            Anomaly {
                kind: AnomalyKind::LowEntropy,
                offset: 256,
                length: 256,
                entropy: 0.1,
                chi_squared: 9999.0,
                confidence: 70,
                description: "b".into(),
            },
        ];
        let s = AnomalySummary::from_anomalies(&anomalies);
        assert_eq!(s.total, 2);
        assert_eq!(s.suspicious_count, 1);
        assert!((s.avg_confidence - 80.0).abs() < 1.0);
        assert_eq!(
            s.highest_confidence_kind,
            Some(AnomalyKind::LikelyEncrypted)
        );
        assert!(s.has_suspicious());
    }

    #[test]
    fn test_anomaly_summary_file_level() {
        let anomalies = vec![Anomaly {
            kind: AnomalyKind::FileEntropy,
            offset: 0,
            length: 1024,
            entropy: 7.5,
            chi_squared: 1.0,
            confidence: 70,
            description: "file".into(),
        }];
        let s = AnomalySummary::from_anomalies(&anomalies);
        assert_eq!(s.file_level_count, 1);
    }
}
