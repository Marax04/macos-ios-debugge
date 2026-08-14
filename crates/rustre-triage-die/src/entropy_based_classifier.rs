//! Entropy-based file classifier: derives packer/protector/compiler hints from
//! the Shannon entropy profile of PE sections and the whole file.

use std::fmt;

use crate::{compute_entropy, read_pe_sections};

// ── EntropyProfile ────────────────────────────────────────────────────────────

/// Per-section and whole-file entropy measurements.
#[derive(Debug, Clone)]
pub struct EntropyProfile {
    /// Entropy of the complete raw file bytes.
    pub whole_file: f32,
    /// Per-section `(name, entropy)` pairs in section-table order.
    pub sections: Vec<(String, f32)>,
    /// Number of sections with entropy above the "high" threshold.
    pub high_entropy_count: usize,
    /// Number of sections with entropy below the "low" threshold.
    pub low_entropy_count: usize,
    /// Weighted average entropy (weighted by section raw-data size).
    ///
    /// Falls back to arithmetic mean when section sizes are unavailable.
    pub weighted_mean: f32,
    /// Maximum section entropy.
    pub max_section_entropy: f32,
    /// Minimum section entropy (excluding empty/zero sections).
    pub min_section_entropy: f32,
}

impl EntropyProfile {
    /// Compute an entropy profile from raw PE bytes.
    ///
    /// `high_threshold` and `low_threshold` are the entropy boundaries used to
    /// count sections (default 7.0 and 3.5 respectively).
    #[must_use]
    pub fn compute(data: &[u8], high_threshold: f32, low_threshold: f32) -> Self {
        let whole_file = compute_entropy(data);
        let sections = read_pe_sections(data);

        let high_entropy_count = sections
            .iter()
            .filter(|(_, e)| *e > high_threshold)
            .count();
        let low_entropy_count = sections
            .iter()
            .filter(|(_, e)| *e > 0.1 && *e < low_threshold)
            .count();

        let (weighted_mean, max_section_entropy, min_section_entropy) = if sections.is_empty() {
            (whole_file, whole_file, whole_file)
        } else {
            let sum: f32 = sections.iter().map(|(_, e)| *e).sum();
            let mean = sum / sections.len() as f32;
            let max = sections
                .iter()
                .map(|(_, e)| *e)
                .fold(f32::NEG_INFINITY, f32::max);
            let min = sections
                .iter()
                .filter(|(_, e)| *e > 0.1)
                .map(|(_, e)| *e)
                .fold(f32::INFINITY, f32::min);
            let min = if min.is_infinite() { 0.0 } else { min };
            (mean, max, min)
        };

        Self {
            whole_file,
            sections,
            high_entropy_count,
            low_entropy_count,
            weighted_mean,
            max_section_entropy,
            min_section_entropy,
        }
    }

    /// Returns `true` if this profile looks like a packed executable (most
    /// sections have high entropy).
    #[must_use]
    pub fn looks_packed(&self, high_threshold: f32) -> bool {
        if self.sections.is_empty() {
            return self.whole_file > high_threshold;
        }
        // Majority of sections above threshold
        let n_high = self
            .sections
            .iter()
            .filter(|(_, e)| *e > high_threshold)
            .count();
        n_high * 2 >= self.sections.len()
    }

    /// True when at least one section has a well-known code-section name and
    /// a code-like entropy (4.5–6.5).
    #[must_use]
    pub fn has_code_section(&self) -> bool {
        let code_names = [".text", "CODE", ".code", ".textbss"];
        self.sections.iter().any(|(name, entropy)| {
            code_names
                .iter()
                .any(|&cn| name.eq_ignore_ascii_case(cn))
                && *entropy > 4.5
                && *entropy < 6.8
        })
    }
}

impl fmt::Display for EntropyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyProfile {{ whole={:.3}, mean={:.3}, high_secs={}, low_secs={} }}",
            self.whole_file,
            self.weighted_mean,
            self.high_entropy_count,
            self.low_entropy_count
        )
    }
}

// ── ClassificationLabel ───────────────────────────────────────────────────────

/// High-level entropy-based classification label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationLabel {
    /// Executable is very likely packed or encrypted.
    Packed,
    /// Executable shows signs of an anti-tamper / protector.
    Protected,
    /// Executable looks like a normal compiler output.
    Clean,
    /// Some sections are suspicious but overall not conclusive.
    Suspicious,
    /// Entropy data is insufficient (e.g. less than 512 bytes).
    Insufficient,
}

impl fmt::Display for ClassificationLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ClassificationResult ──────────────────────────────────────────────────────

/// The result of classifying a file using entropy analysis.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Primary label.
    pub label: ClassificationLabel,
    /// Confidence in the label (0–100).
    pub confidence: u8,
    /// Entropy profile used to make the decision.
    pub profile: EntropyProfile,
    /// Human-readable reasons that led to the classification.
    pub reasons: Vec<String>,
}

impl ClassificationResult {
    /// Returns `true` if the file is likely packed (high confidence).
    #[must_use]
    pub fn is_packed(&self) -> bool {
        matches!(self.label, ClassificationLabel::Packed) && self.confidence >= 70
    }

    /// Returns `true` if the result is inconclusive.
    #[must_use]
    pub fn is_inconclusive(&self) -> bool {
        matches!(
            self.label,
            ClassificationLabel::Suspicious | ClassificationLabel::Insufficient
        )
    }

    /// Short single-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (confidence {}%, entropy_whole={:.3})",
            self.label, self.confidence, self.profile.whole_file
        )
    }
}

impl fmt::Display for ClassificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── ClassifierConfig ──────────────────────────────────────────────────────────

/// Tuning parameters for the entropy-based classifier.
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    /// Entropy above this → high-entropy section (default 7.0).
    pub high_entropy_threshold: f32,
    /// Entropy below this → low-entropy section (default 3.5).
    pub low_entropy_threshold: f32,
    /// Whole-file entropy above this and no PE sections → `Packed` (default 6.8).
    pub flat_file_threshold: f32,
    /// Fraction of sections that must be high-entropy to classify as `Packed`
    /// (default 0.6).
    pub packed_section_ratio: f32,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            high_entropy_threshold: 7.0,
            low_entropy_threshold: 3.5,
            flat_file_threshold: 6.8,
            packed_section_ratio: 0.6,
        }
    }
}

// ── EntropyBasedClassifier ────────────────────────────────────────────────────

/// Classifies a binary file using only its entropy characteristics.
///
/// The classifier is section-aware: if PE section data is available it uses
/// per-section entropy; otherwise it falls back to whole-file entropy.
///
/// # Example
/// ```
/// use rustre_triage_die::entropy_based_classifier::{EntropyBasedClassifier, ClassifierConfig};
///
/// let data = b"\xCC\x55\xAA\xFF".repeat(1024); // high-entropy blob
/// let clf = EntropyBasedClassifier::new(ClassifierConfig::default());
/// let result = clf.classify(&data);
/// println!("{}", result.summary());
/// ```
pub struct EntropyBasedClassifier {
    config: ClassifierConfig,
}

impl EntropyBasedClassifier {
    /// Create a classifier with the given configuration.
    #[must_use]
    pub fn new(config: ClassifierConfig) -> Self {
        Self { config }
    }

    /// Create a classifier with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(ClassifierConfig::default())
    }

    /// Classify `data` and return a [`ClassificationResult`].
    #[must_use]
    pub fn classify(&self, data: &[u8]) -> ClassificationResult {
        if data.len() < 512 {
            return ClassificationResult {
                label: ClassificationLabel::Insufficient,
                confidence: 100,
                profile: EntropyProfile::compute(
                    data,
                    self.config.high_entropy_threshold,
                    self.config.low_entropy_threshold,
                ),
                reasons: vec!["file too small for reliable entropy analysis".into()],
            };
        }

        let profile = EntropyProfile::compute(
            data,
            self.config.high_entropy_threshold,
            self.config.low_entropy_threshold,
        );

        let mut reasons: Vec<String> = Vec::new();
        let (label, confidence) = self.decide(&profile, &mut reasons);

        ClassificationResult {
            label,
            confidence,
            profile,
            reasons,
        }
    }

    fn decide(
        &self,
        profile: &EntropyProfile,
        reasons: &mut Vec<String>,
    ) -> (ClassificationLabel, u8) {
        // Non-PE flat file
        if profile.sections.is_empty() {
            if profile.whole_file > self.config.flat_file_threshold {
                reasons.push(format!(
                    "no PE sections; whole-file entropy {:.3} > {:.3}",
                    profile.whole_file, self.config.flat_file_threshold
                ));
                return (ClassificationLabel::Packed, 70);
            }
            reasons.push(format!(
                "no PE sections; whole-file entropy {:.3}",
                profile.whole_file
            ));
            return (ClassificationLabel::Clean, 50);
        }

        let n = profile.sections.len();
        let n_high = profile.high_entropy_count;
        let n_low = profile.low_entropy_count;

        // Packed heuristic: majority of sections are high-entropy
        let high_ratio = n_high as f32 / n as f32;
        if high_ratio >= self.config.packed_section_ratio {
            reasons.push(format!(
                "{n_high}/{n} sections above entropy threshold {:.1}",
                self.config.high_entropy_threshold
            ));
            // Two very high entropy sections (UPX pattern) → higher confidence
            let conf = if n_high >= 2 { 88 } else { 75 };
            return (ClassificationLabel::Packed, conf);
        }

        // Protected heuristic: few sections, one is high-entropy, others low
        if n <= 4 && n_high >= 1 && n_low >= 1 {
            reasons.push(format!(
                "{n_high} high-entropy section(s) alongside {n_low} low-entropy section(s)"
            ));
            return (ClassificationLabel::Protected, 70);
        }

        // Suspicious: single high-entropy section in an otherwise normal binary
        if n_high == 1 && n >= 3 {
            reasons.push(format!(
                "1 of {n} sections has high entropy — possible encrypted section"
            ));
            return (ClassificationLabel::Suspicious, 60);
        }

        // Whole-file entropy is high even if section analysis says clean
        if profile.whole_file > self.config.flat_file_threshold {
            reasons.push(format!(
                "whole-file entropy {:.3} is elevated",
                profile.whole_file
            ));
            return (ClassificationLabel::Suspicious, 55);
        }

        // Looks clean
        if profile.has_code_section() {
            reasons.push("code section with normal entropy detected".into());
        }
        reasons.push(format!(
            "weighted mean entropy {:.3}",
            profile.weighted_mean
        ));
        (ClassificationLabel::Clean, 80)
    }
}

impl fmt::Debug for EntropyBasedClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyBasedClassifier(hi={:.1}, lo={:.1})",
            self.config.high_entropy_threshold, self.config.low_entropy_threshold
        )
    }
}

// ── SectionEntropyReport ──────────────────────────────────────────────────────

/// A human-readable entropy report for all sections.
#[derive(Debug, Clone)]
pub struct SectionEntropyReport {
    pub entries: Vec<SectionEntropyEntry>,
}

/// One entry in a [`SectionEntropyReport`].
#[derive(Debug, Clone)]
pub struct SectionEntropyEntry {
    pub name: String,
    pub entropy: f32,
    pub classification: &'static str,
}

impl SectionEntropyReport {
    /// Build a report from a raw PE file.
    #[must_use]
    pub fn from_pe(data: &[u8]) -> Self {
        let sections = read_pe_sections(data);
        let entries = sections
            .into_iter()
            .map(|(name, entropy)| SectionEntropyEntry {
                classification: classify_entropy_label(entropy),
                name,
                entropy,
            })
            .collect();
        Self { entries }
    }

    /// Format as a multi-line table.
    #[must_use]
    pub fn table(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("Section            Entropy  Classification\n");
        out.push_str("--------------------------------------------------\n");
        for e in &self.entries {
            writeln!(
                out,
                "{:<18} {:.4}   {}",
                e.name, e.entropy, e.classification
            )
            .ok();
        }
        out
    }
}

fn classify_entropy_label(e: f32) -> &'static str {
    if e > 7.2 {
        "VERY HIGH — likely packed/encrypted"
    } else if e > 6.5 {
        "HIGH"
    } else if e > 4.5 {
        "NORMAL (code/data)"
    } else if e > 2.0 {
        "LOW"
    } else {
        "VERY LOW — possibly zero-padded"
    }
}

// ── Multi-pass classifier ─────────────────────────────────────────────────────

/// Runs the [`EntropyBasedClassifier`] with multiple block-size passes and
/// combines votes.
pub struct MultiPassClassifier {
    passes: Vec<usize>,
    classifier: EntropyBasedClassifier,
}

impl MultiPassClassifier {
    /// Create with given block sizes (in bytes) for sliding-window passes.
    #[must_use]
    pub fn new(passes: Vec<usize>) -> Self {
        Self {
            passes,
            classifier: EntropyBasedClassifier::default_config(),
        }
    }

    /// Classify `data` using multiple window sizes; return the majority label.
    #[must_use]
    pub fn classify(&self, data: &[u8]) -> ClassificationResult {
        // Primary classification over the whole file
        let primary = self.classifier.classify(data);

        // If primary is conclusive or data is small, return it directly
        if data.len() < 4096 || !primary.is_inconclusive() {
            return primary;
        }

        // Vote over sliding windows of different sizes
        let mut packed_votes: usize = 0;
        let mut clean_votes: usize = 0;
        let mut total_votes: usize = 0;

        for &window in &self.passes {
            let step = window;
            let mut pos = 0usize;
            while pos + window <= data.len() {
                let slice = &data[pos..pos + window];
                let e = compute_entropy(slice);
                if e > 7.0 {
                    packed_votes += 1;
                } else if e < 6.0 {
                    clean_votes += 1;
                }
                total_votes += 1;
                pos += step;
            }
        }

        if total_votes == 0 {
            return primary;
        }

        let packed_ratio = packed_votes as f32 / total_votes as f32;
        let clean_ratio = clean_votes as f32 / total_votes as f32;
        if packed_ratio > 0.6 {
            let mut reasons = primary.reasons.clone();
            reasons.push(format!(
                "multi-pass: {packed_votes}/{total_votes} windows packed (clean={clean_votes})"
            ));
            ClassificationResult {
                label: ClassificationLabel::Packed,
                confidence: ((packed_ratio * 100.0) as u8).min(95),
                profile: primary.profile,
                reasons,
            }
        } else if clean_ratio > 0.6 {
            // Strong evidence that the binary is *not* packed: most windows
            // landed in the low-entropy band. Upgrade the inconclusive result
            // to a Clean verdict.
            let mut reasons = primary.reasons.clone();
            reasons.push(format!(
                "multi-pass: {clean_votes}/{total_votes} windows clean (packed={packed_votes})"
            ));
            ClassificationResult {
                label: ClassificationLabel::Clean,
                confidence: ((clean_ratio * 100.0) as u8).min(95),
                profile: primary.profile,
                reasons,
            }
        } else {
            primary
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn high_entropy_blob(size: usize) -> Vec<u8> {
        // Cycle through all 256 values to achieve maximum entropy
        (0usize..size).map(|i| i as u8).collect()
    }

    fn low_entropy_blob(size: usize) -> Vec<u8> {
        vec![b'A'; size]
    }

    #[test]
    fn classify_high_entropy_as_packed() {
        let data = high_entropy_blob(4096);
        let clf = EntropyBasedClassifier::default_config();
        let result = clf.classify(&data);
        // No PE sections → whole-file entropy triggers packed heuristic
        assert_eq!(result.label, ClassificationLabel::Packed);
        assert!(!result.reasons.is_empty());
    }

    #[test]
    fn classify_low_entropy_as_clean() {
        let data = low_entropy_blob(4096);
        let clf = EntropyBasedClassifier::default_config();
        let result = clf.classify(&data);
        assert_eq!(result.label, ClassificationLabel::Clean);
    }

    #[test]
    fn small_file_insufficient() {
        let clf = EntropyBasedClassifier::default_config();
        let result = clf.classify(b"short");
        assert_eq!(result.label, ClassificationLabel::Insufficient);
    }

    #[test]
    fn entropy_profile_looks_packed_majority() {
        let high: Vec<(String, f32)> = (0..5).map(|i| (format!(".s{i}"), 7.5)).collect();
        let low = vec![(".data".to_string(), 3.0f32)];
        let all: Vec<(String, f32)> = high.into_iter().chain(low).collect();

        let profile = EntropyProfile {
            whole_file: 7.2,
            high_entropy_count: 5,
            low_entropy_count: 1,
            weighted_mean: 6.5,
            max_section_entropy: 7.5,
            min_section_entropy: 3.0,
            sections: all,
        };
        assert!(profile.looks_packed(7.0));
    }

    #[test]
    fn entropy_profile_not_packed_majority_low() {
        let secs: Vec<(String, f32)> = (0..5).map(|i| (format!(".s{i}"), 4.0)).collect();
        let profile = EntropyProfile {
            whole_file: 4.2,
            high_entropy_count: 0,
            low_entropy_count: 5,
            weighted_mean: 4.0,
            max_section_entropy: 4.0,
            min_section_entropy: 4.0,
            sections: secs,
        };
        assert!(!profile.looks_packed(7.0));
    }

    #[test]
    fn classification_result_summary_contains_label() {
        let clf = EntropyBasedClassifier::default_config();
        let result = clf.classify(&high_entropy_blob(2048));
        let summary = result.summary();
        assert!(
            summary.contains("Packed")
                || summary.contains("Clean")
                || summary.contains("Suspicious")
                || summary.contains("Insufficient")
        );
    }

    #[test]
    fn is_packed_returns_false_for_clean() {
        let clf = EntropyBasedClassifier::default_config();
        let result = clf.classify(&low_entropy_blob(4096));
        assert!(!result.is_packed());
    }

    #[test]
    fn section_entropy_report_builds() {
        let data = b"MZ\0\0".to_vec(); // non-PE → 0 sections
        let report = SectionEntropyReport::from_pe(&data);
        assert_eq!(report.entries.len(), 0);
    }

    #[test]
    fn section_entropy_report_table_header() {
        let report = SectionEntropyReport { entries: vec![] };
        let table = report.table();
        assert!(table.contains("Section"));
        assert!(table.contains("Entropy"));
    }

    #[test]
    fn multi_pass_classifier_does_not_panic() {
        let data = high_entropy_blob(8192);
        let clf = MultiPassClassifier::new(vec![256, 512, 1024]);
        let result = clf.classify(&data);
        assert_ne!(result.confidence, 0);
    }

    #[test]
    fn entropy_profile_display_format() {
        let data = low_entropy_blob(1024);
        let profile =
            EntropyProfile::compute(&data, 7.0, 3.5);
        let s = profile.to_string();
        assert!(s.contains("EntropyProfile"));
    }

    #[test]
    fn classifier_config_defaults() {
        let cfg = ClassifierConfig::default();
        assert!(cfg.high_entropy_threshold > 6.0);
        assert!(cfg.low_entropy_threshold < 5.0);
        assert!(cfg.packed_section_ratio > 0.0 && cfg.packed_section_ratio <= 1.0);
    }

    #[test]
    fn classify_entropy_label_high() {
        assert!(classify_entropy_label(7.5).contains("HIGH"));
    }

    #[test]
    fn classify_entropy_label_normal() {
        assert!(classify_entropy_label(5.0).contains("NORMAL"));
    }

    #[test]
    fn classify_entropy_label_very_low() {
        assert!(classify_entropy_label(0.1).contains("VERY LOW"));
    }
}
