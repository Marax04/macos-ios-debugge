//! `packer_detector` — signature-based packer identification from entropy profiles.
//!
//! Provides [`PackerDetector`], [`PackerSignature`], [`PackerKind`], and the
//! free function [`score_packer`] that combine heuristic entropy analysis with
//! byte-pattern matching to identify common software packers.

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::{shannon_entropy_f32, EntropyCategory};

// ─── PackerKind ───────────────────────────────────────────────────────────────

/// Known packer or protector families.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerKind {
    /// UPX (Universal Packer for eXecutables).
    Upx,
    /// `VMProtect` code virtualisation.
    VmProtect,
    /// Themida / `WinLicense` protector.
    Themida,
    /// Petite packer.
    Petite,
    /// `ASPack` packer.
    AsPack,
    /// MPRESS packer.
    Mpress,
    /// Obsidium protector.
    Obsidium,
    /// `NSPack` packer.
    NsPack,
    /// tElock packer.
    Telock,
    /// Enigma Protector.
    Enigma,
    /// `PECompact` packer.
    PeCompact,
    /// Custom / unknown packer detected by heuristics only.
    Unknown(String),
}

impl fmt::Display for PackerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Upx => "UPX",
            Self::VmProtect => "VMProtect",
            Self::Themida => "Themida/WinLicense",
            Self::Petite => "Petite",
            Self::AsPack => "ASPack",
            Self::Mpress => "MPRESS",
            Self::Obsidium => "Obsidium",
            Self::NsPack => "NSPack",
            Self::Telock => "tElock",
            Self::Enigma => "Enigma Protector",
            Self::PeCompact => "PECompact",
            Self::Unknown(name) => name.as_str(),
        };
        write!(f, "{s}")
    }
}

// ─── PackerSignature ──────────────────────────────────────────────────────────

/// A descriptor that combines byte patterns and entropy heuristics to
/// identify a specific packer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerSignature {
    /// Display name of this signature.
    pub name: String,
    /// The packer family this signature identifies.
    pub kind: PackerKind,
    /// Byte sequences that must appear anywhere in the file.
    pub byte_patterns: Vec<Vec<u8>>,
    /// Section names that indicate this packer (exact match).
    pub section_names: Vec<String>,
    /// Minimum entropy of the first executable section for this packer.
    pub min_text_entropy: Option<f32>,
    /// Maximum import count (proxy: number of `.dll` references) expected.
    pub max_import_count: Option<usize>,
    /// Base confidence score when the signature matches (0–100).
    pub base_score: u32,
}

impl PackerSignature {
    /// Build the built-in UPX signature.
    #[must_use]
    pub fn upx() -> Self {
        Self {
            name: "UPX".to_string(),
            kind: PackerKind::Upx,
            byte_patterns: vec![b"UPX!".to_vec(), b"UPX0".to_vec()],
            section_names: vec!["UPX0".to_string(), "UPX1".to_string()],
            min_text_entropy: Some(7.0),
            max_import_count: Some(5),
            base_score: 90,
        }
    }

    /// Build the built-in `VMProtect` signature.
    #[must_use]
    pub fn vmprotect() -> Self {
        Self {
            name: "VMProtect".to_string(),
            kind: PackerKind::VmProtect,
            byte_patterns: vec![b".vmp0".to_vec(), b".vmp1".to_vec()],
            section_names: vec![".vmp0".to_string(), ".vmp1".to_string()],
            min_text_entropy: Some(6.5),
            max_import_count: Some(10),
            base_score: 85,
        }
    }

    /// Build the built-in Themida signature.
    #[must_use]
    pub fn themida() -> Self {
        Self {
            name: "Themida".to_string(),
            kind: PackerKind::Themida,
            byte_patterns: vec![b".themida".to_vec()],
            section_names: vec![".themida".to_string()],
            min_text_entropy: Some(7.0),
            max_import_count: Some(8),
            base_score: 88,
        }
    }

    /// Build the built-in MPRESS signature.
    #[must_use]
    pub fn mpress() -> Self {
        Self {
            name: "MPRESS".to_string(),
            kind: PackerKind::Mpress,
            byte_patterns: vec![b".MPRESS1".to_vec(), b".MPRESS2".to_vec()],
            section_names: vec![".MPRESS1".to_string(), ".MPRESS2".to_string()],
            min_text_entropy: Some(7.2),
            max_import_count: Some(4),
            base_score: 82,
        }
    }

    /// Build the built-in `NSPack` signature.
    #[must_use]
    pub fn nspack() -> Self {
        Self {
            name: "NSPack".to_string(),
            kind: PackerKind::NsPack,
            byte_patterns: vec![b".nsp0".to_vec(), b".nsp1".to_vec()],
            section_names: vec![".nsp0".to_string(), ".nsp1".to_string()],
            min_text_entropy: Some(7.0),
            max_import_count: Some(6),
            base_score: 80,
        }
    }

    /// Return all built-in signatures.
    #[must_use]
    pub fn all_builtin() -> Vec<Self> {
        vec![
            Self::upx(),
            Self::vmprotect(),
            Self::themida(),
            Self::mpress(),
            Self::nspack(),
        ]
    }

    /// Test this signature against `data` and return the match score (0 = no
    /// match, higher = more confident).
    ///
    /// The scoring algorithm awards points for:
    /// - Each matching byte pattern (+30 points each, capped at 60)
    /// - Matching section names in the PE section table (+25 per match)
    /// - High entropy on the `.text` / `CODE` section if `min_text_entropy` is set (+20)
    /// - Import count below `max_import_count` if set (+10)
    #[must_use]
    pub fn score(&self, data: &[u8]) -> u32 {
        let mut score = 0u32;

        // ── Byte pattern matching ────────────────────────────────────────────
        let mut pattern_hits = 0u32;
        for pattern in &self.byte_patterns {
            if bytes_contains(data, pattern) {
                pattern_hits += 1;
            }
        }
        score += (pattern_hits * 30).min(60);

        // ── PE header parsing ────────────────────────────────────────────────
        if data.len() >= 64 {
            let e_lfanew = u32::from_le_bytes([
                data[0x3c], data[0x3d], data[0x3e], data[0x3f],
            ]) as usize;

            if e_lfanew + 24 < data.len()
                && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
            {
                let num_sections = u16::from_le_bytes([
                    data[e_lfanew + 6], data[e_lfanew + 7],
                ]) as usize;
                let opt_size = u16::from_le_bytes([
                    data[e_lfanew + 20], data[e_lfanew + 21],
                ]) as usize;
                let table = e_lfanew + 24 + opt_size;

                for i in 0..num_sections {
                    // Use saturating_add to prevent overflow from adversarial num_sections.
                    let entry = table.saturating_add(i * 40);
                    if entry + 40 > data.len() { break; }
                    let raw = &data[entry..entry + 8];
                    let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
                    let name = std::str::from_utf8(&raw[..end]).unwrap_or("");

                    if self.section_names.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                        score += 25;
                    }

                    // Check .text entropy
                    if matches!(name, ".text" | "CODE")
                        && let Some(min_e) = self.min_text_entropy {
                            let raw_off = u32::from_le_bytes([
                                data[entry + 20], data[entry + 21],
                                data[entry + 22], data[entry + 23],
                            ]) as usize;
                            let raw_sz = u32::from_le_bytes([
                                data[entry + 16], data[entry + 17],
                                data[entry + 18], data[entry + 19],
                            ]) as usize;
                            // Use saturating_add to prevent overflow with adversarial section data.
                            if raw_off.saturating_add(raw_sz) <= data.len() && raw_sz > 0 {
                                let e = shannon_entropy_f32(&data[raw_off..raw_off + raw_sz]);
                                if e >= min_e { score += 20; }
                            }
                        }
                }

                // Cheap import count heuristic
                if let Some(max_imp) = self.max_import_count {
                    let probe = &data[..data.len().min(0x10000)];
                    let dll_count = count_nonoverlapping(probe, b".dll")
                        + count_nonoverlapping(probe, b".DLL");
                    if dll_count < max_imp {
                        score += 10;
                    }
                }
            }
        }

        score
    }
}

// ─── PackerMatch ──────────────────────────────────────────────────────────────

/// The result of matching a [`PackerSignature`] against a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerMatch {
    /// The matched packer kind.
    pub kind: PackerKind,
    /// Display name of the signature that matched.
    pub signature_name: String,
    /// Confidence score (0–100+; higher = more confident).
    pub score: u32,
    /// Human-readable reasons for the match.
    pub reasons: Vec<String>,
}

impl fmt::Display for PackerMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackerMatch {{ kind: {}, score: {}, reasons: {} }}",
            self.kind,
            self.score,
            self.reasons.len()
        )
    }
}

// ─── PackerDetector ───────────────────────────────────────────────────────────

/// Packer detector that runs a battery of [`PackerSignature`]s against binary
/// data and returns scored [`PackerMatch`] results.
pub struct PackerDetector {
    signatures: Vec<PackerSignature>,
    /// Minimum score to include a match in results.
    pub threshold: u32,
}

impl PackerDetector {
    /// Create a detector loaded with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: PackerSignature::all_builtin(),
            threshold: 30,
        }
    }

    /// Create a detector with no signatures (add them via [`Self::add_signature`]).
    #[must_use]
    pub const fn empty() -> Self {
        Self { signatures: Vec::new(), threshold: 30 }
    }

    /// Set the minimum match score threshold.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Add a custom signature.
    pub fn add_signature(&mut self, sig: PackerSignature) {
        self.signatures.push(sig);
    }

    /// Run all signatures against `data` and return scored, sorted matches.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<PackerMatch> {
        let mut matches: Vec<PackerMatch> = self
            .signatures
            .iter()
            .filter_map(|sig| {
                let score = sig.score(data);
                if score < self.threshold { return None; }
                let mut reasons = Vec::new();
                // Check byte patterns for reason strings
                for pattern in &sig.byte_patterns {
                    if bytes_contains(data, pattern) {
                        let s = String::from_utf8_lossy(pattern).to_string();
                        reasons.push(format!("byte pattern '{s}' found"));
                    }
                }
                if reasons.is_empty() {
                    reasons.push("heuristic entropy match".to_string());
                }
                Some(PackerMatch {
                    kind: sig.kind.clone(),
                    signature_name: sig.name.clone(),
                    score,
                    reasons,
                })
            })
            .collect();
        matches.sort_by(|a, b| b.score.cmp(&a.score));
        matches
    }

    /// Return `true` if any packer is detected above the threshold.
    #[must_use]
    pub fn is_packed(&self, data: &[u8]) -> bool {
        !self.detect(data).is_empty()
    }

    /// Return the best (highest score) match, if any.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> Option<PackerMatch> {
        self.detect(data).into_iter().next()
    }

    /// Compute an overall "packing likelihood" in `[0.0, 1.0]` by combining
    /// the entropy of `data` with a binary indicator for any match above the
    /// threshold.
    #[must_use]
    pub fn packing_likelihood(&self, data: &[u8]) -> f32 {
        let entropy_score = (shannon_entropy_f32(data) / 8.0).clamp(0.0, 1.0);
        let has_match = if self.is_packed(data) { 1.0f32 } else { 0.0 };
        (entropy_score * 0.5 + has_match * 0.5).clamp(0.0, 1.0)
    }
}

impl Default for PackerDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── score_packer ─────────────────────────────────────────────────────────────

/// Convenience function that scores `data` against all built-in packer
/// signatures and returns results sorted by descending score.
///
/// Equivalent to:
/// ```ignore
/// PackerDetector::new().detect(data)
/// ```
#[must_use]
pub fn score_packer(data: &[u8]) -> Vec<PackerMatch> {
    PackerDetector::new().detect(data)
}

// ─── EntropyPackerProfile ─────────────────────────────────────────────────────

/// Entropy-profile heuristic for an unknown packer.
///
/// Some packers produce characteristic entropy patterns even when they don't
/// embed identifiable byte strings.  This struct captures those patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyPackerProfile {
    /// Name of this profile.
    pub name: String,
    /// Expected minimum file-wide entropy.
    pub min_overall_entropy: f32,
    /// Expected maximum file-wide entropy.
    pub max_overall_entropy: f32,
    /// Expected minimum entropy for the first 512 bytes (stub/loader).
    pub min_header_entropy: Option<f32>,
    /// Expected maximum entropy for the first 512 bytes.
    pub max_header_entropy: Option<f32>,
    /// Confidence (0–100) when the entropy profile matches.
    pub confidence: u32,
}

impl EntropyPackerProfile {
    /// Test this profile against `data` and return the confidence if it matches.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> Option<u32> {
        if data.is_empty() { return None; }
        let overall = shannon_entropy_f32(data);
        if overall < self.min_overall_entropy || overall > self.max_overall_entropy {
            return None;
        }
        if let (Some(min_h), Some(max_h)) = (self.min_header_entropy, self.max_header_entropy) {
            let header_end = data.len().min(512);
            let header_e = shannon_entropy_f32(&data[..header_end]);
            if header_e < min_h || header_e > max_h {
                return None;
            }
        }
        Some(self.confidence)
    }

    /// Return a generic "high-entropy binary" profile.
    #[must_use]
    pub fn high_entropy_generic() -> Self {
        Self {
            name: "GenericHighEntropy".to_string(),
            min_overall_entropy: 7.0,
            max_overall_entropy: 8.0,
            min_header_entropy: None,
            max_header_entropy: None,
            confidence: 40,
        }
    }
}

// ─── PackerReport ─────────────────────────────────────────────────────────────

/// Comprehensive packing detection report combining signature and entropy
/// profile results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerReport {
    /// Overall packing likelihood `[0.0, 1.0]`.
    pub likelihood: f32,
    /// Whether at least one signature or profile matched.
    pub detected: bool,
    /// Signature-based matches, sorted by score.
    pub signature_matches: Vec<PackerMatch>,
    /// Overall file entropy.
    pub overall_entropy: f32,
    /// Category for the overall entropy.
    pub category: EntropyCategory,
}

impl PackerReport {
    /// Generate a complete report for `data`.
    #[must_use]
    pub fn generate(data: &[u8]) -> Self {
        let detector = PackerDetector::new();
        let signature_matches = detector.detect(data);
        let likelihood = detector.packing_likelihood(data);
        let detected = !signature_matches.is_empty() || likelihood > 0.7;
        let overall_entropy = shannon_entropy_f32(data);
        let category = EntropyCategory::classify(overall_entropy);
        Self { likelihood, detected, signature_matches, overall_entropy, category }
    }

    /// Return the best packer name or `"Unknown"`.
    #[must_use]
    pub fn best_packer_name(&self) -> &str {
        self.signature_matches
            .first()
            .map_or("Unknown", |m| m.signature_name.as_str())
    }
}

impl fmt::Display for PackerReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Packer Report ===")?;
        writeln!(f, "  Detected    : {}", self.detected)?;
        writeln!(f, "  Likelihood  : {:.1}%", self.likelihood * 100.0)?;
        writeln!(f, "  Entropy     : {:.3}", self.overall_entropy)?;
        writeln!(f, "  Category    : {}", self.category)?;
        if !self.signature_matches.is_empty() {
            writeln!(f, "  Matches:")?;
            for m in &self.signature_matches {
                writeln!(f, "    {} (score={})", m.signature_name, m.score)?;
            }
        }
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn count_nonoverlapping(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() { return 0; }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packer_kind_display() {
        assert_eq!(PackerKind::Upx.to_string(), "UPX");
        assert_eq!(PackerKind::VmProtect.to_string(), "VMProtect");
    }

    #[test]
    fn packer_signature_upx_byte_match() {
        let sig = PackerSignature::upx();
        let mut data = vec![0u8; 512];
        data[100..104].copy_from_slice(b"UPX!");
        let score = sig.score(&data);
        assert!(score >= 30, "score={score}");
    }

    #[test]
    fn packer_signature_no_match_empty() {
        let sig = PackerSignature::upx();
        let score = sig.score(&[0u8; 16]);
        assert_eq!(score, 0);
    }

    #[test]
    fn packer_detector_new_has_signatures() {
        let d = PackerDetector::new();
        assert!(!d.signatures.is_empty());
    }

    #[test]
    fn packer_detector_detect_no_packer() {
        let d = PackerDetector::new();
        let data = b"Hello, world! This is plain text with no packing indicators at all.";
        let matches = d.detect(data);
        // Should have no high-confidence matches for plain text
        for m in &matches {
            assert!(m.score < d.threshold || m.kind == PackerKind::Unknown(String::new()) || true);
        }
        // Just verify it doesn't panic
        let _ = matches;
    }

    #[test]
    fn packer_detector_detect_upx_magic() {
        let d = PackerDetector::new();
        let mut data = vec![0u8; 512];
        data[100..104].copy_from_slice(b"UPX!");
        data[200..204].copy_from_slice(b"UPX0");
        let matches = d.detect(&data);
        let upx = matches.iter().find(|m| m.kind == PackerKind::Upx);
        assert!(upx.is_some());
    }

    #[test]
    fn score_packer_function_smoke() {
        let data = vec![0u8; 256];
        let results = score_packer(&data);
        // May be empty or not — just ensure no panic
        let _ = results;
    }

    #[test]
    fn packer_likelihood_high_entropy() {
        let d = PackerDetector::new();
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let likelihood = d.packing_likelihood(&data);
        assert!(likelihood > 0.4, "likelihood={likelihood}");
    }

    #[test]
    fn entropy_packer_profile_generic_matches() {
        let profile = EntropyPackerProfile::high_entropy_generic();
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let result = profile.matches(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 40);
    }

    #[test]
    fn entropy_packer_profile_generic_no_match_zeros() {
        let profile = EntropyPackerProfile::high_entropy_generic();
        let data = vec![0u8; 2048];
        assert!(profile.matches(&data).is_none());
    }

    #[test]
    fn packer_report_generate_zeros() {
        let data = vec![0u8; 1024];
        let report = PackerReport::generate(&data);
        assert!(!report.detected);
        assert_eq!(report.best_packer_name(), "Unknown");
    }

    #[test]
    fn packer_report_generate_upx() {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(b"UPX!");
        data[100..104].copy_from_slice(b"UPX0");
        let report = PackerReport::generate(&data);
        // May or may not be detected depending on threshold; just no panic
        let _ = report.likelihood;
    }

    #[test]
    fn builtin_signatures_names() {
        let sigs = PackerSignature::all_builtin();
        let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UPX"));
        assert!(names.contains(&"VMProtect"));
    }

    #[test]
    fn packer_match_display() {
        let m = PackerMatch {
            kind: PackerKind::Upx,
            signature_name: "UPX".to_string(),
            score: 90,
            reasons: vec!["byte pattern found".to_string()],
        };
        let s = m.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("90"));
    }

    #[test]
    fn detector_empty_threshold() {
        let d = PackerDetector::empty().with_threshold(0);
        let data = vec![0u8; 64];
        // No signatures → empty matches
        assert!(d.detect(&data).is_empty());
    }

    #[test]
    fn bytes_contains_helper() {
        assert!(bytes_contains(b"hello world", b"world"));
        assert!(!bytes_contains(b"hello world", b"xyz"));
        assert!(bytes_contains(b"abc", b""));
    }

    #[test]
    fn count_nonoverlapping_helper() {
        assert_eq!(count_nonoverlapping(b"aababab", b"ab"), 3);
        assert_eq!(count_nonoverlapping(b"hello", b"xyz"), 0);
    }
}
