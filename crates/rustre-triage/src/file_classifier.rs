//! File classification combining multiple signal sources.
//!
//! The `FileClassifier` aggregates evidence from entropy, format detection,
//! string heuristics, and import/export analysis to assign a final
//! `FileClass` and `RiskLevel` to a binary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{FileKind, ThreatLevel, TriageIndicator, detect_file_kind};

// ─── FileClass ────────────────────────────────────────────────────────────────

/// A high-level classification of the file's purpose/type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileClass {
    /// Legitimate executable or library.
    Benign,
    /// Possibly malicious but evidence is inconclusive.
    Suspicious,
    /// Known packer / protector wrapper.
    Packer,
    /// Downloader / dropper.
    Dropper,
    /// Remote Access Trojan.
    Rat,
    /// Ransomware.
    Ransomware,
    /// Keylogger / credential stealer.
    InfoStealer,
    /// Rootkit / kernel-mode implant.
    Rootkit,
    /// Banking Trojan.
    BankingTrojan,
    /// Exploit or shellcode carrier.
    Exploit,
    /// Coin miner.
    Miner,
    /// Botnet agent.
    Botnet,
    /// Script (`PowerShell`, `VBScript`, batch, etc.).
    Script,
    /// Document with embedded macros or exploits.
    MaliciousDocument,
    /// Unknown / insufficient data.
    Unknown,
}

impl std::fmt::Display for FileClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── RiskLevel ────────────────────────────────────────────────────────────────

/// Quantified risk level (more granular than `ThreatLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No risk detected.
    None,
    /// Informational only.
    Informational,
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk — likely active threat.
    Critical,
}

impl RiskLevel {
    /// Numeric score (0–100).
    #[must_use]
    pub const fn score(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Informational => 5,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }

    /// Convert from a `ThreatLevel`.
    #[must_use]
    pub const fn from_threat(t: ThreatLevel) -> Self {
        match t {
            ThreatLevel::Clean => Self::None,
            ThreatLevel::Informational => Self::Informational,
            ThreatLevel::Low => Self::Low,
            ThreatLevel::Medium => Self::Medium,
            ThreatLevel::High => Self::High,
            ThreatLevel::Critical => Self::Critical,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ClassificationEvidence ───────────────────────────────────────────────────

/// A piece of evidence that contributed to the classification decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationEvidence {
    /// Short evidence identifier.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Weight of this evidence in the classification score (1–10).
    pub weight: u8,
    /// The risk level this evidence implies.
    pub risk: RiskLevel,
}

impl ClassificationEvidence {
    /// Create a new evidence item.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        description: impl Into<String>,
        weight: u8,
        risk: RiskLevel,
    ) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            weight: weight.min(10),
            risk,
        }
    }
}

// ─── ClassificationResult ────────────────────────────────────────────────────

/// The full classification result for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Assigned file class.
    pub file_class: FileClass,
    /// Assigned risk level.
    pub risk_level: RiskLevel,
    /// Aggregated numeric score (0–100).
    pub score: u8,
    /// Evidence items that informed the classification.
    pub evidence: Vec<ClassificationEvidence>,
    /// Secondary class candidates with their scores.
    pub secondary_classes: Vec<(FileClass, u8)>,
    /// SHA-256 of the classified file.
    pub sha256: String,
    /// File format.
    pub file_kind: FileKind,
}

impl ClassificationResult {
    /// Returns `true` if the risk level is High or Critical.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.risk_level >= RiskLevel::High
    }

    /// Format as a one-line summary.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} | class={} risk={} score={}/100 evidence={}",
            self.file_kind,
            self.file_class,
            self.risk_level,
            self.score,
            self.evidence.len()
        )
    }
}

// ─── FileClassifier ───────────────────────────────────────────────────────────

/// Classifies files by combining multiple analysis signals.
///
/// The classifier uses a weighted evidence accumulation scheme:
/// 1. Format detection (PE/ELF/script/etc.)
/// 2. Entropy-based packing detection
/// 3. String/API import matching against known malware indicators
/// 4. Indicator-based scoring (derived from a pre-run triage)
pub struct FileClassifier {
    /// Known family signatures: keyword → (`FileClass`, weight).
    family_signatures: HashMap<String, (FileClass, u8)>,
    /// Minimum score threshold for High risk.
    high_risk_threshold: u8,
    /// Minimum score threshold for Critical risk.
    critical_threshold: u8,
}

impl FileClassifier {
    /// Create a classifier with built-in family signatures.
    #[must_use]
    pub fn new() -> Self {
        let mut family_signatures = HashMap::new();
        // RAT indicators.
        for kw in &[
            "meterpreter", "cobaltstrike", "beacon", "empire", "njrat",
            "darkcomet", "nanocore", "remcos", "asyncrat",
        ] {
            family_signatures.insert(kw.to_string(), (FileClass::Rat, 9));
        }
        // Ransomware.
        for kw in &["wannacry", "petya", "locky", "ryuk", "cryptolocker", "cerber", "gandcrab"] {
            family_signatures.insert(kw.to_string(), (FileClass::Ransomware, 10));
        }
        // Info stealers.
        for kw in &["mimikatz", "lsass", "sekurlsa", "credential", "password steal"] {
            family_signatures.insert(kw.to_string(), (FileClass::InfoStealer, 8));
        }
        // Miners.
        for kw in &["xmrig", "monero", "stratum+tcp", "cryptonight", "nicehash"] {
            family_signatures.insert(kw.to_string(), (FileClass::Miner, 8));
        }
        // Droppers / downloaders.
        for kw in &["downloader", "dropper", "stage2", "payload", "shellcode"] {
            family_signatures.insert(kw.to_string(), (FileClass::Dropper, 6));
        }
        // Banking.
        for kw in &["dridex", "emotet", "trickbot", "ursnif", "qakbot", "zeus", "spyeye"] {
            family_signatures.insert(kw.to_string(), (FileClass::BankingTrojan, 9));
        }
        Self {
            family_signatures,
            high_risk_threshold: 50,
            critical_threshold: 80,
        }
    }

    /// Set a custom high-risk threshold.
    pub const fn set_high_risk_threshold(&mut self, t: u8) {
        self.high_risk_threshold = t;
    }

    /// Classify a file given its raw bytes and pre-computed triage indicators.
    #[must_use]
    pub fn classify(
        &self,
        data: &[u8],
        indicators: &[TriageIndicator],
        sha256: &str,
    ) -> ClassificationResult {
        let file_kind = detect_file_kind(data);
        let mut evidence = Vec::new();

        // ── Format evidence ─────────────────────────────────────────────────
        let format_evidence = Self::format_evidence(file_kind, data);
        evidence.extend(format_evidence);

        // ── Entropy evidence ─────────────────────────────────────────────────
        let entropy_ev = Self::entropy_evidence(data);
        evidence.extend(entropy_ev);

        // ── String / API evidence ────────────────────────────────────────────
        let string_ev = self.string_evidence(data);
        evidence.extend(string_ev);

        // ── Indicator evidence ───────────────────────────────────────────────
        let ind_ev = Self::indicator_evidence(indicators);
        evidence.extend(ind_ev);

        // ── Score accumulation ───────────────────────────────────────────────
        let raw_score: u32 = evidence
            .iter()
            .map(|e| u32::from(e.weight) * u32::from(e.risk.score()))
            .sum();
        let max_possible: u32 = evidence.iter().map(|e| u32::from(e.weight) * 100).sum();
        let score = if max_possible == 0 {
            0u8
        } else {
            u8::try_from((raw_score * 100 / max_possible).min(100)).unwrap_or(100)
        };

        // ── Class vote ───────────────────────────────────────────────────────
        let (file_class, secondary) = self.vote_class(&evidence, file_kind, data);

        let risk_level = if score >= self.critical_threshold {
            RiskLevel::Critical
        } else if score >= self.high_risk_threshold {
            RiskLevel::High
        } else if score >= 25 {
            RiskLevel::Medium
        } else if score >= 5 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        ClassificationResult {
            file_class,
            risk_level,
            score,
            evidence,
            secondary_classes: secondary,
            sha256: sha256.to_string(),
            file_kind,
        }
    }

    fn format_evidence(kind: FileKind, data: &[u8]) -> Vec<ClassificationEvidence> {
        let mut ev = Vec::new();
        match kind {
            FileKind::Pe32 | FileKind::Pe64 => {
                ev.push(ClassificationEvidence::new(
                    "pe-binary",
                    "Windows PE executable",
                    2,
                    RiskLevel::Low,
                ));
                // Check for no section table (hollow / shellcode).
                if data.len() >= 64 {
                    let pe_off = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0;4])) as usize;
                    if pe_off + 6 < data.len() {
                        let num_sections = u16::from_le_bytes(data[pe_off+6..pe_off+8].try_into().unwrap_or([0;2]));
                        if num_sections == 0 {
                            ev.push(ClassificationEvidence::new(
                                "pe-no-sections",
                                "PE with zero sections — possible shellcode",
                                7,
                                RiskLevel::High,
                            ));
                        }
                    }
                }
            }
            FileKind::Elf32 | FileKind::Elf64 => {
                ev.push(ClassificationEvidence::new(
                    "elf-binary",
                    "ELF executable/library",
                    1,
                    RiskLevel::Informational,
                ));
            }
            FileKind::Apk | FileKind::Dex => {
                ev.push(ClassificationEvidence::new(
                    "android-binary",
                    "Android APK or DEX",
                    2,
                    RiskLevel::Low,
                ));
            }
            FileKind::Pdf | FileKind::Doc => {
                ev.push(ClassificationEvidence::new(
                    "document",
                    "Office/PDF document — may contain exploits or macros",
                    4,
                    RiskLevel::Medium,
                ));
            }
            FileKind::Unknown => {
                // Failing to identify the container says something about THIS
                // ANALYSIS, not about the file's intent — so it is reported,
                // but as information rather than as risk.
                //
                // Until 2026-07-29 this carried `RiskLevel::Medium` (= 50).
                // Because the final score is a ratio over the evidence that was
                // actually collected (`raw / max_possible`), a file whose only
                // observation is "format unknown" scored a flat **50**: an
                // absence of information became a mid-level threat verdict.
                // A buffer of 64 zero bytes is the clearest case — nothing is
                // known about it, and it was rated Medium risk.
                ev.push(ClassificationEvidence::new(
                    "unknown-format",
                    "Unknown file format — container not identified",
                    3,
                    RiskLevel::Informational,
                ));
            }
            _ => {}
        }
        ev
    }

    fn entropy_evidence(data: &[u8]) -> Vec<ClassificationEvidence> {
        let entropy = compute_simple_entropy(data);
        if entropy > 7.5 {
            vec![ClassificationEvidence::new(
                "very-high-entropy",
                format!("Very high entropy ({entropy:.2}) — likely packed or encrypted"),
                8,
                RiskLevel::High,
            )]
        } else if entropy > 7.0 {
            vec![ClassificationEvidence::new(
                "high-entropy",
                format!("High entropy ({entropy:.2}) — possibly packed"),
                5,
                RiskLevel::Medium,
            )]
        } else {
            Vec::new()
        }
    }

    fn string_evidence(&self, data: &[u8]) -> Vec<ClassificationEvidence> {
        let scan = &data[..data.len().min(65536)];
        let lower_string = scan
            .iter()
            .map(|&b| if b.is_ascii() { b.to_ascii_lowercase() } else { b'.' })
            .collect::<Vec<u8>>();
        let lower = std::str::from_utf8(&lower_string).unwrap_or("");
        let mut ev = Vec::new();

        for (kw, &(class, weight)) in &self.family_signatures {
            if lower.contains(kw.as_str()) {
                ev.push(ClassificationEvidence::new(
                    format!("family-sig:{kw}"),
                    format!("Family keyword matched: '{kw}' → {class}"),
                    weight,
                    if weight >= 8 { RiskLevel::Critical } else { RiskLevel::High },
                ));
            }
        }

        // Generic suspicious API patterns.
        let suspicious_apis: &[(&str, u8, RiskLevel)] = &[
            ("createremotethread", 8, RiskLevel::High),
            ("writeprocessmemory", 7, RiskLevel::High),
            ("virtualalloc", 4, RiskLevel::Medium),
            ("setwindowshookex", 7, RiskLevel::High),
            ("keylogger", 8, RiskLevel::High),
            ("cryptencrypt", 5, RiskLevel::Medium),
            ("cryptdecrypt", 5, RiskLevel::Medium),
        ];
        for &(api, w, r) in suspicious_apis {
            if lower.contains(api) {
                ev.push(ClassificationEvidence::new(
                    format!("api:{api}"),
                    format!("Suspicious API: {api}"),
                    w,
                    r,
                ));
            }
        }
        ev
    }

    fn indicator_evidence(indicators: &[TriageIndicator]) -> Vec<ClassificationEvidence> {
        indicators
            .iter()
            .map(|ind| {
                let risk = RiskLevel::from_threat(ind.threat_level);
                let weight: u8 = match ind.threat_level {
                    ThreatLevel::Critical => 9,
                    ThreatLevel::High => 7,
                    ThreatLevel::Medium => 5,
                    ThreatLevel::Low => 3,
                    ThreatLevel::Informational => 1,
                    ThreatLevel::Clean => 0,
                };
                ClassificationEvidence::new(
                    format!("indicator:{}", ind.name),
                    ind.description.clone(),
                    weight,
                    risk,
                )
            })
            .collect()
    }

    fn vote_class(
        &self,
        evidence: &[ClassificationEvidence],
        kind: FileKind,
        data: &[u8],
    ) -> (FileClass, Vec<(FileClass, u8)>) {
        let mut class_scores: HashMap<FileClass, u32> = HashMap::new();

        // Score from family signatures.
        for ev in evidence {
            if let Some(class_str) = ev.kind.strip_prefix("family-sig:")
                && let Some(&(class, weight)) = self.family_signatures.get(class_str)
            {
                *class_scores.entry(class).or_insert(0) += u32::from(weight) * 10;
            }
        }

        // Score from API strings.
        for ev in evidence {
            let kw = ev.kind.as_str();
            if kw.contains("createremotethread") || kw.contains("writeprocessmemory") {
                *class_scores.entry(FileClass::Rat).or_insert(0) += 50;
            }
            if kw.contains("keylogger") {
                *class_scores.entry(FileClass::InfoStealer).or_insert(0) += 50;
            }
            if kw.contains("cryptencrypt") || kw.contains("cryptdecrypt") {
                *class_scores.entry(FileClass::Ransomware).or_insert(0) += 20;
            }
        }

        // Format-based class hints.
        match kind {
            FileKind::Pdf | FileKind::Doc => {
                *class_scores.entry(FileClass::MaliciousDocument).or_insert(0) += 30;
            }
            FileKind::Unknown if data.len() < 4096 => {
                *class_scores.entry(FileClass::Exploit).or_insert(0) += 20;
            }
            _ => {}
        }

        // Packer detection.
        if evidence.iter().any(|e| e.kind.contains("packer") || e.kind.contains("entropy")) {
            *class_scores.entry(FileClass::Packer).or_insert(0) += 40;
        }

        let mut sorted: Vec<(FileClass, u8)> = class_scores
            .iter()
            .map(|(&c, &s)| (c, (s / 10).min(100) as u8))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        let best = sorted.first().map_or(FileClass::Unknown, |(c, _)| *c);
        let secondary = sorted.into_iter().skip(1).take(3).collect();
        (best, secondary)
    }
}

impl Default for FileClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple entropy computation (Shannon entropy in bits per byte).
fn compute_simple_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let n = data.len().min(65536);
    for &b in &data[..n] {
        freq[b as usize] += 1;
    }
    let n_f = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n_f;
            -p * p.log2()
        })
        .sum()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::None < RiskLevel::Low);
    }

    #[test]
    fn test_risk_level_score() {
        assert_eq!(RiskLevel::None.score(), 0);
        assert_eq!(RiskLevel::Critical.score(), 100);
        assert!(RiskLevel::High.score() > RiskLevel::Medium.score());
    }

    #[test]
    fn test_classification_evidence_weight_cap() {
        let ev = ClassificationEvidence::new("x", "desc", 255, RiskLevel::High);
        assert_eq!(ev.weight, 10);
    }

    #[test]
    fn test_classify_empty_clean() {
        let classifier = FileClassifier::new();
        let data = vec![0u8; 64];
        let result = classifier.classify(&data, &[], "0000");
        assert!(result.score < 50);
    }

    #[test]
    fn test_classify_meterpreter_string() {
        let classifier = FileClassifier::new();
        let mut data = vec![0u8; 128];
        let sig = b"meterpreter";
        data[10..10 + sig.len()].copy_from_slice(sig);
        let result = classifier.classify(&data, &[], "0000");
        assert!(result.risk_level >= RiskLevel::High);
        assert_eq!(result.file_class, FileClass::Rat);
    }

    #[test]
    fn test_classify_high_entropy() {
        let classifier = FileClassifier::new();
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let result = classifier.classify(&data, &[], "0000");
        assert!(result.score > 0);
    }

    #[test]
    fn test_classify_pe_format() {
        let classifier = FileClassifier::new();
        // Minimal PE magic.
        let mut data = vec![0u8; 128];
        data[0] = 0x4D;
        data[1] = 0x5A;
        let result = classifier.classify(&data, &[], "0000");
        // Should detect PE format.
        assert!(matches!(result.file_kind, FileKind::Pe32 | FileKind::Pe64));
    }

    #[test]
    fn test_classify_with_indicators() {
        let classifier = FileClassifier::new();
        let indicators = vec![TriageIndicator {
            name: "test".to_string(),
            description: "test indicator".to_string(),
            threat_level: ThreatLevel::High,
            category: "test".to_string(),
            evidence: "test".to_string(),
        }];
        let data = vec![0u8; 64];
        let result = classifier.classify(&data, &indicators, "0000");
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_summary_line() {
        let result = ClassificationResult {
            file_class: FileClass::Benign,
            risk_level: RiskLevel::None,
            score: 0,
            evidence: Vec::new(),
            secondary_classes: Vec::new(),
            sha256: "00".to_string(),
            file_kind: FileKind::Unknown,
        };
        assert!(result.summary_line().contains("score="));
    }

    #[test]
    fn test_compute_simple_entropy_all_zero() {
        let data = vec![0u8; 256];
        assert!((compute_simple_entropy(&data)).abs() < 1e-9);
    }

    #[test]
    fn test_compute_simple_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let entropy = compute_simple_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }
}
