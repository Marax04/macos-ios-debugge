//! Composite threat scoring from multiple `VirusTotal` signals.
//!
//! Aggregates detection ratio, community score, sandbox verdicts, file type
//! anomaly, age, and reputation into a normalized 0–100 threat score.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Input signals ────────────────────────────────────────────────────────────

/// Raw signals consumed by the threat scorer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatSignals {
    // ── AV engine detections ──────────────────────────────────────────────
    /// Number of engines that flagged the sample.
    pub positives: u32,
    /// Total number of engines that scanned the sample.
    pub total_engines: u32,

    // ── Community reputation ──────────────────────────────────────────────
    /// VT community reputation score (-100 … +100, negative = bad).
    pub community_reputation: Option<i32>,
    /// Number of community votes marking it as malicious.
    pub community_votes_malicious: u32,
    /// Number of community votes marking it as harmless.
    pub community_votes_harmless: u32,

    // ── Sandbox verdicts ─────────────────────────────────────────────────
    /// Per-sandbox verdict strings (e.g., "malicious", "suspicious", "clean").
    pub sandbox_verdicts: HashMap<String, SandboxVerdict>,

    // ── File metadata ─────────────────────────────────────────────────────
    /// Claimed type tag (e.g., "peexe", "pdf", "zip").
    pub type_tag: Option<String>,
    /// Detected MIME type (may differ from extension).
    pub detected_mime: Option<String>,
    /// True file extension (from submitted filename).
    pub file_extension: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,

    // ── Age ──────────────────────────────────────────────────────────────
    /// First submission date (UNIX timestamp). None means never seen before.
    pub first_seen_utc: Option<i64>,
    /// Last analysis date (UNIX timestamp).
    pub last_analysis_date: Option<i64>,

    // ── Network/threat intel ──────────────────────────────────────────────
    /// VT reputation for the IP/domain/URL.
    pub ip_domain_reputation: Option<i32>,
    /// Known threat categories from VT (e.g., "ransomware", "trojan").
    pub threat_categories: Vec<String>,
    /// Known threat family names from VT intelligence.
    pub threat_families: Vec<String>,
    /// Whether the file has been seen in retrohunt matches.
    pub retrohunt_matches: u32,
    /// YARA rule match count from the VT backend.
    pub yara_rule_matches: u32,
}

impl ThreatSignals {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: set detection counts.
    #[must_use] 
    pub const fn with_detections(mut self, positives: u32, total: u32) -> Self {
        self.positives = positives;
        self.total_engines = total;
        self
    }

    /// Convenience: set community votes.
    #[must_use] 
    pub const fn with_community(mut self, reputation: i32, malicious: u32, harmless: u32) -> Self {
        self.community_reputation = Some(reputation);
        self.community_votes_malicious = malicious;
        self.community_votes_harmless = harmless;
        self
    }

    #[must_use] 
    pub fn detection_ratio(&self) -> f64 {
        if self.total_engines == 0 {
            return 0.0;
        }
        f64::from(self.positives) / f64::from(self.total_engines)
    }
}

/// Sandbox verdict for a single sandbox engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVerdict {
    /// "malicious", "suspicious", "clean", "timeout", "error"
    pub verdict: String,
    /// Optional malware family name identified by the sandbox.
    pub malware_family: Option<String>,
    /// Confidence level 0.0–1.0 if provided.
    pub confidence: Option<f64>,
}

impl SandboxVerdict {
    #[must_use] 
    pub fn is_malicious(&self) -> bool {
        matches!(self.verdict.as_str(), "malicious")
    }

    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        matches!(self.verdict.as_str(), "suspicious")
    }

    #[must_use] 
    pub fn weighted_score(&self) -> f64 {
        let base = match self.verdict.as_str() {
            "malicious" => 1.0,
            "suspicious" => 0.5,
            "clean" | "harmless" => 0.0,
            _ => 0.1, // timeout/error are mildly suspicious
        };
        let conf = self.confidence.unwrap_or(0.8);
        base * conf
    }
}

// ─── Scoring configuration ────────────────────────────────────────────────────

/// Weights for each signal component (must sum to ~1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    /// Weight of AV detection ratio component.
    pub detection_weight: f64,
    /// Weight of community reputation component.
    pub community_weight: f64,
    /// Weight of sandbox verdicts component.
    pub sandbox_weight: f64,
    /// Weight of file type anomaly component.
    pub file_type_weight: f64,
    /// Weight of file age component.
    pub age_weight: f64,
    /// Weight of threat intel (families, rules, categories) component.
    pub threat_intel_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            detection_weight: 0.40,
            community_weight: 0.10,
            sandbox_weight: 0.20,
            file_type_weight: 0.10,
            age_weight: 0.05,
            threat_intel_weight: 0.15,
        }
    }
}

impl ScoringWeights {
    #[must_use] 
    pub const fn av_heavy() -> Self {
        Self {
            detection_weight: 0.60,
            community_weight: 0.05,
            sandbox_weight: 0.15,
            file_type_weight: 0.05,
            age_weight: 0.05,
            threat_intel_weight: 0.10,
        }
    }

    #[must_use] 
    pub const fn sandbox_heavy() -> Self {
        Self {
            detection_weight: 0.25,
            community_weight: 0.05,
            sandbox_weight: 0.40,
            file_type_weight: 0.10,
            age_weight: 0.05,
            threat_intel_weight: 0.15,
        }
    }

    /// Verify weights sum to approximately 1.0.
    #[must_use] 
    pub fn is_valid(&self) -> bool {
        let sum = self.detection_weight
            + self.community_weight
            + self.sandbox_weight
            + self.file_type_weight
            + self.age_weight
            + self.threat_intel_weight;
        (sum - 1.0).abs() < 0.01
    }
}

// ─── Component scores ─────────────────────────────────────────────────────────

/// Detailed breakdown of each scoring component.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScoreBreakdown {
    /// Raw score 0.0–1.0 for AV detections.
    pub detection_score: f64,
    /// Raw score 0.0–1.0 for community reputation.
    pub community_score: f64,
    /// Raw score 0.0–1.0 for sandbox verdicts.
    pub sandbox_score: f64,
    /// Raw score 0.0–1.0 for file type anomaly.
    pub file_type_score: f64,
    /// Raw score 0.0–1.0 for file age.
    pub age_score: f64,
    /// Raw score 0.0–1.0 for threat intel signals.
    pub threat_intel_score: f64,
    /// Weighted composite score 0.0–1.0.
    pub composite_raw: f64,
    /// Final normalized integer score 0–100.
    pub final_score: u8,
    /// Threat level classification.
    pub threat_level: ThreatLevel,
    /// Key reasons that drove the score up.
    pub key_factors: Vec<String>,
}

/// Threat level derived from the final score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ThreatLevel {
    #[default]
    Clean,
    Suspicious,
    ProbablyMalicious,
    Malicious,
    HighlyMalicious,
}

impl ThreatLevel {
    #[must_use] 
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=15 => Self::Clean,
            16..=35 => Self::Suspicious,
            36..=60 => Self::ProbablyMalicious,
            61..=80 => Self::Malicious,
            _ => Self::HighlyMalicious,
        }
    }

    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::ProbablyMalicious => "probably_malicious",
            Self::Malicious => "malicious",
            Self::HighlyMalicious => "highly_malicious",
        }
    }
}


// ─── Scorer ───────────────────────────────────────────────────────────────────

/// Computes composite threat scores from raw VT signals.
pub struct ThreatScorer {
    pub weights: ScoringWeights,
}

impl ThreatScorer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
        }
    }

    #[must_use] 
    pub const fn with_weights(weights: ScoringWeights) -> Self {
        Self { weights }
    }

    // ── Component scorers ────────────────────────────────────────────────

    /// Score based on AV detection ratio. Uses a curve: 0% → 0.0, 10% → 0.3, 30% → 0.7, 100% → 1.0.
    fn score_detection(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        let ratio = signals.detection_ratio();
        let score = if ratio == 0.0 {
            0.0
        } else if ratio < 0.05 {
            // 1–4% detection — might be heuristic FP but somewhat suspicious
            ratio.mul_add(2.0, 0.15)
        } else if ratio < 0.15 {
            (ratio - 0.05).mul_add(3.5, 0.25)
        } else if ratio < 0.50 {
            (ratio - 0.15).mul_add(0.80, 0.60)
        } else {
            (ratio - 0.50).mul_add(0.24, 0.88)
        }
        .min(1.0);

        if score > 0.6 {
            factors.push(format!(
                "AV detection: {}/{} ({:.0}%)",
                signals.positives,
                signals.total_engines,
                ratio * 100.0
            ));
        }
        score
    }

    /// Score based on community reputation and votes.
    fn score_community(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        let mut score = 0.0_f64;

        // Community reputation: -100 = max bad, +100 = max good
        if let Some(rep) = signals.community_reputation {
            let rep_score = if rep < -50 {
                1.0
            } else if rep < 0 {
                0.5 + (f64::from(-rep) / 100.0)
            } else if rep < 10 {
                0.1
            } else {
                0.0
            };
            score = score.max(rep_score);
        }

        // Vote ratio
        let total_votes = signals.community_votes_malicious + signals.community_votes_harmless;
        if total_votes > 0 {
            let mal_ratio =
                f64::from(signals.community_votes_malicious) / f64::from(total_votes);
            score = score.max(mal_ratio * 0.9);

            if mal_ratio > 0.7 {
                factors.push(format!(
                    "Community votes: {}/{} malicious",
                    signals.community_votes_malicious, total_votes
                ));
            }
        }

        score.min(1.0)
    }

    /// Score based on sandbox verdict aggregation.
    fn score_sandbox(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        if signals.sandbox_verdicts.is_empty() {
            return 0.0;
        }

        let total = signals.sandbox_verdicts.len() as f64;
        let weighted_sum: f64 = signals
            .sandbox_verdicts
            .values()
            .map(SandboxVerdict::weighted_score)
            .sum();

        let score = (weighted_sum / total).min(1.0);

        let malicious_sandboxes: Vec<&str> = signals
            .sandbox_verdicts
            .iter()
            .filter(|(_, v)| v.is_malicious())
            .map(|(k, _)| k.as_str())
            .collect();

        if !malicious_sandboxes.is_empty() {
            factors.push(format!(
                "Sandbox malicious: {}",
                malicious_sandboxes.join(", ")
            ));
        }

        score
    }

    /// Score based on file type mismatch (extension vs detected type).
    fn score_file_type(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        let ext = signals.file_extension.as_deref().unwrap_or("");
        let detected = signals.detected_mime.as_deref().unwrap_or("");
        let type_tag = signals.type_tag.as_deref().unwrap_or("");

        // Known dangerous types
        let dangerous_types = [
            "peexe", "pedll", "elf", "macho", "msi", "bat", "cmd", "ps1", "vbs", "js",
        ];
        let base_score: f64 = if dangerous_types.contains(&type_tag) {
            0.2
        } else {
            0.0
        };

        // Extension mismatch detection
        let mismatch = !ext.is_empty()
            && !detected.is_empty()
            && !Self::extension_matches_mime(ext, detected);

        let mismatch_score = if mismatch {
            factors.push(format!(
                "File type mismatch: extension=.{ext}, detected={detected}"
            ));
            0.7
        } else {
            0.0
        };

        // Unusual size for claimed type
        let size_score = signals.file_size.map_or(0.0, |size| match type_tag {
                "peexe" | "pedll" if size < 512 => {
                    factors.push("Suspiciously small PE file".to_owned());
                    0.5
                }
                "pdf" if size < 64 => {
                    factors.push("Suspiciously small PDF".to_owned());
                    0.4
                }
                _ => 0.0,
            });

        (base_score + mismatch_score + size_score).min(1.0)
    }

    fn extension_matches_mime(ext: &str, mime: &str) -> bool {
        matches!(
            (ext, mime),
            ("exe" | "dll", "application/x-dosexec" | "application/x-msdownload")
                | ("pdf", "application/pdf")
                | ("zip", "application/zip")
                | ("rar", "application/x-rar-compressed")
                | ("js", "application/javascript" | "text/javascript")
                | ("vbs", "text/vbscript")
                | ("ps1", "text/x-powershell")
                | ("doc" | "docx", "application/msword" | "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                | ("xls" | "xlsx", "application/vnd.ms-excel" | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        )
    }

    /// Score based on file age. Very new files (never seen before) are more suspicious.
    fn score_age(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);

        match signals.first_seen_utc {
            None => {
                // Never seen before = high suspicion
                factors.push("First submission — never seen before".to_owned());
                0.8
            }
            Some(ts) => {
                let age_days = (now - ts).max(0) / 86400;
                if age_days < 1 {
                    // Less than 24 hours old
                    factors.push("Very new sample (< 1 day old)".to_owned());
                    0.6
                } else if age_days < 7 {
                    0.3
                } else if age_days < 30 {
                    0.1
                } else {
                    // Old known file, not suspicious on its own
                    0.0
                }
            }
        }
    }

    /// Score based on threat intel signals.
    fn score_threat_intel(&self, signals: &ThreatSignals, factors: &mut Vec<String>) -> f64 {
        let mut score = 0.0_f64;

        // Known threat families
        if !signals.threat_families.is_empty() {
            factors.push(format!(
                "Known families: {}",
                signals.threat_families.join(", ")
            ));
            score = score.max(0.9);
        }

        // Threat categories
        let high_risk_cats = ["ransomware", "trojan", "worm", "rootkit", "backdoor", "exploit"];
        for cat in &signals.threat_categories {
            if high_risk_cats.iter().any(|h| cat.to_lowercase().contains(h)) {
                factors.push(format!("Threat category: {cat}"));
                score = score.max(0.85);
            } else {
                score = score.max(0.5);
            }
        }

        // Retrohunt / YARA matches
        if signals.retrohunt_matches > 0 {
            factors.push(format!("{} retrohunt rule matches", signals.retrohunt_matches));
            score = score.max(0.6 + (f64::from(signals.retrohunt_matches) * 0.05).min(0.3));
        }
        if signals.yara_rule_matches > 0 {
            score = score.max(0.4 + (f64::from(signals.yara_rule_matches) * 0.05).min(0.4));
        }

        // IP/domain reputation
        if let Some(rep) = signals.ip_domain_reputation {
            if rep < -50 {
                factors.push(format!("Bad IP/domain reputation: {rep}"));
                score = score.max(0.8);
            } else if rep < 0 {
                score = score.max(0.4);
            }
        }

        score.min(1.0)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Compute the full threat score from raw signals.
    #[must_use] 
    pub fn score(&self, signals: &ThreatSignals) -> ScoreBreakdown {
        let mut factors: Vec<String> = Vec::new();

        let ds = self.score_detection(signals, &mut factors);
        let cs = self.score_community(signals, &mut factors);
        let ss = self.score_sandbox(signals, &mut factors);
        let fs = self.score_file_type(signals, &mut factors);
        let age_s = self.score_age(signals, &mut factors);
        let ts = self.score_threat_intel(signals, &mut factors);

        let composite = ts.mul_add(self.weights.threat_intel_weight, age_s.mul_add(self.weights.age_weight, fs.mul_add(self.weights.file_type_weight, ss.mul_add(self.weights.sandbox_weight, ds.mul_add(self.weights.detection_weight, cs * self.weights.community_weight)))));

        let composite = composite.clamp(0.0, 1.0);
        let final_score = (composite * 100.0).round() as u8;
        let threat_level = ThreatLevel::from_score(final_score);

        ScoreBreakdown {
            detection_score: ds,
            community_score: cs,
            sandbox_score: ss,
            file_type_score: fs,
            age_score: age_s,
            threat_intel_score: ts,
            composite_raw: composite,
            final_score,
            threat_level,
            key_factors: factors,
        }
    }

    /// Quick method that returns just the 0–100 integer score.
    #[must_use] 
    pub fn quick_score(&self, signals: &ThreatSignals) -> u8 {
        self.score(signals).final_score
    }
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Batch scoring ────────────────────────────────────────────────────────────

/// Score a batch of (id, signals) pairs in parallel using rayon.
#[must_use] 
pub fn batch_score(
    pairs: &[(String, ThreatSignals)],
    weights: Option<ScoringWeights>,
) -> Vec<(String, ScoreBreakdown)> {
    use rayon::prelude::*;
    let scorer = ThreatScorer::with_weights(weights.unwrap_or_default());
    pairs
        .par_iter()
        .map(|(id, signals)| (id.clone(), scorer.score(signals)))
        .collect()
}

// ─── Score summarizer ─────────────────────────────────────────────────────────

/// Summary statistics over a batch of scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScoreSummary {
    pub total: usize,
    pub clean: usize,
    pub suspicious: usize,
    pub probably_malicious: usize,
    pub malicious: usize,
    pub highly_malicious: usize,
    pub mean_score: f64,
    pub max_score: u8,
    pub min_score: u8,
    pub top_factors: Vec<(String, usize)>,
}

impl BatchScoreSummary {
    #[must_use] 
    pub fn from_scores(scores: &[(String, ScoreBreakdown)]) -> Self {
        if scores.is_empty() {
            return Self {
                total: 0,
                clean: 0,
                suspicious: 0,
                probably_malicious: 0,
                malicious: 0,
                highly_malicious: 0,
                mean_score: 0.0,
                max_score: 0,
                min_score: 0,
                top_factors: vec![],
            };
        }

        let mut clean = 0usize;
        let mut suspicious = 0usize;
        let mut probably_malicious = 0usize;
        let mut malicious = 0usize;
        let mut highly_malicious = 0usize;
        let mut sum = 0u32;
        let mut max_s = 0u8;
        let mut min_s = 255u8;
        let mut factor_counts: HashMap<String, usize> = HashMap::new();

        for (_, bd) in scores {
            match bd.threat_level {
                ThreatLevel::Clean => clean += 1,
                ThreatLevel::Suspicious => suspicious += 1,
                ThreatLevel::ProbablyMalicious => probably_malicious += 1,
                ThreatLevel::Malicious => malicious += 1,
                ThreatLevel::HighlyMalicious => highly_malicious += 1,
            }
            sum += u32::from(bd.final_score);
            max_s = max_s.max(bd.final_score);
            min_s = min_s.min(bd.final_score);
            for f in &bd.key_factors {
                // Normalize factor strings to categories
                let key = if f.starts_with("AV detection") {
                    "AV detections"
                } else if f.starts_with("Community") {
                    "Community votes"
                } else if f.starts_with("Sandbox") {
                    "Sandbox malicious"
                } else if f.starts_with("Known famil") {
                    "Known threat family"
                } else if f.starts_with("Threat category") {
                    "Threat category"
                } else {
                    f.as_str()
                };
                *factor_counts.entry(key.to_owned()).or_insert(0) += 1;
            }
        }

        let n = scores.len();
        let mean_score = f64::from(sum) / n as f64;

        let mut top_factors: Vec<(String, usize)> = factor_counts.into_iter().collect();
        top_factors.sort_by(|a, b| b.1.cmp(&a.1));
        top_factors.truncate(10);

        Self {
            total: n,
            clean,
            suspicious,
            probably_malicious,
            malicious,
            highly_malicious,
            mean_score,
            max_score: max_s,
            min_score: min_s,
            top_factors,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_signals() -> ThreatSignals {
        ThreatSignals::new()
            .with_detections(0, 70)
            .with_community(50, 0, 100)
    }

    fn malicious_signals() -> ThreatSignals {
        let mut s = ThreatSignals::new()
            .with_detections(55, 70)
            .with_community(-80, 90, 5);
        s.sandbox_verdicts.insert(
            "Cuckoo".to_owned(),
            SandboxVerdict {
                verdict: "malicious".to_owned(),
                malware_family: Some("WannaCry".to_owned()),
                confidence: Some(0.95),
            },
        );
        s.threat_families = vec!["WannaCry".to_owned()];
        s
    }

    #[test]
    fn test_clean_low_score() {
        let scorer = ThreatScorer::new();
        let bd = scorer.score(&clean_signals());
        assert!(bd.final_score < 20, "clean file should score < 20, got {}", bd.final_score);
        assert_eq!(bd.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn test_malicious_high_score() {
        let scorer = ThreatScorer::new();
        let bd = scorer.score(&malicious_signals());
        assert!(bd.final_score > 60, "malicious should score > 60, got {}", bd.final_score);
    }

    #[test]
    fn test_detection_ratio() {
        let s = ThreatSignals::new().with_detections(35, 70);
        assert!((s.detection_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_batch_score() {
        let pairs = vec![
            ("clean".to_owned(), clean_signals()),
            ("mal".to_owned(), malicious_signals()),
        ];
        let results = batch_score(&pairs, None);
        assert_eq!(results.len(), 2);
        let clean_bd = results.iter().find(|(id, _)| id == "clean").unwrap();
        let mal_bd = results.iter().find(|(id, _)| id == "mal").unwrap();
        assert!(clean_bd.1.final_score < mal_bd.1.final_score);
    }

    #[test]
    fn test_batch_summary() {
        let pairs = vec![
            ("clean".to_owned(), clean_signals()),
            ("mal".to_owned(), malicious_signals()),
        ];
        let results = batch_score(&pairs, None);
        let summary = BatchScoreSummary::from_scores(&results);
        assert_eq!(summary.total, 2);
    }

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(50), ThreatLevel::ProbablyMalicious);
        assert_eq!(ThreatLevel::from_score(90), ThreatLevel::HighlyMalicious);
    }

    #[test]
    fn test_file_type_mismatch() {
        let mut s = ThreatSignals::new().with_detections(0, 70);
        s.file_extension = Some("pdf".to_owned());
        s.detected_mime = Some("application/x-dosexec".to_owned());
        s.type_tag = Some("peexe".to_owned());
        let scorer = ThreatScorer::new();
        let bd = scorer.score(&s);
        assert!(
            bd.file_type_score > 0.5,
            "mismatch should have high file_type_score"
        );
    }
}
