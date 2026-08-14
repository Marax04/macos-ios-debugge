//! `VirusTotal` API v3 response data models.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Per-engine analysis statistics from a VT scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VtStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout: u32,
}

impl VtStats {
    /// Total number of engines that participated in the analysis.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.malicious + self.suspicious + self.undetected + self.harmless + self.timeout
    }

    /// Ratio of detections to total engines, in [0.0, 1.0].
    #[must_use]
    pub fn detection_ratio(&self) -> f32 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.malicious + self.suspicious) as f32 / total as f32
    }
}

/// Individual AV-engine analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtEngineResult {
    /// Detection category (e.g. `malicious`, `undetected`).
    pub category: String,
    /// Name of the AV engine.
    pub engine_name: String,
    /// Malware classification string if detected, else `None`.
    pub result: Option<String>,
    /// Detection method used.
    pub method: String,
}

/// `VirusTotal` file report (files/v3/files/{hash}).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileReport {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub name: Option<String>,
    pub size: u64,
    pub type_tag: String,
    pub last_analysis_stats: VtStats,
    pub last_analysis_results: HashMap<String, VtEngineResult>,
    pub first_submission_date: u64,
    pub tags: Vec<String>,
}

impl VtFileReport {
    /// Return `true` if any engine flagged this file as malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.last_analysis_stats.malicious > 0
    }

    /// Compute a simple VT score (0–100) based on detection ratio.
    #[must_use]
    pub fn vt_score(&self) -> f32 {
        self.last_analysis_stats.detection_ratio() * 100.0
    }
}

/// `VirusTotal` IP address report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtIpReport {
    pub ip_address: String,
    pub country: Option<String>,
    pub as_owner: Option<String>,
    pub asn: Option<u32>,
    pub last_analysis_stats: VtStats,
    pub tags: Vec<String>,
}

/// `VirusTotal` domain report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDomainReport {
    pub domain: String,
    pub registrar: Option<String>,
    pub creation_date: Option<u64>,
    pub last_analysis_stats: VtStats,
    pub tags: Vec<String>,
    pub categories: HashMap<String, String>,
}

/// `VirusTotal` URL report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtUrlReport {
    pub url: String,
    pub final_url: Option<String>,
    pub title: Option<String>,
    pub last_analysis_stats: VtStats,
    pub tags: Vec<String>,
    pub threat_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// Analysis submission types
// ---------------------------------------------------------------------------

/// Opaque analysis ID returned after a file or URL submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtAnalysisId(pub String);

impl VtAnalysisId {
    /// Create a new analysis ID wrapper.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Return the inner ID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VtAnalysisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Status of a queued or completed VT analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VtAnalysisStatus {
    /// Analysis is queued but not yet started.
    Queued,
    /// Analysis is currently in progress.
    InProgress,
    /// Analysis has finished.
    Completed,
    /// Unknown status returned by the API.
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for VtAnalysisStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::InProgress => write!(f, "in-progress"),
            Self::Completed => write!(f, "completed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Full analysis report returned by `GET /api/v3/analyses/<id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtAnalysisReport {
    /// The analysis ID.
    pub id: String,
    /// Current status of the analysis.
    pub status: VtAnalysisStatus,
    /// Per-engine results (populated once `status == Completed`).
    pub results: HashMap<String, VtEngineResult>,
    /// Summary statistics (populated once `status == Completed`).
    pub stats: VtStats,
    /// SHA-256 of the analysed file, if available.
    pub sha256: Option<String>,
}

impl VtAnalysisReport {
    /// Return `true` if the analysis has finished.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status == VtAnalysisStatus::Completed
    }

    /// Return `true` if at least one engine flagged this as malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.stats.malicious > 0
    }

    /// Detection ratio as a `"X/Y"` string.
    #[must_use]
    pub fn detection_ratio(&self) -> String {
        format!("{}/{}", self.stats.malicious, self.stats.total())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vt_stats_total() {
        let stats = VtStats {
            malicious: 10,
            suspicious: 2,
            undetected: 50,
            harmless: 0,
            timeout: 1,
        };
        assert_eq!(stats.total(), 63);
    }

    #[test]
    fn test_vt_stats_detection_ratio() {
        let stats = VtStats {
            malicious: 25,
            suspicious: 5,
            undetected: 70,
            harmless: 0,
            timeout: 0,
        };
        let ratio = stats.detection_ratio();
        assert!((ratio - 0.3_f32).abs() < 0.01);
    }

    #[test]
    fn test_vt_stats_zero_engines() {
        let stats = VtStats::default();
        assert!((stats.detection_ratio()).abs() < f32::EPSILON);
    }

    #[test]
    fn test_file_report_is_malicious() {
        let report = VtFileReport {
            sha256: "abc".to_string(),
            md5: "def".to_string(),
            sha1: "ghi".to_string(),
            name: None,
            size: 1024,
            type_tag: "peexe".to_string(),
            last_analysis_stats: VtStats {
                malicious: 5,
                ..Default::default()
            },
            last_analysis_results: HashMap::new(),
            first_submission_date: 0,
            tags: vec![],
        };
        assert!(report.is_malicious());
        assert!(report.vt_score() > 0.0);
    }

    #[test]
    fn test_file_report_serialization() {
        let report = VtFileReport {
            sha256: "deadbeef".to_string(),
            md5: "abc123".to_string(),
            sha1: "sha1val".to_string(),
            name: Some("malware.exe".to_string()),
            size: 2048,
            type_tag: "peexe".to_string(),
            last_analysis_stats: VtStats::default(),
            last_analysis_results: HashMap::new(),
            first_submission_date: 1_000_000,
            tags: vec!["ransomware".to_string()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: VtFileReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sha256, "deadbeef");
        assert_eq!(decoded.name, Some("malware.exe".to_string()));
    }
}
