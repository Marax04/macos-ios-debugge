//! `rustre-sandbox-report` —  Sandbox report generation.
//!
//! Parses behavior records, classifies malicious indicators, generates IOCs,
//! produces HTML/JSON/Markdown reports, scores samples, and maps to MITRE ATT&CK.

use std::fmt::Write as _;
pub mod html_reporter;
pub mod json_reporter;
pub mod mitre_mapping_full;
pub mod network_timeline;
pub mod pdf_export;
pub mod pdf_reporter;
pub mod process_tree_render;
pub mod report_builder;
pub mod report_generator_extended;
pub mod json_report_builder;
pub mod html_report_builder;
pub mod ioc_extractor;

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors that can occur during report generation.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("serialize error: {0}")]
    Serialize(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("template error: {0}")]
    Template(String),
    #[error("missing field: {0}")]
    MissingField(String),
}

// â"€â"€â"€ Severity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Severity level for an indicator or behavior.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Numeric score: Info=0, Low=25, Medium=50, High=75, Critical=100.
    #[must_use]
    pub const fn score(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }

    /// Parse from a string (case-insensitive).
    ///
    /// # Errors
    /// Returns `ReportError::InvalidData` for unknown strings.
    pub fn parse(s: &str) -> Result<Self, ReportError> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(ReportError::InvalidData(format!(
                "unknown severity: {other}"
            ))),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// â"€â"€â"€ IocKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The kind of an Indicator of Compromise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocKind {
    Ip,
    Domain,
    Url,
    FilePath,
    FileHash,
    RegistryKey,
    Mutex,
    Email,
    Other(String),
}

impl fmt::Display for IocKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip => write!(f, "ip"),
            Self::Domain => write!(f, "domain"),
            Self::Url => write!(f, "url"),
            Self::FilePath => write!(f, "filepath"),
            Self::FileHash => write!(f, "filehash"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::Mutex => write!(f, "mutex"),
            Self::Email => write!(f, "email"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// â"€â"€â"€ Ioc â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An Indicator of Compromise extracted from sandbox data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub confidence: u8,
    pub context: String,
}

impl Ioc {
    /// Create a new IOC.
    #[must_use]
    pub fn new(
        kind: IocKind,
        value: impl Into<String>,
        confidence: u8,
        context: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            value: value.into(),
            confidence: confidence.min(100),
            context: context.into(),
        }
    }

    /// Returns `true` if this IOC has confidence above the given threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}

// â"€â"€â"€ IocSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A collection of IOCs extracted from a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSet {
    pub iocs: Vec<Ioc>,
}

impl IocSet {
    /// Create an empty IOC set.
    #[must_use]
    pub const fn new() -> Self {
        Self { iocs: vec![] }
    }

    /// Add an IOC.
    pub fn add(&mut self, ioc: Ioc) {
        self.iocs.push(ioc);
    }

    /// Return all IOCs of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: &IocKind) -> Vec<&Ioc> {
        self.iocs.iter().filter(|i| &i.kind == kind).collect()
    }

    /// Return all IOCs above the given confidence threshold.
    #[must_use]
    pub fn confident(&self, threshold: u8) -> Vec<&Ioc> {
        self.iocs
            .iter()
            .filter(|i| i.is_confident(threshold))
            .collect()
    }

    /// Deduplicate IOCs by `(kind, value)`.
    pub fn deduplicate(&mut self) {
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        self.iocs.retain(|i| {
            let key = (i.kind.to_string(), i.value.clone());
            seen.insert(key)
        });
    }

    /// Total number of IOCs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.iocs.len()
    }

    /// Returns `true` if there are no IOCs.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Create a mock IOC set for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut set = Self::new();
        set.add(Ioc::new(IocKind::Ip, "185.220.101.1", 95, "C2 beacon"));
        set.add(Ioc::new(IocKind::Domain, "c2server.evil", 90, "DNS query"));
        set.add(Ioc::new(
            IocKind::FilePath,
            "C:\\Windows\\Temp\\payload.exe",
            100,
            "dropped file",
        ));
        set.add(Ioc::new(
            IocKind::FileHash,
            "deadbeefcafe0123456789abcdef0123456789ab",
            100,
            "SHA-1 of payload",
        ));
        set.add(Ioc::new(
            IocKind::RegistryKey,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            85,
            "persistence",
        ));
        set.add(Ioc::new(
            IocKind::Mutex,
            "Global\\MalwareMutex_v2",
            70,
            "mutex seen during run",
        ));
        set
    }
}

impl Default for IocSet {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ AttackTechnique â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    /// Technique ID, e.g. `"T1055"`.
    pub id: String,
    /// Sub-technique ID, e.g. `"T1055.001"`, or `None` for top-level.
    pub sub_id: Option<String>,
    /// Technique name.
    pub name: String,
    /// Tactic this technique belongs to.
    pub tactic: AttackTactic,
    /// Evidence for this technique from the sandbox run.
    pub evidence: Vec<String>,
    /// Confidence (0—"100).
    pub confidence: u8,
}

impl AttackTechnique {
    /// Full ID including sub-technique if present.
    #[must_use]
    pub fn full_id(&self) -> &str {
        self.sub_id.as_deref().unwrap_or(&self.id)
    }
}

/// MITRE ATT&CK tactic categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl fmt::Display for AttackTactic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialAccess => write!(f, "initial_access"),
            Self::Execution => write!(f, "execution"),
            Self::Persistence => write!(f, "persistence"),
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::DefenseEvasion => write!(f, "defense_evasion"),
            Self::CredentialAccess => write!(f, "credential_access"),
            Self::Discovery => write!(f, "discovery"),
            Self::LateralMovement => write!(f, "lateral_movement"),
            Self::Collection => write!(f, "collection"),
            Self::CommandAndControl => write!(f, "command_and_control"),
            Self::Exfiltration => write!(f, "exfiltration"),
            Self::Impact => write!(f, "impact"),
        }
    }
}

// â"€â"€â"€ AttackMapping â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Maps observed behaviors to MITRE ATT&CK techniques.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    pub techniques: Vec<AttackTechnique>,
}

impl AttackMapping {
    /// Create an empty mapping.
    #[must_use]
    pub const fn new() -> Self {
        Self { techniques: vec![] }
    }

    /// Add a technique.
    pub fn add(&mut self, t: AttackTechnique) {
        self.techniques.push(t);
    }

    /// Return techniques by tactic.
    #[must_use]
    pub fn by_tactic(&self, tactic: &AttackTactic) -> Vec<&AttackTechnique> {
        self.techniques
            .iter()
            .filter(|t| &t.tactic == tactic)
            .collect()
    }

    /// Return all unique tactic names present.
    #[must_use]
    pub fn tactics_present(&self) -> Vec<String> {
        let mut tactics: Vec<String> = self
            .techniques
            .iter()
            .map(|t| t.tactic.to_string())
            .collect();
        tactics.sort();
        tactics.dedup();
        tactics
    }

    /// Return all technique IDs.
    #[must_use]
    pub fn technique_ids(&self) -> Vec<&str> {
        self.techniques
            .iter()
            .map(AttackTechnique::full_id)
            .collect()
    }

    /// Return high-confidence (>= 80) techniques.
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&AttackTechnique> {
        self.techniques
            .iter()
            .filter(|t| t.confidence >= 80)
            .collect()
    }

    /// Build a standard mapping from a list of observed behavior tags.
    #[must_use]
    pub fn from_behaviors(tags: &[&str]) -> Self {
        let mut mapping = Self::new();
        for tag in tags {
            match *tag {
                "injection" => {
                    mapping.add(AttackTechnique {
                        id: "T1055".to_string(),
                        sub_id: Some("T1055.001".to_string()),
                        name: "Process Injection: Dynamic-link Library Injection".to_string(),
                        tactic: AttackTactic::DefenseEvasion,
                        evidence: vec![
                            "WriteProcessMemory + CreateRemoteThread observed".to_string(),
                        ],
                        confidence: 90,
                    });
                }
                "persistence" => {
                    mapping.add(AttackTechnique {
                        id: "T1547".to_string(),
                        sub_id: Some("T1547.001".to_string()),
                        name: "Boot or Logon Autostart Execution: Registry Run Keys".to_string(),
                        tactic: AttackTactic::Persistence,
                        evidence: vec!["Run key set in HKCU".to_string()],
                        confidence: 95,
                    });
                }
                "anti-analysis" | "antianalysis" => {
                    mapping.add(AttackTechnique {
                        id: "T1497".to_string(),
                        sub_id: None,
                        name: "Virtualization/Sandbox Evasion".to_string(),
                        tactic: AttackTactic::DefenseEvasion,
                        evidence: vec!["IsDebuggerPresent called".to_string()],
                        confidence: 85,
                    });
                }
                "c2" | "network" => {
                    mapping.add(AttackTechnique {
                        id: "T1071".to_string(),
                        sub_id: Some("T1071.001".to_string()),
                        name: "Application Layer Protocol: Web Protocols".to_string(),
                        tactic: AttackTactic::CommandAndControl,
                        evidence: vec!["HTTPS C2 beacon observed".to_string()],
                        confidence: 88,
                    });
                }
                "dropper" | "downloader" => {
                    mapping.add(AttackTechnique {
                        id: "T1105".to_string(),
                        sub_id: None,
                        name: "Ingress Tool Transfer".to_string(),
                        tactic: AttackTactic::CommandAndControl,
                        evidence: vec!["Executable dropped to disk".to_string()],
                        confidence: 80,
                    });
                }
                "keylogger" => {
                    mapping.add(AttackTechnique {
                        id: "T1056".to_string(),
                        sub_id: Some("T1056.001".to_string()),
                        name: "Input Capture: Keylogging".to_string(),
                        tactic: AttackTactic::Collection,
                        evidence: vec!["SetWindowsHookEx(WH_KEYBOARD_LL) observed".to_string()],
                        confidence: 90,
                    });
                }
                "ransomware" => {
                    mapping.add(AttackTechnique {
                        id: "T1486".to_string(),
                        sub_id: None,
                        name: "Data Encrypted for Impact".to_string(),
                        tactic: AttackTactic::Impact,
                        evidence: vec!["Mass file encryption observed".to_string()],
                        confidence: 97,
                    });
                }
                "screenshot" => {
                    mapping.add(AttackTechnique {
                        id: "T1113".to_string(),
                        sub_id: None,
                        name: "Screen Capture".to_string(),
                        tactic: AttackTactic::Collection,
                        evidence: vec!["GDI screen capture APIs used".to_string()],
                        confidence: 80,
                    });
                }
                "worm" => {
                    mapping.add(AttackTechnique {
                        id: "T1210".to_string(),
                        sub_id: None,
                        name: "Exploitation of Remote Services".to_string(),
                        tactic: AttackTactic::LateralMovement,
                        evidence: vec!["Network self-propagation observed".to_string()],
                        confidence: 75,
                    });
                }
                _ => {}
            }
        }
        mapping
    }
}

impl Default for AttackMapping {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ Indicator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A behavioral indicator (higher-level than an IOC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub name: String,
    pub desc: String,
    pub severity: Severity,
    pub ioc: Option<String>,
    pub technique_ids: Vec<String>,
    pub category: IndicatorCategory,
}

impl Indicator {
    /// Create an indicator.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        desc: impl Into<String>,
        severity: Severity,
        category: IndicatorCategory,
    ) -> Self {
        Self {
            name: name.into(),
            desc: desc.into(),
            severity,
            ioc: None,
            technique_ids: vec![],
            category,
        }
    }

    /// Attach an IOC string.
    #[must_use]
    pub fn with_ioc(mut self, ioc: impl Into<String>) -> Self {
        self.ioc = Some(ioc.into());
        self
    }

    /// Attach a technique ID.
    #[must_use]
    pub fn with_technique(mut self, id: impl Into<String>) -> Self {
        self.technique_ids.push(id.into());
        self
    }
}

/// Category for an indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorCategory {
    Injection,
    Network,
    Persistence,
    Evasion,
    Crypto,
    Dropper,
    Keylogging,
    Ransomware,
    Reconnaissance,
    Other,
}

impl fmt::Display for IndicatorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Injection => write!(f, "injection"),
            Self::Network => write!(f, "network"),
            Self::Persistence => write!(f, "persistence"),
            Self::Evasion => write!(f, "evasion"),
            Self::Crypto => write!(f, "crypto"),
            Self::Dropper => write!(f, "dropper"),
            Self::Keylogging => write!(f, "keylogging"),
            Self::Ransomware => write!(f, "ransomware"),
            Self::Reconnaissance => write!(f, "reconnaissance"),
            Self::Other => write!(f, "other"),
        }
    }
}

// â"€â"€â"€ Behavior â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A high-level behavior description, e.g. "Process Injection".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Behavior {
    pub name: String,
    pub desc: String,
    pub severity: Severity,
    pub apis: Vec<String>,
    pub category: String,
    pub first_seen_ms: u64,
    pub pid: u32,
}

impl Behavior {
    /// Create a new behavior entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        desc: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            desc: desc.into(),
            severity,
            apis: vec![],
            category: category.into(),
            first_seen_ms: 0,
            pid: 0,
        }
    }

    /// Add an API name to the evidence list.
    #[must_use]
    pub fn with_api(mut self, api: impl Into<String>) -> Self {
        self.apis.push(api.into());
        self
    }
}

// â"€â"€â"€ Verdict â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// High-level verdict for the analyzed sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    /// A single low-weight indicator was observed; likely benign but worth noting.
    Low,
    Suspicious,
    Malicious,
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Low => write!(f, "low"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Malicious => write!(f, "malicious"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// â"€â"€â"€ ReportSection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A named section within a report (e.g. "Summary", "IOCs", "ATT&CK").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: String,
    pub order: u32,
}

impl ReportSection {
    /// Create a new section.
    #[must_use]
    pub fn new(title: impl Into<String>, content: impl Into<String>, order: u32) -> Self {
        Self {
            title: title.into(),
            content: content.into(),
            order,
        }
    }
}

// â"€â"€â"€ ScoreEngine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Computes a numeric threat score and verdict from indicators.
#[derive(Debug, Clone)]
pub struct ScoreEngine {
    /// Weight for each `IndicatorCategory`.
    category_weights: HashMap<String, u32>,
    /// Hard cap for the computed score.
    cap: u32,
}

impl ScoreEngine {
    /// Create a default score engine with sensible weights.
    #[must_use]
    pub fn new() -> Self {
        let mut w = HashMap::new();
        w.insert("injection".to_string(), 25);
        w.insert("ransomware".to_string(), 30);
        w.insert("keylogging".to_string(), 20);
        w.insert("persistence".to_string(), 15);
        w.insert("network".to_string(), 10);
        w.insert("evasion".to_string(), 15);
        w.insert("dropper".to_string(), 15);
        w.insert("crypto".to_string(), 5);
        w.insert("reconnaissance".to_string(), 5);
        w.insert("other".to_string(), 5);
        Self {
            category_weights: w,
            cap: 100,
        }
    }

    /// Compute the score for a list of indicators.
    #[must_use]
    pub fn compute(&self, indicators: &[Indicator]) -> u32 {
        let mut score = 0u32;
        for ind in indicators {
            let base = u32::from(ind.severity.score());
            let cat_weight = self
                .category_weights
                .get(&ind.category.to_string())
                .copied()
                .unwrap_or(5);
            // weighted score = base * cat_weight / 100
            score = score.saturating_add(base.saturating_mul(cat_weight) / 100);
        }
        score.min(self.cap)
    }

    /// Determine the verdict from a numeric score.
    ///
    /// - `0`       → Clean
    /// - `1..=30`  → Low (a single low-weight indicator; likely benign)
    /// - `31..=70` → Suspicious (multiple or medium-severity indicators)
    /// - `71..`    → Malicious
    #[must_use]
    pub const fn verdict(&self, score: u32) -> Verdict {
        match score {
            0 => Verdict::Clean,
            1..=30 => Verdict::Low,
            31..=70 => Verdict::Suspicious,
            _ => Verdict::Malicious,
        }
    }

    /// Returns `true` if any indicator is `Critical`.
    #[must_use]
    pub fn has_critical(indicators: &[Indicator]) -> bool {
        indicators.iter().any(|i| i.severity == Severity::Critical)
    }
}

impl Default for ScoreEngine {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ BehaviorClassifier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Classifies raw behavior observations into `Indicator` and `Behavior` instances.
#[derive(Debug, Clone, Default)]
pub struct BehaviorClassifier;

impl BehaviorClassifier {
    /// Create a new classifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify a list of API call names into behaviors and indicators.
    #[must_use]
    pub fn classify(&self, api_calls: &[&str]) -> (Vec<Indicator>, Vec<Behavior>) {
        let mut indicators: Vec<Indicator> = vec![];
        let mut behaviors: Vec<Behavior> = vec![];
        Self::classify_injection_and_persistence(api_calls, &mut indicators, &mut behaviors);
        Self::classify_network_and_evasion(api_calls, &mut indicators, &mut behaviors);
        Self::classify_crypto_hook_and_screen(api_calls, &mut indicators);
        (indicators, behaviors)
    }

    fn classify_injection_and_persistence(
        api_calls: &[&str],
        indicators: &mut Vec<Indicator>,
        behaviors: &mut Vec<Behavior>,
    ) {
        let has_virtual_alloc_ex = api_calls.contains(&"VirtualAllocEx");
        let has_write_proc_mem = api_calls.contains(&"WriteProcessMemory");
        let has_create_remote = api_calls.contains(&"CreateRemoteThread");
        if has_virtual_alloc_ex && has_write_proc_mem && has_create_remote {
            indicators.push(
                Indicator::new(
                    "Classic Process Injection",
                    "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread observed",
                    Severity::Critical,
                    IndicatorCategory::Injection,
                )
                .with_technique("T1055.001"),
            );
            behaviors.push(
                Behavior::new(
                    "Process Injection",
                    "Injects shellcode into a remote process",
                    Severity::Critical,
                    "injection",
                )
                .with_api("VirtualAllocEx")
                .with_api("WriteProcessMemory")
                .with_api("CreateRemoteThread"),
            );
        }
        let has_reg_set =
            api_calls.contains(&"RegSetValue") || api_calls.contains(&"NtSetValueKey");
        if has_reg_set {
            indicators.push(
                Indicator::new(
                    "Registry Modification",
                    "SetValue on registry (possible persistence)",
                    Severity::Medium,
                    IndicatorCategory::Persistence,
                )
                .with_technique("T1547.001"),
            );
        }
    }

    fn classify_network_and_evasion(
        api_calls: &[&str],
        indicators: &mut Vec<Indicator>,
        behaviors: &mut Vec<Behavior>,
    ) {
        let has_internet = api_calls.contains(&"InternetConnect")
            || api_calls.contains(&"HttpSendRequest")
            || api_calls.contains(&"WinHttpSendRequest");
        if has_internet {
            indicators.push(
                Indicator::new(
                    "Outbound Network Activity",
                    "HTTP/HTTPS connection initiated",
                    Severity::Medium,
                    IndicatorCategory::Network,
                )
                .with_technique("T1071.001"),
            );
            behaviors.push(
                Behavior::new(
                    "Network Beacon",
                    "Sample makes outbound HTTP connections",
                    Severity::Medium,
                    "network",
                )
                .with_api("InternetConnect"),
            );
        }
        let has_debug_check = api_calls.contains(&"IsDebuggerPresent")
            || api_calls.contains(&"CheckRemoteDebuggerPresent")
            || api_calls.contains(&"NtQueryInformationProcess");
        if has_debug_check {
            indicators.push(
                Indicator::new(
                    "Anti-Debug Check",
                    "Sample probes for debugger presence",
                    Severity::High,
                    IndicatorCategory::Evasion,
                )
                .with_technique("T1497"),
            );
        }
    }

    fn classify_crypto_hook_and_screen(api_calls: &[&str], indicators: &mut Vec<Indicator>) {
        let has_crypt = api_calls.contains(&"CryptEncrypt")
            || api_calls.contains(&"BCryptEncrypt")
            || api_calls.contains(&"CryptDecrypt")
            || api_calls.contains(&"BCryptDecrypt");
        if has_crypt {
            indicators.push(
                Indicator::new(
                    "Encryption Activity",
                    "Cryptographic API calls observed",
                    Severity::Medium,
                    IndicatorCategory::Crypto,
                )
                .with_technique("T1486"),
            );
        }
        let has_hook = api_calls.contains(&"SetWindowsHookEx");
        if has_hook {
            indicators.push(
                Indicator::new(
                    "Keyboard Hook",
                    "SetWindowsHookEx used — possible keylogger",
                    Severity::High,
                    IndicatorCategory::Keylogging,
                )
                .with_technique("T1056.001"),
            );
        }
        let has_screen = api_calls.contains(&"BitBlt") || api_calls.contains(&"GetDC");
        if has_screen {
            indicators.push(
                Indicator::new(
                    "Screen Capture",
                    "GDI screenshot APIs observed",
                    Severity::Medium,
                    IndicatorCategory::Other,
                )
                .with_technique("T1113"),
            );
        }
    }

    /// Infer the malware family based on indicators.
    #[must_use]
    pub fn infer_family(indicators: &[Indicator]) -> &'static str {
        let has_ransomware = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Ransomware);
        let has_keylog = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Keylogging);
        let has_injection = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Injection);
        let has_net = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Network);

        if has_ransomware {
            return "ransomware";
        }
        if has_keylog && has_net {
            return "spyware";
        }
        if has_injection && has_net {
            return "trojan";
        }
        if has_injection {
            return "injector";
        }
        if has_net {
            return "downloader";
        }
        "unknown"
    }
}

// ─── ReportRenderer ───────────────────────────────────────────

/// Pre-rendered fragments passed to `MultiFormatRenderer::assemble_html` so
/// the assembly function stays under the line-count limit without taking a
/// dozen positional arguments.
struct HtmlSections {
    behaviors: String,
    indicators: String,
    iocs_classified: String,
    ttp: String,
    dropped: String,
}

struct HtmlReportParts<'a> {
    css: &'a str,
    exec_rows: &'a str,
    tags_html: &'a str,
    file_rows: &'a str,
    behavior_rows: &'a str,
    indicator_rows: &'a str,
    ioc_rows: &'a str,
    ioc_collection_block: &'a str,
    ttp_rows: &'a str,
    ttp_map_html: &'a str,
    dropped_rows: &'a str,
    extra_sections: &'a str,
}

/// Renders a `SandboxReport` into various output formats.
#[derive(Debug, Clone, Default)]
pub struct ReportRenderer;

impl ReportRenderer {
    /// Create a new renderer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Render the report as JSON.
    ///
    /// # Errors
    /// Returns `ReportError::Serialize` if serialization fails.
    pub fn render_json(&self, report: &SandboxReport) -> Result<String, ReportError> {
        serde_json::to_string_pretty(report).map_err(|e| ReportError::Serialize(e.to_string()))
    }

    /// Render the report as a Markdown document.
    #[must_use]
    pub fn render_markdown(&self, report: &SandboxReport) -> String {
        let mut out = String::new();

        let _ = write!(out, "# Sandbox Report: {}\n\n", report.sample);
        let _ = write!(out, "**SHA-256:** `{}`\n\n", report.sha256);
        let _ = write!(
            out,
            "**Verdict:** {} (score: {})\n\n",
            report.verdict, report.score
        );
        let _ = write!(out, "**Analysis Time:** {} ms\n\n", report.analysis_ms);

        out.push_str("## Indicators\n\n");
        if report.indicators.is_empty() {
            out.push_str("_No indicators found._\n\n");
        } else {
            out.push_str("| Severity | Name | Category | Description |\n");
            out.push_str("|----------|------|----------|-------------|\n");
            for ind in &report.indicators {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    ind.severity, ind.name, ind.category, ind.desc
                );
            }
            out.push('\n');
        }

        out.push_str("## ATT&CK Techniques\n\n");
        if report.attack.techniques.is_empty() {
            out.push_str("_No ATT&CK mappings._\n\n");
        } else {
            for t in &report.attack.techniques {
                let _ = writeln!(out, "- **{}** — {} ({})", t.full_id(), t.name, t.tactic);
            }
            out.push('\n');
        }

        out.push_str("## IOCs\n\n");
        if report.iocs.is_empty() {
            out.push_str("_No IOCs extracted._\n\n");
        } else {
            out.push_str("| Type | Value | Confidence |\n");
            out.push_str("|------|-------|------------|\n");
            for ioc in &report.iocs.iocs {
                let _ = writeln!(
                    out,
                    "| {} | `{}` | {}% |",
                    ioc.kind, ioc.value, ioc.confidence
                );
            }
            out.push('\n');
        }

        for section in &report.sections {
            let _ = write!(out, "## {}\n\n{}\n\n", section.title, section.content);
        }

        out
    }

    /// Render the report as an HTML document.
    #[must_use]
    pub fn render_html(&self, report: &SandboxReport) -> String {
        let verdict_class = match report.verdict {
            Verdict::Clean => "verdict-clean",
            Verdict::Low => "verdict-low",
            Verdict::Suspicious => "verdict-suspicious",
            Verdict::Malicious => "verdict-malicious",
            Verdict::Unknown => "verdict-unknown",
        };

        let mut rows = String::new();
        for ind in &report.indicators {
            let _ = writeln!(
                rows,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&ind.severity.to_string()),
                html_escape(&ind.name),
                html_escape(&ind.category.to_string()),
                html_escape(&ind.desc),
            );
        }

        let mut ioc_rows = String::new();
        for ioc in &report.iocs.iocs {
            let _ = writeln!(
                ioc_rows,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}%</td></tr>",
                html_escape(&ioc.kind.to_string()),
                html_escape(&ioc.value),
                ioc.confidence,
            );
        }

        let mut ttp_list = String::new();
        for t in &report.attack.techniques {
            let _ = writeln!(
                ttp_list,
                "<li><strong>{}</strong> — {} ({})</li>",
                html_escape(t.full_id()),
                html_escape(&t.name),
                html_escape(&t.tactic.to_string()),
            );
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Sandbox Report: {sample}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
.{vc} {{ padding: 0.5em 1em; border-radius: 4px; display: inline-block; }}
.verdict-clean {{ background: #d4edda; color: #155724; }}
.verdict-suspicious {{ background: #fff3cd; color: #856404; }}
.verdict-malicious {{ background: #f8d7da; color: #721c24; }}
.verdict-unknown {{ background: #e2e3e5; color: #383d41; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 1em; }}
th, td {{ border: 1px solid #dee2e6; padding: 0.4em 0.8em; text-align: left; }}
th {{ background: #f8f9fa; }}
</style>
</head>
<body>
<h1>Sandbox Report: {sample}</h1>
<p><strong>SHA-256:</strong> <code>{sha}</code></p>
<p><strong>Verdict:</strong> <span class="{vc}">{verdict}</span> (score: {score})</p>
<p><strong>Analysis Time:</strong> {ms} ms</p>
<h2>Indicators</h2>
<table><tr><th>Severity</th><th>Name</th><th>Category</th><th>Description</th></tr>
{rows}</table>
<h2>ATT&CK Techniques</h2>
<ul>{ttp_list}</ul>
<h2>IOCs</h2>
<table><tr><th>Type</th><th>Value</th><th>Confidence</th></tr>
{ioc_rows}</table>
</body>
</html>"#,
            sample = html_escape(&report.sample),
            sha = html_escape(&report.sha256),
            vc = verdict_class,
            verdict = report.verdict,
            score = report.score,
            ms = report.analysis_ms,
            rows = rows,
            ttp_list = ttp_list,
            ioc_rows = ioc_rows,
        )
    }
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Escape pipe characters in a Markdown table cell.
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

// â"€â"€â"€ SandboxReport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Full report produced after a sandbox analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub sample: String,
    pub sha256: String,
    pub analysis_ms: u64,
    pub indicators: Vec<Indicator>,
    pub behaviors: Vec<Behavior>,
    pub verdict: Verdict,
    pub score: u32,
    pub ttps: Vec<String>,
    pub attack: AttackMapping,
    pub iocs: IocSet,
    pub sections: Vec<ReportSection>,
    pub family: String,
    pub tags: Vec<String>,
}

impl SandboxReport {
    /// Create a new empty report.
    #[must_use]
    pub fn new(sample: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            sample: sample.into(),
            sha256: sha256.into(),
            analysis_ms: 0,
            indicators: vec![],
            behaviors: vec![],
            verdict: Verdict::Unknown,
            score: 0,
            ttps: vec![],
            attack: AttackMapping::new(),
            iocs: IocSet::new(),
            sections: vec![],
            family: String::new(),
            tags: vec![],
        }
    }

    /// Add an indicator.
    pub fn add_indicator(&mut self, i: Indicator) {
        self.indicators.push(i);
    }

    /// Add a behavior.
    pub fn add_behavior(&mut self, b: Behavior) {
        self.behaviors.push(b);
    }

    /// Add a MITRE ATT&CK TTP ID.
    pub fn add_ttp(&mut self, t: impl Into<String>) {
        self.ttps.push(t.into());
    }

    /// Add a report section.
    pub fn add_section(&mut self, s: ReportSection) {
        self.sections.push(s);
        self.sections.sort_by_key(|sec| sec.order);
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Sum indicator scores using the score engine, cap at 100, and set verdict.
    pub fn compute_score(&mut self) {
        let engine = ScoreEngine::new();
        self.score = engine.compute(&self.indicators);
        self.verdict = engine.verdict(self.score);

        if ScoreEngine::has_critical(&self.indicators) {
            self.verdict = Verdict::Malicious;
        }
    }

    /// Build the ATT&CK mapping from the current behavior tags.
    pub fn build_attack_mapping(&mut self) {
        let tags: Vec<&str> = self.tags.iter().map(std::string::String::as_str).collect();
        self.attack = AttackMapping::from_behaviors(&tags);
    }

    /// Infer and set the malware family.
    pub fn infer_family(&mut self) {
        self.family = BehaviorClassifier::infer_family(&self.indicators).to_string();
    }

    /// Return all critical-severity indicators.
    #[must_use]
    pub fn critical_indicators(&self) -> Vec<&Indicator> {
        self.indicators
            .iter()
            .filter(|i| i.severity == Severity::Critical)
            .collect()
    }

    /// Return indicators by category.
    #[must_use]
    pub fn indicators_by_category(&self, cat: &IndicatorCategory) -> Vec<&Indicator> {
        self.indicators
            .iter()
            .filter(|i| &i.category == cat)
            .collect()
    }

    /// Serialize the report to JSON.
    ///
    /// # Errors
    /// Returns `ReportError::Serialize` on failure.
    pub fn to_json(&self) -> Result<String, ReportError> {
        serde_json::to_string(self).map_err(|e| ReportError::Serialize(e.to_string()))
    }

    /// Render as Markdown using the default renderer.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        ReportRenderer::new().render_markdown(self)
    }

    /// Render as HTML using the default renderer.
    #[must_use]
    pub fn to_html(&self) -> String {
        ReportRenderer::new().render_html(self)
    }

    /// Create a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut r = Self::new("malware.exe", "deadbeef0123456789abcdef0123456789abcdef");
        r.analysis_ms = 30_000;

        r.add_indicator(
            Indicator::new(
                "Code injection",
                "WriteProcessMemory called on external process",
                Severity::Critical,
                IndicatorCategory::Injection,
            )
            .with_ioc("pid:1234")
            .with_technique("T1055.001"),
        );
        r.add_indicator(
            Indicator::new(
                "Network beacon",
                "Periodic connection to C2",
                Severity::High,
                IndicatorCategory::Network,
            )
            .with_ioc("185.220.101.1:443")
            .with_technique("T1071.001"),
        );
        r.add_indicator(
            Indicator::new(
                "Registry persistence",
                "Run key added",
                Severity::Medium,
                IndicatorCategory::Persistence,
            )
            .with_technique("T1547.001"),
        );
        r.add_indicator(
            Indicator::new(
                "Anti-debug",
                "IsDebuggerPresent called",
                Severity::High,
                IndicatorCategory::Evasion,
            )
            .with_technique("T1497"),
        );

        r.add_behavior(
            Behavior::new(
                "Process injection",
                "Injects code into legitimate processes",
                Severity::Critical,
                "injection",
            )
            .with_api("VirtualAllocEx")
            .with_api("WriteProcessMemory")
            .with_api("CreateRemoteThread"),
        );

        r.add_ttp("T1055");
        r.add_ttp("T1547.001");
        r.add_ttp("T1071.001");
        r.add_ttp("T1497");

        r.iocs = IocSet::mock();

        r.add_tag("injection");
        r.add_tag("c2");
        r.add_tag("persistence");
        r.add_tag("anti-analysis");

        r.add_section(ReportSection::new(
            "Executive Summary",
            "Sample shows classic RAT behavior with injection, C2 beaconing, and persistence.",
            1,
        ));
        r.add_section(ReportSection::new(
            "Technical Details",
            "Three-stage injection via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.",
            2,
        ));

        r.compute_score();
        r.build_attack_mapping();
        r.infer_family();
        r
    }
}

// â"€â"€â"€ ReportFormat â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Output format for a generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    /// Machine-readable JSON.
    Json,
    /// Rendered HTML document.
    Html,
    /// PDF (placeholder —" requires an external renderer).
    Pdf,
    /// Comma-separated values (IOC export).
    Csv,
    /// GitHub-flavoured Markdown.
    Markdown,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
            Self::Pdf => write!(f, "pdf"),
            Self::Csv => write!(f, "csv"),
            Self::Markdown => write!(f, "markdown"),
        }
    }
}

impl ReportFormat {
    /// Return the conventional file extension for this format.
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Csv => "csv",
            Self::Markdown => "md",
        }
    }

    /// Parse a format from a file-extension string (case-insensitive).
    ///
    /// # Errors
    /// Returns `ReportError::InvalidData` for unknown extensions.
    pub fn from_extension(ext: &str) -> std::result::Result<Self, ReportError> {
        match ext.to_ascii_lowercase().trim_start_matches('.') {
            "json" => Ok(Self::Json),
            "html" | "htm" => Ok(Self::Html),
            "pdf" => Ok(Self::Pdf),
            "csv" => Ok(Self::Csv),
            "md" | "markdown" => Ok(Self::Markdown),
            other => Err(ReportError::InvalidData(format!("unknown format: {other}"))),
        }
    }
}

// â"€â"€â"€ IocCollection (local mirror) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// A lightweight inline IOC collection to avoid a crate dependency cycle.
// The real version lives in `rustre-sandbox-extract`.

/// Flat collection of IOC strings passed to the report builder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocCollection {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub file_paths: Vec<String>,
    pub registry_keys: Vec<String>,
    pub mutexes: Vec<String>,
    pub hashes: Vec<String>,
    pub btc_addresses: Vec<String>,
}

impl IocCollection {
    /// Create an empty collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total IOC count across all categories.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.ips.len()
            + self.domains.len()
            + self.urls.len()
            + self.file_paths.len()
            + self.registry_keys.len()
            + self.mutexes.len()
            + self.hashes.len()
            + self.btc_addresses.len()
    }

    /// Returns `true` if no IOCs are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Build a compact plain-text summary of all IOCs for embedding in reports.
    #[must_use]
    pub fn summary_text(&self) -> String {
        let mut out = String::new();
        if !self.ips.is_empty() {
            let _ = writeln!(out, "IPs: {}", self.ips.join(", "));
        }
        if !self.domains.is_empty() {
            let _ = writeln!(out, "Domains: {}", self.domains.join(", "));
        }
        if !self.urls.is_empty() {
            let _ = writeln!(out, "URLs: {}", self.urls.join(", "));
        }
        if !self.hashes.is_empty() {
            let _ = writeln!(out, "Hashes: {}", self.hashes.join(", "));
        }
        if !self.registry_keys.is_empty() {
            let _ = writeln!(out, "Registry: {}", self.registry_keys.join(", "));
        }
        if !self.mutexes.is_empty() {
            let _ = writeln!(out, "Mutexes: {}", self.mutexes.join(", "));
        }
        if !self.file_paths.is_empty() {
            let _ = writeln!(out, "Paths: {}", self.file_paths.join(", "));
        }
        if !self.btc_addresses.is_empty() {
            let _ = writeln!(out, "BTC: {}", self.btc_addresses.join(", "));
        }
        out
    }

    /// Render this collection as CSV rows.
    /// Columns: `type,value`
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut rows = String::from("type,value\n");
        for ip in &self.ips {
            let _ = writeln!(rows, "ip,{ip}");
        }
        for d in &self.domains {
            let _ = writeln!(rows, "domain,{d}");
        }
        for u in &self.urls {
            let _ = writeln!(rows, "url,{u}");
        }
        for h in &self.hashes {
            let _ = writeln!(rows, "hash,{h}");
        }
        for r in &self.registry_keys {
            let _ = writeln!(rows, "registry,{r}");
        }
        for m in &self.mutexes {
            let _ = writeln!(rows, "mutex,{m}");
        }
        for p in &self.file_paths {
            let _ = writeln!(rows, "path,{p}");
        }
        for b in &self.btc_addresses {
            let _ = writeln!(rows, "btc,{b}");
        }
        rows
    }

    /// Construct a populated mock IOC collection for tests.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            ips: vec!["185.220.101.1".to_string(), "10.0.0.1".to_string()],
            domains: vec!["c2server.evil".to_string()],
            urls: vec!["https://c2server.evil/beacon".to_string()],
            file_paths: vec![r"C:\Windows\Temp\payload.exe".to_string()],
            registry_keys: vec![r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string()],
            mutexes: vec!["Global\\EvilMutex".to_string()],
            hashes: vec![
                "deadbeef0123456789abcdef0123456789abcdef01234567890abcdef01234567".to_string(),
            ],
            btc_addresses: vec![],
        }
    }
}

// â"€â"€â"€ SandboxReportBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Builder that assembles a rich report from a `SandboxReport` plus optional
/// enrichment data (IOCs, TTP map) and renders it to multiple formats.
#[derive(Debug, Clone)]
pub struct SandboxReportBuilder {
    report: SandboxReport,
    iocs: Option<IocCollection>,
    ttp_map: Option<HashMap<String, Vec<String>>>,
}

impl SandboxReportBuilder {
    /// Create a new builder from a completed `SandboxReport`.
    #[must_use]
    pub const fn new(result: SandboxReport) -> Self {
        Self {
            report: result,
            iocs: None,
            ttp_map: None,
        }
    }

    /// Attach an `IocCollection` to the report.
    pub fn add_iocs(&mut self, iocs: IocCollection) -> &mut Self {
        self.iocs = Some(iocs);
        self
    }

    /// Attach a manual TTP map (`technique_id â†' [evidence —¦]`).
    pub fn add_ttp_map(&mut self, ttps: HashMap<String, Vec<String>>) -> &mut Self {
        self.ttp_map = Some(ttps);
        self
    }

    // â"€â"€ Convenience accessors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Return a reference to the underlying `SandboxReport`.
    #[must_use]
    pub const fn report(&self) -> &SandboxReport {
        &self.report
    }

    /// Return the attached `IocCollection`, if any.
    #[must_use]
    pub const fn iocs(&self) -> Option<&IocCollection> {
        self.iocs.as_ref()
    }

    // â"€â"€ JSON â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as a pretty-printed JSON string.
    ///
    /// The output wraps the `SandboxReport` fields together with any attached
    /// IOCs and TTP map.
    #[must_use]
    pub fn build_json(&self) -> String {
        // We build an ad-hoc enriched structure so the output is self-contained.
        #[derive(Serialize)]
        struct Full<'a> {
            report: &'a SandboxReport,
            #[serde(skip_serializing_if = "Option::is_none")]
            iocs: Option<&'a IocCollection>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ttp_map: Option<&'a HashMap<String, Vec<String>>>,
        }
        let full = Full {
            report: &self.report,
            iocs: self.iocs.as_ref(),
            ttp_map: self.ttp_map.as_ref(),
        };
        serde_json::to_string_pretty(&full).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    // â"€â"€ Markdown â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as a full GitHub-flavoured Markdown document.
    #[must_use]
    pub fn build_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Sandbox Analysis Report\n\n");
        self.markdown_executive_and_file(&mut out);
        self.markdown_behaviors_and_iocs(&mut out);
        self.markdown_attack_and_drops(&mut out);
        self.markdown_additional_sections(&mut out);
        out
    }

    fn markdown_executive_and_file(&self, out: &mut String) {
        let r = &self.report;
        out.push_str("## Executive Summary\n\n");
        let _ = write!(
            out,
            "| Field | Value |\n|-------|-------|\n\
             | Sample | `{}` |\n\
             | Verdict | **{}** |\n\
             | Threat Score | {} / 100 |\n\
             | Family | `{}` |\n\
             | Analysis Duration | {} ms |\n\n",
            r.sample, r.verdict, r.score, r.family, r.analysis_ms
        );
        if !r.tags.is_empty() {
            let _ = write!(out, "**Tags:** {}\n\n", r.tags.join(", "));
        }
        for sec in r.sections.iter().filter(|s| s.order <= 2) {
            let _ = write!(out, "### {}\n\n{}\n\n", sec.title, sec.content);
        }
        out.push_str("## File Information\n\n");
        let _ = write!(
            out,
            "| Property | Value |\n|----------|-------|\n\
             | SHA-256 | `{}` |\n\
             | Name | `{}` |\n",
            r.sha256, r.sample
        );
        out.push('\n');
    }

    fn markdown_behaviors_and_iocs(&self, out: &mut String) {
        let r = &self.report;
        out.push_str("## Behavioral Analysis\n\n");
        if r.behaviors.is_empty() {
            out.push_str("_No behaviors recorded._\n\n");
        } else {
            out.push_str("### Observed Behaviors\n\n");
            out.push_str("| Behavior | Severity | Category | APIs |\n");
            out.push_str("|----------|----------|----------|------|\n");
            for b in &r.behaviors {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    b.name,
                    b.severity,
                    b.category,
                    b.apis.join(", "),
                );
            }
            out.push('\n');
        }
        if !r.indicators.is_empty() {
            out.push_str("### Indicators\n\n");
            out.push_str("| Severity | Name | Category | Description |\n");
            out.push_str("|----------|------|----------|-------------|\n");
            for ind in &r.indicators {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    ind.severity, ind.name, ind.category, ind.desc
                );
            }
            out.push('\n');
        }
        out.push_str("## IOCs\n\n");
        if !r.iocs.is_empty() {
            out.push_str("### Classified IOCs\n\n");
            out.push_str("| Type | Value | Confidence |\n");
            out.push_str("|------|-------|------------|\n");
            for ioc in &r.iocs.iocs {
                let _ = writeln!(
                    out,
                    "| {} | `{}` | {}% |",
                    ioc.kind, ioc.value, ioc.confidence,
                );
            }
            out.push('\n');
        }
        if let Some(iocs) = &self.iocs
            && !iocs.is_empty()
        {
            out.push_str("### Extracted IOC Collection\n\n");
            out.push_str("```\n");
            out.push_str(&iocs.summary_text());
            out.push_str("```\n\n");
        }
        if r.iocs.is_empty() && self.iocs.as_ref().is_none_or(IocCollection::is_empty) {
            out.push_str("_No IOCs extracted._\n\n");
        }
    }

    fn markdown_attack_and_drops(&self, out: &mut String) {
        let r = &self.report;
        out.push_str("## MITRE ATT&CK Mapping\n\n");
        if r.attack.techniques.is_empty()
            && self
                .ttp_map
                .as_ref()
                .is_none_or(std::collections::HashMap::is_empty)
        {
            out.push_str("_No ATT\\&CK techniques mapped._\n\n");
        } else {
            if !r.attack.techniques.is_empty() {
                out.push_str("| ID | Technique | Tactic | Confidence |\n");
                out.push_str("|----|-----------|--------|------------|\n");
                for t in &r.attack.techniques {
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {}% |",
                        t.full_id(),
                        t.name,
                        t.tactic,
                        t.confidence,
                    );
                }
                out.push('\n');
            }
            if let Some(map) = &self.ttp_map {
                for (id, evidence) in map {
                    let _ = writeln!(out, "- **{id}**: {}", evidence.join("; "));
                }
                out.push('\n');
            }
        }
        out.push_str("## Dropped Files\n\n");
        let dropped_paths: Vec<_> = self
            .iocs
            .as_ref()
            .map(|iocs| iocs.file_paths.iter().collect())
            .unwrap_or_default();
        if dropped_paths.is_empty() && r.iocs.by_kind(&crate::IocKind::FilePath).is_empty() {
            out.push_str("_No dropped files recorded._\n\n");
        } else {
            out.push_str("| Path |\n|------|\n");
            for path in &dropped_paths {
                let _ = writeln!(out, "| `{path}` |");
            }
            for ioc in r.iocs.by_kind(&crate::IocKind::FilePath) {
                let _ = writeln!(out, "| `{}` |", ioc.value);
            }
            out.push('\n');
        }
    }

    fn markdown_additional_sections(&self, out: &mut String) {
        for sec in self.report.sections.iter().filter(|s| s.order > 2) {
            let _ = write!(out, "## {}\n\n{}\n\n", sec.title, sec.content);
        }
    }

    // â"€â"€ HTML â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as a complete, self-contained HTML document with
    /// inline CSS covering the same sections as `build_markdown`.
    #[must_use]
    pub fn build_html(&self) -> String {
        let r = &self.report;
        let verdict_class = match r.verdict {
            Verdict::Clean => "verdict-clean",
            Verdict::Low => "verdict-low",
            Verdict::Suspicious => "verdict-suspicious",
            Verdict::Malicious => "verdict-malicious",
            Verdict::Unknown => "verdict-unknown",
        };
        let (exec_rows, tags_html, file_rows) = self.build_html_header_rows(verdict_class);
        let (behavior_rows, indicator_rows) = self.build_html_behavior_rows();
        let (ioc_rows, ioc_collection_block) = self.build_html_ioc_blocks();
        let (ttp_rows, ttp_map_html) = self.build_html_attack_blocks();
        let (dropped_rows, extra_sections) = self.build_html_drop_and_extra();
        let parts = HtmlReportParts {
            css: Self::build_html_css(),
            exec_rows: &exec_rows,
            tags_html: &tags_html,
            file_rows: &file_rows,
            behavior_rows: &behavior_rows,
            indicator_rows: &indicator_rows,
            ioc_rows: &ioc_rows,
            ioc_collection_block: &ioc_collection_block,
            ttp_rows: &ttp_rows,
            ttp_map_html: &ttp_map_html,
            dropped_rows: &dropped_rows,
            extra_sections: &extra_sections,
        };
        self.assemble_html(&parts)
    }

    const fn build_html_css() -> &'static str {
        r"
body { font-family: 'Segoe UI', Arial, sans-serif; background:#f5f5f5; color:#222; margin:0; padding:0; }
.container { max-width:1100px; margin:2em auto; background:#fff; border-radius:8px; box-shadow:0 2px 8px #0002; padding:2em; }
h1 { color:#1a1a2e; border-bottom:2px solid #e63946; padding-bottom:0.4em; }
h2 { color:#1d3557; border-bottom:1px solid #a8dadc; margin-top:1.5em; }
h3 { color:#457b9d; }
.badge { display:inline-block; padding:0.3em 0.8em; border-radius:4px; font-weight:bold; }
.verdict-clean      { background:#d4edda; color:#155724; }
.verdict-suspicious { background:#fff3cd; color:#856404; }
.verdict-malicious  { background:#f8d7da; color:#721c24; }
.verdict-unknown    { background:#e2e3e5; color:#383d41; }
table { border-collapse:collapse; width:100%; margin-bottom:1em; }
th { background:#1d3557; color:#fff; padding:0.5em 0.8em; text-align:left; }
td { border:1px solid #dee2e6; padding:0.4em 0.8em; }
tr:nth-child(even) td { background:#f8f9fa; }
code { background:#f0f0f0; padding:0.1em 0.3em; border-radius:3px; font-size:0.92em; }
pre  { background:#1a1a2e; color:#ccc; padding:1em; border-radius:6px; overflow-x:auto; }
.tag { display:inline-block; background:#a8dadc; color:#1d3557; border-radius:3px; padding:0.1em 0.5em; margin:0.1em; font-size:0.85em; }
.section { margin-bottom:1.5em; }
"
    }

    fn build_html_header_rows(&self, verdict_class: &str) -> (String, String, String) {
        let r = &self.report;
        let exec_rows = format!(
            "<tr><td>Sample</td><td><code>{}</code></td></tr>\
             <tr><td>Verdict</td><td><span class=\"badge {vc}\">{}</span></td></tr>\
             <tr><td>Threat Score</td><td><strong>{} / 100</strong></td></tr>\
             <tr><td>Family</td><td><code>{}</code></td></tr>\
             <tr><td>Analysis Duration</td><td>{} ms</td></tr>",
            html_escape(&r.sample),
            html_escape(&r.verdict.to_string()),
            r.score,
            html_escape(&r.family),
            r.analysis_ms,
            vc = verdict_class,
        );
        let tags_html: String = r
            .tags
            .iter()
            .map(|t| format!("<span class=\"tag\">{}</span>", html_escape(t)))
            .collect::<Vec<_>>()
            .join(" ");
        let file_rows = format!(
            "<tr><td>SHA-256</td><td><code>{}</code></td></tr>\
             <tr><td>Name</td><td><code>{}</code></td></tr>",
            html_escape(&r.sha256),
            html_escape(&r.sample),
        );
        (exec_rows, tags_html, file_rows)
    }

    fn build_html_behavior_rows(&self) -> (String, String) {
        let r = &self.report;
        let behavior_rows: String = r.behaviors.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                html_escape(&b.name),
                html_escape(&b.severity.to_string()),
                html_escape(&b.category),
                html_escape(&b.apis.join(", ")),
            );
            acc
        });
        let indicator_rows: String = r.indicators.iter().fold(String::new(), |mut acc, ind| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&ind.severity.to_string()),
                html_escape(&ind.name),
                html_escape(&ind.category.to_string()),
                html_escape(&ind.desc),
            );
            acc
        });
        (behavior_rows, indicator_rows)
    }

    fn build_html_ioc_blocks(&self) -> (String, String) {
        let r = &self.report;
        let ioc_rows: String = r.iocs.iocs.iter().fold(String::new(), |mut acc, ioc| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}%</td></tr>",
                html_escape(&ioc.kind.to_string()),
                html_escape(&ioc.value),
                ioc.confidence,
            );
            acc
        });
        let ioc_collection_block = self.iocs.as_ref().map_or_else(String::new, |iocs| {
            if iocs.is_empty() {
                String::new()
            } else {
                format!("<pre>{}</pre>", html_escape(&iocs.summary_text()))
            }
        });
        (ioc_rows, ioc_collection_block)
    }

    fn build_html_attack_blocks(&self) -> (String, String) {
        let r = &self.report;
        let ttp_rows: String = r
            .attack
            .techniques
            .iter()
            .fold(String::new(), |mut acc, t| {
                let _ = write!(
                    acc,
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}%</td></tr>",
                    html_escape(t.full_id()),
                    html_escape(&t.name),
                    html_escape(&t.tactic.to_string()),
                    t.confidence,
                );
                acc
            });
        let ttp_map_html: String = self
            .ttp_map
            .as_ref()
            .map(|map| {
                let items: String = map.iter().fold(String::new(), |mut acc, (id, ev)| {
                    let _ = write!(
                        acc,
                        "<li><strong>{}</strong>: {}</li>",
                        html_escape(id),
                        html_escape(&ev.join("; ")),
                    );
                    acc
                });
                format!("<ul>{items}</ul>")
            })
            .unwrap_or_default();
        (ttp_rows, ttp_map_html)
    }

    fn build_html_drop_and_extra(&self) -> (String, String) {
        let r = &self.report;
        let dropped_rows: String = {
            let mut rows = String::new();
            if let Some(iocs) = &self.iocs {
                for path in &iocs.file_paths {
                    let _ = write!(rows, "<tr><td><code>{}</code></td></tr>", html_escape(path));
                }
            }
            for ioc in r.iocs.by_kind(&crate::IocKind::FilePath) {
                let _ = write!(
                    rows,
                    "<tr><td><code>{}</code></td></tr>",
                    html_escape(&ioc.value),
                );
            }
            rows
        };
        let extra_sections: String = r.sections.iter().fold(String::new(), |mut acc, sec| {
            let _ = write!(
                acc,
                "<div class=\"section\"><h2>{}</h2><p>{}</p></div>",
                html_escape(&sec.title),
                html_escape(&sec.content),
            );
            acc
        });
        (dropped_rows, extra_sections)
    }

    /// Build the inner section strings from parts.
    fn build_html_sections(report: &SandboxReport, parts: &HtmlReportParts<'_>) -> HtmlSections {
        let behavior_rows = parts.behavior_rows;
        let indicator_rows = parts.indicator_rows;
        let ioc_rows = parts.ioc_rows;
        let ttp_rows = parts.ttp_rows;
        let dropped_rows = parts.dropped_rows;
        HtmlSections {
            behaviors: Self::html_section_or_empty(
                report.behaviors.is_empty(),
                "<p><em>No behaviors recorded.</em></p>",
                &format!(
                    "<table><tr><th>Behavior</th><th>Severity</th><th>Category</th><th>APIs</th></tr>{behavior_rows}</table>",
                ),
            ),
            indicators: Self::html_section_or_empty(
                report.indicators.is_empty(),
                "",
                &format!(
                    "<h3>Indicators</h3>\
                     <table><tr><th>Severity</th><th>Name</th><th>Category</th><th>Description</th></tr>{indicator_rows}</table>",
                ),
            ),
            iocs_classified: Self::html_section_or_empty(
                report.iocs.is_empty(),
                "",
                &format!(
                    "<table><tr><th>Type</th><th>Value</th><th>Confidence</th></tr>{ioc_rows}</table>",
                ),
            ),
            ttp: Self::html_section_or_empty(
                report.attack.techniques.is_empty(),
                "",
                &format!(
                    "<table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th></tr>{ttp_rows}</table>",
                ),
            ),
            dropped: Self::html_section_or_empty(
                dropped_rows.is_empty(),
                "<p><em>No dropped files recorded.</em></p>",
                &format!("<table><tr><th>Path</th></tr>{dropped_rows}</table>"),
            ),
        }
    }

    fn assemble_html(&self, parts: &HtmlReportParts<'_>) -> String {
        let r = &self.report;
        let HtmlReportParts {
            css,
            exec_rows,
            tags_html,
            file_rows,
            behavior_rows: _,
            indicator_rows: _,
            ioc_rows: _,
            ioc_collection_block,
            ttp_rows: _,
            ttp_map_html,
            dropped_rows: _,
            extra_sections,
        } = *parts;
        let secs = Self::build_html_sections(r, parts);
        let behaviors_section = secs.behaviors;
        let indicators_section = secs.indicators;
        let iocs_classified = secs.iocs_classified;
        let ttp_section = secs.ttp;
        let dropped_section = secs.dropped;
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sandbox Analysis Report —  {sample}</title>
  <style>{css}</style>
</head>
<body>
<div class="container">
<h1>Sandbox Analysis Report</h1>

<div class="section">
<h2>Executive Summary</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  {exec_rows}
</table>
<div>{tags_html}</div>
</div>

<div class="section">
<h2>File Information</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  {file_rows}
</table>
</div>

<div class="section">
<h2>Behavioral Analysis</h2>
{behaviors_section}
{indicators_section}
</div>

<div class="section">
<h2>IOCs</h2>
{iocs_classified}
{ioc_collection_block}
</div>

<div class="section">
<h2>MITRE ATT&amp;CK Mapping</h2>
{ttp_section}
{ttp_map_html}
</div>

<div class="section">
<h2>Dropped Files</h2>
{dropped_section}
</div>

{extra_sections}
</div>
</body>
</html>"#,
            sample = html_escape(&r.sample),
        )
    }

    /// Pick the empty-placeholder string when `is_empty`, otherwise the
    /// rendered content —" small helper used by `assemble_html` to keep its
    /// body within clippy's `too_many_lines` budget.
    fn html_section_or_empty(is_empty: bool, empty_text: &str, content: &str) -> String {
        if is_empty {
            empty_text.to_string()
        } else {
            content.to_string()
        }
    }

    // â"€â"€ CSV (IOC export) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render all IOCs (from both the embedded `IocSet` and the attached
    /// `IocCollection`) as CSV with columns `type,value,confidence`.
    #[must_use]
    pub fn build_csv(&self) -> String {
        let mut rows = String::from("type,value,confidence\n");

        // From the built-in IocSet.
        for ioc in &self.report.iocs.iocs {
            let _ = writeln!(
                rows,
                "{},{},{}",
                ioc.kind,
                csv_escape(&ioc.value),
                ioc.confidence,
            );
        }

        // From the attached IocCollection.
        // IocCollection stores raw strings without per-entry confidence values,
        // so the confidence column is emitted as "" (empty) to signal unavailable
        // rather than a misleading 0.
        if let Some(iocs) = &self.iocs {
            for ip in &iocs.ips {
                let _ = writeln!(rows, "ip,{ip},");
            }
            for d in &iocs.domains {
                let _ = writeln!(rows, "domain,{d},");
            }
            for u in &iocs.urls {
                let _ = writeln!(rows, "url,{},", csv_escape(u));
            }
            for h in &iocs.hashes {
                let _ = writeln!(rows, "hash,{h},");
            }
            for r in &iocs.registry_keys {
                let _ = writeln!(rows, "registry,{},", csv_escape(r));
            }
            for m in &iocs.mutexes {
                let _ = writeln!(rows, "mutex,{},", csv_escape(m));
            }
            for p in &iocs.file_paths {
                let _ = writeln!(rows, "path,{},", csv_escape(p));
            }
            for b in &iocs.btc_addresses {
                let _ = writeln!(rows, "btc,{b},");
            }
        }

        rows
    }
}

/// Escape a value for inclusion in a CSV field (wrap in quotes if it contains a comma).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// â"€â"€â"€ ReportStore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Persists and loads report strings from the file system.
pub struct ReportStore;

impl ReportStore {
    /// Write `report` to `path`, creating parent directories if necessary.
    ///
    /// The `format` parameter is informational (for callers that want to log it)
    /// but does not alter the written bytes —" the caller is expected to have
    /// already serialized the content to the right format.
    ///
    /// # Errors
    /// Returns `anyhow::Error` on I/O failure.
    pub fn save(report: &str, _format: ReportFormat, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, report.as_bytes())?;
        Ok(())
    }

    /// Read the contents of a previously saved report file.
    ///
    /// # Errors
    /// Returns `anyhow::Error` on I/O failure.
    pub fn load(path: &Path) -> Result<String> {
        let bytes = std::fs::read(path)?;
        let text = String::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("report file is not valid UTF-8: {e}"))?;
        Ok(text)
    }

    /// Round-trip helper: save and immediately reload, returning the reloaded string.
    ///
    /// Useful for smoke-testing persistence in unit tests.
    ///
    /// # Errors
    /// Returns `anyhow::Error` on I/O failure.
    pub fn save_and_reload(report: &str, format: ReportFormat, path: &Path) -> Result<String> {
        Self::save(report, format, path)?;
        Self::load(path)
    }
}

// â"€â"€â"€ SandboxEvent (local lightweight definition) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// Defined here so that `BehaviorTimeline` can operate independently of the
// VM crate.  Consumers bridging the two crates should convert their VM-crate
// events into this type before calling `BehaviorTimeline::build`.

/// High-level category for a lightweight `SandboxEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxEventKind {
    /// An API function was called.
    ApiCall(String),
    /// A file operation (create / write / delete).
    FileOp(String),
    /// A network connection was attempted.
    NetworkConn,
    /// A registry key was read or written.
    RegistryOp,
    /// A process or thread was created.
    ProcessSpawn,
    /// Code injection detected.
    CodeInjection,
    /// Shadow-copy delete detected.
    DeleteShadowCopies,
    /// File extension changed (ransomware indicator).
    ExtensionChange,
    /// Screen-capture API called.
    ScreenCapture,
    /// Keyboard-hook API called.
    KeyboardHook,
    /// High CPU usage observed.
    HighCpuLoad,
    /// A module / DLL was loaded.
    ModuleLoad(String),
    /// Mutex created.
    MutexCreate,
    /// Generic / uncategorised.
    Other(String),
}

impl fmt::Display for SandboxEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiCall(n) => write!(f, "api:{n}"),
            Self::FileOp(p) => write!(f, "file:{p}"),
            Self::NetworkConn => write!(f, "net"),
            Self::RegistryOp => write!(f, "reg"),
            Self::ProcessSpawn => write!(f, "proc"),
            Self::CodeInjection => write!(f, "inject"),
            Self::DeleteShadowCopies => write!(f, "vss_delete"),
            Self::ExtensionChange => write!(f, "ext_change"),
            Self::ScreenCapture => write!(f, "screenshot"),
            Self::KeyboardHook => write!(f, "keyhook"),
            Self::HighCpuLoad => write!(f, "cpu_high"),
            Self::ModuleLoad(m) => write!(f, "mod:{m}"),
            Self::MutexCreate => write!(f, "mutex"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

/// A discrete event recorded during sandbox execution (report crate version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvent {
    /// Milliseconds since execution start.
    pub ts_ms: u64,
    /// PID that generated this event.
    pub pid: u32,
    /// High-level category.
    pub kind: SandboxEventKind,
    /// Human-readable detail string.
    pub detail: String,
}

impl SandboxEvent {
    /// Create a new event.
    #[must_use]
    pub fn new(ts_ms: u64, pid: u32, kind: SandboxEventKind, detail: impl Into<String>) -> Self {
        Self {
            ts_ms,
            pid,
            kind,
            detail: detail.into(),
        }
    }
}

// ─── ReportRenderer ───────────────────────────────────────────

/// Renders a `SandboxReport` to multiple output formats.
///
/// Unlike `SandboxReportBuilder` (which assembles a report from enrichment
/// data), `SandboxReportRenderer` takes an already-complete `SandboxReport`
/// and focuses purely on format conversion.
///
/// The `report` field is kept as a convenience for callers that want to call
/// `render_*` methods without passing the report each time (use
/// `self.report`).  The three render methods also accept an explicit
/// `&SandboxReport` so that they can be called on a different report if
/// needed.
pub struct SandboxReportRenderer<'a> {
    report: &'a SandboxReport,
}

impl<'a> SandboxReportRenderer<'a> {
    /// Borrow the underlying report.
    #[must_use]
    pub const fn report(&self) -> &'a SandboxReport {
        self.report
    }

    /// Create a renderer for the given report.
    #[must_use]
    pub const fn new(report: &'a SandboxReport) -> Self {
        Self { report }
    }

    // â"€â"€ HTML â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as a self-contained HTML page with inline CSS.
    #[must_use]
    pub fn render_html(&self, report: &SandboxReport) -> String {
        let r = report;
        let verdict_class = match r.verdict {
            Verdict::Malicious => "verdict-malicious",
            Verdict::Suspicious => "verdict-suspicious",
            Verdict::Low => "verdict-low",
            Verdict::Clean => "verdict-clean",
            Verdict::Unknown => "verdict-unknown",
        };
        let indicator_rows = Self::render_html_indicator_rows(r);
        let behavior_rows = Self::render_html_behavior_rows(r);
        let tags_html = Self::render_html_tags(r);
        Self::assemble_renderer_html(
            r,
            verdict_class,
            &indicator_rows,
            &behavior_rows,
            &tags_html,
        )
    }

    fn render_html_indicator_rows(r: &SandboxReport) -> String {
        r.indicators.iter().fold(String::new(), |mut acc, i| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td class=\"sev-{}\">{}</td></tr>",
                html_escape(&i.name),
                html_escape(&i.desc),
                i.severity.to_string().to_ascii_lowercase(),
                html_escape(&i.severity.to_string()),
            );
            acc
        })
    }

    fn render_html_behavior_rows(r: &SandboxReport) -> String {
        r.behaviors.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td class=\"sev-{}\">{}</td><td>{}</td></tr>",
                html_escape(&b.name),
                html_escape(&b.desc),
                b.severity.to_string().to_ascii_lowercase(),
                html_escape(&b.severity.to_string()),
                html_escape(&b.category),
            );
            acc
        })
    }

    fn render_html_tags(r: &SandboxReport) -> String {
        if r.tags.is_empty() {
            "<span class=\"no-data\">none</span>".to_string()
        } else {
            r.tags
                .iter()
                .map(|t| format!("<span class=\"tag\">{}</span>", html_escape(t)))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    fn assemble_renderer_html(
        r: &SandboxReport,
        verdict_class: &str,
        indicator_rows: &str,
        behavior_rows: &str,
        tags_html: &str,
    ) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Sandbox Report —  {sample}</title>
<style>
body{{font-family:sans-serif;margin:2rem;background:#f5f5f5;color:#333}}
h1{{border-bottom:3px solid #e63946;padding-bottom:.5rem}}
h2{{margin-top:2rem;color:#1d3557}}
table{{border-collapse:collapse;width:100%;margin-bottom:1rem}}
th,td{{border:1px solid #ccc;padding:.5rem .75rem;text-align:left}}
th{{background:#1d3557;color:#fff}}
tr:nth-child(even){{background:#eee}}
.verdict-malicious{{color:#fff;background:#e63946;padding:.2rem .6rem;border-radius:4px;font-weight:bold}}
.verdict-suspicious{{color:#fff;background:#f4a261;padding:.2rem .6rem;border-radius:4px;font-weight:bold}}
.verdict-clean{{color:#fff;background:#2a9d8f;padding:.2rem .6rem;border-radius:4px;font-weight:bold}}
.verdict-unknown{{color:#fff;background:#457b9d;padding:.2rem .6rem;border-radius:4px;font-weight:bold}}
.sev-critical{{color:#e63946;font-weight:bold}}
.sev-high{{color:#f4a261;font-weight:bold}}
.sev-medium{{color:#e9c46a}}
.sev-low{{color:#2a9d8f}}
.sev-info{{color:#aaa}}
.tag{{display:inline-block;background:#457b9d;color:#fff;padding:.1rem .5rem;border-radius:3px;margin:.1rem;font-size:.85rem}}
.no-data{{color:#999;font-style:italic}}
.score-bar{{width:100%;background:#ddd;border-radius:4px;height:1.2rem}}
.score-fill{{height:1.2rem;border-radius:4px;background:#e63946}}
</style>
</head>
<body>
<h1>Sandbox Analysis Report</h1>

<h2>Executive Summary</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Sample</td><td><code>{sample}</code></td></tr>
<tr><td>SHA-256</td><td><code>{sha256}</code></td></tr>
<tr><td>Verdict</td><td><span class="{verdict_class}">{verdict}</span></td></tr>
<tr><td>Threat Score</td><td>
  <div class="score-bar"><div class="score-fill" style="width:{score}%"></div></div>
  {score} / 100
</td></tr>
<tr><td>Family</td><td>{family}</td></tr>
<tr><td>Analysis Duration</td><td>{analysis_ms} ms</td></tr>
</table>

<h2>Tags</h2>
<p>{tags}</p>

<h2>Indicators ({n_indicators})</h2>
<table>
<tr><th>Name</th><th>Description</th><th>Severity</th></tr>
{indicator_rows}
</table>

<h2>Behaviors ({n_behaviors})</h2>
<table>
<tr><th>Name</th><th>Description</th><th>Severity</th><th>Category</th></tr>
{behavior_rows}
</table>

<h2>MITRE ATT&amp;CK TTPs</h2>
<p>{ttps}</p>
</body>
</html>"#,
            sample = html_escape(&r.sample),
            sha256 = html_escape(&r.sha256),
            verdict_class = verdict_class,
            verdict = html_escape(&r.verdict.to_string()),
            score = r.score.min(100),
            family = html_escape(&r.family),
            analysis_ms = r.analysis_ms,
            tags = tags_html,
            n_indicators = r.indicators.len(),
            indicator_rows = indicator_rows,
            n_behaviors = r.behaviors.len(),
            behavior_rows = behavior_rows,
            ttps = if r.ttps.is_empty() {
                "<span class=\"no-data\">none</span>".to_string()
            } else {
                r.ttps
                    .iter()
                    .map(|t| html_escape(t))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        )
    }

    // â"€â"€ Markdown â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as a GitHub-flavoured Markdown document.
    #[must_use]
    pub fn render_markdown(&self, report: &SandboxReport) -> String {
        let r = report;
        let mut out = String::new();

        out.push_str("# Sandbox Analysis Report\n\n");

        // Summary table.
        out.push_str("## Executive Summary\n\n");
        let _ = write!(
            out,
            "| Field | Value |\n|---|---|\n\
             | Sample | `{sample}` |\n\
             | SHA-256 | `{sha256}` |\n\
             | Verdict | **{verdict}** |\n\
             | Score | {score}/100 |\n\
             | Family | `{family}` |\n\
             | Duration | {ms} ms |\n\n",
            sample = r.sample,
            sha256 = r.sha256,
            verdict = r.verdict,
            score = r.score,
            family = r.family,
            ms = r.analysis_ms,
        );

        if !r.tags.is_empty() {
            let _ = write!(out, "**Tags:** {}\n\n", r.tags.join(", "));
        }

        // Indicators.
        let _ = write!(out, "## Indicators ({})\n\n", r.indicators.len());
        if r.indicators.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            out.push_str("| Name | Description | Severity |\n|---|---|---|\n");
            for ind in &r.indicators {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} |",
                    md_escape(&ind.name),
                    md_escape(&ind.desc),
                    ind.severity,
                );
            }
            out.push('\n');
        }

        // Behaviors.
        let _ = write!(out, "## Behaviors ({})\n\n", r.behaviors.len());
        if r.behaviors.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            out.push_str("| Name | Description | Severity | Category |\n|---|---|---|---|\n");
            for beh in &r.behaviors {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    md_escape(&beh.name),
                    md_escape(&beh.desc),
                    beh.severity,
                    md_escape(&beh.category),
                );
            }
            out.push('\n');
        }

        // TTPs.
        out.push_str("## MITRE ATT&CK\n\n");
        if r.ttps.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for ttp in &r.ttps {
                let _ = writeln!(out, "- `{ttp}`");
            }
            out.push('\n');
        }

        out
    }

    // â"€â"€ JSON â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Render the report as pretty-printed JSON.
    ///
    /// # Errors
    /// Returns a JSON error string if serialisation fails (should never happen
    /// for well-formed `SandboxReport` values).
    #[must_use]
    pub fn render_json(&self, report: &SandboxReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

// â"€â"€â"€ BehaviorTimeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A timeline of sandbox events ordered by their millisecond timestamp.
pub struct BehaviorTimeline {
    /// Events sorted by `ts_ms` in ascending order.
    events: Vec<SandboxEvent>,
}

impl BehaviorTimeline {
    /// Build a `BehaviorTimeline` from an unordered slice of events.
    ///
    /// Events are cloned and sorted by `ts_ms`.
    #[must_use]
    pub fn build(events: &[SandboxEvent]) -> Self {
        let mut sorted = events.to_vec();
        sorted.sort_by_key(|e| e.ts_ms);
        Self { events: sorted }
    }

    /// Return a reference to the sorted event list.
    #[must_use]
    pub fn events(&self) -> &[SandboxEvent] {
        &self.events
    }

    /// Return the number of events in the timeline.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the timeline contains no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Produce a human-readable one-line summary per second of activity.
    ///
    /// Each output line has the form:
    ///
    /// ```text
    /// t=<second>s  [<N> events]  <kind1>, <kind2>, ...
    /// ```
    ///
    /// where `<N>` is the number of events in that second and the kinds are
    /// the distinct `SandboxEventKind` display values (up to 5, then `—¦`).
    #[must_use]
    pub fn summary(&self) -> String {
        if self.events.is_empty() {
            return "(no events)".to_string();
        }

        // Group events into 1-second buckets.
        let mut buckets: HashMap<u64, Vec<&SandboxEvent>> = HashMap::new();
        for e in &self.events {
            let bucket = e.ts_ms / 1000;
            buckets.entry(bucket).or_default().push(e);
        }

        let mut entries: Vec<(u64, Vec<&SandboxEvent>)> = buckets.into_iter().collect();
        entries.sort_unstable_by_key(|(sec, _)| *sec);

        let mut lines = Vec::with_capacity(entries.len());
        for (sec, evts) in &entries {
            let count = evts.len();

            // Collect distinct kind strings.
            let mut kinds: Vec<String> = evts.iter().map(|e| e.kind.to_string()).collect();
            kinds.sort_unstable();
            kinds.dedup();

            let kinds_str = if kinds.len() > 5 {
                let mut s = kinds[..5].join(", ");
                s.push_str(", ...");
                s
            } else {
                kinds.join(", ")
            };

            lines.push(format!("t={sec:>6}s  [{count:>4} events]  {kinds_str}"));
        }

        lines.join("\n")
    }

    /// Return the timestamp (ms) of the first event, or 0 if empty.
    #[must_use]
    pub fn start_ms(&self) -> u64 {
        self.events.first().map_or(0, |e| e.ts_ms)
    }

    /// Return the timestamp (ms) of the last event, or 0 if empty.
    #[must_use]
    pub fn end_ms(&self) -> u64 {
        self.events.last().map_or(0, |e| e.ts_ms)
    }

    /// Total wall-clock span of the timeline in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        self.end_ms().saturating_sub(self.start_ms())
    }
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Severity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_severity_score_info() {
        assert_eq!(Severity::Info.score(), 0);
    }

    #[test]
    fn test_severity_score_low() {
        assert_eq!(Severity::Low.score(), 25);
    }

    #[test]
    fn test_severity_score_medium() {
        assert_eq!(Severity::Medium.score(), 50);
    }

    #[test]
    fn test_severity_score_high() {
        assert_eq!(Severity::High.score(), 75);
    }

    #[test]
    fn test_severity_score_critical() {
        assert_eq!(Severity::Critical.score(), 100);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_severity_parse_ok() {
        assert_eq!(Severity::parse("medium").unwrap(), Severity::Medium);
        assert_eq!(Severity::parse("CRITICAL").unwrap(), Severity::Critical);
    }

    #[test]
    fn test_severity_parse_err() {
        assert!(Severity::parse("extreme").is_err());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
    }

    // â"€â"€ IocKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_ioc_kind_display() {
        assert_eq!(IocKind::Ip.to_string(), "ip");
        assert_eq!(IocKind::Domain.to_string(), "domain");
        assert_eq!(IocKind::FileHash.to_string(), "filehash");
    }

    // â"€â"€ IocSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_ioc_set_add_and_len() {
        let mut s = IocSet::new();
        s.add(Ioc::new(IocKind::Ip, "1.2.3.4", 90, "c2"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_ioc_set_by_kind() {
        let s = IocSet::mock();
        let ips = s.by_kind(&IocKind::Ip);
        assert!(!ips.is_empty());
    }

    #[test]
    fn test_ioc_set_confident() {
        let s = IocSet::mock();
        let confident = s.confident(90);
        assert!(!confident.is_empty());
        for ioc in &confident {
            assert!(ioc.confidence >= 90);
        }
    }

    #[test]
    fn test_ioc_set_deduplicate() {
        let mut s = IocSet::new();
        s.add(Ioc::new(IocKind::Ip, "1.2.3.4", 90, "a"));
        s.add(Ioc::new(IocKind::Ip, "1.2.3.4", 80, "b"));
        s.deduplicate();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_ioc_set_is_empty() {
        let s = IocSet::new();
        assert!(s.is_empty());
    }

    #[test]
    fn test_ioc_set_mock_not_empty() {
        let s = IocSet::mock();
        assert!(!s.is_empty());
    }

    // â"€â"€ AttackTactic â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_attack_tactic_display() {
        assert_eq!(AttackTactic::Persistence.to_string(), "persistence");
        assert_eq!(
            AttackTactic::CommandAndControl.to_string(),
            "command_and_control"
        );
        assert_eq!(AttackTactic::Impact.to_string(), "impact");
    }

    // â"€â"€ AttackMapping â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_attack_mapping_from_behaviors_injection() {
        let m = AttackMapping::from_behaviors(&["injection"]);
        assert!(!m.techniques.is_empty());
        assert!(m.technique_ids().iter().any(|id| id.contains("T1055")));
    }

    #[test]
    fn test_attack_mapping_from_behaviors_persistence() {
        let m = AttackMapping::from_behaviors(&["persistence"]);
        assert!(m.technique_ids().iter().any(|id| id.contains("T1547")));
    }

    #[test]
    fn test_attack_mapping_by_tactic() {
        let m = AttackMapping::from_behaviors(&["injection", "c2"]);
        let evasion = m.by_tactic(&AttackTactic::DefenseEvasion);
        assert!(!evasion.is_empty());
    }

    #[test]
    fn test_attack_mapping_tactics_present() {
        let m = AttackMapping::from_behaviors(&["injection", "persistence", "c2"]);
        let tactics = m.tactics_present();
        assert!(!tactics.is_empty());
    }

    #[test]
    fn test_attack_mapping_high_confidence() {
        let m = AttackMapping::from_behaviors(&["persistence"]);
        let high = m.high_confidence();
        assert!(!high.is_empty());
    }

    // â"€â"€ Indicator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_indicator_new() {
        let i = Indicator::new("test", "desc", Severity::High, IndicatorCategory::Injection);
        assert_eq!(i.name, "test");
        assert!(i.ioc.is_none());
        assert!(i.technique_ids.is_empty());
    }

    #[test]
    fn test_indicator_with_ioc() {
        let i =
            Indicator::new("t", "d", Severity::Low, IndicatorCategory::Other).with_ioc("1.2.3.4");
        assert_eq!(i.ioc.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn test_indicator_with_technique() {
        let i = Indicator::new("t", "d", Severity::Low, IndicatorCategory::Other)
            .with_technique("T1055");
        assert_eq!(i.technique_ids.len(), 1);
    }

    #[test]
    fn test_indicator_category_display() {
        assert_eq!(IndicatorCategory::Injection.to_string(), "injection");
        assert_eq!(IndicatorCategory::Ransomware.to_string(), "ransomware");
    }

    // â"€â"€ ScoreEngine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_score_engine_empty() {
        let e = ScoreEngine::new();
        assert_eq!(e.compute(&[]), 0);
    }

    #[test]
    fn test_score_engine_critical_verdict() {
        let e = ScoreEngine::new();
        let indicators = vec![
            Indicator::new("inj", "d", Severity::Critical, IndicatorCategory::Injection),
            Indicator::new(
                "ran",
                "d",
                Severity::Critical,
                IndicatorCategory::Ransomware,
            ),
        ];
        let score = e.compute(&indicators);
        assert!(score > 0);
        // Because Critical indicators exist, has_critical returns true.
        assert!(ScoreEngine::has_critical(&indicators));
    }

    #[test]
    fn test_score_engine_clean_verdict() {
        let e = ScoreEngine::new();
        assert_eq!(e.verdict(0), Verdict::Clean);
    }

    #[test]
    fn test_score_engine_malicious_verdict() {
        let e = ScoreEngine::new();
        assert_eq!(e.verdict(85), Verdict::Malicious);
    }

    #[test]
    fn test_score_engine_suspicious_verdict() {
        let e = ScoreEngine::new();
        // Spec: 1..=30 -> Low, 31..=70 -> Suspicious. Use a value in the suspicious band.
        assert_eq!(e.verdict(50), Verdict::Suspicious);
    }

    #[test]
    fn test_score_engine_no_critical() {
        let indicators = vec![Indicator::new(
            "n",
            "d",
            Severity::Low,
            IndicatorCategory::Other,
        )];
        assert!(!ScoreEngine::has_critical(&indicators));
    }

    // â"€â"€ BehaviorClassifier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_classifier_injection_apis() {
        let c = BehaviorClassifier::new();
        let (indicators, behaviors) =
            c.classify(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
        assert!(!indicators.is_empty());
        assert!(!behaviors.is_empty());
        let has_crit = indicators.iter().any(|i| i.severity == Severity::Critical);
        assert!(has_crit);
    }

    #[test]
    fn test_classifier_network_apis() {
        let c = BehaviorClassifier::new();
        let (indicators, _) = c.classify(&["InternetConnect", "HttpSendRequest"]);
        let has_net = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Network);
        assert!(has_net);
    }

    #[test]
    fn test_classifier_debug_check() {
        let c = BehaviorClassifier::new();
        let (indicators, _) = c.classify(&["IsDebuggerPresent"]);
        let has_evasion = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Evasion);
        assert!(has_evasion);
    }

    #[test]
    fn test_classifier_keylogger() {
        let c = BehaviorClassifier::new();
        let (indicators, _) = c.classify(&["SetWindowsHookEx"]);
        let has_kl = indicators
            .iter()
            .any(|i| i.category == IndicatorCategory::Keylogging);
        assert!(has_kl);
    }

    #[test]
    fn test_classifier_infer_family_trojan() {
        let indicators = vec![
            Indicator::new("n", "d", Severity::Critical, IndicatorCategory::Injection),
            Indicator::new("n2", "d", Severity::High, IndicatorCategory::Network),
        ];
        assert_eq!(BehaviorClassifier::infer_family(&indicators), "trojan");
    }

    #[test]
    fn test_classifier_infer_family_unknown() {
        let indicators: Vec<Indicator> = vec![];
        assert_eq!(BehaviorClassifier::infer_family(&indicators), "unknown");
    }

// ─── ReportRenderer ───────────────────────────────────────────

    #[test]
    fn test_renderer_json_contains_sample() {
        let r = SandboxReport::mock();
        let renderer = ReportRenderer::new();
        let json = renderer.render_json(&r).unwrap();
        assert!(json.contains("malware.exe"));
    }

    #[test]
    fn test_renderer_markdown_contains_verdict() {
        let r = SandboxReport::mock();
        let md = r.to_markdown();
        assert!(md.contains("malicious") || md.contains("Malicious"));
    }

    #[test]
    fn test_renderer_html_contains_title() {
        let r = SandboxReport::mock();
        let html = r.to_html();
        assert!(html.contains("<html"));
        assert!(html.contains("malware.exe"));
    }

    #[test]
    fn test_renderer_html_verdict_class() {
        let r = SandboxReport::mock();
        let html = r.to_html();
        assert!(html.contains("verdict-malicious"));
    }

    // â"€â"€ SandboxReport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_report_new() {
        let r = SandboxReport::new("sample.exe", "abc123");
        assert_eq!(r.sample, "sample.exe");
        assert_eq!(r.sha256, "abc123");
        assert_eq!(r.verdict, Verdict::Unknown);
        assert_eq!(r.score, 0);
    }

    #[test]
    fn test_report_add_indicator() {
        let mut r = SandboxReport::new("s", "h");
        r.add_indicator(Indicator::new(
            "test",
            "test",
            Severity::Low,
            IndicatorCategory::Other,
        ));
        assert_eq!(r.indicators.len(), 1);
    }

    #[test]
    fn test_report_add_behavior() {
        let mut r = SandboxReport::new("s", "h");
        r.add_behavior(Behavior::new("b", "d", Severity::Medium, "misc"));
        assert_eq!(r.behaviors.len(), 1);
    }

    #[test]
    fn test_report_add_ttp() {
        let mut r = SandboxReport::new("s", "h");
        r.add_ttp("T1055");
        assert_eq!(r.ttps.len(), 1);
        assert_eq!(r.ttps[0], "T1055");
    }

    #[test]
    fn test_compute_score_clean() {
        let mut r = SandboxReport::new("s", "h");
        r.compute_score();
        assert_eq!(r.score, 0);
        assert_eq!(r.verdict, Verdict::Clean);
    }

    #[test]
    fn test_compute_score_malicious_with_critical() {
        let mut r = SandboxReport::new("s", "h");
        r.add_indicator(Indicator::new(
            "inj",
            "code injection",
            Severity::Critical,
            IndicatorCategory::Injection,
        ));
        r.compute_score();
        assert_eq!(r.verdict, Verdict::Malicious);
    }

    #[test]
    fn test_compute_score_capped_at_100() {
        let mut r = SandboxReport::new("s", "h");
        for _ in 0..10 {
            r.add_indicator(Indicator::new(
                "x",
                "y",
                Severity::High,
                IndicatorCategory::Injection,
            ));
        }
        r.compute_score();
        assert!(r.score <= 100);
    }

    #[test]
    fn test_to_json() {
        let r = SandboxReport::mock();
        let json = r.to_json().unwrap();
        assert!(json.contains("malware.exe"));
    }

    #[test]
    fn test_mock_has_verdict_malicious() {
        let r = SandboxReport::mock();
        assert_eq!(r.verdict, Verdict::Malicious);
    }

    #[test]
    fn test_mock_has_ttps() {
        let r = SandboxReport::mock();
        assert!(!r.ttps.is_empty());
    }

    #[test]
    fn test_mock_has_behaviors() {
        let r = SandboxReport::mock();
        assert!(!r.behaviors.is_empty());
    }

    #[test]
    fn test_mock_has_iocs() {
        let r = SandboxReport::mock();
        assert!(!r.iocs.is_empty());
    }

    #[test]
    fn test_mock_has_attack_mapping() {
        let r = SandboxReport::mock();
        assert!(!r.attack.techniques.is_empty());
    }

    #[test]
    fn test_mock_has_sections() {
        let r = SandboxReport::mock();
        assert!(!r.sections.is_empty());
    }

    #[test]
    fn test_mock_family_inferred() {
        let r = SandboxReport::mock();
        assert!(!r.family.is_empty());
        assert_ne!(r.family, "unknown");
    }

    #[test]
    fn test_report_serialization_roundtrip() {
        let r = SandboxReport::mock();
        let json = r.to_json().unwrap();
        let decoded: SandboxReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sample, r.sample);
        assert_eq!(decoded.verdict, r.verdict);
    }

    #[test]
    fn test_report_error_serialize() {
        let e = ReportError::Serialize("json error".to_string());
        assert!(e.to_string().contains("json error"));
    }

    #[test]
    fn test_report_error_invalid_data() {
        let e = ReportError::InvalidData("missing field".to_string());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn test_report_critical_indicators() {
        let r = SandboxReport::mock();
        let crits = r.critical_indicators();
        assert!(!crits.is_empty());
    }

    #[test]
    fn test_report_indicators_by_category() {
        let r = SandboxReport::mock();
        let net = r.indicators_by_category(&IndicatorCategory::Network);
        assert!(!net.is_empty());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(Verdict::Clean.to_string(), "clean");
        assert_eq!(Verdict::Suspicious.to_string(), "suspicious");
        assert_eq!(Verdict::Malicious.to_string(), "malicious");
        assert_eq!(Verdict::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_html_escape_basics() {
        let s = html_escape("<script>alert('xss')</script>");
        assert!(!s.contains('<'));
        assert!(!s.contains('>'));
    }

    #[test]
    fn test_report_section_order() {
        let mut r = SandboxReport::new("s", "h");
        r.add_section(ReportSection::new("Second", "content", 2));
        r.add_section(ReportSection::new("First", "content", 1));
        assert_eq!(r.sections[0].title, "First");
    }

    #[test]
    fn test_attack_technique_full_id_with_sub() {
        let t = AttackTechnique {
            id: "T1055".to_string(),
            sub_id: Some("T1055.001".to_string()),
            name: "DLL Injection".to_string(),
            tactic: AttackTactic::DefenseEvasion,
            evidence: vec![],
            confidence: 90,
        };
        assert_eq!(t.full_id(), "T1055.001");
    }

    #[test]
    fn test_attack_technique_full_id_no_sub() {
        let t = AttackTechnique {
            id: "T1497".to_string(),
            sub_id: None,
            name: "Sandbox Evasion".to_string(),
            tactic: AttackTactic::DefenseEvasion,
            evidence: vec![],
            confidence: 80,
        };
        assert_eq!(t.full_id(), "T1497");
    }

    // â"€â"€ ReportFormat â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_report_format_display() {
        assert_eq!(ReportFormat::Json.to_string(), "json");
        assert_eq!(ReportFormat::Html.to_string(), "html");
        assert_eq!(ReportFormat::Pdf.to_string(), "pdf");
        assert_eq!(ReportFormat::Csv.to_string(), "csv");
        assert_eq!(ReportFormat::Markdown.to_string(), "markdown");
    }

    #[test]
    fn test_report_format_extension() {
        assert_eq!(ReportFormat::Json.extension(), "json");
        assert_eq!(ReportFormat::Html.extension(), "html");
        assert_eq!(ReportFormat::Markdown.extension(), "md");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
        assert_eq!(ReportFormat::Pdf.extension(), "pdf");
    }

    #[test]
    fn test_report_format_from_extension_ok() {
        assert_eq!(
            ReportFormat::from_extension("json").unwrap(),
            ReportFormat::Json
        );
        assert_eq!(
            ReportFormat::from_extension("HTML").unwrap(),
            ReportFormat::Html
        );
        assert_eq!(
            ReportFormat::from_extension(".md").unwrap(),
            ReportFormat::Markdown
        );
        assert_eq!(
            ReportFormat::from_extension("csv").unwrap(),
            ReportFormat::Csv
        );
    }

    #[test]
    fn test_report_format_from_extension_err() {
        assert!(ReportFormat::from_extension("xyz").is_err());
        assert!(ReportFormat::from_extension("docx").is_err());
    }

    // â"€â"€ IocCollection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_ioc_collection_new_empty() {
        let c = IocCollection::new();
        assert!(c.is_empty());
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn test_ioc_collection_mock_not_empty() {
        let c = IocCollection::mock();
        assert!(!c.is_empty());
        assert!(c.total() > 0);
    }

    #[test]
    fn test_ioc_collection_summary_text_has_ips() {
        let c = IocCollection::mock();
        let text = c.summary_text();
        assert!(text.contains("185.220.101.1"));
    }

    #[test]
    fn test_ioc_collection_summary_text_has_domains() {
        let c = IocCollection::mock();
        let text = c.summary_text();
        assert!(text.contains("c2server.evil"));
    }

    #[test]
    fn test_ioc_collection_to_csv_header() {
        let c = IocCollection::mock();
        let csv = c.to_csv();
        assert!(csv.starts_with("type,value\n"));
    }

    #[test]
    fn test_ioc_collection_to_csv_contains_ip() {
        let c = IocCollection::mock();
        let csv = c.to_csv();
        assert!(csv.contains("ip,185.220.101.1"));
    }

    #[test]
    fn test_ioc_collection_to_csv_contains_domain() {
        let c = IocCollection::mock();
        let csv = c.to_csv();
        assert!(csv.contains("domain,c2server.evil"));
    }

    // â"€â"€ SandboxReportBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_builder_new() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r.clone());
        assert_eq!(builder.report().sample, r.sample);
        assert!(builder.iocs().is_none());
    }

    #[test]
    fn test_builder_add_iocs() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        builder.add_iocs(IocCollection::mock());
        assert!(builder.iocs().is_some());
    }

    #[test]
    fn test_builder_build_json_contains_sample() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let json = builder.build_json();
        assert!(json.contains("malware.exe"));
    }

    #[test]
    fn test_builder_build_json_contains_verdict() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let json = builder.build_json();
        // Verdict is serialised using the Serde-derived form ("Malicious") or the
        // Display form ("malicious") depending on the derive; accept either.
        assert!(json.to_ascii_lowercase().contains("malicious"));
    }

    #[test]
    fn test_builder_build_json_with_iocs() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        builder.add_iocs(IocCollection::mock());
        let json = builder.build_json();
        assert!(json.contains("185.220.101.1"));
    }

    #[test]
    fn test_builder_build_json_is_valid() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let json = builder.build_json();
        // Must be parseable.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(v.is_object());
    }

    #[test]
    fn test_builder_build_markdown_contains_title() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("# Sandbox Analysis Report"));
    }

    #[test]
    fn test_builder_build_markdown_contains_executive_summary() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## Executive Summary"));
    }

    #[test]
    fn test_builder_build_markdown_contains_file_information() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## File Information"));
    }

    #[test]
    fn test_builder_build_markdown_contains_behavioral_analysis() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## Behavioral Analysis"));
    }

    #[test]
    fn test_builder_build_markdown_contains_iocs_section() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## IOCs"));
    }

    #[test]
    fn test_builder_build_markdown_contains_attack_section() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## MITRE ATT&CK Mapping"));
    }

    #[test]
    fn test_builder_build_markdown_contains_dropped_files() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        assert!(md.contains("## Dropped Files"));
    }

    #[test]
    fn test_builder_build_markdown_with_ioc_collection() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        builder.add_iocs(IocCollection::mock());
        let md = builder.build_markdown();
        assert!(md.contains("c2server.evil"));
    }

    #[test]
    fn test_builder_build_markdown_with_ttp_map() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        let mut ttps = HashMap::new();
        ttps.insert(
            "T1055".to_string(),
            vec!["WriteProcessMemory called".to_string()],
        );
        builder.add_ttp_map(ttps);
        let md = builder.build_markdown();
        assert!(md.contains("T1055"));
    }

    #[test]
    fn test_builder_build_html_is_html() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_builder_build_html_contains_sample() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        assert!(html.contains("malware.exe"));
    }

    #[test]
    fn test_builder_build_html_has_css() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        assert!(html.contains("<style>"));
    }

    #[test]
    fn test_builder_build_html_verdict_badge() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        assert!(html.contains("verdict-malicious"));
    }

    #[test]
    fn test_builder_build_html_sections() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        assert!(html.contains("Behavioral Analysis"));
        assert!(html.contains("MITRE ATT"));
        assert!(html.contains("Dropped Files"));
    }

    #[test]
    fn test_builder_build_html_with_iocs() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        builder.add_iocs(IocCollection::mock());
        let html = builder.build_html();
        assert!(html.contains("c2server.evil"));
    }

    #[test]
    fn test_builder_build_csv_header() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let csv = builder.build_csv();
        assert!(csv.starts_with("type,value,confidence\n"));
    }

    #[test]
    fn test_builder_build_csv_contains_ioc_data() {
        let r = SandboxReport::mock();
        let mut builder = SandboxReportBuilder::new(r);
        builder.add_iocs(IocCollection::mock());
        let csv = builder.build_csv();
        assert!(csv.contains("185.220.101.1"));
    }

    #[test]
    fn test_builder_build_csv_from_ioc_set() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let csv = builder.build_csv();
        // Mock report has an IocSet with an IP.
        assert!(csv.contains("ip,185.220.101.1"));
    }

    // â"€â"€ ReportStore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_report_store_save_and_load() {
        let dir = std::env::temp_dir().join("rustre_report_store_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("report.json");
        let content = "{\"test\":true}";
        ReportStore::save(content, ReportFormat::Json, &path).unwrap();
        let loaded = ReportStore::load(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded, content);
    }

    #[test]
    fn test_report_store_save_creates_parent_dirs() {
        let dir = std::env::temp_dir()
            .join("rustre_report_store_nested")
            .join("sub");
        let path = dir.join("r.md");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        ReportStore::save("# test", ReportFormat::Markdown, &path).unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn test_report_store_load_not_found() {
        let path = std::path::PathBuf::from("/tmp/this_file_does_not_exist_rustre_99.txt");
        assert!(ReportStore::load(&path).is_err());
    }

    #[test]
    fn test_report_store_save_and_reload() {
        let dir = std::env::temp_dir().join("rustre_report_store_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roundtrip.html");
        let content = "<html>test</html>";
        let reloaded = ReportStore::save_and_reload(content, ReportFormat::Html, &path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reloaded, content);
    }

    #[test]
    fn test_report_store_roundtrip_markdown() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let md = builder.build_markdown();
        let dir = std::env::temp_dir().join("rustre_md_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("report.md");
        let reloaded = ReportStore::save_and_reload(&md, ReportFormat::Markdown, &path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reloaded, md);
    }

    #[test]
    fn test_report_store_roundtrip_html() {
        let r = SandboxReport::mock();
        let builder = SandboxReportBuilder::new(r);
        let html = builder.build_html();
        let dir = std::env::temp_dir().join("rustre_html_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("report.html");
        let reloaded = ReportStore::save_and_reload(&html, ReportFormat::Html, &path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reloaded, html);
    }

    // â"€â"€ csv_escape â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_csv_escape_no_comma() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_with_comma() {
        let escaped = csv_escape("a,b");
        assert!(escaped.starts_with('"') && escaped.ends_with('"'));
    }

    #[test]
    fn test_csv_escape_with_quote() {
        let escaped = csv_escape("say \"hi\"");
        assert!(escaped.contains("\"\""));
    }

// ─── ReportRenderer ───────────────────────────────────────────

    fn make_renderer_report() -> SandboxReport {
        let mut r = SandboxReport::new("test.exe", "aabbccdd");
        r.analysis_ms = 10_000;
        r.score = 75;
        r.verdict = Verdict::Malicious;
        r.family = "TestFamily".to_string();
        r.tags = vec!["ransomware".to_string(), "dropper".to_string()];
        r.add_indicator(Indicator::new(
            "FileMassWrite",
            "Many file writes",
            Severity::High,
            IndicatorCategory::Ransomware,
        ));
        let beh = Behavior::new(
            "ProcessInjection",
            "Code injected into svchost",
            Severity::Critical,
            "injection",
        );
        r.add_behavior(beh);
        r.add_ttp("T1059.001");
        r
    }

    #[test]
    fn test_render_html_contains_sample() {
        let r = make_renderer_report();
        let renderer = SandboxReportRenderer::new(&r);
        let html = renderer.render_html(&r);
        assert!(html.contains("test.exe"), "HTML should contain sample name");
        assert!(
            html.contains("<!DOCTYPE html>"),
            "Should be a full HTML document"
        );
        assert!(
            html.contains("FileMassWrite"),
            "Should contain indicator name"
        );
        assert!(html.contains("T1059.001"), "Should contain TTP");
    }

    #[test]
    fn test_render_html_verdict_class() {
        let r = make_renderer_report(); // verdict = Malicious
        let renderer = SandboxReportRenderer::new(&r);
        let html = renderer.render_html(&r);
        assert!(
            html.contains("verdict-malicious"),
            "Should contain verdict CSS class"
        );
    }

    #[test]
    fn test_render_html_escapes_special_chars() {
        let mut r = SandboxReport::new("<script>alert(1)</script>", "aa");
        r.verdict = Verdict::Clean;
        let renderer = SandboxReportRenderer::new(&r);
        let html = renderer.render_html(&r);
        assert!(
            !html.contains("<script>"),
            "Raw <script> tag should be escaped"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "Should contain escaped version"
        );
    }

    #[test]
    fn test_render_markdown_contains_fields() {
        let r = make_renderer_report();
        let renderer = SandboxReportRenderer::new(&r);
        let md = renderer.render_markdown(&r);
        assert!(md.contains("# Sandbox Analysis Report"));
        assert!(md.contains("test.exe"));
        assert!(md.contains("aabbccdd"));
        assert!(md.contains("FileMassWrite"));
        assert!(md.contains("ProcessInjection"));
        assert!(md.contains("T1059.001"));
    }

    #[test]
    fn test_render_markdown_empty_indicators() {
        let r = SandboxReport::new("clean.exe", "00000000");
        let renderer = SandboxReportRenderer::new(&r);
        let md = renderer.render_markdown(&r);
        assert!(md.contains("_None._"), "Empty indicators should show None");
    }

    #[test]
    fn test_render_json_is_valid_json() {
        let r = make_renderer_report();
        let renderer = SandboxReportRenderer::new(&r);
        let json = renderer.render_json(&r);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");
        assert_eq!(parsed["sample"], "test.exe");
        assert_eq!(parsed["sha256"], "aabbccdd");
    }

    #[test]
    fn test_render_json_pretty_indented() {
        let r = make_renderer_report();
        let renderer = SandboxReportRenderer::new(&r);
        let json = renderer.render_json(&r);
        // Pretty-printed JSON has newlines and indentation.
        assert!(json.contains('\n'), "JSON should be pretty-printed");
    }

    // â"€â"€ BehaviorTimeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_tl_event(ts_ms: u64, kind: SandboxEventKind) -> SandboxEvent {
        SandboxEvent::new(ts_ms, 1, kind, "")
    }

    #[test]
    fn test_behavior_timeline_sorts_events() {
        let events = vec![
            make_tl_event(3000, SandboxEventKind::NetworkConn),
            make_tl_event(1000, SandboxEventKind::ApiCall("CreateFile".to_string())),
            make_tl_event(2000, SandboxEventKind::ProcessSpawn),
        ];
        let tl = BehaviorTimeline::build(&events);
        assert_eq!(tl.events()[0].ts_ms, 1000);
        assert_eq!(tl.events()[1].ts_ms, 2000);
        assert_eq!(tl.events()[2].ts_ms, 3000);
    }

    #[test]
    fn test_behavior_timeline_len_and_empty() {
        let tl_empty = BehaviorTimeline::build(&[]);
        assert!(tl_empty.is_empty());
        assert_eq!(tl_empty.len(), 0);

        let events = vec![make_tl_event(0, SandboxEventKind::RegistryOp)];
        let tl = BehaviorTimeline::build(&events);
        assert!(!tl.is_empty());
        assert_eq!(tl.len(), 1);
    }

    #[test]
    fn test_behavior_timeline_duration() {
        let events = vec![
            make_tl_event(500, SandboxEventKind::NetworkConn),
            make_tl_event(5500, SandboxEventKind::ProcessSpawn),
        ];
        let tl = BehaviorTimeline::build(&events);
        assert_eq!(tl.start_ms(), 500);
        assert_eq!(tl.end_ms(), 5500);
        assert_eq!(tl.duration_ms(), 5000);
    }

    #[test]
    fn test_behavior_timeline_summary_empty() {
        let tl = BehaviorTimeline::build(&[]);
        assert_eq!(tl.summary(), "(no events)");
    }

    #[test]
    fn test_behavior_timeline_summary_groups_by_second() {
        let events = vec![
            make_tl_event(0, SandboxEventKind::NetworkConn),
            make_tl_event(500, SandboxEventKind::ApiCall("WriteFile".to_string())),
            make_tl_event(1100, SandboxEventKind::ProcessSpawn),
        ];
        let tl = BehaviorTimeline::build(&events);
        let summary = tl.summary();
        // First second (bucket 0) should contain 2 events.
        assert!(
            summary.contains("2 events") || summary.contains("[   2"),
            "first bucket should have 2 events"
        );
        // Second second (bucket 1) should contain 1 event.
        assert!(
            summary.contains("1 event") || summary.contains("[   1"),
            "second bucket should have 1 event"
        );
        // Each line should be on its own line.
        assert_eq!(summary.lines().count(), 2, "should have 2 time buckets");
    }

    #[test]
    fn test_behavior_timeline_summary_deduplicates_kinds() {
        let events = vec![
            make_tl_event(0, SandboxEventKind::NetworkConn),
            make_tl_event(0, SandboxEventKind::NetworkConn),
            make_tl_event(0, SandboxEventKind::NetworkConn),
        ];
        let tl = BehaviorTimeline::build(&events);
        let summary = tl.summary();
        // "net" should appear only once in the kind list even though there are 3 events.
        let net_occurrences = summary.matches("net").count();
        assert_eq!(
            net_occurrences, 1,
            "duplicate kinds should be deduped in summary"
        );
    }
}

