//! Sandbox analysis report generator.
//!
//! Aggregates all behavioral data from a sandbox run, computes a threat score,
//! extracts IOC lists, produces MITRE ATT&CK mappings, and outputs reports
//! in JSON or HTML format.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::api_monitor::{ApiChain, MalwareBehaviorPattern};
use crate::syscall_interceptor::{PatternMatch, SyscallPattern};

// ─── ReportFormat ─────────────────────────────────────────────────────────────

/// Output format for the sandbox report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    /// Machine-readable JSON.
    Json,
    /// Human-readable HTML with embedded CSS.
    Html,
    /// Plain text summary.
    PlainText,
    /// Compact YAML.
    Yaml,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
            Self::PlainText => write!(f, "text"),
            Self::Yaml => write!(f, "yaml"),
        }
    }
}

// ─── ThreatLevel ─────────────────────────────────────────────────────────────

/// Overall threat classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Clean — no suspicious activity detected.
    Clean,
    /// Low — minor suspicions, likely benign.
    Low,
    /// Medium — multiple suspicious indicators.
    Medium,
    /// High — strong evidence of malicious behavior.
    High,
    /// Critical — confirmed malware with active exploitation.
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl ThreatLevel {
    /// Determine threat level from a numeric score [0, 100].
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        if score == 0 {
            Self::Clean
        } else if score < 20 {
            Self::Low
        } else if score < 50 {
            Self::Medium
        } else if score < 80 {
            Self::High
        } else {
            Self::Critical
        }
    }

    /// Color code for HTML rendering.
    #[must_use]
    pub const fn color(&self) -> &'static str {
        match self {
            Self::Clean => "#22c55e",
            Self::Low => "#84cc16",
            Self::Medium => "#f59e0b",
            Self::High => "#ef4444",
            Self::Critical => "#7f1d1d",
        }
    }
}

// ─── ThreatScore ─────────────────────────────────────────────────────────────

/// A computed threat score with component breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// Total score [0, 100].
    pub total: u32,
    /// Overall threat level.
    pub level: ThreatLevel,
    /// Score contributions from individual components.
    pub components: Vec<ScoreComponent>,
}

impl ThreatScore {
    /// Compute a threat score from behavioral inputs.
    #[must_use]
    pub fn compute(inputs: &ScoreInputs) -> Self {
        let mut components = Vec::new();
        let mut total: u32 = 0;

        // Injection behaviors
        if inputs.has_process_injection {
            let pts = 30u32;
            components.push(ScoreComponent::new("process_injection", pts, "Process injection techniques detected"));
            total = total.saturating_add(pts);
        }

        // Persistence
        if inputs.has_persistence {
            let pts = 20u32;
            components.push(ScoreComponent::new("persistence", pts, "Persistence mechanism installed"));
            total = total.saturating_add(pts);
        }

        // C2 communication
        if inputs.has_c2_communication {
            let pts = 25u32;
            components.push(ScoreComponent::new("c2_comms", pts, "Command-and-control communication observed"));
            total = total.saturating_add(pts);
        }

        // Privilege escalation
        if inputs.has_privilege_escalation {
            let pts = 20u32;
            components.push(ScoreComponent::new("priv_escalation", pts, "Privilege escalation attempted"));
            total = total.saturating_add(pts);
        }

        // Anti-debug / anti-sandbox
        if inputs.anti_analysis_count > 0 {
            let pts = (inputs.anti_analysis_count * 5).min(20);
            components.push(ScoreComponent::new(
                "anti_analysis",
                pts,
                format!("{} anti-analysis technique(s)", inputs.anti_analysis_count),
            ));
            total = total.saturating_add(pts);
        }

        // Crypto operations (ransomware indicator)
        if inputs.crypto_api_calls > 5 {
            let pts = 15u32;
            components.push(ScoreComponent::new("crypto", pts, "High volume of crypto API calls"));
            total = total.saturating_add(pts);
        }

        // Blocked syscalls
        if inputs.blocked_syscalls > 0 {
            let pts = (inputs.blocked_syscalls * 2).min(15);
            components.push(ScoreComponent::new(
                "blocked_syscalls",
                pts,
                format!("{} blocked syscall(s)", inputs.blocked_syscalls),
            ));
            total = total.saturating_add(pts);
        }

        // Network activity without apparent user trigger
        if inputs.network_connections > 3 {
            let pts = 10u32;
            components.push(ScoreComponent::new("network", pts, "Significant outbound network activity"));
            total = total.saturating_add(pts);
        }

        // Registry modifications
        if inputs.registry_writes > 0 {
            let pts = 8u32;
            components.push(ScoreComponent::new("registry_writes", pts, "Registry keys modified"));
            total = total.saturating_add(pts);
        }

        // File system — suspicious paths
        if inputs.sensitive_file_accesses > 0 {
            let pts = 10u32;
            components.push(ScoreComponent::new(
                "sensitive_files",
                pts,
                "Access to sensitive file paths",
            ));
            total = total.saturating_add(pts);
        }

        let total = total.min(100);
        Self {
            level: ThreatLevel::from_score(total),
            total,
            components,
        }
    }
}

/// Inputs used to compute the threat score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreInputs {
    pub has_process_injection: bool,
    pub has_persistence: bool,
    pub has_c2_communication: bool,
    pub has_privilege_escalation: bool,
    pub anti_analysis_count: u32,
    pub crypto_api_calls: u32,
    pub blocked_syscalls: u32,
    pub network_connections: u32,
    pub registry_writes: u32,
    pub sensitive_file_accesses: u32,
}

/// A single component contributing to the threat score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreComponent {
    /// Short identifier.
    pub name: String,
    /// Points contributed.
    pub points: u32,
    /// Human-readable explanation.
    pub reason: String,
}

impl ScoreComponent {
    /// Create a new score component.
    #[must_use]
    pub fn new(name: impl Into<String>, points: u32, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            points,
            reason: reason.into(),
        }
    }
}

// ─── Ioc ─────────────────────────────────────────────────────────────────────

/// Indicator of compromise type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    /// File path accessed or created.
    FilePath,
    /// Registry key path.
    RegistryKey,
    /// Network hostname or IP.
    NetworkHost,
    /// Mutex name.
    Mutex,
    /// Process name.
    ProcessName,
    /// DNS query.
    DnsQuery,
    /// User-agent string.
    UserAgent,
    /// File hash.
    FileHash,
    /// URL.
    Url,
    /// Other IOC type.
    Other(String),
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FilePath => write!(f, "file_path"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::NetworkHost => write!(f, "network_host"),
            Self::Mutex => write!(f, "mutex"),
            Self::ProcessName => write!(f, "process_name"),
            Self::DnsQuery => write!(f, "dns_query"),
            Self::UserAgent => write!(f, "user_agent"),
            Self::FileHash => write!(f, "file_hash"),
            Self::Url => write!(f, "url"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

/// A single indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// Type of indicator.
    pub ioc_type: IocType,
    /// The indicator value.
    pub value: String,
    /// Optional context note.
    pub context: String,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
}

impl Ioc {
    /// Create a new IOC.
    #[must_use]
    pub fn new(ioc_type: IocType, value: impl Into<String>, context: impl Into<String>, confidence: f32) -> Self {
        Self {
            ioc_type,
            value: value.into(),
            context: context.into(),
            confidence,
        }
    }
}

// ─── IocList ─────────────────────────────────────────────────────────────────

/// Aggregated list of indicators of compromise.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocList {
    pub iocs: Vec<Ioc>,
}

impl IocList {
    /// Create an empty IOC list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an IOC.
    pub fn add(&mut self, ioc: Ioc) {
        self.iocs.push(ioc);
    }

    /// Filter IOCs by type.
    #[must_use]
    pub fn by_type(&self, ioc_type: &IocType) -> Vec<&Ioc> {
        self.iocs.iter().filter(|i| &i.ioc_type == ioc_type).collect()
    }

    /// Return the total count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.iocs.len()
    }

    /// Return true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Deduplicate IOCs by value.
    pub fn dedup(&mut self) {
        self.iocs.sort_by(|a, b| a.value.cmp(&b.value));
        self.iocs.dedup_by_key(|i| i.value.clone());
    }
}

// ─── MitreMapping ─────────────────────────────────────────────────────────────

/// A MITRE ATT&CK technique/sub-technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g. "T1055").
    pub id: String,
    /// Sub-technique ID (e.g. "T1055.001").
    pub sub_id: Option<String>,
    /// Technique name.
    pub name: String,
    /// Tactic (e.g. "Defense Evasion").
    pub tactic: String,
    /// Confidence that this technique applies [0.0, 1.0].
    pub confidence: f32,
    /// Source behavior that triggered this mapping.
    pub source: String,
}

impl MitreTechnique {
    /// Create a new technique mapping.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        tactic: impl Into<String>,
        confidence: f32,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sub_id: None,
            name: name.into(),
            tactic: tactic.into(),
            confidence,
            source: source.into(),
        }
    }

    /// Add a sub-technique ID.
    #[must_use]
    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub_id = Some(sub.into());
        self
    }

    /// Full ID string, including sub-technique if present.
    #[must_use]
    pub fn full_id(&self) -> String {
        match &self.sub_id {
            Some(s) => s.clone(),
            None => self.id.clone(),
        }
    }
}

/// A full MITRE ATT&CK mapping for a sandbox report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreMapping {
    pub techniques: Vec<MitreTechnique>,
}

impl MitreMapping {
    /// Create an empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a technique.
    pub fn add(&mut self, t: MitreTechnique) {
        if !self.techniques.iter().any(|e| e.full_id() == t.full_id()) {
            self.techniques.push(t);
        }
    }

    /// Build MITRE mappings from detected behavior patterns.
    #[must_use]
    pub fn from_behaviors(behaviors: &[MalwareBehaviorPattern]) -> Self {
        let mut m = Self::new();
        for behavior in behaviors {
            match behavior {
                MalwareBehaviorPattern::ClassicRemoteInjection => {
                    m.add(MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.92, "api_chain").with_sub("T1055.001"));
                }
                MalwareBehaviorPattern::ProcessHollowing => {
                    m.add(MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.90, "api_chain").with_sub("T1055.012"));
                }
                MalwareBehaviorPattern::DllInjection => {
                    m.add(MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.85, "api_chain").with_sub("T1055.001"));
                }
                MalwareBehaviorPattern::ApcInjection => {
                    m.add(MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.85, "api_chain").with_sub("T1055.004"));
                }
                MalwareBehaviorPattern::RegistryPersistence => {
                    m.add(MitreTechnique::new("T1547", "Boot or Logon Autostart", "Persistence", 0.85, "api_chain").with_sub("T1547.001"));
                }
                MalwareBehaviorPattern::ServicePersistence => {
                    m.add(MitreTechnique::new("T1543", "Create or Modify System Process", "Persistence", 0.88, "api_chain").with_sub("T1543.003"));
                }
                MalwareBehaviorPattern::ScheduledTaskPersistence => {
                    m.add(MitreTechnique::new("T1053", "Scheduled Task/Job", "Persistence", 0.82, "api_chain").with_sub("T1053.005"));
                }
                MalwareBehaviorPattern::C2RawSocket | MalwareBehaviorPattern::C2Http => {
                    m.add(MitreTechnique::new("T1071", "Application Layer Protocol", "Command and Control", 0.80, "api_chain"));
                }
                MalwareBehaviorPattern::CredentialDumping => {
                    m.add(MitreTechnique::new("T1003", "OS Credential Dumping", "Credential Access", 0.88, "api_chain"));
                }
                MalwareBehaviorPattern::RansomwareEncryption => {
                    m.add(MitreTechnique::new("T1486", "Data Encrypted for Impact", "Impact", 0.95, "api_chain"));
                }
                MalwareBehaviorPattern::ShadowCopyDeletion => {
                    m.add(MitreTechnique::new("T1490", "Inhibit System Recovery", "Impact", 0.92, "api_chain"));
                }
                MalwareBehaviorPattern::Keylogging => {
                    m.add(MitreTechnique::new("T1056", "Input Capture", "Collection", 0.88, "api_chain").with_sub("T1056.001"));
                }
                MalwareBehaviorPattern::AntiDebug => {
                    m.add(MitreTechnique::new("T1622", "Debugger Evasion", "Defense Evasion", 0.80, "api_chain"));
                }
                MalwareBehaviorPattern::AntiSandbox => {
                    m.add(MitreTechnique::new("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion", 0.82, "api_chain"));
                }
                MalwareBehaviorPattern::TokenImpersonation => {
                    m.add(MitreTechnique::new("T1134", "Access Token Manipulation", "Defense Evasion", 0.87, "api_chain"));
                }
                MalwareBehaviorPattern::UacBypass => {
                    m.add(MitreTechnique::new("T1548", "Abuse Elevation Control Mechanism", "Defense Evasion", 0.85, "api_chain").with_sub("T1548.002"));
                }
                MalwareBehaviorPattern::SuspiciousBehavior(_) => {
                    m.add(MitreTechnique::new("T0000", "Unknown Technique", "Unknown", 0.50, "api_chain"));
                }
            }
        }
        m
    }

    /// Also map from syscall patterns.
    pub fn apply_syscall_patterns(&mut self, patterns: &[SyscallPattern]) {
        for p in patterns {
            match p {
                SyscallPattern::PrivilegeEscalation => {
                    self.add(MitreTechnique::new("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.88, "syscall"));
                }
                SyscallPattern::AntiDebugPtrace => {
                    self.add(MitreTechnique::new("T1622", "Debugger Evasion", "Defense Evasion", 0.82, "syscall"));
                }
                SyscallPattern::ShellcodeStaging => {
                    self.add(MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.78, "syscall"));
                }
                SyscallPattern::C2NetworkPattern => {
                    self.add(MitreTechnique::new("T1071", "Application Layer Protocol", "Command and Control", 0.70, "syscall"));
                }
                _ => {}
            }
        }
    }

    /// Number of mapped techniques.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.techniques.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.techniques.is_empty()
    }
}

// ─── ProcessInfo ──────────────────────────────────────────────────────────────

/// Information about a process observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub command_line: String,
    pub spawned_at_ms: u64,
    pub exited_at_ms: Option<u64>,
}

// ─── SandboxReport ────────────────────────────────────────────────────────────

/// A comprehensive sandbox analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Report format version.
    pub version: String,
    /// Sample SHA-256 hash.
    pub sample_hash: String,
    /// Sample file name.
    pub sample_name: String,
    /// Analysis duration in milliseconds.
    pub analysis_duration_ms: u64,
    /// Timestamp of analysis (Unix epoch seconds).
    pub analysis_timestamp: u64,
    /// Overall threat score.
    pub threat_score: ThreatScore,
    /// IOC list.
    pub iocs: IocList,
    /// MITRE ATT&CK mapping.
    pub mitre: MitreMapping,
    /// Detected API behavior chains.
    pub api_chains: Vec<ApiChain>,
    /// Detected syscall patterns.
    pub syscall_patterns: Vec<PatternMatch>,
    /// Process tree observed.
    pub processes: Vec<ProcessInfo>,
    /// Summary of API call categories.
    pub api_category_summary: HashMap<String, u64>,
    /// Summary of syscall categories.
    pub syscall_category_summary: HashMap<String, u64>,
    /// Total API calls recorded.
    pub total_api_calls: u64,
    /// Total syscalls recorded.
    pub total_syscalls: u64,
    /// Free-text analyst notes.
    pub notes: Vec<String>,
    /// Tags assigned to this sample.
    pub tags: Vec<String>,
}

impl SandboxReport {
    /// Create an empty report skeleton.
    #[must_use]
    pub fn new(sample_hash: impl Into<String>, sample_name: impl Into<String>) -> Self {
        Self {
            version: "1.0.0".to_string(),
            sample_hash: sample_hash.into(),
            sample_name: sample_name.into(),
            analysis_duration_ms: 0,
            analysis_timestamp: 0,
            threat_score: ThreatScore {
                total: 0,
                level: ThreatLevel::Clean,
                components: vec![],
            },
            iocs: IocList::new(),
            mitre: MitreMapping::new(),
            api_chains: vec![],
            syscall_patterns: vec![],
            processes: vec![],
            api_category_summary: HashMap::new(),
            syscall_category_summary: HashMap::new(),
            total_api_calls: 0,
            total_syscalls: 0,
            notes: vec![],
            tags: vec![],
        }
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Returns true if the sample is considered malicious (score >= 50).
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.threat_score.total >= 50
    }
}

// ─── ReportGenerator ─────────────────────────────────────────────────────────

/// Generates sandbox reports from aggregated analysis data.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Build a complete `SandboxReport` from the provided inputs.
    #[must_use]
    pub fn generate(input: ReportInput) -> SandboxReport {
        let score_inputs = Self::build_score_inputs(&input);
        let threat_score = ThreatScore::compute(&score_inputs);

        // Build MITRE mapping.
        let behaviors: Vec<MalwareBehaviorPattern> =
            input.api_chains.iter().map(|c| c.behavior.clone()).collect();
        let mut mitre = MitreMapping::from_behaviors(&behaviors);
        let syscall_patterns_flat: Vec<SyscallPattern> = input
            .syscall_patterns
            .iter()
            .map(|m| m.pattern.clone())
            .collect();
        mitre.apply_syscall_patterns(&syscall_patterns_flat);

        // Auto-generate IOCs from chains.
        let mut iocs = IocList::new();
        for chain in &input.api_chains {
            let desc = format!("behavior:{}", chain.behavior);
            iocs.add(Ioc::new(IocType::Other("behavior".to_string()), &desc, &chain.description, chain.confidence));
        }
        iocs.add_from_processes(&input.processes);
        iocs.dedup();

        // Auto-tag.
        let mut tags = input.tags.clone();
        if threat_score.total >= 80 {
            tags.push("malware".to_string());
        } else if threat_score.total >= 50 {
            tags.push("suspicious".to_string());
        }
        if behaviors.contains(&MalwareBehaviorPattern::RansomwareEncryption) {
            tags.push("ransomware".to_string());
        }
        if behaviors.iter().any(|b| {
            matches!(b,
                MalwareBehaviorPattern::ClassicRemoteInjection
                    | MalwareBehaviorPattern::ProcessHollowing
                    | MalwareBehaviorPattern::DllInjection
            )
        }) {
            tags.push("injector".to_string());
        }

        SandboxReport {
            version: "1.0.0".to_string(),
            sample_hash: input.sample_hash,
            sample_name: input.sample_name,
            analysis_duration_ms: input.analysis_duration_ms,
            analysis_timestamp: input.analysis_timestamp,
            threat_score,
            iocs,
            mitre,
            api_chains: input.api_chains,
            syscall_patterns: input.syscall_patterns,
            processes: input.processes,
            api_category_summary: input.api_category_summary,
            syscall_category_summary: input.syscall_category_summary,
            total_api_calls: input.total_api_calls,
            total_syscalls: input.total_syscalls,
            notes: input.notes,
            tags,
        }
    }

    fn build_score_inputs(input: &ReportInput) -> ScoreInputs {
        let behaviors: Vec<&MalwareBehaviorPattern> =
            input.api_chains.iter().map(|c| &c.behavior).collect();

        let has_process_injection = behaviors.iter().any(|b| {
            matches!(b,
                MalwareBehaviorPattern::ClassicRemoteInjection
                    | MalwareBehaviorPattern::ProcessHollowing
                    | MalwareBehaviorPattern::DllInjection
                    | MalwareBehaviorPattern::ApcInjection
            )
        });
        let has_persistence = behaviors.iter().any(|b| {
            matches!(b,
                MalwareBehaviorPattern::RegistryPersistence
                    | MalwareBehaviorPattern::ServicePersistence
                    | MalwareBehaviorPattern::ScheduledTaskPersistence
            )
        });
        let has_c2_communication = behaviors.iter().any(|b| {
            matches!(b, MalwareBehaviorPattern::C2Http | MalwareBehaviorPattern::C2RawSocket)
        });
        let has_privilege_escalation = input
            .syscall_patterns
            .iter()
            .any(|m| m.pattern == SyscallPattern::PrivilegeEscalation);
        let anti_analysis_count = behaviors
            .iter()
            .filter(|b| matches!(b, MalwareBehaviorPattern::AntiDebug | MalwareBehaviorPattern::AntiSandbox))
            .count() as u32;
        let crypto_api_calls = input
            .api_category_summary
            .get("crypto")
            .copied()
            .unwrap_or(0) as u32;
        let blocked_syscalls = input
            .syscall_category_summary
            .get("blocked")
            .copied()
            .unwrap_or(0) as u32;
        let network_connections = input
            .api_category_summary
            .get("network")
            .copied()
            .unwrap_or(0) as u32;
        let registry_writes = input
            .api_category_summary
            .get("persistence")
            .copied()
            .unwrap_or(0) as u32;

        ScoreInputs {
            has_process_injection,
            has_persistence,
            has_c2_communication,
            has_privilege_escalation,
            anti_analysis_count,
            crypto_api_calls,
            blocked_syscalls,
            network_connections,
            registry_writes,
            sensitive_file_accesses: 0,
        }
    }

    /// Render a report to the requested format.
    #[must_use]
    pub fn render(report: &SandboxReport, format: &ReportFormat) -> String {
        match format {
            ReportFormat::Json => Self::to_json(report),
            ReportFormat::Html => Self::to_html(report),
            ReportFormat::PlainText => Self::to_text(report),
            ReportFormat::Yaml => Self::to_yaml(report),
        }
    }

    fn to_json(report: &SandboxReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    fn to_text(report: &SandboxReport) -> String {
        let mut out = String::new();
        out.push_str("=== Sandbox Report ===\n");
        out.push_str(&format!("Sample: {}\n", report.sample_name));
        out.push_str(&format!("SHA256: {}\n", report.sample_hash));
        out.push_str(&format!("Threat Level: {}\n", report.threat_score.level));
        out.push_str(&format!("Threat Score: {}/100\n", report.threat_score.total));
        out.push_str(&format!("API Calls: {}\n", report.total_api_calls));
        out.push_str(&format!("Syscalls: {}\n", report.total_syscalls));
        out.push_str(&format!("IOCs: {}\n", report.iocs.len()));
        out.push_str(&format!("MITRE Techniques: {}\n", report.mitre.len()));
        out.push_str(&format!("Tags: {}\n", report.tags.join(", ")));
        if !report.api_chains.is_empty() {
            out.push_str("\n--- API Behavior Chains ---\n");
            for chain in &report.api_chains {
                out.push_str(&format!("  [{}] {} (conf={:.2})\n", chain.behavior, chain.name, chain.confidence));
            }
        }
        if !report.mitre.techniques.is_empty() {
            out.push_str("\n--- MITRE ATT&CK ---\n");
            for t in &report.mitre.techniques {
                out.push_str(&format!("  {} {} [{}] conf={:.2}\n", t.full_id(), t.name, t.tactic, t.confidence));
            }
        }
        out
    }

    fn to_html(report: &SandboxReport) -> String {
        let color = report.threat_score.level.color();
        let json_body = Self::to_json(report);
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Sandbox Report — {name}</title>
<style>
body{{font-family:monospace;background:#111;color:#eee;padding:2em}}
h1{{color:{color}}}
.score{{font-size:2em;color:{color}}}
pre{{background:#1a1a2e;padding:1em;overflow:auto;border-radius:4px}}
</style>
</head>
<body>
<h1>Sandbox Report: {name}</h1>
<p>SHA256: <code>{hash}</code></p>
<p>Threat Level: <span class="score">{level}</span> ({score}/100)</p>
<p>Tags: {tags}</p>
<h2>Full JSON Report</h2>
<pre>{json}</pre>
</body>
</html>"#,
            name = report.sample_name,
            hash = report.sample_hash,
            level = report.threat_score.level,
            score = report.threat_score.total,
            color = color,
            tags = report.tags.join(", "),
            json = json_body,
        )
    }

    fn to_yaml(report: &SandboxReport) -> String {
        format!(
            "sample_name: {}\nsample_hash: {}\nthreat_level: {}\nthreat_score: {}\ntotal_api_calls: {}\ntotal_syscalls: {}\nioc_count: {}\nmitre_techniques: {}\ntags:\n{}\n",
            report.sample_name,
            report.sample_hash,
            report.threat_score.level,
            report.threat_score.total,
            report.total_api_calls,
            report.total_syscalls,
            report.iocs.len(),
            report.mitre.len(),
            report.tags.iter().map(|t| format!("  - {t}")).collect::<Vec<_>>().join("\n"),
        )
    }
}

/// Helper to extract IOCs from process information.
trait IocListExt {
    fn add_from_processes(&mut self, procs: &[ProcessInfo]);
}

impl IocListExt for IocList {
    fn add_from_processes(&mut self, procs: &[ProcessInfo]) {
        for p in procs {
            if !p.name.is_empty() {
                self.add(Ioc::new(IocType::ProcessName, &p.name, "observed process", 0.9));
            }
            if !p.command_line.is_empty() {
                self.add(Ioc::new(
                    IocType::Other("command_line".into()),
                    &p.command_line,
                    "process command line",
                    0.75,
                ));
            }
        }
    }
}

/// Input data bundle for report generation.
#[derive(Debug, Clone, Default)]
pub struct ReportInput {
    pub sample_hash: String,
    pub sample_name: String,
    pub analysis_duration_ms: u64,
    pub analysis_timestamp: u64,
    pub api_chains: Vec<ApiChain>,
    pub syscall_patterns: Vec<PatternMatch>,
    pub processes: Vec<ProcessInfo>,
    pub api_category_summary: HashMap<String, u64>,
    pub syscall_category_summary: HashMap<String, u64>,
    pub total_api_calls: u64,
    pub total_syscalls: u64,
    pub notes: Vec<String>,
    pub tags: Vec<String>,
}

impl ReportInput {
    /// Create a minimal input.
    #[must_use]
    pub fn new(hash: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            sample_hash: hash.into(),
            sample_name: name.into(),
            ..Self::default()
        }
    }
}

// ─── C2 Type alias ────────────────────────────────────────────────────────────

/// Alias for the C2/HTTP behavior variant emitted by `api_monitor`.
/// Currently carries no payload — kept as a distinct type so callers can
/// pattern-match on the channel kind without touching the `api_monitor`
/// internals.
pub type C2Http = ();

/// Tag a C2/HTTP behaviour observation. Returns the marker type so it can
/// be stored in heterogenous behaviour-log channels.
#[must_use]
pub const fn tag_c2_http() -> C2Http {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(10), ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(35), ThreatLevel::Medium);
        assert_eq!(ThreatLevel::from_score(65), ThreatLevel::High);
        assert_eq!(ThreatLevel::from_score(95), ThreatLevel::Critical);
    }

    #[test]
    fn test_threat_score_compute_injection() {
        let inputs = ScoreInputs {
            has_process_injection: true,
            has_c2_communication: true,
            has_persistence: true,
            ..Default::default()
        };
        let score = ThreatScore::compute(&inputs);
        assert!(score.total >= 50);
        assert!(score.level >= ThreatLevel::High);
    }

    #[test]
    fn test_mitre_mapping_from_behaviors() {
        let behaviors = vec![
            MalwareBehaviorPattern::ClassicRemoteInjection,
            MalwareBehaviorPattern::RegistryPersistence,
        ];
        let mapping = MitreMapping::from_behaviors(&behaviors);
        assert!(mapping.len() >= 2);
    }

    #[test]
    fn test_report_generator_clean() {
        let input = ReportInput::new("abc123", "test.exe");
        let report = ReportGenerator::generate(input);
        assert_eq!(report.threat_score.level, ThreatLevel::Clean);
        assert!(!report.is_malicious());
    }

    #[test]
    fn test_render_text() {
        let input = ReportInput::new("abc123", "test.exe");
        let report = ReportGenerator::generate(input);
        let text = ReportGenerator::render(&report, &ReportFormat::PlainText);
        assert!(text.contains("Sandbox Report"));
    }

    #[test]
    fn test_render_html() {
        let input = ReportInput::new("abc123", "test.exe");
        let report = ReportGenerator::generate(input);
        let html = ReportGenerator::render(&report, &ReportFormat::Html);
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_ioc_dedup() {
        let mut list = IocList::new();
        list.add(Ioc::new(IocType::FilePath, "c:\\temp\\a.exe", "", 0.9));
        list.add(Ioc::new(IocType::FilePath, "c:\\temp\\a.exe", "", 0.9));
        list.dedup();
        assert_eq!(list.len(), 1);
    }
}
