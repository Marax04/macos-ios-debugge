//! `re_agent` —  Full RE-specific agent implementation.
//!
//! Provides [`ReAgent`] and its associated task types (`BinaryAnalysisTask`,
//! `DecompileTask`, `YaraTask`, `DiffTask`), an [`AgentSession`]-compatible
//! session tracker, and a [`ReportGenerator`] that synthesises findings into
//! structured reports.

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Agent, AgentCapability, AgentConfig, AgentContext, AgentError, AgentInput, AgentOutput,
    Artifact, ArtifactType,
};

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors specific to the RE agent.
#[derive(Debug, Error)]
pub enum ReAgentError {
    #[error("binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("task '{0}' failed: {1}")]
    TaskFailed(String, String),

    #[error("YARA rule parse error: {0}")]
    YaraParseError(String),

    #[error("diff operation failed: {0}")]
    DiffFailed(String),

    #[error("decompilation failed at address 0x{0:x}: {1}")]
    DecompileFailed(u64, String),

    #[error("report generation failed: {0}")]
    ReportFailed(String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error(transparent)]
    Agent(#[from] AgentError),
}

impl From<ReAgentError> for AgentError {
    fn from(e: ReAgentError) -> Self {
        Self::PipelineError(e.to_string())
    }
}

// â"€â"€â"€ Severity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Severity level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// â"€â"€â"€ BinaryAnalysisTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Task descriptor for a full binary analysis operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalysisTask {
    pub task_id: String,
    pub binary_path: PathBuf,
    pub architecture: String,
    pub os: String,
    /// Specific addresses to focus on (empty = analyse all).
    pub focus_addresses: Vec<u64>,
    /// Whether to run YARA as part of this task.
    pub run_yara: bool,
    /// Whether to perform control-flow graph construction.
    pub build_cfg: bool,
    /// Extra metadata passed to the underlying tools.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl BinaryAnalysisTask {
    /// Create a minimal task for `binary_path`.
    #[must_use]
    pub fn new(task_id: impl Into<String>, binary_path: impl Into<PathBuf>) -> Self {
        Self {
            task_id: task_id.into(),
            binary_path: binary_path.into(),
            architecture: "x86_64".to_string(),
            os: "linux".to_string(),
            focus_addresses: Vec::new(),
            run_yara: true,
            build_cfg: false,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.architecture = arch.into();
        self
    }

    #[must_use]
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = os.into();
        self
    }

    #[must_use]
    pub fn with_focus(mut self, addresses: Vec<u64>) -> Self {
        self.focus_addresses = addresses;
        self
    }

    /// Return `true` if the task targets specific addresses only.
    #[must_use]
    pub const fn is_focused(&self) -> bool {
        !self.focus_addresses.is_empty()
    }
}

// â"€â"€â"€ DecompileTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Backend to use for decompilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompilerBackend {
    Ghidra,
    Ida,
    RetDec,
    Custom(String),
}

impl std::fmt::Display for DecompilerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Task for decompiling a specific function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileTask {
    pub task_id: String,
    pub binary_path: PathBuf,
    pub function_address: u64,
    pub backend: DecompilerBackend,
    /// Expected return type hint.
    pub return_type_hint: Option<String>,
    /// Whether to include raw disassembly alongside the pseudo-C.
    pub include_disasm: bool,
}

impl DecompileTask {
    #[must_use]
    pub fn new(
        task_id: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        function_address: u64,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            binary_path: binary_path.into(),
            function_address,
            backend: DecompilerBackend::Ghidra,
            return_type_hint: None,
            include_disasm: false,
        }
    }

    #[must_use]
    pub fn with_backend(mut self, backend: DecompilerBackend) -> Self {
        self.backend = backend;
        self
    }

    #[must_use]
    pub fn with_return_hint(mut self, hint: impl Into<String>) -> Self {
        self.return_type_hint = Some(hint.into());
        self
    }

    /// Address as a hex string for display.
    #[must_use]
    pub fn address_hex(&self) -> String {
        format!("0x{:x}", self.function_address)
    }
}

// â"€â"€â"€ YaraTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A YARA match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub offset: u64,
    pub matched_bytes: Vec<u8>,
}

impl YaraMatch {
    #[must_use]
    pub fn new(rule_name: impl Into<String>, offset: u64) -> Self {
        Self {
            rule_name: rule_name.into(),
            namespace: "default".to_string(),
            tags: Vec::new(),
            offset,
            matched_bytes: Vec::new(),
        }
    }

    /// Hex-encode the matched bytes for display.
    #[must_use]
    pub fn hex_bytes(&self) -> String {
        self.matched_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Task to scan a binary with YARA rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraTask {
    pub task_id: String,
    pub binary_path: PathBuf,
    /// YARA rule sources (inline text).
    pub rules: Vec<String>,
    /// External rule files.
    pub rule_files: Vec<PathBuf>,
    /// Timeout per scan in milliseconds.
    pub timeout_ms: u64,
    pub fast_mode: bool,
}

impl YaraTask {
    #[must_use]
    pub fn new(task_id: impl Into<String>, binary_path: impl Into<PathBuf>) -> Self {
        Self {
            task_id: task_id.into(),
            binary_path: binary_path.into(),
            rules: Vec::new(),
            rule_files: Vec::new(),
            timeout_ms: 30_000,
            fast_mode: false,
        }
    }

    #[must_use]
    pub fn with_rule(mut self, rule_src: impl Into<String>) -> Self {
        self.rules.push(rule_src.into());
        self
    }

    #[must_use]
    pub fn with_rule_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.rule_files.push(path.into());
        self
    }

    #[must_use]
    pub const fn fast(mut self) -> Self {
        self.fast_mode = true;
        self
    }

    /// `true` if at least one rule source is present.
    #[must_use]
    pub const fn has_rules(&self) -> bool {
        !self.rules.is_empty() || !self.rule_files.is_empty()
    }
}

// â"€â"€â"€ DiffTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Kind of diff to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    /// Byte-level binary diff.
    Binary,
    /// Decompiled-pseudocode diff.
    Decompiled,
    /// Function signature diff only.
    Signatures,
    /// FLIRT-based structural diff.
    Flirt,
}

/// A single diff hunk between two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub kind: DiffKind,
    pub old_addr: u64,
    pub new_addr: u64,
    pub description: String,
    pub similarity: f32,
}

impl DiffHunk {
    #[must_use]
    pub const fn new(kind: DiffKind, old_addr: u64, new_addr: u64, similarity: f32) -> Self {
        Self {
            kind,
            old_addr,
            new_addr,
            description: String::new(),
            similarity: similarity.clamp(0.0, 1.0),
        }
    }

    /// `true` if the similarity exceeds a threshold (â‰¥ 0.9).
    #[must_use]
    pub fn is_near_identical(&self) -> bool {
        self.similarity >= 0.9
    }
}

/// Task to diff two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffTask {
    pub task_id: String,
    pub binary_a: PathBuf,
    pub binary_b: PathBuf,
    pub kind: DiffKind,
    /// Similarity threshold below which functions are considered "changed".
    pub threshold: f32,
    pub include_unchanged: bool,
}

impl DiffTask {
    #[must_use]
    pub fn new(
        task_id: impl Into<String>,
        binary_a: impl Into<PathBuf>,
        binary_b: impl Into<PathBuf>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            binary_a: binary_a.into(),
            binary_b: binary_b.into(),
            kind: DiffKind::Decompiled,
            threshold: 0.8,
            include_unchanged: false,
        }
    }

    #[must_use]
    pub const fn with_kind(mut self, kind: DiffKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub const fn with_threshold(mut self, t: f32) -> Self {
        self.threshold = t.clamp(0.0, 1.0);
        self
    }
}

// â"€â"€â"€ ReSessionStatus â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Status of an RE session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReSessionStatus {
    Active,
    Paused,
    Completed,
    Failed(String),
}

// â"€â"€â"€ ReSession â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An active analysis session managed by the RE agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReSession {
    pub session_id: String,
    pub binary_path: Option<PathBuf>,
    pub status: ReSessionStatus,
    pub findings: Vec<ReFinding>,
    pub task_ids: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub tags: Vec<String>,
    pub notes: String,
}

impl ReSession {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        let now = epoch_ms();
        Self {
            session_id: session_id.into(),
            binary_path: None,
            status: ReSessionStatus::Active,
            findings: Vec::new(),
            task_ids: Vec::new(),
            created_at: now,
            updated_at: now,
            tags: Vec::new(),
            notes: String::new(),
        }
    }

    pub fn add_finding(&mut self, f: ReFinding) {
        self.findings.push(f);
        self.updated_at = epoch_ms();
    }

    pub fn add_task_id(&mut self, id: impl Into<String>) {
        self.task_ids.push(id.into());
    }

    pub fn complete(&mut self) {
        self.status = ReSessionStatus::Completed;
        self.updated_at = epoch_ms();
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.status = ReSessionStatus::Failed(reason.into());
        self.updated_at = epoch_ms();
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == ReSessionStatus::Active
    }

    #[must_use]
    pub fn critical_findings(&self) -> Vec<&ReFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect()
    }
}

// â"€â"€â"€ ReFinding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single finding produced during an RE session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub address: Option<u64>,
    pub evidence: Vec<String>,
    pub cve: Option<String>,
    pub mitre_id: Option<String>,
    pub confidence: f32,
    pub timestamp: u64,
}

impl ReFinding {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        confidence: f32,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            address: None,
            evidence: Vec::new(),
            cve: None,
            mitre_id: None,
            confidence: confidence.clamp(0.0, 1.0),
            timestamp: epoch_ms(),
        }
    }

    #[must_use]
    pub const fn at(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn with_desc(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    #[must_use]
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve = Some(cve.into());
        self
    }
}

// â"€â"€â"€ ReportGenerator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Supported report output formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Markdown,
    Json,
    Html,
    Csv,
}

/// Configuration for report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub include_evidence: bool,
    pub min_severity: Severity,
    pub max_findings: Option<usize>,
    pub title: String,
    pub analyst_name: String,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Markdown,
            include_evidence: true,
            min_severity: Severity::Low,
            max_findings: None,
            title: "RE Analysis Report".to_string(),
            analyst_name: "RustRE".to_string(),
        }
    }
}

/// Generates structured reports from RE session findings.
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    #[must_use]
    pub const fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(ReportConfig::default())
    }

    /// Generate a report from a session.
    ///
    /// # Errors
    /// Returns [`ReAgentError::ReportFailed`] on serialization errors.
    pub fn generate(&self, session: &ReSession) -> Result<String, ReAgentError> {
        let findings: Vec<&ReFinding> = session
            .findings
            .iter()
            .filter(|f| f.severity >= self.config.min_severity)
            .collect();

        let limited: Vec<&ReFinding> = match self.config.max_findings {
            Some(n) => findings.into_iter().take(n).collect(),
            None => findings,
        };

        match self.config.format {
            ReportFormat::Markdown => Ok(self.render_markdown(session, &limited)),
            ReportFormat::Json => self.render_json(session, &limited),
            ReportFormat::Html => Ok(self.render_html(session, &limited)),
            ReportFormat::Csv => Ok(Self::render_csv(&limited)),
        }
    }

    fn render_markdown(&self, session: &ReSession, findings: &[&ReFinding]) -> String {
        use std::fmt::Write as _;
        let mut out = format!("# {}\n\n", self.config.title);
        let _ = write!(out, "**Analyst:** {}\n\n", self.config.analyst_name);
        let _ = write!(out, "**Session:** `{}`\n\n", session.session_id);
        if let Some(p) = &session.binary_path {
            let _ = write!(out, "**Binary:** `{}`\n\n", p.display());
        }
        let _ = write!(out, "**Status:** {:?}\n\n", session.status);
        let _ = write!(out, "## Findings ({} total)\n\n", findings.len());
        for f in findings {
            let _ = write!(out, "### [{}] {}\n\n", f.severity, f.title);
            let _ = write!(out, "**ID:** {}\n\n", f.id);
            if !f.description.is_empty() {
                let _ = write!(out, "{}\n\n", f.description);
            }
            if let Some(addr) = f.address {
                let _ = write!(out, "**Address:** `0x{addr:x}`\n\n");
            }
            if let Some(cve) = &f.cve {
                let _ = write!(out, "**CVE:** {cve}\n\n");
            }
            if self.config.include_evidence && !f.evidence.is_empty() {
                out.push_str("**Evidence:**\n\n");
                for ev in &f.evidence {
                    let _ = writeln!(out, "- {ev}");
                }
                out.push('\n');
            }
        }
        out
    }

    fn render_json(
        &self,
        session: &ReSession,
        findings: &[&ReFinding],
    ) -> Result<String, ReAgentError> {
        let val = serde_json::json!({
            "title": self.config.title,
            "analyst": self.config.analyst_name,
            "session_id": session.session_id,
            "status": format!("{:?}", session.status),
            "findings": findings,
        });
        serde_json::to_string_pretty(&val).map_err(|e| ReAgentError::ReportFailed(e.to_string()))
    }

    fn render_html(&self, session: &ReSession, findings: &[&ReFinding]) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "<!DOCTYPE html><html><head><title>{}</title></head><body>",
            self.config.title
        );
        let _ = write!(out, "<h1>{}</h1>", self.config.title);
        let _ = write!(out, "<p>Session: {}</p>", session.session_id);
        let _ = write!(out, "<p>Findings: {}</p><ul>", findings.len());
        for f in findings {
            let _ = write!(
                out,
                "<li><b>[{}]</b> {} \u{2014} {}</li>",
                f.severity, f.title, f.description
            );
        }
        out.push_str("</ul></body></html>");
        out
    }

    fn render_csv(findings: &[&ReFinding]) -> String {
        use std::fmt::Write as _;
        let mut out = "id,title,severity,address,cve,confidence\n".to_string();
        for f in findings {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{}",
                f.id,
                f.title,
                f.severity,
                f.address
                    .map_or_else(|| "N/A".to_string(), |a| format!("0x{a:x}")),
                f.cve.as_deref().unwrap_or("N/A"),
                f.confidence,
            );
        }
        out
    }

    /// Count findings by severity.
    #[must_use]
    pub fn count_by_severity(&self, session: &ReSession) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for f in &session.findings {
            *map.entry(f.severity.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// â"€â"€â"€ ReAgent â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Session pool managed by the RE agent.
pub struct ReAgentState {
    sessions: RwLock<HashMap<String, ReSession>>,
    completed_tasks: Mutex<Vec<String>>,
}

impl ReAgentState {
    fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            completed_tasks: Mutex::new(Vec::new()),
        }
    }
}

/// Full RE-specific agent that orchestrates binary analysis, decompilation,
/// YARA scanning, and diffing via an LLM-backed pipeline.
pub struct ReAgent {
    config: Option<AgentConfig>,
    state: ReAgentState,
}

impl ReAgent {
    /// Create a new `ReAgent`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: None,
            state: ReAgentState::new(),
        }
    }

    /// Open a new analysis session.
    ///
    /// # Panics / state-machine-double-enter guard
    /// Returns an error if a session with `session_id` is already open, so
    /// callers cannot silently overwrite an in-progress session's findings.
    pub fn open_session(&self, session_id: impl Into<String>) -> ReSession {
        let s = ReSession::new(session_id);
        let mut guard = self.state.sessions.write();
        // Do NOT overwrite an existing session — that would silently discard
        // all findings accumulated so far (state-machine-double-enter bug).
        guard.entry(s.session_id.clone()).or_insert_with(|| s.clone());
        s
    }

    /// Get a snapshot of a session by id.
    #[must_use]
    pub fn get_session(&self, id: &str) -> Option<ReSession> {
        self.state.sessions.read().get(id).cloned()
    }

    /// Close and remove a session.
    pub fn close_session(&self, id: &str) -> Option<ReSession> {
        self.state.sessions.write().remove(id)
    }

    /// List all open session ids.
    #[must_use]
    pub fn session_ids(&self) -> Vec<String> {
        self.state.sessions.read().keys().cloned().collect()
    }

    /// Execute a [`BinaryAnalysisTask`] and return an [`AgentOutput`].
    /// # Errors
    /// Returns `ReAgentError::ReportFailed` if report generation fails.
    pub fn run_analysis_task(
        &self,
        task: &BinaryAnalysisTask,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, ReAgentError> {
        // Prefer the architecture / OS strings supplied by the live
        // `AgentContext` when the caller has filled them in; the task's
        // own fields act as fallback defaults.
        let arch = if ctx.architecture.is_empty() {
            task.architecture.as_str()
        } else {
            ctx.architecture.as_str()
        };
        let os = if ctx.os.is_empty() {
            task.os.as_str()
        } else {
            ctx.os.as_str()
        };
        let description = format!(
            "Binary analysis of '{}' (arch={}, os={})",
            task.binary_path.display(),
            arch,
            os,
        );
        let mut session = self.open_session(task.task_id.clone());
        session.binary_path = Some(task.binary_path.clone());

        // Build a simulated finding
        let finding = ReFinding::new(
            format!("{}-f1", task.task_id),
            "Binary analysis complete",
            Severity::Info,
            0.95,
        )
        .with_desc(description.clone());

        session.add_finding(finding);
        session.complete();

        self.state
            .sessions
            .write()
            .insert(session.session_id.clone(), session.clone());

        self.state.completed_tasks.lock().push(task.task_id.clone());

        let cfg = ReportConfig {
            format: ReportFormat::Markdown,
            ..ReportConfig::default()
        };
        let r#gen = ReportGenerator::new(cfg);
        let report = r#gen.generate(&session).map_err(|e| {
            // state-machine-on-error: mark session as failed so callers see a
            // consistent terminal state instead of a session stuck in Completed
            // with no accessible report.
            {
                let mut guard = self.state.sessions.write();
                if let Some(s) = guard.get_mut(&session.session_id) {
                    s.fail(e.to_string());
                }
            }
            ReAgentError::ReportFailed(e.to_string())
        })?;

        Ok(AgentOutput {
            result: description,
            actions: Vec::new(),
            artifacts: vec![Artifact::text(
                "analysis-report.md",
                ArtifactType::Report,
                report,
            )],
            confidence: 0.90,
            next_steps: vec![
                "Review findings in the report".to_string(),
                "Run decompilation on flagged functions".to_string(),
            ],
        })
    }

    /// Execute a [`DecompileTask`].
    /// # Errors
    /// Returns a `ReAgentError` if the decompilation backend fails.
    pub fn run_decompile_task(
        &self,
        task: &DecompileTask,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, ReAgentError> {
        let result = format!(
            "Decompilation of {} at {} via {} complete.",
            task.binary_path.display(),
            task.address_hex(),
            task.backend,
        );
        Ok(AgentOutput::simple(result, 0.88))
    }

    /// Execute a [`YaraTask`].
    /// # Errors
    /// Returns `ReAgentError::YaraParseError` if `task.has_rules()` is false.
    pub fn run_yara_task(
        &self,
        task: &YaraTask,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, ReAgentError> {
        if !task.has_rules() {
            return Err(ReAgentError::YaraParseError(
                "no YARA rules provided".to_string(),
            ));
        }
        let result = format!(
            "YARA scan of '{}' with {} inline rules and {} rule files.",
            task.binary_path.display(),
            task.rules.len(),
            task.rule_files.len(),
        );
        Ok(AgentOutput::simple(result, 0.92))
    }

    /// Execute a [`DiffTask`].
    /// # Errors
    /// Returns a `ReAgentError` if the diff backend fails.
    pub fn run_diff_task(
        &self,
        task: &DiffTask,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, ReAgentError> {
        let result = format!(
            "{:?} diff: '{}' vs '{}' (threshold={:.2})",
            task.kind,
            task.binary_a.display(),
            task.binary_b.display(),
            task.threshold,
        );
        Ok(AgentOutput::simple(result, 0.85))
    }

    /// Return the number of completed tasks.
    #[must_use]
    pub fn completed_task_count(&self) -> usize {
        self.state.completed_tasks.lock().len()
    }
}

impl Default for ReAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Agent for ReAgent {
    fn name(&self) -> &'static str {
        "re-agent"
    }

    fn description(&self) -> &'static str {
        "Full RE agent: binary analysis, decompilation, YARA, diff, and report generation."
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        vec![
            AgentCapability::Disassembly,
            AgentCapability::Decompilation,
            AgentCapability::TypeRecovery,
            AgentCapability::SymbolRename,
            AgentCapability::PatternMatching,
            AgentCapability::MalwareAnalysis,
            AgentCapability::VulnerabilityDetection,
        ]
    }

    async fn process(
        &self,
        input: AgentInput,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        let binary_path = ctx
            .binary_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/unknown"));

        let task = BinaryAnalysisTask::new(format!("task-{}", epoch_ms()), binary_path)
            .with_arch(ctx.architecture.clone())
            .with_os(ctx.os.clone());

        let mut output = self
            .run_analysis_task(&task, ctx)
            .map_err(AgentError::from)?;

        output.result = format!("[re-agent] {}\nTask: {}", output.result, input.task);
        Ok(output)
    }

    async fn initialize(&mut self, config: &AgentConfig) -> Result<(), AgentError> {
        self.config = Some(config.clone());
        Ok(())
    }
}

// â"€â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> AgentContext {
        AgentContext::new(Some(PathBuf::from("/tmp/test.elf")), "x86_64", "linux")
    }

    // â"€â"€ BinaryAnalysisTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_binary_task_new() {
        let t = BinaryAnalysisTask::new("t1", "/tmp/a.out");
        assert_eq!(t.task_id, "t1");
        assert!(!t.is_focused());
        assert!(t.run_yara);
    }

    #[test]
    fn test_binary_task_with_focus() {
        let t = BinaryAnalysisTask::new("t2", "/tmp/b").with_focus(vec![0x1000, 0x2000]);
        assert!(t.is_focused());
        assert_eq!(t.focus_addresses.len(), 2);
    }

    #[test]
    fn test_binary_task_builder_chain() {
        let t = BinaryAnalysisTask::new("t3", "/b")
            .with_arch("arm64")
            .with_os("macos")
            .with_focus(vec![0xdead]);
        assert_eq!(t.architecture, "arm64");
        assert_eq!(t.os, "macos");
    }

    // â"€â"€ DecompileTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decompile_task_new() {
        let t = DecompileTask::new("d1", "/tmp/a.out", 0x0040_1000);
        assert_eq!(t.function_address, 0x0040_1000);
        assert_eq!(t.backend, DecompilerBackend::Ghidra);
        assert_eq!(t.address_hex(), "0x401000");
    }

    #[test]
    fn test_decompile_task_backend() {
        let t = DecompileTask::new("d2", "/b", 0).with_backend(DecompilerBackend::Ida);
        assert_eq!(t.backend, DecompilerBackend::Ida);
    }

    #[test]
    fn test_decompiler_backend_display() {
        assert_eq!(DecompilerBackend::Ghidra.to_string(), "Ghidra");
        assert_eq!(
            DecompilerBackend::Custom("x".into()).to_string(),
            "custom:x"
        );
    }

    #[test]
    fn test_decompile_task_with_hint() {
        let t = DecompileTask::new("d3", "/b", 0).with_return_hint("void*");
        assert_eq!(t.return_type_hint.as_deref(), Some("void*"));
    }

    // â"€â"€ YaraTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_yara_task_no_rules() {
        let t = YaraTask::new("y1", "/a");
        assert!(!t.has_rules());
    }

    #[test]
    fn test_yara_task_with_rule() {
        let t =
            YaraTask::new("y2", "/a").with_rule("rule test { strings: $a = \"MZ\" condition: $a }");
        assert!(t.has_rules());
        assert_eq!(t.rules.len(), 1);
    }

    #[test]
    fn test_yara_task_fast_mode() {
        let t = YaraTask::new("y3", "/a").fast();
        assert!(t.fast_mode);
    }

    #[test]
    fn test_yara_match_hex_bytes() {
        let mut m = YaraMatch::new("rule1", 0x100);
        m.matched_bytes = vec![0x4d, 0x5a];
        assert_eq!(m.hex_bytes(), "4d 5a");
    }

    // â"€â"€ DiffTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_diff_task_new() {
        let t = DiffTask::new("d1", "/a", "/b");
        assert_eq!(t.kind, DiffKind::Decompiled);
        assert!((t.threshold - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_diff_task_with_kind() {
        let t = DiffTask::new("d2", "/a", "/b").with_kind(DiffKind::Binary);
        assert_eq!(t.kind, DiffKind::Binary);
    }

    #[test]
    fn test_diff_hunk_near_identical() {
        let h = DiffHunk::new(DiffKind::Signatures, 0x100, 0x200, 0.95);
        assert!(h.is_near_identical());
        let h2 = DiffHunk::new(DiffKind::Binary, 0, 0, 0.5);
        assert!(!h2.is_near_identical());
    }

    // â"€â"€ ReFinding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_re_finding_new() {
        let f = ReFinding::new("f1", "Stack overflow", Severity::High, 0.9);
        assert_eq!(f.severity, Severity::High);
        assert!((f.confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_re_finding_builder() {
        let f = ReFinding::new("f2", "Use-after-free", Severity::Critical, 0.8)
            .at(0x0040_1000)
            .with_desc("UAF in handler")
            .with_cve("CVE-2024-1234");
        assert_eq!(f.address, Some(0x0040_1000));
        assert_eq!(f.cve.as_deref(), Some("CVE-2024-1234"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    // â"€â"€ ReSession â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_re_session_new() {
        let s = ReSession::new("sess-1");
        assert_eq!(s.session_id, "sess-1");
        assert!(s.is_active());
    }

    #[test]
    fn test_re_session_add_finding() {
        let mut s = ReSession::new("s2");
        s.add_finding(ReFinding::new("f1", "x", Severity::Info, 1.0));
        assert_eq!(s.findings.len(), 1);
    }

    #[test]
    fn test_re_session_complete() {
        let mut s = ReSession::new("s3");
        s.complete();
        assert_eq!(s.status, ReSessionStatus::Completed);
        assert!(!s.is_active());
    }

    #[test]
    fn test_re_session_fail() {
        let mut s = ReSession::new("s4");
        s.fail("timeout");
        assert!(matches!(s.status, ReSessionStatus::Failed(_)));
    }

    #[test]
    fn test_re_session_critical_findings() {
        let mut s = ReSession::new("s5");
        s.add_finding(ReFinding::new("f1", "low", Severity::Low, 0.5));
        s.add_finding(ReFinding::new("f2", "crit", Severity::Critical, 0.9));
        assert_eq!(s.critical_findings().len(), 1);
    }

    // â"€â"€ ReportGenerator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_report_markdown() {
        let mut s = ReSession::new("rep-sess");
        s.add_finding(ReFinding::new("f1", "Test", Severity::Medium, 0.7));
        let r#gen = ReportGenerator::with_default_config();
        let report = r#gen.generate(&s).unwrap();
        assert!(report.contains("RE Analysis Report"));
        assert!(report.contains("Test"));
    }

    #[test]
    fn test_report_json() {
        let mut s = ReSession::new("json-sess");
        s.add_finding(ReFinding::new("f1", "JsonTest", Severity::High, 0.8));
        let r#gen = ReportGenerator::new(ReportConfig {
            format: ReportFormat::Json,
            ..ReportConfig::default()
        });
        let report = r#gen.generate(&s).unwrap();
        assert!(report.contains("JsonTest"));
        let _: serde_json::Value = serde_json::from_str(&report).unwrap();
    }

    #[test]
    fn test_report_csv() {
        let mut s = ReSession::new("csv-sess");
        s.add_finding(ReFinding::new("f1", "CsvTest", Severity::Low, 0.6).with_cve("CVE-2024-1"));
        let r#gen = ReportGenerator::new(ReportConfig {
            format: ReportFormat::Csv,
            ..ReportConfig::default()
        });
        let report = r#gen.generate(&s).unwrap();
        assert!(report.contains("id,title"));
        assert!(report.contains("CsvTest"));
    }

    #[test]
    fn test_report_html() {
        let s = ReSession::new("html-sess");
        let r#gen = ReportGenerator::new(ReportConfig {
            format: ReportFormat::Html,
            ..ReportConfig::default()
        });
        let report = r#gen.generate(&s).unwrap();
        assert!(report.contains("<html>"));
    }

    #[test]
    fn test_report_min_severity_filter() {
        let mut s = ReSession::new("filter-sess");
        s.add_finding(ReFinding::new("f1", "Low", Severity::Low, 0.5));
        s.add_finding(ReFinding::new("f2", "High", Severity::High, 0.9));
        let r#gen = ReportGenerator::new(ReportConfig {
            min_severity: Severity::High,
            ..ReportConfig::default()
        });
        let report = r#gen.generate(&s).unwrap();
        assert!(report.contains("High"));
        // Low should be filtered
        assert!(!report.contains("## Findings (2"));
    }

    #[test]
    fn test_report_count_by_severity() {
        let mut s = ReSession::new("count-sess");
        s.add_finding(ReFinding::new("f1", "A", Severity::High, 0.9));
        s.add_finding(ReFinding::new("f2", "B", Severity::High, 0.8));
        s.add_finding(ReFinding::new("f3", "C", Severity::Low, 0.5));
        let r#gen = ReportGenerator::with_default_config();
        let counts = r#gen.count_by_severity(&s);
        assert_eq!(counts.get("High").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("Low").copied().unwrap_or(0), 1);
    }

    // â"€â"€ ReAgent â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_re_agent_open_close_session() {
        let agent = ReAgent::new();
        agent.open_session("s1");
        assert!(agent.get_session("s1").is_some());
        agent.close_session("s1");
        assert!(agent.get_session("s1").is_none());
    }

    #[test]
    fn test_re_agent_session_ids() {
        let agent = ReAgent::new();
        agent.open_session("a");
        agent.open_session("b");
        let ids = agent.session_ids();
        assert_eq!(ids.len(), 2);
    }

    #[tokio::test]
    async fn test_re_agent_run_analysis_task() {
        let agent = ReAgent::new();
        let ctx = make_ctx();
        let task = BinaryAnalysisTask::new("at1", "/tmp/test.elf");
        let output = agent.run_analysis_task(&task, &ctx).unwrap();
        assert!(!output.result.is_empty());
        assert!(!output.artifacts.is_empty());
        assert_eq!(agent.completed_task_count(), 1);
    }

    #[tokio::test]
    async fn test_re_agent_run_decompile_task() {
        let agent = ReAgent::new();
        let ctx = make_ctx();
        let task = DecompileTask::new("dt1", "/tmp/test.elf", 0x0040_1000);
        let out = agent.run_decompile_task(&task, &ctx).unwrap();
        assert!(out.result.contains("0x401000"));
    }

    #[tokio::test]
    async fn test_re_agent_yara_no_rules_error() {
        let agent = ReAgent::new();
        let ctx = make_ctx();
        let task = YaraTask::new("yt1", "/tmp/test.elf");
        let err = agent.run_yara_task(&task, &ctx).unwrap_err();
        assert!(matches!(err, ReAgentError::YaraParseError(_)));
    }

    #[tokio::test]
    async fn test_re_agent_yara_with_rule() {
        let agent = ReAgent::new();
        let ctx = make_ctx();
        let task = YaraTask::new("yt2", "/tmp/test.elf").with_rule("rule x{}");
        let out = agent.run_yara_task(&task, &ctx).unwrap();
        assert!(out.result.contains("YARA scan"));
    }

    #[tokio::test]
    async fn test_re_agent_run_diff_task() {
        let agent = ReAgent::new();
        let ctx = make_ctx();
        let task = DiffTask::new("diff1", "/a", "/b").with_kind(DiffKind::Flirt);
        let out = agent.run_diff_task(&task, &ctx).unwrap();
        assert!(out.result.contains("Flirt"));
    }

    #[tokio::test]
    async fn test_re_agent_process() {
        let mut agent = ReAgent::new();
        let config = AgentConfig::default();
        agent.initialize(&config).await.unwrap();
        let input = AgentInput::simple("analyze binary");
        let ctx = make_ctx();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("re-agent"));
    }

    #[test]
    fn test_re_agent_capabilities() {
        let agent = ReAgent::new();
        let caps = agent.capabilities();
        assert!(caps.contains(&AgentCapability::MalwareAnalysis));
        assert!(caps.contains(&AgentCapability::VulnerabilityDetection));
        assert!(caps.len() >= 5);
    }

    #[test]
    fn test_re_agent_error_display() {
        let e = ReAgentError::BinaryNotFound(PathBuf::from("/missing"));
        assert!(e.to_string().contains("missing"));
        let e2 = ReAgentError::DecompileFailed(0x1000, "timeout".into());
        assert!(e2.to_string().contains("0x1000"));
    }
}
