//! Analysis findings database.
//!
//! Provides [`Finding`], [`FindingKind`] (50+ kinds), [`FindingDb`],
//! [`FindingFilter`], and [`FindingExporter`] (JSON/HTML).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FindingError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("finding with id {0} not found")]
    NotFound(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity / Confidence
// ─────────────────────────────────────────────────────────────────────────────

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "Informational"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Confidence in a finding (0–100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Confidence(u8);

impl Confidence {
    /// Create a confidence value, clamping to `[0, 100]`.
    #[must_use]
    pub fn new(v: u8) -> Self {
        Self(v.min(100))
    }

    /// Return the raw confidence percentage.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    pub const LOW: Self = Self(25);
    pub const MEDIUM: Self = Self(50);
    pub const HIGH: Self = Self(75);
    pub const CERTAIN: Self = Self(100);
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingKind — 50+ categories
// ─────────────────────────────────────────────────────────────────────────────

/// Category/kind of an analysis finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FindingKind {
    // ── Vulnerabilities ──────────────────────────────────────────────────────
    BufferOverflow,
    HeapOverflow,
    UseAfterFree,
    DoubleFree,
    IntegerOverflow,
    IntegerUnderflow,
    FormatString,
    NullDereference,
    OutOfBounds,
    RaceCondition,
    UaFTypeConfusion,
    StackOverflow,
    CommandInjection,
    PathTraversal,
    SQLInjection,
    XXE,
    SSRF,
    // ── Cryptography ─────────────────────────────────────────────────────────
    WeakHash,
    InsecureRandom,
    HardcodedKey,
    HardcodedIv,
    WeakCipher,
    MissingAuthentication,
    BrokenMac,
    PaddingOracleRisk,
    EcbMode,
    CryptoAlgorithmDetected,
    // ── Anti-debug / Anti-analysis ───────────────────────────────────────────
    AntiDebugIsDebuggerPresent,
    AntiDebugRdtsc,
    AntiDebugTimingCheck,
    AntiDebugNtQueryInfo,
    AntiDebugPebCheck,
    AntiDebugExceptionHook,
    AntiVmCpuid,
    AntiVmArtifacts,
    AntiSandboxSleepSkip,
    AntiSandboxUserActivity,
    // ── Network / C2 ─────────────────────────────────────────────────────────
    NetworkConnect,
    NetworkDns,
    NetworkHttp,
    NetworkHttps,
    HardcodedIpAddress,
    HardcodedUrl,
    C2Pattern,
    // ── Persistence ──────────────────────────────────────────────────────────
    RegistryAutorun,
    ServiceCreation,
    ScheduledTask,
    StartupFolder,
    BootkitIndicator,
    // ── Injection ────────────────────────────────────────────────────────────
    ProcessInjection,
    DllInjection,
    ShellcodeInjection,
    HollowingPattern,
    ReflectiveDll,
    AtomBombing,
    // ── Obfuscation ──────────────────────────────────────────────────────────
    ObfuscatedString,
    XorEncodedPayload,
    Base64EncodedPayload,
    PackedSection,
    SelfModifyingCode,
    VmProtected,
    // ── Miscellaneous ────────────────────────────────────────────────────────
    SuspiciousImport,
    SuspiciousExport,
    UnusualEntryPoint,
    EmbeddedPe,
    EmbeddedScript,
    HighEntropy,
    Custom(String),
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BufferOverflow => "BufferOverflow",
            Self::HeapOverflow => "HeapOverflow",
            Self::UseAfterFree => "UseAfterFree",
            Self::DoubleFree => "DoubleFree",
            Self::IntegerOverflow => "IntegerOverflow",
            Self::IntegerUnderflow => "IntegerUnderflow",
            Self::FormatString => "FormatString",
            Self::NullDereference => "NullDereference",
            Self::OutOfBounds => "OutOfBounds",
            Self::RaceCondition => "RaceCondition",
            Self::UaFTypeConfusion => "UaFTypeConfusion",
            Self::StackOverflow => "StackOverflow",
            Self::CommandInjection => "CommandInjection",
            Self::PathTraversal => "PathTraversal",
            Self::SQLInjection => "SQLInjection",
            Self::XXE => "XXE",
            Self::SSRF => "SSRF",
            Self::WeakHash => "WeakHash",
            Self::InsecureRandom => "InsecureRandom",
            Self::HardcodedKey => "HardcodedKey",
            Self::HardcodedIv => "HardcodedIv",
            Self::WeakCipher => "WeakCipher",
            Self::MissingAuthentication => "MissingAuthentication",
            Self::BrokenMac => "BrokenMac",
            Self::PaddingOracleRisk => "PaddingOracleRisk",
            Self::EcbMode => "EcbMode",
            Self::CryptoAlgorithmDetected => "CryptoAlgorithmDetected",
            Self::AntiDebugIsDebuggerPresent => "AntiDebug:IsDebuggerPresent",
            Self::AntiDebugRdtsc => "AntiDebug:Rdtsc",
            Self::AntiDebugTimingCheck => "AntiDebug:TimingCheck",
            Self::AntiDebugNtQueryInfo => "AntiDebug:NtQueryInfo",
            Self::AntiDebugPebCheck => "AntiDebug:PebCheck",
            Self::AntiDebugExceptionHook => "AntiDebug:ExceptionHook",
            Self::AntiVmCpuid => "AntiVM:Cpuid",
            Self::AntiVmArtifacts => "AntiVM:Artifacts",
            Self::AntiSandboxSleepSkip => "AntiSandbox:SleepSkip",
            Self::AntiSandboxUserActivity => "AntiSandbox:UserActivity",
            Self::NetworkConnect => "Network:Connect",
            Self::NetworkDns => "Network:DNS",
            Self::NetworkHttp => "Network:HTTP",
            Self::NetworkHttps => "Network:HTTPS",
            Self::HardcodedIpAddress => "HardcodedIpAddress",
            Self::HardcodedUrl => "HardcodedUrl",
            Self::C2Pattern => "C2Pattern",
            Self::RegistryAutorun => "Persistence:RegistryAutorun",
            Self::ServiceCreation => "Persistence:ServiceCreation",
            Self::ScheduledTask => "Persistence:ScheduledTask",
            Self::StartupFolder => "Persistence:StartupFolder",
            Self::BootkitIndicator => "Persistence:BootkitIndicator",
            Self::ProcessInjection => "Injection:Process",
            Self::DllInjection => "Injection:Dll",
            Self::ShellcodeInjection => "Injection:Shellcode",
            Self::HollowingPattern => "Injection:Hollowing",
            Self::ReflectiveDll => "Injection:ReflectiveDll",
            Self::AtomBombing => "Injection:AtomBombing",
            Self::ObfuscatedString => "Obfuscation:String",
            Self::XorEncodedPayload => "Obfuscation:XorPayload",
            Self::Base64EncodedPayload => "Obfuscation:Base64Payload",
            Self::PackedSection => "Obfuscation:PackedSection",
            Self::SelfModifyingCode => "Obfuscation:SelfModifying",
            Self::VmProtected => "Obfuscation:VmProtected",
            Self::SuspiciousImport => "SuspiciousImport",
            Self::SuspiciousExport => "SuspiciousExport",
            Self::UnusualEntryPoint => "UnusualEntryPoint",
            Self::EmbeddedPe => "EmbeddedPe",
            Self::EmbeddedScript => "EmbeddedScript",
            Self::HighEntropy => "HighEntropy",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

impl FindingKind {
    /// Default severity for this kind.
    #[must_use]
    pub const fn default_severity(&self) -> Severity {
        match self {
            Self::BufferOverflow
            | Self::HeapOverflow
            | Self::UseAfterFree
            | Self::DoubleFree
            | Self::ProcessInjection
            | Self::DllInjection
            | Self::ShellcodeInjection
            | Self::HollowingPattern
            | Self::ReflectiveDll
            | Self::AtomBombing => Severity::Critical,
            Self::RaceCondition
            | Self::StackOverflow
            | Self::CommandInjection
            | Self::SQLInjection
            | Self::IntegerOverflow
            | Self::IntegerUnderflow
            | Self::FormatString
            | Self::WeakHash
            | Self::InsecureRandom
            | Self::HardcodedKey
            | Self::WeakCipher
            | Self::VmProtected
            | Self::SelfModifyingCode
            | Self::C2Pattern
            | Self::HardcodedIpAddress
            | Self::HardcodedUrl
            | Self::RegistryAutorun
            | Self::ServiceCreation
            | Self::ScheduledTask => Severity::High,
            Self::HardcodedIv
            | Self::EcbMode
            | Self::PaddingOracleRisk
            | Self::AntiDebugIsDebuggerPresent
            | Self::AntiDebugRdtsc
            | Self::AntiVmCpuid
            | Self::AntiVmArtifacts
            | Self::PackedSection
            | Self::HighEntropy => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding
// ─────────────────────────────────────────────────────────────────────────────

/// A single analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique ID within a [`FindingDb`].
    pub id: u64,
    /// Virtual address associated with the finding (0 if not applicable).
    pub address: u64,
    /// Category.
    pub kind: FindingKind,
    /// Human-readable description.
    pub description: String,
    /// Confidence level.
    pub confidence: Confidence,
    /// Severity level.
    pub severity: Severity,
    /// Name of the analysis pass or plugin that produced it.
    pub source: String,
    /// Optional tags for additional categorization.
    pub tags: Vec<String>,
}

impl Finding {
    /// Create a new finding with auto-derived severity from the kind.
    #[must_use]
    pub fn new(
        id: u64,
        address: u64,
        kind: FindingKind,
        description: impl Into<String>,
        confidence: Confidence,
        source: impl Into<String>,
    ) -> Self {
        let severity = kind.default_severity();
        Self {
            id,
            address,
            kind,
            description: description.into(),
            confidence,
            severity,
            source: source.into(),
            tags: Vec::new(),
        }
    }

    /// Override the severity.
    #[must_use]
    pub const fn with_severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:04}] {:#010x} {:25} {:12} {} ({})",
            self.id,
            self.address,
            self.kind.to_string(),
            self.severity.to_string(),
            self.description,
            self.confidence,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingDb
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory database of [`Finding`] values.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FindingDb {
    findings: Vec<Finding>,
    next_id: u64,
}

impl FindingDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a finding, assigning it the next available ID.
    pub fn insert(
        &mut self,
        address: u64,
        kind: FindingKind,
        description: impl Into<String>,
        confidence: Confidence,
        source: impl Into<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.findings.push(Finding::new(
            id,
            address,
            kind,
            description,
            confidence,
            source,
        ));
        id
    }

    /// Insert a fully constructed finding, overwriting its ID.
    pub fn push(&mut self, mut finding: Finding) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        finding.id = id;
        self.findings.push(finding);
        id
    }

    /// Return a reference to a finding by ID.
    ///
    /// # Errors
    /// Returns [`FindingError::NotFound`] if the ID does not exist.
    pub fn get(&self, id: u64) -> Result<&Finding, FindingError> {
        self.findings
            .iter()
            .find(|f| f.id == id)
            .ok_or(FindingError::NotFound(id))
    }

    /// Return all findings.
    #[must_use]
    pub fn all(&self) -> &[Finding] {
        &self.findings
    }

    /// Return the total number of findings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.findings.len()
    }

    /// Return `true` if there are no findings.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Remove findings by ID.
    pub fn remove(&mut self, id: u64) -> bool {
        if let Some(pos) = self.findings.iter().position(|f| f.id == id) {
            self.findings.remove(pos);
            true
        } else {
            false
        }
    }

    /// Merge another database into this one (reassigning IDs).
    pub fn merge(&mut self, other: Self) {
        for f in other.findings {
            self.push(f);
        }
    }

    /// Count findings per severity.
    #[must_use]
    pub fn severity_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *map.entry(f.severity.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Return findings filtered by a [`FindingFilter`].
    #[must_use]
    pub fn filter(&self, filter: &FindingFilter) -> Vec<&Finding> {
        self.findings.iter().filter(|f| filter.matches(f)).collect()
    }

    /// Sort findings by severity (descending) then address.
    pub fn sort_by_severity(&mut self) {
        self.findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.address.cmp(&b.address)));
    }

    /// Clear all findings.
    pub fn clear(&mut self) {
        self.findings.clear();
        self.next_id = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Filter criteria for querying a [`FindingDb`].
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    /// Only findings at or above this severity.
    pub min_severity: Option<Severity>,
    /// Only findings with confidence at or above this value.
    pub min_confidence: Option<u8>,
    /// Only findings from this source.
    pub source: Option<String>,
    /// Only findings whose kind matches this.
    pub kind: Option<FindingKind>,
    /// Only findings within this address range.
    pub address_range: Option<(u64, u64)>,
    /// Only findings containing this text in their description (case-insensitive).
    pub description_contains: Option<String>,
    /// Only findings that carry this tag.
    pub tag: Option<String>,
}

impl FindingFilter {
    /// Create an empty filter (matches everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum severity.
    #[must_use]
    pub const fn with_min_severity(mut self, s: Severity) -> Self {
        self.min_severity = Some(s);
        self
    }

    /// Set minimum confidence.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = Some(c);
        self
    }

    /// Set source filter.
    #[must_use]
    pub fn with_source(mut self, s: impl Into<String>) -> Self {
        self.source = Some(s.into());
        self
    }

    /// Set kind filter.
    #[must_use]
    pub fn with_kind(mut self, k: FindingKind) -> Self {
        self.kind = Some(k);
        self
    }

    /// Set address range filter.
    #[must_use]
    pub const fn with_address_range(mut self, lo: u64, hi: u64) -> Self {
        self.address_range = Some((lo, hi));
        self
    }

    /// Set description substring filter.
    #[must_use]
    pub fn with_description(mut self, s: impl Into<String>) -> Self {
        self.description_contains = Some(s.into().to_lowercase());
        self
    }

    /// Set tag filter.
    #[must_use]
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tag = Some(t.into());
        self
    }

    /// Return `true` if a finding satisfies all filter criteria.
    #[must_use]
    pub fn matches(&self, f: &Finding) -> bool {
        if let Some(min) = self.min_severity
            && f.severity < min {
                return false;
            }
        if let Some(min) = self.min_confidence
            && f.confidence.value() < min {
                return false;
            }
        if let Some(ref src) = self.source
            && f.source != *src {
                return false;
            }
        if let Some(ref kind) = self.kind
            && f.kind != *kind {
                return false;
            }
        if let Some((lo, hi)) = self.address_range
            && (f.address < lo || f.address > hi) {
                return false;
            }
        if let Some(ref desc) = self.description_contains
            && !f.description.to_lowercase().contains(desc.as_str()) {
                return false;
            }
        if let Some(ref tag) = self.tag
            && !f.tags.iter().any(|t| t == tag) {
                return false;
            }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingExporter
// ─────────────────────────────────────────────────────────────────────────────

/// Export format for [`FindingExporter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Html,
    Csv,
    PlainText,
}

/// Exports a [`FindingDb`] in the requested format.
pub struct FindingExporter<'a> {
    db: &'a FindingDb,
    format: ExportFormat,
    title: String,
}

impl<'a> FindingExporter<'a> {
    /// Create an exporter.
    #[must_use]
    pub fn new(db: &'a FindingDb, format: ExportFormat) -> Self {
        Self {
            db,
            format,
            title: "Analysis Findings".to_owned(),
        }
    }

    /// Set the report title (used in HTML export).
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Render findings to a string.
    ///
    /// # Errors
    /// Returns [`FindingError::Serialization`] on JSON serialisation failure.
    pub fn export(&self) -> Result<String, FindingError> {
        match self.format {
            ExportFormat::Json => self.export_json(),
            ExportFormat::Html => Ok(self.export_html()),
            ExportFormat::Csv => Ok(self.export_csv()),
            ExportFormat::PlainText => Ok(self.export_plaintext()),
        }
    }

    fn export_json(&self) -> Result<String, FindingError> {
        serde_json::to_string_pretty(self.db.all())
            .map_err(|e| FindingError::Serialization(e.to_string()))
    }

    fn export_html(&self) -> String {
        use std::fmt::Write as _;
        let mut html = format!(
            "<!DOCTYPE html><html><head><meta charset='utf-8'/>\
             <title>{}</title>\
             <style>body{{font-family:monospace;}}table{{border-collapse:collapse;width:100%}}\
             th,td{{border:1px solid #ccc;padding:4px 8px;}}th{{background:#444;color:#fff}}\
             tr:nth-child(even){{background:#f0f0f0}}\
             .Critical{{color:#c00}}.High{{color:#e07000}}.Medium{{color:#aa0}}.Low{{color:#00a}}\
             </style></head><body><h1>{}</h1>",
            self.title, self.title
        );
        html.push_str("<table><tr><th>ID</th><th>Address</th><th>Kind</th><th>Severity</th><th>Confidence</th><th>Description</th><th>Source</th></tr>");
        for f in self.db.all() {
            let _ = write!(html,
                "<tr><td>{}</td><td>{:#010x}</td><td>{}</td>\
                 <td class='{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.id,
                f.address,
                f.kind,
                f.severity,
                f.severity,
                f.confidence,
                f.description,
                f.source
            );
        }
        html.push_str("</table></body></html>");
        html
    }

    fn export_csv(&self) -> String {
        use std::fmt::Write as _;
        let mut out = "id,address,kind,severity,confidence,description,source\n".to_owned();
        for f in self.db.all() {
            let _ = writeln!(out,
                "{},{:#010x},{},{},{},\"{}\",{}",
                f.id,
                f.address,
                f.kind,
                f.severity,
                f.confidence.value(),
                f.description.replace('"', "\"\""),
                f.source,
            );
        }
        out
    }

    fn export_plaintext(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("=== {} ({} findings) ===\n", self.title, self.db.len());
        for f in self.db.all() {
            let _ = writeln!(out, "{f}");
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a finding database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
    pub unique_kinds: usize,
    pub unique_sources: usize,
}

impl FindingStats {
    /// Compute stats from a slice of findings.
    #[must_use]
    pub fn from_db(db: &FindingDb) -> Self {
        let findings = db.all();
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut informational = 0;
        let mut kinds = std::collections::HashSet::new();
        let mut sources = std::collections::HashSet::new();
        for f in findings {
            match f.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Informational => informational += 1,
            }
            kinds.insert(format!("{}", f.kind));
            sources.insert(f.source.clone());
        }
        Self {
            total: findings.len(),
            critical,
            high,
            medium,
            low,
            informational,
            unique_kinds: kinds.len(),
            unique_sources: sources.len(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_db() -> FindingDb {
        let mut db = FindingDb::new();
        db.insert(
            0x1000,
            FindingKind::BufferOverflow,
            "stack bof in foo",
            Confidence::HIGH,
            "TestPass",
        );
        db.insert(
            0x2000,
            FindingKind::HardcodedKey,
            "AES-128 key embedded",
            Confidence::CERTAIN,
            "CryptoPass",
        );
        db.insert(
            0x3000,
            FindingKind::AntiDebugRdtsc,
            "RDTSC timing check",
            Confidence::MEDIUM,
            "AntiDbg",
        );
        db.insert(
            0x4000,
            FindingKind::NetworkHttp,
            "HTTP connect to C2",
            Confidence::HIGH,
            "NetworkPass",
        );
        db
    }

    // -- Confidence ----------------------------------------------------------

    #[test]
    fn test_confidence_clamping() {
        assert_eq!(Confidence::new(200).value(), 100);
        assert_eq!(Confidence::new(50).value(), 50);
    }

    #[test]
    fn test_confidence_constants() {
        assert_eq!(Confidence::LOW.value(), 25);
        assert_eq!(Confidence::CERTAIN.value(), 100);
    }

    // -- FindingKind ---------------------------------------------------------

    #[test]
    fn test_finding_kind_default_severity() {
        assert_eq!(
            FindingKind::BufferOverflow.default_severity(),
            Severity::Critical
        );
        assert_eq!(FindingKind::WeakHash.default_severity(), Severity::High);
        assert_eq!(
            FindingKind::HighEntropy.default_severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_finding_kind_display() {
        assert_eq!(FindingKind::BufferOverflow.to_string(), "BufferOverflow");
        assert_eq!(FindingKind::AntiDebugRdtsc.to_string(), "AntiDebug:Rdtsc");
    }

    #[test]
    fn test_finding_kind_custom() {
        let k = FindingKind::Custom("MyPlugin:Weird".into());
        assert_eq!(k.to_string(), "MyPlugin:Weird");
    }

    // -- Finding -------------------------------------------------------------

    #[test]
    fn test_finding_creation() {
        let f = Finding::new(
            0,
            0x1000,
            FindingKind::BufferOverflow,
            "overflow",
            Confidence::HIGH,
            "P",
        );
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.address, 0x1000);
    }

    #[test]
    fn test_finding_with_severity_override() {
        let f = Finding::new(
            0,
            0,
            FindingKind::SuspiciousImport,
            "x",
            Confidence::LOW,
            "P",
        )
        .with_severity(Severity::Critical);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_finding_with_tag() {
        let f = Finding::new(0, 0, FindingKind::HighEntropy, "x", Confidence::LOW, "P")
            .with_tag("packed");
        assert!(f.tags.contains(&"packed".to_owned()));
    }

    #[test]
    fn test_finding_display() {
        let f = Finding::new(
            0,
            0x1000,
            FindingKind::BufferOverflow,
            "bof",
            Confidence::HIGH,
            "P",
        );
        let s = format!("{f}");
        assert!(s.contains("BufferOverflow"));
        assert!(s.contains("0x00001000"));
    }

    // -- FindingDb -----------------------------------------------------------

    #[test]
    fn test_db_insert_and_len() {
        let db = sample_db();
        assert_eq!(db.len(), 4);
    }

    #[test]
    fn test_db_get_by_id() {
        let db = sample_db();
        let f = db.get(0).unwrap();
        assert_eq!(f.kind, FindingKind::BufferOverflow);
    }

    #[test]
    fn test_db_get_not_found() {
        let db = sample_db();
        assert!(db.get(999).is_err());
    }

    #[test]
    fn test_db_remove() {
        let mut db = sample_db();
        assert!(db.remove(0));
        assert!(!db.remove(0));
        assert_eq!(db.len(), 3);
    }

    #[test]
    fn test_db_severity_counts() {
        let db = sample_db();
        let counts = db.severity_counts();
        assert!(*counts.get("Critical").unwrap_or(&0) >= 1);
    }

    #[test]
    fn test_db_sort_by_severity() {
        let mut db = sample_db();
        db.sort_by_severity();
        let sev: Vec<_> = db.all().iter().map(|f| f.severity).collect();
        for w in sev.windows(2) {
            assert!(w[0] >= w[1]);
        }
    }

    #[test]
    fn test_db_merge() {
        let db1 = sample_db();
        let db2 = sample_db();
        let mut merged = db1;
        merged.merge(db2);
        assert_eq!(merged.len(), 8);
    }

    #[test]
    fn test_db_clear() {
        let mut db = sample_db();
        db.clear();
        assert!(db.is_empty());
    }

    // -- FindingFilter -------------------------------------------------------

    #[test]
    fn test_filter_min_severity() {
        let db = sample_db();
        let filter = FindingFilter::new().with_min_severity(Severity::High);
        let results = db.filter(&filter);
        for f in &results {
            assert!(f.severity >= Severity::High);
        }
    }

    #[test]
    fn test_filter_source() {
        let db = sample_db();
        let filter = FindingFilter::new().with_source("CryptoPass");
        let results = db.filter(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, FindingKind::HardcodedKey);
    }

    #[test]
    fn test_filter_description() {
        let db = sample_db();
        let filter = FindingFilter::new().with_description("AES");
        let results = db.filter(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_address_range() {
        let db = sample_db();
        let filter = FindingFilter::new().with_address_range(0x1000, 0x2000);
        let results = db.filter(&filter);
        assert!(
            results
                .iter()
                .all(|f| f.address >= 0x1000 && f.address <= 0x2000)
        );
    }

    #[test]
    fn test_filter_empty_matches_all() {
        let db = sample_db();
        let filter = FindingFilter::new();
        assert_eq!(db.filter(&filter).len(), db.len());
    }

    // -- FindingExporter -----------------------------------------------------

    #[test]
    fn test_export_json() {
        let db = sample_db();
        let exp = FindingExporter::new(&db, ExportFormat::Json);
        let json = exp.export().unwrap();
        assert!(json.contains("BufferOverflow"));
    }

    #[test]
    fn test_export_html() {
        let db = sample_db();
        let exp = FindingExporter::new(&db, ExportFormat::Html).with_title("Test");
        let html = exp.export().unwrap();
        assert!(html.contains("<table>"));
        assert!(html.contains("Test"));
    }

    #[test]
    fn test_export_csv() {
        let db = sample_db();
        let exp = FindingExporter::new(&db, ExportFormat::Csv);
        let csv = exp.export().unwrap();
        assert!(csv.starts_with("id,address"));
    }

    #[test]
    fn test_export_plaintext() {
        let db = sample_db();
        let exp = FindingExporter::new(&db, ExportFormat::PlainText);
        let txt = exp.export().unwrap();
        assert!(txt.contains("findings"));
    }

    // -- FindingStats --------------------------------------------------------

    #[test]
    fn test_stats_from_db() {
        let db = sample_db();
        let stats = FindingStats::from_db(&db);
        assert_eq!(stats.total, 4);
        assert!(stats.critical >= 1);
        assert!(stats.unique_kinds >= 4);
        assert!(stats.unique_sources >= 3);
    }

    #[test]
    fn test_stats_empty() {
        let db = FindingDb::new();
        let stats = FindingStats::from_db(&db);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.unique_kinds, 0);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Informational < Severity::Low);
    }

    // ── New comprehensive edge-case tests ────────────────────────────────────

    #[test]
    fn test_confidence_clamps_above_100() {
        assert_eq!(Confidence::new(150).value(), 100);
        assert_eq!(Confidence::new(0).value(), 0);
        assert_eq!(Confidence::new(100).value(), 100);
        assert_eq!(Confidence::CERTAIN.value(), 100);
        assert_eq!(format!("{}", Confidence::new(42)), "42%");
    }

    #[test]
    fn test_empty_db_queries() {
        let db = FindingDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.all().is_empty());
        assert!(db.get(0).is_err());
        assert!(db.severity_counts().is_empty());
    }

    #[test]
    fn test_remove_nonexistent_and_existing() {
        let mut db = FindingDb::new();
        assert!(!db.remove(999));
        let id = db.insert(0x1000, FindingKind::WeakHash, "weak", Confidence::HIGH, "src");
        assert!(db.remove(id));
        assert!(!db.remove(id));
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn test_insert_assigns_monotonic_ids() {
        let mut db = FindingDb::new();
        let a = db.insert(0, FindingKind::HighEntropy, "a", Confidence::LOW, "s");
        let b = db.insert(0, FindingKind::HighEntropy, "b", Confidence::LOW, "s");
        let c = db.insert(0, FindingKind::HighEntropy, "c", Confidence::LOW, "s");
        assert_eq!((a, b, c), (0, 1, 2));
    }

    #[test]
    fn test_clear_resets_next_id() {
        let mut db = FindingDb::new();
        db.insert(0, FindingKind::HighEntropy, "x", Confidence::LOW, "s");
        db.clear();
        assert!(db.is_empty());
        let id = db.insert(0, FindingKind::HighEntropy, "y", Confidence::LOW, "s");
        assert_eq!(id, 0);
    }

    #[test]
    fn test_merge_reassigns_ids() {
        let mut a = FindingDb::new();
        a.insert(0x10, FindingKind::HighEntropy, "a", Confidence::LOW, "s");
        let mut b = FindingDb::new();
        b.insert(0x20, FindingKind::WeakHash, "b", Confidence::HIGH, "s");
        b.insert(0x30, FindingKind::WeakHash, "c", Confidence::HIGH, "s");
        a.merge(b);
        assert_eq!(a.len(), 3);
        let ids: Vec<u64> = a.all().iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn test_default_severity_buckets() {
        assert_eq!(FindingKind::BufferOverflow.default_severity(), Severity::Critical);
        assert_eq!(FindingKind::UseAfterFree.default_severity(), Severity::Critical);
        assert_eq!(FindingKind::IntegerOverflow.default_severity(), Severity::High);
        assert_eq!(FindingKind::HighEntropy.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_sort_by_severity_descending() {
        let mut db = FindingDb::new();
        db.insert(0x10, FindingKind::HighEntropy, "low", Confidence::LOW, "s");
        db.insert(0x20, FindingKind::BufferOverflow, "crit", Confidence::HIGH, "s");
        db.insert(0x30, FindingKind::IntegerOverflow, "high", Confidence::HIGH, "s");
        db.sort_by_severity();
        let sev: Vec<Severity> = db.all().iter().map(|f| f.severity).collect();
        assert_eq!(sev[0], Severity::Critical);
        assert!(sev[1] >= sev[2]);
    }

    #[test]
    fn test_finding_with_tag_and_severity_override() {
        let f = Finding::new(0, 0, FindingKind::HighEntropy, "x", Confidence::LOW, "s")
            .with_severity(Severity::Critical)
            .with_tag("urgent")
            .with_tag("review");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.tags, vec!["urgent", "review"]);
    }

    #[test]
    fn test_address_boundary_values() {
        let mut db = FindingDb::new();
        db.insert(0, FindingKind::HighEntropy, "zero", Confidence::LOW, "s");
        db.insert(u64::MAX, FindingKind::HighEntropy, "max", Confidence::LOW, "s");
        assert_eq!(db.len(), 2);
        let s = format!("{}", db.all()[1]);
        assert!(s.contains("0xffffffffffffffff"));
    }
}
