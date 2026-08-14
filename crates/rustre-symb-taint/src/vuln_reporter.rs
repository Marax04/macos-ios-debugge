//! Vulnerability reporting for taint analysis.
//!
//! Classifies findings into CWE categories, assigns confidence scores, builds
//! evidence chains (source → sink), and provides remediation suggestions.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{TaintId, taint_bits};
use crate::taint_policy::SinkKind;

// ─── CWE classification ───────────────────────────────────────────────────────

/// Common Weakness Enumeration entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CweEntry {
    /// CWE number (e.g. 78).
    pub number: u32,
    /// Short name (e.g. "OS Command Injection").
    pub name: String,
    /// URL to the NVD/MITRE entry.
    pub url: String,
}

impl CweEntry {
    pub fn new(number: u32, name: impl Into<String>) -> Self {
        Self {
            number,
            name: name.into(),
            url: format!("https://cwe.mitre.org/data/definitions/{number}.html"),
        }
    }
}

impl fmt::Display for CweEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CWE-{}: {}", self.number, self.name)
    }
}

/// Well-known CWE entries used by the reporter.
pub mod cwe {
    use super::CweEntry;

    pub fn command_injection() -> CweEntry {
        CweEntry::new(78, "Improper Neutralization of Special Elements in OS Command (OS Command Injection)")
    }
    pub fn sql_injection() -> CweEntry {
        CweEntry::new(89, "Improper Neutralization of Special Elements in SQL Command (SQL Injection)")
    }
    pub fn format_string() -> CweEntry {
        CweEntry::new(134, "Use of Externally-Controlled Format String")
    }
    pub fn buffer_overflow() -> CweEntry {
        CweEntry::new(119, "Improper Restriction of Operations within the Bounds of a Memory Buffer")
    }
    pub fn heap_overflow() -> CweEntry {
        CweEntry::new(122, "Heap-based Buffer Overflow")
    }
    pub fn stack_overflow() -> CweEntry {
        CweEntry::new(121, "Stack-based Buffer Overflow")
    }
    pub fn use_after_free() -> CweEntry {
        CweEntry::new(416, "Use After Free")
    }
    pub fn integer_overflow() -> CweEntry {
        CweEntry::new(190, "Integer Overflow or Wraparound")
    }
    pub fn path_traversal() -> CweEntry {
        CweEntry::new(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')")
    }
    pub fn null_deref() -> CweEntry {
        CweEntry::new(476, "NULL Pointer Dereference")
    }
    pub fn tainted_network_data() -> CweEntry {
        CweEntry::new(20, "Improper Input Validation")
    }
    pub fn uncontrolled_memory_alloc() -> CweEntry {
        CweEntry::new(789, "Memory Allocation with Excessive Size Value")
    }
}

// ─── Evidence item ────────────────────────────────────────────────────────────

/// One step in the source→sink evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStep {
    /// Program counter.
    pub pc: u64,
    /// Register or memory cell carrying the taint.
    pub location: String,
    /// Taint mask at this step.
    pub taint: TaintId,
    /// Human-readable description of what happened.
    pub description: String,
}

impl EvidenceStep {
    pub fn new(pc: u64, location: impl Into<String>, taint: TaintId, desc: impl Into<String>) -> Self {
        Self { pc, location: location.into(), taint, description: desc.into() }
    }
}

// ─── Report entry ─────────────────────────────────────────────────────────────

/// Severity level for a reported vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReportSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ReportSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "INFORMATIONAL"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single reported vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    /// Sequential ID.
    pub id: u64,
    /// CWE classification.
    pub cwe: CweEntry,
    /// Severity.
    pub severity: ReportSeverity,
    /// One-liner title.
    pub title: String,
    /// Full description.
    pub description: String,
    /// PC of the vulnerable instruction.
    pub sink_pc: u64,
    /// PC where the tainted data originated.
    pub source_pc: u64,
    /// The sink function name.
    pub sink_api: String,
    /// The source API.
    pub source_api: String,
    /// The taint sources contributing to this finding.
    pub taint_mask: TaintId,
    /// Evidence chain from source to sink.
    pub evidence_chain: Vec<EvidenceStep>,
    /// Confidence in [0, 100].
    pub confidence: u8,
    /// Remediation suggestion.
    pub remediation: String,
    /// Additional key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl VulnReport {
    fn new(id: u64, cwe: CweEntry, severity: ReportSeverity, title: impl Into<String>) -> Self {
        Self {
            id,
            cwe,
            severity,
            title: title.into(),
            description: String::new(),
            sink_pc: 0,
            source_pc: 0,
            sink_api: String::new(),
            source_api: String::new(),
            taint_mask: 0,
            evidence_chain: Vec::new(),
            confidence: 80,
            remediation: String::new(),
            metadata: HashMap::new(),
        }
    }

    /// Format the finding as a concise text summary.
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} ({}) — confidence {}% — {} @ {:#x}",
            self.severity,
            self.title,
            self.cwe,
            self.confidence,
            self.sink_api,
            self.sink_pc,
        )
    }

    /// Taint source names derived from the mask.
    pub fn source_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if taint_bits::has_bit(self.taint_mask, taint_bits::USER_INPUT) {
            names.push("user_input");
        }
        if taint_bits::has_bit(self.taint_mask, taint_bits::NETWORK) {
            names.push("network");
        }
        if taint_bits::has_bit(self.taint_mask, taint_bits::FILE) {
            names.push("file");
        }
        if taint_bits::has_bit(self.taint_mask, taint_bits::COMMAND_LINE) {
            names.push("command_line");
        }
        if taint_bits::has_bit(self.taint_mask, taint_bits::ENVIRONMENT) {
            names.push("environment");
        }
        if taint_bits::has_bit(self.taint_mask, taint_bits::REGISTRY) {
            names.push("registry");
        }
        names
    }
}

// ─── Reporter configuration ────────────────────────────────────────────────────

/// Configuration for the vulnerability reporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReporterConfig {
    /// Minimum confidence to emit a report.
    pub min_confidence: u8,
    /// Minimum severity to emit a report.
    pub min_severity: ReportSeverity,
    /// Maximum evidence chain length.
    pub max_evidence_steps: usize,
    /// Whether to deduplicate findings with the same (CWE, sink_pc, source_pc).
    pub deduplicate: bool,
}

impl Default for ReporterConfig {
    fn default() -> Self {
        Self {
            min_confidence: 50,
            min_severity: ReportSeverity::Low,
            max_evidence_steps: 32,
            deduplicate: true,
        }
    }
}

// ─── VulnReporter ─────────────────────────────────────────────────────────────

/// Classifies taint findings into CWE-annotated vulnerability reports.
pub struct VulnReporter {
    config: ReporterConfig,
    reports: Vec<VulnReport>,
    next_id: u64,
    /// (cwe_number, sink_pc, source_pc) → report id, for deduplication.
    dedup_set: HashMap<(u32, u64, u64), u64>,
}

impl VulnReporter {
    pub fn new(config: ReporterConfig) -> Self {
        Self {
            config,
            reports: Vec::new(),
            next_id: 1,
            dedup_set: HashMap::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(ReporterConfig::default())
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn should_emit(&self, confidence: u8, severity: ReportSeverity) -> bool {
        confidence >= self.config.min_confidence && severity >= self.config.min_severity
    }

    fn try_dedup(&mut self, cwe: u32, sink_pc: u64, source_pc: u64, id: u64) -> bool {
        if !self.config.deduplicate {
            return false;
        }
        let key = (cwe, sink_pc, source_pc);
        if self.dedup_set.contains_key(&key) {
            return true; // already reported
        }
        self.dedup_set.insert(key, id);
        false
    }

    fn push(&mut self, r: VulnReport) {
        if self.should_emit(r.confidence, r.severity) {
            let dup = self.try_dedup(r.cwe.number, r.sink_pc, r.source_pc, r.id);
            if !dup {
                self.reports.push(r);
            }
        }
    }

    // ─── Reporting methods ────────────────────────────────────────────────

    /// Report a command injection (CWE-78).
    pub fn report_command_injection(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: impl Into<String>,
        source_api: impl Into<String>,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let api = api_name.into();
        let mut r = VulnReport::new(
            id,
            cwe::command_injection(),
            ReportSeverity::Critical,
            format!("Command injection via tainted argument to `{api}`"),
        );
        r.description = format!(
            "Tainted data from user-controlled source reaches the `{api}` call at {sink_pc:#x}. \
             An attacker can inject shell metacharacters to execute arbitrary commands."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.sink_api = api;
        r.source_api = source_api.into();
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 90);
        r.remediation = "Validate and sanitize all user-supplied input before passing to shell \
            commands. Prefer execve() with argument arrays over system()/popen()."
            .into();
        self.push(r);
    }

    /// Report a SQL injection (CWE-89).
    pub fn report_sql_injection(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: impl Into<String>,
        source_api: impl Into<String>,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let api = api_name.into();
        let mut r = VulnReport::new(
            id,
            cwe::sql_injection(),
            ReportSeverity::Critical,
            format!("SQL injection via tainted argument to `{api}`"),
        );
        r.description = format!(
            "User-controlled data reaches SQL query function `{api}` at {sink_pc:#x} without \
             proper sanitization, allowing SQL injection."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.sink_api = api;
        r.source_api = source_api.into();
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 88);
        r.remediation =
            "Use parameterized queries / prepared statements. Never concatenate user data into SQL strings."
                .into();
        self.push(r);
    }

    /// Report a format string vulnerability (CWE-134).
    pub fn report_format_string(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: impl Into<String>,
        source_api: impl Into<String>,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let api = api_name.into();
        let mut r = VulnReport::new(
            id,
            cwe::format_string(),
            ReportSeverity::Critical,
            format!("Format string vulnerability: tainted format arg to `{api}`"),
        );
        r.description = format!(
            "The format string argument to `{api}` at {sink_pc:#x} is tainted. \
             Using `%n` allows arbitrary memory writes."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.sink_api = api;
        r.source_api = source_api.into();
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 92);
        r.remediation =
            "Always use a literal format string, e.g. printf(\"%s\", user_data) instead of printf(user_data)."
                .into();
        self.push(r);
    }

    /// Report a buffer overflow (CWE-119 / 122 / 121).
    pub fn report_buffer_overflow(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: impl Into<String>,
        source_api: impl Into<String>,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
        on_heap: bool,
    ) {
        let id = self.alloc_id();
        let api = api_name.into();
        let cwe = if on_heap { cwe::heap_overflow() } else { cwe::stack_overflow() };
        let mut r = VulnReport::new(
            id,
            cwe,
            ReportSeverity::High,
            format!("Buffer overflow via tainted length argument to `{api}`"),
        );
        r.description = format!(
            "Tainted length/index argument at {sink_pc:#x} may cause a buffer overflow in `{api}`."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.sink_api = api;
        r.source_api = source_api.into();
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 80);
        r.remediation =
            "Validate the length against the destination buffer size before copy/memset operations."
                .into();
        self.push(r);
    }

    /// Report a use-after-free (CWE-416).
    pub fn report_use_after_free(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let mut r = VulnReport::new(
            id,
            cwe::use_after_free(),
            ReportSeverity::Critical,
            "Use-after-free: tainted pointer accesses freed memory",
        );
        r.description = format!(
            "A pointer derived from tainted data at {source_pc:#x} is used after the backing \
             allocation was freed (dereference at {sink_pc:#x})."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = 85;
        r.remediation =
            "Set pointers to NULL after free(). Use ownership-tracking data structures or \
             garbage collection where available."
                .into();
        self.push(r);
    }

    /// Report an integer overflow (CWE-190).
    pub fn report_integer_overflow(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        taint: TaintId,
        width: u32,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let mut r = VulnReport::new(
            id,
            cwe::integer_overflow(),
            ReportSeverity::Medium,
            format!("Integer overflow in {width}-bit computation from tainted input"),
        );
        r.description = format!(
            "Tainted {width}-bit arithmetic at {sink_pc:#x} may wrap around, \
             leading to incorrect size calculations or exploitable allocation sizes."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 70);
        r.remediation =
            "Use checked arithmetic (e.g. checked_add in Rust, __builtin_add_overflow in C). \
             Validate size values are within expected ranges before use."
                .into();
        self.push(r);
    }

    /// Report a path traversal (CWE-22).
    pub fn report_path_traversal(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: impl Into<String>,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
    ) {
        let id = self.alloc_id();
        let api = api_name.into();
        let mut r = VulnReport::new(
            id,
            cwe::path_traversal(),
            ReportSeverity::High,
            format!("Path traversal: tainted filename argument to `{api}`"),
        );
        r.description = format!(
            "Tainted filename at {sink_pc:#x} passed to `{api}` may contain '../' sequences, \
             allowing access to arbitrary filesystem paths."
        );
        r.sink_pc = sink_pc;
        r.source_pc = source_pc;
        r.sink_api = api;
        r.taint_mask = taint;
        r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
        r.confidence = compute_confidence(taint, source_pc, sink_pc, 82);
        r.remediation =
            "Canonicalize paths with realpath() and verify they start with the expected prefix. \
             Reject inputs containing '..' components."
                .into();
        self.push(r);
    }

    // ─── Batch classification ─────────────────────────────────────────────

    /// Classify a raw sink alert (from [`DataFlowTracker::check_sink_call`]) into
    /// a report, using the policy to determine the CWE.
    pub fn classify_sink_alert(
        &mut self,
        sink_pc: u64,
        source_pc: u64,
        api_name: &str,
        source_api: &str,
        sink_kind: SinkKind,
        taint: TaintId,
        evidence: Vec<EvidenceStep>,
    ) {
        match sink_kind {
            SinkKind::CommandExec => self.report_command_injection(
                sink_pc, source_pc, api_name, source_api, taint, evidence,
            ),
            SinkKind::SqlQuery => self.report_sql_injection(
                sink_pc, source_pc, api_name, source_api, taint, evidence,
            ),
            SinkKind::FormatString => self.report_format_string(
                sink_pc, source_pc, api_name, source_api, taint, evidence,
            ),
            SinkKind::FileWrite | SinkKind::MemoryCopy => self.report_buffer_overflow(
                sink_pc, source_pc, api_name, source_api, taint, evidence, true,
            ),
            SinkKind::NetworkSend => {
                // Network send of tainted data — CWE-20 (Improper Input Validation).
                let id = self.alloc_id();
                let mut r = VulnReport::new(
                    id,
                    cwe::tainted_network_data(),
                    ReportSeverity::Medium,
                    format!("Tainted data sent to network via `{api_name}`"),
                );
                r.sink_pc = sink_pc;
                r.source_pc = source_pc;
                r.sink_api = api_name.into();
                r.source_api = source_api.into();
                r.taint_mask = taint;
                r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
                r.confidence = 65;
                r.remediation = "Validate and sanitize data before sending to the network.".into();
                self.push(r);
            }
            SinkKind::Custom(_) => {
                let id = self.alloc_id();
                let mut r = VulnReport::new(
                    id,
                    cwe::tainted_network_data(),
                    ReportSeverity::Low,
                    format!("Tainted data reaches custom sink `{api_name}`"),
                );
                r.sink_pc = sink_pc;
                r.source_pc = source_pc;
                r.taint_mask = taint;
                r.evidence_chain = evidence.into_iter().take(self.config.max_evidence_steps).collect();
                r.confidence = 55;
                self.push(r);
            }
        }
    }

    // ─── Accessors ────────────────────────────────────────────────────────

    pub fn reports(&self) -> &[VulnReport] {
        &self.reports
    }

    pub fn take_reports(&mut self) -> Vec<VulnReport> {
        std::mem::take(&mut self.reports)
    }

    pub fn total(&self) -> usize {
        self.reports.len()
    }

    pub fn by_severity(&self, severity: ReportSeverity) -> Vec<&VulnReport> {
        self.reports.iter().filter(|r| r.severity == severity).collect()
    }

    pub fn by_cwe(&self, number: u32) -> Vec<&VulnReport> {
        self.reports.iter().filter(|r| r.cwe.number == number).collect()
    }

    /// Return a counts map by CWE number.
    pub fn cwe_counts(&self) -> HashMap<u32, usize> {
        let mut m = HashMap::new();
        for r in &self.reports {
            *m.entry(r.cwe.number).or_insert(0) += 1;
        }
        m
    }

    /// Render a plain-text summary of all reports.
    pub fn text_summary(&self) -> String {
        let mut s = format!("=== Vulnerability Report ({} findings) ===\n", self.reports.len());
        for r in &self.reports {
            s.push_str(&format!("  {}\n", r.summary()));
        }
        s
    }

    /// Render a JSON-compatible summary (using serde_json if available;
    /// otherwise basic serialization).
    pub fn json_summary(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.reports)
    }
}

// ─── Confidence computation ───────────────────────────────────────────────────

/// Compute the confidence for a finding.
///
/// Factors:
/// - Base confidence (from the check type).
/// - Source diversity: more taint bits → slightly lower confidence (harder to
///   reason about individually).
/// - Distance: source and sink at the same address → higher confidence.
fn compute_confidence(taint: TaintId, source_pc: u64, sink_pc: u64, base: u8) -> u8 {
    let taint_bits_count = taint.count_ones() as u8;
    // More taint sources → slightly less certain about the specific path.
    let diversity_penalty = (taint_bits_count.saturating_sub(1)).min(10);
    // Same-function finding (within 4KB) → small boost.
    let distance_bonus: u8 = if sink_pc.abs_diff(source_pc) < 0x1000 { 5 } else { 0 };
    base.saturating_sub(diversity_penalty).saturating_add(distance_bonus).min(100)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reporter() -> VulnReporter {
        VulnReporter::with_default_config()
    }

    fn no_evidence() -> Vec<EvidenceStep> {
        Vec::new()
    }

    #[test]
    fn test_report_command_injection() {
        let mut r = reporter();
        r.report_command_injection(0x2000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        assert_eq!(r.total(), 1);
        assert_eq!(r.reports()[0].cwe.number, 78);
        assert_eq!(r.reports()[0].severity, ReportSeverity::Critical);
    }

    #[test]
    fn test_report_format_string() {
        let mut r = reporter();
        r.report_format_string(0x3000, 0x1000, "printf", "getenv",
            taint_bits::ENVIRONMENT, no_evidence());
        assert_eq!(r.by_cwe(134).len(), 1);
    }

    #[test]
    fn test_report_sql_injection() {
        let mut r = reporter();
        r.report_sql_injection(0x4000, 0x1000, "sqlite3_exec", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        assert!(!r.by_cwe(89).is_empty());
    }

    #[test]
    fn test_deduplication() {
        let mut r = reporter();
        r.report_command_injection(0x2000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        r.report_command_injection(0x2000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        assert_eq!(r.total(), 1);
    }

    #[test]
    fn test_min_confidence_filter() {
        let mut r = VulnReporter::new(ReporterConfig {
            min_confidence: 99,
            ..Default::default()
        });
        r.report_integer_overflow(0x5000, 0x1000, taint_bits::FILE, 32, no_evidence());
        assert_eq!(r.total(), 0);
    }

    #[test]
    fn test_min_severity_filter() {
        let mut r = VulnReporter::new(ReporterConfig {
            min_severity: ReportSeverity::Critical,
            ..Default::default()
        });
        r.report_integer_overflow(0x5000, 0x1000, taint_bits::FILE, 32, no_evidence());
        assert_eq!(r.total(), 0);
        r.report_command_injection(0x6000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        assert_eq!(r.total(), 1);
    }

    #[test]
    fn test_cwe_counts() {
        let mut r = reporter();
        r.report_command_injection(0x2000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT, no_evidence());
        r.report_sql_injection(0x3000, 0x1000, "sqlite3_exec", "fgets",
            taint_bits::NETWORK, no_evidence());
        let counts = r.cwe_counts();
        assert_eq!(counts.get(&78), Some(&1));
        assert_eq!(counts.get(&89), Some(&1));
    }

    #[test]
    fn test_text_summary_nonempty() {
        let mut r = reporter();
        r.report_use_after_free(0x7000, 0x1000, no_evidence());
        let s = r.text_summary();
        assert!(s.contains("CWE-416"));
    }

    #[test]
    fn test_source_names() {
        let mut rep = reporter();
        rep.report_command_injection(0x2000, 0x1000, "execve", "fgets",
            taint_bits::USER_INPUT | taint_bits::NETWORK, no_evidence());
        let names = rep.reports()[0].source_names();
        assert!(names.contains(&"user_input"));
        assert!(names.contains(&"network"));
    }

    #[test]
    fn test_classify_sink_alert() {
        let mut r = reporter();
        r.classify_sink_alert(0x8000, 0x1000, "printf", "fgets",
            SinkKind::FormatString, taint_bits::USER_INPUT, no_evidence());
        assert!(!r.by_cwe(134).is_empty());
    }
}
