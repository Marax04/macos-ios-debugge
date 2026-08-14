//! `taint_report_generator` — Produce structured taint-analysis reports.
//!
//! Provides [`TaintReportGenerator`] which aggregates [`TaintFinding`]s,
//! sanitizer matches, and state snapshots into a comprehensive [`TaintReport`]
//! with severity scoring, deduplication, and multiple output formats.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

use crate::{FindingType, TaintFinding, TaintId, TaintReport, TaintState, taint_bits};

// ─── ReportSeverity ──────────────────────────────────────────────────────────

/// Severity level for a finding, used when grouping and prioritising output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReportSeverity {
    /// Informational only — no security impact.
    Info,
    /// Low risk; likely requires exploit chaining.
    Low,
    /// Moderate risk; exploitable under certain conditions.
    Medium,
    /// High risk; directly exploitable.
    High,
    /// Critical risk; trivially exploitable, possibly without authentication.
    Critical,
}

impl ReportSeverity {
    /// Score on a 0–100 scale for sorting purposes.
    #[must_use]
    pub const fn score(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }

    /// Label string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for ReportSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Map a `FindingType` to its default `ReportSeverity`.
#[must_use]
pub fn default_severity(t: &FindingType) -> ReportSeverity {
    match t {
        FindingType::CommandInjection => ReportSeverity::Critical,
        FindingType::BufferOverflow => ReportSeverity::High,
        FindingType::FormatString => ReportSeverity::High,
        FindingType::SqlInjection => ReportSeverity::High,
        FindingType::PathTraversal => ReportSeverity::Medium,
        FindingType::UseAfterFree => ReportSeverity::High,
        FindingType::IntegerOverflow => ReportSeverity::Medium,
        FindingType::TaintedCondition => ReportSeverity::Low,
        FindingType::Custom(_) => ReportSeverity::Medium,
    }
}

// ─── ReportEntry ─────────────────────────────────────────────────────────────

/// A single report entry enriched with severity and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEntry {
    /// Unique entry ID within the report (1-based).
    pub id: usize,
    /// Underlying finding.
    pub finding: TaintFinding,
    /// Assigned severity.
    pub severity: ReportSeverity,
    /// Hex string of the sink address, e.g. `"0x00401234"`.
    pub sink_addr_hex: String,
    /// Names of taint source bits present (e.g. `["user_input", "network"]`).
    pub source_names: Vec<String>,
    /// Whether this entry was suppressed as a duplicate.
    pub is_duplicate: bool,
    /// Optional analyst note added during review.
    pub note: Option<String>,
    /// CWE identifier (if known), e.g. `"CWE-78"`.
    pub cwe: Option<String>,
}

impl ReportEntry {
    /// Create a new entry from a finding.
    #[must_use]
    pub fn new(id: usize, finding: TaintFinding) -> Self {
        let severity = default_severity(&finding.finding_type);
        let sink_addr_hex = format!("0x{:08x}", finding.sink_addr);
        let source_names = taint_source_names(finding.taint_sources);
        let cwe = cwe_for_finding_type(&finding.finding_type).map(str::to_string);
        Self {
            id,
            finding,
            severity,
            sink_addr_hex,
            source_names,
            is_duplicate: false,
            note: None,
            cwe,
        }
    }

    /// Override the severity.
    #[must_use]
    pub fn with_severity(mut self, s: ReportSeverity) -> Self {
        self.severity = s;
        self
    }

    /// Attach an analyst note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Mark as duplicate.
    #[must_use]
    pub fn as_duplicate(mut self) -> Self {
        self.is_duplicate = true;
        self
    }

    /// One-line summary suitable for a CLI table.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "[{}] {:?} @ {} — {} (sources: {})",
            self.severity,
            self.finding.finding_type,
            self.sink_addr_hex,
            self.finding.description,
            self.source_names.join(", ")
        )
    }
}

// ─── TaintFlow ───────────────────────────────────────────────────────────────

/// A complete taint flow from a source to a sink, as stored in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Flow identifier.
    pub id: usize,
    /// Human-readable name of the taint source.
    pub source_name: String,
    /// Address of the source.
    pub source_addr: u64,
    /// Address of the sink.
    pub sink_addr: u64,
    /// Name of the sink function.
    pub sink_function: String,
    /// Propagation path (list of instruction addresses).
    pub path: Vec<u64>,
    /// Length of the propagation path.
    pub path_length: usize,
    /// Taint source bits involved.
    pub taint_id: TaintId,
    /// Whether a sanitizer was observed on this path.
    pub sanitized: bool,
    /// Severity of the sink.
    pub severity: ReportSeverity,
}

impl TaintFlow {
    /// Create from source/sink info.
    #[must_use]
    pub fn new(
        id: usize,
        source_name: impl Into<String>,
        source_addr: u64,
        sink_addr: u64,
        sink_function: impl Into<String>,
        path: Vec<u64>,
        taint_id: TaintId,
        severity: ReportSeverity,
    ) -> Self {
        let path_length = path.len();
        Self {
            id,
            source_name: source_name.into(),
            source_addr,
            sink_addr,
            sink_function: sink_function.into(),
            path,
            path_length,
            taint_id,
            sanitized: false,
            severity,
        }
    }

    /// Mark this flow as passing through a sanitizer.
    #[must_use]
    pub fn with_sanitizer(mut self) -> Self {
        self.sanitized = true;
        self
    }

    /// One-line display.
    #[must_use]
    pub fn display(&self) -> String {
        format!(
            "Flow#{}: {} (0x{:x}) → {} (0x{:x}) [{} hops]{}",
            self.id,
            self.source_name,
            self.source_addr,
            self.sink_function,
            self.sink_addr,
            self.path_length,
            if self.sanitized { " [sanitized]" } else { "" }
        )
    }
}

// ─── TaintReportConfig ───────────────────────────────────────────────────────

/// Configuration controlling report generation behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintReportConfig {
    /// Minimum severity to include in the report.
    pub min_severity: ReportSeverity,
    /// Deduplicate findings with the same type and sink address.
    pub deduplicate: bool,
    /// Sort entries by severity (descending).
    pub sort_by_severity: bool,
    /// Include informational CF-taint entries.
    pub include_cf_taint: bool,
    /// Maximum number of entries in the report (0 = unlimited).
    pub max_entries: usize,
    /// Binary name for the report header.
    pub binary_name: String,
}

impl Default for TaintReportConfig {
    fn default() -> Self {
        Self {
            min_severity: ReportSeverity::Low,
            deduplicate: true,
            sort_by_severity: true,
            include_cf_taint: false,
            max_entries: 0,
            binary_name: String::new(),
        }
    }
}

impl TaintReportConfig {
    /// Create a config that shows everything (for debugging).
    #[must_use]
    pub fn verbose() -> Self {
        Self {
            min_severity: ReportSeverity::Info,
            deduplicate: false,
            sort_by_severity: false,
            include_cf_taint: true,
            max_entries: 0,
            binary_name: String::new(),
        }
    }

    /// Create a config for CI gate usage (high+ only).
    #[must_use]
    pub fn ci_gate() -> Self {
        Self {
            min_severity: ReportSeverity::High,
            deduplicate: true,
            sort_by_severity: true,
            include_cf_taint: false,
            max_entries: 0,
            binary_name: String::new(),
        }
    }
}

// ─── TaintReportGenerator ────────────────────────────────────────────────────

/// Aggregates findings and generates a structured taint analysis report.
///
/// Typical usage:
/// ```ignore
/// let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
/// reporter.add_finding(finding1);
/// reporter.add_finding(finding2);
/// reporter.set_state_snapshot(final_state);
/// let report = reporter.generate();
/// println!("{}", reporter.format_text(&report));
/// ```
#[derive(Debug)]
pub struct TaintReportGenerator {
    config: TaintReportConfig,
    raw_findings: Vec<TaintFinding>,
    cf_taint_addrs: Vec<u64>,
    state_snapshot: Option<TaintState>,
    flows: Vec<TaintFlow>,
    binary_name: String,
    analysis_time_ms: Option<u64>,
    total_instructions: u64,
}

impl TaintReportGenerator {
    /// Create a generator with the given config.
    #[must_use]
    pub fn new(config: TaintReportConfig) -> Self {
        let binary_name = config.binary_name.clone();
        Self {
            config,
            raw_findings: Vec::new(),
            cf_taint_addrs: Vec::new(),
            state_snapshot: None,
            flows: Vec::new(),
            binary_name,
            analysis_time_ms: None,
            total_instructions: 0,
        }
    }

    /// Add a finding to the generator.
    pub fn add_finding(&mut self, f: TaintFinding) {
        self.raw_findings.push(f);
    }

    /// Add multiple findings at once.
    pub fn add_findings(&mut self, findings: Vec<TaintFinding>) {
        self.raw_findings.extend(findings);
    }

    /// Set CF-taint addresses.
    pub fn set_cf_taints(&mut self, addrs: Vec<u64>) {
        self.cf_taint_addrs = addrs;
    }

    /// Set the final taint state snapshot.
    pub fn set_state_snapshot(&mut self, state: TaintState) {
        self.state_snapshot = Some(state);
    }

    /// Add a taint flow.
    pub fn add_flow(&mut self, flow: TaintFlow) {
        self.flows.push(flow);
    }

    /// Set analysis duration.
    pub fn set_analysis_time_ms(&mut self, ms: u64) {
        self.analysis_time_ms = Some(ms);
    }

    /// Set total instruction count.
    pub fn set_total_instructions(&mut self, n: u64) {
        self.total_instructions = n;
    }

    /// Generate the final report.
    #[must_use]
    pub fn generate(&self) -> GeneratedReport {
        let mut entries: Vec<ReportEntry> = self
            .raw_findings
            .iter()
            .enumerate()
            .map(|(i, f)| ReportEntry::new(i + 1, f.clone()))
            .collect();

        // Filter by minimum severity
        entries.retain(|e| e.severity >= self.config.min_severity);

        // Deduplicate
        if self.config.deduplicate {
            let mut seen: HashMap<(String, u64), bool> = HashMap::new();
            for e in &mut entries {
                let key = (format!("{:?}", e.finding.finding_type), e.finding.sink_addr);
                if seen.insert(key, true).is_some() {
                    e.is_duplicate = true;
                }
            }
        }

        // Sort by severity descending
        if self.config.sort_by_severity {
            entries.sort_by(|a, b| b.severity.cmp(&a.severity));
        }

        // Limit
        if self.config.max_entries > 0 && entries.len() > self.config.max_entries {
            entries.truncate(self.config.max_entries);
        }

        // Counts by severity
        let mut counts_by_severity: HashMap<String, usize> = HashMap::new();
        for e in &entries {
            if !e.is_duplicate {
                *counts_by_severity.entry(e.severity.label().to_string()).or_insert(0) += 1;
            }
        }

        // Tainted registers/addresses from snapshot
        let (tainted_registers, tainted_addresses) = self
            .state_snapshot
            .as_ref()
            .map(|s| {
                let regs: Vec<String> = s
                    .registers
                    .iter()
                    .filter(|(_, v)| v.is_tainted())
                    .map(|(r, _)| r.clone())
                    .collect();
                let addrs: Vec<u64> = s
                    .memory
                    .iter()
                    .filter(|(_, v)| v.is_tainted())
                    .map(|(a, _)| *a)
                    .collect();
                (regs, addrs)
            })
            .unwrap_or_default();

        let total_unique = entries.iter().filter(|e| !e.is_duplicate).count();
        let critical_count = entries
            .iter()
            .filter(|e| e.severity == ReportSeverity::Critical && !e.is_duplicate)
            .count();

        GeneratedReport {
            binary_name: self.binary_name.clone(),
            entries,
            flows: self.flows.clone(),
            cf_taint_addrs: if self.config.include_cf_taint {
                self.cf_taint_addrs.clone()
            } else {
                Vec::new()
            },
            tainted_registers,
            tainted_addresses,
            total_unique_findings: total_unique,
            critical_count,
            counts_by_severity,
            total_instructions: self.total_instructions,
            analysis_time_ms: self.analysis_time_ms,
        }
    }

    /// Consume findings from a [`TaintReport`] (from lib.rs).
    pub fn ingest_taint_report(&mut self, report: &TaintReport) {
        for f in &report.findings {
            self.raw_findings.push(f.clone());
        }
        for &addr in &report.cf_taints {
            self.cf_taint_addrs.push(addr);
        }
        self.total_instructions = report.total_instructions;
    }

    /// Reset all accumulated data.
    pub fn reset(&mut self) {
        self.raw_findings.clear();
        self.cf_taint_addrs.clear();
        self.state_snapshot = None;
        self.flows.clear();
        self.total_instructions = 0;
        self.analysis_time_ms = None;
    }

    /// Format a generated report as plain text.
    #[must_use]
    pub fn format_text(&self, report: &GeneratedReport) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "═══ Taint Analysis Report ═══");
        let _ = writeln!(out, "Binary : {}", report.binary_name);
        let _ = writeln!(out, "Unique findings  : {}", report.total_unique_findings);
        let _ = writeln!(out, "Critical findings: {}", report.critical_count);
        let _ = writeln!(out, "Instructions     : {}", report.total_instructions);
        if let Some(ms) = report.analysis_time_ms {
            let _ = writeln!(out, "Analysis time    : {ms} ms");
        }
        let _ = writeln!(out);

        if report.entries.is_empty() {
            let _ = writeln!(out, "No findings above minimum severity threshold.");
        } else {
            let _ = writeln!(out, "─── Findings ───");
            for e in &report.entries {
                if e.is_duplicate {
                    continue;
                }
                let _ = writeln!(out, "  {}", e.summary_line());
                if let Some(cwe) = &e.cwe {
                    let _ = writeln!(out, "    CWE: {cwe}");
                }
                if let Some(note) = &e.note {
                    let _ = writeln!(out, "    Note: {note}");
                }
            }
        }

        if !report.flows.is_empty() {
            let _ = writeln!(out, "─── Taint Flows ───");
            for f in &report.flows {
                let _ = writeln!(out, "  {}", f.display());
            }
        }

        if !report.tainted_registers.is_empty() {
            let _ = writeln!(
                out,
                "─── Tainted Registers at Exit ───\n  {}",
                report.tainted_registers.join(", ")
            );
        }

        if !report.tainted_addresses.is_empty() {
            let addrs: Vec<String> =
                report.tainted_addresses.iter().map(|a| format!("0x{a:x}")).collect();
            let _ = writeln!(
                out,
                "─── Tainted Memory at Exit ───\n  {}",
                addrs.join(", ")
            );
        }

        out
    }

    /// Format a generated report as JSON (manual serialisation, no serde dependency at
    /// runtime for the generator itself).
    #[must_use]
    pub fn format_json(&self, report: &GeneratedReport) -> String {
        match serde_json::to_string_pretty(report) {
            Ok(s) => s,
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// Format a generated report as a Markdown table suitable for GitHub / GitLab comments.
    #[must_use]
    pub fn format_markdown(&self, report: &GeneratedReport) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "## Taint Analysis Report: `{}`\n", report.binary_name);
        let _ = writeln!(
            out,
            "| Severity | Type | Sink Address | Description | CWE |"
        );
        let _ = writeln!(out, "|----------|------|--------------|-------------|-----|");
        for e in &report.entries {
            if e.is_duplicate {
                continue;
            }
            let cwe = e.cwe.as_deref().unwrap_or("–");
            let _ = writeln!(
                out,
                "| **{}** | {:?} | `{}` | {} | {} |",
                e.severity,
                e.finding.finding_type,
                e.sink_addr_hex,
                e.finding.description,
                cwe
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "> Total unique findings: {}  |  Critical: {}  |  Instructions: {}",
            report.total_unique_findings, report.critical_count, report.total_instructions
        );
        out
    }
}

// ─── GeneratedReport ─────────────────────────────────────────────────────────

/// The finished report produced by [`TaintReportGenerator::generate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedReport {
    /// Binary name.
    pub binary_name: String,
    /// All report entries (findings), sorted and filtered.
    pub entries: Vec<ReportEntry>,
    /// All taint flows.
    pub flows: Vec<TaintFlow>,
    /// CF-taint addresses (only populated when `include_cf_taint` is true).
    pub cf_taint_addrs: Vec<u64>,
    /// Registers that were tainted at the end of analysis.
    pub tainted_registers: Vec<String>,
    /// Memory addresses that were tainted at the end of analysis.
    pub tainted_addresses: Vec<u64>,
    /// Total number of unique (non-duplicate) findings.
    pub total_unique_findings: usize,
    /// Number of critical unique findings.
    pub critical_count: usize,
    /// Counts per severity label.
    pub counts_by_severity: HashMap<String, usize>,
    /// Total instructions analysed.
    pub total_instructions: u64,
    /// Wall-clock analysis time in milliseconds.
    pub analysis_time_ms: Option<u64>,
}

impl GeneratedReport {
    /// Whether any findings exist above the minimum threshold.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.total_unique_findings > 0
    }

    /// Whether any critical findings exist.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical_count > 0
    }

    /// All non-duplicate entries of the given severity.
    #[must_use]
    pub fn entries_by_severity(&self, sev: ReportSeverity) -> Vec<&ReportEntry> {
        self.entries
            .iter()
            .filter(|e| !e.is_duplicate && e.severity == sev)
            .collect()
    }

    /// Sink addresses for all unique findings of a given `FindingType`.
    #[must_use]
    pub fn sinks_for_type(&self, t: &FindingType) -> Vec<u64> {
        self.entries
            .iter()
            .filter(|e| !e.is_duplicate && &e.finding.finding_type == t)
            .map(|e| e.finding.sink_addr)
            .collect()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a taint bitmask into a list of source name strings.
#[must_use]
pub fn taint_source_names(taint: TaintId) -> Vec<String> {
    let mut names = Vec::new();
    if taint_bits::has_bit(taint, taint_bits::USER_INPUT) {
        names.push("user_input".to_string());
    }
    if taint_bits::has_bit(taint, taint_bits::NETWORK) {
        names.push("network".to_string());
    }
    if taint_bits::has_bit(taint, taint_bits::FILE) {
        names.push("file".to_string());
    }
    if taint_bits::has_bit(taint, taint_bits::ENVIRONMENT) {
        names.push("environment".to_string());
    }
    if taint_bits::has_bit(taint, taint_bits::COMMAND_LINE) {
        names.push("command_line".to_string());
    }
    if taint_bits::has_bit(taint, taint_bits::REGISTRY) {
        names.push("registry".to_string());
    }
    // Custom bits 6..63
    for bit in 6..64u8 {
        let mask = 1u64 << bit;
        if taint_bits::has_bit(taint, mask) {
            names.push(format!("custom_{}", bit - 6));
        }
    }
    if names.is_empty() {
        names.push("none".to_string());
    }
    names
}

/// Return the CWE identifier for a `FindingType`, if known.
#[must_use]
pub fn cwe_for_finding_type(t: &FindingType) -> Option<&'static str> {
    match t {
        FindingType::CommandInjection => Some("CWE-78"),
        FindingType::BufferOverflow => Some("CWE-120"),
        FindingType::FormatString => Some("CWE-134"),
        FindingType::SqlInjection => Some("CWE-89"),
        FindingType::PathTraversal => Some("CWE-22"),
        FindingType::UseAfterFree => Some("CWE-416"),
        FindingType::IntegerOverflow => Some("CWE-190"),
        FindingType::TaintedCondition => Some("CWE-807"),
        FindingType::Custom(_) => None,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FindingType, TaintFinding, taint_bits};

    fn make_finding(t: FindingType, addr: u64) -> TaintFinding {
        TaintFinding::new(t, addr, taint_bits::USER_INPUT, "test finding")
    }

    #[test]
    fn test_severity_order() {
        assert!(ReportSeverity::Critical > ReportSeverity::High);
        assert!(ReportSeverity::High > ReportSeverity::Medium);
        assert!(ReportSeverity::Medium > ReportSeverity::Low);
        assert!(ReportSeverity::Low > ReportSeverity::Info);
    }

    #[test]
    fn test_severity_scores() {
        assert_eq!(ReportSeverity::Critical.score(), 100);
        assert_eq!(ReportSeverity::Info.score(), 0);
    }

    #[test]
    fn test_default_severity_mapping() {
        assert_eq!(default_severity(&FindingType::CommandInjection), ReportSeverity::Critical);
        assert_eq!(default_severity(&FindingType::BufferOverflow), ReportSeverity::High);
        assert_eq!(default_severity(&FindingType::PathTraversal), ReportSeverity::Medium);
        assert_eq!(default_severity(&FindingType::TaintedCondition), ReportSeverity::Low);
    }

    #[test]
    fn test_cwe_mapping() {
        assert_eq!(cwe_for_finding_type(&FindingType::CommandInjection), Some("CWE-78"));
        assert_eq!(cwe_for_finding_type(&FindingType::SqlInjection), Some("CWE-89"));
        assert_eq!(cwe_for_finding_type(&FindingType::Custom("x".into())), None);
    }

    #[test]
    fn test_taint_source_names_single() {
        let names = taint_source_names(taint_bits::USER_INPUT);
        assert!(names.contains(&"user_input".to_string()));
    }

    #[test]
    fn test_taint_source_names_multiple() {
        let t = taint_bits::USER_INPUT | taint_bits::NETWORK;
        let names = taint_source_names(t);
        assert!(names.contains(&"user_input".to_string()));
        assert!(names.contains(&"network".to_string()));
    }

    #[test]
    fn test_taint_source_names_none() {
        let names = taint_source_names(taint_bits::NONE);
        assert_eq!(names, vec!["none"]);
    }

    #[test]
    fn test_generate_empty() {
        let reporter = TaintReportGenerator::new(TaintReportConfig::default());
        let report = reporter.generate();
        assert!(!report.has_findings());
        assert_eq!(report.total_unique_findings, 0);
    }

    #[test]
    fn test_generate_single_finding() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1000));
        let report = reporter.generate();
        assert!(report.has_findings());
        assert_eq!(report.total_unique_findings, 1);
        assert_eq!(report.critical_count, 1);
    }

    #[test]
    fn test_deduplication() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1000));
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1000));
        let report = reporter.generate();
        // Second is duplicate
        assert_eq!(report.total_unique_findings, 1);
    }

    #[test]
    fn test_no_deduplication_when_disabled() {
        let mut config = TaintReportConfig::default();
        config.deduplicate = false;
        let mut reporter = TaintReportGenerator::new(config);
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1000));
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1000));
        let report = reporter.generate();
        assert_eq!(report.total_unique_findings, 2);
    }

    #[test]
    fn test_minimum_severity_filter() {
        let mut config = TaintReportConfig::default();
        config.min_severity = ReportSeverity::High;
        let mut reporter = TaintReportGenerator::new(config);
        reporter.add_finding(make_finding(FindingType::TaintedCondition, 0x1000)); // Low
        reporter.add_finding(make_finding(FindingType::BufferOverflow, 0x2000)); // High
        let report = reporter.generate();
        assert_eq!(report.total_unique_findings, 1);
    }

    #[test]
    fn test_sort_by_severity() {
        let config = TaintReportConfig::default();
        let mut reporter = TaintReportGenerator::new(config);
        reporter.add_finding(make_finding(FindingType::TaintedCondition, 0x1));
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x2));
        reporter.add_finding(make_finding(FindingType::PathTraversal, 0x3));
        let report = reporter.generate();
        // First entry should be the highest severity
        assert_eq!(report.entries[0].severity, ReportSeverity::Critical);
    }

    #[test]
    fn test_format_text_non_empty() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.add_finding(make_finding(FindingType::FormatString, 0xDEAD));
        let report = reporter.generate();
        let text = reporter.format_text(&report);
        assert!(text.contains("Taint Analysis Report"));
        assert!(text.contains("FormatString"));
    }

    #[test]
    fn test_format_markdown() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.binary_name = "test.exe".to_string();
        reporter.add_finding(make_finding(FindingType::SqlInjection, 0x5000));
        let report = reporter.generate();
        let md = reporter.format_markdown(&report);
        assert!(md.contains("## Taint Analysis Report"));
        assert!(md.contains("SqlInjection"));
    }

    #[test]
    fn test_entries_by_severity() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1));
        reporter.add_finding(make_finding(FindingType::BufferOverflow, 0x2));
        reporter.add_finding(make_finding(FindingType::PathTraversal, 0x3));
        let report = reporter.generate();
        let crit = report.entries_by_severity(ReportSeverity::Critical);
        assert_eq!(crit.len(), 1);
    }

    #[test]
    fn test_ingest_taint_report() {
        use crate::TaintReport;
        let mut tr = TaintReport::new();
        tr.add_finding(make_finding(FindingType::CommandInjection, 0x1));
        tr.total_instructions = 500;

        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.ingest_taint_report(&tr);
        assert_eq!(reporter.raw_findings.len(), 1);
        assert_eq!(reporter.total_instructions, 500);
    }

    #[test]
    fn test_add_flow() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        let flow = TaintFlow::new(
            1,
            "user_input",
            0x100,
            0x200,
            "system",
            vec![0x100, 0x150, 0x200],
            taint_bits::USER_INPUT,
            ReportSeverity::Critical,
        );
        reporter.add_flow(flow);
        let report = reporter.generate();
        assert_eq!(report.flows.len(), 1);
        assert_eq!(report.flows[0].path_length, 3);
    }

    #[test]
    fn test_ci_gate_config_filters_medium() {
        let config = TaintReportConfig::ci_gate();
        let mut reporter = TaintReportGenerator::new(config);
        reporter.add_finding(make_finding(FindingType::PathTraversal, 0x1)); // Medium
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x2)); // Critical
        let report = reporter.generate();
        assert_eq!(report.total_unique_findings, 1);
    }

    #[test]
    fn test_reset() {
        let mut reporter = TaintReportGenerator::new(TaintReportConfig::default());
        reporter.add_finding(make_finding(FindingType::CommandInjection, 0x1));
        reporter.set_total_instructions(1000);
        reporter.reset();
        assert!(reporter.raw_findings.is_empty());
        assert_eq!(reporter.total_instructions, 0);
        let report = reporter.generate();
        assert!(!report.has_findings());
    }
}
