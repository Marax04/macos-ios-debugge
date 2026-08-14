//! `report` — structured deobfuscation report with JSON/HTML export.
//!
//! # Relation to `deobf_report` and `deobf_report_extended`
//! This module provides a **pass-centric, serde-based** report (`DeobfReport`)
//! with `Finding`/`Severity` classification, a fluent `ReportBuilder`, and
//! JSON + HTML export backed by `serde_json`.
//!
//! [`deobf_report`](crate::deobf_report) provides a **statistics-centric**
//! report that tracks obfuscation scores (`ObfScore`), per-pass transform
//! stats (`TransformStat`), and multi-format export (plain text, JSON, HTML,
//! CSV, Markdown) without a serde dependency.
//!
//! [`deobf_report_extended`](crate::deobf_report_extended) provides an
//! **extended, technique-aware** report (`DeobfReportExtended`) with a 50+
//! entry `TechniqueUsed` taxonomy, per-pass byte-level timelines, a confidence
//! matrix, and recovered-asset inventory. Choose this when you need fine-
//! grained per-technique attribution.
//!
//! [`DeobfReport`] collects per-pass findings from a deobfuscation session,
//! computes confidence and severity classifications, and can serialise to both
//! machine-readable JSON and a minimal HTML document for human review.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by report construction or serialisation.
#[derive(Debug, Error)]
pub enum ReportError {
    /// JSON serialisation failed.
    #[error("json serialisation error: {0}")]
    Json(#[from] serde_json::Error),
    /// A formatting error occurred while building HTML.
    #[error("format error: {0}")]
    Format(#[from] std::fmt::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity
// ─────────────────────────────────────────────────────────────────────────────

/// Severity classification for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational — no code is changed.
    Info,
    /// Low — minor code simplification possible.
    Low,
    /// Medium — significant obfuscation removed.
    Medium,
    /// High — major obfuscation layer eliminated.
    High,
    /// Critical — binary is fully decoded / unpacked.
    Critical,
}

impl Severity {
    /// Return the CSS colour string used in HTML reports.
    #[must_use]
    pub const fn css_color(self) -> &'static str {
        match self {
            Self::Info => "#6c757d",
            Self::Low => "#17a2b8",
            Self::Medium => "#ffc107",
            Self::High => "#fd7e14",
            Self::Critical => "#dc3545",
        }
    }

    /// Human-readable label.
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

    /// Derive severity from a confidence value in `[0.0, 1.0]` and a patch count.
    #[must_use]
    pub fn from_heuristics(confidence: f32, patches: usize) -> Self {
        match (confidence, patches) {
            (c, _) if c >= 0.95 && patches >= 50 => Self::Critical,
            (c, p) if c >= 0.85 || p >= 20 => Self::High,
            (c, p) if c >= 0.65 || p >= 5 => Self::Medium,
            (c, p) if c >= 0.3 || p >= 1 => Self::Low,
            _ => Self::Info,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding
// ─────────────────────────────────────────────────────────────────────────────

/// A single finding recorded for one pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The pass that produced this finding.
    pub pass_name: String,
    /// Human-readable description of what was found.
    pub description: String,
    /// Byte offset in the binary where the finding applies (if applicable).
    pub offset: Option<usize>,
    /// Confidence in this finding (0.0–1.0).
    pub confidence: f32,
    /// Number of bytes affected.
    pub bytes_affected: usize,
    /// Severity classification.
    pub severity: Severity,
    /// Optional structured metadata key/value pairs.
    pub metadata: HashMap<String, String>,
}

impl Finding {
    /// Create a new finding.
    #[must_use]
    pub fn new(
        pass_name: impl Into<String>,
        description: impl Into<String>,
        confidence: f32,
        bytes_affected: usize,
    ) -> Self {
        let confidence = confidence.clamp(0.0, 1.0);
        let severity = Severity::from_heuristics(confidence, bytes_affected);
        Self {
            pass_name: pass_name.into(),
            description: description.into(),
            offset: None,
            confidence,
            bytes_affected,
            severity,
            metadata: HashMap::new(),
        }
    }

    /// Set the byte offset for this finding.
    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach metadata.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Override the computed severity.
    #[must_use]
    pub const fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of one pass's contribution to the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassSummary {
    /// Pass name.
    pub name: String,
    /// Number of patches this pass applied.
    pub patches_applied: usize,
    /// Bytes modified by this pass.
    pub bytes_modified: usize,
    /// Confidence reported by the pass.
    pub confidence: f32,
    /// Wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Findings emitted for this pass.
    pub findings: Vec<Finding>,
    /// Overall severity for this pass (highest finding severity).
    pub severity: Severity,
}

impl PassSummary {
    /// Compute severity as the highest severity across findings.
    fn compute_severity(findings: &[Finding]) -> Severity {
        findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// Total bytes affected by findings in this pass.
    #[must_use]
    pub fn total_finding_bytes(&self) -> usize {
        self.findings.iter().map(|f| f.bytes_affected).sum()
    }

    /// Number of high-or-above severity findings.
    #[must_use]
    pub fn high_severity_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for [`DeobfReport`].
///
/// # Example
/// ```rust,no_run
/// use rustre_deobf::report::{ReportBuilder, Severity};
/// let report = ReportBuilder::new("target.exe")
///     .binary_size(1024 * 64)
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct ReportBuilder {
    binary_name: String,
    binary_size: usize,
    pass_summaries: Vec<PassSummary>,
    extra_metadata: HashMap<String, serde_json::Value>,
    elapsed: Duration,
}

impl ReportBuilder {
    /// Start building a report for the given binary.
    #[must_use]
    pub fn new(binary_name: impl Into<String>) -> Self {
        Self {
            binary_name: binary_name.into(),
            ..Default::default()
        }
    }

    /// Set the binary size in bytes.
    #[must_use]
    pub const fn binary_size(mut self, size: usize) -> Self {
        self.binary_size = size;
        self
    }

    /// Set total elapsed time.
    #[must_use]
    pub const fn elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    /// Append a pass summary.
    #[must_use]
    pub fn add_pass(mut self, summary: PassSummary) -> Self {
        self.pass_summaries.push(summary);
        self
    }

    /// Attach arbitrary metadata to the report header.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra_metadata.insert(key.into(), value);
        self
    }

    /// Finalise and produce a [`DeobfReport`].
    #[must_use]
    pub fn build(self) -> DeobfReport {
        let total_patches: usize = self.pass_summaries.iter().map(|s| s.patches_applied).sum();
        let total_bytes: usize = self.pass_summaries.iter().map(|s| s.bytes_modified).sum();
        let all_findings: Vec<&Finding> = self
            .pass_summaries
            .iter()
            .flat_map(|s| &s.findings)
            .collect();

        let overall_confidence = if self.pass_summaries.is_empty() {
            0.0
        } else {
            let sum: f32 = self.pass_summaries.iter().map(|s| s.confidence).sum();
            sum / f32::from(u16::try_from(self.pass_summaries.len()).unwrap_or(u16::MAX))
        };

        let overall_severity = all_findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        DeobfReport {
            binary_name: self.binary_name,
            binary_size: self.binary_size,
            pass_summaries: self.pass_summaries,
            total_patches,
            total_bytes_modified: total_bytes,
            overall_confidence,
            overall_severity,
            elapsed_ms: u64::try_from(self.elapsed.as_millis()).unwrap_or(u64::MAX),
            metadata: self.extra_metadata,
        }
    }
}

/// Builder for a single [`PassSummary`].
#[derive(Debug, Default)]
pub struct PassSummaryBuilder {
    name: String,
    patches_applied: usize,
    bytes_modified: usize,
    confidence: f32,
    elapsed_ms: u64,
    findings: Vec<Finding>,
}

impl PassSummaryBuilder {
    /// Start building a pass summary.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set patch count.
    #[must_use]
    pub const fn patches(mut self, n: usize) -> Self {
        self.patches_applied = n;
        self
    }

    /// Set bytes modified.
    #[must_use]
    pub const fn bytes(mut self, b: usize) -> Self {
        self.bytes_modified = b;
        self
    }

    /// Set confidence.
    #[must_use]
    pub const fn confidence(mut self, c: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. With NaN every comparison is false, so we
        // fall through to 0.0 rather than letting it settle into the field.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    /// Set elapsed time in milliseconds.
    #[must_use]
    pub const fn elapsed_ms(mut self, ms: u64) -> Self {
        self.elapsed_ms = ms;
        self
    }

    /// Add a finding.
    #[must_use]
    pub fn finding(mut self, f: Finding) -> Self {
        self.findings.push(f);
        self
    }

    /// Build the [`PassSummary`].
    #[must_use]
    pub fn build(self) -> PassSummary {
        let severity = PassSummary::compute_severity(&self.findings);
        PassSummary {
            name: self.name,
            patches_applied: self.patches_applied,
            bytes_modified: self.bytes_modified,
            confidence: self.confidence,
            elapsed_ms: self.elapsed_ms,
            findings: self.findings,
            severity,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfReport
// ─────────────────────────────────────────────────────────────────────────────

/// Structured report for an entire deobfuscation session.
///
/// Build one with [`ReportBuilder`] and export it via [`to_json`] or
/// [`to_html`].
///
/// [`to_json`]: DeobfReport::to_json
/// [`to_html`]: DeobfReport::to_html
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfReport {
    /// Binary filename or label.
    pub binary_name: String,
    /// Binary size in bytes.
    pub binary_size: usize,
    /// Ordered per-pass summaries.
    pub pass_summaries: Vec<PassSummary>,
    /// Total patches across all passes.
    pub total_patches: usize,
    /// Total bytes modified.
    pub total_bytes_modified: usize,
    /// Weighted average confidence.
    pub overall_confidence: f32,
    /// Highest severity finding across all passes.
    pub overall_severity: Severity,
    /// Total wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Arbitrary key/value metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DeobfReport {
    /// Return all findings across all passes filtered by minimum severity.
    #[must_use]
    pub fn findings_by_severity(&self, min: Severity) -> Vec<&Finding> {
        self.pass_summaries
            .iter()
            .flat_map(|s| &s.findings)
            .filter(|f| f.severity >= min)
            .collect()
    }

    /// Return all findings across all passes sorted by descending confidence.
    ///
    /// # Panics
    /// Panics if a confidence value is NaN (should never occur with well-formed data).
    #[must_use]
    pub fn findings_by_confidence(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self
            .pass_summaries
            .iter()
            .flat_map(|s| &s.findings)
            .collect();
        findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        findings
    }

    /// Total finding count across all passes.
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.pass_summaries.iter().map(|s| s.findings.len()).sum()
    }

    /// Serialise the report to a compact JSON string.
    ///
    /// # Errors
    /// Returns [`ReportError::Json`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialise the report to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns [`ReportError::Json`] if serialisation fails.
    pub fn to_json_pretty(&self) -> Result<String, ReportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Render the report as a self-contained HTML document.
    ///
    /// # Errors
    /// Returns [`ReportError::Format`] if formatting fails.
    pub fn to_html(&self) -> Result<String, ReportError> {
        let mut html = String::new();
        self.html_write_head(&mut html)?;
        self.html_write_summary_table(&mut html)?;
        self.html_write_pass_table(&mut html)?;
        self.html_write_findings_table(&mut html)?;
        writeln!(html, "</body></html>")?;
        Ok(html)
    }

    fn html_write_head(&self, html: &mut String) -> Result<(), ReportError> {
        writeln!(html, "<!DOCTYPE html>")?;
        writeln!(html, "<html lang=\"en\"><head><meta charset=\"UTF-8\">")?;
        writeln!(html, "<title>RustRE Deobfuscation Report — {}</title>", escape_html(&self.binary_name))?;
        writeln!(html, "<style>")?;
        writeln!(html, "body{{font-family:monospace;background:#1e1e2e;color:#cdd6f4;padding:2em;}}")?;
        writeln!(html, "h1,h2{{color:#cba6f7;}} table{{border-collapse:collapse;width:100%;}}")?;
        writeln!(html, "th,td{{border:1px solid #313244;padding:6px 12px;text-align:left;}}")?;
        writeln!(html, "th{{background:#313244;}} .badge{{padding:2px 8px;border-radius:4px;color:#fff;}}")?;
        writeln!(html, "</style></head><body>")?;
        Ok(())
    }

    fn html_write_summary_table(&self, html: &mut String) -> Result<(), ReportError> {
        writeln!(html, "<h1>RustRE Deobfuscation Report</h1>")?;
        writeln!(html, "<table>")?;
        writeln!(html, "<tr><th>Binary</th><td>{}</td></tr>", escape_html(&self.binary_name))?;
        writeln!(html, "<tr><th>Size</th><td>{} bytes</td></tr>", self.binary_size)?;
        writeln!(html, "<tr><th>Total patches</th><td>{}</td></tr>", self.total_patches)?;
        writeln!(html, "<tr><th>Bytes modified</th><td>{}</td></tr>", self.total_bytes_modified)?;
        writeln!(html, "<tr><th>Confidence</th><td>{:.1}%</td></tr>", self.overall_confidence * 100.0)?;
        writeln!(
            html,
            "<tr><th>Severity</th><td><span class=\"badge\" style=\"background:{}\">{}</span></td></tr>",
            self.overall_severity.css_color(),
            self.overall_severity.label()
        )?;
        writeln!(html, "<tr><th>Elapsed</th><td>{}ms</td></tr>", self.elapsed_ms)?;
        writeln!(html, "</table>")?;
        Ok(())
    }

    fn html_write_pass_table(&self, html: &mut String) -> Result<(), ReportError> {
        writeln!(html, "<h2>Pass Summaries</h2><table>")?;
        writeln!(html, "<tr><th>Pass</th><th>Patches</th><th>Bytes</th><th>Confidence</th><th>Severity</th><th>Elapsed</th></tr>")?;
        for s in &self.pass_summaries {
            writeln!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td><td><span class=\"badge\" style=\"background:{}\">{}</span></td><td>{}ms</td></tr>",
                escape_html(&s.name),
                s.patches_applied,
                s.bytes_modified,
                s.confidence * 100.0,
                s.severity.css_color(),
                s.severity.label(),
                s.elapsed_ms
            )?;
        }
        writeln!(html, "</table>")?;
        Ok(())
    }

    fn html_write_findings_table(&self, html: &mut String) -> Result<(), ReportError> {
        if self.total_findings() == 0 {
            return Ok(());
        }
        writeln!(html, "<h2>Findings</h2><table>")?;
        writeln!(html, "<tr><th>Pass</th><th>Severity</th><th>Confidence</th><th>Offset</th><th>Bytes</th><th>Description</th></tr>")?;
        for s in &self.pass_summaries {
            for f in &s.findings {
                let offset_str = f.offset.map_or_else(|| "-".to_owned(), |o| format!("{o:#x}"));
                writeln!(
                    html,
                    "<tr><td>{}</td><td><span class=\"badge\" style=\"background:{}\">{}</span></td><td>{:.1}%</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&f.pass_name),
                    f.severity.css_color(),
                    f.severity.label(),
                    f.confidence * 100.0,
                    offset_str,
                    f.bytes_affected,
                    escape_html(&f.description)
                )?;
            }
        }
        writeln!(html, "</table>")?;
        Ok(())
    }

    /// One-line human-readable summary.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{}: {} passes, {} patches, {} bytes, confidence {:.1}%, severity {}",
            self.binary_name,
            self.pass_summaries.len(),
            self.total_patches,
            self.total_bytes_modified,
            self.overall_confidence * 100.0,
            self.overall_severity.label(),
        )
    }
}

impl std::fmt::Display for DeobfReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary_line())
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report() -> DeobfReport {
        let finding = Finding::new("xor-pass", "XOR key 0x42 detected", 0.9, 256)
            .with_offset(0x1000)
            .with_meta("key", "0x42");
        let summary = PassSummaryBuilder::new("xor-pass")
            .patches(10)
            .bytes(256)
            .confidence(0.9)
            .elapsed_ms(12)
            .finding(finding)
            .build();
        ReportBuilder::new("sample.exe")
            .binary_size(65536)
            .elapsed(Duration::from_millis(120))
            .add_pass(summary)
            .build()
    }

    #[test]
    fn test_report_totals() {
        let r = make_report();
        assert_eq!(r.total_patches, 10);
        assert_eq!(r.total_bytes_modified, 256);
        assert_eq!(r.total_findings(), 1);
    }

    #[test]
    fn test_json_roundtrip() {
        let r = make_report();
        let json = r.to_json().unwrap();
        let r2: DeobfReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r.total_patches, r2.total_patches);
        assert_eq!(r.binary_name, r2.binary_name);
    }

    #[test]
    fn test_html_contains_binary_name() {
        let r = make_report();
        let html = r.to_html().unwrap();
        assert!(html.contains("sample.exe"));
        assert!(html.contains("DOCTYPE html"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_findings_by_severity_filter() {
        let r = make_report();
        let high_plus = r.findings_by_severity(Severity::High);
        // finding has confidence 0.9, bytes 256 → High
        assert!(!high_plus.is_empty());
    }

    #[test]
    fn test_summary_line() {
        let r = make_report();
        let s = r.summary_line();
        assert!(s.contains("sample.exe"));
        assert!(s.contains("patches"));
    }
}
