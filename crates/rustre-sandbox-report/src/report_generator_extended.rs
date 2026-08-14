//! Extended report generator — HTML, PDF stub, JSON, MITRE Navigator,
//! and executive summary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportExtError {
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("template error: {0}")]
    Template(String),
    #[error("PDF export not supported on this platform")]
    PdfUnsupported,
}

// ─── ReportData ───────────────────────────────────────────────────────────────

/// Score severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        match score {
            0..=10 => Self::Clean,
            11..=30 => Self::Low,
            31..=60 => Self::Medium,
            61..=90 => Self::High,
            _ => Self::Critical,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub const fn html_color(self) -> &'static str {
        match self {
            Self::Clean => "#28a745",
            Self::Low => "#6c757d",
            Self::Medium => "#ffc107",
            Self::High => "#fd7e14",
            Self::Critical => "#dc3545",
        }
    }
}

/// Serde helper for `&'static str` fields.
pub mod serde_static_str_local {
    use serde::{Deserialize, Deserializer, Serializer};
    /// Serialize the borrowed static string through the serializer.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by the underlying serializer.
    pub fn serialize<S: Serializer>(s: &&'static str, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(s)
    }
    /// Deserialize a string and leak it to yield a `&'static str`.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by the underlying deserializer when the
    /// input is not a valid UTF-8 string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<&'static str, D::Error> {
        let s: String = String::deserialize(de)?;
        Ok(Box::leak(s.into_boxed_str()))
    }
}

/// A network indicator of compromise.
///
/// `kind` is stored as a `String` to avoid leaking memory on every
/// deserialization (the previous `&'static str` design required `Box::leak`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIoc {
    pub kind: String, // "ip", "domain", "url"
    pub value: String,
    pub port: Option<u16>,
}

/// Owned shim kept for backwards-compatible serde transitions; now identical
/// to [`NetworkIoc`] itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIocOwned {
    pub kind: String,
    pub value: String,
    pub port: Option<u16>,
}

impl From<NetworkIoc> for NetworkIocOwned {
    fn from(v: NetworkIoc) -> Self {
        Self {
            kind: v.kind,
            value: v.value,
            port: v.port,
        }
    }
}

impl From<NetworkIocOwned> for NetworkIoc {
    fn from(v: NetworkIocOwned) -> Self {
        Self {
            kind: v.kind,
            value: v.value,
            port: v.port,
        }
    }
}

/// A file indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIoc {
    pub path: Option<String>,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub size: Option<u64>,
}

/// A registry indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIoc {
    pub key: String,
    pub value: Option<String>,
    pub data: Option<String>,
}

/// A MITRE ATT&CK technique finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

/// Full report data structure.
#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub sample_name: String,
    pub sample_sha256: String,
    pub sample_size: u64,
    pub analysis_time: u64,
    pub verdict: Severity,
    pub score: u32,
    pub family: Option<String>,
    pub network_iocs: Vec<NetworkIoc>,
    pub file_iocs: Vec<FileIoc>,
    pub registry_iocs: Vec<RegistryIoc>,
    pub techniques: Vec<MitreTechnique>,
    pub behaviors: Vec<String>,
    pub dropped_files: Vec<String>,
    pub process_tree: Vec<String>,
}

/// Owned shim used solely for [`ReportData`] deserialization (to avoid
/// `&'static str` lifetime issues via [`NetworkIoc`]).
#[derive(Debug, Clone, Deserialize)]
pub struct ReportDataOwned {
    pub sample_name: String,
    pub sample_sha256: String,
    pub sample_size: u64,
    pub analysis_time: u64,
    pub verdict: Severity,
    pub score: u32,
    pub family: Option<String>,
    pub network_iocs: Vec<NetworkIocOwned>,
    pub file_iocs: Vec<FileIoc>,
    pub registry_iocs: Vec<RegistryIoc>,
    pub techniques: Vec<MitreTechnique>,
    pub behaviors: Vec<String>,
    pub dropped_files: Vec<String>,
    pub process_tree: Vec<String>,
}

impl<'de> serde::Deserialize<'de> for ReportData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let h = ReportDataOwned::deserialize(deserializer)?;
        Ok(Self {
            sample_name: h.sample_name,
            sample_sha256: h.sample_sha256,
            sample_size: h.sample_size,
            analysis_time: h.analysis_time,
            verdict: h.verdict,
            score: h.score,
            family: h.family,
            network_iocs: h.network_iocs.into_iter().map(NetworkIoc::from).collect(),
            file_iocs: h.file_iocs,
            registry_iocs: h.registry_iocs,
            techniques: h.techniques,
            behaviors: h.behaviors,
            dropped_files: h.dropped_files,
            process_tree: h.process_tree,
        })
    }
}

impl ReportData {
    /// Create a minimal report.
    #[must_use]
    pub fn new(name: impl Into<String>, sha256: impl Into<String>, score: u32) -> Self {
        Self {
            sample_name: name.into(),
            sample_sha256: sha256.into(),
            sample_size: 0,
            analysis_time: 0,
            verdict: Severity::from_score(score),
            score,
            family: None,
            network_iocs: Vec::new(),
            file_iocs: Vec::new(),
            registry_iocs: Vec::new(),
            techniques: Vec::new(),
            behaviors: Vec::new(),
            dropped_files: Vec::new(),
            process_tree: Vec::new(),
        }
    }

    /// Whether the report indicates malware.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        matches!(self.verdict, Severity::High | Severity::Critical)
    }

    /// Number of network IOCs.
    #[must_use]
    pub const fn network_ioc_count(&self) -> usize {
        self.network_iocs.len()
    }

    /// All unique MITRE tactic names.
    #[must_use]
    pub fn unique_tactics(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.techniques
            .iter()
            .filter(|t| seen.insert(t.tactic.as_str()))
            .map(|t| t.tactic.as_str())
            .collect()
    }
}

// ─── ExecutiveSummary ─────────────────────────────────────────────────────────

/// Plain-language executive summary of the analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub headline: String,
    pub verdict: String,
    pub key_findings: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub mitre_coverage: usize,
}

impl ExecutiveSummary {
    /// Generate summary from report data.
    #[must_use]
    pub fn generate(data: &ReportData) -> Self {
        let headline = if data.is_malicious() {
            format!(
                "MALICIOUS: {} detected as {} (score: {})",
                data.sample_name,
                data.family.as_deref().unwrap_or("unknown family"),
                data.score
            )
        } else {
            format!(
                "CLEAN: {} appears benign (score: {})",
                data.sample_name, data.score
            )
        };

        let mut findings = Vec::new();
        if !data.network_iocs.is_empty() {
            findings.push(format!(
                "{} C2 network indicators identified",
                data.network_iocs.len()
            ));
        }
        if !data.techniques.is_empty() {
            findings.push(format!(
                "{} MITRE ATT&CK techniques observed",
                data.techniques.len()
            ));
        }
        if !data.behaviors.is_empty() {
            findings.push(format!("Behaviors: {}", data.behaviors.join(", ")));
        }
        if !data.dropped_files.is_empty() {
            findings.push(format!(
                "{} files dropped on disk",
                data.dropped_files.len()
            ));
        }

        let actions = if data.is_malicious() {
            vec![
                "Isolate affected system immediately".to_string(),
                "Block all identified C2 IPs/domains at perimeter".to_string(),
                "Reset credentials for affected users".to_string(),
                "Submit IOCs to threat intelligence platform".to_string(),
            ]
        } else {
            vec!["No immediate action required".to_string()]
        };

        Self {
            headline,
            verdict: data.verdict.label().to_string(),
            key_findings: findings,
            recommended_actions: actions,
            mitre_coverage: data.techniques.len(),
        }
    }
}

// ─── HtmlReportFull ──────────────────────────────────────────────────────────

/// Generates a full HTML report.
pub struct HtmlReportFull;

impl HtmlReportFull {
    /// Render a complete HTML report.
    ///
    /// # Errors
    ///
    /// Returns a [`ReportExtError`] if rendering or formatting fails. The
    /// stub implementation here is infallible but the signature is reserved
    /// for future backends that may fail (e.g. template engines).
    pub fn render(data: &ReportData) -> Result<String, ReportExtError> {
        use std::fmt::Write as _;

        /// Escape HTML special characters to prevent XSS injection from
        /// attacker-controlled strings (sample names, IOC values, etc.).
        fn he(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;")
        }

        let summary = ExecutiveSummary::generate(data);
        let color = data.verdict.html_color();
        let ioc_rows: String = data.network_iocs.iter().fold(String::new(), |mut acc, i| {
            let port = i.port.map(|p| p.to_string()).unwrap_or_default();
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                he(&i.kind), he(&i.value), port,
            );
            acc
        });
        let tech_rows: String = data.techniques.iter().fold(String::new(), |mut acc, t| {
            let _ = write!(
                acc,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}%</td></tr>",
                he(&t.technique_id), he(&t.technique_name), he(&t.tactic), t.confidence,
            );
            acc
        });

        Ok(format!(
            r#"<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>RustRE Sandbox Report</title>
<style>body{{font-family:monospace;background:#1a1a2e;color:#eee}}
.verdict{{color:{color};font-size:1.5em;font-weight:bold}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #444;padding:6px;text-align:left}}
th{{background:#2d2d44}}</style></head>
<body>
<h1>RustRE Sandbox Analysis Report</h1>
<div class="verdict">{verdict}</div>
<p><b>Sample:</b> {name} &nbsp; <b>SHA256:</b> {sha}</p>
<p><b>Score:</b> {score} &nbsp; <b>Family:</b> {family}</p>
<h2>Executive Summary</h2>
<p>{headline}</p>
<ul>{findings}</ul>
<h2>Network IOCs</h2>
<table><tr><th>Type</th><th>Value</th><th>Port</th></tr>{ioc_rows}</table>
<h2>MITRE ATT&CK Techniques</h2>
<table><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr>{tech_rows}</table>
<h2>Recommended Actions</h2>
<ol>{actions}</ol>
</body></html>"#,
            color = color,
            verdict = he(data.verdict.label()).to_uppercase(),
            name = he(&data.sample_name),
            sha = he(&data.sample_sha256),
            score = data.score,
            family = he(data.family.as_deref().unwrap_or("n/a")),
            headline = he(&summary.headline),
            findings = summary
                .key_findings
                .iter()
                .fold(String::new(), |mut acc, f| {
                    let _ = write!(acc, "<li>{}</li>", he(f));
                    acc
                }),
            ioc_rows = ioc_rows,
            tech_rows = tech_rows,
            actions = summary
                .recommended_actions
                .iter()
                .fold(String::new(), |mut acc, a| {
                    let _ = write!(acc, "<li>{}</li>", he(a));
                    acc
                }),
        ))
    }
}

// ─── PdfReportStub ────────────────────────────────────────────────────────────

/// PDF report export (stub — requires external rendering).
pub struct PdfReportStub;

impl PdfReportStub {
    /// Export to PDF (stub: returns error unless HTML-to-PDF backend is present).
    ///
    /// # Errors
    ///
    /// Always returns [`ReportExtError::PdfUnsupported`] until an external
    /// HTML-to-PDF backend (such as wkhtmltopdf) is wired in.
    pub const fn export(_data: &ReportData, _output_path: &str) -> Result<(), ReportExtError> {
        // In a real implementation this would call wkhtmltopdf or similar.
        Err(ReportExtError::PdfUnsupported)
    }

    /// Generate a PDF-compatible HTML source (subset of HTML).
    ///
    /// # Errors
    ///
    /// Propagates any [`ReportExtError`] returned by [`HtmlReportFull::render`].
    pub fn pdf_html(data: &ReportData) -> Result<String, ReportExtError> {
        // Reuse full HTML as the PDF source.
        HtmlReportFull::render(data)
    }
}

// ─── JsonReport ──────────────────────────────────────────────────────────────

/// JSON-format report.
pub struct JsonReport;

impl JsonReport {
    /// Serialize report to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ReportExtError::Serialization`] when `serde_json` fails to
    /// encode `data` (e.g. when a custom serializer fails).
    pub fn render(data: &ReportData) -> Result<String, ReportExtError> {
        serde_json::to_string_pretty(data).map_err(|e| ReportExtError::Serialization(e.to_string()))
    }

    /// Serialize executive summary to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ReportExtError::Serialization`] when `serde_json` fails to
    /// encode the generated summary.
    pub fn summary_json(data: &ReportData) -> Result<String, ReportExtError> {
        let summary = ExecutiveSummary::generate(data);
        serde_json::to_string_pretty(&summary)
            .map_err(|e| ReportExtError::Serialization(e.to_string()))
    }
}

// ─── MitreNavigatorJson ───────────────────────────────────────────────────────

/// Generates a MITRE ATT&CK Navigator layer JSON.
pub struct MitreNavigatorJson;

impl MitreNavigatorJson {
    /// Generate navigator layer from report techniques.
    ///
    /// # Errors
    ///
    /// Returns a [`ReportExtError`] if rendering fails. The current
    /// implementation is infallible but the signature is reserved for future
    /// backends that may fail.
    pub fn render(data: &ReportData) -> Result<String, ReportExtError> {
        use std::fmt::Write as _;
        let techniques_json: String =
            data.techniques.iter().enumerate().fold(String::new(), |mut acc, (idx, t)| {
                if idx > 0 {
                    acc.push_str(",\n");
                }
                let _ = write!(
                    acc,
                    r#"{{"techniqueID":"{id}","score":{score},"comment":"{tactic}","enabled":true}}"#,
                    id = t.technique_id,
                    score = t.confidence,
                    tactic = t.tactic,
                );
                acc
            });

        let layer = format!(
            r#"{{
  "name": "RustRE Analysis - {name}",
  "versions": {{"attack": "14", "navigator": "4.9.1", "layer": "4.5"}},
  "domain": "enterprise-attack",
  "description": "Generated by RustRE sandbox for sample {sha}",
  "gradient": {{"colors": ["{hash}ffffff","{hash}ff6666"], "minValue": 0, "maxValue": 100}},
  "techniques": [
{techniques}
  ]
}}"#,
            name = data.sample_name,
            sha = data.sample_sha256,
            techniques = techniques_json,
            hash = "#",
        );
        Ok(layer)
    }
}

// ─── ReportGeneratorExtended ──────────────────────────────────────────────────

/// Orchestrates all report formats.
pub struct ReportGeneratorExtended;

impl ReportGeneratorExtended {
    /// Generate all report formats and return them as a map.
    #[must_use]
    pub fn generate_all(data: &ReportData) -> HashMap<&'static str, String> {
        let mut out = HashMap::new();
        if let Ok(html) = HtmlReportFull::render(data) {
            out.insert("html", html);
        }
        if let Ok(json) = JsonReport::render(data) {
            out.insert("json", json);
        }
        if let Ok(nav) = MitreNavigatorJson::render(data) {
            out.insert("mitre_navigator", nav);
        }
        if let Ok(summary) = JsonReport::summary_json(data) {
            out.insert("executive_summary", summary);
        }
        out
    }

    /// Generate only the HTML report.
    ///
    /// # Errors
    ///
    /// Propagates the [`ReportExtError`] returned by [`HtmlReportFull::render`].
    pub fn html(data: &ReportData) -> Result<String, ReportExtError> {
        HtmlReportFull::render(data)
    }

    /// Generate only the JSON report.
    ///
    /// # Errors
    ///
    /// Propagates the [`ReportExtError`] returned by [`JsonReport::render`].
    pub fn json(data: &ReportData) -> Result<String, ReportExtError> {
        JsonReport::render(data)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ReportData {
        let mut r = ReportData::new("malware.exe", "abc123", 85);
        r.family = Some("trickbot".into());
        r.network_iocs.push(NetworkIoc {
            kind: "ip".to_string(),
            value: "10.0.0.1".into(),
            port: Some(443),
        });
        r.network_iocs.push(NetworkIoc {
            kind: "domain".to_string(),
            value: "evil.com".into(),
            port: None,
        });
        r.techniques.push(MitreTechnique {
            technique_id: "T1055".into(),
            technique_name: "Process Injection".into(),
            tactic: "Defense Evasion".into(),
            confidence: 90,
            evidence: vec!["WriteProcessMemory".into()],
        });
        r.behaviors.push("process_injection".into());
        r.dropped_files.push("C:\\Temp\\bad.dll".into());
        r
    }

    // ── Severity ─────────────────────────────────────────────────────────────

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(0), Severity::Clean);
        assert_eq!(Severity::from_score(25), Severity::Low);
        assert_eq!(Severity::from_score(50), Severity::Medium);
        assert_eq!(Severity::from_score(75), Severity::High);
        assert_eq!(Severity::from_score(100), Severity::Critical);
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::Clean.label(), "clean");
    }

    #[test]
    fn test_severity_html_colors() {
        assert!(Severity::Critical.html_color().starts_with('#'));
        assert!(Severity::Clean.html_color().starts_with('#'));
    }

    // ── ReportData ────────────────────────────────────────────────────────────

    #[test]
    fn test_report_is_malicious() {
        let r = sample_report();
        assert!(r.is_malicious());
    }

    #[test]
    fn test_report_not_malicious() {
        let r = ReportData::new("clean.exe", "def456", 5);
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_report_network_ioc_count() {
        let r = sample_report();
        assert_eq!(r.network_ioc_count(), 2);
    }

    #[test]
    fn test_report_unique_tactics() {
        let r = sample_report();
        let tactics = r.unique_tactics();
        assert!(tactics.contains(&"Defense Evasion"));
    }

    // ── ExecutiveSummary ──────────────────────────────────────────────────────

    #[test]
    fn test_summary_headline_malicious() {
        let r = sample_report();
        let s = ExecutiveSummary::generate(&r);
        assert!(s.headline.contains("MALICIOUS"));
    }

    #[test]
    fn test_summary_headline_clean() {
        let r = ReportData::new("good.exe", "abc", 5);
        let s = ExecutiveSummary::generate(&r);
        assert!(s.headline.contains("CLEAN"));
    }

    #[test]
    fn test_summary_findings_non_empty() {
        let r = sample_report();
        let s = ExecutiveSummary::generate(&r);
        assert!(!s.key_findings.is_empty());
    }

    #[test]
    fn test_summary_recommended_actions_malicious() {
        let r = sample_report();
        let s = ExecutiveSummary::generate(&r);
        assert!(s.recommended_actions.len() > 1);
    }

    // ── HtmlReportFull ────────────────────────────────────────────────────────

    #[test]
    fn test_html_report_contains_sample_name() {
        let r = sample_report();
        let html = HtmlReportFull::render(&r).unwrap();
        assert!(html.contains("malware.exe"));
    }

    #[test]
    fn test_html_report_contains_doctype() {
        let r = sample_report();
        let html = HtmlReportFull::render(&r).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_html_report_contains_c2() {
        let r = sample_report();
        let html = HtmlReportFull::render(&r).unwrap();
        assert!(html.contains("10.0.0.1"));
    }

    #[test]
    fn test_html_report_contains_mitre_technique() {
        let r = sample_report();
        let html = HtmlReportFull::render(&r).unwrap();
        assert!(html.contains("T1055"));
    }

    // ── PdfReportStub ─────────────────────────────────────────────────────────

    #[test]
    fn test_pdf_stub_returns_unsupported() {
        let r = sample_report();
        let result = PdfReportStub::export(&r, "/tmp/test.pdf");
        assert!(matches!(result, Err(ReportExtError::PdfUnsupported)));
    }

    #[test]
    fn test_pdf_html_generates_html() {
        let r = sample_report();
        let html = PdfReportStub::pdf_html(&r).unwrap();
        assert!(html.contains("DOCTYPE"));
    }

    // ── JsonReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_json_report_valid() {
        let r = sample_report();
        let json = JsonReport::render(&r).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["sample_name"], "malware.exe");
    }

    #[test]
    fn test_json_summary_valid() {
        let r = sample_report();
        let json = JsonReport::summary_json(&r).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["headline"].as_str().is_some());
    }

    // ── MitreNavigatorJson ────────────────────────────────────────────────────

    #[test]
    fn test_mitre_navigator_valid_json() {
        let r = sample_report();
        let nav = MitreNavigatorJson::render(&r).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&nav).unwrap();
        assert_eq!(parsed["domain"], "enterprise-attack");
    }

    #[test]
    fn test_mitre_navigator_contains_technique() {
        let r = sample_report();
        let nav = MitreNavigatorJson::render(&r).unwrap();
        assert!(nav.contains("T1055"));
    }

    // ── ReportGeneratorExtended ───────────────────────────────────────────────

    #[test]
    fn test_generator_all_formats() {
        let r = sample_report();
        let all = ReportGeneratorExtended::generate_all(&r);
        assert!(all.contains_key("html"));
        assert!(all.contains_key("json"));
        assert!(all.contains_key("mitre_navigator"));
        assert!(all.contains_key("executive_summary"));
    }

    #[test]
    fn test_generator_html() {
        let r = sample_report();
        let html = ReportGeneratorExtended::html(&r).unwrap();
        assert!(!html.is_empty());
    }

    #[test]
    fn test_generator_json() {
        let r = sample_report();
        let json = ReportGeneratorExtended::json(&r).unwrap();
        assert!(!json.is_empty());
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
    }

    #[test]
    fn test_network_ioc_ip_kind() {
        let r = sample_report();
        assert!(r.network_iocs.iter().any(|i| i.kind == "ip"));
    }

    #[test]
    fn test_network_ioc_domain_kind() {
        let r = sample_report();
        assert!(r.network_iocs.iter().any(|i| i.kind == "domain"));
    }

    #[test]
    fn test_mitre_technique_confidence() {
        let r = sample_report();
        assert_eq!(r.techniques[0].confidence, 90);
    }

    #[test]
    fn test_report_dropped_files() {
        let r = sample_report();
        assert_eq!(r.dropped_files.len(), 1);
    }

    #[test]
    fn test_summary_mitre_coverage() {
        let r = sample_report();
        let s = ExecutiveSummary::generate(&r);
        assert_eq!(s.mitre_coverage, 1);
    }

    #[test]
    fn test_html_report_contains_score() {
        let r = sample_report();
        let html = HtmlReportFull::render(&r).unwrap();
        assert!(html.contains("85"));
    }

    #[test]
    fn test_json_report_contains_family() {
        let r = sample_report();
        let json = JsonReport::render(&r).unwrap();
        assert!(json.contains("trickbot"));
    }

    #[test]
    fn test_mitre_navigator_contains_sample_name() {
        let r = sample_report();
        let nav = MitreNavigatorJson::render(&r).unwrap();
        assert!(nav.contains("malware.exe"));
    }
}
