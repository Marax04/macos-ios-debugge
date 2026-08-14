//! Triage report generation in multiple formats.
//!
//! Provides `TriageReport2` (a richer report type supplementing `TriageReport`),
//! `ReportFormat`, `ReportSection`, and the `render_html()` function for
//! producing a self-contained HTML coverage report.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

use crate::{FileKind, ThreatLevel, TriageIndicator, TriageResult};

// ─── ReportFormat ─────────────────────────────────────────────────────────────

/// Output format for triage reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    /// Plain text (human-readable summary).
    Text,
    /// JSON (machine-readable).
    Json,
    /// HTML (self-contained with embedded CSS).
    Html,
    /// Markdown.
    Markdown,
    /// CSV (for spreadsheet import).
    Csv,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ReportSection ────────────────────────────────────────────────────────────

/// A logical section inside a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    /// Section title.
    pub title: String,
    /// Pre-rendered content lines.
    pub content_lines: Vec<String>,
    /// Optional indicators belonging to this section.
    pub indicators: Vec<TriageIndicator>,
    /// Whether this section is considered high-severity.
    pub is_critical: bool,
}

impl ReportSection {
    /// Create an empty section.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            content_lines: Vec::new(),
            indicators: Vec::new(),
            is_critical: false,
        }
    }

    /// Add a content line.
    pub fn push(&mut self, line: impl Into<String>) {
        self.content_lines.push(line.into());
    }

    /// Add a key-value pair.
    pub fn push_kv(&mut self, key: &str, value: &str) {
        self.content_lines.push(format!("{key}: {value}"));
    }

    /// Render the section as plain text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = format!("=== {} ===\n", self.title);
        for line in &self.content_lines {
            out.push_str(line);
            out.push('\n');
        }
        for ind in &self.indicators {
            let _ = writeln!(out, "  [{:?}] {} — {}", ind.threat_level, ind.name, ind.description);
        }
        out
    }

    /// Render the section as Markdown.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = format!("## {}\n\n", self.title);
        for line in &self.content_lines {
            out.push_str(line);
            out.push('\n');
        }
        if !self.indicators.is_empty() {
            out.push_str("\n| Level | Name | Description |\n");
            out.push_str("|-------|------|-------------|\n");
            for ind in &self.indicators {
                let _ = writeln!(out, "| {:?} | {} | {} |", ind.threat_level, ind.name, ind.description);
            }
        }
        out
    }
}

// ─── TriageReport2 ────────────────────────────────────────────────────────────

/// A structured, multi-section triage report.
///
/// This is a richer alternative to the flat `TriageReport` already in lib.rs,
/// providing per-section breakdown, chart-ready statistics, and multiple
/// rendering modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport2 {
    /// Report title (usually the file name).
    pub title: String,
    /// Ordered list of sections.
    pub sections: Vec<ReportSection>,
    /// Overall threat level.
    pub threat_level: ThreatLevel,
    /// Numeric score 0–100.
    pub score: u8,
    /// File format detected.
    pub file_kind: FileKind,
    /// SHA-256 hex string.
    pub sha256: String,
    /// MD5 hex string.
    #[serde(default)]
    pub md5: String,
    /// File size in bytes.
    pub file_size: usize,
    /// Entropy of the file.
    pub entropy: f64,
    /// Whether the file is packed.
    pub is_packed: bool,
    /// Whether obfuscation was detected.
    pub is_obfuscated: bool,
    /// Analysis timestamp (Unix seconds).
    pub timestamp: u64,
    /// All indicators flattened across all sections.
    pub all_indicators: Vec<TriageIndicator>,
}

impl TriageReport2 {
    /// Build a `TriageReport2` from a `TriageResult`.
    #[must_use]
    pub fn from_result(title: impl Into<String>, result: &TriageResult) -> Self {
        let mut report = Self {
            title: title.into(),
            sections: Vec::new(),
            threat_level: result.threat_level,
            score: result.score,
            file_kind: result.file_kind,
            sha256: result.sha256.clone(),
            md5: result.md5.clone(),
            file_size: result.file_size,
            entropy: result.entropy,
            is_packed: result.is_packed,
            is_obfuscated: result.is_obfuscated,
            timestamp: 0,
            all_indicators: result.indicators.clone(),
        };

        // Section 1: File overview.
        let mut overview = ReportSection::new("File Overview");
        overview.push_kv("SHA-256", &result.sha256);
        overview.push_kv("MD5", &result.md5);
        overview.push_kv("Size", &format!("{} bytes", result.file_size));
        overview.push_kv("Format", &format!("{:?}", result.file_kind));
        overview.push_kv("Entropy", &format!("{:.4}", result.entropy));
        overview.push_kv("Packed", &result.is_packed.to_string());
        overview.push_kv("Obfuscated", &result.is_obfuscated.to_string());
        report.sections.push(overview);

        // Section 2: Threat assessment.
        let mut threat = ReportSection::new("Threat Assessment");
        threat.push_kv("Level", &result.threat_level.to_string());
        threat.push_kv("Score", &format!("{}/100", result.score));
        threat.is_critical = result.threat_level >= ThreatLevel::High;
        report.sections.push(threat);

        // Section 3: Indicators grouped by category.
        let mut by_cat: HashMap<&str, Vec<&TriageIndicator>> = HashMap::new();
        for ind in &result.indicators {
            by_cat.entry(ind.category.as_str()).or_default().push(ind);
        }
        let mut cats: Vec<&str> = by_cat.keys().copied().collect();
        cats.sort_unstable();
        for cat in cats {
            let mut section = ReportSection::new(format!("Indicators: {cat}"));
            section.is_critical = by_cat[cat]
                .iter()
                .any(|i| i.threat_level >= ThreatLevel::High);
            section.indicators = by_cat[cat].iter().map(|i| (*i).clone()).collect();
            report.sections.push(section);
        }

        report
    }

    /// Total indicator count across all sections.
    #[must_use]
    pub const fn indicator_count(&self) -> usize {
        self.all_indicators.len()
    }

    /// Count indicators by threat level.
    #[must_use]
    pub fn indicators_by_level(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for ind in &self.all_indicators {
            *map.entry(format!("{:?}", ind.threat_level)).or_insert(0) += 1;
        }
        map
    }

    /// Render as plain text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = format!("Triage Report: {}\n", self.title);
        out.push_str(&"=".repeat(60));
        out.push('\n');
        for section in &self.sections {
            out.push_str(&section.render_text());
            out.push('\n');
        }
        out
    }

    /// Render as Markdown.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = format!("# Triage Report: {}\n\n", self.title);
        for section in &self.sections {
            out.push_str(&section.render_markdown());
            out.push('\n');
        }
        out
    }

    /// Render as CSV (one row per indicator).
    #[must_use]
    pub fn render_csv(&self) -> String {
        let mut out = String::from("category,name,threat_level,description,evidence\n");
        for ind in &self.all_indicators {
            let desc = ind.description.replace('"', "'");
            let ev = ind.evidence.replace('"', "'");
            let _ = writeln!(out, "{},{},{:?},{:?},{:?}", ind.category, ind.name, ind.threat_level, desc, ev);
        }
        out
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json` error if serialization fails.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render as a self-contained HTML document.
    #[must_use]
    pub fn render_html(&self) -> String {
        render_html(self)
    }
}

// ─── HTML renderer ────────────────────────────────────────────────────────────

fn render_indicator_rows(report: &TriageReport2) -> String {
    let mut rows = String::new();
    for ind in &report.all_indicators {
        let (bg, fg) = indicator_colors(ind.threat_level);
        let desc = html_escape(&ind.description);
        let ev = html_escape(&ind.evidence);
        let _ = writeln!(
            rows,
            "<tr>\
              <td style=\"background:{bg};color:{fg};padding:4px 8px\">{:?}</td>\
              <td>{}</td>\
              <td>{}</td>\
              <td>{}</td>\
              <td>{ev}</td>\
            </tr>",
            ind.threat_level, html_escape(&ind.category), html_escape(&ind.name), desc,
        );
    }
    rows
}

fn render_section_html(report: &TriageReport2) -> String {
    report
        .sections
        .iter()
        .map(|s| {
            let kv_rows: String = s
                .content_lines
                .iter()
                .map(|line| {
                    line.find(": ").map_or_else(
                        || format!("<tr><td colspan=\"2\">{}</td></tr>", html_escape(line)),
                        |pos| {
                            let k = &line[..pos];
                            let v = &line[pos + 2..];
                            format!("<tr><th>{k}</th><td>{v}</td></tr>")
                        },
                    )
                })
                .collect();
            if kv_rows.is_empty() && s.indicators.is_empty() {
                String::new()
            } else {
                format!(
                    "<details{open}><summary><b>{}</b></summary>\
                     <table class=\"kv\">{kv_rows}</table></details>\n",
                    html_escape(&s.title),
                    open = if s.is_critical { " open" } else { "" },
                )
            }
        })
        .collect::<String>()
}

/// Render a `TriageReport2` as a self-contained HTML document.
#[must_use]
pub fn render_html(report: &TriageReport2) -> String {
    let level_color = match report.threat_level {
        ThreatLevel::Clean | ThreatLevel::Informational => "#2ecc71",
        ThreatLevel::Low => "#f39c12",
        ThreatLevel::Medium => "#e67e22",
        ThreatLevel::High => "#e74c3c",
        ThreatLevel::Critical => "#8e44ad",
    };
    let rows = render_indicator_rows(report);
    let section_html = render_section_html(report);
    let score_bar_width = report.score;
    let bar_color = level_color;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Triage Report — {title}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #12121f; color: #d0d0e0; margin: 0; padding: 1em 2em; }}
  h1 {{ color: #00d4ff; font-size: 1.6em; margin-bottom: 0.2em; }}
  h2 {{ color: #aaccff; font-size: 1.1em; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px;
            background: {level_color}; color: #000; font-weight: bold; }}
  .score-bar-outer {{ height: 18px; background: #333; border-radius: 4px; margin: 8px 0; }}
  .score-bar-inner {{ height: 100%; width: {score_bar_width}%;
                      background: {bar_color}; border-radius: 4px; transition: width 0.4s; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
  th, td {{ border: 1px solid #2a2a4a; padding: 6px 10px; text-align: left; }}
  th {{ background: #1a1a3a; color: #aaccff; }}
  tr:nth-child(even) {{ background: #1a1a2e; }}
  table.kv th {{ width: 30%; }}
  details {{ margin: 8px 0; background: #1a1a2e; border-radius: 4px; padding: 4px 12px; }}
  summary {{ cursor: pointer; font-weight: bold; color: #aaccff; }}
  .meta {{ display: flex; gap: 1.5em; flex-wrap: wrap; margin: 1em 0; }}
  .meta-item {{ background: #1a1a3a; border-radius: 6px; padding: 8px 16px; }}
  .meta-item .label {{ font-size: 0.75em; color: #7788aa; }}
  .meta-item .value {{ font-size: 1.2em; font-weight: bold; }}
</style>
</head>
<body>
<h1>Triage Report</h1>
<div style="color:#7788aa;margin-bottom:1em;font-size:0.9em">{title}</div>
<div class="meta">
  <div class="meta-item"><div class="label">Threat Level</div>
    <div class="value"><span class="badge">{threat_level:?}</span></div></div>
  <div class="meta-item"><div class="label">Score</div>
    <div class="value">{score}/100</div></div>
  <div class="meta-item"><div class="label">Format</div>
    <div class="value">{file_kind:?}</div></div>
  <div class="meta-item"><div class="label">Size</div>
    <div class="value">{file_size} B</div></div>
  <div class="meta-item"><div class="label">Entropy</div>
    <div class="value">{entropy:.3}</div></div>
  <div class="meta-item"><div class="label">Packed</div>
    <div class="value">{is_packed}</div></div>
</div>
<div class="score-bar-outer"><div class="score-bar-inner"></div></div>
{section_html}
<h2>All Indicators ({ind_count})</h2>
<table>
<tr><th>Level</th><th>Category</th><th>Name</th><th>Description</th><th>Evidence</th></tr>
{rows}
</table>
<div style="color:#444;font-size:0.8em;margin-top:2em">SHA-256: {sha256}<br>MD5: {md5}</div>
</body>
</html>
"#,
        title = html_escape(&report.title),
        level_color = level_color,
        threat_level = report.threat_level,
        score = report.score,
        score_bar_width = score_bar_width,
        bar_color = bar_color,
        file_kind = report.file_kind,
        file_size = report.file_size,
        entropy = report.entropy,
        is_packed = report.is_packed,
        section_html = section_html,
        ind_count = report.all_indicators.len(),
        rows = rows,
        sha256 = &report.sha256,
        md5 = &report.md5,
    )
}

const fn indicator_colors(level: ThreatLevel) -> (&'static str, &'static str) {
    match level {
        ThreatLevel::Clean | ThreatLevel::Informational => ("#2ecc71", "#000"),
        ThreatLevel::Low => ("#f39c12", "#000"),
        ThreatLevel::Medium => ("#e67e22", "#000"),
        ThreatLevel::High => ("#e74c3c", "#fff"),
        ThreatLevel::Critical => ("#8e44ad", "#fff"),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ─── ReportBuilder ────────────────────────────────────────────────────────────

/// Builder for constructing a `TriageReport2` from scratch (without a `TriageResult`).
#[derive(Debug, Default)]
pub struct ReportBuilder {
    title: String,
    sections: Vec<ReportSection>,
    threat_level: ThreatLevel,
    score: u8,
    file_kind: FileKind,
    sha256: String,
    md5: String,
    file_size: usize,
    entropy: f64,
    is_packed: bool,
    is_obfuscated: bool,
    all_indicators: Vec<TriageIndicator>,
}

impl ReportBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            file_kind: FileKind::Unknown,
            ..Default::default()
        }
    }

    /// Set the threat level.
    #[must_use]
    pub const fn threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = level;
        self
    }

    /// Set the score.
    #[must_use]
    pub const fn score(mut self, score: u8) -> Self {
        self.score = score;
        self
    }

    /// Set the file kind.
    #[must_use]
    pub const fn file_kind(mut self, kind: FileKind) -> Self {
        self.file_kind = kind;
        self
    }

    /// Set the SHA-256 hex string.
    #[must_use]
    pub fn sha256(mut self, sha: impl Into<String>) -> Self {
        self.sha256 = sha.into();
        self
    }

    /// Set the MD5 hex string.
    #[must_use]
    pub fn md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = md5.into();
        self
    }

    /// Set the file size.
    #[must_use]
    pub const fn file_size(mut self, size: usize) -> Self {
        self.file_size = size;
        self
    }

    /// Set the entropy.
    #[must_use]
    pub const fn entropy(mut self, e: f64) -> Self {
        self.entropy = e;
        self
    }

    /// Mark as packed.
    #[must_use]
    pub const fn packed(mut self, p: bool) -> Self {
        self.is_packed = p;
        self
    }

    /// Add a section.
    #[must_use]
    pub fn add_section(mut self, section: ReportSection) -> Self {
        self.sections.push(section);
        self
    }

    /// Add an indicator to the flat list.
    #[must_use]
    pub fn add_indicator(mut self, ind: TriageIndicator) -> Self {
        self.all_indicators.push(ind);
        self
    }

    /// Build the final report.
    #[must_use]
    pub fn build(self) -> TriageReport2 {
        TriageReport2 {
            title: self.title,
            sections: self.sections,
            threat_level: self.threat_level,
            score: self.score,
            file_kind: self.file_kind,
            sha256: self.sha256,
            md5: self.md5,
            file_size: self.file_size,
            entropy: self.entropy,
            is_packed: self.is_packed,
            is_obfuscated: self.is_obfuscated,
            timestamp: 0,
            all_indicators: self.all_indicators,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileKind, ThreatLevel, TriageResult};

    fn make_result() -> TriageResult {
        let data = vec![0u8; 128];
        let mut r = TriageResult::new(FileKind::Unknown, &data);
        r.add_indicator(TriageIndicator {
            name: "test-indicator".to_string(),
            description: "Test".to_string(),
            threat_level: ThreatLevel::Medium,
            category: "test".to_string(),
            evidence: "ev".to_string(),
        });
        r
    }

    #[test]
    fn test_report2_from_result() {
        let result = make_result();
        let report = TriageReport2::from_result("test.exe", &result);
        assert_eq!(report.title, "test.exe");
        assert!(!report.sections.is_empty());
        assert_eq!(report.indicator_count(), 1);
    }

    #[test]
    fn test_render_text_contains_title() {
        let result = make_result();
        let report = TriageReport2::from_result("malware.exe", &result);
        let text = report.render_text();
        assert!(text.contains("malware.exe"));
    }

    #[test]
    fn test_render_markdown() {
        let result = make_result();
        let report = TriageReport2::from_result("test.exe", &result);
        let md = report.render_markdown();
        assert!(md.starts_with("# Triage Report:"));
    }

    #[test]
    fn test_render_csv() {
        let result = make_result();
        let report = TriageReport2::from_result("test.exe", &result);
        let csv = report.render_csv();
        assert!(csv.contains("category,name,threat_level"));
        assert!(csv.contains("test-indicator"));
    }

    #[test]
    fn test_render_json() {
        let result = make_result();
        let report = TriageReport2::from_result("test.exe", &result);
        let json = report.render_json().unwrap();
        assert!(json.contains("test-indicator"));
    }

    #[test]
    fn test_render_html() {
        let result = make_result();
        let report = TriageReport2::from_result("test.exe", &result);
        let html = report.render_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test-indicator"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn test_report_section_render_text() {
        let mut s = ReportSection::new("Test Section");
        s.push_kv("Key", "Value");
        let text = s.render_text();
        assert!(text.contains("Test Section"));
        assert!(text.contains("Key: Value"));
    }

    #[test]
    fn test_report_section_render_markdown() {
        let mut s = ReportSection::new("Section");
        s.push("content line");
        let md = s.render_markdown();
        assert!(md.contains("## Section"));
    }

    #[test]
    fn test_builder() {
        let report = ReportBuilder::new("built")
            .threat_level(ThreatLevel::High)
            .score(80)
            .file_kind(FileKind::Pe64)
            .sha256("aabbcc")
            .md5("ddeeff")
            .file_size(4096)
            .entropy(7.5)
            .packed(true)
            .build();
        assert_eq!(report.title, "built");
        assert_eq!(report.score, 80);
        assert_eq!(report.md5, "ddeeff");
        assert!(report.is_packed);
    }

    #[test]
    fn test_report2_propagates_md5() {
        let data = vec![0u8; 16];
        let result = TriageResult::new(FileKind::Unknown, &data);
        let report = TriageReport2::from_result("t.bin", &result);
        assert_eq!(report.md5, result.md5);
        assert_eq!(report.md5.len(), 32);
        let text = report.render_text();
        assert!(text.contains("MD5"));
        let html = report.render_html();
        assert!(html.contains("MD5"));
    }

    #[test]
    fn test_indicators_by_level() {
        let result = make_result();
        let report = TriageReport2::from_result("t", &result);
        let map = report.indicators_by_level();
        assert!(map.contains_key("Medium"));
    }
}
