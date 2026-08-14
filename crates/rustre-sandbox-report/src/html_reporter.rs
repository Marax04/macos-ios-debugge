/// HTML report generator: full self-contained HTML with embedded CSS;
/// timeline table, IOC lists, behavior summary, screenshots.
use std::fmt::Write as FmtWrite;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    html_escape, Behavior, IocCollection, IocKind, IocSet, Indicator, SandboxReport,
    Severity, Verdict, AttackMapping, AttackTechnique,
};

// ─── HtmlTheme ────────────────────────────────────────────────────────────────

/// Color/font theme for HTML reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlTheme {
    pub primary_color: String,
    pub danger_color: String,
    pub warning_color: String,
    pub success_color: String,
    pub background_color: String,
    pub text_color: String,
    pub font_family: String,
    pub max_width_px: u32,
}

impl Default for HtmlTheme {
    fn default() -> Self {
        Self {
            primary_color: "#1d3557".to_string(),
            danger_color: "#e63946".to_string(),
            warning_color: "#f4a261".to_string(),
            success_color: "#2a9d8f".to_string(),
            background_color: "#f1faee".to_string(),
            text_color: "#222222".to_string(),
            font_family: "'Segoe UI', 'Helvetica Neue', Arial, sans-serif".to_string(),
            max_width_px: 1200,
        }
    }
}

impl HtmlTheme {
    /// Static CSS fragments that do not depend on theme colors.
    const CSS_STATIC: &'static str = concat!(
        "\n*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n",
        ".container{margin:0 auto;background:#fff;border-radius:10px;",
        "box-shadow:0 4px 24px rgba(0,0,0,0.12);overflow:hidden;}\n",
        ".header{color:#fff;padding:2rem 2.5rem;}\n",
        ".header h1{font-size:1.9rem;font-weight:700;letter-spacing:-0.5px}\n",
        ".header p{margin-top:0.3rem;opacity:0.82;font-size:0.92rem}\n",
        ".content{padding:2rem 2.5rem}\n",
        ".verdict-badge{display:inline-block;padding:0.3em 0.9em;border-radius:999px;",
        "font-weight:700;font-size:0.95rem;text-transform:uppercase;letter-spacing:0.06em;}\n",
        ".verdict-clean{background:#d4edda;color:#155724}\n",
        ".verdict-suspicious{background:#fff3cd;color:#856404}\n",
        ".verdict-malicious{background:#f8d7da;color:#721c24}\n",
        ".verdict-unknown{background:#e2e3e5;color:#383d41}\n",
        ".score-bar-wrap{background:#e9ecef;border-radius:999px;height:14px;margin:0.6rem 0}\n",
        ".score-bar{height:100%;border-radius:999px;transition:width 0.4s ease;}\n",
        ".section{margin-top:2rem}\n",
        ".table-wrap{overflow-x:auto;margin-bottom:1rem}\n",
        "table{border-collapse:collapse;width:100%;font-size:0.9rem}\n",
        "thead th{color:#fff;padding:0.55em 0.9em;text-align:left;font-weight:600;white-space:nowrap;}\n",
        "tbody tr:nth-child(even){background:#f8f9fa}\n",
        "tbody tr:hover{background:#eaf2ff}\n",
        "td,th{border:1px solid #dee2e6;padding:0.45em 0.9em;vertical-align:top}\n",
        ".sev{display:inline-block;padding:0.15em 0.6em;border-radius:4px;",
        "font-size:0.78rem;font-weight:700;text-transform:uppercase;letter-spacing:0.04em}\n",
        ".sev-info{background:#cff4fc;color:#055160}\n",
        ".sev-low{background:#d1ecf1;color:#0c5460}\n",
        ".sev-medium{background:#fff3cd;color:#664d03}\n",
        ".sev-high{background:#f8d7da;color:#842029}\n",
        ".sev-critical{background:#721c24;color:#fff}\n",
        ".tag{display:inline-block;border-radius:3px;padding:0.1em 0.55em;margin:0.15em;font-size:0.8rem;}\n",
        "code{background:#f0f0f0;padding:0.1em 0.4em;border-radius:3px;font-size:0.87em;word-break:break-all;}\n",
        "pre{background:#1a1a2e;color:#c8c8c8;padding:1em 1.2em;border-radius:6px;",
        "overflow-x:auto;font-size:0.84rem;line-height:1.5;}\n",
        ".timeline{list-style:none;padding-left:1.5rem;margin-top:0.5rem}\n",
        ".timeline li{position:relative;padding:0.4rem 0 0.4rem 0.2rem;margin-bottom:0.5rem}\n",
        ".timeline li::before{content:\"\";position:absolute;left:-1.72rem;top:0.6rem;",
        "width:12px;height:12px;border-radius:50%;border:2px solid #fff;}\n",
        ".timeline .ts{font-size:0.78rem;color:#888;margin-right:0.5rem}\n",
        ".report-footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #dee2e6;",
        "font-size:0.78rem;color:#888;text-align:center;}\n",
    );

    /// Generate the CSS string for this theme.
    #[must_use]
    pub fn to_css(&self) -> String {
        let p = &self.primary_color;
        let mut css = format!(
            "body{{font-family:{font};background:{bg};color:{text};line-height:1.55;padding:1rem;}}\n",
            font = self.font_family,
            bg   = self.background_color,
            text = self.text_color,
        );
        css.push_str(Self::CSS_STATIC);
        let _ = write!(css,
            ".container{{max-width:{mw}px;}}\n\
             .header{{background:{p};}}\n\
             .score-bar.low{{background:{success}}}\n\
             .score-bar.medium{{background:{warning}}}\n\
             .score-bar.high{{background:{danger}}}\n\
             .section-title{{font-size:1.2rem;font-weight:700;color:{p};border-bottom:2px solid {p};padding-bottom:0.4rem;margin-bottom:1rem;}}\n\
             thead th{{background:{p};}}\n\
             .tag{{background:{p}22;color:{p};border:1px solid {p}55;}}\n\
             .timeline{{border-left:3px solid {p};}}\n\
             .timeline li::before{{background:{p};box-shadow:0 0 0 2px {p};}}\n",
            mw      = self.max_width_px,
            p       = p,
            success = self.success_color,
            warning = self.warning_color,
            danger  = self.danger_color,
        );
        css
    }
}

// ─── ScreenshotEntry ──────────────────────────────────────────────────────────

/// A screenshot captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotEntry {
    /// Timestamp in milliseconds from start.
    pub timestamp_ms: u64,
    /// Base64-encoded PNG data.
    pub data_base64: String,
    /// Optional caption.
    pub caption: String,
}

impl ScreenshotEntry {
    #[must_use]
    pub fn new(timestamp_ms: u64, data_base64: impl Into<String>, caption: impl Into<String>) -> Self {
        Self { timestamp_ms, data_base64: data_base64.into(), caption: caption.into() }
    }

    /// Render as an HTML `<figure>` element with embedded PNG.
    #[must_use]
    pub fn to_html_figure(&self) -> String {
        format!(
            r#"<figure style="display:inline-block;margin:0.5rem;border:1px solid #dee2e6;border-radius:6px;overflow:hidden;max-width:320px">
  <img src="data:image/png;base64,{}" alt="{}" style="width:100%;display:block">
  <figcaption style="padding:0.3rem 0.5rem;font-size:0.78rem;background:#f8f9fa;color:#555">
    <strong>T+{}ms</strong> — {}
  </figcaption>
</figure>"#,
            html_escape(&self.data_base64),
            html_escape(&self.caption),
            self.timestamp_ms,
            html_escape(&self.caption),
        )
    }
}

// ─── TimelineEvent ────────────────────────────────────────────────────────────

/// A single event in the execution timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp_ms: u64,
    pub pid: u32,
    pub category: String,
    pub description: String,
    pub severity: Severity,
}

impl TimelineEvent {
    #[must_use]
    pub fn new(
        timestamp_ms: u64,
        pid: u32,
        category: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self { timestamp_ms, pid, category: category.into(), description: description.into(), severity }
    }

    #[must_use]
    pub const fn severity_class(&self) -> &'static str {
        match self.severity {
            Severity::Info => "sev-info",
            Severity::Low => "sev-low",
            Severity::Medium => "sev-medium",
            Severity::High => "sev-high",
            Severity::Critical => "sev-critical",
        }
    }
}

// ─── HtmlReportOptions ────────────────────────────────────────────────────────

/// Bitmask of which HTML report sections to render.
#[derive(Debug, Clone, Copy)]
pub struct HtmlSectionFlags(u8);

impl HtmlSectionFlags {
    const TIMELINE:       u8 = 0b0000_0001;
    const SCREENSHOTS:    u8 = 0b0000_0010;
    const IOC_SECTION:    u8 = 0b0000_0100;
    const ATTACK_SECTION: u8 = 0b0000_1000;
    const DROPPED_FILES:  u8 = 0b0001_0000;
    const NETWORK:        u8 = 0b0010_0000;
    const BEHAVIOR:       u8 = 0b0100_0000;

    /// All sections enabled.
    #[must_use]
    pub const fn all() -> Self { Self(0x7F) }

    #[must_use] pub const fn timeline(self) -> bool       { self.0 & Self::TIMELINE       != 0 }
    #[must_use] pub const fn screenshots(self) -> bool    { self.0 & Self::SCREENSHOTS    != 0 }
    #[must_use] pub const fn ioc_section(self) -> bool    { self.0 & Self::IOC_SECTION    != 0 }
    #[must_use] pub const fn attack_section(self) -> bool { self.0 & Self::ATTACK_SECTION != 0 }
    #[must_use] pub const fn dropped_files(self) -> bool  { self.0 & Self::DROPPED_FILES  != 0 }
    #[must_use] pub const fn network(self) -> bool        { self.0 & Self::NETWORK        != 0 }
    #[must_use] pub const fn behavior(self) -> bool       { self.0 & Self::BEHAVIOR       != 0 }
}

impl Default for HtmlSectionFlags {
    fn default() -> Self { Self::all() }
}

/// Options controlling what sections appear in the HTML report.
#[derive(Debug, Clone)]
pub struct HtmlReportOptions {
    /// Which sections to render.
    pub sections: HtmlSectionFlags,
    pub max_iocs_per_table: usize,
    pub title_override: Option<String>,
}

impl HtmlReportOptions {
    #[must_use] pub const fn include_timeline(&self) -> bool        { self.sections.timeline() }
    #[must_use] pub const fn include_screenshots(&self) -> bool     { self.sections.screenshots() }
    #[must_use] pub const fn include_ioc_section(&self) -> bool     { self.sections.ioc_section() }
    #[must_use] pub const fn include_attack_section(&self) -> bool  { self.sections.attack_section() }
    #[must_use] pub const fn include_dropped_files(&self) -> bool   { self.sections.dropped_files() }
    #[must_use] pub const fn include_network_section(&self) -> bool { self.sections.network() }
    #[must_use] pub const fn include_behavior_section(&self) -> bool { self.sections.behavior() }
}

impl Default for HtmlReportOptions {
    fn default() -> Self {
        Self {
            sections: HtmlSectionFlags::default(),
            max_iocs_per_table: 500,
            title_override: None,
        }
    }
}

// ─── HtmlReporter ─────────────────────────────────────────────────────────────

/// Full self-contained HTML report generator.
pub struct HtmlReporter {
    theme: HtmlTheme,
    opts: HtmlReportOptions,
    screenshots: Vec<ScreenshotEntry>,
    timeline: Vec<TimelineEvent>,
    extra_iocs: Option<IocCollection>,
    ttp_map: Option<HashMap<String, Vec<String>>>,
}

impl HtmlReporter {
    /// Create a reporter with default theme and options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            theme: HtmlTheme::default(),
            opts: HtmlReportOptions::default(),
            screenshots: Vec::new(),
            timeline: Vec::new(),
            extra_iocs: None,
            ttp_map: None,
        }
    }

    /// Set a custom theme.
    #[must_use]
    pub fn with_theme(mut self, theme: HtmlTheme) -> Self {
        self.theme = theme;
        self
    }

    /// Set custom options.
    #[must_use]
    pub fn with_options(mut self, opts: HtmlReportOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Add screenshots.
    #[must_use]
    pub fn with_screenshots(mut self, screenshots: Vec<ScreenshotEntry>) -> Self {
        self.screenshots = screenshots;
        self
    }

    /// Add timeline events.
    #[must_use]
    pub fn with_timeline(mut self, events: Vec<TimelineEvent>) -> Self {
        self.timeline = events;
        self
    }

    /// Attach an extracted IOC collection.
    #[must_use]
    pub fn with_ioc_collection(mut self, iocs: IocCollection) -> Self {
        self.extra_iocs = Some(iocs);
        self
    }

    /// Attach a TTP override map.
    #[must_use]
    pub fn with_ttp_map(mut self, map: HashMap<String, Vec<String>>) -> Self {
        self.ttp_map = Some(map);
        self
    }

    /// Generate a full self-contained HTML report from `report`.
    #[must_use]
    pub fn render(&self, report: &SandboxReport) -> String {
        let css = self.theme.to_css();
        let title = self.opts.title_override.as_deref()
            .unwrap_or(&report.sample)
            .to_owned();

        let mut body = String::with_capacity(65536);
        Self::render_header(&mut body, report);
        Self::render_summary_table(&mut body, report);
        if self.opts.include_behavior_section() {
            Self::render_behavior_section(&mut body, report);
        }
        if self.opts.include_timeline() {
            self.render_timeline_section(&mut body);
        }
        if self.opts.include_ioc_section() {
            self.render_ioc_section(&mut body, report);
        }
        if self.opts.include_attack_section() {
            self.render_attack_section(&mut body, report);
        }
        if self.opts.include_dropped_files() {
            self.render_dropped_files(&mut body, report);
        }
        if self.opts.include_network_section() {
            self.render_network_iocs(&mut body, report);
        }
        Self::render_sections(&mut body, report);
        if self.opts.include_screenshots() && !self.screenshots.is_empty() {
            self.render_screenshots(&mut body);
        }
        Self::render_footer(&mut body, report);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="generator" content="RustRE HtmlReporter">
  <title>Sandbox Report — {title}</title>
  <style>{css}</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"#,
            title = html_escape(&title),
        )
    }

    #[must_use]
    const fn verdict_class(v: &Verdict) -> &'static str {
        match v {
            Verdict::Clean => "verdict-clean",
            Verdict::Low => "verdict-low",
            Verdict::Suspicious => "verdict-suspicious",
            Verdict::Malicious => "verdict-malicious",
            Verdict::Unknown => "verdict-unknown",
        }
    }

    #[must_use]
    const fn score_bar_class(score: u32) -> &'static str {
        if score < 30 { "low" } else if score < 70 { "medium" } else { "high" }
    }

    fn render_header(out: &mut String, report: &SandboxReport) {
        let vc = Self::verdict_class(&report.verdict);
        let _ = write!(
            out,
            r#"<div class="header">
  <h1>Sandbox Analysis Report</h1>
  <p>Sample: <strong>{sample}</strong> &nbsp;|&nbsp;
     SHA-256: <code style="font-size:0.82rem;background:rgba(255,255,255,0.15);padding:0.1em 0.4em;border-radius:3px">{sha}</code></p>
  <p style="margin-top:0.8rem">
    <span class="verdict-badge {vc}">{verdict}</span>
    &nbsp; Threat score: <strong>{score}/100</strong>
    &nbsp; Family: <strong>{family}</strong>
  </p>
</div>
"#,
            sample = html_escape(&report.sample),
            sha = html_escape(&report.sha256),
            vc = vc,
            verdict = report.verdict,
            score = report.score,
            family = html_escape(&report.family),
        );
    }

    fn render_summary_table(out: &mut String, report: &SandboxReport) {
        let vc = Self::verdict_class(&report.verdict);
        let sbc = Self::score_bar_class(report.score);
        let tags_html: String = report.tags.iter()
            .map(|t| format!("<span class=\"tag\">{}</span>", html_escape(t)))
            .collect::<Vec<_>>()
            .join(" ");

        let _ = write!(
            out,
            r#"<div class="content">
<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="table-wrap">
  <table>
    <thead><tr><th style="width:200px">Property</th><th>Value</th></tr></thead>
    <tbody>
      <tr><td>Sample Name</td><td><code>{sample}</code></td></tr>
      <tr><td>SHA-256</td><td><code>{sha}</code></td></tr>
      <tr><td>Verdict</td><td><span class="verdict-badge {vc}">{verdict}</span></td></tr>
      <tr><td>Threat Score</td>
          <td>
            <strong>{score}/100</strong>
            <div class="score-bar-wrap"><div class="score-bar {sbc}" style="width:{score}%"></div></div>
          </td></tr>
      <tr><td>Malware Family</td><td><code>{family}</code></td></tr>
      <tr><td>Analysis Duration</td><td>{ms} ms</td></tr>
      <tr><td>Tags</td><td>{tags}</td></tr>
      <tr><td>Indicators</td><td>{ind_count}</td></tr>
      <tr><td>IOCs</td><td>{ioc_count}</td></tr>
      <tr><td>ATT&amp;CK Techniques</td><td>{ttp_count}</td></tr>
    </tbody>
  </table>
  </div>
</div>
"#,
            sample = html_escape(&report.sample),
            sha = html_escape(&report.sha256),
            vc = vc,
            verdict = report.verdict,
            score = report.score,
            sbc = sbc,
            family = html_escape(&report.family),
            ms = report.analysis_ms,
            tags = tags_html,
            ind_count = report.indicators.len(),
            ioc_count = report.iocs.len(),
            ttp_count = report.attack.techniques.len(),
        );
    }

    fn render_behavior_section(out: &mut String, report: &SandboxReport) {
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Behavioral Analysis</div>\n");

        if !report.behaviors.is_empty() {
            out.push_str("<h3 style=\"margin-bottom:0.5rem;color:#457b9d\">Observed Behaviors</h3>\n");
            out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Severity</th><th>Category</th><th>APIs Involved</th></tr></thead><tbody>\n");
            for b in &report.behaviors {
                let sev_cls = Self::sev_class(&b.severity);
                let _ = writeln!(
                    out,
                    "<tr><td><strong>{}</strong><br><small style=\"color:#666\">{}</small></td>\
                     <td><span class=\"sev {}\">{}</span></td>\
                     <td>{}</td>\
                     <td><code>{}</code></td></tr>",
                    html_escape(&b.name),
                    html_escape(&b.desc),
                    sev_cls, b.severity,
                    html_escape(&b.category),
                    html_escape(&b.apis.join(", ")),
                );
            }
            out.push_str("</tbody></table></div>\n");
        }

        if !report.indicators.is_empty() {
            out.push_str("<h3 style=\"margin-top:1rem;margin-bottom:0.5rem;color:#457b9d\">Indicators</h3>\n");
            out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Severity</th><th>Name</th><th>Category</th><th>Description</th><th>Techniques</th></tr></thead><tbody>\n");
            for ind in &report.indicators {
                let sev_cls = Self::sev_class(&ind.severity);
                let techs = ind.technique_ids.join(", ");
                let _ = writeln!(
                    out,
                    "<tr><td><span class=\"sev {}\">{}</span></td>\
                     <td><strong>{}</strong></td>\
                     <td>{}</td>\
                     <td>{}</td>\
                     <td>{}</td></tr>",
                    sev_cls, ind.severity,
                    html_escape(&ind.name),
                    html_escape(&ind.category.to_string()),
                    html_escape(&ind.desc),
                    html_escape(&techs),
                );
            }
            out.push_str("</tbody></table></div>\n");
        }

        out.push_str("</div>\n");
    }

    fn render_timeline_section(&self, out: &mut String) {
        if self.timeline.is_empty() {
            return;
        }
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Execution Timeline</div>\n");
        out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Time (ms)</th><th>PID</th><th>Category</th><th>Event</th><th>Severity</th></tr></thead><tbody>\n");
        let mut sorted = self.timeline.clone();
        sorted.sort_by_key(|e| e.timestamp_ms);
        for ev in &sorted {
            let sev_cls = Self::sev_class(&ev.severity);
            let _ = writeln!(
                out,
                "<tr><td>+{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"sev {}\">{}</span></td></tr>",
                ev.timestamp_ms,
                ev.pid,
                html_escape(&ev.category),
                html_escape(&ev.description),
                sev_cls, ev.severity,
            );
        }
        out.push_str("</tbody></table></div>\n</div>\n");
    }

    fn render_ioc_section(&self, out: &mut String, report: &SandboxReport) {
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Indicators of Compromise</div>\n");

        if !report.iocs.is_empty() {
            out.push_str("<h3 style=\"margin-bottom:0.5rem;color:#457b9d\">Classified IOCs</h3>\n");
            out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Context</th></tr></thead><tbody>\n");
            for ioc in report.iocs.iocs.iter().take(self.opts.max_iocs_per_table) {
                let conf_bar = format!(
                    "<div style=\"background:#e9ecef;border-radius:999px;height:8px;width:80px\"><div style=\"width:{}%;height:100%;border-radius:999px;background:#1d3557\"></div></div>",
                    ioc.confidence
                );
                let _ = writeln!(
                    out,
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}% {}</td><td>{}</td></tr>",
                    html_escape(&ioc.kind.to_string()),
                    html_escape(&ioc.value),
                    ioc.confidence,
                    conf_bar,
                    html_escape(&ioc.context),
                );
            }
            out.push_str("</tbody></table></div>\n");
        }

        if let Some(extra) = self.extra_iocs.as_ref().filter(|c| !c.is_empty()) {
            out.push_str("<h3 style=\"margin-top:1rem;margin-bottom:0.5rem;color:#457b9d\">Extracted IOC Collection</h3>\n");
            self.render_ioc_collection_table(out, extra);
        }

        if report.iocs.is_empty() && self.extra_iocs.as_ref().is_none_or(IocCollection::is_empty) {
            out.push_str("<p><em>No IOCs extracted from this sample.</em></p>\n");
        }

        out.push_str("</div>\n");
    }

    fn render_ioc_collection_table(&self, out: &mut String, collection: &IocCollection) {
        out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Category</th><th>Values</th></tr></thead><tbody>\n");
        let sections: &[(&str, &[String])] = &[
            ("IP Addresses", &collection.ips),
            ("Domains", &collection.domains),
            ("URLs", &collection.urls),
            ("File Paths", &collection.file_paths),
            ("File Hashes", &collection.hashes),
            ("Registry Keys", &collection.registry_keys),
            ("Mutexes", &collection.mutexes),
            ("Bitcoin Addresses", &collection.btc_addresses),
        ];
        for (label, values) in sections {
            if !values.is_empty() {
                let vals = values.iter()
                    .take(self.opts.max_iocs_per_table)
                    .map(|v| format!("<code>{}</code>", html_escape(v)))
                    .collect::<Vec<_>>()
                    .join("<br>");
                let _ = writeln!(out, "<tr><td><strong>{label}</strong></td><td>{vals}</td></tr>");
            }
        }
        out.push_str("</tbody></table></div>\n");
    }

    fn render_attack_section(&self, out: &mut String, report: &SandboxReport) {
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">MITRE ATT&amp;CK Mapping</div>\n");

        if report.attack.techniques.is_empty() {
            if let Some(map) = self.ttp_map.as_ref().filter(|m| !m.is_empty()) {
                Self::render_ttp_override_map(out, map);
                out.push_str("</div>\n");
                return;
            }
            out.push_str("<p><em>No ATT&amp;CK techniques mapped for this sample.</em></p>\n");
        } else {
            out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>\n");
            for t in &report.attack.techniques {
                let conf_pct = t.confidence;
                let mut evidence_html = String::new();
                for e in &t.evidence {
                    let _ = write!(evidence_html, "<li>{}</li>", html_escape(e));
                }
                let _ = writeln!(
                    out,
                    "<tr>\
                      <td><a href=\"https://attack.mitre.org/techniques/{}\" target=\"_blank\" rel=\"noopener\"><code>{}</code></a></td>\
                      <td>{}</td>\
                      <td><code>{}</code></td>\
                      <td>{}%</td>\
                      <td><ul style=\"margin:0;padding-left:1rem;font-size:0.82rem\">{}</ul></td>\
                    </tr>",
                    html_escape(t.full_id()),
                    html_escape(t.full_id()),
                    html_escape(&t.name),
                    html_escape(&t.tactic.to_string()),
                    conf_pct,
                    evidence_html,
                );
            }
            out.push_str("</tbody></table></div>\n");
        }

        out.push_str("</div>\n");
    }

    fn render_ttp_override_map(out: &mut String, map: &HashMap<String, Vec<String>>) {
        out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Technique ID</th><th>Evidence</th></tr></thead><tbody>\n");
        let mut ids: Vec<&String> = map.keys().collect();
        ids.sort();
        for id in ids {
            let mut evidence = String::new();
            for e in &map[id] {
                let _ = write!(evidence, "<li>{}</li>", html_escape(e));
            }
            let _ = writeln!(
                out,
                "<tr><td><code>{}</code></td><td><ul style=\"margin:0;padding-left:1rem\">{}</ul></td></tr>",
                html_escape(id),
                evidence,
            );
        }
        out.push_str("</tbody></table></div>\n");
    }

    fn render_dropped_files(&self, out: &mut String, report: &SandboxReport) {
        let dropped: Vec<String> = {
            let mut v: Vec<String> = self.extra_iocs.as_ref()
                .map(|c| c.file_paths.clone())
                .unwrap_or_default();
            v.extend(report.iocs.by_kind(&IocKind::FilePath).iter().map(|i| i.value.clone()));
            v
        };
        if dropped.is_empty() {
            return;
        }
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Dropped Files</div>\n");
        out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>File Path</th></tr></thead><tbody>\n");
        for path in &dropped {
            let _ = writeln!(out, "<tr><td><code>{}</code></td></tr>", html_escape(path));
        }
        out.push_str("</tbody></table></div>\n</div>\n");
    }

    fn render_network_iocs(&self, out: &mut String, report: &SandboxReport) {
        let ips: Vec<&str> = report.iocs.by_kind(&IocKind::Ip).iter()
            .map(|i| i.value.as_str())
            .collect();
        let domains: Vec<&str> = report.iocs.by_kind(&IocKind::Domain).iter()
            .map(|i| i.value.as_str())
            .collect();
        let urls: Vec<&str> = report.iocs.by_kind(&IocKind::Url).iter()
            .map(|i| i.value.as_str())
            .collect();

        if ips.is_empty() && domains.is_empty() && urls.is_empty() {
            return;
        }

        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Network IOCs</div>\n");
        out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>\n");

        for ip in &ips {
            let _ = writeln!(out, "<tr><td>IP</td><td><code>{}</code></td></tr>", html_escape(ip));
        }
        for d in &domains {
            let _ = writeln!(out, "<tr><td>Domain</td><td><code>{}</code></td></tr>", html_escape(d));
        }
        for u in &urls {
            let _ = writeln!(out, "<tr><td>URL</td><td><code>{}</code></td></tr>", html_escape(u));
        }

        if let Some(extra) = &self.extra_iocs {
            for ip in &extra.ips {
                let _ = writeln!(out, "<tr><td>IP</td><td><code>{}</code></td></tr>", html_escape(ip));
            }
            for d in &extra.domains {
                let _ = writeln!(out, "<tr><td>Domain</td><td><code>{}</code></td></tr>", html_escape(d));
            }
            for u in &extra.urls {
                let _ = writeln!(out, "<tr><td>URL</td><td><code>{}</code></td></tr>", html_escape(u));
            }
        }

        out.push_str("</tbody></table></div>\n</div>\n");
    }

    fn render_sections(out: &mut String, report: &SandboxReport) {
        for sec in &report.sections {
            let _ = write!(
                out,
                "<div class=\"section\">\n<div class=\"section-title\">{}</div>\n<p>{}</p>\n</div>\n",
                html_escape(&sec.title),
                html_escape(&sec.content),
            );
        }
    }

    fn render_screenshots(&self, out: &mut String) {
        out.push_str("<div class=\"section\">\n<div class=\"section-title\">Screenshots</div>\n");
        out.push_str("<div style=\"display:flex;flex-wrap:wrap;gap:0.5rem\">\n");
        for ss in &self.screenshots {
            out.push_str(&ss.to_html_figure());
        }
        out.push_str("</div>\n</div>\n");
    }

    fn render_footer(out: &mut String, report: &SandboxReport) {
        let _ = write!(
            out,
            r#"<div class="report-footer">
  Generated by RustRE Sandbox Analysis Platform &nbsp;|&nbsp;
  Sample: <code>{}</code> &nbsp;|&nbsp;
  Analysis duration: {} ms
</div>
</div>
"#,
            html_escape(&report.sha256),
            report.analysis_ms,
        );
    }

    #[must_use]
    const fn sev_class(s: &Severity) -> &'static str {
        match s {
            Severity::Info => "sev-info",
            Severity::Low => "sev-low",
            Severity::Medium => "sev-medium",
            Severity::High => "sev-high",
            Severity::Critical => "sev-critical",
        }
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── HtmlReportBuilder ────────────────────────────────────────────────────────

/// Fluent builder for constructing an `HtmlReporter` and rendering a report.
pub struct HtmlReportBuilder {
    reporter: HtmlReporter,
    report: Option<SandboxReport>,
}

impl HtmlReportBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self { reporter: HtmlReporter::new(), report: None }
    }

    #[must_use]
    pub fn report(mut self, r: SandboxReport) -> Self {
        self.report = Some(r);
        self
    }

    #[must_use]
    pub fn theme(mut self, theme: HtmlTheme) -> Self {
        self.reporter = self.reporter.with_theme(theme);
        self
    }

    #[must_use]
    pub fn options(mut self, opts: HtmlReportOptions) -> Self {
        self.reporter = self.reporter.with_options(opts);
        self
    }

    #[must_use]
    pub fn screenshots(mut self, ss: Vec<ScreenshotEntry>) -> Self {
        self.reporter = self.reporter.with_screenshots(ss);
        self
    }

    #[must_use]
    pub fn timeline(mut self, events: Vec<TimelineEvent>) -> Self {
        self.reporter = self.reporter.with_timeline(events);
        self
    }

    #[must_use]
    pub fn ioc_collection(mut self, iocs: IocCollection) -> Self {
        self.reporter = self.reporter.with_ioc_collection(iocs);
        self
    }

    #[must_use]
    pub fn ttp_map(mut self, map: HashMap<String, Vec<String>>) -> Self {
        self.reporter = self.reporter.with_ttp_map(map);
        self
    }

    /// Build and render the report to HTML.
    ///
    /// # Panics
    /// Panics if [`HtmlReportBuilder::report`] was not called before building.
    #[must_use]
    pub fn build(self) -> String {
        let report = self.report.expect("HtmlReportBuilder: report not set");
        self.reporter.render(&report)
    }
}

impl Default for HtmlReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Public helpers wiring crate-level types into the HTML rendering API ──────

/// Render an HTML `<span>` with severity classification for a timeline event.
///
/// Exposes [`TimelineEvent::severity_class`] in the public API so external
/// callers can produce consistent severity markup outside of full report rendering.
#[must_use]
pub fn render_timeline_event_badge(event: &TimelineEvent) -> String {
    format!(
        "<span class=\"{cls}\">{desc}</span>",
        cls = event.severity_class(),
        desc = html_escape(&event.description),
    )
}

/// Render a behavior summary fragment as an HTML `<li>` element.
#[must_use]
pub fn render_behavior_li(behavior: &Behavior) -> String {
    format!(
        "<li><strong>{name}</strong>: {desc}</li>",
        name = html_escape(&behavior.name),
        desc = html_escape(&behavior.desc),
    )
}

/// Render an [`Indicator`] as a compact HTML fragment.
#[must_use]
pub fn render_indicator_fragment(indicator: &Indicator) -> String {
    format!(
        "<span class=\"indicator\">{name}</span>",
        name = html_escape(&indicator.name),
    )
}

/// Render an IOC set summary line (count of values) as HTML.
#[must_use]
pub fn render_ioc_set_summary(kind: &IocKind, set: &IocSet) -> String {
    format!(
        "<div class=\"ioc-set\">{kind:?}: {n} values</div>",
        n = set.iocs.len(),
    )
}

/// Render an [`AttackMapping`] as an HTML fragment with the linked technique.
#[must_use]
pub fn render_attack_mapping(mapping: &AttackMapping, technique: &AttackTechnique) -> String {
    format!(
        "<div class=\"attack-mapping\"><code>{tid}</code> {tname} (confidence: {conf}, total: {total})</div>",
        tid = html_escape(&technique.id),
        tname = html_escape(&technique.name),
        conf = technique.confidence,
        total = mapping.techniques.len(),
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    #[test]
    fn test_html_reporter_basic() {
        let report = SandboxReport::mock();
        let html = HtmlReporter::new().render(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("malware.exe"));
        assert!(html.contains("malicious"));
    }

    #[test]
    fn test_html_reporter_with_theme() {
        let theme = HtmlTheme {
            primary_color: "#ff0000".to_string(),
            ..HtmlTheme::default()
        };
        let report = SandboxReport::mock();
        let html = HtmlReporter::new().with_theme(theme).render(&report);
        assert!(html.contains("#ff0000"));
    }

    #[test]
    fn test_html_reporter_with_timeline() {
        let events = vec![
            TimelineEvent::new(100, 1234, "network", "DNS query to c2server.evil", Severity::High),
            TimelineEvent::new(200, 1234, "injection", "WriteProcessMemory called", Severity::Critical),
        ];
        let report = SandboxReport::mock();
        let html = HtmlReporter::new().with_timeline(events).render(&report);
        assert!(html.contains("c2server.evil"));
        assert!(html.contains("WriteProcessMemory"));
    }

    #[test]
    fn test_html_reporter_with_ioc_collection() {
        let iocs = IocCollection::mock();
        let report = SandboxReport::mock();
        let html = HtmlReporter::new().with_ioc_collection(iocs).render(&report);
        assert!(html.contains("185.220.101.1"));
    }

    #[test]
    fn test_builder_pattern() {
        let report = SandboxReport::mock();
        let html = HtmlReportBuilder::new()
            .report(report)
            .build();
        assert!(html.contains("malware.exe"));
    }

    #[test]
    fn test_screenshot_figure() {
        let ss = ScreenshotEntry::new(500, "aGVsbG8=", "Login dialog");
        let fig = ss.to_html_figure();
        assert!(fig.contains("data:image/png;base64,aGVsbG8="));
        assert!(fig.contains("T+500ms"));
    }

    #[test]
    fn test_theme_css_contains_font() {
        let t = HtmlTheme::default();
        let css = t.to_css();
        assert!(css.contains("Segoe UI"));
    }
}
