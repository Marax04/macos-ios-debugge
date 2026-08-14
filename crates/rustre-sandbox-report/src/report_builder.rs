//! HTML report builder with Bootstrap-inspired inline CSS,
//! collapsible sections, severity badges, and structured report sections.

use std::fmt::Write as _;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    AttackMapping, AttackTactic, Behavior, Indicator, IndicatorCategory,
    IocSet, IocKind, SandboxReport, Severity, Verdict,
};

// ─── ReportSection enum ───────────────────────────────────────────────────────

/// The type of a report section, used to control rendering order and style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSectionKind {
    Executive,
    BehaviorSummary,
    NetworkActivity,
    FileSystemChanges,
    RegistryChanges,
    ProcessTree,
    Screenshots,
    IoCs,
    MitreMatrix,
    Custom(String),
}

impl std::fmt::Display for ReportSectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Executive => write!(f, "Executive Summary"),
            Self::BehaviorSummary => write!(f, "Behavior Summary"),
            Self::NetworkActivity => write!(f, "Network Activity"),
            Self::FileSystemChanges => write!(f, "File System Changes"),
            Self::RegistryChanges => write!(f, "Registry Changes"),
            Self::ProcessTree => write!(f, "Process Tree"),
            Self::Screenshots => write!(f, "Screenshots"),
            Self::IoCs => write!(f, "Indicators of Compromise"),
            Self::MitreMatrix => write!(f, "MITRE ATT&CK Matrix"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl ReportSectionKind {
    /// Default rendering order (lower = earlier in report).
    #[must_use]
    pub const fn default_order(&self) -> u32 {
        match self {
            Self::Executive => 1,
            Self::BehaviorSummary => 2,
            Self::NetworkActivity => 3,
            Self::FileSystemChanges => 4,
            Self::RegistryChanges => 5,
            Self::ProcessTree => 6,
            Self::Screenshots => 7,
            Self::IoCs => 8,
            Self::MitreMatrix => 9,
            Self::Custom(_) => 99,
        }
    }
}

// ─── ReportSectionContent ─────────────────────────────────────────────────────

/// Content for a single structured section of the HTML report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSectionContent {
    pub kind: ReportSectionKind,
    pub title: String,
    pub html_body: String,
    pub order: u32,
    pub collapsible: bool,
    pub collapsed_by_default: bool,
    pub icon: Option<String>,
}

impl ReportSectionContent {
    #[must_use]
    pub fn new(kind: ReportSectionKind, html_body: impl Into<String>) -> Self {
        let title = kind.to_string();
        let order = kind.default_order();
        Self {
            kind,
            title,
            html_body: html_body.into(),
            order,
            collapsible: true,
            collapsed_by_default: false,
            icon: None,
        }
    }

    #[must_use]
    pub fn with_title(mut self, t: impl Into<String>) -> Self {
        self.title = t.into();
        self
    }

    #[must_use]
    pub const fn collapsed(mut self) -> Self {
        self.collapsed_by_default = true;
        self
    }

    #[must_use]
    pub const fn not_collapsible(mut self) -> Self {
        self.collapsible = false;
        self
    }
}

// ─── SeverityBadge ────────────────────────────────────────────────────────────

/// Renders severity as an HTML badge.
pub struct SeverityBadge;

impl SeverityBadge {
    #[must_use]
    pub fn render(severity: &Severity) -> String {
        let (bg, text, label) = match severity {
            Severity::Critical => ("#721c24", "#f8d7da", "CRITICAL"),
            Severity::High => ("#856404", "#fff3cd", "HIGH"),
            Severity::Medium => ("#0c5460", "#d1ecf1", "MEDIUM"),
            Severity::Low => ("#155724", "#d4edda", "LOW"),
            Severity::Info => ("#383d41", "#e2e3e5", "INFO"),
        };
        format!(
            r#"<span style="background:{bg};color:{text};padding:2px 8px;border-radius:4px;font-size:0.85em;font-weight:bold;">{label}</span>"#
        )
    }

    #[must_use]
    pub fn render_verdict(verdict: &Verdict) -> String {
        let (bg, text, label) = match verdict {
            Verdict::Malicious => ("#721c24", "#f8d7da", "MALICIOUS"),
            Verdict::Suspicious => ("#856404", "#fff3cd", "SUSPICIOUS"),
            Verdict::Low => ("#0c5460", "#d1ecf1", "LOW"),
            Verdict::Clean => ("#155724", "#d4edda", "CLEAN"),
            Verdict::Unknown => ("#383d41", "#e2e3e5", "UNKNOWN"),
        };
        format!(
            r#"<span style="background:{bg};color:{text};padding:4px 14px;border-radius:6px;font-size:1.1em;font-weight:bold;">{label}</span>"#
        )
    }

    #[must_use]
    pub fn render_score(score: u32) -> String {
        let (bg, fg) = if score >= 75 {
            ("#721c24", "#f8d7da")
        } else if score >= 50 {
            ("#856404", "#fff3cd")
        } else if score >= 25 {
            ("#0c5460", "#d1ecf1")
        } else {
            ("#155724", "#d4edda")
        };
        format!(
            r#"<span style="background:{bg};color:{fg};padding:3px 10px;border-radius:12px;font-weight:bold;">{score}/100</span>"#
        )
    }
}

// ─── HtmlReportBuilder ────────────────────────────────────────────────────────

/// Builds a rich, standalone HTML report from a `SandboxReport`.
pub struct HtmlReportBuilder {
    report: SandboxReport,
    sections: Vec<ReportSectionContent>,
    extra_css: String,
    include_print_styles: bool,
    /// Network activity entries (if provided separately).
    network_entries: Vec<HashMap<String, String>>,
    /// File system change entries.
    fs_entries: Vec<HashMap<String, String>>,
    /// Registry change entries.
    reg_entries: Vec<HashMap<String, String>>,
    /// Process tree rows: (indent, pid, ppid, name, cmdline).
    process_rows: Vec<(u32, u32, u32, String, String)>,
    /// Screenshot paths/base64.
    screenshots: Vec<(String, String)>,
}

impl HtmlReportBuilder {
    /// Create a new builder from a `SandboxReport`.
    #[must_use]
    pub const fn new(report: SandboxReport) -> Self {
        Self {
            report,
            sections: Vec::new(),
            extra_css: String::new(),
            include_print_styles: false,
            network_entries: Vec::new(),
            fs_entries: Vec::new(),
            reg_entries: Vec::new(),
            process_rows: Vec::new(),
            screenshots: Vec::new(),
        }
    }

    /// Add a custom CSS block.
    #[must_use]
    pub fn with_css(mut self, css: impl Into<String>) -> Self {
        self.extra_css = css.into();
        self
    }

    /// Include print-friendly media query.
    #[must_use]
    pub const fn with_print_styles(mut self) -> Self {
        self.include_print_styles = true;
        self
    }

    /// Add network activity entries.
    pub fn add_network_entries(&mut self, entries: Vec<HashMap<String, String>>) {
        self.network_entries = entries;
    }

    /// Add file system change entries.
    pub fn add_fs_entries(&mut self, entries: Vec<HashMap<String, String>>) {
        self.fs_entries = entries;
    }

    /// Add registry change entries.
    pub fn add_reg_entries(&mut self, entries: Vec<HashMap<String, String>>) {
        self.reg_entries = entries;
    }

    /// Add process tree rows: (indent, pid, ppid, name, cmdline).
    pub fn add_process_rows(&mut self, rows: Vec<(u32, u32, u32, String, String)>) {
        self.process_rows = rows;
    }

    /// Add screenshots (`alt_text`, `src`).
    pub fn add_screenshots(&mut self, shots: Vec<(String, String)>) {
        self.screenshots = shots;
    }

    // ── Internal section builders ─────────────────────────────────────────────

    fn build_executive_section(&self) -> ReportSectionContent {
        let r = &self.report;
        let verdict_badge = SeverityBadge::render_verdict(&r.verdict);
        let score_badge = SeverityBadge::render_score(r.score);

        let family_display = if r.family.is_empty() { "Unknown".to_string() } else { esc(&r.family) };
        let tags_html: String = r.tags.iter()
            .map(|t| format!(r#"<span style="background:#e9ecef;padding:2px 6px;border-radius:3px;font-size:0.82em;margin:1px;">{}</span>"#, esc(t)))
            .collect::<Vec<_>>()
            .join(" ");

        let body = format!(r#"
<div style="display:grid;grid-template-columns:1fr 1fr;gap:1em;">
  <div>
    <table style="border-collapse:collapse;width:100%;">
      <tr><th style="text-align:left;padding:6px 10px;background:#343a40;color:#fff;">Property</th><th style="text-align:left;padding:6px 10px;background:#343a40;color:#fff;">Value</th></tr>
      <tr style="background:#f8f9fa;"><td style="padding:5px 10px;"><strong>Sample</strong></td><td><code>{sample}</code></td></tr>
      <tr><td style="padding:5px 10px;"><strong>SHA-256</strong></td><td><code style="font-size:0.82em;">{sha}</code></td></tr>
      <tr style="background:#f8f9fa;"><td style="padding:5px 10px;"><strong>Verdict</strong></td><td>{verdict_badge}</td></tr>
      <tr><td style="padding:5px 10px;"><strong>Threat Score</strong></td><td>{score_badge}</td></tr>
      <tr style="background:#f8f9fa;"><td style="padding:5px 10px;"><strong>Family</strong></td><td><code>{family}</code></td></tr>
      <tr><td style="padding:5px 10px;"><strong>Analysis Duration</strong></td><td>{ms} ms</td></tr>
    </table>
  </div>
  <div>
    <p><strong>Tags:</strong> {tags}</p>
    <p><strong>Indicators:</strong> {ind_count} ({critical_count} critical)</p>
    <p><strong>Techniques:</strong> {ttp_count}</p>
    <p><strong>IOCs:</strong> {ioc_count}</p>
  </div>
</div>"#,
            sample = esc(&r.sample),
            sha = esc(&r.sha256),
            verdict_badge = verdict_badge,
            score_badge = score_badge,
            family = family_display,
            ms = r.analysis_ms,
            tags = if tags_html.is_empty() { "<em>none</em>".to_string() } else { tags_html },
            ind_count = r.indicators.len(),
            critical_count = r.indicators.iter().filter(|i| i.severity == Severity::Critical).count(),
            ttp_count = r.attack.techniques.len(),
            ioc_count = r.iocs.len(),
        );
        ReportSectionContent::new(ReportSectionKind::Executive, body).not_collapsible()
    }

    fn build_behavior_section(&self) -> ReportSectionContent {
        let r = &self.report;

        let mut indicator_rows = String::new();
        for ind in &r.indicators {
            let bg = if ind.severity >= Severity::High { "style=\"background:#fff8f8;\"" } else { "" };
            let _ = write!(
                indicator_rows,
                "<tr {bg}><td style=\"padding:5px 10px;\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                SeverityBadge::render(&ind.severity),
                esc(&ind.name),
                esc(&ind.category.to_string()),
                esc(&ind.desc),
            );
        }

        let mut behavior_rows = String::new();
        for b in &r.behaviors {
            let _ = write!(
                behavior_rows,
                "<tr><td style=\"padding:5px 10px;\">{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                esc(&b.name),
                SeverityBadge::render(&b.severity),
                esc(&b.category),
                esc(&b.apis.join(", ")),
            );
        }

        let mut body = String::new();

        if indicator_rows.is_empty() {
            body.push_str("<p><em>No indicators found.</em></p>");
        } else {
            body.push_str("<h3 style=\"color:#1d3557;\">Indicators</h3>");
            body.push_str("<div style=\"overflow-x:auto;\"><table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Severity</th><th style=\"padding:6px 10px;\">Name</th><th style=\"padding:6px 10px;\">Category</th><th style=\"padding:6px 10px;\">Description</th></tr>");
            body.push_str(&indicator_rows);
            body.push_str("</table></div>");
        }

        if !behavior_rows.is_empty() {
            body.push_str("<h3 style=\"color:#1d3557;margin-top:1.5em;\">Observed Behaviors</h3>");
            body.push_str("<div style=\"overflow-x:auto;\"><table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Behavior</th><th style=\"padding:6px 10px;\">Severity</th><th style=\"padding:6px 10px;\">Category</th><th style=\"padding:6px 10px;\">APIs</th></tr>");
            body.push_str(&behavior_rows);
            body.push_str("</table></div>");
        }

        ReportSectionContent::new(ReportSectionKind::BehaviorSummary, body)
    }

    fn build_network_section(&self) -> ReportSectionContent {
        let mut body = String::new();
        if self.network_entries.is_empty() {
            // Extract from IOCs.
            let iocs = &self.report.iocs;
            let ips = iocs.by_kind(&IocKind::Ip);
            let domains = iocs.by_kind(&IocKind::Domain);
            let urls = iocs.by_kind(&IocKind::Url);

            if ips.is_empty() && domains.is_empty() && urls.is_empty() {
                body.push_str("<p><em>No network activity recorded.</em></p>");
            } else {
                body.push_str("<table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Type</th><th style=\"padding:6px 10px;\">Value</th><th style=\"padding:6px 10px;\">Confidence</th></tr>");
                for ioc in ips.iter().chain(domains.iter()).chain(urls.iter()) {
                    let _ = write!(body, 
                        "<tr><td style=\"padding:5px 10px;\">{}</td><td><code>{}</code></td><td>{}%</td></tr>",
                        esc(&ioc.kind.to_string()),
                        esc(&ioc.value),
                        ioc.confidence,
                    );
                }
                body.push_str("</table>");
            }
        } else {
            body.push_str("<table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">IP</th><th style=\"padding:6px 10px;\">Port</th><th style=\"padding:6px 10px;\">Proto</th><th style=\"padding:6px 10px;\">Bytes Sent</th><th style=\"padding:6px 10px;\">Bytes Recv</th></tr>");
            for row in &self.network_entries {
                let _ = write!(body,
                    "<tr><td style=\"padding:5px 10px;\"><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(row.get("ip").map_or("-", String::as_str)),
                    esc(row.get("port").map_or("-", String::as_str)),
                    esc(row.get("proto").map_or("-", String::as_str)),
                    esc(row.get("bytes_sent").map_or("0", String::as_str)),
                    esc(row.get("bytes_recv").map_or("0", String::as_str)),
                );
            }
            body.push_str("</table>");
        }
        ReportSectionContent::new(ReportSectionKind::NetworkActivity, body)
    }

    fn build_filesystem_section(&self) -> ReportSectionContent {
        let mut body = String::new();
        let file_iocs = self.report.iocs.by_kind(&IocKind::FilePath);

        if self.fs_entries.is_empty() && file_iocs.is_empty() {
            body.push_str("<p><em>No file system changes recorded.</em></p>");
        } else {
            body.push_str("<table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Path</th><th style=\"padding:6px 10px;\">Operation</th><th style=\"padding:6px 10px;\">Confidence</th></tr>");
            for row in &self.fs_entries {
                let _ = write!(body,
                    "<tr><td style=\"padding:5px 10px;\"><code>{}</code></td><td>{}</td><td>-</td></tr>",
                    esc(row.get("path").map_or("-", String::as_str)),
                    esc(row.get("operation").map_or("-", String::as_str)),
                );
            }
            for ioc in &file_iocs {
                let _ = write!(body, 
                    "<tr><td style=\"padding:5px 10px;\"><code>{}</code></td><td>dropped/modified</td><td>{}%</td></tr>",
                    esc(&ioc.value), ioc.confidence,
                );
            }
            body.push_str("</table>");
        }
        ReportSectionContent::new(ReportSectionKind::FileSystemChanges, body)
    }

    fn build_registry_section(&self) -> ReportSectionContent {
        let mut body = String::new();
        let reg_iocs = self.report.iocs.by_kind(&IocKind::RegistryKey);

        if self.reg_entries.is_empty() && reg_iocs.is_empty() {
            body.push_str("<p><em>No registry changes recorded.</em></p>");
        } else {
            body.push_str("<table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Key Path</th><th style=\"padding:6px 10px;\">Value</th><th style=\"padding:6px 10px;\">Operation</th></tr>");
            for row in &self.reg_entries {
                let _ = write!(body,
                    "<tr><td style=\"padding:5px 10px;\"><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    esc(row.get("key").map_or("-", String::as_str)),
                    esc(row.get("value").map_or("-", String::as_str)),
                    esc(row.get("operation").map_or("-", String::as_str)),
                );
            }
            for ioc in &reg_iocs {
                let _ = write!(body, 
                    "<tr><td style=\"padding:5px 10px;\"><code>{}</code></td><td>-</td><td>observed</td></tr>",
                    esc(&ioc.value),
                );
            }
            body.push_str("</table>");
        }
        ReportSectionContent::new(ReportSectionKind::RegistryChanges, body)
    }

    fn build_process_section(&self) -> ReportSectionContent {
        let mut body = String::new();
        if self.process_rows.is_empty() {
            body.push_str("<p><em>No process tree data available.</em></p>");
        } else {
            body.push_str("<table style=\"border-collapse:collapse;width:100%;font-family:monospace;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">PID</th><th style=\"padding:6px 10px;\">PPID</th><th style=\"padding:6px 10px;\">Name</th><th style=\"padding:6px 10px;\">Command Line</th></tr>");
            for (indent, pid, ppid, name, cmdline) in &self.process_rows {
                // Cap indent to avoid multi-GB allocation from attacker-controlled data.
                let prefix = "  ".repeat((*indent).min(64) as usize);
                let _ = write!(body, 
                    "<tr><td style=\"padding:5px 10px;\">{pid}</td><td>{ppid}</td><td><code>{prefix}{name}</code></td><td style=\"max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\"><code title=\"{cmdline_esc}\">{cmdline_short}</code></td></tr>",
                    pid = pid,
                    ppid = ppid,
                    prefix = esc(&prefix),
                    name = esc(name),
                    cmdline_esc = esc(cmdline),
                    cmdline_short = esc(cmdline.get(..80).unwrap_or(cmdline)),
                );
            }
            body.push_str("</table>");
        }
        ReportSectionContent::new(ReportSectionKind::ProcessTree, body)
    }

    fn build_screenshots_section(&self) -> ReportSectionContent {
        let mut body = String::new();
        if self.screenshots.is_empty() {
            body.push_str("<p><em>No screenshots available.</em></p>");
        } else {
            body.push_str("<div style=\"display:flex;flex-wrap:wrap;gap:1em;\">");
            for (alt, src) in &self.screenshots {
                let _ = write!(body, 
                    r#"<div style="border:1px solid #dee2e6;border-radius:4px;overflow:hidden;">
                       <img src="{src}" alt="{alt}" style="max-width:320px;display:block;" loading="lazy">
                       <p style="padding:4px;margin:0;font-size:0.82em;background:#f8f9fa;">{alt}</p>
                       </div>"#,
                    src = esc(src),
                    alt = esc(alt),
                );
            }
            body.push_str("</div>");
        }
        ReportSectionContent::new(ReportSectionKind::Screenshots, body).collapsed()
    }

    fn build_ioc_section(&self) -> ReportSectionContent {
        let iocs = &self.report.iocs;
        let mut body = String::new();

        if iocs.is_empty() {
            body.push_str("<p><em>No IOCs extracted.</em></p>");
        } else {
            body.push_str("<table style=\"border-collapse:collapse;width:100%;\"><tr style=\"background:#343a40;color:#fff;\"><th style=\"padding:6px 10px;\">Type</th><th style=\"padding:6px 10px;\">Value</th><th style=\"padding:6px 10px;\">Confidence</th><th style=\"padding:6px 10px;\">Context</th></tr>");
            for ioc in &iocs.iocs {
                let conf_badge = if ioc.confidence >= 90 {
                    format!(r#"<span style="color:#155724;font-weight:bold;">{}%</span>"#, ioc.confidence)
                } else if ioc.confidence >= 70 {
                    format!(r#"<span style="color:#856404;">{}%</span>"#, ioc.confidence)
                } else {
                    format!("{}%", ioc.confidence)
                };
                let _ = write!(body, 
                    "<tr><td style=\"padding:5px 10px;\">{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    esc(&ioc.kind.to_string()),
                    esc(&ioc.value),
                    conf_badge,
                    esc(&ioc.context),
                );
            }
            body.push_str("</table>");
        }
        ReportSectionContent::new(ReportSectionKind::IoCs, body)
    }

    fn build_mitre_section(&self) -> ReportSectionContent {
        let mapping = &self.report.attack;
        let mut body = String::new();

        if mapping.techniques.is_empty() {
            body.push_str("<p><em>No ATT&amp;CK techniques mapped.</em></p>");
        } else {
            // Group by tactic.
            let mut by_tactic: HashMap<String, Vec<_>> = HashMap::new();
            for t in &mapping.techniques {
                by_tactic
                    .entry(t.tactic.to_string())
                    .or_default()
                    .push(t);
            }
            let mut tactic_entries: Vec<(String, Vec<_>)> = by_tactic.into_iter().collect();
            tactic_entries.sort_by(|a, b| a.0.cmp(&b.0));

            for (tactic, techs) in &tactic_entries {
                let _ = write!(body, 
                    "<h4 style=\"color:#457b9d;margin-top:1em;text-transform:capitalize;\">{}</h4>",
                    esc(&tactic.replace('_', " "))
                );
                body.push_str("<ul style=\"margin:0;padding-left:1.5em;\">");
                for t in techs {
                    let conf_color = if t.confidence >= 80 { "#155724" } else { "#856404" };
                    let _ = write!(body, 
                        r#"<li style="margin-bottom:4px;"><code><a href="https://attack.mitre.org/techniques/{tid}/" target="_blank" style="text-decoration:none;color:#0d6efd;">{tid}</a></code> — <strong>{name}</strong> <span style="color:{conf_color};font-size:0.88em;">({conf}% confidence)</span></li>"#,
                        tid = esc(t.full_id()),
                        name = esc(&t.name),
                        conf = t.confidence,
                        conf_color = conf_color,
                    );
                }
                body.push_str("</ul>");
            }
        }
        ReportSectionContent::new(ReportSectionKind::MitreMatrix, body)
    }

    // ── Main build method ─────────────────────────────────────────────────────

    /// Build the complete HTML report as a self-contained string.
    #[must_use]
    pub fn build(&self) -> String {
        let r = &self.report;

        // Build all standard sections.
        let mut sections: Vec<ReportSectionContent> = vec![
            self.build_executive_section(),
            self.build_behavior_section(),
            self.build_network_section(),
            self.build_filesystem_section(),
            self.build_registry_section(),
            self.build_process_section(),
            self.build_screenshots_section(),
            self.build_ioc_section(),
            self.build_mitre_section(),
        ];

        // Add any extra custom sections.
        sections.extend(self.sections.iter().cloned());

        // Sort by order.
        sections.sort_by_key(|s| s.order);

        // Build section HTML.
        let mut sections_html = String::new();
        for (idx, sec) in sections.iter().enumerate() {
            let sec_id = format!("sec-{idx}");
            let toggle_js = if sec.collapsible {
                format!(r#" onclick="var b=document.getElementById('{sec_id}-body');b.style.display=(b.style.display==='none'?'block':'none');"#)
            } else {
                String::new()
            };
            let display = if sec.collapsed_by_default && sec.collapsible { "none" } else { "block" };
            let cursor = if sec.collapsible { "cursor:pointer;" } else { "" };
            let _ = write!(
                sections_html,
                r#"<div class="report-section" style="background:#fff;border-radius:6px;box-shadow:0 1px 4px #0001;margin-bottom:1.2em;">
  <div style="background:#1d3557;color:#fff;padding:0.6em 1em;border-radius:6px 6px 0 0;{cursor}"{toggle_js}>
    <strong>{title}</strong>
  </div>
  <div id="{sec_id}-body" style="padding:1em;display:{display};">
    {body}
  </div>
</div>"#,
                cursor = cursor,
                toggle_js = toggle_js,
                title = esc(&sec.title),
                sec_id = sec_id,
                display = display,
                body = sec.html_body,
            );
        }

        let print_styles = if self.include_print_styles {
            r"@media print { .report-section { page-break-inside: avoid; } }"
        } else {
            ""
        };

        let title = format!("Sandbox Report — {}", esc(&r.sample));

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
*{{box-sizing:border-box;}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#222;margin:0;padding:0;}}
.container{{max-width:1200px;margin:2em auto;padding:0 1em;}}
h1{{color:#1a1a2e;margin:0 0 0.5em 0;}}
h2,h3,h4{{color:#1d3557;}}
code{{background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.9em;}}
a{{color:#0d6efd;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #dee2e6;padding:4px 8px;text-align:left;font-size:0.88em;}}
tr:nth-child(even) td{{background:#f8f9fa;}}
{extra_css}
{print_styles}
  </style>
</head>
<body>
<div class="container">
  <h1>Sandbox Analysis Report</h1>
  <p style="color:#6c757d;font-size:0.9em;">Generated at report assembly time &middot; {sample}</p>
  {sections_html}
</div>
<script>/* Toggle collapsible sections via inline onclick handlers */</script>
</body>
</html>"#,
            title = title,
            sample = esc(&r.sample),
            extra_css = self.extra_css,
            print_styles = print_styles,
            sections_html = sections_html,
        )
    }

    /// Build a compact HTML summary fragment (no full `<html>` wrapper).
    #[must_use]
    pub fn build_fragment(&self) -> String {
        let r = &self.report;
        let verdict_badge = SeverityBadge::render_verdict(&r.verdict);
        let score_badge = SeverityBadge::render_score(r.score);

        format!(
            r"<div><strong>Sample:</strong> <code>{sample}</code> {verdict} {score} &middot; {ind} indicators, {ttp} TTPs</div>",
            sample = esc(&r.sample),
            verdict = verdict_badge,
            score = score_badge,
            ind = r.indicators.len(),
            ttp = r.attack.techniques.len(),
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─── Public report-section helpers wiring crate-level types into the API ─────

/// Render a [`Behavior`] as an HTML row for inclusion in a custom report section.
#[must_use]
pub fn behavior_row_html(b: &Behavior) -> String {
    format!(
        "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        b.severity, b.name, b.desc, b.category,
    )
}

/// Render an [`Indicator`] (categorised by [`IndicatorCategory`]) as an HTML row.
#[must_use]
pub fn indicator_row_html(i: &Indicator) -> String {
    let cat: &IndicatorCategory = &i.category;
    format!(
        "<tr><td>{cat}</td><td>{}</td><td>{}</td></tr>",
        i.name, i.desc,
    )
}

/// Render an [`AttackMapping`] grouped by [`AttackTactic`] as an HTML `<ul>`.
#[must_use]
pub fn attack_mapping_by_tactic_html(mapping: &AttackMapping, tactic: &AttackTactic) -> String {
    let mut out = String::from("<ul>");
    for t in mapping.by_tactic(tactic) {
        let _ = write!(out, "<li>{}: {}</li>", t.id, t.name);
    }
    out.push_str("</ul>");
    out
}

/// Render an [`IocSet`] section (by [`IocKind`]) as an HTML `<ul>`.
#[must_use]
pub fn ioc_set_section_html(kind: &IocKind, set: &IocSet) -> String {
    let mut out = format!("<h4>{kind:?}</h4><ul>");
    for ioc in &set.iocs {
        let _ = write!(out, "<li>{}</li>", ioc.value);
    }
    out.push_str("</ul>");
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    fn mock_report() -> SandboxReport {
        SandboxReport::mock()
    }

    #[test]
    fn test_build_returns_html() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<title>"));
    }

    #[test]
    fn test_build_contains_sample_name() {
        let report = mock_report();
        let sample = report.sample.clone();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        assert!(html.contains(&sample));
    }

    #[test]
    fn test_build_contains_verdict() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        // Verdict badge text should appear.
        assert!(html.contains("MALICIOUS") || html.contains("SUSPICIOUS") || html.contains("CLEAN"));
    }

    #[test]
    fn test_build_contains_mitre_section() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        assert!(html.contains("MITRE ATT&amp;CK"));
    }

    #[test]
    fn test_build_contains_ioc_section() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        assert!(html.contains("Indicators of Compromise"));
    }

    #[test]
    fn test_build_contains_sections() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let html = builder.build();
        assert!(html.contains("Behavior Summary"));
        assert!(html.contains("Network Activity"));
        assert!(html.contains("Registry Changes"));
    }

    #[test]
    fn test_build_fragment() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report);
        let frag = builder.build_fragment();
        assert!(frag.contains("Sample:"));
        assert!(frag.contains("indicators"));
    }

    #[test]
    fn test_severity_badge_critical() {
        let s = SeverityBadge::render(&Severity::Critical);
        assert!(s.contains("CRITICAL"));
    }

    #[test]
    fn test_severity_badge_all_levels() {
        for sev in [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
            let badge = SeverityBadge::render(&sev);
            assert!(badge.contains("<span"));
        }
    }

    #[test]
    fn test_verdict_badge_malicious() {
        let s = SeverityBadge::render_verdict(&Verdict::Malicious);
        assert!(s.contains("MALICIOUS"));
    }

    #[test]
    fn test_score_badge_high() {
        let s = SeverityBadge::render_score(85);
        assert!(s.contains("85/100"));
    }

    #[test]
    fn test_score_badge_low() {
        let s = SeverityBadge::render_score(10);
        assert!(s.contains("10/100"));
    }

    #[test]
    fn test_report_section_kind_order() {
        assert!(ReportSectionKind::Executive.default_order() < ReportSectionKind::MitreMatrix.default_order());
    }

    #[test]
    fn test_report_section_kind_display() {
        assert_eq!(ReportSectionKind::Executive.to_string(), "Executive Summary");
        assert_eq!(ReportSectionKind::IoCs.to_string(), "Indicators of Compromise");
    }

    #[test]
    fn test_esc_html() {
        assert_eq!(esc("<b>Hello & World</b>"), "&lt;b&gt;Hello &amp; World&lt;/b&gt;");
    }

    #[test]
    fn test_with_network_entries() {
        let report = mock_report();
        let mut builder = HtmlReportBuilder::new(report);
        let mut entry = HashMap::new();
        entry.insert("ip".to_string(), "185.220.101.1".to_string());
        entry.insert("port".to_string(), "443".to_string());
        entry.insert("proto".to_string(), "TCP".to_string());
        entry.insert("bytes_sent".to_string(), "512".to_string());
        entry.insert("bytes_recv".to_string(), "1024".to_string());
        builder.add_network_entries(vec![entry]);
        let html = builder.build();
        assert!(html.contains("185.220.101.1"));
    }

    #[test]
    fn test_with_process_rows() {
        let report = mock_report();
        let mut builder = HtmlReportBuilder::new(report);
        builder.add_process_rows(vec![
            (0, 1234, 0, "explorer.exe".to_string(), "C:\\Windows\\explorer.exe".to_string()),
            (1, 5678, 1234, "cmd.exe".to_string(), "cmd.exe /c whoami".to_string()),
        ]);
        let html = builder.build();
        assert!(html.contains("explorer.exe"));
        assert!(html.contains("cmd.exe"));
    }

    #[test]
    fn test_with_print_styles() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report).with_print_styles();
        let html = builder.build();
        assert!(html.contains("@media print"));
    }

    #[test]
    fn test_with_extra_css() {
        let report = mock_report();
        let builder = HtmlReportBuilder::new(report).with_css("body { color: red; }");
        let html = builder.build();
        assert!(html.contains("color: red;"));
    }

    #[test]
    fn test_collapsible_section() {
        let sec = ReportSectionContent::new(
            ReportSectionKind::Screenshots,
            "<p>screen</p>",
        ).collapsed();
        assert!(sec.collapsed_by_default);
        assert!(sec.collapsible);
    }

    #[test]
    fn test_not_collapsible() {
        let sec = ReportSectionContent::new(
            ReportSectionKind::Executive,
            "<p>exec</p>",
        ).not_collapsible();
        assert!(!sec.collapsible);
    }
}
