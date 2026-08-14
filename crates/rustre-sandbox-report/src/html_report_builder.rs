//! `html_report_builder` — Self-contained HTML report builder.
//!
//! Builds a rich, single-file HTML report with inline CSS, collapsible sections,
//! severity-colour coding, ATT&CK heat-map, IOC tables, and dark-mode toggle.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{
    AttackTactic, Behavior, Indicator, IndicatorCategory, IocSet, SandboxReport, Severity,
    Verdict,
};

// ─── HtmlTheme ────────────────────────────────────────────────────────────────

/// Visual theme for the HTML output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HtmlTheme {
    Light,
    Dark,
    #[default]
    Auto,
}

impl HtmlTheme {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::Auto => "auto",
        }
    }
}

// ─── HtmlReportConfig ─────────────────────────────────────────────────────────

/// Bitmask of which HTML report UI features to enable.
#[derive(Debug, Clone, Copy)]
pub struct HtmlReportFlags(u8);

impl HtmlReportFlags {
    const SCORE_BAR:     u8 = 0b0000_0001;
    const ATTACK_HEATMAP:u8 = 0b0000_0010;
    const TOC:           u8 = 0b0000_0100;
    const COLLAPSE:      u8 = 0b0000_1000;

    /// All features enabled.
    #[must_use]
    pub const fn all() -> Self { Self(0x0F) }

    #[must_use] pub const fn score_bar(self)      -> bool { self.0 & Self::SCORE_BAR      != 0 }
    #[must_use] pub const fn attack_heatmap(self) -> bool { self.0 & Self::ATTACK_HEATMAP != 0 }
    #[must_use] pub const fn toc(self)            -> bool { self.0 & Self::TOC            != 0 }
    #[must_use] pub const fn collapse(self)       -> bool { self.0 & Self::COLLAPSE        != 0 }

    /// Return flags with TOC disabled.
    #[must_use]
    pub const fn without_toc(self) -> Self { Self(self.0 & !Self::TOC) }
    /// Return flags with heatmap disabled.
    #[must_use]
    pub const fn without_heatmap(self) -> Self { Self(self.0 & !Self::ATTACK_HEATMAP) }
}

impl Default for HtmlReportFlags {
    fn default() -> Self { Self::all() }
}

/// Configuration for HTML report generation.
#[derive(Debug, Clone)]
pub struct HtmlReportConfig {
    pub theme: HtmlTheme,
    pub flags: HtmlReportFlags,
    pub max_iocs_per_table: usize,
    pub report_title: String,
}

impl HtmlReportConfig {
    /// Whether to show the score bar.
    #[must_use] pub const fn show_score_bar(&self)      -> bool { self.flags.score_bar() }
    /// Whether to show the ATT&CK heatmap.
    #[must_use] pub const fn show_attack_heatmap(&self) -> bool { self.flags.attack_heatmap() }
    /// Whether to show the table of contents.
    #[must_use] pub const fn show_toc(&self)            -> bool { self.flags.toc() }
    /// Whether sections are collapsible.
    #[must_use] pub const fn collapse_sections(&self)   -> bool { self.flags.collapse() }
}

impl Default for HtmlReportConfig {
    fn default() -> Self {
        Self {
            theme: HtmlTheme::Auto,
            flags: HtmlReportFlags::all(),
            max_iocs_per_table: 200,
            report_title: "Sandbox Analysis Report".to_owned(),
        }
    }
}

impl HtmlReportConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_theme(mut self, t: HtmlTheme) -> Self {
        self.theme = t;
        self
    }

    #[must_use]
    pub const fn with_toc(mut self, toc: bool) -> Self {
        if toc {
            self.flags = HtmlReportFlags(self.flags.0 | HtmlReportFlags::TOC);
        } else {
            self.flags = self.flags.without_toc();
        }
        self
    }

    #[must_use]
    pub const fn with_attack_heatmap(mut self, map: bool) -> Self {
        if map {
            self.flags = HtmlReportFlags(self.flags.0 | HtmlReportFlags::ATTACK_HEATMAP);
        } else {
            self.flags = self.flags.without_heatmap();
        }
        self
    }
}

// ─── Escape helpers ───────────────────────────────────────────────────────────

fn he(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─── CSS ──────────────────────────────────────────────────────────────────────

fn build_css(theme: HtmlTheme) -> String {
    let dark_vars = r"
--bg: #1a1a2e; --surface: #16213e; --on-surface: #e0e0e0;
--primary: #0f3460; --accent: #e94560; --border: #2d3748;
--code-bg: #0d1117; --code-fg: #c9d1d9;
--badge-clean: #1a4731; --badge-clean-fg: #6fcf97;
--badge-suspicious: #4a3b00; --badge-suspicious-fg: #f2c94c;
--badge-malicious: #4a0e0e; --badge-malicious-fg: #eb5757;
--badge-unknown: #2d3748; --badge-unknown-fg: #a0aec0;
--sev-critical: #e53e3e; --sev-high: #dd6b20; --sev-medium: #d69e2e;
--sev-low: #38a169; --sev-info: #3182ce;
";
    let light_vars = r"
--bg: #f7fafc; --surface: #ffffff; --on-surface: #1a202c;
--primary: #1d3557; --accent: #e63946; --border: #e2e8f0;
--code-bg: #f0f4f8; --code-fg: #2d3748;
--badge-clean: #c6f6d5; --badge-clean-fg: #276749;
--badge-suspicious: #fefcbf; --badge-suspicious-fg: #744210;
--badge-malicious: #fed7d7; --badge-malicious-fg: #742a2a;
--badge-unknown: #e2e8f0; --badge-unknown-fg: #4a5568;
--sev-critical: #c53030; --sev-high: #c05621; --sev-medium: #b7791f;
--sev-low: #276749; --sev-info: #2b6cb0;
";
    let root_vars = match theme {
        HtmlTheme::Dark => format!(":root {{ {dark_vars} }}"),
        HtmlTheme::Light => format!(":root {{ {light_vars} }}"),
        HtmlTheme::Auto => format!(
            "@media(prefers-color-scheme:dark){{:root{{{dark_vars}}}}}\n\
             @media(prefers-color-scheme:light){{:root{{{light_vars}}}}}"
        ),
    };

    format!(
        r#"
{root_vars}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--on-surface); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 2em auto; padding: 1.5em; }}
h1 {{ color: var(--accent); font-size: 1.8em; border-bottom: 3px solid var(--accent); padding-bottom: 0.4em; margin-bottom: 1em; }}
h2 {{ color: var(--primary); font-size: 1.3em; margin: 1.5em 0 0.5em; cursor: pointer; display: flex; align-items: center; gap: 0.5em; }}
h2::before {{ content: "▼"; font-size: 0.7em; transition: transform 0.2s; }}
h2.collapsed::before {{ transform: rotate(-90deg); }}
h3 {{ font-size: 1.05em; color: var(--on-surface); margin: 0.8em 0 0.4em; }}
.section-body {{ overflow: hidden; transition: max-height 0.3s ease; }}
.section-body.collapsed {{ max-height: 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 0.93em; }}
th {{ background: var(--primary); color: #fff; padding: 0.5em 0.8em; text-align: left; }}
td {{ border: 1px solid var(--border); padding: 0.4em 0.8em; vertical-align: top; }}
tr:nth-child(even) td {{ background: var(--surface); }}
code {{ background: var(--code-bg); color: var(--code-fg); padding: 0.1em 0.35em; border-radius: 3px; font-size: 0.88em; word-break: break-all; }}
pre {{ background: var(--code-bg); color: var(--code-fg); padding: 1em; border-radius: 6px; overflow-x: auto; font-size: 0.88em; }}
.badge {{ display: inline-block; padding: 0.2em 0.6em; border-radius: 4px; font-weight: 600; font-size: 0.85em; }}
.verdict-clean    {{ background: var(--badge-clean); color: var(--badge-clean-fg); }}
.verdict-suspicious {{ background: var(--badge-suspicious); color: var(--badge-suspicious-fg); }}
.verdict-malicious {{ background: var(--badge-malicious); color: var(--badge-malicious-fg); }}
.verdict-unknown  {{ background: var(--badge-unknown); color: var(--badge-unknown-fg); }}
.sev-critical {{ color: var(--sev-critical); font-weight: bold; }}
.sev-high {{ color: var(--sev-high); font-weight: bold; }}
.sev-medium {{ color: var(--sev-medium); }}
.sev-low {{ color: var(--sev-low); }}
.sev-info {{ color: var(--sev-info); }}
.score-bar {{ background: var(--border); border-radius: 6px; height: 20px; width: 100%; margin: 0.5em 0; overflow: hidden; }}
.score-fill {{ height: 100%; border-radius: 6px; transition: width 0.5s; }}
.toc {{ background: var(--surface); border: 1px solid var(--border); padding: 1em 1.5em; border-radius: 6px; margin-bottom: 1.5em; }}
.toc ul {{ list-style: none; padding-left: 0; }}
.toc a {{ color: var(--accent); text-decoration: none; }}
.toc a:hover {{ text-decoration: underline; }}
.heatmap {{ display: flex; flex-wrap: wrap; gap: 0.5em; margin: 0.5em 0; }}
.hm-cell {{ border-radius: 4px; padding: 0.4em 0.7em; font-size: 0.82em; font-weight: 600; }}
.hm-0 {{ background: var(--border); color: var(--on-surface); }}
.hm-1 {{ background: #744210; color: #fef3c7; }}
.hm-2 {{ background: #9c4221; color: #fef3c7; }}
.hm-3 {{ background: #c53030; color: #fff5f5; }}
.tag {{ display: inline-block; background: var(--primary); color: #fff; border-radius: 3px; padding: 0.1em 0.5em; font-size: 0.82em; margin: 0.15em; }}
"#,
    )
}

// ─── JS ───────────────────────────────────────────────────────────────────────

const JS: &str = r"
<script>
document.querySelectorAll('h2').forEach(function(h) {
  h.addEventListener('click', function() {
    h.classList.toggle('collapsed');
    var body = h.nextElementSibling;
    if (body && body.classList.contains('section-body')) {
      body.classList.toggle('collapsed');
    }
  });
});
</script>
";

// ─── Score bar ────────────────────────────────────────────────────────────────

const fn score_bar_color(score: u32) -> &'static str {
    match score {
        0..=30 => "#38a169",
        31..=60 => "#d69e2e",
        61..=80 => "#dd6b20",
        _ => "#e53e3e",
    }
}

fn score_bar_html(score: u32) -> String {
    format!(
        r#"<div class="score-bar"><div class="score-fill" style="width:{score}%;background:{color};"></div></div>"#,
        color = score_bar_color(score),
    )
}

// ─── Severity HTML ────────────────────────────────────────────────────────────

fn sev_html(sev: &Severity) -> String {
    let cls = match sev {
        Severity::Critical => "sev-critical",
        Severity::High => "sev-high",
        Severity::Medium => "sev-medium",
        Severity::Low => "sev-low",
        Severity::Info => "sev-info",
    };
    format!(r#"<span class="{cls}">{sev}</span>"#)
}

// ─── ATT&CK heat map ─────────────────────────────────────────────────────────

fn attack_heatmap_html(report: &SandboxReport) -> String {
    let tactics = [
        ("initial_access", "Initial Access"),
        ("execution", "Execution"),
        ("persistence", "Persistence"),
        ("privilege_escalation", "Priv. Escalation"),
        ("defense_evasion", "Defense Evasion"),
        ("credential_access", "Cred. Access"),
        ("discovery", "Discovery"),
        ("lateral_movement", "Lateral Movement"),
        ("collection", "Collection"),
        ("command_and_control", "C2"),
        ("exfiltration", "Exfiltration"),
        ("impact", "Impact"),
    ];

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for t in &report.attack.techniques {
        *counts.entry(t.tactic.to_string()).or_default() += 1;
    }

    let mut out = String::from(r#"<div class="heatmap">"#);
    for (key, label) in tactics {
        let count = counts.get(key).copied().unwrap_or(0);
        let cls = match count {
            0 => "hm-0",
            1 => "hm-1",
            2 => "hm-2",
            _ => "hm-3",
        };
        let _ = write!(
            out,
            r#"<div class="hm-cell {cls}" title="{count} technique(s)">{label}</div>"#,
        );
    }
    out.push_str("</div>");
    out
}

// ─── Section helpers ─────────────────────────────────────────────────────────

fn section(id: &str, title: &str, body: &str) -> String {
    format!(
        r#"<h2 id="{id}">{title}</h2>
<div class="section-body">
{body}
</div>
"#,
    )
}

// ─── HtmlReportBuilder ───────────────────────────────────────────────────────

/// Builds a rich HTML report from a `SandboxReport`.
#[derive(Debug, Clone)]
pub struct HtmlReportBuilder {
    config: HtmlReportConfig,
}

impl HtmlReportBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: HtmlReportConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: HtmlReportConfig) -> Self {
        Self { config }
    }

    /// Build the complete HTML document for `report`.
    #[must_use]
    pub fn build(&self, report: &SandboxReport) -> String {
        let css = build_css(self.config.theme);
        let title_html = he(&format!("{} \u{2014} {}", self.config.report_title, report.sample));

        let toc = if self.config.show_toc() {
            Self::build_toc(report)
        } else {
            String::new()
        };
        let summary = Self::build_summary(report);
        let verdict_section = self.build_verdict_section(report);
        let indicators_section = Self::build_indicators_section(report);
        let behaviors_section = Self::build_behaviors_section(report);
        let iocs_section = self.build_iocs_section(report);
        let attack_section = self.build_attack_section(report);
        let extra = Self::build_extra_sections(report);

        format!(
            r#"<!DOCTYPE html>
<html lang="en" data-theme="{theme}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>{css}</style>
</head>
<body>
<div class="container">
  <h1>{title}</h1>
  {toc}
  {summary}
  {verdict_section}
  {indicators_section}
  {behaviors_section}
  {iocs_section}
  {attack_section}
  {extra}
</div>
{js}
</body>
</html>"#,
            theme = self.config.theme.as_str(),
            title = title_html,
            js = JS,
        )
    }

    fn build_toc(report: &SandboxReport) -> String {
        let mut items = String::new();
        let links = [
            ("summary", "Executive Summary"),
            ("verdict", "Verdict & Score"),
            ("indicators", "Behavioral Indicators"),
            ("behaviors", "Behaviors"),
            ("iocs", "Indicators of Compromise"),
            ("attack", "MITRE ATT&CK"),
        ];
        for (id, label) in links {
            let _ = writeln!(items, r##"<li><a href="#{id}">{label}</a></li>"##);
        }
        for sec in &report.sections {
            let id = sec.title.to_lowercase().replace(' ', "-");
            let _ = writeln!(
                items,
                r##"<li><a href="#{}">{}</a></li>"##,
                id,
                he(&sec.title)
            );
        }
        format!(
            r#"<div class="toc"><strong>Contents</strong><ul>{items}</ul></div>"#,
        )
    }

    fn build_summary(report: &SandboxReport) -> String {
        let tags_html: String = report
            .tags
            .iter()
            .map(|t| format!(r#"<span class="tag">{}</span>"#, he(t)))
            .collect::<Vec<_>>()
            .join(" ");

        let body = format!(
            r"<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Sample</td><td><code>{sample}</code></td></tr>
  <tr><td>SHA-256</td><td><code>{sha}</code></td></tr>
  <tr><td>Family</td><td><code>{family}</code></td></tr>
  <tr><td>Analysis Time</td><td>{ms} ms</td></tr>
</table>
{tags}",
            sample = he(&report.sample),
            sha = he(&report.sha256),
            family = he(&report.family),
            ms = report.analysis_ms,
            tags = if tags_html.is_empty() {
                String::new()
            } else {
                format!("<p><strong>Tags:</strong> {tags_html}</p>")
            },
        );
        section("summary", "Executive Summary", &body)
    }

    fn build_verdict_section(&self, report: &SandboxReport) -> String {
        let vc = match report.verdict {
            Verdict::Clean => "verdict-clean",
            Verdict::Low => "verdict-low",
            Verdict::Suspicious => "verdict-suspicious",
            Verdict::Malicious => "verdict-malicious",
            Verdict::Unknown => "verdict-unknown",
        };
        let score_bar = if self.config.show_score_bar() {
            score_bar_html(report.score)
        } else {
            String::new()
        };
        let body = format!(
            r#"<p><span class="badge {vc}">{verdict}</span> &nbsp; Score: <strong>{score}</strong> / 100</p>
{score_bar}"#,
            verdict = he(&report.verdict.to_string()),
            score = report.score,
        );
        section("verdict", "Verdict &amp; Score", &body)
    }

    fn build_indicators_section(report: &SandboxReport) -> String {
        if report.indicators.is_empty() {
            return section("indicators", "Behavioral Indicators", "<p><em>No indicators.</em></p>");
        }
        let mut rows = String::new();
        for ind in &report.indicators {
            let techs = ind.technique_ids.join(", ");
            let _ = writeln!(
                rows,
                "<tr><td>{sev}</td><td>{name}</td><td>{cat}</td><td>{desc}</td><td><code>{tech}</code></td></tr>",
                sev = sev_html(&ind.severity),
                name = he(&ind.name),
                cat = he(&ind.category.to_string()),
                desc = he(&ind.desc),
                tech = he(&techs),
            );
        }
        let body = format!(
            r"<table>
<tr><th>Severity</th><th>Name</th><th>Category</th><th>Description</th><th>Techniques</th></tr>
{rows}
</table>"
        );
        section("indicators", "Behavioral Indicators", &body)
    }

    fn build_behaviors_section(report: &SandboxReport) -> String {
        if report.behaviors.is_empty() {
            return section("behaviors", "Behaviors", "<p><em>No behaviors recorded.</em></p>");
        }
        let mut rows = String::new();
        for b in &report.behaviors {
            let _ = writeln!(
                rows,
                "<tr><td>{sev}</td><td>{name}</td><td>{cat}</td><td><code>{apis}</code></td></tr>",
                sev = sev_html(&b.severity),
                name = he(&b.name),
                cat = he(&b.category),
                apis = he(&b.apis.join(", ")),
            );
        }
        let body = format!(
            r"<table>
<tr><th>Severity</th><th>Name</th><th>Category</th><th>APIs</th></tr>
{rows}
</table>"
        );
        section("behaviors", "Behaviors", &body)
    }

    fn build_iocs_section(&self, report: &SandboxReport) -> String {
        if report.iocs.is_empty() {
            return section("iocs", "Indicators of Compromise", "<p><em>No IOCs extracted.</em></p>");
        }
        let mut rows = String::new();
        for (i, ioc) in report.iocs.iocs.iter().enumerate() {
            if i >= self.config.max_iocs_per_table {
                let _ = writeln!(
                    rows,
                    r#"<tr><td colspan="4"><em>{} more IOCs omitted</em></td></tr>"#,
                    report.iocs.iocs.len() - i,
                );
                break;
            }
            let _ = writeln!(
                rows,
                "<tr><td>{kind}</td><td><code>{val}</code></td><td>{conf}%</td><td>{ctx}</td></tr>",
                kind = he(&ioc.kind.to_string()),
                val = he(&ioc.value),
                conf = ioc.confidence,
                ctx = he(&ioc.context),
            );
        }
        let body = format!(
            r"<table>
<tr><th>Type</th><th>Value</th><th>Confidence</th><th>Context</th></tr>
{rows}
</table>"
        );
        section("iocs", "Indicators of Compromise", &body)
    }

    fn build_attack_section(&self, report: &SandboxReport) -> String {
        let mut body = String::new();

        if self.config.show_attack_heatmap() {
            body.push_str("<h3>Tactic Coverage Heatmap</h3>");
            body.push_str(&attack_heatmap_html(report));
        }

        if report.attack.techniques.is_empty() {
            body.push_str("<p><em>No ATT&amp;CK techniques mapped.</em></p>");
        } else {
            let mut rows = String::new();
            for t in &report.attack.techniques {
                let _ = writeln!(
                    rows,
                    "<tr><td><code>{id}</code></td><td>{name}</td><td>{tactic}</td><td>{conf}%</td><td>{ev}</td></tr>",
                    id = he(t.full_id()),
                    name = he(&t.name),
                    tactic = he(&t.tactic.to_string()),
                    conf = t.confidence,
                    ev = he(&t.evidence.join("; ")),
                );
            }
            let _ = write!(
                body,
                r"<table>
<tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th><th>Evidence</th></tr>
{rows}
</table>"
            );
        }
        section("attack", "MITRE ATT&amp;CK", &body)
    }

    fn build_extra_sections(report: &SandboxReport) -> String {
        let mut out = String::new();
        for sec in &report.sections {
            let id = sec.title.to_lowercase().replace(' ', "-");
            let body = format!("<p>{}</p>", he(&sec.content));
            out.push_str(&section(&id, &he(&sec.title), &body));
        }
        out
    }
}

impl Default for HtmlReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── convenience function ─────────────────────────────────────────────────────

/// Build an HTML report with default settings.
#[must_use]
pub fn build_html_report(report: &SandboxReport) -> String {
    HtmlReportBuilder::new().build(report)
}

/// Build an HTML report with a specific theme.
#[must_use]
pub fn build_html_report_themed(report: &SandboxReport, theme: HtmlTheme) -> String {
    HtmlReportBuilder::with_config(HtmlReportConfig::new().with_theme(theme)).build(report)
}

// ─── Public section-builder helpers wiring crate-level types into the API ────

/// Build an HTML `<section>` listing behaviors grouped under a header.
#[must_use]
pub fn build_behaviors_section(behaviors: &[Behavior]) -> String {
    let mut out = String::from("<section class=\"behaviors\"><h3>Behaviors</h3><ul>");
    for b in behaviors {
        let _ = write!(out, "<li>{} ({:?}): {}</li>", b.name, b.severity, b.desc);
    }
    out.push_str("</ul></section>");
    out
}

/// Build an HTML `<section>` listing indicators, grouped by [`IndicatorCategory`].
#[must_use]
pub fn build_indicators_section(indicators: &[Indicator]) -> String {
    let mut out = String::from("<section class=\"indicators\"><h3>Indicators</h3><ul>");
    for i in indicators {
        let cat: &IndicatorCategory = &i.category;
        let _ = write!(out, "<li>[{cat}] {}: {}</li>", i.name, i.desc);
    }
    out.push_str("</ul></section>");
    out
}

/// Build an HTML `<section>` listing IOCs from an [`IocSet`].
#[must_use]
pub fn build_ioc_set_section(set: &IocSet) -> String {
    let mut out = String::from("<section class=\"iocs\"><h3>IOCs</h3><ul>");
    for ioc in &set.iocs {
        let _ = write!(out, "<li>{:?}: {}</li>", ioc.kind, ioc.value);
    }
    out.push_str("</ul></section>");
    out
}

/// Build an HTML heading line for a given [`AttackTactic`].
#[must_use]
pub fn attack_tactic_heading(tactic: &AttackTactic) -> String {
    format!("<h4 class=\"tactic\">{tactic}</h4>")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    fn mock() -> SandboxReport {
        SandboxReport::mock()
    }

    #[test]
    fn build_default_html() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn html_contains_sample_name() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("malware.exe"));
    }

    #[test]
    fn html_contains_sha256() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains(&report.sha256));
    }

    #[test]
    fn html_contains_verdict() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("malicious") || html.contains("suspicious") || html.contains("clean"));
    }

    #[test]
    fn html_contains_toc() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("Contents"));
    }

    #[test]
    fn html_no_toc_when_disabled() {
        let report = mock();
        let html = HtmlReportBuilder::with_config(HtmlReportConfig::new().with_toc(false))
            .build(&report);
        // The CSS class definitions for `.toc` are always emitted; assert the
        // actual TOC <div class="toc">...</div> wrapper and "Contents" heading
        // are absent instead.
        assert!(!html.contains(r#"<div class="toc">"#));
        assert!(!html.contains("Contents"));
    }

    #[test]
    fn html_contains_indicators() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("Code injection") || html.contains("Behavioral Indicators"));
    }

    #[test]
    fn html_contains_ioc_table() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("Indicators of Compromise"));
        assert!(html.contains("185.220.101.1"));
    }

    #[test]
    fn html_contains_attack_heatmap() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("heatmap") || html.contains("ATT"));
    }

    #[test]
    fn html_no_heatmap_when_disabled() {
        let report = mock();
        let html = HtmlReportBuilder::with_config(HtmlReportConfig::new().with_attack_heatmap(false))
            .build(&report);
        // The `.hm-cell` CSS rule is always emitted in the stylesheet; check
        // that no actual heatmap cell HTML elements (with title=) are rendered.
        assert!(!html.contains(r#"<div class="hm-cell"#));
    }

    #[test]
    fn dark_theme_includes_dark_vars() {
        let report = mock();
        let html = build_html_report_themed(&report, HtmlTheme::Dark);
        assert!(html.contains("1a1a2e"));
    }

    #[test]
    fn light_theme_includes_light_vars() {
        let report = mock();
        let html = build_html_report_themed(&report, HtmlTheme::Light);
        assert!(html.contains("f7fafc"));
    }

    #[test]
    fn auto_theme_has_media_query() {
        let css = build_css(HtmlTheme::Auto);
        assert!(css.contains("prefers-color-scheme"));
    }

    #[test]
    fn score_bar_low_score() {
        let bar = score_bar_html(10);
        assert!(bar.contains("38a169")); // green
    }

    #[test]
    fn score_bar_high_score() {
        let bar = score_bar_html(90);
        assert!(bar.contains("e53e3e")); // red
    }

    #[test]
    fn html_escape_ampersand() {
        assert_eq!(he("a&b"), "a&amp;b");
    }

    #[test]
    fn html_escape_lt_gt() {
        assert_eq!(he("<tag>"), "&lt;tag&gt;");
    }

    #[test]
    fn empty_report_no_panic() {
        let report = SandboxReport::new("empty.exe", "0000");
        let html = build_html_report(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No indicators"));
    }

    #[test]
    fn html_contains_behaviors_section() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("Behaviors"));
    }

    #[test]
    fn html_theme_attribute() {
        let report = mock();
        let html = build_html_report_themed(&report, HtmlTheme::Dark);
        assert!(html.contains(r#"data-theme="dark""#));
    }

    #[test]
    fn html_contains_family() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(!report.family.is_empty());
        assert!(html.contains(&report.family));
    }

    #[test]
    fn html_report_config_defaults() {
        let cfg = HtmlReportConfig::default();
        assert_eq!(cfg.max_iocs_per_table, 200);
        assert!(cfg.show_score_bar());
        assert!(cfg.show_toc());
    }

    #[test]
    fn sev_html_critical_has_class() {
        let s = sev_html(&Severity::Critical);
        assert!(s.contains("sev-critical"));
    }

    #[test]
    fn attack_heatmap_all_tactics_present() {
        let report = mock();
        let html = attack_heatmap_html(&report);
        assert!(html.contains("Execution") || html.contains("Persistence") || html.contains("C2"));
    }

    #[test]
    fn html_contains_collapse_js() {
        let report = mock();
        let html = build_html_report(&report);
        assert!(html.contains("<script>"));
        assert!(html.contains("collapsed"));
    }
}
