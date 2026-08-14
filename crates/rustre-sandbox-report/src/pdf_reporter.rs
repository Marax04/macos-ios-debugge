/// PDF-like text report: formatted text output with sections, tables, headers.
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

use crate::{
    IocCollection, IocKind, SandboxReport, Severity, Verdict,
};

// ─── TextWidth / Layout ──────────────────────────────────────────────────────

/// Page/column width in characters.
const DEFAULT_WIDTH: usize = 100;

/// Separator styles.
#[derive(Debug, Clone, Copy)]
pub enum SeparatorStyle {
    Heavy,     // ═══
    Light,     // ───
    Dashed,    // - - -
    Double,    // ══════
    Star,      // *****
}

impl SeparatorStyle {
    #[must_use]
    pub const fn char(self) -> char {
        match self {
            Self::Heavy => '═',
            Self::Light => '─',
            Self::Dashed => '-',
            Self::Double => '=',
            Self::Star => '*',
        }
    }

    fn make(self, width: usize) -> String {
        std::iter::repeat_n(self.char(), width).collect()
    }
}

// ─── TextReportOptions ────────────────────────────────────────────────────────

/// Bitmask controlling which sections appear in a text report.
///
/// Each bit maps to a section:
/// `HEADER_BOX | TOC | INDICATORS | BEHAVIORS | IOCS | ATTACK | DROPPED | SECTIONS`.
#[derive(Debug, Clone, Copy)]
pub struct TextSectionFlags(u8);

impl TextSectionFlags {
    const HEADER_BOX:  u8 = 0b0000_0001;
    const TOC:         u8 = 0b0000_0010;
    const INDICATORS:  u8 = 0b0000_0100;
    const BEHAVIORS:   u8 = 0b0000_1000;
    const IOCS:        u8 = 0b0001_0000;
    const ATTACK:      u8 = 0b0010_0000;
    const DROPPED:     u8 = 0b0100_0000;
    const SECTIONS:    u8 = 0b1000_0000;

    /// All sections enabled.
    #[must_use]
    pub const fn all() -> Self { Self(0xFF) }
    /// No sections.
    #[must_use]
    pub const fn none() -> Self { Self(0) }

    #[must_use] pub const fn header_box(self) -> bool { self.0 & Self::HEADER_BOX != 0 }
    #[must_use] pub const fn toc(self) -> bool        { self.0 & Self::TOC        != 0 }
    #[must_use] pub const fn indicators(self) -> bool { self.0 & Self::INDICATORS != 0 }
    #[must_use] pub const fn behaviors(self) -> bool  { self.0 & Self::BEHAVIORS  != 0 }
    #[must_use] pub const fn iocs(self) -> bool       { self.0 & Self::IOCS       != 0 }
    #[must_use] pub const fn attack(self) -> bool     { self.0 & Self::ATTACK     != 0 }
    #[must_use] pub const fn dropped(self) -> bool    { self.0 & Self::DROPPED    != 0 }
    #[must_use] pub const fn sections(self) -> bool   { self.0 & Self::SECTIONS   != 0 }

    /// Return a copy with the `toc` bit toggled off.
    #[must_use]
    pub const fn without_toc(self) -> Self { Self(self.0 & !Self::TOC) }
}

impl Default for TextSectionFlags {
    fn default() -> Self { Self::all() }
}

/// Controls layout of the text report.
#[derive(Debug, Clone)]
pub struct TextReportOptions {
    pub page_width: usize,
    /// Which sections to render.
    pub sections: TextSectionFlags,
    pub monospace_tables: bool,
}

impl TextReportOptions {
    /// Convenience accessor.
    #[must_use]
    pub const fn include_header_box(&self) -> bool { self.sections.header_box() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_toc(&self) -> bool { self.sections.toc() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_indicators(&self) -> bool { self.sections.indicators() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_behaviors(&self) -> bool { self.sections.behaviors() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_iocs(&self) -> bool { self.sections.iocs() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_attack(&self) -> bool { self.sections.attack() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_dropped(&self) -> bool { self.sections.dropped() }
    /// Convenience accessor.
    #[must_use]
    pub const fn include_sections(&self) -> bool { self.sections.sections() }
}

impl Default for TextReportOptions {
    fn default() -> Self {
        Self {
            page_width: DEFAULT_WIDTH,
            sections: TextSectionFlags::default(),
            monospace_tables: true,
        }
    }
}

// ─── Column descriptor ────────────────────────────────────────────────────────

/// A column in a text table.
#[derive(Debug, Clone)]
struct Column {
    header: String,
    width: usize,
    left_align: bool,
}

impl Column {
    fn new(header: impl Into<String>, width: usize) -> Self {
        Self { header: header.into(), width, left_align: true }
    }

    #[must_use]
    pub const fn right(mut self) -> Self { self.left_align = false; self }

    fn format(&self, s: &str) -> String {
        let s = if s.chars().count() > self.width {
            let mut truncated: String = s.chars().take(self.width.saturating_sub(1)).collect();
            truncated.push('…');
            truncated
        } else {
            s.to_owned()
        };
        if self.left_align {
            format!("{:<width$}", s, width = self.width)
        } else {
            format!("{:>width$}", s, width = self.width)
        }
    }
}

// ─── TextTable ────────────────────────────────────────────────────────────────

/// A simple ASCII/Unicode text table renderer.
struct TextTable {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
}

impl TextTable {
    const fn new(columns: Vec<Column>) -> Self {
        Self { columns, rows: Vec::new() }
    }

    fn add_row(&mut self, row: Vec<impl Into<String>>) {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    fn render(&self) -> String {
        let total_width: usize = self.columns.iter().map(|c| c.width).sum::<usize>()
            + self.columns.len() * 3
            + 1;

        let sep_light = SeparatorStyle::Light.make(total_width);
        let sep_heavy = SeparatorStyle::Heavy.make(total_width);

        let mut out = String::new();
        // Top border (heavy)
        let _ = writeln!(out, "{sep_heavy}");

        // Header row
        let _ = write!(out, "│");
        for col in &self.columns {
            let _ = write!(out, " {} │", col.format(&col.header));
        }
        out.push('\n');

        // Header separator (heavy under header)
        let _ = writeln!(out, "{sep_heavy}");

        // Data rows; insert a light separator every 5 rows for readability.
        for (i, row) in self.rows.iter().enumerate() {
            if i > 0 && i % 5 == 0 {
                let _ = writeln!(out, "{sep_light}");
            }
            let _ = write!(out, "│");
            for (j, col) in self.columns.iter().enumerate() {
                let cell = row.get(j).map_or("", String::as_str);
                let _ = write!(out, " {} │", col.format(cell));
            }
            out.push('\n');
        }

        // Bottom border (heavy)
        let _ = writeln!(out, "{sep_heavy}");
        out
    }
}

// ─── PdfTextReporter ──────────────────────────────────────────────────────────

/// Generates a plain-text "PDF-like" report with structured sections and tables.
pub struct PdfTextReporter {
    opts: TextReportOptions,
    extra_iocs: Option<IocCollection>,
}

impl PdfTextReporter {
    #[must_use]
    pub fn new() -> Self {
        Self { opts: TextReportOptions::default(), extra_iocs: None }
    }

    #[must_use]
    pub const fn with_options(mut self, opts: TextReportOptions) -> Self {
        self.opts = opts;
        self
    }

    #[must_use]
    pub fn with_ioc_collection(mut self, iocs: IocCollection) -> Self {
        self.extra_iocs = Some(iocs);
        self
    }

    /// Generate the full text report.
    #[must_use]
    pub fn render(&self, report: &SandboxReport) -> String {
        let mut out = String::with_capacity(32768);
        let w = self.opts.page_width;

        if self.opts.include_header_box() {
            Self::render_header_box(&mut out, report, w);
        }

        if self.opts.include_toc() {
            self.render_toc(&mut out, report, w);
        }

        Self::render_file_info(&mut out, report, w);

        if self.opts.include_sections() {
            for sec in &report.sections {
                Self::render_section_heading(&mut out, &sec.title, w);
                Self::wrap_paragraph(&mut out, &sec.content, w);
                out.push('\n');
            }
        }

        if self.opts.include_indicators() {
            Self::render_indicators(&mut out, report, w);
        }

        if self.opts.include_behaviors() {
            Self::render_behaviors(&mut out, report, w);
        }

        if self.opts.include_iocs() {
            self.render_iocs(&mut out, report, w);
        }

        if self.opts.include_attack() {
            Self::render_attack(&mut out, report, w);
        }

        if self.opts.include_dropped() {
            self.render_dropped(&mut out, report, w);
        }

        Self::render_footer(&mut out, report, w);
        out
    }

    fn center(s: &str, width: usize) -> String {
        let len = s.chars().count();
        if len >= width { return s.to_owned(); }
        let pad = (width - len) / 2;
        format!("{}{}{}", " ".repeat(pad), s, " ".repeat(width - len - pad))
    }

    fn render_header_box(out: &mut String, report: &SandboxReport, w: usize) {
        let heavy = SeparatorStyle::Heavy.make(w);
        let light = SeparatorStyle::Light.make(w);
        let verdict_label = match report.verdict {
            Verdict::Clean => "[CLEAN]",
            Verdict::Low => "[LOW]",
            Verdict::Suspicious => "[SUSPICIOUS]",
            Verdict::Malicious => "[MALICIOUS]",
            Verdict::Unknown => "[UNKNOWN]",
        };

        let _ = writeln!(out, "{heavy}");
        let _ = writeln!(out, "{}", Self::center("SANDBOX ANALYSIS REPORT", w));
        let _ = writeln!(out, "{}", Self::center("RustRE Analysis Platform", w));
        let _ = writeln!(out, "{light}");
        let _ = writeln!(out, "  Sample  : {}", report.sample);
        let _ = writeln!(out, "  SHA-256 : {}", report.sha256);
        let _ = writeln!(out, "  Verdict : {} (score: {}/100)", verdict_label, report.score);
        let _ = writeln!(out, "  Family  : {}", if report.family.is_empty() { "unknown" } else { &report.family });
        let _ = writeln!(out, "  Duration: {} ms", report.analysis_ms);
        if !report.tags.is_empty() {
            let _ = writeln!(out, "  Tags    : {}", report.tags.join(", "));
        }
        let _ = writeln!(out, "{heavy}");
        out.push('\n');
    }

    fn render_toc(&self, out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "TABLE OF CONTENTS", w);
        let mut idx = 1;
        let sections: &[&str] = &[
            "File Information",
        ];
        for s in sections {
            let dots_count = w.saturating_sub(s.len() + 6);
            let _ = writeln!(out, "  {idx}. {}{} ...", s, ".".repeat(dots_count.min(50)));
            idx += 1;
        }
        for sec in &report.sections {
            let dots_count = w.saturating_sub(sec.title.len() + 6);
            let _ = writeln!(out, "  {idx}. {}{} ...", sec.title, ".".repeat(dots_count.min(50)));
            idx += 1;
        }
        if self.opts.include_indicators() { let _ = writeln!(out, "  {idx}. Indicators "); idx += 1; }
        if self.opts.include_behaviors()  { let _ = writeln!(out, "  {idx}. Behaviors  "); idx += 1; }
        if self.opts.include_iocs()       { let _ = writeln!(out, "  {idx}. IOCs       "); idx += 1; }
        if self.opts.include_attack()     { let _ = writeln!(out, "  {idx}. ATT&CK     "); idx += 1; }
        if self.opts.include_dropped()    { let _ = writeln!(out, "  {idx}. Dropped    "); }
        out.push('\n');
    }

    fn render_file_info(out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "FILE INFORMATION", w);
        let mut table = TextTable::new(vec![
            Column::new("Property", 20),
            Column::new("Value", 70),
        ]);
        table.add_row(vec!["Sample Name", &report.sample]);
        table.add_row(vec!["SHA-256", &report.sha256]);
        table.add_row(vec!["Verdict", &format!("{} (score: {})", report.verdict, report.score)]);
        table.add_row(vec!["Family", &report.family]);
        table.add_row(vec!["Analysis Time", &format!("{} ms", report.analysis_ms)]);
        table.add_row(vec!["Tags", &report.tags.join(", ")]);
        table.add_row(vec!["Indicators", &report.indicators.len().to_string()]);
        table.add_row(vec!["IOCs", &report.iocs.len().to_string()]);
        table.add_row(vec!["Techniques", &report.attack.techniques.len().to_string()]);
        out.push_str(&table.render());
        out.push('\n');
    }

    fn render_indicators(out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "INDICATORS", w);
        if report.indicators.is_empty() {
            out.push_str("  No indicators found.\n\n");
            return;
        }
        let mut table = TextTable::new(vec![
            Column::new("Severity", 10),
            Column::new("Name", 30),
            Column::new("Category", 15),
            Column::new("Description", 38),
        ]);
        for ind in &report.indicators {
            table.add_row(vec![
                ind.severity.to_string().to_uppercase(),
                ind.name.clone(),
                ind.category.to_string(),
                ind.desc.clone(),
            ]);
        }
        out.push_str(&table.render());
        out.push('\n');
    }

    fn render_behaviors(out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "BEHAVIORAL ANALYSIS", w);
        if report.behaviors.is_empty() {
            out.push_str("  No behaviors recorded.\n\n");
            return;
        }
        let mut table = TextTable::new(vec![
            Column::new("Name", 25),
            Column::new("Severity", 10),
            Column::new("Category", 13),
            Column::new("APIs", 45),
        ]);
        for b in &report.behaviors {
            table.add_row(vec![
                b.name.clone(),
                b.severity.to_string().to_uppercase(),
                b.category.clone(),
                b.apis.join(", "),
            ]);
        }
        out.push_str(&table.render());
        out.push('\n');
    }

    fn render_iocs(&self, out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "INDICATORS OF COMPROMISE", w);

        if !report.iocs.is_empty() {
            let _ = writeln!(out, "  -- Classified IOCs --\n");
            let mut table = TextTable::new(vec![
                Column::new("Type", 14),
                Column::new("Value", 52),
                Column::new("Conf%", 6).right(),
            ]);
            for ioc in &report.iocs.iocs {
                table.add_row(vec![
                    ioc.kind.to_string().to_uppercase(),
                    ioc.value.clone(),
                    format!("{}%", ioc.confidence),
                ]);
            }
            out.push_str(&table.render());
            out.push('\n');
        }

        if let Some(extra) = self.extra_iocs.as_ref().filter(|c| !c.is_empty()) {
            let _ = writeln!(out, "  -- Extracted IOC Collection --\n");
            let summary = extra.summary_text();
            for line in summary.lines() {
                let _ = writeln!(out, "  {line}");
            }
            out.push('\n');
        }

        if report.iocs.is_empty() && self.extra_iocs.as_ref().is_none_or(IocCollection::is_empty) {
            out.push_str("  No IOCs extracted from this sample.\n\n");
        }
    }

    fn render_attack(out: &mut String, report: &SandboxReport, w: usize) {
        Self::render_section_heading(out, "MITRE ATT&CK MAPPING", w);
        if report.attack.techniques.is_empty() {
            out.push_str("  No ATT&CK techniques mapped.\n\n");
            return;
        }
        let tactics = report.attack.tactics_present();
        let _ = writeln!(out, "  Tactics covered: {}", tactics.join(", "));
        out.push('\n');

        let mut table = TextTable::new(vec![
            Column::new("ID", 14),
            Column::new("Name", 42),
            Column::new("Tactic", 20),
            Column::new("Conf%", 6).right(),
        ]);
        for t in &report.attack.techniques {
            table.add_row(vec![
                t.full_id().to_owned(),
                t.name.clone(),
                t.tactic.to_string().replace('_', " ").to_uppercase(),
                format!("{}%", t.confidence),
            ]);
        }
        out.push_str(&table.render());
        out.push('\n');
    }

    fn render_dropped(&self, out: &mut String, report: &SandboxReport, w: usize) {
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
        Self::render_section_heading(out, "DROPPED FILES", w);
        let mut table = TextTable::new(vec![Column::new("File Path", w - 6)]);
        for path in &dropped {
            table.add_row(vec![path.as_str()]);
        }
        out.push_str(&table.render());
        out.push('\n');
    }

    fn render_footer(out: &mut String, report: &SandboxReport, w: usize) {
        let sep = SeparatorStyle::Heavy.make(w);
        let _ = writeln!(out, "{sep}");
        let _ = writeln!(out, "{}", Self::center("END OF REPORT", w));
        let _ = writeln!(out, "{}", Self::center(
            &format!("Generated by RustRE Sandbox Analysis Platform | SHA-256: {}", &report.sha256[..16]),
            w,
        ));
        let _ = writeln!(out, "{sep}");
    }

    fn render_section_heading(out: &mut String, title: &str, w: usize) {
        let light = SeparatorStyle::Light.make(w);
        let _ = writeln!(out, "{light}");
        let _ = writeln!(out, "  {title}");
        let _ = writeln!(out, "{light}");
    }

    fn wrap_paragraph(out: &mut String, text: &str, w: usize) {
        let indent = "  ";
        let usable = w.saturating_sub(indent.len());
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut line_len = 0usize;
        let mut line = String::from(indent);
        for word in words {
            if line_len + word.len() + 1 > usable && line_len > 0 {
                out.push_str(&line);
                out.push('\n');
                line = String::from(indent);
                line_len = 0;
            }
            if line_len > 0 { line.push(' '); line_len += 1; }
            line.push_str(word);
            line_len += word.len();
        }
        if line_len > 0 {
            out.push_str(&line);
            out.push('\n');
        }
    }
}

impl Default for PdfTextReporter {
    fn default() -> Self { Self::new() }
}

// ─── PdfReportWriter ─────────────────────────────────────────────────────────

/// Writes a text report to a file or string, with pagination support.
pub struct PdfReportWriter {
    reporter: PdfTextReporter,
    page_separator: String,
    page_size: usize,
}

impl PdfReportWriter {
    #[must_use]
    pub fn new(reporter: PdfTextReporter) -> Self {
        Self {
            reporter,
            page_separator: "\n\n\x0c\n\n".to_string(), // form-feed
            page_size: 60,  // lines per page
        }
    }

    #[must_use]
    pub const fn page_size(mut self, n: usize) -> Self { self.page_size = n; self }

    /// Render and paginate the report.
    #[must_use]
    pub fn render_paginated(&self, report: &SandboxReport) -> Vec<String> {
        let full = self.reporter.render(report);
        let lines: Vec<&str> = full.lines().collect();
        let mut pages: Vec<String> = Vec::new();
        let mut current_page = String::new();

        for (line_count, line) in lines.into_iter().enumerate() {
            if line_count > 0 && line_count.is_multiple_of(self.page_size) {
                pages.push(current_page.clone());
                current_page.clear();
            }
            current_page.push_str(line);
            current_page.push('\n');
        }
        if !current_page.is_empty() {
            pages.push(current_page);
        }
        pages
    }

    /// Render all pages joined by the page separator.
    #[must_use]
    pub fn render(&self, report: &SandboxReport) -> String {
        self.render_paginated(report).join(&self.page_separator)
    }

    /// Write to a file.
    ///
    /// # Errors
    /// Returns `std::io::Error` on file write failure.
    pub fn write_to_file(&self, report: &SandboxReport, path: &std::path::Path) -> std::io::Result<()> {
        let content = self.render(report);
        std::fs::write(path, content)
    }
}

// ─── Public serializable summary types ────────────────────────────────────────

/// A serializable severity summary line included alongside the text report.
///
/// This is exposed so callers consuming text reports can persist a structured
/// header (JSON sidecar) describing what severity tier the report covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfSeveritySummary {
    pub label: String,
    pub severity: Severity,
    pub count: usize,
}

impl PdfSeveritySummary {
    #[must_use]
    pub fn new(label: impl Into<String>, severity: Severity, count: usize) -> Self {
        Self { label: label.into(), severity, count }
    }

    /// Render the summary as a single text line, suitable for inclusion at the
    /// top of a text report.
    #[must_use]
    pub fn to_line(&self) -> String {
        format!("[{:?}] {}: {}", self.severity, self.label, self.count)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    #[test]
    fn test_basic_render() {
        let report = SandboxReport::mock();
        let out = PdfTextReporter::new().render(&report);
        assert!(out.contains("SANDBOX ANALYSIS REPORT"));
        assert!(out.contains("malware.exe"));
        assert!(out.contains("MALICIOUS"));
    }

    #[test]
    fn test_contains_attack() {
        let report = SandboxReport::mock();
        let out = PdfTextReporter::new().render(&report);
        assert!(out.contains("ATT&CK"));
    }

    #[test]
    fn test_table_render() {
        let mut t = TextTable::new(vec![
            Column::new("Name", 10),
            Column::new("Value", 10),
        ]);
        t.add_row(vec!["foo", "bar"]);
        let rendered = t.render();
        assert!(rendered.contains("foo"));
        assert!(rendered.contains("bar"));
    }

    #[test]
    fn test_paginated_output() {
        let report = SandboxReport::mock();
        let reporter = PdfTextReporter::new();
        let writer = PdfReportWriter::new(reporter).page_size(10);
        let pages = writer.render_paginated(&report);
        assert!(!pages.is_empty());
    }

    #[test]
    fn test_center() {
        let s = PdfTextReporter::center("hello", 11);
        assert_eq!(s.len(), 11);
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_separator_style() {
        let s = SeparatorStyle::Heavy.make(5);
        assert_eq!(s, "═════");
    }

    #[test]
    fn test_column_truncate() {
        let col = Column::new("H", 5);
        let formatted = col.format("hello world");
        assert_eq!(formatted.chars().count(), 5);
    }

    #[test]
    fn test_no_toc() {
        let report = SandboxReport::mock();
        let opts = TextReportOptions { sections: TextSectionFlags::default().without_toc(), ..Default::default() };
        let out = PdfTextReporter::new().with_options(opts).render(&report);
        assert!(!out.contains("TABLE OF CONTENTS"));
    }
}
