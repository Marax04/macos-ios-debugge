//! `pdf_export` — stub PDF report exporter.
//!
//! Produces a minimal, syntactically-valid PDF byte stream entirely in pure
//! Rust (no external PDF library required).  The output is a simple 1.4-level
//! PDF with plain-text content pages.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

// ─── PdfClassification ────────────────────────────────────────────────────────

/// Security classification banner for a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfClassification {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
    Internal,
}

impl std::fmt::Display for PdfClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclassified => write!(f, "UNCLASSIFIED"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Secret => write!(f, "SECRET"),
            Self::TopSecret => write!(f, "TOP SECRET"),
            Self::Internal => write!(f, "INTERNAL"),
        }
    }
}

// ─── PdfMetadata ─────────────────────────────────────────────────────────────

/// Document-level metadata embedded in the PDF info dictionary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfMetadata {
    /// Report title.
    pub title: String,
    /// Author or analyst name.
    pub author: String,
    /// Creation date (ISO-8601 string or YYYY-MM-DD).
    pub date: String,
    /// Security classification.
    pub classification: PdfClassification,
    /// Subject / short description.
    pub subject: String,
    /// Keywords.
    pub keywords: Vec<String>,
}

impl PdfMetadata {
    /// Create metadata with minimal required fields.
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        author: impl Into<String>,
        date: impl Into<String>,
        classification: PdfClassification,
    ) -> Self {
        Self {
            title: title.into(),
            author: author.into(),
            date: date.into(),
            classification,
            subject: String::new(),
            keywords: Vec::new(),
        }
    }

    /// Attach a subject line.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Attach keywords.
    #[must_use]
    pub fn with_keywords(mut self, kw: Vec<String>) -> Self {
        self.keywords = kw;
        self
    }
}

// ─── PdfSection ──────────────────────────────────────────────────────────────

/// A titled section within the PDF document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfSection {
    /// Section heading.
    pub title: String,
    /// Free-form text content.
    pub content: String,
    /// Optional page-break before this section.
    pub page_break: bool,
}

impl PdfSection {
    /// Create a section.
    #[must_use]
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            content: content.into(),
            page_break: false,
        }
    }

    /// Force a page break before this section.
    #[must_use]
    pub const fn with_page_break(mut self) -> Self {
        self.page_break = true;
        self
    }

    /// Total character count (title + content).
    #[must_use]
    pub const fn char_count(&self) -> usize {
        self.title.len() + self.content.len()
    }
}

// ─── PdfReport ───────────────────────────────────────────────────────────────

/// A complete PDF report composed of metadata and ordered sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfReport {
    pub metadata: PdfMetadata,
    pub sections: Vec<PdfSection>,
}

impl PdfReport {
    /// Create a new report with the given metadata.
    #[must_use]
    pub const fn new(metadata: PdfMetadata) -> Self {
        Self {
            metadata,
            sections: Vec::new(),
        }
    }

    /// Append a section.
    pub fn add_section(&mut self, section: PdfSection) {
        self.sections.push(section);
    }

    /// Number of sections.
    #[must_use]
    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Total character count across all section content.
    #[must_use]
    pub fn total_chars(&self) -> usize {
        self.sections.iter().map(PdfSection::char_count).sum()
    }
}

// ─── PdfExporter ─────────────────────────────────────────────────────────────

/// Produces a minimal valid PDF byte stream from a [`PdfReport`].
///
/// The generated PDF:
/// * Conforms to PDF 1.4 structure (header, body, cross-reference table, trailer).
/// * Embeds each section as a content stream on its own page.
/// * Uses only Helvetica (base-14 font — always available in PDF viewers).
/// * Contains no external resources or binary streams.
#[derive(Debug, Default)]
pub struct PdfExporter {
    /// Font size for body text (points).
    pub font_size: u8,
    /// Font size for section headings (points).
    pub heading_size: u8,
    /// Left/right margin in points (1 pt ≈ 0.353 mm).
    pub margin: u32,
    /// Page width in points (A4 = 595).
    pub page_width: u32,
    /// Page height in points (A4 = 842).
    pub page_height: u32,
}

impl PdfExporter {
    /// Create an exporter with A4 defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            font_size: 10,
            heading_size: 14,
            margin: 50,
            page_width: 595,
            page_height: 842,
        }
    }

    /// Produce the PDF byte stream for `report`.
    #[must_use]
    pub fn export(&self, report: &PdfReport) -> Vec<u8> {
        // We use a simple incremental object builder.
        let mut objects: Vec<(u32, String)> = Vec::new(); // (obj_id, obj_bytes)
        let mut obj_id: u32 = 1;

        let mut alloc = || {
            let id = obj_id;
            obj_id += 1;
            id
        };

        // ── Object IDs (pre-allocate) ─────────────────────────────────────
        let catalog_id = alloc();
        let pages_id = alloc();
        let font_id = alloc();
        let info_id = alloc();

        // Build section pages.
        // For the cover (title) page + each section we need (page_dict, content_stream).
        let page_count = 1 + report.sections.len(); // cover + sections
        let mut page_ids: Vec<u32> = Vec::new();
        let mut content_ids: Vec<u32> = Vec::new();
        for _ in 0..page_count {
            page_ids.push(alloc());
            content_ids.push(alloc());
        }

        // ── Font ─────────────────────────────────────────────────────────
        let font_obj = format!(
            "{font_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        );
        objects.push((font_id, font_obj));

        // ── Info dictionary ───────────────────────────────────────────────
        let meta = &report.metadata;
        let info_obj = format!(
            "{info_id} 0 obj\n<< /Title ({title})\n   /Author ({author})\n   /CreationDate (D:{date})\n   /Subject ({subject})\n   /Keywords ({kw})\n>>\nendobj\n",
            title = pdf_escape(&meta.title),
            author = pdf_escape(&meta.author),
            date = meta.date.replace('-', ""),
            subject = pdf_escape(&meta.subject),
            kw = pdf_escape(&meta.keywords.join("; ")),
        );
        objects.push((info_id, info_obj));

        // ── Content streams ───────────────────────────────────────────────
        // Cover page.
        let cover_stream = self.cover_page_stream(meta);
        let cover_content_obj = make_content_obj(content_ids[0], &cover_stream);
        objects.push((content_ids[0], cover_content_obj));

        // Section pages.
        for (i, section) in report.sections.iter().enumerate() {
            let stream = self.section_page_stream(section);
            let obj = make_content_obj(content_ids[i + 1], &stream);
            objects.push((content_ids[i + 1], obj));
        }

        // ── Page dictionaries ─────────────────────────────────────────────
        for (i, &pid) in page_ids.iter().enumerate() {
            let cid = content_ids[i];
            let page_obj = format!(
                "{pid} 0 obj\n<< /Type /Page\n   /Parent {pages_id} 0 R\n   /MediaBox [0 0 {w} {h}]\n   /Contents {cid} 0 R\n   /Resources << /Font << /F1 {font_id} 0 R >> >>\n>>\nendobj\n",
                w = self.page_width,
                h = self.page_height,
            );
            objects.push((pid, page_obj));
        }

        // ── Pages dictionary ──────────────────────────────────────────────
        let kids: String = page_ids
            .iter()
            .map(|id| format!("{id} 0 R"))
            .collect::<Vec<_>>()
            .join(" ");
        let pages_obj = format!(
            "{pages_id} 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {page_count} >>\nendobj\n"
        );
        objects.push((pages_id, pages_obj));

        // ── Catalog ───────────────────────────────────────────────────────
        let catalog_obj =
            format!("{catalog_id} 0 obj\n<< /Type /Catalog /Pages {pages_id} 0 R >>\nendobj\n");
        objects.push((catalog_id, catalog_obj));

        // ── Assemble file ─────────────────────────────────────────────────
        objects.sort_by_key(|(id, _)| *id);

        let header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec(); // standard binary comment
        let mut body = header;

        // Write objects and record byte offsets for xref.
        let mut offsets: HashMap<u32, usize> = HashMap::new();
        for (id, obj_text) in &objects {
            offsets.insert(*id, body.len());
            body.extend_from_slice(obj_text.as_bytes());
        }

        // ── Cross-reference table ─────────────────────────────────────────
        let xref_offset = body.len();
        let max_id = objects.iter().map(|(id, _)| *id).max().unwrap_or(0);
        let mut xref = format!("xref\n0 {}\n", max_id + 1);
        xref.push_str("0000000000 65535 f \n"); // entry 0
        for id in 1..=max_id {
            let off = offsets.get(&id).copied().unwrap_or(0);
            let _ = writeln!(xref, "{off:010} 00000 n ");
        }
        body.extend_from_slice(xref.as_bytes());

        // ── Trailer ───────────────────────────────────────────────────────
        let trailer = format!(
            "trailer\n<< /Size {sz} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            sz = max_id + 1,
        );
        body.extend_from_slice(trailer.as_bytes());
        body
    }

    // ── Stream builders ───────────────────────────────────────────────────

    fn cover_page_stream(&self, meta: &PdfMetadata) -> String {
        let title_y = self.page_height - self.margin - 80;
        let mut ops = String::new();
        ops.push_str("BT\n");
        // Classification banner
        let _ = write!(
            ops,
            "/F1 12 Tf\n{} {} Td\n({}) Tj\n",
            self.margin,
            self.page_height - self.margin + 10,
            pdf_escape(&format!("[{}]", meta.classification))
        );
        // Title
        let _ = write!(
            ops,
            "/F1 {} Tf\n{} {} Td\n({}) Tj\n",
            self.heading_size + 4,
            self.margin,
            title_y,
            pdf_escape(&meta.title)
        );
        // Author / date
        let _ = write!(
            ops,
            "/F1 {} Tf\n{} {} Td\n(Author: {}) Tj\n",
            self.font_size,
            self.margin,
            title_y - 30,
            pdf_escape(&meta.author)
        );
        let _ = write!(
            ops,
            "0 -{leading} Td\n(Date: {date}) Tj\n",
            leading = self.font_size + 4,
            date = pdf_escape(&meta.date)
        );
        if !meta.subject.is_empty() {
            let _ = write!(
                ops,
                "0 -{leading} Td\n(Subject: {sub}) Tj\n",
                leading = self.font_size + 4,
                sub = pdf_escape(&meta.subject)
            );
        }
        ops.push_str("ET\n");
        ops
    }

    fn section_page_stream(&self, section: &PdfSection) -> String {
        let heading_y = self.page_height - self.margin - 20;
        let mut ops = String::new();
        ops.push_str("BT\n");
        // Heading
        let _ = write!(
            ops,
            "/F1 {} Tf\n{} {} Td\n({}) Tj\n",
            self.heading_size,
            self.margin,
            heading_y,
            pdf_escape(&section.title)
        );
        // Body — split at ~80 chars to simulate wrapping
        let lead = i32::from(self.font_size) + 4;
        let _ = write!(ops, "/F1 {} Tf\n0 -{} Td\n", self.font_size, lead + 4);
        for line in wrap_text(&section.content, 90) {
            let _ = write!(ops, "({}) Tj\n0 -{} Td\n", pdf_escape(&line), lead);
        }
        ops.push_str("ET\n");
        ops
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_content_obj(id: u32, stream: &str) -> String {
    format!(
        "{id} 0 obj\n<< /Length {} >>\nstream\n{stream}endstream\nendobj\n",
        stream.len()
    )
}

/// Escape a string for embedding in a PDF literal string `(...)`.
fn pdf_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '(' => vec!['\\', '('],
            ')' => vec!['\\', ')'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            other => vec![other],
        })
        .collect()
}

/// Naively wrap text at `width` characters.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.len() + 1 + word.len() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(current.clone());
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

use std::collections::HashMap;

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> PdfMetadata {
        PdfMetadata::new(
            "Malware Analysis Report",
            "Analyst A",
            "2026-06-05",
            PdfClassification::Confidential,
        )
        .with_subject("Dynamic analysis of sample.exe")
        .with_keywords(vec!["malware".into(), "analysis".into()])
    }

    fn sample_report() -> PdfReport {
        let mut r = PdfReport::new(sample_metadata());
        r.add_section(PdfSection::new(
            "Executive Summary",
            "The sample exhibits ransomware behavior with C2 beaconing.",
        ));
        r.add_section(
            PdfSection::new("IOCs", "IP: 185.220.101.1\nDomain: c2.evil\n").with_page_break(),
        );
        r
    }

    // ── PdfClassification ───────────────────────────────────────────────────

    #[test]
    fn test_classification_display() {
        assert_eq!(PdfClassification::Confidential.to_string(), "CONFIDENTIAL");
        assert_eq!(PdfClassification::Unclassified.to_string(), "UNCLASSIFIED");
        assert_eq!(PdfClassification::TopSecret.to_string(), "TOP SECRET");
    }

    // ── PdfMetadata ─────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_fields() {
        let m = sample_metadata();
        assert_eq!(m.title, "Malware Analysis Report");
        assert_eq!(m.classification, PdfClassification::Confidential);
        assert_eq!(m.keywords.len(), 2);
    }

    // ── PdfSection ──────────────────────────────────────────────────────────

    #[test]
    fn test_section_char_count() {
        let s = PdfSection::new("Title", "Hello world");
        assert_eq!(s.char_count(), 5 + 11);
    }

    #[test]
    fn test_section_page_break() {
        let s = PdfSection::new("X", "Y").with_page_break();
        assert!(s.page_break);
    }

    // ── PdfReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_report_section_count() {
        let r = sample_report();
        assert_eq!(r.section_count(), 2);
    }

    #[test]
    fn test_report_total_chars() {
        let r = sample_report();
        assert!(r.total_chars() > 0);
    }

    // ── PdfExporter ─────────────────────────────────────────────────────────

    #[test]
    fn test_export_produces_bytes() {
        let exp = PdfExporter::new();
        let r = sample_report();
        let bytes = exp.export(&r);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_export_starts_with_pdf_header() {
        let exp = PdfExporter::new();
        let bytes = exp.export(&sample_report());
        assert!(bytes.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn test_export_contains_eof() {
        let exp = PdfExporter::new();
        let bytes = exp.export(&sample_report());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("%%EOF"));
    }

    #[test]
    fn test_export_contains_title() {
        let exp = PdfExporter::new();
        let bytes = exp.export(&sample_report());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Malware Analysis Report"));
    }

    #[test]
    fn test_export_contains_xref() {
        let exp = PdfExporter::new();
        let bytes = exp.export(&sample_report());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("xref"));
        assert!(text.contains("startxref"));
    }

    #[test]
    fn test_export_empty_sections() {
        let exp = PdfExporter::new();
        let r = PdfReport::new(sample_metadata());
        let bytes = exp.export(&r);
        assert!(bytes.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn test_pdf_escape() {
        assert_eq!(pdf_escape("(hello)"), "\\(hello\\)");
        assert_eq!(pdf_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_wrap_text_short_line() {
        let lines = wrap_text("short", 80);
        assert_eq!(lines, vec!["short"]);
    }

    #[test]
    fn test_wrap_text_wraps() {
        let long = "word ".repeat(40);
        let lines = wrap_text(&long, 20);
        assert!(lines.len() > 1);
    }
}
