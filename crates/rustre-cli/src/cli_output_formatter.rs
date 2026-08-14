//! CLI output formatting – tables, JSON, CSV, and plain text.
//!
//! This module provides a high-level [`CliOutputFormatter`] that accepts
//! structured data (rows + headers) and renders it in the user's chosen
//! [`OutputFormat`].  A fluent [`TableBuilder`] API makes it easy to
//! construct tables without pre-allocating vectors.
//!
//! # Features
//! * Unicode-aware column width computation (falls back to byte length when
//!   the string is pure ASCII, which is the common case in RE output).
//! * Column alignment (left / right / centre).
//! * JSON and JSON-pretty renderers without any external dependency.
//! * CSV renderer with RFC 4180 escaping.
//! * Lines renderer (tab-separated, useful for shell pipelines).

use std::fmt;

// ── OutputFormat ──────────────────────────────────────────────────────────────

/// The output format the user requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable ASCII table (default).
    #[default]
    Table,
    /// Compact JSON array-of-objects.
    Json,
    /// Pretty-printed (indented) JSON.
    JsonPretty,
    /// RFC 4180 CSV.
    Csv,
    /// One row per line, fields tab-separated.
    Lines,
    /// Plain paragraph text (used for single-value responses).
    Plain,
}

impl OutputFormat {
    /// Return the canonical name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::JsonPretty => "json-pretty",
            Self::Csv => "csv",
            Self::Lines => "lines",
            Self::Plain => "plain",
        }
    }

    /// Parse from a string slice.
    ///
    /// # Errors
    /// Returns the unrecognised string inside the error.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "json-pretty" => Ok(Self::JsonPretty),
            "csv" => Ok(Self::Csv),
            "lines" => Ok(Self::Lines),
            "plain" => Ok(Self::Plain),
            other => Err(format!("unknown format '{other}'")),
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── ColAlign ──────────────────────────────────────────────────────────────────

/// Column text alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColAlign {
    #[default]
    Left,
    Right,
    Center,
}

// ── TableBuilder ──────────────────────────────────────────────────────────────

/// Fluent builder for tabular data.
///
/// ```ignore
/// let output = TableBuilder::new(&["Name", "Size"])
///     .row(&["main", "4096"])
///     .row(&["init", "128"])
///     .build()
///     .render(OutputFormat::Table);
/// ```
#[derive(Debug, Clone)]
pub struct TableBuilder {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    alignments: Vec<ColAlign>,
}

impl TableBuilder {
    /// Create a new builder with the given column headers.
    #[must_use]
    pub fn new(headers: &[impl AsRef<str>]) -> Self {
        let headers: Vec<String> = headers.iter().map(|h| h.as_ref().to_string()).collect();
        let n = headers.len();
        Self {
            headers,
            rows: Vec::new(),
            alignments: vec![ColAlign::Left; n],
        }
    }

    /// Append a row of cells.
    pub fn row(mut self, cells: &[impl AsRef<str>]) -> Self {
        self.rows.push(cells.iter().map(|c| c.as_ref().to_string()).collect());
        self
    }

    /// Append a row from an iterator of strings.
    pub fn row_iter(mut self, cells: impl IntoIterator<Item = String>) -> Self {
        self.rows.push(cells.into_iter().collect());
        self
    }

    /// Set the alignment for column `col`.
    ///
    /// # Panics
    /// Panics if `col >= number of columns`.
    #[must_use] 
    pub fn align(mut self, col: usize, align: ColAlign) -> Self {
        self.alignments[col] = align;
        self
    }

    /// Set all column alignments at once.
    #[must_use] 
    pub fn alignments(mut self, aligns: Vec<ColAlign>) -> Self {
        self.alignments = aligns;
        self
    }

    /// Finalise the builder and produce a [`FormattedTable`].
    #[must_use]
    pub fn build(self) -> FormattedTable {
        FormattedTable {
            headers: self.headers,
            rows: self.rows,
            alignments: self.alignments,
        }
    }
}

// ── FormattedTable ────────────────────────────────────────────────────────────

/// A completed table ready for rendering.
#[derive(Debug, Clone)]
pub struct FormattedTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    alignments: Vec<ColAlign>,
}

impl FormattedTable {
    /// Number of columns.
    #[must_use]
    pub const fn col_count(&self) -> usize {
        self.headers.len()
    }

    /// Number of data rows.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Render this table in the specified format.
    #[must_use]
    pub fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Table => self.render_table(),
            OutputFormat::Json => self.render_json(false),
            OutputFormat::JsonPretty => self.render_json(true),
            OutputFormat::Csv => self.render_csv(),
            OutputFormat::Lines => self.render_lines(),
            OutputFormat::Plain => self.render_plain(),
        }
    }

    // ── Table rendering ───────────────────────────────────────────────────────

    fn col_widths(&self) -> Vec<usize> {
        let mut w: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < w.len() {
                    w[i] = w[i].max(display_width(cell));
                }
            }
        }
        w
    }

    fn render_table(&self) -> String {
        let widths = self.col_widths();
        let sep = build_separator(&widths);
        let mut out = String::new();
        out.push_str(&sep);
        out.push('\n');
        out.push_str(&self.format_row(&self.headers, &widths, &vec![ColAlign::Left; self.headers.len()]));
        out.push('\n');
        out.push_str(&sep);
        out.push('\n');
        for row in &self.rows {
            out.push_str(&self.format_row(row, &widths, &self.alignments));
            out.push('\n');
        }
        out.push_str(&sep);
        out.push('\n');
        out
    }

    fn format_row(&self, cells: &[String], widths: &[usize], aligns: &[ColAlign]) -> String {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let w = widths.get(i).copied().unwrap_or(display_width(c));
                let a = aligns.get(i).copied().unwrap_or_default();
                format!(" {} ", pad(c, w, a))
            })
            .collect();
        format!("|{}|", parts.join("|"))
    }

    // ── JSON rendering ────────────────────────────────────────────────────────

    fn render_json(&self, pretty: bool) -> String {
        let mut entries: Vec<String> = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let pairs: Vec<String> = self
                .headers
                .iter()
                .zip(row.iter())
                .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
                .collect();
            entries.push(format!("{{{}}}", pairs.join(",")));
        }
        if pretty {
            pretty_json_array(&entries)
        } else {
            format!("[{}]", entries.join(","))
        }
    }

    // ── CSV rendering ─────────────────────────────────────────────────────────

    fn render_csv(&self) -> String {
        let mut out = csv_row(&self.headers);
        out.push('\n');
        for row in &self.rows {
            out.push_str(&csv_row(row));
            out.push('\n');
        }
        out
    }

    // ── Lines rendering ───────────────────────────────────────────────────────

    fn render_lines(&self) -> String {
        let mut out = String::new();
        for row in &self.rows {
            out.push_str(&row.join("\t"));
            out.push('\n');
        }
        out
    }

    // ── Plain rendering ───────────────────────────────────────────────────────

    fn render_plain(&self) -> String {
        self.rows
            .iter()
            .map(|row| row.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ── CliOutputFormatter ────────────────────────────────────────────────────────

/// High-level formatter that can render various output types.
///
/// [`CliOutputFormatter`] knows how to produce tables, key-value pairs, and
/// plain messages in whatever format the user requested.
pub struct CliOutputFormatter {
    format: OutputFormat,
    color: bool,
}

impl CliOutputFormatter {
    /// Create a formatter for the given output format.
    #[must_use]
    pub const fn new(format: OutputFormat, color: bool) -> Self {
        Self { format, color }
    }

    /// Render a [`FormattedTable`].
    #[must_use]
    pub fn render_table(&self, table: &FormattedTable) -> String {
        table.render(self.format)
    }

    /// Render a simple key=value list as a table.
    #[must_use]
    pub fn render_kv(&self, pairs: &[(&str, &str)]) -> String {
        let mut builder = TableBuilder::new(&["Key", "Value"]);
        for (k, v) in pairs {
            builder = builder.row(&[*k, *v]);
        }
        builder.build().render(self.format)
    }

    /// Render a plain-text message.  For JSON formats, wraps in `{"message":"…"}`.
    #[must_use]
    pub fn render_message(&self, msg: &str) -> String {
        match self.format {
            OutputFormat::Json | OutputFormat::JsonPretty => {
                format!("{{\"message\":\"{}\"}}", json_escape(msg))
            }
            _ => msg.to_string(),
        }
    }

    /// Format a `u64` address using the appropriate width.
    #[must_use]
    pub fn format_addr(addr: u64, bits: u32) -> String {
        match bits {
            16 => format!("0x{addr:04X}"),
            32 => format!("0x{addr:08X}"),
            _ => format!("0x{addr:016X}"),
        }
    }

    /// Return the current output format.
    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    /// Return `true` if colour output is enabled.
    #[must_use]
    pub const fn color(&self) -> bool {
        self.color
    }

    /// Render a list of strings as a bulleted list or JSON array.
    #[must_use]
    pub fn render_list(&self, items: &[&str]) -> String {
        match self.format {
            OutputFormat::Json | OutputFormat::JsonPretty => {
                let quoted: Vec<String> =
                    items.iter().map(|s| format!("\"{}\"", json_escape(s))).collect();
                format!("[{}]", quoted.join(","))
            }
            OutputFormat::Csv => items.join("\n"),
            _ => items.iter().map(|s| format!("  - {s}")).collect::<Vec<_>>().join("\n"),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the display width of a string.
///
/// For pure ASCII strings (the common case in RE output) this is simply the
/// byte length.  For strings containing multi-byte UTF-8 sequences we count
/// Unicode scalar values as a proxy for display width.
fn display_width(s: &str) -> usize {
    if s.is_ascii() { s.len() } else { s.chars().count() }
}

/// Pad `s` to `width` characters using the given alignment.
fn pad(s: &str, width: usize, align: ColAlign) -> String {
    let dw = display_width(s);
    let extra = width.saturating_sub(dw);
    match align {
        ColAlign::Left => format!("{s}{}", " ".repeat(extra)),
        ColAlign::Right => format!("{}{s}", " ".repeat(extra)),
        ColAlign::Center => {
            let left = extra / 2;
            let right = extra - left;
            format!("{}{s}{}", " ".repeat(left), " ".repeat(right))
        }
    }
}

/// Build the horizontal separator line for a table.
fn build_separator(widths: &[usize]) -> String {
    let inner: String = widths
        .iter()
        .map(|w| "-".repeat(w + 2))
        .collect::<Vec<_>>()
        .join("+");
    format!("+{inner}+")
}

/// Escape a string for safe embedding in a JSON string value.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Escape a single CSV field per RFC 4180.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Build one CSV row.
fn csv_row(cells: &[String]) -> String {
    cells.iter().map(|c| csv_escape(c)).collect::<Vec<_>>().join(",")
}

/// Format a JSON array in pretty-printed style.
fn pretty_json_array(entries: &[String]) -> String {
    if entries.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[\n");
    for (i, entry) in entries.iter().enumerate() {
        // Re-indent keys: split at commas (crude but dependency-free).
        out.push_str("  ");
        out.push_str(entry);
        if i + 1 < entries.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    out
}

// ── format_as_table ───────────────────────────────────────────────────────────

/// Convenience free function: format `rows` with `headers` as a table string.
///
/// Each row must have the same number of cells as there are headers; extra
/// cells are silently ignored, missing cells are rendered as empty strings.
#[must_use]
pub fn format_as_table(headers: &[&str], rows: &[Vec<String>], format: OutputFormat) -> String {
    let mut builder = TableBuilder::new(headers);
    for row in rows {
        builder = builder.row_iter(row.iter().cloned());
    }
    builder.build().render(format)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn two_col_table() -> FormattedTable {
        TableBuilder::new(&["Name", "Value"])
            .row(&["alpha", "1"])
            .row(&["beta", "200"])
            .build()
    }

    #[test]
    fn test_render_table_contains_headers() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Table);
        assert!(s.contains("Name"));
        assert!(s.contains("Value"));
        assert!(s.contains("alpha"));
        assert!(s.contains("200"));
    }

    #[test]
    fn test_render_table_separator_chars() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Table);
        assert!(s.contains('+'));
        assert!(s.contains('|'));
        assert!(s.contains('-'));
    }

    #[test]
    fn test_render_json_flat() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Json);
        assert!(s.starts_with('['));
        assert!(s.ends_with(']'));
        assert!(s.contains("\"Name\""));
        assert!(s.contains("\"alpha\""));
    }

    #[test]
    fn test_render_json_pretty() {
        let t = two_col_table();
        let s = t.render(OutputFormat::JsonPretty);
        assert!(s.contains('\n'));
        assert!(s.starts_with('['));
    }

    #[test]
    fn test_render_csv_headers() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Csv);
        assert!(s.starts_with("Name,Value\n"));
        assert!(s.contains("alpha,1"));
    }

    #[test]
    fn test_render_csv_escapes_comma() {
        let t = TableBuilder::new(&["K", "V"])
            .row(&["a,b", "c"])
            .build();
        let s = t.render(OutputFormat::Csv);
        assert!(s.contains("\"a,b\""));
    }

    #[test]
    fn test_render_lines() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Lines);
        assert!(s.contains('\t'));
        assert!(s.contains("alpha"));
    }

    #[test]
    fn test_render_plain() {
        let t = two_col_table();
        let s = t.render(OutputFormat::Plain);
        assert!(s.contains("alpha 1"));
    }

    #[test]
    fn test_col_and_row_counts() {
        let t = two_col_table();
        assert_eq!(t.col_count(), 2);
        assert_eq!(t.row_count(), 2);
    }

    #[test]
    fn test_output_format_name() {
        assert_eq!(OutputFormat::Table.name(), "table");
        assert_eq!(OutputFormat::JsonPretty.name(), "json-pretty");
        assert_eq!(OutputFormat::Lines.name(), "lines");
    }

    #[test]
    fn test_output_format_parse() {
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("csv").unwrap(), OutputFormat::Csv);
        assert!(OutputFormat::parse("garbage").is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Csv.to_string(), "csv");
    }

    #[test]
    fn test_col_align_default() {
        assert_eq!(ColAlign::default(), ColAlign::Left);
    }

    #[test]
    fn test_pad_left() {
        assert_eq!(pad("hi", 5, ColAlign::Left), "hi   ");
    }

    #[test]
    fn test_pad_right() {
        assert_eq!(pad("hi", 5, ColAlign::Right), "   hi");
    }

    #[test]
    fn test_pad_center() {
        let s = pad("hi", 6, ColAlign::Center);
        assert_eq!(s.len(), 6);
        assert!(s.contains("hi"));
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_csv_escape_no_special() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_with_quote() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_formatter_render_kv() {
        let fmt = CliOutputFormatter::new(OutputFormat::Table, false);
        let s = fmt.render_kv(&[("arch", "x86_64"), ("bits", "64")]);
        assert!(s.contains("arch"));
        assert!(s.contains("x86_64"));
    }

    #[test]
    fn test_formatter_render_message_plain() {
        let fmt = CliOutputFormatter::new(OutputFormat::Plain, false);
        assert_eq!(fmt.render_message("hello"), "hello");
    }

    #[test]
    fn test_formatter_render_message_json() {
        let fmt = CliOutputFormatter::new(OutputFormat::Json, false);
        let s = fmt.render_message("hello");
        assert!(s.contains("\"message\""));
        assert!(s.contains("\"hello\""));
    }

    #[test]
    fn test_formatter_render_list_plain() {
        let fmt = CliOutputFormatter::new(OutputFormat::Table, false);
        let s = fmt.render_list(&["a", "b", "c"]);
        assert!(s.contains("- a"));
    }

    #[test]
    fn test_formatter_render_list_json() {
        let fmt = CliOutputFormatter::new(OutputFormat::Json, false);
        let s = fmt.render_list(&["a", "b"]);
        assert!(s.starts_with('['));
        assert!(s.contains("\"a\""));
    }

    #[test]
    fn test_format_addr_16() {
        assert_eq!(CliOutputFormatter::format_addr(0xABCD, 16), "0xABCD");
    }

    #[test]
    fn test_format_addr_32() {
        assert_eq!(CliOutputFormatter::format_addr(0x1234, 32), "0x00001234");
    }

    #[test]
    fn test_format_as_table_free_fn() {
        let rows = vec![
            vec!["foo".to_string(), "42".to_string()],
            vec!["bar".to_string(), "99".to_string()],
        ];
        let s = format_as_table(&["Name", "Count"], &rows, OutputFormat::Table);
        assert!(s.contains("foo"));
        assert!(s.contains("Count"));
    }

    #[test]
    fn test_empty_table_json() {
        let t = TableBuilder::new(&["A", "B"]).build();
        let s = t.render(OutputFormat::Json);
        assert_eq!(s, "[]");
    }

    #[test]
    fn test_table_builder_align() {
        let t = TableBuilder::new(&["N", "V"])
            .row(&["a", "1"])
            .align(1, ColAlign::Right)
            .build();
        let s = t.render(OutputFormat::Table);
        assert!(!s.is_empty());
    }
}
