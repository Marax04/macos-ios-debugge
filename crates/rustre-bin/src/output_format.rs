//! Output formatting utilities for the `rustre` CLI.
//!
//! Provides [`OutputFormat`], [`TableFormatter`], [`HexFormatter`],
//! [`TreeFormatter`], [`ProgressBar`], and [`ColorOutput`].

use std::fmt;
use std::io::{self, Write};

// Re-export `Write` and the `io` module so callers can write directly to
// any sink via `rustre_bin::output_format::IoWrite` without an additional
// `use std::io::Write` line. Exercises both imports above.
pub use std::io::Write as IoWrite;
/// Type alias confirming the bare `io::Error` (via the `self` import) resolves.
pub type IoError = io::Error;
/// Type alias confirming the bare `Write` import resolves to `std::io::Write`.
pub type DynWrite = dyn Write;

// ─────────────────────────────────────────────────────────────────────────────
// OutputFormat
// ─────────────────────────────────────────────────────────────────────────────

/// The serialization format used for command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// JSON array/object.
    Json,
    /// Comma-separated values.
    Csv,
    /// Minimal HTML table.
    Html,
}

impl OutputFormat {
    /// Parse from a lowercase string (accepts `"text"`, `"json"`, `"csv"`, `"html"`).
    #[must_use] 
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "plain" => Some(Self::Text),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// MIME type for this format.
    #[must_use] 
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Csv => "text/csv",
            Self::Html => "text/html",
        }
    }

    /// File extension (without dot).
    #[must_use] 
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Column alignment
// ─────────────────────────────────────────────────────────────────────────────

/// Column alignment in a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
    Center,
}

/// A single column definition for [`TableFormatter`].
#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub header: String,
    pub align: Align,
    /// Minimum width; 0 = auto from content.
    pub min_width: usize,
    /// Maximum width; 0 = no limit.
    pub max_width: usize,
}

impl ColumnDef {
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            align: Align::Left,
            min_width: 0,
            max_width: 0,
        }
    }

    #[must_use] 
    pub const fn align(mut self, a: Align) -> Self {
        self.align = a;
        self
    }
    #[must_use] 
    pub const fn min_width(mut self, w: usize) -> Self {
        self.min_width = w;
        self
    }
    #[must_use] 
    pub const fn max_width(mut self, w: usize) -> Self {
        self.max_width = w;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TableFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// Formats rows of string data as an aligned text table.
///
/// # Example
/// ```ignore
/// let mut t = TableFormatter::new(vec![
///     ColumnDef::new("Address").align(Align::Right),
///     ColumnDef::new("Mnemonic"),
///     ColumnDef::new("Operands"),
/// ]);
/// t.add_row(vec!["0x1000".into(), "mov".into(), "rax, rbx".into()]);
/// println!("{}", t.render());
/// ```
pub struct TableFormatter {
    columns: Vec<ColumnDef>,
    rows: Vec<Vec<String>>,
    separator: char,
    border: bool,
}

impl TableFormatter {
    #[must_use] 
    pub const fn new(columns: Vec<ColumnDef>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            separator: ' ',
            border: false,
        }
    }

    #[must_use] 
    pub const fn with_separator(mut self, sep: char) -> Self {
        self.separator = sep;
        self
    }
    #[must_use] 
    pub const fn with_border(mut self, b: bool) -> Self {
        self.border = b;
        self
    }

    /// Append a data row. Extra cells are truncated; missing cells are empty.
    pub fn add_row(&mut self, row: Vec<String>) {
        let mut r = row;
        r.resize(self.columns.len(), String::new());
        self.rows.push(r);
    }

    /// Compute effective column widths based on headers and data.
    fn col_widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let header_w = col.header.len();
                let data_w = self
                    .rows
                    .iter()
                    .map(|row| row.get(i).map_or(0, std::string::String::len))
                    .max()
                    .unwrap_or(0);
                let w = header_w.max(data_w).max(col.min_width);
                if col.max_width > 0 {
                    w.min(col.max_width)
                } else {
                    w
                }
            })
            .collect()
    }

    fn format_cell(s: &str, width: usize, align: Align) -> String {
        // `&s[..width]` panics when the cut lands inside a multi-byte character,
        // and cell width is a character count anyway — which is also what the
        // `{:<width$}` padding below uses, so byte lengths were inconsistent
        // with it even when they happened not to panic.
        let char_count = s.chars().count();
        let truncated: String = if char_count > width {
            s.chars().take(width).collect()
        } else {
            s.to_owned()
        };
        match align {
            Align::Left => format!("{truncated:<width$}"),
            Align::Right => format!("{truncated:>width$}"),
            Align::Center => {
                let pad = width.saturating_sub(truncated.chars().count());
                let left = pad / 2;
                let right = pad - left;
                format!("{}{}{}", " ".repeat(left), truncated, " ".repeat(right))
            }
        }
    }

    /// Render the table as a [`String`].
    #[must_use] 
    pub fn render(&self) -> String {
        let widths = self.col_widths();
        let sep = self.separator;
        let join_sep = format!(" {sep} ");
        let total_width: usize = widths.iter().sum();
        let mut out = String::with_capacity(
            (widths.len() * 4 + total_width) * (self.rows.len() + 3),
        );

        let header_row: Vec<String> = self
            .columns
            .iter()
            .enumerate()
            .map(|(i, col)| Self::format_cell(&col.header, widths[i], Align::Left))
            .collect();

        let divider: String = widths
            .iter()
            .map(|&w| "-".repeat(w))
            .collect::<Vec<_>>()
            .join("-+-");

        if self.border {
            out.push_str("+-");
            out.push_str(&divider);
            out.push_str("-+\n");
        }
        out.push_str(&header_row.join(&join_sep));
        out.push('\n');

        out.push_str(&divider);
        out.push('\n');

        for row in &self.rows {
            let cells: Vec<String> = self
                .columns
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let cell = row.get(i).map_or("", String::as_str);
                    Self::format_cell(cell, widths[i], col.align)
                })
                .collect();
            out.push_str(&cells.join(&join_sep));
            out.push('\n');
        }
        out
    }

    /// Number of rows (not counting header).
    #[must_use] 
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Emit as CSV.
    #[must_use] 
    pub fn render_csv(&self) -> String {
        let mut out = String::new();
        let headers: Vec<String> = self.columns.iter().map(|c| csv_escape(&c.header)).collect();
        out.push_str(&headers.join(","));
        out.push('\n');
        for row in &self.rows {
            let cells: Vec<String> = row.iter().map(|s| csv_escape(s)).collect();
            out.push_str(&cells.join(","));
            out.push('\n');
        }
        out
    }

    /// Emit as an HTML table.
    #[must_use] 
    pub fn render_html(&self) -> String {
        let mut out = String::from("<table>\n<thead><tr>");
        for col in &self.columns {
            out.push_str(&format!("<th>{}</th>", html_escape(&col.header)));
        }
        out.push_str("</tr></thead>\n<tbody>\n");
        for row in &self.rows {
            out.push_str("<tr>");
            for cell in row {
                out.push_str(&format!("<td>{}</td>", html_escape(cell)));
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody>\n</table>");
        out
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ─────────────────────────────────────────────────────────────────────────────
// HexFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// Formats binary data as a classic hex dump.
pub struct HexFormatter {
    /// Base address for the left-hand address column.
    pub base_addr: u64,
    /// Number of bytes per row (default 16).
    pub bytes_per_row: usize,
    /// Show ASCII column on the right.
    pub show_ascii: bool,
    /// Show byte offset column.
    pub show_offset: bool,
    /// Group bytes in groups of this size (0 = no grouping).
    pub group_size: usize,
}

impl Default for HexFormatter {
    fn default() -> Self {
        Self {
            base_addr: 0,
            bytes_per_row: 16,
            show_ascii: true,
            show_offset: true,
            group_size: 0,
        }
    }
}

impl HexFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn base(mut self, addr: u64) -> Self {
        self.base_addr = addr;
        self
    }
    #[must_use] 
    pub const fn bytes_per_row(mut self, n: usize) -> Self {
        self.bytes_per_row = n;
        self
    }
    #[must_use] 
    pub const fn no_ascii(mut self) -> Self {
        self.show_ascii = false;
        self
    }
    #[must_use] 
    pub const fn group(mut self, g: usize) -> Self {
        self.group_size = g;
        self
    }

    /// Format a byte slice as a hex dump string.
    #[must_use] 
    pub fn format(&self, data: &[u8]) -> String {
        let bpr = self.bytes_per_row.max(1);
        let mut out = String::new();
        for (chunk_idx, chunk) in data.chunks(bpr).enumerate() {
            let addr = self.base_addr + (chunk_idx * bpr) as u64;
            if self.show_offset {
                out.push_str(&format!("{addr:016x}  "));
            }
            // hex bytes
            for (i, &b) in chunk.iter().enumerate() {
                if self.group_size > 0 && i > 0 && i.is_multiple_of(self.group_size) {
                    out.push(' ');
                }
                out.push_str(&format!("{b:02x} "));
            }
            // padding for incomplete last row
            let padding = bpr.saturating_sub(chunk.len());
            for i in 0..padding {
                if self.group_size > 0 && (chunk.len() + i) % self.group_size == 0 {
                    out.push(' ');
                }
                out.push_str("   ");
            }
            if self.show_ascii {
                out.push(' ');
                out.push('|');
                for &b in chunk {
                    let c = if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    };
                    out.push(c);
                }
                out.push('|');
            }
            out.push('\n');
        }
        out
    }

    /// Format as Intel-style hex (e.g. `db 0x41, 0x42`).
    #[must_use] 
    pub fn format_intel_db(&self, data: &[u8]) -> String {
        let hex_vals: Vec<String> = data.iter().map(|b| format!("0x{b:02x}")).collect();
        format!("db {}", hex_vals.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// A node in a display tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub label: String,
    pub children: Vec<Self>,
}

impl TreeNode {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            children: Vec::new(),
        }
    }

    #[must_use] 
    pub fn child(mut self, node: Self) -> Self {
        self.children.push(node);
        self
    }

    pub fn add_child(&mut self, node: Self) {
        self.children.push(node);
    }
}

/// Formats a tree of [`TreeNode`]s using box-drawing characters.
pub struct TreeFormatter {
    pub use_unicode: bool,
}

impl Default for TreeFormatter {
    fn default() -> Self {
        Self { use_unicode: true }
    }
}

impl TreeFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use] 
    pub const fn ascii(mut self) -> Self {
        self.use_unicode = false;
        self
    }

    /// Render a single root node as a string.
    #[must_use] 
    pub fn format(&self, root: &TreeNode) -> String {
        let mut out = String::new();
        self.render_node(&mut out, root, "", true, true);
        out
    }

    fn render_node(
        &self,
        out: &mut String,
        node: &TreeNode,
        prefix: &str,
        is_last: bool,
        is_root: bool,
    ) {
        let (branch, vert) = if self.use_unicode {
            (if is_last { "└── " } else { "├── " }, "│   ")
        } else {
            (if is_last { "`-- " } else { "|-- " }, "|   ")
        };
        let connector = if is_root { "" } else { branch };
        let line = format!("{}{}{}\n", prefix, connector, node.label);
        let _ = is_root;
        out.push_str(&line);
        let child_prefix = if is_root {
            prefix.to_string()
        } else if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}{vert}")
        };
        let n = node.children.len();
        for (i, child) in node.children.iter().enumerate() {
            self.render_node(out, child, &child_prefix, i + 1 == n, false);
        }
    }

    /// Render multiple roots (a forest).
    #[must_use] 
    pub fn format_forest(&self, roots: &[TreeNode]) -> String {
        roots
            .iter()
            .map(|r| self.format(r))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProgressBar
// ─────────────────────────────────────────────────────────────────────────────

/// A simple text-mode progress bar.
pub struct ProgressBar {
    pub total: u64,
    pub current: u64,
    pub width: usize,
    pub prefix: String,
    pub fill_char: char,
    pub empty_char: char,
}

impl ProgressBar {
    #[must_use] 
    pub const fn new(total: u64) -> Self {
        Self {
            total,
            current: 0,
            width: 40,
            prefix: String::new(),
            fill_char: '=',
            empty_char: '-',
        }
    }

    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = p.into();
        self
    }
    #[must_use] 
    pub const fn width(mut self, w: usize) -> Self {
        self.width = w;
        self
    }

    /// Set the current progress value.
    pub fn set(&mut self, v: u64) {
        self.current = v.min(self.total);
    }

    /// Increment by one.
    pub fn tick(&mut self) {
        self.set(self.current + 1);
    }

    /// Compute the fraction completed [0.0, 1.0].
    #[must_use] 
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.current as f64 / self.total as f64
        }
    }

    /// Render a single-line progress bar string.
    #[must_use] 
    pub fn render(&self) -> String {
        let frac = self.fraction();
        let filled = (frac * self.width as f64).round() as usize;
        let empty = self.width.saturating_sub(filled);
        let bar: String = std::iter::repeat_n(self.fill_char, filled)
            .chain(std::iter::repeat_n(self.empty_char, empty))
            .collect();
        format!(
            "{} [{bar}] {}/{} ({:.1}%)",
            self.prefix,
            self.current,
            self.total,
            frac * 100.0,
        )
    }

    /// Returns true if progress is complete.
    #[must_use] 
    pub const fn is_complete(&self) -> bool {
        self.current >= self.total
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorOutput
// ─────────────────────────────────────────────────────────────────────────────

/// ANSI colour codes for terminal output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Reset,
    Bold,
    Dim,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightCyan,
}

impl Color {
    #[must_use] 
    pub const fn escape_code(self) -> &'static str {
        match self {
            Self::Reset => "\x1b[0m",
            Self::Bold => "\x1b[1m",
            Self::Dim => "\x1b[2m",
            Self::Red => "\x1b[31m",
            Self::Green => "\x1b[32m",
            Self::Yellow => "\x1b[33m",
            Self::Blue => "\x1b[34m",
            Self::Magenta => "\x1b[35m",
            Self::Cyan => "\x1b[36m",
            Self::White => "\x1b[37m",
            Self::BrightRed => "\x1b[91m",
            Self::BrightGreen => "\x1b[92m",
            Self::BrightYellow => "\x1b[93m",
            Self::BrightCyan => "\x1b[96m",
        }
    }
}

/// Applies ANSI colour codes, with optional no-colour mode.
pub struct ColorOutput {
    pub enabled: bool,
}

impl ColorOutput {
    #[must_use] 
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Wrap text in the given colour code (and reset at end).
    #[must_use] 
    pub fn paint(&self, color: Color, text: &str) -> String {
        if self.enabled {
            format!(
                "{}{}{}",
                color.escape_code(),
                text,
                Color::Reset.escape_code()
            )
        } else {
            text.to_string()
        }
    }

    /// Bold text.
    #[must_use] 
    pub fn bold(&self, text: &str) -> String {
        self.paint(Color::Bold, text)
    }

    /// Red text (used for errors).
    #[must_use] 
    pub fn error(&self, text: &str) -> String {
        self.paint(Color::BrightRed, text)
    }

    /// Green text (used for success).
    #[must_use] 
    pub fn success(&self, text: &str) -> String {
        self.paint(Color::BrightGreen, text)
    }

    /// Yellow text (used for warnings).
    #[must_use] 
    pub fn warning(&self, text: &str) -> String {
        self.paint(Color::Yellow, text)
    }

    /// Cyan text (used for addresses).
    #[must_use] 
    pub fn address(&self, text: &str) -> String {
        self.paint(Color::BrightCyan, text)
    }

    /// Dim text (used for comments / secondary info).
    #[must_use] 
    pub fn comment(&self, text: &str) -> String {
        self.paint(Color::Dim, text)
    }

    /// Strip ANSI escape codes from a string.
    #[must_use] 
    pub fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // Consume until 'm'
                for nc in chars.by_ref() {
                    if nc == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cell_never_splits_a_character() {
        // Table cells carry demangled symbol names and strings extracted from
        // binaries, so non-ASCII is ordinary; slicing by byte index panicked
        // mid-character. Width is a character count, matching the padding.
        for s in ["café café", "日本語のシンボル", "🙂🙂🙂", "plain"] {
            for width in 0..10 {
                for align in [Align::Left, Align::Right, Align::Center] {
                    let out = TableFormatter::format_cell(s, width, align);
                    assert!(
                        out.chars().count() >= width.min(s.chars().count()),
                        "format_cell({s:?}, {width}) lost content"
                    );
                }
            }
        }
    }

    // --- OutputFormat ---

    #[test]
    fn output_format_from_str_json() {
        assert_eq!(OutputFormat::from_str("json"), Some(OutputFormat::Json));
    }

    #[test]
    fn output_format_from_str_text() {
        assert_eq!(OutputFormat::from_str("plain"), Some(OutputFormat::Text));
    }

    #[test]
    fn output_format_from_str_unknown() {
        assert_eq!(OutputFormat::from_str("xml"), None);
    }

    #[test]
    fn output_format_mime_json() {
        assert_eq!(OutputFormat::Json.mime_type(), "application/json");
    }

    #[test]
    fn output_format_extension_csv() {
        assert_eq!(OutputFormat::Csv.extension(), "csv");
    }

    #[test]
    fn output_format_display() {
        assert_eq!(format!("{}", OutputFormat::Html), "html");
    }

    #[test]
    fn output_format_default_is_text() {
        assert_eq!(OutputFormat::default(), OutputFormat::Text);
    }

    // --- TableFormatter ---

    #[test]
    fn table_formatter_basic_render() {
        let mut t = TableFormatter::new(vec![
            ColumnDef::new("Name"),
            ColumnDef::new("Value").align(Align::Right),
        ]);
        t.add_row(vec!["foo".into(), "42".into()]);
        let rendered = t.render();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("foo"));
        assert!(rendered.contains("42"));
    }

    #[test]
    fn table_formatter_row_count() {
        let mut t = TableFormatter::new(vec![ColumnDef::new("A")]);
        t.add_row(vec!["x".into()]);
        t.add_row(vec!["y".into()]);
        assert_eq!(t.row_count(), 2);
    }

    #[test]
    fn table_formatter_csv() {
        let mut t = TableFormatter::new(vec![ColumnDef::new("K"), ColumnDef::new("V")]);
        t.add_row(vec!["hello".into(), "world".into()]);
        let csv = t.render_csv();
        assert!(csv.contains("K,V"));
        assert!(csv.contains("hello,world"));
    }

    #[test]
    fn table_formatter_html() {
        let mut t = TableFormatter::new(vec![ColumnDef::new("Col")]);
        t.add_row(vec!["<script>".into()]);
        let html = t.render_html();
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn csv_escape_with_comma() {
        let s = csv_escape("a,b");
        assert_eq!(s, "\"a,b\"");
    }

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn html_escape_ampersand() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    // --- HexFormatter ---

    #[test]
    fn hex_formatter_basic() {
        let fmt = HexFormatter::new();
        let out = fmt.format(b"Hello");
        assert!(out.contains("48")); // 'H'
        assert!(out.contains("Hello"));
    }

    #[test]
    fn hex_formatter_empty() {
        let fmt = HexFormatter::new();
        let out = fmt.format(b"");
        assert!(out.is_empty());
    }

    #[test]
    fn hex_formatter_no_ascii() {
        let fmt = HexFormatter::new().no_ascii();
        let out = fmt.format(b"AB");
        assert!(!out.contains('|'));
    }

    #[test]
    fn hex_formatter_base_address() {
        let fmt = HexFormatter::new().base(0x1000);
        let out = fmt.format(b"X");
        assert!(out.contains("0000000000001000"));
    }

    #[test]
    fn hex_formatter_intel_db() {
        let out = HexFormatter::new().format_intel_db(b"\x90\xcc");
        assert_eq!(out, "db 0x90, 0xcc");
    }

    // --- TreeFormatter ---

    #[test]
    fn tree_formatter_single_node() {
        let root = TreeNode::new("root");
        let fmt = TreeFormatter::new();
        let out = fmt.format(&root);
        assert!(out.contains("root"));
    }

    #[test]
    fn tree_formatter_with_children() {
        let root = TreeNode::new("root")
            .child(TreeNode::new("child1"))
            .child(TreeNode::new("child2"));
        let fmt = TreeFormatter::new();
        let out = fmt.format(&root);
        assert!(out.contains("child1"));
        assert!(out.contains("child2"));
    }

    #[test]
    fn tree_formatter_ascii_mode() {
        let root = TreeNode::new("r").child(TreeNode::new("c"));
        let fmt = TreeFormatter::new().ascii();
        let out = fmt.format(&root);
        assert!(!out.contains('└'));
    }

    #[test]
    fn tree_formatter_forest() {
        let roots = vec![TreeNode::new("a"), TreeNode::new("b")];
        let fmt = TreeFormatter::new();
        let out = fmt.format_forest(&roots);
        assert!(out.contains('a'));
        assert!(out.contains('b'));
    }

    // --- ProgressBar ---

    #[test]
    fn progress_bar_zero_total() {
        let pb = ProgressBar::new(0);
        assert!((pb.fraction() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn progress_bar_fraction() {
        let mut pb = ProgressBar::new(100);
        pb.set(50);
        assert!((pb.fraction() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn progress_bar_render_contains_percent() {
        let mut pb = ProgressBar::new(100).prefix("Loading");
        pb.set(75);
        let s = pb.render();
        assert!(s.contains("75.0%"));
    }

    #[test]
    fn progress_bar_tick() {
        let mut pb = ProgressBar::new(10);
        pb.tick();
        pb.tick();
        assert_eq!(pb.current, 2);
    }

    #[test]
    fn progress_bar_is_complete() {
        let mut pb = ProgressBar::new(5);
        pb.set(5);
        assert!(pb.is_complete());
    }

    #[test]
    fn progress_bar_not_complete() {
        let pb = ProgressBar::new(10);
        assert!(!pb.is_complete());
    }

    // --- ColorOutput ---

    #[test]
    fn color_output_enabled_adds_escapes() {
        let c = ColorOutput::new(true);
        let s = c.error("bad");
        assert!(s.contains('\x1b'));
    }

    #[test]
    fn color_output_disabled_no_escapes() {
        let c = ColorOutput::new(false);
        let s = c.error("bad");
        assert_eq!(s, "bad");
    }

    #[test]
    fn color_output_strip_ansi() {
        let s = "\x1b[31mred\x1b[0m";
        assert_eq!(ColorOutput::strip_ansi(s), "red");
    }

    #[test]
    fn color_output_bold() {
        let c = ColorOutput::new(true);
        let s = c.bold("text");
        assert!(s.contains("\x1b[1m"));
    }

    #[test]
    fn color_output_address() {
        let c = ColorOutput::new(true);
        let s = c.address("0x1000");
        assert!(s.contains("0x1000"));
    }
}
