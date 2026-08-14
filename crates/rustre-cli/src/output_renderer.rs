//! `output_renderer` — Multi-format output rendering for the `RustRE` CLI.
//!
//! Provides [`OutputRenderer`], [`RenderFormat`], [`ColorTheme`],
//! [`TableLayout`], [`TreeView`], and [`ProgressDisplay`].

use std::collections::HashMap;
use std::fmt;

// Re-export the `std::io` module and the `Write` trait so external
// consumers writing custom renderer sinks can refer to them through
// `output_renderer::io` / `output_renderer::IoWrite`.
pub use std::io::{self, Write as IoWrite};

use serde::{Deserialize, Serialize};

// ─── RenderFormat ─────────────────────────────────────────────────────────────

/// Output format supported by the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderFormat {
    Text,
    Json,
    Table,
    Tree,
    Hex,
    Csv,
    Markdown,
}

impl std::fmt::Display for RenderFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::str::FromStr for RenderFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "plain" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            "tree" => Ok(Self::Tree),
            "hex" => Ok(Self::Hex),
            "csv" => Ok(Self::Csv),
            "markdown" | "md" => Ok(Self::Markdown),
            other => Err(format!("unknown format '{other}'")),
        }
    }
}

// ─── ColorTheme ───────────────────────────────────────────────────────────────

/// ANSI colour codes for terminal output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorTheme {
    pub header: String,
    pub key: String,
    pub value: String,
    pub error: String,
    pub warning: String,
    pub success: String,
    pub info: String,
    pub dim: String,
    pub reset: String,
    pub enabled: bool,
}

impl ColorTheme {
    /// Build the default dark-terminal theme.
    #[must_use]
    pub fn default_dark() -> Self {
        Self {
            header: "\x1b[1;34m".to_string(),  // bold blue
            key: "\x1b[1;33m".to_string(),     // bold yellow
            value: "\x1b[0;37m".to_string(),   // white
            error: "\x1b[1;31m".to_string(),   // bold red
            warning: "\x1b[1;33m".to_string(), // bold yellow
            success: "\x1b[1;32m".to_string(), // bold green
            info: "\x1b[0;36m".to_string(),    // cyan
            dim: "\x1b[2;37m".to_string(),     // dim white
            reset: "\x1b[0m".to_string(),
            enabled: true,
        }
    }

    /// No-colour theme (all codes empty).
    #[must_use]
    pub const fn no_color() -> Self {
        Self {
            header: String::new(),
            key: String::new(),
            value: String::new(),
            error: String::new(),
            warning: String::new(),
            success: String::new(),
            info: String::new(),
            dim: String::new(),
            reset: String::new(),
            enabled: false,
        }
    }

    /// Wrap `text` in the given colour code if colours are enabled.
    #[must_use]
    pub fn colorize(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("{code}{text}{}", self.reset)
        } else {
            text.to_string()
        }
    }

    #[must_use]
    pub fn header(&self, s: &str) -> String {
        self.colorize(&self.header, s)
    }
    #[must_use]
    pub fn error(&self, s: &str) -> String {
        self.colorize(&self.error, s)
    }
    #[must_use]
    pub fn warning(&self, s: &str) -> String {
        self.colorize(&self.warning, s)
    }
    #[must_use]
    pub fn success(&self, s: &str) -> String {
        self.colorize(&self.success, s)
    }
    #[must_use]
    pub fn info(&self, s: &str) -> String {
        self.colorize(&self.info, s)
    }
    #[must_use]
    pub fn key(&self, s: &str) -> String {
        self.colorize(&self.key, s)
    }
    #[must_use]
    pub fn dim(&self, s: &str) -> String {
        self.colorize(&self.dim, s)
    }
}

impl Default for ColorTheme {
    fn default() -> Self {
        Self::no_color()
    }
}

// ─── TableLayout ──────────────────────────────────────────────────────────────

/// Column definition for a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    pub header: String,
    pub width: usize,
    pub align: ColumnAlign,
    pub truncate: bool,
}

/// Text alignment within a table column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnAlign {
    Left,
    Right,
    Center,
}

impl TableColumn {
    #[must_use]
    pub fn new(header: impl Into<String>, width: usize) -> Self {
        Self {
            header: header.into(),
            width,
            align: ColumnAlign::Left,
            truncate: true,
        }
    }

    #[must_use]
    pub const fn right(mut self) -> Self {
        self.align = ColumnAlign::Right;
        self
    }

    #[must_use]
    pub const fn center(mut self) -> Self {
        self.align = ColumnAlign::Center;
        self
    }

    /// Render a single cell value to a padded string.
    #[must_use]
    pub fn render_cell(&self, value: &str) -> String {
        let v = if self.truncate && value.len() > self.width {
            let mut s: String = value.chars().take(self.width.saturating_sub(1)).collect();
            s.push('…');
            s
        } else {
            value.to_string()
        };
        match self.align {
            ColumnAlign::Left => format!("{:<width$}", v, width = self.width),
            ColumnAlign::Right => format!("{:>width$}", v, width = self.width),
            ColumnAlign::Center => format!("{:^width$}", v, width = self.width),
        }
    }
}

/// A rendered table.
#[derive(Debug, Default)]
pub struct TableLayout {
    pub columns: Vec<TableColumn>,
    pub rows: Vec<Vec<String>>,
    pub border: bool,
    pub header_separator: bool,
}

impl TableLayout {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            border: true,
            header_separator: true,
        }
    }

    #[must_use]
    pub fn with_column(mut self, col: TableColumn) -> Self {
        self.columns.push(col);
        self
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    /// Render the table to a string.
    #[must_use]
    pub fn render(&self) -> String {
        let sep_char = if self.border { "│" } else { " " };
        let mut out = String::new();

        // Header
        let header: String = self
            .columns
            .iter()
            .map(|c| c.render_cell(&c.header))
            .collect::<Vec<_>>()
            .join(sep_char);
        out.push_str(&header);
        out.push('\n');

        if self.header_separator {
            let sep: String = self
                .columns
                .iter()
                .map(|c| "─".repeat(c.width))
                .collect::<Vec<_>>()
                .join(if self.border { "┼" } else { "-" });
            out.push_str(&sep);
            out.push('\n');
        }

        for row in &self.rows {
            let cells: String = self
                .columns
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let val = row.get(i).map_or("", std::string::String::as_str);
                    col.render_cell(val)
                })
                .collect::<Vec<_>>()
                .join(sep_char);
            out.push_str(&cells);
            out.push('\n');
        }

        out
    }

    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }
}

// ─── TreeView ────────────────────────────────────────────────────────────────

/// A node in a tree view.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub label: String,
    pub children: Vec<Self>,
    pub metadata: HashMap<String, String>,
}

impl TreeNode {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            children: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_child(mut self, child: Self) -> Self {
        self.children.push(child);
        self
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }

    /// Recursively count all nodes.
    #[must_use]
    pub fn total_nodes(&self) -> usize {
        1 + self.children.iter().map(Self::total_nodes).sum::<usize>()
    }
}

/// Renders a tree of [`TreeNode`]s to text.
#[derive(Debug, Default)]
pub struct TreeView {
    pub root: Option<TreeNode>,
    pub show_metadata: bool,
    pub indent_char: String,
}

impl TreeView {
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: None,
            show_metadata: false,
            indent_char: "  ".to_string(),
        }
    }

    pub fn set_root(&mut self, node: TreeNode) {
        self.root = Some(node);
    }

    #[must_use]
    pub fn with_root(mut self, node: TreeNode) -> Self {
        self.root = Some(node);
        self
    }

    /// Render the tree to a string.
    #[must_use]
    pub fn render(&self) -> String {
        match &self.root {
            Some(root) => self.render_node(root, "", true),
            None => String::new(),
        }
    }

    fn render_node(&self, node: &TreeNode, prefix: &str, is_last: bool) -> String {
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last {
            format!("{}{}", prefix, &self.indent_char)
        } else {
            format!(
                "{}│{}",
                prefix,
                &self.indent_char[..self.indent_char.len().min(1)]
            )
        };

        let mut out = format!("{prefix}{connector}{}\n", node.label);

        if self.show_metadata {
            for (k, v) in &node.metadata {
                out.push_str(&format!("{child_prefix}  {k}: {v}\n"));
            }
        }

        for (i, child) in node.children.iter().enumerate() {
            let child_is_last = i + 1 == node.children.len();
            out.push_str(&self.render_node(child, &child_prefix, child_is_last));
        }

        out
    }
}

// ─── ProgressDisplay ─────────────────────────────────────────────────────────

/// A simple text-based progress bar.
#[derive(Debug)]
pub struct ProgressDisplay {
    pub total: u64,
    pub current: u64,
    pub width: usize,
    pub label: String,
    pub bar_char: char,
    pub empty_char: char,
    pub show_percentage: bool,
    pub show_count: bool,
}

impl ProgressDisplay {
    #[must_use]
    pub fn new(total: u64, label: impl Into<String>) -> Self {
        Self {
            total,
            current: 0,
            width: 40,
            label: label.into(),
            bar_char: '█',
            empty_char: '░',
            show_percentage: true,
            show_count: true,
        }
    }

    /// Advance progress.
    pub fn advance(&mut self, n: u64) {
        self.current = (self.current + n).min(self.total);
    }

    /// Set progress to a specific value.
    pub fn set(&mut self, n: u64) {
        self.current = n.min(self.total);
    }

    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.current as f64 / self.total as f64
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.current >= self.total
    }

    /// Render the progress bar to a string.
    #[must_use]
    pub fn render(&self) -> String {
        let frac = self.fraction();
        let filled = (frac * self.width as f64) as usize;
        let empty = self.width.saturating_sub(filled);
        let bar: String = std::iter::repeat_n(self.bar_char, filled)
            .chain(std::iter::repeat_n(self.empty_char, empty))
            .collect();

        let mut parts = vec![format!("{} [{}]", self.label, bar)];
        if self.show_percentage {
            parts.push(format!("{:.1}%", frac * 100.0));
        }
        if self.show_count {
            parts.push(format!("{}/{}", self.current, self.total));
        }
        parts.join(" ")
    }
}

// ─── OutputRenderer ──────────────────────────────────────────────────────────

/// Central renderer that dispatches to the appropriate format handler.
pub struct OutputRenderer {
    pub format: RenderFormat,
    pub theme: ColorTheme,
    pub indent: usize,
    pub compact: bool,
}

impl OutputRenderer {
    /// Create a renderer with the given format.
    #[must_use]
    pub const fn new(format: RenderFormat) -> Self {
        Self {
            format,
            theme: ColorTheme::no_color(),
            indent: 2,
            compact: false,
        }
    }

    #[must_use]
    pub fn with_theme(mut self, theme: ColorTheme) -> Self {
        self.theme = theme;
        self
    }

    #[must_use]
    pub fn with_color(mut self) -> Self {
        self.theme = ColorTheme::default_dark();
        self
    }

    #[must_use]
    pub const fn compact(mut self) -> Self {
        self.compact = true;
        self
    }

    /// Render a JSON value according to the current format.
    #[must_use]
    pub fn render_value(&self, value: &serde_json::Value) -> String {
        match self.format {
            RenderFormat::Json => {
                if self.compact {
                    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
                } else {
                    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
                }
            }
            RenderFormat::Text => self.render_value_text(value, 0),
            RenderFormat::Hex => {
                if let Some(s) = value.as_str() {
                    hex_encode(s.as_bytes())
                } else {
                    let s = value.to_string();
                    hex_encode(s.as_bytes())
                }
            }
            RenderFormat::Markdown => self.render_value_markdown(value),
            _ => self.render_value_text(value, 0),
        }
    }

    fn render_value_text(&self, value: &serde_json::Value, depth: usize) -> String {
        let pad = " ".repeat(depth * self.indent);
        match value {
            serde_json::Value::Object(map) => {
                let mut out = String::new();
                for (k, v) in map {
                    let key_str = self.theme.key(k);
                    let val_str = match v {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            format!("\n{}", self.render_value_text(v, depth + 1))
                        }
                        _ => format!(
                            " {}",
                            self.theme
                                .colorize(&self.theme.value, &v.to_string())
                        ),
                    };
                    out.push_str(&format!("{pad}{key_str}:{val_str}\n"));
                }
                out
            }
            serde_json::Value::Array(arr) => {
                let mut out = String::new();
                for (i, item) in arr.iter().enumerate() {
                    out.push_str(&format!(
                        "{pad}[{i}] {}\n",
                        self.render_value_text(item, depth)
                    ));
                }
                out
            }
            other => format!("{pad}{other}\n"),
        }
    }

    fn render_value_markdown(&self, value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut out = String::new();
                for (k, v) in map {
                    out.push_str(&format!("**{k}**: {v}\n\n"));
                }
                out
            }
            serde_json::Value::Array(arr) => arr.iter().fold(String::new(), |mut acc, v| { use std::fmt::Write; let _ = writeln!(acc, "- {v}"); acc }),
            other => other.to_string(),
        }
    }

    /// Render a key-value map.
    #[must_use]
    pub fn render_kv(&self, data: &HashMap<String, String>) -> String {
        match self.format {
            RenderFormat::Json => {
                let val: serde_json::Value = data
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect::<serde_json::Map<_, _>>()
                    .into();
                if self.compact {
                    serde_json::to_string(&val).unwrap_or_default()
                } else {
                    serde_json::to_string_pretty(&val).unwrap_or_default()
                }
            }
            RenderFormat::Csv => {
                let mut out = "key,value\n".to_string();
                for (k, v) in data {
                    out.push_str(&format!("{k},{v}\n"));
                }
                out
            }
            _ => {
                let mut out = String::new();
                for (k, v) in data {
                    out.push_str(&format!("{}: {}\n", self.theme.key(k), v));
                }
                out
            }
        }
    }

    /// Render a list of strings.
    #[must_use]
    pub fn render_list(&self, items: &[String]) -> String {
        match self.format {
            RenderFormat::Json => {
                let val = serde_json::json!(items);
                serde_json::to_string_pretty(&val).unwrap_or_default()
            }
            RenderFormat::Csv => items.join(",\n"),
            RenderFormat::Markdown => items.iter().fold(String::new(), |mut acc, s| { use std::fmt::Write; let _ = writeln!(acc, "- {s}"); acc }),
            _ => items.iter().enumerate().fold(String::new(), |mut acc, (i, s)| {
                use std::fmt::Write;
                let _ = writeln!(acc, "{:>4}. {s}", i + 1);
                acc
            }),
        }
    }

    /// Render a hex dump of bytes.
    #[must_use]
    pub fn render_hex(&self, bytes: &[u8], base_addr: u64) -> String {
        let mut out = String::new();
        for (i, chunk) in bytes.chunks(16).enumerate() {
            let addr = base_addr + (i as u64 * 16);
            let hex: String = chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            out.push_str(&format!("{addr:08x}  {hex:<47}  |{ascii}|\n"));
        }
        out
    }

    /// Render a section header.
    #[must_use]
    pub fn header(&self, text: &str) -> String {
        match self.format {
            RenderFormat::Markdown => format!("## {text}\n"),
            _ => format!("{}\n{}\n", self.theme.header(text), "─".repeat(text.len())),
        }
    }

    /// Print rendered output to stdout.
    pub fn print(&self, s: &str) {
        print!("{s}");
    }

    /// Print an error message to stderr.
    pub fn print_error(&self, msg: &str) {
        eprintln!("{}", self.theme.error(msg));
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ── RenderFormat ──────────────────────────────────────────────────────────

    #[test]
    fn test_render_format_display() {
        assert_eq!(RenderFormat::Text.to_string(), "Text");
        assert_eq!(RenderFormat::Json.to_string(), "Json");
        assert_eq!(RenderFormat::Hex.to_string(), "Hex");
    }

    #[test]
    fn test_render_format_from_str() {
        assert_eq!(RenderFormat::from_str("json").unwrap(), RenderFormat::Json);
        assert_eq!(
            RenderFormat::from_str("table").unwrap(),
            RenderFormat::Table
        );
        assert_eq!(
            RenderFormat::from_str("md").unwrap(),
            RenderFormat::Markdown
        );
        assert!(RenderFormat::from_str("bad_format").is_err());
    }

    // ── ColorTheme ────────────────────────────────────────────────────────────

    #[test]
    fn test_color_theme_no_color() {
        let t = ColorTheme::no_color();
        assert!(!t.enabled);
        assert_eq!(t.error("x"), "x");
    }

    #[test]
    fn test_color_theme_dark_enabled() {
        let t = ColorTheme::default_dark();
        assert!(t.enabled);
        let colored = t.header("Hello");
        assert!(colored.contains("Hello"));
        assert!(colored.contains('\x1b'));
    }

    #[test]
    fn test_color_theme_colorize_disabled() {
        let t = ColorTheme::no_color();
        assert_eq!(t.colorize("\x1b[1m", "text"), "text");
    }

    #[test]
    fn test_color_helpers() {
        let t = ColorTheme::no_color();
        assert_eq!(t.key("k"), "k");
        assert_eq!(t.success("ok"), "ok");
        assert_eq!(t.warning("warn"), "warn");
        assert_eq!(t.info("info"), "info");
        assert_eq!(t.dim("dim"), "dim");
    }

    // ── TableColumn ───────────────────────────────────────────────────────────

    #[test]
    fn test_column_render_cell_left() {
        let col = TableColumn::new("Header", 10);
        let rendered = col.render_cell("hello");
        assert_eq!(rendered.len(), 10);
        assert!(rendered.starts_with("hello"));
    }

    #[test]
    fn test_column_render_cell_right() {
        let col = TableColumn::new("H", 10).right();
        let rendered = col.render_cell("val");
        assert_eq!(rendered.len(), 10);
        assert!(rendered.ends_with("val"));
    }

    #[test]
    fn test_column_render_cell_truncate() {
        let col = TableColumn::new("H", 5);
        let rendered = col.render_cell("abcdefghij");
        assert_eq!(rendered.chars().count(), 5);
    }

    // ── TableLayout ───────────────────────────────────────────────────────────

    #[test]
    fn test_table_render_headers() {
        let table = TableLayout::new()
            .with_column(TableColumn::new("Name", 10))
            .with_column(TableColumn::new("Value", 10));
        let rendered = table.render();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("Value"));
    }

    #[test]
    fn test_table_render_row() {
        let mut table = TableLayout::new()
            .with_column(TableColumn::new("A", 10))
            .with_column(TableColumn::new("B", 10));
        table.add_row(vec!["hello".to_string(), "world".to_string()]);
        let rendered = table.render();
        assert!(rendered.contains("hello"));
        assert!(rendered.contains("world"));
    }

    #[test]
    fn test_table_row_count() {
        let mut table = TableLayout::new();
        assert_eq!(table.row_count(), 0);
        table.add_row(vec![]);
        assert_eq!(table.row_count(), 1);
    }

    // ── TreeNode / TreeView ───────────────────────────────────────────────────

    #[test]
    fn test_tree_node_total_nodes() {
        let root = TreeNode::new("root")
            .with_child(TreeNode::new("child1"))
            .with_child(TreeNode::new("child2").with_child(TreeNode::new("grandchild")));
        assert_eq!(root.total_nodes(), 4);
    }

    #[test]
    fn test_tree_view_render() {
        let root = TreeNode::new("root").with_child(TreeNode::new("child"));
        let tv = TreeView::new().with_root(root);
        let rendered = tv.render();
        assert!(rendered.contains("root"));
        assert!(rendered.contains("child"));
    }

    #[test]
    fn test_tree_view_empty() {
        let tv = TreeView::new();
        assert_eq!(tv.render(), "");
    }

    #[test]
    fn test_tree_view_metadata() {
        let node = TreeNode::new("func_0x1000")
            .with_meta("type", "void")
            .with_meta("size", "42");
        let mut tv = TreeView::new();
        tv.show_metadata = true;
        tv.set_root(node);
        let rendered = tv.render();
        assert!(rendered.contains("func_0x1000"));
    }

    // ── ProgressDisplay ───────────────────────────────────────────────────────

    #[test]
    fn test_progress_display_new() {
        let p = ProgressDisplay::new(100, "Loading");
        assert_eq!(p.fraction(), 0.0);
        assert!(!p.is_complete());
    }

    #[test]
    fn test_progress_display_advance() {
        let mut p = ProgressDisplay::new(10, "x");
        p.advance(5);
        assert!((p.fraction() - 0.5).abs() < 0.01);
        p.advance(10); // cannot exceed total
        assert!(p.is_complete());
    }

    #[test]
    fn test_progress_display_set() {
        let mut p = ProgressDisplay::new(100, "x");
        p.set(75);
        assert!((p.fraction() - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_progress_display_render() {
        let mut p = ProgressDisplay::new(100, "Analyzing");
        p.set(50);
        let rendered = p.render();
        assert!(rendered.contains("Analyzing"));
        assert!(rendered.contains("50.0%"));
    }

    #[test]
    fn test_progress_display_complete() {
        let mut p = ProgressDisplay::new(10, "x");
        p.set(10);
        assert!(p.is_complete());
    }

    #[test]
    fn test_progress_zero_total() {
        let p = ProgressDisplay::new(0, "x");
        assert!((p.fraction() - 1.0).abs() < 0.01);
    }

    // ── OutputRenderer ────────────────────────────────────────────────────────

    #[test]
    fn test_render_json() {
        let r = OutputRenderer::new(RenderFormat::Json);
        let val = serde_json::json!({"key": "value"});
        let out = r.render_value(&val);
        assert!(out.contains("key"));
        assert!(out.contains("value"));
    }

    #[test]
    fn test_render_json_compact() {
        let r = OutputRenderer::new(RenderFormat::Json).compact();
        let val = serde_json::json!({"a": 1});
        let out = r.render_value(&val);
        assert!(!out.contains('\n'));
    }

    #[test]
    fn test_render_text_object() {
        let r = OutputRenderer::new(RenderFormat::Text);
        let val = serde_json::json!({"arch": "x86_64"});
        let out = r.render_value(&val);
        assert!(out.contains("arch"));
        assert!(out.contains("x86_64"));
    }

    #[test]
    fn test_render_hex_format() {
        let r = OutputRenderer::new(RenderFormat::Hex);
        let val = serde_json::json!("hello");
        let out = r.render_value(&val);
        assert!(out.contains("68")); // 'h' = 0x68
    }

    #[test]
    fn test_render_kv_text() {
        let r = OutputRenderer::new(RenderFormat::Text);
        let mut kv = HashMap::new();
        kv.insert("arch".to_string(), "x86_64".to_string());
        let out = r.render_kv(&kv);
        assert!(out.contains("arch"));
    }

    #[test]
    fn test_render_kv_json() {
        let r = OutputRenderer::new(RenderFormat::Json);
        let mut kv = HashMap::new();
        kv.insert("k".to_string(), "v".to_string());
        let out = r.render_kv(&kv);
        let _: serde_json::Value = serde_json::from_str(&out).unwrap();
    }

    #[test]
    fn test_render_list_text() {
        let r = OutputRenderer::new(RenderFormat::Text);
        let items = vec!["a".to_string(), "b".to_string()];
        let out = r.render_list(&items);
        assert!(out.contains("1. a"));
        assert!(out.contains("2. b"));
    }

    #[test]
    fn test_render_list_markdown() {
        let r = OutputRenderer::new(RenderFormat::Markdown);
        let items = vec!["item1".to_string()];
        let out = r.render_list(&items);
        assert!(out.contains("- item1"));
    }

    #[test]
    fn test_render_hex_dump() {
        let r = OutputRenderer::new(RenderFormat::Text);
        let bytes = b"Hello, World!";
        let hex = r.render_hex(bytes, 0x1000);
        assert!(hex.contains("00001000"));
        assert!(hex.contains("Hello"));
    }

    #[test]
    fn test_render_header() {
        let r = OutputRenderer::new(RenderFormat::Text);
        let h = r.header("Functions");
        assert!(h.contains("Functions"));
    }

    #[test]
    fn test_render_header_markdown() {
        let r = OutputRenderer::new(RenderFormat::Markdown);
        let h = r.header("Summary");
        assert!(h.starts_with("## Summary"));
    }

    #[test]
    fn test_renderer_with_color() {
        let r = OutputRenderer::new(RenderFormat::Text).with_color();
        assert!(r.theme.enabled);
    }
}
