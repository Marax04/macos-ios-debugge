//! `table_renderer` — Rich terminal table rendering for `RustRE`.
//!
//! Column alignment, colour coding, sorting, filtering, pagination,
//! CSV/JSON export from table data, and dynamic column widths.

use std::cmp::Ordering;
use std::fmt;
use std::io::{self};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the table renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    /// A column index is out of range.
    ColumnOutOfRange(usize),
    /// Row cell count does not match header count.
    RowWidthMismatch { expected: usize, actual: usize },
    /// Sort key column name not found.
    SortKeyNotFound(String),
    /// An invalid page number was requested.
    InvalidPage { page: usize, total_pages: usize },
    /// An I/O error occurred while writing output.
    Io(String),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ColumnOutOfRange(i)          => write!(f, "column index out of range: {i}"),
            Self::RowWidthMismatch{expected,actual} => write!(f, "row has {actual} cells, expected {expected}"),
            Self::SortKeyNotFound(k)           => write!(f, "sort key not found: {k}"),
            Self::InvalidPage{page, total_pages} => write!(f, "page {page} out of range (total {total_pages})"),
            Self::Io(e)                        => write!(f, "I/O error: {e}"),
        }
    }
}

// ── Column alignment ──────────────────────────────────────────────────────────

/// Column alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum Align {
    #[default]
    Left,
    Right,
    Center,
}


/// Column data type (affects sorting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum ColType {
    #[default]
    Text,
    Integer,
    HexAddress,
    Float,
    Bytes,
}


// ── Cell ──────────────────────────────────────────────────────────────────────

/// A typed cell value.
#[derive(Debug, Clone, PartialEq)]
pub enum CellValue {
    Text(String),
    Int(i64),
    UInt(u64),
    Float(f64),
    Hex(u64),
    Bool(bool),
    Bytes(u64),
}

impl CellValue {
    /// Display string for the cell.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Text(s)  => s.clone(),
            Self::Int(n)   => n.to_string(),
            Self::UInt(n)  => n.to_string(),
            Self::Float(f) => format!("{f:.4}"),
            Self::Hex(h)   => format!("{h:#x}"),
            Self::Bool(b)  => b.to_string(),
            Self::Bytes(n) => fmt_bytes(*n),
        }
    }

    /// Sort key (numeric where possible).
    #[must_use]
    pub fn sort_key(&self) -> SortKey {
        match self {
            Self::Int(n)  => SortKey::Int(*n),
            Self::UInt(n) => SortKey::Int(*n as i64),
            Self::Hex(h)  => SortKey::Int(*h as i64),
            Self::Float(f)=> SortKey::Float(*f),
            _ => SortKey::Str(self.display()),
        }
    }
}

impl From<&str>  for CellValue { fn from(s: &str)  -> Self { Self::Text(s.into()) } }
impl From<String> for CellValue { fn from(s: String) -> Self { Self::Text(s) } }
impl From<i64>   for CellValue { fn from(n: i64)   -> Self { Self::Int(n) } }
impl From<u64>   for CellValue { fn from(n: u64)   -> Self { Self::UInt(n) } }
impl From<bool>  for CellValue { fn from(b: bool)  -> Self { Self::Bool(b) } }
impl From<f64>   for CellValue { fn from(f: f64)   -> Self { Self::Float(f) } }

fn fmt_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut val = n as f64;
    let mut u = 0;
    while val >= 1024.0 && u + 1 < UNITS.len() { val /= 1024.0; u += 1; }
    if u == 0 { format!("{n} B") } else { format!("{val:.1} {}", UNITS[u]) }
}

// ── Sort key ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SortKey {
    Int(i64),
    Float(f64),
    Str(String),
}

impl Eq for SortKey {}

impl PartialOrd for SortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for SortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a.cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
            (Self::Str(a), Self::Str(b)) => a.cmp(b),
            (Self::Int(a), Self::Float(b)) => (*a as f64).partial_cmp(b).unwrap_or(Ordering::Equal),
            (Self::Float(a), Self::Int(b)) => a.partial_cmp(&(*b as f64)).unwrap_or(Ordering::Equal),
            (Self::Str(a), Self::Int(b)) => a.cmp(&b.to_string()),
            (Self::Int(a), Self::Str(b)) => a.to_string().cmp(b),
            _ => self.clone().into_str().cmp(&other.clone().into_str()),
        }
    }
}

impl SortKey {
    fn into_str(self) -> String {
        match self {
            Self::Int(n) => n.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Str(s) => s,
        }
    }
}

// ── Column definition ─────────────────────────────────────────────────────────

/// Definition of a single table column.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// Column header name.
    pub name: String,
    /// Column alignment.
    pub align: Align,
    /// Column data type (affects sorting).
    pub col_type: ColType,
    /// Minimum column width.
    pub min_width: usize,
    /// Maximum column width (0 = unlimited).
    pub max_width: usize,
    /// Whether this column is visible.
    pub visible: bool,
    /// ANSI colour code for column values (empty = default).
    pub value_color: &'static str,
}

impl ColumnDef {
    /// Create a simple left-aligned text column.
    #[must_use]
    pub fn text(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            align: Align::Left,
            col_type: ColType::Text,
            min_width: 4,
            max_width: 0,
            visible: true,
            value_color: "",
        }
    }

    /// Create a right-aligned integer column.
    #[must_use]
    pub fn integer(name: impl Into<String>) -> Self {
        Self { align: Align::Right, col_type: ColType::Integer, ..Self::text(name) }
    }

    /// Create a right-aligned hex address column.
    #[must_use]
    pub fn hex(name: impl Into<String>) -> Self {
        Self { align: Align::Right, col_type: ColType::HexAddress, value_color: "\x1b[33m", ..Self::text(name) }
    }

    /// Create a right-aligned bytes column.
    #[must_use]
    pub fn bytes(name: impl Into<String>) -> Self {
        Self { align: Align::Right, col_type: ColType::Bytes, ..Self::text(name) }
    }

    /// Set `max_width`.
    #[must_use]
    pub const fn max_width(mut self, w: usize) -> Self { self.max_width = w; self }

    /// Set `value_color`.
    #[must_use]
    pub const fn color(mut self, c: &'static str) -> Self { self.value_color = c; self }

    /// Set hidden.
    #[must_use]
    pub const fn hidden(mut self) -> Self { self.visible = false; self }
}

// ── Row ───────────────────────────────────────────────────────────────────────

/// A single table row.
#[derive(Debug, Clone)]
pub struct Row {
    pub cells: Vec<CellValue>,
    /// Optional row-level highlight colour.
    pub highlight: Option<&'static str>,
}

impl Row {
    /// Create a row from any iterator of `Into<CellValue>`.
    #[must_use]
    pub fn new(cells: impl IntoIterator<Item = CellValue>) -> Self {
        Self { cells: cells.into_iter().collect(), highlight: None }
    }

    /// Set a row-level highlight colour.
    #[must_use]
    pub const fn highlighted(mut self, color: &'static str) -> Self {
        self.highlight = Some(color);
        self
    }

    /// Build from string slices.
    #[must_use]
    pub fn from_strs(cells: &[&str]) -> Self {
        Self::new(cells.iter().map(|s| CellValue::Text((*s).into())))
    }
}

// ── Sort / filter options ─────────────────────────────────────────────────────

/// Sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder { Ascending, Descending }

/// A sort specification.
#[derive(Debug, Clone)]
pub struct SortSpec {
    pub column_idx: usize,
    pub order: SortOrder,
}

/// A predicate to filter rows.
pub struct Filter {
    /// Column index to match against.
    pub column_idx: usize,
    /// Substring that must appear in the cell's display value.
    pub substring: String,
    /// Case sensitive matching.
    pub case_sensitive: bool,
}

impl Filter {
    /// Return `true` if `row` matches this filter.
    #[must_use]
    pub fn matches(&self, row: &Row) -> bool {
        let cell = match row.cells.get(self.column_idx) {
            Some(c) => c.display(),
            None => return false,
        };
        if self.case_sensitive {
            cell.contains(self.substring.as_str())
        } else {
            cell.to_lowercase().contains(&self.substring.to_lowercase())
        }
    }
}

// ── Render configuration ──────────────────────────────────────────────────────

/// Configuration for table rendering.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Show a row-count footer.
    pub show_footer: bool,
    /// Enable ANSI colour output.
    pub color: bool,
    /// Draw horizontal separators between rows.
    pub row_separator: bool,
    /// Zebra-stripe even rows.
    pub zebra: bool,
    /// Zebra colour (applied to even data rows).
    pub zebra_color: &'static str,
    /// Header colour.
    pub header_color: &'static str,
    /// Separator colour.
    pub sep_color: &'static str,
    /// Border style.
    pub border: BorderStyle,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            show_footer: true,
            color: true,
            row_separator: false,
            zebra: false,
            zebra_color: "\x1b[2m",
            header_color: "\x1b[1;36m",
            sep_color: "\x1b[2m",
            border: BorderStyle::Plain,
        }
    }
}

/// Table border style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorderStyle {
    /// Simple `+`, `-`, `|` borders.
    Plain,
    /// Unicode box-drawing characters.
    Unicode,
    /// No border characters at all.
    Minimal,
    /// Markdown-compatible pipe table.
    Markdown,
}

// ── The Table ─────────────────────────────────────────────────────────────────

/// A rich sortable, filterable, pageable table.
pub struct RichTable {
    columns: Vec<ColumnDef>,
    rows: Vec<Row>,
    sort: Option<SortSpec>,
    filters: Vec<Filter>,
    page_size: usize,
    config: RenderConfig,
    title: Option<String>,
}

impl RichTable {
    /// Create a table with the given column definitions.
    #[must_use]
    pub fn new(columns: Vec<ColumnDef>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            sort: None,
            filters: Vec::new(),
            page_size: 0,
            config: RenderConfig::default(),
            title: None,
        }
    }

    /// Set the render configuration.
    #[must_use]
    pub const fn with_config(mut self, config: RenderConfig) -> Self { self.config = config; self }

    /// Set a title shown above the table.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self { self.title = Some(title.into()); self }

    /// Set a page size (0 = no paging).
    #[must_use]
    pub const fn with_page_size(mut self, size: usize) -> Self { self.page_size = size; self }

    /// Append a row.
    ///
    /// # Errors
    /// Returns `TableError::RowWidthMismatch` if the cell count is wrong.
    pub fn push(&mut self, row: Row) -> Result<(), TableError> {
        let expected = self.visible_count();
        let actual = row.cells.len();
        if actual != expected {
            return Err(TableError::RowWidthMismatch { expected, actual });
        }
        self.rows.push(row);
        Ok(())
    }

    /// Append a row, truncating/padding to fit if needed.
    pub fn push_flex(&mut self, mut row: Row) {
        let expected = self.visible_count();
        while row.cells.len() < expected { row.cells.push(CellValue::Text(String::new())); }
        row.cells.truncate(expected);
        self.rows.push(row);
    }

    /// Set the sort specification.
    pub const fn sort_by(&mut self, spec: SortSpec) { self.sort = Some(spec); }

    /// Sort by column name.
    ///
    /// # Errors
    /// Returns `TableError::SortKeyNotFound` if the column is not found.
    pub fn sort_by_name(&mut self, name: &str, order: SortOrder) -> Result<(), TableError> {
        let idx = self.visible_columns().iter().position(|(_, col)| col.name == name)
            .ok_or_else(|| TableError::SortKeyNotFound(name.into()))?;
        self.sort = Some(SortSpec { column_idx: idx, order });
        Ok(())
    }

    /// Add a filter.
    pub fn add_filter(&mut self, filter: Filter) { self.filters.push(filter); }

    /// Clear all filters.
    pub fn clear_filters(&mut self) { self.filters.clear(); }

    /// Number of visible columns.
    #[must_use]
    pub fn visible_count(&self) -> usize {
        self.columns.iter().filter(|c| c.visible).count()
    }

    /// Returns (`original_index`, column) for each visible column.
    #[must_use]
    fn visible_columns(&self) -> Vec<(usize, &ColumnDef)> {
        self.columns.iter().enumerate().filter(|(_, c)| c.visible).collect()
    }

    /// Apply filters and sort, returning a filtered+sorted view.
    #[must_use]
    fn prepare_rows(&self) -> Vec<&Row> {
        let mut rows: Vec<&Row> = self.rows.iter()
            .filter(|row| self.filters.iter().all(|f| f.matches(row)))
            .collect();

        if let Some(ref spec) = self.sort {
            rows.sort_by(|a, b| {
                let ak = a.cells.get(spec.column_idx).map_or(SortKey::Str(String::new()), CellValue::sort_key);
                let bk = b.cells.get(spec.column_idx).map_or(SortKey::Str(String::new()), CellValue::sort_key);
                let cmp = ak.cmp(&bk);
                if spec.order == SortOrder::Descending { cmp.reverse() } else { cmp }
            });
        }
        rows
    }

    /// Total row count (before filtering).
    #[must_use]
    pub const fn row_count(&self) -> usize { self.rows.len() }

    /// Filtered row count.
    #[must_use]
    pub fn filtered_count(&self) -> usize { self.prepare_rows().len() }

    /// Render the full table to a `String`.
    #[must_use]
    pub fn render(&self) -> String {
        let rows = self.prepare_rows();
        self.render_rows(&rows, 0, rows.len())
    }

    /// Render a single page (1-indexed).
    ///
    /// # Errors
    /// Returns `TableError::InvalidPage` if `page` is out of range.
    pub fn render_page(&self, page: usize) -> Result<String, TableError> {
        let rows = self.prepare_rows();
        let ps = if self.page_size == 0 { rows.len().max(1) } else { self.page_size };
        let total_pages = rows.len().div_ceil(ps);
        let total_pages = total_pages.max(1);
        if page == 0 || page > total_pages {
            return Err(TableError::InvalidPage { page, total_pages });
        }
        let start = (page - 1) * ps;
        let end = (start + ps).min(rows.len());
        let mut out = self.render_rows(&rows, start, end);
        if self.page_size > 0 {
            out.push_str(&format!("  Page {page}/{total_pages}\n"));
        }
        Ok(out)
    }

    fn render_rows(&self, rows: &[&Row], start: usize, end: usize) -> String {
        let vcols = self.visible_columns();
        let c = |code: &'static str| if self.config.color { code } else { "" };

        // Compute column widths.
        let mut widths: Vec<usize> = vcols.iter().map(|(_, col)| {
            
            col.min_width.max(col.name.len())
        }).collect();

        for row in rows.iter().skip(start).take(end - start) {
            for (ci, &(_orig_idx, _)) in vcols.iter().enumerate() {
                let cell = row.cells.get(ci).map(CellValue::display).unwrap_or_default();
                let cell_len = visible_len(&cell);
                widths[ci] = widths[ci].max(cell_len);
            }
        }

        // Apply max_width constraints.
        for (ci, (_, col)) in vcols.iter().enumerate() {
            if col.max_width > 0 { widths[ci] = widths[ci].min(col.max_width); }
        }

        let (sep_l, sep_m, sep_r, sep_h, head_sep_l, head_sep_m, head_sep_r) = match self.config.border {
            BorderStyle::Plain    => ("+", "+", "+", "-", "+", "+", "+"),
            BorderStyle::Unicode  => ("├", "┼", "┤", "─", "├", "┼", "┤"),
            BorderStyle::Minimal  => (" ", " ", " ", " ", "-", "+", "-"),
            BorderStyle::Markdown => ("|", "|", "|", "-", "|", "|", "|"),
        };

        let make_hline = |l: &str, m: &str, r: &str, h: &str| -> String {
            let segs: Vec<String> = widths.iter().map(|w| h.repeat(w + 2)).collect();
            format!("{}{}{}\n", l, segs.join(m), r)
        };

        let mut out = String::new();

        // Title.
        if let Some(ref title) = self.title {
            out.push_str(&format!("{}{}{}\n", c("\x1b[1;35m"), title, c("\x1b[0m")));
        }

        let top_sep = match self.config.border {
            BorderStyle::Plain   => make_hline("+", "+", "+", "-"),
            BorderStyle::Unicode => make_hline("┌", "┬", "┐", "─"),
            _ => String::new(),
        };
        if !top_sep.is_empty() { out.push_str(&format!("{}{}{}", c("\x1b[2m"), top_sep, c("\x1b[0m"))); }

        // Header row.
        let header_cells: Vec<String> = vcols.iter().enumerate().map(|(ci, (_, col))| {
            pad_cell(&col.name, widths[ci], Align::Left)
        }).collect();
        let col_sep = match self.config.border {
            BorderStyle::Markdown => "|",
            _ => "|",
        };
        out.push_str(&format!("{}{col_sep} {} {col_sep}{}\n",
            c("\x1b[1;36m"),
            header_cells.join(&format!("{} {col_sep}{} ", c("\x1b[0m"), c("\x1b[1;36m"))),
            c("\x1b[0m"),
        ));

        // Header separator.
        let head_sep = make_hline(head_sep_l, head_sep_m, head_sep_r, "-");
        out.push_str(&format!("{}{}{}", c("\x1b[2m"), head_sep, c("\x1b[0m")));

        // Data rows.
        for (ri, row) in rows.iter().enumerate().skip(start).take(end - start) {
            let row_color = row.highlight.unwrap_or(
                if self.config.zebra && ri % 2 == 1 { self.config.zebra_color } else { "" }
            );
            let cells: Vec<String> = vcols.iter().enumerate().map(|(ci, (_, col))| {
                let cell = row.cells.get(ci).map(CellValue::display).unwrap_or_default();
                let truncated = truncate_cell(&cell, widths[ci]);
                let padded = pad_cell(&truncated, widths[ci], col.align);
                format!("{}{}{}", col.value_color, padded, if col.value_color.is_empty() { "" } else { "\x1b[0m" })
            }).collect();
            out.push_str(&format!("{row_color}|{} {}{}|{}\n",
                cells.join(" | "), "", c("\x1b[0m"), if row_color.is_empty() { "" } else { "\x1b[0m" },
            ));
            if self.config.row_separator && ri + 1 < end {
                out.push_str(&format!("{}{}{}", c("\x1b[2m"), make_hline(sep_l, sep_m, sep_r, sep_h), c("\x1b[0m")));
            }
        }

        // Bottom border.
        let bot_sep = match self.config.border {
            BorderStyle::Plain   => make_hline("+", "+", "+", "-"),
            BorderStyle::Unicode => make_hline("└", "┴", "┘", "─"),
            _ => make_hline("+", "+", "+", "-"),
        };
        out.push_str(&format!("{}{}{}", c("\x1b[2m"), bot_sep, c("\x1b[0m")));

        // Footer.
        if self.config.show_footer {
            let total = self.row_count();
            let shown = end - start;
            let filtered = self.filtered_count();
            if total == filtered {
                out.push_str(&format!("  {}{shown}/{total} rows{}\n", c("\x1b[2m"), c("\x1b[0m")));
            } else {
                out.push_str(&format!("  {}{shown}/{filtered} rows (filtered from {total}){}\n",
                    c("\x1b[2m"), c("\x1b[0m")));
            }
        }
        out
    }

    /// Render as CSV.
    #[must_use]
    pub fn render_csv(&self) -> String {
        let vcols = self.visible_columns();
        let rows = self.prepare_rows();
        let mut out = vcols.iter().map(|(_, c)| csv_esc(&c.name)).collect::<Vec<_>>().join(",");
        out.push('\n');
        for row in rows {
            let line = vcols.iter().enumerate()
                .map(|(ci, _)| csv_esc(&row.cells.get(ci).map(CellValue::display).unwrap_or_default()))
                .collect::<Vec<_>>().join(",");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    /// Render as JSON array of objects.
    #[must_use]
    pub fn render_json(&self, pretty: bool) -> String {
        let vcols = self.visible_columns();
        let rows = self.prepare_rows();
        let indent = if pretty { "  " } else { "" };
        let nl = if pretty { "\n" } else { "" };
        let mut out = String::from("[");
        out.push_str(nl);
        for (ri, row) in rows.iter().enumerate() {
            out.push_str(indent);
            out.push('{');
            out.push_str(nl);
            let pairs: Vec<String> = vcols.iter().enumerate().map(|(ci, (_, col))| {
                let val = row.cells.get(ci).map(CellValue::display).unwrap_or_default();
                let val_escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
                if pretty {
                    format!("    \"{}\": \"{}\"", col.name, val_escaped)
                } else {
                    format!("\"{}\":\"{}\"", col.name, val_escaped)
                }
            }).collect();
            out.push_str(&pairs.join(if pretty { ",\n" } else { "," }));
            out.push_str(nl);
            out.push_str(indent);
            out.push('}');
            if ri + 1 < rows.len() { out.push(','); }
            out.push_str(nl);
        }
        out.push(']');
        out.push_str(nl);
        out
    }

    /// Render as Markdown pipe table.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let vcols = self.visible_columns();
        let rows = self.prepare_rows();

        let mut widths: Vec<usize> = vcols.iter().map(|(_, c)| c.name.len().max(3)).collect();
        for row in &rows {
            for (ci, _) in vcols.iter().enumerate() {
                let w = row.cells.get(ci).map_or(0, |c| c.display().len());
                widths[ci] = widths[ci].max(w);
            }
        }

        let mut out = String::new();
        // Header.
        let headers: Vec<String> = vcols.iter().enumerate()
            .map(|(ci, (_, col))| format!(" {:<w$} ", col.name, w = widths[ci]))
            .collect();
        out.push_str(&format!("|{}|\n", headers.join("|")));
        // Separator.
        let seps: Vec<String> = widths.iter().map(|w| format!(" {} ", "-".repeat(*w))).collect();
        out.push_str(&format!("|{}|\n", seps.join("|")));
        // Rows.
        for row in rows {
            let cells: Vec<String> = vcols.iter().enumerate()
                .map(|(ci, (_, col))| {
                    let val = row.cells.get(ci).map(CellValue::display).unwrap_or_default();
                    
                    match col.align {
                        Align::Left   => format!(" {:<w$} ", val, w = widths[ci]),
                        Align::Right  => format!(" {:>w$} ", val, w = widths[ci]),
                        Align::Center => format!(" {:^w$} ", val, w = widths[ci]),
                    }
                })
                .collect();
            out.push_str(&format!("|{}|\n", cells.join("|")));
        }
        out
    }

    /// Write the full render to `w`.
    ///
    /// # Errors
    /// Returns `TableError::Io` on write failure.
    pub fn print(&self, w: &mut dyn io::Write) -> Result<(), TableError> {
        let rendered = self.render();
        w.write_all(rendered.as_bytes()).map_err(|e| TableError::Io(e.to_string()))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn visible_len(s: &str) -> usize {
    // Strip ANSI escape sequences for width calculation.
    let mut len = 0;
    let mut iter = s.chars().peekable();
    while let Some(ch) = iter.next() {
        if ch == '\x1b' {
            // Skip until 'm'.
            for c in iter.by_ref() { if c == 'm' { break; } }
        } else {
            len += 1;
        }
    }
    len
}

fn pad_cell(s: &str, width: usize, align: Align) -> String {
    let vlen = visible_len(s);
    let pad = width.saturating_sub(vlen);
    match align {
        Align::Left   => format!("{s}{}", " ".repeat(pad)),
        Align::Right  => format!("{}{s}", " ".repeat(pad)),
        Align::Center => {
            let lpad = pad / 2;
            let rpad = pad - lpad;
            format!("{}{s}{}", " ".repeat(lpad), " ".repeat(rpad))
        }
    }
}

fn truncate_cell(s: &str, max: usize) -> String {
    // `saturating_sub` guarded the underflow but not the char boundary:
    // `&s[..n]` panics when the cut lands inside a multi-byte character. Cell
    // width is a character count anyway, not a byte count.
    if max == 0 { return s.into(); }
    if s.chars().count() <= max { s.into() }
    else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn csv_esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.into()
    }
}

// ── Convenience builder ───────────────────────────────────────────────────────

/// Build a `RichTable` for RE-specific symbol lists.
#[must_use]
pub fn symbol_table(color: bool) -> RichTable {
    let cols = vec![
        ColumnDef::hex("Address"),
        ColumnDef::text("Name").color("\x1b[1m").max_width(64),
        ColumnDef::text("Kind"),
        ColumnDef::bytes("Size"),
        ColumnDef::text("Section"),
    ];
    RichTable::new(cols).with_config(RenderConfig { color, ..Default::default() })
}

/// Build a `RichTable` for disassembly listings.
#[must_use]
pub fn disasm_table(color: bool) -> RichTable {
    let cols = vec![
        ColumnDef::hex("Address"),
        ColumnDef::text("Bytes").color("\x1b[2m"),
        ColumnDef::text("Mnemonic").color("\x1b[33m"),
        ColumnDef::text("Operands"),
        ColumnDef::text("Comment").color("\x1b[2m").max_width(48),
    ];
    RichTable::new(cols).with_config(RenderConfig { color, ..Default::default() })
}

/// Build a `RichTable` for string listings.
#[must_use]
pub fn strings_table(color: bool) -> RichTable {
    let cols = vec![
        ColumnDef::hex("Offset"),
        ColumnDef::text("Encoding"),
        ColumnDef::integer("Length").col_type_int(),
        ColumnDef::text("Value").color("\x1b[32m").max_width(80),
    ];
    RichTable::new(cols).with_config(RenderConfig { color, ..Default::default() })
}

// Helper extension.
trait ColDefExt: Sized {
    fn col_type_int(self) -> Self;
}
impl ColDefExt for ColumnDef {
    fn col_type_int(mut self) -> Self { self.col_type = ColType::Integer; self.align = Align::Right; self }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_cell_never_splits_a_character() {
        // Cells hold demangled symbol names and strings pulled out of binaries,
        // so non-ASCII is routine. Slicing by byte index panicked mid-character.
        for s in [
            "café café café",
            "日本語のシンボル名",
            "🙂🙂🙂🙂🙂",
            "Ludwig_van_Beethoven",
        ] {
            for max in 0..12 {
                let out = truncate_cell(s, max);
                assert!(
                    out.chars().count() <= max.max(s.chars().count()),
                    "truncate_cell({s:?}, {max}) grew the cell"
                );
            }
        }
        assert_eq!(truncate_cell("abcdef", 3), "ab…");
        assert_eq!(truncate_cell("ab", 5), "ab");
    }

    fn make_table() -> RichTable {
        let cols = vec![
            ColumnDef::text("Name"),
            ColumnDef::integer("Size"),
            ColumnDef::text("Type"),
        ];
        RichTable::new(cols).with_config(RenderConfig { color: false, ..Default::default() })
    }

    fn push_row(t: &mut RichTable, name: &str, size: i64, kind: &str) {
        t.push_flex(Row::new(vec![
            CellValue::Text(name.into()),
            CellValue::Int(size),
            CellValue::Text(kind.into()),
        ]));
    }

    #[test]
    fn test_push_and_row_count() {
        let mut t = make_table();
        push_row(&mut t, "main", 128, "func");
        push_row(&mut t, "printf", 0, "import");
        assert_eq!(t.row_count(), 2);
    }

    #[test]
    fn test_render_contains_headers() {
        let mut t = make_table();
        push_row(&mut t, "main", 64, "func");
        let r = t.render();
        assert!(r.contains("Name"));
        assert!(r.contains("Size"));
        assert!(r.contains("Type"));
    }

    #[test]
    fn test_render_contains_data() {
        let mut t = make_table();
        push_row(&mut t, "sub_1000", 32, "func");
        let r = t.render();
        assert!(r.contains("sub_1000"));
    }

    #[test]
    fn test_sort_ascending() {
        let mut t = make_table();
        push_row(&mut t, "z_func", 10, "func");
        push_row(&mut t, "a_func", 20, "func");
        t.sort_by(SortSpec { column_idx: 0, order: SortOrder::Ascending });
        let r = t.render();
        let pos_a = r.find("a_func").unwrap();
        let pos_z = r.find("z_func").unwrap();
        assert!(pos_a < pos_z);
    }

    #[test]
    fn test_sort_descending() {
        let mut t = make_table();
        push_row(&mut t, "z_func", 10, "func");
        push_row(&mut t, "a_func", 20, "func");
        t.sort_by(SortSpec { column_idx: 0, order: SortOrder::Descending });
        let r = t.render();
        let pos_a = r.find("a_func").unwrap();
        let pos_z = r.find("z_func").unwrap();
        assert!(pos_z < pos_a);
    }

    #[test]
    fn test_filter_matches() {
        let mut t = make_table();
        push_row(&mut t, "malloc",   8, "import");
        push_row(&mut t, "free",    0, "import");
        push_row(&mut t, "sub_401", 32, "func");
        t.add_filter(Filter { column_idx: 2, substring: "import".into(), case_sensitive: false });
        assert_eq!(t.filtered_count(), 2);
    }

    #[test]
    fn test_render_csv() {
        let mut t = make_table();
        push_row(&mut t, "test,func", 0, "func");
        let csv = t.render_csv();
        assert!(csv.contains("\"test,func\""));
        assert!(csv.starts_with("Name,Size,Type\n"));
    }

    #[test]
    fn test_render_json() {
        let mut t = make_table();
        push_row(&mut t, "main", 128, "func");
        let json = t.render_json(false);
        assert!(json.starts_with('['));
        assert!(json.contains("\"Name\":\"main\""));
    }

    #[test]
    fn test_render_json_pretty() {
        let mut t = make_table();
        push_row(&mut t, "main", 64, "func");
        let json = t.render_json(true);
        assert!(json.contains("  {"));
    }

    #[test]
    fn test_render_markdown() {
        let mut t = make_table();
        push_row(&mut t, "foo", 1, "data");
        let md = t.render_markdown();
        assert!(md.contains("| Name"));
        assert!(md.contains("| foo"));
        assert!(md.contains("---"));
    }

    #[test]
    fn test_pagination() {
        let mut t = make_table().with_page_size(2);
        for i in 0..5 { push_row(&mut t, &format!("fn{i}"), i as i64, "func"); }
        let page1 = t.render_page(1).unwrap();
        assert!(page1.contains("fn0"));
        let page2 = t.render_page(2).unwrap();
        assert!(page2.contains("fn2"));
        assert!(t.render_page(10).is_err());
    }

    #[test]
    fn test_cell_value_display() {
        assert_eq!(CellValue::Text("hello".into()).display(), "hello");
        assert_eq!(CellValue::Hex(0xff).display(), "0xff");
        assert_eq!(CellValue::Bool(true).display(), "true");
        assert_eq!(CellValue::Bytes(1024).display(), "1.0 KiB");
    }

    #[test]
    fn test_sort_key_ordering() {
        let a = SortKey::Int(10);
        let b = SortKey::Int(20);
        assert!(a < b);
        let c = SortKey::Str("abc".into());
        let d = SortKey::Str("xyz".into());
        assert!(c < d);
    }

    #[test]
    fn test_sort_by_name_not_found() {
        let mut t = make_table();
        let err = t.sort_by_name("NonExistent", SortOrder::Ascending);
        assert!(matches!(err, Err(TableError::SortKeyNotFound(_))));
    }

    #[test]
    fn test_convenience_builders() {
        let _sym  = symbol_table(false);
        let _dis  = disasm_table(false);
        let _str  = strings_table(false);
    }

    #[test]
    fn test_row_width_mismatch() {
        let mut t = make_table();
        let row = Row::from_strs(&["a", "b"]); // 2 cells, expects 3
        let err = t.push(row);
        assert!(matches!(err, Err(TableError::RowWidthMismatch { .. })));
    }
}
