//! Output formatting: table renderer, JSON/YAML/CSV output, colored terminal
//! output, progress bars, and spinner.

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Color Support ────────────────────────────────────────────────────────────

/// Whether to emit ANSI escape codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

thread_local! {
    static COLOR_MODE: std::cell::Cell<ColorMode> = const { std::cell::Cell::new(ColorMode::Auto) };
}

pub fn set_color_mode(mode: ColorMode) {
    COLOR_MODE.with(|m| m.set(mode));
}

#[must_use] 
pub fn color_enabled() -> bool {
    COLOR_MODE.with(|m| match m.get() {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            // Simple heuristic: check if stdout is a tty via env variable.
            std::env::var("NO_COLOR").is_err() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
        }
    })
}

/// ANSI color codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Black, Red, Green, Yellow, Blue, Magenta, Cyan, White,
    BrightBlack, BrightRed, BrightGreen, BrightYellow,
    BrightBlue, BrightMagenta, BrightCyan, BrightWhite,
    Reset,
}

impl Color {
    const fn ansi_code(self) -> &'static str {
        match self {
            Self::Black => "\x1b[30m",
            Self::Red => "\x1b[31m",
            Self::Green => "\x1b[32m",
            Self::Yellow => "\x1b[33m",
            Self::Blue => "\x1b[34m",
            Self::Magenta => "\x1b[35m",
            Self::Cyan => "\x1b[36m",
            Self::White => "\x1b[37m",
            Self::BrightBlack => "\x1b[90m",
            Self::BrightRed => "\x1b[91m",
            Self::BrightGreen => "\x1b[92m",
            Self::BrightYellow => "\x1b[93m",
            Self::BrightBlue => "\x1b[94m",
            Self::BrightMagenta => "\x1b[95m",
            Self::BrightCyan => "\x1b[96m",
            Self::BrightWhite => "\x1b[97m",
            Self::Reset => "\x1b[0m",
        }
    }
}

/// Style attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Bold, Dim, Italic, Underline, Blink, Reverse, Strikethrough,
}

impl Style {
    const fn ansi_code(self) -> &'static str {
        match self {
            Self::Bold => "\x1b[1m",
            Self::Dim => "\x1b[2m",
            Self::Italic => "\x1b[3m",
            Self::Underline => "\x1b[4m",
            Self::Blink => "\x1b[5m",
            Self::Reverse => "\x1b[7m",
            Self::Strikethrough => "\x1b[9m",
        }
    }
}

/// Apply color and optional style to a string.
#[must_use] 
pub fn colorize(text: &str, color: Color, style: Option<Style>) -> String {
    if !color_enabled() {
        return text.to_string();
    }
    let mut out = String::new();
    if let Some(s) = style {
        out.push_str(s.ansi_code());
    }
    out.push_str(color.ansi_code());
    out.push_str(text);
    out.push_str(Color::Reset.ansi_code());
    out
}

#[must_use] 
pub fn bold(text: &str) -> String { colorize(text, Color::White, Some(Style::Bold)) }
#[must_use] 
pub fn red(text: &str) -> String { colorize(text, Color::Red, None) }
#[must_use] 
pub fn green(text: &str) -> String { colorize(text, Color::Green, None) }
#[must_use] 
pub fn yellow(text: &str) -> String { colorize(text, Color::Yellow, None) }
#[must_use] 
pub fn cyan(text: &str) -> String { colorize(text, Color::Cyan, None) }
#[must_use] 
pub fn magenta(text: &str) -> String { colorize(text, Color::Magenta, None) }
#[must_use] 
pub fn dim(text: &str) -> String { colorize(text, Color::BrightBlack, None) }

// ─── Output Format ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Table,
    Json,
    JsonPretty,
    Csv,
    Yaml,
    Plain,
}

impl OutputFormat {
    #[must_use] 
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "table" => Some(Self::Table),
            "json" => Some(Self::Json),
            "json-pretty" | "jsonpretty" => Some(Self::JsonPretty),
            "csv" => Some(Self::Csv),
            "yaml" | "yml" => Some(Self::Yaml),
            "plain" | "text" => Some(Self::Plain),
            _ => None,
        }
    }
}

// ─── Table Renderer ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColAlign {
    Left,
    Right,
    Center,
}

#[derive(Debug, Clone)]
pub struct Column {
    pub header: String,
    pub align: ColAlign,
    pub max_width: Option<usize>,
    pub color: Option<Color>,
}

impl Column {
    pub fn new(header: impl Into<String>) -> Self {
        Self { header: header.into(), align: ColAlign::Left, max_width: None, color: None }
    }

    #[must_use] 
    pub const fn right(mut self) -> Self { self.align = ColAlign::Right; self }
    #[must_use] 
    pub const fn center(mut self) -> Self { self.align = ColAlign::Center; self }
    #[must_use] 
    pub const fn max_width(mut self, w: usize) -> Self { self.max_width = Some(w); self }
    #[must_use] 
    pub const fn color(mut self, c: Color) -> Self { self.color = Some(c); self }
}

#[derive(Debug, Default)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<String>>,
    pub border: bool,
    pub header_color: Option<Color>,
}

impl Table {
    #[must_use] 
    pub const fn new() -> Self {
        Self { columns: Vec::new(), rows: Vec::new(), border: false, header_color: None }
    }

    #[must_use] 
    pub fn with_columns(mut self, cols: Vec<Column>) -> Self {
        self.columns = cols;
        self
    }

    #[must_use] 
    pub const fn with_border(mut self) -> Self { self.border = true; self }

    pub fn add_row(&mut self, row: Vec<impl Into<String>>) {
        self.rows.push(row.into_iter().map(std::convert::Into::into).collect());
    }

    fn col_widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let header_w = col.header.len();
                let data_w = self.rows.iter()
                    .filter_map(|row| row.get(i))
                    .map(std::string::String::len)
                    .max()
                    .unwrap_or(0);
                let w = header_w.max(data_w);
                col.max_width.map_or(w, |m| w.min(m))
            })
            .collect()
    }

    fn format_cell(value: &str, width: usize, align: ColAlign, color: Option<Color>) -> String {
        // Truncate at a character boundary, not a byte boundary, to avoid
        // splitting multibyte UTF-8 codepoints and causing a panic.
        let truncated: String = value.chars().take(width).collect();
        let padded = match align {
            ColAlign::Left => format!("{truncated:<width$}"),
            ColAlign::Right => format!("{truncated:>width$}"),
            ColAlign::Center => {
                let s = truncated.as_str();
                let total_pad = width.saturating_sub(s.chars().count());
                let left = total_pad / 2;
                let right = total_pad - left;
                format!("{:>lw$}{}{:>rw$}", "", s, "", lw = left, rw = right)
            }
        };
        if let Some(c) = color {
            colorize(&padded, c, None)
        } else {
            padded
        }
    }

    #[must_use] 
    pub fn render(&self) -> String {
        let widths = self.col_widths();
        let mut out = String::new();

        let sep = if self.border {
            let line: String = widths.iter().map(|&w| "-".repeat(w + 2)).collect::<Vec<_>>().join("+");
            format!("+{line}+\n")
        } else {
            String::new()
        };

        if self.border {
            out.push_str(&sep);
        }

        // Header row.
        let header_row: String = self.columns.iter().enumerate().map(|(i, col)| {
            let w = widths[i];
            let cell = Self::format_cell(&col.header, w, ColAlign::Left, self.header_color.or(Some(Color::Cyan)));
            if self.border { format!("| {cell} ") } else { format!("{:width$}  ", cell, width = w + 6) }
        }).collect();
        out.push_str(&header_row);
        if self.border { out.push_str("|\n"); } else { out.push('\n'); }

        // Separator.
        if self.border {
            out.push_str(&sep);
        } else {
            let underline: String = widths.iter().map(|&w| "-".repeat(w)).collect::<Vec<_>>().join("  ");
            out.push_str(&underline);
            out.push('\n');
        }

        // Data rows.
        for row in &self.rows {
            let row_str: String = self.columns.iter().enumerate().map(|(i, col)| {
                let val = row.get(i).map_or("", std::string::String::as_str);
                let w = widths[i];
                let cell = Self::format_cell(val, w, col.align, col.color);
                if self.border { format!("| {cell} ") } else { format!("{:width$}  ", cell, width = w + 6) }
            }).collect();
            out.push_str(&row_str);
            if self.border { out.push_str("|\n"); } else { out.push('\n'); }
        }
        if self.border { out.push_str(&sep); }
        out
    }

    /// Convert to CSV string.
    #[must_use] 
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        let headers: Vec<&str> = self.columns.iter().map(|c| c.header.as_str()).collect();
        out.push_str(&csv_row(&headers));
        for row in &self.rows {
            let cells: Vec<&str> = row.iter().map(std::string::String::as_str).collect();
            out.push_str(&csv_row(&cells));
        }
        out
    }

    /// Convert to JSON array of objects.
    #[must_use] 
    pub fn to_json(&self, pretty: bool) -> String {
        let headers: Vec<&str> = self.columns.iter().map(|c| c.header.as_str()).collect();
        let objects: Vec<HashMap<&str, &str>> = self.rows.iter().map(|row| {
            headers.iter().enumerate().filter_map(|(i, &h)| {
                row.get(i).map(|v| (h, v.as_str()))
            }).collect()
        }).collect();
        if pretty {
            serde_json::to_string_pretty(&objects).unwrap_or_default()
        } else {
            serde_json::to_string(&objects).unwrap_or_default()
        }
    }
}

fn csv_row(cells: &[&str]) -> String {
    let escaped: Vec<String> = cells.iter().map(|c| {
        if c.contains(',') || c.contains('"') || c.contains('\n') {
            format!("\"{}\"", c.replace('"', "\"\""))
        } else {
            c.to_string()
        }
    }).collect();
    format!("{}\n", escaped.join(","))
}

// ─── Progress Bar ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ProgressBar {
    pub total: u64,
    pub current: u64,
    pub width: usize,
    pub label: String,
    pub filled_char: char,
    pub empty_char: char,
    start: Instant,
}

impl ProgressBar {
    pub fn new(total: u64, label: impl Into<String>) -> Self {
        Self {
            total,
            current: 0,
            width: 40,
            label: label.into(),
            filled_char: '█',
            empty_char: '░',
            start: Instant::now(),
        }
    }

    pub fn set(&mut self, current: u64) {
        self.current = current.min(self.total);
    }

    pub fn increment(&mut self, delta: u64) {
        self.current = (self.current + delta).min(self.total);
    }

    #[must_use] 
    pub fn percent(&self) -> f64 {
        if self.total == 0 { return 100.0; }
        100.0 * self.current as f64 / self.total as f64
    }

    #[must_use] 
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    #[must_use] 
    pub fn eta(&self) -> Option<Duration> {
        if self.current == 0 { return None; }
        let elapsed = self.elapsed().as_secs_f64();
        let rate = self.current as f64 / elapsed;
        let remaining = (self.total - self.current) as f64;
        Some(Duration::from_secs_f64(remaining / rate))
    }

    #[must_use] 
    pub fn render(&self) -> String {
        let pct = self.percent();
        let filled = (self.width as f64 * pct / 100.0) as usize;
        let empty = self.width - filled;
        let bar: String = std::iter::repeat_n(self.filled_char, filled)
            .chain(std::iter::repeat_n(self.empty_char, empty))
            .collect();
        let eta_str = match self.eta() {
            Some(d) if d.as_secs() < 3600 => format!(" ETA: {:02}:{:02}", d.as_secs() / 60, d.as_secs() % 60),
            Some(_) => " ETA: >1h".to_string(),
            None => String::new(),
        };
        format!("{} [{}] {:>5.1}%{}", self.label, green(&bar), pct, eta_str)
    }

    pub fn print<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write!(w, "\r{}", self.render())?;
        w.flush()
    }

    pub fn finish<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(w, "\r{}", self.render())?;
        w.flush()
    }

    #[must_use] 
    pub const fn is_done(&self) -> bool {
        self.current >= self.total
    }
}

// ─── Spinner ─────────────────────────────────────────────────────────────────

pub struct Spinner {
    frames: Vec<&'static str>,
    index: usize,
    pub label: String,
    start: Instant,
}

impl Spinner {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            index: 0,
            label: label.into(),
            start: Instant::now(),
        }
    }

    pub fn braille(label: impl Into<String>) -> Self {
        Self::new(label)
    }

    pub fn classic(label: impl Into<String>) -> Self {
        let mut s = Self::new(label);
        s.frames = vec!["|", "/", "-", "\\"];
        s
    }

    pub const fn tick(&mut self) {
        self.index = (self.index + 1) % self.frames.len();
    }

    #[must_use] 
    pub fn current_frame(&self) -> &str {
        self.frames[self.index % self.frames.len()]
    }

    #[must_use] 
    pub fn render(&self) -> String {
        let elapsed = self.start.elapsed().as_secs_f64();
        format!("{} {} ({:.1}s)", self.current_frame(), self.label, elapsed)
    }

    pub fn print<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.tick();
        write!(w, "\r{}", self.render())?;
        w.flush()
    }

    pub fn finish<W: Write>(&self, msg: &str, w: &mut W) -> io::Result<()> {
        writeln!(w, "\r{} {}", green("✓"), msg)?;
        w.flush()
    }
}

// ─── Output Formatter ─────────────────────────────────────────────────────────

/// Central formatter: knows the requested output format and handles all rendering.
pub struct Formatter {
    pub format: OutputFormat,
    pub use_color: bool,
    pub indent: usize,
}

impl Formatter {
    #[must_use] 
    pub fn new(format: OutputFormat) -> Self {
        Self { format, use_color: color_enabled(), indent: 0 }
    }

    #[must_use] 
    pub fn table() -> Self { Self::new(OutputFormat::Table) }
    #[must_use] 
    pub fn json() -> Self { Self::new(OutputFormat::Json) }
    #[must_use] 
    pub fn json_pretty() -> Self { Self::new(OutputFormat::JsonPretty) }
    #[must_use] 
    pub fn csv() -> Self { Self::new(OutputFormat::Csv) }
    #[must_use] 
    pub fn plain() -> Self { Self::new(OutputFormat::Plain) }

    pub fn format_value<T: Serialize>(&self, value: &T) -> String {
        match self.format {
            OutputFormat::Json => serde_json::to_string(value).unwrap_or_default(),
            OutputFormat::JsonPretty => serde_json::to_string_pretty(value).unwrap_or_default(),
            OutputFormat::Yaml => serde_json::to_string_pretty(value).unwrap_or_default(), // stub
            _ => serde_json::to_string(value).unwrap_or_default(),
        }
    }

    #[must_use] 
    pub fn format_table(&self, table: &Table) -> String {
        match self.format {
            OutputFormat::Json => table.to_json(false),
            OutputFormat::JsonPretty => table.to_json(true),
            OutputFormat::Csv => table.to_csv(),
            _ => table.render(),
        }
    }

    /// Print a key-value pair.
    #[must_use] 
    pub fn kv(&self, key: &str, value: &str) -> String {
        if self.use_color {
            format!("{}: {}", cyan(key), value)
        } else {
            format!("{key}: {value}")
        }
    }

    /// Print a section header.
    #[must_use] 
    pub fn section(&self, title: &str) -> String {
        if self.use_color {
            format!("\n{}\n{}", bold(title), "─".repeat(title.len()))
        } else {
            format!("\n{}\n{}", title, "─".repeat(title.len()))
        }
    }

    /// Print a success message.
    #[must_use] 
    pub fn success(&self, msg: &str) -> String {
        if self.use_color {
            format!("{} {}", green("✓"), msg)
        } else {
            format!("[OK] {msg}")
        }
    }

    /// Print a warning.
    #[must_use] 
    pub fn warning(&self, msg: &str) -> String {
        if self.use_color {
            format!("{} {}", yellow("⚠"), msg)
        } else {
            format!("[WARN] {msg}")
        }
    }

    /// Print an error.
    #[must_use] 
    pub fn error(&self, msg: &str) -> String {
        if self.use_color {
            format!("{} {}", red("✗"), msg)
        } else {
            format!("[ERROR] {msg}")
        }
    }

    #[must_use] 
    pub fn info(&self, msg: &str) -> String {
        if self.use_color {
            format!("{} {}", cyan("ℹ"), msg)
        } else {
            format!("[INFO] {msg}")
        }
    }

    /// Format a hex address.
    #[must_use] 
    pub fn hex_addr(&self, addr: u64) -> String {
        if self.use_color {
            colorize(&format!("{addr:#018x}"), Color::BrightYellow, None)
        } else {
            format!("{addr:#018x}")
        }
    }

    /// Format a hex dump line.
    #[must_use] 
    pub fn hex_dump_line(&self, offset: u64, bytes: &[u8]) -> String {
        let hex: String = bytes.iter().enumerate().map(|(i, b)| {
            if i % 4 == 0 && i > 0 { format!(" {b:02x}") } else { format!("{b:02x}") }
        }).collect::<Vec<_>>().join(" ");
        let ascii: String = bytes.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
        }).collect();
        if self.use_color {
            format!("{}  {}  |{}|",
                colorize(&format!("{offset:#010x}"), Color::BrightYellow, None),
                colorize(&hex, Color::BrightCyan, None),
                colorize(&ascii, Color::BrightGreen, None),
            )
        } else {
            format!("{offset:#010x}  {hex}  |{ascii}|")
        }
    }
}

// ─── Test Utilities ──────────────────────────────────────────────────────────

/// Capture formatter output to a string.
pub struct StringSink(pub String);

impl Write for StringSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> Table {
        let mut t = Table::new().with_columns(vec![
            Column::new("Name"),
            Column::new("Size").right(),
            Column::new("Address").right(),
        ]);
        t.add_row(vec!["main", "1024", "0x401000"]);
        t.add_row(vec!["init", "256", "0x401400"]);
        t
    }

    #[test]
    fn test_table_render() {
        let t = make_table();
        let rendered = t.render();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("main"));
        assert!(rendered.contains("0x401000"));
    }

    #[test]
    fn test_table_csv() {
        let t = make_table();
        let csv = t.to_csv();
        assert!(csv.contains("Name,Size,Address"));
        assert!(csv.contains("main,1024,0x401000"));
    }

    #[test]
    fn test_table_json() {
        let t = make_table();
        let json = t.to_json(false);
        let parsed: Vec<HashMap<&str, &str>> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["Name"], "main");
    }

    #[test]
    fn test_progress_bar_percent() {
        let mut pb = ProgressBar::new(200, "test");
        pb.set(100);
        assert!((pb.percent() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_progress_bar_done() {
        let mut pb = ProgressBar::new(100, "test");
        pb.set(100);
        assert!(pb.is_done());
    }

    #[test]
    fn test_progress_bar_render() {
        let mut pb = ProgressBar::new(100, "Loading");
        pb.set(75);
        let rendered = pb.render();
        assert!(rendered.contains("Loading"));
        assert!(rendered.contains("75.0%"));
    }

    #[test]
    fn test_spinner_tick() {
        let mut sp = Spinner::new("Processing");
        let f0 = sp.current_frame().to_string();
        sp.tick();
        let f1 = sp.current_frame().to_string();
        assert_ne!(f0, f1);
    }

    #[test]
    fn test_formatter_kv() {
        let fmt = Formatter::plain();
        let s = fmt.kv("pid", "1234");
        assert!(s.contains("pid"));
        assert!(s.contains("1234"));
    }

    #[test]
    fn test_formatter_hex_addr() {
        let fmt = Formatter::plain();
        let s = fmt.hex_addr(0xDEAD_BEEF);
        assert!(s.contains("deadbeef"));
    }

    #[test]
    fn test_formatter_hex_dump_line() {
        let fmt = Formatter::plain();
        let bytes = b"Hello, World!";
        let line = fmt.hex_dump_line(0, bytes);
        assert!(line.contains("48"));
        assert!(line.contains("Hello"));
    }

    #[test]
    fn test_colorize_no_color() {
        set_color_mode(ColorMode::Never);
        let s = colorize("test", Color::Red, None);
        assert_eq!(s, "test");
        set_color_mode(ColorMode::Auto);
    }

    #[test]
    fn test_colorize_with_color() {
        set_color_mode(ColorMode::Always);
        let s = colorize("test", Color::Red, None);
        assert!(s.contains("\x1b["));
        set_color_mode(ColorMode::Auto);
    }

    #[test]
    fn test_csv_escaping() {
        let mut t = Table::new().with_columns(vec![Column::new("Value")]);
        t.add_row(vec!["has, comma"]);
        t.add_row(vec!["has \"quote\""]);
        let csv = t.to_csv();
        assert!(csv.contains("\"has, comma\""));
    }

    #[test]
    fn test_formatter_table_to_json() {
        let fmt = Formatter::json();
        let t = make_table();
        let s = fmt.format_table(&t);
        assert!(s.starts_with('['));
    }

    #[test]
    fn test_formatter_table_to_csv() {
        let fmt = Formatter::csv();
        let t = make_table();
        let s = fmt.format_table(&t);
        assert!(s.contains(','));
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("table"), Some(OutputFormat::Table));
        assert_eq!(OutputFormat::from_str("csv"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::from_str("unknown"), None);
    }
}
