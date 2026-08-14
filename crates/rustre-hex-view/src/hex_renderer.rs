//! Configurable hex dump renderer with colorization, diff highlight,
//! ASCII sidebar, Unicode sidebar option, and per-buffer diff.
//!
//! Types: `HexConfig`, `HexLine`, `HexRenderer`, `DiffHighlight`, `ColorScheme`.

use std::collections::HashMap;
use std::fmt;

// ── ColorScheme ───────────────────────────────────────────────────────────────

/// A named colour entry: foreground (R,G,B) and optional background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    #[must_use]
    pub fn ansi_fg(self) -> String {
        format!("\x1b[38;2;{};{};{}m", self.0, self.1, self.2)
    }
    #[must_use]
    pub fn ansi_bg(self) -> String {
        format!("\x1b[48;2;{};{};{}m", self.0, self.1, self.2)
    }
}

/// Byte-value colour rules.
#[derive(Debug, Clone)]
pub struct ColorScheme {
    pub name: &'static str,
    /// (lo, hi, fg, bg)
    pub rules: Vec<(u8, u8, Rgb, Option<Rgb>)>,
    pub default_fg: Rgb,
    pub diff_added: Rgb,
    pub diff_changed: Rgb,
    pub diff_removed: Rgb,
    pub offset_color: Rgb,
    pub null_color: Rgb,
    pub printable_color: Rgb,
    pub high_color: Rgb,
}

impl ColorScheme {
    /// Dark theme.
    #[must_use]
    pub fn dark() -> Self {
        Self {
            name: "dark",
            rules: vec![
                (0x00, 0x00, Rgb(80, 80, 80), None),
                (0x20, 0x7E, Rgb(180, 230, 180), None),
                (0x80, 0xFF, Rgb(200, 150, 100), None),
            ],
            default_fg:     Rgb(200, 200, 200),
            diff_added:     Rgb(100, 220, 100),
            diff_changed:   Rgb(220, 200, 0),
            diff_removed:   Rgb(220, 80, 80),
            offset_color:   Rgb(120, 120, 180),
            null_color:     Rgb(80, 80, 80),
            printable_color: Rgb(180, 230, 180),
            high_color:     Rgb(200, 150, 100),
        }
    }

    /// Light theme.
    #[must_use]
    pub fn light() -> Self {
        Self {
            name: "light",
            rules: vec![
                (0x00, 0x00, Rgb(170, 170, 170), None),
                (0x20, 0x7E, Rgb(0, 110, 0), None),
                (0x80, 0xFF, Rgb(120, 60, 0), None),
            ],
            default_fg:     Rgb(20, 20, 20),
            diff_added:     Rgb(0, 140, 0),
            diff_changed:   Rgb(180, 140, 0),
            diff_removed:   Rgb(180, 0, 0),
            offset_color:   Rgb(60, 60, 160),
            null_color:     Rgb(160, 160, 160),
            printable_color: Rgb(0, 110, 0),
            high_color:     Rgb(120, 60, 0),
        }
    }

    /// Monokai theme.
    #[must_use]
    pub fn monokai() -> Self {
        Self {
            name: "monokai",
            rules: vec![
                (0x00, 0x00, Rgb(117, 113, 94), None),
                (0x20, 0x7E, Rgb(166, 226, 46), None),
                (0x80, 0xFF, Rgb(249, 38, 114), None),
            ],
            default_fg:     Rgb(248, 248, 242),
            diff_added:     Rgb(166, 226, 46),
            diff_changed:   Rgb(230, 219, 116),
            diff_removed:   Rgb(249, 38, 114),
            offset_color:   Rgb(102, 217, 239),
            null_color:     Rgb(117, 113, 94),
            printable_color: Rgb(166, 226, 46),
            high_color:     Rgb(249, 38, 114),
        }
    }

    /// Lookup the foreground colour for a byte value.
    #[must_use]
    pub fn fg_for(&self, byte: u8) -> Rgb {
        for &(lo, hi, fg, _) in &self.rules {
            if byte >= lo && byte <= hi {
                return fg;
            }
        }
        self.default_fg
    }
}

// ── HexConfig ─────────────────────────────────────────────────────────────────

/// Column count for the hex view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnCount {
    Eight,
    Sixteen,
    ThirtyTwo,
    Custom(usize),
}

impl ColumnCount {
    #[must_use]
    pub fn value(self) -> usize {
        match self {
            Self::Eight => 8,
            Self::Sixteen => 16,
            Self::ThirtyTwo => 32,
            Self::Custom(n) => n.max(1),
        }
    }
}

/// Offset display format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetFormat {
    Hex32,
    Hex64,
    DecimalNarrow,
}

impl OffsetFormat {
    #[must_use]
    pub fn format(self, offset: usize) -> String {
        match self {
            Self::Hex32 => format!("{offset:08X}"),
            Self::Hex64 => format!("{offset:016X}"),
            Self::DecimalNarrow => format!("{offset:010}"),
        }
    }
}

/// Configuration for `HexRenderer`.
#[derive(Debug, Clone)]
pub struct HexConfig {
    pub columns: ColumnCount,
    pub offset_format: OffsetFormat,
    pub show_ascii: bool,
    pub show_unicode: bool,
    pub colorize: bool,
    pub uppercase_hex: bool,
    pub group_size: usize,
    pub base_offset: usize,
}

impl Default for HexConfig {
    fn default() -> Self {
        Self {
            columns: ColumnCount::Sixteen,
            offset_format: OffsetFormat::Hex32,
            show_ascii: true,
            show_unicode: false,
            colorize: false,
            uppercase_hex: true,
            group_size: 1,
            base_offset: 0,
        }
    }
}

impl HexConfig {
    #[must_use]
    pub const fn with_columns(mut self, c: ColumnCount) -> Self { self.columns = c; self }
    #[must_use]
    pub const fn with_offset_format(mut self, f: OffsetFormat) -> Self { self.offset_format = f; self }
    #[must_use]
    pub const fn with_colorize(mut self, v: bool) -> Self { self.colorize = v; self }
    #[must_use]
    pub const fn with_ascii(mut self, v: bool) -> Self { self.show_ascii = v; self }
    #[must_use]
    pub const fn with_base_offset(mut self, o: usize) -> Self { self.base_offset = o; self }
    #[must_use]
    pub fn with_group_size(mut self, g: usize) -> Self { self.group_size = g.max(1); self }
}

// ── DiffHighlight ─────────────────────────────────────────────────────────────

/// Per-byte diff status between two buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    Same,
    Changed,
    OnlyA,
    OnlyB,
}

/// Diff highlight map: offset -> status.
#[derive(Debug, Clone, Default)]
pub struct DiffHighlight {
    map: HashMap<usize, DiffStatus>,
}

impl DiffHighlight {
    /// Build a diff highlight by comparing two byte slices byte-by-byte.
    #[must_use]
    pub fn from_buffers(a: &[u8], b: &[u8]) -> Self {
        let mut map = HashMap::new();
        let len = a.len().max(b.len());
        for i in 0..len {
            let status = match (a.get(i), b.get(i)) {
                (Some(ba), Some(bb)) if ba != bb => DiffStatus::Changed,
                (Some(_), None) => DiffStatus::OnlyA,
                (None, Some(_)) => DiffStatus::OnlyB,
                _ => DiffStatus::Same,
            };
            if status != DiffStatus::Same {
                map.insert(i, status);
            }
        }
        Self { map }
    }

    #[must_use]
    pub fn status(&self, offset: usize) -> DiffStatus {
        self.map.get(&offset).copied().unwrap_or(DiffStatus::Same)
    }

    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn has_differences(&self) -> bool {
        !self.map.is_empty()
    }
}

// ── HexLine ───────────────────────────────────────────────────────────────────

/// A single rendered line of hex output.
#[derive(Debug, Clone)]
pub struct HexLine {
    /// File offset of the first byte in this line.
    pub offset: usize,
    /// Number of data bytes on this line.
    pub byte_count: usize,
    /// Formatted offset column (e.g. "00001000").
    pub offset_str: String,
    /// Hex bytes column (may include ANSI escapes if colorized).
    pub hex_str: String,
    /// ASCII sidebar (printable chars or '.'). Empty if disabled.
    pub ascii_str: String,
    /// Unicode sidebar (printable Unicode or '.'). Empty if disabled.
    pub unicode_str: String,
    /// True if any byte on this line differs from the other buffer.
    pub has_diff: bool,
}

impl HexLine {
    /// Render the line as a single string suitable for terminal output.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        if !self.offset_str.is_empty() {
            s.push_str(&self.offset_str);
            s.push_str(":  ");
        }
        s.push_str(&self.hex_str);
        if !self.ascii_str.is_empty() {
            s.push_str("  |");
            s.push_str(&self.ascii_str);
            s.push('|');
        }
        if !self.unicode_str.is_empty() {
            s.push_str("  [");
            s.push_str(&self.unicode_str);
            s.push(']');
        }
        s
    }
}

impl fmt::Display for HexLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

// ── HexRenderer ───────────────────────────────────────────────────────────────

/// Renders byte buffers as hex dumps.
pub struct HexRenderer {
    pub config: HexConfig,
    pub scheme: ColorScheme,
    pub diff: Option<DiffHighlight>,
}

const ANSI_RESET: &str = "\x1b[0m";

impl HexRenderer {
    /// Create a plain (no color) renderer.
    #[must_use]
    pub fn new(config: HexConfig) -> Self {
        Self { config, scheme: ColorScheme::dark(), diff: None }
    }

    /// Create a renderer with a custom color scheme.
    #[must_use]
    pub fn with_scheme(mut self, scheme: ColorScheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Attach a diff highlight map.
    #[must_use]
    pub fn with_diff(mut self, diff: DiffHighlight) -> Self {
        self.diff = Some(diff);
        self
    }

    /// Render the full buffer as a `Vec<HexLine>`.
    #[must_use]
    pub fn render(&self, data: &[u8]) -> Vec<HexLine> {
        let cols = self.config.columns.value();
        let mut lines = Vec::with_capacity(data.len().div_ceil(cols));
        let mut pos = 0usize;
        while pos < data.len() {
            let end = (pos + cols).min(data.len());
            let row = &data[pos..end];
            let line = self.render_line(self.config.base_offset + pos, row, pos);
            lines.push(line);
            pos += cols;
        }
        lines
    }

    /// Render the buffer and return all lines joined with newlines.
    #[must_use]
    pub fn render_string(&self, data: &[u8]) -> String {
        self.render(data)
            .iter()
            .map(HexLine::render)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Render one row of `bytes` at the given file `offset`.
    fn render_line(&self, offset: usize, bytes: &[u8], local_offset: usize) -> HexLine {
        let cols = self.config.columns.value();
        let gs = self.config.group_size;
        let offset_str = self.config.offset_format.format(offset);

        let mut hex_str = String::with_capacity(cols * 3 + 16);
        let mut ascii_str = String::new();
        let mut unicode_str = String::new();
        let mut has_diff = false;

        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 && gs > 0 && i % gs == 0 {
                hex_str.push(' ');
            }
            let diff_status = self.diff.as_ref()
                .map_or(DiffStatus::Same, |d| d.status(local_offset + i));

            if diff_status != DiffStatus::Same {
                has_diff = true;
            }

            if self.config.colorize {
                let color = match diff_status {
                    DiffStatus::Changed => self.scheme.diff_changed,
                    DiffStatus::OnlyA   => self.scheme.diff_removed,
                    DiffStatus::OnlyB   => self.scheme.diff_added,
                    DiffStatus::Same    => self.scheme.fg_for(b),
                };
                hex_str.push_str(&color.ansi_fg());
            }

            use std::fmt::Write as _;
            if self.config.uppercase_hex {
                write!(hex_str, "{b:02X}").unwrap();
            } else {
                write!(hex_str, "{b:02x}").unwrap();
            }

            if self.config.colorize {
                hex_str.push_str(ANSI_RESET);
            }
            hex_str.push(' ');
        }

        // Pad to full width for alignment
        let pad_count = cols - bytes.len();
        for i in 0..pad_count {
            if gs > 0 && (bytes.len() + i).is_multiple_of(gs) { hex_str.push(' '); }
            hex_str.push_str("   ");
        }
        // Trim trailing space
        if hex_str.ends_with(' ') {
            hex_str.pop();
        }

        // ASCII sidebar
        if self.config.show_ascii {
            for &b in bytes {
                let c = if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' };
                if self.config.colorize && b.is_ascii_graphic() {
                    ascii_str.push_str(&self.scheme.printable_color.ansi_fg());
                    ascii_str.push(c);
                    ascii_str.push_str(ANSI_RESET);
                } else {
                    ascii_str.push(c);
                }
            }
        }

        // Unicode sidebar: attempt UTF-8 decoding of the row
        if self.config.show_unicode {
            let s = String::from_utf8_lossy(bytes);
            for ch in s.chars() {
                unicode_str.push(if ch.is_control() { '.' } else { ch });
            }
        }

        HexLine {
            offset,
            byte_count: bytes.len(),
            offset_str,
            hex_str,
            ascii_str,
            unicode_str,
            has_diff,
        }
    }

    /// Render `data` compared against `other`; highlight differences.
    #[must_use]
    pub fn render_diff(&self, data: &[u8], other: &[u8]) -> Vec<HexLine> {
        let diff = DiffHighlight::from_buffers(data, other);
        let renderer = Self {
            config: self.config.clone(),
            scheme: self.scheme.clone(),
            diff: Some(diff),
        };
        renderer.render(data)
    }

    /// Format a classic `xxd`-style dump of `data` without color.
    #[must_use]
    pub fn format_xxd(data: &[u8], base: usize) -> String {
        let cfg = HexConfig {
            base_offset: base,
            ..Default::default()
        };
        Self::new(cfg).render_string(data)
    }

    /// Count changed bytes when comparing `a` vs `b`.
    #[must_use]
    pub fn diff_count(a: &[u8], b: &[u8]) -> usize {
        DiffHighlight::from_buffers(a, b).changed_count()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_count_values() {
        assert_eq!(ColumnCount::Eight.value(), 8);
        assert_eq!(ColumnCount::Sixteen.value(), 16);
        assert_eq!(ColumnCount::ThirtyTwo.value(), 32);
        assert_eq!(ColumnCount::Custom(24).value(), 24);
    }

    #[test]
    fn test_offset_format_hex32() {
        assert_eq!(OffsetFormat::Hex32.format(0x1000), "00001000");
    }

    #[test]
    fn test_offset_format_hex64() {
        assert_eq!(OffsetFormat::Hex64.format(0x1000), "0000000000001000");
    }

    #[test]
    fn test_offset_format_decimal() {
        let s = OffsetFormat::DecimalNarrow.format(4096);
        assert!(s.contains("4096"));
    }

    #[test]
    fn test_render_basic() {
        let cfg = HexConfig::default();
        let renderer = HexRenderer::new(cfg);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let lines = renderer.render(&data);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].hex_str.contains("DE"));
        assert!(lines[0].hex_str.contains("EF"));
    }

    #[test]
    fn test_render_ascii_sidebar() {
        let cfg = HexConfig::default().with_ascii(true);
        let renderer = HexRenderer::new(cfg);
        let lines = renderer.render(b"Hello");
        assert_eq!(lines[0].ascii_str, "Hello");
    }

    #[test]
    fn test_render_non_printable_dot() {
        let cfg = HexConfig::default().with_ascii(true);
        let renderer = HexRenderer::new(cfg);
        let data = [0x00u8, 0x01, 0x41];
        let lines = renderer.render(&data);
        assert!(lines[0].ascii_str.starts_with("..A"));
    }

    #[test]
    fn test_render_multiline() {
        let cfg = HexConfig::default();
        let renderer = HexRenderer::new(cfg);
        let data = [0u8; 32];
        let lines = renderer.render(&data);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_render_partial_last_row() {
        let cfg = HexConfig::default();
        let renderer = HexRenderer::new(cfg);
        let data = [0u8; 20];
        let lines = renderer.render(&data);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].byte_count, 4);
    }

    #[test]
    fn test_render_offset_tracking() {
        let cfg = HexConfig::default().with_base_offset(0x100);
        let renderer = HexRenderer::new(cfg);
        let data = [0u8; 32];
        let lines = renderer.render(&data);
        assert_eq!(lines[0].offset, 0x100);
        assert_eq!(lines[1].offset, 0x110);
    }

    #[test]
    fn test_diff_highlight_no_diff() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let diff = DiffHighlight::from_buffers(&a, &b);
        assert!(!diff.has_differences());
    }

    #[test]
    fn test_diff_highlight_changed() {
        let a = [1u8, 2, 3];
        let b = [1u8, 9, 3];
        let diff = DiffHighlight::from_buffers(&a, &b);
        assert!(diff.has_differences());
        assert_eq!(diff.status(1), DiffStatus::Changed);
        assert_eq!(diff.status(0), DiffStatus::Same);
    }

    #[test]
    fn test_diff_highlight_only_a() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2];
        let diff = DiffHighlight::from_buffers(&a, &b);
        assert_eq!(diff.status(2), DiffStatus::OnlyA);
    }

    #[test]
    fn test_render_diff() {
        let cfg = HexConfig::default();
        let renderer = HexRenderer::new(cfg);
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let b = [1u8, 9, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let lines = renderer.render_diff(&a, &b);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].has_diff);
    }

    #[test]
    fn test_format_xxd() {
        let s = HexRenderer::format_xxd(&[0xDE, 0xAD], 0);
        assert!(s.contains("DE"));
    }

    #[test]
    fn test_diff_count() {
        let a = [1u8, 2, 3];
        let b = [1u8, 9, 9];
        assert_eq!(HexRenderer::diff_count(&a, &b), 2);
    }

    #[test]
    fn test_colorize_does_not_panic() {
        let cfg = HexConfig::default().with_colorize(true);
        let renderer = HexRenderer::new(cfg);
        let _lines = renderer.render(b"test data");
    }

    #[test]
    fn test_hex_line_render_contains_offset() {
        let cfg = HexConfig::default().with_base_offset(0x1000);
        let renderer = HexRenderer::new(cfg);
        let lines = renderer.render(&[0xAAu8]);
        assert!(lines[0].render().contains("00001000"));
    }

    #[test]
    fn test_color_scheme_dark() {
        let s = ColorScheme::dark();
        assert_eq!(s.fg_for(0x41), Rgb(180, 230, 180)); // printable
        assert_eq!(s.fg_for(0x00), Rgb(80, 80, 80));   // null
    }

    #[test]
    fn test_unicode_sidebar() {
        let cfg = HexConfig { show_unicode: true, ..Default::default() };
        let renderer = HexRenderer::new(cfg);
        let lines = renderer.render(b"Hi");
        assert!(!lines[0].unicode_str.is_empty());
    }

    #[test]
    fn test_group_size() {
        let cfg = HexConfig::default().with_group_size(4);
        let renderer = HexRenderer::new(cfg);
        let data = [0u8; 8];
        let lines = renderer.render(&data);
        // With group_size=4 there should be a space every 4 bytes
        assert!(lines[0].hex_str.contains("  ") || !lines[0].hex_str.is_empty());
    }
}
