//! `entropy_visualization` — ASCII art entropy visualization for terminal output.
//!
//! Provides:
//! - [`AsciiBar`] — render a single entropy value as a proportional ASCII bar.
//! - [`SectionEntropyTable`] — tabular per-section entropy display.
//! - [`ColorCode`] — ANSI colour codes for entropy levels.

use crate::{EntropyRating, SectionEntropy, casts};

// ---------------------------------------------------------------------------
// ColorCode
// ---------------------------------------------------------------------------

/// ANSI escape-code colour pairs for entropy levels.
///
/// Each variant provides `fg()` (foreground) and `reset()` escape sequences
/// suitable for embedding in terminal strings.
use std::fmt::Write as _;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorCode {
    /// Very low entropy (< 1.0): dark grey.
    VeryLow,
    /// Low entropy [1.0, 3.0): cyan.
    Low,
    /// Medium entropy [3.0, 5.0): green.
    Medium,
    /// High entropy [5.0, 7.0): yellow.
    High,
    /// Very high entropy (≥ 7.0): bold red.
    VeryHigh,
}

impl ColorCode {
    /// Select the appropriate colour code for an entropy value.
    #[must_use]
    pub fn for_entropy(entropy: f64) -> Self {
        match EntropyRating::from_entropy(entropy) {
            EntropyRating::VeryLow => Self::VeryLow,
            EntropyRating::Low => Self::Low,
            EntropyRating::Medium => Self::Medium,
            EntropyRating::High => Self::High,
            EntropyRating::VeryHigh => Self::VeryHigh,
        }
    }

    /// ANSI foreground colour escape sequence.
    #[must_use]
    pub const fn fg(self) -> &'static str {
        match self {
            Self::VeryLow => "\x1b[90m",    // dark grey
            Self::Low => "\x1b[36m",        // cyan
            Self::Medium => "\x1b[32m",     // green
            Self::High => "\x1b[33m",       // yellow
            Self::VeryHigh => "\x1b[1;31m", // bold red
        }
    }

    /// ANSI reset escape sequence.
    #[must_use]
    pub const fn reset() -> &'static str {
        "\x1b[0m"
    }

    /// Wrap `text` in the colour's escape codes.
    #[must_use]
    pub fn colorise(self, text: &str) -> String {
        format!("{}{}{}", self.fg(), text, Self::reset())
    }

    /// Name of the colour (useful for test assertions without ANSI codes).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VeryLow => "dark-grey",
            Self::Low => "cyan",
            Self::Medium => "green",
            Self::High => "yellow",
            Self::VeryHigh => "bold-red",
        }
    }
}

// ---------------------------------------------------------------------------
// AsciiBar
// ---------------------------------------------------------------------------

/// Renders an entropy value as a proportional ASCII bar.
///
/// The bar is scaled from 0.0 to `max_entropy` (default 8.0) and uses the
/// block character `█` for filled cells and `░` for empty cells.
#[derive(Debug, Clone)]
pub struct AsciiBar {
    /// Total width of the bar in characters.
    pub width: usize,
    /// Maximum entropy value (the full-bar anchor).
    pub max_entropy: f64,
    /// Character used for filled (high-entropy) cells.
    pub fill_char: char,
    /// Character used for empty (low-entropy) cells.
    pub empty_char: char,
    /// Whether to append a numeric percentage label.
    pub show_percent: bool,
    /// Whether to surround the bar with `[` and `]`.
    pub show_brackets: bool,
}

impl AsciiBar {
    /// Create a bar with sensible defaults: 40 chars wide, max 8.0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            width: 40,
            max_entropy: 8.0,
            fill_char: '\u{2588}',  // █
            empty_char: '\u{2591}', // ░
            show_percent: true,
            show_brackets: true,
        }
    }

    /// Override the bar width.
    #[must_use]
    pub const fn with_width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Override the max entropy anchor.
    #[must_use]
    pub const fn with_max(mut self, max: f64) -> Self {
        self.max_entropy = max.max(1.0);
        self
    }

    /// Disable the percentage label.
    #[must_use]
    pub const fn no_percent(mut self) -> Self {
        self.show_percent = false;
        self
    }

    /// Disable surrounding brackets.
    #[must_use]
    pub const fn no_brackets(mut self) -> Self {
        self.show_brackets = false;
        self
    }

    /// Render `entropy` as an ASCII bar string.
    ///
    /// Example output: `[████████████████░░░░░░░░░░░░░░░░░░░░░░]  75.0%`
    #[must_use]
    pub fn render(&self, entropy: f64) -> String {
        let ratio = (entropy / self.max_entropy).clamp(0.0, 1.0);
        let filled = casts::f64_to_usize((ratio * casts::usize_to_f64(self.width)).round());
        let empty = self.width.saturating_sub(filled);

        let bar: String = std::iter::repeat_n(self.fill_char, filled)
            .chain(std::iter::repeat_n(self.empty_char, empty))
            .collect();

        let mut result = String::new();

        if self.show_brackets {
            result.push('[');
        }
        result.push_str(&bar);
        if self.show_brackets {
            result.push(']');
        }

        if self.show_percent {
            write!(result, "  {:.1}%", ratio * 100.0).unwrap();
        }

        result
    }

    /// Render with ANSI colour codes applied based on the entropy level.
    #[must_use]
    pub fn render_colored(&self, entropy: f64) -> String {
        let code = ColorCode::for_entropy(entropy);
        let bar = self.render(entropy);
        code.colorise(&bar)
    }

    /// Render a labelled bar: `"label  [██░░░]  25.0%"`.
    #[must_use]
    pub fn render_labeled(&self, label: &str, entropy: f64, label_width: usize) -> String {
        let bar = self.render(entropy);
        format!(
            "{label:<label_width$}  {bar}"
        )
    }
}

impl Default for AsciiBar {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SectionEntropyTable
// ---------------------------------------------------------------------------

/// Renders a tabular per-section entropy breakdown for terminal display.
pub struct SectionEntropyTable {
    /// Bar renderer used for each row.
    bar: AsciiBar,
    /// Column header for the section-name column.
    header_name: String,
    /// Whether to show the byte offset column.
    show_offset: bool,
    /// Whether to show the rating column.
    show_rating: bool,
    /// Whether to show ANSI colours.
    use_color: bool,
}

impl SectionEntropyTable {
    /// Create a table with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bar: AsciiBar::new().with_width(30),
            header_name: "Section".to_string(),
            show_offset: true,
            show_rating: true,
            use_color: false,
        }
    }

    /// Enable ANSI colour output.
    #[must_use]
    pub const fn with_color(mut self) -> Self {
        self.use_color = true;
        self
    }

    /// Hide the byte offset column.
    #[must_use]
    pub const fn no_offset(mut self) -> Self {
        self.show_offset = false;
        self
    }

    /// Override the section-name column header.
    #[must_use]
    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.header_name = header.into();
        self
    }

    /// Render `sections` as a formatted table string.
    #[must_use]
    pub fn render(&self, sections: &[SectionEntropy]) -> String {
        if sections.is_empty() {
            return "(no sections)\n".to_string();
        }

        // Determine column widths
        let name_w = sections
            .iter()
            .map(|s| s.name.len())
            .max()
            .unwrap_or(7)
            .max(self.header_name.len());

        let bar_w = self.bar.width + 2 + 7; // brackets + " 100.0%"
        let header = self.build_header(name_w, bar_w);
        let separator = "-".repeat(header.len());

        let mut lines = vec![header, separator];

        for section in sections {
            lines.push(self.render_row(section, name_w));
        }

        lines.join("\n") + "\n"
    }

    fn build_header(&self, name_w: usize, bar_w: usize) -> String {
        let mut h = format!(
            "{:<name_w$}  {:<8}  {:bar_w$}",
            self.header_name, "Entropy", "Bar"
        );
        if self.show_offset {
            h.push_str("  Offset   ");
        }
        if self.show_rating {
            h.push_str("  Rating   ");
        }
        h
    }

    fn render_row(&self, s: &SectionEntropy, name_w: usize) -> String {
        let bar = if self.use_color {
            self.bar.render_colored(s.entropy)
        } else {
            self.bar.render(s.entropy)
        };
        let mut row = format!("{:<name_w$}  {:8.4}  {}", s.name, s.entropy, bar,);
        if self.show_offset {
            write!(row, "  {:#010x}", s.offset).unwrap();
        }
        if self.show_rating {
            write!(row, "  {:}", s.rating).unwrap();
        }
        row
    }

    /// Render a summary footer line.
    #[must_use]
    pub fn summary_footer(&self, sections: &[SectionEntropy]) -> String {
        if sections.is_empty() {
            return String::new();
        }
        let max_e = sections
            .iter()
            .map(|s| s.entropy)
            .fold(f64::NEG_INFINITY, f64::max);
        let min_e = sections
            .iter()
            .map(|s| s.entropy)
            .fold(f64::INFINITY, f64::min);
        let avg_e = sections.iter().map(|s| s.entropy).sum::<f64>() / casts::usize_to_f64(sections.len());
        let packed = sections.iter().filter(|s| s.is_packed()).count();
        format!(
            "Summary: {} section(s), min={:.3}, max={:.3}, avg={:.3}, packed={}",
            sections.len(),
            min_e,
            max_e,
            avg_e,
            packed
        )
    }
}

impl Default for SectionEntropyTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionEntropy;

    fn make_section(name: &str, entropy: f64) -> SectionEntropy {
        SectionEntropy {
            name: name.to_string(),
            entropy,
            size: 1024,
            offset: 0x1000,
            rating: EntropyRating::from_entropy(entropy),
        }
    }

    // ── ColorCode ─────────────────────────────────────────────────────────────

    #[test]
    fn color_code_very_low() {
        assert_eq!(ColorCode::for_entropy(0.5), ColorCode::VeryLow);
    }

    #[test]
    fn color_code_very_high() {
        assert_eq!(ColorCode::for_entropy(7.5), ColorCode::VeryHigh);
    }

    #[test]
    fn color_code_fg_not_empty() {
        assert!(!ColorCode::High.fg().is_empty());
    }

    #[test]
    fn color_code_reset_is_ansi() {
        assert!(ColorCode::reset().starts_with('\x1b'));
    }

    #[test]
    fn color_code_colorise_wraps_text() {
        let s = ColorCode::Medium.colorise("hello");
        assert!(s.contains("hello"));
        assert!(s.contains('\x1b'));
    }

    #[test]
    fn color_code_names_distinct() {
        let names = [
            ColorCode::VeryLow.name(),
            ColorCode::Low.name(),
            ColorCode::Medium.name(),
            ColorCode::High.name(),
            ColorCode::VeryHigh.name(),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    // ── AsciiBar ──────────────────────────────────────────────────────────────

    #[test]
    fn ascii_bar_zero_entropy_is_empty() {
        let bar = AsciiBar::new().no_percent();
        let rendered = bar.render(0.0);
        // Should contain all empty chars
        assert!(!rendered.contains('\u{2588}'));
    }

    #[test]
    fn ascii_bar_max_entropy_is_full() {
        let bar = AsciiBar::new().with_width(10).no_percent();
        let rendered = bar.render(8.0);
        // Should contain all fill chars (width = 10)
        let fill_count = rendered.chars().filter(|&c| c == '\u{2588}').count();
        assert_eq!(fill_count, 10);
    }

    #[test]
    fn ascii_bar_brackets_present_by_default() {
        let bar = AsciiBar::new();
        let rendered = bar.render(4.0);
        assert!(rendered.starts_with('[') && rendered.contains(']'));
    }

    #[test]
    fn ascii_bar_no_brackets() {
        let bar = AsciiBar::new().no_brackets().no_percent();
        let rendered = bar.render(4.0);
        assert!(!rendered.starts_with('['));
    }

    #[test]
    fn ascii_bar_percent_shown_by_default() {
        let bar = AsciiBar::new().with_width(10);
        let rendered = bar.render(4.0);
        assert!(rendered.contains('%'));
    }

    #[test]
    fn ascii_bar_no_percent() {
        let bar = AsciiBar::new().no_percent();
        let rendered = bar.render(4.0);
        assert!(!rendered.contains('%'));
    }

    #[test]
    fn ascii_bar_colored_contains_ansi() {
        let bar = AsciiBar::new();
        let colored = bar.render_colored(7.5);
        assert!(colored.contains('\x1b'));
    }

    #[test]
    fn ascii_bar_labeled_includes_label() {
        let bar = AsciiBar::new();
        let labeled = bar.render_labeled(".text", 6.5, 10);
        assert!(labeled.contains(".text"));
    }

    // ── SectionEntropyTable ───────────────────────────────────────────────────

    #[test]
    fn table_empty_returns_no_sections() {
        let table = SectionEntropyTable::new();
        let rendered = table.render(&[]);
        assert!(rendered.contains("no sections"));
    }

    #[test]
    fn table_renders_section_name() {
        let table = SectionEntropyTable::new();
        let sections = vec![make_section(".text", 6.5)];
        let rendered = table.render(&sections);
        assert!(rendered.contains(".text"));
    }

    #[test]
    fn table_renders_entropy_value() {
        let table = SectionEntropyTable::new();
        let sections = vec![make_section(".data", 2.3)];
        let rendered = table.render(&sections);
        assert!(rendered.contains("2.3"));
    }

    #[test]
    fn table_multiple_sections() {
        let table = SectionEntropyTable::new();
        let sections = vec![
            make_section(".text", 6.5),
            make_section(".data", 2.0),
            make_section(".rsrc", 4.5),
        ];
        let rendered = table.render(&sections);
        assert!(rendered.contains(".text"));
        assert!(rendered.contains(".data"));
        assert!(rendered.contains(".rsrc"));
    }

    #[test]
    fn table_summary_footer_contains_stats() {
        let sections = vec![make_section(".text", 7.8), make_section(".data", 2.0)];
        let table = SectionEntropyTable::new();
        let footer = table.summary_footer(&sections);
        assert!(footer.contains("min=") && footer.contains("max=") && footer.contains("avg="));
    }

    #[test]
    fn table_summary_footer_empty() {
        let table = SectionEntropyTable::new();
        assert!(table.summary_footer(&[]).is_empty());
    }
}
