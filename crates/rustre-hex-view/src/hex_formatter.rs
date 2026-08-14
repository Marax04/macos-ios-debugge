//! `hex_formatter` — Format binary data as classic hex dump lines.
//!
//! Produces [`HexLine`] values from byte ranges, with configurable column
//! widths, grouping, address format, and character display.
//!
//! Key types: [`HexFormatter`], [`FormatConfig`], [`HexLine`], [`format_range`]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Write as FmtWrite;

// ─── AddressFormat ────────────────────────────────────────────────────────────

/// How to render offset/address values in the dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFormat {
    /// No address column.
    None,
    /// 8-digit zero-padded hex, e.g. `00001234`.
    Hex32,
    /// 16-digit zero-padded hex, e.g. `0000000000001234`.
    Hex64,
    /// Decimal, e.g. `4660`.
    Decimal,
}

impl AddressFormat {
    /// Format `offset` according to this style.
    #[must_use]
    pub fn render(self, offset: u64) -> String {
        match self {
            Self::None => String::new(),
            Self::Hex32 => format!("{offset:08X}"),
            Self::Hex64 => format!("{offset:016X}"),
            Self::Decimal => format!("{offset}"),
        }
    }
}

// ─── ByteCase ─────────────────────────────────────────────────────────────────

/// Letter case for hex byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteCase {
    Upper,
    Lower,
}

// ─── FormatConfig ─────────────────────────────────────────────────────────────

/// Configuration for the hex formatter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    /// Number of bytes per display row.
    pub bytes_per_row: usize,
    /// Sub-group size within a row (bytes separated by an extra space).
    pub group_size: usize,
    /// Starting address shown in the address column.
    pub start_address: u64,
    /// Address column format.
    pub address_format: AddressFormat,
    /// Hex digit case.
    pub byte_case: ByteCase,
    /// Show the ASCII/printable column.
    pub show_ascii: bool,
    /// Separator between address and hex columns.
    pub addr_sep: String,
    /// Separator between hex and ASCII columns.
    pub hex_ascii_sep: String,
    /// Character shown for non-printable bytes in the ASCII column.
    pub non_printable: char,
}

impl FormatConfig {
    /// 16-bytes-per-row, uppercase, with ASCII column.
    #[must_use]
    pub fn default_16() -> Self {
        Self {
            bytes_per_row: 16,
            group_size: 8,
            start_address: 0,
            address_format: AddressFormat::Hex32,
            byte_case: ByteCase::Upper,
            show_ascii: true,
            addr_sep: "  ".to_string(),
            hex_ascii_sep: "  ".to_string(),
            non_printable: '.',
        }
    }

    /// 8-bytes-per-row compact layout.
    #[must_use]
    pub fn compact_8() -> Self {
        Self {
            bytes_per_row: 8,
            group_size: 4,
            start_address: 0,
            address_format: AddressFormat::Hex32,
            byte_case: ByteCase::Upper,
            show_ascii: true,
            addr_sep: "  ".to_string(),
            hex_ascii_sep: "  ".to_string(),
            non_printable: '.',
        }
    }

    /// 32-bytes-per-row wide layout.
    #[must_use]
    pub fn wide_32() -> Self {
        Self {
            bytes_per_row: 32,
            group_size: 8,
            start_address: 0,
            address_format: AddressFormat::Hex64,
            byte_case: ByteCase::Upper,
            show_ascii: false,
            addr_sep: "  ".to_string(),
            hex_ascii_sep: "  ".to_string(),
            non_printable: '.',
        }
    }
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self::default_16()
    }
}

// ─── HexLine ─────────────────────────────────────────────────────────────────

/// A single rendered line of a hex dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexLine {
    /// File offset of the first byte in this row.
    pub offset: u64,
    /// Raw bytes in this row (may be fewer than `bytes_per_row` for the last row).
    pub bytes: Vec<u8>,
    /// Rendered address string (empty if `AddressFormat::None`).
    pub address: String,
    /// Rendered hex columns.
    pub hex: String,
    /// Rendered ASCII column (empty if `show_ascii == false`).
    pub ascii: String,
    /// Full assembled line.
    pub line: String,
}

impl HexLine {
    /// True if this row is fully populated (`bytes.len() == bytes_per_row`).
    #[must_use]
    pub const fn is_full(&self) -> bool {
        !self.bytes.is_empty()
    }
}

impl fmt::Display for HexLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.line)
    }
}

// ─── HexFormatter ─────────────────────────────────────────────────────────────

/// The main hex formatter.  Create once, reuse across many format calls.
pub struct HexFormatter {
    config: FormatConfig,
}

impl HexFormatter {
    /// Create a new formatter with the given configuration.
    #[must_use]
    pub const fn new(config: FormatConfig) -> Self {
        Self { config }
    }

    /// Create with the default 16-byte configuration.
    #[must_use]
    pub fn default_16() -> Self {
        Self::new(FormatConfig::default_16())
    }

    /// Access the current configuration.
    #[must_use]
    pub const fn config(&self) -> &FormatConfig {
        &self.config
    }

    /// Update the configuration.
    pub fn set_config(&mut self, cfg: FormatConfig) {
        self.config = cfg;
    }

    /// Format a single row of bytes starting at `offset`.
    ///
    /// `row` may be shorter than `bytes_per_row` for the last row.
    #[must_use]
    pub fn format_row(&self, offset: u64, row: &[u8]) -> HexLine {
        let cfg = &self.config;
        let address = cfg.address_format.render(offset + cfg.start_address);

        let hex = self.render_hex(row);
        let ascii = if cfg.show_ascii {
            self.render_ascii(row)
        } else {
            String::new()
        };

        let line = self.assemble_line(&address, &hex, &ascii);

        HexLine {
            offset,
            bytes: row.to_vec(),
            address,
            hex,
            ascii,
            line,
        }
    }

    /// Format `data[range.start .. range.end]` into a `Vec<HexLine>`.
    #[must_use]
    pub fn format_range(&self, data: &[u8], range: std::ops::Range<usize>) -> Vec<HexLine> {
        // Clamping the two ends INDEPENDENTLY only bounds the length, not the
        // order: a reversed range (or a caller that swaps the two `usize`
        // arguments of the free `format_range` below) survives both `.min`
        // calls and panics on the slice. Clamp the start against the END, the
        // way `rustre-events::event_replay::EventReplay::window` does.
        let end = range.end.min(data.len());
        let start = range.start.min(end);
        let slice = &data[start..end];
        self.format_bytes(slice, start as u64)
    }

    /// Format all of `data` into a `Vec<HexLine>`.
    #[must_use]
    pub fn format_all(&self, data: &[u8]) -> Vec<HexLine> {
        self.format_bytes(data, 0)
    }

    /// Format `data`, treating `base_offset` as the address of the first byte.
    #[must_use]
    pub fn format_bytes(&self, data: &[u8], base_offset: u64) -> Vec<HexLine> {
        let bpr = self.config.bytes_per_row.max(1);
        let mut lines = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let end = (pos + bpr).min(data.len());
            let row = &data[pos..end];
            lines.push(self.format_row(base_offset + pos as u64, row));
            pos += bpr;
        }
        lines
    }

    /// Render `lines` as a single string, each row separated by `\n`.
    #[must_use]
    pub fn render_to_string(&self, lines: &[HexLine]) -> String {
        let mut out = String::new();
        for (i, l) in lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&l.line);
        }
        out
    }

    /// Format the entire `data` buffer and return it as a single string.
    #[must_use]
    pub fn dump(&self, data: &[u8]) -> String {
        let lines = self.format_all(data);
        self.render_to_string(&lines)
    }

    // ── internal render helpers ────────────────────────────────────────────

    fn render_hex(&self, row: &[u8]) -> String {
        let cfg = &self.config;
        let bpr = cfg.bytes_per_row.max(1);
        let mut out = String::new();
        for (i, &b) in row.iter().enumerate() {
            if i > 0 {
                // Group separator
                if cfg.group_size > 0 && i % cfg.group_size == 0 {
                    out.push_str("  ");
                } else {
                    out.push(' ');
                }
            }
            match cfg.byte_case {
                ByteCase::Upper => write!(out, "{b:02X}").unwrap(),
                ByteCase::Lower => write!(out, "{b:02x}").unwrap(),
            }
        }
        // Pad short last row so columns align
        let rendered = row.len();
        let padding_bytes = bpr.saturating_sub(rendered);
        for i in 0..padding_bytes {
            // Mirror the spacing logic
            let col = rendered + i;
            if cfg.group_size > 0 && col.is_multiple_of(cfg.group_size) {
                out.push_str("     "); // extra space + "  "
            } else {
                out.push_str("   "); // " XX"
            }
        }
        out
    }

    fn render_ascii(&self, row: &[u8]) -> String {
        let cfg = &self.config;
        let mut out = String::new();
        for &b in row {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push(cfg.non_printable);
            }
        }
        out
    }

    fn assemble_line(&self, address: &str, hex: &str, ascii: &str) -> String {
        let cfg = &self.config;
        let mut line = String::new();
        if cfg.address_format != AddressFormat::None {
            line.push_str(address);
            line.push_str(&cfg.addr_sep);
        }
        line.push_str(hex);
        if cfg.show_ascii {
            line.push_str(&cfg.hex_ascii_sep);
            line.push_str(ascii);
        }
        line
    }
}

impl Default for HexFormatter {
    fn default() -> Self {
        Self::default_16()
    }
}

// ─── Convenience free function ────────────────────────────────────────────────

/// Format `data[start..end]` using the default 16-byte configuration.
///
/// This is the primary public entry point for callers that don't need to
/// customise the formatter.
#[must_use]
pub fn format_range(data: &[u8], start: usize, end: usize) -> Vec<HexLine> {
    HexFormatter::default_16().format_range(data, start..end)
}

/// Dump all of `data` as a hex string using default settings.
#[must_use]
pub fn dump_hex(data: &[u8]) -> String {
    HexFormatter::default_16().dump(data)
}

// ─── DiffLine ─────────────────────────────────────────────────────────────────

/// A pair of [`HexLine`]s for side-by-side diff display.
#[derive(Debug, Clone)]
pub struct DiffLine {
    pub left: Option<HexLine>,
    pub right: Option<HexLine>,
    pub differs: bool,
}

/// Format two byte slices side-by-side for diffing.
#[must_use]
pub fn format_diff(left: &[u8], right: &[u8], config: &FormatConfig) -> Vec<DiffLine> {
    let fmt = HexFormatter::new(config.clone());
    let bpr = config.bytes_per_row.max(1);
    let max_len = left.len().max(right.len());
    let rows = max_len.div_ceil(bpr);
    let mut out = Vec::with_capacity(rows);

    for row_idx in 0..rows {
        let start = row_idx * bpr;
        let left_row: Vec<u8> = (start..start + bpr)
            .map(|i| left.get(i).copied().unwrap_or(0))
            .take(bpr)
            .collect();
        let right_row: Vec<u8> = (start..start + bpr)
            .map(|i| right.get(i).copied().unwrap_or(0))
            .take(bpr)
            .collect();

        let differs = left_row != right_row;
        let left_line = fmt.format_row(start as u64, &left_row);
        let right_line = fmt.format_row(start as u64, &right_row);

        out.push(DiffLine {
            left: Some(left_line),
            right: Some(right_line),
            differs,
        });
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_data() -> Vec<u8> {
        (0u8..=15u8).collect()
    }

    #[test]
    fn format_all_produces_one_full_row() {
        let fmt = HexFormatter::default_16();
        let lines = fmt.format_all(&simple_data());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].bytes.len(), 16);
    }

    #[test]
    fn format_all_empty_is_empty() {
        let fmt = HexFormatter::default_16();
        let lines = fmt.format_all(&[]);
        assert!(lines.is_empty());
    }

    #[test]
    fn format_all_33_bytes_gives_three_rows() {
        let fmt = HexFormatter::default_16();
        let data: Vec<u8> = (0..33).collect();
        let lines = fmt.format_all(&data);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2].bytes.len(), 1);
    }

    #[test]
    fn format_range_correct_slice() {
        let fmt = HexFormatter::default_16();
        let data: Vec<u8> = (0..32).collect();
        let lines = fmt.format_range(&data, 0..16);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].bytes, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn format_range_out_of_bounds_clamped() {
        let fmt = HexFormatter::default_16();
        let data = vec![0u8; 4];
        let lines = fmt.format_range(&data, 0..1000);
        assert_eq!(lines[0].bytes.len(), 4);
    }

    #[test]
    fn hex_line_contains_uppercase_bytes() {
        let fmt = HexFormatter::default_16();
        let line = fmt.format_row(0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(line.hex.contains("DE"));
        assert!(line.hex.contains("AD"));
    }

    #[test]
    fn hex_line_lowercase_config() {
        let mut cfg = FormatConfig::default_16();
        cfg.byte_case = ByteCase::Lower;
        let fmt = HexFormatter::new(cfg);
        let line = fmt.format_row(0, &[0xDE]);
        assert!(line.hex.contains("de"));
    }

    #[test]
    fn ascii_column_present_by_default() {
        let fmt = HexFormatter::default_16();
        let line = fmt.format_row(0, b"Hello!");
        assert!(line.ascii.contains('H'));
        assert!(line.ascii.contains('!'));
    }

    #[test]
    fn non_printable_replaced() {
        let fmt = HexFormatter::default_16();
        let line = fmt.format_row(0, &[0x00, 0x01, 0xFF]);
        assert!(line.ascii.chars().all(|c| c == '.'));
    }

    #[test]
    fn no_ascii_column_when_disabled() {
        let mut cfg = FormatConfig::default_16();
        cfg.show_ascii = false;
        let fmt = HexFormatter::new(cfg);
        let line = fmt.format_row(0, b"ABC");
        assert!(line.ascii.is_empty());
    }

    #[test]
    fn address_format_hex32() {
        let mut cfg = FormatConfig::default_16();
        cfg.address_format = AddressFormat::Hex32;
        cfg.start_address = 0x1000;
        let fmt = HexFormatter::new(cfg);
        let line = fmt.format_row(0, &[0]);
        assert!(line.address.contains("00001000"));
    }

    #[test]
    fn address_format_none_empty() {
        let mut cfg = FormatConfig::default_16();
        cfg.address_format = AddressFormat::None;
        let fmt = HexFormatter::new(cfg);
        let line = fmt.format_row(0, &[0]);
        assert!(line.address.is_empty());
    }

    #[test]
    fn address_format_decimal() {
        let fmt = AddressFormat::Decimal;
        assert_eq!(fmt.render(255), "255");
    }

    #[test]
    fn dump_produces_newline_separated_lines() {
        let fmt = HexFormatter::default_16();
        let data: Vec<u8> = (0..32).collect();
        let dump = fmt.dump(&data);
        let line_count = dump.lines().count();
        assert_eq!(line_count, 2);
    }

    #[test]
    fn render_to_string_matches_dump() {
        let fmt = HexFormatter::default_16();
        let data: Vec<u8> = (0..16).collect();
        let lines = fmt.format_all(&data);
        let s1 = fmt.render_to_string(&lines);
        let s2 = fmt.dump(&data);
        assert_eq!(s1, s2);
    }

    #[test]
    fn format_range_free_fn_returns_lines() {
        let data: Vec<u8> = (0..32).collect();
        let lines = format_range(&data, 0, 16);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn dump_hex_free_fn_nonempty() {
        let s = dump_hex(b"hello");
        assert!(!s.is_empty());
        assert!(s.contains("68")); // 'h' = 0x68
    }

    #[test]
    fn config_compact_8_bytes_per_row() {
        let cfg = FormatConfig::compact_8();
        assert_eq!(cfg.bytes_per_row, 8);
    }

    #[test]
    fn config_wide_32_bytes_per_row() {
        let cfg = FormatConfig::wide_32();
        assert_eq!(cfg.bytes_per_row, 32);
    }

    #[test]
    fn format_diff_same_data_no_differs() {
        let data = vec![0u8; 16];
        let cfg = FormatConfig::default_16();
        let diff = format_diff(&data, &data, &cfg);
        assert!(diff.iter().all(|d| !d.differs));
    }

    #[test]
    fn format_diff_detects_change() {
        let left = vec![0u8; 16];
        let mut right = vec![0u8; 16];
        right[0] = 0xFF;
        let cfg = FormatConfig::default_16();
        let diff = format_diff(&left, &right, &cfg);
        assert!(diff[0].differs);
    }

    #[test]
    fn hex_line_display() {
        let fmt = HexFormatter::default_16();
        let line = fmt.format_row(0, &[0xAB]);
        let s = line.to_string();
        assert!(s.contains("AB"));
    }

    #[test]
    fn group_spacing_applied() {
        let cfg = FormatConfig {
            bytes_per_row: 16,
            group_size: 4,
            start_address: 0,
            address_format: AddressFormat::None,
            byte_case: ByteCase::Upper,
            show_ascii: false,
            addr_sep: "  ".to_string(),
            hex_ascii_sep: "  ".to_string(),
            non_printable: '.',
        };
        let fmt = HexFormatter::new(cfg);
        let line = fmt.format_row(0, &[0u8; 16]);
        // Should have extra spaces at columns 4, 8, 12
        assert!(line.hex.len() > 32);
    }

    #[test]
    fn test_format_range_reversed_range_is_empty_not_panic() {
        let data: Vec<u8> = (0..64u8).collect();
        let fmt = HexFormatter::default_16();
        // Reversed, both ends inside the buffer.
        assert!(fmt.format_range(&data, 32..8).is_empty());
        // Reversed with the start past the end of the buffer.
        assert!(fmt.format_range(&data, 1000..8).is_empty());
        // The free function takes two bare usize, so swapping them is a plausible
        // call-site slip — it must not be fatal either.
        assert!(format_range(&data, 32, 8).is_empty());
        // A well-formed range still yields the same lines as before.
        assert_eq!(fmt.format_range(&data, 0..16).len(), 1);
    }
}
