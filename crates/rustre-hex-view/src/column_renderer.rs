//! `column_renderer` — Configurable column renderers for the hex view.
//!
//! Provides renderers for:
//! - Offset column (hex/dec/octal)
//! - Hex column (byte groups 1/2/4/8, big/little endian)
//! - Text column (ASCII, UTF-8, UTF-16, EBCDIC, custom charset)
//! - Decoded column (float/int/timestamp interpretations)
//! - Color column (actual RGB preview for 3-byte groups)

use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ColumnError
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ColumnError {
    #[error("offset {offset} + group size {group} exceeds buffer length {len}")]
    OutOfBounds { offset: usize, group: usize, len: usize },
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
    #[error("format error: {0}")]
    Format(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// ColumnCell
// ─────────────────────────────────────────────────────────────────────────────

/// A single rendered cell in a column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnCell {
    pub text: String,
    /// ANSI colour prefix (empty = no colour).
    pub ansi_color: String,
    /// Width in terminal columns.
    pub width: u8,
}

impl ColumnCell {
    fn plain(text: impl Into<String>, width: u8) -> Self {
        Self { text: text.into(), ansi_color: String::new(), width }
    }

    fn colored(text: impl Into<String>, color: impl Into<String>, width: u8) -> Self {
        Self { text: text.into(), ansi_color: color.into(), width }
    }

    /// Render with ANSI reset suffix.
    #[must_use]
    pub fn render_ansi(&self) -> String {
        if self.ansi_color.is_empty() {
            self.text.clone()
        } else {
            format!("{}{}\x1b[0m", self.ansi_color, self.text)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OffsetColumn
// ─────────────────────────────────────────────────────────────────────────────

/// How to format the offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffsetFormat {
    Hex,
    Dec,
    Octal,
}

/// Renders the offset (address) column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetColumn {
    pub format: OffsetFormat,
    /// Total width of the column in characters.
    pub width: u8,
    pub color: String,
    /// Show a separator character after offset.
    pub separator: char,
}

impl Default for OffsetColumn {
    fn default() -> Self {
        Self {
            format: OffsetFormat::Hex,
            width: 10,
            color: "\x1b[33m".to_string(), // yellow
            separator: ':',
        }
    }
}

impl OffsetColumn {
    #[must_use]
    pub fn render(&self, offset: usize) -> ColumnCell {
        let text = match self.format {
            OffsetFormat::Hex => format!("{:0>width$X}", offset, width = self.width as usize - 2),
            OffsetFormat::Dec => format!("{:0>width$}", offset, width = self.width as usize),
            OffsetFormat::Octal => format!("{:0>width$o}", offset, width = self.width as usize),
        };
        let full = format!("{text}{}", self.separator);
        ColumnCell::colored(full, &self.color, self.width + 1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexColumn
// ─────────────────────────────────────────────────────────────────────────────

/// Byte grouping in the hex column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteGroup {
    One,
    Two,
    Four,
    Eight,
}

impl ByteGroup {
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }
}

/// Renders the hex column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexColumn {
    pub group: ByteGroup,
    pub little_endian: bool,
    pub uppercase: bool,
    pub group_separator: String,
}

impl Default for HexColumn {
    fn default() -> Self {
        Self {
            group: ByteGroup::One,
            little_endian: true,
            uppercase: true,
            group_separator: " ".to_string(),
        }
    }
}

impl HexColumn {
    /// Render a byte group at `offset` in `data`.
    ///
    /// # Errors
    /// Returns [`ColumnError::OutOfBounds`] when `offset + group_size > data.len()`.
    ///
    /// # Panics
    /// Panics if the byte slice cannot be converted to the expected array size (unreachable).
    pub fn render_group(&self, data: &[u8], offset: usize) -> Result<ColumnCell, ColumnError> {
        let gs = self.group.size();
        if offset + gs > data.len() {
            return Err(ColumnError::OutOfBounds { offset, group: gs, len: data.len() });
        }

        let bytes = &data[offset..offset + gs];
        let text = match gs {
            1 => {
                if self.uppercase {
                    format!("{:02X}", bytes[0])
                } else {
                    format!("{:02x}", bytes[0])
                }
            }
            2 => {
                let v = if self.little_endian {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    u16::from_be_bytes([bytes[0], bytes[1]])
                };
                if self.uppercase { format!("{v:04X}") } else { format!("{v:04x}") }
            }
            4 => {
                let v = if self.little_endian {
                    u32::from_le_bytes(bytes.try_into().unwrap())
                } else {
                    u32::from_be_bytes(bytes.try_into().unwrap())
                };
                if self.uppercase { format!("{v:08X}") } else { format!("{v:08x}") }
            }
            8 => {
                let v = if self.little_endian {
                    u64::from_le_bytes(bytes.try_into().unwrap())
                } else {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                };
                if self.uppercase { format!("{v:016X}") } else { format!("{v:016x}") }
            }
            _ => unreachable!(),
        };

        let width = u8::try_from(gs * 2).unwrap_or(u8::MAX);
        Ok(ColumnCell::plain(text, width))
    }

    /// Render an entire row of `row_bytes` bytes starting at `offset`.
    ///
    /// # Errors
    /// Returns [`ColumnError::OutOfBounds`] if any byte group falls outside `data`.
    pub fn render_row(
        &self,
        data: &[u8],
        offset: usize,
        row_bytes: usize,
    ) -> Result<String, ColumnError> {
        let gs = self.group.size();
        let mut out = String::new();
        let mut pos = offset;
        let end = (offset + row_bytes).min(data.len());

        while pos + gs <= end {
            if pos > offset {
                out.push_str(&self.group_separator);
            }
            let cell = self.render_group(data, pos)?;
            out.push_str(&cell.text);
            pos += gs;
        }

        // Pad incomplete row
        let rendered = (end - offset) / gs * gs;
        let missing = row_bytes - rendered;
        if missing > 0 {
            let pad_groups = missing / gs;
            for _ in 0..pad_groups {
                out.push_str(&self.group_separator);
                for _ in 0..gs * 2 {
                    out.push(' ');
                }
            }
        }

        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TextColumn
// ─────────────────────────────────────────────────────────────────────────────

/// Text encoding for the text column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Ebcdic,
    /// Custom: a 256-entry lookup table mapping byte → char (stored as a Vec for serde compatibility).
    #[serde(skip)]
    Custom(Box<[char; 256]>),
}

/// Renders the decoded text column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextColumn {
    pub encoding: TextEncoding,
    /// Replacement character for non-printable bytes.
    pub placeholder: char,
    pub width: usize,
}

impl Default for TextColumn {
    fn default() -> Self {
        Self {
            encoding: TextEncoding::Ascii,
            placeholder: '.',
            width: 16,
        }
    }
}

impl TextColumn {
    /// Render a row of bytes as text.
    #[must_use]
    pub fn render_row(&self, data: &[u8], offset: usize, row_bytes: usize) -> String {
        let end = (offset + row_bytes).min(data.len());
        let slice = &data[offset..end];

        match &self.encoding {
            TextEncoding::Ascii => slice
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { self.placeholder })
                .collect(),

            TextEncoding::Utf8 => {
                String::from_utf8_lossy(slice)
                    .chars()
                    .map(|c| {
                        if c.is_control() || c == '\u{FFFD}' { self.placeholder } else { c }
                    })
                    .collect()
            }

            TextEncoding::Utf16Le => {
                let pairs: Vec<u16> = slice
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&pairs)
                    .chars()
                    .map(|c| if c.is_control() { self.placeholder } else { c })
                    .collect()
            }

            TextEncoding::Utf16Be => {
                let pairs: Vec<u16> = slice
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&pairs)
                    .chars()
                    .map(|c| if c.is_control() { self.placeholder } else { c })
                    .collect()
            }

            TextEncoding::Ebcdic => slice.iter().map(|&b| ebcdic_to_ascii(b)).collect(),

            TextEncoding::Custom(table) => {
                slice.iter().map(|&b| {
                    let c = table[b as usize];
                    if c.is_control() { self.placeholder } else { c }
                }).collect()
            }
        }
    }
}

/// Basic EBCDIC to ASCII lookup.
fn ebcdic_to_ascii(b: u8) -> char {
    static TABLE: [u8; 256] = {
        let mut t = [b'.'; 256];
        // Basic printable EBCDIC mappings
        t[0x40] = b' ';
        t[0x4B] = b'.';
        t[0x4C] = b'<';
        t[0x4D] = b'(';
        t[0x4E] = b'+';
        t[0x50] = b'&';
        t[0x5A] = b'!';
        t[0x5B] = b'$';
        t[0x5C] = b'*';
        t[0x5D] = b')';
        t[0x5E] = b';';
        t[0x60] = b'-';
        t[0x61] = b'/';
        t[0x6B] = b',';
        t[0x6C] = b'%';
        t[0x6D] = b'_';
        t[0x6E] = b'>';
        t[0x6F] = b'?';
        t[0x7A] = b':';
        t[0x7B] = b'#';
        t[0x7C] = b'@';
        t[0x7D] = b'\'';
        t[0x7E] = b'=';
        t[0x7F] = b'"';
        // Letters A-Z
        let mut i = 0u8;
        while i < 9 { t[0xC1 + i as usize] = b'A' + i; i += 1; }
        let mut i = 0u8;
        while i < 9 { t[0xD1 + i as usize] = b'J' + i; i += 1; }
        let mut i = 0u8;
        while i < 8 { t[0xE2 + i as usize] = b'S' + i; i += 1; }
        // a-z
        let mut i = 0u8;
        while i < 9 { t[0x81 + i as usize] = b'a' + i; i += 1; }
        let mut i = 0u8;
        while i < 9 { t[0x91 + i as usize] = b'j' + i; i += 1; }
        let mut i = 0u8;
        while i < 8 { t[0xA2 + i as usize] = b's' + i; i += 1; }
        // Digits 0-9
        let mut i = 0u8;
        while i < 10 { t[0xF0 + i as usize] = b'0' + i; i += 1; }
        t
    };
    TABLE[b as usize] as char
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedColumn
// ─────────────────────────────────────────────────────────────────────────────

/// Interpretation mode for the decoded column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodedMode {
    Float32Le,
    Float32Be,
    Float64Le,
    Float64Be,
    Int8,
    Int16Le,
    Int16Be,
    Int32Le,
    Int32Be,
    Int64Le,
    Int64Be,
    Uint8,
    Uint16Le,
    Uint16Be,
    Uint32Le,
    Uint32Be,
    Uint64Le,
    Uint64Be,
    /// Unix timestamp (u32 LE seconds).
    UnixTimestampU32Le,
    /// Windows FILETIME (u64 LE 100ns intervals since 1601).
    WindowsFiletime,
}

impl DecodedMode {
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        match self {
            Self::Int8 | Self::Uint8 => 1,
            Self::Int16Le | Self::Int16Be
            | Self::Uint16Le | Self::Uint16Be => 2,
            Self::Float32Le | Self::Float32Be
            | Self::Int32Le | Self::Int32Be
            | Self::Uint32Le | Self::Uint32Be
            | Self::UnixTimestampU32Le => 4,
            Self::Float64Le | Self::Float64Be
            | Self::Int64Le | Self::Int64Be
            | Self::Uint64Le | Self::Uint64Be
            | Self::WindowsFiletime => 8,
        }
    }
}

/// Renders a numeric/timestamp interpretation of bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedColumn {
    pub mode: DecodedMode,
    pub precision: usize,
}

impl Default for DecodedColumn {
    fn default() -> Self {
        Self { mode: DecodedMode::Uint8, precision: 6 }
    }
}

impl DecodedColumn {
    /// Render the value at `offset`.
    ///
    /// # Errors
    /// Returns [`ColumnError::OutOfBounds`] when `offset + mode_size > data.len()`.
    ///
    /// # Panics
    /// Panics if the byte slice cannot be converted to the expected array size (unreachable).
    pub fn render(&self, data: &[u8], offset: usize) -> Result<ColumnCell, ColumnError> {
        let sz = self.mode.byte_size();
        if offset + sz > data.len() {
            return Err(ColumnError::OutOfBounds { offset, group: sz, len: data.len() });
        }
        let bytes = &data[offset..offset + sz];

        let text = match &self.mode {
            DecodedMode::Uint8 => format!("{}", bytes[0]),
            DecodedMode::Int8 => format!("{}", bytes[0].cast_signed()),
            DecodedMode::Uint16Le => format!("{}", u16::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Uint16Be => format!("{}", u16::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int16Le => format!("{}", i16::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int16Be => format!("{}", i16::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Uint32Le => format!("{}", u32::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Uint32Be => format!("{}", u32::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int32Le => format!("{}", i32::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int32Be => format!("{}", i32::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Uint64Le => format!("{}", u64::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Uint64Be => format!("{}", u64::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int64Le => format!("{}", i64::from_le_bytes(bytes.try_into().unwrap())),
            DecodedMode::Int64Be => format!("{}", i64::from_be_bytes(bytes.try_into().unwrap())),
            DecodedMode::Float32Le => {
                let v = f32::from_le_bytes(bytes.try_into().unwrap());
                format!("{:.prec$e}", v, prec = self.precision)
            }
            DecodedMode::Float32Be => {
                let v = f32::from_be_bytes(bytes.try_into().unwrap());
                format!("{:.prec$e}", v, prec = self.precision)
            }
            DecodedMode::Float64Le => {
                let v = f64::from_le_bytes(bytes.try_into().unwrap());
                format!("{:.prec$e}", v, prec = self.precision)
            }
            DecodedMode::Float64Be => {
                let v = f64::from_be_bytes(bytes.try_into().unwrap());
                format!("{:.prec$e}", v, prec = self.precision)
            }
            DecodedMode::UnixTimestampU32Le => {
                let secs = u32::from_le_bytes(bytes.try_into().unwrap());
                format!("unix:{secs}")
            }
            DecodedMode::WindowsFiletime => {
                let ft = u64::from_le_bytes(bytes.try_into().unwrap());
                // Convert to unix epoch: (ft - 116444736000000000) / 10_000_000
                let unix = ft.saturating_sub(116_444_736_000_000_000) / 10_000_000;
                format!("winft:{unix}")
            }
        };

        let w = u8::try_from(text.len()).unwrap_or(u8::MAX);
        Ok(ColumnCell::plain(text, w))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColorColumn
// ─────────────────────────────────────────────────────────────────────────────

/// Renders a colour swatch for each 3-byte RGB group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorColumn {
    /// Character to use for the swatch (typically a block character).
    pub swatch_char: char,
    pub swatch_width: u8,
}

impl Default for ColorColumn {
    fn default() -> Self {
        Self { swatch_char: '█', swatch_width: 3 }
    }
}

impl ColorColumn {
    /// Render the RGB swatch at `offset` (reads 3 bytes: R, G, B).
    ///
    /// # Errors
    /// Returns [`ColumnError::OutOfBounds`] when `offset + 3 > data.len()`.
    pub fn render(&self, data: &[u8], offset: usize) -> Result<ColumnCell, ColumnError> {
        if offset + 3 > data.len() {
            return Err(ColumnError::OutOfBounds { offset, group: 3, len: data.len() });
        }
        let r = data[offset];
        let g = data[offset + 1];
        let b = data[offset + 2];
        let ansi = format!("\x1b[38;2;{r};{g};{b}m");
        let text: String = std::iter::repeat_n(self.swatch_char, self.swatch_width as usize)
            .collect();
        Ok(ColumnCell::colored(text, ansi, self.swatch_width))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColumnSet — compose multiple columns into a full row
// ─────────────────────────────────────────────────────────────────────────────

/// A set of columns to render for each row.
#[derive(Debug, Default)]
pub struct ColumnSet {
    pub offset: Option<OffsetColumn>,
    pub hex: Option<HexColumn>,
    pub text: Option<TextColumn>,
    pub decoded: Option<DecodedColumn>,
    pub color: Option<ColorColumn>,
    pub row_separator: String,
}

impl ColumnSet {
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            offset: Some(OffsetColumn::default()),
            hex: Some(HexColumn::default()),
            text: Some(TextColumn::default()),
            decoded: None,
            color: None,
            row_separator: "  ".to_string(),
        }
    }

    /// Render a full row for the given offset.
    #[must_use]
    pub fn render_row(
        &self,
        data: &[u8],
        offset: usize,
        row_bytes: usize,
    ) -> String {
        let mut parts: Vec<String> = vec![];

        if let Some(ref col) = self.offset {
            parts.push(col.render(offset).render_ansi());
        }

        if let Some(ref col) = self.hex {
            let hex = col.render_row(data, offset, row_bytes).unwrap_or_default();
            parts.push(hex);
        }

        if let Some(ref col) = self.text {
            parts.push(col.render_row(data, offset, row_bytes));
        }

        if let Some(ref col) = self.decoded {
            let decoded = col.render(data, offset)
                .map_or_else(|_| " ".repeat(8), |c| c.text);
            parts.push(decoded);
        }

        if let Some(ref col) = self.color {
            let swatch = col.render(data, offset)
                .map_or_else(|_| "   ".to_string(), |c| c.render_ansi());
            parts.push(swatch);
        }

        parts.join(&self.row_separator)
    }

    /// Render a row directly into a [`std::fmt::Write`] sink, avoiding the
    /// intermediate [`String`] returned by [`Self::render_row`]. This is
    /// useful when streaming many rows into a single output buffer.
    ///
    /// # Errors
    /// Returns [`std::fmt::Error`] if writing to the sink fails.
    pub fn render_row_into<W: FmtWrite>(
        &self,
        out: &mut W,
        data: &[u8],
        offset: usize,
        row_bytes: usize,
    ) -> std::fmt::Result {
        let line = self.render_row(data, offset, row_bytes);
        out.write_str(&line)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_column_hex() {
        let col = OffsetColumn::default();
        let cell = col.render(0x1234);
        assert!(cell.text.contains("1234") || cell.text.contains("1234:"));
    }

    #[test]
    fn hex_column_one_byte() {
        let col = HexColumn::default();
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let cell = col.render_group(&data, 0).unwrap();
        assert_eq!(cell.text, "DE");
    }

    #[test]
    fn hex_column_four_byte_le() {
        let col = HexColumn { group: ByteGroup::Four, little_endian: true, ..Default::default() };
        let data = [0x01, 0x02, 0x03, 0x04];
        let cell = col.render_group(&data, 0).unwrap();
        assert_eq!(cell.text, "04030201");
    }

    #[test]
    fn text_column_ascii() {
        let col = TextColumn::default();
        let data = b"Hello\x00World";
        let s = col.render_row(data, 0, 10);
        assert!(s.contains('H'));
        assert!(s.contains('.') || s.contains('W'));
    }

    #[test]
    fn decoded_column_u32_le() {
        let col = DecodedColumn { mode: DecodedMode::Uint32Le, precision: 6 };
        let data = [0x01, 0x00, 0x00, 0x00];
        let cell = col.render(&data, 0).unwrap();
        assert_eq!(cell.text, "1");
    }

    #[test]
    fn decoded_column_float32() {
        let col = DecodedColumn { mode: DecodedMode::Float32Le, precision: 2 };
        let data = 1.0f32.to_le_bytes();
        let cell = col.render(&data, 0).unwrap();
        assert!(cell.text.contains("1.00e"));
    }

    #[test]
    fn color_column_render() {
        let col = ColorColumn::default();
        let data = [255u8, 0, 128, 0, 0, 0];
        let cell = col.render(&data, 0).unwrap();
        assert!(cell.ansi_color.contains("255;0;128"));
    }

    #[test]
    fn column_set_render_row() {
        let cs = ColumnSet::with_defaults();
        let data = b"Hello World!!!!";
        let row = cs.render_row(data, 0, 16);
        assert!(!row.is_empty());
        assert!(row.contains("48")); // 'H' = 0x48
    }
}
