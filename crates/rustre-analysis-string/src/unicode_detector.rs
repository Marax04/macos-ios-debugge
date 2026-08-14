//! Unicode string detection for `rustre-analysis-string`.
//!
//! Detects and decodes strings encoded as UTF-8, UTF-16LE, UTF-16BE,
//! UTF-32LE, or UTF-32BE inside raw binary data.  Also handles:
//!
//! * **BOM detection** — recognises and strips Byte Order Marks.
//! * **Cross-encoding deduplication** — identifies strings that are
//!   semantically identical when decoded from different encodings.
//! * **Wide-string normalisation** — converts UTF-16/UTF-32 to UTF-8
//!   for uniform downstream processing.
//! * **Emoji and special-character handling** — reports whether a string
//!   contains non-BMP code points.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Unicode encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Detected Unicode encoding of a string candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeEncoding {
    /// 7-bit ASCII subset of UTF-8.
    Ascii,
    /// UTF-8 (superset of ASCII, variable-width 1–4 bytes).
    Utf8,
    /// UTF-16 Little-Endian.
    Utf16Le,
    /// UTF-16 Big-Endian.
    Utf16Be,
    /// UTF-32 Little-Endian.
    Utf32Le,
    /// UTF-32 Big-Endian.
    Utf32Be,
}

impl UnicodeEncoding {
    /// Return the BOM bytes for this encoding, if it has one.
    #[must_use]
    pub const fn bom(self) -> Option<&'static [u8]> {
        match self {
            Self::Utf8 => Some(&[0xEF, 0xBB, 0xBF]),
            Self::Utf16Le => Some(&[0xFF, 0xFE]),
            Self::Utf16Be => Some(&[0xFE, 0xFF]),
            Self::Utf32Le => Some(&[0xFF, 0xFE, 0x00, 0x00]),
            Self::Utf32Be => Some(&[0x00, 0x00, 0xFE, 0xFF]),
            Self::Ascii => None,
        }
    }

    /// Minimum byte width of a single code unit.
    #[must_use]
    pub const fn code_unit_width(self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32Le | Self::Utf32Be => 4,
        }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16LE",
            Self::Utf16Be => "UTF-16BE",
            Self::Utf32Le => "UTF-32LE",
            Self::Utf32Be => "UTF-32BE",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BOM detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect a BOM at the start of `data` and return the encoding and BOM length.
#[must_use]
pub fn detect_bom(data: &[u8]) -> Option<(UnicodeEncoding, usize)> {
    // UTF-32LE: FF FE 00 00 — must be checked before UTF-16LE (same prefix).
    if data.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        return Some((UnicodeEncoding::Utf32Le, 4));
    }
    // UTF-32BE: 00 00 FE FF
    if data.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        return Some((UnicodeEncoding::Utf32Be, 4));
    }
    // UTF-8: EF BB BF
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some((UnicodeEncoding::Utf8, 3));
    }
    // UTF-16LE: FF FE
    if data.starts_with(&[0xFF, 0xFE]) {
        return Some((UnicodeEncoding::Utf16Le, 2));
    }
    // UTF-16BE: FE FF
    if data.starts_with(&[0xFE, 0xFF]) {
        return Some((UnicodeEncoding::Utf16Be, 2));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding auto-detection (heuristic)
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristically detect the encoding of a short byte sequence.
///
/// Priority:
/// 1. BOM
/// 2. UTF-32LE (every 4th byte is zero)
/// 3. UTF-32BE (every 4th byte at offset 3 is zero)
/// 4. UTF-16LE (every 2nd byte is zero)
/// 5. UTF-16BE (every 2nd byte at offset 1 is zero)
/// 6. UTF-8 (valid UTF-8)
/// 7. ASCII
#[must_use]
pub fn auto_detect_encoding(data: &[u8]) -> UnicodeEncoding {
    if data.is_empty() {
        return UnicodeEncoding::Ascii;
    }

    // BOM takes priority.
    if let Some((enc, _)) = detect_bom(data) {
        return enc;
    }

    // Require at least 8 bytes for width detection.
    if data.len() >= 8 {
        // UTF-32LE: bytes 2,3,6,7 (high bytes of first two code units) are 0.
        let le32_score = data
            .chunks(4)
            .take(4)
            .filter(|c| c.len() == 4 && c[2] == 0 && c[3] == 0)
            .count();
        if le32_score >= 2 {
            return UnicodeEncoding::Utf32Le;
        }

        // UTF-32BE: bytes 0,1 of each 4-byte unit are 0.
        let be32_score = data
            .chunks(4)
            .take(4)
            .filter(|c| c.len() == 4 && c[0] == 0 && c[1] == 0)
            .count();
        if be32_score >= 2 {
            return UnicodeEncoding::Utf32Be;
        }

        // UTF-16: judge the qualifying units as a PROPORTION of the units
        // actually inspected, not against a fixed count.
        //
        // The threshold used to be a bare `>= 5` while only
        // `chunks(2).take(8)` were examined — and the enclosing gate merely
        // requires 8 BYTES, i.e. 4 units. Five out of four is unreachable, so
        // every 8- or 9-byte UTF-16 string was misreported as ASCII; in a
        // binary that is most of the interesting ones (`exit`, `test`, short
        // registry keys). `string_recovery.rs::CharsetDetector::detect` uses a
        // proportional test, which is the shape borrowed here.
        //
        // The ratio is 5/8, so an 8-unit input behaves exactly as before and
        // shorter inputs are judged on the same standard rather than on an
        // impossible one.
        let units: Vec<&[u8]> = data.chunks(2).take(8).filter(|c| c.len() == 2).collect();
        let examined = units.len();
        let qualifies = |score: usize| examined >= 2 && score * 8 >= examined * 5;

        // UTF-16LE: every second byte is 0 (common for ASCII text in UTF-16LE).
        let le16_score = units.iter().filter(|c| c[1] == 0).count();
        if qualifies(le16_score) {
            return UnicodeEncoding::Utf16Le;
        }

        // UTF-16BE: every second byte at offset 0 is 0.
        let be16_score = units.iter().filter(|c| c[0] == 0).count();
        if qualifies(be16_score) {
            return UnicodeEncoding::Utf16Be;
        }
    }

    // Try valid UTF-8.
    if std::str::from_utf8(data).is_ok() {
        // All ASCII?
        if data.iter().all(|&b| b < 0x80) {
            return UnicodeEncoding::Ascii;
        }
        return UnicodeEncoding::Utf8;
    }

    // Default: treat as ASCII (may produce replacement characters).
    UnicodeEncoding::Ascii
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Result of decoding a byte slice to a Rust `String`.
#[derive(Debug, Clone)]
pub struct DecodeResult {
    /// The decoded string (replacement characters `U+FFFD` for invalid bytes).
    pub text: String,
    /// Detected encoding.
    pub encoding: UnicodeEncoding,
    /// Whether any replacement characters were inserted.
    pub had_errors: bool,
    /// Whether the string contains non-BMP code points (> U+FFFF).
    pub has_non_bmp: bool,
    /// BOM length stripped from the front (0 if no BOM was present).
    pub bom_stripped: usize,
}

/// Decode `data` from `encoding` to a UTF-8 `String`.
#[must_use]
pub fn decode(data: &[u8], encoding: UnicodeEncoding) -> DecodeResult {
    let (data, bom_stripped) = match detect_bom(data) {
        Some((bom_enc, bom_len)) if bom_enc == encoding => (&data[bom_len..], bom_len),
        _ => (data, 0),
    };

    match encoding {
        UnicodeEncoding::Ascii | UnicodeEncoding::Utf8 => {
            let (text, had_errors) = decode_utf8_lossy(data);
            let has_non_bmp = text.chars().any(|c| c as u32 > 0xFFFF);
            DecodeResult { text, encoding, had_errors, has_non_bmp, bom_stripped }
        }
        UnicodeEncoding::Utf16Le => decode_utf16(data, true, bom_stripped),
        UnicodeEncoding::Utf16Be => decode_utf16(data, false, bom_stripped),
        UnicodeEncoding::Utf32Le => decode_utf32(data, true, bom_stripped),
        UnicodeEncoding::Utf32Be => decode_utf32(data, false, bom_stripped),
    }
}

/// Auto-detect encoding and decode.
#[must_use]
pub fn auto_decode(data: &[u8]) -> DecodeResult {
    let enc = auto_detect_encoding(data);
    decode(data, enc)
}

fn decode_utf8_lossy(data: &[u8]) -> (String, bool) {
    let s = String::from_utf8_lossy(data);
    let had_errors = s.contains('\u{FFFD}');
    (s.into_owned(), had_errors)
}

fn decode_utf16(data: &[u8], little_endian: bool, bom_stripped: usize) -> DecodeResult {
    let mut text = String::with_capacity(data.len() / 2);
    let mut had_errors = false;
    let mut has_non_bmp = false;
    let mut i = 0usize;

    while i + 1 < data.len() {
        let unit = if little_endian {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };
        i += 2;

        // Surrogate pair handling.
        if (0xD800..=0xDBFF).contains(&unit) {
            // High surrogate — need low surrogate.
            if i + 1 < data.len() {
                let low = if little_endian {
                    u16::from_le_bytes([data[i], data[i + 1]])
                } else {
                    u16::from_be_bytes([data[i], data[i + 1]])
                };
                if (0xDC00..=0xDFFF).contains(&low) {
                    let cp = 0x10000u32
                        + ((u32::from(unit) - 0xD800) << 10)
                        + (u32::from(low) - 0xDC00);
                    if let Some(c) = char::from_u32(cp) {
                        text.push(c);
                        has_non_bmp = true;
                        i += 2;
                        continue;
                    }
                }
            }
            // Invalid surrogate.
            text.push('\u{FFFD}');
            had_errors = true;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            // Lone low surrogate.
            text.push('\u{FFFD}');
            had_errors = true;
        } else if let Some(c) = char::from_u32(u32::from(unit)) {
            text.push(c);
        } else {
            text.push('\u{FFFD}');
            had_errors = true;
        }
    }

    let encoding = if little_endian { UnicodeEncoding::Utf16Le } else { UnicodeEncoding::Utf16Be };
    DecodeResult { text, encoding, had_errors, has_non_bmp, bom_stripped }
}

fn decode_utf32(data: &[u8], little_endian: bool, bom_stripped: usize) -> DecodeResult {
    let mut text = String::with_capacity(data.len() / 4);
    let mut had_errors = false;
    let mut has_non_bmp = false;
    let mut i = 0usize;

    while i + 3 < data.len() {
        let cp = if little_endian {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };
        i += 4;

        if let Some(c) = char::from_u32(cp) {
            if cp > 0xFFFF { has_non_bmp = true; }
            text.push(c);
        } else {
            text.push('\u{FFFD}');
            had_errors = true;
        }
    }

    let encoding = if little_endian { UnicodeEncoding::Utf32Le } else { UnicodeEncoding::Utf32Be };
    DecodeResult { text, encoding, had_errors, has_non_bmp, bom_stripped }
}

// ─────────────────────────────────────────────────────────────────────────────
// String scanning
// ─────────────────────────────────────────────────────────────────────────────

/// A detected Unicode string in binary data.
#[derive(Debug, Clone)]
pub struct UnicodeString {
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Byte length (including null terminator if present).
    pub byte_len: usize,
    /// Decoded content.
    pub text: String,
    /// Encoding.
    pub encoding: UnicodeEncoding,
    /// Whether the string is null-terminated.
    pub null_terminated: bool,
}

/// Which encoding widths the Unicode string scanner should attempt.
///
/// Stored as a bitset of enabled encodings; use the `with_*` builders to
/// toggle individual encodings and the accessor methods to query them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanEncodings {
    bits: u8,
}

impl ScanEncodings {
    const UTF16LE: u8 = 1;
    const UTF16BE: u8 = 1 << 1;
    const UTF32: u8 = 1 << 2;
    const UTF8: u8 = 1 << 3;

    /// No encodings enabled.
    #[must_use]
    pub const fn none() -> Self {
        Self { bits: 0 }
    }

    /// Enable or disable UTF-16LE scanning.
    #[must_use]
    pub const fn with_utf16le(self, enabled: bool) -> Self {
        self.set(Self::UTF16LE, enabled)
    }

    /// Enable or disable UTF-16BE scanning.
    #[must_use]
    pub const fn with_utf16be(self, enabled: bool) -> Self {
        self.set(Self::UTF16BE, enabled)
    }

    /// Enable or disable UTF-32 scanning.
    #[must_use]
    pub const fn with_utf32(self, enabled: bool) -> Self {
        self.set(Self::UTF32, enabled)
    }

    /// Enable or disable UTF-8 (including ASCII) scanning.
    #[must_use]
    pub const fn with_utf8(self, enabled: bool) -> Self {
        self.set(Self::UTF8, enabled)
    }

    /// Whether UTF-16LE scanning is enabled.
    #[must_use]
    pub const fn utf16le(self) -> bool {
        self.bits & Self::UTF16LE != 0
    }

    /// Whether UTF-16BE scanning is enabled.
    #[must_use]
    pub const fn utf16be(self) -> bool {
        self.bits & Self::UTF16BE != 0
    }

    /// Whether UTF-32 scanning is enabled.
    #[must_use]
    pub const fn utf32(self) -> bool {
        self.bits & Self::UTF32 != 0
    }

    /// Whether UTF-8 scanning is enabled.
    #[must_use]
    pub const fn utf8(self) -> bool {
        self.bits & Self::UTF8 != 0
    }

    const fn set(self, flag: u8, enabled: bool) -> Self {
        if enabled {
            Self { bits: self.bits | flag }
        } else {
            Self { bits: self.bits & !flag }
        }
    }
}

impl Default for ScanEncodings {
    fn default() -> Self {
        Self::none().with_utf16le(true).with_utf8(true)
    }
}

/// Configuration for the Unicode string scanner.
#[derive(Debug, Clone)]
pub struct UnicodeStringConfig {
    /// Minimum number of printable characters to accept a string.
    pub min_char_count: usize,
    /// Which encodings to scan for.
    pub encodings: ScanEncodings,
}

impl Default for UnicodeStringConfig {
    fn default() -> Self {
        Self {
            min_char_count: 4,
            encodings: ScanEncodings::default(),
        }
    }
}

/// Scan `data` for Unicode strings and return them in offset order.
#[must_use]
pub fn scan_unicode_strings(data: &[u8], config: &UnicodeStringConfig) -> Vec<UnicodeString> {
    let mut results = Vec::new();

    if config.encodings.utf8() {
        results.extend(scan_utf8_strings(data, config.min_char_count));
    }
    if config.encodings.utf16le() {
        results.extend(scan_utf16_strings(data, true, config.min_char_count));
    }
    if config.encodings.utf16be() {
        results.extend(scan_utf16_strings(data, false, config.min_char_count));
    }
    if config.encodings.utf32() {
        results.extend(scan_utf32_strings(data, true, config.min_char_count));
        results.extend(scan_utf32_strings(data, false, config.min_char_count));
    }

    results.sort_by_key(|s| s.offset);
    results
}

fn is_printable(c: char) -> bool {
    !c.is_control() || c == '\t' || c == '\n' || c == '\r'
}

fn scan_utf8_strings(data: &[u8], min_chars: usize) -> Vec<UnicodeString> {
    let mut results = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        // Skip non-printable bytes.
        if data[i] == 0 || (data[i] < 0x20 && data[i] != 9 && data[i] != 10 && data[i] != 13) {
            i += 1;
            continue;
        }

        // Try to consume a valid UTF-8 string.
        let start = i;
        let mut chars = 0usize;
        let mut end = i;

        while end < data.len() && data[end] != 0 {
            // Attempt to validate the next UTF-8 sequence.
            let remaining = &data[end..];
            let b = remaining[0];
            let seq_len = if b < 0x80 {
                1
            } else if b & 0xE0 == 0xC0 {
                2
            } else if b & 0xF0 == 0xE0 {
                3
            } else if b & 0xF8 == 0xF0 {
                4
            } else {
                break; // invalid UTF-8 start byte
            };

            if end + seq_len > data.len() {
                break;
            }

            if let Ok(s) = std::str::from_utf8(&data[end..end + seq_len])
                && let Some(c) = s.chars().next()
                && is_printable(c)
            {
                chars += 1;
                end += seq_len;
                continue;
            }
            break;
        }

        if chars >= min_chars {
            let null_terminated = end < data.len() && data[end] == 0;
            let byte_len = end - start + usize::from(null_terminated);
            let text = String::from_utf8_lossy(&data[start..end]).into_owned();
            let encoding = if data[start..end].iter().all(|&b| b < 0x80) {
                UnicodeEncoding::Ascii
            } else {
                UnicodeEncoding::Utf8
            };
            results.push(UnicodeString {
                offset: start,
                byte_len,
                text,
                encoding,
                null_terminated,
            });
            i = end + usize::from(null_terminated);
        } else {
            i += 1;
        }
    }

    results
}

fn scan_utf16_strings(data: &[u8], little_endian: bool, min_chars: usize) -> Vec<UnicodeString> {
    let mut results = Vec::new();
    let enc = if little_endian { UnicodeEncoding::Utf16Le } else { UnicodeEncoding::Utf16Be };

    let mut i = 0usize;
    // Align to 2-byte boundary.
    if !i.is_multiple_of(2) { i += 1; }

    while i + 1 < data.len() {
        let unit = if little_endian {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };

        if unit == 0 { i += 2; continue; }

        if unit < 0x0020 && unit != 9 && unit != 10 && unit != 13 { i += 2; continue; }

        // Consume a UTF-16 string.
        let start = i;
        let mut chars = 0usize;
        let mut j = i;

        while j + 1 < data.len() {
            let u = if little_endian {
                u16::from_le_bytes([data[j], data[j + 1]])
            } else {
                u16::from_be_bytes([data[j], data[j + 1]])
            };
            if u == 0 { break; }
            if u < 0x0020 && u != 9 && u != 10 && u != 13 { break; }
            chars += 1;
            j += 2;
        }

        if chars >= min_chars {
            let null_terminated = j + 1 < data.len() && data[j] == 0 && data[j + 1] == 0;
            let byte_len = j - start + if null_terminated { 2 } else { 0 };
            let decoded = decode(&data[start..j], enc);
            results.push(UnicodeString {
                offset: start,
                byte_len,
                text: decoded.text,
                encoding: enc,
                null_terminated,
            });
            i = j + if null_terminated { 2 } else { 0 };
        } else {
            i += 2;
        }
    }

    results
}

fn scan_utf32_strings(data: &[u8], little_endian: bool, min_chars: usize) -> Vec<UnicodeString> {
    let mut results = Vec::new();
    let enc = if little_endian { UnicodeEncoding::Utf32Le } else { UnicodeEncoding::Utf32Be };

    let mut i = 0usize;
    // Align to 4-byte boundary.
    i = (i + 3) & !3;

    while i + 3 < data.len() {
        let cp = if little_endian {
            u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]])
        } else {
            u32::from_be_bytes([data[i], data[i+1], data[i+2], data[i+3]])
        };

        if cp == 0 || (cp < 0x20 && cp != 9 && cp != 10 && cp != 13) { i += 4; continue; }

        let start = i;
        let mut chars = 0usize;
        let mut j = i;

        while j + 3 < data.len() {
            let u = if little_endian {
                u32::from_le_bytes([data[j], data[j+1], data[j+2], data[j+3]])
            } else {
                u32::from_be_bytes([data[j], data[j+1], data[j+2], data[j+3]])
            };
            if u == 0 { break; }
            if u < 0x20 && u != 9 && u != 10 && u != 13 { break; }
            chars += 1;
            j += 4;
        }

        if chars >= min_chars {
            let null_term = j + 3 < data.len() && data[j..j+4] == [0,0,0,0];
            let byte_len = j - start + if null_term { 4 } else { 0 };
            let decoded = decode(&data[start..j], enc);
            results.push(UnicodeString { offset: start, byte_len, text: decoded.text, encoding: enc, null_terminated: null_term });
            i = j + if null_term { 4 } else { 0 };
        } else {
            i += 4;
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-encoding deduplication
// ─────────────────────────────────────────────────────────────────────────────

/// Deduplicate a list of [`UnicodeString`] values by their decoded text.
///
/// When the same text appears in multiple encodings, only the first occurrence
/// (by offset) is kept.
#[must_use]
pub fn deduplicate_strings(strings: Vec<UnicodeString>) -> Vec<UnicodeString> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut result = Vec::new();

    for s in strings {
        if !seen.contains_key(&s.text) {
            seen.insert(s.text.clone(), s.offset);
            result.push(s);
        }
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_detection_utf16le() {
        let data = &[0xFF, 0xFE, b'H', 0x00];
        let bom = detect_bom(data);
        assert_eq!(bom, Some((UnicodeEncoding::Utf16Le, 2)));
    }

    #[test]
    fn bom_detection_utf32le_priority_over_utf16() {
        // UTF-32LE BOM: FF FE 00 00
        let data = &[0xFF, 0xFE, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00];
        let bom = detect_bom(data);
        assert_eq!(bom, Some((UnicodeEncoding::Utf32Le, 4)));
    }

    #[test]
    fn bom_detection_utf8() {
        let data = &[0xEF, 0xBB, 0xBF, b'H'];
        let bom = detect_bom(data);
        assert_eq!(bom, Some((UnicodeEncoding::Utf8, 3)));
    }

    #[test]
    fn bom_detection_none() {
        let data = b"Hello";
        assert!(detect_bom(data).is_none());
    }

    #[test]
    fn auto_detect_encoding_ascii() {
        assert_eq!(auto_detect_encoding(b"Hello, world!"), UnicodeEncoding::Ascii);
    }

    #[test]
    fn auto_detect_encoding_utf16le() {
        // "Hi" in UTF-16LE: 48 00 69 00
        let data: &[u8] = &[0x48, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        assert_eq!(auto_detect_encoding(data), UnicodeEncoding::Utf16Le);
    }

    #[test]
    fn decode_utf16le_hello() {
        // "Hello" in UTF-16LE
        let data: &[u8] = &[0x48,0x00, 0x65,0x00, 0x6C,0x00, 0x6C,0x00, 0x6F,0x00];
        let result = decode(data, UnicodeEncoding::Utf16Le);
        assert_eq!(result.text, "Hello");
        assert!(!result.had_errors);
    }

    #[test]
    fn decode_utf32le() {
        // "Hi" in UTF-32LE
        let data: &[u8] = &[0x48,0x00,0x00,0x00, 0x69,0x00,0x00,0x00];
        let result = decode(data, UnicodeEncoding::Utf32Le);
        assert_eq!(result.text, "Hi");
    }

    #[test]
    fn decode_utf16_surrogate_pair() {
        // U+1F600 😀 in UTF-16LE: D8 3D DE 00
        let data: &[u8] = &[0x3D, 0xD8, 0x00, 0xDE];
        let result = decode(data, UnicodeEncoding::Utf16Le);
        assert!(result.has_non_bmp, "expected non-BMP codepoint");
        assert!(!result.had_errors);
    }

    #[test]
    fn scan_utf8_finds_ascii_string() {
        let mut data = vec![0x00u8; 4];
        data.extend_from_slice(b"Hello, world!");
        data.push(0x00);
        let config = UnicodeStringConfig::default();
        let strings = scan_unicode_strings(&data, &config);
        assert!(strings.iter().any(|s| s.text.contains("Hello, world!")));
    }

    #[test]
    fn scan_utf16le_finds_string() {
        // "Test" in UTF-16LE padded with nulls
        let mut data = vec![0x00u8; 2];
        for b in b"Test" {
            data.push(*b);
            data.push(0x00);
        }
        data.push(0x00);
        data.push(0x00);
        let config = UnicodeStringConfig { min_char_count: 4, encodings: ScanEncodings::none().with_utf16le(true) };
        let strings = scan_unicode_strings(&data, &config);
        assert!(strings.iter().any(|s| s.text.contains("Test")));
    }

    #[test]
    fn deduplicate_strings_removes_duplicates() {
        let s1 = UnicodeString { offset: 0, byte_len: 5, text: "Hello".into(), encoding: UnicodeEncoding::Ascii, null_terminated: true };
        let s2 = UnicodeString { offset: 10, byte_len: 10, text: "Hello".into(), encoding: UnicodeEncoding::Utf16Le, null_terminated: true };
        let deduped = deduplicate_strings(vec![s1, s2]);
        assert_eq!(deduped.len(), 1);
    }
}
