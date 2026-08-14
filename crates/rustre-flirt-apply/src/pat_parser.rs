//! `.pat` text-format parser for IDA FLIRT patterns.
//!
//! Each non-header line has the form:
//! ```text
//! PATBYTES :CRC_LEN CRC16 TOTAL_LEN :OFFSET:KIND:NAME[ :OFFSET:KIND:NAME...]
//! ```
//! where PATBYTES is a continuous hex string with `..` for wildcards.

use std::fmt;

// ── PatError ──────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a `.pat` text file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatError {
    /// A line (1-based) was structurally invalid.
    InvalidLine(usize),
    /// A hex string could not be decoded.
    InvalidHex(String),
    /// A CRC field was malformed.
    InvalidCrc(String),
    /// The input was empty (no non-comment lines).
    Empty,
}

impl fmt::Display for PatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine(n) => write!(f, "invalid pat line {n}"),
            Self::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            Self::InvalidCrc(s) => write!(f, "invalid crc field: {s}"),
            Self::Empty => write!(f, "empty pat input"),
        }
    }
}

impl std::error::Error for PatError {}

// ── PatNameKind ───────────────────────────────────────────────────────────────

/// The kind of a name entry in a `.pat` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatNameKind {
    /// Globally visible (exported) symbol.
    Public,
    /// File-local symbol.
    Local,
    /// A reference to another symbol embedded in the function.
    Reference,
}

// ── PatName ───────────────────────────────────────────────────────────────────

/// A single name entry within a parsed `.pat` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatName {
    /// Byte offset from the function start.
    pub offset: u16,
    /// Kind of the name.
    pub kind: PatNameKind,
    /// The symbol name string.
    pub name: String,
}

// ── PatLine ───────────────────────────────────────────────────────────────────

/// A fully parsed `.pat` line.
#[derive(Debug, Clone)]
pub struct PatLine {
    /// Initial pattern bytes; `None` = wildcard.
    pub pattern_bytes: Vec<Option<u8>>,
    /// Number of bytes after the initial block that the CRC covers.
    pub crc_len: u8,
    /// CRC-16 of the covered bytes.
    pub crc16: u16,
    /// Total length of the function.
    pub total_len: u16,
    /// All name entries on this line.
    pub names: Vec<PatName>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a complete `.pat` text into a list of [`PatLine`]s.
///
/// Lines starting with `---` (separator / `---END---`) are skipped silently.
/// Blank lines are also skipped.
///
/// # Errors
///
/// Returns the first [`PatError`] encountered.
pub fn parse_pat_text(text: &str) -> Result<Vec<PatLine>, PatError> {
    let mut results = Vec::new();
    let mut lineno = 0usize;

    for raw in text.lines() {
        lineno += 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with("---") {
            continue;
        }
        let parsed = parse_pat_line(line, lineno)?;
        results.push(parsed);
    }

    Ok(results)
}

/// Parse a single `.pat` line.
///
/// Format: `PATBYTES :CRC_LEN CRC16 TOTAL_LEN :OFF:KIND:NAME ...`
///
/// # Errors
///
/// Returns [`PatError::InvalidLine`] for structural problems, and the
/// specialised error variants for hex / CRC decoding failures.
pub fn parse_pat_line(line: &str, lineno: usize) -> Result<PatLine, PatError> {
    // Split off the leading pattern-bytes token from the rest.
    // The pattern-bytes token is the first whitespace-delimited field.
    let (pat_hex, rest) = line
        .split_once(char::is_whitespace)
        .ok_or(PatError::InvalidLine(lineno))?;
    let rest = rest.trim_start();

    let pattern_bytes = parse_hex_pattern(pat_hex)?;

    // The next field must start with ':' and have the form:
    // `:CRC_LEN CRC16 TOTAL_LEN`
    if !rest.starts_with(':') {
        return Err(PatError::InvalidLine(lineno));
    }
    let rest = &rest[1..]; // skip leading ':'

    // Parse CRC_LEN (decimal), CRC16 (hex), TOTAL_LEN (decimal)
    let (crc_len, rest) = parse_next_token(rest, lineno)?;
    let (crc16_tok, rest) = parse_next_token(rest, lineno)?;
    let (total_len_tok, rest) = parse_next_token(rest, lineno)?;

    let crc_len: u8 = crc_len
        .parse()
        .map_err(|_| PatError::InvalidCrc(crc_len.to_string()))?;
    let crc16: u16 = u16::from_str_radix(crc16_tok, 16)
        .map_err(|_| PatError::InvalidCrc(crc16_tok.to_string()))?;
    let total_len: u16 = total_len_tok
        .parse()
        .map_err(|_| PatError::InvalidCrc(total_len_tok.to_string()))?;

    // Parse name entries: `:OFFSET:KIND:NAME`
    let names = parse_name_entries(rest.trim_start(), lineno)?;

    Ok(PatLine {
        pattern_bytes,
        crc_len,
        crc16,
        total_len,
        names,
    })
}

/// Parse a hex pattern string where each byte is two hex digits and `..` denotes
/// a wildcard.
///
/// The string must have an even number of characters.
///
/// # Errors
///
/// Returns [`PatError::InvalidHex`] if the string contains invalid characters
/// or has an odd length.
pub fn parse_hex_pattern(s: &str) -> Result<Vec<Option<u8>>, PatError> {
    if !s.len().is_multiple_of(2) {
        return Err(PatError::InvalidHex(format!("odd-length hex string: {s}")));
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = bytes[i];
        let lo = bytes[i + 1];
        if hi == b'.' && lo == b'.' {
            result.push(None);
        } else {
            let h = hex_nibble(hi).ok_or_else(|| {
                PatError::InvalidHex(format!("bad char '{}' in {s}", char::from(hi)))
            })?;
            let l = hex_nibble(lo).ok_or_else(|| {
                PatError::InvalidHex(format!("bad char '{}' in {s}", char::from(lo)))
            })?;
            result.push(Some((h << 4) | l));
        }
        i += 2;
    }
    Ok(result)
}

/// Decompose a [`PatLine`] into its raw fields.
///
/// Returns `(pattern_bytes, crc_len, crc16, total_len)`.
#[must_use]
pub fn pat_line_to_bytes(line: &PatLine) -> (Vec<Option<u8>>, u8, u16, u16) {
    (
        line.pattern_bytes.clone(),
        line.crc_len,
        line.crc16,
        line.total_len,
    )
}

// ── Internal helpers ──────────────────────────────────────────────────────────

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Pull the next whitespace-separated token from `s`.
///
/// Returns `(token, remainder)`.
fn parse_next_token(s: &str, lineno: usize) -> Result<(&str, &str), PatError> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(PatError::InvalidLine(lineno));
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Ok((&s[..end], &s[end..]))
}

/// Parse zero or more `:OFFSET:KIND:NAME` name entries.
fn parse_name_entries(s: &str, lineno: usize) -> Result<Vec<PatName>, PatError> {
    let mut names = Vec::new();
    let mut rest = s;

    while !rest.is_empty() {
        let r = rest.trim_start();
        if r.is_empty() {
            break;
        }
        if !r.starts_with(':') {
            // Could be trailing whitespace or garbage — stop gracefully.
            break;
        }
        let inner = &r[1..]; // skip ':'

        // Format: OFFSET:KIND:NAME
        // OFFSET is a 4-digit hex string (or decimal — IDA uses hex)
        let (offset_tok, inner) = parse_next_colon_token(inner, lineno)?;
        let (kind_tok, inner) = parse_next_colon_token(inner, lineno)?;
        // Name extends until the next ':' (next name entry) or end
        let (name_tok, remaining) = split_name_from_rest(inner);

        let offset: u16 = u16::from_str_radix(offset_tok, 16)
            .or_else(|_| offset_tok.parse::<u16>())
            .map_err(|_| PatError::InvalidLine(lineno))?;

        let kind = match kind_tok {
            "local" | "l" => PatNameKind::Local,
            "ref" | "r" | "reference" => PatNameKind::Reference,
            _ => PatNameKind::Public, // default for unknown kinds (including "public" | "p")
        };

        if !name_tok.is_empty() {
            names.push(PatName {
                offset,
                kind,
                name: name_tok.to_string(),
            });
        }

        rest = remaining;
    }

    Ok(names)
}

/// Split off the next colon-separated token from `s`.
///
/// Returns `(token_before_colon, rest_after_colon)`.
fn parse_next_colon_token(s: &str, lineno: usize) -> Result<(&str, &str), PatError> {
    let pos = s.find(':').ok_or(PatError::InvalidLine(lineno))?;
    Ok((&s[..pos], &s[pos + 1..]))
}

/// Split a name token from the rest of the string.
///
/// A name runs until the next ` :` (space followed by colon) or end of string.
fn split_name_from_rest(s: &str) -> (&str, &str) {
    // Find " :" which signals the start of the next name entry
    find_space_colon(s).map_or_else(|| (s.trim_end(), ""), |pos| (&s[..pos], &s[pos + 1..]))
}

/// Find the position of the first ` :` sequence in `s`.
fn find_space_colon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    (0..bytes.len().saturating_sub(1)).find(|&i| bytes[i] == b' ' && bytes[i + 1] == b':')
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hex_pattern ────────────────────────────────────────────────────

    #[test]
    fn test_parse_hex_exact_bytes() {
        let r = parse_hex_pattern("558BEC").unwrap();
        assert_eq!(r, vec![Some(0x55), Some(0x8B), Some(0xEC)]);
    }

    #[test]
    fn test_parse_hex_with_wildcards() {
        let r = parse_hex_pattern("55..EC").unwrap();
        assert_eq!(r, vec![Some(0x55), None, Some(0xEC)]);
    }

    #[test]
    fn test_parse_hex_all_wildcards() {
        let r = parse_hex_pattern("......").unwrap();
        assert_eq!(r, vec![None, None, None]);
    }

    #[test]
    fn test_parse_hex_empty() {
        let r = parse_hex_pattern("").unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_parse_hex_odd_length_error() {
        let r = parse_hex_pattern("55A");
        assert!(matches!(r, Err(PatError::InvalidHex(_))));
    }

    #[test]
    fn test_parse_hex_invalid_char_error() {
        let r = parse_hex_pattern("55ZZ");
        assert!(matches!(r, Err(PatError::InvalidHex(_))));
    }

    #[test]
    fn test_parse_hex_lowercase() {
        let r = parse_hex_pattern("aabb").unwrap();
        assert_eq!(r, vec![Some(0xAA), Some(0xBB)]);
    }

    // ── parse_pat_line ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_pat_line_basic() {
        // Minimal valid pat line
        let line = "558BEC :0 0000 3 :0000:public:my_func";
        let pl = parse_pat_line(line, 1).unwrap();
        assert_eq!(pl.pattern_bytes, vec![Some(0x55), Some(0x8B), Some(0xEC)]);
        assert_eq!(pl.crc_len, 0);
        assert_eq!(pl.crc16, 0);
        assert_eq!(pl.total_len, 3);
        assert_eq!(pl.names.len(), 1);
        assert_eq!(pl.names[0].name, "my_func");
        assert_eq!(pl.names[0].kind, PatNameKind::Public);
        assert_eq!(pl.names[0].offset, 0);
    }

    #[test]
    fn test_parse_pat_line_with_crc() {
        let line = "558BEC..8B4508 :4 ABCD 20 :0000:public:func_a";
        let pl = parse_pat_line(line, 1).unwrap();
        assert_eq!(pl.crc_len, 4);
        assert_eq!(pl.crc16, 0xABCD);
        assert_eq!(pl.total_len, 20);
    }

    #[test]
    fn test_parse_pat_line_multiple_names() {
        let line = "55..8B :2 1234 10 :0000:public:main_fn :0004:local:helper";
        let pl = parse_pat_line(line, 1).unwrap();
        assert_eq!(pl.names.len(), 2);
        assert_eq!(pl.names[0].name, "main_fn");
        assert_eq!(pl.names[0].kind, PatNameKind::Public);
        assert_eq!(pl.names[1].name, "helper");
        assert_eq!(pl.names[1].kind, PatNameKind::Local);
        assert_eq!(pl.names[1].offset, 4);
    }

    #[test]
    fn test_parse_pat_line_reference_kind() {
        let line = "AA :0 0000 5 :0000:public:fn :0002:ref:ext_sym";
        let pl = parse_pat_line(line, 1).unwrap();
        assert_eq!(pl.names[1].kind, PatNameKind::Reference);
    }

    #[test]
    fn test_parse_pat_line_missing_colon_error() {
        // No ':' prefix for crc section
        let line = "558BEC 0 0000 3 :0000:public:f";
        let r = parse_pat_line(line, 2);
        assert!(matches!(r, Err(PatError::InvalidLine(2))));
    }

    // ── parse_pat_text ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_pat_text_skips_separator() {
        let text = "---\n558BEC :0 0000 3 :0000:public:f\n---END---\n";
        let lines = parse_pat_text(text).unwrap();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_parse_pat_text_skips_blank_lines() {
        let text = "\n\n558BEC :0 0000 3 :0000:public:f\n\n";
        let lines = parse_pat_text(text).unwrap();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_parse_pat_text_multiple_lines() {
        let text = concat!(
            "558BEC :0 0000 3 :0000:public:func1\n",
            "488B..C3 :2 BEEF 4 :0000:public:func2\n"
        );
        let lines = parse_pat_text(text).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].names[0].name, "func1");
        assert_eq!(lines[1].names[0].name, "func2");
    }

    #[test]
    fn test_parse_pat_text_empty_returns_empty() {
        let lines = parse_pat_text("").unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn test_parse_pat_text_only_separators() {
        let lines = parse_pat_text("---\n---END---\n").unwrap();
        assert!(lines.is_empty());
    }

    // ── pat_line_to_bytes ─────────────────────────────────────────────────────

    #[test]
    fn test_pat_line_to_bytes() {
        let pl = PatLine {
            pattern_bytes: vec![Some(0x55), None],
            crc_len: 4,
            crc16: 0x1234,
            total_len: 20,
            names: vec![],
        };
        let (bytes, cl, c16, tl) = pat_line_to_bytes(&pl);
        assert_eq!(bytes, vec![Some(0x55), None]);
        assert_eq!(cl, 4);
        assert_eq!(c16, 0x1234);
        assert_eq!(tl, 20);
    }

    // ── PatError display ──────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_line() {
        let e = PatError::InvalidLine(5);
        assert!(e.to_string().contains('5'));
    }

    #[test]
    fn test_error_display_invalid_hex() {
        let e = PatError::InvalidHex("ZZ".to_string());
        assert!(e.to_string().contains("ZZ"));
    }

    #[test]
    fn test_error_display_invalid_crc() {
        let e = PatError::InvalidCrc("XYZW".to_string());
        assert!(e.to_string().contains("XYZW"));
    }

    #[test]
    fn test_error_display_empty() {
        assert!(!PatError::Empty.to_string().is_empty());
    }

    // ── PatNameKind ───────────────────────────────────────────────────────────

    #[test]
    fn test_pat_name_kind_eq() {
        assert_eq!(PatNameKind::Public, PatNameKind::Public);
        assert_ne!(PatNameKind::Public, PatNameKind::Local);
    }

    // ── Realistic .pat lines ─────────────────────────────────────────────────

    #[test]
    fn test_parse_realistic_memcpy_line() {
        // Simulated realistic .pat line for memcpy
        let line = "558BEC8B4D108B550C8B4508........ :4 A1B2 40 :0000:public:memcpy";
        let pl = parse_pat_line(line, 1).unwrap();
        assert_eq!(pl.names[0].name, "memcpy");
        assert_eq!(pl.total_len, 40);
    }

    #[test]
    fn test_parse_long_pattern_bytes() {
        // 32-byte pattern (64 hex chars)
        let pat = "5548890000000000000000000000000000000000000000000000000000000000";
        let line = format!("{pat} :0 0000 32 :0000:public:big_fn");
        let pl = parse_pat_line(&line, 1).unwrap();
        assert_eq!(pl.pattern_bytes.len(), 32);
    }
}
