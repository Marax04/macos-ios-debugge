//! Full PDF object parser.
//!
//! Provides `PdfParser`, a byte-oriented parser that walks raw PDF data and
//! produces `PdfObjKind` values for every object type defined by the PDF spec.

use super::PdfObjKind;

// ── PdfParser ─────────────────────────────────────────────────────────────────

/// Stateful, forward-scanning PDF byte parser.
#[derive(Debug)]
pub struct PdfParser {
    /// Raw file bytes.
    pub data: Vec<u8>,
    /// Current read position.
    pub pos: usize,
}

impl PdfParser {
    /// Construct a new `PdfParser` owning `data`.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Peek at the byte at the current position without advancing.
    ///
    /// Returns `0` when past end-of-data.
    #[must_use]
    pub fn at_pos(&self) -> u8 {
        self.data.get(self.pos).copied().unwrap_or(0)
    }

    /// Return `true` when the parser has consumed all bytes.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Advance `pos` past any PDF whitespace (space, tab, CR, LF, FF, NUL)
    /// and comment lines that begin with `%`.
    pub fn skip_whitespace(&mut self) {
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' || b == b'\x0C' || b == 0 {
                self.pos += 1;
            } else if b == b'%' {
                self.skip_comment();
            } else {
                break;
            }
        }
    }

    /// Skip from the current `%` to the end of the line (inclusive).
    pub fn skip_comment(&mut self) {
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            if b == b'\n' || b == b'\r' {
                break;
            }
        }
    }

    /// Read bytes until (and not including) the next CR or LF; advances past
    /// the line terminator.  Returns a slice into the internal buffer.
    pub fn read_line(&mut self) -> &[u8] {
        let start = self.pos;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b'\n' || b == b'\r' {
                break;
            }
            self.pos += 1;
        }
        let end = self.pos;
        // Skip the line terminator (handle CRLF too)
        if self.pos < self.data.len() && self.data[self.pos] == b'\r' {
            self.pos += 1;
        }
        if self.pos < self.data.len() && self.data[self.pos] == b'\n' {
            self.pos += 1;
        }
        &self.data[start..end]
    }

    /// Try to parse a `true` or `false` PDF boolean.
    pub fn parse_boolean(&mut self) -> Option<bool> {
        self.skip_whitespace();
        if self.data[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Some(true)
        } else if self.data[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Some(false)
        } else {
            None
        }
    }

    /// Parse an integer or real number.
    ///
    /// Returns `PdfObjKind::Integer` for integers and `PdfObjKind::Real` for
    /// numbers containing a decimal point.
    pub fn parse_number(&mut self) -> Option<PdfObjKind> {
        self.skip_whitespace();
        let start = self.pos;
        let mut has_dot = false;
        // Leading sign
        if self.pos < self.data.len()
            && (self.data[self.pos] == b'+' || self.data[self.pos] == b'-')
        {
            self.pos += 1;
        }
        let digit_start = self.pos;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b.is_ascii_digit() {
                self.pos += 1;
            } else if b == b'.' && !has_dot {
                has_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == digit_start {
            self.pos = start;
            return None;
        }
        let s = std::str::from_utf8(&self.data[start..self.pos]).ok()?;
        if has_dot {
            let r: f64 = s.parse().ok()?;
            Some(PdfObjKind::Real(r))
        } else {
            let n: i64 = s.parse().ok()?;
            Some(PdfObjKind::Integer(n))
        }
    }

    /// Parse a PDF name object: `/Name` with optional `#XX` hex escapes.
    pub fn parse_name(&mut self) -> Option<String> {
        self.skip_whitespace();
        if self.pos >= self.data.len() || self.data[self.pos] != b'/' {
            return None;
        }
        self.pos += 1; // consume '/'
        let mut name = String::new();
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b'#' && self.pos + 2 < self.data.len() {
                // Hex escape
                let hi = self.data[self.pos + 1];
                let lo = self.data[self.pos + 2];
                if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                    let val = hex_byte(hi) * 16 + hex_byte(lo);
                    name.push(val as char);
                    self.pos += 3;
                    continue;
                }
            }
            // Delimiters that end a name
            if b == b' '
                || b == b'\t'
                || b == b'\r'
                || b == b'\n'
                || b == b'/'
                || b == b'<'
                || b == b'>'
                || b == b'['
                || b == b']'
                || b == b'('
                || b == b')'
                || b == b'%'
                || b == b'{'
                || b == b'}'
            {
                break;
            }
            name.push(b as char);
            self.pos += 1;
        }
        Some(name)
    }

    /// Parse a PDF literal string: `(...)` with balanced parens and escape
    /// sequences `\n \r \t \\ \( \)`.
    pub fn parse_literal_string(&mut self) -> Option<String> {
        self.skip_whitespace();
        if self.pos >= self.data.len() || self.data[self.pos] != b'(' {
            return None;
        }
        self.pos += 1; // consume '('
        let mut result = String::new();
        let mut depth: usize = 1;
        while self.pos < self.data.len() && depth > 0 {
            let b = self.data[self.pos];
            self.pos += 1;
            match b {
                b'(' => {
                    depth += 1;
                    result.push('(');
                }
                b')' => {
                    depth -= 1;
                    if depth > 0 {
                        result.push(')');
                    }
                }
                b'\\' => {
                    if self.pos < self.data.len() {
                        let esc = self.data[self.pos];
                        self.pos += 1;
                        match esc {
                            b'n' => result.push('\n'),
                            b'r' => result.push('\r'),
                            b't' => result.push('\t'),
                            b'\\' => result.push('\\'),
                            b'(' => result.push('('),
                            b')' => result.push(')'),
                            b'\n' | b'\r' => {} // line continuation
                            _ => {
                                result.push('\\');
                                result.push(esc as char);
                            }
                        }
                    }
                }
                _ => result.push(b as char),
            }
        }
        Some(result)
    }

    /// Parse a PDF hex string: `<hexdata>`.
    pub fn parse_hex_string(&mut self) -> Option<Vec<u8>> {
        self.skip_whitespace();
        if self.pos >= self.data.len() || self.data[self.pos] != b'<' {
            return None;
        }
        // Distinguish from `<<` (dict start)
        if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'<' {
            return None;
        }
        self.pos += 1; // consume '<'
        let mut bytes = Vec::new();
        let mut nibble: Option<u8> = None;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            if b == b'>' {
                break;
            }
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                continue;
            }
            if b.is_ascii_hexdigit() {
                let v = hex_byte(b);
                if let Some(hi) = nibble.take() {
                    bytes.push(hi * 16 + v);
                } else {
                    nibble = Some(v);
                }
            }
        }
        // Odd nibble: treat last as high nibble padded with 0
        if let Some(hi) = nibble {
            bytes.push(hi * 16);
        }
        Some(bytes)
    }

    /// Parse a PDF array: `[obj1 obj2 ...]`.
    pub fn parse_array(&mut self) -> Option<Vec<PdfObjKind>> {
        self.skip_whitespace();
        if self.pos >= self.data.len() || self.data[self.pos] != b'[' {
            return None;
        }
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.data.len() {
                break;
            }
            if self.data[self.pos] == b']' {
                self.pos += 1;
                break;
            }
            match self.parse_object() {
                Some(obj) => items.push(obj),
                None => break,
            }
        }
        Some(items)
    }

    /// Parse a PDF dictionary: `<< /Key val ... >>`.
    pub fn parse_dict(&mut self) -> Option<Vec<(String, PdfObjKind)>> {
        self.skip_whitespace();
        if self.pos + 1 >= self.data.len() {
            return None;
        }
        if self.data[self.pos] != b'<' || self.data[self.pos + 1] != b'<' {
            return None;
        }
        self.pos += 2; // consume '<<'
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos + 1 < self.data.len()
                && self.data[self.pos] == b'>'
                && self.data[self.pos + 1] == b'>'
            {
                self.pos += 2;
                break;
            }
            if self.pos >= self.data.len() {
                break;
            }
            let key = self.parse_name()?;
            self.skip_whitespace();
            let val = self.parse_object()?;
            entries.push((key, val));
        }
        Some(entries)
    }

    /// Parse the next PDF object at the current position, dispatching on the
    /// first significant byte.
    pub fn parse_object(&mut self) -> Option<PdfObjKind> {
        self.skip_whitespace();
        if self.pos >= self.data.len() {
            return None;
        }
        let b = self.data[self.pos];
        match b {
            b't' | b'f' => self.parse_boolean().map(PdfObjKind::Boolean),
            b'n' if self.data[self.pos..].starts_with(b"null") => {
                self.pos += 4;
                Some(PdfObjKind::Null)
            }
            b'/' => self.parse_name().map(PdfObjKind::Name),
            b'(' => self.parse_literal_string().map(PdfObjKind::PdfString),
            b'<' => {
                if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'<' {
                    self.parse_dict().map(PdfObjKind::Dictionary)
                } else {
                    self.parse_hex_string()
                        .map(|v| PdfObjKind::PdfString(String::from_utf8_lossy(&v).into_owned()))
                }
            }
            b'[' => self.parse_array().map(PdfObjKind::Array),
            b'+' | b'-' | b'0'..=b'9' | b'.' => self.parse_indirect_ref_or_number(),
            _ => None,
        }
    }

    /// Parse either an indirect reference `N G R` or a plain number.
    ///
    /// Saves the position before parsing so that on failure (not a reference)
    /// the plain number already consumed is returned.
    pub fn parse_indirect_ref_or_number(&mut self) -> Option<PdfObjKind> {
        let saved = self.pos;
        // Parse first number
        let n1 = match self.parse_number()? {
            PdfObjKind::Integer(n) => n,
            other => return Some(other),
        };
        // Try to read second number + 'R'
        let pos_after_n1 = self.pos;
        self.skip_whitespace();
        let n2 = match self.parse_number() {
            Some(PdfObjKind::Integer(n)) => n,
            _ => {
                self.pos = pos_after_n1;
                return Some(PdfObjKind::Integer(n1));
            }
        };
        let pos_after_n2 = self.pos;
        self.skip_whitespace();
        if self.pos < self.data.len() && self.data[self.pos] == b'R' {
            // Peek ahead: must be followed by delimiter
            let after_r = self.pos + 1;
            let next = self.data.get(after_r).copied().unwrap_or(b' ');
            if next == b' '
                || next == b'\t'
                || next == b'\r'
                || next == b'\n'
                || next == b'>'
                || next == b']'
                || next == b'/'
                || next == b'('
                || next == b'%'
            {
                self.pos += 1; // consume 'R'
                if n1 >= 0 && n2 >= 0 {
                    return Some(PdfObjKind::Reference {
                        obj: n1 as u32,
                        generation: n2 as u32,
                    });
                }
            }
        }
        // Not a reference — rewind to before the second number so it can be
        // parsed as the next independent token in the stream.
        self.pos = pos_after_n1;
        let _ = (saved, pos_after_n2); // keep borrow checker happy
        Some(PdfObjKind::Integer(n1))
    }

    /// Search the data buffer for the marker `N G obj` and position the parser
    /// there.  Returns `true` on success.
    pub fn seek_to_obj(&mut self, obj_num: u32, generation: u32) -> bool {
        let needle = format!("{obj_num} {generation} obj");
        let nbytes = needle.as_bytes();
        let limit = if self.data.len() >= nbytes.len() {
            self.data.len() - nbytes.len()
        } else {
            return false;
        };
        for i in 0..=limit {
            if self.data[i..i + nbytes.len()] == *nbytes {
                // Ensure it's not part of a larger number
                let ok_before = i == 0 || {
                    let b = self.data[i - 1];
                    b == b'\n' || b == b'\r' || b == b' ' || b == b'\t'
                };
                if ok_before {
                    self.pos = i + nbytes.len();
                    return true;
                }
            }
        }
        false
    }

    /// Parse a complete indirect object `N G obj ... endobj`.
    ///
    /// Returns `(obj_num, gen_num, value)` on success.
    pub fn parse_indirect_object(&mut self) -> Option<(u32, u32, PdfObjKind)> {
        self.skip_whitespace();
        let saved = self.pos;
        let n1 = match self.parse_number()? {
            PdfObjKind::Integer(n) => n,
            _ => {
                self.pos = saved;
                return None;
            }
        };
        self.skip_whitespace();
        let n2 = match self.parse_number()? {
            PdfObjKind::Integer(n) => n,
            _ => {
                self.pos = saved;
                return None;
            }
        };
        self.skip_whitespace();
        if !self.data[self.pos..].starts_with(b"obj") {
            self.pos = saved;
            return None;
        }
        self.pos += 3; // consume 'obj'
        self.skip_whitespace();

        // Check for stream after dict
        let dict = if self.pos + 1 < self.data.len()
            && self.data[self.pos] == b'<'
            && self.data[self.pos + 1] == b'<'
        {
            self.parse_dict()
        } else {
            None
        };

        if let Some(d) = dict {
            self.skip_whitespace();
            if self.data[self.pos..].starts_with(b"stream") {
                self.pos += 6;
                // Skip optional CR+LF or LF after 'stream'
                if self.pos < self.data.len() && self.data[self.pos] == b'\r' {
                    self.pos += 1;
                }
                if self.pos < self.data.len() && self.data[self.pos] == b'\n' {
                    self.pos += 1;
                }
                let stream_start = self.pos;
                // Find 'endstream'
                let endstream = self.data[self.pos..]
                    .windows(9)
                    .position(|w| w == b"endstream")
                    .unwrap_or(0);
                let length = endstream;
                self.pos += endstream + 9;
                // skip to endobj
                if let Some(eob) = self.data[self.pos..]
                    .windows(6)
                    .position(|w| w == b"endobj")
                {
                    self.pos += eob + 6;
                }
                return Some((
                    n1 as u32,
                    n2 as u32,
                    PdfObjKind::Stream {
                        dict: d,
                        offset: stream_start,
                        length,
                    },
                ));
            }
            // Plain dict
            if let Some(eob) = self.data[self.pos..]
                .windows(6)
                .position(|w| w == b"endobj")
            {
                self.pos += eob + 6;
            }
            return Some((n1 as u32, n2 as u32, PdfObjKind::Dictionary(d)));
        }

        let val = self.parse_object()?;
        // Skip to endobj
        if let Some(eob) = self.data[self.pos..]
            .windows(6)
            .position(|w| w == b"endobj")
        {
            self.pos += eob + 6;
        }
        Some((n1 as u32, n2 as u32, val))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Convert a hex ASCII byte to its nibble value.
const fn hex_byte(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PdfObjKind;

    fn parser(s: &[u8]) -> PdfParser {
        PdfParser::new(s.to_vec())
    }

    // ── at_pos / is_eof ───────────────────────────────────────────────────────

    #[test]
    fn test_at_pos_returns_current_byte() {
        let p = parser(b"hello");
        assert_eq!(p.at_pos(), b'h');
    }

    #[test]
    fn test_at_pos_eof_returns_zero() {
        let mut p = parser(b"x");
        p.pos = 10;
        assert_eq!(p.at_pos(), 0);
    }

    #[test]
    fn test_is_eof_false() {
        let p = parser(b"x");
        assert!(!p.is_eof());
    }

    #[test]
    fn test_is_eof_true() {
        let mut p = parser(b"x");
        p.pos = 1;
        assert!(p.is_eof());
    }

    // ── skip_whitespace ───────────────────────────────────────────────────────

    #[test]
    fn test_skip_whitespace_spaces_tabs() {
        let mut p = parser(b"   \t\n hello");
        p.skip_whitespace();
        assert_eq!(p.at_pos(), b'h');
    }

    #[test]
    fn test_skip_whitespace_skips_comment() {
        let mut p = parser(b"% comment\nhello");
        p.skip_whitespace();
        assert_eq!(p.at_pos(), b'h');
    }

    #[test]
    fn test_skip_whitespace_multiple_comments() {
        let mut p = parser(b"% a\n% b\nX");
        p.skip_whitespace();
        assert_eq!(p.at_pos(), b'X');
    }

    // ── skip_comment ─────────────────────────────────────────────────────────

    #[test]
    fn test_skip_comment_to_lf() {
        let mut p = parser(b"% abc\nY");
        p.skip_comment();
        assert_eq!(p.at_pos(), b'Y');
    }

    #[test]
    fn test_skip_comment_to_cr() {
        let mut p = parser(b"% abc\rY");
        p.skip_comment();
        assert_eq!(p.at_pos(), b'Y');
    }

    // ── read_line ─────────────────────────────────────────────────────────────

    #[test]
    fn test_read_line_basic() {
        let mut p = parser(b"hello\nworld");
        let line = p.read_line().to_vec();
        assert_eq!(line, b"hello");
        assert_eq!(p.at_pos(), b'w');
    }

    #[test]
    fn test_read_line_crlf() {
        let mut p = parser(b"hello\r\nworld");
        let line = p.read_line().to_vec();
        assert_eq!(line, b"hello");
        assert_eq!(p.at_pos(), b'w');
    }

    // ── parse_boolean ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_boolean_true() {
        let mut p = parser(b"true");
        assert_eq!(p.parse_boolean(), Some(true));
    }

    #[test]
    fn test_parse_boolean_false() {
        let mut p = parser(b"false");
        assert_eq!(p.parse_boolean(), Some(false));
    }

    #[test]
    fn test_parse_boolean_with_leading_whitespace() {
        let mut p = parser(b"  true");
        assert_eq!(p.parse_boolean(), Some(true));
    }

    #[test]
    fn test_parse_boolean_none() {
        let mut p = parser(b"42");
        assert_eq!(p.parse_boolean(), None);
    }

    // ── parse_number ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_number_integer() {
        let mut p = parser(b"42");
        assert!(matches!(p.parse_number(), Some(PdfObjKind::Integer(42))));
    }

    #[test]
    fn test_parse_number_negative() {
        let mut p = parser(b"-7");
        assert!(matches!(p.parse_number(), Some(PdfObjKind::Integer(-7))));
    }

    #[test]
    fn test_parse_number_real() {
        let mut p = parser(b"3.14");
        assert!(matches!(p.parse_number(), Some(PdfObjKind::Real(_))));
    }

    #[test]
    fn test_parse_number_none_on_name() {
        let mut p = parser(b"/Name");
        assert!(p.parse_number().is_none());
    }

    // ── parse_name ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_name_simple() {
        let mut p = parser(b"/Type");
        assert_eq!(p.parse_name().unwrap(), "Type");
    }

    #[test]
    fn test_parse_name_hex_escape() {
        // #4D = 0x4D = 'M' uppercase; result is "NaMe"
        let mut p = parser(b"/Na#4De");
        assert_eq!(p.parse_name().unwrap(), "NaMe");
    }

    #[test]
    fn test_parse_name_none_no_slash() {
        let mut p = parser(b"Type");
        assert!(p.parse_name().is_none());
    }

    // ── parse_literal_string ──────────────────────────────────────────────────

    #[test]
    fn test_parse_literal_string_simple() {
        let mut p = parser(b"(hello)");
        assert_eq!(p.parse_literal_string().unwrap(), "hello");
    }

    #[test]
    fn test_parse_literal_string_nested_parens() {
        let mut p = parser(b"(a(b)c)");
        assert_eq!(p.parse_literal_string().unwrap(), "a(b)c");
    }

    #[test]
    fn test_parse_literal_string_escape_n() {
        let mut p = parser(b"(a\\nb)");
        let s = p.parse_literal_string().unwrap();
        assert!(s.contains('\n'));
    }

    #[test]
    fn test_parse_literal_string_escape_parens() {
        let mut p = parser(b"(\\(\\))");
        assert_eq!(p.parse_literal_string().unwrap(), "()");
    }

    // ── parse_hex_string ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_hex_string_simple() {
        let mut p = parser(b"<4142>");
        assert_eq!(p.parse_hex_string().unwrap(), b"AB");
    }

    #[test]
    fn test_parse_hex_string_odd_nibble() {
        let mut p = parser(b"<4>");
        assert_eq!(p.parse_hex_string().unwrap(), &[0x40]);
    }

    #[test]
    fn test_parse_hex_string_ignores_whitespace() {
        let mut p = parser(b"<41 42>");
        assert_eq!(p.parse_hex_string().unwrap(), b"AB");
    }

    #[test]
    fn test_parse_hex_string_not_dict() {
        let mut p = parser(b"<<");
        assert!(p.parse_hex_string().is_none());
    }

    // ── parse_array ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_array_integers() {
        let mut p = parser(b"[1 2 3]");
        let arr = p.parse_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_parse_array_mixed() {
        let mut p = parser(b"[1 /Name true]");
        let arr = p.parse_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_parse_array_empty() {
        let mut p = parser(b"[]");
        let arr = p.parse_array().unwrap();
        assert!(arr.is_empty());
    }

    // ── parse_dict ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_dict_simple() {
        let mut p = parser(b"<</Type /Catalog>>");
        let d = p.parse_dict().unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "Type");
    }

    #[test]
    fn test_parse_dict_multiple_entries() {
        let mut p = parser(b"<</A 1 /B 2>>");
        let d = p.parse_dict().unwrap();
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn test_parse_dict_empty() {
        let mut p = parser(b"<<>>");
        let d = p.parse_dict().unwrap();
        assert!(d.is_empty());
    }

    // ── parse_indirect_ref_or_number ─────────────────────────────────────────

    #[test]
    fn test_indirect_ref_parsed() {
        let mut p = parser(b"1 0 R");
        let obj = p.parse_indirect_ref_or_number().unwrap();
        assert!(matches!(
            obj,
            PdfObjKind::Reference {
                obj: 1,
                generation: 0
            }
        ));
    }

    #[test]
    fn test_indirect_ref_plain_integer() {
        let mut p = parser(b"42 endobj");
        let obj = p.parse_indirect_ref_or_number().unwrap();
        assert!(matches!(obj, PdfObjKind::Integer(42)));
    }

    // ── seek_to_obj ───────────────────────────────────────────────────────────

    #[test]
    fn test_seek_to_obj_found() {
        let mut p = parser(b"\n3 0 obj\n42\nendobj\n");
        assert!(p.seek_to_obj(3, 0));
    }

    #[test]
    fn test_seek_to_obj_not_found() {
        let mut p = parser(b"nothing here");
        assert!(!p.seek_to_obj(99, 0));
    }

    // ── parse_indirect_object ─────────────────────────────────────────────────

    #[test]
    fn test_parse_indirect_object_integer() {
        let mut p = parser(b"5 0 obj\n42\nendobj\n");
        let (n, g, val) = p.parse_indirect_object().unwrap();
        assert_eq!(n, 5);
        assert_eq!(g, 0);
        assert!(matches!(val, PdfObjKind::Integer(42)));
    }

    #[test]
    fn test_parse_indirect_object_boolean() {
        let mut p = parser(b"1 0 obj\ntrue\nendobj\n");
        let (_, _, val) = p.parse_indirect_object().unwrap();
        assert!(matches!(val, PdfObjKind::Boolean(true)));
    }

    #[test]
    fn test_parse_indirect_object_dict() {
        let mut p = parser(b"2 0 obj\n<</Type /Catalog>>\nendobj\n");
        let (_, _, val) = p.parse_indirect_object().unwrap();
        assert!(matches!(val, PdfObjKind::Dictionary(_)));
    }

    #[test]
    fn test_parse_indirect_object_stream() {
        let mut p = parser(b"3 0 obj\n<</Length 5>>\nstream\nhello\nendstream\nendobj\n");
        let (_, _, val) = p.parse_indirect_object().unwrap();
        assert!(matches!(val, PdfObjKind::Stream { .. }));
    }

    // ── parse_object dispatch ─────────────────────────────────────────────────

    #[test]
    fn test_parse_object_null() {
        let mut p = parser(b"null");
        assert!(matches!(p.parse_object(), Some(PdfObjKind::Null)));
    }

    #[test]
    fn test_parse_object_name() {
        let mut p = parser(b"/Foo");
        assert!(matches!(p.parse_object(), Some(PdfObjKind::Name(_))));
    }

    #[test]
    fn test_parse_object_string() {
        let mut p = parser(b"(text)");
        assert!(matches!(p.parse_object(), Some(PdfObjKind::PdfString(_))));
    }
}
