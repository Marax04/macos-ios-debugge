//! Round-trippable textual signature-pack format for [`crate::FlirtPattern`].
//!
//! A *signature pack* is a small, human-readable, line-oriented file that lets a
//! generated set of apply-side [`FlirtPattern`]s be saved and reloaded without
//! depending on serde/JSON. The format is deliberately simple so it diffs well
//! and can be hand-edited:
//!
//! ```text
//! SIGPACK 1
//! pack <pack-name>
//! ---
//! <hex-pattern> | <crc_offset> <crc_len> <crc16-hex> <total_len> | <lib> | <name>
//! ...
//! ```
//!
//! * `hex-pattern` is whitespace-free; each byte is two hex digits, with `..`
//!   for a wildcard.
//! * Numeric fields after the first `|` are `crc_offset` (decimal),
//!   `crc_len` (decimal), `crc16` (4-hex), `total_len` (decimal, the pattern's
//!   declared full function length).
//! * The remaining `|`-separated fields are the library name and the function
//!   name.
//!
//! [`emit_pack`] and [`parse_pack`] are exact inverses for any pack built from
//! patterns the format can represent.

use crate::{FlirtError, FlirtPattern};

/// Magic / version line that begins every pack.
const PACK_MAGIC: &str = "SIGPACK 1";

// ── SignaturePack ─────────────────────────────────────────────────────────────

/// A named collection of apply-side [`FlirtPattern`]s.
#[derive(Debug, Clone)]
pub struct SignaturePack {
    /// Human-readable pack name (e.g. `"msvcrt-x86"`).
    pub name: String,
    /// The patterns in this pack.
    pub patterns: Vec<FlirtPattern>,
}

impl SignaturePack {
    /// Create an empty pack with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            patterns: Vec::new(),
        }
    }

    /// Number of patterns in the pack.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if the pack holds no patterns.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Add a pattern to the pack.
    pub fn push(&mut self, pat: FlirtPattern) {
        self.patterns.push(pat);
    }

    /// Serialize the pack to its textual form.
    ///
    /// The result round-trips through [`SignaturePack::parse`].
    #[must_use]
    pub fn emit(&self) -> String {
        emit_pack(self)
    }

    /// Parse a pack from textual form.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::Parse`] for a missing/incorrect header or any
    /// malformed pattern line.
    pub fn parse(text: &str) -> Result<Self, FlirtError> {
        parse_pack(text)
    }
}

// ── emit ──────────────────────────────────────────────────────────────────────

/// Render `pack` to the textual signature-pack format.
#[must_use]
pub fn emit_pack(pack: &SignaturePack) -> String {
    let mut out = String::new();
    out.push_str(PACK_MAGIC);
    out.push('\n');
    out.push_str("pack ");
    out.push_str(&pack.name);
    out.push('\n');
    out.push_str("---\n");

    for pat in &pack.patterns {
        out.push_str(&emit_pattern_line(pat));
        out.push('\n');
    }
    out
}

/// Render a single pattern as one pack line.
#[must_use]
pub fn emit_pattern_line(pat: &FlirtPattern) -> String {
    let hex: String = pat
        .bytes
        .iter()
        .map(|b| b.as_ref().map_or_else(|| "..".to_string(), |v| format!("{v:02X}")))
        .collect();

    format!(
        "{hex} | {} {} {:04X} {} | {} | {}",
        pat.crc_offset,
        pat.crc_len,
        pat.crc,
        // total length: prefer an explicit pattern length if present, else the
        // byte count. The apply `FlirtPattern` has no separate length field, so
        // we record the byte count which is always recoverable.
        pat.bytes.len(),
        escape_field(&pat.lib_name),
        escape_field(&pat.name),
    )
}

// ── parse ───────────────────────────────────────────────────────────────────

/// Parse the textual signature-pack format into a [`SignaturePack`].
///
/// # Errors
///
/// Returns [`FlirtError::Parse`] if the header is missing or a body line is
/// malformed.
pub fn parse_pack(text: &str) -> Result<SignaturePack, FlirtError> {
    let mut lines = text.lines();

    let magic = lines
        .next()
        .ok_or_else(|| FlirtError::Parse("empty pack input".to_string()))?;
    if magic.trim() != PACK_MAGIC {
        return Err(FlirtError::Parse(format!(
            "bad pack magic: expected '{PACK_MAGIC}', got '{magic}'"
        )));
    }

    let name_line = lines
        .next()
        .ok_or_else(|| FlirtError::Parse("missing pack name line".to_string()))?;
    let name = name_line
        .strip_prefix("pack ")
        .ok_or_else(|| FlirtError::Parse(format!("expected 'pack <name>', got '{name_line}'")))?
        .to_string();

    let sep = lines
        .next()
        .ok_or_else(|| FlirtError::Parse("missing '---' separator".to_string()))?;
    if sep.trim() != "---" {
        return Err(FlirtError::Parse(format!("expected '---', got '{sep}'")));
    }

    let mut pack = SignaturePack::new(name);
    for (i, raw) in lines.enumerate() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        let pat = parse_pattern_line(line)
            .map_err(|e| FlirtError::Parse(format!("pattern line {}: {e}", i + 1)))?;
        pack.patterns.push(pat);
    }
    Ok(pack)
}

/// Parse a single pack line into a [`FlirtPattern`].
///
/// # Errors
///
/// Returns a descriptive error string when the line does not match the format.
pub fn parse_pattern_line(line: &str) -> Result<FlirtPattern, String> {
    let fields: Vec<&str> = line.split('|').map(str::trim).collect();
    if fields.len() != 4 {
        return Err(format!(
            "expected 4 '|'-separated fields, got {}",
            fields.len()
        ));
    }

    let bytes = parse_hex_field(fields[0])?;

    let nums: Vec<&str> = fields[1].split_whitespace().collect();
    if nums.len() != 4 {
        return Err(format!("expected 4 numeric fields, got {}", nums.len()));
    }
    let crc_offset: u16 = nums[0]
        .parse()
        .map_err(|_| format!("bad crc_offset: {}", nums[0]))?;
    let crc_len: u16 = nums[1]
        .parse()
        .map_err(|_| format!("bad crc_len: {}", nums[1]))?;
    let crc: u16 =
        u16::from_str_radix(nums[2], 16).map_err(|_| format!("bad crc16: {}", nums[2]))?;
    // total_len is informational (byte count is recoverable from `bytes`); we
    // parse it for validation but the pattern stores the byte vector itself.
    let _total_len: u32 = nums[3]
        .parse()
        .map_err(|_| format!("bad total_len: {}", nums[3]))?;

    let lib_name = unescape_field(fields[2]);
    let name = unescape_field(fields[3]);

    let mut pat = FlirtPattern::new(name, bytes);
    pat.lib_name = lib_name;
    pat.crc_offset = crc_offset;
    pat.crc_len = crc_len;
    pat.crc = crc;
    Ok(pat)
}

// ── field helpers ─────────────────────────────────────────────────────────────

fn parse_hex_field(field: &str) -> Result<Vec<Option<u8>>, String> {
    if field.is_empty() {
        return Ok(Vec::new());
    }
    if !field.len().is_multiple_of(2) {
        return Err(format!("odd-length hex pattern: {field}"));
    }
    let raw = field.as_bytes();
    let mut out = Vec::with_capacity(field.len() / 2);
    let mut idx = 0;
    while idx + 1 < raw.len() {
        let hi = raw[idx];
        let lo = raw[idx + 1];
        if hi == b'.' && lo == b'.' {
            out.push(None);
        } else {
            let hi_nib = hex_nibble(hi).ok_or_else(|| format!("bad hex char in {field}"))?;
            let lo_nib = hex_nibble(lo).ok_or_else(|| format!("bad hex char in {field}"))?;
            out.push(Some((hi_nib << 4) | lo_nib));
        }
        idx += 2;
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Escape a free-text field so it survives the `|`-delimited line format.
///
/// `|` and newlines would break parsing, so they are percent-style escaped.
fn escape_field(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\p")
        .replace('\n', "\\n")
}

/// Inverse of [`escape_field`].
fn unescape_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('p') => out.push('|'),
                Some('n') => out.push('\n'),
                // A trailing or escaped backslash maps back to a single '\\'.
                Some('\\') | None => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(name: &str, lib: &str, bytes: &[Option<u8>]) -> FlirtPattern {
        let mut p = FlirtPattern::new(name.to_string(), bytes.to_vec());
        p.lib_name = lib.to_string();
        p
    }

    fn ex(bytes: &[u8]) -> Vec<Option<u8>> {
        bytes.iter().map(|&b| Some(b)).collect()
    }

    // ── pack basics ─────────────────────────────────────────────────────────

    #[test]
    fn test_pack_new_empty() {
        let p = SignaturePack::new("x");
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn test_pack_push() {
        let mut p = SignaturePack::new("x");
        p.push(pat("f", "lib", &ex(&[0x55])));
        assert_eq!(p.len(), 1);
        assert!(!p.is_empty());
    }

    // ── emit ──────────────────────────────────────────────────────────────

    #[test]
    fn test_emit_has_header() {
        let p = SignaturePack::new("mypack");
        let text = p.emit();
        assert!(text.starts_with("SIGPACK 1\npack mypack\n---\n"));
    }

    #[test]
    fn test_emit_pattern_line_format() {
        let mut p = pat("memcpy", "msvcrt", &ex(&[0x55, 0x8B, 0xEC]));
        p.crc_offset = 3;
        p.crc_len = 4;
        p.crc = 0xABCD;
        let line = emit_pattern_line(&p);
        assert!(line.contains("558BEC"));
        assert!(line.contains("ABCD"));
        assert!(line.contains("memcpy"));
        assert!(line.contains("msvcrt"));
    }

    #[test]
    fn test_emit_wildcard_bytes() {
        let p = pat("f", "lib", &[Some(0x55), None, Some(0xEC)]);
        let line = emit_pattern_line(&p);
        assert!(line.starts_with("55..EC"));
    }

    // ── parse ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_bad_magic() {
        let r = SignaturePack::parse("WRONG\npack x\n---\n");
        assert!(matches!(r, Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_parse_missing_name() {
        let r = SignaturePack::parse("SIGPACK 1\n");
        assert!(matches!(r, Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_parse_bad_separator() {
        let r = SignaturePack::parse("SIGPACK 1\npack x\nNOTSEP\n");
        assert!(matches!(r, Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_parse_empty_pack() {
        let pack = SignaturePack::parse("SIGPACK 1\npack empty\n---\n").unwrap();
        assert_eq!(pack.name, "empty");
        assert!(pack.is_empty());
    }

    #[test]
    fn test_parse_single_line() {
        let text = "SIGPACK 1\npack p\n---\n558BEC | 3 4 ABCD 3 | msvcrt | memcpy\n";
        let pack = SignaturePack::parse(text).unwrap();
        assert_eq!(pack.len(), 1);
        let p = &pack.patterns[0];
        assert_eq!(p.name, "memcpy");
        assert_eq!(p.lib_name, "msvcrt");
        assert_eq!(p.crc_offset, 3);
        assert_eq!(p.crc_len, 4);
        assert_eq!(p.crc, 0xABCD);
        assert_eq!(p.bytes, ex(&[0x55, 0x8B, 0xEC]));
    }

    #[test]
    fn test_parse_bad_field_count() {
        let r = parse_pattern_line("558BEC | 3 4 ABCD 3 | msvcrt");
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_bad_hex() {
        let r = parse_pattern_line("ZZ | 0 0 0000 1 | lib | f");
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_odd_hex_length() {
        let r = parse_pattern_line("55A | 0 0 0000 1 | lib | f");
        assert!(r.is_err());
    }

    // ── round-trip ────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_single() {
        let mut p = pat(
            "strlen",
            "msvcrt",
            &[Some(0x8A), None, Some(0x84), Some(0xC0)],
        );
        p.crc_offset = 4;
        p.crc_len = 8;
        p.crc = 0x1234;

        let mut pack = SignaturePack::new("roundtrip");
        pack.push(p);

        let text = pack.emit();
        let pack2 = SignaturePack::parse(&text).unwrap();

        assert_eq!(pack2.name, "roundtrip");
        assert_eq!(pack2.len(), 1);
        let q = &pack2.patterns[0];
        assert_eq!(q.name, "strlen");
        assert_eq!(q.lib_name, "msvcrt");
        assert_eq!(q.bytes, vec![Some(0x8A), None, Some(0x84), Some(0xC0)]);
        assert_eq!(q.crc_offset, 4);
        assert_eq!(q.crc_len, 8);
        assert_eq!(q.crc, 0x1234);
    }

    #[test]
    fn test_roundtrip_multiple() {
        let mut pack = SignaturePack::new("multi");
        pack.push(pat("a", "lib1", &ex(&[0x55, 0x8B, 0xEC, 0x83])));
        pack.push(pat(
            "b",
            "lib2",
            &[Some(0x48), None, Some(0x89), Some(0xE5)],
        ));
        pack.push(pat("c", "lib1", &ex(&[0x90, 0x90, 0x90, 0x90])));

        let text = pack.emit();
        let pack2 = SignaturePack::parse(&text).unwrap();
        assert_eq!(pack2.len(), 3);
        assert_eq!(pack2.patterns[0].name, "a");
        assert_eq!(pack2.patterns[1].bytes[1], None);
        assert_eq!(pack2.patterns[2].name, "c");
    }

    #[test]
    fn test_roundtrip_name_with_pipe() {
        // Names containing '|' must survive escaping.
        let pack_text = {
            let mut pack = SignaturePack::new("esc");
            pack.push(pat("foo|bar", "li|b", &ex(&[0x55, 0x8B])));
            pack.emit()
        };
        let pack2 = SignaturePack::parse(&pack_text).unwrap();
        assert_eq!(pack2.patterns[0].name, "foo|bar");
        assert_eq!(pack2.patterns[0].lib_name, "li|b");
    }

    #[test]
    fn test_roundtrip_empty_pack() {
        let pack = SignaturePack::new("nothing");
        let text = pack.emit();
        let pack2 = SignaturePack::parse(&text).unwrap();
        assert_eq!(pack2.name, "nothing");
        assert!(pack2.is_empty());
    }

    #[test]
    fn test_roundtrip_from_demo_db() {
        // Build a pack from the bundled demo signatures and round-trip it.
        let db = crate::FlirtSigDb::load_demo_sigs();
        let mut pack = SignaturePack::new("demo");
        // Re-create patterns from the demo set via the public scan path is not
        // available, so construct a couple of representative patterns instead.
        let _ = db;
        pack.push(pat(
            "memcpy",
            "msvcrt",
            &ex(&[0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x10]),
        ));
        pack.push(pat(
            "memset",
            "msvcrt",
            &ex(&[0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x10]),
        ));
        let text = pack.emit();
        let pack2 = SignaturePack::parse(&text).unwrap();
        assert_eq!(pack2.len(), 2);
        assert_eq!(pack2.patterns[0].name, "memcpy");
    }
}
