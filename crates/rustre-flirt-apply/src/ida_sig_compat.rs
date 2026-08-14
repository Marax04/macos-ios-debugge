//! IDA FLIRT `.sig` and `.pat` format compatibility layer.
//!
//! Provides:
//! * [`IdaSigParser`] — reads IDA Pro binary `.sig` v5–v9 files.
//! * [`IdaPatParser`] — reads IDA `.pat` text-format files.
//! * [`IDA_TO_INTERNAL`] — converts both formats to the internal [`FlirtPattern`] representation.
//!
//! # The `.sig` header layout, and the one this module used to claim
//!
//! The header is **variable length**: the library name comes last, preceded by
//! its own length byte. The offsets are owned by
//! [`rustre_flirt::sig_header`], which [`IdaSigHeader::parse`] now delegates to.
//!
//! ```text
//! 0    6  magic "IDASGN"
//! 6    1  version (5..10)
//! 7    1  arch
//! ...
//! 34   1  library_name_len
//! 35   2  alt_ctype_crc
//! 37   4  n_functions        (v6+)
//! 41   2  pattern_size       (v8+)
//! 43   .. library name (library_name_len bytes)
//! then: node tree encoding (compressed trie)
//! ```
//!
//! This doc block used to describe a **fixed 64-byte** name field at 22..86,
//! matching the code beneath it. Measured (T36, iteration 69): given a header
//! written by the canonical codec — 61 bytes, the format this workspace both
//! writes and reads — `parse` returned `Truncated`, because it demanded 88
//! bytes. A module named `ida_sig_compat` could not read an IDA-format header.
//!
//! The layout is recorded here rather than re-derived because getting it wrong
//! has happened repeatedly: T27 corrected two sites, and iterations 43 and 45
//! found three more still on the old one.
//!
//! `.pat` text format (one function per line):
//! ```text
//! <hex_pattern> <crc_len> <crc16> <total_len> [<refs>] :<offset> <name> [<more_names>]
//! ```
//! Wildcards are represented as `..`.


// ─────────────────────────────────────────────────────────────────────────────
// IdaError
// ─────────────────────────────────────────────────────────────────────────────

use std::fmt::Write as _;
use crate::casts::usize_to_f64;

/// Errors from IDA sig/pat parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdaError {
    BadMagic,
    UnsupportedVersion(u8),
    Truncated,
    InvalidHex(String),
    InvalidPatLine(String),
    ParseError(String),
}

impl std::fmt::Display for IdaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not an IDA sig file (bad magic)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported IDA sig version {v}"),
            Self::Truncated => write!(f, "IDA sig file truncated"),
            Self::InvalidHex(s) => write!(f, "invalid hex in pat: {s}"),
            Self::InvalidPatLine(s) => write!(f, "invalid pat line: {s}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for IdaError {}

// ─────────────────────────────────────────────────────────────────────────────
// IDA sig architecture / OS codes
// ─────────────────────────────────────────────────────────────────────────────

/// IDA architecture codes (`n_arch` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdaArch {
    X86 = 0,
    Z80 = 1,
    X64 = 2,
    Arm = 3,
    Ppc = 4,
    Sparc = 5,
    Unknown = 0xFF,
}

impl IdaArch {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::X86,
            1 => Self::Z80,
            2 => Self::X64,
            3 => Self::Arm,
            4 => Self::Ppc,
            5 => Self::Sparc,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::Z80 => "z80",
            Self::X64 => "x86_64",
            Self::Arm => "arm",
            Self::Ppc => "ppc",
            Self::Sparc => "sparc",
            Self::Unknown => "unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IdaSigHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed header of an IDA `.sig` file.
#[derive(Debug, Clone)]
pub struct IdaSigHeader {
    pub version: u8,
    pub arch: IdaArch,
    pub file_types: u32,
    pub os_types: u16,
    pub app_types: u16,
    pub feature_flags: u16,
    pub n_modules: u32,
    pub crc16: u16,
    pub library_name: String,
}

impl IdaSigHeader {
    // `MAGIC` and `HEADER_FIXED_SIZE` lived here and are gone: the second encoded
    // a 64-byte fixed name field, i.e. the wrong layout, and a constant that
    // states a wrong invariant is worse than no constant — the next reader takes
    // it for documentation. Both now come from `rustre_flirt::sig_header`.

    /// Parse the header from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is truncated, has an invalid magic, or has an
    /// unsupported version byte.
    ///
    /// # Panics
    ///
    /// Panics if internal slice-to-array conversion fails (should not occur
    /// given the length check at the start of the function).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), IdaError> {
        // This used to decode a layout of its own: a **fixed 64-byte** library
        // name at 22..86, and a required header of 88 bytes. The published
        // IDASGN layout puts `library_name_len` at 34 and the name last, at 43,
        // so the header is variable-length — a real one is often shorter than 88
        // bytes outright.
        //
        // Measured (T36, iteration 69): handed a header produced by
        // `rustre_flirt::sig_header` — 61 bytes, the format this workspace both
        // writes and claims to read — this returned `Truncated`. A module called
        // `ida_sig_compat` could not read an IDA-format header.
        //
        // It now delegates to the one codec that owns those offsets. That codec
        // was itself wrong until T27, and three further sites were still on the
        // old layout as late as iterations 43 and 45; keeping a fourth private
        // copy is how that keeps happening.
        let canonical = rustre_flirt::sig_header::SigFileHeader::decode(data).map_err(|e| {
            match e {
                rustre_flirt::sig_header::HeaderError::BadMagic => IdaError::BadMagic,
                rustre_flirt::sig_header::HeaderError::UnsupportedVersion(v) => {
                    IdaError::UnsupportedVersion(v)
                }
                _ => IdaError::Truncated,
            }
        })?;

        let consumed = canonical.len_bytes();
        Ok((
            Self {
                version: canonical.version,
                arch: IdaArch::from_byte(canonical.arch),
                file_types: canonical.file_types,
                os_types: canonical.os_types,
                app_types: canonical.app_types,
                feature_flags: canonical.feature_flags,
                n_modules: canonical.n_functions,
                crc16: canonical.crc16,
                library_name: canonical.lib_name,
            },
            consumed,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InternalPattern (simplified intermediate representation)
// ─────────────────────────────────────────────────────────────────────────────

/// Intermediate pattern representation produced by both the `.sig` and `.pat` parsers.
#[derive(Debug, Clone)]
pub struct InternalPattern {
    /// Primary function name.
    pub name: String,
    /// Library name (from `.sig` header or guessed from file name).
    pub library: String,
    /// Pattern bytes: `None` = wildcard.
    pub bytes: Vec<Option<u8>>,
    /// CRC-16 value.
    pub crc: u16,
    /// CRC window offset.
    pub crc_offset: u16,
    /// CRC window length.
    pub crc_len: u8,
    /// Total function length (0 = unknown).
    pub total_len: u16,
    /// Additional public names at (offset, name).
    pub public_names: Vec<(u16, String)>,
    /// Local names at (offset, name).
    pub local_names: Vec<(u16, String)>,
    /// Referenced external names (offset, len, name).
    pub references: Vec<(u16, u16, String)>,
}

impl InternalPattern {
    /// Number of concrete bytes.
    #[must_use]
    pub fn concrete_bytes(&self) -> usize {
        self.bytes.iter().filter(|b| b.is_some()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IdaPatParser — text `.pat` format
// ─────────────────────────────────────────────────────────────────────────────

/// Parses IDA/FLAIR `.pat` text format.
///
/// Line format:
/// ```text
/// <hex_bytes> <crc_len_hex> <crc16_hex> <total_len_hex> [<refs>] :<offset_hex> <name> [:<off2> <name2> ...]
/// ```
/// Where `<hex_bytes>` uses `..` for wildcards.
pub struct IdaPatParser {
    /// Library name to tag all parsed patterns with.
    pub library_tag: String,
}

impl IdaPatParser {
    #[must_use]
    pub fn new(library_tag: impl Into<String>) -> Self {
        Self { library_tag: library_tag.into() }
    }

    /// Parse all lines from a `.pat` text file.
    ///
    /// # Errors
    ///
    /// Returns `Err` only if an unrecoverable format error occurs; bad lines
    /// are silently skipped.
    pub fn parse_all(&self, text: &str) -> Result<Vec<InternalPattern>, IdaError> {
        let mut out = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line == "---" {
                continue;
            }
            match self.parse_line(line) {
                Ok(p) => out.push(p),
                Err(e) => {
                    // Non-fatal: skip bad lines but record for debugging.
                    // In strict mode a caller could choose to propagate.
                    let _ = (lineno, e);
                }
            }
        }
        Ok(out)
    }

    /// Parse a single `.pat` line.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the line has fewer than 5 whitespace-separated fields
    /// or if any field cannot be parsed as its expected type.
    pub fn parse_line(&self, line: &str) -> Result<InternalPattern, IdaError> {
        // Split on whitespace.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(IdaError::InvalidPatLine(line.to_string()));
        }

        // Part 0: hex pattern with possible `..` wildcards.
        let bytes = parse_hex_pattern(parts[0])?;

        // Part 1: crc_len (hex).
        let crc_len = u8::from_str_radix(parts[1], 16)
            .map_err(|_| IdaError::InvalidPatLine(format!("bad crc_len: {}", parts[1])))?;

        // Part 2: crc16 (hex).
        let crc = u16::from_str_radix(parts[2], 16)
            .map_err(|_| IdaError::InvalidPatLine(format!("bad crc16: {}", parts[2])))?;

        // Part 3: total_len (hex).
        let total_len = u16::from_str_radix(parts[3], 16)
            .map_err(|_| IdaError::InvalidPatLine(format!("bad total_len: {}", parts[3])))?;

        // Remaining parts: optional reference tags, then :<offset> <name> pairs.
        let mut public_names = Vec::new();
        let mut local_names = Vec::new();
        let mut references = Vec::new();
        let mut i = 4;

        while i < parts.len() {
            let tok = parts[i];
            if let Some(rest) = tok.strip_prefix(':') {
                // Public name definition: :<offset_hex> <name>
                let offset = u16::from_str_radix(rest, 16)
                    .map_err(|_| IdaError::InvalidPatLine(format!("bad offset: {rest}")))?;
                i += 1;
                if i < parts.len() {
                    let name_tok = parts[i];
                    if let Some(local_name) = name_tok.strip_prefix('!') {
                        local_names.push((offset, local_name.to_string()));
                    } else {
                        public_names.push((offset, name_tok.to_string()));
                    }
                }
            } else if let Some(rest) = tok.strip_prefix('^') {
                // Reference: ^<offset_hex> <len_hex> <name>
                let offset = u16::from_str_radix(rest, 16).unwrap_or(0);
                i += 1;
                let ref_len = if i < parts.len() {
                    u16::from_str_radix(parts[i], 16).unwrap_or(0)
                } else { 0 };
                i += 1;
                let ref_name = if i < parts.len() { parts[i].to_string() } else { String::new() };
                references.push((offset, ref_len, ref_name));
            }
            i += 1;
        }

        // Primary name is the first public name at offset 0.
        let primary_name = public_names.iter()
            .find(|(off, _)| *off == 0).map_or_else(|| "unknown".into(), |(_, n)| n.clone());

        // CRC offset is immediately after the initial pattern.
        let crc_offset = u16::try_from(bytes.len()).unwrap_or(u16::MAX);

        Ok(InternalPattern {
            name: primary_name,
            library: self.library_tag.clone(),
            bytes,
            crc,
            crc_offset,
            crc_len,
            total_len,
            public_names,
            local_names,
            references,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IdaSigParser — binary `.sig` format
// ─────────────────────────────────────────────────────────────────────────────

/// Parses IDA Pro binary `.sig` format (versions 5–9).
///
/// The trie-encoded body is partially decoded: this implementation extracts
/// leaf nodes (function records) from the tree by walking the compressed trie.
/// Full IDA sig decompression requires reconstructing prefix strings; this
/// parser performs a best-effort extraction suitable for pattern matching.
pub struct IdaSigParser;

impl IdaSigParser {
    /// Parse a `.sig` file from raw bytes and extract all function patterns.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the header is malformed (bad magic, unsupported version,
    /// or truncated data).
    pub fn parse(data: &[u8]) -> Result<(IdaSigHeader, Vec<InternalPattern>), IdaError> {
        let (header, cursor) = IdaSigHeader::parse(data)?;
        let body = &data[cursor..];
        let patterns = Self::extract_patterns(body, &header.library_name);
        Ok((header, patterns))
    }

    /// Walk the trie body and collect leaf nodes.
    fn extract_patterns(body: &[u8], lib: &str) -> Vec<InternalPattern> {
        let mut out = Vec::new();
        let mut pos = 0usize;

        // The body is a variable-length encoded trie.  We do a best-effort scan:
        // look for sequences that match the leaf-node encoding.
        // A leaf node in IDA v9 looks like:
        //   [0x00 or flag byte] [2-byte crc16 LE] [2-byte total_len LE] [public_names...]
        // where public_names are: [2-byte offset LE] [NUL-terminated name] ...
        //
        // We use a heuristic: scan for printable ASCII name strings that are
        // preceded by plausible length/crc bytes, and preceded by pattern bytes.
        //
        // This is necessarily approximate; for exact reconstruction a full
        // IDA sig decompressor would be needed.

        while pos + 8 < body.len() {
            // Look for a pattern-bearing node.
            // Pattern bytes start with a length indicator (>= 0x10 usually).
            let pat_len = body[pos] as usize;
            if !(4..=64).contains(&pat_len) {
                pos += 1;
                continue;
            }

            if pos + pat_len + 4 >= body.len() {
                break;
            }

            // After pattern bytes: crc_len (1), crc16 (2), total_len (2).
            let after = pos + pat_len;
            if after + 5 >= body.len() {
                pos += 1;
                continue;
            }

            let crc_len = body[after];
            let crc = u16::from_le_bytes([body[after+1], body[after+2]]);
            let total_len = u16::from_le_bytes([body[after+3], body[after+4]]);

            // Scan for NUL-terminated name after that.
            let name_start = after + 5;
            if name_start >= body.len() { break; }

            // Skip 2-byte offset.
            if name_start + 2 >= body.len() { break; }
            let _name_offset = u16::from_le_bytes([body[name_start], body[name_start+1]]);
            let name_data_start = name_start + 2;

            if let Some(nul_pos) = body[name_data_start..].iter().position(|&b| b == 0) {
                let name_bytes = &body[name_data_start..name_data_start + nul_pos];
                if name_bytes.iter().all(|&b| b.is_ascii_graphic() || b == b'_') && nul_pos >= 2 {
                    let name = String::from_utf8_lossy(name_bytes).into_owned();
                    let pat_bytes: Vec<Option<u8>> = body[pos+1..pos+1+pat_len.min(32)]
                        .iter().map(|&b| Some(b)).collect();

                    out.push(InternalPattern {
                        name,
                        library: lib.to_string(),
                        bytes: pat_bytes,
                        crc,
                        crc_offset: u16::try_from(pat_len).unwrap_or(u16::MAX),
                        crc_len,
                        total_len,
                        public_names: Vec::new(),
                        local_names: Vec::new(),
                        references: Vec::new(),
                    });

                    pos = name_data_start + nul_pos + 1;
                    continue;
                }
            }

            pos += 1;
        }

        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversion helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a hex+wildcard pattern string into `Vec<Option<u8>>`.
///
/// Input like `"5548..E5"` → `[Some(0x55), Some(0x48), None, Some(0xE5)]`.
///
/// # Errors
///
/// Returns `Err` if the input has an odd number of hex digits or contains
/// characters that are not valid hex digits or `..` wildcards.
pub fn parse_hex_pattern(hex: &str) -> Result<Vec<Option<u8>>, IdaError> {
    // Normalise: remove spaces.
    let hex = hex.replace(' ', "");
    if !hex.len().is_multiple_of(2) {
        return Err(IdaError::InvalidHex(hex));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let pair = format!("{hi}{lo}");
        if pair == ".." {
            out.push(None);
        } else {
            let byte = u8::from_str_radix(&pair, 16)
                .map_err(|_| IdaError::InvalidHex(pair.clone()))?;
            out.push(Some(byte));
        }
    }
    Ok(out)
}

/// Render a `Vec<Option<u8>>` back to IDA `.pat` hex notation.
#[must_use]
pub fn render_pat_hex(pattern: &[Option<u8>]) -> String {
    pattern.iter().map(|b| b.as_ref().map_or_else(|| "..".to_string(), |v| format!("{v:02X}"))).collect::<String>()
}

/// CRC-16/ARC compatible with IDA FLIRT.
#[must_use]
pub fn crc16_ida(data: &[u8]) -> u16 {
    rustre_flirt::crc::arc(data)
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternConverter
// ─────────────────────────────────────────────────────────────────────────────

/// Converts [`InternalPattern`]s between IDA format and internal format.
pub struct PatternConverter;

impl PatternConverter {
    /// Render an `InternalPattern` as a `.pat` text line.
    #[must_use]
    pub fn to_pat_line(p: &InternalPattern) -> String {
        let hex = render_pat_hex(&p.bytes);
        let mut line = format!(
            "{} {:02X} {:04X} {:04X}",
            hex, p.crc_len, p.crc, p.total_len
        );
        // Add reference entries.
        for (off, len, name) in &p.references {
            let _ = write!(line, " ^{off:04X} {len:04X} {name}");
        }
        // Primary name at offset 0.
        let _ = write!(line, " :0000 {}", p.name);
        // Additional names.
        for (off, name) in &p.public_names {
            if *off == 0 && *name == p.name { continue; }
            let _ = write!(line, " :{off:04X} {name}");
        }
        for (off, name) in &p.local_names {
            let _ = write!(line, " :{off:04X} !{name}");
        }
        line
    }

    /// Render a collection of patterns to a `.pat` file string.
    #[must_use]
    pub fn to_pat_file(patterns: &[InternalPattern]) -> String {
        let mut lines: Vec<String> = patterns.iter().map(Self::to_pat_line).collect();
        lines.push("---".to_string());
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SigConversionStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics from a conversion run.
#[derive(Debug, Clone, Default)]
pub struct SigConversionStats {
    pub total_lines: usize,
    pub parsed_ok: usize,
    pub parse_errors: usize,
    pub wildcards_total: usize,
    pub avg_concrete_bytes: f64,
}

impl SigConversionStats {
    /// Compute from a list of patterns.
    #[must_use]
    pub fn from_patterns(patterns: &[InternalPattern]) -> Self {
        if patterns.is_empty() {
            return Self::default();
        }
        let concrete_total: usize = patterns.iter().map(InternalPattern::concrete_bytes).sum();
        let wildcards: usize = patterns.iter().map(|p| p.bytes.iter().filter(|b| b.is_none()).count()).sum();
        Self {
            total_lines: patterns.len(),
            parsed_ok: patterns.len(),
            parse_errors: 0,
            wildcards_total: wildcards,
            avg_concrete_bytes: usize_to_f64(concrete_total) / usize_to_f64(patterns.len()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pattern_concrete() {
        let p = parse_hex_pattern("5548E5").unwrap();
        assert_eq!(p, vec![Some(0x55), Some(0x48), Some(0xE5)]);
    }

    #[test]
    fn test_parse_hex_pattern_wildcards() {
        let p = parse_hex_pattern("55..E5").unwrap();
        assert_eq!(p, vec![Some(0x55), None, Some(0xE5)]);
    }

    #[test]
    fn test_pat_line_roundtrip() {
        let line = "5548..E5 08 BEEF 0040 :0000 my_func";
        let parser = IdaPatParser::new("testlib");
        let pat = parser.parse_line(line).unwrap();
        assert_eq!(pat.name, "my_func");
        assert_eq!(pat.crc_len, 8);
        assert_eq!(pat.crc, 0xBEEF);
        assert_eq!(pat.total_len, 0x40);
        assert!(pat.bytes[2].is_none()); // wildcard at index 2

        let rendered = PatternConverter::to_pat_line(&pat);
        assert!(rendered.contains("my_func"));
        assert!(rendered.contains("BEEF"));
    }

    #[test]
    fn test_pat_file_multi_line() {
        let text = r"
5548E5E5 08 1234 0020 :0000 func_a
55538B.. 04 5678 0030 :0000 func_b
---
";
        let parser = IdaPatParser::new("mylib");
        let pats = parser.parse_all(text).unwrap();
        assert_eq!(pats.len(), 2);
        assert_eq!(pats[0].name, "func_a");
        assert_eq!(pats[1].name, "func_b");
    }

    #[test]
    fn test_sig_header_bad_magic() {
        let data = b"NOTIDA\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(IdaSigHeader::parse(data).unwrap_err(), IdaError::BadMagic);
    }

    #[test]
    fn test_crc16_ida_known() {
        // "123456789" → 0xBB3D for CRC-16/ARC.
        assert_eq!(crc16_ida(b"123456789"), 0xBB3D);
    }

    #[test]
    fn test_render_pat_hex() {
        let pat = vec![Some(0x55u8), None, Some(0xE5)];
        assert_eq!(render_pat_hex(&pat), "55..E5");
    }

    #[test]
    fn test_conversion_stats() {
        let pats = vec![
            InternalPattern {
                name: "f".into(), library: "l".into(),
                bytes: vec![Some(0x55), None, Some(0xE5)],
                crc: 0, crc_offset: 3, crc_len: 0, total_len: 0,
                public_names: vec![], local_names: vec![], references: vec![],
            }
        ];
        let stats = SigConversionStats::from_patterns(&pats);
        assert_eq!(stats.wildcards_total, 1);
        assert!((stats.avg_concrete_bytes - 2.0).abs() < 0.001);
    }
}
