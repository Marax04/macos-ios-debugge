//! IDA FLIRT `.pat` file writer.
//!
//! Serialises [`FlirtPattern`] slices to the plain-text `.pat` format
//! understood by IDA Pro's `sigmake` tool.
//!
//! # Format reference
//!
//! Each non-comment line in a `.pat` file describes one function signature:
//!
//! ```text
//! <hex_pattern> <crc_len> <crc16> <total_len> <primary_name> [<ref_offset>:<ref_name> ...]
//! ```
//!
//! Where:
//! - `<hex_pattern>` — hex digits and `..` wildcard pairs, at most 64 pairs.
//! - `<crc_len>` — number of bytes after the pattern covered by the CRC (hex, 2 chars).
//! - `<crc16>` — CRC-16 value (hex, 4 chars).
//! - `<total_len>` — total function length in bytes (hex, 4 chars).
//! - `<primary_name>` — the function's primary name.
//! - Optional additional names / referenced names with `:offset:name` syntax.
//!
//! The file ends with a `---` line.

use std::fmt;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;

use rustre_flirt::{FlirtPattern, PatternByte};

// ── PatLine ───────────────────────────────────────────────────────────────────

/// A single line in a `.pat` file, in parsed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatLine {
    /// The hex-encoded initial bytes with `..` for wildcards.
    pub hex_pattern: String,
    /// Number of CRC bytes (after the initial pattern).
    pub crc_length: u8,
    /// CRC-16 value.
    pub crc16: u16,
    /// Total function length in bytes.
    pub total_length: u16,
    /// Primary function name.
    pub primary_name: String,
    /// Additional named offsets (`offset:name`).
    pub extra_names: Vec<(u16, String)>,
    /// Referenced names (`^offset:name`).
    pub referenced_names: Vec<(u16, String)>,
}

impl PatLine {
    /// Create a `PatLine` with only a primary name and no extras.
    #[must_use]
    pub fn new(
        hex_pattern: impl Into<String>,
        crc_length: u8,
        crc16: u16,
        total_length: u16,
        primary_name: impl Into<String>,
    ) -> Self {
        Self {
            hex_pattern: hex_pattern.into(),
            crc_length,
            crc16,
            total_length,
            primary_name: primary_name.into(),
            extra_names: Vec::new(),
            referenced_names: Vec::new(),
        }
    }

    /// Serialise this line to the `.pat` text representation.
    ///
    /// ```text
    /// 5548 0F 1234 0010 my_func :0000:extra_func ^0004:ref_func
    /// ```
    #[must_use]
    pub fn to_pat_string(&self) -> String {
        let mut s = format!(
            "{} {:02X} {:04X} {:04X} {}",
            self.hex_pattern.to_uppercase(),
            self.crc_length,
            self.crc16,
            self.total_length,
            self.primary_name,
        );
        for (off, name) in &self.extra_names {
            let _ = write!(s, " :{off:04X}:{name}");
        }
        for (off, name) in &self.referenced_names {
            let _ = write!(s, " ^{off:04X}:{name}");
        }
        s
    }

    /// Parse a `.pat` line from text.
    ///
    /// Returns `None` if the line is too short or malformed.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line == "---" {
            return None;
        }
        let mut parts = line.splitn(6, ' ');
        let hex_pattern = parts.next()?.to_owned();
        let crc_len_str = parts.next()?;
        let crc16_str = parts.next()?;
        let total_len_str = parts.next()?;
        let primary_name = parts.next().unwrap_or("").trim().to_owned();
        let rest = parts.next().unwrap_or("").trim();

        let crc_length = u8::from_str_radix(crc_len_str, 16).ok()?;
        let crc16 = u16::from_str_radix(crc16_str, 16).ok()?;
        let total_length = u16::from_str_radix(total_len_str, 16).ok()?;

        // Parse optional extra / referenced names.
        let tokens = rest.split_whitespace();
        let mut extra_names = Vec::new();
        let mut referenced_names = Vec::new();

        for tok in tokens {
            if let Some(stripped) = tok.strip_prefix('^') {
                // Referenced name: ^OFFSET:name
                if let Some((off_s, name_s)) = stripped.split_once(':')
                    && let Ok(off) = u16::from_str_radix(off_s, 16) {
                        referenced_names.push((off, name_s.to_owned()));
                    }
            } else if let Some(stripped) = tok.strip_prefix(':') {
                // Extra name: :OFFSET:name
                if let Some((off_s, name_s)) = stripped.split_once(':')
                    && let Ok(off) = u16::from_str_radix(off_s, 16) {
                        extra_names.push((off, name_s.to_owned()));
                    }
            }
        }

        Some(Self {
            hex_pattern,
            crc_length,
            crc16,
            total_length,
            primary_name,
            extra_names,
            referenced_names,
        })
    }
}

impl fmt::Display for PatLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_pat_string())
    }
}

// ── PatRecord ─────────────────────────────────────────────────────────────────

/// Rich metadata for one pattern, combining a [`PatLine`] with library context.
#[derive(Debug, Clone)]
pub struct PatRecord {
    /// The serialisable `.pat` line.
    pub line: PatLine,
    /// Source library name (for provenance tracking).
    pub library: String,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl PatRecord {
    /// Create a `PatRecord` from a `PatLine` with library provenance.
    #[must_use]
    pub fn new(line: PatLine, library: impl Into<String>, confidence: f32) -> Self {
        Self {
            line,
            library: library.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Convenience: create from a [`FlirtPattern`].
    #[must_use]
    pub fn from_pattern(pattern: &FlirtPattern, library: impl Into<String>) -> Self {
        let line = PatLine::from_flirt_pattern(pattern);
        Self::new(line, library, 1.0)
    }
}

impl fmt::Display for PatRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  ; lib={} conf={:.2}", self.line, self.library, self.confidence)
    }
}

// ── PatLine helpers ───────────────────────────────────────────────────────────

impl PatLine {
    /// Build a `PatLine` from a [`FlirtPattern`].
    #[must_use]
    pub fn from_flirt_pattern(pat: &FlirtPattern) -> Self {
        // Build hex string: exact bytes as two hex digits, wildcards as "..".
        let hex_pattern: String = pat
            .initial_bytes
            .iter()
            .map(|pb| match pb {
                PatternByte::Exact(b) => format!("{b:02X}"),
                PatternByte::Wildcard => "..".to_owned(),
            })
            .collect();

        let primary_name = pat.primary_name().unwrap_or("").to_owned();

        // Extra names: all non-primary names (offset > 0).
        let extra_names: Vec<(u16, String)> = pat
            .names
            .iter()
            .filter(|n| n.offset > 0)
            .map(|n| (n.offset, n.name.clone()))
            .collect();

        // Referenced names from the pattern.
        let referenced_names: Vec<(u16, String)> = pat
            .referenced_names
            .iter()
            .map(|r| (r.offset, r.name.clone()))
            .collect();

        Self {
            hex_pattern,
            crc_length: pat.crc_length,
            crc16: pat.crc16,
            total_length: pat.pattern_length,
            primary_name,
            extra_names,
            referenced_names,
        }
    }
}

// ── PatFileWriter ─────────────────────────────────────────────────────────────

/// Serialises FLIRT signatures to IDA's `.pat` plain-text format.
///
/// # Usage
///
/// ```no_run
/// use rustre_flirt_gen::pat_file_writer::{PatFileWriter, write_pat_file};
/// use std::path::Path;
///
/// // write_pat_file(&patterns, "mylib", Path::new("output.pat")).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct PatFileWriter {
    /// Library name written in the file header comment.
    pub library_name: String,
    /// If `true`, write a comment header with generation info.
    pub write_header: bool,
    /// If `true`, only write patterns with `confidence >= min_confidence`.
    pub filter_by_confidence: bool,
    /// Minimum confidence threshold (used when `filter_by_confidence` is `true`).
    pub min_confidence: f32,
    /// Maximum pattern hex length (IDA expects at most 64 byte-pairs = 128 chars).
    pub max_hex_length: usize,
}

impl Default for PatFileWriter {
    fn default() -> Self {
        Self {
            library_name: "unnamed".to_owned(),
            write_header: true,
            filter_by_confidence: false,
            min_confidence: 0.5,
            max_hex_length: 128,
        }
    }
}

impl PatFileWriter {
    /// Create a new writer for the given library.
    #[must_use]
    pub fn new(library_name: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            ..Self::default()
        }
    }

    /// Build the complete `.pat` file contents as a `String`.
    #[must_use]
    pub fn build_string(&self, patterns: &[FlirtPattern]) -> String {
        let mut out = String::new();

        if self.write_header {
            out.push_str("; IDA FLIRT .pat signature file\n");
            let _ = writeln!(out, "; Library: {}", self.library_name);
            let _ = writeln!(out, "; Patterns: {}", patterns.len());
            out.push(';');
            out.push('\n');
        }

        for pat in patterns {
            let line = PatLine::from_flirt_pattern(pat);
            // Truncate hex if too long.
            let hex = if line.hex_pattern.len() > self.max_hex_length {
                line.hex_pattern[..self.max_hex_length].to_owned()
            } else {
                line.hex_pattern.clone()
            };
            let adjusted = PatLine {
                hex_pattern: hex,
                ..line
            };
            out.push_str(&adjusted.to_pat_string());
            out.push('\n');
        }

        out.push_str("---\n");
        out
    }

    /// Build `.pat` contents from [`PatRecord`] slices, honouring confidence
    /// filtering.
    #[must_use]
    pub fn build_from_records(&self, records: &[PatRecord]) -> String {
        let mut out = String::new();

        if self.write_header {
            out.push_str("; IDA FLIRT .pat signature file\n");
            let _ = writeln!(out, "; Library: {}", self.library_name);
            out.push(';');
            out.push('\n');
        }

        for rec in records {
            if self.filter_by_confidence && rec.confidence < self.min_confidence {
                continue;
            }
            let hex = if rec.line.hex_pattern.len() > self.max_hex_length {
                rec.line.hex_pattern[..self.max_hex_length].to_owned()
            } else {
                rec.line.hex_pattern.clone()
            };
            let adjusted = PatLine {
                hex_pattern: hex,
                ..rec.line.clone()
            };
            // Write a provenance comment.
            let _ = writeln!(out, "; lib={} conf={:.2}", rec.library, rec.confidence);
            out.push_str(&adjusted.to_pat_string());
            out.push('\n');
        }

        out.push_str("---\n");
        out
    }

    /// Write `.pat` file to the given writer.
    ///
    /// # Errors
    ///
    /// Returns any I/O error propagated from `writer`.
    pub fn write_to<W: Write>(&self, writer: &mut W, patterns: &[FlirtPattern]) -> io::Result<()> {
        let content = self.build_string(patterns);
        writer.write_all(content.as_bytes())
    }

    /// Write `.pat` contents to a file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be created or written.
    pub fn write_to_file(&self, path: &Path, patterns: &[FlirtPattern]) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        self.write_to(&mut file, patterns)
    }

    /// Write `PatRecord` slices to a file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be created or written.
    pub fn write_records_to_file(&self, path: &Path, records: &[PatRecord]) -> io::Result<()> {
        let content = self.build_from_records(records);
        let mut file = std::fs::File::create(path)?;
        file.write_all(content.as_bytes())
    }
}

// ── write_pat_file ────────────────────────────────────────────────────────────

/// Write a set of FLIRT signatures to a `.pat` text file.
///
/// This is the most direct entry point: provide the pattern slice, the library
/// name embedded in the comment header, and the output path.
///
/// # Errors
///
/// Returns `io::Error` on I/O failure.
pub fn write_pat_file(
    patterns: &[FlirtPattern],
    library_name: &str,
    path: &Path,
) -> io::Result<()> {
    let writer = PatFileWriter::new(library_name);
    writer.write_to_file(path, patterns)
}

// ── PatFileReader ─────────────────────────────────────────────────────────────

/// Parse an existing `.pat` file and return the decoded lines.
#[derive(Debug, Clone, Default)]
pub struct PatFileReader;

impl PatFileReader {
    /// Create a new reader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `content` (the full text of a `.pat` file) into a `Vec<PatLine>`.
    ///
    /// Comment lines (starting with `;`) and the terminator (`---`) are
    /// silently ignored.
    #[must_use]
    pub fn parse_str(&self, content: &str) -> Vec<PatLine> {
        content
            .lines()
            .filter_map(PatLine::parse)
            .collect()
    }

    /// Read and parse a `.pat` file from disk.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the file cannot be read.
    pub fn read_file(&self, path: &Path) -> io::Result<Vec<PatLine>> {
        let content = std::fs::read_to_string(path)?;
        Ok(self.parse_str(&content))
    }
}

// ── PatStats ──────────────────────────────────────────────────────────────────

/// Statistics about a `.pat` file or pattern set.
#[derive(Debug, Clone, Default)]
pub struct PatStats {
    /// Total number of patterns.
    pub pattern_count: usize,
    /// Number of patterns with wildcards in the initial bytes.
    pub patterns_with_wildcards: usize,
    /// Number of patterns with referenced names.
    pub patterns_with_refs: usize,
    /// Average hex pattern length (in byte pairs).
    pub avg_hex_length: f64,
    /// Minimum total function length.
    pub min_func_len: u16,
    /// Maximum total function length.
    pub max_func_len: u16,
}

impl PatStats {
    /// Compute stats from a slice of [`PatLine`]s.
    #[must_use]
    pub fn from_lines(lines: &[PatLine]) -> Self {
        if lines.is_empty() {
            return Self::default();
        }
        let pattern_count = lines.len();
        let patterns_with_wildcards = lines.iter().filter(|l| l.hex_pattern.contains("..")).count();
        let patterns_with_refs = lines.iter().filter(|l| !l.referenced_names.is_empty()).count();
        let total_hex_len: usize = lines.iter().map(|l| l.hex_pattern.len() / 2).sum();
        let avg_hex_length = f64::from(u32::try_from(total_hex_len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(pattern_count).unwrap_or(u32::MAX));
        let min_func_len = lines.iter().map(|l| l.total_length).min().unwrap_or(0);
        let max_func_len = lines.iter().map(|l| l.total_length).max().unwrap_or(0);
        Self {
            pattern_count,
            patterns_with_wildcards,
            patterns_with_refs,
            avg_hex_length,
            min_func_len,
            max_func_len,
        }
    }

    /// Compute stats from a slice of [`FlirtPattern`]s.
    #[must_use]
    pub fn from_patterns(patterns: &[FlirtPattern]) -> Self {
        let lines: Vec<PatLine> = patterns.iter().map(PatLine::from_flirt_pattern).collect();
        Self::from_lines(&lines)
    }
}

impl fmt::Display for PatStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatStats {{ count={}, wildcards={}, refs={}, avg_len={:.1}, func_len=[{}, {}] }}",
            self.pattern_count,
            self.patterns_with_wildcards,
            self.patterns_with_refs,
            self.avg_hex_length,
            self.min_func_len,
            self.max_func_len,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PatternGenerator;
    use rustre_flirt::FlirtName;

    fn make_pattern(bytes: &[u8], name: &str) -> FlirtPattern {
        let pg = PatternGenerator::new();
        let fname = FlirtName {
            name: name.to_owned(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        pg.generate(bytes, &[], vec![fname]).unwrap()
    }

    #[test]
    fn pat_line_to_pat_string_basic() {
        let line = PatLine::new("5548", 4, 0x1234, 10, "my_func");
        let s = line.to_pat_string();
        assert!(s.contains("5548"));
        assert!(s.contains("1234"));
        assert!(s.contains("my_func"));
    }

    #[test]
    fn pat_line_parse_roundtrip() {
        let line = PatLine::new("5548", 4, 0x1234, 10, "my_func");
        let s = line.to_pat_string();
        let parsed = PatLine::parse(&s).expect("parse failed");
        assert_eq!(parsed.hex_pattern, line.hex_pattern);
        assert_eq!(parsed.crc16, line.crc16);
        assert_eq!(parsed.primary_name, line.primary_name);
    }

    #[test]
    fn pat_line_parse_extra_names() {
        let line = "5548 04 1234 000A foo :0004:bar ^0008:baz";
        let parsed = PatLine::parse(line).unwrap();
        assert_eq!(parsed.extra_names.len(), 1);
        assert_eq!(parsed.referenced_names.len(), 1);
        assert_eq!(parsed.extra_names[0], (4, "bar".to_owned()));
        assert_eq!(parsed.referenced_names[0], (8, "baz".to_owned()));
    }

    #[test]
    fn pat_line_parse_ignores_comment() {
        assert!(PatLine::parse("; this is a comment").is_none());
    }

    #[test]
    fn pat_line_parse_ignores_separator() {
        assert!(PatLine::parse("---").is_none());
    }

    #[test]
    fn pat_line_from_flirt_pattern() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let line = PatLine::from_flirt_pattern(&pat);
        assert!(!line.hex_pattern.is_empty());
        assert_eq!(line.primary_name, "foo");
    }

    #[test]
    fn pat_file_writer_builds_string_with_header() {
        let writer = PatFileWriter::new("mylib");
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "myfunc");
        let s = writer.build_string(&[pat]);
        assert!(s.contains("; Library: mylib"));
        assert!(s.contains("myfunc"));
        assert!(s.ends_with("---\n"));
    }

    #[test]
    fn pat_file_writer_ends_with_separator() {
        let writer = PatFileWriter::new("lib");
        let s = writer.build_string(&[]);
        assert!(s.ends_with("---\n"));
    }

    #[test]
    fn write_pat_file_creates_file() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "test_func");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pat");
        write_pat_file(&[pat], "testlib", &path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("testlib"));
        assert!(content.contains("---"));
    }

    #[test]
    fn pat_file_reader_roundtrip() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "roundtrip_func");
        let writer = PatFileWriter::new("rt");
        let content = writer.build_string(&[pat]);
        let reader = PatFileReader::new();
        let lines = reader.parse_str(&content);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].primary_name, "roundtrip_func");
    }

    #[test]
    fn pat_file_reader_read_file() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "disk_func");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test2.pat");
        write_pat_file(&[pat], "lib", &path).unwrap();
        let reader = PatFileReader::new();
        let lines = reader.read_file(&path).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].primary_name, "disk_func");
    }

    #[test]
    fn pat_stats_from_lines() {
        let line = PatLine::new("5548", 4, 0x1234, 10, "foo");
        let stats = PatStats::from_lines(&[line]);
        assert_eq!(stats.pattern_count, 1);
        assert_eq!(stats.min_func_len, 10);
        assert_eq!(stats.max_func_len, 10);
    }

    #[test]
    fn pat_stats_from_patterns() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "a");
        let p2 = make_pattern(&[0x56, 0x48, 0x89, 0xE5, 0xC3], "b");
        let stats = PatStats::from_patterns(&[p1, p2]);
        assert_eq!(stats.pattern_count, 2);
    }

    #[test]
    fn pat_stats_display() {
        let stats = PatStats::default();
        let s = stats.to_string();
        assert!(s.contains("PatStats"));
    }

    #[test]
    fn pat_record_from_pattern() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "myfunc");
        let rec = PatRecord::from_pattern(&pat, "mylib");
        assert_eq!(rec.library, "mylib");
        assert_eq!(rec.line.primary_name, "myfunc");
    }

    #[test]
    fn pat_file_writer_filter_by_confidence() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "lowconf");
        let rec = PatRecord::new(PatLine::from_flirt_pattern(&pat), "lib", 0.3);
        let writer = PatFileWriter {
            filter_by_confidence: true,
            min_confidence: 0.5,
            ..PatFileWriter::new("lib")
        };
        let content = writer.build_from_records(&[rec]);
        // Low-confidence pattern should be filtered out — only the `---` line.
        assert!(!content.contains("lowconf"));
    }

    #[test]
    fn pat_line_display() {
        let line = PatLine::new("5548", 4, 0xABCD, 20, "disp_func");
        let s = format!("{line}");
        assert!(s.contains("ABCD"));
    }

    #[test]
    fn pat_record_display() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "rec_func");
        let rec = PatRecord::from_pattern(&pat, "reclib");
        let s = format!("{rec}");
        assert!(s.contains("reclib"));
    }

    #[test]
    fn pat_line_wildcard_representation() {
        use crate::RelocationEntry;
        let pg = PatternGenerator::new();
        let bytes = vec![0x55u8, 0x48, 0xAA, 0xBB, 0xC3, 0xCC, 0xDD, 0xEE];
        let relocs = vec![RelocationEntry { offset: 2, size: 2 }];
        let fname = FlirtName {
            name: "reloc_func".to_owned(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        let pat = pg.generate(&bytes, &relocs, vec![fname]).unwrap();
        let line = PatLine::from_flirt_pattern(&pat);
        // Bytes 2..4 should be wildcards (`..`).
        assert!(line.hex_pattern.contains(".."));
    }

    #[test]
    fn write_to_writer_produces_valid_content() {
        let pat = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "writer_func");
        let writer = PatFileWriter::new("writerlib");
        let mut buf = Vec::new();
        writer.write_to(&mut buf, &[pat]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("writerlib"));
        assert!(s.contains("writer_func"));
    }

    #[test]
    fn pat_file_writer_max_hex_length_truncates() {
        let bytes: Vec<u8> = (0u8..64).collect();
        let fname = FlirtName {
            name: "long_func".to_owned(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        let pg = PatternGenerator::new();
        let pat = pg.generate(&bytes, &[], vec![fname]).unwrap();
        let writer = PatFileWriter {
            max_hex_length: 4, // only 2 bytes
            ..PatFileWriter::new("lib")
        };
        let s = writer.build_string(&[pat]);
        // Find the line with the pattern.
        let data_line = s.lines().find(|l| !l.starts_with(';') && *l != "---").unwrap_or("");
        let hex_field = data_line.split_whitespace().next().unwrap_or("");
        assert!(hex_field.len() <= 4);
    }

    #[test]
    fn pat_stats_empty() {
        let stats = PatStats::from_lines(&[]);
        assert_eq!(stats.pattern_count, 0);
        assert_eq!(stats.min_func_len, 0);
    }
}
