//! PDB source line information reader.
//!
//! Reads C13-style line number data from PDB module streams.
//! Each module stream may contain a sequence of `CV_DebugSSubsectionDesc` records.
//! The two subsection types we care about are:
//!   - `FileChecksums` (0xF4) — maps file index → checksum + path
//!   - Lines (0xF2)          — maps (offset, length) code ranges to (file, line) pairs

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while parsing C13 line information.
#[derive(Debug)]
pub enum SourceLinesError {
    /// The data ended before the parser could read the required bytes.
    UnexpectedEof {
        /// Offset at which more data was needed.
        offset: usize,
        /// Number of additional bytes required.
        needed: usize,
    },
    /// A file checksum entry used an unrecognised algorithm code.
    UnknownChecksumKind {
        /// The checksum kind byte actually read.
        kind: u8,
    },
    /// A string in the data is not valid UTF-8.
    InvalidUtf8 {
        /// Offset of the invalid string.
        offset: usize,
    },
    /// A subsection header used an unrecognised kind code.
    InvalidSubsectionKind {
        /// The subsection kind actually read.
        kind: u32,
    },
    /// A line block referenced a file index missing from the checksum table.
    FileIndexNotFound {
        /// The unresolved file index.
        file_index: u32,
    },
}

impl fmt::Display for SourceLinesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset, needed } =>
                write!(f, "unexpected EOF at offset {offset}: needed {needed} bytes"),
            Self::UnknownChecksumKind { kind } =>
                write!(f, "unknown checksum kind {kind:#04X}"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 at offset {offset}"),
            Self::InvalidSubsectionKind { kind } =>
                write!(f, "unknown subsection kind {kind:#010X}"),
            Self::FileIndexNotFound { file_index } =>
                write!(f, "file index {file_index} not found in checksum table"),
        }
    }
}

impl std::error::Error for SourceLinesError {}
/// Result alias for C13 line-info parsing.
pub type SourceResult<T> = Result<T, SourceLinesError>;

// ---------------------------------------------------------------------------
// Checksum kind
// ---------------------------------------------------------------------------

/// The algorithm used to hash a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumKind {
    /// No checksum stored.
    None   = 0,
    /// MD5 (16 bytes).
    Md5    = 1,
    /// SHA-1 (20 bytes).
    Sha1   = 2,
    /// SHA-256 (32 bytes).
    Sha256 = 3,
}

impl ChecksumKind {
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub const fn from_u8(v: u8) -> SourceResult<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Md5),
            2 => Ok(Self::Sha1),
            3 => Ok(Self::Sha256),
            other => Err(SourceLinesError::UnknownChecksumKind { kind: other }),
        }
    }

    /// Expected checksum length in bytes for this algorithm.
    #[must_use]
    pub const fn checksum_len(&self) -> usize {
        match self {
            Self::None   => 0,
            Self::Md5    => 16,
            Self::Sha1   => 20,
            Self::Sha256 => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// File checksum record
// ---------------------------------------------------------------------------

/// One entry in the `FileChecksums` subsection.
#[derive(Debug, Clone)]
pub struct FileChecksum {
    /// Byte offset of the file path in the module's string table.
    pub name_offset: u32,
    /// Checksum algorithm.
    pub kind: ChecksumKind,
    /// Raw checksum bytes.
    pub checksum: Vec<u8>,
}

impl FileChecksum {
    /// Parse one `FileChecksum` entry from `data[offset..]`.
    /// Returns (entry, `bytes_consumed`), aligned to 4 bytes.
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8], offset: usize) -> SourceResult<(Self, usize)> {
        if data.len() < offset + 4 {
            return Err(SourceLinesError::UnexpectedEof { offset, needed: 4 });
        }
        let name_offset = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
        if data.len() < offset + 6 {
            return Err(SourceLinesError::UnexpectedEof { offset: offset + 4, needed: 2 });
        }
        let len = data[offset + 4] as usize;
        let kind = ChecksumKind::from_u8(data[offset + 5])?;
        if data.len() < offset + 6 + len {
            return Err(SourceLinesError::UnexpectedEof { offset: offset + 6, needed: len });
        }
        let checksum = data[offset + 6..offset + 6 + len].to_vec();
        let raw = 6 + len;
        let aligned = (raw + 3) & !3;
        Ok((Self { name_offset, kind, checksum }, aligned))
    }

    /// Returns a hex string of the checksum bytes.
    #[must_use]
    pub fn checksum_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(self.checksum.len() * 2);
        for b in &self.checksum {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Source file
// ---------------------------------------------------------------------------

/// Resolved source file information (combines checksum + path).
#[derive(Debug, Clone)]
pub struct SrcFile {
    /// File path from the string table.
    pub path: String,
    /// Checksum kind.
    pub checksum_kind: ChecksumKind,
    /// Checksum bytes.
    pub checksum: Vec<u8>,
}

impl SrcFile {
    /// Returns a hex string of the checksum bytes.
    #[must_use]
    pub fn checksum_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(self.checksum.len() * 2);
        for b in &self.checksum {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Line record
// ---------------------------------------------------------------------------

/// One line number entry within a Lines subsection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRecord {
    /// Byte offset relative to the function/contribution start.
    pub offset: u32,
    /// 1-based line number. 0 means "no line info".
    pub line_start: u32,
    /// 1-based end line number (for statement ranges).
    pub line_end: u32,
    /// Starting column (1-based, 0 = unknown).
    pub col_start: u16,
    /// Ending column (0 = unknown).
    pub col_end: u16,
    /// Whether this record has a statement end rather than just a start.
    pub has_columns: bool,
}

impl LineRecord {
    /// Parse a packed line entry (4-byte offset + 4-byte `line_start_with_flags`).
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse_entry(offset_bytes: &[u8], line_bytes: &[u8]) -> SourceResult<Self> {
        if offset_bytes.len() < 4 || line_bytes.len() < 4 {
            return Err(SourceLinesError::UnexpectedEof { offset: 0, needed: 8 });
        }
        let offset = u32::from_le_bytes(offset_bytes[..4].try_into().unwrap());
        let raw    = u32::from_le_bytes(line_bytes[..4].try_into().unwrap());
        let line_start = raw & 0x00FF_FFFF;
        let delta      = (raw >> 24) & 0x7F;
        let line_end   = line_start + delta;
        Ok(Self {
            offset,
            line_start,
            line_end,
            col_start: 0,
            col_end: 0,
            has_columns: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Subsection header
// ---------------------------------------------------------------------------

const SUBSECTION_FILECHECKSUMS: u32 = 0xF4;
const SUBSECTION_LINES: u32         = 0xF2;
const SUBSECTION_STRINGTABLE: u32   = 0xF3;
const SUBSECTION_INLINEEELINES: u32 = 0xF6;

/// Return the human-readable name of a `CodeView` C13 subsection kind.
///
/// Covers the subset that `SourceLinesReader` recognises; unknown kinds
/// return `"DEBUG_S_UNKNOWN"`.
#[must_use]
pub const fn subsection_kind_name(kind: u32) -> &'static str {
    match kind {
        SUBSECTION_LINES => "DEBUG_S_LINES",
        SUBSECTION_STRINGTABLE => "DEBUG_S_STRINGTABLE",
        SUBSECTION_FILECHECKSUMS => "DEBUG_S_FILECHKSMS",
        SUBSECTION_INLINEEELINES => "DEBUG_S_INLINEELINES",
        _ => "DEBUG_S_UNKNOWN",
    }
}

/// One C13 debug subsection.
#[derive(Debug, Clone)]
pub struct DebugSubsection {
    /// `DEBUG_S_*` subsection kind code.
    pub kind: u32,
    /// Raw subsection payload bytes.
    pub data: Vec<u8>,
}

impl DebugSubsection {
    /// Parse all subsections from a module stream's C13 data region.
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse_all(data: &[u8]) -> SourceResult<Vec<Self>> {
        let mut out = Vec::new();
        let mut cur = 0usize;
        while cur + 8 <= data.len() {
            let kind = u32::from_le_bytes(data[cur..cur+4].try_into().unwrap());
            let size = u32::from_le_bytes(data[cur+4..cur+8].try_into().unwrap()) as usize;
            cur += 8;
            if cur + size > data.len() {
                return Err(SourceLinesError::UnexpectedEof { offset: cur, needed: size });
            }
            let payload = data[cur..cur + size].to_vec();
            out.push(Self { kind, data: payload });
            cur += size;
            // Align to 4 bytes
            let aligned = (cur + 3) & !3;
            if aligned > data.len() { break; }
            cur = aligned;
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Lines subsection
// ---------------------------------------------------------------------------

/// Header for a Lines subsection.
#[derive(Debug, Clone)]
pub struct LinesSubsection {
    /// Offset from the start of the function.
    pub reloc_offset: u32,
    /// Section index.
    pub reloc_segment: u16,
    /// Flags (0x0001 = has columns).
    pub flags: u16,
    /// Length of the code region described by this subsection.
    pub code_size: u32,
    /// Per-file line blocks.
    pub file_blocks: Vec<LineFileBlock>,
}

/// A block of line records associated with one source file.
#[derive(Debug, Clone)]
pub struct LineFileBlock {
    /// Byte offset into the `FileChecksums` subsection.
    pub file_index: u32,
    /// Line records in this block.
    pub lines: Vec<LineRecord>,
}

impl LinesSubsection {
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8]) -> SourceResult<Self> {
        if data.len() < 12 {
            return Err(SourceLinesError::UnexpectedEof { offset: 0, needed: 12 });
        }
        let reloc_offset  = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let reloc_segment = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let flags         = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let code_size     = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let has_columns   = flags & 0x0001 != 0;

        let mut file_blocks = Vec::new();
        let mut cur = 12usize;
        while cur + 12 <= data.len() {
            let file_index   = u32::from_le_bytes(data[cur..cur+4].try_into().unwrap());
            let num_lines    = u32::from_le_bytes(data[cur+4..cur+8].try_into().unwrap()) as usize;
            let block_size   = u32::from_le_bytes(data[cur+8..cur+12].try_into().unwrap()) as usize;
            cur += 12;

            let entries_start = cur;
            let col_data_start = entries_start + num_lines * 8;

            // `num_lines` is attacker-controlled; cap the pre-allocation by
            // the number of 8-byte entries the remaining bytes can hold.
            let mut lines =
                Vec::with_capacity(num_lines.min(data.len().saturating_sub(entries_start) / 8));
            for i in 0..num_lines {
                let base = entries_start + i * 8;
                if base + 8 > data.len() { break; }
                let off_bytes  = &data[base..base+4];
                let line_bytes = &data[base+4..base+8];
                let mut rec = LineRecord::parse_entry(off_bytes, line_bytes)?;
                if has_columns && col_data_start + i * 4 + 4 <= data.len() {
                    let cb = col_data_start + i * 4;
                    rec.col_start = u16::from_le_bytes(data[cb..cb+2].try_into().unwrap());
                    rec.col_end   = u16::from_le_bytes(data[cb+2..cb+4].try_into().unwrap());
                    rec.has_columns = true;
                }
                lines.push(rec);
            }
            file_blocks.push(LineFileBlock { file_index, lines });

            // Advance past the whole block (header already consumed above)
            let expected_end = entries_start - 12 + block_size;
            cur = expected_end.max(cur);
        }

        Ok(Self { reloc_offset, reloc_segment, flags, code_size, file_blocks })
    }
}

// ---------------------------------------------------------------------------
// SourceLinesReader — top level
// ---------------------------------------------------------------------------

/// Parsed source-line information for one module.
pub struct SourceLinesReader {
    /// All resolved source files referenced by this module.
    pub files: Vec<SrcFile>,
    /// Maps `FileChecksum` byte-offset → index into `files`.
    file_offset_to_index: HashMap<u32, usize>,
    /// All line blocks, resolved to file indices.
    pub resolved_blocks: Vec<ResolvedLineBlock>,
}

/// A line block with the file path resolved.
#[derive(Debug, Clone)]
pub struct ResolvedLineBlock {
    /// Code offset from the function start.
    pub reloc_offset: u32,
    /// Section index of the code region.
    pub reloc_segment: u16,
    /// Length of the code region in bytes.
    pub code_size: u32,
    /// Index into [`SourceLinesReader::files`].
    pub file_index: usize,
    /// Line records for this block.
    pub lines: Vec<LineRecord>,
}

impl SourceLinesReader {
    /// Parse C13 line data from a module's symbol stream segment.
    ///
    /// `c13_data`: raw bytes of the C13 region (at the end of the module sym stream).
    /// `string_table`: the PDB-wide string table (byte slice), used to resolve file paths.
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(c13_data: &[u8], string_table: &[u8]) -> SourceResult<Self> {
        let subsections = DebugSubsection::parse_all(c13_data)?;

        // First pass: collect FileChecksums
        let mut checksum_entries: Vec<(u32, FileChecksum)> = Vec::new(); // (byte_offset, entry)
        for sub in &subsections {
            if sub.kind == SUBSECTION_FILECHECKSUMS {
                let mut off = 0usize;
                while off < sub.data.len() {
                    let (entry, consumed) = FileChecksum::parse(&sub.data, off)?;
                    checksum_entries.push((u32::try_from(off).unwrap_or(u32::MAX), entry));
                    off += consumed;
                    if consumed == 0 { break; }
                }
            }
        }

        // Resolve file paths from string table
        let mut files = Vec::new();
        let mut file_offset_to_index = HashMap::new();
        for (byte_off, entry) in &checksum_entries {
            let path = read_string_table(string_table, entry.name_offset as usize)?;
            let idx = files.len();
            files.push(SrcFile {
                path,
                checksum_kind: entry.kind,
                checksum: entry.checksum.clone(),
            });
            file_offset_to_index.insert(*byte_off, idx);
        }

        // Second pass: collect Lines subsections
        let mut resolved_blocks = Vec::new();
        for sub in &subsections {
            if sub.kind == SUBSECTION_LINES {
                let ls = LinesSubsection::parse(&sub.data)?;
                for fb in &ls.file_blocks {
                    let file_index = file_offset_to_index
                        .get(&fb.file_index)
                        .copied()
                        .unwrap_or(0);
                    resolved_blocks.push(ResolvedLineBlock {
                        reloc_offset: ls.reloc_offset,
                        reloc_segment: ls.reloc_segment,
                        code_size: ls.code_size,
                        file_index,
                        lines: fb.lines.clone(),
                    });
                }
            }
        }

        Ok(Self { files, file_offset_to_index, resolved_blocks })
    }

    /// Resolve a `FileChecksum` byte-offset (as stored in `DEBUG_S_LINES`
    /// blocks) to an index into [`files`](Self::files).
    ///
    /// Used by callers that have a raw checksum offset and want to look up
    /// the corresponding `SrcFile` without re-walking the resolved blocks.
    #[must_use]
    pub fn file_index_for_checksum_offset(&self, byte_offset: u32) -> Option<usize> {
        self.file_offset_to_index.get(&byte_offset).copied()
    }

    /// Number of distinct `FileChecksum` entries indexed by this reader.
    #[must_use]
    pub fn checksum_count(&self) -> usize {
        self.file_offset_to_index.len()
    }

    /// Find the source location for a given code offset within a function.
    /// Returns (`file_path`, `line_number`) for the nearest line record at or before `offset`.
    #[must_use]
    pub fn find_line(&self, segment: u16, offset: u32) -> Option<(&str, u32)> {
        let mut best: Option<(u32, &ResolvedLineBlock, u32)> = None;
        for block in &self.resolved_blocks {
            if block.reloc_segment != segment { continue; }
            for rec in &block.lines {
                let abs = block.reloc_offset + rec.offset;
                if abs <= offset {
                    match best {
                        None => { best = Some((abs, block, rec.line_start)); }
                        Some((ba, _, _)) if abs > ba => { best = Some((abs, block, rec.line_start)); }
                        _ => {}
                    }
                }
            }
        }
        best.map(|(_, block, line)| {
            let path = self.files.get(block.file_index).map_or("<unknown>", |f| f.path.as_str());
            (path, line)
        })
    }

    /// Return all unique source files referenced by this module.
    #[must_use]
    pub fn source_files(&self) -> &[SrcFile] {
        &self.files
    }

    /// Return all line records for a given source file (by path).
    #[must_use]
    pub fn lines_for_file(&self, path: &str) -> Vec<(u32, u32)> {
        let file_index = self.files.iter().position(|f| f.path == path);
        file_index.map_or_else(std::vec::Vec::new, |fi| {
                let mut out = Vec::new();
                for block in &self.resolved_blocks {
                    if block.file_index != fi { continue; }
                    for rec in &block.lines {
                        out.push((block.reloc_offset + rec.offset, rec.line_start));
                    }
                }
                out.sort_by_key(|&(off, _)| off);
                out
            })
    }

    /// Return a summary of line info coverage.
    #[must_use]
    pub fn summary(&self) -> String {
        let total_lines: usize = self.resolved_blocks.iter().map(|b| b.lines.len()).sum();
        format!(
            "source_lines: {} files, {} blocks, {} line records",
            self.files.len(),
            self.resolved_blocks.len(),
            total_lines,
        )
    }
}

// ---------------------------------------------------------------------------
// String table helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated string from the PDB string table at byte `offset`.
fn read_string_table(data: &[u8], offset: usize) -> SourceResult<String> {
    if offset >= data.len() {
        return Ok(String::new()); // tolerate missing path
    }
    let rest = &data[offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|_| SourceLinesError::InvalidUtf8 { offset })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a FileChecksums subsection
    fn make_checksums_subsection(entries: &[(&str, ChecksumKind)], string_table: &mut Vec<u8>) -> Vec<u8> {
        let mut data = Vec::new();
        for (name, kind) in entries {
            let name_offset = u32::try_from(string_table.len()).unwrap();
            string_table.extend_from_slice(name.as_bytes());
            string_table.push(0u8);
            while !string_table.len().is_multiple_of(4) { string_table.push(0); }

            let checksum = match kind {
                ChecksumKind::Md5    => vec![0xAAu8; 16],
                ChecksumKind::Sha1   => vec![0xBBu8; 20],
                ChecksumKind::Sha256 => vec![0xCCu8; 32],
                ChecksumKind::None   => vec![],
            };
            data.extend_from_slice(&name_offset.to_le_bytes());
            data.push(u8::try_from(checksum.len()).unwrap());
            data.push(*kind as u8);
            data.extend_from_slice(&checksum);
            while data.len() % 4 != 0 { data.push(0); }
        }
        data
    }

    fn wrap_subsection(kind: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(data);
        while out.len() % 4 != 0 { out.push(0); }
        out
    }

    #[test]
    fn file_checksum_md5_parse() {
        let mut data = vec![0u8; 4]; // name_offset = 0
        data.push(16u8); // len
        data.push(ChecksumKind::Md5 as u8);
        data.extend_from_slice(&[0xAAu8; 16]);
        // pad to 4 bytes: 6+16=22, next 4-aligned = 24
        while !data.len().is_multiple_of(4) { data.push(0); }
        let (fc, consumed) = FileChecksum::parse(&data, 0).unwrap();
        assert_eq!(fc.kind, ChecksumKind::Md5);
        assert_eq!(fc.checksum.len(), 16);
        assert_eq!(consumed, 24);
        assert_eq!(fc.checksum_hex(), "aa".repeat(16));
    }

    #[test]
    fn checksum_kind_lens() {
        assert_eq!(ChecksumKind::None.checksum_len(), 0);
        assert_eq!(ChecksumKind::Md5.checksum_len(), 16);
        assert_eq!(ChecksumKind::Sha1.checksum_len(), 20);
        assert_eq!(ChecksumKind::Sha256.checksum_len(), 32);
    }

    #[test]
    fn line_record_parse_entry() {
        let offset_bytes = 0x1234u32.to_le_bytes();
        // line 42, delta 5 => (42 | (5 << 24))
        let raw: u32 = 0x2A | (5 << 24);
        let line_bytes = raw.to_le_bytes();
        let rec = LineRecord::parse_entry(&offset_bytes, &line_bytes).unwrap();
        assert_eq!(rec.offset, 0x1234);
        assert_eq!(rec.line_start, 42);
        assert_eq!(rec.line_end, 47);
    }

    #[test]
    fn debug_subsection_parse_all_two_sections() {
        let mut data = Vec::new();
        data.extend_from_slice(&SUBSECTION_FILECHECKSUMS.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // size=4
        data.extend_from_slice(&[1u8, 2u8, 3u8, 4u8]);

        data.extend_from_slice(&SUBSECTION_LINES.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // size=8
        data.extend_from_slice(&[5u8; 8]);

        let subs = DebugSubsection::parse_all(&data).unwrap();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].kind, SUBSECTION_FILECHECKSUMS);
        assert_eq!(subs[0].data, [1u8, 2u8, 3u8, 4u8]);
        assert_eq!(subs[1].kind, SUBSECTION_LINES);
    }

    #[test]
    fn source_lines_reader_find_line() {
        let mut string_table = Vec::new();
        let checksums = make_checksums_subsection(&[("foo.c", ChecksumKind::Md5)], &mut string_table);
        let cs_sub = wrap_subsection(SUBSECTION_FILECHECKSUMS, &checksums);

        // Build a minimal Lines subsection manually
        let mut lines_data = Vec::new();
        // Header: reloc_offset=0x1000, segment=1, flags=0, code_size=0x100
        lines_data.extend_from_slice(&0x1000u32.to_le_bytes());
        lines_data.extend_from_slice(&1u16.to_le_bytes());
        lines_data.extend_from_slice(&0u16.to_le_bytes());
        lines_data.extend_from_slice(&0x100u32.to_le_bytes());
        // FileBlock: file_index=0, num_lines=2, block_size = 12 + 2*8 = 28
        lines_data.extend_from_slice(&0u32.to_le_bytes()); // file_index=0
        lines_data.extend_from_slice(&2u32.to_le_bytes()); // num_lines
        lines_data.extend_from_slice(&28u32.to_le_bytes()); // block_size
        // line entry 1: offset=0, line=10
        lines_data.extend_from_slice(&0u32.to_le_bytes());
        lines_data.extend_from_slice(&(0x0Au32 | (1 << 24)).to_le_bytes());
        // line entry 2: offset=0x20, line=15
        lines_data.extend_from_slice(&0x20u32.to_le_bytes());
        lines_data.extend_from_slice(&(15u32 | (1 << 24)).to_le_bytes());

        let lines_sub = wrap_subsection(SUBSECTION_LINES, &lines_data);

        let mut c13 = cs_sub;
        c13.extend_from_slice(&lines_sub);

        let reader = SourceLinesReader::parse(&c13, &string_table).unwrap();
        assert_eq!(reader.files.len(), 1);
        assert_eq!(reader.files[0].path, "foo.c");

        // find_line at 0x1010 (between 0x1000 and 0x1020)
        let (path, line) = reader.find_line(1, 0x1010).unwrap();
        assert_eq!(path, "foo.c");
        assert_eq!(line, 10);

        // find_line at 0x1020 exactly
        let (_path2, line2) = reader.find_line(1, 0x1020).unwrap();
        assert_eq!(line2, 15);

        // find_line at 0x1025
        let (_, line3) = reader.find_line(1, 0x1025).unwrap();
        assert_eq!(line3, 15);
    }

    #[test]
    fn source_lines_reader_lines_for_file() {
        let mut string_table = Vec::new();
        let checksums = make_checksums_subsection(&[("bar.cpp", ChecksumKind::None)], &mut string_table);
        let cs_sub = wrap_subsection(SUBSECTION_FILECHECKSUMS, &checksums);

        let mut lines_data = Vec::new();
        lines_data.extend_from_slice(&0u32.to_le_bytes());   // reloc_offset
        lines_data.extend_from_slice(&1u16.to_le_bytes());   // segment
        lines_data.extend_from_slice(&0u16.to_le_bytes());   // flags
        lines_data.extend_from_slice(&0x50u32.to_le_bytes()); // code_size
        // FileBlock
        lines_data.extend_from_slice(&0u32.to_le_bytes()); // file_index
        lines_data.extend_from_slice(&1u32.to_le_bytes()); // num_lines
        lines_data.extend_from_slice(&20u32.to_le_bytes()); // block_size = 12+8=20
        lines_data.extend_from_slice(&0u32.to_le_bytes());
        lines_data.extend_from_slice(&100u32.to_le_bytes());

        let lines_sub = wrap_subsection(SUBSECTION_LINES, &lines_data);
        let mut c13 = cs_sub;
        c13.extend_from_slice(&lines_sub);

        let reader = SourceLinesReader::parse(&c13, &string_table).unwrap();
        let lns = reader.lines_for_file("bar.cpp");
        assert_eq!(lns.len(), 1);
        assert_eq!(lns[0].1, 100);
    }

    #[test]
    fn summary_format() {
        let reader = SourceLinesReader {
            files: vec![
                SrcFile { path: "a.c".into(), checksum_kind: ChecksumKind::None, checksum: vec![] },
            ],
            file_offset_to_index: HashMap::new(),
            resolved_blocks: vec![
                ResolvedLineBlock {
                    reloc_offset: 0, reloc_segment: 1, code_size: 100,
                    file_index: 0,
                    lines: vec![
                        LineRecord { offset: 0, line_start: 1, line_end: 1, col_start: 0, col_end: 0, has_columns: false },
                        LineRecord { offset: 4, line_start: 2, line_end: 2, col_start: 0, col_end: 0, has_columns: false },
                    ],
                },
            ],
        };
        let s = reader.summary();
        assert!(s.contains("1 files"));
        assert!(s.contains("1 blocks"));
        assert!(s.contains("2 line records"));
    }
}
