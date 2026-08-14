//! `pdb_line_info` — C13 line number information parser.
//!
//! Parses:
//! * C13 `DEBUG_S_LINES` subsections (file/line → address mappings)
//! * `DEBUG_S_FILECHKSMS` (file checksum table)
//! * `DEBUG_S_INLINEELINES` (inline site line info)
//! * src-to-lines (source line → address set) reverse mapping

use std::collections::HashMap;

// ── C13 subsection type codes ─────────────────────────────────────────────────

const DEBUG_S_SYMBOLS: u32 = 0xF1;
const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_STRINGTABLE: u32 = 0xF3;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;
const DEBUG_S_FRAMEDATA: u32 = 0xF5;
const DEBUG_S_INLINEELINES: u32 = 0xF6;
const DEBUG_S_CROSSSCOPEIMPORTS: u32 = 0xF7;
const DEBUG_S_CROSSSCOPEEXPORTS: u32 = 0xF8;
const DEBUG_S_IL_LINES: u32 = 0xF9;
const DEBUG_S_FUNC_MDTOKEN_MAP: u32 = 0xFA;
const DEBUG_S_TYPE_MDTOKEN_MAP: u32 = 0xFB;
const DEBUG_S_MERGED_ASSEMBLYINPUT: u32 = 0xFC;
const DEBUG_S_COFF_SYMBOL_RVA: u32 = 0xFD;

/// Classify a raw C13 subsection-kind code into its mnemonic.
///
/// Covers every subsection kind documented for CodeView/PDB C13 line info,
/// including those (`SYMBOLS`, `FRAMEDATA`, `IL_LINES`, ...) that this
/// parser does not consume but which higher layers may want to recognise.
#[must_use]
pub const fn debug_subsection_kind_name(kind: u32) -> &'static str {
    match kind {
        DEBUG_S_SYMBOLS => "DEBUG_S_SYMBOLS",
        DEBUG_S_LINES => "DEBUG_S_LINES",
        DEBUG_S_STRINGTABLE => "DEBUG_S_STRINGTABLE",
        DEBUG_S_FILECHKSMS => "DEBUG_S_FILECHKSMS",
        DEBUG_S_FRAMEDATA => "DEBUG_S_FRAMEDATA",
        DEBUG_S_INLINEELINES => "DEBUG_S_INLINEELINES",
        DEBUG_S_CROSSSCOPEIMPORTS => "DEBUG_S_CROSSSCOPEIMPORTS",
        DEBUG_S_CROSSSCOPEEXPORTS => "DEBUG_S_CROSSSCOPEEXPORTS",
        DEBUG_S_IL_LINES => "DEBUG_S_IL_LINES",
        DEBUG_S_FUNC_MDTOKEN_MAP => "DEBUG_S_FUNC_MDTOKEN_MAP",
        DEBUG_S_TYPE_MDTOKEN_MAP => "DEBUG_S_TYPE_MDTOKEN_MAP",
        DEBUG_S_MERGED_ASSEMBLYINPUT => "DEBUG_S_MERGED_ASSEMBLYINPUT",
        DEBUG_S_COFF_SYMBOL_RVA => "DEBUG_S_COFF_SYMBOL_RVA",
        _ => "DEBUG_S_UNKNOWN",
    }
}

/// Returns `true` if the given subsection kind is one this parser can decode
/// (currently `DEBUG_S_LINES`, `DEBUG_S_FILECHKSMS`, `DEBUG_S_STRINGTABLE`,
/// `DEBUG_S_INLINEELINES`).
#[must_use]
pub const fn is_supported_debug_subsection(kind: u32) -> bool {
    matches!(
        kind,
        DEBUG_S_LINES | DEBUG_S_FILECHKSMS | DEBUG_S_STRINGTABLE | DEBUG_S_INLINEELINES
    )
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing C13 line information.
#[derive(Debug, thiserror::Error)]
pub enum LineInfoError {
    /// The stream ended before the offset the parser needed to read.
    #[error("stream too short at offset {0}")]
    TooShort(usize),
    /// The C13 data at the given offset is structurally invalid.
    #[error("corrupt C13 data at offset {0}")]
    Corrupt(usize),
}

/// Result alias for C13 line-info parsing.
pub type Result<T> = std::result::Result<T, LineInfoError>;

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(LineInfoError::TooShort(off))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(LineInfoError::TooShort(off))
}

/// Read a null-terminated C string at `off`; returns `(string, next_offset)`.
///
/// Used internally by inline-line/string-table decoders and exposed so
/// external consumers can walk auxiliary substreams with the same lossy
/// UTF-8 rules as the rest of the C13 line-info parser.
#[must_use]
pub fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    let start = off;
    let mut pos = off;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..pos]).into_owned();
    (s, if pos < data.len() { pos + 1 } else { pos })
}

// ── File checksum ─────────────────────────────────────────────────────────────

/// A file checksum entry (`DEBUG_S_FILECHKSMS`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileChecksum {
    /// Byte offset of the file name in the string table.
    pub name_offset: u32,
    /// Checksum bytes (may be empty for `CHKSUM_TYPE_NONE`).
    pub checksum: Vec<u8>,
    /// Checksum type: 0=none, 1=MD5, 2=SHA1, 3=SHA256.
    pub checksum_type: u8,
}

/// Parse a `DEBUG_S_FILECHKSMS` subsection.
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_file_checksums(data: &[u8]) -> Result<Vec<FileChecksum>> {
    let mut off = 0usize;
    let mut out = Vec::new();

    while off + 8 <= data.len() {
        let name_offset = read_u32(data, off)?;
        let len = data[off + 4] as usize;
        let kind = data[off + 5];
        // 2 bytes padding after (align to 4 bytes)
        let entry_size = (6 + len + 3) & !3;
        let checksum = data.get(off + 6..off + 6 + len).unwrap_or(&[]).to_vec();
        out.push(FileChecksum {
            name_offset,
            checksum,
            checksum_type: kind,
        });
        off += entry_size;
    }
    Ok(out)
}

// ── Line entry ────────────────────────────────────────────────────────────────

/// A single address→(file, line) mapping.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LineEntry {
    /// Section-relative offset of the instruction.
    pub offset: u32,
    /// File checksum index (index into the checksum table).
    pub file_index: u32,
    /// 1-based source line number.
    pub line_start: u32,
    /// End line (inclusive), or same as `line_start`.
    pub line_end: u32,
    /// Column start (0 = not present).
    pub col_start: u16,
    /// Column end (0 = not present).
    pub col_end: u16,
    /// True if this is a statement boundary.
    pub is_statement: bool,
}

// ── Block header for DEBUG_S_LINES ────────────────────────────────────────────

/// Header for one file-block within a `DEBUG_S_LINES` subsection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileBlockHeader {
    /// Index into the checksum table.
    pub file_index: u32,
    /// Number of line entries in this block.
    pub num_lines: u32,
    /// Total byte size of this block (header + entries).
    pub block_size: u32,
}

// ── C13 lines subsection ──────────────────────────────────────────────────────

/// Contents of one `DEBUG_S_LINES` subsection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinesSubsection {
    /// RVA (section-relative offset) of the function/block this covers.
    pub code_offset: u32,
    /// Segment index.
    pub segment: u16,
    /// Whether column information is present.
    pub has_columns: bool,
    /// Total code length covered.
    pub code_length: u32,
    /// Parsed line entries.
    pub entries: Vec<LineEntry>,
}

/// Parse a raw `DEBUG_S_LINES` subsection.
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_lines_subsection(data: &[u8]) -> Result<LinesSubsection> {
    if data.len() < 12 {
        return Err(LineInfoError::TooShort(0));
    }
    let code_offset = read_u32(data, 0)?;
    let segment = read_u16(data, 4)?;
    let flags = read_u16(data, 6)?;
    let has_columns = flags & 0x0001 != 0;
    let code_length = read_u32(data, 8)?;

    let mut off = 12usize;
    let mut entries = Vec::new();

    while off + 12 <= data.len() {
        let block_start = off;
        let file_index = read_u32(data, off)?;
        let num_lines = read_u32(data, off + 4)? as usize;
        let block_size = read_u32(data, off + 8)? as usize;
        off += 12;

        // Read line-number entries (8 bytes each).
        // Remember where this block's entries begin in `entries`, so the
        // column loop below patches this block's entries, not block 0's.
        let entries_base = entries.len();
        let line_start_off = off;
        for _ in 0..num_lines {
            if off + 8 > data.len() {
                break;
            }
            let entry_offset = read_u32(data, off)?;
            let line_flags = read_u32(data, off + 4)?;
            let line_start = line_flags & 0x00FF_FFFF;
            let delta_end = (line_flags >> 24) & 0x7F;
            let is_statement = (line_flags >> 31) & 1 == 0;
            entries.push(LineEntry {
                offset: entry_offset,
                file_index,
                line_start,
                line_end: line_start + delta_end,
                col_start: 0,
                col_end: 0,
                is_statement,
            });
            off += 8;
        }

        // Read optional column entries (4 bytes each).
        if has_columns {
            let col_start_off = line_start_off + num_lines * 8;
            for i in 0..num_lines {
                let col_off = col_start_off + i * 4;
                if col_off + 4 > data.len() {
                    break;
                }
                let col_s = read_u16(data, col_off)?;
                let col_e = read_u16(data, col_off + 2)?;
                if let Some(e) = entries.get_mut(entries_base + i) {
                    e.col_start = col_s;
                    e.col_end = col_e;
                }
            }
            off = col_start_off + num_lines * 4;
        }

        // Honor the declared block_size when advancing: the format permits a
        // block to carry trailing data beyond num_lines*8 (+columns). Without
        // this, padding bytes get reparsed as a bogus FileBlockHeader.
        // Mirrors pdb_source_lines.rs (`cur = expected_end.max(cur)`).
        let expected_end = block_start.saturating_add(block_size);
        off = expected_end.max(off).min(data.len());
    }

    Ok(LinesSubsection {
        code_offset,
        segment,
        has_columns,
        code_length,
        entries,
    })
}

// ── Inline line entry ─────────────────────────────────────────────────────────

/// An inline site line entry (`DEBUG_S_INLINEELINES`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineLineEntry {
    /// IPI item id of the inlined function.
    pub inlinee: u32,
    /// Byte offset into the file checksum table.
    pub file_index: u32,
    /// 1-based source line of the inlinee's definition.
    pub source_line: u32,
    /// Extra annotations (e.g. parent/child links in compressed format).
    pub annotations: Vec<InlineAnnotation>,
}

/// A single annotation in a compressed inline-line record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineAnnotation {
    /// Binary annotation opcode.
    pub opcode: u8,
    /// Compressed operand value.
    pub operand: u32,
}

/// Parse a `DEBUG_S_INLINEELINES` subsection.
/// Two formats: signature=0x0 (non-compressed) or 0x1 (compressed).
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_inline_lines(data: &[u8]) -> Result<Vec<InlineLineEntry>> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let signature = read_u32(data, 0)?;
    let mut off = 4usize;
    let mut entries = Vec::new();

    if signature == 0 {
        // Non-compressed: each entry is 12 bytes
        while off + 12 <= data.len() {
            let inlinee = read_u32(data, off)?;
            let file_index = read_u32(data, off + 4)?;
            let source_line = read_u32(data, off + 8)?;
            entries.push(InlineLineEntry {
                inlinee,
                file_index,
                source_line,
                annotations: vec![],
            });
            off += 12;
        }
    } else {
        // Compressed: each entry is 12 bytes + variable-length annotations
        while off + 12 <= data.len() {
            let inlinee = read_u32(data, off)?;
            let file_index = read_u32(data, off + 4)?;
            let source_line = read_u32(data, off + 8)?;
            off += 12;

            let mut annotations = Vec::new();
            // Read CodeLengthAndCodeOffset annotationsuntil opcode 0
            while off < data.len() {
                let opcode = data[off];
                off += 1;
                if opcode == 0 {
                    break;
                }
                let operand = decode_unsigned_operand(data, &mut off);
                annotations.push(InlineAnnotation { opcode, operand });
            }
            entries.push(InlineLineEntry { inlinee, file_index, source_line, annotations });
        }
    }
    Ok(entries)
}

fn decode_unsigned_operand(data: &[u8], off: &mut usize) -> u32 {
    // Simple variable-length encoding (4-bit prefix per byte)
    let mut result = 0u32;
    let mut shift = 0u32;
    while *off < data.len() {
        let b = data[*off];
        *off += 1;
        result |= u32::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    result
}

// ── C13 subsection iterator ───────────────────────────────────────────────────

/// A parsed C13 debug subsection.
#[derive(Debug, Clone)]
pub struct C13Subsection {
    /// `DEBUG_S_*` subsection kind code.
    pub kind: u32,
    /// Raw subsection payload bytes.
    pub data: Vec<u8>,
}

/// Split a C13 debug stream into typed subsections.
/// # Panics
///
/// May panic on malformed input.
#[must_use]
pub fn split_c13_subsections(stream: &[u8]) -> Vec<C13Subsection> {
    let mut off = 0usize;
    let mut out = Vec::new();

    while off + 8 <= stream.len() {
        let kind = u32::from_le_bytes(stream[off..off + 4].try_into().unwrap());
        let size = u32::from_le_bytes(stream[off + 4..off + 8].try_into().unwrap()) as usize;
        off += 8;
        let data = stream.get(off..off + size).unwrap_or(&[]).to_vec();
        out.push(C13Subsection { kind, data });
        // Align to 4-byte boundary.
        off += (size + 3) & !3;
    }
    out
}

// ── LineInfoDatabase — full source location maps ──────────────────────────────

/// Source location for an address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceLocation {
    /// Source file path.
    pub file_name: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column (0 = unknown).
    pub column: u16,
}

/// Full line information database built from C13 data + file checksum table.
pub struct LineInfoDatabase {
    /// Offset → source location.
    pub by_offset: HashMap<u32, SourceLocation>,
    /// File name → list of (offset, line) pairs (srcToLines).
    pub src_to_lines: HashMap<String, Vec<(u32, u32)>>,
    /// File checksum entries.
    pub checksums: Vec<FileChecksum>,
    /// String table used for resolving file names from checksum offsets.
    pub string_table: Vec<u8>,
}

impl LineInfoDatabase {
    /// Build the database from parsed C13 subsections.
    #[must_use]
    pub fn build(subsections: &[C13Subsection]) -> Self {
        let mut checksums = Vec::new();
        let mut string_table = Vec::new();
        let mut lines_list: Vec<LinesSubsection> = Vec::new();

        for ss in subsections {
            match ss.kind {
                DEBUG_S_FILECHKSMS => {
                    checksums = parse_file_checksums(&ss.data).unwrap_or_default();
                }
                DEBUG_S_STRINGTABLE => {
                    string_table.clone_from(&ss.data);
                }
                DEBUG_S_LINES => {
                    if let Ok(ls) = parse_lines_subsection(&ss.data) {
                        lines_list.push(ls);
                    }
                }
                _ => {}
            }
        }

        let mut by_offset: HashMap<u32, SourceLocation> = HashMap::new();
        let mut src_to_lines: HashMap<String, Vec<(u32, u32)>> = HashMap::new();

        for ls in &lines_list {
            for entry in &ls.entries {
                let file_name = resolve_file_name(entry.file_index, &checksums, &string_table);
                let abs_offset = ls.code_offset + entry.offset;
                let loc = SourceLocation {
                    file_name: file_name.clone(),
                    line: entry.line_start,
                    column: entry.col_start,
                };
                by_offset.insert(abs_offset, loc);
                src_to_lines
                    .entry(file_name)
                    .or_default()
                    .push((abs_offset, entry.line_start));
            }
        }

        Self { by_offset, src_to_lines, checksums, string_table }
    }

    /// Look up the source location for a given code offset.
    #[must_use]
    pub fn lookup_offset(&self, offset: u32) -> Option<&SourceLocation> {
        self.by_offset.get(&offset)
    }

    /// Get all (offset, line) pairs for a source file.
    #[must_use]
    pub fn lines_for_file(&self, file: &str) -> &[(u32, u32)] {
        self.src_to_lines.get(file).map_or(&[], Vec::as_slice)
    }
}

fn resolve_file_name(file_index: u32, checksums: &[FileChecksum], string_table: &[u8]) -> String {
    let Some(chk) = checksums.get(file_index as usize) else { return format!("<file#{file_index}>") };
    let off = chk.name_offset as usize;
    if off >= string_table.len() {
        return format!("<strtab@{off}>");
    }
    let end = string_table[off..]
        .iter()
        .position(|&b| b == 0)
        .map_or(string_table.len(), |p| off + p);
    String::from_utf8_lossy(&string_table[off..end]).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lines_subsection(code_offset: u32, entries: &[(u32, u32)]) -> Vec<u8> {
        // entries: (offset, line)
        let num_lines = u32::try_from(entries.len()).unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&code_offset.to_le_bytes()); // code_offset
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(&0u16.to_le_bytes()); // flags (no columns)
        data.extend_from_slice(&0x100u32.to_le_bytes()); // code_length

        // File block header
        let block_size = 12 + num_lines * 8;
        data.extend_from_slice(&0u32.to_le_bytes()); // file_index
        data.extend_from_slice(&num_lines.to_le_bytes());
        data.extend_from_slice(&block_size.to_le_bytes());

        // Line entries
        for &(off, line) in entries {
            data.extend_from_slice(&off.to_le_bytes());
            let flags = line & 0xFF_FFFF; // no end delta, is_statement
            data.extend_from_slice(&flags.to_le_bytes());
        }
        data
    }

    #[test]
    fn test_parse_lines_subsection() {
        let data = make_lines_subsection(0x1000, &[(0, 10), (8, 11), (16, 12)]);
        let ls = parse_lines_subsection(&data).unwrap();
        assert_eq!(ls.code_offset, 0x1000);
        assert_eq!(ls.entries.len(), 3);
        assert_eq!(ls.entries[0].line_start, 10);
        assert_eq!(ls.entries[1].offset, 8);
        assert_eq!(ls.entries[2].line_start, 12);
    }

    #[test]
    fn test_columns_second_file_block_indexed_correctly() {
        // Two file blocks with has_columns: block 1's column data must land on
        // block 1's entries, not overwrite block 0's (regression: global vs
        // block-local index).
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // code_offset
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(&1u16.to_le_bytes()); // flags: has_columns
        data.extend_from_slice(&0x100u32.to_le_bytes()); // code_length
        for (file_index, col_s, col_e) in [(0u32, 1u16, 2u16), (1u32, 7u16, 9u16)] {
            let block_size = 12u32 + 8 + 4; // header + 1 line + 1 column
            data.extend_from_slice(&file_index.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes()); // num_lines
            data.extend_from_slice(&block_size.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes()); // line offset
            data.extend_from_slice(&5u32.to_le_bytes()); // line 5
            data.extend_from_slice(&col_s.to_le_bytes());
            data.extend_from_slice(&col_e.to_le_bytes());
        }
        let ls = parse_lines_subsection(&data).unwrap();
        assert_eq!(ls.entries.len(), 2);
        assert_eq!((ls.entries[0].col_start, ls.entries[0].col_end), (1, 2));
        assert_eq!((ls.entries[1].col_start, ls.entries[1].col_end), (7, 9));
        assert_eq!(ls.entries[1].file_index, 1);
    }

    #[test]
    fn test_block_size_with_trailing_padding_honored() {
        // block_size declares 4 trailing padding bytes after the line entries;
        // the parser must skip them instead of reparsing them as a header, and
        // must correctly parse the following block.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // code_offset
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.extend_from_slice(&0x100u32.to_le_bytes()); // code_length
        // Block 0: 1 line + 4 bytes padding included in block_size
        data.extend_from_slice(&0u32.to_le_bytes()); // file_index
        data.extend_from_slice(&1u32.to_le_bytes()); // num_lines
        data.extend_from_slice(&(12u32 + 8 + 4).to_le_bytes()); // block_size w/ pad
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&10u32.to_le_bytes()); // line 10
        data.extend_from_slice(&[0u8; 4]); // padding
        // Block 1: 1 line, no padding
        data.extend_from_slice(&2u32.to_le_bytes()); // file_index
        data.extend_from_slice(&1u32.to_le_bytes()); // num_lines
        data.extend_from_slice(&(12u32 + 8).to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes()); // line 20
        let ls = parse_lines_subsection(&data).unwrap();
        assert_eq!(ls.entries.len(), 2);
        assert_eq!(ls.entries[0].line_start, 10);
        assert_eq!(ls.entries[1].line_start, 20);
        assert_eq!(ls.entries[1].file_index, 2);
    }

    #[test]
    fn test_parse_lines_has_columns() {
        // Build with has_columns set
        let entries = [(0u32, 5u32)];
        let num_lines = u32::try_from(entries.len()).unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(&1u16.to_le_bytes()); // flags: has_columns
        data.extend_from_slice(&0x80u32.to_le_bytes()); // code_length
        let block_size = 12 + num_lines * 8 + num_lines * 4;
        data.extend_from_slice(&0u32.to_le_bytes()); // file_index
        data.extend_from_slice(&num_lines.to_le_bytes());
        data.extend_from_slice(&block_size.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // offset
        data.extend_from_slice(&5u32.to_le_bytes()); // line 5
        // column entry
        data.extend_from_slice(&3u16.to_le_bytes()); // col_start
        data.extend_from_slice(&10u16.to_le_bytes()); // col_end
        let ls = parse_lines_subsection(&data).unwrap();
        assert!(ls.has_columns);
        assert_eq!(ls.entries[0].col_start, 3);
        assert_eq!(ls.entries[0].col_end, 10);
    }

    #[test]
    fn test_parse_file_checksums() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // name_offset
        data.push(16u8); // checksum len (MD5)
        data.push(1u8); // type MD5
        data.extend_from_slice(&[0xABu8; 16]); // md5
        data.push(0); data.push(0); // padding to 4 bytes: 6+16=22 → 24
        data.push(0); data.push(0);
        let entries = parse_file_checksums(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].checksum_type, 1);
        assert_eq!(entries[0].checksum.len(), 16);
    }

    #[test]
    fn test_split_c13_subsections() {
        let mut stream = Vec::new();
        let payload = b"hello";
        stream.extend_from_slice(&DEBUG_S_STRINGTABLE.to_le_bytes());
        stream.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(payload);
        stream.push(0); stream.push(0); stream.push(0); // padding to 8 (5 bytes → 3 pad)
        let subs = split_c13_subsections(&stream);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].kind, DEBUG_S_STRINGTABLE);
    }

    #[test]
    fn test_line_info_database_lookup() {
        let lines_data = make_lines_subsection(0x1000, &[(0, 42), (4, 43)]);
        // Build a minimal string table and checksum table
        let string_table = b"src/main.c\x00".to_vec();
        let mut chk_data = Vec::new();
        chk_data.extend_from_slice(&0u32.to_le_bytes()); // name_offset=0
        chk_data.push(0u8); // len 0 (no checksum)
        chk_data.push(0u8); // type 0
        chk_data.push(0); chk_data.push(0); // pad

        let subsections = vec![
            C13Subsection { kind: DEBUG_S_STRINGTABLE, data: string_table },
            C13Subsection { kind: DEBUG_S_FILECHKSMS, data: chk_data },
            C13Subsection { kind: DEBUG_S_LINES, data: lines_data },
        ];

        let db = LineInfoDatabase::build(&subsections);
        let loc = db.lookup_offset(0x1000);
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().line, 42);
        assert_eq!(loc.unwrap().file_name, "src/main.c");

        let loc2 = db.lookup_offset(0x1004);
        assert!(loc2.is_some());
        assert_eq!(loc2.unwrap().line, 43);

        // srcToLines
        let by_file = db.lines_for_file("src/main.c");
        assert_eq!(by_file.len(), 2);
    }

    #[test]
    fn test_inline_lines_non_compressed() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // signature=non-compressed
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // inlinee
        data.extend_from_slice(&2u32.to_le_bytes()); // file_index
        data.extend_from_slice(&100u32.to_le_bytes()); // source_line
        let entries = parse_inline_lines(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_line, 100);
        assert_eq!(entries[0].file_index, 2);
    }

    #[test]
    fn test_lookup_missing() {
        let db = LineInfoDatabase {
            by_offset: HashMap::new(),
            src_to_lines: HashMap::new(),
            checksums: vec![],
            string_table: vec![],
        };
        assert!(db.lookup_offset(0x9999).is_none());
        assert!(db.lines_for_file("nonexistent.c").is_empty());
    }
}
