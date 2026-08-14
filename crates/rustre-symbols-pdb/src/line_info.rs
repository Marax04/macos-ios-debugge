//! `line_info` — source file and line number information.
//!
//! Parses the C13 line-number sub-sections embedded in each module's symbol
//! stream.  The C13 format stores a header followed by file checksum and
//! line-number blocks.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::stream_reader::StreamReader;

// ── LineRecord ────────────────────────────────────────────────────────────────

/// One source-line mapping: a code address maps to a specific file/line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRecord {
    /// Relative virtual address (`RVA`) of the code covered by this record.
    pub address: u64,
    /// Source file path.
    pub file: String,
    /// 1-based source line number.
    pub line: u32,
    /// Column number (if present in the debug info).
    pub column: Option<u32>,
    /// True when this record marks the beginning of a statement.
    pub is_statement: bool,
}

impl LineRecord {
    /// True when this record has valid column information.
    #[must_use]
    pub const fn has_column(&self) -> bool {
        self.column.is_some()
    }
}

// ── LineInfo ──────────────────────────────────────────────────────────────────

/// All recovered line records for a module, indexed by `RVA`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineInfo {
    /// Sorted by `address` for binary-search lookup.
    records: Vec<LineRecord>,
}

impl LineInfo {
    /// Create an empty line table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a record (records are sorted on first `finalize` call).
    pub fn push(&mut self, rec: LineRecord) {
        self.records.push(rec);
    }

    /// Sort records by address for efficient lookup.  Must be called after all
    /// records are inserted.
    pub fn finalize(&mut self) {
        self.records.sort_by_key(|r| r.address);
        self.records.dedup_by_key(|r| r.address);
    }

    /// Find the line record covering `rva` using binary search.
    #[must_use]
    pub fn lookup_line(&self, rva: u64) -> Option<&LineRecord> {
        let idx = self.records.partition_point(|r| r.address <= rva);
        if idx == 0 {
            return None;
        }
        self.records.get(idx - 1)
    }

    /// Return all records.
    #[must_use]
    pub fn records(&self) -> &[LineRecord] {
        &self.records
    }

    /// Number of line records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// True when there are no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Build a map from source file to line numbers.
    #[must_use]
    pub fn by_file(&self) -> BTreeMap<String, Vec<u32>> {
        let mut map: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for rec in &self.records {
            map.entry(rec.file.clone()).or_default().push(rec.line);
        }
        for lines in map.values_mut() {
            lines.sort_unstable();
            lines.dedup();
        }
        map
    }
}

// ── C13 line sub-section parsing ──────────────────────────────────────────────

/// C13 debug sub-section types.
const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;

/// Parse the C13 line information embedded in a module's symbol stream.
///
/// The stream may contain multiple sub-sections; we collect all LINE sub-sections
/// and correlate them with the FILECHKSMS sub-section for file names.
///
/// # Errors
/// Returns an error if parsing/reading fails.
pub fn parse_line_info(
    module_stream: &[u8],
    string_table: &crate::stream_reader::StringTable,
) -> Result<LineInfo> {
    let mut info = LineInfo::new();

    // File checksum table: `offset_in_stream → file_name_offset_in_string_table`
    let mut file_names: Vec<String> = Vec::new();

    let mut rdr = StreamReader::new(module_stream);

    // Skip the symbol bytes — they are terminated by a zero-length record or a
    // specific terminator.  We scan for the C13 sub-sections that follow.
    // In practice the module stream layout is:
    //   symbols | padding | [C13 subsections]
    // We scan for the DEBUG_S_* magic values rather than parsing the symbol
    // length, since we don't have the DBI header with the exact symbol byte count.
    parse_c13_subsections(&mut rdr, string_table, &mut file_names, &mut info)?;

    info.finalize();
    Ok(info)
}

fn parse_c13_subsections(
    rdr: &mut StreamReader<'_>,
    string_table: &crate::stream_reader::StringTable,
    file_names: &mut Vec<String>,
    info: &mut LineInfo,
) -> Result<()> {
    // Scan the stream for C13 debug sub-section signatures.
    // Sub-section layout: u32 kind | u32 length | <data>
    while rdr.remaining() >= 8 {
        let kind = rdr.read_u32()?;
        let length = rdr.read_u32()? as usize;

        if rdr.remaining() < length {
            break;
        }

        let start = rdr.pos();

        match kind {
            DEBUG_S_FILECHKSMS => {
                // File checksum records: each is 8+ bytes.
                // offset_in_names(4) + hash_len(1) + hash_type(1) + hash[hash_len] + align
                let end = start + length;
                while rdr.pos() + 8 <= end {
                    let name_off = rdr.read_u32()?;
                    let hash_len = rdr.read_u8()?;
                    let _hash_type = rdr.read_u8()?;
                    // Skip hash bytes.
                    let _ = rdr.skip(hash_len as usize);
                    rdr.align(4);

                    let name = string_table
                        .get(name_off)
                        .unwrap_or("<unknown>")
                        .to_string();
                    file_names.push(name);
                }
            }
            DEBUG_S_LINES => {
                // Lines section:
                // offset(4) + segment(2) + flags(2) + code_size(4)
                // Followed by one or more file blocks:
                //   file_index(4) + num_lines(4) + block_size(4)
                //   Then `num_lines` line entries: offset(4) + line_start(24b) + delta_end(7b) + is_statement(1b)
                let section_end = start + length;
                if rdr.remaining() < 12 {
                    rdr.seek(section_end);
                    continue;
                }
                let code_offset = rdr.read_u32()?;
                let _segment = rdr.read_u16()?;
                let flags = rdr.read_u16()?;
                let _code_size = rdr.read_u32()?;
                let has_columns = (flags & 0x0001) != 0;

                while rdr.pos() + 12 <= section_end {
                    let file_index = rdr.read_u32()? as usize;
                    let num_lines = rdr.read_u32()? as usize;
                    let _block_size = rdr.read_u32()?;

                    for _ in 0..num_lines {
                        if rdr.remaining() < 8 {
                            break;
                        }
                        let offset = rdr.read_u32()?;
                        let line_flags = rdr.read_u32()?;
                        let line_start = line_flags & 0x00FF_FFFF;
                        let _ = (line_flags >> 24) & 0x7F; // delta_end unused
                        let is_statement = (line_flags >> 31) & 0x1 == 1;

                        let column = if has_columns && rdr.remaining() >= 4 {
                            let start_col = rdr.read_u16()?;
                            let _end_col = rdr.read_u16()?;
                            Some(u32::from(start_col))
                        } else {
                            None
                        };

                        let file = file_names
                            .get(file_index)
                            .cloned()
                            .unwrap_or_else(|| format!("<file_{file_index}>"));

                        info.push(LineRecord {
                            address: u64::from(code_offset) + u64::from(offset),
                            file,
                            line: line_start,
                            column,
                            is_statement,
                        });
                    }
                }
                rdr.seek(section_end);
            }
            _ => {
                // Unknown or uninteresting sub-section; skip.
                rdr.seek(start + length);
            }
        }

        // Align to 4-byte boundary.
        rdr.align(4);
    }

    Ok(())
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Look up the line record with the highest address ≤ `rva` in `records`.
#[must_use]
pub fn lookup_line(records: &[LineRecord], rva: u64) -> Option<&LineRecord> {
    let idx = records.partition_point(|r| r.address <= rva);
    if idx == 0 { None } else { records.get(idx - 1) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_records() -> Vec<LineRecord> {
        vec![
            LineRecord {
                address: 0x1000,
                file: "main.c".into(),
                line: 10,
                column: None,
                is_statement: true,
            },
            LineRecord {
                address: 0x1010,
                file: "main.c".into(),
                line: 11,
                column: None,
                is_statement: true,
            },
            LineRecord {
                address: 0x1020,
                file: "main.c".into(),
                line: 12,
                column: Some(4),
                is_statement: false,
            },
        ]
    }

    #[test]
    fn test_lookup_line_exact() {
        let records = make_records();
        let r = lookup_line(&records, 0x1000).unwrap();
        assert_eq!(r.line, 10);
    }

    #[test]
    fn test_lookup_line_between() {
        let records = make_records();
        let r = lookup_line(&records, 0x1008).unwrap();
        assert_eq!(r.line, 10); // nearest lower
    }

    #[test]
    fn test_lookup_line_above_all() {
        let records = make_records();
        let r = lookup_line(&records, 0x2000).unwrap();
        assert_eq!(r.line, 12);
    }

    #[test]
    fn test_lookup_line_below_all() {
        let records = make_records();
        assert!(lookup_line(&records, 0x0FFF).is_none());
    }

    #[test]
    fn test_line_info_finalize_sorts() {
        let mut info = LineInfo::new();
        info.push(LineRecord {
            address: 0x1020,
            file: "f.c".into(),
            line: 3,
            column: None,
            is_statement: true,
        });
        info.push(LineRecord {
            address: 0x1000,
            file: "f.c".into(),
            line: 1,
            column: None,
            is_statement: true,
        });
        info.finalize();
        assert_eq!(info.records()[0].address, 0x1000);
        assert_eq!(info.records()[1].address, 0x1020);
    }

    #[test]
    fn test_line_info_dedup() {
        let mut info = LineInfo::new();
        info.push(LineRecord {
            address: 0x1000,
            file: "f.c".into(),
            line: 1,
            column: None,
            is_statement: true,
        });
        info.push(LineRecord {
            address: 0x1000,
            file: "f.c".into(),
            line: 1,
            column: None,
            is_statement: true,
        });
        info.finalize();
        assert_eq!(info.len(), 1);
    }

    #[test]
    fn test_line_info_lookup() {
        let mut info = LineInfo::new();
        for rec in make_records() {
            info.push(rec);
        }
        info.finalize();
        let r = info.lookup_line(0x1018).unwrap();
        assert_eq!(r.line, 11);
    }

    #[test]
    fn test_by_file() {
        let mut info = LineInfo::new();
        info.push(LineRecord {
            address: 0x1000,
            file: "a.c".into(),
            line: 5,
            column: None,
            is_statement: true,
        });
        info.push(LineRecord {
            address: 0x1010,
            file: "b.c".into(),
            line: 10,
            column: None,
            is_statement: true,
        });
        info.push(LineRecord {
            address: 0x1020,
            file: "a.c".into(),
            line: 7,
            column: None,
            is_statement: true,
        });
        info.finalize();
        let by = info.by_file();
        assert_eq!(by["a.c"], vec![5, 7]);
        assert_eq!(by["b.c"], vec![10]);
    }

    #[test]
    fn test_has_column() {
        let r = LineRecord {
            address: 0,
            file: "x.c".into(),
            line: 1,
            column: Some(4),
            is_statement: true,
        };
        assert!(r.has_column());
        let r2 = LineRecord { column: None, ..r };
        assert!(!r2.has_column());
    }

    #[test]
    fn test_empty_line_info() {
        let info = LineInfo::new();
        assert!(info.is_empty());
        assert!(info.lookup_line(0x1000).is_none());
    }

    #[test]
    fn test_parse_line_info_empty_stream() {
        let st = crate::stream_reader::StringTable::new();
        let li = parse_line_info(&[], &st).unwrap();
        assert!(li.is_empty());
    }
}
