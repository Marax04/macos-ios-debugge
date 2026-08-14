//! `CodeView` line number (`CV8`) tables and source file name tables.
//!
//! Data model for the CV8 (`.debug$S` style) line number sub-sections
//! `DEBUG_S_LINES` (0xF2), `DEBUG_S_FILECHKSMS` (0xF4) and
//! `DEBUG_S_STRINGTABLE` (0xF3).
//!
//! This module defines the table types only; it contains no byte-level parser.
//! To decode a line sub-section from bytes, use
//! [`crate::codeview_parser::parse_line_subsection`] (which also handles the
//! `HaveColumns` flag) or [`crate::parse_cv8_lines`].

use std::fmt;

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// CV8 sub-section kinds
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Cv8SubSection {
    Symbols = 0xF1,
    Lines = 0xF2,
    StringTable = 0xF3,
    FileChecksums = 0xF4,
    FrameData = 0xF5,
    InlineeLines = 0xF6,
    CrossScopeImports = 0xF7,
    CrossScopeExports = 0xF8,
    ILLines = 0xF9,
    FuncMdToken = 0xFA,
    MergeFuncEnds = 0xFB,
    DbgFacilities = 0xFC,
    Unknown(u32),
}

impl Cv8SubSection {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0xF1 => Self::Symbols,
            0xF2 => Self::Lines,
            0xF3 => Self::StringTable,
            0xF4 => Self::FileChecksums,
            0xF5 => Self::FrameData,
            0xF6 => Self::InlineeLines,
            0xF7 => Self::CrossScopeImports,
            0xF8 => Self::CrossScopeExports,
            _ => Self::Unknown(v),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Symbols => "SYMBOLS",
            Self::Lines => "LINES",
            Self::StringTable => "STRINGTABLE",
            Self::FileChecksums => "FILECHKSMS",
            Self::FrameData => "FRAMEDATA",
            Self::InlineeLines => "INLINEE_LINES",
            Self::CrossScopeImports => "CROSSSCOPE_IMPORTS",
            Self::CrossScopeExports => "CROSSSCOPE_EXPORTS",
            _ => "UNKNOWN",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File checksum entry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumKind {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA256 = 3,
}

impl ChecksumKind {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MD5,
            2 => Self::SHA1,
            3 => Self::SHA256,
            _ => Self::None,
        }
    }

    #[must_use]
    pub const fn checksum_size(self) -> usize {
        match self {
            Self::MD5 => 16,
            Self::SHA1 => 20,
            Self::SHA256 => 32,
            Self::None => 0,
        }
    }
}

impl fmt::Display for ChecksumKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::MD5 => "MD5",
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
        };
        f.write_str(s)
    }
}

/// A file checksum entry from the `DEBUG_S_FILECHKSMS` sub-section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChecksum {
    /// Offset into the string table for the file path.
    pub name_offset: u32,
    /// Resolved file name.
    pub name: Option<String>,
    pub kind: ChecksumKind,
    pub checksum: Vec<u8>,
}

impl FileChecksum {
    #[must_use]
    pub fn checksum_hex(&self) -> String {
        self.checksum.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Line number entry
// ─────────────────────────────────────────────────────────────────────────────

/// A single line number entry in a `DEBUG_S_LINES` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cv8LineEntry {
    /// Offset from the start of the contribution.
    pub offset: u32,
    /// 1-based line number (0 = epilogue / no line).
    pub line_start: u32,
    /// End line (0 if not present).
    pub line_end: u32,
    /// Column start (0 if not present).
    pub col_start: u16,
    /// Column end (0 if not present).
    pub col_end: u16,
    /// True if this entry marks a statement (vs. expression).
    pub is_statement: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// File block (lines for one file in a contribution)
// ─────────────────────────────────────────────────────────────────────────────

/// One file's worth of line entries within a `DEBUG_S_LINES` contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cv8FileBlock {
    /// Index into the file checksum table.
    pub file_index: u32,
    /// Resolved file path.
    pub file_name: Option<String>,
    pub entries: Vec<Cv8LineEntry>,
}

impl Cv8FileBlock {
    /// Number of line entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Look up the entry whose offset is nearest to but not exceeding `offset`.
    #[must_use]
    pub fn lookup(&self, offset: u32) -> Option<&Cv8LineEntry> {
        self.entries.iter().rfind(|e| e.offset <= offset)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cv8Contribution
// ─────────────────────────────────────────────────────────────────────────────

/// A single `DEBUG_S_LINES` contribution (one function or chunk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cv8Contribution {
    /// Relocatable segment offset.
    pub offset: u32,
    /// Segment selector.
    pub segment: u16,
    /// Has column information.
    pub has_columns: bool,
    /// Total byte size of the contribution.
    pub code_size: u32,
    /// File blocks within this contribution.
    pub file_blocks: Vec<Cv8FileBlock>,
}

impl Cv8Contribution {
    /// Resolve the source location (file, line) for a given code offset.
    #[must_use]
    pub fn resolve(&self, offset: u32) -> Option<(Option<&str>, u32)> {
        let local = offset.checked_sub(self.offset)?;
        for block in &self.file_blocks {
            if let Some(entry) = block.lookup(local) {
                return Some((block.file_name.as_deref(), entry.line_start));
            }
        }
        None
    }

    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.file_blocks.iter().map(Cv8FileBlock::entry_count).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cv8LineTable
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated CV8 line number information.
#[derive(Debug, Default)]
pub struct Cv8LineTable {
    pub contributions: Vec<Cv8Contribution>,
    pub checksums: Vec<FileChecksum>,
    pub string_table: Vec<u8>,
}

impl Cv8LineTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a string from the string table at the given offset.
    #[must_use]
    pub fn resolve_string(&self, offset: u32) -> Option<String> {
        let start = offset as usize;
        if start >= self.string_table.len() {
            return None;
        }
        let end = self.string_table[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.string_table.len(), |p| start + p);
        String::from_utf8(self.string_table[start..end].to_vec()).ok()
    }

    /// Resolve a file checksum entry by index.
    #[must_use]
    pub fn file_name(&self, idx: u32) -> Option<&str> {
        self.checksums.get(idx as usize)?.name.as_deref()
    }

    /// Look up source location for a given offset.
    #[must_use]
    pub fn resolve_location(&self, seg: u16, offset: u32) -> Option<(&str, u32)> {
        for contrib in &self.contributions {
            if contrib.segment == seg && offset >= contrib.offset && offset < contrib.offset + contrib.code_size && let Some((file, line)) = contrib.resolve(offset) {
                return Some((file.unwrap_or("(unknown)"), line));
            }
        }
        None
    }

    /// Number of contributions.
    #[must_use]
    pub const fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Total line entries across all contributions.
    #[must_use]
    pub fn total_line_entries(&self) -> usize {
        self.contributions.iter().map(Cv8Contribution::total_lines).sum()
    }

    /// All unique source files referenced.
    #[must_use]
    pub fn source_files(&self) -> Vec<&str> {
        let mut files: Vec<&str> = self
            .checksums
            .iter()
            .filter_map(|c| c.name.as_deref())
            .collect();
        files.sort_unstable();
        files.dedup();
        files
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(offset: u32, line: u32) -> Cv8LineEntry {
        Cv8LineEntry {
            offset,
            line_start: line,
            line_end: 0,
            col_start: 0,
            col_end: 0,
            is_statement: true,
        }
    }

    fn make_file_block(file_idx: u32, entries: Vec<Cv8LineEntry>) -> Cv8FileBlock {
        Cv8FileBlock {
            file_index: file_idx,
            file_name: Some(format!("file{file_idx}.cpp")),
            entries,
        }
    }

    fn make_contrib(offset: u32, size: u32, blocks: Vec<Cv8FileBlock>) -> Cv8Contribution {
        Cv8Contribution {
            offset,
            segment: 1,
            has_columns: false,
            code_size: size,
            file_blocks: blocks,
        }
    }

    // --- Cv8SubSection ---

    #[test]
    fn subsection_from_u32_lines() {
        assert_eq!(Cv8SubSection::from_u32(0xF2), Cv8SubSection::Lines);
    }

    #[test]
    fn subsection_name_lines() {
        assert_eq!(Cv8SubSection::Lines.name(), "LINES");
    }

    #[test]
    fn subsection_unknown() {
        let s = Cv8SubSection::from_u32(0x999);
        assert_eq!(s.name(), "UNKNOWN");
    }

    // --- ChecksumKind ---

    #[test]
    fn checksum_kind_from_u8() {
        assert_eq!(ChecksumKind::from_u8(1), ChecksumKind::MD5);
        assert_eq!(ChecksumKind::from_u8(99), ChecksumKind::None);
    }

    #[test]
    fn checksum_md5_size() {
        assert_eq!(ChecksumKind::MD5.checksum_size(), 16);
    }

    #[test]
    fn checksum_display() {
        assert_eq!(format!("{}", ChecksumKind::SHA256), "SHA256");
    }

    // --- FileChecksum ---

    #[test]
    fn file_checksum_hex() {
        let fc = FileChecksum {
            name_offset: 0,
            name: Some("foo.cpp".into()),
            kind: ChecksumKind::MD5,
            checksum: vec![0xde, 0xad],
        };
        assert_eq!(fc.checksum_hex(), "dead");
    }

    // --- Cv8FileBlock ---

    #[test]
    fn file_block_lookup_exact() {
        let block = make_file_block(0, vec![make_entry(0, 10), make_entry(8, 11)]);
        assert_eq!(block.lookup(0).unwrap().line_start, 10);
    }

    #[test]
    fn file_block_lookup_nearest() {
        let block = make_file_block(0, vec![make_entry(0, 5), make_entry(8, 6)]);
        assert_eq!(block.lookup(4).unwrap().line_start, 5);
    }

    #[test]
    fn file_block_lookup_none() {
        let block = make_file_block(0, vec![make_entry(10, 1)]);
        assert!(block.lookup(5).is_none());
    }

    #[test]
    fn file_block_entry_count() {
        let block = make_file_block(0, vec![make_entry(0, 1), make_entry(4, 2)]);
        assert_eq!(block.entry_count(), 2);
    }

    // --- Cv8Contribution ---

    #[test]
    fn contrib_resolve_basic() {
        let block = make_file_block(0, vec![make_entry(0, 10), make_entry(4, 11)]);
        let contrib = make_contrib(0x1000, 0x20, vec![block]);
        let result = contrib.resolve(0x1004);
        assert!(result.is_some());
        let (_, line) = result.unwrap();
        assert_eq!(line, 11);
    }

    #[test]
    fn contrib_resolve_before_start() {
        let block = make_file_block(0, vec![make_entry(0, 1)]);
        let contrib = make_contrib(0x1000, 0x20, vec![block]);
        assert!(contrib.resolve(0x0ff0).is_none()); // Below offset
    }

    #[test]
    fn contrib_total_lines() {
        let b1 = make_file_block(0, vec![make_entry(0, 1), make_entry(4, 2)]);
        let b2 = make_file_block(1, vec![make_entry(8, 3)]);
        let c = make_contrib(0, 100, vec![b1, b2]);
        assert_eq!(c.total_lines(), 3);
    }

    // --- Cv8LineTable ---

    #[test]
    fn line_table_resolve_string() {
        let mut t = Cv8LineTable::new();
        t.string_table = b"hello\0world\0".to_vec();
        assert_eq!(t.resolve_string(0), Some("hello".into()));
        assert_eq!(t.resolve_string(6), Some("world".into()));
    }

    #[test]
    fn line_table_resolve_string_out_of_bounds() {
        let t = Cv8LineTable::new();
        assert!(t.resolve_string(999).is_none());
    }

    #[test]
    fn line_table_file_name() {
        let mut t = Cv8LineTable::new();
        t.checksums.push(FileChecksum {
            name_offset: 0,
            name: Some("main.cpp".into()),
            kind: ChecksumKind::None,
            checksum: vec![],
        });
        assert_eq!(t.file_name(0), Some("main.cpp"));
    }

    #[test]
    fn line_table_contribution_count() {
        let mut t = Cv8LineTable::new();
        t.contributions.push(make_contrib(0, 100, vec![]));
        t.contributions.push(make_contrib(100, 100, vec![]));
        assert_eq!(t.contribution_count(), 2);
    }

    #[test]
    fn line_table_total_line_entries() {
        let mut t = Cv8LineTable::new();
        let b = make_file_block(0, vec![make_entry(0, 1), make_entry(4, 2)]);
        t.contributions.push(make_contrib(0, 100, vec![b]));
        assert_eq!(t.total_line_entries(), 2);
    }

    #[test]
    fn line_table_source_files() {
        let mut t = Cv8LineTable::new();
        t.checksums.push(FileChecksum {
            name_offset: 0,
            name: Some("a.cpp".into()),
            kind: ChecksumKind::None,
            checksum: vec![],
        });
        t.checksums.push(FileChecksum {
            name_offset: 0,
            name: Some("b.cpp".into()),
            kind: ChecksumKind::None,
            checksum: vec![],
        });
        let files = t.source_files();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn line_table_resolve_location() {
        let mut t = Cv8LineTable::new();
        let b = make_file_block(0, vec![make_entry(0, 42)]);
        t.contributions.push(make_contrib(0x1000, 0x100, vec![b]));
        let result = t.resolve_location(1, 0x1000);
        assert!(result.is_some());
        let (_, line) = result.unwrap();
        assert_eq!(line, 42);
    }
}
