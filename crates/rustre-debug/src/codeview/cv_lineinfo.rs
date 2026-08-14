//! `CodeView` line number (`CV8`) tables and source file name tables.
//!
//! Parses the CV8 (`.debug$S` style) line number sub-sections:
//! `DEBUG_S_LINES` (0xF2) and `DEBUG_S_FILECHKSMS` (0xF4) / `DEBUG_S_STRINGTABLE` (0xF3).
//!
//! # Status: no external caller found (as of 2026-07-21)
//!
//! Grepping the crate and `rustre-mcp-tools` finds no use of anything
//! defined here outside this file's own `#[cfg(test)]` module. See
//! `ENHANCEMENT_LOG.md` iters 230/232/233.

use std::fmt;

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// CV8 sub-section kinds
// ─────────────────────────────────────────────────────────────────────────────

/// CV8 (`.debug$S`) sub-section kind (`DEBUG_S_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Cv8SubSection {
    /// `DEBUG_S_SYMBOLS` — symbol records.
    Symbols = 0xF1,
    /// `DEBUG_S_LINES` — line number tables.
    Lines = 0xF2,
    /// `DEBUG_S_STRINGTABLE` — string table for file names.
    StringTable = 0xF3,
    /// `DEBUG_S_FILECHKSMS` — source file checksums.
    FileChecksums = 0xF4,
    /// `DEBUG_S_FRAMEDATA` — frame data (FPO) records.
    FrameData = 0xF5,
    /// `DEBUG_S_INLINEELINES` — inlinee source line records.
    InlineeLines = 0xF6,
    /// `DEBUG_S_CROSSSCOPEIMPORTS` — cross-scope import references.
    CrossScopeImports = 0xF7,
    /// `DEBUG_S_CROSSSCOPEEXPORTS` — cross-scope export references.
    CrossScopeExports = 0xF8,
    /// `DEBUG_S_IL_LINES` — managed IL line tables.
    ILLines = 0xF9,
    /// `DEBUG_S_FUNC_MDTOKEN_MAP` — function-to-metadata-token map.
    FuncMdToken = 0xFA,
    /// `DEBUG_S_TYPE_MDTOKEN_MAP` / merged-function-ends section.
    MergeFuncEnds = 0xFB,
    /// Debugger facilities section.
    DbgFacilities = 0xFC,
    /// Any unrecognized sub-section kind.
    Unknown(u32),
}

impl Cv8SubSection {
    /// Decode a sub-section kind from its raw `u32` value.
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

    /// Short uppercase name of the sub-section kind.
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

/// Hash algorithm used for a source-file checksum entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumKind {
    /// No checksum present.
    None = 0,
    /// MD5 (16 bytes).
    MD5 = 1,
    /// SHA-1 (20 bytes).
    SHA1 = 2,
    /// SHA-256 (32 bytes).
    SHA256 = 3,
}

impl ChecksumKind {
    /// Decode a checksum kind from its raw byte value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MD5,
            2 => Self::SHA1,
            3 => Self::SHA256,
            _ => Self::None,
        }
    }

    /// Digest length in bytes for this checksum kind.
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
    /// Hash algorithm of the checksum.
    pub kind: ChecksumKind,
    /// Raw checksum digest bytes.
    pub checksum: Vec<u8>,
}

impl FileChecksum {
    /// The checksum digest as a lowercase hex string.
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
    /// Line entries for this file, in code-offset order.
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
    ///
    /// `None` when `offset` is outside this contribution. Two things used to
    /// make that answer wrong rather than absent:
    ///
    /// 1. **`code_size` was never consulted.** Any offset at or after the start
    ///    produced a hit, so an address in the NEXT function — or in padding,
    ///    or anywhere higher in the image — came back with this function's file
    ///    and line, stated as fact. The bound was sitting in the struct; the
    ///    same defect as `source_map::addr_to_source` in iteration 451, except
    ///    that here the exact extent is known and simply was not read.
    /// 2. **The first file block that had any preceding entry won.** A
    ///    contribution has one block per source file (inlined code), and
    ///    `rfind` on block 0 succeeds for nearly every offset — so offsets
    ///    belonging to block 1 were attributed to block 0's file. The right
    ///    block is the one whose nearest preceding entry is the CLOSEST to the
    ///    offset, across all of them.
    ///
    /// A `code_size` of 0 means the record did not say how far the
    /// contribution reaches: only the exact start resolves, rather than
    /// everything above it.
    #[must_use]
    pub fn resolve(&self, offset: u32) -> Option<(Option<&str>, u32)> {
        let local = offset.checked_sub(self.offset)?;
        if self.code_size == 0 {
            if local != 0 {
                return None;
            }
        } else if local >= self.code_size {
            return None;
        }
        self.file_blocks
            .iter()
            .filter_map(|block| block.lookup(local).map(|entry| (block, entry)))
            .max_by_key(|(_, entry)| entry.offset)
            .map(|(block, entry)| (block.file_name.as_deref(), entry.line_start))
    }

    /// Total number of line entries across all file blocks.
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
    /// All `DEBUG_S_LINES` contributions parsed so far.
    pub contributions: Vec<Cv8Contribution>,
    /// File checksum entries from `DEBUG_S_FILECHKSMS`.
    pub checksums: Vec<FileChecksum>,
    /// Raw `DEBUG_S_STRINGTABLE` bytes (null-terminated strings).
    pub string_table: Vec<u8>,
}

impl Cv8LineTable {
    /// Create an empty line table.
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

    /// An offset past the end of a contribution has NO source location.
    ///
    /// `code_size` was never consulted, so any offset at or after the start
    /// produced a hit: an address in the next function, or in padding, came
    /// back with this function file and line, stated as fact. The bound was in
    /// the struct all along.
    #[test]
    fn an_offset_past_the_contribution_has_no_location() {
        let contrib = Cv8Contribution {
            offset: 0x1000,
            segment: 1,
            has_columns: false,
            code_size: 0x40,
            file_blocks: vec![make_file_block(0, vec![make_entry(0, 10), make_entry(0x20, 11)])],
        };

        assert_eq!(contrib.resolve(0x1000).map(|(_, l)| l), Some(10));
        assert_eq!(contrib.resolve(0x1030).map(|(_, l)| l), Some(11));
        // The last byte covered.
        assert_eq!(contrib.resolve(0x103F).map(|(_, l)| l), Some(11));
        // One past the end: a different function starts here.
        assert!(
            contrib.resolve(0x1040).is_none(),
            "an offset past code_size belongs to other code and must not borrow this line"
        );
        assert!(contrib.resolve(0x9999).is_none());
        // Below the start is already refused by the subtraction.
        assert!(contrib.resolve(0x0FFF).is_none());
    }

    /// With several file blocks, the block whose entry is CLOSEST to the
    /// offset wins — not simply the first one that has any earlier entry.
    ///
    /// A contribution has one block per source file (inlined code), and
    /// `rfind` on block 0 succeeds for nearly every offset, so offsets
    /// belonging to block 1 were attributed to block 0 file.
    #[test]
    fn the_nearest_file_block_wins_not_the_first_one() {
        let contrib = Cv8Contribution {
            offset: 0,
            segment: 1,
            has_columns: false,
            code_size: 0x100,
            file_blocks: vec![
                make_file_block(0, vec![make_entry(0x00, 100)]),
                make_file_block(1, vec![make_entry(0x80, 200)]),
            ],
        };

        // Before the inlined block: the outer file.
        let (file, line) = contrib.resolve(0x10).expect("covered");
        assert_eq!(file, Some("file0.cpp"));
        assert_eq!(line, 100);

        // Inside the inlined block: the inlined file, not the outer one.
        let (file, line) = contrib.resolve(0x90).expect("covered");
        assert_eq!(
            file,
            Some("file1.cpp"),
            "the offset falls in the second block; attributing it to the first names the wrong file"
        );
        assert_eq!(line, 200);
    }

}
