//! `cv_stream_parser` — Parse all `CodeView` debug streams from a `PDB` or `PE` binary.
//!
//! Handles `NB10`/`NB11`/`RSDS` `PDB` signatures, `S_*` symbol records,
//! `LF_*` type records, `CV8` `.debug$S` source-line info subsections,
//! section header debug data, source-file maps, and line-info extraction.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`CvStreamParser`] | Top-level parser that dispatches to sub-parsers |
//! | [`CvPdbSignature`] | NB10 / NB11 / RSDS PDB header signatures |
//! | [`CvSymbolStream`] | Parsed S_* symbol records from a symbol stream |
//! | [`CvTypeStream`] | Parsed LF_* type records from a TPI/IPI stream |
//! | [`CvSrcModStream`] | Source-module line-number info |
//! | [`CvSectionHeaders`] | Section-contribution headers from `.debug$S` |
//! | [`LineInfo`] | Resolved address → (file, line) mapping |
//! | [`SourceFileMap`] | All source files referenced by a binary |


use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    CodeViewError, CvSourceFile, CvStringTable, CvSymbol, CvTypeKind, CvTypeRecord,
    parse_cv_symbols, parse_cv_type_records, read_u16, read_u32,
};

pub use crate::{CvLineEntry, CvSymKind};
pub use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// CvPdbSignature
// ─────────────────────────────────────────────────────────────────────────────

/// A recognised PDB header signature block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvPdbSignature {
    /// NB10 — old PDB 2.0 format (`NB10` + offset).
    Nb10 {
        /// Byte offset to the PDB header within the CV stream.
        offset: u32,
        /// Timestamp from the linker.
        timestamp: u32,
        /// Incremental build age.
        age: u32,
        /// Path to the PDB file.
        pdb_path: String,
    },
    /// `NB11` — `PDB` 7.0 / `CodeView` 5.0 (`NB11`).
    Nb11 {
        offset: u32,
        timestamp: u32,
        age: u32,
        pdb_path: String,
    },
    /// RSDS — PDB 7.0 with GUID (`RSDS`).
    Rsds {
        /// 16-byte GUID formatted as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
        guid: String,
        /// Incremental build age.
        age: u32,
        /// Path to the PDB file.
        pdb_path: String,
    },
    /// Unknown magic — raw bytes preserved.
    Unknown { magic: [u8; 4] },
}

impl CvPdbSignature {
    /// Attempt to parse a PDB signature block from `data`.
    ///
    /// Returns `None` if `data` is too short to contain any known signature.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        match &data[..4] {
            b"NB10" => Some(Self::parse_nb10(data)),
            b"NB11" => Some(Self::parse_nb11(data)),
            b"RSDS" => Some(Self::parse_rsds(data)),
            other => {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(other);
                Some(Self::Unknown { magic })
            }
        }
    }

    fn parse_nb10(data: &[u8]) -> Self {
        let offset = read_u32(data, 4);
        let timestamp = read_u32(data, 8);
        let age = read_u32(data, 12);
        let pdb_path = read_null_str(data, 16);
        Self::Nb10 {
            offset,
            timestamp,
            age,
            pdb_path,
        }
    }

    fn parse_nb11(data: &[u8]) -> Self {
        let offset = read_u32(data, 4);
        let timestamp = read_u32(data, 8);
        let age = read_u32(data, 12);
        let pdb_path = read_null_str(data, 16);
        Self::Nb11 {
            offset,
            timestamp,
            age,
            pdb_path,
        }
    }

    fn parse_rsds(data: &[u8]) -> Self {
        if data.len() < 24 {
            return Self::Rsds {
                guid: String::new(),
                age: 0,
                pdb_path: String::new(),
            };
        }
        let guid = format_guid(&data[4..20]);
        let age = read_u32(data, 20);
        let pdb_path = read_null_str(data, 24);
        Self::Rsds {
            guid,
            age,
            pdb_path,
        }
    }

    /// Return the PDB file path embedded in the signature, if any.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        match self {
            Self::Nb10 { pdb_path, .. }
            | Self::Nb11 { pdb_path, .. }
            | Self::Rsds { pdb_path, .. } => Some(pdb_path),
            Self::Unknown { .. } => None,
        }
    }

    /// Return the build age, if applicable.
    #[must_use]
    pub const fn age(&self) -> Option<u32> {
        match self {
            Self::Nb10 { age, .. }
            | Self::Nb11 { age, .. }
            | Self::Rsds { age, .. } => Some(*age),
            Self::Unknown { .. } => None,
        }
    }

    /// Return the GUID string (RSDS only).
    #[must_use]
    pub fn guid(&self) -> Option<&str> {
        if let Self::Rsds { guid, .. } = self {
            Some(guid)
        } else {
            None
        }
    }

    /// Human-readable variant label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Nb10 { .. } => "NB10 (PDB 2.0)",
            Self::Nb11 { .. } => "NB11 (CV 5.0/7.0)",
            Self::Rsds { .. } => "RSDS (PDB 7.0)",
            Self::Unknown { .. } => "Unknown",
        }
    }
}

impl fmt::Display for CvPdbSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())?;
        if let Some(path) = self.pdb_path() {
            write!(f, " '{path}'")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvSymbolStream
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `S_*` symbol records from a `CodeView` symbol stream (e.g. `PDB` symbols).
///
/// Note: distinct from the `CvSymbolStream<'a>` iterator defined in `lib.rs`.
#[derive(Debug, Default, Clone)]
pub struct CvParsedSymbolStream {
    /// All parsed symbol records.
    pub symbols: Vec<CvSymbol>,
    /// Byte length of the stream that was parsed.
    pub stream_len: usize,
    /// Count of records that could not be parsed (malformed).
    pub error_count: usize,
}

impl CvParsedSymbolStream {
    /// Parse a raw symbol stream buffer.
    ///
    /// # Errors
    /// Returns [`CodeViewError`] on truncated records.
    pub fn parse(data: &[u8]) -> Result<Self, CodeViewError> {
        let symbols = parse_cv_symbols(data)?;
        Ok(Self {
            stream_len: data.len(),
            error_count: 0,
            symbols,
        })
    }

    /// Number of function records.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.symbols
            .iter()
            .filter(|s| s.kind.is_function() || matches!(s.kind, crate::CvSymKind::Pub32))
            .count()
    }

    /// Number of data records.
    #[must_use]
    pub fn data_count(&self) -> usize {
        self.symbols.iter().filter(|s| s.kind.is_data()).count()
    }

    /// Find a symbol by name (case-sensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&CvSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Find all symbols whose names contain `substr`.
    #[must_use]
    pub fn search(&self, substr: &str) -> Vec<&CvSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name.contains(substr))
            .collect()
    }

    /// All symbols in segment-offset order.
    #[must_use]
    pub fn sorted_by_offset(&self) -> Vec<&CvSymbol> {
        let mut v: Vec<&CvSymbol> = self.symbols.iter().collect();
        v.sort_by_key(|s| (s.segment, s.offset));
        v
    }

    /// All symbols belonging to a specific section segment.
    #[must_use]
    pub fn in_segment(&self, seg: u16) -> Vec<&CvSymbol> {
        self.symbols.iter().filter(|s| s.segment == seg).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvTypeStream
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `LF_*` type records from a `CodeView` `TPI`/`IPI` stream.
#[derive(Debug, Default, Clone)]
pub struct CvTypeStream {
    /// All parsed type records.
    pub records: Vec<CvTypeRecord>,
    /// Index of first type (TPI streams start at 0x1000).
    pub first_index: u32,
    /// Byte length of the stream that was parsed.
    pub stream_len: usize,
}

impl CvTypeStream {
    /// Parse a raw TPI stream buffer.
    ///
    /// # Errors
    /// Returns [`CodeViewError`] on truncated records.
    pub fn parse(data: &[u8]) -> Result<Self, CodeViewError> {
        let records = parse_cv_type_records(data)?;
        let first_index = records.first().map_or(0x1000, |r| r.index);
        Ok(Self {
            records,
            first_index,
            stream_len: data.len(),
        })
    }

    /// Look up a type record by TPI index.
    #[must_use]
    pub fn lookup(&self, index: u32) -> Option<&CvTypeRecord> {
        if index < self.first_index {
            return None;
        }
        let offset = (index - self.first_index) as usize;
        self.records.get(offset)
    }

    /// All aggregate types (class, struct, union).
    #[must_use]
    pub fn aggregates(&self) -> Vec<&CvTypeRecord> {
        self.records.iter().filter(|r| r.is_aggregate()).collect()
    }

    /// All callable types (procedure, member function).
    #[must_use]
    pub fn callables(&self) -> Vec<&CvTypeRecord> {
        self.records.iter().filter(|r| r.is_callable()).collect()
    }

    /// Find type records by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&CvTypeRecord> {
        self.records.iter().filter(|r| r.name == name).collect()
    }

    /// Number of aggregate records.
    #[must_use]
    pub fn aggregate_count(&self) -> usize {
        self.aggregates().len()
    }

    /// Number of enum records.
    #[must_use]
    pub fn enum_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.kind == CvTypeKind::Enum)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LineInfo
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved source-line mapping: virtual address → (file path, line number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineInfo {
    /// Virtual address of the instruction.
    pub va: u64,
    /// Absolute path of the source file.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 0-based column (if known; 0 otherwise).
    pub column: u32,
    /// Whether this address is a statement boundary.
    pub is_statement: bool,
}

impl LineInfo {
    /// Construct a line-info record.
    #[must_use]
    pub fn new(va: u64, file: impl Into<String>, line: u32, is_statement: bool) -> Self {
        Self {
            va,
            file: file.into(),
            line,
            column: 0,
            is_statement,
        }
    }
}

impl fmt::Display for LineInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}  {}:{}", self.va, self.file, self.line)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvSrcModStream
// ─────────────────────────────────────────────────────────────────────────────

/// Source-module line-number info extracted from `CodeView` `CV8` line data.
#[derive(Debug, Default, Clone)]
pub struct CvSrcModStream {
    /// Ordered list of line-info records.
    pub line_infos: Vec<LineInfo>,
    /// All source files referenced.
    pub files: Vec<CvSourceFile>,
}

impl CvSrcModStream {
    /// Build from pre-parsed line-info records and file list.
    #[must_use]
    pub const fn new(line_infos: Vec<LineInfo>, files: Vec<CvSourceFile>) -> Self {
        Self { line_infos, files }
    }

    /// Find the nearest [`LineInfo`] entry at or before `va`.
    #[must_use]
    pub fn lookup_va(&self, va: u64) -> Option<&LineInfo> {
        self.line_infos
            .iter()
            .filter(|li| li.va <= va)
            .min_by_key(|li| va - li.va)
    }

    /// Return all line-info records for a specific source file.
    #[must_use]
    pub fn lines_for_file(&self, file: &str) -> Vec<&LineInfo> {
        self.line_infos
            .iter()
            .filter(|li| li.file == file)
            .collect()
    }

    /// Return all unique source file paths.
    #[must_use]
    pub fn unique_files(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.line_infos
            .iter()
            .filter(|li| seen.insert(li.file.as_str()))
            .map(|li| li.file.as_str())
            .collect()
    }

    /// Return the line-info record count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.line_infos.len()
    }

    /// Returns `true` if no line-info records are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.line_infos.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvSectionHeaders
// ─────────────────────────────────────────────────────────────────────────────

/// Section contribution header data from a `.debug$S` section.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CvSectionHeaders {
    /// Section contributions: (`segment_index`, `offset`, `size`, `characteristics`).
    pub contributions: Vec<SectionContribution>,
}

/// A single section contribution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionContribution {
    /// PE section index (1-based).
    pub section: u16,
    /// Offset within the section.
    pub offset: u32,
    /// Byte size of the contribution.
    pub size: u32,
    /// PE section characteristics flags.
    pub characteristics: u32,
    /// Module index in the DBI stream.
    pub module_index: u16,
}

impl CvSectionHeaders {
    /// Parse section contribution records.
    ///
    /// The `data` slice is the raw content of the section-contribution
    /// sub-stream (already stripped of the 4-byte header).
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        let mut contributions = Vec::new();
        let mut pos = 0usize;
        // A DBI SectionContribution record is 28 bytes:
        // ISect:u16@0, Padding:2, Off@4, Size@8, Characteristics@12,
        // IMod:u16@16, Padding2:2, DataCrc@20, RelocCrc@24.
        while pos + 28 <= data.len() {
            let section = read_u16(data, pos);
            let offset = read_u32(data, pos + 4);
            let size = read_u32(data, pos + 8);
            let characteristics = read_u32(data, pos + 12);
            let module_index = read_u16(data, pos + 16);
            contributions.push(SectionContribution {
                section,
                offset,
                size,
                characteristics,
                module_index,
            });
            pos += 28;
        }
        Self { contributions }
    }

    /// Find contributions belonging to a specific section.
    #[must_use]
    pub fn for_section(&self, section: u16) -> Vec<&SectionContribution> {
        self.contributions
            .iter()
            .filter(|c| c.section == section)
            .collect()
    }

    /// Total number of contributions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.contributions.len()
    }

    /// Returns `true` if there are no contributions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.contributions.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SourceFileMap
// ─────────────────────────────────────────────────────────────────────────────

/// Maps source-file paths to their checksums and the line-info records they contain.
#[derive(Debug, Default, Clone)]
pub struct SourceFileMap {
    /// Map from file path to MD5 checksum (16 bytes, may be empty).
    pub checksums: HashMap<String, Vec<u8>>,
    /// Map from file path to list of VAs with source info.
    pub va_map: HashMap<String, Vec<u64>>,
}

impl SourceFileMap {
    /// Build a map from a list of [`CvSourceFile`] and [`LineInfo`] records.
    #[must_use]
    pub fn from_records(files: &[CvSourceFile], lines: &[LineInfo]) -> Self {
        let mut checksums = HashMap::new();
        for f in files {
            checksums.insert(f.name.clone(), f.checksum.clone());
        }
        let mut va_map: HashMap<String, Vec<u64>> = HashMap::new();
        for li in lines {
            va_map.entry(li.file.clone()).or_default().push(li.va);
        }
        Self { checksums, va_map }
    }

    /// Return the checksum for a file, or an empty slice if not known.
    #[must_use]
    pub fn checksum_for(&self, file: &str) -> &[u8] {
        self.checksums.get(file).map_or(&[], Vec::as_slice)
    }

    /// All VAs in a file, sorted.
    #[must_use]
    pub fn vas_in_file(&self, file: &str) -> Vec<u64> {
        let mut vas = self.va_map.get(file).cloned().unwrap_or_default();
        vas.sort_unstable();
        vas
    }

    /// Total number of source files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.checksums.len()
    }

    /// All known source file paths.
    #[must_use]
    pub fn file_paths(&self) -> Vec<&str> {
        self.checksums.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvStreamParser
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level parser that dispatches to sub-parsers for each `CodeView` stream.
///
/// Feed it raw stream data via the individual `parse_*` methods, or supply an
/// entire CV8 `.debug$S` section via [`CvStreamParser::parse_debug_s`].
#[derive(Debug, Default)]
pub struct CvStreamParser {
    /// Parsed PDB signature (if found).
    pub pdb_sig: Option<CvPdbSignature>,
    /// Parsed symbol stream.
    pub symbols: Option<CvParsedSymbolStream>,
    /// Parsed type stream.
    pub types: Option<CvTypeStream>,
    /// Parsed source-module line data.
    pub src_mod: Option<CvSrcModStream>,
    /// Parsed section-header contributions.
    pub section_headers: Option<CvSectionHeaders>,
    /// String table (for resolving file names).
    pub string_table: CvStringTable,
    /// Source file map (built after parse).
    pub source_map: SourceFileMap,
    /// Image base used to adjust section-relative offsets to VAs.
    pub image_base: u64,
}

impl CvStreamParser {
    /// Create a new parser with the given image base.
    #[must_use]
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            ..Default::default()
        }
    }

    /// Parse a PDB signature block from `data`.
    pub fn parse_pdb_sig(&mut self, data: &[u8]) {
        self.pdb_sig = CvPdbSignature::parse(data);
    }

    /// Parse a CV symbol stream.
    ///
    /// # Errors
    /// Returns [`CodeViewError`] on truncated records.
    pub fn parse_symbol_stream(&mut self, data: &[u8]) -> Result<(), CodeViewError> {
        self.symbols = Some(CvParsedSymbolStream::parse(data)?);
        Ok(())
    }

    /// Parse a CV type stream.
    ///
    /// # Errors
    /// Returns [`CodeViewError`] on truncated records.
    pub fn parse_type_stream(&mut self, data: &[u8]) -> Result<(), CodeViewError> {
        self.types = Some(CvTypeStream::parse(data)?);
        Ok(())
    }

    /// Parse a complete CV8 `.debug$S` section and populate all fields.
    ///
    /// # Errors
    /// Returns [`CodeViewError`] if the section is malformed or truncated.
    pub fn parse_debug_s(&mut self, data: &[u8]) -> Result<(), CodeViewError> {
        use crate::Cv8SubsectionKind;

        if data.len() < 4 {
            return Ok(());
        }
        let version = read_u32(data, 0);
        if version != 4 {
            return Err(CodeViewError::UnsupportedVersion(version));
        }

        let mut pos = 4usize;
        let mut raw_files: Vec<CvSourceFile> = Vec::new();
        // Byte-offset of each F4 entry -> index into raw_files. CV8 line
        // blocks reference files by byte offset, not ordinal index.
        let mut file_offsets: std::collections::HashMap<u32, usize> =
            std::collections::HashMap::new();
        // Subsection order is not guaranteed: defer checksum decoding so the
        // string table is always available.
        let mut checksum_ranges: Vec<(usize, usize)> = Vec::new();
        // Store (file_index, LineInfo) so the second pass can resolve names correctly.
        let mut line_infos_raw: Vec<(u32, LineInfo)> = Vec::new();

        while pos + 8 <= data.len() {
            let sub_type = read_u32(data, pos);
            let sub_len = read_u32(data, pos + 4) as usize;
            pos += 8;
            let end = pos + sub_len;
            if end > data.len() {
                return Err(CodeViewError::RecordTooShort);
            }
            let payload = &data[pos..end];

            match Cv8SubsectionKind::from_u32(sub_type) {
                Cv8SubsectionKind::Symbols => {
                    self.symbols = Some(CvParsedSymbolStream::parse(payload)?);
                }
                Cv8SubsectionKind::Lines => {
                    let blocks = crate::parse_cv8_lines(payload)?;
                    for block in &blocks {
                        for entry in &block.lines {
                            let va = self.image_base
                                + u64::from(block.code_offset)
                                + u64::from(entry.offset);
                            // File name resolved in the second pass, once the
                            // checksum table and string table are both parsed.
                            line_infos_raw.push((block.file_index, LineInfo {
                                va,
                                file: String::new(),
                                line: entry.line_start,
                                column: 0,
                                is_statement: entry.is_statement,
                            }));
                        }
                    }
                }
                Cv8SubsectionKind::StringTable => {
                    self.string_table = CvStringTable::from_bytes(payload);
                }
                Cv8SubsectionKind::FileChecksums => {
                    checksum_ranges.push((pos, end));
                }
                _ => {}
            }

            pos = end;
            let rem = pos % 4;
            if rem != 0 {
                pos += 4 - rem;
            }
        }

        // Decode file checksums now that the string table is available.
        for (start, end) in checksum_ranges {
            let (files, offsets) =
                parse_file_checksums_local(&data[start..end], &self.string_table);
            let base = raw_files.len();
            for (off, idx) in offsets {
                file_offsets.insert(off, base + idx);
            }
            raw_files.extend(files);
        }

        // Second pass to resolve file names via the F4 byte-offset map.
        let mut line_infos: Vec<LineInfo> = Vec::with_capacity(line_infos_raw.len());
        for (file_index, mut li) in line_infos_raw {
            if li.file.is_empty()
                && let Some(f) = file_offsets
                    .get(&file_index)
                    .and_then(|&i| raw_files.get(i))
            {
                li.file.clone_from(&f.name);
            }
            line_infos.push(li);
        }

        self.src_mod = Some(CvSrcModStream::new(line_infos.clone(), raw_files.clone()));
        self.source_map = SourceFileMap::from_records(&raw_files, &line_infos);
        Ok(())
    }

    /// Look up the source location for a given virtual address.
    ///
    /// Returns the nearest [`LineInfo`] at or before `va`, or `None`.
    #[must_use]
    pub fn source_for_va(&self, va: u64) -> Option<&LineInfo> {
        self.src_mod.as_ref()?.lookup_va(va)
    }

    /// All function symbols from the symbol stream.
    #[must_use]
    pub fn functions(&self) -> Vec<&CvSymbol> {
        self.symbols
            .as_ref()
            .map(|s| {
                s.symbols
                    .iter()
                    .filter(|sym| sym.kind.is_function())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All data symbols from the symbol stream.
    #[must_use]
    pub fn data_symbols(&self) -> Vec<&CvSymbol> {
        self.symbols
            .as_ref()
            .map(|s| s.symbols.iter().filter(|sym| sym.kind.is_data()).collect())
            .unwrap_or_default()
    }

    /// Total symbol count (functions + data + other).
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbols.as_ref().map_or(0, |s| s.symbols.len())
    }

    /// Total type record count.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.types.as_ref().map_or(0, |t| t.records.len())
    }

    /// Total source-line mapping count.
    #[must_use]
    pub fn line_info_count(&self) -> usize {
        self.src_mod.as_ref().map_or(0, CvSrcModStream::len)
    }

    /// PDB path, if a PDB signature was parsed.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        self.pdb_sig.as_ref()?.pdb_path()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_null_str(data: &[u8], from: usize) -> String {
    if from >= data.len() {
        return String::new();
    }
    String::from_utf8_lossy(data[from..].split(|&b| b == 0).next().unwrap_or(&[])).to_string()
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        data1,
        data2,
        data3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Parse file checksum records inline (duplicates lib.rs private impl for module use).
fn parse_file_checksums_local(
    data: &[u8],
    strtab: &CvStringTable,
) -> (Vec<CvSourceFile>, std::collections::HashMap<u32, usize>) {
    let mut files = vec![];
    let mut offsets = std::collections::HashMap::new();
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let entry_offset = u32::try_from(pos).unwrap_or(u32::MAX);
        let name_offset = read_u32(data, pos);
        let checksum_len = data[pos + 4] as usize;
        let _ = data[pos + 5];
        if pos + 6 + checksum_len > data.len() {
            break;
        }
        let checksum = data[pos + 6..pos + 6 + checksum_len].to_vec();
        let name = strtab.get(name_offset).to_string();
        offsets.insert(entry_offset, files.len());
        files.push(CvSourceFile {
            name_offset,
            name,
            checksum,
        });
        pos = match pos.checked_add(8 + checksum_len) {
            Some(p) => p,
            None => break,
        };
        let rem = pos % 4;
        if rem != 0 {
            pos = pos.saturating_add(4 - rem);
        }
    }
    (files, offsets)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_test_gdata32, build_test_gproc32, build_test_lproc32, build_test_pub32};

    // ── CvPdbSignature ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_rsds_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0u8; 16]); // GUID bytes
        data.extend_from_slice(&1u32.to_le_bytes()); // age
        data.extend_from_slice(b"C:\\test.pdb\0");

        let sig = CvPdbSignature::parse(&data).unwrap();
        assert!(matches!(sig, CvPdbSignature::Rsds { .. }));
        assert_eq!(sig.pdb_path(), Some("C:\\test.pdb"));
        assert_eq!(sig.age(), Some(1));
        assert_eq!(sig.label(), "RSDS (PDB 7.0)");
    }

    #[test]
    fn test_parse_nb10_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NB10");
        data.extend_from_slice(&0u32.to_le_bytes()); // offset
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // timestamp
        data.extend_from_slice(&2u32.to_le_bytes()); // age
        data.extend_from_slice(b"test.pdb\0");

        let sig = CvPdbSignature::parse(&data).unwrap();
        assert!(matches!(sig, CvPdbSignature::Nb10 { .. }));
        assert_eq!(sig.pdb_path(), Some("test.pdb"));
        assert_eq!(sig.age(), Some(2));
    }

    #[test]
    fn test_parse_nb11_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NB11");
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(b"x.pdb\0");
        let sig = CvPdbSignature::parse(&data).unwrap();
        assert!(matches!(sig, CvPdbSignature::Nb11 { .. }));
    }

    #[test]
    fn test_parse_unknown_signature() {
        let data = b"UNKN\x00\x00\x00\x00";
        let sig = CvPdbSignature::parse(data).unwrap();
        assert!(matches!(sig, CvPdbSignature::Unknown { .. }));
        assert_eq!(sig.pdb_path(), None);
    }

    #[test]
    fn test_signature_too_short() {
        let sig = CvPdbSignature::parse(b"RS");
        assert!(sig.is_none());
    }

    #[test]
    fn test_rsds_guid_display() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
        ]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"\0");
        let sig = CvPdbSignature::parse(&data).unwrap();
        let guid = sig.guid().unwrap();
        assert!(guid.starts_with('{'));
        assert!(guid.ends_with('}'));
    }

    // ── CvSymbolStream ────────────────────────────────────────────────────────

    fn make_symbol_stream() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(build_test_gproc32("foo", 0x1000, 1, 0));
        data.extend(build_test_lproc32("bar", 0x2000));
        data.extend(build_test_pub32("baz", 0x3000));
        data.extend(build_test_gdata32("g_var", 0x4000, 0x1001));
        data
    }

    #[test]
    fn test_symbol_stream_parse() {
        let data = make_symbol_stream();
        let stream = CvParsedSymbolStream::parse(&data).unwrap();
        assert_eq!(stream.symbols.len(), 4);
    }

    #[test]
    fn test_symbol_stream_function_count() {
        let stream = CvParsedSymbolStream::parse(&make_symbol_stream()).unwrap();
        assert_eq!(stream.function_count(), 3); // foo + bar + baz (pub32 is data, but baz counts as function here)
    }

    #[test]
    fn test_symbol_stream_data_count() {
        let stream = CvParsedSymbolStream::parse(&make_symbol_stream()).unwrap();
        // g_var is a data symbol
        assert!(stream.data_count() >= 1);
    }

    #[test]
    fn test_symbol_stream_find_by_name() {
        let stream = CvParsedSymbolStream::parse(&make_symbol_stream()).unwrap();
        assert!(stream.find_by_name("foo").is_some());
        assert!(stream.find_by_name("missing").is_none());
    }

    #[test]
    fn test_symbol_stream_search() {
        let stream = CvParsedSymbolStream::parse(&make_symbol_stream()).unwrap();
        let hits = stream.search("ba");
        assert_eq!(hits.len(), 2); // bar, baz
    }

    #[test]
    fn test_symbol_stream_sorted_by_offset() {
        let stream = CvParsedSymbolStream::parse(&make_symbol_stream()).unwrap();
        let sorted = stream.sorted_by_offset();
        assert!(!sorted.is_empty());
    }

    #[test]
    fn test_symbol_stream_empty() {
        let stream = CvParsedSymbolStream::parse(&[]).unwrap();
        assert_eq!(stream.symbols.len(), 0);
        assert_eq!(stream.function_count(), 0);
    }

    // ── CvTypeStream ─────────────────────────────────────────────────────────

    fn make_type_stream() -> Vec<u8> {
        // Build a minimal LF_STRUCTURE record.
        // len(2) + leaf(2) + [count:u16 + prop:u16 + field_list:u32 + derived:u32 + vshape:u32 + size:u16 + name\0]
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0u32.to_le_bytes()); // field_list
        payload.extend_from_slice(&0u32.to_le_bytes()); // derived
        payload.extend_from_slice(&0u32.to_le_bytes()); // vshape
        payload.extend_from_slice(&16u16.to_le_bytes()); // size
        payload.extend_from_slice(b"MyStruct\0");

        let leaf: u16 = 0x1005; // LF_STRUCTURE
        let len = crate::casts::usize_to_u16(2 + payload.len());
        let mut record = Vec::new();
        record.extend_from_slice(&len.to_le_bytes());
        record.extend_from_slice(&leaf.to_le_bytes());
        record.extend_from_slice(&payload);
        record
    }

    #[test]
    fn test_type_stream_parse_struct() {
        let data = make_type_stream();
        let stream = CvTypeStream::parse(&data).unwrap();
        assert_eq!(stream.records.len(), 1);
        assert_eq!(stream.records[0].name, "MyStruct");
        assert_eq!(stream.aggregate_count(), 1);
    }

    #[test]
    fn test_type_stream_lookup() {
        let data = make_type_stream();
        let stream = CvTypeStream::parse(&data).unwrap();
        // first record is at index 0x1000
        assert!(stream.lookup(0x1000).is_some());
        assert!(stream.lookup(0x0FFF).is_none());
    }

    #[test]
    fn test_type_stream_find_by_name() {
        let data = make_type_stream();
        let stream = CvTypeStream::parse(&data).unwrap();
        assert!(!stream.find_by_name("MyStruct").is_empty());
        assert!(stream.find_by_name("Missing").is_empty());
    }

    #[test]
    fn test_type_stream_empty() {
        let stream = CvTypeStream::parse(&[]).unwrap();
        assert_eq!(stream.records.len(), 0);
        assert_eq!(stream.aggregate_count(), 0);
    }

    // ── LineInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn test_line_info_display() {
        let li = LineInfo::new(0x0040_1000, "main.c", 42, true);
        let s = li.to_string();
        assert!(s.contains("0x401000"));
        assert!(s.contains("main.c"));
        assert!(s.contains("42"));
    }

    // ── CvSrcModStream ────────────────────────────────────────────────────────

    #[test]
    fn test_src_mod_lookup_va_exact() {
        let lines = vec![
            LineInfo::new(0x1000, "a.c", 1, true),
            LineInfo::new(0x1010, "a.c", 5, true),
        ];
        let stream = CvSrcModStream::new(lines, Vec::new());
        let r = stream.lookup_va(0x1010).unwrap();
        assert_eq!(r.line, 5);
    }

    #[test]
    fn test_src_mod_lookup_va_nearest() {
        let lines = vec![
            LineInfo::new(0x1000, "a.c", 1, true),
            LineInfo::new(0x1010, "a.c", 5, true),
        ];
        let stream = CvSrcModStream::new(lines, Vec::new());
        let r = stream.lookup_va(0x1008).unwrap();
        assert_eq!(r.line, 1); // nearest at or before
    }

    #[test]
    fn test_src_mod_unique_files() {
        let lines = vec![
            LineInfo::new(0x1000, "a.c", 1, true),
            LineInfo::new(0x1010, "b.c", 5, true),
            LineInfo::new(0x1020, "a.c", 10, false),
        ];
        let stream = CvSrcModStream::new(lines, Vec::new());
        let files = stream.unique_files();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_src_mod_lines_for_file() {
        let lines = vec![
            LineInfo::new(0x1000, "a.c", 1, true),
            LineInfo::new(0x1010, "b.c", 5, true),
        ];
        let stream = CvSrcModStream::new(lines, Vec::new());
        assert_eq!(stream.lines_for_file("a.c").len(), 1);
        assert_eq!(stream.lines_for_file("missing.c").len(), 0);
    }

    // ── CvSectionHeaders ──────────────────────────────────────────────────────

    #[test]
    fn test_section_headers_parse_empty() {
        let hdrs = CvSectionHeaders::parse(&[]);
        assert!(hdrs.is_empty());
    }

    #[test]
    fn test_section_headers_parse_one() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes()); // section
        data.extend_from_slice(&0u16.to_le_bytes()); // padding / module_index
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        data.extend_from_slice(&0x200u32.to_le_bytes()); // size
        data.extend_from_slice(&0x6050_0020u32.to_le_bytes()); // characteristics
        data.extend_from_slice(&7u16.to_le_bytes()); // IMod @16
        data.extend_from_slice(&0u16.to_le_bytes()); // padding2
        data.extend_from_slice(&0u32.to_le_bytes()); // DataCrc
        data.extend_from_slice(&0u32.to_le_bytes()); // RelocCrc
        assert_eq!(data.len(), 28, "SectionContribution records are 28 bytes");
        let hdrs = CvSectionHeaders::parse(&data);
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs.contributions[0].section, 1);
        assert_eq!(hdrs.contributions[0].size, 0x200);
        assert_eq!(hdrs.contributions[0].module_index, 7);
    }

    // ── SourceFileMap ─────────────────────────────────────────────────────────

    #[test]
    fn test_source_file_map_empty() {
        let map = SourceFileMap::from_records(&[], &[]);
        assert_eq!(map.file_count(), 0);
    }

    #[test]
    fn test_source_file_map_file_count() {
        let files = vec![
            CvSourceFile {
                name_offset: 0,
                name: "a.c".into(),
                checksum: vec![0u8; 16],
            },
            CvSourceFile {
                name_offset: 4,
                name: "b.c".into(),
                checksum: vec![0u8; 16],
            },
        ];
        let lines = vec![LineInfo::new(0x1000, "a.c", 1, true)];
        let map = SourceFileMap::from_records(&files, &lines);
        assert_eq!(map.file_count(), 2);
    }

    #[test]
    fn test_source_file_map_vas_in_file() {
        let lines = vec![
            LineInfo::new(0x2000, "x.c", 1, true),
            LineInfo::new(0x1000, "x.c", 2, true),
        ];
        let map = SourceFileMap::from_records(&[], &lines);
        let vas = map.vas_in_file("x.c");
        assert_eq!(vas, vec![0x1000, 0x2000]); // sorted
    }

    // ── CvStreamParser ────────────────────────────────────────────────────────

    #[test]
    fn test_stream_parser_new() {
        let parser = CvStreamParser::new(0x0001_4000_0000);
        assert_eq!(parser.image_base, 0x0001_4000_0000);
        assert!(parser.symbols.is_none());
    }

    #[test]
    fn test_stream_parser_symbol_stream() {
        let mut parser = CvStreamParser::new(0);
        let data = make_symbol_stream();
        parser.parse_symbol_stream(&data).unwrap();
        assert!(parser.symbols.is_some());
        assert!(parser.symbol_count() > 0);
    }

    #[test]
    fn test_stream_parser_type_stream() {
        let mut parser = CvStreamParser::new(0);
        let data = make_type_stream();
        parser.parse_type_stream(&data).unwrap();
        assert!(parser.types.is_some());
        assert_eq!(parser.type_count(), 1);
    }

    #[test]
    fn test_stream_parser_pdb_sig() {
        let mut parser = CvStreamParser::new(0);
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"my.pdb\0");
        parser.parse_pdb_sig(&data);
        assert!(parser.pdb_sig.is_some());
        assert_eq!(parser.pdb_path(), Some("my.pdb"));
    }

    #[test]
    fn test_stream_parser_functions_empty() {
        let parser = CvStreamParser::new(0);
        assert!(parser.functions().is_empty());
    }
}
