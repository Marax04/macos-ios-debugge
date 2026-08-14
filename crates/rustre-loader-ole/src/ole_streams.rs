//! `ole_streams` — Key OLE2 stream analysis for Office document forensics.
//!
//! Parses well-known streams embedded inside OLE2 compound files:
//! - `WordDocument` (Word binary `.doc` version detection via `wIdent`/`nFib`)
//! - `_VBA_PROJECT` / `VBA/dir` (VBA project stream detection)
//! - `Workbook` / `Book` (Excel `.xls` stream detection)
//! - CLSID-based document type identification
//!
//! # Design note — intentionally separate from `ole_stream_analyzer`
//!
//! This module provides a **stateful builder** ([`OleStreamAnalyzer`]) that
//! accumulates streams one at a time via [`OleStreamAnalyzer::ingest_stream`]
//! and produces aggregated document-level metadata (doc type, encryption,
//! VBA presence, CLSID).  It is oriented toward building a picture of the
//! whole document.
//!
//! [`crate::ole_stream_analyzer`] provides a **stateless per-stream analyzer**
//! ([`crate::ole_stream_analyzer::OleStreamAnalyzer`]) that classifies and
//! deep-parses a single named stream in isolation, returning a
//! [`crate::ole_stream_analyzer::StreamAnalysisResult`] with forensic notes.
//!
//! The two `OleStreamAnalyzer` types share a name but serve different roles
//! and are kept distinct deliberately.  Both also define a `WordDocument` /
//! `WordDocHeader` parser and a `VbaProject` / `VbaProjectStream` parser;
//! these overlap but differ in the fields and error semantics they expose.
//! A future refactor should unify the underlying parsers into shared types.

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from OLE stream analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// Stream is too short for the expected structure.
    Truncated,
    /// Stream signature or magic does not match.
    InvalidSignature(String),
    /// Generic parse error.
    ParseError(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "stream truncated"),
            Self::InvalidSignature(s) => write!(f, "invalid signature: {s}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

// ── CLSIDs for common Office document types ───────────────────────────────────

/// CLSID of a Word 97–2003 document (DOC/DOT).
pub const CLSID_WORD97: [u8; 16] = [
    0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// CLSID of an Excel 97–2003 workbook (XLS/XLT).
pub const CLSID_EXCEL97: [u8; 16] = [
    0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// CLSID of a `PowerPoint` 97–2003 presentation (PPT/PPS).
pub const CLSID_POWERPOINT97: [u8; 16] = [
    0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// ── DocumentType ─────────────────────────────────────────────────────────────

/// High-level document type identified from CLSID or stream names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DocumentType {
    Word,
    Excel,
    PowerPoint,
    Visio,
    Project,
    Unknown,
    Custom(String),
}

impl DocumentType {
    /// Classify a 16-byte CLSID.
    #[must_use]
    pub fn from_clsid(clsid: &[u8; 16]) -> Self {
        if clsid == &CLSID_WORD97 {
            Self::Word
        } else if clsid == &CLSID_EXCEL97 {
            Self::Excel
        } else if clsid == &CLSID_POWERPOINT97 {
            Self::PowerPoint
        } else {
            Self::Unknown
        }
    }

    /// Classify by known stream names in the compound file.
    #[must_use]
    pub fn from_stream_names(names: &[impl AsRef<str>]) -> Self {
        for name in names {
            let n = name.as_ref().to_ascii_lowercase();
            match n.as_str() {
                "worddocument" => return Self::Word,
                "workbook" | "book" => return Self::Excel,
                "powerpoint document" => return Self::PowerPoint,
                "visio document" => return Self::Visio,
                _ => {}
            }
        }
        Self::Unknown
    }
}

impl fmt::Display for DocumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Word => "Word",
            Self::Excel => "Excel",
            Self::PowerPoint => "PowerPoint",
            Self::Visio => "Visio",
            Self::Project => "Project",
            Self::Unknown => "Unknown",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// ── WordDocHeader ─────────────────────────────────────────────────────────────

/// First 32 bytes of the `WordDocument` stream — the FIB (File Information Block) base.
///
/// Reference: MS-DOC §2.5.1 `FibBase`.
#[derive(Debug, Clone)]
pub struct WordDocHeader {
    /// `wIdent` — must be `0xA5EC` for Word 97+.
    pub w_ident: u16,
    /// `nFib` — file format version.
    pub n_fib: u16,
    /// `unused` field at offset 4.
    pub unused: u16,
    /// `lid` — language identifier.
    pub lid: u16,
    /// `pnNext` — page number of next file in chain.
    pub pn_next: u16,
    /// `flags` — various boolean flags packed as bitfield.
    pub flags: u16,
    /// `nFibBack` — minimum version understood.
    pub n_fib_back: u16,
    /// `lKey` — file encryption key (0 if not encrypted).
    pub l_key: u32,
    /// `envr` — environment (0=Win, 1=Mac).
    pub envr: u8,
    /// `bitmapFib` — additional flags.
    pub bitmap_fib: u8,
    /// `chs` — default character set.
    pub chs: u16,
    /// `chsTables` — character set for internal tables.
    pub chs_tables: u16,
    /// `fcMin` — minimum file character position.
    pub fc_min: u32,
    /// `fcMac` — maximum file character position.
    pub fc_mac: u32,
}

impl WordDocHeader {
    /// Expected `wIdent` value for Word 97+ documents.
    pub const WORD_IDENT: u16 = 0xA5EC;

    /// Parse from the first 32 bytes of a `WordDocument` stream.
    ///
    /// # Errors
    /// Returns [`StreamError::Truncated`] if fewer than 32 bytes are provided.
    /// Returns [`StreamError::InvalidSignature`] if `wIdent` is wrong.
    pub fn parse(data: &[u8]) -> Result<Self, StreamError> {
        if data.len() < 32 {
            return Err(StreamError::Truncated);
        }
        let w_ident = u16_le(data, 0);
        if w_ident != Self::WORD_IDENT {
            return Err(StreamError::InvalidSignature(format!(
                "expected 0xA5EC, got {w_ident:#06x}"
            )));
        }
        Ok(Self {
            w_ident,
            n_fib: u16_le(data, 2),
            unused: u16_le(data, 4),
            lid: u16_le(data, 6),
            pn_next: u16_le(data, 8),
            flags: u16_le(data, 10),
            n_fib_back: u16_le(data, 12),
            l_key: u32_le(data, 14),
            envr: data[18],
            bitmap_fib: data[19],
            chs: u16_le(data, 20),
            chs_tables: u16_le(data, 22),
            fc_min: u32_le(data, 24),
            fc_mac: u32_le(data, 28),
        })
    }

    /// Return a human-readable Word version description based on `nFib`.
    #[must_use]
    pub const fn version_description(&self) -> &'static str {
        match self.n_fib {
            0x00C1 => "Word 97",
            0x00D9 => "Word 2000",
            0x0101 => "Word 2002 (XP)",
            0x010C => "Word 2003",
            0x0112 => "Word 2007",
            _ => "Word (unknown version)",
        }
    }

    /// Returns `true` if the document is password-protected.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.l_key != 0 || (self.flags & 0x0100) != 0
    }

    /// Returns `true` if this is a template (`.dot`) rather than a document.
    #[must_use]
    pub const fn is_template(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    /// Returns `true` if the document is marked as a macro-enabled file.
    #[must_use]
    pub const fn has_macros(&self) -> bool {
        (self.flags & 0x0020) != 0
    }
}

impl fmt::Display for WordDocHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WordDoc nFib={:#06x} ({}) encrypted={} template={}",
            self.n_fib,
            self.version_description(),
            self.is_encrypted(),
            self.is_template()
        )
    }
}

// ── VbaProjectStream ─────────────────────────────────────────────────────────

/// Parsed information about a `_VBA_PROJECT` stream.
///
/// The `_VBA_PROJECT` stream begins with a 4-byte header:
/// `0x61 0x00 0x00 0x00` (`LittleEndian`) in most Office implementations.
/// The actual VBA bytecode follows; source code is stored compressed in
/// individual `VBA/<module>` streams.
#[derive(Debug, Clone)]
pub struct VbaProjectStream {
    /// First 4 bytes of the `_VBA_PROJECT` stream.
    pub header: [u8; 4],
    /// Total stream length.
    pub stream_length: usize,
    /// Whether the stream appears to contain VBA code.
    pub has_vba_signature: bool,
    /// Extracted printable ASCII strings from the header region.
    pub header_strings: Vec<String>,
}

impl VbaProjectStream {
    /// Parse from raw `_VBA_PROJECT` stream data.
    ///
    /// # Errors
    /// Returns [`StreamError::Truncated`] if data is empty.
    pub fn parse(data: &[u8]) -> Result<Self, StreamError> {
        if data.is_empty() {
            return Err(StreamError::Truncated);
        }
        let mut header = [0u8; 4];
        let copy_len = data.len().min(4);
        header[..copy_len].copy_from_slice(&data[..copy_len]);
        // VBA project magic: first two bytes should be 61 00
        let has_vba_signature = data.len() >= 2 && data[0] == 0x61 && data[1] == 0x00;
        let header_strings = extract_printable(&data[..data.len().min(256)], 4);
        Ok(Self {
            header,
            stream_length: data.len(),
            has_vba_signature,
            header_strings,
        })
    }
}

impl fmt::Display for VbaProjectStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VbaProject len={} has_sig={} strings={}",
            self.stream_length,
            self.has_vba_signature,
            self.header_strings.len()
        )
    }
}

// ── WorkbookStream ────────────────────────────────────────────────────────────

/// Parsed information from the Excel `Workbook` (or `Book`) stream.
///
/// The Workbook stream is a sequence of BIFF records; each record has:
/// - 2-byte type (LE)
/// - 2-byte length (LE)
/// - `length` bytes of data
///
/// The first record in a valid XLS file is always BOF (type 0x0809).
#[derive(Debug, Clone)]
pub struct WorkbookStream {
    /// BIFF BOF record type (first record).
    pub bof_type: u16,
    /// Excel version from BOF `vers` field.
    pub excel_version: u16,
    /// BOF `dt` (document type): 0x10=worksheet, 0x20=chart, etc.
    pub doc_type: u16,
    /// Whether a `FILEPASS` record was found (encrypted).
    pub is_encrypted: bool,
    /// Number of BIFF records scanned.
    pub record_count: usize,
    /// List of record types encountered (deduplicated).
    pub record_types: Vec<u16>,
}

impl WorkbookStream {
    /// BIFF8 BOF record type.
    pub const BOF_TYPE: u16 = 0x0809;
    /// FILEPASS record type (indicates encryption).
    pub const FILEPASS_TYPE: u16 = 0x002F;
    /// Maximum BIFF records to scan before stopping.
    const MAX_RECORDS: usize = 4096;

    /// Parse from raw `Workbook` stream bytes.
    ///
    /// # Errors
    /// Returns [`StreamError::Truncated`] if data has fewer than 4 bytes.
    /// Returns [`StreamError::InvalidSignature`] if the first record is not BOF.
    pub fn parse(data: &[u8]) -> Result<Self, StreamError> {
        if data.len() < 4 {
            return Err(StreamError::Truncated);
        }
        let first_type = u16_le(data, 0);
        if first_type != Self::BOF_TYPE {
            return Err(StreamError::InvalidSignature(format!(
                "expected BOF 0x0809, got {first_type:#06x}"
            )));
        }
        let bof_len = u16_le(data, 2) as usize;
        let (excel_version, doc_type) = if data.len() >= 4 + bof_len && bof_len >= 4 {
            (u16_le(data, 4), u16_le(data, 6))
        } else {
            (0, 0)
        };

        // Scan all BIFF records.
        let mut pos = 0usize;
        let mut record_count = 0usize;
        let mut is_encrypted = false;
        let mut seen_types: HashMap<u16, bool> = HashMap::new();

        while pos + 4 <= data.len() && record_count < Self::MAX_RECORDS {
            let rec_type = u16_le(data, pos);
            let rec_len = u16_le(data, pos + 2) as usize;
            if rec_type == Self::FILEPASS_TYPE {
                is_encrypted = true;
            }
            seen_types.insert(rec_type, true);
            pos += 4 + rec_len;
            record_count += 1;
        }
        let mut record_types: Vec<u16> = seen_types.keys().copied().collect();
        record_types.sort_unstable();

        Ok(Self {
            bof_type: first_type,
            excel_version,
            doc_type,
            is_encrypted,
            record_count,
            record_types,
        })
    }

    /// Return a human-readable Excel version from the BOF `vers` field.
    #[must_use]
    pub const fn version_description(&self) -> &'static str {
        match self.excel_version {
            0x0500 => "Excel 5.0/7.0",
            0x0600 => "Excel 97-2003 (BIFF8)",
            _ => "Excel (unknown)",
        }
    }

    /// Return a description of the document type from the BOF `dt` field.
    #[must_use]
    pub const fn doc_type_description(&self) -> &'static str {
        match self.doc_type {
            0x0005 => "Workbook globals",
            0x0006 => "Visual Basic module",
            0x0010 => "Worksheet or dialog",
            0x0020 => "Chart",
            0x0040 => "Excel 4.0 macro sheet",
            0x0100 => "Workspace file",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for WorkbookStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Workbook {} doc_type={} encrypted={} records={}",
            self.version_description(),
            self.doc_type_description(),
            self.is_encrypted,
            self.record_count,
        )
    }
}

// ── OleStreamAnalyzer ─────────────────────────────────────────────────────────

/// High-level stream analyzer: identifies document type and extracts
/// structured information from well-known streams.
#[derive(Debug, Default)]
pub struct OleStreamAnalyzer {
    /// Identified document type.
    pub doc_type: Option<DocumentType>,
    /// Parsed `WordDocument` stream header, if present.
    pub word_doc: Option<WordDocHeader>,
    /// Parsed `_VBA_PROJECT` stream, if present.
    pub vba_project: Option<VbaProjectStream>,
    /// Parsed `Workbook` / `Book` stream, if present.
    pub workbook: Option<WorkbookStream>,
    /// CLSID from the root directory entry.
    pub root_clsid: Option<[u8; 16]>,
    /// All stream names found.
    pub stream_names: Vec<String>,
    /// Per-stream size map.
    pub stream_sizes: HashMap<String, u64>,
    /// Analysis warnings.
    pub warnings: Vec<String>,
}

impl OleStreamAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a stream by name and raw bytes.
    ///
    /// Recognized names: `WordDocument`, `_VBA_PROJECT`, `Workbook`, `Book`.
    pub fn ingest_stream(&mut self, name: &str, data: &[u8]) {
        self.stream_names.push(name.to_string());
        self.stream_sizes.insert(name.to_string(), data.len() as u64);
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "worddocument" => {
                match WordDocHeader::parse(data) {
                    Ok(hdr) => {
                        self.doc_type = Some(DocumentType::Word);
                        self.word_doc = Some(hdr);
                    }
                    Err(e) => self.warnings.push(format!("WordDocument parse: {e}")),
                }
            }
            "_vba_project" => {
                match VbaProjectStream::parse(data) {
                    Ok(vba) => self.vba_project = Some(vba),
                    Err(e) => self.warnings.push(format!("_VBA_PROJECT parse: {e}")),
                }
            }
            "workbook" | "book" => {
                match WorkbookStream::parse(data) {
                    Ok(wb) => {
                        self.doc_type = Some(DocumentType::Excel);
                        self.workbook = Some(wb);
                    }
                    Err(e) => self.warnings.push(format!("Workbook parse: {e}")),
                }
            }
            _ => {}
        }
    }

    /// Set the root CLSID; updates `doc_type` if it hasn't been set yet.
    pub fn set_root_clsid(&mut self, clsid: [u8; 16]) {
        self.root_clsid = Some(clsid);
        if self.doc_type.is_none() {
            let dt = DocumentType::from_clsid(&clsid);
            if dt != DocumentType::Unknown {
                self.doc_type = Some(dt);
            }
        }
    }

    /// Finalize: if `doc_type` is still unknown, try to infer from stream names.
    pub fn finalize(&mut self) {
        if self.doc_type.is_none() {
            let dt = DocumentType::from_stream_names(&self.stream_names);
            if dt != DocumentType::Unknown {
                self.doc_type = Some(dt);
            }
        }
    }

    /// Returns `true` if VBA macros were detected.
    #[must_use]
    pub fn has_vba(&self) -> bool {
        self.vba_project.as_ref().is_some_and(|v| v.has_vba_signature)
            || self.stream_names.iter().any(|n| {
                n.eq_ignore_ascii_case("VBA") || n.eq_ignore_ascii_case("_VBA_PROJECT")
            })
    }

    /// Returns `true` if the document appears to be encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.word_doc.as_ref().is_some_and(WordDocHeader::is_encrypted)
            || self.workbook.as_ref().is_some_and(|wb| wb.is_encrypted)
    }

    /// Return a concise risk summary.
    #[must_use]
    pub fn risk_summary(&self) -> String {
        let mut flags = Vec::new();
        if self.has_vba() {
            flags.push("VBA");
        }
        if self.is_encrypted() {
            flags.push("ENCRYPTED");
        }
        if self.word_doc.as_ref().is_some_and(WordDocHeader::has_macros) {
            flags.push("MACROS");
        }
        if flags.is_empty() {
            "CLEAN".to_string()
        } else {
            flags.join("|")
        }
    }
}

impl fmt::Display for OleStreamAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OleStreamAnalyzer type={} streams={} vba={} encrypted={}",
            self.doc_type
                .as_ref().map_or_else(|| "?".into(), std::string::ToString::to_string),
            self.stream_names.len(),
            self.has_vba(),
            self.is_encrypted(),
        )
    }
}

// ── ClsidClassifier ───────────────────────────────────────────────────────────

/// Maps known CLSIDs to human-readable names and document types.
pub struct ClsidClassifier {
    entries: HashMap<[u8; 16], (String, DocumentType)>,
}

impl ClsidClassifier {
    /// Create a classifier pre-loaded with well-known CLSIDs.
    #[must_use]
    pub fn new() -> Self {
        let mut entries: HashMap<[u8; 16], (String, DocumentType)> = HashMap::new();
        entries.insert(CLSID_WORD97, ("Word 97-2003 Document".into(), DocumentType::Word));
        entries.insert(CLSID_EXCEL97, ("Excel 97-2003 Workbook".into(), DocumentType::Excel));
        entries.insert(
            CLSID_POWERPOINT97,
            ("PowerPoint 97-2003 Presentation".into(), DocumentType::PowerPoint),
        );
        Self { entries }
    }

    /// Look up a CLSID.  Returns `None` if unknown.
    #[must_use]
    pub fn classify(&self, clsid: &[u8; 16]) -> Option<&(String, DocumentType)> {
        self.entries.get(clsid)
    }

    /// Register a custom CLSID → (name, type) mapping.
    pub fn register(&mut self, clsid: [u8; 16], name: impl Into<String>, doc_type: DocumentType) {
        self.entries.insert(clsid, (name.into(), doc_type));
    }

    /// Return the number of registered CLSIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no CLSIDs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ClsidClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── StreamInfo ────────────────────────────────────────────────────────────────

/// Summary of a single stream for reporting purposes.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
    pub category: StreamCategory,
    pub printable_excerpt: String,
}

/// Category assigned to a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamCategory {
    WordContent,
    ExcelContent,
    VbaProject,
    VbaModule,
    Thumbnail,
    Summary,
    Unknown,
}

impl StreamInfo {
    /// Classify a stream by name and produce a [`StreamInfo`].
    #[must_use]
    pub fn classify(name: &str, data: &[u8]) -> Self {
        let lower = name.to_ascii_lowercase();
        let category = match lower.as_str() {
            "worddocument" => StreamCategory::WordContent,
            "workbook" | "book" => StreamCategory::ExcelContent,
            "_vba_project" | "vba/dir" | "vbaproject" => StreamCategory::VbaProject,
            n if n.starts_with("vba/") => StreamCategory::VbaModule,
            "\x05summaryinformation" | "\x05documentsummaryinformation" => StreamCategory::Summary,
            _ => StreamCategory::Unknown,
        };
        let printable_excerpt = extract_printable(&data[..data.len().min(128)], 4)
            .into_iter()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        Self {
            name: name.to_string(),
            size: data.len() as u64,
            category,
            printable_excerpt,
        }
    }
}

impl fmt::Display for StreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' [{:?}] size={}",
            self.name, self.category, self.size
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract printable ASCII runs of at least `min_len` from `data`.
fn extract_printable(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = String::new();
    for &b in data {
        if (0x20..0x7F).contains(&b) {
            run.push(b as char);
        } else {
            if run.len() >= min_len {
                out.push(run.clone());
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        out.push(run);
    }
    out
}

#[inline(always)]
fn u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline(always)]
fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_word_doc_stream() -> Vec<u8> {
        let mut d = vec![0u8; 32];
        d[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes()); // wIdent
        d[2..4].copy_from_slice(&0x00C1u16.to_le_bytes()); // nFib = Word 97
        d[18] = 0; // envr = Windows
        d
    }

    fn make_workbook_stream() -> Vec<u8> {
        let mut d = vec![0u8; 16];
        d[0..2].copy_from_slice(&0x0809u16.to_le_bytes()); // BOF
        d[2..4].copy_from_slice(&8u16.to_le_bytes()); // len = 8
        d[4..6].copy_from_slice(&0x0600u16.to_le_bytes()); // vers = BIFF8
        d[6..8].copy_from_slice(&0x0005u16.to_le_bytes()); // dt = globals
        // Terminator record (EOF = 0x000A)
        d[12..14].copy_from_slice(&0x000Au16.to_le_bytes());
        d[14..16].copy_from_slice(&0u16.to_le_bytes());
        d
    }

    // ── DocumentType ─────────────────────────────────────────────────────────

    #[test]
    fn test_doc_type_from_clsid_word() {
        assert_eq!(DocumentType::from_clsid(&CLSID_WORD97), DocumentType::Word);
    }

    #[test]
    fn test_doc_type_from_clsid_excel() {
        assert_eq!(DocumentType::from_clsid(&CLSID_EXCEL97), DocumentType::Excel);
    }

    #[test]
    fn test_doc_type_from_clsid_unknown() {
        assert_eq!(DocumentType::from_clsid(&[0u8; 16]), DocumentType::Unknown);
    }

    #[test]
    fn test_doc_type_from_stream_names() {
        let names = vec!["WordDocument".to_string()];
        assert_eq!(DocumentType::from_stream_names(&names), DocumentType::Word);
        let names2 = vec!["Workbook".to_string()];
        assert_eq!(DocumentType::from_stream_names(&names2), DocumentType::Excel);
    }

    // ── WordDocHeader ─────────────────────────────────────────────────────────

    #[test]
    fn test_word_doc_header_valid() {
        let d = make_word_doc_stream();
        let h = WordDocHeader::parse(&d).unwrap();
        assert_eq!(h.w_ident, 0xA5EC);
        assert_eq!(h.n_fib, 0x00C1);
        assert_eq!(h.version_description(), "Word 97");
    }

    #[test]
    fn test_word_doc_header_invalid_magic() {
        let d = vec![0u8; 32];
        assert!(matches!(
            WordDocHeader::parse(&d),
            Err(StreamError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_word_doc_header_truncated() {
        assert!(matches!(
            WordDocHeader::parse(&[0u8; 8]),
            Err(StreamError::Truncated)
        ));
    }

    #[test]
    fn test_word_doc_header_display() {
        let d = make_word_doc_stream();
        let h = WordDocHeader::parse(&d).unwrap();
        let s = h.to_string();
        assert!(s.contains("WordDoc"));
        assert!(s.contains("Word 97"));
    }

    // ── VbaProjectStream ──────────────────────────────────────────────────────

    #[test]
    fn test_vba_project_stream_valid() {
        let data = vec![0x61, 0x00, 0xAA, 0xBB, b'V', b'B', b'A', b'P'];
        let v = VbaProjectStream::parse(&data).unwrap();
        assert!(v.has_vba_signature);
        assert_eq!(v.stream_length, 8);
    }

    #[test]
    fn test_vba_project_stream_empty() {
        assert!(matches!(
            VbaProjectStream::parse(&[]),
            Err(StreamError::Truncated)
        ));
    }

    #[test]
    fn test_vba_project_stream_no_sig() {
        let data = vec![0xFF, 0xFF, 0x00, 0x00];
        let v = VbaProjectStream::parse(&data).unwrap();
        assert!(!v.has_vba_signature);
    }

    // ── WorkbookStream ────────────────────────────────────────────────────────

    #[test]
    fn test_workbook_stream_valid() {
        let d = make_workbook_stream();
        let wb = WorkbookStream::parse(&d).unwrap();
        assert_eq!(wb.bof_type, 0x0809);
        assert_eq!(wb.version_description(), "Excel 97-2003 (BIFF8)");
        assert_eq!(wb.doc_type_description(), "Workbook globals");
        assert!(!wb.is_encrypted);
    }

    #[test]
    fn test_workbook_stream_invalid_bof() {
        let d = vec![0xFF, 0xFF, 0x00, 0x00];
        assert!(matches!(
            WorkbookStream::parse(&d),
            Err(StreamError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_workbook_stream_truncated() {
        assert!(matches!(
            WorkbookStream::parse(&[0u8; 2]),
            Err(StreamError::Truncated)
        ));
    }

    // ── OleStreamAnalyzer ────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_ingest_word() {
        let mut a = OleStreamAnalyzer::new();
        a.ingest_stream("WordDocument", &make_word_doc_stream());
        assert_eq!(a.doc_type, Some(DocumentType::Word));
        assert!(a.word_doc.is_some());
    }

    #[test]
    fn test_analyzer_ingest_workbook() {
        let mut a = OleStreamAnalyzer::new();
        a.ingest_stream("Workbook", &make_workbook_stream());
        assert_eq!(a.doc_type, Some(DocumentType::Excel));
        assert!(a.workbook.is_some());
    }

    #[test]
    fn test_analyzer_has_vba() {
        let mut a = OleStreamAnalyzer::new();
        a.ingest_stream("_VBA_PROJECT", &[0x61, 0x00, 0x00, 0x00]);
        assert!(a.has_vba());
    }

    #[test]
    fn test_analyzer_display() {
        let a = OleStreamAnalyzer::new();
        let s = a.to_string();
        assert!(s.contains("OleStreamAnalyzer"));
    }

    #[test]
    fn test_analyzer_root_clsid() {
        let mut a = OleStreamAnalyzer::new();
        a.set_root_clsid(CLSID_WORD97);
        assert_eq!(a.doc_type, Some(DocumentType::Word));
    }

    // ── ClsidClassifier ───────────────────────────────────────────────────────

    #[test]
    fn test_clsid_classifier_known() {
        let c = ClsidClassifier::new();
        let r = c.classify(&CLSID_WORD97).unwrap();
        assert!(r.0.contains("Word"));
        assert_eq!(r.1, DocumentType::Word);
    }

    #[test]
    fn test_clsid_classifier_unknown() {
        let c = ClsidClassifier::new();
        assert!(c.classify(&[0u8; 16]).is_none());
    }

    #[test]
    fn test_clsid_classifier_register() {
        let mut c = ClsidClassifier::new();
        let custom_clsid = [0xAAu8; 16];
        c.register(custom_clsid, "Custom App", DocumentType::Custom("custom".into()));
        assert!(c.classify(&custom_clsid).is_some());
    }

    // ── StreamInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_stream_info_classify_word() {
        let info = StreamInfo::classify("WordDocument", &[0xEC, 0xA5, 0xC1, 0x00]);
        assert_eq!(info.category, StreamCategory::WordContent);
    }

    #[test]
    fn test_stream_info_classify_vba() {
        let info = StreamInfo::classify("VBA/Module1", &[]);
        assert_eq!(info.category, StreamCategory::VbaModule);
    }

    #[test]
    fn test_stream_info_display() {
        let info = StreamInfo::classify("Test", b"hello world test data");
        let s = info.to_string();
        assert!(s.contains("Test"));
    }

    #[test]
    fn test_extract_printable() {
        let data = b"AB\x00hello world\x00\x01test";
        let runs = extract_printable(data, 4);
        assert!(runs.iter().any(|r| r == "hello world"));
    }
}
