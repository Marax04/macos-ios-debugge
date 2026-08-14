//! `ole_stream_analyzer` — high-level analysis of named streams inside OLE2 files.
//!
//! Provides heuristics and structured parsers for the most forensically relevant
//! streams: `WordDocument`, `Workbook`, `_VBA_PROJECT`, `VBA/dir`, `SummaryInformation`,
//! `\x05DocumentSummaryInformation`, and `\x01Ole`.  Detects suspicious properties,
//! auto-exec macros, embedded objects, and version metadata.
//!
//! # Design note — intentionally separate from `ole_streams`
//!
//! This module's [`OleStreamAnalyzer`] is a **stateless per-stream analyzer**:
//! call [`OleStreamAnalyzer::analyze`] with a stream name and raw bytes and
//! receive a [`StreamAnalysisResult`] with forensic notes, suspicion flags,
//! and parsed sub-structures specific to that stream type.
//!
//! [`crate::ole_streams::OleStreamAnalyzer`] is a **stateful document-level
//! builder** that accumulates multiple streams and exposes document-wide
//! properties (doc type, encryption, CLSID).
//!
//! Both modules parse `WordDocument` and `_VBA_PROJECT` streams, but with
//! different field coverage and error handling.  They are kept separate rather
//! than merged because they serve distinct consumers (forensic per-stream
//! analysis vs document-level classification).

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// OleStreamKind

/// Classification of a named stream based on its name and/or content signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OleStreamKind {
    /// Microsoft Word binary document stream (`WordDocument`).
    WordDocument,
    /// Excel workbook stream (`Workbook` / `Book`).
    Workbook,
    /// VBA project root stream (`_VBA_PROJECT`).
    VbaProject,
    /// VBA compiled/compressed source (`VBA/dir` or module streams).
    VbaDir,
    /// Summary information property set (`\x05SummaryInformation`).
    SummaryInformation,
    /// Document summary information property set.
    DocumentSummaryInformation,
    /// OLE1 link/embed header (`\x01Ole`).
    OleLink,
    /// Equation editor stream (CVE-2017-11882 related).
    EquationEditor,
    /// `PowerPoint` presentation stream (`PowerPoint Document`).
    PowerPointDocument,
    /// Generic / unrecognised stream.
    Unknown,
}

impl OleStreamKind {
    /// Classify a stream by its name.
    #[must_use] 
    pub fn from_name(name: &str) -> Self {
        match name {
            "WordDocument" => Self::WordDocument,
            "Workbook" | "Book" => Self::Workbook,
            "_VBA_PROJECT" => Self::VbaProject,
            "dir" => Self::VbaDir,
            "\x05SummaryInformation" => Self::SummaryInformation,
            "\x05DocumentSummaryInformation" => Self::DocumentSummaryInformation,
            "\x01Ole" => Self::OleLink,
            "Equation Native" => Self::EquationEditor,
            "PowerPoint Document" => Self::PowerPointDocument,
            _ => Self::Unknown,
        }
    }

    /// Return `true` if this stream kind is VBA-related.
    #[must_use] 
    pub const fn is_vba(&self) -> bool {
        matches!(self, Self::VbaProject | Self::VbaDir)
    }

    /// Return `true` if this stream kind poses potential macro/code execution risk.
    #[must_use] 
    pub const fn is_code_bearing(&self) -> bool {
        matches!(
            self,
            Self::VbaProject
                | Self::VbaDir
                | Self::EquationEditor
        )
    }
}

impl fmt::Display for OleStreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::WordDocument => "WordDocument",
            Self::Workbook => "Workbook",
            Self::VbaProject => "_VBA_PROJECT",
            Self::VbaDir => "VBA/dir",
            Self::SummaryInformation => "SummaryInformation",
            Self::DocumentSummaryInformation => "DocumentSummaryInformation",
            Self::OleLink => "OleLink",
            Self::EquationEditor => "EquationEditor",
            Self::PowerPointDocument => "PowerPointDocument",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// WordDocument

/// Information extracted from a `WordDocument` stream.
#[derive(Debug, Clone)]
pub struct WordDocument {
    /// `wIdent` field (0xA5EC for .doc).
    pub w_ident: u16,
    /// `nFib` (version number).
    pub n_fib: u16,
    /// `fEncrypted` flag.
    pub encrypted: bool,
    /// `fWhichTblStm` — which table stream is active (0 or 1).
    pub which_tbl_stm: u8,
    /// `ccpText` — count of characters in main text.
    pub ccp_text: u32,
    /// File information block offset / length sanity.
    pub fib_len: usize,
}

impl WordDocument {
    /// Parse the `WordDocument` stream. Returns `None` if data is too short.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 { return None; }
        let w_ident   = u16::from_le_bytes([data[0], data[1]]);
        let n_fib     = u16::from_le_bytes([data[2], data[3]]);
        if w_ident != 0xA5EC && w_ident != 0xA5DC && w_ident != 0xA5DB { return None; }
        // flags byte at offset 10
        let flags     = u16::from_le_bytes([data[10], data[11]]);
        let encrypted = (flags >> 8) & 0x01 != 0;
        let which_tbl_stm = ((flags >> 9) & 0x01) as u8;
        // ccpText at offset 128 in FIB (if available)
        let ccp_text = if data.len() >= 132 {
            u32::from_le_bytes([data[128], data[129], data[130], data[131]])
        } else { 0 };

        Some(Self { w_ident, n_fib, encrypted, which_tbl_stm, ccp_text, fib_len: data.len() })
    }

    /// Return the Word version name.
    #[must_use] 
    pub const fn version_name(&self) -> &'static str {
        match self.n_fib {
            0x0065 => "Word 6.0 / 95",
            0x00C1 => "Word 97",
            0x00D9 => "Word 2000",
            0x0101 => "Word 2002 (XP)",
            0x010C => "Word 2003",
            0x0112 => "Word 2007+",
            _ => "Unknown Word version",
        }
    }
}

// ---------------------------------------------------------------------------
// VbaProject

/// Metadata extracted from a `_VBA_PROJECT` stream.
#[derive(Debug, Clone)]
pub struct VbaProject {
    /// Reserved signature bytes (0x61 0x4C at offset 0..2).
    pub signature_ok: bool,
    /// VBA version (high byte).
    pub performance_cache_version: u16,
    /// Approximate size of the compiled p-code cache.
    pub cache_size: usize,
    /// Whether the stream appears to contain a valid VBA header.
    pub valid: bool,
}

impl VbaProject {
    /// Parse `_VBA_PROJECT` stream.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self { signature_ok: false, performance_cache_version: 0, cache_size: 0, valid: false };
        }
        // Bytes 0x00–0x01 should be 0x61 0x4C (VBA6 signature)
        let signature_ok = data[0] == 0x61 && data[1] == 0x4C;
        let performance_cache_version = u16::from_le_bytes([data[2], data[3]]);
        Self {
            signature_ok,
            performance_cache_version,
            cache_size: data.len(),
            valid: signature_ok,
        }
    }
}

// ---------------------------------------------------------------------------
// EmbeddedOle

/// Information about an OLE embedded object (`\x01Ole` stream).
#[derive(Debug, Clone)]
pub struct EmbeddedOle {
    /// OLE version (typically 2).
    pub ole_version: u32,
    /// Flags field.
    pub flags: u32,
    /// Linked or embedded.
    pub is_linked: bool,
}

impl EmbeddedOle {
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        let ole_version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags       = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let is_linked   = (flags & 0x1) != 0;
        Some(Self { ole_version, flags, is_linked })
    }
}

// ---------------------------------------------------------------------------
// PropertySet parsing (SummaryInformation)

/// A parsed property from a Windows property set stream.
#[derive(Debug, Clone)]
pub struct PropertyValue {
    pub prop_id: u32,
    pub variant_type: u16,
    /// The raw value bytes.
    pub raw: Vec<u8>,
    /// String value if variant is `VT_LPSTR` or `VT_LPWSTR`.
    pub string_value: Option<String>,
    /// Integer value for `VT_I4` / `VT_UI4`.
    pub int_value: Option<i64>,
}

/// A property set parsed from a `SummaryInformation` or `DocumentSummaryInformation` stream.
#[derive(Debug, Clone, Default)]
pub struct PropertySet {
    pub properties: HashMap<u32, PropertyValue>,
    pub format_id: [u8; 16],
}

impl PropertySet {
    /// Minimalist property set parser.  Handles `VT_LPSTR`, `VT_I4`, `VT_BOOL`.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Header: ByteOrder(2) + Version(2) + SystemIdentifier(4) + CLSID(16) + NumSets(4)
        if data.len() < 28 { return None; }
        let byte_order = u16::from_le_bytes([data[0], data[1]]);
        if byte_order != 0xFFFE { return None; }
        let num_sets = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        if num_sets < 1 { return None; }
        // First set: FMTID(16) + Offset(4)
        if data.len() < 48 { return None; }
        let mut format_id = [0u8; 16];
        format_id.copy_from_slice(&data[28..44]);
        let set_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        if set_offset + 8 > data.len() { return None; }
        let set = &data[set_offset..];
        let _set_size = u32::from_le_bytes([set[0], set[1], set[2], set[3]]) as usize;
        let num_props  = u32::from_le_bytes([set[4], set[5], set[6], set[7]]) as usize;
        if set.len() < 8 + num_props * 8 { return None; }

        let mut properties = HashMap::new();
        for i in 0..num_props {
            let base = 8 + i * 8;
            let prop_id = u32::from_le_bytes([set[base], set[base+1], set[base+2], set[base+3]]);
            let value_offset = u32::from_le_bytes([set[base+4], set[base+5], set[base+6], set[base+7]]) as usize;
            if value_offset + 4 > set.len() { continue; }
            let variant_type = u16::from_le_bytes([set[value_offset], set[value_offset+1]]);
            let (string_value, int_value, raw) = match variant_type {
                0x001E => { // VT_LPSTR
                    if value_offset + 8 > set.len() { continue; }
                    let len = u32::from_le_bytes([
                        set[value_offset+4], set[value_offset+5],
                        set[value_offset+6], set[value_offset+7],
                    ]) as usize;
                    let str_off = value_offset + 8;
                    if str_off + len > set.len() { continue; }
                    let s = String::from_utf8_lossy(&set[str_off..str_off+len])
                        .trim_end_matches('\0').to_string();
                    (Some(s), None, set[value_offset..value_offset+4+len.min(64)].to_vec())
                }
                0x0003 => { // VT_I4
                    if value_offset + 8 > set.len() { continue; }
                    let v = i64::from(i32::from_le_bytes([
                        set[value_offset+4], set[value_offset+5],
                        set[value_offset+6], set[value_offset+7],
                    ]));
                    (None, Some(v), vec![])
                }
                _ => (None, None, vec![]),
            };
            properties.insert(prop_id, PropertyValue { prop_id, variant_type, raw, string_value, int_value });
        }

        Some(Self { properties, format_id })
    }

    /// Return the string value of property `id`, if present.
    #[must_use] 
    pub fn get_string(&self, id: u32) -> Option<&str> {
        self.properties.get(&id).and_then(|p| p.string_value.as_deref())
    }
}

// ---------------------------------------------------------------------------
// StreamAnalysisResult

/// Aggregate analysis result for a single OLE2 stream.
#[derive(Debug, Clone)]
pub struct StreamAnalysisResult {
    pub name: String,
    pub kind: OleStreamKind,
    pub raw_size: usize,
    pub word_doc: Option<WordDocument>,
    pub vba_project: Option<VbaProject>,
    pub embedded_ole: Option<EmbeddedOle>,
    pub property_set: Option<PropertySet>,
    pub suspicious: bool,
    pub notes: Vec<String>,
}

impl StreamAnalysisResult {
    const fn new(name: String, kind: OleStreamKind, data: &[u8]) -> Self {
        Self {
            name,
            kind,
            raw_size: data.len(),
            word_doc: None,
            vba_project: None,
            embedded_ole: None,
            property_set: None,
            suspicious: false,
            notes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// OleStreamAnalyzer

/// Analyzes individual named streams extracted from an OLE2 file.
#[derive(Debug, Default)]
pub struct OleStreamAnalyzer;

impl OleStreamAnalyzer {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Analyze a single named stream given its raw bytes.
    #[must_use] 
    pub fn analyze(&self, name: &str, data: &[u8]) -> StreamAnalysisResult {
        let kind = OleStreamKind::from_name(name);
        let mut result = StreamAnalysisResult::new(name.to_string(), kind, data);

        match kind {
            OleStreamKind::WordDocument => {
                if let Some(wd) = WordDocument::parse(data) {
                    if wd.encrypted {
                        result.suspicious = true;
                        result.notes.push("WordDocument: file is encrypted".into());
                    }
                    result.notes.push(format!("Word version: {} (nFib={:#x})", wd.version_name(), wd.n_fib));
                    result.word_doc = Some(wd);
                } else {
                    result.notes.push("WordDocument: failed to parse FIB".into());
                }
            }
            OleStreamKind::VbaProject => {
                let vba = VbaProject::parse(data);
                if !vba.signature_ok {
                    result.notes.push("_VBA_PROJECT: unexpected signature".into());
                }
                result.suspicious = true;
                result.notes.push("VBA project stream present".into());
                result.vba_project = Some(vba);
            }
            OleStreamKind::VbaDir => {
                result.suspicious = true;
                result.notes.push("VBA dir stream present — likely contains macro code".into());
                // Scan for auto-exec keywords in raw bytes using case-insensitive window
                // comparison to avoid allocating a full lowercased copy of the stream.
                let keywords: &[&[u8]] = &[b"auto_open", b"autoopen", b"auto_close", b"document_open", b"workbook_open"];
                for &keyword in keywords {
                    if data.windows(keyword.len()).any(|w| {
                        w.iter().zip(keyword.iter()).all(|(&a, &b)| a.to_ascii_lowercase() == b)
                    }) {
                        result.suspicious = true;
                        result.notes.push(format!("Auto-exec keyword found: {}", String::from_utf8_lossy(keyword)));
                    }
                }
            }
            OleStreamKind::OleLink => {
                if let Some(emb) = EmbeddedOle::parse(data) {
                    if emb.is_linked {
                        result.notes.push("OLE: linked object (potential external resource)".into());
                        result.suspicious = true;
                    }
                    result.embedded_ole = Some(emb);
                }
            }
            OleStreamKind::SummaryInformation | OleStreamKind::DocumentSummaryInformation => {
                if let Some(ps) = PropertySet::parse(data) {
                    // Property IDs for SummaryInformation:
                    // 4 = Author, 8 = LastAuthor, 18 = AppName
                    if let Some(app) = ps.get_string(18) {
                        result.notes.push(format!("App: {app}"));
                    }
                    result.property_set = Some(ps);
                }
            }
            OleStreamKind::EquationEditor => {
                result.suspicious = true;
                result.notes.push("Equation Editor stream detected — check for CVE-2017-11882".into());
                // Very basic: look for shellcode patterns (high byte density).
                if data.len() > 64 {
                    let high_bytes = data.iter().filter(|&&b| b > 0x7f).count();
                    if high_bytes * 10 > data.len() * 3 {
                        result.notes.push("High-entropy equation stream — possible shellcode".into());
                    }
                }
            }
            _ => {}
        }

        // Generic: scan for PE header in any stream.
        if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
            result.suspicious = true;
            result.notes.push("Stream starts with MZ — embedded PE executable".into());
        }

        result
    }

    /// Analyze a collection of named streams and return aggregated results.
    #[must_use] 
    pub fn analyze_all(&self, streams: &[(&str, &[u8])]) -> Vec<StreamAnalysisResult> {
        streams.iter().map(|(name, data)| self.analyze(name, data)).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_kind_from_name() {
        assert_eq!(OleStreamKind::from_name("WordDocument"), OleStreamKind::WordDocument);
        assert_eq!(OleStreamKind::from_name("Workbook"), OleStreamKind::Workbook);
        assert_eq!(OleStreamKind::from_name("_VBA_PROJECT"), OleStreamKind::VbaProject);
        assert_eq!(OleStreamKind::from_name("unknown_stream"), OleStreamKind::Unknown);
    }

    #[test]
    fn test_vba_project_parse() {
        let data = vec![0x61, 0x4C, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00];
        let vba = VbaProject::parse(&data);
        assert!(vba.signature_ok);
        assert_eq!(vba.performance_cache_version, 0x3000);
    }

    #[test]
    fn test_vba_project_bad_sig() {
        let data = vec![0x00, 0x00, 0x00, 0x00];
        let vba = VbaProject::parse(&data);
        assert!(!vba.signature_ok);
    }

    #[test]
    fn test_embedded_ole_linked() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // ole_version
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // flags (linked)
        let emb = EmbeddedOle::parse(&data).unwrap();
        assert!(emb.is_linked);
    }

    #[test]
    fn test_analyzer_vba_suspicious() {
        let data = b"\x61\x4C\x00\x30".to_vec();
        let analyzer = OleStreamAnalyzer::new();
        let result = analyzer.analyze("_VBA_PROJECT", &data);
        assert!(result.suspicious);
        assert_eq!(result.kind, OleStreamKind::VbaProject);
    }

    #[test]
    fn test_analyzer_mz_header() {
        let data = b"MZ\x90\x00".to_vec();
        let analyzer = OleStreamAnalyzer::new();
        let result = analyzer.analyze("unknown", &data);
        assert!(result.suspicious);
    }

    #[test]
    fn test_equation_editor_suspicious() {
        let data = vec![0xAAu8; 128];
        let analyzer = OleStreamAnalyzer::new();
        let result = analyzer.analyze("Equation Native", &data);
        assert!(result.suspicious);
    }
}
