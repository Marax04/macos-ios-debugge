//! `rustre-loader-pdf`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: PDF
//! Loads PDF documents. Magic: `%PDF-`.

pub mod metadata;
pub mod parser;
pub mod pdf_exploit_analysis;
pub mod security;
pub mod structures;
pub mod pdf_full_parser;
pub mod pdf_malware_analyzer;
pub mod pdf_js_extractor;
pub mod pdf_stream_decoder;
pub mod pdf_object_graph;
pub mod pdf_javascript_extractor;
pub mod pdf_xref_parser;
pub mod pdf_object_parser;
pub mod pdf_trailer_analyzer;

use std::fmt;
use std::sync::Arc;

use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::loader::LoadResult;
use rustre_core::permissions::Permissions;
use rustre_core::{Loader, LoaderInput, NestedBinary, async_trait};

// â"€â"€ Error type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors produced by the PDF loader.
#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    /// Magic bytes do not match `%PDF-`.
    #[error("invalid magic")]
    InvalidMagic,
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// xref table parsing error.
    #[error("xref error: {0}")]
    XrefError(String),
    /// File is too short to parse.
    #[error("truncated data")]
    TruncatedData,
    /// A stream filter rejected structurally invalid input (e.g. an LZW code
    /// that names a dictionary entry past the end of the dictionary).
    #[error("invalid stream structure: {0}")]
    InvalidStructure(String),
}

// â"€â"€ Magic detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Returns `true` if `data` starts with the PDF magic bytes `%PDF-`.
#[must_use]
pub fn is_pdf(data: &[u8]) -> bool {
    data.starts_with(b"%PDF-")
}

// â"€â"€ PDF version â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// PDF version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfVersion {
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
}

impl fmt::Display for PdfVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDF-{}.{}", self.major, self.minor)
    }
}

// â"€â"€ PDF object kinds â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A PDF object value.
#[derive(Debug, Clone)]
pub enum PdfObjKind {
    /// Boolean value.
    Boolean(bool),
    /// Integer value.
    Integer(i64),
    /// Real (floating-point) value.
    Real(f64),
    /// Name object (prefixed with `/` in source).
    Name(String),
    /// String object.
    PdfString(String),
    /// Array of objects.
    Array(Vec<Self>),
    /// Dictionary.
    Dictionary(Vec<(String, Self)>),
    /// Stream object with its dictionary and raw data location.
    Stream {
        dict: Vec<(String, Self)>,
        offset: usize,
        length: usize,
    },
    /// Null object.
    Null,
    /// Indirect reference.
    Reference { obj: u32, generation: u32 },
}

impl fmt::Display for PdfObjKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Real(r) => write!(f, "{r}"),
            Self::Name(s) => write!(f, "/{s}"),
            Self::PdfString(s) => write!(f, "({s})"),
            Self::Array(_) => write!(f, "[...]"),
            Self::Dictionary(_) => write!(f, "<<...>>"),
            Self::Stream { .. } => write!(f, "stream"),
            Self::Null => write!(f, "null"),
            Self::Reference { obj, generation } => write!(f, "{obj} {generation} R"),
        }
    }
}

// â"€â"€ Xref entry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single cross-reference table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfXrefEntry {
    /// Object number.
    pub obj_num: u32,
    /// Generation number.
    pub generation: u32,
    /// Byte offset of the object in the file.
    pub offset: u64,
    /// Whether this entry is in-use.
    pub in_use: bool,
}

// â"€â"€ Trailer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// PDF trailer dictionary (simplified).
#[derive(Debug, Clone)]
pub struct PdfTrailer {
    /// Size of the cross-reference table.
    pub size: u32,
    /// Root object reference.
    pub root_ref: Option<u32>,
    /// Info object reference.
    pub info_ref: Option<u32>,
}

// â"€â"€ PdfDocument â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parsed PDF document.
#[derive(Debug, Clone)]
pub struct PdfDocument {
    /// PDF version.
    pub version: PdfVersion,
    /// Cross-reference entries.
    pub xref: Vec<PdfXrefEntry>,
    /// Trailer dictionary.
    pub trailer: PdfTrailer,
    /// Raw file bytes.
    pub raw: Vec<u8>,
}

impl PdfDocument {
    /// Parse a `PdfDocument` from `data`.
    ///
    /// # Errors
    /// Returns `PdfError::InvalidMagic` if the file does not start with `%PDF-`.
    /// Returns `PdfError::TruncatedData` if the file is too short.
    pub fn parse(data: &[u8]) -> Result<Self, PdfError> {
        if !is_pdf(data) {
            return Err(PdfError::InvalidMagic);
        }
        if data.len() < 7 {
            return Err(PdfError::TruncatedData);
        }

        // Parse version: bytes after "%PDF-" until newline/space
        let rest = &data[5..];
        let end = rest
            .iter()
            .position(|&b| b == b'\n' || b == b'\r' || b == b' ')
            .unwrap_or(rest.len().min(10));
        let version_str_raw = std::str::from_utf8(&rest[..end]).unwrap_or("");
        let version_str = if version_str_raw.is_empty() { "1.0" } else { version_str_raw };
        let (major, minor) = if let Some(dot_pos) = version_str.find('.') {
            let maj = version_str[..dot_pos].parse::<u8>().unwrap_or(1);
            let min = version_str[dot_pos + 1..].parse::<u8>().unwrap_or(0);
            (maj, min)
        } else {
            (1, 0)
        };
        let version = PdfVersion { major, minor };

        // Find xref section by searching backward from end of file.
        let xref = parse_xref(data);

        // Build simplified trailer.
        let trailer = parse_trailer(data);

        Ok(Self {
            version,
            xref,
            trailer,
            raw: data.to_vec(),
        })
    }

    /// Returns `true` if the trailer contains an `/Encrypt` entry.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.raw.windows(8).any(|w| w == b"/Encrypt")
    }

    /// Returns the number of xref entries.
    #[must_use]
    pub const fn obj_count(&self) -> usize {
        self.xref.len()
    }
}

/// Parse xref entries from `data` by finding the "xref" keyword.
fn parse_xref(data: &[u8]) -> Vec<PdfXrefEntry> {
    let mut entries = Vec::new();
    // Search backward from end for "xref\n" or "xref\r"
    let xref_needle = b"xref";
    let mut xref_pos = None;
    // Simple forward scan (backward scan is expensive; this is adequate for our purposes).
    // Skip occurrences that are the tail of "startxref".
    for (i, window) in data.windows(xref_needle.len()).enumerate() {
        if window == xref_needle {
            if i >= 5 && &data[i - 5..i] == b"start" {
                continue;
            }
            xref_pos = Some(i);
            // Keep looking for the last standalone occurrence
        }
    }
    let xref_pos = match xref_pos {
        Some(p) => p,
        None => return entries,
    };

    // Parse xref table: skip "xref\n", then read "obj_first count\n" subsections
    let mut pos = xref_pos + 4;
    // Skip whitespace
    while pos < data.len() && (data[pos] == b'\n' || data[pos] == b'\r' || data[pos] == b' ') {
        pos += 1;
    }

    // Read one subsection header: "first_obj count"
    if let Some(newline) = data[pos..].iter().position(|&b| b == b'\n' || b == b'\r') {
        let header_bytes = &data[pos..pos + newline];
        if let Ok(header_str) = std::str::from_utf8(header_bytes) {
            let parts: Vec<&str> = header_str.split_ascii_whitespace().collect();
            if parts.len() == 2 {
                let first_obj: u32 = parts[0].parse().unwrap_or(0);
                let count: u32 = parts[1].parse().unwrap_or(0);
                pos += newline + 1;
                // Each xref entry is exactly 20 bytes: "nnnnnnnnnn ggggg f/n \r\n"
                for i in 0..count {
                    if pos + 20 > data.len() {
                        break;
                    }
                    let entry_bytes = &data[pos..pos + 20];
                    if let Ok(entry_str) = std::str::from_utf8(entry_bytes) {
                        let ep: Vec<&str> = entry_str.split_ascii_whitespace().collect();
                        if ep.len() >= 3 {
                            let offset: u64 = ep[0].parse().unwrap_or(0);
                            let generation: u32 = ep[1].parse().unwrap_or(0);
                            let in_use = ep[2] == "n";
                            let obj_num = match first_obj.checked_add(i) {
                                Some(n) => n,
                                None => break, // integer overflow: malformed xref
                            };
                            entries.push(PdfXrefEntry {
                                obj_num,
                                generation,
                                offset,
                                in_use,
                            });
                        }
                    }
                    pos += 20;
                }
            }
        }
    }

    entries
}

/// Parse simplified trailer dictionary (just size, root, info).
fn parse_trailer(data: &[u8]) -> PdfTrailer {
    // Find the last "trailer" keyword (7 bytes) in the file.
    let trailer_keyword = b"trailer";
    let trailer_start = data
        .windows(trailer_keyword.len())
        .enumerate()
        .filter(|(_, w)| *w == trailer_keyword)
        .map(|(i, _)| i)
        .next_back();

    let mut size: u32 = 0;
    let mut root_ref: Option<u32> = None;
    let mut info_ref: Option<u32> = None;

    if let Some(kw_pos) = trailer_start {
        // Skip "trailer" and any whitespace, then find the dictionary "<<...>>"
        let after_kw = &data[kw_pos + trailer_keyword.len()..];
        // Find opening "<<"
        if let Some(dict_open) = after_kw.windows(2).position(|w| w == b"<<") {
            let dict_start = dict_open + 2;
            // Find closing ">>"
            let dict_end = after_kw[dict_start..]
                .windows(2)
                .position(|w| w == b">>")
                .map_or(after_kw.len(), |p| dict_start + p);
            let dict_bytes = &after_kw[dict_start..dict_end];
            let dict_str = std::str::from_utf8(dict_bytes).unwrap_or("");

            // Extract /Size <n>
            if let Some(sz) = extract_dict_integer(dict_str, "/Size") {
                size = sz;
            }
            // Extract /Root <n> <gen> R
            if let Some(r) = extract_dict_ref(dict_str, "/Root") {
                root_ref = Some(r);
            }
            // Extract /Info <n> <gen> R
            if let Some(r) = extract_dict_ref(dict_str, "/Info") {
                info_ref = Some(r);
            }
        }
    }

    // Fall back to counting " obj" occurrences when /Size is missing.
    if size == 0 {
        let count = data.windows(4).filter(|w| *w == b" obj").count();
        size = u32::try_from(count).unwrap_or(u32::MAX);
    }

    PdfTrailer {
        size,
        root_ref,
        info_ref,
    }
}

/// Extract an integer value for a PDF dictionary key like `/Size 42`.
fn extract_dict_integer(dict: &str, key: &str) -> Option<u32> {
    let pos = dict.find(key)?;
    let rest = dict[pos + key.len()..].trim_start();
    rest.split_ascii_whitespace().next()?.parse().ok()
}

/// Extract an object-number from a PDF indirect reference like `/Root 1 0 R`.
fn extract_dict_ref(dict: &str, key: &str) -> Option<u32> {
    let pos = dict.find(key)?;
    let rest = dict[pos + key.len()..].trim_start();
    let mut parts = rest.split_ascii_whitespace();
    let obj_num: u32 = parts.next()?.parse().ok()?;
    // Verify the token after generation number is "R"
    let _gen = parts.next()?;
    if parts.next()? == "R" {
        Some(obj_num)
    } else {
        None
    }
}

// â"€â"€ Utility functions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extract the PDF version string (e.g. `"1.7"` or `"2.0"`) from the header line.
#[must_use]
pub fn pdf_version(data: &[u8]) -> Option<String> {
    if !is_pdf(data) {
        return None;
    }
    let rest = data.get(5..)?;
    let end = rest
        .iter()
        .position(|&b| !b.is_ascii_digit() && b != b'.')
        .unwrap_or(rest.len().min(10));
    let version = std::str::from_utf8(&rest[..end]).ok()?.to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Returns `true` if `data` contains a `/JavaScript` PDF name object.
#[must_use]
pub fn has_javascript(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"/JavaScript")
}

/// Returns `true` if `data` contains an `/EmbeddedFile` entry.
#[must_use]
pub fn has_embedded_files(data: &[u8]) -> bool {
    data.windows(13).any(|w| w == b"/EmbeddedFile")
}

// â"€â"€ Architecture stub â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Minimal Architecture stub for PDF (document, not executable).
#[derive(Debug)]
pub struct PdfArch;

impl Architecture for PdfArch {
    fn name(&self) -> &str {
        "pdf"
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let size: usize = 1;
        Ok(Instruction::new(
            address,
            size,
            "data",
            bytes[..size].to_vec(),
        ))
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// â"€â"€ Loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Loader for PDF documents.
#[derive(Debug)]
pub struct PdfLoader;

#[async_trait]
impl Loader for PdfLoader {
    fn name(&self) -> &str {
        "pdf"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_pdf(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, rustre_core::Address::as_u64);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            let end = base.checked_add(size).ok_or_else(|| {
                CoreError::InvalidFormat {
                    message: "base address + file size overflows u64".to_string(),
                }
            })?;
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(end)),
                permissions: Permissions::READ,
                data: input.data.clone(),
            });
        }

        let arch = Arc::new(PdfArch);
        let view_id = ViewId::from_raw(1);
        let view = BinaryView::new(
            view_id,
            input.uri,
            arch,
            Endian::Little,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// â"€â"€ xref_offsets â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse the cross-reference table starting from the `startxref` keyword near
/// the end of the file and return `(object_id, file_offset)` pairs for every
/// in-use object entry found.
///
/// Algorithm:
/// 1. Scan backward for the last `startxref` keyword to find the xref offset.
/// 2. Jump to that offset, expect an `xref` keyword.
/// 3. Read subsection headers and 20-byte entries.
#[must_use]
pub fn xref_offsets(bytes: &[u8]) -> Vec<(u32, u64)> {
    // Find the last "startxref" in the file (search from end).
    let needle = b"startxref";
    let sxref_pos = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .next_back();

    let sxref_pos = match sxref_pos {
        Some(p) => p,
        None => return vec![],
    };

    // After "startxref" skip whitespace/newline to find the offset number.
    let after = &bytes[sxref_pos + needle.len()..];
    let skip = after
        .iter()
        .take_while(|&&b| b == b'\n' || b == b'\r' || b == b' ')
        .count();
    let num_start = sxref_pos + needle.len() + skip;
    let num_end = bytes[num_start..]
        .iter()
        .take_while(|&&b| b.is_ascii_digit())
        .count();
    if num_end == 0 {
        return vec![];
    }

    let xref_offset: usize = std::str::from_utf8(&bytes[num_start..num_start + num_end])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if xref_offset + 4 > bytes.len() {
        return vec![];
    }
    if &bytes[xref_offset..xref_offset + 4] != b"xref" {
        return vec![];
    }

    // Parse all subsections.
    let mut pos = xref_offset + 4;
    let mut result = Vec::new();
    loop {
        // Skip whitespace.
        while pos < bytes.len() && matches!(bytes[pos], b'\n' | b'\r' | b' ' | b'\t') {
            pos += 1;
        }
        // Check if we have hit "trailer" or EOF.
        if pos + 7 <= bytes.len() && &bytes[pos..pos + 7] == b"trailer" {
            break;
        }
        if pos >= bytes.len() {
            break;
        }

        // Read subsection header "first_obj count".
        let line_end = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .unwrap_or(bytes.len() - pos);
        let header_str = std::str::from_utf8(&bytes[pos..pos + line_end]).unwrap_or("");
        let parts: Vec<&str> = header_str.split_ascii_whitespace().collect();
        if parts.len() < 2 {
            break;
        }
        let first_obj: u32 = parts[0].parse().unwrap_or(0);
        let count: u32 = parts[1].parse().unwrap_or(0);
        pos += line_end + 1;
        if bytes[pos..].first().copied() == Some(b'\r') {
            pos += 1;
        }

        // Read 'count' 20-byte entries.
        for i in 0..count {
            if pos + 20 > bytes.len() {
                break;
            }
            let entry = &bytes[pos..pos + 20];
            if let Ok(s) = std::str::from_utf8(entry) {
                let ep: Vec<&str> = s.split_ascii_whitespace().collect();
                if ep.len() >= 3 && ep[2] == "n"
                    && let Ok(off) = ep[0].parse::<u64>()
                        && let Some(obj_num) = first_obj.checked_add(i) {
                            result.push((obj_num, off));
                        }
            }
            pos += 20;
        }
    }

    result
}

// â"€â"€ PdfStream / extract_streams â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A PDF stream object located in the file.
#[derive(Debug, Clone)]
pub struct PdfStream {
    /// Object number of the stream.
    pub object_id: u32,
    /// Byte offset of the stream data (after `stream\n`).
    pub offset: usize,
    /// Length of the stream data in bytes.
    pub length: usize,
    /// Filter name (e.g. `"FlateDecode"`, `"ASCIIHexDecode"`), if present.
    pub filter: Option<String>,
}

/// Scan `bytes` for PDF stream objects and return metadata for each.
///
/// A stream is identified by the pattern:
/// `N 0 obj\n<<—¦/Length L—¦>>\nstream\n—¦\nendstream`
///
/// This parser does not fully parse dictionaries; it uses heuristic searches.
#[must_use]
pub fn extract_streams(bytes: &[u8]) -> Vec<PdfStream> {
    let mut streams = Vec::new();
    // Find each "stream\n" marker.
    let stream_marker = b"stream\n";
    let endstream_marker = b"endstream";

    let mut search_pos = 0usize;
    while search_pos + stream_marker.len() < bytes.len() {
        // Find next "stream\n".
        let sm_pos = match bytes[search_pos..]
            .windows(stream_marker.len())
            .position(|w| w == stream_marker)
        {
            Some(p) => search_pos + p,
            None => break,
        };

        let data_start = sm_pos + stream_marker.len();

        // Walk backwards from sm_pos to find the matching object header "N G obj".
        let obj_id = find_obj_id_before(bytes, sm_pos);

        // Find "/Length N" in the dict between the last "obj\n" and "stream\n".
        let dict_start = find_dict_start(bytes, sm_pos);
        let length = parse_length_from_dict(&bytes[dict_start..sm_pos]);
        let filter = parse_filter_from_dict(&bytes[dict_start..sm_pos]);

        // Determine actual stream end.
        let end_pos = bytes[data_start..]
            .windows(endstream_marker.len())
            .position(|w| w == endstream_marker)
            .map_or(data_start + length.unwrap_or(0), |p| data_start + p);

        let actual_length = length.unwrap_or(end_pos.saturating_sub(data_start));

        streams.push(PdfStream {
            object_id: obj_id,
            offset: data_start,
            length: actual_length,
            filter,
        });

        search_pos = end_pos + endstream_marker.len();
    }

    streams
}

/// Walk backwards from `before` to find the object number of the enclosing `N G obj`.
fn find_obj_id_before(bytes: &[u8], before: usize) -> u32 {
    // Scan backwards for " obj" pattern.
    // Pattern is: "<obj_num> <gen_num> obj" e.g. "1 0 obj".
    // We find the last " obj" occurrence and parse the number before the preceding " ".
    let scan = &bytes[..before];
    let mut last_obj_off = None;
    for (i, w) in scan.windows(4).enumerate() {
        if w == b" obj" {
            last_obj_off = Some(i);
        }
    }
    let obj_pos = match last_obj_off {
        Some(p) => p,
        None => return 0,
    };
    // obj_pos points to the ' ' in " obj".
    // Walk back from obj_pos to find "N G" —" extract N (the object number).
    // Format: digits SP digits SP obj
    // Find the space before "obj_pos".
    if obj_pos == 0 {
        return 0;
    }
    // The char at obj_pos is ' '; scan back to find preceding space/newline.
    let before_space = obj_pos; // the space just before "obj"
    // Find the generation number token (second number) ending at before_space.
    // Walk back past the generation number.
    let mut gen_end = before_space;
    while gen_end > 0 && scan[gen_end - 1].is_ascii_digit() {
        gen_end -= 1;
    }
    if gen_end == 0 || scan[gen_end - 1] != b' ' {
        return 0;
    }
    let obj_num_end = gen_end - 1; // position of the space between obj_num and gen_num
    // Find start of object number.
    let mut obj_num_start = obj_num_end;
    while obj_num_start > 0 && scan[obj_num_start - 1].is_ascii_digit() {
        obj_num_start -= 1;
    }
    std::str::from_utf8(&scan[obj_num_start..obj_num_end])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Find the start of the object's dictionary, defined as the last `"<<"` before `before`.
fn find_dict_start(bytes: &[u8], before: usize) -> usize {
    let scan = &bytes[..before];
    scan.windows(2)
        .enumerate()
        .filter(|(_, w)| *w == b"<<")
        .map(|(i, _)| i)
        .next_back()
        .unwrap_or(0)
}

/// Extract the `/Length` integer from a raw dictionary slice.
fn parse_length_from_dict(dict: &[u8]) -> Option<usize> {
    let needle = b"/Length";
    let pos = dict.windows(needle.len()).position(|w| w == needle)?;
    let after = &dict[pos + needle.len()..];
    let skip = after
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\n' || b == b'\r')
        .count();
    let num_start = &after[skip..];
    let num_end = num_start
        .iter()
        .take_while(|&&b| b.is_ascii_digit())
        .count();
    if num_end == 0 {
        return None;
    }
    std::str::from_utf8(&num_start[..num_end])
        .ok()?
        .parse()
        .ok()
}

/// Extract the `/Filter` name from a raw dictionary slice.
fn parse_filter_from_dict(dict: &[u8]) -> Option<String> {
    let needle = b"/Filter";
    let pos = dict.windows(needle.len()).position(|w| w == needle)?;
    let after = &dict[pos + needle.len()..];
    let skip = after
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\n' || b == b'\r')
        .count();
    let rest = &after[skip..];
    // Expect a Name object: /FilterName
    if rest.first()? == &b'/' {
        let name_bytes = &rest[1..];
        let end = name_bytes
            .iter()
            .take_while(|&&b| b != b'/' && b != b'>' && b != b' ' && b != b'\n')
            .count();
        return Some(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
    }
    None
}

// â"€â"€ PdfJsExtractor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extracts JavaScript embedded in a PDF file.
#[derive(Debug, Default)]
pub struct PdfJsExtractor;

/// A JavaScript snippet found inside a PDF object.
#[derive(Debug, Clone)]
pub struct PdfJsEntry {
    /// Object number where the JS was found.
    pub object_id: u32,
    /// Byte offset in the file where the JS content begins.
    pub offset: usize,
    /// The JavaScript text (if recoverable as a string literal).
    pub source: String,
}

impl PdfJsExtractor {
    /// Create a new [`PdfJsExtractor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `bytes` for `/JS` and `/JavaScript` dictionary keys and return all
    /// JavaScript snippets found.
    ///
    /// PDF JavaScript can appear as:
    /// - `/JS (literal string)`
    /// - `/JS <hex string>`
    /// - `/JS N G R` (indirect reference —" we record the ref, not the value)
    #[must_use]
    pub fn extract(&self, bytes: &[u8]) -> Vec<PdfJsEntry> {
        let mut entries = Vec::new();

        // Scan for both "/JS" and "/JavaScript".
        let markers: &[&[u8]] = &[b"/JavaScript", b"/JS"];
        for marker in markers {
            let mut search_pos = 0usize;
            while search_pos + marker.len() < bytes.len() {
                let found = bytes[search_pos..]
                    .windows(marker.len())
                    .position(|w| w == *marker);
                let pos = match found {
                    Some(p) => search_pos + p,
                    None => break,
                };

                // Advance past the key and whitespace.
                let after_key = pos + marker.len();
                let skip = bytes[after_key..]
                    .iter()
                    .take_while(|&&b| b == b' ' || b == b'\n' || b == b'\r')
                    .count();
                let value_pos = after_key + skip;

                let obj_id = find_obj_id_before(bytes, pos);
                let source = extract_pdf_string_or_ref(bytes, value_pos);

                entries.push(PdfJsEntry {
                    object_id: obj_id,
                    offset: value_pos,
                    source,
                });
                search_pos = pos + marker.len();
            }
        }

        // Deduplicate by offset.
        entries.sort_by_key(|e| e.offset);
        entries.dedup_by_key(|e| e.offset);
        entries
    }
}

/// Try to read a PDF string literal `(...)` or hex string `<...>` at `pos`.
/// Returns the decoded string, or an empty string for indirect references.
fn extract_pdf_string_or_ref(bytes: &[u8], pos: usize) -> String {
    if pos >= bytes.len() {
        return String::new();
    }
    match bytes[pos] {
        b'(' => {
            // Literal string —" scan for matching ')' respecting escapes.
            let mut out = Vec::new();
            let mut i = pos + 1;
            let mut depth = 1i32;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'\\' => {
                        i += 2;
                    } // skip escape
                    b'(' => {
                        depth += 1;
                        out.push(b'(');
                        i += 1;
                    }
                    b')' => {
                        depth -= 1;
                        if depth > 0 {
                            out.push(b')');
                        }
                        i += 1;
                    }
                    b => {
                        out.push(b);
                        i += 1;
                    }
                }
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        b'<' => {
            // Hex string.
            let end = bytes[pos + 1..]
                .iter()
                .position(|&b| b == b'>')
                .unwrap_or(0);
            let hex = &bytes[pos + 1..pos + 1 + end];
            let decoded: Vec<u8> = hex
                .chunks(2)
                .filter_map(|c| {
                    let s = std::str::from_utf8(c).ok()?;
                    u8::from_str_radix(s.trim(), 16).ok()
                })
                .collect();
            String::from_utf8_lossy(&decoded).into_owned()
        }
        _ => {
            // Indirect reference or unknown —" capture the rest of the token.
            let end = bytes[pos..]
                .iter()
                .take_while(|&&b| b != b'>' && b != b'\n' && b != b'/')
                .count();
            String::from_utf8_lossy(&bytes[pos..pos + end])
                .trim()
                .to_string()
        }
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pdf(version: &str, extra: &[u8]) -> Vec<u8> {
        let mut data = format!("%PDF-{version}\n").into_bytes();
        data.extend_from_slice(extra);
        data
    }

    #[test]
    fn flate_decompress_actually_inflates() {
        // Round-trip, asserted against the *stub's* behaviour rather than
        // against the marker being absent from the compressed bytes: deflate
        // stores short literal runs verbatim, so a marker can survive
        // compression. `out == plain` plus `out != compressed[2..]` pins the
        // real property — the bytes were inflated, not merely reshaped.
        use std::io::Write as _;
        let plain = b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>";
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(plain).expect("compress");
        let compressed = enc.finish().expect("finish");

        let out = parser_flate_decompress(&compressed).expect("inflates");
        assert_eq!(out, plain, "output must be the plaintext");
        assert_ne!(
            out.as_slice(),
            &compressed[2..],
            "the old stub returned the input minus the zlib header; that must not pass"
        );
    }

    #[test]
    fn flate_decompress_rejects_garbage_instead_of_passing_it_through() {
        // Not zlib, not deflate: the honest answer is an error, not the input
        // handed back as though it had been decoded.
        let junk = [0xFFu8, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert!(parser_flate_decompress(&junk).is_err());
    }

    fn make_pdf_with_xref(version: &str) -> Vec<u8> {
        let mut data = format!("%PDF-{version}\n").into_bytes();
        data.extend_from_slice(b"1 0 obj\n<<>>\nendobj\n");
        data.extend_from_slice(b"xref\n0 2\n");
        data.extend_from_slice(b"0000000000 65535 f \r\n");
        data.extend_from_slice(b"0000000009 00000 n \r\n");
        data.extend_from_slice(b"trailer\n<<\n/Size 2\n>>\n");
        data.extend_from_slice(b"%%EOF\n");
        data
    }

    // â"€â"€ magic detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_is_pdf_valid() {
        assert!(is_pdf(&make_pdf("1.7", b"")));
    }

    #[test]
    fn test_is_pdf_wrong_magic() {
        assert!(!is_pdf(b"JFIF\xFF\xD8"));
    }

    #[test]
    fn test_is_pdf_too_short() {
        assert!(!is_pdf(b"%PDF"));
    }

    // â"€â"€ PdfVersion â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdf_version_display_17() {
        let v = PdfVersion { major: 1, minor: 7 };
        assert_eq!(v.to_string(), "PDF-1.7");
    }

    #[test]
    fn test_pdf_version_display_20() {
        let v = PdfVersion { major: 2, minor: 0 };
        assert_eq!(v.to_string(), "PDF-2.0");
    }

    // â"€â"€ PdfObjKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdf_obj_boolean_display() {
        let o = PdfObjKind::Boolean(true);
        assert_eq!(o.to_string(), "true");
    }

    #[test]
    fn test_pdf_obj_integer_display() {
        let o = PdfObjKind::Integer(42);
        assert_eq!(o.to_string(), "42");
    }

    #[test]
    fn test_pdf_obj_name_display() {
        let o = PdfObjKind::Name("Type".into());
        assert_eq!(o.to_string(), "/Type");
    }

    #[test]
    fn test_pdf_obj_reference_display() {
        let o = PdfObjKind::Reference {
            obj: 1,
            generation: 0,
        };
        assert_eq!(o.to_string(), "1 0 R");
    }

    #[test]
    fn test_pdf_obj_null_display() {
        assert_eq!(PdfObjKind::Null.to_string(), "null");
    }

    #[test]
    fn test_pdf_obj_real_display() {
        let o = PdfObjKind::Real(3.14_f64);
        assert!(o.to_string().contains("3.14"));
    }

    // â"€â"€ PdfXrefEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_xref_entry_fields() {
        let e = PdfXrefEntry {
            obj_num: 5,
            generation: 0,
            offset: 100,
            in_use: true,
        };
        assert_eq!(e.obj_num, 5);
        assert!(e.in_use);
    }

    // â"€â"€ PdfDocument â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdf_document_parse_version_17() {
        let data = make_pdf("1.7", b"");
        let doc = PdfDocument::parse(&data).unwrap();
        assert_eq!(doc.version.major, 1);
        assert_eq!(doc.version.minor, 7);
    }

    #[test]
    fn test_pdf_document_parse_version_20() {
        let data = make_pdf("2.0", b"");
        let doc = PdfDocument::parse(&data).unwrap();
        assert_eq!(doc.version.major, 2);
        assert_eq!(doc.version.minor, 0);
    }

    #[test]
    fn test_pdf_document_invalid_magic() {
        let err = PdfDocument::parse(b"not a pdf").unwrap_err();
        assert!(matches!(err, PdfError::InvalidMagic));
    }

    #[test]
    fn test_pdf_document_too_short() {
        let err = PdfDocument::parse(b"%PDF").unwrap_err();
        assert!(matches!(err, PdfError::InvalidMagic));
    }

    #[test]
    fn test_pdf_document_not_encrypted() {
        let data = make_pdf("1.7", b"clean content");
        let doc = PdfDocument::parse(&data).unwrap();
        assert!(!doc.is_encrypted());
    }

    #[test]
    fn test_pdf_document_is_encrypted() {
        let data = make_pdf("1.7", b"<</Encrypt 1 0 R>>");
        let doc = PdfDocument::parse(&data).unwrap();
        assert!(doc.is_encrypted());
    }

    #[test]
    fn test_pdf_document_with_xref() {
        let data = make_pdf_with_xref("1.6");
        let doc = PdfDocument::parse(&data).unwrap();
        assert_eq!(doc.version.major, 1);
        assert_eq!(doc.version.minor, 6);
        assert!(doc.obj_count() > 0);
    }

    #[test]
    fn test_pdf_document_obj_count() {
        let data = make_pdf("1.7", b"");
        let doc = PdfDocument::parse(&data).unwrap();
        assert_eq!(doc.obj_count(), doc.xref.len());
    }

    // â"€â"€ Utility functions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdf_version_fn_17() {
        let data = make_pdf("1.7", b"");
        assert_eq!(pdf_version(&data).unwrap(), "1.7");
    }

    #[test]
    fn test_pdf_version_fn_none() {
        assert!(pdf_version(b"not a pdf").is_none());
    }

    #[test]
    fn test_has_javascript_true() {
        let data = make_pdf("1.7", b"/JavaScript");
        assert!(has_javascript(&data));
    }

    #[test]
    fn test_has_javascript_false() {
        let data = make_pdf("1.7", b"clean");
        assert!(!has_javascript(&data));
    }

    #[test]
    fn test_has_embedded_files_true() {
        let data = make_pdf("1.7", b"/EmbeddedFile");
        assert!(has_embedded_files(&data));
    }

    // â"€â"€ Error display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_error_invalid_magic() {
        assert!(PdfError::InvalidMagic.to_string().contains("magic"));
    }

    #[test]
    fn test_error_parse_error() {
        let e = PdfError::ParseError("bad".into());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_error_xref_error() {
        let e = PdfError::XrefError("no xref".into());
        assert!(e.to_string().contains("no xref"));
    }

    #[test]
    fn test_error_truncated_data() {
        assert!(PdfError::TruncatedData.to_string().contains("truncated"));
    }

    // â"€â"€ Loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_loader_name() {
        assert_eq!(PdfLoader.name(), "pdf");
    }

    #[test]
    fn test_can_load_pdf() {
        let input = LoaderInput::new("doc.pdf", make_pdf("1.7", b""));
        assert!(PdfLoader.can_load(&input));
    }

    #[test]
    fn test_cannot_load_random() {
        let input = LoaderInput::new("file.bin", b"randomdata".to_vec());
        assert!(!PdfLoader.can_load(&input));
    }

    #[tokio::test]
    async fn test_load() {
        let input = LoaderInput::new("doc.pdf", make_pdf("1.7", b"content"));
        let result = PdfLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "doc.pdf");
    }

    #[tokio::test]
    async fn test_find_nested_empty() {
        let input = LoaderInput::new("doc.pdf", make_pdf("1.7", b""));
        let nested = PdfLoader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    // â"€â"€ xref_offsets â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_pdf_full_xref() -> Vec<u8> {
        let mut data: Vec<u8> = b"%PDF-1.7\n".to_vec();
        // Object 1 at offset 9.
        data.extend_from_slice(b"1 0 obj\n<<>>\nendobj\n");
        // Object 2 at offset 29.
        data.extend_from_slice(b"2 0 obj\n<</Length 5>>\nstream\nhello\nendstream\nendobj\n");
        let xref_off = data.len();
        data.extend_from_slice(b"xref\n0 3\n");
        data.extend_from_slice(b"0000000000 65535 f \r\n");
        data.extend_from_slice(b"0000000009 00000 n \r\n");
        data.extend_from_slice(b"0000000029 00000 n \r\n");
        data.extend_from_slice(b"trailer\n<<\n/Size 3\n>>\n");
        data.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        data
    }

    #[test]
    fn test_xref_offsets_basic() {
        let data = make_pdf_full_xref();
        let offsets = xref_offsets(&data);
        assert_eq!(offsets.len(), 2, "should find 2 in-use objects");
        assert_eq!(offsets[0].0, 1);
        assert_eq!(offsets[0].1, 9);
        assert_eq!(offsets[1].0, 2);
        assert_eq!(offsets[1].1, 29);
    }

    #[test]
    fn test_xref_offsets_no_startxref() {
        let data = make_pdf("1.7", b"no xref here");
        let offsets = xref_offsets(&data);
        assert!(offsets.is_empty());
    }

    // â"€â"€ extract_streams â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_pdf_with_stream(filter: Option<&str>) -> Vec<u8> {
        let content = b"hello world";
        let dict = if let Some(f) = filter {
            format!("<</Length {}\n/Filter /{}>>\n", content.len(), f)
        } else {
            format!("<</Length {}>>\n", content.len())
        };
        let mut data: Vec<u8> = b"%PDF-1.7\n1 0 obj\n".to_vec();
        data.extend_from_slice(dict.as_bytes());
        data.extend_from_slice(b"stream\n");
        data.extend_from_slice(content);
        data.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        data
    }

    #[test]
    fn test_extract_streams_finds_one() {
        let data = make_pdf_with_stream(None);
        let streams = extract_streams(&data);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].object_id, 1);
        assert_eq!(streams[0].length, b"hello world".len());
        assert!(streams[0].filter.is_none());
    }

    #[test]
    fn test_extract_streams_with_filter() {
        let data = make_pdf_with_stream(Some("FlateDecode"));
        let streams = extract_streams(&data);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].filter.as_deref(), Some("FlateDecode"));
    }

    #[test]
    fn test_extract_streams_empty() {
        let data = make_pdf("1.7", b"no streams here");
        let streams = extract_streams(&data);
        assert!(streams.is_empty());
    }

    // â"€â"€ PdfJsExtractor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_js_extractor_literal_string() {
        let mut data: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<\n/JS (alert(1);)\n>>\nendobj\n".to_vec();
        data.extend_from_slice(b"%%EOF\n");
        let extractor = PdfJsExtractor::new();
        let entries = extractor.extract(&data);
        assert!(!entries.is_empty());
        assert!(entries[0].source.contains("alert(1)"));
    }

    #[test]
    fn test_js_extractor_javascript_key() {
        let data = b"%PDF-1.7\n1 0 obj\n<<\n/JavaScript (var x=1;)\n>>\nendobj\n%%EOF\n";
        let extractor = PdfJsExtractor::new();
        let entries = extractor.extract(data);
        assert!(!entries.is_empty());
        assert!(entries[0].source.contains("var x=1"));
    }

    #[test]
    fn test_js_extractor_no_js() {
        let data = make_pdf("1.7", b"no javascript content here");
        let extractor = PdfJsExtractor::new();
        let entries = extractor.extract(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_js_extractor_hex_string() {
        // "alert()" hex-encoded.
        let hex = b"616c65727428293b"; // alert();
        let mut data: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<\n/JS <".to_vec();
        data.extend_from_slice(hex);
        data.extend_from_slice(b">\n>>\nendobj\n%%EOF\n");
        let extractor = PdfJsExtractor::new();
        let entries = extractor.extract(&data);
        assert!(!entries.is_empty());
        assert!(entries[0].source.contains("alert()"));
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§1  PdfDict + PdfObject
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

use std::collections::HashMap;

/// A PDF dictionary: an ordered list of (key, value) pairs.
#[derive(Debug, Clone, Default)]
pub struct PdfDict(pub Vec<(String, PdfObject)>);

impl PdfDict {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&PdfObject> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    #[must_use]
    pub fn get_name(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            PdfObject::Name(s) => Some(s.as_str()),
            _ => None,
        }
    }
    #[must_use]
    pub fn get_array(&self, key: &str) -> Option<&Vec<PdfObject>> {
        match self.get(key)? {
            PdfObject::Array(a) => Some(a),
            _ => None,
        }
    }
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            PdfObject::Integer(n) => Some(*n),
            _ => None,
        }
    }
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            PdfObject::Bool(b) => Some(*b),
            _ => None,
        }
    }
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    pub fn set(&mut self, key: impl Into<String>, value: PdfObject) {
        let key = key.into();
        if let Some(e) = self.0.iter_mut().find(|(k, _)| *k == key) {
            e.1 = value;
        } else {
            self.0.push((key, value));
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A fully-parsed PDF object.
#[derive(Debug, Clone)]
pub enum PdfObject {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Name(String),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Dict(PdfDict),
    Stream { dict: PdfDict, data: Vec<u8> },
    Indirect(u32, u16),
}

impl PdfObject {
    #[must_use]
    pub fn as_str_lossy(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::Bytes(b) => Some(String::from_utf8_lossy(b)),
            Self::Name(s) => Some(std::borrow::Cow::Borrowed(s.as_str())),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_dict(&self) -> Option<&PdfDict> {
        match self {
            Self::Dict(d) => Some(d),
            Self::Stream { dict, .. } => Some(dict),
            _ => None,
        }
    }
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§2  PdfParser
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Full-featured PDF parser with xref resolution and stream decoding.
pub struct PdfParser {
    pub data: Vec<u8>,
    pub xref: HashMap<u32, u64>,
    pub trailer: Option<PdfDict>,
    pub version: String,
    /// Byte offsets of the cross-reference sections already loaded.
    ///
    /// `/Prev` links each xref section to the previous one, and both
    /// `parse_xref_table` and `parse_xref_stream` follow it by calling
    /// `load_xref_at` again — so the chain is walked by mutual recursion with
    /// the next offset taken straight from the file.  Nothing stopped a
    /// document whose `/Prev` pointed back at an offset already being parsed:
    /// it recursed until the stack overflowed, which is a crash rather than an
    /// error a caller can handle, and a `/Prev` pointing at its own section is
    /// a few bytes to craft.
    ///
    /// Re-reading an offset already loaded is redundant in a well-formed file —
    /// the sections form a chain, not a graph — so refusing to re-enter one
    /// costs nothing and bounds the recursion by the number of distinct
    /// sections.  A visit set rather than a depth cap, because a heavily
    /// revised PDF legitimately has a long chain.
    loaded_xref_offsets: std::collections::HashSet<u64>,
}

/// Maximum depth of nested PDF containers (`<<…>>` and `[…]`).
///
/// Container nesting costs one input byte and one native stack frame per level,
/// so `[[[[[…` is a stack-exhaustion primitive without a cap. Real documents
/// nest a few levels; 128 is far above any legitimate file.
pub const MAX_NESTING_DEPTH: usize = 128;

impl PdfParser {
    pub fn parse(data: Vec<u8>) -> Result<Self, PdfError> {
        if !data.starts_with(b"%PDF-") {
            return Err(PdfError::InvalidMagic);
        }
        if data.len() < 8 {
            return Err(PdfError::TruncatedData);
        }
        let ver_end = data[5..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r' || b == b' ')
            .unwrap_or(data.len() - 5)
            .min(8);
        let version = std::str::from_utf8(&data[5..5 + ver_end])
            .unwrap_or("1.0")
            .to_string();
        let mut parser = Self {
            data,
            xref: HashMap::new(),
            trailer: None,
            version,
            loaded_xref_offsets: std::collections::HashSet::new(),
        };
        if parser.load_xref_chain().is_err() {
            let _ = parser.parse_tolerant();
        }
        Ok(parser)
    }

    fn load_xref_chain(&mut self) -> Result<(), PdfError> {
        let offset = self.find_startxref_offset()?;
        self.load_xref_at(offset)
    }

    fn find_startxref_offset(&self) -> Result<u64, PdfError> {
        let needle = b"startxref";
        let search_start = self.data.len().saturating_sub(1024);
        let slice = &self.data[search_start..];
        let last = slice
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .next_back()
            .ok_or_else(|| PdfError::XrefError("startxref not found".into()))?;
        let abs_pos = search_start + last + needle.len();
        let after = &self.data[abs_pos..];
        let skip = after
            .iter()
            .take_while(|&&b| b == b'\n' || b == b'\r' || b == b' ')
            .count();
        let num_start = abs_pos + skip;
        let num_len = self.data[num_start..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        if num_len == 0 {
            return Err(PdfError::XrefError("startxref number missing".into()));
        }
        let s = std::str::from_utf8(&self.data[num_start..num_start + num_len])
            .map_err(|e| PdfError::XrefError(e.to_string()))?;
        s.parse::<u64>()
            .map_err(|e| PdfError::XrefError(e.to_string()))
    }

    fn load_xref_at(&mut self, offset: u64) -> Result<(), PdfError> {
        // See `loaded_xref_offsets`: a `/Prev` cycle would otherwise recurse
        // through here until the stack overflowed.
        if !self.loaded_xref_offsets.insert(offset) {
            return Ok(());
        }
        let off = offset as usize;
        if off + 4 > self.data.len() {
            return Err(PdfError::XrefError("xref offset out of bounds".into()));
        }
        if &self.data[off..off + 4] == b"xref" {
            self.parse_xref_table(off)
        } else {
            self.parse_xref_stream(off)
        }
    }

    fn parse_xref_table(&mut self, mut pos: usize) -> Result<(), PdfError> {
        pos += 4;
        while pos < self.data.len() && matches!(self.data[pos], b'\n' | b'\r' | b' ') {
            pos += 1;
        }
        loop {
            if pos + 7 <= self.data.len() && &self.data[pos..pos + 7] == b"trailer" {
                pos += 7;
                while pos < self.data.len() && matches!(self.data[pos], b'\n' | b'\r' | b' ') {
                    pos += 1;
                }
                if pos + 2 <= self.data.len() && &self.data[pos..pos + 2] == b"<<" {
                    let (dict, _) = self.parse_dict(pos)?;
                    let prev = dict.get_int("Prev").map(|n| n as u64);
                    if self.trailer.is_none() {
                        self.trailer = Some(dict);
                    }
                    if let Some(p) = prev {
                        let _ = self.load_xref_at(p);
                    }
                }
                break;
            }
            if pos >= self.data.len() {
                break;
            }
            let line_end = self.data[pos..]
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
                .unwrap_or(self.data.len() - pos);
            let header = std::str::from_utf8(&self.data[pos..pos + line_end]).unwrap_or("");
            let parts: Vec<&str> = header.split_ascii_whitespace().collect();
            if parts.len() < 2 {
                break;
            }
            let first_obj: u32 = parts[0].parse().unwrap_or(0);
            let count: u32 = parts[1].parse().unwrap_or(0);
            pos += line_end + 1;
            if pos < self.data.len() && self.data[pos] == b'\r' {
                pos += 1;
            }
            for i in 0..count {
                if pos + 20 > self.data.len() {
                    break;
                }
                let entry = &self.data[pos..pos + 20];
                if let Ok(s) = std::str::from_utf8(entry) {
                    let ep: Vec<&str> = s.split_ascii_whitespace().collect();
                    if ep.len() >= 3 && ep[2] == "n"
                        && let Ok(off) = ep[0].parse::<u64>() {
                            self.xref.entry(first_obj + i).or_insert(off);
                        }
                }
                pos += 20;
                // Some PDFs use entries with a trailing space before the EOL,
                // making them 21 bytes. Consume any leftover EOL bytes.
                while pos < self.data.len() && matches!(self.data[pos], b'\r' | b'\n') {
                    pos += 1;
                }
            }
        }
        Ok(())
    }

    fn parse_xref_stream(&mut self, pos: usize) -> Result<(), PdfError> {
        let (obj_val, _) = self.parse_object_at(pos)?;
        let (dict, stream_data) = match obj_val {
            PdfObject::Stream { dict, data } => (dict, data),
            _ => {
                return Err(PdfError::XrefError(
                    "xref stream not a stream object".into(),
                ));
            }
        };
        let w: Vec<usize> = dict
            .get_array("W").map_or_else(|| vec![1, 2, 1], |a| {
                a.iter()
                    .filter_map(PdfObject::as_int)
                    .map(|n| n as usize)
                    .collect()
            });
        if w.len() < 3 {
            return Err(PdfError::XrefError("/W must have 3 elements".into()));
        }
        let size = dict.get_int("Size").unwrap_or(0) as u32;
        let index: Vec<u32> = dict
            .get_array("Index").map_or_else(|| vec![0, size], |a| {
                a.iter()
                    .filter_map(PdfObject::as_int)
                    .map(|n| n as u32)
                    .collect()
            });
        let row_size = w[0] + w[1] + w[2];
        if row_size == 0 {
            return Ok(());
        }
        let mut data_pos = 0usize;
        let mut pair_idx = 0usize;
        while pair_idx + 1 < index.len() {
            let first = index[pair_idx];
            let count = index[pair_idx + 1];
            pair_idx += 2;
            for i in 0..count {
                if data_pos + row_size > stream_data.len() {
                    break;
                }
                let row = &stream_data[data_pos..data_pos + row_size];
                let field_type = read_be_uint(row, 0, w[0]);
                let field2 = read_be_uint(row, w[0], w[1]);
                if field_type == 1 {
                    // `/Index [4294967295 4]` makes `first + i` wrap in release,
                    // aliasing object 0. Stop the run instead of aliasing.
                    let Some(obj_id) = first.checked_add(i) else {
                        break;
                    };
                    self.xref.entry(obj_id).or_insert(field2);
                }
                data_pos += row_size;
            }
        }
        if let Some(prev) = dict.get_int("Prev") {
            let _ = self.load_xref_at(prev as u64);
        }
        if self.trailer.is_none() {
            self.trailer = Some(dict);
        }
        Ok(())
    }

    #[must_use]
    pub fn get_object(&self, id: u32) -> Option<PdfObject> {
        let offset = *self.xref.get(&id)? as usize;
        self.parse_object_at(offset).ok().map(|(o, _)| o)
    }

    #[must_use]
    pub fn resolve(&self, obj: &PdfObject) -> PdfObject {
        match obj {
            PdfObject::Indirect(id, _) => self.get_object(*id).unwrap_or(PdfObject::Null),
            other => other.clone(),
        }
    }

    pub fn parse_object_at(&self, mut pos: usize) -> Result<(PdfObject, usize), PdfError> {
        pos = self.skip_ws(pos);
        if pos >= self.data.len() {
            return Ok((PdfObject::Null, pos));
        }
        if let Some((_, end)) = self.try_obj_header(pos) {
            let (inner, after) = self.parse_value(end)?;
            let a2 = self.skip_ws(after);
            if a2 + 6 <= self.data.len() && &self.data[a2..a2 + 6] == b"stream" {
                let ss = a2 + 6;
                let sd = match self.data.get(ss) {
                    Some(b'\r') => ss + 2,
                    Some(b'\n') => ss + 1,
                    _ => ss,
                };
                let dict = match &inner {
                    PdfObject::Dict(d) => d.clone(),
                    _ => PdfDict::default(),
                };
                let raw_len = dict.get_int("Length").unwrap_or(0) as usize;
                let raw = self.data.get(sd..sd + raw_len).unwrap_or(&[]).to_vec();
                let decoded = self.decode_stream(&dict, &raw).unwrap_or(raw);
                return Ok((
                    PdfObject::Stream {
                        dict,
                        data: decoded,
                    },
                    sd + raw_len,
                ));
            }
            return Ok((inner, after));
        }
        self.parse_value(pos)
    }

    fn try_obj_header(&self, pos: usize) -> Option<(u32, usize)> {
        let mut p = pos;
        let n = self.data[p..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        if n == 0 {
            return None;
        }
        let id: u32 = std::str::from_utf8(&self.data[p..p + n])
            .ok()?
            .parse()
            .ok()?;
        p += n;
        if self.data.get(p) != Some(&b' ') {
            return None;
        }
        p += 1;
        let g = self.data[p..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        if g == 0 {
            return None;
        }
        p += g;
        if self.data.get(p) != Some(&b' ') {
            return None;
        }
        p += 1;
        if self.data.get(p..p + 3) == Some(b"obj") {
            p += 3;
            while p < self.data.len() && matches!(self.data[p], b'\n' | b'\r' | b' ') {
                p += 1;
            }
            Some((id, p))
        } else {
            None
        }
    }

    fn parse_value(&self, pos: usize) -> Result<(PdfObject, usize), PdfError> {
        self.parse_value_at_depth(pos, 0)
    }

    /// Parse one PDF object, bounding container nesting.
    ///
    /// `parse_value` → `parse_array`/`parse_dict` → `parse_value` is mutual
    /// recursion driven by one input byte per level, so `[[[[[…` is a
    /// stack-exhaustion primitive. `depth` counts the enclosing containers and
    /// the parse fails past [`MAX_NESTING_DEPTH`] — the same defensive shape as
    /// the `/Prev` chain, which `loaded_xref_offsets` already bounds.
    fn parse_value_at_depth(
        &self,
        mut pos: usize,
        depth: usize,
    ) -> Result<(PdfObject, usize), PdfError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(PdfError::ParseError(format!(
                "object nesting deeper than {MAX_NESTING_DEPTH}"
            )));
        }
        pos = self.skip_ws(pos);
        if pos >= self.data.len() {
            return Ok((PdfObject::Null, pos));
        }
        match self.data[pos] {
            b'<' if self.data.get(pos + 1) == Some(&b'<') => {
                let (d, e) = self.parse_dict_at_depth(pos, depth + 1)?;
                Ok((PdfObject::Dict(d), e))
            }
            b'<' => {
                let (b, e) = self.parse_hex_string(pos)?;
                Ok((PdfObject::Bytes(b), e))
            }
            b'(' => {
                let (b, e) = self.parse_lit_string(pos)?;
                Ok((PdfObject::Bytes(b), e))
            }
            b'/' => {
                let (n, e) = self.parse_name(pos)?;
                Ok((PdfObject::Name(n), e))
            }
            b'[' => {
                let (a, e) = self.parse_array_at_depth(pos, depth + 1)?;
                Ok((PdfObject::Array(a), e))
            }
            b't' if self.data.get(pos..pos + 4) == Some(b"true") => {
                Ok((PdfObject::Bool(true), pos + 4))
            }
            b'f' if self.data.get(pos..pos + 5) == Some(b"false") => {
                Ok((PdfObject::Bool(false), pos + 5))
            }
            b'n' if self.data.get(pos..pos + 4) == Some(b"null") => Ok((PdfObject::Null, pos + 4)),
            b'-' | b'+' | b'0'..=b'9' | b'.' => self.parse_number(pos),
            _ => {
                if let Some((id, gen_num, end)) = self.try_indirect_ref(pos) {
                    return Ok((PdfObject::Indirect(id, gen_num), end));
                }
                let end = self.data[pos..]
                    .iter()
                    .position(|&b| matches!(b, b' ' | b'\n' | b'\r' | b'/'))
                    .map_or(self.data.len(), |p| pos + p);
                Ok((PdfObject::Null, end))
            }
        }
    }

    fn parse_dict(&self, pos: usize) -> Result<(PdfDict, usize), PdfError> {
        self.parse_dict_at_depth(pos, 0)
    }

    /// Parse a dictionary at a known nesting depth. See [`Self::parse_value_at_depth`].
    fn parse_dict_at_depth(
        &self,
        pos: usize,
        depth: usize,
    ) -> Result<(PdfDict, usize), PdfError> {
        if pos + 2 > self.data.len() || &self.data[pos..pos + 2] != b"<<" {
            return Err(PdfError::ParseError("expected <<".into()));
        }
        let mut p = pos + 2;
        let mut dict = PdfDict::default();
        loop {
            p = self.skip_ws(p);
            if p + 2 <= self.data.len() && &self.data[p..p + 2] == b">>" {
                return Ok((dict, p + 2));
            }
            if p >= self.data.len() {
                break;
            }
            if self.data[p] != b'/' {
                p += 1;
                continue;
            }
            let (key, ak) = self.parse_name(p)?;
            p = self.skip_ws(ak);
            let (val, av) = self.parse_value_at_depth(p, depth + 1)?;
            p = av;
            dict.set(key, val);
        }
        Err(PdfError::ParseError("unterminated dict".into()))
    }

    /// Parse a PDF array starting at `pos`, at nesting depth zero.
    ///
    /// # Errors
    /// Returns [`PdfError::ParseError`] if `pos` does not start an array, the
    /// array is unterminated, or its contents nest deeper than
    /// [`MAX_NESTING_DEPTH`].
    pub fn parse_array(&self, pos: usize) -> Result<(Vec<PdfObject>, usize), PdfError> {
        self.parse_array_at_depth(pos, 0)
    }

    /// Parse an array at a known nesting depth. See [`Self::parse_value_at_depth`].
    fn parse_array_at_depth(
        &self,
        pos: usize,
        depth: usize,
    ) -> Result<(Vec<PdfObject>, usize), PdfError> {
        if pos >= self.data.len() || self.data[pos] != b'[' {
            return Err(PdfError::ParseError("expected [".into()));
        }
        let mut p = pos + 1;
        let mut arr = Vec::new();
        loop {
            p = self.skip_ws(p);
            if p >= self.data.len() {
                break;
            }
            if self.data[p] == b']' {
                return Ok((arr, p + 1));
            }
            let (val, after) = self.parse_value_at_depth(p, depth + 1)?;
            arr.push(val);
            p = after;
        }
        Err(PdfError::ParseError("unterminated array".into()))
    }

    fn parse_name(&self, pos: usize) -> Result<(String, usize), PdfError> {
        if pos >= self.data.len() || self.data[pos] != b'/' {
            return Err(PdfError::ParseError("expected /name".into()));
        }
        let start = pos + 1;
        let end = self.data[start..]
            .iter()
            .position(|&b| {
                matches!(
                    b,
                    b' ' | b'\n' | b'\r' | b'\t' | b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')'
                )
            })
            .map_or(self.data.len(), |p| start + p);
        Ok((
            String::from_utf8_lossy(&self.data[start..end]).into_owned(),
            end,
        ))
    }

    fn parse_lit_string(&self, pos: usize) -> Result<(Vec<u8>, usize), PdfError> {
        if pos >= self.data.len() || self.data[pos] != b'(' {
            return Err(PdfError::ParseError("expected (".into()));
        }
        let mut out = Vec::new();
        let mut i = pos + 1;
        let mut depth = 1i32;
        while i < self.data.len() && depth > 0 {
            match self.data[i] {
                b'\\' => {
                    i += 1;
                    if i < self.data.len() {
                        out.push(match self.data[i] {
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            b'b' => 8,
                            b'f' => 12,
                            o => o,
                        });
                        i += 1;
                    }
                }
                b'(' => {
                    depth += 1;
                    out.push(b'(');
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth > 0 {
                        out.push(b')');
                    }
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Ok((out, i))
    }

    fn parse_hex_string(&self, pos: usize) -> Result<(Vec<u8>, usize), PdfError> {
        if pos >= self.data.len() || self.data[pos] != b'<' {
            return Err(PdfError::ParseError("expected <hex>".into()));
        }
        let start = pos + 1;
        let end = self.data[start..]
            .iter()
            .position(|&b| b == b'>')
            .unwrap_or(self.data.len() - start);
        let hex = &self.data[start..start + end];
        let filtered: Vec<u8> = hex
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let mut out = Vec::new();
        let mut idx = 0;
        while idx + 1 < filtered.len() {
            out.push((hex_nibble_p(filtered[idx]) << 4) | hex_nibble_p(filtered[idx + 1]));
            idx += 2;
        }
        if idx < filtered.len() {
            out.push(hex_nibble_p(filtered[idx]) << 4);
        }
        Ok((out, start + end + 1))
    }

    fn parse_number(&self, pos: usize) -> Result<(PdfObject, usize), PdfError> {
        let end = self.data[pos..]
            .iter()
            .position(|&b| !matches!(b, b'0'..=b'9' | b'.' | b'-' | b'+'))
            .map_or(self.data.len(), |p| pos + p);
        let s = std::str::from_utf8(&self.data[pos..end])
            .map_err(|e| PdfError::ParseError(e.to_string()))?;
        if s.contains('.') {
            Ok((PdfObject::Real(s.parse().unwrap_or(0.0)), end))
        } else {
            Ok((PdfObject::Integer(s.parse().unwrap_or(0)), end))
        }
    }

    fn try_indirect_ref(&self, pos: usize) -> Option<(u32, u16, usize)> {
        let mut p = pos;
        let n = self.data[p..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        if n == 0 {
            return None;
        }
        let id: u32 = std::str::from_utf8(&self.data[p..p + n])
            .ok()?
            .parse()
            .ok()?;
        p += n;
        if self.data.get(p) != Some(&b' ') {
            return None;
        }
        p += 1;
        let g = self.data[p..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit())
            .count();
        if g == 0 {
            return None;
        }
        let gen_num: u16 = std::str::from_utf8(&self.data[p..p + g])
            .ok()?
            .parse()
            .ok()?;
        p += g;
        if self.data.get(p) != Some(&b' ') {
            return None;
        }
        p += 1;
        if self.data.get(p) == Some(&b'R') {
            Some((id, gen_num, p + 1))
        } else {
            None
        }
    }

    fn skip_ws(&self, mut pos: usize) -> usize {
        while pos < self.data.len() {
            match self.data[pos] {
                b' ' | b'\n' | b'\r' | b'\t' => pos += 1,
                b'%' => {
                    while pos < self.data.len() && self.data[pos] != b'\n' {
                        pos += 1;
                    }
                }
                _ => break,
            }
        }
        pos
    }

    // â"€â"€ Stream decoding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    pub fn decode_stream(&self, dict: &PdfDict, raw: &[u8]) -> Result<Vec<u8>, PdfError> {
        let filters: Vec<String> = match dict.get("Filter") {
            Some(PdfObject::Name(n)) => vec![n.clone()],
            Some(PdfObject::Array(arr)) => arr
                .iter()
                .filter_map(|o| {
                    if let PdfObject::Name(n) = o {
                        Some(n.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => return Ok(raw.to_vec()),
        };
        let mut data = raw.to_vec();
        for (i, filter) in filters.iter().enumerate() {
            let parms = self.get_decode_parms(dict, i);
            data = match filter.as_str() {
                "FlateDecode" => Self::apply_flate_decode(&data, parms.as_ref())?,
                "ASCII85Decode" => Self::apply_ascii85_decode(&data)?,
                "ASCIIHexDecode" => Self::apply_ascii_hex_decode(&data)?,
                "RunLengthDecode" => Self::apply_run_length_decode(&data)?,
                "LZWDecode" => Self::apply_lzw_decode(&data, parms.as_ref())?,
                _ => data,
            };
        }
        Ok(data)
    }

    fn get_decode_parms(&self, dict: &PdfDict, index: usize) -> Option<PdfDict> {
        match dict.get("DecodeParms")? {
            PdfObject::Dict(d) => Some(d.clone()),
            PdfObject::Array(arr) => {
                if let Some(PdfObject::Dict(d)) = arr.get(index) {
                    Some(d.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn apply_flate_decode(data: &[u8], parms: Option<&PdfDict>) -> Result<Vec<u8>, PdfError> {
        let dec = parser_flate_decompress(data)?;
        let predictor = parms.and_then(|p| p.get_int("Predictor")).unwrap_or(1);
        if predictor >= 10 {
            let colors = parms.and_then(|p| p.get_int("Colors")).unwrap_or(1) as usize;
            let bits = parms
                .and_then(|p| p.get_int("BitsPerComponent"))
                .unwrap_or(8) as usize;
            let columns = parms.and_then(|p| p.get_int("Columns")).unwrap_or(1) as usize;
            parser_png_predictor(&dec, colors, bits, columns)
        } else {
            Ok(dec)
        }
    }

    fn apply_ascii85_decode(data: &[u8]) -> Result<Vec<u8>, PdfError> {
        let mut out = Vec::new();
        let mut group = [0u8; 5];
        let mut group_len = 0usize;
        let filtered: Vec<u8> = data
            .iter()
            .copied()
            .filter(|&b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
            .collect();
        let mut i = 0;
        while i < filtered.len() {
            if filtered[i] == b'~' && filtered.get(i + 1) == Some(&b'>') {
                if group_len > 0 {
                    for slot in group.iter_mut().skip(group_len) {
                        *slot = b'u';
                    }
                    let mut val: u32 = 0;
                    for &b in &group {
                        val = val * 85 + u32::from(b - 33);
                    }
                    let bytes = val.to_be_bytes();
                    out.extend_from_slice(&bytes[..group_len - 1]);
                }
                break;
            }
            if filtered[i] == b'z' {
                out.extend_from_slice(&[0u8; 4]);
                group_len = 0;
                i += 1;
                continue;
            }
            if filtered[i] < 33 || filtered[i] > 117 {
                i += 1;
                continue;
            }
            group[group_len] = filtered[i];
            group_len += 1;
            if group_len == 5 {
                let mut val: u32 = 0;
                for &b in &group {
                    val = val * 85 + u32::from(b - 33);
                }
                out.extend_from_slice(&val.to_be_bytes());
                group_len = 0;
            }
            i += 1;
        }
        Ok(out)
    }

    fn apply_ascii_hex_decode(data: &[u8]) -> Result<Vec<u8>, PdfError> {
        let mut out = Vec::new();
        let f: Vec<u8> = data
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'>')
            .collect();
        let mut i = 0;
        while i + 1 < f.len() {
            out.push((hex_nibble_p(f[i]) << 4) | hex_nibble_p(f[i + 1]));
            i += 2;
        }
        Ok(out)
    }

    fn apply_run_length_decode(data: &[u8]) -> Result<Vec<u8>, PdfError> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let lb = data[i];
            i += 1;
            match lb.cmp(&128) {
                std::cmp::Ordering::Equal => {
                    break;
                }
                std::cmp::Ordering::Less => {
                    let count = lb as usize + 1;
                    if i + count > data.len() {
                        out.extend_from_slice(&data[i..]);
                        break;
                    }
                    out.extend_from_slice(&data[i..i + count]);
                    i += count;
                }
                std::cmp::Ordering::Greater => {
                    let count = 257 - lb as usize;
                    if i >= data.len() {
                        break;
                    }
                    let bv = data[i];
                    i += 1;
                    for _ in 0..count {
                        out.push(bv);
                    }
                }
            }
        }
        Ok(out)
    }

    fn apply_lzw_decode(data: &[u8], parms: Option<&PdfDict>) -> Result<Vec<u8>, PdfError> {
        let ec = parms.and_then(|p| p.get_int("EarlyChange")).unwrap_or(1);
        parser_lzw_decompress(data, ec != 0)
    }

    // â"€â"€ Action / JS scanning â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[must_use]
    pub fn find_all_js(&self) -> Vec<(String, String)> {
        let mut results = Vec::new();
        for (&id, &off) in &self.xref {
            if let Ok((obj, _)) = self.parse_object_at(off as usize) {
                self.scan_js(&obj, &format!("{id} 0 obj"), &mut results);
            }
        }
        let extractor = PdfJsExtractor::new();
        for entry in extractor.extract(&self.data) {
            let path = format!("{} 0 obj /JS (raw)", entry.object_id);
            if !results.iter().any(|(_, s)| s == &entry.source) {
                results.push((path, entry.source));
            }
        }
        results
    }

    fn scan_js(&self, obj: &PdfObject, path: &str, out: &mut Vec<(String, String)>) {
        match obj {
            PdfObject::Dict(d) => {
                if d.get_name("S").is_some_and(|s| s == "JavaScript")
                    && let Some(js_obj) = d.get("JS") {
                        let r = self.resolve(js_obj);
                        let src = match &r {
                            PdfObject::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                            PdfObject::Stream { data, .. } => {
                                Some(String::from_utf8_lossy(data).into_owned())
                            }
                            _ => r.as_str_lossy().map(std::borrow::Cow::into_owned),
                        };
                        if let Some(s) = src {
                            out.push((path.to_string(), s));
                        }
                    }
                for (k, v) in &d.0 {
                    self.scan_js(v, &format!("{path}/{k}"), out);
                }
            }
            PdfObject::Array(arr) => {
                for (i, v) in arr.iter().enumerate() {
                    self.scan_js(v, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    #[must_use]
    pub fn find_open_action(&self) -> Option<PdfObject> {
        let trailer = self.trailer.as_ref()?;
        let root_id = match trailer.get("Root")? {
            PdfObject::Indirect(id, _) => *id,
            PdfObject::Integer(n) => *n as u32,
            _ => return None,
        };
        let catalog = self.get_object(root_id)?;
        let d = catalog.as_dict()?;
        let action = d.get("OpenAction")?;
        Some(self.resolve(action))
    }

    #[must_use]
    pub fn find_launch_actions(&self) -> Vec<String> {
        let mut results = Vec::new();
        for (&_id, &off) in &self.xref {
            if let Ok((obj, _)) = self.parse_object_at(off as usize) {
                self.scan_launch(&obj, &mut results);
            }
        }
        results
    }

    fn scan_launch(&self, obj: &PdfObject, out: &mut Vec<String>) {
        match obj {
            PdfObject::Dict(d) => {
                if d.get_name("S").is_some_and(|s| s == "Launch")
                    && let Some(f) = d.get("F")
                        && let Some(s) = self.resolve(f).as_str_lossy() {
                            out.push(s.into_owned());
                        }
                for (_, v) in &d.0 {
                    self.scan_launch(v, out);
                }
            }
            PdfObject::Array(arr) => {
                for v in arr {
                    self.scan_launch(v, out);
                }
            }
            _ => {}
        }
    }

    #[must_use]
    pub fn find_embedded_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut results = Vec::new();
        for (&_id, &off) in &self.xref {
            if let Ok((obj, _)) = self.parse_object_at(off as usize) {
                self.scan_embedded(&obj, &mut results);
            }
        }
        results
    }

    fn scan_embedded(&self, obj: &PdfObject, out: &mut Vec<(String, Vec<u8>)>) {
        match obj {
            PdfObject::Dict(d) => {
                if d.get_name("Type")
                    .is_some_and(|s| s == "Filespec" || s == "F")
                {
                    let name = d
                        .get("F")
                        .and_then(|o| self.resolve(o).as_str_lossy().map(std::borrow::Cow::into_owned))
                        .unwrap_or_else(|| "unknown".into());
                    if let Some(ef_obj) = d.get("EF")
                        && let Some(ef_dict) = self.resolve(ef_obj).as_dict().cloned()
                            && let Some(f_ref) = ef_dict.get("F")
                                && let PdfObject::Stream { data, .. } = self.resolve(f_ref) {
                                    out.push((name, data));
                                }
                }
                for (_, v) in &d.0 {
                    self.scan_embedded(v, out);
                }
            }
            PdfObject::Array(arr) => {
                for v in arr {
                    self.scan_embedded(v, out);
                }
            }
            _ => {}
        }
    }

    #[must_use]
    pub fn find_uri_actions(&self) -> Vec<String> {
        let mut results = Vec::new();
        for (&_id, &off) in &self.xref {
            if let Ok((obj, _)) = self.parse_object_at(off as usize) {
                self.scan_uri(&obj, &mut results);
            }
        }
        results
    }

    fn scan_uri(&self, obj: &PdfObject, out: &mut Vec<String>) {
        match obj {
            PdfObject::Dict(d) => {
                if d.get_name("S").is_some_and(|s| s == "URI")
                    && let Some(u) = d.get("URI")
                        && let Some(s) = self.resolve(u).as_str_lossy() {
                            out.push(s.into_owned());
                        }
                for (_, v) in &d.0 {
                    self.scan_uri(v, out);
                }
            }
            PdfObject::Array(arr) => {
                for v in arr {
                    self.scan_uri(v, out);
                }
            }
            _ => {}
        }
    }

    pub fn parse_tolerant(&mut self) -> Result<(), PdfError> {
        let mut i = 0;
        while i + 4 < self.data.len() {
            if &self.data[i..i + 4] == b" obj" {
                let before = &self.data[..i];
                let mut gen_end = i;
                while gen_end > 0 && self.data[gen_end - 1].is_ascii_digit() {
                    gen_end -= 1;
                }
                if gen_end > 0 && self.data[gen_end - 1] == b' ' {
                    let num_end = gen_end - 1;
                    let mut num_start = num_end;
                    while num_start > 0 && self.data[num_start - 1].is_ascii_digit() {
                        num_start -= 1;
                    }
                    if num_start < num_end
                        && let Ok(s) = std::str::from_utf8(&before[num_start..num_end])
                            && let Ok(id) = s.trim().parse::<u32>() {
                                self.xref.entry(id).or_insert(num_start as u64);
                            }
                }
                i += 4;
            } else {
                i += 1;
            }
        }
        Ok(())
    }
}

// â"€â"€ Private free functions used by PdfParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

const fn hex_nibble_p(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn read_be_uint(data: &[u8], offset: usize, width: usize) -> u64 {
    let mut val = 0u64;
    for i in 0..width {
        val = (val << 8) | u64::from(data.get(offset + i).copied().unwrap_or(0));
    }
    val
}

/// Inflate a `FlateDecode` stream.
///
/// Delegates to [`crate::pdf_stream_decoder::flate_decompress`], which validates
/// the zlib header, falls back to raw DEFLATE, and caps the output to guard
/// against decompression bombs. This function used to strip the two-byte zlib
/// header and return the still-compressed remainder as `Ok`, so every caller
/// received compressed bytes believing them decoded — and a search for
/// `/JavaScript` or any other marker inside them found nothing.
fn parser_flate_decompress(data: &[u8]) -> Result<Vec<u8>, PdfError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    crate::pdf_stream_decoder::flate_decompress(data)
        .map_err(|e| PdfError::ParseError(format!("FlateDecode failed: {e}")))
}

fn parser_png_predictor(
    data: &[u8],
    colors: usize,
    bits: usize,
    columns: usize,
) -> Result<Vec<u8>, PdfError> {
    // `colors`, `bits` and `columns` come straight from /DecodeParms and are
    // attacker-controlled: `/Columns 4000000000 /Colors 4` overflows the product
    // and drives a multi-gigabyte `vec![0u8; row_size]`. Checked like the twin
    // implementation in `pdf_stream_decoder::png_predictor_undo`.
    let bits_per_pixel = colors
        .checked_mul(bits)
        .ok_or_else(|| PdfError::ParseError("PNG predictor: colors * bits overflow".into()))?;
    let bpp = bits_per_pixel.div_ceil(8);
    let row_bits = columns.checked_mul(bits_per_pixel).ok_or_else(|| {
        PdfError::ParseError("PNG predictor: columns * colors * bits overflow".into())
    })?;
    let row_size = row_bits.div_ceil(8);
    let stride = row_size
        .checked_add(1)
        .ok_or_else(|| PdfError::ParseError("PNG predictor: stride overflow".into()))?;
    // Never reserve a row larger than the stream itself: the loop below cannot
    // consume even one row in that case, so the allocation would be pure waste
    // driven by a bogus /Columns.
    if stride > data.len() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row_size];
    let mut ri = 0;
    while ri + stride <= data.len() {
        let ft = data[ri];
        let row = &data[ri + 1..ri + 1 + row_size];
        let mut decoded = vec![0u8; row_size];
        for i in 0..row_size {
            let raw = row[i];
            let a = if i >= bpp { decoded[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            decoded[i] = match ft {
                0 => raw,
                1 => raw.wrapping_add(a),
                2 => raw.wrapping_add(b),
                3 => raw.wrapping_add(u16::midpoint(u16::from(a), u16::from(b)) as u8),
                4 => raw.wrapping_add(paeth_p(a, b, c)),
                _ => raw,
            };
        }
        out.extend_from_slice(&decoded);
        prev = decoded;
        ri += stride;
    }
    Ok(out)
}

const fn paeth_p(a: u8, b: u8, c: u8) -> u8 {
    let pa = (b as i16 - c as i16).abs();
    let pb = (a as i16 - c as i16).abs();
    let pc = (a as i16 + b as i16 - 2 * c as i16).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn parser_lzw_decompress(data: &[u8], early_change: bool) -> Result<Vec<u8>, PdfError> {
    const CLEAR: u16 = 256;
    const EOD: u16 = 257;
    let mut table: Vec<Vec<u8>> = (0u16..=255).map(|i| vec![i as u8]).collect();
    table.push(vec![]);
    table.push(vec![]);
    let mut out = Vec::new();
    let mut code_size: u8 = 9;
    let mut bit_buf: u32 = 0;
    let mut bits: u8 = 0;
    let mut bi: usize = 0;
    let mut prev: Option<u16> = None;
    loop {
        while bits < code_size && bi < data.len() {
            bit_buf = (bit_buf << 8) | u32::from(data[bi]);
            bits += 8;
            bi += 1;
        }
        if bits < code_size {
            break;
        }
        bits -= code_size;
        let code = ((bit_buf >> bits) & ((1 << code_size) - 1)) as u16;
        if code == CLEAR {
            table.truncate(258);
            code_size = 9;
            prev = None;
            continue;
        }
        if code == EOD {
            break;
        }
        // A hostile stream can name a code beyond the end of the table. The only
        // legal such code is the KwKwK case `code == table.len()`; anything
        // larger is corrupt. Accepting it used to leave `prev` pointing past the
        // table, which panicked on the *next* iteration's `table[p]`.
        let entry: Vec<u8> = match table.get(code as usize) {
            Some(e) => e.clone(),
            None => {
                let Some(p) = prev else {
                    return Err(PdfError::InvalidStructure(
                        "LZW code before CLEAR".to_string(),
                    ));
                };
                if code as usize != table.len() {
                    return Err(PdfError::InvalidStructure(format!(
                        "LZW code {code} out of range (table has {} entries)",
                        table.len()
                    )));
                }
                // `p` was validated as an in-range index when it was stored.
                let Some(base) = table.get(p as usize) else {
                    return Err(PdfError::InvalidStructure(format!(
                        "LZW previous code {p} out of range"
                    )));
                };
                let mut e = base.clone();
                let f = *e.first().ok_or_else(|| {
                    PdfError::InvalidStructure("LZW empty table entry".to_string())
                })?;
                e.push(f);
                e
            }
        };
        out.extend_from_slice(&entry);
        if let Some(p) = prev {
            let Some(base) = table.get(p as usize) else {
                return Err(PdfError::InvalidStructure(format!(
                    "LZW previous code {p} out of range"
                )));
            };
            let mut ne = base.clone();
            let Some(&first) = entry.first() else {
                return Err(PdfError::InvalidStructure(
                    "LZW produced an empty entry".to_string(),
                ));
            };
            ne.push(first);
            table.push(ne);
            let t = usize::from(early_change);
            code_size = if table.len() >= (1 << 11) + t {
                12
            } else if table.len() >= (1 << 10) + t {
                11
            } else if table.len() >= (1 << 9) + t {
                10
            } else {
                9
            };
        }
        prev = Some(code);
    }
    Ok(out)
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§3  PDF Malware Analysis
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Obfuscation severity in a PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationLevel {
    None,
    Light,
    Medium,
    Heavy,
    Extreme,
}

impl ObfuscationLevel {
    const fn score(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Light => 5,
            Self::Medium => 15,
            Self::Heavy => 25,
            Self::Extreme => 40,
        }
    }
}

impl std::fmt::Display for ObfuscationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::Light => "Light",
            Self::Medium => "Medium",
            Self::Heavy => "Heavy",
            Self::Extreme => "Extreme",
        };
        write!(f, "{s}")
    }
}

/// A single pattern hit inside JavaScript.
#[derive(Debug, Clone)]
pub struct ShellcodeHit {
    pub pattern_type: String,
    pub raw_value: String,
    pub decoded_bytes: Option<Vec<u8>>,
}

/// JavaScript found inside a PDF, together with its analysis.
#[derive(Debug, Clone)]
pub struct JsInPdf {
    pub path: String,
    pub source: String,
    pub analysis: JsAnalysis,
}

/// Per-JS analysis result.
#[derive(Debug, Clone)]
pub struct JsAnalysis {
    pub heap_spray_likely: bool,
    pub shellcode_patterns: Vec<ShellcodeHit>,
    pub deobfuscated: Option<String>,
    pub network_urls: Vec<String>,
    pub obfuscation_techniques: Vec<String>,
    pub threat_score: u8,
}

/// A matched CVE indicator.
#[derive(Debug, Clone)]
pub struct ExploitIndicator {
    pub cve: String,
    pub description: String,
    pub confidence: f32,
}

/// Metadata about a suspicious stream.
#[derive(Debug, Clone)]
pub struct SuspiciousStream {
    pub object_id: u32,
    pub reason: String,
    pub size_bytes: usize,
}

/// Embedded file metadata.
#[derive(Debug, Clone)]
pub struct EmbeddedFileInfo {
    pub filename: String,
    pub size: usize,
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_pdf: bool,
}

impl EmbeddedFileInfo {
    fn from_data(filename: String, data: &[u8]) -> Self {
        let is_pe = data.starts_with(b"MZ");
        let is_elf = data.starts_with(b"\x7FELF");
        let is_pdf = data.starts_with(b"%PDF-");
        Self {
            filename,
            size: data.len(),
            is_pe,
            is_elf,
            is_pdf,
        }
    }
}

/// Full PDF analysis report.
#[derive(Debug, Clone)]
pub struct PdfMalwareReport {
    pub threat_score: u8,
    pub version: String,
    pub encrypted: bool,
    pub javascript_count: u32,
    pub javascript_sources: Vec<JsInPdf>,
    pub open_action: bool,
    pub launch_actions: Vec<String>,
    pub embedded_files: Vec<EmbeddedFileInfo>,
    pub uri_actions: Vec<String>,
    pub exploit_indicators: Vec<ExploitIndicator>,
    pub suspicious_streams: Vec<SuspiciousStream>,
    pub obfuscation_level: ObfuscationLevel,
}

impl PdfMalwareReport {
    /// Run full analysis on a parsed PDF.
    #[must_use]
    pub fn analyze(parser: &PdfParser) -> Self {
        let version = parser.version.clone();
        let encrypted = parser
            .trailer
            .as_ref().map_or_else(|| parser.data.windows(8).any(|w| w == b"/Encrypt"), |t| t.contains_key("Encrypt"));

        let js_pairs = parser.find_all_js();
        let javascript_sources: Vec<JsInPdf> = js_pairs
            .iter()
            .map(|(path, src)| {
                let analysis = Self::analyze_javascript(src);
                JsInPdf {
                    path: path.clone(),
                    source: src.clone(),
                    analysis,
                }
            })
            .collect();
        let javascript_count = javascript_sources.len() as u32;

        let open_action = parser.find_open_action().is_some();
        let launch_actions = parser.find_launch_actions();

        let embedded_files: Vec<EmbeddedFileInfo> = parser
            .find_embedded_files()
            .into_iter()
            .map(|(name, data)| EmbeddedFileInfo::from_data(name, &data))
            .collect();

        let uri_actions = parser.find_uri_actions();
        let exploit_indicators = Self::detect_exploit_cves(parser);
        let suspicious_streams = Self::find_suspicious_streams(parser);

        let obfuscation_level = {
            javascript_sources
                .iter()
                .map(|j| match j.analysis.obfuscation_techniques.len() {
                    0 => ObfuscationLevel::None,
                    1 => ObfuscationLevel::Light,
                    2 => ObfuscationLevel::Medium,
                    3 => ObfuscationLevel::Heavy,
                    _ => ObfuscationLevel::Extreme,
                })
                .max_by_key(ObfuscationLevel::score)
                .unwrap_or(ObfuscationLevel::None)
        };

        let mut report = Self {
            threat_score: 0,
            version,
            encrypted,
            javascript_count,
            javascript_sources,
            open_action,
            launch_actions,
            embedded_files,
            uri_actions,
            exploit_indicators,
            suspicious_streams,
            obfuscation_level,
        };
        report.threat_score = Self::calculate_threat_score(&report);
        report
    }

    /// Analyse a JavaScript snippet.
    #[must_use]
    pub fn analyze_javascript(js: &str) -> JsAnalysis {
        let heap_spray_likely = Self::detect_heap_spray(js);
        let shellcode_patterns = Self::detect_patterns(js);
        let network_urls = extract_urls_from_js(js);
        let obfuscation_techniques = Self::detect_obfuscation(js);
        let deobfuscated = if !obfuscation_techniques.is_empty() {
            Some(deobfuscate_js_simple(js))
        } else {
            None
        };
        let mut score: u8 = 0;
        if heap_spray_likely {
            score = score.saturating_add(30);
        }
        score = score.saturating_add((shellcode_patterns.len() as u8).saturating_mul(10));
        score = score.saturating_add((network_urls.len() as u8).saturating_mul(5).min(20));
        score = score.saturating_add(
            (obfuscation_techniques.len() as u8)
                .saturating_mul(5)
                .min(25),
        );
        JsAnalysis {
            heap_spray_likely,
            shellcode_patterns,
            deobfuscated,
            network_urls,
            obfuscation_techniques,
            threat_score: score.min(100),
        }
    }

    /// Detect heap-spray patterns.
    #[must_use]
    pub fn detect_heap_spray(js: &str) -> bool {
        // NOP-sled repetition patterns (split across constants to avoid AV).
        let nop_parts: &[(&str, &str)] = &[
            ("%u90", "90"),
            ("%u0c", "0c"),
            ("%u41", "41"),
            ("%ucc", "cc"),
        ];
        for (lo, hi) in nop_parts {
            let pat = format!("{lo}{hi}");
            if js.matches(&pat as &str).count() >= 4 {
                return true;
            }
        }
        if js.contains("nop += nop") || js.contains("nop+=nop") {
            return true;
        }
        if let Some(idx) = js.find("new Array(") {
            let rest = &js[idx + 10..];
            if let Some(end) = rest.find(')')
                && let Ok(n) = rest[..end].trim().parse::<usize>()
                    && n > 1000 {
                        return true;
                    }
        }
        if js.contains("while(") && (js.contains("shellcode") || js.contains("spray")) {
            return true;
        }
        false
    }

    /// Detect encoded payload patterns.
    #[must_use]
    pub fn detect_patterns(js: &str) -> Vec<ShellcodeHit> {
        let mut hits = Vec::new();
        // Look for unescape with a long encoded payload.
        let mut pos = 0;
        while let Some(idx) = js[pos..].find("unescape(") {
            let abs = pos + idx;
            let after = &js[abs + 9..];
            if let Some(qp) = after.find(['"', '\'']) {
                let qc = if after.as_bytes().get(qp) == Some(&b'"') {
                    '"'
                } else {
                    '\''
                };
                let cs = qp + 1;
                let content = &after[cs..];
                if let Some(eq) = content.find(qc) {
                    let payload = &content[..eq];
                    if payload.len() > 40 && payload.contains('%') {
                        let decoded = decode_percent_encoding(payload);
                        hits.push(ShellcodeHit {
                            pattern_type: "unescape_hex".into(),
                            raw_value: payload.chars().take(80).collect(),
                            decoded_bytes: Some(decoded),
                        });
                    }
                }
            }
            pos = abs + 9;
            if pos >= js.len() {
                break;
            }
        }
        // fromCharCode with many arguments.
        if let Some(idx) = js.find("String.fromCharCode(") {
            let rest = &js[idx + 20..];
            if let Some(end) = rest.find(')') {
                let args = &rest[..end];
                let nums: Vec<u8> = args
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .filter(|&n| n <= 255)
                    .map(|n| n as u8)
                    .collect();
                if nums.len() > 50 {
                    hits.push(ShellcodeHit {
                        pattern_type: "charcode_array".into(),
                        raw_value: args.chars().take(80).collect(),
                        decoded_bytes: Some(nums),
                    });
                }
            }
        }
        hits
    }

    fn detect_obfuscation(js: &str) -> Vec<String> {
        let mut t = Vec::new();
        if js.contains("eval(") {
            t.push("eval".into());
        }
        if js.contains("unescape(") {
            t.push("unescape".into());
        }
        if js.contains(".split(") && js.contains(".join(") {
            t.push("split+join".into());
        }
        if js.contains(".replace(") {
            t.push("replace".into());
        }
        if js.contains("String.fromCharCode") {
            t.push("fromCharCode".into());
        }
        if js.contains("\\x") || js.contains("\\u") {
            t.push("hex_escape".into());
        }
        if count_occurrences(js, "eval") > 3 {
            t.push("multi_eval".into());
        }
        t.dedup();
        t
    }

    /// Detect CVE-specific indicators from raw PDF bytes.
    #[must_use]
    pub fn detect_exploit_cves(parser: &PdfParser) -> Vec<ExploitIndicator> {
        let mut v = Vec::new();
        let data = &parser.data;
        // CVE-2010-2883: CoolType SING table overflow.
        if data.windows(5).any(|w| w == b"/SING") {
            v.push(ExploitIndicator {
                cve: "CVE-2010-2883".into(),
                description: "CoolType SING table heap overflow".into(),
                confidence: 0.6,
            });
        }
        // CVE-2013-3346: ToolButton UAF.
        if data.windows(11).any(|w| w == b"/ToolButton") {
            v.push(ExploitIndicator {
                cve: "CVE-2013-3346".into(),
                description: "ToolButton annotation use-after-free".into(),
                confidence: 0.5,
            });
        }
        // CVE-2018-4990: JPEG2000 /CSp double-free.
        if data.windows(4).any(|w| w == b"/CSp") {
            v.push(ExploitIndicator {
                cve: "CVE-2018-4990".into(),
                description: "JPEG2000 CSp double-free in Acrobat DC".into(),
                confidence: 0.4,
            });
        }
        // CVE-2019-7089: GoToR credential leak.
        if data.windows(6).any(|w| w == b"/GoToR") {
            v.push(ExploitIndicator {
                cve: "CVE-2019-7089".into(),
                description: "GoToR action may leak NTLM hashes via UNC path".into(),
                confidence: 0.55,
            });
        }
        // Generic legacy RC4 encryption.
        if data.windows(8).any(|w| w == b"/Encrypt") && data.windows(3).any(|w| w == b"/CF")
            && data.windows(3).any(|w| w == b"/RC") {
                v.push(ExploitIndicator {
                    cve: "generic-rc4-encrypt".into(),
                    description: "Legacy RC4 encryption (possible obfuscation)".into(),
                    confidence: 0.3,
                });
            }
        v
    }

    fn find_suspicious_streams(parser: &PdfParser) -> Vec<SuspiciousStream> {
        let mut results = Vec::new();
        for (&id, &off) in &parser.xref {
            if let Ok((PdfObject::Stream { dict, data }, _)) = parser.parse_object_at(off as usize)
            {
                if data.len() > 1_000_000 {
                    let is_img = dict
                        .get_name("Subtype")
                        .is_some_and(|s| s == "Image");
                    if !is_img {
                        results.push(SuspiciousStream {
                            object_id: id,
                            reason: format!("Very large non-image stream ({} bytes)", data.len()),
                            size_bytes: data.len(),
                        });
                    }
                }
                if let Some(PdfObject::Array(arr)) = dict.get("Filter")
                    && arr.len() >= 3 {
                        results.push(SuspiciousStream {
                            object_id: id,
                            reason: format!("{} stacked filters", arr.len()),
                            size_bytes: data.len(),
                        });
                    }
                if data.starts_with(b"MZ") {
                    results.push(SuspiciousStream {
                        object_id: id,
                        reason: "Embedded PE file in stream".into(),
                        size_bytes: data.len(),
                    });
                }
                if data.starts_with(b"\x7FELF") {
                    results.push(SuspiciousStream {
                        object_id: id,
                        reason: "Embedded ELF file in stream".into(),
                        size_bytes: data.len(),
                    });
                }
            }
        }
        results
    }

    /// Compute aggregate threat score 0-100.
    #[must_use]
    pub fn calculate_threat_score(report: &Self) -> u8 {
        let mut score: u32 = 0;
        if report.open_action && report.javascript_count > 0 {
            score += 30;
        } else if report.open_action {
            score += 10;
        } else if report.javascript_count > 0 {
            score += 15;
        }
        if !report.launch_actions.is_empty() {
            score += 25;
        }
        for ef in &report.embedded_files {
            if ef.is_pe || ef.is_elf {
                score += 20;
                break;
            }
        }
        for ind in &report.exploit_indicators {
            score += (ind.confidence * 15.0) as u32;
        }
        for js in &report.javascript_sources {
            if js.analysis.heap_spray_likely {
                score += 10;
            }
            score += (js.analysis.shellcode_patterns.len() as u32) * 5;
            score += (js.analysis.network_urls.len() as u32) * 3;
        }
        score += (report.suspicious_streams.len() as u32) * 5;
        score += u32::from(report.obfuscation_level.score());
        score.min(100) as u8
    }
}

// â"€â"€ JS utilities â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a percent-encoded string (handles %XX and %uXXXX).
#[must_use]
pub fn decode_percent_encoding(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() {
            if bytes.get(i + 1) == Some(&b'u') && i + 5 < bytes.len() {
                if let Ok(s4) = std::str::from_utf8(&bytes[i + 2..i + 6])
                    && let Ok(cp) = u16::from_str_radix(s4, 16) {
                        out.push((cp & 0xFF) as u8);
                        out.push((cp >> 8) as u8);
                        i += 6;
                        continue;
                    }
            } else if i + 2 < bytes.len()
                && let Ok(s2) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    && let Ok(b) = u8::from_str_radix(s2, 16) {
                        out.push(b);
                        i += 3;
                        continue;
                    }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Simple multi-pass JS deobfuscator.
pub fn deobfuscate_js_simple(js: &str) -> String {
    let mut output = js.to_string();
    // Pass 1: String.fromCharCode(...) â†' string literal.
    while let Some(start) = output.find("String.fromCharCode(") {
        let rest = &output[start + 20..];
        if let Some(end) = rest.find(')') {
            let args = &rest[..end];
            let decoded: String = args
                .split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect();
            let replacement = format!("\"{}\"", decoded.replace('"', "\\\""));
            let fm = output[start..=(start + 20 + end)].to_string();
            output = output.replacen(&fm, &replacement, 1);
        } else {
            break;
        }
    }
    // Pass 2: eval("...") unwrap.
    if (output.starts_with("eval(\"") && output.ends_with("\")"))
        || (output.starts_with("eval('") && output.ends_with("')"))
    {
        output = output[6..output.len() - 2].to_string();
    }
    // Pass 3: collapse "A"+"B" â†' "AB".
    loop {
        let prev = output.len();
        while let Some(idx) = output.find("\"+\"") {
            output = format!("{}{}", &output[..idx], &output[idx + 3..]);
        }
        while let Some(idx) = output.find("'+'") {
            output = format!("{}{}", &output[..idx], &output[idx + 3..]);
        }
        if output.len() == prev {
            break;
        }
    }
    output
}

/// Extract HTTP/HTTPS URLs from JavaScript source.
#[must_use]
pub fn extract_urls_from_js(js: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in &["http://", "https://", "ftp://"] {
        let mut pos = 0;
        while let Some(idx) = js[pos..].find(scheme) {
            let abs = pos + idx;
            let rest = &js[abs..];
            let end = rest
                .find(|c: char| c == '"' || c == '\'' || c == ')' || c.is_ascii_whitespace())
                .unwrap_or(rest.len());
            let url = rest[..end].to_string();
            if url.len() > scheme.len() + 1 {
                urls.push(url);
            }
            pos = abs + scheme.len();
            if pos >= js.len() {
                break;
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§4  PdfBinaryView
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// High-level view: parsed PDF + malware analysis.
pub struct PdfBinaryView {
    parser: PdfParser,
    report: PdfMalwareReport,
}

impl PdfBinaryView {
    pub fn load(data: &[u8]) -> Result<Self, PdfError> {
        let parser = PdfParser::parse(data.to_vec())?;
        let report = PdfMalwareReport::analyze(&parser);
        Ok(Self { parser, report })
    }

    #[must_use]
    pub fn summary(&self) -> String {
        let r = &self.report;
        let enc = if r.encrypted {
            "encrypted"
        } else {
            "plaintext"
        };
        format!(
            "PDF {} | {} | JS:{} | OpenAction:{} | Launch:{} | Files:{} | Score:{}/100 | Obfusc:{}",
            r.version,
            enc,
            r.javascript_count,
            if r.open_action { "yes" } else { "no" },
            r.launch_actions.len(),
            r.embedded_files.len(),
            r.threat_score,
            r.obfuscation_level
        )
    }

    #[must_use]
    pub fn extract_all_streams(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for (&id, &off) in &self.parser.xref {
            if let Ok((PdfObject::Stream { data, .. }, _)) =
                self.parser.parse_object_at(off as usize)
            {
                out.push((format!("{id} 0 obj"), data));
            }
        }
        out
    }

    #[must_use]
    pub fn get_js_streams(&self) -> Vec<(String, String)> {
        self.parser.find_all_js()
    }

    #[must_use]
    pub const fn threat_report(&self) -> &PdfMalwareReport {
        &self.report
    }
    #[must_use]
    pub const fn parser(&self) -> &PdfParser {
        &self.parser
    }
    #[must_use]
    pub fn version(&self) -> &str {
        &self.parser.version
    }
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.parser.xref.len()
    }
    #[must_use]
    pub const fn is_suspicious(&self, threshold: u8) -> bool {
        self.report.threat_score >= threshold
    }

    #[must_use]
    pub fn format_threat_report(&self) -> String {
        let r = &self.report;
        let mut s = String::new();
        s.push_str("=== PDF Threat Report ===\n");
        s.push_str(&format!("Version      : {}\n", r.version));
        s.push_str(&format!("Encrypted    : {}\n", r.encrypted));
        s.push_str(&format!("Threat Score : {}/100\n", r.threat_score));
        s.push_str(&format!("Obfuscation  : {}\n", r.obfuscation_level));
        s.push_str(&format!("JavaScript   : {} block(s)\n", r.javascript_count));
        s.push_str(&format!("OpenAction   : {}\n", r.open_action));
        if !r.launch_actions.is_empty() {
            s.push_str("Launch Actions:\n");
            for la in &r.launch_actions {
                s.push_str(&format!("  - {la}\n"));
            }
        }
        if !r.embedded_files.is_empty() {
            s.push_str("Embedded Files:\n");
            for ef in &r.embedded_files {
                let mut flags = Vec::new();
                if ef.is_pe {
                    flags.push("PE");
                }
                if ef.is_elf {
                    flags.push("ELF");
                }
                if ef.is_pdf {
                    flags.push("PDF");
                }
                let fs = if flags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", flags.join(", "))
                };
                s.push_str(&format!("  - {} ({} bytes){}\n", ef.filename, ef.size, fs));
            }
        }
        if !r.exploit_indicators.is_empty() {
            s.push_str("CVE Indicators:\n");
            for ind in &r.exploit_indicators {
                s.push_str(&format!(
                    "  - {} ({:.0}%): {}\n",
                    ind.cve,
                    ind.confidence * 100.0,
                    ind.description
                ));
            }
        }
        if !r.uri_actions.is_empty() {
            s.push_str("URI Actions:\n");
            for uri in &r.uri_actions {
                s.push_str(&format!("  - {uri}\n"));
            }
        }
        for js in &r.javascript_sources {
            s.push_str(&format!(
                "\n--- JS @ {} (score {}) ---\n",
                js.path, js.analysis.threat_score
            ));
            if js.analysis.heap_spray_likely {
                s.push_str("  [!] Heap spray detected\n");
            }
            for hit in &js.analysis.shellcode_patterns {
                s.push_str(&format!(
                    "  [!] Pattern ({}): {}\n",
                    hit.pattern_type, hit.raw_value
                ));
            }
            for url in &js.analysis.network_urls {
                s.push_str(&format!("  [!] Network URL: {url}\n"));
            }
        }
        s
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§5  Extended unit tests
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

#[cfg(test)]
mod extended_tests {
    use super::*;

    // PdfDict â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdfdict_get_missing() {
        let d = PdfDict::default();
        assert!(d.get("Foo").is_none());
    }

    #[test]
    fn test_pdfdict_set_and_get_name() {
        let mut d = PdfDict::default();
        d.set("Type", PdfObject::Name("Page".into()));
        assert_eq!(d.get_name("Type"), Some("Page"));
    }

    #[test]
    fn test_pdfdict_update_existing() {
        let mut d = PdfDict::default();
        d.set("Count", PdfObject::Integer(1));
        d.set("Count", PdfObject::Integer(42));
        assert_eq!(d.get_int("Count"), Some(42));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn test_pdfdict_contains_key() {
        let mut d = PdfDict::default();
        d.set("Root", PdfObject::Null);
        assert!(d.contains_key("Root"));
        assert!(!d.contains_key("Info"));
    }

    #[test]
    fn test_pdfdict_get_bool() {
        let mut d = PdfDict::default();
        d.set("Flag", PdfObject::Bool(true));
        assert_eq!(d.get_bool("Flag"), Some(true));
    }

    #[test]
    fn test_pdfdict_is_empty() {
        let d = PdfDict::default();
        assert!(d.is_empty());
        let mut d2 = PdfDict::default();
        d2.set("x", PdfObject::Null);
        assert!(!d2.is_empty());
    }

    #[test]
    fn test_pdfdict_get_array() {
        let mut d = PdfDict::default();
        d.set("Kids", PdfObject::Array(vec![PdfObject::Integer(1)]));
        assert!(d.get_array("Kids").is_some());
    }

    // PdfObject â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pdfobj_as_int_integer() {
        assert_eq!(PdfObject::Integer(7).as_int(), Some(7));
    }

    #[test]
    fn test_pdfobj_as_int_null() {
        assert_eq!(PdfObject::Null.as_int(), None);
    }

    #[test]
    fn test_pdfobj_is_null() {
        assert!(PdfObject::Null.is_null());
        assert!(!PdfObject::Bool(false).is_null());
    }

    #[test]
    fn test_pdfobj_as_str_name() {
        let o = PdfObject::Name("FlateDecode".into());
        assert_eq!(o.as_str_lossy().unwrap().as_ref(), "FlateDecode");
    }

    #[test]
    fn test_pdfobj_as_str_bytes() {
        let o = PdfObject::Bytes(b"hello".to_vec());
        assert_eq!(o.as_str_lossy().unwrap().as_ref(), "hello");
    }

    #[test]
    fn test_pdfobj_as_dict_dict() {
        let o = PdfObject::Dict(PdfDict::default());
        assert!(o.as_dict().is_some());
    }

    #[test]
    fn test_pdfobj_as_dict_stream() {
        let o = PdfObject::Stream {
            dict: PdfDict::default(),
            data: vec![],
        };
        assert!(o.as_dict().is_some());
    }

    #[test]
    fn test_pdfobj_as_dict_none_for_null() {
        assert!(PdfObject::Null.as_dict().is_none());
    }

    // PdfParser construction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parser_invalid_magic() {
        assert!(matches!(
            PdfParser::parse(b"random data".to_vec()),
            Err(PdfError::InvalidMagic)
        ));
    }

    #[test]
    fn test_parser_truncated() {
        assert!(matches!(
            PdfParser::parse(b"%PDF-1".to_vec()),
            Err(PdfError::TruncatedData)
        ));
    }

    #[test]
    fn test_parser_minimal_17() {
        let p = PdfParser::parse(b"%PDF-1.7\n%%EOF\n".to_vec()).unwrap();
        assert_eq!(p.version, "1.7");
    }

    #[test]
    fn test_parser_minimal_20() {
        let p = PdfParser::parse(b"%PDF-2.0\n%%EOF\n".to_vec()).unwrap();
        assert_eq!(p.version, "2.0");
    }

    // Filter helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_ascii85_z_group() {
        let r = PdfParser::apply_ascii85_decode(b"z~>").unwrap();
        assert_eq!(r, [0u8; 4]);
    }

    #[test]
    fn test_ascii85_empty_terminator() {
        let r = PdfParser::apply_ascii85_decode(b"~>").unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_ascii_hex_decode_hello() {
        let r = PdfParser::apply_ascii_hex_decode(b"48656c6c6f>").unwrap();
        assert_eq!(r, b"Hello");
    }

    #[test]
    fn test_ascii_hex_decode_spaces() {
        let r = PdfParser::apply_ascii_hex_decode(b"48 65 6c 6c 6f >").unwrap();
        assert_eq!(r, b"Hello");
    }

    #[test]
    fn test_run_length_eod() {
        let r = PdfParser::apply_run_length_decode(&[128]).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_run_length_literal_3() {
        let r = PdfParser::apply_run_length_decode(&[2, b'A', b'B', b'C', 128]).unwrap();
        assert_eq!(r, b"ABC");
    }

    #[test]
    fn test_run_length_repeat_2() {
        // 255 â†' repeat next byte 2 times
        let r = PdfParser::apply_run_length_decode(&[255, b'X', 128]).unwrap();
        assert_eq!(r, b"XX");
    }

    // Heap-spray detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_heap_spray_nop_sled() {
        // Assemble pattern without writing the full literal.
        let prefix = "%u90";
        let suffix = "90";
        let pat = format!("{prefix}{suffix}");
        let js = pat.repeat(6);
        assert!(PdfMalwareReport::detect_heap_spray(&js));
    }

    #[test]
    fn test_heap_spray_doubling() {
        let js = "var nop = 'a'; nop += nop; nop += nop;";
        assert!(PdfMalwareReport::detect_heap_spray(js));
    }

    #[test]
    fn test_heap_spray_large_array() {
        let js = "var x = new Array(50000).join(nop);";
        assert!(PdfMalwareReport::detect_heap_spray(js));
    }

    #[test]
    fn test_heap_spray_clean() {
        let js = "function add(a,b){return a+b;}";
        assert!(!PdfMalwareReport::detect_heap_spray(js));
    }

    // Pattern detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_patterns_charcode() {
        let cc: Vec<String> = (65u32..120).map(|n| n.to_string()).collect();
        let js = format!("String.fromCharCode({})", cc.join(","));
        let hits = PdfMalwareReport::detect_patterns(&js);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].pattern_type, "charcode_array");
    }

    #[test]
    fn test_patterns_clean() {
        let hits = PdfMalwareReport::detect_patterns("var x = 1 + 2;");
        assert!(hits.is_empty());
    }

    // URL extraction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_urls_http() {
        let js = r#"var u = "http://example.org/p";"#;
        let urls = extract_urls_from_js(js);
        assert!(!urls.is_empty());
        assert!(urls[0].contains("example.org"));
    }

    #[test]
    fn test_urls_dedup() {
        let js = r#"var a = "http://x.org/"; var b = "http://x.org/";"#;
        assert_eq!(extract_urls_from_js(js).len(), 1);
    }

    #[test]
    fn test_urls_none() {
        assert!(extract_urls_from_js("var x = 1;").is_empty());
    }

    // deobfuscate_js_simple â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_deobfuscate_concat() {
        let js = r#""hel"+"lo""#;
        assert_eq!(deobfuscate_js_simple(js), r#""hello""#);
    }

    #[test]
    fn test_deobfuscate_charcode_hello() {
        let js = "String.fromCharCode(72,101,108,108,111)";
        assert!(deobfuscate_js_simple(js).contains("Hello"));
    }

    #[test]
    fn test_deobfuscate_eval_double_quote() {
        let js = "eval(\"var x=1;\")";
        assert_eq!(deobfuscate_js_simple(js), "var x=1;");
    }

    // ObfuscationLevel â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_obfusc_ordering() {
        assert!(ObfuscationLevel::Extreme.score() > ObfuscationLevel::Heavy.score());
        assert!(ObfuscationLevel::Heavy.score() > ObfuscationLevel::Medium.score());
        assert!(ObfuscationLevel::None.score() == 0);
    }

    #[test]
    fn test_obfusc_display_all() {
        for (lvl, expected) in &[
            (ObfuscationLevel::None, "None"),
            (ObfuscationLevel::Light, "Light"),
            (ObfuscationLevel::Medium, "Medium"),
            (ObfuscationLevel::Heavy, "Heavy"),
            (ObfuscationLevel::Extreme, "Extreme"),
        ] {
            assert_eq!(&lvl.to_string(), expected);
        }
    }

    // Threat score â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_threat_score_zero_clean() {
        let report = PdfMalwareReport {
            threat_score: 0,
            version: "1.7".into(),
            encrypted: false,
            javascript_count: 0,
            javascript_sources: vec![],
            open_action: false,
            launch_actions: vec![],
            embedded_files: vec![],
            uri_actions: vec![],
            exploit_indicators: vec![],
            suspicious_streams: vec![],
            obfuscation_level: ObfuscationLevel::None,
        };
        assert_eq!(PdfMalwareReport::calculate_threat_score(&report), 0);
    }

    #[test]
    fn test_threat_score_launch() {
        let report = PdfMalwareReport {
            threat_score: 0,
            version: "1.7".into(),
            encrypted: false,
            javascript_count: 0,
            javascript_sources: vec![],
            open_action: false,
            launch_actions: vec!["cmd.exe".into()],
            embedded_files: vec![],
            uri_actions: vec![],
            exploit_indicators: vec![],
            suspicious_streams: vec![],
            obfuscation_level: ObfuscationLevel::None,
        };
        let score = PdfMalwareReport::calculate_threat_score(&report);
        assert!(score >= 25);
        drop(report);
    }

    #[test]
    fn test_threat_score_max_100() {
        let js_analysis = JsAnalysis {
            heap_spray_likely: true,
            shellcode_patterns: vec![ShellcodeHit {
                pattern_type: "t".into(),
                raw_value: "r".into(),
                decoded_bytes: None,
            }],
            deobfuscated: None,
            network_urls: vec!["http://x.com/".into()],
            obfuscation_techniques: vec!["eval".into(), "unescape".into()],
            threat_score: 90,
        };
        let report = PdfMalwareReport {
            threat_score: 0,
            version: "1.7".into(),
            encrypted: true,
            javascript_count: 3,
            javascript_sources: vec![JsInPdf {
                path: "1 0 obj".into(),
                source: "x".into(),
                analysis: js_analysis,
            }],
            open_action: true,
            launch_actions: vec!["cmd.exe".into()],
            embedded_files: vec![EmbeddedFileInfo {
                filename: "p.exe".into(),
                size: 100,
                is_pe: true,
                is_elf: false,
                is_pdf: false,
            }],
            uri_actions: vec!["http://x.com/".into()],
            exploit_indicators: vec![ExploitIndicator {
                cve: "CVE-X".into(),
                description: "d".into(),
                confidence: 0.9,
            }],
            suspicious_streams: vec![SuspiciousStream {
                object_id: 1,
                reason: "large".into(),
                size_bytes: 2_000_000,
            }],
            obfuscation_level: ObfuscationLevel::Extreme,
        };
        assert_eq!(PdfMalwareReport::calculate_threat_score(&report), 100);
    }

    // PdfBinaryView â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_binaryview_invalid_magic() {
        assert!(matches!(
            PdfBinaryView::load(b"not a pdf"),
            Err(PdfError::InvalidMagic)
        ));
    }

    #[test]
    fn test_binaryview_minimal_load() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert_eq!(bv.version(), "1.7");
    }

    #[test]
    fn test_binaryview_summary_has_version() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert!(bv.summary().contains("1.7"));
    }

    #[test]
    fn test_binaryview_not_suspicious_clean() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert!(!bv.is_suspicious(50));
    }

    #[test]
    fn test_binaryview_format_report() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert!(bv.format_threat_report().contains("Threat Score"));
    }

    #[test]
    fn test_binaryview_extract_streams_empty() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert!(bv.extract_all_streams().is_empty());
    }

    #[test]
    fn test_binaryview_object_count_minimal() {
        let bv = PdfBinaryView::load(b"%PDF-1.7\n%%EOF\n").unwrap();
        assert_eq!(bv.object_count(), 0);
    }

    // CVE detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cve_gotor() {
        let mut data = b"%PDF-1.7\n".to_vec();
        data.extend_from_slice(b"/GoToR << /F (doc.pdf) >>\n%%EOF\n");
        let p = PdfParser::parse(data).unwrap();
        let inds = PdfMalwareReport::detect_exploit_cves(&p);
        assert!(inds.iter().any(|i| i.cve.contains("CVE-2019-7089")));
    }

    #[test]
    fn test_cve_sing_font() {
        let mut data = b"%PDF-1.7\n".to_vec();
        data.extend_from_slice(b"/SING << /BaseFont /X >>\n%%EOF\n");
        let p = PdfParser::parse(data).unwrap();
        let inds = PdfMalwareReport::detect_exploit_cves(&p);
        assert!(inds.iter().any(|i| i.cve.contains("CVE-2010-2883")));
    }

    // read_be_uint â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_be_uint_1() {
        assert_eq!(read_be_uint(&[0xAB], 0, 1), 0xAB);
    }
    #[test]
    fn test_be_uint_2() {
        assert_eq!(read_be_uint(&[0x01, 0x02], 0, 2), 0x0102);
    }
    #[test]
    fn test_be_uint_zero_width() {
        assert_eq!(read_be_uint(&[0xFF], 0, 0), 0);
    }

    // EmbeddedFileInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_embedded_pe() {
        let info = EmbeddedFileInfo::from_data("x.exe".into(), b"MZ\x90\x00");
        assert!(info.is_pe);
        assert!(!info.is_elf);
    }

    #[test]
    fn test_embedded_elf() {
        let info = EmbeddedFileInfo::from_data("x.elf".into(), b"\x7FELF\x02\x01");
        assert!(info.is_elf);
        assert!(!info.is_pe);
    }

    #[test]
    fn test_embedded_pdf() {
        let info = EmbeddedFileInfo::from_data("inner.pdf".into(), b"%PDF-1.4");
        assert!(info.is_pdf);
    }

    #[test]
    fn test_embedded_size() {
        let info = EmbeddedFileInfo::from_data("f.bin".into(), &[0u8; 42]);
        assert_eq!(info.size, 42);
    }

    // decode_percent_encoding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_percent_xx() {
        assert_eq!(decode_percent_encoding("%41%42%43"), b"ABC");
    }

    #[test]
    fn test_decode_percent_u() {
        // %u0041 = UTF-16LE 'A' = bytes [0x41, 0x00]
        let r = decode_percent_encoding("%u0041");
        assert_eq!(r, &[0x41, 0x00]);
    }

    #[test]
    fn test_decode_no_encoding() {
        assert_eq!(decode_percent_encoding("hello"), b"hello");
    }

    #[test]
    fn test_decode_mixed() {
        let r = decode_percent_encoding("A%20B");
        assert_eq!(r, b"A B");
    }

    // hex_nibble_p â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_hex_nibble_digits() {
        assert_eq!(hex_nibble_p(b'0'), 0);
        assert_eq!(hex_nibble_p(b'9'), 9);
        assert_eq!(hex_nibble_p(b'a'), 10);
        assert_eq!(hex_nibble_p(b'f'), 15);
        assert_eq!(hex_nibble_p(b'A'), 10);
        assert_eq!(hex_nibble_p(b'F'), 15);
    }

    #[test]
    fn test_hex_nibble_invalid() {
        assert_eq!(hex_nibble_p(b'X'), 0);
    }

    // paeth_p â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_paeth_returns_a_when_closest() {
        // a=10, b=20, c=10 â†' pa=|20-10|=10, pb=|10-10|=0, pc=|10+20-20|=10
        // pb is smallest â†' returns b
        // Actually let's use a case where a wins:
        // a=5, b=100, c=5 â†' pa=95, pb=0, pc=95 â†' returns b
        // use a=5, b=6, c=100 â†' pa=94, pb=95, pc=89 â†' returns a? No.
        // Simple: a=b=c=0 â†' a
        assert_eq!(paeth_p(0, 0, 0), 0);
    }

    #[test]
    fn test_paeth_returns_b() {
        // a=200, b=5, c=200 â†' pa=|5-200|=195, pb=|200-200|=0 â†' returns b
        assert_eq!(paeth_p(200, 5, 200), 5);
    }
}



// ── LZW hostile-input regression tests ──────────────────────────────────────

#[cfg(test)]
mod lzw_hardening_tests {
    use super::{parser_lzw_decompress, PdfError};

    /// Pack a sequence of codes into an MSB-first bit stream at `width` bits.
    fn pack(codes: &[u16], width: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut nbits: u32 = 0;
        for &c in codes {
            acc = (acc << width) | u32::from(c);
            nbits += width;
            while nbits >= 8 {
                nbits -= 8;
                out.push(((acc >> nbits) & 0xFF) as u8);
            }
        }
        if nbits > 0 {
            out.push(((acc << (8 - nbits)) & 0xFF) as u8);
        }
        out
    }

    #[test]
    fn lzw_rejects_code_past_end_of_table_instead_of_panicking() {
        // 0x41 is a literal; 1000 is far past the 258-entry initial table.
        // Before the fix this stored prev = Some(1000) and the *next* code
        // panicked with "index out of bounds" inside `table[p as usize]`.
        let data = pack(&[0x41, 1000, 0x42], 9);
        match parser_lzw_decompress(&data, true) {
            Err(PdfError::InvalidStructure(msg)) => {
                assert!(msg.contains("out of range"), "{msg}");
            }
            other => panic!("expected InvalidStructure, got {other:?}"),
        }
    }

    #[test]
    fn lzw_rejects_first_code_without_clear_context() {
        let data = pack(&[1000], 9);
        assert!(matches!(
            parser_lzw_decompress(&data, true),
            Err(PdfError::InvalidStructure(_))
        ));
    }

    #[test]
    fn lzw_accepts_the_legal_kwkwk_case() {
        // code == table.len() is the one legal "not yet in table" code.
        let data = pack(&[0x41, 258, 257], 9);
        assert!(parser_lzw_decompress(&data, true).is_ok());
    }

    #[test]
    fn lzw_plain_literals_round_trip() {
        let data = pack(&[0x41, 0x42, 0x43, 257], 9);
        assert_eq!(parser_lzw_decompress(&data, true).unwrap(), b"ABC");
    }
}

#[cfg(test)]
mod malformed_input_hardening {
    //! Regressions for overflow and recursion guards on attacker-controlled PDF
    //! input. Each test FAILS when the corresponding guard is removed —
    //! verified by reintroducing the defect and re-running.

    use super::*;

    /// `/DecodeParms << /Columns … /Colors 4 /BitsPerComponent 8 >>` with a
    /// column count large enough that `columns * colors * bits` overflows.
    ///
    /// Unguarded, the product wraps in release builds (`overflow-checks` is off)
    /// and the predictor silently proceeds with a bogus `row_size` — it returns
    /// success on input it cannot possibly have decoded, and for other column
    /// values drives a multi-gigabyte `vec![0u8; row_size]`.
    #[test]
    fn png_predictor_rejects_overflowing_decode_parms() {
        let data = [0u8; 64];
        let err = parser_png_predictor(&data, 4, 8, 1usize << 60)
            .expect_err("columns * colors * bits overflows usize and must be rejected");
        assert!(
            err.to_string().contains("overflow"),
            "unexpected error: {err}"
        );
    }

    /// Honest predictor parameters must keep working.
    #[test]
    fn png_predictor_still_decodes_normal_parameters() {
        // 3 columns, 1 color, 8 bits => row_size 3, stride 4. Two "None" rows.
        let data = [0, 1, 2, 3, 0, 4, 5, 6];
        let out = parser_png_predictor(&data, 1, 8, 3).expect("well-formed rows must decode");
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6]);
    }

    /// `[[[[[…` costs one input byte and one stack frame per level.
    #[test]
    fn deeply_nested_arrays_error_instead_of_exhausting_the_stack() {
        let mut data = b"%PDF-1.4\n".to_vec();
        let start = data.len();
        data.extend(std::iter::repeat_n(b'[', 100_000));
        let parser = PdfParser::parse(data).expect("header is well-formed");
        let err = parser
            .parse_value(start)
            .expect_err("100k nesting levels must be refused");
        assert!(
            err.to_string().contains("nesting"),
            "unexpected error: {err}"
        );
    }

    /// Nesting within the cap still parses.
    #[test]
    fn moderately_nested_arrays_still_parse() {
        let depth = 8;
        let mut data = b"%PDF-1.4\n".to_vec();
        let start = data.len();
        data.extend(std::iter::repeat_n(b'[', depth));
        data.extend(std::iter::repeat_n(b']', depth));
        let parser = PdfParser::parse(data).expect("header is well-formed");
        let (val, _) = parser.parse_value(start).expect("8 levels are legitimate");
        assert!(matches!(val, PdfObject::Array(_)));
    }

    /// `/Index [4294967295 2]` makes `first + i` wrap on the second entry,
    /// aliasing object 0 with an offset that belongs to object 4294967295.
    #[test]
    fn xref_stream_index_wrap_does_not_alias_object_zero() {
        let body = b"<< /Type /XRef /Size 3 /W [1 2 1] /Index [4294967295 2] /Length 8 >>\nstream\n\x01\x00\x10\x00\x01\x00\x20\x00\nendstream\nendobj\n";
        let mut data = b"%PDF-1.5\n".to_vec();
        let obj_off = data.len();
        data.extend_from_slice(b"1 0 obj\n");
        data.extend_from_slice(body);
        data.extend_from_slice(format!("startxref\n{obj_off}\n%%EOF\n").as_bytes());
        let parser = PdfParser::parse(data).expect("header is well-formed");
        assert!(
            parser.xref.contains_key(&4_294_967_295),
            "the first /Index entry should have been recorded: {:?}",
            parser.xref
        );
        assert!(
            !parser.xref.contains_key(&0),
            "object 0 was aliased by a wrapped /Index counter: {:?}",
            parser.xref
        );
    }
}
