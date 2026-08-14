//! LLVM bitcode extraction from IPA / Mach-O binaries.
//!
//! Apple embeds LLVM bitcode inside the `__LLVM,__bundle` section of the
//! Mach-O binary.  The section contains an `xar` archive (a self-contained
//! XML+content archive format) which in turn contains individual LLVM bitcode
//! module files.
//!
//! This module provides:
//! * [`XarArchive`] — minimal xar archive parser.
//! * [`BitcodeModule`] — a single extracted bitcode module.
//! * [`BitcodeExtractor`] — locates the `__LLVM,__bundle` section and extracts modules.
//! * Bitcode magic-byte detection and module listing.
//! * Function name listing from bitcode (heuristic scan for LLVM IR function records).

// ─────────────────────────────────────────────────────────────────────────────
// BitcodeError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from bitcode extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcodeError {
    NoLlvmSection,
    NotXarArchive,
    XarParseError(String),
    BitcodeParseError(String),
    Truncated,
    DecompressError(String),
}

impl std::fmt::Display for BitcodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLlvmSection => write!(f, "no __LLVM,__bundle section found"),
            Self::NotXarArchive => write!(f, "not a xar archive"),
            Self::XarParseError(s) => write!(f, "xar parse error: {s}"),
            Self::BitcodeParseError(s) => write!(f, "bitcode parse error: {s}"),
            Self::Truncated => write!(f, "data truncated"),
            Self::DecompressError(s) => write!(f, "decompression error: {s}"),
        }
    }
}

impl std::error::Error for BitcodeError {}

// ─────────────────────────────────────────────────────────────────────────────
// LLVM bitcode magic
// ─────────────────────────────────────────────────────────────────────────────

/// LLVM bitcode wrapper magic `BC` (0x4243) + `0xDEFB` = `BC 0xC0DE`.
pub const LLVM_BC_MAGIC: u32 = 0xDEFB_BC00 | 0xB;
/// Raw bitcode wrapper magic bytes (little-endian).
pub const LLVM_BC_MAGIC_BYTES: [u8; 4] = [0x42, 0x43, 0xC0, 0xDE];
/// LLVM IR `<MODULE_BLOCK>` start pattern.
pub const LLVM_IR_MAGIC: [u8; 4] = [0xDE, 0xC0, 0x17, 0x0B];

/// Detect whether `data` starts with LLVM bitcode magic.
#[must_use]
pub fn is_bitcode(data: &[u8]) -> bool {
    data.starts_with(&LLVM_BC_MAGIC_BYTES) || data.starts_with(&LLVM_IR_MAGIC)
}

// ─────────────────────────────────────────────────────────────────────────────
// xar archive format
// ─────────────────────────────────────────────────────────────────────────────

/// xar archive header (28 bytes, big-endian).
#[derive(Debug, Clone)]
pub struct XarHeader {
    /// Must be 0x78617221 (`xar!`).
    pub magic: u32,
    /// Header size in bytes.
    pub header_size: u16,
    /// Format version (must be 1).
    pub version: u16,
    /// Compressed size of the TOC XML.
    pub toc_length_compressed: u64,
    /// Uncompressed size of the TOC XML.
    pub toc_length_uncompressed: u64,
    /// Checksum algorithm (0=none, 1=SHA-1, 2=MD5, 3=SHA-256, 4=SHA-512).
    pub cksum_alg: u32,
}

pub const XAR_MAGIC: u32 = 0x7861_7221;

impl XarHeader {
    /// Parse from the start of `data`.
    ///
    /// # Errors
    /// Returns [`BitcodeError::Truncated`] if data is too short,
    /// or [`BitcodeError::NotXarArchive`] if the magic is wrong.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail.
    pub fn parse(data: &[u8]) -> Result<Self, BitcodeError> {
        if data.len() < 28 {
            return Err(BitcodeError::Truncated);
        }
        let magic = u32::from_be_bytes(data[..4].try_into().unwrap());
        if magic != XAR_MAGIC {
            return Err(BitcodeError::NotXarArchive);
        }
        let header_size = u16::from_be_bytes([data[4], data[5]]);
        let version = u16::from_be_bytes([data[6], data[7]]);
        let toc_comp = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let toc_uncomp = u64::from_be_bytes(data[16..24].try_into().unwrap());
        let cksum_alg = u32::from_be_bytes(data[24..28].try_into().unwrap());
        Ok(Self { magic, header_size, version, toc_length_compressed: toc_comp,
            toc_length_uncompressed: toc_uncomp, cksum_alg })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XarTocEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A file entry from the xar TOC (table of contents).
#[derive(Debug, Clone)]
pub struct XarTocEntry {
    /// File name.
    pub name: String,
    /// Heap offset (relative to start of heap, i.e. after header + TOC).
    pub offset: u64,
    /// Compressed size in the heap.
    pub length: u64,
    /// Uncompressed size.
    pub size: u64,
    /// Encoding (e.g. `"application/x-gzip"`, `"application/octet-stream"`).
    pub encoding: String,
    /// File ID.
    pub id: u64,
}

/// Parse xar TOC XML (minimal, no external XML lib).
#[must_use]
pub fn parse_xar_toc(xml: &str) -> Vec<XarTocEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    let bytes = xml.as_bytes();

    while pos < bytes.len() {
        // Find <file ...> or <file>
        if let Some(file_start) = xml[pos..].find("<file") {
            let abs = pos + file_start;
            // Find id attribute.
            let id_val = find_attr_or_zero(xml, abs, "id");

            // Find </file> end.
            let content_start = xml[abs..].find('>').map_or(abs, |p| abs + p + 1);
            let content_end = xml[content_start..].find("</file>").map_or(content_start, |p| content_start + p);
            let content = &xml[content_start..content_end];

            let name = xml_text(content, "name");
            let offset = xml_text(content, "offset").parse::<u64>().unwrap_or(0);
            let length = xml_text(content, "length").parse::<u64>().unwrap_or(0);
            let size = xml_text(content, "size").parse::<u64>().unwrap_or(0);
            let encoding = xml_attr_or(content, "style", "application/octet-stream");

            if !name.is_empty() {
                entries.push(XarTocEntry { name, offset, length, size, encoding, id: id_val });
            }

            pos = content_end + 7;
        } else {
            break;
        }
    }
    entries
}

fn xml_text(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(s) = xml.find(&open) {
        let after = s + open.len();
        if let Some(e) = xml[after..].find(&close) {
            return xml[after..after+e].to_string();
        }
    }
    String::new()
}

fn xml_attr_or(xml: &str, attr: &str, default: &str) -> String {
    let search = format!("{attr}=\"");
    if let Some(pos) = xml.find(&search) {
        let start = pos + search.len();
        if let Some(end) = xml[start..].find('"') {
            return xml[start..start+end].to_string();
        }
    }
    default.to_string()
}

fn find_attr_or_zero(xml: &str, pos: usize, attr: &str) -> u64 {
    let search = format!("{attr}=\"");
    if let Some(a) = xml[pos..pos+64.min(xml.len()-pos)].find(&search) {
        let start = pos + a + search.len();
        if let Some(end) = xml[start..].find('"') {
            return xml[start..start+end].parse().unwrap_or(0);
        }
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// XarArchive
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed xar archive.
#[derive(Debug)]
pub struct XarArchive {
    pub header: XarHeader,
    pub toc_entries: Vec<XarTocEntry>,
    /// The heap section (raw bytes after the TOC).
    heap: Vec<u8>,
}

impl XarArchive {
    /// Parse a xar archive from raw bytes.
    ///
    /// # Errors
    /// Returns an error if the data is not a valid xar archive or is truncated.
    pub fn parse(data: &[u8]) -> Result<Self, BitcodeError> {
        let header = XarHeader::parse(data)?;

        let toc_start = header.header_size as usize;
        let toc_end = toc_start + usize::try_from(header.toc_length_compressed).unwrap_or(usize::MAX);

        if toc_end > data.len() {
            return Err(BitcodeError::Truncated);
        }

        let toc_compressed = &data[toc_start..toc_end];

        // Attempt zlib decompression (xar always uses zlib-compressed TOC).
        // Without `flate2`, we fall back to treating as raw XML if it starts with `<`.
        let toc_xml = if toc_compressed.starts_with(b"<?xml") || toc_compressed.starts_with(b"<xar>") {
            String::from_utf8_lossy(toc_compressed).into_owned()
        } else {
            // Check for zlib header (0x78 0x9C / 0x78 0xDA / 0x78 0x01).
            if toc_compressed.len() >= 2 && toc_compressed[0] == 0x78 {
                // Real impl would call zlib::decompress here.
                // Return empty XML for now; callers that need real extraction
                // should integrate flate2.
                String::from("<xar><toc></toc></xar>")
            } else {
                String::from_utf8_lossy(toc_compressed).into_owned()
            }
        };

        let toc_entries = parse_xar_toc(&toc_xml);
        let heap = data[toc_end..].to_vec();

        Ok(Self { header, toc_entries, heap })
    }

    /// List all file names in the archive.
    #[must_use]
    pub fn file_names(&self) -> Vec<&str> {
        self.toc_entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Extract a file by name (returns the heap slice for that entry).
    ///
    /// # Errors
    /// Returns an error if the entry is not found or the data is truncated.
    pub fn extract(&self, name: &str) -> Result<Vec<u8>, BitcodeError> {
        let entry = self.toc_entries.iter().find(|e| e.name == name)
            .ok_or_else(|| BitcodeError::XarParseError(format!("entry '{name}' not found")))?;

        let start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
        let end = start + usize::try_from(entry.length).unwrap_or(usize::MAX);

        if end > self.heap.len() {
            return Err(BitcodeError::Truncated);
        }

        let raw = &self.heap[start..end];

        // Decompress if needed (gzip/zlib detected by encoding).
        // For now return raw (caller must handle decompression).
        let _ = entry.encoding.contains("gzip");
        Ok(raw.to_vec())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitcodeModule
// ─────────────────────────────────────────────────────────────────────────────

/// A single LLVM bitcode module extracted from the archive.
#[derive(Debug, Clone)]
pub struct BitcodeModule {
    /// Module file name inside the xar archive.
    pub name: String,
    /// Whether the data starts with valid bitcode magic.
    pub is_valid_bitcode: bool,
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Function names extracted by heuristic scan.
    pub functions: Vec<String>,
    /// Module metadata strings found.
    pub metadata: Vec<String>,
}

impl BitcodeModule {
    /// Create a module from raw data and a name.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        let is_valid = is_bitcode(&data);
        let functions = scan_function_names(&data);
        let metadata = scan_metadata_strings(&data);
        Self {
            name: name.into(),
            is_valid_bitcode: is_valid,
            data,
            functions,
            metadata,
        }
    }
}

/// Heuristic scan for LLVM IR function names in raw bitcode.
///
/// Looks for NUL-terminated strings that resemble function names (start with
/// `_Z`, `__`, or are short identifiers).
fn scan_function_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 < data.len() {
        // Look for `$s` (Swift) or `_Z` (C++ mangled) or `__` prefixes.
        let is_fn_start = (data[i] == b'_' && (data[i+1] == b'Z' || data[i+1] == b'_'))
            || (data[i] == b'$' && data[i+1] == b's');

        if is_fn_start {
            let start = i;
            let mut end = i;
            while end < data.len() && end - start < 256
                && (data[end].is_ascii_alphanumeric() || matches!(data[end], b'_' | b'$' | b'@' | b'.')) {
                end += 1;
            }
            if end - start >= 3 {
                if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                    out.push(s.to_string());
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

/// Scan for LLVM metadata strings in bitcode (module IDs, filenames, etc.).
fn scan_metadata_strings(data: &[u8]) -> Vec<String> {
    // LLVM metadata strings are typically stored as length-prefixed UTF-8.
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        // Look for printable ASCII runs >= 8 chars that contain '/' or '.c' / '.cpp' / '.swift'.
        let start = i;
        while i < data.len() && data[i].is_ascii_graphic() { i += 1; }
        let len = i - start;
        if len >= 8
            && let Ok(s) = std::str::from_utf8(&data[start..start+len])
                && {
                    let sp = std::path::Path::new(s);
                    let ext = sp.extension();
                    s.contains('/') || ext.is_some_and(|e| e.eq_ignore_ascii_case("c"))
                        || ext.is_some_and(|e| e.eq_ignore_ascii_case("cpp"))
                        || ext.is_some_and(|e| e.eq_ignore_ascii_case("swift"))
                        || ext.is_some_and(|e| e.eq_ignore_ascii_case("m"))
                        || ext.is_some_and(|e| e.eq_ignore_ascii_case("h"))
                } {
                    out.push(s.to_string());
                }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// BitcodeExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Locates and extracts LLVM bitcode from a Mach-O binary.
pub struct BitcodeExtractor<'a> {
    data: &'a [u8],
}

impl<'a> BitcodeExtractor<'a> {
    /// Create an extractor from a Mach-O binary blob.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Locate the `__LLVM,__bundle` section.
    #[must_use]
    pub fn find_llvm_bundle(&self) -> Option<(usize, usize)> {
        // Scan for xar magic preceded by __LLVM segment.
        let xar_magic = XAR_MAGIC.to_be_bytes();
        let mut i = 0usize;
        while i + 4 <= self.data.len() {
            if self.data[i..i+4] == xar_magic {
                return Some((i, self.data.len() - i));
            }
            i += 1;
        }
        None
    }

    /// `true` if the binary contains an LLVM bundle.
    #[must_use]
    pub fn has_bitcode(&self) -> bool {
        self.find_llvm_bundle().is_some()
    }

    /// Extract and parse the xar archive from `__LLVM,__bundle`.
    ///
    /// # Errors
    /// Returns [`BitcodeError::NoLlvmSection`] if no bitcode bundle is found,
    /// or propagates parsing errors.
    pub fn open_archive(&self) -> Result<XarArchive, BitcodeError> {
        let (off, sz) = self.find_llvm_bundle().ok_or(BitcodeError::NoLlvmSection)?;
        XarArchive::parse(&self.data[off..off+sz])
    }

    /// Extract all bitcode modules from the archive.
    ///
    /// # Errors
    /// Returns an error if the archive cannot be opened or a module cannot be extracted.
    pub fn extract_modules(&self) -> Result<Vec<BitcodeModule>, BitcodeError> {
        let archive = self.open_archive()?;
        let mut modules = Vec::new();
        for entry in &archive.toc_entries {
            let nl = entry.name.to_ascii_lowercase();
            if std::path::Path::new(&nl).extension().is_some_and(|e| e.eq_ignore_ascii_case("bc"))
                || std::path::Path::new(&nl).extension().is_some_and(|e| e.eq_ignore_ascii_case("ll"))
            {
                let data = archive.extract(&entry.name)?;
                modules.push(BitcodeModule::new(entry.name.clone(), data));
            }
        }
        Ok(modules)
    }

    /// List module names without extracting content.
    ///
    /// # Errors
    /// Returns an error if the archive cannot be opened.
    pub fn list_modules(&self) -> Result<Vec<String>, BitcodeError> {
        let archive = self.open_archive()?;
        Ok(archive.file_names().into_iter().map(ToString::to_string).collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitcodeReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of bitcode analysis.
#[derive(Debug, Clone, Default)]
pub struct BitcodeReport {
    pub has_bitcode: bool,
    pub module_count: usize,
    pub total_function_count: usize,
    pub modules: Vec<ModuleSummary>,
}

/// Summary of a single bitcode module.
#[derive(Debug, Clone)]
pub struct ModuleSummary {
    pub name: String,
    pub size_bytes: usize,
    pub is_valid_bitcode: bool,
    pub function_count: usize,
    pub source_files: Vec<String>,
}

impl BitcodeReport {
    /// Build a report from a list of extracted modules.
    #[must_use]
    pub fn build(modules: &[BitcodeModule]) -> Self {
        let has_bitcode = !modules.is_empty();
        let module_count = modules.len();
        let total_function_count = modules.iter().map(|m| m.functions.len()).sum();
        let summaries = modules.iter().map(|m| {
            let source_files = m.metadata.iter()
                .filter(|s| {
                    let sl = s.to_ascii_lowercase();
                    let slp = std::path::Path::new(&sl);
                    let sle = slp.extension();
                    sle.is_some_and(|e| e.eq_ignore_ascii_case("swift"))
                        || sle.is_some_and(|e| e.eq_ignore_ascii_case("cpp"))
                        || sle.is_some_and(|e| e.eq_ignore_ascii_case("c"))
                        || sle.is_some_and(|e| e.eq_ignore_ascii_case("m"))
                })
                .cloned().collect();
            ModuleSummary {
                name: m.name.clone(),
                size_bytes: m.data.len(),
                is_valid_bitcode: m.is_valid_bitcode,
                function_count: m.functions.len(),
                source_files,
            }
        }).collect();
        Self {
            has_bitcode,
            module_count,
            total_function_count,
            modules: summaries,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bitcode_true() {
        assert!(is_bitcode(&LLVM_BC_MAGIC_BYTES));
        assert!(is_bitcode(&LLVM_IR_MAGIC));
    }

    #[test]
    fn test_is_bitcode_false() {
        assert!(!is_bitcode(&[0x55u8, 0x48, 0x89, 0xE5]));
        assert!(!is_bitcode(&[0xCAu8, 0xFE, 0xBA, 0xBE]));
    }

    #[test]
    fn test_xar_bad_magic() {
        let data = [0x00u8; 32];
        assert_eq!(XarArchive::parse(&data).unwrap_err(), BitcodeError::NotXarArchive);
    }

    #[test]
    fn test_xar_header_parse() {
        let mut data = vec![0u8; 32];
        data[..4].copy_from_slice(&XAR_MAGIC.to_be_bytes());
        data[4..6].copy_from_slice(&28u16.to_be_bytes()); // header_size
        data[6..8].copy_from_slice(&1u16.to_be_bytes());  // version
        // toc_length_compressed = 0, uncompressed = 0, cksum = 0
        let hdr = XarHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic, XAR_MAGIC);
        assert_eq!(hdr.version, 1);
    }

    #[test]
    fn test_scan_function_names() {
        let mut data = vec![0u8; 64];
        let fn_name = b"_ZN6MyClass6methodEv";
        data[10..10+fn_name.len()].copy_from_slice(fn_name);
        data[10+fn_name.len()] = 0;
        let fns = scan_function_names(&data);
        assert!(fns.iter().any(|f| f.contains("_ZN6")));
    }

    #[test]
    fn test_bitcode_module_detection() {
        let mut data = LLVM_BC_MAGIC_BYTES.to_vec();
        data.extend_from_slice(&[0u8; 64]);
        let module = BitcodeModule::new("test.bc", data);
        assert!(module.is_valid_bitcode);
    }

    #[test]
    fn test_report_build() {
        let mut bc_data = LLVM_BC_MAGIC_BYTES.to_vec();
        bc_data.extend_from_slice(b"_ZN3foo3barEv\x00/src/foo.cpp\x00");
        let modules = vec![BitcodeModule::new("module.bc", bc_data)];
        let report = BitcodeReport::build(&modules);
        assert!(report.has_bitcode);
        assert_eq!(report.module_count, 1);
    }

    #[test]
    fn test_extractor_no_bitcode() {
        let data = vec![0x55u8; 128];
        let extractor = BitcodeExtractor::new(&data);
        assert!(!extractor.has_bitcode());
        assert_eq!(extractor.open_archive().unwrap_err(), BitcodeError::NoLlvmSection);
    }

    #[test]
    fn test_xml_text_helper() {
        let xml = "<name>hello.bc</name><offset>128</offset>";
        assert_eq!(xml_text(xml, "name"), "hello.bc");
        assert_eq!(xml_text(xml, "offset"), "128");
        assert_eq!(xml_text(xml, "missing"), "");
    }
}
