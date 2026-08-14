//! `vba_stream_extractor` — Extract and decode VBA macro streams from OLE files.
//!
//! Handles the VBA dir stream (module metadata) and the per-module compressed
//! p-code streams.  Implements the ZLIB-like MS-OVBA compression format used
//! by Office VBA containers.
//!
//! # Design note — intentionally separate from `vba_extractor`
//!
//! This module owns the lowest-level stream-extraction workflow:
//! [`VbaStreamExtractor`] consumes raw bytes of the `dir` stream and per-module
//! streams and produces [`VbaStream`] / [`VbaModule`] values.
//!
//! [`crate::vba_extractor`] operates one level higher — it takes pre-split
//! stream bytes (`dir`, `_VBA_PROJECT`, module map) and produces a full
//! [`crate::vba_extractor::VbaProject`] with version detection and source code.
//!
//! [`crate::ole_vba_extractor`] adds a security analysis layer on top
//! (`VbaReport`, `SecurityFinding`, `ObfuscatedVba`).
//!
//! All three modules contain an independent implementation of the MS-OVBA
//! RLE decompressor ([`decompress_vba`] here, `decompress_ovba` in
//! `vba_extractor`, `VbaCompressedStream::decompress` in `ole_vba_extractor`).
//! The three implementations are functionally equivalent; a future clean-up
//! should consolidate them into a single crate-internal helper.

use std::collections::HashMap;
use std::fmt;

// ── VbaModuleKind ─────────────────────────────────────────────────────────────

/// The kind of a VBA module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VbaModuleKind {
    /// Standard module (Module1, etc.).
    Standard,
    /// Class module (`ThisWorkbook`, Sheet1, etc.).
    Class,
    /// `UserForm` module (GUI form — we never render it).
    Form,
    /// Unknown / not yet determined.
    Unknown,
}

impl fmt::Display for VbaModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Standard => "Standard",
            Self::Class => "Class",
            Self::Form => "Form",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ── VbaModule ─────────────────────────────────────────────────────────────────

/// A single VBA module with its source code.
#[derive(Debug, Clone)]
pub struct VbaModule {
    /// Module name (e.g., "Module1", "`ThisWorkbook`").
    pub name: String,
    /// Kind of module.
    pub kind: VbaModuleKind,
    /// Offset within the module stream where the compressed source starts.
    pub text_offset: u32,
    /// Uncompressed source code bytes.
    pub source_code: Vec<u8>,
    /// Number of lines in the source code.
    pub line_count: usize,
    /// Whether the module is marked as read-only / protected.
    pub read_only: bool,
    /// Whether the module is private.
    pub private: bool,
}

impl VbaModule {
    /// Create a new module.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: VbaModuleKind, source: Vec<u8>) -> Self {
        let source_str = String::from_utf8_lossy(&source);
        let line_count = source_str.lines().count();
        Self {
            name: name.into(),
            kind,
            text_offset: 0,
            source_code: source,
            line_count,
            read_only: false,
            private: false,
        }
    }

    /// Return the source code as a UTF-8 string (lossy).
    #[must_use]
    pub fn source_str(&self) -> String {
        String::from_utf8_lossy(&self.source_code).into_owned()
    }

    /// Return `true` if the source code contains the given keyword (case-insensitive).
    #[must_use]
    pub fn contains_keyword(&self, keyword: &str) -> bool {
        let src = self.source_str().to_lowercase();
        src.contains(&keyword.to_lowercase())
    }

    /// Scan for suspicious patterns (common in macro malware).
    #[must_use]
    pub fn suspicious_keywords(&self) -> Vec<&'static str> {
        const SUSPICIOUS: &[&str] = &[
            "Shell",
            "CreateObject",
            "WScript",
            "PowerShell",
            "cmd.exe",
            "AutoOpen",
            "Document_Open",
            "Workbook_Open",
            "Auto_Open",
            "URLDownloadToFile",
            "environ",
            "Chr(",
            "StrReverse",
            "Base64",
        ];
        SUSPICIOUS
            .iter()
            .filter(|&&kw| self.contains_keyword(kw))
            .copied()
            .collect()
    }
}

impl fmt::Display for VbaModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VbaModule({:?}) kind={} lines={} bytes={}",
            self.name,
            self.kind,
            self.line_count,
            self.source_code.len(),
        )
    }
}

// ── VbaStream ─────────────────────────────────────────────────────────────────

/// A decoded VBA project, containing all modules and metadata.
#[derive(Debug, Clone)]
pub struct VbaStream {
    /// Office application name (from PROJECTNAME record in dir stream).
    pub project_name: String,
    /// VBA version string.
    pub vba_version: String,
    /// Code page of the VBA source.
    pub code_page: u16,
    /// All modules in the project.
    pub modules: Vec<VbaModule>,
    /// Raw dir stream bytes (for forensic reference).
    pub dir_stream: Vec<u8>,
    /// Number of modules with suspicious keywords.
    pub suspicious_module_count: usize,
}

impl VbaStream {
    /// Create a new `VbaStream`.
    #[must_use]
    pub fn new(project_name: impl Into<String>, code_page: u16) -> Self {
        Self {
            project_name: project_name.into(),
            vba_version: String::new(),
            code_page,
            modules: Vec::new(),
            dir_stream: Vec::new(),
            suspicious_module_count: 0,
        }
    }

    /// Add a module and update the suspicious count.
    pub fn add_module(&mut self, module: VbaModule) {
        if !module.suspicious_keywords().is_empty() {
            self.suspicious_module_count += 1;
        }
        self.modules.push(module);
    }

    /// Return a reference to a module by name.
    #[must_use]
    pub fn module_by_name(&self, name: &str) -> Option<&VbaModule> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Return all modules of a given kind.
    #[must_use]
    pub fn modules_of_kind(&self, kind: VbaModuleKind) -> Vec<&VbaModule> {
        self.modules.iter().filter(|m| m.kind == kind).collect()
    }

    /// Return `true` if any module has suspicious content.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.suspicious_module_count > 0
    }

    /// Total lines across all modules.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.modules.iter().map(|m| m.line_count).sum()
    }
}

impl fmt::Display for VbaStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VbaStream({:?}) modules={} lines={} suspicious={}",
            self.project_name,
            self.modules.len(),
            self.total_lines(),
            self.suspicious_module_count,
        )
    }
}

// ── MS-OVBA decompression ─────────────────────────────────────────────────────

/// Decompress a VBA module stream using MS-OVBA compression (MS-OVBA §2.4.1).
///
/// The compressed container starts with the byte `0x01`.  Data follows as a
/// sequence of decompressed chunks: each chunk starts with a 2-byte header
/// (little-endian) where bits [15] = 1 (compressed) or 0 (raw), bits [14:0]
/// give compressedSize-3.
///
/// Each compressed chunk contains 8-entry flag groups: a flag byte followed by
/// 8 tokens.  A 0-flag token is a literal byte; a 1-flag token is a copy token
/// (a back-reference into the decompressed buffer).
///
/// Returns `None` if the data does not begin with `0x01` or is malformed.
#[must_use]
pub fn decompress_vba(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data[0] != 0x01 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 1usize;

    while pos + 2 <= data.len() {
        let chunk_header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        let compressed = (chunk_header >> 15) & 1 == 1;
        let chunk_size = (chunk_header & 0x7FFF) as usize + 3;

        if pos + chunk_size > data.len() {
            // Truncated; use what we have.
            let raw = &data[pos..data.len()];
            out.extend_from_slice(raw);
            break;
        }

        let chunk_data = &data[pos..pos + chunk_size];
        pos += chunk_size;

        if !compressed {
            out.extend_from_slice(chunk_data);
            continue;
        }

        // Decompress the chunk.
        let decompressed_start = out.len();
        let mut ci = 0usize;
        while ci < chunk_data.len() {
            let flag_byte = chunk_data[ci];
            ci += 1;
            for bit in 0..8 {
                if ci >= chunk_data.len() {
                    break;
                }
                if (flag_byte >> bit) & 1 == 0 {
                    // Literal byte.
                    out.push(chunk_data[ci]);
                    ci += 1;
                } else {
                    // Copy token (2 bytes).
                    if ci + 1 >= chunk_data.len() {
                        break;
                    }
                    let token = u16::from_le_bytes([chunk_data[ci], chunk_data[ci + 1]]);
                    ci += 2;

                    let current_len = out.len() - decompressed_start;
                    let len_mask_bits = length_mask_bits(current_len);
                    let length_mask = (1u16 << len_mask_bits) - 1;
                    let offset_mask = !length_mask;

                    let length = (token & length_mask) as usize + 3;
                    let offset = ((token & offset_mask) >> len_mask_bits) as usize + 1;

                    let copy_start = out.len().saturating_sub(offset);
                    for i in 0..length {
                        let b = if copy_start + i < out.len() {
                            out[copy_start + i]
                        } else {
                            0
                        };
                        out.push(b);
                    }
                }
            }
        }
    }
    Some(out)
}

const fn length_mask_bits(decompressed_so_far: usize) -> usize {
    // MS-OVBA: the split between offset and length bits varies with how much
    // data has been decompressed in the current chunk.
    match decompressed_so_far {
        0..=15 => 12,
        16..=31 => 11,
        32..=63 => 10,
        64..=127 => 9,
        128..=255 => 8,
        256..=511 => 7,
        512..=1023 => 6,
        1024..=2047 => 5,
        _ => 4,
    }
}

/// Compress a byte slice using a simplified MS-OVBA raw (uncompressed) chunk
/// format.  Each chunk is at most 4096 bytes.
///
/// Used for round-trip testing — the output can be decompressed by [`decompress_vba`].
#[must_use]
pub fn compress_vba_raw(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01u8]; // signature byte
    for chunk in data.chunks(4093) {
        // chunk_size = chunk.len(); raw chunk: header bit 15 = 0
        let header = (chunk.len() as u16).wrapping_sub(3) & 0x7FFF; // compressed bit = 0
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

// ── VbaStreamExtractor ────────────────────────────────────────────────────────

/// Extracts VBA modules from raw OLE stream bytes.
///
/// Workflow:
/// 1. Call [`parse_dir_stream`] with the raw bytes of the `dir` stream to get
///    module metadata.
/// 2. Call [`extract_vba_code`] with the module stream bytes to decompress and
///    return source code.
#[derive(Debug)]
pub struct VbaStreamExtractor {
    /// Module metadata parsed from the dir stream.
    pub module_meta: HashMap<String, (VbaModuleKind, u32)>,
}

impl VbaStreamExtractor {
    /// Create a new extractor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            module_meta: HashMap::new(),
        }
    }

    /// Register module metadata manually (used when the dir stream has already
    /// been parsed by another component).
    pub fn register_module(&mut self, name: impl Into<String>, kind: VbaModuleKind, text_offset: u32) {
        self.module_meta.insert(name.into(), (kind, text_offset));
    }

    /// Parse a simplified dir stream and populate `module_meta`.
    ///
    /// The simulated dir stream format (for testing) is:
    /// ```text
    /// [4 bytes] module count (u32 LE)
    /// Per module:
    ///   [1 byte]  kind (0=Standard, 1=Class, 2=Form)
    ///   [4 bytes] text_offset (u32 LE)
    ///   [1 byte]  name_len
    ///   [N bytes] name (UTF-8)
    /// ```
    pub fn parse_dir_stream(&mut self, data: &[u8]) -> usize {
        if data.len() < 4 {
            return 0;
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let mut pos = 4;
        let mut parsed = 0;

        for _ in 0..count {
            if pos + 6 > data.len() {
                break;
            }
            let kind_byte = data[pos];
            pos += 1;
            let text_offset = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let name_len = data[pos] as usize;
            pos += 1;
            if pos + name_len > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
            pos += name_len;
            let kind = match kind_byte {
                0 => VbaModuleKind::Standard,
                1 => VbaModuleKind::Class,
                2 => VbaModuleKind::Form,
                _ => VbaModuleKind::Unknown,
            };
            self.module_meta.insert(name, (kind, text_offset));
            parsed += 1;
        }
        parsed
    }

    /// Extract VBA source code from a raw module stream.
    ///
    /// The `text_offset` tells us where in the module stream the compressed
    /// source begins (the bytes before are p-code we ignore).
    ///
    /// Returns `None` if decompression fails.
    #[must_use] 
    pub fn extract_vba_code(&self, module_name: &str, stream_data: &[u8]) -> Option<VbaModule> {
        let (kind, text_offset) = self.module_meta.get(module_name).copied().unwrap_or((VbaModuleKind::Unknown, 0));
        let offset = text_offset as usize;
        if offset >= stream_data.len() {
            return None;
        }
        let compressed = &stream_data[offset..];
        let source = decompress_vba(compressed)?;
        let mut module = VbaModule::new(module_name, kind, source);
        module.text_offset = text_offset;
        Some(module)
    }

    /// Build a complete `VbaStream` from a dir stream and a map of module
    /// stream bytes.
    pub fn build_vba_stream(
        &mut self,
        project_name: &str,
        dir_data: &[u8],
        module_streams: &HashMap<String, Vec<u8>>,
    ) -> VbaStream {
        self.parse_dir_stream(dir_data);
        let mut vba = VbaStream::new(project_name, 1252);
        vba.dir_stream = dir_data.to_vec();
        for (name, data) in module_streams {
            if let Some(module) = self.extract_vba_code(name, data) {
                vba.add_module(module);
            }
        }
        vba
    }

    /// Encode a simplified dir stream for testing (inverse of `parse_dir_stream`).
    #[must_use]
    pub fn encode_dir_stream(modules: &[(VbaModuleKind, u32, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        for (kind, offset, name) in modules {
            let kind_byte: u8 = match kind {
                VbaModuleKind::Standard => 0,
                VbaModuleKind::Class => 1,
                VbaModuleKind::Form => 2,
                VbaModuleKind::Unknown => 3,
            };
            out.push(kind_byte);
            out.extend_from_slice(&offset.to_le_bytes());
            let name_bytes = name.as_bytes();
            out.push(name_bytes.len() as u8);
            out.extend_from_slice(name_bytes);
        }
        out
    }
}

impl Default for VbaStreamExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"Hello World from VBA! This is some source code.";
        let compressed = compress_vba_raw(original);
        let decompressed = decompress_vba(&compressed).unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn test_decompress_requires_signature() {
        let bad = vec![0x00, 0x01, 0x02];
        assert!(decompress_vba(&bad).is_none());
    }

    #[test]
    fn test_decompress_empty_after_signature() {
        let data = vec![0x01u8];
        let result = decompress_vba(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_compress_vba_raw_large() {
        let data = vec![0xAAu8; 10_000];
        let compressed = compress_vba_raw(&data);
        let decompressed = decompress_vba(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_vba_module_kind_display() {
        assert_eq!(VbaModuleKind::Standard.to_string(), "Standard");
        assert_eq!(VbaModuleKind::Class.to_string(), "Class");
    }

    #[test]
    fn test_vba_module_contains_keyword() {
        let m = VbaModule::new("Module1", VbaModuleKind::Standard, b"Shell cmd.exe".to_vec());
        assert!(m.contains_keyword("shell"));
        assert!(!m.contains_keyword("python"));
    }

    #[test]
    fn test_vba_module_suspicious_keywords() {
        let m = VbaModule::new(
            "Module1",
            VbaModuleKind::Standard,
            b"Shell CreateObject AutoOpen".to_vec(),
        );
        let kws = m.suspicious_keywords();
        assert!(!kws.is_empty());
        assert!(kws.contains(&"Shell"));
    }

    #[test]
    fn test_vba_module_line_count() {
        let src = b"Sub foo()\n  Shell \"cmd\"\nEnd Sub";
        let m = VbaModule::new("M", VbaModuleKind::Standard, src.to_vec());
        assert_eq!(m.line_count, 3);
    }

    #[test]
    fn test_vba_module_display() {
        let m = VbaModule::new("Module1", VbaModuleKind::Standard, b"code".to_vec());
        assert!(m.to_string().contains("Module1"));
    }

    #[test]
    fn test_vba_stream_add_module_suspicious() {
        let mut vs = VbaStream::new("Project", 1252);
        let m = VbaModule::new("M", VbaModuleKind::Standard, b"Shell".to_vec());
        vs.add_module(m);
        assert_eq!(vs.suspicious_module_count, 1);
        assert!(vs.is_suspicious());
    }

    #[test]
    fn test_vba_stream_add_module_clean() {
        let mut vs = VbaStream::new("Project", 1252);
        let m = VbaModule::new("M", VbaModuleKind::Standard, b"Dim x As Integer".to_vec());
        vs.add_module(m);
        assert_eq!(vs.suspicious_module_count, 0);
        assert!(!vs.is_suspicious());
    }

    #[test]
    fn test_vba_stream_module_by_name() {
        let mut vs = VbaStream::new("Proj", 1252);
        vs.add_module(VbaModule::new("M1", VbaModuleKind::Standard, b"code".to_vec()));
        assert!(vs.module_by_name("M1").is_some());
        assert!(vs.module_by_name("M2").is_none());
    }

    #[test]
    fn test_vba_stream_modules_of_kind() {
        let mut vs = VbaStream::new("Proj", 1252);
        vs.add_module(VbaModule::new("M1", VbaModuleKind::Standard, b"x".to_vec()));
        vs.add_module(VbaModule::new("Cls", VbaModuleKind::Class, b"y".to_vec()));
        assert_eq!(vs.modules_of_kind(VbaModuleKind::Standard).len(), 1);
        assert_eq!(vs.modules_of_kind(VbaModuleKind::Class).len(), 1);
    }

    #[test]
    fn test_vba_stream_total_lines() {
        let mut vs = VbaStream::new("Proj", 1252);
        vs.add_module(VbaModule::new("M1", VbaModuleKind::Standard, b"a\nb\nc".to_vec()));
        vs.add_module(VbaModule::new("M2", VbaModuleKind::Standard, b"d\ne".to_vec()));
        assert_eq!(vs.total_lines(), 5);
    }

    #[test]
    fn test_vba_stream_display() {
        let vs = VbaStream::new("MyProject", 1252);
        let s = vs.to_string();
        assert!(s.contains("MyProject"));
    }

    #[test]
    fn test_parse_dir_stream() {
        let dir = VbaStreamExtractor::encode_dir_stream(&[
            (VbaModuleKind::Standard, 0, "Module1"),
            (VbaModuleKind::Class, 0, "ThisWorkbook"),
        ]);
        let mut ex = VbaStreamExtractor::new();
        let n = ex.parse_dir_stream(&dir);
        assert_eq!(n, 2);
        assert!(ex.module_meta.contains_key("Module1"));
        assert!(ex.module_meta.contains_key("ThisWorkbook"));
    }

    #[test]
    fn test_extract_vba_code() {
        let source = b"Sub AutoOpen()\nShell \"cmd\"\nEnd Sub";
        let compressed = compress_vba_raw(source);

        let mut ex = VbaStreamExtractor::new();
        ex.register_module("Module1", VbaModuleKind::Standard, 0);
        let module = ex.extract_vba_code("Module1", &compressed).unwrap();
        assert_eq!(&module.source_code, source);
        assert_eq!(module.kind, VbaModuleKind::Standard);
    }

    #[test]
    fn test_extract_vba_code_with_offset() {
        let source = b"Dim x As Integer";
        let mut stream_data = vec![0xAAu8; 8]; // p-code garbage at front
        stream_data.extend_from_slice(&compress_vba_raw(source));

        let mut ex = VbaStreamExtractor::new();
        ex.register_module("M", VbaModuleKind::Standard, 8);
        let module = ex.extract_vba_code("M", &stream_data).unwrap();
        assert_eq!(&module.source_code, source);
    }

    #[test]
    fn test_extract_vba_code_unknown_module() {
        let ex = VbaStreamExtractor::new();
        // offset=0, kind=Unknown because not registered
        let compressed = compress_vba_raw(b"code");
        let module = ex.extract_vba_code("UnknownMod", &compressed).unwrap();
        assert_eq!(module.kind, VbaModuleKind::Unknown);
    }

    #[test]
    fn test_build_vba_stream() {
        let dir = VbaStreamExtractor::encode_dir_stream(&[
            (VbaModuleKind::Standard, 0, "Module1"),
        ]);
        let source = b"Sub foo()\nEnd Sub";
        let mut streams = HashMap::new();
        streams.insert("Module1".to_string(), compress_vba_raw(source));

        let mut ex = VbaStreamExtractor::new();
        let vba = ex.build_vba_stream("TestProject", &dir, &streams);
        assert_eq!(vba.project_name, "TestProject");
        assert_eq!(vba.modules.len(), 1);
        assert_eq!(vba.modules[0].name, "Module1");
    }
}
