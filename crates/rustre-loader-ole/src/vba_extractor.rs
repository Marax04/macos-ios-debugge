//! `vba_extractor` — VBA source code extraction from OLE compound files
//!
//! Implements the VBA project parsing algorithm from the MS-OVBA specification:
//!
//! 1. Locate the `VBA` storage inside the OLE compound file.
//! 2. Read the `_VBA_PROJECT` stream to determine VBA version (VBA6 / VBA7).
//! 3. Read the `VBA/dir` stream, decompress it (MS-OVBA RLE), and parse the
//!    module list (names, offsets, code page).
//! 4. For each module, read the corresponding stream, decompress the p-code
//!    region, and extract the source code text.
//! 5. Optionally deobfuscate `Chr(n) & Chr(m)` concatenation patterns.
//!
//! # References
//! * [MS-OVBA] Open Office VBA File Format Structure specification.
//! * [MS-CFB]  Compound File Binary Format specification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VbaExtractorError {
    #[error("not an OLE file: {0}")]
    NotOle(String),
    #[error("VBA project not found: {0}")]
    ProjectNotFound(String),
    #[error("decompression error: {0}")]
    Decompression(String),
    #[error("dir stream parse error: {0}")]
    DirParse(String),
    #[error("module stream error: {0}")]
    ModuleStream(String),
    #[error("I/O error: {0}")]
    Io(String),
}

// ---------------------------------------------------------------------------
// VBA version
// ---------------------------------------------------------------------------

/// VBA version as encoded in the `_VBA_PROJECT` stream magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VbaVersion {
    Vba6,
    Vba7,
    Unknown(u16),
}

impl fmt::Display for VbaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vba6        => write!(f, "VBA6"),
            Self::Vba7        => write!(f, "VBA7"),
            Self::Unknown(v)  => write!(f, "Unknown({v:#06x})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Module type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ModuleType {
    /// Standard module (MODULETYPE record = 0x0021).
    #[default]
    Standard,
    /// Class module (MODULETYPE record = 0x0022).
    Class,
}

impl fmt::Display for ModuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "Standard"),
            Self::Class    => write!(f, "Class"),
        }
    }
}

// ---------------------------------------------------------------------------
// VBA module
// ---------------------------------------------------------------------------

/// A single VBA module with its decompressed source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaModule {
    /// Module name (from dir stream MODULENAME record).
    pub name: String,
    /// Module stream name inside the VBA storage.
    pub stream_name: String,
    /// Module type.
    pub module_type: ModuleType,
    /// Byte offset into the module stream where source code starts.
    pub text_offset: u32,
    /// Decompressed source code text.
    pub source_code: String,
    /// True if this module had p-code removed (`text_offset` applied).
    pub p_code_stripped: bool,
}

// ---------------------------------------------------------------------------
// VBA project
// ---------------------------------------------------------------------------

/// Parsed VBA project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaProject {
    /// VBA version.
    pub version: VbaVersion,
    /// Code page used in the dir stream.
    pub code_page: u16,
    /// Project name from PROJECTNAME record.
    pub project_name: String,
    /// Project description (may be empty).
    pub description: String,
    /// List of extracted modules.
    pub modules: Vec<VbaModule>,
    /// Raw dir stream bytes (decompressed).
    pub dir_stream: Vec<u8>,
}

impl VbaProject {
    /// Find a module by name (case-insensitive).
    #[must_use] 
    pub fn find_module(&self, name: &str) -> Option<&VbaModule> {
        self.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    /// Return source code for all modules concatenated with headers.
    #[must_use] 
    pub fn all_source(&self) -> String {
        self.modules
            .iter()
            .map(|m| format!("' === {} ({}) ===\n{}\n", m.name, m.module_type, m.source_code))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// MS-OVBA compression (RLE decompression)
// ---------------------------------------------------------------------------

/// Decompress a `CompressedContainer` as defined in MS-OVBA section 2.4.
pub fn decompress_ovba(data: &[u8]) -> Result<Vec<u8>, VbaExtractorError> {
    if data.is_empty() {
        return Err(VbaExtractorError::Decompression("empty input".into()));
    }
    // Signature byte must be 0x01.
    if data[0] != 0x01 {
        return Err(VbaExtractorError::Decompression(format!(
            "bad signature byte: {:#04x}",
            data[0]
        )));
    }
    let mut output = Vec::new();
    let mut pos = 1usize;

    while pos < data.len() {
        // Each CompressedChunk starts with a 2-byte header.
        if pos + 2 > data.len() { break; }
        let chunk_header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Bits 0-11: CompressedChunkSize - 3 (so actual = + 3).
        // Bit 15: 1 = compressed, 0 = uncompressed.
        let chunk_size  = ((chunk_header & 0x0FFF) + 3) as usize;
        let is_compressed = (chunk_header & 0x8000) != 0;

        if pos + chunk_size > data.len() { break; }
        let chunk = &data[pos..pos + chunk_size];
        pos += chunk_size;

        if !is_compressed {
            // Raw 4096-byte uncompressed chunk.
            output.extend_from_slice(&chunk[..chunk.len().min(4096)]);
            if chunk.len() < 4096 {
                output.resize(output.len() + 4096 - chunk.len(), 0);
            }
            continue;
        }

        // Compressed chunk: 8-byte flag groups.
        let output_start = output.len();
        let mut ci = 0usize;

        while ci < chunk.len() {
            let flags = chunk[ci];
            ci += 1;
            for bit in 0..8u8 {
                if ci >= chunk.len() { break; }
                if (flags >> bit) & 1 == 0 {
                    // Literal byte.
                    output.push(chunk[ci]);
                    ci += 1;
                } else {
                    // Copy token.
                    if ci + 2 > chunk.len() { break; }
                    let token = u16::from_le_bytes([chunk[ci], chunk[ci + 1]]);
                    ci += 2;

                    // Number of offset bits depends on the current decompressed size
                    // within this chunk (CopyToken encoding from MS-OVBA 2.4.1.3.6).
                    let decompressed_so_far = output.len() - output_start;
                    let length_mask;
                    let offset_mask;
                    let bit_count;
                    let max_length;
                    if decompressed_so_far <= 16 {
                        length_mask = 0x000F; offset_mask = 0xFFF0; bit_count = 12; max_length = 19;
                    } else if decompressed_so_far <= 32 {
                        length_mask = 0x001F; offset_mask = 0xFFE0; bit_count = 11; max_length = 35;
                    } else if decompressed_so_far <= 64 {
                        length_mask = 0x003F; offset_mask = 0xFFC0; bit_count = 10; max_length = 67;
                    } else if decompressed_so_far <= 128 {
                        length_mask = 0x007F; offset_mask = 0xFF80; bit_count = 9; max_length = 131;
                    } else if decompressed_so_far <= 256 {
                        length_mask = 0x00FF; offset_mask = 0xFF00; bit_count = 8; max_length = 259;
                    } else if decompressed_so_far <= 512 {
                        length_mask = 0x01FF; offset_mask = 0xFE00; bit_count = 7; max_length = 515;
                    } else if decompressed_so_far <= 1024 {
                        length_mask = 0x03FF; offset_mask = 0xFC00; bit_count = 6; max_length = 1027;
                    } else if decompressed_so_far <= 2048 {
                        length_mask = 0x07FF; offset_mask = 0xF800; bit_count = 5; max_length = 2051;
                    } else {
                        length_mask = 0x0FFF; offset_mask = 0xF000; bit_count = 4; max_length = 4099;
                    }

                    let length = (token & length_mask) as usize + 3;
                    let offset = ((token & offset_mask) >> (16 - bit_count)) as usize + 1;
                    // Enforce the per-window max_length per MS-OVBA 2.4.1.3.6:
                    // an over-long copy run would indicate stream corruption.
                    debug_assert!(
                        length <= max_length,
                        "VBA CopyToken length {length} exceeds window max_length {max_length}"
                    );
                    let length = length.min(max_length);

                    let copy_start = output.len().saturating_sub(offset);
                    for j in 0..length {
                        let byte = output.get(copy_start + j).copied().unwrap_or(0);
                        output.push(byte);
                    }
                }
            }
        }
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Dir stream parser
// ---------------------------------------------------------------------------

/// Parsed module entry from the dir stream.
#[derive(Debug, Default)]
struct DirModule {
    name: String,
    stream_name: String,
    module_type: ModuleType,
    text_offset: u32,
}


/// Parse the decompressed dir stream and return project metadata + module list.
fn parse_dir_stream(
    dir: &[u8],
) -> Result<(u16, String, String, Vec<DirModule>), VbaExtractorError> {
    let mut pos = 0usize;
    let mut code_page = 1252u16;
    let mut project_name = String::new();
    let mut description = String::new();
    let mut modules: Vec<DirModule> = Vec::new();
    let mut current_module: Option<DirModule> = None;

    macro_rules! read_u16 {
        () => {{
            if pos + 2 > dir.len() { break; }
            let v = u16::from_le_bytes([dir[pos], dir[pos+1]]);
            pos += 2;
            v
        }};
    }
    macro_rules! read_u32 {
        () => {{
            if pos + 4 > dir.len() { break; }
            let v = u32::from_le_bytes(dir[pos..pos+4].try_into().unwrap());
            pos += 4;
            v
        }};
    }
    macro_rules! read_bytes {
        ($n:expr) => {{
            let n = $n as usize;
            if pos + n > dir.len() { break; }
            let v = &dir[pos..pos+n];
            pos += n;
            v
        }};
    }

    loop {
        if pos + 2 > dir.len() { break; }
        let record_id = read_u16!();
        let record_size = read_u32!();

        match record_id {
            0x0003 => { // PROJECTCODEPAGE
                let cp = read_u16!();
                code_page = cp;
            }
            0x0004 => { // PROJECTNAME
                let s = read_bytes!(record_size);
                project_name = String::from_utf8_lossy(s).into_owned();
            }
            0x0005 => { // PROJECTDOCSTRING
                let s = read_bytes!(record_size);
                description = String::from_utf8_lossy(s).into_owned();
            }
            0x0006 | 0x003C | 0x003D | 0x0007 | 0x0008 | 0x000C
            | 0x000D | 0x000E | 0x000F | 0x0011 | 0x0012 | 0x0013
            | 0x0014 | 0x0016 | 0x0019 | 0x001C | 0x001D
            | 0x002F | 0x0030 | 0x0032 | 0x0033 | 0x002C | 0x002D
            | 0x002E => {
                // Skip these known project-level records.
                let _ = read_bytes!(record_size);
            }
            0x0015 => { // MODULENAME
                if let Some(m) = current_module.as_mut() {
                    let s = read_bytes!(record_size);
                    m.name = String::from_utf8_lossy(s).into_owned();
                } else {
                    current_module = Some(DirModule {
                        name: String::from_utf8_lossy(read_bytes!(record_size)).into_owned(),
                        ..Default::default()
                    });
                }
            }
            0x0047 => { /* MODULENAME Unicode (MODULENAMEUNICODE) — skip */ let _ = read_bytes!(record_size); }
            0x001A => { // MODULESTREAMNAME
                if let Some(m) = current_module.as_mut() {
                    let s = read_bytes!(record_size);
                    m.stream_name = String::from_utf8_lossy(s).into_owned();
                } else {
                    let _ = read_bytes!(record_size);
                }
            }
            0x0021 => { // MODULETYPE Standard
                if let Some(m) = current_module.as_mut() { m.module_type = ModuleType::Standard; }
                let _ = read_bytes!(record_size);
            }
            0x0022 => { // MODULETYPE Class
                if let Some(m) = current_module.as_mut() { m.module_type = ModuleType::Class; }
                let _ = read_bytes!(record_size);
            }
            0x0031 => { // MODULEOFFSET (text offset)
                if record_size == 4 {
                    let off = read_u32!();
                    if let Some(m) = current_module.as_mut() { m.text_offset = off; }
                } else { let _ = read_bytes!(record_size); }
            }
            0x002B => { // MODULETERM — end of module record
                let _ = read_bytes!(record_size);
                if let Some(m) = current_module.take() { modules.push(m); }
            }
            0x0010 => { // PROJECTMODULES — count of modules, skip
                let _ = read_bytes!(record_size);
            }
            _ => { let _ = read_bytes!(record_size); }
        }
    }
    if let Some(m) = current_module { modules.push(m); }
    Ok((code_page, project_name, description, modules))
}

pub trait GetOrInsertDefault<T> {
    fn get_or_insert_default_mut(&mut self) -> &mut T;
}
impl GetOrInsertDefault<DirModule> for Option<DirModule> {
    fn get_or_insert_default_mut(&mut self) -> &mut DirModule {
        if self.is_none() { *self = Some(DirModule::default()); }
        self.as_mut().unwrap()
    }
}

// ---------------------------------------------------------------------------
// VbaExtractor
// ---------------------------------------------------------------------------

/// Extracts VBA source code from an OLE compound file.
///
/// The caller is responsible for locating and providing the VBA-related
/// streams.  In a full implementation these would be read from the CFB
/// directory; here we accept pre-extracted stream bytes.
pub struct VbaExtractor {
    /// Raw bytes of the `_VBA_PROJECT` stream.
    pub vba_project_stream: Vec<u8>,
    /// Raw bytes of the `VBA/dir` stream (compressed).
    pub dir_stream_compressed: Vec<u8>,
    /// Map of module stream name → raw compressed module stream bytes.
    pub module_streams: HashMap<String, Vec<u8>>,
}

impl VbaExtractor {
    #[must_use] 
    pub const fn new(
        vba_project_stream: Vec<u8>,
        dir_stream_compressed: Vec<u8>,
        module_streams: HashMap<String, Vec<u8>>,
    ) -> Self {
        Self { vba_project_stream, dir_stream_compressed, module_streams }
    }

    /// Detect the VBA version from the `_VBA_PROJECT` stream magic bytes.
    #[must_use] 
    pub fn detect_version(&self) -> VbaVersion {
        if self.vba_project_stream.len() < 4 { return VbaVersion::Unknown(0); }
        // First 2 bytes are the PerformanceCache signature (ignored).
        // Bytes 2-3: version magic.
        let magic = u16::from_le_bytes([
            self.vba_project_stream[2],
            self.vba_project_stream[3],
        ]);
        match magic {
            0x61 => VbaVersion::Vba6,
            0x5F => VbaVersion::Vba7,
            v    => VbaVersion::Unknown(v),
        }
    }

    /// Extract the full VBA project.
    pub fn extract(&self) -> Result<VbaProject, VbaExtractorError> {
        let version = self.detect_version();

        // Decompress dir stream.
        let dir = decompress_ovba(&self.dir_stream_compressed)?;

        // Parse dir stream.
        let (code_page, project_name, description, dir_modules) =
            parse_dir_stream(&dir).map_err(|e| VbaExtractorError::DirParse(e.to_string()))?;

        // Extract source code for each module.
        let mut modules = Vec::new();
        for dm in dir_modules {
            let stream_name = if dm.stream_name.is_empty() { dm.name.clone() } else { dm.stream_name.clone() };
            let source_code = if let Some(compressed) = self.module_streams.get(&stream_name) {
                let raw = decompress_ovba(compressed)?;
                let offset = dm.text_offset as usize;
                let text_bytes = if offset < raw.len() { &raw[offset..] } else { &raw[..] };
                // Convert from code page to UTF-8 (simplified: treat as Latin-1).
                String::from_utf8_lossy(text_bytes).into_owned()
            } else {
                String::new()
            };

            let p_code_stripped = dm.text_offset > 0;
            modules.push(VbaModule {
                name: dm.name,
                stream_name,
                module_type: dm.module_type,
                text_offset: dm.text_offset,
                source_code,
                p_code_stripped,
            });
        }

        Ok(VbaProject {
            version,
            code_page,
            project_name,
            description,
            modules,
            dir_stream: dir,
        })
    }
}

// ---------------------------------------------------------------------------
// Deobfuscation
// ---------------------------------------------------------------------------

/// Deobfuscate VBA source code that uses `Chr(n)` concatenation.
///
/// Replaces patterns like `Chr(79) & Chr(83) & Chr(50)` with the literal
/// string `"OS2"`.
#[must_use] 
pub fn deobfuscate_chr_concat(source: &str) -> String {
    let mut result = source.to_owned();
    loop {
        // Find a Chr(...) & Chr(...) sequence.
        let pattern_start = result.find("Chr(");
        if pattern_start.is_none() { break; }
        // Replace all simple Chr(n) expressions.
        let new = replace_chr_calls(&result);
        if new == result { break; }
        result = new;
    }
    result
}

fn replace_chr_calls(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(pos) = rest.find("Chr(") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 4..];
        if let Some(close) = after.find(')') {
            let num_str = &after[..close];
            if let Ok(n) = num_str.trim().parse::<u32>()
                && let Some(c) = char::from_u32(n) {
                    out.push(c);
                    rest = &after[close + 1..];
                    // Skip " & " if present.
                    let trimmed = rest.trim_start_matches([' ', '&', ' ']);
                    if trimmed.len() < rest.len() { rest = trimmed; }
                    continue;
                }
        }
        // Not a simple Chr call — keep it as-is.
        out.push_str("Chr(");
        rest = after;
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// P-code removal
// ---------------------------------------------------------------------------

/// Strip the P-code from a raw module stream, leaving only source text.
///
/// The VBA spec stores source code starting at `text_offset` bytes into
/// the (decompressed) module stream.  The bytes before that offset are
/// compiled P-code which can differ between VBA6 and VBA7.
pub fn strip_pcode(compressed_module: &[u8], text_offset: u32) -> Result<String, VbaExtractorError> {
    let raw = decompress_ovba(compressed_module)?;
    let start = text_offset as usize;
    let text = if start < raw.len() { &raw[start..] } else { &[] };
    Ok(String::from_utf8_lossy(text).into_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_uncompressed_chunk() {
        // Minimal CompressedContainer: sig=0x01, chunk header with compressed=0.
        // An uncompressed chunk is 4096 bytes of raw data prefixed by a
        // 2-byte header with bit 15 = 0 and size field = 4093 (stored as 4096 - 3).
        let mut data = vec![0x01u8]; // signature
        let chunk_header: u16 = 4093_u16; // uncompressed, 4096 bytes
        data.extend_from_slice(&chunk_header.to_le_bytes());
        data.extend_from_slice(&vec![b'A'; 4096]);
        let result = decompress_ovba(&data);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert_eq!(out.len(), 4096);
        assert!(out.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn decompress_empty_fails() {
        assert!(decompress_ovba(&[]).is_err());
    }

    #[test]
    fn decompress_bad_signature_fails() {
        assert!(decompress_ovba(&[0x02, 0x00, 0x00]).is_err());
    }

    #[test]
    fn deobfuscate_chr_basic() {
        let src = r#"Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)"#;
        let result = deobfuscate_chr_concat(src);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn deobfuscate_chr_no_match() {
        let src = "MsgBox \"Hello\"";
        let result = deobfuscate_chr_concat(src);
        assert_eq!(result, src);
    }
}
