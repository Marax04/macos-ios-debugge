//! `xex_loader` — Xbox 360 XEX2 format loader
//!
//! Implements parsing of Xbox 360 Executable (XEX) format version 2 (XEX2),
//! the primary executable format used on the Xbox 360 retail and development
//! kits.
//!
//! # Format overview
//!
//! ```text
//! XEX2 File:
//!   [XEX2 Header]         — 24 bytes (magic, flags, PE offset, security offset, …)
//!   [Directory Entries]   — array of (type, offset) pairs
//!   [Security Info]       — image key, execution info, page descriptors
//!   [Optional Headers]    — variable list of typed headers (import libs, TLS, etc.)
//!   [Compressed / Raw PE] — the embedded Xbox 360 PE image
//! ```
//!
//! # References
//! * Free60 XEX format documentation.
//! * xextool / x360t source.
//! * Xbox 360 SDK headers.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const XEX2_MAGIC: u32 = 0x5845_5832; // "XEX2"
pub const XEX1_MAGIC: u32 = 0x5845_5831; // "XEX1"
pub const XEX0_MAGIC: u32 = 0x5845_5830; // "XEX0"
pub const XUIZ_MAGIC: u32 = 0x5855_495A; // "XUIZ" (XNA XNET compressed)

/// Module flags.
pub mod module_flags {
    pub const TITLE_MODULE:   u32 = 0x0001;
    pub const EXPORTS_TO_TITLE: u32 = 0x0002;
    pub const SYSTEM_DEBUGGER: u32 = 0x0004;
    pub const DLL_MODULE:     u32 = 0x0008;
    pub const MODULE_PATCH:   u32 = 0x0010;
    pub const PATCH_FULL:     u32 = 0x0020;
    pub const PATCH_DELTA:    u32 = 0x0040;
    pub const USER_MODE:      u32 = 0x0080;
}

/// Optional header type IDs.
pub mod opt_header {
    pub const SYSTEM_FLAGS:    u32 = 0x0001_0000;
    pub const EXECUTION_ID:    u32 = 0x0004_0006;
    pub const SERVICE_ID_LIST: u32 = 0x000E_0102;
    pub const FILE_FORMAT_INFO: u32 = 0x0000_03FF;
    pub const DELTA_PATCH_DESC: u32 = 0x0000_5005;
    pub const BOUND_PATH:      u32 = 0x0008_0101;
    pub const DEVICE_ID:       u32 = 0x0000_8105;
    pub const ORIGINAL_PE_NAME: u32 = 0x0001_83FF;
    pub const STATIC_LIBS:     u32 = 0x0002_00FF;
    pub const TLS_INFO:        u32 = 0x0002_0104;
    pub const DEFAULT_STACK_SIZE: u32 = 0x0002_0200;
    pub const DEFAULT_HEAP_SIZE: u32 = 0x0002_0301;
    pub const PAGE_HEAP_SIZE:  u32 = 0x0002_8002;
    pub const IMPORT_LIBS:     u32 = 0x0001_03FF;
    pub const CHECKSUM_TIMESTAMP: u32 = 0x0001_8002;
    pub const ENABLED_FOR_CALLCAP: u32 = 0x0001_8102;
    pub const ENABLED_FOR_FASTCAP: u32 = 0x0001_8200;
    pub const ORIGINAL_PE_IMPORT_THUNK: u32 = 0x0001_8300;
    pub const EXPORT_BY_NAME:  u32 = 0x0040_0100;
    pub const EXPORT_BY_NAME_NEXT: u32 = 0x0041_8100;
    pub const COMPRESSION_INFO: u32 = 0x0001_83FE;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum XexLoaderError {
    #[error("not a XEX file: bad magic {0:#010x}")]
    BadMagic(u32),
    #[error("XEX header truncated")]
    Truncated,
    #[error("security info out of bounds")]
    SecurityInfoOob,
    #[error("PE data out of bounds")]
    PeDataOob,
    #[error("compression method {0} not supported")]
    UnsupportedCompression(u8),
    #[error("import library table corrupt")]
    ImportLibsCorrupt,
    #[error("decryption not supported (requires console key)")]
    EncryptionRequired,
}

// ---------------------------------------------------------------------------
// XEX2 Header
// ---------------------------------------------------------------------------

/// The fixed-size XEX2 file header (24 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xex2Header {
    /// Magic: "XEX2".
    pub magic: u32,
    /// Module flags.
    pub module_flags: u32,
    /// Byte offset of the PE data (compressed or raw) within the XEX file.
    pub pe_data_offset: u32,
    /// Reserved field.
    pub reserved: u32,
    /// Byte offset of the `XEX2SecurityInfo` structure.
    pub security_info_offset: u32,
    /// Number of optional header entries.
    pub optional_header_count: u32,
}

impl Xex2Header {
    /// # Errors
    /// Returns `Err` if the data is shorter than 24 bytes or the magic is not `XEX2_MAGIC`.
    pub fn parse(data: &[u8]) -> Result<Self, XexLoaderError> {
        if data.len() < 24 { return Err(XexLoaderError::Truncated); }
        let magic = read_u32be(data, 0);
        if magic != XEX2_MAGIC {
            return Err(XexLoaderError::BadMagic(magic));
        }
        Ok(Self {
            magic,
            module_flags:          read_u32be(data, 4),
            pe_data_offset:        read_u32be(data, 8),
            reserved:              read_u32be(data, 12),
            security_info_offset:  read_u32be(data, 16),
            optional_header_count: read_u32be(data, 20),
        })
    }

    #[must_use]
    pub const fn is_dll(&self) -> bool { self.module_flags & module_flags::DLL_MODULE != 0 }
    #[must_use]
    pub const fn is_title(&self) -> bool { self.module_flags & module_flags::TITLE_MODULE != 0 }
    #[must_use]
    pub const fn is_patch(&self) -> bool { self.module_flags & module_flags::MODULE_PATCH != 0 }
}

// ---------------------------------------------------------------------------
// Optional header entry
// ---------------------------------------------------------------------------

/// A single optional header entry (id + offset/value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalHeader {
    /// Header type ID.
    pub id: u32,
    /// Raw value field (may be an inline value or a file offset).
    pub value: u32,
}

impl OptionalHeader {
    /// Returns `true` if `value` is a file offset (id low byte indicates size > 1 DWORD).
    #[must_use]
    pub const fn is_offset(&self) -> bool { (self.id & 0xFF) > 1 }
    /// Returns `true` if `value` is inlined.
    #[must_use]
    pub const fn is_inline(&self) -> bool { !self.is_offset() }
}

// ---------------------------------------------------------------------------
// Execution info
// ---------------------------------------------------------------------------

/// XEX2 execution info block (from optional header or security info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xex2ExecutionInfo {
    pub media_id: u32,
    pub version: u32,
    pub base_version: u32,
    pub title_id: u32,
    pub platform: u8,
    pub executable_type: u8,
    pub disc_number: u8,
    pub disc_count: u8,
    pub savegame_id: u32,
}

impl Xex2ExecutionInfo {
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 24 > data.len() { return None; }
        let d = &data[off..];
        Some(Self {
            media_id:        read_u32be(d, 0),
            version:         read_u32be(d, 4),
            base_version:    read_u32be(d, 8),
            title_id:        read_u32be(d, 12),
            platform:        d[16],
            executable_type: d[17],
            disc_number:     d[18],
            disc_count:      d[19],
            savegame_id:     read_u32be(d, 20),
        })
    }

    /// Title ID formatted as a hex string (e.g. `5841006F`).
    #[must_use]
    pub fn title_id_hex(&self) -> String { format!("{:08X}", self.title_id) }

    /// Human-readable version string (major.minor.build.qfe).
    #[must_use]
    pub fn version_string(&self) -> String {
        let major = (self.version >> 28) & 0xF;
        let minor = (self.version >> 24) & 0xF;
        let build = (self.version >> 8) & 0xFFFF;
        let qfe   = self.version & 0xFF;
        format!("{major}.{minor}.{build}.{qfe}")
    }
}

// ---------------------------------------------------------------------------
// Import library
// ---------------------------------------------------------------------------

/// An imported library record from the XEX import table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexImportLibrary {
    /// Library name (e.g. `"xam.xex"`).
    pub name: String,
    /// Library version.
    pub version: u32,
    /// Minimum required version.
    pub version_min: u32,
    /// Number of imported symbols.
    pub symbol_count: u32,
    /// Import record list (thunk addresses + ordinals).
    pub imports: Vec<XexImport>,
}

/// A single XEX import record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexImport {
    /// Import type (0 = data, 1 = function).
    pub import_type: u8,
    /// Ordinal number.
    pub ordinal: u16,
    /// Thunk address in the image.
    pub thunk_address: u32,
}

// ---------------------------------------------------------------------------
// Compression info
// ---------------------------------------------------------------------------

/// Compression / encryption info from the XEX optional header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xex2FileFormatInfo {
    /// Encryption type (0 = none, 1 = AES-CBC with console-specific key).
    pub encryption_type: u16,
    /// Compression type (0 = none, 1 = raw/identity, 2 = LZX, 3 = delta).
    pub compression_type: u16,
}

impl Xex2FileFormatInfo {
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 8 > data.len() { return None; }
        Some(Self {
            encryption_type:  read_u16be(data, off + 4),
            compression_type: read_u16be(data, off + 6),
        })
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool { self.encryption_type != 0 }
    #[must_use]
    pub const fn is_compressed(&self) -> bool { self.compression_type > 1 }

    #[must_use]
    pub const fn compression_name(&self) -> &'static str {
        match self.compression_type {
            0 => "None",
            1 => "Identity (raw)",
            2 => "LZX",
            3 => "Delta",
            _ => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// TLS info
// ---------------------------------------------------------------------------

/// TLS information from the XEX optional header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xex2TlsInfo {
    pub slot_count: u32,
    pub raw_data_address: u32,
    pub data_size: u32,
    pub raw_data_size: u32,
}

impl Xex2TlsInfo {
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 16 > data.len() { return None; }
        Some(Self {
            slot_count:       read_u32be(data, off),
            raw_data_address: read_u32be(data, off + 4),
            data_size:        read_u32be(data, off + 8),
            raw_data_size:    read_u32be(data, off + 12),
        })
    }
}

// ---------------------------------------------------------------------------
// Parsed XEX
// ---------------------------------------------------------------------------

/// A fully parsed XEX2 file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedXex {
    pub header: Xex2Header,
    pub optional_headers: Vec<OptionalHeader>,
    pub execution_info: Option<Xex2ExecutionInfo>,
    pub file_format_info: Option<Xex2FileFormatInfo>,
    pub tls_info: Option<Xex2TlsInfo>,
    pub import_libraries: Vec<XexImportLibrary>,
    /// PE data offset within the file.
    pub pe_data_offset: usize,
    /// True if the PE data appears to be encrypted.
    pub is_encrypted: bool,
    /// True if the PE data is compressed.
    pub is_compressed: bool,
    /// Raw (possibly compressed/encrypted) PE bytes.
    pub raw_pe: Vec<u8>,
    /// Original PE name (if present in optional headers).
    pub original_pe_name: Option<String>,
    /// Default stack size.
    pub default_stack_size: Option<u32>,
    /// Default heap size.
    pub default_heap_size: Option<u32>,
}

impl ParsedXex {
    #[must_use]
    pub fn title_id(&self) -> Option<String> {
        self.execution_info.as_ref().map(Xex2ExecutionInfo::title_id_hex)
    }
    #[must_use]
    pub fn version(&self) -> Option<String> {
        self.execution_info.as_ref().map(Xex2ExecutionInfo::version_string)
    }
}

// ---------------------------------------------------------------------------
// XexLoader
// ---------------------------------------------------------------------------

/// Parses a raw XEX2 file.
pub struct XexLoader;

impl XexLoader {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// # Errors
    /// Returns `Err` if the data is not a valid XEX2 file or if any required section is out of bounds.
    pub fn parse(&self, data: &[u8]) -> Result<ParsedXex, XexLoaderError> {
        let header = Xex2Header::parse(data)?;

        // Optional headers start immediately after the fixed header (at offset 24).
        let mut opt_headers = Vec::new();
        let count = header.optional_header_count as usize;
        let opt_base = 24usize;
        for i in 0..count {
            let off = opt_base + i * 8;
            if off + 8 > data.len() { break; }
            let id    = read_u32be(data, off);
            let value = read_u32be(data, off + 4);
            opt_headers.push(OptionalHeader { id, value });
        }

        // Process optional headers for known types.
        let mut execution_info   = None;
        let mut file_format_info = None;
        let mut tls_info         = None;
        let mut import_libraries = Vec::new();
        let mut original_pe_name = None;
        let mut default_stack_size = None;
        let mut default_heap_size  = None;

        for oh in &opt_headers {
            match oh.id {
                x if x == opt_header::EXECUTION_ID => {
                    let off = oh.value as usize;
                    execution_info = Xex2ExecutionInfo::parse(data, off);
                }
                x if x == opt_header::FILE_FORMAT_INFO => {
                    let off = oh.value as usize;
                    file_format_info = Xex2FileFormatInfo::parse(data, off);
                }
                x if x == opt_header::TLS_INFO => {
                    let off = oh.value as usize;
                    tls_info = Xex2TlsInfo::parse(data, off);
                }
                x if x == opt_header::IMPORT_LIBS => {
                    import_libraries = parse_import_libs(data, oh.value as usize)
                        .unwrap_or_default();
                }
                x if x == opt_header::ORIGINAL_PE_NAME => {
                    let off = oh.value as usize;
                    if off + 4 <= data.len() {
                        let sz = read_u32be(data, off) as usize;
                        if off + 4 + sz <= data.len() {
                            original_pe_name = String::from_utf8(
                                data[off+4..off+4+sz].to_vec()
                            ).ok();
                        }
                    }
                }
                x if x == opt_header::DEFAULT_STACK_SIZE => {
                    default_stack_size = Some(oh.value);
                }
                x if x == opt_header::DEFAULT_HEAP_SIZE => {
                    default_heap_size = Some(oh.value);
                }
                _ => {}
            }
        }

        let pe_off = header.pe_data_offset as usize;
        if pe_off > data.len() { return Err(XexLoaderError::PeDataOob); }
        let raw_pe = data[pe_off..].to_vec();

        let is_encrypted  = file_format_info.as_ref().is_some_and(Xex2FileFormatInfo::is_encrypted);
        let is_compressed = file_format_info.as_ref().is_some_and(Xex2FileFormatInfo::is_compressed);

        Ok(ParsedXex {
            header,
            optional_headers: opt_headers,
            execution_info,
            file_format_info,
            tls_info,
            import_libraries,
            pe_data_offset: pe_off,
            is_encrypted,
            is_compressed,
            raw_pe,
            original_pe_name,
            default_stack_size,
            default_heap_size,
        })
    }

    /// Attempt to extract the embedded PE if unencrypted and uncompressed.
    ///
    /// # Errors
    /// Returns `Err` if the PE data is encrypted or compressed.
    pub fn extract_pe<'a>(&self, xex: &'a ParsedXex) -> Result<&'a [u8], XexLoaderError> {
        if xex.is_encrypted { return Err(XexLoaderError::EncryptionRequired); }
        if xex.is_compressed {
            return Err(XexLoaderError::UnsupportedCompression(
                xex.file_format_info.as_ref().map_or(255, |f| u8::try_from(f.compression_type).unwrap_or(255)),
            ));
        }
        Ok(&xex.raw_pe)
    }
}

impl Default for XexLoader {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Import library parsing
// ---------------------------------------------------------------------------

fn parse_import_libs(data: &[u8], off: usize) -> Option<Vec<XexImportLibrary>> {
    // Header: total_size (4) + library_count (4).
    if off + 8 > data.len() { return None; }
    let _total_sz   = read_u32be(data, off) as usize;
    let lib_count   = read_u32be(data, off + 4) as usize;
    let mut pos     = off + 8;
    let mut libs    = Vec::new();

    for _ in 0..lib_count {
        // Each import library header: size(4) + next_import_offset(4) + version(8) + version_min(8) + …
        if pos + 44 > data.len() { break; }
        let lib_size    = read_u32be(data, pos) as usize;
        let name_len    = data[pos + 36] as usize;
        let symbol_count = read_u32be(data, pos + 40) as usize;
        let version     = read_u32be(data, pos + 8);
        let version_min = read_u32be(data, pos + 12);
        let name_off    = pos + 44;
        let name = if name_off + name_len <= data.len() {
            String::from_utf8_lossy(&data[name_off..name_off+name_len]).into_owned()
        } else { String::new() };

        // Import records follow after name (aligned to 4 bytes).
        let records_off = align4(name_off + name_len);
        let mut imports  = Vec::new();
        for j in 0..symbol_count {
            let r = records_off + j * 4;
            if r + 4 > data.len() { break; }
            let raw = read_u32be(data, r);
            imports.push(XexImport {
                import_type:    ((raw >> 24) & 0xFF) as u8,
                ordinal:        ((raw >> 8) & 0xFFFF) as u16,
                thunk_address:  raw & 0x00FF_FFFF,
            });
        }

        libs.push(XexImportLibrary { name, version, version_min, symbol_count: u32::try_from(symbol_count).unwrap_or(u32::MAX), imports });
        pos += lib_size;
    }
    Some(libs)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_u32be(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off+4].try_into().unwrap())
}
fn read_u16be(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(data[off..off+2].try_into().unwrap())
}
const fn align4(v: usize) -> usize { (v + 3) & !3 }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xex2_header_parse_bad_magic() {
        let data = [0x00u8; 24];
        assert!(Xex2Header::parse(&data).is_err());
    }

    #[test]
    fn xex2_header_parse_valid() {
        let mut data = [0u8; 24];
        data[0..4].copy_from_slice(&XEX2_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&module_flags::TITLE_MODULE.to_be_bytes());
        data[8..12].copy_from_slice(&0x800u32.to_be_bytes()); // pe_data_offset
        data[16..20].copy_from_slice(&0x300u32.to_be_bytes()); // security_info_offset
        let h = Xex2Header::parse(&data).unwrap();
        assert_eq!(h.magic, XEX2_MAGIC);
        assert!(h.is_title());
        assert!(!h.is_dll());
    }

    #[test]
    fn execution_info_title_id_hex() {
        let mut data = [0u8; 64];
        data[12..16].copy_from_slice(&0x5841_006F_u32.to_be_bytes());
        let ei = Xex2ExecutionInfo::parse(&data, 0).unwrap();
        assert_eq!(ei.title_id_hex(), "5841006F");
    }

    #[test]
    fn execution_info_version() {
        // version = 2.0.17559.0 → 0x20449700
        let mut data = [0u8; 64];
        let ver: u32 = (2 << 28) | (17559 << 8);
        data[4..8].copy_from_slice(&ver.to_be_bytes());
        let ei = Xex2ExecutionInfo::parse(&data, 0).unwrap();
        assert!(ei.version_string().starts_with("2.0."));
    }

    #[test]
    fn file_format_not_encrypted_uncompressed() {
        let mut data = [0u8; 16];
        data[4..6].copy_from_slice(&0u16.to_be_bytes()); // encryption_type = 0
        data[6..8].copy_from_slice(&0u16.to_be_bytes()); // compression_type = 0
        let ff = Xex2FileFormatInfo::parse(&data, 0).unwrap();
        assert!(!ff.is_encrypted());
        assert!(!ff.is_compressed());
        assert_eq!(ff.compression_name(), "None");
    }

    #[test]
    fn import_library_struct_fields() {
        let lib = XexImportLibrary {
            name: "xboxkrnl.exe".into(),
            version: 1,
            version_min: 0,
            symbol_count: 3,
            imports: vec![
                XexImport { import_type: 0, ordinal: 1, thunk_address: 0x1000 },
                XexImport { import_type: 0, ordinal: 2, thunk_address: 0x1004 },
            ],
        };
        assert_eq!(lib.name, "xboxkrnl.exe");
        assert_eq!(lib.imports.len(), 2);
        assert_eq!(lib.imports[0].ordinal, 1);
    }

    #[test]
    fn xex_loader_default() {
        let loader = XexLoader::new();
        let result = loader.parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn module_flags_title() {
        let flags = module_flags::TITLE_MODULE;
        assert_ne!(flags, 0);
    }

    #[test]
    fn align4_helper() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }
}
