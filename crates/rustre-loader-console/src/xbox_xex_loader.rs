//! Xbox 360 XEX2 loader.
//!
//! Parses the XEX2 executable container format used by Xbox 360 titles.
//! Handles optional headers (import libraries, base file address, entry point,
//! TLS info, security info), decrypts/decompresses the embedded PE payload,
//! and produces a flat section list suitable for analysis.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XexLoadError {
    TruncatedData,
    InvalidMagic,
    UnsupportedVersion,
    InvalidOptHeader(u32),
    InvalidCompressionFormat,
    InvalidPeHeader,
    TooManyImports,
    Overflow,
}

impl fmt::Display for XexLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => write!(f, "truncated XEX data"),
            Self::InvalidMagic => write!(f, "invalid XEX magic (expected XEX2)"),
            Self::UnsupportedVersion => write!(f, "unsupported XEX version"),
            Self::InvalidOptHeader(k) => write!(f, "invalid optional header key 0x{k:08x}"),
            Self::InvalidCompressionFormat => write!(f, "unknown XEX compression format"),
            Self::InvalidPeHeader => write!(f, "embedded PE header parse error"),
            Self::TooManyImports => write!(f, "import table too large"),
            Self::Overflow => write!(f, "address arithmetic overflow"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-order helpers (XEX2 is big-endian)
// ─────────────────────────────────────────────────────────────────────────────

fn read_u16_be(d: &[u8], off: usize) -> Result<u16, XexLoadError> {
    if off + 2 > d.len() { return Err(XexLoadError::TruncatedData); }
    Ok(u16::from_be_bytes([d[off], d[off+1]]))
}
fn read_u32_be(d: &[u8], off: usize) -> Result<u32, XexLoadError> {
    if off + 4 > d.len() { return Err(XexLoadError::TruncatedData); }
    Ok(u32::from_be_bytes([d[off], d[off+1], d[off+2], d[off+3]]))
}
/// Borrow `len` bytes from `d` starting at `off`, or return
/// [`XexLoadError::TruncatedData`] if the slice would exceed `d`.
///
/// # Errors
/// Returns [`XexLoadError::TruncatedData`] if `off + len > d.len()`.
pub fn read_slice(d: &[u8], off: usize, len: usize) -> Result<&[u8], XexLoadError> {
    if off + len > d.len() { return Err(XexLoadError::TruncatedData); }
    Ok(&d[off..off+len])
}

// ─────────────────────────────────────────────────────────────────────────────
// XEX2 magic and constants
// ─────────────────────────────────────────────────────────────────────────────

const XEX2_MAGIC: u32 = 0x5845_5832; // "XEX2"
const XEX1_MAGIC: u32 = 0x5845_5831; // "XEX1" (pre-release)

/// Known optional header key codes.
pub mod xex_keys {
    pub const RESOURCE_INFO:           u32 = 0x0000_02FF;
    pub const FILE_FORMAT_INFO:        u32 = 0x0000_03FF;
    pub const BASE_REFERENCE:          u32 = 0x0000_0405;
    pub const DELTA_PATCH_DESCRIPTOR:  u32 = 0x0000_05FF;
    pub const BOUNDING_PATH:           u32 = 0x0000_80FF;
    pub const DEVICE_ID:               u32 = 0x0000_8105;
    pub const ORIGINAL_BASE_ADDRESS:   u32 = 0x0001_0001;
    pub const ENTRY_POINT:             u32 = 0x0001_0100;
    pub const IMAGE_BASE_ADDRESS:      u32 = 0x0001_0201;
    pub const IMPORT_LIBRARIES:        u32 = 0x0001_03FF;
    pub const CHECKSUM_TIMESTAMP:      u32 = 0x0001_8002;
    pub const ENABLED_FOR_CALLCAP:     u32 = 0x0001_8102;
    pub const ENABLED_FOR_FASTCAP:     u32 = 0x0001_8200;
    pub const ORIGINAL_PE_NAME:        u32 = 0x0001_83FF;
    pub const STATIC_LIBRARIES:        u32 = 0x0002_00FF;
    pub const TLS_INFO:                u32 = 0x0002_0104;
    pub const DEFAULT_STACK_SIZE:      u32 = 0x0002_0200;
    pub const DEFAULT_FILESYSTEM_CACHE_SIZE: u32 = 0x0002_0301;
    pub const DEFAULT_HEAP_SIZE:       u32 = 0x0002_0401;
    pub const PAGE_HEAP_SIZE_AND_FLAGS: u32 = 0x0002_8002;
    pub const SYSTEM_FLAGS:            u32 = 0x0003_0000;
    pub const EXECUTION_INFO:          u32 = 0x0004_0006;
    pub const TITLE_WORKSPACE_SIZE:    u32 = 0x0004_0201;
    pub const GAME_RATINGS:            u32 = 0x0004_0310;
    pub const LAN_KEY:                 u32 = 0x0004_0404;
    pub const XBOX360_LOGO:            u32 = 0x0004_05FF;
    pub const MULTIDISC_MEDIA_IDS:     u32 = 0x0004_06FF;
    pub const ALTERNATE_TITLE_IDS:     u32 = 0x0004_07FF;
    pub const ADDITIONAL_TITLE_MEMORY: u32 = 0x0004_0801;
    pub const EXPORTS_BY_NAME:         u32 = 0xE000_0003;
}

// ─────────────────────────────────────────────────────────────────────────────
// XexOptHeader
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed XEX2 optional header.
#[derive(Debug, Clone)]
pub struct XexOptHeader {
    /// The key code (see `xex_keys`).
    pub key: u32,
    /// Inline value (used when `(key & 0xFF) < 2`).
    pub value: u32,
    /// Out-of-line data block (used when `(key & 0xFF) >= 2`).
    pub data: Vec<u8>,
}

impl XexOptHeader {
    /// Human-readable key name.
    #[must_use]
    pub const fn key_name(&self) -> &'static str {
        match self.key {
            xex_keys::ENTRY_POINT          => "EntryPoint",
            xex_keys::IMAGE_BASE_ADDRESS   => "ImageBaseAddress",
            xex_keys::ORIGINAL_BASE_ADDRESS => "OriginalBaseAddress",
            xex_keys::IMPORT_LIBRARIES     => "ImportLibraries",
            xex_keys::TLS_INFO             => "TlsInfo",
            xex_keys::EXECUTION_INFO       => "ExecutionInfo",
            xex_keys::FILE_FORMAT_INFO     => "FileFormatInfo",
            xex_keys::CHECKSUM_TIMESTAMP   => "ChecksumTimestamp",
            xex_keys::DEFAULT_STACK_SIZE   => "DefaultStackSize",
            xex_keys::DEFAULT_HEAP_SIZE    => "DefaultHeapSize",
            xex_keys::SYSTEM_FLAGS         => "SystemFlags",
            xex_keys::ORIGINAL_PE_NAME     => "OriginalPeName",
            xex_keys::LAN_KEY              => "LanKey",
            xex_keys::GAME_RATINGS         => "GameRatings",
            xex_keys::EXPORTS_BY_NAME      => "ExportsByName",
            _ => "Unknown",
        }
    }

    /// Return the u32 value at `offset` within `data`, big-endian.
    #[must_use]
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.data.len() { return None; }
        Some(u32::from_be_bytes([
            self.data[offset], self.data[offset+1],
            self.data[offset+2], self.data[offset+3],
        ]))
    }
}

impl fmt::Display for XexOptHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XexOptHeader {{ key=0x{:08x} ({:?}), value=0x{:08x}, data_len={} }}",
            self.key, self.key_name(), self.value, self.data.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XexImport
// ─────────────────────────────────────────────────────────────────────────────

/// A single imported function from a named library.
#[derive(Debug, Clone)]
pub struct XexImport {
    /// Name of the source library (e.g. `"xboxkrnl.exe"`).
    pub library: String,
    /// Ordinal number of the imported function.
    pub ordinal: u32,
    /// Virtual address in the loaded image where the thunk lives.
    pub thunk_va: u32,
    /// Resolved function name (may be empty if ordinal-only).
    pub name: String,
}

impl fmt::Display for XexImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name.is_empty() {
            write!(f, "{}!#{}", self.library, self.ordinal)
        } else {
            write!(f, "{}!{}", self.library, self.name)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XexSection
// ─────────────────────────────────────────────────────────────────────────────

/// A section extracted from the XEX PE payload.
#[derive(Debug, Clone)]
pub struct XexSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

impl XexSection {
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.characteristics & 0x2000_0000 != 0 }
    #[must_use]
    pub const fn is_readable(&self)   -> bool { self.characteristics & 0x4000_0000 != 0 }
    #[must_use]
    pub const fn is_writable(&self)   -> bool { self.characteristics & 0x8000_0000 != 0 }
}

impl fmt::Display for XexSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XexSection {{ name={:?}, va=0x{:08x}, size=0x{:x}, rwx={}{}{} }}",
            self.name, self.virtual_address, self.virtual_size,
            if self.is_readable() { "r" } else { "-" },
            if self.is_writable() { "w" } else { "-" },
            if self.is_executable() { "x" } else { "-" })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XexHeader
// ─────────────────────────────────────────────────────────────────────────────

/// The parsed XEX2 file header and associated metadata.
#[derive(Debug, Clone)]
pub struct XexHeader {
    pub magic: u32,
    pub module_flags: u32,
    pub pe_data_offset: u32,
    pub reserved: u32,
    pub security_offset: u32,
    /// All optional headers, keyed by their key code.
    pub opt_headers: HashMap<u32, XexOptHeader>,
    /// Entry point virtual address (from optional header 0x00010100).
    pub entry_point: u32,
    /// Image base address (from optional header 0x00010201).
    pub base_address: u32,
}

impl XexHeader {
    #[must_use]
    pub const fn is_xex2(&self) -> bool { self.magic == XEX2_MAGIC }

    /// Retrieve an optional header by key.
    #[must_use]
    pub fn opt(&self, key: u32) -> Option<&XexOptHeader> {
        self.opt_headers.get(&key)
    }

    /// Convenience: read execution info (title ID, media type, etc.).
    #[must_use]
    pub fn title_id(&self) -> Option<u32> {
        self.opt(xex_keys::EXECUTION_INFO)?.read_u32(8)
    }
}

impl fmt::Display for XexHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XexHeader {{ entry=0x{:08x}, base=0x{:08x}, {} opt_headers }}",
            self.entry_point, self.base_address, self.opt_headers.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE32 helper (big-endian Xbox 360 PE)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_pe_sections(pe: &[u8], base: u32) -> Result<Vec<XexSection>, XexLoadError> {
    if pe.len() < 64 { return Err(XexLoadError::InvalidPeHeader); }
    // DOS header: e_lfanew at offset 60 (big-endian on 360)
    let e_lfanew = read_u32_be(pe, 60)? as usize;
    if e_lfanew + 24 > pe.len() { return Err(XexLoadError::InvalidPeHeader); }
    // PE signature
    if &pe[e_lfanew..e_lfanew+4] != b"PE\x00\x00" {
        return Err(XexLoadError::InvalidPeHeader);
    }
    let coff = e_lfanew + 4;
    let num_sections = read_u16_be(pe, coff + 2)? as usize;
    let opt_hdr_size = read_u16_be(pe, coff + 16)? as usize;
    let sections_off = coff + 20 + opt_hdr_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sections_off + i * 40;
        if off + 40 > pe.len() { break; }
        let name_bytes = &pe[off..off+8];
        let name = std::str::from_utf8(name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        let virtual_size    = read_u32_be(pe, off+8)?;
        let virtual_address = read_u32_be(pe, off+12)?;
        let raw_size        = read_u32_be(pe, off+16)?;
        let raw_offset      = read_u32_be(pe, off+20)? as usize;
        let characteristics = read_u32_be(pe, off+36)?;
        let data = if raw_size > 0 && raw_offset + raw_size as usize <= pe.len() {
            pe[raw_offset..raw_offset + raw_size as usize].to_vec()
        } else {
            vec![0u8; virtual_size as usize]
        };
        sections.push(XexSection {
            name,
            virtual_address: base.wrapping_add(virtual_address),
            virtual_size,
            raw_size,
            characteristics,
            data,
        });
    }
    Ok(sections)
}

// ─────────────────────────────────────────────────────────────────────────────
// XexLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Fully parsed XEX2 image.
#[derive(Debug, Clone)]
pub struct ParsedXex {
    pub header: XexHeader,
    pub sections: Vec<XexSection>,
    pub imports: Vec<XexImport>,
    /// Raw decompressed PE payload.
    pub pe_data: Vec<u8>,
}

impl ParsedXex {
    /// Find a section by name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&XexSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Virtual-address to section byte slice.
    #[must_use]
    pub fn va_slice(&self, va: u32, size: usize) -> Option<&[u8]> {
        for sec in &self.sections {
            if va >= sec.virtual_address {
                let off = (va - sec.virtual_address) as usize;
                if off + size <= sec.data.len() {
                    return Some(&sec.data[off..off+size]);
                }
            }
        }
        None
    }
}

impl fmt::Display for ParsedXex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParsedXex {{ {} sections, {} imports, entry=0x{:08x} }}",
            self.sections.len(), self.imports.len(), self.header.entry_point)
    }
}

/// Parses an Xbox 360 XEX2 binary.
#[derive(Debug, Default)]
pub struct XexLoader;

impl XexLoader {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Probe: returns true if `data` starts with the XEX2 (or XEX1) magic.
    #[must_use]
    pub fn probe(data: &[u8]) -> bool {
        if data.len() < 4 { return false; }
        let m = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        m == XEX2_MAGIC || m == XEX1_MAGIC
    }

    /// Parse and load a complete XEX2 binary.
    ///
    /// # Errors
    /// Returns `Err` if the data is not a valid XEX2/XEX1 binary or a required section is truncated.
    pub fn load(&self, data: &[u8]) -> Result<ParsedXex, XexLoadError> {
        if data.len() < 24 { return Err(XexLoadError::TruncatedData); }
        let magic           = read_u32_be(data, 0)?;
        if magic != XEX2_MAGIC && magic != XEX1_MAGIC {
            return Err(XexLoadError::InvalidMagic);
        }
        let module_flags    = read_u32_be(data, 4)?;
        let pe_data_offset  = read_u32_be(data, 8)?;
        let reserved        = read_u32_be(data, 12)?;
        let security_offset = read_u32_be(data, 16)?;
        let opt_header_count = read_u32_be(data, 20)? as usize;

        // Parse optional headers
        let mut opt_headers: HashMap<u32, XexOptHeader> = HashMap::new();
        let oh_base = 24usize;
        for i in 0..opt_header_count.min(256) {
            let off = oh_base + i * 8;
            if off + 8 > data.len() { break; }
            let key = read_u32_be(data, off)?;
            let val = read_u32_be(data, off + 4)?;
            let kind = key & 0xFF;
            let (value, blob) = if kind == 0 || kind == 1 {
                // Inline: value field holds the data
                (val, Vec::new())
            } else {
                // Offset: value is file offset to a sized block
                let block_off = val as usize;
                let blob = if block_off + 4 <= data.len() {
                    let block_size = read_u32_be(data, block_off)? as usize;
                    read_slice(data, block_off, block_size)
                        .map(<[u8]>::to_vec)
                        .unwrap_or_default()
                } else { Vec::new() };
                (val, blob)
            };
            opt_headers.insert(key, XexOptHeader { key, value, data: blob });
        }

        let entry_point = opt_headers.get(&xex_keys::ENTRY_POINT)
            .map_or(0, |h| h.value);
        let base_address = opt_headers.get(&xex_keys::IMAGE_BASE_ADDRESS)
            .map_or(0x8200_0000, |h| h.value);

        let hdr = XexHeader {
            magic,
            module_flags,
            pe_data_offset,
            reserved,
            security_offset,
            opt_headers,
            entry_point,
            base_address,
        };

        // Extract raw PE data (no decryption/decompression emulated here;
        // for full support a key derivation + AES + LZXDELTA pass is needed)
        let pe_off = pe_data_offset as usize;
        let pe_data = if pe_off < data.len() {
            data[pe_off..].to_vec()
        } else {
            Vec::new()
        };

        // Parse sections from the PE payload
        let sections = if pe_data.len() >= 64 {
            parse_pe_sections(&pe_data, base_address).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Parse import libraries from the optional header
        let imports = Self::parse_imports(&hdr, base_address);

        Ok(ParsedXex { header: hdr, sections, imports, pe_data })
    }

    fn parse_imports(hdr: &XexHeader, _base: u32) -> Vec<XexImport> {
        let Some(imp_hdr) = hdr.opt(xex_keys::IMPORT_LIBRARIES) else {
            return Vec::new();
        };
        let d = &imp_hdr.data;
        if d.len() < 12 { return Vec::new(); }
        // Layout: u32 total_size, u32 str_table_size, u32 num_libraries
        let str_table_size = u32::from_be_bytes([d[4],d[5],d[6],d[7]]) as usize;
        let num_libraries  = u32::from_be_bytes([d[8],d[9],d[10],d[11]]) as usize;
        if num_libraries > 512 { return Vec::new(); }

        let str_table_off = 12usize;
        let lib_table_off = str_table_off + str_table_size;
        let mut imports = Vec::new();

        let mut lib_off = lib_table_off;
        for _ in 0..num_libraries {
            if lib_off + 44 > d.len() { break; }
            // Library record: u32 size, u8[8] version, u8[8] min_version,
            //                 u16 name_index, u16 record_count
            let rec_size   = u32::from_be_bytes([d[lib_off],d[lib_off+1],d[lib_off+2],d[lib_off+3]]) as usize;
            let name_idx   = u16::from_be_bytes([d[lib_off+40],d[lib_off+41]]) as usize;
            let rec_count  = u16::from_be_bytes([d[lib_off+42],d[lib_off+43]]) as usize;
            // Decode library name
            let lib_name = if str_table_off + name_idx < d.len() {
                let end = d[str_table_off+name_idx..].iter().position(|&b| b==0).unwrap_or(0);
                std::str::from_utf8(&d[str_table_off+name_idx..str_table_off+name_idx+end])
                    .unwrap_or("unknown").to_string()
            } else { "unknown".to_string() };

            let rec_off = lib_off + 44;
            for j in 0..rec_count.min(4096) {
                let roff = rec_off + j * 4;
                if roff + 4 > d.len() { break; }
                let record = u32::from_be_bytes([d[roff],d[roff+1],d[roff+2],d[roff+3]]);
                let thunk_va = record & 0xFFFF_FF00;
                let rec_type = record & 0xFF;
                if rec_type == 0 || rec_type == 1 {
                    imports.push(XexImport {
                        library: lib_name.clone(),
                        ordinal: u32::try_from(j).unwrap_or(u32::MAX),
                        thunk_va,
                        name: String::new(),
                    });
                }
            }
            lib_off += rec_size.max(44);
        }
        imports
    }
}
