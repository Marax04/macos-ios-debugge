//! Xbox 360 XEX2 loader.
//!
//! Parses the XEX2 (Xbox Executable 2) format used by all Xbox 360 titles.
//! Magic: `XEX2` at offset 0 (bytes `0x58 0x45 0x58 0x32`).
//!
//! Structure overview:
//! ```text
//! XexHeader
//!   OptionalHeaderList  (array of (key, offset) pairs)
//!   SecurityInfo        (certificate + page descriptors)
//!   ImportLibraries     (table of imported DLL names + thunk addrs)
//!   Sections            (array of XexSection)
//! BaseFileFormat        (compression descriptor)
//! Compressed PE image
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ─── constants ────────────────────────────────────────────────────────────────

/// XEX2 magic.
pub const XEX2_MAGIC: u32 = 0x5845_5832; // 'XEX2'

/// Minimum size we require before attempting a parse.
pub const XEX2_MIN_SIZE: usize = 0x18;

/// Standard XEX2 header size (fixed portion).
pub const XEX2_HEADER_SIZE: usize = 0x18;

/// XEX optional header keys.
pub mod opt_key {
    pub const RESOURCES: u32 = 0x0000_02FF;
    pub const BASE_FILE_FORMAT: u32 = 0x0000_03FF;
    pub const DELTA_PATCH_DESC: u32 = 0x0000_05FF;
    pub const BOUND_PATH: u32 = 0x0000_0080;
    pub const ENTRY_POINT: u32 = 0x0001_0100;
    pub const IMAGE_BASE_ADDRESS: u32 = 0x0001_0201;
    pub const IMPORT_LIBRARIES: u32 = 0x0001_03FF;
    pub const CHECKSUM_TIMESTAMP: u32 = 0x0001_8002;
    pub const ENABLED_FOR_CALLCAP: u32 = 0x0001_8102;
    pub const ENABLED_FOR_FASTCAP: u32 = 0x0001_8200;
    pub const ORIGINAL_PE_NAME: u32 = 0x0001_83FF;
    pub const STATIC_LIBRARIES: u32 = 0x0002_00FF;
    pub const TLS_DATA: u32 = 0x0002_0104;
    pub const DEFAULT_STACK_SIZE: u32 = 0x0002_0200;
    pub const DEFAULT_FS_CACHE_SIZE: u32 = 0x0002_0301;
    pub const DEFAULT_HEAP_SIZE: u32 = 0x0002_0401;
    pub const PAGE_HEAP_SIZE_FLAGS: u32 = 0x0002_8002;
    pub const SYSTEM_FLAGS: u32 = 0x0003_0000;
    pub const EXECUTION_ID: u32 = 0x0004_0006;
    pub const SERVICE_ID_LIST: u32 = 0x0004_01FF;
    pub const TITLE_WORKSPACE_SIZE: u32 = 0x0004_0201;
    pub const GAME_RATINGS: u32 = 0x0004_0310;
    pub const LAN_KEY: u32 = 0x0004_0404;
    pub const XBOX360_LOGO: u32 = 0x0004_05FF;
    pub const MULTI_DISC_MEDIA_IDS: u32 = 0x0004_06FF;
    pub const ALTERNATE_TITLE_IDS: u32 = 0x0004_07FF;
    pub const ADDITIONAL_TITLE_MEM: u32 = 0x0004_0501;
    pub const EXPORTS_BY_NAME: u32 = 0x00E1_0402;
}

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the XEX2 loader.
#[derive(Debug, Error)]
pub enum XexError {
    /// Magic mismatch.
    #[error("bad XEX2 magic: expected {expected:#010x}, got {got:#010x}")]
    BadMagic { expected: u32, got: u32 },
    /// File too short.
    #[error("file too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    /// Offset in header points outside the file.
    #[error("offset {offset:#x} is outside file (len {file_len:#x})")]
    OffsetOob { offset: usize, file_len: usize },
    /// Unknown compression type.
    #[error("unsupported compression type: {0:#06x}")]
    UnsupportedCompression(u16),
    /// Delta-patch not supported.
    #[error("delta patches are not supported in this loader version")]
    DeltaPatchUnsupported,
    /// Generic parse error.
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── XexModuleFlags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Module flags from the XEX2 header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct XexModuleFlags: u32 {
        /// Module is a title (game executable).
        const TITLE                = 0x0001;
        /// Module exports entry to the kernel/dash.
        const EXPORTS_TO_DASH      = 0x0002;
        /// Module is a system module.
        const SYSTEM_MODULE        = 0x0004;
        /// Module is a user mode module.
        const USER_MODE            = 0x0008;
        /// Module has a title ID.
        const HAS_TITLE_ID         = 0x0010;
        /// Module is a DLC pack.
        const DLC_PACK             = 0x0020;
    }
}

// ─── XexHeader ────────────────────────────────────────────────────────────────

/// Fixed XEX2 header (0x18 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexHeader {
    /// Magic (`XEX2`).
    pub magic: u32,
    /// Module flags.
    pub module_flags: XexModuleFlags,
    /// Offset to the PE/COFF data (compressed or raw) within the XEX file.
    pub pe_data_offset: u32,
    /// Reserved.
    pub reserved: u32,
    /// Offset to the security info block.
    pub security_info_offset: u32,
    /// Number of optional header entries.
    pub optional_header_count: u32,
}

impl XexHeader {
    /// Parse from the first 0x18 bytes of `data`.
    ///
    /// # Errors
    /// Returns [`XexError`] on short input or bad magic.
    pub fn parse(data: &[u8]) -> Result<Self, XexError> {
        if data.len() < XEX2_HEADER_SIZE {
            return Err(XexError::TooShort {
                need: XEX2_HEADER_SIZE,
                have: data.len(),
            });
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != XEX2_MAGIC {
            return Err(XexError::BadMagic {
                expected: XEX2_MAGIC,
                got: magic,
            });
        }
        Ok(Self {
            magic,
            module_flags: XexModuleFlags::from_bits_truncate(u32::from_be_bytes([
                data[4], data[5], data[6], data[7],
            ])),
            pe_data_offset: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reserved: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            security_info_offset: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            optional_header_count: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }
}

impl fmt::Display for XexHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XEX2 flags={:?} pe_offset={:#010x} opt_headers={}",
            self.module_flags, self.pe_data_offset, self.optional_header_count
        )
    }
}

// ─── XexOptionalHeader ────────────────────────────────────────────────────────

/// One entry in the optional header list.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct XexOptionalHeader {
    /// Key identifying this optional header (see `opt_key` constants).
    pub key: u32,
    /// Data or file offset.  When `key & 0xFF == 0x00` the value is inline.
    /// When `key & 0xFF == 0x01` it is a single u32 value.  Otherwise it is
    /// a file offset to a variable-size data block.
    pub value: u32,
}

impl XexOptionalHeader {
    /// Returns `true` when the value is inline (not a file offset).
    #[must_use]
    pub const fn is_inline(&self) -> bool {
        (self.key & 0xFF) < 2
    }

    /// Parse a single 8-byte entry from `data`.
    ///
    /// # Errors
    /// Returns [`XexError::TooShort`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, XexError> {
        if data.len() < 8 {
            return Err(XexError::TooShort {
                need: 8,
                have: data.len(),
            });
        }
        Ok(Self {
            key: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            value: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// Parse the full optional header list from `data` starting at byte 0x18.
///
/// Returns a map from key → `XexOptionalHeader`.
///
/// # Errors
/// Returns [`XexError`] if any entry extends beyond `data`.
pub fn parse_optional_headers(
    data: &[u8],
    count: usize,
) -> Result<HashMap<u32, XexOptionalHeader>, XexError> {
    // count comes from the untrusted optional_header_count field; cap it to avoid
    // excessive HashMap allocation before bounds are verified per-iteration.
    let count = count.min(data.len() / 8);
    let mut map = HashMap::with_capacity(count);
    let base = XEX2_HEADER_SIZE;
    for i in 0..count {
        let off = base + i * 8;
        if off + 8 > data.len() {
            return Err(XexError::TooShort {
                need: off + 8,
                have: data.len(),
            });
        }
        let hdr = XexOptionalHeader::parse(&data[off..off + 8])?;
        map.insert(hdr.key, hdr);
    }
    Ok(map)
}

// ─── XexSecurityInfo ─────────────────────────────────────────────────────────

/// XEX security info block (starts at `security_info_offset`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexSecurityInfo {
    /// Size of this structure.
    pub size: u32,
    /// Image info flags.
    pub image_flags: u32,
    /// Load address.
    pub load_address: u32,
    /// SHA-1 hash of section table.
    pub section_digest: [u8; 20],
    /// Import table count.
    pub import_table_count: u32,
    /// Import digest.
    pub import_digest: [u8; 20],
    /// Media ID.
    pub media_id: [u8; 16],
    /// AES key (encrypted with Xbox 360 master key, stored for reference).
    pub aes_key: [u8; 16],
    /// Export table virtual address.
    pub export_table: u32,
    /// Header SHA-1 digest.
    pub header_digest: [u8; 20],
    /// Game region mask.
    pub game_region: u32,
    /// Allowed media types.
    pub allowed_media_types: u32,
    /// Number of page descriptors.
    pub page_descriptor_count: u32,
}

impl XexSecurityInfo {
    /// Minimum size.
    pub const MIN_SIZE: usize = 0x80;

    /// Parse from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`XexError::OffsetOob`] if `offset + MIN_SIZE > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, XexError> {
        let end = offset + Self::MIN_SIZE;
        if end > data.len() {
            return Err(XexError::OffsetOob {
                offset,
                file_len: data.len(),
            });
        }
        let d = &data[offset..];

        let size = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        let image_flags = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
        let load_address = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);

        let mut section_digest = [0u8; 20];
        section_digest.copy_from_slice(&d[0xC..0x20]);

        let import_table_count = u32::from_be_bytes([d[0x20], d[0x21], d[0x22], d[0x23]]);

        let mut import_digest = [0u8; 20];
        import_digest.copy_from_slice(&d[0x24..0x38]);

        let mut media_id = [0u8; 16];
        media_id.copy_from_slice(&d[0x38..0x48]);

        let mut aes_key = [0u8; 16];
        aes_key.copy_from_slice(&d[0x48..0x58]);

        let export_table = u32::from_be_bytes([d[0x58], d[0x59], d[0x5A], d[0x5B]]);

        let mut header_digest = [0u8; 20];
        if d.len() >= 0x6C + 20 {
            header_digest.copy_from_slice(&d[0x5C..0x70]);
        }

        let game_region = u32::from_be_bytes([d[0x70], d[0x71], d[0x72], d[0x73]]);
        let allowed_media_types = u32::from_be_bytes([d[0x74], d[0x75], d[0x76], d[0x77]]);
        let page_descriptor_count = u32::from_be_bytes([d[0x78], d[0x79], d[0x7A], d[0x7B]]);

        Ok(Self {
            size,
            image_flags,
            load_address,
            section_digest,
            import_table_count,
            import_digest,
            media_id,
            aes_key,
            export_table,
            header_digest,
            game_region,
            allowed_media_types,
            page_descriptor_count,
        })
    }

    /// Return load address as u64.
    #[must_use]
    pub const fn load_addr_u64(&self) -> u64 {
        // u64::from() not stable in const context; cast is lossless (u32 → u64)
        self.load_address as u64
    }
}

// ─── XexImportLibrary ─────────────────────────────────────────────────────────

/// A single imported library referenced by a XEX2 binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexImportLibrary {
    /// Library name (e.g. `"xboxkrnl.exe"`).
    pub name: String,
    /// Version major.minor.build.qfe.
    pub version: (u16, u16, u16, u16),
    /// List of imported thunk addresses.
    pub thunks: Vec<u32>,
}

impl XexImportLibrary {
    /// Minimum bytes for one import library entry.
    pub const MIN_SIZE: usize = 0x28;
}

impl fmt::Display for XexImportLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XexImport \"{}\" v{}.{}.{}.{} ({} thunks)",
            self.name,
            self.version.0,
            self.version.1,
            self.version.2,
            self.version.3,
            self.thunks.len()
        )
    }
}

/// Parse the import libraries block at `offset` from `data`.
///
/// # Errors
/// Returns [`XexError::OffsetOob`] if the block extends beyond `data`.
pub fn parse_import_libraries(
    data: &[u8],
    offset: usize,
) -> Result<Vec<XexImportLibrary>, XexError> {
    if offset + 8 > data.len() {
        return Err(XexError::OffsetOob {
            offset,
            file_len: data.len(),
        });
    }
    let block = &data[offset..];
    let block_size = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) as usize;
    let lib_count = u32::from_be_bytes([block[4], block[5], block[6], block[7]]) as usize;

    // lib_count is from untrusted binary data; cap to avoid excessive allocation.
    let lib_count = lib_count.min(block.len() / XexImportLibrary::MIN_SIZE);
    let mut libs = Vec::with_capacity(lib_count);
    let mut pos = 8usize;

    for _ in 0..lib_count {
        if pos + XexImportLibrary::MIN_SIZE > block_size.min(block.len()) {
            break;
        }
        let entry_size =
            u32::from_be_bytes([block[pos], block[pos + 1], block[pos + 2], block[pos + 3]])
                as usize;
        let name_size = u32::from_be_bytes([
            block[pos + 4],
            block[pos + 5],
            block[pos + 6],
            block[pos + 7],
        ]) as usize;
        let thunk_count = u32::from_be_bytes([
            block[pos + 8],
            block[pos + 9],
            block[pos + 10],
            block[pos + 11],
        ]) as usize;

        let ver_major = u16::from_be_bytes([block[pos + 0x0C], block[pos + 0x0D]]);
        let ver_minor = u16::from_be_bytes([block[pos + 0x0E], block[pos + 0x0F]]);
        let ver_build = u16::from_be_bytes([block[pos + 0x10], block[pos + 0x11]]);
        let ver_qfe = u16::from_be_bytes([block[pos + 0x12], block[pos + 0x13]]);

        let name_off = pos + 0x14;
        let name_end = (name_off + name_size).min(block.len());
        let name = std::str::from_utf8(&block[name_off..name_end])
            .unwrap_or("<invalid>")
            .trim_end_matches('\0')
            .to_string();

        let thunk_start = name_off + name_size;
        // `thunk_count` is a raw big-endian u32 from the import-library record, so an
        // unclamped `with_capacity` reserves up to 16 GiB from a ~50-byte crafted XEX
        // (the per-iteration bounds check below only runs after the allocation). Each
        // thunk is 4 bytes, so the block cannot hold more than block.len() / 4 of them.
        let thunk_capacity = thunk_count.min(block.len().saturating_sub(thunk_start) / 4);
        let mut thunks = Vec::with_capacity(thunk_capacity);
        for t in 0..thunk_count {
            let toff = thunk_start + t * 4;
            if toff + 4 > block.len() {
                break;
            }
            thunks.push(u32::from_be_bytes([
                block[toff],
                block[toff + 1],
                block[toff + 2],
                block[toff + 3],
            ]));
        }

        libs.push(XexImportLibrary {
            name,
            version: (ver_major, ver_minor, ver_build, ver_qfe),
            thunks,
        });
        // entry_size comes from untrusted input; if zero or smaller than the
        // fields already consumed, we would loop forever or revisit the same
        // bytes, so clamp to the minimum amount we actually consumed.
        // Use saturating arithmetic: name_size and thunk_count are also from
        // untrusted input and their product/sum can overflow on its own.
        let thunks_bytes = thunk_count.saturating_mul(4);
        let min_advance = XexImportLibrary::MIN_SIZE
            .saturating_add(name_size)
            .saturating_add(thunks_bytes);
        pos += entry_size.max(min_advance);
    }
    Ok(libs)
}

// ─── XexSection ───────────────────────────────────────────────────────────────

/// One XEX2 section (maps to a PE section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexSection {
    /// Digest of this section (SHA-1).
    pub digest: [u8; 20],
    /// Page info flags packed in the upper bits.
    pub info: u32,
}

impl XexSection {
    /// Size of one section descriptor.
    pub const SIZE: usize = 24;

    /// Parse a single section from a 24-byte slice.
    ///
    /// # Errors
    /// Returns [`XexError::TooShort`] if `data.len() < 24`.
    pub fn parse(data: &[u8]) -> Result<Self, XexError> {
        if data.len() < Self::SIZE {
            return Err(XexError::TooShort {
                need: Self::SIZE,
                have: data.len(),
            });
        }
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&data[..20]);
        let info = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        Ok(Self { digest, info })
    }

    /// Page size in bytes (4 KiB pages).
    #[must_use]
    pub const fn page_count(&self) -> u32 {
        self.info >> 4
    }
    /// Page type flags.
    #[must_use]
    pub const fn page_flags(&self) -> u32 {
        self.info & 0xF
    }
}

// ─── BaseFileFormat / compression ────────────────────────────────────────────

/// Compression type of the PE data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XexCompression {
    /// No compression.
    Uncompressed,
    /// Basic delta-compression (XOR with a fixed table).
    BasicCompressed,
    /// LZX compression (used by retail titles).
    Compressed,
    /// Delta patch only — not a standalone executable.
    DeltaPatch,
}

impl XexCompression {
    /// Parse from the raw u16 `compression_type` field.
    ///
    /// # Errors
    /// Returns [`XexError::UnsupportedCompression`] for unknown values.
    pub const fn from_u16(v: u16) -> Result<Self, XexError> {
        match v {
            0 => Ok(Self::Uncompressed),
            1 => Ok(Self::BasicCompressed),
            2 => Ok(Self::Compressed),
            3 => Ok(Self::DeltaPatch),
            other => Err(XexError::UnsupportedCompression(other)),
        }
    }
}

impl fmt::Display for XexCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Uncompressed => "uncompressed",
            Self::BasicCompressed => "basic-compressed",
            Self::Compressed => "lzx-compressed",
            Self::DeltaPatch => "delta-patch",
        };
        write!(f, "{s}")
    }
}

/// Base file format descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexBaseFileFormat {
    /// Encryption key in use (0 = none, 1 = retail).
    pub encryption_type: u16,
    /// Compression type.
    pub compression_type: XexCompression,
}

impl XexBaseFileFormat {
    /// Minimum size of this structure.
    pub const MIN_SIZE: usize = 4;

    /// Parse at `offset`.
    ///
    /// # Errors
    /// Returns [`XexError`] if the block is out of bounds or the compression type is unsupported.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, XexError> {
        if offset + Self::MIN_SIZE > data.len() {
            return Err(XexError::OffsetOob {
                offset,
                file_len: data.len(),
            });
        }
        let d = &data[offset..];
        // The optional header block starts with a u32 size field, skip it.
        let skip = if d.len() >= 4 { 4 } else { 0 };
        let d = &d[skip..];
        if d.len() < 4 {
            return Err(XexError::TooShort {
                need: 4,
                have: d.len(),
            });
        }
        let enc_type = u16::from_be_bytes([d[0], d[1]]);
        let cmp_type = u16::from_be_bytes([d[2], d[3]]);
        Ok(Self {
            encryption_type: enc_type,
            compression_type: XexCompression::from_u16(cmp_type)?,
        })
    }
}

// ─── DeltaPatch stub ─────────────────────────────────────────────────────────

/// Applies a XEX delta patch to a base image (stub implementation).
///
/// Real delta-patch logic requires the original XEX to produce the patched XEX.
/// This stub records the patch metadata and returns an error indicating that
/// the operation requires the base binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexDeltaPatch {
    /// Base build ID (20 bytes).
    pub base_build_id: [u8; 20],
    /// New build ID (20 bytes).
    pub new_build_id: [u8; 20],
    /// Sequence of `(offset, size, new_data)` patches.
    pub patches: Vec<(u32, u32, Vec<u8>)>,
}

impl XexDeltaPatch {
    /// Apply this patch to `base_data`.
    ///
    /// # Errors
    /// Always returns [`XexError::DeltaPatchUnsupported`] in this stub.
    pub const fn apply(&self, _base_data: &[u8]) -> Result<Vec<u8>, XexError> {
        Err(XexError::DeltaPatchUnsupported)
    }
}

// ─── XexFile ─────────────────────────────────────────────────────────────────

/// Top-level parsed XEX2 file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexFile {
    /// Fixed header.
    pub header: XexHeader,
    /// Optional headers, keyed by `opt_key` constant.
    pub optional_headers: HashMap<u32, XexOptionalHeader>,
    /// Security info block.
    pub security_info: Option<XexSecurityInfo>,
    /// Import libraries.
    pub imports: Vec<XexImportLibrary>,
    /// Section descriptors.
    pub sections: Vec<XexSection>,
    /// Base file format (compression info).
    pub base_format: Option<XexBaseFileFormat>,
    /// Entry point virtual address (from optional header).
    pub entry_point: Option<u64>,
    /// Image base virtual address (from optional header).
    pub image_base: Option<u64>,
}

impl XexFile {
    /// Parse a XEX2 file from `data`.
    ///
    /// # Errors
    /// Returns [`XexError`] on parse failures.
    pub fn parse(data: &[u8]) -> Result<Self, XexError> {
        let header = XexHeader::parse(data)?;
        let opt_count = header.optional_header_count as usize;
        let optional_headers = parse_optional_headers(data, opt_count)?;

        // Security info
        let security_info = {
            let off = header.security_info_offset as usize;
            if off > 0 && off < data.len() {
                XexSecurityInfo::parse(data, off).ok()
            } else {
                None
            }
        };

        // Import libraries
        let imports = optional_headers.get(&opt_key::IMPORT_LIBRARIES).map_or_else(Vec::new, |imp_hdr| {
            let off = imp_hdr.value as usize;
            if off > 0 && off < data.len() {
                parse_import_libraries(data, off).unwrap_or_default()
            } else {
                vec![]
            }
        });

        // Sections from security info page descriptors
        let sections = security_info.as_ref().map_or_else(Vec::new, |si| {
            // page_descriptor_count is from untrusted binary data; cap to avoid
            // excessive allocation and overflow in offset arithmetic.
            let count = (si.page_descriptor_count as usize)
                .min(data.len() / XexSection::SIZE);
            let sec_off = (header.security_info_offset as usize)
                .saturating_add(XexSecurityInfo::MIN_SIZE);
            let mut secs = Vec::with_capacity(count);
            for i in 0..count {
                let off = sec_off.saturating_add(i.saturating_mul(XexSection::SIZE));
                if off + XexSection::SIZE <= data.len() && let Ok(sec) = XexSection::parse(&data[off..off + XexSection::SIZE]) {
                    secs.push(sec);
                }
            }
            secs
        });

        // Base format
        let base_format = optional_headers.get(&opt_key::BASE_FILE_FORMAT).and_then(|bf_hdr| {
            let off = bf_hdr.value as usize;
            if off > 0 && off < data.len() {
                XexBaseFileFormat::parse(data, off).ok()
            } else {
                None
            }
        });

        // Entry point & image base from inline headers
        let entry_point = optional_headers
            .get(&opt_key::ENTRY_POINT)
            .map(|h| u64::from(h.value));
        let image_base = optional_headers
            .get(&opt_key::IMAGE_BASE_ADDRESS)
            .map(|h| u64::from(h.value));

        Ok(Self {
            header,
            optional_headers,
            security_info,
            imports,
            sections,
            base_format,
            entry_point,
            image_base,
        })
    }

    /// Returns `true` if the PE data is uncompressed.
    #[must_use]
    pub fn is_uncompressed(&self) -> bool {
        self.base_format
            .as_ref()
            .is_none_or(|f| f.compression_type == XexCompression::Uncompressed)
    }

    /// Returns the raw PE bytes at the `pe_data_offset`, if uncompressed.
    #[must_use]
    pub fn pe_bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let off = self.header.pe_data_offset as usize;
        if off < data.len() {
            Some(&data[off..])
        } else {
            None
        }
    }
}

// ─── is_xex helper ────────────────────────────────────────────────────────────

/// Returns `true` if `data` starts with the XEX2 magic.
#[must_use]
pub fn is_xex2(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == XEX2_MAGIC
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod alloc_regression_tests {
    use super::*;

    /// `thunk_count` is a raw big-endian u32 from the import-library record. Before the
    /// clamp, `Vec::with_capacity(thunk_count)` reserved 4 * thunk_count bytes -- up to
    /// 16 GiB -- from this ~0x94-byte input, because the per-thunk bounds check only
    /// runs after the allocation. The result must stay bounded by the block.
    #[test]
    fn thunk_count_is_clamped_to_block_size() {
        let lib = XexImportLibrary::MIN_SIZE;
        let mut block = vec![0u8; 8 + lib];
        let total = block.len() as u32;
        block[0..4].copy_from_slice(&total.to_be_bytes()); // block_size
        block[4..8].copy_from_slice(&1u32.to_be_bytes()); // lib_count = 1
        let e = 8;
        block[e..e + 4].copy_from_slice(&(lib as u32).to_be_bytes()); // entry_size
        block[e + 4..e + 8].copy_from_slice(&4u32.to_be_bytes()); // name_size
        block[e + 8..e + 12].copy_from_slice(&u32::MAX.to_be_bytes()); // thunk_count

        let libs = parse_import_libraries(&block, 0).expect("should parse");
        assert_eq!(libs.len(), 1);
        // Assert on CAPACITY, not len: the loop's per-thunk `break` already bounded
        // `len`, so a len-only assertion would pass against the unfixed code. It is
        // the reservation that was unbounded.
        assert!(
            libs[0].thunks.capacity() <= block.len() / 4,
            "reserved capacity {} exceeded block bound {}",
            libs[0].thunks.capacity(),
            block.len() / 4
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_xex() -> Vec<u8> {
        let mut d = vec![0u8; 0x100];
        // magic XEX2 (big-endian)
        d[0..4].copy_from_slice(&XEX2_MAGIC.to_be_bytes());
        // module flags = 0x0001 (TITLE)
        d[4..8].copy_from_slice(&1_u32.to_be_bytes());
        // pe_data_offset = 0x80
        d[8..12].copy_from_slice(&0x80_u32.to_be_bytes());
        // reserved = 0
        // security_info_offset = 0x40
        d[16..20].copy_from_slice(&0x40_u32.to_be_bytes());
        // optional_header_count = 0
        d
    }

    #[test]
    fn test_is_xex2() {
        let d = minimal_xex();
        assert!(is_xex2(&d));
    }

    #[test]
    fn test_is_xex2_false() {
        assert!(!is_xex2(b"MZ\x00\x00..."));
    }

    #[test]
    fn test_xex_header_parse_ok() {
        let d = minimal_xex();
        let h = XexHeader::parse(&d).unwrap();
        assert_eq!(h.magic, XEX2_MAGIC);
        assert!(h.module_flags.contains(XexModuleFlags::TITLE));
        assert_eq!(h.pe_data_offset, 0x80);
        assert_eq!(h.optional_header_count, 0);
    }

    #[test]
    fn test_xex_header_bad_magic() {
        let mut d = minimal_xex();
        d[0] = 0xFF;
        let err = XexHeader::parse(&d).unwrap_err();
        assert!(matches!(err, XexError::BadMagic { .. }));
    }

    #[test]
    fn test_xex_header_too_short() {
        let err = XexHeader::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, XexError::TooShort { .. }));
    }

    #[test]
    fn test_xex_header_display() {
        let d = minimal_xex();
        let h = XexHeader::parse(&d).unwrap();
        let s = format!("{h}");
        assert!(s.contains("XEX2"));
    }

    #[test]
    fn test_xex_optional_header_parse() {
        let data = [
            0x00, 0x01, 0x01, 0x00, // key = ENTRY_POINT
            0x00, 0x40, 0x00, 0x00, // value = 0x400000
        ];
        let h = XexOptionalHeader::parse(&data).unwrap();
        assert_eq!(h.key, 0x0001_0100);
        assert_eq!(h.value, 0x0040_0000);
        assert!(h.is_inline());
    }

    #[test]
    fn test_xex_compression_from_u16() {
        assert_eq!(
            XexCompression::from_u16(0).unwrap(),
            XexCompression::Uncompressed
        );
        assert_eq!(
            XexCompression::from_u16(1).unwrap(),
            XexCompression::BasicCompressed
        );
        assert_eq!(
            XexCompression::from_u16(2).unwrap(),
            XexCompression::Compressed
        );
        assert!(XexCompression::from_u16(0xFF).is_err());
    }

    #[test]
    fn test_xex_compression_display() {
        assert_eq!(XexCompression::Uncompressed.to_string(), "uncompressed");
        assert_eq!(XexCompression::Compressed.to_string(), "lzx-compressed");
    }

    #[test]
    fn test_xex_section_parse() {
        let mut data = vec![0xABu8; 24];
        data[20..24].copy_from_slice(&0x00_01_00_01_u32.to_be_bytes());
        let sec = XexSection::parse(&data).unwrap();
        assert_eq!(sec.page_count(), 0x1000);
    }

    #[test]
    fn test_xex_section_too_short() {
        let err = XexSection::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, XexError::TooShort { .. }));
    }

    #[test]
    fn test_xex_delta_patch_unsupported() {
        let patch = XexDeltaPatch {
            base_build_id: [0u8; 20],
            new_build_id: [1u8; 20],
            patches: vec![],
        };
        let err = patch.apply(&[]).unwrap_err();
        assert!(matches!(err, XexError::DeltaPatchUnsupported));
    }

    #[test]
    fn test_xex_file_parse_minimal() {
        let d = minimal_xex();
        let xex = XexFile::parse(&d).unwrap();
        assert_eq!(xex.header.magic, XEX2_MAGIC);
        assert!(xex.imports.is_empty());
        assert!(xex.is_uncompressed());
    }

    #[test]
    fn test_xex_module_flags_bitflags() {
        let f = XexModuleFlags::TITLE | XexModuleFlags::USER_MODE;
        assert!(f.contains(XexModuleFlags::TITLE));
        assert!(!f.contains(XexModuleFlags::SYSTEM_MODULE));
    }

    #[test]
    fn test_import_library_display() {
        let lib = XexImportLibrary {
            name: "xboxkrnl.exe".to_string(),
            version: (2, 0, 17559, 0),
            thunks: vec![0x8000_0001, 0x8000_0002],
        };
        let s = format!("{lib}");
        assert!(s.contains("xboxkrnl.exe"));
        assert!(s.contains("2 thunks"));
    }

    #[test]
    fn test_xex_error_messages() {
        let e = XexError::BadMagic {
            expected: XEX2_MAGIC,
            got: 0,
        };
        assert!(e.to_string().contains("XEX2"));
        let e2 = XexError::TooShort { need: 100, have: 4 };
        assert!(e2.to_string().contains("100"));
    }

    #[test]
    fn test_parse_optional_headers_empty() {
        let d = minimal_xex();
        let headers = parse_optional_headers(&d, 0).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_xex_security_info_parse() {
        let mut d = vec![0u8; XexSecurityInfo::MIN_SIZE + 0x100];
        // size field
        d[0..4].copy_from_slice(&u32::try_from(XexSecurityInfo::MIN_SIZE).unwrap_or(u32::MAX).to_be_bytes());
        // load_address = 0x82000000
        d[8..12].copy_from_slice(&0x8200_0000_u32.to_be_bytes());
        let si = XexSecurityInfo::parse(&d, 0).unwrap();
        assert_eq!(si.load_address, 0x8200_0000);
    }
}
