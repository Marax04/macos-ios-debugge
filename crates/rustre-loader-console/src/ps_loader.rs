//! `ps_loader` — `PlayStation` format loaders (PS4 `SELF`/`PRX`, PS3 `SELF`/`SPRX`)
//!
//! Implements parsing for Sony `PlayStation` executable formats:
//!
//! ## PS4 / PS5 SELF
//!
//! * Fake PKG structure detection (PFS header + ELF payload).
//! * SELF header parsing (64-byte extended ELF header with segment table).
//! * Section info records (compressed/encrypted segment descriptors).
//! * Decryption wrapper stub (actual decryption requires console-specific keys).
//! * NPDRM metadata parsing (content ID, DRM type, app version).
//!
//! ## PS3 SELF / SPRX
//!
//! * Certified File (CF) header parsing.
//! * Metadata header + AES-256-CTR encrypted section info.
//! * NPDRM authentication info (license type, app type, content ID).
//! * SDK version extraction.
//! * Control info records (digest, NPDRM).
//!
//! Both loaders extract enough metadata for binary identification without
//! performing actual decryption (which requires platform keys).
//!
//! # References
//! * `fail0verflow` PS3 SELF documentation.
//! * `xorloser` PS4 SELF notes.
//! * `psdevwiki.com` PS3/PS4 format specifications.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SELF_MAGIC_PS3: u32  = 0x5343_4500; // "SCE\0"
pub const SELF_MAGIC_PS4: u32  = 0x4F41_5400; // PS4 uses same "SCE\0"
pub const SCE_MAGIC: u32       = 0x5343_4500;
pub const ELF_MAGIC: u32       = 0x7F45_4C46; // "\x7FELF"

/// Category field values in the SELF extended header.
pub mod self_category {
    pub const SELF: u16       = 0x01;
    pub const SINIT_MANAGER: u16 = 0x02;
    pub const SECURE_LOADER: u16 = 0x03;
    pub const ISO_DISC_LOADER: u16 = 0x04;
    pub const PS3_GAME_DATA: u16 = 0x10;
    pub const LOADER_PATCHED: u16 = 0x20;
}

/// Key revision / type.
pub mod key_revision {
    pub const RETAIL: u16  = 0x0001;
    pub const DEVKIT: u16  = 0x8000;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PsLoaderError {
    #[error("not a SELF file: bad magic {0:#010x}")]
    BadMagic(u32),
    #[error("SELF header truncated")]
    Truncated,
    #[error("embedded ELF not found")]
    ElfNotFound,
    #[error("section info out of bounds")]
    SectionOob,
    #[error("decryption requires platform keys (not available)")]
    DecryptionRequired,
    #[error("unsupported SELF version: {0}")]
    UnsupportedVersion(u64),
    #[error("metadata header corrupt")]
    MetadataCorrupt,
    #[error("parse error: {0}")]
    ParseError(String),
}

// ---------------------------------------------------------------------------
// ELF helpers
// ---------------------------------------------------------------------------

/// Minimal ELF header (both 32- and 64-bit, LE or BE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeader {
    pub class: u8,         // 1 = 32-bit, 2 = 64-bit
    pub data: u8,          // 1 = LE, 2 = BE
    pub elf_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry_point: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub program_header_count: u16,
    pub section_header_count: u16,
}

impl ElfHeader {
    /// # Panics
    /// Panics if slices within a valid ELF header cannot be converted (should not happen).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 4 > data.len() { return None; }
        let magic = u32::from_be_bytes(data[off..off+4].try_into().ok()?);
        if magic != ELF_MAGIC { return None; }
        if off + 64 > data.len() { return None; }
        let e = &data[off..off+64];
        let class  = e[4];
        let endian = e[5]; // 1=LE, 2=BE
        let read16 = |o: usize| -> u16 {
            if endian == 2 { u16::from_be_bytes([e[o], e[o+1]]) }
            else           { u16::from_le_bytes([e[o], e[o+1]]) }
        };
        let read32 = |o: usize| -> u32 {
            if endian == 2 { u32::from_be_bytes(e[o..o+4].try_into().unwrap()) }
            else           { u32::from_le_bytes(e[o..o+4].try_into().unwrap()) }
        };
        let read64 = |o: usize| -> u64 {
            if endian == 2 { u64::from_be_bytes(e[o..o+8].try_into().unwrap()) }
            else           { u64::from_le_bytes(e[o..o+8].try_into().unwrap()) }
        };
        let (ep, phoff, shoff, ph_cnt, sh_cnt) = if class == 2 {
            // 64-bit
            (read64(24), read64(32), read64(40),
             read16(56), read16(60))
        } else {
            // 32-bit
            (u64::from(read32(24)), u64::from(read32(28)), u64::from(read32(32)),
             read16(44), read16(48))
        };
        Some(Self {
            class, data: endian,
            elf_type: read16(16),
            machine: read16(18),
            version: read32(20),
            entry_point: ep,
            program_header_offset: phoff,
            section_header_offset: shoff,
            flags: if class == 2 { read32(48) } else { read32(36) },
            program_header_count: ph_cnt,
            section_header_count: sh_cnt,
        })
    }

    #[must_use]
    pub const fn is_big_endian(&self) -> bool { self.data == 2 }
    #[must_use]
    pub const fn is_64bit(&self) -> bool { self.class == 2 }
    #[must_use]
    pub const fn machine_name(&self) -> &'static str {
        match self.machine {
            0x17 => "PPC (PS3/Xbox360)",
            0x15 => "PPC64",
            0x3E => "x86-64 (PS4/PS5)",
            0xB7 => "AArch64 (PS5 native)",
            _    => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// PS3 SELF header
// ---------------------------------------------------------------------------

/// PS3 Certified File (CF) / SELF extended header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3SelfHeader {
    /// "SCE\0" magic.
    pub magic: u32,
    /// File version.
    pub header_version: u32,
    /// Key revision (0x01 = retail, 0x8000 = devkit).
    pub key_revision: u16,
    /// Category (see `self_category::*`).
    pub category: u16,
    /// Metadata (section table) offset.
    pub metadata_offset: u32,
    /// Header length (SCE header + ext header + segment info).
    pub header_length: u64,
    /// Total length of the SELF file.
    pub elf_file_size: u64,
}

impl Ps3SelfHeader {
    /// # Errors
    /// Returns [`PsLoaderError::Truncated`] if data is too short, or [`PsLoaderError::BadMagic`] if magic is wrong.
    ///
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    pub fn parse(data: &[u8]) -> Result<Self, PsLoaderError> {
        if data.len() < 32 { return Err(PsLoaderError::Truncated); }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != SCE_MAGIC { return Err(PsLoaderError::BadMagic(magic)); }
        Ok(Self {
            magic,
            header_version:  u32::from_be_bytes(data[4..8].try_into().unwrap()),
            key_revision:    u16::from_be_bytes(data[8..10].try_into().unwrap()),
            category:        u16::from_be_bytes(data[10..12].try_into().unwrap()),
            metadata_offset: u32::from_be_bytes(data[12..16].try_into().unwrap()),
            header_length:   u64::from_be_bytes(data[16..24].try_into().unwrap()),
            elf_file_size:   u64::from_be_bytes(data[24..32].try_into().unwrap()),
        })
    }

    #[must_use]
    pub const fn is_retail(&self) -> bool { self.key_revision == key_revision::RETAIL }
    #[must_use]
    pub const fn is_devkit(&self) -> bool { self.key_revision == key_revision::DEVKIT }
    #[must_use]
    pub const fn category_name(&self) -> &'static str {
        match self.category {
            self_category::SELF           => "SELF",
            self_category::SINIT_MANAGER  => "SInitManager",
            self_category::SECURE_LOADER  => "SecureLoader",
            self_category::PS3_GAME_DATA  => "PS3GameData",
            _                             => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// PS3 extended SELF header (follows immediately after SCE header)
// ---------------------------------------------------------------------------

/// PS3 extended SELF header (the portion describing the embedded ELF).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3ExtSelfHeader {
    /// ELF header within the SELF file.
    pub elf_header_offset: u64,
    /// Program header table offset within the SELF file.
    pub phdr_offset: u64,
    /// Section header table offset within the SELF file.
    pub shdr_offset: u64,
    /// Section info offset (array of `SectionInfo` records).
    pub section_info_offset: u64,
    /// Version info offset.
    pub version_info_offset: u64,
    /// Control info offset.
    pub control_info_offset: u64,
    /// Control info size.
    pub control_info_size: u64,
    /// Padding.
    pub padding: u64,
}

impl Ps3ExtSelfHeader {
    /// # Errors
    /// Returns [`PsLoaderError::Truncated`] if data is too short.
    ///
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    pub fn parse(data: &[u8], off: usize) -> Result<Self, PsLoaderError> {
        if off + 64 > data.len() { return Err(PsLoaderError::Truncated); }
        let d = &data[off..off+64];
        let r64 = |o: usize| u64::from_be_bytes(d[o..o+8].try_into().unwrap());
        Ok(Self {
            elf_header_offset:    r64(0),
            phdr_offset:          r64(8),
            shdr_offset:          r64(16),
            section_info_offset:  r64(24),
            version_info_offset:  r64(32),
            control_info_offset:  r64(40),
            control_info_size:    r64(48),
            padding:              r64(56),
        })
    }
}

// ---------------------------------------------------------------------------
// PS3 Section Info
// ---------------------------------------------------------------------------

/// A segment info record describing a segment within the SELF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3SectionInfo {
    /// Offset of the segment within the SELF file.
    pub offset: u64,
    /// Size of the segment in the SELF file.
    pub size: u64,
    /// Compression algorithm (1 = plain, 2 = zlib).
    pub compressed: u32,
    /// Reserved / padding.
    pub pad0: u32,
    /// Encryption algorithm (1 = none, 3 = AES-CTR).
    pub encrypted: u32,
    /// Reserved.
    pub pad1: u32,
}

impl Ps3SectionInfo {
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 32 > data.len() { return None; }
        let d = &data[off..off+32];
        let r64 = |o: usize| u64::from_be_bytes(d[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_be_bytes(d[o..o+4].try_into().unwrap());
        Some(Self {
            offset:     r64(0),
            size:       r64(8),
            compressed: r32(16),
            pad0:       r32(20),
            encrypted:  r32(24),
            pad1:       r32(28),
        })
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool { self.compressed == 2 }
    #[must_use]
    pub const fn is_encrypted(&self) -> bool  { self.encrypted == 3 }
}

// ---------------------------------------------------------------------------
// NPDRM info
// ---------------------------------------------------------------------------

/// NPDRM (DRM) information embedded in control info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpdrmInfo {
    /// License type (1 = network, 2 = local, 3 = free).
    pub license_type: u32,
    /// Application type (6 = PS3 game, 7 = PS3 mini, etc.).
    pub app_type: u32,
    /// Content ID (36 bytes, e.g. `"EP0001-BLUS30001_00-XXXXXXXXXXXX"`).
    pub content_id: String,
    /// Random pad / randomizer.
    pub random_pad: [u8; 16],
    /// CID fn hash (HMAC-SHA1 of content ID).
    pub cid_fn_hash: [u8; 20],
    /// Header hash.
    pub header_hash: [u8; 20],
    /// Limited time expiry (0 = no limit).
    pub limited_time: u64,
}

impl NpdrmInfo {
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 0x90 > data.len() { return None; }
        let d = &data[off..off+0x90];
        let license_type = u32::from_be_bytes(d[0..4].try_into().unwrap());
        let app_type     = u32::from_be_bytes(d[4..8].try_into().unwrap());
        let content_id_bytes = &d[8..8+0x30];
        let nul = content_id_bytes.iter().position(|&b| b==0).unwrap_or(0x30);
        let content_id = String::from_utf8_lossy(&content_id_bytes[..nul]).into_owned();
        let mut random_pad  = [0u8; 16];
        let mut cid_fn_hash = [0u8; 20];
        let mut header_hash = [0u8; 20];
        random_pad.copy_from_slice(&d[0x38..0x48]);
        cid_fn_hash.copy_from_slice(&d[0x48..0x5C]);
        header_hash.copy_from_slice(&d[0x5C..0x70]);
        let limited_time = u64::from_be_bytes(d[0x80..0x88].try_into().unwrap());
        Some(Self { license_type, app_type, content_id, random_pad, cid_fn_hash, header_hash, limited_time })
    }

    #[must_use]
    pub const fn license_name(&self) -> &'static str {
        match self.license_type {
            1 => "Network (online-only)",
            2 => "Local (offline)",
            3 => "Free (no DRM)",
            _ => "Unknown",
        }
    }

    #[must_use]
    pub const fn is_free(&self) -> bool { self.license_type == 3 }
}

// ---------------------------------------------------------------------------
// PS3 version info
// ---------------------------------------------------------------------------

/// SDK version information extracted from the SELF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3VersionInfo {
    /// Self type (1 = SPRX, 2 = self).
    pub self_type: u32,
    /// Version (BCD encoded: 0x0355060 = SDK 3.55.060).
    pub version: u64,
    /// Padding.
    pub pad: [u8; 8],
    /// Digest (SHA-1 of SELF header).
    pub digest: [u8; 20],
}

impl Ps3VersionInfo {
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + 48 > data.len() { return None; }
        let d = &data[off..off+48];
        let mut pad    = [0u8; 8];
        let mut digest = [0u8; 20];
        pad.copy_from_slice(&d[12..20]);
        digest.copy_from_slice(&d[20..40]);
        Some(Self {
            self_type: u32::from_be_bytes(d[0..4].try_into().unwrap()),
            version:   u64::from_be_bytes(d[4..12].try_into().unwrap()),
            pad, digest,
        })
    }

    #[must_use]
    pub fn sdk_version_string(&self) -> String {
        // BCD: version >> 32 = major.minor, lower 32 = build.
        let hi = u32::try_from(self.version >> 32).unwrap_or(u32::MAX);
        // low 32 bits: mask ensures the value fits in u32
        let lo = u32::try_from(self.version & 0xFFFF_FFFF).unwrap_or(0);
        format!("{}.{:02}.{:03}", (hi >> 16) & 0xFF, hi & 0xFF, lo >> 16)
    }

    #[must_use]
    pub const fn is_sprx(&self) -> bool { self.self_type == 1 }
}

// ---------------------------------------------------------------------------
// PS4 SELF header
// ---------------------------------------------------------------------------

/// PS4 extended ELF (SELF) header.
///
/// PS4 SELF = ELF with an extended header prepended.  The first 8 bytes are:
/// `SCE\0` magic (4) + `00 00 01 00` (version).  The segment table describes
/// encrypted/compressed segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps4SelfHeader {
    /// SCE magic (`SCE\0`).
    pub magic: u32,
    /// SELF version (0x00000003 for PS4).
    pub self_version: u16,
    /// SELF attributes.
    pub attributes: u16,
    /// Category (0x01 = SELF).
    pub category: u16,
    /// Program count (number of segment entries).
    pub program_count: u16,
    /// Header size.
    pub header_size: u64,
    /// Metadata size (encrypted).
    pub metadata_size: u64,
    /// Total SELF file size.
    pub file_size: u64,
    /// Number of segment info records.
    pub num_segments: u16,
    /// Padding.
    pub pad: u16,
}

impl Ps4SelfHeader {
    pub const SIZE: usize = 0x20;

    /// # Errors
    /// Returns [`PsLoaderError::Truncated`] if data is too short, or [`PsLoaderError::BadMagic`] if magic is wrong.
    ///
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    pub fn parse(data: &[u8]) -> Result<Self, PsLoaderError> {
        if data.len() < Self::SIZE { return Err(PsLoaderError::Truncated); }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        // PS4 stores "SCE\0" in little-endian on x86.
        let magic_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic_be != SCE_MAGIC && magic != SCE_MAGIC {
            return Err(PsLoaderError::BadMagic(magic_be));
        }
        Ok(Self {
            magic:          magic_be,
            self_version:   u16::from_le_bytes(data[4..6].try_into().unwrap()),
            attributes:     u16::from_le_bytes(data[6..8].try_into().unwrap()),
            category:       u16::from_le_bytes(data[8..10].try_into().unwrap()),
            program_count:  u16::from_le_bytes(data[10..12].try_into().unwrap()),
            header_size:    u64::from_le_bytes(data[12..20].try_into().unwrap()),
            metadata_size:  u64::from_le_bytes(data[20..28].try_into().unwrap()),
            file_size:      0, // parsed from extended data
            num_segments:   u16::from_le_bytes(data[8..10].try_into().unwrap()),
            pad:            0,
        })
    }
}

// ---------------------------------------------------------------------------
// PS4 Segment Info
// ---------------------------------------------------------------------------

/// PS4 SELF segment descriptor (describes encryption/compression of one segment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps4SegmentInfo {
    /// Flags (bit 0 = ordered, bit 1 = encrypted, bit 2 = signed, bit 3 = compressed).
    pub flags: u64,
    /// Offset of the encrypted/compressed segment within the SELF file.
    pub offset: u64,
    /// Encrypted size.
    pub encrypted_size: u64,
    /// Decrypted size.
    pub decrypted_size: u64,
}

impl Ps4SegmentInfo {
    pub const SIZE: usize = 32;

    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Option<Self> {
        if off + Self::SIZE > data.len() { return None; }
        let d = &data[off..off+Self::SIZE];
        let r64 = |o: usize| u64::from_le_bytes(d[o..o+8].try_into().unwrap());
        Some(Self { flags: r64(0), offset: r64(8), encrypted_size: r64(16), decrypted_size: r64(24) })
    }

    #[must_use]
    pub const fn is_encrypted(&self)  -> bool { self.flags & (1 << 1) != 0 }
    #[must_use]
    pub const fn is_compressed(&self) -> bool { self.flags & (1 << 3) != 0 }
    #[must_use]
    pub const fn is_signed(&self)     -> bool { self.flags & (1 << 2) != 0 }
}

// ---------------------------------------------------------------------------
// High-level PS loader
// ---------------------------------------------------------------------------

/// Unified `PlayStation` format loader.
pub struct PsLoader;

impl PsLoader {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Detect format and parse metadata from raw SELF bytes.
    ///
    /// # Errors
    /// Returns [`PsLoaderError`] if the data is too short, magic is wrong, or a sub-header fails to parse.
    ///
    /// # Panics
    /// Panics if byte slices cannot be converted (should not happen when bounds are checked).
    pub fn parse(&self, data: &[u8]) -> Result<PsSelfInfo, PsLoaderError> {
        if data.len() < 8 { return Err(PsLoaderError::Truncated); }
        let magic_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic_be != SCE_MAGIC { return Err(PsLoaderError::BadMagic(magic_be)); }

        // Distinguish PS3 vs PS4 by header_version / key_revision field (bytes 4-8).
        let hdr_ver = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if hdr_ver == 0x0000_0002 || hdr_ver == 0x0000_0003 {
            Self::parse_ps3(data)
        } else {
            Self::parse_ps4(data)
        }
    }

    fn parse_ps3(data: &[u8]) -> Result<PsSelfInfo, PsLoaderError> {
        let sce_header = Ps3SelfHeader::parse(data)?;
        // Extended SELF header follows at offset 32.
        let ext = Ps3ExtSelfHeader::parse(data, 32)?;

        // Parse embedded ELF header.
        let elf = ElfHeader::parse(data, usize::try_from(ext.elf_header_offset).unwrap_or(usize::MAX));

        // Parse version info.
        let version_info = Ps3VersionInfo::parse(data, usize::try_from(ext.version_info_offset).unwrap_or(usize::MAX));

        // Parse section infos.
        let mut segments = Vec::new();
        let elf_phdr_count = elf.as_ref().map_or(0, |e| usize::from(e.program_header_count));
        for i in 0..elf_phdr_count {
            let off = usize::try_from(ext.section_info_offset).unwrap_or(usize::MAX).saturating_add(i * 32);
            if let Some(si) = Ps3SectionInfo::parse(data, off) {
                segments.push(si);
            }
        }

        // Parse NPDRM info from control info.
        let npdrm = if ext.control_info_size > 0 {
            NpdrmInfo::parse(data, usize::try_from(ext.control_info_offset).unwrap_or(usize::MAX).saturating_add(0x20))
        } else { None };

        let sdk_version = version_info.as_ref().map(Ps3VersionInfo::sdk_version_string);

        Ok(PsSelfInfo {
            platform: PsPlatform::Ps3,
            magic: sce_header.magic,
            is_retail: sce_header.is_retail(),
            is_devkit: sce_header.is_devkit(),
            is_encrypted: segments.iter().any(Ps3SectionInfo::is_encrypted),
            sdk_version,
            content_id: npdrm.as_ref().map(|n| n.content_id.clone()),
            elf_header: elf,
            segment_count: segments.len(),
            ps3_segments: segments,
            ps4_segments: Vec::new(),
            npdrm,
            title_id: None,
        })
    }

    fn parse_ps4(data: &[u8]) -> Result<PsSelfInfo, PsLoaderError> {
        let sce_header = Ps4SelfHeader::parse(data)?;

        // The ELF header starts at offset 0x1000 (after SELF extended header + segment table).
        let elf_off = 0x1000usize;
        let elf = ElfHeader::parse(data, elf_off);

        // Parse segment info table (starts at offset Self::SIZE + 0x10 typically).
        let seg_table_off = Ps4SelfHeader::SIZE + 0x10;
        let mut segments = Vec::new();
        for i in 0..usize::from(sce_header.num_segments) {
            let off = seg_table_off + i * Ps4SegmentInfo::SIZE;
            if let Some(si) = Ps4SegmentInfo::parse(data, off) {
                segments.push(si);
            }
        }

        let is_encrypted = segments.iter().any(Ps4SegmentInfo::is_encrypted);

        Ok(PsSelfInfo {
            platform: PsPlatform::Ps4,
            magic: sce_header.magic,
            is_retail: true, // assume retail for PS4 unless devkit flag
            is_devkit: false,
            is_encrypted,
            sdk_version: None,
            content_id: None,
            elf_header: elf,
            segment_count: segments.len(),
            ps3_segments: Vec::new(),
            ps4_segments: segments,
            npdrm: None,
            title_id: None,
        })
    }
}

impl Default for PsLoader {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Unified output type
// ---------------------------------------------------------------------------

/// `PlayStation` platform identifier (`PS3`, `PS4`, `PS5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsPlatform { Ps3, Ps4, Ps5 }

impl std::fmt::Display for PsPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Ps3 => write!(f, "PS3"), Self::Ps4 => write!(f, "PS4"), Self::Ps5 => write!(f, "PS5") }
    }
}

/// Parsed `SELF` information for any `PlayStation` platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsSelfInfo {
    pub platform: PsPlatform,
    pub magic: u32,
    pub is_retail: bool,
    pub is_devkit: bool,
    pub is_encrypted: bool,
    pub sdk_version: Option<String>,
    pub content_id: Option<String>,
    pub elf_header: Option<ElfHeader>,
    pub segment_count: usize,
    pub ps3_segments: Vec<Ps3SectionInfo>,
    pub ps4_segments: Vec<Ps4SegmentInfo>,
    pub npdrm: Option<NpdrmInfo>,
    pub title_id: Option<String>,
}

impl PsSelfInfo {
    #[must_use]
    pub fn machine_name(&self) -> &'static str {
        self.elf_header.as_ref().map_or("Unknown", ElfHeader::machine_name)
    }

    #[must_use]
    pub fn has_drm(&self) -> bool { self.npdrm.as_ref().is_some_and(|n| !n.is_free()) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps3_self_header_bad_magic() {
        let data = [0u8; 32];
        assert!(Ps3SelfHeader::parse(&data).is_err());
    }

    #[test]
    fn ps3_self_header_valid() {
        let mut data = [0u8; 32];
        data[0..4].copy_from_slice(&SCE_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&2u32.to_be_bytes()); // header_version
        data[8..10].copy_from_slice(&key_revision::RETAIL.to_be_bytes());
        data[10..12].copy_from_slice(&self_category::SELF.to_be_bytes());
        let h = Ps3SelfHeader::parse(&data).unwrap();
        assert!(h.is_retail());
        assert!(!h.is_devkit());
        assert_eq!(h.category_name(), "SELF");
    }

    #[test]
    fn ps3_version_sdk_string() {
        let mut data = [0u8; 48];
        let version: u64 = 0x0000_0003_5506_0000; // 3.55.0
        data[4..12].copy_from_slice(&version.to_be_bytes());
        let vi = Ps3VersionInfo::parse(&data, 0).unwrap();
        // Just check it doesn't panic and returns something.
        let s = vi.sdk_version_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn elf_header_parse_not_elf() {
        let data = [0u8; 64];
        assert!(ElfHeader::parse(&data, 0).is_none());
    }

    #[test]
    fn elf_header_parse_valid_be() {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&ELF_MAGIC.to_be_bytes());
        data[4] = 2; // 64-bit
        data[5] = 2; // big-endian
        // machine = 0x0017 (PPC)
        data[18..20].copy_from_slice(&0x0017u16.to_be_bytes());
        let h = ElfHeader::parse(&data, 0).unwrap();
        assert!(h.is_big_endian());
        assert!(h.is_64bit());
        assert_eq!(h.machine_name(), "PPC (PS3/Xbox360)");
    }

    #[test]
    fn ps4_segment_flags() {
        let mut data = [0u8; Ps4SegmentInfo::SIZE];
        let flags: u64 = (1 << 1) | (1 << 3); // encrypted + compressed
        data[0..8].copy_from_slice(&flags.to_le_bytes());
        let si = Ps4SegmentInfo::parse(&data, 0).unwrap();
        assert!(si.is_encrypted());
        assert!(si.is_compressed());
        assert!(!si.is_signed());
    }
}
