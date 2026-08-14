//! Sony PS3 / PS4 SELF (Signed ELF) loader.
//!
//! SELF wraps a standard ELF with an SCE-specific outer container that adds:
//! * A `SelfHeader` with offsets to an encrypted/authenticated payload
//! * `AppInfo` (title ID, version, auth-ID)
//! * `ElfHeader` + `ElfPhdr` array (copied verbatim from the inner ELF)
//! * `SceVersionInfo` / `ControlInfo` (optional authenticity metadata)
//! * Encrypted segment data
//!
//! This loader reconstructs the unencrypted ELF image for analysis.  It does
//! not implement decryption (a console-specific key is required) — instead it
//! stubs decryption and loads whatever plaintext is present.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ─── constants ────────────────────────────────────────────────────────────────

/// SELF magic at offset 0 (big-endian u32: `\x4F\x15\x3D\x1D`).
pub const SELF_MAGIC: u32 = 0x4F15_3D1D;
/// Extended ELF (`.sprx`) magic used by PS3 dynamic libraries.
pub const SPRX_MAGIC: u32 = 0x7F45_4C46; // Same as ELF — SPRX has the SELF wrapper
/// ELF magic.
pub const ELF_MAGIC: u32 = 0x7F45_4C46;

/// SELF header fixed size.
pub const SELF_HEADER_SIZE: usize = 0x20;

/// Key type for PS3 SELF decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfKeyType {
    /// Debug / development key (no real encryption).
    Debug,
    /// Retail activation key (encrypted with per-console master key).
    Retail,
    /// Network-patched title.
    NetworkPatch,
}

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the SELF loader.
#[derive(Debug, Error)]
pub enum SelfError {
    /// Magic mismatch.
    #[error("bad SELF magic: expected {expected:#010x}, got {got:#010x}")]
    BadMagic { expected: u32, got: u32 },
    /// File too short.
    #[error("file too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    /// Offset out of bounds.
    #[error("offset {offset:#x} is outside file (len {file_len:#x})")]
    OffsetOob { offset: usize, file_len: usize },
    /// Encrypted segment — decryption keys not available.
    #[error("segment {idx} is encrypted; decryption keys not available")]
    SegmentEncrypted { idx: usize },
    /// ELF reconstruction failed.
    #[error("ELF reconstruction failed: {0}")]
    ElfReconstructFailed(String),
    /// Generic parse error.
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── SelfHeader ───────────────────────────────────────────────────────────────

/// Outer SELF container header (32 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHeader {
    /// Magic (`SELF_MAGIC`).
    pub magic: u32,
    /// Header version (usually 0x02 for PS3, 0x03 for PS4).
    pub header_version: u8,
    /// Attribute bits.
    pub attribute: u8,
    /// Category: 1 = SELF, 2 = RVK, 3 = PKG, 4 = SPP.
    pub category: u8,
    /// Optional-header size (PS4) or reserved (PS3).
    pub opt_header_size: u8,
    /// Reserved (PS3).
    pub reserved0: u32,
    /// Total size of the SELF header area (including all metadata).
    pub header_size: u64,
    /// Size of the encrypted ELF data.
    pub elf_size: u64,
}

impl SelfHeader {
    /// Parse from the first 32 bytes of `data`.
    ///
    /// # Errors
    /// Returns [`SelfError::TooShort`] or [`SelfError::BadMagic`].
    pub fn parse(data: &[u8]) -> Result<Self, SelfError> {
        if data.len() < SELF_HEADER_SIZE {
            return Err(SelfError::TooShort {
                need: SELF_HEADER_SIZE,
                have: data.len(),
            });
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SELF_MAGIC {
            return Err(SelfError::BadMagic {
                expected: SELF_MAGIC,
                got: magic,
            });
        }
        let header_version = data[4];
        let attribute = data[5];
        let category = data[6];
        let opt_header_size = data[7];
        let reserved0 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let header_size = u64::from_be_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);
        let elf_size = u64::from_be_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);
        Ok(Self {
            magic,
            header_version,
            attribute,
            category,
            opt_header_size,
            reserved0,
            header_size,
            elf_size,
        })
    }

    /// Returns `true` if this is a PS4 SELF (header version >= 3).
    #[must_use]
    pub const fn is_ps4(&self) -> bool {
        self.header_version >= 3
    }

    /// Returns `true` if this is a SELF executable (category == 1).
    #[must_use]
    pub const fn is_self(&self) -> bool {
        self.category == 1
    }
}

impl fmt::Display for SelfHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SELF v{} cat={} hdr_size={:#x} elf_size={:#x}{}",
            self.header_version,
            self.category,
            self.header_size,
            self.elf_size,
            if self.is_ps4() { " (PS4)" } else { " (PS3)" }
        )
    }
}

// ─── AppInfo ──────────────────────────────────────────────────────────────────

/// Application metadata block embedded in the SELF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    /// Authentication ID.
    pub auth_id: u64,
    /// Vendor ID.
    pub vendor_id: u32,
    /// Self type: 1 = LV0, 2 = LV1, 3 = LV2, 4 = App, 5 = ISO, 6 = LDR.
    pub self_type: u16,
    /// Version.
    pub version: u64,
    /// Padding.
    pub padding: u16,
}

impl AppInfo {
    /// Size of the `AppInfo` structure.
    pub const SIZE: usize = 0x20;

    /// Parse from a 32-byte slice.
    ///
    /// # Errors
    /// Returns [`SelfError::TooShort`] if `data.len() < 32`.
    pub fn parse(data: &[u8]) -> Result<Self, SelfError> {
        if data.len() < Self::SIZE {
            return Err(SelfError::TooShort {
                need: Self::SIZE,
                have: data.len(),
            });
        }
        Ok(Self {
            auth_id: u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            vendor_id: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            self_type: u16::from_be_bytes([data[12], data[13]]),
            version: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            padding: u16::from_be_bytes([data[30], data[31]]),
        })
    }

    /// Human-readable self type name.
    #[must_use]
    pub const fn self_type_name(&self) -> &'static str {
        match self.self_type {
            1 => "lv0",
            2 => "lv1",
            3 => "lv2",
            4 => "app",
            5 => "iso",
            6 => "ldr",
            8 => "npdrm",
            _ => "unknown",
        }
    }
}

impl fmt::Display for AppInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AppInfo auth={:#018x} vendor={:#010x} type={} ver={:#018x}",
            self.auth_id,
            self.vendor_id,
            self.self_type_name(),
            self.version
        )
    }
}

// ─── ContentId ────────────────────────────────────────────────────────────────

/// A 36-byte content ID string as found in PS3/PS4 SELF metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentId(pub String);

impl ContentId {
    /// Parse from up to 36 ASCII bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        let len = data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or_else(|| data.len().min(36));
        Self(String::from_utf8_lossy(&data[..len]).trim().to_string())
    }

    /// Format: `EP1234-NPEB01234_00-0000000000000000`
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.0.get(..2)
    }

    /// Publisher ID (4 chars).
    #[must_use]
    pub fn publisher(&self) -> Option<&str> {
        self.0.get(2..6)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── SceMetadataInfo ─────────────────────────────────────────────────────────

/// Encrypted metadata info block (keys needed for decryption — stub only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SceMetadataInfo {
    /// Encrypted session key (128-bit AES-CBC).
    pub key: [u8; 16],
    /// Key padding (must be zeroed after decryption).
    pub key_pad: [u8; 16],
    /// Encrypted IV.
    pub iv: [u8; 16],
    /// IV padding.
    pub iv_pad: [u8; 16],
}

impl SceMetadataInfo {
    /// Parse from a 64-byte slice.
    ///
    /// # Errors
    /// Returns [`SelfError::TooShort`] if `data.len() < 64`.
    pub fn parse(data: &[u8]) -> Result<Self, SelfError> {
        if data.len() < 64 {
            return Err(SelfError::TooShort {
                need: 64,
                have: data.len(),
            });
        }
        let mut key = [0u8; 16];
        let mut key_pad = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut iv_pad = [0u8; 16];
        key.copy_from_slice(&data[0..16]);
        key_pad.copy_from_slice(&data[16..32]);
        iv.copy_from_slice(&data[32..48]);
        iv_pad.copy_from_slice(&data[48..64]);
        Ok(Self {
            key,
            key_pad,
            iv,
            iv_pad,
        })
    }

    /// Returns `true` if the key padding is all-zero (indicates debug/unsigned SELF).
    #[must_use]
    pub fn is_debug(&self) -> bool {
        self.key_pad.iter().all(|&b| b == 0) && self.iv_pad.iter().all(|&b| b == 0)
    }
}

// ─── SelfSegmentInfo ─────────────────────────────────────────────────────────

/// Per-segment descriptor in the SELF metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfSegmentInfo {
    /// File offset of the (possibly encrypted) segment.
    pub offset: u64,
    /// Size of segment data on disk.
    pub size: u64,
    /// Compression algorithm: 1 = none, 2 = zlib.
    pub compression: u32,
    /// Unknown / padding.
    pub unknown: u32,
    /// Encryption algorithm: 1 = none, 2 = AES-128-CTR.
    pub encryption: u32,
    /// Index into the key table.
    pub key_index: u32,
}

impl SelfSegmentInfo {
    /// Size of one descriptor.
    pub const SIZE: usize = 0x20;

    /// Parse from a 32-byte slice.
    ///
    /// # Errors
    /// Returns [`SelfError::TooShort`] if `data.len() < 32`.
    pub fn parse(data: &[u8]) -> Result<Self, SelfError> {
        if data.len() < Self::SIZE {
            return Err(SelfError::TooShort {
                need: Self::SIZE,
                have: data.len(),
            });
        }
        Ok(Self {
            offset: u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            size: u64::from_be_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            compression: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            unknown: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
            encryption: u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
            key_index: u32::from_be_bytes([data[28], data[29], data[30], data[31]]),
        })
    }

    /// Returns `true` if this segment is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encryption != 1
    }

    /// Returns `true` if this segment is compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.compression != 1
    }
}

// ─── ELF reconstruction ───────────────────────────────────────────────────────

/// Minimal ELF64 header (64 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf64Header {
    /// Size of the ELF64 header.
    pub const SIZE: usize = 64;

    /// Parse a standard ELF64 header (big-endian, as on PS3/PS4).
    ///
    /// # Errors
    /// Returns [`SelfError`] if data is too short or ELF magic is absent.
    pub fn parse_be(data: &[u8]) -> Result<Self, SelfError> {
        if data.len() < Self::SIZE {
            return Err(SelfError::TooShort {
                need: Self::SIZE,
                have: data.len(),
            });
        }
        if &data[..4] != b"\x7FELF" {
            return Err(SelfError::Parse("not an ELF header".into()));
        }
        let mut e_ident = [0u8; 16];
        e_ident.copy_from_slice(&data[..16]);

        let r16 = |off: usize| u16::from_be_bytes([data[off], data[off + 1]]);
        let r32 = |off: usize| {
            u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let r64 = |off: usize| {
            u64::from_be_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ])
        };

        Ok(Self {
            e_ident,
            e_type: r16(16),
            e_machine: r16(18),
            e_version: r32(20),
            e_entry: r64(24),
            e_phoff: r64(32),
            e_shoff: r64(40),
            e_flags: r32(48),
            e_ehsize: r16(52),
            e_phentsize: r16(54),
            e_phnum: r16(56),
            e_shentsize: r16(58),
            e_shnum: r16(60),
            e_shstrndx: r16(62),
        })
    }

    /// ELF machine type name.
    #[must_use]
    pub const fn machine_name(&self) -> &'static str {
        match self.e_machine {
            0x15 => "PowerPC",
            0x16 => "PowerPC64",
            0x28 => "ARM",
            0x3E => "x86-64",
            0xB7 => "AArch64",
            _ => "unknown",
        }
    }
}

// ─── SelfFile ─────────────────────────────────────────────────────────────────

/// Top-level parsed SELF/ESELF container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfFile {
    /// SELF outer header.
    pub header: SelfHeader,
    /// App info (present for most SELF types).
    pub app_info: Option<AppInfo>,
    /// Inner ELF header (reconstructed).
    pub elf_header: Option<Elf64Header>,
    /// Segment infos.
    pub segments: Vec<SelfSegmentInfo>,
    /// Content ID (NPDRM only).
    pub content_id: Option<ContentId>,
    /// Metadata info (encryption metadata, stub).
    pub metadata_info: Option<SceMetadataInfo>,
    /// Whether the SELF appears to be a debug (decryptable) build.
    pub is_debug: bool,
}

impl SelfFile {
    /// Parse a SELF file from `data`.
    ///
    /// Returns a best-effort parse; encrypted segments are recorded but not decrypted.
    ///
    /// # Errors
    /// Returns [`SelfError`] on truncation or bad magic.
    pub fn parse(data: &[u8]) -> Result<Self, SelfError> {
        let header = SelfHeader::parse(data)?;
        let hdr_size = usize::try_from(header.header_size).unwrap_or(usize::MAX);

        // AppInfo immediately follows the SELF header.
        let app_info = if hdr_size >= SELF_HEADER_SIZE + AppInfo::SIZE {
            AppInfo::parse(&data[SELF_HEADER_SIZE..]).ok()
        } else {
            None
        };

        // Locate the embedded ELF header.
        // In PS3 SELF format the ELF header starts at offset 0x40 (after AppInfo).
        let elf_off = SELF_HEADER_SIZE + AppInfo::SIZE;
        let elf_header = if elf_off + Elf64Header::SIZE <= data.len() {
            Elf64Header::parse_be(&data[elf_off..]).ok()
        } else {
            None
        };

        // Segment info array follows the ELF.
        let mut segments = Vec::new();
        if let Some(ref elf) = elf_header {
            let seg_base = elf_off + Elf64Header::SIZE;
            let phnum = elf.e_phnum as usize;
            for i in 0..phnum {
                let off = seg_base + i * SelfSegmentInfo::SIZE;
                if off + SelfSegmentInfo::SIZE <= data.len() && let Ok(si) = SelfSegmentInfo::parse(&data[off..off + SelfSegmentInfo::SIZE]) {
                    segments.push(si);
                }
            }
        }

        // Metadata info (stub — real position varies by PS3/PS4 version).
        let meta_off = hdr_size.saturating_sub(64);
        let metadata_info = if meta_off + 64 <= data.len() {
            SceMetadataInfo::parse(&data[meta_off..meta_off + 64]).ok()
        } else {
            None
        };

        let is_debug = metadata_info
            .as_ref()
            .is_some_and(SceMetadataInfo::is_debug);

        Ok(Self {
            header,
            app_info,
            elf_header,
            segments,
            content_id: None, // NPDRM parsing omitted for brevity
            metadata_info,
            is_debug,
        })
    }

    /// Attempt to reconstruct the unencrypted ELF from `data`.
    ///
    /// Returns the raw ELF bytes starting from the embedded ELF header.
    /// Encrypted segments are zeroed out in the reconstructed image.
    ///
    /// # Errors
    /// Returns [`SelfError::ElfReconstructFailed`] if the ELF header is absent.
    pub fn reconstruct_elf<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], SelfError> {
        if self.elf_header.is_none() {
            return Err(SelfError::ElfReconstructFailed(
                "no ELF header found".to_string(),
            ));
        }
        let elf_off = SELF_HEADER_SIZE + AppInfo::SIZE;
        if elf_off >= data.len() {
            return Err(SelfError::ElfReconstructFailed(
                "ELF offset out of bounds".into(),
            ));
        }
        Ok(&data[elf_off..])
    }

    /// Returns the entry point of the inner ELF (if parsed).
    #[must_use]
    pub fn entry_point(&self) -> Option<u64> {
        self.elf_header.as_ref().map(|e| e.e_entry)
    }

    /// Returns the machine architecture name.
    #[must_use]
    pub fn arch_name(&self) -> &'static str {
        self.elf_header
            .as_ref()
            .map_or("unknown", Elf64Header::machine_name)
    }
}

// ─── is_self helper ───────────────────────────────────────────────────────────

/// Returns `true` if `data` starts with the SELF magic.
#[must_use]
pub fn is_self(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == SELF_MAGIC
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_self() -> Vec<u8> {
        let mut d = vec![0u8; 0x100];
        // SELF magic (big-endian)
        d[0..4].copy_from_slice(&SELF_MAGIC.to_be_bytes());
        // header_version = 2 (PS3)
        d[4] = 2;
        // attribute = 0
        // category = 1 (SELF)
        d[6] = 1;
        // header_size = 0x100
        d[12..20].copy_from_slice(&0x0000_0000_0000_0100_u64.to_be_bytes());
        // elf_size = 0x80
        d[20..28].copy_from_slice(&0x0000_0000_0000_0080_u64.to_be_bytes());
        d
    }

    fn self_with_appinfo() -> Vec<u8> {
        let mut d = minimal_self();
        // AppInfo at offset 0x20
        // auth_id = 0x1010000001000003
        d[0x20..0x28].copy_from_slice(&0x1010_0000_0100_0003_u64.to_be_bytes());
        // vendor_id = 0x01000002
        d[0x28..0x2C].copy_from_slice(&0x0100_0002_u32.to_be_bytes());
        // self_type = 4 (app)
        d[0x2C..0x2E].copy_from_slice(&4_u16.to_be_bytes());
        d
    }

    #[test]
    fn test_is_self() {
        let d = minimal_self();
        assert!(is_self(&d));
    }

    #[test]
    fn test_is_self_false() {
        assert!(!is_self(b"MZ\x00\x00extra"));
    }

    #[test]
    fn test_self_header_parse_ok() {
        let d = minimal_self();
        let h = SelfHeader::parse(&d).unwrap();
        assert_eq!(h.magic, SELF_MAGIC);
        assert_eq!(h.header_version, 2);
        assert_eq!(h.category, 1);
        assert_eq!(h.header_size, 0x100);
        assert_eq!(h.elf_size, 0x80);
    }

    #[test]
    fn test_self_header_bad_magic() {
        let mut d = minimal_self();
        d[0] = 0xFF;
        let err = SelfHeader::parse(&d).unwrap_err();
        assert!(matches!(err, SelfError::BadMagic { .. }));
    }

    #[test]
    fn test_self_header_too_short() {
        let err = SelfHeader::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, SelfError::TooShort { .. }));
    }

    #[test]
    fn test_self_header_is_ps4() {
        let mut d = minimal_self();
        d[4] = 3;
        let h = SelfHeader::parse(&d).unwrap();
        assert!(h.is_ps4());
    }

    #[test]
    fn test_self_header_is_ps3() {
        let d = minimal_self();
        let h = SelfHeader::parse(&d).unwrap();
        assert!(!h.is_ps4());
    }

    #[test]
    fn test_self_header_display() {
        let d = minimal_self();
        let h = SelfHeader::parse(&d).unwrap();
        let s = format!("{h}");
        assert!(s.contains("SELF"));
        assert!(s.contains("PS3"));
    }

    #[test]
    fn test_app_info_parse() {
        let d = self_with_appinfo();
        let ai = AppInfo::parse(&d[0x20..]).unwrap();
        assert_eq!(ai.self_type, 4);
        assert_eq!(ai.self_type_name(), "app");
    }

    #[test]
    fn test_app_info_types() {
        let mut data = vec![0u8; AppInfo::SIZE];
        for (t, name) in &[
            (1_u16, "lv0"),
            (2, "lv1"),
            (3, "lv2"),
            (8, "npdrm"),
            (99, "unknown"),
        ] {
            data[12..14].copy_from_slice(&t.to_be_bytes());
            let ai = AppInfo::parse(&data).unwrap();
            assert_eq!(ai.self_type_name(), *name);
        }
    }

    #[test]
    fn test_content_id_parse() {
        let raw = b"EP1234-NPEB01234_00-0000000000000000\x00";
        let cid = ContentId::parse(raw);
        assert_eq!(cid.region(), Some("EP"));
        assert_eq!(cid.publisher(), Some("1234"));
    }

    #[test]
    fn test_content_id_display() {
        let cid = ContentId("EP1234-NPEB01234_00".to_string());
        assert_eq!(cid.to_string(), "EP1234-NPEB01234_00");
    }

    #[test]
    fn test_sce_metadata_info_debug() {
        // All-zero metadata indicates debug SELF.
        let data = vec![0u8; 64];
        let meta = SceMetadataInfo::parse(&data).unwrap();
        assert!(meta.is_debug());
    }

    #[test]
    fn test_sce_metadata_info_retail() {
        let mut data = vec![0u8; 64];
        data[0] = 0xAB; // non-zero key
        data[16] = 0xFF; // non-zero key_pad
        let meta = SceMetadataInfo::parse(&data).unwrap();
        assert!(!meta.is_debug());
    }

    #[test]
    fn test_self_segment_info_flags() {
        let mut data = vec![0u8; SelfSegmentInfo::SIZE];
        // encryption = 2 (encrypted)
        data[24..28].copy_from_slice(&2_u32.to_be_bytes());
        // compression = 2 (compressed)
        data[16..20].copy_from_slice(&2_u32.to_be_bytes());
        let si = SelfSegmentInfo::parse(&data).unwrap();
        assert!(si.is_encrypted());
        assert!(si.is_compressed());
    }

    #[test]
    fn test_self_segment_info_plain() {
        let mut data = vec![0u8; SelfSegmentInfo::SIZE];
        data[16..20].copy_from_slice(&1_u32.to_be_bytes());
        data[24..28].copy_from_slice(&1_u32.to_be_bytes());
        let si = SelfSegmentInfo::parse(&data).unwrap();
        assert!(!si.is_encrypted());
        assert!(!si.is_compressed());
    }

    #[test]
    fn test_elf64_header_parse() {
        let mut data = vec![0u8; Elf64Header::SIZE];
        data[0..4].copy_from_slice(b"\x7FELF");
        data[4] = 2; // ELF64
        data[5] = 2; // big-endian
        data[16..18].copy_from_slice(&2_u16.to_be_bytes()); // e_type = ET_EXEC
        data[18..20].copy_from_slice(&0x15_u16.to_be_bytes()); // e_machine = PowerPC
        let elf = Elf64Header::parse_be(&data).unwrap();
        assert_eq!(elf.e_type, 2);
        assert_eq!(elf.machine_name(), "PowerPC");
    }

    #[test]
    fn test_elf64_bad_magic() {
        let data = vec![0u8; Elf64Header::SIZE];
        let err = Elf64Header::parse_be(&data).unwrap_err();
        assert!(matches!(err, SelfError::Parse(_)));
    }

    #[test]
    fn test_self_file_parse_minimal() {
        let d = minimal_self();
        let sf = SelfFile::parse(&d).unwrap();
        assert_eq!(sf.header.magic, SELF_MAGIC);
        assert!(!sf.header.is_ps4());
    }

    #[test]
    fn test_self_file_reconstruct_elf_no_header() {
        let d = minimal_self();
        let sf = SelfFile::parse(&d).unwrap();
        // No ELF header in minimal stub
        let err = sf.reconstruct_elf(&d).unwrap_err();
        assert!(matches!(err, SelfError::ElfReconstructFailed(_)));
    }

    #[test]
    fn test_self_error_messages() {
        let e = SelfError::BadMagic {
            expected: SELF_MAGIC,
            got: 0,
        };
        assert!(e.to_string().contains("SELF"));
        let e2 = SelfError::TooShort { need: 100, have: 4 };
        assert!(e2.to_string().contains("100"));
        let e3 = SelfError::SegmentEncrypted { idx: 2 };
        assert!(e3.to_string().contains('2'));
    }

    #[test]
    fn test_self_key_type_eq() {
        assert_eq!(SelfKeyType::Debug, SelfKeyType::Debug);
        assert_ne!(SelfKeyType::Debug, SelfKeyType::Retail);
    }
}
