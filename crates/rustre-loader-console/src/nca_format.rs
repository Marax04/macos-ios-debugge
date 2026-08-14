// rustre-loader-console/src/nca_format.rs
//! Nintendo Content Archive (NCA) format parser.
//!
//! The NCA format is used by Nintendo Switch to distribute game content.
//! Magic: 0x33414349 ("ICA3" big-endian) at offset 0x200 (after RSA signature).

use std::fmt;

// ─── Constants ────────────────────────────────────────────────────────────────

/// NCA magic value at offset 0x200: "NCA3" as little-endian u32.
pub const NCA_MAGIC_NCA3: u32 = 0x3341_4349; // "ICA3" = "3ACI"
/// NCA magic value for NCA0.
pub const NCA_MAGIC_NCA0: u32 = 0x3041_4349; // "ICA0"
/// NCA magic value for NCA1.
pub const NCA_MAGIC_NCA1: u32 = 0x3141_4349;
/// NCA magic value for NCA2.
pub const NCA_MAGIC_NCA2: u32 = 0x3241_4349;
/// Total NCA header size (0x400 bytes).
pub const NCA_HEADER_SIZE: usize = 0x400;
/// Offset of the NCA fixed header within the file (after the RSA-2048 signature).
pub const NCA_FIXED_HEADER_OFFSET: usize = 0x200;
/// Size of one NCA media unit (512 bytes).
pub const NCA_MEDIA_UNIT_SIZE: u64 = 512;
/// Maximum number of sections in an NCA.
pub const NCA_MAX_SECTIONS: usize = 4;

// ─── NcaContentType ──────────────────────────────────────────────────────────

/// NCA content type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NcaContentType {
    /// Executable program (code).
    Program,
    /// Title metadata (CNMT).
    Meta,
    /// Application control data.
    Control,
    /// HTML manual.
    Manual,
    /// Generic data.
    Data,
    /// Publicly accessible data.
    PublicData,
    /// Unknown type.
    Unknown(u8),
}

impl NcaContentType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Program,
            1 => Self::Meta,
            2 => Self::Control,
            3 => Self::Manual,
            4 => Self::Data,
            5 => Self::PublicData,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Program => 0,
            Self::Meta => 1,
            Self::Control => 2,
            Self::Manual => 3,
            Self::Data => 4,
            Self::PublicData => 5,
            Self::Unknown(b) => b,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Program => "Program",
            Self::Meta => "Meta",
            Self::Control => "Control",
            Self::Manual => "Manual",
            Self::Data => "Data",
            Self::PublicData => "PublicData",
            Self::Unknown(_) => "Unknown",
        }
    }

    #[must_use]
    pub fn is_executable(self) -> bool {
        self == Self::Program
    }
}

impl fmt::Display for NcaContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── NcaCryptoType ────────────────────────────────────────────────────────────

/// Encryption type used for an NCA section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NcaCryptoType {
    /// No encryption.
    None,
    /// XTS (AES-XTS with sector-based tweak).
    Xts,
    /// CTR (AES-128-CTR).
    Ctr,
    /// BKTR (patch section).
    Bktr,
    /// Unknown encryption type.
    Unknown(u8),
}

impl NcaCryptoType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::None,
            2 => Self::Xts,
            3 => Self::Ctr,
            4 => Self::Bktr,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Xts => "XTS",
            Self::Ctr => "CTR",
            Self::Bktr => "BKTR",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for NcaCryptoType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── NcaDistributionType ──────────────────────────────────────────────────────

/// Distribution source of this NCA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcaDistributionType {
    /// Downloaded from Nintendo eShop.
    Download,
    /// On a game cartridge.
    GameCard,
    Unknown(u8),
}

impl NcaDistributionType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Download,
            1 => Self::GameCard,
            other => Self::Unknown(other),
        }
    }
}

// ─── NcaSection ──────────────────────────────────────────────────────────────

/// One of the four NCA section table entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcaSection {
    /// Start offset in media units.
    pub media_offset: u32,
    /// End offset in media units.
    pub media_end_offset: u32,
    /// Encryption type of this section.
    pub crypto_type: NcaCryptoType,
    /// Whether this entry is valid (non-zero).
    pub is_valid: bool,
}

impl NcaSection {
    /// Byte offset of the section start within the NCA file.
    #[must_use]
    pub const fn byte_offset(&self) -> u64 {
        // u64::from() not stable in const; cast is lossless (u32 → u64)
        self.media_offset as u64 * NCA_MEDIA_UNIT_SIZE
    }

    /// Byte size of the section.
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        (self.media_end_offset - self.media_offset) as u64 * NCA_MEDIA_UNIT_SIZE
    }

    /// True if this section entry is used.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.is_valid && self.media_offset != 0
    }

    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let media_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let media_end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Some(Self {
            media_offset,
            media_end_offset,
            crypto_type: NcaCryptoType::None, // filled in separately
            is_valid: media_offset != 0 || media_end_offset != 0,
        })
    }
}

impl fmt::Display for NcaSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NcaSection offset={:#x} size={:#x} crypto={}",
            self.byte_offset(),
            self.byte_size(),
            self.crypto_type,
        )
    }
}

// ─── NcaHeader ────────────────────────────────────────────────────────────────

/// Parsed NCA fixed header (starts at file offset 0x200).
#[derive(Debug, Clone)]
pub struct NcaHeader {
    /// Magic bytes (one of NCA0–NCA3).
    pub magic: u32,
    /// Distribution type.
    pub distribution_type: NcaDistributionType,
    /// Content type.
    pub content_type: NcaContentType,
    /// Key generation used for decryption.
    pub key_generation: u8,
    /// Key area encryption key index.
    pub kaek_index: u8,
    /// Total NCA content size in bytes.
    pub size: u64,
    /// Title (program) ID.
    pub title_id: u64,
    /// Content index.
    pub content_index: u32,
    /// SDK version packed as major.minor.micro.patch.
    pub sdk_version: u32,
    /// Section table (up to 4 entries).
    pub sections: [Option<NcaSection>; NCA_MAX_SECTIONS],
    /// Whether the NCA appears valid (magic check passed).
    pub is_valid: bool,
}

impl NcaHeader {
    /// Parse a header from `data`. The data should start at file offset 0x200.
    ///
    /// Layout of the fixed header (all little-endian):
    /// ```text
    /// 0x00   magic       u32
    /// 0x04   dist_type   u8
    /// 0x05   content_type u8
    /// 0x06   key_gen     u8
    /// 0x07   kaek_index  u8
    /// 0x08   size        u64
    /// 0x10   title_id    u64
    /// 0x18   content_idx u32
    /// 0x1C   sdk_ver     u32
    /// ...
    /// 0x40   section[0]  8 bytes (media_offset u32, media_end u32)
    /// 0x48   section[1]  8 bytes
    /// 0x50   section[2]  8 bytes
    /// 0x58   section[3]  8 bytes
    /// ```
    /// # Errors
    /// Returns an error string if the data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x60 {
            return Err(format!("NCA header too short: {} bytes", data.len()));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let is_valid = matches!(
            magic,
            NCA_MAGIC_NCA0 | NCA_MAGIC_NCA1 | NCA_MAGIC_NCA2 | NCA_MAGIC_NCA3
        );

        let distribution_type = NcaDistributionType::from_byte(data[4]);
        let content_type = NcaContentType::from_byte(data[5]);
        let key_generation = data[6];
        let kaek_index = data[7];
        let size = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let title_id = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let content_index = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let sdk_version = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        let mut sections: [Option<NcaSection>; 4] = [None, None, None, None];
        for (i, sec) in sections.iter_mut().enumerate() {
            let off = 0x40 + i * 8;
            if off + 8 <= data.len() && let Some(s) = NcaSection::parse(&data[off..off + 8]) {
                *sec = Some(s);
            }
        }

        Ok(Self {
            magic,
            distribution_type,
            content_type,
            key_generation,
            kaek_index,
            size,
            title_id,
            content_index,
            sdk_version,
            sections,
            is_valid,
        })
    }

    /// Decode the SDK version into (major, minor, micro, patch).
    #[must_use]
    pub const fn sdk_version_parts(&self) -> (u8, u8, u8, u8) {
        let v = self.sdk_version;
        (
            ((v >> 24) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        )
    }

    /// Number of present (non-empty) sections.
    #[must_use]
    pub fn section_count(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| s.as_ref().is_some_and(NcaSection::is_present))
            .count()
    }

    /// Version string derived from magic bytes ("NCA0"–"NCA3").
    #[must_use]
    pub const fn version_str(&self) -> &'static str {
        match self.magic {
            NCA_MAGIC_NCA0 => "NCA0",
            NCA_MAGIC_NCA1 => "NCA1",
            NCA_MAGIC_NCA2 => "NCA2",
            NCA_MAGIC_NCA3 => "NCA3",
            _ => "NCA?",
        }
    }

    /// True if this is the newest NCA3 format.
    #[must_use]
    pub const fn is_nca3(&self) -> bool {
        self.magic == NCA_MAGIC_NCA3
    }
}

impl fmt::Display for NcaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (maj, min, mic, pat) = self.sdk_version_parts();
        write!(
            f,
            "{} title_id={:#018x} content={} size={:#x} sdk={}.{}.{}.{} key_gen={} valid={}",
            self.version_str(),
            self.title_id,
            self.content_type,
            self.size,
            maj,
            min,
            mic,
            pat,
            self.key_generation,
            self.is_valid,
        )
    }
}

// ─── NcaMetadata ─────────────────────────────────────────────────────────────

/// High-level metadata derived from a parsed NCA header.
#[derive(Debug, Clone)]
pub struct NcaMetadata {
    /// NCA version string.
    pub version: String,
    /// Title ID as hex string.
    pub title_id_hex: String,
    /// Content type name.
    pub content_type_name: String,
    /// SDK version string "major.minor.micro.patch".
    pub sdk_version_str: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Key generation byte.
    pub key_generation: u8,
    /// Whether the NCA magic is valid.
    pub valid_magic: bool,
    /// Number of present sections.
    pub section_count: usize,
}

impl NcaMetadata {
    /// Build from a parsed header.
    #[must_use]
    pub fn from_header(h: &NcaHeader) -> Self {
        let (maj, min, mic, pat) = h.sdk_version_parts();
        Self {
            version: h.version_str().to_string(),
            title_id_hex: format!("{:016x}", { h.title_id }),
            content_type_name: h.content_type.name().to_string(),
            sdk_version_str: format!("{maj}.{min}.{mic}.{pat}"),
            file_size: h.size,
            key_generation: h.key_generation,
            valid_magic: h.is_valid,
            section_count: h.section_count(),
        }
    }
}

impl fmt::Display for NcaMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] title={} sdk={} size={:#x}",
            self.version,
            self.content_type_name,
            self.title_id_hex,
            self.sdk_version_str,
            self.file_size,
        )
    }
}

// ─── is_nca helper ────────────────────────────────────────────────────────────

/// Quick-probe: return true if `data` at offset 0x200 has a valid NCA magic.
#[must_use]
pub fn is_nca(data: &[u8]) -> bool {
    if data.len() < NCA_FIXED_HEADER_OFFSET + 4 {
        return false;
    }
    let magic = u32::from_le_bytes([
        data[NCA_FIXED_HEADER_OFFSET],
        data[NCA_FIXED_HEADER_OFFSET + 1],
        data[NCA_FIXED_HEADER_OFFSET + 2],
        data[NCA_FIXED_HEADER_OFFSET + 3],
    ]);
    matches!(
        magic,
        NCA_MAGIC_NCA0 | NCA_MAGIC_NCA1 | NCA_MAGIC_NCA2 | NCA_MAGIC_NCA3
    )
}

/// Parse an NCA header from `data`, where `data` is the full NCA file.
///
/// # Errors
/// Returns an error string if the data is too short or the inner header is malformed.
pub fn parse_nca(data: &[u8]) -> Result<NcaHeader, String> {
    if data.len() < NCA_FIXED_HEADER_OFFSET + NCA_HEADER_SIZE {
        return Err(format!("NCA file too short: {} bytes", data.len()));
    }
    NcaHeader::parse(&data[NCA_FIXED_HEADER_OFFSET..])
}

/// Build a minimal valid NCA3 header buffer for testing.
#[cfg(test)]
fn build_test_nca(content_type: u8, title_id: u64, size: u64) -> Vec<u8> {
    let mut data = vec![0u8; NCA_FIXED_HEADER_OFFSET + NCA_HEADER_SIZE];
    let h = &mut data[NCA_FIXED_HEADER_OFFSET..];
    // magic: NCA3
    h[0] = 0x49;
    h[1] = 0x43;
    h[2] = 0x41;
    h[3] = 0x33; // "ICA3" = NCA3 LE
    // distribution_type = download (0)
    h[4] = 0;
    // content_type
    h[5] = content_type;
    // key_generation = 9
    h[6] = 9;
    // kaek_index = 0
    h[7] = 0;
    // size
    let sb = size.to_le_bytes();
    h[8..16].copy_from_slice(&sb);
    // title_id
    let tb = title_id.to_le_bytes();
    h[16..24].copy_from_slice(&tb);
    // content_index
    h[24..28].copy_from_slice(&0u32.to_le_bytes());
    // sdk_version: 13.0.0.0 → 0x0D_00_00_00
    h[28..32].copy_from_slice(&0x0D_00_00_00u32.to_le_bytes());
    // section[0]: media_offset=1, media_end=2
    h[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
    h[0x44..0x48].copy_from_slice(&2u32.to_le_bytes());
    data
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NcaContentType ────────────────────────────────────────────────────────

    #[test]
    fn test_content_type_round_trip() {
        for b in 0u8..=5 {
            let ct = NcaContentType::from_byte(b);
            assert_eq!(ct.to_byte(), b);
        }
    }

    #[test]
    fn test_content_type_names() {
        assert_eq!(NcaContentType::Program.name(), "Program");
        assert_eq!(NcaContentType::Meta.name(), "Meta");
        assert_eq!(NcaContentType::Control.name(), "Control");
        assert_eq!(NcaContentType::Manual.name(), "Manual");
        assert_eq!(NcaContentType::Data.name(), "Data");
        assert_eq!(NcaContentType::PublicData.name(), "PublicData");
    }

    #[test]
    fn test_content_type_is_executable() {
        assert!(NcaContentType::Program.is_executable());
        assert!(!NcaContentType::Data.is_executable());
    }

    #[test]
    fn test_content_type_unknown() {
        let ct = NcaContentType::from_byte(0xFF);
        assert_eq!(ct, NcaContentType::Unknown(0xFF));
    }

    // ── NcaCryptoType ─────────────────────────────────────────────────────────

    #[test]
    fn test_crypto_type_names() {
        assert_eq!(NcaCryptoType::None.name(), "None");
        assert_eq!(NcaCryptoType::Xts.name(), "XTS");
        assert_eq!(NcaCryptoType::Ctr.name(), "CTR");
        assert_eq!(NcaCryptoType::Bktr.name(), "BKTR");
    }

    #[test]
    fn test_crypto_type_from_byte() {
        assert_eq!(NcaCryptoType::from_byte(1), NcaCryptoType::None);
        assert_eq!(NcaCryptoType::from_byte(2), NcaCryptoType::Xts);
        assert_eq!(NcaCryptoType::from_byte(3), NcaCryptoType::Ctr);
        assert_eq!(NcaCryptoType::from_byte(4), NcaCryptoType::Bktr);
    }

    // ── NcaSection ────────────────────────────────────────────────────────────

    #[test]
    fn test_section_byte_offset() {
        let s = NcaSection {
            media_offset: 4,
            media_end_offset: 8,
            crypto_type: NcaCryptoType::Ctr,
            is_valid: true,
        };
        assert_eq!(s.byte_offset(), 4 * 512);
        assert_eq!(s.byte_size(), 4 * 512);
    }

    #[test]
    fn test_section_is_present() {
        let s = NcaSection {
            media_offset: 1,
            media_end_offset: 10,
            crypto_type: NcaCryptoType::None,
            is_valid: true,
        };
        assert!(s.is_present());
    }

    #[test]
    fn test_section_not_present_zero_offset() {
        let s = NcaSection {
            media_offset: 0,
            media_end_offset: 0,
            crypto_type: NcaCryptoType::None,
            is_valid: false,
        };
        assert!(!s.is_present());
    }

    // ── NcaHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_header_parse_valid_nca3() {
        let data = build_test_nca(0, 0x0100_ABCD_1234_5678, 0x0010_0000);
        let h = parse_nca(&data).unwrap();
        assert!(h.is_valid);
        assert_eq!(h.version_str(), "NCA3");
        assert!(h.is_nca3());
        assert_eq!(h.content_type, NcaContentType::Program);
        assert_eq!(h.title_id, 0x0100_ABCD_1234_5678);
        assert_eq!(h.size, 0x0010_0000);
        assert_eq!(h.key_generation, 9);
    }

    #[test]
    fn test_header_parse_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_nca(&data).is_err());
    }

    #[test]
    fn test_header_parse_invalid_magic() {
        let mut data = build_test_nca(0, 0, 0);
        data[NCA_FIXED_HEADER_OFFSET] = 0xFF; // corrupt magic
        let h = parse_nca(&data).unwrap();
        assert!(!h.is_valid);
    }

    #[test]
    fn test_header_sdk_version() {
        let data = build_test_nca(0, 0, 0);
        let h = parse_nca(&data).unwrap();
        let (maj, min, mic, pat) = h.sdk_version_parts();
        assert_eq!(maj, 13);
        assert_eq!(min, 0);
        assert_eq!(mic, 0);
        assert_eq!(pat, 0);
    }

    #[test]
    fn test_header_section_count() {
        let data = build_test_nca(0, 0, 0);
        let h = parse_nca(&data).unwrap();
        assert_eq!(h.section_count(), 1); // only section[0] has non-zero offsets
    }

    #[test]
    fn test_header_display() {
        let data = build_test_nca(0, 0x0100_0000_0000_0001, 0x400);
        let h = parse_nca(&data).unwrap();
        let s = h.to_string();
        assert!(s.contains("NCA3"));
        assert!(s.contains("Program"));
    }

    #[test]
    fn test_is_nca_true() {
        let data = build_test_nca(1, 0, 0);
        assert!(is_nca(&data));
    }

    #[test]
    fn test_is_nca_false_too_short() {
        let data = vec![0u8; 10];
        assert!(!is_nca(&data));
    }

    // ── NcaMetadata ───────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_from_header() {
        let data = build_test_nca(2, 0x0100_CAFE_BABE_0000, 0x80000);
        let h = parse_nca(&data).unwrap();
        let meta = NcaMetadata::from_header(&h);
        assert_eq!(meta.version, "NCA3");
        assert_eq!(meta.content_type_name, "Control");
        assert!(meta.title_id_hex.contains("cafe"));
        assert_eq!(meta.sdk_version_str, "13.0.0.0");
        assert!(meta.valid_magic);
    }

    #[test]
    fn test_metadata_display() {
        let data = build_test_nca(0, 0x0100_0000_0000_ABCD, 0x1000);
        let h = parse_nca(&data).unwrap();
        let meta = NcaMetadata::from_header(&h);
        let s = meta.to_string();
        assert!(s.contains("NCA3"));
        assert!(s.contains("Program"));
    }

    #[test]
    fn test_all_content_types_parseable() {
        for b in 0u8..=5 {
            let data = build_test_nca(b, 0, 0);
            let h = parse_nca(&data).unwrap();
            assert_ne!(h.content_type.name(), "");
        }
    }
}
