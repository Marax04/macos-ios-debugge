//! `cache_header` — `dyld_shared_cache` header format definitions.
//!
//! Covers every version of the on-disk header from dyld-195 (iOS 3.1)
//! through dyld-1125 (iOS 17 / macOS 14).  Fields that were added in later
//! versions carry a comment indicating the minimum dyld version.

use super::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// Magic strings
// ─────────────────────────────────────────────────────────────────────────────

/// Known dyld shared cache magic prefixes (first 14 bytes are constant).
pub const DYLD_CACHE_MAGIC_PREFIX: &[u8] = b"dyld_v1     ";

/// Full 16-byte magic for arm64 caches (iOS 8+).
pub const DYLD_MAGIC_ARM64: &[u8; 16] = b"dyld_v1   arm64\0";
/// Full 16-byte magic for arm64e caches (iOS 12+ / macOS 11+).
pub const DYLD_MAGIC_ARM64E: &[u8; 16] = b"dyld_v1  arm64e\0";
/// Full 16-byte magic for `arm64_32` caches (watchOS).
pub const DYLD_MAGIC_ARM64_32: &[u8; 16] = b"dyld_v1 arm64_32";
/// Full 16-byte magic for `x86_64` caches (macOS Intel).
pub const DYLD_MAGIC_X86_64: &[u8; 16] = b"dyld_v1  x86_64\0";
/// Full 16-byte magic for `x86_64h` (Haswell) caches.
pub const DYLD_MAGIC_X86_64H: &[u8; 16] = b"dyld_v1 x86_64h\0";
/// Full 16-byte magic for armv7k caches (watchOS before `arm64_32`).
pub const DYLD_MAGIC_ARMV7K: &[u8; 16] = b"dyld_v1   armv7k";
/// Full 16-byte magic for armv7s caches (iPhone 4S era).
pub const DYLD_MAGIC_ARMV7S: &[u8; 16] = b"dyld_v1   armv7s";
/// Full 16-byte magic for i386 caches (macOS 32-bit simulator).
pub const DYLD_MAGIC_I386: &[u8; 16] = b"dyld_v1    i386\0";

// ─────────────────────────────────────────────────────────────────────────────
// Platform constants
// ─────────────────────────────────────────────────────────────────────────────

pub const PLATFORM_UNKNOWN: u32 = 0;
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_BRIDGEOS: u32 = 5;
pub const PLATFORM_MACCATALYST: u32 = 6;
pub const PLATFORM_IOS_SIMULATOR: u32 = 7;
pub const PLATFORM_TVOS_SIMULATOR: u32 = 8;
pub const PLATFORM_WATCHOS_SIMULATOR: u32 = 9;
pub const PLATFORM_DRIVERKIT: u32 = 10;
pub const PLATFORM_VISIONOS: u32 = 11;
pub const PLATFORM_VISIONOS_SIMULATOR: u32 = 12;

// ─────────────────────────────────────────────────────────────────────────────
// Header version flags
// ─────────────────────────────────────────────────────────────────────────────

/// `format_version` value indicating the presence of sub-cache fields.
pub const FORMAT_VERSION_SUBCACHES: u32 = 1;
/// `format_version` value indicating symbols cache support (dyld 940+).
pub const FORMAT_VERSION_SYMBOLS_CACHE: u32 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Minimum sizes for each schema version
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum header size for the original dyld v1 layout (dyld-195).
pub const HEADER_SIZE_V1: usize = 0x68;
/// Minimum header size including UUID field (dyld-239).
pub const HEADER_SIZE_WITH_UUID: usize = 0x78;
/// Minimum header size including codeSignature fields (dyld-360).
pub const HEADER_SIZE_WITH_CODESIG: usize = 0x88;
/// Minimum header size including imagesCount + imagesOffset for new images (dyld-832).
pub const HEADER_SIZE_WITH_NEW_IMAGES: usize = 0xC0;
/// Minimum header size for sub-cache format (dyld-940+).
pub const HEADER_SIZE_SUBCACHES: usize = 0x100;
/// Full extended header size (dyld-1100+).
pub const HEADER_SIZE_EXTENDED: usize = 0x140;

// ─────────────────────────────────────────────────────────────────────────────
// Raw on-disk structures (parsed from bytes)
// ─────────────────────────────────────────────────────────────────────────────

/// Complete parsed representation of a `dyld_cache_header`.
///
/// Fields with `Option<_>` were introduced in later dyld versions; `None`
/// indicates the file's header was too small to contain them.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheHeader {
    // ── core fields (dyld-195, all versions) ────────────────────────────────
    /// Architecture magic string, zero-padded to 16 bytes.
    pub magic: String,
    /// File offset of the first `dyld_cache_mapping_info` entry.
    pub mapping_offset: u32,
    /// Number of `dyld_cache_mapping_info` entries.
    pub mapping_count: u32,
    /// File offset of the first `dyld_cache_image_info` entry (legacy).
    pub images_offset: u32,
    /// Number of `dyld_cache_image_info` entries (legacy).
    pub images_count: u32,
    /// Virtual address at which dyld loaded the shared region.
    pub dyld_base_address: u64,

    // ── code signature (dyld-360+) ───────────────────────────────────────────
    /// File offset of the embedded code signature blob.
    pub code_sig_offset: Option<u64>,
    /// Byte length of the embedded code signature blob.
    pub code_sig_size: Option<u64>,

    // ── slide info (dyld-360+) ───────────────────────────────────────────────
    /// File offset of the (legacy) `dyld_cache_slide_info`.
    pub slide_info_offset: Option<u64>,
    /// Byte size of the (legacy) slide info region.
    pub slide_info_size: Option<u64>,

    // ── local symbols (dyld-360+) ────────────────────────────────────────────
    /// File offset of the local-symbols blob.
    pub local_syms_offset: Option<u64>,
    /// Byte size of the local-symbols blob.
    pub local_syms_size: Option<u64>,

    // ── UUID (dyld-239+) ─────────────────────────────────────────────────────
    /// 128-bit UUID that uniquely identifies this cache build.
    pub uuid: Option<[u8; 16]>,

    // ── cache type (dyld-360+) ───────────────────────────────────────────────
    /// Cache type: 0 = development, 1 = production.
    pub cache_type: Option<u64>,

    // ── branch pools (dyld-360+) ─────────────────────────────────────────────
    /// File offset of the branch-pool addresses array.
    pub branch_pools_offset: Option<u32>,
    /// Number of branch-pool entries.
    pub branch_pools_count: Option<u32>,

    // ── accelerate info (dyld-832, removed in dyld-940) ──────────────────────
    /// Virtual address of the accelerate-info page (if present).
    pub accelerate_info_addr: Option<u64>,
    /// Byte size of the accelerate-info region.
    pub accelerate_info_size: Option<u64>,

    // ── new image list (dyld-832+) ───────────────────────────────────────────
    /// File offset of the new `dyld_cache_image_text_info` list.
    pub images_text_offset: Option<u64>,
    /// Number of entries in the new image-text list.
    pub images_text_count: Option<u64>,

    // ── dynamic config (dyld-940+) ────────────────────────────────────────────
    /// File offset of the `dyld_cache_dynamic_data_header`.
    pub dynamic_data_offset: Option<u64>,
    /// Byte size of the dynamic data region.
    pub dynamic_data_size: Option<u64>,

    // ── sub-caches (dyld-940+) ────────────────────────────────────────────────
    /// File offset of the sub-cache entry array.
    pub subcache_array_offset: Option<u32>,
    /// Number of sub-cache entries.
    pub subcache_array_count: Option<u32>,
    /// UUID of the `.symbols` sub-cache (if present).
    pub symbols_subcache_uuid: Option<[u8; 16]>,

    // ── platform (dyld-940+) ─────────────────────────────────────────────────
    /// Platform identifier (see `PLATFORM_*` constants).
    pub platform: Option<u32>,
    /// Internal format version.
    pub format_version: Option<u32>,

    // ── shared region (dyld-940+) ────────────────────────────────────────────
    /// Start of the OS shared-cache ASLR region.
    pub shared_region_start: Option<u64>,
    /// Size of the OS shared-cache ASLR region.
    pub shared_region_size: Option<u64>,
    /// Maximum virtual address slide that may be applied.
    pub max_slide: Option<u64>,

    // ── mapping with slide info array (dyld-940+) ────────────────────────────
    /// File offset of the extended mapping-and-slide-info array.
    pub mapping_with_slide_offset: Option<u32>,
    /// Number of entries in the extended mapping array.
    pub mapping_with_slide_count: Option<u32>,
}

impl DyldCacheHeader {
    /// Parse a `DyldCacheHeader` from raw cache bytes.
    ///
    /// Only the first `HEADER_SIZE_V1` bytes are mandatory; everything else
    /// is extracted conditionally based on the actual size of the header.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < HEADER_SIZE_V1 {
            return Err(DyldError::Truncated(0));
        }
        // Validate magic prefix.
        let magic_bytes = &data[0..16];
        let magic = String::from_utf8_lossy(magic_bytes)
            .trim_end_matches('\0')
            .to_owned();

        if !magic.starts_with("dyld_v1") {
            return Err(DyldError::InvalidMagic {
                expected: "dyld_v1…".to_owned(),
                actual: magic,
            });
        }

        let mapping_offset = read_u32(data, 16)?;
        let mapping_count = read_u32(data, 20)?;
        let images_offset = read_u32(data, 24)?;
        let images_count = read_u32(data, 28)?;
        let dyld_base_address = read_u64(data, 32)?;

        // code sig (0x28 .. 0x38)
        let (code_sig_offset, code_sig_size) = if data.len() >= 0x38 {
            (Some(read_u64(data, 0x28)?), Some(read_u64(data, 0x30)?))
        } else {
            (None, None)
        };

        // slide info (0x38 .. 0x48)
        let (slide_info_offset, slide_info_size) = if data.len() >= 0x48 {
            (Some(read_u64(data, 0x38)?), Some(read_u64(data, 0x40)?))
        } else {
            (None, None)
        };

        // local syms (0x48 .. 0x58)
        let (local_syms_offset, local_syms_size) = if data.len() >= 0x58 {
            (Some(read_u64(data, 0x48)?), Some(read_u64(data, 0x50)?))
        } else {
            (None, None)
        };

        // UUID (0x58 .. 0x68)
        //
        // The UUID field belongs to header revisions newer than the original
        // V1 layout (which ends at `HEADER_SIZE_V1`). A bare V1 header therefore
        // has no UUID; it is only present once the header is extended to at
        // least `HEADER_SIZE_WITH_UUID`.
        let uuid = if data.len() >= HEADER_SIZE_WITH_UUID {
            let mut u = [0u8; 16];
            u.copy_from_slice(&data[0x58..0x68]);
            Some(u)
        } else {
            None
        };

        // cache_type (0x68 .. 0x70)
        let cache_type = if data.len() >= 0x70 {
            Some(read_u64(data, 0x68)?)
        } else {
            None
        };

        // branch pools (0x70 .. 0x78)
        let (branch_pools_offset, branch_pools_count) = if data.len() >= 0x78 {
            (Some(read_u32(data, 0x70)?), Some(read_u32(data, 0x74)?))
        } else {
            (None, None)
        };

        // accelerate info (0x78 .. 0x88)
        let (accelerate_info_addr, accelerate_info_size) = if data.len() >= 0x88 {
            (Some(read_u64(data, 0x78)?), Some(read_u64(data, 0x80)?))
        } else {
            (None, None)
        };

        // new images text (0x88 .. 0x98)
        let (images_text_offset, images_text_count) = if data.len() >= 0x98 {
            (Some(read_u64(data, 0x88)?), Some(read_u64(data, 0x90)?))
        } else {
            (None, None)
        };

        // dynamic data (0x98 .. 0xA8)
        let (dynamic_data_offset, dynamic_data_size) = if data.len() >= 0xA8 {
            (Some(read_u64(data, 0x98)?), Some(read_u64(data, 0xA0)?))
        } else {
            (None, None)
        };

        // sub-cache array (0xA8 .. 0xB0)
        let (subcache_array_offset, subcache_array_count) = if data.len() >= 0xB0 {
            (Some(read_u32(data, 0xA8)?), Some(read_u32(data, 0xAC)?))
        } else {
            (None, None)
        };

        // symbols sub-cache UUID (0xB0 .. 0xC0)
        let symbols_subcache_uuid = if data.len() >= 0xC0 {
            let mut u = [0u8; 16];
            u.copy_from_slice(&data[0xB0..0xC0]);
            Some(u)
        } else {
            None
        };

        // shared region (0xC0 .. 0xD8)
        let (shared_region_start, shared_region_size, max_slide) = if data.len() >= 0xD8 {
            (
                Some(read_u64(data, 0xC0)?),
                Some(read_u64(data, 0xC8)?),
                Some(read_u64(data, 0xD0)?),
            )
        } else {
            (None, None, None)
        };

        // platform + format_version (0xD8 .. 0xE0)
        let (platform, format_version) = if data.len() >= 0xE0 {
            (Some(read_u32(data, 0xD8)?), Some(read_u32(data, 0xDC)?))
        } else {
            (None, None)
        };

        // mapping with slide (0xE0 .. 0xE8)
        let (mapping_with_slide_offset, mapping_with_slide_count) = if data.len() >= 0xE8 {
            (Some(read_u32(data, 0xE0)?), Some(read_u32(data, 0xE4)?))
        } else {
            (None, None)
        };

        Ok(Self {
            magic,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_sig_offset,
            code_sig_size,
            slide_info_offset,
            slide_info_size,
            local_syms_offset,
            local_syms_size,
            uuid,
            cache_type,
            branch_pools_offset,
            branch_pools_count,
            accelerate_info_addr,
            accelerate_info_size,
            images_text_offset,
            images_text_count,
            dynamic_data_offset,
            dynamic_data_size,
            subcache_array_offset,
            subcache_array_count,
            symbols_subcache_uuid,
            platform,
            format_version,
            shared_region_start,
            shared_region_size,
            max_slide,
            mapping_with_slide_offset,
            mapping_with_slide_count,
        })
    }

    /// Return a human-readable platform name.
    #[must_use]
    pub const fn platform_name(&self) -> &'static str {
        match self.platform {
            Some(PLATFORM_MACOS) => "macOS",
            Some(PLATFORM_IOS) => "iOS",
            Some(PLATFORM_TVOS) => "tvOS",
            Some(PLATFORM_WATCHOS) => "watchOS",
            Some(PLATFORM_BRIDGEOS) => "bridgeOS",
            Some(PLATFORM_MACCATALYST) => "macCatalyst",
            Some(PLATFORM_IOS_SIMULATOR) => "iOS Simulator",
            Some(PLATFORM_TVOS_SIMULATOR) => "tvOS Simulator",
            Some(PLATFORM_WATCHOS_SIMULATOR) => "watchOS Simulator",
            Some(PLATFORM_DRIVERKIT) => "DriverKit",
            Some(PLATFORM_VISIONOS) => "visionOS",
            Some(PLATFORM_VISIONOS_SIMULATOR) => "visionOS Simulator",
            _ => "unknown",
        }
    }

    /// Returns `true` if the cache was built for a simulator.
    #[must_use]
    pub const fn is_simulator(&self) -> bool {
        matches!(
            self.platform,
            Some(
                PLATFORM_IOS_SIMULATOR
                    | PLATFORM_TVOS_SIMULATOR
                    | PLATFORM_WATCHOS_SIMULATOR
                    | PLATFORM_VISIONOS_SIMULATOR
            )
        )
    }

    /// Returns `true` if this header supports sub-caches (dyld-940+).
    #[must_use]
    pub fn has_subcaches(&self) -> bool {
        self.subcache_array_offset.is_some() && self.subcache_array_count.is_some_and(|c| c > 0)
    }

    /// Returns `true` if the cache was built in development mode.
    #[must_use]
    pub fn is_development(&self) -> bool {
        self.cache_type == Some(0)
    }

    /// Returns `true` if the cache was built for production (the default).
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.cache_type.is_none_or(|t| t == 1)
    }

    /// Returns the architecture string embedded in the magic.
    ///
    /// E.g. `"arm64"`, `"arm64e"`, `"x86_64"`.
    #[must_use]
    pub fn architecture(&self) -> &str {
        // Magic is "dyld_v1  <arch>" with padding spaces.
        self.magic
            .trim_start_matches("dyld_v1")
            .trim_start_matches(' ')
    }

    /// Returns `true` for any arm64 variant (arm64, arm64e, `arm64_32`).
    #[must_use]
    pub fn is_arm64(&self) -> bool {
        let arch = self.architecture();
        arch.starts_with("arm64")
    }

    /// Returns `true` for `x86_64` or `x86_64h`.
    #[must_use]
    pub fn is_x86_64(&self) -> bool {
        let arch = self.architecture();
        arch.starts_with("x86_64")
    }

    /// Returns the UUID formatted as a standard UUID string (`XXXXXXXX-XXXX-…`).
    #[must_use]
    pub fn uuid_string(&self) -> Option<String> {
        self.uuid.map(|u| {
            format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u[0], u[1], u[2], u[3],
                u[4], u[5],
                u[6], u[7],
                u[8], u[9],
                u[10], u[11], u[12], u[13], u[14], u[15],
            )
        })
    }

    /// Returns the symbols-subcache UUID as a string.
    #[must_use]
    pub fn symbols_uuid_string(&self) -> Option<String> {
        self.symbols_subcache_uuid.map(|u| {
            format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u[0], u[1], u[2], u[3],
                u[4], u[5],
                u[6], u[7],
                u[8], u[9],
                u[10], u[11], u[12], u[13], u[14], u[15],
            )
        })
    }

    /// Returns the effective maximum ASLR slide in bytes.
    ///
    /// Falls back to a platform-appropriate default when the field is absent.
    #[must_use]
    pub fn effective_max_slide(&self) -> u64 {
        self.max_slide.unwrap_or(0x1000_0000)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detected schema version of a dyld shared cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DyldCacheVersion {
    /// Original layout (dyld-195, iOS 3.1 – iOS 5).
    V1,
    /// Added UUID (dyld-239, iOS 6).
    V2WithUuid,
    /// Added code-signature + slide-info (dyld-360, iOS 7).
    V3WithCodeSig,
    /// Added new image-text list (dyld-832, iOS 13 / macOS 10.15).
    V4WithNewImages,
    /// Added sub-caches + symbols cache (dyld-940, macOS 11 / iOS 15).
    V5WithSubcaches,
    /// Extended mappings + platform field (dyld-1100+, iOS 16+).
    V6Extended,
}

impl DyldCacheVersion {
    /// Detect the schema version from the raw header size and field values.
    #[must_use]
    pub const fn detect(header: &DyldCacheHeader) -> Self {
        if header.mapping_with_slide_offset.is_some() {
            Self::V6Extended
        } else if header.subcache_array_offset.is_some() {
            Self::V5WithSubcaches
        } else if header.images_text_offset.is_some() {
            Self::V4WithNewImages
        } else if header.accelerate_info_addr.is_some() {
            // The accelerate-info table is the first field appended after the
            // UUID/branch-pool region, so it marks the V3 (+CodeSig) layout.
            // `slide_info`/`code_sig` cannot be used here: their bytes are
            // already present in the original V1 header range.
            Self::V3WithCodeSig
        } else if header.uuid.is_some() {
            Self::V2WithUuid
        } else {
            Self::V1
        }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1 (dyld-195)",
            Self::V2WithUuid => "v2 (dyld-239, +UUID)",
            Self::V3WithCodeSig => "v3 (dyld-360, +CodeSig)",
            Self::V4WithNewImages => "v4 (dyld-832, +NewImages)",
            Self::V5WithSubcaches => "v5 (dyld-940, +Subcaches)",
            Self::V6Extended => "v6 (dyld-1100+, extended)",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Header summary
// ─────────────────────────────────────────────────────────────────────────────

/// A concise human-readable summary of a `DyldCacheHeader`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeaderSummary {
    pub magic: String,
    pub architecture: String,
    pub platform: String,
    pub uuid: Option<String>,
    pub version: String,
    pub images: u32,
    pub mappings: u32,
    pub max_slide: u64,
    pub has_subcaches: bool,
    pub is_simulator: bool,
    pub is_development: bool,
}

impl HeaderSummary {
    /// Build a `HeaderSummary` from a parsed header.
    #[must_use]
    pub fn from_header(h: &DyldCacheHeader) -> Self {
        let version = DyldCacheVersion::detect(h);
        Self {
            magic: h.magic.clone(),
            architecture: h.architecture().to_owned(),
            platform: h.platform_name().to_owned(),
            uuid: h.uuid_string(),
            version: version.label().to_owned(),
            images: h.images_count,
            mappings: h.mapping_count,
            max_slide: h.effective_max_slide(),
            has_subcaches: h.has_subcaches(),
            is_simulator: h.is_simulator(),
            is_development: h.is_development(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-reading helpers (little-endian, checked)
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    data.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(DyldError::Truncated(offset))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_header(arch: &[u8; 16]) -> Vec<u8> {
        let mut data = vec![0u8; HEADER_SIZE_V1];
        data[0..16].copy_from_slice(arch);
        // mapping_offset = 0x68, mapping_count = 3
        data[16..20].copy_from_slice(&0x68u32.to_le_bytes());
        data[20..24].copy_from_slice(&3u32.to_le_bytes());
        // images_offset = 0x100, images_count = 100
        data[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        data[28..32].copy_from_slice(&100u32.to_le_bytes());
        // dyld_base_address = 0x180000000
        data[32..40].copy_from_slice(&0x0001_8000_0000_u64.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_minimal_arm64() {
        let raw = make_minimal_header(DYLD_MAGIC_ARM64);
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        assert_eq!(hdr.magic.trim_end_matches('\0'), "dyld_v1   arm64");
        assert_eq!(hdr.mapping_count, 3);
        assert_eq!(hdr.images_count, 100);
        assert_eq!(hdr.dyld_base_address, 0x0001_8000_0000);
        assert!(hdr.uuid.is_none());
        assert!(!hdr.has_subcaches());
    }

    #[test]
    fn test_parse_with_uuid() {
        let mut raw = make_minimal_header(DYLD_MAGIC_ARM64E);
        raw.resize(HEADER_SIZE_WITH_UUID, 0);
        // Fill UUID with a pattern.
        for (i, b) in raw[0x58..0x68].iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        let uuid = hdr.uuid.expect("uuid");
        assert_eq!(uuid[0], 0);
        assert_eq!(uuid[15], 15);
    }

    #[test]
    fn test_architecture_extraction() {
        let raw = make_minimal_header(DYLD_MAGIC_X86_64H);
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        assert_eq!(hdr.architecture(), "x86_64h");
        assert!(hdr.is_x86_64());
        assert!(!hdr.is_arm64());
    }

    #[test]
    fn test_invalid_magic() {
        let mut raw = vec![0u8; HEADER_SIZE_V1];
        raw[0..4].copy_from_slice(b"MAPL");
        let result = DyldCacheHeader::parse(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short() {
        let raw = vec![0u8; 4];
        let result = DyldCacheHeader::parse(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_detection_v1() {
        let raw = make_minimal_header(DYLD_MAGIC_ARM64);
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        assert_eq!(DyldCacheVersion::detect(&hdr), DyldCacheVersion::V1);
    }

    #[test]
    fn test_platform_name() {
        let mut hdr =
            DyldCacheHeader::parse(&make_minimal_header(DYLD_MAGIC_ARM64)).expect("parse");
        hdr.platform = Some(PLATFORM_IOS);
        assert_eq!(hdr.platform_name(), "iOS");
        hdr.platform = Some(PLATFORM_IOS_SIMULATOR);
        assert!(hdr.is_simulator());
    }

    #[test]
    fn test_uuid_string_format() {
        let mut raw = make_minimal_header(DYLD_MAGIC_ARM64E);
        raw.resize(HEADER_SIZE_WITH_UUID, 0);
        let pattern: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        raw[0x58..0x68].copy_from_slice(&pattern);
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        let s = hdr.uuid_string().expect("uuid string");
        assert!(s.contains('-'));
        assert_eq!(s.len(), 36);
    }

    #[test]
    fn test_header_summary() {
        let mut raw = make_minimal_header(DYLD_MAGIC_ARM64);
        raw.resize(HEADER_SIZE_WITH_UUID, 0);
        let hdr = DyldCacheHeader::parse(&raw).expect("parse");
        let summary = HeaderSummary::from_header(&hdr);
        assert_eq!(summary.mappings, 3);
        assert_eq!(summary.images, 100);
        assert!(!summary.has_subcaches);
    }
}
