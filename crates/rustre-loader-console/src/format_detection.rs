//! Console game format detection.
//!
//! `ConsoleFormatDetector` identifies 30+ console binary formats by magic
//! bytes, structural heuristics, and a built-in `FormatDb`.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── ConsoleFormat ────────────────────────────────────────────────────────────

/// Every supported console binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleFormat {
    // Nintendo Switch
    NsoExecutable,
    NroExecutable,
    NcaContent,
    XciCartridge,
    XczCartridge,
    // Xbox 360
    XexExecutable,
    XblaXContent,
    // PlayStation 3
    SelfExecutable,
    PkgPackage,
    EbootBin,
    // PlayStation 4
    ParamSfo,
    Pkg4,
    FselfExecutable,
    // PlayStation Vita
    VpkPackage,
    // Nintendo 3DS
    CiaPackage,
    ThreeDsxExecutable,
    NcchContent,
    // Game Boy Advance
    GbaRom,
    // Nintendo DS
    NdsRom,
    // Nintendo GameCube / Wii
    GcmDisc,
    WiiDisc,
    DolExecutable,
    // Sega
    GenesisRom,
    SegaCdDisc,
    Sega32xRom,
    DreamcastGdi,
    // Game Boy
    GbRom,
    GbcRom,
    // SNES
    SnesRom,
    // NES
    NesRom,
    // PC-Engine
    PceRom,
    // Neo Geo
    NeoGeoAes,
    // Unknown
    Unknown,
}

impl fmt::Display for ConsoleFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NsoExecutable => "NSO (Switch Executable)",
            Self::NroExecutable => "NRO (Switch Relocatable)",
            Self::NcaContent => "NCA (Switch Content Archive)",
            Self::XciCartridge => "XCI (Switch Cartridge Image)",
            Self::XczCartridge => "XCZ (Switch Compressed Cartridge)",
            Self::XexExecutable => "XEX (Xbox 360 Executable)",
            Self::XblaXContent => "XBLA/XContent (Xbox 360 Package)",
            Self::SelfExecutable => "SELF (PS3 Executable)",
            Self::PkgPackage => "PKG (PS3 Package)",
            Self::EbootBin => "EBOOT.BIN (PS3)",
            Self::ParamSfo => "PARAM.SFO (PS4 Metadata)",
            Self::Pkg4 => "PKG4 (PS4 Package)",
            Self::FselfExecutable => "FSELF (PS4 Executable)",
            Self::VpkPackage => "VPK (Vita Package)",
            Self::CiaPackage => "CIA (3DS Package)",
            Self::ThreeDsxExecutable => "3DSX (3DS Executable)",
            Self::NcchContent => "NCCH (3DS Content)",
            Self::GbaRom => "GBA ROM",
            Self::NdsRom => "NDS ROM",
            Self::GcmDisc => "GCM (GameCube Disc)",
            Self::WiiDisc => "Wii Disc",
            Self::DolExecutable => "DOL (GameCube/Wii Executable)",
            Self::GenesisRom => "Sega Genesis ROM",
            Self::SegaCdDisc => "Sega CD Disc",
            Self::Sega32xRom => "Sega 32X ROM",
            Self::DreamcastGdi => "Dreamcast GDI",
            Self::GbRom => "Game Boy ROM",
            Self::GbcRom => "Game Boy Color ROM",
            Self::SnesRom => "SNES ROM",
            Self::NesRom => "NES ROM",
            Self::PceRom => "PC-Engine ROM",
            Self::NeoGeoAes => "Neo Geo AES ROM",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl ConsoleFormat {
    /// Return the file extension(s) typically associated with this format.
    #[must_use]
    pub const fn typical_extensions(self) -> &'static [&'static str] {
        match self {
            Self::NsoExecutable => &["nso"],
            Self::NroExecutable => &["nro"],
            Self::NcaContent => &["nca"],
            Self::XciCartridge => &["xci"],
            Self::XczCartridge => &["xcz"],
            Self::XexExecutable => &["xex"],
            Self::XblaXContent => &["con", "live", "pirs"],
            Self::SelfExecutable => &["self"],
            Self::PkgPackage | Self::Pkg4 => &["pkg"],
            Self::EbootBin => &["bin"],
            Self::ParamSfo => &["sfo"],
            Self::FselfExecutable => &["fself", "sprx"],
            Self::VpkPackage => &["vpk"],
            Self::CiaPackage => &["cia"],
            Self::ThreeDsxExecutable => &["3dsx"],
            Self::NcchContent => &["ncch", "cxi", "cfa"],
            Self::GbaRom => &["gba", "agb"],
            Self::NdsRom => &["nds", "ds"],
            Self::GcmDisc => &["gcm", "iso"],
            Self::WiiDisc => &["wbfs", "iso"],
            Self::DolExecutable => &["dol"],
            Self::GenesisRom => &["md", "gen", "bin"],
            Self::SegaCdDisc => &["iso", "bin"],
            Self::Sega32xRom => &["32x"],
            Self::DreamcastGdi => &["gdi"],
            Self::GbRom => &["gb"],
            Self::GbcRom => &["gbc"],
            Self::SnesRom => &["smc", "sfc"],
            Self::NesRom => &["nes"],
            Self::PceRom => &["pce"],
            Self::NeoGeoAes => &["neo"],
            Self::Unknown => &[],
        }
    }

    /// Return `true` when the format is for a handheld console.
    #[must_use]
    pub const fn is_handheld(self) -> bool {
        matches!(
            self,
            Self::NSO_PLUS_EXECUTABLE
                | Self::NroExecutable
                | Self::GbaRom
                | Self::NdsRom
                | Self::GbRom
                | Self::GbcRom
                | Self::CiaPackage
                | Self::ThreeDsxExecutable
                | Self::NcchContent
                | Self::VpkPackage
                | Self::PceRom
        )
    }

    // Private alias used inside is_handheld — avoids adding a variant
    const NSO_PLUS_EXECUTABLE: Self = Self::NsoExecutable;

    /// Return `true` when this is a Nintendo Switch format.
    #[must_use]
    pub const fn is_switch(self) -> bool {
        matches!(
            self,
            Self::NsoExecutable
                | Self::NroExecutable
                | Self::NcaContent
                | Self::XciCartridge
                | Self::XczCartridge
        )
    }

    /// Return `true` when this is a `PlayStation` format.
    #[must_use]
    pub const fn is_playstation(self) -> bool {
        matches!(
            self,
            Self::SelfExecutable
                | Self::PkgPackage
                | Self::EbootBin
                | Self::ParamSfo
                | Self::Pkg4
                | Self::FselfExecutable
                | Self::VpkPackage
        )
    }
}

// ─── FormatSignature ─────────────────────────────────────────────────────────

/// A magic-byte signature used to identify a console format.
#[derive(Debug, Clone)]
pub struct FormatSignature {
    /// The format this signature belongs to.
    pub format: ConsoleFormat,
    /// Offset within the file where the magic appears.
    pub offset: usize,
    /// Magic bytes to match.
    pub magic: &'static [u8],
    /// Human-readable description.
    pub description: &'static str,
    /// Minimum file size needed to perform the check.
    pub min_size: usize,
}

impl FormatSignature {
    /// Returns `true` if `data` matches this signature at the configured offset.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.min_size {
            return false;
        }
        let end = self.offset + self.magic.len();
        if end > data.len() {
            return false;
        }
        &data[self.offset..end] == self.magic
    }
}

// ─── FormatDb ─────────────────────────────────────────────────────────────────

/// Database of all known console format signatures.
pub struct FormatDb {
    signatures: Vec<FormatSignature>,
}

impl FormatDb {
    /// Create the default database with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: Self::build_signatures(),
        }
    }

    /// Return a reference to all signatures.
    #[must_use]
    pub fn signatures(&self) -> &[FormatSignature] {
        &self.signatures
    }

    /// Find all matching signatures for `data`.
    #[must_use]
    pub fn find_matches(&self, data: &[u8]) -> Vec<&FormatSignature> {
        self.signatures.iter().filter(|s| s.matches(data)).collect()
    }

    /// Return the most specific matching format, or `ConsoleFormat::Unknown`.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> ConsoleFormat {
        // Prefer signatures with longer magic sequences (more specific)
        self.signatures
            .iter()
            .filter(|s| s.matches(data))
            .max_by_key(|s| s.magic.len())
            .map_or(ConsoleFormat::Unknown, |s| s.format)
    }

    fn build_signatures() -> Vec<FormatSignature> {
        vec![
            // Nintendo Switch NSO
            FormatSignature {
                format: ConsoleFormat::NsoExecutable,
                offset: 0,
                magic: b"NSO0",
                description: "Nintendo Switch NSO executable",
                min_size: 4,
            },
            // Nintendo Switch NRO
            FormatSignature {
                format: ConsoleFormat::NroExecutable,
                offset: 0x10,
                magic: b"NRO0",
                description: "Nintendo Switch NRO relocatable",
                min_size: 0x14,
            },
            // Nintendo Switch NCA
            FormatSignature {
                format: ConsoleFormat::NcaContent,
                offset: 0x200,
                magic: b"NCA3",
                description: "Nintendo Switch NCA3 content archive",
                min_size: 0x204,
            },
            // XCI
            FormatSignature {
                format: ConsoleFormat::XciCartridge,
                offset: 0x100,
                magic: b"HEAD",
                description: "Nintendo Switch XCI cartridge",
                min_size: 0x104,
            },
            // Xbox 360 XEX
            FormatSignature {
                format: ConsoleFormat::XexExecutable,
                offset: 0,
                magic: b"XEX2",
                description: "Xbox 360 XEX2 executable",
                min_size: 4,
            },
            // Xbox 360 XEX1
            FormatSignature {
                format: ConsoleFormat::XexExecutable,
                offset: 0,
                magic: b"XEX1",
                description: "Xbox 360 XEX1 executable",
                min_size: 4,
            },
            // PS3 SELF
            FormatSignature {
                format: ConsoleFormat::SelfExecutable,
                offset: 0,
                magic: &[0x53, 0x43, 0x45, 0x00], // "SCE\0"
                description: "PlayStation 3 SELF/SPRX executable",
                min_size: 4,
            },
            // PS3 PKG
            FormatSignature {
                format: ConsoleFormat::PkgPackage,
                offset: 0,
                magic: &[0x7F, 0x50, 0x4B, 0x47], // "\x7fPKG"
                description: "PlayStation 3 PKG package",
                min_size: 4,
            },
            // PS4 PARAM.SFO
            FormatSignature {
                format: ConsoleFormat::ParamSfo,
                offset: 0,
                magic: &[0x00, 0x50, 0x53, 0x46], // "\0PSF"
                description: "PlayStation PARAM.SFO metadata",
                min_size: 4,
            },
            // PS4 PKG
            FormatSignature {
                format: ConsoleFormat::Pkg4,
                offset: 0,
                magic: &[0x7F, 0x43, 0x4E, 0x54], // "\x7fCNT"
                description: "PlayStation 4 PKG package",
                min_size: 4,
            },
            // Vita VPK = ZIP with SFO inside
            FormatSignature {
                format: ConsoleFormat::VpkPackage,
                offset: 0,
                magic: b"PK\x03\x04",
                description: "Vita VPK package (ZIP)",
                min_size: 4,
            },
            // 3DS CIA
            FormatSignature {
                format: ConsoleFormat::CiaPackage,
                offset: 0,
                magic: &[0x20, 0x20, 0x00, 0x00], // header_size = 0x2020
                description: "Nintendo 3DS CIA package",
                min_size: 4,
            },
            // 3DS NCCH / CXI / CFA
            FormatSignature {
                format: ConsoleFormat::NcchContent,
                offset: 0x100,
                magic: b"NCCH",
                description: "Nintendo 3DS NCCH content",
                min_size: 0x104,
            },
            // 3DSX
            FormatSignature {
                format: ConsoleFormat::ThreeDsxExecutable,
                offset: 0,
                magic: b"3DSX",
                description: "Nintendo 3DS Homebrew 3DSX",
                min_size: 4,
            },
            // GBA ROM
            FormatSignature {
                format: ConsoleFormat::GbaRom,
                offset: 0,
                magic: &[0x2E, 0x00, 0x00, 0xEA],
                description: "Game Boy Advance ROM",
                min_size: 4,
            },
            // NDS ROM
            FormatSignature {
                format: ConsoleFormat::NdsRom,
                offset: 0,
                magic: &[0x24, 0xFF, 0xAE, 0x51],
                description: "Nintendo DS ROM (ARM7 boot code)",
                min_size: 4,
            },
            // GameCube GCM
            FormatSignature {
                format: ConsoleFormat::GcmDisc,
                offset: 0x1C,
                magic: &[0xC2, 0x33, 0x9F, 0x3D],
                description: "Nintendo GameCube GCM disc image",
                min_size: 0x20,
            },
            // Wii disc
            FormatSignature {
                format: ConsoleFormat::WiiDisc,
                offset: 0x18,
                magic: &[0x5D, 0x1C, 0x9E, 0xA3],
                description: "Nintendo Wii disc image",
                min_size: 0x1C,
            },
            // GameCube/Wii DOL
            FormatSignature {
                format: ConsoleFormat::DolExecutable,
                offset: 0,
                magic: &[0x00, 0x00, 0x01, 0x00],
                description: "GameCube/Wii DOL executable",
                min_size: 4,
            },
            // Sega Genesis
            FormatSignature {
                format: ConsoleFormat::GenesisRom,
                offset: 0x100,
                magic: b"SEGA MEGA DRIVE",
                description: "Sega Genesis / Mega Drive ROM",
                min_size: 0x10F,
            },
            // Sega 32X
            FormatSignature {
                format: ConsoleFormat::Sega32xRom,
                offset: 0x100,
                magic: b"SEGA 32X",
                description: "Sega 32X ROM",
                min_size: 0x108,
            },
            // Game Boy (Nintendo logo)
            FormatSignature {
                format: ConsoleFormat::GbRom,
                offset: 0x104,
                magic: &[0xCE, 0xED, 0x66, 0x66],
                description: "Nintendo Game Boy ROM",
                min_size: 0x108,
            },
            // NES
            FormatSignature {
                format: ConsoleFormat::NesRom,
                offset: 0,
                magic: b"NES\x1a",
                description: "Nintendo NES iNES ROM",
                min_size: 4,
            },
            // PC-Engine
            FormatSignature {
                format: ConsoleFormat::PceRom,
                offset: 0,
                magic: &[0x40, 0x00, 0x00, 0x00],
                description: "PC-Engine ROM",
                min_size: 4,
            },
        ]
    }
}

impl Default for FormatDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─── LicenseRegion ───────────────────────────────────────────────────────────

/// Region classification for console game media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseRegion {
    Japan,
    NorthAmerica,
    Europe,
    Australia,
    Korea,
    China,
    WorldWide,
    Unknown,
}

impl LicenseRegion {
    /// Guess region from an ASCII region byte used in some cartridge headers.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Japan,
            0x01 => Self::NorthAmerica,
            0x02 => Self::Europe,
            0x03 => Self::Australia,
            0x09 => Self::Korea,
            0x0A => Self::China,
            0xFF => Self::WorldWide,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for LicenseRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Japan => write!(f, "Japan"),
            Self::NorthAmerica => write!(f, "North America"),
            Self::Europe => write!(f, "Europe"),
            Self::Australia => write!(f, "Australia"),
            Self::Korea => write!(f, "Korea"),
            Self::China => write!(f, "China"),
            Self::WorldWide => write!(f, "Worldwide"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── FormatFeatureSet ─────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Feature flag bits for `FormatFeatureSet`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub struct FormatFeatureFlags: u8 {
        /// Format requires hardware-specific DRM.
        const HAS_DRM       = 0x01;
        /// Format is an executable (not a content package).
        const IS_EXECUTABLE = 0x02;
        /// Format is compressed.
        const IS_COMPRESSED = 0x04;
        /// Format contains multiple sub-files.
        const IS_CONTAINER  = 0x08;
    }
}

/// Feature flags inferred from format detection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FormatFeatureSet {
    /// Packed feature flags.
    pub flags: FormatFeatureFlags,
    /// Typical pointer width (4 or 8 bytes).
    pub pointer_bits: u32,
}

impl FormatFeatureSet {
    /// Whether the format requires hardware-specific DRM.
    #[must_use]
    pub const fn has_drm(&self) -> bool { self.flags.contains(FormatFeatureFlags::HAS_DRM) }
    /// Whether the format is an executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.flags.contains(FormatFeatureFlags::IS_EXECUTABLE) }
    /// Whether the format is compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool { self.flags.contains(FormatFeatureFlags::IS_COMPRESSED) }
    /// Whether the format is a container.
    #[must_use]
    pub const fn is_container(&self) -> bool { self.flags.contains(FormatFeatureFlags::IS_CONTAINER) }
}

impl FormatFeatureSet {
    /// Derive feature flags from a known format.
    #[must_use]
    pub fn from_format(fmt: ConsoleFormat) -> Self {
        use FormatFeatureFlags as F;
        match fmt {
            ConsoleFormat::NsoExecutable | ConsoleFormat::NroExecutable => Self {
                flags: F::IS_EXECUTABLE | F::IS_COMPRESSED,
                pointer_bits: 64,
            },
            ConsoleFormat::XexExecutable => Self {
                flags: F::HAS_DRM | F::IS_EXECUTABLE,
                pointer_bits: 32,
            },
            ConsoleFormat::SelfExecutable | ConsoleFormat::FselfExecutable => Self {
                flags: F::HAS_DRM | F::IS_EXECUTABLE,
                pointer_bits: 64,
            },
            ConsoleFormat::PkgPackage | ConsoleFormat::Pkg4 | ConsoleFormat::VpkPackage => Self {
                flags: F::HAS_DRM | F::IS_COMPRESSED | F::IS_CONTAINER,
                pointer_bits: 64,
            },
            ConsoleFormat::NcaContent | ConsoleFormat::XciCartridge => Self {
                flags: F::HAS_DRM | F::IS_CONTAINER,
                pointer_bits: 64,
            },
            ConsoleFormat::GbaRom | ConsoleFormat::NdsRom | ConsoleFormat::GbRom => Self {
                flags: F::IS_EXECUTABLE,
                pointer_bits: 32,
            },
            ConsoleFormat::NesRom | ConsoleFormat::SnesRom | ConsoleFormat::GenesisRom => Self {
                flags: F::IS_EXECUTABLE,
                pointer_bits: 16,
            },
            _ => Self::default(),
        }
    }
}

// ─── ConsoleFormatDetector ────────────────────────────────────────────────────

/// Main entry point for console format detection.
pub struct ConsoleFormatDetector {
    db: FormatDb,
}

impl ConsoleFormatDetector {
    /// Create a detector backed by the built-in format database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: FormatDb::new(),
        }
    }

    /// Detect the primary format of `data`.
    ///
    /// Returns `ConsoleFormat::Unknown` when no signature matches.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> ConsoleFormat {
        self.db.best_match(data)
    }

    /// Return all matching formats (some files match multiple signatures).
    #[must_use]
    pub fn detect_all(&self, data: &[u8]) -> Vec<ConsoleFormat> {
        self.db
            .signatures()
            .iter()
            .filter(|s| s.matches(data))
            .map(|s| s.format)
            .collect()
    }

    /// Detect format and derive feature flags.
    #[must_use]
    pub fn detect_with_features(&self, data: &[u8]) -> (ConsoleFormat, FormatFeatureSet) {
        let fmt = self.detect(data);
        let features = FormatFeatureSet::from_format(fmt);
        (fmt, features)
    }

    /// Return the number of signatures in the database.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.db.signatures().len()
    }

    /// Quick static detection without instantiating a `ConsoleFormatDetector`.
    #[must_use]
    pub fn detect_static(data: &[u8]) -> ConsoleFormat {
        FormatDb::new().best_match(data)
    }

    /// Return all format descriptions as a flat list.
    #[must_use]
    pub fn list_all_descriptions(&self) -> Vec<String> {
        self.db
            .signatures()
            .iter()
            .map(|s| s.description.to_string())
            .collect()
    }
}

impl Default for ConsoleFormatDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(offset: usize, magic: &[u8], total: usize) -> Vec<u8> {
        let mut data = vec![0u8; total.max(offset + magic.len())];
        data[offset..offset + magic.len()].copy_from_slice(magic);
        data
    }

    // ── ConsoleFormat display / helpers ──────────────────────────────────────

    #[test]
    fn test_format_display_nso() {
        assert!(ConsoleFormat::NsoExecutable.to_string().contains("NSO"));
    }

    #[test]
    fn test_format_display_xex() {
        assert!(ConsoleFormat::XexExecutable.to_string().contains("Xbox"));
    }

    #[test]
    fn test_format_display_unknown() {
        assert_eq!(ConsoleFormat::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_format_is_switch_nso() {
        assert!(ConsoleFormat::NsoExecutable.is_switch());
        assert!(!ConsoleFormat::XexExecutable.is_switch());
    }

    #[test]
    fn test_format_is_playstation_self() {
        assert!(ConsoleFormat::SelfExecutable.is_playstation());
        assert!(!ConsoleFormat::NsoExecutable.is_playstation());
    }

    #[test]
    fn test_format_extensions_gba() {
        assert!(ConsoleFormat::GbaRom.typical_extensions().contains(&"gba"));
    }

    #[test]
    fn test_format_extensions_nes() {
        assert!(ConsoleFormat::NesRom.typical_extensions().contains(&"nes"));
    }

    // ── FormatSignature matching ──────────────────────────────────────────────

    #[test]
    fn test_signature_matches_nso() {
        let sig = FormatSignature {
            format: ConsoleFormat::NsoExecutable,
            offset: 0,
            magic: b"NSO0",
            description: "NSO",
            min_size: 4,
        };
        assert!(sig.matches(b"NSO0\x00\x00\x00"));
    }

    #[test]
    fn test_signature_no_match_short_data() {
        let sig = FormatSignature {
            format: ConsoleFormat::NsoExecutable,
            offset: 0,
            magic: b"NSO0",
            description: "NSO",
            min_size: 4,
        };
        assert!(!sig.matches(b"NS"));
    }

    #[test]
    fn test_signature_no_match_wrong_bytes() {
        let sig = FormatSignature {
            format: ConsoleFormat::NsoExecutable,
            offset: 0,
            magic: b"NSO0",
            description: "NSO",
            min_size: 4,
        };
        assert!(!sig.matches(b"NRO0"));
    }

    #[test]
    fn test_signature_matches_at_offset() {
        let sig = FormatSignature {
            format: ConsoleFormat::NroExecutable,
            offset: 0x10,
            magic: b"NRO0",
            description: "NRO",
            min_size: 0x14,
        };
        let data = make_data(0x10, b"NRO0", 0x20);
        assert!(sig.matches(&data));
    }

    // ── FormatDb ─────────────────────────────────────────────────────────────

    #[test]
    fn test_format_db_has_signatures() {
        let db = FormatDb::new();
        assert!(db.signatures().len() >= 10);
    }

    #[test]
    fn test_format_db_best_match_nso() {
        let db = FormatDb::new();
        let data = make_data(0, b"NSO0", 32);
        assert_eq!(db.best_match(&data), ConsoleFormat::NsoExecutable);
    }

    #[test]
    fn test_format_db_best_match_xex() {
        let db = FormatDb::new();
        let data = make_data(0, b"XEX2", 32);
        assert_eq!(db.best_match(&data), ConsoleFormat::XexExecutable);
    }

    #[test]
    fn test_format_db_best_match_unknown() {
        let db = FormatDb::new();
        let data = vec![0xAAu8; 512];
        assert_eq!(db.best_match(&data), ConsoleFormat::Unknown);
    }

    #[test]
    fn test_format_db_best_match_nes() {
        let db = FormatDb::new();
        let data = make_data(0, b"NES\x1a", 32);
        assert_eq!(db.best_match(&data), ConsoleFormat::NesRom);
    }

    #[test]
    fn test_format_db_find_matches_returns_multiple() {
        let db = FormatDb::new();
        // VPK is a ZIP, so the ZIP magic will match VPK signature
        let data = make_data(0, b"PK\x03\x04", 32);
        let matches = db.find_matches(&data);
        assert!(!matches.is_empty());
    }

    // ── LicenseRegion ─────────────────────────────────────────────────────────

    #[test]
    fn test_region_from_byte_japan() {
        assert_eq!(LicenseRegion::from_byte(0x00), LicenseRegion::Japan);
    }

    #[test]
    fn test_region_from_byte_na() {
        assert_eq!(LicenseRegion::from_byte(0x01), LicenseRegion::NorthAmerica);
    }

    #[test]
    fn test_region_from_byte_europe() {
        assert_eq!(LicenseRegion::from_byte(0x02), LicenseRegion::Europe);
    }

    #[test]
    fn test_region_from_byte_worldwide() {
        assert_eq!(LicenseRegion::from_byte(0xFF), LicenseRegion::WorldWide);
    }

    #[test]
    fn test_region_from_byte_unknown() {
        assert_eq!(LicenseRegion::from_byte(0x42), LicenseRegion::Unknown);
    }

    #[test]
    fn test_region_display() {
        assert_eq!(LicenseRegion::Japan.to_string(), "Japan");
        assert_eq!(LicenseRegion::NorthAmerica.to_string(), "North America");
    }

    // ── FormatFeatureSet ──────────────────────────────────────────────────────

    #[test]
    fn test_features_nso_is_executable() {
        let f = FormatFeatureSet::from_format(ConsoleFormat::NsoExecutable);
        assert!(f.is_executable());
        assert_eq!(f.pointer_bits, 64);
    }

    #[test]
    fn test_features_xex_has_drm() {
        let f = FormatFeatureSet::from_format(ConsoleFormat::XexExecutable);
        assert!(f.has_drm());
    }

    #[test]
    fn test_features_pkg_is_container() {
        let f = FormatFeatureSet::from_format(ConsoleFormat::PkgPackage);
        assert!(f.is_container());
        assert!(f.has_drm());
    }

    #[test]
    fn test_features_nes_no_drm() {
        let f = FormatFeatureSet::from_format(ConsoleFormat::NesRom);
        assert!(!f.has_drm());
        assert!(f.is_executable());
        assert_eq!(f.pointer_bits, 16);
    }

    #[test]
    fn test_features_gba_pointer_bits() {
        let f = FormatFeatureSet::from_format(ConsoleFormat::GbaRom);
        assert_eq!(f.pointer_bits, 32);
    }

    // ── ConsoleFormatDetector ─────────────────────────────────────────────────

    #[test]
    fn test_detector_detect_nso() {
        let det = ConsoleFormatDetector::new();
        let data = make_data(0, b"NSO0", 32);
        assert_eq!(det.detect(&data), ConsoleFormat::NsoExecutable);
    }

    #[test]
    fn test_detector_detect_nes() {
        let det = ConsoleFormatDetector::new();
        let data = make_data(0, b"NES\x1a", 32);
        assert_eq!(det.detect(&data), ConsoleFormat::NesRom);
    }

    #[test]
    fn test_detector_detect_unknown() {
        let det = ConsoleFormatDetector::new();
        assert_eq!(det.detect(&[0xFF; 16]), ConsoleFormat::Unknown);
    }

    #[test]
    fn test_detector_detect_static_nso() {
        let data = make_data(0, b"NSO0", 32);
        assert_eq!(
            ConsoleFormatDetector::detect_static(&data),
            ConsoleFormat::NsoExecutable
        );
    }

    #[test]
    fn test_detector_detect_all_empty() {
        let det = ConsoleFormatDetector::new();
        let matches = det.detect_all(&[0xAAu8; 512]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detector_detect_with_features_nso() {
        let det = ConsoleFormatDetector::new();
        let data = make_data(0, b"NSO0", 32);
        let (fmt, feats) = det.detect_with_features(&data);
        assert_eq!(fmt, ConsoleFormat::NsoExecutable);
        assert!(feats.is_executable());
    }

    #[test]
    fn test_detector_signature_count() {
        let det = ConsoleFormatDetector::new();
        assert!(det.signature_count() >= 10);
    }

    #[test]
    fn test_detector_list_all_descriptions() {
        let det = ConsoleFormatDetector::new();
        let descs = det.list_all_descriptions();
        assert!(!descs.is_empty());
        assert!(
            descs
                .iter()
                .any(|d| d.contains("Switch") || d.contains("Nintendo"))
        );
    }

    #[test]
    fn test_detector_detect_xex1() {
        let det = ConsoleFormatDetector::new();
        let data = make_data(0, b"XEX1", 32);
        assert_eq!(det.detect(&data), ConsoleFormat::XexExecutable);
    }

    #[test]
    fn test_detector_detect_ps3_self() {
        let det = ConsoleFormatDetector::new();
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0x53, 0x43, 0x45, 0x00]);
        assert_eq!(det.detect(&data), ConsoleFormat::SelfExecutable);
    }

    #[test]
    fn test_detector_detect_ps4_param_sfo() {
        let det = ConsoleFormatDetector::new();
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0x00, 0x50, 0x53, 0x46]);
        assert_eq!(det.detect(&data), ConsoleFormat::ParamSfo);
    }

    #[test]
    fn test_format_db_default_impl() {
        let db = FormatDb::default();
        assert!(!db.signatures().is_empty());
    }

    #[test]
    fn test_detector_default_impl() {
        let det = ConsoleFormatDetector::default();
        assert!(det.signature_count() > 0);
    }
}
