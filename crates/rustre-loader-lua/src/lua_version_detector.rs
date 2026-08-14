//! Lua bytecode version detector.
//!
//! Determines whether bytecode is Lua 5.0/5.1/5.2/5.3/5.4 or `LuaJIT` 2.x
//! based on magic bytes and header field layout.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── LuaVersion ──────────────────────────────────────────────────────────────

/// Lua bytecode version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LuaVersion {
    Lua50,
    Lua51,
    Lua52,
    Lua53,
    Lua54,
    LuaJIT20,
    LuaJIT21,
    Unknown,
}

impl fmt::Display for LuaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lua50 => write!(f, "Lua 5.0"),
            Self::Lua51 => write!(f, "Lua 5.1"),
            Self::Lua52 => write!(f, "Lua 5.2"),
            Self::Lua53 => write!(f, "Lua 5.3"),
            Self::Lua54 => write!(f, "Lua 5.4"),
            Self::LuaJIT20 => write!(f, "LuaJIT 2.0"),
            Self::LuaJIT21 => write!(f, "LuaJIT 2.1"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl LuaVersion {
    /// Return the version byte as it appears in the header.
    #[must_use]
    pub const fn version_byte(self) -> Option<u8> {
        match self {
            Self::Lua50 => Some(0x50),
            Self::Lua51 => Some(0x51),
            Self::Lua52 => Some(0x52),
            Self::Lua53 => Some(0x53),
            Self::Lua54 => Some(0x54),
            Self::LuaJIT20 | Self::LuaJIT21 | Self::Unknown => None,
        }
    }

    /// Returns `true` if this is a `LuaJIT` variant.
    #[must_use]
    pub const fn is_luajit(self) -> bool {
        matches!(self, Self::LuaJIT20 | Self::LuaJIT21)
    }

    /// Major version number (e.g. 5 for Lua 5.4, 2 for `LuaJIT` 2.x).
    #[must_use]
    pub const fn major(self) -> u8 {
        match self {
            Self::Lua50 | Self::Lua51 | Self::Lua52 | Self::Lua53 | Self::Lua54 => 5,
            Self::LuaJIT20 | Self::LuaJIT21 => 2,
            Self::Unknown => 0,
        }
    }

    /// Minor version number (e.g. 4 for Lua 5.4, 1 for `LuaJIT` 2.1).
    #[must_use]
    pub const fn minor(self) -> u8 {
        match self {
            Self::Lua50 | Self::LuaJIT20 | Self::Unknown => 0,
            Self::Lua51 | Self::LuaJIT21 => 1,
            Self::Lua52 => 2,
            Self::Lua53 => 3,
            Self::Lua54 => 4,
        }
    }

    /// Returns `true` if integer arithmetic is the default (5.3+).
    #[must_use]
    pub const fn has_integer_type(self) -> bool {
        matches!(self, Self::Lua53 | Self::Lua54)
    }

    /// Returns `true` if the version supports bitwise operators natively.
    #[must_use]
    pub const fn has_bitwise_ops(self) -> bool {
        matches!(
            self,
            Self::Lua53 | Self::Lua54 | Self::LuaJIT20 | Self::LuaJIT21
        )
    }

    /// Returns `true` if the version supports goto.
    #[must_use]
    pub const fn has_goto(self) -> bool {
        matches!(self, Self::Lua52 | Self::Lua53 | Self::Lua54)
    }
}

// ─── VersionSignature ────────────────────────────────────────────────────────

/// Magic bytes + header fields that identify a Lua version.
#[derive(Debug, Clone)]
pub struct VersionSignature {
    pub version: LuaVersion,
    /// Magic prefix (first 4 bytes: `\x1bLua` or `\x1bLJ`).
    pub magic: &'static [u8],
    /// Version byte offset in the file (usually byte 4).
    pub version_offset: usize,
    /// Expected version byte (for Lua) or feature byte (for `LuaJIT`).
    pub version_byte: u8,
    /// Minimum expected header size in bytes.
    pub min_header_size: usize,
    /// Human-readable description.
    pub description: &'static str,
}

impl VersionSignature {
    /// Returns `true` if `data` matches this signature.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.min_header_size {
            return false;
        }
        if !data.starts_with(self.magic) {
            return false;
        }
        data.get(self.version_offset).copied() == Some(self.version_byte)
    }
}

/// All known version signatures.
#[must_use]
pub fn all_signatures() -> Vec<VersionSignature> {
    vec![
        // LuaJIT 2.1 — magic \x1bLJ, version byte 2
        VersionSignature {
            version: LuaVersion::LuaJIT21,
            magic: b"\x1bLJ",
            version_offset: 3,
            version_byte: 2,
            min_header_size: 5,
            description: "LuaJIT 2.1 bytecode",
        },
        // LuaJIT 2.0 — magic \x1bLJ, version byte 1
        VersionSignature {
            version: LuaVersion::LuaJIT20,
            magic: b"\x1bLJ",
            version_offset: 3,
            version_byte: 1,
            min_header_size: 5,
            description: "LuaJIT 2.0 bytecode",
        },
        // Lua 5.4
        VersionSignature {
            version: LuaVersion::Lua54,
            magic: b"\x1bLua",
            version_offset: 4,
            version_byte: 0x54,
            min_header_size: 12,
            description: "Lua 5.4 bytecode",
        },
        // Lua 5.3
        VersionSignature {
            version: LuaVersion::Lua53,
            magic: b"\x1bLua",
            version_offset: 4,
            version_byte: 0x53,
            min_header_size: 12,
            description: "Lua 5.3 bytecode",
        },
        // Lua 5.2
        VersionSignature {
            version: LuaVersion::Lua52,
            magic: b"\x1bLua",
            version_offset: 4,
            version_byte: 0x52,
            min_header_size: 12,
            description: "Lua 5.2 bytecode",
        },
        // Lua 5.1
        VersionSignature {
            version: LuaVersion::Lua51,
            magic: b"\x1bLua",
            version_offset: 4,
            version_byte: 0x51,
            min_header_size: 12,
            description: "Lua 5.1 bytecode",
        },
        // Lua 5.0
        VersionSignature {
            version: LuaVersion::Lua50,
            magic: b"\x1bLua",
            version_offset: 4,
            version_byte: 0x50,
            min_header_size: 12,
            description: "Lua 5.0 bytecode",
        },
    ]
}

// ─── LuaFeatureSet ────────────────────────────────────────────────────────────

/// Feature flags for a specific Lua version.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LuaFeatureSet {
    pub has_goto: bool,
    pub has_bitwise_ops: bool,
    pub has_integer_type: bool,
    pub has_closures: bool,
    pub has_metatables: bool,
    pub has_coroutines: bool,
    pub has_vararg: bool,
    pub has_multiple_assignment: bool,
    pub has_string_coercion: bool,
    pub has_jit: bool,
    pub has_ffi: bool,
    pub opcode_count: u32,
}

impl LuaFeatureSet {
    /// Build from a version enum.
    #[must_use]
    pub fn for_version(ver: LuaVersion) -> Self {
        let base = Self {
            has_closures: true,
            has_metatables: true,
            has_coroutines: true,
            has_vararg: true,
            has_multiple_assignment: true,
            has_string_coercion: true,
            ..Default::default()
        };
        match ver {
            LuaVersion::Lua50 | LuaVersion::Lua51 => Self {
                opcode_count: 38,
                ..base
            },
            LuaVersion::Lua52 => Self {
                has_goto: true,
                opcode_count: 40,
                ..base
            },
            LuaVersion::Lua53 => Self {
                has_goto: true,
                has_bitwise_ops: true,
                has_integer_type: true,
                opcode_count: 47,
                ..base
            },
            LuaVersion::Lua54 => Self {
                has_goto: true,
                has_bitwise_ops: true,
                has_integer_type: true,
                opcode_count: 82,
                ..base
            },
            LuaVersion::LuaJIT20 | LuaVersion::LuaJIT21 => Self {
                has_bitwise_ops: true,
                has_jit: true,
                has_ffi: true,
                opcode_count: 97,
                ..base
            },
            LuaVersion::Unknown => Self::default(),
        }
    }
}

// ─── VersionReport ────────────────────────────────────────────────────────────

/// Result of Lua version detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionReport {
    pub version: LuaVersion,
    pub description: String,
    pub features: LuaFeatureSet,
    pub magic_bytes: Vec<u8>,
    pub header_size: usize,
    pub endianness: Option<String>,
    pub int_size: Option<u8>,
    pub size_t_size: Option<u8>,
    pub instruction_size: Option<u8>,
    pub number_size: Option<u8>,
}

impl VersionReport {
    /// Build from detection result.
    #[must_use]
    pub fn from_detection(version: LuaVersion, data: &[u8]) -> Self {
        let description = match version {
            LuaVersion::Lua50 => "Lua 5.0 bytecode".to_string(),
            LuaVersion::Lua51 => "Lua 5.1 bytecode".to_string(),
            LuaVersion::Lua52 => "Lua 5.2 bytecode".to_string(),
            LuaVersion::Lua53 => "Lua 5.3 bytecode".to_string(),
            LuaVersion::Lua54 => "Lua 5.4 bytecode".to_string(),
            LuaVersion::LuaJIT20 => "LuaJIT 2.0 bytecode".to_string(),
            LuaVersion::LuaJIT21 => "LuaJIT 2.1 bytecode".to_string(),
            LuaVersion::Unknown => "Unknown bytecode format".to_string(),
        };
        let features = LuaFeatureSet::for_version(version);
        let magic_bytes = data.get(..4).unwrap_or(&[]).to_vec();

        // Parse standard Lua header fields (Lua 5.x)
        let (endianness, int_size, size_t_size, instruction_size, number_size) =
            if !version.is_luajit() && data.len() >= 12 {
                let e = data.get(6).map(|&b| {
                    if b == 1 {
                        "little".into()
                    } else {
                        "big".into()
                    }
                });
                let is = data.get(7).copied();
                let ss = data.get(8).copied();
                let ins = data.get(9).copied();
                let ns = data.get(10).copied();
                (e, is, ss, ins, ns)
            } else {
                (None, None, None, None, None)
            };

        Self {
            version,
            description,
            features,
            magic_bytes,
            header_size: 12,
            endianness,
            int_size,
            size_t_size,
            instruction_size,
            number_size,
        }
    }
}

impl fmt::Display for VersionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} int={} inst={} endian={}",
            self.version,
            self.int_size.map_or_else(|| "?".into(), |n| n.to_string()),
            self.instruction_size
                .map_or_else(|| "?".into(), |n| n.to_string()),
            self.endianness.as_deref().unwrap_or("?"),
        )
    }
}

// ─── AutoDecoder ─────────────────────────────────────────────────────────────

/// Picks the right decoder for a byte slice and returns a version report.
#[derive(Debug, Default)]
pub struct AutoDecoder;

impl AutoDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect and return the version report for `data`.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> VersionReport {
        let version = LuaVersionDetector::new().detect(data);
        VersionReport::from_detection(version, data)
    }

    /// Returns `true` if `data` is any known Lua/LuaJIT bytecode.
    #[must_use]
    pub fn is_lua_bytecode(data: &[u8]) -> bool {
        data.starts_with(b"\x1bLua") || data.starts_with(b"\x1bLJ")
    }
}

// ─── LuaVersionDetector ──────────────────────────────────────────────────────

/// Main version detector.
#[derive(Debug, Default)]
pub struct LuaVersionDetector {
    signatures: Vec<VersionSignature>,
}

impl LuaVersionDetector {
    /// Create with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: all_signatures(),
        }
    }

    /// Detect the version of `data`.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> LuaVersion {
        for sig in &self.signatures {
            if sig.matches(data) {
                return sig.version;
            }
        }
        LuaVersion::Unknown
    }

    /// Return all matching signatures.
    #[must_use]
    pub fn detect_all(&self, data: &[u8]) -> Vec<LuaVersion> {
        self.signatures
            .iter()
            .filter(|s| s.matches(data))
            .map(|s| s.version)
            .collect()
    }

    /// Return the full version report.
    #[must_use]
    pub fn report(&self, data: &[u8]) -> VersionReport {
        let version = self.detect(data);
        VersionReport::from_detection(version, data)
    }

    /// Number of registered signatures.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lua_header(version: u8) -> Vec<u8> {
        let mut h = vec![0u8; 16];
        h[..4].copy_from_slice(b"\x1bLua");
        h[4] = version;
        h[5] = 0; // format
        h[6] = 1; // little-endian
        h[7] = 4; // int size
        h[8] = 4; // size_t
        h[9] = 4; // instruction size
        h[10] = 8; // number size
        h[11] = 0; // is_integral
        h
    }

    fn luajit_header(version: u8) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[..3].copy_from_slice(b"\x1bLJ");
        h[3] = version;
        h[4] = 0x02; // flags
        h
    }

    // ── LuaVersion ────────────────────────────────────────────────────────────

    #[test]
    fn test_lua_version_display() {
        assert_eq!(LuaVersion::Lua51.to_string(), "Lua 5.1");
        assert_eq!(LuaVersion::LuaJIT21.to_string(), "LuaJIT 2.1");
    }

    #[test]
    fn test_lua_version_byte() {
        assert_eq!(LuaVersion::Lua53.version_byte(), Some(0x53));
        assert_eq!(LuaVersion::LuaJIT20.version_byte(), None);
    }

    #[test]
    fn test_lua_version_is_luajit() {
        assert!(LuaVersion::LuaJIT20.is_luajit());
        assert!(!LuaVersion::Lua53.is_luajit());
    }

    #[test]
    fn test_lua_version_has_integer_type() {
        assert!(LuaVersion::Lua53.has_integer_type());
        assert!(LuaVersion::Lua54.has_integer_type());
        assert!(!LuaVersion::Lua52.has_integer_type());
    }

    #[test]
    fn test_lua_version_has_bitwise() {
        assert!(LuaVersion::LuaJIT20.has_bitwise_ops());
        assert!(!LuaVersion::Lua51.has_bitwise_ops());
    }

    #[test]
    fn test_lua_version_has_goto() {
        assert!(LuaVersion::Lua52.has_goto());
        assert!(!LuaVersion::Lua51.has_goto());
    }

    // ── VersionSignature ──────────────────────────────────────────────────────

    #[test]
    fn test_version_signature_matches_lua51() {
        let sigs = all_signatures();
        let sig = sigs
            .iter()
            .find(|s| s.version == LuaVersion::Lua51)
            .unwrap();
        assert!(sig.matches(&lua_header(0x51)));
    }

    #[test]
    fn test_version_signature_no_match_wrong_version() {
        let sigs = all_signatures();
        let sig = sigs
            .iter()
            .find(|s| s.version == LuaVersion::Lua51)
            .unwrap();
        assert!(!sig.matches(&lua_header(0x52)));
    }

    #[test]
    fn test_version_signature_matches_luajit20() {
        let sigs = all_signatures();
        let sig = sigs
            .iter()
            .find(|s| s.version == LuaVersion::LuaJIT20)
            .unwrap();
        assert!(sig.matches(&luajit_header(1)));
    }

    #[test]
    fn test_version_signature_no_match_short_data() {
        let sigs = all_signatures();
        let sig = sigs
            .iter()
            .find(|s| s.version == LuaVersion::Lua51)
            .unwrap();
        assert!(!sig.matches(b"\x1bLu"));
    }

    // ── LuaFeatureSet ─────────────────────────────────────────────────────────

    #[test]
    fn test_feature_set_lua54_opcode_count() {
        let f = LuaFeatureSet::for_version(LuaVersion::Lua54);
        assert_eq!(f.opcode_count, 82);
    }

    #[test]
    fn test_feature_set_lua51_has_closures() {
        let f = LuaFeatureSet::for_version(LuaVersion::Lua51);
        assert!(f.has_closures);
        assert!(!f.has_goto);
    }

    #[test]
    fn test_feature_set_luajit_has_jit() {
        let f = LuaFeatureSet::for_version(LuaVersion::LuaJIT20);
        assert!(f.has_jit);
        assert!(f.has_ffi);
    }

    #[test]
    fn test_feature_set_unknown_default() {
        let f = LuaFeatureSet::for_version(LuaVersion::Unknown);
        assert_eq!(f.opcode_count, 0);
    }

    // ── LuaVersionDetector ────────────────────────────────────────────────────

    #[test]
    fn test_detector_detect_lua51() {
        let det = LuaVersionDetector::new();
        assert_eq!(det.detect(&lua_header(0x51)), LuaVersion::Lua51);
    }

    #[test]
    fn test_detector_detect_lua54() {
        let det = LuaVersionDetector::new();
        assert_eq!(det.detect(&lua_header(0x54)), LuaVersion::Lua54);
    }

    #[test]
    fn test_detector_detect_luajit21() {
        let det = LuaVersionDetector::new();
        assert_eq!(det.detect(&luajit_header(2)), LuaVersion::LuaJIT21);
    }

    #[test]
    fn test_detector_detect_unknown() {
        let det = LuaVersionDetector::new();
        assert_eq!(det.detect(b"random data"), LuaVersion::Unknown);
    }

    #[test]
    fn test_detector_signature_count() {
        let det = LuaVersionDetector::new();
        assert!(det.signature_count() >= 7);
    }

    #[test]
    fn test_detector_report_version() {
        let det = LuaVersionDetector::new();
        let r = det.report(&lua_header(0x52));
        assert_eq!(r.version, LuaVersion::Lua52);
    }

    // ── VersionReport ─────────────────────────────────────────────────────────

    #[test]
    fn test_version_report_little_endian() {
        let r = VersionReport::from_detection(LuaVersion::Lua53, &lua_header(0x53));
        assert_eq!(r.endianness.as_deref(), Some("little"));
    }

    #[test]
    fn test_version_report_int_size() {
        let r = VersionReport::from_detection(LuaVersion::Lua51, &lua_header(0x51));
        assert_eq!(r.int_size, Some(4));
    }

    #[test]
    fn test_version_report_display() {
        let r = VersionReport::from_detection(LuaVersion::Lua54, &lua_header(0x54));
        let s = r.to_string();
        assert!(s.contains("Lua 5.4"));
    }

    #[test]
    fn test_version_report_serialization() {
        let r = VersionReport::from_detection(LuaVersion::Lua52, &lua_header(0x52));
        let json = serde_json::to_string(&r).unwrap();
        let back: VersionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, LuaVersion::Lua52);
    }

    // ── AutoDecoder ───────────────────────────────────────────────────────────

    #[test]
    fn test_auto_decoder_is_lua_bytecode_true() {
        assert!(AutoDecoder::is_lua_bytecode(b"\x1bLua\x54"));
        assert!(AutoDecoder::is_lua_bytecode(b"\x1bLJ\x02"));
    }

    #[test]
    fn test_auto_decoder_is_lua_bytecode_false() {
        assert!(!AutoDecoder::is_lua_bytecode(b"PK\x03\x04"));
    }

    #[test]
    fn test_auto_decoder_detect_lua53() {
        let ad = AutoDecoder::new();
        let r = ad.detect(&lua_header(0x53));
        assert_eq!(r.version, LuaVersion::Lua53);
    }

    #[test]
    fn test_all_signatures_not_empty() {
        assert!(!all_signatures().is_empty());
    }
    #[test]
    fn test_lua_version_lua50_byte() {
        assert_eq!(LuaVersion::Lua50.version_byte(), Some(0x50));
    }
    #[test]
    fn test_lua_version_lua52_byte() {
        assert_eq!(LuaVersion::Lua52.version_byte(), Some(0x52));
    }
    #[test]
    fn test_lua_version_major_lua54() {
        assert_eq!(LuaVersion::Lua54.major(), 5);
    }
    #[test]
    fn test_lua_version_minor_lua54() {
        assert_eq!(LuaVersion::Lua54.minor(), 4);
    }
    #[test]
    fn test_feature_set_lua52_has_goto() {
        let f = LuaFeatureSet::for_version(LuaVersion::Lua52);
        assert!(f.has_goto);
    }
    #[test]
    fn test_feature_set_lua51_no_integer() {
        let f = LuaFeatureSet::for_version(LuaVersion::Lua51);
        assert!(!f.has_integer_type);
    }
    #[test]
    fn test_feature_set_lua53_has_coroutines() {
        let f = LuaFeatureSet::for_version(LuaVersion::Lua53);
        assert!(f.has_coroutines);
    }
    #[test]
    fn test_detector_detect_lua50() {
        let det = LuaVersionDetector::new();
        assert_eq!(det.detect(&lua_header(0x50)), LuaVersion::Lua50);
    }
    #[test]
    fn test_version_report_instruction_size() {
        let r = VersionReport::from_detection(LuaVersion::Lua53, &lua_header(0x53));
        assert_eq!(r.instruction_size, Some(4));
    }
    #[test]
    fn test_version_report_is_utf8_field() {
        let r = VersionReport::from_detection(LuaVersion::Lua51, &lua_header(0x51));
        let _ = r.features.has_closures;
    }
    #[test]
    fn test_auto_decoder_is_luajit() {
        assert!(AutoDecoder::is_lua_bytecode(b"\x1bLJ\x02"));
    }
    #[test]
    fn test_version_report_luajit_no_endian() {
        let r = VersionReport::from_detection(LuaVersion::LuaJIT20, &luajit_header(1));
        assert!(r.endianness.is_none());
    }
}
