//! `rustre-loader-android::vdex_parser`
//!
//! Android VDEX (Verified DEX) format parser.
//!
//! VDEX is the container used by ART to store pre-verified DEX files alongside
//! quickening information and verifier dependency data.  This module parses
//! VDEX versions 6, 10, 18, and 21 as found in the AOSP source tree.
//!
//! # References
//! - AOSP `art/runtime/vdex_file.h`
//! - AOSP `art/dex2oat/linker/oat_writer.cc`

use crate::AndroidLoaderError;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// VdexVersion
// ─────────────────────────────────────────────────────────────────────────────

/// Known VDEX file format versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VdexVersion {
    /// Android 8.0 (Oreo) — version 006.
    V006,
    /// Android 9 (Pie) — version 010.
    V010,
    /// Android 10 (Q) — version 018.
    V018,
    /// Android 11 (R) and later — version 021.
    V021,
    /// Unknown / future version stored as raw bytes.
    Unknown([u8; 4]),
}

impl VdexVersion {
    /// Parse a 4-byte version field.
    #[must_use]
    pub fn from_bytes(v: [u8; 4]) -> Self {
        // Version bytes are ASCII digits followed by a NUL: e.g. b"006\0".
        let s = std::str::from_utf8(&v[..3]).unwrap_or("---");
        match s {
            "006" => Self::V006,
            "010" => Self::V010,
            "018" => Self::V018,
            "021" => Self::V021,
            _ => Self::Unknown(v),
        }
    }

    /// Return the canonical 3-character ASCII version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::V006 => "006",
            Self::V010 => "010",
            Self::V018 => "018",
            Self::V021 => "021",
            Self::Unknown(b) => std::str::from_utf8(&b[..3]).unwrap_or("???"),
        }
    }

    /// Integer representation of the version number.
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        self.as_str().parse().unwrap_or(0)
    }

    /// Returns `true` when the version is one of the known / supported ones.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for VdexVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VdexHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed VDEX file header (all known versions).
///
/// Layout (AOSP `VdexFile::Header`):
/// ```text
/// [0..4]   magic    — b"vdex"
/// [4..8]   version  — e.g. b"018\0"
/// [8..12]  number_of_dex_files
/// [12..16] dex_section_size
/// [16..20] dex_shared_data_size    (version >= 021)
/// [20..24] verifier_deps_size
/// [24..28] quicken_info_size       (version <= 018)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdexHeader {
    /// Magic bytes (`b"vdex"`).
    pub magic: [u8; 4],
    /// Parsed version.
    pub version: VdexVersion,
    /// Number of embedded DEX files.
    pub number_of_dex_files: u32,
    /// Total byte size of all embedded DEX data.
    pub dex_section_size: u32,
    /// Shared DEX data size (version >= 021, else 0).
    pub dex_shared_data_size: u32,
    /// Size of the verifier dependency section.
    pub verifier_deps_size: u32,
    /// Size of the quickening info section (version <= 018, else 0).
    pub quicken_info_size: u32,
}

impl VdexHeader {
    /// Minimum supported header byte length.
    pub const MIN_HEADER_SIZE: usize = 28;

    /// Parse a VDEX header.
    ///
    /// # Errors
    ///
    /// Returns [`AndroidLoaderError::TruncatedHeader`] when `data` is shorter
    /// than 28 bytes, or [`AndroidLoaderError::InvalidMagic`] when the magic
    /// does not equal `b"vdex"`.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return Err(AndroidLoaderError::TruncatedHeader);
        }
        if &data[0..4] != b"vdex" {
            return Err(AndroidLoaderError::InvalidMagic);
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        let ver_raw: [u8; 4] = data[4..8].try_into().unwrap();
        let version = VdexVersion::from_bytes(ver_raw);

        let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());

        let number_of_dex_files = rd32(8);
        let dex_section_size = rd32(12);
        let dex_shared_data_size = rd32(16);
        let verifier_deps_size = rd32(20);
        let quicken_info_size = rd32(24);

        Ok(Self {
            magic,
            version,
            number_of_dex_files,
            dex_section_size,
            dex_shared_data_size,
            verifier_deps_size,
            quicken_info_size,
        })
    }

    /// Offset in `data` at which the first embedded DEX file begins.
    ///
    /// The VDEX header is followed by `number_of_dex_files` u32 checksum
    /// entries, then the raw DEX data.
    #[must_use]
    pub fn dex_data_offset(&self) -> usize {
        (self.number_of_dex_files as usize)
            .checked_mul(4)
            .and_then(|n| Self::MIN_HEADER_SIZE.checked_add(n))
            .unwrap_or(usize::MAX)
    }

    /// Total header + checksum array size.
    #[must_use]
    pub fn total_header_size(&self) -> usize {
        self.dex_data_offset()
    }

    /// Returns `true` when this version carries quickening info.
    #[must_use]
    pub fn has_quickening_info(&self) -> bool {
        self.version.as_u32() <= 18 && self.quicken_info_size > 0
    }

    /// Returns `true` when this version carries shared DEX data.
    #[must_use]
    pub fn has_shared_dex_data(&self) -> bool {
        self.version.as_u32() >= 21 && self.dex_shared_data_size > 0
    }
}

impl fmt::Display for VdexHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VDEX v{} ndex={} dex_size={} deps={} quicken={}",
            self.version,
            self.number_of_dex_files,
            self.dex_section_size,
            self.verifier_deps_size,
            self.quicken_info_size,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VdexDexFile
// ─────────────────────────────────────────────────────────────────────────────

/// Reference to a single embedded DEX file within a VDEX container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdexDexFile {
    /// Index of this DEX file within the VDEX.
    pub index: usize,
    /// Byte offset of the DEX data relative to the start of the VDEX.
    pub vdex_offset: usize,
    /// Adler-32 checksum stored in the VDEX checksum array.
    pub stored_checksum: u32,
    /// Size of the DEX data in bytes (from the DEX `file_size` field).
    pub size: usize,
}

impl VdexDexFile {
    /// Returns `true` when `stored_checksum` matches the Adler-32 of `data`.
    #[must_use]
    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        let end = self.vdex_offset + self.size;
        if end > data.len() || self.size < 12 {
            return false;
        }
        let dex_slice = &data[self.vdex_offset..end];
        let computed = crate::adler32(&dex_slice[12..]);
        computed == self.stored_checksum
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VdexSections
// ─────────────────────────────────────────────────────────────────────────────

/// Logical sections of a parsed VDEX file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdexSections {
    /// DEX files embedded in the VDEX.
    pub dex_files: Vec<VdexDexFile>,
    /// Byte range of the verifier dependency section.
    pub verifier_deps_range: Option<(usize, usize)>,
    /// Byte range of the quickening info section (if present).
    pub quickening_info_range: Option<(usize, usize)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifierDeps
// ─────────────────────────────────────────────────────────────────────────────

/// Type-check information from the VDEX verifier dependency section.
///
/// The verifier deps store resolved type-assignment checks that ART validated
/// at install time so they don't need to be re-checked at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierDeps {
    /// Number of DEX files this dep block covers.
    pub dex_file_count: u32,
    /// All raw type pairs `(declaring_type_idx, assigned_type_idx)`.
    pub type_assignments: Vec<(u32, u32)>,
    /// Raw section bytes for further analysis.
    pub raw: Vec<u8>,
}

impl VerifierDeps {
    /// Parse the verifier deps from a raw byte slice.
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self {
                dex_file_count: 0,
                type_assignments: vec![],
                raw: data.to_vec(),
            };
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        // Parse pairs: each is 8 bytes (two u32 indices), starting at offset 4.
        let mut pairs = Vec::new();
        let mut pos = 4usize;
        while pos + 8 <= data.len() {
            let a = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4]));
            let b = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4]));
            pairs.push((a, b));
            pos += 8;
        }
        Self {
            dex_file_count: count,
            type_assignments: pairs,
            raw: data.to_vec(),
        }
    }

    /// Number of type-assignment pairs.
    #[must_use]
    pub const fn pair_count(&self) -> usize {
        self.type_assignments.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuickeningInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-verified (quickened) bytecode information stored in VDEX.
///
/// For each DEX file, ART may store index mappings for `invoke-virtual-quick`
/// and similar quickened opcodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickeningInfo {
    /// Per-DEX quicken info blocks (raw bytes).
    pub per_dex_blocks: Vec<Vec<u8>>,
}

impl QuickeningInfo {
    /// Parse quickening info for `n_dex` DEX files from `data`.
    ///
    /// Each block is prefixed by a u32 length, allowing them to be split apart.
    #[must_use]
    pub fn parse(data: &[u8], n_dex: usize) -> Self {
        // Cap pre-allocation: each block has a 4-byte length prefix, so the
        // real count is bounded by data.len() / 4. Prevents OOM from a crafted
        // number_of_dex_files field.
        let mut blocks = Vec::with_capacity(n_dex.min(data.len() / 4 + 1));
        let mut pos = 0usize;
        for _ in 0..n_dex {
            if pos + 4 > data.len() {
                break;
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
            pos += 4;
            if pos + len > data.len() {
                break;
            }
            blocks.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Self {
            per_dex_blocks: blocks,
        }
    }

    /// Total number of bytes across all blocks.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.per_dex_blocks.iter().map(std::vec::Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VdexFile — complete parsed VDEX
// ─────────────────────────────────────────────────────────────────────────────

/// A fully parsed VDEX file.
#[derive(Debug, Clone)]
pub struct VdexFile {
    /// Parsed header.
    pub header: VdexHeader,
    /// Logical sections.
    pub sections: VdexSections,
    /// Verifier dependency information, if present.
    pub verifier_deps: Option<VerifierDeps>,
    /// Quickening info, if present.
    pub quickening: Option<QuickeningInfo>,
}

impl VdexFile {
    /// Parse a complete VDEX file from `data`.
    ///
    /// # Errors
    ///
    /// Returns an [`AndroidLoaderError`] when the data is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        let header = VdexHeader::parse(data)?;
        let n = header.number_of_dex_files as usize;

        // Read per-DEX checksums from the header checksum array.
        let cs_base = VdexHeader::MIN_HEADER_SIZE;
        // Cap pre-allocation: each checksum is 4 bytes; the real count is
        // bounded by data.len() / 4. Prevents OOM from a crafted header count.
        let mut checksums = Vec::with_capacity(n.min(data.len() / 4 + 1));
        for i in 0..n {
            let off = cs_base + i * 4;
            if off + 4 > data.len() {
                break;
            }
            checksums.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
        }

        // Walk the DEX section: each DEX file declares its own size.
        let dex_base = header.dex_data_offset();
        // Bounded by the number of checksums actually read (each embedded DEX
        // needs a checksum entry), which is already capped above.
        let mut dex_files = Vec::with_capacity(checksums.len());
        let mut offset = dex_base;
        for (i, &cs) in checksums.iter().enumerate() {
            if offset + 36 > data.len() {
                break;
            }
            if &data[offset..offset + 4] != b"dex\n" {
                break;
            }
            let size =
                u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap()) as usize;
            dex_files.push(VdexDexFile {
                index: i,
                vdex_offset: offset,
                stored_checksum: cs,
                size,
            });
            offset += size;
        }

        // Verifier deps section follows DEX data.
        let verifier_deps_start = dex_base.saturating_add(header.dex_section_size as usize);
        let vdeps_size = header.verifier_deps_size as usize;
        let verifier_deps_end = verifier_deps_start.saturating_add(vdeps_size);
        let verifier_deps_range =
            if vdeps_size > 0 && verifier_deps_end <= data.len() {
                Some((verifier_deps_start, verifier_deps_end))
            } else {
                None
            };

        let verifier_deps = verifier_deps_range.map(|(s, e)| VerifierDeps::parse(&data[s..e]));

        // Quickening info follows verifier deps.
        let quicken_start = verifier_deps_start.saturating_add(vdeps_size);
        let quicken_size = header.quicken_info_size as usize;
        let quicken_end = quicken_start.saturating_add(quicken_size);
        let quickening_info_range =
            if quicken_size > 0 && quicken_end <= data.len() {
                Some((quicken_start, quicken_end))
            } else {
                None
            };

        let quickening = quickening_info_range.map(|(s, e)| QuickeningInfo::parse(&data[s..e], n));

        let sections = VdexSections {
            dex_files,
            verifier_deps_range,
            quickening_info_range,
        };

        Ok(Self {
            header,
            sections,
            verifier_deps,
            quickening,
        })
    }

    /// Number of embedded DEX files.
    #[must_use]
    pub const fn dex_count(&self) -> usize {
        self.sections.dex_files.len()
    }

    /// Return a slice of the DEX data for DEX file `idx`.
    #[must_use]
    pub fn dex_data<'a>(&self, data: &'a [u8], idx: usize) -> Option<&'a [u8]> {
        let df = self.sections.dex_files.get(idx)?;
        let end = df.vdex_offset + df.size;
        if end <= data.len() {
            Some(&data[df.vdex_offset..end])
        } else {
            None
        }
    }
}

impl fmt::Display for VdexFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VdexFile v{} dex_count={} deps={} quicken={}",
            self.header.version,
            self.dex_count(),
            self.verifier_deps
                .as_ref()
                .map_or(0, VerifierDeps::pair_count),
            self.quickening
                .as_ref()
                .map_or(0, QuickeningInfo::total_bytes),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vdex_header_bytes(version: &[u8; 3], ndex: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"vdex");
        v.extend_from_slice(version);
        v.push(0); // NUL terminator
        v.extend_from_slice(&ndex.to_le_bytes()); // number_of_dex_files
        v.extend_from_slice(&0_u32.to_le_bytes()); // dex_section_size
        v.extend_from_slice(&0_u32.to_le_bytes()); // dex_shared_data_size
        v.extend_from_slice(&0_u32.to_le_bytes()); // verifier_deps_size
        v.extend_from_slice(&0_u32.to_le_bytes()); // quicken_info_size
        v
    }

    /// A crafted `number_of_dex_files` of `u32::MAX` must not cause a huge
    /// pre-allocation (OOM) — capacity is bounded by the actual buffer length.
    #[test]
    fn huge_dex_count_does_not_oom() {
        let mut data = make_vdex_header_bytes(b"021", u32::MAX);
        // A little trailing data so the checksum/dex loops have something to see.
        data.extend_from_slice(&[0u8; 64]);
        // Must return without panicking or attempting a multi-GB allocation.
        let f = VdexFile::parse(&data).expect("header is well-formed");
        assert!(f.sections.dex_files.len() < 64);
        // QuickeningInfo with a giant count must likewise stay bounded.
        let q = QuickeningInfo::parse(&data, u32::MAX as usize);
        assert!(q.per_dex_blocks.len() < data.len());
    }

    // ── VdexVersion ──────────────────────────────────────────────────────────

    #[test]
    fn test_vdex_version_v006() {
        let v = VdexVersion::from_bytes(*b"006\0");
        assert_eq!(v, VdexVersion::V006);
        assert_eq!(v.as_str(), "006");
        assert_eq!(v.as_u32(), 6);
        assert!(v.is_known());
    }

    #[test]
    fn test_vdex_version_v010() {
        let v = VdexVersion::from_bytes(*b"010\0");
        assert_eq!(v, VdexVersion::V010);
        assert_eq!(v.as_u32(), 10);
    }

    #[test]
    fn test_vdex_version_v018() {
        let v = VdexVersion::from_bytes(*b"018\0");
        assert_eq!(v, VdexVersion::V018);
    }

    #[test]
    fn test_vdex_version_v021() {
        let v = VdexVersion::from_bytes(*b"021\0");
        assert_eq!(v, VdexVersion::V021);
    }

    #[test]
    fn test_vdex_version_unknown() {
        let v = VdexVersion::from_bytes(*b"099\0");
        assert!(!v.is_known());
    }

    #[test]
    fn test_vdex_version_display() {
        assert_eq!(VdexVersion::V018.to_string(), "018");
    }

    // ── VdexHeader parsing ────────────────────────────────────────────────────

    #[test]
    fn test_vdex_header_v018() {
        let data = make_vdex_header_bytes(b"018", 2);
        let hdr = VdexHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, VdexVersion::V018);
        assert_eq!(hdr.number_of_dex_files, 2);
        assert_eq!(hdr.dex_data_offset(), 28 + 2 * 4);
    }

    #[test]
    fn test_vdex_header_truncated() {
        let data = [b'v', b'd', b'e', b'x'];
        assert!(matches!(
            VdexHeader::parse(&data),
            Err(AndroidLoaderError::TruncatedHeader)
        ));
    }

    #[test]
    fn test_vdex_header_invalid_magic() {
        let mut data = make_vdex_header_bytes(b"018", 0);
        data[0] = b'X';
        assert!(matches!(
            VdexHeader::parse(&data),
            Err(AndroidLoaderError::InvalidMagic)
        ));
    }

    #[test]
    fn test_vdex_header_v006_no_quicken() {
        let data = make_vdex_header_bytes(b"006", 1);
        let hdr = VdexHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, VdexVersion::V006);
        assert!(!hdr.has_quickening_info()); // quicken_info_size == 0
        assert!(!hdr.has_shared_dex_data());
    }

    #[test]
    fn test_vdex_header_display() {
        let data = make_vdex_header_bytes(b"018", 3);
        let hdr = VdexHeader::parse(&data).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("018"));
        assert!(s.contains("ndex=3"));
    }

    #[test]
    fn test_vdex_header_v021_shared_data() {
        let mut data = make_vdex_header_bytes(b"021", 1);
        // Overwrite dex_shared_data_size at offset 16
        data[16..20].copy_from_slice(&1024_u32.to_le_bytes());
        let hdr = VdexHeader::parse(&data).unwrap();
        assert!(hdr.has_shared_dex_data());
    }

    // ── VerifierDeps ──────────────────────────────────────────────────────────

    #[test]
    fn test_verifier_deps_empty() {
        let deps = VerifierDeps::parse(&[]);
        assert_eq!(deps.dex_file_count, 0);
        assert_eq!(deps.pair_count(), 0);
    }

    #[test]
    fn test_verifier_deps_with_pairs() {
        let mut raw = [2_u32.to_le_bytes().as_ref().to_vec()].concat();
        raw.extend_from_slice(&1_u32.to_le_bytes());
        raw.extend_from_slice(&2_u32.to_le_bytes());
        raw.extend_from_slice(&3_u32.to_le_bytes());
        raw.extend_from_slice(&4_u32.to_le_bytes());
        let deps = VerifierDeps::parse(&raw);
        assert_eq!(deps.dex_file_count, 2);
        assert_eq!(deps.pair_count(), 2);
        assert_eq!(deps.type_assignments[0], (1, 2));
        assert_eq!(deps.type_assignments[1], (3, 4));
    }

    #[test]
    fn test_verifier_deps_truncated_pair() {
        let mut raw = 0_u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[1, 2, 3]); // incomplete pair
        let deps = VerifierDeps::parse(&raw);
        assert_eq!(deps.pair_count(), 0);
    }

    // ── QuickeningInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_quickening_info_two_blocks() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&3_u32.to_le_bytes()); // block0 len = 3
        raw.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        raw.extend_from_slice(&2_u32.to_le_bytes()); // block1 len = 2
        raw.extend_from_slice(&[0x11, 0x22]);
        let qi = QuickeningInfo::parse(&raw, 2);
        assert_eq!(qi.per_dex_blocks.len(), 2);
        assert_eq!(qi.per_dex_blocks[0], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(qi.per_dex_blocks[1], &[0x11, 0x22]);
        assert_eq!(qi.total_bytes(), 5);
    }

    #[test]
    fn test_quickening_info_empty() {
        let qi = QuickeningInfo::parse(&[], 0);
        assert_eq!(qi.total_bytes(), 0);
    }

    #[test]
    fn test_quickening_info_truncated() {
        let raw = [5_u32.to_le_bytes()].concat(); // claims 5 bytes but none follow
        let qi = QuickeningInfo::parse(&raw, 1);
        assert_eq!(qi.per_dex_blocks.len(), 0);
    }

    // ── VdexDexFile ───────────────────────────────────────────────────────────

    #[test]
    fn test_vdex_dex_file_checksum_mismatch() {
        let df = VdexDexFile {
            index: 0,
            vdex_offset: 0,
            stored_checksum: 0xDEADBEEF,
            size: 20,
        };
        let data = vec![0u8; 40];
        assert!(!df.verify_checksum(&data));
    }

    #[test]
    fn test_vdex_dex_file_out_of_bounds() {
        let df = VdexDexFile {
            index: 0,
            vdex_offset: 0,
            stored_checksum: 0,
            size: 1000,
        };
        let data = vec![0u8; 10];
        assert!(!df.verify_checksum(&data));
    }

    // ── VdexFile parsing ──────────────────────────────────────────────────────

    #[test]
    fn test_vdex_file_parse_no_dex() {
        let data = make_vdex_header_bytes(b"018", 0);
        let vf = VdexFile::parse(&data).unwrap();
        assert_eq!(vf.dex_count(), 0);
        assert!(vf.verifier_deps.is_none());
        assert!(vf.quickening.is_none());
    }

    #[test]
    fn test_vdex_file_display() {
        let data = make_vdex_header_bytes(b"018", 0);
        let vf = VdexFile::parse(&data).unwrap();
        let s = vf.to_string();
        assert!(s.contains("VdexFile"));
        assert!(s.contains("018"));
    }

    #[test]
    fn test_vdex_file_parse_invalid() {
        let bad = b"XXXX000000000000000000000000";
        assert!(VdexFile::parse(bad).is_err());
    }

    #[test]
    fn test_vdex_file_dex_data_out_of_bounds() {
        let data = make_vdex_header_bytes(b"018", 0);
        let vf = VdexFile::parse(&data).unwrap();
        assert!(vf.dex_data(&data, 0).is_none());
    }
}
