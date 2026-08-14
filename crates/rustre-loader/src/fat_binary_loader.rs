//! `fat_binary_loader` — High-level loader for Apple FAT / universal binaries.
//!
//! # Relation to `fat_binary_splitter`
//!
//! This module is the **high-level loading layer**: it owns the file data,
//! computes SHA-256 digests of extracted slices, provides [`ArchSelector`]
//! strategy-pattern enum, and returns self-contained [`LoadedSlice`] values.
//!
//! [`fat_binary_splitter`](crate::fat_binary_splitter) is the **low-level
//! splitting layer**: it yields borrowed `&[u8]` slices and exposes the
//! stateful [`FatBinarySplitter`](crate::fat_binary_splitter::FatBinarySplitter)
//! struct with alignment validation and `MAX_FAT_ARCHES` limits.
//!
//! # Format (from `<mach-o/fat.h>`)
//!
//!   * 4-byte magic (`0xCAFEBABE` big-endian or `0xBEBAFECA` for 32-bit reversed)
//!   * 4-byte `nfat_arch` (number of architecture entries)
//!   * Per-arch entries: `(cputype u32, cpusubtype u32, offset u32, size u32, align u32)`
//!
//! This module:
//!   * Validates and parses the FAT header
//!   * Selects an architecture slice by CPU type or host preference
//!   * Extracts individual Mach-O slices as byte buffers
//!   * Provides an [`ArchSelector`] strategy for automatic slice selection
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Big-endian FAT magic (the standard FAT universal binary).
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
/// Little-endian FAT magic (`fat_header` fields stored reversed, rare).
pub const FAT_CIGAM: u32 = 0xBEBA_FECA;
/// 64-bit FAT magic.
pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// Little-endian 64-bit FAT magic.
pub const FAT_CIGAM_64: u32 = 0xBFBA_FECA;

/// Minimum size of a FAT binary (magic + count + 1 arch entry × 20 bytes).
const MIN_FAT_SIZE: usize = 8 + 20;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FatLoaderError {
    #[error("Buffer too small to be a FAT binary ({size} bytes, need at least {need})")]
    TooSmall { size: usize, need: usize },
    #[error("Not a FAT binary — magic 0x{magic:08X} does not match")]
    InvalidMagic { magic: u32 },
    #[error("FAT header declares {count} slices but the buffer cannot fit them all")]
    TruncatedHeader { count: u32 },
    #[error("Architecture slice {index} (cpu {cpu}) has offset+size beyond file end")]
    SliceOutOfBounds { index: usize, cpu: u32 },
    #[error("No architecture slice found matching the selection criteria")]
    ArchNotFound,
    #[error("FAT binary has zero slices")]
    NoSlices,
}

// ---------------------------------------------------------------------------
// CPU type constants (subset, matching <mach/machine.h>)
// ---------------------------------------------------------------------------

/// Known Mach-O CPU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum CpuType {
    Any = 0,
    Vax = 1,
    Mc680x0 = 6,
    X86 = 7,
    X86_64 = 0x0100_0007,
    Mc98000 = 10,
    Hppa = 11,
    Arm = 12,
    Arm64 = 0x0100_000C,
    Arm64_32 = 0x0200_000C,
    Mc88000 = 13,
    Sparc = 14,
    I860 = 15,
    PowerPc = 18,
    PowerPc64 = 0x0100_0012,
    Unknown(u32),
}

impl CpuType {
    #[must_use] 
    pub const fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Any,
            1 => Self::Vax,
            6 => Self::Mc680x0,
            7 => Self::X86,
            0x0100_0007 => Self::X86_64,
            10 => Self::Mc98000,
            11 => Self::Hppa,
            12 => Self::Arm,
            0x0100_000C => Self::Arm64,
            0x0200_000C => Self::Arm64_32,
            13 => Self::Mc88000,
            14 => Self::Sparc,
            15 => Self::I860,
            18 => Self::PowerPc,
            0x0100_0012 => Self::PowerPc64,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn raw(self) -> u32 {
        match self {
            Self::Any => 0,
            Self::Vax => 1,
            Self::Mc680x0 => 6,
            Self::X86 => 7,
            Self::X86_64 => 0x0100_0007,
            Self::Mc98000 => 10,
            Self::Hppa => 11,
            Self::Arm => 12,
            Self::Arm64 => 0x0100_000C,
            Self::Arm64_32 => 0x0200_000C,
            Self::Mc88000 => 13,
            Self::Sparc => 14,
            Self::I860 => 15,
            Self::PowerPc => 18,
            Self::PowerPc64 => 0x0100_0012,
            Self::Unknown(v) => v,
        }
    }

    #[must_use] 
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Arm64_32 => "arm64_32",
            Self::PowerPc => "ppc",
            Self::PowerPc64 => "ppc64",
            Self::Sparc => "sparc",
            _ => "unknown",
        }
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// FAT architecture entry
// ---------------------------------------------------------------------------

/// Represents one architecture entry inside a FAT binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatArch {
    /// Zero-based index within the FAT header.
    pub index: usize,
    /// CPU type.
    pub cpu_type: CpuType,
    /// CPU sub-type (implementation variant).
    pub cpu_subtype: u32,
    /// File offset of the Mach-O slice.
    pub offset: u64,
    /// Size of the Mach-O slice in bytes.
    pub size: u64,
    /// Required alignment (expressed as a power of 2).
    pub align: u32,
    /// Whether this is a 64-bit `fat_arch_64` entry.
    pub is_64: bool,
}

impl FatArch {
    /// Returns the Mach-O magic read from the first 4 bytes of this slice, if the buffer
    /// is long enough.
    #[must_use]
    pub fn slice_magic(&self, data: &[u8]) -> Option<u32> {
        let start = usize::try_from(self.offset).ok()?;
        if start + 4 <= data.len() {
            Some(u32::from_be_bytes([
                data[start],
                data[start + 1],
                data[start + 2],
                data[start + 3],
            ]))
        } else {
            None
        }
    }

    /// Returns `true` if the slice magic is a known Mach-O magic.
    #[must_use] 
    pub fn is_valid_macho(&self, data: &[u8]) -> bool {
        match self.slice_magic(data) {
            Some(0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE) => true, // 64-bit Mach-O LE
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed FAT header
// ---------------------------------------------------------------------------

/// The result of parsing a FAT binary header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatHeader {
    /// True when the file uses `fat_arch_64` entries.
    pub is_64: bool,
    /// Architecture entries in order.
    pub arches: Vec<FatArch>,
    /// Total file size used for bounds checking.
    pub file_size: usize,
}

impl FatHeader {
    /// Looks up a `FatArch` by `CpuType`.
    #[must_use] 
    pub fn find_arch(&self, cpu: CpuType) -> Option<&FatArch> {
        self.arches.iter().find(|a| a.cpu_type == cpu)
    }

    /// Returns all architectures present, sorted by CPU type raw value.
    #[must_use] 
    pub fn sorted_arches(&self) -> Vec<&FatArch> {
        let mut v: Vec<&FatArch> = self.arches.iter().collect();
        v.sort_by_key(|a| a.cpu_type.raw());
        v
    }

    /// Returns a `HashMap` from CPU type to arch index.
    #[must_use] 
    pub fn arch_index_map(&self) -> HashMap<u32, usize> {
        self.arches
            .iter()
            .map(|a| (a.cpu_type.raw(), a.index))
            .collect()
    }

    /// Returns `true` if the FAT binary contains a 64-bit x86 slice.
    #[must_use] 
    pub fn has_x86_64(&self) -> bool {
        self.find_arch(CpuType::X86_64).is_some()
    }

    /// Returns `true` if the FAT binary contains an ARM64 slice.
    #[must_use] 
    pub fn has_arm64(&self) -> bool {
        self.find_arch(CpuType::Arm64).is_some()
    }
}

// ---------------------------------------------------------------------------
// Slice selection strategy
// ---------------------------------------------------------------------------

/// Strategy for choosing which architecture slice to load when multiple are available.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchSelector {
    /// Select a slice by exact CPU type.
    ByCpuType(CpuType),
    /// Select the first slice regardless of architecture.
    First,
    /// Select the last slice.
    Last,
    /// Prefer 64-bit slices; fall back to 32-bit if none present.
    Prefer64Bit,
    /// Prefer ARM64 → `x86_64` → ARM → x86 → first.
    AppleDefault,
    /// Select the largest slice by raw byte count.
    Largest,
    /// Select the slice with the lowest file offset.
    LowestOffset,
}

impl ArchSelector {
    fn select<'a>(&self, header: &'a FatHeader) -> Option<&'a FatArch> {
        match self {
            Self::ByCpuType(cpu) => header.find_arch(*cpu),
            Self::First => header.arches.first(),
            Self::Last => header.arches.last(),
            Self::Prefer64Bit => {
                // Check for any 64-bit arch.
                header
                    .arches
                    .iter()
                    .find(|a| {
                        matches!(
                            a.cpu_type,
                            CpuType::X86_64 | CpuType::Arm64 | CpuType::PowerPc64
                        )
                    })
                    .or_else(|| header.arches.first())
            }
            Self::AppleDefault => {
                for cpu in &[CpuType::Arm64, CpuType::X86_64, CpuType::Arm, CpuType::X86] {
                    if let Some(a) = header.find_arch(*cpu) {
                        return Some(a);
                    }
                }
                header.arches.first()
            }
            Self::Largest => header
                .arches
                .iter()
                .max_by_key(|a| a.size),
            Self::LowestOffset => header
                .arches
                .iter()
                .min_by_key(|a| a.offset),
        }
    }
}

// ---------------------------------------------------------------------------
// Loaded slice
// ---------------------------------------------------------------------------

/// A successfully loaded Mach-O slice extracted from a FAT binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedSlice {
    /// Metadata about the architecture this slice belongs to.
    pub arch: FatArch,
    /// The raw bytes of the Mach-O slice.
    #[serde(skip)]
    pub data: Vec<u8>,
    /// SHA-256 digest of the slice bytes (hex-encoded).
    pub sha256: String,
}

impl LoadedSlice {
    /// Returns the Mach-O magic value from the start of the slice.
    #[must_use] 
    pub fn macho_magic(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Returns `true` if the slice contains a 64-bit Mach-O.
    #[must_use] 
    pub fn is_macho64(&self) -> bool {
        matches!(
            self.macho_magic(),
            Some(0xFEED_FACF | 0xCFFA_EDFE)
        )
    }
}

// ---------------------------------------------------------------------------
// SHA-256 helper (no external dep)
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    // Tiny SHA-256 without pulling in a crate — uses the standard transform.
    // For production code you'd use `sha2` crate; this self-contained version
    // exists so the module compiles without extra dependencies.
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
        0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
        0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
        0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
        0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];

    let bit_len = u64::try_from(data.len()).unwrap_or(u64::MAX).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for idx in 0..16 {
            w[idx] = u32::from_be_bytes([
                chunk[idx * 4],
                chunk[idx * 4 + 1],
                chunk[idx * 4 + 2],
                chunk[idx * 4 + 3],
            ]);
        }
        for idx in 16..64 {
            let sigma0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let sigma1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(sigma0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(sigma1);
        }
        let [mut hash_a, mut hash_b, mut hash_c, mut hash_d, mut hash_e, mut hash_f, mut hash_g, mut hh] = h;
        for idx in 0..64 {
            let ep1 = hash_e.rotate_right(6) ^ hash_e.rotate_right(11) ^ hash_e.rotate_right(25);
            let ch = (hash_e & hash_f) ^ (!hash_e & hash_g);
            let temp1 = hh
                .wrapping_add(ep1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let ep0 = hash_a.rotate_right(2) ^ hash_a.rotate_right(13) ^ hash_a.rotate_right(22);
            let maj = (hash_a & hash_b) ^ (hash_a & hash_c) ^ (hash_b & hash_c);
            let temp2 = ep0.wrapping_add(maj);
            hh = hash_g;
            hash_g = hash_f;
            hash_f = hash_e;
            hash_e = hash_d.wrapping_add(temp1);
            hash_d = hash_c;
            hash_c = hash_b;
            hash_b = hash_a;
            hash_a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(hash_a);
        h[1] = h[1].wrapping_add(hash_b);
        h[2] = h[2].wrapping_add(hash_c);
        h[3] = h[3].wrapping_add(hash_d);
        h[4] = h[4].wrapping_add(hash_e);
        h[5] = h[5].wrapping_add(hash_f);
        h[6] = h[6].wrapping_add(hash_g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().fold(String::new(), |mut acc, v| { write!(acc, "{v:08x}").unwrap(); acc })
}

// ---------------------------------------------------------------------------
// FAT binary parser
// ---------------------------------------------------------------------------

/// Parses and loads architecture slices from Apple FAT / universal binaries.
pub struct FatBinaryLoader;

impl FatBinaryLoader {
    /// Parses a FAT header from `data`.  Returns an error if `data` does not
    /// start with a recognised FAT magic.
    ///
    /// # Errors
    /// Returns `FatLoaderError` if the buffer is too small, has an invalid magic, or is truncated.
    pub fn parse_header(data: &[u8]) -> Result<FatHeader, FatLoaderError> {
        if data.len() < MIN_FAT_SIZE {
            return Err(FatLoaderError::TooSmall {
                size: data.len(),
                need: MIN_FAT_SIZE,
            });
        }

        let raw_magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let (is_64, big_endian) = match raw_magic {
            FAT_MAGIC => (false, true),
            FAT_CIGAM => (false, false),
            FAT_MAGIC_64 => (true, true),
            FAT_CIGAM_64 => (true, false),
            other => return Err(FatLoaderError::InvalidMagic { magic: other }),
        };

        let read_u32 = |offset: usize| -> u32 {
            let b = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            let b = [
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ];
            if big_endian {
                u64::from_be_bytes(b)
            } else {
                u64::from_le_bytes(b)
            }
        };

        let nfat_arch = read_u32(4);
        let entry_size: usize = if is_64 { 32 } else { 20 };
        // Reject absurd arch counts before computing header_bytes to avoid
        // integer overflow in the multiplication and OOM in Vec::with_capacity.
        // A fat binary with more than 64 architectures has never existed in
        // practice; cap at 256 to allow generous future growth.
        if nfat_arch > 256 {
            return Err(FatLoaderError::TruncatedHeader { count: nfat_arch });
        }
        let header_bytes = 8 + nfat_arch as usize * entry_size;
        if data.len() < header_bytes {
            return Err(FatLoaderError::TruncatedHeader { count: nfat_arch });
        }

        let mut arches = Vec::with_capacity(nfat_arch as usize);
        for i in 0..nfat_arch as usize {
            let base = 8 + i * entry_size;
            let cpu_type_raw = read_u32(base);
            let cpu_subtype = read_u32(base + 4);

            let (offset, size, align) = if is_64 {
                let off = read_u64(base + 8);
                let sz = read_u64(base + 16);
                let al = read_u32(base + 24);
                (off, sz, al)
            } else {
                let off = u64::from(read_u32(base + 8));
                let sz = u64::from(read_u32(base + 12));
                let al = read_u32(base + 16);
                (off, sz, al)
            };

            // Bounds check.
            if offset + size > data.len() as u64 {
                return Err(FatLoaderError::SliceOutOfBounds {
                    index: i,
                    cpu: cpu_type_raw,
                });
            }

            arches.push(FatArch {
                index: i,
                cpu_type: CpuType::from_raw(cpu_type_raw),
                cpu_subtype,
                offset,
                size,
                align,
                is_64,
            });
        }

        if arches.is_empty() {
            return Err(FatLoaderError::NoSlices);
        }

        Ok(FatHeader {
            is_64,
            arches,
            file_size: data.len(),
        })
    }

    /// Extracts a specific architecture slice from `data` based on `selector`.
    ///
    /// # Errors
    /// Returns `FatLoaderError` if the header is invalid, no matching arch is found, or the slice is out of bounds.
    pub fn load_slice(
        data: &[u8],
        selector: &ArchSelector,
    ) -> Result<LoadedSlice, FatLoaderError> {
        let header = Self::parse_header(data)?;
        let arch = selector.select(&header).ok_or(FatLoaderError::ArchNotFound)?;
        Self::extract_arch(data, arch)
    }

    /// Extracts all architecture slices from `data`.
    ///
    /// # Errors
    /// Returns `FatLoaderError` if the header is invalid or any slice is out of bounds.
    pub fn load_all_slices(data: &[u8]) -> Result<Vec<LoadedSlice>, FatLoaderError> {
        let header = Self::parse_header(data)?;
        let mut slices = Vec::with_capacity(header.arches.len());
        for arch in &header.arches {
            slices.push(Self::extract_arch(data, arch)?);
        }
        Ok(slices)
    }

    /// Returns `true` if `data` starts with a FAT binary magic.
    #[must_use] 
    pub fn is_fat_binary(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64)
    }

    /// Lists the CPU architectures present in the FAT binary without loading slices.
    ///
    /// # Errors
    /// Returns `FatLoaderError` if the header cannot be parsed.
    pub fn list_architectures(data: &[u8]) -> Result<Vec<CpuType>, FatLoaderError> {
        let header = Self::parse_header(data)?;
        Ok(header.arches.iter().map(|a| a.cpu_type).collect())
    }

    // ------------------------------------------------------------------

    fn extract_arch(data: &[u8], arch: &FatArch) -> Result<LoadedSlice, FatLoaderError> {
        let start = usize::try_from(arch.offset).unwrap_or(usize::MAX);
        let size = usize::try_from(arch.size).unwrap_or(usize::MAX);
        let end = start.saturating_add(size);
        if end > data.len() {
            return Err(FatLoaderError::SliceOutOfBounds {
                index: arch.index,
                cpu: arch.cpu_type.raw(),
            });
        }
        let slice_bytes = data[start..end].to_vec();
        let sha256 = sha256_hex(&slice_bytes);
        Ok(LoadedSlice {
            arch: arch.clone(),
            data: slice_bytes,
            sha256,
        })
    }
}

// ---------------------------------------------------------------------------
// Summary report
// ---------------------------------------------------------------------------

/// High-level report about a FAT binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatBinaryReport {
    pub is_64: bool,
    pub num_slices: usize,
    pub architectures: Vec<String>,
    pub has_x86_64: bool,
    pub has_arm64: bool,
    pub total_file_size: u64,
    pub slice_info: Vec<FatArch>,
}

/// Produce a summary report from raw file bytes.
///
/// # Errors
/// Returns `FatLoaderError` if the FAT header cannot be parsed.
pub fn fat_binary_report(data: &[u8]) -> Result<FatBinaryReport, FatLoaderError> {
    let header = FatBinaryLoader::parse_header(data)?;
    let architectures = header
        .arches
        .iter()
        .map(|a| a.cpu_type.display_name().to_string())
        .collect();
    Ok(FatBinaryReport {
        is_64: header.is_64,
        num_slices: header.arches.len(),
        has_x86_64: header.has_x86_64(),
        has_arm64: header.has_arm64(),
        total_file_size: data.len() as u64,
        architectures,
        slice_info: header.arches,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic FAT binary with two slices.
    fn make_fat_binary(slices: &[(&[u8], CpuType)]) -> Vec<u8> {
        let n = slices.len() as u32;
        let header_size: u32 = 8 + n * 20;
        let mut buf: Vec<u8> = Vec::new();
        // Magic + nfat_arch
        buf.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        buf.extend_from_slice(&n.to_be_bytes());
        // Compute offsets
        let mut offset = header_size;
        for (slice, cpu) in slices {
            let size = slice.len() as u32;
            buf.extend_from_slice(&cpu.raw().to_be_bytes()); // cputype
            buf.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            buf.extend_from_slice(&offset.to_be_bytes()); // offset
            buf.extend_from_slice(&size.to_be_bytes()); // size
            buf.extend_from_slice(&12u32.to_be_bytes()); // align
            offset += size;
        }
        // Append slice data
        for (slice, _) in slices {
            buf.extend_from_slice(slice);
        }
        buf
    }

    #[test]
    fn test_is_fat_binary() {
        let fat = make_fat_binary(&[(&[0xCF, 0xFA, 0xED, 0xFE], CpuType::X86_64)]);
        assert!(FatBinaryLoader::is_fat_binary(&fat));
        assert!(!FatBinaryLoader::is_fat_binary(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_parse_header_two_slices() {
        let slice1 = vec![0xCF, 0xFA, 0xED, 0xFE]; // LE 64-bit Mach-O magic
        let slice2 = vec![0xCE, 0xFA, 0xED, 0xFE]; // LE 32-bit Mach-O magic
        let fat = make_fat_binary(&[(&slice1, CpuType::X86_64), (&slice2, CpuType::X86)]);
        let header = FatBinaryLoader::parse_header(&fat).unwrap();
        assert_eq!(header.arches.len(), 2);
        assert_eq!(header.arches[0].cpu_type, CpuType::X86_64);
        assert_eq!(header.arches[1].cpu_type, CpuType::X86);
    }

    #[test]
    fn test_load_slice_by_cpu() {
        let slice_x64 = b"MACHO64".to_vec();
        let slice_arm = b"MACHOARM".to_vec();
        let fat = make_fat_binary(&[(&slice_x64, CpuType::X86_64), (&slice_arm, CpuType::Arm64)]);
        let loaded = FatBinaryLoader::load_slice(&fat, &ArchSelector::ByCpuType(CpuType::Arm64))
            .unwrap();
        assert_eq!(loaded.data, b"MACHOARM".to_vec());
    }

    #[test]
    fn test_load_all_slices() {
        let slice1 = b"SLICE1".to_vec();
        let slice2 = b"SLICE2".to_vec();
        let fat = make_fat_binary(&[(&slice1, CpuType::X86), (&slice2, CpuType::X86_64)]);
        let slices = FatBinaryLoader::load_all_slices(&fat).unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].data, b"SLICE1".to_vec());
        assert_eq!(slices[1].data, b"SLICE2".to_vec());
    }

    #[test]
    fn test_arch_not_found() {
        let fat = make_fat_binary(&[(&[0u8; 4], CpuType::X86)]);
        let result = FatBinaryLoader::load_slice(&fat, &ArchSelector::ByCpuType(CpuType::Arm64));
        assert!(matches!(result, Err(FatLoaderError::ArchNotFound)));
    }

    #[test]
    fn test_list_architectures() {
        let fat = make_fat_binary(&[
            (&[0u8; 4], CpuType::X86_64),
            (&[0u8; 4], CpuType::Arm64),
        ]);
        let arches = FatBinaryLoader::list_architectures(&fat).unwrap();
        assert_eq!(arches, vec![CpuType::X86_64, CpuType::Arm64]);
    }

    #[test]
    fn test_apple_default_selector_prefers_arm64() {
        let fat = make_fat_binary(&[
            (&[0u8; 4], CpuType::X86),
            (&[0u8; 4], CpuType::Arm64),
        ]);
        let loaded = FatBinaryLoader::load_slice(&fat, &ArchSelector::AppleDefault).unwrap();
        assert_eq!(loaded.arch.cpu_type, CpuType::Arm64);
    }

    #[test]
    fn test_sha256_hex_length() {
        let digest = sha256_hex(b"hello");
        assert_eq!(digest.len(), 64, "SHA-256 hex digest should be 64 chars");
    }

    #[test]
    fn test_fat_binary_report() {
        let fat = make_fat_binary(&[
            (&[0u8; 4], CpuType::X86_64),
            (&[0u8; 4], CpuType::Arm64),
        ]);
        let report = fat_binary_report(&fat).unwrap();
        assert!(report.has_x86_64);
        assert!(report.has_arm64);
        assert_eq!(report.num_slices, 2);
    }
}
