//! Fat binary splitter — splits Mach-O universal / fat binaries into
//! per-architecture slices.
//!
//! # Relation to `fat_binary_loader`
//!
//! This module is the **low-level splitting layer**: it produces borrowed
//! `&[u8]` slices for each architecture and exposes the stateful
//! [`FatBinarySplitter`] struct.  It validates alignment (power-of-two) and
//! enforces a [`MAX_FAT_ARCHES`] guard against malformed headers.
//!
//! [`fat_binary_loader`](crate::fat_binary_loader) is the **high-level loading
//! layer**: it owns the data, computes SHA-256 digests, provides an
//! [`ArchSelector`](crate::fat_binary_loader::ArchSelector) strategy enum, and
//! returns [`LoadedSlice`](crate::fat_binary_loader::LoadedSlice) values.
//!
//! Supports both `FAT_MAGIC` (32-bit) and `FAT_MAGIC_64` (64-bit) headers
//! as defined in `<mach-o/fat.h>`.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the fat binary splitter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FatError {
    #[error("data too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("not a fat binary: bad magic {0:#010x}")]
    BadMagic(u32),
    #[error("entry {index} slice {offset}+{size} overflows fat binary of {total} bytes")]
    SliceOverflow { index: usize, offset: u64, size: u64, total: usize },
    #[error("entry {index} alignment {align} is not a power of two")]
    BadAlignment { index: usize, align: u32 },
    #[error("too many fat architectures: {0}")]
    TooManyArches(u32),
}

pub type FatResult<T> = Result<T, FatError>;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_CIGAM: u32 = 0xBEBA_FECA; // little-endian byte-swap of FAT_MAGIC
const FAT_MAGIC_64: u32 = 0xCAFE_BABF; // 64-bit fat magic (big-endian)
const FAT_CIGAM_64: u32 = 0xBFBA_FECA; // 64-bit fat magic (little-endian byte-swap)

const MAX_FAT_ARCHES: u32 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Arch
// ─────────────────────────────────────────────────────────────────────────────

/// CPU type / subtype pair identifying a Mach-O architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Arch {
    /// Mach-O `cpu_type_t`.
    pub cpu_type: i32,
    /// Mach-O `cpu_subtype_t`.
    pub cpu_subtype: i32,
}

impl Arch {
    pub const X86: Self = Self { cpu_type: 7, cpu_subtype: 3 };
    pub const X86_64: Self = Self { cpu_type: 0x0100_0007, cpu_subtype: 3 };
    pub const ARM: Self = Self { cpu_type: 12, cpu_subtype: 0 };
    pub const ARM64: Self = Self { cpu_type: 0x0100_000C, cpu_subtype: 0 };
    pub const PPC: Self = Self { cpu_type: 18, cpu_subtype: 0 };
    pub const PPC64: Self = Self { cpu_type: 0x0100_0012, cpu_subtype: 0 };

    /// Return a human-readable architecture name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match (self.cpu_type, self.cpu_subtype) {
            (7, _) => "x86",
            (0x0100_0007, _) => "x86_64",
            (12, _) => "arm",
            (0x0100_000C, _) => "arm64",
            (18, _) => "ppc",
            (0x0100_0012, _) => "ppc64",
            _ => "unknown",
        }
    }

    /// Return `true` if this is a 64-bit architecture.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.cpu_type & 0x0100_0000 != 0
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name();
        if name == "unknown" {
            write!(f, "cpu_type={:#010x}/sub={:#010x}", self.cpu_type, self.cpu_subtype)
        } else {
            write!(f, "{name}")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FatEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for one architecture slice inside a fat binary.
#[derive(Debug, Clone)]
pub struct FatEntry {
    /// Architecture (`cpu_type` / `cpu_subtype`).
    pub arch: Arch,
    /// Byte offset of the slice within the fat binary.
    pub offset: u64,
    /// Byte size of the slice.
    pub size: u64,
    /// Alignment (log2); 0 = unaligned.
    pub align: u32,
    /// Whether the parent fat binary uses the 64-bit fat header.
    pub is_64: bool,
}

impl FatEntry {
    /// Return the byte alignment of the slice (2^align).
    #[must_use]
    pub const fn alignment_bytes(&self) -> u64 {
        1u64 << self.align
    }
}

impl fmt::Display for FatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} offset={:#x} size={} align=2^{}",
            self.arch, self.offset, self.size, self.align
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level byte readers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32_be(buf: &[u8], off: usize) -> FatResult<u32> {
    if off + 4 > buf.len() {
        return Err(FatError::TooShort { need: off + 4, have: buf.len() });
    }
    Ok(u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]))
}

fn read_i32_be(buf: &[u8], off: usize) -> FatResult<i32> {
    read_u32_be(buf, off).map(|v| i32::from_ne_bytes(v.to_ne_bytes()))
}

fn read_u64_be(buf: &[u8], off: usize) -> FatResult<u64> {
    if off + 8 > buf.len() {
        return Err(FatError::TooShort { need: off + 8, have: buf.len() });
    }
    Ok(u64::from_be_bytes([
        buf[off], buf[off+1], buf[off+2], buf[off+3],
        buf[off+4], buf[off+5], buf[off+6], buf[off+7],
    ]))
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_fat_header — internal
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the fat header and return the list of entries without slicing.
fn parse_fat_header(data: &[u8]) -> FatResult<(Vec<FatEntry>, bool)> {
    if data.len() < 8 {
        return Err(FatError::TooShort { need: 8, have: data.len() });
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let is_64 = matches!(magic, FAT_MAGIC_64 | FAT_CIGAM_64);

    // Validate magic.
    if !matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64) {
        return Err(FatError::BadMagic(magic));
    }

    let nfat_arch = read_u32_be(data, 4)?;
    if nfat_arch > MAX_FAT_ARCHES {
        return Err(FatError::TooManyArches(nfat_arch));
    }

    let mut entries = Vec::with_capacity(nfat_arch as usize);
    let mut off = 8usize;

    for i in 0..nfat_arch as usize {
        let cpu_type = read_i32_be(data, off)?;
        let cpu_subtype = read_i32_be(data, off + 4)?;
        let arch = Arch { cpu_type, cpu_subtype };

        let (offset, size, align, entry_size) = if is_64 {
            // fat_arch_64: 4+4+8+8+4+4 = 32 bytes
            if off + 32 > data.len() {
                return Err(FatError::TooShort { need: off + 32, have: data.len() });
            }
            let offset = read_u64_be(data, off + 8)?;
            let size = read_u64_be(data, off + 16)?;
            let align = read_u32_be(data, off + 24)?;
            (offset, size, align, 32usize)
        } else {
            // fat_arch: 4+4+4+4+4 = 20 bytes
            if off + 20 > data.len() {
                return Err(FatError::TooShort { need: off + 20, have: data.len() });
            }
            let offset = u64::from(read_u32_be(data, off + 8)?);
            let size = u64::from(read_u32_be(data, off + 12)?);
            let align = read_u32_be(data, off + 16)?;
            (offset, size, align, 20usize)
        };

        // The Mach-O fat header stores alignment as a log2 exponent
        // (e.g. 12 means 2^12 = 4096-byte alignment).  Any exponent in
        // [0, 63] yields a valid power-of-two alignment.
        if align > 63 {
            return Err(FatError::BadAlignment { index: i, align });
        }

        // Validate that the slice fits within the file.
        let end = offset.saturating_add(size);
        if end > data.len() as u64 {
            return Err(FatError::SliceOverflow {
                index: i,
                offset,
                size,
                total: data.len(),
            });
        }

        entries.push(FatEntry { arch, offset, size, align, is_64 });
        off += entry_size;
    }

    Ok((entries, is_64))
}

// ─────────────────────────────────────────────────────────────────────────────
// split_fat_binary — public function
// ─────────────────────────────────────────────────────────────────────────────

/// Split a fat binary into per-architecture byte slices.
///
/// Returns a `Vec<(FatEntry, &[u8])>` mapping each entry to its slice.
///
/// # Errors
/// Returns [`FatError`] on any header or slice validation failure.
pub fn split_fat_binary(data: &[u8]) -> FatResult<Vec<(FatEntry, &[u8])>> {
    let (entries, _) = parse_fat_header(data)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(entry.size).unwrap_or(usize::MAX));
        let slice = &data[start..end];
        out.push((entry, slice));
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// FatBinarySplitter
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful fat binary splitter — extracts slices and provides filtering.
#[derive(Debug)]
pub struct FatBinarySplitter {
    entries: Vec<FatEntry>,
    data: Vec<u8>,
    is_64: bool,
}

impl FatBinarySplitter {
    /// Parse a fat binary and prepare for slice extraction.
    ///
    /// # Errors
    /// Returns [`FatError`] on any parse failure.
    pub fn new(data: Vec<u8>) -> FatResult<Self> {
        let (entries, is_64) = parse_fat_header(&data)?;
        Ok(Self { entries, data, is_64 })
    }

    /// Return the list of architecture entries.
    #[must_use]
    pub fn entries(&self) -> &[FatEntry] {
        &self.entries
    }

    /// Return whether the fat header uses 64-bit offsets.
    #[must_use]
    pub const fn is_64bit_fat(&self) -> bool {
        self.is_64
    }

    /// Extract the slice for a specific architecture.
    ///
    /// Returns `None` if no matching architecture is found.
    #[must_use]
    pub fn slice_for_arch(&self, arch: Arch) -> Option<&[u8]> {
        for entry in &self.entries {
            if entry.arch.cpu_type == arch.cpu_type
                && (arch.cpu_subtype == 0 || entry.arch.cpu_subtype == arch.cpu_subtype)
            {
                let start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(entry.size).unwrap_or(usize::MAX));
                return Some(&self.data[start..end]);
            }
        }
        None
    }

    /// Return all slices as `(entry_index, arch_name, slice)` tuples.
    #[must_use]
    pub fn all_slices(&self) -> Vec<(usize, &str, &[u8])> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let start = usize::try_from(e.offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(e.size).unwrap_or(usize::MAX));
                (i, e.arch.name(), &self.data[start..end])
            })
            .collect()
    }

    /// Return the total number of architecture slices.
    #[must_use]
    pub const fn arch_count(&self) -> usize {
        self.entries.len()
    }

    /// Return the size of the original fat binary.
    #[must_use]
    pub const fn fat_size(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the fat binary contains a slice for `arch`.
    #[must_use]
    pub fn contains_arch(&self, arch: Arch) -> bool {
        self.slice_for_arch(arch).is_some()
    }

    /// Extract the x86-64 slice if present.
    #[must_use]
    pub fn x86_64_slice(&self) -> Option<&[u8]> {
        self.slice_for_arch(Arch::X86_64)
    }

    /// Extract the ARM64 slice if present.
    #[must_use]
    pub fn arm64_slice(&self) -> Option<&[u8]> {
        self.slice_for_arch(Arch::ARM64)
    }

    /// Extract the ARM (32-bit) slice if present.
    #[must_use]
    pub fn arm_slice(&self) -> Option<&[u8]> {
        self.slice_for_arch(Arch::ARM)
    }

    /// Return architecture names for all contained slices.
    #[must_use]
    pub fn arch_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.arch.name()).collect()
    }

    /// Return the largest slice.
    #[must_use]
    pub fn largest_slice(&self) -> Option<(Arch, &[u8])> {
        self.entries
            .iter()
            .max_by_key(|e| e.size)
            .map(|e| {
                let start = usize::try_from(e.offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(e.size).unwrap_or(usize::MAX));
                (e.arch, &self.data[start..end])
            })
    }

    /// Verify that all slices have valid Mach-O magic bytes.
    #[must_use]
    pub fn verify_slices(&self) -> Vec<(usize, bool)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let start = usize::try_from(e.offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(e.size).unwrap_or(usize::MAX));
                let slice = &self.data[start..end];
                let valid = slice.len() >= 4 && is_macho_magic(slice);
                (i, valid)
            })
            .collect()
    }
}

fn is_macho_magic(data: &[u8]) -> bool {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(v, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE)
        || {
            let vbe = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            matches!(vbe, 0xFEED_FACE | 0xFEED_FACF)
        }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_fat(slices: &[(i32, i32, &[u8])]) -> Vec<u8> {
        // Build a minimal 32-bit FAT binary.
        let nfat = slices.len() as u32;
        let header_size = 8 + nfat as usize * 20;
        let mut slice_offsets = Vec::new();
        let mut current = header_size;
        for (_, _, data) in slices {
            slice_offsets.push(current);
            current += data.len();
        }

        let mut out = Vec::new();
        out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        out.extend_from_slice(&nfat.to_be_bytes());
        for (idx, (ctype, csub, data)) in slices.iter().enumerate() {
            out.extend_from_slice(&(*ctype as u32).to_be_bytes());
            out.extend_from_slice(&(*csub as u32).to_be_bytes());
            out.extend_from_slice(&(slice_offsets[idx] as u32).to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&12u32.to_be_bytes()); // align = 2^12
        }
        for (_, _, data) in slices {
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn split_two_arches() {
        let arm_payload = vec![0xCF, 0xFA, 0xED, 0xFE, 0u8, 0, 0, 0]; // fake arm64
        let x86_payload = vec![0xCE, 0xFA, 0xED, 0xFE, 0u8, 0, 0, 0]; // fake x86
        let fat = make_fake_fat(&[
            (0x0100_000C, 0, &arm_payload),
            (7, 3, &x86_payload),
        ]);
        let splitter = FatBinarySplitter::new(fat).unwrap();
        assert_eq!(splitter.arch_count(), 2);
        assert!(splitter.contains_arch(Arch::ARM64));
        assert!(splitter.contains_arch(Arch::X86));
        assert_eq!(splitter.arm64_slice().unwrap(), arm_payload.as_slice());
    }

    #[test]
    fn bad_magic() {
        let result = FatBinarySplitter::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]);
        assert!(matches!(result, Err(FatError::BadMagic(_))));
    }

    #[test]
    fn arch_display() {
        assert_eq!(Arch::X86_64.to_string(), "x86_64");
        assert_eq!(Arch::ARM64.to_string(), "arm64");
    }

    #[test]
    fn too_short() {
        let result = FatBinarySplitter::new(vec![0u8; 4]);
        assert!(matches!(result, Err(FatError::TooShort { .. })));
    }
}
