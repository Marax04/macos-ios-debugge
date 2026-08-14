//! `mappings` — dyld shared cache memory mapping descriptors.
//!
//! A dyld shared cache is divided into a set of contiguous on-disk segments
//! that are each mapped at a specific virtual address.  This module parses
//! both the original `dyld_cache_mapping_info` structure and the extended
//! `dyld_cache_mapping_and_slide_info` structure introduced in dyld-940.

use super::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// VM Protection constants (matches <mach/vm_prot.h>)
// ─────────────────────────────────────────────────────────────────────────────

pub const VM_PROT_NONE: u32 = 0x00;
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;
pub const VM_PROT_COPY: u32 = 0x10;
pub const VM_PROT_NO_CHANGE: u32 = 0x08;

// ─────────────────────────────────────────────────────────────────────────────
// Mapping flags (dyld-940+)
// ─────────────────────────────────────────────────────────────────────────────

/// Mapping flag: this mapping contains auth pointers (arm64e).
pub const DYLD_CACHE_MAPPING_AUTH_DATA: u64 = 0x1;
/// Mapping flag: this mapping is dirty (written at runtime).
pub const DYLD_CACHE_MAPPING_DIRTY_DATA: u64 = 0x2;
/// Mapping flag: this mapping contains const data.
pub const DYLD_CACHE_MAPPING_CONST_DATA: u64 = 0x4;
/// Mapping flag: this mapping is text-stubs.
pub const DYLD_CACHE_MAPPING_TEXT_STUBS: u64 = 0x8;
/// Mapping flag: this mapping is read-execute linked (LINKEDIT).
pub const DYLD_CACHE_MAPPING_LINKEDIT: u64 = 0x10;

// ─────────────────────────────────────────────────────────────────────────────
// On-disk sizes
// ─────────────────────────────────────────────────────────────────────────────

/// Byte size of the original `dyld_cache_mapping_info` struct.
pub const MAPPING_INFO_SIZE: usize = 32;
/// Byte size of the extended `dyld_cache_mapping_and_slide_info` struct.
pub const MAPPING_AND_SLIDE_INFO_SIZE: usize = 56;

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheMappingInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_mapping_info` entry (original format, all versions).
///
/// Each entry describes one contiguous region of the shared cache file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheMappingInfo {
    /// Virtual address at which this region is mapped.
    pub address: u64,
    /// Byte size of the mapped region.
    pub size: u64,
    /// File offset of this region within the cache file.
    pub file_offset: u64,
    /// Maximum VM protection bits (`VM_PROT_*`).
    pub max_prot: u32,
    /// Initial VM protection bits (`VM_PROT_*`).
    pub init_prot: u32,
}

impl DyldCacheMappingInfo {
    /// Parse a single `DyldCacheMappingInfo` from raw bytes at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + MAPPING_INFO_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let d = &data[offset..];
        Ok(Self {
            address: read_u64(d, 0)?,
            size: read_u64(d, 8)?,
            file_offset: read_u64(d, 16)?,
            max_prot: read_u32(d, 24)?,
            init_prot: read_u32(d, 28)?,
        })
    }

    /// Parse all mapping entries from the cache file.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, DyldError> {
        let max_possible = data.len() / MAPPING_INFO_SIZE;
        let count_capped = (count as usize).min(max_possible);
        let mut mappings = Vec::with_capacity(count_capped);
        for i in 0..count as usize {
            let entry_offset = (offset as usize)
                .checked_add(i.checked_mul(MAPPING_INFO_SIZE).ok_or(DyldError::InvalidOffset(i as u64))?)
                .ok_or(DyldError::InvalidOffset(i as u64))?;
            mappings.push(Self::parse(data, entry_offset)?);
        }
        Ok(mappings)
    }

    /// Returns `true` if this mapping is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.init_prot & VM_PROT_READ != 0
    }

    /// Returns `true` if this mapping is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.init_prot & VM_PROT_WRITE != 0
    }

    /// Returns `true` if this mapping is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.init_prot & VM_PROT_EXECUTE != 0
    }

    /// Returns `true` if the virtual address `va` falls within this mapping.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.address && va < self.address.saturating_add(self.size)
    }

    /// Convert a virtual address to a file offset within this mapping.
    #[must_use]
    pub const fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if self.contains_va(va) {
            Some(self.file_offset.saturating_add(va - self.address))
        } else {
            None
        }
    }

    /// Returns a protection string like `"r-x"`.
    #[must_use]
    pub fn prot_string(&self) -> String {
        let r = if self.init_prot & VM_PROT_READ != 0 {
            'r'
        } else {
            '-'
        };
        let w = if self.init_prot & VM_PROT_WRITE != 0 {
            'w'
        } else {
            '-'
        };
        let x = if self.init_prot & VM_PROT_EXECUTE != 0 {
            'x'
        } else {
            '-'
        };
        format!("{r}{w}{x}")
    }

    /// Returns a human-readable label for the segment type (heuristic).
    #[must_use]
    pub const fn segment_label(&self) -> &'static str {
        let r = self.init_prot & VM_PROT_READ != 0;
        let w = self.init_prot & VM_PROT_WRITE != 0;
        let x = self.init_prot & VM_PROT_EXECUTE != 0;
        match (r, w, x) {
            (true, false, true) => "__TEXT",
            (true, false, false) => "__RODATA",
            (true, true, false) => "__DATA",
            (true, true, true) => "__DATA_CONST",
            _ => "?",
        }
    }

    /// End virtual address (exclusive).
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// End file offset (exclusive).
    #[must_use]
    pub const fn end_file_offset(&self) -> u64 {
        self.file_offset.saturating_add(self.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheMappingAndSlideInfo (extended, dyld-940+)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_mapping_and_slide_info` entry (dyld-940+).
///
/// This is a superset of `DyldCacheMappingInfo` that adds slide-fixup
/// information for per-mapping ASLR rebasing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheMappingAndSlideInfo {
    /// Underlying mapping info.
    pub mapping: DyldCacheMappingInfo,
    /// Slide-info file offset for this mapping (0 = no slide fixups).
    pub slide_info_file_offset: u64,
    /// Byte size of the slide-info blob.
    pub slide_info_file_size: u64,
    /// Flags — see `DYLD_CACHE_MAPPING_*` constants.
    pub flags: u64,
}

impl DyldCacheMappingAndSlideInfo {
    /// Parse a single `DyldCacheMappingAndSlideInfo` from raw bytes at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + MAPPING_AND_SLIDE_INFO_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let d = &data[offset..];
        let mapping = DyldCacheMappingInfo {
            address: read_u64(d, 0)?,
            size: read_u64(d, 8)?,
            file_offset: read_u64(d, 16)?,
            max_prot: read_u32(d, 24)?,
            init_prot: read_u32(d, 28)?,
        };
        Ok(Self {
            mapping,
            slide_info_file_offset: read_u64(d, 32)?,
            slide_info_file_size: read_u64(d, 40)?,
            flags: read_u64(d, 48)?,
        })
    }

    /// Parse all extended mapping entries.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, DyldError> {
        let mut mappings = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_offset = offset as usize + i * MAPPING_AND_SLIDE_INFO_SIZE;
            mappings.push(Self::parse(data, entry_offset)?);
        }
        Ok(mappings)
    }

    /// Returns `true` if this mapping contains auth (PAC-signed) pointers.
    #[must_use]
    pub const fn is_auth_data(&self) -> bool {
        self.flags & DYLD_CACHE_MAPPING_AUTH_DATA != 0
    }

    /// Returns `true` if this mapping contains dirty (runtime-writable) data.
    #[must_use]
    pub const fn is_dirty_data(&self) -> bool {
        self.flags & DYLD_CACHE_MAPPING_DIRTY_DATA != 0
    }

    /// Returns `true` if this mapping is const (read-only after init).
    #[must_use]
    pub const fn is_const_data(&self) -> bool {
        self.flags & DYLD_CACHE_MAPPING_CONST_DATA != 0
    }

    /// Returns `true` if this mapping has associated slide-fixup data.
    #[must_use]
    pub const fn has_slide_info(&self) -> bool {
        self.slide_info_file_offset != 0 && self.slide_info_file_size != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MappingSet — convenience wrapper over a collection of mappings
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of parsed cache mappings with lookup helpers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MappingSet {
    pub entries: Vec<DyldCacheMappingInfo>,
}

impl MappingSet {
    /// Construct from a `Vec<DyldCacheMappingInfo>`.
    #[must_use]
    pub const fn new(entries: Vec<DyldCacheMappingInfo>) -> Self {
        Self { entries }
    }

    /// Find the mapping that contains virtual address `va`.
    #[must_use]
    pub fn mapping_for_va(&self, va: u64) -> Option<&DyldCacheMappingInfo> {
        self.entries.iter().find(|m| m.contains_va(va))
    }

    /// Convert a virtual address to a file offset.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.mapping_for_va(va)?.va_to_file_offset(va)
    }

    /// Returns the lowest virtual address covered by any mapping.
    #[must_use]
    pub fn lowest_va(&self) -> u64 {
        self.entries.iter().map(|m| m.address).min().unwrap_or(0)
    }

    /// Returns the highest virtual address (exclusive) covered.
    #[must_use]
    pub fn highest_va(&self) -> u64 {
        self.entries
            .iter()
            .map(DyldCacheMappingInfo::end_address)
            .max()
            .unwrap_or(0)
    }

    /// Returns the total virtual address span.
    #[must_use]
    pub fn virtual_span(&self) -> u64 {
        self.highest_va().saturating_sub(self.lowest_va())
    }

    /// Returns the number of executable mappings.
    #[must_use]
    pub fn exec_mapping_count(&self) -> usize {
        self.entries.iter().filter(|m| m.is_executable()).count()
    }

    /// Returns the number of writable mappings.
    #[must_use]
    pub fn writable_mapping_count(&self) -> usize {
        self.entries.iter().filter(|m| m.is_writable()).count()
    }

    /// Read `len` bytes from the cache data at virtual address `va`.
    #[must_use]
    pub fn read_at_va<'a>(&self, data: &'a [u8], va: u64, len: usize) -> Option<&'a [u8]> {
        let file_off = self.va_to_file_offset(va)? as usize;
        let end = file_off.checked_add(len)?;
        data.get(file_off..end)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
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

    fn make_mapping_bytes(addr: u64, size: u64, file_off: u64, max: u32, init: u32) -> Vec<u8> {
        let mut b = vec![0u8; MAPPING_INFO_SIZE];
        b[0..8].copy_from_slice(&addr.to_le_bytes());
        b[8..16].copy_from_slice(&size.to_le_bytes());
        b[16..24].copy_from_slice(&file_off.to_le_bytes());
        b[24..28].copy_from_slice(&max.to_le_bytes());
        b[28..32].copy_from_slice(&init.to_le_bytes());
        b
    }

    #[test]
    fn test_parse_mapping_info() {
        let raw = make_mapping_bytes(0x0001_8000_0000, 0x0400_0000, 0x4000, 5, 5);
        let m = DyldCacheMappingInfo::parse(&raw, 0).expect("parse");
        assert_eq!(m.address, 0x0001_8000_0000);
        assert_eq!(m.size, 0x0400_0000);
        assert_eq!(m.file_offset, 0x4000);
        assert_eq!(m.max_prot, 5);
        assert_eq!(m.init_prot, 5);
        assert!(m.is_readable());
        assert!(m.is_executable());
        assert!(!m.is_writable());
    }

    #[test]
    fn test_contains_va() {
        let raw = make_mapping_bytes(0x1000, 0x1000, 0x0, 5, 5);
        let m = DyldCacheMappingInfo::parse(&raw, 0).expect("parse");
        assert!(m.contains_va(0x1000));
        assert!(m.contains_va(0x1FFF));
        assert!(!m.contains_va(0x2000));
        assert!(!m.contains_va(0x0FFF));
    }

    #[test]
    fn test_va_to_file_offset() {
        let raw = make_mapping_bytes(0x10000, 0x5000, 0x100, 5, 5);
        let m = DyldCacheMappingInfo::parse(&raw, 0).expect("parse");
        assert_eq!(m.va_to_file_offset(0x10000), Some(0x100));
        assert_eq!(m.va_to_file_offset(0x10100), Some(0x200));
        assert_eq!(m.va_to_file_offset(0x15000), None);
    }

    #[test]
    fn test_prot_string() {
        let raw = make_mapping_bytes(0, 0, 0, 7, VM_PROT_READ | VM_PROT_EXECUTE);
        let m = DyldCacheMappingInfo::parse(&raw, 0).expect("parse");
        assert_eq!(m.prot_string(), "r-x");
    }

    #[test]
    fn test_mapping_set_lookup() {
        let m1 = DyldCacheMappingInfo::parse(
            &make_mapping_bytes(0x1000, 0x1000, 0x0, 5, VM_PROT_READ | VM_PROT_EXECUTE),
            0,
        )
        .unwrap();
        let m2 = DyldCacheMappingInfo::parse(
            &make_mapping_bytes(0x2000, 0x1000, 0x1000, 3, VM_PROT_READ | VM_PROT_WRITE),
            0,
        )
        .unwrap();
        let set = MappingSet::new(vec![m1, m2]);
        assert_eq!(set.va_to_file_offset(0x1500), Some(0x500));
        assert_eq!(set.va_to_file_offset(0x2800), Some(0x1800));
        assert_eq!(set.va_to_file_offset(0x9000), None);
        assert_eq!(set.exec_mapping_count(), 1);
        assert_eq!(set.writable_mapping_count(), 1);
    }

    #[test]
    fn test_extended_mapping_parse() {
        let mut raw = vec![0u8; MAPPING_AND_SLIDE_INFO_SIZE];
        // address=0x100000, size=0x200000, file_offset=0x1000
        raw[0..8].copy_from_slice(&0x0010_0000_u64.to_le_bytes());
        raw[8..16].copy_from_slice(&0x0020_0000_u64.to_le_bytes());
        raw[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        raw[24..28].copy_from_slice(&5u32.to_le_bytes()); // max_prot
        raw[28..32].copy_from_slice(&5u32.to_le_bytes()); // init_prot
        // slide_info_file_offset=0x500000, size=0x1000
        raw[32..40].copy_from_slice(&0x0050_0000_u64.to_le_bytes());
        raw[40..48].copy_from_slice(&0x1000u64.to_le_bytes());
        // flags = AUTH_DATA
        raw[48..56].copy_from_slice(&DYLD_CACHE_MAPPING_AUTH_DATA.to_le_bytes());

        let m = DyldCacheMappingAndSlideInfo::parse(&raw, 0).expect("parse");
        assert_eq!(m.mapping.address, 0x0010_0000);
        assert!(m.is_auth_data());
        assert!(m.has_slide_info());
        assert!(!m.is_dirty_data());
    }

    #[test]
    fn test_parse_all() {
        let mut raw = Vec::new();
        for i in 0u64..3 {
            raw.extend_from_slice(&(0x1000u64 * (i + 1)).to_le_bytes()); // addr
            raw.extend_from_slice(&0x1000u64.to_le_bytes()); // size
            raw.extend_from_slice(&(0x100u64 * (i + 1)).to_le_bytes()); // file_off
            raw.extend_from_slice(&5u32.to_le_bytes()); // max_prot
            raw.extend_from_slice(&5u32.to_le_bytes()); // init_prot
        }
        let mappings = DyldCacheMappingInfo::parse_all(&raw, 0, 3).expect("parse_all");
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[2].address, 0x3000);
    }
}
