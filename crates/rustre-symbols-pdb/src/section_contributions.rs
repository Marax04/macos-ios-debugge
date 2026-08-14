//! `section_contributions` — maps `(segment, offset)` to module indices.
//!
//! The `DBI` section-contributions sub-stream records which address range in the
//! final binary came from which module (object file / import library entry).
//! This enables "who owns this code?" queries.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::stream_reader::StreamReader;

// ── SectionContrib ────────────────────────────────────────────────────────────

/// One section-contribution record: a contiguous range in the binary that
/// originated from `module_idx`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionContrib {
    /// Zero-based index into the module table.
    pub module_idx: u16,
    /// PE section number (1-based).
    pub segment: u16,
    /// Byte offset within the section.
    pub offset: u32,
    /// Byte length of the contribution.
    pub size: u32,
    /// PE section characteristics flags (`IMAGE_SCN`_*).
    pub characteristics: u32,
}

impl SectionContrib {
    /// True when `(seg, off)` falls inside this contribution.
    #[must_use]
    pub const fn contains(&self, seg: u16, off: u32) -> bool {
        seg == self.segment && off >= self.offset && off.wrapping_sub(self.offset) < self.size
    }

    /// True when this contribution is executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        // IMAGE_SCN_CNT_CODE = 0x20 | IMAGE_SCN_MEM_EXECUTE = 0x2000_0000
        self.characteristics & 0x20 != 0 || self.characteristics & 0x2000_0000 != 0
    }

    /// True when this contribution is initialised data.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.characteristics & 0x40 != 0
    }

    /// True when this contribution is read-only data.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        // IMAGE_SCN_MEM_READ but NOT IMAGE_SCN_MEM_WRITE
        let read = 0x4000_0000u32;
        let write = 0x8000_0000u32;
        self.characteristics & read != 0 && self.characteristics & write == 0
    }
}

// ── Version 2 header signature ────────────────────────────────────────────────

const SC_V2_MAGIC: u32 = 0xEFFE_0000 + 19_970_605;

// ── parse_section_contribs ────────────────────────────────────────────────────

/// Parse the section-contributions sub-stream of the `DBI` stream.
///
/// Format (V1): `[SectionContribEntry42]` repeated.
/// Format (V2): `magic(4)` then `[SectionContribEntry2]` (adds `isect_coff` field).
///
/// Each V1 entry: `segment(2)+pad(2)+offset(4)+size(4)+characteristics(4)+module_idx(2)+pad(2)+data_crc(4)+reloc_crc(4)` = 28 bytes.
/// Each V2 entry: V1 + `isect_coff(4)` = 32 bytes.
///
/// # Errors
/// Returns an error if parsing/reading fails.
pub fn parse_section_contribs(data: &[u8]) -> Result<Vec<SectionContrib>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut rdr = StreamReader::new(data);

    // Check for V2 magic.
    let first_u32 = rdr.read_u32()?;
    let (is_v2, _skip) = if first_u32 == SC_V2_MAGIC {
        (true, 0usize)
    } else {
        (false, 0usize)
    };

    if !is_v2 {
        // V1: rewind to start (the first u32 is actually the segment field of the first entry).
        rdr.seek(0);
    }

    let entry_size = if is_v2 { 32usize } else { 28usize };
    let mut contribs = Vec::new();

    while rdr.remaining() >= entry_size {
        let segment = rdr.read_u16()?;
        let _pad1 = rdr.read_u16()?;
        let offset = rdr.read_u32()?;
        let size = rdr.read_u32()?;
        let characteristics = rdr.read_u32()?;
        let module_idx = rdr.read_u16()?;
        let _pad2 = rdr.read_u16()?;
        let _data_crc = rdr.read_u32()?;
        let _reloc_crc = rdr.read_u32()?;
        if is_v2 {
            let _isect_coff = rdr.read_u32()?;
        }

        contribs.push(SectionContrib {
            module_idx,
            segment,
            offset,
            size,
            characteristics,
        });
    }

    Ok(contribs)
}

// ── find_module_for_address ───────────────────────────────────────────────────

/// Return the module index that owns `(seg, off)`, or `None` if not found.
#[must_use]
pub fn find_module_for_address(contribs: &[SectionContrib], seg: u16, off: u32) -> Option<u16> {
    // Linear scan — for large binaries a sorted + binary-search approach would
    // be faster, but correctness is identical.
    contribs
        .iter()
        .find(|c| c.contains(seg, off))
        .map(|c| c.module_idx)
}

/// Sort contributions by `(segment, offset)` for binary-search lookups.
pub fn sort_contribs(contribs: &mut [SectionContrib]) {
    contribs.sort_by(|a, b| a.segment.cmp(&b.segment).then(a.offset.cmp(&b.offset)));
}

/// Binary-search variant of `find_module_for_address` (requires sorted input).
#[must_use]
pub fn find_module_sorted(contribs: &[SectionContrib], seg: u16, off: u32) -> Option<u16> {
    // Find the last contribution whose (seg, offset) ≤ query.
    let idx =
        contribs.partition_point(|c| c.segment < seg || (c.segment == seg && c.offset <= off));
    if idx == 0 {
        return None;
    }
    let c = &contribs[idx - 1];
    if c.contains(seg, off) {
        Some(c.module_idx)
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v1_entry(seg: u16, off: u32, size: u32, module: u16, chars: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&seg.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // pad
        v.extend_from_slice(&off.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&chars.to_le_bytes());
        v.extend_from_slice(&module.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // pad
        v.extend_from_slice(&0u32.to_le_bytes()); // data_crc
        v.extend_from_slice(&0u32.to_le_bytes()); // reloc_crc
        assert_eq!(v.len(), 28);
        v
    }

    #[test]
    fn test_parse_v1_single() {
        let data = make_v1_entry(1, 0x1000, 0x100, 5, 0x20);
        let contribs = parse_section_contribs(&data).unwrap();
        assert_eq!(contribs.len(), 1);
        assert_eq!(contribs[0].segment, 1);
        assert_eq!(contribs[0].offset, 0x1000);
        assert_eq!(contribs[0].size, 0x100);
        assert_eq!(contribs[0].module_idx, 5);
    }

    #[test]
    fn test_parse_v1_multiple() {
        let mut data = make_v1_entry(1, 0x1000, 0x100, 0, 0x20);
        data.extend(make_v1_entry(1, 0x2000, 0x200, 1, 0x40));
        let contribs = parse_section_contribs(&data).unwrap();
        assert_eq!(contribs.len(), 2);
    }

    #[test]
    fn test_find_module_for_address() {
        let mut data = make_v1_entry(1, 0x1000, 0x100, 7, 0x20);
        data.extend(make_v1_entry(1, 0x2000, 0x200, 8, 0x40));
        let contribs = parse_section_contribs(&data).unwrap();

        assert_eq!(find_module_for_address(&contribs, 1, 0x1050), Some(7));
        assert_eq!(find_module_for_address(&contribs, 1, 0x2100), Some(8));
        assert!(find_module_for_address(&contribs, 1, 0x5000).is_none());
    }

    #[test]
    fn test_find_module_sorted() {
        let mut contribs = vec![
            SectionContrib {
                module_idx: 2,
                segment: 1,
                offset: 0x2000,
                size: 0x100,
                characteristics: 0,
            },
            SectionContrib {
                module_idx: 1,
                segment: 1,
                offset: 0x1000,
                size: 0x100,
                characteristics: 0,
            },
        ];
        sort_contribs(&mut contribs);
        assert_eq!(find_module_sorted(&contribs, 1, 0x1050), Some(1));
        assert_eq!(find_module_sorted(&contribs, 1, 0x2010), Some(2));
        assert!(find_module_sorted(&contribs, 1, 0x0100).is_none());
    }

    #[test]
    fn test_section_contrib_contains() {
        let c = SectionContrib {
            module_idx: 0,
            segment: 2,
            offset: 0x100,
            size: 0x40,
            characteristics: 0,
        };
        assert!(c.contains(2, 0x100));
        assert!(c.contains(2, 0x13F));
        assert!(!c.contains(2, 0x140));
        assert!(!c.contains(1, 0x100));
    }

    #[test]
    fn test_section_contrib_is_code() {
        let code = SectionContrib {
            module_idx: 0,
            segment: 1,
            offset: 0,
            size: 0x100,
            characteristics: 0x20,
        };
        assert!(code.is_code());
    }

    #[test]
    fn test_section_contrib_is_read_only() {
        let ro = SectionContrib {
            module_idx: 0,
            segment: 2,
            offset: 0,
            size: 0x100,
            characteristics: 0x4000_0000,
        };
        assert!(ro.is_read_only());
        let rw = SectionContrib {
            characteristics: 0xC000_0000,
            ..ro
        };
        assert!(!rw.is_read_only());
    }

    #[test]
    fn test_empty_input() {
        let contribs = parse_section_contribs(&[]).unwrap();
        assert!(contribs.is_empty());
    }

    #[test]
    fn test_sort_contribs() {
        let mut v = vec![
            SectionContrib {
                module_idx: 1,
                segment: 1,
                offset: 0x2000,
                size: 1,
                characteristics: 0,
            },
            SectionContrib {
                module_idx: 0,
                segment: 1,
                offset: 0x1000,
                size: 1,
                characteristics: 0,
            },
        ];
        sort_contribs(&mut v);
        assert_eq!(v[0].offset, 0x1000);
        assert_eq!(v[1].offset, 0x2000);
    }
}
