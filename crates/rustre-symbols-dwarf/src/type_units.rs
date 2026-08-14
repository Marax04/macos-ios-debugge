//! `type_units` — DWARF v4/v5 type unit support (`.debug_types` section).
//!
//! Type units allow type definitions to be shared across compilation units
//! via a stable 8-byte type signature.  This module provides:
//!
//! * [`TypeUnitHeader`] — parsed header of a `.debug_types` entry.
//! * [`TypeUnit`] — a complete type unit with header and raw DIE bytes.
//! * [`TypeSignatureIndex`] — maps 8-byte signatures to type definitions.
//! * [`find_type_by_signature`] — top-level lookup function.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── TypeUnitHeader ──────────────────────────────────────────────────────────

/// Header fields of a single DWARF type unit.
///
/// Layout (DWARF 4, 32-bit form):
///
/// ```text
/// unit_length   (4 bytes)
/// version       (2 bytes)
/// debug_abbrev_offset (4 bytes)
/// address_size  (1 byte)
/// type_signature (8 bytes)
/// type_offset   (4 or 8 bytes depending on 64-bit flag)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeUnitHeader {
    /// Total byte length of the unit (not counting the length field itself).
    pub unit_length: u64,
    /// DWARF version (4 or 5).
    pub version: u16,
    /// Byte offset into `.debug_abbrev` for this unit's abbreviation table.
    pub debug_abbrev_offset: u64,
    /// Pointer size in bytes (4 or 8).
    pub address_size: u8,
    /// Unique 8-byte type signature.
    pub type_signature: u64,
    /// Byte offset within this type unit to the DIE that defines the type.
    pub type_offset: u64,
    /// `true` if this is a 64-bit DWARF unit.
    pub is_64bit: bool,
}

impl TypeUnitHeader {
    /// Total header size in bytes.
    #[must_use]
    pub const fn header_size(&self) -> usize {
        // 32-bit form: 4 (len) + 2 (ver) + 4 (abbrev_off) + 1 (addr_sz) + 8 (sig) + 4 (type_off) = 23
        // 64-bit form: 4 (marker) + 8 (len) + 2 (ver) + 8 (abbrev_off) + 1 (addr_sz) + 8 (sig) + 8 (type_off) = 39
        if self.is_64bit { 39 } else { 23 }
    }
}

/// Parse a [`TypeUnitHeader`] from a byte slice starting at `offset`.
///
/// Returns the header and the new offset (i.e., `offset + bytes_consumed`).
///
/// Returns `None` if there are not enough bytes or the data is malformed.
#[must_use]
pub fn parse_type_unit_header(data: &[u8], offset: usize) -> Option<(TypeUnitHeader, usize)> {
    let mut off = offset;

    let read_u8 = |d: &[u8], o: &mut usize| -> Option<u8> {
        let v = *d.get(*o)?;
        *o += 1;
        Some(v)
    };
    let read_u16 = |d: &[u8], o: &mut usize| -> Option<u16> {
        if *o + 2 > d.len() {
            return None;
        }
        let v = u16::from_le_bytes([d[*o], d[*o + 1]]);
        *o += 2;
        Some(v)
    };
    let read_u32 = |d: &[u8], o: &mut usize| -> Option<u32> {
        if *o + 4 > d.len() {
            return None;
        }
        let v = u32::from_le_bytes(d[*o..*o + 4].try_into().ok()?);
        *o += 4;
        Some(v)
    };
    let read_u64 = |d: &[u8], o: &mut usize| -> Option<u64> {
        if *o + 8 > d.len() {
            return None;
        }
        let v = u64::from_le_bytes(d[*o..*o + 8].try_into().ok()?);
        *o += 8;
        Some(v)
    };

    // Unit length (may be 32-bit or 64-bit DWARF).
    let initial = read_u32(data, &mut off)?;
    let (is_64bit, unit_length) = if initial == 0xFFFF_FFFF {
        (true, read_u64(data, &mut off)?)
    } else {
        (false, u64::from(initial))
    };

    let version = read_u16(data, &mut off)?;
    if version < 4 {
        return None;
    } // type units only exist from DWARF 4

    let debug_abbrev_offset = if is_64bit {
        read_u64(data, &mut off)?
    } else {
        u64::from(read_u32(data, &mut off)?)
    };
    let address_size = read_u8(data, &mut off)?;
    let type_signature = read_u64(data, &mut off)?;
    let type_offset = if is_64bit {
        read_u64(data, &mut off)?
    } else {
        u64::from(read_u32(data, &mut off)?)
    };

    Some((
        TypeUnitHeader {
            unit_length,
            version,
            debug_abbrev_offset,
            address_size,
            type_signature,
            type_offset,
            is_64bit,
        },
        off,
    ))
}

// ─── TypeUnit ────────────────────────────────────────────────────────────────

/// A complete DWARF type unit: header plus the raw DIE bytes for the type body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeUnit {
    /// Parsed header.
    pub header: TypeUnitHeader,
    /// The raw bytes of the DIE content (after the header).
    pub die_bytes: Vec<u8>,
    /// Human-readable type name, if extracted.
    pub type_name: Option<String>,
}

impl TypeUnit {
    /// Create a type unit from header + raw DIE bytes.
    #[must_use]
    pub const fn new(header: TypeUnitHeader, die_bytes: Vec<u8>) -> Self {
        Self {
            header,
            die_bytes,
            type_name: None,
        }
    }

    /// Attach a resolved type name.
    #[must_use]
    pub fn with_type_name(mut self, name: impl Into<String>) -> Self {
        self.type_name = Some(name.into());
        self
    }

    /// The 8-byte type signature of this unit.
    #[must_use]
    pub const fn signature(&self) -> u64 {
        self.header.type_signature
    }

    /// DWARF version (4 or 5).
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.header.version
    }

    /// Byte size of the DIE body.
    #[must_use]
    pub const fn die_size(&self) -> usize {
        self.die_bytes.len()
    }
}

// ─── TypeSignatureIndex ───────────────────────────────────────────────────────

/// An index mapping 8-byte DWARF type signatures to [`TypeUnit`]s.
///
/// Build one by calling [`TypeSignatureIndex::from_debug_types`] or by
/// constructing it manually with [`TypeSignatureIndex::insert`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TypeSignatureIndex {
    units: HashMap<u64, TypeUnit>,
}

impl TypeSignatureIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a type unit.
    pub fn insert(&mut self, unit: TypeUnit) {
        self.units.insert(unit.signature(), unit);
    }

    /// Look up a type unit by its 8-byte signature.
    #[must_use]
    pub fn get(&self, signature: u64) -> Option<&TypeUnit> {
        self.units.get(&signature)
    }

    /// Number of type units in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Returns `true` if the index contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Return all type unit signatures as a sorted `Vec`.
    #[must_use]
    pub fn signatures(&self) -> Vec<u64> {
        let mut sigs: Vec<u64> = self.units.keys().copied().collect();
        sigs.sort_unstable();
        sigs
    }

    /// Parse all type units from a `.debug_types` section blob.
    ///
    /// Malformed entries are silently skipped.
    #[must_use]
    pub fn from_debug_types(data: &[u8]) -> Self {
        let mut index = Self::new();
        let mut off = 0usize;

        while off < data.len() {
            let start = off;
            let Some((hdr, after_header)) = parse_type_unit_header(data, off) else {
                break;
            };
            let unit_body_end = start
                + if hdr.is_64bit { 12 } else { 4 } // initial-length field
                + usize::try_from(hdr.unit_length).unwrap_or(usize::MAX);
            if unit_body_end > data.len() {
                break;
            }
            let die_bytes = data[after_header..unit_body_end].to_vec();
            index.insert(TypeUnit::new(hdr, die_bytes));
            off = unit_body_end;
        }

        index
    }
}

// ─── find_type_by_signature ───────────────────────────────────────────────────

/// Convenience wrapper: look up a type unit by its 8-byte signature in `index`.
///
/// Returns `None` if the signature is not present.
#[must_use]
pub fn find_type_by_signature(index: &TypeSignatureIndex, signature: u64) -> Option<&TypeUnit> {
    index.get(signature)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Header building helpers ──────────────────────────────────────────────

    /// Build a minimal 32-bit DWARF 4 type unit header blob.
    fn make_type_unit_blob(signature: u64, type_name: &str) -> Vec<u8> {
        // Minimal .debug_types entry layout (32-bit DWARF 4).
        // body = version(2) + abbrev_off(4) + addr_sz(1) + sig(8) + type_off(4) = 19 bytes
        // We append a fake DW_AT_name string so `die_bytes` is non-empty.
        let extra = type_name.as_bytes().to_vec();
        let body_len: u32 = 19 + extra.len() as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&body_len.to_le_bytes()); // unit_length
        buf.extend_from_slice(&4u16.to_le_bytes()); // version
        buf.extend_from_slice(&0u32.to_le_bytes()); // abbrev_offset
        buf.push(8); // address_size
        buf.extend_from_slice(&signature.to_le_bytes()); // type_signature
        buf.extend_from_slice(&0u32.to_le_bytes()); // type_offset
        buf.extend_from_slice(&extra); // fake DIE content
        buf
    }

    // ── TypeUnitHeader ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_type_unit_header() {
        let blob = make_type_unit_blob(0xDEAD_BEEF_0000_0001, "MyStruct");
        let (hdr, after) = parse_type_unit_header(&blob, 0).unwrap();
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.type_signature, 0xDEAD_BEEF_0000_0001);
        assert_eq!(hdr.address_size, 8);
        assert!(!hdr.is_64bit);
        assert!(after > 0);
    }

    #[test]
    fn test_header_size_32bit() {
        let hdr = TypeUnitHeader {
            unit_length: 0,
            version: 4,
            debug_abbrev_offset: 0,
            address_size: 8,
            type_signature: 0,
            type_offset: 0,
            is_64bit: false,
        };
        assert_eq!(hdr.header_size(), 23);
    }

    #[test]
    fn test_header_size_64bit() {
        let hdr = TypeUnitHeader {
            unit_length: 0,
            version: 4,
            debug_abbrev_offset: 0,
            address_size: 8,
            type_signature: 0,
            type_offset: 0,
            is_64bit: true,
        };
        assert_eq!(hdr.header_size(), 39);
    }

    // ── TypeUnit ─────────────────────────────────────────────────────────────

    #[test]
    fn test_type_unit_signature() {
        let blob = make_type_unit_blob(0x1234_5678_9ABC_DEF0, "Foo");
        let (hdr, _) = parse_type_unit_header(&blob, 0).unwrap();
        let unit = TypeUnit::new(hdr, vec![]);
        assert_eq!(unit.signature(), 0x1234_5678_9ABC_DEF0);
        assert_eq!(unit.version(), 4);
    }

    #[test]
    fn test_type_unit_with_name() {
        let blob = make_type_unit_blob(0xFF, "Bar");
        let (hdr, _) = parse_type_unit_header(&blob, 0).unwrap();
        let unit = TypeUnit::new(hdr, b"Bar\x00".to_vec()).with_type_name("Bar");
        assert_eq!(unit.type_name.as_deref(), Some("Bar"));
        assert_eq!(unit.die_size(), 4);
    }

    // ── TypeSignatureIndex ───────────────────────────────────────────────────

    #[test]
    fn test_index_insert_and_get() {
        let mut idx = TypeSignatureIndex::new();
        let blob = make_type_unit_blob(42, "T");
        let (hdr, _) = parse_type_unit_header(&blob, 0).unwrap();
        idx.insert(TypeUnit::new(hdr, vec![]));
        assert_eq!(idx.len(), 1);
        assert!(idx.get(42).is_some());
    }

    #[test]
    fn test_index_signatures_sorted() {
        let mut idx = TypeSignatureIndex::new();
        for sig in [30u64, 10, 20] {
            let blob = make_type_unit_blob(sig, "X");
            let (hdr, _) = parse_type_unit_header(&blob, 0).unwrap();
            idx.insert(TypeUnit::new(hdr, vec![]));
        }
        assert_eq!(idx.signatures(), vec![10, 20, 30]);
    }

    #[test]
    fn test_index_from_debug_types() {
        let mut data = Vec::new();
        data.extend(make_type_unit_blob(0xAABB, "TypeA"));
        data.extend(make_type_unit_blob(0xCCDD, "TypeB"));
        let idx = TypeSignatureIndex::from_debug_types(&data);
        assert_eq!(idx.len(), 2);
        assert!(idx.get(0xAABB).is_some());
        assert!(idx.get(0xCCDD).is_some());
    }

    #[test]
    fn test_find_type_by_signature() {
        let mut idx = TypeSignatureIndex::new();
        let blob = make_type_unit_blob(0xBEEF, "CoolType");
        let (hdr, _) = parse_type_unit_header(&blob, 0).unwrap();
        idx.insert(TypeUnit::new(hdr, vec![]).with_type_name("CoolType"));
        let found = find_type_by_signature(&idx, 0xBEEF).unwrap();
        assert_eq!(found.type_name.as_deref(), Some("CoolType"));
        assert!(find_type_by_signature(&idx, 0xDEAD).is_none());
    }

    #[test]
    fn test_index_empty() {
        let idx = TypeSignatureIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }
}
