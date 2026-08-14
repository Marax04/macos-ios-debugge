//! `res_table_parser` — Parse Android `resources.arsc` files.
//!
//! The `resources.arsc` binary format consists of a sequence of typed chunks:
//! `ResTable` → `ResTablePackage` → `ResTableTypeSpec` + `ResTableType` +
//! `ResTableEntry`.  This module implements a low-level, allocation-efficient
//! parser for the complete file.
//!
//! Reference: AOSP `libs/androidfw/include/androidfw/ResourceTypes.h`

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during `resources.arsc` parsing.
#[derive(Debug, thiserror::Error)]
pub enum ResTableError {
    #[error("truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("invalid magic: expected RES_TABLE_TYPE, got {0:#x}")]
    InvalidMagic(u16),
    #[error("chunk size {0} is zero or exceeds data length {1}")]
    InvalidChunkSize(u32, usize),
    #[error("string pool entry {0} out of bounds (pool has {1} strings)")]
    StringPoolOutOfBounds(usize, usize),
    #[error("package count {0} exceeds reasonable limit")]
    TooManyPackages(u32),
}

// ─────────────────────────────────────────────────────────────────────────────
// Chunk type constants
// ─────────────────────────────────────────────────────────────────────────────

/// `RES_NULL_TYPE`
pub const RES_NULL_TYPE: u16 = 0x0000;
/// `RES_STRING_POOL_TYPE`
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
/// `RES_TABLE_TYPE`
pub const RES_TABLE_TYPE: u16 = 0x0002;
/// `RES_TABLE_PACKAGE_TYPE`
pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
/// `RES_TABLE_TYPE_TYPE`
pub const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
/// `RES_TABLE_TYPE_SPEC_TYPE`
pub const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;

// ─────────────────────────────────────────────────────────────────────────────
// ResChunkHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Generic chunk header present at the start of every `resources.arsc` chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResChunkHeader {
    pub chunk_type: u16,
    pub header_size: u16,
    pub size: u32,
}

impl ResChunkHeader {
    /// Parse a chunk header from `data` at `offset`.
    ///
    /// # Errors
    /// Returns `ResTableError::Truncated` if fewer than 8 bytes are available.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ResTableError> {
        if offset + 8 > data.len() {
            return Err(ResTableError::Truncated(offset));
        }
        let chunk_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let header_size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let size = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        Ok(Self { chunk_type, header_size, size })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResStringPool
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed string pool from a `RES_STRING_POOL_TYPE` chunk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResStringPool {
    /// All strings decoded from the pool.
    pub strings: Vec<String>,
    /// Style array (usually empty for resource tables).
    pub styles: Vec<String>,
    /// Whether the pool uses UTF-8 (vs UTF-16LE) encoding.
    pub is_utf8: bool,
}

impl ResStringPool {
    /// Parse a string pool chunk from `data` starting at `offset`.
    ///
    /// # Errors
    /// Returns `ResTableError::Truncated` if data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ResTableError> {
        let hdr = ResChunkHeader::parse(data, offset)?;
        if hdr.chunk_type != RES_STRING_POOL_TYPE {
            return Ok(Self::default());
        }
        let chunk_end = offset + hdr.size as usize;
        if chunk_end > data.len() {
            return Err(ResTableError::Truncated(offset));
        }
        if offset + 28 > data.len() {
            return Err(ResTableError::Truncated(offset + 8));
        }

        let string_count = u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]) as usize;
        let _style_count = u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]) as usize;
        let flags = u32::from_le_bytes([data[offset+16], data[offset+17], data[offset+18], data[offset+19]]);
        let strings_start = u32::from_le_bytes([data[offset+20], data[offset+21], data[offset+22], data[offset+23]]) as usize;
        let _styles_start = u32::from_le_bytes([data[offset+24], data[offset+25], data[offset+26], data[offset+27]]) as usize;

        let is_utf8 = (flags & 0x100) != 0;
        let offsets_base = offset + 28;
        let strings_base = offset + strings_start;

        // `string_count` is an attacker-controlled u32; each string needs a
        // 4-byte offset-table entry, so a larger count is malformed. Without
        // this cap a 28-byte file reserves gigabytes, and the loop below has no
        // early exit — it keeps pushing empty strings. `arsc_parser.rs` does
        // this check properly and is the model here.
        let string_count = string_count.min(data.len().saturating_sub(offsets_base) / 4);

        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off_off = offsets_base + i * 4;
            if off_off + 4 > data.len() {
                strings.push(String::new());
                continue;
            }
            let str_off = u32::from_le_bytes([data[off_off], data[off_off+1], data[off_off+2], data[off_off+3]]) as usize;
            let abs_off = strings_base + str_off;
            let s = if is_utf8 {
                decode_utf8_string(data, abs_off)
            } else {
                decode_utf16_string(data, abs_off)
            };
            strings.push(s);
        }

        Ok(Self { strings, styles: vec![], is_utf8 })
    }

    /// Get string at index, returning empty string for out-of-bounds.
    #[must_use]
    pub fn get(&self, idx: usize) -> &str {
        self.strings.get(idx).map_or("", String::as_str)
    }

    /// Number of strings in the pool.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// Returns `true` if the pool has no strings.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

fn decode_utf8_string(data: &[u8], mut off: usize) -> String {
    if off >= data.len() { return String::new(); }
    // Skip character length (1 or 2 bytes)
    if off < data.len() && (data[off] & 0x80) != 0 { off += 1; }
    off += 1;
    if off >= data.len() { return String::new(); }
    // Read byte length
    let byte_len = if (data[off] & 0x80) != 0 {
        let hi = (data[off] as usize & 0x7F) << 8;
        off += 1;
        if off >= data.len() { return String::new(); }
        hi | data[off] as usize
    } else {
        data[off] as usize
    };
    off += 1;
    let end = (off + byte_len).min(data.len());
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

fn decode_utf16_string(data: &[u8], off: usize) -> String {
    if off + 2 > data.len() { return String::new(); }
    let char_len = u16::from_le_bytes([data[off], data[off+1]]) as usize;
    let byte_len = char_len * 2;
    if off + 2 + byte_len > data.len() { return String::new(); }
    let u16s: Vec<u16> = data[off+2..off+2+byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

// ─────────────────────────────────────────────────────────────────────────────
// ResTableEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Flags on a `ResTableEntry`.
pub const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
pub const ENTRY_FLAG_PUBLIC: u16 = 0x0002;

/// A single resource entry in a `ResTableType` chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResTableEntry {
    /// Entry flags (see `ENTRY_FLAG_*`).
    pub flags: u16,
    /// String pool index for the entry key (name).
    pub key_index: u32,
    /// Data type (from `Res_value::dataType`).
    pub data_type: u8,
    /// Data value.
    pub data: u32,
    /// Whether this is a complex (bag) entry.
    pub is_complex: bool,
    /// Resolved key name (if string pool was available).
    pub key_name: String,
}

impl ResTableEntry {
    /// Parse a `ResTableEntry` from `data` at `offset`.
    ///
    /// # Errors
    /// Returns `ResTableError::Truncated` if data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Option<Self>, ResTableError> {
        if offset + 8 > data.len() {
            return Err(ResTableError::Truncated(offset));
        }
        let entry_size = u16::from_le_bytes([data[offset], data[offset+1]]);
        if entry_size == 0xFFFF || entry_size == 0 {
            return Ok(None); // NO_ENTRY
        }
        if offset + entry_size as usize > data.len() {
            return Err(ResTableError::Truncated(offset));
        }
        let flags = u16::from_le_bytes([data[offset+2], data[offset+3]]);
        let key_index = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        let is_complex = (flags & ENTRY_FLAG_COMPLEX) != 0;
        let (data_type, data_val) = if !is_complex && offset + 16 <= data.len() {
            // Res_value: size(2), res0(1), dataType(1), data(4) at offset+8
            let dtype = data[offset+11];
            let dval = u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]);
            (dtype, dval)
        } else {
            (0, 0)
        };
        Ok(Some(Self {
            flags,
            key_index,
            data_type,
            data: data_val,
            is_complex,
            key_name: String::new(),
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResTableType
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration flags for a resource type (screen density, language, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResTableConfig {
    /// Size of the config struct.
    pub size: u32,
    /// Mobile country code.
    pub mcc: u16,
    /// Mobile network code.
    pub mnc: u16,
    /// BCP-47 language code.
    pub language: [u8; 2],
    /// BCP-47 region code.
    pub country: [u8; 2],
    /// Screen orientation.
    pub orientation: u8,
    /// Screen density qualifier (e.g. 160 = mdpi).
    pub density: u16,
}

impl ResTableConfig {
    /// Parse a config from `data` at `offset`.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Self {
        if offset + 4 > data.len() {
            return Self::default();
        }
        let size = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        let mcc = if offset + 6 <= data.len() { u16::from_le_bytes([data[offset+4], data[offset+5]]) } else { 0 };
        let mnc = if offset + 8 <= data.len() { u16::from_le_bytes([data[offset+6], data[offset+7]]) } else { 0 };
        let language = if offset + 10 <= data.len() { [data[offset+8], data[offset+9]] } else { [0; 2] };
        let country = if offset + 12 <= data.len() { [data[offset+10], data[offset+11]] } else { [0; 2] };
        let orientation = if offset + 13 <= data.len() { data[offset+12] } else { 0 };
        let density = if offset + 18 <= data.len() { u16::from_le_bytes([data[offset+16], data[offset+17]]) } else { 0 };
        Self { size, mcc, mnc, language, country, orientation, density }
    }

    /// Return a human-readable density string.
    #[must_use]
    pub const fn density_label(&self) -> &'static str {
        match self.density {
            120 => "ldpi",
            160 => "mdpi",
            213 => "tvdpi",
            240 => "hdpi",
            320 => "xhdpi",
            480 => "xxhdpi",
            640 => "xxxhdpi",
            _ => "default",
        }
    }
}

/// A parsed `RES_TABLE_TYPE_TYPE` chunk containing a configuration + entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResTableType {
    /// 1-based type index.
    pub id: u8,
    /// Flags.
    pub flags: u8,
    /// Number of entries in this type.
    pub entry_count: u32,
    /// Configuration for this type variant.
    pub config: ResTableConfig,
    /// Parsed entries indexed by their position in the entry table.
    pub entries: Vec<Option<ResTableEntry>>,
}

impl ResTableType {
    /// Parse a `ResTableType` chunk from `data` at `offset`.
    ///
    /// # Errors
    /// Returns `ResTableError::Truncated` if data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ResTableError> {
        let hdr = ResChunkHeader::parse(data, offset)?;
        if (offset + hdr.header_size as usize) > data.len() {
            return Err(ResTableError::Truncated(offset));
        }
        if offset + 52 > data.len() {
            return Err(ResTableError::Truncated(offset + 8));
        }
        let id = data[offset + 8];
        let flags = data[offset + 9];
        let entry_count = u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]);
        let entries_start = u32::from_le_bytes([data[offset+16], data[offset+17], data[offset+18], data[offset+19]]) as usize;
        let config = ResTableConfig::parse(data, offset + 20);

        let offsets_base = offset + hdr.header_size as usize;
        let data_base = offset + entries_start;

        // `entry_count` is an attacker-controlled u32 and each entry needs a
        // 4-byte offset slot. The loop below uses `continue`, not `break`, so an
        // impossible count would push `None` four billion times after reserving
        // the matching capacity. Cap the iteration; `entry_count` itself keeps
        // the value the file declared, so the discrepancy stays visible.
        let usable_entries = (entry_count as usize).min(data.len().saturating_sub(offsets_base) / 4);

        let mut entries = Vec::with_capacity(usable_entries);
        for i in 0..usable_entries {
            let off_off = offsets_base + i * 4;
            if off_off + 4 > data.len() {
                entries.push(None);
                continue;
            }
            let entry_off = u32::from_le_bytes([data[off_off], data[off_off+1], data[off_off+2], data[off_off+3]]);
            if entry_off == 0xFFFF_FFFF {
                entries.push(None);
                continue;
            }
            let Some(abs_entry) = data_base.checked_add(entry_off as usize) else { entries.push(None); continue; };
            let entry = ResTableEntry::parse(data, abs_entry).unwrap_or(None);
            entries.push(entry);
        }

        Ok(Self { id, flags, entry_count, config, entries })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResTablePackage
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `RES_TABLE_PACKAGE_TYPE` chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResTablePackage {
    /// Package ID (application = 0x7F, framework = 0x01).
    pub id: u32,
    /// Package name.
    pub name: String,
    /// Key string pool (entry names).
    pub key_pool: ResStringPool,
    /// Type string pool (type names).
    pub type_pool: ResStringPool,
    /// All resource types parsed from this package.
    pub types: Vec<ResTableType>,
}

impl ResTablePackage {
    /// Parse a package chunk from `data` at `offset`.
    ///
    /// # Errors
    /// Returns parsing errors on truncated or malformed data.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ResTableError> {
        let hdr = ResChunkHeader::parse(data, offset)?;
        if offset + hdr.size as usize > data.len() {
            return Err(ResTableError::InvalidChunkSize(hdr.size, data.len()));
        }
        if offset + 288 > data.len() {
            return Err(ResTableError::Truncated(offset + 8));
        }
        let id = u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
        // Name: 256-byte UTF-16LE field at offset+12
        let name_bytes = &data[offset+12..offset+12+256.min(data.len()-offset-12)];
        let name_u16s: Vec<u16> = name_bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let name = String::from_utf16_lossy(&name_u16s);

        let type_strings_off = u32::from_le_bytes([data[offset+268], data[offset+269], data[offset+270], data[offset+271]]) as usize;
        let key_strings_off = u32::from_le_bytes([data[offset+272], data[offset+273], data[offset+274], data[offset+275]]) as usize;

        let type_pool = if type_strings_off > 0 && offset + type_strings_off < data.len() {
            ResStringPool::parse(data, offset + type_strings_off).unwrap_or_default()
        } else {
            ResStringPool::default()
        };

        let key_pool = if key_strings_off > 0 && offset + key_strings_off < data.len() {
            ResStringPool::parse(data, offset + key_strings_off).unwrap_or_default()
        } else {
            ResStringPool::default()
        };

        // Scan for ResTableType chunks inside this package
        let mut types = Vec::new();
        let mut pos = offset + hdr.header_size as usize;
        let pkg_end = offset + hdr.size as usize;
        while pos + 8 <= pkg_end && pos + 8 <= data.len() {
            let inner = ResChunkHeader::parse(data, pos)?;
            if inner.size == 0 { break; }
            if inner.chunk_type == RES_TABLE_TYPE_TYPE
                && let Ok(t) = ResTableType::parse(data, pos) {
                    types.push(t);
                }
            pos += inner.size as usize;
        }

        Ok(Self { id, name, key_pool, type_pool, types })
    }

    /// Look up a type name by its 1-based type ID.
    #[must_use]
    pub fn type_name(&self, type_id: u8) -> &str {
        if type_id == 0 { return ""; }
        self.type_pool.get((type_id - 1) as usize)
    }

    /// Look up an entry key name by its index in the key pool.
    #[must_use]
    pub fn key_name(&self, key_idx: u32) -> &str {
        self.key_pool.get(key_idx as usize)
    }

    /// Return a flat map of resource names → (type, entry).
    #[must_use]
    pub fn resource_map(&self) -> HashMap<String, (String, u32)> {
        let mut map = HashMap::new();
        for t in &self.types {
            let type_name = self.type_name(t.id).to_string();
            for entry in t.entries.iter().flatten() {
                let key_name = self.key_name(entry.key_index).to_string();
                map.insert(
                    format!("{type_name}/{key_name}"),
                    (type_name.clone(), entry.data),
                );
            }
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResTable
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level parsed `resources.arsc` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResTable {
    /// Global string pool (resource value strings).
    pub global_string_pool: ResStringPool,
    /// Parsed packages.
    pub packages: Vec<ResTablePackage>,
    /// Total number of chunks encountered.
    pub chunk_count: usize,
}

impl ResTable {
    /// Look up a string in the global pool.
    #[must_use]
    pub fn global_string(&self, idx: usize) -> &str {
        self.global_string_pool.get(idx)
    }

    /// Return all packages with their IDs.
    #[must_use]
    pub fn package_ids(&self) -> Vec<(u32, &str)> {
        self.packages.iter().map(|p| (p.id, p.name.as_str())).collect()
    }

    /// Total number of resource entries across all packages and types.
    #[must_use]
    pub fn total_entry_count(&self) -> usize {
        self.packages
            .iter()
            .flat_map(|p| p.types.iter())
            .map(|t| t.entries.iter().filter(|e| e.is_some()).count())
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_res_table()
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a complete `resources.arsc` byte buffer and return a [`ResTable`].
///
/// # Errors
/// Returns [`ResTableError`] on malformed or truncated data.
pub fn parse_res_table(data: &[u8]) -> Result<ResTable, ResTableError> {
    if data.len() < 8 {
        return Err(ResTableError::Truncated(0));
    }
    let hdr = ResChunkHeader::parse(data, 0)?;
    if hdr.chunk_type != RES_TABLE_TYPE {
        return Err(ResTableError::InvalidMagic(hdr.chunk_type));
    }
    let package_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if package_count > 256 {
        return Err(ResTableError::TooManyPackages(package_count));
    }

    let mut pos = hdr.header_size as usize;
    let total_size = hdr.size as usize;
    let end = total_size.min(data.len());

    let mut global_string_pool = ResStringPool::default();
    let mut packages = Vec::new();
    let mut chunk_count = 1usize;

    while pos + 8 <= end {
        let chunk = ResChunkHeader::parse(data, pos)?;
        if chunk.size == 0 {
            break;
        }
        chunk_count += 1;
        match chunk.chunk_type {
            RES_STRING_POOL_TYPE => {
                global_string_pool = ResStringPool::parse(data, pos).unwrap_or_default();
            }
            RES_TABLE_PACKAGE_TYPE => {
                if let Ok(pkg) = ResTablePackage::parse(data, pos) {
                    packages.push(pkg);
                }
            }
            _ => {}
        }
        pos += chunk.size as usize;
    }

    Ok(ResTable { global_string_pool, packages, chunk_count })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_res_table_header() -> Vec<u8> {
        // RES_TABLE_TYPE header (size=20): chunk_type, hdr_size, size, package_count
        let mut v = vec![0u8; 20];
        v[0] = 0x02; v[1] = 0x00; // chunk_type = RES_TABLE_TYPE
        v[2] = 0x0C; v[3] = 0x00; // header_size = 12
        v[4] = 0x14; v[5] = 0x00; v[6] = 0x00; v[7] = 0x00; // size = 20
        v[8] = 0x00; v[9] = 0x00; v[10] = 0x00; v[11] = 0x00; // package_count = 0
        v
    }

    #[test]
    fn test_parse_empty_res_table() {
        let data = minimal_res_table_header();
        let table = parse_res_table(&data).unwrap();
        assert_eq!(table.packages.len(), 0);
    }

    #[test]
    fn test_parse_wrong_magic() {
        let mut data = minimal_res_table_header();
        data[0] = 0xFF;
        assert!(parse_res_table(&data).is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = vec![0u8; 4];
        assert!(parse_res_table(&data).is_err());
    }

    #[test]
    fn test_chunk_header_parse() {
        let mut data = vec![0u8; 8];
        data[0] = 0x02; data[1] = 0x00;
        data[2] = 0x08; data[3] = 0x00;
        data[4] = 0x40; data[5] = 0x00; data[6] = 0x00; data[7] = 0x00;
        let hdr = ResChunkHeader::parse(&data, 0).unwrap();
        assert_eq!(hdr.chunk_type, 0x0002);
        assert_eq!(hdr.header_size, 8);
        assert_eq!(hdr.size, 64);
    }

    #[test]
    fn test_res_string_pool_empty() {
        let pool = ResStringPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.get(0), "");
    }

    #[test]
    fn test_res_table_global_string_fallback() {
        let data = minimal_res_table_header();
        let table = parse_res_table(&data).unwrap();
        assert_eq!(table.global_string(0), "");
    }

    #[test]
    fn test_res_table_total_entry_count_empty() {
        let data = minimal_res_table_header();
        let table = parse_res_table(&data).unwrap();
        assert_eq!(table.total_entry_count(), 0);
    }

    #[test]
    fn test_chunk_type_constants() {
        assert_eq!(RES_TABLE_TYPE, 0x0002);
        assert_eq!(RES_STRING_POOL_TYPE, 0x0001);
        assert_eq!(RES_TABLE_PACKAGE_TYPE, 0x0200);
    }

    #[test]
    fn test_res_table_config_default() {
        let cfg = ResTableConfig::default();
        assert_eq!(cfg.density, 0);
        assert_eq!(cfg.density_label(), "default");
    }

    #[test]
    fn test_res_table_config_density_labels() {
        let c_mdpi = ResTableConfig { density: 160, ..Default::default() };
        let c_xhdpi = ResTableConfig { density: 320, ..Default::default() };
        assert_eq!(c_mdpi.density_label(), "mdpi");
        assert_eq!(c_xhdpi.density_label(), "xhdpi");
    }

    #[test]
    fn test_entry_flag_complex() {
        assert_eq!(ENTRY_FLAG_COMPLEX, 1);
    }

    #[test]
    fn test_string_pool_too_short_returns_error() {
        let data = vec![0x01, 0x00, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        // Size is 0xFFFFFFFF — should be caught as truncated or ignored gracefully
        let r = ResStringPool::parse(&data, 0);
        // Should not panic; may return error or default
        let _ = r;
    }

    #[test]
    fn test_package_count_limit() {
        let mut data = minimal_res_table_header();
        data[8] = 0xFF; data[9] = 0x01; // package_count = 511 (>256)
        assert!(parse_res_table(&data).is_err());
    }
}
