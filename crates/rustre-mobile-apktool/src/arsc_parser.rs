//! Android `resources.arsc` binary parser.
//!
//! Parses the binary resource table format used in Android APKs.
//!
//! Structure:
//! ```text
//! ArscHeader (RES_TABLE_TYPE, 8 bytes)
//! StringPool  (package names + key names)
//! PackageChunk (one per package, usually one):
//!   StringPool (type strings)
//!   StringPool (key strings)
//!   TypeSpec   (one per resource type)
//!   TypeChunk  (one per configuration per type)
//!     ResTable_config (language/region/screen/etc.)
//!     ResourceEntry[]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ─── constants ────────────────────────────────────────────────────────────────

/// Chunk type: resource table.
pub const RES_TABLE_TYPE: u16 = 0x0002;
/// Chunk type: string pool.
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
/// Chunk type: package.
pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
/// Chunk type: type spec.
pub const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
/// Chunk type: type (configuration + entries).
pub const RES_TABLE_TYPE_TYPE: u16 = 0x0201;

/// Flag: string pool uses UTF-8 encoding.
pub const STRING_POOL_UTF8_FLAG: u32 = 1 << 8;

/// `NO_ENTRY` sentinel in a `TypeChunk` entry offset array.
pub const NO_ENTRY: u32 = 0xFFFF_FFFF;

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the ARSC parser.
#[derive(Debug, Error)]
pub enum ArscError {
    /// File is too short.
    #[error("file too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    /// Unknown chunk type.
    #[error("unknown chunk type: {0:#06x}")]
    UnknownChunk(u16),
    /// Malformed string pool.
    #[error("string pool malformed: {0}")]
    StringPool(String),
    /// Invalid resource ID.
    #[error("invalid resource id {0:#010x}")]
    InvalidResourceId(u32),
    /// Generic parse error.
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── ArscHeader ───────────────────────────────────────────────────────────────

/// Top-level `resources.arsc` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscHeader {
    /// Chunk type (must be [`RES_TABLE_TYPE`]).
    pub chunk_type: u16,
    /// Header size in bytes.
    pub header_size: u16,
    /// Total chunk size (entire file).
    pub chunk_size: u32,
    /// Number of `ResTable_package` chunks.
    pub package_count: u32,
}

impl ArscHeader {
    /// Minimum size of the ARSC header.
    pub const SIZE: usize = 12;

    /// Parse from the first 12 bytes of `data`.
    ///
    /// # Errors
    /// Returns [`ArscError::TooShort`] if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self, ArscError> {
        if data.len() < Self::SIZE {
            return Err(ArscError::TooShort {
                need: Self::SIZE,
                have: data.len(),
            });
        }
        let chunk_type = u16_le(data, 0);
        let header_size = u16_le(data, 2);
        let chunk_size = u32_le(data, 4);
        let package_count = u32_le(data, 8);
        Ok(Self {
            chunk_type,
            header_size,
            chunk_size,
            package_count,
        })
    }
}

// ─── StringPool ───────────────────────────────────────────────────────────────

/// String pool flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringPoolFlags(pub u32);

impl StringPoolFlags {
    /// Returns `true` if UTF-8 encoding is used.
    #[must_use]
    pub const fn is_utf8(&self) -> bool {
        (self.0 & STRING_POOL_UTF8_FLAG) != 0
    }
    /// Returns `true` if the string pool is sorted.
    #[must_use]
    pub const fn is_sorted(&self) -> bool {
        (self.0 & 1) != 0
    }
}

/// Parsed string pool (extracted strings only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringPool {
    /// All strings, indexed by their position.
    pub strings: Vec<String>,
    /// Pool flags.
    pub flags: StringPoolFlags,
    /// Byte offset of this chunk within the file.
    pub chunk_offset: usize,
    /// Total chunk size.
    pub chunk_size: u32,
}

impl StringPool {
    /// Header size.
    pub const HEADER_SIZE: usize = 28;

    /// Parse a string pool chunk starting at `offset` within `data`.
    ///
    /// # Errors
    /// Returns [`ArscError::TooShort`] or [`ArscError::Truncated`] on malformed input.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ArscError> {
        // `offset` is a public parameter: near `usize::MAX` a bare `+` wraps in
        // release, the bound check below then passes with a small wrapped value,
        // and the slice that follows is indexed out of range. The guard has to
        // survive the arithmetic, not only the comparison.
        let end = offset
            .checked_add(Self::HEADER_SIZE)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if end > data.len() {
            return Err(ArscError::TooShort {
                need: end,
                have: data.len(),
            });
        }
        let d = &data[offset..];
        let chunk_type = u16_le(d, 0);
        if chunk_type != RES_STRING_POOL_TYPE {
            return Err(ArscError::UnknownChunk(chunk_type));
        }
        let chunk_size = u32_le(d, 4);
        let string_count = u32_le(d, 8) as usize;
        let style_count = u32_le(d, 12) as usize;
        let flags_raw = u32_le(d, 16);
        let flags = StringPoolFlags(flags_raw);
        let strings_start = u32_le(d, 20) as usize;
        // styles_start at offset 24 (ignored for now)

        let offsets_start = Self::HEADER_SIZE;
        let offsets_end = offsets_start.checked_add(
            string_count.checked_mul(4).ok_or_else(|| ArscError::Parse(
                format!("string_count {string_count} overflows offset calculation")
            ))?
        ).ok_or_else(|| ArscError::Parse("string pool offsets_end overflows usize".into()))?;
        let need = offset
            .checked_add(offsets_end)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if need > data.len() {
            return Err(ArscError::TooShort { need, have: data.len() });
        }

        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off_slot = offsets_start + i * 4;
            let str_off = u32_le(d, off_slot) as usize;
            // Both `strings_start` and `str_off` are read from the file, so
            // the sum is attacker-chosen; a wrapped result would index at a
            // wholly unrelated place instead of being rejected.
            let Some(abs) = offset
                .checked_add(strings_start)
                .and_then(|a| a.checked_add(str_off))
            else {
                strings.push(String::new());
                continue;
            };

            let s = if flags.is_utf8() {
                parse_utf8_string(data, abs)
            } else {
                parse_utf16_string(data, abs)
            };
            strings.push(s.unwrap_or_default());
        }
        let _ = style_count; // styles not parsed
        Ok(Self {
            strings,
            flags,
            chunk_offset: offset,
            chunk_size,
        })
    }

    /// Return string at `index`, or empty string if out of bounds.
    #[must_use]
    pub fn get(&self, index: usize) -> &str {
        self.strings
            .get(index)
            .map_or("", std::string::String::as_str)
    }

    /// Number of strings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// True if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

fn parse_utf8_string(data: &[u8], abs: usize) -> Option<String> {
    if abs >= data.len() {
        return None;
    }
    // Read char_count as ULEB128
    let mut pos = abs;
    loop {
        let b = *data.get(pos)?;
        pos += 1;
        if b & 0x80 == 0 { break; }
    }
    // Read byte_len as ULEB128
    let byte_len = {
        let mut value = 0usize;
        let mut shift = 0;
        loop {
            let b = *data.get(pos)? as usize;
            pos += 1;
            value |= (b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 { break; }
        }
        value
    };
    let end = pos + byte_len;
    if end > data.len() {
        return None;
    }
    std::str::from_utf8(&data[pos..end])
        .ok()
        .map(std::string::ToString::to_string)
}

fn parse_utf16_string(data: &[u8], abs: usize) -> Option<String> {
    if abs + 2 > data.len() {
        return None;
    }
    let char_len = u16_le(data, abs) as usize;
    let bytes_start = abs + 2;
    let bytes_end = bytes_start + char_len * 2;
    if bytes_end > data.len() {
        return None;
    }
    let words: Vec<u16> = (0..char_len)
        .map(|i| u16_le(data, bytes_start + i * 2))
        .collect();
    String::from_utf16(&words).ok()
}

// ─── ResTableConfig ───────────────────────────────────────────────────────────

/// Screen orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    Any,
    Portrait,
    Landscape,
    Square,
}

/// Screen density bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Density {
    Default,
    Low,
    Medium,
    TV,
    High,
    XHigh,
    XXHigh,
    XXXHigh,
    Any,
    None,
    Custom(u16),
}

impl Density {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Default,
            120 => Self::Low,
            160 => Self::Medium,
            213 => Self::TV,
            240 => Self::High,
            320 => Self::XHigh,
            480 => Self::XXHigh,
            640 => Self::XXXHigh,
            0xFFFE => Self::Any,
            0xFFFF => Self::None,
            other => Self::Custom(other),
        }
    }
}

/// Configuration block for a resource type chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResTableConfig {
    pub size: u32,
    pub mcc: u16,
    pub mnc: u16,
    pub language: [u8; 2],
    pub region: [u8; 2],
    pub orientation: u8,
    pub touchscreen: u8,
    pub density: u16,
    pub keyboard: u8,
    pub navigation: u8,
    pub input_flags: u8,
    pub screen_width: u16,
    pub screen_height: u16,
    pub sdk_version: u16,
    pub minor_version: u16,
    pub screen_layout: u8,
    pub ui_mode: u8,
    pub smallest_screen_width_dp: u16,
    pub screen_width_dp: u16,
    pub screen_height_dp: u16,
}

impl ResTableConfig {
    /// Minimum size.
    pub const MIN_SIZE: usize = 32;

    /// Parse from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`ArscError::TooShort`] if the slice is shorter than [`Self::MIN_SIZE`].
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ArscError> {
        let end = offset
            .checked_add(Self::MIN_SIZE)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if end > data.len() {
            return Err(ArscError::TooShort {
                need: end,
                have: data.len(),
            });
        }
        let d = &data[offset..];
        let size = u32_le(d, 0);
        let actual_size = size.min(u32::try_from(d.len()).unwrap_or(u32::MAX)) as usize;
        let d = &d[..actual_size];

        let get16 = |off: usize| {
            if off + 2 <= d.len() {
                u16_le(d, off)
            } else {
                0
            }
        };
        let get8 = |off: usize| if off < d.len() { d[off] } else { 0 };

        let mut language = [0u8; 2];
        let mut region = [0u8; 2];
        if 6 <= d.len() {
            language.copy_from_slice(&d[4..6]);
        }
        if 8 <= d.len() {
            region.copy_from_slice(&d[6..8]);
        }

        Ok(Self {
            size,
            mcc: get16(0),
            mnc: get16(2),
            language,
            region,
            orientation: get8(8),
            touchscreen: get8(9),
            density: get16(10),
            keyboard: get8(12),
            navigation: get8(13),
            input_flags: get8(14),
            screen_width: get16(16),
            screen_height: get16(18),
            sdk_version: get16(20),
            minor_version: get16(22),
            screen_layout: get8(24),
            ui_mode: get8(25),
            smallest_screen_width_dp: get16(26),
            screen_width_dp: get16(28),
            screen_height_dp: get16(30),
        })
    }

    /// Language tag (e.g. `"en"`, `"zh"`).
    #[must_use]
    pub fn language_tag(&self) -> String {
        String::from_utf8_lossy(&self.language)
            .trim_matches('\0')
            .to_string()
    }

    /// Region tag (e.g. `"US"`, `"CN"`).
    #[must_use]
    pub fn region_tag(&self) -> String {
        String::from_utf8_lossy(&self.region)
            .trim_matches('\0')
            .to_string()
    }

    /// Density bucket.
    #[must_use]
    pub const fn density_bucket(&self) -> Density {
        Density::from_u16(self.density)
    }

    /// Returns `true` if this is the default (any) configuration.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.language == [0, 0]
            && self.region == [0, 0]
            && self.sdk_version == 0
            && self.density == 0
    }
}

impl fmt::Display for ResTableConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lang = self.language_tag();
        let reg = self.region_tag();
        let qualifier = match (lang.is_empty(), reg.is_empty()) {
            (true, true) => "default".to_string(),
            (false, true) => lang,
            (false, false) => format!("{lang}-r{reg}"),
            (true, false) => format!("r{reg}"),
        };
        write!(f, "{qualifier}~sdk{}", self.sdk_version)
    }
}

// ─── ResourceValue ────────────────────────────────────────────────────────────

/// Type code of a resource value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ValueType {
    Null = 0x00,
    Reference = 0x01,
    Attribute = 0x02,
    String = 0x03,
    Float = 0x04,
    Dimension = 0x05,
    Fraction = 0x06,
    IntDec = 0x10,
    IntHex = 0x11,
    IntBoolean = 0x12,
    IntColorARGB8 = 0x1C,
    IntColorRGB8 = 0x1D,
    IntColorARGB4 = 0x1E,
    IntColorRGB4 = 0x1F,
}

impl ValueType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Reference,
            0x02 => Self::Attribute,
            0x03 => Self::String,
            0x04 => Self::Float,
            0x05 => Self::Dimension,
            0x06 => Self::Fraction,
            0x10 => Self::IntDec,
            0x11 => Self::IntHex,
            0x12 => Self::IntBoolean,
            0x1C => Self::IntColorARGB8,
            0x1D => Self::IntColorRGB8,
            0x1E => Self::IntColorARGB4,
            0x1F => Self::IntColorRGB4,
            // 0x00 and any unknown value map to Null.
            _ => Self::Null,
        }
    }
}

/// A single resource value (8 bytes: size(2), res0(1), `data_type(1)`, data(4)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceValue {
    pub data_type: ValueType,
    pub data: u32,
}

impl ResourceValue {
    pub const SIZE: usize = 8;

    /// Parse a resource value from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`ArscError::TooShort`] if the slice is too small.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ArscError> {
        let end = offset
            .checked_add(Self::SIZE)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if end > data.len() {
            return Err(ArscError::TooShort {
                need: end,
                have: data.len(),
            });
        }
        let d = &data[offset..];
        Ok(Self {
            data_type: ValueType::from_u8(d[3]),
            data: u32_le(d, 4),
        })
    }
}

// ─── ResourceEntry ────────────────────────────────────────────────────────────

/// A single resource entry (value or map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Size of this entry header.
    pub size: u16,
    /// Flags.
    pub flags: u16,
    /// Index into the key string pool.
    pub key_index: u32,
    /// Value (for simple entries).
    pub value: Option<ResourceValue>,
}

impl ResourceEntry {
    /// Parse a resource entry from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`ArscError::TooShort`] if the slice is too small.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ArscError> {
        let need = offset
            .checked_add(8)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if need > data.len() {
            return Err(ArscError::TooShort { need, have: data.len() });
        }
        let d = &data[offset..];
        let size = u16_le(d, 0);
        let flags = u16_le(d, 2);
        let key_index = u32_le(d, 4);

        let is_complex = (flags & 0x0001) != 0;
        let value = if !is_complex && offset + 8 + ResourceValue::SIZE <= data.len() {
            ResourceValue::parse(data, offset + 8).ok()
        } else {
            None
        };

        Ok(Self {
            size,
            flags,
            key_index,
            value,
        })
    }

    #[must_use]
    pub const fn is_complex(&self) -> bool {
        (self.flags & 0x0001) != 0
    }
}

// ─── TypeSpec ─────────────────────────────────────────────────────────────────

/// Configuration flags array for a resource type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSpec {
    pub type_id: u8,
    pub entry_count: u32,
    pub flags: Vec<u32>,
}

// ─── TypeChunk ────────────────────────────────────────────────────────────────

/// One configuration variant for a resource type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeChunk {
    pub type_id: u8,
    pub config: ResTableConfig,
    pub entries: Vec<Option<ResourceEntry>>,
}

impl TypeChunk {
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── PackageChunk ─────────────────────────────────────────────────────────────

/// A resource package (usually one per APK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageChunk {
    /// Package ID (usually 0x7F for the app, 0x01 for system).
    pub package_id: u32,
    /// Package name (e.g. `"com.example.app"`).
    pub package_name: String,
    /// Type string pool.
    pub type_strings: StringPool,
    /// Key string pool.
    pub key_strings: StringPool,
    /// Type specs (one per resource type).
    pub type_specs: HashMap<u8, TypeSpec>,
    /// Type chunks (multiple configurations per type).
    pub types: Vec<TypeChunk>,
}

impl PackageChunk {
    /// Package header size.
    pub const HEADER_SIZE: usize = 288;

    /// Parse a package chunk at `offset` in `data`.
    ///
    /// # Errors
    /// Returns an [`ArscError`] if the slice is too small or malformed.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ArscError> {
        let min_end = offset
            .checked_add(Self::HEADER_SIZE)
            .ok_or(ArscError::TooShort { need: usize::MAX, have: data.len() })?;
        if min_end > data.len() {
            return Err(ArscError::TooShort {
                need: min_end,
                have: data.len(),
            });
        }
        let d = &data[offset..];
        let _chunk_type = u16_le(d, 0);
        let header_size = u16_le(d, 2) as usize;
        let _chunk_size = u32_le(d, 4) as usize;
        let package_id = u32_le(d, 8);

        // Package name: 128 UTF-16LE chars at offset 12, bounded by header_size.
        let name_end = 12
            + 256
                .min(d.len().saturating_sub(12))
                .min(header_size.saturating_sub(12));
        let max_words = (name_end.saturating_sub(12)) / 2;
        let name_words: Vec<u16> = (0..max_words.min(128))
            .map(|i| u16_le(d, 12 + i * 2))
            .take_while(|&c| c != 0)
            .collect();
        let package_name = String::from_utf16_lossy(&name_words);

        let type_strings_offset = u32_le(d, 268) as usize;
        let key_strings_offset = u32_le(d, 272) as usize;

        // Both offsets are read from the file. The bound checks below catch an
        // out-of-range result, but a wrapped one would pass them and parse an
        // unrelated location silently, so saturate instead.
        let ts_abs = offset.saturating_add(type_strings_offset);
        let ks_abs = offset.saturating_add(key_strings_offset);

        let type_strings = if ts_abs < data.len() {
            StringPool::parse(data, ts_abs).unwrap_or_else(|_| StringPool {
                strings: vec![],
                flags: StringPoolFlags(0),
                chunk_offset: ts_abs,
                chunk_size: 0,
            })
        } else {
            StringPool {
                strings: vec![],
                flags: StringPoolFlags(0),
                chunk_offset: ts_abs,
                chunk_size: 0,
            }
        };

        let key_strings = if ks_abs < data.len() {
            StringPool::parse(data, ks_abs).unwrap_or_else(|_| StringPool {
                strings: vec![],
                flags: StringPoolFlags(0),
                chunk_offset: ks_abs,
                chunk_size: 0,
            })
        } else {
            StringPool {
                strings: vec![],
                flags: StringPoolFlags(0),
                chunk_offset: ks_abs,
                chunk_size: 0,
            }
        };

        Ok(Self {
            package_id,
            package_name,
            type_strings,
            key_strings,
            type_specs: HashMap::new(),
            types: vec![],
        })
    }
}

// ─── ArscFile ─────────────────────────────────────────────────────────────────

/// Top-level parsed `resources.arsc` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscFile {
    pub header: ArscHeader,
    pub global_string_pool: StringPool,
    pub packages: Vec<PackageChunk>,
}

impl ArscFile {
    /// Parse a `resources.arsc` file from `data`.
    ///
    /// # Errors
    /// Returns [`ArscError`] on format errors.
    pub fn parse(data: &[u8]) -> Result<Self, ArscError> {
        let header = ArscHeader::parse(data)?;

        let sp_offset = header.header_size as usize;
        let global_string_pool =
            StringPool::parse(data, sp_offset).unwrap_or_else(|_| StringPool {
                strings: vec![],
                flags: StringPoolFlags(0),
                chunk_offset: sp_offset,
                chunk_size: 0,
            });

        let pkg_offset = sp_offset.saturating_add(global_string_pool.chunk_size as usize);
        // Only parse a package chunk if the header advertises at least one and
        // the remaining slice can fit one.
        let packages = if header.package_count > 0 && pkg_offset < data.len() {
            let pkg = PackageChunk::parse(data, pkg_offset)?;
            vec![pkg]
        } else {
            vec![]
        };

        Ok(Self {
            header,
            global_string_pool,
            packages,
        })
    }

    /// Resolve a resource ID to its string value, if available.
    ///
    /// Resource ID format: `0xPPTTEEEE` (package, type, entry).
    ///
    /// # Errors
    /// Returns [`ArscError::InvalidResourceId`] if the ID is malformed.
    pub fn resolve_resource_id(&self, res_id: u32) -> Result<Option<String>, ArscError> {
        let package_id = (res_id >> 24) & 0xFF;
        let type_id = (res_id >> 16) & 0xFF;
        let entry_id = res_id & 0xFFFF;

        if package_id == 0 {
            return Err(ArscError::InvalidResourceId(res_id));
        }

        // Scan packages
        for pkg in &self.packages {
            if pkg.package_id & 0xFF == package_id {
                for type_chunk in &pkg.types {
                    if u32::from(type_chunk.type_id) == type_id
                        && let Some(Some(entry)) = type_chunk.entries.get(entry_id as usize)
                    {
                        let key = pkg.key_strings.get(entry.key_index as usize);
                        if !key.is_empty() {
                            return Ok(Some(key.to_string()));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Returns the global string at `index`.
    #[must_use]
    pub fn global_string(&self, index: usize) -> &str {
        self.global_string_pool.get(index)
    }

    /// Number of packages.
    #[must_use]
    pub const fn package_count(&self) -> usize {
        self.packages.len()
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_arsc() -> Vec<u8> {
        let mut d = vec![0u8; 64];
        // RES_TABLE_TYPE = 0x0002 (LE)
        d[0..2].copy_from_slice(&0x0002_u16.to_le_bytes());
        // header size = 12
        d[2..4].copy_from_slice(&12_u16.to_le_bytes());
        // chunk size = 64
        d[4..8].copy_from_slice(&64_u32.to_le_bytes());
        // package count = 0
        d[8..12].copy_from_slice(&0_u32.to_le_bytes());
        d
    }

    fn minimal_string_pool(strings: &[&str]) -> Vec<u8> {
        // Build a minimal UTF-8 string pool
        let mut data = vec![0u8; 512];
        data[0..2].copy_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        data[2..4].copy_from_slice(&28_u16.to_le_bytes()); // header size
        let string_count = u32::try_from(strings.len()).unwrap();
        data[8..12].copy_from_slice(&string_count.to_le_bytes());
        // UTF-8 flag
        data[16..20].copy_from_slice(&STRING_POOL_UTF8_FLAG.to_le_bytes());
        // strings_start = 28 + count*4
        let strings_start = 28 + string_count * 4;
        data[20..24].copy_from_slice(&strings_start.to_le_bytes());

        // Write offsets + string data
        let mut str_data_off = 0usize;
        let mut offsets = Vec::new();
        let mut str_bytes: Vec<u8> = Vec::new();
        for s in strings {
            offsets.push(u32::try_from(str_data_off).unwrap());
            let encoded = s.as_bytes();
            // char count (1 byte) + byte count (1 byte) + bytes
            str_bytes.push(u8::try_from(s.chars().count()).unwrap());
            str_bytes.push(u8::try_from(encoded.len()).unwrap());
            str_bytes.extend_from_slice(encoded);
            str_data_off += 2 + encoded.len();
        }
        for (i, off) in offsets.iter().enumerate() {
            let pos = 28 + i * 4;
            data[pos..pos + 4].copy_from_slice(&off.to_le_bytes());
        }
        let str_start = strings_start as usize;
        let copy_len = str_bytes.len().min(data.len() - str_start);
        data[str_start..str_start + copy_len].copy_from_slice(&str_bytes[..copy_len]);

        let total = strings_start as usize + str_bytes.len();
        data[4..8].copy_from_slice(&u32::try_from(total).unwrap().to_le_bytes());
        data.truncate(total.max(28));
        data
    }

    #[test]
    fn test_arsc_header_parse() {
        let d = minimal_arsc();
        let h = ArscHeader::parse(&d).unwrap();
        assert_eq!(h.chunk_type, RES_TABLE_TYPE);
        assert_eq!(h.package_count, 0);
    }

    #[test]
    fn test_arsc_header_too_short() {
        let err = ArscHeader::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, ArscError::TooShort { .. }));
    }

    #[test]
    fn test_string_pool_utf8_flag() {
        let f = StringPoolFlags(STRING_POOL_UTF8_FLAG);
        assert!(f.is_utf8());
        let f2 = StringPoolFlags(0);
        assert!(!f2.is_utf8());
    }

    #[test]
    fn test_string_pool_parse_utf8() {
        let pool_data = minimal_string_pool(&["hello", "world"]);
        let pool = StringPool::parse(&pool_data, 0).unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.get(0), "hello");
        assert_eq!(pool.get(1), "world");
    }

    #[test]
    fn test_string_pool_get_oob() {
        let pool = StringPool {
            strings: vec!["one".into()],
            flags: StringPoolFlags(0),
            chunk_offset: 0,
            chunk_size: 0,
        };
        assert_eq!(pool.get(999), "");
    }

    #[test]
    fn test_res_table_config_default() {
        let mut d = vec![0u8; ResTableConfig::MIN_SIZE];
        d[0..4].copy_from_slice(&u32::try_from(ResTableConfig::MIN_SIZE).unwrap().to_le_bytes());
        let c = ResTableConfig::parse(&d, 0).unwrap();
        assert!(c.is_default());
        assert_eq!(c.language_tag(), "");
    }

    #[test]
    fn test_res_table_config_language() {
        let mut d = vec![0u8; ResTableConfig::MIN_SIZE];
        d[0..4].copy_from_slice(&u32::try_from(ResTableConfig::MIN_SIZE).unwrap().to_le_bytes());
        d[4] = b'e';
        d[5] = b'n';
        d[6] = b'U';
        d[7] = b'S';
        let c = ResTableConfig::parse(&d, 0).unwrap();
        assert_eq!(c.language_tag(), "en");
        assert_eq!(c.region_tag(), "US");
    }

    #[test]
    fn test_res_table_config_display() {
        let mut d = vec![0u8; ResTableConfig::MIN_SIZE];
        d[0..4].copy_from_slice(&u32::try_from(ResTableConfig::MIN_SIZE).unwrap().to_le_bytes());
        d[4] = b'z';
        d[5] = b'h';
        let c = ResTableConfig::parse(&d, 0).unwrap();
        let s = format!("{c}");
        assert!(s.contains("zh"));
    }

    #[test]
    fn test_density_from_u16() {
        assert_eq!(Density::from_u16(160), Density::Medium);
        assert_eq!(Density::from_u16(320), Density::XHigh);
        assert_eq!(Density::from_u16(0xFFFF), Density::None);
    }

    #[test]
    fn test_value_type_from_u8() {
        assert_eq!(ValueType::from_u8(0x01), ValueType::Reference);
        assert_eq!(ValueType::from_u8(0x03), ValueType::String);
        assert_eq!(ValueType::from_u8(0x12), ValueType::IntBoolean);
    }

    #[test]
    fn test_resource_entry_is_complex() {
        let mut d = vec![0u8; 16];
        d[2] = 0x01; // flags = complex
        let e = ResourceEntry::parse(&d, 0).unwrap();
        assert!(e.is_complex());
    }

    #[test]
    fn test_arsc_file_parse_minimal() {
        let mut d = minimal_arsc();
        // Append a minimal string pool (just header, no strings)
        let sp = vec![
            0x01, 0x00, // RES_STRING_POOL_TYPE
            0x1C, 0x00, // header size 28
            0x1C, 0x00, 0x00, 0x00, // chunk size 28
            0x00, 0x00, 0x00, 0x00, // string count 0
            0x00, 0x00, 0x00, 0x00, // style count 0
            0x00, 0x00, 0x00, 0x00, // flags 0
            0x1C, 0x00, 0x00, 0x00, // strings start 28
            0x00, 0x00, 0x00, 0x00, // styles start 0
        ];
        d.extend_from_slice(&sp);
        let arsc = ArscFile::parse(&d).unwrap();
        assert_eq!(arsc.package_count(), 0);
    }

    #[test]
    fn test_arsc_resolve_invalid_id() {
        let d = minimal_arsc();
        // Append a dummy string pool
        let sp = vec![
            0x01, 0x00, 0x1C, 0x00, 0x1C, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x1C, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut full = d;
        full.extend_from_slice(&sp);
        let arsc = ArscFile::parse(&full).unwrap();
        let err = arsc.resolve_resource_id(0x0000_0001).unwrap_err();
        assert!(matches!(err, ArscError::InvalidResourceId(_)));
    }

    #[test]
    fn test_no_entry_sentinel() {
        assert_eq!(NO_ENTRY, 0xFFFF_FFFF);
    }
}
