//! .NET managed resources parser.
//!
//! Parses .NET resources from the RESOURCES data directory, implementing
//! the binary `ResourceReader` format used by System.Resources.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from managed resource parsing.
#[derive(Debug)]
pub enum ResourceError {
    TooSmall,
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidEncoding,
    IndexOutOfRange(usize),
    ParseError(String),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::InvalidMagic => write!(f, "invalid resource magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported resource version: {v}"),
            Self::InvalidEncoding => write!(f, "invalid string encoding"),
            Self::IndexOutOfRange(i) => write!(f, "index out of range: {i}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

// ─── ResourceType ────────────────────────────────────────────────────────────

/// The value type of a resource entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResourceType {
    /// Null value.
    Null,
    /// A string value.
    String(String),
    /// A byte array.
    ByteArray(Vec<u8>),
    /// A stream (byte sequence).
    Stream(Vec<u8>),
    /// A boolean.
    Bool(bool),
    /// A signed 32-bit integer.
    Int32(i32),
    /// A signed 64-bit integer.
    Int64(i64),
    /// A 32-bit float.
    Float32(f32),
    /// A 64-bit float.
    Float64(f64),
    /// A decimal (stored as 4×u32).
    Decimal([u32; 4]),
    /// A `DateTime` (stored as i64 ticks).
    DateTime(i64),
    /// A `TimeSpan` (stored as i64 ticks).
    TimeSpan(i64),
    /// An unknown type code.
    Unknown { type_code: u32, data: Vec<u8> },
}

impl ResourceType {
    /// Return a short type label.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "Null",
            Self::String(_) => "String",
            Self::ByteArray(_) => "Byte[]",
            Self::Stream(_) => "Stream",
            Self::Bool(_) => "Boolean",
            Self::Int32(_) => "Int32",
            Self::Int64(_) => "Int64",
            Self::Float32(_) => "Single",
            Self::Float64(_) => "Double",
            Self::Decimal(_) => "Decimal",
            Self::DateTime(_) => "DateTime",
            Self::TimeSpan(_) => "TimeSpan",
            Self::Unknown { .. } => "Unknown",
        }
    }

    /// Return true if this is a string value.
    #[must_use]
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Extract the string value if this is a String variant.
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Extract byte data if this is a `ByteArray` or Stream.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::ByteArray(b) | Self::Stream(b) => Some(b),
            _ => None,
        }
    }
}

// ─── ResourceEntry ────────────────────────────────────────────────────────────

/// A single resource entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Resource name.
    pub name: String,
    /// Offset within the resource data section.
    pub offset: u32,
    /// Length of the resource data.
    pub length: u32,
    /// Parsed resource value.
    pub value: ResourceType,
}

impl ResourceEntry {
    /// Create a new resource entry.
    #[must_use]
    pub fn new(name: impl Into<String>, offset: u32, length: u32, value: ResourceType) -> Self {
        Self {
            name: name.into(),
            offset,
            length,
            value,
        }
    }

    /// Return a display summary.
    #[must_use]
    pub fn display(&self) -> String {
        format!(
            "{} [{}] @{:#x}+{:#x}",
            self.name,
            self.value.type_name(),
            self.offset,
            self.length
        )
    }
}

// ─── ResourceSection ─────────────────────────────────────────────────────────

/// Parsed .NET managed resource section.
///
/// Corresponds to the data pointed to by `IMAGE_COR20_HEADER.Resources`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSection {
    /// All parsed resource entries.
    pub entries: Vec<ResourceEntry>,
    /// Resource name → entry index map.
    name_index: HashMap<String, usize>,
}

impl ResourceSection {
    /// Create an empty resource section.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the section.
    pub fn add_entry(&mut self, entry: ResourceEntry) {
        let idx = self.entries.len();
        self.name_index.insert(entry.name.clone(), idx);
        self.entries.push(entry);
    }

    /// Return the number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find an entry by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&ResourceEntry> {
        self.name_index.get(name).map(|&i| &self.entries[i])
    }

    /// Return all string resources as (name, value) pairs.
    #[must_use]
    pub fn strings(&self) -> Vec<(&str, &str)> {
        self.entries
            .iter()
            .filter_map(|e| e.value.as_string().map(|s| (e.name.as_str(), s)))
            .collect()
    }

    /// Return all binary (byte array / stream) resources.
    #[must_use]
    pub fn binary_entries(&self) -> Vec<&ResourceEntry> {
        self.entries
            .iter()
            .filter(|e| {
                matches!(
                    e.value,
                    ResourceType::ByteArray(_) | ResourceType::Stream(_)
                )
            })
            .collect()
    }

    /// Parse a .NET `ResourceReader` binary format from `data`.
    ///
    /// Format overview:
    /// ```text
    /// Header (magic + version + reader type name + resource set type name)
    /// Padding to 8-byte boundary
    /// u32: version (1 or 2)
    /// u32: numResources
    /// u32: numTypes (v2 only)
    /// type name strings (v2 only)
    /// name hash array: numResources × u32
    /// name position array: numResources × u32
    /// data section offset: u32
    /// names section: numResources × (length-prefixed UTF-16 name + i32 data offset)
    /// data section: value bytes
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ResourceError> {
        let mut section = Self::new();
        let mut pos = 0usize;

        // Magic: 0xBEEFCACE
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let magic = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if magic != 0xBEEF_CACE {
            return Err(ResourceError::InvalidMagic);
        }
        pos += 4;

        // Header version
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let header_version =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        if header_version != 1 && header_version != 2 {
            return Err(ResourceError::UnsupportedVersion(header_version));
        }

        // Skip reader type length + string
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let reader_type_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + reader_type_len > data.len() {
            return Err(ResourceError::TooSmall);
        }
        pos += reader_type_len;

        // Skip resource set type length + string
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let set_type_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + set_type_len > data.len() {
            return Err(ResourceError::TooSmall);
        }
        pos += set_type_len;

        // Pad to 8-byte boundary
        while !pos.is_multiple_of(8) {
            pos += 1;
        }

        // Resource data version
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let resource_version =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Num resources
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let num_resources =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if num_resources > 100_000 {
            return Err(ResourceError::ParseError(format!(
                "unreasonable resource count: {num_resources}"
            )));
        }

        // Num types (v2)
        if resource_version == 2 {
            if pos + 4 > data.len() {
                return Err(ResourceError::TooSmall);
            }
            let num_types =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;
            // Skip type name strings
            for _ in 0..num_types {
                pos = Self::skip_string(data, pos)?;
            }
        }

        // Pad to 8-byte boundary
        while !pos.is_multiple_of(8) {
            pos += 1;
        }

        // Skip name hash array
        if pos + num_resources * 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        pos += num_resources * 4;

        // Read name position array
        if pos + num_resources * 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let mut name_positions = Vec::with_capacity(num_resources);
        for _ in 0..num_resources {
            let p = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            name_positions.push(p);
            pos += 4;
        }

        // Data section offset
        if pos + 4 > data.len() {
            return Err(ResourceError::TooSmall);
        }
        let data_section_offset =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // Names section starts here; each entry is a length-prefixed UTF-16LE name + i32 data offset
        let names_section_start = pos;

        for __item in name_positions.iter().take(num_resources) {
            let name_pos = names_section_start + (*__item);
            if name_pos + 2 > data.len() {
                break;
            }

            // Read name: 7-bit encoded length in bytes, then UTF-16LE chars
            let (name_byte_len, len_bytes) = Self::read_7bit_int(data, name_pos);
            let char_start = name_pos + len_bytes;
            let char_end = (char_start + name_byte_len).min(data.len());

            let name = if char_end > char_start && (char_end - char_start).is_multiple_of(2) {
                let chars: Vec<u16> = data[char_start..char_end]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&chars)
            } else {
                String::from_utf8_lossy(&data[char_start..char_end]).to_string()
            };

            // Data offset (i32) follows the name
            let data_offset_pos = char_end;
            if data_offset_pos + 4 > data.len() {
                break;
            }
            let data_offset_raw = i32::from_le_bytes([
                data[data_offset_pos],
                data[data_offset_pos + 1],
                data[data_offset_pos + 2],
                data[data_offset_pos + 3],
            ]);
            // A negative offset is illegal in the ResourceReader format; skip this entry.
            let Ok(data_offset) = usize::try_from(data_offset_raw) else { break };

            // Parse the value from the data section
            let value_pos = data_section_offset.saturating_add(data_offset);
            let (value, value_len) = if value_pos < data.len() {
                Self::parse_resource_value(data, value_pos, resource_version).unwrap_or_else(|_| (ResourceType::Unknown { type_code: 0, data: Vec::new() }, 0))
            } else {
                (ResourceType::Unknown { type_code: 0, data: Vec::new() }, 0)
            };

            section.add_entry(ResourceEntry::new(
                name,
                value_pos as u32,
                value_len as u32,
                value,
            ));
        }

        Ok(section)
    }

    fn read_7bit_int(data: &[u8], pos: usize) -> (usize, usize) {
        let mut value = 0usize;
        let mut shift = 0;
        let mut consumed = 0;
        loop {
            if pos + consumed >= data.len() {
                break;
            }
            let b = data[pos + consumed];
            consumed += 1;
            value |= ((b & 0x7F) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift >= 35 {
                break;
            } // safety
        }
        (value, consumed)
    }

    fn skip_string(data: &[u8], pos: usize) -> Result<usize, ResourceError> {
        let (len, consumed) = Self::read_7bit_int(data, pos);
        let end = pos + consumed + len;
        if end > data.len() {
            return Err(ResourceError::TooSmall);
        }
        Ok(end)
    }

    fn parse_resource_value(
        data: &[u8],
        pos: usize,
        version: u32,
    ) -> Result<(ResourceType, usize), ResourceError> {
        if pos >= data.len() {
            return Err(ResourceError::TooSmall);
        }

        // Resource type code is a 7-bit encoded integer
        let (type_code, consumed) = Self::read_7bit_int(data, pos);
        let value_start = pos + consumed;

        let (value, value_size) = match type_code {
            0x00 => (ResourceType::Null, 0),
            0x01 => {
                // String
                let (len, lc) = Self::read_7bit_int(data, value_start);
                let s_end = (value_start + lc + len).min(data.len());
                let s = String::from_utf8_lossy(&data[value_start + lc..s_end]).to_string();
                (ResourceType::String(s), lc + len)
            }
            0x02 => {
                // Bool
                if value_start >= data.len() {
                    return Err(ResourceError::TooSmall);
                }
                (ResourceType::Bool(data[value_start] != 0), 1)
            }
            0x04 => {
                // Char (ignored, stored as u16)
                if value_start + 2 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = u16::from_le_bytes([data[value_start], data[value_start + 1]]);
                (ResourceType::Int32(i32::from(v)), 2)
            }
            0x08 => {
                // Int32
                if value_start + 4 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = i32::from_le_bytes([
                    data[value_start],
                    data[value_start + 1],
                    data[value_start + 2],
                    data[value_start + 3],
                ]);
                (ResourceType::Int32(v), 4)
            }
            0x0A => {
                // Int64
                if value_start + 8 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = i64::from_le_bytes(data[value_start..value_start + 8].try_into().unwrap());
                (ResourceType::Int64(v), 8)
            }
            0x0B => {
                // Float32
                if value_start + 4 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = f32::from_le_bytes([
                    data[value_start],
                    data[value_start + 1],
                    data[value_start + 2],
                    data[value_start + 3],
                ]);
                (ResourceType::Float32(v), 4)
            }
            0x0C => {
                // Float64
                if value_start + 8 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = f64::from_le_bytes(data[value_start..value_start + 8].try_into().unwrap());
                (ResourceType::Float64(v), 8)
            }
            0x0D => {
                // Decimal
                if value_start + 16 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let d = [
                    u32::from_le_bytes([
                        data[value_start],
                        data[value_start + 1],
                        data[value_start + 2],
                        data[value_start + 3],
                    ]),
                    u32::from_le_bytes([
                        data[value_start + 4],
                        data[value_start + 5],
                        data[value_start + 6],
                        data[value_start + 7],
                    ]),
                    u32::from_le_bytes([
                        data[value_start + 8],
                        data[value_start + 9],
                        data[value_start + 10],
                        data[value_start + 11],
                    ]),
                    u32::from_le_bytes([
                        data[value_start + 12],
                        data[value_start + 13],
                        data[value_start + 14],
                        data[value_start + 15],
                    ]),
                ];
                (ResourceType::Decimal(d), 16)
            }
            0x0E => {
                // DateTime (int64 ticks)
                if value_start + 8 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = i64::from_le_bytes(data[value_start..value_start + 8].try_into().unwrap());
                (ResourceType::DateTime(v), 8)
            }
            0x0F => {
                // TimeSpan
                if value_start + 8 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let v = i64::from_le_bytes(data[value_start..value_start + 8].try_into().unwrap());
                (ResourceType::TimeSpan(v), 8)
            }
            0x20 => {
                // ByteArray
                if value_start + 4 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let len = u32::from_le_bytes([
                    data[value_start],
                    data[value_start + 1],
                    data[value_start + 2],
                    data[value_start + 3],
                ]) as usize;
                let end = (value_start + 4 + len).min(data.len());
                let bytes = data[value_start + 4..end].to_vec();
                (ResourceType::ByteArray(bytes), 4 + len)
            }
            0x21 => {
                // Stream
                if value_start + 4 > data.len() {
                    return Err(ResourceError::TooSmall);
                }
                let len = u32::from_le_bytes([
                    data[value_start],
                    data[value_start + 1],
                    data[value_start + 2],
                    data[value_start + 3],
                ]) as usize;
                let end = (value_start + 4 + len).min(data.len());
                let bytes = data[value_start + 4..end].to_vec();
                (ResourceType::Stream(bytes), 4 + len)
            }
            _ => {
                // Encode the resource-set version into the high 16 bits so
                // downstream consumers can disambiguate version-specific opcodes.
                let tagged = ((version & 0xFFFF) << 16) | (type_code as u32 & 0xFFFF);
                (
                    ResourceType::Unknown {
                        type_code: tagged,
                        data: Vec::new(),
                    },
                    0,
                )
            }
        };

        Ok((value, consumed + value_size))
    }

    /// Build a resource section from a pre-parsed list of entries.
    #[must_use]
    pub fn from_entries(entries: Vec<ResourceEntry>) -> Self {
        let mut section = Self::new();
        for entry in entries {
            section.add_entry(entry);
        }
        section
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_with_strings() -> ResourceSection {
        let mut sec = ResourceSection::new();
        sec.add_entry(ResourceEntry::new(
            "greeting",
            0,
            7,
            ResourceType::String("Hello!".to_owned()),
        ));
        sec.add_entry(ResourceEntry::new(
            "farewell",
            8,
            8,
            ResourceType::String("Goodbye!".to_owned()),
        ));
        sec.add_entry(ResourceEntry::new(
            "icon",
            16,
            10,
            ResourceType::ByteArray(vec![0x89, 0x50, 0x4E, 0x47]),
        ));
        sec
    }

    #[test]
    fn test_resource_section_len() {
        let sec = make_section_with_strings();
        assert_eq!(sec.len(), 3);
    }

    #[test]
    fn test_resource_section_find() {
        let sec = make_section_with_strings();
        assert!(sec.find("greeting").is_some());
        assert!(sec.find("nonexistent").is_none());
    }

    #[test]
    fn test_resource_section_strings() {
        let sec = make_section_with_strings();
        let strings = sec.strings();
        assert_eq!(strings.len(), 2);
        assert!(
            strings
                .iter()
                .any(|(n, v)| *n == "greeting" && *v == "Hello!")
        );
    }

    #[test]
    fn test_resource_section_binary() {
        let sec = make_section_with_strings();
        let binary = sec.binary_entries();
        assert_eq!(binary.len(), 1);
        assert_eq!(binary[0].name, "icon");
    }

    #[test]
    fn test_resource_type_names() {
        assert_eq!(ResourceType::Null.type_name(), "Null");
        assert_eq!(ResourceType::String("x".to_owned()).type_name(), "String");
        assert_eq!(ResourceType::ByteArray(vec![]).type_name(), "Byte[]");
        assert_eq!(ResourceType::Int32(0).type_name(), "Int32");
        assert_eq!(ResourceType::Float64(0.0).type_name(), "Double");
        assert_eq!(ResourceType::Bool(true).type_name(), "Boolean");
    }

    #[test]
    fn test_resource_type_is_string() {
        assert!(ResourceType::String("hello".to_owned()).is_string());
        assert!(!ResourceType::Int32(42).is_string());
    }

    #[test]
    fn test_resource_type_as_string() {
        let r = ResourceType::String("world".to_owned());
        assert_eq!(r.as_string(), Some("world"));
        assert!(ResourceType::Int32(0).as_string().is_none());
    }

    #[test]
    fn test_resource_type_as_bytes() {
        let r = ResourceType::ByteArray(vec![1, 2, 3]);
        assert_eq!(r.as_bytes(), Some(&[1u8, 2, 3][..]));
        let s = ResourceType::Stream(vec![4, 5]);
        assert_eq!(s.as_bytes(), Some(&[4u8, 5][..]));
        assert!(ResourceType::Null.as_bytes().is_none());
    }

    #[test]
    fn test_resource_entry_display() {
        let e = ResourceEntry::new(
            "test",
            0x100,
            0x50,
            ResourceType::String("value".to_owned()),
        );
        let d = e.display();
        assert!(d.contains("test"));
        assert!(d.contains("String"));
    }

    #[test]
    fn test_resource_section_from_entries() {
        let entries = vec![
            ResourceEntry::new("a", 0, 1, ResourceType::Int32(1)),
            ResourceEntry::new("b", 4, 1, ResourceType::Int32(2)),
        ];
        let sec = ResourceSection::from_entries(entries);
        assert_eq!(sec.len(), 2);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = vec![0xAAu8, 0xBB, 0xCC, 0xDD];
        let result = ResourceSection::parse(&data);
        assert!(matches!(result, Err(ResourceError::InvalidMagic)));
    }

    #[test]
    fn test_parse_too_small() {
        let data = vec![0u8; 2];
        let result = ResourceSection::parse(&data);
        assert!(matches!(result, Err(ResourceError::TooSmall)));
    }

    #[test]
    fn test_resource_type_datetime() {
        let r = ResourceType::DateTime(637_123_456_789_000_000i64);
        assert_eq!(r.type_name(), "DateTime");
    }

    #[test]
    fn test_resource_type_timespan() {
        let r = ResourceType::TimeSpan(36_000_000_000i64);
        assert_eq!(r.type_name(), "TimeSpan");
    }

    #[test]
    fn test_resource_type_decimal() {
        let r = ResourceType::Decimal([1, 2, 3, 4]);
        assert_eq!(r.type_name(), "Decimal");
    }

    #[test]
    fn test_resource_section_is_empty() {
        let sec = ResourceSection::new();
        assert!(sec.is_empty());
    }

    #[test]
    fn test_resource_section_not_empty() {
        let mut sec = ResourceSection::new();
        sec.add_entry(ResourceEntry::new("x", 0, 0, ResourceType::Null));
        assert!(!sec.is_empty());
    }

    #[test]
    fn test_resource_unknown() {
        let r = ResourceType::Unknown {
            type_code: 0xFF,
            data: vec![1, 2, 3],
        };
        assert_eq!(r.type_name(), "Unknown");
    }

    #[test]
    fn test_read_7bit_int_single_byte() {
        let data = [0x05u8];
        let (v, c) = ResourceSection::read_7bit_int(&data, 0);
        assert_eq!(v, 5);
        assert_eq!(c, 1);
    }

    #[test]
    fn test_read_7bit_int_two_bytes() {
        // Encode 300 (= 0b100_101100) as two bytes: 0xAC 0x02
        let data = [0xACu8, 0x02];
        let (v, c) = ResourceSection::read_7bit_int(&data, 0);
        assert_eq!(v, 300);
        assert_eq!(c, 2);
    }

    #[test]
    fn test_resource_section_multiple_finds() {
        let sec = make_section_with_strings();
        for name in &["greeting", "farewell", "icon"] {
            assert!(sec.find(name).is_some(), "missing: {name}");
        }
    }
}
