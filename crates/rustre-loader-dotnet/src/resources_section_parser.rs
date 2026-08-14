// resources_section_parser.rs — .NET resources section and ResourceManager parser
// Parses the #Blob stream / .NET resources embedded in assemblies.
// Implements the binary format documented in ECMA-335 §II.24.2.6 and
// the ResourceManager binary format from the .NET runtime source.

use std::collections::HashMap;
use std::fmt;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourcesError {
    TruncatedData { offset: usize, needed: usize, have: usize },
    InvalidMagic { got: u32 },
    InvalidVersion { got: u32 },
    InvalidResourceType(u8),
    InvalidUtf8 { offset: usize },
    NullTerminatorMissing,
    InvalidIndex { index: usize, max: usize },
    Leb128Overflow,
    UnknownTypeCode(u32),
    XmlParseError(String),
}

impl fmt::Display for ResourcesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData { offset, needed, have } =>
                write!(f, "truncated at {offset}: need {needed} have {have}"),
            Self::InvalidMagic { got } =>
                write!(f, "invalid magic 0x{got:08X} (expected 0xBEEFCACE or 0xCECAFEBE)"),
            Self::InvalidVersion { got } =>
                write!(f, "unsupported ResourceManager version {got}"),
            Self::InvalidResourceType(t) =>
                write!(f, "invalid resource type byte 0x{t:02X}"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 at offset {offset}"),
            Self::NullTerminatorMissing =>
                write!(f, "expected null terminator"),
            Self::InvalidIndex { index, max } =>
                write!(f, "index {index} out of range (max {max})"),
            Self::Leb128Overflow =>
                write!(f, "LEB-128 value overflows u64"),
            Self::UnknownTypeCode(c) =>
                write!(f, "unknown ResourceTypeCode 0x{c:08X}"),
            Self::XmlParseError(s) =>
                write!(f, "XML parse error: {s}"),
        }
    }
}

impl std::error::Error for ResourcesError {}

// ── Resource type codes (ResourceTypeCode enum from .NET runtime) ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceTypeCode {
    Null      = 0,
    String    = 1,
    Bool      = 2,
    Char      = 3,
    Byte      = 4,
    SByte     = 5,
    Int16     = 6,
    UInt16    = 7,
    Int32     = 8,
    UInt32    = 9,
    Int64     = 10,
    UInt64    = 11,
    Single    = 12,
    Double    = 13,
    Decimal   = 14,
    DateTime  = 15,
    TimeSpan  = 16,
    StartOfUserTypes = 64,
    ByteArray = 32,
    Stream    = 33,
}

impl ResourceTypeCode {
    pub const fn from_u32(v: u32) -> Result<Self, ResourcesError> {
        match v {
            0  => Ok(Self::Null),
            1  => Ok(Self::String),
            2  => Ok(Self::Bool),
            3  => Ok(Self::Char),
            4  => Ok(Self::Byte),
            5  => Ok(Self::SByte),
            6  => Ok(Self::Int16),
            7  => Ok(Self::UInt16),
            8  => Ok(Self::Int32),
            9  => Ok(Self::UInt32),
            10 => Ok(Self::Int64),
            11 => Ok(Self::UInt64),
            12 => Ok(Self::Single),
            13 => Ok(Self::Double),
            14 => Ok(Self::Decimal),
            15 => Ok(Self::DateTime),
            16 => Ok(Self::TimeSpan),
            32 => Ok(Self::ByteArray),
            33 => Ok(Self::Stream),
            64 => Ok(Self::StartOfUserTypes),
            n  => Err(ResourcesError::UnknownTypeCode(n)),
        }
    }

    #[must_use] 
    pub const fn is_primitive(self) -> bool {
        (self as u32) < 64 && (self as u32) != 32 && (self as u32) != 33
    }
}

// ── ResourceValue ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceValue {
    Null,
    String(String),
    Bool(bool),
    Char(char),
    Byte(u8),
    SByte(i8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Single(f32),
    Double(f64),
    DateTime(i64),   // ticks
    TimeSpan(i64),   // ticks
    ByteArray(Vec<u8>),
    Stream(Vec<u8>),
    UserType { type_name: String, data: Vec<u8> },
}

impl ResourceValue {
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::String(_) => "String",
            Self::Bool(_) => "Boolean",
            Self::Char(_) => "Char",
            Self::Byte(_) => "Byte",
            Self::SByte(_) => "SByte",
            Self::Int16(_) => "Int16",
            Self::UInt16(_) => "UInt16",
            Self::Int32(_) => "Int32",
            Self::UInt32(_) => "UInt32",
            Self::Int64(_) => "Int64",
            Self::UInt64(_) => "UInt64",
            Self::Single(_) => "Single",
            Self::Double(_) => "Double",
            Self::DateTime(_) => "DateTime",
            Self::TimeSpan(_) => "TimeSpan",
            Self::ByteArray(_) => "Byte[]",
            Self::Stream(_) => "Stream",
            Self::UserType { .. } => "UserType",
        }
    }

    #[must_use] 
    pub fn as_string(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s) } else { None }
    }

    #[must_use] 
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::ByteArray(b) | Self::Stream(b) => Some(b),
            _ => None,
        }
    }

    #[must_use] 
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int32(v) => Some(i64::from(*v)),
            Self::Int64(v) => Some(*v),
            Self::Int16(v) => Some(i64::from(*v)),
            Self::Byte(v) => Some(i64::from(*v)),
            Self::SByte(v) => Some(i64::from(*v)),
            Self::UInt16(v) => Some(i64::from(*v)),
            Self::UInt32(v) => Some(i64::from(*v)),
            Self::UInt64(v) => Some(*v as i64),
            _ => None,
        }
    }
}

impl fmt::Display for ResourceValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "<null>"),
            Self::String(s) => write!(f, "{s:?}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Char(c) => write!(f, "'{c}'"),
            Self::Byte(v) => write!(f, "0x{v:02X}"),
            Self::SByte(v) => write!(f, "{v}"),
            Self::Int16(v) => write!(f, "{v}"),
            Self::UInt16(v) => write!(f, "{v}"),
            Self::Int32(v) => write!(f, "{v}"),
            Self::UInt32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}"),
            Self::UInt64(v) => write!(f, "{v}"),
            Self::Single(v) => write!(f, "{v}"),
            Self::Double(v) => write!(f, "{v}"),
            Self::DateTime(t) => write!(f, "DateTime({t})"),
            Self::TimeSpan(t) => write!(f, "TimeSpan({t})"),
            Self::ByteArray(b) => write!(f, "byte[{}]", b.len()),
            Self::Stream(b) => write!(f, "stream[{}]", b.len()),
            Self::UserType { type_name, data } =>
                write!(f, "{}[{} bytes]", type_name, data.len()),
        }
    }
}

// ── ResourceEntry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub name: String,
    pub value: ResourceValue,
}

// ── ResourceSection (raw .NET resources blob) ─────────────────────────────────

pub struct ResourcesSectionParser;

impl ResourcesSectionParser {
    /// Parse a .NET `ResourceManager` binary (.resources) file/stream.
    /// Magic: 0xBEEFCACE (little-endian = CE CA EF BE) or 0xCECAFEBE (big-endian)
    pub fn parse_resources_stream(data: &[u8]) -> Result<Vec<ResourceEntry>, ResourcesError> {
        if data.len() < 4 {
            return Err(ResourcesError::TruncatedData { offset: 0, needed: 4, have: data.len() });
        }
        let magic = rd32(data, 0)?;
        if magic != 0xBEEFCACE && magic != 0xCECAFEBE {
            return Err(ResourcesError::InvalidMagic { got: magic });
        }
        let big_endian = magic == 0xCECAFEBE;

        let version = rd32_maybe_be(data, 4, big_endian)?;
        if version != 1 && version != 2 {
            return Err(ResourcesError::InvalidVersion { got: version });
        }

        // Read header section length (4 bytes), then skip it
        let header_section_len = rd32_maybe_be(data, 8, big_endian)? as usize;
        let header_start = 12usize;
        let data_section_start = header_start + header_section_len;

        // After header_section_len bytes: resource count
        let after_header = header_start.saturating_add(header_section_len);
        if after_header >= data.len() {
            return Err(ResourcesError::TruncatedData { offset: after_header, needed: 4, have: 0 });
        }
        let num_resources = rd32_maybe_be(data, after_header, big_endian)? as usize;

        // Type names (only for version 1)
        let mut pos = after_header + 4;
        let num_types = rd32_maybe_be(data, pos, big_endian)? as usize;
        pos += 4;
        // Cap pre-allocation: each type name consumes >= 1 byte.
        let mut type_names: Vec<String> =
            Vec::with_capacity(num_types.min(data.len().saturating_sub(pos)));
        for _ in 0..num_types {
            let (s, consumed) = read_dotnet_string(data, pos)?;
            type_names.push(s);
            pos += consumed;
        }

        // Padding to 8-byte boundary
        pos = (pos + 7) & !7;

        // Name hashes (4 bytes * num_resources)
        let _name_hashes_start = pos;
        let hash_section_size = num_resources.checked_mul(4)
            .ok_or(ResourcesError::Leb128Overflow)?;
        if pos.saturating_add(hash_section_size) > data.len() {
            return Err(ResourcesError::TruncatedData { offset: pos, needed: hash_section_size, have: data.len().saturating_sub(pos) });
        }
        pos += hash_section_size;

        // Name positions (4 bytes * num_resources) — offsets from start of name section
        let name_positions_start = pos;
        let name_pos_size = num_resources.checked_mul(4)
            .ok_or(ResourcesError::Leb128Overflow)?;
        if pos.saturating_add(name_pos_size) > data.len() {
            return Err(ResourcesError::TruncatedData { offset: pos, needed: name_pos_size, have: data.len().saturating_sub(pos) });
        }
        pos += name_pos_size;

        // Data section offset (4 bytes)
        let data_section_off = rd32_maybe_be(data, pos, big_endian)? as usize;
        pos += 4;

        // Now read name + data for each resource
        let name_section_base = pos;
        let data_base = data_section_off;
        let _ = data_section_start;

        let mut entries = Vec::with_capacity(num_resources);
        for i in 0..num_resources {
            // read name offset
            let name_off_pos = name_positions_start + i * 4;
            let name_off = rd32_maybe_be(data, name_off_pos, big_endian)? as usize;
            let name_pos = name_section_base + name_off;

            // name is a length-prefixed UTF-16LE string
            let (name, _) = read_utf16le_string(data, name_pos)?;

            // 4-byte data offset follows the name
            let data_off_pos = name_pos + 2 * ((data[name_pos] as usize) + 1); // approx
            // Actually: name is encoded as a 7-bit encoded length then chars. Use helper:
            let (name2, name_consumed) = read_dotnet_string_utf16(data, name_pos)?;
            let resource_data_off = rd32_maybe_be(data, name_pos + name_consumed, big_endian)? as usize;
            let _ = name;
            let _ = data_off_pos;
            let name = name2;

            // Read resource value at data_base + resource_data_off
            let value_pos = data_base + resource_data_off;
            if value_pos >= data.len() {
                entries.push(ResourceEntry { name, value: ResourceValue::Null });
                continue;
            }

            let (value, _) = Self::read_resource_value(data, value_pos, &type_names)?;
            entries.push(ResourceEntry { name, value });
        }

        Ok(entries)
    }

    fn read_resource_value(data: &[u8], pos: usize, type_names: &[String])
        -> Result<(ResourceValue, usize), ResourcesError>
    {
        let (type_code_raw, leb_size) = read_leb128(data, pos)?;
        let consumed_base = leb_size;

        // User-defined types use any code >= 64; treat them uniformly as
        // StartOfUserTypes here even though `from_u32` only accepts exactly 64
        // as a valid named variant.
        let tc = if type_code_raw as u32 >= 64 {
            ResourceTypeCode::StartOfUserTypes
        } else {
            ResourceTypeCode::from_u32(type_code_raw as u32)?
        };
        let p = pos + consumed_base;

        match tc {
            ResourceTypeCode::String => {
                let (s, sz) = read_dotnet_string(data, p)?;
                Ok((ResourceValue::String(s), consumed_base + sz))
            }
            ResourceTypeCode::Bool => {
                ensure_len(data, p, 1)?;
                Ok((ResourceValue::Bool(data[p] != 0), consumed_base + 1))
            }
            ResourceTypeCode::Char => {
                ensure_len(data, p, 2)?;
                let codepoint = u32::from(u16::from_le_bytes([data[p], data[p+1]]));
                let c = char::from_u32(codepoint).unwrap_or('\u{FFFD}');
                Ok((ResourceValue::Char(c), consumed_base + 2))
            }
            ResourceTypeCode::Byte => {
                ensure_len(data, p, 1)?;
                Ok((ResourceValue::Byte(data[p]), consumed_base + 1))
            }
            ResourceTypeCode::SByte => {
                ensure_len(data, p, 1)?;
                Ok((ResourceValue::SByte(data[p] as i8), consumed_base + 1))
            }
            ResourceTypeCode::Int16 => {
                ensure_len(data, p, 2)?;
                Ok((ResourceValue::Int16(i16::from_le_bytes([data[p], data[p+1]])), consumed_base + 2))
            }
            ResourceTypeCode::UInt16 => {
                ensure_len(data, p, 2)?;
                Ok((ResourceValue::UInt16(u16::from_le_bytes([data[p], data[p+1]])), consumed_base + 2))
            }
            ResourceTypeCode::Int32 => {
                ensure_len(data, p, 4)?;
                Ok((ResourceValue::Int32(i32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]])), consumed_base + 4))
            }
            ResourceTypeCode::UInt32 => {
                ensure_len(data, p, 4)?;
                Ok((ResourceValue::UInt32(u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]])), consumed_base + 4))
            }
            ResourceTypeCode::Int64 => {
                ensure_len(data, p, 8)?;
                let v = i64::from_le_bytes(data[p..p+8].try_into().unwrap());
                Ok((ResourceValue::Int64(v), consumed_base + 8))
            }
            ResourceTypeCode::UInt64 => {
                ensure_len(data, p, 8)?;
                let v = u64::from_le_bytes(data[p..p+8].try_into().unwrap());
                Ok((ResourceValue::UInt64(v), consumed_base + 8))
            }
            ResourceTypeCode::Single => {
                ensure_len(data, p, 4)?;
                let v = f32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
                Ok((ResourceValue::Single(v), consumed_base + 4))
            }
            ResourceTypeCode::Double => {
                ensure_len(data, p, 8)?;
                let v = f64::from_le_bytes(data[p..p+8].try_into().unwrap());
                Ok((ResourceValue::Double(v), consumed_base + 8))
            }
            ResourceTypeCode::DateTime => {
                ensure_len(data, p, 8)?;
                let v = i64::from_le_bytes(data[p..p+8].try_into().unwrap());
                Ok((ResourceValue::DateTime(v), consumed_base + 8))
            }
            ResourceTypeCode::TimeSpan => {
                ensure_len(data, p, 8)?;
                let v = i64::from_le_bytes(data[p..p+8].try_into().unwrap());
                Ok((ResourceValue::TimeSpan(v), consumed_base + 8))
            }
            ResourceTypeCode::ByteArray | ResourceTypeCode::Stream => {
                ensure_len(data, p, 4)?;
                let len = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]) as usize;
                ensure_len(data, p + 4, len)?;
                let bytes = data[p+4..p+4+len].to_vec();
                let v = if tc == ResourceTypeCode::ByteArray {
                    ResourceValue::ByteArray(bytes)
                } else {
                    ResourceValue::Stream(bytes)
                };
                Ok((v, consumed_base + 4 + len))
            }
            ResourceTypeCode::StartOfUserTypes => {
                let type_idx = (type_code_raw as u32 - 64) as usize;
                let type_name = type_names.get(type_idx)
                    .cloned()
                    .unwrap_or_else(|| format!("UserType{type_idx}"));
                ensure_len(data, p, 4)?;
                let len = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]) as usize;
                ensure_len(data, p + 4, len)?;
                let bytes = data[p+4..p+4+len].to_vec();
                Ok((ResourceValue::UserType { type_name, data: bytes }, consumed_base + 4 + len))
            }
            _ => Ok((ResourceValue::Null, consumed_base)),
        }
    }

    /// Extract all string resources from entries.
    #[must_use] 
    pub fn extract_strings(entries: &[ResourceEntry]) -> Vec<(&str, &str)> {
        entries.iter()
            .filter_map(|e| {
                if let ResourceValue::String(s) = &e.value {
                    Some((e.name.as_str(), s.as_str()))
                } else { None }
            })
            .collect()
    }

    /// Extract all embedded byte/stream resources.
    #[must_use] 
    pub fn extract_embedded_files(entries: &[ResourceEntry]) -> Vec<(&str, &[u8])> {
        entries.iter()
            .filter_map(|e| {
                e.value.as_bytes().map(|b| (e.name.as_str(), b))
            })
            .collect()
    }

    /// Parse minimal RESX XML (text only, no System.Xml dependency).
    /// Format: <root><data name="key"><value>text</value></data></root>
    pub fn parse_resx_xml(xml: &str) -> Result<HashMap<String, String>, ResourcesError> {
        let mut map = HashMap::new();
        // Very simple pull parser — find <data name="..."> ... <value>...</value>
        let mut search = xml;
        while let Some(data_tag_start) = search.find("<data ") {
            search = &search[data_tag_start..];
            // extract name=
            let name = if let Some(name_start) = search.find("name=\"") {
                let after = &search[name_start + 6..];
                if let Some(end) = after.find('"') {
                    after[..end].to_string()
                } else { break; }
            } else { break; };

            // find <value>
            if let Some(val_start) = search.find("<value>") {
                let after_val = &search[val_start + 7..];
                if let Some(val_end) = after_val.find("</value>") {
                    let value = after_val[..val_end].to_string();
                    map.insert(name, value);
                    search = &after_val[val_end + 8..];
                } else { break; }
            } else {
                search = &search[6..];
            }
        }
        Ok(map)
    }
}

// ── ResourceManager header (v1/v2) helper ─────────────────────────────────────

#[derive(Debug)]
pub struct ResourceManagerInfo {
    pub version: u32,
    pub num_resources: u32,
    pub num_types: u32,
    pub type_names: Vec<String>,
}

impl ResourceManagerInfo {
    #[must_use] 
    pub fn probe(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        let magic = rd32(data, 0).ok()?;
        if magic != 0xBEEFCACE && magic != 0xCECAFEBE { return None; }
        let be = magic == 0xCECAFEBE;
        let version = rd32_maybe_be(data, 4, be).ok()?;
        let header_len = rd32_maybe_be(data, 8, be).ok()? as usize;
        let after = 12 + header_len;
        let num_resources = rd32_maybe_be(data, after, be).ok()?;
        let num_types = rd32_maybe_be(data, after + 4, be).ok()?;
        let mut pos = after + 8;
        let mut type_names = Vec::new();
        for _ in 0..num_types as usize {
            if let Ok((s, sz)) = read_dotnet_string(data, pos) {
                type_names.push(s);
                pos += sz;
            } else { break; }
        }
        Some(Self { version, num_resources, num_types, type_names })
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

const fn ensure_len(data: &[u8], offset: usize, needed: usize) -> Result<(), ResourcesError> {
    // saturating_add: offset + needed must not wrap around on adversarial input
    if data.len() < offset.saturating_add(needed) {
        Err(ResourcesError::TruncatedData {
            offset, needed, have: data.len().saturating_sub(offset)
        })
    } else {
        Ok(())
    }
}

fn rd32(data: &[u8], pos: usize) -> Result<u32, ResourcesError> {
    ensure_len(data, pos, 4)?;
    Ok(u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
}

fn rd32_maybe_be(data: &[u8], pos: usize, big_endian: bool) -> Result<u32, ResourcesError> {
    ensure_len(data, pos, 4)?;
    if big_endian {
        Ok(u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
    } else {
        Ok(u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
    }
}

/// Read a .NET "7-bit encoded int" prefixed UTF-8 string.
fn read_dotnet_string(data: &[u8], pos: usize) -> Result<(String, usize), ResourcesError> {
    let (len, leb_sz) = read_7bit_encoded_int(data, pos)?;
    let start = pos + leb_sz;
    ensure_len(data, start, len as usize)?;
    let s = std::str::from_utf8(&data[start..start + len as usize])
        .map_err(|_| ResourcesError::InvalidUtf8 { offset: start })?;
    Ok((s.to_string(), leb_sz + len as usize))
}

/// Read a .NET "7-bit encoded int" prefixed UTF-16LE string (resource names).
fn read_dotnet_string_utf16(data: &[u8], pos: usize) -> Result<(String, usize), ResourcesError> {
    let (char_count, leb_sz) = read_7bit_encoded_int(data, pos)?;
    let byte_count = char_count as usize * 2;
    let start = pos + leb_sz;
    ensure_len(data, start, byte_count)?;
    let chars: Vec<u16> = (0..char_count as usize)
        .map(|i| u16::from_le_bytes([data[start + i * 2], data[start + i * 2 + 1]]))
        .collect();
    let s = String::from_utf16_lossy(&chars);
    Ok((s, leb_sz + byte_count))
}

/// Read a null-terminated UTF-16LE string (approximate fallback).
fn read_utf16le_string(data: &[u8], pos: usize) -> Result<(String, usize), ResourcesError> {
    let mut chars = Vec::new();
    let mut p = pos;
    while p + 2 <= data.len() {
        let c = u16::from_le_bytes([data[p], data[p+1]]);
        p += 2;
        if c == 0 { break; }
        chars.push(c);
    }
    Ok((String::from_utf16_lossy(&chars), p - pos))
}

/// Read a .NET `BinaryWriter` "7-bit encoded int" (LEB-128 variant).
fn read_7bit_encoded_int(data: &[u8], pos: usize) -> Result<(u32, usize), ResourcesError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        if pos + i >= data.len() {
            return Err(ResourcesError::TruncatedData { offset: pos + i, needed: 1, have: 0 });
        }
        let b = data[pos + i];
        i += 1;
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if (b & 0x80) == 0 { break; }
        if shift >= 35 {
            return Err(ResourcesError::Leb128Overflow);
        }
    }
    Ok((result, i))
}

/// Read a ULEB-128 encoded unsigned integer (used in `CodedTokens` etc.).
fn read_leb128(data: &[u8], pos: usize) -> Result<(u64, usize), ResourcesError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        if pos + i >= data.len() {
            return Err(ResourcesError::TruncatedData { offset: pos + i, needed: 1, have: 0 });
        }
        let b = data[pos + i];
        i += 1;
        result |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if (b & 0x80) == 0 { break; }
        if shift >= 70 {
            return Err(ResourcesError::Leb128Overflow);
        }
    }
    Ok((result, i))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_code_primitives() {
        assert_eq!(ResourceTypeCode::from_u32(1).unwrap(), ResourceTypeCode::String);
        assert_eq!(ResourceTypeCode::from_u32(8).unwrap(), ResourceTypeCode::Int32);
        assert_eq!(ResourceTypeCode::from_u32(0).unwrap(), ResourceTypeCode::Null);
        assert!(ResourceTypeCode::from_u32(99).is_err());
    }

    #[test]
    fn test_resource_type_code_is_primitive() {
        assert!(ResourceTypeCode::String.is_primitive());
        assert!(ResourceTypeCode::Int32.is_primitive());
        assert!(!ResourceTypeCode::ByteArray.is_primitive());
        assert!(!ResourceTypeCode::Stream.is_primitive());
    }

    #[test]
    fn test_resource_value_type_name() {
        assert_eq!(ResourceValue::Null.type_name(), "null");
        assert_eq!(ResourceValue::String("hi".into()).type_name(), "String");
        assert_eq!(ResourceValue::ByteArray(vec![]).type_name(), "Byte[]");
    }

    #[test]
    fn test_resource_value_as_i64() {
        assert_eq!(ResourceValue::Int32(42).as_i64(), Some(42));
        assert_eq!(ResourceValue::Int64(-100).as_i64(), Some(-100));
        assert_eq!(ResourceValue::String("x".into()).as_i64(), None);
    }

    #[test]
    fn test_resource_value_display() {
        let s = format!("{}", ResourceValue::String("hello".into()));
        assert!(s.contains("hello"));
        let b = format!("{}", ResourceValue::ByteArray(vec![1,2,3]));
        assert!(b.contains('3'));
    }

    #[test]
    fn test_read_7bit_encoded_int_single_byte() {
        let data = [0x2A];
        let (v, sz) = read_7bit_encoded_int(&data, 0).unwrap();
        assert_eq!(v, 42);
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_read_7bit_encoded_int_two_bytes() {
        // 300 = 0x12C → 0xAC 0x02
        let data = [0xAC, 0x02];
        let (v, sz) = read_7bit_encoded_int(&data, 0).unwrap();
        assert_eq!(v, 300);
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_read_leb128() {
        let data = [0x01];
        let (v, sz) = read_leb128(&data, 0).unwrap();
        assert_eq!(v, 1);
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_read_leb128_multibyte() {
        let data = [0x80, 0x01]; // 128
        let (v, sz) = read_leb128(&data, 0).unwrap();
        assert_eq!(v, 128);
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_read_dotnet_string() {
        let mut data = vec![0x05u8]; // length = 5
        data.extend_from_slice(b"hello");
        let (s, sz) = read_dotnet_string(&data, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(sz, 6);
    }

    #[test]
    fn test_read_dotnet_string_utf16() {
        let mut data = vec![0x03u8]; // 3 chars
        for c in "abc".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let (s, sz) = read_dotnet_string_utf16(&data, 0).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(sz, 7);
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = ResourcesSectionParser::parse_resources_stream(&data).unwrap_err();
        assert!(matches!(err, ResourcesError::InvalidMagic { .. }));
    }

    #[test]
    fn test_extract_strings_empty() {
        let entries = vec![];
        let strings = ResourcesSectionParser::extract_strings(&entries);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings() {
        let entries = vec![
            ResourceEntry { name: "key1".into(), value: ResourceValue::String("val1".into()) },
            ResourceEntry { name: "key2".into(), value: ResourceValue::Int32(42) },
        ];
        let s = ResourcesSectionParser::extract_strings(&entries);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], ("key1", "val1"));
    }

    #[test]
    fn test_extract_embedded_files() {
        let entries = vec![
            ResourceEntry { name: "img".into(), value: ResourceValue::ByteArray(vec![1,2,3]) },
            ResourceEntry { name: "str".into(), value: ResourceValue::String("x".into()) },
        ];
        let files = ResourcesSectionParser::extract_embedded_files(&entries);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "img");
        assert_eq!(files[0].1, &[1u8, 2, 3]);
    }

    #[test]
    fn test_parse_resx_xml_empty() {
        let map = ResourcesSectionParser::parse_resx_xml("<root></root>").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_resx_xml_single() {
        let xml = r#"<root>
  <data name="greeting">
    <value>Hello World</value>
  </data>
</root>"#;
        let map = ResourcesSectionParser::parse_resx_xml(xml).unwrap();
        assert_eq!(map.get("greeting").map(std::string::String::as_str), Some("Hello World"));
    }

    #[test]
    fn test_parse_resx_xml_multiple() {
        let xml = r#"<root>
  <data name="a"><value>alpha</value></data>
  <data name="b"><value>beta</value></data>
</root>"#;
        let map = ResourcesSectionParser::parse_resx_xml(xml).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["a"], "alpha");
        assert_eq!(map["b"], "beta");
    }

    #[test]
    fn test_resource_manager_info_invalid() {
        let data = [0u8; 8];
        assert!(ResourceManagerInfo::probe(&data).is_none());
    }

    #[test]
    fn test_resource_value_char() {
        let v = ResourceValue::Char('A');
        assert_eq!(format!("{v}"), "'A'");
    }

    #[test]
    fn test_resource_value_datetime() {
        let ticks = 637_000_000_000_000_000i64;
        let v = ResourceValue::DateTime(ticks);
        let s = format!("{v}");
        assert!(s.contains("DateTime"));
    }

    #[test]
    fn test_rd32_truncated() {
        let data = [1u8, 2, 3];
        assert!(matches!(rd32(&data, 1), Err(ResourcesError::TruncatedData { .. })));
    }
}
