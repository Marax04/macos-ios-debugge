//! OLE property stream reader.
//!
//! Parses `\x05SummaryInformation` and `\x05DocumentSummaryInformation`
//! streams according to MS-OLEPS (OLE Property Set Data Structures).
//!
//! Each property stream contains one or more *property sets*, each with a
//! FMTID (format identifier GUID) and a collection of typed property values.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the OLE property reader.
#[derive(Debug, thiserror::Error)]
pub enum PropertyError {
    /// The stream is too short for the expected structure.
    #[error("truncated property stream")]
    TruncatedStream,
    /// An unknown property type code was encountered.
    #[error("unknown property type: {0:#06x}")]
    UnknownType(u16),
    /// A string could not be decoded.
    #[error("string decode error")]
    StringDecode,
    /// The property count exceeds a sanity limit.
    #[error("property count too large: {0}")]
    TooManyProperties(u32),
}

/// Maximum number of properties per set (sanity limit).
const MAX_PROPERTIES: u32 = 4096;

// ─── PropertyVariant ─────────────────────────────────────────────────────────

/// A typed property value as defined by the MS-OLEPS `TYPEDPROPERTYVALUE`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyVariant {
    /// `VT_EMPTY` (0x0000) — no value.
    Empty,
    /// `VT_NULL` (0x0001) — null value.
    Null,
    /// `VT_I2` (0x0002) — 16-bit signed integer.
    I2(i16),
    /// `VT_I4` (0x0003) — 32-bit signed integer.
    I4(i32),
    /// `VT_R4` (0x0004) — 32-bit IEEE floating point.
    R4(f32),
    /// `VT_R8` (0x0005) — 64-bit IEEE floating point.
    R8(f64),
    /// `VT_BOOL` (0x000B) — boolean (0xFFFF = true, 0x0000 = false).
    Bool(bool),
    /// `VT_I1` (0x0010) — 8-bit signed integer.
    I1(i8),
    /// `VT_UI1` (0x0011) — 8-bit unsigned integer.
    Ui1(u8),
    /// `VT_UI2` (0x0012) — 16-bit unsigned integer.
    Ui2(u16),
    /// `VT_UI4` (0x0013) — 32-bit unsigned integer.
    Ui4(u32),
    /// `VT_I8` (0x0014) — 64-bit signed integer.
    I8(i64),
    /// `VT_UI8` (0x0015) — 64-bit unsigned integer.
    Ui8(u64),
    /// `VT_LPSTR` (0x001E) — code-page string (counted byte string).
    LpStr(String),
    /// `VT_LPWSTR` (0x001F) — Unicode string (counted wide string).
    LpWStr(String),
    /// `VT_FILETIME` (0x0040) — FILETIME (64-bit Windows timestamp).
    FileTime(u64),
    /// `VT_BLOB` (0x0041) — raw bytes.
    Blob(Vec<u8>),
    /// `VT_CF` (0x0047) — clipboard format.
    Cf(Vec<u8>),
    /// Any other type code — stores the raw bytes.
    Unknown {
        /// Type code.
        vt: u16,
        /// Raw payload.
        data: Vec<u8>,
    },
}

impl PropertyVariant {
    /// Return a human-readable type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Empty => "VT_EMPTY",
            Self::Null => "VT_NULL",
            Self::I2(_) => "VT_I2",
            Self::I4(_) => "VT_I4",
            Self::R4(_) => "VT_R4",
            Self::R8(_) => "VT_R8",
            Self::Bool(_) => "VT_BOOL",
            Self::I1(_) => "VT_I1",
            Self::Ui1(_) => "VT_UI1",
            Self::Ui2(_) => "VT_UI2",
            Self::Ui4(_) => "VT_UI4",
            Self::I8(_) => "VT_I8",
            Self::Ui8(_) => "VT_UI8",
            Self::LpStr(_) => "VT_LPSTR",
            Self::LpWStr(_) => "VT_LPWSTR",
            Self::FileTime(_) => "VT_FILETIME",
            Self::Blob(_) => "VT_BLOB",
            Self::Cf(_) => "VT_CF",
            Self::Unknown { .. } => "VT_UNKNOWN",
        }
    }

    /// Return the string value, if this is a string variant.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::LpStr(s) | Self::LpWStr(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the i4 value if this is `VT_I4`.
    #[must_use]
    pub const fn as_i4(&self) -> Option<i32> {
        if let Self::I4(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Return the boolean value if this is `VT_BOOL`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

impl fmt::Display for PropertyVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "<empty>"),
            Self::Null => write!(f, "<null>"),
            Self::I2(v) => write!(f, "{v}i16"),
            Self::I4(v) => write!(f, "{v}i32"),
            Self::R4(v) => write!(f, "{v}f32"),
            Self::R8(v) => write!(f, "{v}f64"),
            Self::Bool(b) => write!(f, "{}", if *b { "true" } else { "false" }),
            Self::I1(v) => write!(f, "{v}i8"),
            Self::Ui1(v) => write!(f, "{v}u8"),
            Self::Ui2(v) => write!(f, "{v}u16"),
            Self::Ui4(v) => write!(f, "{v}u32"),
            Self::I8(v) => write!(f, "{v}i64"),
            Self::Ui8(v) => write!(f, "{v}u64"),
            Self::LpStr(s) | Self::LpWStr(s) => write!(f, "\"{s}\""),
            Self::FileTime(ft) => write!(f, "FILETIME({ft:#018x})"),
            Self::Blob(b) => write!(f, "Blob({} bytes)", b.len()),
            Self::Cf(b) => write!(f, "CF({} bytes)", b.len()),
            Self::Unknown { vt, data } => write!(f, "Unknown(vt={vt:#06x}, {} bytes)", data.len()),
        }
    }
}

// ─── PropertyId ──────────────────────────────────────────────────────────────

/// Well-known property identifiers for `SummaryInformation`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SummaryPropertyId {
    Title = 0x0002,
    Subject = 0x0003,
    Author = 0x0004,
    Keywords = 0x0005,
    Comments = 0x0006,
    Template = 0x0007,
    LastAuthor = 0x0008,
    RevisionNumber = 0x0009,
    TotalEditingTime = 0x000A,
    LastPrinted = 0x000B,
    CreateTime = 0x000C,
    LastSaved = 0x000D,
    PageCount = 0x000E,
    WordCount = 0x000F,
    CharCount = 0x0010,
    AppName = 0x0012,
    Security = 0x0013,
}

impl SummaryPropertyId {
    /// Try to parse from a raw property ID.
    #[must_use]
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            0x0002 => Some(Self::Title),
            0x0003 => Some(Self::Subject),
            0x0004 => Some(Self::Author),
            0x0005 => Some(Self::Keywords),
            0x0006 => Some(Self::Comments),
            0x0007 => Some(Self::Template),
            0x0008 => Some(Self::LastAuthor),
            0x0009 => Some(Self::RevisionNumber),
            0x000A => Some(Self::TotalEditingTime),
            0x000B => Some(Self::LastPrinted),
            0x000C => Some(Self::CreateTime),
            0x000D => Some(Self::LastSaved),
            0x000E => Some(Self::PageCount),
            0x000F => Some(Self::WordCount),
            0x0010 => Some(Self::CharCount),
            0x0012 => Some(Self::AppName),
            0x0013 => Some(Self::Security),
            _ => None,
        }
    }

    /// Return the property name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Title => "Title",
            Self::Subject => "Subject",
            Self::Author => "Author",
            Self::Keywords => "Keywords",
            Self::Comments => "Comments",
            Self::Template => "Template",
            Self::LastAuthor => "LastAuthor",
            Self::RevisionNumber => "RevisionNumber",
            Self::TotalEditingTime => "TotalEditingTime",
            Self::LastPrinted => "LastPrinted",
            Self::CreateTime => "CreateTime",
            Self::LastSaved => "LastSaved",
            Self::PageCount => "PageCount",
            Self::WordCount => "WordCount",
            Self::CharCount => "CharCount",
            Self::AppName => "AppName",
            Self::Security => "Security",
        }
    }
}

impl fmt::Display for SummaryPropertyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── PropertyEntry ────────────────────────────────────────────────────────────

/// A single property ID → value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyEntry {
    /// Property identifier.
    pub id: u32,
    /// Typed value.
    pub value: PropertyVariant,
}

impl PropertyEntry {
    /// Return a human-readable name for this property if it is a known
    /// `SummaryInformation` property.
    #[must_use]
    pub fn name(&self) -> String {
        SummaryPropertyId::from_id(self.id).map_or_else(|| format!("PID_{:#010x}", self.id), |p| p.name().to_owned())
    }
}

impl fmt::Display for PropertyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name(), self.value)
    }
}

// ─── PropertySet ──────────────────────────────────────────────────────────────

/// A parsed OLE property set (one FMTID section within the property stream).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PropertySet {
    /// FMTID of this property set (16 bytes, stored as hex string).
    pub fmtid: String,
    /// All properties, keyed by their property ID.
    pub properties: HashMap<u32, PropertyVariant>,
}

impl PropertySet {
    /// Create a new empty property set with the given FMTID.
    #[must_use]
    pub fn new(fmtid: impl Into<String>) -> Self {
        Self {
            fmtid: fmtid.into(),
            properties: HashMap::new(),
        }
    }

    /// Insert a property.
    pub fn insert(&mut self, id: u32, value: PropertyVariant) {
        self.properties.insert(id, value);
    }

    /// Look up a property by its ID.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&PropertyVariant> {
        self.properties.get(&id)
    }

    /// Look up a known `SummaryInformation` property.
    #[must_use]
    pub fn get_summary(&self, prop: SummaryPropertyId) -> Option<&PropertyVariant> {
        self.get(prop as u32)
    }

    /// Return the title, if present.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.get_summary(SummaryPropertyId::Title)
            .and_then(|v| v.as_str())
    }

    /// Return the author, if present.
    #[must_use]
    pub fn author(&self) -> Option<&str> {
        self.get_summary(SummaryPropertyId::Author)
            .and_then(|v| v.as_str())
    }

    /// Return the application name, if present.
    #[must_use]
    pub fn app_name(&self) -> Option<&str> {
        self.get_summary(SummaryPropertyId::AppName)
            .and_then(|v| v.as_str())
    }

    /// Return the number of properties.
    #[must_use]
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Return `true` if no properties are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }

    /// Return all entries sorted by property ID.
    #[must_use]
    pub fn sorted_entries(&self) -> Vec<PropertyEntry> {
        let mut entries: Vec<PropertyEntry> = self
            .properties
            .iter()
            .map(|(&id, value)| PropertyEntry {
                id,
                value: value.clone(),
            })
            .collect();
        entries.sort_by_key(|e| e.id);
        entries
    }
}

// ─── OlePropertyReader ────────────────────────────────────────────────────────

/// Reads and parses OLE2 property streams (`SummaryInformation` /
/// `DocumentSummaryInformation`) from raw stream bytes.
pub struct OlePropertyReader;

impl OlePropertyReader {
    /// Create a new property reader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a property set stream from raw bytes.
    ///
    /// Follows the MS-OLEPS binary layout:
    /// - Byte order mark (2 bytes, always `0xFEFF`)
    /// - Version (2 bytes)
    /// - System identifier (4 bytes)
    /// - CLSID (16 bytes)
    /// - Reserved (4 bytes)
    /// - Number of property sets (4 bytes)
    /// - For each property set: FMTID (16 bytes) + offset (4 bytes)
    ///
    /// # Errors
    /// Returns [`PropertyError::TruncatedStream`] if the data is too short.
    pub fn parse_stream(&self, data: &[u8]) -> Result<Vec<PropertySet>, PropertyError> {
        if data.len() < 48 {
            return Err(PropertyError::TruncatedStream);
        }

        // Byte order mark at offset 0
        let _bom = u16::from_le_bytes([data[0], data[1]]);
        // Version at offset 2
        let _version = u16::from_le_bytes([data[2], data[3]]);
        // Number of property sets at offset 44
        let count = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        // Sanity-limit: MS-OLEPS allows at most 31 property sets in practice;
        // reject anything larger to avoid OOM from adversarial input.
        if count > 31 {
            return Err(PropertyError::TooManyProperties(count));
        }

        let mut sets = Vec::new();
        let header_base = 48usize;

        for i in 0..count as usize {
            let desc_off = header_base + i * 20;
            if desc_off + 20 > data.len() {
                return Err(PropertyError::TruncatedStream);
            }
            // FMTID is 16 bytes starting at desc_off
            let fmtid_bytes = &data[desc_off..desc_off + 16];
            let fmtid = format_fmtid(fmtid_bytes);
            // Offset to property set data (4 bytes at desc_off + 16)
            let set_offset =
                u32::from_le_bytes([data[desc_off + 16], data[desc_off + 17], data[desc_off + 18], data[desc_off + 19]]) as usize;

            let prop_set = self.parse_property_set(data, set_offset, fmtid)?;
            sets.push(prop_set);
        }

        Ok(sets)
    }

    /// Parse a single property set at the given byte offset within `data`.
    fn parse_property_set(
        &self,
        data: &[u8],
        offset: usize,
        fmtid: String,
    ) -> Result<PropertySet, PropertyError> {
        if offset + 8 > data.len() {
            return Err(PropertyError::TruncatedStream);
        }

        let _size = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let prop_count = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);

        if prop_count > MAX_PROPERTIES {
            return Err(PropertyError::TooManyProperties(prop_count));
        }

        let mut set = PropertySet::new(fmtid);

        // Each property identifier+offset is a pair of u32 values (8 bytes).
        for i in 0..prop_count as usize {
            let id_off = offset + 8 + i * 8;
            if id_off + 8 > data.len() {
                break;
            }
            let prop_id = u32::from_le_bytes([data[id_off], data[id_off + 1], data[id_off + 2], data[id_off + 3]]);
            let prop_off = u32::from_le_bytes([data[id_off + 4], data[id_off + 5], data[id_off + 6], data[id_off + 7]]) as usize;
            let abs_off = offset + prop_off;

            if let Ok(variant) = self.parse_variant(data, abs_off) {
                set.insert(prop_id, variant);
            }
        }

        Ok(set)
    }

    /// Parse a `TYPEDPROPERTYVALUE` at `offset` in `data`.
    fn parse_variant(&self, data: &[u8], offset: usize) -> Result<PropertyVariant, PropertyError> {
        if offset + 4 > data.len() {
            return Err(PropertyError::TruncatedStream);
        }
        let vt = u16::from_le_bytes([data[offset], data[offset + 1]]);
        // Padding / reserved at [offset+2..offset+4] is ignored.

        match vt {
            0x0000 => Ok(PropertyVariant::Empty),
            0x0001 => Ok(PropertyVariant::Null),
            0x0002 => {
                if offset + 6 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::I2(i16::from_le_bytes([data[offset + 4], data[offset + 5]])))
            }
            0x0003 => {
                if offset + 8 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::I4(i32::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                ])))
            }
            0x0004 => {
                if offset + 8 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                let bits = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
                Ok(PropertyVariant::R4(f32::from_bits(bits)))
            }
            0x0005 => {
                if offset + 12 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                let bits = u64::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                ]);
                Ok(PropertyVariant::R8(f64::from_bits(bits)))
            }
            0x000B => {
                if offset + 6 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                let raw = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
                Ok(PropertyVariant::Bool(raw != 0))
            }
            0x0010 => {
                if offset + 5 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::I1(data[offset + 4] as i8))
            }
            0x0011 => {
                if offset + 5 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::Ui1(data[offset + 4]))
            }
            0x0012 => {
                if offset + 6 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::Ui2(u16::from_le_bytes([data[offset + 4], data[offset + 5]])))
            }
            0x0013 => {
                if offset + 8 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::Ui4(u32::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                ])))
            }
            0x0014 => {
                if offset + 12 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::I8(i64::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                ])))
            }
            0x0015 => {
                if offset + 12 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::Ui8(u64::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                ])))
            }
            0x001E => self.parse_lpstr(data, offset),
            0x001F => self.parse_lpwstr(data, offset),
            0x0040 => {
                if offset + 12 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                Ok(PropertyVariant::FileTime(u64::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                ])))
            }
            0x0041 | 0x0047 => {
                if offset + 8 > data.len() {
                    return Err(PropertyError::TruncatedStream);
                }
                let size = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]) as usize;
                let end = (offset + 8 + size).min(data.len());
                let blob = data[offset + 8..end].to_vec();
                if vt == 0x0041 {
                    Ok(PropertyVariant::Blob(blob))
                } else {
                    Ok(PropertyVariant::Cf(blob))
                }
            }
            other => Ok(PropertyVariant::Unknown {
                vt: other,
                data: vec![],
            }),
        }
    }

    /// Parse a `VT_LPSTR` (counted byte string) at `offset`.
    fn parse_lpstr(&self, data: &[u8], offset: usize) -> Result<PropertyVariant, PropertyError> {
        if offset + 8 > data.len() {
            return Err(PropertyError::TruncatedStream);
        }
        let count = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]) as usize;
        if count == 0 {
            return Ok(PropertyVariant::LpStr(String::new()));
        }
        if offset + 8 + count > data.len() {
            return Err(PropertyError::TruncatedStream);
        }
        let raw = &data[offset + 8..offset + 8 + count];
        // Strip NUL terminator if present
        let s = raw
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        Ok(PropertyVariant::LpStr(s))
    }

    /// Parse a `VT_LPWSTR` (counted wide string) at `offset`.
    fn parse_lpwstr(&self, data: &[u8], offset: usize) -> Result<PropertyVariant, PropertyError> {
        if offset + 8 > data.len() {
            return Err(PropertyError::TruncatedStream);
        }
        let count = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]) as usize;
        if count == 0 {
            return Ok(PropertyVariant::LpWStr(String::new()));
        }
        let byte_count = count * 2;
        if offset + 8 + byte_count > data.len() {
            return Err(PropertyError::TruncatedStream);
        }
        let raw = &data[offset + 8..offset + 8 + byte_count];
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let s = String::from_utf16_lossy(&units);
        Ok(PropertyVariant::LpWStr(s))
    }
}

impl Default for OlePropertyReader {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Format a 16-byte FMTID as a GUID string `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
#[must_use]
pub fn format_fmtid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "00000000-0000-0000-0000-000000000000".to_owned();
    }
    // MS-OLEPS stores GUIDs in mixed-endian:
    // Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes BE)
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Well-known FMTIDs as string constants.
pub mod fmtid {
    /// `SummaryInformation`: `{F29F85E0-4FF9-1068-AB91-08002B27B3D9}`
    pub const SUMMARY_INFORMATION: &str =
        "F29F85E0-4FF9-1068-AB91-08002B27B3D9";
    /// `DocumentSummaryInformation`: `{D5CDD502-2E9C-101B-9397-08002B2CF9AE}`
    pub const DOCUMENT_SUMMARY_INFORMATION: &str =
        "D5CDD502-2E9C-101B-9397-08002B2CF9AE";
}

// ─── SummaryInformation ───────────────────────────────────────────────────────

/// High-level view over a parsed `SummaryInformation` property set.
#[derive(Debug, Clone, Default)]
pub struct SummaryInformation {
    /// The underlying property set.
    pub set: PropertySet,
}

impl SummaryInformation {
    /// Wrap a property set.
    #[must_use]
    pub const fn new(set: PropertySet) -> Self {
        Self { set }
    }

    /// Return the document title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.set.title()
    }

    /// Return the document subject.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.set
            .get_summary(SummaryPropertyId::Subject)
            .and_then(|v| v.as_str())
    }

    /// Return the document author.
    #[must_use]
    pub fn author(&self) -> Option<&str> {
        self.set.author()
    }

    /// Return the application name that created the document.
    #[must_use]
    pub fn app_name(&self) -> Option<&str> {
        self.set.app_name()
    }

    /// Return the page count.
    #[must_use]
    pub fn page_count(&self) -> Option<i32> {
        self.set
            .get_summary(SummaryPropertyId::PageCount)
            .and_then(PropertyVariant::as_i4)
    }

    /// Return the word count.
    #[must_use]
    pub fn word_count(&self) -> Option<i32> {
        self.set
            .get_summary(SummaryPropertyId::WordCount)
            .and_then(PropertyVariant::as_i4)
    }

    /// Return the security level (0 = unsecured).
    #[must_use]
    pub fn security(&self) -> Option<i32> {
        self.set
            .get_summary(SummaryPropertyId::Security)
            .and_then(PropertyVariant::as_i4)
    }

    /// Return the last-saved FILETIME, if present.
    #[must_use]
    pub fn last_saved(&self) -> Option<u64> {
        self.set
            .get_summary(SummaryPropertyId::LastSaved)
            .and_then(|v| {
                if let PropertyVariant::FileTime(ft) = v {
                    Some(*ft)
                } else {
                    None
                }
            })
    }
}

// ─── DocumentSummaryInformation ───────────────────────────────────────────────

/// High-level view over a parsed `DocumentSummaryInformation` property set.
#[derive(Debug, Clone, Default)]
pub struct DocumentSummaryInformation {
    /// The underlying property set.
    pub set: PropertySet,
}

impl DocumentSummaryInformation {
    /// Wrap a property set.
    #[must_use]
    pub const fn new(set: PropertySet) -> Self {
        Self { set }
    }

    /// Return the company name (PID 0x000F in `DocSummary`).
    #[must_use]
    pub fn company(&self) -> Option<&str> {
        self.set.get(0x000F).and_then(|v| v.as_str())
    }

    /// Return the manager name (PID 0x000E in `DocSummary`).
    #[must_use]
    pub fn manager(&self) -> Option<&str> {
        self.set.get(0x000E).and_then(|v| v.as_str())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lpstr_variant(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        // vt = VT_LPSTR (0x001E), padding 0x0000
        v.extend_from_slice(&0x001Eu16.to_le_bytes());
        v.extend_from_slice(&0x0000u16.to_le_bytes());
        let count = s.len() + 1; // include NUL
        v.extend_from_slice(&(count as u32).to_le_bytes());
        v.extend_from_slice(s.as_bytes());
        v.push(0); // NUL terminator
        // Pad to 4-byte boundary
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn build_minimal_property_stream(props: &[(u32, Vec<u8>)]) -> Vec<u8> {
        // Build a minimal one-set property stream header.
        // The stream header is 48 + 20 bytes (one property set descriptor).
        let set_offset: u32 = 68; // after the 48-byte header + 20-byte descriptor
        let prop_count = props.len() as u32;

        // Build the property set body.
        // Header: size (4) + count (4) + identifier_offset_pairs (count * 8)
        let id_table_size = prop_count as usize * 8;
        let id_table_start = 8usize;

        // Compute offsets for each property value (relative to set body start).
        let mut value_offsets: Vec<usize> = Vec::new();
        let mut current = id_table_start + id_table_size;
        for (_, data) in props {
            // align to 4 bytes
            while !current.is_multiple_of(4) {
                current += 1;
            }
            value_offsets.push(current);
            current += data.len();
        }
        let set_body_size = current;

        let mut set_body = vec![0u8; set_body_size];
        // size field
        set_body[0..4].copy_from_slice(&(set_body_size as u32).to_le_bytes());
        // count field
        set_body[4..8].copy_from_slice(&prop_count.to_le_bytes());

        for (i, ((id, data), &voff)) in props.iter().zip(value_offsets.iter()).enumerate() {
            let base = id_table_start + i * 8;
            set_body[base..base + 4].copy_from_slice(&id.to_le_bytes());
            set_body[base + 4..base + 8].copy_from_slice(&(voff as u32).to_le_bytes());
            set_body[voff..voff + data.len()].copy_from_slice(data);
        }

        // Build full stream
        let total = set_offset as usize + set_body_size;
        let mut stream = vec![0u8; total];

        // Header: BOM=0xFEFF at 0, version=0x0000 at 2, sysid at 4,
        // CLSID at 8 (16 bytes), reserved at 24 (4 bytes), count at 44
        stream[0..2].copy_from_slice(&0xFEFFu16.to_le_bytes());
        stream[44..48].copy_from_slice(&1u32.to_le_bytes()); // 1 property set
        // Descriptor: FMTID 16 bytes + offset 4 bytes (at offset 48)
        // FMTID = all zeroes (test fixture)
        stream[64..68].copy_from_slice(&set_offset.to_le_bytes());
        stream[set_offset as usize..].copy_from_slice(&set_body);

        stream
    }

    #[test]
    fn test_property_variant_type_names() {
        assert_eq!(PropertyVariant::Empty.type_name(), "VT_EMPTY");
        assert_eq!(PropertyVariant::I4(42).type_name(), "VT_I4");
        assert_eq!(PropertyVariant::LpStr("hi".into()).type_name(), "VT_LPSTR");
        assert_eq!(PropertyVariant::Bool(true).type_name(), "VT_BOOL");
        assert_eq!(PropertyVariant::FileTime(0).type_name(), "VT_FILETIME");
    }

    #[test]
    fn test_property_variant_as_str() {
        assert_eq!(
            PropertyVariant::LpStr("hello".into()).as_str(),
            Some("hello")
        );
        assert!(PropertyVariant::I4(1).as_str().is_none());
    }

    #[test]
    fn test_property_variant_as_bool() {
        assert_eq!(PropertyVariant::Bool(true).as_bool(), Some(true));
        assert!(PropertyVariant::Empty.as_bool().is_none());
    }

    #[test]
    fn test_property_variant_as_i4() {
        assert_eq!(PropertyVariant::I4(-7).as_i4(), Some(-7));
        assert!(PropertyVariant::Empty.as_i4().is_none());
    }

    #[test]
    fn test_property_variant_display_string() {
        let v = PropertyVariant::LpStr("test".into());
        assert_eq!(v.to_string(), "\"test\"");
    }

    #[test]
    fn test_property_variant_display_i4() {
        let v = PropertyVariant::I4(42);
        assert!(v.to_string().contains("42"));
    }

    #[test]
    fn test_property_variant_display_bool() {
        assert_eq!(PropertyVariant::Bool(true).to_string(), "true");
        assert_eq!(PropertyVariant::Bool(false).to_string(), "false");
    }

    #[test]
    fn test_property_variant_display_filetime() {
        let v = PropertyVariant::FileTime(0x1234_5678_9ABC_DEF0);
        let s = v.to_string();
        assert!(s.contains("FILETIME"));
    }

    #[test]
    fn test_summary_property_id_from_id() {
        assert_eq!(
            SummaryPropertyId::from_id(0x0002),
            Some(SummaryPropertyId::Title)
        );
        assert_eq!(
            SummaryPropertyId::from_id(0x0004),
            Some(SummaryPropertyId::Author)
        );
        assert!(SummaryPropertyId::from_id(0xFFFF).is_none());
    }

    #[test]
    fn test_summary_property_id_name() {
        assert_eq!(SummaryPropertyId::Title.name(), "Title");
        assert_eq!(SummaryPropertyId::AppName.name(), "AppName");
    }

    #[test]
    fn test_summary_property_id_display() {
        assert_eq!(SummaryPropertyId::Author.to_string(), "Author");
    }

    #[test]
    fn test_property_set_insert_get() {
        let mut set = PropertySet::new("test-fmtid");
        set.insert(0x0002, PropertyVariant::LpStr("My Document".into()));
        assert!(set.get(0x0002).is_some());
        assert!(set.get(0xFFFF).is_none());
    }

    #[test]
    fn test_property_set_title() {
        let mut set = PropertySet::new("fmtid");
        set.insert(0x0002, PropertyVariant::LpStr("Title Here".into()));
        assert_eq!(set.title(), Some("Title Here"));
    }

    #[test]
    fn test_property_set_author() {
        let mut set = PropertySet::new("fmtid");
        set.insert(0x0004, PropertyVariant::LpStr("Jane Doe".into()));
        assert_eq!(set.author(), Some("Jane Doe"));
    }

    #[test]
    fn test_property_set_len_and_empty() {
        let mut set = PropertySet::new("fmtid");
        assert!(set.is_empty());
        set.insert(1, PropertyVariant::I4(1));
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_property_set_sorted_entries() {
        let mut set = PropertySet::new("fmtid");
        set.insert(3, PropertyVariant::I4(3));
        set.insert(1, PropertyVariant::I4(1));
        set.insert(2, PropertyVariant::I4(2));
        let entries = set.sorted_entries();
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[1].id, 2);
        assert_eq!(entries[2].id, 3);
    }

    #[test]
    fn test_property_entry_display() {
        let e = PropertyEntry {
            id: 0x0002,
            value: PropertyVariant::LpStr("Foo".into()),
        };
        let s = e.to_string();
        assert!(s.contains("Title"));
        assert!(s.contains("Foo"));
    }

    #[test]
    fn test_property_entry_name_unknown() {
        let e = PropertyEntry {
            id: 0xDEAD,
            value: PropertyVariant::Empty,
        };
        assert!(e.name().starts_with("PID_"));
    }

    #[test]
    fn test_parse_stream_too_short() {
        let reader = OlePropertyReader::new();
        let err = reader.parse_stream(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, PropertyError::TruncatedStream));
    }

    #[test]
    fn test_parse_stream_zero_sets() {
        // Stream with 0 property sets — just the 48-byte header
        let reader = OlePropertyReader::new();
        let mut data = vec![0u8; 48];
        data[0..2].copy_from_slice(&0xFEFFu16.to_le_bytes());
        // count at 44 = 0
        let sets = reader.parse_stream(&data).unwrap();
        assert!(sets.is_empty());
    }

    #[test]
    fn test_parse_stream_with_i4_property() {
        // Build a stream with one property: PID 0x0003 = VT_I4(42)
        let mut value_bytes = vec![];
        value_bytes.extend_from_slice(&0x0003u16.to_le_bytes()); // VT_I4
        value_bytes.extend_from_slice(&0x0000u16.to_le_bytes()); // padding
        value_bytes.extend_from_slice(&42i32.to_le_bytes());

        let stream = build_minimal_property_stream(&[(0x0003, value_bytes)]);
        let reader = OlePropertyReader::new();
        let sets = reader.parse_stream(&stream).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].len(), 1);
        let val = sets[0].get(0x0003).unwrap();
        assert_eq!(*val, PropertyVariant::I4(42));
    }

    #[test]
    fn test_parse_stream_with_lpstr_property() {
        let value_bytes = make_lpstr_variant("Hello, OLE!");
        let stream = build_minimal_property_stream(&[(0x0002, value_bytes)]);
        let reader = OlePropertyReader::new();
        let sets = reader.parse_stream(&stream).unwrap();
        assert_eq!(sets.len(), 1);
        let val = sets[0].get(0x0002).unwrap();
        assert_eq!(val.as_str(), Some("Hello, OLE!"));
    }

    #[test]
    fn test_format_fmtid_summary_information() {
        // SummaryInformation FMTID bytes (mixed-endian)
        let bytes: [u8; 16] = [
            0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
            0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
        ];
        let s = format_fmtid(&bytes);
        // Data1 = 0xF29F85E0 (LE from [E0 85 9F F2])
        assert!(s.starts_with("F29F85E0"));
    }

    #[test]
    fn test_format_fmtid_too_short() {
        let s = format_fmtid(&[0u8; 4]);
        assert!(s.contains("00000000"));
    }

    #[test]
    fn test_summary_information_fields() {
        let mut set = PropertySet::new("fmtid");
        set.insert(0x0002, PropertyVariant::LpStr("Doc Title".into()));
        set.insert(0x0004, PropertyVariant::LpStr("John Doe".into()));
        set.insert(0x0012, PropertyVariant::LpStr("Microsoft Word".into()));
        set.insert(0x000E, PropertyVariant::I4(5));
        let si = SummaryInformation::new(set);
        assert_eq!(si.title(), Some("Doc Title"));
        assert_eq!(si.author(), Some("John Doe"));
        assert_eq!(si.app_name(), Some("Microsoft Word"));
        assert_eq!(si.page_count(), Some(5));
    }

    #[test]
    fn test_document_summary_information_company() {
        let mut set = PropertySet::new("fmtid");
        set.insert(0x000F, PropertyVariant::LpStr("Acme Corp".into()));
        let dsi = DocumentSummaryInformation::new(set);
        assert_eq!(dsi.company(), Some("Acme Corp"));
    }

    #[test]
    fn test_ole_property_reader_default() {
        let _reader = OlePropertyReader;
    }

    #[test]
    fn test_property_variant_blob_display() {
        let v = PropertyVariant::Blob(vec![1, 2, 3]);
        let s = v.to_string();
        assert!(s.contains("3 bytes"));
    }

    #[test]
    fn test_property_variant_unknown_display() {
        let v = PropertyVariant::Unknown {
            vt: 0xABCD,
            data: vec![],
        };
        let s = v.to_string();
        assert!(s.contains("Unknown"));
    }
}
