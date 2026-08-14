//! Android binary XML (AXML) resource decoder.
//!
//! Parses binary XML from APK `AndroidManifest.xml` and `res/` resources:
//! AXML header chunks, string pool chunk, resource map chunk, and XML
//! content (`start_element`, `end_element`, attribute values).  Decodes
//! attribute value types: `TYPE_STRING`, `TYPE_INT_DEC`, `TYPE_INT_HEX`,
//! `TYPE_BOOL`, `TYPE_ATTRIBUTE`, `TYPE_REFERENCE`.

use std::collections::HashMap;
use std::fmt;

// ── Chunk types ───────────────────────────────────────────────────────────────

const CHUNK_XML:         u16 = 0x0003;
const CHUNK_STRINGPOOL:  u16 = 0x0001;
const CHUNK_RESMAP:      u16 = 0x0180;
const CHUNK_XML_NS_START:u16 = 0x0100;
const CHUNK_XML_NS_END:  u16 = 0x0101;

/// Returns true if the chunk type carries no body we currently parse.
const fn is_noop_chunk(ty: u16) -> bool {
    matches!(ty, CHUNK_XML_NS_END | CHUNK_XML_CDATA)
}
const CHUNK_XML_ELEM_START: u16 = 0x0102;
const CHUNK_XML_ELEM_END:   u16 = 0x0103;
const CHUNK_XML_CDATA:   u16 = 0x0104;

// ── AttributeValue ────────────────────────────────────────────────────────────

/// Decoded attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    Null,
    /// `TYPE_STRING` (0x03)
    Str(String),
    /// `TYPE_INT_DEC` (0x10)
    IntDec(i32),
    /// `TYPE_INT_HEX` (0x11)
    IntHex(u32),
    /// `TYPE_BOOL` (0x12)
    Bool(bool),
    /// `TYPE_REFERENCE` (0x01)
    Reference(u32),
    /// `TYPE_ATTRIBUTE` (0x02)
    Attribute(u32),
    /// `TYPE_FLOAT` (0x04)
    Float(f32),
    /// Other raw type
    Raw { data_type: u8, data: u32 },
}

impl AttributeValue {
    /// Decode from the binary representation.
    /// `data_type` is the byte at offset 3 of the value block.
    #[must_use] 
    pub fn decode(data_type: u8, data: u32, strings: &StringPool) -> Self {
        match data_type {
            0x00 => Self::Null,
            0x01 => Self::Reference(data),
            0x02 => Self::Attribute(data),
            0x03 => {
                let s = strings.get(data as usize).unwrap_or_default();
                Self::Str(s)
            }
            0x04 => Self::Float(f32::from_bits(data)),
            0x10 => Self::IntDec(data.cast_signed()),
            0x11 => Self::IntHex(data),
            0x12 => Self::Bool(data != 0),
            _ => Self::Raw { data_type, data },
        }
    }
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "(null)"),
            Self::Str(s) => write!(f, "{s}"),
            Self::IntDec(i) => write!(f, "{i}"),
            Self::IntHex(h) => write!(f, "{h:#x}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Reference(r) => write!(f, "@{r:#010x}"),
            Self::Attribute(a) => write!(f, "?{a:#010x}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Raw { data_type, data } => write!(f, "raw(type={data_type:#x},data={data:#x})"),
        }
    }
}

// ── StringPool ────────────────────────────────────────────────────────────────

/// Parsed AXML string pool.
#[derive(Debug, Clone, Default)]
pub struct StringPool {
    pub strings: Vec<String>,
    pub is_utf8: bool,
}

impl StringPool {
    /// Get a string by index.
    #[must_use] 
    pub fn get(&self, idx: usize) -> Option<String> {
        self.strings.get(idx).cloned()
    }

    /// Parse from raw bytes starting at `offset` (chunk header already read).
    fn parse(data: &[u8], offset: usize, chunk_size: u32) -> Result<Self, AxmlError> {
        if offset + 28 > data.len() || (chunk_size as usize) < 28 {
            return Err(AxmlError::TooShort);
        }
        let string_count = read_u32(data, offset + 8)?;
        let style_count  = read_u32(data, offset + 12)?;
        let flags        = read_u32(data, offset + 16)?;
        let string_start = read_u32(data, offset + 20)?;
        let _style_start = read_u32(data, offset + 24)?;
        let is_utf8 = (flags & (1 << 8)) != 0;

        // String offsets start at offset + 28
        let off_base = offset + 28;
        let string_data_start = offset + string_start as usize;

        // Cap the attacker-controlled count against what the offset table can
        // actually hold, so a tiny file cannot make us reserve gigabytes.
        let string_count = (string_count as usize).min(data.len().saturating_sub(off_base) / 4);
        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let str_off_pos = off_base + i * 4;
            if str_off_pos + 4 > data.len() { break; }
            let str_off = read_u32(data, str_off_pos)? as usize;
            let abs = string_data_start + str_off;
            let s = if is_utf8 {
                parse_utf8_string(data, abs)
            } else {
                parse_utf16_string(data, abs)
            };
            strings.push(s);
        }
        // skip style offsets (string_count..string_count+style_count)
        let _ = style_count;
        Ok(Self { strings, is_utf8 })
    }
}

fn parse_utf8_string(data: &[u8], pos: usize) -> String {
    if pos >= data.len() { return String::new(); }
    // First byte is UTF-16 char count (skip), second is UTF-8 byte count
    let char_len_pos = pos;
    let byte_len_pos = if data[char_len_pos] & 0x80 != 0 { pos + 2 } else { pos + 1 };
    let byte_len = if byte_len_pos < data.len() {
        if data[byte_len_pos] & 0x80 != 0 && byte_len_pos + 1 < data.len() {
            (((data[byte_len_pos] & 0x7F) as usize) << 8) | data[byte_len_pos + 1] as usize
        } else {
            data[byte_len_pos] as usize
        }
    } else { 0 };
    let str_start = byte_len_pos + 1 + usize::from(data.get(byte_len_pos).copied().unwrap_or(0) & 0x80 != 0);
    if str_start + byte_len > data.len() { return String::new(); }
    String::from_utf8_lossy(&data[str_start..str_start + byte_len]).into_owned()
}

fn parse_utf16_string(data: &[u8], pos: usize) -> String {
    if pos + 2 > data.len() { return String::new(); }
    let len = if data[pos + 1] & 0x80 != 0 && pos + 4 <= data.len() {
        (((data[pos + 1] & 0x7F) as usize) << 8) | data[pos] as usize
    } else {
        u16::from_le_bytes([data[pos], data[pos + 1]]) as usize
    };
    let str_start = pos + 2 + if data.get(pos + 1).copied().unwrap_or(0) & 0x80 != 0 { 2 } else { 0 };
    let byte_len = len * 2;
    if str_start + byte_len > data.len() { return String::new(); }
    let utf16: Vec<u16> = data[str_start..str_start + byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&utf16)
}

// ── XmlChunk ──────────────────────────────────────────────────────────────────

/// A chunk header from the binary XML stream.
#[derive(Debug, Clone)]
pub struct XmlChunk {
    pub chunk_type: u16,
    pub header_size: u16,
    pub chunk_size: u32,
    pub line_number: u32,
}

// ── XmlAttribute ─────────────────────────────────────────────────────────────

/// A single attribute of an XML element.
#[derive(Debug, Clone)]
pub struct XmlAttribute {
    pub namespace: Option<String>,
    pub name: String,
    pub value: AttributeValue,
    pub raw_string_idx: Option<u32>,
}

impl fmt::Display for XmlAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ns) = &self.namespace {
            write!(f, "{ns}:{}", self.name)?;
        } else {
            write!(f, "{}", self.name)?;
        }
        write!(f, "=\"{}\"", self.value)
    }
}

// ── XmlElement ────────────────────────────────────────────────────────────────

/// A parsed XML element (start tag with attributes, or end tag).
#[derive(Debug, Clone)]
pub struct XmlElement {
    pub line: u32,
    pub namespace: Option<String>,
    pub name: String,
    pub attributes: Vec<XmlAttribute>,
    pub children: Vec<Self>,
    pub is_end: bool,
}

impl XmlElement {
    /// Find an attribute by local name.
    #[must_use] 
    pub fn attr(&self, name: &str) -> Option<&XmlAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Find all attributes by local name.
    #[must_use] 
    pub fn attrs(&self, name: &str) -> Vec<&XmlAttribute> {
        self.attributes.iter().filter(|a| a.name == name).collect()
    }
}

impl fmt::Display for XmlElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_end {
            return write!(f, "</{}>", self.name);
        }
        write!(f, "<{}", self.name)?;
        for a in &self.attributes {
            write!(f, " {a}")?;
        }
        write!(f, ">")
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AxmlError {
    TooShort,
    BadMagic,
    UnsupportedVersion,
    InvalidChunk(u16),
    ParseError(String),
}

impl fmt::Display for AxmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::BadMagic => write!(f, "bad AXML magic"),
            Self::UnsupportedVersion => write!(f, "unsupported AXML version"),
            Self::InvalidChunk(t) => write!(f, "invalid chunk type {t:#x}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

// ── AxmlParser ────────────────────────────────────────────────────────────────

/// Parses binary Android XML (AXML) documents.
#[derive(Debug)]
pub struct AxmlParser {
    pub string_pool: StringPool,
    pub resource_map: Vec<u32>,
    pub elements: Vec<XmlElement>,
    /// Namespace URI → prefix map
    pub namespaces: HashMap<String, String>,
}

impl AxmlParser {
    /// Parse binary AXML from `data`.
    ///
    /// # Errors
    /// Returns an [`AxmlError`] when the magic is wrong, the buffer is truncated, or any chunk is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, AxmlError> {
        if data.len() < 8 {
            return Err(AxmlError::TooShort);
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != CHUNK_XML {
            return Err(AxmlError::BadMagic);
        }
        // header_size at [2..4], chunk_size at [4..8]
        let _file_size = read_u32(data, 4)?;

        let mut pos = 8usize;
        let mut string_pool = StringPool::default();
        let mut resource_map: Vec<u32> = Vec::new();
        let mut elements: Vec<XmlElement> = Vec::new();
        let mut namespaces: HashMap<String, String> = HashMap::new();
        // Stack of open elements
        let mut stack: Vec<XmlElement> = Vec::new();

        while pos + 8 <= data.len() {
            let chunk_type  = u16::from_le_bytes([data[pos], data[pos + 1]]);
            let header_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
            let chunk_size  = read_u32(data, pos + 4)?;

            if chunk_size == 0 || pos + chunk_size as usize > data.len() {
                break;
            }

            match chunk_type {
                CHUNK_STRINGPOOL => {
                    string_pool = StringPool::parse(data, pos, chunk_size)?;
                }
                CHUNK_RESMAP => {
                    // resource IDs follow the 8-byte chunk header
                    let count = (chunk_size as usize - header_size as usize) / 4;
                    for i in 0..count {
                        let off = pos + header_size as usize + i * 4;
                        if off + 4 <= data.len() {
                            resource_map.push(read_u32(data, off)?);
                        }
                    }
                }
                CHUNK_XML_NS_START => {
                    // line(4) comment(4) prefix_idx(4) uri_idx(4)
                    if pos + 24 <= data.len() {
                        let prefix_idx = read_u32(data, pos + 16)? as usize;
                        let uri_idx    = read_u32(data, pos + 20)? as usize;
                        let prefix = string_pool.get(prefix_idx).unwrap_or_default();
                        let uri    = string_pool.get(uri_idx).unwrap_or_default();
                        namespaces.insert(uri, prefix);
                    }
                }
                CHUNK_XML_ELEM_START => {
                    if pos + 28 > data.len() { break; }
                    let line       = read_u32(data, pos + 8)?;
                    let ns_idx     = read_u32(data, pos + 16)?;
                    let name_idx   = read_u32(data, pos + 20)?;
                    let attr_count = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;

                    let ns   = if ns_idx == 0xFFFF_FFFF { None } else { string_pool.get(ns_idx as usize) };
                    let name = string_pool.get(name_idx as usize).unwrap_or_default();

                    let mut attrs = Vec::with_capacity(attr_count);
                    let attr_base = pos + 28 + 4; // skip attribute_start(2)+attribute_size(2)+id/class/style(6)
                    // Actually: attr_start at [28..30], attr_size at [30..32], id_attr at [32..34], class_attr at [34..36], style_attr at [36..38]
                    // Attributes start at pos+header_size
                    let attr_start_off = pos + header_size as usize;
                    for ai in 0..attr_count {
                        let aoff = attr_start_off + ai * 20;
                        if aoff + 20 > data.len() { break; }
                        let ans_idx   = read_u32(data, aoff)?;
                        let aname_idx = read_u32(data, aoff + 4)?;
                        let astr_idx  = read_u32(data, aoff + 8)?;
                        let atype_raw = read_u32(data, aoff + 12)?;
                        let adata     = read_u32(data, aoff + 16)?;

                        let data_type = ((atype_raw >> 24) & 0xFF) as u8;
                        let ans = if ans_idx == 0xFFFF_FFFF { None } else { string_pool.get(ans_idx as usize) };
                        let aname = string_pool.get(aname_idx as usize).unwrap_or_default();
                        let value = AttributeValue::decode(data_type, adata, &string_pool);
                        let raw_string_idx = if astr_idx == 0xFFFF_FFFF { None } else { Some(astr_idx) };

                        attrs.push(XmlAttribute {
                            namespace: ans,
                            name: aname,
                            value,
                            raw_string_idx,
                        });
                    }
                    let _ = attr_base; // suppress warning

                    let elem = XmlElement {
                        line,
                        namespace: ns,
                        name,
                        attributes: attrs,
                        children: Vec::new(),
                        is_end: false,
                    };
                    stack.push(elem);
                }
                CHUNK_XML_ELEM_END => {
                    if let Some(elem) = stack.pop() {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(elem);
                        } else {
                            elements.push(elem);
                        }
                    }
                }
                other => {
                    let _ = is_noop_chunk(other); // wire NS_END/CDATA recognition
                    // Skip unknown / no-op chunks
                }
            }

            pos += chunk_size as usize;
        }

        // Drain remaining stack (malformed AXML)
        while let Some(elem) = stack.pop() {
            if let Some(parent) = stack.last_mut() {
                parent.children.push(elem);
            } else {
                elements.push(elem);
            }
        }

        Ok(Self { string_pool, resource_map, elements, namespaces })
    }

    /// Return the root element if any.
    #[must_use] 
    pub fn root(&self) -> Option<&XmlElement> {
        self.elements.first()
    }

    /// Collect all element names (DFS).
    #[must_use] 
    pub fn all_element_names(&self) -> Vec<String> {
        fn walk(elem: &XmlElement, out: &mut Vec<String>) {
            out.push(elem.name.clone());
            for c in &elem.children { walk(c, out); }
        }
        let mut out = Vec::new();
        for e in &self.elements { walk(e, &mut out); }
        out
    }
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32, AxmlError> {
    if pos + 4 > data.len() { return Err(AxmlError::TooShort); }
    Ok(u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_value_decode_null() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x00, 0, &sp);
        assert_eq!(v, AttributeValue::Null);
    }

    #[test]
    fn test_attribute_value_decode_int_dec() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x10, 42, &sp);
        assert_eq!(v, AttributeValue::IntDec(42));
    }

    #[test]
    fn test_attribute_value_decode_int_hex() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x11, 0xDEAD, &sp);
        assert_eq!(v, AttributeValue::IntHex(0xDEAD));
    }

    #[test]
    fn test_attribute_value_decode_bool_true() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x12, 1, &sp);
        assert_eq!(v, AttributeValue::Bool(true));
    }

    #[test]
    fn test_attribute_value_decode_bool_false() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x12, 0, &sp);
        assert_eq!(v, AttributeValue::Bool(false));
    }

    #[test]
    fn test_attribute_value_decode_reference() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x01, 0x7F01_0001, &sp);
        assert_eq!(v, AttributeValue::Reference(0x7F01_0001));
    }

    #[test]
    fn test_attribute_value_decode_attribute() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x02, 0x0101_0003, &sp);
        assert_eq!(v, AttributeValue::Attribute(0x0101_0003));
    }

    #[test]
    fn test_attribute_value_decode_string() {
        let sp = StringPool {
            strings: vec!["android".to_string()],
            is_utf8: true,
        };
        let v = AttributeValue::decode(0x03, 0, &sp);
        assert_eq!(v, AttributeValue::Str("android".to_string()));
    }

    #[test]
    fn test_attribute_value_display_int_hex() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x11, 0xFF, &sp);
        assert!(v.to_string().contains("0xff"));
    }

    #[test]
    fn test_attribute_value_display_bool() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0x12, 1, &sp);
        assert_eq!(v.to_string(), "true");
    }

    #[test]
    fn test_string_pool_get_none() {
        let sp = StringPool::default();
        assert!(sp.get(0).is_none());
    }

    #[test]
    fn test_string_pool_get_some() {
        let sp = StringPool {
            strings: vec!["foo".to_string(), "bar".to_string()],
            is_utf8: false,
        };
        assert_eq!(sp.get(1), Some("bar".to_string()));
    }

    #[test]
    fn test_axml_bad_magic() {
        let data = [0xFFu8, 0xFF, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00];
        let err = AxmlParser::parse(&data).unwrap_err();
        assert!(matches!(err, AxmlError::BadMagic));
    }

    #[test]
    fn test_axml_too_short() {
        let err = AxmlParser::parse(&[0x00, 0x00]).unwrap_err();
        assert!(matches!(err, AxmlError::TooShort));
    }

    #[test]
    fn test_xml_attribute_display_no_ns() {
        let _sp = StringPool::default();
        let attr = XmlAttribute {
            namespace: None,
            name: "package".to_string(),
            value: AttributeValue::Str("com.example".to_string()),
            raw_string_idx: None,
        };
        let s = format!("{attr}");
        assert!(s.contains("package"));
        assert!(s.contains("com.example"));
    }

    #[test]
    fn test_xml_element_display_end() {
        let elem = XmlElement {
            line: 1,
            namespace: None,
            name: "application".to_string(),
            attributes: vec![],
            children: vec![],
            is_end: true,
        };
        assert_eq!(format!("{elem}"), "</application>");
    }

    #[test]
    fn test_xml_element_attr_lookup() {
        let sp = StringPool::default();
        let elem = XmlElement {
            line: 1,
            namespace: None,
            name: "manifest".to_string(),
            attributes: vec![
                XmlAttribute {
                    namespace: None,
                    name: "package".to_string(),
                    value: AttributeValue::Str("com.foo".to_string()),
                    raw_string_idx: None,
                }
            ],
            children: vec![],
            is_end: false,
        };
        let _ = sp;
        let found = elem.attr("package");
        assert!(found.is_some());
        assert!(elem.attr("missing").is_none());
    }

    #[test]
    fn test_read_u32_too_short() {
        let data = [0x01u8, 0x02];
        assert!(read_u32(&data, 0).is_err());
    }

    #[test]
    fn test_read_u32_ok() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        assert_eq!(read_u32(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_axml_empty_file_bad_magic() {
        let data = vec![0u8; 32];
        // zero magic → error
        let err = AxmlParser::parse(&data).unwrap_err();
        assert!(matches!(err, AxmlError::BadMagic));
    }

    #[test]
    fn test_attribute_raw_variant() {
        let sp = StringPool::default();
        let v = AttributeValue::decode(0xAA, 0x1234, &sp);
        assert!(matches!(v, AttributeValue::Raw { .. }));
    }
}
