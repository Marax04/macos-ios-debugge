//! `rustre-loader-android::axml_full`
//!
//! Complete Android binary XML (AXML) parser.
//!
//! Android binary XML is the compact wire format used by `aapt` for
//! `AndroidManifest.xml` and resource files inside APKs.  Every XML document
//! is stored as a sequence of typed *chunks*, each starting with a 8-byte
//! chunk header (`type:u16`, `header_size:u16`, `chunk_size:u32`).
//!
//! This module implements a full chunk-type table, a string pool decoder,
//! namespace stack tracking, start/end element decoding with attribute
//! resolution, and builds an [`AXMLDocument`] object.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Chunk type constants
// ─────────────────────────────────────────────────────────────────────────────

/// All defined AXML chunk type values (from `android/frameworks/base/include/androidfw/ResourceTypes.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ChunkType {
    /// Null / padding chunk.
    Null = 0x0000,
    /// String pool chunk.
    StringPool = 0x0001,
    /// Table (resource) chunk.
    Table = 0x0002,
    /// XML document root chunk.
    Xml = 0x0003,
    // ── XML node sub-types ──────────────────────────────────────────────────
    /// XML `StartNamespace` node.
    XmlStartNamespace = 0x0100,
    /// XML `EndNamespace` node.
    XmlEndNamespace = 0x0101,
    /// XML `StartElement` node.
    XmlStartElement = 0x0102,
    /// XML `EndElement` node.
    XmlEndElement = 0x0103,
    /// XML `CData` node.
    XmlCdata = 0x0104,
    /// XML resource map (array of resource IDs for attribute names).
    XmlResourceMap = 0x0180,
    // ── Table section types ────────────────────────────────────────────────
    TablePackage = 0x0200,
    TableType = 0x0201,
    TableTypeSpec = 0x0202,
    TableLibrary = 0x0203,
    /// Unknown/unsupported chunk type.
    Unknown = 0xFFFF,
}

impl ChunkType {
    /// Decode a raw u16 into a `ChunkType`.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0000 => Self::Null,
            0x0001 => Self::StringPool,
            0x0002 => Self::Table,
            0x0003 => Self::Xml,
            0x0100 => Self::XmlStartNamespace,
            0x0101 => Self::XmlEndNamespace,
            0x0102 => Self::XmlStartElement,
            0x0103 => Self::XmlEndElement,
            0x0104 => Self::XmlCdata,
            0x0180 => Self::XmlResourceMap,
            0x0200 => Self::TablePackage,
            0x0201 => Self::TableType,
            0x0202 => Self::TableTypeSpec,
            0x0203 => Self::TableLibrary,
            _ => Self::Unknown,
        }
    }

    /// Human-readable name for this chunk type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "Null",
            Self::StringPool => "StringPool",
            Self::Table => "Table",
            Self::Xml => "Xml",
            Self::XmlStartNamespace => "XmlStartNamespace",
            Self::XmlEndNamespace => "XmlEndNamespace",
            Self::XmlStartElement => "XmlStartElement",
            Self::XmlEndElement => "XmlEndElement",
            Self::XmlCdata => "XmlCdata",
            Self::XmlResourceMap => "XmlResourceMap",
            Self::TablePackage => "TablePackage",
            Self::TableType => "TableType",
            Self::TableTypeSpec => "TableTypeSpec",
            Self::TableLibrary => "TableLibrary",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns `true` when this is an XML node type.
    #[must_use]
    pub const fn is_xml_node(self) -> bool {
        matches!(
            self,
            Self::XmlStartNamespace
                | Self::XmlEndNamespace
                | Self::XmlStartElement
                | Self::XmlEndElement
                | Self::XmlCdata
        )
    }
}

impl fmt::Display for ChunkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chunk header
// ─────────────────────────────────────────────────────────────────────────────

/// The 8-byte header common to every AXML chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Chunk type code.
    pub chunk_type: ChunkType,
    /// Size of this specific header in bytes (usually 8).
    pub header_size: u16,
    /// Total byte size of this chunk (including header).
    pub chunk_size: u32,
}

impl ChunkHeader {
    /// Parse a chunk header from 8 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let type_raw = u16::from_le_bytes([data[0], data[1]]);
        let header_size = u16::from_le_bytes([data[2], data[3]]);
        let chunk_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Some(Self {
            chunk_type: ChunkType::from_u16(type_raw),
            header_size,
            chunk_size,
        })
    }

    /// Data size (`chunk_size` minus `header_size`).
    #[must_use]
    pub fn data_size(&self) -> usize {
        self.chunk_size.saturating_sub(u32::from(self.header_size)) as usize
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResStringPool
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `ResStringPool` (AXML string pool chunk).
///
/// Stores all string literals referenced by indices throughout the AXML file.
#[derive(Debug, Clone, Default)]
pub struct ResStringPool {
    /// String entries in declaration order.
    pub strings: Vec<String>,
    /// Style entries (parallel to `strings`; empty if no styles).
    pub styles: Vec<String>,
    /// Whether the strings are encoded as UTF-8 (flag 0x100) or UTF-16LE.
    pub is_utf8: bool,
}

impl ResStringPool {
    /// Parse a string pool from the full `StringPool` chunk bytes (including
    /// the 8-byte chunk header).
    #[must_use]
    pub fn parse(chunk: &[u8]) -> Self {
        if chunk.len() < 28 {
            return Self::default();
        }
        let string_count = u32::from_le_bytes(chunk[8..12].try_into().unwrap_or([0; 4])) as usize;
        let _style_count = u32::from_le_bytes(chunk[12..16].try_into().unwrap_or([0; 4])) as usize;
        let flags = u32::from_le_bytes(chunk[16..20].try_into().unwrap_or([0; 4]));
        let strings_start = u32::from_le_bytes(chunk[20..24].try_into().unwrap_or([0; 4])) as usize;
        let _styles_start = u32::from_le_bytes(chunk[24..28].try_into().unwrap_or([0; 4]));
        let is_utf8 = (flags & 0x100) != 0;

        let offsets_base = 28usize;
        // Cap pre-allocation: each string offset is 4 bytes, bounding the real
        // count by chunk.len() / 4. Prevents OOM from a crafted string_count.
        let mut strings = Vec::with_capacity(string_count.min(chunk.len() / 4 + 1));

        for i in 0..string_count {
            let Some(off_off) = offsets_base.checked_add(i.saturating_mul(4)) else {
                break;
            };
            if off_off + 4 > chunk.len() {
                break;
            }
            let raw_off = u32::from_le_bytes(chunk[off_off..off_off + 4].try_into().unwrap_or([0; 4])) as usize;
            let Some(str_off) = raw_off.checked_add(strings_start) else {
                break;
            };
            let s = if is_utf8 {
                decode_utf8_pool_string(chunk, str_off)
            } else {
                decode_utf16_pool_string(chunk, str_off)
            };
            strings.push(s);
        }

        Self {
            strings,
            styles: Vec::new(),
            is_utf8,
        }
    }

    /// Look up a string by pool index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&str> {
        self.strings.get(idx).map(String::as_str)
    }

    /// Number of strings in the pool.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// Returns `true` when the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

/// Decode a UTF-8 pool string from `data` at `offset`.
fn decode_utf8_pool_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let mut off = offset;
    // Skip character count (1 or 2 bytes ULEB128)
    if off < data.len() && data[off] & 0x80 != 0 {
        off += 1;
    }
    off += 1;
    if off >= data.len() {
        return String::new();
    }
    // Byte length (1 or 2 bytes ULEB128)
    let byte_len = if data[off] & 0x80 != 0 {
        let hi = (data[off] as usize & 0x7F) << 8;
        off += 1;
        if off >= data.len() {
            return String::new();
        }
        hi | data[off] as usize
    } else {
        data[off] as usize
    };
    off += 1;
    let end = (off + byte_len).min(data.len());
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

/// Decode a UTF-16LE pool string from `data` at `offset`.
fn decode_utf16_pool_string(data: &[u8], offset: usize) -> String {
    if offset + 2 > data.len() {
        return String::new();
    }
    let char_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let byte_len = char_len * 2;
    let start = offset + 2;
    let end = (start + byte_len).min(data.len());
    if end <= start {
        return String::new();
    }
    let u16s: Vec<u16> = data[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

// ─────────────────────────────────────────────────────────────────────────────
// Namespace mapping
// ─────────────────────────────────────────────────────────────────────────────

/// A namespace declaration encountered in the XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDecl {
    /// Namespace prefix (e.g. `"android"`).
    pub prefix: String,
    /// Namespace URI (e.g. `"http://schemas.android.com/apk/res/android"`).
    pub uri: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribute
// ─────────────────────────────────────────────────────────────────────────────

/// A single XML attribute decoded from a `StartElement` chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AXMLAttribute {
    /// Namespace URI, if present.
    pub namespace_uri: Option<String>,
    /// Attribute name (resolved from string pool).
    pub name: String,
    /// Raw string value, if available.
    pub raw_value: Option<String>,
    /// Android resource ID for this attribute, if available.
    pub resource_id: Option<u32>,
    /// Typed data value.
    pub data_value: u32,
    /// Data type (0x10 = int, 0x03 = string, etc.)
    pub data_type: u8,
}

impl AXMLAttribute {
    /// Return the value as a human-readable string.
    #[must_use]
    pub fn value_str(&self) -> String {
        if let Some(ref s) = self.raw_value
            && !s.is_empty() {
                return s.clone();
            }
        match self.data_type {
            0x10 => format!("{}", self.data_value as i32), // TYPE_INT_DEC
            0x11 => format!("{:#010x}", self.data_value),  // TYPE_INT_HEX
            0x12 => {
                if self.data_value != 0 {
                    "true".into()
                } else {
                    "false".into()
                }
            } // TYPE_BOOLEAN
            0x03 => format!("@str:{}", self.data_value),
            _ => format!("{:#010x}", self.data_value),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XML node types
// ─────────────────────────────────────────────────────────────────────────────

/// An individual XML node in the decoded document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AXMLNode {
    StartNamespace(NamespaceDecl),
    EndNamespace(String),
    StartElement {
        namespace_uri: Option<String>,
        name: String,
        attributes: Vec<AXMLAttribute>,
        line_number: u32,
    },
    EndElement {
        namespace_uri: Option<String>,
        name: String,
    },
    CData(String),
}

impl fmt::Display for AXMLNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartNamespace(ns) => write!(f, "xmlns:{}={}", ns.prefix, ns.uri),
            Self::EndNamespace(uri) => write!(f, "/xmlns:{uri}"),
            Self::StartElement {
                name, attributes, ..
            } => {
                let attrs: Vec<_> = attributes
                    .iter()
                    .map(|a| format!("{}={}", a.name, a.value_str()))
                    .collect();
                write!(f, "<{} {}>", name, attrs.join(" "))
            }
            Self::EndElement { name, .. } => write!(f, "</{name}>"),
            Self::CData(s) => write!(f, "CDATA[{s}]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResXMLTree_attrExt
// ─────────────────────────────────────────────────────────────────────────────

/// The `ResXMLTree_attrExt` portion of a `StartElement` chunk (16-byte block after
/// the common node header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResXMLTreeAttrExt {
    /// String pool index for the element namespace URI.
    pub ns_idx: u32,
    /// String pool index for the element name.
    pub name_idx: u32,
    /// Offset of attribute data from the start of this block.
    pub attribute_start: u16,
    /// Size of one attribute entry in bytes.
    pub attribute_size: u16,
    /// Number of attributes.
    pub attribute_count: u16,
    /// Index of `id` attribute, or 0xFFFF.
    pub id_index: u16,
    /// Index of `class` attribute, or 0xFFFF.
    pub class_index: u16,
    /// Index of `style` attribute, or 0xFFFF.
    pub style_index: u16,
}

impl ResXMLTreeAttrExt {
    /// Parse from 16 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let rd16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
        let rd32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        Some(Self {
            ns_idx: rd32(0),
            name_idx: rd32(4),
            attribute_start: rd16(8),
            attribute_size: rd16(10),
            attribute_count: rd16(12),
            id_index: rd16(14),
            class_index: if data.len() >= 18 { rd16(16) } else { 0xFFFF },
            style_index: if data.len() >= 20 { rd16(18) } else { 0xFFFF },
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AXMLDocument
// ─────────────────────────────────────────────────────────────────────────────

/// A fully decoded Android Binary XML document.
#[derive(Debug, Clone)]
pub struct AXMLDocument {
    /// The string pool.
    pub string_pool: ResStringPool,
    /// Resource ID map (optional; maps attribute pool indices to resource IDs).
    pub resource_map: Vec<u32>,
    /// Decoded XML nodes in document order.
    pub nodes: Vec<AXMLNode>,
}

impl AXMLDocument {
    /// Parse an Android Binary XML document from `data`.
    ///
    /// # Errors
    ///
    /// Returns a `String` description on parse failure.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("data too short for AXML header".into());
        }
        let file_type = u16::from_le_bytes([data[0], data[1]]);
        if file_type != 0x0003 {
            return Err(format!(
                "expected XML file type 0x0003, got {file_type:#06x}"
            ));
        }
        let total_size = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])) as usize;
        let data = &data[..total_size.min(data.len())];

        let mut string_pool = ResStringPool::default();
        let mut resource_map: Vec<u32> = Vec::new();
        let mut nodes: Vec<AXMLNode> = Vec::new();
        // Namespace stack: URI → prefix
        let mut ns_stack: Vec<NamespaceDecl> = Vec::new();
        // Current namespace map: URI → prefix
        let mut ns_map: HashMap<String, String> = HashMap::new();

        let mut pos = 8usize;
        while pos + 8 <= data.len() {
            let Some(hdr) = ChunkHeader::parse(&data[pos..]) else {
                break;
            };
            let chunk_size = hdr.chunk_size as usize;
            if chunk_size == 0 || pos + chunk_size > data.len() {
                break;
            }
            let chunk = &data[pos..pos + chunk_size];

            match hdr.chunk_type {
                ChunkType::StringPool => {
                    string_pool = ResStringPool::parse(chunk);
                }
                ChunkType::XmlResourceMap => {
                    let n = (chunk_size - 8) / 4;
                    for i in 0..n {
                        let off = 8 + i * 4;
                        if off + 4 > chunk.len() {
                            break;
                        }
                        resource_map
                            .push(u32::from_le_bytes(chunk[off..off + 4].try_into().unwrap()));
                    }
                }
                ChunkType::XmlStartNamespace => {
                    if chunk.len() >= 16 {
                        let prefix_idx =
                            u32::from_le_bytes(chunk[8..12].try_into().unwrap()) as usize;
                        let uri_idx =
                            u32::from_le_bytes(chunk[12..16].try_into().unwrap()) as usize;
                        let prefix = string_pool.get(prefix_idx).unwrap_or("").to_string();
                        let uri = string_pool.get(uri_idx).unwrap_or("").to_string();
                        ns_map.insert(uri.clone(), prefix.clone());
                        let ns = NamespaceDecl { prefix, uri };
                        ns_stack.push(ns.clone());
                        nodes.push(AXMLNode::StartNamespace(ns));
                    }
                }
                ChunkType::XmlEndNamespace => {
                    if chunk.len() >= 16 {
                        let uri_idx =
                            u32::from_le_bytes(chunk[12..16].try_into().unwrap()) as usize;
                        let uri = string_pool.get(uri_idx).unwrap_or("").to_string();
                        ns_stack.retain(|n| n.uri != uri);
                        nodes.push(AXMLNode::EndNamespace(uri));
                    }
                }
                ChunkType::XmlStartElement => {
                    if chunk.len() < 16 {
                        pos += chunk_size;
                        continue;
                    }
                    let line_number = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                    let ext_off = hdr.header_size as usize;
                    let Some(ext) = ResXMLTreeAttrExt::parse(&chunk[ext_off..]) else {
                        pos += chunk_size;
                        continue;
                    };
                    let ns_uri = resolve_ns_idx(&string_pool, ext.ns_idx, 0xFFFF_FFFF);
                    let name = string_pool
                        .get(ext.name_idx as usize)
                        .unwrap_or("?")
                        .to_string();

                    // Parse attributes
                    let attr_base = ext_off + ext.attribute_start as usize;
                    let attr_size = if ext.attribute_size > 0 {
                        ext.attribute_size as usize
                    } else {
                        20
                    };
                    // Cap pre-allocation: each attribute is at least 20 bytes,
                    // bounding the real count by the remaining chunk length.
                    let mut attributes = Vec::with_capacity(
                        (ext.attribute_count as usize).min(chunk.len() / 20 + 1),
                    );
                    for i in 0..ext.attribute_count as usize {
                        let aoff = attr_base + i * attr_size;
                        if aoff + 20 > chunk.len() {
                            break;
                        }
                        let attr = parse_attribute(
                            &chunk[aoff..aoff + 20],
                            &string_pool,
                            &resource_map,
                            i,
                        );
                        attributes.push(attr);
                    }

                    nodes.push(AXMLNode::StartElement {
                        namespace_uri: ns_uri,
                        name,
                        attributes,
                        line_number,
                    });
                }
                ChunkType::XmlEndElement => {
                    if chunk.len() < 16 {
                        pos += chunk_size;
                        continue;
                    }
                    let ns_idx = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                    let name_idx = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
                    let ns_uri = resolve_ns_idx(&string_pool, ns_idx, 0xFFFF_FFFF);
                    let name = string_pool
                        .get(name_idx as usize)
                        .unwrap_or("?")
                        .to_string();
                    nodes.push(AXMLNode::EndElement {
                        namespace_uri: ns_uri,
                        name,
                    });
                }
                ChunkType::XmlCdata
                    if chunk.len() >= 12 => {
                        let cdata_idx =
                            u32::from_le_bytes(chunk[8..12].try_into().unwrap()) as usize;
                        let cdata = string_pool.get(cdata_idx).unwrap_or("").to_string();
                        nodes.push(AXMLNode::CData(cdata));
                    }
                _ => {} // Skip unknown chunks
            }

            pos += chunk_size;
        }

        let _ = ns_map; // used during parse
        Ok(Self {
            string_pool,
            resource_map,
            nodes,
        })
    }

    /// Find all `StartElement` nodes with the given element name.
    #[must_use]
    pub fn find_elements<'a>(&'a self, name: &str) -> Vec<&'a AXMLNode> {
        self.nodes
            .iter()
            .filter(|n| {
                if let AXMLNode::StartElement { name: n, .. } = n {
                    n == name
                } else {
                    false
                }
            })
            .collect()
    }

    /// Find the first attribute value for `attr_name` in element `elem_name`.
    #[must_use]
    pub fn find_attribute_value(&self, elem_name: &str, attr_name: &str) -> Option<String> {
        for node in &self.nodes {
            if let AXMLNode::StartElement {
                name, attributes, ..
            } = node
                && name == elem_name {
                    for attr in attributes {
                        if attr.name == attr_name {
                            return Some(attr.value_str());
                        }
                    }
                }
        }
        None
    }

    /// Number of decoded nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Collect all declared namespaces.
    #[must_use]
    pub fn namespaces(&self) -> Vec<&NamespaceDecl> {
        self.nodes
            .iter()
            .filter_map(|n| {
                if let AXMLNode::StartNamespace(ns) = n {
                    Some(ns)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect all element names encountered in the document.
    #[must_use]
    pub fn element_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for node in &self.nodes {
            if let AXMLNode::StartElement { name, .. } = node
                && !names.contains(name) {
                    names.push(name.clone());
                }
        }
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private parse helpers
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_ns_idx(pool: &ResStringPool, idx: u32, sentinel: u32) -> Option<String> {
    if idx == sentinel || idx == 0xFFFF_FFFF {
        return None;
    }
    pool.get(idx as usize).map(std::string::ToString::to_string)
}

fn parse_attribute(
    data: &[u8],
    pool: &ResStringPool,
    res_map: &[u32],
    pool_idx: usize,
) -> AXMLAttribute {
    let rd32 = |o: usize| -> u32 {
        if o + 4 <= data.len() {
            u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
        } else {
            0
        }
    };

    let ns_idx = rd32(0);
    let name_idx = rd32(4) as usize;
    let raw_idx = rd32(8) as i32;
    let data_type = if data.len() >= 16 { data[15] } else { 0 };
    let data_val = rd32(16);

    let namespace_uri = resolve_ns_idx(pool, ns_idx, 0xFFFF_FFFF);
    let name = pool.get(name_idx).unwrap_or("?").to_string();
    let raw_value = if raw_idx >= 0 {
        pool.get(raw_idx as usize).map(std::string::ToString::to_string)
    } else {
        None
    };
    let resource_id = res_map.get(pool_idx).copied();

    AXMLAttribute {
        namespace_uri,
        name,
        raw_value,
        resource_id,
        data_value: data_val,
        data_type,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ChunkType ─────────────────────────────────────────────────────────────

    #[test]
    fn test_chunk_type_string_pool() {
        assert_eq!(ChunkType::from_u16(0x0001), ChunkType::StringPool);
        assert_eq!(ChunkType::StringPool.name(), "StringPool");
    }

    #[test]
    fn test_chunk_type_xml() {
        assert_eq!(ChunkType::from_u16(0x0003), ChunkType::Xml);
        assert!(!ChunkType::Xml.is_xml_node());
    }

    #[test]
    fn test_chunk_type_start_element() {
        let ct = ChunkType::from_u16(0x0102);
        assert_eq!(ct, ChunkType::XmlStartElement);
        assert!(ct.is_xml_node());
        assert_eq!(ct.to_string(), "XmlStartElement");
    }

    #[test]
    fn test_chunk_type_end_element() {
        assert!(ChunkType::from_u16(0x0103).is_xml_node());
    }

    #[test]
    fn test_chunk_type_start_namespace() {
        assert!(ChunkType::from_u16(0x0100).is_xml_node());
    }

    #[test]
    fn test_chunk_type_end_namespace() {
        assert!(ChunkType::from_u16(0x0101).is_xml_node());
    }

    #[test]
    fn test_chunk_type_resource_map() {
        let ct = ChunkType::from_u16(0x0180);
        assert_eq!(ct, ChunkType::XmlResourceMap);
        assert!(!ct.is_xml_node());
    }

    #[test]
    fn test_chunk_type_unknown() {
        let ct = ChunkType::from_u16(0xABCD);
        assert_eq!(ct, ChunkType::Unknown);
    }

    #[test]
    fn test_chunk_type_cdata() {
        let ct = ChunkType::from_u16(0x0104);
        assert_eq!(ct, ChunkType::XmlCdata);
        assert!(ct.is_xml_node());
    }

    // ── ChunkHeader ───────────────────────────────────────────────────────────

    #[test]
    fn test_chunk_header_parse() {
        let data = [
            0x01, 0x00, // type = StringPool
            0x1C, 0x00, // header_size = 28
            0x40, 0x00, 0x00, 0x00, // chunk_size = 64
        ];
        let hdr = ChunkHeader::parse(&data).unwrap();
        assert_eq!(hdr.chunk_type, ChunkType::StringPool);
        assert_eq!(hdr.header_size, 28);
        assert_eq!(hdr.chunk_size, 64);
        assert_eq!(hdr.data_size(), 64 - 28);
    }

    #[test]
    fn test_chunk_header_parse_too_short() {
        assert!(ChunkHeader::parse(&[0u8; 7]).is_none());
    }

    // ── ResStringPool ─────────────────────────────────────────────────────────

    #[test]
    fn test_string_pool_empty_chunk() {
        let pool = ResStringPool::parse(&[]);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_string_pool_get_out_of_bounds() {
        let pool = ResStringPool::default();
        assert!(pool.get(0).is_none());
    }

    #[test]
    fn test_string_pool_len() {
        let pool = ResStringPool {
            strings: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(pool.len(), 2);
        assert!(!pool.is_empty());
    }

    // ── ResXMLTreeAttrExt ─────────────────────────────────────────────────────

    #[test]
    fn test_attr_ext_parse_valid() {
        let data = [
            0xFF, 0xFF, 0xFF, 0xFF, // ns_idx = 0xFFFFFFFF
            0x03, 0x00, 0x00, 0x00, // name_idx = 3
            0x14, 0x00, // attribute_start = 20
            0x14, 0x00, // attribute_size = 20
            0x02, 0x00, // attribute_count = 2
            0xFF, 0xFF, // id_index
        ];
        let ext = ResXMLTreeAttrExt::parse(&data).unwrap();
        assert_eq!(ext.ns_idx, 0xFFFF_FFFF);
        assert_eq!(ext.name_idx, 3);
        assert_eq!(ext.attribute_count, 2);
    }

    #[test]
    fn test_attr_ext_parse_too_short() {
        assert!(ResXMLTreeAttrExt::parse(&[0u8; 10]).is_none());
    }

    // ── AXMLAttribute ─────────────────────────────────────────────────────────

    #[test]
    fn test_attribute_value_int() {
        let attr = AXMLAttribute {
            namespace_uri: None,
            name: "minSdkVersion".into(),
            raw_value: None,
            resource_id: None,
            data_value: 21,
            data_type: 0x10, // INT_DEC
        };
        assert_eq!(attr.value_str(), "21");
    }

    #[test]
    fn test_attribute_value_bool_true() {
        let attr = AXMLAttribute {
            namespace_uri: None,
            name: "exported".into(),
            raw_value: None,
            resource_id: None,
            data_value: 1,
            data_type: 0x12, // BOOLEAN
        };
        assert_eq!(attr.value_str(), "true");
    }

    #[test]
    fn test_attribute_value_bool_false() {
        let attr = AXMLAttribute {
            namespace_uri: None,
            name: "exported".into(),
            raw_value: None,
            resource_id: None,
            data_value: 0,
            data_type: 0x12,
        };
        assert_eq!(attr.value_str(), "false");
    }

    #[test]
    fn test_attribute_value_raw_string() {
        let attr = AXMLAttribute {
            namespace_uri: None,
            name: "package".into(),
            raw_value: Some("com.example.app".into()),
            resource_id: None,
            data_value: 0,
            data_type: 0x03,
        };
        assert_eq!(attr.value_str(), "com.example.app");
    }

    #[test]
    fn test_attribute_value_hex() {
        let attr = AXMLAttribute {
            namespace_uri: None,
            name: "flags".into(),
            raw_value: None,
            resource_id: None,
            data_value: 0xABCDEF01,
            data_type: 0x11,
        };
        assert!(
            attr.value_str().contains("abcdef01")
                || attr.value_str().contains("ABCDEF01")
                || attr.value_str().contains("0xabcdef01")
        );
    }

    // ── AXMLNode display ──────────────────────────────────────────────────────

    #[test]
    fn test_node_display_start_namespace() {
        let ns = NamespaceDecl {
            prefix: "android".into(),
            uri: "http://schemas.android.com/apk/res/android".into(),
        };
        let node = AXMLNode::StartNamespace(ns);
        assert!(node.to_string().contains("android"));
    }

    #[test]
    fn test_node_display_end_element() {
        let node = AXMLNode::EndElement {
            namespace_uri: None,
            name: "manifest".into(),
        };
        assert!(node.to_string().contains("manifest"));
    }

    #[test]
    fn test_node_display_cdata() {
        let node = AXMLNode::CData("some text".into());
        assert!(node.to_string().contains("some text"));
    }

    // ── AXMLDocument.parse ────────────────────────────────────────────────────

    #[test]
    fn test_axml_parse_too_short() {
        assert!(AXMLDocument::parse(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_axml_parse_wrong_type() {
        let mut data = [0u8; 8];
        data[0] = 0x01; // type = 0x0001 (StringPool, not XML)
        data[4..8].copy_from_slice(&8_u32.to_le_bytes());
        assert!(AXMLDocument::parse(&data).is_err());
    }

    #[test]
    fn test_axml_parse_minimal_xml_header() {
        let mut data = [0u8; 8];
        data[0] = 0x03;
        data[1] = 0x00; // type = XML
        data[2] = 0x08;
        data[3] = 0x00; // header_size
        data[4..8].copy_from_slice(&8_u32.to_le_bytes()); // chunk_size = 8
        let doc = AXMLDocument::parse(&data).unwrap();
        assert_eq!(doc.node_count(), 0);
    }

    #[test]
    fn test_axml_find_attribute_missing() {
        let doc = AXMLDocument {
            string_pool: ResStringPool::default(),
            resource_map: vec![],
            nodes: vec![],
        };
        assert!(doc.find_attribute_value("manifest", "package").is_none());
    }

    #[test]
    fn test_axml_element_names_empty() {
        let doc = AXMLDocument {
            string_pool: ResStringPool::default(),
            resource_map: vec![],
            nodes: vec![],
        };
        assert!(doc.element_names().is_empty());
    }

    #[test]
    fn test_axml_namespaces_empty() {
        let doc = AXMLDocument {
            string_pool: ResStringPool::default(),
            resource_map: vec![],
            nodes: vec![],
        };
        assert!(doc.namespaces().is_empty());
    }

    #[test]
    fn test_axml_find_elements() {
        let node = AXMLNode::StartElement {
            namespace_uri: None,
            name: "activity".into(),
            attributes: vec![],
            line_number: 10,
        };
        let doc = AXMLDocument {
            string_pool: ResStringPool::default(),
            resource_map: vec![],
            nodes: vec![node],
        };
        assert_eq!(doc.find_elements("activity").len(), 1);
        assert_eq!(doc.find_elements("service").len(), 0);
    }
}
