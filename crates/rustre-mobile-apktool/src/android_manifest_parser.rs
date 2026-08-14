//! Binary AndroidManifest.xml (AXML) parser.
//!
//! Android APKs contain a binary-encoded `AndroidManifest.xml` in the AXML
//! (Android Binary XML) format.  This module parses that format to extract
//! permissions, activities, services, providers, and receivers.
//!
//! AXML chunk layout:
//! ```text
//! ChunkHeader (type=0x0003, header_size=8, chunk_size=N)
//! StringPool chunk
//! ResourceIdChunk (optional)
//! XmlEvent chunks: StartNamespace, EndNamespace, StartElement, EndElement, CData
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use std::collections::HashMap;
pub use std::fmt;

// ─── constants ────────────────────────────────────────────────────────────────

/// AXML file header chunk type.
pub const AXML_MAGIC: u16 = 0x0003;
/// String pool chunk type.
pub const CHUNK_STRING_POOL: u16 = 0x0001;
/// XML start namespace chunk type.
pub const CHUNK_XML_START_NAMESPACE: u16 = 0x0100;
/// XML end namespace chunk type.
pub const CHUNK_XML_END_NAMESPACE: u16 = 0x0101;
/// XML start element chunk type.
pub const CHUNK_XML_START_ELEMENT: u16 = 0x0102;
/// XML end element chunk type.
pub const CHUNK_XML_END_ELEMENT: u16 = 0x0103;
/// XML CDATA chunk type.
pub const CHUNK_XML_CDATA: u16 = 0x0104;
/// Resource ID chunk type.
pub const CHUNK_XML_RESOURCE_MAP: u16 = 0x0180;

/// Android manifest namespace.
pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the AXML parser.
#[derive(Debug, Error)]
pub enum AxmlError {
    /// File too short.
    #[error("file too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    /// Bad file magic.
    #[error("not an AXML file: magic {0:#06x}")]
    BadMagic(u16),
    /// Unknown chunk type.
    #[error("unknown chunk type {0:#06x} at offset {1:#x}")]
    UnknownChunk(u16, usize),
    /// String index out of range.
    #[error("string index {0} out of range (pool size {1})")]
    StringOob(usize, usize),
    /// Malformed attribute.
    #[error("malformed attribute at offset {0:#x}: {1}")]
    BadAttribute(usize, String),
    /// Generic parse error.
    #[error("axml parse error: {0}")]
    Parse(String),
}

// ─── XmlAttribute ─────────────────────────────────────────────────────────────

/// The data type of an AXML attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttrType {
    Null = 0x00,
    Reference = 0x01,
    String = 0x03,
    IntDec = 0x10,
    IntHex = 0x11,
    Bool = 0x12,
}

impl AttrType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Reference,
            0x03 => Self::String,
            0x10 => Self::IntDec,
            0x11 => Self::IntHex,
            0x12 => Self::Bool,
            _ => Self::Null,
        }
    }
}

/// One XML attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlAttribute {
    /// Namespace string index (-1 = none).
    pub ns_idx: i32,
    /// Name string index.
    pub name_idx: i32,
    /// Raw string value index (-1 = use `typed_value`).
    pub raw_value_idx: i32,
    /// Type code.
    pub attr_type: AttrType,
    /// Typed data value.
    pub typed_value: u32,
}

// ─── XmlEvent ─────────────────────────────────────────────────────────────────

/// One parsed AXML event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XmlEvent {
    /// Start of an XML namespace declaration.
    StartNamespace { prefix_idx: i32, uri_idx: i32 },
    /// End of an XML namespace.
    EndNamespace { prefix_idx: i32, uri_idx: i32 },
    /// Start of an XML element.
    StartElement {
        line: u32,
        ns_idx: i32,
        name_idx: i32,
        attrs: Vec<XmlAttribute>,
    },
    /// End of an XML element.
    EndElement {
        line: u32,
        ns_idx: i32,
        name_idx: i32,
    },
    /// Character data.
    CData { line: u32, data_idx: i32 },
}

// ─── AXML string pool parser ──────────────────────────────────────────────────

/// Minimal string pool from an AXML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxmlStringPool {
    pub strings: Vec<String>,
}

impl AxmlStringPool {
    /// Parse from `data` starting at `offset`.
    ///
    /// # Errors
    /// Returns an [`AxmlError`] when the buffer is truncated or the string pool is malformed.
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize), AxmlError> {
        if offset + 28 > data.len() {
            return Err(AxmlError::TooShort {
                need: offset + 28,
                have: data.len(),
            });
        }
        let d = &data[offset..];
        let _chunk_type = u16_le(d, 0);
        let _header_size = u16_le(d, 2);
        let chunk_size = u32_le(d, 4) as usize;
        let string_count = u32_le(d, 8) as usize;
        let _style_count = u32_le(d, 12) as usize;
        let flags = u32_le(d, 16);
        let strings_start = u32_le(d, 20) as usize;

        let is_utf8 = (flags & (1 << 8)) != 0;
        let offsets_base = 28usize;

        // `string_count` is an attacker-controlled u32. Every string needs a
        // 4-byte entry in the offset table that follows the header, so a count
        // larger than the buffer can hold is malformed by construction. Without
        // this check a 28-byte file declaring 0xFFFF_FFFF strings makes
        // `with_capacity` reserve ~100 GiB, and the loop below never terminates
        // early: once the offsets run out it just keeps pushing empty strings.
        let max_possible = d.len().saturating_sub(offsets_base) / 4;
        if string_count > max_possible {
            return Err(AxmlError::TooShort {
                need: offsets_base + string_count * 4,
                have: d.len(),
            });
        }

        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off_pos = offsets_base + i * 4;
            let str_off = if off_pos + 4 <= d.len() {
                u32_le(d, off_pos) as usize
            } else {
                0
            };
            let abs = strings_start + str_off;
            let s = if is_utf8 {
                parse_utf8_str(d, abs)
            } else {
                parse_utf16_str(d, abs)
            };
            strings.push(s.unwrap_or_default());
        }

        Ok((Self { strings }, offset + chunk_size))
    }

    /// Get string at `idx`, or empty string.
    #[must_use]
    pub fn get(&self, idx: i32) -> &str {
        if idx < 0 {
            return "";
        }
        self.strings
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .map_or("", std::string::String::as_str)
    }
}

fn parse_utf8_str(data: &[u8], abs: usize) -> Option<String> {
    if abs >= data.len() {
        return None;
    }
    let mut pos = abs;
    // Skip char-length byte
    if pos >= data.len() {
        return None;
    }
    let char_len = data[pos];
    let _ = char_len; // byte read for layout traversal
    pos += 1;
    if pos >= data.len() {
        return None;
    }
    let byte_len = data[pos] as usize;
    pos += 1;
    let end = pos + byte_len;
    if end > data.len() {
        return None;
    }
    std::str::from_utf8(&data[pos..end])
        .ok()
        .map(std::string::ToString::to_string)
}

fn parse_utf16_str(data: &[u8], abs: usize) -> Option<String> {
    if abs + 2 > data.len() {
        return None;
    }
    let len = u16_le(data, abs) as usize;
    let start = abs + 2;
    let end = start + len * 2;
    if end > data.len() {
        return None;
    }
    let words: Vec<u16> = (0..len).map(|i| u16_le(data, start + i * 2)).collect();
    String::from_utf16(&words).ok()
}

// ─── AXML parser ──────────────────────────────────────────────────────────────

/// Parse a complete AXML binary file.
///
/// Returns the string pool and ordered list of events.
///
/// # Errors
/// Returns an [`AxmlError`] when the file is truncated, the magic is invalid, or any chunk is malformed.
pub fn parse_axml(data: &[u8]) -> Result<(AxmlStringPool, Vec<XmlEvent>), AxmlError> {
    if data.len() < 8 {
        return Err(AxmlError::TooShort {
            need: 8,
            have: data.len(),
        });
    }
    let magic = u16_le(data, 0);
    if magic != AXML_MAGIC {
        return Err(AxmlError::BadMagic(magic));
    }
    let _file_size = u32_le(data, 4);

    let mut pos = 8usize;

    // Parse string pool (must be first chunk after header)
    if pos + 8 > data.len() {
        return Err(AxmlError::TooShort {
            need: pos + 8,
            have: data.len(),
        });
    }
    let sp_type = u16_le(data, pos);
    if sp_type != CHUNK_STRING_POOL {
        return Err(AxmlError::Parse(format!(
            "expected string pool at {pos:#x}, got {sp_type:#06x}"
        )));
    }
    let (pool, new_pos) = AxmlStringPool::parse(data, pos)?;
    pos = new_pos;

    let mut events = Vec::new();

    while pos + 8 <= data.len() {
        let chunk_type = u16_le(data, pos);
        let _header_sz = u16_le(data, pos + 2);
        let chunk_sz = u32_le(data, pos + 4) as usize;
        if chunk_sz == 0 {
            break;
        }
        let chunk_end = pos + chunk_sz;
        if chunk_end > data.len() {
            break;
        }

        match chunk_type {
            CHUNK_XML_START_NAMESPACE => {
                if pos + 16 <= data.len() {
                    events.push(XmlEvent::StartNamespace {
                        prefix_idx: i32_le(data, pos + 8),
                        uri_idx: i32_le(data, pos + 12),
                    });
                }
            }
            CHUNK_XML_END_NAMESPACE => {
                if pos + 16 <= data.len() {
                    events.push(XmlEvent::EndNamespace {
                        prefix_idx: i32_le(data, pos + 8),
                        uri_idx: i32_le(data, pos + 12),
                    });
                }
            }
            CHUNK_XML_START_ELEMENT => {
                if pos + 28 <= data.len() {
                    let line = u32_le(data, pos + 8);
                    let ns_idx = i32_le(data, pos + 12);
                    let name_idx = i32_le(data, pos + 16);
                    // attr_start(20), attr_size(22), attr_count(24), id_idx(26), class_idx(28), style_idx(30)
                    let attr_count = if pos + 26 <= data.len() {
                        u16_le(data, pos + 24) as usize
                    } else {
                        0
                    };
                    let attr_off = pos + 32;
                    let attr_size = 20usize;
                    let mut attrs = Vec::with_capacity(attr_count);
                    for i in 0..attr_count {
                        let a = attr_off + i * attr_size;
                        if a + attr_size > data.len() {
                            break;
                        }
                        let attr_type_byte = if data.is_empty() {
                            0
                        } else {
                            data[(a + 15).min(data.len() - 1)]
                        };
                        attrs.push(XmlAttribute {
                            ns_idx: i32_le(data, a),
                            name_idx: i32_le(data, a + 4),
                            raw_value_idx: i32_le(data, a + 8),
                            attr_type: AttrType::from_u8(attr_type_byte),
                            typed_value: u32_le(data, a + 16),
                        });
                    }
                    events.push(XmlEvent::StartElement {
                        line,
                        ns_idx,
                        name_idx,
                        attrs,
                    });
                }
            }
            CHUNK_XML_END_ELEMENT => {
                if pos + 20 <= data.len() {
                    events.push(XmlEvent::EndElement {
                        line: u32_le(data, pos + 8),
                        ns_idx: i32_le(data, pos + 12),
                        name_idx: i32_le(data, pos + 16),
                    });
                }
            }
            CHUNK_XML_CDATA
                if pos + 16 <= data.len() => {
                    events.push(XmlEvent::CData {
                        line: u32_le(data, pos + 8),
                        data_idx: i32_le(data, pos + 12),
                    });
                }
            _ => {} // skip resource map / unknown chunks
        }

        pos = chunk_end;
    }

    Ok((pool, events))
}

// ─── ManifestInfo ─────────────────────────────────────────────────────────────

/// Parsed Android manifest metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestInfo {
    /// Package name.
    pub package_name: String,
    /// Version code.
    pub version_code: Option<u32>,
    /// Version name.
    pub version_name: Option<String>,
    /// Min SDK version.
    pub min_sdk: Option<u32>,
    /// Target SDK version.
    pub target_sdk: Option<u32>,
    /// Declared permissions (e.g. `"android.permission.INTERNET"`).
    pub permissions: Vec<String>,
    /// Activity class names.
    pub activities: Vec<ActivityInfo>,
    /// Service class names.
    pub services: Vec<ServiceInfo>,
    /// Content provider authorities.
    pub providers: Vec<ProviderInfo>,
    /// Broadcast receivers.
    pub receivers: Vec<ReceiverInfo>,
    /// Application label attribute.
    pub app_label: Option<String>,
    /// Application debuggable flag.
    pub debuggable: bool,
    /// Application allow-backup flag.
    pub allow_backup: bool,
}

/// Activity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityInfo {
    pub name: String,
    pub exported: Option<bool>,
    pub intent_filters: Vec<IntentFilter>,
}

/// Service metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
}

/// Content provider metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub authorities: String,
    pub exported: Option<bool>,
}

/// Broadcast receiver metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverInfo {
    pub name: String,
    pub exported: Option<bool>,
    pub intent_filters: Vec<IntentFilter>,
}

/// Intent filter (action + category list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
}

// ─── ManifestParser ───────────────────────────────────────────────────────────

/// High-level manifest parser that extracts structured metadata from
/// a parsed AXML event stream.
pub struct ManifestParser {
    pool: AxmlStringPool,
    events: Vec<XmlEvent>,
}

impl ManifestParser {
    /// Parse from raw AXML bytes.
    ///
    /// # Errors
    /// Forwards [`AxmlError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, AxmlError> {
        let (pool, events) = parse_axml(data)?;
        Ok(Self { pool, events })
    }

    /// Create from a pre-parsed pool and event list.
    #[must_use]
    pub const fn new(pool: AxmlStringPool, events: Vec<XmlEvent>) -> Self {
        Self { pool, events }
    }

    /// Resolve a string index.
    #[must_use]
    fn str(&self, idx: i32) -> &str {
        self.pool.get(idx)
    }

    /// Find attribute value by name in an attribute list.
    fn attr_value<'a>(&'a self, attrs: &'a [XmlAttribute], name: &str) -> Option<&'a str> {
        for a in attrs {
            if self.str(a.name_idx) == name && a.raw_value_idx >= 0 {
                return Some(self.str(a.raw_value_idx));
            }
        }
        None
    }

    fn attr_bool(&self, attrs: &[XmlAttribute], name: &str) -> Option<bool> {
        for a in attrs {
            if self.str(a.name_idx) == name {
                if matches!(a.attr_type, AttrType::Bool) {
                    return Some(a.typed_value != 0);
                }
                if a.raw_value_idx >= 0 {
                    let s = self.str(a.raw_value_idx).to_lowercase();
                    return Some(s == "true");
                }
            }
        }
        None
    }

    fn attr_u32(&self, attrs: &[XmlAttribute], name: &str) -> Option<u32> {
        for a in attrs {
            if self.str(a.name_idx) == name {
                if matches!(
                    a.attr_type,
                    AttrType::IntDec | AttrType::IntHex | AttrType::Reference
                ) {
                    return Some(a.typed_value);
                }
                if a.raw_value_idx >= 0 {
                    return self.str(a.raw_value_idx).parse().ok();
                }
            }
        }
        None
    }

    /// Parse into a [`ManifestInfo`].
    #[must_use]
    pub fn parse(&self) -> ManifestInfo {
        let mut info = ManifestInfo::default();
        let mut stack: Vec<String> = Vec::new();
        let mut cur_intent: Option<IntentFilter> = None;

        for event in &self.events {
            match event {
                XmlEvent::StartElement {
                    name_idx, attrs, ..
                } => {
                    let name = self.str(*name_idx).to_string();

                    match name.as_str() {
                        "manifest" => {
                            info.package_name =
                                self.attr_value(attrs, "package").unwrap_or("").to_string();
                            info.version_code = self.attr_u32(attrs, "versionCode");
                            info.version_name = self
                                .attr_value(attrs, "versionName")
                                .map(std::string::ToString::to_string);
                        }
                        "uses-sdk" => {
                            info.min_sdk = self.attr_u32(attrs, "minSdkVersion");
                            info.target_sdk = self.attr_u32(attrs, "targetSdkVersion");
                        }
                        "uses-permission" | "permission" => {
                            if let Some(perm) = self.attr_value(attrs, "name") {
                                info.permissions.push(perm.to_string());
                            }
                        }
                        "application" => {
                            info.app_label = self
                                .attr_value(attrs, "label")
                                .map(std::string::ToString::to_string);
                            info.debuggable = self.attr_bool(attrs, "debuggable").unwrap_or(false);
                            info.allow_backup =
                                self.attr_bool(attrs, "allowBackup").unwrap_or(true);
                        }
                        "activity" => {
                            let act_name = self.attr_value(attrs, "name").unwrap_or("").to_string();
                            info.activities.push(ActivityInfo {
                                name: act_name,
                                exported: self.attr_bool(attrs, "exported"),
                                intent_filters: vec![],
                            });
                        }
                        "service" => {
                            info.services.push(ServiceInfo {
                                name: self.attr_value(attrs, "name").unwrap_or("").to_string(),
                                exported: self.attr_bool(attrs, "exported"),
                                permission: self
                                    .attr_value(attrs, "permission")
                                    .map(std::string::ToString::to_string),
                            });
                        }
                        "provider" => {
                            info.providers.push(ProviderInfo {
                                name: self.attr_value(attrs, "name").unwrap_or("").to_string(),
                                authorities: self
                                    .attr_value(attrs, "authorities")
                                    .unwrap_or("")
                                    .to_string(),
                                exported: self.attr_bool(attrs, "exported"),
                            });
                        }
                        "receiver" => {
                            info.receivers.push(ReceiverInfo {
                                name: self.attr_value(attrs, "name").unwrap_or("").to_string(),
                                exported: self.attr_bool(attrs, "exported"),
                                intent_filters: vec![],
                            });
                        }
                        "intent-filter" => {
                            cur_intent = Some(IntentFilter {
                                actions: vec![],
                                categories: vec![],
                            });
                        }
                        "action" => {
                            if let Some(ref mut fi) = cur_intent
                                && let Some(a) = self.attr_value(attrs, "name")
                            {
                                fi.actions.push(a.to_string());
                            }
                        }
                        "category" => {
                            if let Some(ref mut fi) = cur_intent
                                && let Some(c) = self.attr_value(attrs, "name")
                            {
                                fi.categories.push(c.to_string());
                            }
                        }
                        _ => {}
                    }
                    stack.push(name);
                }
                XmlEvent::EndElement { name_idx, .. } => {
                    let name = self.str(*name_idx);
                    if name == "intent-filter"
                        && let Some(fi) = cur_intent.take()
                    {
                        // Attach to the most recent activity / receiver
                        if let Some(act) = info.activities.last_mut()
                            && stack.contains(&"activity".to_string())
                        {
                            act.intent_filters.push(fi);
                            stack.pop();
                            continue;
                        }
                        if let Some(rec) = info.receivers.last_mut() {
                            rec.intent_filters.push(fi);
                        }
                    }
                    stack.pop();
                }
                _ => {}
            }
        }
        info
    }

    /// Extract only permissions from the event stream.
    #[must_use]
    pub fn extract_permissions(&self) -> Vec<String> {
        self.parse().permissions
    }

    /// Extract only activity names.
    #[must_use]
    pub fn extract_activities(&self) -> Vec<String> {
        self.parse()
            .activities
            .into_iter()
            .map(|a| a.name)
            .collect()
    }

    /// Extract only service names.
    #[must_use]
    pub fn extract_services(&self) -> Vec<String> {
        self.parse().services.into_iter().map(|s| s.name).collect()
    }

    /// Extract only provider authorities.
    #[must_use]
    pub fn extract_providers(&self) -> Vec<String> {
        self.parse()
            .providers
            .into_iter()
            .map(|p| p.authorities)
            .collect()
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn i32_le(data: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

// ─── build minimal AXML for testing ──────────────────────────────────────────

/// Build a minimal valid AXML binary for testing.
///
/// Creates a string pool with `strings`, then a single `StartElement` event.
#[must_use]
pub fn build_test_axml(strings: &[&str], element_name_idx: usize) -> Vec<u8> {
    let mut sp = build_string_pool_utf16(strings);
    // Pad to 4-byte alignment
    while !sp.len().is_multiple_of(4) {
        sp.push(0);
    }
    let sp_len = sp.len();

    // StartElement chunk: header(8) + line(4) + ext_hdr(4) + ns(4) + name(4)
    // + attr_list_hdr(8) + no attrs
    let elem_chunk_size = 8 + 4 + 4 + 4 + 4 + 8;
    let mut elem: Vec<u8> = Vec::with_capacity(elem_chunk_size);
    append_u16(&mut elem, CHUNK_XML_START_ELEMENT);
    append_u16(&mut elem, 8);
    append_u32(
        &mut elem,
        u32::try_from(elem_chunk_size).unwrap_or(u32::MAX),
    );
    append_u32(&mut elem, 1); // line number
    append_u32(&mut elem, 0xFFFF_FFFF_u32); // comment
    append_i32(&mut elem, -1); // ns
    append_i32(
        &mut elem,
        i32::try_from(element_name_idx).unwrap_or(i32::MAX),
    ); // name
    append_u16(&mut elem, 20); // attr_start
    append_u16(&mut elem, 20); // attr_size
    append_u16(&mut elem, 0); // attr_count
    append_u16(&mut elem, 0xFFFF); // id_idx
    append_u16(&mut elem, 0xFFFF); // class_idx
    append_u16(&mut elem, 0xFFFF); // style_idx

    // File header
    let total_size = 8 + sp_len + elem_chunk_size;
    let mut out: Vec<u8> = Vec::with_capacity(total_size);
    append_u16(&mut out, AXML_MAGIC);
    append_u16(&mut out, 8); // header size
    append_u32(&mut out, u32::try_from(total_size).unwrap_or(u32::MAX));
    out.extend_from_slice(&sp);
    out.extend_from_slice(&elem);
    out
}

fn build_string_pool_utf16(strings: &[&str]) -> Vec<u8> {
    let count = strings.len();
    // offsets: count * 4 bytes
    let offsets_size = count * 4;
    let header_size = 28usize;
    let strings_start = header_size + offsets_size;

    // encode each string as u16_le length + utf16 chars
    let est_bytes: usize = strings.iter().map(|s| s.len() * 2 + 4).sum();
    let mut string_data: Vec<u8> = Vec::with_capacity(est_bytes);
    let mut offsets: Vec<u32> = Vec::with_capacity(count);
    for s in strings {
        offsets.push(u32::try_from(string_data.len()).unwrap_or(u32::MAX));
        let chars: Vec<u16> = s.encode_utf16().collect();
        append_u16_slice(
            &mut string_data,
            u16::try_from(chars.len()).unwrap_or(u16::MAX),
        );
        for c in &chars {
            append_u16(&mut string_data, *c);
        }
        append_u16(&mut string_data, 0); // null terminator
    }

    let chunk_size =
        u32::try_from(header_size + offsets_size + string_data.len()).unwrap_or(u32::MAX);
    let mut out: Vec<u8> = Vec::with_capacity(chunk_size as usize);
    append_u16(&mut out, CHUNK_STRING_POOL);
    append_u16(&mut out, u16::try_from(header_size).unwrap_or(u16::MAX));
    append_u32(&mut out, chunk_size);
    append_u32(&mut out, u32::try_from(count).unwrap_or(u32::MAX));
    append_u32(&mut out, 0); // style_count
    append_u32(&mut out, 0); // flags (UTF-16)
    append_u32(&mut out, u32::try_from(strings_start).unwrap_or(u32::MAX)); // strings_start
    append_u32(&mut out, 0); // styles_start
    for off in &offsets {
        append_u32(&mut out, *off);
    }
    out.extend_from_slice(&string_data);
    out
}

fn append_u16(v: &mut Vec<u8>, val: u16) {
    v.extend_from_slice(&val.to_le_bytes());
}
fn append_u32(v: &mut Vec<u8>, val: u32) {
    v.extend_from_slice(&val.to_le_bytes());
}
fn append_i32(v: &mut Vec<u8>, val: i32) {
    v.extend_from_slice(&val.to_le_bytes());
}
fn append_u16_slice(v: &mut Vec<u8>, val: u16) {
    v.extend_from_slice(&val.to_le_bytes());
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axml_bad_magic() {
        let data = vec![0xFF_u8; 16];
        let err = parse_axml(&data).unwrap_err();
        assert!(matches!(err, AxmlError::BadMagic(_)));
    }

    #[test]
    fn test_axml_too_short() {
        let err = parse_axml(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, AxmlError::TooShort { .. }));
    }

    #[test]
    fn test_build_test_axml_parse() {
        let strings = &["android", "manifest", "package", "com.example.test"];
        let data = build_test_axml(strings, 1); // element = "manifest"
        let (pool, events) = parse_axml(&data).unwrap();
        assert_eq!(pool.strings.len(), 4);
        assert!(!events.is_empty());
    }

    #[test]
    fn test_axml_string_pool_rejects_impossible_count() {
        // A 28-byte header declaring 0xFFFF_FFFF strings: the offset table alone
        // would need 16 GiB. Trusting the count means reserving ~100 GiB and
        // looping four billion times, so a tiny file becomes a memory-exhaustion
        // DoS. The count must be rejected against what the buffer can hold.
        let mut data = vec![0u8; 28];
        data[4..8].copy_from_slice(&28u32.to_le_bytes()); // chunk_size
        data[8..12].copy_from_slice(&u32::MAX.to_le_bytes()); // string_count
        data[20..24].copy_from_slice(&28u32.to_le_bytes()); // strings_start

        let err = AxmlStringPool::parse(&data, 0).unwrap_err();
        assert!(
            matches!(err, AxmlError::TooShort { .. }),
            "expected TooShort for an impossible string count, got {err:?}"
        );
    }

    #[test]
    fn test_axml_string_pool_get() {
        let pool = AxmlStringPool {
            strings: vec!["hello".into(), "world".into()],
        };
        assert_eq!(pool.get(0), "hello");
        assert_eq!(pool.get(1), "world");
        assert_eq!(pool.get(-1), "");
        assert_eq!(pool.get(99), "");
    }

    #[test]
    fn test_attr_type_from_u8() {
        assert_eq!(AttrType::from_u8(0x03), AttrType::String);
        assert_eq!(AttrType::from_u8(0x12), AttrType::Bool);
        assert_eq!(AttrType::from_u8(0xFF), AttrType::Null);
    }

    #[test]
    fn test_manifest_info_default() {
        let info = ManifestInfo::default();
        assert!(info.package_name.is_empty());
        assert!(info.permissions.is_empty());
        assert!(info.activities.is_empty());
    }

    #[test]
    fn test_manifest_parser_extract_permissions_empty() {
        let pool = AxmlStringPool { strings: vec![] };
        let parser = ManifestParser::new(pool, vec![]);
        let perms = parser.extract_permissions();
        assert!(perms.is_empty());
    }

    #[test]
    fn test_manifest_parser_extract_from_events() {
        // Build a pool with the strings we need
        let strings = [
            "uses-permission",             // 0
            "name",                        // 1
            "android.permission.INTERNET", // 2
            "manifest",                    // 3
            "package",                     // 4
            "com.test",                    // 5
        ];
        let pool = AxmlStringPool {
            strings: strings
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        };
        let events = vec![
            XmlEvent::StartElement {
                line: 1,
                ns_idx: -1,
                name_idx: 3,
                attrs: vec![XmlAttribute {
                    ns_idx: -1,
                    name_idx: 4,
                    raw_value_idx: 5,
                    attr_type: AttrType::String,
                    typed_value: 0,
                }],
            },
            XmlEvent::StartElement {
                line: 2,
                ns_idx: -1,
                name_idx: 0, // uses-permission
                attrs: vec![XmlAttribute {
                    ns_idx: -1,
                    name_idx: 1,
                    raw_value_idx: 2, // name=android.permission.INTERNET
                    attr_type: AttrType::String,
                    typed_value: 0,
                }],
            },
            XmlEvent::EndElement {
                line: 2,
                ns_idx: -1,
                name_idx: 0,
            },
            XmlEvent::EndElement {
                line: 10,
                ns_idx: -1,
                name_idx: 3,
            },
        ];
        let parser = ManifestParser::new(pool, events);
        let info = parser.parse();
        assert_eq!(info.package_name, "com.test");
        assert_eq!(info.permissions, vec!["android.permission.INTERNET"]);
    }

    #[test]
    fn test_manifest_parser_activities() {
        let strings = ["activity", "name", "com.example.MainActivity"];
        let pool = AxmlStringPool {
            strings: strings
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        };
        let events = vec![
            XmlEvent::StartElement {
                line: 1,
                ns_idx: -1,
                name_idx: 0,
                attrs: vec![XmlAttribute {
                    ns_idx: -1,
                    name_idx: 1,
                    raw_value_idx: 2,
                    attr_type: AttrType::String,
                    typed_value: 0,
                }],
            },
            XmlEvent::EndElement {
                line: 2,
                ns_idx: -1,
                name_idx: 0,
            },
        ];
        let parser = ManifestParser::new(pool, events);
        let acts = parser.extract_activities();
        assert_eq!(acts, vec!["com.example.MainActivity"]);
    }

    #[test]
    fn test_manifest_parser_services() {
        let strings = ["service", "name", "com.example.MyService"];
        let pool = AxmlStringPool {
            strings: strings
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        };
        let events = vec![
            XmlEvent::StartElement {
                line: 1,
                ns_idx: -1,
                name_idx: 0,
                attrs: vec![XmlAttribute {
                    ns_idx: -1,
                    name_idx: 1,
                    raw_value_idx: 2,
                    attr_type: AttrType::String,
                    typed_value: 0,
                }],
            },
            XmlEvent::EndElement {
                line: 1,
                ns_idx: -1,
                name_idx: 0,
            },
        ];
        let parser = ManifestParser::new(pool, events);
        assert_eq!(parser.extract_services(), vec!["com.example.MyService"]);
    }

    #[test]
    fn test_manifest_parser_providers() {
        let strings = [
            "provider",
            "name",
            "MyProvider",
            "authorities",
            "com.example.provider",
        ];
        let pool = AxmlStringPool {
            strings: strings
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        };
        let events = vec![XmlEvent::StartElement {
            line: 1,
            ns_idx: -1,
            name_idx: 0,
            attrs: vec![
                XmlAttribute {
                    ns_idx: -1,
                    name_idx: 1,
                    raw_value_idx: 2,
                    attr_type: AttrType::String,
                    typed_value: 0,
                },
                XmlAttribute {
                    ns_idx: -1,
                    name_idx: 3,
                    raw_value_idx: 4,
                    attr_type: AttrType::String,
                    typed_value: 0,
                },
            ],
        }];
        let parser = ManifestParser::new(pool, events);
        let providers = parser.extract_providers();
        assert_eq!(providers, vec!["com.example.provider"]);
    }

    #[test]
    fn test_axml_error_messages() {
        let e = AxmlError::BadMagic(0xFFFF);
        assert!(e.to_string().contains("0xffff"));
        let e2 = AxmlError::StringOob(100, 50);
        assert!(e2.to_string().contains("100"));
    }

    #[test]
    fn test_axml_magic_constants() {
        assert_eq!(AXML_MAGIC, 0x0003);
        assert_eq!(CHUNK_XML_START_ELEMENT, 0x0102);
        assert_eq!(CHUNK_STRING_POOL, 0x0001);
    }
}
