//! Binary Android XML (AXML) parser — decodes `AndroidManifest.xml` from APKs.

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AxmlError {
    #[error("invalid AXML magic")]
    InvalidMagic,
    #[error("truncated AXML data")]
    Truncated,
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("invalid string index {0}")]
    InvalidStringIndex(u32),
}

// ── Chunk type constants ──────────────────────────────────────────────────────

pub const CHUNK_XML: u16 = 0x0003;
pub const CHUNK_STRING_POOL: u16 = 0x0001;
pub const CHUNK_XML_START_NS: u16 = 0x0100;
pub const CHUNK_XML_END_NS: u16 = 0x0101;
pub const CHUNK_XML_START_ELEM: u16 = 0x0102;
pub const CHUNK_XML_END_ELEM: u16 = 0x0103;
pub const CHUNK_XML_CDATA: u16 = 0x0104;

// ── String pool ───────────────────────────────────────────────────────────────

/// Decoded string pool from a binary AXML file.
#[derive(Debug, Clone, Default)]
pub struct AxmlStringPool {
    pub strings: Vec<String>,
}

/// Parse an AXML string pool chunk. `offset` is the start of the chunk header.
pub fn parse_string_pool(data: &[u8], offset: usize) -> Result<AxmlStringPool, AxmlError> {
    if offset.saturating_add(28) > data.len() {
        return Err(AxmlError::Truncated);
    }

    // String pool chunk header (28 bytes total for the header part we care about):
    // type(2), header_size(2), chunk_size(4), string_count(4), style_count(4),
    // flags(4), strings_start(4), styles_start(4)
    // let chunk_type   = le_u16(data, offset);
    let header_size = le_u16(data, offset + 2) as usize;
    // let chunk_size   = le_u32(data, offset + 4) as usize;
    let string_count = le_u32(data, offset + 8) as usize;
    // let style_count  = le_u32(data, offset + 12);
    let flags = le_u32(data, offset + 16);
    let strings_start = le_u32(data, offset + 20) as usize;
    // let styles_start = le_u32(data, offset + 24);

    let is_utf8 = flags & 0x100 != 0;

    // Read string offsets (u32 each), located right after the header.
    let offsets_start = offset.checked_add(header_size).ok_or(AxmlError::Truncated)?;
    let offsets_end = offsets_start.checked_add(string_count.checked_mul(4).ok_or(AxmlError::Truncated)?).ok_or(AxmlError::Truncated)?;
    if offsets_end > data.len() {
        return Err(AxmlError::Truncated);
    }
    let offsets: Vec<usize> = (0..string_count)
        .map(|i| le_u32(data, offsets_start + i * 4) as usize)
        .collect();

    // Absolute start of the strings data section.
    let str_data_base = offset.checked_add(strings_start).ok_or(AxmlError::Truncated)?;

    let mut strings = Vec::with_capacity(string_count);
    for &off in &offsets {
        let abs = str_data_base.saturating_add(off);
        if abs >= data.len() {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            decode_utf8_str(data, abs)
        } else {
            decode_utf16_str(data, abs)
        };
        strings.push(s);
    }

    Ok(AxmlStringPool { strings })
}

// ── Value type ────────────────────────────────────────────────────────────────

/// A typed attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum AxmlValue {
    Null,
    String(String),
    Int(i32),
    Bool(bool),
    Reference(u32),
    Float(f32),
    Color(u32),
}

// ── Events ────────────────────────────────────────────────────────────────────

/// A single attribute on an XML element.
#[derive(Debug, Clone)]
pub struct AxmlAttr {
    pub ns: Option<String>,
    pub name: String,
    pub raw_value: Option<String>,
    pub typed_value: AxmlValue,
}

/// Parsed AXML events.
#[derive(Debug, Clone)]
pub enum AxmlEvent {
    StartElement {
        ns: Option<String>,
        name: String,
        attrs: Vec<AxmlAttr>,
    },
    EndElement {
        name: String,
    },
    StartNamespace {
        prefix: String,
        uri: String,
    },
    EndNamespace {
        prefix: String,
    },
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Stateful AXML parser.
pub struct AxmlParser {
    data: Vec<u8>,
    pos: usize,
    string_pool: AxmlStringPool,
}

impl AxmlParser {
    /// Parse all events from a binary AndroidManifest.xml blob.
    pub fn parse(data: &[u8]) -> Result<Vec<AxmlEvent>, AxmlError> {
        if data.len() < 8 {
            return Err(AxmlError::Truncated);
        }
        let magic = le_u16(data, 0);
        if magic != CHUNK_XML {
            return Err(AxmlError::InvalidMagic);
        }

        let mut parser = Self {
            data: data.to_vec(),
            pos: 8, // skip root XML chunk header
            string_pool: AxmlStringPool::default(),
        };
        parser.parse_chunks()
    }

    fn parse_chunks(&mut self) -> Result<Vec<AxmlEvent>, AxmlError> {
        let mut events = Vec::new();

        while self.pos + 8 <= self.data.len() {
            let chunk_type = le_u16(&self.data, self.pos);
            let header_size = le_u16(&self.data, self.pos + 2) as usize;
            let chunk_size = le_u32(&self.data, self.pos + 4) as usize;

            if chunk_size < 8 || self.pos + chunk_size > self.data.len() {
                break;
            }

            match chunk_type {
                CHUNK_STRING_POOL => {
                    self.string_pool = parse_string_pool(&self.data, self.pos)?;
                }
                CHUNK_XML_START_NS => {
                    if self.pos + header_size >= self.pos + 16 + 8 {
                        // need at least 16 bytes body
                        let base = self.pos + header_size;
                        if base + 8 <= self.data.len() {
                            let prefix_idx = le_u32(&self.data, base);
                            let uri_idx = le_u32(&self.data, base + 4);
                            let prefix = self.string_at(prefix_idx);
                            let uri = self.string_at(uri_idx);
                            events.push(AxmlEvent::StartNamespace { prefix, uri });
                        }
                    }
                }
                CHUNK_XML_END_NS => {
                    let base = self.pos + header_size;
                    if base + 8 <= self.data.len() {
                        let prefix_idx = le_u32(&self.data, base);
                        let prefix = self.string_at(prefix_idx);
                        events.push(AxmlEvent::EndNamespace { prefix });
                    }
                }
                CHUNK_XML_START_ELEM => {
                    if let Some(ev) = self.parse_start_element(header_size) {
                        events.push(ev);
                    }
                }
                CHUNK_XML_END_ELEM => {
                    let base = self.pos + header_size;
                    if base + 8 <= self.data.len() {
                        let ns_idx = le_u32(&self.data, base);
                        let name_idx = le_u32(&self.data, base + 4);
                        let name = self.string_at(name_idx);
                        let ns = if ns_idx == 0xFFFF_FFFF {
                            None
                        } else {
                            Some(self.string_at(ns_idx))
                        };
                        let _ = ns;
                        events.push(AxmlEvent::EndElement { name });
                    }
                }
                _ => {}
            }

            self.pos += chunk_size;
        }

        Ok(events)
    }

    fn parse_start_element(&self, header_size: usize) -> Option<AxmlEvent> {
        let base = self.pos + header_size;
        // line_number(4), comment(4), ns_idx(4), name_idx(4)
        if base + 16 > self.data.len() {
            return None;
        }
        // let _line_number = le_u32(&self.data, base);
        // let _comment     = le_u32(&self.data, base + 4);
        let ns_idx = le_u32(&self.data, base + 8);
        let name_idx = le_u32(&self.data, base + 12);
        // attr_start(2), attr_size(2), attr_count(2), id_idx(2), class_idx(2), style_idx(2)
        if base + 28 > self.data.len() {
            return None;
        }
        let attr_start = le_u16(&self.data, base + 16) as usize;
        let attr_size = le_u16(&self.data, base + 18) as usize;
        let attr_count = le_u16(&self.data, base + 20) as usize;

        let name = self.string_at(name_idx);
        let ns = if ns_idx == 0xFFFF_FFFF {
            None
        } else {
            Some(self.string_at(ns_idx))
        };

        // Cap pre-allocation: each attribute occupies at least 20 bytes, so the
        // real count is bounded by the remaining buffer. Guards against a large
        // attr_count paired with a zero attr_size.
        let mut attrs = Vec::with_capacity(attr_count.min(self.data.len() / 20 + 1));
        // attr_start is relative to the start of ResXMLTree_attrExt (ns_idx field),
        // which is at base + 8 (after line_number and comment).
        let attr_base = base + 8 + attr_start;
        for i in 0..attr_count {
            let off = attr_base + i * attr_size;
            if off + 20 > self.data.len() {
                break;
            }
            let attr_ns_idx = le_u32(&self.data, off);
            let attr_name_idx = le_u32(&self.data, off + 4);
            let attr_raw_idx = le_u32(&self.data, off + 8);
            let _value_size = le_u16(&self.data, off + 12);
            let _res0 = self.data.get(off + 14).copied().unwrap_or(0);
            let data_type = self.data.get(off + 15).copied().unwrap_or(0);
            let data_val = le_u32(&self.data, off + 16);

            let attr_name = self.string_at(attr_name_idx);
            let attr_ns = if attr_ns_idx == 0xFFFF_FFFF {
                None
            } else {
                Some(self.string_at(attr_ns_idx))
            };
            let raw_value = if attr_raw_idx == 0xFFFF_FFFF {
                None
            } else {
                Some(self.string_at(attr_raw_idx))
            };

            let typed_value = decode_typed_value(data_type, data_val, &self.string_pool);

            attrs.push(AxmlAttr {
                ns: attr_ns,
                name: attr_name,
                raw_value,
                typed_value,
            });
        }

        Some(AxmlEvent::StartElement { ns, name, attrs })
    }

    fn string_at(&self, idx: u32) -> String {
        if idx == 0xFFFF_FFFF {
            return String::new();
        }
        self.string_pool
            .strings
            .get(idx as usize)
            .cloned()
            .unwrap_or_default()
    }
}

// ── High-level manifest parser ────────────────────────────────────────────────

/// High-level summary of an Android manifest.
#[derive(Debug, Clone, Default)]
pub struct BinaryManifest {
    pub package: String,
    pub version_code: i32,
    pub version_name: String,
    pub min_sdk: i32,
    pub target_sdk: i32,
    pub debuggable: bool,
    pub permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
}

/// Parse a binary `AndroidManifest.xml` into a [`BinaryManifest`].
pub fn parse_android_manifest_binary(data: &[u8]) -> Result<BinaryManifest, AxmlError> {
    let events = AxmlParser::parse(data)?;
    let mut manifest = BinaryManifest::default();

    for event in &events {
        match event {
            AxmlEvent::StartElement { name, attrs, .. } => match name.as_str() {
                "manifest" => {
                    for attr in attrs {
                        match attr.name.as_str() {
                            "package" => {
                                if let AxmlValue::String(s) = &attr.typed_value {
                                    manifest.package.clone_from(s);
                                }
                                if let Some(raw) = &attr.raw_value
                                    && manifest.package.is_empty() {
                                        manifest.package.clone_from(raw);
                                    }
                            }
                            "versionCode" => {
                                if let AxmlValue::Int(v) = attr.typed_value {
                                    manifest.version_code = v;
                                }
                            }
                            "versionName" => {
                                if let AxmlValue::String(s) = &attr.typed_value {
                                    manifest.version_name.clone_from(s);
                                }
                                if let Some(raw) = &attr.raw_value
                                    && manifest.version_name.is_empty() {
                                        manifest.version_name.clone_from(raw);
                                    }
                            }
                            _ => {}
                        }
                    }
                }
                "uses-sdk" => {
                    for attr in attrs {
                        match attr.name.as_str() {
                            "minSdkVersion" => {
                                if let AxmlValue::Int(v) = attr.typed_value {
                                    manifest.min_sdk = v;
                                }
                            }
                            "targetSdkVersion" => {
                                if let AxmlValue::Int(v) = attr.typed_value {
                                    manifest.target_sdk = v;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "application" => {
                    for attr in attrs {
                        if attr.name == "debuggable" {
                            manifest.debuggable = matches!(attr.typed_value, AxmlValue::Bool(true));
                        }
                    }
                }
                "uses-permission" => {
                    for attr in attrs {
                        if attr.name == "name" {
                            let perm = attr
                                .raw_value
                                .clone()
                                .or_else(|| {
                                    if let AxmlValue::String(s) = &attr.typed_value {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();
                            if !perm.is_empty() {
                                manifest.permissions.push(perm);
                            }
                        }
                    }
                }
                "activity" => {
                    for attr in attrs {
                        if attr.name == "name" {
                            let act = attr
                                .raw_value
                                .clone()
                                .or_else(|| {
                                    if let AxmlValue::String(s) = &attr.typed_value {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();
                            if !act.is_empty() {
                                manifest.activities.push(act);
                            }
                        }
                    }
                }
                "service" => {
                    for attr in attrs {
                        if attr.name == "name" {
                            let svc = attr
                                .raw_value
                                .clone()
                                .or_else(|| {
                                    if let AxmlValue::String(s) = &attr.typed_value {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();
                            if !svc.is_empty() {
                                manifest.services.push(svc);
                            }
                        }
                    }
                }
                _ => {}
            },
            AxmlEvent::EndElement { .. }
            | AxmlEvent::StartNamespace { .. }
            | AxmlEvent::EndNamespace { .. } => {}
        }
    }

    Ok(manifest)
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn decode_typed_value(data_type: u8, data_val: u32, pool: &AxmlStringPool) -> AxmlValue {
    match data_type {
        0x00 => AxmlValue::Null,
        0x03 => {
            let s = pool
                .strings
                .get(data_val as usize)
                .cloned()
                .unwrap_or_default();
            AxmlValue::String(s)
        }
        0x10 => AxmlValue::Int(data_val as i32),
        0x11 => AxmlValue::Bool(data_val != 0),
        0x01 => AxmlValue::Reference(data_val),
        0x04 => AxmlValue::Float(f32::from_bits(data_val)),
        0x1C..=0x1F => AxmlValue::Color(data_val),
        _ => AxmlValue::Int(data_val as i32),
    }
}

fn decode_utf16_str(data: &[u8], abs: usize) -> String {
    if abs + 2 > data.len() {
        return String::new();
    }
    // First u16 = character count
    let char_count = le_u16(data, abs) as usize;
    let str_start = abs + 2;
    let str_end = str_start + char_count * 2;
    if str_end > data.len() {
        return String::new();
    }
    let units: Vec<u16> = (0..char_count)
        .map(|i| le_u16(data, str_start + i * 2))
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_utf8_str(data: &[u8], abs: usize) -> String {
    if abs >= data.len() {
        return String::new();
    }
    let mut pos = abs;
    // Skip utf16_len (1 or 2 bytes)
    let _utf16_len = read_utf8_str_len(data, &mut pos);
    // utf8_len
    let utf8_len = read_utf8_str_len(data, &mut pos) as usize;
    if pos + utf8_len > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[pos..pos + utf8_len]).into_owned()
}

fn read_utf8_str_len(data: &[u8], pos: &mut usize) -> u32 {
    if *pos >= data.len() {
        return 0;
    }
    let b = u32::from(data[*pos]);
    *pos += 1;
    if b & 0x80 != 0 {
        if *pos >= data.len() {
            return b & 0x7F;
        }
        let b2 = u32::from(data[*pos]);
        *pos += 1;
        ((b & 0x7F) << 8) | b2
    } else {
        b
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_axml_header(chunk_size: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&CHUNK_XML.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes()); // header size
        v.extend_from_slice(&chunk_size.to_le_bytes());
        v
    }

    fn make_string_pool_chunk(strings: &[&str]) -> Vec<u8> {
        // Build a UTF-16 string pool chunk.
        let header_size: u16 = 28;
        let _strings_start_rel: u32 = (strings.len() as u32) * 4;
        let flags: u32 = 0; // UTF-16

        // Encode each string as: u16 char_count + UTF-16LE data + u16(0)
        let mut str_data = Vec::<u8>::new();
        let mut offsets = Vec::<u32>::new();
        for s in strings {
            offsets.push(str_data.len() as u32);
            let char_count = s.encode_utf16().count();
            str_data.extend_from_slice(&(char_count as u16).to_le_bytes());
            for c in s.encode_utf16() {
                str_data.extend_from_slice(&c.to_le_bytes());
            }
            str_data.extend_from_slice(&0u16.to_le_bytes()); // NUL
        }

        let chunk_size = u32::from(header_size) + (strings.len() as u32) * 4 + str_data.len() as u32;

        let mut v = Vec::new();
        v.extend_from_slice(&CHUNK_STRING_POOL.to_le_bytes());
        v.extend_from_slice(&header_size.to_le_bytes());
        v.extend_from_slice(&chunk_size.to_le_bytes());
        v.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // string_count
        v.extend_from_slice(&0u32.to_le_bytes()); // style_count
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&(u32::from(header_size) + strings.len() as u32 * 4).to_le_bytes()); // strings_start relative to chunk
        v.extend_from_slice(&0u32.to_le_bytes()); // styles_start

        for off in &offsets {
            v.extend_from_slice(&off.to_le_bytes());
        }
        v.extend_from_slice(&str_data);
        v
    }

    // ── Chunk constants ───────────────────────────────────────────────────────

    #[test]
    fn test_chunk_constants() {
        assert_eq!(CHUNK_XML, 0x0003);
        assert_eq!(CHUNK_STRING_POOL, 0x0001);
        assert_eq!(CHUNK_XML_START_ELEM, 0x0102);
        assert_eq!(CHUNK_XML_END_ELEM, 0x0103);
    }

    // ── parse_string_pool ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_string_pool_basic() {
        let pool_chunk = make_string_pool_chunk(&["hello", "world"]);
        let pool = parse_string_pool(&pool_chunk, 0).unwrap();
        assert_eq!(pool.strings.len(), 2);
        assert_eq!(pool.strings[0], "hello");
        assert_eq!(pool.strings[1], "world");
    }

    #[test]
    fn test_parse_string_pool_empty() {
        let pool_chunk = make_string_pool_chunk(&[]);
        let pool = parse_string_pool(&pool_chunk, 0).unwrap();
        assert!(pool.strings.is_empty());
    }

    #[test]
    fn test_parse_string_pool_truncated() {
        let result = parse_string_pool(&[0u8; 4], 0);
        assert!(result.is_err());
    }

    // ── AxmlParser ────────────────────────────────────────────────────────────

    #[test]
    fn test_parser_invalid_magic() {
        let mut data = vec![0u8; 8];
        data[0] = 0xFF;
        data[1] = 0xFF; // wrong magic
        assert!(matches!(
            AxmlParser::parse(&data),
            Err(AxmlError::InvalidMagic)
        ));
    }

    #[test]
    fn test_parser_truncated() {
        assert!(matches!(
            AxmlParser::parse(&[0u8; 4]),
            Err(AxmlError::Truncated)
        ));
    }

    #[test]
    fn test_parser_empty_body() {
        // Valid XML chunk header with no body chunks
        let mut data = make_axml_header(8);
        data[4..8].copy_from_slice(&8u32.to_le_bytes()); // chunk_size = 8
        let events = AxmlParser::parse(&data).unwrap();
        assert!(events.is_empty());
    }

    // ── decode_typed_value ────────────────────────────────────────────────────

    #[test]
    fn test_typed_value_null() {
        let pool = AxmlStringPool::default();
        assert_eq!(decode_typed_value(0x00, 0, &pool), AxmlValue::Null);
    }

    #[test]
    fn test_typed_value_int() {
        let pool = AxmlStringPool::default();
        assert_eq!(decode_typed_value(0x10, 42, &pool), AxmlValue::Int(42));
    }

    #[test]
    fn test_typed_value_bool_true() {
        let pool = AxmlStringPool::default();
        assert_eq!(decode_typed_value(0x11, 1, &pool), AxmlValue::Bool(true));
    }

    #[test]
    fn test_typed_value_bool_false() {
        let pool = AxmlStringPool::default();
        assert_eq!(decode_typed_value(0x11, 0, &pool), AxmlValue::Bool(false));
    }

    #[test]
    fn test_typed_value_string() {
        let mut pool = AxmlStringPool::default();
        pool.strings.push("com.example".to_string());
        assert_eq!(
            decode_typed_value(0x03, 0, &pool),
            AxmlValue::String("com.example".to_string())
        );
    }

    #[test]
    fn test_typed_value_reference() {
        let pool = AxmlStringPool::default();
        assert_eq!(
            decode_typed_value(0x01, 0x7F04_0001, &pool),
            AxmlValue::Reference(0x7F04_0001)
        );
    }

    // ── BinaryManifest ────────────────────────────────────────────────────────

    #[test]
    fn test_binary_manifest_default() {
        let m = BinaryManifest::default();
        assert!(m.package.is_empty());
        assert_eq!(m.min_sdk, 0);
        assert!(!m.debuggable);
        assert!(m.permissions.is_empty());
    }

    // ── parse_android_manifest_binary (round-trip) ────────────────────────────

    fn build_manifest_axml() -> Vec<u8> {
        // Build a minimal AXML blob with a string pool and a manifest element.
        // This tests the full parsing path.

        let pool_strings = vec![
            "android",
            "http://schemas.android.com/apk/res/android",
            "package",
            "versionCode",
            "versionName",
            "manifest",
            "com.test.app",
            "1.0",
        ];

        let pool_chunk = make_string_pool_chunk(&pool_strings);

        // Build start element for <manifest package="com.test.app" versionCode="1" versionName="1.0">
        // StartElement chunk layout after 8-byte header:
        //   header_size bytes of "extended header" then body
        // We use a simplified approach: just emit what AxmlParser expects.
        // For test purposes we'll build a minimal blob that has the right structure.

        // Start namespace chunk
        let mut ns_chunk = Vec::<u8>::new();
        ns_chunk.extend_from_slice(&CHUNK_XML_START_NS.to_le_bytes());
        ns_chunk.extend_from_slice(&8u16.to_le_bytes()); // header_size
        let ns_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // line
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
            b.extend_from_slice(&0u32.to_le_bytes()); // prefix idx = "android"
            b.extend_from_slice(&1u32.to_le_bytes()); // uri idx
            b
        };
        ns_chunk.extend_from_slice(&((8 + ns_body.len()) as u32).to_le_bytes());
        ns_chunk.extend_from_slice(&ns_body);

        // StartElement for "manifest"
        // attr records: ns_idx(4) name_idx(4) raw_idx(4) value_size(2) res0(1) type(1) data(4) = 20 bytes
        let attrs: Vec<u8> = {
            let mut b = Vec::new();
            // package = "com.test.app" (raw string index 6)
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns=none
            b.extend_from_slice(&2u32.to_le_bytes()); // name="package"
            b.extend_from_slice(&6u32.to_le_bytes()); // raw="com.test.app"
            b.extend_from_slice(&8u16.to_le_bytes()); // value_size
            b.push(0x00); // res0
            b.push(0x03); // type=string
            b.extend_from_slice(&6u32.to_le_bytes()); // data=string idx 6
            b
        };
        let attr_count: u16 = 1;
        let attr_size: u16 = 20;

        let elem_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // line
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns=none
            b.extend_from_slice(&5u32.to_le_bytes()); // name="manifest"
            b.extend_from_slice(&20u16.to_le_bytes()); // attr_start (relative to end of base header)
            b.extend_from_slice(&attr_size.to_le_bytes());
            b.extend_from_slice(&attr_count.to_le_bytes());
            b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // id_idx
            b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // class_idx
            b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // style_idx
            b.extend_from_slice(&attrs);
            b
        };

        let mut start_elem_chunk = Vec::<u8>::new();
        start_elem_chunk.extend_from_slice(&CHUNK_XML_START_ELEM.to_le_bytes());
        start_elem_chunk.extend_from_slice(&8u16.to_le_bytes()); // header_size
        start_elem_chunk.extend_from_slice(&((8 + elem_body.len()) as u32).to_le_bytes());
        start_elem_chunk.extend_from_slice(&elem_body);

        // End element
        let end_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // line
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
            b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
            b.extend_from_slice(&5u32.to_le_bytes()); // name="manifest"
            b
        };
        let mut end_elem_chunk = Vec::<u8>::new();
        end_elem_chunk.extend_from_slice(&CHUNK_XML_END_ELEM.to_le_bytes());
        end_elem_chunk.extend_from_slice(&8u16.to_le_bytes());
        end_elem_chunk.extend_from_slice(&((8 + end_body.len()) as u32).to_le_bytes());
        end_elem_chunk.extend_from_slice(&end_body);

        let total_body_size: usize =
            pool_chunk.len() + ns_chunk.len() + start_elem_chunk.len() + end_elem_chunk.len();
        let total_size = 8 + total_body_size;

        let mut out = make_axml_header(total_size as u32);
        out.extend_from_slice(&pool_chunk);
        out.extend_from_slice(&ns_chunk);
        out.extend_from_slice(&start_elem_chunk);
        out.extend_from_slice(&end_elem_chunk);
        out
    }

    #[test]
    fn test_parse_manifest_package() {
        let data = build_manifest_axml();
        let manifest = parse_android_manifest_binary(&data).unwrap();
        // The package should be "com.test.app" from our string pool
        assert_eq!(manifest.package, "com.test.app");
    }

    #[test]
    fn test_parse_manifest_no_crash_on_valid() {
        let data = build_manifest_axml();
        assert!(parse_android_manifest_binary(&data).is_ok());
    }

    #[test]
    fn test_parse_manifest_invalid_magic() {
        assert!(parse_android_manifest_binary(&[0u8; 16]).is_err());
    }

    // ── decode helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_decode_utf16_str_basic() {
        // "Hi" as UTF-16LE with length prefix
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes()); // length=2
        data.extend_from_slice(&b'H'.to_le_bytes());
        data.push(0);
        data.extend_from_slice(&b'i'.to_le_bytes());
        data.push(0);
        let s = decode_utf16_str(&data, 0);
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_decode_utf16_str_empty_on_bad_offset() {
        let s = decode_utf16_str(&[0u8; 4], 100);
        assert!(s.is_empty());
    }
}
