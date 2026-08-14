//! Binary and XML plist parser.
//!
//! Binary plist format magic: `bplist00`.
//! Supports: bool, int, real, string, data, date, array, dict, uid.

use std::collections::HashSet;
use thiserror::Error;

// ─── PlistError ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PlistError {
    #[error("not a plist: {0}")]
    NotAPlist(String),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("unsupported object type: {0:#x}")]
    UnsupportedType(u8),
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(String),
    #[error("xml parse error: {0}")]
    XmlParse(String),
    #[error("integer overflow")]
    Overflow,
    #[error("reference out of range: {0}")]
    BadRef(usize),
}

// ─── PlistValue ───────────────────────────────────────────────────────────────

/// A parsed plist value (binary or XML).
#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    Boolean(bool),
    Integer(i64),
    Real(f64),
    String(String),
    Data(Vec<u8>),
    /// Seconds since Apple epoch (2001-01-01 00:00:00 UTC).
    Date(f64),
    Array(Vec<Self>),
    Dict(Vec<(String, Self)>),
    Uid(u64),
    Null,
}

impl PlistValue {
    /// Return `true` if the value is a boolean `true`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Return the integer value if this is an `Integer`.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Return the string value if this is a `String`.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the array if this is an `Array`.
    #[must_use]
    pub const fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    /// Lookup a key in a `Dict`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Dict(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Return the byte slice if this is `Data`.
    #[must_use]
    pub const fn as_data(&self) -> Option<&[u8]> {
        match self {
            Self::Data(d) => Some(d.as_slice()),
            _ => None,
        }
    }

    /// Return a list of string values from an array, filtering non-strings.
    #[must_use]
    pub fn string_array(&self) -> Vec<&str> {
        match self {
            Self::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            _ => vec![],
        }
    }
}

// ─── Binary plist parser ──────────────────────────────────────────────────────

const BPLIST_MAGIC: &[u8] = b"bplist00";

/// Parse a binary plist from raw bytes.
///
/// # Errors
/// Returns [`PlistError`] on invalid input.
pub fn parse_binary_plist(data: &[u8]) -> Result<PlistValue, PlistError> {
    if data.len() < 32 {
        return Err(PlistError::Truncated(0));
    }
    if !data.starts_with(BPLIST_MAGIC) {
        return Err(PlistError::NotAPlist("not bplist00".into()));
    }

    // Trailer is the last 32 bytes.
    let trailer_start = data.len() - 32;
    let trailer = &data[trailer_start..];

    // Offset table offset size and object ref size.
    let offset_int_size = trailer[6] as usize;
    let object_ref_size = trailer[7] as usize;
    let num_objects = usize::try_from(u64::from_be_bytes(
        trailer[8..16]
            .try_into()
            .map_err(|_| PlistError::Truncated(trailer_start + 8))?,
    ))
    .map_err(|_| PlistError::Truncated(trailer_start + 8))?;
    let top_object = usize::try_from(u64::from_be_bytes(
        trailer[16..24]
            .try_into()
            .map_err(|_| PlistError::Truncated(trailer_start + 16))?,
    ))
    .map_err(|_| PlistError::Truncated(trailer_start + 16))?;
    let offset_table_offset = usize::try_from(u64::from_be_bytes(
        trailer[24..32]
            .try_into()
            .map_err(|_| PlistError::Truncated(trailer_start + 24))?,
    ))
    .map_err(|_| PlistError::Truncated(trailer_start + 24))?;

    if offset_int_size == 0 || offset_int_size > 8 {
        return Err(PlistError::NotAPlist(format!(
            "bad offset_int_size={offset_int_size}"
        )));
    }
    if object_ref_size == 0 || object_ref_size > 8 {
        return Err(PlistError::NotAPlist(format!(
            "bad object_ref_size={object_ref_size}"
        )));
    }

    // Read offset table.
    let offset_table_end = offset_table_offset.saturating_add(num_objects * offset_int_size);
    if offset_table_end > trailer_start {
        return Err(PlistError::Truncated(offset_table_offset));
    }

    let mut offsets: Vec<usize> = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let off = offset_table_offset + i * offset_int_size;
        let val = read_be_uint(data, off, offset_int_size)?;
        offsets.push(usize::try_from(val).map_err(|_| PlistError::Truncated(off))?);
    }

    // Parse the top-level object.
    let mut visited: HashSet<usize> = HashSet::new();
    parse_object(data, top_object, &offsets, object_ref_size, &mut visited)
}

fn read_be_uint(data: &[u8], offset: usize, size: usize) -> Result<u64, PlistError> {
    if offset + size > data.len() {
        return Err(PlistError::Truncated(offset));
    }
    let mut val: u64 = 0;
    for i in 0..size {
        val = (val << 8) | u64::from(data[offset + i]);
    }
    Ok(val)
}

fn parse_object(
    data: &[u8],
    obj_idx: usize,
    offsets: &[usize],
    ref_size: usize,
    visited: &mut HashSet<usize>,
) -> Result<PlistValue, PlistError> {
    if obj_idx >= offsets.len() {
        return Err(PlistError::BadRef(obj_idx));
    }
    // Cycle detection (protect against malformed plists).
    if !visited.insert(obj_idx) {
        return Ok(PlistValue::Null);
    }
    let result = parse_object_at(data, offsets[obj_idx], obj_idx, offsets, ref_size, visited);
    visited.remove(&obj_idx);
    result
}

fn parse_real(data: &[u8], offset: usize, low: u8, marker: u8) -> Result<PlistValue, PlistError> {
    let byte_count = 1usize << low;
    if offset + 1 + byte_count > data.len() {
        return Err(PlistError::Truncated(offset));
    }
    let val = match byte_count {
        4 => {
            let b: [u8; 4] = data[offset + 1..offset + 5]
                .try_into()
                .map_err(|_| PlistError::Truncated(offset))?;
            f64::from(f32::from_be_bytes(b))
        }
        8 => {
            let b: [u8; 8] = data[offset + 1..offset + 9]
                .try_into()
                .map_err(|_| PlistError::Truncated(offset))?;
            f64::from_be_bytes(b)
        }
        _ => return Err(PlistError::UnsupportedType(marker)),
    };
    Ok(PlistValue::Real(val))
}

fn parse_utf16_string(data: &[u8], offset: usize, low: u8) -> Result<PlistValue, PlistError> {
    let (char_count, consumed) = read_variable_length(data, offset + 1, low)?;
    let byte_len = char_count * 2;
    let start = offset + 1 + consumed;
    if start + byte_len > data.len() {
        return Err(PlistError::Truncated(start));
    }
    let mut chars: Vec<u16> = Vec::with_capacity(char_count);
    for i in 0..char_count {
        let hi = u16::from(data[start + i * 2]);
        let lo = u16::from(data[start + i * 2 + 1]);
        chars.push((hi << 8) | lo);
    }
    let s = String::from_utf16(&chars).map_err(|e| PlistError::InvalidUtf8(e.to_string()))?;
    Ok(PlistValue::String(s))
}

fn parse_array(
    data: &[u8],
    offset: usize,
    low: u8,
    offsets: &[usize],
    ref_size: usize,
    visited: &mut HashSet<usize>,
) -> Result<PlistValue, PlistError> {
    let (count, consumed) = read_variable_length(data, offset + 1, low)?;
    let refs_start = offset + 1 + consumed;
    if refs_start + count * ref_size > data.len() {
        return Err(PlistError::Truncated(refs_start));
    }
    let mut arr = Vec::with_capacity(count);
    for i in 0..count {
        let ref_off = refs_start + i * ref_size;
        let child_idx = usize::try_from(read_be_uint(data, ref_off, ref_size)?)
            .map_err(|_| PlistError::BadRef(0))?;
        arr.push(parse_object(data, child_idx, offsets, ref_size, visited)?);
    }
    Ok(PlistValue::Array(arr))
}

fn parse_dict(
    data: &[u8],
    offset: usize,
    low: u8,
    offsets: &[usize],
    ref_size: usize,
    visited: &mut HashSet<usize>,
) -> Result<PlistValue, PlistError> {
    let (count, consumed) = read_variable_length(data, offset + 1, low)?;
    let keys_start = offset + 1 + consumed;
    let vals_start = keys_start + count * ref_size;
    if vals_start + count * ref_size > data.len() {
        return Err(PlistError::Truncated(keys_start));
    }
    let mut pairs: Vec<(String, PlistValue)> = Vec::with_capacity(count);
    for i in 0..count {
        let key_idx = usize::try_from(read_be_uint(data, keys_start + i * ref_size, ref_size)?)
            .map_err(|_| PlistError::BadRef(0))?;
        let val_idx = usize::try_from(read_be_uint(data, vals_start + i * ref_size, ref_size)?)
            .map_err(|_| PlistError::BadRef(0))?;
        let key_val = parse_object(data, key_idx, offsets, ref_size, visited)?;
        let key_str = match key_val {
            PlistValue::String(s) => s,
            _ => format!("<key:{key_idx}>"),
        };
        let val = parse_object(data, val_idx, offsets, ref_size, visited)?;
        pairs.push((key_str, val));
    }
    Ok(PlistValue::Dict(pairs))
}

fn parse_object_at(
    data: &[u8],
    offset: usize,
    _obj_idx: usize,
    offsets: &[usize],
    ref_size: usize,
    visited: &mut HashSet<usize>,
) -> Result<PlistValue, PlistError> {
    if offset >= data.len() {
        return Err(PlistError::Truncated(offset));
    }
    let marker = data[offset];
    let high = (marker >> 4) & 0x0F;
    let low = marker & 0x0F;

    match high {
        0x0 => {
            // Singleton.
            match low {
                0x0 | 0xF => Ok(PlistValue::Null), // null or fill byte
                0x8 => Ok(PlistValue::Boolean(false)),
                0x9 => Ok(PlistValue::Boolean(true)),
                _ => Err(PlistError::UnsupportedType(marker)),
            }
        }
        0x1 => {
            // Integer: 2^low bytes, big-endian, signed if 8 bytes.
            let byte_count = 1usize << low;
            if offset + 1 + byte_count > data.len() {
                return Err(PlistError::Truncated(offset));
            }
            let raw = read_be_uint(data, offset + 1, byte_count)?;
            let val = raw.cast_signed();
            Ok(PlistValue::Integer(val))
        }
        0x2 => parse_real(data, offset, low, marker),
        0x3 => {
            // Date: 8-byte big-endian f64.
            if offset + 9 > data.len() {
                return Err(PlistError::Truncated(offset));
            }
            let b: [u8; 8] = data[offset + 1..offset + 9]
                .try_into()
                .map_err(|_| PlistError::Truncated(offset))?;
            Ok(PlistValue::Date(f64::from_be_bytes(b)))
        }
        0x4 => {
            // Data.
            let (len, consumed) = read_variable_length(data, offset + 1, low)?;
            let start = offset + 1 + consumed;
            if start + len > data.len() {
                return Err(PlistError::Truncated(start));
            }
            Ok(PlistValue::Data(data[start..start + len].to_vec()))
        }
        0x5 => {
            // ASCII string.
            let (len, consumed) = read_variable_length(data, offset + 1, low)?;
            let start = offset + 1 + consumed;
            if start + len > data.len() {
                return Err(PlistError::Truncated(start));
            }
            let s = std::str::from_utf8(&data[start..start + len])
                .map_err(|e| PlistError::InvalidUtf8(e.to_string()))?;
            Ok(PlistValue::String(s.to_string()))
        }
        0x6 => parse_utf16_string(data, offset, low),
        0x8 => {
            // UID: (low + 1) bytes.
            let byte_count = (low as usize) + 1;
            if offset + 1 + byte_count > data.len() {
                return Err(PlistError::Truncated(offset));
            }
            let uid = read_be_uint(data, offset + 1, byte_count)?;
            Ok(PlistValue::Uid(uid))
        }
        0xA => parse_array(data, offset, low, offsets, ref_size, visited),
        0xD => parse_dict(data, offset, low, offsets, ref_size, visited),
        _ => Err(PlistError::UnsupportedType(marker)),
    }
}

fn read_variable_length(data: &[u8], offset: usize, low: u8) -> Result<(usize, usize), PlistError> {
    if low != 0x0F {
        return Ok((low as usize, 0));
    }
    // Length is encoded as an integer object immediately following.
    if offset >= data.len() {
        return Err(PlistError::Truncated(offset));
    }
    let int_marker = data[offset];
    if (int_marker >> 4) != 0x1 {
        return Err(PlistError::UnsupportedType(int_marker));
    }
    let byte_count = 1usize << (int_marker & 0x0F);
    if offset + 1 + byte_count > data.len() {
        return Err(PlistError::Truncated(offset));
    }
    let len = usize::try_from(read_be_uint(data, offset + 1, byte_count)?)
        .map_err(|_| PlistError::Truncated(offset))?;
    Ok((len, 1 + byte_count))
}

// ─── XML plist parser ─────────────────────────────────────────────────────────

/// Parse an XML plist from raw bytes.
///
/// # Errors
/// Returns [`PlistError`] on invalid input.
pub fn parse_xml_plist(data: &[u8]) -> Result<PlistValue, PlistError> {
    let xml = std::str::from_utf8(data).map_err(|e| PlistError::InvalidUtf8(e.to_string()))?;
    parse_xml_plist_str(xml)
}

/// Parse an XML plist from a string slice.
///
/// # Errors
/// Returns [`PlistError`] on invalid input.
pub fn parse_xml_plist_str(xml: &str) -> Result<PlistValue, PlistError> {
    // Find the top-level <dict> or <array>.
    let xml = xml.trim();
    // Skip <?xml?> and <!DOCTYPE> and <plist> wrappers.
    let body = strip_plist_wrapper(xml);
    parse_xml_value(body.trim())
}

fn strip_plist_wrapper(xml: &str) -> &str {
    let mut s = xml;
    // Strip <?xml ... ?>
    if let Some(pos) = s.find("?>") {
        s = &s[pos + 2..];
    }
    // Strip <!DOCTYPE ...>
    if let Some(start) = s.find("<!DOCTYPE")
        && let Some(end) = s[start..].find('>')
    {
        s = &s[start + end + 1..];
    }
    // Strip <plist ...>
    if let Some(start) = s.find("<plist")
        && let Some(end) = s[start..].find('>')
    {
        s = &s[start + end + 1..];
    }
    // Strip </plist>
    if let Some(pos) = s.rfind("</plist>") {
        s = &s[..pos];
    }
    s
}

fn parse_xml_value(s: &str) -> Result<PlistValue, PlistError> {
    let s = s.trim();
    if s.starts_with("<dict>") {
        parse_xml_dict(s)
    } else if s.starts_with("<array>") {
        parse_xml_array(s)
    } else if s.starts_with("<string>") {
        let inner = extract_tag_content(s, "string")
            .ok_or_else(|| PlistError::XmlParse("bad <string>".into()))?;
        Ok(PlistValue::String(unescape_xml(inner)))
    } else if s.starts_with("<integer>") {
        let inner = extract_tag_content(s, "integer")
            .ok_or_else(|| PlistError::XmlParse("bad <integer>".into()))?;
        let n: i64 = inner
            .trim()
            .parse()
            .map_err(|_| PlistError::XmlParse(format!("bad integer: {inner}")))?;
        Ok(PlistValue::Integer(n))
    } else if s.starts_with("<real>") {
        let inner = extract_tag_content(s, "real")
            .ok_or_else(|| PlistError::XmlParse("bad <real>".into()))?;
        let r: f64 = inner
            .trim()
            .parse()
            .map_err(|_| PlistError::XmlParse(format!("bad real: {inner}")))?;
        Ok(PlistValue::Real(r))
    } else if s.starts_with("<true/>") || s.starts_with("<true />") {
        Ok(PlistValue::Boolean(true))
    } else if s.starts_with("<false/>") || s.starts_with("<false />") {
        Ok(PlistValue::Boolean(false))
    } else if s.starts_with("<data>") {
        let inner = extract_tag_content(s, "data")
            .ok_or_else(|| PlistError::XmlParse("bad <data>".into()))?;
        let bytes = decode_base64(inner.trim())?;
        Ok(PlistValue::Data(bytes))
    } else if s.starts_with("<date>") {
        let inner = extract_tag_content(s, "date")
            .ok_or_else(|| PlistError::XmlParse("bad <date>".into()))?;
        // Store as 0.0; full ISO 8601 parsing is out of scope.
        let _ = inner;
        Ok(PlistValue::Date(0.0))
    } else {
        Err(PlistError::XmlParse(format!(
            "unknown element at: {}",
            &s[..s.len().min(40)]
        )))
    }
}

fn extract_tag_content<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(&s[start..end])
}

fn parse_xml_dict(s: &str) -> Result<PlistValue, PlistError> {
    let inner = &s["<dict>".len()..];
    let end = inner
        .rfind("</dict>")
        .ok_or_else(|| PlistError::XmlParse("missing </dict>".into()))?;
    let inner = &inner[..end];

    let mut pairs: Vec<(String, PlistValue)> = Vec::new();
    let mut pos = 0;
    let bytes = inner.as_bytes();

    while pos < inner.len() {
        // Skip whitespace.
        while pos < inner.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= inner.len() {
            break;
        }
        // Expect <key>...</key>.
        if !inner[pos..].starts_with("<key>") {
            break;
        }
        let key_end = inner[pos + 5..]
            .find("</key>")
            .ok_or_else(|| PlistError::XmlParse("missing </key>".into()))?;
        let key = unescape_xml(&inner[pos + 5..pos + 5 + key_end]);
        pos = pos + 5 + key_end + 6; // skip </key>

        // Skip whitespace.
        while pos < inner.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // Find the end of the next element.
        let remaining = &inner[pos..];
        let (val, consumed) = parse_xml_value_with_length(remaining)?;
        pairs.push((key, val));
        pos += consumed;
    }

    Ok(PlistValue::Dict(pairs))
}

fn parse_xml_array(s: &str) -> Result<PlistValue, PlistError> {
    let inner = &s["<array>".len()..];
    let end = inner
        .rfind("</array>")
        .ok_or_else(|| PlistError::XmlParse("missing </array>".into()))?;
    let inner = &inner[..end];

    let mut arr: Vec<PlistValue> = Vec::new();
    let mut pos = 0;
    let bytes = inner.as_bytes();

    while pos < inner.len() {
        while pos < inner.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= inner.len() {
            break;
        }
        let remaining = &inner[pos..];
        let (val, consumed) = parse_xml_value_with_length(remaining)?;
        arr.push(val);
        pos += consumed;
    }

    Ok(PlistValue::Array(arr))
}

/// Parse a value and return (value, `bytes_consumed`).
fn parse_xml_value_with_length(s: &str) -> Result<(PlistValue, usize), PlistError> {
    let s = s.trim_start();
    if s.starts_with("<dict>") {
        let end = find_closing_tag(s, "dict")?;
        let val = parse_xml_dict(&s[..end])?;
        Ok((val, end))
    } else if s.starts_with("<array>") {
        let end = find_closing_tag(s, "array")?;
        let val = parse_xml_array(&s[..end])?;
        Ok((val, end))
    } else if s.starts_with("<true/>") || s.starts_with("<true />") {
        let len = if s.starts_with("<true/>") { 7 } else { 8 };
        Ok((PlistValue::Boolean(true), len))
    } else if s.starts_with("<false/>") || s.starts_with("<false />") {
        let len = if s.starts_with("<false/>") { 8 } else { 9 };
        Ok((PlistValue::Boolean(false), len))
    } else {
        // Single-line tags: string, integer, real, data, date.
        for tag in &["string", "integer", "real", "data", "date"] {
            let open = format!("<{tag}>");
            let close = format!("</{tag}>");
            if s.starts_with(open.as_str()) {
                let close_pos = s
                    .find(close.as_str())
                    .ok_or_else(|| PlistError::XmlParse(format!("missing {close}")))?;
                let total = close_pos + close.len();
                let val = parse_xml_value(&s[..total])?;
                return Ok((val, total));
            }
        }
        Err(PlistError::XmlParse(format!(
            "unknown element: {}",
            &s[..s.len().min(40)]
        )))
    }
}

fn find_closing_tag(s: &str, tag: &str) -> Result<usize, PlistError> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut depth: i32 = 0;
    let mut pos = 0;
    while pos < s.len() {
        if s[pos..].starts_with(open.as_str()) {
            depth += 1;
            pos += open.len();
        } else if s[pos..].starts_with(close.as_str()) {
            depth -= 1;
            if depth == 0 {
                return Ok(pos + close.len());
            }
            pos += close.len();
        } else {
            pos += 1;
        }
    }
    Err(PlistError::XmlParse(format!("missing </{tag}>")))
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
}

/// Very simple base64 decoder (no padding checking).
fn decode_base64(s: &str) -> Result<Vec<u8>, PlistError> {
    const TABLE: &[u8; 128] = b"\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f\
\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\
\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\
\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff";

    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in s.as_bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        if b as usize >= TABLE.len() {
            return Err(PlistError::XmlParse(format!("invalid base64 char {b}")));
        }
        let val = TABLE[b as usize];
        if val == 0xFF {
            return Err(PlistError::XmlParse(format!("invalid base64 char {b}")));
        }
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xFF).unwrap_or(0));
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ─── Auto-detect ──────────────────────────────────────────────────────────────

/// Automatically detect binary vs XML plist and parse accordingly.
///
/// # Errors
/// Returns [`PlistError`] on invalid input.
pub fn plist_auto_detect(data: &[u8]) -> Result<PlistValue, PlistError> {
    if data.starts_with(BPLIST_MAGIC) {
        parse_binary_plist(data)
    } else if data.starts_with(b"<?xml")
        || data.starts_with(b"<plist")
        || data.starts_with(b"<dict")
    {
        parse_xml_plist(data)
    } else {
        Err(PlistError::NotAPlist("cannot detect plist format".into()))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_plist_simple_dict() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key><string>com.example.App</string>
<key>CFBundleVersion</key><string>1.0</string>
<key>MinOS</key><integer>14</integer>
<key>Enabled</key><true/>
</dict>
</plist>"#;
        let val = parse_xml_plist(xml.as_bytes()).unwrap();
        assert_eq!(
            val.get("CFBundleIdentifier").and_then(|v| v.as_str()),
            Some("com.example.App")
        );
        assert_eq!(
            val.get("Enabled").and_then(super::PlistValue::as_bool),
            Some(true)
        );
        assert_eq!(
            val.get("MinOS").and_then(super::PlistValue::as_integer),
            Some(14)
        );
    }

    #[test]
    fn test_xml_plist_array() {
        let xml = r"<plist><array><string>a</string><string>b</string></array></plist>";
        let val = parse_xml_plist(xml.as_bytes()).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str(), Some("a"));
    }

    #[test]
    fn test_xml_plist_nested_dict() {
        let xml = r"<plist><dict>
<key>outer</key><dict><key>inner</key><string>value</string></dict>
</dict></plist>";
        let val = parse_xml_plist(xml.as_bytes()).unwrap();
        let inner = val.get("outer").unwrap().get("inner").unwrap();
        assert_eq!(inner.as_str(), Some("value"));
    }

    #[test]
    fn test_auto_detect_xml() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict></dict></plist>";
        let r = plist_auto_detect(xml);
        assert!(r.is_ok());
    }

    #[test]
    fn test_auto_detect_unknown() {
        let r = plist_auto_detect(b"\xDE\xAD\xBE\xEF");
        assert!(matches!(r, Err(PlistError::NotAPlist(_))));
    }

    #[test]
    fn test_plist_value_string_array() {
        let val = PlistValue::Array(vec![
            PlistValue::String("x".into()),
            PlistValue::Integer(5),
            PlistValue::String("y".into()),
        ]);
        let arr = val.string_array();
        assert_eq!(arr, vec!["x", "y"]);
    }

    #[test]
    fn test_plist_value_as_data() {
        let val = PlistValue::Data(vec![1, 2, 3]);
        assert_eq!(val.as_data(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn test_plist_error_display() {
        assert!(PlistError::Truncated(100).to_string().contains("100"));
        assert!(
            PlistError::UnsupportedType(0xAB)
                .to_string()
                .contains("0xab")
        );
        assert!(PlistError::BadRef(5).to_string().contains('5'));
    }

    #[test]
    fn test_xml_true_false() {
        let xml = b"<plist><dict><key>a</key><true/><key>b</key><false/></dict></plist>";
        let val = plist_auto_detect(xml).unwrap();
        assert_eq!(
            val.get("a").and_then(super::PlistValue::as_bool),
            Some(true)
        );
        assert_eq!(
            val.get("b").and_then(super::PlistValue::as_bool),
            Some(false)
        );
    }

    #[test]
    fn test_base64_simple() {
        // "hello" in base64 is "aGVsbG8="
        let bytes = decode_base64("aGVsbG8=").unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_xml_data_element() {
        let xml = b"<plist><dict><key>blob</key><data>aGVsbG8=</data></dict></plist>";
        let val = plist_auto_detect(xml).unwrap();
        let data = val.get("blob").and_then(|v| v.as_data());
        assert_eq!(data, Some(b"hello" as &[u8]));
    }

    #[test]
    fn test_xml_real_element() {
        let xml = b"<plist><dict><key>pi</key><real>2.71</real></dict></plist>";
        let val = plist_auto_detect(xml).unwrap();
        match val.get("pi") {
            Some(PlistValue::Real(r)) => assert!((*r - 2.71).abs() < 0.01),
            _ => panic!("expected real"),
        }
    }

    #[test]
    fn test_unescape_xml() {
        assert_eq!(unescape_xml("a &amp; b"), "a & b");
        assert_eq!(unescape_xml("&lt;tag&gt;"), "<tag>");
    }

    #[test]
    fn test_plist_value_get_missing() {
        let val = PlistValue::Dict(vec![("k".into(), PlistValue::Integer(1))]);
        assert!(val.get("missing").is_none());
    }

    #[test]
    fn test_binary_plist_bad_magic() {
        let data = b"notabplist000000000000000000000000000000000000000";
        let err = parse_binary_plist(data).unwrap_err();
        assert!(matches!(err, PlistError::NotAPlist(_)));
    }

    #[test]
    fn test_binary_plist_too_short() {
        let data = b"bplist00";
        let err = parse_binary_plist(data).unwrap_err();
        assert!(matches!(err, PlistError::Truncated(_)));
    }
}
