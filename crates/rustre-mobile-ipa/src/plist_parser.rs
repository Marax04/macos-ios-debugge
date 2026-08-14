// Property List parser — binary bplist00 and XML plist formats.
// Supports all standard plist value types: string, integer, real, bool,
// date, data, uid, array, dict.  No external plist crate needed.

use std::collections::HashMap;
use std::fmt;

// ── Value type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    Boolean(bool),
    Integer(i64),
    Real(f64),
    /// RFC 3339 / "seconds since 2001-01-01" stored as f64
    Date(f64),
    Data(Vec<u8>),
    String(String),
    Uid(u64),
    Array(Vec<Self>),
    Dict(IndexedDict),
}

impl PlistValue {
    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Boolean(b) = self { Some(*b) } else { None }
    }
    #[must_use] 
    pub const fn as_i64(&self) -> Option<i64> {
        if let Self::Integer(n) = self { Some(*n) } else { None }
    }
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Real(f) => Some(*f),
            Self::Integer(n) => Some(f64::from(i32::try_from(*n).unwrap_or(i32::MAX))),
            _ => None,
        }
    }
    #[must_use] 
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s) } else { None }
    }
    #[must_use] 
    pub fn as_data(&self) -> Option<&[u8]> {
        if let Self::Data(d) = self { Some(d) } else { None }
    }
    #[must_use] 
    pub fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(a) = self { Some(a) } else { None }
    }
    #[must_use] 
    pub const fn as_dict(&self) -> Option<&IndexedDict> {
        if let Self::Dict(d) = self { Some(d) } else { None }
    }
    #[must_use] 
    pub fn dict_get(&self, key: &str) -> Option<&Self> {
        self.as_dict().and_then(|d| d.get(key))
    }
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::Date(_) => "date",
            Self::Data(_) => "data",
            Self::String(_) => "string",
            Self::Uid(_) => "uid",
            Self::Array(_) => "array",
            Self::Dict(_) => "dict",
        }
    }
}

impl fmt::Display for PlistValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Real(v) => write!(f, "{v}"),
            Self::Date(ts) => write!(f, "date({ts:.3})"),
            Self::Data(d) => write!(f, "<{} bytes>", d.len()),
            Self::String(s) => write!(f, "{s}"),
            Self::Uid(u) => write!(f, "uid({u})"),
            Self::Array(a) => write!(f, "[{}]", a.len()),
            Self::Dict(d) => write!(f, "{{{}}}", d.len()),
        }
    }
}

// ── IndexedDict — preserves insertion order ────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IndexedDict {
    keys: Vec<String>,
    values: HashMap<String, PlistValue>,
}

impl IndexedDict {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, k: String, v: PlistValue) {
        if !self.values.contains_key(&k) {
            self.keys.push(k.clone());
        }
        self.values.insert(k, v);
    }

    #[must_use] 
    pub fn get(&self, k: &str) -> Option<&PlistValue> {
        self.values.get(k)
    }

    #[must_use] 
    pub fn contains_key(&self, k: &str) -> bool { self.values.contains_key(k) }

    #[must_use] 
    pub const fn len(&self) -> usize { self.keys.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.keys.is_empty() }

    /// # Panics
    /// Never panics in practice; keys and values are always kept in sync.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PlistValue)> {
        self.keys.iter().map(move |k| (k.as_str(), self.values.get(k).unwrap()))
    }

    #[must_use] 
    pub fn keys(&self) -> &[String] { &self.keys }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PlistError {
    UnknownFormat,
    Truncated { offset: usize },
    InvalidMagic,
    UnsupportedVersion { version: [u8; 2] },
    InvalidObjectRef { idx: usize },
    CycleDetected,
    InvalidUtf8 { offset: usize },
    InvalidXml { msg: String },
    IntegerOverflow,
    UnknownMarker { marker: u8, offset: usize },
    Io(String),
}

impl fmt::Display for PlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "unknown plist format"),
            Self::Truncated { offset } => write!(f, "truncated at offset {offset}"),
            Self::InvalidMagic => write!(f, "invalid magic bytes"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported bplist version {:02x}{:02x}", version[0], version[1])
            }
            Self::InvalidObjectRef { idx } => write!(f, "invalid object ref {idx}"),
            Self::CycleDetected => write!(f, "cycle detected in object graph"),
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {offset}"),
            Self::InvalidXml { msg } => write!(f, "invalid XML plist: {msg}"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::UnknownMarker { marker, offset } => {
                write!(f, "unknown marker 0x{marker:02x} at offset {offset}")
            }
            Self::Io(s) => write!(f, "I/O: {s}"),
        }
    }
}

impl std::error::Error for PlistError {}

pub type PlistResult<T> = Result<T, PlistError>;

// ── Top-level parser ─────────────────────────────────────────────────────────

pub struct PlistParser;

impl PlistParser {
    /// Auto-detect format and parse.
    ///
    /// # Errors
    /// Returns [`PlistError`] if the data cannot be parsed as a plist.
    pub fn parse(data: &[u8]) -> PlistResult<PlistValue> {
        if data.starts_with(b"bplist00") {
            BinaryPlistParser::parse(data)
        } else if data.starts_with(b"bplist") {
            Err(PlistError::UnsupportedVersion {
                version: [data.get(6).copied().unwrap_or(0), data.get(7).copied().unwrap_or(0)],
            })
        } else if data.starts_with(b"<?xml") || data.starts_with(b"<plist") || contains_plist_doctype(data) || data.iter().take(64).any(|&b| b == b'<') {
            XmlPlistParser::parse(data)
        } else {
            Err(PlistError::UnknownFormat)
        }
    }
}

fn contains_plist_doctype(data: &[u8]) -> bool {
    data.windows(9).any(|w| w == b"<!DOCTYPE")
}

// ── Binary plist parser ───────────────────────────────────────────────────────

struct Trailer {
    offset_table_offset_size: u8,
    object_ref_size: u8,
    num_objects: u64,
    top_object: u64,
    offset_table_offset: u64,
}

struct BinaryPlistParser<'a> {
    data: &'a [u8],
    trailer: Trailer,
    offsets: Vec<u64>,
    stack: Vec<usize>, // for cycle detection
}

impl<'a> BinaryPlistParser<'a> {
    fn parse(data: &'a [u8]) -> PlistResult<PlistValue> {
        if data.len() < 32 {
            return Err(PlistError::Truncated { offset: 0 });
        }
        let trailer = Self::read_trailer(data);
        let offsets = Self::read_offset_table(data, &trailer)?;
        let top = usize::try_from(trailer.top_object).map_err(|_| PlistError::IntegerOverflow)?;
        let mut parser = BinaryPlistParser { data, trailer, offsets, stack: Vec::new() };
        parser.read_object(top)
    }

    fn read_trailer(data: &[u8]) -> Trailer {
        let len = data.len();
        let t = &data[len - 32..];
        // bytes 0-5: padding/sort-version
        // byte 6: offset-table int size, byte 7: object ref size
        // bytes 8-15: num objects, bytes 16-23: top object, bytes 24-31: offset table offset
        Trailer {
            offset_table_offset_size: t[6],
            object_ref_size: t[7],
            num_objects: read_be_u64(&t[8..16]),
            top_object: read_be_u64(&t[16..24]),
            offset_table_offset: read_be_u64(&t[24..32]),
        }
    }

    fn read_offset_table(data: &[u8], t: &Trailer) -> PlistResult<Vec<u64>> {
        let off_size = t.offset_table_offset_size as usize;
        if off_size == 0 || off_size > 8 {
            return Err(PlistError::IntegerOverflow);
        }
        let n = usize::try_from(t.num_objects).map_err(|_| PlistError::IntegerOverflow)?;
        let base = usize::try_from(t.offset_table_offset).map_err(|_| PlistError::IntegerOverflow)?;
        let table_bytes = n.checked_mul(off_size).ok_or(PlistError::IntegerOverflow)?;
        let needed = base.checked_add(table_bytes).ok_or(PlistError::IntegerOverflow)?;
        if data.len() < needed {
            return Err(PlistError::Truncated { offset: base });
        }
        let mut offsets = Vec::with_capacity(n);
        for i in 0..n {
            let start = base + i * off_size;
            let val = read_be_uint(&data[start..start + off_size]);
            offsets.push(val);
        }
        Ok(offsets)
    }

    fn read_object(&mut self, idx: usize) -> PlistResult<PlistValue> {
        if idx >= self.offsets.len() {
            return Err(PlistError::InvalidObjectRef { idx });
        }
        if self.stack.len() > 128 {
            return Err(PlistError::CycleDetected); // reuse error for depth limit
        }
        if self.stack.contains(&idx) {
            return Err(PlistError::CycleDetected);
        }
        self.stack.push(idx);
        let offset = usize::try_from(self.offsets[idx]).map_err(|_| PlistError::IntegerOverflow)?;
        if offset >= self.data.len() {
            return Err(PlistError::Truncated { offset });
        }
        let marker = self.data[offset];
        let high = (marker >> 4) & 0x0f;
        let low = marker & 0x0f;

        let result = match high {
            0x0 => Ok(Self::parse_simple(low, offset)),
            0x1 => self.parse_int(low, offset),
            0x2 => self.parse_real(low, offset),
            0x3 => self.parse_date(offset),
            0x4 => self.parse_data(low, offset),
            0x5 => self.parse_ascii_string(low, offset),
            0x6 => self.parse_utf16_string(low, offset),
            0x8 => self.parse_uid(low, offset),
            0xa => self.parse_array(low, offset),
            0xd => self.parse_dict(low, offset),
            _ => Err(PlistError::UnknownMarker { marker, offset }),
        }?;

        self.stack.pop();
        Ok(result)
    }

    const fn parse_simple(low: u8, _offset: usize) -> PlistValue {
        match low {
            0x9 => PlistValue::Boolean(true),
            _ => PlistValue::Boolean(false),
        }
    }

    fn parse_int(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let byte_count = 1usize << low;
        let start = offset + 1;
        if start + byte_count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let val = read_be_uint(&self.data[start..start + byte_count]);
        Ok(PlistValue::Integer(val.cast_signed()))
    }

    fn parse_real(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let byte_count = 1usize << low;
        let start = offset + 1;
        if start + byte_count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let val = match byte_count {
            4 => {
                let bits = u32::from_be_bytes(self.data[start..start + 4].try_into().unwrap());
                f64::from(f32::from_bits(bits))
            }
            8 => {
                let bits = u64::from_be_bytes(self.data[start..start + 8].try_into().unwrap());
                f64::from_bits(bits)
            }
            _ => return Err(PlistError::UnknownMarker { marker: 0x20 | low, offset }),
        };
        Ok(PlistValue::Real(val))
    }

    fn parse_date(&self, offset: usize) -> PlistResult<PlistValue> {
        let start = offset + 1;
        if start + 8 > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let bits = u64::from_be_bytes(self.data[start..start + 8].try_into().unwrap());
        Ok(PlistValue::Date(f64::from_bits(bits)))
    }

    fn parse_data(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let (count, skip) = self.read_count(low, offset + 1)?;
        let start = offset + 1 + skip;
        if start + count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        Ok(PlistValue::Data(self.data[start..start + count].to_vec()))
    }

    fn parse_ascii_string(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let (count, skip) = self.read_count(low, offset + 1)?;
        let start = offset + 1 + skip;
        if start + count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let s = std::str::from_utf8(&self.data[start..start + count])
            .map_err(|_| PlistError::InvalidUtf8 { offset: start })?;
        Ok(PlistValue::String(s.to_string()))
    }

    fn parse_utf16_string(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let (count, skip) = self.read_count(low, offset + 1)?;
        let start = offset + 1 + skip;
        let byte_count = count.checked_mul(2).ok_or(PlistError::IntegerOverflow)?;
        if start + byte_count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let units: Vec<u16> = self.data[start..start + byte_count]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&units)
            .map_err(|_| PlistError::InvalidUtf8 { offset: start })?;
        Ok(PlistValue::String(s))
    }

    fn parse_uid(&self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let byte_count = low as usize + 1;
        let start = offset + 1;
        if start + byte_count > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let val = read_be_uint(&self.data[start..start + byte_count]);
        Ok(PlistValue::Uid(val))
    }

    fn parse_array(&mut self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let (count, skip) = self.read_count(low, offset + 1)?;
        let ref_size = self.trailer.object_ref_size as usize;
        let start = offset + 1 + skip;
        let needed = count.checked_mul(ref_size)
            .and_then(|x| x.checked_add(start))
            .ok_or(PlistError::IntegerOverflow)?;
        if needed > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let mut refs = Vec::with_capacity(count);
        for i in 0..count {
            let p = start + i * ref_size;
            refs.push(usize::try_from(read_be_uint(&self.data[p..p + ref_size])).map_err(|_| PlistError::IntegerOverflow)?);
        }
        let mut items = Vec::with_capacity(count);
        for r in refs {
            items.push(self.read_object(r)?);
        }
        Ok(PlistValue::Array(items))
    }

    fn parse_dict(&mut self, low: u8, offset: usize) -> PlistResult<PlistValue> {
        let (count, skip) = self.read_count(low, offset + 1)?;
        let ref_size = self.trailer.object_ref_size as usize;
        let start = offset + 1 + skip;
        let needed = count.checked_mul(2)
            .and_then(|x| x.checked_mul(ref_size))
            .and_then(|x| x.checked_add(start))
            .ok_or(PlistError::IntegerOverflow)?;
        if needed > self.data.len() {
            return Err(PlistError::Truncated { offset: start });
        }
        let mut key_refs = Vec::with_capacity(count);
        let mut val_refs = Vec::with_capacity(count);
        for i in 0..count {
            let p = start + i * ref_size;
            key_refs.push(usize::try_from(read_be_uint(&self.data[p..p + ref_size])).map_err(|_| PlistError::IntegerOverflow)?);
        }
        for i in 0..count {
            let p = start + count * ref_size + i * ref_size;
            val_refs.push(usize::try_from(read_be_uint(&self.data[p..p + ref_size])).map_err(|_| PlistError::IntegerOverflow)?);
        }
        let mut dict = IndexedDict::new();
        for (kr, vr) in key_refs.into_iter().zip(val_refs) {
            let key_val = self.read_object(kr)?;
            let key = match key_val {
                PlistValue::String(s) => s,
                other => other.to_string(),
            };
            let val = self.read_object(vr)?;
            dict.insert(key, val);
        }
        Ok(PlistValue::Dict(dict))
    }

    /// Decode count: if low < 15, use low directly; otherwise read an int object.
    fn read_count(&self, low: u8, offset: usize) -> PlistResult<(usize, usize)> {
        if low < 0x0f {
            Ok((low as usize, 0))
        } else {
            // next byte is a marker for an integer
            if offset >= self.data.len() {
                return Err(PlistError::Truncated { offset });
            }
            let int_marker = self.data[offset];
            let int_low = int_marker & 0x0f;
            let byte_count = 1usize << int_low;
            let start = offset + 1;
            if start + byte_count > self.data.len() {
                return Err(PlistError::Truncated { offset: start });
            }
            let count = usize::try_from(read_be_uint(&self.data[start..start + byte_count])).map_err(|_| PlistError::IntegerOverflow)?;
            Ok((count, 1 + byte_count))
        }
    }
}

fn read_be_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in b {
        v = (v << 8) | u64::from(byte);
    }
    v
}

fn read_be_uint(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in b {
        v = (v << 8) | u64::from(byte);
    }
    v
}

// ── XML plist parser ──────────────────────────────────────────────────────────

pub struct XmlPlistParser;

impl XmlPlistParser {
    /// # Errors
    /// Returns [`PlistError`] if the data is not valid XML plist.
    pub fn parse(data: &[u8]) -> PlistResult<PlistValue> {
        let text = std::str::from_utf8(data)
            .map_err(|_| PlistError::InvalidUtf8 { offset: 0 })?;
        let mut tokenizer = XmlTokenizer::new(text);
        tokenizer.skip_to_plist_root()?;
        tokenizer.parse_value()
    }
}

// Minimal hand-rolled XML tokenizer for plist files.
struct XmlTokenizer<'a> {
    src: &'a str,
    pos: usize,
}

#[derive(Debug)]
enum XmlToken<'a> {
    OpenTag { name: &'a str, self_closing: bool },
    CloseTag { name: &'a str },
    Text(&'a str),
}

impl<'a> XmlTokenizer<'a> {
    const fn new(src: &'a str) -> Self { Self { src, pos: 0 } }

    fn remaining(&self) -> &'a str { &self.src[self.pos..] }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len()
            && self.src.as_bytes()[self.pos].is_ascii_whitespace()
        {
            self.pos += 1;
        }
    }

    fn skip_to_plist_root(&mut self) -> PlistResult<()> {
        // Skip past any <?xml ?> and <!DOCTYPE ...> to find <plist>
        loop {
            self.skip_whitespace();
            let rem = self.remaining();
            if rem.is_empty() {
                return Err(PlistError::InvalidXml { msg: "no <plist> element found".into() });
            }
            if rem.starts_with("<!--") {
                self.skip_comment()?;
            } else if rem.starts_with("<?") {
                self.skip_pi();
            } else if rem.starts_with("<!DOCTYPE") || rem.starts_with("<!doctype") {
                self.skip_doctype()?;
            } else if rem.starts_with("<plist") {
                // consume the <plist ...> open tag
                self.consume_open_tag();
                return Ok(());
            } else if rem.starts_with('<') {
                // some other tag — skip
                self.skip_to('>');
                self.pos += 1;
            } else {
                self.pos += 1;
            }
        }
    }

    fn skip_comment(&mut self) -> PlistResult<()> {
        self.pos += 4; // <!--
        while self.pos + 2 < self.src.len() {
            if self.src[self.pos..].starts_with("-->") {
                self.pos += 3;
                return Ok(());
            }
            self.pos += 1;
        }
        Err(PlistError::InvalidXml { msg: "unterminated comment".into() })
    }

    fn skip_pi(&mut self) {
        self.skip_to('>');
        self.pos += 1;
    }

    fn skip_doctype(&mut self) -> PlistResult<()> {
        let mut depth = 0i32;
        while self.pos < self.src.len() {
            match self.src.as_bytes()[self.pos] {
                b'<' => { depth += 1; self.pos += 1; }
                b'>' => {
                    depth -= 1;
                    self.pos += 1;
                    if depth <= 0 { return Ok(()); }
                }
                _ => { self.pos += 1; }
            }
        }
        Err(PlistError::InvalidXml { msg: "unterminated DOCTYPE".into() })
    }

    fn skip_to(&mut self, ch: char) {
        while self.pos < self.src.len() {
            if self.src.as_bytes()[self.pos] == ch as u8 {
                return;
            }
            self.pos += 1;
        }
    }

    fn consume_open_tag(&mut self) {
        self.skip_to('>');
        if self.pos < self.src.len() { self.pos += 1; }
    }

    fn next_token(&mut self) -> PlistResult<Option<XmlToken<'a>>> {
        self.skip_whitespace();
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        let rem = self.remaining();
        if rem.starts_with("<!--") {
            self.skip_comment()?;
            return self.next_token();
        }
        if rem.starts_with("</") {
            // close tag
            let start = self.pos + 2;
            self.pos = start;
            self.skip_to('>');
            let name = self.src[start..self.pos].trim();
            self.pos += 1;
            return Ok(Some(XmlToken::CloseTag { name }));
        }
        if rem.starts_with('<') {
            // open tag — possibly self-closing
            let start = self.pos + 1;
            self.pos = start;
            // read until '>' or '/>'
            let tag_start = self.pos;
            while self.pos < self.src.len() {
                let b = self.src.as_bytes()[self.pos];
                if b == b'>' || b == b'/' {
                    break;
                }
                self.pos += 1;
            }
            let raw_name = self.src[tag_start..self.pos].trim();
            // strip attributes: name is first word
            let name = raw_name.split_whitespace().next().unwrap_or(raw_name);
            let self_closing = self.remaining().starts_with("/>") || self.remaining().starts_with("/>");
            if self_closing {
                self.pos += 2; // skip />
            } else if self.remaining().starts_with('>') {
                self.pos += 1;
            }
            return Ok(Some(XmlToken::OpenTag { name, self_closing }));
        }
        // text content — read until '<', handle CDATA
        if rem.starts_with("<![CDATA[") {
            self.pos += 9;
            let start = self.pos;
            while self.pos + 2 < self.src.len() {
                if self.src[self.pos..].starts_with("]]>") {
                    let text = &self.src[start..self.pos];
                    self.pos += 3;
                    return Ok(Some(XmlToken::Text(text)));
                }
                self.pos += 1;
            }
            return Err(PlistError::InvalidXml { msg: "unterminated CDATA".into() });
        }
        let start = self.pos;
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos] != b'<' {
            self.pos += 1;
        }
        let text = &self.src[start..self.pos];
        Ok(Some(XmlToken::Text(text)))
    }

    fn parse_value(&mut self) -> PlistResult<PlistValue> {
        loop {
            match self.next_token()? {
                None => return Err(PlistError::InvalidXml { msg: "unexpected EOF".into() }),
                Some(XmlToken::CloseTag { .. }) => {
                    return Err(PlistError::InvalidXml { msg: "unexpected close tag".into() })
                }
                Some(XmlToken::Text(_)) => {}
                Some(XmlToken::OpenTag { name, self_closing }) => {
                    return self.parse_typed_value(name, self_closing);
                }
            }
        }
    }

    fn parse_typed_value(&mut self, tag: &str, self_closing: bool) -> PlistResult<PlistValue> {
        match tag {
            "true" => {
                if !self_closing { self.expect_close("true")?; }
                Ok(PlistValue::Boolean(true))
            }
            "false" => {
                if !self_closing { self.expect_close("false")?; }
                Ok(PlistValue::Boolean(false))
            }
            "integer" => {
                let text = self.collect_text_until_close("integer")?;
                let n: i64 = text.trim().parse()
                    .map_err(|_| PlistError::InvalidXml { msg: format!("bad integer: {text}") })?;
                Ok(PlistValue::Integer(n))
            }
            "real" => {
                let text = self.collect_text_until_close("real")?;
                let f: f64 = text.trim().parse()
                    .map_err(|_| PlistError::InvalidXml { msg: format!("bad real: {text}") })?;
                Ok(PlistValue::Real(f))
            }
            "string" => {
                if self_closing {
                    return Ok(PlistValue::String(String::new()));
                }
                let text = self.collect_text_until_close("string")?;
                Ok(PlistValue::String(xml_unescape(&text)))
            }
            "data" => {
                let text = self.collect_text_until_close("data")?;
                let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes = base64_decode(&clean)
                    .map_err(|e| PlistError::InvalidXml { msg: format!("bad base64: {e}") })?;
                Ok(PlistValue::Data(bytes))
            }
            "date" => {
                let text = self.collect_text_until_close("date")?;
                // Parse ISO 8601 date to seconds since 2001-01-01
                let ts = parse_iso8601_to_apple_epoch(text.trim());
                Ok(PlistValue::Date(ts))
            }
            "array" => {
                if self_closing { return Ok(PlistValue::Array(vec![])); }
                let mut items = Vec::new();
                loop {
                    self.skip_whitespace();
                    match self.next_token()? {
                        None => return Err(PlistError::InvalidXml { msg: "unclosed array".into() }),
                        Some(XmlToken::CloseTag { name: "array" }) => break,
                        Some(XmlToken::CloseTag { name }) => {
                            return Err(PlistError::InvalidXml {
                                msg: format!("unexpected </{name}> in array"),
                            });
                        }
                        Some(XmlToken::Text(_)) => {}
                        Some(XmlToken::OpenTag { name, self_closing }) => {
                            items.push(self.parse_typed_value(name, self_closing)?);
                        }
                    }
                }
                Ok(PlistValue::Array(items))
            }
            "dict" => {
                if self_closing { return Ok(PlistValue::Dict(IndexedDict::new())); }
                let mut dict = IndexedDict::new();
                loop {
                    self.skip_whitespace();
                    match self.next_token()? {
                        None => return Err(PlistError::InvalidXml { msg: "unclosed dict".into() }),
                        Some(XmlToken::CloseTag { name: "dict" }) => break,
                        Some(XmlToken::CloseTag { name }) => {
                            return Err(PlistError::InvalidXml {
                                msg: format!("unexpected </{name}> in dict"),
                            });
                        }
                        Some(XmlToken::Text(_)) => {}
                        Some(XmlToken::OpenTag { name: "key", .. }) => {
                            let key = self.collect_text_until_close("key")?;
                            let key = xml_unescape(key.trim());
                            let val = self.parse_value()?;
                            dict.insert(key, val);
                        }
                        Some(XmlToken::OpenTag { name, .. }) => {
                            return Err(PlistError::InvalidXml {
                                msg: format!("expected <key>, got <{name}>"),
                            });
                        }
                    }
                }
                Ok(PlistValue::Dict(dict))
            }
            other => Err(PlistError::InvalidXml { msg: format!("unknown tag <{other}>") }),
        }
    }

    fn expect_close(&mut self, tag: &str) -> PlistResult<()> {
        loop {
            match self.next_token()? {
                Some(XmlToken::CloseTag { name }) if name == tag => return Ok(()),
                Some(XmlToken::Text(_)) => {}
                Some(other) => {
                    return Err(PlistError::InvalidXml {
                        msg: format!("expected </{tag}>, got {other:?}"),
                    })
                }
                None => return Err(PlistError::InvalidXml { msg: format!("EOF waiting for </{tag}>") }),
            }
        }
    }

    fn collect_text_until_close(&mut self, tag: &str) -> PlistResult<String> {
        let mut out = String::new();
        loop {
            match self.next_token()? {
                Some(XmlToken::CloseTag { name }) if name == tag => return Ok(out),
                Some(XmlToken::Text(t)) => out.push_str(t),
                Some(XmlToken::CloseTag { name }) => {
                    return Err(PlistError::InvalidXml {
                        msg: format!("unexpected </{name}> collecting <{tag}>"),
                    })
                }
                Some(XmlToken::OpenTag { .. }) => {
                    return Err(PlistError::InvalidXml {
                        msg: format!("unexpected open tag collecting <{tag}>"),
                    })
                }
                None => return Err(PlistError::InvalidXml { msg: format!("EOF in <{tag}>") }),
            }
        }
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
}

/// Minimal base64 decoder (standard alphabet with '=' padding).
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 { t[(b'A' + i) as usize] = i.cast_signed(); i += 1; }
        i = 0;
        while i < 26 { t[(b'a' + i) as usize] = (i + 26).cast_signed(); i += 1; }
        i = 0;
        while i < 10 { t[(b'0' + i) as usize] = (i + 52).cast_signed(); i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' { break; }
        let v = TABLE[b as usize];
        if v < 0 { return Err(format!("invalid base64 char {b:#x}")); }
        buf = (buf << 6) | u32::from(v.cast_unsigned());
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buf >> bits).unwrap_or(0));
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Approximate ISO 8601 → Apple epoch (seconds since 2001-01-01).
/// We do a rough conversion; exact timezone handling is out of scope.
fn parse_iso8601_to_apple_epoch(s: &str) -> f64 {
    // Format: 2023-11-15T14:30:00Z
    let unix = parse_iso8601_to_unix(s);
    // Apple epoch = Unix - 978307200 (seconds from 1970-01-01 to 2001-01-01)
    unix - 978_307_200.0
}

fn grab(b: &[u8], start: usize, len: usize) -> i32 {
    let mut v = 0i32;
    for i in 0..len {
        let c = b.get(start + i).copied().unwrap_or(b'0');
        if c.is_ascii_digit() { v = v * 10 + i32::from(c - b'0'); }
    }
    v
}

fn parse_iso8601_to_unix(s: &str) -> f64 {
    // Very rough: extract Y M D H Min S
    let bytes = s.as_bytes();
    let year = i64::from(grab(bytes, 0, 4));
    let month = i64::from(grab(bytes, 5, 2));
    let day = i64::from(grab(bytes, 8, 2));
    let hour = grab(bytes, 11, 2);
    let min = grab(bytes, 14, 2);
    let sec = grab(bytes, 17, 2);

    // Days from 1970-01-01 using civil calendar
    let days = days_from_civil(year, month, day);
    f64::from(i32::try_from(days).unwrap_or(i32::MAX)).mul_add(86400.0, f64::from(hour * 3600 + min * 60 + sec))
}

const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ── PlistValue query helpers ──────────────────────────────────────────────────

/// Walk a dot-separated key path through nested dicts/arrays.
/// Array indices are written as decimal numbers: "items.0.name"
#[must_use] 
pub fn plist_path<'a>(root: &'a PlistValue, path: &str) -> Option<&'a PlistValue> {
    let mut cur = root;
    for seg in path.split('.') {
        match cur {
            PlistValue::Dict(d) => {
                cur = d.get(seg)?;
            }
            PlistValue::Array(a) => {
                let idx: usize = seg.parse().ok()?;
                cur = a.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

/// Collect all string values under a given key anywhere in the tree.
#[must_use] 
pub fn plist_collect_strings(root: &PlistValue, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    collect_strings_inner(root, key, &mut out);
    out
}

fn collect_strings_inner(v: &PlistValue, key: &str, out: &mut Vec<String>) {
    match v {
        PlistValue::Dict(d) => {
            if let Some(val) = d.get(key)
                && let PlistValue::String(s) = val {
                    out.push(s.clone());
                }
            for (_, child) in d.iter() {
                collect_strings_inner(child, key, out);
            }
        }
        PlistValue::Array(a) => {
            for child in a { collect_strings_inner(child, key, out); }
        }
        _ => {}
    }
}

/// Flatten a plist dict to a map of dot-separated paths to string values.
#[must_use] 
pub fn plist_flatten(root: &PlistValue) -> HashMap<String, String> {
    let mut out = HashMap::new();
    plist_flatten_inner(root, String::new(), &mut out);
    out
}

fn plist_flatten_inner(v: &PlistValue, prefix: String, out: &mut HashMap<String, String>) {
    match v {
        PlistValue::Dict(d) => {
            for (k, child) in d.iter() {
                let path = if prefix.is_empty() { k.to_string() } else { format!("{prefix}.{k}") };
                plist_flatten_inner(child, path, out);
            }
        }
        PlistValue::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                let path = if prefix.is_empty() { i.to_string() } else { format!("{prefix}.{i}") };
                plist_flatten_inner(child, path, out);
            }
        }
        leaf => {
            out.insert(prefix, leaf.to_string());
        }
    }
}

// ── Pretty printer ────────────────────────────────────────────────────────────

pub struct PlistPrinter {
    pub indent: usize,
    pub max_data_bytes: usize,
}

impl Default for PlistPrinter {
    fn default() -> Self { Self { indent: 2, max_data_bytes: 16 } }
}

impl PlistPrinter {
    #[must_use] 
    pub fn print(&self, v: &PlistValue) -> String {
        let mut buf = String::new();
        self.print_inner(v, 0, &mut buf);
        buf
    }

    fn print_inner(&self, v: &PlistValue, depth: usize, buf: &mut String) {
        use std::fmt::Write as _;
        let pad: String = " ".repeat(depth * self.indent);
        match v {
            PlistValue::Dict(d) => {
                buf.push_str("{\n");
                for (k, val) in d.iter() {
                    buf.push_str(&pad);
                    buf.push_str(&" ".repeat(self.indent));
                    write!(buf, "{k:?}: ").ok();
                    self.print_inner(val, depth + 1, buf);
                    buf.push('\n');
                }
                buf.push_str(&pad);
                buf.push('}');
            }
            PlistValue::Array(a) => {
                buf.push_str("[\n");
                for item in a {
                    buf.push_str(&pad);
                    buf.push_str(&" ".repeat(self.indent));
                    self.print_inner(item, depth + 1, buf);
                    buf.push('\n');
                }
                buf.push_str(&pad);
                buf.push(']');
            }
            PlistValue::Data(d) => {
                let show = d.len().min(self.max_data_bytes);
                let hex: String = d[..show].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                if d.len() > show {
                    write!(buf, "<{hex} ... ({} bytes)>", d.len()).ok();
                } else {
                    write!(buf, "<{hex}>").ok();
                }
            }
            PlistValue::String(s) => write!(buf, "{s:?}").ok().unwrap_or(()),
            other => buf.push_str(&other.to_string()),
        }
    }
}

// ── Serialise back to XML plist ───────────────────────────────────────────────

#[must_use] 
pub fn to_xml_plist(v: &PlistValue) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n",
    );
    encode_xml_value(v, 0, &mut out);
    out.push_str("</plist>\n");
    out
}

fn encode_xml_value(v: &PlistValue, depth: usize, out: &mut String) {
    use std::fmt::Write as _;
    let pad: String = "\t".repeat(depth);
    match v {
        PlistValue::Boolean(true) => { writeln!(out, "{pad}<true/>").ok(); }
        PlistValue::Boolean(false) => { writeln!(out, "{pad}<false/>").ok(); }
        PlistValue::Integer(n) => { writeln!(out, "{pad}<integer>{n}</integer>").ok(); }
        PlistValue::Real(f) => { writeln!(out, "{pad}<real>{f}</real>").ok(); }
        PlistValue::Date(ts) => {
            let unix = ts + 978_307_200.0;
            writeln!(out, "{pad}<date>{unix:.0}</date>").ok();
        }
        PlistValue::Data(d) => {
            let b64 = base64_encode(d);
            writeln!(out, "{pad}<data>{b64}</data>").ok();
        }
        PlistValue::String(s) => {
            let esc = s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            writeln!(out, "{pad}<string>{esc}</string>").ok();
        }
        PlistValue::Uid(u) => {
            writeln!(out, "{pad}<dict>\n{pad}\t<key>CF$UID</key>\n{pad}\t<integer>{u}</integer>\n{pad}</dict>").ok();
        }
        PlistValue::Array(a) => {
            writeln!(out, "{pad}<array>").ok();
            for item in a { encode_xml_value(item, depth + 1, out); }
            writeln!(out, "{pad}</array>").ok();
        }
        PlistValue::Dict(d) => {
            writeln!(out, "{pad}<dict>").ok();
            for (k, val) in d.iter() {
                let esc_k = k.replace('&', "&amp;").replace('<', "&lt;");
                writeln!(out, "{pad}\t<key>{esc_k}</key>").ok();
                encode_xml_value(val, depth + 1, out);
            }
            writeln!(out, "{pad}</dict>").ok();
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[(n >> 18) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 { out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char); } else { out.push('='); }
        if chunk.len() > 2 { out.push(ALPHA[(n & 0x3f) as usize] as char); } else { out.push('='); }
    }
    out
}

// ── Typed plist key access helpers ───────────────────────────────────────────

/// Typed read helpers that propagate errors cleanly.
pub struct PlistReader<'a>(pub &'a PlistValue);

impl PlistReader<'_> {
    pub fn get(&self, key: &str) -> Option<PlistReader<'_>> {
        self.0.dict_get(key).map(PlistReader)
    }
    #[must_use] 
    pub fn string(&self) -> Option<&str> { self.0.as_str() }
    #[must_use] 
    pub const fn integer(&self) -> Option<i64> { self.0.as_i64() }
    #[must_use] 
    pub const fn bool_val(&self) -> Option<bool> { self.0.as_bool() }
    #[must_use] 
    pub fn array_len(&self) -> Option<usize> {
        self.0.as_array().map(<[PlistValue]>::len)
    }
    pub fn array_item(&self, idx: usize) -> Option<PlistReader<'_>> {
        self.0.as_array().and_then(|a| a.get(idx)).map(PlistReader)
    }
    #[must_use] 
    pub const fn inner(&self) -> &PlistValue { self.0 }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_simple_dict() {
        let xml = br#"<?xml version="1.0"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.example.app</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>UIRequiresFullScreen</key><true/>
  <key>MinimumOSVersion</key><string>14.0</string>
</dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        assert_eq!(v.dict_get("CFBundleIdentifier").and_then(|v| v.as_str()), Some("com.example.app"));
        assert_eq!(v.dict_get("UIRequiresFullScreen").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_xml_array() {
        let xml = br#"<plist version="1.0">
<array>
  <string>hello</string>
  <integer>42</integer>
  <real>3.14</real>
</array>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[1].as_i64(), Some(42));
    }

    #[test]
    fn test_xml_nested() {
        let xml = br#"<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key><true/>
  </dict>
</dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let inner = v.dict_get("NSAppTransportSecurity").unwrap();
        assert_eq!(inner.dict_get("NSAllowsArbitraryLoads").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_plist_path() {
        let xml = br#"<plist version="1.0">
<dict>
  <key>a</key><dict><key>b</key><string>found</string></dict>
</dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let r = plist_path(&v, "a.b").unwrap();
        assert_eq!(r.as_str(), Some("found"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World! This is a test.";
        let enc = base64_encode(data);
        let dec = base64_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_xml_data() {
        let xml = br#"<plist version="1.0">
<dict><key>raw</key><data>SGVsbG8=</data></dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let d = v.dict_get("raw").unwrap().as_data().unwrap();
        assert_eq!(d, b"Hello");
    }

    #[test]
    fn test_plist_flatten() {
        let xml = br#"<plist version="1.0">
<dict><key>x</key><string>1</string><key>y</key><string>2</string></dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let flat = plist_flatten(&v);
        assert_eq!(flat.get("x").map(|s| s.as_str()), Some("1"));
    }

    #[test]
    fn test_xml_roundtrip() {
        let xml = br#"<plist version="1.0">
<dict><key>name</key><string>Test &amp; Demo</string></dict>
</plist>"#;
        let v = PlistParser::parse(xml).unwrap();
        let out = to_xml_plist(&v);
        let v2 = PlistParser::parse(out.as_bytes()).unwrap();
        assert_eq!(v2.dict_get("name").and_then(|v| v.as_str()), Some("Test & Demo"));
    }
}
