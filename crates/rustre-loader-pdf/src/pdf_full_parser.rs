use std::collections::HashMap;
use std::io::{Read, BufRead};
use anyhow::{Result, bail, Context};
use serde::{Serialize, Deserialize};

/// Read all bytes from a generic `Read` implementer and parse them as a PDF
/// document. Convenience adapter around [`PdfParser::parse_bytes`].
pub fn parse_pdf_from_reader<R: Read>(mut reader: R) -> Result<PdfDocument> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).context("reading PDF stream")?;
    PdfDocument::parse(buf)
}

/// Read a PDF document line-by-line from a [`BufRead`] source, concatenating
/// lines back together before parsing. Useful for sources that yield text
/// lines (e.g. piped tools) rather than raw bytes.
pub fn parse_pdf_from_buf_reader<R: BufRead>(mut reader: R) -> Result<PdfDocument> {
    let mut buf = Vec::new();
    loop {
        let consumed = {
            let chunk = reader.fill_buf().context("reading PDF chunk")?;
            if chunk.is_empty() {
                break;
            }
            buf.extend_from_slice(chunk);
            chunk.len()
        };
        reader.consume(consumed);
    }
    PdfDocument::parse(buf)
}

// ── PDF object model ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PdfObject {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    String(PdfString),
    Name(String),
    Array(Vec<PdfObject>),
    Dictionary(PdfDictionary),
    Stream(PdfStream),
    Reference(u32, u16),  // obj, gen
}

#[derive(Debug, Clone, PartialEq)]
pub struct PdfString {
    pub bytes: Vec<u8>,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StringEncoding {
    Literal,
    Hex,
}

impl PdfString {
    #[must_use]
    pub fn as_text(&self) -> String {
        if self.bytes.starts_with(&[0xFE, 0xFF]) {
            // UTF-16 BE
            let words: Vec<u16> = self.bytes[2..].chunks(2)
                .map(|c| if c.len() == 2 { (u16::from(c[0]) << 8) | u16::from(c[1]) } else { 0 })
                .collect();
            String::from_utf16_lossy(&words).to_string()
        } else {
            String::from_utf8_lossy(&self.bytes).to_string()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdfDictionary(pub HashMap<String, PdfObject>);

impl PdfDictionary {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&PdfObject> { self.0.get(key) }
    #[must_use]
    pub fn get_name(&self, key: &str) -> Option<&str> {
        match self.0.get(key) {
            Some(PdfObject::Name(n)) => Some(n.as_str()),
            _ => None,
        }
    }
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.0.get(key) {
            Some(PdfObject::Integer(n)) => Some(*n),
            _ => None,
        }
    }
    #[must_use]
    pub fn get_array(&self, key: &str) -> Option<&[PdfObject]> {
        match self.0.get(key) {
            Some(PdfObject::Array(a)) => Some(a),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PdfStream {
    pub dict: PdfDictionary,
    pub raw_data: Vec<u8>,
    pub decoded_data: Option<Vec<u8>>,
}

// ── Cross-reference table ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct XRefEntry {
    pub offset: u64,
    pub gen_val: u16,
    pub in_use: bool,
    pub compressed: bool,
    pub stream_obj: Option<u32>,
    pub index_in_stream: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct XRefTable {
    pub entries: HashMap<u32, XRefEntry>,
    pub trailer: PdfDictionary,
}

impl XRefTable {
    #[must_use]
    pub fn root_ref(&self) -> Option<(u32, u16)> {
        match self.trailer.get("Root") {
            Some(PdfObject::Reference(n, g)) => Some((*n, *g)),
            _ => None,
        }
    }
    #[must_use]
    pub fn info_ref(&self) -> Option<(u32, u16)> {
        match self.trailer.get("Info") {
            Some(PdfObject::Reference(n, g)) => Some((*n, *g)),
            _ => None,
        }
    }
    #[must_use]
    pub fn encrypt_ref(&self) -> Option<(u32, u16)> {
        match self.trailer.get("Encrypt") {
            Some(PdfObject::Reference(n, g)) => Some((*n, *g)),
            _ => None,
        }
    }
}

// ── Document structure ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfDocumentInfo {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub mod_date: Option<String>,
    pub trapped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfPage {
    pub number: u32,
    pub obj_id: u32,
    pub media_box: Option<[f64; 4]>,
    pub crop_box: Option<[f64; 4]>,
    pub rotation: Option<i32>,
    pub resources: PdfPageResources,
    pub content_stream_ids: Vec<u32>,
    pub annotations: Vec<PdfAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfPageResources {
    pub fonts: HashMap<String, u32>,
    pub xobjects: HashMap<String, u32>,
    pub color_spaces: Vec<String>,
    pub patterns: Vec<String>,
    pub shadings: Vec<String>,
    pub ext_g_states: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfAnnotation {
    pub obj_id: u32,
    pub subtype: String,
    pub rect: Option<[f64; 4]>,
    pub action: Option<PdfAction>,
    pub uri: Option<String>,
    pub contents: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfAction {
    pub action_type: String,
    pub uri: Option<String>,
    pub javascript: Option<String>,
    pub destination: Option<String>,
    pub file: Option<String>,
}

// ── Full parser ───────────────────────────────────────────────────────────────

pub struct PdfParser {
    data: Vec<u8>,
    pos: usize,
}

impl PdfParser {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("Cannot read PDF: {}", path.display()))?;
        Ok(Self::new(data))
    }

    fn peek(&self) -> Option<u8> { self.data.get(self.pos).copied() }
    const fn advance(&mut self) { if self.pos < self.data.len() { self.pos += 1; } }
    fn current(&self) -> Option<u8> { self.data.get(self.pos).copied() }

    /// Current cursor position within the raw PDF byte buffer.
    #[must_use]
    pub const fn position(&self) -> usize { self.pos }

    /// Byte at the current cursor position, or `None` at end of input.
    /// Public wrapper around the internal `current()` accessor.
    #[must_use]
    pub fn current_byte(&self) -> Option<u8> { self.current() }

    /// Parse `bytes` as a PDF document. Equivalent to
    /// `PdfDocument::parse(bytes.to_vec())` but accepts a borrowed slice.
    pub fn parse_bytes(bytes: &[u8]) -> Result<PdfDocument> {
        PdfDocument::parse(bytes.to_vec())
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b'%' {
                while self.peek().map(|c| c != b'\n' && c != b'\r').unwrap_or(false) {
                    self.advance();
                }
            } else if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn read_until_whitespace(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x00) { break; }
            if matches!(b, b'/' | b'(' | b')' | b'[' | b']' | b'<' | b'>' | b'{' | b'}') { break; }
            out.push(b);
            self.advance();
        }
        out
    }

    #[must_use]
    pub fn check_magic(&self) -> bool {
        self.data.starts_with(b"%PDF-")
    }

    #[must_use]
    pub fn get_version(&self) -> Option<String> {
        if !self.check_magic() { return None; }
        let end = self.data[5..].iter().position(|&b| b == b'\n' || b == b'\r')
            .map(|i| i + 5)
            .unwrap_or(9.min(self.data.len()));
        String::from_utf8(self.data[5..end].to_vec()).ok()
    }

    pub fn find_xref_offset(&self) -> Result<u64> {
        // Scan backwards from end looking for "startxref"
        let marker = b"startxref";
        let search_from = self.data.len().saturating_sub(1024);
        let slice = &self.data[search_from..];
        for i in (0..slice.len().saturating_sub(marker.len())).rev() {
            if &slice[i..i + marker.len()] == marker {
                let after = &slice[i + marker.len()..];
                let after_str = String::from_utf8_lossy(after);
                for line in after_str.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && trimmed != "%%EOF" {
                        if let Ok(offset) = trimmed.parse::<u64>() {
                            return Ok(offset);
                        }
                    }
                }
            }
        }
        bail!("Cannot find startxref marker")
    }

    pub fn parse_xref_at(&mut self, offset: u64) -> Result<XRefTable> {
        let offset_usize = usize::try_from(offset)
            .ok()
            .filter(|&o| o < self.data.len())
            .context("xref offset out of range")?;
        self.pos = offset_usize;
        self.skip_whitespace();
        let mut table = XRefTable::default();

        if self.data[self.pos..].starts_with(b"xref") {
            self.pos += 4;
            self.parse_traditional_xref(&mut table)?;
        } else {
            self.parse_xref_stream(&mut table)?;
        }
        Ok(table)
    }

    fn parse_traditional_xref(&mut self, table: &mut XRefTable) -> Result<()> {
        self.skip_whitespace();
        while self.pos < self.data.len() {
            // Check for "trailer"
            if self.data[self.pos..].starts_with(b"trailer") {
                self.pos += 7;
                self.skip_whitespace();
                let dict = self.parse_dictionary()?;
                table.trailer = dict;
                break;
            }
            // Parse subsection header: start count
            let start_bytes = self.read_until_whitespace();
            self.skip_whitespace();
            let count_bytes = self.read_until_whitespace();
            self.skip_whitespace();

            let start: u32 = String::from_utf8_lossy(&start_bytes).parse()
                .context("XRef subsection start")?;
            let count: u32 = String::from_utf8_lossy(&count_bytes).parse()
                .context("XRef subsection count")?;

            for i in 0..count {
                if self.pos + 20 > self.data.len() { break; }
                let entry_str = &self.data[self.pos..self.pos + 20];
                self.pos += 20;
                // Format: "oooooooooo ggggg n/f \n"
                let offset = u64::from_str_radix(
                    std::str::from_utf8(&entry_str[0..10]).unwrap_or("0").trim(), 10
                ).unwrap_or(0);
                let gen_val = u16::from_str_radix(
                    std::str::from_utf8(&entry_str[11..16]).unwrap_or("0").trim(), 10
                ).unwrap_or(0);
                let in_use = entry_str.get(17).copied() == Some(b'n');
                table.entries.insert(start + i, XRefEntry {
                    offset, gen_val, in_use,
                    compressed: false, stream_obj: None, index_in_stream: None,
                });
            }
        }
        Ok(())
    }

    fn parse_xref_stream(&mut self, table: &mut XRefTable) -> Result<()> {
        // XRef stream is a PDF object: N G obj << ... >> stream ... endstream
        // For now, parse the header dict and raw data
        let obj = self.parse_object()?;
        if let PdfObject::Stream(ref s) = obj {
            table.trailer = s.dict.clone();
            // Decode W field to interpret entries
            let w: Vec<i64> = s.dict.get_array("W")
                .map(|arr| arr.iter().filter_map(|o| if let PdfObject::Integer(n) = o { Some(*n) } else { None }).collect())
                .unwrap_or_default();
            if w.len() == 3 {
                let (w0, w1, w2) = (w[0] as usize, w[1] as usize, w[2] as usize);
                let entry_size = w0 + w1 + w2;
                let data = s.decoded_data.as_deref().unwrap_or(&s.raw_data);
                let index: Vec<i64> = s.dict.get_array("Index")
                    .map(|arr| arr.iter().filter_map(|o| if let PdfObject::Integer(n) = o { Some(*n) } else { None }).collect())
                    .unwrap_or_else(|| {
                        let size = s.dict.get_int("Size").unwrap_or(0);
                        vec![0, size]
                    });
                let mut offset = 0;
                let mut idx_pos = 0;
                while idx_pos + 1 < index.len() {
                    let start = index[idx_pos] as u32;
                    let count = index[idx_pos + 1] as u32;
                    idx_pos += 2;
                    for i in 0..count {
                        if offset + entry_size > data.len() { break; }
                        let t = read_be_uint(&data[offset..offset + w0], w0);
                        let f1 = read_be_uint(&data[offset + w0..offset + w0 + w1], w1);
                        let f2 = read_be_uint(&data[offset + w0 + w1..offset + w0 + w1 + w2], w2);
                        offset += entry_size;
                        table.entries.insert(start + i, match t {
                            0 => XRefEntry { offset: 0, gen_val: f2 as u16, in_use: false, compressed: false, stream_obj: None, index_in_stream: None },
                            1 => XRefEntry { offset: f1, gen_val: f2 as u16, in_use: true, compressed: false, stream_obj: None, index_in_stream: None },
                            2 => XRefEntry { offset: 0, gen_val: 0, in_use: true, compressed: true, stream_obj: Some(f1 as u32), index_in_stream: Some(f2 as u32) },
                            _ => continue,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn parse_object(&mut self) -> Result<PdfObject> {
        self.skip_whitespace();
        match self.peek() {
            Some(b't') if self.data[self.pos..].starts_with(b"true") => {
                self.pos += 4; Ok(PdfObject::Boolean(true))
            }
            Some(b'f') if self.data[self.pos..].starts_with(b"false") => {
                self.pos += 5; Ok(PdfObject::Boolean(false))
            }
            Some(b'n') if self.data[self.pos..].starts_with(b"null") => {
                self.pos += 4; Ok(PdfObject::Null)
            }
            Some(b'/') => { self.advance(); Ok(PdfObject::Name(self.parse_name()?)) }
            Some(b'(') => { self.advance(); Ok(PdfObject::String(self.parse_literal_string()?)) }
            Some(b'<') if self.data.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                let dict = self.parse_dictionary()?;
                self.skip_whitespace();
                if self.data[self.pos..].starts_with(b"stream") {
                    Ok(PdfObject::Stream(self.parse_stream(dict)?))
                } else {
                    Ok(PdfObject::Dictionary(dict))
                }
            }
            Some(b'<') => { self.advance(); Ok(PdfObject::String(self.parse_hex_string()?)) }
            Some(b'[') => { self.advance(); Ok(PdfObject::Array(self.parse_array()?)) }
            Some(b'+') | Some(b'-') | Some(b'0'..=b'9') | Some(b'.') => {
                self.parse_number()
            }
            Some(b) => bail!("Unexpected byte in object: {:#02x} at pos {}", b, self.pos),
            None => bail!("Unexpected end of file"),
        }
    }

    fn parse_name(&mut self) -> Result<String> {
        let mut name = Vec::new();
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'(' | b')' |
                        b'[' | b']' | b'<' | b'>' | b'{' | b'}' | b'%' | 0x00) {
                break;
            }
            if b == b'#' && self.pos + 2 < self.data.len() {
                let h = &self.data[self.pos + 1..self.pos + 3];
                if let Ok(s) = std::str::from_utf8(h) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        name.push(byte);
                        self.pos += 3;
                        continue;
                    }
                }
            }
            name.push(b);
            self.advance();
        }
        Ok(String::from_utf8_lossy(&name).to_string())
    }

    fn parse_literal_string(&mut self) -> Result<PdfString> {
        let mut bytes = Vec::new();
        let mut depth = 1i32;
        while self.pos < self.data.len() {
            let b = self.data[self.pos]; self.pos += 1;
            match b {
                b'(' => { depth += 1; bytes.push(b); }
                b')' => {
                    depth -= 1;
                    if depth == 0 { break; }
                    bytes.push(b);
                }
                b'\\' if self.pos < self.data.len() => {
                    let esc = self.data[self.pos]; self.pos += 1;
                    match esc {
                        b'n' => bytes.push(b'\n'),
                        b'r' => bytes.push(b'\r'),
                        b't' => bytes.push(b'\t'),
                        b'b' => bytes.push(0x08),
                        b'f' => bytes.push(0x0C),
                        b'(' => bytes.push(b'('),
                        b')' => bytes.push(b')'),
                        b'\\' => bytes.push(b'\\'),
                        b'\n' | b'\r' => {} // line continuation
                        b'0'..=b'7' => {
                            let mut oct = u32::from(esc - b'0');
                            for _ in 0..2 {
                                if matches!(self.peek(), Some(b'0'..=b'7')) {
                                    oct = oct * 8 + u32::from(self.data[self.pos] - b'0');
                                    self.pos += 1;
                                } else { break; }
                            }
                            bytes.push(oct as u8);
                        }
                        _ => { bytes.push(b'\\'); bytes.push(esc); }
                    }
                }
                _ => bytes.push(b),
            }
        }
        Ok(PdfString { bytes, encoding: StringEncoding::Literal })
    }

    fn parse_hex_string(&mut self) -> Result<PdfString> {
        let mut bytes = Vec::new();
        let mut nibble: Option<u8> = None;
        while let Some(b) = self.peek() {
            self.advance();
            if b == b'>' { break; }
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') { continue; }
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => continue,
            };
            if let Some(high) = nibble.take() {
                bytes.push((high << 4) | digit);
            } else {
                nibble = Some(digit);
            }
        }
        if let Some(high) = nibble { bytes.push(high << 4); }
        Ok(PdfString { bytes, encoding: StringEncoding::Hex })
    }

    fn parse_array(&mut self) -> Result<Vec<PdfObject>> {
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b']') { self.advance(); break; }
            if self.pos >= self.data.len() { bail!("Unclosed array"); }
            items.push(self.parse_object()?);
        }
        Ok(items)
    }

    fn parse_dictionary(&mut self) -> Result<PdfDictionary> {
        let mut map = HashMap::new();
        loop {
            self.skip_whitespace();
            if self.data[self.pos..].starts_with(b">>") { self.pos += 2; break; }
            if self.pos >= self.data.len() { bail!("Unclosed dictionary"); }
            if self.peek() != Some(b'/') { bail!("Expected name key in dict at pos {}", self.pos); }
            self.advance();
            let key = self.parse_name()?;
            self.skip_whitespace();
            let val = self.parse_object()?;
            map.insert(key, val);
        }
        Ok(PdfDictionary(map))
    }

    fn parse_stream(&mut self, dict: PdfDictionary) -> Result<PdfStream> {
        // Skip "stream" keyword and CRLF/LF
        self.pos += 6; // "stream"
        if self.peek() == Some(b'\r') { self.advance(); }
        if self.peek() == Some(b'\n') { self.advance(); }

        let length = dict.get_int("Length").unwrap_or(0) as usize;
        let raw_data = if self.pos + length <= self.data.len() {
            self.data[self.pos..self.pos + length].to_vec()
        } else {
            // Fallback: scan for "endstream"
            let marker = b"endstream";
            let slice = &self.data[self.pos..];
            let end = slice.windows(marker.len()).position(|w| w == marker).unwrap_or(slice.len());
            slice[..end].to_vec()
        };
        self.pos += raw_data.len();
        // Skip "endstream"
        self.skip_whitespace();
        if self.data[self.pos..].starts_with(b"endstream") { self.pos += 9; }

        let decoded_data = decode_stream(&raw_data, &dict).ok();
        Ok(PdfStream { dict, raw_data, decoded_data })
    }

    fn parse_number(&mut self) -> Result<PdfObject> {
        let start = self.pos;
        let mut is_real = false;
        if matches!(self.peek(), Some(b'+') | Some(b'-')) { self.advance(); }
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        if self.peek() == Some(b'.') { is_real = true; self.advance(); }
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }

        let s = std::str::from_utf8(&self.data[start..self.pos]).unwrap_or("0").to_string();

        // Check for reference: "N G R"
        let saved_pos = self.pos;
        self.skip_whitespace();
        let gen_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        if self.pos > gen_start {
            let saved2 = self.pos;
            self.skip_whitespace();
            if self.peek() == Some(b'R') {
                self.advance();
                let n: u32 = s.parse().unwrap_or(0);
                let g: u16 = std::str::from_utf8(&self.data[gen_start..saved2]).unwrap_or("0")
                    .trim().parse().unwrap_or(0);
                return Ok(PdfObject::Reference(n, g));
            }
            self.pos = saved_pos;
        } else {
            self.pos = saved_pos;
        }

        if is_real {
            Ok(PdfObject::Real(s.parse::<f64>().unwrap_or(0.0)))
        } else {
            Ok(PdfObject::Integer(s.parse::<i64>().unwrap_or(0)))
        }
    }

    pub fn parse_indirect_object_at(&mut self, offset: u64) -> Result<(u32, u16, PdfObject)> {
        self.pos = usize::try_from(offset)
            .ok()
            .filter(|&o| o < self.data.len())
            .context("object offset out of range")?;
        self.skip_whitespace();
        let n_bytes = self.read_until_whitespace();
        self.skip_whitespace();
        let g_bytes = self.read_until_whitespace();
        self.skip_whitespace();
        // Expect "obj"
        if !self.data[self.pos..].starts_with(b"obj") { bail!("Expected 'obj' keyword"); }
        self.pos += 3;
        self.skip_whitespace();
        let obj = self.parse_object()?;
        self.skip_whitespace();
        if self.data[self.pos..].starts_with(b"endobj") { self.pos += 6; }
        let n: u32 = String::from_utf8_lossy(&n_bytes).parse().unwrap_or(0);
        let g: u16 = String::from_utf8_lossy(&g_bytes).parse().unwrap_or(0);
        Ok((n, g, obj))
    }
}

fn read_be_uint(bytes: &[u8], width: usize) -> u64 {
    let mut result = 0u64;
    for i in 0..width.min(bytes.len()) {
        result = (result << 8) | u64::from(bytes[i]);
    }
    result
}

fn decode_stream(data: &[u8], dict: &PdfDictionary) -> Result<Vec<u8>> {
    let filter = dict.get("Filter");
    match filter {
        None => Ok(data.to_vec()),
        Some(PdfObject::Name(name)) => apply_filter(data, name),
        Some(PdfObject::Array(filters)) => {
            let mut current = data.to_vec();
            for f in filters {
                if let PdfObject::Name(name) = f {
                    current = apply_filter(&current, name)?;
                }
            }
            Ok(current)
        }
        _ => Ok(data.to_vec()),
    }
}

fn apply_filter(data: &[u8], filter: &str) -> Result<Vec<u8>> {
    match filter {
        "FlateDecode" | "Fl" => {
            use std::io::Read;
            // Limit decompressed output to prevent zip-bomb DoS.
            const FLATE_MAX: u64 = 256 * 1024 * 1024; // 256 MiB
            let decoder = flate2::read::ZlibDecoder::new(data);
            let mut out = Vec::new();
            decoder.take(FLATE_MAX + 1).read_to_end(&mut out)?;
            if out.len() > FLATE_MAX as usize {
                bail!("FlateDecode output exceeds size limit (possible bomb)");
            }
            Ok(out)
        }
        "ASCIIHexDecode" | "AHx" => {
            let mut bytes = Vec::new();
            let mut nibble: Option<u8> = None;
            for &b in data {
                if b == b'>' { break; }
                if matches!(b, b' ' | b'\t' | b'\n' | b'\r') { continue; }
                let d = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => bail!("Invalid hex digit in ASCIIHexDecode"),
                };
                if let Some(h) = nibble.take() { bytes.push((h << 4) | d); }
                else { nibble = Some(d); }
            }
            if let Some(h) = nibble { bytes.push(h << 4); }
            Ok(bytes)
        }
        "ASCII85Decode" | "A85" => decode_ascii85(data),
        "RunLengthDecode" | "RL" => decode_rle(data),
        _ => {
            // Unknown filter — return raw
            Ok(data.to_vec())
        }
    }
}

fn decode_ascii85(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u32; 5];
    let mut count = 0;
    for &b in data {
        match b {
            b'~' => break,
            b'z' if count == 0 => { out.extend_from_slice(&[0u8; 4]); }
            b'!'..=b'u' => {
                buf[count] = u32::from(b - b'!');
                count += 1;
                if count == 5 {
                    let v = buf[0]*85u32.pow(4) + buf[1]*85u32.pow(3) + buf[2]*85*85 + buf[3]*85 + buf[4];
                    out.extend_from_slice(&v.to_be_bytes());
                    count = 0;
                }
            }
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => {}
        }
    }
    if count > 0 {
        for i in count..5 { buf[i] = 84; }
        let v = buf[0]*85u32.pow(4) + buf[1]*85u32.pow(3) + buf[2]*85*85 + buf[3]*85 + buf[4];
        let bytes = v.to_be_bytes();
        out.extend_from_slice(&bytes[..count - 1]);
    }
    Ok(out)
}

fn decode_rle(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let run = i32::from(data[i]);
        i += 1;
        if run == 128 { break; }
        if run >= 0 {
            let count = (run + 1) as usize;
            if i + count <= data.len() {
                out.extend_from_slice(&data[i..i + count]);
                i += count;
            }
        } else {
            let count = (-run + 1) as usize;
            if i < data.len() {
                let byte = data[i];
                i += 1;
                for _ in 0..count { out.push(byte); }
            }
        }
    }
    Ok(out)
}

pub struct PdfDocument {
    pub version: String,
    pub xref: XRefTable,
    pub info: Option<PdfDocumentInfo>,
    pub pages: Vec<PdfPage>,
    pub is_encrypted: bool,
    pub is_linearized: bool,
    pub object_count: usize,
    pub stream_count: usize,
    pub javascript_streams: Vec<u32>,
    pub embedded_files: Vec<EmbeddedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFile {
    pub obj_id: u32,
    pub name: String,
    pub size: u64,
    pub mime_type: Option<String>,
    pub data: Vec<u8>,
}

impl PdfDocument {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let mut parser = PdfParser::new(data);
        if !parser.check_magic() { bail!("Not a PDF file"); }
        let version = parser.get_version().unwrap_or_else(|| "unknown".to_string());
        let xref_offset = parser.find_xref_offset()?;
        let xref = parser.parse_xref_at(xref_offset)?;
        let is_encrypted = xref.encrypt_ref().is_some();
        let object_count = xref.entries.len();

        // Count streams (rough heuristic from xref)
        let stream_count = 0; // would need to load all objects

        Ok(PdfDocument {
            version,
            is_encrypted,
            is_linearized: false,
            object_count,
            stream_count,
            xref,
            info: None,
            pages: Vec::new(),
            javascript_streams: Vec::new(),
            embedded_files: Vec::new(),
        })
    }
}
