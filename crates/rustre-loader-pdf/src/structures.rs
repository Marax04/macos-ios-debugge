//! High-level PDF structural types extracted from raw document bytes.
//!
//! Provides typed representations of catalogs, page trees, info dictionaries,
//! encryption dictionaries, and stream objects.

use super::{PdfDocument, PdfVersion};

// ── PdfCatalog ────────────────────────────────────────────────────────────────

/// Parsed document catalog.
#[derive(Debug, Clone, Default)]
pub struct PdfCatalog {
    /// PDF version override declared in the catalog (if any).
    pub version: Option<PdfVersion>,
    /// Object number of the page tree root.
    pub pages_ref: Option<u32>,
    /// Object number of the document outline (bookmarks).
    pub outlines_ref: Option<u32>,
    /// Object number of the XMP metadata stream.
    pub metadata_ref: Option<u32>,
    /// Whether an AcroForm dictionary is present.
    pub acroform: bool,
    /// Count of JavaScript action dictionaries found.
    pub javascript_count: usize,
    /// Whether an /OpenAction is present in the catalog.
    pub openaction: bool,
}

// ── PdfInfo ───────────────────────────────────────────────────────────────────

/// Document information dictionary.
#[derive(Debug, Clone, Default)]
pub struct PdfInfo {
    /// Document title.
    pub title: Option<String>,
    /// Author.
    pub author: Option<String>,
    /// Subject.
    pub subject: Option<String>,
    /// Creator application.
    pub creator: Option<String>,
    /// Producer application.
    pub producer: Option<String>,
    /// Creation date string.
    pub creation_date: Option<String>,
    /// Modification date string.
    pub mod_date: Option<String>,
    /// Keywords.
    pub keywords: Option<String>,
}

// ── PdfPage ───────────────────────────────────────────────────────────────────

/// A single page parsed from the document.
#[derive(Debug, Clone)]
pub struct PdfPage {
    /// Object number of this page dictionary.
    pub obj_num: u32,
    /// Media box: `[llx lly urx ury]`.
    pub mediabox: Option<[f64; 4]>,
    /// Rotation in degrees (0, 90, 180, 270).
    pub rotation: i32,
    /// Object numbers of associated content streams.
    pub contents_refs: Vec<u32>,
}

// ── PdfPageTree ───────────────────────────────────────────────────────────────

/// Flattened page tree.
#[derive(Debug, Clone, Default)]
pub struct PdfPageTree {
    /// Total page count declared in the tree.
    pub count: u32,
    /// Individual parsed pages.
    pub pages: Vec<PdfPage>,
}

// ── PdfEncrypt ────────────────────────────────────────────────────────────────

/// Encryption dictionary.
#[derive(Debug, Clone)]
pub struct PdfEncrypt {
    /// Security handler name (e.g. `"Standard"`).
    pub filter: String,
    /// Encryption version.
    pub version: i64,
    /// Revision of the standard security handler.
    pub revision: i64,
    /// Key length in bits.
    pub key_length: i64,
    /// Permission flags bit field.
    pub permissions: i64,
}

impl Default for PdfEncrypt {
    fn default() -> Self {
        Self {
            filter: String::new(),
            version: 0,
            revision: 0,
            key_length: 40,
            permissions: -1,
        }
    }
}

// ── PdfStream ─────────────────────────────────────────────────────────────────

/// A PDF stream object with its dictionary and byte range in the file.
#[derive(Debug, Clone)]
pub struct PdfStream {
    /// Object number.
    pub obj_num: u32,
    /// Dictionary entries (key, value) as raw strings.
    pub dict_entries: Vec<(String, String)>,
    /// Byte offset of the raw stream data within the file.
    pub data_offset: usize,
    /// Byte length of the raw stream data.
    pub data_length: usize,
    /// Filter pipeline names in order (e.g. `["FlateDecode"]`).
    pub filters: Vec<String>,
}

// ── Extraction functions ──────────────────────────────────────────────────────

/// Extract a `PdfCatalog` by scanning the raw bytes of `doc` for catalog markers.
#[must_use]
pub fn extract_catalog(doc: &PdfDocument) -> PdfCatalog {
    let data = &doc.raw;
    let mut cat = PdfCatalog::default();

    // /Pages ref
    if let Some(pos) = find_bytes(data, b"/Pages") && let Some(n) = parse_ref_after(data, pos + 6) {
        cat.pages_ref = Some(n);
    }

    // /Outlines ref
    if let Some(pos) = find_bytes(data, b"/Outlines") && let Some(n) = parse_ref_after(data, pos + 9) {
        cat.outlines_ref = Some(n);
    }

    // /Metadata ref
    if let Some(pos) = find_bytes(data, b"/Metadata") && let Some(n) = parse_ref_after(data, pos + 9) {
        cat.metadata_ref = Some(n);
    }

    // /AcroForm
    cat.acroform = data.windows(9).any(|w| w == b"/AcroForm");

    // /JavaScript count
    cat.javascript_count = data.windows(11).filter(|w| *w == b"/JavaScript").count();

    // /OpenAction
    cat.openaction = data.windows(11).any(|w| w == b"/OpenAction");

    // /Version in catalog
    if let Some(pos) = find_bytes(data, b"/Version") {
        let rest = &data[pos + 8..];
        // skip whitespace then '/'
        let mut i = 0;
        while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
            i += 1;
        }
        if i < rest.len() && rest[i] == b'/' {
            i += 1;
            let start = i;
            while i < rest.len() && (rest[i].is_ascii_digit() || rest[i] == b'.') {
                i += 1;
            }
            if let Ok(vs) = std::str::from_utf8(&rest[start..i]) && let Some(dot) = vs.find('.') {
                let major = vs[..dot].parse::<u8>().unwrap_or(1);
                let minor = vs[dot + 1..].parse::<u8>().unwrap_or(0);
                cat.version = Some(PdfVersion { major, minor });
            }
        }
    }

    cat
}

/// Extract a `PdfInfo` by scanning the raw bytes of `doc` for /Info markers.
#[must_use]
pub fn extract_info(doc: &PdfDocument) -> PdfInfo {
    let data = &doc.raw;

    PdfInfo {
        title: extract_string_key(data, b"/Title"),
        author: extract_string_key(data, b"/Author"),
        subject: extract_string_key(data, b"/Subject"),
        creator: extract_string_key(data, b"/Creator"),
        producer: extract_string_key(data, b"/Producer"),
        creation_date: extract_string_key(data, b"/CreationDate"),
        mod_date: extract_string_key(data, b"/ModDate"),
        keywords: extract_string_key(data, b"/Keywords"),
    }
}

/// Extract a `PdfEncrypt` dict by scanning for `/Encrypt` and its sub-keys.
///
/// Returns `None` if no encryption dictionary is found.
#[must_use]
pub fn extract_encrypt(doc: &PdfDocument) -> Option<PdfEncrypt> {
    let data = &doc.raw;
    if !data.windows(8).any(|w| w == b"/Encrypt") {
        return None;
    }
    let mut enc = PdfEncrypt::default();

    if let Some(pos) = find_bytes(data, b"/Filter") {
        let rest = &data[pos + 7..];
        let mut i = 0;
        while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
            i += 1;
        }
        if i < rest.len() && rest[i] == b'/' {
            i += 1;
            let start = i;
            while i < rest.len()
                && rest[i] != b' '
                && rest[i] != b'\n'
                && rest[i] != b'\r'
                && rest[i] != b'>'
            {
                i += 1;
            }
            enc.filter = std::str::from_utf8(&rest[start..i])
                .unwrap_or("Standard")
                .to_string();
        }
    }

    if let Some(v) = extract_integer_key(data, b"/V") {
        enc.version = v;
    }
    if let Some(v) = extract_integer_key(data, b"/R") {
        enc.revision = v;
    }
    if let Some(v) = extract_integer_key(data, b"/Length") {
        enc.key_length = v;
    }
    if let Some(v) = extract_integer_key(data, b"/P") {
        enc.permissions = v;
    }

    Some(enc)
}

/// Enumerate all stream objects within `doc`.
#[must_use]
pub fn enumerate_streams(doc: &PdfDocument) -> Vec<PdfStream> {
    let data = &doc.raw;
    let mut streams = Vec::new();
    let mut obj_num: u32 = 0;

    let mut i = 0;
    while i + 7 < data.len() {
        // Look for 'stream' keyword
        if &data[i..i + 6] != b"stream" {
            i += 1;
            continue;
        }
        // Must be followed by \n or \r\n
        let stream_header_end = if data[i + 6] == b'\n' {
            i + 7
        } else if i + 7 < data.len() && data[i + 6] == b'\r' && data[i + 7] == b'\n' {
            i + 8
        } else {
            i += 1;
            continue;
        };

        // Find 'endstream'
        let data_start = stream_header_end;
        let end_pos = data[data_start..]
            .windows(9)
            .position(|w| w == b"endstream");
        let (measured_length, endstream_end) = match end_pos {
            Some(ep) => (ep, data_start + ep + 9),
            None => {
                i += 1;
                continue;
            }
        };

        // Scan backward for dict start '<<' to extract dict entries
        let dict_start = scan_backward_for_dict(data, i);
        let dict_slice = &data[dict_start..i];
        let dict_entries = extract_dict_entries_raw(dict_slice);
        let filters = extract_filter_names(&dict_entries);

        // Prefer the /Length value declared in the stream dictionary; fall
        // back to the measured byte count if it is absent or unparseable.
        let data_length = dict_entries
            .iter()
            .find(|(k, _)| k == "Length")
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            .unwrap_or(measured_length);

        // Scan backward further for 'N G obj' to get object number
        if dict_start > 4 {
            let back = &data[..dict_start];
            if let Some(n) = scan_backward_for_obj_num(back) {
                obj_num = n;
            }
        }

        streams.push(PdfStream {
            obj_num,
            dict_entries,
            data_offset: data_start,
            data_length,
            filters,
        });

        i = endstream_end;
    }

    streams
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Find first occurrence of `needle` in `data`. Returns the byte offset.
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// After a key, skip whitespace then try to read `N G R` indirect reference
/// or a bare integer.
fn parse_ref_after(data: &[u8], start: usize) -> Option<u32> {
    let slice = data.get(start..)?;
    let mut i = 0;
    while i < slice.len()
        && (slice[i] == b' ' || slice[i] == b'\t' || slice[i] == b'\r' || slice[i] == b'\n')
    {
        i += 1;
    }
    // Parse first integer
    let n_start = i;
    while i < slice.len() && slice[i].is_ascii_digit() {
        i += 1;
    }
    if i == n_start {
        return None;
    }
    let n: u32 = std::str::from_utf8(&slice[n_start..i]).ok()?.parse().ok()?;
    Some(n)
}

/// Extract a PDF literal-string or name value after `key` in `data`.
fn extract_string_key(data: &[u8], key: &[u8]) -> Option<String> {
    let pos = find_bytes(data, key)?;
    let rest = &data[pos + key.len()..];
    let mut i = 0;
    // Skip whitespace
    while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
        i += 1;
    }
    if i >= rest.len() {
        return None;
    }
    if rest[i] == b'(' {
        // Literal string
        let mut depth = 1usize;
        i += 1;
        let mut s = String::new();
        while i < rest.len() && depth > 0 {
            match rest[i] {
                b'(' => {
                    depth += 1;
                    s.push('(');
                }
                b')' => {
                    depth -= 1;
                    if depth > 0 {
                        s.push(')');
                    }
                }
                b'\\' if i + 1 < rest.len() => {
                    i += 1;
                    match rest[i] {
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'\\' => s.push('\\'),
                        b'(' => s.push('('),
                        b')' => s.push(')'),
                        _ => {
                            s.push('\\');
                            s.push(rest[i] as char);
                        }
                    }
                }
                b => s.push(b as char),
            }
            i += 1;
        }
        Some(s)
    } else if rest[i] == b'/' {
        // Name value
        i += 1;
        let start = i;
        while i < rest.len()
            && rest[i] != b' '
            && rest[i] != b'\n'
            && rest[i] != b'\r'
            && rest[i] != b'>'
        {
            i += 1;
        }
        Some(
            std::str::from_utf8(&rest[start..i])
                .unwrap_or("")
                .to_string(),
        )
    } else {
        None
    }
}

/// Extract an integer value after `key` in `data`.
fn extract_integer_key(data: &[u8], key: &[u8]) -> Option<i64> {
    let pos = find_bytes(data, key)?;
    let rest = &data[pos + key.len()..];
    let mut i = 0;
    while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
        i += 1;
    }
    let sign = if i < rest.len() && rest[i] == b'-' {
        i += 1;
        -1i64
    } else {
        1i64
    };
    let start = i;
    while i < rest.len() && rest[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let n: i64 = std::str::from_utf8(&rest[start..i]).ok()?.parse().ok()?;
    Some(sign * n)
}

/// Scan backward from `limit` to find the start of `<<`.
fn scan_backward_for_dict(data: &[u8], limit: usize) -> usize {
    if limit < 2 {
        return 0;
    }
    let mut i = limit - 2;
    loop {
        if i + 1 < data.len() && data[i] == b'<' && data[i + 1] == b'<' {
            return i;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    0
}

/// Scan backward in `data` (before dict) for `N G obj` pattern; return N.
fn scan_backward_for_obj_num(data: &[u8]) -> Option<u32> {
    // Search from the end backward for " obj"
    let needle = b" obj";
    // Find the last occurrence of " obj"
    let pos = rposition_windows(data, needle)?;
    // Walk backward to find the object number
    let before = &data[..pos];
    let trimmed = before
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t' && b != b'\r' && b != b'\n')?;
    // Now walk backward past the generation number
    let gen_end = trimmed + 1;
    let gen_start = before[..gen_end]
        .iter()
        .rposition(|&b| !b.is_ascii_digit())
        .map(|p| p + 1)
        .unwrap_or(0);
    if gen_start >= gen_end {
        return None;
    }
    // Walk backward past whitespace
    let ws_end = gen_start;
    let ws_start = before[..ws_end]
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|p| p + 1)
        .unwrap_or(0);
    // Parse object number
    let obj_end = ws_start;
    let obj_start = before[..obj_end]
        .iter()
        .rposition(|&b| !b.is_ascii_digit())
        .map(|p| p + 1)
        .unwrap_or(0);
    if obj_start >= obj_end {
        return None;
    }
    std::str::from_utf8(&before[obj_start..obj_end])
        .ok()?
        .parse()
        .ok()
}

/// Find the last occurrence of `needle` in `haystack`, returning the start index.
fn rposition_windows(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Extract `(key, value)` pairs from a raw dict slice as strings.
fn extract_dict_entries_raw(dict: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let text = String::from_utf8_lossy(dict);
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '/' {
            continue;
        }
        // Read key
        let mut key = String::new();
        while let Some(&(_, kc)) = chars.peek() {
            if kc == ' '
                || kc == '\t'
                || kc == '\n'
                || kc == '\r'
                || kc == '/'
                || kc == '<'
                || kc == '>'
                || kc == '['
            {
                break;
            }
            key.push(kc);
            chars.next();
        }
        // Skip whitespace
        while let Some(&(_, wc)) = chars.peek() {
            if wc == ' ' || wc == '\t' {
                chars.next();
            } else {
                break;
            }
        }
        // Read value. If it starts with '/' it is a PDF name — consume it
        // as one token (up to whitespace, '/', or '>'), then stop.
        let mut val = String::new();
        if let Some(&(_, '/')) = chars.peek() {
            val.push('/');
            chars.next();
            while let Some(&(_, vc)) = chars.peek() {
                if vc == ' ' || vc == '\t' || vc == '\n' || vc == '\r' || vc == '/' || vc == '>' {
                    break;
                }
                val.push(vc);
                chars.next();
            }
        } else {
            while let Some(&(_, vc)) = chars.peek() {
                if vc == '/' || vc == '>' {
                    break;
                }
                val.push(vc);
                chars.next();
            }
        }
        let val = val.trim().to_string();
        if !key.is_empty() {
            entries.push((key, val));
        }
    }
    entries
}

/// Extract filter names from dict entries.
fn extract_filter_names(entries: &[(String, String)]) -> Vec<String> {
    let mut filters = Vec::new();
    for (k, v) in entries {
        if k == "Filter" {
            // v might be "/FlateDecode" or "[/Fl /Ascii85Decode]"
            let v2 = v.replace('[', "").replace(']', "");
            for part in v2.split_whitespace() {
                let name = part.trim_start_matches('/').to_string();
                if !name.is_empty() {
                    filters.push(name);
                }
            }
        }
    }
    filters
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PdfDocument, PdfVersion};

    fn make_doc(body: &[u8]) -> PdfDocument {
        let mut data = b"%PDF-1.7\n".to_vec();
        data.extend_from_slice(body);
        PdfDocument::parse(&data).unwrap()
    }

    // ── PdfCatalog ────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_catalog_empty_doc() {
        let doc = make_doc(b"");
        let cat = extract_catalog(&doc);
        assert!(!cat.acroform);
        assert_eq!(cat.javascript_count, 0);
    }

    #[test]
    fn test_extract_catalog_detects_acroform() {
        let doc = make_doc(b"/Catalog /AcroForm 1 0 R");
        let cat = extract_catalog(&doc);
        assert!(cat.acroform);
    }

    #[test]
    fn test_extract_catalog_detects_openaction() {
        let doc = make_doc(b"/Catalog /OpenAction 2 0 R");
        let cat = extract_catalog(&doc);
        assert!(cat.openaction);
    }

    #[test]
    fn test_extract_catalog_javascript_count() {
        let doc = make_doc(b"/JavaScript /JS (code) /JavaScript /JS (code2)");
        let cat = extract_catalog(&doc);
        assert_eq!(cat.javascript_count, 2);
    }

    #[test]
    fn test_extract_catalog_pages_ref() {
        let doc = make_doc(b"/Catalog << /Type /Catalog /Pages 3 0 R >>");
        let cat = extract_catalog(&doc);
        assert_eq!(cat.pages_ref, Some(3));
    }

    #[test]
    fn test_extract_catalog_outlines_ref() {
        let doc = make_doc(b"/Outlines 5 0 R");
        let cat = extract_catalog(&doc);
        assert_eq!(cat.outlines_ref, Some(5));
    }

    #[test]
    fn test_extract_catalog_metadata_ref() {
        let doc = make_doc(b"/Metadata 7 0 R");
        let cat = extract_catalog(&doc);
        assert_eq!(cat.metadata_ref, Some(7));
    }

    // ── PdfInfo ───────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_info_empty() {
        let doc = make_doc(b"");
        let info = extract_info(&doc);
        assert!(info.title.is_none());
    }

    #[test]
    fn test_extract_info_title() {
        let doc = make_doc(b"/Title (My Document)");
        let info = extract_info(&doc);
        assert_eq!(info.title.unwrap(), "My Document");
    }

    #[test]
    fn test_extract_info_author() {
        let doc = make_doc(b"/Author (Alice)");
        let info = extract_info(&doc);
        assert_eq!(info.author.unwrap(), "Alice");
    }

    #[test]
    fn test_extract_info_producer() {
        let doc = make_doc(b"/Producer (Acrobat 9.0)");
        let info = extract_info(&doc);
        assert_eq!(info.producer.unwrap(), "Acrobat 9.0");
    }

    #[test]
    fn test_extract_info_creator() {
        let doc = make_doc(b"/Creator (Word 2019)");
        let info = extract_info(&doc);
        assert_eq!(info.creator.unwrap(), "Word 2019");
    }

    #[test]
    fn test_extract_info_creation_date() {
        let doc = make_doc(b"/CreationDate (D:20200101)");
        let info = extract_info(&doc);
        assert!(info.creation_date.is_some());
    }

    #[test]
    fn test_extract_info_keywords() {
        let doc = make_doc(b"/Keywords (rust pdf re)");
        let info = extract_info(&doc);
        assert_eq!(info.keywords.unwrap(), "rust pdf re");
    }

    // ── PdfEncrypt ────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_encrypt_none() {
        let doc = make_doc(b"clean content");
        assert!(extract_encrypt(&doc).is_none());
    }

    #[test]
    fn test_extract_encrypt_present() {
        let doc = make_doc(b"<</Encrypt 1 0 R>> /Filter /Standard /V 2 /R 3 /Length 128 /P -3904");
        let enc = extract_encrypt(&doc);
        assert!(enc.is_some());
    }

    #[test]
    fn test_extract_encrypt_version() {
        let doc = make_doc(b"<</Encrypt>> /Filter /Standard /V 4 /R 4 /Length 128 /P -4");
        let enc = extract_encrypt(&doc).unwrap();
        assert_eq!(enc.version, 4);
    }

    // ── PdfStream ─────────────────────────────────────────────────────────────

    #[test]
    fn test_enumerate_streams_empty() {
        let doc = make_doc(b"");
        let streams = enumerate_streams(&doc);
        assert!(streams.is_empty());
    }

    #[test]
    fn test_enumerate_streams_finds_stream() {
        let doc = make_doc(b"3 0 obj\n<</Length 5>>\nstream\nhello\nendstream\nendobj\n");
        let streams = enumerate_streams(&doc);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].data_length, 5);
    }

    #[test]
    fn test_enumerate_streams_multiple() {
        let body = b"1 0 obj\n<</Length 2>>\nstream\nhi\nendstream\nendobj\n\
                     2 0 obj\n<</Length 3>>\nstream\nbye\nendstream\nendobj\n";
        let doc = make_doc(body);
        let streams = enumerate_streams(&doc);
        assert_eq!(streams.len(), 2);
    }

    #[test]
    fn test_enumerate_streams_filter_names() {
        let body = b"4 0 obj\n<</Length 10 /Filter /FlateDecode>>\nstream\n0123456789\nendstream\nendobj\n";
        let doc = make_doc(body);
        let streams = enumerate_streams(&doc);
        assert_eq!(streams.len(), 1);
        assert!(streams[0].filters.iter().any(|f| f == "FlateDecode"));
    }

    // ── PdfVersion / PdfPage / PdfPageTree type checks ────────────────────────

    #[test]
    fn test_pdf_page_default_fields() {
        let page = PdfPage {
            obj_num: 5,
            mediabox: Some([0.0, 0.0, 612.0, 792.0]),
            rotation: 0,
            contents_refs: vec![6, 7],
        };
        assert_eq!(page.obj_num, 5);
        assert_eq!(page.rotation, 0);
        assert_eq!(page.contents_refs.len(), 2);
    }

    #[test]
    fn test_pdf_page_tree_default() {
        let tree = PdfPageTree::default();
        assert_eq!(tree.count, 0);
        assert!(tree.pages.is_empty());
    }

    #[test]
    fn test_pdf_encrypt_default_key_length() {
        let enc = PdfEncrypt::default();
        assert_eq!(enc.key_length, 40);
    }

    #[test]
    fn test_pdf_stream_filters_field() {
        let s = PdfStream {
            obj_num: 1,
            dict_entries: vec![],
            data_offset: 100,
            data_length: 50,
            filters: vec!["FlateDecode".to_string()],
        };
        assert_eq!(s.filters[0], "FlateDecode");
    }

    #[test]
    fn test_pdf_catalog_version() {
        let cat = PdfCatalog {
            version: Some(PdfVersion { major: 1, minor: 6 }),
            ..PdfCatalog::default()
        };
        assert_eq!(cat.version.unwrap().minor, 6);
    }
}
