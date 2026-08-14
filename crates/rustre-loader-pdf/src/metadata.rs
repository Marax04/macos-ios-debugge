//! PDF metadata and forensics extraction.

use super::structures::PdfInfo;

// ── PdfMetadata ───────────────────────────────────────────────────────────────

/// High-level metadata extracted from a PDF file.
#[derive(Debug, Clone)]
pub struct PdfMetadata {
    /// Version string from the header (e.g. `"1.7"`).
    pub version: String,
    /// Total file size in bytes.
    pub file_size: usize,
    /// Approximate object count.
    pub obj_count: usize,
    /// Whether the file contains an `/Encrypt` dictionary.
    pub encrypted: bool,
    /// Whether an xref stream is present (PDF 1.5+).
    pub has_xref_stream: bool,
    /// Whether the file is linearized (optimized for web viewing).
    pub linearized: bool,
    /// Number of incremental updates (number of `%%EOF` markers).
    pub update_count: u32,
    /// Document information dictionary.
    pub info: PdfInfo,
}

impl Default for PdfMetadata {
    fn default() -> Self {
        Self {
            version: "unknown".to_string(),
            file_size: 0,
            obj_count: 0,
            encrypted: false,
            has_xref_stream: false,
            linearized: false,
            update_count: 0,
            info: PdfInfo::default(),
        }
    }
}

// ── PdfForensics ──────────────────────────────────────────────────────────────

/// Forensic indicators extracted from a PDF file.
#[derive(Debug, Clone, Default)]
pub struct PdfForensics {
    /// Whether the PDF magic bytes are valid (`%PDF-`).
    pub magic_valid: bool,
    /// Whether the file is linearized.
    pub linearized: bool,
    /// Whether the file is encrypted.
    pub encrypted: bool,
    /// Whether JavaScript is present.
    pub has_javascript: bool,
    /// Whether embedded files are present.
    pub has_embedded_files: bool,
    /// Number of incremental updates.
    pub update_count: u32,
    /// Approximate object count.
    pub obj_count: usize,
    /// Number of stream objects.
    pub stream_count: usize,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Extract `PdfMetadata` from raw PDF bytes.
#[must_use]
pub fn extract_metadata(data: &[u8]) -> PdfMetadata {
    let version = extract_version_string(data);
    let file_size = data.len();
    let obj_count = count_objects(data);
    let encrypted = data.windows(8).any(|w| w == b"/Encrypt");
    let has_xref_stream = detect_xref_stream(data);
    let linearized = detect_linearized(data);
    let update_count = count_updates(data);
    let info = extract_info_metadata(data);

    PdfMetadata {
        version,
        file_size,
        obj_count,
        encrypted,
        has_xref_stream,
        linearized,
        update_count,
        info,
    }
}

/// Detect whether a PDF is linearized (optimized for fast web viewing).
///
/// A linearized PDF contains `/Linearized` near the start of the file.
#[must_use]
pub fn detect_linearized(data: &[u8]) -> bool {
    // Linearized hint must appear in the first 8 KiB.
    // b"/Linearized" is 11 bytes; use windows(11) for exact match.
    let search_window = data.get(..data.len().min(8192)).unwrap_or(data);
    search_window.windows(11).any(|w| w == b"/Linearized")
}

/// Count incremental updates by counting `%%EOF` markers.
#[must_use]
pub fn count_updates(data: &[u8]) -> u32 {
    data.windows(5).filter(|w| *w == b"%%EOF").count() as u32
}

/// Count approximate object count by scanning for ` obj\n` markers (avoids
/// matching "objects", "objref", etc.).
#[must_use]
pub fn count_objects(data: &[u8]) -> usize {
    data.windows(5).filter(|w| *w == b" obj\n").count()
}

/// Detect whether an xref stream is used (contains `xref` as an indirect
/// object header rather than a plain `xref` keyword table).
#[must_use]
pub fn detect_xref_stream(data: &[u8]) -> bool {
    // An xref stream object looks like `N G obj\n<<..../Type /XRef`
    data.windows(5).any(|w| w == b"/XRef")
}

/// Compute full forensics for `data`.
#[must_use]
pub fn compute_forensics(data: &[u8]) -> PdfForensics {
    let magic_valid = data.starts_with(b"%PDF-");
    let linearized = detect_linearized(data);
    let encrypted = data.windows(8).any(|w| w == b"/Encrypt");
    let has_javascript = data.windows(11).any(|w| w == b"/JavaScript");
    let has_embedded_files = data.windows(13).any(|w| w == b"/EmbeddedFile");
    let update_count = count_updates(data);
    let obj_count = count_objects(data);
    let stream_count = count_streams(data);

    PdfForensics {
        magic_valid,
        linearized,
        encrypted,
        has_javascript,
        has_embedded_files,
        update_count,
        obj_count,
        stream_count,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Extract version string from header.
fn extract_version_string(data: &[u8]) -> String {
    if !data.starts_with(b"%PDF-") {
        return "unknown".to_string();
    }
    let rest = &data[5..];
    let end = rest
        .iter()
        .position(|&b| !b.is_ascii_digit() && b != b'.')
        .unwrap_or(rest.len().min(10));
    std::str::from_utf8(&rest[..end])
        .unwrap_or("unknown")
        .to_string()
}

/// Count stream objects.
fn count_streams(data: &[u8]) -> usize {
    // Count 'stream\n' or 'stream\r\n' occurrences
    let mut count = 0;
    let mut i = 0;
    while i + 6 < data.len() {
        if &data[i..i + 6] == b"stream" {
            let next = data.get(i + 6).copied().unwrap_or(0);
            if next == b'\n' || next == b'\r' {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

/// Extract simplified /Info fields from raw bytes.
fn extract_info_metadata(data: &[u8]) -> PdfInfo {
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

/// Extract a literal-string or name value after `key`.
fn extract_string_key(data: &[u8], key: &[u8]) -> Option<String> {
    let pos = data.windows(key.len()).position(|w| w == key)?;
    let rest = &data[pos + key.len()..];
    let mut i = 0;
    while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
        i += 1;
    }
    if i >= rest.len() {
        return None;
    }
    if rest[i] == b'(' {
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
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pdf(body: &[u8]) -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend_from_slice(body);
        v
    }

    // ── detect_linearized ─────────────────────────────────────────────────────

    #[test]
    fn test_detect_linearized_true() {
        let data = pdf(b"/Linearized 1");
        assert!(detect_linearized(&data));
    }

    #[test]
    fn test_detect_linearized_false() {
        let data = pdf(b"regular document");
        assert!(!detect_linearized(&data));
    }

    #[test]
    fn test_detect_linearized_only_near_start() {
        // If /Linearized appears after 8 KiB, should not be detected
        let mut data = pdf(b"");
        data.extend(vec![b' '; 9000]);
        data.extend_from_slice(b"/Linearized 1");
        assert!(!detect_linearized(&data));
    }

    // ── count_updates ─────────────────────────────────────────────────────────

    #[test]
    fn test_count_updates_one() {
        let data = pdf(b"%%EOF\n");
        assert_eq!(count_updates(&data), 1);
    }

    #[test]
    fn test_count_updates_multiple() {
        let data = pdf(b"%%EOF\ncontent%%EOF\n");
        assert_eq!(count_updates(&data), 2);
    }

    #[test]
    fn test_count_updates_zero() {
        let data = pdf(b"no eof marker");
        assert_eq!(count_updates(&data), 0);
    }

    // ── count_objects ─────────────────────────────────────────────────────────

    #[test]
    fn test_count_objects_one() {
        let data = pdf(b"1 0 obj\n42\nendobj\n");
        assert_eq!(count_objects(&data), 1);
    }

    #[test]
    fn test_count_objects_multiple() {
        let data = pdf(b"1 0 obj\n42\nendobj\n2 0 obj\ntrue\nendobj\n");
        assert_eq!(count_objects(&data), 2);
    }

    #[test]
    fn test_count_objects_zero() {
        let data = pdf(b"no objects here");
        assert_eq!(count_objects(&data), 0);
    }

    // ── detect_xref_stream ───────────────────────────────────────────────────

    #[test]
    fn test_detect_xref_stream_true() {
        let data = pdf(b"<</Type /XRef /Size 10>>");
        assert!(detect_xref_stream(&data));
    }

    #[test]
    fn test_detect_xref_stream_false() {
        let data = pdf(b"xref\n0 1\n0000000000 65535 f \r\n");
        assert!(!detect_xref_stream(&data));
    }

    // ── extract_metadata ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_metadata_version() {
        let data = pdf(b"");
        let meta = extract_metadata(&data);
        assert_eq!(meta.version, "1.7");
    }

    #[test]
    fn test_extract_metadata_file_size() {
        let body = b"body content";
        let data = pdf(body);
        let meta = extract_metadata(&data);
        assert_eq!(meta.file_size, data.len());
    }

    #[test]
    fn test_extract_metadata_encrypted_false() {
        let data = pdf(b"clean");
        let meta = extract_metadata(&data);
        assert!(!meta.encrypted);
    }

    #[test]
    fn test_extract_metadata_encrypted_true() {
        let data = pdf(b"<</Encrypt 1 0 R>>");
        let meta = extract_metadata(&data);
        assert!(meta.encrypted);
    }

    // ── compute_forensics ─────────────────────────────────────────────────────

    #[test]
    fn test_compute_forensics_magic_valid() {
        let data = pdf(b"");
        let f = compute_forensics(&data);
        assert!(f.magic_valid);
    }

    #[test]
    fn test_compute_forensics_invalid_magic() {
        let f = compute_forensics(b"JUNK");
        assert!(!f.magic_valid);
    }

    #[test]
    fn test_compute_forensics_javascript() {
        let data = pdf(b"/JavaScript (alert(1))");
        let f = compute_forensics(&data);
        assert!(f.has_javascript);
    }

    #[test]
    fn test_compute_forensics_embedded_files() {
        let data = pdf(b"/EmbeddedFile");
        let f = compute_forensics(&data);
        assert!(f.has_embedded_files);
    }

    #[test]
    fn test_compute_forensics_stream_count() {
        let data = pdf(b"1 0 obj\n<</Length 2>>\nstream\nhi\nendstream\nendobj\n");
        let f = compute_forensics(&data);
        assert!(f.stream_count >= 1);
    }

    #[test]
    fn test_compute_forensics_update_count() {
        let data = pdf(b"%%EOF\n%%EOF\n");
        let f = compute_forensics(&data);
        assert_eq!(f.update_count, 2);
    }

    #[test]
    fn test_compute_forensics_obj_count() {
        let data = pdf(b"1 0 obj\n<</Type /Catalog>>\nendobj\n2 0 obj\n42\nendobj\n");
        let f = compute_forensics(&data);
        assert_eq!(f.obj_count, 2);
    }

    // ── PdfMetadata default ───────────────────────────────────────────────────

    #[test]
    fn test_pdf_metadata_default() {
        let m = PdfMetadata::default();
        assert_eq!(m.version, "unknown");
        assert!(!m.encrypted);
        assert!(!m.linearized);
    }

    // ── version extraction ────────────────────────────────────────────────────

    #[test]
    fn test_version_string_20() {
        let data = b"%PDF-2.0\n".to_vec();
        let meta = extract_metadata(&data);
        assert_eq!(meta.version, "2.0");
    }

    #[test]
    fn test_version_string_invalid() {
        let data = b"JUNK".to_vec();
        let meta = extract_metadata(&data);
        assert_eq!(meta.version, "unknown");
    }
}
