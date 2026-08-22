//! String scanning for PE files.
//!
//! Extracts ASCII (printable, 4+ character) and UTF-16LE strings from
//! binary data, along with their file offsets and optionally their
//! associated section names.

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Minimum number of consecutive printable bytes to consider an ASCII string.
pub const MIN_ASCII_LEN: usize = 4;

/// Minimum number of consecutive UTF-16LE characters to consider a string.
pub const MIN_UTF16_LEN: usize = 4;

// ---------------------------------------------------------------------------
// String encoding
// ---------------------------------------------------------------------------

/// The encoding in which a string was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringEncoding {
    /// 8-bit ASCII / Latin-1 printable characters.
    Ascii,
    /// 16-bit little-endian Unicode (UTF-16LE).
    Utf16Le,
}

// ---------------------------------------------------------------------------
// Found string
// ---------------------------------------------------------------------------

/// A string extracted from binary data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    /// The string value.
    pub value: String,
    /// File offset where the string starts.
    pub offset: usize,
    /// String encoding.
    pub encoding: StringEncoding,
    /// Section name this string was found in, if known.
    pub section: Option<String>,
}

impl ExtractedString {
    /// Length of the string in characters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns `true` if the string is empty (should not happen with `MIN_LEN` > 0).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns the byte size in the source file (ASCII: len bytes, UTF-16LE: len*2 bytes).
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        match self.encoding {
            StringEncoding::Ascii => self.value.len(),
            StringEncoding::Utf16Le => self.value.len() * 2,
        }
    }

    /// Returns `true` if this string looks like a Windows path or URL.
    #[must_use]
    pub fn looks_like_path(&self) -> bool {
        let v = &self.value;
        v.contains('\\')
            || v.contains('/')
            || v.starts_with("http://")
            || v.starts_with("https://")
            || v.starts_with("ftp://")
    }

    /// Returns `true` if this could be a Windows API function name.
    #[must_use]
    pub fn looks_like_api_name(&self) -> bool {
        let v = &self.value;
        // API names: start with uppercase letter, alphanumeric + optional ordinal suffix
        v.len() >= 4
            && v.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Returns `true` if this string looks like a registry key path.
    #[must_use]
    pub fn looks_like_registry_key(&self) -> bool {
        let v = &self.value;
        v.starts_with("HKEY_")
            || v.starts_with("HKLM\\")
            || v.starts_with("HKCU\\")
            || v.starts_with("HKCR\\")
            || v.starts_with("HKU\\")
            || v.starts_with("HKCC\\")
    }

    /// Returns `true` if the string looks like a DNS hostname or IP address.
    #[must_use]
    pub fn looks_like_host(&self) -> bool {
        let v = &self.value;
        // Simple heuristic: contains a dot and only hostname-valid chars
        v.contains('.')
            && v.len() >= 4
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }
}

// ---------------------------------------------------------------------------
// ASCII string scanning
// ---------------------------------------------------------------------------

/// Returns `true` if `b` is a printable ASCII character (0x20-0x7E) or common
/// whitespace (tab, CR, LF) that is acceptable in strings.
#[inline]
#[must_use]
pub const fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

/// Scan `data` for ASCII strings of at least `min_len` printable characters.
#[must_use]
pub fn scan_ascii(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut start = 0usize;
    let mut in_string = false;

    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if !in_string {
                start = i;
                in_string = true;
            }
        } else if in_string {
            let len = i - start;
            if len >= min_len {
                // SAFETY: every byte in [start..i] passed is_printable_ascii (<=0x7E), so valid UTF-8.
                let value = std::str::from_utf8(&data[start..i])
                    .map_or_else(|_| String::from_utf8_lossy(&data[start..i]).into_owned(), str::to_owned);
                results.push(ExtractedString {
                    value,
                    offset: start,
                    encoding: StringEncoding::Ascii,
                    section: None,
                });
            }
            in_string = false;
        }
    }

    // Handle string at end of buffer
    if in_string {
        let len = data.len() - start;
        if len >= min_len {
            // SAFETY: every byte in [start..] passed is_printable_ascii (<=0x7E), so valid UTF-8.
            let value = std::str::from_utf8(&data[start..])
                .map_or_else(|_| String::from_utf8_lossy(&data[start..]).into_owned(), str::to_owned);
            results.push(ExtractedString {
                value,
                offset: start,
                encoding: StringEncoding::Ascii,
                section: None,
            });
        }
    }

    results
}

// ---------------------------------------------------------------------------
// UTF-16LE string scanning
// ---------------------------------------------------------------------------

/// Returns `true` if the UTF-16LE code unit represents a printable BMP character.
#[inline]
#[must_use]
pub const fn is_printable_utf16(unit: u16) -> bool {
    matches!(unit, 0x0009 | 0x000A | 0x000D | 0x0020..=0x007E | 0x00A0..=0xD7FF)
}

/// Scan `data` for UTF-16LE strings of at least `min_len` printable characters.
///
/// UTF-16LE code units are 2 bytes wide and a given string is laid out on a
/// fixed 2-byte boundary. To discover strings regardless of whether they begin
/// at an even or odd byte offset, the buffer is scanned twice — once from each
/// alignment — and within a single pass the cursor always advances by whole
/// code units (2 bytes). Advancing by a single byte mid-scan would desynchronise
/// the high/low halves of every subsequent unit and corrupt the decoded text
/// (e.g. turning trailing ASCII into spurious CJK code points).
#[must_use]
pub fn scan_utf16le(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    if data.len() < 2 {
        return Vec::new();
    }

    // Collect candidate runs from both alignments.
    let mut candidates: Vec<Utf16Candidate> = Vec::new();
    for align in 0..2usize {
        scan_utf16le_aligned(data, min_len, align, &mut candidates);
    }

    // A misaligned read of an ASCII-range wide string decodes the byte pairs
    // out of phase and turns clean text (high byte 0x00) into spurious CJK code
    // points (high byte non-zero). When candidate runs from the two alignments
    // overlap the same bytes, the genuine string is the one with more
    // ASCII-range code units, so resolve overlaps in favour of the higher score.
    candidates.sort_by(|a, b| {
        b.ascii_score
            .cmp(&a.ascii_score)
            .then_with(|| b.byte_len().cmp(&a.byte_len()))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut accepted: Vec<Utf16Candidate> = Vec::new();
    for cand in candidates {
        let overlaps = accepted
            .iter()
            .any(|a| cand.start < a.end && a.start < cand.end);
        if !overlaps {
            accepted.push(cand);
        }
    }

    accepted.sort_by_key(|c| c.start);
    accepted
        .into_iter()
        .map(|c| ExtractedString {
            value: c.value,
            offset: c.start,
            encoding: StringEncoding::Utf16Le,
            section: None,
        })
        .collect()
}

/// A candidate UTF-16LE run discovered during scanning.
struct Utf16Candidate {
    value: String,
    /// Inclusive start byte offset.
    start: usize,
    /// Exclusive end byte offset.
    end: usize,
    /// Number of ASCII-range (`< 0x80`) code units — higher means more likely
    /// to be a genuine, correctly-aligned string.
    ascii_score: usize,
}

impl Utf16Candidate {
    const fn byte_len(&self) -> usize {
        self.end - self.start
    }
}

/// Scan a single 2-byte alignment of `data`, appending candidate runs to `out`.
fn scan_utf16le_aligned(data: &[u8], min_len: usize, align: usize, out: &mut Vec<Utf16Candidate>) {
    let mut i = align;
    let mut start_byte: Option<usize> = None;
    let mut chars: Vec<char> = Vec::new();
    let mut ascii_score = 0usize;

    // Iterate over 2-byte code units, never breaking alignment.
    while i + 1 < data.len() {
        let unit = u16::from_le_bytes([data[i], data[i + 1]]);
        if is_printable_utf16(unit) {
            if start_byte.is_none() {
                start_byte = Some(i);
            }
            if unit < 0x80 {
                ascii_score += 1;
            }
            chars.push(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}'));
        } else {
            flush_utf16(
                &mut start_byte,
                &mut chars,
                &mut ascii_score,
                i,
                out,
                min_len,
            );
        }
        i += 2;
    }

    // Handle a string running to the end of the buffer.
    let end = if data.len() % 2 == align % 2 {
        data.len()
    } else {
        data.len() - 1
    };
    flush_utf16(
        &mut start_byte,
        &mut chars,
        &mut ascii_score,
        end,
        out,
        min_len,
    );
}

/// Emit the accumulated run as a candidate (if long enough) and reset state.
fn flush_utf16(
    start_byte: &mut Option<usize>,
    chars: &mut Vec<char>,
    ascii_score: &mut usize,
    end: usize,
    out: &mut Vec<Utf16Candidate>,
    min_len: usize,
) {
    if let Some(sb) = *start_byte
        && chars.len() >= min_len {
            // Most code units are ASCII (1 byte each); pre-size to char count to avoid regrowth.
            let mut value = String::with_capacity(chars.len());
            value.extend(chars.iter());
            out.push(Utf16Candidate {
                value,
                start: sb,
                end,
                ascii_score: *ascii_score,
            });
        }
    *start_byte = None;
    chars.clear();
    *ascii_score = 0;
}

// ---------------------------------------------------------------------------
// Combined scanner
// ---------------------------------------------------------------------------

/// Scan options controlling what the combined scanner extracts.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Minimum ASCII string length (default: `MIN_ASCII_LEN`).
    pub min_ascii_len: usize,
    /// Minimum UTF-16LE string length (default: `MIN_UTF16_LEN`).
    pub min_utf16_len: usize,
    /// Whether to scan for ASCII strings.
    pub scan_ascii: bool,
    /// Whether to scan for UTF-16LE strings.
    pub scan_utf16le: bool,
    /// Whether to deduplicate identical string values.
    pub deduplicate: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            min_ascii_len: MIN_ASCII_LEN,
            min_utf16_len: MIN_UTF16_LEN,
            scan_ascii: true,
            scan_utf16le: true,
            deduplicate: false,
        }
    }
}

/// Scan `data` for both ASCII and UTF-16LE strings using the given `options`.
///
/// Results are sorted by offset.
#[must_use]
pub fn scan_strings(data: &[u8], options: &ScanOptions) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    if options.scan_ascii {
        results.extend(scan_ascii(data, options.min_ascii_len));
    }
    if options.scan_utf16le {
        results.extend(scan_utf16le(data, options.min_utf16_len));
    }

    // Sort by offset, then by encoding (ASCII before UTF-16)
    results.sort_by(|a, b| {
        a.offset.cmp(&b.offset).then_with(|| {
            a.encoding
                .partial_cmp_key()
                .cmp(&b.encoding.partial_cmp_key())
        })
    });

    if options.deduplicate {
        let mut seen = std::collections::HashSet::new();
        results.retain(|s| seen.insert(s.value.clone()));
    }

    results
}

/// Helper for ordering `StringEncoding` without implementing `Ord` on the enum.
trait EncodingOrd {
    fn partial_cmp_key(&self) -> u8;
}

impl EncodingOrd for StringEncoding {
    fn partial_cmp_key(&self) -> u8 {
        match self {
            Self::Ascii => 0,
            Self::Utf16Le => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Section-aware scanning
// ---------------------------------------------------------------------------

/// Scan a single raw section for strings and annotate them with the section name.
#[must_use]
pub fn scan_section(
    data: &[u8],
    raw_offset: usize,
    raw_size: usize,
    section_name: &str,
    options: &ScanOptions,
) -> Vec<ExtractedString> {
    let end = (raw_offset + raw_size).min(data.len());
    if raw_offset >= end {
        return Vec::new();
    }
    let slice = &data[raw_offset..end];
    let base_offset = raw_offset;

    let mut results = scan_strings(slice, options);
    for s in &mut results {
        s.offset += base_offset;
        s.section = Some(section_name.to_string());
    }
    results
}

// ---------------------------------------------------------------------------
// Interesting-string classification
// ---------------------------------------------------------------------------

/// Categories for interesting strings found during analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterestingCategory {
    /// Windows API function name import hint.
    ApiName,
    /// URL or URI.
    Url,
    /// File system path.
    FilePath,
    /// Windows registry key.
    RegistryKey,
    /// IP address or DNS hostname.
    Host,
    /// Possible command-line string.
    CommandLine,
    /// Base64-encoded data (heuristic).
    Base64,
}

/// Classify a string and return its category if interesting.
#[must_use]
pub fn classify_string(s: &ExtractedString) -> Option<InterestingCategory> {
    let v = &s.value;
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return Some(InterestingCategory::Url);
    }
    if s.looks_like_registry_key() {
        return Some(InterestingCategory::RegistryKey);
    }
    if v.contains(":\\") || (v.starts_with('/') && v.contains('/')) {
        return Some(InterestingCategory::FilePath);
    }
    if v.contains(' ') && (v.contains('-') || v.contains('/')) && v.len() > 8 {
        return Some(InterestingCategory::CommandLine);
    }
    // Rough base64 heuristic: long string, only base64 alphabet characters.
    // This must be checked before the API-name heuristic: API names are short
    // identifiers, whereas a long run of base64-alphabet characters is far more
    // likely to be encoded data than a Windows API symbol (which would otherwise
    // also satisfy the permissive alphanumeric API-name test).
    if v.len() >= 20
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Some(InterestingCategory::Base64);
    }
    if s.looks_like_api_name() {
        return Some(InterestingCategory::ApiName);
    }
    if s.looks_like_host() {
        return Some(InterestingCategory::Host);
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_ascii_basic() {
        let data = b"AAA\x00hello world\x00\x01\x02";
        let strings = scan_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
        assert_eq!(strings[0].offset, 4);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn test_scan_ascii_min_len() {
        let data = b"abc\x00abcd\x00";
        // "abc" = 3 chars (below threshold), "abcd" = 4 chars (at threshold)
        let strings = scan_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "abcd");
    }

    #[test]
    fn test_scan_ascii_at_end_of_buffer() {
        let data = b"helloworld";
        let strings = scan_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "helloworld");
    }

    #[test]
    fn test_scan_ascii_empty() {
        assert!(scan_ascii(&[], 4).is_empty());
    }

    #[test]
    fn test_scan_utf16le_basic() {
        // "ABCD" encoded as UTF-16LE
        let data: Vec<u8> = "ABCD"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let strings = scan_utf16le(&data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "ABCD");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn test_scan_utf16le_with_non_printable() {
        // "hello\0\0world" in UTF-16LE (null word terminates)
        let mut data: Vec<u8> = "hello"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        data.extend_from_slice(&[0x00, 0x00]); // null terminator
        data.extend("worldXY".encode_utf16().flat_map(u16::to_le_bytes));
        let strings = scan_utf16le(&data, 4);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "hello");
        assert_eq!(strings[1].value, "worldXY");
    }

    #[test]
    fn test_scan_strings_combined() {
        let mut data = b"ASCII_STRING\x00".to_vec();
        let utf16: Vec<u8> = "WIDE_STR"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        data.extend_from_slice(&utf16);

        let opts = ScanOptions::default();
        let results = scan_strings(&data, &opts);
        let ascii_found = results
            .iter()
            .any(|s| s.encoding == StringEncoding::Ascii && s.value.contains("ASCII_STRING"));
        let utf16_found = results
            .iter()
            .any(|s| s.encoding == StringEncoding::Utf16Le && s.value.contains("WIDE_STR"));
        assert!(ascii_found);
        assert!(utf16_found);
    }

    #[test]
    fn test_scan_strings_dedup() {
        let data = b"hello\x00hello\x00hello\x00";
        let opts = ScanOptions {
            deduplicate: true,
            scan_utf16le: false,
            ..Default::default()
        };
        let results = scan_strings(data, &opts);
        assert_eq!(results.iter().filter(|s| s.value == "hello").count(), 1);
    }

    #[test]
    fn test_extracted_string_properties() {
        let s = ExtractedString {
            value: "kernel32.dll".into(),
            offset: 0x100,
            encoding: StringEncoding::Ascii,
            section: Some(".idata".into()),
        };
        assert_eq!(s.len(), 12);
        assert_eq!(s.byte_size(), 12);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_extracted_string_utf16_byte_size() {
        let s = ExtractedString {
            value: "ABCD".into(),
            offset: 0,
            encoding: StringEncoding::Utf16Le,
            section: None,
        };
        assert_eq!(s.byte_size(), 8); // 4 chars * 2 bytes
    }

    #[test]
    fn test_looks_like_path() {
        let s = ExtractedString {
            value: r"C:\Windows\System32\ntdll.dll".into(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            section: None,
        };
        assert!(s.looks_like_path());
    }

    #[test]
    fn test_looks_like_url() {
        let s = ExtractedString {
            value: "https://evil.example.com/payload".into(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            section: None,
        };
        assert!(s.looks_like_path()); // URLs also match path heuristic
        assert_eq!(classify_string(&s), Some(InterestingCategory::Url));
    }

    #[test]
    fn test_looks_like_registry_key() {
        let s = ExtractedString {
            value: r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft".into(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            section: None,
        };
        assert!(s.looks_like_registry_key());
        assert_eq!(classify_string(&s), Some(InterestingCategory::RegistryKey));
    }

    #[test]
    fn test_looks_like_api_name() {
        let s = ExtractedString {
            value: "CreateFileW".into(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            section: None,
        };
        assert!(s.looks_like_api_name());
    }

    #[test]
    fn test_classify_base64() {
        let s = ExtractedString {
            value: "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0".into(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            section: None,
        };
        assert_eq!(classify_string(&s), Some(InterestingCategory::Base64));
    }

    #[test]
    fn test_scan_section_adds_section_name() {
        let data = b"ABCDEFGH";
        let opts = ScanOptions {
            scan_utf16le: false,
            min_ascii_len: 4,
            ..Default::default()
        };
        let results = scan_section(data, 0, data.len(), ".text", &opts);
        assert!(!results.is_empty());
        assert_eq!(results[0].section, Some(".text".to_string()));
    }

    #[test]
    fn test_scan_section_offset_applied() {
        let mut data = vec![0u8; 0x100];
        data.extend_from_slice(b"ABCDEFGH");
        let opts = ScanOptions {
            scan_utf16le: false,
            min_ascii_len: 4,
            ..Default::default()
        };
        let results = scan_section(&data, 0x100, 8, ".data", &opts);
        assert!(!results.is_empty());
        assert_eq!(results[0].offset, 0x100);
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'~'));
        assert!(is_printable_ascii(b'\t'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0x80));
    }

    #[test]
    fn test_is_printable_utf16() {
        assert!(is_printable_utf16(u16::from(b'A')));
        assert!(is_printable_utf16(0x00A0)); // non-breaking space
        assert!(!is_printable_utf16(0x0000)); // null
        assert!(!is_printable_utf16(0xD800)); // surrogate
    }
}
