//! String extraction and classification from memory images.
//!
//! Extracts ASCII and UTF-16LE strings from raw memory, then classifies them
//! as URLs, IP addresses, file paths, registry keys, base64 blobs, etc.

// ─── StringEncoding ───────────────────────────────────────────────────────────

/// Encoding of a recovered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// 7-bit printable ASCII.
    Ascii,
    /// UTF-16 little-endian (Windows-style wide strings).
    Utf16Le,
    /// UTF-8 (superset of ASCII, confirmed by UTF-8 validation).
    Utf8,
}

// ─── MemString ────────────────────────────────────────────────────────────────

/// A string recovered from memory.
#[derive(Debug, Clone)]
pub struct MemString {
    /// Virtual address of the first byte.
    pub address: u64,
    /// Decoded string value.
    pub value: String,
    /// How the bytes were interpreted.
    pub encoding: StringEncoding,
    /// Number of characters (not bytes).
    pub length: usize,
}

impl MemString {
    /// Create a new `MemString`.
    #[must_use]
    pub fn new(address: u64, value: String, encoding: StringEncoding) -> Self {
        let length = value.chars().count();
        Self {
            address,
            value,
            encoding,
            length,
        }
    }
}

// ─── StringExtractionConfig ───────────────────────────────────────────────────

/// Configuration for the string extractor.
#[derive(Debug, Clone)]
pub struct StringExtractionConfig {
    /// Minimum string length (characters).
    pub min_length: usize,
    /// Maximum string length (characters).
    pub max_length: usize,
    /// Extract ASCII strings.
    pub ascii: bool,
    /// Extract UTF-16LE strings.
    pub utf16le: bool,
}

impl Default for StringExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 2048,
            ascii: true,
            utf16le: true,
        }
    }
}

// ─── extract_strings ──────────────────────────────────────────────────────────

/// Extract all strings from `mem` according to `cfg`.
///
/// Results are not deduplicated and are returned in address order (ASCII
/// results come first, then UTF-16LE results, both sorted by address).
#[must_use]
pub fn extract_strings(mem: &[u8], base: u64, cfg: &StringExtractionConfig) -> Vec<MemString> {
    let mut result = Vec::new();

    if cfg.ascii {
        result.extend(extract_ascii(mem, base, cfg.min_length, cfg.max_length));
    }
    if cfg.utf16le {
        result.extend(extract_utf16le(mem, base, cfg.min_length, cfg.max_length));
    }

    result.sort_by_key(|s| s.address);
    result
}

/// Extract printable ASCII string runs from `mem`.
///
/// A printable byte is in the range `0x20..=0x7E` (space through tilde).
/// Tab (`0x09`) and newline/carriage-return characters (`0x0A`, `0x0D`) are
/// also accepted as they commonly appear in strings.
#[must_use]
pub fn extract_ascii(mem: &[u8], base: u64, min: usize, max: usize) -> Vec<MemString> {
    let mut result = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in mem.iter().enumerate() {
        let printable = (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D;
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let run = &mem[s..i];
            if run.len() >= min && run.len() <= max {
                // Trim trailing whitespace/control chars
                let s_trimmed = trim_ascii(run);
                if s_trimmed.len() >= min {
                    result.push(MemString::new(
                        base + s as u64,
                        String::from_utf8_lossy(s_trimmed).into_owned(),
                        StringEncoding::Ascii,
                    ));
                }
            }
        }
    }

    // Handle a run that ends at the buffer boundary
    if let Some(s) = start {
        let run = &mem[s..];
        if run.len() >= min && run.len() <= max {
            let s_trimmed = trim_ascii(run);
            if s_trimmed.len() >= min {
                result.push(MemString::new(
                    base + s as u64,
                    String::from_utf8_lossy(s_trimmed).into_owned(),
                    StringEncoding::Ascii,
                ));
            }
        }
    }

    result
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c > 0x20).unwrap_or(0);
    let end = b
        .iter()
        .rposition(|&c| c > 0x20)
        .map_or(b.len(), |i| i + 1);
    if start < end { &b[start..end] } else { b }
}

/// Extract UTF-16LE string runs from `mem`.
///
/// Scans pairs of bytes; a character is considered printable if its code point
/// is in the Basic Multilingual Plane and printable (roughly `0x0020..=0xD7FF`
/// plus surrogates are rejected).
#[must_use]
pub fn extract_utf16le(mem: &[u8], base: u64, min: usize, max: usize) -> Vec<MemString> {
    let mut result = Vec::new();

    if mem.len() < 2 {
        return result;
    }

    let mut run_start: Option<usize> = None;
    let mut run: Vec<u16> = Vec::new();

    let pairs = mem.len() / 2;
    for i in 0..pairs {
        let lo = mem[i * 2];
        let hi = mem[i * 2 + 1];
        let cp = u16::from_le_bytes([lo, hi]);
        let printable = (0x0020..=0xD7FF).contains(&cp) || (0xE000..=0xFFFD).contains(&cp);

        if printable {
            if run_start.is_none() {
                run_start = Some(i * 2);
            }
            run.push(cp);
        } else if let Some(start_byte) = run_start.take() {
            let chars = run.len();
            if chars >= min && chars <= max
                && let Ok(s) = String::from_utf16(&run)
                    && s.chars().count() >= min {
                        result.push(MemString::new(
                            base + start_byte as u64,
                            s,
                            StringEncoding::Utf16Le,
                        ));
                    }
            run.clear();
        }
    }

    if let Some(start_byte) = run_start {
        let chars = run.len();
        if chars >= min && chars <= max
            && let Ok(s) = String::from_utf16(&run)
                && s.chars().count() >= min {
                    result.push(MemString::new(
                        base + start_byte as u64,
                        s,
                        StringEncoding::Utf16Le,
                    ));
                }
    }

    result
}

// ─── StringClass ─────────────────────────────────────────────────────────────

/// Semantic classification of a recovered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringClass {
    /// HTTP/HTTPS/FTP URL.
    Url,
    /// IPv4 address (`N.N.N.N`).
    IpV4,
    /// Windows or Unix file path.
    FilePath,
    /// Windows registry key path.
    RegistryKey,
    /// Base64-encoded data.
    Base64,
    /// Hex-encoded blob.
    HexBlob,
    /// Well-known Windows API function name.
    WinApiName,
    /// .NET type name.
    DotNetType,
    /// `printf`-style format string.
    Format,
    /// Unclassified plain string.
    Plain,
}

/// Classify a string by heuristics.
#[must_use]
pub fn classify_string(s: &str) -> StringClass {
    // URL
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return StringClass::Url;
    }

    // Registry key
    if s.starts_with("HKEY_")
        || s.starts_with("HKLM\\")
        || s.starts_with("HKCU\\")
        || s.starts_with("HKU\\")
        || s.starts_with("HKCR\\")
    {
        return StringClass::RegistryKey;
    }

    // File path
    if s.starts_with("C:\\")
        || s.starts_with("D:\\")
        || s.starts_with("\\\\")
        || s.starts_with("/home/")
        || s.starts_with("/etc/")
        || s.starts_with("/usr/")
        || s.starts_with("/tmp/")
        || s.starts_with("/var/")
        || s.starts_with("/proc/")
    {
        return StringClass::FilePath;
    }

    // IPv4 — simple pattern: 4 numeric octets separated by dots
    if is_ipv4(s) {
        return StringClass::IpV4;
    }

    // HexBlob: only hex chars, length >= 16. Checked before Base64 because the
    // hex alphabet is a strict subset of the base64 alphabet, so a pure-hex
    // blob would otherwise be mis-classified as Base64.
    if s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return StringClass::HexBlob;
    }

    // Win32 API names (common suspicious ones). Checked before Base64 because
    // short alphanumeric API names (e.g. "VirtualAlloc") can coincidentally
    // satisfy the base64 alphabet/length constraints.
    if is_win_api_name(s) {
        return StringClass::WinApiName;
    }

    // Base64: only base64 alphabet characters, length >= 12, multiple of 4
    if s.len() >= 12 && s.len().is_multiple_of(4) && s.chars().all(is_base64_char) {
        return StringClass::Base64;
    }

    // .NET type name
    if s.contains("System.") || s.contains("Microsoft.") || s.contains("mscorlib") {
        return StringClass::DotNetType;
    }

    // Format string
    if s.contains("%s") || s.contains("%d") || s.contains("%x") || s.contains("%p") {
        return StringClass::Format;
    }

    StringClass::Plain
}

fn is_ipv4(s: &str) -> bool {
    let mut count = 0usize;
    for p in s.split('.') {
        count += 1;
        if count > 4 {
            return false;
        }
        if p.is_empty()
            || !p.bytes().all(|c| c.is_ascii_digit())
            || p.parse::<u16>().map_or(true, |n| n > 255)
        {
            return false;
        }
    }
    count == 4
}

const fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

fn is_win_api_name(s: &str) -> bool {
    const WIN_APIS: &[&str] = &[
        "CreateFile",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "LoadLibrary",
        "GetProcAddress",
        "OpenProcess",
        "CreateProcess",
        "ShellExecute",
        "WinExec",
        "URLDownloadToFile",
        "InternetOpen",
        "InternetConnect",
        "HttpSendRequest",
        "RegOpenKey",
        "RegSetValue",
        "RegCreateKey",
        "CreateRemoteThread",
        "NtCreateThread",
        "ZwUnmapViewOfSection",
        "SetWindowsHookEx",
    ];
    WIN_APIS.iter().any(|api| s == *api || s.starts_with(api))
}

// ─── StringReport ─────────────────────────────────────────────────────────────

/// Categorized summary of strings extracted from memory.
#[derive(Debug, Default, Clone)]
pub struct StringReport {
    /// Total number of strings.
    pub total: usize,
    /// URL strings.
    pub urls: Vec<MemString>,
    /// IPv4 address strings.
    pub ips: Vec<MemString>,
    /// File path strings.
    pub paths: Vec<MemString>,
    /// Registry key strings.
    pub registry_keys: Vec<MemString>,
    /// Win32 API name strings.
    pub api_names: Vec<MemString>,
}

impl StringReport {
    /// Returns the number of interesting findings (non-plain).
    #[must_use]
    pub const fn interesting_count(&self) -> usize {
        self.urls.len()
            + self.ips.len()
            + self.paths.len()
            + self.registry_keys.len()
            + self.api_names.len()
    }
}

/// Build a [`StringReport`] from a slice of extracted strings.
#[must_use]
pub fn build_report(strings: &[MemString]) -> StringReport {
    let mut report = StringReport {
        total: strings.len(),
        ..Default::default()
    };

    for s in strings {
        match classify_string(&s.value) {
            StringClass::Url => report.urls.push(s.clone()),
            StringClass::IpV4 => report.ips.push(s.clone()),
            StringClass::FilePath => report.paths.push(s.clone()),
            StringClass::RegistryKey => report.registry_keys.push(s.clone()),
            StringClass::WinApiName => report.api_names.push(s.clone()),
            _ => {}
        }
    }

    report
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── extract_ascii ────────────────────────────────────────────────────────

    #[test]
    fn extract_ascii_simple() {
        let mem = b"hello world";
        let strings = extract_ascii(mem, 0, 4, 2048);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
    }

    #[test]
    fn extract_ascii_min_length_filter() {
        let mem = b"\x00AB\x00hello\x00";
        let strings = extract_ascii(mem, 0, 4, 2048);
        // "AB" is 2 chars → filtered; "hello" is 5 → kept
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello");
    }

    #[test]
    fn extract_ascii_multiple_strings() {
        let mem = b"foo\x00\x00bar\x00baz";
        let strings = extract_ascii(mem, 0, 3, 2048);
        assert!(strings.iter().any(|s| s.value.contains("foo")));
        assert!(strings.iter().any(|s| s.value.contains("bar")));
    }

    #[test]
    fn extract_ascii_address_tracking() {
        let mem = b"\x00\x00\x00hello";
        let strings = extract_ascii(mem, 0x1000, 4, 2048);
        assert_eq!(strings[0].address, 0x1003);
    }

    #[test]
    fn extract_ascii_empty_input() {
        assert!(extract_ascii(&[], 0, 4, 2048).is_empty());
    }

    #[test]
    fn extract_ascii_encoding() {
        let mem = b"test_string";
        let strings = extract_ascii(mem, 0, 4, 2048);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
    }

    // ─── extract_utf16le ──────────────────────────────────────────────────────

    fn encode_utf16le(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for c in s.encode_utf16() {
            v.extend_from_slice(&c.to_le_bytes());
        }
        v
    }

    #[test]
    fn extract_utf16le_simple() {
        let mem = encode_utf16le("hello");
        let strings = extract_utf16le(&mem, 0, 4, 2048);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn extract_utf16le_short_ignored() {
        let mem = encode_utf16le("hi");
        let strings = extract_utf16le(&mem, 0, 4, 2048);
        assert!(strings.is_empty());
    }

    #[test]
    fn extract_utf16le_empty() {
        assert!(extract_utf16le(&[], 0, 4, 2048).is_empty());
    }

    #[test]
    fn extract_utf16le_address() {
        let mut mem = vec![0u8; 4]; // 2 null chars
        mem.extend(encode_utf16le("hello"));
        let strings = extract_utf16le(&mem, 0x2000, 4, 2048);
        assert_eq!(strings[0].address, 0x2004);
    }

    // ─── extract_strings ──────────────────────────────────────────────────────

    #[test]
    fn extract_strings_combines_both() {
        let mut mem = b"hello".to_vec();
        mem.extend_from_slice(b"\x00\x00\x00");
        mem.extend(encode_utf16le("world"));
        let cfg = StringExtractionConfig::default();
        let strings = extract_strings(&mem, 0, &cfg);
        assert!(strings.iter().any(|s| s.value == "hello"));
        assert!(strings.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn extract_strings_ascii_only() {
        let mem = b"hello";
        let cfg = StringExtractionConfig {
            ascii: true,
            utf16le: false,
            ..Default::default()
        };
        let strings = extract_strings(mem, 0, &cfg);
        assert!(strings.iter().all(|s| s.encoding == StringEncoding::Ascii));
    }

    // ─── classify_string ──────────────────────────────────────────────────────

    #[test]
    fn classify_url_https() {
        assert_eq!(
            classify_string("https://malware.example.com/payload"),
            StringClass::Url
        );
    }

    #[test]
    fn classify_url_http() {
        assert_eq!(classify_string("http://192.168.1.1/c2"), StringClass::Url);
    }

    #[test]
    fn classify_url_ftp() {
        assert_eq!(
            classify_string("ftp://files.example.com/drop"),
            StringClass::Url
        );
    }

    #[test]
    fn classify_ipv4() {
        assert_eq!(classify_string("192.168.1.100"), StringClass::IpV4);
    }

    #[test]
    fn classify_ipv4_invalid() {
        assert_ne!(classify_string("256.1.1.1"), StringClass::IpV4);
    }

    #[test]
    fn classify_file_path_windows() {
        assert_eq!(
            classify_string("C:\\Windows\\System32\\cmd.exe"),
            StringClass::FilePath
        );
    }

    #[test]
    fn classify_file_path_unc() {
        assert_eq!(
            classify_string("\\\\server\\share\\file.txt"),
            StringClass::FilePath
        );
    }

    #[test]
    fn classify_file_path_linux() {
        assert_eq!(classify_string("/etc/passwd"), StringClass::FilePath);
    }

    #[test]
    fn classify_registry_key_hklm() {
        assert_eq!(
            classify_string("HKLM\\Software\\Microsoft\\Windows"),
            StringClass::RegistryKey
        );
    }

    #[test]
    fn classify_registry_key_hkey() {
        assert_eq!(
            classify_string("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet"),
            StringClass::RegistryKey
        );
    }

    #[test]
    fn classify_base64() {
        // Valid base64, length=16, multiple of 4
        assert_eq!(classify_string("dGVzdHN0cmluZw=="), StringClass::Base64);
    }

    #[test]
    fn classify_hex_blob() {
        assert_eq!(
            classify_string("deadbeefcafebabe0102030405060708"),
            StringClass::HexBlob
        );
    }

    #[test]
    fn classify_win_api_name() {
        assert_eq!(classify_string("VirtualAlloc"), StringClass::WinApiName);
        assert_eq!(classify_string("CreateFile"), StringClass::WinApiName);
    }

    #[test]
    fn classify_plain() {
        assert_eq!(classify_string("some random text here"), StringClass::Plain);
    }

    // ─── build_report ─────────────────────────────────────────────────────────

    fn make_mem_string(addr: u64, value: &str) -> MemString {
        MemString::new(addr, value.to_string(), StringEncoding::Ascii)
    }

    #[test]
    fn build_report_urls() {
        let strings = vec![
            make_mem_string(0, "https://c2.example.com"),
            make_mem_string(100, "hello world this is plain"),
        ];
        let report = build_report(&strings);
        assert_eq!(report.total, 2);
        assert_eq!(report.urls.len(), 1);
    }

    #[test]
    fn build_report_ips() {
        let strings = vec![make_mem_string(0, "10.0.0.1")];
        let report = build_report(&strings);
        assert_eq!(report.ips.len(), 1);
    }

    #[test]
    fn build_report_paths() {
        let strings = vec![make_mem_string(
            0,
            "C:\\Users\\user\\AppData\\Local\\Temp\\a.exe",
        )];
        let report = build_report(&strings);
        assert_eq!(report.paths.len(), 1);
    }

    #[test]
    fn build_report_api_names() {
        let strings = vec![
            make_mem_string(0, "VirtualAlloc"),
            make_mem_string(50, "LoadLibrary"),
        ];
        let report = build_report(&strings);
        assert_eq!(report.api_names.len(), 2);
    }

    #[test]
    fn build_report_registry_keys() {
        let strings = vec![make_mem_string(
            0,
            "HKCU\\Software\\Microsoft\\Windows\\Run",
        )];
        let report = build_report(&strings);
        assert_eq!(report.registry_keys.len(), 1);
    }

    #[test]
    fn build_report_interesting_count() {
        let strings = vec![
            make_mem_string(0, "https://example.com"),
            make_mem_string(100, "plain string"),
        ];
        let report = build_report(&strings);
        assert_eq!(report.interesting_count(), 1);
    }

    #[test]
    fn mem_string_length_chars() {
        let s = MemString::new(0, "hello".to_string(), StringEncoding::Ascii);
        assert_eq!(s.length, 5);
    }

    #[test]
    fn default_config() {
        let cfg = StringExtractionConfig::default();
        assert_eq!(cfg.min_length, 4);
        assert_eq!(cfg.max_length, 2048);
        assert!(cfg.ascii);
        assert!(cfg.utf16le);
    }
}
