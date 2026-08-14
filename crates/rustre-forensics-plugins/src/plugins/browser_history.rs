//! Browser history and artifact parser for Chrome, Firefox, and Edge.
//!
//! Parses SQLite-based history databases, cookie stores, download history,
//! form data, and session storage artifacts from browser profile directories.
//! This module operates on raw byte slices that represent the `SQLite` file
//! format — it does not depend on a live `SQLite` library.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("unsupported browser: {0}")]
    UnsupportedBrowser(String),
    #[error("invalid database header: {0}")]
    InvalidHeader(String),
    #[error("truncated record at offset {0}")]
    TruncatedRecord(usize),
    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("encoding error: {0}")]
    EncodingError(String),
}

// ─── Browser type ─────────────────────────────────────────────────────────────

/// Which browser produced the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Unknown(String),
}

impl BrowserType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Edge => "Edge",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Infer browser type from a profile directory path.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let lower = path.to_lowercase();
        if lower.contains("chrome") {
            return Self::Chrome;
        }
        if lower.contains("firefox") {
            return Self::Firefox;
        }
        if lower.contains("edge") {
            return Self::Edge;
        }
        Self::Unknown(path.to_string())
    }
}

// ─── SQLite page / magic detection ────────────────────────────────────────────

/// `SQLite` database file magic: "`SQLite` format 3\000"
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\x00";

/// Check whether a byte slice starts with the `SQLite` file header.
#[must_use]
pub fn is_sqlite(data: &[u8]) -> bool {
    data.len() >= 16 && &data[..16] == SQLITE_MAGIC
}

/// Read the page size from an `SQLite` header (bytes 16–17, big-endian).
#[must_use]
pub fn sqlite_page_size(data: &[u8]) -> Option<u16> {
    if data.len() < 18 {
        return None;
    }
    Some(u16::from_be_bytes([data[16], data[17]]))
}

/// Read the user-version field from an `SQLite` header (bytes 60–63, big-endian).
/// Chrome uses this field to store the schema version.
#[must_use]
pub fn sqlite_user_version(data: &[u8]) -> Option<u32> {
    if data.len() < 64 {
        return None;
    }
    Some(u32::from_be_bytes([data[60], data[61], data[62], data[63]]))
}

// ─── History record ────────────────────────────────────────────────────────────

/// A single browsing history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique row identifier.
    pub id: i64,
    /// Full URL visited.
    pub url: String,
    /// Page title at time of visit.
    pub title: String,
    /// Number of times this URL has been visited.
    pub visit_count: i32,
    /// Last visit timestamp (Windows FILETIME or Unix epoch micros).
    pub last_visit_time: i64,
    /// Whether the URL was typed directly.
    pub typed_count: i32,
    /// Whether this URL appears in the browser's Omnibox.
    pub hidden: bool,
    /// Source browser.
    pub browser: BrowserType,
}

impl HistoryEntry {
    /// Convert a Chrome `WebKit` timestamp (microseconds since 1601-01-01) to Unix epoch seconds.
    #[must_use]
    pub const fn webkit_to_unix(ts: i64) -> i64 {
        // Difference between Unix epoch and Windows epoch in microseconds
        const EPOCH_DIFF: i64 = 11_644_473_600_000_000;
        (ts - EPOCH_DIFF) / 1_000_000
    }

    /// Convert a Firefox `PRTime` (microseconds since Unix epoch) to Unix epoch seconds.
    #[must_use]
    pub const fn prtime_to_unix(ts: i64) -> i64 {
        ts / 1_000_000
    }
}

// ─── Cookie record ────────────────────────────────────────────────────────────

/// Security level of a cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CookieSameSite {
    None,
    Lax,
    Strict,
}

impl CookieSameSite {
    #[must_use]
    pub const fn from_int(v: i32) -> Self {
        match v {
            1 => Self::Lax,
            2 => Self::Strict,
            _ => Self::None,
        }
    }
}

/// A single cookie from a browser's Cookies database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub id: i64,
    pub host_key: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expires_utc: i64,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub same_site: CookieSameSite,
    pub creation_utc: i64,
    pub last_access_utc: i64,
    pub has_expires: bool,
    pub is_persistent: bool,
    pub encrypted_value_len: usize,
    pub browser: BrowserType,
}

impl CookieRecord {
    /// Returns `true` if the cookie was encrypted (DPAPI / AES-GCM on newer Chrome).
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted_value_len > 0
    }

    /// Returns `true` if this looks like a session authentication cookie
    /// (no expiry, `HttpOnly`, Secure).
    #[must_use]
    pub const fn is_session_auth(&self) -> bool {
        !self.has_expires && self.is_httponly && self.is_secure
    }
}

// ─── Download record ──────────────────────────────────────────────────────────

/// State of a browser download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    InProgress,
    Complete,
    Cancelled,
    Interrupted,
    Unknown(i32),
}

impl DownloadState {
    #[must_use]
    pub const fn from_int(v: i32) -> Self {
        match v {
            0 => Self::InProgress,
            1 => Self::Complete,
            2 => Self::Cancelled,
            4 => Self::Interrupted,
            n => Self::Unknown(n),
        }
    }
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::InProgress => "in_progress",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// A file downloaded via the browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRecord {
    pub id: i64,
    pub url: String,
    pub target_path: String,
    pub total_bytes: i64,
    pub received_bytes: i64,
    pub state: DownloadState,
    pub start_time: i64,
    pub end_time: i64,
    pub referrer_url: String,
    pub tab_url: String,
    pub mime_type: String,
    pub opened: bool,
    pub browser: BrowserType,
}

impl DownloadRecord {
    /// Check whether the downloaded file might be an executable or script.
    #[must_use]
    pub fn is_potentially_malicious(&self) -> bool {
        let path_lower = self.target_path.to_lowercase();
        let malicious_exts = [
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".msi", ".jar",
            ".pif",
        ];
        malicious_exts.iter().any(|ext| path_lower.ends_with(ext))
    }
}

// ─── Form data ────────────────────────────────────────────────────────────────

/// An autofill / form data entry from the browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormDataEntry {
    pub id: i64,
    pub field_name: String,
    pub value: String,
    pub count: i32,
    pub date_created: i64,
    pub date_last_used: i64,
    pub browser: BrowserType,
}

impl FormDataEntry {
    /// Return `true` if the field name suggests a credential field.
    #[must_use]
    pub fn looks_like_credential(&self) -> bool {
        let lower = self.field_name.to_lowercase();
        lower.contains("pass")
            || lower.contains("pwd")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("user")
            || lower.contains("login")
            || lower.contains("email")
            || lower.contains("auth")
    }
}

// ─── Session storage ──────────────────────────────────────────────────────────

/// A key/value pair from browser session or local storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub origin: String,
    pub key: String,
    pub value: String,
    pub storage_type: StorageType,
    pub browser: BrowserType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageType {
    SessionStorage,
    LocalStorage,
    IndexedDB,
}

impl StorageType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::SessionStorage => "session_storage",
            Self::LocalStorage => "local_storage",
            Self::IndexedDB => "indexed_db",
        }
    }
}

// ─── Database schema descriptors ──────────────────────────────────────────────

/// Schema definition for Chrome's `History` `SQLite` database.
pub struct ChromeHistorySchema;

impl ChromeHistorySchema {
    /// Expected table names in the Chrome history database.
    pub const TABLES: &'static [&'static str] = &[
        "urls",
        "visits",
        "visit_source",
        "keyword_search_terms",
        "downloads",
        "downloads_url_chains",
        "segments",
        "segment_usage",
        "typed_url_sync_metadata",
    ];

    /// Minimum supported schema version.
    pub const MIN_VERSION: u32 = 20;
    /// Maximum tested schema version.
    pub const MAX_VERSION: u32 = 60;

    /// Column layout for the `urls` table (index → name).
    pub const URLS_COLUMNS: &'static [&'static str] = &[
        "id",
        "url",
        "title",
        "visit_count",
        "typed_count",
        "last_visit_time",
        "hidden",
    ];

    /// Column layout for the `downloads` table.
    pub const DOWNLOADS_COLUMNS: &'static [&'static str] = &[
        "id",
        "guid",
        "current_path",
        "target_path",
        "start_time",
        "received_bytes",
        "total_bytes",
        "state",
        "danger_type",
        "interrupt_reason",
        "hash",
        "end_time",
        "opened",
        "last_access_time",
        "transient",
        "referrer",
        "site_url",
        "tab_url",
        "tab_referrer_url",
        "http_method",
        "by_ext_id",
        "by_ext_name",
        "etag",
        "last_modified",
        "mime_type",
        "original_mime_type",
    ];
}

/// Schema definition for Firefox's `places.sqlite`.
pub struct FirefoxPlacesSchema;

impl FirefoxPlacesSchema {
    pub const TABLES: &'static [&'static str] = &[
        "moz_places",
        "moz_historyvisits",
        "moz_inputhistory",
        "moz_bookmarks",
        "moz_bookmarks_deleted",
        "moz_keywords",
        "moz_origins",
        "moz_meta",
    ];

    pub const PLACES_COLUMNS: &'static [&'static str] = &[
        "id",
        "url",
        "title",
        "rev_host",
        "visit_count",
        "hidden",
        "typed",
        "favicon_id",
        "frecency",
        "last_visit_date",
        "guid",
        "foreign_count",
        "url_hash",
        "description",
        "preview_image_url",
        "site_name",
    ];
}

// ─── Mock parser ──────────────────────────────────────────────────────────────

/// Mock `SQLite` record scanner — locates embedded text strings that look like
/// URLs within a raw `SQLite` page dump.
///
/// A real implementation would decode the B-tree page format, varint-encoded
/// record headers, and column serial types.  This mock is sufficient for
/// forensic triage on raw memory dumps where full `SQLite` parsing is unavailable.
pub struct BrowserArtifactScanner;

impl BrowserArtifactScanner {
    /// Minimum URL length to consider.
    const MIN_URL_LEN: usize = 12;

    /// Scan raw bytes for embedded URL strings (http/https/ftp prefixes).
    #[must_use]
    pub fn scan_urls(data: &[u8]) -> Vec<String> {
        let mut urls = Vec::new();
        let prefixes: &[&[u8]] = &[b"http://", b"https://", b"ftp://"];
        for prefix in prefixes {
            let mut pos = 0;
            while pos + prefix.len() < data.len() {
                if data[pos..].starts_with(prefix) {
                    // Extract printable run
                    let start = pos;
                    let mut end = pos + prefix.len();
                    while end < data.len()
                        && (data[end].is_ascii_graphic() || data[end] == b' ')
                        && data[end] != b'\x00'
                    {
                        end += 1;
                    }
                    if end - start >= Self::MIN_URL_LEN
                        && let Ok(s) = std::str::from_utf8(&data[start..end]) {
                            urls.push(s.to_string());
                        }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    /// Scan for cookie-like `key=value; Domain=` patterns.
    #[must_use]
    pub fn scan_cookie_strings(data: &[u8]) -> Vec<CookieRecord> {
        let mut cookies = Vec::new();
        // Look for "Domain=" markers as anchors
        let marker = b"Domain=";
        let mut pos = 0;
        while pos + marker.len() < data.len() {
            if data[pos..].starts_with(marker) {
                let domain_start = pos + marker.len();
                let domain_end = data[domain_start..]
                    .iter()
                    .position(|&b| b == b';' || b == b'\x00').map_or_else(|| data.len().min(domain_start + 128), |i| domain_start + i);
                let host = String::from_utf8_lossy(&data[domain_start..domain_end])
                    .trim()
                    .to_string();
                if !host.is_empty() && host.len() < 128 {
                    cookies.push(CookieRecord {
                        id: i64::try_from(pos).unwrap_or(i64::MAX),
                        host_key: host,
                        name: String::new(),
                        value: String::new(),
                        path: "/".into(),
                        expires_utc: 0,
                        is_secure: false,
                        is_httponly: false,
                        same_site: CookieSameSite::None,
                        creation_utc: 0,
                        last_access_utc: 0,
                        has_expires: false,
                        is_persistent: false,
                        encrypted_value_len: 0,
                        browser: BrowserType::Unknown("scan".into()),
                    });
                }
                pos = domain_end;
            } else {
                pos += 1;
            }
        }
        cookies
    }

    /// Build a summary map from scanned artifacts.
    #[must_use]
    pub fn summarize(data: &[u8], browser: BrowserType) -> BrowserArtifactSummary {
        let urls = Self::scan_urls(data);
        let cookies = Self::scan_cookie_strings(data);
        let is_db = is_sqlite(data);
        let page_size = sqlite_page_size(data);
        let schema_ver = sqlite_user_version(data);
        BrowserArtifactSummary {
            browser,
            is_sqlite_database: is_db,
            page_size,
            schema_version: schema_ver,
            url_count: urls.len(),
            unique_domains: extract_domains(&urls),
            cookie_domains: cookies.iter().map(|c| c.host_key.clone()).collect(),
            scanned_urls: urls,
        }
    }
}

/// Summary of artifacts found in a browser profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifactSummary {
    pub browser: BrowserType,
    pub is_sqlite_database: bool,
    pub page_size: Option<u16>,
    pub schema_version: Option<u32>,
    pub url_count: usize,
    pub unique_domains: Vec<String>,
    pub cookie_domains: Vec<String>,
    pub scanned_urls: Vec<String>,
}

/// Extract unique domain names from a list of URLs.
#[must_use]
pub fn extract_domains(urls: &[String]) -> Vec<String> {
    let mut domains: Vec<String> = urls
        .iter()
        .filter_map(|url| {
            // Strip scheme
            let rest = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
            // Take up to first '/' or end
            let host = rest.split('/').next().unwrap_or("");
            // Drop port
            let host = host.split(':').next().unwrap_or("");
            if host.is_empty() {
                None
            } else {
                Some(host.to_string())
            }
        })
        .collect();
    domains.sort();
    domains.dedup();
    domains
}

// ─── Chrome-specific login data ───────────────────────────────────────────────

/// A saved login entry from Chrome's `Login Data` database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginEntry {
    pub id: i64,
    pub origin_url: String,
    pub action_url: String,
    pub username_element: String,
    pub username_value: String,
    pub password_element: String,
    /// Raw (possibly DPAPI-encrypted) password bytes length.
    pub password_encrypted_len: usize,
    pub date_created: i64,
    pub blacklisted_by_user: bool,
    pub scheme: i32,
    pub times_used: i32,
    pub date_last_used: i64,
}

impl LoginEntry {
    /// Check whether the entry is for an HTTP (insecure) origin.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        self.origin_url.to_lowercase().starts_with("http://")
    }
}

/// Scanner for Chrome Login Data artifacts.
pub struct LoginDataScanner;

impl LoginDataScanner {
    /// Scan raw bytes for embedded login URL patterns.
    #[must_use]
    pub fn scan_login_origins(data: &[u8]) -> Vec<String> {
        let mut origins = Vec::new();
        for prefix in &[b"http://".as_slice(), b"https://".as_slice()] {
            let mut pos = 0;
            while pos + prefix.len() < data.len() {
                if data[pos..].starts_with(prefix) {
                    let start = pos;
                    let end = data[pos..]
                        .iter()
                        .position(|&b| b == b'\x00' || b == b'"' || b == b'\'').map_or_else(|| data.len().min(pos + 512), |i| pos + i);
                    if let Ok(s) = std::str::from_utf8(&data[start..end])
                        && s.len() > 8 {
                            origins.push(s.to_string());
                        }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        origins.sort();
        origins.dedup();
        origins
    }
}

// ─── Firefox cookie reader ────────────────────────────────────────────────────

/// Firefox stores cookies in `cookies.sqlite` with this schema:
///
/// `moz_cookies(id, baseDomain, originAttributes, name, value, host, path,
///              expiry, lastAccessed, creationTime, isSecure, isHttpOnly,
///              appId, inBrowserElement, sameSite, rawSameSite, schemeMap)`
pub struct FirefoxCookieScanner;

impl FirefoxCookieScanner {
    /// Scan raw bytes for Firefox cookie domain markers.
    #[must_use]
    pub fn scan_domains(data: &[u8]) -> Vec<String> {
        // Firefox stores baseDomain as a UTF-8 string; look for TLD patterns
        let tlds: &[&[u8]] = &[b".com", b".net", b".org", b".io", b".gov", b".edu"];
        let mut domains = Vec::new();
        for tld in tlds {
            let mut pos = 0;
            while pos + tld.len() < data.len() {
                if data[pos..].starts_with(tld) {
                    // Walk backward to find domain start
                    let start = data[..pos]
                        .iter()
                        .rev()
                        .position(|&b| !b.is_ascii_alphanumeric() && b != b'.' && b != b'-')
                        .map_or(0, |i| pos.saturating_sub(i));
                    let end = pos + tld.len();
                    if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        let s =
                            s.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
                        if !s.is_empty() && s.len() < 128 {
                            domains.push(s.to_string());
                        }
                    }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        domains.sort();
        domains.dedup();
        domains
    }
}

// ─── Edge-specific artifacts ──────────────────────────────────────────────────

/// Microsoft Edge (Chromium-based) uses the same `SQLite` schemas as Chrome,
/// but with an additional `edge_identity` table.
pub struct EdgeArtifactScanner;

impl EdgeArtifactScanner {
    /// Edge sync metadata marker bytes.
    const EDGE_MARKER: &'static [u8] = b"MSEdge";

    /// Check whether a byte slice likely comes from an Edge profile.
    #[must_use]
    pub fn looks_like_edge(data: &[u8]) -> bool {
        data.windows(Self::EDGE_MARKER.len())
            .any(|w| w == Self::EDGE_MARKER)
    }
}

// ─── High-level analyzer ──────────────────────────────────────────────────────

/// High-level browser artifact analyzer.
/// Accepts a raw byte slice (from a memory dump or disk image) and returns
/// a structured analysis result.
pub struct BrowserArtifactAnalyzer;

impl BrowserArtifactAnalyzer {
    /// Detect browser type and summarize artifacts.
    #[must_use]
    pub fn analyze(data: &[u8], hint_path: Option<&str>) -> BrowserArtifactSummary {
        let browser = hint_path.map_or_else(
            || {
                if EdgeArtifactScanner::looks_like_edge(data) {
                    BrowserType::Edge
                } else if is_sqlite(data) {
                    // Check Firefox-specific table names
                    let has_moz = data.windows(10).any(|w| w == b"moz_places");
                    if has_moz { BrowserType::Firefox } else { BrowserType::Chrome }
                } else {
                    BrowserType::Unknown("unknown".into())
                }
            },
            BrowserType::from_path,
        );
        BrowserArtifactScanner::summarize(data, browser)
    }

    /// Classify all URLs in the artifact by category.
    #[must_use]
    pub fn classify_urls(urls: &[String]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::with_capacity(8);
        for url in urls {
            let category = Self::url_category(url);
            map.entry(category).or_default().push(url.clone());
        }
        map
    }

    fn url_category(url: &str) -> String {
        let lower = url.to_lowercase();
        if lower.contains("google.") {
            return "search_engine".into();
        }
        if lower.contains("bing.") || lower.contains("yahoo.") {
            return "search_engine".into();
        }
        if lower.contains("github.") || lower.contains("gitlab.") {
            return "developer".into();
        }
        if lower.contains("mail.") || lower.contains("outlook.") || lower.contains("gmail.") {
            return "webmail".into();
        }
        if lower.contains("youtube.") || lower.contains("twitch.") {
            return "streaming".into();
        }
        if lower.contains("192.168.") || lower.contains("10.0.") || lower.contains("localhost") {
            return "local_network".into();
        }
        if lower.contains("onion") {
            return "tor".into();
        }
        "other".into()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_magic_detection() {
        let mut data = vec![0u8; 100];
        data[..16].copy_from_slice(SQLITE_MAGIC);
        assert!(is_sqlite(&data));
        assert!(!is_sqlite(b"not a database"));
    }

    #[test]
    fn sqlite_page_size_parsing() {
        let mut data = vec![0u8; 100];
        data[..16].copy_from_slice(SQLITE_MAGIC);
        data[16] = 0x10;
        data[17] = 0x00;
        assert_eq!(sqlite_page_size(&data), Some(0x1000));
    }

    #[test]
    fn browser_type_from_path() {
        assert_eq!(
            BrowserType::from_path("/home/user/.config/google-chrome/Default"),
            BrowserType::Chrome
        );
        assert_eq!(
            BrowserType::from_path("C:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox"),
            BrowserType::Firefox
        );
        assert_eq!(
            BrowserType::from_path("C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User Data"),
            BrowserType::Edge
        );
    }

    #[test]
    fn webkit_timestamp_conversion() {
        // Chrome stores timestamps as microseconds since 1601-01-01
        // 13266054396000000 should be approximately 2021-01-01
        let ts = 13_266_054_396_000_000i64;
        let unix = HistoryEntry::webkit_to_unix(ts);
        assert!(unix > 1_600_000_000);
    }

    #[test]
    fn url_scanning() {
        let data = b"\x00\x00https://example.com/path?q=1\x00junk\x00http://test.org\x00";
        let urls = BrowserArtifactScanner::scan_urls(data);
        assert!(urls.iter().any(|u| u.contains("example.com")));
        assert!(urls.iter().any(|u| u.contains("test.org")));
    }

    #[test]
    fn domain_extraction() {
        let urls = vec![
            "https://google.com/search?q=test".to_string(),
            "https://github.com/user/repo".to_string(),
            "https://google.com/maps".to_string(),
        ];
        let domains = extract_domains(&urls);
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"google.com".to_string()));
        assert!(domains.contains(&"github.com".to_string()));
    }

    #[test]
    fn download_malicious_extension_check() {
        let d = DownloadRecord {
            id: 1,
            url: "http://evil.com/payload.exe".into(),
            target_path: "C:\\Users\\User\\Downloads\\payload.exe".into(),
            total_bytes: 1024,
            received_bytes: 1024,
            state: DownloadState::Complete,
            start_time: 0,
            end_time: 0,
            referrer_url: String::new(),
            tab_url: String::new(),
            mime_type: "application/octet-stream".into(),
            opened: true,
            browser: BrowserType::Chrome,
        };
        assert!(d.is_potentially_malicious());
    }

    #[test]
    fn form_data_credential_detection() {
        let entry = FormDataEntry {
            id: 1,
            field_name: "password".into(),
            value: "secret123".into(),
            count: 3,
            date_created: 0,
            date_last_used: 0,
            browser: BrowserType::Chrome,
        };
        assert!(entry.looks_like_credential());

        let safe = FormDataEntry {
            id: 2,
            field_name: "search_query".into(),
            value: "rust lang".into(),
            count: 1,
            date_created: 0,
            date_last_used: 0,
            browser: BrowserType::Chrome,
        };
        assert!(!safe.looks_like_credential());
    }

    #[test]
    fn cookie_session_auth_detection() {
        let c = CookieRecord {
            id: 1,
            host_key: ".example.com".into(),
            name: "session_id".into(),
            value: "abc123".into(),
            path: "/".into(),
            expires_utc: 0,
            is_secure: true,
            is_httponly: true,
            same_site: CookieSameSite::Strict,
            creation_utc: 0,
            last_access_utc: 0,
            has_expires: false,
            is_persistent: false,
            encrypted_value_len: 0,
            browser: BrowserType::Chrome,
        };
        assert!(c.is_session_auth());
    }

    #[test]
    fn edge_detection() {
        let data = b"some data MSEdge profile data";
        assert!(EdgeArtifactScanner::looks_like_edge(data));
        assert!(!EdgeArtifactScanner::looks_like_edge(b"just regular bytes"));
    }

    #[test]
    fn url_classification() {
        let urls = vec![
            "https://google.com/search".to_string(),
            "https://github.com/rust-lang".to_string(),
            "http://192.168.1.1/admin".to_string(),
        ];
        let classified = BrowserArtifactAnalyzer::classify_urls(&urls);
        assert!(classified.contains_key("search_engine"));
        assert!(classified.contains_key("developer"));
        assert!(classified.contains_key("local_network"));
    }

    #[test]
    fn firefox_domain_scan() {
        let data = b"\x00example.com\x00github.org\x00test.net\x00";
        let domains = FirefoxCookieScanner::scan_domains(data);
        assert!(!domains.is_empty());
    }

    #[test]
    fn summarize_empty_data() {
        let summary = BrowserArtifactScanner::summarize(b"", BrowserType::Chrome);
        assert_eq!(summary.url_count, 0);
        assert!(!summary.is_sqlite_database);
    }

    #[test]
    fn cookie_same_site_from_int() {
        assert_eq!(CookieSameSite::from_int(0), CookieSameSite::None);
        assert_eq!(CookieSameSite::from_int(1), CookieSameSite::Lax);
        assert_eq!(CookieSameSite::from_int(2), CookieSameSite::Strict);
    }

    #[test]
    fn download_state_from_int() {
        assert_eq!(DownloadState::from_int(1), DownloadState::Complete);
        assert_eq!(DownloadState::from_int(2), DownloadState::Cancelled);
        assert_eq!(DownloadState::from_int(99), DownloadState::Unknown(99));
    }
}
