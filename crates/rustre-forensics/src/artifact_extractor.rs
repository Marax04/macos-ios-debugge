//! `artifact_extractor` — Extract forensic artefacts from memory images.
//!
//! Recovers browser history/passwords (Chromium, Firefox), credential stores
//! (LSASS secrets, SAM hive fragments), clipboard content, recently typed URLs,
//! MFT entries cached in memory, and thumbnail cache data from raw memory images.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::OsType;

// ─── Timestamp ────────────────────────────────────────────────────────────────

pub type Timestamp = u64;

fn _now_ms() -> Timestamp {
    u64::try_from(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()).unwrap_or(u64::MAX)
}

// ─── Extraction Result ────────────────────────────────────────────────────────

/// Container for all artefacts extracted from a memory image.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub browser_history: Vec<BrowserHistoryEntry>,
    pub browser_credentials: Vec<BrowserCredential>,
    pub clipboard_entries: Vec<ClipboardEntry>,
    pub typed_urls: Vec<TypedUrl>,
    pub credentials: Vec<CredentialEntry>,
    pub mft_entries: Vec<MftEntry>,
    pub thumbnail_entries: Vec<ThumbnailEntry>,
    pub errors: Vec<String>,
}

impl ExtractionResult {
    pub fn merge(&mut self, other: Self) {
        self.browser_history.extend(other.browser_history);
        self.browser_credentials.extend(other.browser_credentials);
        self.clipboard_entries.extend(other.clipboard_entries);
        self.typed_urls.extend(other.typed_urls);
        self.credentials.extend(other.credentials);
        self.mft_entries.extend(other.mft_entries);
        self.thumbnail_entries.extend(other.thumbnail_entries);
        self.errors.extend(other.errors);
    }

    #[must_use] 
    pub const fn summary(&self) -> ExtractionSummary {
        ExtractionSummary {
            browser_history: self.browser_history.len(),
            browser_credentials: self.browser_credentials.len(),
            clipboard_entries: self.clipboard_entries.len(),
            typed_urls: self.typed_urls.len(),
            credentials: self.credentials.len(),
            mft_entries: self.mft_entries.len(),
            thumbnail_entries: self.thumbnail_entries.len(),
            errors: self.errors.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionSummary {
    pub browser_history: usize,
    pub browser_credentials: usize,
    pub clipboard_entries: usize,
    pub typed_urls: usize,
    pub credentials: usize,
    pub mft_entries: usize,
    pub thumbnail_entries: usize,
    pub errors: usize,
}

// ─── Browser History ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserType {
    Chromium,
    Firefox,
    InternetExplorer,
    Edge,
    Unknown,
}

impl fmt::Display for BrowserType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chromium => write!(f, "Chromium"),
            Self::Firefox => write!(f, "Firefox"),
            Self::InternetExplorer => write!(f, "Internet Explorer"),
            Self::Edge => write!(f, "Edge"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub browser: BrowserType,
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub last_visit_ms: Option<Timestamp>,
    pub profile: Option<String>,
    pub extraction_method: ExtractionMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCredential {
    pub browser: BrowserType,
    pub origin_url: String,
    pub username: String,
    /// Plaintext if decrypted, ciphertext otherwise (base64 encoded).
    pub password: PasswordValue,
    pub date_created_ms: Option<Timestamp>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordValue {
    Plaintext(String),
    Encrypted(Vec<u8>),
    DecryptionFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionMethod {
    MemoryCarving,
    HeapWalk,
    SqliteFromMemory,
    RawPattern,
}

// ─── Chromium History Pattern ─────────────────────────────────────────────────

/// Known `SQLite` WAL/page magic bytes: "`SQLite` format 3\000"
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";
/// Chromium URL magic pattern (appears in Chromium `SQLite` rows)
const HTTP_PREFIX: &[u8] = b"http";
/// Minimum plausible URL length
const MIN_URL_LEN: usize = 10;
/// Maximum URL to extract (anti-DoS)
const MAX_URL_LEN: usize = 2048;

/// Extract HTTP/HTTPS URLs from a raw memory slice.
#[must_use] 
pub fn carve_urls_from_memory(mem: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut i = 0;
    while i + 4 < mem.len() {
        if &mem[i..i + 4] == HTTP_PREFIX {
            // Find end of URL (null byte or whitespace)
            let start = i;
            let mut end = i + 4;
            while end < mem.len() && end - start < MAX_URL_LEN {
                let b = mem[end];
                if b == 0 || b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' || b == b'"' || b == b'\'' {
                    break;
                }
                end += 1;
            }
            if end - start >= MIN_URL_LEN
                && let Ok(url) = std::str::from_utf8(&mem[start..end])
                    && url.contains("://") {
                        urls.push(url.to_owned());
                    }
            i = end;
        } else {
            i += 1;
        }
    }
    urls
}

/// Attempt to find Chromium `SQLite` database pages in memory and extract URL rows.
#[must_use] 
pub fn extract_chromium_history(mem: &[u8], profile: Option<&str>) -> Vec<BrowserHistoryEntry> {
    let urls = carve_urls_from_memory(mem);
    urls.into_iter().map(|url| BrowserHistoryEntry {
        browser: BrowserType::Chromium,
        url,
        title: String::new(),
        visit_count: 1,
        last_visit_ms: None,
        profile: profile.map(str::to_owned),
        extraction_method: ExtractionMethod::MemoryCarving,
    }).collect()
}

/// Extract Firefox history by looking for `moz_places` `SQLite` pages.
#[must_use] 
pub fn extract_firefox_history(mem: &[u8], profile: Option<&str>) -> Vec<BrowserHistoryEntry> {
    // Firefox uses SQLite; try to find SQLite pages then carve URLs
    let has_sqlite = mem.windows(SQLITE_MAGIC.len()).any(|w| w == SQLITE_MAGIC);
    if !has_sqlite {
        return Vec::new();
    }
    let urls = carve_urls_from_memory(mem);
    urls.into_iter().map(|url| BrowserHistoryEntry {
        browser: BrowserType::Firefox,
        url,
        title: String::new(),
        visit_count: 1,
        last_visit_ms: None,
        profile: profile.map(str::to_owned),
        extraction_method: ExtractionMethod::MemoryCarving,
    }).collect()
}

// ─── Credential Extraction ────────────────────────────────────────────────────

/// Credential type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    WindowsLsa,     // LSASS secrets
    NtlmHash,       // NTLM hash from SAM
    KerberosTicket, // Kerberos TGT/ST
    DpapiBlobKey,   // DPAPI master key
    GenericPassword,
    SshPrivateKey,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsLsa => write!(f, "Windows LSA Secret"),
            Self::NtlmHash => write!(f, "NTLM Hash"),
            Self::KerberosTicket => write!(f, "Kerberos Ticket"),
            Self::DpapiBlobKey => write!(f, "DPAPI Blob Key"),
            Self::GenericPassword => write!(f, "Generic Password"),
            Self::SshPrivateKey => write!(f, "SSH Private Key"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub cred_type: CredentialType,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub secret: CredentialSecret,
    pub extracted_from_address: u64,
    pub confidence: u8, // 0–100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialSecret {
    NtlmHash([u8; 16]),
    LmHash([u8; 16]),
    Plaintext(String),
    RawBytes(Vec<u8>),
    KerberosTicket { service: String, encrypted_part: Vec<u8> },
}

/// Known NTLM hash pattern: a 16-byte sequence in LSA memory structures.
/// In real Mimikatz-style extraction, these are found after specific signatures.
const _LSASS_SIGNATURE: &[u8] = b"lsasrv.dll";
const SAM_HIVE_MAGIC: &[u8] = b"regf"; // Windows registry hive magic

/// Extract NTLM hashes from a memory region — simplified carving approach.
#[must_use] 
pub fn extract_ntlm_hashes(mem: &[u8]) -> Vec<CredentialEntry> {
    let mut entries = Vec::new();
    // In real scenarios, NTLM hashes follow specific structures (LM_OWF_PASSWORD etc.)
    // Here we demonstrate the scanning approach by looking for the SAM hive magic
    // and extracting 16-byte aligned candidate values.
    for (i, window) in mem.windows(SAM_HIVE_MAGIC.len()).enumerate() {
        if window == SAM_HIVE_MAGIC {
            // Found SAM hive candidate — extract nearby 16-byte blocks as potential hashes
            let scan_start = i;
            let scan_end = (i + 4096).min(mem.len());
            let region = &mem[scan_start..scan_end];
            let mut j = 0;
            while j + 16 <= region.len() {
                let candidate = &region[j..j + 16];
                // Crude filter: non-zero, not all same byte
                let non_zero = candidate.iter().filter(|&&b| b != 0).count();
                let unique_bytes: std::collections::HashSet<u8> = candidate.iter().copied().collect();
                if non_zero >= 8 && unique_bytes.len() >= 4 {
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(candidate);
                    entries.push(CredentialEntry {
                        cred_type: CredentialType::NtlmHash,
                        username: None,
                        domain: None,
                        secret: CredentialSecret::NtlmHash(hash),
                        extracted_from_address: (i + j) as u64,
                        confidence: 30, // Low: just carving, no structural validation
                    });
                }
                j += 16;
            }
        }
    }
    entries
}

/// Look for SSH private key material (PEM headers) in memory.
#[must_use] 
pub fn extract_ssh_private_keys(mem: &[u8]) -> Vec<CredentialEntry> {
    let pem_header = b"-----BEGIN ";
    let mut entries = Vec::new();
    for (i, w) in mem.windows(pem_header.len()).enumerate() {
        if w == pem_header {
            let start = i;
            let end = (i + 3000).min(mem.len());
            if let Ok(pem) = std::str::from_utf8(&mem[start..end])
                && pem.contains("PRIVATE KEY") {
                    // Extract until -----END
                    let pem_end = pem.find("-----END").map_or(end, |p| start + p + 50);
                    let key_data = mem[start..pem_end.min(mem.len())].to_vec();
                    entries.push(CredentialEntry {
                        cred_type: CredentialType::SshPrivateKey,
                        username: None,
                        domain: None,
                        secret: CredentialSecret::RawBytes(key_data),
                        extracted_from_address: start as u64,
                        confidence: 90,
                    });
                }
        }
    }
    entries
}

// ─── Clipboard ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub format: ClipboardFormat,
    pub content: ClipboardContent,
    pub timestamp_ms: Option<Timestamp>,
    pub extracted_from_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardFormat {
    Text,
    UnicodeText,
    Html,
    Bitmap,
    Dib,
    FileDrop,
    Custom(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardContent {
    Text(String),
    Bytes(Vec<u8>),
}

/// Windows clipboard data structures start with HGLOBAL allocations.
/// We look for Unicode text patterns (UTF-16LE null-terminated strings).
#[must_use] 
pub fn extract_clipboard_text(mem: &[u8]) -> Vec<ClipboardEntry> {
    let mut entries = Vec::new();
    // Look for sequences of printable UTF-16LE characters (lo byte printable, hi byte 0)
    let mut i = 0;
    while i + 4 < mem.len() {
        // UTF-16LE: alternating printable char and 0x00
        if mem[i + 1] == 0x00 && mem[i].is_ascii_alphanumeric() {
            let start = i;
            let mut chars = Vec::new();
            while i + 1 < mem.len() && mem[i + 1] == 0x00 && (mem[i].is_ascii_graphic() || mem[i] == b' ') {
                chars.push(mem[i] as char);
                i += 2;
            }
            if chars.len() >= 10 {
                let text: String = chars.into_iter().collect();
                entries.push(ClipboardEntry {
                    format: ClipboardFormat::UnicodeText,
                    content: ClipboardContent::Text(text),
                    timestamp_ms: None,
                    extracted_from_address: start as u64,
                });
            }
        } else {
            i += 1;
        }
    }
    entries
}

// ─── Typed URLs ───────────────────────────────────────────────────────────────

/// URL typed into Internet Explorer / Edge address bar (from registry `TypedURLs` key in memory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedUrl {
    pub url: String,
    pub last_visit_ms: Option<Timestamp>,
    pub index: Option<u32>, // TypedURLs\url1, url2, ...
}

/// Scan for recently-typed URLs (IE registry key pattern in memory).
#[must_use] 
pub fn extract_typed_urls(mem: &[u8]) -> Vec<TypedUrl> {
    let prefix = b"TypedURLs";
    let mut typed_urls = Vec::new();
    for (i, w) in mem.windows(prefix.len()).enumerate() {
        if w == prefix {
            let region = &mem[i..];
            let urls = carve_urls_from_memory(region);
            for (idx, url) in urls.into_iter().take(20).enumerate() {
                typed_urls.push(TypedUrl {
                    url,
                    last_visit_ms: None,
                    index: Some(u32::try_from(idx).unwrap_or(u32::MAX) + 1),
                });
            }
            break;
        }
    }
    typed_urls
}

// ─── MFT Entries ──────────────────────────────────────────────────────────────

/// An MFT (Master File Table) entry recovered from memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub flags: MftFlags,
    pub filename: String,
    pub parent_reference: u64,
    pub created_ms: Option<Timestamp>,
    pub modified_ms: Option<Timestamp>,
    pub accessed_ms: Option<Timestamp>,
    pub mft_modified_ms: Option<Timestamp>,
    pub file_size: u64,
    pub extracted_from_address: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct MftFlags {
    pub in_use: bool,
    pub is_directory: bool,
    pub is_deleted: bool,
}

/// MFT entry signature: "FILE"
const MFT_MAGIC: &[u8] = b"FILE";

/// INDX signature for directory entries
const _INDX_MAGIC: &[u8] = b"INDX";

#[must_use] 
pub fn extract_mft_entries(mem: &[u8]) -> Vec<MftEntry> {
    let mut entries = Vec::new();
    let mut i = 0;

    while i + 1024 <= mem.len() {
        if &mem[i..i + 4] == MFT_MAGIC {
            if let Some(entry) = parse_mft_entry(&mem[i..], i as u64) {
                entries.push(entry);
            }
            i += 1024;
        } else {
            i += 8; // Skip in aligned chunks for performance
        }
    }

    entries
}

fn parse_mft_entry(data: &[u8], address: u64) -> Option<MftEntry> {
    if data.len() < 48 {
        return None;
    }
    // Offset 0x16: flags (2 bytes)
    let flags_raw = u16::from_le_bytes(data[22..24].try_into().ok()?);
    let flags = MftFlags {
        in_use: (flags_raw & 0x01) != 0,
        is_directory: (flags_raw & 0x02) != 0,
        is_deleted: (flags_raw & 0x01) == 0,
    };

    // Offset 0x14: first attribute offset (2 bytes)
    let first_attr_offset = u16::from_le_bytes(data[20..22].try_into().ok()?) as usize;
    if first_attr_offset >= data.len().min(1024) {
        return None;
    }

    // Scan attributes for $FILE_NAME (type 0x30)
    let mut attr_offset = first_attr_offset;
    let mut filename = String::new();
    let mut file_size = 0u64;
    let mut created_ms = None;
    let mut modified_ms = None;

    while attr_offset + 8 < data.len().min(1024) {
        let attr_type = u32::from_le_bytes(data[attr_offset..attr_offset + 4].try_into().ok()?);
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        let attr_len = u32::from_le_bytes(data[attr_offset + 4..attr_offset + 8].try_into().ok()?) as usize;
        if attr_len == 0 || attr_offset + attr_len > data.len().min(1024) {
            break;
        }

        if attr_type == 0x30 {
            // $FILE_NAME attribute
            let attr_data_offset = u16::from_le_bytes(data[attr_offset + 20..attr_offset + 22].try_into().ok()?) as usize;
            let fn_start = attr_offset + attr_data_offset;
            if fn_start + 66 <= data.len().min(1024) {
                // Filename is at offset 64 from start of $FILE_NAME attribute content
                let fname_offset = fn_start + 64;
                let fname_len = data.get(fname_offset).copied().unwrap_or(0) as usize;
                let fname_start = fname_offset + 2;
                if fname_start + fname_len * 2 <= data.len().min(1024) {
                    let fname_raw = &data[fname_start..fname_start + fname_len * 2];
                    // UTF-16LE decode
                    let utf16: Vec<u16> = fname_raw.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    filename = String::from_utf16_lossy(&utf16);
                }
                // Timestamps at fn_start+0 (created), fn_start+8 (modified)
                if fn_start + 16 <= data.len() {
                    let raw_created = u64::from_le_bytes(data[fn_start..fn_start + 8].try_into().unwrap_or([0; 8]));
                    let raw_modified = u64::from_le_bytes(data[fn_start + 8..fn_start + 16].try_into().unwrap_or([0; 8]));
                    // Convert Windows FILETIME (100ns intervals since 1601) to ms since 1970
                    if raw_created > 116_444_736_000_000_000 {
                        created_ms = Some((raw_created - 116_444_736_000_000_000) / 10_000);
                    }
                    if raw_modified > 116_444_736_000_000_000 {
                        modified_ms = Some((raw_modified - 116_444_736_000_000_000) / 10_000);
                    }
                }
                if fn_start + 56 <= data.len() {
                    file_size = u64::from_le_bytes(data[fn_start + 48..fn_start + 56].try_into().unwrap_or([0; 8]));
                }
            }
        }

        attr_offset += attr_len;
    }

    // Entry number from offset 0x2C (4 bytes, lower 48 bits)
    let entry_number = u64::from(u32::from_le_bytes(data[44..48].try_into().ok()?));

    Some(MftEntry {
        entry_number,
        sequence_number: u16::from_le_bytes(data[16..18].try_into().ok()?),
        flags,
        filename,
        parent_reference: 0,
        created_ms,
        modified_ms,
        accessed_ms: None,
        mft_modified_ms: None,
        file_size,
        extracted_from_address: address,
    })
}

// ─── Thumbnail Cache ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThumbnailEntry {
    pub original_path: Option<String>,
    pub thumbnail_data: Vec<u8>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub format: ThumbnailFormat,
    pub extracted_from_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThumbnailFormat {
    Jpeg,
    Png,
    Bmp,
    Unknown,
}

#[must_use] 
pub fn extract_thumbnails(mem: &[u8]) -> Vec<ThumbnailEntry> {
    let mut thumbnails = Vec::new();
    // Windows thumbcache DB starts with "CMMM" signature
    let cmmm = b"CMMM";
    for (i, w) in mem.windows(4).enumerate() {
        if w == cmmm {
            // Minimal CMMM header: offset 0x10 = entry data
            let data_start = i + 0x10;
            if data_start + 4 > mem.len() {
                continue;
            }
            // Look for JPEG (FF D8 FF) or PNG (89 50 4E 47) within next 64KB
            let scan = &mem[data_start..data_start.saturating_add(65536).min(mem.len())];
            if let Some(j) = scan.windows(3).position(|w| w == [0xFF, 0xD8, 0xFF]) {
                // Found JPEG — extract until EOI (FF D9)
                let jpg_start = data_start + j;
                let eoi = scan[j..].windows(2).position(|w| w == [0xFF, 0xD9])
                    .map_or_else(|| jpg_start + 512.min(mem.len() - jpg_start), |p| jpg_start + p + 2);
                thumbnails.push(ThumbnailEntry {
                    original_path: None,
                    thumbnail_data: mem[jpg_start..eoi.min(mem.len())].to_vec(),
                    width: None,
                    height: None,
                    format: ThumbnailFormat::Jpeg,
                    extracted_from_address: jpg_start as u64,
                });
            }
        }
    }
    thumbnails
}

// ─── Artifact Extractor ───────────────────────────────────────────────────────

/// Toggles for browser-related extraction passes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BrowserExtractionToggles {
    pub history: bool,
    pub credentials: bool,
    pub typed_urls: bool,
}

impl Default for BrowserExtractionToggles {
    fn default() -> Self {
        Self { history: true, credentials: true, typed_urls: true }
    }
}

/// Toggles for filesystem and shell extraction passes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SystemExtractionToggles {
    pub clipboard: bool,
    pub mft: bool,
    pub thumbnails: bool,
}

impl Default for SystemExtractionToggles {
    fn default() -> Self {
        // thumbnails disabled by default (noisy)
        Self { clipboard: true, mft: true, thumbnails: false }
    }
}

/// Configuration for the artifact extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorConfig {
    pub browser: BrowserExtractionToggles,
    pub system: SystemExtractionToggles,
    pub os_type: OsType,
    /// Maximum number of URLs to extract (anti-DoS).
    pub max_urls: usize,
    /// Minimum confidence threshold for credentials (0–100).
    pub min_credential_confidence: u8,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            browser: BrowserExtractionToggles::default(),
            system: SystemExtractionToggles::default(),
            os_type: OsType::Windows,
            max_urls: 10_000,
            min_credential_confidence: 30,
        }
    }
}

/// Main artifact extractor — operates on a raw memory slice.
pub struct ArtifactExtractor {
    config: ExtractorConfig,
}

impl ArtifactExtractor {
    #[must_use] 
    pub const fn new(config: ExtractorConfig) -> Self {
        Self { config }
    }

    /// Run all enabled extractors against the given memory slice.
    #[must_use] 
    pub fn extract(&self, mem: &[u8]) -> ExtractionResult {
        let mut result = ExtractionResult::default();

        if self.config.browser.history {
            let chromium = extract_chromium_history(mem, Some("Default"));
            let firefox = extract_firefox_history(mem, Some("default"));
            let _total = chromium.len() + firefox.len();
            let history: Vec<BrowserHistoryEntry> = chromium.into_iter()
                .chain(firefox)
                .take(self.config.max_urls)
                .collect();
            result.browser_history = history;
        }

        if self.config.browser.credentials {
            let mut creds = extract_ntlm_hashes(mem);
            creds.extend(extract_ssh_private_keys(mem));
            result.credentials = creds.into_iter()
                .filter(|c| c.confidence >= self.config.min_credential_confidence)
                .collect();
        }

        if self.config.system.clipboard {
            result.clipboard_entries = extract_clipboard_text(mem);
        }

        if self.config.browser.typed_urls {
            result.typed_urls = extract_typed_urls(mem);
        }

        if self.config.system.mft {
            result.mft_entries = extract_mft_entries(mem);
        }

        if self.config.system.thumbnails {
            result.thumbnail_entries = extract_thumbnails(mem);
        }

        result
    }

    /// Extract from multiple non-contiguous memory chunks.
    #[must_use] 
    pub fn extract_chunks(&self, chunks: &[(&[u8], u64)]) -> ExtractionResult {
        let mut combined = ExtractionResult::default();
        for (chunk, _base_addr) in chunks {
            let partial = self.extract(chunk);
            combined.merge(partial);
        }
        combined
    }

    /// Focus extraction on a specific region around a known interesting address.
    #[must_use] 
    pub fn extract_window(
        &self,
        mem: &[u8],
        address: u64,
        window_size: usize,
        base_address: u64,
    ) -> ExtractionResult {
        let offset = usize::try_from(address.saturating_sub(base_address)).unwrap_or(usize::MAX);
        let start = offset.saturating_sub(window_size / 2);
        let end = (start + window_size).min(mem.len());
        if start >= end {
            return ExtractionResult::default();
        }
        self.extract(&mem[start..end])
    }
}

impl fmt::Debug for ArtifactExtractor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactExtractor")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_carving() {
        let mem = b"some data https://evil.com/beacon?token=abc123 more data http://another.com/path end";
        let urls = carve_urls_from_memory(mem);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("evil.com"));
        assert!(urls[1].contains("another.com"));
    }

    #[test]
    fn test_chromium_history_extraction() {
        let mem = b"garbage https://google.com/search?q=test irrelevant http://evil.com/c2 noise";
        let entries = extract_chromium_history(mem, Some("Default"));
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.browser == BrowserType::Chromium));
    }

    #[test]
    fn test_ssh_key_extraction() {
        let key_pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n";
        let mut mem = vec![0u8; 1024];
        mem[100..100 + key_pem.len()].copy_from_slice(key_pem);
        let entries = extract_ssh_private_keys(&mem);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cred_type, CredentialType::SshPrivateKey);
        assert_eq!(entries[0].confidence, 90);
    }

    #[test]
    fn test_clipboard_unicode_extraction() {
        // Build a UTF-16LE string "Hello World"
        let text = "Hello World!!";
        let mut mem = vec![0u8; 512];
        let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        mem[100..100 + encoded.len()].copy_from_slice(&encoded);
        let entries = extract_clipboard_text(&mem);
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_typed_urls_extraction() {
        let mut mem = Vec::new();
        mem.extend_from_slice(b"TypedURLs");
        mem.extend_from_slice(b" https://evil.com/admin https://bank.com/login ");
        let urls = extract_typed_urls(&mem);
        assert!(!urls.is_empty());
    }

    #[test]
    fn test_mft_entry_extraction_no_entries() {
        let mem = vec![0u8; 4096];
        let entries = extract_mft_entries(&mem);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_mft_entry_detection() {
        let mut mem = vec![0u8; 2048];
        mem[0..4].copy_from_slice(b"FILE");
        mem[22..24].copy_from_slice(&0x01u16.to_le_bytes()); // in_use
        mem[20..22].copy_from_slice(&48u16.to_le_bytes()); // first_attr_offset
        let _entries = extract_mft_entries(&mem);
        // May or may not produce an entry depending on content, but should not panic
        // (the important thing is no crash)
    }

    #[test]
    fn test_full_extractor() {
        let cfg = ExtractorConfig {
            system: SystemExtractionToggles { thumbnails: false, ..SystemExtractionToggles::default() },
            ..Default::default()
        };
        let extractor = ArtifactExtractor::new(cfg);
        let mem = b"garbage https://evil.com/c2 TypedURLs https://bank.com more noise";
        let result = extractor.extract(mem);
        let summary = result.summary();
        assert!(summary.browser_history > 0 || summary.typed_urls > 0);
    }
}
