//! `IoC` (Indicator of Compromise) extraction from binary or text data.
//!
//! The [`IocExtractor`] scans raw bytes or text and identifies common `IoC`
//! patterns including IP addresses, domains, URLs, email addresses, file
//! hashes, cryptocurrency addresses, mutex names, registry keys, file paths,
//! and HTTP User-Agent strings.
//!
//! All regex patterns are pre-compiled once at construction time via lazy
//! initialisation to avoid the cost of repeated compilation.

use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ioc::{IoC, IoCType};

// ─────────────────────────────────────────────────────────────────────────────
// ExtractedIocs
// ─────────────────────────────────────────────────────────────────────────────

/// Collection of all `IoCs` extracted from a single input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractedIocs {
    /// IPv4 addresses (dotted-decimal notation).
    pub ipv4: Vec<String>,
    /// IPv6 addresses (colon-hex notation, full or compressed).
    pub ipv6: Vec<String>,
    /// Domain names (≥ 2 labels, valid TLD).
    pub domains: Vec<String>,
    /// Full URLs (http / https / ftp).
    pub urls: Vec<String>,
    /// Email addresses.
    pub emails: Vec<String>,
    /// MD5 hashes (32 hex chars).
    pub md5: Vec<String>,
    /// SHA-1 hashes (40 hex chars).
    pub sha1: Vec<String>,
    /// SHA-256 hashes (64 hex chars).
    pub sha256: Vec<String>,
    /// SHA-512 hashes (128 hex chars).
    pub sha512: Vec<String>,
    /// Bitcoin addresses (P2PKH, P2SH, bech32).
    pub bitcoin_addresses: Vec<String>,
    /// Ethereum addresses (0x-prefixed, 40 hex chars).
    pub ethereum_addresses: Vec<String>,
    /// Windows mutex names extracted from strings.
    pub mutex_names: Vec<String>,
    /// Windows registry keys.
    pub registry_keys: Vec<String>,
    /// Windows and POSIX file paths.
    pub file_paths: Vec<String>,
    /// HTTP User-Agent strings.
    pub user_agents: Vec<String>,
}

impl ExtractedIocs {
    /// Return the total number of unique `IoCs` across all categories.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.ipv4.len()
            + self.ipv6.len()
            + self.domains.len()
            + self.urls.len()
            + self.emails.len()
            + self.md5.len()
            + self.sha1.len()
            + self.sha256.len()
            + self.sha512.len()
            + self.bitcoin_addresses.len()
            + self.ethereum_addresses.len()
            + self.mutex_names.len()
            + self.registry_keys.len()
            + self.file_paths.len()
            + self.user_agents.len()
    }

    /// Flatten all `IoCs` into a `Vec<IoC>` with appropriate types.
    #[must_use]
    pub fn to_ioc_list(&self) -> Vec<IoC> {
        let mut iocs = Vec::with_capacity(self.total_count());
        let src = "extractor";

        macro_rules! push_type {
            ($field:expr, $ty:expr) => {
                for v in &$field {
                    iocs.push(IoC::new($ty, v.clone(), src.to_owned()));
                }
            };
        }

        push_type!(self.ipv4, IoCType::Ip);
        push_type!(self.ipv6, IoCType::Ip);
        push_type!(self.domains, IoCType::Domain);
        push_type!(self.urls, IoCType::Url);
        push_type!(self.emails, IoCType::Email);
        push_type!(self.md5, IoCType::Md5);
        push_type!(self.sha1, IoCType::Sha1);
        push_type!(self.sha256, IoCType::Sha256);
        push_type!(self.sha512, IoCType::Sha512);
        push_type!(self.mutex_names, IoCType::Mutex);
        push_type!(self.registry_keys, IoCType::Registry);
        push_type!(self.file_paths, IoCType::Filename);

        iocs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IocExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts `IoC` patterns from raw text or binary data converted to strings.
///
/// ```rust
/// use rustre_threatintel::ioc_extractor::IocExtractor;
///
/// let extractor = IocExtractor::new();
/// let text = "contacted 8.8.8.8 and example.com via http://evil.org/payload.exe";
/// let iocs = extractor.extract_from_str(text);
/// assert!(!iocs.ipv4.is_empty());
/// assert!(!iocs.domains.is_empty());
/// assert!(!iocs.urls.is_empty());
/// ```
pub struct IocExtractor {
    ipv4: Regex,
    ipv6: Regex,
    domain: Regex,
    url: Regex,
    email: Regex,
    md5: Regex,
    sha1: Regex,
    sha256: Regex,
    sha512: Regex,
    btc: Regex,
    eth: Regex,
    mutex: Regex,
    regkey: Regex,
    win_path: Regex,
    posix_path: Regex,
    useragent: Regex,
}

impl IocExtractor {
    /// Construct a new extractor, compiling all regexes.
    ///
    /// # Panics
    /// Panics if a regex fails to compile (indicates a bug in the pattern).
    #[must_use]
    pub fn new() -> Self {
        Self {
            ipv4: Regex::new(
                r"(?:^|[^.\d])((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?:[^.\d]|$)"
            ).expect("ipv4 regex"),

            ipv6: Regex::new(
                r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}"
            ).expect("ipv6 regex"),

            domain: Regex::new(
                r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|fr|br|info|biz|co|me|xyz|top|site|online|store|shop|club|pro|app|dev|tech|ai|cloud|gov|edu|mil|int)\b"
            ).expect("domain regex"),

            url: Regex::new(
                r#"(?i)https?://[^\s<>"'`|{}\[\]\\^;,]+"#
            ).expect("url regex"),

            email: Regex::new(
                r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"
            ).expect("email regex"),

            md5: Regex::new(r"(?i)\b[0-9a-f]{32}\b").expect("md5 regex"),
            sha1: Regex::new(r"(?i)\b[0-9a-f]{40}\b").expect("sha1 regex"),
            sha256: Regex::new(r"(?i)\b[0-9a-f]{64}\b").expect("sha256 regex"),
            sha512: Regex::new(r"(?i)\b[0-9a-f]{128}\b").expect("sha512 regex"),

            btc: Regex::new(
                r"(?:^|[^a-zA-Z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})(?:[^a-zA-Z0-9]|$)"
            ).expect("btc regex"),

            eth: Regex::new(r"0x[0-9a-fA-F]{40}\b").expect("eth regex"),

            mutex: Regex::new(
                r"(?i)\bGlobal\\[A-Za-z0-9_\-\.]{4,64}\b|\bLocal\\[A-Za-z0-9_\-\.]{4,64}\b|\\BaseNamedObjects\\[A-Za-z0-9_\-\.]{4,64}"
            ).expect("mutex regex"),

            regkey: Regex::new(
                r"(?i)\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9\\_\-\. ]{4,200}"
            ).expect("regkey regex"),

            win_path: Regex::new(
                r#"(?i)(?:[A-Za-z]:\\|\\\\)(?:[^\\/<>:"|\x00-\x1f]+\\)*[^\\/<>:"|\x00-\x1f ]+"#
            ).expect("win_path regex"),

            posix_path: Regex::new(
                r"(?:^|[ \t,;|])(/(?:[a-zA-Z0-9._\-]+/)*[a-zA-Z0-9._\-]+)"
            ).expect("posix_path regex"),

            useragent: Regex::new(
                r"(?i)(?:Mozilla|curl|python-requests|Go-http-client|libwww|Wget|okhttp|Apache-HttpClient|Java)/[^\s\x00-\x1f]+"
            ).expect("useragent regex"),
        }
    }

    /// Extract `IoCs` from a UTF-8 string slice.
    #[must_use]
    pub fn extract_from_str(&self, text: &str) -> ExtractedIocs {
        let (clean, mut out) = self.extract_network(text);
        self.extract_hashes(text, &mut out);
        self.extract_misc(text, &clean, &mut out);
        out
    }

    fn extract_network(&self, text: &str) -> (String, ExtractedIocs) {
        // ── URLs first (they may contain IPs and domains; extract before those) ──
        let mut out = ExtractedIocs {
            urls: dedup(self.url.find_iter(text).map(|m| m.as_str().to_owned())),
            ..ExtractedIocs::default()
        };

        // ── Remove URL spans so we don't double-count their IPs/domains ──
        let mut clean = text.to_owned();
        for m in self.url.find_iter(text).collect::<Vec<_>>().iter().rev() {
            clean.replace_range(m.start()..m.end(), &" ".repeat(m.len()));
        }

        // ── Emails (before domain so foo@bar.com doesn't produce bar.com domain) ──
        out.emails = dedup(self.email.find_iter(&clean).map(|m| m.as_str().to_owned()));
        let clean_copy = clean.clone();
        for m in self.email.find_iter(&clean_copy).collect::<Vec<_>>().iter().rev() {
            clean.replace_range(m.start()..m.end(), &" ".repeat(m.len()));
        }

        // ── IPv4 ──
        out.ipv4 = dedup(
            self.ipv4
                .captures_iter(&clean)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().to_owned()),
        );

        // ── IPv6 ──
        out.ipv6 = dedup(self.ipv6.find_iter(&clean).map(|m| m.as_str().to_owned()));

        // ── Domains ──
        out.domains = dedup(
            self.domain
                .find_iter(&clean)
                .map(|m| m.as_str().to_lowercase())
                .filter(|d| !out.ipv4.contains(d)),
        );

        (clean, out)
    }

    fn extract_hashes(&self, text: &str, out: &mut ExtractedIocs) {
        // ── Hashes (longest first to avoid prefix collisions) ──
        out.sha512 = dedup(self.sha512.find_iter(text).map(|m| m.as_str().to_lowercase()));
        let sha512_set: HashSet<String> = out.sha512.iter().cloned().collect();

        out.sha256 = dedup(
            self.sha256
                .find_iter(text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|h| !sha512_set.contains(h.as_str())),
        );
        let sha256_set: HashSet<String> = out.sha256.iter().cloned().collect();

        out.sha1 = dedup(
            self.sha1
                .find_iter(text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|h| !sha256_set.contains(h.as_str()) && !sha512_set.contains(h.as_str())),
        );
        let sha1_set: HashSet<String> = out.sha1.iter().cloned().collect();

        out.md5 = dedup(
            self.md5
                .find_iter(text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|h| {
                    !sha1_set.contains(h.as_str())
                        && !sha256_set.contains(h.as_str())
                        && !sha512_set.contains(h.as_str())
                }),
        );
    }

    fn extract_misc(&self, text: &str, _clean: &str, out: &mut ExtractedIocs) {
        // ── Crypto addresses ──
        out.bitcoin_addresses = dedup(
            self.btc
                .captures_iter(text)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().to_owned()),
        );
        out.ethereum_addresses = dedup(self.eth.find_iter(text).map(|m| m.as_str().to_owned()));

        // ── Mutex names ──
        out.mutex_names = dedup(self.mutex.find_iter(text).map(|m| m.as_str().to_owned()));

        // ── Registry keys ──
        out.registry_keys =
            dedup(self.regkey.find_iter(text).map(|m| m.as_str().to_owned()));

        // ── File paths ──
        let win_paths: Vec<String> =
            dedup(self.win_path.find_iter(text).map(|m| m.as_str().to_owned()));
        let posix_paths: Vec<String> = dedup(
            self.posix_path
                .captures_iter(text)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().to_owned()),
        );
        out.file_paths = [win_paths, posix_paths].concat();
        out.file_paths.sort();
        out.file_paths.dedup();

        // ── User-Agent strings ──
        out.user_agents =
            dedup(self.useragent.find_iter(text).map(|m| m.as_str().to_owned()));
    }

    /// Maximum number of bytes processed by [`Self::extract_from_bytes`].
    /// Input beyond this limit is silently truncated to prevent unbounded memory
    /// allocation on adversarial or accidentally-large inputs.
    pub const MAX_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

    /// Extract `IoCs` from raw bytes by interpreting printable ASCII sequences.
    ///
    /// Non-printable bytes are replaced with a space; the resulting string is
    /// then processed by [`Self::extract_from_str`].
    ///
    /// Input is truncated to [`Self::MAX_BYTES`] to prevent unbounded allocation.
    #[must_use]
    pub fn extract_from_bytes(&self, data: &[u8]) -> ExtractedIocs {
        let data = if data.len() > Self::MAX_BYTES {
            &data[..Self::MAX_BYTES]
        } else {
            data
        };
        let text: String = data
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
                    b as char
                } else {
                    ' '
                }
            })
            .collect();
        self.extract_from_str(&text)
    }

}

/// Deduplicate an iterator of strings while preserving order.
fn dedup(it: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in it {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

impl Default for IocExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ex() -> IocExtractor {
        IocExtractor::new()
    }

    #[test]
    fn test_extract_ipv4() {
        let iocs = ex().extract_from_str("ping 192.168.1.1 and 10.0.0.255");
        assert_eq!(iocs.ipv4.len(), 2);
        assert!(iocs.ipv4.contains(&"192.168.1.1".to_owned()));
    }

    #[test]
    fn test_extract_url() {
        let iocs = ex().extract_from_str("GET http://evil.com/payload.exe HTTP/1.1");
        assert!(!iocs.urls.is_empty());
        assert!(iocs.urls[0].starts_with("http://evil.com"));
    }

    #[test]
    fn test_extract_email() {
        let iocs = ex().extract_from_str("contact bad@actor.com for details");
        assert!(iocs.emails.contains(&"bad@actor.com".to_owned()));
    }

    #[test]
    fn test_extract_md5() {
        let hash = "d41d8cd98f00b204e9800998ecf8427e";
        let iocs = ex().extract_from_str(&format!("hash: {hash}"));
        assert!(iocs.md5.contains(&hash.to_owned()));
    }

    #[test]
    fn test_extract_sha256() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let iocs = ex().extract_from_str(hash);
        assert!(iocs.sha256.contains(&hash.to_owned()));
    }

    #[test]
    fn test_sha512_not_sha256() {
        // 128-char SHA-512 (canonical hash of the empty string); the 128-char
        // regex must match first so this is never classified as SHA-256.
        let long = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let iocs = ex().extract_from_str(long);
        assert!(iocs.sha512.contains(&long.to_lowercase()));
        assert!(
            !iocs
                .sha256
                .iter()
                .any(|s| s.len() == 64 && long.starts_with(s.as_str()))
        );
    }

    #[test]
    fn test_extract_domain() {
        let iocs = ex().extract_from_str("connected to evil.example.com via DNS");
        assert!(iocs.domains.iter().any(|d| d.contains("evil.example.com")));
    }

    #[test]
    fn test_extract_eth_address() {
        let addr = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae";
        let iocs = ex().extract_from_str(addr);
        assert!(iocs.ethereum_addresses.contains(&addr.to_owned()));
    }

    #[test]
    fn test_extract_registry_key() {
        let text = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let iocs = ex().extract_from_str(text);
        assert!(!iocs.registry_keys.is_empty());
    }

    #[test]
    fn test_extract_win_path() {
        let text = r"C:\Windows\System32\cmd.exe";
        let iocs = ex().extract_from_str(text);
        assert!(!iocs.file_paths.is_empty());
        assert!(iocs.file_paths.iter().any(|p| p.contains("cmd.exe")));
    }

    #[test]
    fn test_extract_from_bytes() {
        let data = b"connected to 1.2.3.4\x00garbage\xff";
        let iocs = ex().extract_from_bytes(data);
        assert!(iocs.ipv4.contains(&"1.2.3.4".to_owned()));
    }

    #[test]
    fn test_total_count() {
        let iocs = ex().extract_from_str(
            "ip: 1.2.3.4, domain: evil.com, md5: d41d8cd98f00b204e9800998ecf8427e",
        );
        assert!(iocs.total_count() >= 2);
    }

    #[test]
    fn test_to_ioc_list() {
        let iocs = ex().extract_from_str("1.2.3.4 evil.com");
        let list = iocs.to_ioc_list();
        assert!(list.iter().any(|i| i.ioc_type == IoCType::Ip));
        assert!(list.iter().any(|i| i.ioc_type == IoCType::Domain));
    }

    #[test]
    fn test_dedup() {
        let text = "8.8.8.8 and 8.8.8.8 again";
        let iocs = ex().extract_from_str(text);
        assert_eq!(
            iocs.ipv4
                .iter()
                .filter(|ip| ip.as_str() == "8.8.8.8")
                .count(),
            1
        );
    }
}
