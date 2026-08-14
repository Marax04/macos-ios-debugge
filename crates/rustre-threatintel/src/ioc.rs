//! Indicator of Compromise (`IoC`) types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of an indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoCType {
    /// MD5 file hash.
    Md5,
    /// SHA-1 file hash.
    Sha1,
    /// SHA-256 file hash.
    Sha256,
    /// SHA-512 file hash.
    Sha512,
    /// IPv4 or IPv6 address.
    Ip,
    /// Domain name.
    Domain,
    /// Uniform resource locator.
    Url,
    /// E-mail address.
    Email,
    /// Windows registry key or value.
    Registry,
    /// File name.
    Filename,
    /// Mutex name.
    Mutex,
    /// YARA rule text.
    Yara,
}

impl fmt::Display for IoCType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Ip => "IP",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::Email => "Email",
            Self::Registry => "Registry",
            Self::Filename => "Filename",
            Self::Mutex => "Mutex",
            Self::Yara => "YARA",
        };
        f.write_str(s)
    }
}

impl IoCType {
    /// Serialise to a short string key used for storage.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Registry => "registry",
            Self::Filename => "filename",
            Self::Mutex => "mutex",
            Self::Yara => "yara",
        }
    }

    /// Parse an `IoCType` from its storage key.
    #[must_use]
    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            "ip" => Some(Self::Ip),
            "domain" => Some(Self::Domain),
            "url" => Some(Self::Url),
            "email" => Some(Self::Email),
            "registry" => Some(Self::Registry),
            "filename" => Some(Self::Filename),
            "mutex" => Some(Self::Mutex),
            "yara" => Some(Self::Yara),
            _ => None,
        }
    }
}

/// Severity level assigned to an `IoC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low impact or confidence.
    Low,
    /// Medium impact or confidence.
    Medium,
    /// High impact or confidence.
    High,
    /// Critical — immediate action required.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

/// An individual Indicator of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    /// Database row identifier (absent before first persist).
    pub id: Option<u64>,
    /// Category of this indicator.
    pub ioc_type: IoCType,
    /// The actual indicator value (hash hex string, IP, domain, etc.).
    pub value: String,
    /// Optional free-text description.
    pub description: Option<String>,
    /// Analyst-assigned tags for classification.
    pub tags: Vec<String>,
    /// Confidence score in [0, 100].
    pub confidence: u8,
    /// Severity assigned to this indicator.
    pub severity: Severity,
    /// Unix timestamp (seconds) when this `IoC` was first observed.
    pub first_seen: u64,
    /// Unix timestamp (seconds) when this `IoC` was last observed.
    pub last_seen: u64,
    /// Name or URL of the originating intelligence source.
    pub source: String,
}

impl IoC {
    /// Construct a new `IoC` with required fields and sensible defaults.
    #[must_use]
    pub const fn new(ioc_type: IoCType, value: String, source: String) -> Self {
        Self {
            id: None,
            ioc_type,
            value,
            description: None,
            tags: Vec::new(),
            confidence: 50,
            severity: Severity::Medium,
            first_seen: 0,
            last_seen: 0,
            source,
        }
    }

    /// Return `true` if this `IoC` is a network indicator.
    #[must_use]
    pub const fn is_network(&self) -> bool {
        matches!(self.ioc_type, IoCType::Ip | IoCType::Domain | IoCType::Url)
    }

    /// Return `true` if this `IoC` is a file hash.
    #[must_use]
    pub const fn is_hash(&self) -> bool {
        matches!(
            self.ioc_type,
            IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512
        )
    }
}

impl fmt::Display for IoC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (confidence={}, severity={})",
            self.ioc_type, self.value, self.confidence, self.severity
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_new_defaults() {
        let ioc = IoC::new(IoCType::Sha256, "abc123".to_string(), "vt".to_string());
        assert!(ioc.id.is_none());
        assert_eq!(ioc.ioc_type, IoCType::Sha256);
        assert_eq!(ioc.value, "abc123");
        assert_eq!(ioc.confidence, 50);
        assert_eq!(ioc.severity, Severity::Medium);
        assert!(ioc.tags.is_empty());
    }

    #[test]
    fn test_ioc_is_hash() {
        assert!(IoC::new(IoCType::Md5, String::new(), String::new()).is_hash());
        assert!(IoC::new(IoCType::Sha1, String::new(), String::new()).is_hash());
        assert!(IoC::new(IoCType::Sha256, String::new(), String::new()).is_hash());
        assert!(IoC::new(IoCType::Sha512, String::new(), String::new()).is_hash());
        assert!(!IoC::new(IoCType::Ip, String::new(), String::new()).is_hash());
    }

    #[test]
    fn test_ioc_is_network() {
        assert!(IoC::new(IoCType::Ip, String::new(), String::new()).is_network());
        assert!(IoC::new(IoCType::Domain, String::new(), String::new()).is_network());
        assert!(IoC::new(IoCType::Url, String::new(), String::new()).is_network());
        assert!(!IoC::new(IoCType::Md5, String::new(), String::new()).is_network());
    }

    #[test]
    fn test_ioc_type_display() {
        assert_eq!(IoCType::Md5.to_string(), "MD5");
        assert_eq!(IoCType::Ip.to_string(), "IP");
        assert_eq!(IoCType::Domain.to_string(), "Domain");
        assert_eq!(IoCType::Yara.to_string(), "YARA");
    }

    #[test]
    fn test_ioc_type_roundtrip() {
        let types = [
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Sha512,
            IoCType::Ip,
            IoCType::Domain,
            IoCType::Url,
            IoCType::Email,
            IoCType::Registry,
            IoCType::Filename,
            IoCType::Mutex,
            IoCType::Yara,
        ];
        for ty in &types {
            let key = ty.as_str();
            let parsed =
                IoCType::from_key(key).unwrap_or_else(|| panic!("round-trip failed for {key}"));
            assert_eq!(&parsed, ty);
        }
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::Low.to_string(), "Low");
    }

    #[test]
    fn test_ioc_display() {
        let ioc = IoC::new(
            IoCType::Domain,
            "evil.example.com".to_string(),
            "test".to_string(),
        );
        let s = ioc.to_string();
        assert!(s.contains("Domain"));
        assert!(s.contains("evil.example.com"));
    }

    #[test]
    fn test_ioc_serialization() {
        let mut ioc = IoC::new(
            IoCType::Domain,
            "malware.example.com".to_string(),
            "feed".to_string(),
        );
        ioc.tags.push("c2".to_string());
        ioc.confidence = 90;
        let json = serde_json::to_string(&ioc).unwrap();
        let decoded: IoC = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.value, "malware.example.com");
        assert_eq!(decoded.tags, vec!["c2"]);
        assert_eq!(decoded.confidence, 90);
    }
}
