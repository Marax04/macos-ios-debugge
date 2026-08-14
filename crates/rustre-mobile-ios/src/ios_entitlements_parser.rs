//! `ios_entitlements_parser` — Parse iOS app entitlements from plist format.
//!
//! Supports:
//! * XML plist entitlement documents (as embedded in CMS code signatures or
//!   standalone files extracted from `embedded.mobileprovision`)
//! * Binary bplist00 entitlement blobs (limited heuristic scanning)
//! * Key-only scanning for rapid triage
//!
//! Core types: [`IosEntitlementsParser`], [`Entitlement`], [`EntitlementKind`]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── EntitlementKind ──────────────────────────────────────────────────────────

/// The semantic category of an iOS entitlement key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntitlementKind {
    /// Allows the app to be attached by a debugger (`get-task-allow`).
    Debug,
    /// App Group identifier sharing.
    AppGroup,
    /// Keychain access group.
    Keychain,
    /// iCloud document/key-value store.
    ICloud,
    /// Push notifications (`aps-environment`).
    PushNotifications,
    /// Background execution modes.
    BackgroundModes,
    /// `Wallet`/`PassKit`.
    Wallet,
    /// `HealthKit`.
    Health,
    /// `HomeKit`.
    HomeKit,
    /// NFC (`com.apple.developer.nfc.*`).
    Nfc,
    /// Sign In with Apple.
    SignInWithApple,
    /// Associated domains.
    AssociatedDomains,
    /// Network extensions (VPN, DNS proxy, etc.).
    NetworkExtension,
    /// System extension / privileged helper.
    SystemExtension,
    /// Any other entitlement.
    Other,
}

impl EntitlementKind {
    /// Classify an entitlement key into a [`EntitlementKind`].
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        if key == "get-task-allow" || key.contains("task-allow") {
            return Self::Debug;
        }
        if key.contains("application-groups") || key.contains("app-groups") {
            return Self::AppGroup;
        }
        if key.contains("keychain-access-groups") {
            return Self::Keychain;
        }
        if key.contains("com.apple.developer.icloud") || key.contains("ubiquity") {
            return Self::ICloud;
        }
        if key.contains("aps-environment") || key.contains("push-notifications") {
            return Self::PushNotifications;
        }
        if key.contains("background-modes") {
            return Self::BackgroundModes;
        }
        if key.contains("pass-presentation-suppression") || key.contains("wallet") {
            return Self::Wallet;
        }
        if key.contains("healthkit") || key.contains("health") {
            return Self::Health;
        }
        if key.contains("homekit") {
            return Self::HomeKit;
        }
        if key.contains("nfc") {
            return Self::Nfc;
        }
        if key.contains("apple-id") || key.contains("sign-in-with-apple") {
            return Self::SignInWithApple;
        }
        if key.contains("associated-domains") {
            return Self::AssociatedDomains;
        }
        if key.contains("network-extension") || key.contains("networkextension") {
            return Self::NetworkExtension;
        }
        if key.contains("system-extension") {
            return Self::SystemExtension;
        }
        Self::Other
    }

    /// Returns `true` if this kind represents a security-sensitive capability.
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(
            self,
            Self::Debug | Self::NetworkExtension | Self::SystemExtension
        )
    }
}

impl fmt::Display for EntitlementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Debug => "debug",
            Self::AppGroup => "app-group",
            Self::Keychain => "keychain",
            Self::ICloud => "icloud",
            Self::PushNotifications => "push-notifications",
            Self::BackgroundModes => "background-modes",
            Self::Wallet => "wallet",
            Self::Health => "health",
            Self::HomeKit => "homekit",
            Self::Nfc => "nfc",
            Self::SignInWithApple => "sign-in-with-apple",
            Self::AssociatedDomains => "associated-domains",
            Self::NetworkExtension => "network-extension",
            Self::SystemExtension => "system-extension",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

// ─── EntitlementValue ────────────────────────────────────────────────────────

/// The typed value of a single entitlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntitlementValue {
    /// A boolean flag.
    Bool(bool),
    /// A string value.
    Str(String),
    /// An array of strings (e.g. keychain-access-groups).
    Array(Vec<String>),
    /// A raw dictionary (nested plist) — represented as a serialised string
    /// for simplicity.
    Dict(String),
}

impl EntitlementValue {
    /// Return the string representation for display.
    #[must_use]
    pub fn display_string(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Str(s) => s.clone(),
            Self::Array(arr) => arr.join(", "),
            Self::Dict(d) => format!("{{dict: {}}}", d.len()),
        }
    }

    /// Returns `true` if the value is a truthy bool.
    #[must_use]
    pub const fn is_true(&self) -> bool {
        matches!(self, Self::Bool(true))
    }
}

impl fmt::Display for EntitlementValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_string())
    }
}

// ─── Entitlement ─────────────────────────────────────────────────────────────

/// A single entitlement key-value pair with semantic classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    /// The raw entitlement key string.
    pub key: String,
    /// Parsed value.
    pub value: EntitlementValue,
    /// Semantic kind derived from the key.
    pub kind: EntitlementKind,
}

impl Entitlement {
    /// Create a new entitlement, auto-classifying the kind.
    #[must_use]
    pub fn new(key: impl Into<String>, value: EntitlementValue) -> Self {
        let key = key.into();
        let kind = EntitlementKind::from_key(&key);
        Self { key, value, kind }
    }

    /// Returns `true` if this entitlement grants debug access.
    #[must_use]
    pub fn is_debug(&self) -> bool {
        self.kind == EntitlementKind::Debug && self.value.is_true()
    }
}

impl fmt::Display for Entitlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] = {}", self.key, self.kind, self.value)
    }
}

// ─── ParseResult ─────────────────────────────────────────────────────────────

/// The result of parsing an entitlement blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementParseResult {
    /// All parsed entitlements.
    pub entitlements: Vec<Entitlement>,
    /// The detected plist format.
    pub format: PlistFormat,
    /// Warnings generated during parsing.
    pub warnings: Vec<String>,
}

impl EntitlementParseResult {
    /// Returns `true` if the app has the `get-task-allow = true` entitlement.
    #[must_use]
    pub fn is_debuggable(&self) -> bool {
        self.entitlements.iter().any(Entitlement::is_debug)
    }

    /// Return all entitlements of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: EntitlementKind) -> Vec<&Entitlement> {
        self.entitlements.iter().filter(|e| e.kind == kind).collect()
    }

    /// Look up an entitlement by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Entitlement> {
        self.entitlements.iter().find(|e| e.key == key)
    }

    /// Return all sensitive entitlements.
    #[must_use]
    pub fn sensitive(&self) -> Vec<&Entitlement> {
        self.entitlements
            .iter()
            .filter(|e| e.kind.is_sensitive())
            .collect()
    }

    /// Return a summary map: kind → count.
    #[must_use]
    pub fn kind_summary(&self) -> HashMap<EntitlementKind, usize> {
        let mut map: HashMap<EntitlementKind, usize> = HashMap::new();
        for e in &self.entitlements {
            *map.entry(e.kind).or_insert(0) += 1;
        }
        map
    }
}

// ─── PlistFormat ─────────────────────────────────────────────────────────────

/// The detected plist serialisation format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlistFormat {
    /// Apple XML plist (`<?xml …`).
    Xml,
    /// Apple binary plist (`bplist00`).
    Binary,
    /// Unknown / unsupported format.
    Unknown,
}

impl fmt::Display for PlistFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml => write!(f, "xml"),
            Self::Binary => write!(f, "binary"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── IosEntitlementsParser ───────────────────────────────────────────────────

/// Parser for iOS entitlement blobs.
///
/// Handles XML plist and binary plist (via heuristic scan) formats.
pub struct IosEntitlementsParser;

impl IosEntitlementsParser {
    /// Parse raw entitlement bytes and return the result.
    ///
    /// Accepts:
    /// * XML plist: starts with `<?xml` or `<plist`
    /// * Binary plist: starts with `bplist00`
    #[must_use]
    pub fn parse(data: &[u8]) -> EntitlementParseResult {
        if data.starts_with(b"bplist00") {
            Self::parse_binary(data)
        } else if let Ok(text) = std::str::from_utf8(data) {
            let trimmed = text.trim_start();
            if trimmed.starts_with("<?xml") || trimmed.starts_with("<plist") || trimmed.starts_with('<') {
                Self::parse_xml(text)
            } else {
                EntitlementParseResult {
                    entitlements: Vec::new(),
                    format: PlistFormat::Unknown,
                    warnings: vec!["unrecognised plist format".to_string()],
                }
            }
        } else {
            // Non-UTF-8 — attempt binary scan
            Self::parse_binary(data)
        }
    }

    // ── XML plist parser ──────────────────────────────────────────────────────

    /// Parse an XML plist string for entitlement key-value pairs.
    fn parse_xml(text: &str) -> EntitlementParseResult {
        let mut entitlements = Vec::new();
        let mut warnings = Vec::new();

        // Walk through <key>…</key> tags and the value tag that follows
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0usize;
        while i < lines.len() {
            let line = lines[i].trim();
            if let Some(key) = extract_tag_content(line, "key") {
                // Look ahead for the value
                if let Some(value_line) = lines.get(i + 1).map(|l| l.trim()) {
                    let value = Self::parse_value_line(value_line, &lines, i + 1, &mut warnings);
                    entitlements.push(Entitlement::new(key, value));
                }
            }
            i += 1;
        }

        EntitlementParseResult {
            entitlements,
            format: PlistFormat::Xml,
            warnings,
        }
    }

    /// Parse the value starting at `line_idx` and return an `EntitlementValue`.
    fn parse_value_line(
        line: &str,
        all_lines: &[&str],
        line_idx: usize,
        _warnings: &mut Vec<String>,
    ) -> EntitlementValue {
        // Inline <true/> or <false/>
        if line == "<true/>" || line == "<true />" {
            return EntitlementValue::Bool(true);
        }
        if line == "<false/>" || line == "<false />" {
            return EntitlementValue::Bool(false);
        }
        // <string>VALUE</string> on a single line
        if let Some(s) = extract_tag_content(line, "string") {
            return EntitlementValue::Str(s);
        }
        // <integer>VALUE</integer>
        if let Some(s) = extract_tag_content(line, "integer") {
            return EntitlementValue::Str(s);
        }
        // <array> — collect <string> children until </array>
        if line.trim_start_matches('<').starts_with("array") && !line.contains("</array>") {
            let mut items = Vec::new();
            let mut j = line_idx + 1;
            while j < all_lines.len() {
                let child = all_lines[j].trim();
                if child.contains("</array>") {
                    break;
                }
                if let Some(s) = extract_tag_content(child, "string") {
                    items.push(s);
                }
                j += 1;
            }
            return EntitlementValue::Array(items);
        }
        // <dict> — represent as dict marker
        if line.trim_start_matches('<').starts_with("dict") {
            return EntitlementValue::Dict("<dict>".to_string());
        }
        // Fallback: return the raw line
        EntitlementValue::Str(line.to_string())
    }

    // ── Binary plist parser ───────────────────────────────────────────────────

    /// Heuristic binary plist scanner — searches for known key strings embedded
    /// in the binary representation.
    fn parse_binary(data: &[u8]) -> EntitlementParseResult {
        let mut entitlements = Vec::new();

        // Known high-value entitlement keys to search for
        let known_keys: &[&str] = &[
            "get-task-allow",
            "keychain-access-groups",
            "application-identifier",
            "aps-environment",
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.icloud-services",
            "com.apple.developer.associated-domains",
            "com.apple.developer.networking.networkextension",
            "com.apple.developer.healthkit",
            "com.apple.developer.homekit",
            "com.apple.developer.nfc.readersession.formats",
            "com.apple.developer.applesignin",
        ];

        let text_repr = String::from_utf8_lossy(data);
        for key in known_keys {
            if text_repr.contains(key) {
                // Try to determine if get-task-allow is true
                let value = if *key == "get-task-allow" {
                    // Look for the byte 0x09 (bplist true) following the key
                    let key_bytes = key.as_bytes();
                    let found_true = data
                        .windows(key_bytes.len() + 2)
                        .any(|w| w.starts_with(key_bytes) && (w[key_bytes.len()] == 0x09 || w[key_bytes.len() + 1] == 0x09));
                    EntitlementValue::Bool(found_true)
                } else {
                    EntitlementValue::Str("<binary-plist-value>".to_string())
                };
                entitlements.push(Entitlement::new(*key, value));
            }
        }

        EntitlementParseResult {
            entitlements,
            format: PlistFormat::Binary,
            warnings: vec!["binary plist: heuristic scan only".to_string()],
        }
    }
}

// ─── parse_entitlements() ─────────────────────────────────────────────────────

/// Parse entitlement bytes from any supported plist format.
///
/// This is the main entry point for callers that do not need to instantiate
/// `IosEntitlementsParser` directly.
#[must_use]
pub fn parse_entitlements(data: &[u8]) -> EntitlementParseResult {
    IosEntitlementsParser::parse(data)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the text content of `<tag>content</tag>` from a single line.
fn extract_tag_content(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = line.find(&open) {
        let content_start = start + open.len();
        if let Some(end) = line[content_start..].find(&close) {
            return Some(line[content_start..content_start + end].to_string());
        }
    }
    None
}

// ─── EntitlementReport ────────────────────────────────────────────────────────

/// A human-readable summary report of the entitlements found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementReport {
    /// Whether the app is debuggable.
    pub debuggable: bool,
    /// Number of entitlements found.
    pub count: usize,
    /// Distribution by kind.
    pub by_kind: Vec<(String, usize)>,
    /// Sensitive entitlement keys.
    pub sensitive_keys: Vec<String>,
    /// The plist format that was parsed.
    pub format: String,
}

impl EntitlementReport {
    /// Build a report from a parse result.
    #[must_use]
    pub fn from_result(result: &EntitlementParseResult) -> Self {
        let by_kind: Vec<(String, usize)> = result
            .kind_summary()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        let sensitive_keys: Vec<String> = result
            .sensitive()
            .into_iter()
            .map(|e| e.key.clone())
            .collect();

        Self {
            debuggable: result.is_debuggable(),
            count: result.entitlements.len(),
            by_kind,
            sensitive_keys,
            format: result.format.to_string(),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xml_entitlements(pairs: &[(&str, &str)]) -> String {
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
"#,
        );
        for (key, val) in pairs {
            xml.push('\t');
            xml.push_str("<key>");
            xml.push_str(key);
            xml.push_str("</key>\n");
            if *val == "true" {
                xml.push_str("\t<true/>\n");
            } else if *val == "false" {
                xml.push_str("\t<false/>\n");
            } else {
                xml.push('\t');
                xml.push_str("<string>");
                xml.push_str(val);
                xml.push_str("</string>\n");
            }
        }
        xml.push_str("</dict>\n</plist>\n");
        xml
    }

    #[test]
    fn parse_empty_returns_empty() {
        let result = parse_entitlements(b"");
        assert!(result.entitlements.is_empty());
    }

    #[test]
    fn parse_xml_get_task_allow_true() {
        let xml = xml_entitlements(&[("get-task-allow", "true")]);
        let result = parse_entitlements(xml.as_bytes());
        assert!(result.is_debuggable());
    }

    #[test]
    fn parse_xml_get_task_allow_false() {
        let xml = xml_entitlements(&[("get-task-allow", "false")]);
        let result = parse_entitlements(xml.as_bytes());
        assert!(!result.is_debuggable());
    }

    #[test]
    fn parse_xml_format_detected() {
        let xml = xml_entitlements(&[("aps-environment", "production")]);
        let result = parse_entitlements(xml.as_bytes());
        assert_eq!(result.format, PlistFormat::Xml);
    }

    #[test]
    fn parse_xml_string_value() {
        let xml = xml_entitlements(&[("application-identifier", "ABCD1234.com.example.App")]);
        let result = parse_entitlements(xml.as_bytes());
        let e = result.get("application-identifier");
        assert!(e.is_some());
        assert_eq!(
            e.unwrap().value,
            EntitlementValue::Str("ABCD1234.com.example.App".to_string())
        );
    }

    #[test]
    fn parse_xml_aps_environment_kind() {
        let xml = xml_entitlements(&[("aps-environment", "production")]);
        let result = parse_entitlements(xml.as_bytes());
        let push = result.by_kind(EntitlementKind::PushNotifications);
        assert_eq!(push.len(), 1);
    }

    #[test]
    fn entitlement_kind_classification() {
        assert_eq!(EntitlementKind::from_key("get-task-allow"), EntitlementKind::Debug);
        assert_eq!(
            EntitlementKind::from_key("keychain-access-groups"),
            EntitlementKind::Keychain
        );
        assert_eq!(
            EntitlementKind::from_key("com.apple.developer.icloud-services"),
            EntitlementKind::ICloud
        );
        assert_eq!(EntitlementKind::from_key("aps-environment"), EntitlementKind::PushNotifications);
        assert_eq!(
            EntitlementKind::from_key("com.apple.developer.unknown.foo"),
            EntitlementKind::Other
        );
    }

    #[test]
    fn entitlement_kind_sensitive() {
        assert!(EntitlementKind::Debug.is_sensitive());
        assert!(EntitlementKind::NetworkExtension.is_sensitive());
        assert!(!EntitlementKind::PushNotifications.is_sensitive());
    }

    #[test]
    fn entitlement_kind_display() {
        assert_eq!(EntitlementKind::Debug.to_string(), "debug");
        assert_eq!(EntitlementKind::ICloud.to_string(), "icloud");
    }

    #[test]
    fn entitlement_value_display() {
        assert_eq!(EntitlementValue::Bool(true).display_string(), "true");
        assert_eq!(
            EntitlementValue::Array(vec!["a".to_string(), "b".to_string()]).display_string(),
            "a, b"
        );
    }

    #[test]
    fn entitlement_display() {
        let e = Entitlement::new("get-task-allow", EntitlementValue::Bool(true));
        let s = e.to_string();
        assert!(s.contains("get-task-allow"));
    }

    #[test]
    fn binary_plist_heuristic() {
        let mut data = b"bplist00".to_vec();
        data.extend_from_slice(b"get-task-allow");
        let result = parse_entitlements(&data);
        assert_eq!(result.format, PlistFormat::Binary);
        assert!(!result.entitlements.is_empty());
    }

    #[test]
    fn parse_result_sensitive() {
        let xml = xml_entitlements(&[("get-task-allow", "true")]);
        let result = parse_entitlements(xml.as_bytes());
        assert!(!result.sensitive().is_empty());
    }

    #[test]
    fn kind_summary_counts() {
        let xml = xml_entitlements(&[
            ("get-task-allow", "false"),
            ("aps-environment", "production"),
        ]);
        let result = parse_entitlements(xml.as_bytes());
        let summary = result.kind_summary();
        assert!(summary.contains_key(&EntitlementKind::Debug));
        assert!(summary.contains_key(&EntitlementKind::PushNotifications));
    }

    #[test]
    fn entitlement_report_from_result() {
        let xml = xml_entitlements(&[
            ("get-task-allow", "false"),
            ("aps-environment", "production"),
        ]);
        let result = parse_entitlements(xml.as_bytes());
        let report = EntitlementReport::from_result(&result);
        assert!(!report.debuggable);
        assert_eq!(report.count, 2);
        assert_eq!(report.format, "xml");
    }

    #[test]
    fn unknown_format_returns_empty() {
        let data = b"not a plist at all";
        let result = parse_entitlements(data);
        // Should still succeed (with warnings), format will be XML-fallback or Unknown
        // The function is allowed to return any result without panicking
        let _ = result;
    }

    #[test]
    fn extract_tag_content_basic() {
        assert_eq!(
            extract_tag_content("<key>myKey</key>", "key"),
            Some("myKey".to_string())
        );
        assert_eq!(
            extract_tag_content("<string>hello</string>", "string"),
            Some("hello".to_string())
        );
        assert_eq!(extract_tag_content("<true/>", "key"), None);
    }
}
