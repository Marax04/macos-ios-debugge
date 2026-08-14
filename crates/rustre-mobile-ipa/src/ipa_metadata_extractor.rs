//! IPA metadata extraction — structured representation of all human-readable
//! metadata embedded in an iOS application bundle.
//!
//! This module parses `Info.plist`, `embedded.mobileprovision`, and other
//! well-known bundle artefacts to produce an [`AppMetadata`] record that can
//! be serialised and compared across IPA versions.

use std::collections::HashMap;

// ── PlistValue re-export / thin shim ─────────────────────────────────────────

/// A dynamically typed plist value.  Mirrors the variant set understood by the
/// crate's own `plist_parser`, but is self-contained so that callers of this
/// module do not need to import the parser directly.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PlistValue {
    /// Boolean scalar.
    Bool(bool),
    /// Integer scalar (signed 64-bit covers all plist integer ranges).
    Integer(i64),
    /// Floating-point scalar.
    Real(f64),
    /// UTF-8 string.
    String(String),
    /// Base64-encoded data bytes (stored decoded).
    Data(Vec<u8>),
    /// RFC-3339 date string.
    Date(String),
    /// Ordered array of values.
    Array(Vec<Self>),
    /// Key-value dictionary.
    Dict(HashMap<String, Self>),
}

impl PlistValue {
    /// Return the contained string slice, if this is a `String` variant.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    /// Return the contained boolean, if this is a `Bool` variant.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Return the contained integer, if this is an `Integer` variant.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        if let Self::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    /// Return the contained dict, if this is a `Dict` variant.
    #[must_use]
    pub const fn as_dict(&self) -> Option<&HashMap<String, Self>> {
        if let Self::Dict(d) = self {
            Some(d)
        } else {
            None
        }
    }

    /// Return the contained array, if this is an `Array` variant.
    #[must_use]
    pub const fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(a) = self {
            Some(a.as_slice())
        } else {
            None
        }
    }

    /// Recursively look up a dot-separated key path inside nested dicts.
    ///
    /// `"CFBundleURLTypes.0.CFBundleURLSchemes"` – array index as decimal.
    #[must_use]
    pub fn get_path(&self, path: &str) -> Option<&Self> {
        let mut current = self;
        for part in path.split('.') {
            match current {
                Self::Dict(d) => {
                    current = d.get(part)?;
                }
                Self::Array(a) => {
                    let idx: usize = part.parse().ok()?;
                    current = a.get(idx)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }
}

// ── Metadata extraction error ─────────────────────────────────────────────────

/// Errors that can occur during metadata extraction.
#[derive(Debug)]
pub enum MetadataError {
    /// Required plist key missing.
    MissingKey(String),
    /// Plist value has an unexpected type.
    TypeMismatch { key: String, expected: &'static str },
    /// Raw bytes could not be decoded as UTF-8.
    Utf8(String),
    /// The supplied slice is too short to contain a valid plist.
    TooShort,
    /// Generic parse failure.
    Parse(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey(k) => write!(f, "missing plist key: {k}"),
            Self::TypeMismatch { key, expected } => {
                write!(f, "type mismatch for key '{key}': expected {expected}")
            }
            Self::Utf8(s) => write!(f, "UTF-8 decode error: {s}"),
            Self::TooShort => write!(f, "data too short for plist"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for MetadataError {}

// ── URL scheme ────────────────────────────────────────────────────────────────

/// A single registered URL scheme entry from `CFBundleURLTypes`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UrlScheme {
    /// Schemes registered (e.g. `["myapp", "myapp-debug"]`).
    pub schemes: Vec<String>,
    /// Role: `"Editor"`, `"Viewer"`, `"Shell"`, or `"None"`.
    pub role: String,
    /// Optional human-readable name for the URL type.
    pub name: Option<String>,
}

// ── Document type ─────────────────────────────────────────────────────────────

/// A file-type handler declared in `CFBundleDocumentTypes`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DocumentType {
    /// Display name.
    pub name: String,
    /// UTI content types handled.
    pub content_types: Vec<String>,
    /// Handler role: `"Editor"` | `"Viewer"` | `"Shell"` | `"QLThumbnail"`.
    pub role: String,
}

// ── Privacy permission entry ──────────────────────────────────────────────────

/// A `NS*UsageDescription` entry from `Info.plist`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivacyPermission {
    /// The plist key, e.g. `"NSCameraUsageDescription"`.
    pub key: String,
    /// The user-facing justification string.
    pub description: String,
}

// ── AppMetadata ───────────────────────────────────────────────────────────────

/// Structured application metadata extracted from an IPA's `Info.plist` and
/// bundle structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppMetadata {
    // ── Identity ────────────────────────────────────────────────────────────
    /// `CFBundleIdentifier`
    pub bundle_id: String,
    /// `CFBundleName`
    pub bundle_name: String,
    /// `CFBundleDisplayName` (may equal `bundle_name`).
    pub display_name: String,
    /// `CFBundleShortVersionString` – marketing version.
    pub short_version: String,
    /// `CFBundleVersion` – build number.
    pub build_version: String,
    /// `CFBundleExecutable` – name of the main binary inside the `.app`.
    pub executable: String,

    // ── Platform requirements ────────────────────────────────────────────────
    /// `MinimumOSVersion`
    pub minimum_os_version: String,
    /// `CFBundleSupportedPlatforms`
    pub supported_platforms: Vec<String>,
    /// `UIDeviceFamily`: 1 = iPhone, 2 = iPad, …
    pub device_families: Vec<u32>,
    /// `DTPlatformVersion`
    pub sdk_version: Option<String>,
    /// `DTXcode` – Xcode build string used to compile.
    pub xcode_version: Option<String>,

    // ── Capabilities ─────────────────────────────────────────────────────────
    /// `UIRequiredDeviceCapabilities`
    pub required_capabilities: Vec<String>,
    /// `UIBackgroundModes`
    pub background_modes: Vec<String>,

    // ── URL / document handling ──────────────────────────────────────────────
    /// Registered URL schemes (`CFBundleURLTypes`).
    pub url_schemes: Vec<UrlScheme>,
    /// Document types handled (`CFBundleDocumentTypes`).
    pub document_types: Vec<DocumentType>,

    // ── Privacy ──────────────────────────────────────────────────────────────
    /// `NS*UsageDescription` privacy permission strings.
    pub privacy_permissions: Vec<PrivacyPermission>,
    /// `NSPrivacyCollectedDataTypes` (iOS 17+).
    pub privacy_manifest_types: Vec<String>,

    // ── App Transport Security ───────────────────────────────────────────────
    /// `NSAllowsArbitraryLoads` from `NSAppTransportSecurity`.
    pub ats_allows_arbitrary_loads: bool,
    /// Exception domains declared under `NSAppTransportSecurity`.
    pub ats_exception_domains: Vec<String>,

    // ── Extras ───────────────────────────────────────────────────────────────
    /// All raw top-level keys from `Info.plist` (key names only).
    pub raw_keys: Vec<String>,
}

impl AppMetadata {
    /// Return `true` if the application targets both iPhone and iPad.
    #[must_use]
    pub fn is_universal(&self) -> bool {
        self.device_families.contains(&1) && self.device_families.contains(&2)
    }

    /// Return the minimum OS version as `(major, minor)` if parseable.
    #[must_use]
    pub fn parsed_min_os(&self) -> Option<(u32, u32)> {
        let mut parts = self.minimum_os_version.splitn(3, '.');
        let major: u32 = parts.next()?.parse().ok()?;
        let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        Some((major, minor))
    }

    /// Return all URL scheme strings (flat list).
    #[must_use]
    pub fn flat_url_schemes(&self) -> Vec<&str> {
        self.url_schemes
            .iter()
            .flat_map(|u| u.schemes.iter().map(std::string::String::as_str))
            .collect()
    }

    /// Return the number of privacy permission keys declared.
    #[must_use]
    pub const fn permission_count(&self) -> usize {
        self.privacy_permissions.len()
    }
}

// ── IpaMetadataExtractor ──────────────────────────────────────────────────────

/// Extracts [`AppMetadata`] from the raw bytes of an `Info.plist` file.
///
/// Only XML plists are supported directly by this extractor (binary plist
/// support is delegated to [`crate::plist_binary`]).  The extractor degrades
/// gracefully: missing optional keys produce `None` / empty collections rather
/// than errors.
pub struct IpaMetadataExtractor {
    /// When `true`, unknown / extra keys are recorded in `AppMetadata::raw_keys`.
    pub record_raw_keys: bool,
    /// When `true`, extraction continues even if mandatory keys are absent,
    /// substituting empty strings.
    pub lenient: bool,
}

impl Default for IpaMetadataExtractor {
    fn default() -> Self {
        Self { record_raw_keys: true, lenient: false }
    }
}

impl IpaMetadataExtractor {
    /// Create a new extractor with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a lenient extractor that never fails on missing keys.
    #[must_use]
    pub const fn lenient() -> Self {
        Self { record_raw_keys: true, lenient: true }
    }

    /// Parse an `Info.plist` from its raw UTF-8 XML bytes and return structured
    /// [`AppMetadata`].
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the bytes are not valid UTF-8 or the plist XML cannot be parsed.
    pub fn extract_from_xml(&self, xml: &[u8]) -> Result<AppMetadata, MetadataError> {
        let text = std::str::from_utf8(xml)
            .map_err(|e| MetadataError::Utf8(e.to_string()))?;

        let dict = parse_xml_plist_to_dict(text)?;

        let require_string = |key: &str| -> Result<String, MetadataError> {
            match dict.get(key) {
                Some(PlistValue::String(s)) => Ok(s.clone()),
                Some(_) => Err(MetadataError::TypeMismatch {
                    key: key.to_string(),
                    expected: "string",
                }),
                None if self.lenient => Ok(String::new()),
                None => Err(MetadataError::MissingKey(key.to_string())),
            }
        };

        let optional_string = |key: &str| -> Option<String> {
            match dict.get(key) {
                Some(PlistValue::String(s)) => Some(s.clone()),
                _ => None,
            }
        };

        let string_array = |key: &str| -> Vec<String> {
            match dict.get(key) {
                Some(PlistValue::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            }
        };

        let u32_array = |key: &str| -> Vec<u32> {
            match dict.get(key) {
                Some(PlistValue::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_i64().and_then(|i| u32::try_from(i).ok()))
                    .collect(),
                _ => Vec::new(),
            }
        };

        // ── Identity ─────────────────────────────────────────────────────────
        let bundle_id = require_string("CFBundleIdentifier")?;
        let bundle_name = require_string("CFBundleName")
            .or_else(|_| require_string("CFBundleDisplayName"))
            .unwrap_or_default();
        let display_name = optional_string("CFBundleDisplayName")
            .unwrap_or_else(|| bundle_name.clone());
        let short_version = optional_string("CFBundleShortVersionString")
            .unwrap_or_else(|| "0.0".into());
        let build_version = optional_string("CFBundleVersion")
            .unwrap_or_else(|| "0".into());
        let executable = require_string("CFBundleExecutable")?;

        // ── Platform requirements ─────────────────────────────────────────────
        let minimum_os_version = optional_string("MinimumOSVersion")
            .unwrap_or_else(|| "0.0".into());
        let supported_platforms = string_array("CFBundleSupportedPlatforms");
        let device_families = u32_array("UIDeviceFamily");
        let sdk_version = optional_string("DTPlatformVersion");
        let xcode_version = optional_string("DTXcode");

        // ── Capabilities ──────────────────────────────────────────────────────
        let required_capabilities = string_array("UIRequiredDeviceCapabilities");
        let background_modes = string_array("UIBackgroundModes");

        // ── URL schemes ───────────────────────────────────────────────────────
        let url_schemes = extract_url_schemes(&dict);

        // ── Document types ────────────────────────────────────────────────────
        let document_types = extract_document_types(&dict);

        // ── Privacy permissions ───────────────────────────────────────────────
        let privacy_permissions = extract_privacy_permissions(&dict);

        // ── Privacy manifest (iOS 17+) ────────────────────────────────────────
        let privacy_manifest_types =
            extract_privacy_manifest_types(&dict);

        // ── ATS ───────────────────────────────────────────────────────────────
        let (ats_allows_arbitrary_loads, ats_exception_domains) =
            extract_ats_info(&dict);

        // ── Raw keys ──────────────────────────────────────────────────────────
        let raw_keys = if self.record_raw_keys {
            dict.keys().cloned().collect()
        } else {
            Vec::new()
        };

        Ok(AppMetadata {
            bundle_id,
            bundle_name,
            display_name,
            short_version,
            build_version,
            executable,
            minimum_os_version,
            supported_platforms,
            device_families,
            sdk_version,
            xcode_version,
            required_capabilities,
            background_modes,
            url_schemes,
            document_types,
            privacy_permissions,
            privacy_manifest_types,
            ats_allows_arbitrary_loads,
            ats_exception_domains,
            raw_keys,
        })
    }
}

// ── Extraction helpers ────────────────────────────────────────────────────────

fn extract_url_schemes(dict: &HashMap<String, PlistValue>) -> Vec<UrlScheme> {
    let Some(PlistValue::Array(types)) = dict.get("CFBundleURLTypes") else {
        return Vec::new();
    };
    types
        .iter()
        .filter_map(|entry| {
            let d = entry.as_dict()?;
            let schemes = match d.get("CFBundleURLSchemes") {
                Some(PlistValue::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => return None,
            };
            let role = d
                .get("CFBundleTypeRole")
                .and_then(|v| v.as_str())
                .unwrap_or("None")
                .to_string();
            let name = d
                .get("CFBundleURLName")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some(UrlScheme { schemes, role, name })
        })
        .collect()
}

fn extract_document_types(dict: &HashMap<String, PlistValue>) -> Vec<DocumentType> {
    let Some(PlistValue::Array(types)) = dict.get("CFBundleDocumentTypes") else {
        return Vec::new();
    };
    types
        .iter()
        .filter_map(|entry| {
            let d = entry.as_dict()?;
            let name = d
                .get("CFBundleTypeName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_types = match d.get("LSItemContentTypes") {
                Some(PlistValue::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            };
            let role = d
                .get("CFBundleTypeRole")
                .and_then(|v| v.as_str())
                .unwrap_or("Viewer")
                .to_string();
            Some(DocumentType { name, content_types, role })
        })
        .collect()
}

fn extract_privacy_permissions(
    dict: &HashMap<String, PlistValue>,
) -> Vec<PrivacyPermission> {
    dict.iter()
        .filter(|(k, _)| k.starts_with("NS") && k.ends_with("UsageDescription"))
        .map(|(k, v)| PrivacyPermission {
            key: k.clone(),
            description: v.as_str().unwrap_or("").to_string(),
        })
        .collect()
}

fn extract_privacy_manifest_types(
    dict: &HashMap<String, PlistValue>,
) -> Vec<String> {
    match dict.get("NSPrivacyCollectedDataTypes") {
        Some(PlistValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| {
                let d = v.as_dict()?;
                d.get("NSPrivacyCollectedDataType")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn extract_ats_info(dict: &HashMap<String, PlistValue>) -> (bool, Vec<String>) {
    let Some(PlistValue::Dict(ats)) = dict.get("NSAppTransportSecurity") else {
        return (false, Vec::new());
    };
    let allows_arbitrary = ats
        .get("NSAllowsArbitraryLoads")
        .and_then(PlistValue::as_bool)
        .unwrap_or(false);
    let exception_domains: Vec<String> = match ats.get("NSExceptionDomains") {
        Some(PlistValue::Dict(d)) => d.keys().cloned().collect(),
        _ => Vec::new(),
    };
    (allows_arbitrary, exception_domains)
}

// ── Minimal XML plist parser ──────────────────────────────────────────────────
// Parses only the subset of plist XML produced by Xcode / plutil without
// pulling in an external XML library.

fn parse_xml_plist_to_dict(
    xml: &str,
) -> Result<HashMap<String, PlistValue>, MetadataError> {
    // Locate the outermost <dict> block.
    let start = xml
        .find("<dict>")
        .ok_or_else(|| MetadataError::Parse("no <dict> found".into()))?;
    let end = xml
        .rfind("</dict>")
        .ok_or_else(|| MetadataError::Parse("no </dict> found".into()))?;
    let body = &xml[start + 6..end];
    parse_dict_body(body)
}

fn parse_dict_body(body: &str) -> Result<HashMap<String, PlistValue>, MetadataError> {
    let mut map = HashMap::new();
    let tokens = tokenise(body);
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].0 == "key" {
            let key = tokens[i].1.clone();
            i += 1;
            if i < tokens.len() {
                let val = parse_value(&tokens, &mut i)?;
                map.insert(key, val);
            }
        } else {
            i += 1;
        }
    }
    Ok(map)
}

fn parse_value(
    tokens: &[(String, String)],
    i: &mut usize,
) -> Result<PlistValue, MetadataError> {
    if *i >= tokens.len() {
        return Err(MetadataError::Parse("unexpected end of tokens".into()));
    }
    let (tag, content) = &tokens[*i];
    *i += 1;
    match tag.as_str() {
        "string" => Ok(PlistValue::String(content.clone())),
        "integer" => content
            .parse::<i64>()
            .map(PlistValue::Integer)
            .map_err(|e| MetadataError::Parse(e.to_string())),
        "real" => content
            .parse::<f64>()
            .map(PlistValue::Real)
            .map_err(|e| MetadataError::Parse(e.to_string())),
        "true" => Ok(PlistValue::Bool(true)),
        "false" => Ok(PlistValue::Bool(false)),
        "date" => Ok(PlistValue::Date(content.clone())),
        "data" => Ok(PlistValue::Data(content.as_bytes().to_vec())),
        "array" => {
            // content holds the inner raw body
            let inner_tokens = tokenise(content);
            let mut j = 0;
            let mut arr = Vec::new();
            while j < inner_tokens.len() {
                arr.push(parse_value(&inner_tokens, &mut j)?);
            }
            Ok(PlistValue::Array(arr))
        }
        "dict" => {
            let inner = parse_dict_body(content)?;
            Ok(PlistValue::Dict(inner))
        }
        other => Err(MetadataError::Parse(format!("unknown tag: {other}"))),
    }
}

/// Very small XML tokeniser that recognises plist element tags and their text
/// content.  Returns `(tag_name, inner_text)` pairs.
fn tokenise(src: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();
    let mut rest = src;
    while let Some(open) = rest.find('<') {
        rest = &rest[open + 1..];
        // Find tag name end (space or '>').
        let tag_end = rest
            .find(|c: char| c == '>' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let tag = &rest[..tag_end];
        // Skip self-closing and processing instructions.
        if tag.starts_with('?') || tag.starts_with('/') || tag.starts_with('!') {
            if let Some(close) = rest.find('>') {
                rest = &rest[close + 1..];
            }
            continue;
        }
        // Advance past the '>'
        let close_angle = rest.find('>').unwrap_or(rest.len());
        rest = &rest[close_angle + 1..];
        // Decide self-closing BEFORE trimming: the trim removes the very '/'
        // the check was looking for, so `tag.ends_with('/')` could never be
        // true and this branch was unreachable. A `<true/>` therefore fell
        // through to the container path, searched for a `</true>` that does not
        // exist, and `break` discarded the rest of the document — which is why
        // `<key>NSAllowsArbitraryLoads</key><true/>` yielded the key with no
        // value at all.
        let self_closing = tag.trim_end().ends_with('/');
        let tag = tag.trim_end_matches(|c: char| c == '/' || c.is_ascii_whitespace());
        if self_closing {
            tokens.push((tag.to_string(), String::new()));
            continue;
        }
        let closing = format!("</{tag}>");
        if let Some(end_pos) = find_matching_close(rest, tag) {
            let inner = &rest[..end_pos];
            // For container tags, store the raw inner content.
            tokens.push((tag.to_string(), inner.to_string()));
            rest = &rest[end_pos + closing.len()..];
        } else {
            // Unmatched tag — skip.
            break;
        }
    }
    tokens
}

/// Find the position in `src` of the matching `</tag>`, handling nesting.
///
/// `pub(crate)` so the bplist reader in `lib.rs` can share it: it was
/// using a plain `find("</dict>")`, which stops at the FIRST close tag —
/// the one belonging to the *inner* dictionary — and truncated the outer
/// body mid-structure.
pub(crate) fn find_matching_close(src: &str, tag: &str) -> Option<usize> {
    let open_tag = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut depth = 1usize;
    let mut pos = 0;
    while pos < src.len() {
        // Look for next open or close occurrence.
        let next_open = src[pos..].find(&open_tag).map(|p| pos + p);
        let next_close = src[pos..].find(&close_tag).map(|p| pos + p);
        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                pos = o + open_tag.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                if depth == 0 {
                    return Some(c);
                }
                pos = c + close_tag.len();
            }
            _ => break,
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_plist(extra: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.TestApp</string>
    <key>CFBundleName</key>
    <string>TestApp</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
    <key>CFBundleVersion</key>
    <string>42</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2.3</string>
    {extra}
</dict>
</plist>"#
        )
    }

    #[test]
    fn test_basic_extraction() {
        let xml = minimal_plist("");
        let extractor = IpaMetadataExtractor::new();
        let meta = extractor.extract_from_xml(xml.as_bytes()).unwrap();
        assert_eq!(meta.bundle_id, "com.example.TestApp");
        assert_eq!(meta.bundle_name, "TestApp");
        assert_eq!(meta.executable, "TestApp");
        assert_eq!(meta.build_version, "42");
        assert_eq!(meta.short_version, "1.2.3");
    }

    #[test]
    fn test_device_families() {
        let xml = minimal_plist(
            "<key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array>",
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        assert!(meta.is_universal());
    }

    #[test]
    fn test_privacy_permissions() {
        let xml = minimal_plist(
            "<key>NSCameraUsageDescription</key><string>We use camera.</string>",
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        assert_eq!(meta.permission_count(), 1);
        assert_eq!(meta.privacy_permissions[0].key, "NSCameraUsageDescription");
    }

    #[test]
    fn test_ats_arbitrary_loads() {
        let xml = minimal_plist(
            r#"<key>NSAppTransportSecurity</key>
            <dict>
                <key>NSAllowsArbitraryLoads</key><true/>
            </dict>"#,
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        assert!(meta.ats_allows_arbitrary_loads);
    }

    #[test]
    fn test_min_os_parsed() {
        let xml = minimal_plist(
            "<key>MinimumOSVersion</key><string>15.0</string>",
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        assert_eq!(meta.parsed_min_os(), Some((15, 0)));
    }

    #[test]
    fn test_plist_value_get_path() {
        let mut inner = HashMap::new();
        inner.insert("x".to_string(), PlistValue::Integer(7));
        let mut root = HashMap::new();
        root.insert("a".to_string(), PlistValue::Dict(inner));
        let root_val = PlistValue::Dict(root);
        assert_eq!(root_val.get_path("a.x"), Some(&PlistValue::Integer(7)));
        assert!(root_val.get_path("a.missing").is_none());
    }

    #[test]
    fn test_lenient_missing_executable() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict>
    <key>CFBundleIdentifier</key><string>com.x</string>
    <key>CFBundleName</key><string>X</string>
</dict></plist>"#;
        let extractor = IpaMetadataExtractor::lenient();
        let meta = extractor.extract_from_xml(xml.as_bytes()).unwrap();
        assert_eq!(meta.executable, "");
    }

    #[test]
    fn test_url_schemes_flat() {
        let xml = minimal_plist(
            r#"<key>CFBundleURLTypes</key>
            <array>
                <dict>
                    <key>CFBundleURLSchemes</key>
                    <array><string>myapp</string><string>myapp-debug</string></array>
                    <key>CFBundleTypeRole</key><string>Editor</string>
                </dict>
            </array>"#,
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        let schemes = meta.flat_url_schemes();
        assert!(schemes.contains(&"myapp"));
        assert!(schemes.contains(&"myapp-debug"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let xml = minimal_plist(
            "<key>MinimumOSVersion</key><string>16.0</string>",
        );
        let meta = IpaMetadataExtractor::new()
            .extract_from_xml(xml.as_bytes())
            .unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        let back: AppMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bundle_id, meta.bundle_id);
        assert_eq!(back.short_version, meta.short_version);
    }
}
