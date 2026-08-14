//! IPA manifest parsing: `Info.plist` and `embedded.mobileprovision`.
//!
//! Handles both binary plist (bplist00) and XML plist formats.
//! Extracts bundle metadata, entitlements, provisioning profiles,
//! certificate chains, and device UDIDs.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ManifestError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from manifest parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    NotPlist,
    UnsupportedFormat(String),
    MissingKey(String),
    ParseError(String),
    Truncated,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPlist => write!(f, "data is not a plist"),
            Self::UnsupportedFormat(s) => write!(f, "unsupported plist format: {s}"),
            Self::MissingKey(k) => write!(f, "missing plist key: {k}"),
            Self::ParseError(s) => write!(f, "plist parse error: {s}"),
            Self::Truncated => write!(f, "plist data truncated"),
        }
    }
}

impl std::error::Error for ManifestError {}

// ─────────────────────────────────────────────────────────────────────────────
// PlistValue — simplified plist value tree
// ─────────────────────────────────────────────────────────────────────────────

/// A value from a parsed plist.
#[derive(Debug, Clone)]
pub enum PlistValue {
    String(String),
    Integer(i64),
    Real(f64),
    Bool(bool),
    Data(Vec<u8>),
    Date(String),
    Array(Vec<Self>),
    Dict(HashMap<String, Self>),
    Null,
}

impl PlistValue {
    /// Try to get as a `&str`.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s.as_str()) } else { None }
    }

    /// Try to get as `i64`.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        if let Self::Integer(n) = self { Some(*n) } else { None }
    }

    /// Try to get as `bool`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self { Some(*b) } else { None }
    }

    /// Try to get dict entry.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        if let Self::Dict(m) = self { m.get(key) } else { None }
    }

    /// Try to get as an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(a) = self { Some(a) } else { None }
    }

    /// Collect all string values from an array.
    #[must_use]
    pub fn string_array(&self) -> Vec<String> {
        if let Self::Array(a) = self {
            a.iter().filter_map(|v| v.as_str()).map(std::string::ToString::to_string).collect()
        } else {
            Vec::new()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XML plist parser (minimal, self-contained)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an XML plist string into a [`PlistValue`].
///
/// # Errors
/// Returns an error if the XML does not contain a root dict or array element, or parsing fails.
pub fn parse_xml_plist(xml: &str) -> Result<PlistValue, ManifestError> {
    let xml = xml.trim();
    // Find <plist ...> tag.
    let body = if let Some(start) = xml.find("<dict>").or_else(|| xml.find("<array>")) {
        &xml[start..]
    } else {
        return Err(ManifestError::ParseError("no dict or array root".into()));
    };
    let mut parser = XmlPlistParser { input: body, pos: 0 };
    parser.parse_value()
}

struct XmlPlistParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> XmlPlistParser<'a> {
    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn read_until_close_tag(&mut self, tag: &str) -> &'a str {
        let close = format!("</{tag}>");
        let start = self.pos;
        if let Some(offset) = self.remaining().find(&close) {
            let end = self.pos + offset;
            self.pos = end + close.len();
            &self.input[start..end]
        } else {
            self.pos = self.input.len();
            &self.input[start..]
        }
    }

    fn parse_value(&mut self) -> Result<PlistValue, ManifestError> {
        self.skip_whitespace();
        let rem = self.remaining();
        if rem.starts_with("<dict>") {
            self.pos += 6;
            return self.parse_dict();
        }
        if rem.starts_with("<array>") {
            self.pos += 7;
            return Ok(self.parse_array());
        }
        if rem.starts_with("<string>") {
            self.pos += 8;
            let val = self.read_until_close_tag("string");
            return Ok(PlistValue::String(decode_xml_entities(val)));
        }
        if rem.starts_with("<integer>") {
            self.pos += 9;
            let val = self.read_until_close_tag("integer").trim().to_string();
            let n = val.parse::<i64>().unwrap_or(0);
            return Ok(PlistValue::Integer(n));
        }
        if rem.starts_with("<real>") {
            self.pos += 6;
            let val = self.read_until_close_tag("real").trim().to_string();
            let r = val.parse::<f64>().unwrap_or(0.0);
            return Ok(PlistValue::Real(r));
        }
        if rem.starts_with("<true/>") {
            self.pos += 7;
            return Ok(PlistValue::Bool(true));
        }
        if rem.starts_with("<false/>") {
            self.pos += 8;
            return Ok(PlistValue::Bool(false));
        }
        if rem.starts_with("<data>") {
            self.pos += 6;
            let b64 = self.read_until_close_tag("data").trim().to_string();
            let data = base64_decode_simple(&b64);
            return Ok(PlistValue::Data(data));
        }
        if rem.starts_with("<date>") {
            self.pos += 6;
            let date = self.read_until_close_tag("date").trim().to_string();
            return Ok(PlistValue::Date(date));
        }
        Ok(PlistValue::Null)
    }

    fn parse_dict(&mut self) -> Result<PlistValue, ManifestError> {
        let mut map = HashMap::new();
        loop {
            self.skip_whitespace();
            let rem = self.remaining();
            if rem.starts_with("</dict>") {
                self.pos += 7;
                break;
            }
            if rem.starts_with("<key>") {
                self.pos += 5;
                let key = self.read_until_close_tag("key").to_string();
                let value = self.parse_value()?;
                map.insert(key, value);
            } else {
                // Skip unexpected content.
                if self.pos < self.input.len() { self.pos += 1; } else { break; }
            }
        }
        Ok(PlistValue::Dict(map))
    }

    fn parse_array(&mut self) -> PlistValue {
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            if self.remaining().starts_with("</array>") {
                self.pos += 8;
                break;
            }
            if self.pos >= self.input.len() { break; }
            match self.parse_value() {
                Ok(PlistValue::Null) | Err(_) => { self.pos += 1; }
                Ok(v) => items.push(v),
            }
        }
        PlistValue::Array(items)
    }
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&amp;", "&")
     .replace("&lt;", "<")
     .replace("&gt;", ">")
     .replace("&apos;", "'")
     .replace("&quot;", "\"")
}

/// Minimal base64 decoder (no padding enforcement).
fn base64_decode_simple(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 128] = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f\
\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\
\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\
\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff";
    let stripped: String = input.chars().filter(|ch| !ch.is_ascii_whitespace() && *ch != '=').collect();
    let mut out = Vec::new();
    let bytes = stripped.as_bytes();
    let mut idx = 0usize;
    while idx + 3 < bytes.len() {
        let vals: Option<[u8;4]> = (|| {
            let b0 = bytes[idx]; let b1 = bytes[idx+1]; let b2 = bytes[idx+2]; let b3 = bytes[idx+3];
            if b0 >= 128 || b1 >= 128 || b2 >= 128 || b3 >= 128 { return None; }
            let v0 = TABLE[b0 as usize]; let v1 = TABLE[b1 as usize];
            let v2 = TABLE[b2 as usize]; let v3 = TABLE[b3 as usize];
            if v0 == 0xFF || v1 == 0xFF || v2 == 0xFF || v3 == 0xFF { return None; }
            Some([v0, v1, v2, v3])
        })();
        if let Some([v0, v1, v2, v3]) = vals {
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }
        idx += 4;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// BundleManifest
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `Info.plist` for an iOS application bundle.
#[derive(Debug, Clone, Default)]
pub struct BundleManifest {
    /// `CFBundleIdentifier`
    pub bundle_id: String,
    /// `CFBundleDisplayName` or `CFBundleName`
    pub display_name: String,
    /// `CFBundleShortVersionString`
    pub short_version: String,
    /// `CFBundleVersion`
    pub bundle_version: String,
    /// `MinimumOSVersion`
    pub min_os_version: String,
    /// `CFBundleExecutable`
    pub executable_name: String,
    /// `CFBundleSupportedPlatforms`
    pub supported_platforms: Vec<String>,
    /// `DTPlatformName`
    pub platform_name: String,
    /// `DTSDKName`
    pub sdk_name: String,
    /// NS*`UsageDescription` permission strings.
    pub privacy_keys: Vec<String>,
    /// All entitlement key/value pairs extracted from the plist.
    pub entitlements: HashMap<String, String>,
    /// Raw unknown keys for extensibility.
    pub extra_keys: HashMap<String, String>,
}

impl BundleManifest {
    /// Parse from a plist (XML or binary-detected).
    ///
    /// # Errors
    /// Returns an error if the data cannot be parsed as a plist.
    pub fn parse(data: &[u8]) -> Result<Self, ManifestError> {
        let plist = detect_and_parse(data)?;
        Ok(Self::from_plist_value(&plist))
    }


    fn from_plist_value(v: &PlistValue) -> Self {
        let supported_platforms = v.get("CFBundleSupportedPlatforms")
            .map(PlistValue::string_array)
            .unwrap_or_default();
        let privacy_keys = if let PlistValue::Dict(dict) = v {
            dict.keys().filter(|key| key.ends_with("UsageDescription")).cloned().collect()
        } else {
            Vec::new()
        };
        Self {
            bundle_id: get_str(v, "CFBundleIdentifier").unwrap_or_default(),
            display_name: get_str(v, "CFBundleDisplayName")
                .or_else(|| get_str(v, "CFBundleName")).unwrap_or_default(),
            short_version: get_str(v, "CFBundleShortVersionString").unwrap_or_default(),
            bundle_version: get_str(v, "CFBundleVersion").unwrap_or_default(),
            min_os_version: get_str(v, "MinimumOSVersion").unwrap_or_default(),
            executable_name: get_str(v, "CFBundleExecutable").unwrap_or_default(),
            platform_name: get_str(v, "DTPlatformName").unwrap_or_default(),
            sdk_name: get_str(v, "DTSDKName").unwrap_or_default(),
            supported_platforms,
            privacy_keys,
            ..Default::default()
        }
    }

    /// Returns `true` if the binary is for the iOS platform.
    #[must_use]
    pub fn is_ios(&self) -> bool {
        self.platform_name.contains("iphone") || self.supported_platforms.iter().any(|p| p.to_lowercase().contains("iphone"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvisioningManifest
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `embedded.mobileprovision` file.
#[derive(Debug, Clone, Default)]
pub struct ProvisioningManifest {
    /// Profile name.
    pub name: String,
    /// App ID name.
    pub app_id_name: String,
    /// App ID prefix (team ID + "." + bundle ID).
    pub app_id_prefix: Vec<String>,
    /// Profile UUID.
    pub uuid: String,
    /// Team identifier(s).
    pub team_identifier: Vec<String>,
    /// Team name.
    pub team_name: String,
    /// Profile creation date.
    pub creation_date: String,
    /// Profile expiry date.
    pub expiration_date: String,
    /// Whether the profile provisions all devices.
    pub provisions_all_devices: bool,
    /// Provisioned device UDIDs.
    pub provisioned_devices: Vec<String>,
    /// Entitlement key/value pairs.
    pub entitlements: HashMap<String, EntitlementValue>,
    /// DER-encoded certificates (as raw bytes).
    pub developer_certificates: Vec<Vec<u8>>,
    /// Platform identifier(s).
    pub platform: Vec<String>,
}

/// An entitlement value (string, bool, or array of strings).
#[derive(Debug, Clone)]
pub enum EntitlementValue {
    Bool(bool),
    Str(String),
    StringArray(Vec<String>),
}

impl ProvisioningManifest {
    /// Parse from a `.mobileprovision` file.
    ///
    /// `.mobileprovision` is a CMS/PKCS#7 signed blob.  We extract the inner
    /// XML plist by searching for the `<?xml` marker (Apple uses DER but the
    /// plist payload is embedded as-is between the PKCS#7 envelope).
    ///
    /// # Errors
    /// Returns an error if no XML plist is found in the data, or it cannot be parsed.
    pub fn parse(data: &[u8]) -> Result<Self, ManifestError> {
        // Find the XML plist embedded in the CMS blob.
        let xml_start = find_bytes(data, b"<?xml").or_else(|| find_bytes(data, b"<plist"));
        let xml_data = if let Some(start) = xml_start {
            // Find the closing </plist> tag.
            let rest = &data[start..];
            let end = find_bytes(rest, b"</plist>").map_or(rest.len(), |e| e + 8);
            &rest[..end]
        } else {
            return Err(ManifestError::ParseError("no XML plist found in mobileprovision".into()));
        };

        let xml_str = std::str::from_utf8(xml_data)
            .map_err(|_| ManifestError::ParseError("UTF-8 decode".into()))?;
        let plist = parse_xml_plist(xml_str)?;
        Ok(Self::from_plist_value(&plist))
    }

    fn from_plist_value(v: &PlistValue) -> Self {
        let app_id_prefix = v.get("ApplicationIdentifierPrefix").map(PlistValue::string_array).unwrap_or_default();
        let team_identifier = v.get("TeamIdentifier").map(PlistValue::string_array).unwrap_or_default();
        let provisioned_devices = v.get("ProvisionedDevices").map(PlistValue::string_array).unwrap_or_default();
        let platform = v.get("Platform").map(PlistValue::string_array).unwrap_or_default();

        let entitlements = if let Some(ents) = v.get("Entitlements")
            && let PlistValue::Dict(dict) = ents {
                dict.iter().map(|(k, val)| {
                    let ev = match val {
                        PlistValue::Bool(b) => EntitlementValue::Bool(*b),
                        PlistValue::String(s) => EntitlementValue::Str(s.clone()),
                        PlistValue::Array(_) => EntitlementValue::StringArray(val.string_array()),
                        _ => EntitlementValue::Str(format!("{val:?}")),
                    };
                    (k.clone(), ev)
                }).collect()
            } else {
                HashMap::new()
            };

        let developer_certificates = if let Some(certs) = v.get("DeveloperCertificates")
            && let PlistValue::Array(arr) = certs {
                arr.iter().filter_map(|item| {
                    if let PlistValue::Data(d) = item { Some(d.clone()) } else { None }
                }).collect()
            } else {
                Vec::new()
            };

        Self {
            name: get_str(v, "Name").unwrap_or_default(),
            app_id_name: get_str(v, "AppIDName").unwrap_or_default(),
            uuid: get_str(v, "UUID").unwrap_or_default(),
            team_name: get_str(v, "TeamName").unwrap_or_default(),
            creation_date: get_str(v, "CreationDate").unwrap_or_default(),
            expiration_date: get_str(v, "ExpirationDate").unwrap_or_default(),
            provisions_all_devices: v.get("ProvisionsAllDevices").and_then(PlistValue::as_bool).unwrap_or(false),
            app_id_prefix,
            team_identifier,
            provisioned_devices,
            platform,
            entitlements,
            developer_certificates,
        }
    }

    /// Returns the primary team identifier, if any.
    #[must_use]
    pub fn primary_team_id(&self) -> Option<&str> {
        self.team_identifier.first().map(std::string::String::as_str)
    }

    /// Returns `true` if `get-task-allow` entitlement is set to `true`.
    #[must_use]
    pub fn get_task_allow(&self) -> bool {
        matches!(self.entitlements.get("get-task-allow"), Some(EntitlementValue::Bool(true)))
    }

    /// Returns `true` for development profiles.
    #[must_use]
    pub fn is_development(&self) -> bool {
        self.get_task_allow() && !self.provisioned_devices.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn detect_and_parse(data: &[u8]) -> Result<PlistValue, ManifestError> {
    // Binary plist starts with "bplist".
    if data.starts_with(b"bplist") {
        return Err(ManifestError::UnsupportedFormat(
            "binary plist — use plist_binary crate module".into()
        ));
    }
    // XML plist.
    let s = std::str::from_utf8(data)
        .map_err(|_| ManifestError::ParseError("not valid UTF-8".into()))?;
    parse_xml_plist(s)
}

fn get_str(v: &PlistValue, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(std::string::ToString::to_string)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INFOPLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.MyApp</string>
    <key>CFBundleDisplayName</key>
    <string>My App</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2.3</string>
    <key>CFBundleVersion</key>
    <string>42</string>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
    <key>CFBundleExecutable</key>
    <string>MyApp</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>iPhoneOS</string>
    </array>
    <key>NSCameraUsageDescription</key>
    <string>We need camera access</string>
</dict>
</plist>"#;

    #[test]
    fn test_parse_info_plist() {
        let manifest = BundleManifest::parse(SAMPLE_INFOPLIST.as_bytes()).unwrap();
        assert_eq!(manifest.bundle_id, "com.example.MyApp");
        assert_eq!(manifest.display_name, "My App");
        assert_eq!(manifest.short_version, "1.2.3");
        assert_eq!(manifest.bundle_version, "42");
        assert_eq!(manifest.min_os_version, "14.0");
        assert_eq!(manifest.executable_name, "MyApp");
        assert!(manifest.supported_platforms.contains(&"iPhoneOS".to_string()));
        assert!(manifest.privacy_keys.contains(&"NSCameraUsageDescription".to_string()));
    }

    #[test]
    fn test_is_ios() {
        let mut m = BundleManifest::default();
        m.supported_platforms = vec!["iPhoneOS".into()];
        assert!(m.is_ios());
    }

    #[test]
    fn test_xml_plist_parser_nested() {
        let xml = "<dict><key>outer</key><dict><key>inner</key><string>hello</string></dict></dict>";
        let v = parse_xml_plist(xml).unwrap();
        let inner = v.get("outer").and_then(|x| x.get("inner")).and_then(|x| x.as_str());
        assert_eq!(inner, Some("hello"));
    }

    #[test]
    fn test_xml_entities_decode() {
        assert_eq!(decode_xml_entities("a &amp; b &lt;c&gt;"), "a & b <c>");
    }

    #[test]
    fn test_provisioning_get_task_allow() {
        let xml = r#"<dict>
            <key>Entitlements</key>
            <dict>
                <key>get-task-allow</key>
                <true/>
            </dict>
        </dict>"#;
        // Embed in a mobileprovision-like structure with <?xml header.
        let data = format!("<?xml version=\"1.0\"?>{xml}</plist>").into_bytes();
        let m = ProvisioningManifest::parse(&data).unwrap();
        assert!(m.get_task_allow());
    }
}
