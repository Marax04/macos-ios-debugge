//! Android Binary XML (AXML) parser.
//!
//! Parses the binary XML encoding used by `AndroidManifest.xml` inside APK
//! archives.  The format is also known as "AXML" or "Binary XML" and is
//! produced by the AAPT tool during APK build.
//!
//! This implementation handles the most common nodes found in real manifests:
//! `<manifest>`, `<uses-permission>`, `<activity>`, `<service>`,
//! `<receiver>`, `<provider>`, and `<application>`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AXML constants
// ---------------------------------------------------------------------------

/// Binary XML file magic (little-endian u16).
const AXML_MAGIC: u16 = 0x0003;

/// Node type tag for `START_ELEMENT`.
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
/// Node type tag for `END_ELEMENT`.
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
/// Chunk type for string pool.
const RES_STRING_POOL_TYPE: u16 = 0x0001;

// ---------------------------------------------------------------------------
// ManifestPermission
// ---------------------------------------------------------------------------

/// A permission entry parsed from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPermission {
    /// Fully-qualified permission name (e.g. `android.permission.CAMERA`).
    pub name: String,
    /// Whether this is a `<uses-permission>` (vs. `<permission>` declaration).
    pub is_uses: bool,
    /// `maxSdkVersion` attribute, if present.
    pub max_sdk: Option<u32>,
    /// `protectionLevel` attribute (only for declared permissions).
    pub protection_level: Option<u32>,
}

impl ManifestPermission {
    /// Returns `true` if the permission is a dangerous one (level 0x01 or 0x11).
    #[must_use]
    pub fn is_dangerous(&self) -> bool {
        match self.protection_level {
            Some(level) => (level & 0xF) == 1,
            None => {
                // For uses-permissions, check the known dangerous list.
                KNOWN_DANGEROUS_PERMISSIONS
                    .iter()
                    .any(|&p| self.name == p)
            }
        }
    }
}

/// Well-known dangerous Android permissions.
const KNOWN_DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
];

// ---------------------------------------------------------------------------
// ActivityDecl
// ---------------------------------------------------------------------------

/// An `<activity>` component declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityDecl {
    /// Class name (may be relative or absolute).
    pub name: String,
    /// `exported` attribute value.
    pub exported: Option<bool>,
    /// `launchMode` value.
    pub launch_mode: Option<u32>,
    /// `screenOrientation` value.
    pub screen_orientation: Option<u32>,
    /// `theme` attribute.
    pub theme: Option<String>,
    /// `enabled` attribute.
    pub enabled: bool,
    /// Whether this activity has a MAIN/LAUNCHER intent filter.
    pub is_launcher: bool,
    /// Extra attributes not explicitly decoded.
    pub extra: HashMap<String, String>,
}

impl ActivityDecl {
    /// Returns `true` if this is the application's launcher entry point.
    #[must_use]
    pub const fn is_main_entry(&self) -> bool {
        self.is_launcher
    }
}

// ---------------------------------------------------------------------------
// ServiceDecl
// ---------------------------------------------------------------------------

/// A `<service>` component declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDecl {
    /// Class name.
    pub name: String,
    /// `exported` attribute.
    pub exported: Option<bool>,
    /// `enabled` attribute.
    pub enabled: bool,
    /// `permission` required to bind.
    pub permission: Option<String>,
    /// Whether this service runs in a separate process.
    pub separate_process: bool,
    /// `foregroundServiceType` flag.
    pub foreground_type: Option<u32>,
}

impl ServiceDecl {
    /// Returns `true` if the service is exposed without a permission guard.
    #[must_use]
    pub fn is_exposed(&self) -> bool {
        self.exported.unwrap_or(false) && self.permission.is_none()
    }
}

// ---------------------------------------------------------------------------
// ReceiverDecl / ProviderDecl
// ---------------------------------------------------------------------------

/// A `<receiver>` component declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverDecl {
    /// Class name.
    pub name: String,
    /// Whether the receiver is exported.
    pub exported: Option<bool>,
    /// Required permission.
    pub permission: Option<String>,
    /// Actions from contained intent filters.
    pub actions: Vec<String>,
}

impl ReceiverDecl {
    /// Returns `true` if this receiver listens for `BOOT_COMPLETED`.
    #[must_use]
    pub fn is_boot_receiver(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.contains("BOOT_COMPLETED") || a.contains("QUICKBOOT_POWERON"))
    }
}

/// A `<provider>` component declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDecl {
    /// Class name.
    pub name: String,
    /// Content URI authority.
    pub authorities: Option<String>,
    /// `exported` attribute.
    pub exported: Option<bool>,
    /// `grantUriPermissions` attribute.
    pub grant_uri_permissions: bool,
    /// `readPermission` attribute.
    pub read_permission: Option<String>,
    /// `writePermission` attribute.
    pub write_permission: Option<String>,
}

// ---------------------------------------------------------------------------
// ParsedManifest
// ---------------------------------------------------------------------------

/// The fully parsed `AndroidManifest.xml` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedManifest {
    /// Application package identifier.
    pub package: String,
    /// `versionName` attribute.
    pub version_name: String,
    /// `versionCode` attribute.
    pub version_code: u32,
    /// Minimum SDK version.
    pub min_sdk_version: Option<u32>,
    /// Target SDK version.
    pub target_sdk_version: Option<u32>,
    /// Maximum SDK version.
    pub max_sdk_version: Option<u32>,
    /// `debuggable` attribute of `<application>`.
    pub debuggable: bool,
    /// `allowBackup` attribute.
    pub allow_backup: bool,
    /// `usesCleartextTraffic` attribute.
    pub uses_cleartext_traffic: bool,
    /// `networkSecurityConfig` attribute.
    pub network_security_config: Option<String>,
    /// Application class name.
    pub application_class: Option<String>,
    /// `sharedUserId` attribute.
    pub shared_user_id: Option<String>,
    /// Permissions declared or used.
    pub permissions: Vec<ManifestPermission>,
    /// Declared activities.
    pub activities: Vec<ActivityDecl>,
    /// Declared services.
    pub services: Vec<ServiceDecl>,
    /// Declared broadcast receivers.
    pub receivers: Vec<ReceiverDecl>,
    /// Declared content providers.
    pub providers: Vec<ProviderDecl>,
}

impl ParsedManifest {
    /// Construct an empty manifest.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            package: String::new(),
            version_name: String::new(),
            version_code: 0,
            min_sdk_version: None,
            target_sdk_version: None,
            max_sdk_version: None,
            debuggable: false,
            allow_backup: true,
            uses_cleartext_traffic: false,
            network_security_config: None,
            application_class: None,
            shared_user_id: None,
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
        }
    }

    /// Returns all `uses-permission` entries.
    #[must_use]
    pub fn uses_permissions(&self) -> Vec<&ManifestPermission> {
        self.permissions.iter().filter(|p| p.is_uses).collect()
    }

    /// Returns dangerous permissions.
    #[must_use]
    pub fn dangerous_permissions(&self) -> Vec<&ManifestPermission> {
        self.permissions.iter().filter(|p| p.is_dangerous()).collect()
    }

    /// Returns exposed (exported, no permission) services.
    #[must_use]
    pub fn exposed_services(&self) -> Vec<&ServiceDecl> {
        self.services.iter().filter(|s| s.is_exposed()).collect()
    }

    /// Returns boot receivers.
    #[must_use]
    pub fn boot_receivers(&self) -> Vec<&ReceiverDecl> {
        self.receivers
            .iter()
            .filter(|r| r.is_boot_receiver())
            .collect()
    }

    /// Compute a threat score (0.0 – 10.0).
    #[must_use]
    pub fn threat_score(&self) -> f64 {
        let mut score = 0.0_f64;
        let dp = self.dangerous_permissions().len();
        score += (dp as f64 * 0.4).min(3.0);
        if !self.boot_receivers().is_empty() {
            score += 1.5;
        }
        if self.debuggable {
            score += 0.5;
        }
        if self.uses_cleartext_traffic {
            score += 0.5;
        }
        if !self.exposed_services().is_empty() {
            score += 1.0;
        }
        score.min(10.0)
    }
}

// ---------------------------------------------------------------------------
// AXmlStringPool
// ---------------------------------------------------------------------------

/// The string pool extracted from a binary XML file.
#[derive(Debug, Default)]
pub struct AXmlStringPool {
    strings: Vec<String>,
    /// Whether strings are UTF-8 encoded (flag bit 8 of pool header flags).
    utf8: bool,
}

impl AXmlStringPool {
    /// Parse a string pool chunk from `data` starting at `offset`.
    ///
    /// Returns `(pool, bytes_consumed)`.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> (Self, usize) {
        let mut pool = Self::default();
        if offset + 28 > data.len() {
            return (pool, 0);
        }
        // Chunk header: type(u16) + header_size(u16) + chunk_size(u32) = 8 bytes
        // String pool header after that:
        //   string_count(u32) style_count(u32) flags(u32)
        //   strings_start(u32) styles_start(u32)
        let chunk_size = read_u32(data, offset + 4) as usize;
        let string_count = read_u32(data, offset + 8) as usize;
        let flags = read_u32(data, offset + 16);
        let strings_start = read_u32(data, offset + 20) as usize;
        pool.utf8 = (flags >> 8) & 1 != 0;

        // String offsets table starts at offset + 28.
        let offsets_base = offset + 28;
        let data_base = offset.saturating_add(8).saturating_add(strings_start); // chunk header(8) + strings_start

        // Cap string_count to prevent allocation/loop exhaustion on malformed input.
        let string_count = string_count.min(100_000);

        for i in 0..string_count {
            let off_pos = offsets_base.saturating_add(i.saturating_mul(4));
            if off_pos + 4 > data.len() {
                break;
            }
            let str_off = read_u32(data, off_pos) as usize;
            let abs = data_base + str_off;
            let s = if pool.utf8 {
                read_utf8_string(data, abs)
            } else {
                read_utf16_string(data, abs)
            };
            pool.strings.push(s);
        }

        (pool, chunk_size)
    }

    /// Get string by index.
    #[must_use]
    pub fn get(&self, idx: u32) -> &str {
        self.strings
            .get(idx as usize)
            .map_or("", String::as_str)
    }

    /// Total string count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

fn read_utf8_string(data: &[u8], mut off: usize) -> String {
    // Skip char count (ULEB128), then byte count (ULEB128), then bytes.
    if off >= data.len() {
        return String::new();
    }
    // Skip char-length ULEB128 — limit iterations to avoid unbounded loop on malformed data.
    let mut iters = 0usize;
    while off < data.len() && data[off] & 0x80 != 0 && iters < 5 {
        off += 1;
        iters += 1;
    }
    if off < data.len() {
        off += 1; // final byte of char-len
    }
    // Now byte-length ULEB128 — limit shift to avoid left-shift overflow.
    let mut byte_len = 0usize;
    let mut shift = 0u32;
    while off < data.len() && shift < (usize::BITS - 7) {
        let b = data[off];
        off += 1;
        byte_len |= ((b & 0x7F) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    let end = off.saturating_add(byte_len).min(data.len());
    String::from_utf8_lossy(&data[off..end]).to_string()
}

fn read_utf16_string(data: &[u8], off: usize) -> String {
    if off + 2 > data.len() {
        return String::new();
    }
    let char_count = read_u16(data, off) as usize;
    let start = off + 2;
    let byte_count = char_count * 2;
    if start + byte_count > data.len() {
        return String::new();
    }
    let mut s = String::with_capacity(char_count);
    for i in 0..char_count {
        let cp = read_u16(data, start + i * 2);
        if let Some(c) = char::from_u32(u32::from(cp)) {
            s.push(c);
        }
    }
    s
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

// ---------------------------------------------------------------------------
// AXmlParser
// ---------------------------------------------------------------------------

/// Parses a binary XML (AXML) byte stream into a [`ParsedManifest`].
///
/// Handles the chunk-based layout:
/// * File header (type = 0x0003)
/// * String pool (type = 0x0001)
/// * Resource map (type = 0x0180) — skipped
/// * Namespace start/end (types 0x0100/0x0101) — skipped
/// * Start element (type = 0x0102)
/// * End element (type = 0x0103)
pub struct AXmlParser {
    /// Minimum confidence for attribute heuristics.
    _strict: bool,
}

impl AXmlParser {
    /// Create a parser with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { _strict: false }
    }

    /// Parse `data` as a binary XML file and return a [`ParsedManifest`].
    ///
    /// On format errors the parser applies best-effort heuristics and returns
    /// whatever was successfully decoded up to the error point.
    #[must_use]
    pub fn parse(&self, data: &[u8]) -> ParsedManifest {
        if data.len() < 8 {
            return ParsedManifest::empty();
        }
        let magic = read_u16(data, 0);
        if magic != AXML_MAGIC {
            // Possibly plain-text XML — try the text path.
            if data.starts_with(b"<?xml") || data.starts_with(b"<manifest") {
                return self.parse_plain_xml(data);
            }
            return ParsedManifest::empty();
        }

        let mut manifest = ParsedManifest::empty();
        let mut pool = AXmlStringPool::default();
        let mut pos = 8usize; // skip file header (8 bytes)

        while pos + 8 <= data.len() {
            let chunk_type = read_u16(data, pos);
            let chunk_size = read_u32(data, pos + 4) as usize;
            if chunk_size < 8 || pos + chunk_size > data.len() {
                break;
            }

            match chunk_type {
                t if t == RES_STRING_POOL_TYPE => {
                    let (p, _) = AXmlStringPool::parse(data, pos);
                    pool = p;
                }
                t if t == RES_XML_START_ELEMENT_TYPE => {
                    self.handle_start_element(data, pos, chunk_size, &pool, &mut manifest);
                }
                t if t == RES_XML_END_ELEMENT_TYPE => {
                    // Nothing needed for end elements in this parser.
                    let _ = t;
                }
                _ => {}
            }

            pos += chunk_size;
        }

        manifest
    }

    /// Handle a `START_ELEMENT` chunk.
    fn handle_start_element(
        &self,
        data: &[u8],
        chunk_start: usize,
        _chunk_size: usize,
        pool: &AXmlStringPool,
        manifest: &mut ParsedManifest,
    ) {
        // Chunk layout (after 8-byte generic header):
        //   line_number(u32)  comment(u32)  ns(u32)  name(u32)  flags(u32)
        //   attr_count(u16)   id_idx(u16)   class_idx(u16)  style_idx(u16)
        // Each attribute:
        //   ns(u32) name(u32) raw_value(u32) value_size(u16) res0(u8) data_type(u8) data(u32)
        let base = chunk_start + 8; // skip generic header
        if base + 20 > data.len() {
            return;
        }
        let name_idx = read_u32(data, base + 8);
        let elem_name = pool.get(name_idx);

        let attr_count = read_u16(data, base + 16) as usize;
        let attrs_base = base + 20;
        const ATTR_SIZE: usize = 20;

        // Build attr map: name_idx → data value.
        let mut attrs: HashMap<u32, u32> = HashMap::new();
        let mut attr_strings: HashMap<u32, String> = HashMap::new();
        for i in 0..attr_count {
            let a = attrs_base + i * ATTR_SIZE;
            if a + ATTR_SIZE > data.len() {
                break;
            }
            let a_name = read_u32(data, a + 4);
            let a_raw = read_u32(data, a + 8);
            let a_data = read_u32(data, a + 16);
            attrs.insert(a_name, a_data);
            if a_raw != 0xFFFF_FFFF {
                attr_strings.insert(a_name, pool.get(a_raw).to_string());
            }
        }

        // Look up attr value by name string.
        let get_attr = |name: &str| -> Option<u32> {
            for (k, v) in &attrs {
                if pool.get(*k) == name {
                    return Some(*v);
                }
            }
            None
        };
        let get_attr_str = |name: &str| -> Option<String> {
            for (k, v) in &attr_strings {
                if pool.get(*k) == name {
                    return Some(v.clone());
                }
            }
            None
        };
        let attr_str_from_pool = |name: &str| -> Option<String> {
            for (k, v) in &attrs {
                if pool.get(*k) == name {
                    let s = pool.get(*v);
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
            None
        };

        match elem_name {
            "manifest" => {
                if let Some(s) = attr_str_from_pool("package")
                    .or_else(|| get_attr_str("package"))
                {
                    manifest.package = s;
                }
                if let Some(v) = get_attr("versionCode") {
                    manifest.version_code = v;
                }
                if let Some(s) = attr_str_from_pool("versionName") {
                    manifest.version_name = s;
                }
                if let Some(s) = get_attr_str("sharedUserId") {
                    manifest.shared_user_id = Some(s);
                }
            }
            "uses-sdk" => {
                if let Some(v) = get_attr("minSdkVersion") {
                    manifest.min_sdk_version = Some(v);
                }
                if let Some(v) = get_attr("targetSdkVersion") {
                    manifest.target_sdk_version = Some(v);
                }
                if let Some(v) = get_attr("maxSdkVersion") {
                    manifest.max_sdk_version = Some(v);
                }
            }
            "uses-permission" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                let max_sdk = get_attr("maxSdkVersion");
                manifest.permissions.push(ManifestPermission {
                    name,
                    is_uses: true,
                    max_sdk,
                    protection_level: None,
                });
            }
            "permission" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                let protection_level = get_attr("protectionLevel");
                manifest.permissions.push(ManifestPermission {
                    name,
                    is_uses: false,
                    max_sdk: None,
                    protection_level,
                });
            }
            "application" => {
                manifest.debuggable = get_attr("debuggable").unwrap_or(0) != 0;
                manifest.allow_backup = get_attr("allowBackup").unwrap_or(1) != 0;
                manifest.uses_cleartext_traffic =
                    get_attr("usesCleartextTraffic").unwrap_or(0) != 0;
                if let Some(cls) = attr_str_from_pool("name") {
                    manifest.application_class = Some(cls);
                }
            }
            "activity" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                let exported = get_attr("exported").map(|v| v != 0);
                let theme = attr_str_from_pool("theme");
                manifest.activities.push(ActivityDecl {
                    name,
                    exported,
                    launch_mode: get_attr("launchMode"),
                    screen_orientation: get_attr("screenOrientation"),
                    theme,
                    enabled: get_attr("enabled").unwrap_or(1) != 0,
                    is_launcher: false, // refined by intent-filter parsing
                    extra: HashMap::new(),
                });
            }
            "service" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                manifest.services.push(ServiceDecl {
                    name,
                    exported: get_attr("exported").map(|v| v != 0),
                    enabled: get_attr("enabled").unwrap_or(1) != 0,
                    permission: attr_str_from_pool("permission"),
                    separate_process: false,
                    foreground_type: get_attr("foregroundServiceType"),
                });
            }
            "receiver" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                manifest.receivers.push(ReceiverDecl {
                    name,
                    exported: get_attr("exported").map(|v| v != 0),
                    permission: attr_str_from_pool("permission"),
                    actions: Vec::new(),
                });
            }
            "provider" => {
                let name = attr_str_from_pool("name")
                    .or_else(|| get_attr_str("name"))
                    .unwrap_or_default();
                manifest.providers.push(ProviderDecl {
                    name,
                    authorities: attr_str_from_pool("authorities"),
                    exported: get_attr("exported").map(|v| v != 0),
                    grant_uri_permissions: get_attr("grantUriPermissions").unwrap_or(0) != 0,
                    read_permission: attr_str_from_pool("readPermission"),
                    write_permission: attr_str_from_pool("writePermission"),
                });
            }
            "action" => {
                // Record action names for the last open receiver/activity.
                if let Some(action_name) =
                    attr_str_from_pool("name").or_else(|| get_attr_str("name"))
                {
                    if let Some(r) = manifest.receivers.last_mut() {
                        r.actions.push(action_name.clone());
                    }
                    if action_name.contains("MAIN")
                        && let Some(a) = manifest.activities.last_mut() {
                            a.is_launcher = true;
                        }
                }
            }
            _ => {}
        }
    }

    /// Minimal fallback parser for plain-text XML manifests.
    fn parse_plain_xml(&self, data: &[u8]) -> ParsedManifest {
        let mut m = ParsedManifest::empty();
        if let Ok(xml) = std::str::from_utf8(data) {
            if let Some(pkg) = extract_attr(xml, "package") {
                m.package = pkg;
            }
            if let Some(ver) = extract_attr(xml, "android:versionName") {
                m.version_name = ver;
            }
            // Collect uses-permission.
            let mut search = xml;
            while let Some(pos) = search.find("uses-permission") {
                let rest = &search[pos..];
                if let Some(name) = extract_attr(rest, "android:name") {
                    m.permissions.push(ManifestPermission {
                        name,
                        is_uses: true,
                        max_sdk: None,
                        protection_level: None,
                    });
                }
                search = &search[pos + 1..];
            }
        }
        m
    }
}

impl Default for AXmlParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the value of `attr="value"` from a text fragment.
fn extract_attr(text: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let parser = AXmlParser::new();
        let m = parser.parse(&[]);
        assert_eq!(m.package, "");
    }

    #[test]
    fn test_parse_plain_xml_package() {
        let xml = br#"<?xml version="1.0"?><manifest package="com.test.app" android:versionName="2.0">"#;
        let parser = AXmlParser::new();
        let m = parser.parse(xml.as_slice());
        assert_eq!(m.package, "com.test.app");
        assert_eq!(m.version_name, "2.0");
    }

    #[test]
    fn test_parse_plain_xml_permissions() {
        let xml = br#"<?xml version="1.0"?>
<manifest package="com.test">
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.INTERNET"/>
</manifest>"#;
        let parser = AXmlParser::new();
        let m = parser.parse(xml.as_slice());
        assert_eq!(m.permissions.len(), 2);
        assert!(m.permissions.iter().any(|p| p.name.contains("CAMERA")));
    }

    #[test]
    fn test_manifest_permission_is_dangerous() {
        let p = ManifestPermission {
            name: "android.permission.CAMERA".to_string(),
            is_uses: true,
            max_sdk: None,
            protection_level: None,
        };
        assert!(p.is_dangerous());
    }

    #[test]
    fn test_manifest_permission_not_dangerous() {
        let p = ManifestPermission {
            name: "android.permission.INTERNET".to_string(),
            is_uses: true,
            max_sdk: None,
            protection_level: None,
        };
        assert!(!p.is_dangerous());
    }

    #[test]
    fn test_service_decl_is_exposed() {
        let s = ServiceDecl {
            name: "com.example.Svc".to_string(),
            exported: Some(true),
            enabled: true,
            permission: None,
            separate_process: false,
            foreground_type: None,
        };
        assert!(s.is_exposed());
    }

    #[test]
    fn test_service_decl_not_exposed_with_permission() {
        let s = ServiceDecl {
            name: "com.example.Svc".to_string(),
            exported: Some(true),
            enabled: true,
            permission: Some("com.example.PERM".to_string()),
            separate_process: false,
            foreground_type: None,
        };
        assert!(!s.is_exposed());
    }

    #[test]
    fn test_receiver_is_boot() {
        let r = ReceiverDecl {
            name: "com.example.Boot".to_string(),
            exported: Some(true),
            permission: None,
            actions: vec!["android.intent.action.BOOT_COMPLETED".to_string()],
        };
        assert!(r.is_boot_receiver());
    }

    #[test]
    fn test_parsed_manifest_empty() {
        let m = ParsedManifest::empty();
        assert!(m.package.is_empty());
        assert!(m.permissions.is_empty());
    }

    #[test]
    fn test_parsed_manifest_threat_score_zero() {
        let m = ParsedManifest::empty();
        assert_eq!(m.threat_score(), 0.0);
    }

    #[test]
    fn test_parsed_manifest_threat_score_nonzero() {
        let mut m = ParsedManifest::empty();
        m.debuggable = true;
        m.permissions.push(ManifestPermission {
            name: "android.permission.CAMERA".to_string(),
            is_uses: true,
            max_sdk: None,
            protection_level: None,
        });
        assert!(m.threat_score() > 0.0);
    }

    #[test]
    fn test_read_utf16_string() {
        // "AB" in UTF-16LE = 02 00 41 00 42 00
        let data = [0x02, 0x00, 0x41, 0x00, 0x42, 0x00];
        let s = read_utf16_string(&data, 0);
        assert_eq!(s, "AB");
    }

    #[test]
    fn test_extract_attr() {
        let text = r#"package="com.example.app" versionName="1.0""#;
        assert_eq!(extract_attr(text, "package"), Some("com.example.app".to_string()));
        assert_eq!(extract_attr(text, "versionName"), Some("1.0".to_string()));
        assert_eq!(extract_attr(text, "missing"), None);
    }

    #[test]
    fn test_axml_string_pool_empty() {
        let pool = AXmlStringPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.get(0), "");
    }

    #[test]
    fn test_uses_permissions_filter() {
        let mut m = ParsedManifest::empty();
        m.permissions.push(ManifestPermission {
            name: "android.permission.CAMERA".to_string(),
            is_uses: true,
            max_sdk: None,
            protection_level: None,
        });
        m.permissions.push(ManifestPermission {
            name: "com.example.MY_PERM".to_string(),
            is_uses: false,
            max_sdk: None,
            protection_level: Some(1),
        });
        assert_eq!(m.uses_permissions().len(), 1);
    }
}
