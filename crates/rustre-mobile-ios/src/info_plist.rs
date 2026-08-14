//! Structured access to iOS `Info.plist` fields.

use crate::plist::PlistValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── AtsConfig ────────────────────────────────────────────────────────────────

/// App Transport Security configuration extracted from `NSAppTransportSecurity`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AtsConfig {
    /// `NSAllowsArbitraryLoads`
    pub allows_arbitrary_loads: bool,
    /// `NSAllowsArbitraryLoadsInWebContent`
    pub allows_arbitrary_loads_in_web_content: bool,
    /// `NSAllowsLocalNetworking`
    pub allows_local_networking: bool,
    /// Per-domain exceptions: domain → `allows_arbitrary_loads_for_domain`.
    pub exception_domains: HashMap<String, bool>,
}

// ─── UrlType ──────────────────────────────────────────────────────────────────

/// A URL scheme registration from `CFBundleURLTypes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlType {
    pub name: String,
    pub role: String,
    pub schemes: Vec<String>,
}

// ─── DocumentType ─────────────────────────────────────────────────────────────

/// A document type registration from `CFBundleDocumentTypes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentType {
    pub name: String,
    pub types: Vec<String>,
    pub extensions: Vec<String>,
    pub mime_types: Vec<String>,
}

// ─── InfoPlist ────────────────────────────────────────────────────────────────

/// Structured wrapper around a parsed `Info.plist` value.
pub struct InfoPlist {
    raw: PlistValue,
}

impl InfoPlist {
    /// Create from a pre-parsed [`PlistValue`].
    #[must_use]
    pub const fn from_plist(raw: PlistValue) -> Self {
        Self { raw }
    }

    /// `CFBundleIdentifier`
    #[must_use]
    pub fn bundle_id(&self) -> Option<&str> {
        self.raw.get("CFBundleIdentifier")?.as_str()
    }

    /// `CFBundleVersion` (build number)
    #[must_use]
    pub fn bundle_version(&self) -> Option<&str> {
        self.raw.get("CFBundleVersion")?.as_str()
    }

    /// `CFBundleShortVersionString` (marketing version)
    #[must_use]
    pub fn bundle_short_version(&self) -> Option<&str> {
        self.raw.get("CFBundleShortVersionString")?.as_str()
    }

    /// `CFBundleDisplayName` or `CFBundleName`
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.raw
            .get("CFBundleDisplayName")
            .or_else(|| self.raw.get("CFBundleName"))
            .and_then(|v| v.as_str())
    }

    /// `MinimumOSVersion`
    #[must_use]
    pub fn minimum_os_version(&self) -> Option<&str> {
        self.raw.get("MinimumOSVersion")?.as_str()
    }

    /// `CFBundleExecutable`
    #[must_use]
    pub fn bundle_executable(&self) -> Option<&str> {
        self.raw.get("CFBundleExecutable")?.as_str()
    }

    /// `UIBackgroundModes` array values.
    #[must_use]
    pub fn background_modes(&self) -> Vec<&str> {
        self.raw
            .get("UIBackgroundModes")
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    /// All `NS*UsageDescription` keys and their values.
    #[must_use]
    pub fn privacy_usage_descriptions(&self) -> HashMap<&str, &str> {
        let mut map = HashMap::new();
        if let PlistValue::Dict(pairs) = &self.raw {
            for (k, v) in pairs {
                if k.starts_with("NS")
                    && k.ends_with("UsageDescription")
                    && let Some(desc) = v.as_str()
                {
                    map.insert(k.as_str(), desc);
                }
            }
        }
        map
    }

    /// `UISupportedInterfaceOrientations` values.
    #[must_use]
    pub fn supported_interface_orientations(&self) -> Vec<&str> {
        self.raw
            .get("UISupportedInterfaceOrientations")
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    /// Parse `NSAppTransportSecurity` into an [`AtsConfig`].
    #[must_use]
    pub fn app_transport_security(&self) -> Option<AtsConfig> {
        let ats = self.raw.get("NSAppTransportSecurity")?;
        let mut cfg = AtsConfig {
            allows_arbitrary_loads: ats
                .get("NSAllowsArbitraryLoads")
                .and_then(super::plist::PlistValue::as_bool)
                .unwrap_or(false),
            allows_arbitrary_loads_in_web_content: ats
                .get("NSAllowsArbitraryLoadsInWebContent")
                .and_then(super::plist::PlistValue::as_bool)
                .unwrap_or(false),
            allows_local_networking: ats
                .get("NSAllowsLocalNetworking")
                .and_then(super::plist::PlistValue::as_bool)
                .unwrap_or(false),
            ..AtsConfig::default()
        };
        if let Some(domains) = ats.get("NSExceptionDomains")
            && let PlistValue::Dict(pairs) = domains
        {
            for (domain, exc) in pairs {
                let allow = exc
                    .get("NSExceptionAllowsInsecureHTTPLoads")
                    .and_then(super::plist::PlistValue::as_bool)
                    .unwrap_or(false);
                cfg.exception_domains.insert(domain.clone(), allow);
            }
        }
        Some(cfg)
    }

    /// `CFBundleURLTypes` → collect scheme strings.
    #[must_use]
    pub fn url_schemes(&self) -> Vec<&str> {
        let mut schemes = Vec::new();
        if let Some(PlistValue::Array(types)) = self.raw.get("CFBundleURLTypes") {
            for t in types {
                if let Some(arr) = t.get("CFBundleURLSchemes") {
                    schemes.extend(arr.string_array());
                }
            }
        }
        schemes
    }

    /// `LSApplicationQueriesSchemes`
    #[must_use]
    pub fn queried_url_schemes(&self) -> Vec<&str> {
        self.raw
            .get("LSApplicationQueriesSchemes")
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    /// `CFBundleURLTypes` as structured [`UrlType`] values.
    #[must_use]
    pub fn url_types(&self) -> Vec<UrlType> {
        let mut result = Vec::new();
        if let Some(PlistValue::Array(types)) = self.raw.get("CFBundleURLTypes") {
            for t in types {
                let name = t
                    .get("CFBundleURLName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let role = t
                    .get("CFBundleURLRole")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Editor")
                    .to_string();
                let schemes = t
                    .get("CFBundleURLSchemes")
                    .map(|v| v.string_array().into_iter().map(str::to_string).collect())
                    .unwrap_or_default();
                result.push(UrlType {
                    name,
                    role,
                    schemes,
                });
            }
        }
        result
    }

    /// `CFBundleDocumentTypes` as structured [`DocumentType`] values.
    #[must_use]
    pub fn document_types(&self) -> Vec<DocumentType> {
        let mut result = Vec::new();
        if let Some(PlistValue::Array(types)) = self.raw.get("CFBundleDocumentTypes") {
            for t in types {
                let name = t
                    .get("CFBundleTypeName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let types_arr = t
                    .get("LSItemContentTypes")
                    .map(|v| v.string_array().into_iter().map(str::to_string).collect())
                    .unwrap_or_default();
                let extensions = t
                    .get("CFBundleTypeExtensions")
                    .map(|v| v.string_array().into_iter().map(str::to_string).collect())
                    .unwrap_or_default();
                let mime_types = t
                    .get("LSHandlerRank")
                    .map(|v| v.string_array().into_iter().map(str::to_string).collect())
                    .unwrap_or_default();
                result.push(DocumentType {
                    name,
                    types: types_arr,
                    extensions,
                    mime_types,
                });
            }
        }
        result
    }

    /// `UIRequiredDeviceCapabilities`
    #[must_use]
    pub fn required_device_capabilities(&self) -> Vec<&str> {
        self.raw
            .get("UIRequiredDeviceCapabilities")
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    /// `LSApplicationQueriesSchemes` (alias for `queried_url_schemes`).
    #[must_use]
    pub fn allowed_callers(&self) -> Vec<&str> {
        self.raw
            .get("NSXPCCallerAccountClassNames")
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    /// Return the raw plist value.
    #[must_use]
    pub const fn raw(&self) -> &PlistValue {
        &self.raw
    }

    /// Return `true` if the app has any privacy usage description keys.
    #[must_use]
    pub fn has_any_privacy_key(&self) -> bool {
        !self.privacy_usage_descriptions().is_empty()
    }

    /// Return `true` if the app targets iOS.
    #[must_use]
    pub fn targets_ios(&self) -> bool {
        if let Some(PlistValue::Array(platforms)) = self.raw.get("CFBundleSupportedPlatforms") {
            return platforms.iter().any(|p| {
                p.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("iphoneos"))
            });
        }
        false
    }

    /// Return `true` if this is a Catalyst app.
    #[must_use]
    pub fn is_catalyst(&self) -> bool {
        self.raw
            .get("LSUIElement")
            .and_then(super::plist::PlistValue::as_bool)
            .unwrap_or(false)
            || self
                .raw
                .get("LSEnvironment")
                .and_then(|v| v.get("MALACHITE_PRODUCT"))
                .is_some()
    }

    /// Number of keys in the top-level dict.
    #[must_use]
    pub const fn key_count(&self) -> usize {
        match &self.raw {
            PlistValue::Dict(pairs) => pairs.len(),
            _ => 0,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plist::parse_xml_plist;

    fn make_info_plist(xml: &str) -> InfoPlist {
        let val = parse_xml_plist(xml.as_bytes()).unwrap();
        InfoPlist::from_plist(val)
    }

    #[test]
    fn test_bundle_id() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleIdentifier</key><string>com.example.App</string>
</dict></plist>",
        );
        assert_eq!(plist.bundle_id(), Some("com.example.App"));
    }

    #[test]
    fn test_bundle_id_missing() {
        let plist = make_info_plist("<plist><dict></dict></plist>");
        assert!(plist.bundle_id().is_none());
    }

    #[test]
    fn test_display_name_fallback() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleName</key><string>MyApp</string>
</dict></plist>",
        );
        assert_eq!(plist.display_name(), Some("MyApp"));
    }

    #[test]
    fn test_privacy_descriptions() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>NSCameraUsageDescription</key><string>Need camera</string>
<key>NSMicrophoneUsageDescription</key><string>Need mic</string>
<key>CFBundleIdentifier</key><string>com.test</string>
</dict></plist>",
        );
        let descs = plist.privacy_usage_descriptions();
        assert_eq!(descs.len(), 2);
        assert!(descs.contains_key("NSCameraUsageDescription"));
    }

    #[test]
    fn test_has_any_privacy_key() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>NSLocationUsageDescription</key><string>loc</string>
</dict></plist>",
        );
        assert!(plist.has_any_privacy_key());
    }

    #[test]
    fn test_no_privacy_keys() {
        let plist = make_info_plist("<plist><dict></dict></plist>");
        assert!(!plist.has_any_privacy_key());
    }

    #[test]
    fn test_background_modes() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>UIBackgroundModes</key><array><string>audio</string><string>location</string></array>
</dict></plist>",
        );
        let modes = plist.background_modes();
        assert_eq!(modes.len(), 2);
        assert!(modes.contains(&"audio"));
    }

    #[test]
    fn test_url_schemes() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleURLTypes</key><array>
<dict><key>CFBundleURLSchemes</key><array><string>myapp</string></array></dict>
</array>
</dict></plist>",
        );
        assert_eq!(plist.url_schemes(), vec!["myapp"]);
    }

    #[test]
    fn test_queried_url_schemes() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>LSApplicationQueriesSchemes</key><array><string>fb</string><string>twitter</string></array>
</dict></plist>",
        );
        let schemes = plist.queried_url_schemes();
        assert_eq!(schemes.len(), 2);
    }

    #[test]
    fn test_key_count() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>a</key><string>1</string>
<key>b</key><string>2</string>
</dict></plist>",
        );
        assert_eq!(plist.key_count(), 2);
    }

    #[test]
    fn test_minimum_os_version() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>MinimumOSVersion</key><string>16.0</string>
</dict></plist>",
        );
        assert_eq!(plist.minimum_os_version(), Some("16.0"));
    }

    #[test]
    fn test_bundle_executable() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleExecutable</key><string>MyApp</string>
</dict></plist>",
        );
        assert_eq!(plist.bundle_executable(), Some("MyApp"));
    }

    #[test]
    fn test_short_version() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleShortVersionString</key><string>3.1.4</string>
</dict></plist>",
        );
        assert_eq!(plist.bundle_short_version(), Some("3.1.4"));
    }

    #[test]
    fn test_required_device_capabilities() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>UIRequiredDeviceCapabilities</key><array>
<string>arm64</string><string>nfc</string>
</array>
</dict></plist>",
        );
        let caps = plist.required_device_capabilities();
        assert!(caps.contains(&"arm64"));
        assert!(caps.contains(&"nfc"));
    }

    #[test]
    fn test_targets_ios() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
</dict></plist>",
        );
        assert!(plist.targets_ios());
    }

    #[test]
    fn test_ats_config() {
        let plist = make_info_plist(
            r"<plist><dict>
<key>NSAppTransportSecurity</key><dict>
<key>NSAllowsArbitraryLoads</key><true/>
</dict>
</dict></plist>",
        );
        let ats = plist.app_transport_security().unwrap();
        assert!(ats.allows_arbitrary_loads);
    }

    #[test]
    fn test_ats_none_when_missing() {
        let plist = make_info_plist("<plist><dict></dict></plist>");
        assert!(plist.app_transport_security().is_none());
    }
}
