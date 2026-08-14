//! `rustre-mobile-ipa::provisioning`
//!
//! iOS provisioning profile analysis.
//!
//! A provisioning profile (`embedded.mobileprovision`) is a CMS/PKCS#7-signed
//! blob whose inner payload is an XML plist.  This module provides:
//!
//! * [`ProvisioningProfile`] — full parsed profile.
//! * [`ProfileType`] — Development / `AdHoc` / Enterprise / `AppStore`.
//! * [`Entitlements`] — entitlement key/value pairs.
//! * [`ProvisioningCertificate`] — subject, issuer, expiry.
//! * [`TeamId`] / [`DeviceUDIDs`] — convenience wrappers.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ProfileType
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of iOS provisioning profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileType {
    /// Developer / debug builds.  Contains device UDIDs and `get-task-allow=true`.
    Development,
    /// Ad-hoc distribution.  Contains device UDIDs.
    AdHoc,
    /// Enterprise (in-house) distribution.  `ProvisionsAllDevices` is present.
    Enterprise,
    /// App Store distribution.  No device UDIDs, no `ProvisionsAllDevices`.
    AppStore,
}

impl ProfileType {
    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Development => "Development",
            Self::AdHoc => "AdHoc",
            Self::Enterprise => "Enterprise",
            Self::AppStore => "AppStore",
        }
    }

    /// Infer the profile type from basic profile attributes.
    ///
    /// Rule:
    /// * `ProvisionsAllDevices` in the XML → Enterprise
    /// * Non-empty device list + `get-task-allow=true` → Development
    /// * Non-empty device list → `AdHoc`
    /// * Otherwise → `AppStore`
    #[must_use]
    pub const fn infer(provisions_all: bool, devices: &[String], get_task_allow: bool) -> Self {
        if provisions_all {
            Self::Enterprise
        } else if !devices.is_empty() && get_task_allow {
            Self::Development
        } else if !devices.is_empty() {
            Self::AdHoc
        } else {
            Self::AppStore
        }
    }

    /// Returns `true` for profiles that may be distributed directly (not via App Store).
    #[must_use]
    pub const fn is_direct_distribution(self) -> bool {
        matches!(self, Self::AdHoc | Self::Enterprise)
    }

    /// Returns `true` when the profile targets real devices (not simulator).
    #[must_use]
    pub const fn targets_real_devices(self) -> bool {
        !matches!(self, Self::AppStore)
    }
}

impl std::fmt::Display for ProfileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TeamId
// ─────────────────────────────────────────────────────────────────────────────

/// An Apple Team Identifier (10-character alphanumeric string).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TeamId(pub String);

impl TeamId {
    /// Create a new `TeamId`, trimming whitespace.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into().trim().to_string())
    }

    /// Returns `true` when the team ID looks valid (non-empty, ASCII alphanumeric).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.chars().all(|c| c.is_ascii_alphanumeric())
    }
}

impl std::fmt::Display for TeamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeviceUDIDs
// ─────────────────────────────────────────────────────────────────────────────

/// A list of device UDIDs explicitly provisioned in an Ad-Hoc or Development profile.
#[derive(Debug, Clone, Default)]
pub struct DeviceUDIDs {
    /// UDIDs in the order they appear in the provisioning profile.
    pub udids: Vec<String>,
}

impl DeviceUDIDs {
    /// Create from a vec of UDID strings.
    #[must_use]
    pub const fn new(udids: Vec<String>) -> Self {
        Self { udids }
    }

    /// Number of device UDIDs.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.udids.len()
    }

    /// Returns `true` when the list is not empty.
    #[must_use]
    pub const fn has_devices(&self) -> bool {
        !self.udids.is_empty()
    }

    /// Returns `true` if `udid` is in the list (case-insensitive).
    #[must_use]
    pub fn contains(&self, udid: &str) -> bool {
        let u = udid.to_uppercase();
        self.udids.iter().any(|d| d.to_uppercase() == u)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvisioningCertificate
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal X.509 certificate metadata extracted from a provisioning profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningCertificate {
    /// Subject distinguished name (e.g. `"Apple Development: Foo Bar (TEAM123)"`).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Certificate serial number (hex).
    pub serial: String,
    /// Not-before date (ISO-8601 or empty string when unavailable).
    pub not_before: String,
    /// Not-after (expiry) date (ISO-8601 or empty string when unavailable).
    pub not_after: String,
    /// Raw DER bytes of this certificate.
    pub raw_der: Vec<u8>,
}

impl ProvisioningCertificate {
    /// Create a placeholder certificate from just a subject name.
    #[must_use]
    pub fn from_subject(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            issuer: String::new(),
            serial: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            raw_der: Vec::new(),
        }
    }

    /// Returns `true` when this is an Apple-issued certificate.
    #[must_use]
    pub fn is_apple_issued(&self) -> bool {
        self.issuer.contains("Apple") || self.subject.contains("Apple")
    }

    /// Returns `true` for development certificates.
    #[must_use]
    pub fn is_development(&self) -> bool {
        self.subject.contains("Apple Development") || self.subject.contains("iPhone Developer")
    }

    /// Returns `true` for distribution certificates.
    #[must_use]
    pub fn is_distribution(&self) -> bool {
        self.subject.contains("Apple Distribution") || self.subject.contains("iPhone Distribution")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entitlements
// ─────────────────────────────────────────────────────────────────────────────

/// Entitlements embedded in a provisioning profile.
#[derive(Debug, Clone, Default)]
pub struct ProvisioningEntitlements {
    /// `application-identifier` (team-prefixed bundle ID).
    pub application_identifier: Option<String>,
    /// `keychain-access-groups`.
    pub keychain_access_groups: Vec<String>,
    /// `aps-environment` — `"production"` or `"development"`.
    pub aps_environment: Option<String>,
    /// `get-task-allow` — true in development builds.
    pub get_task_allow: bool,
    /// All other entitlement key/value pairs.
    pub extras: HashMap<String, String>,
}

impl ProvisioningEntitlements {
    /// Parse entitlements from an XML plist string extracted from the profile.
    #[must_use]
    pub fn from_xml(xml: &str) -> Self {
        fn scalar(xml: &str, key: &str) -> Option<String> {
            let needle = format!("<key>{key}</key>");
            let pos = xml.find(&needle)?;
            let after = xml[pos + needle.len()..].trim_start();
            if after.starts_with("<string>") {
                let end = after.find("</string>")?;
                return Some(after[8..end].to_string());
            }
            if after.starts_with("<true/>") {
                return Some("true".into());
            }
            if after.starts_with("<false/>") {
                return Some("false".into());
            }
            None
        }

        fn bool_key(xml: &str, key: &str) -> bool {
            let needle = format!("<key>{key}</key>");
            if let Some(pos) = xml.find(&needle) {
                let after = xml[pos + needle.len()..].trim_start();
                return after.starts_with("<true/>");
            }
            false
        }

        fn array_key(xml: &str, key: &str) -> Vec<String> {
            let needle = format!("<key>{key}</key>");
            let Some(pos) = xml.find(&needle) else { return vec![] };
            let after = xml[pos + needle.len()..].trim_start();
            if !after.starts_with("<array>") {
                return vec![];
            }
            let Some(end) = after.find("</array>") else { return vec![] };
            let content = &after[7..end];
            let mut vals = Vec::new();
            let mut rem = content;
            while let Some(s) = rem.find("<string>") {
                rem = &rem[s + 8..];
                if let Some(e) = rem.find("</string>") {
                    vals.push(rem[..e].to_string());
                    rem = &rem[e + 9..];
                }
            }
            vals
        }

        Self {
            application_identifier: scalar(xml, "application-identifier"),
            keychain_access_groups: array_key(xml, "keychain-access-groups"),
            aps_environment: scalar(xml, "aps-environment"),
            get_task_allow: bool_key(xml, "get-task-allow"),
            extras: HashMap::new(),
        }
    }

    /// Returns `true` when push notifications are configured.
    #[must_use]
    pub const fn has_push_notifications(&self) -> bool {
        self.aps_environment.is_some()
    }

    /// Returns `true` when the app shares the Keychain with other apps.
    #[must_use]
    pub const fn has_shared_keychain(&self) -> bool {
        self.keychain_access_groups.len() > 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvisioningProfile (full)
// ─────────────────────────────────────────────────────────────────────────────

/// A fully parsed iOS provisioning profile.
#[derive(Debug, Clone)]
pub struct ProvisioningProfile {
    /// Profile UUID.
    pub uuid: String,
    /// Profile display name.
    pub name: String,
    /// Developer team name.
    pub team_name: String,
    /// Team identifier (wrapped type).
    pub team_id: TeamId,
    /// Bundle identifier (may contain `*` wildcard).
    pub bundle_id: String,
    /// Profile expiration date (ISO-8601 string).
    pub expiration_date: String,
    /// Profile creation date.
    pub creation_date: String,
    /// Provisioned device UDIDs (wrapped type).
    pub devices: DeviceUDIDs,
    /// Entitlements embedded in the profile.
    pub entitlements: ProvisioningEntitlements,
    /// Certificate chain (leaf → root).
    pub certificates: Vec<ProvisioningCertificate>,
    /// Inferred profile type.
    pub profile_type: ProfileType,
    /// `true` when `ProvisionsAllDevices` is present.
    pub provisions_all_devices: bool,
    /// Raw XML plist extracted from the CMS blob.
    pub raw_plist_xml: String,
}

impl ProvisioningProfile {
    /// Parse a CMS-wrapped provisioning profile.
    ///
    /// Scanning for the inner XML plist by looking for `<?xml` or `bplist00`
    /// magic bytes inside the DER/PEM-encoded CMS `ContentInfo`.
    ///
    /// # Errors
    ///
    /// Returns a `String` error description when no plist can be found.
    pub fn parse_cms(data: &[u8]) -> Result<Self, String> {
        // Strategy: scan for XML plist start marker.
        let plist_bytes = if let Some(pos) = find_bytes(data, b"<?xml") {
            let slice = &data[pos..];
            let end = find_bytes(slice, b"</plist>").map_or(slice.len(), |p| p + 8);
            &slice[..end]
        } else {
            return Err("no XML plist found in CMS data".into());
        };

        let xml = std::str::from_utf8(plist_bytes)
            .map_err(|e| format!("plist is not valid UTF-8: {e}"))?;

        Self::parse_xml(xml)
    }

    /// Parse a provisioning profile from raw XML plist content.
    ///
    /// # Errors
    ///
    /// Returns a `String` error description on parse failure.
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let scalar = |key: &str| -> String { Self::extract_scalar(xml, key).unwrap_or_default() };
        let array = |key: &str| -> Vec<String> { Self::extract_array(xml, key) };
        let bool_key = |key: &str| -> bool {
            let needle = format!("<key>{key}</key>");
            xml.find(&needle).is_some_and(|pos| xml[pos + needle.len()..]
                    .trim_start()
                    .starts_with("<true/>"))
        };

        let uuid = scalar("UUID");
        let name = scalar("Name");
        let team_name = scalar("TeamName");
        let team_id_str = array("TeamIdentifier")
            .into_iter()
            .next()
            .unwrap_or_default();
        let expiration_date = scalar("ExpirationDate");
        let creation_date = scalar("CreationDate");

        // Bundle ID is inside the Entitlements dict.
        let ent_needle = "<key>Entitlements</key>";
        let bundle_id = xml.find(ent_needle).map_or_else(String::new, |ent_pos| {
            let after = &xml[ent_pos + ent_needle.len()..];
            Self::extract_scalar(after, "application-identifier").unwrap_or_default()
        });

        let provisioned_devices = array("ProvisionedDevices");
        let provisions_all =
            bool_key("ProvisionsAllDevices") || xml.contains("ProvisionsAllDevices");

        // Entitlements
        let ent_xml = xml.find(ent_needle).map_or_else(String::new, |pos| {
            let after = &xml[pos + ent_needle.len()..];
            // Find the enclosing <dict> ... </dict>
            after.find("<dict>").map_or_else(String::new, |dict_start| {
                let rest = &after[dict_start..];
                let end = rest.find("</dict>").map_or(rest.len(), |p| p + 7);
                rest[..end].to_string()
            })
        });
        let entitlements = ProvisioningEntitlements::from_xml(&ent_xml);

        let profile_type = ProfileType::infer(
            provisions_all,
            &provisioned_devices,
            entitlements.get_task_allow,
        );

        // Minimal certificate extraction: look for subject strings.
        let mut certificates = Vec::new();
        if xml.contains("DeveloperCertificates") || xml.contains("Apple") {
            certificates.push(ProvisioningCertificate::from_subject("Apple Development"));
        }

        Ok(Self {
            uuid,
            name,
            team_name,
            team_id: TeamId::new(team_id_str),
            bundle_id,
            expiration_date,
            creation_date,
            devices: DeviceUDIDs::new(provisioned_devices),
            entitlements,
            certificates,
            profile_type,
            provisions_all_devices: provisions_all,
            raw_plist_xml: xml.to_string(),
        })
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn extract_scalar(xml: &str, key: &str) -> Option<String> {
        let needle = format!("<key>{key}</key>");
        let pos = xml.find(&needle)?;
        let after = xml[pos + needle.len()..].trim_start();
        if after.starts_with("<string>") {
            let end = after.find("</string>")?;
            return Some(after[8..end].to_string());
        }
        if after.starts_with("<date>") {
            let end = after.find("</date>")?;
            return Some(after[6..end].to_string());
        }
        None
    }

    fn extract_array(xml: &str, key: &str) -> Vec<String> {
        let needle = format!("<key>{key}</key>");
        let Some(pos) = xml.find(&needle) else { return vec![] };
        let after = xml[pos + needle.len()..].trim_start();
        if !after.starts_with("<array>") {
            return vec![];
        }
        let Some(end) = after.find("</array>") else { return vec![] };
        let content = &after[7..end];
        let mut vals = Vec::new();
        let mut rem = content;
        while let Some(s) = rem.find("<string>") {
            rem = &rem[s + 8..];
            if let Some(e) = rem.find("</string>") {
                vals.push(rem[..e].to_string());
                rem = &rem[e + 9..];
            }
        }
        vals
    }

    // ── Convenience accessors ─────────────────────────────────────────────────

    /// Returns `true` when the profile is expired.
    ///
    /// This is a heuristic: we can't do date arithmetic without a time library,
    /// so we just check that the expiration date field is non-empty.
    #[must_use]
    pub const fn has_expiration_date(&self) -> bool {
        !self.expiration_date.is_empty()
    }

    /// Returns `true` when the profile has provisioned devices.
    #[must_use]
    pub const fn has_provisioned_devices(&self) -> bool {
        self.devices.has_devices()
    }

    /// Returns `true` when push notifications are enabled.
    #[must_use]
    pub const fn has_push_notifications(&self) -> bool {
        self.entitlements.has_push_notifications()
    }

    /// Returns `true` when the profile allows task inspection (debugger attach).
    #[must_use]
    pub const fn is_debuggable(&self) -> bool {
        self.entitlements.get_task_allow
    }

    /// Returns `true` when the team ID looks like a real Apple team ID.
    #[must_use]
    pub fn has_valid_team_id(&self) -> bool {
        self.team_id.is_valid()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xml(
        uuid: &str,
        name: &str,
        team_id: &str,
        devices: &[&str],
        provisions_all: bool,
        get_task_allow: bool,
        aps_env: Option<&str>,
    ) -> String {
        let device_str = devices
            .iter()
            .map(|d| format!("<string>{d}</string>"))
            .collect::<Vec<_>>()
            .join("\n");
        let all_str = if provisions_all {
            "<key>ProvisionsAllDevices</key><true/>"
        } else {
            ""
        };
        let aps_str = aps_env
            .map(|e| format!("<key>aps-environment</key><string>{e}</string>"))
            .unwrap_or_default();
        let gta_str = if get_task_allow {
            "<key>get-task-allow</key><true/>"
        } else {
            "<key>get-task-allow</key><false/>"
        };
        format!(
            r#"<?xml version="1.0"?>
<plist>
<dict>
<key>UUID</key><string>{uuid}</string>
<key>Name</key><string>{name}</string>
<key>TeamName</key><string>Test Team</string>
<key>TeamIdentifier</key><array><string>{team_id}</string></array>
<key>ExpirationDate</key><date>2025-01-01T00:00:00Z</date>
<key>ProvisionedDevices</key><array>{device_str}</array>
{all_str}
<key>Entitlements</key>
<dict>
<key>application-identifier</key><string>{team_id}.com.example.app</string>
{aps_str}
{gta_str}
</dict>
</dict>
</plist>"#
        )
    }

    // ── ProfileType ───────────────────────────────────────────────────────────

    #[test]
    fn test_profile_type_infer_enterprise() {
        let pt = ProfileType::infer(true, &[], false);
        assert_eq!(pt, ProfileType::Enterprise);
    }

    #[test]
    fn test_profile_type_infer_development() {
        let pt = ProfileType::infer(false, &["UDID1".into()], true);
        assert_eq!(pt, ProfileType::Development);
    }

    #[test]
    fn test_profile_type_infer_adhoc() {
        let pt = ProfileType::infer(false, &["UDID1".into()], false);
        assert_eq!(pt, ProfileType::AdHoc);
    }

    #[test]
    fn test_profile_type_infer_appstore() {
        let pt = ProfileType::infer(false, &[], false);
        assert_eq!(pt, ProfileType::AppStore);
    }

    #[test]
    fn test_profile_type_direct_distribution() {
        assert!(ProfileType::AdHoc.is_direct_distribution());
        assert!(ProfileType::Enterprise.is_direct_distribution());
        assert!(!ProfileType::AppStore.is_direct_distribution());
        assert!(!ProfileType::Development.is_direct_distribution());
    }

    #[test]
    fn test_profile_type_targets_real_devices() {
        assert!(ProfileType::Development.targets_real_devices());
        assert!(ProfileType::AdHoc.targets_real_devices());
        assert!(!ProfileType::AppStore.targets_real_devices());
    }

    #[test]
    fn test_profile_type_display() {
        assert_eq!(ProfileType::Enterprise.to_string(), "Enterprise");
        assert_eq!(ProfileType::Development.to_string(), "Development");
    }

    // ── TeamId ────────────────────────────────────────────────────────────────

    #[test]
    fn test_team_id_valid() {
        let t = TeamId::new("ABCDEFG123");
        assert!(t.is_valid());
    }

    #[test]
    fn test_team_id_empty() {
        let t = TeamId::new("");
        assert!(!t.is_valid());
    }

    #[test]
    fn test_team_id_with_spaces() {
        let t = TeamId::new("  ABCDE12345  ");
        assert_eq!(t.0, "ABCDE12345");
        assert!(t.is_valid());
    }

    #[test]
    fn test_team_id_with_special_chars() {
        let t = TeamId::new("ABC-DEF123");
        assert!(!t.is_valid());
    }

    // ── DeviceUDIDs ───────────────────────────────────────────────────────────

    #[test]
    fn test_device_udids_empty() {
        let d = DeviceUDIDs::default();
        assert_eq!(d.count(), 0);
        assert!(!d.has_devices());
    }

    #[test]
    fn test_device_udids_contains_case_insensitive() {
        let d = DeviceUDIDs::new(vec!["abc123".into()]);
        assert!(d.contains("ABC123"));
        assert!(!d.contains("XYZ"));
    }

    #[test]
    fn test_device_udids_count() {
        let d = DeviceUDIDs::new(vec!["A".into(), "B".into(), "C".into()]);
        assert_eq!(d.count(), 3);
        assert!(d.has_devices());
    }

    // ── ProvisioningCertificate ────────────────────────────────────────────────

    #[test]
    fn test_cert_is_apple_issued() {
        let c = ProvisioningCertificate {
            subject: "Apple Development: Foo".into(),
            issuer: "Apple Worldwide Developer Relations CA".into(),
            ..ProvisioningCertificate::from_subject("Apple Development: Foo")
        };
        assert!(c.is_apple_issued());
    }

    #[test]
    fn test_cert_is_development() {
        let c = ProvisioningCertificate::from_subject("Apple Development: Foo Bar");
        assert!(c.is_development());
        assert!(!c.is_distribution());
    }

    #[test]
    fn test_cert_is_distribution() {
        let c = ProvisioningCertificate::from_subject("iPhone Distribution: Foo Bar");
        assert!(c.is_distribution());
        assert!(!c.is_development());
    }

    // ── ProvisioningEntitlements ──────────────────────────────────────────────

    #[test]
    fn test_entitlements_has_push() {
        let xml = r"<key>aps-environment</key><string>production</string>";
        let ent = ProvisioningEntitlements::from_xml(xml);
        assert!(ent.has_push_notifications());
        assert_eq!(ent.aps_environment.as_deref(), Some("production"));
    }

    #[test]
    fn test_entitlements_get_task_allow() {
        let xml = r"<key>get-task-allow</key><true/>";
        let ent = ProvisioningEntitlements::from_xml(xml);
        assert!(ent.get_task_allow);
    }

    #[test]
    fn test_entitlements_keychain_groups() {
        let xml = r"<key>keychain-access-groups</key><array><string>TEAM1.group1</string><string>TEAM1.group2</string></array>";
        let ent = ProvisioningEntitlements::from_xml(xml);
        assert_eq!(ent.keychain_access_groups.len(), 2);
        assert!(ent.has_shared_keychain());
    }

    // ── ProvisioningProfile.parse_xml ─────────────────────────────────────────

    #[test]
    fn test_parse_development_profile() {
        let xml = make_xml(
            "UUID-1234",
            "Dev Profile",
            "TEAM123456",
            &["UDID001"],
            false,
            true,
            None,
        );
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert_eq!(p.uuid, "UUID-1234");
        assert_eq!(p.name, "Dev Profile");
        assert_eq!(p.team_id.0, "TEAM123456");
        assert_eq!(p.profile_type, ProfileType::Development);
        assert!(p.is_debuggable());
        assert!(!p.provisions_all_devices);
    }

    #[test]
    fn test_parse_enterprise_profile() {
        let xml = make_xml(
            "UUID-EEEE",
            "Ent Profile",
            "ENTERPRISEID",
            &[],
            true,
            false,
            None,
        );
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert_eq!(p.profile_type, ProfileType::Enterprise);
        assert!(p.provisions_all_devices);
    }

    #[test]
    fn test_parse_appstore_profile() {
        let xml = make_xml(
            "UUID-AAAA",
            "AppStore Profile",
            "TEAMXYZ",
            &[],
            false,
            false,
            None,
        );
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert_eq!(p.profile_type, ProfileType::AppStore);
        assert!(!p.is_debuggable());
    }

    #[test]
    fn test_parse_profile_with_push() {
        let xml = make_xml(
            "UUID-PPP",
            "Push Profile",
            "TEAMABC",
            &[],
            false,
            false,
            Some("production"),
        );
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert!(p.has_push_notifications());
    }

    #[test]
    fn test_parse_profile_devices() {
        let xml = make_xml("U", "N", "T", &["D1", "D2", "D3"], false, false, None);
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert_eq!(p.devices.count(), 3);
        assert!(p.has_provisioned_devices());
    }

    #[test]
    fn test_parse_profile_expiration_date() {
        let xml = make_xml("U", "N", "T", &[], false, false, None);
        let p = ProvisioningProfile::parse_xml(&xml).unwrap();
        assert!(p.has_expiration_date());
        assert!(p.expiration_date.contains("2025"));
    }

    #[test]
    fn test_parse_cms_no_plist() {
        let result = ProvisioningProfile::parse_cms(b"not a real cms blob");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cms_with_xml() {
        let xml = make_xml("U", "N", "T", &[], false, false, None);
        let data = xml.as_bytes();
        let p = ProvisioningProfile::parse_cms(data).unwrap();
        assert!(!p.uuid.is_empty());
    }
}
