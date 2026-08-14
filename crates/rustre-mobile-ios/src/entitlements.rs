//! Entitlement analysis for iOS applications.
//!
//! Parses the entitlements plist embedded in the Mach-O code signature and
//! provides structured access to security-relevant entitlement keys.

use crate::plist::PlistValue;
use serde::{Deserialize, Serialize};

// ─── FileAccessEntitlement ───────────────────────────────────────────────────

/// A file-access entitlement granted to the app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEntitlement {
    pub key: String,
    pub paths: Vec<String>,
}

// ─── SandboxEntitlement ───────────────────────────────────────────────────────

/// A sandbox-related entitlement (macOS/Catalyst).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEntitlement {
    pub key: String,
    pub value: String,
}

// ─── Entitlements ─────────────────────────────────────────────────────────────

/// Structured access to the app's entitlement dict.
pub struct Entitlements {
    raw: PlistValue,
}

impl Entitlements {
    /// Create from a pre-parsed [`PlistValue`].
    #[must_use]
    pub const fn from_plist(raw: PlistValue) -> Self {
        Self { raw }
    }

    /// Helper: return a bool entitlement value (default `false`).
    fn bool_key(&self, key: &str) -> bool {
        self.raw
            .get(key)
            .and_then(super::plist::PlistValue::as_bool)
            .unwrap_or(false)
    }

    /// Helper: return an array entitlement value.
    fn string_array_key(&self, key: &str) -> Vec<&str> {
        self.raw
            .get(key)
            .map(|v| v.string_array())
            .unwrap_or_default()
    }

    // ── Group / keychain ───────────────────────────────────────────────────────

    /// `com.apple.security.application-groups`
    #[must_use]
    pub fn application_groups(&self) -> Vec<&str> {
        self.string_array_key("com.apple.security.application-groups")
    }

    /// `keychain-access-groups`
    #[must_use]
    pub fn keychain_groups(&self) -> Vec<&str> {
        self.string_array_key("keychain-access-groups")
    }

    /// Extract the team ID prefix from `application-identifier` or `keychain-access-groups`.
    #[must_use]
    pub fn team_id(&self) -> Option<&str> {
        let id = self.raw.get("com.apple.developer.team-identifier")?;
        id.as_str()
    }

    // ── Debug entitlements ─────────────────────────────────────────────────────

    /// `com.apple.security.cs.debugger` — allows attaching a debugger.
    #[must_use]
    pub fn has_debugger_entitlement(&self) -> bool {
        self.bool_key("com.apple.security.cs.debugger")
    }

    /// `get-task-allow` — present in debug builds, allows lldb to attach.
    #[must_use]
    pub fn has_get_task_allow(&self) -> bool {
        self.bool_key("get-task-allow")
    }

    /// `com.apple.private.security.no-sandbox` — removes sandbox.
    #[must_use]
    pub fn has_platform_application(&self) -> bool {
        self.bool_key("com.apple.private.security.no-sandbox")
            || self.bool_key("platform-application")
    }

    /// `com.apple.system-task-ports` or `task_for_pid-allow`.
    #[must_use]
    pub fn has_task_for_pid(&self) -> bool {
        self.bool_key("task_for_pid-allow") || self.bool_key("com.apple.system-task-ports")
    }

    // ── Capability entitlements ────────────────────────────────────────────────

    /// `com.apple.developer.networking.networkextension` or `com.apple.networking.networkextension`.
    #[must_use]
    pub fn network_client(&self) -> bool {
        self.bool_key("com.apple.security.network.client")
    }

    /// `aps-environment` is set to `"production"` or `"development"`.
    #[must_use]
    pub fn push_notifications(&self) -> bool {
        self.raw
            .get("aps-environment")
            .and_then(|v| v.as_str())
            .is_some()
    }

    /// `com.apple.developer.in-app-payments`
    #[must_use]
    pub fn apple_pay(&self) -> bool {
        self.raw
            .get("com.apple.developer.in-app-payments")
            .and_then(|v| v.as_array())
            .is_some_and(|arr| !arr.is_empty())
    }

    /// `com.apple.developer.healthkit`
    #[must_use]
    pub fn health_kit(&self) -> bool {
        self.bool_key("com.apple.developer.healthkit")
    }

    /// `com.apple.developer.homekit`
    #[must_use]
    pub fn homekit(&self) -> bool {
        self.bool_key("com.apple.developer.homekit")
    }

    /// `inter-app-audio` (deprecated in iOS 13)
    #[must_use]
    pub fn inter_app_audio(&self) -> bool {
        self.bool_key("inter-app-audio")
    }

    // ── File access ────────────────────────────────────────────────────────────

    /// Return all file-access-related entitlements.
    #[must_use]
    pub fn has_file_access_entitlements(&self) -> Vec<FileAccessEntitlement> {
        let file_keys = [
            "com.apple.security.files.user-selected.read-only",
            "com.apple.security.files.user-selected.read-write",
            "com.apple.security.files.downloads.read-only",
            "com.apple.security.files.downloads.read-write",
            "com.apple.security.files.bookmarks.app-scope",
            "com.apple.security.files.bookmarks.document-scope",
            "com.apple.security.assets.pictures.read-only",
            "com.apple.security.assets.pictures.read-write",
            "com.apple.security.assets.music.read-only",
            "com.apple.security.assets.music.read-write",
            "com.apple.security.assets.movies.read-only",
            "com.apple.security.assets.movies.read-write",
            "com.apple.security.temporary-exception.files.absolute-path.read-only",
            "com.apple.security.temporary-exception.files.absolute-path.read-write",
        ];

        let mut result = Vec::with_capacity(file_keys.len());
        for key in &file_keys {
            match self.raw.get(key) {
                Some(PlistValue::Boolean(true)) => {
                    result.push(FileAccessEntitlement {
                        key: (*key).to_string(),
                        paths: vec![],
                    });
                }
                Some(PlistValue::Array(_)) => {
                    let paths = self
                        .string_array_key(key)
                        .into_iter()
                        .map(str::to_string)
                        .collect();
                    result.push(FileAccessEntitlement {
                        key: (*key).to_string(),
                        paths,
                    });
                }
                _ => {}
            }
        }
        result
    }

    // ── Sandbox ────────────────────────────────────────────────────────────────

    /// Return macOS sandbox-related entitlements as key/value pairs.
    #[must_use]
    pub fn sandbox_entitlements(&self) -> Vec<SandboxEntitlement> {
        let sandbox_keys = [
            ("com.apple.security.app-sandbox", "app-sandbox"),
            ("com.apple.security.network.server", "network-server"),
            ("com.apple.security.network.client", "network-client"),
            ("com.apple.security.device.camera", "camera"),
            ("com.apple.security.device.microphone", "microphone"),
            ("com.apple.security.device.usb", "usb"),
            ("com.apple.security.device.bluetooth", "bluetooth"),
            (
                "com.apple.security.personal-information.contacts",
                "contacts",
            ),
            (
                "com.apple.security.personal-information.calendars",
                "calendars",
            ),
            (
                "com.apple.security.personal-information.location",
                "location",
            ),
            (
                "com.apple.security.personal-information.photos-library",
                "photos",
            ),
            ("com.apple.security.automation.apple-events", "apple-events"),
        ];

        let mut result = Vec::with_capacity(sandbox_keys.len());
        for (key, name) in &sandbox_keys {
            if self.bool_key(key) {
                result.push(SandboxEntitlement {
                    key: (*key).to_string(),
                    value: (*name).to_string(),
                });
            }
        }
        result
    }

    // ── Security analysis ──────────────────────────────────────────────────────

    /// Return a list of suspicious entitlement keys present.
    #[must_use]
    pub fn suspicious_entitlements(&self) -> Vec<&str> {
        let mut findings = Vec::new();
        if self.has_get_task_allow() {
            findings.push("get-task-allow");
        }
        if self.has_task_for_pid() {
            findings.push("task_for_pid-allow");
        }
        if self.has_platform_application() {
            findings.push("no-sandbox");
        }
        if self.has_debugger_entitlement() {
            findings.push("cs.debugger");
        }
        findings
    }

    /// Return `true` if any suspicious entitlement is present.
    #[must_use]
    pub fn has_suspicious_entitlements(&self) -> bool {
        !self.suspicious_entitlements().is_empty()
    }

    /// All entitlement keys in the plist.
    #[must_use]
    pub fn all_keys(&self) -> Vec<&str> {
        match &self.raw {
            PlistValue::Dict(pairs) => pairs.iter().map(|(k, _)| k.as_str()).collect(),
            _ => vec![],
        }
    }

    /// Number of entitlement keys.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.all_keys().len()
    }

    /// Return the raw plist.
    #[must_use]
    pub const fn raw(&self) -> &PlistValue {
        &self.raw
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plist::parse_xml_plist;

    fn make_entitlements(xml: &str) -> Entitlements {
        let val = parse_xml_plist(xml.as_bytes()).unwrap();
        Entitlements::from_plist(val)
    }

    #[test]
    fn test_get_task_allow_true() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>get-task-allow</key><true/>
</dict></plist>",
        );
        assert!(ent.has_get_task_allow());
        assert!(ent.has_suspicious_entitlements());
    }

    #[test]
    fn test_get_task_allow_false() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>get-task-allow</key><false/>
</dict></plist>",
        );
        assert!(!ent.has_get_task_allow());
    }

    #[test]
    fn test_team_id() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.developer.team-identifier</key><string>ABCD123456</string>
</dict></plist>",
        );
        assert_eq!(ent.team_id(), Some("ABCD123456"));
    }

    #[test]
    fn test_keychain_groups() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>keychain-access-groups</key><array>
<string>ABCD.*</string><string>com.example.shared</string>
</array>
</dict></plist>",
        );
        let groups = ent.keychain_groups();
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_application_groups() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.security.application-groups</key><array>
<string>group.com.example.app</string>
</array>
</dict></plist>",
        );
        assert_eq!(ent.application_groups(), vec!["group.com.example.app"]);
    }

    #[test]
    fn test_push_notifications() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>aps-environment</key><string>production</string>
</dict></plist>",
        );
        assert!(ent.push_notifications());
    }

    #[test]
    fn test_health_kit() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.developer.healthkit</key><true/>
</dict></plist>",
        );
        assert!(ent.health_kit());
    }

    #[test]
    fn test_homekit() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.developer.homekit</key><true/>
</dict></plist>",
        );
        assert!(ent.homekit());
    }

    #[test]
    fn test_no_suspicious() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>aps-environment</key><string>production</string>
</dict></plist>",
        );
        assert!(!ent.has_suspicious_entitlements());
        assert!(ent.suspicious_entitlements().is_empty());
    }

    #[test]
    fn test_all_keys() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>get-task-allow</key><true/>
<key>aps-environment</key><string>production</string>
</dict></plist>",
        );
        let keys = ent.all_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"get-task-allow"));
    }

    #[test]
    fn test_key_count() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>a</key><true/>
<key>b</key><true/>
<key>c</key><true/>
</dict></plist>",
        );
        assert_eq!(ent.key_count(), 3);
    }

    #[test]
    fn test_sandbox_entitlements() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
</dict></plist>",
        );
        let sandbox = ent.sandbox_entitlements();
        assert!(!sandbox.is_empty());
        assert!(sandbox.iter().any(|s| s.value == "network-client"));
    }

    #[test]
    fn test_file_access_entitlements() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.security.files.user-selected.read-write</key><true/>
</dict></plist>",
        );
        let access = ent.has_file_access_entitlements();
        assert!(!access.is_empty());
    }

    #[test]
    fn test_network_client() {
        let ent = make_entitlements(
            r"<plist><dict>
<key>com.apple.security.network.client</key><true/>
</dict></plist>",
        );
        assert!(ent.network_client());
    }
}
