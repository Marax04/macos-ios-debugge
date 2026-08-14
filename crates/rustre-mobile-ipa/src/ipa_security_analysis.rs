//! IPA security analysis: ATS, data protection, keychain, biometrics,
//! jailbreak detection, PIE/ASLR, stack canary, ARC.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum IpaSecurityError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("analysis error: {0}")]
    Analysis(String),
}

/// ATS security flags (bitfield).
#[derive(Debug, Clone, Default)]
pub struct AppTransportSecurity {
    /// Packed boolean flags (use accessor methods).
    pub flags: u8,
    pub exception_domains: Vec<String>,
}
impl AppTransportSecurity {
    pub const ALLOWS_ARBITRARY_LOADS: u8 = 1;
    pub const ALLOWS_ARBITRARY_LOADS_FOR_MEDIA: u8 = 2;
    pub const ALLOWS_ARBITRARY_LOADS_IN_WEB_CONTENT: u8 = 4;
    pub const REQUIRES_CERTIFICATE_TRANSPARENCY: u8 = 8;
    #[must_use] pub const fn allows_arbitrary_loads(&self) -> bool { self.flags & Self::ALLOWS_ARBITRARY_LOADS != 0 }
    #[must_use] pub const fn allows_arbitrary_loads_for_media(&self) -> bool { self.flags & Self::ALLOWS_ARBITRARY_LOADS_FOR_MEDIA != 0 }
    #[must_use] pub const fn allows_arbitrary_loads_in_web_content(&self) -> bool { self.flags & Self::ALLOWS_ARBITRARY_LOADS_IN_WEB_CONTENT != 0 }
    #[must_use] pub const fn requires_certificate_transparency(&self) -> bool { self.flags & Self::REQUIRES_CERTIFICATE_TRANSPARENCY != 0 }
    #[must_use]
    pub const fn is_insecure(&self) -> bool {
        self.allows_arbitrary_loads() || !self.exception_domains.is_empty()
    }
    #[must_use]
    pub fn risk_summary(&self) -> String {
        if self.allows_arbitrary_loads() {
            "AllowsArbitraryLoads=true (all HTTPS disabled)".into()
        } else if !self.exception_domains.is_empty() {
            format!("{} ATS exception domains", self.exception_domains.len())
        } else {
            "ATS compliant".into()
        }
    }
}
impl Serialize for AppTransportSecurity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(5))?;
        map.serialize_entry("allows_arbitrary_loads", &self.allows_arbitrary_loads())?;
        map.serialize_entry("allows_arbitrary_loads_for_media", &self.allows_arbitrary_loads_for_media())?;
        map.serialize_entry("allows_arbitrary_loads_in_web_content", &self.allows_arbitrary_loads_in_web_content())?;
        map.serialize_entry("exception_domains", &self.exception_domains)?;
        map.serialize_entry("requires_certificate_transparency", &self.requires_certificate_transparency())?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for AppTransportSecurity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = AppTransportSecurity;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("map") }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut flags = 0u8;
                let mut exception_domains = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "allows_arbitrary_loads" => { if map.next_value::<bool>()? { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS; } }
                        "allows_arbitrary_loads_for_media" => { if map.next_value::<bool>()? { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS_FOR_MEDIA; } }
                        "allows_arbitrary_loads_in_web_content" => { if map.next_value::<bool>()? { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS_IN_WEB_CONTENT; } }
                        "requires_certificate_transparency" => { if map.next_value::<bool>()? { flags |= AppTransportSecurity::REQUIRES_CERTIFICATE_TRANSPARENCY; } }
                        "exception_domains" => { exception_domains = map.next_value()?; }
                        _ => { let _ = map.next_value::<serde::de::IgnoredAny>()?; }
                    }
                }
                Ok(AppTransportSecurity { flags, exception_domains })
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataProtectionClass {
    CompleteUntilFirstAuth,
    Complete,
    CompleteUnlessOpen,
    None,
}
impl fmt::Display for DataProtectionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompleteUntilFirstAuth => {
                write!(f, "NSFileProtectionCompleteUntilFirstUserAuthentication")
            }
            Self::Complete => write!(f, "NSFileProtectionComplete"),
            Self::CompleteUnlessOpen => write!(f, "NSFileProtectionCompleteUnlessOpen"),
            Self::None => write!(f, "NSFileProtectionNone"),
        }
    }
}
impl DataProtectionClass {
    #[must_use]
    pub const fn is_strong(&self) -> bool {
        matches!(self, Self::Complete | Self::CompleteUntilFirstAuth)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataProtection {
    pub default_class: Option<DataProtectionClass>,
    pub file_classes: HashMap<String, DataProtectionClass>,
    pub has_any_none: bool,
    pub database_encrypted: bool,
}
impl DataProtection {
    #[must_use]
    pub fn risk_level(&self) -> &'static str {
        if self.has_any_none
            || self
                .default_class
                .is_some_and(|c| c == DataProtectionClass::None)
        {
            "HIGH"
        } else {
            "LOW"
        }
    }
}

/// Keychain usage flags (bitfield).
#[derive(Debug, Clone, Default)]
pub struct KeychainUsage {
    /// Packed boolean flags (use accessor methods).
    pub flags: u8,
}
impl KeychainUsage {
    pub const STORES_PASSWORDS: u8 = 1;
    pub const STORES_TOKENS: u8 = 2;
    pub const STORES_CERTIFICATES: u8 = 4;
    pub const ACCESSIBILITY_ALWAYS: u8 = 8;
    pub const ACCESSIBILITY_WHEN_UNLOCKED: u8 = 16;
    pub const ICLOUD_SYNC_ENABLED: u8 = 32;
    #[must_use] pub const fn stores_passwords(&self) -> bool { self.flags & Self::STORES_PASSWORDS != 0 }
    #[must_use] pub const fn stores_tokens(&self) -> bool { self.flags & Self::STORES_TOKENS != 0 }
    #[must_use] pub const fn stores_certificates(&self) -> bool { self.flags & Self::STORES_CERTIFICATES != 0 }
    #[must_use] pub const fn accessibility_always(&self) -> bool { self.flags & Self::ACCESSIBILITY_ALWAYS != 0 }
    #[must_use] pub const fn accessibility_when_unlocked(&self) -> bool { self.flags & Self::ACCESSIBILITY_WHEN_UNLOCKED != 0 }
    #[must_use] pub const fn icloud_sync_enabled(&self) -> bool { self.flags & Self::ICLOUD_SYNC_ENABLED != 0 }
    #[must_use]
    pub const fn is_risky(&self) -> bool {
        self.accessibility_always() || self.icloud_sync_enabled()
    }
}
impl Serialize for KeychainUsage {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(6))?;
        map.serialize_entry("stores_passwords", &self.stores_passwords())?;
        map.serialize_entry("stores_tokens", &self.stores_tokens())?;
        map.serialize_entry("stores_certificates", &self.stores_certificates())?;
        map.serialize_entry("accessibility_always", &self.accessibility_always())?;
        map.serialize_entry("accessibility_when_unlocked", &self.accessibility_when_unlocked())?;
        map.serialize_entry("icloud_sync_enabled", &self.icloud_sync_enabled())?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for KeychainUsage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = KeychainUsage;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("map") }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut flags = 0u8;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "stores_passwords" => { if map.next_value::<bool>()? { flags |= KeychainUsage::STORES_PASSWORDS; } }
                        "stores_tokens" => { if map.next_value::<bool>()? { flags |= KeychainUsage::STORES_TOKENS; } }
                        "stores_certificates" => { if map.next_value::<bool>()? { flags |= KeychainUsage::STORES_CERTIFICATES; } }
                        "accessibility_always" => { if map.next_value::<bool>()? { flags |= KeychainUsage::ACCESSIBILITY_ALWAYS; } }
                        "accessibility_when_unlocked" => { if map.next_value::<bool>()? { flags |= KeychainUsage::ACCESSIBILITY_WHEN_UNLOCKED; } }
                        "icloud_sync_enabled" => { if map.next_value::<bool>()? { flags |= KeychainUsage::ICLOUD_SYNC_ENABLED; } }
                        _ => { let _ = map.next_value::<serde::de::IgnoredAny>()?; }
                    }
                }
                Ok(KeychainUsage { flags })
            }
        }
        d.deserialize_map(V)
    }
}

/// Biometric auth flags (bitfield).
#[derive(Debug, Clone, Default)]
pub struct BiometricAuth {
    /// Packed boolean flags (use accessor methods).
    pub flags: u8,
    pub biometric_policy: Option<String>,
}
impl BiometricAuth {
    pub const FACE_ID_USED: u8 = 1;
    pub const TOUCH_ID_USED: u8 = 2;
    pub const FALLBACK_TO_PASSCODE: u8 = 4;
    pub const DEVICE_OWNER_AUTH: u8 = 8;
    #[must_use] pub const fn face_id_used(&self) -> bool { self.flags & Self::FACE_ID_USED != 0 }
    #[must_use] pub const fn touch_id_used(&self) -> bool { self.flags & Self::TOUCH_ID_USED != 0 }
    #[must_use] pub const fn fallback_to_passcode(&self) -> bool { self.flags & Self::FALLBACK_TO_PASSCODE != 0 }
    #[must_use] pub const fn device_owner_auth(&self) -> bool { self.flags & Self::DEVICE_OWNER_AUTH != 0 }
    #[must_use]
    pub const fn has_any_biometric(&self) -> bool {
        self.face_id_used() || self.touch_id_used()
    }
}
impl Serialize for BiometricAuth {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(5))?;
        map.serialize_entry("face_id_used", &self.face_id_used())?;
        map.serialize_entry("touch_id_used", &self.touch_id_used())?;
        map.serialize_entry("biometric_policy", &self.biometric_policy)?;
        map.serialize_entry("fallback_to_passcode", &self.fallback_to_passcode())?;
        map.serialize_entry("device_owner_auth", &self.device_owner_auth())?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for BiometricAuth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BiometricAuth;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("map") }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut flags = 0u8;
                let mut biometric_policy = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "face_id_used" => { if map.next_value::<bool>()? { flags |= BiometricAuth::FACE_ID_USED; } }
                        "touch_id_used" => { if map.next_value::<bool>()? { flags |= BiometricAuth::TOUCH_ID_USED; } }
                        "fallback_to_passcode" => { if map.next_value::<bool>()? { flags |= BiometricAuth::FALLBACK_TO_PASSCODE; } }
                        "device_owner_auth" => { if map.next_value::<bool>()? { flags |= BiometricAuth::DEVICE_OWNER_AUTH; } }
                        "biometric_policy" => { biometric_policy = map.next_value()?; }
                        _ => { let _ = map.next_value::<serde::de::IgnoredAny>()?; }
                    }
                }
                Ok(BiometricAuth { flags, biometric_policy })
            }
        }
        d.deserialize_map(V)
    }
}

/// Jailbreak detection flags (bitfield).
#[derive(Debug, Clone, Default)]
pub struct JailbreakDetection {
    /// Packed boolean flags (use accessor methods).
    pub flags: u8,
    pub paths_checked: Vec<String>,
    pub dylibs_checked: Vec<String>,
    pub confidence: f64,
}
impl JailbreakDetection {
    pub const HAS_DETECTION: u8 = 1;
    pub const FORK_CHECK: u8 = 2;
    pub const SANDBOX_CHECK: u8 = 4;
    pub const BYPASSED_EASILY: u8 = 8;
    #[must_use] pub const fn has_detection(&self) -> bool { self.flags & Self::HAS_DETECTION != 0 }
    #[must_use] pub const fn fork_check(&self) -> bool { self.flags & Self::FORK_CHECK != 0 }
    #[must_use] pub const fn sandbox_check(&self) -> bool { self.flags & Self::SANDBOX_CHECK != 0 }
    #[must_use] pub const fn bypassed_easily(&self) -> bool { self.flags & Self::BYPASSED_EASILY != 0 }
}
impl Serialize for JailbreakDetection {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(7))?;
        map.serialize_entry("has_detection", &self.has_detection())?;
        map.serialize_entry("paths_checked", &self.paths_checked)?;
        map.serialize_entry("dylibs_checked", &self.dylibs_checked)?;
        map.serialize_entry("fork_check", &self.fork_check())?;
        map.serialize_entry("sandbox_check", &self.sandbox_check())?;
        map.serialize_entry("confidence", &self.confidence)?;
        map.serialize_entry("bypassed_easily", &self.bypassed_easily())?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for JailbreakDetection {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = JailbreakDetection;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("map") }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut flags = 0u8;
                let mut paths_checked = Vec::new();
                let mut dylibs_checked = Vec::new();
                let mut confidence = 0.0f64;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "has_detection" => { if map.next_value::<bool>()? { flags |= JailbreakDetection::HAS_DETECTION; } }
                        "fork_check" => { if map.next_value::<bool>()? { flags |= JailbreakDetection::FORK_CHECK; } }
                        "sandbox_check" => { if map.next_value::<bool>()? { flags |= JailbreakDetection::SANDBOX_CHECK; } }
                        "bypassed_easily" => { if map.next_value::<bool>()? { flags |= JailbreakDetection::BYPASSED_EASILY; } }
                        "paths_checked" => { paths_checked = map.next_value()?; }
                        "dylibs_checked" => { dylibs_checked = map.next_value()?; }
                        "confidence" => { confidence = map.next_value()?; }
                        _ => { let _ = map.next_value::<serde::de::IgnoredAny>()?; }
                    }
                }
                Ok(JailbreakDetection { flags, paths_checked, dylibs_checked, confidence })
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PieAslr {
    pub pie_enabled: bool,
    pub high_entropy_aslr: bool,
    pub aslr_bits: u32,
}
impl PieAslr {
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.pie_enabled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StackCanary {
    pub enabled: bool,
    pub symbol_found: String,
    pub coverage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArcStatus {
    pub enabled: bool,
    pub coverage: f64,
    pub objc_release_found: bool,
    pub objc_retain_found: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaSecurityReport {
    pub ats: AppTransportSecurity,
    pub data_protection: DataProtection,
    pub keychain: KeychainUsage,
    pub biometric: BiometricAuth,
    pub jailbreak_detection: JailbreakDetection,
    pub pie_aslr: PieAslr,
    pub stack_canary: StackCanary,
    pub arc: ArcStatus,
    pub overall_score: f64,
    pub findings: Vec<String>,
}

impl IpaSecurityReport {
    #[must_use]
    pub fn mock() -> Self {
        let ats = AppTransportSecurity {
            flags: 0,
            exception_domains: vec!["api.dev.example.com".into()],
        };
        let dp = DataProtection {
            default_class: Some(DataProtectionClass::CompleteUntilFirstAuth),
            file_classes: HashMap::new(),
            has_any_none: false,
            database_encrypted: true,
        };
        let kc = KeychainUsage {
            flags: KeychainUsage::STORES_PASSWORDS | KeychainUsage::STORES_TOKENS | KeychainUsage::ACCESSIBILITY_WHEN_UNLOCKED,
        };
        let bio = BiometricAuth {
            flags: BiometricAuth::FACE_ID_USED | BiometricAuth::TOUCH_ID_USED | BiometricAuth::FALLBACK_TO_PASSCODE | BiometricAuth::DEVICE_OWNER_AUTH,
            biometric_policy: Some("LAPolicyDeviceOwnerAuthenticationWithBiometrics".into()),
        };
        let jb = JailbreakDetection {
            flags: JailbreakDetection::HAS_DETECTION | JailbreakDetection::SANDBOX_CHECK | JailbreakDetection::BYPASSED_EASILY,
            paths_checked: vec!["/Applications/Cydia.app".into(), "/bin/bash".into()],
            dylibs_checked: vec!["MobileSubstrate".into()],
            confidence: 0.75,
        };
        let pie = PieAslr {
            pie_enabled: true,
            high_entropy_aslr: true,
            aslr_bits: 24,
        };
        let sc = StackCanary {
            enabled: true,
            symbol_found: "___stack_chk_fail".into(),
            coverage: 0.85,
        };
        let arc = ArcStatus {
            enabled: true,
            coverage: 0.92,
            objc_release_found: true,
            objc_retain_found: true,
        };
        let findings = vec![
            "ATS exception domain detected".into(),
            "Jailbreak detection can be bypassed easily".into(),
            "No client certificate pinning".into(),
        ];
        Self {
            ats,
            data_protection: dp,
            keychain: kc,
            biometric: bio,
            jailbreak_detection: jb,
            pie_aslr: pie,
            stack_canary: sc,
            arc,
            overall_score: 72.0,
            findings,
        }
    }

    #[must_use]
    pub fn security_mitigations_count(&self) -> u32 {
        [
            self.pie_aslr.is_secure(),
            self.stack_canary.enabled,
            self.arc.enabled,
            self.biometric.has_any_biometric(),
            !self.ats.is_insecure(),
        ]
        .iter()
        .filter(|&&b| b)
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "IpaSecurityReport score={:.1} mitigations={} findings={}",
            self.overall_score,
            self.security_mitigations_count(),
            self.findings.len()
        )
    }
}

impl fmt::Display for IpaSecurityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[derive(Debug, Default)]
pub struct IpaSecurityAnalyzer;
impl IpaSecurityAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn analyze_info_plist(&self, xml: &str) -> AppTransportSecurity {
        let lower = xml.to_lowercase();
        let has_true = lower.contains("<true/>");
        let mut flags = 0u8;
        if lower.contains("nsallowsarbitraryloads") && has_true { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS; }
        if lower.contains("nsallowsarbitraryloadsinmedia") && has_true { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS_FOR_MEDIA; }
        if lower.contains("nsallowsarbitraryloadsinwebcontent") && has_true { flags |= AppTransportSecurity::ALLOWS_ARBITRARY_LOADS_IN_WEB_CONTENT; }
        if lower.contains("nsrequirescertificatetransparency") { flags |= AppTransportSecurity::REQUIRES_CERTIFICATE_TRANSPARENCY; }
        AppTransportSecurity { flags, exception_domains: vec![] }
    }

    #[must_use]
    pub fn analyze_macho_binary(&self, data: &[u8]) -> (PieAslr, StackCanary, ArcStatus) {
        let has_pie = if data.len() >= 4 {
            let magic = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4]));
            matches!(magic, 0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE)
        } else {
            false
        };
        let has_sc = data
            .windows(b"___stack_chk_fail".len())
            .any(|w| w == b"___stack_chk_fail");
        let has_arc = data
            .windows(b"_objc_release".len())
            .any(|w| w == b"_objc_release");
        let pie = PieAslr {
            pie_enabled: has_pie,
            high_entropy_aslr: has_pie,
            aslr_bits: if has_pie { 24 } else { 0 },
        };
        let sc = StackCanary {
            enabled: has_sc,
            symbol_found: if has_sc {
                "___stack_chk_fail".into()
            } else {
                String::new()
            },
            coverage: if has_sc { 0.8 } else { 0.0 },
        };
        let arc = ArcStatus {
            enabled: has_arc,
            coverage: if has_arc { 0.9 } else { 0.0 },
            objc_release_found: has_arc,
            objc_retain_found: data
                .windows(b"_objc_retain".len())
                .any(|w| w == b"_objc_retain"),
        };
        (pie, sc, arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ats_allows_arbitrary_insecure() {
        let a = AppTransportSecurity {
            flags: AppTransportSecurity::ALLOWS_ARBITRARY_LOADS,
            ..Default::default()
        };
        assert!(a.is_insecure());
    }
    #[test]
    fn test_ats_exception_domain_insecure() {
        let a = AppTransportSecurity {
            exception_domains: vec!["dev.example.com".into()],
            ..Default::default()
        };
        assert!(a.is_insecure());
    }
    #[test]
    fn test_ats_compliant() {
        let a = AppTransportSecurity::default();
        assert!(!a.is_insecure());
    }
    #[test]
    fn test_ats_risk_summary_allows_all() {
        let a = AppTransportSecurity {
            flags: AppTransportSecurity::ALLOWS_ARBITRARY_LOADS,
            ..Default::default()
        };
        assert!(a.risk_summary().contains("AllowsArbitraryLoads"));
    }
    #[test]
    fn test_data_protection_is_strong() {
        assert!(DataProtectionClass::Complete.is_strong());
        assert!(!DataProtectionClass::None.is_strong());
    }
    #[test]
    fn test_data_protection_display() {
        assert!(
            DataProtectionClass::Complete
                .to_string()
                .contains("Complete")
        );
    }
    #[test]
    fn test_dp_risk_none() {
        let d = DataProtection {
            has_any_none: true,
            ..Default::default()
        };
        assert_eq!(d.risk_level(), "HIGH");
    }
    #[test]
    fn test_keychain_is_risky_when_always() {
        let k = KeychainUsage { flags: KeychainUsage::ACCESSIBILITY_ALWAYS };
        assert!(k.is_risky());
    }
    #[test]
    fn test_keychain_not_risky() {
        let k = KeychainUsage { flags: KeychainUsage::ACCESSIBILITY_WHEN_UNLOCKED };
        assert!(!k.is_risky());
    }
    #[test]
    fn test_biometric_has_any() {
        let b = BiometricAuth { flags: BiometricAuth::FACE_ID_USED, ..Default::default() };
        assert!(b.has_any_biometric());
    }
    #[test]
    fn test_biometric_none() {
        let b = BiometricAuth::default();
        assert!(!b.has_any_biometric());
    }
    #[test]
    fn test_pie_aslr_is_secure() {
        let p = PieAslr {
            pie_enabled: true,
            ..Default::default()
        };
        assert!(p.is_secure());
    }
    #[test]
    fn test_pie_not_secure() {
        assert!(!PieAslr::default().is_secure());
    }
    #[test]
    fn test_report_mock_score() {
        let r = IpaSecurityReport::mock();
        assert!(r.overall_score > 0.0 && r.overall_score <= 100.0);
    }
    #[test]
    fn test_report_mitigations() {
        let r = IpaSecurityReport::mock();
        assert!(r.security_mitigations_count() >= 3);
    }
    #[test]
    fn test_report_findings_nonempty() {
        let r = IpaSecurityReport::mock();
        assert!(!r.findings.is_empty());
    }
    #[test]
    fn test_report_display() {
        let r = IpaSecurityReport::mock();
        let s = format!("{r}");
        assert!(s.contains("IpaSecurityReport"));
    }
    #[test]
    fn test_report_serialization() {
        let r = IpaSecurityReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: IpaSecurityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.findings.len(), r.findings.len());
    }
    #[test]
    fn test_analyzer_ats_allows_arbitrary() {
        let az = IpaSecurityAnalyzer::new();
        let xml = "<key>NSAllowsArbitraryLoads</key><true/>";
        let a = az.analyze_info_plist(xml);
        assert!(a.allows_arbitrary_loads());
    }
    #[test]
    fn test_analyzer_ats_clean() {
        let az = IpaSecurityAnalyzer::new();
        let a = az.analyze_info_plist("<plist></plist>");
        assert!(!a.allows_arbitrary_loads());
    }
    #[test]
    fn test_analyzer_macho_stack_canary() {
        let az = IpaSecurityAnalyzer::new();
        let data = b"___stack_chk_fail";
        let (_, sc, _) = az.analyze_macho_binary(data);
        assert!(sc.enabled);
    }
    #[test]
    fn test_analyzer_macho_arc() {
        let az = IpaSecurityAnalyzer::new();
        let data = b"_objc_release _objc_retain";
        let (_, _, arc) = az.analyze_macho_binary(data);
        assert!(arc.enabled);
    }
    #[test]
    fn test_ats_exception_count() {
        let r = IpaSecurityReport::mock();
        assert_eq!(r.ats.exception_domains.len(), 1);
    }
    #[test]
    fn test_dp_default_class_set() {
        let r = IpaSecurityReport::mock();
        assert!(r.data_protection.default_class.is_some());
    }
    #[test]
    fn test_dp_database_encrypted() {
        let r = IpaSecurityReport::mock();
        assert!(r.data_protection.database_encrypted);
    }
    #[test]
    fn test_keychain_stores_tokens() {
        let r = IpaSecurityReport::mock();
        assert!(r.keychain.stores_tokens());
    }
    #[test]
    fn test_keychain_not_risky_via_report() {
        let r = IpaSecurityReport::mock();
        assert!(!r.keychain.is_risky());
    }
    #[test]
    fn test_biometric_face_id_set() {
        let r = IpaSecurityReport::mock();
        assert!(r.biometric.face_id_used());
    }
    #[test]
    fn test_biometric_fallback_passcode() {
        let r = IpaSecurityReport::mock();
        assert!(r.biometric.fallback_to_passcode());
    }
    #[test]
    fn test_jailbreak_detection_paths() {
        let r = IpaSecurityReport::mock();
        assert!(!r.jailbreak_detection.paths_checked.is_empty());
    }
    #[test]
    fn test_jailbreak_sandbox_check() {
        let r = IpaSecurityReport::mock();
        assert!(r.jailbreak_detection.sandbox_check());
    }
    #[test]
    fn test_jailbreak_easily_bypassed() {
        let r = IpaSecurityReport::mock();
        assert!(r.jailbreak_detection.bypassed_easily());
    }
    #[test]
    fn test_pie_high_entropy() {
        let r = IpaSecurityReport::mock();
        assert!(r.pie_aslr.high_entropy_aslr);
    }
    #[test]
    fn test_pie_bits() {
        let r = IpaSecurityReport::mock();
        assert_eq!(r.pie_aslr.aslr_bits, 24);
    }
    #[test]
    fn test_stack_canary_coverage() {
        let r = IpaSecurityReport::mock();
        assert!(r.stack_canary.coverage > 0.0);
    }
    #[test]
    fn test_arc_coverage() {
        let r = IpaSecurityReport::mock();
        assert!(r.arc.coverage > 0.0);
    }
    #[test]
    fn test_arc_retain_found() {
        let r = IpaSecurityReport::mock();
        assert!(r.arc.objc_retain_found);
    }
    #[test]
    fn test_report_findings_count() {
        let r = IpaSecurityReport::mock();
        assert!(r.findings.len() >= 2);
    }
    #[test]
    fn test_analyzer_default() {
        let _ = IpaSecurityAnalyzer;
    }
    #[test]
    fn test_dp_class_complete_is_strong() {
        assert!(DataProtectionClass::Complete.is_strong());
    }
    #[test]
    fn test_dp_class_none_not_strong() {
        assert!(!DataProtectionClass::None.is_strong());
    }
}
