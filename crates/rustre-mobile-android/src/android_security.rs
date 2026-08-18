//! Android app security analysis: network security, storage, cryptography,
//! auth mechanisms, permissions risk, anti-reverse detection, report.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::format_push_string,
    clippy::format_in_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::redundant_guards,
    clippy::map_unwrap_or,
    clippy::if_not_else,
    clippy::struct_excessive_bools,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::default_trait_access,
    clippy::wildcard_imports,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::needless_continue,
    clippy::implicit_hasher,
    clippy::ignored_unit_patterns,
    clippy::semicolon_if_nothing_returned,
    clippy::stable_sort_primitive,
    clippy::trivially_copy_pass_by_ref,
    clippy::ptr_as_ptr,
    clippy::ref_option,
    clippy::fn_params_excessive_bools,
    clippy::should_implement_trait,
    clippy::or_fun_call,
    clippy::manual_string_new,
    clippy::single_char_pattern,
    clippy::needless_late_init,
    clippy::or_then_unwrap,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::redundant_else,
    clippy::useless_let_if_seq,
    clippy::let_underscore_untyped,
    clippy::missing_fields_in_debug,
    clippy::ref_as_ptr,
    clippy::manual_range_contains
)]

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum AndroidSecurityError {
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum SecurityRisk {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}
impl fmt::Display for SecurityRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSecurity {
    pub allows_cleartext: bool,
    pub certificate_pinning: bool,
    pub pinned_domains: Vec<String>,
    pub trust_user_certs: bool,
    pub network_security_config: bool,
    pub risk: Option<SecurityRisk>,
    #[serde(default)]
    pub exception_domains: Vec<String>,
}
impl NetworkSecurity {
    #[must_use]
    pub const fn risk_level(&self) -> SecurityRisk {
        if self.allows_cleartext && !self.certificate_pinning {
            return SecurityRisk::High;
        }
        if self.trust_user_certs {
            return SecurityRisk::High;
        }
        if !self.certificate_pinning {
            return SecurityRisk::Medium;
        }
        SecurityRisk::Low
    }
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        self.allows_cleartext || self.trust_user_certs || !self.exception_domains.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageSecurity {
    pub external_storage_used: bool,
    pub internal_storage_encrypted: bool,
    pub encrypted_shared_prefs: bool,
    pub world_readable_files: Vec<String>,
    pub world_writable_files: Vec<String>,
}
impl StorageSecurity {
    #[must_use]
    pub const fn risk_level(&self) -> SecurityRisk {
        if !self.world_readable_files.is_empty() || !self.world_writable_files.is_empty() {
            return SecurityRisk::High;
        }
        if self.external_storage_used && !self.internal_storage_encrypted {
            return SecurityRisk::Medium;
        }
        SecurityRisk::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptographyUsage {
    pub algorithms: Vec<String>,
    pub uses_weak_cipher: bool,
    pub uses_ecb_mode: bool,
    pub hardcoded_keys: Vec<String>,
    pub static_ivs: Vec<String>,
}
impl CryptographyUsage {
    #[must_use]
    pub const fn risk_level(&self) -> SecurityRisk {
        if !self.hardcoded_keys.is_empty() {
            return SecurityRisk::Critical;
        }
        if self.uses_weak_cipher || self.uses_ecb_mode {
            return SecurityRisk::High;
        }
        SecurityRisk::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthMechanism {
    pub biometric: bool,
    pub pin_required: bool,
    pub oauth: bool,
    pub client_cert: bool,
    pub hardcoded_credentials: Vec<String>,
    pub weak_passwords_allowed: bool,
}
impl AuthMechanism {
    #[must_use]
    pub const fn risk_level(&self) -> SecurityRisk {
        if !self.hardcoded_credentials.is_empty() {
            return SecurityRisk::Critical;
        }
        if self.weak_passwords_allowed {
            return SecurityRisk::High;
        }
        SecurityRisk::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PermissionsRisk {
    pub dangerous_count: usize,
    pub spyware_count: usize,
    pub total_count: usize,
    pub high_risk_perms: Vec<String>,
    pub risk: SecurityRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AntiReverseDetection {
    pub has_root_detection: bool,
    pub has_emulator_detection: bool,
    pub has_debugger_detection: bool,
    pub has_frida_detection: bool,
    pub has_integrity_check: bool,
    pub obfuscation_tool: Option<String>,
    pub packer: Option<String>,
}
impl AntiReverseDetection {
    #[must_use]
    pub fn sophistication_score(&self) -> u32 {
        [
            self.has_root_detection,
            self.has_emulator_detection,
            self.has_debugger_detection,
            self.has_frida_detection,
            self.has_integrity_check,
        ]
        .iter()
        .filter(|&&b| b)
        .count() as u32
            * 2
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub network: NetworkSecurity,
    pub storage: StorageSecurity,
    pub cryptography: CryptographyUsage,
    pub auth: AuthMechanism,
    pub permissions: PermissionsRisk,
    pub anti_reverse: AntiReverseDetection,
    pub overall_risk: SecurityRisk,
    pub findings: Vec<String>,
    pub risk_score: f64,
}

impl SecurityReport {
    /// A hand-written fixture used by this crate's own tests.
    ///
    /// It is NOT derived from any APK: nothing in it was measured, so it must
    /// never be reported to a user as the analysis of a real file. The real
    /// paths are `ApkAnalyzer::parse_bytes` (ZIP + DEX + AXML from bytes) and
    /// `AndroidManifest::parse` (binary AXML).
    #[must_use]
    pub fn mock() -> Self {
        let net = NetworkSecurity {
            allows_cleartext: true,
            certificate_pinning: false,
            pinned_domains: vec![],
            trust_user_certs: false,
            network_security_config: false,
            risk: None,
            exception_domains: vec![],
        };
        let stor = StorageSecurity {
            external_storage_used: true,
            internal_storage_encrypted: false,
            encrypted_shared_prefs: false,
            world_readable_files: vec!["/data/data/com.example/cache/data.bin".into()],
            world_writable_files: vec![],
        };
        let crypto = CryptographyUsage {
            algorithms: vec!["AES/ECB/PKCS5Padding".into(), "DES".into()],
            uses_weak_cipher: true,
            uses_ecb_mode: true,
            hardcoded_keys: vec!["0x1234567890ABCDEF".into()],
            static_ivs: vec![],
        };
        let auth = AuthMechanism {
            biometric: false,
            pin_required: false,
            oauth: false,
            client_cert: false,
            hardcoded_credentials: vec!["admin:admin123".into()],
            weak_passwords_allowed: true,
        };
        let perms = PermissionsRisk {
            dangerous_count: 5,
            spyware_count: 3,
            total_count: 12,
            high_risk_perms: vec!["READ_SMS".into(), "ACCESS_FINE_LOCATION".into()],
            risk: SecurityRisk::High,
        };
        let ar = AntiReverseDetection {
            has_root_detection: true,
            has_emulator_detection: false,
            has_debugger_detection: true,
            has_frida_detection: false,
            has_integrity_check: false,
            obfuscation_tool: Some("ProGuard".into()),
            packer: None,
        };
        let findings = vec![
            "Cleartext traffic allowed".into(),
            "ECB mode encryption detected".into(),
            "Hardcoded credentials".into(),
            "Hardcoded encryption key".into(),
        ];
        Self {
            network: net,
            storage: stor,
            cryptography: crypto,
            auth,
            permissions: perms,
            anti_reverse: ar,
            overall_risk: SecurityRisk::Critical,
            findings,
            risk_score: 88.0,
        }
    }

    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.overall_risk == SecurityRisk::Critical
    }
    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn recompute(&mut self) {
        let mut score = 0.0_f64;
        let nr = self.network.risk_level();
        let sr = self.storage.risk_level();
        let cr = self.cryptography.risk_level();
        let ar = self.auth.risk_level();
        for r in [nr, sr, cr, ar] {
            score += match r {
                SecurityRisk::Low => 5.0,
                SecurityRisk::Medium => 20.0,
                SecurityRisk::High => 40.0,
                SecurityRisk::Critical => 70.0,
            };
        }
        score = (self.permissions.dangerous_count as f64).mul_add(3.0, score);
        self.risk_score = score.min(100.0);
        self.overall_risk = if score >= 60.0 {
            SecurityRisk::Critical
        } else if score >= 40.0 {
            SecurityRisk::High
        } else if score >= 20.0 {
            SecurityRisk::Medium
        } else {
            SecurityRisk::Low
        };
    }
}

impl fmt::Display for SecurityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityReport risk={} score={:.1} findings={}",
            self.overall_risk,
            self.risk_score,
            self.findings.len()
        )
    }
}

#[derive(Debug, Default)]
pub struct AndroidSecurityAnalyzer;
impl AndroidSecurityAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    #[must_use]
    pub fn analyze_manifest_xml(&self, xml: &str) -> NetworkSecurity {
        let lower = xml.to_lowercase();
        let allows_cleartext = lower.contains("usescleartexttraffic=\"true\"")
            || lower.contains("cleartexttrafficpermitted=\"true\"");
        let cert_pinning = lower.contains("pinset") || lower.contains("pin-set");
        let trust_user =
            lower.contains("trust-anchors") && lower.contains("certificates src=\"user\"");
        NetworkSecurity {
            allows_cleartext,
            certificate_pinning: cert_pinning,
            pinned_domains: vec![],
            trust_user_certs: trust_user,
            network_security_config: lower.contains("networksecurityconfig"),
            risk: None,
            exception_domains: vec![],
        }
    }
    #[must_use]
    pub fn analyze_dex_strings(&self, strings: &[String]) -> CryptographyUsage {
        let mut algos = Vec::new();
        let mut weak = false;
        let mut ecb = false;
        let mut hardcoded = Vec::new();
        for s in strings {
            let lower = s.to_lowercase();
            if lower.contains("aes") {
                algos.push("AES".into());
            }
            if lower.contains("des") && !lower.contains("3des") {
                weak = true;
                algos.push("DES (weak)".into());
            }
            if lower.contains("ecb") {
                ecb = true;
            }
            if lower.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                hardcoded.push(s.clone());
            }
        }
        CryptographyUsage {
            algorithms: algos,
            uses_weak_cipher: weak,
            uses_ecb_mode: ecb,
            hardcoded_keys: hardcoded,
            static_ivs: vec![],
        }
    }
    #[must_use]
    pub fn detect_anti_reverse(&self, strings: &[String]) -> AntiReverseDetection {
        let combined: String = strings
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        AntiReverseDetection {
            has_root_detection: combined.contains("isrooted")
                || combined.contains("/system/bin/su"),
            has_emulator_detection: combined.contains("emulator") || combined.contains("x86"),
            has_debugger_detection: combined.contains("isdebuggable")
                || combined.contains("debugger"),
            has_frida_detection: combined.contains("frida") || combined.contains("ptrace"),
            has_integrity_check: combined.contains("checksum")
                || combined.contains("signature")
                || combined.contains("sandbox"),
            obfuscation_tool: None,
            packer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_risk_display() {
        assert_eq!(SecurityRisk::Critical.to_string(), "CRITICAL");
    }
    #[test]
    fn test_network_cleartext_is_high() {
        let n = NetworkSecurity {
            allows_cleartext: true,
            certificate_pinning: false,
            ..Default::default()
        };
        assert!(n.risk_level() >= SecurityRisk::High);
    }
    #[test]
    fn test_network_pinning_is_low() {
        let n = NetworkSecurity {
            certificate_pinning: true,
            ..Default::default()
        };
        assert_eq!(n.risk_level(), SecurityRisk::Low);
    }
    #[test]
    fn test_storage_world_readable_is_high() {
        let s = StorageSecurity {
            world_readable_files: vec!["a".into()],
            ..Default::default()
        };
        assert_eq!(s.risk_level(), SecurityRisk::High);
    }
    #[test]
    fn test_crypto_hardcoded_key_critical() {
        let c = CryptographyUsage {
            hardcoded_keys: vec!["key".into()],
            ..Default::default()
        };
        assert_eq!(c.risk_level(), SecurityRisk::Critical);
    }
    #[test]
    fn test_crypto_ecb_mode_high() {
        let c = CryptographyUsage {
            uses_ecb_mode: true,
            ..Default::default()
        };
        assert_eq!(c.risk_level(), SecurityRisk::High);
    }
    #[test]
    fn test_auth_hardcoded_creds_critical() {
        let a = AuthMechanism {
            hardcoded_credentials: vec!["a:b".into()],
            ..Default::default()
        };
        assert_eq!(a.risk_level(), SecurityRisk::Critical);
    }
    #[test]
    fn test_anti_reverse_sophistication() {
        let ar = AntiReverseDetection {
            has_root_detection: true,
            has_debugger_detection: true,
            ..Default::default()
        };
        assert_eq!(ar.sophistication_score(), 4);
    }
    #[test]
    fn test_report_mock_has_critical() {
        let r = SecurityReport::mock();
        assert!(r.has_critical());
    }
    #[test]
    fn test_report_mock_findings_nonempty() {
        let r = SecurityReport::mock();
        assert!(!r.findings.is_empty());
    }
    #[test]
    fn test_report_display() {
        let r = SecurityReport::mock();
        let s = format!("{r}");
        assert!(s.contains("SecurityReport"));
    }
    #[test]
    fn test_report_recompute() {
        let mut r = SecurityReport::mock();
        r.recompute();
        assert!(r.risk_score <= 100.0);
    }
    #[test]
    fn test_report_serialization() {
        let r = SecurityReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: SecurityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.findings.len(), r.findings.len());
    }
    #[test]
    fn test_analyzer_manifest_cleartext() {
        let az = AndroidSecurityAnalyzer::new();
        let xml = "<application usesCleartextTraffic=\"true\">";
        let n = az.analyze_manifest_xml(xml);
        assert!(n.allows_cleartext);
    }
    #[test]
    fn test_analyzer_manifest_no_cleartext() {
        let az = AndroidSecurityAnalyzer::new();
        let n = az.analyze_manifest_xml("<application>");
        assert!(!n.allows_cleartext);
    }
    #[test]
    fn test_analyzer_dex_strings_ecb() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["AES/ECB/PKCS5Padding".into()];
        let c = az.analyze_dex_strings(&strs);
        assert!(c.uses_ecb_mode);
    }
    #[test]
    fn test_analyzer_detect_root() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["isRooted".into()];
        let ar = az.detect_anti_reverse(&strs);
        assert!(ar.has_root_detection);
    }
    #[test]
    fn test_analyzer_detect_frida() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["frida-agent".into()];
        let ar = az.detect_anti_reverse(&strs);
        assert!(ar.has_frida_detection);
    }
    #[test]
    fn test_permissions_risk_default() {
        let p = PermissionsRisk::default();
        assert_eq!(p.dangerous_count, 0);
    }
    #[test]
    fn test_security_risk_low_display() {
        assert_eq!(SecurityRisk::Low.to_string(), "LOW");
    }
    #[test]
    fn test_security_risk_medium() {
        assert_eq!(SecurityRisk::Medium.to_string(), "MEDIUM");
    }
    #[test]
    fn test_network_trust_user_is_high() {
        let n = NetworkSecurity {
            trust_user_certs: true,
            ..Default::default()
        };
        assert!(n.risk_level() >= SecurityRisk::High);
    }
    #[test]
    fn test_storage_external_no_encrypt_medium() {
        let s = StorageSecurity {
            external_storage_used: true,
            internal_storage_encrypted: false,
            ..Default::default()
        };
        assert!(s.risk_level() >= SecurityRisk::Medium);
    }
    #[test]
    fn test_crypto_ecb_mode_risk() {
        let c = CryptographyUsage {
            uses_ecb_mode: true,
            ..Default::default()
        };
        assert_eq!(c.risk_level(), SecurityRisk::High);
    }
    #[test]
    fn test_auth_weak_password_high() {
        let a = AuthMechanism {
            weak_passwords_allowed: true,
            ..Default::default()
        };
        assert_eq!(a.risk_level(), SecurityRisk::High);
    }
    #[test]
    fn test_anti_reverse_no_checks_zero() {
        let ar = AntiReverseDetection::default();
        assert_eq!(ar.sophistication_score(), 0);
    }
    #[test]
    fn test_report_mock_risk_high_or_critical() {
        let r = SecurityReport::mock();
        assert!(r.overall_risk >= SecurityRisk::High);
    }
    #[test]
    fn test_report_finding_count_positive() {
        let r = SecurityReport::mock();
        assert!(r.finding_count() > 0);
    }
    #[test]
    fn test_analyzer_dex_strings_des() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["DES/CBC".into()];
        let c = az.analyze_dex_strings(&strs);
        assert!(c.uses_weak_cipher);
    }
    #[test]
    fn test_analyzer_detect_emulator() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["emulator detected".into()];
        let ar = az.detect_anti_reverse(&strs);
        assert!(ar.has_emulator_detection);
    }
    #[test]
    fn test_analyzer_detect_debugger() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["isDebuggable check".into()];
        let ar = az.detect_anti_reverse(&strs);
        assert!(ar.has_debugger_detection);
    }
    #[test]
    fn test_analyzer_detect_sandbox() {
        let az = AndroidSecurityAnalyzer::new();
        let strs = vec!["sandbox_check failed".into()];
        let ar = az.detect_anti_reverse(&strs);
        assert!(ar.has_integrity_check);
    }
    #[test]
    fn test_report_recompute_score_capped() {
        let mut r = SecurityReport::mock();
        r.recompute();
        assert!(r.risk_score <= 100.0);
    }
    #[test]
    fn test_network_no_cleartext_no_exception() {
        let n = NetworkSecurity {
            allows_cleartext: false,
            certificate_pinning: true,
            ..Default::default()
        };
        assert_eq!(n.risk_level(), SecurityRisk::Low);
    }
    #[test]
    fn test_storage_world_writable_high() {
        let s = StorageSecurity {
            world_writable_files: vec!["f".into()],
            ..Default::default()
        };
        assert_eq!(s.risk_level(), SecurityRisk::High);
    }
    #[test]
    fn test_auth_biometric_set() {
        let a = AuthMechanism {
            biometric: true,
            ..Default::default()
        };
        assert!(a.biometric);
    }
    #[test]
    fn test_anti_reverse_five_checks_max_score() {
        let ar = AntiReverseDetection {
            has_root_detection: true,
            has_emulator_detection: true,
            has_debugger_detection: true,
            has_frida_detection: true,
            has_integrity_check: true,
            obfuscation_tool: None,
            packer: None,
        };
        assert_eq!(ar.sophistication_score(), 10);
    }
    #[test]
    fn test_crypto_hardcoded_key_risk() {
        let c = CryptographyUsage {
            hardcoded_keys: vec!["key".into()],
            ..Default::default()
        };
        assert_eq!(c.risk_level(), SecurityRisk::Critical);
    }
    #[test]
    fn test_network_exception_domain_risk_medium() {
        let n = NetworkSecurity {
            exception_domains: vec!["dev.example.com".into()],
            certificate_pinning: false,
            ..Default::default()
        };
        assert!(n.risk_level() >= SecurityRisk::Medium);
    }
    #[test]
    fn test_report_mock_network_is_insecure() {
        let r = SecurityReport::mock();
        assert!(r.network.is_insecure() || !r.network.exception_domains.is_empty());
    }
}
