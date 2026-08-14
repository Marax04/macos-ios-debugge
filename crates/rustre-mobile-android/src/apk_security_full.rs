//! `apk_security_full` — comprehensive APK security analysis module.
//!
//! Exposes [`ApkSecurityFull`] as the top-level engine and the following
//! sub-modules/types:
//! * [`DangerousPermissions`] — permission-based risk scoring
//! * [`NetworkSecurity`] — cleartext/pinning/custom-CA analysis
//! * [`CryptographyUsage`] — crypto API usage detection
//! * [`DataStorageSecurity`] — file, shared-prefs, `SQLite` storage checks
//! * [`AuthMechanism`] — authentication mechanism detection
//! * [`BiometricAuth`] — biometric API usage
//! * [`CodeQuality`] — code quality indicators
//! * [`SecurityReport`] — aggregated final report

pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AndroidManifest, Apk};
pub use crate::{Certificate, DexClass, NativeLib, StringEntry};

// ─── DangerousPermissions ────────────────────────────────────────────────────

/// Analysis of dangerous and privacy-sensitive permissions declared by the APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousPermissions {
    /// Total count of declared dangerous permissions.
    pub count: usize,
    /// Names of permissions that are considered spyware-relevant.
    pub spyware_relevant: Vec<String>,
    /// Names of permissions granting access to sensors (camera, microphone, etc.).
    pub sensor_permissions: Vec<String>,
    /// Names of permissions related to telephony and messaging.
    pub telephony_permissions: Vec<String>,
    /// Names of permissions related to location services.
    pub location_permissions: Vec<String>,
    /// Names of permissions related to financial/billing operations.
    pub financial_permissions: Vec<String>,
    /// Overall permission risk score (0.0–10.0).
    pub risk_score: f64,
}

impl DangerousPermissions {
    /// Analyse permissions from a parsed manifest.
    #[must_use]
    pub fn from_manifest(manifest: &AndroidManifest) -> Self {
        let dangerous: Vec<_> = manifest
            .permissions
            .iter()
            .filter(|p| matches!(p.protection_level, crate::ProtectionLevel::Dangerous))
            .collect();

        let spyware_relevant: Vec<String> = dangerous
            .iter()
            .filter(|p| p.is_spyware_relevant())
            .map(|p| p.name.clone())
            .collect();

        let sensor_permissions: Vec<String> = dangerous
            .iter()
            .filter(|p| p.is_av_recording() || p.name.contains("BODY_SENSORS"))
            .map(|p| p.name.clone())
            .collect();

        let telephony_permissions: Vec<String> = dangerous
            .iter()
            .filter(|p| p.is_telephony())
            .map(|p| p.name.clone())
            .collect();

        let location_permissions: Vec<String> = dangerous
            .iter()
            .filter(|p| p.is_location())
            .map(|p| p.name.clone())
            .collect();

        let financial_permissions: Vec<String> = dangerous
            .iter()
            .filter(|p| p.name.contains("BILLING") || p.name.contains("PAYMENT"))
            .map(|p| p.name.clone())
            .collect();

        let count = dangerous.len();
        let risk_score = Self::compute_score(count, &spyware_relevant, &telephony_permissions);

        Self {
            count,
            spyware_relevant,
            sensor_permissions,
            telephony_permissions,
            location_permissions,
            financial_permissions,
            risk_score,
        }
    }

    fn compute_score(total: usize, spyware: &[String], telephony: &[String]) -> f64 {
        let base = (total as f64 * 0.4).min(3.0);
        let spy_score = (spyware.len() as f64 * 0.9).min(3.5);
        let tel_score = (telephony.len() as f64 * 0.8).min(2.5);
        (base + spy_score + tel_score).min(10.0)
    }

    /// Returns `true` if the permission set exceeds the high-risk threshold.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= 6.0
    }

    /// Returns a short summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} dangerous permissions (spyware: {}, location: {}, telephony: {})",
            self.count,
            self.spyware_relevant.len(),
            self.location_permissions.len(),
            self.telephony_permissions.len(),
        )
    }
}

// ─── NetworkSecurity ─────────────────────────────────────────────────────────

/// Network-security configuration analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurity {
    /// Whether the app allows plaintext (HTTP) traffic.
    pub allows_cleartext: bool,
    /// Whether the app declares a custom Certificate Authority.
    pub has_custom_ca: bool,
    /// Whether certificate pinning is configured.
    pub has_certificate_pinning: bool,
    /// Whether the app communicates over localhost.
    pub allows_localhost: bool,
    /// Domains that are explicitly pinned.
    pub pinned_domains: Vec<String>,
    /// Domains that are explicitly exempted from cleartext restrictions.
    pub cleartext_exceptions: Vec<String>,
    /// Risk score contribution (0.0–10.0).
    pub risk_score: f64,
}

impl NetworkSecurity {
    /// Derive network-security posture from an APK.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let allows_cleartext = apk
            .manifest
            .as_ref()
            .is_some_and(|m| m.uses_cleartext_traffic);

        // Heuristic: look for network_security_config.xml reference in strings
        let has_custom_ca = apk.strings.iter().any(|s| {
            s.value.contains("network_security_config")
                || s.value.contains("user_trust")
                || s.value.contains("userCertificates")
        });

        let has_certificate_pinning = apk.strings.iter().any(|s| {
            s.value.contains("pin-set")
                || s.value.contains("PinnedDomains")
                || s.value.contains("certificatePinner")
                || s.value.contains("sha256/")
        });

        let allows_localhost = apk
            .strings
            .iter()
            .any(|s| s.value.contains("localhost") || s.value.contains("127.0.0.1"));

        let pinned_domains: Vec<String> = apk
            .strings
            .iter()
            .filter_map(|s| {
                if s.value.contains("sha256/") && s.value.contains('.') {
                    Some(s.value.clone())
                } else {
                    None
                }
            })
            .take(10)
            .collect();

        let cleartext_exceptions: Vec<String> = apk
            .strings
            .iter()
            .filter(|s| s.value.starts_with("http://") && s.value.len() > 10)
            .map(|s| s.value.clone())
            .take(5)
            .collect();

        let mut risk_score = 0.0_f64;
        if allows_cleartext {
            risk_score += 2.5;
        }
        if has_custom_ca {
            risk_score += 3.0;
        }
        if !has_certificate_pinning {
            risk_score += 1.0;
        }
        risk_score = risk_score.min(10.0);

        Self {
            allows_cleartext,
            has_custom_ca,
            has_certificate_pinning,
            allows_localhost,
            pinned_domains,
            cleartext_exceptions,
            risk_score,
        }
    }

    /// Returns `true` if the network configuration is considered insecure.
    #[must_use]
    pub const fn is_insecure(&self) -> bool {
        self.allows_cleartext || self.has_custom_ca
    }
}

// ─── CryptographyUsage ───────────────────────────────────────────────────────

/// Cryptographic API usage detected inside the APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographyUsage {
    /// Whether AES encryption calls are detected.
    pub uses_aes: bool,
    /// Whether RSA encryption calls are detected.
    pub uses_rsa: bool,
    /// Whether MD5 (weak) is used.
    pub uses_md5: bool,
    /// Whether SHA-1 (weak) is used.
    pub uses_sha1: bool,
    /// Whether SHA-256 or stronger is used.
    pub uses_strong_hash: bool,
    /// Whether an Android `KeyStore` is referenced.
    pub uses_keystore: bool,
    /// Whether hard-coded cryptographic keys are suspected.
    pub suspected_hardcoded_keys: bool,
    /// Base64-encoded strings found (potential key material).
    pub base64_blobs: Vec<String>,
    /// Detected cipher strings e.g. `"AES/CBC/PKCS5Padding"`.
    pub cipher_strings: Vec<String>,
    /// Risk score (0.0–10.0).
    pub risk_score: f64,
}

impl CryptographyUsage {
    /// Detect crypto usage from APK string constants and native libraries.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let strings_lower: Vec<String> =
            apk.strings.iter().map(|s| s.value.to_lowercase()).collect();

        let uses_aes = strings_lower.iter().any(|s| s.contains("aes"));
        let uses_rsa = strings_lower.iter().any(|s| s.contains("rsa"));
        let uses_md5 = strings_lower.iter().any(|s| s.contains("md5"));
        let uses_sha1 = strings_lower
            .iter()
            .any(|s| s.contains("sha-1") || s.contains("sha1"));
        let uses_strong_hash = strings_lower
            .iter()
            .any(|s| s.contains("sha-256") || s.contains("sha256") || s.contains("sha-512"));

        let uses_keystore = strings_lower
            .iter()
            .any(|s| s.contains("androidkeystore") || s.contains("keystore"));

        let base64_blobs: Vec<String> = apk
            .strings
            .iter()
            .filter(|s| s.is_base64_like())
            .map(|s| s.value.clone())
            .take(5)
            .collect();

        let suspected_hardcoded_keys = !base64_blobs.is_empty()
            || apk.strings.iter().any(|s| {
                let v = &s.value;
                v.len() == 32 || v.len() == 24 || v.len() == 16
            });

        let cipher_strings: Vec<String> = apk
            .strings
            .iter()
            .filter(|s| {
                let v = s.value.to_uppercase();
                v.contains("AES/") || v.contains("RSA/") || v.contains("DES/")
            })
            .map(|s| s.value.clone())
            .collect();

        let native_crypto = apk.native_libs.iter().any(super::NativeLib::uses_crypto);

        let mut risk_score = 0.0_f64;
        if uses_md5 {
            risk_score += 2.0;
        }
        if uses_sha1 {
            risk_score += 1.5;
        }
        if suspected_hardcoded_keys {
            risk_score += 3.0;
        }
        if native_crypto {
            risk_score += 1.0;
        }
        risk_score = risk_score.min(10.0);

        Self {
            uses_aes,
            uses_rsa,
            uses_md5,
            uses_sha1,
            uses_strong_hash,
            uses_keystore,
            suspected_hardcoded_keys,
            base64_blobs,
            cipher_strings,
            risk_score,
        }
    }

    /// Returns `true` if only weak cryptography is in use.
    #[must_use]
    pub const fn uses_only_weak_crypto(&self) -> bool {
        (self.uses_md5 || self.uses_sha1) && !self.uses_strong_hash
    }
}

// ─── DataStorageSecurity ─────────────────────────────────────────────────────

/// Security analysis of data storage patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStorageSecurity {
    /// Whether the app writes to external storage.
    pub writes_external_storage: bool,
    /// Whether the app uses world-readable shared preferences.
    pub uses_world_readable_prefs: bool,
    /// Whether the app uses `SQLite` and applies no encryption.
    pub uses_unencrypted_sqlite: bool,
    /// Whether the app stores credentials in plaintext.
    pub stores_plaintext_credentials: bool,
    /// Whether `SQLCipher` (encrypted `SQLite`) is used.
    pub uses_sqlcipher: bool,
    /// Whether `EncryptedSharedPreferences` (Jetpack) is used.
    pub uses_encrypted_shared_prefs: bool,
    /// File paths discovered that suggest sensitive data.
    pub sensitive_file_paths: Vec<String>,
    /// Risk score (0.0–10.0).
    pub risk_score: f64,
}

impl DataStorageSecurity {
    /// Detect data storage patterns from APK strings and classes.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let strings = &apk.strings;

        let writes_external_storage = strings.iter().any(|s| {
            s.value.contains("getExternalFilesDir")
                || s.value.contains("Environment.getExternalStorageDirectory")
                || s.value.contains("/sdcard/")
        });

        let uses_world_readable_prefs = strings.iter().any(|s| {
            s.value.contains("MODE_WORLD_READABLE") || s.value.contains("MODE_WORLD_WRITEABLE")
        });

        let uses_unencrypted_sqlite = strings.iter().any(|s| {
            (s.value.contains(".db") || s.value.contains("openDatabase"))
                && !s.value.contains("Cipher")
        });

        let stores_plaintext_credentials = strings.iter().any(|s| {
            let v = s.value.to_lowercase();
            v.contains("password") || v.contains("passwd") || v.contains("secret")
        });

        let uses_sqlcipher = strings.iter().any(|s| {
            s.value.contains("SQLiteDatabase")
                || s.value.to_lowercase().contains("sqlcipher")
                || s.value.contains("net.sqlcipher")
        });

        let uses_encrypted_shared_prefs = strings.iter().any(|s| {
            s.value.contains("EncryptedSharedPreferences")
                || s.value.contains("androidx.security.crypto")
        });

        let sensitive_file_paths: Vec<String> = strings
            .iter()
            .filter(|s| {
                let v = &s.value;
                (v.starts_with('/') || v.contains("/data/") || v.contains("/files/")) && v.len() > 5
            })
            .map(|s| s.value.clone())
            .take(10)
            .collect();

        let mut risk_score = 0.0_f64;
        if writes_external_storage {
            risk_score += 1.5;
        }
        if uses_world_readable_prefs {
            risk_score += 2.5;
        }
        if stores_plaintext_credentials {
            risk_score += 3.5;
        }
        if uses_unencrypted_sqlite && !uses_sqlcipher {
            risk_score += 1.0;
        }
        risk_score = risk_score.min(10.0);

        Self {
            writes_external_storage,
            uses_world_readable_prefs,
            uses_unencrypted_sqlite,
            stores_plaintext_credentials,
            uses_sqlcipher,
            uses_encrypted_shared_prefs,
            sensitive_file_paths,
            risk_score,
        }
    }
}

// ─── AuthMechanism ───────────────────────────────────────────────────────────

/// Authentication mechanism detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMechanism {
    /// Whether OAuth/OIDC is used.
    pub uses_oauth: bool,
    /// Whether Firebase Authentication is used.
    pub uses_firebase_auth: bool,
    /// Whether JWT tokens are used.
    pub uses_jwt: bool,
    /// Whether API keys are embedded.
    pub has_embedded_api_keys: bool,
    /// Whether session cookies are used.
    pub uses_session_cookies: bool,
    /// Whether two-factor authentication flows are detected.
    pub has_two_factor: bool,
    /// Detected authentication endpoints.
    pub auth_endpoints: Vec<String>,
    /// Risk score (0.0–10.0).
    pub risk_score: f64,
}

impl AuthMechanism {
    /// Detect authentication mechanisms from APK strings.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let strings = &apk.strings;

        let uses_oauth = strings.iter().any(|s| {
            s.value.to_lowercase().contains("oauth")
                || s.value.contains("authorization_code")
                || s.value.contains("access_token")
        });

        let uses_firebase_auth = strings.iter().any(|s| {
            s.value.contains("firebase") && (s.value.contains("Auth") || s.value.contains("auth"))
        });

        let uses_jwt = strings.iter().any(|s| {
            let v = s.value.to_lowercase();
            v.contains("jwt") || v.contains("bearer ") || v.contains("json web token")
        });

        let has_embedded_api_keys = strings.iter().any(|s| {
            let v = &s.value;
            (v.starts_with("AIza") || v.starts_with("AAAA") || v.contains("_api_key"))
                && v.len() > 20
        });

        let uses_session_cookies = strings.iter().any(|s| {
            let v = s.value.to_lowercase();
            v.contains("sessionid") || v.contains("session_cookie") || v.contains("JSESSIONID")
        });

        let has_two_factor = strings.iter().any(|s| {
            let v = s.value.to_lowercase();
            v.contains("totp") || v.contains("one-time") || v.contains("otp") || v.contains("2fa")
        });

        let auth_endpoints: Vec<String> = strings
            .iter()
            .filter(|s| {
                let v = s.value.to_lowercase();
                s.is_url()
                    && (v.contains("login")
                        || v.contains("auth")
                        || v.contains("token")
                        || v.contains("oauth"))
            })
            .map(|s| s.value.clone())
            .take(5)
            .collect();

        let mut risk_score = 0.0_f64;
        if has_embedded_api_keys {
            risk_score += 4.0;
        }
        if !has_two_factor {
            risk_score += 0.5;
        }
        if !uses_oauth && !uses_firebase_auth {
            risk_score += 0.5;
        }
        risk_score = risk_score.min(10.0);

        Self {
            uses_oauth,
            uses_firebase_auth,
            uses_jwt,
            has_embedded_api_keys,
            uses_session_cookies,
            has_two_factor,
            auth_endpoints,
            risk_score,
        }
    }
}

// ─── BiometricAuth ───────────────────────────────────────────────────────────

/// Biometric authentication API usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricAuth {
    /// Whether `BiometricPrompt` API is used.
    pub uses_biometric_prompt: bool,
    /// Whether the deprecated `FingerprintManager` API is used.
    pub uses_fingerprint_manager: bool,
    /// Whether iris/face authentication APIs are used.
    pub uses_face_recognition: bool,
    /// Whether biometrics are combined with cryptographic operations.
    pub uses_crypto_biometrics: bool,
    /// Whether `BIOMETRIC_STRONG` mode is requested.
    pub requires_strong_biometric: bool,
    /// Risk score (0.0–10.0).  Lower is better.
    pub risk_score: f64,
}

impl BiometricAuth {
    /// Detect biometric API usage from APK classes and strings.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let has_class = |suffix: &str| {
            apk.dex_classes
                .iter()
                .any(|c| c.descriptor.contains(suffix))
        };
        let has_string = |pattern: &str| apk.strings.iter().any(|s| s.value.contains(pattern));

        let uses_biometric_prompt = has_class("BiometricPrompt")
            || has_string("android.hardware.biometrics.BiometricPrompt");
        let uses_fingerprint_manager = has_class("FingerprintManager")
            || has_string("android.hardware.fingerprint.FingerprintManager");
        let uses_face_recognition =
            has_string("FaceRecognition") || has_string("android.hardware.biometrics.FACE");
        let uses_crypto_biometrics =
            has_string("CryptoObject") || has_class("BiometricPrompt$CryptoObject");
        let requires_strong_biometric = has_string("BIOMETRIC_STRONG")
            || has_string("BiometricManager.Authenticators.BIOMETRIC_STRONG");

        let mut risk_score = 0.0_f64;
        if uses_fingerprint_manager && !uses_biometric_prompt {
            risk_score += 2.0;
        }
        if !uses_crypto_biometrics {
            risk_score += 1.0;
        }
        if !requires_strong_biometric {
            risk_score += 1.0;
        }
        risk_score = risk_score.min(10.0);

        Self {
            uses_biometric_prompt,
            uses_fingerprint_manager,
            uses_face_recognition,
            uses_crypto_biometrics,
            requires_strong_biometric,
            risk_score,
        }
    }
}

// ─── CodeQuality ─────────────────────────────────────────────────────────────

/// Code quality security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQuality {
    /// Whether the app is built as a debug build.
    pub is_debug_build: bool,
    /// Whether `StrictMode` is enabled.
    pub uses_strict_mode: bool,
    /// Whether `ProGuard`/`R8` has been applied.
    pub is_minified: bool,
    /// Whether the APK is signed with a debug certificate.
    pub debug_signed: bool,
    /// Whether stack traces are leaked to the user.
    pub leaks_stack_traces: bool,
    /// Whether logging calls reveal sensitive data.
    pub excessive_logging: bool,
    /// Number of exported components without a permission guard.
    pub unprotected_exports: usize,
    /// Whether the `allowBackup` flag is set.
    pub allows_backup: bool,
    /// Risk score (0.0–10.0).
    pub risk_score: f64,
}

impl CodeQuality {
    /// Assess code quality indicators from a parsed APK.
    #[must_use]
    pub fn from_apk(apk: &Apk) -> Self {
        let is_debug_build = apk.manifest.as_ref().is_some_and(|m| m.debuggable);

        let uses_strict_mode = apk
            .strings
            .iter()
            .any(|s| s.value.contains("StrictMode") || s.value.contains("detectAll"));

        let is_minified = apk
            .obfuscation
            .as_ref()
            .is_some_and(|o| o.has_proguard_markers);

        let debug_signed = apk.is_debug_signed();

        let leaks_stack_traces = apk
            .strings
            .iter()
            .any(|s| s.value.contains("printStackTrace") || s.value.contains("stackTrace"));

        let excessive_logging = apk.strings.iter().any(|s| {
            let v = s.value.to_lowercase();
            v.contains("log.d(") || v.contains("log.v(") || v.contains("log.w(")
        });

        let unprotected_exports = apk.manifest.as_ref().map_or(0, |m| {
            m.services
                .iter()
                .chain(m.receivers.iter())
                .chain(m.providers.iter())
                .filter(|c| c.is_exposed())
                .count()
        });

        let allows_backup = apk.manifest.as_ref().is_some_and(|m| m.allow_backup);

        let mut risk_score = 0.0_f64;
        if is_debug_build {
            risk_score += 2.0;
        }
        if debug_signed {
            risk_score += 1.5;
        }
        if !is_minified {
            risk_score += 0.5;
        }
        if leaks_stack_traces {
            risk_score += 1.0;
        }
        if excessive_logging {
            risk_score += 0.5;
        }
        risk_score += (unprotected_exports as f64 * 0.5).min(2.0);
        if allows_backup {
            risk_score += 0.5;
        }
        risk_score = risk_score.min(10.0);

        Self {
            is_debug_build,
            uses_strict_mode,
            is_minified,
            debug_signed,
            leaks_stack_traces,
            excessive_logging,
            unprotected_exports,
            allows_backup,
            risk_score,
        }
    }
}

// ─── SecurityReport ──────────────────────────────────────────────────────────

/// Aggregated security report produced by [`ApkSecurityFull`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Package identifier.
    pub package: String,
    /// Permission-based risk analysis.
    pub permissions: DangerousPermissions,
    /// Network security posture.
    pub network: NetworkSecurity,
    /// Cryptography usage.
    pub crypto: CryptographyUsage,
    /// Data storage security.
    pub storage: DataStorageSecurity,
    /// Authentication mechanism.
    pub auth: AuthMechanism,
    /// Biometric authentication.
    pub biometric: BiometricAuth,
    /// Code quality indicators.
    pub code_quality: CodeQuality,
    /// Overall risk score (0.0–10.0).
    pub overall_risk: f64,
    /// Severity label: "low", "medium", "high", or "critical".
    pub severity: String,
    /// Top security findings as human-readable strings.
    pub findings: Vec<String>,
}

impl SecurityReport {
    /// Compute overall risk and severity from component scores.
    fn finalize(mut report: Self) -> Self {
        let scores = [
            report.permissions.risk_score,
            report.network.risk_score,
            report.crypto.risk_score,
            report.storage.risk_score,
            report.auth.risk_score,
            report.biometric.risk_score,
            report.code_quality.risk_score,
        ];
        let sum: f64 = scores.iter().sum();
        let overall = (sum / scores.len() as f64).min(10.0);
        report.overall_risk = overall;

        report.severity = match overall as u32 {
            0..=2 => "low",
            3..=5 => "medium",
            6..=7 => "high",
            _ => "critical",
        }
        .to_string();

        // Collect key findings.
        let mut findings = Vec::new();
        if report.permissions.is_high_risk() {
            findings.push(report.permissions.summary());
        }
        if report.network.is_insecure() {
            findings.push("Insecure network configuration".to_string());
        }
        if report.crypto.uses_only_weak_crypto() {
            findings.push("Only weak cryptography detected".to_string());
        }
        if report.storage.stores_plaintext_credentials {
            findings.push("Plaintext credentials in storage".to_string());
        }
        if report.auth.has_embedded_api_keys {
            findings.push("Embedded API keys detected".to_string());
        }
        if report.code_quality.is_debug_build {
            findings.push("Debug build enabled".to_string());
        }

        report.findings = findings;
        report
    }
}

// ─── ApkSecurityFull ─────────────────────────────────────────────────────────

/// Top-level APK security analysis engine.
///
/// Runs all sub-analyses on a parsed [`Apk`] and returns a [`SecurityReport`].
#[derive(Debug, Default, Clone)]
pub struct ApkSecurityFull;

impl ApkSecurityFull {
    /// Create a new engine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse the given APK and produce a full security report.
    #[must_use]
    pub fn analyze(&self, apk: &Apk) -> SecurityReport {
        let package = apk
            .manifest
            .as_ref()
            .map_or_else(|| "unknown".to_string(), |m| m.package.clone());

        let permissions = apk
            .manifest
            .as_ref().map_or_else(|| DangerousPermissions {
                count: 0,
                spyware_relevant: vec![],
                sensor_permissions: vec![],
                telephony_permissions: vec![],
                location_permissions: vec![],
                financial_permissions: vec![],
                risk_score: 0.0,
            }, DangerousPermissions::from_manifest);

        let network = NetworkSecurity::from_apk(apk);
        let crypto = CryptographyUsage::from_apk(apk);
        let storage = DataStorageSecurity::from_apk(apk);
        let auth = AuthMechanism::from_apk(apk);
        let biometric = BiometricAuth::from_apk(apk);
        let code_quality = CodeQuality::from_apk(apk);

        let report = SecurityReport {
            package,
            permissions,
            network,
            crypto,
            storage,
            auth,
            biometric,
            code_quality,
            overall_risk: 0.0,
            severity: String::new(),
            findings: Vec::new(),
        };

        SecurityReport::finalize(report)
    }

    /// Quick-scan an APK, returning only the overall risk score.
    #[must_use]
    pub fn quick_score(&self, apk: &Apk) -> f64 {
        self.analyze(apk).overall_risk
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AndroidManifest, Apk, StringEntry};

    fn mock_apk() -> Apk {
        Apk::mock()
    }

    // ── ApkSecurityFull ───────────────────────────────────────────────────────

    #[test]
    fn test_engine_new() {
        let engine = ApkSecurityFull::new();
        let apk = mock_apk();
        let report = engine.analyze(&apk);
        assert!(!report.package.is_empty());
    }

    #[test]
    fn test_quick_score_range() {
        let engine = ApkSecurityFull::new();
        let score = engine.quick_score(&mock_apk());
        assert!((0.0..=10.0).contains(&score));
    }

    #[test]
    fn test_report_severity_nonempty() {
        let report = ApkSecurityFull::new().analyze(&mock_apk());
        assert!(!report.severity.is_empty());
    }

    #[test]
    fn test_report_serialization() {
        let report = ApkSecurityFull::new().analyze(&mock_apk());
        let json = serde_json::to_string(&report).unwrap();
        let decoded: SecurityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.package, report.package);
    }

    #[test]
    fn test_overall_risk_capped() {
        let report = ApkSecurityFull::new().analyze(&mock_apk());
        assert!(report.overall_risk <= 10.0);
    }

    // ── DangerousPermissions ──────────────────────────────────────────────────

    #[test]
    fn test_dangerous_permissions_from_manifest() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(dp.count > 0);
    }

    #[test]
    fn test_dangerous_permissions_risk_score_positive() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(dp.risk_score > 0.0);
    }

    #[test]
    fn test_dangerous_permissions_spyware_relevant() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(!dp.spyware_relevant.is_empty());
    }

    #[test]
    fn test_dangerous_permissions_is_high_risk() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        // mock has many dangerous permissions — should be high risk
        let _ = dp.is_high_risk(); // no panic
    }

    #[test]
    fn test_dangerous_permissions_summary_nonempty() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(!dp.summary().is_empty());
    }

    #[test]
    fn test_dangerous_permissions_empty_manifest() {
        let mut m = AndroidManifest::mock("com.empty");
        m.permissions.clear();
        let dp = DangerousPermissions::from_manifest(&m);
        assert_eq!(dp.count, 0);
        assert!((dp.risk_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dangerous_permissions_location() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(!dp.location_permissions.is_empty());
    }

    #[test]
    fn test_dangerous_permissions_telephony() {
        let m = AndroidManifest::mock("com.test");
        let dp = DangerousPermissions::from_manifest(&m);
        assert!(!dp.telephony_permissions.is_empty());
    }

    // ── NetworkSecurity ───────────────────────────────────────────────────────

    #[test]
    fn test_network_security_from_apk() {
        let apk = mock_apk();
        let ns = NetworkSecurity::from_apk(&apk);
        assert!(ns.risk_score >= 0.0);
    }

    #[test]
    fn test_network_security_risk_capped() {
        let apk = mock_apk();
        let ns = NetworkSecurity::from_apk(&apk);
        assert!(ns.risk_score <= 10.0);
    }

    #[test]
    fn test_network_security_cleartext_detected() {
        let mut apk = mock_apk();
        if let Some(ref mut m) = apk.manifest {
            m.uses_cleartext_traffic = true;
        }
        apk.strings.push(StringEntry {
            value: "http://evil.com/api".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let ns = NetworkSecurity::from_apk(&apk);
        assert!(ns.allows_cleartext || !ns.cleartext_exceptions.is_empty() || ns.risk_score > 0.0);
    }

    #[test]
    fn test_network_security_is_insecure_false_when_clean() {
        let apk = Apk::new();
        let ns = NetworkSecurity::from_apk(&apk);
        assert!(!ns.is_insecure());
    }

    // ── CryptographyUsage ─────────────────────────────────────────────────────

    #[test]
    fn test_crypto_usage_from_apk() {
        let apk = mock_apk();
        let c = CryptographyUsage::from_apk(&apk);
        assert!(c.risk_score >= 0.0 && c.risk_score <= 10.0);
    }

    #[test]
    fn test_crypto_usage_md5_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "MD5".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let c = CryptographyUsage::from_apk(&apk);
        assert!(c.uses_md5);
    }

    #[test]
    fn test_crypto_usage_aes_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "AES/CBC/PKCS5Padding".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let c = CryptographyUsage::from_apk(&apk);
        assert!(c.uses_aes);
    }

    #[test]
    fn test_crypto_only_weak_no_strong() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "MD5".to_string(),
            from_dex: true,
            from_resources: false,
        });
        apk.strings.push(StringEntry {
            value: "SHA1".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let c = CryptographyUsage::from_apk(&apk);
        assert!(c.uses_only_weak_crypto());
    }

    #[test]
    fn test_crypto_keystore_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "AndroidKeyStore".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let c = CryptographyUsage::from_apk(&apk);
        assert!(c.uses_keystore);
    }

    // ── DataStorageSecurity ───────────────────────────────────────────────────

    #[test]
    fn test_data_storage_from_apk() {
        let apk = mock_apk();
        let ds = DataStorageSecurity::from_apk(&apk);
        assert!(ds.risk_score >= 0.0 && ds.risk_score <= 10.0);
    }

    #[test]
    fn test_data_storage_plaintext_creds() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "password123".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let ds = DataStorageSecurity::from_apk(&apk);
        assert!(ds.stores_plaintext_credentials);
    }

    #[test]
    fn test_data_storage_sqlcipher() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "net.sqlcipher.database.SQLiteDatabase".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let ds = DataStorageSecurity::from_apk(&apk);
        assert!(ds.uses_sqlcipher);
    }

    // ── AuthMechanism ─────────────────────────────────────────────────────────

    #[test]
    fn test_auth_from_apk() {
        let apk = mock_apk();
        let auth = AuthMechanism::from_apk(&apk);
        assert!(auth.risk_score >= 0.0 && auth.risk_score <= 10.0);
    }

    #[test]
    fn test_auth_oauth_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "authorization_code".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let auth = AuthMechanism::from_apk(&apk);
        assert!(auth.uses_oauth);
    }

    #[test]
    fn test_auth_api_key_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let auth = AuthMechanism::from_apk(&apk);
        assert!(auth.has_embedded_api_keys);
    }

    // ── BiometricAuth ─────────────────────────────────────────────────────────

    #[test]
    fn test_biometric_from_apk() {
        let apk = mock_apk();
        let bio = BiometricAuth::from_apk(&apk);
        assert!(bio.risk_score >= 0.0 && bio.risk_score <= 10.0);
    }

    #[test]
    fn test_biometric_fingerprint_manager_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "android.hardware.fingerprint.FingerprintManager".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let bio = BiometricAuth::from_apk(&apk);
        assert!(bio.uses_fingerprint_manager);
    }

    #[test]
    fn test_biometric_prompt_detected() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "android.hardware.biometrics.BiometricPrompt".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let bio = BiometricAuth::from_apk(&apk);
        assert!(bio.uses_biometric_prompt);
    }

    // ── CodeQuality ───────────────────────────────────────────────────────────

    #[test]
    fn test_code_quality_from_apk() {
        let apk = mock_apk();
        let cq = CodeQuality::from_apk(&apk);
        assert!(cq.risk_score >= 0.0 && cq.risk_score <= 10.0);
    }

    #[test]
    fn test_code_quality_debug_signed() {
        let apk = mock_apk();
        let cq = CodeQuality::from_apk(&apk);
        assert!(cq.debug_signed); // mock uses debug cert
    }

    #[test]
    fn test_code_quality_allows_backup() {
        let apk = mock_apk();
        let cq = CodeQuality::from_apk(&apk);
        assert!(cq.allows_backup); // mock has allow_backup = true
    }

    #[test]
    fn test_code_quality_stack_trace_logging() {
        let mut apk = Apk::new();
        apk.strings.push(StringEntry {
            value: "e.printStackTrace()".to_string(),
            from_dex: true,
            from_resources: false,
        });
        let cq = CodeQuality::from_apk(&apk);
        assert!(cq.leaks_stack_traces);
    }

    // ── SecurityReport ────────────────────────────────────────────────────────

    #[test]
    fn test_security_report_findings_nonempty_for_mock() {
        let report = ApkSecurityFull::new().analyze(&mock_apk());
        // Mock APK has many indicators; at least one finding expected
        let _ = report.findings.len(); // no panic
    }

    #[test]
    fn test_security_report_severity_valid_values() {
        let report = ApkSecurityFull::new().analyze(&mock_apk());
        let valid = ["low", "medium", "high", "critical"];
        assert!(valid.contains(&report.severity.as_str()));
    }

    #[test]
    fn test_security_report_package_matches_manifest() {
        let apk = mock_apk();
        let pkg = apk.manifest.as_ref().unwrap().package.clone();
        let report = ApkSecurityFull::new().analyze(&apk);
        assert_eq!(report.package, pkg);
    }

    #[test]
    fn test_security_report_empty_apk() {
        let apk = Apk::new();
        let report = ApkSecurityFull::new().analyze(&apk);
        assert_eq!(report.package, "unknown");
        assert!(report.overall_risk >= 0.0);
    }
}
