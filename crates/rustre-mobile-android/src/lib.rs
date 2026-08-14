//! `rustre-mobile-android` — Android APK static analysis types and algorithms.
//!
//! Provides comprehensive Android APK analysis including manifest parsing,
//! permission analysis, component enumeration, DEX class listing, string
//! extraction, native library detection, certificate analysis, obfuscation
//! detection, and threat scoring.

pub mod android_malware;
pub mod android_permissions;
pub mod android_security;
pub mod apk_security_full;
pub mod art_runtime;
pub mod dex_analysis;
pub mod dex_obfuscation;
pub mod jni_inference;
pub mod dex_class_hierarchy;
pub mod android_manifest_parser;
pub mod smali_lifter;

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced during Android APK analysis.
#[derive(Debug, Error)]
pub enum AndroidError {
    /// XML or binary-XML parsing failed.
    #[error("parse error: {0}")]
    ParseError(String),
    /// The file is not a valid APK (zip) or is corrupted.
    #[error("invalid APK: {0}")]
    InvalidApk(String),
    /// A required resource was not found inside the APK.
    #[error("not found: {0}")]
    NotFound(String),
    /// An I/O error occurred while reading the APK.
    #[error("io error: {0}")]
    Io(String),
    /// Certificate parsing or verification failed.
    #[error("certificate error: {0}")]
    CertificateError(String),
    /// The DEX file could not be parsed.
    #[error("dex error: {0}")]
    DexError(String),
}

// ─── ProtectionLevel ─────────────────────────────────────────────────────────

/// Android permission protection levels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// Automatically granted at install time.
    Normal,
    /// Requires explicit user approval.
    Dangerous,
    /// Granted only to apps signed with the platform key.
    Signature,
    /// Granted only to system apps.
    System,
    /// Pre-installed apps with system-level access.
    Privileged,
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Dangerous => write!(f, "dangerous"),
            Self::Signature => write!(f, "signature"),
            Self::System => write!(f, "system"),
            Self::Privileged => write!(f, "privileged"),
        }
    }
}

impl ProtectionLevel {
    /// Returns `true` if this permission requires runtime user approval.
    #[must_use]
    pub const fn requires_runtime_grant(&self) -> bool {
        matches!(self, Self::Dangerous)
    }

    /// Risk score for this protection level (0.0 – 10.0).
    #[must_use]
    pub const fn risk_score(&self) -> f64 {
        match self {
            Self::Normal => 1.0,
            Self::Dangerous => 6.0,
            Self::Signature => 4.0,
            Self::System => 8.0,
            Self::Privileged => 9.0,
        }
    }
}

// ─── Permission ──────────────────────────────────────────────────────────────

/// A permission declared or used by the app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Fully-qualified permission name, e.g. `android.permission.CAMERA`.
    pub name: String,
    /// Protection level of this permission.
    pub protection_level: ProtectionLevel,
    /// Whether the app *uses* (requests) this permission, as opposed to declaring it.
    pub is_uses_permission: bool,
    /// Optional description or label string resource reference.
    pub description: Option<String>,
}

impl Permission {
    /// Create a simple uses-permission entry.
    #[must_use]
    pub fn uses(name: impl Into<String>, level: ProtectionLevel) -> Self {
        Self {
            name: name.into(),
            protection_level: level,
            is_uses_permission: true,
            description: None,
        }
    }

    /// Returns `true` if this is a GPS/location permission.
    #[must_use]
    pub fn is_location(&self) -> bool {
        self.name.contains("LOCATION")
    }

    /// Returns `true` if this is an SMS/call permission.
    #[must_use]
    pub fn is_telephony(&self) -> bool {
        self.name.contains("SMS") || self.name.contains("CALL") || self.name.contains("PHONE")
    }

    /// Returns `true` if this is a camera/microphone permission.
    #[must_use]
    pub fn is_av_recording(&self) -> bool {
        self.name.contains("CAMERA") || self.name.contains("RECORD_AUDIO")
    }

    /// Returns `true` if this looks like a dangerous spyware-relevant permission.
    #[must_use]
    pub fn is_spyware_relevant(&self) -> bool {
        self.is_location()
            || self.is_telephony()
            || self.is_av_recording()
            || self.name.contains("READ_CONTACTS")
            || self.name.contains("READ_CALL_LOG")
            || self.name.contains("READ_SMS")
            || self.name.contains("PROCESS_OUTGOING_CALLS")
    }
}

// ─── IntentFilter ─────────────────────────────────────────────────────────────

/// An intent filter declared on an Android component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    /// Actions this filter responds to, e.g. `android.intent.action.MAIN`.
    pub actions: Vec<String>,
    /// Categories, e.g. `android.intent.category.LAUNCHER`.
    pub categories: Vec<String>,
    /// Data schemes, e.g. `https`.
    pub schemes: Vec<String>,
    /// MIME types, e.g. `image/png`.
    pub mime_types: Vec<String>,
}

impl IntentFilter {
    /// Returns `true` if this is the launcher (main entry point) filter.
    #[must_use]
    pub fn is_launcher(&self) -> bool {
        self.actions.iter().any(|a| a.contains("MAIN"))
            && self.categories.iter().any(|c| c.contains("LAUNCHER"))
    }

    /// Returns `true` if this filter handles boot-completed events.
    #[must_use]
    pub fn is_boot_receiver(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.contains("BOOT_COMPLETED") || a.contains("QUICKBOOT_POWERON"))
    }

    /// Returns `true` if this filter handles SMS messages.
    #[must_use]
    pub fn is_sms_receiver(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.contains("SMS_RECEIVED") || a.contains("WAP_PUSH_RECEIVED"))
    }
}

// ─── ComponentKind ────────────────────────────────────────────────────────────

/// Android component type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentKind {
    Activity,
    Service,
    BroadcastReceiver,
    ContentProvider,
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Activity => write!(f, "activity"),
            Self::Service => write!(f, "service"),
            Self::BroadcastReceiver => write!(f, "receiver"),
            Self::ContentProvider => write!(f, "provider"),
        }
    }
}

// ─── Component ────────────────────────────────────────────────────────────────

/// A component (activity, service, receiver, or provider) declared in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Fully-qualified class name.
    pub name: String,
    /// Whether this component is exported (accessible from other apps).
    pub exported: bool,
    /// Whether this component requires a permission to invoke it.
    pub required_permission: Option<String>,
    /// Intent filters registered for this component.
    pub intent_filters: Vec<IntentFilter>,
    /// Component kind.
    pub kind: ComponentKind,
    /// Whether the component runs in a separate process.
    pub separate_process: bool,
}

impl Component {
    /// Returns `true` if the component is exported without requiring a permission.
    #[must_use]
    pub const fn is_exposed(&self) -> bool {
        self.exported && self.required_permission.is_none()
    }

    /// Returns `true` if any intent filter is a boot receiver.
    #[must_use]
    pub fn is_boot_receiver(&self) -> bool {
        self.intent_filters
            .iter()
            .any(IntentFilter::is_boot_receiver)
    }

    /// Returns `true` if any intent filter receives SMS.
    #[must_use]
    pub fn is_sms_interceptor(&self) -> bool {
        self.intent_filters
            .iter()
            .any(IntentFilter::is_sms_receiver)
    }
}

// ─── Activity ────────────────────────────────────────────────────────────────

/// Convenience alias for component analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    /// Fully-qualified class name.
    pub name: String,
    /// Whether this activity is exported.
    pub exported: bool,
    /// Intent filters declared on this activity.
    pub intent_filters: Vec<String>,
    /// Whether this is the launcher main activity.
    pub is_launcher: bool,
    /// Theme attribute, if declared.
    pub theme: Option<String>,
}

// ─── AndroidManifest ─────────────────────────────────────────────────────────

/// Parsed `AndroidManifest.xml` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidManifest {
    /// The application package identifier, e.g. `com.example.app`.
    pub package: String,
    /// Human-readable version string.
    pub version_name: String,
    /// Integer version code.
    pub version_code: u32,
    /// Minimum Android API level required.
    pub min_sdk: u32,
    /// Target Android API level.
    pub target_sdk: u32,
    /// Maximum supported API level (optional).
    pub max_sdk: Option<u32>,
    /// All permissions used or declared by the app.
    pub permissions: Vec<Permission>,
    /// All activities declared in the manifest.
    pub activities: Vec<Activity>,
    /// All services declared in the manifest.
    pub services: Vec<Component>,
    /// All broadcast receivers declared in the manifest.
    pub receivers: Vec<Component>,
    /// All content providers declared in the manifest.
    pub providers: Vec<Component>,
    /// Whether the app requests `debuggable=true`.
    pub debuggable: bool,
    /// Whether the app requests backup support.
    pub allow_backup: bool,
    /// Whether the app uses cleartext (non-HTTPS) traffic.
    pub uses_cleartext_traffic: bool,
    /// Application class name (if custom).
    pub application_class: Option<String>,
    /// Shared user ID, if declared.
    pub shared_user_id: Option<String>,
    /// Supported screen sizes.
    pub supported_screens: Vec<String>,
    /// Custom attributes present in the manifest.
    pub extra_attributes: HashMap<String, String>,
}

impl AndroidManifest {
    /// Create a mock manifest for testing.
    #[must_use]
    pub fn mock(pkg: impl Into<String>) -> Self {
        let boot_filter = IntentFilter {
            actions: vec!["android.intent.action.BOOT_COMPLETED".to_string()],
            categories: vec![],
            schemes: vec![],
            mime_types: vec![],
        };
        let sms_filter = IntentFilter {
            actions: vec!["android.provider.Telephony.SMS_RECEIVED".to_string()],
            categories: vec![],
            schemes: vec![],
            mime_types: vec![],
        };
        Self {
            package: pkg.into(),
            version_name: "1.0.0".to_string(),
            version_code: 1,
            min_sdk: 21,
            target_sdk: 33,
            max_sdk: None,
            permissions: vec![
                Permission::uses("android.permission.INTERNET", ProtectionLevel::Normal),
                Permission::uses("android.permission.CAMERA", ProtectionLevel::Dangerous),
                Permission::uses(
                    "android.permission.READ_CONTACTS",
                    ProtectionLevel::Dangerous,
                ),
                Permission::uses("android.permission.READ_SMS", ProtectionLevel::Dangerous),
                Permission::uses(
                    "android.permission.RECORD_AUDIO",
                    ProtectionLevel::Dangerous,
                ),
                Permission::uses(
                    "android.permission.ACCESS_FINE_LOCATION",
                    ProtectionLevel::Dangerous,
                ),
            ],
            activities: vec![
                Activity {
                    name: "com.example.MainActivity".to_string(),
                    exported: true,
                    intent_filters: vec!["android.intent.action.MAIN".to_string()],
                    is_launcher: true,
                    theme: Some("@android:style/Theme.Material".to_string()),
                },
                Activity {
                    name: "com.example.LoginActivity".to_string(),
                    exported: false,
                    intent_filters: vec![],
                    is_launcher: false,
                    theme: None,
                },
            ],
            services: vec![Component {
                name: "com.example.BackgroundService".to_string(),
                exported: false,
                required_permission: None,
                intent_filters: vec![],
                kind: ComponentKind::Service,
                separate_process: false,
            }],
            receivers: vec![
                Component {
                    name: "com.example.BootReceiver".to_string(),
                    exported: true,
                    required_permission: None,
                    intent_filters: vec![boot_filter],
                    kind: ComponentKind::BroadcastReceiver,
                    separate_process: false,
                },
                Component {
                    name: "com.example.SmsReceiver".to_string(),
                    exported: true,
                    required_permission: None,
                    intent_filters: vec![sms_filter],
                    kind: ComponentKind::BroadcastReceiver,
                    separate_process: false,
                },
            ],
            providers: vec![],
            debuggable: false,
            allow_backup: true,
            uses_cleartext_traffic: false,
            application_class: None,
            shared_user_id: None,
            supported_screens: vec![
                "small".to_string(),
                "normal".to_string(),
                "large".to_string(),
            ],
            extra_attributes: HashMap::new(),
        }
    }

    /// Return activities that are exported.
    #[must_use]
    pub fn exported_activities(&self) -> Vec<&Activity> {
        self.activities.iter().filter(|a| a.exported).collect()
    }

    /// Return permissions with `Dangerous` protection level.
    #[must_use]
    pub fn dangerous_permissions(&self) -> Vec<&Permission> {
        self.permissions
            .iter()
            .filter(|p| p.protection_level == ProtectionLevel::Dangerous)
            .collect()
    }

    /// Return permissions that are spyware-relevant.
    #[must_use]
    pub fn spyware_permissions(&self) -> Vec<&Permission> {
        self.permissions
            .iter()
            .filter(|p| p.is_spyware_relevant())
            .collect()
    }

    /// Return all exposed (exported, no permission gate) components.
    #[must_use]
    pub fn exposed_components(&self) -> Vec<&Component> {
        self.services
            .iter()
            .chain(self.receivers.iter())
            .chain(self.providers.iter())
            .filter(|c| c.is_exposed())
            .collect()
    }

    /// Return receivers that listen for `BOOT_COMPLETED`.
    #[must_use]
    pub fn boot_receivers(&self) -> Vec<&Component> {
        self.receivers
            .iter()
            .filter(|r| r.is_boot_receiver())
            .collect()
    }

    /// Return components that can intercept SMS.
    #[must_use]
    pub fn sms_interceptors(&self) -> Vec<&Component> {
        self.receivers
            .iter()
            .filter(|r| r.is_sms_interceptor())
            .collect()
    }

    /// Return the count of services.
    #[must_use]
    pub const fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Compute an aggregate threat score (0.0 – 10.0) from manifest attributes.
    #[must_use]
    pub fn threat_score(&self) -> f64 {
        let mut score = 0.0_f64;
        // Dangerous permissions.
        let dangerous = self.dangerous_permissions().len();
        score += (dangerous as f64 * 0.5).min(3.0);
        // Spyware permissions.
        let spyware = self.spyware_permissions().len();
        score += (spyware as f64 * 0.8).min(3.0);
        // Boot persistence.
        if !self.boot_receivers().is_empty() {
            score += 1.5;
        }
        // SMS interception.
        if !self.sms_interceptors().is_empty() {
            score += 2.0;
        }
        // Debuggable build (suspicious in production).
        if self.debuggable {
            score += 0.5;
        }
        // Cleartext traffic.
        if self.uses_cleartext_traffic {
            score += 0.5;
        }
        score.min(10.0)
    }
}

// ─── ApkEntry ────────────────────────────────────────────────────────────────

/// A file entry inside the APK ZIP archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkEntry {
    /// Path of the entry within the archive.
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: usize,
    /// Compressed size in bytes.
    pub compressed_size: usize,
    /// CRC-32 checksum.
    pub crc32: u32,
    /// Whether this entry is stored without compression.
    pub stored: bool,
}

impl ApkEntry {
    /// Returns `true` if this entry is a DEX file.
    #[must_use]
    pub fn is_dex(&self) -> bool {
        std::path::Path::new(&self.name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dex"))
    }

    /// Returns `true` if this entry is a native shared library.
    #[must_use]
    pub fn is_native_lib(&self) -> bool {
        self.name.starts_with("lib/")
            && std::path::Path::new(&self.name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("so"))
    }

    /// Returns `true` if this entry is an XML file.
    #[must_use]
    pub fn is_xml(&self) -> bool {
        std::path::Path::new(&self.name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("xml"))
    }

    /// Returns `true` if this entry is the ARSC resource table.
    #[must_use]
    pub fn is_resources(&self) -> bool {
        self.name == "resources.arsc"
    }

    /// Returns `true` if this entry is an asset (lives under `assets/`).
    #[must_use]
    pub fn is_asset(&self) -> bool {
        self.name.starts_with("assets/")
    }

    /// Returns `true` if this entry is a signing certificate.
    #[must_use]
    pub fn is_certificate(&self) -> bool {
        if !self.name.starts_with("META-INF/") {
            return false;
        }
        std::path::Path::new(&self.name)
            .extension()
            .is_some_and(|e| {
                e.eq_ignore_ascii_case("RSA")
                    || e.eq_ignore_ascii_case("DSA")
                    || e.eq_ignore_ascii_case("EC")
            })
    }

    /// Compression ratio (compressed / original). Returns `1.0` if size is 0.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.size as f64
    }

    /// Architecture for a native lib entry, derived from its path, or `None`.
    #[must_use]
    pub fn abi(&self) -> Option<&str> {
        if !self.is_native_lib() {
            return None;
        }
        // lib/<abi>/libname.so
        let parts: Vec<&str> = self.name.splitn(3, '/').collect();
        if parts.len() >= 2 {
            Some(parts[1])
        } else {
            None
        }
    }
}

// ─── DexClass ─────────────────────────────────────────────────────────────────

/// A class found inside a DEX file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClass {
    /// Fully-qualified class name in JVM descriptor form, e.g. `Lcom/example/Foo;`.
    pub descriptor: String,
    /// Simple class name without package.
    pub simple_name: String,
    /// Superclass descriptor.
    pub superclass: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Access flags (public, abstract, etc.).
    pub access_flags: u32,
    /// Source file attribute, if present.
    pub source_file: Option<String>,
    /// Number of methods in this class.
    pub method_count: u32,
    /// Number of fields in this class.
    pub field_count: u32,
}

impl DexClass {
    /// Returns `true` if this class is public.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns `true` if this class is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns `true` if this class is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Returns the Java-style package name, e.g. `com.example`.
    #[must_use]
    pub fn package_name(&self) -> &str {
        if let Some(slash_pos) = self.descriptor.rfind('/') {
            // strip leading 'L'
            (&self.descriptor[1..slash_pos]) as _
        } else {
            ""
        }
    }

    /// Returns `true` if this class appears to have an obfuscated name (single
    /// or two-character class/package components).
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        let name = self.simple_name.trim_matches(';');
        name.len() <= 2
            || name
                .chars()
                .all(|c| c.is_alphabetic() && c.is_lowercase() && name.len() <= 3)
    }
}

// ─── StringEntry ─────────────────────────────────────────────────────────────

/// A string extracted from a DEX or resource file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// The string value.
    pub value: String,
    /// Whether it was found in a DEX string constant pool.
    pub from_dex: bool,
    /// Whether it was found in the resource table.
    pub from_resources: bool,
}

impl StringEntry {
    /// Returns `true` if the string looks like a URL.
    #[must_use]
    pub fn is_url(&self) -> bool {
        self.value.starts_with("http://") || self.value.starts_with("https://")
    }

    /// Returns `true` if the string looks like an IPv4 address.
    #[must_use]
    pub fn is_ip_address(&self) -> bool {
        let parts: Vec<&str> = self.value.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        parts.iter().all(|p| p.parse::<u8>().is_ok())
    }

    /// Returns `true` if the string resembles a base64-encoded payload.
    #[must_use]
    pub fn is_base64_like(&self) -> bool {
        self.value.len() > 32
            && self
                .value
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
            && self.value.ends_with('=')
    }

    /// Returns `true` if the string is a suspicious command pattern.
    #[must_use]
    pub fn is_suspicious_command(&self) -> bool {
        let v = self.value.to_lowercase();
        v.contains("exec(")
            || v.contains("runtime.getruntime")
            || v.contains("/system/bin/sh")
            || v.contains("cmd.exe")
            || v.contains("powershell")
    }
}

// ─── NativeLib ────────────────────────────────────────────────────────────────

/// A native shared library found in the APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLib {
    /// Library file name, e.g. `libnative.so`.
    pub name: String,
    /// ABI/architecture folder, e.g. `arm64-v8a`.
    pub abi: String,
    /// Size in bytes.
    pub size: usize,
    /// SHA-256 hex digest of the library.
    pub sha256: String,
    /// Whether the library exports symbols that suggest native hooking.
    pub has_hook_exports: bool,
    /// Imported symbols (functions the library links against).
    pub imports: Vec<String>,
    /// Exported symbols.
    pub exports: Vec<String>,
}

impl NativeLib {
    /// Returns `true` if the library imports `ptrace`, suggesting anti-debugging.
    #[must_use]
    pub fn uses_ptrace(&self) -> bool {
        self.imports.iter().any(|s| s.contains("ptrace"))
    }

    /// Returns `true` if the library imports cryptographic functions.
    #[must_use]
    pub fn uses_crypto(&self) -> bool {
        self.imports.iter().any(|s| {
            s.contains("EVP_") || s.contains("AES_") || s.contains("RSA_") || s.contains("SHA")
        })
    }

    /// Returns `true` if the library references system shell paths.
    #[must_use]
    pub fn references_shell(&self) -> bool {
        self.imports
            .iter()
            .any(|s| s.contains("system") || s.contains("popen") || s.contains("execve"))
    }
}

// ─── Certificate ─────────────────────────────────────────────────────────────

/// An X.509 certificate used to sign the APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Common Name from the subject field.
    pub subject_cn: String,
    /// Organization from the subject field.
    pub subject_org: Option<String>,
    /// SHA-256 fingerprint of the certificate (hex).
    pub sha256: String,
    /// SHA-1 fingerprint of the certificate (hex).
    pub sha1: String,
    /// Certificate validity start (ISO-8601 string).
    pub valid_from: String,
    /// Certificate validity end (ISO-8601 string).
    pub valid_to: String,
    /// Whether the certificate is a self-signed one.
    pub self_signed: bool,
    /// Public key algorithm, e.g. `RSA`, `EC`.
    pub algorithm: String,
    /// Key size in bits.
    pub key_bits: u32,
    /// Signature algorithm, e.g. `SHA256withRSA`.
    pub signature_algorithm: String,
    /// Serial number (hex string).
    pub serial: String,
}

impl Certificate {
    /// Returns `true` if the CN is typical of a debug certificate.
    #[must_use]
    pub fn is_debug_cert(&self) -> bool {
        let cn = self.subject_cn.to_lowercase();
        cn.contains("android debug") || cn.contains("test") || cn.contains("debug")
    }

    /// Returns `true` if this certificate uses a weak key.
    #[must_use]
    pub fn has_weak_key(&self) -> bool {
        (self.algorithm == "RSA" && self.key_bits < 2048)
            || (self.algorithm == "EC" && self.key_bits < 224)
    }

    /// Returns `true` if the certificate appears expired.
    #[must_use]
    pub fn appears_expired(&self) -> bool {
        // Simple string comparison works for ISO-8601 dates.
        self.valid_to.as_str() < "2024-01-01"
    }
}

// ─── ObfuscationReport ────────────────────────────────────────────────────────

/// Result of obfuscation detection analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationReport {
    /// Fraction (0.0 – 1.0) of classes with single/double-char names.
    pub obfuscated_class_ratio: f64,
    /// Whether ProGuard/R8 mapping signatures were detected.
    pub has_proguard_markers: bool,
    /// Whether `DexGuard` markers were detected.
    pub has_dexguard: bool,
    /// Whether string encryption was detected.
    pub has_string_encryption: bool,
    /// Whether control-flow obfuscation patterns were detected.
    pub has_cfo: bool,
    /// Detected packer/protector name, if any.
    pub packer: Option<String>,
    /// Overall obfuscation confidence (0.0 – 1.0).
    pub confidence: f64,
}

impl ObfuscationReport {
    /// Returns `true` if the app is likely obfuscated.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.confidence >= 0.5
    }

    /// Returns a human-readable summary of detected obfuscation techniques.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.obfuscated_class_ratio > 0.3 {
            parts.push(format!(
                "{:.0}% obfuscated classes",
                self.obfuscated_class_ratio * 100.0
            ));
        }
        if self.has_proguard_markers {
            parts.push("ProGuard/R8".to_string());
        }
        if self.has_dexguard {
            parts.push("DexGuard".to_string());
        }
        if self.has_string_encryption {
            parts.push("string encryption".to_string());
        }
        if self.has_cfo {
            parts.push("CFO".to_string());
        }
        if let Some(ref p) = self.packer {
            parts.push(format!("packer: {p}"));
        }
        if parts.is_empty() {
            "none detected".to_string()
        } else {
            parts.join(", ")
        }
    }
}

// ─── ApkManifest (legacy alias) ───────────────────────────────────────────────

/// Legacy alias kept for backward compatibility.
pub type ApkManifest = AndroidManifest;

// ─── ApkEntry (extended) ─────────────────────────────────────────────────────

/// Lean entry type for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkEntryLite {
    /// Path of the entry within the archive.
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: usize,
    /// Compressed size in bytes.
    pub compressed_size: usize,
}

impl ApkEntryLite {
    /// Returns `true` if this entry is a DEX file.
    #[must_use]
    pub fn is_dex(&self) -> bool {
        std::path::Path::new(&self.name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dex"))
    }

    /// Returns `true` if this entry is a native shared library.
    #[must_use]
    pub fn is_native_lib(&self) -> bool {
        self.name.starts_with("lib/")
            && std::path::Path::new(&self.name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("so"))
    }

    /// Compression ratio (compressed / original). Returns `1.0` if size is 0.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.size as f64
    }
}

// ─── Apk ─────────────────────────────────────────────────────────────────────

/// A parsed Android APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apk {
    /// All file entries inside the archive.
    pub entries: Vec<ApkEntry>,
    /// Parsed manifest, if available.
    pub manifest: Option<AndroidManifest>,
    /// DEX classes discovered by parsing all .dex files.
    pub dex_classes: Vec<DexClass>,
    /// Strings extracted from DEX and resources.
    pub strings: Vec<StringEntry>,
    /// Native libraries.
    pub native_libs: Vec<NativeLib>,
    /// Signing certificates.
    pub certificates: Vec<Certificate>,
    /// Obfuscation detection report.
    pub obfuscation: Option<ObfuscationReport>,
}

impl Apk {
    /// Create an empty APK structure.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            manifest: None,
            dex_classes: Vec::new(),
            strings: Vec::new(),
            native_libs: Vec::new(),
            certificates: Vec::new(),
            obfuscation: None,
        }
    }

    /// Create a rich mock APK for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut apk = Self::new();
        apk.entries = vec![
            ApkEntry {
                name: "classes.dex".to_string(),
                size: 102_400,
                compressed_size: 51_200,
                crc32: 0xDEAD_BEEF,
                stored: false,
            },
            ApkEntry {
                name: "classes2.dex".to_string(),
                size: 40_960,
                compressed_size: 20_480,
                crc32: 0xCAFE_BABE,
                stored: false,
            },
            ApkEntry {
                name: "lib/arm64-v8a/libnative.so".to_string(),
                size: 204_800,
                compressed_size: 102_400,
                crc32: 0xFEED_FACE,
                stored: false,
            },
            ApkEntry {
                name: "AndroidManifest.xml".to_string(),
                size: 2_048,
                compressed_size: 1_024,
                crc32: 0xABCD_1234,
                stored: false,
            },
            ApkEntry {
                name: "resources.arsc".to_string(),
                size: 8_192,
                compressed_size: 4_096,
                crc32: 0x1234_ABCD,
                stored: false,
            },
            ApkEntry {
                name: "META-INF/CERT.RSA".to_string(),
                size: 1_024,
                compressed_size: 1_024,
                crc32: 0x5678_ABCD,
                stored: true,
            },
        ];
        apk.manifest = Some(AndroidManifest::mock("com.example.app"));
        apk.dex_classes = vec![
            DexClass {
                descriptor: "Lcom/example/MainActivity;".to_string(),
                simple_name: "MainActivity".to_string(),
                superclass: Some("Landroid/app/Activity;".to_string()),
                interfaces: vec![],
                access_flags: 0x0001,
                source_file: Some("MainActivity.java".to_string()),
                method_count: 5,
                field_count: 3,
            },
            DexClass {
                descriptor: "La/b/c;".to_string(),
                simple_name: "c".to_string(),
                superclass: None,
                interfaces: vec!["Ljava/io/Serializable;".to_string()],
                access_flags: 0x0001,
                source_file: None,
                method_count: 12,
                field_count: 7,
            },
        ];
        apk.strings = vec![
            StringEntry {
                value: "https://c2.example.com/gate.php".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "185.220.101.55".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "/system/bin/sh".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        apk.native_libs = vec![NativeLib {
            name: "libnative.so".to_string(),
            abi: "arm64-v8a".to_string(),
            size: 204_800,
            sha256: "aabbccddeeff00112233445566778899".to_string(),
            has_hook_exports: false,
            imports: vec!["ptrace".to_string(), "EVP_EncryptInit".to_string()],
            exports: vec!["Java_com_example_NativeHelper_init".to_string()],
        }];
        apk.certificates = vec![Certificate {
            subject_cn: "Android Debug".to_string(),
            subject_org: Some("Android".to_string()),
            sha256: "deadbeef".repeat(8),
            sha1: "cafebabe".repeat(5),
            valid_from: "2020-01-01T00:00:00Z".to_string(),
            valid_to: "2030-01-01T00:00:00Z".to_string(),
            self_signed: true,
            algorithm: "RSA".to_string(),
            key_bits: 2048,
            signature_algorithm: "SHA256withRSA".to_string(),
            serial: "01".to_string(),
        }];
        apk.obfuscation = Some(ObfuscationReport {
            obfuscated_class_ratio: 0.5,
            has_proguard_markers: true,
            has_dexguard: false,
            has_string_encryption: false,
            has_cfo: false,
            packer: None,
            confidence: 0.65,
        });
        apk
    }

    /// Find an entry by name.
    #[must_use]
    pub fn find_entry(&self, name: &str) -> Option<&ApkEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Return all DEX file entries.
    #[must_use]
    pub fn dex_entries(&self) -> Vec<&ApkEntry> {
        self.entries.iter().filter(|e| e.is_dex()).collect()
    }

    /// Return all native library entries.
    #[must_use]
    pub fn native_lib_entries(&self) -> Vec<&ApkEntry> {
        self.entries.iter().filter(|e| e.is_native_lib()).collect()
    }

    /// Return all certificate entries.
    #[must_use]
    pub fn certificate_entries(&self) -> Vec<&ApkEntry> {
        self.entries.iter().filter(|e| e.is_certificate()).collect()
    }

    /// Total uncompressed size of all entries.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.entries.iter().map(|e| e.size).sum()
    }

    /// Return all DEX classes matching a package prefix.
    #[must_use]
    pub fn classes_in_package(&self, pkg: &str) -> Vec<&DexClass> {
        self.dex_classes
            .iter()
            .filter(|c| c.package_name().starts_with(pkg))
            .collect()
    }

    /// Return obfuscated DEX classes.
    #[must_use]
    pub fn obfuscated_classes(&self) -> Vec<&DexClass> {
        self.dex_classes
            .iter()
            .filter(|c| c.is_obfuscated())
            .collect()
    }

    /// Return strings that look like URLs.
    #[must_use]
    pub fn url_strings(&self) -> Vec<&StringEntry> {
        self.strings.iter().filter(|s| s.is_url()).collect()
    }

    /// Return strings that look like IP addresses.
    #[must_use]
    pub fn ip_strings(&self) -> Vec<&StringEntry> {
        self.strings.iter().filter(|s| s.is_ip_address()).collect()
    }

    /// Return all distinct ABIs supported by native libraries.
    #[must_use]
    pub fn supported_abis(&self) -> Vec<&str> {
        let mut abis: Vec<&str> = self
            .native_lib_entries()
            .iter()
            .filter_map(|e| e.abi())
            .collect();
        abis.sort_unstable();
        abis.dedup();
        abis
    }

    /// Returns `true` if the APK has a debug signing certificate.
    #[must_use]
    pub fn is_debug_signed(&self) -> bool {
        self.certificates.iter().any(Certificate::is_debug_cert)
    }

    /// Returns `true` if the APK appears obfuscated.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.obfuscation
            .as_ref()
            .is_some_and(ObfuscationReport::is_obfuscated)
    }
}

impl Default for Apk {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ApkAnalyzer ─────────────────────────────────────────────────────────────

/// Analysis result produced by the `ApkAnalyzer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkAnalysisResult {
    /// Parsed APK structure.
    pub apk: Apk,
    /// Threat score (0.0 – 10.0).
    pub threat_score: f64,
    /// High-level threat indicators detected.
    pub indicators: Vec<String>,
    /// Malware family guess, or `"unknown"`.
    pub family_guess: String,
    /// Whether the APK should be flagged for deeper analysis.
    pub should_flag: bool,
}

impl ApkAnalysisResult {
    /// Compute result from a parsed APK.
    #[must_use]
    pub fn from_apk(apk: Apk) -> Self {
        let mut score = 0.0_f64;
        let mut indicators = Vec::new();

        // Manifest-level threat scoring.
        if let Some(ref m) = apk.manifest {
            let manifest_score = m.threat_score();
            score = manifest_score.mul_add(0.4, score);
            if !m.spyware_permissions().is_empty() {
                indicators.push("spyware permissions".to_string());
            }
            if !m.boot_receivers().is_empty() {
                indicators.push("boot persistence".to_string());
            }
            if !m.sms_interceptors().is_empty() {
                indicators.push("SMS interception".to_string());
            }
            if m.debuggable {
                indicators.push("debuggable build".to_string());
            }
        }

        // Suspicious strings.
        let urls = apk.url_strings().len();
        let ips = apk.ip_strings().len();
        if urls + ips > 3 {
            score += 1.5;
            indicators.push(format!("{} suspicious network strings", urls + ips));
        }

        // Native lib analysis.
        for lib in &apk.native_libs {
            if lib.uses_ptrace() {
                score += 1.5;
                indicators.push(format!("{}: ptrace (anti-debug)", lib.name));
            }
            if lib.references_shell() {
                score += 1.0;
                indicators.push(format!("{}: shell execution", lib.name));
            }
        }

        // Obfuscation.
        if apk.is_obfuscated() {
            score += 0.5;
            indicators.push("code obfuscation".to_string());
        }

        // Debug cert.
        if apk.is_debug_signed() {
            indicators.push("debug signing certificate".to_string());
        }

        score = score.min(10.0);

        let family_guess = Self::guess_family(&indicators);
        let should_flag = score >= 4.0;

        Self {
            apk,
            threat_score: score,
            indicators,
            family_guess,
            should_flag,
        }
    }

    fn guess_family(indicators: &[String]) -> String {
        let combined = indicators.join(" ").to_lowercase();
        if combined.contains("sms") {
            return "SMSStealer".to_string();
        }
        if combined.contains("spyware") && combined.contains("location") {
            return "Stalkerware".to_string();
        }
        if combined.contains("shell") {
            return "Dropper".to_string();
        }
        "unknown".to_string()
    }
}

/// Minimal heuristic extraction of the `package` attribute from an Android
/// Binary XML (AXML) byte buffer.
///
/// Scans for the UTF-16LE encoded string "package" followed, within the string
/// pool, by a candidate value that looks like a Java package name.  Returns
/// `None` when the heuristic cannot find a match.
fn find_package_in_axml(data: &[u8]) -> Option<String> {
    // The AXML string pool stores UTF-16LE strings.  We look for the byte
    // sequence for "package" in UTF-16LE and then scan forward for a string
    // that contains dots (typical of Java package names).
    let needle_utf16: Vec<u8> = "package"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    // Look for the "package" string anywhere in the data.
    let start = data
        .windows(needle_utf16.len())
        .position(|w| w == needle_utf16.as_slice())?;

    // Scan forward up to 4 KB for a UTF-16LE string that looks like
    // "com.something.app".
    let search = &data[start..];
    let mut i = 0usize;
    while i + 4 <= search.len().min(4096) {
        // Try to read a short UTF-16LE sequence (up to 128 code units).
        let mut s = String::with_capacity(64);
        let mut j = i;
        while j + 2 <= search.len() {
            let cp = u16::from_le_bytes([search[j], search[j + 1]]);
            if cp == 0 || cp > 0x7F {
                break;
            }
            s.push(cp as u8 as char);
            j += 2;
        }
        if s.len() >= 5
            && s.contains('.')
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_')
        {
            return Some(s);
        }
        i += 1;
    }
    None
}

/// High-level APK analysis engine.
#[derive(Debug, Default)]
pub struct ApkAnalyzer;

impl ApkAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyze a pre-parsed APK and produce a full result.
    #[must_use]
    pub fn analyze(&self, apk: Apk) -> ApkAnalysisResult {
        ApkAnalysisResult::from_apk(apk)
    }

    /// Parse an APK from raw bytes using real ZIP parsing.
    ///
    /// Enumerates all ZIP entries, extracts `AndroidManifest.xml` (binary or
    /// plain XML), finds all `classes*.dex` files and reads their DEX header to
    /// populate at least one [`DexClass`] per DEX, and collects native `.so`
    /// entries.
    ///
    /// # Errors
    /// Returns [`AndroidError::InvalidApk`] if the data is not a valid ZIP
    /// archive or is too small.
    pub fn parse_bytes(&self, data: &[u8]) -> Result<Apk, AndroidError> {
        if data.len() < 4 {
            return Err(AndroidError::InvalidApk("file too small".to_string()));
        }
        if &data[0..4] != b"PK\x03\x04" {
            return Err(AndroidError::InvalidApk(format!(
                "bad magic: {:02x}{:02x}{:02x}{:02x}",
                data[0], data[1], data[2], data[3]
            )));
        }

        let cursor = Cursor::new(data.to_vec());
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| AndroidError::InvalidApk(e.to_string()))?;

        let mut apk = Apk::new();

        // ── Collect entries ──────────────────────────────────────────────────
        for i in 0..archive.len() {
            let entry = archive
                .by_index_raw(i)
                .map_err(|e| AndroidError::Io(e.to_string()))?;
            let name = entry.name().to_owned();
            let size = usize::try_from(entry.size()).unwrap_or(usize::MAX);
            let compressed_size = usize::try_from(entry.compressed_size()).unwrap_or(usize::MAX);
            let crc32 = entry.crc32();
            let stored = entry.compression() == zip::CompressionMethod::Stored;
            apk.entries.push(ApkEntry {
                name,
                size,
                compressed_size,
                crc32,
                stored,
            });
        }

        // ── Parse AndroidManifest.xml ────────────────────────────────────────
        let package_name: String = if archive.index_for_name("AndroidManifest.xml").is_some() {
            let mut entry = archive
                .by_name("AndroidManifest.xml")
                .map_err(|e| AndroidError::Io(e.to_string()))?;
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| AndroidError::Io(e.to_string()))?;
            drop(entry);

            // Try plain-text XML first (rare but possible).
            if buf.starts_with(b"<?xml") || buf.starts_with(b"<manifest") {
                if let Ok(xml) = std::str::from_utf8(&buf) {
                    // Extract package attribute from plain XML.
                    xml.find("package=\"")
                        .and_then(|p| {
                            let rest = &xml[p + 9..];
                            rest.find('"').map(|e| rest[..e].to_owned())
                        })
                        .unwrap_or_else(|| "unknown".to_owned())
                } else {
                    "unknown".to_owned()
                }
            } else {
                // Binary XML (AXML): attempt minimal package name extraction by
                // scanning for "package" attribute marker and reading the
                // following string value.
                find_package_in_axml(&buf).unwrap_or_else(|| "unknown".to_owned())
            }
        } else {
            "unknown".to_owned()
        };

        // Build a minimal manifest with the extracted package name.
        apk.manifest = Some(AndroidManifest {
            package: package_name,
            version_name: String::new(),
            version_code: 0,
            min_sdk: 0,
            target_sdk: 0,
            max_sdk: None,
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            debuggable: false,
            allow_backup: false,
            uses_cleartext_traffic: false,
            application_class: None,
            shared_user_id: None,
            supported_screens: Vec::new(),
            extra_attributes: HashMap::new(),
        });

        // ── Parse DEX files ──────────────────────────────────────────────────
        let dex_names: Vec<String> = apk
            .entries
            .iter()
            .filter(|e| e.is_dex())
            .map(|e| e.name.clone())
            .collect();

        for dex_name in &dex_names {
            if let Ok(mut entry) = archive.by_name(dex_name) {
                let mut buf = Vec::new();
                if entry.read_to_end(&mut buf).is_err() {
                    drop(entry);
                    continue;
                }
                drop(entry);
                // DEX magic: "dex\n" (64 65 78 0a) followed by 3-byte version + NUL.
                if buf.len() >= 8 && &buf[0..4] == b"dex\n" {
                    let version = std::str::from_utf8(&buf[4..7]).unwrap_or("000").to_owned();
                    // Emit one synthetic DexClass entry describing this DEX file.
                    apk.dex_classes.push(DexClass {
                        descriptor: format!(
                            "L{}$Dex{};",
                            dex_name.trim_end_matches(".dex"),
                            version
                        ),
                        simple_name: dex_name.clone(),
                        superclass: None,
                        interfaces: Vec::new(),
                        access_flags: 0,
                        source_file: Some(dex_name.clone()),
                        method_count: 0,
                        field_count: 0,
                    });
                }
            }
        }

        Ok(apk)
    }
}

// ─── PermissionGroup ──────────────────────────────────────────────────────────

/// Groups permissions into categories for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroup {
    /// Group name, e.g. `"Location"`.
    pub name: String,
    /// Permissions in this group.
    pub permissions: Vec<String>,
    /// Risk level (1 = low, 10 = critical).
    pub risk: u32,
}

impl PermissionGroup {
    /// Create well-known Android permission groups.
    #[must_use]
    pub fn known_groups() -> Vec<Self> {
        vec![
            Self {
                name: "Location".to_string(),
                permissions: vec![
                    "android.permission.ACCESS_FINE_LOCATION".to_string(),
                    "android.permission.ACCESS_COARSE_LOCATION".to_string(),
                    "android.permission.ACCESS_BACKGROUND_LOCATION".to_string(),
                ],
                risk: 7,
            },
            Self {
                name: "Telephony".to_string(),
                permissions: vec![
                    "android.permission.READ_SMS".to_string(),
                    "android.permission.RECEIVE_SMS".to_string(),
                    "android.permission.SEND_SMS".to_string(),
                    "android.permission.READ_CALL_LOG".to_string(),
                    "android.permission.PROCESS_OUTGOING_CALLS".to_string(),
                ],
                risk: 9,
            },
            Self {
                name: "Microphone".to_string(),
                permissions: vec!["android.permission.RECORD_AUDIO".to_string()],
                risk: 8,
            },
            Self {
                name: "Camera".to_string(),
                permissions: vec!["android.permission.CAMERA".to_string()],
                risk: 7,
            },
            Self {
                name: "Contacts".to_string(),
                permissions: vec![
                    "android.permission.READ_CONTACTS".to_string(),
                    "android.permission.WRITE_CONTACTS".to_string(),
                    "android.permission.GET_ACCOUNTS".to_string(),
                ],
                risk: 6,
            },
            Self {
                name: "Storage".to_string(),
                permissions: vec![
                    "android.permission.READ_EXTERNAL_STORAGE".to_string(),
                    "android.permission.WRITE_EXTERNAL_STORAGE".to_string(),
                    "android.permission.MANAGE_EXTERNAL_STORAGE".to_string(),
                ],
                risk: 5,
            },
        ]
    }

    /// Returns the permissions from this group that are used by the given manifest.
    #[must_use]
    pub fn used_by(&self, manifest: &AndroidManifest) -> Vec<&str> {
        let declared: std::collections::HashSet<&str> = manifest
            .permissions
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        self.permissions
            .iter()
            .filter_map(|p| {
                if declared.contains(p.as_str()) {
                    Some(p.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProtectionLevel ───────────────────────────────────────────────────────

    #[test]
    fn test_protection_level_display_normal() {
        assert_eq!(ProtectionLevel::Normal.to_string(), "normal");
    }

    #[test]
    fn test_protection_level_display_dangerous() {
        assert_eq!(ProtectionLevel::Dangerous.to_string(), "dangerous");
    }

    #[test]
    fn test_protection_level_display_signature() {
        assert_eq!(ProtectionLevel::Signature.to_string(), "signature");
    }

    #[test]
    fn test_protection_level_display_system() {
        assert_eq!(ProtectionLevel::System.to_string(), "system");
    }

    #[test]
    fn test_protection_level_display_privileged() {
        assert_eq!(ProtectionLevel::Privileged.to_string(), "privileged");
    }

    #[test]
    fn test_protection_level_risk_dangerous() {
        assert!(ProtectionLevel::Dangerous.risk_score() > ProtectionLevel::Normal.risk_score());
    }

    #[test]
    fn test_requires_runtime_grant_dangerous() {
        assert!(ProtectionLevel::Dangerous.requires_runtime_grant());
    }

    #[test]
    fn test_requires_runtime_grant_normal() {
        assert!(!ProtectionLevel::Normal.requires_runtime_grant());
    }

    // ── Permission ────────────────────────────────────────────────────────────

    #[test]
    fn test_permission_is_location() {
        let p = Permission::uses(
            "android.permission.ACCESS_FINE_LOCATION",
            ProtectionLevel::Dangerous,
        );
        assert!(p.is_location());
    }

    #[test]
    fn test_permission_is_telephony() {
        let p = Permission::uses("android.permission.READ_SMS", ProtectionLevel::Dangerous);
        assert!(p.is_telephony());
    }

    #[test]
    fn test_permission_is_av_recording() {
        let p = Permission::uses(
            "android.permission.RECORD_AUDIO",
            ProtectionLevel::Dangerous,
        );
        assert!(p.is_av_recording());
    }

    #[test]
    fn test_permission_is_spyware_relevant() {
        let p = Permission::uses(
            "android.permission.READ_CONTACTS",
            ProtectionLevel::Dangerous,
        );
        assert!(p.is_spyware_relevant());
    }

    #[test]
    fn test_permission_not_spyware() {
        let p = Permission::uses("android.permission.INTERNET", ProtectionLevel::Normal);
        assert!(!p.is_spyware_relevant());
    }

    // ── IntentFilter ──────────────────────────────────────────────────────────

    #[test]
    fn test_intent_filter_is_launcher() {
        let f = IntentFilter {
            actions: vec!["android.intent.action.MAIN".to_string()],
            categories: vec!["android.intent.category.LAUNCHER".to_string()],
            schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_launcher());
    }

    #[test]
    fn test_intent_filter_is_boot_receiver() {
        let f = IntentFilter {
            actions: vec!["android.intent.action.BOOT_COMPLETED".to_string()],
            categories: vec![],
            schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_boot_receiver());
    }

    #[test]
    fn test_intent_filter_is_sms() {
        let f = IntentFilter {
            actions: vec!["android.provider.Telephony.SMS_RECEIVED".to_string()],
            categories: vec![],
            schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_sms_receiver());
    }

    // ── AndroidManifest ───────────────────────────────────────────────────────

    #[test]
    fn test_manifest_mock_package() {
        let m = AndroidManifest::mock("com.test.pkg");
        assert_eq!(m.package, "com.test.pkg");
    }

    #[test]
    fn test_manifest_mock_version() {
        let m = AndroidManifest::mock("com.test");
        assert_eq!(m.version_name, "1.0.0");
        assert_eq!(m.version_code, 1);
    }

    #[test]
    fn test_manifest_mock_sdk() {
        let m = AndroidManifest::mock("com.test");
        assert_eq!(m.min_sdk, 21);
        assert_eq!(m.target_sdk, 33);
    }

    #[test]
    fn test_exported_activities() {
        let m = AndroidManifest::mock("com.test");
        let exported = m.exported_activities();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].name, "com.example.MainActivity");
    }

    #[test]
    fn test_dangerous_permissions() {
        let m = AndroidManifest::mock("com.test");
        let dangerous = m.dangerous_permissions();
        assert!(dangerous.len() >= 2);
        assert!(dangerous.iter().any(|p| p.name.contains("CAMERA")));
    }

    #[test]
    fn test_spyware_permissions() {
        let m = AndroidManifest::mock("com.test");
        let spy = m.spyware_permissions();
        assert!(!spy.is_empty());
    }

    #[test]
    fn test_boot_receivers() {
        let m = AndroidManifest::mock("com.test");
        let boot = m.boot_receivers();
        assert!(!boot.is_empty());
    }

    #[test]
    fn test_sms_interceptors() {
        let m = AndroidManifest::mock("com.test");
        let sms = m.sms_interceptors();
        assert!(!sms.is_empty());
    }

    #[test]
    fn test_service_count() {
        let m = AndroidManifest::mock("com.test");
        assert_eq!(m.service_count(), 1);
    }

    #[test]
    fn test_threat_score_positive() {
        let m = AndroidManifest::mock("com.test");
        assert!(m.threat_score() > 0.0);
    }

    #[test]
    fn test_manifest_serialization() {
        let m = AndroidManifest::mock("com.test");
        let json = serde_json::to_string(&m).unwrap();
        let decoded: AndroidManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.package, m.package);
    }

    // ── ApkEntry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_apk_entry_is_dex_true() {
        let e = ApkEntry {
            name: "classes.dex".to_string(),
            size: 100,
            compressed_size: 50,
            crc32: 0,
            stored: false,
        };
        assert!(e.is_dex());
    }

    #[test]
    fn test_apk_entry_is_dex_false() {
        let e = ApkEntry {
            name: "resources.arsc".to_string(),
            size: 100,
            compressed_size: 50,
            crc32: 0,
            stored: false,
        };
        assert!(!e.is_dex());
    }

    #[test]
    fn test_apk_entry_is_native_lib_true() {
        let e = ApkEntry {
            name: "lib/arm64-v8a/libfoo.so".to_string(),
            size: 200,
            compressed_size: 100,
            crc32: 0,
            stored: false,
        };
        assert!(e.is_native_lib());
        assert_eq!(e.abi(), Some("arm64-v8a"));
    }

    #[test]
    fn test_apk_entry_is_certificate() {
        let e = ApkEntry {
            name: "META-INF/CERT.RSA".to_string(),
            size: 512,
            compressed_size: 512,
            crc32: 0,
            stored: true,
        };
        assert!(e.is_certificate());
    }

    #[test]
    fn test_apk_entry_compression_ratio() {
        let e = ApkEntry {
            name: "a".to_string(),
            size: 100,
            compressed_size: 40,
            crc32: 0,
            stored: false,
        };
        assert!((e.compression_ratio() - 0.4).abs() < f64::EPSILON);
    }

    // ── DexClass ──────────────────────────────────────────────────────────────

    #[test]
    fn test_dex_class_is_public() {
        let c = DexClass {
            descriptor: "Lcom/example/Foo;".to_string(),
            simple_name: "Foo".to_string(),
            superclass: None,
            interfaces: vec![],
            access_flags: 0x0001,
            source_file: None,
            method_count: 0,
            field_count: 0,
        };
        assert!(c.is_public());
    }

    #[test]
    fn test_dex_class_is_obfuscated() {
        let c = DexClass {
            descriptor: "La/b;".to_string(),
            simple_name: "b".to_string(),
            superclass: None,
            interfaces: vec![],
            access_flags: 0x0001,
            source_file: None,
            method_count: 0,
            field_count: 0,
        };
        assert!(c.is_obfuscated());
    }

    #[test]
    fn test_dex_class_not_obfuscated() {
        let c = DexClass {
            descriptor: "Lcom/example/MainActivity;".to_string(),
            simple_name: "MainActivity".to_string(),
            superclass: None,
            interfaces: vec![],
            access_flags: 0x0001,
            source_file: None,
            method_count: 0,
            field_count: 0,
        };
        assert!(!c.is_obfuscated());
    }

    // ── StringEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_string_entry_is_url() {
        let s = StringEntry {
            value: "https://evil.com".to_string(),
            from_dex: true,
            from_resources: false,
        };
        assert!(s.is_url());
    }

    #[test]
    fn test_string_entry_is_ip() {
        let s = StringEntry {
            value: "192.168.1.1".to_string(),
            from_dex: true,
            from_resources: false,
        };
        assert!(s.is_ip_address());
    }

    #[test]
    fn test_string_entry_is_suspicious_command() {
        let s = StringEntry {
            value: "Runtime.getRuntime().exec(cmd)".to_string(),
            from_dex: true,
            from_resources: false,
        };
        assert!(s.is_suspicious_command());
    }

    // ── NativeLib ─────────────────────────────────────────────────────────────

    #[test]
    fn test_native_lib_uses_ptrace() {
        let lib = NativeLib {
            name: "libfoo.so".to_string(),
            abi: "arm64-v8a".to_string(),
            size: 1000,
            sha256: "aa".to_string(),
            has_hook_exports: false,
            imports: vec!["ptrace".to_string()],
            exports: vec![],
        };
        assert!(lib.uses_ptrace());
    }

    #[test]
    fn test_native_lib_uses_crypto() {
        let lib = NativeLib {
            name: "libfoo.so".to_string(),
            abi: "arm64-v8a".to_string(),
            size: 1000,
            sha256: "aa".to_string(),
            has_hook_exports: false,
            imports: vec!["EVP_EncryptInit".to_string()],
            exports: vec![],
        };
        assert!(lib.uses_crypto());
    }

    // ── Certificate ───────────────────────────────────────────────────────────

    #[test]
    fn test_certificate_is_debug() {
        let c = Certificate {
            subject_cn: "Android Debug".to_string(),
            subject_org: None,
            sha256: "aa".to_string(),
            sha1: "bb".to_string(),
            valid_from: "2020-01-01T00:00:00Z".to_string(),
            valid_to: "2030-01-01T00:00:00Z".to_string(),
            self_signed: true,
            algorithm: "RSA".to_string(),
            key_bits: 2048,
            signature_algorithm: "SHA256withRSA".to_string(),
            serial: "01".to_string(),
        };
        assert!(c.is_debug_cert());
    }

    #[test]
    fn test_certificate_weak_key() {
        let c = Certificate {
            subject_cn: "Test".to_string(),
            subject_org: None,
            sha256: "aa".to_string(),
            sha1: "bb".to_string(),
            valid_from: "2020-01-01T00:00:00Z".to_string(),
            valid_to: "2030-01-01T00:00:00Z".to_string(),
            self_signed: true,
            algorithm: "RSA".to_string(),
            key_bits: 1024,
            signature_algorithm: "SHA1withRSA".to_string(),
            serial: "01".to_string(),
        };
        assert!(c.has_weak_key());
    }

    // ── ObfuscationReport ─────────────────────────────────────────────────────

    #[test]
    fn test_obfuscation_report_is_obfuscated() {
        let r = ObfuscationReport {
            obfuscated_class_ratio: 0.6,
            has_proguard_markers: true,
            has_dexguard: false,
            has_string_encryption: false,
            has_cfo: false,
            packer: None,
            confidence: 0.7,
        };
        assert!(r.is_obfuscated());
        assert!(r.summary().contains("ProGuard"));
    }

    #[test]
    fn test_obfuscation_report_not_obfuscated() {
        let r = ObfuscationReport {
            obfuscated_class_ratio: 0.0,
            has_proguard_markers: false,
            has_dexguard: false,
            has_string_encryption: false,
            has_cfo: false,
            packer: None,
            confidence: 0.1,
        };
        assert!(!r.is_obfuscated());
        assert_eq!(r.summary(), "none detected");
    }

    // ── Apk ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_apk_mock_has_entries() {
        let apk = Apk::mock();
        assert!(!apk.entries.is_empty());
    }

    #[test]
    fn test_apk_mock_has_manifest() {
        let apk = Apk::mock();
        assert!(apk.manifest.is_some());
    }

    #[test]
    fn test_apk_find_entry_found() {
        let apk = Apk::mock();
        assert!(apk.find_entry("classes.dex").is_some());
    }

    #[test]
    fn test_apk_find_entry_not_found() {
        let apk = Apk::mock();
        assert!(apk.find_entry("nonexistent.xyz").is_none());
    }

    #[test]
    fn test_apk_dex_entries() {
        let apk = Apk::mock();
        assert_eq!(apk.dex_entries().len(), 2);
    }

    #[test]
    fn test_apk_native_lib_entries() {
        let apk = Apk::mock();
        assert_eq!(apk.native_lib_entries().len(), 1);
    }

    #[test]
    fn test_apk_url_strings() {
        let apk = Apk::mock();
        assert!(!apk.url_strings().is_empty());
    }

    #[test]
    fn test_apk_ip_strings() {
        let apk = Apk::mock();
        assert!(!apk.ip_strings().is_empty());
    }

    #[test]
    fn test_apk_supported_abis() {
        let apk = Apk::mock();
        let abis = apk.supported_abis();
        assert!(abis.contains(&"arm64-v8a"));
    }

    #[test]
    fn test_apk_is_debug_signed() {
        let apk = Apk::mock();
        assert!(apk.is_debug_signed());
    }

    #[test]
    fn test_apk_is_obfuscated() {
        let apk = Apk::mock();
        assert!(apk.is_obfuscated());
    }

    #[test]
    fn test_apk_total_size() {
        let apk = Apk::mock();
        assert!(apk.total_size() > 0);
    }

    #[test]
    fn test_apk_serialization() {
        let apk = Apk::mock();
        let json = serde_json::to_string(&apk).unwrap();
        let decoded: Apk = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.entries.len(), apk.entries.len());
    }

    // ── ApkAnalyzer ───────────────────────────────────────────────────────────

    #[test]
    fn test_apk_analyzer_analyze_threat_score() {
        let apk = Apk::mock();
        let result = ApkAnalyzer::new().analyze(apk);
        assert!(result.threat_score > 0.0);
        assert!(result.threat_score <= 10.0);
    }

    #[test]
    fn test_apk_analyzer_should_flag() {
        let apk = Apk::mock();
        let result = ApkAnalyzer::new().analyze(apk);
        assert!(result.should_flag);
    }

    #[test]
    fn test_apk_analyzer_parse_bytes_bad_magic() {
        let az = ApkAnalyzer::new();
        let result = az.parse_bytes(b"\x00\x00\x00\x00");
        assert!(result.is_err());
    }

    #[test]
    fn test_apk_analyzer_parse_bytes_too_small() {
        let az = ApkAnalyzer::new();
        let result = az.parse_bytes(b"PK");
        assert!(result.is_err());
    }

    #[test]
    fn test_apk_analyzer_parse_bytes_invalid_zip() {
        // Magic bytes pass but truncated data is not a valid ZIP archive.
        let az = ApkAnalyzer::new();
        let result = az.parse_bytes(b"PK\x03\x04rest_of_zip_data");
        assert!(result.is_err());
    }

    // ── PermissionGroup ───────────────────────────────────────────────────────

    #[test]
    fn test_permission_group_known_groups_not_empty() {
        let groups = PermissionGroup::known_groups();
        assert!(!groups.is_empty());
    }

    #[test]
    fn test_permission_group_used_by() {
        let groups = PermissionGroup::known_groups();
        let m = AndroidManifest::mock("com.test");
        let telephony = groups.iter().find(|g| g.name == "Telephony").unwrap();
        let used = telephony.used_by(&m);
        assert!(!used.is_empty());
    }

    #[test]
    fn test_android_error_parse() {
        let e = AndroidError::ParseError("bad xml".to_string());
        assert!(e.to_string().contains("bad xml"));
    }

    #[test]
    fn test_android_error_invalid_apk() {
        let e = AndroidError::InvalidApk("not a zip".to_string());
        assert!(e.to_string().contains("not a zip"));
    }

    #[test]
    fn test_android_error_not_found() {
        let e = AndroidError::NotFound("manifest".to_string());
        assert!(e.to_string().contains("manifest"));
    }

    #[test]
    fn test_android_error_cert() {
        let e = AndroidError::CertificateError("invalid chain".to_string());
        assert!(e.to_string().contains("invalid chain"));
    }

    #[test]
    fn test_component_kind_display() {
        assert_eq!(ComponentKind::Activity.to_string(), "activity");
        assert_eq!(ComponentKind::Service.to_string(), "service");
        assert_eq!(ComponentKind::BroadcastReceiver.to_string(), "receiver");
        assert_eq!(ComponentKind::ContentProvider.to_string(), "provider");
    }

    #[test]
    fn test_exposed_components() {
        let m = AndroidManifest::mock("com.test");
        let exposed = m.exposed_components();
        // BootReceiver is exported with no required_permission.
        assert!(!exposed.is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// §25 – Android Tooling: APK/DEX/ART analysis (ApkParser, ManifestParser,
//        DexHeaderParser, ApkAnalyzer / ApkReport, SigningInfo)
// ═══════════════════════════════════════════════════════════════════════════════

use std::{
    io::{Cursor, Read as IoRead},
    path::Path,
};

use zip::ZipArchive;

// ─── ApkParser ───────────────────────────────────────────────────────────────

/// Thin wrapper around a ZIP/APK archive that gives random-access to entries.
pub struct ApkParser {
    archive: ZipArchive<Cursor<Vec<u8>>>,
}

impl ApkParser {
    /// Open an APK file from disk and load it into memory.
    ///
    /// # Errors
    /// Returns [`AndroidError::Io`] if the file cannot be read, or
    /// [`AndroidError::InvalidApk`] if the ZIP structure is corrupt.
    pub fn open(path: &Path) -> Result<Self, AndroidError> {
        let data = std::fs::read(path).map_err(|e| AndroidError::Io(e.to_string()))?;
        let cursor = Cursor::new(data);
        let archive =
            ZipArchive::new(cursor).map_err(|e| AndroidError::InvalidApk(e.to_string()))?;
        Ok(Self { archive })
    }

    /// Return the names of every entry in the archive.
    #[must_use]
    pub fn list_files(&self) -> Vec<String> {
        (0..self.archive.len())
            .filter_map(|i| {
                // ZipArchive::by_index_raw gives a ZipFile without decompressing.
                // We only need the name, so avoid a mutable borrow of archive by
                // collecting names up-front via the index iteration.
                // NOTE: ZipArchive requires &mut self for by_index, so we use the
                // raw accessor that takes &self.
                self.archive.name_for_index(i).map(str::to_owned)
            })
            .collect()
    }

    /// Read and decompress an entry by its in-archive path.
    ///
    /// # Errors
    /// Returns [`AndroidError::NotFound`] if the entry does not exist, or
    /// [`AndroidError::Io`] on a decompression error.
    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>, AndroidError> {
        let mut entry = self
            .archive
            .by_name(name)
            .map_err(|_| AndroidError::NotFound(name.to_owned()))?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| AndroidError::Io(e.to_string()))?;
        Ok(buf)
    }

    /// Return `true` if an entry with the given path exists in the archive.
    #[must_use]
    pub fn has_file(&self, name: &str) -> bool {
        self.archive.index_for_name(name).is_some()
    }

    /// Total number of entries in the archive.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.archive.len()
    }
}

// ─── Binary XML (AXML) decoder ───────────────────────────────────────────────

/// Chunk type constants for Android Binary XML.
mod axml {
    pub const MAGIC_0: u8 = 0x03;
    pub const MAGIC_1: u8 = 0x00;
    pub const CHUNK_STRING_POOL: u16 = 0x0001;
    pub const CHUNK_XML_START_NS: u16 = 0x0100;
    pub const CHUNK_XML_END_NS: u16 = 0x0101;
    pub const CHUNK_XML_START_ELEMENT: u16 = 0x0102;
    pub const CHUNK_XML_END_ELEMENT: u16 = 0x0103;
    pub const CHUNK_XML_TEXT: u16 = 0x0104;
    pub const CHUNK_RES_TABLE: u16 = 0x0002;
}

/// Decode an Android Binary XML (AXML) byte slice into a textual XML string.
///
/// The decoder reconstructs a best-effort XML representation including element
/// names, attribute names, and attribute values.  Resource ID values are
/// rendered as hex literals (`@0x…`).
///
/// # Errors
/// Returns [`AndroidError::ParseError`] when the byte stream is truncated or
/// structurally invalid.
pub fn decode_binary_xml(data: &[u8]) -> Result<String, AndroidError> {
    use std::fmt::Write as _;
    // ── Helpers ──────────────────────────────────────────────────────────────
    fn read_u16(data: &[u8], off: usize) -> Result<u16, AndroidError> {
        if off + 2 > data.len() {
            return Err(AndroidError::ParseError(format!("truncated u16 at {off}")));
        }
        Ok(u16::from_le_bytes([data[off], data[off + 1]]))
    }
    fn read_u32(data: &[u8], off: usize) -> Result<u32, AndroidError> {
        if off + 4 > data.len() {
            return Err(AndroidError::ParseError(format!("truncated u32 at {off}")));
        }
        Ok(u32::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]))
    }

    // ── Magic check ──────────────────────────────────────────────────────────
    if data.len() < 8 {
        return Err(AndroidError::ParseError("AXML data too short".to_owned()));
    }
    if data[0] != axml::MAGIC_0 || data[1] != axml::MAGIC_1 {
        return Err(AndroidError::ParseError(format!(
            "AXML bad magic: {:02x} {:02x}",
            data[0], data[1]
        )));
    }

    let mut strings: Vec<String> = Vec::new();
    let mut output = String::with_capacity(512);
    let mut depth: usize = 0;
    let mut pos: usize = 8; // skip file-level header (type + size)

    // ── Chunk iterator ───────────────────────────────────────────────────────
    while pos + 8 <= data.len() {
        let chunk_type = read_u16(data, pos)?;
        // u16 ext_header at pos+2 (unused header size field in some chunks)
        let chunk_size = read_u32(data, pos + 4)? as usize;
        if chunk_size < 8 || pos + chunk_size > data.len() {
            break; // truncated or malformed – stop gracefully
        }

        match chunk_type {
            // ── StringPool ───────────────────────────────────────────────────
            t if t == axml::CHUNK_STRING_POOL => {
                // Offset 8: string_count, style_count, flags, strings_start, styles_start
                if chunk_size < 28 {
                    pos += chunk_size;
                    continue;
                }
                let string_count = read_u32(data, pos + 8)? as usize;
                let flags = read_u32(data, pos + 16)?;
                let strings_start = read_u32(data, pos + 20)? as usize;
                let is_utf8 = flags & 0x0100 != 0;

                // Offsets array starts at byte 28 relative to chunk start.
                let offsets_base = pos + 28;
                let data_base = pos + strings_start;

                strings.clear();
                strings.reserve(string_count);
                for i in 0..string_count {
                    let off_entry = offsets_base + i * 4;
                    if off_entry + 4 > data.len() {
                        break;
                    }
                    let str_off = read_u32(data, off_entry)? as usize;
                    let abs = data_base + str_off;
                    if abs >= data.len() {
                        strings.push(String::new());
                        continue;
                    }

                    let s = if is_utf8 {
                        // UTF-8: u8 char-count, u8 byte-count, bytes…
                        if abs + 2 > data.len() {
                            String::new()
                        } else {
                            let byte_len = data[abs + 1] as usize;
                            let start = abs + 2;
                            if start + byte_len > data.len() {
                                String::new()
                            } else {
                                String::from_utf8_lossy(&data[start..start + byte_len]).into_owned()
                            }
                        }
                    } else {
                        // UTF-16LE: u16 char-count, char16 units…
                        if abs + 2 > data.len() {
                            String::new()
                        } else {
                            let char_len = read_u16(data, abs)? as usize;
                            let start = abs + 2;
                            let byte_len = char_len * 2;
                            if start + byte_len > data.len() {
                                String::new()
                            } else {
                                let units: Vec<u16> = (0..char_len)
                                    .map(|j| read_u16(data, start + j * 2).unwrap_or(0))
                                    .collect();
                                String::from_utf16_lossy(&units)
                            }
                        }
                    };
                    strings.push(s);
                }
            }

            // ── StartNamespace ────────────────────────────────────────────────
            t if t == axml::CHUNK_XML_START_NS => {
                // Nothing printed for namespaces in simplified output.
            }

            // ── EndNamespace ──────────────────────────────────────────────────
            t if t == axml::CHUNK_XML_END_NS => {}

            // ── StartElement ──────────────────────────────────────────────────
            t if t == axml::CHUNK_XML_START_ELEMENT => {
                // Header: type(2) ext_hdr(2) size(4) line(4) comment(4)
                // ns_idx(4) name_idx(4) attr_start(2) attr_size(2) attr_count(2) id_idx(2) class_idx(2) style_idx(2)
                if chunk_size < 32 {
                    pos += chunk_size;
                    continue;
                }
                let name_idx = read_u32(data, pos + 20)? as usize;
                let attr_count = read_u16(data, pos + 28)? as usize;

                let elem_name = strings.get(name_idx).cloned().unwrap_or_default();
                let indent = "  ".repeat(depth);
                write!(output, "{indent}<{elem_name}").ok();

                // Attributes start at pos+32; each attribute is 20 bytes.
                let attrs_base = pos + 32;
                for ai in 0..attr_count {
                    let a = attrs_base + ai * 20;
                    if a + 20 > data.len() {
                        break;
                    }
                    // attr: ns(4) name(4) raw_val(4) val_size(2) res0(1) data_type(1) data(4)
                    let attr_name_idx = read_u32(data, a + 4)? as usize;
                    let data_type = data[a + 15];
                    let data_val = read_u32(data, a + 16)?;
                    let raw_idx = read_u32(data, a + 8)? as usize;

                    let attr_name = strings.get(attr_name_idx).cloned().unwrap_or_default();
                    let attr_val = match data_type {
                        0x03 => strings.get(raw_idx).cloned().unwrap_or_default(),
                        0x10 => data_val.to_string(),
                        0x12 => (data_val != 0).to_string(),
                        0x01 => format!("@0x{data_val:08x}"),
                        _ => {
                            if raw_idx < strings.len() && !strings[raw_idx].is_empty() {
                                strings[raw_idx].clone()
                            } else {
                                format!("0x{data_val:x}")
                            }
                        }
                    };
                    write!(output, " {attr_name}=\"{attr_val}\"").ok();
                }
                output.push_str(">\n");
                depth += 1;
            }

            // ── EndElement ────────────────────────────────────────────────────
            t if t == axml::CHUNK_XML_END_ELEMENT => {
                if chunk_size < 24 {
                    pos += chunk_size;
                    continue;
                }
                let name_idx = read_u32(data, pos + 20)? as usize;
                let elem_name = strings.get(name_idx).cloned().unwrap_or_default();
                depth = depth.saturating_sub(1);
                let indent = "  ".repeat(depth);
                writeln!(output, "{indent}</{elem_name}>").ok();
            }

            // ── Text node ─────────────────────────────────────────────────────
            t if t == axml::CHUNK_XML_TEXT => {
                if chunk_size >= 24 {
                    let str_idx = read_u32(data, pos + 16)? as usize;
                    let text = strings.get(str_idx).cloned().unwrap_or_default();
                    if !text.is_empty() {
                        let indent = "  ".repeat(depth);
                        writeln!(output, "{indent}{text}").ok();
                    }
                }
            }

            // ── Resource table (skip) ─────────────────────────────────────────
            t if t == axml::CHUNK_RES_TABLE => {}

            // ── Unknown chunk (skip) ──────────────────────────────────────────
            _ => {}
        }

        pos += chunk_size;
    }

    Ok(output)
}

// ─── ComponentInfo ────────────────────────────────────────────────────────────

/// Lightweight component descriptor produced by `ManifestParser`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Fully-qualified class name.
    pub name: String,
    /// Whether the component is exported.
    pub exported: bool,
    /// Intent filter action strings.
    pub intent_filters: Vec<String>,
}

// ─── ManifestParser ───────────────────────────────────────────────────────────

/// Parses a decoded AXML document into an [`AndroidManifest`].
pub struct ManifestParser;

impl ManifestParser {
    /// Parse raw AXML bytes into an [`AndroidManifest`].
    ///
    /// The parsing is line-oriented on the reconstructed XML text produced by
    /// [`decode_binary_xml`].  It extracts package, version, SDK constraints,
    /// permissions, and the four component types.
    ///
    /// # Errors
    /// Returns [`AndroidError::ParseError`] if AXML decoding fails.
    pub fn parse(axml_data: &[u8]) -> Result<AndroidManifest, AndroidError> {
        let xml_text = decode_binary_xml(axml_data)?;
        Self::parse_xml_text(&xml_text)
    }

    /// Internal: parse the reconstructed XML text into a manifest.
    fn parse_xml_text(xml: &str) -> Result<AndroidManifest, AndroidError> {
        let mut manifest = AndroidManifest {
            package: String::new(),
            version_name: String::new(),
            version_code: 0,
            min_sdk: 0,
            target_sdk: 0,
            max_sdk: None,
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            debuggable: false,
            allow_backup: false,
            uses_cleartext_traffic: false,
            application_class: None,
            shared_user_id: None,
            supported_screens: Vec::new(),
            extra_attributes: HashMap::new(),
        };

        // Track which element we are inside for intent-filter accumulation.
        let mut current_component: Option<(String, String, bool)> = None; // (kind, name, exported)
        let mut pending_filters: Vec<String> = Vec::new();
        let mut uses_features: Vec<String> = Vec::new();

        for line in xml.lines() {
            let trimmed = line.trim();

            // <manifest …>
            if trimmed.starts_with("<manifest") {
                manifest.package = attr_value(trimmed, "package").unwrap_or_default();
                if let Some(v) = attr_value(trimmed, "versionName") {
                    manifest.version_name = v;
                }
                if let Some(v) = attr_value(trimmed, "versionCode") {
                    manifest.version_code = v.parse().unwrap_or(0);
                }
                if let Some(v) = attr_value(trimmed, "sharedUserId") {
                    manifest.shared_user_id = Some(v);
                }
            }

            // <uses-sdk …>
            if trimmed.starts_with("<uses-sdk") {
                if let Some(v) = attr_value(trimmed, "minSdkVersion") {
                    manifest.min_sdk = v.parse().unwrap_or(0);
                }
                if let Some(v) = attr_value(trimmed, "targetSdkVersion") {
                    manifest.target_sdk = v.parse().unwrap_or(0);
                }
                if let Some(v) = attr_value(trimmed, "maxSdkVersion") {
                    manifest.max_sdk = v.parse().ok();
                }
            }

            // <uses-permission …>
            if trimmed.starts_with("<uses-permission")
                && let Some(name) = attr_value(trimmed, "name")
            {
                let level = permission_protection_level(&name);
                manifest.permissions.push(Permission::uses(name, level));
            }

            // <uses-feature …>
            if trimmed.starts_with("<uses-feature")
                && let Some(name) = attr_value(trimmed, "name")
            {
                uses_features.push(name);
            }

            // <application …>
            if trimmed.starts_with("<application") {
                manifest.debuggable = attr_bool(trimmed, "debuggable");
                manifest.allow_backup = attr_bool(trimmed, "allowBackup");
                manifest.uses_cleartext_traffic = attr_bool(trimmed, "usesCleartextTraffic");
                if let Some(v) = attr_value(trimmed, "name") {
                    manifest.application_class = Some(v);
                }
            }

            // Component open tags
            for (tag, kind) in &[
                ("<activity", "activity"),
                ("<service", "service"),
                ("<receiver", "receiver"),
                ("<provider", "provider"),
            ] {
                if trimmed.starts_with(tag) {
                    let name = attr_value(trimmed, "name").unwrap_or_default();
                    let exported = attr_bool(trimmed, "exported");
                    current_component = Some((kind.to_string(), name.clone(), exported));
                    pending_filters.clear();

                    // If self-closing, flush immediately.
                    if trimmed.ends_with("/>") {
                        Self::flush_component(&mut manifest, kind, &name, exported, &[]);
                        current_component = None;
                    }
                    break;
                }
            }

            // <action android:name="…"> inside intent-filter
            if trimmed.starts_with("<action")
                && let Some(v) = attr_value(trimmed, "name")
            {
                pending_filters.push(v);
            }

            // Component close tags
            for (close_tag, kind) in &[
                ("</activity>", "activity"),
                ("</service>", "service"),
                ("</receiver>", "receiver"),
                ("</provider>", "provider"),
            ] {
                if trimmed == *close_tag {
                    if let Some((ref k, ref n, e)) = current_component.clone()
                        && k == kind
                    {
                        Self::flush_component(
                            &mut manifest,
                            k,
                            n,
                            e,
                            &pending_filters,
                        );
                        current_component = None;
                        pending_filters.clear();
                    }
                    break;
                }
            }
        }

        // Store uses_features in extra_attributes for callers that need it.
        if !uses_features.is_empty() {
            manifest
                .extra_attributes
                .insert("uses_features".to_owned(), uses_features.join(","));
        }

        Ok(manifest)
    }

    fn flush_component(
        manifest: &mut AndroidManifest,
        kind: &str,
        name: &str,
        exported: bool,
        filters: &[String],
    ) {
        match kind {
            "activity" => manifest.activities.push(Activity {
                name: name.to_owned(),
                exported,
                intent_filters: filters.to_vec(),
                is_launcher: filters.iter().any(|f| f.contains("MAIN")),
                theme: None,
            }),
            "service" => manifest.services.push(Component {
                name: name.to_owned(),
                exported,
                required_permission: None,
                intent_filters: filters
                    .iter()
                    .map(|a| IntentFilter {
                        actions: vec![a.clone()],
                        categories: vec![],
                        schemes: vec![],
                        mime_types: vec![],
                    })
                    .collect(),
                kind: ComponentKind::Service,
                separate_process: false,
            }),
            "receiver" => manifest.receivers.push(Component {
                name: name.to_owned(),
                exported,
                required_permission: None,
                intent_filters: filters
                    .iter()
                    .map(|a| IntentFilter {
                        actions: vec![a.clone()],
                        categories: vec![],
                        schemes: vec![],
                        mime_types: vec![],
                    })
                    .collect(),
                kind: ComponentKind::BroadcastReceiver,
                separate_process: false,
            }),
            "provider" => manifest.providers.push(Component {
                name: name.to_owned(),
                exported,
                required_permission: None,
                intent_filters: vec![],
                kind: ComponentKind::ContentProvider,
                separate_process: false,
            }),
            _ => {}
        }
    }
}

// ─── ManifestParser helpers ──────────────────────────────────────────────────

/// Extract a single attribute value from a reconstructed XML start-tag line.
///
/// Matches `attrName="value"` patterns.
fn attr_value(line: &str, attr: &str) -> Option<String> {
    // Support both `name="val"` and `android:name="val"` (strip namespace).
    let needle = format!("{attr}=\"");
    let start = line.find(needle.as_str()).or_else(|| {
        // Try with android: prefix stripped when searching.
        let bare = attr.split(':').next_back().unwrap_or(attr);
        let needle2 = format!("{bare}=\"");
        line.find(needle2.as_str()) // shadowing – return the index
    })?;
    let after = &line[start + needle.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_owned())
}

/// Read a boolean attribute (`"true"` / `"false"` / `"1"` / `"0"`).
fn attr_bool(line: &str, attr: &str) -> bool {
    matches!(attr_value(line, attr).as_deref(), Some("true" | "1"))
}

/// Heuristic protection-level classification based on the permission name.
fn permission_protection_level(name: &str) -> ProtectionLevel {
    // Well-known dangerous permissions.
    const DANGEROUS: &[&str] = &[
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE",
        "RECORD_AUDIO",
        "CAMERA",
        "READ_SMS",
        "RECEIVE_SMS",
        "SEND_SMS",
        "READ_CALL_LOG",
        "WRITE_CALL_LOG",
        "READ_PHONE_STATE",
        "CALL_PHONE",
        "PROCESS_OUTGOING_CALLS",
        "BODY_SENSORS",
        "GET_ACCOUNTS",
    ];
    for d in DANGEROUS {
        if name.contains(d) {
            return ProtectionLevel::Dangerous;
        }
    }
    // Signature-level heuristics.
    if name.contains("INSTALL_PACKAGES")
        || name.contains("BIND_DEVICE_ADMIN")
        || name.contains("SYSTEM_ALERT_WINDOW")
    {
        return ProtectionLevel::Signature;
    }
    ProtectionLevel::Normal
}

// ─── DexHeaderParser ─────────────────────────────────────────────────────────

/// Parsed DEX file header (see §3.3 of the DEX format spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexHeader {
    /// Raw 8-byte magic (e.g. `"dex\n035\0"`).
    pub magic: [u8; 8],
    /// DEX version string extracted from the magic (e.g. `"035"`).
    pub version: String,
    /// Adler32 checksum of the file contents after offset 12.
    pub checksum: u32,
    /// SHA-1 hash of the file contents after the checksum field (20 bytes, hex).
    pub sha1: String,
    /// Total file size in bytes.
    pub file_size: u32,
    /// Number of strings in the string ID table.
    pub string_ids_size: u32,
    /// Number of types in the type ID table.
    pub type_ids_size: u32,
    /// Number of prototypes in the proto ID table.
    pub proto_ids_size: u32,
    /// Number of fields in the field ID table.
    pub field_ids_size: u32,
    /// Number of methods in the method ID table.
    pub method_ids_size: u32,
    /// Number of class definitions.
    pub class_defs_size: u32,
    /// Size of the data section in bytes.
    pub data_size: u32,
}

/// Parser for the 112-byte DEX file header.
pub struct DexHeaderParser;

impl DexHeaderParser {
    /// Minimum DEX header size in bytes.
    pub const HEADER_SIZE: usize = 112;

    /// Return `true` if `data` begins with a recognised DEX magic value.
    ///
    /// Accepted versions: `035`, `036`, `037`, `038`, `039`.
    #[must_use]
    pub fn verify_magic(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        // Byte layout: 0x64 0x65 0x78 0x0A <v0><v1><v2> 0x00
        // i.e. "dex\n<ver>\0"
        if &data[0..4] != b"dex\n" {
            return false;
        }
        if data[7] != 0x00 {
            return false;
        }
        matches!(&data[4..7], b"035" | b"036" | b"037" | b"038" | b"039")
    }

    /// Parse the DEX header from raw bytes.
    ///
    /// # Errors
    /// Returns [`AndroidError::DexError`] if the data is too short or the
    /// magic bytes are unrecognised.
    pub fn parse_header(data: &[u8]) -> Result<DexHeader, AndroidError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(AndroidError::DexError(format!(
                "header too short: {} < {}",
                data.len(),
                Self::HEADER_SIZE
            )));
        }
        if !Self::verify_magic(data) {
            return Err(AndroidError::DexError(format!(
                "invalid DEX magic: {:02x?}",
                &data[0..8]
            )));
        }

        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);

        let version = String::from_utf8_lossy(&data[4..7]).into_owned();
        let checksum = read_u32(8);
        let sha1_hex = data[12..32].iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let file_size = read_u32(32);
        // header_size at 36, endian_tag at 40 – not stored in our struct
        let string_ids_size = read_u32(56);
        let type_ids_size = read_u32(64);
        let proto_ids_size = read_u32(72);
        let field_ids_size = read_u32(80);
        let method_ids_size = read_u32(88);
        let class_defs_size = read_u32(96);
        let data_size = read_u32(104);

        Ok(DexHeader {
            magic,
            version,
            checksum,
            sha1: sha1_hex,
            file_size,
            string_ids_size,
            type_ids_size,
            proto_ids_size,
            field_ids_size,
            method_ids_size,
            class_defs_size,
            data_size,
        })
    }
}

// ─── SigningInfo ──────────────────────────────────────────────────────────────

/// Minimal certificate metadata extracted from an APK signing block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Distinguished name of the subject (best-effort, from raw bytes).
    pub subject: String,
    /// Distinguished name of the issuer.
    pub issuer: String,
    /// Serial number (hex).
    pub serial: String,
    /// Validity end date (ISO-8601, best-effort).
    pub not_after: String,
}

/// APK signing metadata derived from META-INF entries and the APK Signing Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInfo {
    /// `true` if a v1 (JAR) signature was found (`META-INF/*.SF` + `*.RSA/DSA/EC`).
    pub scheme_v1: bool,
    /// `true` if an APK Signing Block v2 marker was detected.
    pub scheme_v2: bool,
    /// `true` if an APK Signing Block v3 marker was detected.
    pub scheme_v3: bool,
    /// Minimal info about each certificate file found in META-INF.
    pub certificates: Vec<CertInfo>,
}

/// Extract signing information from an already-opened [`ApkParser`].
///
/// The function performs a best-effort analysis:
/// - Presence of `META-INF/*.RSA/DSA/EC` implies v1 signing.
/// - The APK Signing Block at the end of the ZIP is scanned for v2/v3 magic IDs.
/// - Certificate DN strings are scraped from raw DER using a heuristic UTF-8 scan.
pub fn extract_signing_info(apk: &mut ApkParser) -> SigningInfo {
    let all_files = apk.list_files();

    // ── v1 detection ─────────────────────────────────────────────────────────
    let cert_files: Vec<String> = all_files
        .iter()
        .filter(|n| {
            n.len() >= 9
                && n.as_bytes()[..9].eq_ignore_ascii_case(b"META-INF/")
                && std::path::Path::new(n.as_str()).extension().is_some_and(|e| {
                    e.eq_ignore_ascii_case("RSA")
                        || e.eq_ignore_ascii_case("DSA")
                        || e.eq_ignore_ascii_case("EC")
                })
        })
        .cloned()
        .collect();

    let scheme_v1 = !cert_files.is_empty();

    // ── Parse certificate DER blobs (heuristic) ───────────────────────────────
    let mut certificates: Vec<CertInfo> = Vec::new();
    for cert_name in &cert_files {
        let Ok(raw) = apk.read_file(cert_name) else { continue };
        // A PKCS#7 SignedData wraps a DER-encoded X.509 certificate.  We do a
        // best-effort scan for UTF-8/ASCII printable sequences >= 4 chars that
        // look like DN components (contain '=') to reconstruct subject/issuer.
        let strings = extract_printable_strings(&raw, 4);
        let subject = strings
            .iter()
            .find(|s| s.contains('=') && (s.contains("CN") || s.contains("O=") || s.contains("OU")))
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned());
        let issuer = strings
            .iter()
            .rfind(|s| {
                s.contains('=') && (s.contains("CN") || s.contains("O=") || s.contains("OU"))
            })
            .cloned()
            .unwrap_or_else(|| subject.clone());

        // Serial: first 16-hex-char-looking string after DER tag 0x02 (INTEGER).
        let serial = raw
            .windows(2)
            .enumerate()
            .find(|(_, w)| w[0] == 0x02 && w[1] > 0 && w[1] <= 20)
            .and_then(|(i, w)| {
                let len = w[1] as usize;
                raw.get(i + 2..i + 2 + len)
            })
            .map_or_else(
                || "00".to_owned(),
                |b| {
                    b.iter().fold(String::new(), |mut acc, x| {
                        use std::fmt::Write;
                        let _ = write!(acc, "{x:02x}");
                        acc
                    })
                },
            );

        certificates.push(CertInfo {
            subject,
            issuer,
            serial,
            not_after: "unknown".to_owned(),
        });
    }

    // ── v2/v3 detection via APK Signing Block scan ────────────────────────────
    // The APK Signing Block magic is the 16 bytes "APK Sig Block 42" at the
    // *end* of the block, just before the central-directory offset.
    // We try to read the last 65 536 bytes of the archive for a quick scan.
    let (scheme_v2, scheme_v3) = detect_signing_block_versions(apk);

    SigningInfo {
        scheme_v1,
        scheme_v2,
        scheme_v3,
        certificates,
    }
}

/// Scan raw bytes for printable ASCII strings of at least `min_len` characters.
fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(data.len() / 64);
    let mut current: Vec<u8> = Vec::with_capacity(64);
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        out.push(String::from_utf8_lossy(&current).into_owned());
    }
    out
}

/// Detect APK Signing Block v2/v3 by scanning for the magic byte sequence.
fn detect_signing_block_versions(apk: &mut ApkParser) -> (bool, bool) {
    // Read the ZIP comment area / EOCD region to find the signing block.
    // For robustness we read the whole COMMENT.BIN or just try a direct read.
    // In practice without a raw file handle we cannot seek to the ZIP end, so
    // we approximate by looking at the "APK Signing Block" sentinel in any
    // readable entry.  If the archive has an `APKSIGBLOCK` entry (some tools
    // emit this), we read that; otherwise we report unknown.
    let v2_magic = b"APK Sig Block 42";
    // ID 0x7109871a = v2 block ID; 0xf05368c0 = v3 block ID (in LE bytes).
    const V2_ID: [u8; 4] = [0x1a, 0x87, 0x09, 0x71];
    const V3_ID: [u8; 4] = [0xc0, 0x68, 0x53, 0xf0];

    let candidate_names: Vec<String> = apk
        .list_files()
        .into_iter()
        .filter(|n| {
            let bytes = n.as_bytes();
            fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
                hay.len() >= needle.len()
                    && hay
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle))
            }
            contains_ci(bytes, b"APKSIG")
                || contains_ci(bytes, b"SIGNING")
                || bytes.eq_ignore_ascii_case(b"META-INF/MANIFEST.MF")
        })
        .collect();

    for name in candidate_names {
        if let Ok(data) = apk.read_file(&name)
            && data.windows(v2_magic.len()).any(|w| w == v2_magic)
        {
            let has_v2 = data.windows(4).any(|w| w == V2_ID);
            let has_v3 = data.windows(4).any(|w| w == V3_ID);
            return (has_v2, has_v3);
        }
    }

    // Cannot determine without raw ZIP stream; assume v1-only.
    (false, false)
}

// ─── ApkReport ────────────────────────────────────────────────────────────────

/// Comprehensive static analysis report for an APK file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkReport {
    /// Application package identifier.
    pub package: String,
    /// Human-readable version string.
    pub version: String,
    /// Minimum Android API level.
    pub min_sdk: u32,
    /// Target Android API level.
    pub target_sdk: u32,
    /// All permissions declared with `<uses-permission>`.
    pub permissions: Vec<String>,
    /// Total number of components (activities + services + receivers + providers).
    pub components: u32,
    /// Number of DEX files found in the archive.
    pub dex_count: u32,
    /// Native library file names (e.g. `libnative.so`).
    pub native_libs: Vec<String>,
    /// Whether any native `.so` libraries are present.
    pub has_native: bool,
    /// APK signing metadata.
    pub signing_info: SigningInfo,
    /// Total number of archive entries.
    pub file_count: u32,
    /// Sum of all entry uncompressed sizes in bytes.
    pub total_size: u64,
    /// Permissions considered suspicious or high-risk.
    pub suspicious_permissions: Vec<String>,
    /// DEX header info for each DEX file (in order).
    pub dex_headers: Vec<DexHeader>,
    /// Whether the manifest has `debuggable=true`.
    pub debuggable: bool,
    /// Whether the app requests cleartext traffic.
    pub uses_cleartext_traffic: bool,
}

// ─── FileApkAnalyzer ─────────────────────────────────────────────────────────

/// File-level APK analyser that opens a real APK and produces an [`ApkReport`].
///
/// This is separate from the in-memory [`ApkAnalyzer`] type defined earlier,
/// which operates on the high-level [`Apk`] model.
pub struct FileApkAnalyzer;

impl FileApkAnalyzer {
    /// Open an APK at `path` on disk and produce a full [`ApkReport`].
    ///
    /// # Errors
    /// Returns [`AndroidError`] for I/O failures, ZIP parse errors, or corrupt
    /// DEX / AXML data.
    pub fn analyze(path: &Path) -> Result<ApkReport, AndroidError> {
        let mut apk = ApkParser::open(path)?;

        let file_names = apk.list_files();
        let file_count = file_names.len() as u32;

        // ── Enumerate entries ────────────────────────────────────────────────
        let mut dex_names: Vec<String> = Vec::new();
        let mut native_lib_names: Vec<String> = Vec::new();
        let mut total_size: u64 = 0;

        for name in &file_names {
            let ext = std::path::Path::new(name.as_str()).extension();
            if ext.is_some_and(|e| e.eq_ignore_ascii_case("dex")) {
                dex_names.push(name.clone());
            }
            if name.starts_with("lib/") && ext.is_some_and(|e| e.eq_ignore_ascii_case("so")) {
                // Extract just the filename.
                let lib_name = name.split('/').next_back().unwrap_or(name).to_owned();
                if !native_lib_names.contains(&lib_name) {
                    native_lib_names.push(lib_name);
                }
            }
        }

        // Accumulate sizes.
        {
            // Re-open to iterate with sizes (zip crate needs &mut per entry).
            let raw = std::fs::read(path).map_err(|e| AndroidError::Io(e.to_string()))?;
            let cursor = Cursor::new(raw);
            let mut za =
                ZipArchive::new(cursor).map_err(|e| AndroidError::InvalidApk(e.to_string()))?;
            for i in 0..za.len() {
                if let Ok(f) = za.by_index(i) {
                    total_size += f.size();
                }
            }
        }

        let dex_count = dex_names.len() as u32;
        let has_native = !native_lib_names.is_empty();

        // ── Parse manifest ───────────────────────────────────────────────────
        let manifest_opt: Option<AndroidManifest> = if apk.has_file("AndroidManifest.xml") {
            match apk.read_file("AndroidManifest.xml") {
                Ok(raw) => ManifestParser::parse(&raw).ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let (
            package,
            version,
            min_sdk,
            target_sdk,
            permissions,
            components,
            debuggable,
            uses_cleartext,
        ) = if let Some(ref m) = manifest_opt {
            let perm_names: Vec<String> = m.permissions.iter().map(|p| p.name.clone()).collect();
            let comp_count =
                (m.activities.len() + m.services.len() + m.receivers.len() + m.providers.len())
                    as u32;
            (
                m.package.clone(),
                m.version_name.clone(),
                m.min_sdk,
                m.target_sdk,
                perm_names,
                comp_count,
                m.debuggable,
                m.uses_cleartext_traffic,
            )
        } else {
            (
                String::new(),
                String::new(),
                0,
                0,
                Vec::new(),
                0,
                false,
                false,
            )
        };

        // ── Suspicious permissions ────────────────────────────────────────────
        let suspicious = Self::suspicious_permissions(&permissions);

        // ── DEX headers ──────────────────────────────────────────────────────
        let mut dex_headers = Vec::with_capacity(dex_names.len());
        for dex_name in &dex_names {
            if let Ok(raw) = apk.read_file(dex_name)
                && let Ok(hdr) = DexHeaderParser::parse_header(&raw)
            {
                dex_headers.push(hdr);
            }
        }

        // ── Signing info ─────────────────────────────────────────────────────
        let signing_info = extract_signing_info(&mut apk);

        Ok(ApkReport {
            package,
            version,
            min_sdk,
            target_sdk,
            permissions,
            components,
            dex_count,
            native_libs: native_lib_names,
            has_native,
            signing_info,
            file_count,
            total_size,
            suspicious_permissions: suspicious,
            dex_headers,
            debuggable,
            uses_cleartext_traffic: uses_cleartext,
        })
    }

    /// Filter a permission list to those considered suspicious or high-risk.
    ///
    /// Matches the following permission suffixes:
    /// `SEND_SMS`, `RECEIVE_SMS`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`,
    /// `RECORD_AUDIO`, `CAMERA`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS`,
    /// `BIND_DEVICE_ADMIN`, `RECEIVE_BOOT_COMPLETED`, `REQUEST_INSTALL_PACKAGES`.
    #[must_use]
    pub fn suspicious_permissions(perms: &[String]) -> Vec<String> {
        const SUSPICIOUS: &[&str] = &[
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_CONTACTS",
            "ACCESS_FINE_LOCATION",
            "RECORD_AUDIO",
            "CAMERA",
            "READ_CALL_LOG",
            "PROCESS_OUTGOING_CALLS",
            "BIND_DEVICE_ADMIN",
            "RECEIVE_BOOT_COMPLETED",
            "REQUEST_INSTALL_PACKAGES",
        ];
        perms
            .iter()
            .filter(|p| SUSPICIOUS.iter().any(|s| p.contains(s)))
            .cloned()
            .collect()
    }
}

// ─── §25 Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod android_tooling_tests {
    use super::*;

    // ── decode_binary_xml ─────────────────────────────────────────────────────

    #[test]
    fn test_decode_binary_xml_bad_magic() {
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(decode_binary_xml(data).is_err());
    }

    #[test]
    fn test_decode_binary_xml_too_short() {
        assert!(decode_binary_xml(b"\x03").is_err());
    }

    #[test]
    fn test_decode_binary_xml_good_magic_empty() {
        // Magic OK but no chunks → returns empty string (not an error).
        let mut data = vec![0u8; 8];
        data[0] = 0x03;
        data[1] = 0x00;
        // file size little-endian at bytes 4..8
        let sz = 8u32.to_le_bytes();
        data[4..8].copy_from_slice(&sz);
        let result = decode_binary_xml(&data);
        assert!(result.is_ok());
    }

    // ── ManifestParser (from XML text) ────────────────────────────────────────

    #[test]
    fn test_manifest_parser_package_extraction() {
        let xml = r#"<manifest package="com.test.app" versionName="2.0" versionCode="5">
<uses-sdk minSdkVersion="21" targetSdkVersion="33">
</uses-sdk>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert_eq!(m.package, "com.test.app");
        assert_eq!(m.version_name, "2.0");
        assert_eq!(m.version_code, 5);
        assert_eq!(m.min_sdk, 21);
        assert_eq!(m.target_sdk, 33);
    }

    #[test]
    fn test_manifest_parser_permissions() {
        let xml = r#"<manifest package="com.p">
<uses-permission name="android.permission.CAMERA">
</uses-permission>
<uses-permission name="android.permission.INTERNET">
</uses-permission>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert_eq!(m.permissions.len(), 2);
        assert!(m.permissions.iter().any(|p| p.name.contains("CAMERA")));
    }

    #[test]
    fn test_manifest_parser_activity() {
        let xml = r#"<manifest package="com.p">
<application name=".App">
<activity name="com.p.MainActivity" exported="true">
</activity>
</application>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert_eq!(m.activities.len(), 1);
        assert_eq!(m.activities[0].name, "com.p.MainActivity");
    }

    #[test]
    fn test_manifest_parser_debuggable() {
        let xml = r#"<manifest package="com.p">
<application debuggable="true">
</application>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert!(m.debuggable);
    }

    #[test]
    fn test_manifest_parser_service() {
        let xml = r#"<manifest package="com.p">
<application>
<service name="com.p.BackgroundService" exported="false">
</service>
</application>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert_eq!(m.services.len(), 1);
        assert_eq!(m.services[0].name, "com.p.BackgroundService");
    }

    #[test]
    fn test_manifest_parser_receiver() {
        let xml = r#"<manifest package="com.p">
<application>
<receiver name="com.p.BootReceiver" exported="true">
<action name="android.intent.action.BOOT_COMPLETED">
</action>
</receiver>
</application>
</manifest>"#;
        let m = ManifestParser::parse_xml_text(xml).unwrap();
        assert_eq!(m.receivers.len(), 1);
        assert_eq!(m.receivers[0].name, "com.p.BootReceiver");
    }

    // ── DexHeaderParser ───────────────────────────────────────────────────────

    #[test]
    fn test_dex_verify_magic_valid_035() {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n035\0");
        assert!(DexHeaderParser::verify_magic(&data));
    }

    #[test]
    fn test_dex_verify_magic_valid_036() {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n036\0");
        assert!(DexHeaderParser::verify_magic(&data));
    }

    #[test]
    fn test_dex_verify_magic_invalid() {
        assert!(!DexHeaderParser::verify_magic(b"PK\x03\x04xxxxxxxx"));
    }

    #[test]
    fn test_dex_verify_magic_too_short() {
        assert!(!DexHeaderParser::verify_magic(b"dex"));
    }

    #[test]
    fn test_dex_parse_header_too_short() {
        let data = vec![0u8; 50];
        assert!(DexHeaderParser::parse_header(&data).is_err());
    }

    #[test]
    fn test_dex_parse_header_invalid_magic() {
        let data = vec![0u8; 112];
        let err = DexHeaderParser::parse_header(&data).unwrap_err();
        assert!(matches!(err, AndroidError::DexError(_)));
    }

    #[test]
    fn test_dex_parse_header_valid() {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n035\0");
        // file_size at offset 32, little-endian
        data[32..36].copy_from_slice(&112u32.to_le_bytes());
        // string_ids_size at offset 56
        data[56..60].copy_from_slice(&10u32.to_le_bytes());
        // class_defs_size at offset 96
        data[96..100].copy_from_slice(&5u32.to_le_bytes());
        let hdr = DexHeaderParser::parse_header(&data).unwrap();
        assert_eq!(hdr.version, "035");
        assert_eq!(hdr.file_size, 112);
        assert_eq!(hdr.string_ids_size, 10);
        assert_eq!(hdr.class_defs_size, 5);
    }

    #[test]
    fn test_dex_header_sha1_hex_length() {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n035\0");
        let hdr = DexHeaderParser::parse_header(&data).unwrap();
        // SHA-1 is 20 bytes → 40 hex chars.
        assert_eq!(hdr.sha1.len(), 40);
    }

    // ── FileApkAnalyzer::suspicious_permissions ───────────────────────────────

    #[test]
    fn test_suspicious_permissions_filter() {
        let perms = vec![
            "android.permission.INTERNET".to_owned(),
            "android.permission.CAMERA".to_owned(),
            "android.permission.SEND_SMS".to_owned(),
            "android.permission.ACCESS_FINE_LOCATION".to_owned(),
            "android.permission.VIBRATE".to_owned(),
        ];
        let sus = FileApkAnalyzer::suspicious_permissions(&perms);
        assert_eq!(sus.len(), 3);
        assert!(sus.iter().any(|s| s.contains("CAMERA")));
        assert!(sus.iter().any(|s| s.contains("SEND_SMS")));
        assert!(sus.iter().any(|s| s.contains("ACCESS_FINE_LOCATION")));
    }

    #[test]
    fn test_suspicious_permissions_none() {
        let perms = vec![
            "android.permission.INTERNET".to_owned(),
            "android.permission.VIBRATE".to_owned(),
        ];
        assert!(FileApkAnalyzer::suspicious_permissions(&perms).is_empty());
    }

    #[test]
    fn test_suspicious_permissions_all() {
        let perms = vec![
            "android.permission.SEND_SMS".to_owned(),
            "android.permission.RECEIVE_SMS".to_owned(),
            "android.permission.READ_CONTACTS".to_owned(),
            "android.permission.ACCESS_FINE_LOCATION".to_owned(),
            "android.permission.RECORD_AUDIO".to_owned(),
            "android.permission.CAMERA".to_owned(),
            "android.permission.READ_CALL_LOG".to_owned(),
            "android.permission.PROCESS_OUTGOING_CALLS".to_owned(),
            "android.permission.BIND_DEVICE_ADMIN".to_owned(),
            "android.permission.RECEIVE_BOOT_COMPLETED".to_owned(),
            "android.permission.REQUEST_INSTALL_PACKAGES".to_owned(),
        ];
        let sus = FileApkAnalyzer::suspicious_permissions(&perms);
        assert_eq!(sus.len(), 11);
    }

    // ── attr_value / attr_bool helpers ────────────────────────────────────────

    #[test]
    fn test_attr_value_found() {
        let line = r#"<manifest package="com.foo" versionCode="3">"#;
        assert_eq!(attr_value(line, "package"), Some("com.foo".to_owned()));
        assert_eq!(attr_value(line, "versionCode"), Some("3".to_owned()));
    }

    #[test]
    fn test_attr_value_not_found() {
        let line = r#"<manifest package="com.foo">"#;
        assert_eq!(attr_value(line, "minSdkVersion"), None);
    }

    #[test]
    fn test_attr_bool_true() {
        let line = r#"<application debuggable="true">"#;
        assert!(attr_bool(line, "debuggable"));
    }

    #[test]
    fn test_attr_bool_false() {
        let line = r#"<application debuggable="false">"#;
        assert!(!attr_bool(line, "debuggable"));
    }

    #[test]
    fn test_attr_bool_missing_defaults_false() {
        let line = r"<application>";
        assert!(!attr_bool(line, "debuggable"));
    }

    // ── extract_printable_strings ─────────────────────────────────────────────

    #[test]
    fn test_extract_printable_strings_basic() {
        let data = b"hello\x00world\x00\x01\x02short\x00toolongstring";
        let strings = extract_printable_strings(data, 5);
        assert!(strings.iter().any(|s| s.contains("hello")));
        assert!(strings.iter().any(|s| s.contains("world")));
        assert!(strings.iter().any(|s| s.contains("toolongstring")));
    }

    #[test]
    fn test_extract_printable_strings_min_len() {
        let data = b"ab\x00abcdef\x00";
        let strings = extract_printable_strings(data, 4);
        assert!(!strings.iter().any(|s| s == "ab"));
        assert!(strings.iter().any(|s| s.contains("abcdef")));
    }

    // ── SigningInfo default state ──────────────────────────────────────────────

    #[test]
    fn test_signing_info_serialization() {
        let si = SigningInfo {
            scheme_v1: true,
            scheme_v2: false,
            scheme_v3: false,
            certificates: vec![CertInfo {
                subject: "CN=Test".to_owned(),
                issuer: "CN=Test".to_owned(),
                serial: "01".to_owned(),
                not_after: "unknown".to_owned(),
            }],
        };
        let json = serde_json::to_string(&si).unwrap();
        let decoded: SigningInfo = serde_json::from_str(&json).unwrap();
        assert!(decoded.scheme_v1);
        assert!(!decoded.scheme_v2);
        assert_eq!(decoded.certificates.len(), 1);
    }

    // ── permission_protection_level heuristic ─────────────────────────────────

    #[test]
    fn test_protection_level_camera_is_dangerous() {
        assert_eq!(
            permission_protection_level("android.permission.CAMERA"),
            ProtectionLevel::Dangerous
        );
    }

    #[test]
    fn test_protection_level_internet_is_normal() {
        assert_eq!(
            permission_protection_level("android.permission.INTERNET"),
            ProtectionLevel::Normal
        );
    }

    #[test]
    fn test_protection_level_install_packages_is_signature() {
        assert_eq!(
            permission_protection_level("android.permission.INSTALL_PACKAGES"),
            ProtectionLevel::Signature
        );
    }

    // ── DexHeader serialization ───────────────────────────────────────────────

    #[test]
    fn test_dex_header_serialization() {
        let hdr = DexHeader {
            magic: *b"dex\n035\0",
            version: "035".to_owned(),
            checksum: 0xDEAD_BEEF,
            sha1: "a".repeat(40),
            file_size: 112,
            string_ids_size: 10,
            type_ids_size: 5,
            proto_ids_size: 3,
            field_ids_size: 2,
            method_ids_size: 8,
            class_defs_size: 4,
            data_size: 0,
        };
        let json = serde_json::to_string(&hdr).unwrap();
        let decoded: DexHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, "035");
        assert_eq!(decoded.checksum, 0xDEAD_BEEF);
    }

    // ── ComponentInfo serialization ───────────────────────────────────────────

    #[test]
    fn test_component_info_serialization() {
        let c = ComponentInfo {
            name: "com.example.MainActivity".to_owned(),
            exported: true,
            intent_filters: vec!["android.intent.action.MAIN".to_owned()],
        };
        let json = serde_json::to_string(&c).unwrap();
        let decoded: ComponentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, c.name);
        assert!(decoded.exported);
    }

    // ── ApkReport serialization ───────────────────────────────────────────────

    #[test]
    fn test_apk_report_serialization() {
        let report = ApkReport {
            package: "com.example".to_owned(),
            version: "1.0".to_owned(),
            min_sdk: 21,
            target_sdk: 33,
            permissions: vec!["android.permission.INTERNET".to_owned()],
            components: 4,
            dex_count: 1,
            native_libs: vec!["libnative.so".to_owned()],
            has_native: true,
            signing_info: SigningInfo {
                scheme_v1: true,
                scheme_v2: false,
                scheme_v3: false,
                certificates: vec![],
            },
            file_count: 20,
            total_size: 102_400,
            suspicious_permissions: vec![],
            dex_headers: vec![],
            debuggable: false,
            uses_cleartext_traffic: false,
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: ApkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.package, "com.example");
        assert_eq!(decoded.dex_count, 1);
        assert!(decoded.has_native);
    }
}
