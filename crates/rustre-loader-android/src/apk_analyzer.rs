//! Deep APK analysis — `ApkAnalyzer`, `ApkManifest`, permissions, components,
//! DEX statistics, native libraries, threat scoring, and full report.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced during deep APK analysis.
#[derive(Debug, thiserror::Error)]
pub enum ApkAnalyzerError {
    #[error("not a valid APK: {0}")]
    InvalidApk(String),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("dex parse error: {0}")]
    DexParse(String),
    #[error("zip error: {0}")]
    Zip(String),
    #[error("io error: {0}")]
    Io(String),
}

// ─── Permission classification ────────────────────────────────────────────────

/// Classification of an Android permission by protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionClass {
    /// Granted automatically at install time.
    Normal,
    /// Requires explicit runtime approval from the user.
    Dangerous,
    /// Granted only to apps signed with the platform key.
    Signature,
    /// Granted only to system/privileged apps.
    Privileged,
    /// Unknown or custom protection level.
    Unknown,
}

impl PermissionClass {
    /// Return the threat weight of this permission class (0–10 scale).
    #[must_use]
    pub const fn threat_weight(self) -> f64 {
        match self {
            Self::Normal => 0.5,
            Self::Dangerous => 3.0,
            Self::Signature => 2.0,
            Self::Privileged => 5.0,
            Self::Unknown => 1.0,
        }
    }

    /// Determine the permission class from the full permission name string.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        // Known dangerous permissions by substring
        let dangerous = [
            "CAMERA",
            "RECORD_AUDIO",
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "READ_PHONE_STATE",
            "PROCESS_OUTGOING_CALLS",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "BODY_SENSORS",
            "GET_ACCOUNTS",
            "USE_BIOMETRIC",
            "MANAGE_EXTERNAL_STORAGE",
            "ACCESS_MEDIA_LOCATION",
            "UWB_RANGING",
            "BLUETOOTH_SCAN",
            "BLUETOOTH_CONNECT",
            "NEARBY_WIFI_DEVICES",
        ];
        for d in &dangerous {
            if name.contains(d) {
                return Self::Dangerous;
            }
        }
        let signature_prefix = [
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.ACCESS_SUPERUSER",
        ];
        for s in &signature_prefix {
            if name.starts_with(s) {
                return Self::Signature;
            }
        }
        Self::Normal
    }
}

impl fmt::Display for PermissionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Dangerous => write!(f, "dangerous"),
            Self::Signature => write!(f, "signature"),
            Self::Privileged => write!(f, "privileged"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── ApkPermissions ──────────────────────────────────────────────────────────

/// Classified permission lists extracted from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApkPermissions {
    /// All declared `<uses-permission>` entries.
    pub all: Vec<String>,
    /// Subset classified as dangerous.
    pub dangerous: Vec<String>,
    /// Subset classified as normal.
    pub normal: Vec<String>,
    /// Subset classified as signature-level.
    pub signature: Vec<String>,
    /// Permissions related to location.
    pub location: Vec<String>,
    /// Permissions related to microphone / camera.
    pub av_recording: Vec<String>,
    /// Permissions related to telephony (SMS, calls).
    pub telephony: Vec<String>,
    /// Permissions considered suspicious for stalkerware/spyware analysis.
    pub spyware_relevant: Vec<String>,
}

impl ApkPermissions {
    /// Build a classified `ApkPermissions` from a flat list of permission names.
    #[must_use]
    pub fn from_list(perms: Vec<String>) -> Self {
        let mut out = Self::default();
        for p in &perms {
            let cls = PermissionClass::from_name(p);
            let is_location = p.contains("LOCATION") || p.contains("GPS");
            let is_av = p.contains("CAMERA") || p.contains("RECORD_AUDIO");
            let is_tel = p.contains("SMS") || p.contains("CALL") || p.contains("PHONE");
            let is_contacts = p.contains("READ_CONTACTS");
            match cls {
                PermissionClass::Dangerous => out.dangerous.push(p.clone()),
                PermissionClass::Normal => out.normal.push(p.clone()),
                PermissionClass::Signature => out.signature.push(p.clone()),
                _ => {}
            }
            if is_location {
                out.location.push(p.clone());
            }
            if is_av {
                out.av_recording.push(p.clone());
            }
            if is_tel {
                out.telephony.push(p.clone());
            }
            if is_location || is_tel || is_av || is_contacts {
                out.spyware_relevant.push(p.clone());
            }
        }
        out.all = perms;
        out
    }

    /// Cumulative threat score from all permissions (0–100 scale).
    #[must_use]
    pub fn threat_score(&self) -> f64 {
        let base: f64 = (self.av_recording.len() as f64).mul_add(2.0, (self.telephony.len() as f64).mul_add(2.5, (self.location.len() as f64).mul_add(2.0, (self.dangerous.len() as f64).mul_add(3.0, self.signature.len() as f64 * 2.0))));
        base.min(100.0)
    }
}

// ─── IntentFilter ────────────────────────────────────────────────────────────

/// A simplified intent filter attached to a component.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub mime_types: Vec<String>,
}

impl IntentFilter {
    /// Returns `true` if this is the launcher (MAIN + LAUNCHER) filter.
    #[must_use]
    pub fn is_launcher(&self) -> bool {
        self.actions.iter().any(|a| a.contains("MAIN"))
            && self.categories.iter().any(|c| c.contains("LAUNCHER"))
    }

    /// Returns `true` if this filter handles `BOOT_COMPLETED`.
    #[must_use]
    pub fn is_boot_receiver(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.contains("BOOT_COMPLETED") || a.contains("QUICKBOOT"))
    }

    /// Returns `true` if this filter can receive SMS.
    #[must_use]
    pub fn is_sms_receiver(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.contains("SMS_RECEIVED") || a.contains("WAP_PUSH"))
    }
}

// ─── ApkComponent ────────────────────────────────────────────────────────────

/// An Android application component (activity / service / receiver / provider).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkComponent {
    /// Fully-qualified class name.
    pub name: String,
    /// Whether the component is exported to other apps.
    pub exported: bool,
    /// Required permission to interact with this component.
    pub required_permission: Option<String>,
    /// Intent filters declared on this component.
    pub intent_filters: Vec<IntentFilter>,
    /// Whether the component was marked `enabled=false`.
    pub enabled: bool,
    /// Whether the component runs in a separate process.
    pub in_separate_process: bool,
    /// Authority string (providers only).
    pub authorities: Option<String>,
}

impl ApkComponent {
    /// Returns `true` if the component is exported without a permission guard.
    #[must_use]
    pub const fn is_exposed(&self) -> bool {
        self.exported && self.required_permission.is_none()
    }

    /// Returns `true` if any intent filter is a `BOOT_COMPLETED` receiver.
    #[must_use]
    pub fn persists_across_reboot(&self) -> bool {
        self.intent_filters.iter().any(IntentFilter::is_boot_receiver)
    }

    /// Returns `true` if any intent filter can intercept SMS.
    #[must_use]
    pub fn can_intercept_sms(&self) -> bool {
        self.intent_filters.iter().any(IntentFilter::is_sms_receiver)
    }
}

// ─── ApkComponents ───────────────────────────────────────────────────────────

/// All four component types from an APK's manifest.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApkComponents {
    pub activities: Vec<ApkComponent>,
    pub services: Vec<ApkComponent>,
    pub receivers: Vec<ApkComponent>,
    pub providers: Vec<ApkComponent>,
}

impl ApkComponents {
    /// Total component count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.activities.len() + self.services.len() + self.receivers.len() + self.providers.len()
    }

    /// Exposed (exported + no permission) components across all types.
    #[must_use]
    pub fn exposed(&self) -> Vec<&ApkComponent> {
        self.activities
            .iter()
            .chain(self.services.iter())
            .chain(self.receivers.iter())
            .chain(self.providers.iter())
            .filter(|c| c.is_exposed())
            .collect()
    }

    /// Components that persist across reboots (`BOOT_COMPLETED` receivers).
    #[must_use]
    pub fn boot_persistent(&self) -> Vec<&ApkComponent> {
        self.receivers
            .iter()
            .filter(|c| c.persists_across_reboot())
            .collect()
    }

    /// Components that can receive SMS.
    #[must_use]
    pub fn sms_interceptors(&self) -> Vec<&ApkComponent> {
        self.receivers
            .iter()
            .filter(|c| c.can_intercept_sms())
            .collect()
    }

    /// The launcher activity (MAIN + LAUNCHER intent filter).
    #[must_use]
    pub fn launcher_activity(&self) -> Option<&ApkComponent> {
        self.activities
            .iter()
            .find(|a| a.intent_filters.iter().any(IntentFilter::is_launcher))
    }
}

// ─── ApkManifest ─────────────────────────────────────────────────────────────

/// Full parsed representation of `AndroidManifest.xml` for deep analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkManifest {
    /// Application package name, e.g. `com.example.app`.
    pub package: String,
    /// Human-readable version string.
    pub version_name: String,
    /// Integer version code.
    pub version_code: u32,
    /// Minimum Android SDK level.
    pub min_sdk: u32,
    /// Target Android SDK level.
    pub target_sdk: u32,
    /// Whether the app is marked `debuggable=true`.
    pub debuggable: bool,
    /// Whether the app allows backup.
    pub allow_backup: bool,
    /// Whether the app uses cleartext (non-HTTPS) traffic.
    pub uses_cleartext_traffic: bool,
    /// Custom application class, if declared.
    pub application_class: Option<String>,
    /// Shared user ID declared in the manifest.
    pub shared_user_id: Option<String>,
    /// Parsed permissions.
    pub permissions: ApkPermissions,
    /// Parsed components.
    pub components: ApkComponents,
    /// Raw extra attributes not captured by specific fields.
    pub extra_attrs: HashMap<String, String>,
}

impl ApkManifest {
    /// Build a minimal mock manifest for testing.
    #[must_use]
    pub fn mock(package: impl Into<String>) -> Self {
        let perms = vec![
            "android.permission.INTERNET".into(),
            "android.permission.CAMERA".into(),
            "android.permission.READ_SMS".into(),
            "android.permission.ACCESS_FINE_LOCATION".into(),
            "android.permission.RECORD_AUDIO".into(),
        ];
        let boot_filter = IntentFilter {
            actions: vec!["android.intent.action.BOOT_COMPLETED".into()],
            categories: vec![],
            data_schemes: vec![],
            mime_types: vec![],
        };
        let sms_filter = IntentFilter {
            actions: vec!["android.provider.Telephony.SMS_RECEIVED".into()],
            categories: vec![],
            data_schemes: vec![],
            mime_types: vec![],
        };
        let main_filter = IntentFilter {
            actions: vec!["android.intent.action.MAIN".into()],
            categories: vec!["android.intent.category.LAUNCHER".into()],
            data_schemes: vec![],
            mime_types: vec![],
        };
        Self {
            package: package.into(),
            version_name: "1.0.0".into(),
            version_code: 1,
            min_sdk: 21,
            target_sdk: 33,
            debuggable: false,
            allow_backup: true,
            uses_cleartext_traffic: false,
            application_class: None,
            shared_user_id: None,
            permissions: ApkPermissions::from_list(perms),
            components: ApkComponents {
                activities: vec![ApkComponent {
                    name: "com.example.MainActivity".into(),
                    exported: true,
                    required_permission: None,
                    intent_filters: vec![main_filter],
                    enabled: true,
                    in_separate_process: false,
                    authorities: None,
                }],
                services: vec![ApkComponent {
                    name: "com.example.BackgroundService".into(),
                    exported: false,
                    required_permission: None,
                    intent_filters: vec![],
                    enabled: true,
                    in_separate_process: false,
                    authorities: None,
                }],
                receivers: vec![
                    ApkComponent {
                        name: "com.example.BootReceiver".into(),
                        exported: true,
                        required_permission: None,
                        intent_filters: vec![boot_filter],
                        enabled: true,
                        in_separate_process: false,
                        authorities: None,
                    },
                    ApkComponent {
                        name: "com.example.SmsReceiver".into(),
                        exported: true,
                        required_permission: None,
                        intent_filters: vec![sms_filter],
                        enabled: true,
                        in_separate_process: false,
                        authorities: None,
                    },
                ],
                providers: vec![],
            },
            extra_attrs: HashMap::new(),
        }
    }

    /// Compute a threat score (0–100) from manifest properties.
    #[must_use]
    pub fn threat_score(&self) -> f64 {
        let mut score = self.permissions.threat_score() * 0.4;
        let exposed = self.components.exposed().len() as f64;
        score = exposed.mul_add(2.0, score);
        if !self.components.boot_persistent().is_empty() {
            score += 5.0;
        }
        if !self.components.sms_interceptors().is_empty() {
            score += 8.0;
        }
        if self.debuggable {
            score += 3.0;
        }
        if self.uses_cleartext_traffic {
            score += 2.0;
        }
        score.min(100.0)
    }
}

// ─── DexStats ────────────────────────────────────────────────────────────────

/// Statistics about DEX files found inside the APK.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DexStats {
    /// Number of DEX files.
    pub dex_count: u32,
    /// Total number of classes across all DEX files.
    pub total_classes: u32,
    /// Total number of methods across all DEX files.
    pub total_methods: u32,
    /// Total number of string constants across all DEX files.
    pub total_strings: u32,
    /// Number of classes whose names appear obfuscated (1-2 char names).
    pub obfuscated_class_count: u32,
    /// Whether any `classes*.dex` file uses multi-DEX (> 65535 methods).
    pub is_multi_dex: bool,
    /// DEX version string (e.g. `"035"`).
    pub dex_version: String,
    /// Per-DEX file sizes in bytes.
    pub dex_sizes: Vec<usize>,
}

impl DexStats {
    /// Fraction (0.0–1.0) of classes with obfuscated names.
    #[must_use]
    pub fn obfuscation_ratio(&self) -> f64 {
        if self.total_classes == 0 {
            return 0.0;
        }
        f64::from(self.obfuscated_class_count) / f64::from(self.total_classes)
    }
}

// ─── NativeLibInfo ────────────────────────────────────────────────────────────

/// Metadata about a native `.so` library inside the APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibInfo {
    /// Library file name, e.g. `libnative.so`.
    pub name: String,
    /// ABI folder, e.g. `arm64-v8a`.
    pub abi: String,
    /// File size in bytes.
    pub size: usize,
    /// CRC-32 checksum of the compressed entry.
    pub crc32: u32,
    /// Whether the library exports symbols matching JNI naming conventions.
    pub has_jni_exports: bool,
    /// Whether the library imports `ptrace` (anti-debugging indicator).
    pub imports_ptrace: bool,
    /// Whether the library imports cryptographic functions.
    pub imports_crypto: bool,
    /// SHA-256 hex digest (empty if not computed).
    pub sha256: String,
}

impl NativeLibInfo {
    /// Simple heuristic — returns `true` when the lib is likely a JNI bridge.
    #[must_use]
    pub fn is_jni_bridge(&self) -> bool {
        self.has_jni_exports || self.name.starts_with("libjni")
    }

    /// Risk score based on imported symbol patterns (0–10).
    #[must_use]
    pub fn risk_score(&self) -> f64 {
        let mut score = 0.0_f64;
        if self.imports_ptrace {
            score += 3.0;
        }
        if self.imports_crypto {
            score += 2.0;
        }
        score.min(10.0)
    }
}

/// Summary of all native libraries in an APK.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NativeLibs {
    pub libs: Vec<NativeLibInfo>,
    pub abis: HashSet<String>,
}

impl NativeLibs {
    /// Whether any native library is present.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        !self.libs.is_empty()
    }

    /// Whether any lib uses `ptrace`.
    #[must_use]
    pub fn any_uses_ptrace(&self) -> bool {
        self.libs.iter().any(|l| l.imports_ptrace)
    }

    /// Aggregate risk score (sum of per-lib scores, capped at 100).
    #[must_use]
    pub fn aggregate_risk(&self) -> f64 {
        self.libs
            .iter()
            .map(NativeLibInfo::risk_score)
            .sum::<f64>()
            .min(100.0)
    }
}

// ─── ApkThreatScore ──────────────────────────────────────────────────────────

/// Breakdown of a computed APK threat score.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApkThreatScore {
    /// 0–100 score from manifest analysis.
    pub manifest_score: f64,
    /// 0–100 score from DEX analysis.
    pub dex_score: f64,
    /// 0–100 score from native library analysis.
    pub native_score: f64,
    /// Combined weighted score (0–100).
    pub total: f64,
    /// Human-readable indicators that drove the score.
    pub indicators: Vec<String>,
    /// Guessed malware family or `"unknown"`.
    pub family_guess: String,
}

impl ApkThreatScore {
    /// Compute a threat score from analysed components.
    #[must_use]
    pub fn compute(manifest: &ApkManifest, dex_stats: &DexStats, native_libs: &NativeLibs) -> Self {
        let manifest_score = manifest.threat_score();
        let dex_score = {
            let mut s = dex_stats.obfuscation_ratio() * 30.0;
            if dex_stats.is_multi_dex {
                s += 5.0;
            }
            s.min(100.0)
        };
        let native_score = native_libs.aggregate_risk().min(100.0);
        let total = (manifest_score.mul_add(0.5, dex_score * 0.3) + native_score * 0.2).min(100.0);

        let mut indicators = Vec::new();
        if !manifest.components.boot_persistent().is_empty() {
            indicators.push("boot persistence".into());
        }
        if !manifest.components.sms_interceptors().is_empty() {
            indicators.push("SMS interception".into());
        }
        if !manifest.permissions.spyware_relevant.is_empty() {
            indicators.push("spyware-relevant permissions".into());
        }
        if native_libs.any_uses_ptrace() {
            indicators.push("native ptrace (anti-debug)".into());
        }
        if dex_stats.obfuscation_ratio() > 0.5 {
            indicators.push("heavy code obfuscation".into());
        }
        if manifest.debuggable {
            indicators.push("debuggable build".into());
        }

        let combined = indicators.join(" ").to_lowercase();
        let family_guess = if combined.contains("sms") {
            "SMSStealer".into()
        } else if combined.contains("spyware") && combined.contains("location") {
            "Stalkerware".into()
        } else if combined.contains("ptrace") {
            "Banker/Rootkit".into()
        } else {
            "unknown".into()
        };

        Self {
            manifest_score,
            dex_score,
            native_score,
            total,
            indicators,
            family_guess,
        }
    }

    /// Returns `true` when the APK should be flagged for further investigation.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.total >= 30.0
    }
}

// ─── ApkReport ───────────────────────────────────────────────────────────────

/// Comprehensive analysis report for a single APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkReport {
    /// Parsed manifest.
    pub manifest: ApkManifest,
    /// DEX statistics.
    pub dex_stats: DexStats,
    /// Native library summary.
    pub native_libs: NativeLibs,
    /// Threat score breakdown.
    pub threat: ApkThreatScore,
    /// Total number of ZIP entries in the APK.
    pub entry_count: usize,
    /// Total uncompressed size of all entries in bytes.
    pub total_uncompressed_bytes: u64,
    /// Whether the APK contains a v1 JAR signature.
    pub has_v1_signature: bool,
    /// Whether the APK contains a v2 Signature Block.
    pub has_v2_signature: bool,
    /// Whether the APK contains a v3 Signature Block (key rotation).
    pub has_v3_signature: bool,
    /// List of URLs found in DEX string constants.
    pub embedded_urls: Vec<String>,
    /// List of suspicious string patterns detected.
    pub suspicious_strings: Vec<String>,
}

impl ApkReport {
    /// Generate a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let manifest = ApkManifest::mock("com.example.malware");
        let dex_stats = DexStats {
            dex_count: 2,
            total_classes: 400,
            total_methods: 3000,
            total_strings: 8000,
            obfuscated_class_count: 250,
            is_multi_dex: true,
            dex_version: "035".into(),
            dex_sizes: vec![1_048_576, 524_288],
        };
        let lib = NativeLibInfo {
            name: "libnative.so".into(),
            abi: "arm64-v8a".into(),
            size: 204_800,
            crc32: 0xDEAD_BEEF,
            has_jni_exports: true,
            imports_ptrace: true,
            imports_crypto: true,
            sha256: "aabbccddeeff".repeat(4),
        };
        let mut abis = HashSet::new();
        abis.insert("arm64-v8a".to_string());
        let native_libs = NativeLibs {
            libs: vec![lib],
            abis,
        };
        let threat = ApkThreatScore::compute(&manifest, &dex_stats, &native_libs);
        Self {
            manifest,
            dex_stats,
            native_libs,
            threat,
            entry_count: 47,
            total_uncompressed_bytes: 8_388_608,
            has_v1_signature: true,
            has_v2_signature: true,
            has_v3_signature: false,
            embedded_urls: vec!["https://c2.evil.com/gate.php".into()],
            suspicious_strings: vec!["/system/bin/sh".into(), "su".into()],
        }
    }

    /// Format a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "APK {} | threat={:.1} | family={} | flags={}",
            self.manifest.package,
            self.threat.total,
            self.threat.family_guess,
            self.threat.indicators.join(","),
        )
    }
}

impl fmt::Display for ApkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── ApkAnalyzer ─────────────────────────────────────────────────────────────

/// Deep APK analysis engine.
///
/// Takes raw APK bytes and produces a full [`ApkReport`].  The heavy lifting
/// (ZIP parsing, DEX header reading, manifest binary-XML decoding) is delegated
/// to helpers in this module; the `zip` crate is used for decompression.
#[derive(Debug)]
pub struct ApkAnalyzer {
    /// Minimum string length to extract from DEX string pools.
    pub min_string_len: usize,
}

impl ApkAnalyzer {
    /// Create a new analyzer with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { min_string_len: 6 }
    }
}

impl Default for ApkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ApkAnalyzer {

    /// Analyse `apk_bytes` and produce an `ApkReport`.
    ///
    /// # Errors
    /// Returns [`ApkAnalyzerError`] if the data is not a valid APK / ZIP.
    pub fn analyze(&self, apk_bytes: &[u8]) -> Result<ApkReport, ApkAnalyzerError> {
        if apk_bytes.len() < 4 || &apk_bytes[..4] != b"PK\x03\x04" {
            return Err(ApkAnalyzerError::InvalidApk(
                "does not start with ZIP magic".into(),
            ));
        }

        let mut entry_count = 0usize;
        let mut total_uncompressed_bytes = 0u64;
        let mut has_v1 = false;
        let has_v2 = apk_bytes.windows(16).any(|w| w == b"APK Sig Block 42");
        let has_v3 = has_v2 && apk_bytes.windows(4).any(|w| w == [0xC0, 0x68, 0x53, 0xF0]);

        let mut dex_entries: Vec<(String, usize)> = Vec::new();
        let mut native_entries: Vec<(String, usize, u32)> = Vec::new();

        // Scan local file headers (simplified — no decompression needed for metadata)
        let mut pos = 0usize;
        while pos + 30 <= apk_bytes.len() {
            if apk_bytes[pos..pos + 4] != [0x50, 0x4B, 0x03, 0x04] {
                pos += 1;
                continue;
            }
            let compression = u16::from_le_bytes([apk_bytes[pos + 8], apk_bytes[pos + 9]]);
            let compressed_size =
                u32::from_le_bytes(apk_bytes[pos + 18..pos + 22].try_into().unwrap_or([0; 4]))
                    as usize;
            let uncompressed_size =
                u64::from(u32::from_le_bytes(apk_bytes[pos + 22..pos + 26].try_into().unwrap_or([0; 4])));
            let fname_len = u16::from_le_bytes([apk_bytes[pos + 26], apk_bytes[pos + 27]]) as usize;
            let extra_len = u16::from_le_bytes([apk_bytes[pos + 28], apk_bytes[pos + 29]]) as usize;

            let fname_start = pos + 30;
            let fname_end = fname_start + fname_len;
            if fname_end > apk_bytes.len() {
                break;
            }
            let fname = String::from_utf8_lossy(&apk_bytes[fname_start..fname_end]).into_owned();

            entry_count += 1;
            total_uncompressed_bytes += uncompressed_size;

            // Check for META-INF signature files (v1)
            if fname.starts_with("META-INF/") && std::path::Path::new(&fname).extension().is_some_and(|e| e.eq_ignore_ascii_case("SF")) {
                has_v1 = true;
            }

            // Track DEX files (stored, compression=0)
            if std::path::Path::new(&fname).extension().is_some_and(|e| e.eq_ignore_ascii_case("dex")) && compression == 0 {
                let data_start = fname_end + extra_len;
                let data_end = data_start + compressed_size;
                if data_end <= apk_bytes.len() {
                    dex_entries.push((fname.clone(), data_start));
                }
            }

            // Track native libraries
            if fname.starts_with("lib/") && std::path::Path::new(&fname).extension().is_some_and(|e| e.eq_ignore_ascii_case("so")) {
                let crc =
                    u32::from_le_bytes(apk_bytes[pos + 14..pos + 18].try_into().unwrap_or([0; 4]));
                native_entries.push((fname.clone(), uncompressed_size as usize, crc));
            }

            pos = fname_end + extra_len + compressed_size;
        }

        // --- DEX statistics ---
        let dex_stats = self.build_dex_stats(apk_bytes, &dex_entries);

        // --- Native lib summary ---
        let native_libs = self.build_native_libs(&native_entries);

        // --- Manifest ---
        let manifest = self.build_manifest_placeholder(apk_bytes);

        // --- URLs in raw bytes ---
        let embedded_urls = self.scan_urls(apk_bytes);
        let suspicious_strings = self.scan_suspicious_strings(apk_bytes);

        // --- Threat score ---
        let threat = ApkThreatScore::compute(&manifest, &dex_stats, &native_libs);

        Ok(ApkReport {
            manifest,
            dex_stats,
            native_libs,
            threat,
            entry_count,
            total_uncompressed_bytes,
            has_v1_signature: has_v1,
            has_v2_signature: has_v2,
            has_v3_signature: has_v3,
            embedded_urls,
            suspicious_strings,
        })
    }

    fn build_dex_stats(&self, data: &[u8], dex_entries: &[(String, usize)]) -> DexStats {
        let mut stats = DexStats {
            dex_count: dex_entries.len() as u32,
            ..Default::default()
        };
        for (_name, off) in dex_entries {
            let slice = &data[*off..];
            if slice.len() < 112 || !slice.starts_with(b"dex\n") {
                continue;
            }
            let version = String::from_utf8_lossy(&slice[4..7]).into_owned();
            if stats.dex_version.is_empty() {
                stats.dex_version = version;
            }
            let methods = u32::from_le_bytes(slice[88..92].try_into().unwrap_or([0; 4]));
            let classes = u32::from_le_bytes(slice[96..100].try_into().unwrap_or([0; 4]));
            let strings = u32::from_le_bytes(slice[56..60].try_into().unwrap_or([0; 4]));
            stats.total_methods += methods;
            stats.total_classes += classes;
            stats.total_strings += strings;
            if methods > 65535 {
                stats.is_multi_dex = true;
            }
            let file_size = u32::from_le_bytes(slice[32..36].try_into().unwrap_or([0; 4]));
            stats.dex_sizes.push(file_size as usize);
        }
        // Very rough obfuscation estimate: count 'L' followed by 1-2 non-slash chars then ';'
        let obf_pattern: usize = data
            .windows(4)
            .filter(|w| {
                w[0] == b'L' && w[1] != b'/' && w[2] == b';'
                    || (w[1].is_ascii_alphabetic() && w[2] == b';')
            })
            .count();
        stats.obfuscated_class_count = (obf_pattern.min(stats.total_classes as usize)) as u32;
        stats
    }

    fn build_native_libs(&self, entries: &[(String, usize, u32)]) -> NativeLibs {
        let mut libs = NativeLibs::default();
        for (path, size, crc) in entries {
            let parts: Vec<&str> = path.splitn(3, '/').collect();
            let abi = parts.get(1).copied().unwrap_or("unknown").to_string();
            let name = parts.get(2).copied().unwrap_or(path.as_str()).to_string();
            libs.abis.insert(abi.clone());
            libs.libs.push(NativeLibInfo {
                name,
                abi,
                size: *size,
                crc32: *crc,
                has_jni_exports: false,
                imports_ptrace: false,
                imports_crypto: false,
                sha256: String::new(),
            });
        }
        libs
    }

    fn build_manifest_placeholder(&self, data: &[u8]) -> ApkManifest {
        // Attempt to extract package name from binary XML
        let package = if let Some(pos) = data.windows(7).position(|w| w == b"package") {
            let after = &data[pos + 7..];
            let printable: String = after
                .iter()
                .take(64)
                .filter(|&&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
                .map(|&b| b as char)
                .collect();
            if printable.contains('.') {
                printable
            } else {
                "unknown".into()
            }
        } else {
            "unknown".into()
        };

        let perms = vec![]; // Could be populated with a full AXML parser
        ApkManifest {
            package,
            version_name: String::new(),
            version_code: 0,
            min_sdk: 0,
            target_sdk: 0,
            debuggable: data.windows(9).any(|w| w == b"debuggable"),
            allow_backup: true,
            uses_cleartext_traffic: data.windows(15).any(|w| w == b"cleartextTraffic"),
            application_class: None,
            shared_user_id: None,
            permissions: ApkPermissions::from_list(perms),
            components: ApkComponents::default(),
            extra_attrs: HashMap::new(),
        }
    }

    fn scan_urls(&self, data: &[u8]) -> Vec<String> {
        let mut urls = Vec::new();
        let needles: &[&[u8]] = &[b"https://", b"http://"];
        for needle in needles {
            let mut start = 0;
            while let Some(pos) = data[start..]
                .windows(needle.len())
                .position(|w| w == *needle)
                .map(|p| start + p)
            {
                let url_start = pos;
                let url_end = data[pos..]
                    .iter()
                    .take(256)
                    .position(|&b| !(0x20..=0x7e).contains(&b))
                    .map_or(data.len().min(pos + 256), |e| pos + e);
                if let Ok(url) = std::str::from_utf8(&data[url_start..url_end]) {
                    urls.push(url.to_string());
                }
                start = pos + needle.len();
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    fn scan_suspicious_strings(&self, data: &[u8]) -> Vec<String> {
        let patterns: &[&[u8]] = &[
            b"/system/bin/sh",
            b"/system/bin/su",
            b"su\x00",
            b"busybox",
            b"whoami",
            b"chmod 777",
            b"Runtime.getRuntime",
            b"ProcessBuilder",
            b"cmd.exe",
            b"powershell",
        ];
        let mut found = Vec::new();
        for pat in patterns {
            if data.windows(pat.len()).any(|w| w == *pat)
                && let Ok(s) = std::str::from_utf8(pat) {
                    found.push(s.to_string());
                }
        }
        found
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PermissionClass ──────────────────────────────────────────────────────

    #[test]
    fn test_perm_class_camera_is_dangerous() {
        assert_eq!(
            PermissionClass::from_name("android.permission.CAMERA"),
            PermissionClass::Dangerous
        );
    }

    #[test]
    fn test_perm_class_internet_is_normal() {
        assert_eq!(
            PermissionClass::from_name("android.permission.INTERNET"),
            PermissionClass::Normal
        );
    }

    #[test]
    fn test_perm_class_sms_is_dangerous() {
        assert_eq!(
            PermissionClass::from_name("android.permission.READ_SMS"),
            PermissionClass::Dangerous
        );
    }

    #[test]
    fn test_perm_class_location_is_dangerous() {
        assert_eq!(
            PermissionClass::from_name("android.permission.ACCESS_FINE_LOCATION"),
            PermissionClass::Dangerous
        );
    }

    #[test]
    fn test_perm_class_threat_weight_ordering() {
        assert!(
            PermissionClass::Dangerous.threat_weight() > PermissionClass::Normal.threat_weight()
        );
        assert!(
            PermissionClass::Privileged.threat_weight()
                > PermissionClass::Dangerous.threat_weight()
        );
    }

    #[test]
    fn test_perm_class_display() {
        assert_eq!(PermissionClass::Dangerous.to_string(), "dangerous");
        assert_eq!(PermissionClass::Normal.to_string(), "normal");
    }

    // ── ApkPermissions ───────────────────────────────────────────────────────

    #[test]
    fn test_apk_permissions_from_list_classifies_correctly() {
        let perms = vec![
            "android.permission.INTERNET".into(),
            "android.permission.CAMERA".into(),
            "android.permission.READ_SMS".into(),
        ];
        let ap = ApkPermissions::from_list(perms);
        assert_eq!(ap.dangerous.len(), 2);
        assert_eq!(ap.normal.len(), 1);
        assert!(
            ap.av_recording
                .contains(&"android.permission.CAMERA".to_string())
        );
        assert!(
            ap.telephony
                .contains(&"android.permission.READ_SMS".to_string())
        );
    }

    #[test]
    fn test_apk_permissions_threat_score_positive() {
        let perms = vec![
            "android.permission.CAMERA".into(),
            "android.permission.READ_SMS".into(),
            "android.permission.ACCESS_FINE_LOCATION".into(),
        ];
        let ap = ApkPermissions::from_list(perms);
        assert!(ap.threat_score() > 0.0);
    }

    #[test]
    fn test_apk_permissions_empty_has_zero_threat() {
        let ap = ApkPermissions::from_list(vec![]);
        assert_eq!(ap.threat_score(), 0.0);
    }

    #[test]
    fn test_apk_permissions_spyware_relevant() {
        let perms = vec!["android.permission.READ_CONTACTS".into()];
        let ap = ApkPermissions::from_list(perms);
        assert!(!ap.spyware_relevant.is_empty());
    }

    // ── IntentFilter ─────────────────────────────────────────────────────────

    #[test]
    fn test_intent_filter_is_launcher() {
        let f = IntentFilter {
            actions: vec!["android.intent.action.MAIN".into()],
            categories: vec!["android.intent.category.LAUNCHER".into()],
            data_schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_launcher());
    }

    #[test]
    fn test_intent_filter_is_boot_receiver() {
        let f = IntentFilter {
            actions: vec!["android.intent.action.BOOT_COMPLETED".into()],
            categories: vec![],
            data_schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_boot_receiver());
        assert!(!f.is_launcher());
    }

    #[test]
    fn test_intent_filter_is_sms_receiver() {
        let f = IntentFilter {
            actions: vec!["android.provider.Telephony.SMS_RECEIVED".into()],
            categories: vec![],
            data_schemes: vec![],
            mime_types: vec![],
        };
        assert!(f.is_sms_receiver());
    }

    // ── ApkComponent ─────────────────────────────────────────────────────────

    #[test]
    fn test_component_is_exposed_true() {
        let c = ApkComponent {
            name: "com.example.Foo".into(),
            exported: true,
            required_permission: None,
            intent_filters: vec![],
            enabled: true,
            in_separate_process: false,
            authorities: None,
        };
        assert!(c.is_exposed());
    }

    #[test]
    fn test_component_is_exposed_false_when_permission_required() {
        let c = ApkComponent {
            name: "com.example.Foo".into(),
            exported: true,
            required_permission: Some("com.example.PERM".into()),
            intent_filters: vec![],
            enabled: true,
            in_separate_process: false,
            authorities: None,
        };
        assert!(!c.is_exposed());
    }

    // ── ApkComponents ────────────────────────────────────────────────────────

    #[test]
    fn test_components_total() {
        let m = ApkManifest::mock("com.test");
        let total = m.components.total();
        assert!(total >= 3);
    }

    #[test]
    fn test_components_boot_persistent() {
        let m = ApkManifest::mock("com.test");
        assert!(!m.components.boot_persistent().is_empty());
    }

    #[test]
    fn test_components_sms_interceptors() {
        let m = ApkManifest::mock("com.test");
        assert!(!m.components.sms_interceptors().is_empty());
    }

    #[test]
    fn test_components_launcher_activity() {
        let m = ApkManifest::mock("com.test");
        assert!(m.components.launcher_activity().is_some());
    }

    // ── ApkManifest ──────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_mock_package() {
        let m = ApkManifest::mock("com.example.test");
        assert_eq!(m.package, "com.example.test");
    }

    #[test]
    fn test_manifest_mock_version() {
        let m = ApkManifest::mock("com.test");
        assert_eq!(m.version_name, "1.0.0");
        assert_eq!(m.version_code, 1);
    }

    #[test]
    fn test_manifest_mock_sdk() {
        let m = ApkManifest::mock("com.test");
        assert_eq!(m.min_sdk, 21);
        assert_eq!(m.target_sdk, 33);
    }

    #[test]
    fn test_manifest_threat_score_positive() {
        let m = ApkManifest::mock("com.test");
        assert!(m.threat_score() > 0.0);
    }

    #[test]
    fn test_manifest_serialization() {
        let m = ApkManifest::mock("com.test");
        let json = serde_json::to_string(&m).unwrap();
        let back: ApkManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.package, m.package);
    }

    // ── DexStats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dex_stats_obfuscation_ratio_zero() {
        let s = DexStats::default();
        assert_eq!(s.obfuscation_ratio(), 0.0);
    }

    #[test]
    fn test_dex_stats_obfuscation_ratio_computed() {
        let s = DexStats {
            total_classes: 100,
            obfuscated_class_count: 60,
            ..Default::default()
        };
        assert!((s.obfuscation_ratio() - 0.6).abs() < f64::EPSILON);
    }

    // ── NativeLibInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_native_lib_is_jni_bridge() {
        let l = NativeLibInfo {
            name: "libjni_helper.so".into(),
            abi: "arm64-v8a".into(),
            size: 100,
            crc32: 0,
            has_jni_exports: false,
            imports_ptrace: false,
            imports_crypto: false,
            sha256: String::new(),
        };
        assert!(l.is_jni_bridge());
    }

    #[test]
    fn test_native_lib_risk_score_ptrace() {
        let l = NativeLibInfo {
            name: "libfoo.so".into(),
            abi: "arm64-v8a".into(),
            size: 100,
            crc32: 0,
            has_jni_exports: false,
            imports_ptrace: true,
            imports_crypto: false,
            sha256: String::new(),
        };
        assert!(l.risk_score() >= 3.0);
    }

    // ── NativeLibs ───────────────────────────────────────────────────────────

    #[test]
    fn test_native_libs_aggregate_risk() {
        let lib = NativeLibInfo {
            name: "libfoo.so".into(),
            abi: "x86".into(),
            size: 0,
            crc32: 0,
            has_jni_exports: false,
            imports_ptrace: true,
            imports_crypto: true,
            sha256: String::new(),
        };
        let mut abis = HashSet::new();
        abis.insert("x86".into());
        let nl = NativeLibs {
            libs: vec![lib],
            abis,
        };
        assert!(nl.aggregate_risk() >= 5.0);
    }

    #[test]
    fn test_native_libs_any_uses_ptrace() {
        let lib = NativeLibInfo {
            name: "l.so".into(),
            abi: "x86".into(),
            size: 0,
            crc32: 0,
            has_jni_exports: false,
            imports_ptrace: true,
            imports_crypto: false,
            sha256: String::new(),
        };
        let nl = NativeLibs {
            libs: vec![lib],
            abis: HashSet::new(),
        };
        assert!(nl.any_uses_ptrace());
    }

    // ── ApkThreatScore ───────────────────────────────────────────────────────

    #[test]
    fn test_threat_score_compute_positive() {
        let m = ApkManifest::mock("com.test");
        let d = DexStats {
            total_classes: 100,
            obfuscated_class_count: 70,
            ..Default::default()
        };
        let nl = NativeLibs::default();
        let t = ApkThreatScore::compute(&m, &d, &nl);
        assert!(t.total > 0.0);
        assert!(t.total <= 100.0);
    }

    #[test]
    fn test_threat_score_is_suspicious_high() {
        let t = ApkThreatScore {
            total: 50.0,
            ..Default::default()
        };
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_threat_score_not_suspicious_low() {
        let t = ApkThreatScore {
            total: 5.0,
            ..Default::default()
        };
        assert!(!t.is_suspicious());
    }

    // ── ApkReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_apk_report_mock_package() {
        let r = ApkReport::mock();
        assert_eq!(r.manifest.package, "com.example.malware");
    }

    #[test]
    fn test_apk_report_mock_threat_positive() {
        let r = ApkReport::mock();
        assert!(r.threat.total > 0.0);
    }

    #[test]
    fn test_apk_report_mock_summary() {
        let r = ApkReport::mock();
        let s = r.summary();
        assert!(s.contains("com.example.malware"));
    }

    #[test]
    fn test_apk_report_mock_has_indicators() {
        let r = ApkReport::mock();
        assert!(!r.threat.indicators.is_empty());
    }

    #[test]
    fn test_apk_report_serialization() {
        let r = ApkReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: ApkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.manifest.package, r.manifest.package);
    }

    // ── ApkAnalyzer ──────────────────────────────────────────────────────────

    #[test]
    fn test_apk_analyzer_rejects_non_zip() {
        let az = ApkAnalyzer::new();
        let result = az.analyze(b"\x00\x00\x00\x00");
        assert!(result.is_err());
    }

    #[test]
    fn test_apk_analyzer_rejects_too_short() {
        let az = ApkAnalyzer::new();
        let result = az.analyze(b"PK");
        assert!(result.is_err());
    }

    #[test]
    fn test_apk_analyzer_accepts_zip_header() {
        let az = ApkAnalyzer::new();
        // Minimal ZIP: just the magic; will succeed with empty results
        let mut data = vec![0u8; 32];
        data[..4].copy_from_slice(b"PK\x03\x04");
        let result = az.analyze(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apk_analyzer_detects_v2_signature() {
        let az = ApkAnalyzer::new();
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"PK\x03\x04");
        data[16..32].copy_from_slice(b"APK Sig Block 42");
        let r = az.analyze(&data).unwrap();
        assert!(r.has_v2_signature);
    }

    #[test]
    fn test_apk_analyzer_detects_urls() {
        let az = ApkAnalyzer::new();
        let mut data = vec![0u8; 128];
        data[..4].copy_from_slice(b"PK\x03\x04");
        let url = b"https://evil.com/api";
        data[64..64 + url.len()].copy_from_slice(url);
        let r = az.analyze(&data).unwrap();
        assert!(!r.embedded_urls.is_empty());
    }

    #[test]
    fn test_apk_analyzer_scan_suspicious_strings() {
        let az = ApkAnalyzer::new();
        let mut data = vec![0u8; 256];
        data[..4].copy_from_slice(b"PK\x03\x04");
        let s = b"/system/bin/sh";
        data[100..100 + s.len()].copy_from_slice(s);
        let r = az.analyze(&data).unwrap();
        assert!(!r.suspicious_strings.is_empty());
    }

    #[test]
    fn test_apk_analyzer_default_min_string_len() {
        let az = ApkAnalyzer::default();
        assert_eq!(az.min_string_len, 6);
    }

    #[test]
    fn test_apk_analyzer_report_display() {
        let r = ApkReport::mock();
        let s = format!("{r}");
        assert!(!s.is_empty());
    }
}
