//! DEX file analyzer: class/method/field stats, permission inference,
//! sensitive API detection, obfuscation scoring, call graph edges,
//! crypto usage detection, and reflection pattern analysis.

use std::collections::{HashMap, HashSet};
use std::fmt;

#[inline]
const fn usize_to_f32_lossy(x: usize) -> f32 {
    // Deliberate boundary: counts comfortably under 2^23 in practice.
    x as f32
}

// ── Sensitive API database ────────────────────────────────────────────────────

/// A sensitive API call pattern.
#[derive(Debug, Clone)]
pub struct SensitiveApi {
    pub class: &'static str,
    pub method: &'static str,
    pub category: ApiCategory,
    pub risk: RiskLevel,
    pub description: &'static str,
}

/// Category of a sensitive API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiCategory {
    Location,
    Telephony,
    Network,
    Crypto,
    Reflection,
    DynLoad,
    Storage,
    Camera,
    Microphone,
    Clipboard,
    DeviceId,
    RootDetect,
    AntiDebug,
    NativeCode,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Risk level for a detected API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

fn sensitive_apis() -> Vec<SensitiveApi> {
    vec![
        SensitiveApi { class: "android/telephony/TelephonyManager", method: "getDeviceId", category: ApiCategory::DeviceId, risk: RiskLevel::High, description: "Read IMEI" },
        SensitiveApi { class: "android/telephony/TelephonyManager", method: "getSubscriberId", category: ApiCategory::Telephony, risk: RiskLevel::High, description: "Read IMSI" },
        SensitiveApi { class: "android/telephony/SmsManager", method: "sendTextMessage", category: ApiCategory::Telephony, risk: RiskLevel::Critical, description: "Send SMS" },
        SensitiveApi { class: "android/location/LocationManager", method: "getLastKnownLocation", category: ApiCategory::Location, risk: RiskLevel::High, description: "Get location" },
        SensitiveApi { class: "android/net/Uri", method: "parse", category: ApiCategory::Network, risk: RiskLevel::Low, description: "Parse URI" },
        SensitiveApi { class: "java/net/URL", method: "openConnection", category: ApiCategory::Network, risk: RiskLevel::Medium, description: "HTTP connection" },
        SensitiveApi { class: "javax/crypto/Cipher", method: "getInstance", category: ApiCategory::Crypto, risk: RiskLevel::Medium, description: "Cipher init" },
        SensitiveApi { class: "java/lang/reflect/Method", method: "invoke", category: ApiCategory::Reflection, risk: RiskLevel::High, description: "Reflection invoke" },
        SensitiveApi { class: "java/lang/Class", method: "forName", category: ApiCategory::Reflection, risk: RiskLevel::High, description: "Dynamic class load" },
        SensitiveApi { class: "dalvik/system/DexClassLoader", method: "<init>", category: ApiCategory::DynLoad, risk: RiskLevel::Critical, description: "Load external DEX" },
        SensitiveApi { class: "dalvik/system/PathClassLoader", method: "<init>", category: ApiCategory::DynLoad, risk: RiskLevel::High, description: "Load path class" },
        SensitiveApi { class: "android/content/ClipboardManager", method: "getText", category: ApiCategory::Clipboard, risk: RiskLevel::Medium, description: "Read clipboard" },
        SensitiveApi { class: "android/hardware/Camera", method: "open", category: ApiCategory::Camera, risk: RiskLevel::High, description: "Open camera" },
        SensitiveApi { class: "android/media/MediaRecorder", method: "setAudioSource", category: ApiCategory::Microphone, risk: RiskLevel::Critical, description: "Record audio" },
        SensitiveApi { class: "java/lang/Runtime", method: "exec", category: ApiCategory::NativeCode, risk: RiskLevel::Critical, description: "Execute shell command" },
        SensitiveApi { class: "android/content/pm/PackageManager", method: "getInstalledPackages", category: ApiCategory::DeviceId, risk: RiskLevel::Medium, description: "Enumerate packages" },
        SensitiveApi { class: "android/os/Build", method: "getSerial", category: ApiCategory::DeviceId, risk: RiskLevel::Medium, description: "Read device serial" },
        SensitiveApi { class: "android/provider/Settings$Secure", method: "getString", category: ApiCategory::DeviceId, risk: RiskLevel::Medium, description: "Read Android ID" },
        SensitiveApi { class: "android/app/admin/DevicePolicyManager", method: "resetPassword", category: ApiCategory::DeviceId, risk: RiskLevel::Critical, description: "Reset device password" },
        SensitiveApi { class: "android/telephony/TelephonyManager", method: "getCallState", category: ApiCategory::Telephony, risk: RiskLevel::High, description: "Read call state" },
    ]
}

// ── ObfuscationIndicator ──────────────────────────────────────────────────────

/// Indicator of code obfuscation.
#[derive(Debug, Clone)]
pub struct ObfuscationIndicator {
    pub kind: ObfuscationKind,
    pub evidence: String,
    pub score: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationKind {
    ShortNames,
    HighMethodCount,
    StringEncryption,
    ControlFlowObfuscation,
    ReflectionHeavy,
    DynamicLoading,
    AntiAnalysis,
}

impl fmt::Display for ObfuscationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── CallEdge / CallGraph ──────────────────────────────────────────────────────

/// A directed call edge: caller -> callee.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    pub caller_class: String,
    pub caller_method: String,
    pub callee_class: String,
    pub callee_method: String,
    pub line: u32,
}

impl fmt::Display for CallEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{} -> {}.{}",
            self.caller_class, self.caller_method,
            self.callee_class, self.callee_method)
    }
}

// ── DexClassInfo ──────────────────────────────────────────────────────────────

/// Summary of a parsed DEX class.
#[derive(Debug, Clone)]
pub struct DexClassInfo {
    pub class_name: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
    pub method_count: usize,
    pub field_count: usize,
    pub is_abstract: bool,
    pub is_interface: bool,
    pub is_synthetic: bool,
    pub access_flags: u32,
}

impl DexClassInfo {
    /// Returns `true` if this looks like a ProGuard-obfuscated class name.
    #[must_use] 
    pub fn is_obfuscated_name(&self) -> bool {
        let simple = self.class_name.rsplit('/').next().unwrap_or(&self.class_name);
        let name = simple.trim_end_matches(';');
        name.len() <= 2 && name.chars().all(|c| c.is_ascii_alphabetic())
    }

    /// Returns `true` if this is a public class.
    #[must_use] 
    pub const fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }
}

// ── PermissionInference ───────────────────────────────────────────────────────

/// A permission inferred from API usage.
#[derive(Debug, Clone)]
pub struct InferredPermission {
    pub permission: String,
    pub reason: String,
    pub confidence: f32,
}

fn api_to_permission_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("android/telephony/TelephonyManager.getDeviceId", "android.permission.READ_PHONE_STATE");
    m.insert("android/telephony/SmsManager.sendTextMessage", "android.permission.SEND_SMS");
    m.insert("android/location/LocationManager.getLastKnownLocation", "android.permission.ACCESS_FINE_LOCATION");
    m.insert("android/hardware/Camera.open", "android.permission.CAMERA");
    m.insert("android/media/MediaRecorder.setAudioSource", "android.permission.RECORD_AUDIO");
    m.insert("android/content/ClipboardManager.getText", "android.permission.READ_CLIPBOARD");
    m.insert("android/net/wifi/WifiManager.getConnectionInfo", "android.permission.ACCESS_WIFI_STATE");
    m.insert("android/bluetooth/BluetoothAdapter.getDefaultAdapter", "android.permission.BLUETOOTH");
    m
}

// ── DexAnalysisReport ─────────────────────────────────────────────────────────

/// Full analysis report for a DEX file or set of DEX files.
#[derive(Debug, Clone)]
pub struct DexAnalysisReport {
    pub class_count: usize,
    pub method_count: usize,
    pub field_count: usize,
    pub string_count: usize,
    pub sensitive_api_hits: Vec<SensitiveApiHit>,
    pub obfuscation_indicators: Vec<ObfuscationIndicator>,
    pub obfuscation_score: u32,
    pub inferred_permissions: Vec<InferredPermission>,
    pub call_edges: Vec<CallEdge>,
    pub crypto_usages: Vec<CryptoUsage>,
    pub classes: Vec<DexClassInfo>,
    pub risk_level: RiskLevel,
}

/// A concrete hit of a sensitive API.
#[derive(Debug, Clone)]
pub struct SensitiveApiHit {
    pub api: SensitiveApi,
    pub caller_class: String,
    pub caller_method: String,
    pub count: usize,
}

/// A cryptographic primitive usage.
#[derive(Debug, Clone)]
pub struct CryptoUsage {
    pub algorithm: String,
    pub context: String,
    pub is_weak: bool,
}

impl DexAnalysisReport {
    /// Overall risk level based on critical/high hits.
    #[must_use] 
    pub fn compute_risk(&self) -> RiskLevel {
        let critical = self.sensitive_api_hits.iter()
            .filter(|h| h.api.risk == RiskLevel::Critical).count();
        let high = self.sensitive_api_hits.iter()
            .filter(|h| h.api.risk == RiskLevel::High).count();
        // A single Critical-rated sensitive API is enough to escalate the report to Critical.
        if critical >= 1 { RiskLevel::Critical }
        else if high >= 3 { RiskLevel::High }
        else if high >= 1 { RiskLevel::Medium }
        else { RiskLevel::Low }
    }
}

// ── DexAnalyzer ───────────────────────────────────────────────────────────────

/// Analyzes DEX content for sensitive APIs, obfuscation, and permissions.
pub struct DexAnalyzer {
    sensitive_apis: Vec<SensitiveApi>,
    perm_map: HashMap<&'static str, &'static str>,
    _weak_crypto: HashSet<&'static str>,
}

impl DexAnalyzer {
    /// Create a new analyzer with all built-in databases loaded.
    #[must_use] 
    pub fn new() -> Self {
        let mut weak_crypto = HashSet::new();
        for alg in &["DES", "DES/ECB", "MD5", "RC4", "RC2", "Blowfish/ECB", "AES/ECB"] {
            weak_crypto.insert(*alg);
        }
        Self {
            sensitive_apis: sensitive_apis(),
            perm_map: api_to_permission_map(),
            _weak_crypto: weak_crypto,
        }
    }

    /// Analyze a list of class infos and call edges to produce a full report.
    #[must_use] 
    pub fn analyze(
        &self,
        classes: Vec<DexClassInfo>,
        call_edges: Vec<CallEdge>,
        strings: &[String],
    ) -> DexAnalysisReport {
        let method_count: usize = classes.iter().map(|c| c.method_count).sum();
        let field_count: usize = classes.iter().map(|c| c.field_count).sum();
        let class_count = classes.len();
        let string_count = strings.len();

        let sensitive_hits = self.find_sensitive_api_hits(&call_edges);
        let inferred_perms = self.infer_permissions(&sensitive_hits);
        let obfusc = Self::detect_obfuscation(&classes, strings, &call_edges, method_count);
        let obfusc_score: u32 = obfusc.iter().map(|o| o.score).sum();
        let crypto = Self::detect_crypto_usage(&call_edges, strings);

        let mut report = DexAnalysisReport {
            class_count,
            method_count,
            field_count,
            string_count,
            sensitive_api_hits: sensitive_hits,
            obfuscation_indicators: obfusc,
            obfuscation_score: obfusc_score,
            inferred_permissions: inferred_perms,
            call_edges,
            crypto_usages: crypto,
            classes,
            risk_level: RiskLevel::Low,
        };
        report.risk_level = report.compute_risk();
        report
    }

    fn find_sensitive_api_hits(&self, edges: &[CallEdge]) -> Vec<SensitiveApiHit> {
        let mut hits: HashMap<String, SensitiveApiHit> = HashMap::new();
        for edge in edges {
            for api in &self.sensitive_apis {
                if edge.callee_class.contains(api.class) && edge.callee_method.contains(api.method) {
                    let key = format!("{}.{}", api.class, api.method);
                    let hit = hits.entry(key).or_insert_with(|| SensitiveApiHit {
                        api: api.clone(),
                        caller_class: edge.caller_class.clone(),
                        caller_method: edge.caller_method.clone(),
                        count: 0,
                    });
                    hit.count += 1;
                }
            }
        }
        hits.into_values().collect()
    }

    fn infer_permissions(&self, hits: &[SensitiveApiHit]) -> Vec<InferredPermission> {
        let mut perms = Vec::new();
        let mut seen = HashSet::new();
        for hit in hits {
            let key = format!("{}.{}", hit.api.class, hit.api.method);
            if let Some(&perm) = self.perm_map.get(key.as_str())
                && seen.insert(perm) {
                    perms.push(InferredPermission {
                        permission: perm.to_string(),
                        reason: format!("usage of {}", hit.api.method),
                        confidence: 0.85,
                    });
                }
        }
        perms
    }

    fn detect_obfuscation(
        classes: &[DexClassInfo],
        strings: &[String],
        edges: &[CallEdge],
        method_count: usize,
    ) -> Vec<ObfuscationIndicator> {
        let mut indicators = Vec::new();

        let short_count = classes.iter().filter(|c| c.is_obfuscated_name()).count();
        if !classes.is_empty() && usize_to_f32_lossy(short_count) / usize_to_f32_lossy(classes.len()) > 0.4 {
            indicators.push(ObfuscationIndicator {
                kind: ObfuscationKind::ShortNames,
                evidence: format!("{short_count}/{} classes have short names", classes.len()),
                score: 30,
            });
        }

        if !classes.is_empty() && method_count / classes.len() > 20 {
            indicators.push(ObfuscationIndicator {
                kind: ObfuscationKind::HighMethodCount,
                evidence: format!("{method_count} methods across {} classes", classes.len()),
                score: 15,
            });
        }

        let enc_strings = strings.iter().filter(|s| {
            s.len() > 4 && s.chars().filter(|c| !c.is_ascii_graphic()).count() > s.len() / 3
        }).count();
        if enc_strings > 5 {
            indicators.push(ObfuscationIndicator {
                kind: ObfuscationKind::StringEncryption,
                evidence: format!("{enc_strings} suspicious encrypted strings"),
                score: 25,
            });
        }

        let refl_edges = edges.iter().filter(|e| {
            e.callee_class.contains("java/lang/reflect") || e.callee_class.contains("Class")
        }).count();
        if refl_edges > 3 {
            indicators.push(ObfuscationIndicator {
                kind: ObfuscationKind::ReflectionHeavy,
                evidence: format!("{refl_edges} reflection call edges"),
                score: 20,
            });
        }

        let dyn_edges = edges.iter().filter(|e| {
            e.callee_class.contains("ClassLoader") || e.callee_class.contains("DexClass")
        }).count();
        if dyn_edges > 0 {
            indicators.push(ObfuscationIndicator {
                kind: ObfuscationKind::DynamicLoading,
                evidence: format!("{dyn_edges} dynamic class loading edges"),
                score: 35,
            });
        }

        indicators
    }

    fn detect_crypto_usage(edges: &[CallEdge], strings: &[String]) -> Vec<CryptoUsage> {
        let mut usages = Vec::new();
        for edge in edges {
            if edge.callee_class.contains("javax/crypto/Cipher") {
                usages.push(CryptoUsage {
                    algorithm: "Cipher".to_string(),
                    context: edge.caller_method.clone(),
                    is_weak: false,
                });
            }
            if edge.callee_class.contains("MessageDigest") {
                usages.push(CryptoUsage {
                    algorithm: "MessageDigest".to_string(),
                    context: edge.caller_method.clone(),
                    is_weak: false,
                });
            }
        }
        for s in strings {
            let upper = s.to_ascii_uppercase();
            for weak in &["DES", "MD5", "RC4", "AES/ECB"] {
                if upper.contains(weak) {
                    usages.push(CryptoUsage {
                        algorithm: weak.to_string(),
                        context: format!("string literal: {}", &s[..s.len().min(40)]),
                        is_weak: true,
                    });
                }
            }
        }
        usages
    }

    /// Scan a list of strings for embedded URLs, IPs, and C2 patterns.
    #[must_use] 
    pub fn scan_strings_for_iocs(&self, strings: &[String]) -> Vec<String> {
        let mut iocs = Vec::new();
        for s in strings {
            if s.starts_with("http://") || s.starts_with("https://") {
                iocs.push(format!("URL: {s}"));
            } else if looks_like_ip(s) {
                iocs.push(format!("IP: {s}"));
            } else if s.contains(".onion") {
                iocs.push(format!("Tor: {s}"));
            } else if looks_like_base64(s) {
                iocs.push(format!("Base64: {}", &s[..s.len().min(40)]));
            }
        }
        iocs
    }
}

impl Default for DexAnalyzer {
    fn default() -> Self { Self::new() }
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_base64(s: &str) -> bool {
    s.len() >= 16
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && s.ends_with('=')
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_class(name: &str, methods: usize) -> DexClassInfo {
        DexClassInfo {
            class_name: name.to_string(),
            superclass: "java/lang/Object".to_string(),
            interfaces: vec![],
            method_count: methods,
            field_count: 2,
            is_abstract: false,
            is_interface: false,
            is_synthetic: false,
            access_flags: 0x0001,
        }
    }

    #[test]
    fn test_obfuscated_name_detection() {
        let c = make_class("a", 5);
        assert!(c.is_obfuscated_name());
        let c2 = make_class("com/example/MyActivity", 5);
        assert!(!c2.is_obfuscated_name());
    }

    #[test]
    fn test_analyzer_no_edges() {
        let analyzer = DexAnalyzer::new();
        let classes = vec![make_class("com/example/Main", 10)];
        let report = analyzer.analyze(classes, vec![], &[]);
        assert_eq!(report.class_count, 1);
        assert!(report.sensitive_api_hits.is_empty());
    }

    #[test]
    fn test_sensitive_api_sms() {
        let analyzer = DexAnalyzer::new();
        let edge = CallEdge {
            caller_class: "com/evil/Malware".to_string(),
            caller_method: "run".to_string(),
            callee_class: "android/telephony/SmsManager".to_string(),
            callee_method: "sendTextMessage".to_string(),
            line: 42,
        };
        let classes = vec![make_class("com/evil/Malware", 5)];
        let report = analyzer.analyze(classes, vec![edge], &[]);
        assert!(!report.sensitive_api_hits.is_empty());
        assert_eq!(report.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_crypto_usage_from_string() {
        let analyzer = DexAnalyzer::new();
        let classes = vec![make_class("Foo", 1)];
        let strings = vec!["AES/ECB/PKCS5Padding".to_string()];
        let report = analyzer.analyze(classes, vec![], &strings);
        assert!(report.crypto_usages.iter().any(|c| c.is_weak));
    }

    #[test]
    fn test_ioc_url_detection() {
        let analyzer = DexAnalyzer::new();
        let strings = vec![
            "https://evil.example.com/payload".to_string(),
            "hello world".to_string(),
        ];
        let iocs = analyzer.scan_strings_for_iocs(&strings);
        assert!(iocs.iter().any(|i| i.contains("URL:")));
    }

    #[test]
    fn test_ioc_ip_detection() {
        let analyzer = DexAnalyzer::new();
        let strings = vec!["192.168.1.1".to_string()];
        let iocs = analyzer.scan_strings_for_iocs(&strings);
        assert!(iocs.iter().any(|i| i.contains("IP:")));
    }

    #[test]
    fn test_obfuscation_short_names() {
        let analyzer = DexAnalyzer::new();
        let classes: Vec<_> = (0..20).map(|i| {
            if i < 15 { make_class("a", 3) } else { make_class("com/example/Real", 3) }
        }).collect();
        let report = analyzer.analyze(classes, vec![], &[]);
        assert!(report.obfuscation_indicators.iter().any(|o| o.kind == ObfuscationKind::ShortNames));
    }

    #[test]
    fn test_infer_permissions() {
        let analyzer = DexAnalyzer::new();
        let edge = CallEdge {
            caller_class: "Foo".to_string(),
            caller_method: "bar".to_string(),
            callee_class: "android/telephony/SmsManager".to_string(),
            callee_method: "sendTextMessage".to_string(),
            line: 1,
        };
        let report = analyzer.analyze(vec![make_class("Foo", 1)], vec![edge], &[]);
        assert!(report.inferred_permissions.iter().any(|p| p.permission.contains("SEND_SMS")));
    }

    #[test]
    fn test_reflection_obfuscation() {
        let analyzer = DexAnalyzer::new();
        let edges: Vec<CallEdge> = (0i32..5).map(|i| CallEdge {
            caller_class: "com/Foo".to_string(),
            caller_method: "m".to_string(),
            callee_class: "java/lang/reflect/Method".to_string(),
            callee_method: "invoke".to_string(),
            line: i.cast_unsigned(),
        }).collect();
        let report = analyzer.analyze(vec![make_class("com/Foo", 5)], edges, &[]);
        assert!(report.obfuscation_indicators.iter().any(|o| o.kind == ObfuscationKind::ReflectionHeavy));
    }

    #[test]
    fn test_dynamic_loading_detection() {
        let analyzer = DexAnalyzer::new();
        let edge = CallEdge {
            caller_class: "com/Foo".to_string(),
            caller_method: "load".to_string(),
            callee_class: "dalvik/system/DexClassLoader".to_string(),
            callee_method: "<init>".to_string(),
            line: 1,
        };
        let report = analyzer.analyze(vec![make_class("com/Foo", 2)], vec![edge], &[]);
        assert!(report.obfuscation_indicators.iter().any(|o| o.kind == ObfuscationKind::DynamicLoading));
    }

    #[test]
    fn test_risk_level_low() {
        let analyzer = DexAnalyzer::new();
        let report = analyzer.analyze(vec![make_class("Foo", 1)], vec![], &[]);
        assert_eq!(report.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_call_edge_display() {
        let edge = CallEdge {
            caller_class: "Foo".to_string(),
            caller_method: "run".to_string(),
            callee_class: "Bar".to_string(),
            callee_method: "doIt".to_string(),
            line: 0,
        };
        assert!(edge.to_string().contains("->"));
    }

    #[test]
    fn test_api_category_display() {
        assert_eq!(ApiCategory::Telephony.to_string(), "Telephony");
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("SGVsbG8gV29ybGQ="));
        assert!(!looks_like_base64("hello"));
    }

    #[test]
    fn test_looks_like_ip_false() {
        assert!(!looks_like_ip("hello.world"));
        assert!(!looks_like_ip("256.0.0.1"));
    }
}
