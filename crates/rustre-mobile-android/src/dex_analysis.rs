//! DEX static analysis — call graph, permission mapping, string extraction,
//! and obfuscation detection on top of the existing DEX loader types.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{DexClass, StringEntry};

// ---------------------------------------------------------------------------
// DexMethod
// ---------------------------------------------------------------------------

/// A method within a DEX class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMethod {
    /// Fully-qualified class descriptor.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Method descriptor.
    pub descriptor: String,
    /// Access flags (public/static/native/…).
    pub access_flags: u32,
    /// Called method references (callee set).
    pub callees: Vec<DexMethodRef>,
}

impl DexMethod {
    /// Create a minimal method.
    #[must_use]
    pub fn new(class: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            class: class.into(),
            name: name.into(),
            descriptor: "()V".to_string(),
            access_flags: 0x0001,
            callees: Vec::new(),
        }
    }

    /// Return `true` if this is a native method.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        self.access_flags & 0x0100 != 0
    }

    /// Return `true` if this is a static method.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Return the fully-qualified name.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}::{}", self.class, self.name)
    }
}

// ---------------------------------------------------------------------------
// DexMethodRef
// ---------------------------------------------------------------------------

/// A reference to a called method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DexMethodRef {
    /// Target class descriptor.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Method descriptor.
    pub descriptor: String,
}

impl DexMethodRef {
    /// Create a method reference.
    #[must_use]
    pub fn new(
        class: impl Into<String>,
        name: impl Into<String>,
        descriptor: impl Into<String>,
    ) -> Self {
        Self {
            class: class.into(),
            name: name.into(),
            descriptor: descriptor.into(),
        }
    }

    /// Return the qualified name.
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}::{}", self.class, self.name)
    }
}

// ---------------------------------------------------------------------------
// DexCallGraph
// ---------------------------------------------------------------------------

/// Call graph built from DEX method call references.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DexCallGraph {
    /// caller qualified name → set of callee qualified names.
    pub edges: HashMap<String, HashSet<String>>,
}

impl DexCallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directed call edge.
    pub fn add_edge(&mut self, caller: impl Into<String>, callee: impl Into<String>) {
        self.edges
            .entry(caller.into())
            .or_default()
            .insert(callee.into());
    }

    /// Return all callees for a given method.
    #[must_use]
    pub fn callees_of(&self, method: &str) -> Vec<&str> {
        self.edges
            .get(method)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Return all callers of a given method (reverse lookup).
    #[must_use]
    pub fn callers_of(&self, method: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|(_, callees)| callees.iter().any(|c| c == method))
            .map(|(caller, _)| caller.as_str())
            .collect()
    }

    /// Return the total number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges
            .values()
            .map(std::collections::HashSet::len)
            .sum()
    }

    /// Build a call graph from a list of DEX methods.
    #[must_use]
    pub fn from_methods(methods: &[DexMethod]) -> Self {
        let mut cg = Self::new();
        for m in methods {
            for callee in &m.callees {
                cg.add_edge(m.qualified_name(), callee.qualified());
            }
        }
        cg
    }
}

// ---------------------------------------------------------------------------
// Permission mapping — API calls → Android permissions
// ---------------------------------------------------------------------------

/// Maps Android API call patterns to required permissions.
pub struct DexPermissionMapper {
    /// API call pattern (substring match) → required permissions.
    rules: Vec<(String, Vec<String>)>,
}

impl DexPermissionMapper {
    /// Create a mapper populated with well-known Android API/permission pairs.
    #[must_use]
    pub fn new() -> Self {
        let rules: Vec<(&str, &[&str])> = vec![
            (
                "android/telephony/TelephonyManager;->getDeviceId",
                &["android.permission.READ_PHONE_STATE"],
            ),
            (
                "android/telephony/TelephonyManager;->getSubscriberId",
                &["android.permission.READ_PHONE_STATE"],
            ),
            (
                "android/telephony/SmsManager;->sendTextMessage",
                &["android.permission.SEND_SMS"],
            ),
            (
                "android/telephony/SmsManager;->sendMultipartTextMessage",
                &["android.permission.SEND_SMS"],
            ),
            (
                "android/provider/ContactsContract",
                &["android.permission.READ_CONTACTS"],
            ),
            (
                "android/location/LocationManager;->requestLocationUpdates",
                &[
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION",
                ],
            ),
            (
                "android/location/LocationManager;->getLastKnownLocation",
                &[
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION",
                ],
            ),
            (
                "android/hardware/Camera;->open",
                &["android.permission.CAMERA"],
            ),
            (
                "android/media/MediaRecorder;->setAudioSource",
                &["android.permission.RECORD_AUDIO"],
            ),
            (
                "android/media/AudioRecord",
                &["android.permission.RECORD_AUDIO"],
            ),
            (
                "android/net/wifi/WifiManager;->getScanResults",
                &["android.permission.ACCESS_WIFI_STATE"],
            ),
            (
                "android/bluetooth/BluetoothAdapter;->getBondedDevices",
                &["android.permission.BLUETOOTH"],
            ),
            (
                "android/provider/CallLog",
                &["android.permission.READ_CALL_LOG"],
            ),
            (
                "android/provider/Telephony",
                &["android.permission.READ_SMS"],
            ),
            (
                "android/accounts/AccountManager;->getAccounts",
                &["android.permission.GET_ACCOUNTS"],
            ),
            (
                "java/net/HttpURLConnection;->connect",
                &["android.permission.INTERNET"],
            ),
            (
                "java/net/URL;->openConnection",
                &["android.permission.INTERNET"],
            ),
            (
                "android/content/ContentResolver;->query",
                &["android.permission.READ_CONTACTS"],
            ),
            (
                "android/os/Environment;->getExternalStorageDirectory",
                &["android.permission.READ_EXTERNAL_STORAGE"],
            ),
            (
                "android/net/NetworkInfo",
                &["android.permission.ACCESS_NETWORK_STATE"],
            ),
        ];
        Self {
            rules: rules
                .into_iter()
                .map(|(pat, perms)| {
                    (
                        pat.to_string(),
                        perms.iter().map(std::string::ToString::to_string).collect(),
                    )
                })
                .collect(),
        }
    }

    /// Return all permissions required by the given set of API call strings.
    #[must_use]
    pub fn required_permissions(&self, api_calls: &[String]) -> HashSet<String> {
        let mut perms: HashSet<String> = HashSet::new();
        for api in api_calls {
            for (pattern, required) in &self.rules {
                if api.contains(pattern.as_str()) {
                    perms.extend(required.iter().cloned());
                }
            }
        }
        perms
    }

    /// Return `true` if any API call requires the given permission.
    #[must_use]
    pub fn requires_permission(&self, api_calls: &[String], permission: &str) -> bool {
        self.required_permissions(api_calls).contains(permission)
    }
}

impl Default for DexPermissionMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DexStringExtractor
// ---------------------------------------------------------------------------

/// Extracts and categorises string literals from DEX constant pools.
pub struct DexStringExtractor;

impl DexStringExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Extract all strings from a list of `StringEntry` records,
    /// applying heuristic categorisation.
    #[must_use]
    pub fn extract_categorised(strings: &[StringEntry]) -> HashMap<String, Vec<String>> {
        let mut categories: HashMap<String, Vec<String>> = HashMap::new();

        for entry in strings {
            let v = &entry.value;

            let cat = if entry.is_url() {
                "url"
            } else if entry.is_ip_address() {
                "ip"
            } else if entry.is_suspicious_command() {
                "suspicious_command"
            } else if entry.is_base64_like() {
                "base64"
            } else if v.len() >= 32 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                "hash"
            } else if v.contains('@') && v.contains('.') {
                "email"
            } else if v.starts_with("-----BEGIN") || v.starts_with("MII") {
                "certificate"
            } else if v.len() > 4 {
                "other"
            } else {
                continue;
            };

            categories
                .entry(cat.to_string())
                .or_default()
                .push(v.clone());
        }
        categories
    }

    /// Return all strings that look like potential C2 indicators.
    #[must_use]
    pub fn find_c2_indicators(strings: &[StringEntry]) -> Vec<&StringEntry> {
        strings
            .iter()
            .filter(|s| s.is_url() || s.is_ip_address())
            .collect()
    }

    /// Return all strings that contain encryption-related keywords.
    #[must_use]
    pub fn find_crypto_strings(strings: &[StringEntry]) -> Vec<&StringEntry> {
        strings
            .iter()
            .filter(|s| {
                const NEEDLES: &[&str] = &[
                    "aes", "rsa", "des", "encrypt", "decrypt", "cipher", "base64",
                ];
                let bytes = s.value.as_bytes();
                NEEDLES.iter().any(|needle| {
                    let n = needle.as_bytes();
                    bytes.len() >= n.len()
                        && bytes
                            .windows(n.len())
                            .any(|w| w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
                })
            })
            .collect()
    }
}

impl Default for DexStringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ObfuscationIndicator
// ---------------------------------------------------------------------------

/// A single obfuscation indicator found in a DEX file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationIndicator {
    /// Indicator type.
    pub kind: String,
    /// Brief description.
    pub description: String,
    /// Severity [1, 10].
    pub severity: u8,
}

// ---------------------------------------------------------------------------
// DexObfuscationDetector
// ---------------------------------------------------------------------------

/// Detects obfuscation patterns in DEX classes.
pub struct DexObfuscationDetector;

impl DexObfuscationDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse a slice of `DexClass` records for obfuscation patterns.
    /// Returns a list of indicators and an overall confidence score [0.0, 1.0].
    #[must_use]
    pub fn detect(classes: &[DexClass]) -> (Vec<ObfuscationIndicator>, f64) {
        let mut indicators: Vec<ObfuscationIndicator> = Vec::new();

        if classes.is_empty() {
            return (indicators, 0.0);
        }

        // Obfuscated class name ratio.
        let obfuscated_count = classes.iter().filter(|c| c.is_obfuscated()).count();
        let ratio = obfuscated_count as f64 / classes.len() as f64;
        if ratio > 0.2 {
            indicators.push(ObfuscationIndicator {
                kind: "obfuscated_names".to_string(),
                description: format!(
                    "{:.0}% of classes have single/double-char names",
                    ratio * 100.0
                ),
                severity: ((ratio * 10.0) as u8).min(10),
            });
        }

        // Classes with no source file attribute.
        let no_source = classes.iter().filter(|c| c.source_file.is_none()).count();
        let no_source_ratio = no_source as f64 / classes.len() as f64;
        if no_source_ratio > 0.5 {
            indicators.push(ObfuscationIndicator {
                kind: "missing_source_files".to_string(),
                description: format!(
                    "{:.0}% of classes have no source file",
                    no_source_ratio * 100.0
                ),
                severity: 4,
            });
        }

        // Very high method density.
        let avg_methods: f64 = classes
            .iter()
            .map(|c| f64::from(c.method_count))
            .sum::<f64>()
            / classes.len() as f64;
        if avg_methods > 30.0 {
            indicators.push(ObfuscationIndicator {
                kind: "high_method_density".to_string(),
                description: format!("Average {avg_methods:.0} methods per class"),
                severity: 3,
            });
        }

        // Classes implementing many interfaces (obfuscation via interface explosion).
        let multi_iface = classes.iter().filter(|c| c.interfaces.len() >= 3).count();
        if multi_iface > classes.len() / 4 {
            indicators.push(ObfuscationIndicator {
                kind: "interface_explosion".to_string(),
                description: format!("{multi_iface} classes implement ≥3 interfaces"),
                severity: 3,
            });
        }

        // Compute overall confidence.
        let score: f64 = indicators
            .iter()
            .map(|i| f64::from(i.severity))
            .sum::<f64>()
            / (indicators.len().max(1) as f64 * 10.0);
        let confidence = (score + ratio / 2.0).min(1.0);

        (indicators, confidence)
    }

    /// Return `true` if the obfuscation confidence exceeds a threshold.
    #[must_use]
    pub fn is_obfuscated(classes: &[DexClass], threshold: f64) -> bool {
        let (_, conf) = Self::detect(classes);
        conf >= threshold
    }
}

impl Default for DexObfuscationDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DexAnalyzer
// ---------------------------------------------------------------------------

/// High-level DEX static analyser that combines all sub-analysers.
pub struct DexAnalyzer {
    permission_mapper: DexPermissionMapper,
}

impl DexAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            permission_mapper: DexPermissionMapper::new(),
        }
    }

    /// Build a call graph from a list of methods.
    #[must_use]
    pub fn build_call_graph(&self, methods: &[DexMethod]) -> DexCallGraph {
        DexCallGraph::from_methods(methods)
    }

    /// Map API calls to required permissions.
    #[must_use]
    pub fn map_permissions(&self, api_calls: &[String]) -> HashSet<String> {
        self.permission_mapper.required_permissions(api_calls)
    }

    /// Detect obfuscation in a list of DEX classes.
    #[must_use]
    pub fn detect_obfuscation(&self, classes: &[DexClass]) -> (Vec<ObfuscationIndicator>, f64) {
        DexObfuscationDetector::detect(classes)
    }

    /// Extract categorised string literals.
    #[must_use]
    pub fn extract_strings(&self, strings: &[StringEntry]) -> HashMap<String, Vec<String>> {
        DexStringExtractor::extract_categorised(strings)
    }

    /// Produce a full analysis report for a set of DEX classes, methods, and strings.
    #[must_use]
    pub fn analyze(
        &self,
        classes: &[DexClass],
        methods: &[DexMethod],
        strings: &[StringEntry],
        api_calls: &[String],
    ) -> DexAnalysisReport {
        let call_graph = self.build_call_graph(methods);
        let required_permissions = self.map_permissions(api_calls);
        let string_categories = self.extract_strings(strings);
        let (obfuscation_indicators, obfuscation_confidence) = self.detect_obfuscation(classes);
        let c2_indicators = DexStringExtractor::find_c2_indicators(strings);
        let crypto_strings = DexStringExtractor::find_crypto_strings(strings);

        let obfuscated_class_count = classes.iter().filter(|c| c.is_obfuscated()).count();

        DexAnalysisReport {
            class_count: classes.len(),
            method_count: methods.len(),
            obfuscated_class_count,
            call_graph,
            required_permissions: required_permissions.into_iter().collect(),
            string_categories,
            obfuscation_indicators,
            obfuscation_confidence,
            c2_indicator_count: c2_indicators.len(),
            crypto_string_count: crypto_strings.len(),
        }
    }
}

impl Default for DexAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DexAnalysisReport
// ---------------------------------------------------------------------------

/// Full DEX analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexAnalysisReport {
    pub class_count: usize,
    pub method_count: usize,
    pub obfuscated_class_count: usize,
    pub call_graph: DexCallGraph,
    pub required_permissions: Vec<String>,
    pub string_categories: HashMap<String, Vec<String>>,
    pub obfuscation_indicators: Vec<ObfuscationIndicator>,
    pub obfuscation_confidence: f64,
    pub c2_indicator_count: usize,
    pub crypto_string_count: usize,
}

impl DexAnalysisReport {
    /// Return `true` if the DEX is likely obfuscated (confidence ≥ 0.4).
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.obfuscation_confidence >= 0.4
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DexClass, StringEntry};

    fn make_class(descriptor: &str, simple_name: &str, source: Option<&str>) -> DexClass {
        DexClass {
            descriptor: descriptor.to_string(),
            simple_name: simple_name.to_string(),
            superclass: None,
            interfaces: vec![],
            access_flags: 0x0001,
            source_file: source.map(str::to_string),
            method_count: 5,
            field_count: 2,
        }
    }

    fn obf_class(n: u32) -> DexClass {
        DexClass {
            descriptor: format!("La/b{n};"),
            simple_name: "b".to_string(),
            superclass: None,
            interfaces: vec![],
            access_flags: 0x0001,
            source_file: None,
            method_count: 10,
            field_count: 2,
        }
    }

    // ---- DexMethod ----

    #[test]
    fn test_dex_method_new() {
        let m = DexMethod::new("Lcom/example/Foo;", "bar");
        assert!(!m.is_native());
        assert!(!m.is_static());
    }

    #[test]
    fn test_dex_method_native_flag() {
        let mut m = DexMethod::new("Lcom/example/Foo;", "native_func");
        m.access_flags = 0x0101; // public + native
        assert!(m.is_native());
    }

    #[test]
    fn test_dex_method_static_flag() {
        let mut m = DexMethod::new("Lcom/example/Foo;", "static_func");
        m.access_flags = 0x0009; // public + static
        assert!(m.is_static());
    }

    #[test]
    fn test_dex_method_qualified_name() {
        let m = DexMethod::new("Lcom/example/Foo;", "bar");
        assert_eq!(m.qualified_name(), "Lcom/example/Foo;::bar");
    }

    // ---- DexCallGraph ----

    #[test]
    fn test_call_graph_add_edge() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("Foo::bar", "Baz::qux");
        assert!(cg.callees_of("Foo::bar").contains(&"Baz::qux"));
    }

    #[test]
    fn test_call_graph_callers_of() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("A::foo", "B::bar");
        cg.add_edge("C::baz", "B::bar");
        let callers = cg.callers_of("B::bar");
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_call_graph_edge_count() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("A", "B");
        cg.add_edge("A", "C");
        cg.add_edge("D", "E");
        assert_eq!(cg.edge_count(), 3);
    }

    #[test]
    fn test_call_graph_from_methods() {
        let mut m = DexMethod::new("LA;", "foo");
        m.callees.push(DexMethodRef::new("LB;", "bar", "()V"));
        let cg = DexCallGraph::from_methods(&[m]);
        assert_eq!(cg.edge_count(), 1);
    }

    #[test]
    fn test_call_graph_empty_callees() {
        let cg = DexCallGraph::new();
        assert!(cg.callees_of("nonexistent").is_empty());
    }

    // ---- DexPermissionMapper ----

    #[test]
    fn test_mapper_read_phone_state() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/telephony/TelephonyManager;->getDeviceId".to_string()];
        let perms = m.required_permissions(&apis);
        assert!(perms.contains("android.permission.READ_PHONE_STATE"));
    }

    #[test]
    fn test_mapper_send_sms() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/telephony/SmsManager;->sendTextMessage".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.SEND_SMS"));
    }

    #[test]
    fn test_mapper_internet() {
        let m = DexPermissionMapper::new();
        let apis = vec!["java/net/HttpURLConnection;->connect".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.INTERNET"));
    }

    #[test]
    fn test_mapper_no_match() {
        let m = DexPermissionMapper::new();
        let apis = vec!["java/util/ArrayList;->add".to_string()];
        assert!(m.required_permissions(&apis).is_empty());
    }

    #[test]
    fn test_mapper_multiple_apis() {
        let m = DexPermissionMapper::new();
        let apis = vec![
            "android/telephony/SmsManager;->sendTextMessage".to_string(),
            "android/location/LocationManager;->requestLocationUpdates".to_string(),
        ];
        let perms = m.required_permissions(&apis);
        assert!(perms.contains("android.permission.SEND_SMS"));
        assert!(perms.contains("android.permission.ACCESS_FINE_LOCATION"));
    }

    // ---- DexStringExtractor ----

    #[test]
    fn test_extract_url_category() {
        let strings = vec![StringEntry {
            value: "https://evil.com/gate".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("url"));
    }

    #[test]
    fn test_extract_ip_category() {
        let strings = vec![StringEntry {
            value: "192.168.1.1".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("ip"));
    }

    #[test]
    fn test_find_c2_indicators() {
        let strings = vec![
            StringEntry {
                value: "https://c2.example.com".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "192.0.2.1".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "normal string".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        let c2 = DexStringExtractor::find_c2_indicators(&strings);
        assert_eq!(c2.len(), 2);
    }

    #[test]
    fn test_find_crypto_strings() {
        let strings = vec![
            StringEntry {
                value: "AES/CBC/PKCS5Padding".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "unrelated".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        let crypto = DexStringExtractor::find_crypto_strings(&strings);
        assert_eq!(crypto.len(), 1);
    }

    // ---- DexObfuscationDetector ----

    #[test]
    fn test_detect_no_obfuscation() {
        let classes = vec![
            make_class(
                "Lcom/example/MainActivity;",
                "MainActivity",
                Some("MainActivity.java"),
            ),
            make_class(
                "Lcom/example/LoginActivity;",
                "LoginActivity",
                Some("LoginActivity.java"),
            ),
        ];
        let (indicators, conf) = DexObfuscationDetector::detect(&classes);
        assert!(conf < 0.5, "expected low confidence, got {conf}");
        let _ = indicators;
    }

    #[test]
    fn test_detect_obfuscated_classes() {
        let mut classes: Vec<DexClass> = (0..20).map(obf_class).collect();
        classes.push(make_class("Lcom/example/Main;", "Main", Some("Main.java")));
        let (_, conf) = DexObfuscationDetector::detect(&classes);
        assert!(conf > 0.0);
    }

    #[test]
    fn test_is_obfuscated_threshold() {
        let classes: Vec<DexClass> = (0..30).map(obf_class).collect();
        assert!(DexObfuscationDetector::is_obfuscated(&classes, 0.0));
    }

    #[test]
    fn test_detect_empty_classes() {
        let (_, conf) = DexObfuscationDetector::detect(&[]);
        assert_eq!(conf, 0.0);
    }

    // ---- DexAnalyzer ----

    #[test]
    fn test_analyzer_analyze_empty() {
        let az = DexAnalyzer::new();
        let report = az.analyze(&[], &[], &[], &[]);
        assert_eq!(report.class_count, 0);
        assert_eq!(report.method_count, 0);
    }

    #[test]
    fn test_analyzer_analyze_with_data() {
        let az = DexAnalyzer::new();
        let classes = vec![make_class("Lcom/example/Foo;", "Foo", Some("Foo.java"))];
        let strings = vec![StringEntry {
            value: "https://evil.com".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let api_calls = vec!["android/telephony/SmsManager;->sendTextMessage".to_string()];
        let report = az.analyze(&classes, &[], &strings, &api_calls);
        assert_eq!(report.class_count, 1);
        assert!(
            report
                .required_permissions
                .contains(&"android.permission.SEND_SMS".to_string())
        );
        assert_eq!(report.c2_indicator_count, 1);
    }

    #[test]
    fn test_analysis_report_is_obfuscated_false() {
        let az = DexAnalyzer::new();
        let classes = vec![make_class("Lcom/example/Foo;", "Foo", Some("Foo.java"))];
        let report = az.analyze(&classes, &[], &[], &[]);
        assert!(!report.is_obfuscated());
    }

    // ---- DexMethodRef ----

    #[test]
    fn test_method_ref_qualified() {
        let r = DexMethodRef::new("LFoo;", "bar", "()V");
        assert_eq!(r.qualified(), "LFoo;::bar");
    }

    // ---- Serde roundtrips ----

    #[test]
    fn test_dex_method_serde() {
        let m = DexMethod::new("Lcom/example/Foo;", "init");
        let json = serde_json::to_string(&m).unwrap();
        let m2: DexMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.class, "Lcom/example/Foo;");
        assert_eq!(m2.name, "init");
    }

    #[test]
    fn test_dex_method_ref_serde() {
        let r = DexMethodRef::new("LBar;", "process", "(I)V");
        let json = serde_json::to_string(&r).unwrap();
        let r2: DexMethodRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.descriptor, "(I)V");
    }

    #[test]
    fn test_call_graph_serde() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("A::foo", "B::bar");
        let json = serde_json::to_string(&cg).unwrap();
        let cg2: DexCallGraph = serde_json::from_str(&json).unwrap();
        assert!(cg2.callees_of("A::foo").contains(&"B::bar"));
    }

    #[test]
    fn test_analysis_report_serde() {
        let az = DexAnalyzer::new();
        let report = az.analyze(&[], &[], &[], &[]);
        let json = serde_json::to_string(&report).unwrap();
        let r2: DexAnalysisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.class_count, 0);
    }

    #[test]
    fn test_obfuscation_indicator_serde() {
        let ind = ObfuscationIndicator {
            kind: "obfuscated_names".to_string(),
            description: "50% obfuscated".to_string(),
            severity: 5,
        };
        let json = serde_json::to_string(&ind).unwrap();
        let ind2: ObfuscationIndicator = serde_json::from_str(&json).unwrap();
        assert_eq!(ind2.severity, 5);
    }

    // ---- DexCallGraph callers_of with no callers ----

    #[test]
    fn test_callers_of_no_callers() {
        let cg = DexCallGraph::new();
        assert!(cg.callers_of("A::foo").is_empty());
    }

    // ---- DexCallGraph deduplication of edges ----

    #[test]
    fn test_call_graph_no_duplicate_edges() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("A::foo", "B::bar");
        cg.add_edge("A::foo", "B::bar"); // duplicate
        assert_eq!(cg.edge_count(), 1);
    }

    // ---- Permission mapper for camera ----

    #[test]
    fn test_mapper_camera_permission() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/hardware/Camera;->open".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.CAMERA"));
    }

    // ---- Permission mapper for record audio ----

    #[test]
    fn test_mapper_record_audio() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/media/MediaRecorder;->setAudioSource".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.RECORD_AUDIO"));
    }

    // ---- Permission mapper for location ----

    #[test]
    fn test_mapper_location() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/location/LocationManager;->getLastKnownLocation".to_string()];
        let perms = m.required_permissions(&apis);
        assert!(perms.contains("android.permission.ACCESS_FINE_LOCATION"));
    }

    // ---- String extractor base64 ----

    #[test]
    fn test_extract_base64_category() {
        // A 48-char base64-like string ending with '='.
        let val = "SGVsbG9Xb3JsZA==".repeat(3); // len=48, ends with '='
        let strings = vec![StringEntry {
            value: val,
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(
            cats.contains_key("base64"),
            "expected base64 category, got: {:?}",
            cats.keys().collect::<Vec<_>>()
        );
    }

    // ---- String extractor command ----

    #[test]
    fn test_extract_suspicious_command() {
        let strings = vec![StringEntry {
            value: "exec('/system/bin/sh -c id')".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("suspicious_command"));
    }

    // ---- ObfuscationDetector missing source file indicator ----

    #[test]
    fn test_detect_missing_source_indicator() {
        // More than 50% have no source file.
        let classes: Vec<DexClass> = (0..10)
            .map(|i| {
                make_class(
                    &format!("Lcom/example/Class{i};"),
                    &format!("Class{i}"),
                    None,
                )
            })
            .collect();
        let (indicators, _) = DexObfuscationDetector::detect(&classes);
        let has_missing = indicators
            .iter()
            .any(|ind| ind.kind == "missing_source_files");
        assert!(has_missing);
    }

    // ---- Analyzer map_permissions returns sorted vec ----

    #[test]
    fn test_analyzer_map_permissions_multiple() {
        let az = DexAnalyzer::new();
        let apis = vec![
            "android/telephony/SmsManager;->sendTextMessage".to_string(),
            "android/media/MediaRecorder;->setAudioSource".to_string(),
        ];
        let perms = az.map_permissions(&apis);
        assert!(perms.contains("android.permission.SEND_SMS"));
        assert!(perms.contains("android.permission.RECORD_AUDIO"));
    }

    // ---- DexMethod callees ----

    #[test]
    fn test_dex_method_callees() {
        let mut m = DexMethod::new("LA;", "foo");
        m.callees.push(DexMethodRef::new("LB;", "bar", "()V"));
        m.callees.push(DexMethodRef::new("LC;", "baz", "(I)V"));
        assert_eq!(m.callees.len(), 2);
    }

    // ---- call graph from multiple methods ----

    #[test]
    fn test_call_graph_from_multiple_methods() {
        let mut m1 = DexMethod::new("LA;", "foo");
        m1.callees.push(DexMethodRef::new("LB;", "bar", "()V"));

        let mut m2 = DexMethod::new("LB;", "bar");
        m2.callees.push(DexMethodRef::new("LC;", "qux", "()Z"));

        let cg = DexCallGraph::from_methods(&[m1, m2]);
        assert_eq!(cg.edge_count(), 2);
        assert!(cg.callers_of("LB;::bar").contains(&"LA;::foo"));
        assert!(cg.callers_of("LC;::qux").contains(&"LB;::bar"));
    }

    // ---- DexAnalysisReport.is_obfuscated threshold ----

    #[test]
    fn test_analysis_report_obfuscated_highly_obfuscated_classes() {
        let az = DexAnalyzer::new();
        let classes: Vec<DexClass> = (0..30)
            .map(|i| make_class(&format!("La/b{i};"), "b", None))
            .collect();
        let report = az.analyze(&classes, &[], &[], &[]);
        assert!(report.is_obfuscated());
    }

    // ---- DexStringExtractor hash category ----

    #[test]
    fn test_extract_hash_category() {
        let strings = vec![StringEntry {
            value: "a".repeat(64), // 64 hex chars = SHA-256
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("hash"));
    }

    // ---- DexStringExtractor email category ----

    #[test]
    fn test_extract_email_category() {
        let strings = vec![StringEntry {
            value: "attacker@evil.com".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("email"));
    }

    // ---- DexStringExtractor certificate ----

    #[test]
    fn test_extract_certificate_category() {
        let strings = vec![StringEntry {
            value: "-----BEGIN CERTIFICATE-----\nMIIBxx".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("certificate"));
    }

    // ---- DexStringExtractor very short strings skipped ----

    #[test]
    fn test_short_string_not_categorised() {
        let strings = vec![StringEntry {
            value: "ab".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.is_empty());
    }

    // ---- find_c2_indicators empty input ----

    #[test]
    fn test_find_c2_empty() {
        assert!(DexStringExtractor::find_c2_indicators(&[]).is_empty());
    }

    // ---- find_crypto_strings multiple hits ----

    #[test]
    fn test_find_crypto_multiple() {
        let strings = vec![
            StringEntry {
                value: "AES/CBC/PKCS5Padding".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "RSA/ECB/OAEPWithSHA-256".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "sha256withRSA".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "regular string".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        let crypto = DexStringExtractor::find_crypto_strings(&strings);
        assert_eq!(crypto.len(), 3);
    }

    // ---- DexMethod access_flags combinations ----

    #[test]
    fn test_dex_method_public_static_native() {
        let mut m = DexMethod::new("LA;", "jniMethod");
        m.access_flags = 0x0001 | 0x0008 | 0x0100; // public + static + native
        assert!(m.is_native());
        assert!(m.is_static());
    }

    // ---- DexCallGraph multiple callers ----

    #[test]
    fn test_call_graph_three_callers() {
        let mut cg = DexCallGraph::new();
        cg.add_edge("A::foo", "C::target");
        cg.add_edge("B::bar", "C::target");
        cg.add_edge("D::baz", "C::target");
        let callers = cg.callers_of("C::target");
        assert_eq!(callers.len(), 3);
    }

    // ---- DexPermissionMapper contacts api ----

    #[test]
    fn test_mapper_read_contacts() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/provider/ContactsContract;->query".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.READ_CONTACTS"));
    }

    // ---- DexPermissionMapper wifi ----

    #[test]
    fn test_mapper_wifi() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/net/wifi/WifiManager;->getScanResults".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.ACCESS_WIFI_STATE"));
    }

    // ---- DexPermissionMapper bluetooth ----

    #[test]
    fn test_mapper_bluetooth() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/bluetooth/BluetoothAdapter;->getBondedDevices".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.BLUETOOTH"));
    }

    // ---- DexPermissionMapper accounts ----

    #[test]
    fn test_mapper_get_accounts() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/accounts/AccountManager;->getAccounts".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.GET_ACCOUNTS"));
    }

    // ---- Obfuscation high method density ----

    #[test]
    fn test_detect_high_method_density() {
        let classes: Vec<DexClass> = (0..5)
            .map(|i| {
                let mut c = make_class(
                    &format!("Lcom/example/Big{i};"),
                    &format!("Big{i}"),
                    Some("X.java"),
                );
                c.method_count = 50;
                c
            })
            .collect();
        let (indicators, _) = DexObfuscationDetector::detect(&classes);
        assert!(
            indicators
                .iter()
                .any(|ind| ind.kind == "high_method_density")
        );
    }

    // ---- DexAnalyzer build_call_graph convenience ----

    #[test]
    fn test_analyzer_build_call_graph_convenience() {
        let az = DexAnalyzer::new();
        let mut m = DexMethod::new("LA;", "foo");
        m.callees.push(DexMethodRef::new("LB;", "bar", "()V"));
        let cg = az.build_call_graph(&[m]);
        assert_eq!(cg.edge_count(), 1);
    }

    // ---- DexAnalysisReport crypto_string_count ----

    #[test]
    fn test_report_crypto_string_count() {
        let az = DexAnalyzer::new();
        let strings = vec![StringEntry {
            value: "AES/CBC/PKCS5Padding".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let report = az.analyze(&[], &[], &strings, &[]);
        assert_eq!(report.crypto_string_count, 1);
    }

    // ---- DexAnalysisReport c2_indicator_count ----

    #[test]
    fn test_report_c2_indicator_count() {
        let az = DexAnalyzer::new();
        let strings = vec![
            StringEntry {
                value: "http://evil.com".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "192.0.2.100".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        let report = az.analyze(&[], &[], &strings, &[]);
        assert_eq!(report.c2_indicator_count, 2);
    }

    // ---- DexPermissionMapper call_log ----

    #[test]
    fn test_mapper_read_call_log() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/provider/CallLog;->query".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.READ_CALL_LOG"));
    }

    // ---- DexPermissionMapper read_sms ----

    #[test]
    fn test_mapper_read_sms() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/provider/Telephony;->query".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.READ_SMS"));
    }

    // ---- DexPermissionMapper network_state ----

    #[test]
    fn test_mapper_network_state() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/net/NetworkInfo;->isConnected".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.ACCESS_NETWORK_STATE"));
    }

    // ---- DexPermissionMapper external_storage ----

    #[test]
    fn test_mapper_external_storage() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/os/Environment;->getExternalStorageDirectory".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.READ_EXTERNAL_STORAGE"));
    }

    // ---- DexPermissionMapper url_open_connection ----

    #[test]
    fn test_mapper_url_open_connection() {
        let m = DexPermissionMapper::new();
        let apis = vec!["java/net/URL;->openConnection".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.INTERNET"));
    }

    // ---- DexCallGraph empty edge_count ----

    #[test]
    fn test_call_graph_empty_edge_count() {
        assert_eq!(DexCallGraph::new().edge_count(), 0);
    }

    // ---- DexMethod without callees ----

    #[test]
    fn test_dex_method_no_callees() {
        let m = DexMethod::new("Lcom/example/Foo;", "noOp");
        let cg = DexCallGraph::from_methods(&[m]);
        assert_eq!(cg.edge_count(), 0);
    }

    // ---- DexStringExtractor mii prefix cert ----

    #[test]
    fn test_extract_mii_certificate() {
        let strings = vec![StringEntry {
            value: "MIIBvzCCAWWgAwIBAgIJAMxxxxxx".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let cats = DexStringExtractor::extract_categorised(&strings);
        assert!(cats.contains_key("certificate"));
    }

    // ---- DexAnalyzer extract_strings returns categories ----

    #[test]
    fn test_analyzer_extract_strings_categories() {
        let az = DexAnalyzer::new();
        let strings = vec![
            StringEntry {
                value: "https://c2.evil.com".to_string(),
                from_dex: true,
                from_resources: false,
            },
            StringEntry {
                value: "192.168.100.1".to_string(),
                from_dex: true,
                from_resources: false,
            },
        ];
        let cats = az.extract_strings(&strings);
        assert!(cats.contains_key("url"));
        assert!(cats.contains_key("ip"));
    }

    // ---- DexObfuscationDetector interface_explosion ----

    #[test]
    fn test_detect_interface_explosion() {
        let classes: Vec<DexClass> = (0..10)
            .map(|i| DexClass {
                descriptor: format!("Lcom/example/Iface{i};"),
                simple_name: format!("Iface{i}"),
                superclass: None,
                interfaces: vec![
                    "Ljava/io/Serializable;".to_string(),
                    "Ljava/lang/Runnable;".to_string(),
                    "Ljava/lang/Cloneable;".to_string(),
                ],
                access_flags: 0x0201,
                source_file: Some(format!("Iface{i}.java")),
                method_count: 5,
                field_count: 1,
            })
            .collect();
        let (indicators, _) = DexObfuscationDetector::detect(&classes);
        assert!(indicators.iter().any(|i| i.kind == "interface_explosion"));
    }

    // ---- DexAnalysisReport method_count ----

    #[test]
    fn test_analysis_report_method_count() {
        let az = DexAnalyzer::new();
        let methods = vec![
            DexMethod::new("LA;", "foo"),
            DexMethod::new("LB;", "bar"),
            DexMethod::new("LC;", "baz"),
        ];
        let report = az.analyze(&[], &methods, &[], &[]);
        assert_eq!(report.method_count, 3);
    }

    // ---- DexAnalysisReport obfuscated_class_count ----

    #[test]
    fn test_analysis_report_obfuscated_class_count() {
        let az = DexAnalyzer::new();
        let classes: Vec<DexClass> = (0..5).map(obf_class).collect();
        let report = az.analyze(&classes, &[], &[], &[]);
        assert_eq!(report.obfuscated_class_count, 5);
    }

    // ---- DexAnalysisReport with all data points ----

    #[test]
    fn test_full_analysis_report() {
        let az = DexAnalyzer::new();
        let classes = vec![
            make_class("Lcom/example/Main;", "Main", Some("Main.java")),
            make_class("La/b;", "b", None),
            make_class("La/c;", "c", None),
        ];
        let mut m1 = DexMethod::new("Lcom/example/Main;", "onStart");
        m1.callees.push(DexMethodRef::new(
            "Landroid/net/NetworkInfo;",
            "isConnected",
            "()Z",
        ));
        let strings = vec![StringEntry {
            value: "http://c2.example.com/check".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        let api_calls = vec!["android/net/NetworkInfo;->isConnected".to_string()];

        let report = az.analyze(&classes, &[m1], &strings, &api_calls);
        assert_eq!(report.class_count, 3);
        assert_eq!(report.method_count, 1);
        assert!(report.c2_indicator_count >= 1);
        assert!(
            report
                .required_permissions
                .contains(&"android.permission.ACCESS_NETWORK_STATE".to_string())
        );
    }

    // ---- DexPermissionMapper audio_record via AudioRecord ----

    #[test]
    fn test_mapper_audio_record_class() {
        let m = DexPermissionMapper::new();
        let apis = vec!["android/media/AudioRecord;->startRecording".to_string()];
        assert!(m.requires_permission(&apis, "android.permission.RECORD_AUDIO"));
    }

    // ---- DexCallGraph from_methods multiple methods different classes ----

    #[test]
    fn test_call_graph_from_methods_different_classes() {
        let mut m1 = DexMethod::new("LActivityA;", "onCreate");
        m1.callees
            .push(DexMethodRef::new("LHelperB;", "init", "()V"));
        let mut m2 = DexMethod::new("LHelperB;", "init");
        m2.callees.push(DexMethodRef::new(
            "Landroid/telephony/TelephonyManager;",
            "getDeviceId",
            "()Ljava/lang/String;",
        ));
        let cg = DexCallGraph::from_methods(&[m1, m2]);
        assert_eq!(cg.edge_count(), 2);
        let callers = cg.callers_of("LHelperB;::init");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], "LActivityA;::onCreate");
    }

    // ---- DexStringExtractor from_resources string ----

    #[test]
    fn test_extract_resource_string() {
        let strings = vec![StringEntry {
            value: "https://resource.example.com".to_string(),
            from_dex: false,
            from_resources: true,
        }];
        let c2 = DexStringExtractor::find_c2_indicators(&strings);
        assert_eq!(c2.len(), 1);
        assert!(!c2[0].from_dex);
        assert!(c2[0].from_resources);
    }

    // ---- DexAnalysisReport is_obfuscated low confidence ----

    #[test]
    fn test_report_not_obfuscated_clean_classes() {
        let az = DexAnalyzer::new();
        let classes = vec![
            make_class("Lcom/example/Main;", "Main", Some("Main.java")),
            make_class("Lcom/example/Util;", "Util", Some("Util.java")),
        ];
        let report = az.analyze(&classes, &[], &[], &[]);
        assert!(!report.is_obfuscated());
    }

    // ---- DexAnalyzer default ----

    #[test]
    fn test_analyzer_default() {
        let az = DexAnalyzer::default();
        let report = az.analyze(&[], &[], &[], &[]);
        assert_eq!(report.class_count, 0);
    }

    // ---- ObfuscationIndicator severity range ----

    #[test]
    fn test_obfuscation_indicator_severity_range() {
        let classes: Vec<DexClass> = (0..20).map(obf_class).collect();
        let (indicators, _) = DexObfuscationDetector::detect(&classes);
        for ind in &indicators {
            assert!(ind.severity <= 10, "severity {} exceeds 10", ind.severity);
        }
    }

    // ---- DexPermissionMapper default creates rules ----

    #[test]
    fn test_permission_mapper_default_has_rules() {
        let m = DexPermissionMapper::default();
        let apis = vec!["android/telephony/TelephonyManager;->getDeviceId".to_string()];
        assert!(!m.required_permissions(&apis).is_empty());
    }

    // ---- DexStringExtractor default usable ----

    #[test]
    fn test_string_extractor_default() {
        let _extractor = DexStringExtractor;
        let strings = vec![StringEntry {
            value: "http://test.com".to_string(),
            from_dex: true,
            from_resources: false,
        }];
        assert_eq!(DexStringExtractor::find_c2_indicators(&strings).len(), 1);
    }
}
