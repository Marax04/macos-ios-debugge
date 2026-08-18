//! JADX decompilation analysis: class hierarchy, cross-references, strings,
//! crypto patterns, network calls, file operations, reflection, native calls,
//! security vulnerabilities.

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum JadxAnalysisError {
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClassHierarchy {
    pub class_name: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub subclasses: Vec<String>,
    pub depth: u32,
}
impl ClassHierarchy {
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.superclass.as_deref() == Some("java.lang.Object") || self.superclass.is_none()
    }
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.subclasses.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReference {
    pub from_class: String,
    pub from_method: String,
    pub to_class: String,
    pub to_method: String,
    pub ref_type: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringUsage {
    pub value: String,
    pub class: String,
    pub method: String,
    pub category: StringCategory,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringCategory {
    Url,
    Ip,
    Path,
    Command,
    CryptoAlgo,
    Credential,
    Generic,
}
impl fmt::Display for StringCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => write!(f, "url"),
            Self::Ip => write!(f, "ip"),
            Self::Path => write!(f, "path"),
            Self::Command => write!(f, "command"),
            Self::CryptoAlgo => write!(f, "crypto"),
            Self::Credential => write!(f, "credential"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPattern {
    pub class: String,
    pub method: String,
    pub algorithm: String,
    pub key_size: Option<u32>,
    pub mode: Option<String>,
    pub is_insecure: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCall {
    pub class: String,
    pub method: String,
    pub url_pattern: Option<String>,
    pub protocol: String,
    pub is_cleartext: bool,
    pub has_hostname_verify: bool,
    pub has_cert_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub class: String,
    pub method: String,
    pub path_pattern: Option<String>,
    pub operation: String,
    pub is_external_storage: bool,
    pub is_world_readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionUsage {
    pub class: String,
    pub method: String,
    pub target_class: Option<String>,
    pub target_method: Option<String>,
    pub reflection_api: String,
    pub can_bypass_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCall {
    pub class: String,
    pub native_method: String,
    pub library: Option<String>,
    pub is_jni: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVulnerability {
    pub class: String,
    pub method: String,
    pub vuln_type: String,
    pub description: String,
    pub severity: String,
    pub confidence: f64,
    pub line: u32,
}
impl SecurityVulnerability {
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.severity == "critical"
    }
    #[must_use]
    pub fn is_high(&self) -> bool {
        matches!(self.severity.as_str(), "critical" | "high")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxAnalysisResult {
    pub class_hierarchy: Vec<ClassHierarchy>,
    pub cross_references: Vec<CrossReference>,
    pub string_usage: Vec<StringUsage>,
    pub crypto_patterns: Vec<CryptoPattern>,
    pub network_calls: Vec<NetworkCall>,
    pub file_operations: Vec<FileOperation>,
    pub reflection_usage: Vec<ReflectionUsage>,
    pub native_calls: Vec<NativeCall>,
    pub vulnerabilities: Vec<SecurityVulnerability>,
    pub total_classes: usize,
    pub total_methods: usize,
    pub risk_score: f64,
}

impl JadxAnalysisResult {
    #[must_use]
    /// NOTE: a hand-written fixture for this crate's own tests. It is not
    /// derived from any input and is not reachable from the MCP tool surface;
    /// never report it to a user as the analysis of a real file.
    pub fn mock() -> Self {
        let hierarchy = vec![
            ClassHierarchy {
                class_name: "MainActivity".into(),
                superclass: Some("AppCompatActivity".into()),
                interfaces: vec!["View.OnClickListener".into()],
                subclasses: vec![],
                depth: 2,
            },
            ClassHierarchy {
                class_name: "CryptoHelper".into(),
                superclass: Some("java.lang.Object".into()),
                interfaces: vec![],
                subclasses: vec![],
                depth: 1,
            },
        ];
        let xrefs = vec![CrossReference {
            from_class: "MainActivity".into(),
            from_method: "onCreate".into(),
            to_class: "CryptoHelper".into(),
            to_method: "encrypt".into(),
            ref_type: "invoke".into(),
            line: 42,
        }];
        let strings = vec![
            StringUsage {
                value: "https://api.malware.com/c2".into(),
                class: "NetworkManager".into(),
                method: "postData".into(),
                category: StringCategory::Url,
                is_encrypted: false,
            },
            StringUsage {
                value: "AES/CBC/PKCS5Padding".into(),
                class: "CryptoHelper".into(),
                method: "encrypt".into(),
                category: StringCategory::CryptoAlgo,
                is_encrypted: false,
            },
            StringUsage {
                value: "admin:password123".into(),
                class: "AuthManager".into(),
                method: "login".into(),
                category: StringCategory::Credential,
                is_encrypted: false,
            },
        ];
        let crypto = vec![
            CryptoPattern {
                class: "CryptoHelper".into(),
                method: "encrypt".into(),
                algorithm: "AES".into(),
                key_size: Some(128),
                mode: Some("CBC".into()),
                is_insecure: false,
                confidence: 0.9,
            },
            CryptoPattern {
                class: "LegacyCrypto".into(),
                method: "hash".into(),
                algorithm: "MD5".into(),
                key_size: None,
                mode: None,
                is_insecure: true,
                confidence: 0.95,
            },
        ];
        let network = vec![NetworkCall {
            class: "NetworkManager".into(),
            method: "postData".into(),
            url_pattern: Some("https://api.malware.com".into()),
            protocol: "http".into(),
            is_cleartext: false,
            has_hostname_verify: false,
            has_cert_verify: false,
        }];
        let files = vec![FileOperation {
            class: "StorageManager".into(),
            method: "saveData".into(),
            path_pattern: Some("/sdcard/data".into()),
            operation: "write".into(),
            is_external_storage: true,
            is_world_readable: false,
        }];
        let reflection = vec![ReflectionUsage {
            class: "PluginLoader".into(),
            method: "load".into(),
            target_class: None,
            target_method: None,
            reflection_api: "getDeclaredMethod".into(),
            can_bypass_access: true,
        }];
        let native = vec![NativeCall {
            class: "NativeHelper".into(),
            native_method: "nativeProcess".into(),
            library: Some("libnative.so".into()),
            is_jni: true,
        }];
        let vulns = vec![
            SecurityVulnerability {
                class: "SQLHelper".into(),
                method: "query".into(),
                vuln_type: "sql_injection".into(),
                description: "String concatenation in SQL query".into(),
                severity: "critical".into(),
                confidence: 0.9,
                line: 55,
            },
            SecurityVulnerability {
                class: "CryptoHelper".into(),
                method: "hash".into(),
                vuln_type: "weak_crypto".into(),
                description: "MD5 is cryptographically broken".into(),
                severity: "high".into(),
                confidence: 0.95,
                line: 22,
            },
        ];
        Self {
            class_hierarchy: hierarchy,
            cross_references: xrefs,
            string_usage: strings,
            crypto_patterns: crypto,
            network_calls: network,
            file_operations: files,
            reflection_usage: reflection,
            native_calls: native,
            vulnerabilities: vulns,
            total_classes: 42,
            total_methods: 320,
            risk_score: 82.0,
        }
    }

    #[must_use]
    pub fn critical_vulnerabilities(&self) -> Vec<&SecurityVulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.is_critical())
            .collect()
    }
    #[must_use]
    pub fn high_vulnerabilities(&self) -> Vec<&SecurityVulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.is_high())
            .collect()
    }
    #[must_use]
    pub fn insecure_crypto(&self) -> Vec<&CryptoPattern> {
        self.crypto_patterns
            .iter()
            .filter(|c| c.is_insecure)
            .collect()
    }
    #[must_use]
    pub fn cleartext_network(&self) -> Vec<&NetworkCall> {
        self.network_calls
            .iter()
            .filter(|n| n.is_cleartext)
            .collect()
    }
    #[must_use]
    pub fn credential_strings(&self) -> Vec<&StringUsage> {
        self.string_usage
            .iter()
            .filter(|s| s.category == StringCategory::Credential)
            .collect()
    }
    #[must_use]
    pub fn external_storage_ops(&self) -> Vec<&FileOperation> {
        self.file_operations
            .iter()
            .filter(|f| f.is_external_storage)
            .collect()
    }
}

impl fmt::Display for JadxAnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JadxAnalysisResult classes={} vulns={} risk={:.1}",
            self.total_classes,
            self.vulnerabilities.len(),
            self.risk_score
        )
    }
}

#[derive(Debug, Default)]
pub struct JadxDecompilerAnalysis;
impl JadxDecompilerAnalysis {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn analyze_source(&self, java_source: &str) -> JadxAnalysisResult {
        let mut r = JadxAnalysisResult {
            class_hierarchy: vec![],
            cross_references: vec![],
            string_usage: vec![],
            crypto_patterns: vec![],
            network_calls: vec![],
            file_operations: vec![],
            reflection_usage: vec![],
            native_calls: vec![],
            vulnerabilities: vec![],
            total_classes: 1,
            total_methods: 0,
            risk_score: 0.0,
        };
        let lower = java_source.to_lowercase();
        if lower.contains("http://") {
            r.network_calls.push(NetworkCall {
                class: "unknown".into(),
                method: "unknown".into(),
                url_pattern: None,
                protocol: "http".into(),
                is_cleartext: true,
                has_hostname_verify: false,
                has_cert_verify: false,
            });
        }
        if lower.contains("md5") || lower.contains("des") {
            r.crypto_patterns.push(CryptoPattern {
                class: "unknown".into(),
                method: "unknown".into(),
                algorithm: if lower.contains("md5") {
                    "MD5".into()
                } else {
                    "DES".into()
                },
                key_size: None,
                mode: None,
                is_insecure: true,
                confidence: 0.8,
            });
        }
        // `lower` is `java_source.to_lowercase()`, so a needle carrying capitals
        // can never match: this read `"getDeclaredMethod"` and was therefore dead
        // for every input, and reflection went undetected in all of them. The
        // neighbouring checks already use lowercase needles (`"md5"`, `"des"`).
        if lower.contains("getdeclaredmethod") {
            r.reflection_usage.push(ReflectionUsage {
                class: "unknown".into(),
                method: "unknown".into(),
                target_class: None,
                target_method: None,
                reflection_api: "getDeclaredMethod".into(),
                can_bypass_access: true,
            });
        }
        if lower.contains("native ") {
            r.native_calls.push(NativeCall {
                class: "unknown".into(),
                native_method: "native_fn".into(),
                library: None,
                is_jni: true,
            });
        }
        r.total_methods = java_source.matches('(').count();
        let crypto_count = u32::try_from(r.crypto_patterns.len()).unwrap_or(u32::MAX);
        let net_count = u32::try_from(r.network_calls.len()).unwrap_or(u32::MAX);
        r.risk_score = f64::from(crypto_count)
            .mul_add(10.0, f64::from(net_count) * 5.0)
            .min(100.0);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_hierarchy_is_root() {
        let h = ClassHierarchy {
            superclass: Some("java.lang.Object".into()),
            ..Default::default()
        };
        assert!(h.is_root());
    }
    #[test]
    fn test_class_hierarchy_is_leaf() {
        let h = ClassHierarchy {
            subclasses: vec![],
            ..Default::default()
        };
        assert!(h.is_leaf());
    }
    #[test]
    fn test_string_category_display() {
        assert_eq!(StringCategory::Url.to_string(), "url");
        assert_eq!(StringCategory::Credential.to_string(), "credential");
    }
    #[test]
    fn test_vuln_is_critical() {
        let v = SecurityVulnerability {
            class: String::new(),
            method: String::new(),
            vuln_type: String::new(),
            description: String::new(),
            severity: "critical".into(),
            confidence: 0.9,
            line: 0,
        };
        assert!(v.is_critical());
    }
    #[test]
    fn test_vuln_is_high() {
        let v = SecurityVulnerability {
            class: String::new(),
            method: String::new(),
            vuln_type: String::new(),
            description: String::new(),
            severity: "high".into(),
            confidence: 0.8,
            line: 0,
        };
        assert!(v.is_high());
        assert!(!v.is_critical());
    }
    #[test]
    fn test_result_mock_critical_vulns() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.critical_vulnerabilities().is_empty());
    }
    #[test]
    fn test_result_mock_high_vulns() {
        let r = JadxAnalysisResult::mock();
        assert!(r.high_vulnerabilities().len() >= 2);
    }
    #[test]
    fn test_result_mock_insecure_crypto() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.insecure_crypto().is_empty());
    }
    #[test]
    fn test_result_mock_credential_strings() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.credential_strings().is_empty());
    }
    #[test]
    fn test_result_mock_external_storage() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.external_storage_ops().is_empty());
    }
    #[test]
    fn test_result_display() {
        let r = JadxAnalysisResult::mock();
        let s = format!("{r}");
        assert!(s.contains("JadxAnalysisResult"));
    }
    #[test]
    fn test_result_serialization() {
        let r = JadxAnalysisResult::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: JadxAnalysisResult = serde_json::from_str(&j).unwrap();
        assert_eq!(b.total_classes, r.total_classes);
    }
    #[test]
    fn test_analyzer_detects_http() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("String url = \"http://evil.com\";");
        assert!(!r.network_calls.is_empty());
        assert!(r.network_calls[0].is_cleartext);
    }
    #[test]
    fn test_analyzer_detects_md5() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("MessageDigest.getInstance(\"MD5\")");
        assert!(!r.crypto_patterns.is_empty());
        assert!(r.crypto_patterns[0].is_insecure);
    }
    #[test]
    fn test_analyzer_detects_reflection() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("getDeclaredMethod(\"secret\")");
        assert!(!r.reflection_usage.is_empty());
    }
    #[test]
    fn test_analyzer_detects_native() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("public native void doThing();");
        assert!(!r.native_calls.is_empty());
    }
    #[test]
    fn test_analyzer_empty_source() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("");
        assert!(r.risk_score.abs() < f64::EPSILON);
    }
    #[test]
    fn test_crypto_pattern_is_insecure_md5() {
        let c = CryptoPattern {
            class: String::new(),
            method: String::new(),
            algorithm: "MD5".into(),
            key_size: None,
            mode: None,
            is_insecure: true,
            confidence: 0.95,
        };
        assert!(c.is_insecure);
    }
    #[test]
    fn test_class_hierarchy_not_leaf_has_children() {
        let h = ClassHierarchy {
            class_name: "Base".into(),
            superclass: None,
            interfaces: vec![],
            subclasses: vec!["Sub".into()],
            depth: 0,
        };
        assert!(!h.is_leaf());
    }
    #[test]
    fn test_string_category_command() {
        assert_eq!(StringCategory::Command.to_string(), "command");
    }
    #[test]
    fn test_string_category_path() {
        assert_eq!(StringCategory::Path.to_string(), "path");
    }
    #[test]
    fn test_vuln_high_but_not_critical() {
        let v = SecurityVulnerability {
            class: String::new(),
            method: String::new(),
            vuln_type: String::new(),
            description: String::new(),
            severity: "high".into(),
            confidence: 0.8,
            line: 0,
        };
        assert!(v.is_high());
        assert!(!v.is_critical());
    }
    #[test]
    fn test_result_mock_risk_score() {
        let r = JadxAnalysisResult::mock();
        assert!(r.risk_score > 0.0);
    }
    #[test]
    fn test_result_mock_total_classes() {
        let r = JadxAnalysisResult::mock();
        assert_eq!(r.total_classes, 42);
    }
    #[test]
    fn test_result_mock_xrefs() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.cross_references.is_empty());
    }
    #[test]
    fn test_result_mock_string_usage() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.string_usage.is_empty());
    }
    #[test]
    fn test_result_mock_network_calls() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.network_calls.is_empty());
    }
    #[test]
    fn test_result_mock_file_operations() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.file_operations.is_empty());
    }
    #[test]
    fn test_result_mock_reflection() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.reflection_usage.is_empty());
    }
    #[test]
    fn test_result_mock_native_calls() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.native_calls.is_empty());
    }
    #[test]
    fn test_result_cleartext_none() {
        let r = JadxAnalysisResult::mock();
        assert!(r.cleartext_network().is_empty());
    }
    #[test]
    fn test_result_high_vulns_include_medium() {
        let r = JadxAnalysisResult::mock();
        let high = r.high_vulnerabilities();
        assert!(high.len() >= r.critical_vulnerabilities().len());
    }
    #[test]
    fn test_network_call_not_cleartext() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.network_calls[0].is_cleartext);
    }
    #[test]
    fn test_native_call_is_jni() {
        let r = JadxAnalysisResult::mock();
        assert!(r.native_calls[0].is_jni);
    }
    #[test]
    fn test_reflection_can_bypass() {
        let r = JadxAnalysisResult::mock();
        assert!(r.reflection_usage[0].can_bypass_access);
    }
    #[test]
    fn test_analyzer_detects_des() {
        let az = JadxDecompilerAnalysis::new();
        let r = az.analyze_source("DES cipher implementation");
        assert!(!r.crypto_patterns.is_empty());
    }
    #[test]
    fn test_result_total_methods() {
        let r = JadxAnalysisResult::mock();
        assert!(r.total_methods > 0);
    }
    #[test]
    fn test_string_usage_url_category() {
        let r = JadxAnalysisResult::mock();
        let any_url = r
            .string_usage
            .iter()
            .any(|s| s.category == StringCategory::Url);
        assert!(any_url);
    }
    #[test]
    fn test_string_usage_not_encrypted() {
        let r = JadxAnalysisResult::mock();
        assert!(!r.string_usage[0].is_encrypted);
    }
    #[test]
    fn test_file_op_is_external() {
        let r = JadxAnalysisResult::mock();
        assert!(r.file_operations[0].is_external_storage);
    }
}
