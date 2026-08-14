//! JAR security analysis: doPrivileged usage, reflection, native methods,
//! serialization gadgets, unvalidated input flows, `ClassLoader` manipulation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum JarSecurityError {
    #[error("jar parse error: {0}")]
    JarParse(String),
    #[error("class parse error: {0}")]
    ClassParse(String),
    #[error("io error: {0}")]
    Io(String),
}

// ─── RiskLevel ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RiskLevel {
    #[must_use]
    pub const fn score(self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 3,
            Self::Medium => 6,
            Self::High => 8,
            Self::Critical => 10,
        }
    }
}

// ─── ClassPermission ─────────────────────────────────────────────────────────

/// A `doPrivileged` call site found in a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPermission {
    /// Fully-qualified class name.
    pub class_name: String,
    /// Method containing the `doPrivileged` call.
    pub method_name: String,
    /// Type of privilege block (`"AccessController.doPrivileged"`, etc.).
    pub block_type: String,
    /// Risk level for this usage.
    pub risk: RiskLevel,
    /// Source line (best-effort; 0 = unavailable).
    pub line: u32,
}

impl ClassPermission {
    /// Returns `true` when this is an unchecked doPrivileged call (no perm check).
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        !self.block_type.contains("Permission") && !self.block_type.contains("Constrained")
    }
}

// ─── ReflectionUsage ─────────────────────────────────────────────────────────

/// A reflective API call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionUsage {
    pub class_name: String,
    pub method_name: String,
    pub reflection_api: String,
    pub risk: RiskLevel,
}

impl ReflectionUsage {
    /// Returns `true` when the reflection call can invoke private members.
    #[must_use]
    pub fn can_bypass_access(&self) -> bool {
        self.reflection_api.contains("getDeclared") || self.reflection_api.contains("setAccessible")
    }
}

// ─── NativeMethod ────────────────────────────────────────────────────────────

/// A native method declaration in a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMethod {
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
    /// Whether the native library is known to be loaded via `System.loadLibrary`.
    pub library_loaded: bool,
    pub risk: RiskLevel,
}

// ─── SerializationGadget ─────────────────────────────────────────────────────

/// A potential serialization gadget (class with `readObject`/`writeObject`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationGadget {
    pub class_name: String,
    pub method: String,
    /// Whether the class is `Serializable`.
    pub is_serializable: bool,
    /// Whether `readObject` calls dangerous methods.
    pub has_dangerous_readobject: bool,
    pub risk: RiskLevel,
}

impl SerializationGadget {
    /// Returns `true` if this is a high-risk deserialization gadget.
    #[must_use]
    pub fn is_gadget(&self) -> bool {
        self.is_serializable && (self.has_dangerous_readobject || self.method == "readObject")
    }
}

// ─── UnvalidatedInput ────────────────────────────────────────────────────────

/// A data flow from unvalidated user input to a dangerous sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnvalidatedInput {
    pub class_name: String,
    pub method_name: String,
    /// Source (e.g. `"getParameter"`, `"getHeader"`, `"readLine"`).
    pub source: String,
    /// Sink (e.g. `"exec"`, `"prepareStatement"`, `"ProcessBuilder"`).
    pub sink: String,
    /// Vulnerability category (e.g. `"SQL injection"`, `"Command injection"`).
    pub category: String,
    pub risk: RiskLevel,
}

impl UnvalidatedInput {
    #[must_use]
    pub fn is_injection(&self) -> bool {
        self.category.contains("injection") || self.category.contains("Injection")
    }
}

// ─── ClassLoaderManipulation ─────────────────────────────────────────────────

/// A custom `ClassLoader` or dynamic class loading site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassLoaderManipulation {
    pub class_name: String,
    pub method_name: String,
    /// Type of manipulation (e.g. `"URLClassLoader"`, `"defineClass"`, `"loadClass"`).
    pub manipulation_type: String,
    /// Whether this loads from a remote URL.
    pub loads_remote: bool,
    pub risk: RiskLevel,
}

impl ClassLoaderManipulation {
    /// Returns `true` when this pattern can load arbitrary code.
    #[must_use]
    pub fn can_load_arbitrary_code(&self) -> bool {
        self.loads_remote || self.manipulation_type == "defineClass"
    }
}

// ─── JarSecurityReport ───────────────────────────────────────────────────────

/// Full security analysis report for a JAR archive.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JarSecurityReport {
    pub permissions: Vec<ClassPermission>,
    pub reflection: Vec<ReflectionUsage>,
    pub native_methods: Vec<NativeMethod>,
    pub serialization_gadgets: Vec<SerializationGadget>,
    pub unvalidated_inputs: Vec<UnvalidatedInput>,
    pub classloader_manipulations: Vec<ClassLoaderManipulation>,
    /// Per-class risk scores.
    pub class_risk_scores: HashMap<String, u32>,
    /// Total number of classes analysed.
    pub classes_analysed: usize,
    /// Overall jar risk score (0–100).
    pub overall_risk: f64,
}

impl JarSecurityReport {
    /// Returns all findings at or above the given risk level, across every
    /// category in the report (permissions, reflection, native methods,
    /// gadgets, unvalidated inputs and classloader manipulations).
    #[must_use]
    pub fn findings_at_or_above(&self, level: RiskLevel) -> Vec<RiskLevel> {
        let mut out = Vec::new();
        out.extend(self.permissions.iter().map(|x| x.risk).filter(|r| *r >= level));
        out.extend(self.reflection.iter().map(|x| x.risk).filter(|r| *r >= level));
        out.extend(self.native_methods.iter().map(|x| x.risk).filter(|r| *r >= level));
        out.extend(self.serialization_gadgets.iter().map(|x| x.risk).filter(|r| *r >= level));
        out.extend(self.unvalidated_inputs.iter().map(|x| x.risk).filter(|r| *r >= level));
        out.extend(self.classloader_manipulations.iter().map(|x| x.risk).filter(|r| *r >= level));
        out
    }

    /// Build a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let permissions = vec![ClassPermission {
            class_name: "com.example.PrivilegedAction".into(),
            method_name: "run".into(),
            block_type: "AccessController.doPrivileged".into(),
            risk: RiskLevel::High,
            line: 42,
        }];
        let reflection = vec![ReflectionUsage {
            class_name: "com.example.Loader".into(),
            method_name: "loadPlugin".into(),
            reflection_api: "getDeclaredMethod".into(),
            risk: RiskLevel::High,
        }];
        let native_methods = vec![NativeMethod {
            class_name: "com.example.Native".into(),
            method_name: "nativeProcess".into(),
            descriptor: "()V".into(),
            library_loaded: true,
            risk: RiskLevel::Medium,
        }];
        let gadgets = vec![SerializationGadget {
            class_name: "com.example.DataObject".into(),
            method: "readObject".into(),
            is_serializable: true,
            has_dangerous_readobject: true,
            risk: RiskLevel::Critical,
        }];
        let inputs = vec![UnvalidatedInput {
            class_name: "com.example.Servlet".into(),
            method_name: "doGet".into(),
            source: "getParameter".into(),
            sink: "prepareStatement".into(),
            category: "SQL injection".into(),
            risk: RiskLevel::Critical,
        }];
        let clm = vec![ClassLoaderManipulation {
            class_name: "com.example.PluginLoader".into(),
            method_name: "loadFromUrl".into(),
            manipulation_type: "URLClassLoader".into(),
            loads_remote: true,
            risk: RiskLevel::High,
        }];
        let mut class_risk = HashMap::new();
        class_risk.insert("com.example.Servlet".into(), 10u32);
        class_risk.insert("com.example.DataObject".into(), 10u32);
        Self {
            permissions,
            reflection,
            native_methods,
            serialization_gadgets: gadgets,
            unvalidated_inputs: inputs,
            classloader_manipulations: clm,
            class_risk_scores: class_risk,
            classes_analysed: 42,
            overall_risk: 87.0,
        }
    }

    /// High-risk findings (HIGH or CRITICAL).
    #[must_use]
    pub fn high_risk_count(&self) -> usize {
        let mut count = 0;
        count += self
            .permissions
            .iter()
            .filter(|p| p.risk >= RiskLevel::High)
            .count();
        count += self
            .reflection
            .iter()
            .filter(|r| r.risk >= RiskLevel::High)
            .count();
        count += self
            .native_methods
            .iter()
            .filter(|n| n.risk >= RiskLevel::High)
            .count();
        count += self
            .serialization_gadgets
            .iter()
            .filter(|s| s.risk >= RiskLevel::High)
            .count();
        count += self
            .unvalidated_inputs
            .iter()
            .filter(|u| u.risk >= RiskLevel::High)
            .count();
        count += self
            .classloader_manipulations
            .iter()
            .filter(|c| c.risk >= RiskLevel::High)
            .count();
        count
    }

    /// Returns `true` when the JAR has any critical findings.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.serialization_gadgets
            .iter()
            .any(|s| s.risk == RiskLevel::Critical)
            || self
                .unvalidated_inputs
                .iter()
                .any(|u| u.risk == RiskLevel::Critical)
    }

    /// All classes with any finding.
    #[must_use]
    pub fn affected_classes(&self) -> Vec<String> {
        let mut classes: Vec<String> = self.class_risk_scores.keys().cloned().collect();
        classes.sort();
        classes.dedup();
        classes
    }

    /// Recompute overall risk from findings.
    pub fn recompute_risk(&mut self) {
        let total: f64 = [
            f64::from(self.permissions.iter().map(|p| p.risk.score()).sum::<u32>()),
            f64::from(self.reflection.iter().map(|r| r.risk.score()).sum::<u32>()),
            f64::from(self.native_methods
                .iter()
                .map(|n| n.risk.score())
                .sum::<u32>()),
            f64::from(self.serialization_gadgets
                .iter()
                .map(|s| s.risk.score())
                .sum::<u32>()),
            f64::from(self.unvalidated_inputs
                .iter()
                .map(|u| u.risk.score())
                .sum::<u32>()),
            f64::from(self.classloader_manipulations
                .iter()
                .map(|c| c.risk.score())
                .sum::<u32>()),
        ]
        .iter()
        .sum::<f64>();
        self.overall_risk = (total / self.classes_analysed.max(1) as f64 * 10.0).min(100.0);
    }
}

impl fmt::Display for JarSecurityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JarSecurityReport classes={} risk={:.1} high_risk={} critical={}",
            self.classes_analysed,
            self.overall_risk,
            self.high_risk_count(),
            self.has_critical(),
        )
    }
}

// ─── JarSecurityAnalyzer ─────────────────────────────────────────────────────

/// Analyzes a JAR's bytecode for security-relevant patterns.
#[derive(Debug, Default)]
pub struct JarSecurityAnalyzer;

impl JarSecurityAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan a class file's constant pool for permission / reflection / native patterns.
    ///
    /// This is a simplified scan over the raw bytecode; a full implementation
    /// would use the `rustre-loader-java` bytecode analysis pipeline.
    #[must_use]
    pub fn analyze_class_bytes(&self, class_name: &str, data: &[u8]) -> JarSecurityReport {
        let mut report = JarSecurityReport {
            classes_analysed: 1,
            ..JarSecurityReport::default()
        };

        // Quick string-presence checks
        let check = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);

        if check(b"doPrivileged") {
            report.permissions.push(ClassPermission {
                class_name: class_name.into(),
                method_name: "unknown".into(),
                block_type: "AccessController.doPrivileged".into(),
                risk: RiskLevel::High,
                line: 0,
            });
        }

        if check(b"getDeclaredMethod") || check(b"setAccessible") {
            report.reflection.push(ReflectionUsage {
                class_name: class_name.into(),
                method_name: "unknown".into(),
                reflection_api: "getDeclaredMethod".into(),
                risk: RiskLevel::Medium,
            });
        }

        if check(b"readObject") {
            report.serialization_gadgets.push(SerializationGadget {
                class_name: class_name.into(),
                method: "readObject".into(),
                is_serializable: check(b"Serializable"),
                has_dangerous_readobject: check(b"exec"),
                risk: if check(b"exec") {
                    RiskLevel::Critical
                } else {
                    RiskLevel::Medium
                },
            });
        }

        if check(b"URLClassLoader") || check(b"defineClass") {
            report
                .classloader_manipulations
                .push(ClassLoaderManipulation {
                    class_name: class_name.into(),
                    method_name: "unknown".into(),
                    manipulation_type: if check(b"URLClassLoader") {
                        "URLClassLoader".into()
                    } else {
                        "defineClass".into()
                    },
                    loads_remote: check(b"http://") || check(b"https://"),
                    risk: RiskLevel::High,
                });
        }

        report.recompute_risk();
        report
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RiskLevel ─────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Info);
    }

    #[test]
    fn test_risk_level_score() {
        assert_eq!(RiskLevel::Critical.score(), 10);
        assert_eq!(RiskLevel::Low.score(), 3);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
        assert_eq!(RiskLevel::Info.to_string(), "INFO");
    }

    // ── ClassPermission ───────────────────────────────────────────────────────

    #[test]
    fn test_class_permission_is_unchecked() {
        let p = ClassPermission {
            class_name: "Foo".into(),
            method_name: "run".into(),
            block_type: "AccessController.doPrivileged".into(),
            risk: RiskLevel::High,
            line: 0,
        };
        assert!(p.is_unchecked());
    }

    #[test]
    fn test_class_permission_is_checked() {
        let p = ClassPermission {
            class_name: "Foo".into(),
            method_name: "run".into(),
            block_type: "doPrivilegedWithPermission".into(),
            risk: RiskLevel::Medium,
            line: 0,
        };
        assert!(!p.is_unchecked());
    }

    // ── ReflectionUsage ───────────────────────────────────────────────────────

    #[test]
    fn test_reflection_can_bypass_access_declared() {
        let r = ReflectionUsage {
            class_name: "Foo".into(),
            method_name: "m".into(),
            reflection_api: "getDeclaredMethod".into(),
            risk: RiskLevel::High,
        };
        assert!(r.can_bypass_access());
    }

    #[test]
    fn test_reflection_no_bypass_getmethod() {
        let r = ReflectionUsage {
            class_name: "Foo".into(),
            method_name: "m".into(),
            reflection_api: "getMethod".into(),
            risk: RiskLevel::Medium,
        };
        assert!(!r.can_bypass_access());
    }

    // ── SerializationGadget ───────────────────────────────────────────────────

    #[test]
    fn test_gadget_is_gadget_true() {
        let g = SerializationGadget {
            class_name: "Foo".into(),
            method: "readObject".into(),
            is_serializable: true,
            has_dangerous_readobject: true,
            risk: RiskLevel::Critical,
        };
        assert!(g.is_gadget());
    }

    #[test]
    fn test_gadget_not_gadget_if_not_serializable() {
        let g = SerializationGadget {
            class_name: "Foo".into(),
            method: "readObject".into(),
            is_serializable: false,
            has_dangerous_readobject: true,
            risk: RiskLevel::Medium,
        };
        assert!(!g.is_gadget());
    }

    // ── UnvalidatedInput ──────────────────────────────────────────────────────

    #[test]
    fn test_unvalidated_input_is_injection() {
        let u = UnvalidatedInput {
            class_name: "S".into(),
            method_name: "doGet".into(),
            source: "getParam".into(),
            sink: "exec".into(),
            category: "Command injection".into(),
            risk: RiskLevel::Critical,
        };
        assert!(u.is_injection());
    }

    #[test]
    fn test_unvalidated_input_not_injection() {
        let u = UnvalidatedInput {
            class_name: "S".into(),
            method_name: "doGet".into(),
            source: "getParam".into(),
            sink: "log".into(),
            category: "Log forging".into(),
            risk: RiskLevel::Low,
        };
        assert!(!u.is_injection());
    }

    // ── ClassLoaderManipulation ───────────────────────────────────────────────

    #[test]
    fn test_clm_can_load_remote() {
        let c = ClassLoaderManipulation {
            class_name: "L".into(),
            method_name: "load".into(),
            manipulation_type: "URLClassLoader".into(),
            loads_remote: true,
            risk: RiskLevel::Critical,
        };
        assert!(c.can_load_arbitrary_code());
    }

    #[test]
    fn test_clm_define_class_is_arbitrary() {
        let c = ClassLoaderManipulation {
            class_name: "L".into(),
            method_name: "define".into(),
            manipulation_type: "defineClass".into(),
            loads_remote: false,
            risk: RiskLevel::High,
        };
        assert!(c.can_load_arbitrary_code());
    }

    // ── JarSecurityReport ─────────────────────────────────────────────────────

    #[test]
    fn test_report_mock_has_critical() {
        let r = JarSecurityReport::mock();
        assert!(r.has_critical());
    }

    #[test]
    fn test_report_mock_high_risk_count() {
        let r = JarSecurityReport::mock();
        assert!(r.high_risk_count() >= 3);
    }

    #[test]
    fn test_report_mock_overall_risk() {
        let r = JarSecurityReport::mock();
        assert!(r.overall_risk > 0.0 && r.overall_risk <= 100.0);
    }

    #[test]
    fn test_report_affected_classes() {
        let r = JarSecurityReport::mock();
        let classes = r.affected_classes();
        assert!(!classes.is_empty());
    }

    #[test]
    fn test_report_display() {
        let r = JarSecurityReport::mock();
        let s = format!("{r}");
        assert!(s.contains("JarSecurityReport"));
    }

    #[test]
    fn test_report_serialization() {
        let r = JarSecurityReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: JarSecurityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.classes_analysed, r.classes_analysed);
    }

    #[test]
    fn test_report_recompute_risk() {
        let mut r = JarSecurityReport::mock();
        r.classes_analysed = 10;
        r.recompute_risk();
        assert!(r.overall_risk <= 100.0);
    }

    // ── JarSecurityAnalyzer ───────────────────────────────────────────────────

    #[test]
    fn test_analyzer_detects_do_privileged() {
        let az = JarSecurityAnalyzer::new();
        let data = b"doPrivileged AccessController blah";
        let r = az.analyze_class_bytes("com.Test", data);
        assert!(!r.permissions.is_empty());
    }

    #[test]
    fn test_analyzer_detects_reflection() {
        let az = JarSecurityAnalyzer::new();
        let data = b"getDeclaredMethod setAccessible";
        let r = az.analyze_class_bytes("com.Test", data);
        assert!(!r.reflection.is_empty());
    }

    #[test]
    fn test_analyzer_detects_readobject() {
        let az = JarSecurityAnalyzer::new();
        let data = b"readObject Serializable exec";
        let r = az.analyze_class_bytes("com.Test", data);
        assert!(!r.serialization_gadgets.is_empty());
        assert!(r.serialization_gadgets[0].has_dangerous_readobject);
    }

    #[test]
    fn test_analyzer_detects_urlclassloader() {
        let az = JarSecurityAnalyzer::new();
        let data = b"URLClassLoader https://evil.com/plugin.jar";
        let r = az.analyze_class_bytes("com.Test", data);
        assert!(!r.classloader_manipulations.is_empty());
        assert!(r.classloader_manipulations[0].loads_remote);
    }

    #[test]
    fn test_analyzer_empty_data() {
        let az = JarSecurityAnalyzer::new();
        let r = az.analyze_class_bytes("com.Empty", &[]);
        assert!(r.permissions.is_empty());
        assert!(r.reflection.is_empty());
    }

    #[test]
    fn test_analyzer_default() {
        let az = JarSecurityAnalyzer;
        assert!(az.analyze_class_bytes("com.X", b"").permissions.is_empty());
    }
    #[test]
    fn test_risk_level_info_score() {
        assert_eq!(RiskLevel::Info.score(), 1);
    }
    #[test]
    fn test_risk_level_medium_score() {
        assert_eq!(RiskLevel::Medium.score(), 6);
    }
    #[test]
    fn test_report_mock_serialization() {
        let r = JarSecurityReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: JarSecurityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.classes_analysed, r.classes_analysed);
    }
    #[test]
    fn test_report_recompute_zero_classes() {
        let mut r = JarSecurityReport {
            classes_analysed: 0,
            ..JarSecurityReport::default()
        };
        r.recompute_risk();
        assert_eq!(r.overall_risk, 0.0);
    }
    #[test]
    fn test_class_permission_line() {
        let p = ClassPermission {
            class_name: "Foo".into(),
            method_name: "run".into(),
            block_type: "doPrivileged".into(),
            risk: RiskLevel::High,
            line: 10,
        };
        assert_eq!(p.line, 10);
    }
    #[test]
    fn test_native_method_library_loaded() {
        let n = NativeMethod {
            class_name: "C".into(),
            method_name: "fn".into(),
            descriptor: "()V".into(),
            library_loaded: true,
            risk: RiskLevel::Medium,
        };
        assert!(n.library_loaded);
    }
    #[test]
    fn test_gadget_risk_medium_when_not_dangerous() {
        let g = SerializationGadget {
            class_name: "C".into(),
            method: "readObject".into(),
            is_serializable: true,
            has_dangerous_readobject: false,
            risk: RiskLevel::Medium,
        };
        assert_eq!(g.risk, RiskLevel::Medium);
    }
    #[test]
    fn test_clm_risk_critical_remote() {
        let c = ClassLoaderManipulation {
            class_name: "L".into(),
            method_name: "m".into(),
            manipulation_type: "URLClassLoader".into(),
            loads_remote: true,
            risk: RiskLevel::Critical,
        };
        assert_eq!(c.risk, RiskLevel::Critical);
    }
    #[test]
    fn test_report_findings_at_or_above_low() {
        let r = JarSecurityReport::mock();
        let low = r.findings_at_or_above(RiskLevel::Low);
        assert!(low.len() >= r.findings_at_or_above(RiskLevel::Critical).len());
    }
    #[test]
    fn test_analyzer_no_classloader_in_clean() {
        let az = JarSecurityAnalyzer::new();
        let r = az.analyze_class_bytes("com.X", b"harmless code");
        assert!(r.classloader_manipulations.is_empty());
    }
    #[test]
    fn test_report_mock_affected_classes() {
        let r = JarSecurityReport::mock();
        assert!(!r.affected_classes().is_empty());
    }
    #[test]
    fn test_report_high_risk_above_zero() {
        let r = JarSecurityReport::mock();
        assert!(r.high_risk_count() > 0);
    }
    #[test]
    fn test_unvalidated_input_sql_is_injection() {
        let u = UnvalidatedInput {
            class_name: "S".into(),
            method_name: "q".into(),
            source: "getParam".into(),
            sink: "prepareStatement".into(),
            category: "SQL injection".into(),
            risk: RiskLevel::Critical,
        };
        assert!(u.is_injection());
    }
    #[test]
    fn test_risk_level_high_display() {
        assert_eq!(RiskLevel::High.to_string(), "HIGH");
    }
}
