//! `jvm_security` — JVM security analysis: SecurityManager usage, privileged
//! blocks, ClassLoader abuse, serialization risks, and reflection security.
//!
//! Provides:
//! * [`JavaSecurityManager`]  — SecurityManager permission-check detection
//! * [`PrivilegedBlock`]      — AccessController.doPrivileged analysis
//! * [`ClassLoaderAbuse`]     — dangerous ClassLoader patterns
//! * [`SerializationRisk`]    — Java serialization vulnerability detection
//! * [`ReflectionSecurity`]   — security-relevant reflection API usage
//! * [`JvmSecurity`]          — top-level facade

use std::collections::HashSet;

/// Re-export `HashMap` for downstream security analysis tables keyed by permission or class.
pub use std::collections::HashMap;
/// Re-export `std::fmt` for downstream `Display`/`Debug` implementations on security findings.
pub use std::fmt;

// ---------------------------------------------------------------------------
// SecurityManager
// ---------------------------------------------------------------------------

/// A `SecurityManager` permission check type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionKind {
    FileRead,
    FileWrite,
    FileDelete,
    NetworkConnect,
    NetworkListen,
    NetworkAccept,
    RuntimeExec,
    RuntimeExit,
    ReflectAccess,
    ClassLoading,
    PropertyRead,
    PropertyWrite,
    SecurityAccess,
    Unknown,
}

impl PermissionKind {
    /// Detect permission kind from `SecurityManager` method name.
    #[must_use]
    pub fn from_method(method: &str) -> Self {
        match method {
            "checkRead" => Self::FileRead,
            "checkWrite" => Self::FileWrite,
            "checkDelete" => Self::FileDelete,
            "checkConnect" => Self::NetworkConnect,
            "checkListen" => Self::NetworkListen,
            "checkAccept" => Self::NetworkAccept,
            "checkExec" => Self::RuntimeExec,
            "checkExit" => Self::RuntimeExit,
            "checkMemberAccess" | "checkAccessDeclaredMembers" => Self::ReflectAccess,
            "checkPermission" => Self::SecurityAccess,
            "checkPropertyAccess" => Self::PropertyRead,
            "checkPropertiesAccess" => Self::PropertyWrite,
            "checkClassLoader" => Self::ClassLoading,
            _ => Self::Unknown,
        }
    }

    /// Risk level (0=low, 1=medium, 2=high).
    #[must_use]
    pub const fn risk_level(self) -> u8 {
        match self {
            Self::RuntimeExec | Self::ClassLoading | Self::ReflectAccess => 2,
            Self::FileWrite | Self::FileDelete | Self::NetworkConnect => 1,
            _ => 0,
        }
    }
}

/// A detected `SecurityManager` check.
#[derive(Debug, Clone)]
pub struct SecurityCheckRecord {
    pub address: u64,
    pub permission: PermissionKind,
    pub method_name: String,
}

/// `SecurityManager` usage analyzer.
#[derive(Debug, Clone, Default)]
pub struct JavaSecurityManager {
    /// Detected checks.
    pub checks: Vec<SecurityCheckRecord>,
    /// Permissions checked.
    pub permissions_checked: HashSet<PermissionKind>,
    /// Whether the `SecurityManager` is being bypassed.
    pub bypass_detected: bool,
}

impl JavaSecurityManager {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a `SecurityManager` method call.
    pub fn record_check(&mut self, address: u64, method: &str) {
        let perm = PermissionKind::from_method(method);
        self.permissions_checked.insert(perm);
        self.checks.push(SecurityCheckRecord {
            address,
            permission: perm,
            method_name: method.to_string(),
        });
    }

    /// Record a potential bypass attempt.
    pub fn record_bypass(&mut self, address: u64) {
        self.bypass_detected = true;
        self.checks.push(SecurityCheckRecord {
            address,
            permission: PermissionKind::SecurityAccess,
            method_name: "bypass_attempt".to_string(),
        });
    }

    /// High-risk checks (`FileWrite`, `RuntimeExec`, `ClassLoading`, `ReflectAccess`).
    #[must_use]
    pub fn high_risk_checks(&self) -> Vec<&SecurityCheckRecord> {
        self.checks
            .iter()
            .filter(|c| c.permission.risk_level() >= 2)
            .collect()
    }

    /// Whether security checks are present.
    #[must_use]
    pub const fn has_security_checks(&self) -> bool {
        !self.checks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Privileged Block
// ---------------------------------------------------------------------------

/// An `AccessController.doPrivileged` call record.
#[derive(Debug, Clone)]
pub struct PrivilegedCallRecord {
    pub address: u64,
    /// Whether the action throws checked exceptions.
    pub is_exception_action: bool,
    /// Whether the action has a context parameter.
    pub has_context: bool,
}

/// Privileged block analyzer.
#[derive(Debug, Clone, Default)]
pub struct PrivilegedBlock {
    /// Detected privileged calls.
    pub calls: Vec<PrivilegedCallRecord>,
    /// Number of nested privileged blocks.
    pub nested_depth: usize,
    /// Maximum nesting depth seen.
    pub max_nesting: usize,
}

impl PrivilegedBlock {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an `AccessController.doPrivileged` invocation.
    pub fn record(&mut self, address: u64, is_exception_action: bool, has_context: bool) {
        self.nested_depth += 1;
        if self.nested_depth > self.max_nesting {
            self.max_nesting = self.nested_depth;
        }
        self.calls.push(PrivilegedCallRecord {
            address,
            is_exception_action,
            has_context,
        });
    }

    /// Exit a privileged block.
    pub const fn exit(&mut self) {
        self.nested_depth = self.nested_depth.saturating_sub(1);
    }

    /// Number of privileged calls.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.calls.len()
    }

    /// Whether privileged blocks are suspicious (many nested calls).
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.calls.len() > 5 || self.max_nesting > 2
    }

    /// Calls with a context parameter (context-limited privilege).
    #[must_use]
    pub fn context_limited_calls(&self) -> Vec<&PrivilegedCallRecord> {
        self.calls.iter().filter(|c| c.has_context).collect()
    }
}

// ---------------------------------------------------------------------------
// ClassLoader Abuse
// ---------------------------------------------------------------------------

/// A `ClassLoader` abuse record.
#[derive(Debug, Clone)]
pub struct ClassLoaderRecord {
    pub address: u64,
    pub loader_class: String,
    pub method: String,
    pub risk: u8,
    pub description: String,
}

/// Known dangerous `ClassLoader` patterns.
const DANGEROUS_LOADERS: &[(&str, &str, u8, &str)] = &[
    (
        "java/lang/ClassLoader",
        "defineClass",
        90,
        "Direct bytecode injection",
    ),
    (
        "java/lang/ClassLoader",
        "findClass",
        70,
        "Custom class resolution",
    ),
    (
        "java/net/URLClassLoader",
        "<init>",
        80,
        "Dynamic URL-based class loading",
    ),
    (
        "dalvik/system/DexClassLoader",
        "<init>",
        90,
        "Android dynamic DEX loading",
    ),
    (
        "dalvik/system/PathClassLoader",
        "<init>",
        60,
        "Path-based class loading",
    ),
    (
        "dalvik/system/InMemoryDexClassLoader",
        "<init>",
        95,
        "In-memory DEX loading",
    ),
    (
        "java/security/SecureClassLoader",
        "defineClass",
        85,
        "Secure class injection",
    ),
    ("java/net/URLClassLoader", "loadClass", 75, "URL-based load"),
];

/// `ClassLoader` abuse detector.
#[derive(Debug, Clone, Default)]
pub struct ClassLoaderAbuse {
    /// Detected dangerous patterns.
    pub records: Vec<ClassLoaderRecord>,
    /// Whether in-memory class loading was found.
    pub in_memory_loading: bool,
    /// Whether dynamic DEX was used (Android).
    pub dynamic_dex: bool,
}

impl ClassLoaderAbuse {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether (class, method) is dangerous.
    #[must_use]
    pub fn check(class: &str, method: &str) -> Option<(u8, &'static str)> {
        DANGEROUS_LOADERS
            .iter()
            .find(|(c, m, _, _)| *c == class && *m == method)
            .map(|(_, _, risk, desc)| (*risk, *desc))
    }

    /// Record a ClassLoader-related call.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        if let Some((risk, description)) = Self::check(class, method) {
            if class.contains("InMemory") {
                self.in_memory_loading = true;
            }
            if class.contains("Dex") {
                self.dynamic_dex = true;
            }
            self.records.push(ClassLoaderRecord {
                address,
                loader_class: class.to_string(),
                method: method.to_string(),
                risk,
                description: description.to_string(),
            });
        }
    }

    /// Whether any dangerous `ClassLoader` usage was detected.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.records.is_empty()
    }

    /// Maximum risk level found.
    #[must_use]
    pub fn max_risk(&self) -> u8 {
        self.records.iter().map(|r| r.risk).max().unwrap_or(0)
    }

    /// Records with risk >= threshold.
    #[must_use]
    pub fn high_risk_records(&self, threshold: u8) -> Vec<&ClassLoaderRecord> {
        self.records
            .iter()
            .filter(|r| r.risk >= threshold)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Serialization Risk
// ---------------------------------------------------------------------------

/// A serialization-related risk record.
#[derive(Debug, Clone)]
pub struct SerializationRecord {
    pub address: u64,
    pub class: String,
    pub method: String,
    pub risk: u8,
    pub description: String,
}

/// Known dangerous serialization patterns.
const DANGEROUS_SERIAL: &[(&str, &str, u8, &str)] = &[
    (
        "java/io/ObjectInputStream",
        "<init>",
        80,
        "Deserialization sink",
    ),
    (
        "java/io/ObjectInputStream",
        "readObject",
        95,
        "Java deserialization gadget entry",
    ),
    (
        "java/io/ObjectInputStream",
        "readUnshared",
        90,
        "Alternate deserialization",
    ),
    (
        "java/io/ObjectOutputStream",
        "writeObject",
        40,
        "Serialization source",
    ),
    (
        "java/io/Serializable",
        "<init>",
        20,
        "Serializable implementation",
    ),
    (
        "java/io/Externalizable",
        "readExternal",
        85,
        "Externalizable deserialization",
    ),
    (
        "java/io/ObjectStreamClass",
        "lookup",
        60,
        "Stream class reflection",
    ),
    (
        "org/apache/commons/collections",
        "InvokerTransformer",
        99,
        "Commons-Collections gadget chain",
    ),
    (
        "com/sun/org/apache/xalan",
        "TemplatesImpl",
        99,
        "Xalan gadget chain",
    ),
];

/// Serialization risk analyzer.
#[derive(Debug, Clone, Default)]
pub struct SerializationRisk {
    /// Detected risky patterns.
    pub records: Vec<SerializationRecord>,
    /// Whether `readObject` was found.
    pub has_readobject: bool,
    /// Known gadget chain classes found.
    pub gadget_classes: HashSet<String>,
}

impl SerializationRisk {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a (class, method) pair for serialization risk.
    #[must_use]
    pub fn check(class: &str, method: &str) -> Option<(u8, &'static str)> {
        DANGEROUS_SERIAL
            .iter()
            .find(|(c, m, _, _)| class.starts_with(c) && *m == method)
            .map(|(_, _, risk, desc)| (*risk, *desc))
    }

    /// Record a method call.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        if let Some((risk, description)) = Self::check(class, method) {
            if method == "readObject" || method == "readUnshared" || method == "readExternal" {
                self.has_readobject = true;
            }
            if risk >= 95 {
                self.gadget_classes.insert(class.to_string());
            }
            self.records.push(SerializationRecord {
                address,
                class: class.to_string(),
                method: method.to_string(),
                risk,
                description: description.to_string(),
            });
        }
    }

    /// Whether critical serialization risks were found.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.records.iter().any(|r| r.risk >= 85)
            || !self.gadget_classes.is_empty()
            || self.has_readobject
    }

    /// Max risk level.
    #[must_use]
    pub fn max_risk(&self) -> u8 {
        self.records.iter().map(|r| r.risk).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Reflection Security
// ---------------------------------------------------------------------------

/// A reflection-related security record.
#[derive(Debug, Clone)]
pub struct ReflectionSecRecord {
    pub address: u64,
    pub class: String,
    pub method: String,
    pub is_accessibility_override: bool,
    pub risk: u8,
}

/// Dangerous reflection patterns.
const DANGEROUS_REFLECT: &[(&str, &str, u8)] = &[
    ("java/lang/reflect/AccessibleObject", "setAccessible", 90),
    ("java/lang/reflect/Field", "set", 80),
    ("java/lang/reflect/Field", "get", 60),
    ("java/lang/reflect/Method", "invoke", 70),
    ("java/lang/reflect/Constructor", "newInstance", 75),
    ("java/lang/Class", "forName", 65),
    ("java/lang/Class", "getDeclaredMethod", 60),
    ("java/lang/Class", "getDeclaredField", 60),
    ("sun/misc/Unsafe", "allocateInstance", 95),
    ("sun/misc/Unsafe", "putObject", 95),
    ("sun/misc/Unsafe", "getObject", 80),
    ("jdk/internal/misc/Unsafe", "allocateInstance", 95),
];

/// Reflection security analyzer.
#[derive(Debug, Clone, Default)]
pub struct ReflectionSecurity {
    pub records: Vec<ReflectionSecRecord>,
    /// Whether `setAccessible(true)` was found.
    pub has_set_accessible: bool,
    /// Whether `Unsafe` was accessed.
    pub has_unsafe: bool,
}

impl ReflectionSecurity {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a call.
    #[must_use]
    pub fn check(class: &str, method: &str) -> Option<u8> {
        DANGEROUS_REFLECT
            .iter()
            .find(|(c, m, _)| *c == class && *m == method)
            .map(|(_, _, risk)| *risk)
    }

    /// Record a method call.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        if let Some(risk) = Self::check(class, method) {
            let is_acc = method == "setAccessible";
            let is_unsafe = class.contains("Unsafe");
            if is_acc {
                self.has_set_accessible = true;
            }
            if is_unsafe {
                self.has_unsafe = true;
            }
            self.records.push(ReflectionSecRecord {
                address,
                class: class.to_string(),
                method: method.to_string(),
                is_accessibility_override: is_acc,
                risk,
            });
        }
    }

    /// Whether dangerous reflection is used.
    #[must_use]
    pub const fn is_dangerous(&self) -> bool {
        self.has_set_accessible || self.has_unsafe || self.records.len() > 3
    }

    /// Max risk found.
    #[must_use]
    pub fn max_risk(&self) -> u8 {
        self.records.iter().map(|r| r.risk).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// A JVM security finding.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub address: u64,
    pub message: String,
    pub risk: u8,
}

/// Top-level JVM security analysis facade.
#[derive(Debug, Clone)]
pub struct JvmSecurity {
    /// `SecurityManager` analysis.
    pub security_manager: JavaSecurityManager,
    /// Privileged block analysis.
    pub privileged: PrivilegedBlock,
    /// `ClassLoader` abuse.
    pub classloader: ClassLoaderAbuse,
    /// Serialization risk.
    pub serialization: SerializationRisk,
    /// Reflection security.
    pub reflection: ReflectionSecurity,
    /// Findings.
    pub findings: Vec<SecurityFinding>,
    /// Total method calls analyzed.
    pub total_calls: usize,
}

impl Default for JvmSecurity {
    fn default() -> Self {
        Self::new()
    }
}

impl JvmSecurity {
    /// Create a new JVM security analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            security_manager: JavaSecurityManager::new(),
            privileged: PrivilegedBlock::new(),
            classloader: ClassLoaderAbuse::new(),
            serialization: SerializationRisk::new(),
            reflection: ReflectionSecurity::new(),
            findings: Vec::new(),
            total_calls: 0,
        }
    }

    /// Record a method call and route to appropriate sub-analyzers.
    pub fn record_call(&mut self, address: u64, class: &str, method: &str) {
        self.total_calls += 1;
        // SecurityManager
        if class == "java/lang/SecurityManager" {
            self.security_manager.record_check(address, method);
        }
        // AccessController
        if class == "java/security/AccessController" && method.starts_with("doPrivileged") {
            self.privileged.record(
                address,
                method.contains("Exception"),
                method.contains("Context"),
            );
        }
        // ClassLoader
        if let Some((risk, desc)) = ClassLoaderAbuse::check(class, method) {
            self.classloader.record_call(address, class, method);
            self.findings.push(SecurityFinding {
                address,
                message: format!("ClassLoader: {desc}"),
                risk,
            });
        }
        // Serialization
        if let Some((risk, desc)) = SerializationRisk::check(class, method) {
            self.serialization.record_call(address, class, method);
            self.findings.push(SecurityFinding {
                address,
                message: format!("Serialization: {desc}"),
                risk,
            });
        }
        // Reflection
        if let Some(risk) = ReflectionSecurity::check(class, method) {
            self.reflection.record_call(address, class, method);
            self.findings.push(SecurityFinding {
                address,
                message: format!("Reflection: {class}.{method}"),
                risk,
            });
        }
    }

    /// Overall risk score (0–100).
    #[must_use]
    pub fn risk_score(&self) -> u8 {
        let mut score: u32 = 0;
        score += u32::from(self.classloader.max_risk()) / 4;
        score += u32::from(self.serialization.max_risk()) / 4;
        score += u32::from(self.reflection.max_risk()) / 4;
        if self.security_manager.bypass_detected {
            score += 25;
        }
        score.min(100) as u8
    }

    /// Whether the analyzed binary is high-risk.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.risk_score() >= 50
            || self.serialization.is_critical()
            || self.classloader.in_memory_loading
            || self.reflection.has_unsafe
    }

    /// High-risk findings (risk >= threshold).
    #[must_use]
    pub fn high_risk_findings(&self, threshold: u8) -> Vec<&SecurityFinding> {
        self.findings
            .iter()
            .filter(|f| f.risk >= threshold)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── PermissionKind ────────────────────────────────────────────────────────

    #[test]
    fn test_permission_from_method() {
        assert_eq!(
            PermissionKind::from_method("checkRead"),
            PermissionKind::FileRead
        );
        assert_eq!(
            PermissionKind::from_method("checkExec"),
            PermissionKind::RuntimeExec
        );
        assert_eq!(
            PermissionKind::from_method("unknownMethod"),
            PermissionKind::Unknown
        );
    }

    #[test]
    fn test_permission_risk_levels() {
        assert_eq!(PermissionKind::RuntimeExec.risk_level(), 2);
        assert_eq!(PermissionKind::FileWrite.risk_level(), 1);
        assert_eq!(PermissionKind::FileRead.risk_level(), 0);
    }

    // ── JavaSecurityManager ───────────────────────────────────────────────────

    #[test]
    fn test_security_manager_record_check() {
        let mut sm = JavaSecurityManager::new();
        sm.record_check(0x1000, "checkRead");
        assert_eq!(sm.checks.len(), 1);
        assert!(sm.permissions_checked.contains(&PermissionKind::FileRead));
    }

    #[test]
    fn test_security_manager_high_risk() {
        let mut sm = JavaSecurityManager::new();
        sm.record_check(0x1000, "checkExec");
        assert_eq!(sm.high_risk_checks().len(), 1);
    }

    #[test]
    fn test_security_manager_bypass() {
        let mut sm = JavaSecurityManager::new();
        sm.record_bypass(0x2000);
        assert!(sm.bypass_detected);
    }

    #[test]
    fn test_security_manager_no_checks_initially() {
        let sm = JavaSecurityManager::new();
        assert!(!sm.has_security_checks());
    }

    // ── PrivilegedBlock ───────────────────────────────────────────────────────

    #[test]
    fn test_privileged_record() {
        let mut pb = PrivilegedBlock::new();
        pb.record(0x1000, false, false);
        assert_eq!(pb.count(), 1);
        assert_eq!(pb.max_nesting, 1);
    }

    #[test]
    fn test_privileged_nesting() {
        let mut pb = PrivilegedBlock::new();
        pb.record(0x1000, false, false);
        pb.record(0x1010, false, false);
        pb.record(0x1020, false, true);
        assert_eq!(pb.max_nesting, 3);
    }

    #[test]
    fn test_privileged_context_limited() {
        let mut pb = PrivilegedBlock::new();
        pb.record(0x1000, false, true);
        pb.record(0x1010, false, false);
        assert_eq!(pb.context_limited_calls().len(), 1);
    }

    #[test]
    fn test_privileged_is_suspicious_many_calls() {
        let mut pb = PrivilegedBlock::new();
        for i in 0..6 {
            pb.record(crate::numeric::i32_to_u64(i), false, false);
        }
        assert!(pb.is_suspicious());
    }

    // ── ClassLoaderAbuse ──────────────────────────────────────────────────────

    #[test]
    fn test_classloader_check_dangerous() {
        assert!(ClassLoaderAbuse::check("java/lang/ClassLoader", "defineClass").is_some());
        assert!(ClassLoaderAbuse::check("java/io/File", "read").is_none());
    }

    #[test]
    fn test_classloader_record_dex() {
        let mut cl = ClassLoaderAbuse::new();
        cl.record_call(0x1000, "dalvik/system/DexClassLoader", "<init>");
        assert!(cl.dynamic_dex);
        assert!(cl.is_suspicious());
    }

    #[test]
    fn test_classloader_record_in_memory() {
        let mut cl = ClassLoaderAbuse::new();
        cl.record_call(0x1000, "dalvik/system/InMemoryDexClassLoader", "<init>");
        assert!(cl.in_memory_loading);
    }

    #[test]
    fn test_classloader_max_risk() {
        let mut cl = ClassLoaderAbuse::new();
        cl.record_call(0x1000, "java/lang/ClassLoader", "defineClass");
        assert_eq!(cl.max_risk(), 90);
    }

    #[test]
    fn test_classloader_high_risk_records() {
        let mut cl = ClassLoaderAbuse::new();
        cl.record_call(0x1000, "dalvik/system/InMemoryDexClassLoader", "<init>");
        let high = cl.high_risk_records(90);
        assert_eq!(high.len(), 1);
    }

    // ── SerializationRisk ─────────────────────────────────────────────────────

    #[test]
    fn test_serial_readobject() {
        let mut sr = SerializationRisk::new();
        sr.record_call(0x1000, "java/io/ObjectInputStream", "readObject");
        assert!(sr.has_readobject);
        assert!(sr.is_critical());
    }

    #[test]
    fn test_serial_gadget_detection() {
        let mut sr = SerializationRisk::new();
        sr.record_call(
            0x2000,
            "org/apache/commons/collections",
            "InvokerTransformer",
        );
        assert!(!sr.gadget_classes.is_empty());
    }

    #[test]
    fn test_serial_max_risk() {
        let mut sr = SerializationRisk::new();
        sr.record_call(0x1000, "java/io/ObjectInputStream", "readObject");
        assert_eq!(sr.max_risk(), 95);
    }

    #[test]
    fn test_serial_not_critical_writeonly() {
        let mut sr = SerializationRisk::new();
        sr.record_call(0x1000, "java/io/ObjectOutputStream", "writeObject");
        assert!(!sr.is_critical());
    }

    // ── ReflectionSecurity ────────────────────────────────────────────────────

    #[test]
    fn test_reflect_set_accessible() {
        let mut rs = ReflectionSecurity::new();
        rs.record_call(
            0x1000,
            "java/lang/reflect/AccessibleObject",
            "setAccessible",
        );
        assert!(rs.has_set_accessible);
        assert!(rs.is_dangerous());
    }

    #[test]
    fn test_reflect_unsafe() {
        let mut rs = ReflectionSecurity::new();
        rs.record_call(0x2000, "sun/misc/Unsafe", "allocateInstance");
        assert!(rs.has_unsafe);
        assert_eq!(rs.max_risk(), 95);
    }

    #[test]
    fn test_reflect_max_risk_method_invoke() {
        let mut rs = ReflectionSecurity::new();
        rs.record_call(0x1000, "java/lang/reflect/Method", "invoke");
        assert_eq!(rs.max_risk(), 70);
    }

    #[test]
    fn test_reflect_not_dangerous_initially() {
        let rs = ReflectionSecurity::new();
        assert!(!rs.is_dangerous());
    }

    // ── JvmSecurity ───────────────────────────────────────────────────────────

    #[test]
    fn test_jvm_record_classloader_call() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "java/lang/ClassLoader", "defineClass");
        assert!(jvm.classloader.is_suspicious());
        assert!(!jvm.findings.is_empty());
    }

    #[test]
    fn test_jvm_record_serial_call() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x2000, "java/io/ObjectInputStream", "readObject");
        assert!(jvm.serialization.has_readobject);
    }

    #[test]
    fn test_jvm_record_reflection_call() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x3000, "sun/misc/Unsafe", "allocateInstance");
        assert!(jvm.reflection.has_unsafe);
    }

    #[test]
    fn test_jvm_is_high_risk_unsafe() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "sun/misc/Unsafe", "allocateInstance");
        assert!(jvm.is_high_risk());
    }

    #[test]
    fn test_jvm_risk_score_zero_initially() {
        let jvm = JvmSecurity::new();
        assert_eq!(jvm.risk_score(), 0);
    }

    #[test]
    fn test_jvm_high_risk_findings() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "java/io/ObjectInputStream", "readObject");
        let high = jvm.high_risk_findings(90);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_jvm_total_calls() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "java/lang/String", "toString");
        jvm.record_call(0x1004, "java/io/PrintStream", "println");
        assert_eq!(jvm.total_calls, 2);
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_permission_all_kinds() {
        let kinds = [
            ("checkWrite", PermissionKind::FileWrite),
            ("checkDelete", PermissionKind::FileDelete),
            ("checkConnect", PermissionKind::NetworkConnect),
            ("checkListen", PermissionKind::NetworkListen),
            ("checkAccept", PermissionKind::NetworkAccept),
            ("checkExit", PermissionKind::RuntimeExit),
        ];
        for (method, expected) in &kinds {
            assert_eq!(PermissionKind::from_method(method), *expected);
        }
    }

    #[test]
    fn test_privileged_exit() {
        let mut pb = PrivilegedBlock::new();
        pb.record(0x1000, false, false);
        pb.record(0x1010, false, false);
        pb.exit();
        assert_eq!(pb.nested_depth, 1);
    }

    #[test]
    fn test_classloader_url_loader() {
        let mut cl = ClassLoaderAbuse::new();
        cl.record_call(0x1000, "java/net/URLClassLoader", "<init>");
        assert!(cl.is_suspicious());
        assert_eq!(cl.max_risk(), 80);
    }

    #[test]
    fn test_serial_externalizable() {
        let mut sr = SerializationRisk::new();
        sr.record_call(0x1000, "java/io/Externalizable", "readExternal");
        assert!(sr.has_readobject);
        assert!(sr.is_critical()); // risk = 85 >= 90? No. Let's just check records.
        assert_eq!(sr.records.len(), 1);
        assert_eq!(sr.max_risk(), 85);
    }

    #[test]
    fn test_reflect_class_for_name() {
        let mut rs = ReflectionSecurity::new();
        rs.record_call(0x1000, "java/lang/Class", "forName");
        assert_eq!(rs.max_risk(), 65);
        assert!(!rs.has_set_accessible);
    }

    #[test]
    fn test_jvm_security_manager_check() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "java/lang/SecurityManager", "checkExec");
        assert!(jvm.security_manager.has_security_checks());
        assert!(
            jvm.security_manager
                .permissions_checked
                .contains(&PermissionKind::RuntimeExec)
        );
    }

    #[test]
    fn test_jvm_privileged_block() {
        let mut jvm = JvmSecurity::new();
        jvm.record_call(0x1000, "java/security/AccessController", "doPrivileged");
        assert_eq!(jvm.privileged.count(), 1);
    }
}
