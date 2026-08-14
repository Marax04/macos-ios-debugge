//! Smali static analysis: suspicious pattern detection (reflection, crypto, URLs/IPs),
//! inter-method data flow tracking, Smali-level call graph construction.

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SmaliAnalysisError {
    #[error("parse error in {class}: {msg}")]
    ParseError { class: String, msg: String },
    #[error("class not found: {0}")]
    ClassNotFound(String),
}

pub type SmaliAnalysisResult<T> = Result<T, SmaliAnalysisError>;

// ── Suspicious pattern categories ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspiciousPatternKind {
    ReflectionApiCall,
    DynamicClassLoading,
    CryptoApiCall,
    NetworkUrl,
    EmbeddedIpAddress,
    EmbeddedCommand,
    NativeMethod,
    PrivilegedOperation,
    AccessibilityAbuse,
    SmsAbuse,
    ContactAccess,
    LocationAccess,
    CameraAccess,
    OverlayWindow,
    DeviceAdminAbuse,
    AntiAnalysis,
    ObfuscatedString,
}

impl SuspiciousPatternKind {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReflectionApiCall => "reflection API call",
            Self::DynamicClassLoading => "dynamic class loading",
            Self::CryptoApiCall => "crypto API call",
            Self::NetworkUrl => "network URL reference",
            Self::EmbeddedIpAddress => "embedded IP address",
            Self::EmbeddedCommand => "shell command",
            Self::NativeMethod => "native method",
            Self::PrivilegedOperation => "privileged operation",
            Self::AccessibilityAbuse => "accessibility service abuse",
            Self::SmsAbuse => "SMS manipulation",
            Self::ContactAccess => "contact access",
            Self::LocationAccess => "location access",
            Self::CameraAccess => "camera access",
            Self::OverlayWindow => "overlay window",
            Self::DeviceAdminAbuse => "device admin abuse",
            Self::AntiAnalysis => "anti-analysis technique",
            Self::ObfuscatedString => "possibly obfuscated string",
        }
    }

    #[must_use] 
    pub const fn severity(self) -> u32 {
        match self {
            Self::DeviceAdminAbuse | Self::AntiAnalysis => 10,
            Self::DynamicClassLoading | Self::ReflectionApiCall | Self::EmbeddedCommand => 8,
            Self::OverlayWindow | Self::SmsAbuse | Self::AccessibilityAbuse => 7,
            Self::CryptoApiCall | Self::EmbeddedIpAddress | Self::PrivilegedOperation => 6,
            Self::NativeMethod | Self::CameraAccess | Self::ContactAccess => 4,
            Self::NetworkUrl | Self::LocationAccess => 3,
            Self::ObfuscatedString => 2,
        }
    }
}

// ── Suspicious finding ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFinding {
    pub kind: SuspiciousPatternKind,
    pub class: String,
    pub method: String,
    pub line_number: usize,
    pub evidence: String,
    pub severity: u32,
}

// ── Signature tables ──────────────────────────────────────────────────────────

const REFLECTION_SIGS: &[&str] = &[
    "Ljava/lang/Class;->forName(",
    "Ljava/lang/Class;->getDeclaredMethod(",
    "Ljava/lang/Class;->getMethod(",
    "Ljava/lang/reflect/Method;->invoke(",
    "Ljava/lang/ClassLoader;->loadClass(",
    "Ldalvik/system/DexClassLoader;-><init>(",
    "Ldalvik/system/PathClassLoader;-><init>(",
    "Ldalvik/system/InMemoryDexClassLoader;-><init>(",
];

const CRYPTO_SIGS: &[&str] = &[
    "Ljavax/crypto/Cipher;->getInstance(",
    "Ljavax/crypto/Cipher;->doFinal(",
    "Ljavax/crypto/SecretKeySpec;-><init>(",
    "Ljavax/crypto/KeyGenerator;->getInstance(",
    "Ljava/security/MessageDigest;->getInstance(",
    "Ljava/security/Signature;->getInstance(",
    "Ljavax/crypto/Mac;->getInstance(",
];

const PRIVILEGED_SIGS: &[&str] = &[
    "Ljava/lang/Runtime;->exec(",
    "Ljava/lang/ProcessBuilder;-><init>(",
    "Landroid/app/admin/DevicePolicyManager;->",
    "Landroid/content/pm/PackageInstaller;->",
];

const ANTI_ANALYSIS_SIGS: &[&str] = &[
    "Landroid/os/Debug;->isDebuggerConnected(",
    "Landroid/os/Debug;->waitingForDebugger(",
];

const SMS_SIGS: &[&str] = &[
    "Landroid/telephony/SmsManager;->sendTextMessage(",
    "Landroid/telephony/SmsManager;->sendMultipartTextMessage(",
];

const _OVERLAY_SIGS: &[&str] = &[
    "Landroid/view/WindowManager;->addView(",
    "TYPE_APPLICATION_OVERLAY",
    "TYPE_SYSTEM_ALERT",
];

const SHELL_STRINGS: &[&str] = &[
    "su ", "su\n", "/system/bin/sh", "/bin/sh",
    "chmod 777", "chmod 4755",
    "mount -o remount",
    "pm install", "pm uninstall",
    "am start", "am broadcast",
];

// ── Smali method node ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliMethodNode {
    pub class: String,
    pub name: String,
    pub proto: String,
    pub is_native: bool,
    pub is_static: bool,
    pub is_public: bool,
    pub instruction_count: usize,
    pub calls: Vec<CallEdge>,
    pub strings: Vec<String>,
    pub findings: Vec<SuspiciousFinding>,
}

impl SmaliMethodNode {
    #[must_use] 
    pub fn full_ref(&self) -> String {
        format!("{}->{}{}", self.class, self.name, self.proto)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub target_class: String,
    pub target_method: String,
    pub target_proto: String,
    pub invoke_kind: InvokeKind,
    pub call_line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvokeKind {
    Virtual,
    Static,
    Direct,
    Super,
    Interface,
}

impl InvokeKind {
    fn from_opcode(op: &str) -> Self {
        match op.trim() {
            s if s.starts_with("invoke-virtual") => Self::Virtual,
            s if s.starts_with("invoke-static") => Self::Static,
            s if s.starts_with("invoke-direct") => Self::Direct,
            s if s.starts_with("invoke-super") => Self::Super,
            s if s.starts_with("invoke-interface") => Self::Interface,
            _ => Self::Virtual,
        }
    }
}

// ── Method parser ─────────────────────────────────────────────────────────────

#[must_use] 
pub fn parse_smali_method(class: &str, method_text: &str) -> SmaliMethodNode {
    let mut name = String::new();
    let mut proto = String::new();
    let mut is_native = false;
    let mut is_static = false;
    let mut is_public = false;
    let mut instruction_count = 0usize;
    let mut calls = Vec::new();
    let mut strings = Vec::new();

    for (lineno, line) in method_text.lines().enumerate() {
        let t = line.trim();

        if t.starts_with(".method ") {
            let sig = t.strip_prefix(".method ").unwrap_or(t);
            is_native = sig.contains("native");
            is_static = sig.contains("static");
            is_public = sig.contains("public");
            let after_flags = sig.split_whitespace().last().unwrap_or(sig);
            if let Some(paren) = after_flags.find('(') {
                after_flags[..paren].clone_into(&mut name);
                after_flags[paren..].clone_into(&mut proto);
            } else {
                after_flags.clone_into(&mut name);
            }
            continue;
        }

        if t.starts_with(".end method") || t.starts_with(".method") {
            continue;
        }

        if !t.is_empty() && !t.starts_with('.') && !t.starts_with(':') && !t.starts_with('#') {
            instruction_count += 1;
        }

        if t.starts_with("const-string")
            && let Some(q1) = t.find('"')
                && let Some(q2) = t[q1 + 1..].find('"') {
                    strings.push(t[q1 + 1..q1 + 1 + q2].to_owned());
                }

        if t.starts_with("invoke-") {
            let kind = InvokeKind::from_opcode(t);
            if let Some(comma) = t.rfind("},") {
                let method_ref = t[comma + 2..].trim();
                if let Some(arrow) = method_ref.find("->") {
                    let tgt_class = method_ref[..arrow].to_owned();
                    let rest = &method_ref[arrow + 2..];
                    let (tgt_method, tgt_proto) = if let Some(paren) = rest.find('(') {
                        (rest[..paren].to_owned(), rest[paren..].to_owned())
                    } else {
                        (rest.to_owned(), String::new())
                    };
                    calls.push(CallEdge {
                        target_class: tgt_class,
                        target_method: tgt_method,
                        target_proto: tgt_proto,
                        invoke_kind: kind,
                        call_line: lineno,
                    });
                }
            }
        }
    }

    SmaliMethodNode {
        class: class.to_owned(),
        name,
        proto,
        is_native,
        is_static,
        is_public,
        instruction_count,
        calls,
        strings,
        findings: Vec::new(),
    }
}

// ── Suspicious pattern scanner ────────────────────────────────────────────────

pub struct SuspiciousPatternScanner;

impl SuspiciousPatternScanner {
    pub fn scan(node: &mut SmaliMethodNode) {
        for call in &node.calls {
            let target_ref = format!("{}->{}", call.target_class, call.target_method);

            for sig in REFLECTION_SIGS {
                if target_ref.contains(&sig[..sig.find('(').unwrap_or(sig.len())]) {
                    let kind = if sig.contains("ClassLoader") {
                        SuspiciousPatternKind::DynamicClassLoading
                    } else {
                        SuspiciousPatternKind::ReflectionApiCall
                    };
                    node.findings.push(SuspiciousFinding {
                        kind,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: call.call_line,
                        evidence: format!("calls {target_ref}"),
                        severity: kind.severity(),
                    });
                }
            }

            for sig in CRYPTO_SIGS {
                if target_ref.contains(&sig[..sig.find('(').unwrap_or(sig.len())]) {
                    node.findings.push(SuspiciousFinding {
                        kind: SuspiciousPatternKind::CryptoApiCall,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: call.call_line,
                        evidence: format!("crypto: {target_ref}"),
                        severity: SuspiciousPatternKind::CryptoApiCall.severity(),
                    });
                }
            }

            for sig in PRIVILEGED_SIGS {
                if target_ref.contains(&sig[..sig.find('(').unwrap_or(sig.len())]) {
                    node.findings.push(SuspiciousFinding {
                        kind: SuspiciousPatternKind::PrivilegedOperation,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: call.call_line,
                        evidence: format!("privileged: {target_ref}"),
                        severity: SuspiciousPatternKind::PrivilegedOperation.severity(),
                    });
                }
            }

            for sig in SMS_SIGS {
                if target_ref.contains(&sig[..sig.find('(').unwrap_or(sig.len())]) {
                    node.findings.push(SuspiciousFinding {
                        kind: SuspiciousPatternKind::SmsAbuse,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: call.call_line,
                        evidence: format!("SMS: {target_ref}"),
                        severity: SuspiciousPatternKind::SmsAbuse.severity(),
                    });
                }
            }

            for sig in ANTI_ANALYSIS_SIGS {
                if target_ref.contains(&sig[..sig.find('(').unwrap_or(sig.len())]) {
                    node.findings.push(SuspiciousFinding {
                        kind: SuspiciousPatternKind::AntiAnalysis,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: call.call_line,
                        evidence: format!("anti-debug: {target_ref}"),
                        severity: SuspiciousPatternKind::AntiAnalysis.severity(),
                    });
                }
            }
        }

        for s in &node.strings {
            if s.starts_with("http://") || s.starts_with("https://") {
                node.findings.push(SuspiciousFinding {
                    kind: SuspiciousPatternKind::NetworkUrl,
                    class: node.class.clone(),
                    method: node.name.clone(),
                    line_number: 0,
                    evidence: format!("URL: {s}"),
                    severity: SuspiciousPatternKind::NetworkUrl.severity(),
                });
            }
            if is_ip_address(s) {
                node.findings.push(SuspiciousFinding {
                    kind: SuspiciousPatternKind::EmbeddedIpAddress,
                    class: node.class.clone(),
                    method: node.name.clone(),
                    line_number: 0,
                    evidence: format!("IP: {s}"),
                    severity: SuspiciousPatternKind::EmbeddedIpAddress.severity(),
                });
            }
            for cmd in SHELL_STRINGS {
                if s.contains(cmd) {
                    node.findings.push(SuspiciousFinding {
                        kind: SuspiciousPatternKind::EmbeddedCommand,
                        class: node.class.clone(),
                        method: node.name.clone(),
                        line_number: 0,
                        evidence: format!("shell cmd: {s}"),
                        severity: SuspiciousPatternKind::EmbeddedCommand.severity(),
                    });
                }
            }
        }

        if node.is_native {
            node.findings.push(SuspiciousFinding {
                kind: SuspiciousPatternKind::NativeMethod,
                class: node.class.clone(),
                method: node.name.clone(),
                line_number: 0,
                evidence: "native (JNI) method".into(),
                severity: SuspiciousPatternKind::NativeMethod.severity(),
            });
        }
    }
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── Call graph ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmaliCallGraph {
    pub nodes: HashMap<String, SmaliMethodNode>,
    pub edges: HashMap<String, Vec<String>>,
    pub reverse_edges: HashMap<String, Vec<String>>,
}

impl SmaliCallGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: SmaliMethodNode) {
        let key = node.full_ref();
        for call in &node.calls {
            let callee = format!("{}->{}{}", call.target_class, call.target_method, call.target_proto);
            self.edges.entry(key.clone()).or_default().push(callee.clone());
            self.reverse_edges.entry(callee).or_default().push(key.clone());
        }
        self.nodes.insert(key, node);
    }

    #[must_use] 
    pub fn callees_of(&self, method: &str) -> Vec<&str> {
        self.edges
            .get(method)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    #[must_use] 
    pub fn callers_of(&self, method: &str) -> Vec<&str> {
        self.reverse_edges
            .get(method)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    #[must_use] 
    pub fn reachable_from(&self, start: &str, max_depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((start.to_owned(), 0usize));
        while let Some((current, depth)) = queue.pop_front() {
            if visited.contains(&current) || depth > max_depth {
                continue;
            }
            visited.insert(current.clone());
            if let Some(callees) = self.edges.get(&current) {
                for callee in callees {
                    queue.push_back((callee.clone(), depth + 1));
                }
            }
        }
        visited.remove(start);
        visited
    }

    #[must_use] 
    pub fn find_paths_to_suspicious(&self, start: &str) -> Vec<Vec<String>> {
        let suspicious: HashSet<&str> = self.nodes
            .iter()
            .filter(|(_, n)| !n.findings.is_empty())
            .map(|(k, _)| k.as_str())
            .collect();

        let mut paths = Vec::new();
        let mut stack: Vec<(String, Vec<String>)> = vec![(start.to_owned(), vec![start.to_owned()])];
        let mut visited = HashSet::new();

        while let Some((current, path)) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            if suspicious.contains(current.as_str()) && current != start {
                paths.push(path.clone());
            }
            visited.insert(current.clone());
            if let Some(callees) = self.edges.get(&current) {
                for callee in callees {
                    if !visited.contains(callee) {
                        let mut new_path = path.clone();
                        new_path.push(callee.clone());
                        stack.push((callee.clone(), new_path));
                    }
                }
            }
        }
        paths
    }
}

// ── Data flow ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowFact {
    pub register: String,
    pub source: DataFlowSource,
    pub value_hint: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFlowSource {
    Constant,
    Parameter,
    FieldRead,
    MethodReturn,
    ArrayElement,
    Unknown,
}

impl DataFlowSource {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Constant => "constant",
            Self::Parameter => "parameter",
            Self::FieldRead => "field read",
            Self::MethodReturn => "method return",
            Self::ArrayElement => "array element",
            Self::Unknown => "unknown",
        }
    }
}

#[must_use] 
pub fn intra_method_data_flow(method_text: &str) -> Vec<DataFlowFact> {
    let mut facts = Vec::new();
    for (lineno, line) in method_text.lines().enumerate() {
        let t = line.trim();

        if t.starts_with("const-string")
            && let Some((reg_part, rest)) = t.split_once(',') {
                let reg = reg_part.split_whitespace().last().unwrap_or("").to_owned();
                let value = rest.trim().trim_matches('"').to_owned();
                facts.push(DataFlowFact {
                    register: reg,
                    source: DataFlowSource::Constant,
                    value_hint: Some(value),
                    line: lineno,
                });
            }

        if (t.starts_with("const/4") || t.starts_with("const/16") || t.starts_with("const-wide"))
            && let Some((reg_part, val_part)) = t.split_once(',') {
                let reg = reg_part.split_whitespace().last().unwrap_or("").to_owned();
                facts.push(DataFlowFact {
                    register: reg,
                    source: DataFlowSource::Constant,
                    value_hint: Some(val_part.trim().to_owned()),
                    line: lineno,
                });
            }

        if t.starts_with("move-result") {
            let reg = t.split_whitespace().last().unwrap_or("").to_owned();
            facts.push(DataFlowFact {
                register: reg,
                source: DataFlowSource::MethodReturn,
                value_hint: None,
                line: lineno,
            });
        }

        if (t.starts_with("iget") || t.starts_with("sget"))
            && let Some(reg) = t.split_whitespace().nth(1) {
                facts.push(DataFlowFact {
                    register: reg.trim_end_matches(',').to_owned(),
                    source: DataFlowSource::FieldRead,
                    value_hint: None,
                    line: lineno,
                });
            }
    }
    facts
}

// ── Whole-class analyzer ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmaliClassAnalysis {
    pub class_descriptor: String,
    pub methods: Vec<SmaliMethodNode>,
    pub findings: Vec<SuspiciousFinding>,
    pub call_graph: SmaliCallGraph,
    pub total_instructions: usize,
}

impl SmaliClassAnalysis {
    #[must_use] 
    pub fn from_smali_text(class_descriptor: &str, smali: &str) -> Self {
        let mut analysis = Self {
            class_descriptor: class_descriptor.to_owned(),
            ..Default::default()
        };

        let mut in_method = false;
        let mut method_lines: Vec<String> = Vec::new();
        let mut methods = Vec::new();

        for line in smali.lines() {
            let t = line.trim();
            if t.starts_with(".method ") {
                in_method = true;
                method_lines.clear();
                method_lines.push(line.to_owned());
            } else if t == ".end method" && in_method {
                method_lines.push(line.to_owned());
                let method_text = method_lines.join("\n");
                let mut node = parse_smali_method(class_descriptor, &method_text);
                SuspiciousPatternScanner::scan(&mut node);
                analysis.total_instructions += node.instruction_count;
                analysis.findings.extend(node.findings.clone());
                methods.push(node);
                in_method = false;
            } else if in_method {
                method_lines.push(line.to_owned());
            }
        }

        for method in &methods {
            analysis.call_graph.add_node(method.clone());
        }
        analysis.methods = methods;
        analysis
    }

    #[must_use] 
    pub fn high_severity_findings(&self) -> Vec<&SuspiciousFinding> {
        self.findings.iter().filter(|f| f.severity >= 7).collect()
    }

    #[must_use] 
    pub fn risk_score(&self) -> u32 {
        self.findings.iter().map(|f| f.severity).sum()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SMALI: &str = r#".class public Lcom/example/Malware;
.super Ljava/lang/Object;

.method public isRooted()Z
    .locals 1
    const-string v0, "/bin/su"
    invoke-virtual {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    const/4 v0, #0
    return v0
.end method

.method public decrypt(I)Ljava/lang/String;
    .locals 1
    invoke-static {p1}, La/b;->a(I)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
"#;

    #[test]
    fn test_class_analysis() {
        let analysis = SmaliClassAnalysis::from_smali_text("Lcom/example/Malware;", SAMPLE_SMALI);
        assert_eq!(analysis.methods.len(), 2);
    }

    #[test]
    fn test_privileged_call_detection() {
        let analysis = SmaliClassAnalysis::from_smali_text("Lcom/example/Malware;", SAMPLE_SMALI);
        let has_privileged = analysis.findings.iter().any(|f| {
            matches!(f.kind, SuspiciousPatternKind::PrivilegedOperation)
        });
        assert!(has_privileged);
    }

    #[test]
    fn test_call_graph_built() {
        let analysis = SmaliClassAnalysis::from_smali_text("Lcom/example/Malware;", SAMPLE_SMALI);
        assert!(!analysis.call_graph.nodes.is_empty());
    }

    #[test]
    fn test_data_flow() {
        let method = ".method public foo()V\n    .locals 2\n    const-string v0, \"hello\"\n    const/4 v1, #1\n    return-void\n.end method\n";
        let facts = intra_method_data_flow(method);
        assert!(facts.iter().any(|f| matches!(f.source, DataFlowSource::Constant)));
    }

    #[test]
    fn test_parse_method_calls() {
        let method = ".method public static doStuff()V\n    .locals 1\n    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n    return-void\n.end method";
        let node = parse_smali_method("Lcom/example/X;", method);
        assert_eq!(node.calls.len(), 1);
        assert_eq!(node.calls[0].target_class, "Ljava/lang/Class;");
        assert_eq!(node.calls[0].target_method, "forName");
    }

    #[test]
    fn test_ip_detection() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(!is_ip_address("not.an.ip.here"));
    }

    #[test]
    fn test_risk_score() {
        let analysis = SmaliClassAnalysis::from_smali_text("Lcom/example/A;", SAMPLE_SMALI);
        let score = analysis.risk_score();
        assert!(score > 0);
    }

    #[test]
    fn test_reachable_from() {
        let cg = SmaliCallGraph::new();
        let reachable = cg.reachable_from("Lcom/example/A;->foo()V", 3);
        assert!(reachable.is_empty());
    }

    #[test]
    fn test_pattern_severity() {
        assert!(SuspiciousPatternKind::AntiAnalysis.severity() > SuspiciousPatternKind::NetworkUrl.severity());
        assert!(SuspiciousPatternKind::DynamicClassLoading.severity() > SuspiciousPatternKind::CameraAccess.severity());
    }
}
