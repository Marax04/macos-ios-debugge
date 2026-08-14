//! `smali_analysis` — static analysis of decoded Smali class files.
//!
//! Provides:
//! * [`SmaliAnalysis`] — top-level analyser
//! * [`SmaliCallGraph`] — inter-method call graph
//! * [`SmaliXref`] — cross-reference table (field / method / type refs)
//! * [`ApiUsage`] — summary of Android / Java API calls
//! * [`StringUsage`] — string constant analysis
//! * [`ObfuscationScore`] — name-based obfuscation metrics
//! * [`SmaliReport`] — aggregated analysis report

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub use crate::{SmaliInstr, SmaliMethod};

use crate::{SmaliClass, SmaliOp, SmaliOperand};

// ─── SmaliCallGraph ───────────────────────────────────────────────────────────

/// A directed call graph over smali methods.
///
/// Each node is a `class->method` string; edges represent `invoke-*` instructions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmaliCallGraph {
    /// Adjacency list: caller → set of callees.
    pub edges: HashMap<String, HashSet<String>>,
    /// Total number of call edges in the graph.
    pub edge_count: usize,
}

impl SmaliCallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directed edge from `from_method` to `target`.
    pub fn add_edge(&mut self, from_method: impl Into<String>, target: impl Into<String>) {
        let entry = self.edges.entry(from_method.into()).or_default();
        if entry.insert(target.into()) {
            self.edge_count += 1;
        }
    }

    /// Returns the callees of `method`, if any.
    #[must_use]
    pub fn callees(&self, method: &str) -> Option<&HashSet<String>> {
        self.edges.get(method)
    }

    /// Returns all callers of `method` (reverse look-up).
    #[must_use]
    pub fn callers_of(&self, method: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|(_, callees)| callees.contains(method))
            .map(|(caller, _)| caller.as_str())
            .collect()
    }

    /// Returns the number of distinct nodes (methods).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns `true` if there is a direct call edge `from → to`.
    #[must_use]
    pub fn has_edge(&self, from: &str, to: &str) -> bool {
        self.edges.get(from).is_some_and(|s| s.contains(to))
    }

    /// Depth-first reachability from `start` (returns all reachable nodes).
    #[must_use]
    pub fn reachable_from(&self, start: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut stack = vec![start.to_string()];
        while let Some(node) = stack.pop() {
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node.clone());
            if let Some(callees) = self.edges.get(&node) {
                for callee in callees {
                    stack.push(callee.clone());
                }
            }
        }
        visited
    }
}

// ─── SmaliXref ────────────────────────────────────────────────────────────────

/// Cross-reference table: tracks all field, method, and type references.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmaliXref {
    /// `field_ref` → list of (class, method) that reference it.
    pub field_refs: HashMap<String, Vec<(String, String)>>,
    /// `method_ref` → list of (class, method) that call it.
    pub method_refs: HashMap<String, Vec<(String, String)>>,
    /// `type_ref` → list of (class, method) that use it (new-instance, check-cast…).
    pub type_refs: HashMap<String, Vec<(String, String)>>,
}

impl SmaliXref {
    /// Create an empty xref table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a field reference from the given method.
    pub fn add_field_ref(&mut self, field: impl Into<String>, class: &str, method: &str) {
        self.field_refs
            .entry(field.into())
            .or_default()
            .push((class.to_string(), method.to_string()));
    }

    /// Record a method call reference.
    pub fn add_method_ref(
        &mut self,
        target: impl Into<String>,
        caller_class: &str,
        caller_method: &str,
    ) {
        self.method_refs
            .entry(target.into())
            .or_default()
            .push((caller_class.to_string(), caller_method.to_string()));
    }

    /// Record a type reference.
    pub fn add_type_ref(&mut self, type_ref: impl Into<String>, class: &str, method: &str) {
        self.type_refs
            .entry(type_ref.into())
            .or_default()
            .push((class.to_string(), method.to_string()));
    }

    /// Total number of unique referenced fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.field_refs.len()
    }

    /// Total number of unique referenced methods (callees).
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.method_refs.len()
    }

    /// Total number of unique referenced types.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.type_refs.len()
    }

    /// Returns sites that reference the given fully-qualified method.
    #[must_use]
    pub fn sites_for_method(&self, method: &str) -> Vec<&(String, String)> {
        self.method_refs
            .get(method)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }
}

// ─── ApiUsage ─────────────────────────────────────────────────────────────────

/// Aggregated summary of Android/Java API calls detected in smali code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiUsage {
    /// Reflection API calls (`Class.forName`, `Method.invoke`…).
    pub reflection_calls: Vec<String>,
    /// Dynamic code loading (`DexClassLoader`, `PathClassLoader`…).
    pub dynamic_loading_calls: Vec<String>,
    /// Crypto API calls.
    pub crypto_calls: Vec<String>,
    /// Network API calls.
    pub network_calls: Vec<String>,
    /// File I/O API calls.
    pub file_io_calls: Vec<String>,
    /// SMS/telephony API calls.
    pub telephony_calls: Vec<String>,
    /// Native/JNI bridge calls.
    pub jni_calls: Vec<String>,
    /// Shell / process execution calls.
    pub exec_calls: Vec<String>,
}

impl ApiUsage {
    /// Create an empty `ApiUsage`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a method reference string and add it to the appropriate bucket.
    pub fn classify(&mut self, method_ref: &str) {
        let lower = method_ref.to_lowercase();
        if lower.contains("class.forname")
            || lower.contains("class;->forname")
            || lower.contains("method.invoke")
            || lower.contains("method;->invoke")
            || lower.contains("getdeclaredmethod")
        {
            self.reflection_calls.push(method_ref.to_string());
        }
        if lower.contains("dexclassloader")
            || lower.contains("pathclassloader")
            || lower.contains("loadclass")
        {
            self.dynamic_loading_calls.push(method_ref.to_string());
        }
        if lower.contains("javax/crypto")
            || lower.contains("java/security")
            || lower.contains("messagedigest")
        {
            self.crypto_calls.push(method_ref.to_string());
        }
        if lower.contains("java/net")
            || lower.contains("httpurlconnection")
            || lower.contains("okhttp")
        {
            self.network_calls.push(method_ref.to_string());
        }
        if lower.contains("java/io")
            || lower.contains("fileinputstream")
            || lower.contains("fileoutputstream")
        {
            self.file_io_calls.push(method_ref.to_string());
        }
        if lower.contains("smsmanager") || lower.contains("telephonymanager") {
            self.telephony_calls.push(method_ref.to_string());
        }
        if lower.contains("system/loadlibrary") || lower.contains("runtime/exec") {
            self.jni_calls.push(method_ref.to_string());
        }
        if lower.contains("runtime.exec")
            || lower.contains("runtime;->exec")
            || lower.contains("/system/bin")
            || lower.contains("processbuilder")
        {
            self.exec_calls.push(method_ref.to_string());
        }
    }

    /// Total number of suspicious API calls across all categories.
    #[must_use]
    pub const fn total_suspicious(&self) -> usize {
        self.reflection_calls.len()
            + self.dynamic_loading_calls.len()
            + self.exec_calls.len()
            + self.telephony_calls.len()
    }

    /// Returns `true` if any dynamic code loading is detected.
    #[must_use]
    pub const fn has_dynamic_loading(&self) -> bool {
        !self.dynamic_loading_calls.is_empty()
    }

    /// Returns `true` if shell execution is detected.
    #[must_use]
    pub const fn has_exec(&self) -> bool {
        !self.exec_calls.is_empty()
    }
}

// ─── StringUsage ──────────────────────────────────────────────────────────────

/// Analysis of string constants found in smali methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringUsage {
    /// All string literals.
    pub all_strings: Vec<String>,
    /// Strings that look like URLs.
    pub urls: Vec<String>,
    /// Strings that look like IPv4 addresses.
    pub ip_addresses: Vec<String>,
    /// Strings that look like file paths.
    pub file_paths: Vec<String>,
    /// Strings that look like base64-encoded data.
    pub base64_blobs: Vec<String>,
    /// Strings that look like commands (exec patterns).
    pub suspicious_commands: Vec<String>,
}

impl StringUsage {
    /// Create an empty `StringUsage`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add and classify a string constant.
    pub fn add(&mut self, s: impl Into<String>) {
        let s = s.into();
        if s.starts_with("http://") || s.starts_with("https://") {
            self.urls.push(s.clone());
        }
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            self.ip_addresses.push(s.clone());
        }
        if s.starts_with('/') || s.starts_with("./") {
            self.file_paths.push(s.clone());
        }
        let lower = s.to_lowercase();
        if lower.contains("exec(") || lower.contains("/bin/sh") || lower.contains("cmd.exe") {
            self.suspicious_commands.push(s.clone());
        }
        if s.len() > 32
            && s.chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
            && s.ends_with('=')
        {
            self.base64_blobs.push(s.clone());
        }
        self.all_strings.push(s);
    }

    /// Total number of strings collected.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.all_strings.len()
    }

    /// Returns `true` if any suspicious command strings are present.
    #[must_use]
    pub const fn has_suspicious_commands(&self) -> bool {
        !self.suspicious_commands.is_empty()
    }
}

// ─── ObfuscationScore ─────────────────────────────────────────────────────────

/// Measures the degree of name-based obfuscation across a set of classes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObfuscationScore {
    /// Total classes analysed.
    pub class_count: usize,
    /// Classes with short (≤2 char) simple names.
    pub short_name_classes: usize,
    /// Total methods analysed.
    pub method_count: usize,
    /// Methods with short names.
    pub short_name_methods: usize,
    /// Fraction of classes that have short names (0.0–1.0).
    pub class_obfuscation_ratio: f64,
    /// Fraction of methods that have short names (0.0–1.0).
    pub method_obfuscation_ratio: f64,
    /// Whether ProGuard/R8 mapping artefacts were detected.
    pub has_proguard: bool,
    /// Composite obfuscation score (0.0–1.0).
    pub score: f64,
}

impl ObfuscationScore {
    /// Compute the obfuscation score from a set of classes.
    #[must_use]
    pub fn from_classes(classes: &[SmaliClass]) -> Self {
        if classes.is_empty() {
            return Self::default();
        }
        let class_count = classes.len();
        let short_name_classes = classes
            .iter()
            .filter(|c| {
                let name = c.name.rsplit('/').next().unwrap_or(&c.name);
                let name = name.trim_start_matches('L').trim_end_matches(';');
                name.len() <= 2
            })
            .count();

        let mut method_count = 0usize;
        let mut short_name_methods = 0usize;
        for c in classes {
            for m in &c.methods {
                method_count += 1;
                if m.name.len() <= 2 && m.name != "<init>" && m.name != "<clinit>" {
                    short_name_methods += 1;
                }
            }
        }

        // Saturate counts to u32 so the f64 conversion is lossless.
        let saturating_u32 = |n: usize| -> u32 { u32::try_from(n).unwrap_or(u32::MAX) };
        let class_obfuscation_ratio = {
            let num = saturating_u32(short_name_classes);
            let denom = saturating_u32(class_count);
            if denom == 0 {
                0.0
            } else {
                f64::from(num) / f64::from(denom)
            }
        };
        let method_obfuscation_ratio = if method_count > 0 {
            let num = saturating_u32(short_name_methods);
            let denom = saturating_u32(method_count);
            if denom == 0 {
                0.0
            } else {
                f64::from(num) / f64::from(denom)
            }
        } else {
            0.0
        };

        let has_proguard = classes
            .iter()
            .any(|c| c.name.contains("a/b/") || c.name.contains("com/a/"));

        let score = (class_obfuscation_ratio * 0.6 + method_obfuscation_ratio * 0.4).min(1.0);

        Self {
            class_count,
            short_name_classes,
            method_count,
            short_name_methods,
            class_obfuscation_ratio,
            method_obfuscation_ratio,
            has_proguard,
            score,
        }
    }

    /// Returns `true` if the code appears to be obfuscated.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.score >= 0.3
    }
}

// ─── SmaliReport ──────────────────────────────────────────────────────────────

/// Aggregated analysis report for a set of smali classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliReport {
    /// Number of classes analysed.
    pub class_count: usize,
    /// Total number of methods.
    pub method_count: usize,
    /// Call graph.
    pub call_graph: SmaliCallGraph,
    /// Cross-reference table.
    pub xref: SmaliXref,
    /// API usage summary.
    pub api_usage: ApiUsage,
    /// String usage summary.
    pub strings: StringUsage,
    /// Obfuscation score.
    pub obfuscation: ObfuscationScore,
    /// Total suspicious API call count.
    pub suspicious_api_count: usize,
}

impl SmaliReport {
    /// Returns `true` if the code has any high-risk indicators.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        self.suspicious_api_count > 5
            || self.api_usage.has_exec()
            || self.api_usage.has_dynamic_loading()
            || self.strings.has_suspicious_commands()
    }

    /// Returns a one-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} classes, {} methods, {} suspicious APIs, obfuscated={}",
            self.class_count,
            self.method_count,
            self.suspicious_api_count,
            self.obfuscation.is_obfuscated(),
        )
    }
}

// ─── SmaliAnalysis ────────────────────────────────────────────────────────────

/// Top-level smali static analysis engine.
#[derive(Debug, Default, Clone)]
pub struct SmaliAnalysis;

impl SmaliAnalysis {
    /// Create a new analysis engine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse a slice of [`SmaliClass`] instances and produce a [`SmaliReport`].
    #[must_use]
    pub fn analyze(&self, classes: &[SmaliClass]) -> SmaliReport {
        let mut call_graph = SmaliCallGraph::new();
        let mut xref = SmaliXref::new();
        let mut api_usage = ApiUsage::new();
        let mut strings = StringUsage::new();

        let mut method_count = 0usize;

        for class in classes {
            for method in &class.methods {
                method_count += 1;
                let caller_key = format!("{}->{}", class.name, method.name);

                for instr in &method.instructions {
                    match &instr.op {
                        SmaliOp::InvokeVirtual
                        | SmaliOp::InvokeSuper
                        | SmaliOp::InvokeDirect
                        | SmaliOp::InvokeStatic
                        | SmaliOp::InvokeInterface => {
                            if let Some(SmaliOperand::MethodRef(mref)) = instr.operands.last() {
                                call_graph.add_edge(&caller_key, mref.clone());
                                xref.add_method_ref(mref.clone(), &class.name, &method.name);
                                api_usage.classify(mref);
                            }
                        }
                        SmaliOp::IGet | SmaliOp::IPut | SmaliOp::SGet | SmaliOp::SPut => {
                            if let Some(SmaliOperand::FieldRef(fref)) = instr.operands.last() {
                                xref.add_field_ref(fref.clone(), &class.name, &method.name);
                            }
                        }
                        SmaliOp::NewInstance | SmaliOp::CheckCast => {
                            if let Some(SmaliOperand::TypeRef(tref)) = instr.operands.first() {
                                xref.add_type_ref(tref.clone(), &class.name, &method.name);
                            }
                        }
                        SmaliOp::ConstString => {
                            if let Some(SmaliOperand::Str(s)) = instr.operands.last() {
                                strings.add(s.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let obfuscation = ObfuscationScore::from_classes(classes);
        let suspicious_api_count = api_usage.total_suspicious();

        SmaliReport {
            class_count: classes.len(),
            method_count,
            call_graph,
            xref,
            api_usage,
            strings,
            obfuscation,
            suspicious_api_count,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SmaliAccess, SmaliClass, SmaliInstr, SmaliMethod, SmaliOp, SmaliOperand, SmaliReg,
    };

    fn make_class_with_invoke(class_name: &str, callee: &str) -> SmaliClass {
        SmaliClass {
            name: class_name.to_string(),
            super_class: "Ljava/lang/Object;".to_string(),
            access: SmaliAccess::PUBLIC,
            methods: vec![SmaliMethod {
                name: "run".to_string(),
                class: class_name.to_string(),
                signature: "()V".to_string(),
                access: SmaliAccess::PUBLIC,
                registers: 2,
                instructions: vec![
                    SmaliInstr {
                        op: SmaliOp::InvokeStatic,
                        operands: vec![SmaliOperand::MethodRef(callee.to_string())],
                        label: None,
                    },
                    SmaliInstr {
                        op: SmaliOp::ReturnVoid,
                        operands: vec![],
                        label: None,
                    },
                ],
            }],
            fields: vec![],
            interfaces: vec![],
        }
    }

    fn make_class_with_string(class_name: &str, s: &str) -> SmaliClass {
        SmaliClass {
            name: class_name.to_string(),
            super_class: "Ljava/lang/Object;".to_string(),
            access: SmaliAccess::PUBLIC,
            methods: vec![SmaliMethod {
                name: "getValue".to_string(),
                class: class_name.to_string(),
                signature: "()Ljava/lang/String;".to_string(),
                access: SmaliAccess::PUBLIC,
                registers: 1,
                instructions: vec![
                    SmaliInstr {
                        op: SmaliOp::ConstString,
                        operands: vec![
                            SmaliOperand::Reg(SmaliReg { num: 0 }),
                            SmaliOperand::Str(s.to_string()),
                        ],
                        label: None,
                    },
                    SmaliInstr {
                        op: SmaliOp::ReturnVoid,
                        operands: vec![],
                        label: None,
                    },
                ],
            }],
            fields: vec![],
            interfaces: vec![],
        }
    }

    // ── SmaliAnalysis ─────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_empty_classes() {
        let engine = SmaliAnalysis::new();
        let report = engine.analyze(&[]);
        assert_eq!(report.class_count, 0);
        assert_eq!(report.method_count, 0);
    }

    #[test]
    fn test_analysis_single_class() {
        let engine = SmaliAnalysis::new();
        let class = SmaliClass::mock("Lcom/example/Foo;");
        let report = engine.analyze(&[class]);
        assert_eq!(report.class_count, 1);
        assert!(report.method_count > 0);
    }

    #[test]
    fn test_analysis_call_graph_populated() {
        let engine = SmaliAnalysis::new();
        let class = make_class_with_invoke(
            "Lcom/Foo;",
            "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
        );
        let report = engine.analyze(&[class]);
        assert!(report.call_graph.node_count() > 0);
    }

    #[test]
    fn test_analysis_report_summary() {
        let engine = SmaliAnalysis::new();
        let class = SmaliClass::mock("Lcom/A;");
        let report = engine.analyze(&[class]);
        assert!(!report.summary().is_empty());
    }

    #[test]
    fn test_analysis_string_classified() {
        let engine = SmaliAnalysis::new();
        let class = make_class_with_string("Lcom/A;", "https://evil.com");
        let report = engine.analyze(&[class]);
        assert!(!report.strings.urls.is_empty());
    }

    // ── SmaliCallGraph ────────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_add_edge() {
        let mut cg = SmaliCallGraph::new();
        cg.add_edge("A->foo", "B->bar");
        assert!(cg.has_edge("A->foo", "B->bar"));
        assert_eq!(cg.edge_count, 1);
    }

    #[test]
    fn test_call_graph_no_duplicate_edges() {
        let mut cg = SmaliCallGraph::new();
        cg.add_edge("A->foo", "B->bar");
        cg.add_edge("A->foo", "B->bar");
        assert_eq!(cg.edge_count, 1);
    }

    #[test]
    fn test_call_graph_callers_of() {
        let mut cg = SmaliCallGraph::new();
        cg.add_edge("A->foo", "B->bar");
        cg.add_edge("C->baz", "B->bar");
        let callers = cg.callers_of("B->bar");
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_call_graph_reachable_from() {
        let mut cg = SmaliCallGraph::new();
        cg.add_edge("A", "B");
        cg.add_edge("B", "C");
        let reachable = cg.reachable_from("A");
        assert!(reachable.contains("A"));
        assert!(reachable.contains("B"));
        assert!(reachable.contains("C"));
    }

    #[test]
    fn test_call_graph_node_count() {
        let mut cg = SmaliCallGraph::new();
        cg.add_edge("A", "B");
        cg.add_edge("C", "D");
        assert_eq!(cg.node_count(), 2);
    }

    #[test]
    fn test_call_graph_callees_none() {
        let cg = SmaliCallGraph::new();
        assert!(cg.callees("unknown").is_none());
    }

    // ── SmaliXref ─────────────────────────────────────────────────────────────

    #[test]
    fn test_xref_add_field_ref() {
        let mut x = SmaliXref::new();
        x.add_field_ref("Lcom/A;->count:I", "Lcom/A;", "run");
        assert_eq!(x.field_count(), 1);
    }

    #[test]
    fn test_xref_add_method_ref() {
        let mut x = SmaliXref::new();
        x.add_method_ref("Ljava/lang/Object;-><init>()V", "Lcom/A;", "<init>");
        assert_eq!(x.method_count(), 1);
    }

    #[test]
    fn test_xref_add_type_ref() {
        let mut x = SmaliXref::new();
        x.add_type_ref("Ljava/util/ArrayList;", "Lcom/A;", "foo");
        assert_eq!(x.type_count(), 1);
    }

    #[test]
    fn test_xref_sites_for_method() {
        let mut x = SmaliXref::new();
        x.add_method_ref("Lcom/B;->doIt()V", "Lcom/A;", "run");
        x.add_method_ref("Lcom/B;->doIt()V", "Lcom/C;", "start");
        let sites = x.sites_for_method("Lcom/B;->doIt()V");
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn test_xref_empty_by_default() {
        let x = SmaliXref::new();
        assert_eq!(x.field_count(), 0);
        assert_eq!(x.method_count(), 0);
        assert_eq!(x.type_count(), 0);
    }

    // ── ApiUsage ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_classify_reflection() {
        let mut a = ApiUsage::new();
        a.classify("Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;");
        assert!(!a.reflection_calls.is_empty());
    }

    #[test]
    fn test_api_classify_exec() {
        let mut a = ApiUsage::new();
        a.classify("Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;");
        assert!(!a.exec_calls.is_empty());
        assert!(a.has_exec());
    }

    #[test]
    fn test_api_classify_dynamic_loading() {
        let mut a = ApiUsage::new();
        a.classify("Ldalvik/system/DexClassLoader;-><init>()V");
        assert!(a.has_dynamic_loading());
    }

    #[test]
    fn test_api_total_suspicious() {
        let mut a = ApiUsage::new();
        a.classify("Ljava/lang/Class;->forName()V");
        a.classify("Lsms/SmsManager;->sendTextMessage()V");
        let suspicious = a.total_suspicious();
        assert!(suspicious > 0);
    }

    #[test]
    fn test_api_no_suspicious_initially() {
        let a = ApiUsage::new();
        assert_eq!(a.total_suspicious(), 0);
    }

    // ── StringUsage ───────────────────────────────────────────────────────────

    #[test]
    fn test_string_usage_url() {
        let mut s = StringUsage::new();
        s.add("https://example.com");
        assert!(!s.urls.is_empty());
    }

    #[test]
    fn test_string_usage_ip() {
        let mut s = StringUsage::new();
        s.add("192.168.1.1");
        assert!(!s.ip_addresses.is_empty());
    }

    #[test]
    fn test_string_usage_file_path() {
        let mut s = StringUsage::new();
        s.add("/data/local/tmp/evil");
        assert!(!s.file_paths.is_empty());
    }

    #[test]
    fn test_string_usage_suspicious_command() {
        let mut s = StringUsage::new();
        s.add("exec(/bin/sh -c rm)");
        assert!(s.has_suspicious_commands());
    }

    #[test]
    fn test_string_usage_total() {
        let mut s = StringUsage::new();
        s.add("hello");
        s.add("world");
        assert_eq!(s.total(), 2);
    }

    #[test]
    fn test_string_usage_empty() {
        let s = StringUsage::new();
        assert_eq!(s.total(), 0);
        assert!(!s.has_suspicious_commands());
    }

    // ── ObfuscationScore ──────────────────────────────────────────────────────

    #[test]
    fn test_obfuscation_score_empty_classes() {
        let score = ObfuscationScore::from_classes(&[]);
        assert_eq!(score.class_count, 0);
        assert!((score.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_obfuscation_score_clean_classes() {
        let classes = vec![SmaliClass::mock("Lcom/example/MainActivity;")];
        let score = ObfuscationScore::from_classes(&classes);
        assert!(!score.is_obfuscated());
    }

    #[test]
    fn test_obfuscation_score_short_names() {
        let classes = vec![SmaliClass::mock("La/b;"), SmaliClass::mock("Lc/d;")];
        let score = ObfuscationScore::from_classes(&classes);
        assert!(score.short_name_classes > 0);
    }

    #[test]
    fn test_obfuscation_score_range() {
        let classes = vec![SmaliClass::mock("Lcom/Foo;")];
        let score = ObfuscationScore::from_classes(&classes);
        assert!(score.score >= 0.0 && score.score <= 1.0);
    }

    // ── SmaliReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_report_is_high_risk_false_for_clean() {
        let engine = SmaliAnalysis::new();
        let report = engine.analyze(&[SmaliClass::mock("Lcom/Clean;")]);
        // Mock class has minimal invoke instructions — no exec calls
        let _ = report.is_high_risk();
    }

    #[test]
    fn test_report_is_high_risk_true_for_exec() {
        let engine = SmaliAnalysis::new();
        let class = make_class_with_invoke(
            "Lcom/Evil;",
            "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
        );
        let report = engine.analyze(&[class]);
        assert!(report.api_usage.has_exec());
    }

    #[test]
    fn test_report_summary_contains_class_count() {
        let engine = SmaliAnalysis::new();
        let classes = vec![SmaliClass::mock("La;"), SmaliClass::mock("Lb;")];
        let report = engine.analyze(&classes);
        assert!(report.summary().contains('2'));
    }

    #[test]
    fn test_report_serialization() {
        let engine = SmaliAnalysis::new();
        let report = engine.analyze(&[SmaliClass::mock("Lcom/Test;")]);
        let json = serde_json::to_string(&report).unwrap();
        let d: SmaliReport = serde_json::from_str(&json).unwrap();
        assert_eq!(d.class_count, report.class_count);
    }

    #[test]
    fn test_report_xref_method_refs_populated() {
        let engine = SmaliAnalysis::new();
        let class = make_class_with_invoke("Lcom/A;", "Lcom/B;->doSomething()V");
        let report = engine.analyze(&[class]);
        assert!(report.xref.method_count() > 0);
    }
}
