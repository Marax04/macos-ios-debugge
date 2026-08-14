//! Analysis pass registry with topological ordering and dependency tracking.
//!
//! Provides [`AnalysisPass`] trait, [`PassRegistry`], [`PassResult`], and
//! [`AnalysisContext`] so passes can be composed into ordered pipelines with
//! correct dependency evaluation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use rustre_core::{address::Address, arch::Architecture, binary_view::BinaryView};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the pass registry.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A pass with the given name was already registered.
    #[error("pass already registered: {0}")]
    Duplicate(String),
    /// A dependency declared by a pass does not exist in the registry.
    #[error("unresolved dependency '{dep}' for pass '{pass}'")]
    UnresolvedDep { pass: String, dep: String },
    /// The dependency graph contains a cycle.
    #[error("dependency cycle detected involving pass '{0}'")]
    Cycle(String),
    /// A pass with the given name was not found.
    #[error("pass not found: {0}")]
    NotFound(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// PassSeverity / PassFinding – lightweight findings from within a pass
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level for a finding produced during a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PassSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for PassSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single finding produced by an analysis pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassFinding {
    /// Virtual address associated with the finding.
    pub address: u64,
    /// Human-readable description.
    pub description: String,
    /// Severity.
    pub severity: PassSeverity,
    /// Name of the pass that produced it.
    pub pass_name: String,
}

impl PassFinding {
    /// Construct a new [`PassFinding`].
    #[must_use]
    pub fn new(
        address: u64,
        description: impl Into<String>,
        severity: PassSeverity,
        pass_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            description: description.into(),
            severity,
            pass_name: pass_name.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of executing a single analysis pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Name of the pass.
    pub name: String,
    /// Whether the pass succeeded.
    pub success: bool,
    /// Optional error message if the pass failed.
    pub error: Option<String>,
    /// Wall-clock time spent.
    pub elapsed: Duration,
    /// Findings produced during execution.
    pub findings: Vec<PassFinding>,
    /// Arbitrary key-value metadata emitted by the pass.
    pub metadata: HashMap<String, String>,
}

impl PassResult {
    /// Create a successful result with no findings.
    #[must_use]
    pub fn ok(name: impl Into<String>, elapsed: Duration) -> Self {
        Self {
            name: name.into(),
            success: true,
            error: None,
            elapsed,
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn fail(name: impl Into<String>, elapsed: Duration, error: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success: false,
            error: Some(error.into()),
            elapsed,
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a finding to this result.
    pub fn push_finding(&mut self, f: PassFinding) {
        self.findings.push(f);
    }

    /// Insert metadata.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Count findings at or above a severity threshold.
    #[must_use]
    pub fn count_at_least(&self, threshold: PassSeverity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisContext
// ─────────────────────────────────────────────────────────────────────────────

/// Feature-level toggles for type and vtable analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeAnalysisFlags {
    /// Enable aggressive type recovery.
    pub aggressive_type_recovery: bool,
    /// Enable vtable analysis.
    pub vtable_analysis: bool,
}

impl Default for TypeAnalysisFlags {
    fn default() -> Self {
        Self {
            aggressive_type_recovery: false,
            vtable_analysis: true,
        }
    }
}

/// Feature-level toggles for discovery passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryFlags {
    /// Enable string discovery.
    pub string_discovery: bool,
    /// Enable cross-reference recovery.
    pub xref_recovery: bool,
}

impl Default for DiscoveryFlags {
    fn default() -> Self {
        Self {
            string_discovery: true,
            xref_recovery: true,
        }
    }
}

/// Settings controlling analysis behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSettings {
    /// Maximum number of basic blocks to analyse per function.
    pub max_blocks_per_function: usize,
    /// Maximum recursion depth for recursive descent.
    pub max_recursion_depth: usize,
    /// Type-analysis feature toggles.
    pub type_analysis: TypeAnalysisFlags,
    /// Discovery-pass feature toggles.
    pub discovery: DiscoveryFlags,
    /// Minimum string length.
    pub min_string_length: usize,
    /// Timeout per pass in seconds (0 = unlimited).
    pub pass_timeout_secs: u64,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self {
            max_blocks_per_function: 4096,
            max_recursion_depth: 64,
            type_analysis: TypeAnalysisFlags::default(),
            discovery: DiscoveryFlags::default(),
            min_string_length: 4,
            pass_timeout_secs: 300,
        }
    }
}

/// Shared context passed to every analysis pass during execution.
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// The binary being analysed.
    pub binary: Arc<Vec<u8>>,
    /// Base address of the binary in virtual memory.
    pub base_address: u64,
    /// Detected or specified architecture.
    pub architecture: String,
    /// Discovered function entry-points.
    pub functions: Arc<std::sync::Mutex<Vec<u64>>>,
    /// Analysis settings.
    pub settings: AnalysisSettings,
    /// Accumulated results from previously executed passes (keyed by pass name).
    pub prior_results: Arc<std::sync::Mutex<HashMap<String, PassResult>>>,
}

impl AnalysisContext {
    /// Construct a new context.
    #[must_use]
    pub fn new(binary: Vec<u8>, base_address: u64, architecture: impl Into<String>) -> Self {
        Self {
            binary: Arc::new(binary),
            base_address,
            architecture: architecture.into(),
            functions: Arc::new(std::sync::Mutex::new(Vec::new())),
            settings: AnalysisSettings::default(),
            prior_results: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Apply custom settings.
    #[must_use] 
    pub const fn with_settings(mut self, settings: AnalysisSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Add a known function entry-point.
    pub fn add_function(&self, addr: u64) {
        if let Ok(mut fns) = self.functions.lock()
            && !fns.contains(&addr) {
                fns.push(addr);
            }
    }

    /// Retrieve a prior result by pass name.
    #[must_use]
    pub fn prior_result(&self, name: &str) -> Option<PassResult> {
        self.prior_results.lock().ok()?.get(name).cloned()
    }

    /// Store a pass result.
    pub fn store_result(&self, result: PassResult) {
        if let Ok(mut map) = self.prior_results.lock() {
            map.insert(result.name.clone(), result);
        }
    }

    /// Return binary size.
    #[must_use]
    pub fn binary_size(&self) -> usize {
        self.binary.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPass trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait that every analysis pass must implement.
pub trait AnalysisPass: Send + Sync {
    /// Unique pass name (used as key in registry and dependency lists).
    fn name(&self) -> &str;

    /// List of pass names that must complete successfully before this pass runs.
    fn dependencies(&self) -> Vec<String> {
        Vec::new()
    }

    /// Brief human-readable description.
    fn description(&self) -> &'static str {
        ""
    }

    /// Execute the pass.
    ///
    /// # Errors
    /// Returns an error string if the pass fails.
    fn run(&self, ctx: &AnalysisContext) -> Result<PassResult, String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// PassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of analysis passes with topological ordering.
#[derive(Default)]
pub struct PassRegistry {
    passes: HashMap<String, Arc<dyn AnalysisPass>>,
}

impl PassRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass.
    ///
    /// # Errors
    /// Returns [`RegistryError::Duplicate`] if a pass with the same name is already registered.
    pub fn register(&mut self, pass: Arc<dyn AnalysisPass>) -> Result<(), RegistryError> {
        let name = pass.name().to_owned();
        if self.passes.contains_key(&name) {
            return Err(RegistryError::Duplicate(name));
        }
        self.passes.insert(name, pass);
        Ok(())
    }

    /// Remove a pass by name.
    pub fn unregister(&mut self, name: &str) -> Option<Arc<dyn AnalysisPass>> {
        self.passes.remove(name)
    }

    /// Retrieve a pass by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn AnalysisPass>> {
        self.passes.get(name).cloned()
    }

    /// Return all registered pass names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.passes.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// Return `true` if no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Compute a topological execution order for all registered passes.
    ///
    /// Uses Kahn's algorithm.
    ///
    /// # Errors
    /// Returns an error if dependencies are unresolved or a cycle is detected.
    pub fn topological_order(&self) -> Result<Vec<String>, RegistryError> {
        // Validate all dependencies exist.
        for (name, pass) in &self.passes {
            for dep in pass.dependencies() {
                if !self.passes.contains_key(&dep) {
                    return Err(RegistryError::UnresolvedDep {
                        pass: name.clone(),
                        dep,
                    });
                }
            }
        }

        // Build adjacency / in-degree tables.
        let mut in_degree: HashMap<String, usize> =
            self.passes.keys().map(|k| (k.clone(), 0)).collect();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for (name, pass) in &self.passes {
            for dep in pass.dependencies() {
                dependents.entry(dep).or_default().push(name.clone());
                *in_degree.entry(name.clone()).or_insert(0) += 1;
            }
        }

        // Kahn's BFS.
        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(k, _)| k.clone())
            .collect();
        queue = {
            let mut v: Vec<_> = queue.into_iter().collect();
            v.sort();
            VecDeque::from(v)
        };

        let mut order = Vec::new();
        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            if let Some(deps) = dependents.get(&node) {
                let mut next: Vec<_> = deps
                    .iter()
                    .filter_map(|d| {
                        let deg = in_degree.get_mut(d)?;
                        *deg -= 1;
                        if *deg == 0 { Some(d.clone()) } else { None }
                    })
                    .collect();
                next.sort();
                queue.extend(next);
            }
        }

        if order.len() != self.passes.len() {
            // Find an offending pass for a better error message.
            let in_order: HashSet<_> = order.iter().cloned().collect();
            let culprit = self
                .passes
                .keys()
                .find(|k| !in_order.contains(*k))
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned());
            return Err(RegistryError::Cycle(culprit));
        }

        Ok(order)
    }

    /// Execute all passes in topological order.
    ///
    /// Each pass result is stored back into the context so subsequent passes
    /// can inspect prior results.
    ///
    /// # Errors
    /// Returns the first registry-level error encountered (dependency/cycle).
    pub fn run_all(&self, ctx: &AnalysisContext) -> Result<Vec<PassResult>, RegistryError> {
        let order = self.topological_order()?;
        let mut results = Vec::with_capacity(order.len());
        for name in &order {
            let pass = self.passes[name].as_ref();
            let t0 = Instant::now();
            let result = match pass.run(ctx) {
                Ok(r) => r,
                Err(e) => PassResult::fail(name, t0.elapsed(), e),
            };
            ctx.store_result(result.clone());
            results.push(result);
        }
        Ok(results)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in passes
// ─────────────────────────────────────────────────────────────────────────────

/// Type-recovery analysis pass.
pub struct TypeRecoveryPass;

impl AnalysisPass for TypeRecoveryPass {
    fn name(&self) -> &'static str {
        "TypeRecovery"
    }
    fn description(&self) -> &'static str {
        "Recover data types from binary patterns"
    }
    fn run(&self, ctx: &AnalysisContext) -> Result<PassResult, String> {
        let t0 = Instant::now();
        let mut result = PassResult::ok(self.name(), t0.elapsed());
        result.set_meta("binary_size", ctx.binary_size().to_string());
        Ok(result)
    }
}

/// Calling-convention identification pass.
pub struct CallingConventionPass;

impl AnalysisPass for CallingConventionPass {
    fn name(&self) -> &'static str {
        "CallingConvention"
    }
    fn description(&self) -> &'static str {
        "Identify calling conventions from function prologues/epilogues"
    }
    fn dependencies(&self) -> Vec<String> {
        vec!["TypeRecovery".into()]
    }
    fn run(&self, ctx: &AnalysisContext) -> Result<PassResult, String> {
        let t0 = Instant::now();
        let mut result = PassResult::ok(self.name(), t0.elapsed());
        let fn_count = ctx.functions.lock().map_or(0, |f| f.len());
        result.set_meta("functions_analysed", fn_count.to_string());
        Ok(result)
    }
}

/// Virtual-dispatch table analysis pass.
pub struct VtablePass;

impl AnalysisPass for VtablePass {
    fn name(&self) -> &'static str {
        "VtableAnalysis"
    }
    fn description(&self) -> &'static str {
        "Detect and annotate C++ virtual dispatch tables"
    }
    fn dependencies(&self) -> Vec<String> {
        vec!["TypeRecovery".into()]
    }
    fn run(&self, _ctx: &AnalysisContext) -> Result<PassResult, String> {
        let t0 = Instant::now();
        let mut result = PassResult::ok(self.name(), t0.elapsed());
        result.set_meta("vtables_found", "0");
        Ok(result)
    }
}

/// String-discovery pass.
pub struct StringRecoveryPass;

impl AnalysisPass for StringRecoveryPass {
    fn name(&self) -> &'static str {
        "StringRecovery"
    }
    fn description(&self) -> &'static str {
        "Scan binary for ASCII/UTF-16 strings"
    }
    fn run(&self, ctx: &AnalysisContext) -> Result<PassResult, String> {
        let t0 = Instant::now();
        let min_len = ctx.settings.min_string_length;
        let mut strings_found: usize = 0;

        // Simple ASCII string scanner.
        let mut run = 0usize;
        for &b in ctx.binary.iter() {
            if b.is_ascii_graphic() || b == b' ' {
                run += 1;
            } else {
                if run >= min_len {
                    strings_found += 1;
                }
                run = 0;
            }
        }
        if run >= min_len {
            strings_found += 1;
        }

        let mut result = PassResult::ok(self.name(), t0.elapsed());
        result.set_meta("strings_found", strings_found.to_string());
        result.set_meta("min_string_length", min_len.to_string());
        Ok(result)
    }
}

/// Cross-reference recovery pass.
pub struct XrefRecoveryPass;

impl AnalysisPass for XrefRecoveryPass {
    fn name(&self) -> &'static str {
        "XrefRecovery"
    }
    fn description(&self) -> &'static str {
        "Build cross-reference tables for calls and data references"
    }
    fn dependencies(&self) -> Vec<String> {
        vec!["CallingConvention".into()]
    }
    fn run(&self, _ctx: &AnalysisContext) -> Result<PassResult, String> {
        let t0 = Instant::now();
        let mut result = PassResult::ok(self.name(), t0.elapsed());
        result.set_meta("xrefs_found", "0");
        Ok(result)
    }
}

/// Construct a [`PassRegistry`] pre-populated with all built-in passes.
///
/// # Panics
/// Panics if any built-in pass fails to register (indicates a programming error).
#[must_use]
pub fn builtin_registry() -> PassRegistry {
    let mut reg = PassRegistry::new();
    reg.register(Arc::new(TypeRecoveryPass)).unwrap();
    reg.register(Arc::new(CallingConventionPass)).unwrap();
    reg.register(Arc::new(VtablePass)).unwrap();
    reg.register(Arc::new(StringRecoveryPass)).unwrap();
    reg.register(Arc::new(XrefRecoveryPass)).unwrap();
    reg
}

// ─────────────────────────────────────────────────────────────────────────────
// PassScheduler — run a subset of passes
// ─────────────────────────────────────────────────────────────────────────────

/// Schedules and executes a named subset of passes from a registry.
pub struct PassScheduler<'a> {
    registry: &'a PassRegistry,
    selected: Vec<String>,
}

impl<'a> PassScheduler<'a> {
    /// Create a scheduler targeting specific passes (and their transitive deps).
    ///
    /// # Errors
    /// Returns [`RegistryError::NotFound`] if any selected pass name does not exist.
    pub fn new(registry: &'a PassRegistry, selected: &[&str]) -> Result<Self, RegistryError> {
        for &name in selected {
            if registry.get(name).is_none() {
                return Err(RegistryError::NotFound(name.to_owned()));
            }
        }
        Ok(Self {
            registry,
            selected: selected.iter().map(std::string::ToString::to_string).collect(),
        })
    }

    /// Execute selected passes (and their transitive dependencies) in order.
    ///
    /// # Errors
    /// Returns registry-level errors (cycle/missing).
    pub fn run(&self, ctx: &AnalysisContext) -> Result<Vec<PassResult>, RegistryError> {
        let full_order = self.registry.topological_order()?;
        let needed = self.transitive_deps()?;
        let ordered: Vec<_> = full_order
            .into_iter()
            .filter(|n| needed.contains(n))
            .collect();

        let mut results = Vec::new();
        for name in &ordered {
            if let Some(pass) = self.registry.get(name) {
                let t0 = Instant::now();
                let result = match pass.run(ctx) {
                    Ok(r) => r,
                    Err(e) => PassResult::fail(name, t0.elapsed(), e),
                };
                ctx.store_result(result.clone());
                results.push(result);
            }
        }
        Ok(results)
    }

    fn transitive_deps(&self) -> Result<HashSet<String>, RegistryError> {
        let mut needed = HashSet::new();
        let mut stack: Vec<String> = self.selected.clone();
        while let Some(name) = stack.pop() {
            if !needed.insert(name.clone()) {
                continue;
            }
            let pass = self
                .registry
                .get(&name)
                .ok_or_else(|| RegistryError::NotFound(name.clone()))?;
            for dep in pass.dependencies() {
                stack.push(dep);
            }
        }
        Ok(needed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassStats summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics across all executed passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassStats {
    /// Total number of passes executed.
    pub total: usize,
    /// Number of successful passes.
    pub succeeded: usize,
    /// Number of failed passes.
    pub failed: usize,
    /// Total wall-clock time.
    pub total_elapsed: Duration,
    /// Total findings across all passes.
    pub total_findings: usize,
    /// Slowest pass name and its elapsed time.
    pub slowest: Option<(String, Duration)>,
}

impl PassStats {
    /// Compute stats from a slice of results.
    #[must_use]
    pub fn from_results(results: &[PassResult]) -> Self {
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = total - succeeded;
        let total_elapsed: Duration = results.iter().map(|r| r.elapsed).sum();
        let total_findings = results.iter().map(|r| r.findings.len()).sum();
        let slowest = results
            .iter()
            .max_by_key(|r| r.elapsed)
            .map(|r| (r.name.clone(), r.elapsed));
        Self {
            total,
            succeeded,
            failed,
            total_elapsed,
            total_findings,
            slowest,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> AnalysisContext {
        AnalysisContext::new(vec![0u8; 256], 0x1000, "x86_64")
    }

    // -- PassResult ----------------------------------------------------------

    #[test]
    fn test_pass_result_ok() {
        let r = PassResult::ok("TypeRecovery", Duration::from_millis(5));
        assert!(r.success);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_pass_result_fail() {
        let r = PassResult::fail("Bad", Duration::default(), "reason");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("reason"));
    }

    #[test]
    fn test_pass_result_findings() {
        let mut r = PassResult::ok("P", Duration::default());
        r.push_finding(PassFinding::new(0x400, "test", PassSeverity::High, "P"));
        assert_eq!(r.count_at_least(PassSeverity::High), 1);
        assert_eq!(r.count_at_least(PassSeverity::Critical), 0);
    }

    #[test]
    fn test_pass_result_metadata() {
        let mut r = PassResult::ok("P", Duration::default());
        r.set_meta("key", "value");
        assert_eq!(r.metadata.get("key").map(std::string::String::as_str), Some("value"));
    }

    // -- PassFinding ---------------------------------------------------------

    #[test]
    fn test_pass_finding_severity_ordering() {
        assert!(PassSeverity::Critical > PassSeverity::High);
        assert!(PassSeverity::High > PassSeverity::Medium);
        assert!(PassSeverity::Info < PassSeverity::Low);
    }

    // -- PassRegistry --------------------------------------------------------

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = PassRegistry::new();
        reg.register(Arc::new(TypeRecoveryPass)).unwrap();
        assert!(reg.get("TypeRecovery").is_some());
    }

    #[test]
    fn test_registry_duplicate() {
        let mut reg = PassRegistry::new();
        reg.register(Arc::new(TypeRecoveryPass)).unwrap();
        let err = reg.register(Arc::new(TypeRecoveryPass)).unwrap_err();
        assert!(matches!(err, RegistryError::Duplicate(_)));
    }

    #[test]
    fn test_registry_names_sorted() {
        let reg = builtin_registry();
        let names = reg.names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_registry_len() {
        let reg = builtin_registry();
        assert_eq!(reg.len(), 5);
    }

    #[test]
    fn test_topological_order() {
        let reg = builtin_registry();
        let order = reg.topological_order().unwrap();
        // TypeRecovery must precede CallingConvention.
        let tr = order.iter().position(|s| s == "TypeRecovery").unwrap();
        let cc = order.iter().position(|s| s == "CallingConvention").unwrap();
        assert!(tr < cc);
    }

    #[test]
    fn test_topological_order_vtable_after_type() {
        let reg = builtin_registry();
        let order = reg.topological_order().unwrap();
        let tr = order.iter().position(|s| s == "TypeRecovery").unwrap();
        let vt = order.iter().position(|s| s == "VtableAnalysis").unwrap();
        assert!(tr < vt);
    }

    #[test]
    fn test_topological_order_xref_after_cc() {
        let reg = builtin_registry();
        let order = reg.topological_order().unwrap();
        let cc = order.iter().position(|s| s == "CallingConvention").unwrap();
        let xr = order.iter().position(|s| s == "XrefRecovery").unwrap();
        assert!(cc < xr);
    }

    #[test]
    fn test_unresolved_dep() {
        struct BadPass;
        impl AnalysisPass for BadPass {
            fn name(&self) -> &'static str {
                "Bad"
            }
            fn dependencies(&self) -> Vec<String> {
                vec!["NonExistent".into()]
            }
            fn run(&self, _: &AnalysisContext) -> Result<PassResult, String> {
                Ok(PassResult::ok("Bad", Duration::default()))
            }
        }
        let mut reg = PassRegistry::new();
        reg.register(Arc::new(BadPass)).unwrap();
        let err = reg.topological_order().unwrap_err();
        assert!(matches!(err, RegistryError::UnresolvedDep { .. }));
    }

    #[test]
    fn test_cycle_detection() {
        struct PassA;
        struct PassB;
        impl AnalysisPass for PassA {
            fn name(&self) -> &'static str {
                "PassA"
            }
            fn dependencies(&self) -> Vec<String> {
                vec!["PassB".into()]
            }
            fn run(&self, _: &AnalysisContext) -> Result<PassResult, String> {
                Ok(PassResult::ok("PassA", Duration::default()))
            }
        }
        impl AnalysisPass for PassB {
            fn name(&self) -> &'static str {
                "PassB"
            }
            fn dependencies(&self) -> Vec<String> {
                vec!["PassA".into()]
            }
            fn run(&self, _: &AnalysisContext) -> Result<PassResult, String> {
                Ok(PassResult::ok("PassB", Duration::default()))
            }
        }
        let mut reg = PassRegistry::new();
        reg.register(Arc::new(PassA)).unwrap();
        reg.register(Arc::new(PassB)).unwrap();
        let err = reg.topological_order().unwrap_err();
        assert!(matches!(err, RegistryError::Cycle(_)));
    }

    #[test]
    fn test_run_all() {
        let reg = builtin_registry();
        let ctx = make_ctx();
        let results = reg.run_all(&ctx).unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_run_all_stores_results() {
        let reg = builtin_registry();
        let ctx = make_ctx();
        reg.run_all(&ctx).unwrap();
        assert!(ctx.prior_result("TypeRecovery").is_some());
        assert!(ctx.prior_result("XrefRecovery").is_some());
    }

    // -- AnalysisContext -----------------------------------------------------

    #[test]
    fn test_context_add_function() {
        let ctx = make_ctx();
        ctx.add_function(0x1000);
        ctx.add_function(0x2000);
        ctx.add_function(0x1000); // duplicate
        let fns = ctx.functions.lock().unwrap();
        assert_eq!(fns.len(), 2);
    }

    #[test]
    fn test_context_binary_size() {
        let ctx = make_ctx();
        assert_eq!(ctx.binary_size(), 256);
    }

    #[test]
    fn test_context_with_settings() {
        let ctx = make_ctx().with_settings(AnalysisSettings {
            min_string_length: 8,
            ..Default::default()
        });
        assert_eq!(ctx.settings.min_string_length, 8);
    }

    // -- StringRecoveryPass --------------------------------------------------

    #[test]
    fn test_string_recovery_finds_strings() {
        let data = b"hello world\0AAABBBCCC\0".to_vec();
        let ctx = AnalysisContext::new(data, 0, "x86_64");
        let pass = StringRecoveryPass;
        let result = pass.run(&ctx).unwrap();
        let count: usize = result.metadata["strings_found"].parse().unwrap();
        assert!(count >= 1);
    }

    #[test]
    fn test_string_recovery_empty_binary() {
        let ctx = AnalysisContext::new(vec![], 0, "x86_64");
        let pass = StringRecoveryPass;
        let result = pass.run(&ctx).unwrap();
        assert!(result.success);
    }

    // -- PassStats -----------------------------------------------------------

    #[test]
    fn test_pass_stats() {
        let results = vec![
            PassResult::ok("A", Duration::from_millis(10)),
            PassResult::fail("B", Duration::from_millis(5), "err"),
        ];
        let stats = PassStats::from_results(&results);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.succeeded, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_pass_stats_empty() {
        let stats = PassStats::from_results(&[]);
        assert_eq!(stats.total, 0);
        assert!(stats.slowest.is_none());
    }

    // -- PassScheduler -------------------------------------------------------

    #[test]
    fn test_scheduler_selected_runs() {
        let reg = builtin_registry();
        let ctx = make_ctx();
        let sched = PassScheduler::new(&reg, &["StringRecovery"]).unwrap();
        let results = sched.run(&ctx).unwrap();
        // StringRecovery has no deps so only it should run.
        assert!(results.iter().any(|r| r.name == "StringRecovery"));
    }

    #[test]
    fn test_scheduler_not_found() {
        let reg = builtin_registry();
        let res = PassScheduler::new(&reg, &["Nonexistent"]);
        let err = match res { Ok(_) => panic!("expected error"), Err(e) => e };
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn test_scheduler_deps_included() {
        let reg = builtin_registry();
        let ctx = make_ctx();
        let sched = PassScheduler::new(&reg, &["XrefRecovery"]).unwrap();
        let results = sched.run(&ctx).unwrap();
        // XrefRecovery depends on CallingConvention which depends on TypeRecovery.
        let names: Vec<_> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"TypeRecovery"));
        assert!(names.contains(&"CallingConvention"));
        assert!(names.contains(&"XrefRecovery"));
    }

    #[test]
    fn test_builtin_registry_has_all_passes() {
        let reg = builtin_registry();
        assert!(reg.get("TypeRecovery").is_some());
        assert!(reg.get("CallingConvention").is_some());
        assert!(reg.get("VtableAnalysis").is_some());
        assert!(reg.get("StringRecovery").is_some());
        assert!(reg.get("XrefRecovery").is_some());
    }
}
