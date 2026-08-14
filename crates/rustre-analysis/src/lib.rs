//! `rustre-analysis`
//!
//! Core analysis infrastructure for the `RustRE` Suite. Provides the
//! [`AnalysisPass`] trait, [`AnalysisPipeline`] coordinator, and supporting
//! types for structuring binary analysis.

use rustre_core::{address::Address, arch::Architecture, binary_view::BinaryView};
use std::collections::HashMap;
use std::sync::Arc;

pub mod analysis_context;
pub mod analysis_index;
pub mod analysis_pipeline;
pub mod binary_analysis_report;
pub mod control_flow_analysis;

/// Shared test-only PRNG for randomized property tests (one definition
/// instead of per-test copies; identical algorithm, sequences unchanged).
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }
}
pub mod findings;
pub mod pass_registry;
pub mod runner;

/// Interprocedural analysis: CallGraph, SummaryDatabase, BottomUp computation,
/// TopDown propagation, CallSiteSummary, InterproceduralAnalysis.
///
pub mod interprocedural_analysis;
pub mod analysis_scheduler;
pub mod analysis_cache;
pub mod analysis_metrics;
pub mod binary_analysis_suite;
pub mod vulnerability_scanner;

pub use runner::{DependencyRunner, PassOutcome, RunReport};

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisKind
// ─────────────────────────────────────────────────────────────────────────────

/// The category / algorithm of an analysis pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AnalysisKind {
    /// Linear sweep disassembly.
    LinearSweep,
    /// Recursive descent disassembly.
    RecursiveDescent,
    /// Data-flow analysis.
    DataFlow,
    /// Type recovery pass.
    TypeRecovery,
    /// Calling convention identification.
    CallingConvention,
    /// String discovery.
    StringRecovery,
    /// Cross-reference recovery.
    XrefRecovery,
    /// Value-set analysis (VSA).
    VsaAnalysis,
    /// Virtual-dispatch table analysis.
    VtableAnalysis,
    /// A user-defined or plugin-provided analysis.
    Custom(String),
}

impl std::fmt::Display for AnalysisKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinearSweep => write!(f, "LinearSweep"),
            Self::RecursiveDescent => write!(f, "RecursiveDescent"),
            Self::DataFlow => write!(f, "DataFlow"),
            Self::TypeRecovery => write!(f, "TypeRecovery"),
            Self::CallingConvention => write!(f, "CallingConvention"),
            Self::StringRecovery => write!(f, "StringRecovery"),
            Self::XrefRecovery => write!(f, "XrefRecovery"),
            Self::VsaAnalysis => write!(f, "VsaAnalysis"),
            Self::VtableAnalysis => write!(f, "VtableAnalysis"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration passed to every [`AnalysisPass::run`] call.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisConfig {
    /// Which analysis kind to perform.
    pub kind: AnalysisKind,
    /// Maximum call/recursion depth for recursive passes.
    pub max_depth: usize,
    /// Optional wall-clock timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Optional override start address (pass-specific interpretation).
    pub start_address: Option<Address>,
    /// Arbitrary key/value options for pass-specific settings.
    pub options: HashMap<String, String>,
}

impl AnalysisConfig {
    /// Create a minimal config for the given kind.
    #[must_use]
    pub fn new(kind: AnalysisKind) -> Self {
        Self {
            kind,
            max_depth: 256,
            timeout_ms: None,
            start_address: None,
            options: HashMap::new(),
        }
    }

    /// Set the maximum recursion depth.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set a wall-clock timeout.
    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Set the start address hint.
    #[must_use]
    pub const fn with_start(mut self, addr: Address) -> Self {
        self.start_address = Some(addr);
        self
    }

    /// Insert an arbitrary key/value option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Retrieve an option value.
    #[must_use]
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(String::as_str)
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self::new(AnalysisKind::LinearSweep)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisResult
// ─────────────────────────────────────────────────────────────────────────────

/// The output produced by a completed [`AnalysisPass`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisResult {
    /// Which kind of analysis produced this result.
    pub kind: AnalysisKind,
    /// Number of functions discovered.
    pub functions_found: usize,
    /// Number of data cross-references discovered.
    pub data_refs_found: usize,
    /// Number of strings found.
    pub strings_found: usize,
    /// Elapsed wall-clock time in milliseconds.
    pub duration_ms: u64,
    /// Non-fatal warnings emitted during the run.
    pub warnings: Vec<String>,
}

impl AnalysisResult {
    /// Create a zeroed result for the given kind.
    #[must_use]
    pub const fn zero(kind: AnalysisKind) -> Self {
        Self {
            kind,
            functions_found: 0,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: 0,
            warnings: Vec::new(),
        }
    }

    /// Return `true` if any warnings were produced.
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Return the total number of items discovered.
    #[must_use]
    pub const fn total_items(&self) -> usize {
        self.functions_found + self.data_refs_found + self.strings_found
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during analysis.
#[derive(thiserror::Error, Debug)]
pub enum AnalysisError {
    /// No registered pass with the given name was found.
    #[error("Pass not found: {0}")]
    PassNotFound(String),
    /// The analysis pass failed with a message.
    #[error("Analysis failed: {0}")]
    Failed(String),
    /// The pass exceeded its configured timeout.
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    /// Not enough mapped data at the given address.
    #[error("Not enough data at 0x{0:x}")]
    InsufficientData(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPass trait
// ─────────────────────────────────────────────────────────────────────────────

/// A single, named unit of analysis that operates on a [`BinaryView`].
#[async_trait::async_trait]
pub trait AnalysisPass: Send + Sync {
    /// Short, unique identifier for this pass.
    fn name(&self) -> &str;

    /// The [`AnalysisKind`] this pass implements.
    fn kind(&self) -> AnalysisKind;

    /// Human-readable description of what the pass does.
    fn description(&self) -> &str;

    /// Execute the pass against the given binary view.
    ///
    /// # Errors
    /// Returns [`AnalysisError`] on failure.
    async fn run(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError>;

    /// Return `true` if this pass supports the named architecture.
    ///
    /// The default implementation accepts all architectures.
    fn supports_arch(&self, arch_name: &str) -> bool {
        let _ = arch_name;
        true
    }

    /// Optional pass-level priority (higher = runs earlier in the pipeline).
    fn priority(&self) -> i32 {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// A registry and coordinator for multiple [`AnalysisPass`] implementations.
///
/// Passes are stored in insertion order. [`run_all`](Self::run_all) runs every
/// registered pass sequentially and collects results.
pub struct AnalysisPipeline {
    passes: parking_lot::RwLock<Vec<Arc<dyn AnalysisPass>>>,
}

impl std::fmt::Debug for AnalysisPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisPipeline")
            .field("pass_count", &self.passes.read().len())
            .finish_non_exhaustive()
    }
}

impl AnalysisPipeline {
    /// Create a new, empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a pass. Passes with the same name overwrite the previous entry.
    pub fn register(&self, pass: Arc<dyn AnalysisPass>) {
        let mut guard = self.passes.write();
        // Replace existing pass with the same name if present.
        if let Some(pos) = guard.iter().position(|p| p.name() == pass.name()) {
            guard[pos] = pass;
        } else {
            guard.push(pass);
        }
    }

    /// Find a registered pass by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<dyn AnalysisPass>> {
        self.passes
            .read()
            .iter()
            .find(|p| p.name() == name)
            .cloned()
    }

    /// Return all passes whose [`AnalysisPass::kind`] matches `kind`.
    #[must_use]
    pub fn passes_for_kind(&self, kind: &AnalysisKind) -> Vec<Arc<dyn AnalysisPass>> {
        self.passes
            .read()
            .iter()
            .filter(|p| &p.kind() == kind)
            .cloned()
            .collect()
    }

    /// Run every registered pass using [`PassScheduler`] for ordering.
    ///
    /// Passes are sorted by priority via the scheduler. Results are returned in
    /// insertion order so callers can zip them with pass names.
    pub async fn run_all(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Vec<Result<AnalysisResult, AnalysisError>> {
        let passes: Vec<Arc<dyn AnalysisPass>> = self.passes.read().clone();

        let mut scheduler = PassScheduler::new();
        for pass in &passes {
            scheduler.add(PassDescriptor::new(pass.name()).with_priority(pass.priority()));
        }

        let ordered_names = scheduler
            .schedule()
            .unwrap_or_else(|_| passes.iter().map(|p| p.name().to_string()).collect());

        let pass_map: HashMap<String, Arc<dyn AnalysisPass>> = passes
            .iter()
            .map(|p| (p.name().to_string(), Arc::clone(p)))
            .collect();

        let mut ordered_results: HashMap<String, Result<AnalysisResult, AnalysisError>> =
            HashMap::new();
        for name in &ordered_names {
            if let Some(pass) = pass_map.get(name) {
                ordered_results.insert(name.clone(), pass.run(view, config).await);
            }
        }

        passes
            .iter()
            .map(|p| {
                ordered_results
                    .remove(p.name())
                    .unwrap_or_else(|| Err(AnalysisError::PassNotFound(p.name().to_string())))
            })
            .collect()
    }

    /// Run independent passes concurrently, respecting declared dependencies.
    ///
    /// Passes are grouped by the [`PassScheduler`]: all passes in a group have
    /// no mutual dependencies and run in parallel via `futures::future::join_all`.
    /// Dependent groups run after their prerequisite groups complete.
    ///
    /// Results are collected in original insertion order. Pass failures are
    /// recorded in-place; other passes continue unaffected.
    pub async fn run_all_parallel(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Vec<Result<AnalysisResult, AnalysisError>> {
        let passes: Vec<Arc<dyn AnalysisPass>> = self.passes.read().clone();

        if passes.is_empty() {
            return Vec::new();
        }

        let mut scheduler = PassScheduler::new();
        for pass in &passes {
            scheduler.add(PassDescriptor::new(pass.name()).with_priority(pass.priority()));
        }

        let pass_map: HashMap<String, Arc<dyn AnalysisPass>> = passes
            .iter()
            .map(|p| (p.name().to_string(), Arc::clone(p)))
            .collect();

        let groups = scheduler
            .schedule_groups()
            .unwrap_or_else(|_| passes.iter().map(|p| vec![p.name().to_string()]).collect());

        let mut results_map: HashMap<String, Result<AnalysisResult, AnalysisError>> =
            HashMap::new();

        for group in groups {
            let group_futures: Vec<_> = group
                .iter()
                .filter_map(|name| pass_map.get(name).map(|p| (name.clone(), Arc::clone(p))))
                .map(|(name, pass)| async move {
                    let result = pass.run(view, config).await;
                    (name, result)
                })
                .collect();

            let group_results = futures::future::join_all(group_futures).await;
            for (name, result) in group_results {
                results_map.insert(name, result);
            }
        }

        passes
            .iter()
            .map(|p| {
                results_map
                    .remove(p.name())
                    .unwrap_or_else(|| Err(AnalysisError::PassNotFound(p.name().to_string())))
            })
            .collect()
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.read().len()
    }

    /// Remove a pass by name. Returns `true` if a pass was removed.
    pub fn remove(&self, name: &str) -> bool {
        let mut guard = self.passes.write();
        guard.iter().position(|p| p.name() == name).is_some_and(|pos| {
            guard.remove(pos);
            true
        })
    }

    /// Return the names of all registered passes in order.
    #[must_use]
    pub fn pass_names(&self) -> Vec<String> {
        self.passes
            .read()
            .iter()
            .map(|p| p.name().to_string())
            .collect()
    }
}

impl Default for AnalysisPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NoOpAnalysisPass
// ─────────────────────────────────────────────────────────────────────────────

/// A no-op analysis pass that returns a zeroed [`AnalysisResult`] instantly.
///
/// Useful as a test double or placeholder.
pub struct NoOpAnalysisPass {
    name: String,
    kind: AnalysisKind,
}

impl NoOpAnalysisPass {
    /// Create a new no-op pass with the given name (uses `LinearSweep` kind).
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: AnalysisKind::LinearSweep,
        }
    }

    /// Create a no-op pass with an explicit kind.
    #[must_use]
    pub fn with_kind(name: impl Into<String>, kind: AnalysisKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

impl std::fmt::Debug for NoOpAnalysisPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoOpAnalysisPass")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for NoOpAnalysisPass {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> AnalysisKind {
        self.kind.clone()
    }

    fn description(&self) -> &'static str {
        "No-op pass for testing"
    }

    async fn run(
        &self,
        _view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        Ok(AnalysisResult::zero(config.kind.clone()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CountingAnalysisPass  (for tests)
// ─────────────────────────────────────────────────────────────────────────────

/// A test-helper pass that always returns a fixed [`AnalysisResult`].
pub struct CountingAnalysisPass {
    name: String,
    kind: AnalysisKind,
    functions: usize,
    strings: usize,
}

impl CountingAnalysisPass {
    /// Create a pass that reports the given function/string counts.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: AnalysisKind,
        functions: usize,
        strings: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            functions,
            strings,
        }
    }
}

impl std::fmt::Debug for CountingAnalysisPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountingAnalysisPass")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("functions", &self.functions)
            .field("strings", &self.strings)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for CountingAnalysisPass {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> AnalysisKind {
        self.kind.clone()
    }

    fn description(&self) -> &'static str {
        "Test counting pass"
    }

    async fn run(
        &self,
        _view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        Ok(AnalysisResult {
            kind: config.kind.clone(),
            functions_found: self.functions,
            data_refs_found: 0,
            strings_found: self.strings,
            duration_ms: 1,
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisStats — per-pass timing and metrics
// ─────────────────────────────────────────────────────────────────────────────

/// Timing and metric statistics collected for one analysis pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PassStats {
    /// Name of the pass.
    pub pass_name: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Number of functions found.
    pub functions_found: usize,
    /// Number of strings found.
    pub strings_found: usize,
    /// Number of data cross-references found.
    pub data_refs_found: usize,
    /// Whether the pass succeeded.
    pub success: bool,
    /// Error message if the pass failed.
    pub error: Option<String>,
}

impl PassStats {
    /// Create a `PassStats` from an `AnalysisResult`.
    #[must_use]
    pub fn from_result(pass_name: &str, result: &AnalysisResult) -> Self {
        Self {
            pass_name: pass_name.to_string(),
            duration_ms: result.duration_ms,
            functions_found: result.functions_found,
            strings_found: result.strings_found,
            data_refs_found: result.data_refs_found,
            success: true,
            error: None,
        }
    }

    /// Create a failure `PassStats`.
    #[must_use]
    pub fn from_error(pass_name: &str, error: &str) -> Self {
        Self {
            pass_name: pass_name.to_string(),
            duration_ms: 0,
            functions_found: 0,
            strings_found: 0,
            data_refs_found: 0,
            success: false,
            error: Some(error.to_string()),
        }
    }
}

/// Aggregate analysis statistics over all passes.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AnalysisStats {
    /// Per-pass statistics.
    pub passes: Vec<PassStats>,
    /// Total wall-clock time in milliseconds.
    pub total_duration_ms: u64,
    /// Total functions found.
    pub total_functions: usize,
    /// Total strings found.
    pub total_strings: usize,
    /// Number of passes that failed.
    pub failed_passes: usize,
}

impl AnalysisStats {
    /// Create an empty `AnalysisStats`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pass result (success case).
    pub fn record_result(&mut self, pass_name: &str, result: &AnalysisResult) {
        let stats = PassStats::from_result(pass_name, result);
        self.total_duration_ms += stats.duration_ms;
        self.total_functions += stats.functions_found;
        self.total_strings += stats.strings_found;
        self.passes.push(stats);
    }

    /// Record a pass failure.
    pub fn record_error(&mut self, pass_name: &str, error: &str) {
        self.passes.push(PassStats::from_error(pass_name, error));
        self.failed_passes += 1;
    }

    /// Average duration across all recorded passes (0 if none).
    #[must_use]
    pub fn avg_duration_ms(&self) -> f64 {
        if self.passes.is_empty() {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_duration_ms).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.passes.len()).unwrap_or(u32::MAX))
    }

    /// Slowest pass, or `None` if no passes were recorded.
    #[must_use]
    pub fn slowest_pass(&self) -> Option<&PassStats> {
        self.passes.iter().max_by_key(|p| p.duration_ms)
    }

    /// Return `true` if all passes succeeded.
    #[must_use]
    pub const fn all_succeeded(&self) -> bool {
        self.failed_passes == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisEvent — pub-sub event system
// ─────────────────────────────────────────────────────────────────────────────

/// An event emitted during analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AnalysisEvent {
    /// A new function was discovered at the given address.
    FunctionDiscovered {
        /// Virtual address of the function.
        address: u64,
        /// Name hint (e.g. from symbol table), if any.
        name: Option<String>,
    },
    /// A string was recovered at the given address.
    StringRecovered {
        /// Virtual address of the string.
        address: u64,
        /// The string value.
        value: String,
    },
    /// A cross-reference was found: `from` references `to`.
    XrefFound {
        /// Source address of the cross-reference.
        from: u64,
        /// Target address of the cross-reference.
        to: u64,
    },
    /// A pass started.
    PassStarted {
        /// Name of the pass that started.
        pass_name: String,
    },
    /// A pass finished.
    PassFinished {
        /// Name of the pass that finished.
        pass_name: String,
        /// Duration in milliseconds.
        duration_ms: u64,
    },
    /// A warning was emitted by a pass.
    Warning {
        /// Name of the pass that emitted the warning.
        pass_name: String,
        /// Warning message.
        message: String,
    },
    /// An error occurred.
    Error {
        /// Name of the pass that failed.
        pass_name: String,
        /// Error description.
        message: String,
    },
}

impl AnalysisEvent {
    /// Short textual tag for the event kind.
    #[must_use]
    pub const fn kind_tag(&self) -> &'static str {
        match self {
            Self::FunctionDiscovered { .. } => "function_discovered",
            Self::StringRecovered { .. } => "string_recovered",
            Self::XrefFound { .. } => "xref_found",
            Self::PassStarted { .. } => "pass_started",
            Self::PassFinished { .. } => "pass_finished",
            Self::Warning { .. } => "warning",
            Self::Error { .. } => "error",
        }
    }
}

/// A subscriber callback for `AnalysisEvent`s.
pub type EventHandler = Arc<dyn Fn(&AnalysisEvent) + Send + Sync>;

/// A simple pub-sub event bus for analysis events.
#[derive(Default)]
pub struct AnalysisEventBus {
    handlers: parking_lot::RwLock<Vec<EventHandler>>,
}

impl std::fmt::Debug for AnalysisEventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisEventBus")
            .field("handler_count", &self.handlers.read().len())
            .finish_non_exhaustive()
    }
}

impl AnalysisEventBus {
    /// Create a new, empty event bus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe a handler.
    pub fn subscribe(&self, handler: EventHandler) {
        self.handlers.write().push(handler);
    }

    /// Publish an event to all registered handlers.
    pub fn publish(&self, event: &AnalysisEvent) {
        for handler in self.handlers.read().iter() {
            handler(event);
        }
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassScheduler — dependency-ordered pass execution
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor used by `PassScheduler` to represent a pass with dependencies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PassDescriptor {
    /// Unique name of the pass.
    pub name: String,
    /// Names of passes that must run before this one.
    pub dependencies: Vec<String>,
    /// Priority: higher values run earlier among ready passes.
    pub priority: i32,
}

impl PassDescriptor {
    /// Create a new `PassDescriptor` with no dependencies.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dependencies: Vec::new(),
            priority: 0,
        }
    }

    /// Add a dependency.
    #[must_use]
    pub fn with_dep(mut self, dep: impl Into<String>) -> Self {
        self.dependencies.push(dep.into());
        self
    }

    /// Set the priority.
    #[must_use]
    pub const fn with_priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }
}

/// Sorts passes into a dependency-respecting execution order (topological sort).
pub struct PassScheduler {
    descriptors: Vec<PassDescriptor>,
}

impl PassScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descriptors: Vec::new(),
        }
    }

    /// Register a `PassDescriptor`.
    pub fn add(&mut self, desc: PassDescriptor) {
        self.descriptors.push(desc);
    }

    /// Compute a topological execution order, respecting priorities within levels.
    ///
    /// Returns an error string if a cycle is detected.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a dependency cycle.
    pub fn schedule(&self) -> Result<Vec<String>, String> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for desc in &self.descriptors {
            in_degree.entry(desc.name.clone()).or_insert(0);
            for dep in &desc.dependencies {
                *in_degree.entry(desc.name.clone()).or_insert(0) += 1;
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(desc.name.clone());
            }
        }

        let mut ready: Vec<&PassDescriptor> = self
            .descriptors
            .iter()
            .filter(|d| in_degree.get(&d.name).copied().unwrap_or(0) == 0)
            .collect();
        ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

        let mut order = Vec::new();
        let mut ready_queue: std::collections::VecDeque<&PassDescriptor> =
            ready.into_iter().collect();

        while let Some(desc) = ready_queue.pop_front() {
            order.push(desc.name.clone());
            if let Some(dependents_list) = dependents.get(&desc.name) {
                let mut newly_ready: Vec<&PassDescriptor> = Vec::new();
                for dep_name in dependents_list {
                    if let Some(degree) = in_degree.get_mut(dep_name) {
                        *degree = degree.saturating_sub(1);
                        if *degree == 0
                            && let Some(d) = self.descriptors.iter().find(|x| &x.name == dep_name) {
                                newly_ready.push(d);
                            }
                    }
                }
                newly_ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));
                for d in newly_ready {
                    ready_queue.push_back(d);
                }
            }
        }

        if order.len() != self.descriptors.len() {
            return Err("Dependency cycle detected in analysis passes".to_string());
        }
        Ok(order)
    }

    /// Compute groups of passes that can run concurrently.
    ///
    /// Each inner `Vec` is a set of passes with no inter-dependencies that may
    /// be executed in parallel. Groups are ordered so that all dependencies of a
    /// group appear in earlier groups. Within each group, passes are sorted by
    /// descending priority.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a dependency cycle.
    pub fn schedule_groups(&self) -> Result<Vec<Vec<String>>, String> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for desc in &self.descriptors {
            in_degree.entry(desc.name.clone()).or_insert(0);
            for dep in &desc.dependencies {
                *in_degree.entry(desc.name.clone()).or_insert(0) += 1;
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(desc.name.clone());
            }
        }

        let mut groups: Vec<Vec<String>> = Vec::new();
        let mut total_scheduled = 0usize;

        loop {
            // Collect all passes whose in-degree is currently 0 (ready to run).
            let mut ready: Vec<&PassDescriptor> = self
                .descriptors
                .iter()
                .filter(|d| in_degree.contains_key(&d.name))
                .filter(|d| in_degree.get(&d.name).copied().unwrap_or(0) == 0)
                .collect();

            if ready.is_empty() {
                break;
            }

            // Sort by descending priority so higher-priority passes come first.
            ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

            let group: Vec<String> = ready.iter().map(|d| d.name.clone()).collect();
            total_scheduled += group.len();

            // Remove these passes from future consideration.
            for d in &ready {
                in_degree.remove(&d.name);
            }

            // Decrement in-degrees of passes that depended on this group.
            for d in &ready {
                if let Some(dependents_list) = dependents.get(&d.name) {
                    for dep_name in dependents_list {
                        if let Some(degree) = in_degree.get_mut(dep_name) {
                            *degree = degree.saturating_sub(1);
                        }
                    }
                }
            }

            groups.push(group);
        }

        if total_scheduled != self.descriptors.len() {
            return Err("Dependency cycle detected in analysis passes".to_string());
        }

        Ok(groups)
    }
}

impl Default for PassScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisReport — comprehensive output report
// ─────────────────────────────────────────────────────────────────────────────

/// A comprehensive report produced after running an `AnalysisPipeline`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisReport {
    /// Binary URI that was analysed.
    pub uri: String,
    /// Aggregate statistics.
    pub stats: AnalysisStats,
    /// All results, one per pass.
    pub results: Vec<AnalysisResult>,
    /// All warnings from all passes.
    pub all_warnings: Vec<String>,
    /// Whether the analysis completed without errors.
    pub success: bool,
}

impl AnalysisReport {
    /// Build an `AnalysisReport` from a slice of pass outcomes.
    #[must_use]
    pub fn build(uri: &str, outcomes: &[(String, Result<AnalysisResult, AnalysisError>)]) -> Self {
        let mut stats = AnalysisStats::new();
        let mut results = Vec::new();
        let mut all_warnings: Vec<String> = Vec::new();
        let mut success = true;

        for (name, outcome) in outcomes {
            match outcome {
                Ok(r) => {
                    stats.record_result(name, r);
                    all_warnings.extend(r.warnings.iter().cloned());
                    results.push(r.clone());
                }
                Err(e) => {
                    stats.record_error(name, &e.to_string());
                    success = false;
                }
            }
        }

        Self {
            uri: uri.to_string(),
            stats,
            results,
            all_warnings,
            success,
        }
    }

    /// Total number of functions discovered across all passes.
    #[must_use]
    pub fn total_functions(&self) -> usize {
        self.results.iter().map(|r| r.functions_found).sum()
    }

    /// Total number of strings discovered across all passes.
    #[must_use]
    pub fn total_strings(&self) -> usize {
        self.results.iter().map(|r| r.strings_found).sum()
    }

    /// Summary one-liner.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} passes, {} functions, {} strings, {}ms{}",
            self.stats.passes.len(),
            self.total_functions(),
            self.total_strings(),
            self.stats.total_duration_ms,
            if self.success { "" } else { " [FAILED]" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisContext — rich context passed to analysis passes
// ─────────────────────────────────────────────────────────────────────────────

/// Context provided to analysis passes containing shared state.
pub struct AnalysisContext {
    /// The binary view being analysed.
    pub view: Arc<rustre_core::binary_view::BinaryView>,
    /// The event bus for publishing results.
    pub event_bus: Arc<AnalysisEventBus>,
    /// Shared statistics accumulator.
    pub stats: Arc<parking_lot::Mutex<AnalysisStats>>,
}

impl AnalysisContext {
    /// Create a new `AnalysisContext` from a `BinaryView`.
    #[must_use]
    pub fn new(view: Arc<rustre_core::binary_view::BinaryView>) -> Self {
        Self {
            view,
            event_bus: Arc::new(AnalysisEventBus::new()),
            stats: Arc::new(parking_lot::Mutex::new(AnalysisStats::new())),
        }
    }

    /// Emit an event on the shared bus.
    pub fn emit(&self, event: &AnalysisEvent) {
        self.event_bus.publish(event);
    }

    /// Subscribe to events.
    pub fn subscribe(&self, handler: EventHandler) {
        self.event_bus.subscribe(handler);
    }
}

impl std::fmt::Debug for AnalysisContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisContext")
            .field("uri", &self.view.uri)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisDb — persistent result storage
// ─────────────────────────────────────────────────────────────────────────────

/// A record stored in the analysis database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisDbRecord {
    /// Unique record id.
    pub id: u64,
    /// Pass name that produced this record.
    pub pass_name: String,
    /// Binary URI.
    pub uri: String,
    /// JSON-serialised result payload.
    pub payload: String,
    /// Unix timestamp (seconds since epoch) when the record was created.
    pub created_at: u64,
}

/// In-memory analysis result database (production would use SQLite/MySQL).
#[derive(Debug, Default)]
pub struct AnalysisDb {
    records: parking_lot::RwLock<Vec<AnalysisDbRecord>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl AnalysisDb {
    /// Create a new empty `AnalysisDb`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record. Returns the assigned id.
    pub fn insert(&self, pass_name: &str, uri: &str, payload: &str) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.records.write().push(AnalysisDbRecord {
            id,
            pass_name: pass_name.to_string(),
            uri: uri.to_string(),
            payload: payload.to_string(),
            created_at,
        });
        id
    }

    /// Query records by pass name.
    #[must_use]
    pub fn query_by_pass(&self, pass_name: &str) -> Vec<AnalysisDbRecord> {
        self.records
            .read()
            .iter()
            .filter(|r| r.pass_name == pass_name)
            .cloned()
            .collect()
    }

    /// Query records by URI.
    #[must_use]
    pub fn query_by_uri(&self, uri: &str) -> Vec<AnalysisDbRecord> {
        self.records
            .read()
            .iter()
            .filter(|r| r.uri == uri)
            .cloned()
            .collect()
    }

    /// Total number of records.
    #[must_use]
    pub fn count(&self) -> usize {
        self.records.read().len()
    }

    /// Delete all records for a URI.
    pub fn delete_by_uri(&self, uri: &str) -> usize {
        let mut guard = self.records.write();
        let before = guard.len();
        guard.retain(|r| r.uri != uri);
        before - guard.len()
    }

    /// Serialise all records to JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialisation error if serialisation fails.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&*self.records.read())
    }

    /// Deserialise all [`FunctionBoundary`] records stored by the function-discovery
    /// passes.
    ///
    /// Records whose `payload` cannot be parsed as `Vec<FunctionBoundary>` are
    /// silently skipped so that unrelated pass results do not cause a panic.
    #[must_use]
    pub fn query_functions(&self) -> Vec<FunctionBoundary> {
        self.records
            .read()
            .iter()
            .flat_map(|r| {
                serde_json::from_str::<Vec<FunctionBoundary>>(&r.payload).unwrap_or_default()
            })
            .collect()
    }

    /// Deserialise all [`Xref`] records stored by the xref-recovery passes.
    ///
    /// Records whose `payload` cannot be parsed as `Vec<Xref>` are silently
    /// skipped so that unrelated pass results do not cause a panic.
    #[must_use]
    pub fn query_xrefs(&self) -> Vec<Xref> {
        self.records
            .read()
            .iter()
            .flat_map(|r| serde_json::from_str::<Vec<Xref>>(&r.payload).unwrap_or_default())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrossReferenceDb — global xref database
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum XrefType {
    /// Direct call to a function.
    Call,
    /// Unconditional jump.
    Jump,
    /// Read access to a memory location.
    DataRead,
    /// Write access to a memory location.
    DataWrite,
    /// Reference to a string.
    StringRef,
    /// Unknown xref type.
    Unknown,
}

impl std::fmt::Display for XrefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::DataRead => "data_read",
            Self::DataWrite => "data_write",
            Self::StringRef => "string_ref",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// One cross-reference entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Xref {
    /// Address where the reference originates.
    pub from: u64,
    /// Address being referenced.
    pub to: u64,
    /// Kind of cross-reference.
    pub kind: XrefType,
}

impl Xref {
    /// Create a new `Xref`.
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: XrefType) -> Self {
        Self { from, to, kind }
    }
}

/// A global cross-reference database.
///
/// Uses two `HashMap<u64, Vec<Xref>>` indices for O(1) average-case lookups
/// in both the `from` and `to` directions, replacing the previous linear scan
/// over a single `Vec<Xref>`.
#[derive(Debug, Default)]
pub struct CrossReferenceDb {
    /// Index keyed by the *source* address.
    from_index: parking_lot::RwLock<HashMap<u64, Vec<Xref>>>,
    /// Index keyed by the *target* address.
    to_index: parking_lot::RwLock<HashMap<u64, Vec<Xref>>>,
}

impl CrossReferenceDb {
    /// Create a new, empty `CrossReferenceDb`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cross-reference.
    pub fn add(&self, xref: Xref) {
        // Insert into to_index first, then from_index.
        self.to_index.write().entry(xref.to).or_default().push(xref.clone());
        self.from_index.write().entry(xref.from).or_default().push(xref);
    }

    /// Add a cross-reference from raw parts.
    pub fn add_raw(&self, from: u64, to: u64, kind: XrefType) {
        self.add(Xref::new(from, to, kind));
    }

    /// All xrefs *to* the given address.
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> Vec<Xref> {
        self.to_index.read().get(&addr).cloned().unwrap_or_default()
    }

    /// All xrefs *from* the given address.
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> Vec<Xref> {
        self.from_index
            .read()
            .get(&addr)
            .cloned()
            .unwrap_or_default()
    }

    /// All call xrefs.
    #[must_use]
    pub fn calls(&self) -> Vec<Xref> {
        self.from_index
            .read()
            .values()
            .flat_map(|v| v.iter())
            .filter(|x| x.kind == XrefType::Call)
            .cloned()
            .collect()
    }

    /// Total number of xrefs.
    #[must_use]
    pub fn count(&self) -> usize {
        self.from_index.read().values().map(std::vec::Vec::len).sum()
    }

    /// Clear all xrefs.
    pub fn clear(&self) {
        self.from_index.write().clear();
        self.to_index.write().clear();
    }

    /// All unique call targets.
    #[must_use]
    pub fn call_targets(&self) -> Vec<u64> {
        let mut targets: Vec<u64> = self.from_index.read()
            .values()
            .flat_map(|v| v.iter())
            .filter(|x| x.kind == XrefType::Call)
            .map(|x| x.to)
            .collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionBoundary — function start/end discovery
// ─────────────────────────────────────────────────────────────────────────────

/// A detected function boundary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionBoundary {
    /// Start address of the function.
    pub start: u64,
    /// End address (first byte past the function).
    pub end: u64,
    /// Name hint, if available.
    pub name: Option<String>,
    /// How confident we are (0–100).
    pub confidence: u8,
    /// Discovery method.
    pub method: BoundaryMethod,
}

/// How a function boundary was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BoundaryMethod {
    /// Found at a call target.
    CallTarget,
    /// Found via linear sweep.
    LinearSweep,
    /// Found via recursive descent.
    RecursiveDescent,
    /// From a symbol table entry.
    SymbolTable,
    /// Function prologue pattern match.
    ProloguePattern,
    /// Heuristic gap fill.
    HeuristicGap,
}

impl FunctionBoundary {
    /// Create a new `FunctionBoundary`.
    #[must_use]
    pub const fn new(start: u64, end: u64, method: BoundaryMethod) -> Self {
        Self {
            start,
            end,
            name: None,
            confidence: 50,
            method,
        }
    }

    /// Set a name hint.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set confidence level.
    #[must_use]
    pub const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Size of the function in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this boundary is high-confidence (>= 70).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 70
    }
}

/// Analyses a byte slice to find function starts and ends via prologues and call targets.
pub struct FunctionBoundaryAnalysis;

impl FunctionBoundaryAnalysis {
    /// x86-64 function prologue patterns.
    pub const PROLOGUE_PUSH_RBP: &'static [u8] = &[0x55, 0x48, 0x89, 0xE5];
    pub const PROLOGUE_SUB_RSP: &'static [u8] = &[0x48, 0x83, 0xEC];
    pub const PROLOGUE_PUSH_RBP_MOV: &'static [u8] = &[0x55, 0x48, 0x8B, 0xEC];

    /// Scan `bytes` (loaded at `base`) for function prologues.
    ///
    /// Returns **start-only candidates**: each `FunctionBoundary` has `end == start`
    /// because the true function end cannot be determined from prologue matching alone.
    /// Callers that need real end addresses (e.g. [`LinearSweepAnalyzer::sweep`]) must
    /// fill in `end` themselves before using [`FunctionBoundary::size`] or
    /// [`FunctionBoundary::is_high_confidence`].
    ///
    /// # `DoS` note
    /// The result is capped at 1,048,576 entries to prevent a binary consisting
    /// entirely of prologue bytes from exhausting memory (dos-memory-exhaustion).
    #[must_use]
    pub fn scan_prologues(base: u64, bytes: &[u8]) -> Vec<FunctionBoundary> {
        const MAX_PROLOGUES: usize = 1 << 20; // 1 M function candidates
        let mut boundaries = Vec::new();
        let len = bytes.len();

        let mut i = 0usize;
        while i < len {
            // PUSH RBP; MOV RBP, RSP (or variant)
            let remaining = &bytes[i..];
            if remaining.starts_with(Self::PROLOGUE_PUSH_RBP)
                || remaining.starts_with(Self::PROLOGUE_PUSH_RBP_MOV)
            {
                let start = base + i as u64;
                boundaries.push(
                    FunctionBoundary::new(
                        start,
                        start, // end unknown until caller resolves it
                        BoundaryMethod::ProloguePattern,
                    )
                    .with_confidence(80),
                );
                if boundaries.len() >= MAX_PROLOGUES {
                    break;
                }
                i += 4;
                continue;
            }
            if remaining.starts_with(Self::PROLOGUE_SUB_RSP) {
                let start = base + i as u64;
                boundaries.push(
                    FunctionBoundary::new(
                        start,
                        start, // end unknown until caller resolves it
                        BoundaryMethod::ProloguePattern,
                    )
                    .with_confidence(70),
                );
                if boundaries.len() >= MAX_PROLOGUES {
                    break;
                }
                i += 3;
                continue;
            }
            i += 1;
        }
        boundaries
    }

    /// Find call targets from a simple x86-64 `CALL rel32` scan (`E8` opcode).
    ///
    /// # `DoS` note
    /// The result is capped at 1,048,576 unique targets to prevent a
    /// maliciously crafted binary (e.g. a megabyte of 0xE8 bytes) from
    /// exhausting memory before `dedup` runs (dos-memory-exhaustion).
    #[must_use]
    pub fn scan_call_targets(base: u64, bytes: &[u8]) -> Vec<u64> {
        const MAX_TARGETS: usize = 1 << 20; // 1 M targets ≈ 8 MB
        let mut targets = Vec::new();
        let len = bytes.len();
        let mut i = 0usize;
        while i + 5 <= len {
            if bytes[i] == 0xE8 {
                // rel32 call
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_ip = base + (i as u64) + 5;
                let target = next_ip.wrapping_add_signed(i64::from(rel));
                targets.push(target);
                // Enforce cap early to avoid memory exhaustion before dedup.
                if targets.len() >= MAX_TARGETS {
                    break;
                }
            }
            i += 1;
        }
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinearSweepAnalyzer — linear sweep code discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the linear sweep analyzer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinearSweepConfig {
    /// Minimum function size in bytes.
    pub min_function_size: usize,
    /// Maximum gap (dead bytes) before stopping a function.
    pub max_gap: usize,
    /// Whether to follow call targets.
    pub follow_calls: bool,
}

impl Default for LinearSweepConfig {
    fn default() -> Self {
        Self {
            min_function_size: 4,
            max_gap: 16,
            follow_calls: true,
        }
    }
}

/// Discovers functions by linearly sweeping over all executable bytes.
pub struct LinearSweepAnalyzer {
    config: LinearSweepConfig,
}

impl LinearSweepAnalyzer {
    /// Create a new `LinearSweepAnalyzer` with the given config.
    #[must_use]
    pub const fn new(config: LinearSweepConfig) -> Self {
        Self { config }
    }

    /// Run a linear sweep over `bytes` at `base`.
    ///
    /// Returns a list of discovered `FunctionBoundary` entries.
    #[must_use]
    pub fn sweep(&self, base: u64, bytes: &[u8]) -> Vec<FunctionBoundary> {
        let mut results = Vec::new();

        // Collect prologue hits
        let mut prologue_starts = FunctionBoundaryAnalysis::scan_prologues(base, bytes);

        // Collect call targets
        if self.config.follow_calls {
            for target in FunctionBoundaryAnalysis::scan_call_targets(base, bytes) {
                if target >= base && target < base.saturating_add(bytes.len() as u64) {
                    let off = usize::try_from(target - base).unwrap_or(usize::MAX);
                    // A call target that lands directly on a recognised prologue
                    // pattern is far more likely to be a genuine function entry,
                    // so boost the confidence in that case.
                    let at_target = &bytes[off..];
                    let confidence = if at_target
                        .starts_with(FunctionBoundaryAnalysis::PROLOGUE_PUSH_RBP)
                        || at_target.starts_with(FunctionBoundaryAnalysis::PROLOGUE_PUSH_RBP_MOV)
                        || at_target.starts_with(FunctionBoundaryAnalysis::PROLOGUE_SUB_RSP)
                    {
                        90
                    } else {
                        75
                    };
                    let boundary =
                        FunctionBoundary::new(target, target + 1, BoundaryMethod::CallTarget)
                            .with_confidence(confidence);
                    // Avoid duplicates with prologue_starts
                    if !prologue_starts.iter().any(|b| b.start == target) {
                        prologue_starts.push(boundary);
                    }
                }
            }
        }

        prologue_starts.sort_unstable_by_key(|b| b.start);
        prologue_starts.dedup_by_key(|b| b.start);

        // Estimate function ends: each function ends where the next starts (or at file end)
        let file_end = base.saturating_add(bytes.len() as u64);
        for (i, boundary) in prologue_starts.iter().enumerate() {
            let end = if i + 1 < prologue_starts.len() {
                prologue_starts[i + 1].start
            } else {
                file_end
            };
            if end > boundary.start
                && usize::try_from(end - boundary.start).unwrap_or(usize::MAX) >= self.config.min_function_size
            {
                results.push(FunctionBoundary {
                    start: boundary.start,
                    end,
                    name: None,
                    confidence: boundary.confidence,
                    method: boundary.method,
                });
            }
        }
        results
    }

    /// Total functions discovered.
    #[must_use]
    pub fn sweep_count(&self, base: u64, bytes: &[u8]) -> usize {
        self.sweep(base, bytes).len()
    }
}

impl Default for LinearSweepAnalyzer {
    fn default() -> Self {
        Self::new(LinearSweepConfig::default())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchAwareSweepAnalyzer — architecture-agnostic linear sweep
// ─────────────────────────────────────────────────────────────────────────────

/// An architecture-aware linear sweep analyzer that uses the [`Architecture`]
/// trait for disassembly instead of hardcoded x86-64 byte patterns.
///
/// Function entries are identified by two heuristics, both architecture-agnostic:
///
/// 1. **Call targets** — every statically-known target of a `CALL`-flagged
///    instruction (`InstrFlags::CALL`) is recorded as a function entry.
/// 2. **Post-terminator alignment** — the first aligned address after a
///    `TERMINATOR`-flagged instruction (RET, trap, etc.) is treated as a
///    potential function entry.
pub struct ArchAwareSweepAnalyzer {
    arch: Arc<dyn Architecture>,
    config: LinearSweepConfig,
}

impl ArchAwareSweepAnalyzer {
    /// Create a new analyzer bound to `arch`.
    #[must_use]
    pub fn new(arch: Arc<dyn Architecture>, config: LinearSweepConfig) -> Self {
        Self { arch, config }
    }

    /// Create with default [`LinearSweepConfig`].
    #[must_use]
    pub fn with_default_config(arch: Arc<dyn Architecture>) -> Self {
        Self::new(arch, LinearSweepConfig::default())
    }

    /// Run the architecture-aware sweep over `bytes` loaded at `base`.
    ///
    /// Returns a list of discovered [`FunctionBoundary`] entries.
    #[must_use]
    pub fn sweep(&self, base: u64, bytes: &[u8]) -> Vec<FunctionBoundary> {
        use rustre_core::arch::InstrFlags;

        let align = self.arch.instruction_alignment().max(1) as u64;
        let mut candidate_starts: Vec<(u64, BoundaryMethod, u8)> = Vec::new();

        let mut offset: usize = 0;
        let mut after_terminator = false;

        while offset < bytes.len() {
            let addr = Address::new(base + offset as u64);
            let slice = &bytes[offset..];

            match self.arch.disassemble(addr, slice) {
                Err(_) => {
                    // Skip one byte on decode failure and reset the
                    // post-terminator flag so we do not misidentify
                    // a padding byte as a function entry.
                    after_terminator = false;
                    offset += 1;
                }
                Ok(instr) => {
                    let instr_size = instr.size.max(1);
                    let flags = instr.flags;

                    // Heuristic 1: first aligned address after a terminator is
                    // a function entry candidate.
                    if after_terminator {
                        let cur_va = base + offset as u64;
                        if align == 1 || cur_va.is_multiple_of(align) {
                            candidate_starts.push((cur_va, BoundaryMethod::LinearSweep, 60));
                            after_terminator = false;
                        }
                    }

                    // Heuristic 2: call targets.
                    if self.config.follow_calls && flags.contains(InstrFlags::CALL) {
                        // Use get_branches to find the static target(s).
                        for branch in self.arch.get_branches(&instr) {
                            if let Some(target) = branch.target
                                && target >= base && target < base.saturating_add(bytes.len() as u64) {
                                    candidate_starts.push((target, BoundaryMethod::CallTarget, 80));
                                }
                        }
                    }

                    // A TERMINATOR ends the basic block; next iteration may
                    // start a new function.
                    if flags.contains(InstrFlags::TERMINATOR) || flags.contains(InstrFlags::RET) {
                        after_terminator = true;
                    }

                    offset += instr_size;
                }
            }
        }

        // De-duplicate, keeping the highest-confidence entry per address.
        candidate_starts.sort_unstable_by_key(|&(a, _, c)| (a, std::cmp::Reverse(c)));
        candidate_starts.dedup_by_key(|e| e.0);

        // Sort by address so we can estimate function ends.
        candidate_starts.sort_unstable_by_key(|e| e.0);

        let file_end = base.saturating_add(bytes.len() as u64);
        let mut results = Vec::new();

        for (i, &(start, method, confidence)) in candidate_starts.iter().enumerate() {
            let end = if i + 1 < candidate_starts.len() {
                candidate_starts[i + 1].0
            } else {
                file_end
            };
            if end > start && usize::try_from(end - start).unwrap_or(usize::MAX) >= self.config.min_function_size {
                results.push(FunctionBoundary::new(start, end, method).with_confidence(confidence));
            }
        }

        results
    }
}

impl std::fmt::Debug for ArchAwareSweepAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchAwareSweepAnalyzer")
            .field("arch", &self.arch.name())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for ArchAwareSweepAnalyzer {
    fn name(&self) -> &'static str {
        "arch_aware_sweep"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::LinearSweep
    }

    fn description(&self) -> &'static str {
        "Architecture-aware linear sweep using the Architecture trait for disassembly"
    }

    fn supports_arch(&self, arch_name: &str) -> bool {
        self.arch.name() == arch_name
    }

    async fn run(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        // Determine the byte range to sweep.
        let (base, bytes) = {
            // Use the configured start address or fall back to the first
            // entry point / first segment base.
            let start_va = config
                .start_address
                .or_else(|| view.entry_points.first().copied())
                .unwrap_or_else(|| Address::new(0));

            // Read executable bytes from the view's memory map.
            // We collect all bytes in all segments that contain start_va
            // or simply sweep the whole mapped range if none matches.
            let seg_opt = view.mem.read()
                .segments
                .iter()
                .find(|s| s.range.contains(start_va))
                .map(|s| (s.range.start.as_u64(), s.data.clone()));

            match seg_opt {
                Some((base_va, data)) => (base_va, data),
                None => {
                    return Err(AnalysisError::InsufficientData(start_va.as_u64()));
                }
            }
        };

        let boundaries = self.sweep(base, &bytes);
        let functions_found = boundaries.len();

        Ok(AnalysisResult {
            kind: config.kind.clone(),
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecursiveDescentAnalyzer — recursive descent code discovery
// ─────────────────────────────────────────────────────────────────────────────

/// A work-list entry for recursive descent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DescentTarget {
    address: u64,
    depth: usize,
}

/// Discovers functions by recursively following call/jump targets.
pub struct RecursiveDescentAnalyzer {
    /// Maximum recursion depth.
    pub max_depth: usize,
}

impl RecursiveDescentAnalyzer {
    /// Create a new `RecursiveDescentAnalyzer` with the given max depth.
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Perform recursive descent starting from `entry_points`.
    ///
    /// Returns the set of discovered function start addresses.
    ///
    /// # `DoS` note
    /// The total number of visited addresses is capped at 1,048,576 to prevent
    /// a binary with a dense `E8`-byte pattern from exhausting both the worklist
    /// queue and the visited set (dos-memory-exhaustion).
    #[must_use]
    pub fn descend(
        &self,
        base: u64,
        bytes: &[u8],
        entry_points: &[u64],
    ) -> std::collections::HashSet<u64> {
        const MAX_VISITED: usize = 1 << 20; // 1 M addresses ≈ 8 MB
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut worklist: std::collections::VecDeque<DescentTarget> = entry_points
            .iter()
            .map(|&a| DescentTarget {
                address: a,
                depth: 0,
            })
            .collect();

        while let Some(item) = worklist.pop_front() {
            if visited.contains(&item.address) {
                continue;
            }
            if item.depth > self.max_depth {
                continue;
            }
            if item.address < base || item.address >= base.saturating_add(bytes.len() as u64) {
                continue;
            }
            // Enforce the visit cap before inserting so that neither the
            // visited set nor the worklist can grow without bound.
            if visited.len() >= MAX_VISITED {
                break;
            }
            visited.insert(item.address);

            let off = usize::try_from(item.address - base).unwrap_or(usize::MAX);
            let slice = &bytes[off..];

            // Follow CALL rel32 (E8) targets
            for (j, window) in slice.windows(5).enumerate() {
                if window[0] == 0xE8 {
                    let rel = i32::from_le_bytes([window[1], window[2], window[3], window[4]]);
                    let call_ip = item.address + u64::try_from(j).unwrap_or(u64::MAX) + 5;
                    let target = call_ip.wrapping_add_signed(i64::from(rel));
                    if !visited.contains(&target) {
                        worklist.push_back(DescentTarget {
                            address: target,
                            depth: item.depth + 1,
                        });
                    }
                }
            }
        }
        visited
    }

    /// Discover functions and return them as `FunctionBoundary` entries.
    #[must_use]
    pub fn analyze(&self, base: u64, bytes: &[u8], entry_points: &[u64]) -> Vec<FunctionBoundary> {
        let discovered = self.descend(base, bytes, entry_points);
        let mut starts: Vec<u64> = discovered.into_iter().collect();
        starts.sort_unstable();

        let file_end = base.saturating_add(bytes.len() as u64);
        starts
            .iter()
            .enumerate()
            .map(|(i, &start)| {
                let end = if i + 1 < starts.len() {
                    starts[i + 1]
                } else {
                    file_end
                };
                FunctionBoundary::new(start, end, BoundaryMethod::RecursiveDescent)
                    .with_confidence(85)
            })
            .collect()
    }
}

impl Default for RecursiveDescentAnalyzer {
    fn default() -> Self {
        Self::new(512)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IncrementalAnalysis — rerun only affected passes
// ─────────────────────────────────────────────────────────────────────────────

/// A change to a binary that may invalidate some analysis passes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryChange {
    /// Address range that changed.
    pub address_start: u64,
    /// End address (exclusive) of the changed region.
    pub address_end: u64,
    /// What kind of change occurred.
    pub kind: ChangeKind,
}

/// Kind of binary change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChangeKind {
    /// Bytes were modified.
    DataModified,
    /// A new section was added.
    SectionAdded,
    /// A symbol was renamed.
    SymbolRenamed,
    /// Metadata changed.
    MetadataChanged,
}

/// Tracks which passes need to be re-run after a binary change.
pub struct IncrementalAnalysis {
    /// Pass names that are sensitive to byte-level changes.
    byte_sensitive: std::collections::HashSet<String>,
    /// Pass names that are sensitive to symbol changes.
    symbol_sensitive: std::collections::HashSet<String>,
    /// Previously run pass names.
    run_passes: std::collections::HashSet<String>,
}

impl IncrementalAnalysis {
    /// Create a new `IncrementalAnalysis` tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            byte_sensitive: std::collections::HashSet::new(),
            symbol_sensitive: std::collections::HashSet::new(),
            run_passes: std::collections::HashSet::new(),
        }
    }

    /// Mark a pass as byte-change-sensitive.
    pub fn mark_byte_sensitive(&mut self, pass_name: impl Into<String>) {
        self.byte_sensitive.insert(pass_name.into());
    }

    /// Mark a pass as symbol-change-sensitive.
    pub fn mark_symbol_sensitive(&mut self, pass_name: impl Into<String>) {
        self.symbol_sensitive.insert(pass_name.into());
    }

    /// Record that a pass has been run.
    pub fn mark_run(&mut self, pass_name: impl Into<String>) {
        self.run_passes.insert(pass_name.into());
    }

    /// Given a set of changes, return the passes that need to be re-run.
    #[must_use]
    pub fn affected_passes(&self, changes: &[BinaryChange]) -> Vec<String> {
        let has_data = changes.iter().any(|c| c.kind == ChangeKind::DataModified);
        let has_symbol = changes.iter().any(|c| c.kind == ChangeKind::SymbolRenamed);

        let mut affected = std::collections::HashSet::new();
        if has_data {
            for name in &self.byte_sensitive {
                if self.run_passes.contains(name) {
                    affected.insert(name.clone());
                }
            }
        }
        if has_symbol {
            for name in &self.symbol_sensitive {
                if self.run_passes.contains(name) {
                    affected.insert(name.clone());
                }
            }
        }
        // All passes are affected by section additions
        if changes.iter().any(|c| c.kind == ChangeKind::SectionAdded) {
            for name in &self.run_passes {
                affected.insert(name.clone());
            }
        }

        let mut list: Vec<String> = affected.into_iter().collect();
        list.sort_unstable();
        list
    }
}

impl Default for IncrementalAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPlugin — external / dynamically-loaded analysis passes
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for an analysis plugin.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin id.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Plugin version string.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Author.
    pub author: String,
    /// Which `AnalysisKind`s this plugin provides.
    pub provides: Vec<AnalysisKind>,
}

/// Trait for analysis plugins that can be loaded at runtime.
pub trait AnalysisPlugin: Send + Sync {
    /// Return this plugin's metadata.
    fn metadata(&self) -> &PluginMetadata;

    /// Return all analysis passes provided by this plugin.
    fn passes(&self) -> Vec<Arc<dyn AnalysisPass>>;

    /// Called when the plugin is loaded. Perform any initialization here.
    fn on_load(&self) {}

    /// Called when the plugin is unloaded.
    fn on_unload(&self) {}
}

/// Registry of loaded analysis plugins.
#[derive(Default)]
pub struct AnalysisPluginRegistry {
    plugins: parking_lot::RwLock<Vec<Arc<dyn AnalysisPlugin>>>,
}

impl std::fmt::Debug for AnalysisPluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisPluginRegistry")
            .field("count", &self.plugins.read().len())
            .finish_non_exhaustive()
    }
}

impl AnalysisPluginRegistry {
    /// Create a new, empty plugin registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a plugin into the registry.
    pub fn load(&self, plugin: Arc<dyn AnalysisPlugin>) {
        plugin.on_load();
        self.plugins.write().push(plugin);
    }

    /// Find a plugin by id.
    #[must_use]
    pub fn find_by_id(&self, id: &str) -> Option<Arc<dyn AnalysisPlugin>> {
        self.plugins
            .read()
            .iter()
            .find(|p| p.metadata().id == id)
            .cloned()
    }

    /// Get all passes from all loaded plugins.
    #[must_use]
    pub fn all_passes(&self) -> Vec<Arc<dyn AnalysisPass>> {
        self.plugins
            .read()
            .iter()
            .flat_map(|p| p.passes())
            .collect()
    }

    /// Number of loaded plugins.
    #[must_use]
    pub fn plugin_count(&self) -> usize {
        self.plugins.read().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisManager — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level analysis orchestrator that coordinates passes, the event bus,
/// and the result database.
pub struct AnalysisManager {
    pipeline: Arc<AnalysisPipeline>,
    db: Arc<AnalysisDb>,
    xref_db: Arc<CrossReferenceDb>,
    event_bus: Arc<AnalysisEventBus>,
    scheduler: parking_lot::Mutex<PassScheduler>,
    incremental: parking_lot::Mutex<IncrementalAnalysis>,
}

impl std::fmt::Debug for AnalysisManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisManager")
            .field("pass_count", &self.pipeline.pass_count())
            .field("xref_count", &self.xref_db.count())
            .finish_non_exhaustive()
    }
}

impl AnalysisManager {
    /// Create a new `AnalysisManager`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pipeline: Arc::new(AnalysisPipeline::new()),
            db: Arc::new(AnalysisDb::new()),
            xref_db: Arc::new(CrossReferenceDb::new()),
            event_bus: Arc::new(AnalysisEventBus::new()),
            scheduler: parking_lot::Mutex::new(PassScheduler::new()),
            incremental: parking_lot::Mutex::new(IncrementalAnalysis::new()),
        }
    }

    /// Register a pass.
    pub fn register_pass(&self, pass: Arc<dyn AnalysisPass>) {
        self.pipeline.register(pass);
    }

    /// Register a pass with dependency information.
    pub fn register_pass_with_deps(&self, pass: Arc<dyn AnalysisPass>, deps: Vec<String>) {
        let mut desc = PassDescriptor::new(pass.name()).with_priority(pass.priority());
        for dep in deps {
            desc = desc.with_dep(dep);
        }
        self.scheduler.lock().add(desc);
        self.pipeline.register(pass);
    }

    /// Access the event bus.
    #[must_use]
    pub fn event_bus(&self) -> &AnalysisEventBus {
        &self.event_bus
    }

    /// Access the analysis database.
    #[must_use]
    pub fn db(&self) -> &AnalysisDb {
        &self.db
    }

    /// Access the cross-reference database.
    #[must_use]
    pub fn xref_db(&self) -> &CrossReferenceDb {
        &self.xref_db
    }

    /// Run all passes and return a full `AnalysisReport`.
    pub async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        config: &AnalysisConfig,
    ) -> AnalysisReport {
        let pass_names = self.pipeline.pass_names();
        let raw_results = self.pipeline.run_all(view, config).await;

        let outcomes: Vec<(String, Result<AnalysisResult, AnalysisError>)> =
            pass_names.into_iter().zip(raw_results).collect();

        // Store results in DB and record successful passes in the incremental
        // tracker so a later change-set can compute which passes to re-run.
        for (name, result) in &outcomes {
            if let Ok(r) = result {
                self.incremental.lock().mark_run(name);
                if let Ok(json) = serde_json::to_string(r) {
                    self.db.insert(name, &view.uri, &json);
                }
            }
        }

        AnalysisReport::build(&view.uri, &outcomes)
    }

    /// Mark a pass as sensitive to byte-level changes for incremental re-runs.
    pub fn mark_byte_sensitive(&self, pass_name: impl Into<String>) {
        self.incremental.lock().mark_byte_sensitive(pass_name);
    }

    /// Mark a pass as sensitive to symbol changes for incremental re-runs.
    pub fn mark_symbol_sensitive(&self, pass_name: impl Into<String>) {
        self.incremental.lock().mark_symbol_sensitive(pass_name);
    }

    /// Given a set of binary changes, return the passes that must be re-run.
    #[must_use]
    pub fn passes_to_rerun(&self, changes: &[BinaryChange]) -> Vec<String> {
        self.incremental.lock().affected_passes(changes)
    }

    /// Return the scheduled pass order.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a dependency cycle.
    pub fn scheduled_order(&self) -> Result<Vec<String>, String> {
        self.scheduler.lock().schedule()
    }

    /// Register an [`ArchAwareSweepAnalyzer`] for the given architecture.
    ///
    /// If an arch-aware sweep pass is already registered it will be replaced
    /// (because [`AnalysisPipeline::register`] deduplicates by name).
    pub fn register_arch_aware_sweep(
        &self,
        arch: Arc<dyn Architecture>,
        config: LinearSweepConfig,
    ) {
        let pass = Arc::new(ArchAwareSweepAnalyzer::new(arch, config));
        self.pipeline.register(pass);
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.pipeline.pass_count()
    }
}

impl Default for AnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinearSweepPass — AnalysisPass wrapper for LinearSweepAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// An [`AnalysisPass`] that wraps [`LinearSweepAnalyzer`] for use in a pipeline.
pub struct LinearSweepPass {
    inner: LinearSweepAnalyzer,
}

impl LinearSweepPass {
    /// Create a new `LinearSweepPass` with the given config.
    #[must_use]
    pub const fn new(config: LinearSweepConfig) -> Self {
        Self {
            inner: LinearSweepAnalyzer::new(config),
        }
    }
}

impl Default for LinearSweepPass {
    fn default() -> Self {
        Self::new(LinearSweepConfig::default())
    }
}

impl std::fmt::Debug for LinearSweepPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearSweepPass").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for LinearSweepPass {
    fn name(&self) -> &'static str {
        "linear_sweep"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::LinearSweep
    }

    fn description(&self) -> &'static str {
        "Discovers function boundaries by linearly sweeping over executable bytes"
    }

    fn priority(&self) -> i32 {
        100
    }

    async fn run(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let (base, bytes) = {
            let start_va = config
                .start_address
                .or_else(|| view.entry_points.first().copied())
                .unwrap_or_else(|| Address::new(0));

            let seg_opt = {
                let mem_guard = view.mem.read();
                mem_guard
                    .segments
                    .iter()
                    .find(|s| s.range.contains(start_va))
                    .or_else(|| mem_guard.segments.first())
                    .map(|s| (s.range.start.as_u64(), s.data.clone()))
            };

            match seg_opt {
                Some(pair) => pair,
                None => return Err(AnalysisError::InsufficientData(start_va.as_u64())),
            }
        };

        let boundaries = self.inner.sweep(base, &bytes);
        let functions_found = boundaries.len();

        Ok(AnalysisResult {
            kind: AnalysisKind::LinearSweep,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecursiveDescentPass — AnalysisPass wrapper for RecursiveDescentAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// An [`AnalysisPass`] that wraps [`RecursiveDescentAnalyzer`] for use in a pipeline.
pub struct RecursiveDescentPass {
    inner: RecursiveDescentAnalyzer,
}

impl RecursiveDescentPass {
    /// Create a new `RecursiveDescentPass` with the given max depth.
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self {
            inner: RecursiveDescentAnalyzer::new(max_depth),
        }
    }
}

impl Default for RecursiveDescentPass {
    fn default() -> Self {
        Self::new(512)
    }
}

impl std::fmt::Debug for RecursiveDescentPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecursiveDescentPass")
            .field("max_depth", &self.inner.max_depth)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for RecursiveDescentPass {
    fn name(&self) -> &'static str {
        "recursive_descent"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::RecursiveDescent
    }

    fn description(&self) -> &'static str {
        "Discovers functions by recursively following call and jump targets"
    }

    fn priority(&self) -> i32 {
        90
    }

    async fn run(
        &self,
        view: &BinaryView,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let (base, bytes, entry_points) = {
            let seg_opt = {
                let mem_guard = view.mem.read();
                mem_guard
                    .segments
                    .iter()
                    .find(|s| {
                        config
                            .start_address
                            .or_else(|| view.entry_points.first().copied())
                            .is_none_or(|a| s.range.contains(a))
                    })
                    .or_else(|| mem_guard.segments.first())
                    .map(|s| (s.range.start.as_u64(), s.data.clone()))
            };

            match seg_opt {
                Some((base, bytes)) => {
                    let eps: Vec<u64> = view.entry_points.iter().map(|a| a.as_u64()).collect();
                    (base, bytes, eps)
                }
                None => return Err(AnalysisError::InsufficientData(0)),
            }
        };

        let entry_refs: Vec<u64> = if entry_points.is_empty() {
            vec![base]
        } else {
            entry_points
        };
        let boundaries = self.inner.analyze(base, &bytes, &entry_refs);
        let functions_found = boundaries.len();

        Ok(AnalysisResult {
            kind: AnalysisKind::RecursiveDescent,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringRecoveryPass — scan for null-terminated ASCII strings
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum printable ASCII string length to report.
const MIN_STRING_LEN: usize = 4;

/// An [`AnalysisPass`] that scans binary data for printable ASCII strings.
#[derive(Debug, Default)]
pub struct StringRecoveryPass;

impl StringRecoveryPass {
    /// Create a new `StringRecoveryPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Count printable ASCII strings of at least `MIN_STRING_LEN` characters.
    #[must_use]
    pub fn count_strings(bytes: &[u8]) -> usize {
        let mut count = 0usize;
        let mut run = 0usize;
        for &b in bytes {
            if b.is_ascii() && !b.is_ascii_control() {
                run += 1;
            } else {
                // A run ends at ANY non-printable byte, not only at NUL.
                //
                // This used to read `if b == 0 && run >= MIN_STRING_LEN`, so a
                // string followed by a newline, a tab, or any other byte that
                // is not a NUL was silently discarded: "hello", newline,
                // "world", NUL reported ONE string instead of two. The
                // function already contradicted itself -- the end-of-buffer
                // branch below counts a run with no terminator at all -- and
                // the sibling `StringRecoveryPass` in `pass_registry.rs`
                // counts on any terminator. Real images separate strings with
                // padding and other data, not only with NULs.
                if run >= MIN_STRING_LEN {
                    count += 1;
                }
                run = 0;
            }
        }
        // Run still open at end of buffer (no terminator at all).
        if run >= MIN_STRING_LEN {
            count += 1;
        }
        count
    }
}

#[async_trait::async_trait]
impl AnalysisPass for StringRecoveryPass {
    fn name(&self) -> &'static str {
        "string_recovery"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::StringRecovery
    }

    fn description(&self) -> &'static str {
        "Scans all mapped segments for null-terminated printable ASCII strings"
    }

    fn priority(&self) -> i32 {
        80
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let strings_found: usize = {
            let mem_guard = view.mem.read();
            mem_guard
                .segments
                .iter()
                .map(|s| Self::count_strings(&s.data))
                .sum()
        };

        Ok(AnalysisResult {
            kind: AnalysisKind::StringRecovery,
            functions_found: 0,
            data_refs_found: 0,
            strings_found,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefRecoveryPass — recover call/jump cross-references
// ─────────────────────────────────────────────────────────────────────────────

/// An [`AnalysisPass`] that recovers cross-references (calls and jumps) from
/// x86-64 `CALL rel32` and `JMP rel32` instruction patterns.
#[derive(Debug, Default)]
pub struct XrefRecoveryPass;

impl XrefRecoveryPass {
    /// Create a new `XrefRecoveryPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `bytes` at `base` for `CALL rel32` (E8) and `JMP rel32` (E9)
    /// instructions, returning the number of resolved xrefs that fall within
    /// the mapped range.
    #[must_use]
    pub fn count_xrefs(base: u64, bytes: &[u8]) -> usize {
        let mut count = 0usize;
        let len = bytes.len();
        let mut i = 0usize;
        while i + 5 <= len {
            let opcode = bytes[i];
            if opcode == 0xE8 || opcode == 0xE9 {
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_ip = base + (i as u64) + 5;
                let target = next_ip.wrapping_add_signed(i64::from(rel));
                if target >= base && target < base.saturating_add(len as u64) {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }
}

#[async_trait::async_trait]
impl AnalysisPass for XrefRecoveryPass {
    fn name(&self) -> &'static str {
        "xref_recovery"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::XrefRecovery
    }

    fn description(&self) -> &'static str {
        "Recovers intra-binary call and jump cross-references via pattern scanning"
    }

    fn priority(&self) -> i32 {
        70
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let data_refs_found: usize = {
            let mem_guard = view.mem.read();
            mem_guard
                .segments
                .iter()
                .map(|s| Self::count_xrefs(s.range.start.as_u64(), &s.data))
                .sum()
        };

        Ok(AnalysisResult {
            kind: AnalysisKind::XrefRecovery,
            functions_found: 0,
            data_refs_found,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDetectionPass — combined prologue + call-target detection
// ─────────────────────────────────────────────────────────────────────────────

/// An [`AnalysisPass`] that detects function entry points by combining
/// prologue pattern matching and call-target scanning.
#[derive(Debug, Default)]
pub struct FunctionDetectionPass;

impl FunctionDetectionPass {
    /// Create a new `FunctionDetectionPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AnalysisPass for FunctionDetectionPass {
    fn name(&self) -> &'static str {
        "function_detection"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::RecursiveDescent
    }

    fn description(&self) -> &'static str {
        "Detects function boundaries using prologue patterns and call-target analysis"
    }

    fn priority(&self) -> i32 {
        60
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let functions_found: usize = {
            let mem_guard = view.mem.read();
            mem_guard
                .segments
                .iter()
                .map(|s| {
                    let base = s.range.start.as_u64();
                    let prologue_hits =
                        FunctionBoundaryAnalysis::scan_prologues(base, &s.data).len();
                    let call_targets = FunctionBoundaryAnalysis::scan_call_targets(base, &s.data)
                        .into_iter()
                        .filter(|&t| t >= base && t < base.saturating_add(s.data.len() as u64))
                        .count();
                    // Deduplicate by taking the maximum (call targets often overlap prologues)
                    prologue_hits.max(call_targets)
                })
                .sum()
        };

        Ok(AnalysisResult {
            kind: AnalysisKind::RecursiveDescent,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgAnalysisPass — control-flow graph analysis
// ─────────────────────────────────────────────────────────────────────────────

/// An [`AnalysisPass`] that estimates basic-block and edge counts by scanning
/// for branch/return instructions in the mapped binary data.
#[derive(Debug, Default)]
pub struct CfgAnalysisPass;

impl CfgAnalysisPass {
    /// Create a new `CfgAnalysisPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Count approximate basic-block boundaries by scanning for:
    /// - Conditional/unconditional jumps (0x70–0x7F short Jcc, 0xEB JMP short,
    ///   0xE9 JMP rel32, 0x0F 0x8x long Jcc)
    /// - Return instructions (0xC3, 0xC2, 0xCB, 0xCA)
    #[must_use]
    pub fn count_basic_blocks(bytes: &[u8]) -> usize {
        let mut count = 1usize; // at least one block if there are bytes
        let len = bytes.len();
        let mut i = 0usize;
        while i < len {
            let b = bytes[i];
            match b {
                // Short Jcc (0x70–0x7F), JCXZ/JECXZ (0xE3), LOOP (0xE0–0xE2), JMP short (0xEB)
                0x70..=0x7F | 0xE0..=0xE3 | 0xEB => {
                    count += 1;
                    i += 2;
                }
                // JMP rel32 / CALL rel32 / Jcc long (0x0F 0x8x)
                0xE9 | 0xE8 => {
                    count += 1;
                    i += 5;
                }
                0x0F if i + 1 < len && (0x80..=0x8F).contains(&bytes[i + 1]) => {
                    count += 1;
                    i += 6;
                }
                // RET variants
                0xC2 | 0xC3 | 0xCA | 0xCB => {
                    count += 1;
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }
        }
        count
    }
}

#[async_trait::async_trait]
impl AnalysisPass for CfgAnalysisPass {
    fn name(&self) -> &'static str {
        "cfg_analysis"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::DataFlow
    }

    fn description(&self) -> &'static str {
        "Estimates basic-block and edge counts via branch/return instruction scanning"
    }

    fn priority(&self) -> i32 {
        50
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start_time = std::time::Instant::now();

        let data_refs_found: usize = {
            let mem_guard = view.mem.read();
            mem_guard
                .segments
                .iter()
                .map(|s| Self::count_basic_blocks(&s.data))
                .sum()
        };

        Ok(AnalysisResult {
            kind: AnalysisKind::DataFlow,
            functions_found: 0,
            data_refs_found,
            strings_found: 0,
            duration_ms: start_time.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisManager::analyze_binary_view + analyze_binary free function
// ─────────────────────────────────────────────────────────────────────────────

impl AnalysisManager {
    /// Register all standard built-in passes and run them sequentially against
    /// `view`, returning a structured [`AnalysisReport`].
    ///
    /// Passes registered (in priority order, highest first):
    /// 1. `linear_sweep` (priority 100)
    /// 2. `recursive_descent` (priority 90)
    /// 3. `string_recovery` (priority 80)
    /// 4. `xref_recovery` (priority 70)
    /// 5. `function_detection` (priority 60)
    /// 6. `cfg_analysis` (priority 50)
    pub async fn analyze_binary_view(&self, view: &BinaryView) -> AnalysisReport {
        // Register all standard passes (dedup by name if already present)
        self.pipeline.register(Arc::new(LinearSweepPass::default()));
        self.pipeline
            .register(Arc::new(RecursiveDescentPass::default()));
        self.pipeline.register(Arc::new(StringRecoveryPass::new()));
        self.pipeline.register(Arc::new(XrefRecoveryPass::new()));
        self.pipeline
            .register(Arc::new(FunctionDetectionPass::new()));
        self.pipeline.register(Arc::new(CfgAnalysisPass::new()));

        let config = AnalysisConfig::new(AnalysisKind::LinearSweep);
        self.run(view, &config).await
    }
}

/// Flat (byte-at-a-time) architecture used internally by [`analyze_binary`].
#[derive(Debug)]
struct FlatArch {
    arch_name: String,
    bits: u32,
}

impl FlatArch {
    fn new(arch_name: impl Into<String>, bits: u32) -> Self {
        Self {
            arch_name: arch_name.into(),
            bits,
        }
    }
}

impl rustre_core::arch::Architecture for FlatArch {
    fn name(&self) -> &str {
        &self.arch_name
    }

    fn pointer_size(&self) -> usize {
        (self.bits / 8) as usize
    }

    fn endian(&self) -> rustre_core::endian::Endian {
        rustre_core::endian::Endian::Little
    }

    fn disassemble(
        &self,
        address: Address,
        _bytes: &[u8],
    ) -> Result<rustre_core::arch::Instruction, rustre_core::errors::CoreError> {
        Ok(rustre_core::arch::Instruction {
            address,
            size: 1,
            mnemonic: "byte".into(),
            operands: String::new(),
            operand_list: Vec::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
            bytes: vec![0x00],
            comment: None,
        })
    }

    fn get_branches(
        &self,
        _instr: &rustre_core::arch::Instruction,
    ) -> Vec<rustre_core::arch::BranchInfo> {
        Vec::new()
    }

    fn registers(&self) -> Vec<rustre_core::arch::RegisterInfo> {
        Vec::new()
    }

    fn calling_conventions(&self) -> Vec<rustre_core::arch::CallingConvention> {
        Vec::new()
    }
}

/// Convenience function: create a minimal [`BinaryView`] from a raw byte slice,
/// run all standard analysis passes, and return the [`AnalysisReport`].
///
/// # Arguments
/// * `data` — raw binary bytes (treated as a single flat segment)
/// * `arch` — architecture name hint (e.g. `"x86_64"`, `"arm"`)
/// * `base` — virtual base address for the data
///
/// # Panics
/// Panics if the internal `ViewId::new(1)` returns an error (should never happen with a non-zero constant).
pub async fn analyze_binary(data: &[u8], arch: &str, base: u64) -> AnalysisReport {
    use rustre_core::{
        address::{Address, AddressRange},
        binary_view::{Memory, Segment},
        ids::ViewId,
        permissions::Permissions,
    };

    let bits: u32 = if arch.contains("64") { 64 } else { 32 };
    let arch_impl = Arc::new(FlatArch::new(arch, bits));

    let mut mem = Memory::new();
    mem.add_segment(Segment {
        range: AddressRange::new(
            Address::new(base),
            Address::new(base.saturating_add(data.len() as u64)),
        ),
        permissions: Permissions::READ | Permissions::EXECUTE,
        data: data.to_vec(),
    });

    let view = BinaryView::new(
        ViewId::new(1).expect("non-zero view id"),
        format!("memory://{arch}+0x{base:x}"),
        arch_impl,
        rustre_core::endian::Endian::Little,
        bits,
        vec![Address::new(base)],
        mem,
    );

    let manager = AnalysisManager::new();
    manager.analyze_binary_view(&view).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{
        address::{Address, AddressRange},
        arch::{
            Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
        },
        binary_view::{BinaryView, Memory, Segment},
        endian::Endian,
        errors::CoreError,
        ids::ViewId,
        permissions::Permissions,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct DummyArch;

    impl Architecture for DummyArch {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
            Ok(Instruction {
                address,
                size: 1,
                mnemonic: "nop".into(),
                operands: String::new(),
                operand_list: Vec::new(),
                flags: InstrFlags::NONE,
                bytes: vec![0x90],
                comment: None,
            })
        }
        fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }

    fn make_view() -> BinaryView {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: vec![0x90; 0x1000],
        });
        BinaryView::new(
            ViewId::new(1).expect("non-zero view id"),
            "test://dummy".into(),
            Arc::new(DummyArch),
            Endian::Little,
            64,
            vec![Address::new(0x1000)],
            mem,
        )
    }

    // ── AnalysisKind ─────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_kind_display() {
        assert_eq!(AnalysisKind::LinearSweep.to_string(), "LinearSweep");
        assert_eq!(
            AnalysisKind::RecursiveDescent.to_string(),
            "RecursiveDescent"
        );
        assert_eq!(AnalysisKind::DataFlow.to_string(), "DataFlow");
        assert_eq!(AnalysisKind::TypeRecovery.to_string(), "TypeRecovery");
        assert_eq!(
            AnalysisKind::CallingConvention.to_string(),
            "CallingConvention"
        );
        assert_eq!(AnalysisKind::StringRecovery.to_string(), "StringRecovery");
        assert_eq!(AnalysisKind::XrefRecovery.to_string(), "XrefRecovery");
        assert_eq!(AnalysisKind::VsaAnalysis.to_string(), "VsaAnalysis");
        assert_eq!(AnalysisKind::VtableAnalysis.to_string(), "VtableAnalysis");
        assert_eq!(
            AnalysisKind::Custom("my_pass".into()).to_string(),
            "Custom(my_pass)"
        );
    }

    #[test]
    fn test_analysis_kind_equality() {
        assert_eq!(AnalysisKind::LinearSweep, AnalysisKind::LinearSweep);
        assert_ne!(AnalysisKind::LinearSweep, AnalysisKind::DataFlow);
        assert_eq!(
            AnalysisKind::Custom("a".into()),
            AnalysisKind::Custom("a".into())
        );
        assert_ne!(
            AnalysisKind::Custom("a".into()),
            AnalysisKind::Custom("b".into())
        );
    }

    #[test]
    fn test_analysis_kind_hash() {
        let mut map = HashMap::new();
        map.insert(AnalysisKind::LinearSweep, 1u32);
        map.insert(AnalysisKind::DataFlow, 2u32);
        assert_eq!(map[&AnalysisKind::LinearSweep], 1);
        assert_eq!(map[&AnalysisKind::DataFlow], 2);
    }

    // ── AnalysisConfig ────────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = AnalysisConfig::new(AnalysisKind::StringRecovery);
        assert_eq!(cfg.max_depth, 256);
        assert!(cfg.timeout_ms.is_none());
        assert!(cfg.start_address.is_none());
        assert!(cfg.options.is_empty());
    }

    #[test]
    fn test_config_builder_methods() {
        let cfg = AnalysisConfig::new(AnalysisKind::DataFlow)
            .with_max_depth(64)
            .with_timeout(5000)
            .with_start(Address::new(0x4000));
        assert_eq!(cfg.max_depth, 64);
        assert_eq!(cfg.timeout_ms, Some(5000));
        assert_eq!(cfg.start_address, Some(Address::new(0x4000)));
    }

    #[test]
    fn test_config_options() {
        let mut cfg = AnalysisConfig::default();
        cfg.set_option("verbose", "true");
        cfg.set_option("max_strings", "100");
        assert_eq!(cfg.get_option("verbose"), Some("true"));
        assert_eq!(cfg.get_option("max_strings"), Some("100"));
        assert!(cfg.get_option("nonexistent").is_none());
    }

    // ── AnalysisResult ────────────────────────────────────────────────────────

    #[test]
    fn test_result_zero() {
        let r = AnalysisResult::zero(AnalysisKind::LinearSweep);
        assert_eq!(r.functions_found, 0);
        assert_eq!(r.data_refs_found, 0);
        assert_eq!(r.strings_found, 0);
        assert_eq!(r.duration_ms, 0);
        assert!(r.warnings.is_empty());
        assert!(!r.has_warnings());
        assert_eq!(r.total_items(), 0);
    }

    #[test]
    fn test_result_total_items() {
        let r = AnalysisResult {
            kind: AnalysisKind::LinearSweep,
            functions_found: 10,
            data_refs_found: 5,
            strings_found: 3,
            duration_ms: 42,
            warnings: vec!["a warning".into()],
        };
        assert_eq!(r.total_items(), 18);
        assert!(r.has_warnings());
    }

    // ── AnalysisError ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert_eq!(
            AnalysisError::PassNotFound("sweep".into()).to_string(),
            "Pass not found: sweep"
        );
        assert_eq!(
            AnalysisError::Failed("oops".into()).to_string(),
            "Analysis failed: oops"
        );
        assert_eq!(
            AnalysisError::Timeout(3000).to_string(),
            "Timeout after 3000ms"
        );
        assert_eq!(
            AnalysisError::InsufficientData(0xDEAD).to_string(),
            "Not enough data at 0xdead"
        );
    }

    // ── NoOpAnalysisPass ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_noop_pass_runs() {
        let view = make_view();
        let pass = NoOpAnalysisPass::new("noop_test");
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let result = pass.run(&view, &cfg).await.unwrap();
        assert_eq!(result.functions_found, 0);
        assert_eq!(result.kind, AnalysisKind::LinearSweep);
    }

    #[test]
    fn test_noop_pass_metadata() {
        let pass = NoOpAnalysisPass::with_kind("my_noop", AnalysisKind::DataFlow);
        assert_eq!(pass.name(), "my_noop");
        assert_eq!(pass.kind(), AnalysisKind::DataFlow);
        assert!(pass.supports_arch("x86_64"));
        assert_eq!(pass.priority(), 0);
    }

    // ── CountingAnalysisPass ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_counting_pass() {
        let view = make_view();
        let pass = CountingAnalysisPass::new("counter", AnalysisKind::StringRecovery, 7, 42);
        let cfg = AnalysisConfig::new(AnalysisKind::StringRecovery);
        let result = pass.run(&view, &cfg).await.unwrap();
        assert_eq!(result.functions_found, 7);
        assert_eq!(result.strings_found, 42);
        assert_eq!(result.total_items(), 49);
    }

    // ── AnalysisPipeline ──────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_register_and_find() {
        let pipeline = AnalysisPipeline::new();
        let pass = Arc::new(NoOpAnalysisPass::new("sweep"));
        pipeline.register(pass);
        assert!(pipeline.find("sweep").is_some());
        assert!(pipeline.find("missing").is_none());
        assert_eq!(pipeline.pass_count(), 1);
    }

    #[test]
    fn test_pipeline_register_overwrite() {
        let pipeline = AnalysisPipeline::new();
        pipeline.register(Arc::new(NoOpAnalysisPass::new("pass_a")));
        pipeline.register(Arc::new(NoOpAnalysisPass::new("pass_a")));
        assert_eq!(pipeline.pass_count(), 1);
    }

    #[test]
    fn test_pipeline_passes_for_kind() {
        let pipeline = AnalysisPipeline::new();
        pipeline.register(Arc::new(NoOpAnalysisPass::with_kind(
            "sweep1",
            AnalysisKind::LinearSweep,
        )));
        pipeline.register(Arc::new(NoOpAnalysisPass::with_kind(
            "sweep2",
            AnalysisKind::LinearSweep,
        )));
        pipeline.register(Arc::new(NoOpAnalysisPass::with_kind(
            "df1",
            AnalysisKind::DataFlow,
        )));
        let sweeps = pipeline.passes_for_kind(&AnalysisKind::LinearSweep);
        assert_eq!(sweeps.len(), 2);
        let data_flows = pipeline.passes_for_kind(&AnalysisKind::DataFlow);
        assert_eq!(data_flows.len(), 1);
    }

    #[tokio::test]
    async fn test_pipeline_run_all() {
        let view = make_view();
        let pipeline = AnalysisPipeline::default();
        pipeline.register(Arc::new(NoOpAnalysisPass::new("a")));
        pipeline.register(Arc::new(NoOpAnalysisPass::new("b")));
        pipeline.register(Arc::new(NoOpAnalysisPass::new("c")));
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let results = pipeline.run_all(&view, &cfg).await;
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.is_ok());
        }
    }

    #[test]
    fn test_pipeline_remove() {
        let pipeline = AnalysisPipeline::new();
        pipeline.register(Arc::new(NoOpAnalysisPass::new("alpha")));
        pipeline.register(Arc::new(NoOpAnalysisPass::new("beta")));
        assert!(pipeline.remove("alpha"));
        assert!(!pipeline.remove("alpha"));
        assert_eq!(pipeline.pass_count(), 1);
    }

    #[test]
    fn test_pipeline_pass_names() {
        let pipeline = AnalysisPipeline::new();
        pipeline.register(Arc::new(NoOpAnalysisPass::new("first")));
        pipeline.register(Arc::new(NoOpAnalysisPass::new("second")));
        let names = pipeline.pass_names();
        assert!(names.contains(&"first".to_string()));
        assert!(names.contains(&"second".to_string()));
    }

    #[test]
    fn test_pipeline_debug_format() {
        let pipeline = AnalysisPipeline::new();
        pipeline.register(Arc::new(NoOpAnalysisPass::new("x")));
        let s = format!("{pipeline:?}");
        assert!(s.contains("AnalysisPipeline"));
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    #[test]
    fn test_config_serde_roundtrip() {
        let mut cfg = AnalysisConfig::new(AnalysisKind::VtableAnalysis)
            .with_max_depth(32)
            .with_timeout(1000);
        cfg.set_option("key", "value");
        let json = serde_json::to_string(&cfg).unwrap();
        let back: AnalysisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_depth, 32);
        assert_eq!(back.timeout_ms, Some(1000));
        assert_eq!(back.get_option("key"), Some("value"));
    }

    #[test]
    fn test_result_serde_roundtrip() {
        let r = AnalysisResult {
            kind: AnalysisKind::Custom("my_pass".into()),
            functions_found: 99,
            data_refs_found: 10,
            strings_found: 5,
            duration_ms: 123,
            warnings: vec!["warn1".into()],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: AnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.functions_found, 99);
        assert_eq!(back.kind, AnalysisKind::Custom("my_pass".into()));
    }

    #[test]
    fn test_kind_serde_roundtrip() {
        for kind in [
            AnalysisKind::LinearSweep,
            AnalysisKind::RecursiveDescent,
            AnalysisKind::VsaAnalysis,
            AnalysisKind::Custom("x".into()),
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: AnalysisKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn test_noop_pass_debug_format() {
        let pass = NoOpAnalysisPass::new("dbg_pass");
        let s = format!("{pass:?}");
        assert!(s.contains("NoOpAnalysisPass"));
        assert!(s.contains("dbg_pass"));
    }

    #[test]
    fn test_counting_pass_debug_format() {
        let pass = CountingAnalysisPass::new("cnt", AnalysisKind::XrefRecovery, 10, 5);
        let s = format!("{pass:?}");
        assert!(s.contains("CountingAnalysisPass"));
    }

    #[tokio::test]
    async fn test_pipeline_empty_run_all() {
        let view = make_view();
        let pipeline = AnalysisPipeline::new();
        let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
        let results = pipeline.run_all(&view, &cfg).await;
        assert!(results.is_empty());
    }

    #[test]
    fn test_manager_incremental_tracking() {
        let mgr = AnalysisManager::new();
        mgr.mark_byte_sensitive("sweep");
        mgr.mark_symbol_sensitive("symbols");
        // Nothing has run yet, so no pass is eligible to be re-run.
        let changes = [BinaryChange {
            address_start: 0,
            address_end: 16,
            kind: ChangeKind::DataModified,
        }];
        assert!(mgr.passes_to_rerun(&changes).is_empty());
    }

    #[test]
    fn test_sweep_call_target_confidence() {
        // A `CALL rel32` (E8) whose target lands on a non-code byte (0x90 NOP
        // padding) is discovered as a CallTarget with the baseline confidence
        // of 75 (no prologue pattern at the destination).
        // next_ip = 0x1000 + 5 = 0x1005; target = 0x1005 + rel(5) = 0x100A.
        let mut bytes = vec![0xE8, 0x05, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0x90; 32]); // NOP padding; no prologue at target
        let analyzer = LinearSweepAnalyzer::new(LinearSweepConfig {
            min_function_size: 1,
            max_gap: 16,
            follow_calls: true,
        });
        let found = analyzer.sweep(0x1000, &bytes);
        let target = found.iter().find(|b| b.start == 0x100A);
        assert!(target.is_some(), "call target should be discovered");
        assert_eq!(
            target.unwrap().confidence,
            75,
            "non-prologue call target keeps baseline confidence"
        );
        assert_eq!(target.unwrap().method, BoundaryMethod::CallTarget);
    }
}
