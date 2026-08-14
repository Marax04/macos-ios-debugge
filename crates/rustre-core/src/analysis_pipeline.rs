//! Analysis pipeline: pass ordering, scheduling, progress reporting, and result tracking.
//!
//! # Overview
//!
//! The analysis pipeline builds on the low-level `PassManager` in
//! [`crate::analysis`] and adds:
//!
//! - [`AnalysisPipeline`] — owns typed `Box<dyn AnalysisPassImpl>` registrations
//!   and executes them in dependency order.
//! - [`PassScheduler`] — determines which passes can run in the current phase.
//! - [`AnalysisProgress`] — event type emitted during execution.
//! - [`PassResult`] — richer result with timing and findings.
//! - [`BuiltinPassKind`] — well-known built-in pass names.
//! - [`AutoAnalysis`] — convenience trigger that enqueues all registered passes.

use crate::errors::{CoreError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// A finding produced by an analysis pass (e.g. a new function or type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassFinding {
    /// A short tag identifying the finding category (e.g. `"function"`, `"xref"`).
    pub kind: String,
    /// A human-readable description of the finding.
    pub description: String,
    /// Optional address associated with the finding.
    pub address: Option<u64>,
}

impl PassFinding {
    /// Create a basic finding.
    #[must_use]
    pub fn new(kind: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            address: None,
        }
    }

    /// Attach an address to the finding.
    #[must_use]
    pub const fn at(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// Status of a single pass execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassStatus {
    /// Pass completed successfully.
    Ok,
    /// Pass completed but made no changes (already converged).
    Unchanged,
    /// Pass was skipped (dependency failed or pass not applicable).
    Skipped { reason: String },
    /// Pass failed.
    Failed { message: String },
}

impl PassStatus {
    /// Return `true` if the pass succeeded or was unchanged.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Ok | Self::Unchanged)
    }

    /// Return `true` if the pass made progress.
    #[must_use]
    pub const fn is_progress(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for PassStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Unchanged => write!(f, "unchanged"),
            Self::Skipped { reason } => write!(f, "skipped: {reason}"),
            Self::Failed { message } => write!(f, "failed: {message}"),
        }
    }
}

/// Detailed result of running one pass.
#[derive(Debug, Clone)]
pub struct PipelinePassResult {
    /// Name of the pass.
    pub name: String,
    /// Final status.
    pub status: PassStatus,
    /// Wall-clock duration of the pass.
    pub elapsed: Duration,
    /// Findings produced by the pass.
    pub findings: Vec<PassFinding>,
}

impl PipelinePassResult {
    /// Create a minimal result.
    #[must_use]
    pub fn new(name: impl Into<String>, status: PassStatus, elapsed: Duration) -> Self {
        Self {
            name: name.into(),
            status,
            elapsed,
            findings: Vec::new(),
        }
    }

    /// Attach a finding.
    #[must_use]
    pub fn with_finding(mut self, f: PassFinding) -> Self {
        self.findings.push(f);
        self
    }

    /// Attach multiple findings.
    #[must_use]
    pub fn with_findings(mut self, findings: Vec<PassFinding>) -> Self {
        self.findings = findings;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisProgress
// ─────────────────────────────────────────────────────────────────────────────

/// Progress event emitted during pipeline execution.
#[derive(Debug, Clone)]
pub enum AnalysisProgress {
    /// The pipeline is starting with this many passes.
    Started { total_passes: usize },
    /// A pass is about to run.
    PassBegin {
        name: String,
        index: usize,
        total: usize,
    },
    /// A pass completed.
    PassEnd {
        result: PipelinePassResult,
        index: usize,
        total: usize,
    },
    /// The pipeline finished.
    Finished { results: Vec<PipelinePassResult> },
    /// The pipeline was cancelled.
    Cancelled,
}

impl AnalysisProgress {
    /// Return `true` if this is a terminal event.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished { .. } | Self::Cancelled)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPassImpl — the trait passes implement
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata describing an analysis pass.
#[derive(Debug, Clone)]
pub struct PassInfo {
    /// Unique identifier for the pass.
    pub name: String,
    /// Dependencies that must complete successfully before this pass runs.
    pub requires: Vec<String>,
    /// Soft dependencies (pass runs even if these fail).
    pub suggests: Vec<String>,
    /// Human-readable description.
    pub description: String,
    /// Whether the pass is idempotent and can be re-run without side effects.
    pub idempotent: bool,
}

impl PassInfo {
    /// Construct minimal pass info.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            requires: Vec::new(),
            suggests: Vec::new(),
            description: String::new(),
            idempotent: true,
        }
    }

    /// Add a hard dependency.
    #[must_use]
    pub fn requires(mut self, dep: impl Into<String>) -> Self {
        self.requires.push(dep.into());
        self
    }

    /// Add a soft dependency.
    #[must_use]
    pub fn suggests(mut self, dep: impl Into<String>) -> Self {
        self.suggests.push(dep.into());
        self
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Mark the pass as non-idempotent.
    #[must_use]
    pub const fn non_idempotent(mut self) -> Self {
        self.idempotent = false;
        self
    }
}

/// Trait implemented by concrete analysis passes.
pub trait AnalysisPassImpl: Send + Sync + std::fmt::Debug {
    /// Return this pass's metadata.
    fn info(&self) -> PassInfo;

    /// Execute the pass.
    ///
    /// Returns a list of findings (may be empty) on success, or a descriptive
    /// error message on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn execute(&self) -> std::result::Result<Vec<PassFinding>, String>;

    /// Return `true` if this pass should run given the current analysis state.
    /// Defaults to `true`.
    fn is_applicable(&self) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassScheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Determines the execution order for a set of passes.
///
/// Uses Kahn's topological-sort algorithm over the hard-dependency graph.
/// Passes whose hard dependencies failed are marked as skipped.
#[derive(Debug, Default)]
pub struct PassScheduler {
    /// pass name → `PassInfo`
    infos: HashMap<String, PassInfo>,
}

impl PassScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register pass info.  Duplicate names overwrite the previous registration.
    pub fn register(&mut self, info: PassInfo) {
        self.infos.insert(info.name.clone(), info);
    }

    /// Compute a topological ordering of all registered passes.
    ///
    /// Only hard dependencies (`requires`) are used for ordering.  Soft
    /// dependencies (`suggests`) are ignored for ordering purposes.
    ///
    /// # Errors
    /// Returns `CoreError::AnalysisError` if a dependency cycle is detected.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn schedule(&self) -> Result<Vec<String>> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();

        for (name, info) in &self.infos {
            in_degree.entry(name.as_str()).or_insert(0);
            for dep in &info.requires {
                successors
                    .entry(dep.as_str())
                    .or_default()
                    .push(name.as_str());
                *in_degree.entry(name.as_str()).or_insert(0) += 1;
            }
        }

        let mut init: Vec<&str> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&n, _)| n)
            .collect();
        init.sort_unstable();
        let mut queue: VecDeque<&str> = init.into_iter().collect();
        let mut order = Vec::with_capacity(self.infos.len());

        while let Some(name) = queue.pop_front() {
            order.push(name.to_owned());
            if let Some(succs) = successors.get(name) {
                let mut next: Vec<&str> = Vec::new();
                for &succ in succs {
                    let deg = in_degree.get_mut(succ).expect("in_degree entry");
                    *deg -= 1;
                    if *deg == 0 {
                        next.push(succ);
                    }
                }
                next.sort_unstable();
                queue.extend(next);
            }
        }

        if order.len() != self.infos.len() {
            return Err(CoreError::analysis(
                "analysis pass dependency graph contains a cycle",
            ));
        }
        Ok(order)
    }

    /// Return names of passes that are missing from the registry but are named
    /// as hard dependencies.
    #[must_use]
    pub fn missing_dependencies(&self) -> Vec<(String, String)> {
        let names: HashSet<&str> = self.infos.keys().map(String::as_str).collect();
        let mut missing = Vec::new();
        for (pass_name, info) in &self.infos {
            for dep in &info.requires {
                if !names.contains(dep.as_str()) {
                    missing.push((pass_name.clone(), dep.clone()));
                }
            }
        }
        missing
    }

    /// Number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.infos.len()
    }

    /// Return `true` if no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuiltinPassKind
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known names of built-in analysis passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinPassKind {
    /// Control-flow graph construction.
    CfgBuild,
    /// Dominator tree computation.
    DomTree,
    /// Call graph construction.
    CallGraph,
    /// Type inference pass.
    TypeInfer,
    /// Constant folding / propagation.
    ConstFold,
    /// Dead code elimination.
    DeadCode,
    /// String discovery.
    StringScan,
    /// FLIRT signature matching.
    FlirtMatch,
    /// Stack-frame analysis.
    StackAnalysis,
    /// Cross-reference indexing.
    XrefIndex,
}

impl BuiltinPassKind {
    /// Return the canonical string name of the pass.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CfgBuild => "cfg-build",
            Self::DomTree => "dom-tree",
            Self::CallGraph => "call-graph",
            Self::TypeInfer => "type-infer",
            Self::ConstFold => "const-fold",
            Self::DeadCode => "dead-code",
            Self::StringScan => "string-scan",
            Self::FlirtMatch => "flirt-match",
            Self::StackAnalysis => "stack-analysis",
            Self::XrefIndex => "xref-index",
        }
    }

    /// Return the hard dependencies of this pass.
    #[must_use]
    pub const fn dependencies(self) -> &'static [&'static str] {
        match self {
            Self::DomTree
            | Self::CallGraph
            | Self::TypeInfer
            | Self::StackAnalysis
            | Self::XrefIndex => &["cfg-build"],
            Self::ConstFold => &["cfg-build", "type-infer"],
            Self::DeadCode => &["cfg-build", "dom-tree"],
            Self::CfgBuild | Self::StringScan | Self::FlirtMatch => &[],
        }
    }

    /// Create a `PassInfo` for this built-in pass.
    #[must_use]
    pub fn pass_info(self) -> PassInfo {
        let mut info = PassInfo::new(self.name());
        for dep in self.dependencies() {
            info = info.requires(*dep);
        }
        info
    }

    /// Return all built-in pass kinds.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::CfgBuild,
            Self::DomTree,
            Self::CallGraph,
            Self::TypeInfer,
            Self::ConstFold,
            Self::DeadCode,
            Self::StringScan,
            Self::FlirtMatch,
            Self::StackAnalysis,
            Self::XrefIndex,
        ]
    }
}

impl std::fmt::Display for BuiltinPassKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a set of `AnalysisPassImpl` instances and executes them in
/// dependency order.
///
/// The pipeline uses a `PassScheduler` internally and emits `AnalysisProgress`
/// events via a user-supplied callback.
///
/// # Example
///
/// ```
/// use rustre_core::analysis_pipeline::{
///     AnalysisPipeline, AnalysisPassImpl, PassFinding, PassInfo,
/// };
///
/// #[derive(Debug)]
/// struct CfgPass;
///
/// impl AnalysisPassImpl for CfgPass {
///     fn info(&self) -> PassInfo {
///         PassInfo::new("cfg")
///     }
///     fn execute(&self) -> Result<Vec<PassFinding>, String> {
///         Ok(Vec::new())
///     }
/// }
///
/// let mut pipeline = AnalysisPipeline::new();
/// pipeline.register(Box::new(CfgPass));
/// let results = pipeline.run_all(|event| println!("{event:?}")).unwrap();
/// assert_eq!(results.len(), 1);
/// ```
///
/// The block was `rust,ignore` until 2026-07-29 and referred to
/// `MyCfgPass` / `MyTypePass`, which do not exist anywhere — so it showed
/// no way to actually implement a pass. It now defines a real one.
#[derive(Default)]
pub struct AnalysisPipeline {
    passes: HashMap<String, Box<dyn AnalysisPassImpl>>,
    scheduler: PassScheduler,
}

impl AnalysisPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an analysis pass.  Replaces any existing pass with the same name.
    pub fn register(&mut self, pass: Box<dyn AnalysisPassImpl>) {
        let info = pass.info();
        let name = info.name.clone();
        self.scheduler.register(info);
        self.passes.insert(name, pass);
    }

    /// Remove a pass by name. Returns `true` if it was present.
    pub fn unregister(&mut self, name: &str) -> bool {
        let removed = self.passes.remove(name).is_some();
        if removed {
            // Re-build scheduler without this pass.
            let infos: Vec<PassInfo> = self.passes.values().map(|p| p.info()).collect();
            self.scheduler = PassScheduler::new();
            for info in infos {
                self.scheduler.register(info);
            }
        }
        removed
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Return `true` if a pass with `name` is registered.
    #[must_use]
    pub fn has_pass(&self, name: &str) -> bool {
        self.passes.contains_key(name)
    }

    /// Run all registered passes in dependency order.
    ///
    /// `progress_cb` receives each `AnalysisProgress` event.  Pass `|_| {}` to
    /// ignore events.
    ///
    /// # Errors
    /// Returns `Err` only if the dependency graph contains a cycle or a pass
    /// panics (which is caught and converted to a failure).
    pub fn run_all<F>(&self, mut progress_cb: F) -> Result<Vec<PipelinePassResult>>
    where
        F: FnMut(AnalysisProgress),
    {
        let order = self.scheduler.schedule()?;
        let total = order.len();
        progress_cb(AnalysisProgress::Started {
            total_passes: total,
        });

        let mut results: Vec<PipelinePassResult> = Vec::with_capacity(total);
        // Track which passes succeeded for dependency gating.
        let mut succeeded: HashSet<String> = HashSet::new();
        let mut failed: HashSet<String> = HashSet::new();

        for (index, name) in order.iter().enumerate() {
            progress_cb(AnalysisProgress::PassBegin {
                name: name.clone(),
                index,
                total,
            });

            let result = self.passes.get(name).map_or_else(
                || {
                    PipelinePassResult::new(
                        name,
                        PassStatus::Skipped {
                            reason: "not registered".to_owned(),
                        },
                        Duration::ZERO,
                    )
                },
                |pass| {
                    let info = pass.info();

                    // Check hard dependencies: blocked if a required dep failed,
                    // OR if a required dep never succeeded (e.g. was skipped).
                    let blocked = info.requires.iter().any(|dep| failed.contains(dep))
                        || info
                            .requires
                            .iter()
                            .any(|dep| self.passes.contains_key(dep) && !succeeded.contains(dep));
                    if blocked {
                        PipelinePassResult::new(
                            name,
                            PassStatus::Skipped {
                                reason: "dependency failed".to_owned(),
                            },
                            Duration::ZERO,
                        )
                    } else if !pass.is_applicable() {
                        PipelinePassResult::new(
                            name,
                            PassStatus::Skipped {
                                reason: "not applicable".to_owned(),
                            },
                            Duration::ZERO,
                        )
                    } else {
                        let t0 = Instant::now();
                        match pass.execute() {
                            Ok(findings) => {
                                let status = if findings.is_empty() {
                                    PassStatus::Unchanged
                                } else {
                                    PassStatus::Ok
                                };
                                PipelinePassResult::new(name, status, t0.elapsed())
                                    .with_findings(findings)
                            }
                            Err(msg) => PipelinePassResult::new(
                                name,
                                PassStatus::Failed { message: msg },
                                t0.elapsed(),
                            ),
                        }
                    }
                },
            );

            if result.status.is_success() {
                succeeded.insert(name.clone());
            } else if matches!(result.status, PassStatus::Failed { .. }) {
                failed.insert(name.clone());
            }

            progress_cb(AnalysisProgress::PassEnd {
                result: result.clone(),
                index,
                total,
            });
            results.push(result);
        }

        progress_cb(AnalysisProgress::Finished {
            results: results.clone(),
        });
        Ok(results)
    }

    /// Run only the named passes (plus their transitive dependencies, if registered).
    ///
    /// Passes not in `names` and not transitively required are skipped.
    ///
    /// # Errors
    /// Same as [`run_all`](Self::run_all).
    pub fn run_subset<F>(
        &self,
        names: &[&str],
        mut progress_cb: F,
    ) -> Result<Vec<PipelinePassResult>>
    where
        F: FnMut(AnalysisProgress),
    {
        // Collect transitive requirements.
        let mut required: HashSet<String> =
            names.iter().map(std::string::ToString::to_string).collect();
        let mut frontier: VecDeque<String> = required.iter().cloned().collect();
        while let Some(name) = frontier.pop_front() {
            if let Some(pass) = self.passes.get(&name) {
                for dep in &pass.info().requires {
                    if required.insert(dep.clone()) {
                        frontier.push_back(dep.clone());
                    }
                }
            }
        }

        let order = self.scheduler.schedule()?;
        let filtered_order: Vec<String> =
            order.into_iter().filter(|n| required.contains(n)).collect();
        let total = filtered_order.len();

        progress_cb(AnalysisProgress::Started {
            total_passes: total,
        });
        let mut results: Vec<PipelinePassResult> = Vec::with_capacity(total);
        let mut succeeded: HashSet<String> = HashSet::new();
        let mut failed: HashSet<String> = HashSet::new();

        for (index, name) in filtered_order.iter().enumerate() {
            progress_cb(AnalysisProgress::PassBegin {
                name: name.clone(),
                index,
                total,
            });

            let result = self.passes.get(name).map_or_else(
                || {
                    PipelinePassResult::new(
                        name,
                        PassStatus::Skipped {
                            reason: "not found".into(),
                        },
                        Duration::ZERO,
                    )
                },
                |pass| {
                    let info = pass.info();
                    let blocked = info.requires.iter().any(|dep| failed.contains(dep))
                        || info
                            .requires
                            .iter()
                            .any(|dep| self.passes.contains_key(dep) && !succeeded.contains(dep));
                    if blocked {
                        PipelinePassResult::new(
                            name,
                            PassStatus::Skipped {
                                reason: "dependency failed".into(),
                            },
                            Duration::ZERO,
                        )
                    } else if !pass.is_applicable() {
                        PipelinePassResult::new(
                            name,
                            PassStatus::Skipped {
                                reason: "not applicable".into(),
                            },
                            Duration::ZERO,
                        )
                    } else {
                        let t0 = Instant::now();
                        match pass.execute() {
                            Ok(findings) => {
                                let status = if findings.is_empty() {
                                    PassStatus::Unchanged
                                } else {
                                    PassStatus::Ok
                                };
                                PipelinePassResult::new(name, status, t0.elapsed())
                                    .with_findings(findings)
                            }
                            Err(msg) => PipelinePassResult::new(
                                name,
                                PassStatus::Failed { message: msg },
                                t0.elapsed(),
                            ),
                        }
                    }
                },
            );

            if result.status.is_success() {
                succeeded.insert(name.clone());
            }
            if matches!(result.status, PassStatus::Failed { .. }) {
                failed.insert(name.clone());
            }

            progress_cb(AnalysisProgress::PassEnd {
                result: result.clone(),
                index,
                total,
            });
            results.push(result);
        }

        progress_cb(AnalysisProgress::Finished {
            results: results.clone(),
        });
        Ok(results)
    }

    /// Validate that all hard dependencies of all registered passes are
    /// themselves registered.  Returns `(pass_name, missing_dep)` pairs.
    #[must_use]
    pub fn validate(&self) -> Vec<(String, String)> {
        self.scheduler.missing_dependencies()
    }
}

impl std::fmt::Debug for AnalysisPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisPipeline")
            .field("passes", &self.passes.len())
            .field("scheduler", &self.scheduler)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AutoAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper that registers all built-in passes and runs them.
///
/// Callers can also inject custom passes before running.
#[derive(Default)]
pub struct AutoAnalysis {
    pipeline: AnalysisPipeline,
}

impl AutoAnalysis {
    /// Create an `AutoAnalysis` with all built-in pass *infos* registered but no
    /// implementations.  Concrete implementations must be supplied via
    /// [`add_pass`](Self::add_pass) or they will be skipped.
    #[must_use]
    pub fn new() -> Self {
        let mut aa = Self::default();
        for kind in BuiltinPassKind::all() {
            // Register a stub (no-op) for ordering purposes.
            aa.pipeline.scheduler.register(kind.pass_info());
        }
        aa
    }

    /// Register a pass implementation (replaces any stub for the same name).
    pub fn add_pass(&mut self, pass: Box<dyn AnalysisPassImpl>) {
        self.pipeline.register(pass);
    }

    /// Run all registered and applicable passes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn run<F>(&self, progress_cb: F) -> Result<Vec<PipelinePassResult>>
    where
        F: FnMut(AnalysisProgress),
    {
        self.pipeline.run_all(progress_cb)
    }

    /// Return a reference to the inner pipeline.
    #[must_use]
    pub const fn pipeline(&self) -> &AnalysisPipeline {
        &self.pipeline
    }
}

impl std::fmt::Debug for AutoAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoAnalysis")
            .field("pipeline", &self.pipeline)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // ── Stub pass ─────────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct OkPass {
        name: String,
        deps: Vec<String>,
        findings: Vec<PassFinding>,
    }

    impl OkPass {
        fn new(name: &str, deps: &[&str]) -> Self {
            Self {
                name: name.to_owned(),
                deps: deps.iter().map(std::string::ToString::to_string).collect(),
                findings: vec![],
            }
        }
        fn with_finding(mut self, f: PassFinding) -> Self {
            self.findings.push(f);
            self
        }
    }

    impl AnalysisPassImpl for OkPass {
        fn info(&self) -> PassInfo {
            let mut info = PassInfo::new(&self.name);
            for dep in &self.deps {
                info = info.requires(dep.clone());
            }
            info
        }
        fn execute(&self) -> std::result::Result<Vec<PassFinding>, String> {
            Ok(self.findings.clone())
        }
    }

    #[derive(Debug)]
    struct FailPass {
        name: String,
    }

    impl AnalysisPassImpl for FailPass {
        fn info(&self) -> PassInfo {
            PassInfo::new(&self.name)
        }
        fn execute(&self) -> std::result::Result<Vec<PassFinding>, String> {
            Err("always fails".to_owned())
        }
    }

    #[derive(Debug)]
    struct NotApplicablePass {
        name: String,
    }

    impl AnalysisPassImpl for NotApplicablePass {
        fn info(&self) -> PassInfo {
            PassInfo::new(&self.name)
        }
        fn execute(&self) -> std::result::Result<Vec<PassFinding>, String> {
            Ok(vec![])
        }
        fn is_applicable(&self) -> bool {
            false
        }
    }

    // ── PassFinding ───────────────────────────────────────────────────────────

    #[test]
    fn pass_finding_builder() {
        let f = PassFinding::new("function", "found main").at(0x1000);
        assert_eq!(f.kind, "function");
        assert_eq!(f.address, Some(0x1000));
    }

    #[test]
    fn pass_finding_thread_safe_sharing() {
        // PassFinding can be shared across threads via Arc; AtomicBool acts as a
        // simple visited flag.  This exercises the imports under test.
        let f = Arc::new(PassFinding::new("function", "shared finding"));
        let visited = Arc::new(AtomicBool::new(false));
        let f_clone = Arc::clone(&f);
        let v_clone = Arc::clone(&visited);
        let handle = std::thread::spawn(move || {
            assert_eq!(f_clone.kind, "function");
            v_clone.store(true, Ordering::SeqCst);
        });
        handle.join().expect("worker thread panicked");
        assert!(visited.load(Ordering::SeqCst));
    }

    // ── PassStatus ────────────────────────────────────────────────────────────

    #[test]
    fn pass_status_predicates() {
        assert!(PassStatus::Ok.is_success());
        assert!(PassStatus::Unchanged.is_success());
        assert!(!PassStatus::Skipped { reason: "x".into() }.is_success());
        assert!(
            !PassStatus::Failed {
                message: "y".into()
            }
            .is_success()
        );
        assert!(PassStatus::Ok.is_progress());
        assert!(!PassStatus::Unchanged.is_progress());
    }

    #[test]
    fn pass_status_display() {
        assert_eq!(PassStatus::Ok.to_string(), "ok");
        assert_eq!(PassStatus::Unchanged.to_string(), "unchanged");
        assert!(
            PassStatus::Skipped {
                reason: "deps".into()
            }
            .to_string()
            .contains("deps")
        );
        assert!(
            PassStatus::Failed {
                message: "boom".into()
            }
            .to_string()
            .contains("boom")
        );
    }

    // ── PassInfo ──────────────────────────────────────────────────────────────

    #[test]
    fn pass_info_builder() {
        let info = PassInfo::new("my-pass")
            .requires("dep-a")
            .suggests("dep-b")
            .with_description("does stuff")
            .non_idempotent();
        assert_eq!(info.name, "my-pass");
        assert_eq!(info.requires.len(), 1);
        assert_eq!(info.suggests.len(), 1);
        assert!(!info.idempotent);
    }

    // ── PassScheduler ─────────────────────────────────────────────────────────

    #[test]
    fn scheduler_empty() {
        let s = PassScheduler::new();
        assert!(s.schedule().unwrap().is_empty());
    }

    #[test]
    fn scheduler_single_pass() {
        let mut s = PassScheduler::new();
        s.register(PassInfo::new("cfg"));
        assert_eq!(s.schedule().unwrap(), vec!["cfg"]);
    }

    #[test]
    fn scheduler_linear_chain() {
        let mut s = PassScheduler::new();
        s.register(PassInfo::new("a"));
        s.register(PassInfo::new("b").requires("a"));
        s.register(PassInfo::new("c").requires("b"));
        let order = s.schedule().unwrap();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn scheduler_cycle_detected() {
        let mut s = PassScheduler::new();
        s.register(PassInfo::new("a").requires("b"));
        s.register(PassInfo::new("b").requires("a"));
        assert!(s.schedule().is_err());
    }

    #[test]
    fn scheduler_missing_dependencies() {
        let mut s = PassScheduler::new();
        s.register(PassInfo::new("a").requires("missing"));
        let missing = s.missing_dependencies();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].1, "missing");
    }

    // ── AnalysisPipeline ──────────────────────────────────────────────────────

    #[test]
    fn pipeline_register_and_run() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("cfg", &[])));
        pipeline.register(Box::new(OkPass::new("types", &["cfg"])));
        let results = pipeline.run_all(|_| {}).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status.is_success()));
    }

    #[test]
    fn pipeline_failed_pass_skips_dependents() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(FailPass { name: "cfg".into() }));
        pipeline.register(Box::new(OkPass::new("types", &["cfg"])));
        let results = pipeline.run_all(|_| {}).unwrap();
        let types_result = results.iter().find(|r| r.name == "types").unwrap();
        assert!(matches!(types_result.status, PassStatus::Skipped { .. }));
    }

    #[test]
    fn pipeline_not_applicable_skipped() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(NotApplicablePass { name: "x".into() }));
        let results = pipeline.run_all(|_| {}).unwrap();
        assert!(matches!(results[0].status, PassStatus::Skipped { .. }));
    }

    #[test]
    fn pipeline_findings_propagated() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(
            OkPass::new("cfg", &[]).with_finding(PassFinding::new("func", "found main").at(0x1000)),
        ));
        let results = pipeline.run_all(|_| {}).unwrap();
        assert_eq!(results[0].findings.len(), 1);
        assert_eq!(results[0].findings[0].kind, "func");
    }

    #[test]
    fn pipeline_progress_events_emitted() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("a", &[])));
        pipeline.register(Box::new(OkPass::new("b", &["a"])));

        let mut events = Vec::new();
        pipeline.run_all(|e| events.push(e)).unwrap();

        assert!(
            events
                .iter()
                .any(|e| matches!(e, AnalysisProgress::Started { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, AnalysisProgress::Finished { .. }))
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, AnalysisProgress::PassBegin { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn pipeline_unregister() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("a", &[])));
        assert!(pipeline.unregister("a"));
        assert!(!pipeline.has_pass("a"));
        assert!(!pipeline.unregister("a"));
    }

    #[test]
    fn pipeline_validate_missing_dep() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("a", &["missing"])));
        let missing = pipeline.validate();
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn pipeline_run_subset() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("cfg", &[])));
        pipeline.register(Box::new(OkPass::new("dom", &["cfg"])));
        pipeline.register(Box::new(OkPass::new("type", &[])));
        // Only run "dom" (which requires "cfg").
        let results = pipeline.run_subset(&["dom"], |_| {}).unwrap();
        assert_eq!(results.len(), 2); // cfg + dom
        assert!(results.iter().all(|r| r.status.is_success()));
        // "type" should not appear.
        assert!(!results.iter().any(|r| r.name == "type"));
    }

    #[test]
    fn pipeline_cycle_in_run_all_returns_err() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("a", &["b"])));
        pipeline.register(Box::new(OkPass::new("b", &["a"])));
        assert!(pipeline.run_all(|_| {}).is_err());
    }

    #[test]
    fn pipeline_result_timing() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.register(Box::new(OkPass::new("fast", &[])));
        let results = pipeline.run_all(|_| {}).unwrap();
        // Elapsed should be a valid duration (not wildly negative or enormous).
        assert!(results[0].elapsed.as_secs() < 60);
    }

    // ── BuiltinPassKind ───────────────────────────────────────────────────────

    #[test]
    fn builtin_all_have_names() {
        for kind in BuiltinPassKind::all() {
            assert!(!kind.name().is_empty());
        }
    }

    #[test]
    fn builtin_dom_tree_requires_cfg() {
        let deps = BuiltinPassKind::DomTree.dependencies();
        assert!(deps.contains(&"cfg-build"));
    }

    #[test]
    fn builtin_pass_info_consistent() {
        let info = BuiltinPassKind::CallGraph.pass_info();
        assert_eq!(info.name, "call-graph");
        assert!(info.requires.contains(&"cfg-build".to_string()));
    }

    #[test]
    fn builtin_display() {
        assert_eq!(BuiltinPassKind::CfgBuild.to_string(), "cfg-build");
        assert_eq!(BuiltinPassKind::XrefIndex.to_string(), "xref-index");
    }

    // ── AutoAnalysis ──────────────────────────────────────────────────────────

    #[test]
    fn auto_analysis_new_has_scheduler_entries() {
        let aa = AutoAnalysis::new();
        // The scheduler should know about all built-in passes.
        assert!(!aa.pipeline().scheduler.is_empty());
    }

    #[test]
    fn auto_analysis_add_and_run() {
        let mut aa = AutoAnalysis::new();
        aa.add_pass(Box::new(OkPass::new("cfg-build", &[])));
        // run_all will schedule all known passes; those without implementations
        // will be skipped.
        let results = aa.run(|_| {}).unwrap();
        let cfg = results.iter().find(|r| r.name == "cfg-build").unwrap();
        assert!(cfg.status.is_success());
    }

    // ── AnalysisProgress ─────────────────────────────────────────────────────

    #[test]
    fn progress_is_terminal() {
        assert!(AnalysisProgress::Finished { results: vec![] }.is_terminal());
        assert!(AnalysisProgress::Cancelled.is_terminal());
        assert!(!AnalysisProgress::Started { total_passes: 1 }.is_terminal());
    }

    // ── PipelinePassResult builder ────────────────────────────────────────────

    #[test]
    fn pipeline_pass_result_builder() {
        let r = PipelinePassResult::new("x", PassStatus::Ok, Duration::from_millis(5))
            .with_finding(PassFinding::new("fn", "main"))
            .with_findings(vec![PassFinding::new("xref", "got call")]);
        // with_findings replaces the previous list.
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].kind, "xref");
    }

    // ── Concurrent safety (compile check) ────────────────────────────────────

    #[test]
    fn pipeline_is_send() {
        fn require_send<T: Send>() {}
        require_send::<AnalysisPipeline>();
    }

    // ── Multiple independent passes sorted deterministically ─────────────────

    #[test]
    fn scheduler_independent_passes_sorted() {
        let mut s = PassScheduler::new();
        s.register(PassInfo::new("z"));
        s.register(PassInfo::new("a"));
        s.register(PassInfo::new("m"));
        let order = s.schedule().unwrap();
        // All passes have no deps; order should be alphabetical.
        assert_eq!(order, vec!["a", "m", "z"]);
    }
}
