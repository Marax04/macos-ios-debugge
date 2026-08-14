//! `pass_manager` — DAG-aware deobfuscation pass manager.
//!
//! [`DeobfPassManager`] supports pass registration with explicit dependency
//! edges, topological execution ordering, per-pass result caching, selective
//! enable/disable, progress events, and timing via [`PassResult`].
//!
//! # Relation to `deobf_pipeline`
//! This module provides a **DAG-based manager**: passes declare dependencies
//! by name; the manager validates the graph, detects cycles, computes a
//! topological order, and emits progress events during execution. Use it when
//! pass ordering must be derived from dependency constraints rather than
//! explicit insertion order.
//!
//! [`deobf_pipeline`](crate::deobf_pipeline) provides a simpler
//! **ordered-sequence pipeline**: passes are inserted in execution order, with
//! per-pass rollback support, pipeline-level configuration, and `PassId`-keyed
//! result aggregation. Use it when you control the pass order directly.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{DeobfContext, DeobfError, DeobfPass, DeobfResult};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to the pass manager.
#[derive(Debug, Error)]
pub enum PassManagerError {
    /// A pass was registered with a name that already exists.
    #[error("duplicate pass name: {0}")]
    DuplicateName(String),

    /// A dependency edge references a pass that is not registered.
    #[error("unknown dependency '{dep}' required by pass '{pass}'")]
    UnknownDependency { pass: String, dep: String },

    /// Circular dependency detected in the pass DAG.
    #[error("circular dependency detected involving pass '{0}'")]
    CyclicDependency(String),

    /// A pass name requested for execution is not registered.
    #[error("pass not found: {0}")]
    PassNotFound(String),

    /// Underlying deobfuscation error forwarded from a pass.
    #[error("pass '{pass}' error: {source}")]
    PassError {
        pass: String,
        #[source]
        source: DeobfError,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress events
// ─────────────────────────────────────────────────────────────────────────────

/// An event emitted by the pass manager during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PassEvent {
    /// A pass is about to start.
    Starting { name: String },
    /// A pass finished successfully.
    Finished {
        name: String,
        elapsed_ms: u64,
        patches: usize,
    },
    /// A pass was skipped (disabled or not applicable).
    Skipped { name: String, reason: String },
    /// A pass returned an error.
    Failed { name: String, error: String },
    /// All passes have been executed.
    PipelineDone { total_ms: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// Rich result for one pass execution, including timing and dependency info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Name of the pass.
    pub name: String,
    /// The underlying [`DeobfResult`], or `None` if skipped / failed.
    pub result: Option<DeobfResult>,
    /// Wall-clock time spent executing this pass.
    pub elapsed: Duration,
    /// `true` if the pass was enabled and ran to completion.
    pub ran: bool,
    /// Human-readable status description.
    pub status: String,
}

impl PassResult {
    fn success(name: String, result: DeobfResult, elapsed: Duration) -> Self {
        let status = format!(
            "ok: {} patches, {:.2} confidence",
            result.patches_applied, result.confidence
        );
        Self {
            name,
            result: Some(result),
            elapsed,
            ran: true,
            status,
        }
    }

    fn skipped(name: String, reason: &str) -> Self {
        Self {
            name,
            result: None,
            elapsed: Duration::ZERO,
            ran: false,
            status: format!("skipped: {reason}"),
        }
    }

    fn failed(name: String, error: &str, elapsed: Duration) -> Self {
        Self {
            name,
            result: None,
            elapsed,
            ran: false,
            status: format!("failed: {error}"),
        }
    }

    /// Returns the number of patches from this pass, or 0 if skipped/failed.
    #[must_use]
    pub fn patches_applied(&self) -> usize {
        self.result.as_ref().map_or(0, |r| r.patches_applied)
    }

    /// Returns the confidence from this pass, or 0.0 if skipped/failed.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.result.as_ref().map_or(0.0, |r| r.confidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassEntry — internal registration record
// ─────────────────────────────────────────────────────────────────────────────

struct PassEntry {
    pass: Box<dyn DeobfPass>,
    deps: Vec<String>,
    enabled: bool,
    cached_result: Option<PassResult>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPassManager
// ─────────────────────────────────────────────────────────────────────────────

/// A DAG-aware pass manager.
///
/// # Workflow
/// 1. Register passes with [`register`].
/// 2. Declare dependency edges with [`add_dependency`].
/// 3. Optionally disable passes with [`set_enabled`].
/// 4. Call [`run`] with a mutable [`DeobfContext`].
/// 5. Inspect [`PassManagerReport`] for per-pass timing and results.
///
/// Passes are executed in a topological order derived from the dependency DAG.
/// If pass A declares pass B as a dependency, B is guaranteed to complete
/// before A starts.  Cycles are rejected at dependency-add time.
///
/// [`register`]: DeobfPassManager::register
/// [`add_dependency`]: DeobfPassManager::add_dependency
/// [`set_enabled`]: DeobfPassManager::set_enabled
/// [`run`]: DeobfPassManager::run
#[derive(Default)]
pub struct DeobfPassManager {
    passes: HashMap<String, PassEntry>,
    /// Insertion order for stable iteration.
    order: Vec<String>,
    /// Progress event listener (optional).
    listener: Option<Box<dyn Fn(PassEvent) + Send + Sync>>,
}

impl std::fmt::Debug for DeobfPassManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeobfPassManager")
            .field("passes", &self.order)
            .finish_non_exhaustive()
    }
}

impl DeobfPassManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a progress event listener.
    ///
    /// The closure is called synchronously during [`run`] on the calling
    /// thread.  Only one listener can be registered; calling this again
    /// replaces the previous listener.
    pub fn set_listener(&mut self, f: impl Fn(PassEvent) + Send + Sync + 'static) {
        self.listener = Some(Box::new(f));
    }

    fn emit(&self, event: PassEvent) {
        if let Some(l) = &self.listener {
            l(event);
        }
    }

    /// Register a pass.
    ///
    /// # Errors
    /// Returns [`PassManagerError::DuplicateName`] if a pass with the same
    /// name is already registered.
    pub fn register(&mut self, pass: Box<dyn DeobfPass>) -> Result<(), PassManagerError> {
        let name = pass.name().to_owned();
        if self.passes.contains_key(&name) {
            return Err(PassManagerError::DuplicateName(name));
        }
        self.passes.insert(
            name.clone(),
            PassEntry {
                pass,
                deps: Vec::new(),
                enabled: true,
                cached_result: None,
            },
        );
        self.order.push(name);
        Ok(())
    }

    /// Declare that `pass_name` depends on `dep_name` (i.e. `dep_name` must
    /// execute first).
    ///
    /// # Errors
    /// Returns an error if either name is unknown or if adding the edge would
    /// create a cycle.
    ///
    /// # Panics
    ///
    /// Panics if `pass_name` is not found after the initial lookup (internal
    /// consistency error that should never occur in practice).
    pub fn add_dependency(
        &mut self,
        pass_name: &str,
        dep_name: &str,
    ) -> Result<(), PassManagerError> {
        if !self.passes.contains_key(pass_name) {
            return Err(PassManagerError::PassNotFound(pass_name.to_owned()));
        }
        if !self.passes.contains_key(dep_name) {
            return Err(PassManagerError::UnknownDependency {
                pass: pass_name.to_owned(),
                dep: dep_name.to_owned(),
            });
        }
        // Temporarily add the edge and check for cycles.
        self.passes
            .get_mut(pass_name)
            .unwrap()
            .deps
            .push(dep_name.to_owned());
        if let Err(cycle) = self.check_no_cycle() {
            self.passes.get_mut(pass_name).unwrap().deps.pop();
            return Err(PassManagerError::CyclicDependency(cycle));
        }
        Ok(())
    }

    /// Enable or disable a named pass.
    ///
    /// Disabled passes are skipped and their dependents will still run
    /// (dependencies are structural, not data-flow).
    ///
    /// # Errors
    /// Returns [`PassManagerError::PassNotFound`] if the name is unknown.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), PassManagerError> {
        self.passes
            .get_mut(name)
            .ok_or_else(|| PassManagerError::PassNotFound(name.to_owned()))?
            .enabled = enabled;
        Ok(())
    }

    /// Clear the cached result for all passes.
    pub fn invalidate_cache(&mut self) {
        for entry in self.passes.values_mut() {
            entry.cached_result = None;
        }
    }

    /// Number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// Returns `true` if no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Return a topologically sorted list of enabled pass names, respecting
    /// dependency constraints (Kahn's algorithm).
    ///
    /// # Errors
    /// Returns [`PassManagerError::CyclicDependency`] if the dependency graph
    /// contains a cycle (should not happen if `add_dependency` succeeded, but
    /// checked defensively).
    ///
    /// # Panics
    ///
    /// Panics if a pass's in-degree entry is missing during the Kahn's
    /// algorithm traversal (internal consistency error).
    pub fn topological_order(&self) -> Result<Vec<String>, PassManagerError> {
        // Build in-degree table and adjacency list.
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for name in &self.order {
            in_degree.entry(name.as_str()).or_insert(0);
            adj.entry(name.as_str()).or_default();
        }

        for name in &self.order {
            let entry = &self.passes[name.as_str()];
            for dep in &entry.deps {
                // dep → name edge (dep must run before name)
                adj.entry(dep.as_str()).or_default().push(name.as_str());
                *in_degree.entry(name.as_str()).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(&n, _)| n)
            .collect();

        // Stable sort for determinism.
        let mut sorted_queue: Vec<&str> = std::mem::take(&mut queue).into_iter().collect();
        sorted_queue.sort_unstable();
        queue.extend(sorted_queue);

        let mut result = Vec::new();
        while let Some(node) = queue.pop_front() {
            result.push(node.to_owned());
            if let Some(neighbors) = adj.get(node) {
                let mut next_batch: Vec<&str> = Vec::new();
                for &neighbor in neighbors {
                    let deg = in_degree.get_mut(neighbor).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        next_batch.push(neighbor);
                    }
                }
                next_batch.sort_unstable();
                queue.extend(next_batch);
            }
        }

        if result.len() != self.passes.len() {
            return Err(PassManagerError::CyclicDependency(
                "cycle detected during topological sort".to_owned(),
            ));
        }
        Ok(result)
    }

    /// Execute all enabled passes in dependency order.
    ///
    /// Results are cached: if a pass's result is already cached it is reused
    /// without re-running the pass.  Call [`invalidate_cache`] to force
    /// re-execution.
    ///
    /// [`invalidate_cache`]: DeobfPassManager::invalidate_cache
    ///
    /// # Errors
    /// Returns a [`PassManagerError`] if the dependency graph is cyclic or
    /// an unrecoverable internal error occurs.  Individual pass failures are
    /// collected in [`PassManagerReport::results`] rather than aborting.
    ///
    /// # Panics
    ///
    /// Panics if a pass entry referenced by the topological order is not found
    /// in the registry (internal consistency error).
    pub fn run(&mut self, ctx: &mut DeobfContext) -> Result<PassManagerReport, PassManagerError> {
        let pipeline_start = Instant::now();
        let order = self.topological_order()?;
        let mut results: Vec<PassResult> = Vec::new();

        for name in &order {
            let entry = self.passes.get(name).unwrap();

            // Use cache if available.
            if entry.cached_result.is_some() {
                self.emit(PassEvent::Skipped {
                    name: name.clone(),
                    reason: "cached".to_owned(),
                });
                // Report cache hits as skipped so callers can distinguish them
                // from passes that actually executed during this run.
                results.push(PassResult::skipped(name.clone(), "cached"));
                continue;
            }

            if !entry.enabled {
                self.emit(PassEvent::Skipped {
                    name: name.clone(),
                    reason: "disabled".to_owned(),
                });
                results.push(PassResult::skipped(name.clone(), "disabled"));
                continue;
            }

            if !entry.pass.is_applicable(ctx) {
                self.emit(PassEvent::Skipped {
                    name: name.clone(),
                    reason: "not applicable".to_owned(),
                });
                results.push(PassResult::skipped(name.clone(), "not applicable"));
                continue;
            }

            self.emit(PassEvent::Starting { name: name.clone() });
            let start = Instant::now();

            let pass_result = match entry.pass.run(ctx) {
                Ok(r) => {
                    let elapsed = start.elapsed();
                    self.emit(PassEvent::Finished {
                        name: name.clone(),
                        elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                        patches: r.patches_applied,
                    });
                    PassResult::success(name.clone(), r, elapsed)
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    let msg = e.to_string();
                    self.emit(PassEvent::Failed {
                        name: name.clone(),
                        error: msg.clone(),
                    });
                    PassResult::failed(name.clone(), &msg, elapsed)
                }
            };

            self.passes.get_mut(name).unwrap().cached_result = Some(pass_result.clone());
            results.push(pass_result);
        }

        let total_ms = u64::try_from(pipeline_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.emit(PassEvent::PipelineDone { total_ms });

        Ok(PassManagerReport {
            results,
            total_elapsed: pipeline_start.elapsed(),
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn check_no_cycle(&self) -> Result<(), String> {
        let mut visited: HashSet<&str> = HashSet::new();
        let mut stack: HashSet<&str> = HashSet::new();

        for name in &self.order {
            if !visited.contains(name.as_str()) {
                self.dfs_cycle(name.as_str(), &mut visited, &mut stack, 0)?;
            }
        }
        Ok(())
    }

    /// Maximum dependency-chain depth for cycle detection.
    /// Guards against stack overflow from attacker-controlled deep chains
    /// (dos-unbounded-recursion).
    const MAX_DFS_DEPTH: usize = 512;

    fn dfs_cycle<'a>(
        &'a self,
        node: &'a str,
        visited: &mut HashSet<&'a str>,
        stack: &mut HashSet<&'a str>,
        depth: usize,
    ) -> Result<(), String> {
        if depth > Self::MAX_DFS_DEPTH {
            // Treat excessively deep chains as a cycle to prevent stack overflow.
            return Err(node.to_owned());
        }
        visited.insert(node);
        stack.insert(node);

        if let Some(entry) = self.passes.get(node) {
            for dep in &entry.deps {
                if !visited.contains(dep.as_str()) {
                    self.dfs_cycle(dep.as_str(), visited, stack, depth + 1)?;
                } else if stack.contains(dep.as_str()) {
                    return Err(dep.clone());
                }
            }
        }
        stack.remove(node);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassManagerReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate report produced by [`DeobfPassManager::run`].
#[derive(Debug, Clone)]
pub struct PassManagerReport {
    /// Per-pass results in execution order.
    pub results: Vec<PassResult>,
    /// Total wall-clock time for the entire pipeline.
    pub total_elapsed: Duration,
}

impl PassManagerReport {
    /// Total number of patches across all passes.
    #[must_use]
    pub fn total_patches(&self) -> usize {
        self.results.iter().map(PassResult::patches_applied).sum()
    }

    /// Number of passes that ran successfully.
    #[must_use]
    pub fn successful_passes(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.ran && r.result.is_some())
            .count()
    }

    /// Number of passes that were skipped.
    #[must_use]
    pub fn skipped_passes(&self) -> usize {
        self.results.iter().filter(|r| !r.ran).count()
    }

    /// Number of passes that failed.
    #[must_use]
    pub fn failed_passes(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.ran && r.result.is_none())
            .count()
    }

    /// Weighted average confidence across ran passes.
    #[must_use]
    pub fn average_confidence(&self) -> f32 {
        let ran: Vec<&PassResult> = self
            .results
            .iter()
            .filter(|r| r.ran && r.result.is_some())
            .collect();
        if ran.is_empty() {
            return 0.0;
        }
        let sum: f32 = ran.iter().map(|r| r.confidence()).sum();
        sum / f32::from(u16::try_from(ran.len()).unwrap_or(u16::MAX))
    }

    /// Return results for the slowest `n` passes.
    #[must_use]
    pub fn slowest_passes(&self, n: usize) -> Vec<&PassResult> {
        let mut sorted: Vec<&PassResult> = self.results.iter().collect();
        sorted.sort_by(|a, b| b.elapsed.cmp(&a.elapsed));
        sorted.truncate(n);
        sorted
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeobfContext, DeobfError, DeobfPass, DeobfResult};

    struct NamedPass {
        name: &'static str,
        patches: usize,
    }

    impl DeobfPass for NamedPass {
        fn name(&self) -> &'static str {
            self.name
        }
        fn description(&self) -> &'static str {
            "test pass"
        }
        fn is_applicable(&self, _ctx: &DeobfContext) -> bool {
            true
        }
        fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
            Ok(DeobfResult::new(
                self.patches,
                vec![self.name.to_owned()],
                self.patches,
                0.9,
            ))
        }
    }

    #[test]
    fn test_register_and_run() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "a",
            patches: 2,
        }))
        .unwrap();
        mgr.register(Box::new(NamedPass {
            name: "b",
            patches: 3,
        }))
        .unwrap();
        let mut ctx = DeobfContext::new(vec![0x90; 16]);
        let report = mgr.run(&mut ctx).unwrap();
        assert_eq!(report.total_patches(), 5);
        assert_eq!(report.successful_passes(), 2);
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "x",
            patches: 0,
        }))
        .unwrap();
        let result = mgr.register(Box::new(NamedPass {
            name: "x",
            patches: 0,
        }));
        assert!(matches!(result, Err(PassManagerError::DuplicateName(_))));
    }

    #[test]
    fn test_dependency_ordering() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "a",
            patches: 1,
        }))
        .unwrap();
        mgr.register(Box::new(NamedPass {
            name: "b",
            patches: 1,
        }))
        .unwrap();
        mgr.add_dependency("b", "a").unwrap();
        let order = mgr.topological_order().unwrap();
        let pos_a = order.iter().position(|n| n == "a").unwrap();
        let pos_b = order.iter().position(|n| n == "b").unwrap();
        assert!(pos_a < pos_b, "a must come before b");
    }

    #[test]
    fn test_cycle_detection() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "a",
            patches: 0,
        }))
        .unwrap();
        mgr.register(Box::new(NamedPass {
            name: "b",
            patches: 0,
        }))
        .unwrap();
        mgr.add_dependency("b", "a").unwrap();
        let result = mgr.add_dependency("a", "b");
        assert!(matches!(result, Err(PassManagerError::CyclicDependency(_))));
    }

    #[test]
    fn test_disable_pass() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "p",
            patches: 5,
        }))
        .unwrap();
        mgr.set_enabled("p", false).unwrap();
        let mut ctx = DeobfContext::new(vec![0u8; 4]);
        let report = mgr.run(&mut ctx).unwrap();
        assert_eq!(report.total_patches(), 0);
        assert_eq!(report.skipped_passes(), 1);
    }

    #[test]
    fn test_cache_reuse() {
        let mut mgr = DeobfPassManager::new();
        mgr.register(Box::new(NamedPass {
            name: "c",
            patches: 1,
        }))
        .unwrap();
        let mut ctx = DeobfContext::new(vec![0u8; 8]);
        mgr.run(&mut ctx).unwrap();
        // Second run should use cache.
        let report2 = mgr.run(&mut ctx).unwrap();
        assert_eq!(report2.skipped_passes(), 1); // cached → skipped
    }

    #[test]
    fn test_progress_events() {
        use std::sync::{Arc, Mutex};
        let events: Arc<Mutex<Vec<PassEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let ev_clone = Arc::clone(&events);
        let mut mgr = DeobfPassManager::new();
        mgr.set_listener(move |e| {
            ev_clone.lock().unwrap().push(e);
        });
        mgr.register(Box::new(NamedPass {
            name: "ev",
            patches: 1,
        }))
        .unwrap();
        let mut ctx = DeobfContext::new(vec![0u8; 4]);
        mgr.run(&mut ctx).unwrap();
        let ev = events.lock().unwrap();
        assert!(ev.iter().any(|e| matches!(e, PassEvent::Starting { .. })));
        assert!(ev.iter().any(|e| matches!(e, PassEvent::Finished { .. })));
        assert!(
            ev.iter()
                .any(|e| matches!(e, PassEvent::PipelineDone { .. }))
        );
    }
}
