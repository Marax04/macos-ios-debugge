//! `deobf_pipeline` — Ordered-sequence deobfuscation pipeline orchestrator.
//!
//! Passes are inserted in explicit execution order; the pipeline records
//! per-pass statistics, supports rollback on failure, exposes pipeline-level
//! configuration, and aggregates results into a `PipelineRunResult`.
//!
//! # Relation to `pass_manager`
//! This module is a **sequential pipeline**: the caller controls pass order
//! directly via insertion, with optional rollback and a `PassId`-keyed result
//! map.
//!
//! [`pass_manager`](crate::pass_manager) is a **DAG-aware manager**: pass
//! order is derived from declared dependencies, the manager validates for
//! cycles, and progress events are emitted during execution. Use it when you
//! need constraint-driven ordering rather than explicit insertion order.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

// ─── PassId ───────────────────────────────────────────────────────────────────

/// Unique identifier for a registered deobfuscation pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PassId(pub String);

impl PassId {
    /// Create a `PassId` from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for PassId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

// ─── PassCounts ───────────────────────────────────────────────────────────────

/// Numeric counters produced by a single deobfuscation pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassCounts {
    /// Number of binary patches applied.
    pub patches_applied: usize,
    /// Number of instructions (bytes) modified.
    pub instructions_modified: usize,
    /// Number of strings recovered.
    pub strings_recovered: usize,
    /// Number of branches simplified.
    pub branches_simplified: usize,
}

// ─── PassResult ───────────────────────────────────────────────────────────────

/// Outcome of running a single deobfuscation pass.
#[derive(Debug, Clone)]
pub struct PassResult {
    /// Identifier of the pass that produced this result.
    pub pass_id: PassId,
    /// Whether the pass ran without error.
    pub success: bool,
    /// Number of binary patches applied by this pass.
    pub patches_applied: usize,
    /// Number of instructions (bytes) modified.
    pub instructions_modified: usize,
    /// Number of strings recovered (if the pass does string recovery).
    pub strings_recovered: usize,
    /// Number of branches simplified (if the pass does CFG simplification).
    pub branches_simplified: usize,
    /// Human-readable descriptions of transformations performed.
    pub transformations: Vec<String>,
    /// Error message if `success == false`.
    pub error: Option<String>,
    /// Wall-clock time consumed by this pass.
    pub elapsed: Duration,
    /// Confidence score for the changes made, in [0.0, 1.0].
    pub confidence: f64,
    /// Snapshot of the binary before the pass (used for rollback).
    snapshot: Option<Vec<u8>>,
}

impl PassResult {
    /// Create a successful pass result.
    #[must_use]
    pub const fn success(
        pass_id: PassId,
        counts: PassCounts,
        transformations: Vec<String>,
        elapsed: Duration,
        confidence: f64,
    ) -> Self {
        let PassCounts { patches_applied, instructions_modified, strings_recovered, branches_simplified } = counts;
        Self {
            pass_id,
            success: true,
            patches_applied,
            instructions_modified,
            strings_recovered,
            branches_simplified,
            transformations,
            error: None,
            elapsed,
            confidence: confidence.clamp(0.0, 1.0),
            snapshot: None,
        }
    }

    /// Create a failed pass result.
    #[must_use]
    pub fn failure(pass_id: PassId, error: impl Into<String>, elapsed: Duration) -> Self {
        Self {
            pass_id,
            success: false,
            patches_applied: 0,
            instructions_modified: 0,
            strings_recovered: 0,
            branches_simplified: 0,
            transformations: Vec::new(),
            error: Some(error.into()),
            elapsed,
            confidence: 0.0,
            snapshot: None,
        }
    }

    /// Return `true` when the pass made at least one modification.
    #[must_use]
    pub const fn made_changes(&self) -> bool {
        self.patches_applied > 0 || self.instructions_modified > 0
    }

    /// Attach a snapshot of the pre-pass binary so callers can roll back.
    #[must_use] 
    pub fn with_snapshot(mut self, snapshot: Vec<u8>) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    /// Borrow the rollback snapshot, if one was captured.
    #[must_use]
    pub fn snapshot(&self) -> Option<&[u8]> {
        self.snapshot.as_deref()
    }

    /// Consume the result and return the rollback snapshot, if any. Useful
    /// when the pipeline needs to restore the pre-pass binary after a failure.
    #[must_use]
    pub const fn take_snapshot(&mut self) -> Option<Vec<u8>> {
        self.snapshot.take()
    }

    /// Returns true when a rollback snapshot is available.
    #[must_use]
    pub const fn has_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }
}

// ─── DeobfPass (pipeline version) ────────────────────────────────────────────

/// A deobfuscation pass runnable by the pipeline.
///
/// Unlike the trait in `lib.rs` this version operates on an owned `Vec<u8>`
/// and returns a `PassResult`, enabling the pipeline to control snapshots
/// and rollback independently.
pub trait DeobfPass: Send + Sync {
    /// Unique identifier for this pass.
    fn id(&self) -> PassId;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// One-line description.
    fn description(&self) -> &str;

    /// Pass IDs that must run successfully before this pass.
    fn dependencies(&self) -> Vec<PassId> {
        Vec::new()
    }

    /// Return `true` when this pass is applicable to `binary`.
    fn is_applicable(&self, binary: &[u8]) -> bool;

    /// Run the pass on `binary`, returning a modified binary and result.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if the pass encounters an unrecoverable error.
    fn run(&self, binary: Vec<u8>) -> Result<(Vec<u8>, PassResult), String>;
}

// ─── PipelineConfig ───────────────────────────────────────────────────────────

/// Configuration for a [`DeobfPipeline`].
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Whether to roll back a pass's changes when it fails.
    pub rollback_on_failure: bool,
    /// Whether to abort the entire pipeline on the first failing pass.
    pub abort_on_failure: bool,
    /// Maximum wall-clock time per pass (None = no limit).
    pub per_pass_timeout: Option<Duration>,
    /// Maximum total pipeline time (None = no limit).
    pub total_timeout: Option<Duration>,
    /// Whether to skip passes that are not applicable to the binary.
    pub skip_inapplicable: bool,
    /// Override pass execution order (by `PassId`).
    /// If empty, the registration order is used.
    pub pass_order: Vec<PassId>,
    /// Passes to disable (will be skipped even if registered).
    pub disabled_passes: HashSet<PassId>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            rollback_on_failure: true,
            abort_on_failure: false,
            per_pass_timeout: None,
            total_timeout: None,
            skip_inapplicable: true,
            pass_order: Vec::new(),
            disabled_passes: HashSet::new(),
        }
    }
}

impl PipelineConfig {
    /// Create a default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable a specific pass by ID.
    #[must_use]
    pub fn disable_pass(mut self, id: PassId) -> Self {
        self.disabled_passes.insert(id);
        self
    }

    /// Set rollback-on-failure.
    #[must_use]
    pub const fn with_rollback(mut self, rollback: bool) -> Self {
        self.rollback_on_failure = rollback;
        self
    }

    /// Set abort-on-failure.
    #[must_use]
    pub const fn with_abort_on_failure(mut self, abort: bool) -> Self {
        self.abort_on_failure = abort;
        self
    }

    /// Set the per-pass timeout.
    #[must_use]
    pub const fn with_pass_timeout(mut self, timeout: Duration) -> Self {
        self.per_pass_timeout = Some(timeout);
        self
    }
}

// ─── PipelineStats ────────────────────────────────────────────────────────────

/// Aggregate statistics from a completed pipeline run.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    /// Total patches applied across all passes.
    pub total_patches: usize,
    /// Total instructions modified.
    pub total_instructions_modified: usize,
    /// Total strings recovered.
    pub total_strings_recovered: usize,
    /// Total branches simplified.
    pub total_branches_simplified: usize,
    /// Number of passes that ran successfully.
    pub passes_succeeded: usize,
    /// Number of passes that failed.
    pub passes_failed: usize,
    /// Number of passes skipped (inapplicable or disabled).
    pub passes_skipped: usize,
    /// Number of rollbacks performed.
    pub rollbacks: usize,
    /// Total wall-clock time.
    pub total_elapsed: Duration,
    /// Weighted average confidence across successful passes.
    pub average_confidence: f64,
}

impl PipelineStats {
    /// Update stats with a `PassResult`.
    pub fn record(&mut self, result: &PassResult) {
        if result.success {
            self.passes_succeeded += 1;
            self.total_patches += result.patches_applied;
            self.total_instructions_modified += result.instructions_modified;
            self.total_strings_recovered += result.strings_recovered;
            self.total_branches_simplified += result.branches_simplified;
            // Running cumulative-average of confidence scores.
            let n = u32::try_from(self.passes_succeeded).unwrap_or(u32::MAX);
            self.average_confidence = self.average_confidence.mul_add(f64::from(n - 1), result.confidence) / f64::from(n);
        } else {
            self.passes_failed += 1;
        }
        self.total_elapsed += result.elapsed;
    }

    /// Record a skipped pass.
    pub const fn record_skip(&mut self) {
        self.passes_skipped += 1;
    }

    /// Record a rollback.
    pub const fn record_rollback(&mut self) {
        self.rollbacks += 1;
        // Also undo the "succeeded" count for the pass that was rolled back.
        if self.passes_succeeded > 0 {
            self.passes_succeeded -= 1;
            self.passes_failed += 1;
        }
    }
}

// ─── PipelineResult ───────────────────────────────────────────────────────────

/// Full result of a pipeline run.
#[derive(Debug)]
pub struct PipelineResult {
    /// The final binary (after all passes).
    pub binary: Vec<u8>,
    /// Per-pass results in execution order.
    pub pass_results: Vec<PassResult>,
    /// Aggregate statistics.
    pub stats: PipelineStats,
    /// Whether the pipeline completed without any failures.
    pub all_passed: bool,
}

impl PipelineResult {
    /// Return pass results sorted by descending confidence.
    #[must_use]
    pub fn results_by_confidence(&self) -> Vec<&PassResult> {
        let mut refs: Vec<&PassResult> = self.pass_results.iter().collect();
        refs.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        refs
    }

    /// Return failed pass results.
    #[must_use]
    pub fn failures(&self) -> Vec<&PassResult> {
        self.pass_results.iter().filter(|r| !r.success).collect()
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Pipeline: {}/{} passes succeeded, {} patches, {} strings recovered, {}ms",
            self.stats.passes_succeeded,
            self.stats.passes_succeeded + self.stats.passes_failed,
            self.stats.total_patches,
            self.stats.total_strings_recovered,
            self.stats.total_elapsed.as_millis(),
        )
    }
}

// ─── DeobfPipeline ────────────────────────────────────────────────────────────

/// Ordered sequence of `DeobfPass` objects with dependency resolution, rollback,
/// and aggregated statistics.
pub struct DeobfPipeline {
    passes: Vec<Box<dyn DeobfPass>>,
    config: PipelineConfig,
}

impl DeobfPipeline {
    /// Create an empty pipeline with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            config: PipelineConfig::default(),
        }
    }

    /// Create a pipeline with a specific configuration.
    #[must_use]
    pub fn with_config(config: PipelineConfig) -> Self {
        Self {
            passes: Vec::new(),
            config,
        }
    }

    /// Register a pass at the end of the pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn DeobfPass>) {
        self.passes.push(pass);
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Return the names of all registered passes in order.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&str> {
        self.passes.iter().map(|p| p.name()).collect()
    }

    /// Build an ordered execution list respecting `config.pass_order` and
    /// topological dependency ordering.
    ///
    /// Returns the indices into `self.passes` in execution order.
    fn execution_order(&self) -> Vec<usize> {
        /// Maximum dependency-chain depth before we refuse to recurse further.
        /// Prevents stack overflow when a caller registers a pathologically deep
        /// dependency chain (dos-unbounded-recursion).
        const MAX_VISIT_DEPTH: usize = 512;

        fn visit(
            idx: usize,
            passes: &[Box<dyn DeobfPass>],
            id_to_idx: &HashMap<PassId, usize>,
            visited: &mut Vec<bool>,
            order: &mut Vec<usize>,
            depth: usize,
        ) {
            if visited[idx] || depth > MAX_VISIT_DEPTH {
                return;
            }
            visited[idx] = true;
            for dep_id in passes[idx].dependencies() {
                if let Some(&dep_idx) = id_to_idx.get(&dep_id) {
                    visit(dep_idx, passes, id_to_idx, visited, order, depth + 1);
                }
            }
            order.push(idx);
        }

        if !self.config.pass_order.is_empty() {
            // Use explicit order; only include passes found in the registry.
            let id_to_idx: HashMap<PassId, usize> = self
                .passes
                .iter()
                .enumerate()
                .map(|(i, p)| (p.id(), i))
                .collect();
            let mut order: Vec<usize> = self
                .config
                .pass_order
                .iter()
                .filter_map(|id| id_to_idx.get(id).copied())
                .collect();
            // Append passes not mentioned in pass_order at the end.
            let mentioned: HashSet<usize> = order.iter().copied().collect();
            for i in 0..self.passes.len() {
                if !mentioned.contains(&i) {
                    order.push(i);
                }
            }
            return order;
        }

        // Default: topological sort by dependencies.
        let id_to_idx: HashMap<PassId, usize> = self
            .passes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id(), i))
            .collect();

        let n = self.passes.len();
        let mut visited = vec![false; n];
        let mut order = Vec::with_capacity(n);

        for i in 0..n {
            visit(i, &self.passes, &id_to_idx, &mut visited, &mut order, 0);
        }

        order
    }

    /// Run all passes on `binary` and return the full pipeline result.
    ///
    /// The input binary is consumed; the output binary is in `PipelineResult::binary`.
    #[must_use]
    pub fn run(&self, mut binary: Vec<u8>) -> PipelineResult {
        let pipeline_start = Instant::now();
        let order = self.execution_order();
        let mut pass_results: Vec<PassResult> = Vec::new();
        let mut stats = PipelineStats::default();
        let mut completed_ids: HashSet<PassId> = HashSet::new();
        let mut all_passed = true;

        for idx in order {
            let pass = &self.passes[idx];
            let pass_id = pass.id();

            // Check if disabled.
            if self.config.disabled_passes.contains(&pass_id) {
                stats.record_skip();
                continue;
            }

            // Check dependencies are satisfied.
            let deps_satisfied = pass
                .dependencies()
                .iter()
                .all(|dep| completed_ids.contains(dep));
            if !deps_satisfied {
                stats.record_skip();
                continue;
            }

            // Check applicability.
            if self.config.skip_inapplicable && !pass.is_applicable(&binary) {
                stats.record_skip();
                continue;
            }

            // Snapshot for rollback.
            let snapshot = if self.config.rollback_on_failure {
                Some(binary.clone())
            } else {
                None
            };

            // Check total timeout.
            if let Some(total_timeout) = self.config.total_timeout
                && pipeline_start.elapsed() >= total_timeout {
                    break;
                }

            let pass_start = Instant::now();
            let result = pass.run(binary.clone());
            let elapsed = pass_start.elapsed();

            match result {
                Ok((new_binary, mut pr)) => {
                    pr.elapsed = elapsed;
                    binary = new_binary;
                    stats.record(&pr);
                    completed_ids.insert(pass_id);
                    pass_results.push(pr);
                }
                Err(e) => {
                    all_passed = false;
                    let pr = PassResult::failure(pass_id, e, elapsed);

                    if self.config.rollback_on_failure
                        && let Some(snap) = snapshot {
                            binary = snap;
                            stats.record_rollback();
                        }

                    stats.record(&pr);
                    pass_results.push(pr);

                    if self.config.abort_on_failure {
                        break;
                    }
                }
            }
        }

        stats.total_elapsed = pipeline_start.elapsed();

        PipelineResult {
            binary,
            pass_results,
            stats,
            all_passed,
        }
    }

    /// Dry-run: check which passes would execute without modifying the binary.
    ///
    /// Returns `(pass_name, would_execute)` pairs.
    #[must_use]
    pub fn dry_run(&self, binary: &[u8]) -> Vec<(String, bool)> {
        let order = self.execution_order();
        order
            .iter()
            .map(|&idx| {
                let pass = &self.passes[idx];
                let disabled = self.config.disabled_passes.contains(&pass.id());
                let applicable = if self.config.skip_inapplicable {
                    pass.is_applicable(binary)
                } else {
                    true
                };
                (pass.name().to_string(), !disabled && applicable)
            })
            .collect()
    }
}

impl Default for DeobfPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeobfPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeobfPipeline")
            .field("pass_count", &self.passes.len())
            .finish_non_exhaustive()
    }
}

// ─── Convenience pass implementations ────────────────────────────────────────

/// A no-op pass that always succeeds (useful for testing the pipeline).
pub struct NoOpPass {
    id: PassId,
}

impl NoOpPass {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: PassId::new(id) }
    }
}

impl DeobfPass for NoOpPass {
    fn id(&self) -> PassId { self.id.clone() }
    fn name(&self) -> &'static str { "no-op" }
    fn description(&self) -> &'static str { "No-op pass for testing" }
    fn is_applicable(&self, _binary: &[u8]) -> bool { true }
    fn run(&self, binary: Vec<u8>) -> Result<(Vec<u8>, PassResult), String> {
        let result = PassResult::success(
            self.id(),
            PassCounts::default(),
            vec!["no-op".to_string()],
            Duration::ZERO,
            1.0,
        );
        Ok((binary, result))
    }
}

/// A pass that always fails (useful for testing rollback logic).
pub struct AlwaysFailPass {
    id: PassId,
}

impl AlwaysFailPass {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: PassId::new(id) }
    }
}

impl DeobfPass for AlwaysFailPass {
    fn id(&self) -> PassId { self.id.clone() }
    fn name(&self) -> &'static str { "always-fail" }
    fn description(&self) -> &'static str { "Always fails (test pass)" }
    fn is_applicable(&self, _binary: &[u8]) -> bool { true }
    fn run(&self, _binary: Vec<u8>) -> Result<(Vec<u8>, PassResult), String> {
        Err("simulated failure".to_string())
    }
}

/// A pass that XOR-decrypts the binary with a fixed key byte (demonstration pass).
pub struct XorDecryptPass {
    id: PassId,
    key: u8,
}

impl XorDecryptPass {
    #[must_use]
    pub fn new(id: impl Into<String>, key: u8) -> Self {
        Self { id: PassId::new(id), key }
    }
}

impl DeobfPass for XorDecryptPass {
    fn id(&self) -> PassId { self.id.clone() }
    fn name(&self) -> &'static str { "xor-decrypt" }
    fn description(&self) -> &'static str { "XOR-decrypts the binary with a fixed key byte" }
    fn is_applicable(&self, binary: &[u8]) -> bool { !binary.is_empty() }
    fn run(&self, binary: Vec<u8>) -> Result<(Vec<u8>, PassResult), String> {
        let n = binary.len();
        let decrypted: Vec<u8> = binary.iter().map(|&b| b ^ self.key).collect();
        let result = PassResult::success(
            self.id(),
            PassCounts { patches_applied: n, instructions_modified: n, ..Default::default() },
            vec![format!("XOR decrypted {} bytes with key 0x{:02X}", n, self.key)],
            Duration::ZERO,
            0.8,
        );
        Ok((decrypted, result))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_id_new_and_display() {
        let id = PassId::new("xor-decrypt");
        assert_eq!(id.as_str(), "xor-decrypt");
        assert_eq!(id.to_string(), "xor-decrypt");
    }

    #[test]
    fn pass_id_from_str() {
        let id: PassId = "test".into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn pass_result_success() {
        let r = PassResult::success(
            PassId::new("p1"),
            PassCounts { patches_applied: 5, instructions_modified: 20, strings_recovered: 3, branches_simplified: 1 },
            vec!["transform".to_string()],
            Duration::from_millis(10),
            0.9,
        );
        assert!(r.success);
        assert!(r.made_changes());
        assert_eq!(r.patches_applied, 5);
    }

    #[test]
    fn pass_result_failure() {
        let r = PassResult::failure(PassId::new("p2"), "oops", Duration::ZERO);
        assert!(!r.success);
        assert!(!r.made_changes());
        assert!(r.error.unwrap().contains("oops"));
    }

    #[test]
    fn pass_result_confidence_clamped() {
        let r = PassResult::success(
            PassId::new("p"), PassCounts::default(), vec![], Duration::ZERO, 2.5,
        );
        assert_eq!(r.confidence, 1.0);
    }

    #[test]
    fn pipeline_config_default() {
        let cfg = PipelineConfig::default();
        assert!(cfg.rollback_on_failure);
        assert!(!cfg.abort_on_failure);
    }

    #[test]
    fn pipeline_config_builder() {
        let cfg = PipelineConfig::new()
            .with_rollback(false)
            .with_abort_on_failure(true)
            .disable_pass(PassId::new("skip_me"));
        assert!(!cfg.rollback_on_failure);
        assert!(cfg.abort_on_failure);
        assert!(cfg.disabled_passes.contains(&PassId::new("skip_me")));
    }

    #[test]
    fn pipeline_empty_run() {
        let pipeline = DeobfPipeline::new();
        let binary = vec![0u8; 32];
        let result = pipeline.run(binary.clone());
        assert_eq!(result.binary, binary);
        assert!(result.all_passed);
        assert_eq!(result.stats.passes_succeeded, 0);
    }

    #[test]
    fn pipeline_no_op_pass() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(NoOpPass::new("noop")));
        let binary = vec![0xAAu8; 64];
        let result = pipeline.run(binary.clone());
        assert_eq!(result.binary, binary);
        assert_eq!(result.stats.passes_succeeded, 1);
    }

    #[test]
    fn pipeline_xor_pass() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(XorDecryptPass::new("xor", 0xAA)));
        let binary = vec![0xAAu8; 4];
        let result = pipeline.run(binary);
        assert_eq!(result.binary, vec![0u8; 4]);
        assert_eq!(result.stats.total_patches, 4);
    }

    #[test]
    fn pipeline_always_fail_rollback() {
        let original = vec![0x11u8; 32];
        let mut pipeline = DeobfPipeline::with_config(
            PipelineConfig::new().with_rollback(true)
        );
        pipeline.add_pass(Box::new(AlwaysFailPass::new("fail")));
        let result = pipeline.run(original.clone());
        // Binary should be unchanged after rollback.
        assert_eq!(result.binary, original);
        assert_eq!(result.stats.rollbacks, 1);
    }

    #[test]
    fn pipeline_abort_on_failure() {
        let mut pipeline = DeobfPipeline::with_config(
            PipelineConfig::new().with_abort_on_failure(true)
        );
        pipeline.add_pass(Box::new(AlwaysFailPass::new("fail")));
        pipeline.add_pass(Box::new(NoOpPass::new("should_not_run")));
        let result = pipeline.run(vec![0u8; 32]);
        // Second pass should not have run.
        assert_eq!(result.pass_results.len(), 1);
    }

    #[test]
    fn pipeline_disabled_pass_skipped() {
        let cfg = PipelineConfig::new().disable_pass(PassId::new("noop"));
        let mut pipeline = DeobfPipeline::with_config(cfg);
        pipeline.add_pass(Box::new(NoOpPass::new("noop")));
        let result = pipeline.run(vec![0u8; 32]);
        assert_eq!(result.stats.passes_skipped, 1);
        assert_eq!(result.stats.passes_succeeded, 0);
    }

    #[test]
    fn pipeline_pass_names() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(NoOpPass::new("n1")));
        pipeline.add_pass(Box::new(NoOpPass::new("n2")));
        let names = pipeline.pass_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn pipeline_dry_run() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(NoOpPass::new("n1")));
        let plan = pipeline.dry_run(&[0u8; 32]);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].1); // would execute
    }

    #[test]
    fn pipeline_stats_record() {
        let mut stats = PipelineStats::default();
        let r = PassResult::success(
            PassId::new("p"), PassCounts { patches_applied: 10, instructions_modified: 20, strings_recovered: 5, branches_simplified: 2 }, vec![], Duration::from_millis(5), 0.8,
        );
        stats.record(&r);
        assert_eq!(stats.passes_succeeded, 1);
        assert_eq!(stats.total_patches, 10);
        assert_eq!(stats.total_strings_recovered, 5);
        assert!((stats.average_confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn pipeline_result_summary() {
        let result = PipelineResult {
            binary: vec![],
            pass_results: vec![],
            stats: PipelineStats {
                passes_succeeded: 3,
                passes_failed: 1,
                total_patches: 42,
                total_strings_recovered: 7,
                total_elapsed: Duration::from_millis(50),
                ..Default::default()
            },
            all_passed: false,
        };
        let s = result.summary();
        assert!(s.contains("3/4"));
        assert!(s.contains("42"));
    }

    #[test]
    fn pipeline_result_failures() {
        let results = PipelineResult {
            binary: vec![],
            pass_results: vec![
                PassResult::success(PassId::new("ok"), PassCounts::default(), vec![], Duration::ZERO, 1.0),
                PassResult::failure(PassId::new("bad"), "err", Duration::ZERO),
            ],
            stats: PipelineStats::default(),
            all_passed: false,
        };
        assert_eq!(results.failures().len(), 1);
        let by_conf = results.results_by_confidence();
        assert_eq!(by_conf.len(), 2);
        assert!(by_conf[0].confidence >= by_conf[1].confidence);
    }

    #[test]
    fn pipeline_two_passes_in_order() {
        let mut pipeline = DeobfPipeline::new();
        // XOR 0xAA then XOR 0xAA should restore original.
        pipeline.add_pass(Box::new(XorDecryptPass::new("xor1", 0xAA)));
        pipeline.add_pass(Box::new(XorDecryptPass::new("xor2", 0xAA)));
        let binary = vec![0x55u8; 8];
        let result = pipeline.run(binary.clone());
        assert_eq!(result.binary, binary);
        assert_eq!(result.stats.passes_succeeded, 2);
    }

    #[test]
    fn pipeline_debug_format() {
        let pipeline = DeobfPipeline::new();
        let _ = format!("{pipeline:?}");
    }
}
