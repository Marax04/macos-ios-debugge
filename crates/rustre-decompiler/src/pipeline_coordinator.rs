//! `pipeline_coordinator.rs` — Full decompiler pipeline coordinator.
//!
//! Manages the ordered execution of decompiler passes:
//!   LLIL → MLIL → HLIL → CFS → `TypeInfer` → `CPrinter`
//!
//! Features:
//! - Pass dependency tracking and topological ordering
//! - Checkpoint/resume if a pass fails
//! - Per-pass telemetry (time, memory, function count)
//! - Retry with fallback (e.g., if CFS fails, linear emit)

use crate::{DecompilerContext, DecompilerError, DecompilerPass, DecompOptions, IrLevel};
use rustre_core::arch::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// PassId — typed pass identifier
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a pipeline pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PassId(pub String);

impl PassId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for PassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassTelemetry — per-pass metrics
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics collected for a single pass execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassTelemetry {
    /// Wall-clock duration of the pass.
    pub elapsed_ms: u64,
    /// Approximate peak memory usage in bytes (estimated from heap allocator).
    pub peak_memory_bytes: usize,
    /// Number of functions processed in this pass.
    pub functions_processed: usize,
    /// Whether this pass succeeded.
    pub succeeded: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Number of retries that were attempted.
    pub retries: u32,
    /// Whether a fallback was used.
    pub used_fallback: bool,
}

impl fmt::Display for PassTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "elapsed={}ms mem={}B fns={} ok={} retries={}{}",
            self.elapsed_ms,
            self.peak_memory_bytes,
            self.functions_processed,
            self.succeeded,
            self.retries,
            if self.used_fallback { " [fallback]" } else { "" }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassSpec — pass descriptor with dependency info
// ─────────────────────────────────────────────────────────────────────────────

/// Description of a pass and its runtime constraints.
#[derive(Debug, Clone)]
pub struct PassSpec {
    /// Unique pass identifier.
    pub id: PassId,
    /// Passes that must complete successfully before this one.
    pub depends_on: Vec<PassId>,
    /// IR level produced by this pass.
    pub output_level: IrLevel,
    /// Maximum retries on failure (0 = no retry).
    pub max_retries: u32,
    /// Optional fallback pass ID to use if all retries fail.
    pub fallback: Option<PassId>,
    /// Whether the pipeline can continue if this pass fails.
    pub is_required: bool,
    /// Hard timeout for this pass in milliseconds (0 = no limit).
    pub timeout_ms: u64,
}

impl PassSpec {
    /// Create a required pass with no dependencies and no timeout.
    pub fn required(id: impl Into<String>, output_level: IrLevel) -> Self {
        Self {
            id: PassId::new(id),
            depends_on: Vec::new(),
            output_level,
            max_retries: 0,
            fallback: None,
            is_required: true,
            timeout_ms: 0,
        }
    }

    /// Create an optional pass.
    pub fn optional(id: impl Into<String>, output_level: IrLevel) -> Self {
        Self {
            id: PassId::new(id),
            depends_on: Vec::new(),
            output_level,
            max_retries: 1,
            fallback: None,
            is_required: false,
            timeout_ms: 0,
        }
    }

    #[must_use] 
    pub fn with_deps(mut self, deps: &[&str]) -> Self {
        self.depends_on = deps.iter().map(|d| PassId::new(*d)).collect();
        self
    }

    #[must_use]
    pub fn with_fallback(mut self, fallback: impl Into<String>) -> Self {
        self.fallback = Some(PassId::new(fallback));
        self
    }

    #[must_use] 
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    #[must_use] 
    pub const fn with_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckpointStore — persist/resume pass state
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which passes have completed so the pipeline can resume after a crash.
#[derive(Debug, Default)]
pub struct CheckpointStore {
    /// Set of pass IDs that have completed successfully.
    completed: HashSet<String>,
    /// The last checkpoint timestamp.
    last_checkpoint: Option<Instant>,
}

impl CheckpointStore {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a pass as completed.
    pub fn mark_complete(&mut self, id: &PassId) {
        self.completed.insert(id.0.clone());
        self.last_checkpoint = Some(Instant::now());
    }

    /// Returns `true` if the pass has already completed.
    #[must_use] 
    pub fn is_complete(&self, id: &PassId) -> bool {
        self.completed.contains(&id.0)
    }

    /// Clear all checkpoints (start fresh).
    pub fn reset(&mut self) {
        self.completed.clear();
        self.last_checkpoint = None;
    }

    /// Number of completed passes.
    #[must_use] 
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Time since the last checkpoint, if any.
    #[must_use] 
    pub fn since_last_checkpoint(&self) -> Option<Duration> {
        self.last_checkpoint.map(|t| t.elapsed())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PipelineStage — canonical ordered stages
// ─────────────────────────────────────────────────────────────────────────────

/// The canonical order of decompiler pipeline stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Raw disassembly.
    Disassembly = 0,
    /// Low-level IL lifting.
    Llil = 1,
    /// Mid-level IL / SSA construction.
    Mlil = 2,
    /// High-level IL.
    Hlil = 3,
    /// Control flow structuring.
    Cfs = 4,
    /// Type inference.
    TypeInfer = 5,
    /// C pseudo-code printing.
    CPrinter = 6,
}

impl fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disassembly => write!(f, "Disassembly"),
            Self::Llil => write!(f, "LLIL"),
            Self::Mlil => write!(f, "MLIL"),
            Self::Hlil => write!(f, "HLIL"),
            Self::Cfs => write!(f, "CFS"),
            Self::TypeInfer => write!(f, "TypeInfer"),
            Self::CPrinter => write!(f, "CPrinter"),
        }
    }
}

impl PipelineStage {
    /// Return all stages in canonical execution order.
    #[must_use] 
    pub fn all_ordered() -> Vec<Self> {
        vec![
            Self::Disassembly,
            Self::Llil,
            Self::Mlil,
            Self::Hlil,
            Self::Cfs,
            Self::TypeInfer,
            Self::CPrinter,
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DependencyGraph — topological sort of passes
// ─────────────────────────────────────────────────────────────────────────────

/// Builds and queries the dependency graph of passes.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// All registered pass specs, keyed by ID.
    specs: HashMap<String, PassSpec>,
    /// Adjacency list: id → [dependents] (reverse of `depends_on`).
    dependents: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass spec.
    pub fn add_pass(&mut self, spec: PassSpec) {
        let id = spec.id.0.clone();
        for dep in &spec.depends_on {
            self.dependents
                .entry(dep.0.clone())
                .or_default()
                .push(id.clone());
        }
        self.specs.insert(id, spec);
    }

    /// Compute a valid topological execution order using Kahn's algorithm.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the dependency graph contains a cycle.
    pub fn topological_order(&self) -> Result<Vec<PassId>, DecompilerError> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        for id in self.specs.keys() {
            in_degree.entry(id.clone()).or_insert(0);
        }
        for spec in self.specs.values() {
            for dep in &spec.depends_on {
                *in_degree.entry(dep.0.clone()).or_insert(0) += 0; // ensure entry exists
                *in_degree.entry(spec.id.0.clone()).or_insert(0) += 0;
            }
        }
        // Count actual in-degrees.
        let mut in_deg: HashMap<String, usize> = self.specs.keys().map(|k| (k.clone(), 0)).collect();
        for spec in self.specs.values() {
            for _dep in &spec.depends_on {
                *in_deg.entry(spec.id.0.clone()).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<String> = in_deg
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut order = Vec::new();

        while let Some(id) = queue.pop_front() {
            order.push(PassId(id.clone()));
            if let Some(deps) = self.dependents.get(&id) {
                for dep_id in deps {
                    let cnt = in_deg.entry(dep_id.clone()).or_insert(0);
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 {
                        queue.push_back(dep_id.clone());
                    }
                }
            }
        }

        if order.len() != self.specs.len() {
            return Err(DecompilerError::Other(
                "dependency cycle detected in pass graph".to_string(),
            ));
        }

        Ok(order)
    }

    /// Passes that have no remaining dependencies.
    #[must_use] 
    pub fn ready_passes(&self, completed: &HashSet<String>) -> Vec<&PassSpec> {
        self.specs
            .values()
            .filter(|s| {
                !completed.contains(&s.id.0)
                    && s.depends_on.iter().all(|d| completed.contains(&d.0))
            })
            .collect()
    }

    /// Returns `true` if every required pass is in `completed`.
    #[must_use] 
    pub fn all_required_complete(&self, completed: &HashSet<String>) -> bool {
        self.specs
            .values()
            .filter(|s| s.is_required)
            .all(|s| completed.contains(&s.id.0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FallbackStrategy — how to recover when a pass fails
// ─────────────────────────────────────────────────────────────────────────────

/// Describes what to do when a pass fails all retries.
#[derive(Debug, Clone)]
pub enum FallbackStrategy {
    /// Use a completely linear emit (just dump instructions as comments).
    LinearEmit,
    /// Fall back to a specific named pass.
    NamedPass(PassId),
    /// Mark the function as failed and move on.
    SkipFunction,
    /// Abort the entire pipeline.
    Abort,
}

// ─────────────────────────────────────────────────────────────────────────────
// CoordinatorConfig — runtime options
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the `PipelineCoordinator`.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Global per-pass timeout override (0 = use individual specs).
    pub global_timeout_ms: u64,
    /// Maximum total passes before the pipeline is considered stuck.
    pub max_total_passes: usize,
    /// Default fallback when a required pass fails.
    pub default_fallback: FallbackStrategy,
    /// Emit telemetry even for successful passes.
    pub verbose_telemetry: bool,
    /// Whether to resume from a checkpoint if available.
    pub use_checkpoint: bool,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            global_timeout_ms: 0,
            max_total_passes: 1000,
            default_fallback: FallbackStrategy::SkipFunction,
            verbose_telemetry: false,
            use_checkpoint: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PipelineCoordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Coordinates execution of the full decompiler pipeline.
///
/// Manages pass ordering, dependency tracking, checkpoint/resume,
/// retry-with-fallback, and telemetry.
pub struct PipelineCoordinator {
    /// Dependency graph of all registered passes.
    graph: DependencyGraph,
    /// Concrete pass implementations, keyed by ID.
    impls: HashMap<String, Arc<dyn DecompilerPass>>,
    /// Configuration.
    config: CoordinatorConfig,
    /// Checkpoint store.
    checkpoint: CheckpointStore,
    /// Collected telemetry, keyed by pass ID.
    telemetry: HashMap<String, PassTelemetry>,
}

impl PipelineCoordinator {
    /// Create a new coordinator with default configuration.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            graph: DependencyGraph::new(),
            impls: HashMap::new(),
            config: CoordinatorConfig::default(),
            checkpoint: CheckpointStore::new(),
            telemetry: HashMap::new(),
        }
    }

    /// Create with custom config.
    #[must_use] 
    pub fn with_config(config: CoordinatorConfig) -> Self {
        Self {
            graph: DependencyGraph::new(),
            impls: HashMap::new(),
            config,
            checkpoint: CheckpointStore::new(),
            telemetry: HashMap::new(),
        }
    }

    /// Register a pass spec and its implementation.
    pub fn register_pass(&mut self, spec: PassSpec, implementation: Arc<dyn DecompilerPass>) {
        let id = spec.id.0.clone();
        self.graph.add_pass(spec);
        self.impls.insert(id, implementation);
    }

    /// Build a standard LLIL→MLIL→HLIL→CFS→TypeInfer→CPrinter pipeline
    /// from the given pass implementations.
    #[must_use] 
    pub fn build_standard_pipeline(passes: Vec<(PassSpec, Arc<dyn DecompilerPass>)>) -> Self {
        let mut coordinator = Self::new();
        for (spec, imp) in passes {
            coordinator.register_pass(spec, imp);
        }
        coordinator
    }

    /// Reset the checkpoint, forcing all passes to re-run.
    pub fn reset_checkpoint(&mut self) {
        self.checkpoint.reset();
    }

    /// Run the full pipeline for a single function.
    ///
    /// Returns the final `DecompilerContext` after all passes have run.
    ///
    /// # Errors
    ///
    /// Returns `Err` if topological ordering fails or the pass limit is exceeded.
    pub fn run_for_function(
        &mut self,
        address: u64,
        func_name: &str,
        instructions: &[Instruction],
        options: &DecompOptions,
    ) -> Result<DecompilerContext, DecompilerError> {
        // Reset the per-function checkpoint before each run.  The checkpoint is
        // intended only as a crash-resume mechanism within a single function's
        // pass sequence; carrying it across separate function calls would cause
        // every pass to be skipped for the second function (state-machine-skipped).
        self.checkpoint.reset();

        // Compute execution order.
        let order = self.graph.topological_order()?;

        let mut ctx = DecompilerContext::new(address, func_name, options.clone());
        let mut completed: HashSet<String> = HashSet::new();

        for (total_passes, pass_id) in order.iter().enumerate() {
            if total_passes >= self.config.max_total_passes {
                return Err(DecompilerError::Other(format!(
                    "exceeded max_total_passes={} at pass {}",
                    self.config.max_total_passes, pass_id
                )));
            }

            // Skip if already completed (checkpoint resume).
            if self.config.use_checkpoint && self.checkpoint.is_complete(pass_id) {
                completed.insert(pass_id.0.clone());
                continue;
            }

            // Check dependencies.
            let spec = match self.graph.specs.get(&pass_id.0) {
                Some(s) => s.clone(),
                None => continue,
            };

            let deps_met = spec.depends_on.iter().all(|d| completed.contains(&d.0));
            if !deps_met {
                if spec.is_required {
                    return Err(DecompilerError::Other(format!(
                        "pass '{pass_id}' dependencies not met"
                    )));
                }
                continue;
            }

            let impl_pass = match self.impls.get(&pass_id.0) {
                Some(p) => p.clone(),
                None => continue,
            };

            if !impl_pass.is_enabled(options) {
                continue;
            }

            // Execute with retry.
            let (succeeded, telemetry) = self.execute_with_retry(
                &spec,
                impl_pass.as_ref(),
                &mut ctx,
                address,
                instructions,
            );

            self.telemetry.insert(pass_id.0.clone(), telemetry);

            if succeeded {
                completed.insert(pass_id.0.clone());
                self.checkpoint.mark_complete(pass_id);
            } else if spec.is_required {
                // Apply fallback strategy.
                match &self.config.default_fallback {
                    FallbackStrategy::LinearEmit => {
                        Self::apply_linear_fallback(&mut ctx, instructions);
                        completed.insert(pass_id.0.clone());
                    }
                    FallbackStrategy::SkipFunction => {
                        return Err(DecompilerError::PassError {
                            pass: pass_id.0.clone(),
                            message: "required pass failed; function skipped".to_string(),
                        });
                    }
                    FallbackStrategy::Abort => {
                        return Err(DecompilerError::PassError {
                            pass: pass_id.0.clone(),
                            message: "pipeline aborted due to required pass failure".to_string(),
                        });
                    }
                    FallbackStrategy::NamedPass(fallback_id) => {
                        if let Some(fp) = self.impls.get(&fallback_id.0).cloned() {
                            let start = Instant::now();
                            let _ = fp.run(&mut ctx, address, instructions);
                            let elapsed = start.elapsed();
                            ctx.record_pass_time(format!("{pass_id}_fallback"), elapsed);
                            completed.insert(pass_id.0.clone());
                        }
                    }
                }
            }
        }

        Ok(ctx)
    }

    /// Execute a pass with retry logic.
    fn execute_with_retry(
        &self,
        spec: &PassSpec,
        pass: &dyn DecompilerPass,
        ctx: &mut DecompilerContext,
        address: u64,
        instructions: &[Instruction],
    ) -> (bool, PassTelemetry) {
        let mut telem = PassTelemetry::default();
        let mut last_err = String::new();

        let timeout_ms = if self.config.global_timeout_ms > 0 {
            self.config.global_timeout_ms
        } else {
            spec.timeout_ms
        };

        for attempt in 0..=spec.max_retries {
            telem.retries = attempt;
            let start = Instant::now();
            let result = pass.run(ctx, address, instructions);
            let elapsed = start.elapsed();
            let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
            telem.elapsed_ms += elapsed_ms;

            // Timeout check.
            if timeout_ms > 0 && elapsed_ms > timeout_ms {
                last_err = format!("timed out after {elapsed_ms}ms");
                continue;
            }

            match result {
                Ok(()) => {
                    telem.succeeded = true;
                    telem.functions_processed = 1;
                    return (true, telem);
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }

        // Try named fallback if configured.
        if let Some(ref fallback_id) = spec.fallback
            && let Some(fp) = self.impls.get(&fallback_id.0).cloned() {
                let start = Instant::now();
                if fp.run(ctx, address, instructions).is_ok() {
                    telem.elapsed_ms += u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    telem.succeeded = true;
                    telem.used_fallback = true;
                    telem.functions_processed = 1;
                    return (true, telem);
                }
            }

        telem.error = Some(last_err);
        (false, telem)
    }

    /// Apply a linear fallback: emit instructions as comments.
    fn apply_linear_fallback(ctx: &mut DecompilerContext, instructions: &[Instruction]) {
        ctx.emit_line("// [LINEAR FALLBACK] CFS failed; emitting raw disassembly");
        for instr in instructions {
            ctx.emit_line(format!(
                "  /* {:#x}: {} {} */",
                instr.address.0, instr.mnemonic, instr.operands
            ));
        }
        ctx.advance_ir_level(IrLevel::Llil);
    }

    /// Return collected telemetry for all passes.
    #[must_use] 
    pub const fn telemetry(&self) -> &HashMap<String, PassTelemetry> {
        &self.telemetry
    }

    /// Total elapsed time across all passes.
    #[must_use] 
    pub fn total_elapsed_ms(&self) -> u64 {
        self.telemetry.values().map(|t| t.elapsed_ms).sum()
    }

    /// Number of passes that succeeded.
    #[must_use] 
    pub fn succeeded_count(&self) -> usize {
        self.telemetry.values().filter(|t| t.succeeded).count()
    }

    /// Number of passes that failed.
    #[must_use] 
    pub fn failed_count(&self) -> usize {
        self.telemetry.values().filter(|t| !t.succeeded).count()
    }

    /// Summarise telemetry to a human-readable string.
    #[must_use] 
    pub fn telemetry_report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Pipeline telemetry: {} passes, {} ok, {} failed, total {}ms",
            self.telemetry.len(),
            self.succeeded_count(),
            self.failed_count(),
            self.total_elapsed_ms(),
        ));
        let mut ids: Vec<&String> = self.telemetry.keys().collect();
        ids.sort();
        for id in ids {
            let t = &self.telemetry[id];
            lines.push(format!("  [{id}] {t}"));
        }
        lines.join("\n")
    }

    /// Return the checkpoint store (for inspection or serialisation).
    #[must_use] 
    pub const fn checkpoint(&self) -> &CheckpointStore {
        &self.checkpoint
    }
}

impl Default for PipelineCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PipelineCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PipelineCoordinator {{ passes: {}, telemetry: {} }}",
            self.impls.len(),
            self.telemetry.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standard pass specs
// ─────────────────────────────────────────────────────────────────────────────

/// Build the standard ordered `PassSpec` list for the default pipeline.
#[must_use] 
pub fn standard_pass_specs() -> Vec<PassSpec> {
    vec![
        PassSpec::required("disassembly", IrLevel::Llil),
        PassSpec::required("call_sites", IrLevel::Llil)
            .with_deps(&["disassembly"]),
        PassSpec::required("variable_collection", IrLevel::Llil)
            .with_deps(&["disassembly"]),
        PassSpec::required("constant_propagation", IrLevel::MlilSsa)
            .with_deps(&["variable_collection"]),
        PassSpec::optional("dead_code_elimination", IrLevel::MlilSsa)
            .with_deps(&["constant_propagation"])
            .with_retries(1),
        PassSpec::optional("hlil_build", IrLevel::Hlil)
            .with_deps(&["dead_code_elimination"])
            .with_retries(2)
            .with_fallback("linear_emit"),
        PassSpec::optional("cfs", IrLevel::PseudoC)
            .with_deps(&["hlil_build"])
            .with_retries(1)
            .with_fallback("linear_emit"),
        PassSpec::optional("type_infer", IrLevel::PseudoC)
            .with_deps(&["cfs"]),
        PassSpec::required("function_body", IrLevel::PseudoC)
            .with_deps(&["type_infer"])
            .with_retries(0),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topological_order_no_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_pass(PassSpec::required("a", IrLevel::Llil));
        graph.add_pass(PassSpec::required("b", IrLevel::MlilSsa).with_deps(&["a"]));
        graph.add_pass(PassSpec::required("c", IrLevel::Hlil).with_deps(&["b"]));

        let order = graph.topological_order().unwrap();
        let names: Vec<&str> = order.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn standard_specs_no_cycle() {
        let mut graph = DependencyGraph::new();
        for spec in standard_pass_specs() {
            graph.add_pass(spec);
        }
        // Should not panic or error.
        let _ = graph.topological_order().unwrap();
    }

    #[test]
    fn checkpoint_resume() {
        let mut store = CheckpointStore::new();
        let id = PassId::new("test_pass");
        assert!(!store.is_complete(&id));
        store.mark_complete(&id);
        assert!(store.is_complete(&id));
        store.reset();
        assert!(!store.is_complete(&id));
    }

    #[test]
    fn pass_spec_builder() {
        let spec = PassSpec::optional("cfs", IrLevel::PseudoC)
            .with_deps(&["hlil_build"])
            .with_retries(2)
            .with_fallback("linear_emit")
            .with_timeout(5000);
        assert_eq!(spec.max_retries, 2);
        assert_eq!(spec.timeout_ms, 5000);
        assert!(!spec.is_required);
        assert_eq!(spec.depends_on.len(), 1);
        assert_eq!(spec.fallback.unwrap().0, "linear_emit");
    }

    #[test]
    fn pipeline_stage_ordering() {
        let stages = PipelineStage::all_ordered();
        for i in 1..stages.len() {
            assert!(stages[i - 1] < stages[i], "stages must be strictly ordered");
        }
    }

    #[test]
    fn dependency_graph_ready_passes() {
        let mut graph = DependencyGraph::new();
        graph.add_pass(PassSpec::required("a", IrLevel::Llil));
        graph.add_pass(PassSpec::required("b", IrLevel::MlilSsa).with_deps(&["a"]));

        let completed: HashSet<String> = HashSet::new();
        let ready = graph.ready_passes(&completed);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id.0, "a");

        let mut completed2: HashSet<String> = HashSet::new();
        completed2.insert("a".to_string());
        let ready2 = graph.ready_passes(&completed2);
        assert_eq!(ready2.len(), 1);
        assert_eq!(ready2[0].id.0, "b");
    }
}
