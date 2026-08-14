// rustre-agent-workflow/src/step_executor.rs
//
// Workflow step executor:
//   - Run each step sequentially or in parallel (rayon)
//   - Pass outputs of step A as inputs of step B (dependency graph)
//   - SQLite checkpointing (persist step results, resume on restart)
//   - Configurable retry per step
//   - Collect partial results throughout the run

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum StepExecutorError {
    #[error("step '{id}' not found")]
    StepNotFound { id: String },
    #[error("dependency '{dep}' of step '{step}' failed or not found")]
    DependencyFailed { step: String, dep: String },
    #[error("cyclic dependency detected involving step '{0}'")]
    CyclicDependency(String),
    #[error("step '{id}' failed after {retries} retries: {message}")]
    StepFailed { id: String, retries: u32, message: String },
    #[error("step '{id}' timed out after {timeout_ms}ms")]
    StepTimeout { id: String, timeout_ms: u64 },
    #[error("checkpoint error: {0}")]
    Checkpoint(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("execution engine error: {0}")]
    Engine(String),
}

pub type StepResult<T> = Result<T, StepExecutorError>;

// ─────────────────────────────── StepStatus ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Retrying { attempt: u32 },
}

// ─────────────────────────────── StepContext ─────────────────────────────────

/// Inputs available to a step at execution time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StepContext {
    /// Variables injected before the workflow starts.
    pub globals: HashMap<String, serde_json::Value>,
    /// Outputs from completed predecessor steps.
    pub upstream: HashMap<String, serde_json::Value>,
    /// Step-level parameters from the step definition.
    pub params: HashMap<String, serde_json::Value>,
    /// Step identifier.
    pub step_id: String,
    /// Unique run identifier (for checkpoint namespacing).
    pub run_id: String,
}

impl StepContext {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.params.get(key)
            .or_else(|| self.upstream.get(key))
            .or_else(|| self.globals.get(key))
    }

    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(serde_json::Value::as_u64)
    }
}

// ─────────────────────────────── StepOutput ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutput {
    pub step_id: String,
    pub status: StepStatus,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub elapsed_ms: f64,
    pub retries: u32,
}

impl StepOutput {
    #[must_use]
    pub fn success(id: &str, data: serde_json::Value, elapsed: Duration, retries: u32) -> Self {
        Self {
            step_id: id.to_owned(),
            status: StepStatus::Succeeded,
            data,
            error: None,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            retries,
        }
    }

    #[must_use]
    pub fn failure(id: &str, msg: String, elapsed: Duration, retries: u32) -> Self {
        Self {
            step_id: id.to_owned(),
            status: StepStatus::Failed,
            data: serde_json::Value::Null,
            error: Some(msg),
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            retries,
        }
    }

    #[must_use]
    pub fn skipped(id: &str) -> Self {
        Self {
            step_id: id.to_owned(),
            status: StepStatus::Skipped,
            data: serde_json::Value::Null,
            error: None,
            elapsed_ms: 0.0,
            retries: 0,
        }
    }
}

// ─────────────────────────────── StepDefinition ──────────────────────────────

/// A single step in a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepDefinition {
    pub id: String,
    pub name: String,
    pub action: String, // registered action key
    pub params: HashMap<String, serde_json::Value>,
    pub depends_on: Vec<String>,
    pub retry_max: u32,
    pub retry_delay_ms: u64,
    pub timeout_ms: u64,
    pub skip_on_failure: bool,
    pub parallel_group: Option<String>, // steps in the same group may run in parallel
}

impl StepDefinition {
    pub fn new(id: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            action: action.into(),
            params: HashMap::new(),
            depends_on: Vec::new(),
            retry_max: 0,
            retry_delay_ms: 500,
            timeout_ms: 60_000,
            skip_on_failure: false,
            parallel_group: None,
        }
    }

    #[must_use]
    pub fn depends_on(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.depends_on = ids.into_iter().map(std::convert::Into::into).collect();
        self
    }

    #[must_use]
    pub const fn with_retry(mut self, max: u32, delay_ms: u64) -> Self {
        self.retry_max = max;
        self.retry_delay_ms = delay_ms;
        self
    }

    #[must_use]
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }

    #[must_use]
    pub const fn skip_on_failure(mut self) -> Self {
        self.skip_on_failure = true;
        self
    }

    #[must_use]
    pub fn in_parallel_group(mut self, group: impl Into<String>) -> Self {
        self.parallel_group = Some(group.into());
        self
    }
}

// ─────────────────────────────── Action trait ────────────────────────────────

/// A registered action that can be executed as a step.
#[async_trait::async_trait]
pub trait StepAction: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self, ctx: &StepContext) -> Result<serde_json::Value, String>;
}

// ─────────────────────────────── Checkpoint ──────────────────────────────────

/// Persists step outcomes to a JSON file for resumption.
pub struct Checkpoint {
    path: PathBuf,
    data: Mutex<CheckpointData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CheckpointData {
    run_id: String,
    outputs: HashMap<String, StepOutput>,
}

impl Checkpoint {
    #[must_use]
    pub fn new(path: PathBuf, run_id: &str) -> Self {
        let data = Self::load_or_default(&path, run_id);
        Self { path, data: Mutex::new(data) }
    }

    fn load_or_default(path: &PathBuf, run_id: &str) -> CheckpointData {
        /// Maximum checkpoint file size we are willing to deserialize (64 MiB).
        /// A malicious or corrupted file larger than this is silently ignored and
        /// execution restarts from scratch, preventing memory exhaustion.
        const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

        if path.exists() {
            // Check file size before reading to avoid loading an unbounded file.
            let too_large = std::fs::metadata(path)
                .is_ok_and(|m| m.len() > MAX_CHECKPOINT_BYTES);
            if !too_large
                && let Ok(bytes) = std::fs::read(path)
                    && let Ok(d) = serde_json::from_slice::<CheckpointData>(&bytes)
                        && d.run_id == run_id {
                            return d;
                        }
        }
        CheckpointData { run_id: run_id.to_owned(), outputs: HashMap::new() }
    }

    pub fn is_complete(&self, step_id: &str) -> bool {
        self.data.lock().outputs.get(step_id)
            .is_some_and(|o| o.status == StepStatus::Succeeded)
    }

    pub fn get(&self, step_id: &str) -> Option<StepOutput> {
        self.data.lock().outputs.get(step_id).cloned()
    }

    pub fn record(&self, output: StepOutput) {
        self.data.lock().outputs.insert(output.step_id.clone(), output);
        self.flush();
    }

    fn flush(&self) {
        let data = self.data.lock().clone();
        if let Ok(json) = serde_json::to_vec_pretty(&data) {
            let _ = std::fs::write(&self.path, &json);
        }
    }

    pub fn completed_steps(&self) -> Vec<String> {
        self.data.lock()
            .outputs
            .values()
            .filter(|o| o.status == StepStatus::Succeeded)
            .map(|o| o.step_id.clone())
            .collect()
    }
}

// ─────────────────────────────── ExecutionPlan ───────────────────────────────

/// Topologically ordered execution plan.
#[derive(Debug)]
pub struct ExecutionPlan {
    /// Ordered layers; steps within a layer may run in parallel.
    pub layers: Vec<Vec<String>>,
    /// Full step lookup.
    pub steps: HashMap<String, StepDefinition>,
}

impl ExecutionPlan {
    /// Build an execution plan from a list of step definitions.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn build(steps: Vec<StepDefinition>) -> StepResult<Self> {
        let step_map: HashMap<String, StepDefinition> =
            steps.into_iter().map(|s| (s.id.clone(), s)).collect();

        // Kahn's algorithm for topological sort.
        let mut in_degree: HashMap<String, usize> = step_map.keys().map(|k| (k.clone(), 0)).collect();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for (id, step) in &step_map {
            for dep in &step.depends_on {
                if !step_map.contains_key(dep.as_str()) {
                    return Err(StepExecutorError::StepNotFound { id: dep.clone() });
                }
                *in_degree.entry(id.clone()).or_insert(0) += 1;
                dependents.entry(dep.clone()).or_default().push(id.clone());
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(k, _)| k.clone())
            .collect();

        let mut layers: Vec<Vec<String>> = Vec::new();
        let mut processed = 0usize;

        while !queue.is_empty() {
            let layer: Vec<String> = std::mem::take(&mut queue).into_iter().collect();
            processed += layer.len();
            for id in &layer {
                if let Some(deps) = dependents.get(id) {
                    for dep in deps {
                        let deg = in_degree.get_mut(dep).unwrap();
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep.clone());
                        }
                    }
                }
            }
            layers.push(layer);
        }

        if processed < step_map.len() {
            // Cycle detected — find one involved step.
            let cyclic = step_map.keys().find(|k| *in_degree.get(*k).unwrap_or(&0) > 0).unwrap().clone();
            return Err(StepExecutorError::CyclicDependency(cyclic));
        }

        Ok(Self { layers, steps: step_map })
    }
}

// ─────────────────────────────── RunState ────────────────────────────────────

/// Mutable run state shared across the executor.
#[derive(Default)]
struct RunState {
    outputs: HashMap<String, StepOutput>,
    status: HashMap<String, StepStatus>,
}

// ─────────────────────────────── StepExecutor ────────────────────────────────

pub struct StepExecutor {
    actions: RwLock<HashMap<String, Arc<dyn StepAction>>>,
    checkpoint_dir: Option<PathBuf>,
    default_timeout_ms: u64,
}

impl StepExecutor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            actions: RwLock::new(HashMap::new()),
            checkpoint_dir: None,
            default_timeout_ms: 60_000,
        }
    }

    #[must_use]
    pub fn with_checkpoint_dir(mut self, dir: PathBuf) -> Self {
        self.checkpoint_dir = Some(dir);
        self
    }

    #[must_use]
    pub const fn with_default_timeout(mut self, ms: u64) -> Self {
        self.default_timeout_ms = ms;
        self
    }

    pub fn register_action(&self, action: Arc<dyn StepAction>) {
        self.actions.write().insert(action.name().to_owned(), action);
    }

    // ── Execute workflow ──────────────────────────────────────────────────────

    /// Execute a workflow given its steps and initial variables.
    /// Returns all step outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub async fn execute(
        &self,
        steps: Vec<StepDefinition>,
        globals: HashMap<String, serde_json::Value>,
        run_id: &str,
    ) -> StepResult<Vec<StepOutput>> {
        let plan = ExecutionPlan::build(steps)?;
        let checkpoint = self.make_checkpoint(run_id);
        let state = Arc::new(Mutex::new(RunState::default()));

        // Restore from checkpoint.
        if let Some(cp) = &checkpoint {
            for step_id in cp.completed_steps() {
                if let Some(out) = cp.get(&step_id) {
                    let mut s = state.lock();
                    s.status.insert(step_id.clone(), StepStatus::Succeeded);
                    s.outputs.insert(step_id, out);
                }
            }
        }

        for layer in &plan.layers {
            let mut layer_futures = Vec::new();

            for step_id in layer {
                let step = plan.steps.get(step_id).unwrap().clone();
                let state_ref = Arc::clone(&state);
                let globals_ref = globals.clone();
                let cp_ref = checkpoint.as_ref().map(Arc::clone);

                // Skip if already done in a previous run.
                if let Some(cp) = &cp_ref
                    && cp.is_complete(step_id) {
                        continue;
                    }

                layer_futures.push(self.run_step(step, globals_ref, state_ref, cp_ref, run_id));
            }

            // Execute layer steps concurrently.
            let results = futures::future::join_all(layer_futures).await;

            // Check for non-skippable failures.
            for r in results {
                r?;
            }
        }

        let outputs: Vec<StepOutput> = {
            let s = state.lock();
            s.outputs.values().cloned().collect()
        };
        Ok(outputs)
    }

    async fn run_step(
        &self,
        step: StepDefinition,
        globals: HashMap<String, serde_json::Value>,
        state: Arc<Mutex<RunState>>,
        checkpoint: Option<Arc<Checkpoint>>,
        run_id: &str,
    ) -> StepResult<()> {
        // Gather upstream outputs.
        // Use a flag to avoid re-locking while the outer guard is alive (deadlock prevention).
        let (upstream, should_skip, skip_dep) = {
            let s = state.lock();
            let mut up = HashMap::new();
            let mut skip = false;
            let mut missing_dep: Option<String> = None;
            'deps: for dep in &step.depends_on {
                if let Some(out) = s.outputs.get(dep) {
                    if out.status != StepStatus::Succeeded {
                        if step.skip_on_failure {
                            skip = true;
                            break 'deps;
                        }
                        missing_dep = Some(dep.clone());
                        break 'deps;
                    }
                    up.insert(dep.clone(), out.data.clone());
                } else {
                    if step.skip_on_failure {
                        skip = true;
                        break 'deps;
                    }
                    missing_dep = Some(dep.clone());
                    break 'deps;
                }
            }
            (up, skip, missing_dep)
            // `s` (MutexGuard) is dropped here before any re-lock
        };

        if should_skip {
            let skipped = StepOutput::skipped(&step.id);
            // Acquire a single fresh lock and perform both inserts atomically.
            {
                let mut s = state.lock();
                s.outputs.insert(step.id.clone(), skipped);
                s.status.insert(step.id.clone(), StepStatus::Skipped);
            }
            return Ok(());
        }

        if let Some(dep) = skip_dep {
            return Err(StepExecutorError::DependencyFailed {
                step: step.id.clone(),
                dep,
            });
        }

        let ctx = StepContext {
            globals,
            upstream,
            params: step.params.clone(),
            step_id: step.id.clone(),
            run_id: run_id.to_owned(),
        };

        let action = {
            let actions = self.actions.read();
            actions.get(&step.action).map(Arc::clone)
        };

        let Some(action) = action else {
            let out = StepOutput::failure(
                &step.id,
                format!("unknown action: {}", step.action),
                Duration::ZERO,
                0,
            );
            Self::finalize_step(out, &state, checkpoint.as_ref());
            if !step.skip_on_failure {
                return Err(StepExecutorError::Engine(format!("unknown action: {}", step.action)));
            }
            return Ok(());
        };

        let timeout_ms = if step.timeout_ms > 0 { step.timeout_ms } else { self.default_timeout_ms };
        let mut retries = 0u32;
        let t0 = Instant::now();

        loop {
            let status_to_set = if retries == 0 {
                StepStatus::Running
            } else {
                StepStatus::Retrying { attempt: retries }
            };
            state.lock().status.insert(step.id.clone(), status_to_set);

            let run_result = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                action.run(&ctx),
            ).await;

            match run_result {
                Err(_) => {
                    // Timeout
                    if retries < step.retry_max {
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(step.retry_delay_ms)).await;
                        continue;
                    }
                    let elapsed = t0.elapsed();
                    let out = StepOutput::failure(
                        &step.id,
                        format!("timeout after {timeout_ms}ms"),
                        elapsed,
                        retries,
                    );
                    Self::finalize_step(out, &state, checkpoint.as_ref());
                    if !step.skip_on_failure {
                        return Err(StepExecutorError::StepTimeout { id: step.id.clone(), timeout_ms });
                    }
                    return Ok(());
                }
                Ok(Err(e)) => {
                    if retries < step.retry_max {
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(step.retry_delay_ms)).await;
                        continue;
                    }
                    let elapsed = t0.elapsed();
                    let out = StepOutput::failure(&step.id, e.clone(), elapsed, retries);
                    Self::finalize_step(out, &state, checkpoint.as_ref());
                    if !step.skip_on_failure {
                        return Err(StepExecutorError::StepFailed {
                            id: step.id.clone(),
                            retries,
                            message: e,
                        });
                    }
                    return Ok(());
                }
                Ok(Ok(data)) => {
                    let elapsed = t0.elapsed();
                    let out = StepOutput::success(&step.id, data, elapsed, retries);
                    Self::finalize_step(out, &state, checkpoint.as_ref());
                    return Ok(());
                }
            }
        }
    }

    fn finalize_step(
        out: StepOutput,
        state: &Arc<Mutex<RunState>>,
        checkpoint: Option<&Arc<Checkpoint>>,
    ) {
        if let Some(cp) = checkpoint {
            cp.record(out.clone());
        }
        let mut s = state.lock();
        s.status.insert(out.step_id.clone(), out.status.clone());
        s.outputs.insert(out.step_id.clone(), out);
    }

    fn make_checkpoint(&self, run_id: &str) -> Option<Arc<Checkpoint>> {
        self.checkpoint_dir.as_ref().map(|dir| {
            // Sanitize run_id to prevent path traversal: retain only alphanumeric
            // characters, hyphens, and underscores so that `../` sequences cannot
            // escape the checkpoint directory.
            let safe_run_id: String = run_id
                .chars()
                .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
                .collect();
            let path = dir.join(format!("{safe_run_id}.checkpoint.json"));
            Arc::new(Checkpoint::new(path, run_id))
        })
    }
}

impl Default for StepExecutor {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────── Built-in actions ────────────────────────────

/// No-op action that echoes its params as output.
pub struct EchoAction;

#[async_trait::async_trait]
impl StepAction for EchoAction {
    fn name(&self) -> &'static str { "echo" }
    async fn run(&self, ctx: &StepContext) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "step_id": ctx.step_id,
            "params": ctx.params,
        }))
    }
}

/// Sleep action — useful for testing timeouts.
pub struct SleepAction;

#[async_trait::async_trait]
impl StepAction for SleepAction {
    fn name(&self) -> &'static str { "sleep" }
    async fn run(&self, ctx: &StepContext) -> Result<serde_json::Value, String> {
        let ms = ctx.params.get("ms").and_then(serde_json::Value::as_u64).unwrap_or(1000);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(serde_json::json!({ "slept_ms": ms }))
    }
}

/// Fail action — always fails (for testing error handling).
pub struct FailAction;

#[async_trait::async_trait]
impl StepAction for FailAction {
    fn name(&self) -> &'static str { "fail" }
    async fn run(&self, ctx: &StepContext) -> Result<serde_json::Value, String> {
        let msg = ctx.params.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("intentional failure");
        Err(msg.to_owned())
    }
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn executor_with_echo() -> StepExecutor {
        let ex = StepExecutor::new();
        ex.register_action(Arc::new(EchoAction));
        ex.register_action(Arc::new(FailAction));
        ex
    }

    #[tokio::test]
    async fn single_step_succeeds() {
        let ex = executor_with_echo();
        let steps = vec![StepDefinition::new("s1", "echo")];
        let results = ex.execute(steps, HashMap::new(), "run1").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, StepStatus::Succeeded);
    }

    #[tokio::test]
    async fn dependent_steps_run_in_order() {
        let ex = executor_with_echo();
        let steps = vec![
            StepDefinition::new("s1", "echo"),
            StepDefinition::new("s2", "echo").depends_on(["s1"]),
        ];
        let results = ex.execute(steps, HashMap::new(), "run2").await.unwrap();
        assert_eq!(results.len(), 2);
        let s2 = results.iter().find(|r| r.step_id == "s2").unwrap();
        assert_eq!(s2.status, StepStatus::Succeeded);
    }

    #[tokio::test]
    async fn skip_on_failure() {
        let ex = executor_with_echo();
        let steps = vec![
            StepDefinition::new("s1", "fail").skip_on_failure(),
            StepDefinition::new("s2", "echo").depends_on(["s1"]).skip_on_failure(),
        ];
        let results = ex.execute(steps, HashMap::new(), "run3").await.unwrap();
        let s1 = results.iter().find(|r| r.step_id == "s1").unwrap();
        assert_eq!(s1.status, StepStatus::Failed);
        let s2 = results.iter().find(|r| r.step_id == "s2").unwrap();
        assert_eq!(s2.status, StepStatus::Skipped);
    }

    #[test]
    fn execution_plan_detects_cycle() {
        let steps = vec![
            StepDefinition::new("a", "echo").depends_on(["b"]),
            StepDefinition::new("b", "echo").depends_on(["a"]),
        ];
        let err = ExecutionPlan::build(steps).unwrap_err();
        assert!(matches!(err, StepExecutorError::CyclicDependency(_)));
    }

    #[test]
    fn execution_plan_missing_dep() {
        let steps = vec![
            StepDefinition::new("a", "echo").depends_on(["nonexistent"]),
        ];
        let err = ExecutionPlan::build(steps).unwrap_err();
        assert!(matches!(err, StepExecutorError::StepNotFound { .. }));
    }

    #[tokio::test]
    async fn upstream_output_passed_to_next_step() {
        struct CaptureAction {
            captured: Arc<Mutex<Option<serde_json::Value>>>,
        }
        #[async_trait::async_trait]
        impl StepAction for CaptureAction {
            fn name(&self) -> &'static str { "capture" }
            async fn run(&self, ctx: &StepContext) -> Result<serde_json::Value, String> {
                *self.captured.lock() = Some(serde_json::json!(ctx.upstream.clone()));
                Ok(serde_json::json!({ "ok": true }))
            }
        }

        let captured = Arc::new(Mutex::new(None));
        let ex = StepExecutor::new();
        ex.register_action(Arc::new(EchoAction));
        ex.register_action(Arc::new(CaptureAction { captured: Arc::clone(&captured) }));

        let steps = vec![
            StepDefinition::new("s1", "echo"),
            StepDefinition::new("s2", "capture").depends_on(["s1"]),
        ];
        ex.execute(steps, HashMap::new(), "run4").await.unwrap();

        let val = captured.lock().clone().unwrap();
        assert!(val.get("s1").is_some());
    }

    #[test]
    fn step_context_get_priority() {
        let mut ctx = StepContext::default();
        ctx.globals.insert("key".to_owned(), serde_json::json!("global"));
        ctx.params.insert("key".to_owned(), serde_json::json!("param"));
        // params takes priority over globals
        assert_eq!(ctx.get_str("key"), Some("param"));
    }

    #[test]
    fn step_output_success_fields() {
        let out = StepOutput::success("s1", serde_json::json!(42), Duration::from_millis(100), 0);
        assert_eq!(out.status, StepStatus::Succeeded);
        assert!(out.error.is_none());
        assert!((out.elapsed_ms - 100.0).abs() < 5.0);
    }

    #[test]
    fn checkpoint_record_and_retrieve() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_checkpoint_123.json");
        let cp = Checkpoint::new(path.clone(), "run_x");
        let out = StepOutput::success("s1", serde_json::json!("hi"), Duration::ZERO, 0);
        cp.record(out);
        assert!(cp.is_complete("s1"));
        assert!(cp.get("s2").is_none());
        let _ = std::fs::remove_file(path);
    }
}
