//! Complete workflow execution engine for `RustRE` agents.
//!
//! Provides [`WorkflowExecutorFull`] as the root dispatcher, with
//! [`StepExecutor`], [`BranchExecutor`], [`LoopExecutor`],
//! [`ParallelExecutor`], and [`ErrorHandler`].


use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

pub use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("step '{0}' not found")]
    StepNotFound(String),

    #[error("step '{step}' failed: {message}")]
    StepFailed { step: String, message: String },

    #[error("branch condition '{0}' could not be evaluated")]
    BranchConditionError(String),

    #[error("loop exceeded max iterations {0}")]
    LoopMaxIterations(u32),

    #[error("parallel task '{0}' failed: {1}")]
    ParallelTaskFailed(String, String),

    #[error("workflow cancelled")]
    Cancelled,

    #[error("max retries {0} exceeded for step '{1}'")]
    RetriesExceeded(u32, String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("timeout after {ms}ms")]
    Timeout { ms: u64 },
}

pub type ExecResult<T> = std::result::Result<T, ExecutorError>;

// ── ExecutionContext ──────────────────────────────────────────────────────────

/// Shared execution state passed to all steps.
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    pub variables: HashMap<String, serde_json::Value>,
    pub step_outputs: HashMap<String, serde_json::Value>,
    pub iteration: u32,
    pub cancelled: bool,
}

impl ExecutionContext {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.variables.insert(key.into(), value);
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.variables.get(key)
    }

    pub fn record_output(&mut self, step_id: impl Into<String>, output: serde_json::Value) {
        self.step_outputs.insert(step_id.into(), output);
    }

    pub const fn cancel(&mut self) {
        self.cancelled = true;
    }

    #[must_use] 
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

// ── StepStatus ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Succeeded => write!(f, "succeeded"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ── StepDef ───────────────────────────────────────────────────────────────────

/// Definition of a single workflow step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepDef {
    pub id: String,
    pub name: String,
    pub kind: StepKind,
    pub max_retries: u32,
    pub timeout_ms: Option<u64>,
    pub on_failure: FailureAction,
    /// Condition expression (JSON path / simple key=value).
    pub condition: Option<String>,
    /// Payload / parameters for the step.
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    Task,
    Branch,
    Loop,
    Parallel,
    Delay,
    NoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureAction {
    Abort,
    Continue,
    Retry,
}

impl StepDef {
    pub fn task(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind: StepKind::Task,
            max_retries: 0,
            timeout_ms: None,
            on_failure: FailureAction::Abort,
            condition: None,
            params: HashMap::new(),
        }
    }

    #[must_use] 
    pub const fn with_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self.on_failure = FailureAction::Retry;
        self
    }

    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }
}

// ── StepResult ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StepResult {
    pub step_id: String,
    pub status: StepStatus,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub retries: u32,
    pub duration_ms: u64,
}

impl StepResult {
    pub fn success(
        step_id: impl Into<String>,
        output: serde_json::Value,
        duration_ms: u64,
    ) -> Self {
        Self {
            step_id: step_id.into(),
            status: StepStatus::Succeeded,
            output,
            error: None,
            retries: 0,
            duration_ms,
        }
    }

    pub fn failure(step_id: impl Into<String>, error: impl Into<String>, retries: u32) -> Self {
        Self {
            step_id: step_id.into(),
            status: StepStatus::Failed,
            output: serde_json::Value::Null,
            error: Some(error.into()),
            retries,
            duration_ms: 0,
        }
    }

    pub fn skipped(step_id: impl Into<String>) -> Self {
        Self {
            step_id: step_id.into(),
            status: StepStatus::Skipped,
            output: serde_json::Value::Null,
            error: None,
            retries: 0,
            duration_ms: 0,
        }
    }
}

// ── ErrorHandler ─────────────────────────────────────────────────────────────

/// Centralized error handling and recovery logic.
pub struct ErrorHandler {
    pub default_action: FailureAction,
    pub error_log: Mutex<Vec<ErrorRecord>>,
}

#[derive(Debug, Clone)]
pub struct ErrorRecord {
    pub step_id: String,
    pub error: String,
    pub retry_count: u32,
    pub resolved: bool,
}

impl ErrorHandler {
    #[must_use] 
    pub const fn new(default_action: FailureAction) -> Self {
        Self {
            default_action,
            error_log: Mutex::new(Vec::new()),
        }
    }

    pub fn handle(&self, step_id: &str, error: &ExecutorError, retry_count: u32) -> FailureAction {
        self.error_log.lock().push(ErrorRecord {
            step_id: step_id.to_owned(),
            error: error.to_string(),
            retry_count,
            resolved: false,
        });
        self.default_action
    }

    pub fn mark_resolved(&self, step_id: &str) {
        let mut log = self.error_log.lock();
        if let Some(rec) = log.iter_mut().rfind(|r| r.step_id == step_id) {
            rec.resolved = true;
        }
    }

    pub fn error_log(&self) -> Vec<ErrorRecord> {
        self.error_log.lock().clone()
    }

    pub fn error_count(&self) -> usize {
        self.error_log.lock().len()
    }
}

// ── StepExecutor ─────────────────────────────────────────────────────────────

/// Executes a single task step, with retry support.
pub struct StepExecutor {
    pub error_handler: Arc<ErrorHandler>,
}

impl StepExecutor {
    pub const fn new(error_handler: Arc<ErrorHandler>) -> Self {
        Self { error_handler }
    }

    /// Execute a task step. The actual work is provided by the `runner` closure.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn execute<F>(
        &self,
        step: &StepDef,
        ctx: &mut ExecutionContext,
        runner: F,
    ) -> ExecResult<StepResult>
    where
        F: Fn(&StepDef, &ExecutionContext) -> ExecResult<serde_json::Value>,
    {
        if ctx.is_cancelled() {
            return Ok(StepResult::skipped(&step.id));
        }

        // Evaluate condition.
        if let Some(cond) = &step.condition
            && !Self::eval_condition(cond, ctx) {
                return Ok(StepResult::skipped(&step.id));
            }

        let start = Instant::now();
        let mut last_error = None;

        // Use a checked upper bound so u32::MAX in max_retries cannot make the
        // range wrap to 0 iterations (inclusive 0..=u32::MAX overflows in Rust).
        let retry_limit = step.max_retries.saturating_add(1); // total attempts
        for attempt in 0..retry_limit {
            match runner(step, ctx) {
                Ok(output) => {
                    let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    ctx.record_output(&step.id, output.clone());
                    return Ok(StepResult::success(&step.id, output, ms));
                }
                Err(e) => {
                    last_error = Some(e.clone());
                    let action = self.error_handler.handle(&step.id, &e, attempt);
                    match action {
                        FailureAction::Abort => {
                            return Err(ExecutorError::StepFailed {
                                step: step.id.clone(),
                                message: e.to_string(),
                            });
                        }
                        FailureAction::Continue => {
                            return Ok(StepResult::failure(&step.id, e.to_string(), attempt));
                        }
                        FailureAction::Retry => {}
                    }
                }
            }
        }

        // All attempts exhausted without success.
        let _ = last_error; // consumed for documentation; caller sees RetriesExceeded
        Err(ExecutorError::RetriesExceeded(
            step.max_retries,
            step.id.clone(),
        ))
    }

    fn eval_condition(cond: &str, ctx: &ExecutionContext) -> bool {
        // Simple key=value evaluation.
        if let Some((k, v)) = cond.split_once('=') {
            ctx.get(k.trim())
                .and_then(|val| val.as_str())
                .is_some_and(|s| s == v.trim())
        } else {
            // Treat as boolean variable lookup.
            ctx.get(cond.trim())
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        }
    }
}

// ── BranchExecutor ────────────────────────────────────────────────────────────

/// Evaluates conditions and selects the next branch.
pub struct BranchExecutor;

/// A branch definition: condition + step IDs to run if true/false.
#[derive(Debug, Clone)]
pub struct BranchDef {
    pub condition: String,
    pub true_steps: Vec<String>,
    pub false_steps: Vec<String>,
}

impl BranchDef {
    pub fn new(
        condition: impl Into<String>,
        true_steps: Vec<String>,
        false_steps: Vec<String>,
    ) -> Self {
        Self {
            condition: condition.into(),
            true_steps,
            false_steps,
        }
    }
}

impl BranchExecutor {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate `branch.condition` against `ctx`, return the IDs of steps to execute.
    #[must_use] 
    pub fn select(&self, branch: &BranchDef, ctx: &ExecutionContext) -> Vec<String> {
        let result = Self::eval(branch, ctx);
        if result {
            branch.true_steps.clone()
        } else {
            branch.false_steps.clone()
        }
    }

    fn eval(branch: &BranchDef, ctx: &ExecutionContext) -> bool {
        let cond = &branch.condition;
        if let Some((k, v)) = cond.split_once('=') {
            ctx.get(k.trim())
                .and_then(|val| val.as_str())
                .is_some_and(|s| s == v.trim())
        } else if let Some((k, v)) = cond.split_once('>') {
            let lhs = ctx.get(k.trim()).and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let rhs: f64 = v.trim().parse().unwrap_or(0.0);
            lhs > rhs
        } else {
            ctx.get(cond.trim())
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        }
    }
}

impl Default for BranchExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── LoopExecutor ─────────────────────────────────────────────────────────────

/// Executes a sequence of steps in a loop until a condition is false or max
/// iterations is reached.
pub struct LoopExecutor {
    pub max_iterations: u32,
}

#[derive(Debug, Clone)]
pub struct LoopDef {
    pub condition: String,
    pub body_step_ids: Vec<String>,
    pub max_iterations: Option<u32>,
}

impl LoopExecutor {
    #[must_use] 
    pub const fn new(max_iterations: u32) -> Self {
        Self { max_iterations }
    }

    /// Run `body` in a loop until `condition` is false or the iteration limit is hit.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run<F>(
        &self,
        loop_def: &LoopDef,
        ctx: &mut ExecutionContext,
        mut body: F,
    ) -> ExecResult<u32>
    where
        F: FnMut(&mut ExecutionContext) -> ExecResult<()>,
    {
        let limit = loop_def.max_iterations.unwrap_or(self.max_iterations);
        let mut iterations = 0u32;

        while Self::eval_condition(&loop_def.condition, ctx) {
            if iterations >= limit {
                return Err(ExecutorError::LoopMaxIterations(limit));
            }
            ctx.iteration = iterations;
            body(ctx)?;
            iterations += 1;

            if ctx.is_cancelled() {
                break;
            }
        }
        Ok(iterations)
    }

    fn eval_condition(cond: &str, ctx: &ExecutionContext) -> bool {
        ctx.get(cond.trim())
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

// ── ParallelExecutor ──────────────────────────────────────────────────────────

/// Runs multiple steps concurrently (single-threaded simulation: sequential
/// execution with merged results, mimicking the parallel contract).
pub struct ParallelExecutor;

#[derive(Debug, Clone)]
pub struct ParallelTask {
    pub id: String,
    pub step_def: StepDef,
}

impl ParallelTask {
    pub fn new(id: impl Into<String>, step: StepDef) -> Self {
        Self {
            id: id.into(),
            step_def: step,
        }
    }
}

impl ParallelExecutor {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Execute all tasks, collecting results. Continues on individual failures
    /// (to gather all results).
    pub fn run_all<F>(
        &self,
        tasks: &[ParallelTask],
        ctx: &ExecutionContext,
        runner: F,
    ) -> Vec<(String, ExecResult<serde_json::Value>)>
    where
        F: Fn(&ParallelTask, &ExecutionContext) -> ExecResult<serde_json::Value>,
    {
        tasks
            .iter()
            .map(|task| {
                let result = runner(task, ctx);
                (task.id.clone(), result)
            })
            .collect()
    }

    /// Run all tasks, returning Err if any failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run_all_or_fail<F>(
        &self,
        tasks: &[ParallelTask],
        ctx: &ExecutionContext,
        runner: F,
    ) -> ExecResult<Vec<serde_json::Value>>
    where
        F: Fn(&ParallelTask, &ExecutionContext) -> ExecResult<serde_json::Value>,
    {
        let results = self.run_all(tasks, ctx, runner);
        let mut outputs = Vec::new();
        for (id, result) in results {
            match result {
                Ok(v) => outputs.push(v),
                Err(e) => return Err(ExecutorError::ParallelTaskFailed(id, e.to_string())),
            }
        }
        Ok(outputs)
    }
}

impl Default for ParallelExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── WorkflowExecutorFull ──────────────────────────────────────────────────────

/// Complete workflow execution engine.
pub struct WorkflowExecutorFull {
    pub step_executor: Arc<StepExecutor>,
    pub branch_executor: BranchExecutor,
    pub loop_executor: LoopExecutor,
    pub parallel_executor: ParallelExecutor,
    pub error_handler: Arc<ErrorHandler>,
    results: Mutex<Vec<StepResult>>,
}

impl WorkflowExecutorFull {
    #[must_use] 
    pub fn new() -> Self {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        Self {
            step_executor: Arc::new(StepExecutor::new(Arc::clone(&eh))),
            branch_executor: BranchExecutor::new(),
            loop_executor: LoopExecutor::new(1000),
            parallel_executor: ParallelExecutor::new(),
            error_handler: eh,
            results: Mutex::new(Vec::new()),
        }
    }

    /// Execute a sequential list of steps.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run_sequence<F>(
        &self,
        steps: &[StepDef],
        ctx: &mut ExecutionContext,
        runner: F,
    ) -> ExecResult<Vec<StepResult>>
    where
        F: Fn(&StepDef, &ExecutionContext) -> ExecResult<serde_json::Value>,
    {
        let mut step_results = Vec::new();
        for step in steps {
            if ctx.is_cancelled() {
                step_results.push(StepResult::skipped(&step.id));
                continue;
            }
            let result = self.step_executor.execute(step, ctx, &runner)?;
            step_results.push(result.clone());
            self.results.lock().push(result);
        }
        Ok(step_results)
    }

    /// Execute a branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run_branch(
        &self,
        branch: &BranchDef,
        steps: &HashMap<String, StepDef>,
        ctx: &mut ExecutionContext,
        runner: &dyn Fn(&StepDef, &ExecutionContext) -> ExecResult<serde_json::Value>,
    ) -> ExecResult<Vec<StepResult>> {
        let selected = self.branch_executor.select(branch, ctx);
        let mut results = Vec::new();
        for id in &selected {
            let step = steps
                .get(id)
                .ok_or_else(|| ExecutorError::StepNotFound(id.clone()))?;
            let result = self.step_executor.execute(step, ctx, runner)?;
            results.push(result);
        }
        Ok(results)
    }

    /// All results collected so far.
    pub fn all_results(&self) -> Vec<StepResult> {
        self.results.lock().clone()
    }

    pub fn success_count(&self) -> usize {
        self.results
            .lock()
            .iter()
            .filter(|r| r.status == StepStatus::Succeeded)
            .count()
    }

    pub fn failure_count(&self) -> usize {
        self.results
            .lock()
            .iter()
            .filter(|r| r.status == StepStatus::Failed)
            .count()
    }

    pub fn clear_results(&self) {
        self.results.lock().clear();
    }
}

impl Default for WorkflowExecutorFull {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_runner(_step: &StepDef, _ctx: &ExecutionContext) -> ExecResult<serde_json::Value> {
        Ok(serde_json::json!({ "status": "ok" }))
    }

    fn fail_runner(_step: &StepDef, _ctx: &ExecutionContext) -> ExecResult<serde_json::Value> {
        Err(ExecutorError::StepFailed {
            step: "test".into(),
            message: "intentional".into(),
        })
    }

    fn executor() -> WorkflowExecutorFull {
        WorkflowExecutorFull::new()
    }

    // ── ExecutionContext ──────────────────────────────────────────────────────

    #[test]
    fn test_context_set_get() {
        let mut ctx = ExecutionContext::new();
        ctx.set("key", serde_json::json!("value"));
        assert_eq!(ctx.get("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn test_context_cancel() {
        let mut ctx = ExecutionContext::new();
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn test_context_record_output() {
        let mut ctx = ExecutionContext::new();
        ctx.record_output("step1", serde_json::json!(42));
        assert_eq!(ctx.step_outputs["step1"], serde_json::json!(42));
    }

    // ── StepDef ───────────────────────────────────────────────────────────────

    #[test]
    fn test_step_def_builder() {
        let step = StepDef::task("s1", "My Step")
            .with_retries(3)
            .with_condition("flag=true")
            .with_param("x", serde_json::json!(1));
        assert_eq!(step.id, "s1");
        assert_eq!(step.max_retries, 3);
        assert!(step.condition.is_some());
    }

    // ── StepExecutor ─────────────────────────────────────────────────────────

    #[test]
    fn test_step_executor_success() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test");
        let mut ctx = ExecutionContext::new();
        let result = se.execute(&step, &mut ctx, ok_runner).unwrap();
        assert_eq!(result.status, StepStatus::Succeeded);
    }

    #[test]
    fn test_step_executor_fail_abort() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test");
        let mut ctx = ExecutionContext::new();
        let result = se.execute(&step, &mut ctx, fail_runner);
        assert!(result.is_err());
    }

    #[test]
    fn test_step_executor_fail_continue() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Continue));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test");
        let mut ctx = ExecutionContext::new();
        let result = se.execute(&step, &mut ctx, fail_runner).unwrap();
        assert_eq!(result.status, StepStatus::Failed);
    }

    #[test]
    fn test_step_executor_retry_then_fail() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Retry));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test").with_retries(2);
        let mut ctx = ExecutionContext::new();
        let result = se.execute(&step, &mut ctx, fail_runner);
        assert!(matches!(result, Err(ExecutorError::RetriesExceeded(2, _))));
    }

    #[test]
    fn test_step_executor_condition_skip() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test").with_condition("flag=true");
        let mut ctx = ExecutionContext::new();
        // flag is not set → condition false → skip
        let result = se.execute(&step, &mut ctx, fail_runner).unwrap();
        assert_eq!(result.status, StepStatus::Skipped);
    }

    #[test]
    fn test_step_executor_condition_run() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test").with_condition("flag=true");
        let mut ctx = ExecutionContext::new();
        ctx.set("flag", serde_json::json!("true"));
        let result = se.execute(&step, &mut ctx, ok_runner).unwrap();
        assert_eq!(result.status, StepStatus::Succeeded);
    }

    #[test]
    fn test_step_executor_cancelled_context_skips() {
        let eh = Arc::new(ErrorHandler::new(FailureAction::Abort));
        let se = StepExecutor::new(eh);
        let step = StepDef::task("s1", "test");
        let mut ctx = ExecutionContext::new();
        ctx.cancel();
        let result = se.execute(&step, &mut ctx, fail_runner).unwrap();
        assert_eq!(result.status, StepStatus::Skipped);
    }

    // ── BranchExecutor ────────────────────────────────────────────────────────

    #[test]
    fn test_branch_true() {
        let be = BranchExecutor::new();
        let branch = BranchDef::new("flag=yes", vec!["step_a".into()], vec!["step_b".into()]);
        let mut ctx = ExecutionContext::new();
        ctx.set("flag", serde_json::json!("yes"));
        let selected = be.select(&branch, &ctx);
        assert_eq!(selected, vec!["step_a"]);
    }

    #[test]
    fn test_branch_false() {
        let be = BranchExecutor::new();
        let branch = BranchDef::new("flag=yes", vec!["step_a".into()], vec!["step_b".into()]);
        let ctx = ExecutionContext::new();
        let selected = be.select(&branch, &ctx);
        assert_eq!(selected, vec!["step_b"]);
    }

    #[test]
    fn test_branch_numeric_gt() {
        let be = BranchExecutor::new();
        let branch = BranchDef::new("score>50", vec!["high".into()], vec!["low".into()]);
        let mut ctx = ExecutionContext::new();
        ctx.set("score", serde_json::json!(75.0));
        let selected = be.select(&branch, &ctx);
        assert_eq!(selected, vec!["high"]);
    }

    // ── LoopExecutor ─────────────────────────────────────────────────────────

    #[test]
    fn test_loop_runs_until_false() {
        let le = LoopExecutor::new(100);
        let loop_def = LoopDef {
            condition: "running".into(),
            body_step_ids: vec![],
            max_iterations: Some(5),
        };
        let mut ctx = ExecutionContext::new();
        ctx.set("running", serde_json::json!(true));
        let mut count = 0u32;
        le.run(&loop_def, &mut ctx, |c| {
            count += 1;
            if count >= 3 {
                c.set("running", serde_json::json!(false));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_loop_max_iterations() {
        let le = LoopExecutor::new(3);
        let loop_def = LoopDef {
            condition: "running".into(),
            body_step_ids: vec![],
            max_iterations: Some(3),
        };
        let mut ctx = ExecutionContext::new();
        ctx.set("running", serde_json::json!(true));
        let result = le.run(&loop_def, &mut ctx, |_| Ok(()));
        assert!(matches!(result, Err(ExecutorError::LoopMaxIterations(3))));
    }

    #[test]
    fn test_loop_cancelled_stops() {
        let le = LoopExecutor::new(1000);
        let loop_def = LoopDef {
            condition: "running".into(),
            body_step_ids: vec![],
            max_iterations: None,
        };
        let mut ctx = ExecutionContext::new();
        ctx.set("running", serde_json::json!(true));
        let mut count = 0u32;
        le.run(&loop_def, &mut ctx, |c| {
            count += 1;
            if count >= 2 {
                c.cancel();
            }
            Ok(())
        })
        .unwrap();
        assert!(count <= 3);
    }

    // ── ParallelExecutor ──────────────────────────────────────────────────────

    #[test]
    fn test_parallel_all_succeed() {
        let pe = ParallelExecutor::new();
        let tasks = vec![
            ParallelTask::new("t1", StepDef::task("s1", "a")),
            ParallelTask::new("t2", StepDef::task("s2", "b")),
        ];
        let ctx = ExecutionContext::new();
        let results = pe.run_all(&tasks, &ctx, |_task, _ctx| Ok(serde_json::json!("done")));
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[test]
    fn test_parallel_one_fails() {
        let pe = ParallelExecutor::new();
        let tasks = vec![
            ParallelTask::new("t1", StepDef::task("s1", "a")),
            ParallelTask::new("t2", StepDef::task("s2", "b")),
        ];
        let ctx = ExecutionContext::new();
        let results = pe.run_all(&tasks, &ctx, |task, _ctx| {
            if task.id == "t2" {
                Err(ExecutorError::StepFailed {
                    step: "s2".into(),
                    message: "fail".into(),
                })
            } else {
                Ok(serde_json::json!("ok"))
            }
        });
        
        assert_eq!(results.iter().filter(|(_, r)| r.is_err()).count(), 1);
    }

    #[test]
    fn test_parallel_run_all_or_fail() {
        let pe = ParallelExecutor::new();
        let tasks = vec![ParallelTask::new("t1", StepDef::task("s1", "a"))];
        let ctx = ExecutionContext::new();
        let outputs = pe.run_all_or_fail(&tasks, &ctx, |_, _| {
            Err(ExecutorError::StepFailed {
                step: "s1".into(),
                message: "boom".into(),
            })
        });
        assert!(matches!(
            outputs,
            Err(ExecutorError::ParallelTaskFailed(_, _))
        ));
    }

    // ── ErrorHandler ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_handler_log() {
        let eh = ErrorHandler::new(FailureAction::Continue);
        let err = ExecutorError::StepFailed {
            step: "s1".into(),
            message: "oops".into(),
        };
        eh.handle("s1", &err, 0);
        assert_eq!(eh.error_count(), 1);
    }

    #[test]
    fn test_error_handler_mark_resolved() {
        let eh = ErrorHandler::new(FailureAction::Continue);
        let err = ExecutorError::StepFailed {
            step: "s1".into(),
            message: "oops".into(),
        };
        eh.handle("s1", &err, 0);
        eh.mark_resolved("s1");
        assert!(eh.error_log()[0].resolved);
    }

    // ── WorkflowExecutorFull ──────────────────────────────────────────────────

    #[test]
    fn test_run_sequence_all_succeed() {
        let ex = executor();
        let steps = vec![StepDef::task("s1", "a"), StepDef::task("s2", "b")];
        let mut ctx = ExecutionContext::new();
        let results = ex.run_sequence(&steps, &mut ctx, ok_runner).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(ex.success_count(), 2);
    }

    #[test]
    fn test_run_sequence_cancelled() {
        let ex = executor();
        let steps = vec![StepDef::task("s1", "a"), StepDef::task("s2", "b")];
        let mut ctx = ExecutionContext::new();
        ctx.cancel();
        let results = ex.run_sequence(&steps, &mut ctx, ok_runner).unwrap();
        assert!(results.iter().all(|r| r.status == StepStatus::Skipped));
    }

    #[test]
    fn test_run_branch_in_executor() {
        let ex = executor();
        let branch = BranchDef::new("go=yes", vec!["s1".into()], vec!["s2".into()]);
        let mut steps = HashMap::new();
        steps.insert("s1".to_string(), StepDef::task("s1", "branch_true"));
        steps.insert("s2".to_string(), StepDef::task("s2", "branch_false"));
        let mut ctx = ExecutionContext::new();
        ctx.set("go", serde_json::json!("yes"));
        let results = ex
            .run_branch(&branch, &steps, &mut ctx, &ok_runner)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].step_id, "s1");
    }

    #[test]
    fn test_clear_results() {
        let ex = executor();
        let steps = vec![StepDef::task("s1", "a")];
        let mut ctx = ExecutionContext::new();
        ex.run_sequence(&steps, &mut ctx, ok_runner).unwrap();
        assert!(ex.success_count() > 0);
        ex.clear_results();
        assert_eq!(ex.success_count(), 0);
    }

    #[test]
    fn test_step_status_display() {
        assert_eq!(StepStatus::Succeeded.to_string(), "succeeded");
        assert_eq!(StepStatus::Failed.to_string(), "failed");
        assert_eq!(StepStatus::Skipped.to_string(), "skipped");
    }

    #[test]
    fn test_step_result_constructors() {
        let ok = StepResult::success("s1", serde_json::json!(null), 10);
        assert_eq!(ok.status, StepStatus::Succeeded);
        let fail = StepResult::failure("s1", "boom", 2);
        assert_eq!(fail.retries, 2);
        let skip = StepResult::skipped("s1");
        assert_eq!(skip.status, StepStatus::Skipped);
    }

    #[test]
    fn test_context_default() {
        let ctx = ExecutionContext::new();
        assert!(!ctx.is_cancelled());
        assert_eq!(ctx.iteration, 0);
    }

    #[test]
    fn test_step_def_no_op_kind() {
        let step = StepDef {
            id: "noop".into(),
            name: "No Op".into(),
            kind: StepKind::NoOp,
            max_retries: 0,
            timeout_ms: None,
            on_failure: FailureAction::Continue,
            condition: None,
            params: HashMap::new(),
        };
        assert_eq!(step.kind, StepKind::NoOp);
    }

    #[test]
    fn test_executor_failure_count() {
        let ex = WorkflowExecutorFull::new();
        let steps = vec![StepDef::task("s1", "a")];
        let mut ctx = ExecutionContext::new();
        let _ = ex.run_sequence(&steps, &mut ctx, fail_runner);
        // Abort on first error, but failure_count from all_results.
        // all_results is empty since abort returns Err, not a result.
        assert_eq!(ex.failure_count(), 0); // nothing pushed on hard abort
    }

    #[test]
    fn test_branch_empty_true_steps() {
        let be = BranchExecutor::new();
        let branch = BranchDef::new("flag=yes", vec![], vec!["fallback".into()]);
        let mut ctx = ExecutionContext::new();
        ctx.set("flag", serde_json::json!("yes"));
        let selected = be.select(&branch, &ctx);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_branch_bool_condition() {
        let be = BranchExecutor::new();
        let branch = BranchDef::new("enabled", vec!["step_t".into()], vec!["step_f".into()]);
        let mut ctx = ExecutionContext::new();
        ctx.set("enabled", serde_json::json!(true));
        let selected = be.select(&branch, &ctx);
        assert_eq!(selected[0], "step_t");
    }

    #[test]
    fn test_loop_body_receives_iteration() {
        let le = LoopExecutor::new(100);
        let loop_def = LoopDef {
            condition: "go".into(),
            body_step_ids: vec![],
            max_iterations: Some(3),
        };
        let mut ctx = ExecutionContext::new();
        ctx.set("go", serde_json::json!(true));
        let mut max_iter = 0u32;
        le.run(&loop_def, &mut ctx, |c| {
            max_iter = c.iteration;
            if c.iteration >= 2 {
                c.set("go", serde_json::json!(false));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(max_iter, 2);
    }

    #[test]
    fn test_error_handler_default_action() {
        let eh = ErrorHandler::new(FailureAction::Continue);
        let err = ExecutorError::Cancelled;
        let action = eh.handle("step", &err, 0);
        assert_eq!(action, FailureAction::Continue);
    }

    #[test]
    fn test_parallel_empty_tasks() {
        let pe = ParallelExecutor::new();
        let ctx = ExecutionContext::new();
        let results = pe.run_all(&[], &ctx, |_, _| Ok(serde_json::json!(null)));
        assert!(results.is_empty());
    }

    #[test]
    fn test_step_def_with_timeout() {
        let step = StepDef {
            id: "s1".into(),
            name: "n".into(),
            kind: StepKind::Task,
            max_retries: 0,
            timeout_ms: Some(5000),
            on_failure: FailureAction::Abort,
            condition: None,
            params: HashMap::new(),
        };
        assert_eq!(step.timeout_ms, Some(5000));
    }

    #[test]
    fn test_executor_error_display() {
        let err = ExecutorError::LoopMaxIterations(10);
        assert!(err.to_string().contains("10"));
    }

    #[test]
    fn test_run_sequence_records_output_in_context() {
        let ex = executor();
        let steps = vec![StepDef::task("analyzer", "Analyze binary")];
        let mut ctx = ExecutionContext::new();
        ex.run_sequence(&steps, &mut ctx, ok_runner).unwrap();
        assert!(ctx.step_outputs.contains_key("analyzer"));
    }

    #[test]
    fn test_step_kind_variants() {
        assert_eq!(StepKind::Task, StepKind::Task);
        assert_ne!(StepKind::Branch, StepKind::Loop);
    }

    #[test]
    fn test_failure_action_variants() {
        assert_eq!(FailureAction::Abort, FailureAction::Abort);
        assert_ne!(FailureAction::Continue, FailureAction::Retry);
    }

    #[test]
    fn test_step_result_duration() {
        let ok = StepResult::success("s1", serde_json::json!(null), 150);
        assert_eq!(ok.duration_ms, 150);
    }

    #[test]
    fn test_executor_default() {
        let ex = WorkflowExecutorFull::default();
        assert_eq!(ex.success_count(), 0);
    }

    #[test]
    fn test_branch_executor_default() {
        let be = BranchExecutor;
        let branch = BranchDef::new("x=y", vec!["a".into()], vec!["b".into()]);
        let ctx = ExecutionContext::new();
        let selected = be.select(&branch, &ctx);
        assert_eq!(selected, vec!["b"]);
    }

    #[test]
    fn test_parallel_executor_default() {
        let pe = ParallelExecutor;
        let ctx = ExecutionContext::new();
        let results = pe.run_all(&[], &ctx, |_, _| Ok(serde_json::json!(null)));
        assert!(results.is_empty());
    }

    #[test]
    fn test_loop_runs_zero_iterations_if_condition_false() {
        let le = LoopExecutor::new(100);
        let loop_def = LoopDef {
            condition: "never_true".into(),
            body_step_ids: vec![],
            max_iterations: Some(100),
        };
        let mut ctx = ExecutionContext::new();
        // condition variable not set → false → 0 iterations
        let iterations = le.run(&loop_def, &mut ctx, |_| Ok(())).unwrap();
        assert_eq!(iterations, 0);
    }

    #[test]
    fn test_execution_context_get_missing() {
        let ctx = ExecutionContext::new();
        assert!(ctx.get("not_set").is_none());
    }
}
