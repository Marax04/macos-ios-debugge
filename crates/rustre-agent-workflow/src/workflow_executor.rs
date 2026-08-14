//! Workflow execution engine with YAML/JSON-defined steps, checkpointing,
//! scheduling, and conditional expression evaluation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
pub use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use rustre_agent::casts::{u64_to_f64, f64_to_u64 as f64_to_u64_saturating};

// ── WorkflowDefinition ────────────────────────────────────────────────────────

/// A complete workflow definition (parsed from YAML or JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub steps: Vec<WorkflowStep>,
    pub timeout_ms: Option<u64>,
    pub on_failure: FailurePolicy,
}

impl WorkflowDefinition {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: "1.0".to_string(),
            description: None,
            steps: Vec::new(),
            timeout_ms: None,
            on_failure: FailurePolicy::Abort,
        }
    }

    pub fn add_step(&mut self, step: WorkflowStep) {
        self.steps.push(step);
    }
}

// ── FailurePolicy ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailurePolicy {
    Abort,
    Continue,
    Retry { times: u32 },
}

// ── WorkflowStep ──────────────────────────────────────────────────────────────

/// One step in a workflow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Unique name for this step.
    pub name: String,
    /// Action to execute (e.g. "analyze", "export", "notify").
    pub action: String,
    /// Key–value inputs forwarded to the action.
    pub inputs: HashMap<String, serde_json::Value>,
    /// Output variable names produced by this action.
    pub outputs: Vec<String>,
    /// Optional conditional expression; if `false`, the step is skipped.
    pub condition: Option<String>,
    /// Retry configuration.
    pub retry: RetryPolicy,
    /// Step-level timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Whether failures in this step are treated as non-fatal.
    pub allow_failure: bool,
}

impl WorkflowStep {
    pub fn new(name: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action: action.into(),
            inputs: HashMap::new(),
            outputs: Vec::new(),
            condition: None,
            retry: RetryPolicy::default(),
            timeout_ms: None,
            allow_failure: false,
        }
    }

    #[must_use]
    pub fn with_input(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.inputs.insert(key.into(), value);
        self
    }

    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    #[must_use] 
    pub const fn with_retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }
}

// ── RetryPolicy ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub delay_ms: u64,
    pub backoff_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            delay_ms: 0,
            backoff_factor: 1.0,
        }
    }
}

impl RetryPolicy {
    #[must_use] 
    pub fn with_retries(n: u32) -> Self {
        Self {
            max_attempts: n,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        // Clamp the exponent to i32::MAX to avoid overflow in powi; the resulting
        // f64 will be astronomically large anyway and is capped below.
        let exp = i32::try_from(attempt).unwrap_or(i32::MAX).saturating_sub(1);
        let delay_f = u64_to_f64(self.delay_ms);
        let computed = delay_f * self.backoff_factor.powi(exp);
        // Guard against NaN / infinity before casting; cap at u64::MAX.
        if computed.is_nan() || computed < 0.0 {
            return 0;
        }
        if computed >= u64_to_f64(u64::MAX) {
            return u64::MAX;
        }
        f64_to_u64_saturating(computed)
    }
}

// ── StepResult ────────────────────────────────────────────────────────────────

/// Outcome of executing one workflow step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepOutcome {
    Success,
    Failure(String),
    Skipped,
}

/// Full result of a single step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepResult {
    pub step_name: String,
    pub outcome: StepOutcome,
    pub outputs: HashMap<String, serde_json::Value>,
    pub attempts: u32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl WorkflowStepResult {
    #[must_use] 
    pub fn success(
        name: &str,
        outputs: HashMap<String, serde_json::Value>,
        attempts: u32,
        ms: u64,
    ) -> Self {
        Self {
            step_name: name.to_string(),
            outcome: StepOutcome::Success,
            outputs,
            attempts,
            duration_ms: ms,
            error: None,
        }
    }

    pub fn failure(name: &str, err: impl Into<String>, attempts: u32, ms: u64) -> Self {
        let e = err.into();
        Self {
            step_name: name.to_string(),
            outcome: StepOutcome::Failure(e.clone()),
            outputs: HashMap::new(),
            attempts,
            duration_ms: ms,
            error: Some(e),
        }
    }

    #[must_use] 
    pub fn skipped(name: &str) -> Self {
        Self {
            step_name: name.to_string(),
            outcome: StepOutcome::Skipped,
            outputs: HashMap::new(),
            attempts: 0,
            duration_ms: 0,
            error: None,
        }
    }

    #[must_use] 
    pub fn succeeded(&self) -> bool {
        self.outcome == StepOutcome::Success
    }
    #[must_use] 
    pub const fn failed(&self) -> bool {
        matches!(self.outcome, StepOutcome::Failure(_))
    }
}

// ── WorkflowContext ───────────────────────────────────────────────────────────

/// Shared variable store across all steps in a workflow execution.
#[derive(Debug, Default, Clone)]
pub struct WorkflowContext {
    vars: HashMap<String, serde_json::Value>,
}

impl WorkflowContext {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.vars.insert(key.into(), value);
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.vars.get(key)
    }

    #[must_use] 
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.vars.get(key).and_then(|v| v.as_str())
    }

    #[must_use] 
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.vars.get(key).and_then(serde_json::Value::as_i64)
    }

    #[must_use] 
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.vars.get(key).and_then(serde_json::Value::as_bool)
    }

    #[must_use] 
    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    #[must_use] 
    pub const fn all_vars(&self) -> &HashMap<String, serde_json::Value> {
        &self.vars
    }

    pub fn merge(&mut self, other: &HashMap<String, serde_json::Value>) {
        for (k, v) in other {
            self.vars.insert(k.clone(), v.clone());
        }
    }
}

// ── ConditionalExpr ───────────────────────────────────────────────────────────

/// Evaluates simple conditional expressions against a [`WorkflowContext`].
///
/// Supported forms:
/// - `"true"` / `"false"`
/// - `"${VAR}"` — truthy if VAR is set and truthy
/// - `"${VAR} == VALUE"` — equality check
/// - `"${VAR} != VALUE"` — inequality check
/// - `"${VAR} > N"` — integer comparison
/// - `"${VAR} < N"` — integer comparison
/// - `"${VAR} >= N"` / `"${VAR} <= N"`
/// - `"not EXPR"` — logical not
pub struct ConditionalExpr;

impl ConditionalExpr {
    #[must_use] 
    pub fn evaluate(expr: &str, ctx: &WorkflowContext) -> bool {
        let expr = expr.trim();
        if expr.eq_ignore_ascii_case("true") {
            return true;
        }
        if expr.eq_ignore_ascii_case("false") {
            return false;
        }

        // "not EXPR"
        if let Some(rest) = expr.strip_prefix("not ") {
            return !Self::evaluate(rest.trim(), ctx);
        }

        // "${VAR} OP value"
        if let Some(after_dollar) = expr.strip_prefix("${")
            && let Some(close) = after_dollar.find('}') {
                let var_name = &after_dollar[..close];
                let rest = after_dollar[close + 1..].trim();
                let var_val = ctx.get(var_name);

                if rest.is_empty() {
                    // Just variable truthy check
                    return var_val.is_some_and(|v| {
                        !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false))
                    });
                }

                let (op, rhs) = Self::split_op(rest);
                return Self::compare_value(var_val, op, rhs, ctx);
            }

        // Plain boolean variable name
        if let Some(v) = ctx.get(expr) {
            return !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false));
        }

        false
    }

    fn split_op(s: &str) -> (&str, &str) {
        for op in &["==", "!=", ">=", "<=", ">", "<"] {
            if let Some(rest) = s.strip_prefix(op) {
                return (op, rest.trim());
            }
        }
        ("", s)
    }

    fn compare_value(
        var_val: Option<&serde_json::Value>,
        op: &str,
        rhs: &str,
        _ctx: &WorkflowContext,
    ) -> bool {
        match var_val {
            None => false,
            Some(v) => {
                let lhs_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => return false,
                };
                // Try numeric comparison first.
                if let (Ok(lhs_n), Ok(rhs_n)) = (lhs_str.parse::<f64>(), rhs.parse::<f64>()) {
                    return match op {
                        "==" => (lhs_n - rhs_n).abs() < f64::EPSILON,
                        "!=" => (lhs_n - rhs_n).abs() >= f64::EPSILON,
                        ">" => lhs_n > rhs_n,
                        "<" => lhs_n < rhs_n,
                        ">=" => lhs_n >= rhs_n,
                        "<=" => lhs_n <= rhs_n,
                        _ => false,
                    };
                }
                // String comparison
                match op {
                    "==" => lhs_str == rhs,
                    "!=" => lhs_str != rhs,
                    _ => false,
                }
            }
        }
    }
}

// ── CheckpointManager ────────────────────────────────────────────────────────

/// Saves and restores workflow execution state for resume-after-failure.
#[derive(Debug, Default)]
pub struct CheckpointManager {
    checkpoints: Mutex<HashMap<String, Checkpoint>>,
}

/// A saved workflow execution snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub workflow_id: String,
    pub completed_steps: Vec<String>,
    pub context: HashMap<String, serde_json::Value>,
    pub timestamp_ms: u64,
}

impl CheckpointManager {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Save a checkpoint for a running workflow.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn save(&self, workflow_id: &str, completed_steps: Vec<String>, context: &WorkflowContext) {
        let cp = Checkpoint {
            workflow_id: workflow_id.to_string(),
            completed_steps,
            context: context.vars.clone(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis().try_into().unwrap_or(u64::MAX),
        };
        self.checkpoints
            .lock()
            .unwrap()
            .insert(workflow_id.to_string(), cp);
    }

    /// Load the checkpoint for a workflow, if one exists.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn load(&self, workflow_id: &str) -> Option<Checkpoint> {
        self.checkpoints.lock().unwrap().get(workflow_id).cloned()
    }

    /// Delete a checkpoint (e.g. after successful completion).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn clear(&self, workflow_id: &str) {
        self.checkpoints.lock().unwrap().remove(workflow_id);
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn has_checkpoint(&self, workflow_id: &str) -> bool {
        self.checkpoints.lock().unwrap().contains_key(workflow_id)
    }
}

// ── WorkflowHistory ───────────────────────────────────────────────────────────

/// Stores the history of workflow run outcomes.
#[derive(Debug, Default)]
pub struct WorkflowHistory {
    runs: Mutex<Vec<WorkflowRun>>,
}

/// One completed workflow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub workflow_name: String,
    pub run_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub succeeded: bool,
    pub step_results: Vec<WorkflowStepResult>,
}

impl WorkflowRun {
    #[must_use] 
    pub const fn duration_ms(&self) -> u64 {
        self.finished_at.saturating_sub(self.started_at)
    }

    #[must_use] 
    pub fn steps_succeeded(&self) -> usize {
        self.step_results.iter().filter(|r| r.succeeded()).count()
    }

    #[must_use] 
    pub fn steps_failed(&self) -> usize {
        self.step_results.iter().filter(|r| r.failed()).count()
    }
}

impl WorkflowHistory {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn add_run(&self, run: WorkflowRun) {
        self.runs.lock().unwrap().push(run);
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn all_runs(&self) -> Vec<WorkflowRun> {
        self.runs.lock().unwrap().clone()
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn last_run(&self) -> Option<WorkflowRun> {
        self.runs.lock().unwrap().last().cloned()
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn runs_for(&self, workflow_name: &str) -> Vec<WorkflowRun> {
        self.runs
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.workflow_name == workflow_name)
            .cloned()
            .collect()
    }
}

// ── WorkflowScheduler ─────────────────────────────────────────────────────────

/// Cron-style scheduler for workflows.
#[derive(Debug, Default)]
pub struct WorkflowScheduler {
    scheduled: Mutex<Vec<ScheduledWorkflow>>,
}

#[derive(Debug, Clone)]
pub struct ScheduledWorkflow {
    pub id: String,
    pub workflow_name: String,
    pub cron_expr: String,
    pub enabled: bool,
    pub last_run: Option<u64>,
}

impl WorkflowScheduler {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn schedule(
        &self,
        id: impl Into<String>,
        workflow_name: impl Into<String>,
        cron: impl Into<String>,
    ) {
        let sw = ScheduledWorkflow {
            id: id.into(),
            workflow_name: workflow_name.into(),
            cron_expr: cron.into(),
            enabled: true,
            last_run: None,
        };
        self.scheduled.lock().unwrap().push(sw);
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn unschedule(&self, id: &str) {
        self.scheduled.lock().unwrap().retain(|s| s.id != id);
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn enable(&self, id: &str) {
        if let Some(s) = self
            .scheduled
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.id == id)
        {
            s.enabled = true;
        }
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn disable(&self, id: &str) {
        if let Some(s) = self
            .scheduled
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.id == id)
        {
            s.enabled = false;
        }
    }

    /// Panics if invariants are violated.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn list(&self) -> Vec<ScheduledWorkflow> {
        self.scheduled.lock().unwrap().clone()
    }

    /// Return all enabled scheduled workflows whose cron expression matches
    /// the given `now_ms` timestamp (simplified: just check if enabled).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn due_workflows(&self, _now_ms: u64) -> Vec<ScheduledWorkflow> {
        self.scheduled
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.enabled)
            .cloned()
            .collect()
    }
}

// ── ActionHandler ─────────────────────────────────────────────────────────────

/// A function that handles a workflow action.
pub type ActionFn = Box<
    dyn Fn(
            &str,
            &HashMap<String, serde_json::Value>,
            &mut WorkflowContext,
        ) -> Result<HashMap<String, serde_json::Value>, String>
        + Send
        + Sync,
>;

// ── WorkflowExecutor ──────────────────────────────────────────────────────────

/// Executes a [`WorkflowDefinition`] step by step.
pub struct WorkflowExecutor {
    handlers: HashMap<String, ActionFn>,
    pub checkpoint_mgr: Arc<CheckpointManager>,
    pub history: Arc<WorkflowHistory>,
    pub scheduler: Arc<WorkflowScheduler>,
}

impl WorkflowExecutor {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            checkpoint_mgr: Arc::new(CheckpointManager::new()),
            history: Arc::new(WorkflowHistory::new()),
            scheduler: Arc::new(WorkflowScheduler::new()),
        }
    }

    /// Register an action handler.
    pub fn register_action(&mut self, action_name: impl Into<String>, handler: ActionFn) {
        self.handlers.insert(action_name.into(), handler);
    }

    /// Execute a workflow definition, optionally resuming from a checkpoint.
    #[must_use] 
    pub fn execute(
        &self,
        def: &WorkflowDefinition,
        initial_vars: &HashMap<String, serde_json::Value>,
    ) -> WorkflowRun {
        // Sanitize workflow name so that embedded newlines / CRLF sequences
        // in `def.name` cannot inject fake log entries when `run_id` is logged.
        let safe_name: String = def
            .name
            .chars()
            .map(|c| if c == '\n' || c == '\r' { '_' } else { c })
            .collect();
        let run_id = format!("{}-{}", safe_name, Self::now_ms());
        let started_at = Self::now_ms();
        // Use a monotonic Instant for duration measurement so that wall-clock
        // jumps (NTP corrections) cannot make `duration_ms()` return zero or
        // a wildly wrong value.
        let run_instant = Instant::now();
        let mut ctx = WorkflowContext::new();
        ctx.merge(initial_vars);

        // Resume from checkpoint if available.
        let completed_before: std::collections::HashSet<String> =
            if let Some(cp) = self.checkpoint_mgr.load(&def.name) {
                ctx.merge(&cp.context);
                cp.completed_steps.into_iter().collect()
            } else {
                std::collections::HashSet::new()
            };

        let mut step_results = Vec::new();
        let mut succeeded = true;
        let mut completed_steps = Vec::new();

        for step in &def.steps {
            // Skip already-completed steps (resume path).
            if completed_before.contains(&step.name) {
                step_results.push(WorkflowStepResult::skipped(&step.name));
                completed_steps.push(step.name.clone());
                continue;
            }

            // Evaluate condition.
            if let Some(cond) = &step.condition
                && !ConditionalExpr::evaluate(cond, &ctx) {
                    step_results.push(WorkflowStepResult::skipped(&step.name));
                    continue;
                }

            // Execute with retries.
            let result = self.execute_step(step, &mut ctx);

            // Propagate outputs to context.
            for (k, v) in &result.outputs {
                ctx.set(k.clone(), v.clone());
            }

            let step_ok = result.succeeded();
            step_results.push(result);

            if step_ok {
                completed_steps.push(step.name.clone());
                // Save checkpoint after each successful step.
                self.checkpoint_mgr
                    .save(&def.name, completed_steps.clone(), &ctx);
            } else if !step.allow_failure {
                match &def.on_failure {
                    FailurePolicy::Abort | FailurePolicy::Retry { .. } => {
                        succeeded = false;
                        break;
                    }
                    FailurePolicy::Continue => {
                        // record failure but keep going
                    }
                }
            }
        }

        // Clear checkpoint on success.
        if succeeded {
            self.checkpoint_mgr.clear(&def.name);
        }

        // Derive `finished_at` from the monotonic elapsed time added to
        // `started_at` so that wall-clock skews do not produce nonsensical
        // negative durations in `WorkflowRun::duration_ms`.
        let elapsed_ms = u64::try_from(run_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
        let finished_at = started_at.saturating_add(elapsed_ms);
        let run = WorkflowRun {
            workflow_name: def.name.clone(),
            run_id,
            started_at,
            finished_at,
            succeeded,
            step_results,
        };

        self.history.add_run(run.clone());
        run
    }

    fn execute_step(&self, step: &WorkflowStep, ctx: &mut WorkflowContext) -> WorkflowStepResult {
        let t0 = Instant::now();
        let mut last_err = String::new();
        let max_attempts = step.retry.max_attempts.max(1);

        for attempt in 0..max_attempts {
            // Resolve inputs (substitute ${VAR} references).
            let inputs = Self::resolve_inputs(&step.inputs, ctx);

            match self.handlers.get(&step.action) {
                None => {
                    last_err = format!("unknown action: {}", step.action);
                    // No handler — fail immediately without retry.
                    break;
                }
                Some(handler) => {
                    match handler(&step.name, &inputs, ctx) {
                        Ok(outputs) => {
                            // Filter outputs to declared output keys.
                            let declared_outputs: HashMap<String, serde_json::Value> =
                                if step.outputs.is_empty() {
                                    outputs
                                } else {
                                    outputs
                                        .into_iter()
                                        .filter(|(k, _)| step.outputs.contains(k))
                                        .collect()
                                };
                            return WorkflowStepResult::success(
                                &step.name,
                                declared_outputs,
                                attempt + 1,
                                u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
                            );
                        }
                        Err(e) => {
                            last_err = e;
                            if attempt + 1 < max_attempts {
                                // Simple delay (no actual sleep in sync code).
                                let _ = step.retry.delay_for_attempt(attempt + 1);
                            }
                        }
                    }
                }
            }
        }

        WorkflowStepResult::failure(
            &step.name,
            last_err,
            max_attempts,
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }

    fn resolve_inputs(
        inputs: &HashMap<String, serde_json::Value>,
        ctx: &WorkflowContext,
    ) -> HashMap<String, serde_json::Value> {
        inputs
            .iter()
            .map(|(k, v)| {
                let resolved = match v {
                    serde_json::Value::String(s) => {
                        if s.starts_with("${") && s.ends_with('}') {
                            let var_name = &s[2..s.len() - 1];
                            ctx.get(var_name)
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        } else {
                            v.clone()
                        }
                    }
                    other => other.clone(),
                };
                (k.clone(), resolved)
            })
            .collect()
    }

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

impl Default for WorkflowExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_handler() -> ActionFn {
        Box::new(|_step, inputs, _ctx| Ok(inputs.clone()))
    }

    fn fail_handler() -> ActionFn {
        Box::new(|_step, _inputs, _ctx| Err("intentional failure".to_string()))
    }

    fn counter_handler(counter: Arc<Mutex<u32>>) -> ActionFn {
        Box::new(move |_step, _inputs, _ctx| {
            *counter.lock().unwrap() += 1;
            Ok(HashMap::new())
        })
    }

    fn make_executor() -> WorkflowExecutor {
        let mut ex = WorkflowExecutor::new();
        ex.register_action("echo", echo_handler());
        ex.register_action("fail", fail_handler());
        ex.register_action("count", counter_handler(Arc::new(Mutex::new(0))));
        ex
    }

    // ── WorkflowDefinition ────────────────────────────────────────────────────

    #[test]
    fn test_def_add_step() {
        let mut def = WorkflowDefinition::new("wf");
        def.add_step(WorkflowStep::new("s1", "echo"));
        assert_eq!(def.steps.len(), 1);
    }

    #[test]
    fn test_def_default_failure_policy() {
        let def = WorkflowDefinition::new("wf");
        assert_eq!(def.on_failure, FailurePolicy::Abort);
    }

    // ── WorkflowStep ──────────────────────────────────────────────────────────

    #[test]
    fn test_step_builder() {
        let step = WorkflowStep::new("s1", "echo")
            .with_input("key", serde_json::json!("value"))
            .with_condition("${flag} == true")
            .with_retry(RetryPolicy::with_retries(3));
        assert_eq!(step.name, "s1");
        assert_eq!(step.action, "echo");
        assert!(step.inputs.contains_key("key"));
        assert!(step.condition.is_some());
        assert_eq!(step.retry.max_attempts, 3);
    }

    // ── RetryPolicy ───────────────────────────────────────────────────────────

    #[test]
    fn test_retry_delay_linear() {
        let p = RetryPolicy {
            max_attempts: 3,
            delay_ms: 100,
            backoff_factor: 1.0,
        };
        assert_eq!(p.delay_for_attempt(0), 0);
        assert_eq!(p.delay_for_attempt(1), 100);
        assert_eq!(p.delay_for_attempt(2), 100);
    }

    #[test]
    fn test_retry_delay_exponential() {
        let p = RetryPolicy {
            max_attempts: 5,
            delay_ms: 100,
            backoff_factor: 2.0,
        };
        assert_eq!(p.delay_for_attempt(1), 100);
        assert_eq!(p.delay_for_attempt(2), 200);
        assert_eq!(p.delay_for_attempt(3), 400);
    }

    // ── WorkflowContext ───────────────────────────────────────────────────────

    #[test]
    fn test_context_set_get() {
        let mut ctx = WorkflowContext::new();
        ctx.set("x", serde_json::json!(42));
        assert_eq!(ctx.get_int("x"), Some(42));
    }

    #[test]
    fn test_context_missing() {
        let ctx = WorkflowContext::new();
        assert!(ctx.get("missing").is_none());
        assert!(!ctx.contains("missing"));
    }

    #[test]
    fn test_context_merge() {
        let mut ctx = WorkflowContext::new();
        ctx.set("a", serde_json::json!(1));
        let mut extra = HashMap::new();
        extra.insert("b".to_string(), serde_json::json!(2));
        ctx.merge(&extra);
        assert_eq!(ctx.get_int("a"), Some(1));
        assert_eq!(ctx.get_int("b"), Some(2));
    }

    // ── ConditionalExpr ───────────────────────────────────────────────────────

    #[test]
    fn test_cond_true_literal() {
        let ctx = WorkflowContext::new();
        assert!(ConditionalExpr::evaluate("true", &ctx));
    }

    #[test]
    fn test_cond_false_literal() {
        let ctx = WorkflowContext::new();
        assert!(!ConditionalExpr::evaluate("false", &ctx));
    }

    #[test]
    fn test_cond_var_truthy() {
        let mut ctx = WorkflowContext::new();
        ctx.set("flag", serde_json::json!(true));
        assert!(ConditionalExpr::evaluate("${flag}", &ctx));
    }

    #[test]
    fn test_cond_var_missing_falsy() {
        let ctx = WorkflowContext::new();
        assert!(!ConditionalExpr::evaluate("${missing}", &ctx));
    }

    #[test]
    fn test_cond_eq_string() {
        let mut ctx = WorkflowContext::new();
        ctx.set("mode", serde_json::json!("debug"));
        assert!(ConditionalExpr::evaluate("${mode} == debug", &ctx));
        assert!(!ConditionalExpr::evaluate("${mode} == release", &ctx));
    }

    #[test]
    fn test_cond_ne_string() {
        let mut ctx = WorkflowContext::new();
        ctx.set("env", serde_json::json!("prod"));
        assert!(ConditionalExpr::evaluate("${env} != test", &ctx));
        assert!(!ConditionalExpr::evaluate("${env} != prod", &ctx));
    }

    #[test]
    fn test_cond_numeric_gt() {
        let mut ctx = WorkflowContext::new();
        ctx.set("count", serde_json::json!(5));
        assert!(ConditionalExpr::evaluate("${count} > 3", &ctx));
        assert!(!ConditionalExpr::evaluate("${count} > 10", &ctx));
    }

    #[test]
    fn test_cond_not() {
        let ctx = WorkflowContext::new();
        assert!(ConditionalExpr::evaluate("not false", &ctx));
        assert!(!ConditionalExpr::evaluate("not true", &ctx));
    }

    #[test]
    fn test_cond_numeric_lte() {
        let mut ctx = WorkflowContext::new();
        ctx.set("n", serde_json::json!(7));
        assert!(ConditionalExpr::evaluate("${n} <= 7", &ctx));
        assert!(!ConditionalExpr::evaluate("${n} <= 6", &ctx));
    }

    // ── CheckpointManager ─────────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_save_load() {
        let mgr = CheckpointManager::new();
        let mut ctx = WorkflowContext::new();
        ctx.set("step_done", serde_json::json!(true));
        mgr.save("wf1", vec!["s1".to_string()], &ctx);
        let cp = mgr.load("wf1").unwrap();
        assert_eq!(cp.workflow_id, "wf1");
        assert!(cp.completed_steps.contains(&"s1".to_string()));
        assert!(cp.context.contains_key("step_done"));
    }

    #[test]
    fn test_checkpoint_clear() {
        let mgr = CheckpointManager::new();
        let ctx = WorkflowContext::new();
        mgr.save("wf1", vec![], &ctx);
        assert!(mgr.has_checkpoint("wf1"));
        mgr.clear("wf1");
        assert!(!mgr.has_checkpoint("wf1"));
    }

    // ── WorkflowScheduler ────────────────────────────────────────────────────

    #[test]
    fn test_scheduler_add_list() {
        let sched = WorkflowScheduler::new();
        sched.schedule("job1", "wf_a", "0 * * * *");
        assert_eq!(sched.list().len(), 1);
    }

    #[test]
    fn test_scheduler_enable_disable() {
        let sched = WorkflowScheduler::new();
        sched.schedule("job1", "wf_a", "0 * * * *");
        sched.disable("job1");
        let list = sched.list();
        assert!(!list[0].enabled);
        sched.enable("job1");
        let list = sched.list();
        assert!(list[0].enabled);
    }

    #[test]
    fn test_scheduler_unschedule() {
        let sched = WorkflowScheduler::new();
        sched.schedule("j1", "wf", "0 0 * * *");
        sched.unschedule("j1");
        assert!(sched.list().is_empty());
    }

    // ── WorkflowExecutor ──────────────────────────────────────────────────────

    #[test]
    fn test_executor_simple_success() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("test_wf");
        def.add_step(
            WorkflowStep::new("step1", "echo").with_input("msg", serde_json::json!("hello")),
        );
        let run = ex.execute(&def, &HashMap::new());
        assert!(run.succeeded);
        assert_eq!(run.step_results.len(), 1);
        assert!(run.step_results[0].succeeded());
    }

    #[test]
    fn test_executor_abort_on_failure() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("abort_wf");
        def.on_failure = FailurePolicy::Abort;
        def.add_step(WorkflowStep::new("fail_step", "fail"));
        def.add_step(WorkflowStep::new("after_fail", "echo"));
        let run = ex.execute(&def, &HashMap::new());
        assert!(!run.succeeded);
        // Second step should not have run.
        let after = run
            .step_results
            .iter()
            .find(|r| r.step_name == "after_fail");
        assert!(after.is_none());
    }

    #[test]
    fn test_executor_continue_on_failure() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("continue_wf");
        def.on_failure = FailurePolicy::Continue;
        def.add_step(WorkflowStep::new("fail_step", "fail"));
        def.add_step(WorkflowStep::new("echo_step", "echo"));
        let run = ex.execute(&def, &HashMap::new());
        // Second step ran even after failure.
        let echo_r = run.step_results.iter().find(|r| r.step_name == "echo_step");
        assert!(echo_r.is_some());
    }

    #[test]
    fn test_executor_skip_on_condition() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("cond_wf");
        def.add_step(WorkflowStep::new("conditional", "echo").with_condition("false"));
        let run = ex.execute(&def, &HashMap::new());
        assert!(run.step_results[0].outcome == StepOutcome::Skipped);
    }

    #[test]
    fn test_executor_condition_from_context() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("ctx_cond_wf");
        def.add_step(WorkflowStep::new("gated", "echo").with_condition("${enabled} == true"));
        let mut vars = HashMap::new();
        vars.insert("enabled".to_string(), serde_json::json!("true"));
        let run = ex.execute(&def, &vars);
        assert!(run.step_results[0].succeeded());
    }

    #[test]
    fn test_executor_retries() {
        let counter = Arc::new(Mutex::new(0u32));
        let c2 = Arc::clone(&counter);
        let mut ex = WorkflowExecutor::new();
        ex.register_action(
            "count_fail",
            Box::new(move |_, _, _| {
                *c2.lock().unwrap() += 1;
                Err("fail".to_string())
            }),
        );
        let mut def = WorkflowDefinition::new("retry_wf");
        def.on_failure = FailurePolicy::Continue;
        def.add_step(
            WorkflowStep::new("retry_step", "count_fail").with_retry(RetryPolicy::with_retries(3)),
        );
        let _ = ex.execute(&def, &HashMap::new());
        assert_eq!(*counter.lock().unwrap(), 3);
    }

    #[test]
    fn test_executor_output_propagation() {
        let mut ex = WorkflowExecutor::new();
        ex.register_action(
            "produce",
            Box::new(|_, _, _| {
                let mut out = HashMap::new();
                out.insert("result".to_string(), serde_json::json!(42));
                Ok(out)
            }),
        );
        ex.register_action(
            "consume",
            Box::new(|_, inputs, _| {
                let val = inputs.get("val").and_then(serde_json::Value::as_i64).unwrap_or(0);
                assert_eq!(val, 42);
                Ok(HashMap::new())
            }),
        );
        let mut def = WorkflowDefinition::new("prop_wf");
        let mut produce = WorkflowStep::new("produce_step", "produce");
        produce.outputs = vec!["result".to_string()];
        let consume = WorkflowStep::new("consume_step", "consume")
            .with_input("val", serde_json::json!("${result}"));
        def.add_step(produce);
        def.add_step(consume);
        let run = ex.execute(&def, &HashMap::new());
        assert!(run.succeeded);
    }

    #[test]
    fn test_executor_history() {
        let ex = make_executor();
        let def = WorkflowDefinition::new("hist_wf");
        let _ = ex.execute(&def, &HashMap::new());
        let _ = ex.execute(&def, &HashMap::new());
        assert_eq!(ex.history.runs_for("hist_wf").len(), 2);
    }

    #[test]
    fn test_executor_unknown_action() {
        let ex = WorkflowExecutor::new();
        let mut def = WorkflowDefinition::new("unknown_wf");
        def.add_step(WorkflowStep::new("bad", "nonexistent_action"));
        let run = ex.execute(&def, &HashMap::new());
        assert!(run.step_results[0].failed());
    }

    #[test]
    fn test_workflow_run_stats() {
        let ex = make_executor();
        let mut def = WorkflowDefinition::new("stats_wf");
        def.on_failure = FailurePolicy::Continue;
        def.add_step(WorkflowStep::new("ok", "echo"));
        def.add_step(WorkflowStep::new("bad", "fail"));
        let run = ex.execute(&def, &HashMap::new());
        assert_eq!(run.steps_succeeded(), 1);
        assert_eq!(run.steps_failed(), 1);
    }
}
