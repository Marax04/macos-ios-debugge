// #![recursion_limit = "4096"]
//! `rustre-agent-workflow`
//!
//! Agent workflow orchestration for the `RustRE` platform.
//! Supports multi-step RE automation with state machines, retries,
//! conditional branching, and `SQLite` + `MySQL` persistence.

pub mod step_executor;
pub mod parallel_workflow;
pub mod re_workflows;
pub mod result_aggregator;
pub mod task_executor;
pub mod workflow_dsl;
pub mod workflow_executor;
pub mod workflow_executor_full;
pub mod workflow_templates;
pub mod workflow_validator;
pub mod workflow_checkpointer;

use std::collections::HashMap;

use async_trait::async_trait;
use parking_lot::RwLock;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_agent::{
    Agent, AgentCapability, AgentConfig, AgentContext, AgentError, AgentInput, AgentOutput,
};

// ─── Re-export for convenience ───────────────────────────────────────────────
pub use rustre_agent::{AgentAction, Artifact};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors that can occur in the workflow engine.
#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("workflow '{0}' not found")]
    NotFound(String),

    #[error("invalid workflow: {0}")]
    InvalidWorkflow(String),

    #[error("step '{step}' failed: {message}")]
    StepFailed { step: String, message: String },

    #[error("condition evaluation failed: {0}")]
    ConditionError(String),

    #[error("agent error: {0}")]
    AgentError(#[from] AgentError),

    #[error("database error: {0}")]
    DbError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("workflow cancelled")]
    Cancelled,

    #[error("maximum retries exceeded for step '{0}'")]
    RetriesExceeded(String),

    #[error("rollback failed: {0}")]
    RollbackFailed(String),
}

impl From<rusqlite::Error> for WorkflowError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DbError(e.to_string())
    }
}

impl From<serde_json::Error> for WorkflowError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

// ─── Retry config ─────────────────────────────────────────────────────────────

/// Controls retry behaviour for a workflow step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub backoff_ms: u64,
    pub exponential: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            backoff_ms: 0,
            exponential: false,
        }
    }
}

impl RetryConfig {
    /// Compute the sleep duration before attempt `n` (1-indexed).
    #[must_use]
    pub const fn delay_ms(&self, attempt: u32) -> u64 {
        if attempt <= 1 {
            return 0;
        }
        if self.exponential {
            self.backoff_ms
                .saturating_mul(2u64.saturating_pow(attempt - 2))
        } else {
            self.backoff_ms
        }
    }
}

// ─── Condition ────────────────────────────────────────────────────────────────

/// Condition that controls whether a step is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowCondition {
    /// Always execute.
    Always,
    /// Execute only if the previous step succeeded.
    OnSuccess,
    /// Execute only if the previous step failed.
    OnFailure,
    /// Execute if a workflow variable equals a value.
    IfVar { var: String, eq: serde_json::Value },
    /// Execute only if the routed agent has this capability.
    IfCapability(AgentCapability),
}

// ─── Error strategy ──────────────────────────────────────────────────────────

/// What the engine does when a step fails after all retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorStrategy {
    /// Stop the workflow immediately.
    Stop,
    /// Continue to the next step despite the failure.
    Continue,
    /// Retry the whole workflow (handled at the step level via `RetryConfig`).
    Retry,
    /// Attempt to roll back completed steps.
    Rollback,
}

// ─── WorkflowStep ────────────────────────────────────────────────────────────

/// A single step in a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Unique identifier for this step.
    pub id: String,
    /// Name of the agent to invoke.
    pub agent: String,
    /// Maps workflow variable names → `AgentInput` context keys.
    pub input_mapping: HashMap<String, String>,
    /// Maps `AgentOutput` fields → workflow variable names.
    pub output_mapping: HashMap<String, String>,
    /// Whether to execute this step.
    pub condition: Option<WorkflowCondition>,
    pub retry: RetryConfig,
}

impl WorkflowStep {
    #[must_use]
    pub fn new(id: impl Into<String>, agent: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            agent: agent.into(),
            input_mapping: HashMap::new(),
            output_mapping: HashMap::new(),
            condition: Some(WorkflowCondition::Always),
            retry: RetryConfig::default(),
        }
    }
}

// ─── Workflow ─────────────────────────────────────────────────────────────────

/// A named sequence of steps with error handling configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub on_error: ErrorStrategy,
}

impl Workflow {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        steps: Vec<WorkflowStep>,
        on_error: ErrorStrategy,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            steps,
            on_error,
        }
    }
}

// ─── Status & State ──────────────────────────────────────────────────────────

/// Runtime status of a workflow execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Succeeded,
    Failed(String),
    Cancelled,
}

/// Full runtime state of an executing workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    pub workflow_id: String,
    pub current_step: usize,
    /// Shared variable store across all steps.
    pub variables: HashMap<String, serde_json::Value>,
    /// Outputs keyed by step id.
    pub step_results: HashMap<String, AgentOutput>,
    pub status: WorkflowStatus,
}

impl WorkflowState {
    #[must_use]
    pub fn new(workflow_id: impl Into<String>) -> Self {
        Self {
            workflow_id: workflow_id.into(),
            current_step: 0,
            variables: HashMap::new(),
            step_results: HashMap::new(),
            status: WorkflowStatus::Pending,
        }
    }

    /// Set a variable in the workflow's shared store.
    pub fn set_var(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.variables.insert(key.into(), value);
    }

    /// Get a variable from the shared store.
    #[must_use]
    pub fn get_var(&self, key: &str) -> Option<&serde_json::Value> {
        self.variables.get(key)
    }
}

// ─── Registered agent ────────────────────────────────────────────────────────

struct RegisteredAgent {
    agent: std::sync::Arc<dyn Agent>,
}

// ─── WorkflowEngine ──────────────────────────────────────────────────────────

/// Executes workflows by dispatching steps to registered agents.
pub struct WorkflowEngine {
    agents: RwLock<HashMap<String, RegisteredAgent>>,
    /// Optional persistence store.  When set, workflow starts and step results
    /// are persisted automatically during `run()`.
    store: Option<std::sync::Arc<WorkflowStore>>,
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            store: None,
        }
    }

    /// Attach a [`WorkflowStore`] so that `run()` persists state automatically.
    #[must_use]
    pub fn with_store(mut self, store: WorkflowStore) -> Self {
        self.store = Some(std::sync::Arc::new(store));
        self
    }

    /// Register and initialise an agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub async fn register_agent(
        &self,
        mut agent: Box<dyn Agent>,
        config: &AgentConfig,
    ) -> Result<(), WorkflowError> {
        agent.initialize(config).await?;
        let name = agent.name().to_string();
        let agent: std::sync::Arc<dyn Agent> = std::sync::Arc::from(agent);
        self.agents.write().insert(name, RegisteredAgent { agent });
        Ok(())
    }

    /// Return names of all registered agents.
    #[must_use]
    pub fn agent_names(&self) -> Vec<String> {
        self.agents.read().keys().cloned().collect()
    }

    /// Evaluate a step condition against the current state.
    fn evaluate_condition(
        condition: &WorkflowCondition,
        state: &WorkflowState,
        last_step_succeeded: bool,
    ) -> bool {
        match condition {
            // IfCapability: capability check is advisory; always run unless the agent is missing.
            WorkflowCondition::Always | WorkflowCondition::IfCapability(_) => true,
            WorkflowCondition::OnSuccess => last_step_succeeded,
            WorkflowCondition::OnFailure => !last_step_succeeded,
            WorkflowCondition::IfVar { var, eq } => {
                state.variables.get(var) == Some(eq)
            }
        }
    }

    /// Build an `AgentInput` for a step from the current workflow state.
    fn build_input(step: &WorkflowStep, state: &WorkflowState, task: &str) -> AgentInput {
        let mut context = HashMap::new();
        for (wf_var, agent_key) in &step.input_mapping {
            if let Some(val) = state.variables.get(wf_var) {
                context.insert(agent_key.clone(), val.clone());
            }
        }
        AgentInput {
            task: task.to_string(),
            context,
            binary_data: None,
            history: Vec::new(),
        }
    }

    /// Apply an agent's output to the workflow state via `output_mapping`.
    fn apply_output(step: &WorkflowStep, output: &AgentOutput, state: &mut WorkflowState) {
        for (output_key, wf_var) in &step.output_mapping {
            let value: serde_json::Value = match output_key.as_str() {
                "result" => serde_json::Value::String(output.result.clone()),
                "confidence" => serde_json::json!(output.confidence),
                "next_steps" => serde_json::json!(output.next_steps),
                other => serde_json::Value::String(format!("unmapped:{other}")),
            };
            state.variables.insert(wf_var.clone(), value);
        }
        state.step_results.insert(step.id.clone(), output.clone());
    }

    /// Execute a single workflow step, respecting the retry config.
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        state: &WorkflowState,
        ctx: &AgentContext,
        task: &str,
    ) -> Result<AgentOutput, WorkflowError> {
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            let input = Self::build_input(step, state, task);

            // Clone the Arc out of the lock so the lock can be released
            // before the async `process` call. The Arc keeps the agent alive
            // across `.await`.
            let agent = {
                let guard = self.agents.read();
                match guard.get(&step.agent) {
                    None => {
                        return Err(WorkflowError::StepFailed {
                            step: step.id.clone(),
                            message: format!("agent '{}' not registered", step.agent),
                        });
                    }
                    Some(ra) => std::sync::Arc::clone(&ra.agent),
                }
            };
            let result = agent.process(input, ctx).await;

            match result {
                Ok(output) => return Ok(output),
                Err(e) => {
                    if attempt >= step.retry.max_attempts {
                        return Err(WorkflowError::StepFailed {
                            step: step.id.clone(),
                            message: e.to_string(),
                        });
                    }
                    let delay = step.retry.delay_ms(attempt);
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
            }
        }
    }

    /// Execute a workflow with an initial variable set.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub async fn run(
        &self,
        workflow: &Workflow,
        initial_vars: HashMap<String, serde_json::Value>,
        ctx: &AgentContext,
        task: &str,
    ) -> Result<WorkflowState, WorkflowError> {
        let mut state = WorkflowState::new(&workflow.id);
        state.variables.extend(initial_vars);
        state.status = WorkflowStatus::Running;

        // Build a unique run id: "<workflow_id>-<epoch_ms>"
        let run_id = format!(
            "{}-{}",
            workflow.id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        // Persist workflow start.
        if let Some(store) = &self.store {
            let _ = store.add_workflow(&run_id, &workflow.name);
        }

        let mut last_succeeded = true;
        // Track completed step ids for rollback.
        let mut completed_steps: Vec<String> = Vec::new();

        for (i, step) in workflow.steps.iter().enumerate() {
            state.current_step = i;

            // Evaluate condition
            let should_run = step.condition.as_ref().is_none_or(|cond| Self::evaluate_condition(cond, &state, last_succeeded));

            if !should_run {
                continue;
            }

            match self.execute_step(step, &state, ctx, task).await {
                Ok(output) => {
                    Self::apply_output(step, &output, &mut state);
                    last_succeeded = true;
                    completed_steps.push(step.id.clone());

                    // Persist step success.
                    if let Some(store) = &self.store {
                        let result_json = serde_json::to_string(&output).ok();
                        let _ = store.update_step_result(
                            &run_id,
                            &step.id,
                            "succeeded",
                            result_json.as_deref(),
                            None,
                        );
                    }
                }
                Err(e) => {
                    last_succeeded = false;

                    // Persist step failure.
                    if let Some(store) = &self.store {
                        let _ = store.update_step_result(
                            &run_id,
                            &step.id,
                            "failed",
                            None,
                            Some(&e.to_string()),
                        );
                    }

                    match &workflow.on_error {
                        ErrorStrategy::Stop => {
                            state.status = WorkflowStatus::Failed(e.to_string());
                            if let Some(store) = &self.store {
                                let _ = store.set_workflow_status(&run_id, "failed");
                            }
                            return Err(e);
                        }
                        ErrorStrategy::Continue => {
                            // Record the failure but continue.
                            state.variables.insert(
                                format!("{}_error", step.id),
                                serde_json::Value::String(e.to_string()),
                            );
                        }
                        ErrorStrategy::Retry => {
                            // Retry is handled at step level; if we reach here all
                            // retries are exhausted.
                            state.status = WorkflowStatus::Failed(e.to_string());
                            if let Some(store) = &self.store {
                                let _ = store.set_workflow_status(&run_id, "failed");
                            }
                            return Err(e);
                        }
                        ErrorStrategy::Rollback => {
                            // Undo previously completed steps in reverse order.
                            let rollback_err = e.to_string();
                            for prev_step_id in completed_steps.iter().rev() {
                                // Mark the rolled-back step in the store.
                                if let Some(store) = &self.store {
                                    let _ = store.update_step_result(
                                        &run_id,
                                        prev_step_id,
                                        "rolled_back",
                                        None,
                                        Some("rolled back due to downstream failure"),
                                    );
                                }
                                // Remove the step's output from state so callers
                                // can see the undo took effect.
                                state.step_results.remove(prev_step_id);
                                // Also remove the workflow variables that this step
                                // wrote via output_mapping, so the rolled-back state
                                // is not partially visible through state.variables.
                                if let Some(step_def) = workflow.steps.iter().find(|s| &s.id == prev_step_id) {
                                    for wf_var in step_def.output_mapping.values() {
                                        state.variables.remove(wf_var);
                                    }
                                }
                            }
                            state.status = WorkflowStatus::Failed(format!(
                                "rollback triggered: {rollback_err}"
                            ));
                            if let Some(store) = &self.store {
                                let _ = store.set_workflow_status(&run_id, "rolled_back");
                            }
                            return Err(WorkflowError::RollbackFailed(rollback_err));
                        }
                    }
                }
            }
        }

        if state.status == WorkflowStatus::Running {
            state.status = WorkflowStatus::Succeeded;
            if let Some(store) = &self.store {
                let _ = store.set_workflow_status(&run_id, "succeeded");
            }
        }

        Ok(state)
    }
}

// ─── Built-in workflows ───────────────────────────────────────────────────────

/// Returns the catalogue of built-in RE workflows.
#[must_use]
pub fn builtin_workflows() -> Vec<Workflow> {
    vec![
        // ── full_re_analysis ──────────────────────────────────────────────
        Workflow::new(
            "full_re_analysis",
            "Full RE Analysis",
            vec![
                WorkflowStep {
                    id: "disassemble".to_string(),
                    agent: "disasm-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "disassembly".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "decompile".to_string(),
                    agent: "decomp-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "disassembly".to_string(),
                        "disassembly".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "decompiled_code".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "rename".to_string(),
                    agent: "rename-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "decompiled_code".to_string(),
                        "code".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "rename_suggestions".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "identify_vulns".to_string(),
                    agent: "vuln-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "decompiled_code".to_string(),
                        "code".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "vulnerabilities".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig {
                        max_attempts: 2,
                        backoff_ms: 500,
                        exponential: false,
                    },
                },
                WorkflowStep {
                    id: "generate_report".to_string(),
                    agent: "report-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("vulnerabilities".to_string(), "findings".to_string()),
                        ("rename_suggestions".to_string(), "renames".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "final_report".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Continue,
        ),
        // ── malware_triage ────────────────────────────────────────────────
        Workflow::new(
            "malware_triage",
            "Malware Triage",
            vec![
                WorkflowStep {
                    id: "load".to_string(),
                    agent: "loader-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "sample_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "load_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "detect_packers".to_string(),
                    agent: "packer-agent".to_string(),
                    input_mapping: HashMap::new(),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "packer_info".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "analyze_strings".to_string(),
                    agent: "strings-agent".to_string(),
                    input_mapping: HashMap::new(),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "strings_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "lookup_ti".to_string(),
                    agent: "ti-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "strings_result".to_string(),
                        "iocs".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "ti_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig {
                        max_attempts: 3,
                        backoff_ms: 1000,
                        exponential: true,
                    },
                },
                WorkflowStep {
                    id: "report".to_string(),
                    agent: "report-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("ti_result".to_string(), "ti_data".to_string()),
                        ("packer_info".to_string(), "packer_data".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "triage_report".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Continue,
        ),
        // ── function_rename ────────────────────────────────────────────────
        Workflow::new(
            "function_rename",
            "Function Rename Automation",
            vec![
                WorkflowStep {
                    id: "analyze_all".to_string(),
                    agent: "decomp-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "function_list".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "suggest_names".to_string(),
                    agent: "rename-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "function_list".to_string(),
                        "functions".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "name_suggestions".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig {
                        max_attempts: 2,
                        backoff_ms: 500,
                        exponential: false,
                    },
                },
                WorkflowStep {
                    id: "apply_renames".to_string(),
                    agent: "patcher-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "name_suggestions".to_string(),
                        "renames".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "rename_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Stop,
        ),
        // ── vuln_hunt ─────────────────────────────────────────────────────
        Workflow::new(
            "vuln_hunt",
            "Vulnerability Hunt",
            vec![
                WorkflowStep {
                    id: "iterate_functions".to_string(),
                    agent: "decomp-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "function_code".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                WorkflowStep {
                    id: "check_vulns".to_string(),
                    agent: "vuln-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "function_code".to_string(),
                        "code".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "vuln_findings".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig {
                        max_attempts: 3,
                        backoff_ms: 200,
                        exponential: true,
                    },
                },
                WorkflowStep {
                    id: "report_findings".to_string(),
                    agent: "report-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "vuln_findings".to_string(),
                        "findings".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "vuln_report".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Continue,
        ),
        // ── analyze_binary ────────────────────────────────────────────
        //
        // Six-step comprehensive binary analysis pipeline:
        //   1. load_binary   — open the binary via project.open (loader-agent)
        //   2. analyze_full  — run analyze.full (disasm-agent)
        //   3. cross_refs    — run analyze.cross_refs (disasm-agent)
        //   4. yara_scan     — run yara.scan_file with default malware rules
        //   5. triage_analyze— run triage.analyze (vuln-agent)
        //   6. compile_report— aggregate all results into a comprehensive report
        Workflow::new(
            "analyze_binary",
            "Analyze Binary",
            vec![
                // Step 1 — Load binary via MCP project.open
                WorkflowStep {
                    id: "load_binary".to_string(),
                    agent: "loader-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "load_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                // Step 2 — Full disassembly / analysis (analyze.full)
                WorkflowStep {
                    id: "analyze_full".to_string(),
                    agent: "disasm-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("binary_path".to_string(), "binary_path".to_string()),
                        ("load_result".to_string(), "load_result".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "full_analysis".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig {
                        max_attempts: 2,
                        backoff_ms: 500,
                        exponential: false,
                    },
                },
                // Step 3 — Cross-reference analysis (analyze.cross_refs)
                WorkflowStep {
                    id: "cross_refs".to_string(),
                    agent: "disasm-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "full_analysis".to_string(),
                        "disassembly".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "xref_data".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig::default(),
                },
                // Step 4 — YARA scan with default malware rules (yara.scan_file)
                WorkflowStep {
                    id: "yara_scan".to_string(),
                    agent: "yara-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "yara_matches".to_string(),
                    )]),
                    // Run independently — YARA does not depend on disasm output.
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig {
                        max_attempts: 2,
                        backoff_ms: 1000,
                        exponential: false,
                    },
                },
                // Step 5 — Triage analysis (triage.analyze)
                WorkflowStep {
                    id: "triage_analyze".to_string(),
                    agent: "vuln-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("full_analysis".to_string(), "decompiled_code".to_string()),
                        ("yara_matches".to_string(), "yara_matches".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "triage_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                // Step 6 — Compile comprehensive report
                WorkflowStep {
                    id: "compile_report".to_string(),
                    agent: "report-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("full_analysis".to_string(), "analysis".to_string()),
                        ("xref_data".to_string(), "xrefs".to_string()),
                        ("yara_matches".to_string(), "yara".to_string()),
                        ("triage_result".to_string(), "triage".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "final_report".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Continue,
        ),
        // ── find_vulnerabilities ──────────────────────────────────────
        //
        // Four-step vulnerability discovery pipeline:
        //   1. load_binary   — open the binary via project.open
        //   2. analyze_full  — disassemble + decompile for code context
        //   3. vuln_patterns — VulnAgent pattern-matching for vulnerability signatures
        //   4. malfind       — forensics malfind (non-fatal if unavailable)
        //
        // Returns findings in "vuln_findings" and "malfind_result" variables,
        // each containing addresses and descriptions.
        Workflow::new(
            "find_vulnerabilities",
            "Find Vulnerabilities",
            vec![
                // Step 1 — Load binary
                WorkflowStep {
                    id: "load_binary".to_string(),
                    agent: "loader-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "load_result".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                // Step 2 — Full analysis (disassemble + decompile)
                WorkflowStep {
                    id: "analyze_full".to_string(),
                    agent: "disasm-agent".to_string(),
                    input_mapping: HashMap::from([
                        ("binary_path".to_string(), "binary_path".to_string()),
                        ("load_result".to_string(), "load_result".to_string()),
                    ]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "decompiled_code".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig {
                        max_attempts: 2,
                        backoff_ms: 500,
                        exponential: false,
                    },
                },
                // Step 3 — VulnAgent pattern-matching for vulnerability signatures
                WorkflowStep {
                    id: "vuln_patterns".to_string(),
                    agent: "vuln-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "decompiled_code".to_string(),
                        "decompiled_code".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "vuln_findings".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnSuccess),
                    retry: RetryConfig {
                        max_attempts: 3,
                        backoff_ms: 200,
                        exponential: true,
                    },
                },
                // Step 4 — Forensics malfind (optional; continue on failure if unavailable)
                WorkflowStep {
                    id: "malfind".to_string(),
                    agent: "forensics-agent".to_string(),
                    input_mapping: HashMap::from([(
                        "binary_path".to_string(),
                        "binary_path".to_string(),
                    )]),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "malfind_result".to_string(),
                    )]),
                    // Always attempt malfind; ErrorStrategy::Continue makes failure non-fatal.
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            // Non-fatal: malfind / forensics-agent may not be available in every environment.
            ErrorStrategy::Continue,
        ),
    ]
}

// ─── WorkflowStore ────────────────────────────────────────────────────────────

/// Persists workflow definitions and execution state.
/// Backed by `SQLite` (primary) and optionally `MySQL`.
pub struct WorkflowStore {
    sqlite: parking_lot::Mutex<Connection>,
    mysql_url: Option<String>,
    mysql_pool: parking_lot::Mutex<Option<mysql::Pool>>,
}

impl WorkflowStore {
    /// Open (or create) a SQLite-backed store.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn open(path: &str) -> Result<Self, WorkflowError> {
        let conn = Connection::open(path)?;
        let store = Self {
            sqlite: parking_lot::Mutex::new(conn),
            mysql_url: None,
            mysql_pool: parking_lot::Mutex::new(None),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory `SQLite` store (for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn in_memory() -> Result<Self, WorkflowError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            sqlite: parking_lot::Mutex::new(conn),
            mysql_url: None,
            mysql_pool: parking_lot::Mutex::new(None),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Attach a `MySQL` URL for secondary persistence.
    /// The connection pool is initialised eagerly so that repeated `sync_to_mysql`
    /// calls reuse the same pool instead of creating a new one each time.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn with_mysql(mut self, url: impl Into<String>) -> Result<Self, WorkflowError> {
        use mysql::{Opts, Pool};
        let url_str = url.into();
        let opts = Opts::from_url(&url_str).map_err(|e| WorkflowError::DbError(e.to_string()))?;
        let pool = Pool::new(opts).map_err(|e| WorkflowError::DbError(e.to_string()))?;
        self.mysql_url = Some(url_str);
        *self.mysql_pool.lock() = Some(pool);
        Ok(self)
    }

    fn init_schema(&self) -> Result<(), WorkflowError> {
        self.sqlite.lock().execute_batch(
            "CREATE TABLE IF NOT EXISTS workflows (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                definition  TEXT NOT NULL,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS workflow_states (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id     TEXT NOT NULL,
                status          TEXT NOT NULL,
                state_json      TEXT NOT NULL,
                updated_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_wf_states_wfid
                ON workflow_states(workflow_id);
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS workflow_steps (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id TEXT NOT NULL,
                step_name   TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                error_msg   TEXT,
                FOREIGN KEY(workflow_id) REFERENCES workflow_runs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_wf_steps_wfid
                ON workflow_steps(workflow_id);",
        )?;
        Ok(())
    }

    /// Record a new workflow execution in the `workflow_runs` table.
    ///
    /// Call this at the start of a workflow run.  `run_id` should be a unique
    /// identifier for this particular execution (e.g. a UUID or a timestamp-
    /// suffixed workflow id).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn add_workflow(&self, run_id: &str, name: &str) -> Result<(), WorkflowError> {
        self.sqlite.lock().execute(
            "INSERT OR REPLACE INTO workflow_runs (id, name, status) VALUES (?1, ?2, 'running')",
            rusqlite::params![run_id, name],
        )?;
        Ok(())
    }

    /// Persist the result of a completed step in the `workflow_steps` table.
    ///
    /// Pass `result_json` as `Some(json)` on success or `None` on failure;
    /// pass `error_msg` as `Some(msg)` on failure or `None` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn update_step_result(
        &self,
        run_id: &str,
        step_name: &str,
        status: &str,
        result_json: Option<&str>,
        error_msg: Option<&str>,
    ) -> Result<(), WorkflowError> {
        let conn = self.sqlite.lock();
        // Upsert: if a row for this run_id + step_name already exists update it;
        // otherwise insert a new row.
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM workflow_steps WHERE workflow_id = ?1 AND step_name = ?2",
                rusqlite::params![run_id, step_name],
                |row| row.get(0),
            )
            .ok();

        if let Some(row_id) = existing {
            conn.execute(
                "UPDATE workflow_steps SET status = ?1, result_json = ?2, error_msg = ?3
                 WHERE id = ?4",
                rusqlite::params![status, result_json, error_msg, row_id],
            )?;
        } else {
            conn.execute(
                "INSERT INTO workflow_steps (workflow_id, step_name, status, result_json, error_msg)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![run_id, step_name, status, result_json, error_msg],
            )?;
        }

        // Keep the parent run's `updated_at` fresh.
        conn.execute(
            "UPDATE workflow_runs SET updated_at = strftime('%s','now') WHERE id = ?1",
            rusqlite::params![run_id],
        )?;
        drop(conn);
        Ok(())
    }

    /// Query the current status of a workflow run.
    ///
    /// Returns the `status` string from `workflow_runs` (e.g. `"running"`,
    /// `"succeeded"`, `"failed"`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn get_workflow_status(&self, run_id: &str) -> Result<String, WorkflowError> {
        let status: String = {
            let conn = self.sqlite.lock();
            conn.query_row(
                "SELECT status FROM workflow_runs WHERE id = ?1",
                rusqlite::params![run_id],
                |row| row.get(0),
            )
            .map_err(|_| WorkflowError::NotFound(run_id.to_string()))?
        };
        Ok(status)
    }

    /// Update the top-level status of a workflow run.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_workflow_status(&self, run_id: &str, status: &str) -> Result<(), WorkflowError> {
        self.sqlite.lock().execute(
            "UPDATE workflow_runs SET status = ?1, updated_at = strftime('%s','now') WHERE id = ?2",
            rusqlite::params![status, run_id],
        )?;
        Ok(())
    }

    /// Persist a workflow definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn save_workflow(&self, workflow: &Workflow) -> Result<(), WorkflowError> {
        let json = serde_json::to_string(workflow)?;
        self.sqlite.lock().execute(
            "INSERT OR REPLACE INTO workflows (id, name, definition) VALUES (?1, ?2, ?3)",
            rusqlite::params![workflow.id, workflow.name, json],
        )?;
        Ok(())
    }

    /// Load a workflow definition by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn load_workflow(&self, id: &str) -> Result<Workflow, WorkflowError> {
        let json: String = {
            let conn = self.sqlite.lock();
            conn.query_row(
                "SELECT definition FROM workflows WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .map_err(|_| WorkflowError::NotFound(id.to_string()))?
        };
        let wf: Workflow = serde_json::from_str(&json)?;
        Ok(wf)
    }

    /// List all stored workflow ids and names.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn list_workflows(&self) -> Result<Vec<(String, String)>, WorkflowError> {
        let conn = self.sqlite.lock();
        let mut stmt = conn.prepare("SELECT id, name FROM workflows ORDER BY created_at")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let result: Vec<(String, String)> = rows.collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);
        Ok(result)
    }

    /// Persist a workflow execution state.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn save_state(&self, state: &WorkflowState) -> Result<i64, WorkflowError> {
        let status_str = serde_json::to_string(&state.status)?;
        let state_json = serde_json::to_string(state)?;
        let conn = self.sqlite.lock();
        conn.execute(
            "INSERT INTO workflow_states (workflow_id, status, state_json) VALUES (?1, ?2, ?3)",
            rusqlite::params![state.workflow_id, status_str, state_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Load the most recent state for a workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn load_latest_state(&self, workflow_id: &str) -> Result<WorkflowState, WorkflowError> {
        let json: String = {
            let conn = self.sqlite.lock();
            conn.query_row(
                "SELECT state_json FROM workflow_states
                 WHERE workflow_id = ?1
                 ORDER BY updated_at DESC, id DESC LIMIT 1",
                rusqlite::params![workflow_id],
                |row| row.get(0),
            )
            .map_err(|_| WorkflowError::NotFound(workflow_id.to_string()))?
        };
        let state: WorkflowState = serde_json::from_str(&json)?;
        Ok(state)
    }

    /// Delete all states for a workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn delete_states(&self, workflow_id: &str) -> Result<usize, WorkflowError> {
        let count = self.sqlite.lock().execute(
            "DELETE FROM workflow_states WHERE workflow_id = ?1",
            rusqlite::params![workflow_id],
        )?;
        Ok(count)
    }

    /// Attempt to persist a state to `MySQL` (best-effort; errors are non-fatal).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn sync_to_mysql(&self, state: &WorkflowState) -> Result<(), WorkflowError> {
        use mysql::prelude::Queryable;

        let pool_guard = self.mysql_pool.lock();
        let Some(pool) = pool_guard.as_ref() else { return Ok(()) };

        let mut conn = pool
            .get_conn()
            .map_err(|e| WorkflowError::DbError(e.to_string()))?;

        let status_str = serde_json::to_string(&state.status)?;
        let state_json = serde_json::to_string(state)?;

        conn.exec_drop(
            "INSERT INTO workflow_states (workflow_id, status, state_json, updated_at)
             VALUES (?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE status = VALUES(status), state_json = VALUES(state_json), updated_at = NOW()",
            (&state.workflow_id, &status_str, &state_json),
        )
        .map_err(|e| WorkflowError::DbError(e.to_string()))?;

        drop(conn);
        drop(pool_guard);
        Ok(())
    }
}

// ─── No-op agent for testing ─────────────────────────────────────────────────

/// A no-op agent that echoes its task as the result. Used in tests.
pub struct EchoAgent {
    name: String,
    capabilities: Vec<AgentCapability>,
}

impl EchoAgent {
    #[must_use]
    pub fn new(name: impl Into<String>, capabilities: Vec<AgentCapability>) -> Self {
        Self {
            name: name.into(),
            capabilities,
        }
    }
}

#[async_trait]
impl Agent for EchoAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &'static str {
        "Echo agent — returns the task as its result."
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.capabilities.clone()
    }

    async fn process(
        &self,
        input: AgentInput,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        Ok(AgentOutput::simple(
            format!("[{}] {}", self.name, input.task),
            1.0,
        ))
    }

    async fn initialize(&mut self, _config: &AgentConfig) -> Result<(), AgentError> {
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> AgentConfig {
        AgentConfig {
            model: "test".to_string(),
            api_key: "key".to_string(),
            base_url: "http://localhost".to_string(),
            max_tokens: 256,
            temperature: 0.0,
            timeout_ms: 1000,
        }
    }

    fn make_ctx() -> AgentContext {
        AgentContext::new(None, "x86_64", "linux")
    }

    // ── RetryConfig ──────────────────────────────────────────────────────────

    #[test]
    fn test_retry_linear_delay() {
        let r = RetryConfig {
            max_attempts: 3,
            backoff_ms: 100,
            exponential: false,
        };
        assert_eq!(r.delay_ms(1), 0);
        assert_eq!(r.delay_ms(2), 100);
        assert_eq!(r.delay_ms(3), 100);
    }

    #[test]
    fn test_retry_exponential_delay() {
        let r = RetryConfig {
            max_attempts: 5,
            backoff_ms: 100,
            exponential: true,
        };
        assert_eq!(r.delay_ms(1), 0);
        assert_eq!(r.delay_ms(2), 100); // 100 * 2^0
        assert_eq!(r.delay_ms(3), 200); // 100 * 2^1
        assert_eq!(r.delay_ms(4), 400); // 100 * 2^2
    }

    #[test]
    fn test_retry_default() {
        let r = RetryConfig::default();
        assert_eq!(r.max_attempts, 1);
        assert_eq!(r.backoff_ms, 0);
    }

    // ── WorkflowCondition ────────────────────────────────────────────────────

    #[test]
    fn test_condition_always() {
        let state = WorkflowState::new("wf");
        assert!(WorkflowEngine::evaluate_condition(
            &WorkflowCondition::Always,
            &state,
            false
        ));
    }

    #[test]
    fn test_condition_on_success() {
        let state = WorkflowState::new("wf");
        assert!(WorkflowEngine::evaluate_condition(
            &WorkflowCondition::OnSuccess,
            &state,
            true
        ));
        assert!(!WorkflowEngine::evaluate_condition(
            &WorkflowCondition::OnSuccess,
            &state,
            false
        ));
    }

    #[test]
    fn test_condition_on_failure() {
        let state = WorkflowState::new("wf");
        assert!(WorkflowEngine::evaluate_condition(
            &WorkflowCondition::OnFailure,
            &state,
            false
        ));
        assert!(!WorkflowEngine::evaluate_condition(
            &WorkflowCondition::OnFailure,
            &state,
            true
        ));
    }

    #[test]
    fn test_condition_if_var_match() {
        let mut state = WorkflowState::new("wf");
        state.set_var("mode", serde_json::json!("debug"));
        assert!(WorkflowEngine::evaluate_condition(
            &WorkflowCondition::IfVar {
                var: "mode".to_string(),
                eq: serde_json::json!("debug"),
            },
            &state,
            true,
        ));
        assert!(!WorkflowEngine::evaluate_condition(
            &WorkflowCondition::IfVar {
                var: "mode".to_string(),
                eq: serde_json::json!("release"),
            },
            &state,
            true,
        ));
    }

    #[test]
    fn test_condition_if_var_missing() {
        let state = WorkflowState::new("wf");
        assert!(!WorkflowEngine::evaluate_condition(
            &WorkflowCondition::IfVar {
                var: "ghost".to_string(),
                eq: serde_json::json!("x"),
            },
            &state,
            true,
        ));
    }

    // ── WorkflowState ────────────────────────────────────────────────────────

    #[test]
    fn test_workflow_state_vars() {
        let mut s = WorkflowState::new("wf1");
        s.set_var("k", serde_json::json!(42));
        assert_eq!(s.get_var("k"), Some(&serde_json::json!(42)));
        assert!(s.get_var("missing").is_none());
    }

    // ── WorkflowEngine: register + run ───────────────────────────────────────

    #[tokio::test]
    async fn test_engine_register_and_names() {
        let engine = WorkflowEngine::new();
        let agent = Box::new(EchoAgent::new("echo", vec![]));
        engine.register_agent(agent, &make_config()).await.unwrap();
        assert!(engine.agent_names().contains(&"echo".to_string()));
    }

    #[tokio::test]
    async fn test_engine_run_simple_workflow() {
        let engine = WorkflowEngine::new();
        engine
            .register_agent(
                Box::new(EchoAgent::new(
                    "step-agent",
                    vec![AgentCapability::Disassembly],
                )),
                &make_config(),
            )
            .await
            .unwrap();

        let wf = Workflow::new(
            "simple",
            "Simple Test",
            vec![WorkflowStep {
                id: "step1".to_string(),
                agent: "step-agent".to_string(),
                input_mapping: HashMap::new(),
                output_mapping: HashMap::from([("result".to_string(), "output".to_string())]),
                condition: Some(WorkflowCondition::Always),
                retry: RetryConfig::default(),
            }],
            ErrorStrategy::Stop,
        );

        let state = engine
            .run(&wf, HashMap::new(), &make_ctx(), "do work")
            .await
            .unwrap();

        assert_eq!(state.status, WorkflowStatus::Succeeded);
        assert!(state.step_results.contains_key("step1"));
        let output_var = state.get_var("output").unwrap();
        assert!(output_var.as_str().unwrap().contains("do work"));
    }

    #[tokio::test]
    async fn test_engine_run_missing_agent_stop() {
        let engine = WorkflowEngine::new();
        let wf = Workflow::new(
            "fail-wf",
            "Fail",
            vec![WorkflowStep::new("s1", "ghost-agent")],
            ErrorStrategy::Stop,
        );
        let err = engine
            .run(&wf, HashMap::new(), &make_ctx(), "task")
            .await
            .unwrap_err();
        assert!(matches!(err, WorkflowError::StepFailed { .. }));
    }

    #[tokio::test]
    async fn test_engine_run_missing_agent_continue() {
        let engine = WorkflowEngine::new();
        let wf = Workflow::new(
            "cont-wf",
            "Continue",
            vec![
                WorkflowStep::new("s1", "ghost"),
                WorkflowStep {
                    id: "s2".to_string(),
                    agent: "echo".to_string(),
                    input_mapping: HashMap::new(),
                    output_mapping: HashMap::from([("result".to_string(), "s2_out".to_string())]),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Continue,
        );
        engine
            .register_agent(Box::new(EchoAgent::new("echo", vec![])), &make_config())
            .await
            .unwrap();
        let state = engine
            .run(&wf, HashMap::new(), &make_ctx(), "task")
            .await
            .unwrap();
        assert_eq!(state.status, WorkflowStatus::Succeeded);
        assert!(state.variables.contains_key("s1_error"));
    }

    #[tokio::test]
    async fn test_engine_condition_skips_step() {
        let engine = WorkflowEngine::new();
        engine
            .register_agent(Box::new(EchoAgent::new("ea", vec![])), &make_config())
            .await
            .unwrap();

        let wf = Workflow::new(
            "skip-wf",
            "Skip",
            vec![
                WorkflowStep {
                    id: "always".to_string(),
                    agent: "ea".to_string(),
                    input_mapping: HashMap::new(),
                    output_mapping: HashMap::new(),
                    condition: Some(WorkflowCondition::Always),
                    retry: RetryConfig::default(),
                },
                // This step should be skipped because OnFailure is false when previous succeeded.
                WorkflowStep {
                    id: "skipped".to_string(),
                    agent: "ea".to_string(),
                    input_mapping: HashMap::new(),
                    output_mapping: HashMap::from([(
                        "result".to_string(),
                        "skipped_out".to_string(),
                    )]),
                    condition: Some(WorkflowCondition::OnFailure),
                    retry: RetryConfig::default(),
                },
            ],
            ErrorStrategy::Stop,
        );

        let state = engine
            .run(&wf, HashMap::new(), &make_ctx(), "x")
            .await
            .unwrap();
        assert_eq!(state.status, WorkflowStatus::Succeeded);
        // skipped step should not have produced output
        assert!(!state.variables.contains_key("skipped_out"));
    }

    // ── WorkflowStore ────────────────────────────────────────────────────────

    #[test]
    fn test_store_save_and_load_workflow() {
        let store = WorkflowStore::in_memory().unwrap();
        let wf = Workflow::new("wf1", "Test WF", vec![], ErrorStrategy::Stop);
        store.save_workflow(&wf).unwrap();
        let loaded = store.load_workflow("wf1").unwrap();
        assert_eq!(loaded.id, "wf1");
        assert_eq!(loaded.name, "Test WF");
    }

    #[test]
    fn test_store_load_not_found() {
        let store = WorkflowStore::in_memory().unwrap();
        let err = store.load_workflow("ghost").unwrap_err();
        assert!(matches!(err, WorkflowError::NotFound(_)));
    }

    #[test]
    fn test_store_list_workflows() {
        let store = WorkflowStore::in_memory().unwrap();
        let wf1 = Workflow::new("a", "A", vec![], ErrorStrategy::Stop);
        let wf2 = Workflow::new("b", "B", vec![], ErrorStrategy::Continue);
        store.save_workflow(&wf1).unwrap();
        store.save_workflow(&wf2).unwrap();
        let list = store.list_workflows().unwrap();
        assert_eq!(list.len(), 2);
        let ids: Vec<&str> = list.iter().map(|(id, _)| id.as_str()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    #[test]
    fn test_store_save_and_load_state() {
        let store = WorkflowStore::in_memory().unwrap();
        let mut state = WorkflowState::new("wf1");
        state.status = WorkflowStatus::Succeeded;
        state.set_var("key", serde_json::json!("value"));
        store.save_state(&state).unwrap();

        let loaded = store.load_latest_state("wf1").unwrap();
        assert_eq!(loaded.status, WorkflowStatus::Succeeded);
        assert_eq!(loaded.get_var("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn test_store_delete_states() {
        let store = WorkflowStore::in_memory().unwrap();
        let state = WorkflowState::new("wf1");
        store.save_state(&state).unwrap();
        let deleted = store.delete_states("wf1").unwrap();
        assert_eq!(deleted, 1);
        let err = store.load_latest_state("wf1").unwrap_err();
        assert!(matches!(err, WorkflowError::NotFound(_)));
    }

    // ── Built-in workflows ───────────────────────────────────────────────────

    #[test]
    fn test_builtin_workflows_count() {
        let wfs = builtin_workflows();
        assert_eq!(wfs.len(), 6);
    }

    #[test]
    fn test_builtin_workflow_ids() {
        let wfs = builtin_workflows();
        let ids: Vec<&str> = wfs.iter().map(|w| w.id.as_str()).collect();
        assert!(ids.contains(&"full_re_analysis"));
        assert!(ids.contains(&"malware_triage"));
        assert!(ids.contains(&"function_rename"));
        assert!(ids.contains(&"vuln_hunt"));
        assert!(ids.contains(&"analyze_binary"));
        assert!(ids.contains(&"find_vulnerabilities"));
    }

    #[test]
    fn test_builtin_full_re_analysis_steps() {
        let wfs = builtin_workflows();
        let wf = wfs.iter().find(|w| w.id == "full_re_analysis").unwrap();
        assert_eq!(wf.steps.len(), 5);
        assert_eq!(wf.steps[0].id, "disassemble");
        assert_eq!(wf.steps[4].id, "generate_report");
    }

    #[test]
    fn test_builtin_analyze_binary_steps() {
        let wfs = builtin_workflows();
        let wf = wfs.iter().find(|w| w.id == "analyze_binary").unwrap();
        // Must have exactly 6 steps in order.
        assert_eq!(wf.steps.len(), 6);
        assert_eq!(wf.steps[0].id, "load_binary");
        assert_eq!(wf.steps[1].id, "analyze_full");
        assert_eq!(wf.steps[2].id, "cross_refs");
        assert_eq!(wf.steps[3].id, "yara_scan");
        assert_eq!(wf.steps[4].id, "triage_analyze");
        assert_eq!(wf.steps[5].id, "compile_report");
        // Agents
        assert_eq!(wf.steps[0].agent, "loader-agent");
        assert_eq!(wf.steps[1].agent, "disasm-agent");
        assert_eq!(wf.steps[3].agent, "yara-agent");
        assert_eq!(wf.steps[4].agent, "vuln-agent");
        assert_eq!(wf.steps[5].agent, "report-agent");
        // Error strategy allows partial completion
        assert!(matches!(wf.on_error, ErrorStrategy::Continue));
    }

    #[test]
    fn test_builtin_find_vulnerabilities_steps() {
        let wfs = builtin_workflows();
        let wf = wfs.iter().find(|w| w.id == "find_vulnerabilities").unwrap();
        // Must have exactly 4 steps in order.
        assert_eq!(wf.steps.len(), 4);
        assert_eq!(wf.steps[0].id, "load_binary");
        assert_eq!(wf.steps[1].id, "analyze_full");
        assert_eq!(wf.steps[2].id, "vuln_patterns");
        assert_eq!(wf.steps[3].id, "malfind");
        // Agents
        assert_eq!(wf.steps[2].agent, "vuln-agent");
        assert_eq!(wf.steps[3].agent, "forensics-agent");
        // malfind is non-fatal
        assert!(matches!(wf.on_error, ErrorStrategy::Continue));
        // vuln_patterns retries up to 3 times
        assert_eq!(wf.steps[2].retry.max_attempts, 3);
        // vuln_findings stored in output
        assert_eq!(
            wf.steps[2].output_mapping.get("result").map(std::string::String::as_str),
            Some("vuln_findings")
        );
        // malfind_result stored in output
        assert_eq!(
            wf.steps[3].output_mapping.get("result").map(std::string::String::as_str),
            Some("malfind_result")
        );
    }

    // ── WorkflowStatus serialization ─────────────────────────────────────────

    #[test]
    fn test_workflow_status_serialization() {
        let s = WorkflowStatus::Failed("oops".to_string());
        let json = serde_json::to_string(&s).unwrap();
        let back: WorkflowStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, WorkflowStatus::Failed("oops".to_string()));
    }

    // ── WorkflowError display ─────────────────────────────────────────────────

    #[test]
    fn test_workflow_error_display() {
        let e = WorkflowError::StepFailed {
            step: "my_step".to_string(),
            message: "timeout".to_string(),
        };
        assert!(e.to_string().contains("my_step"));
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_workflow_error_cancelled() {
        let e = WorkflowError::Cancelled;
        assert!(e.to_string().contains("cancelled"));
    }
}

// ─── Spec-required types ──────────────────────────────────────────────────────

/// Unique step identifier (spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StepId {
    pub inner: u32,
}

impl StepId {
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self { inner: n }
    }
}

impl std::fmt::Display for StepId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Step({})", self.inner)
    }
}

/// A workflow step with dependency tracking (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecWorkflowStep {
    pub id: StepId,
    pub name: String,
    pub capability: String,
    pub input_template: String,
    pub depends_on: Vec<StepId>,
}

impl SpecWorkflowStep {
    #[must_use]
    pub fn new(id: u32, name: impl Into<String>, cap: impl Into<String>) -> Self {
        Self {
            id: StepId::new(id),
            name: name.into(),
            capability: cap.into(),
            input_template: String::new(),
            depends_on: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_dep(mut self, dep: StepId) -> Self {
        self.depends_on.push(dep);
        self
    }
}

/// Status of a workflow step execution (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed(String),
    Failed(String),
    Skipped,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Running => write!(f, "Running"),
            Self::Completed(s) => write!(f, "Completed({s})"),
            Self::Failed(s) => write!(f, "Failed({s})"),
            Self::Skipped => write!(f, "Skipped"),
        }
    }
}

/// Result of a step execution (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: StepId,
    pub status: StepStatus,
    pub output: Option<serde_json::Value>,
    pub duration_ms: u64,
}

impl StepResult {
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.status, StepStatus::Completed(_))
    }
}

/// Workflow definition with topological ordering (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDef {
    pub name: String,
    pub steps: Vec<SpecWorkflowStep>,
}

impl WorkflowDef {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            steps: Vec::new(),
        }
    }

    pub fn add_step(&mut self, s: SpecWorkflowStep) {
        self.steps.push(s);
    }

    /// Compute topological ordering of steps using Kahn's algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn topological_order(&self) -> Result<Vec<StepId>, SpecWorkflowError> {
        use std::collections::{HashMap as HM, VecDeque};
        let mut in_degree: HM<u32, usize> = HM::new();
        let mut adj: HM<u32, Vec<u32>> = HM::new();

        for s in &self.steps {
            in_degree.entry(s.id.inner).or_insert(0);
            adj.entry(s.id.inner).or_default();
        }

        for s in &self.steps {
            for dep in &s.depends_on {
                // dep must come before s
                let exists = self.steps.iter().any(|st| st.id.inner == dep.inner);
                if !exists {
                    return Err(SpecWorkflowError::MissingStep(dep.inner));
                }
                adj.entry(dep.inner).or_default().push(s.id.inner);
                *in_degree.entry(s.id.inner).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<u32> = in_degree
            .iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(&id, _)| id)
            .collect();
        let mut order = Vec::new();

        while let Some(id) = queue.pop_front() {
            order.push(StepId::new(id));
            if let Some(neighbors) = adj.get(&id) {
                for &next in neighbors {
                    let deg = in_degree.get_mut(&next).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(next);
                    }
                }
            }
        }

        if order.len() != self.steps.len() {
            return Err(SpecWorkflowError::CycleDetected);
        }

        Ok(order)
    }

    /// Validate the workflow: detect cycles and missing dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> Result<(), SpecWorkflowError> {
        self.topological_order()?;
        Ok(())
    }
}

/// Overall workflow run status (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    NotStarted,
    Running,
    Completed,
    Failed(String),
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "NotStarted"),
            Self::Running => write!(f, "Running"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed(s) => write!(f, "Failed({s})"),
        }
    }
}

/// A workflow execution result (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub def_name: String,
    pub results: HashMap<u32, StepResult>,
    pub status: RunStatus,
}

impl WorkflowRun {
    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.results.values().filter(|r| r.succeeded()).count()
    }

    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.results
            .values()
            .filter(|r| matches!(r.status, StepStatus::Failed(_)))
            .count()
    }
}

/// Spec workflow errors.
#[derive(Debug, thiserror::Error)]
pub enum SpecWorkflowError {
    #[error("cycle detected in workflow graph")]
    CycleDetected,
    #[error("missing step: {0}")]
    MissingStep(u32),
    #[error("invalid workflow definition: {0}")]
    InvalidDef(String),
    #[error("step {step} execution failed: {reason}")]
    ExecFailed { step: u32, reason: String },
}

/// Simple workflow executor (spec).
pub struct WorkflowRunner;

impl WorkflowRunner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Execute a workflow: run steps in topological order, marking each Completed.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn execute(&self, def: WorkflowDef) -> WorkflowRun {
        let order = match def.topological_order() {
            Ok(o) => o,
            Err(e) => {
                return WorkflowRun {
                    def_name: def.name,
                    results: HashMap::new(),
                    status: RunStatus::Failed(e.to_string()),
                };
            }
        };

        let mut results = HashMap::new();
        for step_id in &order {
            let step = def.steps.iter().find(|s| s.id == *step_id).unwrap();
            let result = StepResult {
                step_id: *step_id,
                status: StepStatus::Completed(format!("step '{}' completed", step.name)),
                output: Some(serde_json::json!({"step": step.name})),
                duration_ms: 0,
            };
            results.insert(step_id.inner, result);
        }

        WorkflowRun {
            def_name: def.name,
            results,
            status: RunStatus::Completed,
        }
    }
}

impl Default for WorkflowRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;

    fn simple_def() -> WorkflowDef {
        let mut def = WorkflowDef::new("test");
        def.add_step(SpecWorkflowStep::new(1, "step-a", "Analyze"));
        def.add_step(SpecWorkflowStep::new(2, "step-b", "Decompile").with_dep(StepId::new(1)));
        def
    }

    #[test]
    fn test_step_id_display() {
        assert_eq!(StepId::new(5).to_string(), "Step(5)");
    }

    #[test]
    fn test_step_id_new() {
        let id = StepId::new(10);
        assert_eq!(id.inner, 10);
    }

    #[test]
    fn test_spec_workflow_step_new() {
        let s = SpecWorkflowStep::new(1, "analyze", "Analyze");
        assert_eq!(s.id.inner, 1);
        assert_eq!(s.name, "analyze");
        assert!(s.depends_on.is_empty());
    }

    #[test]
    fn test_spec_workflow_step_with_dep() {
        let s = SpecWorkflowStep::new(2, "b", "B").with_dep(StepId::new(1));
        assert_eq!(s.depends_on.len(), 1);
        assert_eq!(s.depends_on[0].inner, 1);
    }

    #[test]
    fn test_step_status_display() {
        assert_eq!(StepStatus::Pending.to_string(), "Pending");
        assert_eq!(StepStatus::Running.to_string(), "Running");
        assert_eq!(
            StepStatus::Completed("ok".to_string()).to_string(),
            "Completed(ok)"
        );
        assert_eq!(
            StepStatus::Failed("err".to_string()).to_string(),
            "Failed(err)"
        );
        assert_eq!(StepStatus::Skipped.to_string(), "Skipped");
    }

    #[test]
    fn test_step_result_succeeded() {
        let r = StepResult {
            step_id: StepId::new(1),
            status: StepStatus::Completed("ok".to_string()),
            output: None,
            duration_ms: 100,
        };
        assert!(r.succeeded());
        let r2 = StepResult {
            step_id: StepId::new(2),
            status: StepStatus::Failed("oops".to_string()),
            output: None,
            duration_ms: 0,
        };
        assert!(!r2.succeeded());
    }

    #[test]
    fn test_workflow_def_new() {
        let def = WorkflowDef::new("my-wf");
        assert_eq!(def.name, "my-wf");
        assert!(def.steps.is_empty());
    }

    #[test]
    fn test_workflow_def_add_step() {
        let mut def = WorkflowDef::new("wf");
        def.add_step(SpecWorkflowStep::new(1, "a", "cap"));
        assert_eq!(def.steps.len(), 1);
    }

    #[test]
    fn test_workflow_def_topological_order_simple() {
        let def = simple_def();
        let order = def.topological_order().unwrap();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0].inner, 1);
        assert_eq!(order[1].inner, 2);
    }

    #[test]
    fn test_workflow_def_topological_order_empty() {
        let def = WorkflowDef::new("empty");
        let order = def.topological_order().unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_workflow_def_validate_ok() {
        let def = simple_def();
        assert!(def.validate().is_ok());
    }

    #[test]
    fn test_workflow_def_validate_missing_dep() {
        let mut def = WorkflowDef::new("bad");
        def.add_step(
            SpecWorkflowStep::new(2, "b", "cap").with_dep(StepId::new(99)), // 99 doesn't exist
        );
        assert!(def.validate().is_err());
    }

    #[test]
    fn test_run_status_display() {
        assert_eq!(RunStatus::NotStarted.to_string(), "NotStarted");
        assert_eq!(RunStatus::Running.to_string(), "Running");
        assert_eq!(RunStatus::Completed.to_string(), "Completed");
        assert_eq!(RunStatus::Failed("x".to_string()).to_string(), "Failed(x)");
    }

    #[test]
    fn test_workflow_run_counts() {
        let mut results = HashMap::new();
        results.insert(
            1u32,
            StepResult {
                step_id: StepId::new(1),
                status: StepStatus::Completed("ok".to_string()),
                output: None,
                duration_ms: 0,
            },
        );
        results.insert(
            2u32,
            StepResult {
                step_id: StepId::new(2),
                status: StepStatus::Failed("err".to_string()),
                output: None,
                duration_ms: 0,
            },
        );
        let run = WorkflowRun {
            def_name: "wf".to_string(),
            results,
            status: RunStatus::Failed("partial".to_string()),
        };
        assert_eq!(run.succeeded_count(), 1);
        assert_eq!(run.failed_count(), 1);
    }

    #[test]
    fn test_workflow_runner_execute() {
        let runner = WorkflowRunner::new();
        let def = simple_def();
        let run = runner.execute(def);
        assert_eq!(run.status, RunStatus::Completed);
        assert_eq!(run.succeeded_count(), 2);
        assert_eq!(run.failed_count(), 0);
    }

    #[test]
    fn test_workflow_runner_execute_empty() {
        let runner = WorkflowRunner::new();
        let def = WorkflowDef::new("empty");
        let run = runner.execute(def);
        assert_eq!(run.status, RunStatus::Completed);
        assert_eq!(run.succeeded_count(), 0);
    }

    #[test]
    fn test_spec_workflow_error_display() {
        let e = SpecWorkflowError::CycleDetected;
        assert!(e.to_string().contains("cycle"));
        let e2 = SpecWorkflowError::MissingStep(5);
        assert!(e2.to_string().contains('5'));
        let e3 = SpecWorkflowError::InvalidDef("bad".to_string());
        assert!(e3.to_string().contains("bad"));
        let e4 = SpecWorkflowError::ExecFailed {
            step: 3,
            reason: "timeout".to_string(),
        };
        assert!(e4.to_string().contains('3'));
        assert!(e4.to_string().contains("timeout"));
    }

    #[test]
    fn test_workflow_run_def_name() {
        let runner = WorkflowRunner::new();
        let def = WorkflowDef::new("my-pipeline");
        let run = runner.execute(def);
        assert_eq!(run.def_name, "my-pipeline");
    }

    #[test]
    fn test_step_result_output() {
        let r = StepResult {
            step_id: StepId::new(1),
            status: StepStatus::Completed("done".to_string()),
            output: Some(serde_json::json!({"key": "value"})),
            duration_ms: 42,
        };
        assert!(r.output.is_some());
        assert_eq!(r.duration_ms, 42);
    }
}

// ─── §31.5  YAML-based workflow definitions ───────────────────────────────────

/// Specification for a workflow input parameter (§31.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InputSpec {
    /// A file-path input; value is a string path.
    File,
    /// An integer input with an optional default.
    Int {
        #[serde(default)]
        default: Option<i64>,
    },
    /// A string input with an optional default.
    String {
        #[serde(default)]
        default: Option<std::string::String>,
    },
    /// A boolean input.
    Bool,
}

/// A single step entry in a YAML workflow definition (§31.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepYaml {
    /// Unique step identifier.
    pub id: std::string::String,
    /// Built-in tool name, e.g. `"binary.info"`.
    #[serde(default)]
    pub tool: Option<std::string::String>,
    /// Custom step name (alternative to `tool`).
    #[serde(default)]
    pub custom: Option<std::string::String>,
    /// Arguments passed to the tool/custom step.  May contain `{{ expr }}`
    /// template expressions that are resolved at runtime.
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// Variable name to store the step's output under.
    #[serde(default)]
    pub out: Option<std::string::String>,
    /// Boolean condition expression; step is skipped when false.
    #[serde(default)]
    pub when: Option<std::string::String>,
    /// What to do when this step fails: `"continue"` or `"fail"` (default).
    #[serde(default)]
    pub on_error: Option<std::string::String>,
    /// Wait condition expression, e.g. `"completed"`.
    #[serde(default)]
    pub wait_until: Option<std::string::String>,
    /// Named inputs for custom steps (key → template expression).
    #[serde(default)]
    pub inputs: Option<HashMap<std::string::String, std::string::String>>,
}

/// Top-level YAML workflow document (§31.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowYaml {
    /// Human-readable workflow name.
    pub name: std::string::String,
    /// Optional description shown in UI / CLI help.
    #[serde(default)]
    pub description: std::string::String,
    /// Declared input parameters for the workflow.
    #[serde(default)]
    pub inputs: HashMap<std::string::String, InputSpec>,
    /// Ordered list of steps.
    pub steps: Vec<StepYaml>,
}

/// Parse a YAML string into a [`WorkflowYaml`].
///
/// # Errors
/// Returns a [`WorkflowError`] if the YAML is malformed or does not conform
/// to the expected schema.
pub fn parse_workflow_yaml(yaml: &str) -> Result<WorkflowYaml, WorkflowError> {
    serde_yaml::from_str(yaml)
        .map_err(|e| WorkflowError::SerializationError(format!("YAML parse error: {e}")))
}

/// Load and parse a YAML workflow file from the file system.
///
/// # Errors
/// Returns a [`WorkflowError`] if the file cannot be read or the YAML is
/// invalid.
pub fn load_workflow_file(path: &std::path::Path) -> Result<WorkflowYaml, WorkflowError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        WorkflowError::SerializationError(format!(
            "cannot read workflow file '{}': {e}",
            path.display()
        ))
    })?;
    parse_workflow_yaml(&content)
}

// ─── TemplateEngine ───────────────────────────────────────────────────────────

/// Lightweight template engine for `{{ expr }}` expressions (§31.5).
///
/// Supported expression forms:
/// - `{{ var }}` – look up `var` in the context and render as JSON.
/// - `{{ var.field }}` – navigate into an object by key.
/// - `{{ len(var) }}` – return the length of an array or string.
pub struct TemplateEngine;

impl TemplateEngine {
    /// Render a template string, substituting every `{{ expr }}` placeholder
    /// with the evaluated value from `context`.
    ///
    /// Unknown variables are replaced with the empty string.
    ///
    /// # Errors
    /// Currently infallible for unknown variables (they silently become `""`).
    /// Returns an error only when the rendered string would be structurally
    /// broken in ways detected by this layer.
    pub fn render(
        template: &str,
        context: &HashMap<std::string::String, serde_json::Value>,
    ) -> Result<std::string::String, WorkflowError> {
        let mut result = template.to_string();
        // Keep replacing until no {{ }} remain or nothing changes.
        while let Some(i) = result.find("{{") {
            let start = i;
            let Some(end_rel) = result[start..].find("}}") else {
                break;
            };
            let end = start + end_rel;
            let expr = result[start + 2..end].trim().to_string();
            let value = Self::eval_expr(&expr, context);
            let new_text = result[..start].to_string() + &value + &result[end + 2..];
            if new_text == result {
                break;
            }
            result = new_text;
        }
        Ok(result)
    }

    /// Evaluate a single template expression against a context map.
    fn eval_expr(
        expr: &str,
        ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> std::string::String {
        // len(var) function
        if let Some(inner) = expr.strip_prefix("len(").and_then(|s| s.strip_suffix(')')) {
            let var = inner.trim();
            return match ctx.get(var) {
                Some(serde_json::Value::Array(arr)) => arr.len().to_string(),
                Some(serde_json::Value::String(s)) => s.len().to_string(),
                Some(serde_json::Value::Object(o)) => o.len().to_string(),
                _ => "0".to_string(),
            };
        }

        // var.field.subfield … navigation
        let mut parts = expr.splitn(2, '.');
        let root = parts.next().unwrap_or("").trim();
        let tail = parts.next();

        let root_val = match ctx.get(root) {
            Some(v) => v.clone(),
            None => return std::string::String::new(),
        };

        let val = match tail {
            None => root_val,
            Some(path) => Self::navigate(&root_val, path),
        };

        Self::value_to_string(&val)
    }

    /// Walk a dot-separated path through a JSON value.
    fn navigate(value: &serde_json::Value, path: &str) -> serde_json::Value {
        let mut cur = value.clone();
        for key in path.split('.') {
            cur = match cur {
                serde_json::Value::Object(ref map) => {
                    map.get(key).cloned().unwrap_or(serde_json::Value::Null)
                }
                serde_json::Value::Array(ref arr) => key.parse::<usize>().map_or(serde_json::Value::Null, |idx| arr.get(idx).cloned().unwrap_or(serde_json::Value::Null)),
                _ => serde_json::Value::Null,
            };
        }
        cur
    }

    /// Convert a JSON value to a human-readable string for template output.
    fn value_to_string(v: &serde_json::Value) -> std::string::String {
        match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => std::string::String::new(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            other => other.to_string(),
        }
    }

    /// Evaluate a boolean condition expression against a context.
    ///
    /// Supported forms:
    /// - `"true"` / `"false"` literals
    /// - `"var"` – truthy if value is not null / false / 0 / empty string / empty array
    /// - `"var == value"` – equality check (value compared as string)
    /// - `"var != value"` – inequality check
    /// - `"completed"` – always `true` (used as a `wait_until` sentinel)
    #[must_use]
    pub fn evaluate_condition(
        expr: &str,
        ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> bool {
        let expr = expr.trim();
        if expr.eq_ignore_ascii_case("true") || expr == "completed" {
            return true;
        }
        if expr.eq_ignore_ascii_case("false") {
            return false;
        }

        // Equality:  var == rhs
        if let Some(pos) = expr.find("==") {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + 2..].trim().trim_matches('"');
            let lhs_val = Self::eval_expr(lhs, ctx);
            return lhs_val == rhs;
        }

        // Inequality:  var != rhs
        if let Some(pos) = expr.find("!=") {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + 2..].trim().trim_matches('"');
            let lhs_val = Self::eval_expr(lhs, ctx);
            return lhs_val != rhs;
        }

        // Plain variable: truthy check
        match ctx.get(expr) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_f64().is_some_and(|f| (f - 0.0).abs() > f64::EPSILON),
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(serde_json::Value::Array(a)) => !a.is_empty(),
            Some(serde_json::Value::Object(o)) => !o.is_empty(),
        }
    }
}

// ─── RunState ─────────────────────────────────────────────────────────────────

/// Execution state produced by [`WorkflowRunner::run_yaml`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    /// Name of the YAML workflow that was executed.
    pub workflow_name: std::string::String,
    /// Named outputs accumulated across all steps.
    pub outputs: HashMap<std::string::String, serde_json::Value>,
    /// Per-step execution log entries (`step_id` → message).
    pub step_log: Vec<(std::string::String, std::string::String)>,
    /// Final run status.
    pub status: RunStatus,
}

impl RunState {
    fn new(name: impl Into<std::string::String>) -> Self {
        Self {
            workflow_name: name.into(),
            outputs: HashMap::new(),
            step_log: Vec::new(),
            status: RunStatus::Running,
        }
    }

    fn log(&mut self, step_id: &str, msg: impl Into<std::string::String>) {
        self.step_log.push((step_id.to_string(), msg.into()));
    }
}

// ─── WorkflowRunner: YAML execution ──────────────────────────────────────────

impl WorkflowRunner {
    /// Execute a parsed [`WorkflowYaml`] with the given named inputs.
    ///
    /// Steps are executed in order.  Template expressions in `args` and
    /// custom-step `inputs` are resolved via [`TemplateEngine`] against the
    /// current execution context (initial inputs merged with step outputs).
    ///
    /// Steps whose `when` condition evaluates to `false` are skipped.
    /// A step with `on_error = "continue"` records the error and moves on;
    /// any other error policy (or unset) stops the run and returns
    /// [`RunStatus::Failed`].
    ///
    /// The dispatcher calls [`WorkflowRunner::dispatch_step`] for each step.
    ///
    /// # Errors
    /// Returns a [`SpecWorkflowError`] if a step fails and `on_error != "continue"`.
    pub fn run_yaml(
        &self,
        yaml: &WorkflowYaml,
        inputs: HashMap<std::string::String, serde_json::Value>,
    ) -> Result<RunState, SpecWorkflowError> {
        let mut state = RunState::new(&yaml.name);

        // Seed context with caller-supplied inputs; apply defaults for missing
        // optional inputs declared in the workflow.
        let mut ctx: HashMap<std::string::String, serde_json::Value> = HashMap::new();
        for (name, spec) in &yaml.inputs {
            match spec {
                InputSpec::Int { default: Some(d) } => {
                    ctx.insert(name.clone(), serde_json::json!(*d));
                }
                InputSpec::String { default: Some(d) } => {
                    ctx.insert(name.clone(), serde_json::Value::String(d.clone()));
                }
                _ => {}
            }
        }
        // Caller-supplied values override defaults.
        ctx.extend(inputs);

        for step in &yaml.steps {
            // Evaluate `when` guard.
            if let Some(cond) = &step.when
                && !TemplateEngine::evaluate_condition(cond, &ctx) {
                    state.log(&step.id, "skipped (when condition false)");
                    continue;
                }

            // Render args template.
            let rendered_args = Self::render_args(step.args.as_ref(), &ctx)?;

            // Render custom-step inputs.
            let rendered_inputs = Self::render_inputs(step.inputs.as_ref(), &ctx)?;

            // Dispatch the step.
            let output = self.dispatch_step(step, rendered_args.as_ref(), &rendered_inputs, &ctx);

            match output {
                Ok(val) => {
                    state.log(&step.id, format!("completed: {val}"));
                    // Store output under declared variable name.
                    if let Some(out_var) = &step.out {
                        ctx.insert(out_var.clone(), val.clone());
                        state.outputs.insert(out_var.clone(), val);
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    state.log(&step.id, format!("error: {err_msg}"));

                    let policy = step.on_error.as_deref().unwrap_or("fail");

                    if policy.eq_ignore_ascii_case("continue") {
                        // Store the error string in context so later steps
                        // can inspect it.
                        let err_key = format!("{}_error", step.id);
                        ctx.insert(err_key.clone(), serde_json::Value::String(err_msg.clone()));
                        state
                            .outputs
                            .insert(err_key, serde_json::Value::String(err_msg));
                    } else {
                        state.status = RunStatus::Failed(err_msg.clone());
                        return Err(SpecWorkflowError::ExecFailed {
                            step: 0,
                            reason: err_msg,
                        });
                    }
                }
            }
        }

        if state.status == RunStatus::Running {
            state.status = RunStatus::Completed;
        }
        Ok(state)
    }

    /// Render template expressions in a step's `args` JSON value.
    fn render_args(
        args: Option<&serde_json::Value>,
        ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> Result<Option<serde_json::Value>, SpecWorkflowError> {
        let Some(v) = args else { return Ok(None) };
        let rendered = Self::render_json_value(v.clone(), ctx)?;
        Ok(Some(rendered))
    }

    /// Recursively walk a JSON value and render every string leaf through
    /// [`TemplateEngine::render`].
    fn render_json_value(
        val: serde_json::Value,
        ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> Result<serde_json::Value, SpecWorkflowError> {
        match val {
            serde_json::Value::String(s) => {
                let rendered = TemplateEngine::render(&s, ctx).map_err(|e| {
                    SpecWorkflowError::InvalidDef(format!("template render error: {e}"))
                })?;
                Ok(serde_json::Value::String(rendered))
            }
            serde_json::Value::Array(arr) => {
                let rendered: Result<Vec<_>, _> = arr
                    .into_iter()
                    .map(|item| Self::render_json_value(item, ctx))
                    .collect();
                Ok(serde_json::Value::Array(rendered?))
            }
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    out.insert(k, Self::render_json_value(v, ctx)?);
                }
                Ok(serde_json::Value::Object(out))
            }
            other => Ok(other),
        }
    }

    /// Render template expressions in a custom step's named `inputs` map.
    fn render_inputs(
        inputs: Option<&HashMap<std::string::String, std::string::String>>,
        ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> Result<HashMap<std::string::String, serde_json::Value>, SpecWorkflowError> {
        let Some(map) = inputs else { return Ok(HashMap::new()) };
        let mut out = HashMap::new();
        for (k, tmpl) in map {
            let rendered = TemplateEngine::render(tmpl, ctx)
                .map_err(|e| SpecWorkflowError::InvalidDef(format!("input render error: {e}")))?;
            out.insert(k.clone(), serde_json::Value::String(rendered));
        }
        Ok(out)
    }

    /// Dispatch a single YAML step to its tool or custom handler.
    ///
    /// This is the extension point for the runtime: concrete implementations
    /// can override what happens for each `tool` or `custom` name.  The
    /// default implementation records the step and returns a JSON object
    /// summarising what would be called.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn dispatch_step(
        &self,
        step: &StepYaml,
        args: Option<&serde_json::Value>,
        inputs: &HashMap<std::string::String, serde_json::Value>,
        _ctx: &HashMap<std::string::String, serde_json::Value>,
    ) -> Result<serde_json::Value, SpecWorkflowError> {
        if let Some(tool) = &step.tool {
            // Built-in tool dispatch.
            let result = serde_json::json!({
                "dispatched": "tool",
                "tool": tool,
                "args": args,
                "step_id": step.id,
            });
            return Ok(result);
        }

        if let Some(custom) = &step.custom {
            // Custom step dispatch.
            let result = serde_json::json!({
                "dispatched": "custom",
                "custom": custom,
                "inputs": inputs,
                "step_id": step.id,
            });
            return Ok(result);
        }

        Err(SpecWorkflowError::InvalidDef(format!(
            "step '{}' has neither 'tool' nor 'custom'",
            step.id
        )))
    }
}

// ─── §31.5 YAML tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod yaml_tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
name: binary_analysis
description: Analyse a binary and report findings
inputs:
  binary:
    type: file
  depth:
    type: int
    default: 3
  label:
    type: string
    default: "unknown"
  verbose:
    type: bool
steps:
  - id: info
    tool: binary.info
    args:
      path: "{{ binary }}"
      depth: "{{ depth }}"
    out: info_result
  - id: decompile
    tool: binary.decompile
    args:
      path: "{{ binary }}"
    out: decompile_result
    when: "verbose"
    on_error: continue
  - id: report
    custom: generate_report
    inputs:
      title: "Report for {{ label }}"
      data: "{{ info_result }}"
    out: final_report
"#;

    #[test]
    fn test_parse_workflow_yaml_basic() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        assert_eq!(wf.name, "binary_analysis");
        assert_eq!(wf.description, "Analyse a binary and report findings");
        assert_eq!(wf.steps.len(), 3);
    }

    #[test]
    fn test_parse_workflow_yaml_inputs() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        assert!(wf.inputs.contains_key("binary"));
        assert!(wf.inputs.contains_key("depth"));
        assert!(wf.inputs.contains_key("label"));
        assert!(wf.inputs.contains_key("verbose"));
        // depth should have default 3
        match wf.inputs.get("depth").unwrap() {
            InputSpec::Int { default: Some(d) } => assert_eq!(*d, 3),
            other => panic!("unexpected: {other:?}"),
        }
        // label should have default "unknown"
        match wf.inputs.get("label").unwrap() {
            InputSpec::String { default: Some(s) } => assert_eq!(s, "unknown"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_parse_workflow_yaml_steps() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        let info = &wf.steps[0];
        assert_eq!(info.id, "info");
        assert_eq!(info.tool.as_deref(), Some("binary.info"));
        assert_eq!(info.out.as_deref(), Some("info_result"));
        assert!(info.when.is_none());

        let dec = &wf.steps[1];
        assert_eq!(dec.id, "decompile");
        assert_eq!(dec.when.as_deref(), Some("verbose"));
        assert_eq!(dec.on_error.as_deref(), Some("continue"));

        let rep = &wf.steps[2];
        assert_eq!(rep.id, "report");
        assert!(rep.tool.is_none());
        assert_eq!(rep.custom.as_deref(), Some("generate_report"));
    }

    #[test]
    fn test_parse_workflow_yaml_invalid() {
        let err = parse_workflow_yaml("{ not: valid yaml for workflow: [").unwrap_err();
        assert!(matches!(err, WorkflowError::SerializationError(_)));
    }

    #[test]
    fn test_load_workflow_file_not_found() {
        let err = load_workflow_file(std::path::Path::new("/nonexistent/path/workflow.yaml"))
            .unwrap_err();
        assert!(matches!(err, WorkflowError::SerializationError(_)));
    }

    // ── TemplateEngine ────────────────────────────────────────────────────────

    fn ctx(pairs: &[(&str, serde_json::Value)]) -> HashMap<std::string::String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn test_template_render_simple_var() {
        let c = ctx(&[("name", serde_json::json!("alice"))]);
        let out = TemplateEngine::render("Hello {{ name }}!", &c).unwrap();
        assert_eq!(out, "Hello alice!");
    }

    #[test]
    fn test_template_render_unknown_var() {
        let c = ctx(&[]);
        let out = TemplateEngine::render("x={{ ghost }}", &c).unwrap();
        assert_eq!(out, "x=");
    }

    #[test]
    fn test_template_render_nested_field() {
        let c = ctx(&[("res", serde_json::json!({"status": "ok", "code": 200}))]);
        let out = TemplateEngine::render("{{ res.status }}/{{ res.code }}", &c).unwrap();
        assert_eq!(out, "ok/200");
    }

    #[test]
    fn test_template_render_len_array() {
        let c = ctx(&[("items", serde_json::json!([1, 2, 3]))]);
        let out = TemplateEngine::render("count={{ len(items) }}", &c).unwrap();
        assert_eq!(out, "count=3");
    }

    #[test]
    fn test_template_render_len_string() {
        let c = ctx(&[("word", serde_json::json!("hello"))]);
        let out = TemplateEngine::render("{{ len(word) }}", &c).unwrap();
        assert_eq!(out, "5");
    }

    #[test]
    fn test_template_render_len_missing() {
        let c = ctx(&[]);
        let out = TemplateEngine::render("{{ len(ghost) }}", &c).unwrap();
        assert_eq!(out, "0");
    }

    #[test]
    fn test_template_render_multiple_placeholders() {
        let c = ctx(&[
            ("a", serde_json::json!("foo")),
            ("b", serde_json::json!("bar")),
        ]);
        let out = TemplateEngine::render("{{ a }}-{{ b }}", &c).unwrap();
        assert_eq!(out, "foo-bar");
    }

    #[test]
    fn test_template_render_no_placeholders() {
        let c = ctx(&[]);
        let out = TemplateEngine::render("plain text", &c).unwrap();
        assert_eq!(out, "plain text");
    }

    #[test]
    fn test_template_evaluate_condition_true_literal() {
        let c = ctx(&[]);
        assert!(TemplateEngine::evaluate_condition("true", &c));
    }

    #[test]
    fn test_template_evaluate_condition_false_literal() {
        let c = ctx(&[]);
        assert!(!TemplateEngine::evaluate_condition("false", &c));
    }

    #[test]
    fn test_template_evaluate_condition_completed() {
        let c = ctx(&[]);
        assert!(TemplateEngine::evaluate_condition("completed", &c));
    }

    #[test]
    fn test_template_evaluate_condition_var_truthy() {
        let c = ctx(&[("verbose", serde_json::json!(true))]);
        assert!(TemplateEngine::evaluate_condition("verbose", &c));
    }

    #[test]
    fn test_template_evaluate_condition_var_falsy_bool() {
        let c = ctx(&[("verbose", serde_json::json!(false))]);
        assert!(!TemplateEngine::evaluate_condition("verbose", &c));
    }

    #[test]
    fn test_template_evaluate_condition_var_missing() {
        let c = ctx(&[]);
        assert!(!TemplateEngine::evaluate_condition("verbose", &c));
    }

    #[test]
    fn test_template_evaluate_condition_eq() {
        let c = ctx(&[("mode", serde_json::json!("debug"))]);
        assert!(TemplateEngine::evaluate_condition("mode == debug", &c));
        assert!(!TemplateEngine::evaluate_condition("mode == release", &c));
    }

    #[test]
    fn test_template_evaluate_condition_ne() {
        let c = ctx(&[("mode", serde_json::json!("debug"))]);
        assert!(TemplateEngine::evaluate_condition("mode != release", &c));
        assert!(!TemplateEngine::evaluate_condition("mode != debug", &c));
    }

    #[test]
    fn test_template_evaluate_condition_empty_string_falsy() {
        let c = ctx(&[("s", serde_json::json!(""))]);
        assert!(!TemplateEngine::evaluate_condition("s", &c));
    }

    #[test]
    fn test_template_evaluate_condition_non_empty_string_truthy() {
        let c = ctx(&[("s", serde_json::json!("hello"))]);
        assert!(TemplateEngine::evaluate_condition("s", &c));
    }

    // ── WorkflowRunner::run_yaml ──────────────────────────────────────────────

    #[test]
    fn test_run_yaml_basic_tool_steps() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        let runner = WorkflowRunner::new();
        // Pass binary so info step args render; verbose=false so decompile skipped.
        let inputs = ctx(&[
            ("binary", serde_json::json!("/bin/ls")),
            ("verbose", serde_json::json!(false)),
        ]);
        let state = runner.run_yaml(&wf, inputs).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        // info step should have produced output
        assert!(state.outputs.contains_key("info_result"));
        // decompile step was skipped (verbose=false)
        assert!(!state.outputs.contains_key("decompile_result"));
    }

    #[test]
    fn test_run_yaml_when_condition_runs_step() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        let runner = WorkflowRunner::new();
        let inputs = ctx(&[
            ("binary", serde_json::json!("/bin/ls")),
            ("verbose", serde_json::json!(true)),
        ]);
        let state = runner.run_yaml(&wf, inputs).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        assert!(state.outputs.contains_key("decompile_result"));
    }

    #[test]
    fn test_run_yaml_default_inputs_applied() {
        let wf = parse_workflow_yaml(SAMPLE_YAML).unwrap();
        let runner = WorkflowRunner::new();
        // supply only required binary; depth and label should get defaults
        let inputs = ctx(&[("binary", serde_json::json!("/bin/ls"))]);
        let state = runner.run_yaml(&wf, inputs).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
    }

    #[test]
    fn test_run_yaml_on_error_continue() {
        // A workflow where a step has no tool AND no custom (will error) but
        // on_error=continue.
        let yaml = r"
name: err_test
inputs: {}
steps:
  - id: bad_step
    on_error: continue
  - id: good_step
    tool: noop.tool
    out: good_out
";
        let wf = parse_workflow_yaml(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let state = runner.run_yaml(&wf, HashMap::new()).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        assert!(state.outputs.contains_key("bad_step_error"));
        assert!(state.outputs.contains_key("good_out"));
    }

    #[test]
    fn test_run_yaml_on_error_fail_stops() {
        let yaml = r"
name: fail_test
inputs: {}
steps:
  - id: bad_step
    on_error: fail
  - id: unreachable
    tool: noop.tool
    out: unreachable_out
";
        let wf = parse_workflow_yaml(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let err = runner.run_yaml(&wf, HashMap::new()).unwrap_err();
        assert!(matches!(err, SpecWorkflowError::ExecFailed { .. }));
    }

    #[test]
    fn test_run_yaml_step_output_propagates() {
        // Verify that `out` variable from one step is visible to the next step's
        // template expressions.
        let yaml = r#"
name: propagate_test
inputs: {}
steps:
  - id: first
    tool: tool.a
    out: first_out
  - id: second
    tool: tool.b
    args:
      from_first: "{{ first_out }}"
    out: second_out
"#;
        let wf = parse_workflow_yaml(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let state = runner.run_yaml(&wf, HashMap::new()).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        // second_out should exist
        assert!(state.outputs.contains_key("second_out"));
    }

    #[test]
    fn test_run_yaml_custom_step_dispatched() {
        let yaml = r#"
name: custom_test
inputs: {}
steps:
  - id: gen
    custom: my_generator
    inputs:
      param: "hello"
    out: gen_out
"#;
        let wf = parse_workflow_yaml(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let state = runner.run_yaml(&wf, HashMap::new()).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        let out = state.outputs.get("gen_out").unwrap();
        assert_eq!(out["dispatched"], "custom");
        assert_eq!(out["custom"], "my_generator");
    }

    #[test]
    fn test_run_yaml_empty_steps() {
        let yaml = r"
name: empty
inputs: {}
steps: []
";
        let wf = parse_workflow_yaml(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let state = runner.run_yaml(&wf, HashMap::new()).unwrap();
        assert_eq!(state.status, RunStatus::Completed);
        assert!(state.outputs.is_empty());
    }
}

// ─── §32  Structured YAML workflow spec (WorkflowSpec / InputDef / StepDef) ──

use std::path::Path;

/// Definition of a single input parameter declared in a YAML workflow.
///
/// The `type_` field uses the string values `"file"`, `"int"`, `"string"`,
/// and `"bool"`.  A `default` may be any JSON-compatible value.  When
/// `required` is omitted it defaults to `false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDef {
    /// Type tag: `"file"`, `"int"`, `"string"`, or `"bool"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// Optional default value (any JSON-compatible type).
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// When `true` the input must be supplied by the caller.
    #[serde(default)]
    pub required: Option<bool>,
}

impl InputDef {
    /// Return `true` if this input must be explicitly supplied.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.required.unwrap_or(false)
    }
}

/// Definition of a single step inside a [`WorkflowSpec`].
///
/// Each step must have exactly one of `tool` or `custom` set.
/// `args` may contain `{{ expr }}` template placeholders.
/// `when` is an optional boolean-expression guard.
/// `on_error` controls failure policy: `"continue"` or `"fail"` (default).
/// `inputs` is a name→template map for custom steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepDef {
    /// Unique identifier for this step within the workflow.
    pub id: String,
    /// Built-in tool name (e.g. `"binary.info"`, `"yara.scan_file"`).
    #[serde(default)]
    pub tool: Option<String>,
    /// Custom step handler name.
    #[serde(default)]
    pub custom: Option<String>,
    /// Arguments for the tool/custom step.  May contain template expressions.
    #[serde(default)]
    pub args: Option<HashMap<String, serde_json::Value>>,
    /// Context variable name under which the step output is stored.
    #[serde(default)]
    pub out: Option<String>,
    /// Boolean condition expression; step is skipped when it evaluates false.
    #[serde(default)]
    pub when: Option<String>,
    /// Error policy: `"continue"` or `"fail"` (default).
    #[serde(default)]
    pub on_error: Option<String>,
    /// Named input map for custom steps (key → template expression).
    #[serde(default)]
    pub inputs: Option<HashMap<String, String>>,
}

impl StepDef {
    /// Return the effective error policy for this step.
    #[must_use]
    pub fn error_policy(&self) -> &str {
        self.on_error.as_deref().unwrap_or("fail")
    }

    /// Return `true` if the step should continue on error.
    #[must_use]
    pub fn continues_on_error(&self) -> bool {
        self.error_policy().eq_ignore_ascii_case("continue")
    }
}

/// Top-level structured YAML workflow specification.
///
/// This is the primary deserialization target for user-authored YAML files.
/// It is more strongly typed than [`WorkflowYaml`] and feeds into
/// [`WorkflowRunner::run_spec`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSpec {
    /// Human-readable workflow name.
    pub name: String,
    /// Optional description shown in CLI / UI help.
    #[serde(default)]
    pub description: Option<String>,
    /// Declared input parameters keyed by name.
    #[serde(default)]
    pub inputs: HashMap<String, InputDef>,
    /// Ordered list of steps.
    pub steps: Vec<StepDef>,
}

impl WorkflowSpec {
    /// Return the names of all inputs that are marked `required: true`.
    #[must_use]
    pub fn required_inputs(&self) -> Vec<&str> {
        self.inputs
            .iter()
            .filter(|(_, def)| def.is_required())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Validate that all required inputs are present in the supplied map.
    ///
    /// Returns `Err` listing any missing names.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate_inputs(
        &self,
        supplied: &HashMap<String, serde_json::Value>,
    ) -> Result<(), WorkflowError> {
        let mut missing: Vec<String> = Vec::new();
        for (name, def) in &self.inputs {
            if def.is_required() && !supplied.contains_key(name.as_str()) {
                missing.push(name.clone());
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(WorkflowError::StepFailed {
                step: "input_validation".to_string(),
                message: format!("missing required inputs: {}", missing.join(", ")),
            })
        }
    }
}

// ─── parse_workflow_spec / load_workflow_spec ─────────────────────────────────

/// Parse a YAML string into a [`WorkflowSpec`].
///
/// # Errors
/// Returns [`WorkflowError::SerializationError`] on any YAML or schema error.
pub fn parse_workflow_spec(yaml: &str) -> Result<WorkflowSpec, WorkflowError> {
    serde_yaml::from_str(yaml)
        .map_err(|e| WorkflowError::SerializationError(format!("spec YAML parse error: {e}")))
}

/// Read a YAML file from `path` and parse it into a [`WorkflowSpec`].
///
/// # Errors
/// Returns [`WorkflowError::SerializationError`] if the file cannot be read
/// or the YAML is structurally invalid.
pub fn load_workflow_spec(path: &Path) -> Result<WorkflowSpec, WorkflowError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        WorkflowError::SerializationError(format!(
            "cannot read spec file '{}': {e}",
            path.display()
        ))
    })?;
    parse_workflow_spec(&content)
}

// ─── TemplateEngine extensions (numeric comparisons via regex) ────────────────

impl TemplateEngine {
    /// Evaluate a numeric or string comparison expression of the form
    /// `"{{ lhs OP rhs }}"`.
    ///
    /// Supported operators: `>`, `>=`, `<`, `<=`, `==`, `!=`.
    /// The outer `{{` / `}}` delimiters are optional; the method handles both
    /// bare expressions (`"len(items) > 0"`) and braced ones
    /// (`"{{ len(items) > 0 }}"`).
    ///
    /// Numeric comparisons are attempted first; if either side cannot be parsed
    /// as `f64` the comparison falls back to lexicographic string comparison.
    ///
    /// # Examples
    /// ```ignore
    /// // "{{ count > 0 }}" where count == 5  →  true
    /// // "{{ mode == 'release' }}" where mode == "debug"  →  false
    /// // "{{ len(items) >= 3 }}" where items is an array of 3  →  true
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn evaluate_comparison(expr: &str, ctx: &HashMap<String, serde_json::Value>) -> bool {
        use regex::Regex;

        // Match: lhs  OP  rhs
        // lhs / rhs may be:  identifier, len(identifier), quoted string, number
        static RE_CMP: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

        // Strip optional {{ }} wrapper.
        let inner = expr.trim();
        let inner = inner
            .strip_prefix("{{")
            .and_then(|s| s.strip_suffix("}}"))
            .map_or(inner, str::trim);

        let re = RE_CMP.get_or_init(|| {
            Regex::new(
                r"^(?P<lhs>[A-Za-z_][A-Za-z0-9_.]*|len\([A-Za-z_][A-Za-z0-9_]*\)|[0-9]+(?:\.[0-9]+)?|'[^']*')\s*(?P<op>>=|<=|!=|==|>|<)\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_.]*|len\([A-Za-z_][A-Za-z0-9_]*\)|[0-9]+(?:\.[0-9]+)?|'[^']*')$"
            )
            .expect("comparison regex is valid")
        });

        let Some(caps) = re.captures(inner) else {
            // Fall back to the simpler evaluate_condition logic.
            return Self::evaluate_condition(inner, ctx);
        };

        let lhs_str = caps.name("lhs").map_or("", |m| m.as_str());
        let op = caps.name("op").map_or("", |m| m.as_str());
        let rhs_str = caps.name("rhs").map_or("", |m| m.as_str());

        let lhs_val = Self::resolve_side(lhs_str, ctx);
        let rhs_val = Self::resolve_side(rhs_str, ctx);

        // Attempt numeric comparison.
        if let (Ok(l), Ok(r)) = (lhs_val.parse::<f64>(), rhs_val.parse::<f64>()) {
            return match op {
                ">" => l > r,
                ">=" => l >= r,
                "<" => l < r,
                "<=" => l <= r,
                "==" => (l - r).abs() < f64::EPSILON,
                "!=" => (l - r).abs() >= f64::EPSILON,
                _ => false,
            };
        }

        // String comparison.
        match op {
            ">" => lhs_val > rhs_val,
            ">=" => lhs_val >= rhs_val,
            "<" => lhs_val < rhs_val,
            "<=" => lhs_val <= rhs_val,
            "==" => lhs_val == rhs_val,
            "!=" => lhs_val != rhs_val,
            _ => false,
        }
    }

    /// Resolve a single expression side (variable lookup, `len()`, literal,
    /// or quoted string) into a plain string for comparison.
    fn resolve_side(side: &str, ctx: &HashMap<String, serde_json::Value>) -> String {
        let side = side.trim();
        // Quoted string literal: 'value'
        if side.starts_with('\'') && side.ends_with('\'') {
            return side[1..side.len() - 1].to_string();
        }
        // len() function
        if side.starts_with("len(") && side.ends_with(')') {
            let inner = &side[4..side.len() - 1];
            return match ctx.get(inner) {
                Some(serde_json::Value::Array(a)) => a.len().to_string(),
                Some(serde_json::Value::String(s)) => s.len().to_string(),
                Some(serde_json::Value::Object(o)) => o.len().to_string(),
                _ => "0".to_string(),
            };
        }
        // Numeric literal — return as-is.
        if side.parse::<f64>().is_ok() {
            return side.to_string();
        }
        // Variable / field path.
        Self::eval_expr(side, ctx)
    }
}

// ─── RunReport ────────────────────────────────────────────────────────────────

/// Status of a single step in a [`RunReport`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepOutcome {
    /// Step completed and produced an output.
    Succeeded,
    /// Step was skipped because its `when` condition was false.
    Skipped,
    /// Step failed; the error message is attached.
    Failed(String),
    /// Step failed but execution continued due to `on_error: continue`.
    FailedContinued(String),
}

/// Record of a single step's execution captured inside a [`RunReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Step id as declared in the workflow YAML.
    pub step_id: String,
    /// Final outcome of this step.
    pub outcome: StepOutcome,
    /// Output produced by the step (if it succeeded and declared `out:`).
    pub output: Option<serde_json::Value>,
    /// Wall-clock duration in milliseconds (approximate).
    pub duration_ms: u64,
}

impl StepRecord {
    /// Return `true` if the step produced a successful result.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.outcome, StepOutcome::Succeeded)
    }

    /// Return `true` if the step was skipped.
    #[must_use]
    pub const fn was_skipped(&self) -> bool {
        matches!(self.outcome, StepOutcome::Skipped)
    }
}

/// Complete report produced after [`WorkflowRunner::run_spec`] finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    /// Name of the workflow that was executed.
    pub workflow_name: String,
    /// Ordered list of step execution records.
    pub steps: Vec<StepRecord>,
    /// Final named outputs accumulated by the run (step `out` variables).
    pub outputs: HashMap<String, serde_json::Value>,
    /// Overall run status.
    pub status: RunStatus,
    /// Total wall-clock duration across all steps (ms).
    pub total_duration_ms: u64,
}

impl RunReport {
    /// Count steps that succeeded.
    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.steps.iter().filter(|s| s.succeeded()).count()
    }

    /// Count steps that were skipped.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.steps.iter().filter(|s| s.was_skipped()).count()
    }

    /// Count steps that failed (with or without continuation).
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| {
                matches!(
                    s.outcome,
                    StepOutcome::Failed(_) | StepOutcome::FailedContinued(_)
                )
            })
            .count()
    }

    /// Return all outputs as a single flattened JSON object.
    #[must_use]
    pub fn outputs_as_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.outputs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }
}

// ─── Built-in step handlers ───────────────────────────────────────────────────

/// Dispatch a built-in tool name to a mock handler and return a JSON result.
///
/// Recognised tool names:
/// - `"binary.info"` – returns mock binary metadata.
/// - `"analyze.full"` – returns a mock full-analysis report.
/// - `"yara.scan_file"` – returns an empty match list.
/// - `"ti.lookup_hash"` – returns an empty TI report.
///
/// Any other name returns a generic `{"tool": "...", "status": "ok"}` object
/// so that workflows can always make progress during testing.
#[must_use]
pub fn dispatch_builtin_tool(
    tool: &str,
    args: &Option<HashMap<String, serde_json::Value>>,
) -> serde_json::Value {
    match tool {
        "binary.info" => {
            let path = args
                .as_ref()
                .and_then(|a| a.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            serde_json::json!({
                "tool": "binary.info",
                "path": path,
                "format": "PE32+",
                "arch": "x86_64",
                "bits": 64,
                "endian": "little",
                "entry_point": "0x140001000",
                "sections": [
                    {"name": ".text",  "vaddr": "0x140001000", "size": 0x10000},
                    {"name": ".rdata", "vaddr": "0x140011000", "size": 0x5000},
                    {"name": ".data",  "vaddr": "0x140016000", "size": 0x2000},
                ],
                "imports_count": 42,
                "exports_count": 0,
                "file_size_bytes": 0x18000,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "status": "ok",
            })
        }

        "analyze.full" => {
            serde_json::json!({
                "tool": "analyze.full",
                "functions_found": 128,
                "strings_found": 512,
                "cross_references": 1024,
                "cfg_nodes": 640,
                "cfg_edges": 980,
                "complexity": {
                    "cyclomatic_avg": 4.2,
                    "max_function": "sub_140002340",
                },
                "potential_vulnerabilities": [],
                "obfuscation_score": 0.12,
                "packer_detected": false,
                "status": "ok",
            })
        }

        "yara.scan_file" => {
            serde_json::json!({
                "tool": "yara.scan_file",
                "matches": [],
                "rules_evaluated": 0,
                "scan_time_ms": 0,
                "status": "ok",
            })
        }

        "ti.lookup_hash" => {
            serde_json::json!({
                "tool": "ti.lookup_hash",
                "hash": null,
                "reputation": "unknown",
                "detections": 0,
                "first_seen": null,
                "last_seen": null,
                "tags": [],
                "sources": [],
                "status": "ok",
            })
        }

        other => {
            serde_json::json!({
                "tool": other,
                "status": "ok",
                "note": "generic mock handler",
            })
        }
    }
}

// ─── WorkflowRunner::run_spec ─────────────────────────────────────────────────

impl WorkflowRunner {
    /// Execute a [`WorkflowSpec`] with caller-supplied named inputs.
    ///
    /// # Execution model
    ///
    /// 1. All required inputs are validated before execution starts.
    /// 2. Default values from [`InputDef::default`] seed the context for any
    ///    input not supplied by the caller.
    /// 3. Steps are executed in declaration order.
    /// 4. Before each step the `when` expression is evaluated; a `false`
    ///    result records a [`StepOutcome::Skipped`] entry and moves on.
    /// 5. Template expressions in `args` and `inputs` are rendered via
    ///    [`TemplateEngine::render`].
    /// 6. Built-in tool steps are dispatched to [`dispatch_builtin_tool`];
    ///    custom steps produce a descriptive JSON object.
    /// 7. The step output is stored in the context under `step.out` (if set)
    ///    so that subsequent steps can reference it via `{{ out_name }}`.
    /// 8. On step failure: if `on_error == "continue"` the error is recorded
    ///    and execution continues; otherwise the run stops and returns
    ///    [`RunStatus::Failed`].
    ///
    /// # Errors
    /// Returns [`WorkflowError`] if required inputs are missing or if a step
    /// fails with the default `"fail"` error policy.
    pub fn run_spec(
        &self,
        spec: WorkflowSpec,
        inputs: HashMap<String, serde_json::Value>,
    ) -> Result<RunReport, WorkflowError> {
        // ── 1. Validate required inputs ─────────────────────────────────────
        spec.validate_inputs(&inputs)?;

        // ── 2. Build initial execution context ──────────────────────────────
        let mut ctx: HashMap<String, serde_json::Value> = HashMap::new();

        // Seed defaults from the spec's input declarations.
        for (name, def) in &spec.inputs {
            if let Some(default_val) = &def.default {
                ctx.insert(name.clone(), default_val.clone());
            }
        }
        // Caller-supplied values override defaults.
        ctx.extend(inputs);

        // ── 3. Execute steps ────────────────────────────────────────────────
        let mut step_records: Vec<StepRecord> = Vec::with_capacity(spec.steps.len());
        let mut outputs: HashMap<String, serde_json::Value> = HashMap::new();
        let mut run_status = RunStatus::Running;
        let mut total_duration_ms: u64 = 0;

        for step in &spec.steps {
            let step_start = std::time::Instant::now();

            // ── 4. Evaluate `when` guard ─────────────────────────────────
            if let Some(when_expr) = &step.when {
                let should_run = if when_expr.contains('>') || when_expr.contains('<') {
                    TemplateEngine::evaluate_comparison(when_expr, &ctx)
                } else {
                    TemplateEngine::evaluate_condition(when_expr, &ctx)
                };

                if !should_run {
                    let duration_ms = u64::try_from(step_start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    total_duration_ms += duration_ms;
                    step_records.push(StepRecord {
                        step_id: step.id.clone(),
                        outcome: StepOutcome::Skipped,
                        output: None,
                        duration_ms,
                    });
                    continue;
                }
            }

            // ── 5. Render template args ──────────────────────────────────
            let rendered_args = Self::render_step_args(step.args.as_ref(), &ctx)?;

            // Render custom-step inputs.
            let rendered_inputs = Self::render_step_inputs(step.inputs.as_ref(), &ctx)?;

            // ── 6. Dispatch to handler ───────────────────────────────────
            let dispatch_result =
                Self::dispatch_spec_step(step, rendered_args.as_ref(), &rendered_inputs, &ctx);

            let duration_ms = u64::try_from(step_start.elapsed().as_millis()).unwrap_or(u64::MAX);
            total_duration_ms += duration_ms;

            match dispatch_result {
                Ok(output_val) => {
                    // ── 7. Store output in context ───────────────────────
                    let stored = step.out.as_ref().map(|out_name| {
                        // If the output object contains a key matching the out
                        // variable name, extract that field; otherwise store
                        // the full output value.
                        let stored_val = if let serde_json::Value::Object(ref obj) = output_val {
                            obj.get(out_name.as_str())
                                .cloned()
                                .unwrap_or_else(|| output_val.clone())
                        } else {
                            output_val.clone()
                        };
                        ctx.insert(out_name.clone(), stored_val.clone());
                        outputs.insert(out_name.clone(), stored_val.clone());
                        stored_val
                    });

                    step_records.push(StepRecord {
                        step_id: step.id.clone(),
                        outcome: StepOutcome::Succeeded,
                        output: stored,
                        duration_ms,
                    });
                }

                // ── 8. Handle step failure ───────────────────────────────
                Err(e) => {
                    let err_msg = e.to_string();

                    if step.continues_on_error() {
                        // Record error in context and continue.
                        let err_key = format!("{}_error", step.id);
                        ctx.insert(err_key.clone(), serde_json::Value::String(err_msg.clone()));
                        outputs.insert(err_key, serde_json::Value::String(err_msg.clone()));
                        step_records.push(StepRecord {
                            step_id: step.id.clone(),
                            outcome: StepOutcome::FailedContinued(err_msg),
                            output: None,
                            duration_ms,
                        });
                    } else {
                        step_records.push(StepRecord {
                            step_id: step.id.clone(),
                            outcome: StepOutcome::Failed(err_msg.clone()),
                            output: None,
                            duration_ms,
                        });
                        let _run_status = RunStatus::Failed(err_msg.clone());
                        return Err(WorkflowError::StepFailed {
                            step: step.id.clone(),
                            message: err_msg,
                        });
                    }
                }
            }
        }

        if run_status == RunStatus::Running {
            run_status = RunStatus::Completed;
        }

        Ok(RunReport {
            workflow_name: spec.name,
            steps: step_records,
            outputs,
            status: run_status,
            total_duration_ms,
        })
    }

    /// Render a `StepDef`'s `args` map using the current context.
    ///
    /// Each value in the map is converted to a string template and rendered
    /// through [`TemplateEngine::render`], then the result is stored back as a
    /// [`serde_json::Value::String`].  Non-string values (numbers, booleans,
    /// arrays, objects) are left unchanged.
    fn render_step_args(
        args: Option<&HashMap<String, serde_json::Value>>,
        ctx: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<HashMap<String, serde_json::Value>>, WorkflowError> {
        let Some(map) = args else { return Ok(None) };
        let mut rendered = HashMap::with_capacity(map.len());
        for (key, val) in map {
            let out = match val {
                serde_json::Value::String(tmpl) => {
                    let s = TemplateEngine::render(tmpl, ctx)?;
                    serde_json::Value::String(s)
                }
                other => other.clone(),
            };
            rendered.insert(key.clone(), out);
        }
        Ok(Some(rendered))
    }

    /// Render a `StepDef`'s `inputs` map (custom steps) through the template
    /// engine.  Each string value may contain `{{ expr }}` placeholders.
    fn render_step_inputs(
        inputs: Option<&HashMap<String, String>>,
        ctx: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, WorkflowError> {
        let Some(map) = inputs else { return Ok(HashMap::new()) };
        let mut rendered = HashMap::with_capacity(map.len());
        for (key, tmpl) in map {
            let s = TemplateEngine::render(tmpl, ctx)?;
            rendered.insert(key.clone(), serde_json::Value::String(s));
        }
        Ok(rendered)
    }

    /// Dispatch a single [`StepDef`] to its handler and return the raw output.
    ///
    /// Built-in tool names are routed through [`dispatch_builtin_tool`].
    /// Custom steps return a descriptive JSON object.
    /// Steps with neither `tool` nor `custom` return an error.
    fn dispatch_spec_step(
        step: &StepDef,
        args: Option<&HashMap<String, serde_json::Value>>,
        inputs: &HashMap<String, serde_json::Value>,
        _ctx: &HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, WorkflowError> {
        if let Some(tool) = &step.tool {
            return Ok(dispatch_builtin_tool(tool, &args.cloned()));
        }

        if let Some(custom) = &step.custom {
            return Ok(serde_json::json!({
                "dispatched": "custom",
                "custom": custom,
                "inputs": inputs,
                "step_id": step.id,
            }));
        }

        Err(WorkflowError::StepFailed {
            step: step.id.clone(),
            message: "step has neither 'tool' nor 'custom'".to_string(),
        })
    }
}

// ─── §32  Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod spec_v2_tests {
    use super::*;

    // ── WorkflowSpec deserialization ─────────────────────────────────────────

    const SPEC_YAML: &str = r#"
name: malware_analysis
description: "Full malware triage workflow"
inputs:
  sample:
    type: file
    required: true
  depth:
    type: int
    default: 2
  label:
    type: string
    default: "unknown"
  verbose:
    type: bool
steps:
  - id: info
    tool: binary.info
    args:
      path: "{{ sample }}"
    out: binary_info
  - id: full_analysis
    tool: analyze.full
    args:
      path: "{{ sample }}"
      depth: "{{ depth }}"
    out: analysis
    when: "verbose"
  - id: yara_scan
    tool: yara.scan_file
    args:
      path: "{{ sample }}"
    out: yara_matches
    on_error: continue
  - id: ti_lookup
    tool: ti.lookup_hash
    args:
      hash: "{{ binary_info.sha256 }}"
    out: ti_report
  - id: report
    custom: generate_report
    inputs:
      binary: "{{ binary_info }}"
      ti: "{{ ti_report }}"
      label: "Analysis of {{ label }}"
    out: final_report
"#;

    fn make_inputs() -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert("sample".to_string(), serde_json::json!("/samples/evil.exe"));
        m
    }

    // ── InputDef ─────────────────────────────────────────────────────────────

    #[test]
    fn test_input_def_required() {
        let def = InputDef {
            type_: "file".to_string(),
            default: None,
            required: Some(true),
        };
        assert!(def.is_required());
    }

    #[test]
    fn test_input_def_not_required_when_omitted() {
        let def = InputDef {
            type_: "string".to_string(),
            default: Some(serde_json::json!("hello")),
            required: None,
        };
        assert!(!def.is_required());
    }

    #[test]
    fn test_input_def_not_required_explicit_false() {
        let def = InputDef {
            type_: "int".to_string(),
            default: Some(serde_json::json!(0)),
            required: Some(false),
        };
        assert!(!def.is_required());
    }

    // ── StepDef ───────────────────────────────────────────────────────────────

    #[test]
    fn test_step_def_error_policy_default() {
        let step = StepDef {
            id: "s".to_string(),
            tool: Some("t".to_string()),
            custom: None,
            args: None,
            out: None,
            when: None,
            on_error: None,
            inputs: None,
        };
        assert_eq!(step.error_policy(), "fail");
        assert!(!step.continues_on_error());
    }

    #[test]
    fn test_step_def_error_policy_continue() {
        let step = StepDef {
            id: "s".to_string(),
            tool: None,
            custom: Some("c".to_string()),
            args: None,
            out: None,
            when: None,
            on_error: Some("continue".to_string()),
            inputs: None,
        };
        assert!(step.continues_on_error());
    }

    // ── parse_workflow_spec ──────────────────────────────────────────────────

    #[test]
    fn test_parse_workflow_spec_name_and_desc() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        assert_eq!(spec.name, "malware_analysis");
        assert_eq!(
            spec.description.as_deref(),
            Some("Full malware triage workflow")
        );
    }

    #[test]
    fn test_parse_workflow_spec_inputs_count() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        assert_eq!(spec.inputs.len(), 4);
    }

    #[test]
    fn test_parse_workflow_spec_required_input() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let sample = spec.inputs.get("sample").unwrap();
        assert_eq!(sample.type_, "file");
        assert!(sample.is_required());
    }

    #[test]
    fn test_parse_workflow_spec_int_default() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let depth = spec.inputs.get("depth").unwrap();
        assert_eq!(depth.type_, "int");
        assert_eq!(depth.default, Some(serde_json::json!(2)));
        assert!(!depth.is_required());
    }

    #[test]
    fn test_parse_workflow_spec_string_default() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let label = spec.inputs.get("label").unwrap();
        assert_eq!(label.default, Some(serde_json::json!("unknown")));
    }

    #[test]
    fn test_parse_workflow_spec_steps_count() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        assert_eq!(spec.steps.len(), 5);
    }

    #[test]
    fn test_parse_workflow_spec_step_fields() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let info = &spec.steps[0];
        assert_eq!(info.id, "info");
        assert_eq!(info.tool.as_deref(), Some("binary.info"));
        assert!(info.custom.is_none());
        assert_eq!(info.out.as_deref(), Some("binary_info"));
        assert!(info.when.is_none());
    }

    #[test]
    fn test_parse_workflow_spec_yara_on_error_continue() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let yara = spec.steps.iter().find(|s| s.id == "yara_scan").unwrap();
        assert!(yara.continues_on_error());
    }

    #[test]
    fn test_parse_workflow_spec_custom_step() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let report = spec.steps.iter().find(|s| s.id == "report").unwrap();
        assert!(report.tool.is_none());
        assert_eq!(report.custom.as_deref(), Some("generate_report"));
        let inputs = report.inputs.as_ref().unwrap();
        assert!(inputs.contains_key("label"));
    }

    #[test]
    fn test_parse_workflow_spec_invalid_yaml() {
        let err = parse_workflow_spec("{ broken: [yaml").unwrap_err();
        assert!(matches!(err, WorkflowError::SerializationError(_)));
    }

    #[test]
    fn test_load_workflow_spec_not_found() {
        let err = load_workflow_spec(Path::new("/nonexistent/path/spec.yaml")).unwrap_err();
        assert!(matches!(err, WorkflowError::SerializationError(_)));
    }

    // ── WorkflowSpec::required_inputs / validate_inputs ─────────────────────

    #[test]
    fn test_required_inputs_list() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let req = spec.required_inputs();
        assert!(req.contains(&"sample"));
        assert!(!req.contains(&"depth"));
    }

    #[test]
    fn test_validate_inputs_passes_with_required() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let inputs = make_inputs();
        assert!(spec.validate_inputs(&inputs).is_ok());
    }

    #[test]
    fn test_validate_inputs_fails_missing_required() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let err = spec.validate_inputs(&HashMap::new()).unwrap_err();
        assert!(matches!(err, WorkflowError::StepFailed { .. }));
        assert!(err.to_string().contains("sample"));
    }

    // ── dispatch_builtin_tool ────────────────────────────────────────────────

    #[test]
    fn test_dispatch_binary_info() {
        let out = dispatch_builtin_tool(
            "binary.info",
            &Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!("/bin/ls"),
            )])),
        );
        assert_eq!(out["tool"], "binary.info");
        assert_eq!(out["arch"], "x86_64");
        assert_eq!(out["status"], "ok");
        assert!(out["sections"].is_array());
    }

    #[test]
    fn test_dispatch_binary_info_unknown_path() {
        let out = dispatch_builtin_tool("binary.info", &None);
        assert_eq!(out["path"], "<unknown>");
    }

    #[test]
    fn test_dispatch_analyze_full() {
        let out = dispatch_builtin_tool("analyze.full", &None);
        assert_eq!(out["tool"], "analyze.full");
        assert!(out["functions_found"].as_u64().unwrap() > 0);
        assert_eq!(out["packer_detected"], false);
    }

    #[test]
    fn test_dispatch_yara_scan_file() {
        let out = dispatch_builtin_tool("yara.scan_file", &None);
        assert_eq!(out["tool"], "yara.scan_file");
        assert!(out["matches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_dispatch_ti_lookup_hash() {
        let out = dispatch_builtin_tool("ti.lookup_hash", &None);
        assert_eq!(out["tool"], "ti.lookup_hash");
        assert_eq!(out["reputation"], "unknown");
        assert!(out["tags"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_dispatch_unknown_tool() {
        let out = dispatch_builtin_tool("some.unknown.tool", &None);
        assert_eq!(out["tool"], "some.unknown.tool");
        assert_eq!(out["status"], "ok");
    }

    // ── TemplateEngine::evaluate_comparison ──────────────────────────────────

    fn ctx(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn test_comparison_numeric_gt() {
        let c = ctx(&[("count", serde_json::json!(5))]);
        assert!(TemplateEngine::evaluate_comparison("count > 0", &c));
        assert!(!TemplateEngine::evaluate_comparison("count > 5", &c));
    }

    #[test]
    fn test_comparison_numeric_gte() {
        let c = ctx(&[("count", serde_json::json!(5))]);
        assert!(TemplateEngine::evaluate_comparison("count >= 5", &c));
        assert!(!TemplateEngine::evaluate_comparison("count >= 6", &c));
    }

    #[test]
    fn test_comparison_numeric_lt() {
        let c = ctx(&[("count", serde_json::json!(3))]);
        assert!(TemplateEngine::evaluate_comparison("count < 5", &c));
        assert!(!TemplateEngine::evaluate_comparison("count < 3", &c));
    }

    #[test]
    fn test_comparison_numeric_eq() {
        let c = ctx(&[("score", serde_json::json!(10))]);
        assert!(TemplateEngine::evaluate_comparison("score == 10", &c));
        assert!(!TemplateEngine::evaluate_comparison("score == 11", &c));
    }

    #[test]
    fn test_comparison_numeric_ne() {
        let c = ctx(&[("score", serde_json::json!(10))]);
        assert!(TemplateEngine::evaluate_comparison("score != 9", &c));
        assert!(!TemplateEngine::evaluate_comparison("score != 10", &c));
    }

    #[test]
    fn test_comparison_len_gt_zero() {
        let c = ctx(&[("items", serde_json::json!([1, 2, 3]))]);
        assert!(TemplateEngine::evaluate_comparison("len(items) > 0", &c));
    }

    #[test]
    fn test_comparison_len_empty() {
        let c = ctx(&[("items", serde_json::json!([]))]);
        assert!(!TemplateEngine::evaluate_comparison("len(items) > 0", &c));
    }

    #[test]
    fn test_comparison_string_eq_quoted() {
        let c = ctx(&[("mode", serde_json::json!("debug"))]);
        assert!(TemplateEngine::evaluate_comparison("mode == 'debug'", &c));
        assert!(!TemplateEngine::evaluate_comparison(
            "mode == 'release'",
            &c
        ));
    }

    #[test]
    fn test_comparison_braced_expression() {
        let c = ctx(&[("x", serde_json::json!(7))]);
        assert!(TemplateEngine::evaluate_comparison("{{ x > 5 }}", &c));
        assert!(!TemplateEngine::evaluate_comparison("{{ x > 7 }}", &c));
    }

    #[test]
    fn test_comparison_fallback_to_condition() {
        // An expression that doesn't match the comparison regex should fall
        // back to evaluate_condition.
        let c = ctx(&[("flag", serde_json::json!(true))]);
        assert!(TemplateEngine::evaluate_comparison("flag", &c));
    }

    // ── RunReport ─────────────────────────────────────────────────────────────

    #[test]
    fn test_run_report_counts() {
        let report = RunReport {
            workflow_name: "test".to_string(),
            steps: vec![
                StepRecord {
                    step_id: "a".to_string(),
                    outcome: StepOutcome::Succeeded,
                    output: None,
                    duration_ms: 10,
                },
                StepRecord {
                    step_id: "b".to_string(),
                    outcome: StepOutcome::Skipped,
                    output: None,
                    duration_ms: 0,
                },
                StepRecord {
                    step_id: "c".to_string(),
                    outcome: StepOutcome::FailedContinued("oops".to_string()),
                    output: None,
                    duration_ms: 5,
                },
            ],
            outputs: HashMap::new(),
            status: RunStatus::Completed,
            total_duration_ms: 15,
        };
        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn test_run_report_outputs_as_json() {
        let mut outputs = HashMap::new();
        outputs.insert("k".to_string(), serde_json::json!(42));
        let report = RunReport {
            workflow_name: "w".to_string(),
            steps: vec![],
            outputs,
            status: RunStatus::Completed,
            total_duration_ms: 0,
        };
        let json = report.outputs_as_json();
        assert_eq!(json["k"], 42);
    }

    // ── WorkflowRunner::run_spec ─────────────────────────────────────────────

    #[test]
    fn test_run_spec_full_workflow() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, make_inputs()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        // info, yara_scan, ti_lookup, report all run (full_analysis skipped; verbose missing)
        assert!(report.outputs.contains_key("binary_info"));
        assert!(report.outputs.contains_key("yara_matches"));
        assert!(report.outputs.contains_key("ti_report"));
        assert!(report.outputs.contains_key("final_report"));
    }

    #[test]
    fn test_run_spec_when_skips_step() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        // verbose not set → full_analysis step should be skipped
        let report = runner.run_spec(spec, make_inputs()).unwrap();
        let full = report
            .steps
            .iter()
            .find(|s| s.step_id == "full_analysis")
            .unwrap();
        assert!(full.was_skipped());
    }

    #[test]
    fn test_run_spec_when_runs_step_when_true() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        let mut inputs = make_inputs();
        inputs.insert("verbose".to_string(), serde_json::json!(true));
        let report = runner.run_spec(spec, inputs).unwrap();
        let full = report
            .steps
            .iter()
            .find(|s| s.step_id == "full_analysis")
            .unwrap();
        assert!(full.succeeded());
        assert!(report.outputs.contains_key("analysis"));
    }

    #[test]
    fn test_run_spec_default_inputs_applied() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        // depth and label not supplied; should use defaults (2 and "unknown")
        let report = runner.run_spec(spec, make_inputs()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
    }

    #[test]
    fn test_run_spec_missing_required_input() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        let err = runner.run_spec(spec, HashMap::new()).unwrap_err();
        assert!(matches!(err, WorkflowError::StepFailed { .. }));
        assert!(err.to_string().contains("sample"));
    }

    #[test]
    fn test_run_spec_on_error_continue() {
        let yaml = r"
name: cont_test
inputs: {}
steps:
  - id: bad
    on_error: continue
  - id: good
    tool: binary.info
    out: good_out
";
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        let bad = report.steps.iter().find(|s| s.step_id == "bad").unwrap();
        assert!(matches!(bad.outcome, StepOutcome::FailedContinued(_)));
        assert!(report.outputs.contains_key("bad_error"));
        assert!(report.outputs.contains_key("good_out"));
    }

    #[test]
    fn test_run_spec_on_error_fail_stops() {
        let yaml = r"
name: fail_test
inputs: {}
steps:
  - id: bad
    on_error: fail
  - id: unreachable
    tool: binary.info
    out: should_not_exist
";
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let err = runner.run_spec(spec, HashMap::new()).unwrap_err();
        assert!(matches!(err, WorkflowError::StepFailed { .. }));
    }

    #[test]
    fn test_run_spec_output_propagation() {
        let yaml = r#"
name: propagate
inputs: {}
steps:
  - id: first
    tool: binary.info
    out: info
  - id: second
    tool: analyze.full
    args:
      note: "arch is {{ info.arch }}"
    out: analysis
"#;
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        assert!(report.outputs.contains_key("info"));
        assert!(report.outputs.contains_key("analysis"));
    }

    #[test]
    fn test_run_spec_custom_step_output() {
        let yaml = r#"
name: custom_out
inputs: {}
steps:
  - id: gen
    custom: my_handler
    inputs:
      msg: "hello world"
    out: gen_out
"#;
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        let out = report.outputs.get("gen_out").unwrap();
        assert_eq!(out["dispatched"], "custom");
        assert_eq!(out["custom"], "my_handler");
    }

    #[test]
    fn test_run_spec_empty_steps() {
        let yaml = r"
name: empty
inputs: {}
steps: []
";
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        assert!(report.steps.is_empty());
        assert!(report.outputs.is_empty());
        assert_eq!(report.total_duration_ms, 0);
    }

    #[test]
    fn test_run_spec_numeric_when_condition() {
        let yaml = r#"
name: numeric_when
inputs:
  count:
    type: int
    default: 5
steps:
  - id: step_gt
    tool: binary.info
    when: "count > 3"
    out: result_gt
  - id: step_lt
    tool: analyze.full
    when: "count < 3"
    out: result_lt
"#;
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        // count defaults to 5: gt step runs, lt step skipped
        assert!(report.outputs.contains_key("result_gt"));
        assert!(!report.outputs.contains_key("result_lt"));
        let lt = report
            .steps
            .iter()
            .find(|s| s.step_id == "step_lt")
            .unwrap();
        assert!(lt.was_skipped());
    }

    #[test]
    fn test_run_spec_len_when_condition() {
        let yaml = r#"
name: len_when
inputs: {}
steps:
  - id: get_matches
    tool: yara.scan_file
    out: matches
  - id: process_matches
    tool: analyze.full
    when: "len(matches) > 0"
    out: analysis
"#;
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        // yara.scan_file returns empty matches → len(matches) == 0 → process_matches skipped
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        let process = report
            .steps
            .iter()
            .find(|s| s.step_id == "process_matches")
            .unwrap();
        assert!(process.was_skipped());
    }

    #[test]
    fn test_step_record_succeeded_flag() {
        let rec = StepRecord {
            step_id: "x".to_string(),
            outcome: StepOutcome::Succeeded,
            output: Some(serde_json::json!({"ok": true})),
            duration_ms: 5,
        };
        assert!(rec.succeeded());
        assert!(!rec.was_skipped());
    }

    #[test]
    fn test_step_record_skipped_flag() {
        let rec = StepRecord {
            step_id: "y".to_string(),
            outcome: StepOutcome::Skipped,
            output: None,
            duration_ms: 0,
        };
        assert!(!rec.succeeded());
        assert!(rec.was_skipped());
    }

    #[test]
    fn test_run_spec_total_duration_accumulates() {
        let spec = parse_workflow_spec(SPEC_YAML).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, make_inputs()).unwrap();
        // Duration should equal sum of all step durations.
        let sum: u64 = report.steps.iter().map(|s| s.duration_ms).sum();
        assert_eq!(report.total_duration_ms, sum);
    }

    #[test]
    fn test_run_spec_binary_info_arch_in_args() {
        // Verify that the arch field from binary.info output propagates
        // into the next step's template args correctly.
        let yaml = r#"
name: arch_prop
inputs: {}
steps:
  - id: info
    tool: binary.info
    out: info
  - id: use_arch
    tool: analyze.full
    args:
      arch: "{{ info.arch }}"
    out: result
"#;
        let spec = parse_workflow_spec(yaml).unwrap();
        let runner = WorkflowRunner::new();
        let report = runner.run_spec(spec, HashMap::new()).unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        assert!(report.outputs.contains_key("result"));
    }
}
