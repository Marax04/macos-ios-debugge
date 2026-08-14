//! `ai_orchestrator` — AI-driven orchestration of RE tool sequences.
//!
//! Given a high-level RE objective (e.g. "analyse this malware binary"), the
//! orchestrator plans a sequence of tool calls, interprets results, and decides
//! next steps using an LLM-reasoning loop.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Objective / Goal
// ─────────────────────────────────────────────────────────────────────────────

/// The category of a reverse engineering objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectiveKind {
    /// General malware analysis.
    MalwareAnalysis,
    /// Vulnerability research / exploit development.
    VulnResearch,
    /// Protocol / format reverse engineering.
    ProtocolRE,
    /// Firmware analysis.
    FirmwareAnalysis,
    /// Binary diffing / patch analysis.
    BinaryDiff,
    /// Custom objective described entirely in text.
    Custom(String),
}

impl std::fmt::Display for ObjectiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalwareAnalysis => write!(f, "malware_analysis"),
            Self::VulnResearch => write!(f, "vuln_research"),
            Self::ProtocolRE => write!(f, "protocol_re"),
            Self::FirmwareAnalysis => write!(f, "firmware_analysis"),
            Self::BinaryDiff => write!(f, "binary_diff"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// High-level RE objective to be orchestrated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Objective {
    pub id: Uuid,
    pub kind: ObjectiveKind,
    /// Natural-language description of what the analyst wants to achieve.
    pub description: String,
    /// Path to the binary (or binaries) under analysis.
    pub binary_paths: Vec<String>,
    /// Preferred tools (empty = no preference).
    pub preferred_tools: Vec<String>,
    /// Maximum number of tool calls the orchestrator may make.
    pub max_tool_calls: u32,
    /// Overall timeout.
    pub timeout: Duration,
    /// Whether to produce a final written report.
    pub produce_report: bool,
}

impl Objective {
    #[must_use]
    pub fn new(kind: ObjectiveKind, description: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            description: description.into(),
            binary_paths: Vec::new(),
            preferred_tools: Vec::new(),
            max_tool_calls: 50,
            timeout: Duration::from_secs(300),
            produce_report: true,
        }
    }

    #[must_use]
    pub fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.binary_paths.push(path.into());
        self
    }

    #[must_use]
    pub fn with_tool_preference(mut self, tool: impl Into<String>) -> Self {
        self.preferred_tools.push(tool.into());
        self
    }

    #[must_use]
    pub const fn with_max_calls(mut self, n: u32) -> Self {
        self.max_tool_calls = n;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plan — the LLM-generated sequence of steps
// ─────────────────────────────────────────────────────────────────────────────

/// A single planned step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: u32,
    /// Tool to call.
    pub tool_name: String,
    /// Server hint (may be empty for "any").
    pub server_hint: Option<String>,
    /// Parameters template (may contain `{{variable}}` placeholders).
    pub params: Value,
    /// Human-readable rationale for this step.
    pub rationale: String,
    /// Whether this step is required or optional (advisory).
    pub required: bool,
    /// Whether to stop the whole plan if this step fails.
    pub abort_on_failure: bool,
}

impl PlanStep {
    #[must_use]
    pub fn new(step_id: u32, tool: impl Into<String>, params: Value) -> Self {
        Self {
            step_id,
            tool_name: tool.into(),
            server_hint: None,
            params,
            rationale: String::new(),
            required: true,
            abort_on_failure: false,
        }
    }

    #[must_use]
    pub fn with_rationale(mut self, r: impl Into<String>) -> Self {
        self.rationale = r.into();
        self
    }

    #[must_use]
    pub fn abort_on_failure(mut self) -> Self {
        self.abort_on_failure = true;
        self
    }
}

/// A complete orchestration plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorPlan {
    pub plan_id: Uuid,
    pub objective_id: Uuid,
    pub steps: Vec<PlanStep>,
    pub model: String,
    pub reasoning: String,
    pub created_at_ms: u64,
}

impl OrchestratorPlan {
    #[must_use]
    pub fn new(objective_id: Uuid, steps: Vec<PlanStep>, model: impl Into<String>, reasoning: impl Into<String>) -> Self {
        Self {
            plan_id: Uuid::new_v4(),
            objective_id,
            steps,
            model: model.into(),
            reasoning: reasoning.into(),
            created_at_ms: now_ms(),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// StepResult — outcome of executing one plan step
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: u32,
    pub tool_name: String,
    pub server: String,
    pub success: bool,
    pub result: Value,
    pub error: Option<String>,
    pub latency_ms: u64,
    /// Interpretation of the result by the reasoning loop.
    pub interpretation: Option<String>,
}

impl StepResult {
    #[must_use]
    pub fn success(step_id: u32, tool: impl Into<String>, server: impl Into<String>, result: Value, latency_ms: u64) -> Self {
        Self {
            step_id,
            tool_name: tool.into(),
            server: server.into(),
            success: true,
            result,
            error: None,
            latency_ms,
            interpretation: None,
        }
    }

    #[must_use]
    pub fn failure(step_id: u32, tool: impl Into<String>, err: impl Into<String>) -> Self {
        Self {
            step_id,
            tool_name: tool.into(),
            server: String::new(),
            success: false,
            result: Value::Null,
            error: Some(err.into()),
            latency_ms: 0,
            interpretation: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestrationSession
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an orchestration session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Planning,
    Running { step: u32 },
    WaitingForReasoning,
    Completed,
    Failed { reason: String },
    TimedOut,
}

/// A live orchestration session.
pub struct OrchestrationSession {
    pub id: Uuid,
    pub objective: Objective,
    pub plan: Option<OrchestratorPlan>,
    pub step_results: Vec<StepResult>,
    pub status: SessionStatus,
    pub started_at: Instant,
    pub call_count: u32,
    /// Accumulated analysis state (findings, indicators, etc.).
    pub findings: HashMap<String, Value>,
    /// Final report (if `objective.produce_report` is true).
    pub report: Option<String>,
}

impl OrchestrationSession {
    #[must_use]
    pub fn new(objective: Objective) -> Self {
        Self {
            id: Uuid::new_v4(),
            objective,
            plan: None,
            step_results: Vec::new(),
            status: SessionStatus::Planning,
            started_at: Instant::now(),
            call_count: 0,
            findings: HashMap::new(),
            report: None,
        }
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        self.elapsed() > self.objective.timeout
    }

    #[must_use]
    pub fn calls_exhausted(&self) -> bool {
        self.call_count >= self.objective.max_tool_calls
    }

    /// Accumulate a finding from a step result.
    pub fn record_finding(&mut self, key: impl Into<String>, value: Value) {
        self.findings.insert(key.into(), value);
    }

    /// Generate a plain-text summary of findings.
    #[must_use]
    pub fn findings_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("# Analysis Report: {}", self.objective.description));
        lines.push(format!("Objective: {}", self.objective.kind));
        lines.push(format!("Steps executed: {}", self.step_results.len()));
        let success = self.step_results.iter().filter(|r| r.success).count();
        lines.push(format!("Successful steps: {success}"));
        lines.push("\n## Findings".into());
        for (k, v) in &self.findings {
            lines.push(format!("- **{k}**: {v}"));
        }
        lines.push("\n## Step Log".into());
        for r in &self.step_results {
            let status = if r.success { "✓" } else { "✗" };
            lines.push(format!("{status} [step {}] {} → {}", r.step_id, r.tool_name,
                if r.success { "success" } else { r.error.as_deref().unwrap_or("error") }));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlmReasoningTrait — abstraction over actual LLM calls
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over the LLM used for planning and interpretation.
///
/// In production this would call `rustre-agent-llm`.  The trait allows
/// injecting a stub for tests.
pub trait LlmReasoning: Send + Sync {
    /// Generate an initial plan for an objective.
    ///
    /// Returns a list of `(tool_name, params, rationale)` tuples.
    fn plan(
        &self,
        objective: &Objective,
        available_tools: &[String],
    ) -> Result<Vec<(String, Value, String)>, String>;

    /// Interpret a step result and decide whether to continue, adapt, or stop.
    fn interpret(
        &self,
        objective: &Objective,
        step: &PlanStep,
        result: &StepResult,
        findings: &HashMap<String, Value>,
    ) -> InterpretDecision;

    /// Generate a written report from accumulated findings.
    fn write_report(&self, objective: &Objective, findings: &HashMap<String, Value>) -> String;
}

/// Decision returned by the reasoning loop after interpreting a step result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterpretDecision {
    /// Continue with the next planned step.
    Continue,
    /// Skip the next N steps.
    Skip { count: u32 },
    /// Inject additional steps before continuing.
    Inject { steps: Vec<PlanStep> },
    /// Abort the plan (finding is sufficient or error is unrecoverable).
    Abort { reason: String },
    /// Retry the current step with modified params.
    Retry { new_params: Value },
}

// ─────────────────────────────────────────────────────────────────────────────
// StubReasoning — default stub for when no LLM is configured
// ─────────────────────────────────────────────────────────────────────────────

/// A simple rule-based stub reasoner for use without an LLM.
pub struct StubReasoning {
    /// Tool names that should be used in order for each objective kind.
    presets: HashMap<String, Vec<String>>,
}

impl StubReasoning {
    #[must_use]
    pub fn new() -> Self {
        let mut presets: HashMap<String, Vec<String>> = HashMap::new();
        presets.insert(
            "malware_analysis".into(),
            vec!["triage".into(), "strings".into(), "imports".into(), "decompile".into(), "yara_scan".into()],
        );
        presets.insert(
            "vuln_research".into(),
            vec!["disasm".into(), "decompile".into(), "xrefs".into(), "taint_analysis".into()],
        );
        presets.insert(
            "protocol_re".into(),
            vec!["strings".into(), "network_capture".into(), "decompile".into()],
        );
        presets.insert(
            "firmware_analysis".into(),
            vec!["binwalk".into(), "strings".into(), "entropy".into(), "decompile".into()],
        );
        Self { presets }
    }
}

impl Default for StubReasoning {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmReasoning for StubReasoning {
    fn plan(
        &self,
        objective: &Objective,
        available_tools: &[String],
    ) -> Result<Vec<(String, Value, String)>, String> {
        let kind_str = objective.kind.to_string();
        let preset = self.presets.get(&kind_str).cloned().unwrap_or_default();

        // Filter to tools that are actually available
        let tools: Vec<String> = if preset.is_empty() {
            available_tools.iter().take(5).cloned().collect()
        } else {
            preset
                .iter()
                .filter(|t| available_tools.contains(t) || available_tools.is_empty())
                .cloned()
                .collect()
        };

        // Build basic steps with sane default params
        let binary = objective.binary_paths.first().cloned().unwrap_or_else(|| "?".into());
        let steps: Vec<(String, Value, String)> = tools
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                let params = serde_json::json!({ "binary": binary, "step": i });
                let rationale = format!("Step {i}: run {t} on {binary}");
                (t, params, rationale)
            })
            .collect();
        Ok(steps)
    }

    fn interpret(
        &self,
        _objective: &Objective,
        _step: &PlanStep,
        result: &StepResult,
        _findings: &HashMap<String, Value>,
    ) -> InterpretDecision {
        if result.success {
            InterpretDecision::Continue
        } else {
            // On failure, skip and continue (non-critical mode)
            InterpretDecision::Skip { count: 0 }
        }
    }

    fn write_report(&self, objective: &Objective, findings: &HashMap<String, Value>) -> String {
        let mut out = format!(
            "# Automated RE Report\nObjective: {}\n\n## Summary\n",
            objective.description
        );
        for (k, v) in findings {
            out.push_str(&format!("- {k}: {v}\n"));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolDispatch — abstraction for executing tool calls
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over the actual tool-call mechanism.
pub trait ToolDispatch: Send + Sync {
    fn call(&self, tool: &str, server: Option<&str>, params: Value) -> Result<Value, String>;
    fn available_tools(&self) -> Vec<String>;
}

/// Stub dispatcher returning pre-configured or generic responses.
pub struct StubDispatch {
    responses: HashMap<String, Value>,
}

impl StubDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self { responses: HashMap::new() }
    }

    pub fn register(mut self, tool: impl Into<String>, response: Value) -> Self {
        self.responses.insert(tool.into(), response);
        self
    }
}

impl Default for StubDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolDispatch for StubDispatch {
    fn call(&self, tool: &str, _server: Option<&str>, _params: Value) -> Result<Value, String> {
        Ok(self
            .responses
            .get(tool)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"stub": true, "tool": tool})))
    }

    fn available_tools(&self) -> Vec<String> {
        self.responses.keys().cloned().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AiOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// The main AI-driven orchestrator.
pub struct AiOrchestrator {
    reasoner: Box<dyn LlmReasoning>,
    dispatcher: Box<dyn ToolDispatch>,
    model_name: String,
}

impl AiOrchestrator {
    #[must_use]
    pub fn new(
        reasoner: Box<dyn LlmReasoning>,
        dispatcher: Box<dyn ToolDispatch>,
        model_name: impl Into<String>,
    ) -> Self {
        Self {
            reasoner,
            dispatcher,
            model_name: model_name.into(),
        }
    }

    /// Create an orchestrator with stub reasoning and dispatch (for testing).
    #[must_use]
    pub fn with_stubs() -> Self {
        Self::new(
            Box::new(StubReasoning::new()),
            Box::new(StubDispatch::new()),
            "stub",
        )
    }

    /// Run an orchestration session to completion.
    pub fn run(&self, objective: Objective) -> OrchestrationSession {
        let mut session = OrchestrationSession::new(objective);

        // ── Phase 1: Planning ───────────────────────────────────────────────
        session.status = SessionStatus::Planning;
        let available = self.dispatcher.available_tools();
        let plan_steps_raw = match self.reasoner.plan(&session.objective, &available) {
            Ok(s) => s,
            Err(e) => {
                session.status = SessionStatus::Failed { reason: format!("planning failed: {e}") };
                return session;
            }
        };

        let steps: Vec<PlanStep> = plan_steps_raw
            .into_iter()
            .enumerate()
            .map(|(i, (tool, params, rationale))| {
                PlanStep::new(i as u32, tool, params).with_rationale(rationale)
            })
            .collect();

        let plan = OrchestratorPlan::new(
            session.objective.id,
            steps,
            &self.model_name,
            format!("Auto-planned for objective: {}", session.objective.kind),
        );
        session.plan = Some(plan);

        // ── Phase 2: Execution loop ─────────────────────────────────────────
        let plan_steps: Vec<PlanStep> = session.plan.as_ref().unwrap().steps.clone();
        let mut step_queue: std::collections::VecDeque<PlanStep> = plan_steps.into();
        let mut skip_remaining = 0u32;

        while let Some(step) = step_queue.pop_front() {
            // Check time / call limits
            if session.is_timed_out() {
                session.status = SessionStatus::TimedOut;
                break;
            }
            if session.calls_exhausted() {
                session.status = SessionStatus::Failed { reason: "call limit reached".into() };
                break;
            }
            if skip_remaining > 0 {
                skip_remaining -= 1;
                session.step_results.push(StepResult {
                    step_id: step.step_id,
                    tool_name: step.tool_name.clone(),
                    server: String::new(),
                    success: true,
                    result: serde_json::json!({"skipped": true}),
                    error: None,
                    latency_ms: 0,
                    interpretation: Some("skipped by reasoning loop".into()),
                });
                continue;
            }

            session.status = SessionStatus::Running { step: step.step_id };
            session.call_count += 1;

            // Execute the step
            let t_start = Instant::now();
            let call_result = self.dispatcher.call(
                &step.tool_name,
                step.server_hint.as_deref(),
                step.params.clone(),
            );
            let latency_ms = t_start.elapsed().as_millis() as u64;

            let mut step_result = match call_result {
                Ok(v) => StepResult::success(step.step_id, &step.tool_name, "unknown", v, latency_ms),
                Err(e) => StepResult::failure(step.step_id, &step.tool_name, e),
            };

            // ── Phase 3: Reasoning / Interpret ──────────────────────────────
            session.status = SessionStatus::WaitingForReasoning;
            let decision = self.reasoner.interpret(
                &session.objective,
                &step,
                &step_result,
                &session.findings,
            );

            step_result.interpretation = Some(format!("{:?}", decision));

            // Accumulate findings from successful results
            if step_result.success {
                self.extract_findings(&mut session, &step.tool_name, &step_result.result);
            }

            session.step_results.push(step_result.clone());

            // Apply decision
            match decision {
                InterpretDecision::Continue => {}
                InterpretDecision::Skip { count } => { skip_remaining = count; }
                InterpretDecision::Inject { steps: new_steps } => {
                    for s in new_steps.into_iter().rev() {
                        step_queue.push_front(s);
                    }
                }
                InterpretDecision::Abort { reason } => {
                    session.status = SessionStatus::Failed { reason };
                    break;
                }
                InterpretDecision::Retry { new_params } => {
                    let mut retry = step.clone();
                    retry.params = new_params;
                    step_queue.push_front(retry);
                }
            }
        }

        // ── Phase 4: Report generation ──────────────────────────────────────
        if session.objective.produce_report && !matches!(session.status, SessionStatus::Failed { .. }) {
            session.report = Some(self.reasoner.write_report(&session.objective, &session.findings));
        }

        if matches!(session.status, SessionStatus::Running { .. } | SessionStatus::WaitingForReasoning | SessionStatus::Planning) {
            session.status = SessionStatus::Completed;
        }

        session
    }

    /// Simple heuristic extraction of findings from tool output.
    fn extract_findings(&self, session: &mut OrchestrationSession, tool: &str, result: &Value) {
        // Suspicious strings → finding
        if let Some(strings) = result.get("strings").and_then(Value::as_array) {
            let suspicious: Vec<&str> = strings
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| {
                    s.contains("http://")
                        || s.contains("https://")
                        || s.len() > 20
                })
                .take(20)
                .collect();
            if !suspicious.is_empty() {
                session.record_finding(
                    format!("{tool}.suspicious_strings"),
                    serde_json::json!(suspicious),
                );
            }
        }
        // Imports
        if let Some(imports) = result.get("imports").and_then(Value::as_array) {
            session.record_finding(
                format!("{tool}.imports"),
                serde_json::json!(imports.len()),
            );
        }
        // YARA matches
        if let Some(matches) = result.get("matches") {
            session.record_finding(format!("{tool}.yara_matches"), matches.clone());
        }
        // Decompiled code length
        if let Some(code) = result.get("code").and_then(Value::as_str) {
            session.record_finding(
                format!("{tool}.code_len"),
                serde_json::json!(code.len()),
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorBuilder — fluent construction
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for `AiOrchestrator`.
pub struct OrchestratorBuilder {
    reasoner: Option<Box<dyn LlmReasoning>>,
    dispatcher: Option<Box<dyn ToolDispatch>>,
    model_name: String,
}

impl OrchestratorBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            reasoner: None,
            dispatcher: None,
            model_name: "default".into(),
        }
    }

    #[must_use]
    pub fn with_reasoner(mut self, r: Box<dyn LlmReasoning>) -> Self {
        self.reasoner = Some(r);
        self
    }

    #[must_use]
    pub fn with_dispatcher(mut self, d: Box<dyn ToolDispatch>) -> Self {
        self.dispatcher = Some(d);
        self
    }

    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model_name = model.into();
        self
    }

    #[must_use]
    pub fn build(self) -> AiOrchestrator {
        AiOrchestrator::new(
            self.reasoner.unwrap_or_else(|| Box::new(StubReasoning::new())),
            self.dispatcher.unwrap_or_else(|| Box::new(StubDispatch::new())),
            self.model_name,
        )
    }
}

impl Default for OrchestratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dispatch() -> StubDispatch {
        StubDispatch::new()
            .register("triage", serde_json::json!({"file_type": "PE32", "arch": "x86"}))
            .register("strings", serde_json::json!({"strings": ["http://evil.com", "cmd.exe"]}))
            .register("imports", serde_json::json!({"imports": ["VirtualAlloc", "WriteProcessMemory"]}))
            .register("decompile", serde_json::json!({"code": "int main(){ return 0; }"}))
            .register("yara_scan", serde_json::json!({"matches": ["Mirai.A"]}))
    }

    #[test]
    fn test_malware_analysis_run() {
        let orchestrator = AiOrchestrator::new(
            Box::new(StubReasoning::new()),
            Box::new(make_dispatch()),
            "stub-model",
        );
        let obj = Objective::new(ObjectiveKind::MalwareAnalysis, "Analyse suspicious PE")
            .with_binary("/samples/evil.exe");
        let session = orchestrator.run(obj);
        assert_eq!(session.status, SessionStatus::Completed);
        assert!(!session.step_results.is_empty());
    }

    #[test]
    fn test_findings_extraction() {
        let orchestrator = AiOrchestrator::new(
            Box::new(StubReasoning::new()),
            Box::new(make_dispatch()),
            "stub",
        );
        let obj = Objective::new(ObjectiveKind::MalwareAnalysis, "Test findings")
            .with_binary("/bin/test");
        let session = orchestrator.run(obj);
        // Should have found strings and yara matches
        assert!(!session.findings.is_empty());
    }

    #[test]
    fn test_report_generated() {
        let orchestrator = AiOrchestrator::with_stubs();
        let obj = Objective::new(ObjectiveKind::VulnResearch, "Find overflow").with_binary("/bin/vuln");
        let session = orchestrator.run(obj);
        assert!(session.report.is_some());
        let report = session.report.unwrap();
        assert!(report.contains("Objective") || report.contains("Report"));
    }

    #[test]
    fn test_max_calls_limit() {
        let orchestrator = AiOrchestrator::new(
            Box::new(StubReasoning::new()),
            Box::new(make_dispatch()),
            "stub",
        );
        let obj = Objective::new(ObjectiveKind::MalwareAnalysis, "Limit test")
            .with_max_calls(2);
        let session = orchestrator.run(obj);
        assert!(session.call_count <= 2);
    }

    #[test]
    fn test_objective_builder() {
        let obj = Objective::new(ObjectiveKind::FirmwareAnalysis, "Firmware RE")
            .with_binary("/fw/image.bin")
            .with_tool_preference("binwalk")
            .with_max_calls(10);
        assert_eq!(obj.binary_paths, vec!["/fw/image.bin"]);
        assert_eq!(obj.preferred_tools, vec!["binwalk"]);
        assert_eq!(obj.max_tool_calls, 10);
    }

    #[test]
    fn test_stub_reasoning_plan() {
        let r = StubReasoning::new();
        let obj = Objective::new(ObjectiveKind::MalwareAnalysis, "test");
        let tools = vec!["triage".into(), "strings".into(), "decompile".into()];
        let plan = r.plan(&obj, &tools).unwrap();
        assert!(!plan.is_empty());
        assert_eq!(plan[0].0, "triage");
    }

    #[test]
    fn test_stub_reasoning_interpret_success() {
        let r = StubReasoning::new();
        let obj = Objective::new(ObjectiveKind::MalwareAnalysis, "test");
        let step = PlanStep::new(0, "decompile", serde_json::json!({}));
        let result = StepResult::success(0, "decompile", "ghidra", serde_json::json!({}), 10);
        let dec = r.interpret(&obj, &step, &result, &HashMap::new());
        assert!(matches!(dec, InterpretDecision::Continue));
    }

    #[test]
    fn test_orchestrator_builder() {
        let orch = OrchestratorBuilder::new()
            .with_reasoner(Box::new(StubReasoning::new()))
            .with_dispatcher(Box::new(StubDispatch::new()))
            .with_model("claude-sonnet")
            .build();
        assert_eq!(orch.model_name, "claude-sonnet");
    }

    #[test]
    fn test_session_findings_summary() {
        let mut session = OrchestrationSession::new(
            Objective::new(ObjectiveKind::MalwareAnalysis, "summary test")
        );
        session.record_finding("malware_family", serde_json::json!("Mirai"));
        session.step_results.push(StepResult::success(0, "yara", "srv", serde_json::json!({}), 5));
        let summary = session.findings_summary();
        assert!(summary.contains("Mirai"));
        assert!(summary.contains("yara"));
    }

    #[test]
    fn test_objective_kind_display() {
        assert_eq!(ObjectiveKind::MalwareAnalysis.to_string(), "malware_analysis");
        assert_eq!(ObjectiveKind::Custom("re-me".into()).to_string(), "custom:re-me");
    }
}
