//! Agent execution loop: `AgentState`, `run_iteration()`,
//! tool-use handling, termination detection, and per-run metrics.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{AgentConfig, AgentContext, AgentError, AgentMessage, MessageRole};
use crate::tool_registry::{ToolRegistry, ToolResult};

// â"€â"€â"€ LoopError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors specific to the agent execution loop.
#[derive(Debug, thiserror::Error)]
pub enum LoopError {
    #[error("max iterations ({0}) exceeded")]
    MaxIterationsExceeded(u32),
    #[error("context window exceeded: {tokens} / {limit} tokens")]
    ContextWindowExceeded { tokens: u32, limit: u32 },
    #[error("tool call failed: {tool} \u{2014} {reason}")]
    ToolCallFailed { tool: String, reason: String },
    #[error("no task to execute")]
    NoTask,
    #[error("agent error: {0}")]
    AgentError(String),
    #[error("serialization: {0}")]
    Serialization(String),
}

impl From<AgentError> for LoopError {
    fn from(e: AgentError) -> Self {
        Self::AgentError(e.to_string())
    }
}

// â"€â"€â"€ ToolCallRecord â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A record of a single tool invocation during one loop iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    /// Unique call identifier.
    pub call_id: String,
    /// Name of the tool that was invoked.
    pub tool_name: String,
    /// Arguments passed to the tool (serialized).
    pub arguments: serde_json::Value,
    /// The tool's result.
    pub result: Option<ToolResult>,
    /// Whether the call succeeded.
    pub success: bool,
    /// Time the call was made (ms since epoch).
    pub timestamp_ms: u64,
    /// Duration of the tool execution.
    pub duration_ms: u64,
    /// Error message if the call failed.
    pub error: Option<String>,
}

impl ToolCallRecord {
    /// Create a new pending tool call record.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            arguments,
            result: None,
            success: false,
            timestamp_ms,
            duration_ms: 0,
            error: None,
        }
    }

    /// Fill in the successful result.
    pub fn complete(&mut self, result: ToolResult) {
        self.duration_ms = result.duration_ms;
        self.success = result.success;
        if !result.success {
            self.error.clone_from(&result.message);
        }
        self.result = Some(result);
    }

    /// Fill in a failure result.
    pub fn fail(&mut self, reason: impl Into<String>) {
        let r = reason.into();
        self.error = Some(r.clone());
        self.success = false;
        self.result = Some(ToolResult::failure(r));
    }
}

// â"€â"€â"€ IterationSummary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary of one agent loop iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationSummary {
    /// Iteration number (1-based).
    pub iteration: u32,
    /// Tokens consumed this iteration.
    pub tokens_used: u32,
    /// Tool calls made this iteration.
    pub tool_calls: Vec<ToolCallRecord>,
    /// The model's textual response for this iteration.
    pub response: String,
    /// Whether the loop should terminate after this iteration.
    pub should_terminate: bool,
    /// Duration of this iteration in milliseconds.
    pub duration_ms: u64,
    /// Reason for termination (if `should_terminate` is true).
    pub termination_reason: Option<String>,
}

// â"€â"€â"€ AgentState â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Mutable state threaded through the agent execution loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Conversation history (system + user + assistant turns).
    pub messages: Vec<AgentMessage>,
    /// All tool calls made so far in this run.
    pub tool_calls: Vec<ToolCallRecord>,
    /// Ambient context about the binary being analysed.
    pub context_vars: HashMap<String, serde_json::Value>,
    /// Current task description.
    pub task: String,
    /// Accumulated token count across all iterations.
    pub total_tokens: u32,
    /// Number of iterations completed.
    pub iterations_done: u32,
    /// Whether the loop is finished.
    pub finished: bool,
    /// Final answer produced by the agent, if finished.
    pub final_answer: Option<String>,
}

impl AgentState {
    /// Create a new state for a given task.
    #[must_use]
    pub fn new(task: impl Into<String>) -> Self {
        Self {
            messages: Vec::new(),
            tool_calls: Vec::new(),
            context_vars: HashMap::new(),
            task: task.into(),
            total_tokens: 0,
            iterations_done: 0,
            finished: false,
            final_answer: None,
        }
    }

    /// Push a message onto the conversation history.
    pub fn push_message(&mut self, role: MessageRole, content: impl Into<String>) {
        self.messages.push(AgentMessage::new(role, content));
    }

    /// Add a context variable.
    pub fn set_context(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.context_vars.insert(key.into(), value);
    }

    /// Number of messages in history.
    #[must_use]
    pub const fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Number of tool calls made.
    #[must_use]
    pub const fn tool_call_count(&self) -> usize {
        self.tool_calls.len()
    }

    /// Mark the loop as finished with a final answer.
    pub fn finish(&mut self, answer: impl Into<String>) {
        self.finished = true;
        self.final_answer = Some(answer.into());
    }

    /// Accumulate tokens from this iteration.
    pub const fn add_tokens(&mut self, tokens: u32) {
        self.total_tokens = self.total_tokens.saturating_add(tokens);
        self.iterations_done += 1;
    }

    /// Estimate rough token count for the message history (4 chars â‰ˆ 1 token).
    #[must_use]
    pub fn estimated_token_count(&self) -> u32 {
        let chars: usize = self.messages.iter().map(|m| m.content.len()).sum();
        u32::try_from(chars / 4).unwrap_or(u32::MAX)
    }
}

// â"€â"€â"€ TerminationCondition â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Specifies when the execution loop should stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminationCondition {
    /// Maximum iterations regardless of content.
    pub max_iterations: u32,
    /// Maximum total tokens across all iterations.
    pub max_tokens: u32,
    /// Stop when the model produces a message containing this exact phrase.
    pub stop_phrase: Option<String>,
    /// Stop when no tool calls were made (the model gave a direct answer).
    pub stop_on_no_tool_calls: bool,
}

impl Default for TerminationCondition {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            max_tokens: 32_000,
            stop_phrase: Some("FINAL_ANSWER:".to_string()),
            stop_on_no_tool_calls: true,
        }
    }
}

impl TerminationCondition {
    /// Check whether the state satisfies any termination condition.
    /// Returns `(should_stop, reason)`.
    #[must_use]
    pub fn check(
        &self,
        state: &AgentState,
        last_response: &str,
        tool_calls_this_iter: usize,
    ) -> (bool, Option<String>) {
        if state.iterations_done >= self.max_iterations {
            return (true, Some(format!("max iterations ({}) reached", self.max_iterations)));
        }

        if state.total_tokens >= self.max_tokens {
            return (
                true,
                Some(format!(
                    "token limit ({}) reached ({} used)",
                    self.max_tokens, state.total_tokens
                )),
            );
        }

        if let Some(ref phrase) = self.stop_phrase
            && last_response.contains(phrase.as_str()) {
                return (true, Some(format!("stop phrase '{phrase}' found")));
            }

        if self.stop_on_no_tool_calls && tool_calls_this_iter == 0 && state.iterations_done > 0 {
            return (true, Some("no tool calls \u{2014} direct answer provided".to_string()));
        }

        (false, None)
    }
}

// â"€â"€â"€ AgentLoopMetrics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Metrics gathered over the course of one agent execution loop run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentLoopMetrics {
    /// Total tokens consumed across all iterations.
    pub tokens_used: u64,
    /// Number of iterations executed.
    pub iterations: u32,
    /// Total number of tool calls made.
    pub tool_calls: u64,
    /// Number of successful tool calls.
    pub tool_calls_succeeded: u64,
    /// Number of failed tool calls.
    pub tool_calls_failed: u64,
    /// Total wall-clock duration of the run in milliseconds.
    pub total_duration_ms: u64,
    /// Whether the run completed successfully (reached termination).
    pub completed: bool,
    /// The termination reason, if known.
    pub termination_reason: Option<String>,
    /// Per-iteration summaries.
    pub iteration_summaries: Vec<IterationSummary>,
}

impl AgentLoopMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the outcome of one iteration.
    pub fn record_iteration(&mut self, summary: IterationSummary) {
        self.iterations += 1;
        self.tokens_used += u64::from(summary.tokens_used);
        self.total_duration_ms += summary.duration_ms;

        let succeeded: usize = summary.tool_calls.iter().filter(|c| c.success).count();
        let failed: usize = summary.tool_calls.iter().filter(|c| !c.success).count();

        self.tool_calls += summary.tool_calls.len() as u64;
        self.tool_calls_succeeded += succeeded as u64;
        self.tool_calls_failed += failed as u64;

        if summary.should_terminate {
            self.completed = true;
            self.termination_reason.clone_from(&summary.termination_reason);
        }
        self.iteration_summaries.push(summary);
    }

    /// Tool call success rate (0.0 if no calls).
    #[must_use]
    pub fn tool_success_rate(&self) -> f64 {
        if self.tool_calls == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.tool_calls_succeeded) / crate::casts::u64_to_f64(self.tool_calls)
    }

    /// Average tokens per iteration.
    #[must_use]
    pub fn avg_tokens_per_iteration(&self) -> f64 {
        if self.iterations == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.tokens_used) / f64::from(self.iterations)
    }
}

// â"€â"€â"€ AgentLoop â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Drives the agentic execution loop for a given task.
///
/// On each iteration the loop:
/// 1. Sends the current `AgentState` messages to the LLM backend (simulated here).
/// 2. Parses any tool-use requests from the response.
/// 3. Executes the requested tools via `ToolRegistry`.
/// 4. Appends the tool results to the message history.
/// 5. Checks the `TerminationCondition`.
pub struct AgentLoop {
    config: AgentConfig,
    tool_registry: ToolRegistry,
    termination: TerminationCondition,
    call_id_counter: std::sync::atomic::AtomicU64,
}

impl AgentLoop {
    /// Create a new loop with a custom configuration.
    #[must_use]
    pub fn new(config: AgentConfig, tool_registry: ToolRegistry) -> Self {
        Self {
            config,
            tool_registry,
            termination: TerminationCondition::default(),
            call_id_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Create a loop with built-in tools registered.
    #[must_use]
    pub fn with_builtins(config: AgentConfig) -> Self {
        let mut reg = ToolRegistry::new();
        reg.register_builtins();
        Self::new(config, reg)
    }

    /// Override the default termination condition.
    #[must_use]
    pub fn with_termination(mut self, cond: TerminationCondition) -> Self {
        self.termination = cond;
        self
    }

    /// Run the full agent loop for the given task and context.
    ///
    /// # Errors
    /// Returns `LoopError::MaxIterationsExceeded` or other `LoopError` variants
    /// on hard failure; returns `Ok(metrics)` when the loop terminates normally.
    pub async fn run(
        &self,
        task: impl Into<String>,
        _ctx: &AgentContext,
    ) -> Result<(AgentState, AgentLoopMetrics), LoopError> {
        let task_str = task.into();
        if task_str.trim().is_empty() {
            return Err(LoopError::NoTask);
        }

        let mut state = AgentState::new(task_str.clone());
        let mut metrics = AgentLoopMetrics::new();

        // Prime the conversation.
        state.push_message(
            MessageRole::System,
            "You are a reverse engineering AI assistant. Use available tools to analyze binaries.",
        );
        state.push_message(MessageRole::User, task_str.clone());

        let wall_start = Instant::now();

        loop {
            let iter_start = Instant::now();
            let summary = self.run_iteration(&mut state).await?;

            let should_stop = summary.should_terminate;
            let term_reason = summary.termination_reason.clone();

            metrics.record_iteration(summary);

            if should_stop {
                if let Some(reason) = term_reason {
                    // Extract final answer from last assistant message.
                    if let Some(last_msg) = state
                        .messages
                        .iter()
                        .rev()
                        .find(|m| m.role == MessageRole::Assistant)
                    {
                        let answer = extract_final_answer(&last_msg.content);
                        state.finish(answer);
                    }
                    metrics.termination_reason = Some(reason);
                }
                metrics.completed = true;
                break;
            }

            let _ = iter_start; // used implicitly via IterationSummary.duration_ms
        }

        // Do NOT overwrite total_duration_ms here: record_iteration already
        // accumulates per-iteration durations into it. Overwriting with the
        // wall-clock elapsed would discard the accumulated sum and hide any
        // discrepancy between iterations.
        let _ = wall_start; // retained for potential future debugging
        Ok((state, metrics))
    }

    /// Execute a single loop iteration: simulate LLM response, handle tool calls.
    ///
    /// # Errors
    /// Returns `LoopError` on tool execution failure or context overflow.
    pub async fn run_iteration(
        &self,
        state: &mut AgentState,
    ) -> Result<IterationSummary, LoopError> {
        let iter_start = Instant::now();

        // Check context window.
        let estimated_tokens = state.estimated_token_count();
        if estimated_tokens > self.config.max_tokens {
            return Err(LoopError::ContextWindowExceeded {
                tokens: estimated_tokens,
                limit: self.config.max_tokens,
            });
        }

        // Simulate LLM response (in production: call OpenAI / Anthropic API).
        let (response, simulated_tool_calls) = Self::simulate_llm_response(state);
        // Use ceiling division to avoid under-counting tokens when response.len()
        // is not a multiple of 4 (e.g. 4095 chars â†' 1024 tokens, not 1023).
        let tokens_this_iter = u32::try_from(response.len().div_ceil(4)).unwrap_or(u32::MAX).saturating_add(10);

        // Append assistant message.
        state.push_message(MessageRole::Assistant, response.clone());

        // Handle tool calls.
        let mut call_records: Vec<ToolCallRecord> = Vec::new();
        for (tool_name, tool_args) in &simulated_tool_calls {
            let record = self
                .handle_tool_use(state, tool_name, tool_args.clone())
                .await;
            call_records.push(record);
        }

        state.add_tokens(tokens_this_iter);

        let (should_terminate, term_reason) = self.termination.check(
            state,
            &response,
            simulated_tool_calls.len(),
        );

        Ok(IterationSummary {
            iteration: state.iterations_done,
            tokens_used: tokens_this_iter,
            tool_calls: call_records,
            response,
            should_terminate,
            duration_ms: u64::try_from(iter_start.elapsed().as_millis()).unwrap_or(u64::MAX),
            termination_reason: term_reason,
        })
    }

    /// Handle a single tool-use request: invoke the registry and record the result.
    async fn handle_tool_use(
        &self,
        state: &mut AgentState,
        tool_name: &str,
        tool_args: serde_json::Value,
    ) -> ToolCallRecord {
        let call_id = format!(
            "call_{}",
            self.call_id_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let mut record = ToolCallRecord::new(call_id.clone(), tool_name, tool_args.clone());

        match self.tool_registry.invoke(tool_name, tool_args).await {
            Ok(result) => {
                let result_content = serde_json::to_string(&result.output)
                    .unwrap_or_else(|_| "{}".to_string());
                // log-injection guard: strip CR/LF from the tool name and call
                // id so that a malicious LLM response cannot forge additional
                // "[tool:…]" lines inside the message history.
                let safe_name = tool_name.replace(['\n', '\r'], "_");
                let safe_id = call_id.replace(['\n', '\r'], "_");
                state.push_message(
                    MessageRole::Tool,
                    format!("[tool:{safe_name}:{safe_id}] {result_content}"),
                );
                record.complete(result);
                state.tool_calls.push(record.clone());
            }
            Err(e) => {
                let err_str = e.to_string();
                let safe_name = tool_name.replace(['\n', '\r'], "_");
                let safe_id = call_id.replace(['\n', '\r'], "_");
                state.push_message(
                    MessageRole::Tool,
                    format!("[tool_error:{safe_name}:{safe_id}] {err_str}"),
                );
                record.fail(err_str);
                state.tool_calls.push(record.clone());
            }
        }

        record
    }

    /// Simulate an LLM response for testing (in production: actual API call).
    fn simulate_llm_response(
        state: &AgentState,
    ) -> (String, Vec<(String, serde_json::Value)>) {
        // On the first iteration, make a tool call; on subsequent ones, give a final answer.
        if state.iterations_done == 0 {
            (
                "I'll analyze the binary by searching for relevant symbols.".to_string(),
                vec![(
                    "search_symbols".to_string(),
                    serde_json::json!({"query": "main"}),
                )],
            )
        } else {
            (
                format!(
                    "FINAL_ANSWER: Analysis of '{}' complete. Found {} tool results.",
                    state.task,
                    state.tool_calls.len()
                ),
                vec![],
            )
        }
    }

    /// Return a reference to the tool registry.
    #[must_use]
    pub const fn tool_registry(&self) -> &ToolRegistry {
        &self.tool_registry
    }

    /// Return a reference to the termination condition.
    #[must_use]
    pub const fn termination(&self) -> &TerminationCondition {
        &self.termination
    }
}

/// Extract the final answer from a response that contains the stop phrase.
fn extract_final_answer(response: &str) -> String {
    response.find("FINAL_ANSWER:").map_or_else(
        || response.trim().to_string(),
        |pos| response[pos + "FINAL_ANSWER:".len()..].trim().to_string(),
    )
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> AgentConfig {
        AgentConfig {
            model: "test-model".to_string(),
            api_key: "sk-test".to_string(),
            base_url: "http://localhost".to_string(),
            max_tokens: 8192,
            temperature: 0.0,
            timeout_ms: 5_000,
        }
    }

    fn make_ctx() -> AgentContext {
        AgentContext::new(None, "x86_64", "windows")
    }

    #[test]
    fn test_agent_state_new() {
        let state = AgentState::new("analyze malware.exe");
        assert_eq!(state.task, "analyze malware.exe");
        assert!(!state.finished);
        assert_eq!(state.total_tokens, 0);
        assert_eq!(state.iterations_done, 0);
    }

    #[test]
    fn test_agent_state_push_message() {
        let mut state = AgentState::new("task");
        state.push_message(MessageRole::User, "hello");
        assert_eq!(state.message_count(), 1);
        assert_eq!(state.messages[0].role, MessageRole::User);
    }

    #[test]
    fn test_agent_state_finish() {
        let mut state = AgentState::new("task");
        state.finish("Found 3 vulnerabilities.");
        assert!(state.finished);
        assert_eq!(state.final_answer.as_deref(), Some("Found 3 vulnerabilities."));
    }

    #[test]
    fn test_termination_max_iterations() {
        let mut state = AgentState::new("task");
        state.iterations_done = 10;
        let cond = TerminationCondition { max_iterations: 10, ..Default::default() };
        let (stop, reason) = cond.check(&state, "", 0);
        assert!(stop);
        assert!(reason.unwrap().contains("max iterations"));
    }

    #[test]
    fn test_termination_stop_phrase() {
        let state = AgentState::new("task");
        let cond = TerminationCondition::default();
        let (stop, reason) = cond.check(&state, "FINAL_ANSWER: done", 1);
        assert!(stop);
        assert!(reason.unwrap().contains("stop phrase"));
    }

    #[test]
    fn test_termination_no_tool_calls() {
        let mut state = AgentState::new("task");
        state.iterations_done = 1;
        let cond = TerminationCondition { stop_on_no_tool_calls: true, ..Default::default() };
        let (stop, _) = cond.check(&state, "direct answer", 0);
        assert!(stop);
    }

    #[test]
    fn test_termination_not_triggered() {
        let mut state = AgentState::new("task");
        state.iterations_done = 1;
        let cond = TerminationCondition { max_iterations: 10, ..Default::default() };
        let (stop, _) = cond.check(&state, "thinking...", 1);
        assert!(!stop);
    }

    #[test]
    fn test_tool_call_record_complete() {
        let mut rec = ToolCallRecord::new("call_1", "run_analysis", serde_json::json!({}));
        let result = ToolResult::success(serde_json::json!({"ok": true}), 5);
        rec.complete(result);
        assert!(rec.success);
        assert_eq!(rec.duration_ms, 5);
        assert!(rec.result.is_some());
    }

    #[test]
    fn test_tool_call_record_fail() {
        let mut rec = ToolCallRecord::new("call_2", "bad_tool", serde_json::json!({}));
        rec.fail("tool not found");
        assert!(!rec.success);
        assert_eq!(rec.error.as_deref(), Some("tool not found"));
    }

    #[test]
    fn test_loop_metrics_record_iteration() {
        let mut metrics = AgentLoopMetrics::new();
        let summary = IterationSummary {
            iteration: 1,
            tokens_used: 100,
            tool_calls: vec![],
            response: "test".to_string(),
            should_terminate: false,
            duration_ms: 50,
            termination_reason: None,
        };
        metrics.record_iteration(summary);
        assert_eq!(metrics.iterations, 1);
        assert_eq!(metrics.tokens_used, 100);
        assert_eq!(metrics.total_duration_ms, 50);
    }

    #[test]
    fn test_loop_metrics_tool_success_rate_no_calls() {
        let metrics = AgentLoopMetrics::new();
        assert!((metrics.tool_success_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_agent_loop_full_run() {
        let lp = AgentLoop::with_builtins(make_config());
        let ctx = make_ctx();
        let (state, metrics) = lp.run("Find symbols for main", &ctx).await.unwrap();
        assert!(state.finished);
        assert!(metrics.completed);
        assert!(metrics.iterations >= 1);
        assert!(state.final_answer.is_some());
    }

    #[tokio::test]
    async fn test_agent_loop_empty_task_error() {
        let lp = AgentLoop::with_builtins(make_config());
        let ctx = make_ctx();
        let err = lp.run("  ", &ctx).await.unwrap_err();
        assert!(matches!(err, LoopError::NoTask));
    }

    #[tokio::test]
    async fn test_agent_loop_tool_calls_recorded() {
        let lp = AgentLoop::with_builtins(make_config());
        let ctx = make_ctx();
        let (state, metrics) = lp.run("Analyze 0x401000", &ctx).await.unwrap();
        // The simulated loop always makes one tool call on the first iteration.
        assert!(metrics.tool_calls >= 1);
        assert!(!state.tool_calls.is_empty());
    }

    #[tokio::test]
    async fn test_agent_loop_single_iteration() {
        let lp = AgentLoop::with_builtins(make_config()).with_termination(TerminationCondition {
            max_iterations: 1,
            stop_on_no_tool_calls: false,
            ..Default::default()
        });
        let ctx = make_ctx();
        let (_, metrics) = lp.run("One shot", &ctx).await.unwrap();
        assert_eq!(metrics.iterations, 1);
    }

    #[test]
    fn test_extract_final_answer_with_phrase() {
        let s = "Some thinking... FINAL_ANSWER: Here is the answer.";
        assert_eq!(extract_final_answer(s), "Here is the answer.");
    }

    #[test]
    fn test_extract_final_answer_no_phrase() {
        let s = "Direct answer without phrase.";
        assert_eq!(extract_final_answer(s), "Direct answer without phrase.");
    }

    #[test]
    fn test_agent_state_estimated_tokens() {
        let mut state = AgentState::new("x");
        // 400 chars / 4 â‰ˆ 100 tokens
        state.push_message(MessageRole::User, "a".repeat(400));
        assert_eq!(state.estimated_token_count(), 100);
    }
}
