//! LLM tool-call loop — drives the LLM → tool → LLM iteration cycle.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use rustre_agent::casts::{usize_to_f64, usize_to_u32};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum LoopError {
    #[error("LLM error: {0}")]
    LlmError(String),
    #[error("tool execution error for '{tool}': {reason}")]
    ToolError { tool: String, reason: String },
    #[error("maximum iterations ({0}) exceeded")]
    MaxIterations(u32),
    #[error("loop aborted: {0}")]
    Aborted(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unknown tool: {0}")]
    UnknownTool(String),
}

// ─── ToolCallRequest ─────────────────────────────────────────────────────────

/// A tool invocation requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    /// Unique call ID (assigned by the LLM, e.g. `"call_abc123"`).
    pub id: String,
    /// Tool name to invoke.
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: serde_json::Value,
    /// Order within this turn (0-indexed).
    pub turn_index: u32,
}

impl ToolCallRequest {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
            turn_index: 0,
        }
    }

    /// Get a string argument field.
    #[must_use]
    pub fn get_str_arg(&self, key: &str) -> Option<&str> {
        self.arguments.get(key).and_then(|v| v.as_str())
    }

    /// Get an integer argument field.
    #[must_use]
    pub fn get_u64_arg(&self, key: &str) -> Option<u64> {
        self.arguments.get(key).and_then(serde_json::Value::as_u64)
    }

    /// Deserialize arguments into a concrete type.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::Serialization`] if the JSON arguments cannot be deserialized.
    pub fn parse_args<T: serde::de::DeserializeOwned>(&self) -> Result<T, LoopError> {
        serde_json::from_value(self.arguments.clone())
            .map_err(|e| LoopError::Serialization(e.to_string()))
    }
}

// ─── ToolCallResult ───────────────────────────────────────────────────────────

/// The result of executing a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// The ID from the originating `ToolCallRequest`.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// Output to feed back to the LLM.
    pub output: String,
    /// Whether this result represents an error.
    pub is_error: bool,
    /// Optional structured output (if the tool returns JSON).
    pub structured: Option<serde_json::Value>,
    /// Execution duration.
    pub duration_ms: u64,
}

impl ToolCallResult {
    /// Successful text result.
    #[must_use]
    pub fn success(
        id: impl Into<String>,
        name: impl Into<String>,
        output: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            output: output.into(),
            is_error: false,
            structured: None,
            duration_ms: 0,
        }
    }

    /// Error result.
    #[must_use]
    pub fn error(
        id: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            output: reason.into(),
            is_error: true,
            structured: None,
            duration_ms: 0,
        }
    }

    /// Builder: add structured JSON output.
    #[must_use]
    pub fn with_structured(mut self, v: serde_json::Value) -> Self {
        self.structured = Some(v);
        self
    }

    /// Builder: record execution time.
    #[must_use]
    pub const fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }
}

// ─── LoopTermination ─────────────────────────────────────────────────────────

/// Reason why the tool-call loop ended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LoopTermination {
    /// The LLM produced a final text response with no more tool calls.
    NaturalEnd,
    /// The maximum number of iterations was reached.
    MaxIterations,
    /// An error occurred.
    Error(String),
    /// The loop was explicitly stopped.
    Aborted,
    /// The LLM explicitly signaled it is done (e.g. stop sequence).
    StopSequence,
}

impl fmt::Display for LoopTermination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NaturalEnd => write!(f, "natural_end"),
            Self::MaxIterations => write!(f, "max_iterations"),
            Self::Error(e) => write!(f, "error:{e}"),
            Self::Aborted => write!(f, "aborted"),
            Self::StopSequence => write!(f, "stop_sequence"),
        }
    }
}

// ─── LoopTurn ────────────────────────────────────────────────────────────────

/// One turn in the tool-call loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopTurn {
    /// Turn number (0-indexed).
    pub index: u32,
    /// Text produced by the LLM at this turn.
    pub llm_text: String,
    /// Tool calls requested by the LLM at this turn.
    pub requests: Vec<ToolCallRequest>,
    /// Results of executing the tool calls.
    pub results: Vec<ToolCallResult>,
    /// Duration of the LLM call in milliseconds.
    pub llm_duration_ms: u64,
}

impl LoopTurn {
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self {
            index,
            llm_text: String::new(),
            requests: Vec::new(),
            results: Vec::new(),
            llm_duration_ms: 0,
        }
    }

    /// Returns `true` if this turn had tool calls.
    #[must_use]
    pub const fn had_tool_calls(&self) -> bool {
        !self.requests.is_empty()
    }

    /// Returns `true` if any tool call resulted in an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.results.iter().any(|r| r.is_error)
    }
}

// ─── LoopHistory ─────────────────────────────────────────────────────────────

/// The full history of a tool-call loop execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopHistory {
    pub turns: Vec<LoopTurn>,
    pub termination: Option<LoopTermination>,
    pub final_text: String,
    pub started_at_secs: u64,
    pub elapsed_ms: u64,
}

impl LoopHistory {
    #[must_use]
    pub fn new() -> Self {
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            turns: Vec::new(),
            termination: None,
            final_text: String::new(),
            started_at_secs: started,
            elapsed_ms: 0,
        }
    }

    /// Total number of tool calls across all turns.
    #[must_use]
    pub fn total_tool_calls(&self) -> usize {
        self.turns.iter().map(|t| t.requests.len()).sum()
    }

    /// Total number of turns with at least one tool call.
    #[must_use]
    pub fn tool_call_turns(&self) -> usize {
        self.turns.iter().filter(|t| t.had_tool_calls()).count()
    }

    /// All tool names used.
    #[must_use]
    pub fn tools_used(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .turns
            .iter()
            .flat_map(|t| t.requests.iter().map(|r| r.name.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Frequency map of tool names.
    #[must_use]
    pub fn tool_frequency(&self) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for turn in &self.turns {
            for req in &turn.requests {
                if let Some(v) = freq.get_mut(&req.name) {
                    *v += 1;
                } else {
                    freq.insert(req.name.clone(), 1);
                }
            }
        }
        freq
    }

    /// Returns `true` if the loop completed successfully.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(
            self.termination,
            Some(LoopTermination::NaturalEnd | LoopTermination::StopSequence)
        )
    }
}

impl Default for LoopHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ToolCallStats ────────────────────────────────────────────────────────────

/// Aggregate statistics for a tool-call loop run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallStats {
    pub total_iterations: u32,
    pub total_tool_calls: usize,
    pub successful_calls: usize,
    pub failed_calls: usize,
    pub total_llm_ms: u64,
    pub total_tool_ms: u64,
    pub unique_tools: usize,
    pub termination: LoopTermination,
}

impl ToolCallStats {
    /// Compute stats from a `LoopHistory`.
    #[must_use]
    pub fn from_history(history: &LoopHistory) -> Self {
        let total_tool_calls = history.total_tool_calls();
        let successful_calls = history
            .turns
            .iter()
            .flat_map(|t| t.results.iter())
            .filter(|r| !r.is_error)
            .count();
        let failed_calls = total_tool_calls - successful_calls;
        let total_llm_ms = history.turns.iter().map(|t| t.llm_duration_ms).sum();
        let total_tool_ms = history
            .turns
            .iter()
            .flat_map(|t| t.results.iter())
            .map(|r| r.duration_ms)
            .sum();
        let unique_tools = history.tools_used().len();
        Self {
            total_iterations: usize_to_u32(history.turns.len()),
            total_tool_calls,
            successful_calls,
            failed_calls,
            total_llm_ms,
            total_tool_ms,
            unique_tools,
            termination: history
                .termination
                .clone()
                .unwrap_or_else(|| LoopTermination::Error("unknown".into())),
        }
    }

    /// Success rate (0.0 – 1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_tool_calls == 0 {
            return 1.0;
        }
        usize_to_f64(self.successful_calls) / usize_to_f64(self.total_tool_calls)
    }
}

// ─── ToolRegistry ─────────────────────────────────────────────────────────────

/// Boxed handler invoked for each tool call.
pub type ToolHandlerFn = Box<dyn Fn(&ToolCallRequest) -> ToolCallResult + Send + Sync>;

/// A registry of callable tool handlers.
pub struct ToolRegistry {
    handlers: HashMap<String, ToolHandlerFn>,
}

impl ToolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a tool handler.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        handler: impl Fn(&ToolCallRequest) -> ToolCallResult + Send + Sync + 'static,
    ) {
        self.handlers.insert(name.into(), Box::new(handler));
    }

    /// Invoke a tool by name.
    ///
    /// # Errors
    ///
    /// Returns [`LoopError::UnknownTool`] if no handler is registered for the requested tool name.
    pub fn call(&self, request: &ToolCallRequest) -> Result<ToolCallResult, LoopError> {
        let handler = self
            .handlers
            .get(&request.name)
            .ok_or_else(|| LoopError::UnknownTool(request.name.clone()))?;
        let t0 = Instant::now();
        let mut result = handler(request);
        result.duration_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(result)
    }

    /// Returns `true` if a handler is registered for `name`.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// List registered tool names.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.handlers.keys().map(std::string::String::as_str).collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ToolCallLoop ─────────────────────────────────────────────────────────────

/// Drives the LLM → tool → LLM loop using a `ToolRegistry` and a mock LLM backend.
///
/// In a real implementation the `llm_fn` closure would call an actual LLM API;
/// here it is parameterised so the loop logic can be fully tested.
pub struct ToolCallLoop {
    max_iterations: u32,
    registry: ToolRegistry,
}

impl ToolCallLoop {
    #[must_use]
    pub const fn new(max_iterations: u32, registry: ToolRegistry) -> Self {
        Self {
            max_iterations,
            registry,
        }
    }

    #[must_use]
    pub const fn with_max_iterations(mut self, n: u32) -> Self {
        self.max_iterations = n;
        self
    }

    /// Run the loop with a mock LLM function.
    ///
    /// `llm_fn` receives the turn index and the results from the previous turn
    /// and returns `(text, Vec<ToolCallRequest>)`.  An empty `Vec` signals that
    /// the LLM is done.
    pub fn run<F>(&self, mut llm_fn: F) -> LoopHistory
    where
        F: FnMut(u32, &[ToolCallResult]) -> (String, Vec<ToolCallRequest>),
    {
        let start = Instant::now();
        let mut history = LoopHistory::new();
        let mut prev_results: Vec<ToolCallResult> = Vec::new();

        for i in 0..self.max_iterations {
            let llm_start = Instant::now();
            let (text, requests) = llm_fn(i, &prev_results);
            let llm_ms = u64::try_from(llm_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            let mut turn = LoopTurn::new(i);
            turn.llm_duration_ms = llm_ms;

            if requests.is_empty() {
                turn.llm_text = text;
                history.final_text.clone_from(&turn.llm_text);
                history.turns.push(turn);
                history.termination = Some(LoopTermination::NaturalEnd);
                break;
            }

            turn.llm_text = text;
            turn.requests = requests;

            // Execute each tool call.
            let mut results = Vec::with_capacity(turn.requests.len());
            for req in &turn.requests {
                let result = match self.registry.call(req) {
                    Ok(r) => r,
                    Err(e) => ToolCallResult::error(&req.id, &req.name, e.to_string()),
                };
                results.push(result);
            }

            turn.results.clone_from(&results);
            prev_results = results;
            history.turns.push(turn);

            if i + 1 == self.max_iterations {
                history.termination = Some(LoopTermination::MaxIterations);
            }
        }

        if history.termination.is_none() {
            history.termination = Some(LoopTermination::MaxIterations);
        }

        history.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        history
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(name: &str) -> ToolCallRequest {
        ToolCallRequest::new(
            format!("call_{name}"),
            name,
            serde_json::json!({"arg": "value"}),
        )
    }

    // ── ToolCallRequest ───────────────────────────────────────────────────────

    #[test]
    fn request_get_str_arg() {
        let r = ToolCallRequest::new("id1", "fn", serde_json::json!({"key": "hello"}));
        assert_eq!(r.get_str_arg("key"), Some("hello"));
        assert_eq!(r.get_str_arg("missing"), None);
    }

    #[test]
    fn request_get_u64_arg() {
        let r = ToolCallRequest::new("id1", "fn", serde_json::json!({"n": 42}));
        assert_eq!(r.get_u64_arg("n"), Some(42));
    }

    #[test]
    fn request_parse_args() {
        #[derive(Deserialize)]
        struct Args {
            addr: String,
        }
        let r = ToolCallRequest::new("id1", "fn", serde_json::json!({"addr": "0x1000"}));
        let parsed: Args = r.parse_args().unwrap();
        assert_eq!(parsed.addr, "0x1000");
    }

    // ── ToolCallResult ────────────────────────────────────────────────────────

    #[test]
    fn result_success() {
        let r = ToolCallResult::success("c1", "fn", "output");
        assert!(!r.is_error);
        assert_eq!(r.output, "output");
    }

    #[test]
    fn result_error() {
        let r = ToolCallResult::error("c1", "fn", "fail");
        assert!(r.is_error);
    }

    #[test]
    fn result_with_structured() {
        let r =
            ToolCallResult::success("c1", "fn", "ok").with_structured(serde_json::json!({"x": 1}));
        assert!(r.structured.is_some());
    }

    #[test]
    fn result_with_duration() {
        let r = ToolCallResult::success("c1", "fn", "ok").with_duration_ms(42);
        assert_eq!(r.duration_ms, 42);
    }

    // ── LoopTermination ───────────────────────────────────────────────────────

    #[test]
    fn termination_display() {
        assert_eq!(LoopTermination::NaturalEnd.to_string(), "natural_end");
        assert_eq!(LoopTermination::MaxIterations.to_string(), "max_iterations");
        assert!(
            LoopTermination::Error("x".into())
                .to_string()
                .contains("error")
        );
    }

    // ── LoopTurn ──────────────────────────────────────────────────────────────

    #[test]
    fn loop_turn_had_tool_calls() {
        let mut t = LoopTurn::new(0);
        assert!(!t.had_tool_calls());
        t.requests.push(make_request("fn"));
        assert!(t.had_tool_calls());
    }

    #[test]
    fn loop_turn_has_errors() {
        let mut t = LoopTurn::new(0);
        t.results.push(ToolCallResult::error("id", "fn", "fail"));
        assert!(t.has_errors());
    }

    // ── LoopHistory ───────────────────────────────────────────────────────────

    #[test]
    fn loop_history_total_tool_calls() {
        let mut h = LoopHistory::new();
        let mut t = LoopTurn::new(0);
        t.requests.push(make_request("a"));
        t.requests.push(make_request("b"));
        h.turns.push(t);
        assert_eq!(h.total_tool_calls(), 2);
    }

    #[test]
    fn loop_history_tools_used() {
        let mut h = LoopHistory::new();
        let mut t = LoopTurn::new(0);
        t.requests.push(make_request("disasm"));
        t.requests.push(make_request("rename"));
        t.requests.push(make_request("disasm")); // duplicate
        h.turns.push(t);
        let tools = h.tools_used();
        assert_eq!(tools.len(), 2);
        assert!(tools.contains(&"disasm".to_string()));
    }

    #[test]
    fn loop_history_is_successful() {
        let mut h = LoopHistory::new();
        h.termination = Some(LoopTermination::NaturalEnd);
        assert!(h.is_successful());
        h.termination = Some(LoopTermination::MaxIterations);
        assert!(!h.is_successful());
    }

    #[test]
    fn loop_history_tool_frequency() {
        let mut h = LoopHistory::new();
        let mut t = LoopTurn::new(0);
        t.requests.push(make_request("fn"));
        t.requests.push(make_request("fn"));
        h.turns.push(t);
        let freq = h.tool_frequency();
        assert_eq!(freq["fn"], 2);
    }

    // ── ToolRegistry ──────────────────────────────────────────────────────────

    #[test]
    fn registry_call_known_tool() {
        let mut reg = ToolRegistry::new();
        reg.register("echo", |req| {
            let arg = req.get_str_arg("arg").unwrap_or("").to_string();
            ToolCallResult::success(req.id.clone(), req.name.clone(), arg)
        });
        assert!(reg.has_tool("echo"));
        let req = ToolCallRequest::new("c1", "echo", serde_json::json!({"arg": "hello"}));
        let res = reg.call(&req).unwrap();
        assert_eq!(res.output, "hello");
    }

    #[test]
    fn registry_call_unknown_tool() {
        let reg = ToolRegistry::new();
        let req = make_request("missing");
        let r = reg.call(&req);
        assert!(matches!(r, Err(LoopError::UnknownTool(_))));
    }

    #[test]
    fn registry_tool_names() {
        let mut reg = ToolRegistry::new();
        reg.register("a", |r| {
            ToolCallResult::success(r.id.clone(), r.name.clone(), "")
        });
        reg.register("b", |r| {
            ToolCallResult::success(r.id.clone(), r.name.clone(), "")
        });
        let names = reg.tool_names();
        assert_eq!(names.len(), 2);
    }

    // ── ToolCallLoop ──────────────────────────────────────────────────────────

    #[test]
    fn loop_natural_end_no_tool_calls() {
        let loop_ = ToolCallLoop::new(10, ToolRegistry::new());
        let history = loop_.run(|_i, _prev| ("final answer".into(), vec![]));
        assert_eq!(history.termination, Some(LoopTermination::NaturalEnd));
        assert_eq!(history.final_text, "final answer");
        assert_eq!(history.turns.len(), 1);
    }

    #[test]
    fn loop_with_one_tool_call() {
        let mut reg = ToolRegistry::new();
        reg.register("get_info", |req| {
            ToolCallResult::success(req.id.clone(), req.name.clone(), "info data")
        });
        let loop_ = ToolCallLoop::new(5, reg);
        let history = loop_.run(|i, _prev| {
            if i == 0 {
                let req = ToolCallRequest::new("c1", "get_info", serde_json::json!({}));
                ("searching...".into(), vec![req])
            } else {
                ("Here is the answer.".into(), vec![])
            }
        });
        assert_eq!(history.termination, Some(LoopTermination::NaturalEnd));
        assert_eq!(history.turns.len(), 2);
        assert_eq!(history.turns[0].results[0].output, "info data");
    }

    #[test]
    fn loop_max_iterations() {
        let _loop_ = ToolCallLoop::new(3, ToolRegistry::new()).with_max_iterations(3);
        let mut reg = ToolRegistry::new();
        reg.register("loop_forever", |req| {
            ToolCallResult::success(req.id.clone(), req.name.clone(), "ok")
        });
        let loop_ = ToolCallLoop::new(3, reg);
        let history = loop_.run(|_i, _prev| {
            let req = ToolCallRequest::new("c1", "loop_forever", serde_json::json!({}));
            ("still going".into(), vec![req])
        });
        assert_eq!(history.termination, Some(LoopTermination::MaxIterations));
        assert_eq!(history.turns.len() as u32, 3);
    }

    // ── ToolCallStats ─────────────────────────────────────────────────────────

    #[test]
    fn stats_from_history() {
        let mut history = LoopHistory::new();
        let mut t = LoopTurn::new(0);
        t.requests.push(make_request("fn"));
        t.results.push(ToolCallResult::success("c1", "fn", "ok"));
        history.turns.push(t);
        history.termination = Some(LoopTermination::NaturalEnd);
        let stats = ToolCallStats::from_history(&history);
        assert_eq!(stats.total_tool_calls, 1);
        assert_eq!(stats.successful_calls, 1);
        assert_eq!(stats.failed_calls, 0);
        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_success_rate_with_failures() {
        let mut history = LoopHistory::new();
        let mut t = LoopTurn::new(0);
        t.requests.push(make_request("fn"));
        t.requests.push(make_request("fn2"));
        t.results.push(ToolCallResult::success("c1", "fn", "ok"));
        t.results.push(ToolCallResult::error("c2", "fn2", "fail"));
        history.turns.push(t);
        history.termination = Some(LoopTermination::NaturalEnd);
        let stats = ToolCallStats::from_history(&history);
        assert!((stats.success_rate() - 0.5).abs() < f64::EPSILON);
    }
}
