//! `tool_execution` — Tool execution engine for the LLM agent framework.
//!
//! Provides [`ToolExecution`], [`ToolInput`], [`ToolOutput`], [`ToolRegistry`],
//! [`ToolExecutor`], [`ToolError`], and [`ToolChain`] for orchestrating
//! deterministic tool calls from within an LLM loop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustre_agent::casts::{u64_to_f64, usize_to_f64};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── ToolError ───────────────────────────────────────────────────────────────

/// Errors that can occur during tool execution.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum ToolError {
    #[error("tool '{0}' not found in registry")]
    NotFound(String),

    #[error("invalid input for tool '{tool}': {reason}")]
    InvalidInput { tool: String, reason: String },

    #[error("tool '{0}' execution timed out")]
    Timeout(String),

    #[error("tool '{tool}' failed: {message}")]
    ExecutionFailed { tool: String, message: String },

    #[error("tool '{0}' is disabled")]
    Disabled(String),

    #[error("tool chain '{0}' is empty")]
    EmptyChain(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("permission denied for tool '{0}'")]
    PermissionDenied(String),

    #[error("rate limit exceeded for tool '{0}'")]
    RateLimited(String),
}

// ─── ToolInput ────────────────────────────────────────────────────────────────

/// Input supplied to a tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    /// Name of the tool to invoke.
    pub tool_name: String,
    /// Structured arguments (JSON).
    pub args: serde_json::Value,
    /// Caller-supplied call identifier for tracing.
    pub call_id: String,
    /// Optional timeout override in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Extra metadata (e.g. session context).
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ToolInput {
    /// Create a minimal input.
    #[must_use]
    pub fn new(tool_name: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            tool_name: tool_name.into(),
            args,
            call_id: uuid_v4(),
            timeout_ms: None,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_call_id(mut self, id: impl Into<String>) -> Self {
        self.call_id = id.into();
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Get a required string argument or return an error.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::InvalidInput`] if the key is missing or not a string.
    pub fn require_str(&self, key: &str) -> Result<&str, ToolError> {
        self.args
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: self.tool_name.clone(),
                reason: format!("missing required string argument '{key}'"),
            })
    }

    /// Get an optional u64 argument.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.args.get(key).and_then(serde_json::Value::as_u64)
    }
}

// ─── ToolOutput ───────────────────────────────────────────────────────────────

/// Output produced by a tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Call id echoed back for correlation.
    pub call_id: String,
    /// Tool name that produced this output.
    pub tool_name: String,
    /// Whether the invocation succeeded.
    pub success: bool,
    /// Structured result (null on failure).
    pub result: serde_json::Value,
    /// Human-readable summary.
    pub summary: String,
    /// Error message if `success == false`.
    pub error: Option<String>,
    /// Wall-clock duration of the tool call.
    pub duration_ms: u64,
    /// Optional raw bytes (e.g. disassembly output).
    #[serde(skip)]
    pub raw_bytes: Option<Vec<u8>>,
}

impl ToolOutput {
    /// Create a successful output.
    #[must_use]
    pub fn success(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        result: serde_json::Value,
        duration_ms: u64,
    ) -> Self {
        let summary = result
            .as_str().map_or_else(|| result.to_string().chars().take(120).collect(), |s| s.chars().take(120).collect::<String>());
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            success: true,
            result,
            summary,
            error: None,
            duration_ms,
            raw_bytes: None,
        }
    }

    /// Create a failure output.
    #[must_use]
    pub fn failure(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        let err = error.into();
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            success: false,
            result: serde_json::Value::Null,
            summary: format!("error: {err}"),
            error: Some(err),
            duration_ms: 0,
            raw_bytes: None,
        }
    }

    #[must_use]
    pub fn with_raw(mut self, bytes: Vec<u8>) -> Self {
        self.raw_bytes = Some(bytes);
        self
    }
}

// ─── Tool trait ───────────────────────────────────────────────────────────────

/// Core trait every executable tool must implement.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Short, `snake_case` tool name.
    fn name(&self) -> &str;
    /// Human-readable description.
    fn description(&self) -> &str;
    /// JSON Schema for the tool's arguments.
    fn schema(&self) -> serde_json::Value;
    /// Execute the tool.
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError>;
    /// Whether this tool is currently enabled.
    fn is_enabled(&self) -> bool {
        true
    }
}

// ─── ToolEntry ────────────────────────────────────────────────────────────────

/// Metadata record stored alongside a tool in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub description: String,
    pub version: String,
    pub enabled: bool,
    pub call_count: u64,
    pub total_duration_ms: u64,
    pub last_error: Option<String>,
}

impl ToolEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            version: "1.0.0".to_string(),
            enabled: true,
            call_count: 0,
            total_duration_ms: 0,
            last_error: None,
        }
    }

    #[must_use]
    pub fn avg_duration_ms(&self) -> f64 {
        if self.call_count == 0 {
            0.0
        } else {
            u64_to_f64(self.total_duration_ms) / u64_to_f64(self.call_count)
        }
    }

    pub fn record_call(&mut self, duration_ms: u64, error: Option<&str>) {
        self.call_count += 1;
        self.total_duration_ms += duration_ms;
        self.last_error = error.map(str::to_string);
    }
}

// ─── ToolRegistry ─────────────────────────────────────────────────────────────

/// Thread-safe registry of all available tools.
pub struct ToolRegistry {
    tools: RwLock<HashMap<String, Arc<dyn Tool>>>,
    entries: RwLock<HashMap<String, ToolEntry>>,
}

impl ToolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a tool.
    pub fn register(&self, tool: Arc<dyn Tool>) {
        let entry = ToolEntry::new(tool.name(), tool.description());
        let name = tool.name().to_string();
        self.tools.write().insert(name.clone(), tool);
        self.entries.write().insert(name, entry);
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.read().get(name).cloned()
    }

    /// List names of all registered tools.
    #[must_use]
    pub fn tool_names(&self) -> Vec<String> {
        self.tools.read().keys().cloned().collect()
    }

    /// Total number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Disable a tool by name.
    pub fn disable(&self, name: &str) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.enabled = false;
        }
    }

    /// Enable a tool by name.
    pub fn enable(&self, name: &str) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.enabled = true;
        }
    }

    /// Check whether a tool is enabled.
    #[must_use]
    pub fn is_enabled(&self, name: &str) -> bool {
        self.entries.read().get(name).is_some_and(|e| e.enabled)
    }

    /// Return a snapshot of all tool entries.
    #[must_use]
    pub fn entries(&self) -> Vec<ToolEntry> {
        self.entries.read().values().cloned().collect()
    }

    /// Record a tool call result.
    pub fn record_call(&self, name: &str, duration_ms: u64, error: Option<&str>) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.record_call(duration_ms, error);
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ToolExecution ────────────────────────────────────────────────────────────

/// A record of a completed tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub execution_id: String,
    pub input: ToolInput,
    pub output: Option<ToolOutput>,
    pub error: Option<ToolError>,
    pub started_at: u64,
    pub finished_at: u64,
    /// Wall-clock-independent duration measured with `Instant` (monotonic clock).
    ///
    /// `finished_at - started_at` is derived from `SystemTime` and can return 0
    /// or an undercount when the system clock is adjusted backward (NTP step).
    /// Prefer this field for any timing logic.
    pub elapsed_ms: u64,
}

impl ToolExecution {
    /// Monotonically-measured duration of the execution.
    ///
    /// Uses the `Instant`-based `elapsed_ms` field rather than the wall-clock
    /// `started_at`/`finished_at` difference, which is subject to system-clock
    /// jumps.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.elapsed_ms
    }

    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.output.as_ref().is_some_and(|o| o.success)
    }
}

// ─── ToolExecutor ─────────────────────────────────────────────────────────────

/// Executes tools from the registry, recording metrics and honouring timeouts.
pub struct ToolExecutor {
    registry: Arc<ToolRegistry>,
    default_timeout_ms: u64,
    history: Mutex<Vec<ToolExecution>>,
    max_history: usize,
}

impl ToolExecutor {
    #[must_use]
    pub const fn new(registry: Arc<ToolRegistry>) -> Self {
        Self {
            registry,
            default_timeout_ms: 30_000,
            history: Mutex::new(Vec::new()),
            max_history: 1000,
        }
    }

    #[must_use]
    pub const fn with_default_timeout(mut self, ms: u64) -> Self {
        self.default_timeout_ms = ms;
        self
    }

    #[must_use]
    pub const fn with_max_history(mut self, n: usize) -> Self {
        self.max_history = n;
        self
    }

    /// Execute a tool by input descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::NotFound`] if the tool is unknown, [`ToolError::Disabled`] if disabled,
    /// or [`ToolError::Timeout`] if the tool exceeds its time budget.
    pub async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        let tool_name = input.tool_name.clone();
        let call_id = input.call_id.clone();
        let timeout_ms = input.timeout_ms.unwrap_or(self.default_timeout_ms);

        let tool = self
            .registry
            .get(&tool_name)
            .ok_or_else(|| ToolError::NotFound(tool_name.clone()))?;

        if !self.registry.is_enabled(&tool_name) {
            return Err(ToolError::Disabled(tool_name.clone()));
        }

        let started_at = epoch_ms();
        let start = Instant::now();

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tool.execute(input.clone()),
        )
        .await
        .map_err(|_| ToolError::Timeout(tool_name.clone()))?;

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let finished_at = epoch_ms();

        let (output_opt, error_opt) = match &result {
            Ok(o) => (Some(o.clone()), None),
            Err(e) => (None, Some(e.clone())),
        };

        let exec = ToolExecution {
            execution_id: call_id.clone(),
            input: input.clone(),
            output: output_opt,
            error: error_opt,
            started_at,
            finished_at,
            elapsed_ms: duration_ms,
        };

        {
            let mut hist = self.history.lock();
            if hist.len() >= self.max_history {
                hist.remove(0);
            }
            hist.push(exec);
        }

        let error_msg = result.as_ref().err().map(std::string::ToString::to_string);
        self.registry
            .record_call(&tool_name, duration_ms, error_msg.as_deref());

        result
    }

    /// Return execution history (newest first).
    #[must_use]
    pub fn history(&self) -> Vec<ToolExecution> {
        let mut h = self.history.lock().clone();
        h.reverse();
        h
    }

    /// Return the number of recorded executions.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.lock().len()
    }

    /// Clear execution history.
    pub fn clear_history(&self) {
        self.history.lock().clear();
    }

    /// Success rate across all recorded executions.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let h = self.history.lock();
        if h.is_empty() {
            return 0.0;
        }
        let ok = h.iter().filter(|e| e.succeeded()).count();
        usize_to_f64(ok) / usize_to_f64(h.len())
    }
}

// ─── ToolChain ────────────────────────────────────────────────────────────────

/// A named sequence of tool inputs to execute in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChain {
    pub chain_id: String,
    pub steps: Vec<ToolInput>,
    /// Whether to stop the chain on the first failure.
    pub stop_on_error: bool,
}

impl ToolChain {
    #[must_use]
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            steps: Vec::new(),
            stop_on_error: true,
        }
    }

    #[must_use]
    pub fn with_step(mut self, step: ToolInput) -> Self {
        self.steps.push(step);
        self
    }

    #[must_use]
    pub const fn continue_on_error(mut self) -> Self {
        self.stop_on_error = false;
        self
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// Execute all steps via the given executor.
    ///
    /// Returns a `Vec` of outputs in step order.  On failure, if
    /// `stop_on_error` is set, the remaining outputs are `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::EmptyChain`] if the chain has no steps, or propagates the last tool error.
    pub async fn execute_all(
        &self,
        executor: &ToolExecutor,
    ) -> Result<Vec<Option<ToolOutput>>, ToolError> {
        if self.steps.is_empty() {
            return Err(ToolError::EmptyChain(self.chain_id.clone()));
        }

        let mut results = Vec::with_capacity(self.steps.len());
        let mut aborted = false;
        let mut pending_err: Option<ToolError> = None;

        for step in &self.steps {
            if aborted {
                results.push(None);
                continue;
            }
            match executor.execute(step.clone()).await {
                Ok(out) => {
                    results.push(Some(out));
                }
                Err(e) => {
                    results.push(None);
                    if self.stop_on_error {
                        aborted = true;
                        // Defer propagation so the remaining steps are filled
                        // with `None` via the `aborted` short-circuit above.
                        pending_err = Some(e);
                    }
                }
            }
        }

        if let Some(e) = pending_err {
            return Err(e);
        }
        Ok(results)
    }
}

// ─── Built-in echo tool ───────────────────────────────────────────────────────

/// A simple echo tool — useful for testing.
pub struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "Returns its input as output."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            },
            "required": ["message"]
        })
    }

    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        let msg = input.require_str("message")?.to_string();
        Ok(ToolOutput::success(
            input.call_id,
            self.name(),
            serde_json::json!(msg),
            0,
        ))
    }
}

/// A tool that always fails — useful for negative tests.
pub struct FailTool;

#[async_trait]
impl Tool for FailTool {
    fn name(&self) -> &'static str {
        "fail"
    }

    fn description(&self) -> &'static str {
        "Always fails."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object" })
    }

    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        Err(ToolError::ExecutionFailed {
            tool: self.name().to_string(),
            message: format!("intentional failure for call_id={}", input.call_id),
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn uuid_v4() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "call-{}",
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> Arc<ToolRegistry> {
        let reg = Arc::new(ToolRegistry::new());
        reg.register(Arc::new(EchoTool));
        reg.register(Arc::new(FailTool));
        reg
    }

    fn make_executor() -> ToolExecutor {
        ToolExecutor::new(make_registry())
    }

    // ── ToolInput ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_input_new() {
        let i = ToolInput::new("echo", serde_json::json!({"message": "hi"}));
        assert_eq!(i.tool_name, "echo");
        assert!(i.timeout_ms.is_none());
    }

    #[test]
    fn test_tool_input_builders() {
        let i = ToolInput::new("echo", serde_json::json!({}))
            .with_call_id("c1")
            .with_timeout(5000)
            .with_meta("key", serde_json::json!("val"));
        assert_eq!(i.call_id, "c1");
        assert_eq!(i.timeout_ms, Some(5000));
        assert_eq!(i.metadata.get("key"), Some(&serde_json::json!("val")));
    }

    #[test]
    fn test_tool_input_require_str_ok() {
        let i = ToolInput::new("echo", serde_json::json!({"message": "hello"}));
        assert_eq!(i.require_str("message").unwrap(), "hello");
    }

    #[test]
    fn test_tool_input_require_str_missing() {
        let i = ToolInput::new("echo", serde_json::json!({}));
        assert!(i.require_str("message").is_err());
    }

    #[test]
    fn test_tool_input_get_u64() {
        let i = ToolInput::new("x", serde_json::json!({"addr": 0x1000u64}));
        assert_eq!(i.get_u64("addr"), Some(0x1000));
        assert_eq!(i.get_u64("missing"), None);
    }

    // ── ToolOutput ────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_output_success() {
        let o = ToolOutput::success("c1", "echo", serde_json::json!("hello"), 5);
        assert!(o.success);
        assert!(o.error.is_none());
        assert_eq!(o.duration_ms, 5);
    }

    #[test]
    fn test_tool_output_failure() {
        let o = ToolOutput::failure("c2", "fail", "oops");
        assert!(!o.success);
        assert!(o.error.is_some());
        assert_eq!(o.result, serde_json::Value::Null);
    }

    #[test]
    fn test_tool_output_with_raw() {
        let o =
            ToolOutput::success("c3", "x", serde_json::json!(null), 0).with_raw(vec![0x90, 0x90]);
        assert_eq!(o.raw_bytes.as_ref().unwrap().len(), 2);
    }

    // ── ToolEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_entry_new() {
        let e = ToolEntry::new("my_tool", "does stuff");
        assert!(e.enabled);
        assert_eq!(e.call_count, 0);
    }

    #[test]
    fn test_tool_entry_record_call() {
        let mut e = ToolEntry::new("t", "d");
        e.record_call(100, None);
        e.record_call(200, Some("fail"));
        assert_eq!(e.call_count, 2);
        assert_eq!(e.total_duration_ms, 300);
        assert!((e.avg_duration_ms() - 150.0).abs() < 0.01);
        assert_eq!(e.last_error.as_deref(), Some("fail"));
    }

    #[test]
    fn test_tool_entry_avg_no_calls() {
        let e = ToolEntry::new("t", "d");
        assert_eq!(e.avg_duration_ms(), 0.0);
    }

    // ── ToolRegistry ──────────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_get() {
        let reg = ToolRegistry::new();
        reg.register(Arc::new(EchoTool));
        assert!(reg.get("echo").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn test_registry_len_is_empty() {
        let reg = ToolRegistry::new();
        assert!(reg.is_empty());
        reg.register(Arc::new(EchoTool));
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_enable_disable() {
        let reg = make_registry();
        assert!(reg.is_enabled("echo"));
        reg.disable("echo");
        assert!(!reg.is_enabled("echo"));
        reg.enable("echo");
        assert!(reg.is_enabled("echo"));
    }

    #[test]
    fn test_registry_tool_names() {
        let reg = make_registry();
        let names = reg.tool_names();
        assert!(names.contains(&"echo".to_string()));
        assert!(names.contains(&"fail".to_string()));
    }

    #[test]
    fn test_registry_record_call() {
        let reg = make_registry();
        reg.record_call("echo", 50, None);
        let entries = reg.entries();
        let echo = entries.iter().find(|e| e.name == "echo").unwrap();
        assert_eq!(echo.call_count, 1);
    }

    // ── ToolExecutor ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_executor_echo_success() {
        let exec = make_executor();
        let input = ToolInput::new("echo", serde_json::json!({"message": "hello"}));
        let out = exec.execute(input).await.unwrap();
        assert!(out.success);
        assert_eq!(out.result, serde_json::json!("hello"));
    }

    #[tokio::test]
    async fn test_executor_not_found() {
        let exec = make_executor();
        let input = ToolInput::new("ghost", serde_json::json!({}));
        let err = exec.execute(input).await.unwrap_err();
        assert!(matches!(err, ToolError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_executor_fail_tool() {
        let exec = make_executor();
        let input = ToolInput::new("fail", serde_json::json!({}));
        let err = exec.execute(input).await.unwrap_err();
        assert!(matches!(err, ToolError::ExecutionFailed { .. }));
    }

    #[tokio::test]
    async fn test_executor_disabled_tool() {
        let reg = make_registry();
        reg.disable("echo");
        let exec = ToolExecutor::new(reg);
        let input = ToolInput::new("echo", serde_json::json!({"message": "x"}));
        let err = exec.execute(input).await.unwrap_err();
        assert!(matches!(err, ToolError::Disabled(_)));
    }

    #[tokio::test]
    async fn test_executor_history() {
        let exec = make_executor();
        exec.execute(ToolInput::new("echo", serde_json::json!({"message": "a"})))
            .await
            .ok();
        exec.execute(ToolInput::new("echo", serde_json::json!({"message": "b"})))
            .await
            .ok();
        assert_eq!(exec.history_len(), 2);
    }

    #[tokio::test]
    async fn test_executor_clear_history() {
        let exec = make_executor();
        exec.execute(ToolInput::new("echo", serde_json::json!({"message": "x"})))
            .await
            .ok();
        exec.clear_history();
        assert_eq!(exec.history_len(), 0);
    }

    #[tokio::test]
    async fn test_executor_success_rate() {
        let exec = make_executor();
        exec.execute(ToolInput::new("echo", serde_json::json!({"message": "a"})))
            .await
            .ok();
        exec.execute(ToolInput::new("fail", serde_json::json!({})))
            .await
            .ok();
        let rate = exec.success_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    // ── ToolChain ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_chain_empty() {
        let tc = ToolChain::new("c1");
        assert!(tc.is_empty());
        assert_eq!(tc.len(), 0);
    }

    #[test]
    fn test_tool_chain_with_step() {
        let tc = ToolChain::new("c1")
            .with_step(ToolInput::new("echo", serde_json::json!({"message": "x"})));
        assert_eq!(tc.len(), 1);
        assert!(!tc.is_empty());
    }

    #[tokio::test]
    async fn test_tool_chain_execute_empty_error() {
        let exec = make_executor();
        let tc = ToolChain::new("empty");
        let err = tc.execute_all(&exec).await.unwrap_err();
        assert!(matches!(err, ToolError::EmptyChain(_)));
    }

    #[tokio::test]
    async fn test_tool_chain_execute_all_success() {
        let exec = make_executor();
        let tc = ToolChain::new("chain")
            .with_step(ToolInput::new("echo", serde_json::json!({"message": "a"})))
            .with_step(ToolInput::new("echo", serde_json::json!({"message": "b"})));
        let results = tc.execute_all(&exec).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].as_ref().unwrap().success);
        assert!(results[1].as_ref().unwrap().success);
    }

    #[tokio::test]
    async fn test_tool_chain_stop_on_error() {
        let exec = make_executor();
        let tc = ToolChain::new("chain")
            .with_step(ToolInput::new("fail", serde_json::json!({})))
            .with_step(ToolInput::new("echo", serde_json::json!({"message": "x"})));
        let err = tc.execute_all(&exec).await.unwrap_err();
        assert!(matches!(err, ToolError::ExecutionFailed { .. }));
    }

    #[tokio::test]
    async fn test_tool_chain_continue_on_error() {
        let exec = make_executor();
        let tc = ToolChain::new("chain")
            .continue_on_error()
            .with_step(ToolInput::new("fail", serde_json::json!({})))
            .with_step(ToolInput::new("echo", serde_json::json!({"message": "ok"})));
        let results = tc.execute_all(&exec).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_none());
        assert!(results[1].as_ref().unwrap().success);
    }

    // ── ToolError display ─────────────────────────────────────────────────────

    #[test]
    fn test_tool_error_display() {
        assert!(ToolError::NotFound("x".into()).to_string().contains('x'));
        assert!(ToolError::Timeout("y".into()).to_string().contains('y'));
        assert!(ToolError::Disabled("z".into()).to_string().contains('z'));
        let e = ToolError::InvalidInput {
            tool: "t".into(),
            reason: "bad".into(),
        };
        assert!(e.to_string().contains("bad"));
    }

    // ── ToolExecution ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_execution_record() {
        let exec = make_executor();
        let input = ToolInput::new("echo", serde_json::json!({"message": "test"}));
        exec.execute(input).await.ok();
        let hist = exec.history();
        assert_eq!(hist.len(), 1);
        assert!(hist[0].succeeded());
        // duration_ms is >= 0
        assert!(hist[0].duration_ms() < u64::MAX);
    }
}
