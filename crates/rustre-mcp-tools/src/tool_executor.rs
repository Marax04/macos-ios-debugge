//! MCP tool executor: dispatch to tool implementations, parameter deserialization,
//! result serialization, timeout handling, and error mapping.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Executor errors
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Errors from the tool executor.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecutorError {
    #[error("tool '{0}' not found")]
    ToolNotFound(String),
    #[error("parameter deserialization failed for tool '{tool}': {message}")]
    DeserializeParams { tool: String, message: String },
    #[error("execution failed for tool '{tool}': {message}")]
    ExecutionFailed { tool: String, message: String },
    #[error("tool '{tool}' timed out after {timeout_ms}ms")]
    Timeout { tool: String, timeout_ms: u64 },
    #[error("tool '{0}' is disabled")]
    ToolDisabled(String),
    #[error("schema validation failed for tool '{tool}': {errors}")]
    ValidationFailed { tool: String, errors: String },
    #[error("internal executor error: {0}")]
    Internal(String),
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tool invocation request / response
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A request to invoke a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// Tool name.
    pub tool: String,
    /// Raw JSON parameters.
    pub params: Value,
    /// Optional invocation identifier (for logging/tracing).
    pub invocation_id: Option<String>,
    /// Maximum time allowed for this invocation (ms). `None` = no limit.
    pub timeout_ms: Option<u64>,
}

impl ToolInvocation {
    /// Create a new invocation.
    #[must_use]
    pub fn new(tool: impl Into<String>, params: Value) -> Self {
        Self {
            tool: tool.into(),
            params,
            invocation_id: None,
            timeout_ms: None,
        }
    }

    /// Set the invocation ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.invocation_id = Some(id.into());
        self
    }

    /// Set the timeout.
    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
}

/// The result of a tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationResult {
    /// Tool name.
    pub tool: String,
    /// Whether the invocation succeeded.
    pub success: bool,
    /// Serialized result (on success).
    pub result: Option<Value>,
    /// Error message (on failure).
    pub error: Option<String>,
    /// Execution duration (ms).
    pub duration_ms: u64,
    /// Invocation ID (if provided).
    pub invocation_id: Option<String>,
    /// Tool-specific metadata.
    pub metadata: HashMap<String, Value>,
}

impl ToolInvocationResult {
    /// Build a successful result.
    #[must_use]
    pub fn success(tool: impl Into<String>, result: Value, duration_ms: u64) -> Self {
        Self {
            tool: tool.into(),
            success: true,
            result: Some(result),
            error: None,
            duration_ms,
            invocation_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Build an error result.
    #[must_use]
    pub fn error(tool: impl Into<String>, err: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            tool: tool.into(),
            success: false,
            result: None,
            error: Some(err.into()),
            duration_ms,
            invocation_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the invocation ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.invocation_id = Some(id.into());
        self
    }

    /// Add a metadata entry.
    pub fn add_meta(&mut self, key: impl Into<String>, value: Value) {
        self.metadata.insert(key.into(), value);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolHandler trait
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Trait for tool implementations.
pub trait ToolHandler: Send + Sync {
    /// Tool name (matches the registry key).
    fn name(&self) -> &'static str;

    /// Execute the tool with the given parameters, returning a JSON result.
    ///
    /// # Errors
    /// Returns `Err` with a human-readable message if execution fails.
    fn execute(&self, params: &Value) -> Result<Value, String>;

    /// Optional parameter pre-processing (e.g. defaults injection).
    fn preprocess_params(&self, params: Value) -> Value {
        params
    }

    /// Optional result post-processing.
    fn postprocess_result(&self, result: Value) -> Value {
        result
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Execution context
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Context passed to each tool invocation.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Maximum allowed execution time.
    pub timeout: Option<Duration>,
    /// Caller identifier.
    pub caller: Option<String>,
    /// Extra context values available to all tools.
    pub extra: HashMap<String, Value>,
}

impl ExecutionContext {
    /// Create a new context.
    #[must_use]
    pub fn new() -> Self {
        Self { timeout: None, caller: None, extra: HashMap::new() }
    }

    /// Set a timeout.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Set the caller.
    #[must_use]
    pub fn with_caller(mut self, c: impl Into<String>) -> Self {
        self.caller = Some(c.into());
        self
    }

    /// Add an extra context value.
    pub fn set_extra(&mut self, key: impl Into<String>, value: Value) {
        self.extra.insert(key.into(), value);
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolExecutor
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Execution statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutorStats {
    pub total_invocations: u64,
    pub successful: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub total_duration_ms: u64,
    pub per_tool: HashMap<String, ToolStats>,
}

/// Per-tool statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolStats {
    pub invocations: u64,
    pub successes: u64,
    pub failures: u64,
    pub total_duration_ms: u64,
}

impl ToolStats {
    /// Average duration (ms) per invocation.
    #[must_use]
    pub fn avg_duration_ms(&self) -> f64 {
        if self.invocations == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.total_duration_ms).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.invocations).unwrap_or(u32::MAX))
        }
    }

    /// Success rate [0, 1].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.invocations == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.successes).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.invocations).unwrap_or(u32::MAX))
        }
    }
}

/// The main tool executor.
pub struct ToolExecutor {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
    default_timeout: Option<Duration>,
    stats: parking_lot::Mutex<ExecutorStats>,
    disabled_tools: Vec<String>,
}

impl ToolExecutor {
    /// Create a new executor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            default_timeout: None,
            stats: parking_lot::Mutex::new(ExecutorStats::default()),
            disabled_tools: Vec::new(),
        }
    }

    /// Set the default timeout for all invocations.
    #[must_use]
    pub const fn with_default_timeout(mut self, t: Duration) -> Self {
        self.default_timeout = Some(t);
        self
    }

    /// Register a tool handler.
    pub fn register(&mut self, handler: Arc<dyn ToolHandler>) {
        self.handlers.insert(handler.name().to_string(), handler);
    }

    /// Disable a tool.
    pub fn disable(&mut self, tool_name: &str) {
        self.disabled_tools.push(tool_name.to_string());
    }

    /// Enable a previously disabled tool.
    pub fn enable(&mut self, tool_name: &str) {
        self.disabled_tools.retain(|t| t != tool_name);
    }

    /// Returns `true` if the tool is registered.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// List all registered tool names.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.handlers.keys().map(String::as_str).collect()
    }

    /// Execute a tool invocation synchronously.
    pub fn execute(&self, invocation: ToolInvocation) -> ToolInvocationResult {
        let start = Instant::now();
        let tool_name = invocation.tool.clone();

        // Check disabled
        if self.disabled_tools.contains(&tool_name) {
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.record_failure(&tool_name, ms);
            return ToolInvocationResult::error(
                &tool_name,
                format!("tool '{tool_name}' is disabled"),
                ms,
            );
        }

        // Find handler
        let Some(handler) = self.handlers.get(&tool_name).map(Arc::clone) else {
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.record_failure(&tool_name, ms);
            return ToolInvocationResult::error(
                &tool_name,
                format!("tool '{tool_name}' not found"),
                ms,
            );
        };

        // Determine timeout
        let timeout = invocation.timeout_ms
            .map(Duration::from_millis)
            .or(self.default_timeout);

        // Preprocess params
        let params = handler.preprocess_params(invocation.params);

        // Execute with timeout check (simple wall-clock check after execution)
        let exec_result = handler.execute(&params);

        let elapsed = start.elapsed();
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);

        // Post-execution timeout check
        if timeout.map_or(false, |limit| elapsed > limit) {
            self.record_timeout(&tool_name, ms);
            return ToolInvocationResult::error(
                &tool_name,
                format!("tool '{tool_name}' timed out after {ms}ms"),
                ms,
            );
        }

        match exec_result {
            Ok(result) => {
                let post = handler.postprocess_result(result);
                self.record_success(&tool_name, ms);
                let mut r = ToolInvocationResult::success(&tool_name, post, ms);
                if let Some(id) = invocation.invocation_id {
                    r = r.with_id(id);
                }
                r
            }
            Err(err) => {
                self.record_failure(&tool_name, ms);
                let mut r = ToolInvocationResult::error(&tool_name, err, ms);
                if let Some(id) = invocation.invocation_id {
                    r = r.with_id(id);
                }
                r
            }
        }
    }

    /// Execute multiple invocations sequentially.
    pub fn execute_batch(
        &self,
        invocations: Vec<ToolInvocation>,
    ) -> Vec<ToolInvocationResult> {
        invocations.into_iter().map(|inv| self.execute(inv)).collect()
    }

    fn record_success(&self, tool: &str, ms: u64) {
        let mut stats = self.stats.lock();
        stats.total_invocations += 1;
        stats.successful += 1;
        stats.total_duration_ms += ms;
        let ts = stats.per_tool.entry(tool.to_string()).or_default();
        ts.invocations += 1;
        ts.successes += 1;
        ts.total_duration_ms += ms;
        drop(stats);
    }

    fn record_failure(&self, tool: &str, ms: u64) {
        let mut stats = self.stats.lock();
        stats.total_invocations += 1;
        stats.failed += 1;
        stats.total_duration_ms += ms;
        let ts = stats.per_tool.entry(tool.to_string()).or_default();
        ts.invocations += 1;
        ts.failures += 1;
        ts.total_duration_ms += ms;
        drop(stats);
    }

    fn record_timeout(&self, tool: &str, ms: u64) {
        let mut stats = self.stats.lock();
        stats.total_invocations += 1;
        stats.failed += 1;
        stats.timed_out += 1;
        stats.total_duration_ms += ms;
        let ts = stats.per_tool.entry(tool.to_string()).or_default();
        ts.invocations += 1;
        ts.failures += 1;
        ts.total_duration_ms += ms;
        drop(stats);
    }

    /// Get a snapshot of execution statistics.
    #[must_use]
    pub fn stats(&self) -> ExecutorStats {
        self.stats.lock().clone()
    }

    /// Reset all statistics.
    pub fn reset_stats(&self) {
        *self.stats.lock() = ExecutorStats::default();
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Serialization helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Deserialize a named field from a `Value` object.
///
/// Returns `Ok(T)` if the field exists and can be deserialized.
///
/// # Errors
/// Returns `Err(String)` if the field is missing or cannot be deserialized.
pub fn extract_field<T: for<'de> Deserialize<'de>>(
    params: &Value,
    field: &str,
) -> Result<T, String> {
    let v = params.get(field)
        .ok_or_else(|| format!("missing field: {field}"))?;
    serde_json::from_value(v.clone())
        .map_err(|e| format!("field '{field}': {e}"))
}

/// Deserialize a named field with a fallback default.
pub fn extract_field_or<T: for<'de> Deserialize<'de>>(
    params: &Value,
    field: &str,
    default: T,
) -> T {
    params.get(field)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(default)
}

/// Extract a string field.
///
/// # Errors
/// Returns `Err` if the field is absent or not a string.
pub fn extract_str<'a>(params: &'a Value, field: &str) -> Result<&'a str, String> {
    params.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string field: {field}"))
}

/// Extract a u64 field.
///
/// # Errors
/// Returns `Err` if the field is absent or not an unsigned integer.
pub fn extract_u64(params: &Value, field: &str) -> Result<u64, String> {
    params.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-integer field: {field}"))
}

/// Extract an optional u64 field.
pub fn extract_opt_u64(params: &Value, field: &str) -> Option<u64> {
    params.get(field).and_then(Value::as_u64)
}

/// Extract a boolean field (with default).
pub fn extract_bool_or(params: &Value, field: &str, default: bool) -> bool {
    params.get(field).and_then(Value::as_bool).unwrap_or(default)
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Result serialization helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wrap a success value with standard envelope fields.
#[must_use]
pub fn wrap_success(data: &Value) -> Value {
    json!({
        "status": "ok",
        "data": data
    })
}

/// Wrap an error with standard envelope fields.
#[must_use]
pub fn wrap_error(message: impl Into<String>, code: &str) -> Value {
    json!({
        "status": "error",
        "code": code,
        "message": message.into()
    })
}

/// Wrap a paginated list result.
#[must_use]
pub fn wrap_list(items: &Value, total: usize, offset: usize, limit: usize) -> Value {
    json!({
        "status": "ok",
        "data": items,
        "pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total,
        }
    })
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Error mapping
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Maps an `ExecutorError` to a JSON error envelope.
#[must_use]
pub fn executor_error_to_json(err: &ExecutorError) -> Value {
    let code = match err {
        ExecutorError::ToolNotFound(_) => "TOOL_NOT_FOUND",
        ExecutorError::DeserializeParams { .. } => "INVALID_PARAMS",
        ExecutorError::ExecutionFailed { .. } => "EXECUTION_FAILED",
        ExecutorError::Timeout { .. } => "TIMEOUT",
        ExecutorError::ToolDisabled(_) => "TOOL_DISABLED",
        ExecutorError::ValidationFailed { .. } => "VALIDATION_FAILED",
        ExecutorError::Internal(_) => "INTERNAL_ERROR",
    };
    wrap_error(err.to_string(), code)
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Built-in example tool handlers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// These small handlers are useful both as integration-test fixtures *and* as
// runnable examples for downstream embedders who want to register a minimal
// tool surface (e.g. when bringing up the executor in a fresh project). They
// are deliberately exported so users can call
// `executor.register(Arc::new(EchoTool))` directly.

/// Echoes its `params` value back as the result.
pub struct EchoTool;

impl ToolHandler for EchoTool {
    fn name(&self) -> &'static str { "echo" }
    fn execute(&self, params: &Value) -> Result<Value, String> {
        Ok(params.clone())
    }
}

/// Always returns an error â€” handy for testing error paths.
pub struct FailingTool;

impl ToolHandler for FailingTool {
    fn name(&self) -> &'static str { "failing" }
    fn execute(&self, _params: &Value) -> Result<Value, String> {
        Err("always fails".to_string())
    }
}

/// Adds two `u64`s from `params.a` and `params.b`, returning `{"result": a+b}`.
pub struct AddTool;

impl ToolHandler for AddTool {
    fn name(&self) -> &'static str { "add" }
    fn execute(&self, params: &Value) -> Result<Value, String> {
        let a = extract_u64(params, "a")?;
        let b = extract_u64(params, "b")?;
        let result = a.checked_add(b)
            .ok_or_else(|| format!("integer overflow: {a} + {b} exceeds u64::MAX"))?;
        Ok(json!({"result": result}))
    }
}

/// Register all three example tools ([`EchoTool`], [`FailingTool`], [`AddTool`])
/// on the supplied executor. Convenience for demos and bring-up.
pub fn register_example_tools(executor: &mut ToolExecutor) {
    executor.register(Arc::new(EchoTool));
    executor.register(Arc::new(FailingTool));
    executor.register(Arc::new(AddTool));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> ToolExecutor {
        let mut e = ToolExecutor::new();
        e.register(Arc::new(EchoTool));
        e.register(Arc::new(FailingTool));
        e.register(Arc::new(AddTool));
        e
    }

    #[test]
    fn test_execute_echo() {
        let e = executor();
        let inv = ToolInvocation::new("echo", json!({"hello": "world"}));
        let result = e.execute(inv);
        assert!(result.success);
        assert_eq!(result.result.unwrap()["hello"], "world");
    }

    #[test]
    fn test_execute_failing() {
        let e = executor();
        let inv = ToolInvocation::new("failing", json!({}));
        let result = e.execute(inv);
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_execute_not_found() {
        let e = executor();
        let inv = ToolInvocation::new("nonexistent", json!({}));
        let result = e.execute(inv);
        assert!(!result.success);
    }

    #[test]
    fn test_execute_add() {
        let e = executor();
        let inv = ToolInvocation::new("add", json!({"a": 3, "b": 7}));
        let result = e.execute(inv);
        assert!(result.success);
        assert_eq!(result.result.unwrap()["result"], 10);
    }

    #[test]
    fn test_execute_disabled() {
        let mut e = executor();
        e.disable("echo");
        let inv = ToolInvocation::new("echo", json!({}));
        let result = e.execute(inv);
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("disabled"));
    }

    #[test]
    fn test_enable_re_enables() {
        let mut e = executor();
        e.disable("echo");
        e.enable("echo");
        let inv = ToolInvocation::new("echo", json!({"x": 1}));
        let result = e.execute(inv);
        assert!(result.success);
    }

    #[test]
    fn test_stats_after_success() {
        let e = executor();
        e.execute(ToolInvocation::new("echo", json!({})));
        let stats = e.stats();
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn test_stats_after_failure() {
        let e = executor();
        e.execute(ToolInvocation::new("failing", json!({})));
        let stats = e.stats();
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_stats_per_tool() {
        let e = executor();
        e.execute(ToolInvocation::new("echo", json!({})));
        e.execute(ToolInvocation::new("echo", json!({})));
        let stats = e.stats();
        assert_eq!(stats.per_tool["echo"].invocations, 2);
    }

    #[test]
    fn test_stats_reset() {
        let e = executor();
        e.execute(ToolInvocation::new("echo", json!({})));
        e.reset_stats();
        assert_eq!(e.stats().total_invocations, 0);
    }

    #[test]
    fn test_invocation_id_propagated() {
        let e = executor();
        let inv = ToolInvocation::new("echo", json!({})).with_id("test-123");
        let result = e.execute(inv);
        assert_eq!(result.invocation_id.as_deref(), Some("test-123"));
    }

    #[test]
    fn test_execute_batch() {
        let e = executor();
        let invocations = vec![
            ToolInvocation::new("echo", json!({"n": 1})),
            ToolInvocation::new("echo", json!({"n": 2})),
        ];
        let results = e.execute_batch(invocations);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_has_tool() {
        let e = executor();
        assert!(e.has_tool("echo"));
        assert!(!e.has_tool("ghost"));
    }

    #[test]
    fn test_extract_field() {
        let v = json!({"x": 42, "y": "hello"});
        let x: u64 = extract_field(&v, "x").unwrap();
        assert_eq!(x, 42);
        let y: String = extract_field(&v, "y").unwrap();
        assert_eq!(y, "hello");
    }

    #[test]
    fn test_extract_field_missing() {
        let v = json!({});
        let r: Result<u64, _> = extract_field(&v, "x");
        assert!(r.is_err());
    }

    #[test]
    fn test_extract_str() {
        let v = json!({"name": "foo"});
        assert_eq!(extract_str(&v, "name").unwrap(), "foo");
        assert!(extract_str(&v, "missing").is_err());
    }

    #[test]
    fn test_extract_bool_or() {
        let v = json!({"flag": true});
        assert!(extract_bool_or(&v, "flag", false));
        assert!(!extract_bool_or(&v, "missing", false));
        assert!(extract_bool_or(&v, "missing", true));
    }

    #[test]
    fn test_wrap_success() {
        let w = wrap_success(&json!({"x": 1}));
        assert_eq!(w["status"], "ok");
        assert_eq!(w["data"]["x"], 1);
    }

    #[test]
    fn test_wrap_error() {
        let w = wrap_error("Something went wrong", "ERR_CODE");
        assert_eq!(w["status"], "error");
        assert_eq!(w["code"], "ERR_CODE");
    }

    #[test]
    fn test_wrap_list() {
        let items = json!([1, 2, 3]);
        let w = wrap_list(&items, 100, 0, 10);
        assert_eq!(w["pagination"]["total"], 100);
        assert_eq!(w["pagination"]["has_more"], true);
    }

    #[test]
    fn test_executor_error_to_json() {
        let err = ExecutorError::ToolNotFound("foo".into());
        let j = executor_error_to_json(&err);
        assert_eq!(j["code"], "TOOL_NOT_FOUND");
    }

    #[test]
    fn test_tool_stats_avg_duration() {
        let ts = ToolStats {
            invocations: 4,
            successes: 4,
            failures: 0,
            total_duration_ms: 200,
        };
        assert!((ts.avg_duration_ms() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_tool_stats_success_rate() {
        let ts = ToolStats {
            invocations: 10,
            successes: 8,
            failures: 2,
            total_duration_ms: 100,
        };
        assert!((ts.success_rate() - 0.8).abs() < 0.001);
    }
}
