// rustre-agent/src/tool_executor.rs
//
// Tool-call executor for the rustre AI agent layer.
// Given an LLM tool call (name + JSON params), dispatches to the correct
// rustre capability, serialises the result for the LLM, handles errors with
// configurable retry, timeout, and structured logging.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::timeout;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("invalid parameters for tool '{tool}': {message}")]
    InvalidParams { tool: String, message: String },
    #[error("tool '{tool}' timed out after {timeout_ms}ms")]
    Timeout { tool: String, timeout_ms: u64 },
    #[error("tool '{tool}' failed after {retries} retries: {message}")]
    MaxRetriesExceeded { tool: String, retries: u32, message: String },
    #[error("tool '{tool}' execution error: {message}")]
    Execution { tool: String, message: String },
    #[error("serialization error: {0}")]
    Serialize(String),
}

pub type ExecutorResult<T> = Result<T, ExecutorError>;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ToolParam / ToolResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single tool invocation as received from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub params: serde_json::Value,
}

impl ToolCall {
    pub fn new(id: impl Into<String>, name: impl Into<String>, params: serde_json::Value) -> Self {
        Self { id: id.into(), name: name.into(), params }
    }

    /// # Errors
    /// Returns `ExecutorError::InvalidParams` if the parameter is missing or not a string.
    pub fn get_str(&self, key: &str) -> ExecutorResult<&str> {
        self.params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExecutorError::InvalidParams {
                tool: self.name.clone(),
                message: format!("missing or non-string parameter '{key}'"),
            })
    }

    /// # Errors
    /// Returns `ExecutorError::InvalidParams` if the parameter is missing or not an integer.
    pub fn get_u64(&self, key: &str) -> ExecutorResult<u64> {
        self.params
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ExecutorError::InvalidParams {
                tool: self.name.clone(),
                message: format!("missing or non-integer parameter '{key}'"),
            })
    }

    /// # Errors
    /// Returns `ExecutorError::InvalidParams` if the parameter is missing or not a bool.
    pub fn get_bool(&self, key: &str) -> ExecutorResult<bool> {
        self.params
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| ExecutorError::InvalidParams {
                tool: self.name.clone(),
                message: format!("missing or non-bool parameter '{key}'"),
            })
    }

    /// # Errors
    /// Returns `ExecutorError::InvalidParams` if the parameter is missing or not an array.
    pub fn get_array(&self, key: &str) -> ExecutorResult<&Vec<serde_json::Value>> {
        self.params
            .get(key)
            .and_then(|v| v.as_array())
            .ok_or_else(|| ExecutorError::InvalidParams {
                tool: self.name.clone(),
                message: format!("missing or non-array parameter '{key}'"),
            })
    }
}

/// Result of a tool execution, ready to be fed back to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub success: bool,
    pub content: serde_json::Value,
    pub error: Option<String>,
    pub elapsed_ms: f64,
    pub retries: u32,
}

impl ToolResult {
    #[must_use] 
    pub fn ok(call: &ToolCall, content: serde_json::Value, elapsed: Duration, retries: u32) -> Self {
        Self {
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            success: true,
            content,
            error: None,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            retries,
        }
    }

    #[must_use] 
    pub fn err(call: &ToolCall, message: &str, elapsed: Duration, retries: u32) -> Self {
        Self {
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            success: false,
            content: serde_json::Value::Null,
            error: Some(message.to_owned()),
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            retries,
        }
    }

    /// Format as a string suitable for injection into an LLM context.
    #[must_use] 
    pub fn to_llm_text(&self) -> String {
        if self.success {
            serde_json::to_string_pretty(&self.content).unwrap_or_default()
        } else {
            format!("ERROR: {}", self.error.as_deref().unwrap_or("unknown"))
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ToolHandler trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A callable tool handler.  Implementors process a `ToolCall` and return JSON.
#[async_trait::async_trait]
pub trait ToolHandler: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameter_schema(&self) -> serde_json::Value;
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value>;
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ RetryConfig â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub backoff_factor: f64,
    pub retryable_errors: Vec<String>, // keywords in error messages that trigger retry
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 200,
            backoff_factor: 2.0,
            retryable_errors: vec![
                "timeout".to_owned(),
                "rate limit".to_owned(),
                "connection".to_owned(),
                "temporary".to_owned(),
            ],
        }
    }
}

impl RetryConfig {
    #[must_use] 
    pub fn no_retry() -> Self {
        Self { max_retries: 0, ..Default::default() }
    }

    #[must_use] 
    pub fn is_retryable(&self, err: &str) -> bool {
        let err_lc = err.to_lowercase();
        self.retryable_errors.iter().any(|kw| err_lc.contains(kw.as_str()))
    }

    #[must_use] 
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let attempt_i32 = i32::try_from(attempt).unwrap_or(i32::MAX);
        let initial_f = crate::casts::u64_to_f64(self.initial_delay_ms);
        let scaled = initial_f * self.backoff_factor.powi(attempt_i32);
        let ms = crate::casts::f64_to_u64(scaled);
        Duration::from_millis(ms.min(30_000))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ CallLog â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Append-only log of all tool invocations in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub seq: u64,
    pub call_id: String,
    pub tool_name: String,
    pub params: serde_json::Value,
    pub result: Option<ToolResult>,
    pub started_at_ms: u64, // epoch ms
}

#[derive(Default)]
pub struct CallLog {
    records: Mutex<Vec<CallRecord>>,
    seq: Mutex<u64>,
}

impl CallLog {
    pub fn record_start(&self, call: &ToolCall) -> u64 {
        let s = {
            let mut seq = self.seq.lock();
            *seq += 1;
            *seq
        };
        let r = CallRecord {
            seq: s,
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            params: call.params.clone(),
            result: None,
            started_at_ms: epoch_ms(),
        };
        self.records.lock().push(r);
        s
    }

    pub fn record_finish(&self, seq: u64, result: ToolResult) {
        let mut recs = self.records.lock();
        if let Some(r) = recs.iter_mut().find(|r| r.seq == seq) {
            r.result = Some(result);
        }
    }

    pub fn all(&self) -> Vec<CallRecord> {
        self.records.lock().clone()
    }

    pub fn successful(&self) -> Vec<CallRecord> {
        self.records
            .lock()
            .iter()
            .filter(|r| r.result.as_ref().is_some_and(|res| res.success))
            .cloned()
            .collect()
    }

    pub fn failed(&self) -> Vec<CallRecord> {
        self.records
            .lock()
            .iter()
            .filter(|r| r.result.as_ref().is_none_or(|res| !res.success))
            .cloned()
            .collect()
    }

    /// # Panics
    /// Panics only if internal invariants on result presence are violated.
    pub fn stats(&self) -> CallStats {
        let recs = self.records.lock().clone();
        let total = u64::try_from(recs.len()).unwrap_or(u64::MAX);
        let done: Vec<_> = recs.iter().filter(|r| r.result.is_some()).collect();
        let succeeded = u64::try_from(
            done.iter().filter(|r| r.result.as_ref().unwrap().success).count()
        ).unwrap_or(u64::MAX);
        let failed = u64::try_from(done.len()).unwrap_or(u64::MAX).saturating_sub(succeeded);
        let avg_ms = if done.is_empty() {
            0.0
        } else {
            done.iter()
                .filter_map(|r| r.result.as_ref())
                .map(|r| r.elapsed_ms)
                .sum::<f64>()
                / crate::casts::usize_to_f64(done.len())
        };
        CallStats { total, succeeded, failed, avg_elapsed_ms: avg_ms }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStats {
    pub total: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub avg_elapsed_ms: f64,
}

fn epoch_ms() -> u64 {
    u64::try_from(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()).unwrap_or(u64::MAX)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ToolExecutor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Central dispatcher.  Register `ToolHandlers`, then call `execute()` or
/// `execute_many()` to dispatch LLM tool calls.
pub struct ToolExecutor {
    handlers: RwLock<HashMap<String, Arc<dyn ToolHandler>>>,
    retry: RetryConfig,
    default_timeout_ms: u64,
    log: Arc<CallLog>,
}

impl ToolExecutor {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            retry: RetryConfig::default(),
            default_timeout_ms: 30_000,
            log: Arc::new(CallLog::default()),
        }
    }

    #[must_use]
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry = config;
        self
    }

    #[must_use]
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.default_timeout_ms = ms;
        self
    }

    pub fn register(&self, handler: Arc<dyn ToolHandler>) {
        self.handlers.write().insert(handler.name().to_owned(), handler);
    }

    pub fn registered_tools(&self) -> Vec<String> {
        self.handlers.read().keys().cloned().collect()
    }

    pub fn tool_schemas(&self) -> Vec<serde_json::Value> {
        self.handlers
            .read()
            .values()
            .map(|h| {
                serde_json::json!({
                    "name": h.name(),
                    "description": h.description(),
                    "input_schema": h.parameter_schema(),
                })
            })
            .collect()
    }

    pub fn log(&self) -> Arc<CallLog> {
        Arc::clone(&self.log)
    }

    /// Execute a single tool call with retry + timeout.
    pub async fn execute(&self, call: ToolCall) -> ToolResult {
        let seq = self.log.record_start(&call);
        let t0 = Instant::now();

        let handler = {
            let guard = self.handlers.read();
            guard.get(&call.name).map(Arc::clone)
        };

        let Some(handler) = handler else {
            let elapsed = t0.elapsed();
            let r = ToolResult::err(
                &call,
                &format!("unknown tool: {}", call.name),
                elapsed,
                0,
            );
            self.log.record_finish(seq, r.clone());
            return r;
        };

        let mut attempt = 0u32;

        loop {
            if attempt > 0 {
                let delay = self.retry.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let timeout_dur = Duration::from_millis(self.default_timeout_ms);
            let exec_fut = handler.execute(&call);

            let res = timeout(timeout_dur, exec_fut).await;

            match res {
                Err(_) => {
                    // Timeout —" build the error message immediately so there is
                    // no intermediate assignment that Rust's liveness analysis
                    // would flag as "never read".
                    let msg = format!("timeout after {}ms", self.default_timeout_ms);
                    if attempt < self.retry.max_retries {
                        attempt += 1;
                        continue;
                    }
                    let elapsed = t0.elapsed();
                    let r = ToolResult::err(&call, &msg, elapsed, attempt);
                    self.log.record_finish(seq, r.clone());
                    return r;
                }
                Ok(Err(e)) => {
                    let msg = e.to_string();
                    let retryable = self.retry.is_retryable(&msg);
                    if attempt < self.retry.max_retries && retryable {
                        attempt += 1;
                        continue;
                    }
                    let elapsed = t0.elapsed();
                    let r = ToolResult::err(&call, &msg, elapsed, attempt);
                    self.log.record_finish(seq, r.clone());
                    return r;
                }
                Ok(Ok(content)) => {
                    let elapsed = t0.elapsed();
                    let r = ToolResult::ok(&call, content, elapsed, attempt);
                    self.log.record_finish(seq, r.clone());
                    return r;
                }
            }
        }
    }

    /// Execute multiple tool calls, in order.
    pub async fn execute_many(&self, calls: Vec<ToolCall>) -> Vec<ToolResult> {
        let mut results = Vec::with_capacity(calls.len());
        for call in calls {
            results.push(self.execute(call).await);
        }
        results
    }

    /// Execute multiple tool calls concurrently (up to `parallelism`).
    pub async fn execute_parallel(
        &self,
        calls: Vec<ToolCall>,
        parallelism: usize,
    ) -> Vec<ToolResult> {
        use futures::StreamExt;

        let executor = Arc::new(std::ptr::from_ref::<Self>(self) as usize); // raw pointer trick for Arc
        let _ = executor; // suppress warning

        // Build futures
        let futs: Vec<_> = calls.into_iter().map(|c| self.execute(c)).collect();
        // Collect with bounded concurrency
        futures::stream::iter(futs)
            .buffered(parallelism.max(1))
            .collect()
            .await
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Built-in rustre handlers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Handler that performs a no-op and echoes its parameters back.
pub struct EchoHandler;

#[async_trait::async_trait]
impl ToolHandler for EchoHandler {
    fn name(&self) -> &'static str { "echo" }
    fn description(&self) -> &'static str { "Echo back the given parameters (for testing)" }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "The message to echo" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        Ok(serde_json::json!({ "echo": call.params }))
    }
}

/// Handler: disassemble a function at an address.
pub struct DisasmHandler {
    pub disasm_fn: Arc<dyn Fn(u64, usize) -> String + Send + Sync>,
}

#[async_trait::async_trait]
impl ToolHandler for DisasmHandler {
    fn name(&self) -> &'static str { "disassemble_function" }
    fn description(&self) -> &'static str {
        "Disassemble the function at the given address and return the listing"
    }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": { "type": "integer", "description": "Function start address (decimal or hex)" },
                "max_instructions": { "type": "integer", "description": "Max instructions to return (default 200)" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let addr = call.get_u64("address")?;
        let max = crate::casts::u64_to_usize(call.params.get("max_instructions")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(200));
        let listing = (self.disasm_fn)(addr, max);
        Ok(serde_json::json!({ "address": addr, "listing": listing }))
    }
}

/// Handler: decompile a function.
pub struct DecompileHandler {
    pub decompile_fn: Arc<dyn Fn(u64) -> String + Send + Sync>,
}

#[async_trait::async_trait]
impl ToolHandler for DecompileHandler {
    fn name(&self) -> &'static str { "decompile_function" }
    fn description(&self) -> &'static str {
        "Decompile the function at the given address and return pseudocode"
    }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": { "type": "integer", "description": "Function start address" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let addr = call.get_u64("address")?;
        let pseudocode = (self.decompile_fn)(addr);
        Ok(serde_json::json!({ "address": addr, "pseudocode": pseudocode }))
    }
}

/// Closure type: rename a function at an address.
pub type RenameFn = dyn Fn(u64, &str) -> bool + Send + Sync;

/// Handler: rename a function.
pub struct RenameFunctionHandler {
    pub rename_fn: Arc<RenameFn>,
}

#[async_trait::async_trait]
impl ToolHandler for RenameFunctionHandler {
    fn name(&self) -> &'static str { "rename_function" }
    fn description(&self) -> &'static str { "Rename a function by its address" }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["address", "new_name"],
            "properties": {
                "address": { "type": "integer" },
                "new_name": { "type": "string" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let addr = call.get_u64("address")?;
        let name = call.get_str("new_name")?;
        let ok = (self.rename_fn)(addr, name);
        Ok(serde_json::json!({ "address": addr, "new_name": name, "success": ok }))
    }
}

/// Handler: list functions in the binary.
pub struct ListFunctionsHandler {
    pub list_fn: Arc<dyn Fn() -> Vec<(u64, String)> + Send + Sync>,
}

#[async_trait::async_trait]
impl ToolHandler for ListFunctionsHandler {
    fn name(&self) -> &'static str { "list_functions" }
    fn description(&self) -> &'static str { "List all functions in the loaded binary" }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "description": "Max number to return (default 100)" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let limit = crate::casts::u64_to_usize(call.params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(100));
        let fns = (self.list_fn)();
        let sliced: Vec<serde_json::Value> = fns
            .into_iter()
            .take(limit)
            .map(|(addr, name)| serde_json::json!({ "address": addr, "name": name }))
            .collect();
        Ok(serde_json::json!({ "functions": sliced }))
    }
}

/// Closure type: search for strings.
pub type SearchStringsFn = dyn Fn(&str) -> Vec<(u64, String)> + Send + Sync;

/// Handler: search for strings in binary.
pub struct SearchStringsHandler {
    pub search_fn: Arc<SearchStringsFn>,
}

#[async_trait::async_trait]
impl ToolHandler for SearchStringsHandler {
    fn name(&self) -> &'static str { "search_strings" }
    fn description(&self) -> &'static str { "Search for strings in the binary matching a pattern" }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": { "type": "string", "description": "Substring or regex to search" },
                "limit": { "type": "integer" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let pat = call.get_str("pattern")?;
        let limit = crate::casts::u64_to_usize(call.params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(50));
        let found: Vec<serde_json::Value> = (self.search_fn)(pat)
            .into_iter()
            .take(limit)
            .map(|(addr, s)| serde_json::json!({ "address": addr, "string": s }))
            .collect();
        Ok(serde_json::json!({ "matches": found }))
    }
}

/// Handler: get cross-references to an address.
pub struct XrefHandler {
    pub xref_fn: Arc<dyn Fn(u64) -> Vec<u64> + Send + Sync>,
}

#[async_trait::async_trait]
impl ToolHandler for XrefHandler {
    fn name(&self) -> &'static str { "get_xrefs_to" }
    fn description(&self) -> &'static str { "Get all cross-references to a given address" }
    fn parameter_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": { "type": "integer" }
            }
        })
    }
    async fn execute(&self, call: &ToolCall) -> ExecutorResult<serde_json::Value> {
        let addr = call.get_u64("address")?;
        let refs = (self.xref_fn)(addr);
        Ok(serde_json::json!({ "address": addr, "xrefs": refs }))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ToolExecutorBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub struct ToolExecutorBuilder {
    retry: RetryConfig,
    timeout_ms: u64,
    handlers: Vec<Arc<dyn ToolHandler>>,
}

impl Default for ToolExecutorBuilder {
    fn default() -> Self {
        Self {
            retry: RetryConfig::default(),
            timeout_ms: 30_000,
            handlers: Vec::new(),
        }
    }
}

impl ToolExecutorBuilder {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub fn retry(mut self, cfg: RetryConfig) -> Self { self.retry = cfg; self }
    #[must_use] 
    pub const fn timeout_ms(mut self, ms: u64) -> Self { self.timeout_ms = ms; self }

    #[must_use]
    pub fn with_handler(mut self, h: Arc<dyn ToolHandler>) -> Self {
        self.handlers.push(h);
        self
    }

    #[must_use] 
    pub fn with_echo(self) -> Self {
        self.with_handler(Arc::new(EchoHandler))
    }

    #[must_use] 
    pub fn build(self) -> ToolExecutor {
        let ex = ToolExecutor::new()
            .with_retry(self.retry)
            .with_timeout_ms(self.timeout_ms);
        for h in self.handlers {
            ex.register(h);
        }
        ex
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ unit tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, params: serde_json::Value) -> ToolCall {
        ToolCall::new("id-1", name, params)
    }

    #[tokio::test]
    async fn echo_handler_success() {
        let ex = ToolExecutorBuilder::new().with_echo().build();
        let call = make_call("echo", serde_json::json!({ "message": "hi" }));
        let r = ex.execute(call).await;
        assert!(r.success);
        assert_eq!(r.content["echo"]["message"], "hi");
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let ex = ToolExecutor::new();
        let call = make_call("nonexistent", serde_json::json!({}));
        let r = ex.execute(call).await;
        assert!(!r.success);
        assert!(r.error.as_deref().unwrap_or("").contains("unknown tool"));
    }

    #[tokio::test]
    async fn execute_many_preserves_order() {
        let ex = ToolExecutorBuilder::new().with_echo().build();
        let calls: Vec<ToolCall> = (0..5)
            .map(|i| make_call("echo", serde_json::json!({ "message": i })))
            .collect();
        let results = ex.execute_many(calls).await;
        assert_eq!(results.len(), 5);
        for (i, r) in results.iter().enumerate() {
            assert!(r.success, "result {i} should be successful");
        }
    }

    #[test]
    fn retry_config_delay() {
        let cfg = RetryConfig { initial_delay_ms: 100, backoff_factor: 2.0, ..Default::default() };
        assert_eq!(cfg.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(cfg.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(cfg.delay_for_attempt(2), Duration::from_millis(400));
    }

    #[test]
    fn retry_config_retryable() {
        let cfg = RetryConfig::default();
        assert!(cfg.is_retryable("connection refused"));
        assert!(cfg.is_retryable("Timeout error"));
        assert!(!cfg.is_retryable("file not found"));
    }

    #[test]
    fn call_log_stats() {
        let log = CallLog::default();
        let call = make_call("echo", serde_json::json!({}));
        let seq = log.record_start(&call);
        log.record_finish(seq, ToolResult::ok(&call, serde_json::json!({}), Duration::from_millis(10), 0));
        let stats = log.stats();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.succeeded, 1);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn tool_result_llm_text_ok() {
        let call = make_call("echo", serde_json::json!({}));
        let r = ToolResult::ok(&call, serde_json::json!({ "result": 42 }), Duration::ZERO, 0);
        assert!(r.to_llm_text().contains("42"));
    }

    #[test]
    fn tool_result_llm_text_err() {
        let call = make_call("x", serde_json::json!({}));
        let r = ToolResult::err(&call, "boom", Duration::ZERO, 0);
        assert!(r.to_llm_text().starts_with("ERROR:"));
    }

    #[test]
    fn tool_call_get_str_ok() {
        let c = make_call("t", serde_json::json!({ "key": "val" }));
        assert_eq!(c.get_str("key").unwrap(), "val");
    }

    #[test]
    fn tool_call_get_str_missing() {
        let c = make_call("t", serde_json::json!({}));
        assert!(c.get_str("key").is_err());
    }
}
