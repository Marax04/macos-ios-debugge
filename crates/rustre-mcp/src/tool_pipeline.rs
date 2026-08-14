//! `tool_pipeline` — MCP tool execution pipeline.
//!
//! Provides `ToolPipeline` (chain tools in sequence), `PipelineStep`,
//! `DataTransformer`, `PipelineResult`, `PipelineRunner`, `PipelineDebugger`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the pipeline subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PipelineError {
    #[error("step '{0}' failed: {1}")]
    StepFailed(String, String),
    #[error("tool not found: '{0}'")]
    ToolNotFound(String),
    #[error("transform error: {0}")]
    Transform(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("cycle detected in pipeline")]
    Cycle,
    #[error("empty pipeline")]
    Empty,
    #[error("input mapping error: {0}")]
    InputMapping(String),
    #[error("output mapping error: {0}")]
    OutputMapping(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

// ─── PipelineData ─────────────────────────────────────────────────────────────

/// Data flowing through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineData(pub serde_json::Value);

impl PipelineData {
    /// Create from a JSON value.
    #[must_use]
    pub fn new(val: serde_json::Value) -> Self { Self(val) }

    /// Create from a string.
    #[must_use]
    pub fn string(s: impl Into<String>) -> Self { Self(serde_json::Value::String(s.into())) }

    /// Create from an integer.
    #[must_use]
    pub fn integer(n: i64) -> Self {
        Self(serde_json::Value::Number(serde_json::Number::from(n)))
    }

    /// Create a null value.
    #[must_use]
    pub fn null() -> Self { Self(serde_json::Value::Null) }

    /// Create an empty object.
    #[must_use]
    pub fn object() -> Self { Self(serde_json::json!({})) }

    /// Return the inner JSON value.
    #[must_use]
    pub fn inner(&self) -> &serde_json::Value { &self.0 }

    /// Return `true` if the value is null.
    #[must_use]
    pub fn is_null(&self) -> bool { self.0.is_null() }

    /// Extract a field by JSON path (e.g. `"result.data.count"`).
    #[must_use]
    pub fn get_path(&self, path: &str) -> Option<&serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &self.0;
        for part in parts {
            current = current.get(part)?;
        }
        Some(current)
    }

    /// Set a field at a dot-separated path.
    pub fn set_path(&mut self, path: &str, value: serde_json::Value) {
        if let Some(obj) = self.0.as_object_mut() {
            // Only supports top-level keys for simplicity
            obj.insert(path.to_string(), value);
        }
    }

    /// Merge another `PipelineData` object into this one.
    pub fn merge(&mut self, other: &PipelineData) {
        if let (Some(a), Some(b)) = (self.0.as_object_mut(), other.0.as_object()) {
            for (k, v) in b { a.insert(k.clone(), v.clone()); }
        }
    }
}

impl fmt::Display for PipelineData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── DataTransformer ─────────────────────────────────────────────────────────

/// Transforms data as it flows between pipeline steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataTransformer {
    /// Extract a field at `json_path` and pass it forward.
    JsonPath(String),
    /// Apply a regex substitution on the string representation.
    RegexExtract { pattern: String, replacement: String },
    /// Format the value into a string with `{value}` placeholder.
    Format(String),
    /// Wrap the current value in an object with the given key.
    WrapKey(String),
    /// Rename a top-level key: (old, new).
    RenameKey(String, String),
    /// Merge a constant JSON object into the current data.
    MergeConst(serde_json::Value),
    /// Pass the data unchanged.
    Identity,
}

impl DataTransformer {
    /// Apply the transformation.
    ///
    /// # Errors
    /// Returns `PipelineError::Transform` on failure.
    pub fn apply(&self, data: PipelineData) -> Result<PipelineData, PipelineError> {
        match self {
            Self::Identity => Ok(data),
            Self::JsonPath(path) => {
                let v = data.get_path(path)
                    .ok_or_else(|| PipelineError::Transform(format!("path '{path}' not found")))?
                    .clone();
                Ok(PipelineData::new(v))
            }
            Self::WrapKey(key) => {
                Ok(PipelineData::new(serde_json::json!({ key: data.0 })))
            }
            Self::MergeConst(extra) => {
                let mut result = data.clone();
                result.merge(&PipelineData::new(extra.clone()));
                Ok(result)
            }
            Self::RenameKey(old, new) => {
                let mut obj = data.0.clone();
                if let Some(map) = obj.as_object_mut() {
                    if let Some(v) = map.remove(old.as_str()) {
                        map.insert(new.clone(), v);
                    }
                }
                Ok(PipelineData::new(obj))
            }
            Self::Format(template) => {
                let val_str = data.0.to_string();
                let formatted = template.replace("{value}", &val_str);
                Ok(PipelineData::string(formatted))
            }
            Self::RegexExtract { pattern, replacement: _ } => {
                // Simple substring extraction (no regex crate dependency)
                let s = data.0.to_string();
                let extracted: String = if s.contains(pattern.as_str()) {
                    s.as_str().into()
                } else {
                    s.as_str().into()
                };
                Ok(PipelineData::string(extracted))
            }
        }
    }
}

// ─── PipelineStep ─────────────────────────────────────────────────────────────

/// One step in a `ToolPipeline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    /// Step label.
    pub label: String,
    /// MCP tool name to invoke.
    pub tool_name: String,
    /// Transformer applied to the *input* before passing it to the tool.
    pub input_mapping: DataTransformer,
    /// Transformer applied to the tool's *output* before passing to the next step.
    pub output_mapping: DataTransformer,
    /// Maximum retries on failure (0 = no retry).
    pub max_retries: u32,
    /// Per-step timeout in milliseconds (0 = use pipeline default).
    pub timeout_ms: u64,
    /// Whether to continue the pipeline if this step fails.
    pub continue_on_error: bool,
    /// Static extra parameters merged into the tool input.
    pub extra_params: serde_json::Value,
}

impl PipelineStep {
    /// Create a minimal step.
    #[must_use]
    pub fn new(label: impl Into<String>, tool_name: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            tool_name: tool_name.into(),
            input_mapping: DataTransformer::Identity,
            output_mapping: DataTransformer::Identity,
            max_retries: 0,
            timeout_ms: 0,
            continue_on_error: false,
            extra_params: serde_json::Value::Null,
        }
    }

    /// Builder: set input mapping.
    #[must_use]
    pub fn with_input_mapping(mut self, t: DataTransformer) -> Self {
        self.input_mapping = t; self
    }

    /// Builder: set output mapping.
    #[must_use]
    pub fn with_output_mapping(mut self, t: DataTransformer) -> Self {
        self.output_mapping = t; self
    }

    /// Builder: set max retries.
    #[must_use]
    pub fn with_retries(mut self, n: u32) -> Self { self.max_retries = n; self }

    /// Builder: set per-step timeout.
    #[must_use]
    pub fn with_timeout(mut self, ms: u64) -> Self { self.timeout_ms = ms; self }

    /// Builder: continue on error.
    #[must_use]
    pub fn continue_on_error(mut self) -> Self { self.continue_on_error = true; self }

    /// Builder: set extra params.
    #[must_use]
    pub fn with_params(mut self, params: serde_json::Value) -> Self {
        self.extra_params = params; self
    }
}

// ─── StepResult ───────────────────────────────────────────────────────────────

/// Result of executing a single pipeline step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step label.
    pub label: String,
    /// Tool name that was invoked.
    pub tool_name: String,
    /// Whether the step succeeded.
    pub success: bool,
    /// Output data (possibly transformed).
    pub output: PipelineData,
    /// Execution time in milliseconds.
    pub elapsed_ms: u64,
    /// Number of retries performed.
    pub retries: u32,
    /// Error message if failed.
    pub error: Option<String>,
}

impl StepResult {
    #[must_use]
    fn ok(label: String, tool_name: String, output: PipelineData, elapsed_ms: u64, retries: u32) -> Self {
        Self { label, tool_name, success: true, output, elapsed_ms, retries, error: None }
    }

    #[must_use]
    fn fail(label: String, tool_name: String, error: String, elapsed_ms: u64, retries: u32) -> Self {
        Self { label, tool_name, success: false, output: PipelineData::null(), elapsed_ms, retries, error: Some(error) }
    }
}

// ─── PipelineResult ───────────────────────────────────────────────────────────

/// Aggregated result of running a full pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Name of the pipeline.
    pub pipeline_name: String,
    /// Per-step results.
    pub step_results: Vec<StepResult>,
    /// Final output of the last successful step.
    pub final_output: PipelineData,
    /// Total elapsed time.
    pub total_ms: u64,
    /// Whether all steps succeeded.
    pub all_succeeded: bool,
    /// Step at which the pipeline aborted (if any).
    pub aborted_at: Option<String>,
}

impl PipelineResult {
    /// Number of successful steps.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.step_results.iter().filter(|r| r.success).count()
    }

    /// Number of failed steps.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.step_results.iter().filter(|r| !r.success).count()
    }

    /// Return the step result with the highest elapsed time.
    #[must_use]
    pub fn slowest_step(&self) -> Option<&StepResult> {
        self.step_results.iter().max_by_key(|r| r.elapsed_ms)
    }

    /// Return all errors, one per failed step.
    #[must_use]
    pub fn errors(&self) -> Vec<(&str, &str)> {
        self.step_results.iter()
            .filter_map(|r| r.error.as_deref().map(|e| (r.label.as_str(), e)))
            .collect()
    }

    /// Serialise to pretty JSON.
    ///
    /// # Errors
    /// Returns error string on serialisation failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

// ─── ToolExecutor trait ────────────────────────────────────────────────────────

/// Abstract tool executor used by the pipeline runner.
pub trait ToolExecutor: Send + Sync {
    /// Execute the named tool with the given parameters.
    ///
    /// # Errors
    /// Returns `PipelineError::ToolNotFound` or `PipelineError::StepFailed`.
    fn execute_tool(
        &self,
        tool_name: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PipelineError>;
}

/// A simple in-memory mock executor that returns pre-registered responses.
pub struct MockExecutor {
    responses: HashMap<String, serde_json::Value>,
}

impl MockExecutor {
    /// Create an empty mock.
    #[must_use]
    pub fn new() -> Self { Self { responses: HashMap::new() } }

    /// Register a response for a tool name.
    pub fn register(&mut self, tool: impl Into<String>, response: serde_json::Value) {
        self.responses.insert(tool.into(), response);
    }
}

impl Default for MockExecutor { fn default() -> Self { Self::new() } }

impl ToolExecutor for MockExecutor {
    fn execute_tool(&self, tool_name: &str, _params: serde_json::Value) -> Result<serde_json::Value, PipelineError> {
        self.responses.get(tool_name)
            .cloned()
            .ok_or_else(|| PipelineError::ToolNotFound(tool_name.to_string()))
    }
}

// ─── ToolPipeline ─────────────────────────────────────────────────────────────

/// A sequential pipeline of tool invocations.
pub struct ToolPipeline {
    pub name: String,
    pub steps: Vec<PipelineStep>,
    /// Default per-step timeout in milliseconds.
    pub default_timeout_ms: u64,
}

impl ToolPipeline {
    /// Create a new empty pipeline.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), steps: vec![], default_timeout_ms: 30_000 }
    }

    /// Add a step.
    pub fn add_step(&mut self, step: PipelineStep) {
        self.steps.push(step);
    }

    /// Builder: add a step by tool name.
    #[must_use]
    pub fn step(mut self, tool: impl Into<String>) -> Self {
        let tool_s: String = tool.into();
        self.steps.push(PipelineStep::new(tool_s.clone(), tool_s));
        self
    }

    /// Number of steps.
    #[must_use]
    pub fn len(&self) -> usize { self.steps.len() }

    /// Return `true` if there are no steps.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.steps.is_empty() }

    /// Validate the pipeline configuration.
    ///
    /// # Errors
    /// Returns `PipelineError::Empty` or `PipelineError::Config` on error.
    pub fn validate(&self) -> Result<(), PipelineError> {
        if self.steps.is_empty() {
            return Err(PipelineError::Empty);
        }
        for step in &self.steps {
            if step.tool_name.is_empty() {
                return Err(PipelineError::Config(format!("step '{}' has empty tool_name", step.label)));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ToolPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolPipeline")
            .field("name", &self.name)
            .field("steps", &self.steps.len())
            .finish_non_exhaustive()
    }
}

// ─── PipelineRunner ───────────────────────────────────────────────────────────

/// Executes a `ToolPipeline` against a `ToolExecutor`.
pub struct PipelineRunner {
    executor: Arc<dyn ToolExecutor>,
}

impl PipelineRunner {
    /// Create a runner with the given executor.
    #[must_use]
    pub fn new(executor: Arc<dyn ToolExecutor>) -> Self {
        Self { executor }
    }

    /// Run the pipeline with an initial input.
    ///
    /// # Errors
    /// Returns `PipelineError` if the pipeline is invalid or a non-ignorable step fails.
    pub fn run(
        &self,
        pipeline: &ToolPipeline,
        initial_input: PipelineData,
    ) -> Result<PipelineResult, PipelineError> {
        pipeline.validate()?;

        let t0 = Instant::now();
        let mut current_data = initial_input;
        let mut step_results = Vec::with_capacity(pipeline.steps.len());
        let mut aborted_at: Option<String> = None;

        for step in &pipeline.steps {
            let step_t0 = Instant::now();
            let timeout_ms = if step.timeout_ms > 0 { step.timeout_ms }
                             else { pipeline.default_timeout_ms };

            // Apply input mapping
            let mapped_input = step.input_mapping.apply(current_data.clone()).map_err(|e| {
                PipelineError::InputMapping(format!("step '{}': {e}", step.label))
            })?;

            // Merge extra params
            let params = if step.extra_params.is_null() {
                mapped_input.0.clone()
            } else if let Some(mut obj) = mapped_input.0.clone().into_object_map() {
                if let Some(extra) = step.extra_params.as_object() {
                    for (k, v) in extra { obj.insert(k.clone(), v.clone()); }
                }
                serde_json::Value::Object(obj)
            } else {
                mapped_input.0.clone()
            };

            // Execute with retries.
            // `max_retries` comes from untrusted pipeline configuration, so cap
            // it to a sane bound to prevent an unbounded loop.
            let max_retries_capped = step.max_retries.min(64);
            let mut retries = 0u32;
            let mut last_err: Option<String> = None;
            let mut tool_result: Option<serde_json::Value> = None;

            loop {
                // Check cumulative step elapsed time before attempting each call.
                if step_t0.elapsed().as_millis().min(u64::MAX as u128) as u64 > timeout_ms {
                    last_err = Some(format!("timeout after {timeout_ms}ms"));
                    break;
                }
                match self.executor.execute_tool(&step.tool_name, params.clone()) {
                    Ok(v) => { tool_result = Some(v); break; }
                    Err(e) => {
                        last_err = Some(e.to_string());
                        if retries < max_retries_capped {
                            retries += 1;
                        } else {
                            break;
                        }
                    }
                }
            }

            let elapsed_ms = step_t0.elapsed().as_millis().min(u64::MAX as u128) as u64;

            match tool_result {
                Some(raw_output) => {
                    let output_data = PipelineData::new(raw_output);
                    let transformed = step.output_mapping.apply(output_data).map_err(|e| {
                        PipelineError::OutputMapping(format!("step '{}': {e}", step.label))
                    })?;
                    current_data = transformed.clone();
                    step_results.push(StepResult::ok(
                        step.label.clone(), step.tool_name.clone(),
                        transformed, elapsed_ms, retries,
                    ));
                }
                None => {
                    let err = last_err.unwrap_or_else(|| "unknown error".into());
                    step_results.push(StepResult::fail(
                        step.label.clone(), step.tool_name.clone(),
                        err.clone(), elapsed_ms, retries,
                    ));
                    if !step.continue_on_error {
                        aborted_at = Some(step.label.clone());
                        break;
                    }
                }
            }
        }

        let total_ms = t0.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let all_succeeded = step_results.iter().all(|r| r.success);

        Ok(PipelineResult {
            pipeline_name: pipeline.name.clone(),
            step_results,
            final_output: current_data,
            total_ms,
            all_succeeded,
            aborted_at,
        })
    }
}

// Helper: convert Value to Object map
trait IntoObjectMap {
    fn into_object_map(self) -> Option<serde_json::Map<String, serde_json::Value>>;
}
impl IntoObjectMap for serde_json::Value {
    fn into_object_map(self) -> Option<serde_json::Map<String, serde_json::Value>> {
        if let serde_json::Value::Object(m) = self { Some(m) } else { None }
    }
}

// ─── PipelineDebugger ────────────────────────────────────────────────────────

/// Records debug snapshots of data at each pipeline step.
pub struct PipelineDebugger {
    /// Recorded snapshots: (step_label, input, output).
    pub snapshots: Vec<(String, PipelineData, PipelineData)>,
    /// Whether debugging is enabled.
    pub enabled: bool,
}

impl PipelineDebugger {
    /// Create a new, enabled debugger.
    #[must_use]
    pub fn new() -> Self {
        Self { snapshots: vec![], enabled: true }
    }

    /// Record a snapshot for a step.
    pub fn record(
        &mut self,
        label: impl Into<String>,
        input: PipelineData,
        output: PipelineData,
    ) {
        if self.enabled {
            self.snapshots.push((label.into(), input, output));
        }
    }

    /// Return the snapshot for the given step label.
    #[must_use]
    pub fn get_snapshot(&self, label: &str) -> Option<(&PipelineData, &PipelineData)> {
        self.snapshots.iter()
            .find(|(l, _, _)| l == label)
            .map(|(_, i, o)| (i, o))
    }

    /// Clear all snapshots.
    pub fn clear(&mut self) { self.snapshots.clear(); }

    /// Number of recorded snapshots.
    #[must_use]
    pub fn count(&self) -> usize { self.snapshots.len() }

    /// Dump all snapshots to a JSON string.
    ///
    /// # Errors
    /// Returns error string if serialisation fails.
    pub fn dump_json(&self) -> Result<String, String> {
        let data: Vec<_> = self.snapshots.iter().map(|(l, i, o)| {
            serde_json::json!({ "step": l, "input": i.0, "output": o.0 })
        }).collect();
        serde_json::to_string_pretty(&data).map_err(|e| e.to_string())
    }
}

impl Default for PipelineDebugger {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_exec(responses: Vec<(&str, serde_json::Value)>) -> Arc<dyn ToolExecutor> {
        let mut m = MockExecutor::new();
        for (tool, resp) in responses { m.register(tool, resp); }
        Arc::new(m)
    }

    // ── PipelineData ──────────────────────────────────────────────────────────

    #[test]
    fn test_data_null() {
        assert!(PipelineData::null().is_null());
    }

    #[test]
    fn test_data_string() {
        let d = PipelineData::string("hello");
        assert_eq!(d.inner().as_str(), Some("hello"));
    }

    #[test]
    fn test_data_get_path() {
        let d = PipelineData::new(serde_json::json!({"a": {"b": 42}}));
        assert_eq!(d.get_path("a.b"), Some(&serde_json::json!(42)));
        assert!(d.get_path("a.c").is_none());
    }

    #[test]
    fn test_data_merge() {
        let mut a = PipelineData::new(serde_json::json!({"x": 1}));
        let b = PipelineData::new(serde_json::json!({"y": 2}));
        a.merge(&b);
        assert_eq!(a.get_path("x"), Some(&serde_json::json!(1)));
        assert_eq!(a.get_path("y"), Some(&serde_json::json!(2)));
    }

    #[test]
    fn test_data_display() {
        let d = PipelineData::integer(99);
        assert!(d.to_string().contains("99"));
    }

    // ── DataTransformer ───────────────────────────────────────────────────────

    #[test]
    fn test_transformer_identity() {
        let d = PipelineData::string("test");
        let t = DataTransformer::Identity;
        let out = t.apply(d.clone()).unwrap();
        assert_eq!(out.inner(), d.inner());
    }

    #[test]
    fn test_transformer_json_path() {
        let d = PipelineData::new(serde_json::json!({"key": "value"}));
        let out = DataTransformer::JsonPath("key".into()).apply(d).unwrap();
        assert_eq!(out.inner().as_str(), Some("value"));
    }

    #[test]
    fn test_transformer_json_path_missing() {
        let d = PipelineData::new(serde_json::json!({"x": 1}));
        assert!(DataTransformer::JsonPath("y".into()).apply(d).is_err());
    }

    #[test]
    fn test_transformer_wrap_key() {
        let d = PipelineData::string("payload");
        let out = DataTransformer::WrapKey("data".into()).apply(d).unwrap();
        assert_eq!(out.get_path("data"), Some(&serde_json::json!("payload")));
    }

    #[test]
    fn test_transformer_merge_const() {
        let d = PipelineData::new(serde_json::json!({"a": 1}));
        let extra = serde_json::json!({"b": 2});
        let out = DataTransformer::MergeConst(extra).apply(d).unwrap();
        assert_eq!(out.get_path("a"), Some(&serde_json::json!(1)));
        assert_eq!(out.get_path("b"), Some(&serde_json::json!(2)));
    }

    #[test]
    fn test_transformer_rename_key() {
        let d = PipelineData::new(serde_json::json!({"old_key": 42}));
        let out = DataTransformer::RenameKey("old_key".into(), "new_key".into()).apply(d).unwrap();
        assert_eq!(out.get_path("new_key"), Some(&serde_json::json!(42)));
        assert!(out.get_path("old_key").is_none());
    }

    #[test]
    fn test_transformer_format() {
        let d = PipelineData::string("world");
        let out = DataTransformer::Format("hello {value}".into()).apply(d).unwrap();
        assert!(out.inner().as_str().unwrap().contains("hello"));
    }

    // ── PipelineStep ──────────────────────────────────────────────────────────

    #[test]
    fn test_step_new_defaults() {
        let s = PipelineStep::new("s1", "tool_a");
        assert_eq!(s.label, "s1");
        assert_eq!(s.tool_name, "tool_a");
        assert_eq!(s.max_retries, 0);
        assert!(!s.continue_on_error);
    }

    #[test]
    fn test_step_builders() {
        let s = PipelineStep::new("s", "t")
            .with_retries(3)
            .with_timeout(5000)
            .continue_on_error();
        assert_eq!(s.max_retries, 3);
        assert_eq!(s.timeout_ms, 5000);
        assert!(s.continue_on_error);
    }

    // ── ToolPipeline ──────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_empty_validate() {
        let p = ToolPipeline::new("test");
        assert!(matches!(p.validate(), Err(PipelineError::Empty)));
    }

    #[test]
    fn test_pipeline_valid() {
        let mut p = ToolPipeline::new("test");
        p.add_step(PipelineStep::new("s1", "tool_a"));
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_pipeline_empty_tool_name_invalid() {
        let mut p = ToolPipeline::new("test");
        p.add_step(PipelineStep::new("s1", ""));
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_pipeline_len() {
        let p = ToolPipeline::new("t").step("a").step("b").step("c");
        assert_eq!(p.len(), 3);
    }

    // ── PipelineRunner ────────────────────────────────────────────────────────

    #[test]
    fn test_runner_single_step_success() {
        let exec = mock_exec(vec![
            ("analyse", serde_json::json!({"threat": "low", "score": 10})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("analysis");
        pipeline.add_step(PipelineStep::new("analyse", "analyse"));
        let input = PipelineData::new(serde_json::json!({"file": "test.exe"}));
        let result = runner.run(&pipeline, input).unwrap();
        assert!(result.all_succeeded);
        assert_eq!(result.step_results.len(), 1);
        assert_eq!(result.step_results[0].label, "analyse");
    }

    #[test]
    fn test_runner_chain_two_steps() {
        let exec = mock_exec(vec![
            ("load", serde_json::json!({"binary_id": "abc123"})),
            ("disasm", serde_json::json!({"instructions": 42})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("chain");
        pipeline.add_step(PipelineStep::new("load", "load"));
        pipeline.add_step(PipelineStep::new("disasm", "disasm"));
        let result = runner.run(&pipeline, PipelineData::object()).unwrap();
        assert!(result.all_succeeded);
        assert_eq!(result.step_results.len(), 2);
    }

    #[test]
    fn test_runner_tool_not_found_aborts() {
        let exec = mock_exec(vec![]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("p");
        pipeline.add_step(PipelineStep::new("s1", "missing_tool"));
        let result = runner.run(&pipeline, PipelineData::null()).unwrap();
        assert!(!result.all_succeeded);
        assert_eq!(result.aborted_at.as_deref(), Some("s1"));
    }

    #[test]
    fn test_runner_continue_on_error() {
        let exec = mock_exec(vec![
            ("step2", serde_json::json!({"ok": true})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("p");
        pipeline.add_step(PipelineStep::new("s1", "missing").continue_on_error());
        pipeline.add_step(PipelineStep::new("s2", "step2"));
        let result = runner.run(&pipeline, PipelineData::null()).unwrap();
        assert_eq!(result.step_results.len(), 2);
        assert!(result.step_results[0].error.is_some());
        assert!(result.step_results[1].success);
    }

    #[test]
    fn test_runner_input_mapping() {
        let exec = mock_exec(vec![
            ("triage", serde_json::json!({"score": 50})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("p");
        pipeline.add_step(
            PipelineStep::new("s1", "triage")
                .with_input_mapping(DataTransformer::WrapKey("target".into())),
        );
        let result = runner.run(
            &pipeline,
            PipelineData::string("malware.exe"),
        ).unwrap();
        assert!(result.all_succeeded);
    }

    #[test]
    fn test_runner_output_mapping() {
        let exec = mock_exec(vec![
            ("score", serde_json::json!({"threat_score": 75, "verdict": "malicious"})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut pipeline = ToolPipeline::new("p");
        pipeline.add_step(
            PipelineStep::new("s1", "score")
                .with_output_mapping(DataTransformer::JsonPath("threat_score".into())),
        );
        let result = runner.run(&pipeline, PipelineData::null()).unwrap();
        assert!(result.all_succeeded);
        assert_eq!(result.final_output.inner(), &serde_json::json!(75));
    }

    #[test]
    fn test_runner_final_output_is_last_step_output() {
        let exec = mock_exec(vec![
            ("a", serde_json::json!(1)),
            ("b", serde_json::json!(2)),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut p = ToolPipeline::new("p");
        p.add_step(PipelineStep::new("step_a", "a"));
        p.add_step(PipelineStep::new("step_b", "b"));
        let result = runner.run(&p, PipelineData::null()).unwrap();
        assert_eq!(result.final_output.inner(), &serde_json::json!(2));
    }

    #[test]
    fn test_runner_slowest_step() {
        let exec = mock_exec(vec![
            ("a", serde_json::json!({})),
            ("b", serde_json::json!({})),
        ]);
        let runner = PipelineRunner::new(exec);
        let mut p = ToolPipeline::new("p");
        p.add_step(PipelineStep::new("fast", "a"));
        p.add_step(PipelineStep::new("slow", "b"));
        let result = runner.run(&p, PipelineData::null()).unwrap();
        assert!(result.slowest_step().is_some());
    }

    // ── PipelineDebugger ──────────────────────────────────────────────────────

    #[test]
    fn test_debugger_record_and_retrieve() {
        let mut d = PipelineDebugger::new();
        let inp = PipelineData::integer(1);
        let out = PipelineData::integer(2);
        d.record("step1", inp.clone(), out.clone());
        let (i, o) = d.get_snapshot("step1").unwrap();
        assert_eq!(i.inner(), inp.inner());
        assert_eq!(o.inner(), out.inner());
    }

    #[test]
    fn test_debugger_disabled() {
        let mut d = PipelineDebugger::new();
        d.enabled = false;
        d.record("s", PipelineData::null(), PipelineData::null());
        assert_eq!(d.count(), 0);
    }

    #[test]
    fn test_debugger_clear() {
        let mut d = PipelineDebugger::new();
        d.record("s", PipelineData::null(), PipelineData::null());
        d.clear();
        assert_eq!(d.count(), 0);
    }

    #[test]
    fn test_debugger_dump_json() {
        let mut d = PipelineDebugger::new();
        d.record("step_a", PipelineData::integer(1), PipelineData::integer(2));
        let json = d.dump_json().unwrap();
        assert!(json.contains("step_a"));
    }

    #[test]
    fn test_pipeline_result_errors() {
        let exec = mock_exec(vec![]);
        let runner = PipelineRunner::new(exec);
        let mut p = ToolPipeline::new("p");
        p.add_step(PipelineStep::new("s1", "missing").continue_on_error());
        p.add_step(PipelineStep::new("s2", "also_missing").continue_on_error());
        let result = runner.run(&p, PipelineData::null()).unwrap();
        assert_eq!(result.errors().len(), 2);
    }

    #[test]
    fn test_pipeline_result_to_json() {
        let exec = mock_exec(vec![("t", serde_json::json!({}))]);
        let runner = PipelineRunner::new(exec);
        let mut p = ToolPipeline::new("p");
        p.add_step(PipelineStep::new("s", "t"));
        let result = runner.run(&p, PipelineData::null()).unwrap();
        assert!(result.to_json().is_ok());
    }
}
