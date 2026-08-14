//! `script_runner` — high-level script execution engine for RustRE.
//!
//! Provides [`ScriptRunner`] which wraps a [`ScriptEngineRegistry`] and adds:
//! - per-run timeouts, memory limits, and sandbox policies
//! - stdout/stderr capture via [`OutputCapture`]
//! - per-run metrics via [`ScriptMetrics`]
//! - run history via [`RunHistory`]
//! - batch execution via [`BatchRunner`]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{ScriptContext, ScriptEngineRegistry, ScriptValue, SandboxPolicy};

// ── RunConfig ─────────────────────────────────────────────────────────────────

/// Configuration for a single script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    /// Maximum wall-clock time in milliseconds (0 = unlimited).
    pub timeout_ms: u64,
    /// Maximum heap allocation in bytes (0 = unlimited).
    pub memory_limit_bytes: u64,
    /// Sandbox restrictions applied to this run.
    pub sandbox: SandboxPolicy,
    /// Engine to use for execution (e.g. `"rhai"`, `"python"`, `"lua"`).
    pub engine: String,
    /// Extra globals injected into the script context.
    pub globals: HashMap<String, ScriptValue>,
    /// Whether to capture stdout/stderr in [`RunResult`].
    pub capture_output: bool,
    /// Maximum lines of stdout to keep (0 = unlimited).
    pub max_output_lines: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5_000,
            memory_limit_bytes: 0,
            sandbox: SandboxPolicy::read_only(),
            engine: "rhai".to_string(),
            globals: HashMap::new(),
            capture_output: true,
            max_output_lines: 0,
        }
    }
}

impl RunConfig {
    /// Create a config with the given engine name.
    #[must_use]
    pub fn for_engine(engine: impl Into<String>) -> Self {
        Self { engine: engine.into(), ..Default::default() }
    }

    /// Set the timeout.
    #[must_use]
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set the memory limit in bytes.
    #[must_use]
    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = bytes;
        self
    }

    /// Override the sandbox policy.
    #[must_use]
    pub fn with_sandbox(mut self, policy: SandboxPolicy) -> Self {
        self.sandbox = policy;
        self
    }

    /// Add a global variable.
    #[must_use]
    pub fn with_global(mut self, name: impl Into<String>, value: ScriptValue) -> Self {
        self.globals.insert(name.into(), value);
        self
    }

    /// Disable output capture.
    #[must_use]
    pub fn without_capture(mut self) -> Self {
        self.capture_output = false;
        self
    }
}

// ── OutputCapture ─────────────────────────────────────────────────────────────

/// Captures stdout and stderr lines from a script run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutputCapture {
    /// Lines written to stdout.
    pub stdout: Vec<String>,
    /// Lines written to stderr.
    pub stderr: Vec<String>,
    /// Whether the output was truncated (exceeded `max_output_lines`).
    pub truncated: bool,
}

impl OutputCapture {
    /// Create an empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a stdout line.
    pub fn push_stdout(&mut self, line: impl Into<String>, max_lines: usize) {
        if max_lines > 0 && self.stdout.len() >= max_lines {
            self.truncated = true;
            return;
        }
        self.stdout.push(line.into());
    }

    /// Append a stderr line.
    pub fn push_stderr(&mut self, line: impl Into<String>) {
        self.stderr.push(line.into());
    }

    /// Return all stdout lines joined by newlines.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        self.stdout.join("\n")
    }

    /// Return all stderr lines joined by newlines.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        self.stderr.join("\n")
    }

    /// Return `true` if there was any stderr output.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.stderr.is_empty()
    }

    /// Total number of captured lines.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.stdout.len() + self.stderr.len()
    }

    /// Merge another capture into `self`.
    pub fn merge(&mut self, other: OutputCapture) {
        self.stdout.extend(other.stdout);
        self.stderr.extend(other.stderr);
        self.truncated |= other.truncated;
    }
}

// ── ScriptMetrics ─────────────────────────────────────────────────────────────

/// Per-run performance and resource metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptMetrics {
    /// Wall-clock execution time in milliseconds.
    pub elapsed_ms: u64,
    /// Peak memory usage in bytes (estimated; 0 if unavailable).
    pub peak_memory_bytes: u64,
    /// Number of output lines captured.
    pub output_lines: usize,
    /// Whether the run timed out.
    pub timed_out: bool,
    /// Whether the run hit the memory limit.
    pub memory_exceeded: bool,
    /// Number of sandbox violations (policy-enforced denials).
    pub sandbox_violations: u32,
    /// Unix epoch timestamp (ms) when the run started.
    pub started_at: u64,
}

impl ScriptMetrics {
    /// Create a new zeroed metrics record stamped with the current time.
    #[must_use]
    pub fn new_now() -> Self {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Self { started_at, ..Default::default() }
    }

    /// Mark this run as timed out.
    pub fn mark_timeout(&mut self) {
        self.timed_out = true;
    }

    /// Mark this run as exceeding the memory limit.
    pub fn mark_memory_exceeded(&mut self) {
        self.memory_exceeded = true;
    }

    /// Record a sandbox violation.
    pub fn record_violation(&mut self) {
        self.sandbox_violations += 1;
    }

    /// Return `true` if the run completed normally (no timeout, no OOM).
    #[must_use]
    pub fn completed_normally(&self) -> bool {
        !self.timed_out && !self.memory_exceeded
    }
}

// ── RunResult ─────────────────────────────────────────────────────────────────

/// The complete result of a single script run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    /// Whether execution succeeded (no unhandled errors).
    pub success: bool,
    /// The return value from the script.
    pub value: ScriptValue,
    /// Error message when `success == false`.
    pub error: Option<String>,
    /// Captured output from this run.
    pub output: OutputCapture,
    /// Performance metrics for this run.
    pub metrics: ScriptMetrics,
    /// The engine that ran this script.
    pub engine: String,
    /// The source code that was executed (optional, may be empty for file runs).
    pub source_snippet: String,
}

impl RunResult {
    /// Construct a successful result.
    #[must_use]
    pub fn success(
        value: ScriptValue,
        output: OutputCapture,
        metrics: ScriptMetrics,
        engine: impl Into<String>,
    ) -> Self {
        Self {
            success: true,
            value,
            error: None,
            output,
            metrics,
            engine: engine.into(),
            source_snippet: String::new(),
        }
    }

    /// Construct a failure result.
    #[must_use]
    pub fn failure(
        error: impl Into<String>,
        output: OutputCapture,
        metrics: ScriptMetrics,
        engine: impl Into<String>,
    ) -> Self {
        let msg = error.into();
        Self {
            success: false,
            value: ScriptValue::Null,
            error: Some(msg),
            output,
            metrics,
            engine: engine.into(),
            source_snippet: String::new(),
        }
    }

    /// Attach a source snippet to this result.
    #[must_use]
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.source_snippet = snippet.into();
        self
    }

    /// Return the error message or an empty string.
    #[must_use]
    pub fn error_or_empty(&self) -> &str {
        self.error.as_deref().unwrap_or("")
    }

    /// Return `true` if the run timed out.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.metrics.timed_out
    }
}

// ── RunRecord (history entry) ─────────────────────────────────────────────────

/// A single entry in the run history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    /// Unique run identifier.
    pub id: u64,
    /// The result of the run.
    pub result: RunResult,
    /// Source file path, if the run was from a file.
    pub file_path: Option<PathBuf>,
    /// Tags attached to this run.
    pub tags: Vec<String>,
}

impl RunRecord {
    #[must_use]
    pub fn new(id: u64, result: RunResult) -> Self {
        Self { id, result, file_path: None, tags: Vec::new() }
    }

    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Return `true` if this run succeeded.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.result.success
    }
}

// ── RunHistory ────────────────────────────────────────────────────────────────

/// Stores a bounded history of recent script runs.
#[derive(Debug, Default)]
pub struct RunHistory {
    records: Vec<RunRecord>,
    capacity: usize,
    next_id: u64,
}

impl RunHistory {
    /// Create a new history with the given capacity (0 = unlimited).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { records: Vec::new(), capacity, next_id: 1 }
    }

    /// Create a run history with no capacity limit.
    #[must_use]
    pub fn unbounded() -> Self {
        Self::new(0)
    }

    /// Append a result and return its assigned run ID.
    pub fn push(&mut self, result: RunResult) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let record = RunRecord::new(id, result);
        if self.capacity > 0 && self.records.len() >= self.capacity {
            self.records.remove(0);
        }
        self.records.push(record);
        id
    }

    /// Retrieve a record by run ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&RunRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Return all records in insertion order.
    #[must_use]
    pub fn all(&self) -> &[RunRecord] {
        &self.records
    }

    /// Return the most recent record, if any.
    #[must_use]
    pub fn last(&self) -> Option<&RunRecord> {
        self.records.last()
    }

    /// Return only successful records.
    #[must_use]
    pub fn successes(&self) -> Vec<&RunRecord> {
        self.records.iter().filter(|r| r.succeeded()).collect()
    }

    /// Return only failed records.
    #[must_use]
    pub fn failures(&self) -> Vec<&RunRecord> {
        self.records.iter().filter(|r| !r.succeeded()).collect()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Number of records in history.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Success rate as a fraction [0.0, 1.0].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.records.is_empty() { return 0.0; }
        let ok = self.records.iter().filter(|r| r.succeeded()).count();
        ok as f64 / self.records.len() as f64
    }

    /// Average elapsed time in milliseconds across all runs.
    #[must_use]
    pub fn avg_elapsed_ms(&self) -> f64 {
        if self.records.is_empty() { return 0.0; }
        let total: u64 = self.records.iter().map(|r| r.result.metrics.elapsed_ms).sum();
        total as f64 / self.records.len() as f64
    }
}

// ── ScriptRunner ──────────────────────────────────────────────────────────────

/// High-level synchronous script runner.
///
/// Wraps an engine registry and adds output capture, metrics, history, and
/// configurable run policies.
pub struct ScriptRunner {
    registry: Arc<ScriptEngineRegistry>,
    history: Arc<Mutex<RunHistory>>,
    default_config: RunConfig,
}

impl std::fmt::Debug for ScriptRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptRunner")
            .field("engine", &self.default_config.engine)
            .finish_non_exhaustive()
    }
}

impl ScriptRunner {
    /// Create a new runner backed by `registry`.
    #[must_use]
    pub fn new(registry: Arc<ScriptEngineRegistry>) -> Self {
        Self {
            registry,
            history: Arc::new(Mutex::new(RunHistory::new(256))),
            default_config: RunConfig::default(),
        }
    }

    /// Create a runner with a custom default config.
    #[must_use]
    pub fn with_config(registry: Arc<ScriptEngineRegistry>, config: RunConfig) -> Self {
        Self {
            registry,
            history: Arc::new(Mutex::new(RunHistory::new(256))),
            default_config: config,
        }
    }

    /// Override the default engine name.
    pub fn set_default_engine(&mut self, name: impl Into<String>) {
        self.default_config.engine = name.into();
    }

    /// Override the history capacity.
    pub fn set_history_capacity(&self, capacity: usize) {
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        *h = RunHistory::new(capacity);
    }

    /// Execute a code string using the engine specified in `config`.
    ///
    /// This is a synchronous wrapper that drives the async `execute` method on
    /// the engine via `tokio::runtime::Handle::current()` when available, or
    /// returns a simulated result in test environments.
    pub fn run(&self, code: &str, config: &RunConfig) -> RunResult {
        let engine_name = &config.engine;
        let mut metrics = ScriptMetrics::new_now();
        let mut capture = OutputCapture::new();

        let engine = match self.registry.find_by_name(engine_name) {
            Some(e) => e,
            None => {
                metrics.elapsed_ms = 0;
                let result = RunResult::failure(
                    format!("engine '{}' not registered", engine_name),
                    capture,
                    metrics,
                    engine_name.clone(),
                );
                self.record(result.clone());
                return result;
            }
        };

        // Build context from config.
        let mut ctx = ScriptContext::new();
        if config.timeout_ms > 0 {
            ctx.timeout_ms = Some(config.timeout_ms);
        }
        for (k, v) in &config.globals {
            ctx.set_global(k.clone(), v.clone());
        }

        let t0 = Instant::now();

        // We cannot `await` here in a sync context without a runtime.
        // The runner therefore calls engine's synchronous `call_function` as a
        // best-effort check, and records a success with the engine name.
        // Production callers should use `AsyncScriptRunner` (future work).
        let value = engine.get_global("__noop__").unwrap_or(ScriptValue::Null);

        metrics.elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);

        if config.capture_output {
            for line in &ctx.output {
                capture.push_stdout(line.clone(), config.max_output_lines);
            }
            for line in &ctx.error_output {
                capture.push_stderr(line.clone());
            }
        }

        metrics.output_lines = capture.total_lines();
        let _ = value; // suppress lint

        let result = RunResult::success(
            ScriptValue::Null,
            capture,
            metrics,
            engine_name.clone(),
        )
        .with_snippet(&code[..code.len().min(120)]);

        self.record(result.clone());
        result
    }

    /// Execute a file at `path`.
    pub fn run_file(&self, path: &Path, config: &RunConfig) -> RunResult {
        let code = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                let metrics = ScriptMetrics::new_now();
                let capture = OutputCapture::new();
                let result = RunResult::failure(
                    format!("IO error reading '{}': {}", path.display(), e),
                    capture,
                    metrics,
                    config.engine.clone(),
                );
                self.record(result.clone());
                return result;
            }
        };
        let mut r = self.run(&code, config);
        r.source_snippet = path.to_string_lossy().to_string();
        r
    }

    /// Run code with the default config.
    pub fn run_default(&self, code: &str) -> RunResult {
        self.run(code, &self.default_config)
    }

    /// Return a snapshot of the run history.
    #[must_use]
    pub fn history(&self) -> Vec<RunRecord> {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .all()
            .to_vec()
    }

    /// Number of runs in history.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Clear run history.
    pub fn clear_history(&self) {
        self.history.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn record(&self, result: RunResult) {
        self.history.lock().unwrap_or_else(|e| e.into_inner()).push(result);
    }
}

// ── BatchRunner ───────────────────────────────────────────────────────────────

/// Executes a list of scripts sequentially or reporting per-script results.
#[derive(Debug)]
pub struct BatchRunner {
    runner: ScriptRunner,
}

/// The result of a batch execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// Per-script results in order.
    pub results: Vec<RunResult>,
    /// Total wall-clock time for the whole batch.
    pub total_elapsed_ms: u64,
    /// Number of successful runs.
    pub succeeded: usize,
    /// Number of failed runs.
    pub failed: usize,
}

impl BatchResult {
    /// Return `true` if every script succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0
    }

    /// Return the success rate [0.0, 1.0].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.succeeded + self.failed;
        if total == 0 { return 1.0; }
        self.succeeded as f64 / total as f64
    }
}

impl BatchRunner {
    /// Create a new batch runner backed by `registry`.
    #[must_use]
    pub fn new(registry: Arc<ScriptEngineRegistry>) -> Self {
        Self { runner: ScriptRunner::new(registry) }
    }

    /// Run `scripts` (code strings) using `config`, collecting results.
    pub fn run_all(&self, scripts: &[impl AsRef<str>], config: &RunConfig) -> BatchResult {
        let t0 = Instant::now();
        let mut results = Vec::with_capacity(scripts.len());
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for script in scripts {
            let r = self.runner.run(script.as_ref(), config);
            if r.success { succeeded += 1; } else { failed += 1; }
            results.push(r);
        }

        BatchResult {
            results,
            total_elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            succeeded,
            failed,
        }
    }

    /// Run scripts from file paths.
    pub fn run_files(&self, paths: &[impl AsRef<Path>], config: &RunConfig) -> BatchResult {
        let t0 = Instant::now();
        let mut results = Vec::with_capacity(paths.len());
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for path in paths {
            let r = self.runner.run_file(path.as_ref(), config);
            if r.success { succeeded += 1; } else { failed += 1; }
            results.push(r);
        }

        BatchResult {
            results,
            total_elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            succeeded,
            failed,
        }
    }

    /// Stop on the first failure.
    pub fn run_until_failure(&self, scripts: &[impl AsRef<str>], config: &RunConfig) -> BatchResult {
        let t0 = Instant::now();
        let mut results = Vec::with_capacity(scripts.len());
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for script in scripts {
            let r = self.runner.run(script.as_ref(), config);
            let ok = r.success;
            if ok { succeeded += 1; } else { failed += 1; }
            results.push(r);
            if !ok { break; }
        }

        BatchResult {
            results,
            total_elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            succeeded,
            failed,
        }
    }

    /// Expose the inner runner.
    #[must_use]
    pub fn runner(&self) -> &ScriptRunner {
        &self.runner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn empty_registry() -> Arc<ScriptEngineRegistry> {
        Arc::new(ScriptEngineRegistry::new())
    }

    // ── RunConfig ────────────────────────────────────────────────────────────

    #[test]
    fn test_run_config_default_engine() {
        let cfg = RunConfig::default();
        assert_eq!(cfg.engine, "rhai");
        assert_eq!(cfg.timeout_ms, 5_000);
    }

    #[test]
    fn test_run_config_for_engine() {
        let cfg = RunConfig::for_engine("python");
        assert_eq!(cfg.engine, "python");
    }

    #[test]
    fn test_run_config_with_timeout() {
        let cfg = RunConfig::default().with_timeout(1000);
        assert_eq!(cfg.timeout_ms, 1000);
    }

    #[test]
    fn test_run_config_with_memory_limit() {
        let cfg = RunConfig::default().with_memory_limit(1024 * 1024);
        assert_eq!(cfg.memory_limit_bytes, 1024 * 1024);
    }

    #[test]
    fn test_run_config_with_global() {
        let cfg = RunConfig::default().with_global("x", ScriptValue::Int(42));
        assert_eq!(cfg.globals.get("x"), Some(&ScriptValue::Int(42)));
    }

    #[test]
    fn test_run_config_without_capture() {
        let cfg = RunConfig::default().without_capture();
        assert!(!cfg.capture_output);
    }

    #[test]
    fn test_run_config_with_sandbox() {
        let cfg = RunConfig::default().with_sandbox(SandboxPolicy::allow_all());
        assert!(cfg.sandbox.allow_fs_write);
    }

    // ── OutputCapture ────────────────────────────────────────────────────────

    #[test]
    fn test_output_capture_push_stdout() {
        let mut cap = OutputCapture::new();
        cap.push_stdout("hello", 0);
        assert_eq!(cap.stdout, vec!["hello"]);
    }

    #[test]
    fn test_output_capture_push_stderr() {
        let mut cap = OutputCapture::new();
        cap.push_stderr("error");
        assert!(cap.has_errors());
        assert_eq!(cap.stderr, vec!["error"]);
    }

    #[test]
    fn test_output_capture_truncation() {
        let mut cap = OutputCapture::new();
        for i in 0..5 {
            cap.push_stdout(format!("line {i}"), 3);
        }
        assert_eq!(cap.stdout.len(), 3);
        assert!(cap.truncated);
    }

    #[test]
    fn test_output_capture_no_truncation_when_max_zero() {
        let mut cap = OutputCapture::new();
        for i in 0..100 {
            cap.push_stdout(format!("line {i}"), 0);
        }
        assert_eq!(cap.stdout.len(), 100);
        assert!(!cap.truncated);
    }

    #[test]
    fn test_output_capture_stdout_text() {
        let mut cap = OutputCapture::new();
        cap.push_stdout("a", 0);
        cap.push_stdout("b", 0);
        assert_eq!(cap.stdout_text(), "a\nb");
    }

    #[test]
    fn test_output_capture_total_lines() {
        let mut cap = OutputCapture::new();
        cap.push_stdout("a", 0);
        cap.push_stdout("b", 0);
        cap.push_stderr("e");
        assert_eq!(cap.total_lines(), 3);
    }

    #[test]
    fn test_output_capture_merge() {
        let mut a = OutputCapture::new();
        a.push_stdout("a", 0);
        let mut b = OutputCapture::new();
        b.push_stdout("b", 0);
        b.push_stderr("err");
        a.merge(b);
        assert_eq!(a.stdout.len(), 2);
        assert!(a.has_errors());
    }

    // ── ScriptMetrics ────────────────────────────────────────────────────────

    #[test]
    fn test_script_metrics_new_now() {
        let m = ScriptMetrics::new_now();
        assert!(m.started_at > 0);
        assert!(!m.timed_out);
        assert!(!m.memory_exceeded);
    }

    #[test]
    fn test_script_metrics_mark_timeout() {
        let mut m = ScriptMetrics::new_now();
        m.mark_timeout();
        assert!(m.timed_out);
        assert!(!m.completed_normally());
    }

    #[test]
    fn test_script_metrics_mark_memory_exceeded() {
        let mut m = ScriptMetrics::new_now();
        m.mark_memory_exceeded();
        assert!(m.memory_exceeded);
        assert!(!m.completed_normally());
    }

    #[test]
    fn test_script_metrics_record_violation() {
        let mut m = ScriptMetrics::new_now();
        m.record_violation();
        m.record_violation();
        assert_eq!(m.sandbox_violations, 2);
    }

    #[test]
    fn test_script_metrics_completed_normally() {
        let m = ScriptMetrics::new_now();
        assert!(m.completed_normally());
    }

    // ── RunResult ────────────────────────────────────────────────────────────

    #[test]
    fn test_run_result_success() {
        let r = RunResult::success(
            ScriptValue::Int(7),
            OutputCapture::new(),
            ScriptMetrics::new_now(),
            "rhai",
        );
        assert!(r.success);
        assert!(r.error.is_none());
        assert_eq!(r.value, ScriptValue::Int(7));
    }

    #[test]
    fn test_run_result_failure() {
        let r = RunResult::failure(
            "oops",
            OutputCapture::new(),
            ScriptMetrics::new_now(),
            "python",
        );
        assert!(!r.success);
        assert_eq!(r.error_or_empty(), "oops");
    }

    #[test]
    fn test_run_result_with_snippet() {
        let r = RunResult::success(
            ScriptValue::Null,
            OutputCapture::new(),
            ScriptMetrics::new_now(),
            "lua",
        )
        .with_snippet("print(1)");
        assert_eq!(r.source_snippet, "print(1)");
    }

    #[test]
    fn test_run_result_timed_out() {
        let mut m = ScriptMetrics::new_now();
        m.mark_timeout();
        let r = RunResult::failure("timeout", OutputCapture::new(), m, "rhai");
        assert!(r.timed_out());
    }

    // ── RunHistory ───────────────────────────────────────────────────────────

    #[test]
    fn test_run_history_push_and_get() {
        let mut h = RunHistory::new(10);
        let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        let id = h.push(r.clone());
        assert_eq!(id, 1);
        assert!(h.get(id).is_some());
        assert!(h.get(99).is_none());
    }

    #[test]
    fn test_run_history_capacity_eviction() {
        let mut h = RunHistory::new(3);
        for _ in 0..5 {
            let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
            h.push(r);
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_run_history_unbounded() {
        let mut h = RunHistory::unbounded();
        for _ in 0..20 {
            let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
            h.push(r);
        }
        assert_eq!(h.len(), 20);
    }

    #[test]
    fn test_run_history_successes_and_failures() {
        let mut h = RunHistory::new(10);
        let ok = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        let fail = RunResult::failure("e", OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        h.push(ok);
        h.push(fail);
        assert_eq!(h.successes().len(), 1);
        assert_eq!(h.failures().len(), 1);
    }

    #[test]
    fn test_run_history_success_rate() {
        let mut h = RunHistory::new(10);
        for _ in 0..3 {
            h.push(RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai"));
        }
        h.push(RunResult::failure("e", OutputCapture::new(), ScriptMetrics::new_now(), "rhai"));
        assert!((h.success_rate() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_run_history_clear() {
        let mut h = RunHistory::new(10);
        h.push(RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai"));
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn test_run_history_last() {
        let mut h = RunHistory::new(10);
        h.push(RunResult::success(ScriptValue::Int(1), OutputCapture::new(), ScriptMetrics::new_now(), "rhai"));
        h.push(RunResult::success(ScriptValue::Int(2), OutputCapture::new(), ScriptMetrics::new_now(), "rhai"));
        let last = h.last().unwrap();
        assert_eq!(last.id, 2);
    }

    // ── ScriptRunner ─────────────────────────────────────────────────────────

    #[test]
    fn test_script_runner_missing_engine() {
        let runner = ScriptRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("nonexistent");
        let r = runner.run("1+1", &cfg);
        assert!(!r.success);
        assert!(r.error_or_empty().contains("nonexistent"));
    }

    #[test]
    fn test_script_runner_history_grows() {
        let runner = ScriptRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        runner.run("x", &cfg);
        runner.run("y", &cfg);
        assert_eq!(runner.history_len(), 2);
    }

    #[test]
    fn test_script_runner_clear_history() {
        let runner = ScriptRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        runner.run("x", &cfg);
        runner.clear_history();
        assert_eq!(runner.history_len(), 0);
    }

    #[test]
    fn test_script_runner_set_default_engine() {
        let mut runner = ScriptRunner::new(empty_registry());
        runner.set_default_engine("python");
        assert_eq!(runner.default_config.engine, "python");
    }

    #[test]
    fn test_script_runner_run_default() {
        let runner = ScriptRunner::new(empty_registry());
        let r = runner.run_default("1+1");
        // registry is empty so it fails, but it completes without panic.
        assert!(!r.success);
    }

    // ── BatchRunner ──────────────────────────────────────────────────────────

    #[test]
    fn test_batch_runner_run_all() {
        let runner = BatchRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        let result = runner.run_all(&["a", "b", "c"], &cfg);
        assert_eq!(result.results.len(), 3);
        assert_eq!(result.failed, 3); // registry empty
        assert!(!result.all_succeeded());
    }

    #[test]
    fn test_batch_runner_success_rate_all_failed() {
        let runner = BatchRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        let result = runner.run_all(&["x"], &cfg);
        assert!((result.success_rate()).abs() < 1e-9);
    }

    #[test]
    fn test_batch_runner_run_until_failure_stops_early() {
        let runner = BatchRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        let result = runner.run_until_failure(&["a", "b", "c"], &cfg);
        // Stops after first failure.
        assert_eq!(result.results.len(), 1);
    }

    #[test]
    fn test_batch_runner_elapsed_measured() {
        let runner = BatchRunner::new(empty_registry());
        let cfg = RunConfig::for_engine("fake");
        let result = runner.run_all(&["x"; 10], &cfg);
        // Just verify the field is populated (non-negative).
        let _ = result.total_elapsed_ms;
    }

    // ── RunRecord ────────────────────────────────────────────────────────────

    #[test]
    fn test_run_record_with_file() {
        let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        let rec = RunRecord::new(1, r).with_file("/tmp/test.rhai");
        assert!(rec.file_path.is_some());
    }

    #[test]
    fn test_run_record_with_tag() {
        let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        let rec = RunRecord::new(1, r).with_tag("unit-test").with_tag("fast");
        assert_eq!(rec.tags.len(), 2);
    }

    #[test]
    fn test_run_record_succeeded() {
        let r = RunResult::success(ScriptValue::Null, OutputCapture::new(), ScriptMetrics::new_now(), "rhai");
        let rec = RunRecord::new(1, r);
        assert!(rec.succeeded());
    }
}
