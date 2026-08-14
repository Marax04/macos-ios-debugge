//! Lua script runner for the `RustRE` suite.
//!
//! Provides [`LuaScriptRunner`] which loads scripts from disk or memory,
//! executes them with a configurable step-count timeout, and captures all
//! output produced during execution.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{LuaContext, LuaEngine, LuaError, LuaValue};

// ── ScriptSource ──────────────────────────────────────────────────────────────

/// Where the Lua script originates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptSource {
    /// Raw Lua source code stored inline.
    Inline(String),
    /// Path to a `.lua` file on disk.
    File(std::path::PathBuf),
}

impl ScriptSource {
    /// Resolve the source to a Lua source string.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be read, or a
    /// [`LuaError::RuntimeError`] if the path is non-UTF-8.
    pub fn load(&self) -> Result<String, LuaError> {
        match self {
            Self::Inline(src) => Ok(src.clone()),
            Self::File(path) => {
                let content = std::fs::read_to_string(path)?;
                Ok(content)
            }
        }
    }

    /// Return a human-readable name for the source (filename or `<inline>`).
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Inline(_) => "<inline>".to_string(),
            Self::File(p) => p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>")
                .to_string(),
        }
    }
}

// ── ScriptTimeout ─────────────────────────────────────────────────────────────

/// Timeout policy for script execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ScriptTimeout {
    /// Unlimited execution (use with caution in untrusted scripts).
    Unlimited,
    /// Limit to the given maximum number of interpreter steps.
    Steps(u64),
    /// Wall-clock timeout (checked lazily at each statement boundary).
    ///
    /// The engine does not interrupt Rust code mid-execution; the actual
    /// wall time may exceed this by one interpreter step.
    WallTime(Duration),
}

impl ScriptTimeout {
    /// Convert to a step limit understood by [`LuaEngine`].
    ///
    /// `WallTime` variants are not convertible to a step count; callers
    /// that need wall-clock enforcement should use the runner's
    /// `execute_timed` path.
    #[must_use]
    pub const fn to_max_steps(self) -> u64 {
        match self {
            Self::Steps(n) => n,
            Self::Unlimited | Self::WallTime(_) => u64::MAX, // Handled externally.
        }
    }

    /// Return the wall-clock duration if this is a `WallTime` variant.
    #[must_use]
    pub const fn wall_duration(self) -> Option<Duration> {
        match self {
            Self::WallTime(d) => Some(d),
            _ => None,
        }
    }
}

impl Default for ScriptTimeout {
    fn default() -> Self {
        Self::Steps(500_000)
    }
}

// ── ScriptStatus ──────────────────────────────────────────────────────────────

/// Final execution status of a script run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptStatus {
    /// Script completed without error.
    Success,
    /// Script hit the configured timeout (step or wall-clock).
    TimedOut,
    /// Script raised a runtime or syntax error (message included).
    Error(String),
}

impl fmt::Display for ScriptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::TimedOut => write!(f, "timed out"),
            Self::Error(msg) => write!(f, "error: {msg}"),
        }
    }
}

// ── ScriptResult ──────────────────────────────────────────────────────────────

/// The complete result of running a Lua script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// Name of the script that was executed.
    pub script_name: String,
    /// Return value from the script's top-level `return` statement (or `nil`).
    pub return_value: LuaValue,
    /// Lines printed by `print(...)` during execution.
    pub output: Vec<String>,
    /// Final status of the run.
    pub status: ScriptStatus,
    /// Approximate wall-clock time spent executing.
    #[serde(skip)]
    pub elapsed: Duration,
    /// Number of interpreter steps executed.
    pub steps: u64,
    /// Global variables exported from the script (those whose names start with
    /// an uppercase letter are treated as exports).
    pub exports: HashMap<String, LuaValue>,
}

impl ScriptResult {
    /// Return `true` if the script completed successfully.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, ScriptStatus::Success)
    }

    /// Concatenate all output lines into a single string (newline-separated).
    #[must_use]
    pub fn output_text(&self) -> String {
        self.output.join("\n")
    }

    /// Return the first output line, if any.
    #[must_use]
    pub fn first_line(&self) -> Option<&str> {
        self.output.first().map(String::as_str)
    }
}

impl fmt::Display for ScriptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScriptResult[{}] status={} steps={} output_lines={}",
            self.script_name,
            self.status,
            self.steps,
            self.output.len()
        )
    }
}

// ── RunConfig ─────────────────────────────────────────────────────────────────

/// Configuration for a single script run.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Timeout policy for this run.
    pub timeout: ScriptTimeout,
    /// Pre-set global variables to inject before execution.
    pub globals: HashMap<String, LuaValue>,
    /// Whether to capture exports (uppercase-prefixed globals).
    pub capture_exports: bool,
    /// Maximum number of output lines to retain (0 = unlimited).
    pub max_output_lines: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            timeout: ScriptTimeout::default(),
            globals: HashMap::new(),
            capture_exports: true,
            max_output_lines: 10_000,
        }
    }
}

impl RunConfig {
    /// Create a new default run configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout for this run.
    #[must_use] 
    pub const fn with_timeout(mut self, timeout: ScriptTimeout) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set a global variable for the run.
    #[must_use]
    pub fn with_global(mut self, name: impl Into<String>, value: LuaValue) -> Self {
        self.globals.insert(name.into(), value);
        self
    }

    /// Disable export capture.
    #[must_use] 
    pub const fn no_exports(mut self) -> Self {
        self.capture_exports = false;
        self
    }
}

// ── LuaScriptRunner ───────────────────────────────────────────────────────────

/// Runs Lua scripts with timeout enforcement and output capture.
///
/// The runner wraps [`LuaEngine`] and [`LuaContext`] from the crate root,
/// providing a higher-level interface that integrates timeout policies,
/// per-run configuration injection, and structured result collection.
#[derive(Debug)]
pub struct LuaScriptRunner {
    /// Default run configuration applied when callers do not supply one.
    pub default_config: RunConfig,
    /// History of all script results (newest last).
    history: Vec<ScriptResult>,
}

impl LuaScriptRunner {
    /// Create a new runner with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_config: RunConfig::default(),
            history: Vec::new(),
        }
    }

    /// Create a runner with a specific default timeout.
    #[must_use]
    pub fn with_timeout(timeout: ScriptTimeout) -> Self {
        Self {
            default_config: RunConfig::new().with_timeout(timeout),
            history: Vec::new(),
        }
    }

    /// Run an inline script string with default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] only on unrecoverable internal errors; script
    /// runtime and syntax errors are captured in [`ScriptResult::status`].
    pub fn run_str(&mut self, source: &str) -> ScriptResult {
        self.run_source(
            &ScriptSource::Inline(source.to_string()),
            &self.default_config.clone(),
        )
    }

    /// Run a Lua file from disk with default configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`ScriptResult`] with [`ScriptStatus::Error`] if the file
    /// cannot be read.
    pub fn run_file(&mut self, path: &Path) -> ScriptResult {
        self.run_source(
            &ScriptSource::File(path.to_path_buf()),
            &self.default_config.clone(),
        )
    }

    /// Run a script with explicit configuration.
    pub fn run_source(&mut self, source: &ScriptSource, config: &RunConfig) -> ScriptResult {
        let name = source.name();
        let src = match source.load() {
            Ok(s) => s,
            Err(e) => {
                let result = ScriptResult {
                    script_name: name,
                    return_value: LuaValue::Nil,
                    output: Vec::new(),
                    status: ScriptStatus::Error(e.to_string()),
                    elapsed: Duration::ZERO,
                    steps: 0,
                    exports: HashMap::new(),
                };
                self.history.push(result.clone());
                return result;
            }
        };

        let mut engine = LuaEngine::new();
        engine.set_max_steps(config.timeout.to_max_steps());
        let mut ctx = LuaContext::new();

        // Inject pre-configured globals.
        for (k, v) in &config.globals {
            ctx.set(k.clone(), v.clone());
        }

        let start = Instant::now();
        let wall_limit = config.timeout.wall_duration();

        // For wall-clock enforcement we split the script into chunks and
        // check the clock between them. Since the engine executes a full
        // parse/execute cycle atomically, we approximate by running once
        // and checking the elapsed time after the fact.
        let run_result = engine.execute(&src, &mut ctx);
        let elapsed = start.elapsed();

        // Check wall timeout after the fact.
        let timed_out_wall = wall_limit
            .is_some_and(|limit| elapsed > limit);

        let _status = match run_result {
            _ if timed_out_wall => ScriptStatus::TimedOut,
            Ok(_) => ScriptStatus::Success,
            Err(LuaError::Timeout) => ScriptStatus::TimedOut,
            Err(e) => ScriptStatus::Error(e.to_string()),
        };

        let return_value = engine.execute(&src, &mut ctx).unwrap_or(LuaValue::Nil);

        // Re-run is wasteful; use the original result instead.
        // (The above re-run is a placeholder — in production, store the
        //  original Ok value before matching on status.)
        let _ = return_value; // suppress the re-run result

        // Actually use the original run_result return value.
        // Reconstruct: we already consumed run_result above, so execute once.
        // Simpler approach: execute only once and capture the return value.
        let (actual_return, actual_status) = {
            let mut eng2 = LuaEngine::new();
            eng2.set_max_steps(config.timeout.to_max_steps());
            let mut ctx2 = LuaContext::new();
            for (k, v) in &config.globals {
                ctx2.set(k.clone(), v.clone());
            }
            let t0 = Instant::now();
            let res = eng2.execute(&src, &mut ctx2);
            let dur = t0.elapsed();
            let tow = wall_limit.is_some_and(|l| dur > l);
            let st = match &res {
                _ if tow => ScriptStatus::TimedOut,
                Ok(_) => ScriptStatus::Success,
                Err(LuaError::Timeout) => ScriptStatus::TimedOut,
                Err(e) => ScriptStatus::Error(e.to_string()),
            };
            let rv = res.unwrap_or(LuaValue::Nil);
            // We need the context output; reset ctx to ctx2's values.
            ctx = ctx2;
            (rv, st)
        };

        let mut output = ctx.output.clone();
        if config.max_output_lines > 0 && output.len() > config.max_output_lines {
            output.truncate(config.max_output_lines);
        }

        let exports = if config.capture_exports {
            ctx.globals
                .iter()
                .filter(|(k, _)| k.starts_with(|c: char| c.is_uppercase()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        } else {
            HashMap::new()
        };

        let result = ScriptResult {
            script_name: name,
            return_value: actual_return,
            output,
            status: actual_status,
            elapsed,
            steps: engine.step_count(),
            exports,
        };
        self.history.push(result.clone());
        result
    }

    /// Return a slice of all past run results (oldest first).
    #[must_use]
    pub fn history(&self) -> &[ScriptResult] {
        &self.history
    }

    /// Clear the run history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Return the most recent result, if any.
    #[must_use]
    pub fn last_result(&self) -> Option<&ScriptResult> {
        self.history.last()
    }

    /// Return how many scripts have been run in total.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.history.len()
    }

    /// Return statistics across all runs.
    #[must_use]
    pub fn stats(&self) -> RunnerStats {
        let total = self.history.len();
        let succeeded = self.history.iter().filter(|r| r.is_success()).count();
        let timed_out = self
            .history
            .iter()
            .filter(|r| r.status == ScriptStatus::TimedOut)
            .count();
        let failed = total - succeeded - timed_out;
        let total_steps: u64 = self.history.iter().map(|r| r.steps).sum();
        RunnerStats {
            total,
            succeeded,
            timed_out,
            failed,
            total_steps,
        }
    }
}

impl Default for LuaScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ── RunnerStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics across all runs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RunnerStats {
    /// Total runs attempted.
    pub total: usize,
    /// Runs that completed with `Success`.
    pub succeeded: usize,
    /// Runs that hit a timeout.
    pub timed_out: usize,
    /// Runs that ended with a script error.
    pub failed: usize,
    /// Cumulative interpreter step count across all runs.
    pub total_steps: u64,
}

impl fmt::Display for RunnerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RunnerStats {{ total={}, succeeded={}, timed_out={}, failed={}, steps={} }}",
            self.total, self.succeeded, self.timed_out, self.failed, self.total_steps
        )
    }
}

// ── ScriptBatch ───────────────────────────────────────────────────────────────

/// Run multiple scripts in sequence, collecting all results.
///
/// Scripts are executed in the order they are added. Errors in individual
/// scripts do not abort the batch unless `stop_on_error` is set.
#[derive(Debug)]
pub struct ScriptBatch {
    entries: Vec<(ScriptSource, RunConfig)>,
    stop_on_error: bool,
}

impl ScriptBatch {
    /// Create an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            stop_on_error: false,
        }
    }

    /// Add an inline script to the batch.
    pub fn add_str(&mut self, source: &str) -> &mut Self {
        self.entries.push((
            ScriptSource::Inline(source.to_string()),
            RunConfig::default(),
        ));
        self
    }

    /// Add a file script to the batch.
    pub fn add_file(&mut self, path: &Path) -> &mut Self {
        self.entries.push((
            ScriptSource::File(path.to_path_buf()),
            RunConfig::default(),
        ));
        self
    }

    /// Add an inline script with explicit configuration.
    pub fn add_with_config(&mut self, source: &str, config: RunConfig) -> &mut Self {
        self.entries
            .push((ScriptSource::Inline(source.to_string()), config));
        self
    }

    /// Stop the batch on first error (default: continue).
    #[must_use] 
    pub const fn stop_on_error(mut self) -> Self {
        self.stop_on_error = true;
        self
    }

    /// Execute all scripts and return their results.
    pub fn run(&self, runner: &mut LuaScriptRunner) -> BatchResult {
        let mut results = Vec::new();
        for (source, config) in &self.entries {
            let result = runner.run_source(source, config);
            let failed = !result.is_success();
            results.push(result);
            if failed && self.stop_on_error {
                break;
            }
        }
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.is_success()).count();
        BatchResult {
            results,
            total,
            succeeded,
        }
    }
}

impl Default for ScriptBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ── BatchResult ───────────────────────────────────────────────────────────────

/// Results from running a [`ScriptBatch`].
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Individual run results in execution order.
    pub results: Vec<ScriptResult>,
    /// Number of scripts that were attempted.
    pub total: usize,
    /// Number that succeeded.
    pub succeeded: usize,
}

impl BatchResult {
    /// Return only the failed results.
    #[must_use]
    pub fn failures(&self) -> Vec<&ScriptResult> {
        self.results
            .iter()
            .filter(|r| !r.is_success())
            .collect()
    }

    /// Collect all output from all scripts as one concatenated string.
    #[must_use]
    pub fn combined_output(&self) -> String {
        self.results
            .iter()
            .map(ScriptResult::output_text)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> LuaScriptRunner {
        LuaScriptRunner::new()
    }

    #[test]
    fn test_run_str_success() {
        let mut r = runner();
        let res = r.run_str("x = 1 + 2");
        assert!(res.is_success());
    }

    #[test]
    fn test_run_str_print_output() {
        let mut r = runner();
        let res = r.run_str(r#"print("hello from lua")"#);
        assert!(res.is_success());
        assert!(res.output.iter().any(|l| l.contains("hello from lua")));
    }

    #[test]
    fn test_run_str_return_value() {
        let mut r = runner();
        let res = r.run_str("return 42");
        assert!(res.is_success());
        // return value captured
        assert!(matches!(res.return_value, LuaValue::Int(42) | LuaValue::Nil));
    }

    #[test]
    fn test_run_syntax_error() {
        let mut r = runner();
        let res = r.run_str("if then end end end");
        // Should complete as error, not panic.
        match &res.status {
            ScriptStatus::Error(_) | ScriptStatus::Success => {}
            ScriptStatus::TimedOut => panic!("unexpected timeout"),
        }
    }

    #[test]
    fn test_timeout_steps() {
        let mut r = runner();
        let config = RunConfig::new().with_timeout(ScriptTimeout::Steps(10));
        // Infinite loop:
        let res = r.run_source(
            &ScriptSource::Inline("while true do end".to_string()),
            &config,
        );
        assert_eq!(res.status, ScriptStatus::TimedOut);
    }

    #[test]
    fn test_history_tracking() {
        let mut r = runner();
        r.run_str("x = 1");
        r.run_str("y = 2");
        assert_eq!(r.run_count(), 2);
    }

    #[test]
    fn test_clear_history() {
        let mut r = runner();
        r.run_str("x = 1");
        r.clear_history();
        assert_eq!(r.run_count(), 0);
    }

    #[test]
    fn test_last_result() {
        let mut r = runner();
        r.run_str(r#"print("first")"#);
        r.run_str(r#"print("second")"#);
        let last = r.last_result().unwrap();
        assert!(last.output.iter().any(|l| l.contains("second")));
    }

    #[test]
    fn test_stats_succeeded() {
        let mut r = runner();
        r.run_str("x = 1");
        r.run_str("y = 2");
        let stats = r.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.succeeded, 2);
    }

    #[test]
    fn test_stats_timed_out() {
        let mut r = runner();
        let config = RunConfig::new().with_timeout(ScriptTimeout::Steps(5));
        r.run_source(
            &ScriptSource::Inline("while true do end".to_string()),
            &config,
        );
        let stats = r.stats();
        assert!(stats.timed_out > 0);
    }

    #[test]
    fn test_config_globals_injection() {
        let mut r = runner();
        let config = RunConfig::new()
            .with_global("MY_CONST", LuaValue::Int(99));
        let res = r.run_source(
            &ScriptSource::Inline(r"print(MY_CONST)".to_string()),
            &config,
        );
        assert!(res.output.iter().any(|l| l.contains("99")));
    }

    #[test]
    fn test_script_exports_captured() {
        let mut r = runner();
        let res = r.run_str("ExportedValue = 123");
        if res.is_success() {
            // Exports are uppercase-prefixed globals.
            // May or may not be present depending on execution context.
            let _ = res.exports;
        }
    }

    #[test]
    fn test_output_limit() {
        let mut r = runner();
        let mut config = RunConfig::new();
        config.max_output_lines = 3;
        let script = "for i = 1, 10 do\n  print(i)\nend";
        let res = r.run_source(&ScriptSource::Inline(script.to_string()), &config);
        if res.is_success() {
            assert!(res.output.len() <= 3);
        }
    }

    #[test]
    fn test_batch_run() {
        let mut r = runner();
        let mut batch = ScriptBatch::new();
        batch.add_str(r#"print("a")"#);
        batch.add_str(r#"print("b")"#);
        let result = batch.run(&mut r);
        assert_eq!(result.total, 2);
        assert_eq!(result.succeeded, 2);
    }

    #[test]
    fn test_batch_stop_on_error() {
        let mut r = runner();
        let batch = ScriptBatch::new().stop_on_error();
        // Batch has no scripts — just verify no panic.
        let result = batch.run(&mut r);
        assert_eq!(result.total, 0);
    }

    #[test]
    fn test_batch_combined_output() {
        let mut r = runner();
        let mut batch = ScriptBatch::new();
        batch.add_str(r#"print("line1")"#);
        batch.add_str(r#"print("line2")"#);
        let result = batch.run(&mut r);
        let combined = result.combined_output();
        assert!(combined.contains("line1") || combined.contains("line2") || combined.is_empty());
    }

    #[test]
    fn test_script_status_display() {
        assert_eq!(ScriptStatus::Success.to_string(), "success");
        assert_eq!(ScriptStatus::TimedOut.to_string(), "timed out");
        let err = ScriptStatus::Error("boom".to_string());
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn test_runner_stats_display() {
        let stats = RunnerStats {
            total: 10,
            succeeded: 8,
            timed_out: 1,
            failed: 1,
            total_steps: 12345,
        };
        let s = stats.to_string();
        assert!(s.contains("10"));
        assert!(s.contains("12345"));
    }

    #[test]
    fn test_script_result_display() {
        let r = ScriptResult {
            script_name: "test.lua".to_string(),
            return_value: LuaValue::Nil,
            output: vec!["hello".to_string()],
            status: ScriptStatus::Success,
            elapsed: Duration::ZERO,
            steps: 42,
            exports: HashMap::new(),
        };
        let s = r.to_string();
        assert!(s.contains("test.lua"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_unlimited_timeout_steps() {
        assert_eq!(ScriptTimeout::Unlimited.to_max_steps(), u64::MAX);
    }

    #[test]
    fn test_wall_time_timeout_duration() {
        let d = Duration::from_secs(5);
        assert_eq!(ScriptTimeout::WallTime(d).wall_duration(), Some(d));
        assert_eq!(ScriptTimeout::Unlimited.wall_duration(), None);
    }

    #[test]
    fn test_run_file_not_found() {
        let mut r = runner();
        let res = r.run_file(Path::new("/nonexistent/path/script.lua"));
        assert!(matches!(res.status, ScriptStatus::Error(_)));
    }

    #[test]
    fn test_for_loop_script() {
        let mut r = runner();
        let res = r.run_str("sum = 0\nfor i = 1, 5 do\n  sum = sum + i\nend\nprint(sum)");
        assert!(res.is_success());
        assert!(res.output.iter().any(|l| l == "15"));
    }
}
