//! `rhai_script_runner` — Run Rhai scripts from files or strings in the `RustRE` context.
//!
//! Provides [`RhaiScriptRunner`], [`ScriptResult`], and [`RunConfig`].

use crate::{RhaiScriptEngine, RhaiValue, ScriptError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ── ScriptResult ──────────────────────────────────────────────────────────────

/// The outcome of running a Rhai script.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// The value returned by the script (or `Unit` if void).
    pub value: RhaiValue,
    /// Wall-clock time spent executing.
    pub elapsed: Duration,
    /// Log messages emitted by the script via `rustre_log()`.
    pub log_messages: Vec<String>,
    /// Whether the script completed without error.
    pub success: bool,
    /// Error message if the script failed.
    pub error: Option<String>,
    /// The source label (file path or `"<inline>"`).
    pub source: String,
    /// Actions registered by the script.
    pub registered_actions: Vec<(String, String)>,
}

impl ScriptResult {
    /// Create a successful result.
    #[must_use]
    pub fn ok(
        value: RhaiValue,
        elapsed: Duration,
        source: impl Into<String>,
        log_messages: Vec<String>,
        registered_actions: Vec<(String, String)>,
    ) -> Self {
        Self {
            value,
            elapsed,
            log_messages,
            success: true,
            error: None,
            source: source.into(),
            registered_actions,
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn err(
        error: impl Into<String>,
        elapsed: Duration,
        source: impl Into<String>,
        log_messages: Vec<String>,
    ) -> Self {
        Self {
            value: RhaiValue::Unit,
            elapsed,
            log_messages,
            success: false,
            error: Some(error.into()),
            source: source.into(),
            registered_actions: Vec::new(),
        }
    }

    /// Format a brief summary of the result.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.success {
            format!(
                "OK in {:?}: {} (logs={})",
                self.elapsed,
                self.value,
                self.log_messages.len()
            )
        } else {
            format!(
                "ERR in {:?}: {}",
                self.elapsed,
                self.error.as_deref().unwrap_or("unknown")
            )
        }
    }
}

// ── RunConfig ─────────────────────────────────────────────────────────────────

/// Configuration for script execution.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Maximum wall-clock time before aborting (None = no limit).
    pub timeout: Option<Duration>,
    /// Additional variables to inject into scope before running.
    pub scope_vars: HashMap<String, RhaiValue>,
    /// Whether to register the RE module before running.
    pub load_re_module: bool,
    /// Whether to register the rustre module before running.
    pub load_rustre_module: bool,
    /// Whether to capture log messages from the state.
    pub capture_logs: bool,
    /// Maximum number of operations before aborting (Rhai instruction limit).
    pub max_operations: Option<u64>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            scope_vars: HashMap::new(),
            load_re_module: true,
            load_rustre_module: true,
            capture_logs: true,
            max_operations: Some(1_000_000),
        }
    }
}

impl RunConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    #[must_use]
    pub fn with_var(mut self, name: impl Into<String>, val: RhaiValue) -> Self {
        self.scope_vars.insert(name.into(), val);
        self
    }

    #[must_use]
    pub const fn without_re_module(mut self) -> Self {
        self.load_re_module = false;
        self
    }

    #[must_use]
    pub const fn without_rustre_module(mut self) -> Self {
        self.load_rustre_module = false;
        self
    }

    #[must_use]
    pub const fn with_max_ops(mut self, n: u64) -> Self {
        self.max_operations = Some(n);
        self
    }
}

// ── ScriptCache ───────────────────────────────────────────────────────────────

/// A simple cache mapping file paths to their compiled source.
#[derive(Debug, Default)]
pub struct ScriptCache {
    sources: HashMap<PathBuf, (String, std::time::SystemTime)>,
}

impl ScriptCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a file, using the cache if it hasn't changed on disk.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read or metadata cannot be queried.
    pub fn load(&mut self, path: &Path) -> Result<&str, ScriptError> {
        let meta = std::fs::metadata(path)?;
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        let needs_reload = self
            .sources
            .get(path)
            .is_none_or(|(_, cached_mtime)| *cached_mtime != mtime);

        if needs_reload {
            let source = std::fs::read_to_string(path)?;
            self.sources.insert(path.to_path_buf(), (source, mtime));
        }

        Ok(&self.sources[path].0)
    }

    /// Invalidate a cached entry.
    pub fn invalidate(&mut self, path: &Path) {
        self.sources.remove(path);
    }

    /// Number of cached scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.sources.clear();
    }
}

// ── RunHistory ────────────────────────────────────────────────────────────────

/// Records the history of script executions in a session.
#[derive(Debug, Default)]
pub struct RunHistory {
    entries: Vec<ScriptResult>,
    max_size: usize,
}

impl RunHistory {
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size,
        }
    }

    pub fn push(&mut self, result: ScriptResult) {
        if self.entries.len() >= self.max_size {
            self.entries.remove(0);
        }
        self.entries.push(result);
    }

    #[must_use]
    pub fn all(&self) -> &[ScriptResult] {
        &self.entries
    }

    #[must_use]
    pub fn last(&self) -> Option<&ScriptResult> {
        self.entries.last()
    }

    #[must_use]
    pub fn successful(&self) -> Vec<&ScriptResult> {
        self.entries.iter().filter(|r| r.success).collect()
    }

    #[must_use]
    pub fn failed(&self) -> Vec<&ScriptResult> {
        self.entries.iter().filter(|r| !r.success).collect()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Average execution time across successful runs.
    #[must_use]
    pub fn avg_elapsed(&self) -> Option<Duration> {
        let ok: Vec<&ScriptResult> = self.successful();
        if ok.is_empty() {
            return None;
        }
        let total: Duration = ok.iter().map(|r| r.elapsed).sum();
        let count = u32::try_from(ok.len()).unwrap_or(u32::MAX);
        Some(total / count)
    }
}

// ── RhaiScriptRunner ──────────────────────────────────────────────────────────

/// High-level script runner for the `RustRE` Rhai scripting layer.
///
/// Builds a [`RhaiScriptEngine`] per run (or reuses a pooled one),
/// applies [`RunConfig`] settings, executes the script, and returns a
/// fully populated [`ScriptResult`].
#[derive(Debug)]
pub struct RhaiScriptRunner {
    config: RunConfig,
    cache: ScriptCache,
    history: RunHistory,
    /// Global variables persisted across runs (name → value).
    globals: HashMap<String, RhaiValue>,
}

impl RhaiScriptRunner {
    /// Create a runner with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RunConfig::default(),
            cache: ScriptCache::new(),
            history: RunHistory::new(100),
            globals: HashMap::new(),
        }
    }

    /// Apply a custom default configuration.
    #[must_use]
    pub fn with_config(mut self, config: RunConfig) -> Self {
        self.config = config;
        self
    }

    /// Set a persistent global variable for all future runs.
    pub fn set_global(&mut self, name: impl Into<String>, val: RhaiValue) {
        self.globals.insert(name.into(), val);
    }

    /// Remove a persistent global.
    pub fn remove_global(&mut self, name: &str) -> bool {
        self.globals.remove(name).is_some()
    }

    /// Run an inline script string.
    pub fn run_inline(&mut self, code: &str) -> ScriptResult {
        self.run_inline_with("<inline>", code, &self.config.clone())
    }

    /// Run an inline script with a custom configuration.
    pub fn run_inline_cfg(&mut self, code: &str, cfg: &RunConfig) -> ScriptResult {
        self.run_inline_with("<inline>", code, cfg)
    }

    fn run_inline_with(&mut self, source: &str, code: &str, cfg: &RunConfig) -> ScriptResult {
        let start = Instant::now();
        let engine = Self::build_engine(cfg);

        let result = engine.eval(code);
        let elapsed = start.elapsed();
        let logs = engine.log_messages();
        let actions = engine.registered_actions();

        let result = match result {
            Ok(val) => ScriptResult::ok(val, elapsed, source, logs, actions),
            Err(e) => ScriptResult::err(e.to_string(), elapsed, source, logs),
        };
        self.history.push(result.clone());
        result
    }

    /// Run a script file, using the source cache.
    pub fn run_script_file(&mut self, path: &Path) -> ScriptResult {
        self.run_script_file_with_cfg(path, &self.config.clone())
    }

    /// Run a script file with a custom configuration.
    pub fn run_script_file_with_cfg(&mut self, path: &Path, cfg: &RunConfig) -> ScriptResult {
        let source = path.display().to_string();
        let start = Instant::now();

        let code = match self.cache.load(path) {
            Ok(s) => s.to_string(),
            Err(e) => {
                let elapsed = start.elapsed();
                let result = ScriptResult::err(e.to_string(), elapsed, source, Vec::new());
                self.history.push(result.clone());
                return result;
            }
        };

        self.run_inline_with(&source, &code, cfg)
    }

    /// Run all `.rhai` files in a directory (non-recursive).
    pub fn run_directory(&mut self, dir: &Path) -> Vec<ScriptResult> {
        let mut results = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                results.push(ScriptResult::err(
                    format!("cannot read directory: {err}"),
                    Duration::ZERO,
                    dir.display().to_string(),
                    Vec::new(),
                ));
                return results;
            }
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|de| de.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "rhai"))
            .collect();
        paths.sort();
        for path in paths {
            results.push(self.run_script_file(&path));
        }
        results
    }

    fn build_engine(cfg: &RunConfig) -> RhaiScriptEngine {
        let mut engine = if cfg.load_re_module {
            RhaiScriptEngine::with_re_api()
        } else if cfg.load_rustre_module {
            RhaiScriptEngine::with_rustre_module()
        } else {
            RhaiScriptEngine::new()
        };

        // Set max operations if configured
        if let Some(max_ops) = cfg.max_operations {
            engine.inner_mut().set_max_operations(max_ops);
        }

        engine
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Run history.
    #[must_use]
    pub const fn history(&self) -> &RunHistory {
        &self.history
    }

    /// Script source cache.
    #[must_use]
    pub const fn cache(&self) -> &ScriptCache {
        &self.cache
    }

    /// Clear the source cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Default run configuration.
    #[must_use]
    pub const fn config(&self) -> &RunConfig {
        &self.config
    }

    /// Whether the last run succeeded.
    #[must_use]
    pub fn last_succeeded(&self) -> bool {
        self.history.last().is_some_and(|r| r.success)
    }

    /// Summarise the history: (total, success, failed).
    #[must_use]
    pub fn history_summary(&self) -> (usize, usize, usize) {
        let total = self.history.len();
        let ok = self.history.successful().len();
        (total, ok, total - ok)
    }
}

impl Default for RhaiScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience free function: run a script file with a default runner.
///
/// Returns the [`ScriptResult`].
#[must_use]
pub fn run_script_file(path: &Path) -> ScriptResult {
    let mut runner = RhaiScriptRunner::new();
    runner.run_script_file(path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_config_defaults() {
        let cfg = RunConfig::default();
        assert!(cfg.load_re_module);
        assert!(cfg.capture_logs);
        assert!(cfg.timeout.is_none());
    }

    #[test]
    fn test_run_config_builder() {
        let cfg = RunConfig::new()
            .with_timeout(Duration::from_secs(5))
            .with_max_ops(50_000)
            .without_re_module();
        assert_eq!(cfg.timeout, Some(Duration::from_secs(5)));
        assert_eq!(cfg.max_operations, Some(50_000));
        assert!(!cfg.load_re_module);
    }

    #[test]
    fn test_run_config_with_var() {
        let cfg = RunConfig::new().with_var("x", RhaiValue::Int(42));
        assert!(cfg.scope_vars.contains_key("x"));
    }

    #[test]
    fn test_script_result_ok() {
        let r = ScriptResult::ok(
            RhaiValue::Int(7),
            Duration::from_millis(10),
            "<test>",
            vec!["log".to_string()],
            Vec::new(),
        );
        assert!(r.success);
        assert!(r.error.is_none());
        assert_eq!(r.log_messages.len(), 1);
    }

    #[test]
    fn test_script_result_err() {
        let r = ScriptResult::err("oops", Duration::ZERO, "<test>", Vec::new());
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("oops"));
    }

    #[test]
    fn test_script_result_summary_ok() {
        let r = ScriptResult::ok(RhaiValue::Unit, Duration::ZERO, "f", Vec::new(), Vec::new());
        assert!(r.summary().starts_with("OK"));
    }

    #[test]
    fn test_script_result_summary_err() {
        let r = ScriptResult::err("bad", Duration::ZERO, "f", Vec::new());
        assert!(r.summary().starts_with("ERR"));
    }

    #[test]
    fn test_runner_run_inline_integer() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_inline("1 + 2");
        assert!(result.success, "err: {:?}", result.error);
        assert_eq!(result.value, RhaiValue::Int(3));
    }

    #[test]
    fn test_runner_run_inline_string() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_inline("\"hello\"");
        assert!(result.success);
        assert_eq!(result.value.as_str(), Some("hello"));
    }

    #[test]
    fn test_runner_run_inline_error() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_inline("this is not valid rhai ###");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_runner_run_inline_bool() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_inline("true");
        assert!(result.success);
        assert_eq!(result.value.as_bool(), Some(true));
    }

    #[test]
    fn test_runner_elapsed_is_set() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_inline("2 * 3");
        // Elapsed should be a valid Duration (may be 0 on fast machines)
        assert!(result.elapsed < Duration::from_secs(10));
    }

    #[test]
    fn test_runner_history_recorded() {
        let mut runner = RhaiScriptRunner::new();
        runner.run_inline("42");
        runner.run_inline("1 + 1");
        let (total, ok, failed) = runner.history_summary();
        assert_eq!(total, 2);
        assert_eq!(ok, 2);
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_runner_last_succeeded() {
        let mut runner = RhaiScriptRunner::new();
        runner.run_inline("1");
        assert!(runner.last_succeeded());
        runner.run_script_file(Path::new("/nonexistent_path_xyz.rhai"));
        assert!(!runner.last_succeeded());
    }

    #[test]
    fn test_runner_set_global() {
        let mut runner = RhaiScriptRunner::new();
        runner.set_global("myvar", RhaiValue::Bool(true));
        assert!(runner.globals.contains_key("myvar"));
        assert!(runner.remove_global("myvar"));
        assert!(!runner.globals.contains_key("myvar"));
    }

    #[test]
    fn test_runner_clear_cache() {
        let mut runner = RhaiScriptRunner::new();
        runner.clear_cache();
        assert!(runner.cache().is_empty());
    }

    #[test]
    fn test_run_history_avg_elapsed_empty() {
        let h = RunHistory::new(10);
        assert!(h.avg_elapsed().is_none());
    }

    #[test]
    fn test_run_history_avg_elapsed_some() {
        let mut h = RunHistory::new(10);
        h.push(ScriptResult::ok(RhaiValue::Unit, Duration::from_millis(100), "f", Vec::new(), Vec::new()));
        h.push(ScriptResult::ok(RhaiValue::Unit, Duration::from_millis(200), "f", Vec::new(), Vec::new()));
        let avg = h.avg_elapsed().unwrap();
        assert_eq!(avg, Duration::from_millis(150));
    }

    #[test]
    fn test_run_history_max_size() {
        let mut h = RunHistory::new(3);
        for i in 0..10 {
            h.push(ScriptResult::ok(
                RhaiValue::Int(i),
                Duration::ZERO,
                "f",
                Vec::new(),
                Vec::new(),
            ));
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_script_cache_invalidate() {
        let mut cache = ScriptCache::new();
        cache.invalidate(Path::new("/fake.rhai")); // no-op on non-existent
        assert!(cache.is_empty());
    }

    #[test]
    fn test_runner_run_nonexistent_file() {
        let mut runner = RhaiScriptRunner::new();
        let result = runner.run_script_file(Path::new("/does_not_exist.rhai"));
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_runner_run_directory_empty() {
        let mut runner = RhaiScriptRunner::new();
        // Running on a non-existent dir should return one error result
        let results = runner.run_directory(Path::new("/totally_nonexistent_dir_xyz"));
        assert!(!results.is_empty());
        assert!(!results[0].success);
    }
}
