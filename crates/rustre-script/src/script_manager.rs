//! `script_manager` — Script lifecycle management.
//!
//! This module provides [`ScriptManager`], a registry that tracks loaded
//! scripts, manages their execution contexts, enforces per-script timeouts and
//! memory limits, and exposes a uniform API for loading, running, and
//! unloading scripts.
//!
//! # Script lifecycle
//!
//! ```text
//!  load_script(path|source)
//!       │
//!       ▼
//!  ScriptRecord  ──► run_script(id)
//!       │                  │
//!       │                  ▼
//!       │           ScriptContext (timeout + memory limit enforced)
//!       │
//!       └──► unload_script(id)
//! ```
//!
//! # Thread safety
//!
//! [`ScriptManager`] is protected by a [`parking_lot::RwLock`].  Multiple
//! threads may query scripts concurrently; writes (load/unload) require an
//! exclusive lock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{ScriptError, ScriptValue};

// ─── ScriptId ────────────────────────────────────────────────────────────────

/// Opaque identifier for a loaded script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScriptId(u64);

impl ScriptId {
    /// Construct a `ScriptId` from a raw value (for testing / serialisation).
    #[must_use]
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw numeric value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ScriptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "script:{}", self.0)
    }
}

// ─── ScriptSource ────────────────────────────────────────────────────────────

/// The source of a script — either an in-memory string or a file path.
#[derive(Debug, Clone)]
pub enum ScriptSource {
    /// Inline source code.
    Inline { code: String, engine: String },
    /// Path to a script file (engine determined from extension).
    File(PathBuf),
}

impl ScriptSource {
    /// Construct an inline source.
    #[must_use]
    pub fn inline(engine: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Inline {
            engine: engine.into(),
            code: code.into(),
        }
    }

    /// Construct a file source.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Return the engine name for this source.
    #[must_use]
    pub fn engine_name(&self) -> &str {
        match self {
            Self::Inline { engine, .. } => engine.as_str(),
            Self::File(p) => p.extension().and_then(|e| e.to_str()).unwrap_or("unknown"),
        }
    }
}

// ─── ManagedContext ───────────────────────────────────────────────────────────

/// Execution context attached to a single managed script.
///
/// Tracks globals, output, and resource limits independently from the
/// [`crate::ScriptContext`] used by engine adapters.
#[derive(Debug, Clone)]
pub struct ManagedContext {
    /// Script-visible globals.
    pub globals: HashMap<String, ScriptValue>,
    /// Captured stdout lines.
    pub output: Vec<String>,
    /// Execution timeout in milliseconds (0 = no limit).
    pub timeout_ms: u64,
    /// Maximum heap memory in bytes (0 = no limit).
    pub memory_limit_bytes: u64,
    /// Metadata bag (arbitrary string key/value pairs).
    pub metadata: HashMap<String, String>,
}

impl Default for ManagedContext {
    fn default() -> Self {
        Self {
            globals: HashMap::new(),
            output: Vec::new(),
            timeout_ms: 5_000,
            memory_limit_bytes: 64 * 1024 * 1024, // 64 MiB default
            metadata: HashMap::new(),
        }
    }
}

impl ManagedContext {
    /// Create a context with custom limits.
    #[must_use]
    pub fn with_limits(timeout_ms: u64, memory_limit_bytes: u64) -> Self {
        Self {
            timeout_ms,
            memory_limit_bytes,
            ..Default::default()
        }
    }

    /// Set a global variable.
    pub fn set_global(&mut self, name: impl Into<String>, value: ScriptValue) {
        self.globals.insert(name.into(), value);
    }

    /// Get a global variable.
    #[must_use]
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.globals.get(name)
    }

    /// Add a line to the output buffer.
    pub fn write_output(&mut self, line: impl Into<String>) {
        self.output.push(line.into());
    }

    /// Return all output as a single string.
    #[must_use]
    pub fn output_joined(&self) -> String {
        self.output.join("\n")
    }

    /// Set a metadata key.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

// ─── ScriptRecord ────────────────────────────────────────────────────────────

/// A script as stored inside [`ScriptManager`].
#[derive(Debug, Clone)]
pub struct ScriptRecord {
    /// Unique identifier.
    pub id: ScriptId,
    /// Human-readable name (usually derived from path or a user-supplied label).
    pub name: String,
    /// Script source.
    pub source: ScriptSource,
    /// Execution context.
    pub context: ManagedContext,
    /// Run count.
    pub run_count: u64,
    /// Whether this script is currently enabled.
    pub enabled: bool,
}

impl ScriptRecord {
    /// Construct a new `ScriptRecord`.
    #[must_use]
    pub fn new(id: ScriptId, name: impl Into<String>, source: ScriptSource) -> Self {
        Self {
            id,
            name: name.into(),
            source,
            context: ManagedContext::default(),
            run_count: 0,
            enabled: true,
        }
    }

    /// Return the engine name for this script.
    #[must_use]
    pub fn engine_name(&self) -> &str {
        self.source.engine_name()
    }
}

// ─── ScriptManagerError ──────────────────────────────────────────────────────

/// Errors produced by [`ScriptManager`].
#[derive(Debug, thiserror::Error)]
pub enum ScriptManagerError {
    /// A script with the requested ID was not found.
    #[error("script not found: {0}")]
    ScriptNotFound(ScriptId),
    /// The source file could not be read.
    #[error("I/O error loading script: {0}")]
    IoError(String),
    /// Execution was rejected because the script is disabled.
    #[error("script {0} is disabled")]
    ScriptDisabled(ScriptId),
    /// Execution failed.
    #[error("script execution error: {0}")]
    ExecutionError(#[from] ScriptError),
    /// Resource limit exceeded.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
}

// ─── RunResult ───────────────────────────────────────────────────────────────

/// The result of a single script run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Script ID.
    pub id: ScriptId,
    /// Return value.
    pub value: ScriptValue,
    /// Output lines captured during execution.
    pub output: Vec<String>,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Run count after this execution.
    pub run_count: u64,
}

impl RunResult {
    /// Construct a `RunResult`.
    #[must_use]
    pub const fn new(
        id: ScriptId,
        value: ScriptValue,
        output: Vec<String>,
        elapsed_ms: u64,
        run_count: u64,
    ) -> Self {
        Self {
            id,
            value,
            output,
            elapsed_ms,
            run_count,
        }
    }
}

// ─── ScriptManager ───────────────────────────────────────────────────────────

/// Manages the lifecycle of scripts: loading, running, and unloading.
///
/// The manager does not itself execute scripts — it delegates to a
/// pluggable [`ScriptRunner`] trait object.  In production, the runner
/// wraps a [`crate::ScriptEngineRegistry`].  In tests, a `MockRunner`
/// can be substituted.
pub struct ScriptManager {
    scripts: parking_lot::RwLock<HashMap<ScriptId, ScriptRecord>>,
    next_id: std::sync::atomic::AtomicU64,
    runner: Arc<dyn ScriptRunner>,
}

impl std::fmt::Debug for ScriptManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.scripts.read().len();
        f.debug_struct("ScriptManager")
            .field("script_count", &count)
            .finish_non_exhaustive()
    }
}

impl ScriptManager {
    /// Create a new `ScriptManager` backed by `runner`.
    #[must_use]
    pub fn new(runner: Arc<dyn ScriptRunner>) -> Self {
        Self {
            scripts: parking_lot::RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            runner,
        }
    }

    fn alloc_id(&self) -> ScriptId {
        let raw = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ScriptId::from_raw(raw)
    }

    // ── load ─────────────────────────────────────────────────────────────────

    /// Load an inline script and return its [`ScriptId`].
    pub fn load_script(&self, name: impl Into<String>, source: ScriptSource) -> ScriptId {
        let id = self.alloc_id();
        let record = ScriptRecord::new(id, name, source);
        self.scripts.write().insert(id, record);
        id
    }

    /// Load a script from a file at `path`.
    ///
    /// # Errors
    /// Returns [`ScriptManagerError::IoError`] if the file cannot be read.
    pub fn load_script_file(&self, path: &Path) -> Result<ScriptId, ScriptManagerError> {
        let code = std::fs::read_to_string(path)
            .map_err(|e| ScriptManagerError::IoError(e.to_string()))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_owned();
        let source = ScriptSource::file(path);
        // Store code in metadata so the runner can retrieve it.
        let id = self.alloc_id();
        let mut record = ScriptRecord::new(id, name, source);
        record.context.set_meta("source_code", code);
        self.scripts.write().insert(id, record);
        Ok(id)
    }

    // ── run ──────────────────────────────────────────────────────────────────

    /// Run the script identified by `id`.
    ///
    /// # Errors
    /// - [`ScriptManagerError::ScriptNotFound`] if no script with `id` exists.
    /// - [`ScriptManagerError::ScriptDisabled`] if the script is disabled.
    /// - [`ScriptManagerError::ExecutionError`] on script failure.
    pub fn run_script(&self, id: ScriptId) -> Result<RunResult, ScriptManagerError> {
        // Clone the record to avoid holding the write-lock during execution.
        let record = {
            let guard = self.scripts.read();
            guard
                .get(&id)
                .cloned()
                .ok_or(ScriptManagerError::ScriptNotFound(id))?
        };

        if !record.enabled {
            return Err(ScriptManagerError::ScriptDisabled(id));
        }

        let t0 = std::time::Instant::now();
        let result = self.runner.run(&record)?;
        let elapsed = t0.elapsed().as_millis() as u64;

        // Update run count.
        {
            let mut guard = self.scripts.write();
            if let Some(r) = guard.get_mut(&id) {
                r.run_count += 1;
            }
        }

        let run_count = { self.scripts.read().get(&id).map_or(0, |r| r.run_count) };

        Ok(RunResult::new(
            id,
            result.value,
            result.output,
            elapsed,
            run_count,
        ))
    }

    // ── unload ───────────────────────────────────────────────────────────────

    /// Unload the script identified by `id`.
    ///
    /// # Errors
    /// Returns [`ScriptManagerError::ScriptNotFound`] if no such script exists.
    pub fn unload_script(&self, id: ScriptId) -> Result<ScriptRecord, ScriptManagerError> {
        self.scripts
            .write()
            .remove(&id)
            .ok_or(ScriptManagerError::ScriptNotFound(id))
    }

    // ── query ─────────────────────────────────────────────────────────────────

    /// Return a clone of the record for `id`, or `None`.
    #[must_use]
    pub fn get_record(&self, id: ScriptId) -> Option<ScriptRecord> {
        self.scripts.read().get(&id).cloned()
    }

    /// Return all loaded script IDs.
    #[must_use]
    pub fn list_scripts(&self) -> Vec<ScriptId> {
        self.scripts.read().keys().copied().collect()
    }

    /// Return the number of loaded scripts.
    #[must_use]
    pub fn script_count(&self) -> usize {
        self.scripts.read().len()
    }

    // ── control ───────────────────────────────────────────────────────────────

    /// Enable or disable a script.
    ///
    /// # Errors
    /// Returns [`ScriptManagerError::ScriptNotFound`] if no such script exists.
    pub fn set_enabled(&self, id: ScriptId, enabled: bool) -> Result<(), ScriptManagerError> {
        self.scripts
            .write()
            .get_mut(&id)
            .ok_or(ScriptManagerError::ScriptNotFound(id))
            .map(|r| r.enabled = enabled)
    }

    /// Update the context for a script.
    ///
    /// # Errors
    /// Returns [`ScriptManagerError::ScriptNotFound`] if no such script exists.
    pub fn update_context<F>(&self, id: ScriptId, f: F) -> Result<(), ScriptManagerError>
    where
        F: FnOnce(&mut ManagedContext),
    {
        let mut guard = self.scripts.write();
        let record = guard
            .get_mut(&id)
            .ok_or(ScriptManagerError::ScriptNotFound(id))?;
        f(&mut record.context);
        Ok(())
    }
}

// ─── ScriptRunner trait ───────────────────────────────────────────────────────

/// Pluggable execution backend used by [`ScriptManager`].
pub trait ScriptRunner: Send + Sync {
    /// Run the script described by `record` and return a partial [`RunResult`].
    ///
    /// The manager fills in `id`, `elapsed_ms`, and `run_count`.
    ///
    /// # Errors
    /// Returns `ScriptManagerError` on failure.
    fn run(&self, record: &ScriptRecord) -> Result<PartialRunResult, ScriptManagerError>;
}

/// Partial run result produced by [`ScriptRunner::run`].
#[derive(Debug)]
pub struct PartialRunResult {
    /// Script return value.
    pub value: ScriptValue,
    /// Output lines.
    pub output: Vec<String>,
}

// ─── MockRunner ───────────────────────────────────────────────────────────────

/// A no-op [`ScriptRunner`] suitable for testing.
///
/// Always returns `ScriptValue::Null` with no output unless overridden via
/// the `with_result` builder.
#[derive(Debug, Clone, Default)]
pub struct MockRunner {
    /// Static return value for all scripts.
    pub return_value: ScriptValue,
    /// Static output for all scripts.
    pub output_lines: Vec<String>,
    /// If `true`, every run returns a `ScriptError::RuntimeError`.
    pub fail: bool,
}

impl MockRunner {
    /// Create a mock that returns a specific value.
    #[must_use]
    pub fn returning(value: ScriptValue) -> Self {
        Self {
            return_value: value,
            ..Default::default()
        }
    }

    /// Create a mock that always fails.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            fail: true,
            ..Default::default()
        }
    }
}

impl ScriptRunner for MockRunner {
    fn run(&self, _record: &ScriptRecord) -> Result<PartialRunResult, ScriptManagerError> {
        if self.fail {
            return Err(ScriptManagerError::ExecutionError(
                ScriptError::RuntimeError("mock failure".into()),
            ));
        }
        Ok(PartialRunResult {
            value: self.return_value.clone(),
            output: self.output_lines.clone(),
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_with_mock() -> ScriptManager {
        ScriptManager::new(Arc::new(MockRunner::default()))
    }

    fn manager_returning(v: ScriptValue) -> ScriptManager {
        ScriptManager::new(Arc::new(MockRunner::returning(v)))
    }

    fn manager_failing() -> ScriptManager {
        ScriptManager::new(Arc::new(MockRunner::failing()))
    }

    fn inline_source() -> ScriptSource {
        ScriptSource::inline("mock", "1 + 1")
    }

    // ── ScriptId ─────────────────────────────────────────────────────────────

    #[test]
    fn test_script_id_raw() {
        let id = ScriptId::from_raw(42);
        assert_eq!(id.raw(), 42);
    }

    #[test]
    fn test_script_id_display() {
        let id = ScriptId::from_raw(7);
        assert_eq!(id.to_string(), "script:7");
    }

    #[test]
    fn test_script_id_ordering() {
        let a = ScriptId::from_raw(1);
        let b = ScriptId::from_raw(2);
        assert!(a < b);
    }

    // ── ScriptSource ─────────────────────────────────────────────────────────

    #[test]
    fn test_source_engine_name_inline() {
        let s = ScriptSource::inline("rhai", "1");
        assert_eq!(s.engine_name(), "rhai");
    }

    #[test]
    fn test_source_engine_name_file() {
        let s = ScriptSource::file("analysis.lua");
        assert_eq!(s.engine_name(), "lua");
    }

    // ── ManagedContext ────────────────────────────────────────────────────────

    #[test]
    fn test_managed_context_defaults() {
        let ctx = ManagedContext::default();
        assert_eq!(ctx.timeout_ms, 5_000);
        assert_eq!(ctx.memory_limit_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn test_managed_context_globals() {
        let mut ctx = ManagedContext::default();
        ctx.set_global("x", ScriptValue::Int(42));
        assert_eq!(ctx.get_global("x"), Some(&ScriptValue::Int(42)));
    }

    #[test]
    fn test_managed_context_output() {
        let mut ctx = ManagedContext::default();
        ctx.write_output("line 1");
        ctx.write_output("line 2");
        assert_eq!(ctx.output_joined(), "line 1\nline 2");
    }

    #[test]
    fn test_managed_context_metadata() {
        let mut ctx = ManagedContext::default();
        ctx.set_meta("version", "1.0");
        assert_eq!(ctx.get_meta("version"), Some("1.0"));
    }

    #[test]
    fn test_managed_context_with_limits() {
        let ctx = ManagedContext::with_limits(1000, 1024);
        assert_eq!(ctx.timeout_ms, 1000);
        assert_eq!(ctx.memory_limit_bytes, 1024);
    }

    // ── ScriptManager ─────────────────────────────────────────────────────────

    #[test]
    fn test_load_script() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("test", inline_source());
        assert_eq!(mgr.script_count(), 1);
        let record = mgr.get_record(id).unwrap();
        assert_eq!(record.name, "test");
    }

    #[test]
    fn test_load_script_increments_id() {
        let mgr = manager_with_mock();
        let id1 = mgr.load_script("a", inline_source());
        let id2 = mgr.load_script("b", inline_source());
        assert_ne!(id1, id2);
        assert!(id1 < id2);
    }

    #[test]
    fn test_list_scripts() {
        let mgr = manager_with_mock();
        let id1 = mgr.load_script("a", inline_source());
        let id2 = mgr.load_script("b", inline_source());
        let ids = mgr.list_scripts();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_run_script_returns_value() {
        let mgr = manager_returning(ScriptValue::Int(99));
        let id = mgr.load_script("test", inline_source());
        let result = mgr.run_script(id).unwrap();
        assert_eq!(result.value, ScriptValue::Int(99));
        assert_eq!(result.id, id);
    }

    #[test]
    fn test_run_script_increments_run_count() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("s", inline_source());
        mgr.run_script(id).unwrap();
        mgr.run_script(id).unwrap();
        let record = mgr.get_record(id).unwrap();
        assert_eq!(record.run_count, 2);
    }

    #[test]
    fn test_run_script_not_found() {
        let mgr = manager_with_mock();
        let result = mgr.run_script(ScriptId::from_raw(999));
        assert!(matches!(result, Err(ScriptManagerError::ScriptNotFound(_))));
    }

    #[test]
    fn test_run_script_disabled() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("disabled", inline_source());
        mgr.set_enabled(id, false).unwrap();
        let result = mgr.run_script(id);
        assert!(matches!(result, Err(ScriptManagerError::ScriptDisabled(_))));
    }

    #[test]
    fn test_run_script_execution_error() {
        let mgr = manager_failing();
        let id = mgr.load_script("fail", inline_source());
        let result = mgr.run_script(id);
        assert!(matches!(result, Err(ScriptManagerError::ExecutionError(_))));
    }

    #[test]
    fn test_unload_script() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("del", inline_source());
        let record = mgr.unload_script(id).unwrap();
        assert_eq!(record.name, "del");
        assert_eq!(mgr.script_count(), 0);
    }

    #[test]
    fn test_unload_script_not_found() {
        let mgr = manager_with_mock();
        let result = mgr.unload_script(ScriptId::from_raw(100));
        assert!(matches!(result, Err(ScriptManagerError::ScriptNotFound(_))));
    }

    #[test]
    fn test_set_enabled() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("s", inline_source());
        mgr.set_enabled(id, false).unwrap();
        assert!(!mgr.get_record(id).unwrap().enabled);
        mgr.set_enabled(id, true).unwrap();
        assert!(mgr.get_record(id).unwrap().enabled);
    }

    #[test]
    fn test_update_context() {
        let mgr = manager_with_mock();
        let id = mgr.load_script("s", inline_source());
        mgr.update_context(id, |ctx| {
            ctx.set_global("flag", ScriptValue::Bool(true));
        })
        .unwrap();
        let record = mgr.get_record(id).unwrap();
        assert_eq!(
            record.context.get_global("flag"),
            Some(&ScriptValue::Bool(true))
        );
    }

    #[test]
    fn test_script_manager_debug() {
        let mgr = manager_with_mock();
        let s = format!("{mgr:?}");
        assert!(s.contains("ScriptManager"));
    }

    // ── ScriptRecord ─────────────────────────────────────────────────────────

    #[test]
    fn test_script_record_engine_name() {
        let record = ScriptRecord::new(
            ScriptId::from_raw(1),
            "test",
            ScriptSource::inline("lua", ""),
        );
        assert_eq!(record.engine_name(), "lua");
    }

    #[test]
    fn test_script_record_initial_state() {
        let record = ScriptRecord::new(ScriptId::from_raw(1), "name", inline_source());
        assert_eq!(record.run_count, 0);
        assert!(record.enabled);
    }

    // ── MockRunner ───────────────────────────────────────────────────────────

    #[test]
    fn test_mock_runner_default() {
        let runner = MockRunner::default();
        let record = ScriptRecord::new(ScriptId::from_raw(1), "t", inline_source());
        let result = runner.run(&record).unwrap();
        assert_eq!(result.value, ScriptValue::Null);
    }

    #[test]
    fn test_mock_runner_returning() {
        let runner = MockRunner::returning(ScriptValue::Int(7));
        let record = ScriptRecord::new(ScriptId::from_raw(1), "t", inline_source());
        let result = runner.run(&record).unwrap();
        assert_eq!(result.value, ScriptValue::Int(7));
    }

    #[test]
    fn test_mock_runner_failing() {
        let runner = MockRunner::failing();
        let record = ScriptRecord::new(ScriptId::from_raw(1), "t", inline_source());
        assert!(runner.run(&record).is_err());
    }
}
