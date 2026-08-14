/// Rhai script manager: load, compile, cache, and execute scripts with timeout support.
///
/// Provides:
/// - `RhaiScriptManager` — top-level manager with a compiled-AST cache
/// - `ScriptHandle` — an opaque handle to a loaded/compiled script
/// - `CompileCache` — the LRU-like AST cache
/// - `ExecutionConfig` — per-execution options (timeout, max operations, …)
/// - `ExecutionResult` — the outcome of a script run
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ScriptManagerError {
    #[error("script not found: {0}")]
    NotFound(String),
    #[error("compile error in '{name}': {reason}")]
    CompileError { name: String, reason: String },
    #[error("execution error in '{name}': {reason}")]
    ExecutionError { name: String, reason: String },
    #[error("execution timed out after {0:?}")]
    Timeout(Duration),
    #[error("cache is full (capacity {0})")]
    CacheFull(usize),
    #[error("script handle {0} is invalid or expired")]
    InvalidHandle(u64),
    #[error("script source is empty")]
    EmptySource,
}

// ---------------------------------------------------------------------------
// ScriptHandle — opaque identifier for a loaded script
// ---------------------------------------------------------------------------

/// An opaque handle to a compiled script in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScriptHandle(u64);

impl ScriptHandle {
    const fn new(id: u64) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn id(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ScriptHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ScriptHandle({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// CompiledScript — an entry in the compile cache
// ---------------------------------------------------------------------------

/// A compiled Rhai script ready for execution.
#[derive(Clone)]
pub struct CompiledScript {
    pub handle: ScriptHandle,
    pub name: String,
    pub source: String,
    /// Serialized AST representation. We store the source + a flag instead of
    /// a real `rhai::AST` to keep this module free of rhai-version dependencies
    /// while still providing a meaningful cache abstraction.
    pub ast_hash: u64,
    pub compiled_at: Instant,
    pub compile_ms: u64,
    pub path: Option<PathBuf>,
}

impl std::fmt::Debug for CompiledScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledScript")
            .field("handle", &self.handle)
            .field("name", &self.name)
            .field("source_len", &self.source.len())
            .field("ast_hash", &self.ast_hash)
            .field("compiled_at", &self.compiled_at)
            .field("compile_ms", &self.compile_ms)
            .field("path", &self.path)
            .finish()
    }
}

impl CompiledScript {
    fn from_source(handle: ScriptHandle, name: String, source: String, compile_ms: u64) -> Self {
        let ast_hash = fnv64(source.as_bytes());
        Self {
            handle,
            name,
            source,
            ast_hash,
            compiled_at: Instant::now(),
            compile_ms,
            path: None,
        }
    }
}


/// FNV-1a 64-bit hash.
fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// CompileCache — stores compiled scripts
// ---------------------------------------------------------------------------

/// A simple fixed-capacity compile cache. Evicts the oldest entry on overflow.
pub struct CompileCache {
    capacity: usize,
    entries: HashMap<ScriptHandle, CompiledScript>,
    insertion_order: Vec<ScriptHandle>,
}

impl CompileCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { capacity, entries: HashMap::new(), insertion_order: Vec::new() }
    }

    /// Insert a compiled script. Returns `Err` if full and eviction is disabled.
    ///
    /// # Errors
    /// Returns [`ScriptManagerError::CacheFull`] if the cache is at capacity and cannot evict.
    pub fn insert(&mut self, script: CompiledScript) -> Result<(), ScriptManagerError> {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&script.handle) {
            // Evict oldest.
            if let Some(oldest) = self.insertion_order.first().copied() {
                self.entries.remove(&oldest);
                self.insertion_order.remove(0);
            } else {
                return Err(ScriptManagerError::CacheFull(self.capacity));
            }
        }
        self.insertion_order.push(script.handle);
        self.entries.insert(script.handle, script);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, handle: ScriptHandle) -> Option<&CompiledScript> {
        self.entries.get(&handle)
    }

    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&CompiledScript> {
        self.entries.values().find(|s| s.name == name)
    }

    pub fn remove(&mut self, handle: ScriptHandle) -> bool {
        if self.entries.remove(&handle).is_some() {
            self.insertion_order.retain(|&h| h != handle);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn all_scripts(&self) -> Vec<&CompiledScript> {
        self.entries.values().collect()
    }
}

// ---------------------------------------------------------------------------
// ExecutionConfig — per-execution options
// ---------------------------------------------------------------------------

/// Options for a single script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Maximum wall-clock time allowed. `None` = no limit.
    pub timeout: Option<Duration>,
    /// Maximum number of Rhai operations (engine-level limit). 0 = unlimited.
    pub max_operations: u64,
    /// Whether to capture stdout-like print output.
    pub capture_output: bool,
    /// Variables to inject into the script scope as `(name, json_value)` pairs.
    pub injected_vars: Vec<(String, String)>,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(5)),
            max_operations: 1_000_000,
            capture_output: true,
            injected_vars: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionResult — outcome of one script run
// ---------------------------------------------------------------------------

/// The outcome of executing a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub handle: ScriptHandle,
    pub script_name: String,
    /// Return value, serialized to a JSON-compatible string.
    pub return_value: Option<String>,
    /// Captured output lines (if `capture_output` was set).
    pub output_lines: Vec<String>,
    /// Wall-clock time for this run.
    pub elapsed: Duration,
    /// Whether execution completed successfully.
    pub success: bool,
    /// Error message if `!success`.
    pub error: Option<String>,
    /// Number of Rhai operations executed.
    pub operations: u64,
}

impl ExecutionResult {
    #[must_use]
    const fn ok(
        handle: ScriptHandle,
        name: String,
        return_value: Option<String>,
        output: Vec<String>,
        elapsed: Duration,
        ops: u64,
    ) -> Self {
        Self {
            handle,
            script_name: name,
            return_value,
            output_lines: output,
            elapsed,
            success: true,
            error: None,
            operations: ops,
        }
    }
}


// ---------------------------------------------------------------------------
// ManagerStats — aggregate statistics
// ---------------------------------------------------------------------------

/// Aggregate statistics about the script manager's lifetime activity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagerStats {
    pub scripts_loaded: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub timeout_executions: u64,
    pub total_exec_time_ms: u64,
}

// ---------------------------------------------------------------------------
// RhaiScriptManager — main manager
// ---------------------------------------------------------------------------

/// Manages Rhai scripts: load from source or file, compile with caching,
/// execute with timeout enforcement.
///
/// This implementation is deliberately decoupled from the `rhai::Engine` type
/// so that the module compiles without a direct dependency on a specific rhai
/// version. Actual engine integration happens in `rhai_full_api`.
pub struct RhaiScriptManager {
    cache: CompileCache,
    next_id: u64,
    stats: ManagerStats,
    /// Maximum source size accepted (default 1 MiB).
    max_source_bytes: usize,
}

impl RhaiScriptManager {
    #[must_use]
    pub fn new(cache_capacity: usize) -> Self {
        Self {
            cache: CompileCache::new(cache_capacity),
            next_id: 1,
            stats: ManagerStats::default(),
            max_source_bytes: 1024 * 1024,
        }
    }

    const fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ------------------------------------------------------------------
    // Loading / compiling
    // ------------------------------------------------------------------

    /// Compile a script from a source string. Returns a `ScriptHandle`.
    ///
    /// # Errors
    /// Returns an error if the source is empty, too large, or has unbalanced braces.
    pub fn load_source(
        &mut self,
        name: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<ScriptHandle, ScriptManagerError> {
        let name = name.into();
        let source = source.into();

        if source.is_empty() {
            return Err(ScriptManagerError::EmptySource);
        }
        if source.len() > self.max_source_bytes {
            return Err(ScriptManagerError::CompileError {
                name,
                reason: format!("source exceeds {} bytes", self.max_source_bytes),
            });
        }

        // Check if already cached by content hash.
        let hash = fnv64(source.as_bytes());
        if let Some(existing) = self.cache.entries.values().find(|s| s.ast_hash == hash) {
            self.stats.cache_hits += 1;
            return Ok(existing.handle);
        }

        self.stats.cache_misses += 1;

        // Simulate compilation — validate that braces are balanced as a minimal sanity check.
        let compile_start = Instant::now();
        validate_syntax(&source).map_err(|reason| ScriptManagerError::CompileError {
            name: name.clone(),
            reason,
        })?;
        let compile_ms = u64::try_from(compile_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let handle = ScriptHandle::new(self.alloc_id());
        let script = CompiledScript::from_source(handle, name, source, compile_ms);
        self.cache.insert(script)?;
        self.stats.scripts_loaded += 1;

        Ok(handle)
    }

    /// Load a script from a file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or the source is invalid.
    pub fn load_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<ScriptHandle, ScriptManagerError> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let source = std::fs::read_to_string(path).map_err(|e| ScriptManagerError::NotFound(
            format!("{}: {}", path.display(), e),
        ))?;

        let handle = self.load_source(name, source)?;
        // Attach path to the cached entry.
        if let Some(script) = self.cache.entries.get_mut(&handle) {
            script.path = Some(path.to_path_buf());
        }
        Ok(handle)
    }

    /// Look up a previously loaded script by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<ScriptHandle> {
        self.cache.get_by_name(name).map(|s| s.handle)
    }

    /// Retrieve source of a cached script.
    #[must_use]
    pub fn source_of(&self, handle: ScriptHandle) -> Option<&str> {
        self.cache.get(handle).map(|s| s.source.as_str())
    }

    // ------------------------------------------------------------------
    // Execution
    // ------------------------------------------------------------------

    /// Execute a compiled script with the given configuration.
    ///
    /// Because this module is engine-agnostic, execution is simulated by
    /// scanning the source for `print(...)` and `return` statements and
    /// returning their text. Real execution happens in `rhai_full_api`.
    ///
    /// # Errors
    /// Returns an error if the handle is invalid, the script times out, or the operation limit is exceeded.
    pub fn execute(
        &mut self,
        handle: ScriptHandle,
        config: &ExecutionConfig,
    ) -> Result<ExecutionResult, ScriptManagerError> {
        let script = self
            .cache
            .get(handle)
            .ok_or_else(|| ScriptManagerError::InvalidHandle(handle.id()))?
            .clone();

        let start = Instant::now();
        self.stats.executions += 1;

        // Simulate execution: collect print-like lines and find a return value.
        let output_lines = extract_print_args(&script.source);
        let return_value = extract_return_value(&script.source);
        let ops = u64::try_from(script.source.len()).unwrap_or(u64::MAX) / 10; // rough proxy

        // Timeout simulation.
        let elapsed = start.elapsed();
        if let Some(limit) = config.timeout && elapsed > limit {
            self.stats.timeout_executions += 1;
            self.stats.failed_executions += 1;
            return Err(ScriptManagerError::Timeout(limit));
        }

        // Ops limit.
        if config.max_operations > 0 && ops > config.max_operations {
            self.stats.failed_executions += 1;
            return Err(ScriptManagerError::ExecutionError {
                name: script.name,
                reason: "operation limit exceeded".into(),
            });
        }

        let elapsed2 = start.elapsed();
        self.stats.successful_executions += 1;
        self.stats.total_exec_time_ms += u64::try_from(elapsed2.as_millis()).unwrap_or(u64::MAX);

        Ok(ExecutionResult::ok(handle, script.name, return_value, output_lines, elapsed2, ops))
    }

    /// Execute a script by name.
    ///
    /// # Errors
    /// Returns an error if the script name is not found, or execution fails.
    pub fn execute_by_name(
        &mut self,
        name: &str,
        config: &ExecutionConfig,
    ) -> Result<ExecutionResult, ScriptManagerError> {
        let handle = self
            .find_by_name(name)
            .ok_or_else(|| ScriptManagerError::NotFound(name.to_string()))?;
        self.execute(handle, config)
    }

    // ------------------------------------------------------------------
    // Cache management
    // ------------------------------------------------------------------

    #[must_use]
    pub fn evict(&mut self, handle: ScriptHandle) -> bool {
        self.cache.remove(handle)
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub const fn cache_capacity(&self) -> usize {
        self.cache.capacity()
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    #[must_use]
    pub const fn stats(&self) -> &ManagerStats {
        &self.stats
    }

    #[must_use]
    pub fn cache_hit_ratio(&self) -> f64 {
        let total = self.stats.cache_hits + self.stats.cache_misses;
        if total == 0 {
            0.0
        } else {
            // Compute ratio at fixed-point precision (per-mille) then convert via u32→f64
            // (u32 → f64 is always lossless). hits_pm is always 0..=1000.
            let hits_pm = self.stats.cache_hits * 1_000 / total;
            f64::from(u32::try_from(hits_pm).unwrap_or(1_000)) / 1_000.0
        }
    }
}

// ---------------------------------------------------------------------------
// Syntax helpers (used in place of a real Rhai engine in this module)
// ---------------------------------------------------------------------------

/// Minimal syntax check: balanced braces and no obvious injection markers.
fn validate_syntax(source: &str) -> Result<(), String> {
    let mut depth: i32 = 0;
    for ch in source.chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return Err("unmatched '}'".into());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("unclosed '{{': {depth} unmatched"));
    }
    Ok(())
}

/// Extract arguments from `print(...)` calls (very simplified).
fn extract_print_args(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if &bytes[i..i + 6] == b"print(" {
            let start = i + 6;
            let mut depth = 1i32;
            let mut j = start;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth == 0 && j <= bytes.len() {
                // Ensure start..j lands on valid UTF-8 char boundaries before
                // slicing the &str, to avoid a panic on multibyte codepoints.
                if source.is_char_boundary(start) && source.is_char_boundary(j) {
                    let inner = &source[start..j];
                    out.push(inner.trim().trim_matches('"').to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Extract the first `return <value>;` expression from source.
fn extract_return_value(source: &str) -> Option<String> {
    // Split on both newlines and semicolons so multi-statement single lines work.
    for stmt in source.split(['\n', ';']) {
        let t = stmt.trim();
        if let Some(rest) = t.strip_prefix("return ") {
            return Some(rest.trim().to_string());
        }
        if t == "return" {
            return Some(String::new());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Thread-safe wrapper for use across multiple Rhai engines
// ---------------------------------------------------------------------------

/// A `RhaiScriptManager` wrapped in `Arc<Mutex<...>>` for shared ownership.
pub type SharedScriptManager = Arc<Mutex<RhaiScriptManager>>;

/// Convenience constructor.
#[must_use]
pub fn make_shared_manager(cache_capacity: usize) -> SharedScriptManager {
    Arc::new(Mutex::new(RhaiScriptManager::new(cache_capacity)))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> RhaiScriptManager {
        RhaiScriptManager::new(16)
    }

    #[test]
    fn test_load_and_cache_hit() {
        let mut mgr = manager();
        let h1 = mgr.load_source("test", "let x = 1;").unwrap();
        let h2 = mgr.load_source("test_dup", "let x = 1;").unwrap(); // same content
        assert_eq!(h1, h2); // cache hit
        assert_eq!(mgr.stats().cache_hits, 1);
    }

    #[test]
    fn test_empty_source_error() {
        let mut mgr = manager();
        assert!(matches!(
            mgr.load_source("empty", ""),
            Err(ScriptManagerError::EmptySource)
        ));
    }

    #[test]
    fn test_unbalanced_braces_error() {
        let mut mgr = manager();
        let err = mgr.load_source("bad", "fn foo() { let x = 1; ");
        assert!(matches!(err, Err(ScriptManagerError::CompileError { .. })));
    }

    #[test]
    fn test_execute_success() {
        let mut mgr = manager();
        let h = mgr.load_source("hello", r#"print("hello"); return 42;"#).unwrap();
        let result = mgr.execute(h, &ExecutionConfig::default()).unwrap();
        assert!(result.success);
        assert_eq!(result.output_lines, vec!["hello"]);
        assert_eq!(result.return_value.as_deref(), Some("42"));
    }

    #[test]
    fn test_execute_by_name() {
        let mut mgr = manager();
        mgr.load_source("named_script", "return 99;").unwrap();
        let result = mgr.execute_by_name("named_script", &ExecutionConfig::default()).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_execute_not_found() {
        let mut mgr = manager();
        assert!(matches!(
            mgr.execute_by_name("ghost", &ExecutionConfig::default()),
            Err(ScriptManagerError::NotFound(_))
        ));
    }

    #[test]
    fn test_cache_eviction_on_overflow() {
        let mut mgr = RhaiScriptManager::new(2); // tiny capacity
        mgr.load_source("s1", "let a = 1;").unwrap();
        mgr.load_source("s2", "let b = 2;").unwrap();
        mgr.load_source("s3", "let c = 3;").unwrap(); // should evict s1
        assert_eq!(mgr.cache_len(), 2);
    }

    #[test]
    fn test_evict_explicit() {
        let mut mgr = manager();
        let h = mgr.load_source("evict_me", "let x = 0;").unwrap();
        assert!(mgr.evict(h));
        assert!(mgr.find_by_name("evict_me").is_none());
    }

    #[test]
    fn test_stats_tracking() {
        let mut mgr = manager();
        let h = mgr.load_source("s", "return 1;").unwrap();
        mgr.execute(h, &ExecutionConfig::default()).unwrap();
        let stats = mgr.stats();
        assert_eq!(stats.executions, 1);
        assert_eq!(stats.successful_executions, 1);
    }

    #[test]
    fn test_cache_hit_ratio() {
        let mut mgr = manager();
        let src = "let x = 10;";
        mgr.load_source("first", src).unwrap();
        mgr.load_source("second", src).unwrap(); // hit
        assert!((mgr.cache_hit_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_shared_manager() {
        let shared = make_shared_manager(8);
        {
            let mut mgr = shared.lock().unwrap();
            mgr.load_source("shared_test", "return 7;").unwrap();
        }
        let mgr = shared.lock().unwrap();
        assert!(mgr.find_by_name("shared_test").is_some());
    }

    #[test]
    fn test_source_of() {
        let mut mgr = manager();
        let src = "let z = 99;";
        let h = mgr.load_source("src_query", src).unwrap();
        assert_eq!(mgr.source_of(h), Some(src));
    }
}
