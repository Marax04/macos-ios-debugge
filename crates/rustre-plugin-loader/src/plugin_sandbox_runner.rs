// rustre-plugin-loader/src/plugin_sandbox_runner.rs
//
// Sandboxed plugin execution for RustRE.  Provides resource accounting,
// permission enforcement, and structured run results without requiring
// OS-level process isolation.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the sandbox runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    /// The plugin exceeded its allocated CPU time.
    CpuTimeExceeded { limit_ms: u64, elapsed_ms: u64 },
    /// The plugin exceeded its memory quota.
    MemoryExceeded { limit_bytes: u64, used_bytes: u64 },
    /// A syscall or API was invoked that the policy does not allow.
    PolicyViolation(String),
    /// The plugin panicked and the panic was caught.
    PluginPanic(String),
    /// An I/O error occurred while setting up the sandbox.
    Setup(String),
    /// The plugin entry function was not found.
    EntryNotFound(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuTimeExceeded { limit_ms, elapsed_ms } => {
                write!(f, "CPU time exceeded: limit {limit_ms}ms, used {elapsed_ms}ms")
            }
            Self::MemoryExceeded { limit_bytes, used_bytes } => {
                write!(
                    f,
                    "memory exceeded: limit {limit_bytes}B, used {used_bytes}B"
                )
            }
            Self::PolicyViolation(msg) => write!(f, "policy violation: {msg}"),
            Self::PluginPanic(msg) => write!(f, "plugin panic: {msg}"),
            Self::Setup(msg) => write!(f, "sandbox setup error: {msg}"),
            Self::EntryNotFound(name) => write!(f, "entry point not found: '{name}'"),
        }
    }
}

impl std::error::Error for SandboxError {}

// ── SandboxPolicy ─────────────────────────────────────────────────────────────

/// Fine-grained boolean permission flags for a sandboxed plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub allow_fs_read: bool,
    pub allow_fs_write: bool,
    pub allow_network: bool,
    pub allow_subprocess: bool,
    pub allow_memory_write: bool,
    pub allow_ui: bool,
    /// List of file-system path prefixes that are explicitly allowed for reads.
    pub allowed_read_paths: Vec<String>,
    /// List of network host patterns that are explicitly allowed.
    pub allowed_hosts: Vec<String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allow_fs_read: false,
            allow_fs_write: false,
            allow_network: false,
            allow_subprocess: false,
            allow_memory_write: false,
            allow_ui: false,
            allowed_read_paths: Vec::new(),
            allowed_hosts: Vec::new(),
        }
    }
}

impl SandboxPolicy {
    /// A policy that allows everything (trusted plugins).
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            allow_fs_read: true,
            allow_fs_write: true,
            allow_network: true,
            allow_subprocess: true,
            allow_memory_write: true,
            allow_ui: true,
            allowed_read_paths: Vec::new(),
            allowed_hosts: Vec::new(),
        }
    }

    /// A policy that denies everything (maximally restricted).
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// A policy suitable for read-only analysis plugins.
    #[must_use]
    pub fn analysis_safe() -> Self {
        Self {
            allow_fs_read: true,
            ..Self::default()
        }
    }

    /// Check whether accessing `path` for reading is permitted.
    #[must_use]
    pub fn check_read_path(&self, path: &str) -> bool {
        if !self.allow_fs_read {
            return false;
        }
        if self.allowed_read_paths.is_empty() {
            return true;
        }
        self.allowed_read_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }

    /// Check whether connecting to `host` is permitted.
    #[must_use]
    pub fn check_host(&self, host: &str) -> bool {
        if !self.allow_network {
            return false;
        }
        if self.allowed_hosts.is_empty() {
            return true;
        }
        self.allowed_hosts
            .iter()
            .any(|h| h == "*" || h.as_str() == host)
    }
}

// ── SandboxConfig ─────────────────────────────────────────────────────────────

/// Configuration for a single sandboxed plugin run.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum wall-clock time (not CPU time) the plugin may run.
    pub max_wall_time: Duration,
    /// Maximum heap memory the plugin may allocate, in bytes (0 = unlimited).
    pub max_memory_bytes: u64,
    /// Maximum number of API calls the plugin may make.
    pub max_api_calls: u64,
    /// Fine-grained permissions.
    pub policy: SandboxPolicy,
    /// Environment variables visible to the plugin.
    pub env: HashMap<String, String>,
    /// Whether to capture the plugin's stdout output.
    pub capture_output: bool,
    /// Whether to log every API call for auditing.
    pub audit_api_calls: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_wall_time: Duration::from_secs(30),
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            max_api_calls: 100_000,
            policy: SandboxPolicy::default(),
            env: HashMap::new(),
            capture_output: true,
            audit_api_calls: false,
        }
    }
}

impl SandboxConfig {
    /// Config suitable for trusted, native plugins with no restrictions.
    #[must_use]
    pub fn trusted() -> Self {
        Self {
            max_wall_time: Duration::from_secs(300),
            max_memory_bytes: 0,
            max_api_calls: u64::MAX,
            policy: SandboxPolicy::permissive(),
            env: HashMap::new(),
            capture_output: false,
            audit_api_calls: false,
        }
    }

    /// Config for a short-lived, maximally restricted plugin evaluation.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self {
            max_wall_time: Duration::from_millis(500),
            max_memory_bytes: 4 * 1024 * 1024, // 4 MB
            max_api_calls: 1_000,
            policy: SandboxPolicy::deny_all(),
            env: HashMap::new(),
            capture_output: true,
            audit_api_calls: true,
        }
    }

    /// Add an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }
}

// ── ResourceUsage ─────────────────────────────────────────────────────────────

/// Accounting data collected during a sandboxed run.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Elapsed wall-clock time.
    pub wall_time: Duration,
    /// Peak memory usage in bytes (sampled, not exact).
    pub peak_memory_bytes: u64,
    /// Total number of API calls made.
    pub api_calls: u64,
    /// Number of API calls denied by the sandbox policy.
    pub denied_calls: u64,
    /// Total bytes read from the filesystem.
    pub fs_bytes_read: u64,
    /// Total bytes written to the filesystem.
    pub fs_bytes_written: u64,
    /// Number of network connections attempted.
    pub network_attempts: u64,
}

impl ResourceUsage {
    /// Whether any resource limit was exceeded (based on comparison with config).
    #[must_use]
    pub fn any_limit_exceeded(&self, cfg: &SandboxConfig) -> bool {
        if cfg.max_memory_bytes > 0 && self.peak_memory_bytes > cfg.max_memory_bytes {
            return true;
        }
        if cfg.max_api_calls < u64::MAX && self.api_calls > cfg.max_api_calls {
            return true;
        }
        if self.wall_time > cfg.max_wall_time {
            return true;
        }
        false
    }
}

impl fmt::Display for ResourceUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wall={:.1}ms mem={}KB calls={} denied={}",
            self.wall_time.as_secs_f64() * 1000.0,
            self.peak_memory_bytes / 1024,
            self.api_calls,
            self.denied_calls,
        )
    }
}

// ── RunResult ─────────────────────────────────────────────────────────────────

/// The outcome of a sandboxed plugin run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Whether the run completed without error.
    pub success: bool,
    /// Error, if any.
    pub error: Option<SandboxError>,
    /// Captured stdout output (only when `capture_output` is set).
    pub output: String,
    /// Resource accounting.
    pub usage: ResourceUsage,
    /// Ordered log of API calls (only when `audit_api_calls` is set).
    pub audit_log: Vec<AuditEntry>,
    /// Arbitrary return value from the plugin entry function.
    pub return_value: Option<String>,
}

impl RunResult {
    fn success(usage: ResourceUsage, output: String, audit_log: Vec<AuditEntry>) -> Self {
        Self {
            success: true,
            error: None,
            output,
            usage,
            audit_log,
            return_value: None,
        }
    }

    fn failure(err: SandboxError, usage: ResourceUsage, output: String) -> Self {
        Self {
            success: false,
            error: Some(err),
            output,
            usage,
            audit_log: Vec::new(),
            return_value: None,
        }
    }
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(f, "RunResult(ok, {})", self.usage)
        } else {
            write!(
                f,
                "RunResult(err={}, {})",
                self.error
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default(),
                self.usage
            )
        }
    }
}

// ── AuditEntry ────────────────────────────────────────────────────────────────

/// One recorded API call in the audit log.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Monotonic offset from run start in milliseconds.
    pub offset_ms: u64,
    /// Name of the API function called.
    pub api: String,
    /// Whether the call was allowed or denied.
    pub allowed: bool,
    /// Optional extra context (e.g. the path or host name).
    pub context: Option<String>,
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.allowed { "allow" } else { "deny" };
        write!(f, "[+{}ms] {status} {}", self.offset_ms, self.api)?;
        if let Some(ctx) = &self.context {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

// ── SandboxContext ─────────────────────────────────────────────────────────────

/// Mutable execution context threaded through a sandboxed run.
struct SandboxContext {
    config: SandboxConfig,
    start: Instant,
    usage: Arc<Mutex<ResourceUsage>>,
    output: Arc<Mutex<String>>,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
}

impl SandboxContext {
    fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            start: Instant::now(),
            usage: Arc::new(Mutex::new(ResourceUsage::default())),
            output: Arc::new(Mutex::new(String::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        // `as_millis()` returns u128; clamp to u64::MAX to avoid truncation.
        self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn record_api_call(&self, api: &str, allowed: bool, context: Option<String>) {
        // Update usage counters and then RELEASE the usage lock before
        // acquiring audit_log, so that both locks are never held simultaneously.
        // Holding usage while acquiring audit_log would create a deadlock if
        // another code path acquires them in a different order.
        {
            let mut usage = self.usage.lock().unwrap();
            usage.api_calls += 1;
            if !allowed {
                usage.denied_calls += 1;
            }
        } // usage lock released here
        if self.config.audit_api_calls {
            let entry = AuditEntry {
                offset_ms: self.elapsed_ms(),
                api: api.to_string(),
                allowed,
                context,
            };
            self.audit_log.lock().unwrap().push(entry);
        }
    }

    fn write_output(&self, text: &str) {
        if self.config.capture_output {
            self.output.lock().unwrap().push_str(text);
        }
    }

    fn check_wall_time(&self) -> Result<(), SandboxError> {
        let elapsed = self.start.elapsed();
        if elapsed > self.config.max_wall_time {
            // Clamp u128 ms values to u64::MAX to avoid truncation on
            // pathologically long durations (> ~584 million years).
            let clamp = |d: Duration| d.as_millis().min(u64::MAX as u128) as u64;
            return Err(SandboxError::CpuTimeExceeded {
                limit_ms: clamp(self.config.max_wall_time),
                elapsed_ms: clamp(elapsed),
            });
        }
        Ok(())
    }

    fn finalize(self) -> (ResourceUsage, String, Vec<AuditEntry>) {
        let mut usage = Arc::try_unwrap(self.usage)
            .unwrap_or_else(|arc| Mutex::new(arc.lock().unwrap().clone()))
            .into_inner()
            .unwrap();
        usage.wall_time = self.start.elapsed();
        let output = Arc::try_unwrap(self.output)
            .unwrap_or_else(|arc| Mutex::new(arc.lock().unwrap().clone()))
            .into_inner()
            .unwrap();
        let audit = Arc::try_unwrap(self.audit_log)
            .unwrap_or_else(|arc| Mutex::new(arc.lock().unwrap().clone()))
            .into_inner()
            .unwrap();
        (usage, output, audit)
    }
}

// ── PluginSandboxRunner ───────────────────────────────────────────────────────

/// Runs plugin callbacks inside a software sandbox with resource accounting
/// and permission enforcement.
///
/// The sandbox does **not** use OS-level process isolation; it enforces limits
/// at the Rust API boundary.  For true isolation, pair this runner with
/// an OS process or WebAssembly boundary.
///
/// # Usage
///
/// ```
/// use rustre_plugin_loader::plugin_sandbox_runner::{
///     PluginSandboxRunner, SandboxConfig,
/// };
///
/// let runner = PluginSandboxRunner::new();
/// let config = SandboxConfig::default();
/// let result = runner.run_sandboxed("my-plugin", &config, || {
///     Ok("hello from plugin".to_string())
/// });
/// assert!(result.success);
/// ```
#[derive(Debug, Default)]
pub struct PluginSandboxRunner {
    /// Per-plugin usage history (plugin_id → list of `ResourceUsage`).
    history: Mutex<HashMap<String, Vec<ResourceUsage>>>,
}

impl PluginSandboxRunner {
    /// Create a new runner with empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` inside a sandbox governed by `config`.
    ///
    /// `f` receives no arguments and returns a `Result<String, SandboxError>`.
    /// The `String` becomes the `return_value` in the [`RunResult`].
    ///
    /// # Errors (via `RunResult::error`)
    ///
    /// - `CpuTimeExceeded` if `f` takes longer than `config.max_wall_time`.
    /// - `PolicyViolation` if `f` calls a blocked helper.
    /// - `PluginPanic` if `f` panics.
    pub fn run_sandboxed<F>(
        &self,
        plugin_id: &str,
        config: &SandboxConfig,
        f: F,
    ) -> RunResult
    where
        F: FnOnce() -> Result<String, SandboxError>,
    {
        let ctx = SandboxContext::new(config.clone());

        // Guard: check max_api_calls before we start.
        if config.max_api_calls == 0 {
            let (usage, output, _) = ctx.finalize();
            return RunResult::failure(
                SandboxError::PolicyViolation("max_api_calls is 0".into()),
                usage,
                output,
            );
        }

        ctx.record_api_call("run_sandboxed", true, Some(plugin_id.to_string()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f()));
        let time_ok = ctx.check_wall_time();

        // If a return value was produced, push it through write_output so the
        // capture buffer reflects the closure's textual output when enabled.
        if let Ok(Ok(ref val)) = result {
            ctx.write_output(val);
        }

        let (usage, output, audit) = ctx.finalize();

        let run_result = match result {
            Ok(Ok(val)) => match time_ok {
                Ok(()) => {
                    let mut r = RunResult::success(usage.clone(), output, audit);
                    r.return_value = Some(val);
                    r
                }
                Err(err) => RunResult::failure(err, usage.clone(), output),
            },
            Ok(Err(err)) => RunResult::failure(err, usage.clone(), output),
            Err(panic_val) => {
                let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                RunResult::failure(SandboxError::PluginPanic(msg), usage.clone(), output)
            }
        };

        // Record usage history.
        self.history
            .lock()
            .unwrap()
            .entry(plugin_id.to_string())
            .or_default()
            .push(usage);

        run_result
    }

    /// Run a batch of sandboxed invocations sequentially, returning all results.
    pub fn run_batch<I, F>(
        &self,
        plugin_id: &str,
        config: &SandboxConfig,
        tasks: I,
    ) -> Vec<RunResult>
    where
        I: IntoIterator<Item = F>,
        F: FnOnce() -> Result<String, SandboxError>,
    {
        tasks
            .into_iter()
            .map(|f| self.run_sandboxed(plugin_id, config, f))
            .collect()
    }

    /// Check whether an access to `path` is permitted under `config`.
    #[must_use]
    pub fn check_fs_read(config: &SandboxConfig, path: &str) -> bool {
        config.policy.check_read_path(path)
    }

    /// Check whether a network connection to `host` is permitted.
    #[must_use]
    pub fn check_network(config: &SandboxConfig, host: &str) -> bool {
        config.policy.check_host(host)
    }

    /// Return the number of runs recorded for `plugin_id`.
    #[must_use]
    pub fn run_count(&self, plugin_id: &str) -> usize {
        self.history
            .lock()
            .unwrap()
            .get(plugin_id)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Return the resource usage history for `plugin_id`.
    #[must_use]
    pub fn history_for(&self, plugin_id: &str) -> Vec<ResourceUsage> {
        self.history
            .lock()
            .unwrap()
            .get(plugin_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Return cumulative stats across all runs for `plugin_id`.
    #[must_use]
    pub fn cumulative_usage(&self, plugin_id: &str) -> ResourceUsage {
        let hist = self.history_for(plugin_id);
        let mut total = ResourceUsage::default();
        for u in &hist {
            // Use saturating_add to avoid panicking if accumulated wall time
            // overflows Duration::MAX (possible with many long-running runs).
            total.wall_time = total.wall_time.saturating_add(u.wall_time);
            total.api_calls = total.api_calls.saturating_add(u.api_calls);
            total.denied_calls = total.denied_calls.saturating_add(u.denied_calls);
            total.fs_bytes_read = total.fs_bytes_read.saturating_add(u.fs_bytes_read);
            total.network_attempts = total.network_attempts.saturating_add(u.network_attempts);
            if u.peak_memory_bytes > total.peak_memory_bytes {
                total.peak_memory_bytes = u.peak_memory_bytes;
            }
        }
        total
    }

    /// Clear usage history for `plugin_id`.
    pub fn clear_history(&self, plugin_id: &str) {
        self.history.lock().unwrap().remove(plugin_id);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_successful_run() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        let result = runner.run_sandboxed("test-plugin", &cfg, || Ok("done".into()));
        assert!(result.success);
        assert_eq!(result.return_value.as_deref(), Some("done"));
    }

    #[test]
    fn test_plugin_error_propagates() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        let result = runner.run_sandboxed("test-plugin", &cfg, || {
            Err(SandboxError::PolicyViolation("no network".into()))
        });
        assert!(!result.success);
        assert!(matches!(result.error, Some(SandboxError::PolicyViolation(_))));
    }

    #[test]
    fn test_panic_caught() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        let result = runner.run_sandboxed("panic-plugin", &cfg, || -> Result<String, SandboxError> {
            panic!("intentional panic");
        });
        assert!(!result.success);
        assert!(matches!(result.error, Some(SandboxError::PluginPanic(_))));
    }

    #[test]
    fn test_run_count_tracked() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        for _ in 0..3 {
            runner.run_sandboxed("counting", &cfg, || Ok("x".into()));
        }
        assert_eq!(runner.run_count("counting"), 3);
    }

    #[test]
    fn test_batch_run() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        let tasks: Vec<Box<dyn FnOnce() -> Result<String, SandboxError>>> = vec![
            Box::new(|| Ok("a".into())),
            Box::new(|| Ok("b".into())),
            Box::new(|| Err(SandboxError::PolicyViolation("blocked".into()))),
        ];
        let results = runner.run_batch("batch", &cfg, tasks);
        assert_eq!(results.len(), 3);
        assert!(results[0].success);
        assert!(results[1].success);
        assert!(!results[2].success);
    }

    #[test]
    fn test_fs_read_check() {
        let mut cfg = SandboxConfig::default();
        cfg.policy.allow_fs_read = true;
        cfg.policy.allowed_read_paths = vec!["/home/user/plugins".into()];
        assert!(PluginSandboxRunner::check_fs_read(&cfg, "/home/user/plugins/a.lua"));
        assert!(!PluginSandboxRunner::check_fs_read(&cfg, "/etc/passwd"));
    }

    #[test]
    fn test_network_check() {
        let mut cfg = SandboxConfig::default();
        cfg.policy.allow_network = true;
        cfg.policy.allowed_hosts = vec!["example.com".into()];
        assert!(PluginSandboxRunner::check_network(&cfg, "example.com"));
        assert!(!PluginSandboxRunner::check_network(&cfg, "evil.com"));
    }

    #[test]
    fn test_zero_api_calls_denied() {
        let runner = PluginSandboxRunner::new();
        let mut cfg = SandboxConfig::default();
        cfg.max_api_calls = 0;
        let result = runner.run_sandboxed("zero-calls", &cfg, || Ok("x".into()));
        assert!(!result.success);
    }

    #[test]
    fn test_sandbox_config_trusted() {
        let cfg = SandboxConfig::trusted();
        assert!(cfg.policy.allow_network);
        assert!(cfg.policy.allow_fs_write);
        assert_eq!(cfg.max_memory_bytes, 0);
    }

    #[test]
    fn test_sandbox_config_ephemeral() {
        let cfg = SandboxConfig::ephemeral();
        assert!(!cfg.policy.allow_network);
        assert!(cfg.audit_api_calls);
    }

    #[test]
    fn test_policy_permissive() {
        let p = SandboxPolicy::permissive();
        assert!(p.check_read_path("/any/path"));
        assert!(p.check_host("anything.io"));
    }

    #[test]
    fn test_policy_deny_all() {
        let p = SandboxPolicy::deny_all();
        assert!(!p.check_read_path("/any/path"));
        assert!(!p.check_host("anything.io"));
    }

    #[test]
    fn test_run_result_display() {
        let r = RunResult::success(ResourceUsage::default(), String::new(), Vec::new());
        assert!(r.to_string().contains("ok"));
    }

    #[test]
    fn test_cumulative_usage() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        runner.run_sandboxed("cum", &cfg, || Ok("a".into()));
        runner.run_sandboxed("cum", &cfg, || Ok("b".into()));
        let cu = runner.cumulative_usage("cum");
        // Each run_sandboxed records one API call ("run_sandboxed" bookkeeping),
        // so two runs produce 2 cumulative API calls.
        assert_eq!(cu.api_calls, 2);
    }

    #[test]
    fn test_clear_history() {
        let runner = PluginSandboxRunner::new();
        let cfg = SandboxConfig::default();
        runner.run_sandboxed("to-clear", &cfg, || Ok("x".into()));
        assert_eq!(runner.run_count("to-clear"), 1);
        runner.clear_history("to-clear");
        assert_eq!(runner.run_count("to-clear"), 0);
    }

    #[test]
    fn test_sandbox_error_display() {
        let e = SandboxError::CpuTimeExceeded { limit_ms: 100, elapsed_ms: 150 };
        assert!(e.to_string().contains("100ms"));
        let e2 = SandboxError::MemoryExceeded { limit_bytes: 1024, used_bytes: 2048 };
        assert!(e2.to_string().contains("1024B"));
    }
}
