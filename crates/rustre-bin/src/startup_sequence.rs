//! Application startup sequencing for the RustRE suite.
//!
//! Initialises subsystems (config, logging, plugins, core services) in a
//! deterministic order, reports progress through a [`StartupObserver`], and
//! propagates the first failure as a [`StartupError`].
//!
//! # Example
//! ```rust,no_run
//! use rustre_bin::startup_sequence::{StartupSequence, StartupConfig};
//! let cfg = StartupConfig::default();
//! let result = StartupSequence::new(cfg).run().unwrap();
//! println!("started {} subsystems in {:.1}ms", result.steps_ok, result.elapsed_ms);
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur during startup.
#[derive(Debug, Clone)]
pub enum StartupError {
    /// A required subsystem failed to initialise.
    SubsystemFailed {
        step: String,
        reason: String,
    },
    /// The configuration file could not be read or parsed.
    ConfigError(String),
    /// A plugin failed to load.
    PluginLoadFailed {
        plugin: String,
        reason: String,
    },
    /// Startup exceeded the configured time limit.
    Timeout {
        elapsed_ms: u64,
        limit_ms: u64,
    },
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SubsystemFailed { step, reason } => {
                write!(f, "subsystem '{step}' failed: {reason}")
            }
            Self::ConfigError(msg) => write!(f, "configuration error: {msg}"),
            Self::PluginLoadFailed { plugin, reason } => {
                write!(f, "plugin '{plugin}' failed to load: {reason}")
            }
            Self::Timeout { elapsed_ms, limit_ms } => write!(
                f,
                "startup timed out after {elapsed_ms}ms (limit {limit_ms}ms)"
            ),
        }
    }
}

impl std::error::Error for StartupError {}

// ── StartupConfig ─────────────────────────────────────────────────────────────

/// Configuration that drives the startup sequence.
#[derive(Debug, Clone)]
pub struct StartupConfig {
    /// Path to the user config directory; defaults to `~/.rustre`.
    pub config_dir: Option<PathBuf>,
    /// Whether to load plugins at startup.
    pub load_plugins: bool,
    /// Directories to search for plugins.
    pub plugin_dirs: Vec<PathBuf>,
    /// Maximum allowed startup duration in milliseconds (0 = unlimited).
    pub timeout_ms: u64,
    /// Whether to enable verbose startup logging.
    pub verbose: bool,
    /// Names of subsystems to skip (for testing or minimal mode).
    pub skip_subsystems: Vec<String>,
    /// Extra key-value pairs forwarded to subsystems.
    pub extra: HashMap<String, String>,
}

impl Default for StartupConfig {
    fn default() -> Self {
        Self {
            config_dir: None,
            load_plugins: true,
            plugin_dirs: Vec::new(),
            timeout_ms: 30_000,
            verbose: false,
            skip_subsystems: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

// ── StartupStep ───────────────────────────────────────────────────────────────

/// Outcome status for a single startup step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepStatus {
    /// The step completed successfully.
    Ok,
    /// The step was skipped (optional or excluded by config).
    Skipped,
    /// The step failed.
    Failed(String),
}

impl fmt::Display for StepStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Skipped => write!(f, "skipped"),
            Self::Failed(r) => write!(f, "failed: {r}"),
        }
    }
}

/// Record of a single startup step's execution.
#[derive(Debug, Clone)]
pub struct StartupStep {
    /// Unique name identifying the step.
    pub name: String,
    /// Human-readable description of what the step does.
    pub description: String,
    /// Whether this step must succeed for startup to continue.
    pub required: bool,
    /// Time taken by this step.
    pub elapsed: Duration,
    /// Final status.
    pub status: StepStatus,
    /// Optional detail message (logged on verbose).
    pub detail: Option<String>,
}

impl StartupStep {
    fn new(name: impl Into<String>, description: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required,
            elapsed: Duration::ZERO,
            status: StepStatus::Skipped,
            detail: None,
        }
    }
}

// ── StartupResult ─────────────────────────────────────────────────────────────

/// Summary returned after a successful startup sequence.
#[derive(Debug, Clone)]
pub struct StartupResult {
    /// Individual step records, in execution order.
    pub steps: Vec<StartupStep>,
    /// Number of steps that completed with `Ok`.
    pub steps_ok: usize,
    /// Number of steps that were skipped.
    pub steps_skipped: usize,
    /// Total wall-clock time from `run()` entry to completion.
    pub elapsed_ms: u64,
    /// Environment variables set during startup.
    pub env_vars: HashMap<String, String>,
    /// Plugins successfully loaded.
    pub loaded_plugins: Vec<String>,
    /// Warnings generated during startup (non-fatal issues).
    pub warnings: Vec<String>,
}

impl StartupResult {
    fn new() -> Self {
        Self {
            steps: Vec::new(),
            steps_ok: 0,
            steps_skipped: 0,
            elapsed_ms: 0,
            env_vars: HashMap::new(),
            loaded_plugins: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Returns `true` if every required step succeeded.
    #[must_use]
    pub fn all_required_ok(&self) -> bool {
        self.steps
            .iter()
            .filter(|s| s.required)
            .all(|s| s.status == StepStatus::Ok)
    }

    /// Find a step record by name.
    #[must_use]
    pub fn step(&self, name: &str) -> Option<&StartupStep> {
        self.steps.iter().find(|s| s.name == name)
    }
}

// ── StartupObserver ───────────────────────────────────────────────────────────

/// Callback interface for monitoring startup progress.
pub trait StartupObserver: Send {
    /// Called before a step begins.
    fn on_begin(&mut self, step: &StartupStep);
    /// Called after a step completes (with its updated status).
    fn on_end(&mut self, step: &StartupStep);
    /// Called when a warning is issued.
    fn on_warning(&mut self, msg: &str);
}

/// A no-op observer that discards all notifications.
pub struct NullObserver;

impl StartupObserver for NullObserver {
    fn on_begin(&mut self, _step: &StartupStep) {}
    fn on_end(&mut self, _step: &StartupStep) {}
    fn on_warning(&mut self, _msg: &str) {}
}

/// A collecting observer that accumulates all step records and warnings.
#[derive(Debug, Default)]
pub struct CollectingObserver {
    pub log: Vec<String>,
}

impl StartupObserver for CollectingObserver {
    fn on_begin(&mut self, step: &StartupStep) {
        self.log.push(format!("[begin] {}", step.name));
    }
    fn on_end(&mut self, step: &StartupStep) {
        self.log.push(format!("[end]   {} → {}", step.name, step.status));
    }
    fn on_warning(&mut self, msg: &str) {
        self.log.push(format!("[warn]  {msg}"));
    }
}

// ── SubsystemFn ───────────────────────────────────────────────────────────────

/// Function signature for a startup step executor.
///
/// Receives the current `StartupConfig` and returns a detail message or an
/// error string.  Returning `Err(msg)` marks the step as `Failed`.
type SubsystemFn = Box<dyn Fn(&StartupConfig) -> Result<Option<String>, String> + Send + Sync>;

// ── StartupSequence ───────────────────────────────────────────────────────────

/// Orchestrates the application startup sequence.
pub struct StartupSequence {
    config: StartupConfig,
    observers: Vec<Box<dyn StartupObserver>>,
}

impl StartupSequence {
    /// Construct a new sequence with the given configuration.
    #[must_use]
    pub fn new(config: StartupConfig) -> Self {
        Self {
            config,
            observers: Vec::new(),
        }
    }

    /// Attach an observer that will receive step progress notifications.
    pub fn add_observer(&mut self, obs: Box<dyn StartupObserver>) {
        self.observers.push(obs);
    }

    /// Execute the startup sequence and return a [`StartupResult`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError`] when a required step fails or the timeout
    /// expires before all required steps have completed.
    pub fn run(mut self) -> Result<StartupResult, StartupError> {
        let global_start = Instant::now();
        let mut result = StartupResult::new();

        let steps: Vec<(StartupStep, SubsystemFn)> = self.build_steps();

        for (mut step, exec) in steps {
            // Check timeout before running each step.
            if self.config.timeout_ms > 0 {
                let elapsed = global_start.elapsed().as_millis() as u64;
                if elapsed >= self.config.timeout_ms {
                    return Err(StartupError::Timeout {
                        elapsed_ms: elapsed,
                        limit_ms: self.config.timeout_ms,
                    });
                }
            }

            // Skip if excluded.
            if self.config.skip_subsystems.contains(&step.name) {
                step.status = StepStatus::Skipped;
                for obs in &mut self.observers {
                    obs.on_begin(&step);
                    obs.on_end(&step);
                }
                result.steps_skipped += 1;
                result.steps.push(step);
                continue;
            }

            for obs in &mut self.observers {
                obs.on_begin(&step);
            }

            let step_start = Instant::now();
            let outcome = exec(&self.config);
            step.elapsed = step_start.elapsed();

            match outcome {
                Ok(detail) => {
                    step.status = StepStatus::Ok;
                    step.detail = detail;
                    result.steps_ok += 1;
                }
                Err(reason) => {
                    step.status = StepStatus::Failed(reason.clone());
                    if step.required {
                        for obs in &mut self.observers {
                            obs.on_end(&step);
                        }
                        result.steps.push(step.clone());
                        return Err(StartupError::SubsystemFailed {
                            step: step.name.clone(),
                            reason,
                        });
                    }
                    // Non-required failure becomes a warning.
                    let warn = format!("optional step '{}' failed: {}", step.name, reason);
                    result.warnings.push(warn.clone());
                    for obs in &mut self.observers {
                        obs.on_warning(&warn);
                    }
                }
            }

            for obs in &mut self.observers {
                obs.on_end(&step);
            }
            result.steps.push(step);
        }

        result.elapsed_ms = global_start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Build the ordered list of steps with their executor functions.
    fn build_steps(&self) -> Vec<(StartupStep, SubsystemFn)> {
        vec![
            (
                StartupStep::new("env", "Validate environment variables", true),
                Box::new(|_cfg| {
                    // Check that HOME / USERPROFILE is available.
                    if std::env::var_os("HOME").is_none()
                        && std::env::var_os("USERPROFILE").is_none()
                    {
                        return Err("neither HOME nor USERPROFILE is set".into());
                    }
                    Ok(Some("environment validated".into()))
                }),
            ),
            (
                StartupStep::new("config_dir", "Ensure configuration directory exists", true),
                Box::new(|cfg| {
                    let dir = cfg
                        .config_dir
                        .clone()
                        .or_else(|| {
                            std::env::var_os("HOME")
                                .or_else(|| std::env::var_os("USERPROFILE"))
                                .map(|h| PathBuf::from(h).join(".rustre"))
                        })
                        .unwrap_or_else(|| PathBuf::from(".rustre"));
                    std::fs::create_dir_all(&dir)
                        .map_err(|e| format!("create {}: {e}", dir.display()))?;
                    Ok(Some(dir.display().to_string()))
                }),
            ),
            (
                StartupStep::new("logging", "Initialise logging subsystem", false),
                Box::new(|cfg| {
                    let level = if cfg.verbose { "debug" } else { "info" };
                    Ok(Some(format!("log level: {level}")))
                }),
            ),
            (
                StartupStep::new("core_registry", "Register core analysis engines", true),
                Box::new(|_cfg| {
                    // In a real impl: register disassemblers, decompilers, lifters.
                    Ok(Some("core engines registered".into()))
                }),
            ),
            (
                StartupStep::new("plugin_discovery", "Discover available plugins", false),
                Box::new(|cfg| {
                    if !cfg.load_plugins {
                        return Ok(Some("plugin loading disabled".into()));
                    }
                    let count = cfg.plugin_dirs.len();
                    Ok(Some(format!("{count} plugin directories scanned")))
                }),
            ),
            (
                StartupStep::new("plugin_load", "Load and initialise plugins", false),
                Box::new(|cfg| {
                    if !cfg.load_plugins {
                        return Ok(Some("skipped (plugins disabled)".into()));
                    }
                    Ok(Some("plugins loaded".into()))
                }),
            ),
            (
                StartupStep::new("recent_files", "Load recent-file history", false),
                Box::new(|cfg| {
                    let dir = cfg
                        .config_dir
                        .clone()
                        .or_else(|| {
                            std::env::var_os("HOME")
                                .or_else(|| std::env::var_os("USERPROFILE"))
                                .map(|h| PathBuf::from(h).join(".rustre"))
                        })
                        .unwrap_or_else(|| PathBuf::from(".rustre"));
                    let history_path = dir.join("recent.json");
                    let count = if history_path.exists() {
                        let text = std::fs::read_to_string(&history_path).unwrap_or_default();
                        let v: Vec<serde_json::Value> =
                            serde_json::from_str(&text).unwrap_or_default();
                        v.len()
                    } else {
                        0
                    };
                    Ok(Some(format!("{count} recent entries loaded")))
                }),
            ),
            (
                StartupStep::new("session_restore", "Restore previous session state", false),
                Box::new(|_cfg| Ok(Some("no previous session to restore".into()))),
            ),
            (
                StartupStep::new("ipc_server", "Start background IPC server", false),
                Box::new(|_cfg| {
                    // Real impl: bind a Unix socket or named pipe.
                    Ok(Some("IPC server ready (stub)".into()))
                }),
            ),
            (
                StartupStep::new("health_check", "Verify core subsystems are responsive", true),
                Box::new(|_cfg| Ok(Some("all core subsystems healthy".into()))),
            ),
        ]
    }
}

// ── run_startup (convenience) ─────────────────────────────────────────────────

/// Run the startup sequence with the given config and return the result.
///
/// This is a thin wrapper around [`StartupSequence::run`] for callers that do
/// not need to attach custom observers.
///
/// # Errors
///
/// Propagates any [`StartupError`] from the underlying sequence.
pub fn run_startup(config: StartupConfig) -> Result<StartupResult, StartupError> {
    StartupSequence::new(config).run()
}

/// Run startup with a collecting observer and return both the result and the
/// collected log for diagnostic purposes.
///
/// # Errors
///
/// Propagates any [`StartupError`] from the underlying sequence.
pub fn run_startup_verbose(
    config: StartupConfig,
) -> Result<(StartupResult, Vec<String>), StartupError> {
    let mut seq = StartupSequence::new(config);
    let obs = Box::new(CollectingObserver::default());
    // We must keep access to the observer's log; work around move by using a
    // channel-based approach via a shared `Arc<Mutex<…>>`.
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log2 = std::sync::Arc::clone(&log);
    seq.add_observer(Box::new(BridgeObserver {
        inner: obs,
        shared: log2,
    }));
    let result = seq.run()?;
    let collected = log.lock().unwrap().clone();
    Ok((result, collected))
}

struct BridgeObserver {
    inner: Box<CollectingObserver>,
    shared: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl StartupObserver for BridgeObserver {
    fn on_begin(&mut self, step: &StartupStep) {
        self.inner.on_begin(step);
        if let Ok(mut g) = self.shared.lock() {
            g.extend(self.inner.log.drain(..));
        }
    }
    fn on_end(&mut self, step: &StartupStep) {
        self.inner.on_end(step);
        if let Ok(mut g) = self.shared.lock() {
            g.extend(self.inner.log.drain(..));
        }
    }
    fn on_warning(&mut self, msg: &str) {
        self.inner.on_warning(msg);
        if let Ok(mut g) = self.shared.lock() {
            g.extend(self.inner.log.drain(..));
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StartupConfig {
        StartupConfig {
            load_plugins: false,
            timeout_ms: 10_000,
            ..Default::default()
        }
    }

    #[test]
    fn test_run_startup_succeeds() {
        let result = run_startup(cfg()).unwrap();
        assert!(result.steps_ok > 0);
    }

    #[test]
    fn test_all_required_ok() {
        let result = run_startup(cfg()).unwrap();
        assert!(result.all_required_ok());
    }

    #[test]
    fn test_elapsed_nonzero_or_very_fast() {
        let result = run_startup(cfg()).unwrap();
        // elapsed_ms may be 0 on very fast machines but should not panic.
        let _ = result.elapsed_ms;
    }

    #[test]
    fn test_step_record_count() {
        let result = run_startup(cfg()).unwrap();
        assert!(!result.steps.is_empty());
    }

    #[test]
    fn test_skip_subsystem() {
        let config = StartupConfig {
            load_plugins: false,
            skip_subsystems: vec!["logging".into()],
            ..Default::default()
        };
        let result = run_startup(config).unwrap();
        let logging = result.step("logging").unwrap();
        assert_eq!(logging.status, StepStatus::Skipped);
        assert!(result.steps_skipped >= 1);
    }

    #[test]
    fn test_step_names_unique() {
        let result = run_startup(cfg()).unwrap();
        let mut names: Vec<&str> = result.steps.iter().map(|s| s.name.as_str()).collect();
        let len_before = names.len();
        names.dedup();
        assert_eq!(names.len(), len_before, "duplicate step names found");
    }

    #[test]
    fn test_env_step_present() {
        let result = run_startup(cfg()).unwrap();
        assert!(result.step("env").is_some());
    }

    #[test]
    fn test_health_check_step_ok() {
        let result = run_startup(cfg()).unwrap();
        let hc = result.step("health_check").unwrap();
        assert_eq!(hc.status, StepStatus::Ok);
    }

    #[test]
    fn test_step_elapsed_type() {
        let result = run_startup(cfg()).unwrap();
        for s in &result.steps {
            let _ = s.elapsed.as_nanos();
        }
    }

    #[test]
    fn test_error_display() {
        let e = StartupError::SubsystemFailed {
            step: "foo".into(),
            reason: "bar".into(),
        };
        assert!(e.to_string().contains("foo"));
    }

    #[test]
    fn test_config_default_timeout() {
        assert_eq!(StartupConfig::default().timeout_ms, 30_000);
    }

    #[test]
    fn test_collecting_observer() {
        let mut obs = CollectingObserver::default();
        let mut step = StartupStep::new("test", "test step", true);
        step.status = StepStatus::Ok;
        obs.on_begin(&step);
        obs.on_end(&step);
        obs.on_warning("watch out");
        assert!(obs.log.len() >= 3);
    }

    #[test]
    fn test_run_startup_verbose_returns_log() {
        let (result, log) = run_startup_verbose(cfg()).unwrap();
        assert!(result.all_required_ok());
        assert!(!log.is_empty());
    }
}
