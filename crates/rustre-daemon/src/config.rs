//! `config` — Daemon configuration loading and CLI-override merging.
//!
//! [`DaemonFullConfig`] is the authoritative, unified configuration struct.
//! It can be:
//!
//! 1. Deserialised from a TOML or JSON file via [`DaemonFullConfig::from_toml_file`]
//!    / [`DaemonFullConfig::from_json_file`].
//! 2. Populated with default values via [`DaemonFullConfig::default`].
//! 3. Merged with CLI overrides via [`CliOverrides::apply`].
//!
//! # Example
//!
//! ```no_run
//! use rustre_daemon::config::{DaemonFullConfig, CliOverrides};
//!
//! let mut cfg = DaemonFullConfig::from_toml_file("/etc/rustre/daemon.toml")
//!     .unwrap_or_default();
//!
//! let overrides = CliOverrides {
//!     listen_addr: Some("0.0.0.0:9090".into()),
//!     log_level: Some("debug".into()),
//!     ..CliOverrides::default()
//! };
//! overrides.apply(&mut cfg);
//! cfg.validate().expect("config is valid");
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── LogLevel ──────────────────────────────────────────────────────────────────

/// Log verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogLevel {
    /// Extremely verbose; includes internal state dumps.
    Trace,
    /// Detailed developer diagnostics.
    Debug,
    /// Normal operational messages.
    #[default]
    Info,
    /// Conditions that should be investigated.
    Warn,
    /// Errors that require immediate attention.
    Error,
}


impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!("unknown log level '{other}'")),
        }
    }
}

// ── NetworkConfig ─────────────────────────────────────────────────────────────

/// Network-related configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// TCP address the daemon listens on for JSON-RPC / HTTP requests.
    pub listen_addr: String,
    /// Optional address for the MCP/SSE endpoint.
    pub mcp_addr: Option<String>,
    /// Maximum number of simultaneous connections.
    pub max_connections: u32,
    /// Optional bearer token for request authentication.
    pub auth_token: Option<String>,
    /// Connection read/write timeout in seconds.
    pub connection_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:7878".into(),
            mcp_addr: None,
            max_connections: 16,
            auth_token: None,
            connection_timeout_secs: 30,
        }
    }
}

// ── SessionConfig ─────────────────────────────────────────────────────────────

/// Session management parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum number of concurrent analysis sessions.
    pub max_sessions: usize,
    /// Seconds of inactivity before a session is auto-closed (0 = disabled).
    pub idle_timeout_secs: u64,
    /// Whether to start analysis automatically when a session is opened.
    pub auto_analyze: bool,
    /// Default analysis depth for auto-started jobs.
    pub default_deep: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            idle_timeout_secs: 3600,
            auto_analyze: true,
            default_deep: false,
        }
    }
}

// ── WorkerConfig ──────────────────────────────────────────────────────────────

/// Worker pool parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Number of analysis worker threads.
    pub threads: usize,
    /// Maximum number of pending jobs in the queue before new submissions block.
    pub max_queue_depth: usize,
    /// Default job timeout in seconds (0 = no timeout).
    pub default_job_timeout_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus(),
            max_queue_depth: 256,
            default_job_timeout_secs: 300,
        }
    }
}

/// Return a reasonable CPU count for the current platform.
fn num_cpus() -> usize {
    // std::thread::available_parallelism is stable since 1.59.
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(2)
}

// ── LoggingConfig ─────────────────────────────────────────────────────────────

/// Logging and tracing parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log verbosity level.
    pub level: LogLevel,
    /// Directory where log files are written.
    pub log_dir: PathBuf,
    /// Base filename (without extension) of the active log file.
    pub log_name: String,
    /// Whether to write structured JSON log lines.
    pub json_format: bool,
    /// Maximum size of a single log file before rotation (bytes).
    pub max_log_size: u64,
    /// Number of rotated log files to retain.
    pub max_log_files: usize,
    /// Whether to log to stdout in addition to the file.
    pub stdout: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        let log_dir = if cfg!(unix) {
            PathBuf::from("/tmp/rustre-logs")
        } else {
            std::env::temp_dir().join("rustre-logs")
        };

        Self {
            level: LogLevel::Info,
            log_dir,
            log_name: "rustre-daemon".into(),
            json_format: false,
            max_log_size: 10 * 1024 * 1024, // 10 MiB
            max_log_files: 5,
            stdout: true,
        }
    }
}

impl LoggingConfig {
    /// Return the path to the active log file.
    #[must_use]
    pub fn log_file_path(&self) -> PathBuf {
        self.log_dir.join(format!("{}.log", self.log_name))
    }
}

// ── PluginConfig ──────────────────────────────────────────────────────────────

/// Plugin loading configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Directories searched for `.so` / `.dll` plugin files.
    pub plugin_dirs: Vec<PathBuf>,
    /// Whether to load plugins automatically at startup.
    pub auto_load: bool,
    /// List of plugin names to always enable (matched by filename stem).
    pub always_enable: Vec<String>,
    /// List of plugin names to permanently disable.
    pub disabled: Vec<String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            plugin_dirs: Vec::new(),
            auto_load: true,
            always_enable: Vec::new(),
            disabled: Vec::new(),
        }
    }
}

// ── DaemonFullConfig ──────────────────────────────────────────────────────────

/// Complete daemon configuration.
///
/// Loadable from TOML / JSON files and mergeable with CLI overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct DaemonFullConfig {
    /// Network binding and connection settings.
    pub network: NetworkConfig,
    /// Session lifecycle management.
    pub session: SessionConfig,
    /// Worker pool settings.
    pub worker: WorkerConfig,
    /// Logging and tracing.
    pub logging: LoggingConfig,
    /// Plugin loading.
    pub plugin: PluginConfig,
    /// Arbitrary extension key-value pairs from the config file.
    #[serde(default)]
    pub extra: HashMap<String, String>,
}


impl DaemonFullConfig {
    /// Load configuration from a TOML file at `path`.
    ///
    /// # Errors
    /// Returns a descriptive string if the file cannot be read or parsed.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("TOML parse {}: {e}", path.display()))
    }

    /// Load configuration from a JSON file at `path`.
    ///
    /// # Errors
    /// Returns a descriptive string if the file cannot be read or parsed.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("JSON parse {}: {e}", path.display()))
    }

    /// Serialise to a TOML string.
    ///
    /// # Errors
    /// Returns a descriptive string if serialisation fails.
    pub fn to_toml_string(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| format!("TOML serialise: {e}"))
    }

    /// Serialise to a JSON string (pretty-printed).
    ///
    /// # Errors
    /// Returns a descriptive string if serialisation fails.
    pub fn to_json_string(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialise: {e}"))
    }

    /// Validate the configuration.
    ///
    /// # Errors
    /// Returns a descriptive string listing all validation failures.
    pub fn validate(&self) -> Result<(), String> {
        let mut errors: Vec<String> = Vec::new();

        // Network validation.
        if self.network.listen_addr.is_empty() {
            errors.push("network.listen_addr must not be empty".into());
        }
        if self.network.max_connections == 0 {
            errors.push("network.max_connections must be > 0".into());
        }
        if self.network.connection_timeout_secs == 0 {
            errors.push("network.connection_timeout_secs must be > 0".into());
        }

        // Session validation.
        if self.session.max_sessions == 0 {
            errors.push("session.max_sessions must be > 0".into());
        }

        // Worker validation.
        if self.worker.threads == 0 {
            errors.push("worker.threads must be > 0".into());
        }
        if self.worker.max_queue_depth == 0 {
            errors.push("worker.max_queue_depth must be > 0".into());
        }

        // Logging validation.
        if self.logging.max_log_size == 0 {
            errors.push("logging.max_log_size must be > 0".into());
        }
        if self.logging.max_log_files == 0 {
            errors.push("logging.max_log_files must be > 0".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Return the listen address as a `SocketAddr`.
    ///
    /// # Errors
    /// Returns a string if the address cannot be parsed.
    pub fn socket_addr(&self) -> Result<std::net::SocketAddr, String> {
        self.network
            .listen_addr
            .parse()
            .map_err(|e| format!("invalid listen_addr '{}': {e}", self.network.listen_addr))
    }
}

// ── CliOverrides ──────────────────────────────────────────────────────────────

/// Command-line argument overrides.
///
/// Any `Some(_)` field in this struct supersedes the corresponding field in
/// [`DaemonFullConfig`] when [`CliOverrides::apply`] is called.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliOverrides {
    /// Override `network.listen_addr`.
    pub listen_addr: Option<String>,
    /// Override `network.mcp_addr`.
    pub mcp_addr: Option<String>,
    /// Override `network.max_connections`.
    pub max_connections: Option<u32>,
    /// Override `network.auth_token`.
    pub auth_token: Option<String>,
    /// Override `session.max_sessions`.
    pub max_sessions: Option<usize>,
    /// Override `session.auto_analyze`.
    pub auto_analyze: Option<bool>,
    /// Override `worker.threads`.
    pub worker_threads: Option<usize>,
    /// Override `logging.level`.
    pub log_level: Option<String>,
    /// Override `logging.log_dir`.
    pub log_dir: Option<PathBuf>,
    /// Override `logging.stdout`.
    pub log_stdout: Option<bool>,
    /// Extra plugin directories to append.
    pub plugin_dirs: Vec<PathBuf>,
}

impl CliOverrides {
    /// Apply all `Some(_)` overrides onto `config` in place.
    pub fn apply(&self, config: &mut DaemonFullConfig) {
        if let Some(ref v) = self.listen_addr {
            config.network.listen_addr.clone_from(v);
        }
        if let Some(ref v) = self.mcp_addr {
            config.network.mcp_addr = Some(v.clone());
        }
        if let Some(v) = self.max_connections {
            config.network.max_connections = v;
        }
        if let Some(ref v) = self.auth_token {
            config.network.auth_token = Some(v.clone());
        }
        if let Some(v) = self.max_sessions {
            config.session.max_sessions = v;
        }
        if let Some(v) = self.auto_analyze {
            config.session.auto_analyze = v;
        }
        if let Some(v) = self.worker_threads {
            config.worker.threads = v;
        }
        if let Some(ref level_str) = self.log_level
            && let Ok(level) = level_str.parse::<LogLevel>() {
                config.logging.level = level;
            }
        if let Some(ref d) = self.log_dir {
            config.logging.log_dir.clone_from(d);
        }
        if let Some(v) = self.log_stdout {
            config.logging.stdout = v;
        }
        for dir in &self.plugin_dirs {
            if !config.plugin.plugin_dirs.contains(dir) {
                config.plugin.plugin_dirs.push(dir.clone());
            }
        }
    }
}

// ── Config loader ─────────────────────────────────────────────────────────────

/// Search for a config file in standard locations, parse it, apply overrides,
/// and return the final [`DaemonFullConfig`].
///
/// Search order (first found wins):
/// 1. `explicit_path` argument (if `Some`).
/// 2. `$RUSTRE_CONFIG` environment variable.
/// 3. `~/.rustre/daemon.toml`
/// 4. `~/.rustre/daemon.json`
/// 5. `/etc/rustre/daemon.toml` (Unix only).
/// 6. Built-in defaults.
///
/// CLI `overrides` are always applied last.
#[must_use]
pub fn load_config(explicit_path: Option<&Path>, overrides: &CliOverrides) -> DaemonFullConfig {
    let mut cfg = try_load_config(explicit_path).unwrap_or_default();
    overrides.apply(&mut cfg);
    cfg
}

fn try_load_config(explicit_path: Option<&Path>) -> Option<DaemonFullConfig> {
    // 1. Explicit path.
    if let Some(p) = explicit_path {
        return load_by_extension(p);
    }

    // 2. Environment variable.
    if let Ok(env_path) = std::env::var("RUSTRE_CONFIG") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return load_by_extension(&p);
        }
    }

    // 3–4. Home directory.
    if let Some(home) = home_dir() {
        let toml_path = home.join(".rustre").join("daemon.toml");
        if toml_path.exists() {
            return DaemonFullConfig::from_toml_file(&toml_path).ok();
        }
        let json_path = home.join(".rustre").join("daemon.json");
        if json_path.exists() {
            return DaemonFullConfig::from_json_file(&json_path).ok();
        }
    }

    // 5. System-wide (Unix).
    #[cfg(unix)]
    {
        let sys = PathBuf::from("/etc/rustre/daemon.toml");
        if sys.exists() {
            return DaemonFullConfig::from_toml_file(&sys).ok();
        }
    }

    None
}

fn load_by_extension(path: &Path) -> Option<DaemonFullConfig> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => DaemonFullConfig::from_toml_file(path).ok(),
        Some("json") => DaemonFullConfig::from_json_file(path).ok(),
        _ => {
            // Try TOML first, then JSON.
            DaemonFullConfig::from_toml_file(path)
                .or_else(|_| DaemonFullConfig::from_json_file(path))
                .ok()
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp(content: &str, ext: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{ext}"))
            .tempfile()
            .expect("tempfile");
        f.write_all(content.as_bytes()).expect("write tempfile");
        f
    }

    // ── LogLevel ──────────────────────────────────────────────────────────────

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("WARNING".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert!("bogus".parse::<LogLevel>().is_err());
    }

    // ── DaemonFullConfig defaults ─────────────────────────────────────────────

    #[test]
    fn test_default_config_validates() {
        let cfg = DaemonFullConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_default_listen_addr() {
        let cfg = DaemonFullConfig::default();
        assert_eq!(cfg.network.listen_addr, "127.0.0.1:7878");
    }

    #[test]
    fn test_default_max_sessions() {
        let cfg = DaemonFullConfig::default();
        assert_eq!(cfg.session.max_sessions, 8);
    }

    // ── Validation ────────────────────────────────────────────────────────────

    #[test]
    fn test_validation_zero_max_connections() {
        let mut cfg = DaemonFullConfig::default();
        cfg.network.max_connections = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_zero_sessions() {
        let mut cfg = DaemonFullConfig::default();
        cfg.session.max_sessions = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_zero_workers() {
        let mut cfg = DaemonFullConfig::default();
        cfg.worker.threads = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_empty_listen_addr() {
        let mut cfg = DaemonFullConfig::default();
        cfg.network.listen_addr = String::new();
        assert!(cfg.validate().is_err());
    }

    // ── JSON round-trip ───────────────────────────────────────────────────────

    #[test]
    fn test_json_roundtrip() {
        let orig = DaemonFullConfig::default();
        let json = orig.to_json_string().unwrap();
        let restored: DaemonFullConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.network.listen_addr, orig.network.listen_addr);
        assert_eq!(restored.session.max_sessions, orig.session.max_sessions);
        assert_eq!(restored.worker.threads, orig.worker.threads);
    }

    // ── TOML round-trip ───────────────────────────────────────────────────────

    #[test]
    fn test_toml_roundtrip() {
        let orig = DaemonFullConfig::default();
        let toml_str = orig.to_toml_string().unwrap();
        let restored: DaemonFullConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.network.listen_addr, orig.network.listen_addr);
        assert_eq!(restored.logging.level, orig.logging.level);
    }

    // ── File loading ──────────────────────────────────────────────────────────

    #[test]
    fn test_from_json_file() {
        let cfg = DaemonFullConfig {
            network: NetworkConfig {
                listen_addr: "0.0.0.0:9999".into(),
                max_connections: 32,
                ..NetworkConfig::default()
            },
            ..DaemonFullConfig::default()
        };
        let json = cfg.to_json_string().unwrap();
        let f = write_temp(&json, "json");
        let loaded = DaemonFullConfig::from_json_file(f.path()).unwrap();
        assert_eq!(loaded.network.listen_addr, "0.0.0.0:9999");
        assert_eq!(loaded.network.max_connections, 32);
    }

    #[test]
    fn test_from_toml_file() {
        let cfg = DaemonFullConfig::default();
        let toml_str = cfg.to_toml_string().unwrap();
        let f = write_temp(&toml_str, "toml");
        let loaded = DaemonFullConfig::from_toml_file(f.path()).unwrap();
        assert_eq!(loaded.network.listen_addr, cfg.network.listen_addr);
    }

    #[test]
    fn test_from_missing_file_err() {
        let err = DaemonFullConfig::from_toml_file("/nonexistent/path/daemon.toml");
        assert!(err.is_err());
    }

    // ── CliOverrides ──────────────────────────────────────────────────────────

    #[test]
    fn test_cli_overrides_apply() {
        let mut cfg = DaemonFullConfig::default();
        let overrides = CliOverrides {
            listen_addr: Some("0.0.0.0:8080".into()),
            log_level: Some("debug".into()),
            max_sessions: Some(4),
            worker_threads: Some(2),
            ..CliOverrides::default()
        };
        overrides.apply(&mut cfg);
        assert_eq!(cfg.network.listen_addr, "0.0.0.0:8080");
        assert_eq!(cfg.logging.level, LogLevel::Debug);
        assert_eq!(cfg.session.max_sessions, 4);
        assert_eq!(cfg.worker.threads, 2);
    }

    #[test]
    fn test_cli_overrides_none_no_change() {
        let orig = DaemonFullConfig::default();
        let mut cfg = orig.clone();
        CliOverrides::default().apply(&mut cfg);
        assert_eq!(cfg.network.listen_addr, orig.network.listen_addr);
    }

    #[test]
    fn test_cli_overrides_plugin_dirs_dedup() {
        let mut cfg = DaemonFullConfig::default();
        let dir = PathBuf::from("/plugins");
        let overrides = CliOverrides {
            plugin_dirs: vec![dir],
            ..CliOverrides::default()
        };
        overrides.apply(&mut cfg);
        overrides.apply(&mut cfg); // apply twice
        assert_eq!(cfg.plugin.plugin_dirs.len(), 1); // no duplicates
    }

    #[test]
    fn test_cli_overrides_invalid_log_level_ignored() {
        let mut cfg = DaemonFullConfig::default();
        let orig_level = cfg.logging.level;
        let overrides = CliOverrides {
            log_level: Some("BOGUS_LEVEL".into()),
            ..CliOverrides::default()
        };
        overrides.apply(&mut cfg);
        assert_eq!(cfg.logging.level, orig_level); // unchanged
    }

    // ── socket_addr ───────────────────────────────────────────────────────────

    #[test]
    fn test_socket_addr_valid() {
        let cfg = DaemonFullConfig::default();
        let addr = cfg.socket_addr().unwrap();
        assert_eq!(addr.port(), 7878);
    }

    #[test]
    fn test_socket_addr_invalid() {
        let mut cfg = DaemonFullConfig::default();
        cfg.network.listen_addr = "not-a-socket-addr".into();
        assert!(cfg.socket_addr().is_err());
    }

    // ── load_config ───────────────────────────────────────────────────────────

    #[test]
    fn test_load_config_falls_back_to_defaults() {
        // Pass a non-existent explicit path; should fall back to defaults.
        let cfg = load_config(None, &CliOverrides::default());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_load_config_with_json_file() {
        let cfg_orig = DaemonFullConfig {
            network: NetworkConfig {
                listen_addr: "127.0.0.1:19191".into(),
                ..NetworkConfig::default()
            },
            ..DaemonFullConfig::default()
        };
        let json = cfg_orig.to_json_string().unwrap();
        let f = write_temp(&json, "json");
        let cfg = load_config(Some(f.path()), &CliOverrides::default());
        assert_eq!(cfg.network.listen_addr, "127.0.0.1:19191");
    }

    // ── LoggingConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_logging_config_log_file_path() {
        let lc = LoggingConfig {
            log_dir: PathBuf::from("/var/log"),
            log_name: "test".into(),
            ..LoggingConfig::default()
        };
        assert_eq!(lc.log_file_path(), PathBuf::from("/var/log/test.log"));
    }
}
