//! `daemon_config` — Daemon configuration loader, validator, and merger.
//!
//! Provides [`DaemonConfig`] with sub-configs for listening, logging, analysis,
//! and plugins. Supports JSON/TOML-like parsing from plain key=value text files,
//! full validation, and merging with built-in defaults.

use std::collections::HashMap;
use std::fmt;
use std::fs;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can arise while loading or validating daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// An I/O failure when reading the config file.
    IoError(String),
    /// The config file contained invalid syntax.
    ParseError(String),
    /// A field value did not satisfy its constraints.
    ValidationError(String),
    /// A required field was absent.
    MissingField(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError(s) => write!(f, "I/O error: {s}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::ValidationError(s) => write!(f, "validation error: {s}"),
            Self::MissingField(s) => write!(f, "missing required field: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ── LogLevel ──────────────────────────────────────────────────────────────────

/// Verbosity level for daemon logging.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Extremely detailed tracing output.
    Trace,
    /// Developer-facing debug messages.
    Debug,
    /// Informational messages about normal operation.
    Info,
    /// Conditions that are unexpected but recoverable.
    Warn,
    /// Fatal or near-fatal conditions.
    Error,
}

impl LogLevel {
    /// Parse a case-insensitive string into a [`LogLevel`].
    ///
    /// # Errors
    /// Returns `Err` when the string does not match any known level.
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" | "err" => Ok(Self::Error),
            other => Err(ConfigError::ParseError(format!("unknown log level: {other}"))),
        }
    }

    /// Return the canonical lower-case string for this level.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── LogOutput ─────────────────────────────────────────────────────────────────

/// Where log lines are written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutput {
    /// Write to standard output.
    Stdout,
    /// Append to the named file.
    File(String),
    /// Forward to the system logger (syslog / Event Log).
    Syslog,
}

impl LogOutput {
    /// Parse a string representation of a log output destination.
    ///
    /// Accepts `"stdout"`, `"syslog"`, or `"file:<path>"`.
    ///
    /// # Errors
    /// Returns `Err` when the string cannot be parsed.
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s {
            "stdout" => Ok(Self::Stdout),
            "syslog" => Ok(Self::Syslog),
            other if other.starts_with("file:") => {
                let path = other.trim_start_matches("file:").to_owned();
                if path.is_empty() {
                    Err(ConfigError::ParseError("file output path is empty".into()))
                } else {
                    Ok(Self::File(path))
                }
            }
            other => Err(ConfigError::ParseError(format!("unknown log output: {other}"))),
        }
    }

    /// Return a serialisable string representation.
    #[must_use]
    pub fn to_config_string(&self) -> String {
        match self {
            Self::Stdout => "stdout".into(),
            Self::Syslog => "syslog".into(),
            Self::File(p) => format!("file:{p}"),
        }
    }
}

// ── ListenConfig ─────────────────────────────────────────────────────────────

/// Network / socket listening parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenConfig {
    /// TCP bind address.
    pub host: String,
    /// TCP port number.
    pub port: u16,
    /// Optional UNIX-domain socket path (ignored on non-Unix platforms).
    pub unix_socket: Option<String>,
    /// Maximum number of simultaneously accepted connections.
    pub max_connections: u32,
}

impl ListenConfig {
    /// Return a `host:port` string suitable for `TcpListener::bind`.
    #[must_use]
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Validate the listen config, returning a list of error messages.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.host.is_empty() {
            errors.push("listen.host must not be empty".into());
        }
        if self.port == 0 {
            errors.push("listen.port must be > 0".into());
        }
        if self.max_connections == 0 {
            errors.push("listen.max_connections must be > 0".into());
        }
        if let Some(sock) = &self.unix_socket {
            if sock.is_empty() {
                errors.push("listen.unix_socket must not be an empty string if set".into());
            }
        }
        errors
    }
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 9000,
            unix_socket: None,
            max_connections: 64,
        }
    }
}

// ── LoggingConfig ─────────────────────────────────────────────────────────────

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    /// Minimum level to emit.
    pub level: LogLevel,
    /// Where messages go.
    pub output: LogOutput,
}

impl LoggingConfig {
    /// Validate the logging config.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if let LogOutput::File(path) = &self.output {
            if path.is_empty() {
                errors.push("logging.output file path is empty".into());
            }
        }
        errors
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            output: LogOutput::Stdout,
        }
    }
}

// ── AnalysisConfig ────────────────────────────────────────────────────────────

/// Parameters controlling background analysis behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisConfig {
    /// How long a single analysis job may run before being cancelled (ms).
    pub default_timeout_ms: u64,
    /// Maximum number of analysis sessions alive at once.
    pub max_concurrent_sessions: u32,
    /// Directory for temporary files produced during analysis.
    pub temp_dir: String,
    /// Directory to search for analysis plug-ins.
    pub plugins_dir: String,
    /// Whether newly loaded binaries should be analyzed automatically.
    pub auto_analyze: bool,
}

impl AnalysisConfig {
    /// Validate the analysis config.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.default_timeout_ms == 0 {
            errors.push("analysis.default_timeout_ms must be > 0".into());
        }
        if self.max_concurrent_sessions == 0 {
            errors.push("analysis.max_concurrent_sessions must be > 0".into());
        }
        if self.temp_dir.is_empty() {
            errors.push("analysis.temp_dir must not be empty".into());
        }
        if self.plugins_dir.is_empty() {
            errors.push("analysis.plugins_dir must not be empty".into());
        }
        errors
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30_000,
            max_concurrent_sessions: 8,
            temp_dir: std::env::temp_dir()
                .to_string_lossy()
                .into_owned(),
            plugins_dir: "./plugins".into(),
            auto_analyze: false,
        }
    }
}

// ── PluginConfig ──────────────────────────────────────────────────────────────

/// Plug-in loading configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginConfig {
    /// Plug-in names (or glob patterns) that should be loaded.
    pub enabled: Vec<String>,
    /// Plug-in names that must never be loaded, even if listed in `enabled`.
    pub disabled: Vec<String>,
    /// Additional directories to search for plug-in shared objects / DLLs.
    pub plugin_dirs: Vec<String>,
}

impl PluginConfig {
    /// Returns `true` if a plug-in with the given name should be loaded,
    /// i.e. it appears in `enabled` and is not in `disabled`.
    #[must_use]
    pub fn should_load(&self, name: &str) -> bool {
        if self.disabled.iter().any(|d| d == name) {
            return false;
        }
        self.enabled.iter().any(|e| e == name || e == "*")
    }

    /// Validate the plugin config.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for dir in &self.plugin_dirs {
            if dir.is_empty() {
                errors.push("plugin_dirs must not contain empty strings".into());
            }
        }
        errors
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: vec!["*".into()],
            disabled: Vec::new(),
            plugin_dirs: vec!["./plugins".into()],
        }
    }
}

// ── DaemonConfig ─────────────────────────────────────────────────────────────

/// Top-level daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Network / socket listening parameters.
    pub listen: ListenConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
    /// Analysis job parameters.
    pub analysis: AnalysisConfig,
    /// Plug-in loading configuration.
    pub plugins: PluginConfig,
    /// Arbitrary extension values not covered by the strongly-typed fields.
    pub extra: HashMap<String, String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::default(),
            logging: LoggingConfig::default(),
            analysis: AnalysisConfig::default(),
            plugins: PluginConfig::default(),
            extra: HashMap::new(),
        }
    }
}

impl DaemonConfig {
    /// Create a new `DaemonConfig` pre-populated with all default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a list of validation error messages, empty on success.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        errors.extend(self.listen.validate());
        errors.extend(self.logging.validate());
        errors.extend(self.analysis.validate());
        errors.extend(self.plugins.validate());
        errors
    }

    /// Merge `other` on top of `self`, overwriting only fields that differ
    /// from `other`'s own defaults.  Fields in `self` that are already
    /// non-default are preserved unless `other` explicitly overrides them.
    pub fn merge_with_defaults(&mut self, other: &DaemonConfig) {
        let default = DaemonConfig::default();

        // listen
        if other.listen.host != default.listen.host {
            self.listen.host.clone_from(&other.listen.host);
        }
        if other.listen.port != default.listen.port {
            self.listen.port = other.listen.port;
        }
        if other.listen.unix_socket != default.listen.unix_socket {
            self.listen.unix_socket.clone_from(&other.listen.unix_socket);
        }
        if other.listen.max_connections != default.listen.max_connections {
            self.listen.max_connections = other.listen.max_connections;
        }

        // logging
        if other.logging.level != default.logging.level {
            self.logging.level = other.logging.level.clone();
        }
        if other.logging.output != default.logging.output {
            self.logging.output = other.logging.output.clone();
        }

        // analysis
        if other.analysis.default_timeout_ms != default.analysis.default_timeout_ms {
            self.analysis.default_timeout_ms = other.analysis.default_timeout_ms;
        }
        if other.analysis.max_concurrent_sessions != default.analysis.max_concurrent_sessions {
            self.analysis.max_concurrent_sessions = other.analysis.max_concurrent_sessions;
        }
        if other.analysis.temp_dir != default.analysis.temp_dir {
            self.analysis.temp_dir.clone_from(&other.analysis.temp_dir);
        }
        if other.analysis.plugins_dir != default.analysis.plugins_dir {
            self.analysis.plugins_dir.clone_from(&other.analysis.plugins_dir);
        }
        if other.analysis.auto_analyze != default.analysis.auto_analyze {
            self.analysis.auto_analyze = other.analysis.auto_analyze;
        }

        // plugins
        if other.plugins.enabled != default.plugins.enabled {
            self.plugins.enabled.clone_from(&other.plugins.enabled);
        }
        if other.plugins.disabled != default.plugins.disabled {
            self.plugins.disabled.clone_from(&other.plugins.disabled);
        }
        if other.plugins.plugin_dirs != default.plugins.plugin_dirs {
            self.plugins.plugin_dirs.clone_from(&other.plugins.plugin_dirs);
        }

        // extra: merge all keys
        for (k, v) in &other.extra {
            self.extra.insert(k.clone(), v.clone());
        }
    }

    /// Produce a simple `key = value` text representation of this config.
    #[must_use]
    pub fn to_config_text(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("[listen]"));
        lines.push(format!("host = {}", self.listen.host));
        lines.push(format!("port = {}", self.listen.port));
        if let Some(sock) = &self.listen.unix_socket {
            lines.push(format!("unix_socket = {sock}"));
        }
        lines.push(format!("max_connections = {}", self.listen.max_connections));
        lines.push(String::new());
        lines.push(format!("[logging]"));
        lines.push(format!("level = {}", self.logging.level));
        lines.push(format!("output = {}", self.logging.output.to_config_string()));
        lines.push(String::new());
        lines.push(format!("[analysis]"));
        lines.push(format!("default_timeout_ms = {}", self.analysis.default_timeout_ms));
        lines.push(format!(
            "max_concurrent_sessions = {}",
            self.analysis.max_concurrent_sessions
        ));
        lines.push(format!("temp_dir = {}", self.analysis.temp_dir));
        lines.push(format!("plugins_dir = {}", self.analysis.plugins_dir));
        lines.push(format!("auto_analyze = {}", self.analysis.auto_analyze));
        lines.push(String::new());
        lines.push(format!("[plugins]"));
        lines.push(format!("enabled = {}", self.plugins.enabled.join(",")));
        lines.push(format!("disabled = {}", self.plugins.disabled.join(",")));
        lines.push(format!("plugin_dirs = {}", self.plugins.plugin_dirs.join(",")));
        for (k, v) in &self.extra {
            lines.push(format!("{k} = {v}"));
        }
        lines.join("\n")
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Internal section state used while parsing a config file.
#[derive(Debug, PartialEq, Eq)]
enum Section {
    None,
    Listen,
    Logging,
    Analysis,
    Plugins,
    Extra,
}

/// Parse a `[section]\nkey = value` config file from a string.
///
/// Lines beginning with `#` or `;` are treated as comments.
/// Unknown sections are collected into `extra`.
///
/// # Errors
/// Returns `ConfigError::ParseError` for syntactically invalid lines, or
/// `ConfigError::ValidationError` for invalid field values.
pub fn parse_config_str(input: &str) -> Result<DaemonConfig, ConfigError> {
    let mut cfg = DaemonConfig::default();
    let mut section = Section::None;

    for (lineno, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Section header
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(ConfigError::ParseError(format!(
                    "line {}: malformed section header: {line}",
                    lineno + 1
                )));
            }
            let name = &line[1..line.len() - 1];
            section = match name {
                "listen" => Section::Listen,
                "logging" => Section::Logging,
                "analysis" => Section::Analysis,
                "plugins" => Section::Plugins,
                _ => Section::Extra,
            };
            continue;
        }
        // Key = value
        let (key, val) = split_kv(line, lineno)?;
        match section {
            Section::Listen => apply_listen(&mut cfg.listen, key, val, lineno)?,
            Section::Logging => apply_logging(&mut cfg.logging, key, val, lineno)?,
            Section::Analysis => apply_analysis(&mut cfg.analysis, key, val, lineno)?,
            Section::Plugins => apply_plugins(&mut cfg.plugins, key, val, lineno)?,
            Section::None | Section::Extra => {
                cfg.extra.insert(key.to_owned(), val.to_owned());
            }
        }
    }
    Ok(cfg)
}

/// Parse a config file at `path`.
///
/// # Errors
/// Returns `ConfigError::IoError` if the file cannot be read, or any parse
/// error from [`parse_config_str`].
pub fn parse_config_file(path: &str) -> Result<DaemonConfig, ConfigError> {
    let content = fs::read_to_string(path)
        .map_err(|e| ConfigError::IoError(format!("{path}: {e}")))?;
    parse_config_str(&content)
}

// helpers

fn split_kv<'a>(line: &'a str, lineno: usize) -> Result<(&'a str, &'a str), ConfigError> {
    let eq = line.find('=').ok_or_else(|| {
        ConfigError::ParseError(format!(
            "line {}: expected 'key = value', got: {line}",
            lineno + 1
        ))
    })?;
    let key = line[..eq].trim();
    let val = line[eq + 1..].trim();
    Ok((key, val))
}

fn apply_listen(cfg: &mut ListenConfig, key: &str, val: &str, lineno: usize) -> Result<(), ConfigError> {
    match key {
        "host" => cfg.host = val.to_owned(),
        "port" => {
            cfg.port = val.parse::<u16>().map_err(|_| {
                ConfigError::ValidationError(format!("line {}: port must be 1-65535", lineno + 1))
            })?;
        }
        "unix_socket" => cfg.unix_socket = Some(val.to_owned()),
        "max_connections" => {
            cfg.max_connections = val.parse::<u32>().map_err(|_| {
                ConfigError::ValidationError(format!(
                    "line {}: max_connections must be a positive integer",
                    lineno + 1
                ))
            })?;
        }
        _ => {} // tolerate unknown keys
    }
    Ok(())
}

fn apply_logging(cfg: &mut LoggingConfig, key: &str, val: &str, _lineno: usize) -> Result<(), ConfigError> {
    match key {
        "level" => cfg.level = LogLevel::from_str(val)?,
        "output" => cfg.output = LogOutput::from_str(val)?,
        _ => {}
    }
    Ok(())
}

fn apply_analysis(cfg: &mut AnalysisConfig, key: &str, val: &str, lineno: usize) -> Result<(), ConfigError> {
    match key {
        "default_timeout_ms" => {
            cfg.default_timeout_ms = val.parse::<u64>().map_err(|_| {
                ConfigError::ValidationError(format!(
                    "line {}: default_timeout_ms must be a positive integer",
                    lineno + 1
                ))
            })?;
        }
        "max_concurrent_sessions" => {
            cfg.max_concurrent_sessions = val.parse::<u32>().map_err(|_| {
                ConfigError::ValidationError(format!(
                    "line {}: max_concurrent_sessions must be a positive integer",
                    lineno + 1
                ))
            })?;
        }
        "temp_dir" => cfg.temp_dir = val.to_owned(),
        "plugins_dir" => cfg.plugins_dir = val.to_owned(),
        "auto_analyze" => {
            cfg.auto_analyze = match val.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                _ => {
                    return Err(ConfigError::ValidationError(format!(
                        "line {}: auto_analyze must be true/false",
                        lineno + 1
                    )))
                }
            };
        }
        _ => {}
    }
    Ok(())
}

fn apply_plugins(cfg: &mut PluginConfig, key: &str, val: &str, _lineno: usize) -> Result<(), ConfigError> {
    match key {
        "enabled" => {
            cfg.enabled = val.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        }
        "disabled" => {
            cfg.disabled = val.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        }
        "plugin_dirs" => {
            cfg.plugin_dirs = val.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        }
        _ => {}
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> &'static str {
        r#"
[listen]
host = 0.0.0.0
port = 9500
max_connections = 128

[logging]
level = debug
output = file:/tmp/daemon.log

[analysis]
default_timeout_ms = 60000
max_concurrent_sessions = 4
temp_dir = /tmp/rustre
plugins_dir = /opt/rustre/plugins
auto_analyze = true

[plugins]
enabled = core,disasm
disabled = experimental
plugin_dirs = /opt/rustre/plugins,/usr/lib/rustre
"#
    }

    #[test]
    fn test_parse_config_str_listen_host() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.listen.host, "0.0.0.0");
    }

    #[test]
    fn test_parse_config_str_listen_port() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.listen.port, 9500);
    }

    #[test]
    fn test_parse_config_str_max_connections() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.listen.max_connections, 128);
    }

    #[test]
    fn test_parse_config_str_log_level() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.logging.level, LogLevel::Debug);
    }

    #[test]
    fn test_parse_config_str_log_output_file() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.logging.output, LogOutput::File("/tmp/daemon.log".into()));
    }

    #[test]
    fn test_parse_config_str_analysis_timeout() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.analysis.default_timeout_ms, 60_000);
    }

    #[test]
    fn test_parse_config_str_analysis_sessions() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.analysis.max_concurrent_sessions, 4);
    }

    #[test]
    fn test_parse_config_str_auto_analyze() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert!(cfg.analysis.auto_analyze);
    }

    #[test]
    fn test_parse_config_str_plugins_enabled() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.plugins.enabled, vec!["core".to_owned(), "disasm".to_owned()]);
    }

    #[test]
    fn test_parse_config_str_plugins_disabled() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.plugins.disabled, vec!["experimental".to_owned()]);
    }

    #[test]
    fn test_parse_config_str_plugin_dirs() {
        let cfg = parse_config_str(sample_config()).unwrap();
        assert_eq!(cfg.plugins.plugin_dirs.len(), 2);
    }

    #[test]
    fn test_default_config_validates() {
        let cfg = DaemonConfig::default();
        let errors = cfg.validate();
        assert!(errors.is_empty(), "default config should be valid: {errors:?}");
    }

    #[test]
    fn test_validate_empty_host() {
        let mut cfg = DaemonConfig::default();
        cfg.listen.host = String::new();
        let errors = cfg.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("host")));
    }

    #[test]
    fn test_validate_zero_port() {
        let mut cfg = DaemonConfig::default();
        cfg.listen.port = 0;
        let errors = cfg.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("port")));
    }

    #[test]
    fn test_validate_zero_timeout() {
        let mut cfg = DaemonConfig::default();
        cfg.analysis.default_timeout_ms = 0;
        let errors = cfg.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("timeout")));
    }

    #[test]
    fn test_parse_error_bad_section() {
        let result = parse_config_str("[unclosed\nkey = val\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_no_equals() {
        let result = parse_config_str("[listen]\nhostname\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_overrides_port() {
        let mut base = DaemonConfig::default();
        let mut overlay = DaemonConfig::default();
        overlay.listen.port = 12345;
        base.merge_with_defaults(&overlay);
        assert_eq!(base.listen.port, 12345);
    }

    #[test]
    fn test_merge_preserves_existing_host() {
        let mut base = DaemonConfig::default();
        base.listen.host = "10.0.0.1".into();
        // overlay leaves host at default → should NOT overwrite base
        let overlay = DaemonConfig::default();
        base.merge_with_defaults(&overlay);
        assert_eq!(base.listen.host, "10.0.0.1");
    }

    #[test]
    fn test_merge_extra_keys() {
        let mut base = DaemonConfig::default();
        let mut overlay = DaemonConfig::default();
        overlay.extra.insert("custom_key".into(), "custom_value".into());
        base.merge_with_defaults(&overlay);
        assert_eq!(base.extra.get("custom_key").map(|s| s.as_str()), Some("custom_value"));
    }

    #[test]
    fn test_to_config_text_roundtrip_port() {
        let mut cfg = DaemonConfig::default();
        cfg.listen.port = 7777;
        let text = cfg.to_config_text();
        let parsed = parse_config_str(&text).unwrap();
        assert_eq!(parsed.listen.port, 7777);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_output_roundtrip() {
        let o = LogOutput::File("/var/log/rustre.log".into());
        let s = o.to_config_string();
        let o2 = LogOutput::from_str(&s).unwrap();
        assert_eq!(o, o2);
    }

    #[test]
    fn test_plugin_should_load_wildcard() {
        let cfg = PluginConfig::default(); // enabled = ["*"]
        assert!(cfg.should_load("anything"));
    }

    #[test]
    fn test_plugin_should_not_load_disabled() {
        let mut cfg = PluginConfig::default();
        cfg.disabled.push("bad_plugin".into());
        assert!(!cfg.should_load("bad_plugin"));
    }

    #[test]
    fn test_listen_bind_addr() {
        let cfg = ListenConfig {
            host: "192.168.1.1".into(),
            port: 8080,
            unix_socket: None,
            max_connections: 32,
        };
        assert_eq!(cfg.bind_addr(), "192.168.1.1:8080");
    }

    #[test]
    fn test_analysis_config_temp_dir_default_non_empty() {
        let cfg = AnalysisConfig::default();
        assert!(!cfg.temp_dir.is_empty());
    }

    #[test]
    fn test_comments_are_ignored() {
        let cfg = parse_config_str("[listen]\n# comment line\n; another comment\nport = 1234\n").unwrap();
        assert_eq!(cfg.listen.port, 1234);
    }

    #[test]
    fn test_unix_socket_parsed() {
        let cfg = parse_config_str("[listen]\nunix_socket = /tmp/rustre.sock\n").unwrap();
        assert_eq!(cfg.listen.unix_socket.as_deref(), Some("/tmp/rustre.sock"));
    }
}
