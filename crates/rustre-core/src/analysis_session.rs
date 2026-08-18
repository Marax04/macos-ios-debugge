//! Complete analysis session management for RustRE.
//!
//! Provides [`AnalysisSession`] as the root type, with
//! [`SessionState`], [`SessionConfig`], [`SessionLog`],
//! [`SessionExport`], and [`SessionRestore`] as supporting types.


use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Re-export of [`std::time::Instant`] for callers that want to take wall-clock
/// measurements against session timestamps without importing `std::time`.
pub use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("session '{0}' already exists")]
    AlreadyExists(String),

    #[error("session '{0}' not found")]
    NotFound(String),

    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: SessionState,
        to: SessionState,
    },

    #[error("session is locked")]
    Locked,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("export failed: {0}")]
    ExportFailed(String),

    #[error("restore failed: {0}")]
    RestoreFailed(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type SessionResult<T> = std::result::Result<T, SessionError>;

// ── SessionState ──────────────────────────────────────────────────────────────

/// Lifecycle state of an analysis session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created but not yet started.
    Created,
    /// Session actively running analysis.
    Running,
    /// Session paused mid-analysis.
    Paused,
    /// Analysis complete.
    Completed,
    /// Session terminated with an error.
    Failed,
    /// Session cancelled by user.
    Cancelled,
}

impl SessionState {
    /// Returns `true` if the session can be started.
    #[must_use]
    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Created | Self::Paused)
    }

    /// Returns `true` if the session can be paused.
    #[must_use]
    pub fn can_pause(&self) -> bool {
        *self == Self::Running
    }

    /// Returns `true` if the session is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Valid state transitions.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub const fn transition_to(&self, next: Self) -> SessionResult<Self> {
        use SessionState::{Cancelled, Completed, Created, Failed, Paused, Running};
        let ok = matches!(
            (self, &next),
            (Created | Paused, Running)
                | (Running, Paused | Completed | Failed | Cancelled)
                | (Paused, Cancelled)
        );
        if ok {
            Ok(next)
        } else {
            Err(SessionError::InvalidTransition {
                from: *self,
                to: next,
            })
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ── SessionConfig ─────────────────────────────────────────────────────────────

/// Configuration for an analysis session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum wall-clock duration for the session.
    pub timeout_secs: Option<u64>,
    /// Maximum number of log entries to keep in memory.
    pub max_log_entries: usize,
    /// Whether to persist the session to disk automatically.
    pub auto_persist: bool,
    /// Path to persist the session (if `auto_persist`).
    pub persist_dir: Option<PathBuf>,
    /// Arbitrary user-defined settings.
    pub settings: HashMap<String, serde_json::Value>,
    /// Number of parallel analysis workers.
    pub parallelism: usize,
    /// Log level: "debug", "info", "warn", "error".
    pub log_level: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_secs: None,
            max_log_entries: 10_000,
            auto_persist: false,
            persist_dir: None,
            settings: HashMap::new(),
            parallelism: 1,
            log_level: "info".into(),
        }
    }
}

impl SessionConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    #[must_use]
    pub fn with_parallelism(mut self, n: usize) -> Self {
        self.parallelism = n.max(1);
        self
    }

    #[must_use]
    pub fn with_persist_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.persist_dir = Some(dir.into());
        self.auto_persist = true;
        self
    }

    pub fn set_setting(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.settings.insert(key.into(), value);
    }

    #[must_use]
    pub fn get_setting(&self, key: &str) -> Option<&serde_json::Value> {
        self.settings.get(key)
    }
}

// ── SessionLog ────────────────────────────────────────────────────────────────

/// Log level for session messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A single log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: i64,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
}

impl LogEntry {
    pub fn new(level: LogLevel, component: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: now_unix(),
            level,
            component: component.into(),
            message: message.into(),
        }
    }
}

/// Thread-safe in-memory session log.
pub struct SessionLog {
    entries: Mutex<Vec<LogEntry>>,
    max_entries: usize,
    min_level: LogLevel,
}

impl SessionLog {
    #[must_use]
    pub const fn new(max_entries: usize, min_level: LogLevel) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            max_entries,
            min_level,
        }
    }

    pub fn log(&self, level: LogLevel, component: impl Into<String>, message: impl Into<String>) {
        if level < self.min_level {
            return;
        }
        let entry = LogEntry::new(level, component, message);
        let mut entries = self.entries.lock();
        if entries.len() >= self.max_entries {
            entries.remove(0);
        }
        entries.push(entry);
    }

    pub fn debug(&self, component: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Debug, component, message);
    }

    pub fn info(&self, component: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Info, component, message);
    }

    pub fn warn(&self, component: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Warn, component, message);
    }

    pub fn error(&self, component: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Error, component, message);
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().clone()
    }

    pub fn entries_by_level(&self, level: LogLevel) -> Vec<LogEntry> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.level == level)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

// ── SessionExport ─────────────────────────────────────────────────────────────

/// Serialized snapshot of a session, suitable for export/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    pub session_id: String,
    pub name: String,
    pub state: SessionState,
    pub config: SessionConfig,
    pub log_entries: Vec<LogEntry>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub exported_at: i64,
    pub schema_version: u32,
}

const EXPORT_SCHEMA_VERSION: u32 = 1;

impl SessionExport {
    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> SessionResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| SessionError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json(json: &str) -> SessionResult<Self> {
        serde_json::from_str(json).map_err(|e| SessionError::Serialization(e.to_string()))
    }

    /// Write to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn write_to_file(&self, path: &Path) -> SessionResult<()> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| SessionError::ExportFailed(e.to_string()))
    }

    /// Read from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn read_from_file(path: &Path) -> SessionResult<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| SessionError::RestoreFailed(e.to_string()))?;
        Self::from_json(&json)
    }
}

// ── SessionRestore ────────────────────────────────────────────────────────────

/// Handles restoring a session from a [`SessionExport`].
pub struct SessionRestore;

impl SessionRestore {
    /// Reconstruct an [`AnalysisSession`] from an exported snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_export(export: SessionExport) -> SessionResult<AnalysisSession> {
        // Cap max_log_entries from untrusted serialized config to prevent
        // dos-memory-exhaustion from a malicious export file.
        const MAX_RESTORED_LOG_ENTRIES: usize = 1_000_000;
        if export.schema_version != EXPORT_SCHEMA_VERSION {
            return Err(SessionError::RestoreFailed(format!(
                "unsupported schema version {}",
                export.schema_version
            )));
        }

        let min_level = match export.config.log_level.as_str() {
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        };
        let max_entries = export.config.max_log_entries.min(MAX_RESTORED_LOG_ENTRIES);
        let log = SessionLog::new(max_entries, min_level);
        for entry in &export.log_entries {
            log.log(entry.level, &entry.component, &entry.message);
        }

        let session = AnalysisSession {
            id: export.session_id,
            name: export.name,
            state: RwLock::new(export.state),
            config: export.config,
            log: Arc::new(log),
            metadata: RwLock::new(export.metadata),
            created_at: export.exported_at,
            started_at: Mutex::new(None),
            completed_at: Mutex::new(None),
            progress: Mutex::new(0.0),
            tags: RwLock::new(Vec::new()),
        };
        Ok(session)
    }

    /// Restore from a JSON file on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_file(path: &Path) -> SessionResult<AnalysisSession> {
        let export = SessionExport::read_from_file(path)?;
        Self::from_export(export)
    }
}

// ── AnalysisSession ───────────────────────────────────────────────────────────

/// Manages a complete analysis session: lifecycle, config, logging, metadata.
pub struct AnalysisSession {
    pub id: String,
    pub name: String,
    state: RwLock<SessionState>,
    pub config: SessionConfig,
    pub log: Arc<SessionLog>,
    metadata: RwLock<HashMap<String, serde_json::Value>>,
    created_at: i64,
    started_at: Mutex<Option<i64>>,
    completed_at: Mutex<Option<i64>>,
    progress: Mutex<f64>,
    tags: RwLock<Vec<String>>,
}

impl AnalysisSession {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a new analysis session with the given name and config.
    pub fn new(name: impl Into<String>, config: SessionConfig) -> Self {
        let min_level = match config.log_level.as_str() {
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        };
        let log = SessionLog::new(config.max_log_entries, min_level);
        let id = format!("session_{}", now_unix());
        // Sanitise the name so CR/LF characters cannot forge additional log lines.
        let name: String = name
            .into()
            .chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
            .collect();
        log.info("session", format!("created session '{name}' (id={id})"));
        Self {
            id,
            name,
            state: RwLock::new(SessionState::Created),
            config,
            log: Arc::new(log),
            metadata: RwLock::new(HashMap::new()),
            created_at: now_unix(),
            started_at: Mutex::new(None),
            completed_at: Mutex::new(None),
            progress: Mutex::new(0.0),
            tags: RwLock::new(Vec::new()),
        }
    }

    /// Create with default config.
    pub fn with_defaults(name: impl Into<String>) -> Self {
        Self::new(name, SessionConfig::default())
    }

    // ── State ─────────────────────────────────────────────────────────────────

    /// Current state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        *self.state.read()
    }

    /// Transition to a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn transition(&self, next: SessionState) -> SessionResult<()> {
        let mut state = self.state.write();
        let new_state = state.transition_to(next)?;
        match new_state {
            SessionState::Running => {
                *self.started_at.lock() = Some(now_unix());
            }
            SessionState::Completed | SessionState::Failed | SessionState::Cancelled => {
                *self.completed_at.lock() = Some(now_unix());
            }
            _ => {}
        }
        self.log
            .info("session", format!("state: {} -> {}", *state, new_state));
        *state = new_state;
        drop(state);
        Ok(())
    }

    /// Convenience: start the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn start(&self) -> SessionResult<()> {
        self.transition(SessionState::Running)
    }

    /// Convenience: pause the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn pause(&self) -> SessionResult<()> {
        self.transition(SessionState::Paused)
    }

    /// Convenience: complete the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn complete(&self) -> SessionResult<()> {
        self.transition(SessionState::Completed)
    }

    /// Convenience: fail the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn fail(&self, reason: &str) -> SessionResult<()> {
        self.log.error("session", format!("failed: {reason}"));
        self.transition(SessionState::Failed)
    }

    /// Convenience: cancel the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn cancel(&self) -> SessionResult<()> {
        self.transition(SessionState::Cancelled)
    }

    // ── Progress ──────────────────────────────────────────────────────────────

    /// Set progress (0.0 – 1.0).
    pub fn set_progress(&self, p: f64) {
        *self.progress.lock() = p.clamp(0.0, 1.0);
    }

    /// Get progress (0.0 – 1.0).
    #[must_use]
    pub fn progress(&self) -> f64 {
        *self.progress.lock()
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    pub fn set_meta(&self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.write().insert(key.into(), value);
    }

    pub fn get_meta(&self, key: &str) -> Option<serde_json::Value> {
        self.metadata.read().get(key).cloned()
    }

    pub fn remove_meta(&self, key: &str) -> Option<serde_json::Value> {
        self.metadata.write().remove(key)
    }

    pub fn metadata_snapshot(&self) -> HashMap<String, serde_json::Value> {
        self.metadata.read().clone()
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    pub fn add_tag(&self, tag: impl Into<String>) {
        let tag = tag.into();
        let mut tags = self.tags.write();
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }

    pub fn remove_tag(&self, tag: &str) {
        self.tags.write().retain(|t| t != tag);
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.read().iter().any(|t| t == tag)
    }

    pub fn tags(&self) -> Vec<String> {
        self.tags.read().clone()
    }

    // ── Timing ───────────────────────────────────────────────────────────────

    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    #[must_use]
    pub fn started_at(&self) -> Option<i64> {
        *self.started_at.lock()
    }

    #[must_use]
    pub fn completed_at(&self) -> Option<i64> {
        *self.completed_at.lock()
    }

    /// Wall-clock duration since the session was started, if running or terminal.
    ///
    /// Note: this uses `SystemTime`-derived unix timestamps, so clock
    /// adjustments (NTP steps, DST, manual changes) can make the reported
    /// duration negative or unexpectedly large.  The result is clamped to
    /// `[0, i64::MAX]` so callers always receive a non-negative value.
    #[must_use]
    pub fn duration_secs(&self) -> Option<i64> {
        let start = (*self.started_at.lock())?;
        let end = self.completed_at.lock().unwrap_or_else(now_unix);
        // Clamp to 0 in case the wall clock jumped backwards (NTP correction,
        // time-monotonic-vs-system: SystemTime is not guaranteed to be monotonic).
        Some((end - start).max(0))
    }

    // ── Timeout check ─────────────────────────────────────────────────────────

    /// Returns `true` if the configured timeout has been exceeded.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        if let Some(limit) = self.config.timeout_secs
            && let Some(dur) = self.duration_secs()
        {
            return dur.cast_unsigned() >= limit;
        }
        false
    }

    // ── Export ───────────────────────────────────────────────────────────────

    /// Export this session to a [`SessionExport`].
    pub fn export(&self) -> SessionExport {
        SessionExport {
            session_id: self.id.clone(),
            name: self.name.clone(),
            state: self.state(),
            config: self.config.clone(),
            log_entries: self.log.entries(),
            metadata: self.metadata_snapshot(),
            exported_at: now_unix(),
            schema_version: EXPORT_SCHEMA_VERSION,
        }
    }

    /// Export to a JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn export_to_file(&self, path: &Path) -> SessionResult<()> {
        self.export().write_to_file(path)
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Session '{}' (id={}) state={} progress={:.0}% log_entries={}",
            self.name,
            self.id,
            self.state(),
            self.progress() * 100.0,
            self.log.len(),
        )
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .cast_signed()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> AnalysisSession {
        AnalysisSession::with_defaults("test_session")
    }

    // ── SessionState ──────────────────────────────────────────────────────────

    #[test]
    fn test_state_initial_is_created() {
        let s = session();
        assert_eq!(s.state(), SessionState::Created);
    }

    #[test]
    fn test_state_transition_created_to_running() {
        let s = session();
        s.start().unwrap();
        assert_eq!(s.state(), SessionState::Running);
    }

    #[test]
    fn test_state_transition_running_to_paused() {
        let s = session();
        s.start().unwrap();
        s.pause().unwrap();
        assert_eq!(s.state(), SessionState::Paused);
    }

    #[test]
    fn test_state_transition_paused_to_running() {
        let s = session();
        s.start().unwrap();
        s.pause().unwrap();
        s.start().unwrap();
        assert_eq!(s.state(), SessionState::Running);
    }

    #[test]
    fn test_state_transition_running_to_completed() {
        let s = session();
        s.start().unwrap();
        s.complete().unwrap();
        assert_eq!(s.state(), SessionState::Completed);
    }

    #[test]
    fn test_state_terminal_no_further_transitions() {
        let s = session();
        s.start().unwrap();
        s.complete().unwrap();
        assert!(s.start().is_err());
    }

    #[test]
    fn test_state_is_terminal() {
        assert!(SessionState::Completed.is_terminal());
        assert!(SessionState::Failed.is_terminal());
        assert!(SessionState::Cancelled.is_terminal());
        assert!(!SessionState::Running.is_terminal());
        assert!(!SessionState::Created.is_terminal());
    }

    #[test]
    fn test_state_can_start() {
        assert!(SessionState::Created.can_start());
        assert!(SessionState::Paused.can_start());
        assert!(!SessionState::Running.can_start());
    }

    #[test]
    fn test_state_can_pause() {
        assert!(SessionState::Running.can_pause());
        assert!(!SessionState::Created.can_pause());
    }

    #[test]
    fn test_invalid_transition_error() {
        let err = SessionState::Created.transition_to(SessionState::Completed);
        assert!(matches!(err, Err(SessionError::InvalidTransition { .. })));
    }

    #[test]
    fn test_state_display() {
        assert_eq!(SessionState::Running.to_string(), "running");
        assert_eq!(SessionState::Created.to_string(), "created");
    }

    // ── SessionConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = SessionConfig::default();
        assert!(cfg.timeout_secs.is_none());
        assert_eq!(cfg.parallelism, 1);
        assert!(!cfg.auto_persist);
    }

    #[test]
    fn test_config_builder() {
        let cfg = SessionConfig::new().with_timeout(120).with_parallelism(4);
        assert_eq!(cfg.timeout_secs, Some(120));
        assert_eq!(cfg.parallelism, 4);
    }

    #[test]
    fn test_config_parallelism_clamped() {
        let cfg = SessionConfig::new().with_parallelism(0);
        assert_eq!(cfg.parallelism, 1);
    }

    #[test]
    fn test_config_settings() {
        let mut cfg = SessionConfig::new();
        cfg.set_setting("arch", serde_json::json!("x86_64"));
        assert_eq!(cfg.get_setting("arch"), Some(&serde_json::json!("x86_64")));
        assert!(cfg.get_setting("missing").is_none());
    }

    // ── SessionLog ────────────────────────────────────────────────────────────

    #[test]
    fn test_log_basic() {
        let log = SessionLog::new(100, LogLevel::Debug);
        log.info("test", "hello");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_log_level_filter() {
        let log = SessionLog::new(100, LogLevel::Warn);
        log.debug("test", "ignored");
        log.info("test", "also ignored");
        log.warn("test", "included");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_log_max_entries_eviction() {
        let log = SessionLog::new(5, LogLevel::Debug);
        for i in 0..10 {
            log.info("test", format!("msg {i}"));
        }
        assert_eq!(log.len(), 5);
    }

    #[test]
    fn test_log_entries_by_level() {
        let log = SessionLog::new(100, LogLevel::Debug);
        log.warn("test", "w1");
        log.error("test", "e1");
        log.warn("test", "w2");
        let warns = log.entries_by_level(LogLevel::Warn);
        assert_eq!(warns.len(), 2);
        let errors = log.entries_by_level(LogLevel::Error);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn test_log_clear() {
        let log = SessionLog::new(100, LogLevel::Debug);
        log.info("test", "hi");
        log.clear();
        assert!(log.is_empty());
    }

    // ── Progress ──────────────────────────────────────────────────────────────

    #[test]
    fn test_progress_initial_zero() {
        let s = session();
        assert!((s.progress() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_set() {
        let s = session();
        s.set_progress(0.5);
        assert!((s.progress() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_progress_clamped() {
        let s = session();
        s.set_progress(2.0);
        assert!((s.progress() - 1.0).abs() < f64::EPSILON);
        s.set_progress(-1.0);
        assert!((s.progress() - 0.0).abs() < f64::EPSILON);
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_set_get() {
        let s = session();
        s.set_meta("binary", serde_json::json!("test.exe"));
        assert_eq!(s.get_meta("binary"), Some(serde_json::json!("test.exe")));
    }

    #[test]
    fn test_metadata_remove() {
        let s = session();
        s.set_meta("k", serde_json::json!(1));
        let removed = s.remove_meta("k");
        assert!(removed.is_some());
        assert!(s.get_meta("k").is_none());
    }

    #[test]
    fn test_metadata_snapshot() {
        let s = session();
        s.set_meta("a", serde_json::json!(1));
        s.set_meta("b", serde_json::json!(2));
        let snap = s.metadata_snapshot();
        assert_eq!(snap.len(), 2);
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_tags_add_and_check() {
        let s = session();
        s.add_tag("malware");
        assert!(s.has_tag("malware"));
    }

    #[test]
    fn test_tags_no_duplicates() {
        let s = session();
        s.add_tag("packed");
        s.add_tag("packed");
        assert_eq!(s.tags().len(), 1);
    }

    #[test]
    fn test_tags_remove() {
        let s = session();
        s.add_tag("crackme");
        s.remove_tag("crackme");
        assert!(!s.has_tag("crackme"));
    }

    // ── Timing ───────────────────────────────────────────────────────────────

    #[test]
    fn test_started_at_none_before_start() {
        let s = session();
        assert!(s.started_at().is_none());
    }

    #[test]
    fn test_started_at_set_after_start() {
        let s = session();
        s.start().unwrap();
        assert!(s.started_at().is_some());
    }

    #[test]
    fn test_completed_at_set_after_complete() {
        let s = session();
        s.start().unwrap();
        s.complete().unwrap();
        assert!(s.completed_at().is_some());
    }

    // ── Timeout ───────────────────────────────────────────────────────────────

    #[test]
    fn test_timeout_not_exceeded_no_config() {
        let s = session();
        s.start().unwrap();
        assert!(!s.is_timed_out());
    }

    // ── Export / Restore ──────────────────────────────────────────────────────

    #[test]
    fn test_export_round_trip() {
        let s = session();
        s.start().unwrap();
        s.set_meta("key", serde_json::json!("val"));
        s.log.warn("test", "exported warning");
        let export = s.export();
        assert_eq!(export.session_id, s.id);
        assert_eq!(export.state, SessionState::Running);
        assert!(!export.log_entries.is_empty());
    }

    #[test]
    fn test_export_json_round_trip() {
        let s = session();
        s.start().unwrap();
        let export = s.export();
        let json = export.to_json().unwrap();
        let back = SessionExport::from_json(&json).unwrap();
        assert_eq!(back.session_id, export.session_id);
        assert_eq!(back.state, SessionState::Running);
    }

    #[test]
    fn test_restore_from_export() {
        let s = session();
        s.start().unwrap();
        s.add_tag("restored");
        let export = s.export();
        let restored = SessionRestore::from_export(export).unwrap();
        assert_eq!(restored.name, s.name);
        assert_eq!(restored.state(), SessionState::Running);
    }

    #[test]
    fn test_restore_rejects_bad_schema() {
        let mut export = session().export();
        export.schema_version = 99;
        let res = SessionRestore::from_export(export);
        assert!(matches!(res, Err(SessionError::RestoreFailed(_))));
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    #[test]
    fn test_summary_contains_name() {
        let s = AnalysisSession::with_defaults("my_analysis");
        assert!(s.summary().contains("my_analysis"));
    }

    #[test]
    fn test_fail_logs_reason() {
        let s = session();
        s.start().unwrap();
        s.fail("disk full").unwrap();
        assert_eq!(s.state(), SessionState::Failed);
        let errors = s.log.entries_by_level(LogLevel::Error);
        assert!(errors.iter().any(|e| e.message.contains("disk full")));
    }

    #[test]
    fn test_session_id_contains_timestamp() {
        let s = session();
        assert!(s.id.starts_with("session_"));
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_entry_new() {
        let entry = LogEntry::new(LogLevel::Info, "comp", "message");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.component, "comp");
        assert_eq!(entry.message, "message");
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_cancel_transition() {
        let s = session();
        s.start().unwrap();
        s.cancel().unwrap();
        assert_eq!(s.state(), SessionState::Cancelled);
    }

    #[test]
    fn test_completed_at_none_before_complete() {
        let s = session();
        s.start().unwrap();
        assert!(s.completed_at().is_none());
    }

    #[test]
    fn test_duration_secs_none_before_start() {
        let s = session();
        assert!(s.duration_secs().is_none());
    }

    #[test]
    fn test_multiple_metadata_keys() {
        let s = session();
        for i in 0..5 {
            s.set_meta(format!("k{i}"), serde_json::json!(i));
        }
        assert_eq!(s.metadata_snapshot().len(), 5);
    }

    #[test]
    fn test_session_log_arc_shared() {
        let s = session();
        let log = s.log.clone();
        log.info("external", "shared log message");
        assert!(!s.log.is_empty());
    }
}
