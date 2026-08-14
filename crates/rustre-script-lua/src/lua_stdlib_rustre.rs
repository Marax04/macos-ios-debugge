//! `lua_stdlib_rustre.rs` — Lua-specific standard library for the rustre namespace.
//!
//! Exposes a `rustre.*` table to Lua scripts running inside `RustRE`, including:
//! * `rustre.log(level, msg)` — structured logging
//! * `rustre.alert(msg)` — pop-up / high-priority notification
//! * `rustre.input(prompt)` — request user input (returns a placeholder in tests)
//! * `rustre.progress(current, total, label)` — progress reporting
//! * `rustre.db.*` — key-value store operations
//! * `rustre.ui.*` — stub UI operations
//!
//! # Relationship to similar stdlib modules
//!
//! | Module | Namespace | Content |
//! |---|---|---|
//! | `lua_stdlib_rustre` (this) | `rustre.*` | Tooling: logging, alerts, UI, DB |
//! | `lua_stdlib_re` | `re.*` | RE analysis: `pe_info`, `elf_info`, entropy, XOR, disasm |
//! | `lua_re_bindings` | `rustre.*` via mlua | mlua bindings wrapping an in-process binary store |
//!
//! These modules are **intentionally distinct**: this one covers host tooling
//! helpers; `lua_stdlib_re` covers file-based RE primitives;
//! `lua_re_bindings` bridges mlua's C-extension API to the data store.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ─── LogLevel ─────────────────────────────────────────────────────────────────

/// Severity level for log messages emitted from scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Default)]
pub enum LogLevel {
    Debug = 0,
    #[default]
    Info = 1,
    Warn = 2,
    Error = 3,
}


impl LogLevel {
    #[must_use]
    pub fn parse_name(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ─── LogRecord ────────────────────────────────────────────────────────────────

/// A single log record emitted by a Lua script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub level: LogLevel,
    pub message: String,
    /// Script source file / chunk name, if known.
    pub source: Option<String>,
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.level, self.message)
    }
}

// ─── AlertRecord ─────────────────────────────────────────────────────────────

/// An alert notification from a Lua script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRecord {
    pub message: String,
    pub kind: AlertKind,
}

/// Kind of alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    Info,
    Warning,
    Error,
}

// ─── ProgressRecord ──────────────────────────────────────────────────────────

/// A progress update from a Lua script.
#[derive(Debug, Clone)]
pub struct ProgressRecord {
    pub current: u64,
    pub total: u64,
    pub label: String,
}

impl ProgressRecord {
    #[must_use]
    pub fn pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (crate::casts::u64_to_f64(self.current) / crate::casts::u64_to_f64(self.total)) * 100.0
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.total > 0 && self.current >= self.total
    }
}

// ─── DbStore ─────────────────────────────────────────────────────────────────

/// Simple string key-value store exposed as `rustre.db.*`.
#[derive(Debug, Default, Clone)]
pub struct DbStore {
    data: HashMap<String, String>,
}

impl DbStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `key` to `value`.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get the value for `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(String::as_str)
    }

    /// Delete `key`.  Returns `true` if it existed.
    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    /// List all keys.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.data.keys().map(std::string::String::as_str).collect()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// `true` when `key` is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Get or return a default.
    #[must_use]
    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.data
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }
}

// ─── UiStub ──────────────────────────────────────────────────────────────────

/// Stub implementation of `rustre.ui.*` — records calls for testing.
#[derive(Debug, Default, Clone)]
pub struct UiStub {
    pub open_calls: Vec<String>,
    pub close_calls: Vec<String>,
    pub refresh_count: u32,
    pub last_title: Option<String>,
}

impl UiStub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stub: "open a panel with this name".
    pub fn open_panel(&mut self, name: impl Into<String>) {
        let n = name.into();
        self.last_title = Some(n.clone());
        self.open_calls.push(n);
    }

    /// Stub: "close a panel".
    pub fn close_panel(&mut self, name: impl Into<String>) {
        self.close_calls.push(name.into());
    }

    /// Stub: trigger a UI refresh.
    pub const fn refresh(&mut self) {
        self.refresh_count += 1;
    }
}

// ─── InputHandler ────────────────────────────────────────────────────────────

/// Handles `rustre.input(prompt)` calls.
///
/// In production this would show a dialog; in tests we can inject pre-loaded
/// responses via [`InputHandler::push_response`].
#[derive(Debug, Default)]
pub struct InputHandler {
    responses: std::collections::VecDeque<String>,
    pub prompt_history: Vec<String>,
}

impl InputHandler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load a response for the next `input()` call.
    pub fn push_response(&mut self, response: impl Into<String>) {
        self.responses.push_back(response.into());
    }

    /// Handle a script-level `input(prompt)` call.
    pub fn input(&mut self, prompt: impl Into<String>) -> String {
        let p = prompt.into();
        self.prompt_history.push(p);
        self.responses.pop_front().unwrap_or_default()
    }
}

// ─── LuaRustreStdlib ─────────────────────────────────────────────────────────

/// The `rustre.*` standard library for Lua scripts.
///
/// Aggregates logging, alert, progress, db, ui, and input subsystems.
/// In the full implementation the methods on this struct are wired into the
/// `mlua::Lua` engine; here the struct is self-contained for testing.
#[derive(Debug)]
pub struct LuaRustreStdlib {
    pub log_records: Vec<LogRecord>,
    pub alerts: Vec<AlertRecord>,
    pub progress_records: Vec<ProgressRecord>,
    pub db: DbStore,
    pub ui: UiStub,
    pub input: InputHandler,
    /// Minimum log level to capture.
    pub min_level: LogLevel,
}

impl Default for LuaRustreStdlib {
    fn default() -> Self {
        Self {
            log_records: Vec::new(),
            alerts: Vec::new(),
            progress_records: Vec::new(),
            db: DbStore::default(),
            ui: UiStub::default(),
            input: InputHandler::default(),
            min_level: LogLevel::Debug,
        }
    }
}

impl LuaRustreStdlib {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ─── rustre.log() ────────────────────────────────────────────────────

    /// Emit a log message at `level`.
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        if level >= self.min_level {
            self.log_records.push(LogRecord {
                level,
                message: message.into(),
                source: None,
            });
        }
    }

    /// Shortcut: debug log.
    pub fn log_debug(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Debug, msg);
    }

    /// Shortcut: info log.
    pub fn log_info(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Info, msg);
    }

    /// Shortcut: warn log.
    pub fn log_warn(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Warn, msg);
    }

    /// Shortcut: error log.
    pub fn log_error(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Error, msg);
    }

    /// Return all log records at or above `min_level`.
    #[must_use]
    pub fn logs_at_or_above(&self, min: LogLevel) -> Vec<&LogRecord> {
        self.log_records.iter().filter(|r| r.level >= min).collect()
    }

    // ─── rustre.alert() ──────────────────────────────────────────────────

    /// Post an alert.
    pub fn alert(&mut self, message: impl Into<String>, kind: AlertKind) {
        self.alerts.push(AlertRecord {
            message: message.into(),
            kind,
        });
    }

    /// Shorthand: info alert.
    pub fn alert_info(&mut self, message: impl Into<String>) {
        self.alert(message, AlertKind::Info);
    }

    /// Shorthand: warning alert.
    pub fn alert_warn(&mut self, message: impl Into<String>) {
        self.alert(message, AlertKind::Warning);
    }

    // ─── rustre.input() ──────────────────────────────────────────────────

    /// Request user input.
    pub fn input(&mut self, prompt: impl Into<String>) -> String {
        self.input.input(prompt)
    }

    // ─── rustre.progress() ───────────────────────────────────────────────

    /// Report progress.
    pub fn progress(&mut self, current: u64, total: u64, label: impl Into<String>) {
        self.progress_records.push(ProgressRecord {
            current,
            total,
            label: label.into(),
        });
    }

    /// Latest progress record.
    #[must_use]
    pub fn latest_progress(&self) -> Option<&ProgressRecord> {
        self.progress_records.last()
    }

    // ─── rustre.db.* ─────────────────────────────────────────────────────

    pub fn db_set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.db.set(key, value);
    }

    #[must_use] 
    pub fn db_get(&self, key: &str) -> Option<&str> {
        self.db.get(key)
    }

    pub fn db_delete(&mut self, key: &str) -> bool {
        self.db.delete(key)
    }

    #[must_use] 
    pub fn db_keys(&self) -> Vec<&str> {
        self.db.keys()
    }

    // ─── rustre.ui.* ─────────────────────────────────────────────────────

    pub fn ui_open_panel(&mut self, name: impl Into<String>) {
        self.ui.open_panel(name);
    }

    pub const fn ui_refresh(&mut self) {
        self.ui.refresh();
    }

    // ─── statistics ──────────────────────────────────────────────────────

    /// Total log records captured.
    #[must_use]
    pub const fn log_count(&self) -> usize {
        self.log_records.len()
    }

    /// Total alerts posted.
    #[must_use]
    pub const fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    /// Clear all records (useful between test cases).
    pub fn clear_all(&mut self) {
        self.log_records.clear();
        self.alerts.clear();
        self.progress_records.clear();
        self.db.clear();
    }
}

// ─── Arc<Mutex<>> wrapper ────────────────────────────────────────────────────

/// Thread-safe wrapper for use with `mlua` callbacks.
pub type SharedStdlib = Arc<Mutex<LuaRustreStdlib>>;

/// Create a new shared stdlib instance.
#[must_use]
pub fn new_shared() -> SharedStdlib {
    Arc::new(Mutex::new(LuaRustreStdlib::new()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stdlib() -> LuaRustreStdlib {
        LuaRustreStdlib::new()
    }

    // LogLevel tests ────────────────────────────────────────────────────────

    #[test]
    fn log_level_from_str_debug() {
        assert_eq!(LogLevel::parse_name("debug"), LogLevel::Debug);
    }

    #[test]
    fn log_level_from_str_warn() {
        assert_eq!(LogLevel::parse_name("warning"), LogLevel::Warn);
    }

    #[test]
    fn log_level_from_str_unknown_defaults_to_info() {
        assert_eq!(LogLevel::parse_name("unknown"), LogLevel::Info);
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Warn.to_string(), "WARN");
    }

    // Logging tests ─────────────────────────────────────────────────────────

    #[test]
    fn log_records_stored() {
        let mut s = stdlib();
        s.log_info("hello");
        assert_eq!(s.log_count(), 1);
    }

    #[test]
    fn log_min_level_filters() {
        let mut s = stdlib();
        s.min_level = LogLevel::Warn;
        s.log_debug("debug msg");
        s.log_info("info msg");
        s.log_warn("warn msg");
        assert_eq!(s.log_count(), 1);
        assert_eq!(s.log_records[0].level, LogLevel::Warn);
    }

    #[test]
    fn logs_at_or_above_filters() {
        let mut s = stdlib();
        s.log_debug("d");
        s.log_warn("w");
        s.log_error("e");
        let high = s.logs_at_or_above(LogLevel::Warn);
        assert_eq!(high.len(), 2);
    }

    #[test]
    fn log_record_display() {
        let r = LogRecord {
            level: LogLevel::Error,
            message: "oops".into(),
            source: None,
        };
        assert!(r.to_string().contains("ERROR"));
        assert!(r.to_string().contains("oops"));
    }

    // Alert tests ───────────────────────────────────────────────────────────

    #[test]
    fn alert_stored() {
        let mut s = stdlib();
        s.alert_info("something happened");
        assert_eq!(s.alert_count(), 1);
        assert_eq!(s.alerts[0].kind, AlertKind::Info);
    }

    #[test]
    fn alert_warn_kind() {
        let mut s = stdlib();
        s.alert_warn("be careful");
        assert_eq!(s.alerts[0].kind, AlertKind::Warning);
    }

    // Progress tests ────────────────────────────────────────────────────────

    #[test]
    fn progress_recorded() {
        let mut s = stdlib();
        s.progress(50, 100, "loading");
        let p = s.latest_progress().unwrap();
        assert_eq!(p.current, 50);
        assert_eq!(p.total, 100);
        assert!((p.pct() - 50.0).abs() < 0.001);
    }

    #[test]
    fn progress_complete() {
        let p = ProgressRecord {
            current: 100,
            total: 100,
            label: "done".into(),
        };
        assert!(p.is_complete());
    }

    #[test]
    fn progress_zero_total() {
        let p = ProgressRecord {
            current: 0,
            total: 0,
            label: "idle".into(),
        };
        assert_eq!(p.pct(), 0.0);
    }

    // DbStore tests ─────────────────────────────────────────────────────────

    #[test]
    fn db_set_get() {
        let mut s = stdlib();
        s.db_set("key", "val");
        assert_eq!(s.db_get("key"), Some("val"));
    }

    #[test]
    fn db_delete() {
        let mut s = stdlib();
        s.db_set("k", "v");
        assert!(s.db_delete("k"));
        assert!(s.db_get("k").is_none());
    }

    #[test]
    fn db_keys_empty() {
        let s = stdlib();
        assert!(s.db.is_empty());
        assert_eq!(s.db_keys().len(), 0);
    }

    #[test]
    fn db_contains() {
        let mut d = DbStore::new();
        d.set("x", "1");
        assert!(d.contains("x"));
        assert!(!d.contains("y"));
    }

    #[test]
    fn db_get_or_default() {
        let d = DbStore::new();
        assert_eq!(d.get_or("missing", "default"), "default");
    }

    #[test]
    fn db_clear() {
        let mut d = DbStore::new();
        d.set("a", "1");
        d.clear();
        assert!(d.is_empty());
    }

    // UiStub tests ──────────────────────────────────────────────────────────

    #[test]
    fn ui_open_panel_records() {
        let mut s = stdlib();
        s.ui_open_panel("hex view");
        assert_eq!(s.ui.open_calls.len(), 1);
        assert_eq!(s.ui.last_title.as_deref(), Some("hex view"));
    }

    #[test]
    fn ui_refresh_counter() {
        let mut s = stdlib();
        s.ui_refresh();
        s.ui_refresh();
        assert_eq!(s.ui.refresh_count, 2);
    }

    // InputHandler tests ────────────────────────────────────────────────────

    #[test]
    fn input_returns_preloaded_response() {
        let mut s = stdlib();
        s.input.push_response("yes");
        let resp = s.input("Are you sure?");
        assert_eq!(resp, "yes");
    }

    #[test]
    fn input_empty_when_no_response() {
        let mut s = stdlib();
        let resp = s.input("prompt");
        assert_eq!(resp, "");
    }

    #[test]
    fn input_records_prompt() {
        let mut s = stdlib();
        s.input.push_response("42");
        s.input("Enter value:");
        assert_eq!(s.input.prompt_history.len(), 1);
        assert_eq!(s.input.prompt_history[0], "Enter value:");
    }

    // clear_all tests ───────────────────────────────────────────────────────

    #[test]
    fn clear_all_resets() {
        let mut s = stdlib();
        s.log_info("msg");
        s.alert_info("alert");
        s.progress(1, 10, "work");
        s.db_set("k", "v");
        s.clear_all();
        assert_eq!(s.log_count(), 0);
        assert_eq!(s.alert_count(), 0);
        assert!(s.progress_records.is_empty());
        assert!(s.db.is_empty());
    }

    // Shared stdlib tests ────────────────────────────────────────────────────

    #[test]
    fn shared_stdlib_creates() {
        let shared = new_shared();
        let mut guard = shared.lock().unwrap();
        guard.log_info("test");
        assert_eq!(guard.log_count(), 1);
    }

    #[test]
    fn log_shortcut_methods() {
        let mut s = stdlib();
        s.log_debug("d");
        s.log_info("i");
        s.log_warn("w");
        s.log_error("e");
        assert_eq!(s.log_count(), 4);
    }

    #[test]
    fn progress_multiple_records() {
        let mut s = stdlib();
        s.progress(10, 100, "step 1");
        s.progress(20, 100, "step 2");
        assert_eq!(s.progress_records.len(), 2);
    }

    #[test]
    fn db_len_reflects_insertions() {
        let mut s = stdlib();
        s.db_set("k1", "v1");
        s.db_set("k2", "v2");
        assert_eq!(s.db.len(), 2);
    }

    #[test]
    fn alert_error_kind() {
        let mut s = stdlib();
        s.alert("boom", AlertKind::Error);
        assert_eq!(s.alerts[0].kind, AlertKind::Error);
    }

    #[test]
    fn input_multiple_responses() {
        let mut s = stdlib();
        s.input.push_response("first");
        s.input.push_response("second");
        assert_eq!(s.input("p1"), "first");
        assert_eq!(s.input("p2"), "second");
    }

    #[test]
    fn log_source_field_optional() {
        let r = LogRecord {
            level: LogLevel::Info,
            message: "msg".into(),
            source: Some("chunk".into()),
        };
        assert_eq!(r.source.as_deref(), Some("chunk"));
    }

    #[test]
    fn ui_close_panel_records() {
        let mut s = stdlib();
        s.ui.close_panel("hex view");
        assert_eq!(s.ui.close_calls.len(), 1);
    }

    #[test]
    fn shared_stdlib_thread_safe() {
        let shared = new_shared();
        let clone = shared.clone();
        {
            let mut g = shared.lock().unwrap();
            g.log_info("from thread 1");
        }
        {
            let mut g = clone.lock().unwrap();
            g.log_info("from thread 2");
            assert_eq!(g.log_count(), 2);
        }
    }
}
