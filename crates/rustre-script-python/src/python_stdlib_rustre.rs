//! `python_stdlib_rustre.rs` — Python standard library for the `rustre` module.
//!
//! Provides the Python-side `rustre.*` bindings.  The actual `pyo3` wiring is
//! done separately; this file defines the pure-Rust layer that the pyo3
//! callbacks delegate to, so it can be unit-tested without a Python interpreter.
//!
//! # Subsystems
//! * **Logging** — `rustre.log(level, msg)`
//! * **Alerts** — `rustre.alert(msg)`
//! * **UI** — `rustre.ui.input(prompt)` (IDA-compatible)
//! * **DB bindings** — thread-safe key-value store
//! * **IDA compat helpers** — `idc_print`, `ask_string`, `ask_yn`, …
//! * **`PythonModuleBuilder`** — generates module registration stubs

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ─── LogLevel ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LogLevel {
    Debug = 0,
    #[default]
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl LogLevel {
    #[must_use]
    pub const fn from_int(n: i32) -> Self {
        match n {
            0 => Self::Debug,
            1 => Self::Info,
            2 => Self::Warn,
            3 => Self::Error,
            _ if n < 0 => Self::Debug,
            _ => Self::Error,
        }
    }

    #[must_use]
    pub fn from_name(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "debug" | "d" => Self::Debug,
            "warn" | "w" => Self::Warn,
            "error" | "e" => Self::Error,
            _ => Self::Info,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        };
        write!(f, "{s}")
    }
}

// ─── LogRecord ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub level: LogLevel,
    pub message: String,
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.level, self.message)
    }
}

// ─── AlertRecord ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AlertRecord {
    pub message: String,
}

// ─── PythonDbStore ────────────────────────────────────────────────────────────

/// Thread-safe key-value store exposed as `rustre.db.*` in Python.
#[derive(Debug, Default, Clone)]
pub struct PythonDbStore {
    data: HashMap<String, String>,
}

impl PythonDbStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(String::as_str)
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.data.keys().map(std::string::String::as_str).collect()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Get all entries as a cloned `HashMap`.
    #[must_use]
    pub fn all(&self) -> HashMap<String, String> {
        self.data.clone()
    }
}

// ─── UiInputHandler ──────────────────────────────────────────────────────────

/// Handles `rustre.ui.input(prompt)` and IDA-compat `ask_string` calls.
#[derive(Debug, Default)]
pub struct UiInputHandler {
    responses: std::collections::VecDeque<String>,
    pub history: Vec<(String, String)>,
}

impl UiInputHandler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load a response.
    pub fn push_response(&mut self, r: impl Into<String>) {
        self.responses.push_back(r.into());
    }

    /// Handle an `input(prompt)` call.
    pub fn input(&mut self, prompt: impl Into<String>) -> String {
        let p = prompt.into();
        let response = self.responses.pop_front().unwrap_or_default();
        self.history.push((p, response.clone()));
        response
    }

    /// Number of responses consumed.
    #[must_use]
    pub const fn calls_made(&self) -> usize {
        self.history.len()
    }
}

// ─── IdaCompatHelpers ────────────────────────────────────────────────────────

/// IDA-style helper functions exposed under `idc.*` / `idaapi.*`.
#[derive(Debug, Default)]
pub struct IdaCompatHelpers {
    pub print_history: Vec<String>,
    yn_responses: std::collections::VecDeque<bool>,
    string_responses: std::collections::VecDeque<String>,
}

impl IdaCompatHelpers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `idc.print(msg)` — append to print history.
    pub fn idc_print(&mut self, msg: impl Into<String>) {
        self.print_history.push(msg.into());
    }

    /// `idc.ask_yn(default, prompt)` — return pre-loaded bool.
    pub fn ask_yn(&mut self, default: bool, _prompt: &str) -> bool {
        self.yn_responses.pop_front().unwrap_or(default)
    }

    /// `idc.ask_str(default, prompt)` — return pre-loaded string.
    pub fn ask_string(&mut self, default: &str, _prompt: &str) -> String {
        self.string_responses
            .pop_front()
            .unwrap_or_else(|| default.to_string())
    }

    /// Pre-load a `ask_yn` response.
    pub fn push_yn(&mut self, val: bool) {
        self.yn_responses.push_back(val);
    }

    /// Pre-load a `ask_str` response.
    pub fn push_string(&mut self, s: impl Into<String>) {
        self.string_responses.push_back(s.into());
    }

    /// `idaapi.get_imagebase()` — stub that returns 0.
    #[must_use]
    pub const fn get_imagebase(&self) -> u64 {
        0x0000_0000_0000_0000
    }

    /// `idaapi.get_inf_structure().min_ea` — stub.
    #[must_use]
    pub const fn min_ea(&self) -> u64 {
        0x0000_0000_0000_0000
    }

    /// `idaapi.get_inf_structure().max_ea` — stub.
    #[must_use]
    pub const fn max_ea(&self) -> u64 {
        u64::MAX
    }
}

// ─── PythonModuleBuilder ─────────────────────────────────────────────────────

/// Generates Python module registration stubs.
///
/// In the full implementation this would build `pyo3` `#[pymodule]` code;
/// here we store the registrations so they can be inspected in tests.
#[derive(Debug, Default)]
pub struct PythonModuleBuilder {
    pub module_name: String,
    pub functions: Vec<FunctionStub>,
    pub classes: Vec<ClassStub>,
    pub submodules: Vec<String>,
}

/// A stub record for a function registration.
#[derive(Debug, Clone)]
pub struct FunctionStub {
    pub name: String,
    pub signature: String,
    pub doc: String,
}

/// A stub record for a class registration.
#[derive(Debug, Clone)]
pub struct ClassStub {
    pub name: String,
    pub methods: Vec<String>,
}

impl PythonModuleBuilder {
    #[must_use]
    pub fn new(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            ..Default::default()
        }
    }

    /// Register a function.
    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        signature: impl Into<String>,
        doc: impl Into<String>,
    ) {
        self.functions.push(FunctionStub {
            name: name.into(),
            signature: signature.into(),
            doc: doc.into(),
        });
    }

    /// Register a class.
    pub fn register_class(&mut self, name: impl Into<String>, methods: Vec<impl Into<String>>) {
        self.classes.push(ClassStub {
            name: name.into(),
            methods: methods.into_iter().map(Into::into).collect(),
        });
    }

    /// Add a submodule.
    pub fn add_submodule(&mut self, name: impl Into<String>) {
        self.submodules.push(name.into());
    }

    /// Generate a human-readable summary of all registrations.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![format!("Module: {}", self.module_name)];
        for f in &self.functions {
            lines.push(format!("  fn {}({}): {}", f.name, f.signature, f.doc));
        }
        for c in &self.classes {
            lines.push(format!("  class {}: {:?}", c.name, c.methods));
        }
        for s in &self.submodules {
            lines.push(format!("  submodule: {s}"));
        }
        lines.join("\n")
    }

    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }
}

// ─── PythonRustreStdlib ──────────────────────────────────────────────────────

/// The `rustre.*` Python standard library.
///
/// Central aggregation of all subsystems.
#[derive(Debug, Default)]
pub struct PythonRustreStdlib {
    pub logs: Vec<LogRecord>,
    pub alerts: Vec<AlertRecord>,
    pub db: PythonDbStore,
    pub ui_input: UiInputHandler,
    pub ida: IdaCompatHelpers,
    pub min_level: LogLevel,
}

impl PythonRustreStdlib {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ─── log ─────────────────────────────────────────────────────────────

    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        if level >= self.min_level {
            self.logs.push(LogRecord {
                level,
                message: message.into(),
            });
        }
    }

    pub fn log_debug(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Debug, msg);
    }
    pub fn log_info(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Info, msg);
    }
    pub fn log_warn(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Warn, msg);
    }
    pub fn log_error(&mut self, msg: impl Into<String>) {
        self.log(LogLevel::Error, msg);
    }

    #[must_use]
    pub const fn log_count(&self) -> usize {
        self.logs.len()
    }

    #[must_use]
    pub fn logs_matching(&self, substr: &str) -> Vec<&LogRecord> {
        self.logs
            .iter()
            .filter(|r| r.message.contains(substr))
            .collect()
    }

    // ─── alert ───────────────────────────────────────────────────────────

    pub fn alert(&mut self, message: impl Into<String>) {
        self.alerts.push(AlertRecord {
            message: message.into(),
        });
    }

    #[must_use]
    pub const fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    // ─── ui.input ────────────────────────────────────────────────────────

    pub fn ui_input(&mut self, prompt: impl Into<String>) -> String {
        self.ui_input.input(prompt)
    }

    // ─── db ──────────────────────────────────────────────────────────────

    pub fn db_set(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.db.set(k, v);
    }
    #[must_use] 
    pub fn db_get(&self, k: &str) -> Option<&str> {
        self.db.get(k)
    }
    pub fn db_delete(&mut self, k: &str) -> bool {
        self.db.delete(k)
    }
    #[must_use] 
    pub fn db_keys(&self) -> Vec<&str> {
        self.db.keys()
    }

    // ─── IDA ─────────────────────────────────────────────────────────────

    pub fn idc_print(&mut self, msg: impl Into<String>) {
        self.ida.idc_print(msg);
    }
    pub fn ask_yn(&mut self, default: bool, prompt: &str) -> bool {
        self.ida.ask_yn(default, prompt)
    }
    pub fn ask_string(&mut self, default: &str, prompt: &str) -> String {
        self.ida.ask_string(default, prompt)
    }

    // ─── misc ────────────────────────────────────────────────────────────

    pub fn clear_all(&mut self) {
        self.logs.clear();
        self.alerts.clear();
        self.db.clear();
    }
}

/// Thread-safe shared instance.
pub type SharedPythonStdlib = Arc<Mutex<PythonRustreStdlib>>;

#[must_use]
pub fn new_shared() -> SharedPythonStdlib {
    Arc::new(Mutex::new(PythonRustreStdlib::new()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stdlib() -> PythonRustreStdlib {
        PythonRustreStdlib::new()
    }

    // LogLevel tests ─────────────────────────────────────────────────────────

    #[test]
    fn log_level_from_int_debug() {
        assert_eq!(LogLevel::from_int(0), LogLevel::Debug);
    }

    #[test]
    fn log_level_from_int_clamps() {
        assert_eq!(LogLevel::from_int(-5), LogLevel::Debug);
        assert_eq!(LogLevel::from_int(100), LogLevel::Error);
    }

    #[test]
    fn log_level_from_str() {
        assert_eq!(LogLevel::from_name("error"), LogLevel::Error);
        assert_eq!(LogLevel::from_name("d"), LogLevel::Debug);
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Error);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "INFO");
    }

    // Logging tests ──────────────────────────────────────────────────────────

    #[test]
    fn log_records_stored() {
        let mut s = stdlib();
        s.log_info("hello");
        assert_eq!(s.log_count(), 1);
    }

    #[test]
    fn log_min_level_filters() {
        let mut s = stdlib();
        s.min_level = LogLevel::Error;
        s.log_debug("d");
        s.log_info("i");
        s.log_error("e");
        assert_eq!(s.log_count(), 1);
    }

    #[test]
    fn log_matching_substr() {
        let mut s = stdlib();
        s.log_info("found function at 0x1000");
        s.log_info("unrelated message");
        let hits = s.logs_matching("function");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn log_record_display() {
        let r = LogRecord {
            level: LogLevel::Warn,
            message: "test".into(),
        };
        assert!(r.to_string().contains("WARN"));
    }

    // Alert tests ────────────────────────────────────────────────────────────

    #[test]
    fn alert_stored() {
        let mut s = stdlib();
        s.alert("important");
        assert_eq!(s.alert_count(), 1);
        assert_eq!(s.alerts[0].message, "important");
    }

    // DB tests ───────────────────────────────────────────────────────────────

    #[test]
    fn db_set_get() {
        let mut s = stdlib();
        s.db_set("x", "42");
        assert_eq!(s.db_get("x"), Some("42"));
    }

    #[test]
    fn db_delete() {
        let mut s = stdlib();
        s.db_set("k", "v");
        assert!(s.db_delete("k"));
        assert!(s.db_get("k").is_none());
    }

    #[test]
    fn db_keys() {
        let mut s = stdlib();
        s.db_set("a", "1");
        s.db_set("b", "2");
        let mut keys = s.db_keys();
        keys.sort_unstable();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn db_all_entries() {
        let mut d = PythonDbStore::new();
        d.set("foo", "bar");
        let all = d.all();
        assert_eq!(all.get("foo").map(std::string::String::as_str), Some("bar"));
    }

    #[test]
    fn db_contains() {
        let mut d = PythonDbStore::new();
        d.set("present", "yes");
        assert!(d.contains("present"));
        assert!(!d.contains("absent"));
    }

    // UiInputHandler tests ───────────────────────────────────────────────────

    #[test]
    fn ui_input_returns_preloaded() {
        let mut s = stdlib();
        s.ui_input.push_response("hello");
        assert_eq!(s.ui_input("prompt"), "hello");
    }

    #[test]
    fn ui_input_empty_default() {
        let mut s = stdlib();
        assert_eq!(s.ui_input("prompt"), "");
    }

    #[test]
    fn ui_input_records_calls() {
        let mut s = stdlib();
        s.ui_input.push_response("42");
        s.ui_input("Enter value");
        assert_eq!(s.ui_input.calls_made(), 1);
        assert_eq!(s.ui_input.history[0].0, "Enter value");
    }

    // IdaCompatHelpers tests ─────────────────────────────────────────────────

    #[test]
    fn idc_print_records() {
        let mut s = stdlib();
        s.idc_print("hello from idc");
        assert_eq!(s.ida.print_history.len(), 1);
    }

    #[test]
    fn ask_yn_default_false() {
        let mut s = stdlib();
        assert!(!s.ask_yn(false, "continue?"));
    }

    #[test]
    fn ask_yn_preloaded() {
        let mut s = stdlib();
        s.ida.push_yn(true);
        assert!(s.ask_yn(false, "continue?"));
    }

    #[test]
    fn ask_string_default() {
        let mut s = stdlib();
        assert_eq!(s.ask_string("default_val", "name?"), "default_val");
    }

    #[test]
    fn ask_string_preloaded() {
        let mut s = stdlib();
        s.ida.push_string("custom");
        assert_eq!(s.ask_string("default", "name?"), "custom");
    }

    #[test]
    fn get_imagebase_stub() {
        let s = stdlib();
        assert_eq!(s.ida.get_imagebase(), 0);
    }

    // PythonModuleBuilder tests ──────────────────────────────────────────────

    #[test]
    fn module_builder_register_function() {
        let mut b = PythonModuleBuilder::new("rustre");
        b.register_function("log", "(level, msg)", "Log a message");
        assert_eq!(b.function_count(), 1);
    }

    #[test]
    fn module_builder_register_class() {
        let mut b = PythonModuleBuilder::new("rustre");
        b.register_class("BinaryView", vec!["read", "write"]);
        assert_eq!(b.class_count(), 1);
    }

    #[test]
    fn module_builder_add_submodule() {
        let mut b = PythonModuleBuilder::new("rustre");
        b.add_submodule("db");
        assert_eq!(b.submodules.len(), 1);
    }

    #[test]
    fn module_builder_summary_contains_name() {
        let mut b = PythonModuleBuilder::new("my_module");
        b.register_function("foo", "()", "does foo");
        let s = b.summary();
        assert!(s.contains("my_module"));
        assert!(s.contains("foo"));
    }

    // clear_all tests ────────────────────────────────────────────────────────

    #[test]
    fn clear_all_resets() {
        let mut s = stdlib();
        s.log_info("x");
        s.alert("y");
        s.db_set("k", "v");
        s.clear_all();
        assert_eq!(s.log_count(), 0);
        assert_eq!(s.alert_count(), 0);
        assert!(s.db.is_empty());
    }

    // Shared stdlib tests ────────────────────────────────────────────────────

    #[test]
    fn shared_stdlib_creates_and_logs() {
        let shared = new_shared();
        let mut guard = shared.lock().unwrap();
        guard.log_info("shared test");
        assert_eq!(guard.log_count(), 1);
    }

    #[test]
    fn db_not_empty_after_insert() {
        let mut s = stdlib();
        s.db_set("hello", "world");
        assert!(!s.db.is_empty());
    }

    #[test]
    fn module_builder_function_stub_has_name() {
        let mut b = PythonModuleBuilder::new("m");
        b.register_function("do_thing", "(x)", "does thing");
        assert_eq!(b.functions[0].name, "do_thing");
    }

    #[test]
    fn module_builder_class_stub_has_methods() {
        let mut b = PythonModuleBuilder::new("m");
        b.register_class("Foo", vec!["bar", "baz"]);
        assert_eq!(b.classes[0].methods, vec!["bar", "baz"]);
    }

    #[test]
    fn ida_min_ea_stub() {
        let s = stdlib();
        assert_eq!(s.ida.min_ea(), 0);
    }

    #[test]
    fn ida_max_ea_stub() {
        let s = stdlib();
        assert_eq!(s.ida.max_ea(), u64::MAX);
    }

    #[test]
    fn log_levels_all_stored_at_debug_min() {
        let mut s = stdlib();
        s.min_level = LogLevel::Debug;
        s.log_debug("d");
        s.log_info("i");
        s.log_warn("w");
        s.log_error("e");
        assert_eq!(s.log_count(), 4);
    }
}
