//! Complete Rhai scripting API for `RustRE`.
//!
//! Provides `RhaiFullApi`, `AnalysisApi`, `DebugApi`, `TypeApi`, `SearchApi`,
//! and `ExportApi` — all-in-one Rhai engine configuration for the `RustRE`
//! platform.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString, Map, Scope};
use serde::{Deserialize, Serialize};

use crate::{sat_i64_to_usize, sat_usize_to_i64, trunc_i64_to_u32, trunc_u128_to_u64};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| trunc_u128_to_u64(d.as_millis()))
}

// ── RhaiError ─────────────────────────────────────────────────────────────────

/// Error wrapper for Rhai API operations.
#[derive(Debug, Clone)]
pub struct RhaiApiError(pub String);

impl std::fmt::Display for RhaiApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RhaiApiError {}

// ── RhaiLogEntry ──────────────────────────────────────────────────────────────

/// A log entry produced by the Rhai scripting layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RhaiLogEntry {
    pub timestamp_ms: u64,
    pub level: String,
    pub message: String,
}

// ── AnalysisApi ───────────────────────────────────────────────────────────────

/// Analysis operations exposed to Rhai scripts.
#[derive(Debug, Default, Clone)]
pub struct AnalysisApi {
    /// Cache of analysis results.
    pub results: HashMap<String, String>,
    /// Renamed functions log.
    pub renames: Vec<(u64, String)>,
}

impl AnalysisApi {
    /// Create a new API handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompile a function at `addr` (mock).
    #[must_use]
    pub fn decompile(&mut self, binary_id: &str, addr: u64) -> String {
        let key = format!("{binary_id}:{addr:#x}");
        self.results
            .entry(key)
            .or_insert_with(|| format!("int64_t sub_{addr:x}(void) {{\n    return 0;\n}}"))
            .clone()
    }

    /// Rename a function.
    pub fn rename_function(&mut self, addr: u64, new_name: &str) {
        self.renames.push((addr, new_name.to_string()));
    }

    /// Get xrefs to an address.
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> Vec<u64> {
        vec![addr.wrapping_sub(0x10), addr.wrapping_sub(0x30)]
    }

    /// Get xrefs from an address.
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> Vec<u64> {
        vec![addr + 0x20, addr + 0x40]
    }

    /// Get call graph edges.
    #[must_use]
    pub fn call_graph(&self, addr: u64) -> Vec<(u64, u64)> {
        vec![(addr, addr + 0x80), (addr, addr + 0xC0)]
    }

    /// Analyse control flow (mock: returns number of basic blocks).
    #[must_use]
    pub const fn cfg_block_count(&self, _addr: u64) -> u32 {
        7
    }

    /// Apply a HLIL comment at an address.
    pub fn set_comment(&mut self, addr: u64, comment: &str) {
        let key = format!("comment:{addr:#x}");
        self.results.insert(key, comment.to_string());
    }
}

// ── DebugApi ──────────────────────────────────────────────────────────────────

/// Debugger operations exposed to Rhai scripts.
#[derive(Debug, Default, Clone)]
pub struct DebugApi {
    sessions: HashMap<String, u64>, // session_id → current_ip
    breakpoints: HashMap<String, Vec<u64>>,
}

impl DebugApi {
    /// Create a new debug API handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach to PID.
    pub fn attach(&mut self, pid: u32) -> String {
        let id = format!("dbg-{pid}");
        self.sessions.insert(id.clone(), 0x0);
        self.breakpoints.insert(id.clone(), Vec::new());
        id
    }

    /// Detach.
    pub fn detach(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Set breakpoint.
    pub fn set_bp(&mut self, session_id: &str, addr: u64) -> bool {
        self.breakpoints.get_mut(session_id).is_some_and(|bps| {
            if !bps.contains(&addr) {
                bps.push(addr);
            }
            true
        })
    }

    /// Remove breakpoint.
    pub fn remove_bp(&mut self, session_id: &str, addr: u64) -> bool {
        self.breakpoints.get_mut(session_id).is_some_and(|bps| {
            let before = bps.len();
            bps.retain(|&b| b != addr);
            bps.len() < before
        })
    }

    /// Get current IP.
    #[must_use]
    pub fn get_ip(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).copied()
    }

    /// Step one instruction.
    pub fn step(&mut self, session_id: &str) -> bool {
        self.sessions.get_mut(session_id).is_some_and(|ip| {
            *ip += 3;
            true
        })
    }

    /// Read memory.
    #[must_use]
    pub fn read_mem(&self, session_id: &str, addr: u64, len: usize) -> Vec<u8> {
        if !self.sessions.contains_key(session_id) {
            return Vec::new();
        }
        vec![(addr & 0xff) as u8; len]
    }

    /// List breakpoints.
    #[must_use]
    pub fn list_bps(&self, session_id: &str) -> Vec<u64> {
        self.breakpoints
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Number of sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ── TypeApi ───────────────────────────────────────────────────────────────────

/// Type system operations exposed to Rhai scripts.
#[derive(Debug, Default, Clone)]
pub struct TypeApi {
    types: HashMap<String, (String, Vec<String>)>, // name → (kind, fields)
}

impl TypeApi {
    /// Create a new type API handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a struct type.
    pub fn define_struct(&mut self, name: &str, fields: Vec<String>) -> bool {
        self.types
            .insert(name.to_string(), ("struct".into(), fields));
        true
    }

    /// Define an enum type.
    pub fn define_enum(&mut self, name: &str, variants: Vec<String>) -> bool {
        self.types
            .insert(name.to_string(), ("enum".into(), variants));
        true
    }

    /// Check if a type is defined.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// Remove a type.
    pub fn remove_type(&mut self, name: &str) -> bool {
        self.types.remove(name).is_some()
    }

    /// Get type kind.
    #[must_use]
    pub fn kind(&self, name: &str) -> Option<&str> {
        self.types.get(name).map(|(k, _)| k.as_str())
    }

    /// Get type fields.
    #[must_use]
    pub fn fields(&self, name: &str) -> Vec<String> {
        self.types
            .get(name)
            .map(|(_, f)| f.clone())
            .unwrap_or_default()
    }

    /// List all type names.
    #[must_use]
    pub fn type_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.types.keys().cloned().collect();
        names.sort();
        names
    }

    /// Number of defined types.
    #[must_use]
    pub fn count(&self) -> usize {
        self.types.len()
    }
}

// ── SearchApi ─────────────────────────────────────────────────────────────────

/// Pattern and string search operations exposed to Rhai scripts.
#[derive(Debug, Default, Clone)]
pub struct SearchApi;

impl SearchApi {
    /// Create a new search API.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Search for a byte pattern (mock).
    #[must_use]
    pub fn search_bytes(&self, _binary_id: &str, pattern: &[u8]) -> Vec<u64> {
        if pattern.is_empty() {
            return Vec::new();
        }
        vec![0x1200, 0x2400]
    }

    /// Search for a string (mock).
    #[must_use]
    pub fn search_string(&self, _binary_id: &str, query: &str) -> Vec<(u64, String)> {
        if query.is_empty() {
            return Vec::new();
        }
        vec![
            (0x2000, format!("0x2000: {query}")),
            (0x3000, format!("0x3000: {query}")),
        ]
    }

    /// Search for functions by name prefix.
    #[must_use]
    pub fn search_function(&self, _binary_id: &str, prefix: &str) -> Vec<(u64, String)> {
        ["entry", "main", "helper", "WinMain"]
            .iter()
            .filter(|n| n.starts_with(prefix))
            .enumerate()
            .map(|(i, &n)| (0x1400 + i as u64 * 0x80, n.to_string()))
            .collect()
    }

    /// Search for YARA-like patterns (mock: always returns one hit).
    #[must_use]
    pub fn yara_scan(&self, _binary_id: &str, rule: &str) -> Vec<u64> {
        if rule.is_empty() {
            return Vec::new();
        }
        vec![0x5000]
    }
}

// ── ExportApi ─────────────────────────────────────────────────────────────────

/// Export/reporting operations exposed to Rhai scripts.
#[derive(Debug, Default, Clone)]
pub struct ExportApi {
    /// Export records.
    exports: Vec<ExportRecord>,
}

/// A single export record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub format: String,
    pub destination: String,
    pub timestamp: u64,
    pub size_bytes: u64,
}

impl ExportApi {
    /// Create a new export API.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Export as JSON (mock).
    pub fn export_json(&mut self, destination: &str, _data: &str) -> u64 {
        let r = ExportRecord {
            format: "json".into(),
            destination: destination.to_string(),
            timestamp: now_ms(),
            size_bytes: 1024,
        };
        self.exports.push(r);
        1024
    }

    /// Export as CSV (mock).
    pub fn export_csv(&mut self, destination: &str, _rows: &[Vec<String>]) -> u64 {
        let r = ExportRecord {
            format: "csv".into(),
            destination: destination.to_string(),
            timestamp: now_ms(),
            size_bytes: 512,
        };
        self.exports.push(r);
        512
    }

    /// Export as YARA rules (mock).
    pub fn export_yara(&mut self, destination: &str, _rules: &[String]) -> u64 {
        let r = ExportRecord {
            format: "yara".into(),
            destination: destination.to_string(),
            timestamp: now_ms(),
            size_bytes: 2048,
        };
        self.exports.push(r);
        2048
    }

    /// Number of export records.
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.exports.len()
    }

    /// List export destinations.
    #[must_use]
    pub fn destinations(&self) -> Vec<String> {
        self.exports.iter().map(|e| e.destination.clone()).collect()
    }
}

// ── RhaiFullApi ───────────────────────────────────────────────────────────────

/// Complete Rhai scripting engine for `RustRE`.
///
/// Registers all `RustRE` APIs into a `rhai::Engine` and provides an
/// `eval` / `exec` interface with integrated logging.
pub struct RhaiFullApi {
    engine: Engine,
    analysis: Arc<Mutex<AnalysisApi>>,
    debug: Arc<Mutex<DebugApi>>,
    types: Arc<Mutex<TypeApi>>,
    search: Arc<Mutex<SearchApi>>,
    export: Arc<Mutex<ExportApi>>,
    /// Execution log.
    pub log: Vec<RhaiLogEntry>,
}

impl Default for RhaiFullApi {
    fn default() -> Self {
        Self::new()
    }
}

impl RhaiFullApi {
    /// Create a new API instance with a fresh Rhai engine.
    #[must_use]
    pub fn new() -> Self {
        let mut api = Self {
            engine: Engine::new(),
            analysis: Arc::new(Mutex::new(AnalysisApi::new())),
            debug: Arc::new(Mutex::new(DebugApi::new())),
            types: Arc::new(Mutex::new(TypeApi::new())),
            search: Arc::new(Mutex::new(SearchApi::new())),
            export: Arc::new(Mutex::new(ExportApi::new())),
            log: Vec::new(),
        };
        api.register_functions();
        api
    }

    /// Register all `RustRE` APIs into the Rhai engine.
    fn register_functions(&mut self) {
        self.register_analysis_fns();
        self.register_debug_fns();
        self.register_type_fns();
        self.register_search_fns();
        self.register_export_fns();
    }

    fn register_analysis_fns(&mut self) {
        let an = Arc::clone(&self.analysis);
        self.engine.register_fn(
            "re_decompile",
            move |binary_id: ImmutableString, addr: i64| {
                an.lock().unwrap().decompile(&binary_id, addr.cast_unsigned())
            },
        );
        let an2 = Arc::clone(&self.analysis);
        self.engine.register_fn("re_rename_fn", move |addr: i64, name: ImmutableString| {
            an2.lock().unwrap().rename_function(addr.cast_unsigned(), &name);
        });
        let an3 = Arc::clone(&self.analysis);
        self.engine.register_fn("re_xrefs_to", move |addr: i64| -> Vec<Dynamic> {
            an3.lock().unwrap().xrefs_to(addr.cast_unsigned())
                .into_iter().map(|a| Dynamic::from_int(a.cast_signed())).collect()
        });
        let an4 = Arc::clone(&self.analysis);
        self.engine.register_fn("re_cfg_blocks", move |addr: i64| -> i64 {
            i64::from(an4.lock().unwrap().cfg_block_count(addr.cast_unsigned()))
        });
        let an5 = Arc::clone(&self.analysis);
        self.engine.register_fn("re_set_comment", move |addr: i64, comment: ImmutableString| {
            an5.lock().unwrap().set_comment(addr.cast_unsigned(), &comment);
        });
    }

    fn register_debug_fns(&mut self) {
        let dbg = Arc::clone(&self.debug);
        self.engine.register_fn("re_debug_attach", move |pid: i64| -> ImmutableString {
            dbg.lock().unwrap().attach(trunc_i64_to_u32(pid)).into()
        });
        let dbg2 = Arc::clone(&self.debug);
        self.engine.register_fn("re_debug_detach", move |id: ImmutableString| {
            dbg2.lock().unwrap().detach(&id)
        });
        let dbg3 = Arc::clone(&self.debug);
        self.engine.register_fn("re_set_bp", move |sid: ImmutableString, addr: i64| {
            dbg3.lock().unwrap().set_bp(&sid, addr.cast_unsigned())
        });
        let dbg4 = Arc::clone(&self.debug);
        self.engine.register_fn("re_step", move |sid: ImmutableString| {
            dbg4.lock().unwrap().step(&sid)
        });
        let dbg5 = Arc::clone(&self.debug);
        self.engine.register_fn(
            "re_read_mem",
            move |sid: ImmutableString, addr: i64, len: i64| -> Vec<Dynamic> {
                dbg5.lock().unwrap()
                    .read_mem(&sid, addr.cast_unsigned(), sat_i64_to_usize(len))
                    .into_iter().map(|b| Dynamic::from_int(i64::from(b))).collect()
            },
        );
    }

    fn register_type_fns(&mut self) {
        let ty = Arc::clone(&self.types);
        self.engine.register_fn(
            "re_define_struct",
            move |name: ImmutableString, fields: Vec<Dynamic>| {
                let fs: Vec<String> = fields.into_iter().map(|d| d.to_string()).collect();
                ty.lock().unwrap().define_struct(&name, fs)
            },
        );
        let ty2 = Arc::clone(&self.types);
        self.engine.register_fn("re_has_type", move |name: ImmutableString| {
            ty2.lock().unwrap().contains(&name)
        });
        let ty3 = Arc::clone(&self.types);
        self.engine.register_fn("re_type_kind", move |name: ImmutableString| -> ImmutableString {
            ty3.lock().unwrap().kind(&name).unwrap_or("unknown").into()
        });
    }

    fn register_search_fns(&mut self) {
        let srch = Arc::clone(&self.search);
        self.engine.register_fn(
            "re_search_string",
            move |binary_id: ImmutableString, query: ImmutableString| -> Vec<Dynamic> {
                srch.lock().unwrap().search_string(&binary_id, &query)
                    .into_iter().map(|(addr, ctx)| {
                        let mut m = Map::new();
                        m.insert("addr".into(), Dynamic::from_int(addr.cast_signed()));
                        m.insert("context".into(), Dynamic::from(ctx));
                        Dynamic::from_map(m)
                    }).collect()
            },
        );
        let srch2 = Arc::clone(&self.search);
        self.engine.register_fn(
            "re_search_fn",
            move |binary_id: ImmutableString, prefix: ImmutableString| -> Vec<Dynamic> {
                srch2.lock().unwrap().search_function(&binary_id, &prefix)
                    .into_iter().map(|(addr, name)| {
                        let mut m = Map::new();
                        m.insert("addr".into(), Dynamic::from_int(addr.cast_signed()));
                        m.insert("name".into(), Dynamic::from(name));
                        Dynamic::from_map(m)
                    }).collect()
            },
        );
    }

    fn register_export_fns(&mut self) {
        let exp = Arc::clone(&self.export);
        self.engine.register_fn(
            "re_export_json",
            move |dest: ImmutableString, data: ImmutableString| -> i64 {
                exp.lock().unwrap().export_json(&dest, &data).cast_signed()
            },
        );
        let exp2 = Arc::clone(&self.export);
        self.engine.register_fn("re_export_count", move || -> i64 {
            sat_usize_to_i64(exp2.lock().unwrap().export_count())
        });
    }

    /// Evaluate a Rhai expression.
    ///
    /// # Errors
    /// Returns a Rhai evaluation error if the code fails.
    pub fn eval<T: Clone + rhai::Variant>(&mut self, code: &str) -> Result<T, Box<EvalAltResult>> {
        let t0 = now_ms();
        let result = self.engine.eval::<T>(code);
        let elapsed = now_ms() - t0;
        self.log.push(RhaiLogEntry {
            timestamp_ms: t0,
            level: if result.is_ok() { "info" } else { "error" }.into(),
            message: format!("eval in {elapsed}ms"),
        });
        result
    }

    /// Execute Rhai code (side-effects only).
    ///
    /// # Errors
    /// Returns a Rhai evaluation error if the code fails.
    pub fn exec(&mut self, code: &str) -> Result<(), Box<EvalAltResult>> {
        self.engine.run(code)
    }

    /// Evaluate with a scope (allows persistent variables).
    ///
    /// # Errors
    /// Returns a Rhai evaluation error if the code fails.
    pub fn eval_with_scope<T: Clone + rhai::Variant>(
        &mut self,
        scope: &mut Scope,
        code: &str,
    ) -> Result<T, Box<EvalAltResult>> {
        self.engine.eval_with_scope::<T>(scope, code)
    }

    /// Return a reference to the analysis API.
    #[must_use]
    pub const fn analysis(&self) -> &Arc<Mutex<AnalysisApi>> {
        &self.analysis
    }

    /// Return a reference to the debug API.
    #[must_use]
    pub const fn debug_api(&self) -> &Arc<Mutex<DebugApi>> {
        &self.debug
    }

    /// Return a reference to the type API.
    #[must_use]
    pub const fn type_api(&self) -> &Arc<Mutex<TypeApi>> {
        &self.types
    }

    /// Return a reference to the search API.
    #[must_use]
    pub const fn search_api(&self) -> &Arc<Mutex<SearchApi>> {
        &self.search
    }

    /// Return a reference to the export API.
    #[must_use]
    pub const fn export_api(&self) -> &Arc<Mutex<ExportApi>> {
        &self.export
    }

    /// Number of log entries.
    #[must_use]
    pub const fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Clear the log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

// ── RhaiSession ───────────────────────────────────────────────────────────────

/// A named Rhai scripting session with persistent scope.
pub struct RhaiSession {
    pub id: String,
    pub scope: rhai::Scope<'static>,
    pub api: RhaiFullApi,
    pub history: Vec<String>,
    pub max_history: usize,
}

impl RhaiSession {
    /// Create a new session.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            scope: rhai::Scope::new(),
            api: RhaiFullApi::new(),
            history: Vec::new(),
            max_history: 100,
        }
    }

    /// Evaluate code with the persistent scope.
    ///
    /// # Errors
    /// Returns a Rhai evaluation error if the code fails to compile or execute.
    pub fn eval<T: Clone + rhai::Variant>(
        &mut self,
        code: &str,
    ) -> Result<T, Box<rhai::EvalAltResult>> {
        self.history.push(code.to_string());
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
        self.api.eval_with_scope::<T>(&mut self.scope, code)
    }

    /// Execute code for side effects.
    ///
    /// # Errors
    /// Returns a Rhai evaluation error if the code fails to compile or execute.
    pub fn exec(&mut self, code: &str) -> Result<(), Box<rhai::EvalAltResult>> {
        self.history.push(code.to_string());
        self.api.exec(code)
    }

    /// Return the number of history entries.
    #[must_use]
    pub const fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Clear history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Return a session summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "RhaiSession[id={}, history={}, log={}]",
            self.id,
            self.history.len(),
            self.api.log_len(),
        )
    }
}

/// Manager for multiple named Rhai sessions.
#[derive(Default)]
pub struct RhaiSessionManager {
    sessions: HashMap<String, RhaiSession>,
}

impl RhaiSessionManager {
    /// Create a new manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session.
    pub fn create(&mut self, id: impl Into<String>) -> &mut RhaiSession {
        let id = id.into();
        self.sessions
            .entry(id.clone())
            .or_insert_with(|| RhaiSession::new(&id))
    }

    /// Remove a session.
    pub fn remove(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Get a session.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&RhaiSession> {
        self.sessions.get(id)
    }

    /// Number of sessions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// All session IDs.
    #[must_use]
    pub fn ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.sessions.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }
}

// ── RhaiAnalysisReport ────────────────────────────────────────────────────────

/// A summary report produced by `RhaiFullApi` after running analysis scripts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RhaiAnalysisReport {
    pub binary_id: String,
    pub functions_analysed: usize,
    pub functions_renamed: usize,
    pub xrefs_found: usize,
    pub types_defined: usize,
    pub search_hits: usize,
    pub exports_generated: usize,
    pub elapsed_ms: u64,
}

impl RhaiAnalysisReport {
    /// Create from the API components.
    ///
    /// # Panics
    /// Panics if any internal lock is poisoned.
    #[must_use]
    pub fn from_api(api: &RhaiFullApi, binary_id: impl Into<String>) -> Self {
        let analysis = api.analysis().lock().unwrap();
        let types = api.type_api().lock().unwrap();
        let export = api.export_api().lock().unwrap();
        Self {
            binary_id: binary_id.into(),
            functions_analysed: analysis.results.len(),
            functions_renamed: analysis.renames.len(),
            xrefs_found: 0,
            types_defined: types.count(),
            search_hits: 0,
            exports_generated: export.export_count(),
            elapsed_ms: api.log.last().map_or(0, |e| e.timestamp_ms),
        }
    }

    /// Return `true` if any work was done.
    #[must_use]
    pub const fn has_results(&self) -> bool {
        self.functions_analysed > 0
            || self.functions_renamed > 0
            || self.types_defined > 0
            || self.exports_generated > 0
    }

    /// Serialise to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ── RhaiScriptLibrary ─────────────────────────────────────────────────────────

/// A named library of Rhai scripts that can be loaded into a `RhaiFullApi`.
#[derive(Debug, Default)]
pub struct RhaiScriptLibrary {
    scripts: HashMap<String, String>,
}

impl RhaiScriptLibrary {
    /// Create a new, empty library.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a script to the library.
    pub fn add(&mut self, name: impl Into<String>, code: impl Into<String>) {
        self.scripts.insert(name.into(), code.into());
    }

    /// Remove a script by name.
    pub fn remove(&mut self, name: &str) -> bool {
        self.scripts.remove(name).is_some()
    }

    /// Get a script by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.scripts.get(name).map(String::as_str)
    }

    /// Execute a named script against a `RhaiFullApi`.
    ///
    /// # Errors
    /// Returns a Rhai error if the script is not found or fails to execute.
    pub fn run(&self, name: &str, api: &mut RhaiFullApi) -> Result<(), Box<rhai::EvalAltResult>> {
        let code = self
            .scripts
            .get(name)
            .ok_or_else(|| {
                Box::new(rhai::EvalAltResult::ErrorRuntime(
                    format!("script '{name}' not found").into(),
                    rhai::Position::NONE,
                ))
            })?
            .clone();
        api.exec(&code)
    }

    /// Number of scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Return all script names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut n: Vec<&str> = self.scripts.keys().map(String::as_str).collect();
        n.sort_unstable();
        n
    }
}

// ── RhaiConfig ────────────────────────────────────────────────────────────────

/// Configuration for the Rhai scripting engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RhaiConfig {
    /// Maximum call stack depth.
    pub max_call_depth: usize,
    /// Maximum number of operations per script run.
    pub max_operations: u64,
    /// Whether the engine allows `eval` calls.
    pub allow_eval: bool,
    /// Whether loop expressions are allowed.
    pub allow_loop_expressions: bool,
    /// Optimization level: "none", "simple", "full".
    pub optimization_level: String,
    /// Whether to enable strict variables mode.
    pub strict_variables: bool,
}

impl Default for RhaiConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 64,
            max_operations: 1_000_000,
            allow_eval: false,
            allow_loop_expressions: true,
            optimization_level: "simple".into(),
            strict_variables: false,
        }
    }
}

impl RhaiConfig {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a sandboxed (restricted) config.
    #[must_use]
    pub fn sandboxed() -> Self {
        Self {
            max_call_depth: 16,
            max_operations: 10_000,
            allow_eval: false,
            allow_loop_expressions: false,
            ..Default::default()
        }
    }

    /// Apply this config to a Rhai engine.
    pub fn apply_to(&self, engine: &mut rhai::Engine) {
        engine.set_max_call_levels(self.max_call_depth);
        engine.set_max_operations(self.max_operations);
        if !self.allow_eval {
            engine.disable_symbol("eval");
        }
    }

    /// Validate the config.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_call_depth > 0
            && self.max_operations > 0
            && ["none", "simple", "full"].contains(&self.optimization_level.as_str())
    }
}

// ── RhaiModuleRegistry ────────────────────────────────────────────────────────

/// Registry of named Rhai modules.
#[derive(Debug, Default)]
pub struct RhaiModuleRegistry {
    modules: HashMap<String, Vec<(String, String)>>, // module_name → [(fn_name, description)]
}

impl RhaiModuleRegistry {
    /// Create a new registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module with its exported functions.
    pub fn register(&mut self, module_name: impl Into<String>, functions: Vec<(String, String)>) {
        self.modules.insert(module_name.into(), functions);
    }

    /// Look up a module.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[(String, String)]> {
        self.modules.get(name).map(Vec::as_slice)
    }

    /// Number of modules.
    #[must_use]
    pub fn count(&self) -> usize {
        self.modules.len()
    }

    /// Return all module names.
    #[must_use]
    pub fn module_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.modules.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Generate Rhai documentation for all modules.
    #[must_use]
    pub fn generate_docs(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        for (name, fns) in &self.modules {
            lines.push(format!("// Module: {name}"));
            for (fn_name, desc) in fns {
                lines.push(format!("// {fn_name}: {desc}"));
            }
            lines.push(String::new());
        }
        lines.join("\n")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AnalysisApi ──────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_decompile() {
        let mut a = AnalysisApi::new();
        let code = a.decompile("bv1", 0x1400);
        assert!(code.contains("sub_1400"));
    }

    #[test]
    fn test_analysis_decompile_cached() {
        let mut a = AnalysisApi::new();
        let r1 = a.decompile("bv1", 0x1400);
        let r2 = a.decompile("bv1", 0x1400);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_analysis_rename() {
        let mut a = AnalysisApi::new();
        a.rename_function(0x1400, "malware_init");
        assert_eq!(a.renames.len(), 1);
        assert_eq!(a.renames[0].1, "malware_init");
    }

    #[test]
    fn test_analysis_xrefs_to() {
        let a = AnalysisApi::new();
        let x = a.xrefs_to(0x1400);
        assert_eq!(x.len(), 2);
    }

    #[test]
    fn test_analysis_xrefs_from() {
        let a = AnalysisApi::new();
        let x = a.xrefs_from(0x1400);
        assert!(!x.is_empty());
    }

    #[test]
    fn test_analysis_cfg_blocks() {
        let a = AnalysisApi::new();
        assert_eq!(a.cfg_block_count(0x1400), 7);
    }

    #[test]
    fn test_analysis_call_graph() {
        let a = AnalysisApi::new();
        let edges = a.call_graph(0x1400);
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].0, 0x1400);
    }

    // ── DebugApi ─────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_attach_detach() {
        let mut d = DebugApi::new();
        let id = d.attach(1234);
        assert_eq!(id, "dbg-1234");
        assert_eq!(d.session_count(), 1);
        assert!(d.detach(&id));
        assert_eq!(d.session_count(), 0);
    }

    #[test]
    fn test_debug_breakpoints() {
        let mut d = DebugApi::new();
        let id = d.attach(1234);
        d.set_bp(&id, 0x401000);
        d.set_bp(&id, 0x402000);
        let bps = d.list_bps(&id);
        assert_eq!(bps.len(), 2);
        assert!(d.remove_bp(&id, 0x401000));
        assert_eq!(d.list_bps(&id).len(), 1);
    }

    #[test]
    fn test_debug_step() {
        let mut d = DebugApi::new();
        let id = d.attach(9999);
        let ip0 = d.get_ip(&id).unwrap();
        d.step(&id);
        assert!(d.get_ip(&id).unwrap() > ip0);
    }

    #[test]
    fn test_debug_read_mem() {
        let mut d = DebugApi::new();
        let id = d.attach(1234);
        let mem = d.read_mem(&id, 0x1000, 8);
        assert_eq!(mem.len(), 8);
    }

    #[test]
    fn test_debug_missing_session() {
        let d = DebugApi::new();
        assert!(d.get_ip("missing").is_none());
        assert!(d.read_mem("missing", 0, 4).is_empty());
    }

    // ── TypeApi ──────────────────────────────────────────────────────────────

    #[test]
    fn test_type_define_struct() {
        let mut t = TypeApi::new();
        assert!(t.define_struct("POINT", vec!["x".into(), "y".into()]));
        assert!(t.contains("POINT"));
        assert_eq!(t.kind("POINT"), Some("struct"));
    }

    #[test]
    fn test_type_define_enum() {
        let mut t = TypeApi::new();
        assert!(t.define_enum("Color", vec!["Red".into(), "Green".into()]));
        assert_eq!(t.kind("Color"), Some("enum"));
    }

    #[test]
    fn test_type_fields() {
        let mut t = TypeApi::new();
        t.define_struct("T", vec!["a".into(), "b".into()]);
        assert_eq!(t.fields("T"), vec!["a", "b"]);
    }

    #[test]
    fn test_type_remove() {
        let mut t = TypeApi::new();
        t.define_struct("X", vec![]);
        assert!(t.remove_type("X"));
        assert!(!t.contains("X"));
    }

    #[test]
    fn test_type_names_sorted() {
        let mut t = TypeApi::new();
        t.define_struct("Beta", vec![]);
        t.define_struct("Alpha", vec![]);
        let names = t.type_names();
        assert_eq!(names[0], "Alpha");
    }

    // ── SearchApi ────────────────────────────────────────────────────────────

    #[test]
    fn test_search_string() {
        let s = SearchApi::new();
        let results = s.search_string("bv1", "CreateRemoteThread");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 0x2000);
    }

    #[test]
    fn test_search_string_empty() {
        let s = SearchApi::new();
        assert!(s.search_string("bv1", "").is_empty());
    }

    #[test]
    fn test_search_bytes() {
        let s = SearchApi::new();
        let hits = s.search_bytes("bv1", &[0x90]);
        assert_eq!(hits.len(), 2);
    }

    // ── RhaiScriptLibrary ────────────────────────────────────────────────────

    #[test]
    fn test_library_add_and_run() {
        let mut lib = RhaiScriptLibrary::new();
        lib.add("hello", "let x = 42;");
        let mut api = RhaiFullApi::new();
        assert!(lib.run("hello", &mut api).is_ok());
    }

    #[test]
    fn test_library_missing_script_error() {
        let lib = RhaiScriptLibrary::new();
        let mut api = RhaiFullApi::new();
        assert!(lib.run("nonexistent", &mut api).is_err());
    }

    #[test]
    fn test_library_get() {
        let mut lib = RhaiScriptLibrary::new();
        lib.add("s1", "return 1");
        assert_eq!(lib.get("s1"), Some("return 1"));
        assert!(lib.get("missing").is_none());
    }

    #[test]
    fn test_library_remove() {
        let mut lib = RhaiScriptLibrary::new();
        lib.add("x", "code");
        assert!(lib.remove("x"));
        assert_eq!(lib.len(), 0);
    }

    #[test]
    fn test_library_names_sorted() {
        let mut lib = RhaiScriptLibrary::new();
        lib.add("beta", "");
        lib.add("alpha", "");
        let names = lib.names();
        assert_eq!(names[0], "alpha");
    }

    // ── RhaiConfig ───────────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = RhaiConfig::new();
        assert_eq!(cfg.max_call_depth, 64);
        assert!(cfg.is_valid());
    }

    #[test]
    fn test_config_sandboxed() {
        let cfg = RhaiConfig::sandboxed();
        assert_eq!(cfg.max_call_depth, 16);
        assert!(!cfg.allow_eval);
    }

    #[test]
    fn test_config_invalid_optimization() {
        let mut cfg = RhaiConfig::new();
        cfg.optimization_level = "invalid".into();
        assert!(!cfg.is_valid());
    }

    #[test]
    fn test_config_apply_to_engine() {
        let cfg = RhaiConfig::sandboxed();
        let mut engine = rhai::Engine::new();
        cfg.apply_to(&mut engine);
        // Just verify it doesn't panic.
        assert!(cfg.max_call_depth > 0);
    }

    // ── RhaiModuleRegistry ───────────────────────────────────────────────────

    #[test]
    fn test_module_registry_register_and_get() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register(
            "analysis",
            vec![("decompile".into(), "Decompile a function".into())],
        );
        assert!(reg.get("analysis").is_some());
    }

    #[test]
    fn test_module_registry_count() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register("a", vec![]);
        reg.register("b", vec![]);
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn test_module_registry_names_sorted() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register("zebra", vec![]);
        reg.register("alpha", vec![]);
        let names = reg.module_names();
        assert_eq!(names[0], "alpha");
    }

    #[test]
    fn test_module_registry_generate_docs() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register("analysis", vec![("decompile".into(), "Decompile".into())]);
        let docs = reg.generate_docs();
        assert!(docs.contains("analysis"));
        assert!(docs.contains("decompile"));
    }

    #[test]
    fn test_search_function() {
        let s = SearchApi::new();
        let results = s.search_function("bv1", "ma");
        assert!(results.iter().any(|(_, n)| n == "main"));
    }

    #[test]
    fn test_search_yara() {
        let s = SearchApi::new();
        let hits = s.yara_scan("bv1", "rule detect_emotet { ... }");
        assert!(!hits.is_empty());
    }

    // ── ExportApi ────────────────────────────────────────────────────────────

    #[test]
    fn test_export_json() {
        let mut e = ExportApi::new();
        let bytes = e.export_json("/tmp/out.json", "{}");
        assert_eq!(bytes, 1024);
        assert_eq!(e.export_count(), 1);
    }

    #[test]
    fn test_export_csv() {
        let mut e = ExportApi::new();
        let bytes = e.export_csv("/tmp/out.csv", &[vec!["a".into(), "b".into()]]);
        assert_eq!(bytes, 512);
    }

    #[test]
    fn test_export_yara() {
        let mut e = ExportApi::new();
        let bytes = e.export_yara("/tmp/rules.yar", &["rule r {}".into()]);
        assert_eq!(bytes, 2048);
    }

    #[test]
    fn test_export_destinations() {
        let mut e = ExportApi::new();
        e.export_json("/tmp/a.json", "{}");
        e.export_csv("/tmp/b.csv", &[]);
        let dests = e.destinations();
        assert!(dests.contains(&"/tmp/a.json".to_string()));
        assert!(dests.contains(&"/tmp/b.csv".to_string()));
    }

    // ── RhaiFullApi ──────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_eval_arithmetic() {
        let mut api = RhaiFullApi::new();
        let result: i64 = api.eval("1 + 2 * 3").unwrap();
        assert_eq!(result, 7);
    }

    #[test]
    fn test_rhai_eval_string() {
        let mut api = RhaiFullApi::new();
        let result: String = api.eval(r#""hello" + " world""#).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_rhai_exec_side_effect() {
        let mut api = RhaiFullApi::new();
        let mut scope = Scope::new();
        scope.push("x", 0i64);
        api.eval_with_scope::<()>(&mut scope, "x = 42;").unwrap();
        let val: i64 = scope.get_value::<i64>("x").unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_rhai_decompile_via_script() {
        let mut api = RhaiFullApi::new();
        let result: String = api.eval(r#"re_decompile("bv1", 0x1400)"#).unwrap();
        assert!(result.contains("sub_1400"));
    }

    #[test]
    fn test_rhai_rename_fn_via_script() {
        let mut api = RhaiFullApi::new();
        api.exec(r#"re_rename_fn(0x1400, "malware_entry")"#)
            .unwrap();
        let renames = api.analysis().lock().unwrap().renames.clone();
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].1, "malware_entry");
    }

    #[test]
    fn test_rhai_xrefs_to_via_script() {
        let mut api = RhaiFullApi::new();
        let result: Vec<Dynamic> = api.eval("re_xrefs_to(0x1400)").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_rhai_debug_attach_via_script() {
        let mut api = RhaiFullApi::new();
        let id: String = api.eval("re_debug_attach(9999)").unwrap();
        assert_eq!(id, "dbg-9999");
    }

    #[test]
    fn test_rhai_set_bp_via_script() {
        let mut api = RhaiFullApi::new();
        api.exec("let sid = re_debug_attach(1234); re_set_bp(sid, 0x401000);")
            .unwrap();
        let bps = api.debug_api().lock().unwrap().list_bps("dbg-1234");
        assert!(bps.contains(&0x401000));
    }

    #[test]
    fn test_rhai_define_struct_via_script() {
        let mut api = RhaiFullApi::new();
        api.exec(r#"re_define_struct("POINT", ["x", "y"]);"#)
            .unwrap();
        assert!(api.type_api().lock().unwrap().contains("POINT"));
    }

    #[test]
    fn test_rhai_search_string_via_script() {
        let mut api = RhaiFullApi::new();
        let results: Vec<Dynamic> = api
            .eval(r#"re_search_string("bv1", "CreateRemoteThread")"#)
            .unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_rhai_export_json_via_script() {
        let mut api = RhaiFullApi::new();
        let bytes: i64 = api
            .eval(r#"re_export_json("/tmp/out.json", "{}")"#)
            .unwrap();
        assert_eq!(bytes, 1024);
    }

    #[test]
    fn test_rhai_export_count_via_script() {
        let mut api = RhaiFullApi::new();
        api.exec(r#"re_export_json("/tmp/a.json", "{}")"#).unwrap();
        let count: i64 = api.eval("re_export_count()").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rhai_log_populated() {
        let mut api = RhaiFullApi::new();
        api.eval::<i64>("1 + 1").unwrap();
        assert!(api.log_len() > 0);
    }

    #[test]
    fn test_rhai_clear_log() {
        let mut api = RhaiFullApi::new();
        api.eval::<i64>("1").unwrap();
        api.clear_log();
        assert_eq!(api.log_len(), 0);
    }

    #[test]
    fn test_rhai_cfg_blocks() {
        let mut api = RhaiFullApi::new();
        let count: i64 = api.eval("re_cfg_blocks(0x1400)").unwrap();
        assert_eq!(count, 7);
    }

    // ── RhaiAnalysisReport ───────────────────────────────────────────────────

    #[test]
    fn test_report_empty_api() {
        let api = RhaiFullApi::new();
        let report = RhaiAnalysisReport::from_api(&api, "bv1");
        assert_eq!(report.binary_id, "bv1");
        assert!(!report.has_results());
    }

    #[test]
    fn test_report_after_operations() {
        let mut api = RhaiFullApi::new();
        api.exec(r#"re_decompile("bv1", 0x1400)"#).unwrap();
        api.exec(r#"re_define_struct("Point", ["x", "y"])"#)
            .unwrap();
        api.exec(r#"re_export_json("/tmp/out.json", "{}")"#)
            .unwrap();
        let report = RhaiAnalysisReport::from_api(&api, "bv1");
        assert!(report.has_results());
        assert!(report.types_defined > 0);
        assert!(report.exports_generated > 0);
    }

    #[test]
    fn test_report_to_json() {
        let api = RhaiFullApi::new();
        let report = RhaiAnalysisReport::from_api(&api, "bv1");
        let json = report.to_json();
        assert!(json.contains("bv1"));
        assert!(json.contains("functions_analysed"));
    }

    #[test]
    fn test_report_renames_tracked() {
        let mut api = RhaiFullApi::new();
        api.exec(r#"re_rename_fn(0x1400, "init")"#).unwrap();
        api.exec(r#"re_rename_fn(0x1480, "main_loop")"#).unwrap();
        let report = RhaiAnalysisReport::from_api(&api, "bv1");
        assert_eq!(report.functions_renamed, 2);
    }

    // ── RhaiSession ──────────────────────────────────────────────────────────

    #[test]
    fn test_session_eval() {
        let mut s = RhaiSession::new("s1");
        let result: i64 = s.eval("1 + 1").unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn test_session_history() {
        let mut s = RhaiSession::new("s1");
        s.eval::<i64>("1").unwrap();
        s.eval::<i64>("2").unwrap();
        assert_eq!(s.history_len(), 2);
    }

    #[test]
    fn test_session_clear_history() {
        let mut s = RhaiSession::new("s1");
        s.eval::<i64>("1").unwrap();
        s.clear_history();
        assert_eq!(s.history_len(), 0);
    }

    #[test]
    fn test_session_persistent_scope() {
        let mut s = RhaiSession::new("s1");
        s.eval::<()>("let x = 42;").unwrap();
        let x: i64 = s.eval("x").unwrap();
        assert_eq!(x, 42);
    }

    #[test]
    fn test_session_summary() {
        let s = RhaiSession::new("my-session");
        let summary = s.summary();
        assert!(summary.contains("my-session"));
    }

    // ── RhaiSessionManager ───────────────────────────────────────────────────

    #[test]
    fn test_session_manager_create() {
        let mut mgr = RhaiSessionManager::new();
        mgr.create("s1");
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_session_manager_remove() {
        let mut mgr = RhaiSessionManager::new();
        mgr.create("s1");
        assert!(mgr.remove("s1"));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_session_manager_get() {
        let mut mgr = RhaiSessionManager::new();
        mgr.create("s1");
        assert!(mgr.get("s1").is_some());
        assert!(mgr.get("missing").is_none());
    }

    #[test]
    fn test_session_manager_ids_sorted() {
        let mut mgr = RhaiSessionManager::new();
        mgr.create("beta");
        mgr.create("alpha");
        let ids = mgr.ids();
        assert_eq!(ids[0], "alpha");
    }
}
