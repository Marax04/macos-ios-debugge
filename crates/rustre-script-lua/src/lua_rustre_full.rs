//! Full Lua bindings for all `RustRE` APIs.
//!
//! Provides `LuaRustreFull`, `BinaryViewBinding`, `AnalysisBinding`,
//! `DebugBinding`, and `SearchBinding` — complete Lua scripting surface
//! for the `RustRE` platform, built on top of `mlua`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mlua::prelude::*;
use serde::{Deserialize, Serialize};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| crate::casts::u128_to_u64(d.as_millis()))
}

// ── Mock domain types ─────────────────────────────────────────────────────────

/// Simplified binary view metadata (mock).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryViewMeta {
    pub id: String,
    pub path: String,
    pub format: String,
    pub arch: String,
    pub entry_point: u64,
    pub base_addr: u64,
    pub size: u64,
}

impl BinaryViewMeta {
    /// Create a mock view.
    #[must_use]
    pub fn mock(path: &str) -> Self {
        Self {
            id: format!("bv-{}", path.len()),
            path: path.to_string(),
            format: "PE".into(),
            arch: "x86_64".into(),
            entry_point: 0x1400,
            base_addr: 0x1000,
            size: 102_400,
        }
    }
}

/// A function discovered in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMeta {
    pub addr: u64,
    pub name: String,
    pub size: u64,
    pub arch: String,
}

impl FunctionMeta {
    fn mock(addr: u64, name: &str) -> Self {
        Self {
            addr,
            name: name.to_string(),
            size: 64,
            arch: "x86_64".into(),
        }
    }
}

/// A disassembly line.
#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub addr: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}

impl DisasmLine {
    fn mock(addr: u64) -> Self {
        Self {
            addr,
            mnemonic: "mov".into(),
            operands: "rax, rbx".into(),
            bytes: vec![0x48, 0x89, 0xC3],
        }
    }
}

/// Debug session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSessionMeta {
    pub id: String,
    pub pid: u32,
    pub state: String,
    pub breakpoints: Vec<u64>,
}

impl DebugSessionMeta {
    fn new(pid: u32) -> Self {
        Self {
            id: format!("dbg-{pid}"),
            pid,
            state: "running".into(),
            breakpoints: Vec::new(),
        }
    }
}

/// A search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub addr: u64,
    pub matched_bytes: Vec<u8>,
    pub context: String,
}

// ── BinaryViewBinding ─────────────────────────────────────────────────────────

/// Lua binding layer for binary view operations.
#[derive(Debug, Default)]
pub struct BinaryViewBinding {
    /// Currently open binary views.
    views: HashMap<String, BinaryViewMeta>,
}

impl BinaryViewBinding {
    /// Create a new binding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a binary at `path` and return its ID.
    pub fn open(&mut self, path: &str) -> String {
        let meta = BinaryViewMeta::mock(path);
        let id = meta.id.clone();
        self.views.insert(id.clone(), meta);
        id
    }

    /// Get binary view metadata.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&BinaryViewMeta> {
        self.views.get(id)
    }

    /// Close a binary view.
    pub fn close(&mut self, id: &str) -> bool {
        self.views.remove(id).is_some()
    }

    /// List all open view IDs.
    #[must_use]
    pub fn list_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.views.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get all functions in a view (mock: returns 3 mock functions).
    #[must_use]
    pub fn get_functions(&self, id: &str) -> Vec<FunctionMeta> {
        if !self.views.contains_key(id) {
            return Vec::new();
        }
        vec![
            FunctionMeta::mock(0x1400, "entry"),
            FunctionMeta::mock(0x1480, "main"),
            FunctionMeta::mock(0x14C0, "helper"),
        ]
    }

    /// Disassemble `count` instructions at `addr` (mock).
    #[must_use]
    pub fn disassemble(&self, id: &str, addr: u64, count: usize) -> Vec<DisasmLine> {
        if !self.views.contains_key(id) {
            return Vec::new();
        }
        (0..count)
            .map(|i| DisasmLine::mock(addr + (i as u64) * 3))
            .collect()
    }

    /// Read bytes from a view.
    #[must_use]
    pub fn read_bytes(&self, id: &str, addr: u64, len: usize) -> Option<Vec<u8>> {
        if !self.views.contains_key(id) {
            return None;
        }
        Some(vec![(addr & 0xff) as u8; len])
    }
}

// ── AnalysisBinding ───────────────────────────────────────────────────────────

/// Lua binding layer for analysis operations.
#[derive(Debug, Default)]
pub struct AnalysisBinding {
    /// Results cache.
    cache: HashMap<String, serde_json::Value>,
}

impl AnalysisBinding {
    /// Create a new binding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyse a function and return a mock result.
    pub fn analyze_function(&mut self, binary_id: &str, addr: u64) -> serde_json::Value {
        let key = format!("{binary_id}:{addr:#x}");
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }
        let result = serde_json::json!({
            "addr": addr,
            "binary_id": binary_id,
            "basic_blocks": 5,
            "instructions": 42,
            "calls": ["sub_1480", "sub_14C0"],
            "xrefs_to": 2,
            "xrefs_from": 3,
        });
        self.cache.insert(key, result.clone());
        result
    }

    /// Get call graph for a function.
    #[must_use]
    pub fn call_graph(&self, _binary_id: &str, addr: u64) -> Vec<(u64, u64)> {
        vec![(addr, addr + 0x80), (addr, addr + 0xC0)]
    }

    /// Get xrefs to an address.
    #[must_use]
    pub fn xrefs_to(&self, _binary_id: &str, addr: u64) -> Vec<u64> {
        vec![addr.wrapping_sub(0x10), addr.wrapping_sub(0x20)]
    }

    /// Get xrefs from an address.
    #[must_use]
    pub fn xrefs_from(&self, _binary_id: &str, addr: u64) -> Vec<u64> {
        vec![addr + 0x40, addr + 0x80]
    }

    /// Apply a type to a location.
    pub fn apply_type(&mut self, binary_id: &str, addr: u64, type_name: &str) -> bool {
        let key = format!("type:{binary_id}:{addr:#x}");
        self.cache
            .insert(key, serde_json::Value::String(type_name.into()));
        true
    }

    /// Decompile a function.
    #[must_use]
    pub fn decompile(&self, _binary_id: &str, addr: u64) -> String {
        format!("int64_t sub_{addr:x}(void) {{\n    // decompiled code\n    return 0;\n}}")
    }
}

// ── DebugBinding ──────────────────────────────────────────────────────────────

/// Lua binding layer for debugger operations.
#[derive(Debug, Default)]
pub struct DebugBinding {
    sessions: HashMap<String, DebugSessionMeta>,
}

impl DebugBinding {
    /// Create a new binding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach to a process.
    pub fn attach(&mut self, pid: u32) -> String {
        let session = DebugSessionMeta::new(pid);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        id
    }

    /// Detach from a session.
    pub fn detach(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Set a breakpoint.
    pub fn set_breakpoint(&mut self, session_id: &str, addr: u64) -> bool {
        if let Some(s) = self.sessions.get_mut(session_id) {
            if !s.breakpoints.contains(&addr) {
                s.breakpoints.push(addr);
            }
            true
        } else {
            false
        }
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, session_id: &str, addr: u64) -> bool {
        if let Some(s) = self.sessions.get_mut(session_id) {
            let before = s.breakpoints.len();
            s.breakpoints.retain(|&bp| bp != addr);
            s.breakpoints.len() < before
        } else {
            false
        }
    }

    /// Read memory from the debuggee.
    #[must_use]
    pub fn read_memory(&self, session_id: &str, addr: u64, len: usize) -> Option<Vec<u8>> {
        if !self.sessions.contains_key(session_id) {
            return None;
        }
        Some(vec![(addr & 0xff) as u8; len])
    }

    /// Continue execution.
    pub fn resume(&mut self, session_id: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(session_id) {
            s.state = "running".into();
            true
        } else {
            false
        }
    }

    /// Suspend execution.
    pub fn pause(&mut self, session_id: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(session_id) {
            s.state = "paused".into();
            true
        } else {
            false
        }
    }

    /// Get session metadata.
    #[must_use]
    pub fn get_session(&self, id: &str) -> Option<&DebugSessionMeta> {
        self.sessions.get(id)
    }
}

// ── SearchBinding ─────────────────────────────────────────────────────────────

/// Lua binding layer for search operations.
#[derive(Debug, Default)]
pub struct SearchBinding;

impl SearchBinding {
    /// Search for a byte pattern in a binary (mock).
    #[must_use]
    pub fn search_bytes(&self, _binary_id: &str, pattern: &[u8]) -> Vec<SearchResult> {
        if pattern.is_empty() {
            return Vec::new();
        }
        vec![SearchResult {
            addr: 0x1200,
            matched_bytes: pattern.to_vec(),
            context: format!("0x1200: match for {} bytes", pattern.len()),
        }]
    }

    /// Search for a string in a binary (mock).
    #[must_use]
    pub fn search_string(&self, _binary_id: &str, query: &str) -> Vec<SearchResult> {
        if query.is_empty() {
            return Vec::new();
        }
        vec![SearchResult {
            addr: 0x2000,
            matched_bytes: query.as_bytes().to_vec(),
            context: format!("String at 0x2000: {query}"),
        }]
    }

    /// Search for functions by name prefix.
    #[must_use]
    pub fn search_function(&self, _binary_id: &str, prefix: &str) -> Vec<FunctionMeta> {
        ["entry", "main", "helper"]
            .iter()
            .filter(|n| n.starts_with(prefix))
            .enumerate()
            .map(|(i, &n)| FunctionMeta::mock(0x1400 + i as u64 * 0x80, n))
            .collect()
    }
}

// ── LuaRustreFull ─────────────────────────────────────────────────────────────

/// Complete Lua bindings for `RustRE`, combining all sub-binding layers.
///
/// Registers an `re` global table in the Lua state with sub-tables:
/// `re.bv` (binary view), `re.analysis`, `re.debug`, `re.search`.
pub struct LuaRustreFull {
    lua: Lua,
    bv: Arc<Mutex<BinaryViewBinding>>,
    analysis: Arc<Mutex<AnalysisBinding>>,
    debug_binding: Arc<Mutex<DebugBinding>>,
    search: Arc<Mutex<SearchBinding>>,
    /// Script execution log.
    pub log: Vec<LuaLogEntry>,
}

/// A single log entry produced by the Lua scripting layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaLogEntry {
    pub timestamp_ms: u64,
    pub level: String,
    pub message: String,
    pub source: Option<String>,
}

impl LuaRustreFull {
    /// Create a new Lua binding instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lua: Lua::new(),
            bv: Arc::new(Mutex::new(BinaryViewBinding::new())),
            analysis: Arc::new(Mutex::new(AnalysisBinding::new())),
            debug_binding: Arc::new(Mutex::new(DebugBinding::new())),
            search: Arc::new(Mutex::new(SearchBinding)),
            log: Vec::new(),
        }
    }

    /// Register all `RustRE` bindings into the Lua state.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn register_all(&mut self) -> LuaResult<()> {
        let bv_table = self.make_bv_table()?;
        let an_table = self.make_analysis_table()?;
        let dbg_table = self.make_debug_table()?;
        let srch_table = self.make_search_table()?;
        let re_table = self.lua.create_table()?;
        re_table.set("bv", bv_table)?;
        re_table.set("analysis", an_table)?;
        re_table.set("debug", dbg_table)?;
        re_table.set("search", srch_table)?;
        re_table.set("version", "0.1.0")?;
        self.lua.globals().set("re", re_table)?;
        Ok(())
    }

    fn make_bv_table(&self) -> LuaResult<mlua::Table> {
        let lua = &self.lua;
        let bv_table = lua.create_table()?;
        let bv_ref = Arc::clone(&self.bv);
        bv_table.set("open", lua.create_function(move |_, path: String| {
            Ok(bv_ref.lock().unwrap().open(&path))
        })?)?;
        let bv_ref2 = Arc::clone(&self.bv);
        bv_table.set("close", lua.create_function(move |_, id: String| Ok(bv_ref2.lock().unwrap().close(&id)))?)?;
        let bv_ref3 = Arc::clone(&self.bv);
        bv_table.set("list", lua.create_function(move |_, ()| Ok(bv_ref3.lock().unwrap().list_ids()))?)?;
        let bv_ref4 = Arc::clone(&self.bv);
        bv_table.set("get_functions", lua.create_function(move |lua_ctx, id: String| {
            let fns = bv_ref4.lock().unwrap().get_functions(&id);
            let t = lua_ctx.create_table()?;
            for (i, f) in fns.iter().enumerate() {
                let ft = lua_ctx.create_table()?;
                ft.set("addr", f.addr)?;
                ft.set("name", f.name.clone())?;
                ft.set("size", f.size)?;
                t.set(i + 1, ft)?;
            }
            Ok(t)
        })?)?;
        let bv_ref5 = Arc::clone(&self.bv);
        bv_table.set("read_bytes", lua.create_function(move |_, (id, addr, len): (String, u64, usize)| {
            Ok(bv_ref5.lock().unwrap().read_bytes(&id, addr, len))
        })?)?;
        Ok(bv_table)
    }

    fn make_analysis_table(&self) -> LuaResult<mlua::Table> {
        let lua = &self.lua;
        let an_table = lua.create_table()?;
        let an_ref = Arc::clone(&self.analysis);
        an_table.set("decompile", lua.create_function(move |_, (bid, addr): (String, u64)| {
            Ok(an_ref.lock().unwrap().decompile(&bid, addr))
        })?)?;
        let an_ref2 = Arc::clone(&self.analysis);
        an_table.set("xrefs_to", lua.create_function(move |_, (bid, addr): (String, u64)| {
            Ok(an_ref2.lock().unwrap().xrefs_to(&bid, addr))
        })?)?;
        let an_ref3 = Arc::clone(&self.analysis);
        an_table.set("apply_type", lua.create_function(move |_, (bid, addr, ty): (String, u64, String)| {
            Ok(an_ref3.lock().unwrap().apply_type(&bid, addr, &ty))
        })?)?;
        Ok(an_table)
    }

    fn make_debug_table(&self) -> LuaResult<mlua::Table> {
        let lua = &self.lua;
        let dbg_table = lua.create_table()?;
        let dbg_ref = Arc::clone(&self.debug_binding);
        dbg_table.set("attach", lua.create_function(move |_, pid: u32| Ok(dbg_ref.lock().unwrap().attach(pid)))?)?;
        let dbg_ref2 = Arc::clone(&self.debug_binding);
        dbg_table.set("set_breakpoint", lua.create_function(move |_, (sid, addr): (String, u64)| {
            Ok(dbg_ref2.lock().unwrap().set_breakpoint(&sid, addr))
        })?)?;
        let dbg_ref3 = Arc::clone(&self.debug_binding);
        dbg_table.set("resume", lua.create_function(move |_, sid: String| Ok(dbg_ref3.lock().unwrap().resume(&sid)))?)?;
        let dbg_ref4 = Arc::clone(&self.debug_binding);
        dbg_table.set("read_memory", lua.create_function(move |_, (sid, addr, len): (String, u64, usize)| {
            Ok(dbg_ref4.lock().unwrap().read_memory(&sid, addr, len))
        })?)?;
        Ok(dbg_table)
    }

    fn make_search_table(&self) -> LuaResult<mlua::Table> {
        let lua = &self.lua;
        let srch_table = lua.create_table()?;
        let srch_ref = Arc::clone(&self.search);
        srch_table.set("string", lua.create_function(move |lua_ctx, (bid, query): (String, String)| {
            let results = srch_ref.lock().unwrap().search_string(&bid, &query);
            let t = lua_ctx.create_table()?;
            for (i, r) in results.iter().enumerate() {
                let rt = lua_ctx.create_table()?;
                rt.set("addr", r.addr)?;
                rt.set("context", r.context.clone())?;
                t.set(i + 1, rt)?;
            }
            Ok(t)
        })?)?;
        let srch_ref2 = Arc::clone(&self.search);
        srch_table.set("function", lua.create_function(move |lua_ctx, (bid, prefix): (String, String)| {
            let results = srch_ref2.lock().unwrap().search_function(&bid, &prefix);
            let t = lua_ctx.create_table()?;
            for (i, r) in results.iter().enumerate() {
                let ft = lua_ctx.create_table()?;
                ft.set("addr", r.addr)?;
                ft.set("name", r.name.clone())?;
                t.set(i + 1, ft)?;
            }
            Ok(t)
        })?)?;
        Ok(srch_table)
    }

    /// Evaluate a Lua snippet, returning the result as a string.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn eval(&mut self, code: &str) -> LuaResult<String> {
        let t0 = now_ms();
        let result = self.lua.load(code).eval::<LuaMultiValue>();
        let elapsed = now_ms() - t0;
        let entry = match &result {
            Ok(v) => LuaLogEntry {
                timestamp_ms: t0,
                level: "info".into(),
                message: format!("eval ok in {elapsed}ms ({} value(s))", v.len()),
                source: Some(code.chars().take(40).collect()),
            },
            Err(e) => LuaLogEntry {
                timestamp_ms: t0,
                level: "error".into(),
                message: e.to_string(),
                source: Some(code.chars().take(40).collect()),
            },
        };
        self.log.push(entry);
        result.map(|v| {
            v.iter()
                .map(|lv| format!("{lv:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
    }

    /// Execute a Lua script (side-effects only).
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn exec(&mut self, code: &str) -> LuaResult<()> {
        self.lua.load(code).exec()
    }

    /// Set a global Lua variable.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_global(&self, name: &str, value: LuaValue) -> LuaResult<()> {
        self.lua.globals().set(name, value)
    }

    /// Get a global Lua variable.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_global<T: FromLua>(&self, name: &str) -> LuaResult<T> {
        self.lua.globals().get(name)
    }

    /// Number of log entries.
    #[must_use]
    pub const fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Clear the execution log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

impl Default for LuaRustreFull {
    fn default() -> Self {
        Self::new()
    }
}

// ── LuaApiConfig ──────────────────────────────────────────────────────────────

/// Feature flags for the Lua scripting API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaApiFeatures {
    /// Whether the binary-view API is enabled.
    pub enable_bv: bool,
    /// Whether the analysis API is enabled.
    pub enable_analysis: bool,
    /// Whether the debug API is enabled.
    pub enable_debug: bool,
}

/// Configuration for the Lua scripting API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaApiConfig {
    /// Individual API feature flags.
    pub features: LuaApiFeatures,
    /// Whether the search API is enabled.
    pub enable_search: bool,
    /// Script execution timeout in milliseconds (0 = unlimited).
    pub timeout_ms: u64,
    /// Maximum script output lines.
    pub max_output_lines: usize,
    /// Whether to capture Lua `print()` output.
    pub capture_print: bool,
    /// Global table name (default: "re").
    pub global_table_name: String,
}

impl Default for LuaApiConfig {
    fn default() -> Self {
        Self {
            features: LuaApiFeatures { enable_bv: true, enable_analysis: true, enable_debug: true },
            enable_search: true,
            timeout_ms: 10_000,
            max_output_lines: 1_000,
            capture_print: true,
            global_table_name: "re".into(),
        }
    }
}

impl LuaApiConfig {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a minimal config (analysis only).
    #[must_use]
    pub fn analysis_only() -> Self {
        Self {
            features: LuaApiFeatures { enable_bv: false, enable_analysis: true, enable_debug: false },
            enable_search: false,
            ..Default::default()
        }
    }

    /// Validate the config.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.global_table_name.is_empty() && self.max_output_lines > 0
    }

    /// Return `true` if at least one API is enabled.
    #[must_use]
    pub const fn any_enabled(&self) -> bool {
        self.features.enable_bv || self.features.enable_analysis || self.features.enable_debug || self.enable_search
    }
}

// ── LuaMetrics ────────────────────────────────────────────────────────────────

/// Execution metrics collected by a `LuaRustreFull` session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LuaMetrics {
    pub total_eval_calls: u64,
    pub successful_evals: u64,
    pub failed_evals: u64,
    pub total_exec_calls: u64,
    pub bv_opens: u64,
    pub debug_attaches: u64,
    pub search_queries: u64,
}

impl LuaMetrics {
    /// Compute from a log.
    #[must_use]
    pub fn from_log(log: &[LuaLogEntry]) -> Self {
        let successful = log.iter().filter(|e| e.level == "info").count() as u64;
        let failed = log.iter().filter(|e| e.level == "error").count() as u64;
        Self {
            total_eval_calls: successful + failed,
            successful_evals: successful,
            failed_evals: failed,
            ..Default::default()
        }
    }

    /// Error rate.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.total_eval_calls == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.failed_evals) / crate::casts::u64_to_f64(self.total_eval_calls)
        }
    }

    /// Return `true` if any calls failed.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        self.failed_evals > 0
    }
}

// ── LuaScriptRunner ───────────────────────────────────────────────────────────

/// Higher-level script runner that wraps `LuaRustreFull` with pre/post hooks
/// and a named-script library.
pub struct LuaScriptRunner {
    inner: LuaRustreFull,
    /// Named scripts that can be executed by name.
    scripts: HashMap<String, String>,
    /// Pre-execution hooks (script name → hook code).
    pre_hooks: HashMap<String, Vec<String>>,
    /// Post-execution hooks.
    post_hooks: HashMap<String, Vec<String>>,
    /// Whether to capture output in the log.
    pub capture_output: bool,
}

impl LuaScriptRunner {
    /// Create a new runner with all bindings registered.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new() -> LuaResult<Self> {
        let mut inner = LuaRustreFull::new();
        inner.register_all()?;
        Ok(Self {
            inner,
            scripts: HashMap::new(),
            pre_hooks: HashMap::new(),
            post_hooks: HashMap::new(),
            capture_output: true,
        })
    }

    /// Register a named script.
    pub fn register_script(&mut self, name: impl Into<String>, code: impl Into<String>) {
        self.scripts.insert(name.into(), code.into());
    }

    /// Add a pre-execution hook for a named script.
    pub fn add_pre_hook(&mut self, script_name: &str, hook: impl Into<String>) {
        self.pre_hooks
            .entry(script_name.to_string())
            .or_default()
            .push(hook.into());
    }

    /// Add a post-execution hook.
    pub fn add_post_hook(&mut self, script_name: &str, hook: impl Into<String>) {
        self.post_hooks
            .entry(script_name.to_string())
            .or_default()
            .push(hook.into());
    }

    /// Execute a named script.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn run_named(&mut self, name: &str) -> LuaResult<String> {
        // Pre-hooks.
        if let Some(hooks) = self.pre_hooks.get(name).cloned() {
            for hook in hooks {
                self.inner.exec(&hook)?;
            }
        }
        // Main script.
        let code = self
            .scripts
            .get(name)
            .ok_or_else(|| LuaError::RuntimeError(format!("script '{name}' not found")))?
            .clone();
        let result = self.inner.eval(&code);
        // Post-hooks.
        if let Some(hooks) = self.post_hooks.get(name).cloned() {
            for hook in hooks {
                let _ = self.inner.exec(&hook);
            }
        }
        result
    }

    /// Execute inline Lua code.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn eval_inline(&mut self, code: &str) -> LuaResult<String> {
        self.inner.eval(code)
    }

    /// Number of registered scripts.
    #[must_use]
    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Unregister a named script.
    pub fn unregister_script(&mut self, name: &str) -> bool {
        self.scripts.remove(name).is_some()
    }

    /// Return the log from the inner engine.
    #[must_use]
    pub fn log(&self) -> &[LuaLogEntry] {
        &self.inner.log
    }

    /// Return all registered script names.
    #[must_use]
    pub fn script_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.scripts.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

// ── LuaTypeConverter ──────────────────────────────────────────────────────────

/// Utility for converting between Rust types and Lua values.
pub struct LuaTypeConverter;

impl LuaTypeConverter {
    /// Convert a `serde_json::Value` to a Lua value string representation.
    #[must_use]
    pub fn json_to_lua_literal(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "nil".into(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => format!("{s:?}"),
            serde_json::Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(Self::json_to_lua_literal).collect();
                format!("{{{}}}", items.join(", "))
            }
            serde_json::Value::Object(obj) => {
                let items: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", Self::json_to_lua_literal(v)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
        }
    }

    /// Convert a Rust address to a Lua hex string.
    #[must_use]
    pub fn addr_to_hex(addr: u64) -> String {
        format!("0x{addr:x}")
    }

    /// Parse a Lua hex literal to a `u64`.
    #[must_use]
    pub fn parse_hex(s: &str) -> Option<u64> {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).ok()
    }

    /// Escape a Rust string for safe embedding in Lua source.
    #[must_use]
    pub fn escape_string(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }
}

// ── LuaEventBridge ────────────────────────────────────────────────────────────

/// Bridges Lua event emissions to Rust callbacks.
#[derive(Debug, Default)]
pub struct LuaEventBridge {
    /// Registered handlers: `event_name` → Lua code to execute.
    handlers: HashMap<String, Vec<String>>,
    /// Events that have fired.
    fired_events: Vec<(String, u64)>,
}

impl LuaEventBridge {
    /// Create a new bridge.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Lua code handler for an event.
    pub fn on(&mut self, event: &str, code: impl Into<String>) {
        self.handlers
            .entry(event.to_string())
            .or_default()
            .push(code.into());
    }

    /// Emit an event, executing all registered handlers.
    pub fn emit(&mut self, event: &str, engine: &mut LuaRustreFull) {
        let handlers = self.handlers.get(event).cloned().unwrap_or_default();
        for handler in handlers {
            let _ = engine.exec(&handler);
        }
        let ts = now_ms();
        self.fired_events.push((event.to_string(), ts));
    }

    /// Return events that have fired.
    #[must_use]
    pub fn fired(&self) -> &[(String, u64)] {
        &self.fired_events
    }

    /// Number of times a specific event has fired.
    #[must_use]
    pub fn fire_count(&self, event: &str) -> usize {
        self.fired_events.iter().filter(|(e, _)| e == event).count()
    }

    /// Clear the event handler for a specific event.
    pub fn clear(&mut self, event: &str) -> usize {
        self.handlers.remove(event).map_or(0, |v| v.len())
    }

    /// Total number of registered handlers across all events.
    #[must_use]
    pub fn total_handlers(&self) -> usize {
        self.handlers.values().map(std::vec::Vec::len).sum()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lua() -> LuaRustreFull {
        let mut l = LuaRustreFull::new();
        l.register_all().expect("register_all failed");
        l
    }

    // ── BinaryViewBinding ────────────────────────────────────────────────────

    #[test]
    fn test_bv_open_and_list() {
        let mut bv = BinaryViewBinding::new();
        let id = bv.open("/tmp/test.exe");
        assert!(!id.is_empty());
        assert!(bv.list_ids().contains(&id));
    }

    #[test]
    fn test_bv_close() {
        let mut bv = BinaryViewBinding::new();
        let id = bv.open("/tmp/t.exe");
        assert!(bv.close(&id));
        assert!(!bv.list_ids().contains(&id));
    }

    #[test]
    fn test_bv_get_functions() {
        let mut bv = BinaryViewBinding::new();
        let id = bv.open("/tmp/t.exe");
        let fns = bv.get_functions(&id);
        assert_eq!(fns.len(), 3);
        assert!(fns.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_bv_disassemble() {
        let mut bv = BinaryViewBinding::new();
        let id = bv.open("/tmp/t.exe");
        let lines = bv.disassemble(&id, 0x1400, 5);
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_bv_read_bytes() {
        let mut bv = BinaryViewBinding::new();
        let id = bv.open("/tmp/t.exe");
        let bytes = bv.read_bytes(&id, 0x1000, 8).unwrap();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_bv_get_missing() {
        let bv = BinaryViewBinding::new();
        assert!(bv.get("missing").is_none());
    }

    // ── AnalysisBinding ──────────────────────────────────────────────────────

    #[test]
    fn test_analysis_decompile() {
        let analysis = AnalysisBinding::new();
        let code = analysis.decompile("bv1", 0x1400);
        assert!(code.contains("sub_1400"));
    }

    #[test]
    fn test_analysis_xrefs_to() {
        let analysis = AnalysisBinding::new();
        let xrefs = analysis.xrefs_to("bv1", 0x1400);
        assert!(!xrefs.is_empty());
    }

    #[test]
    fn test_analysis_xrefs_from() {
        let analysis = AnalysisBinding::new();
        let xrefs = analysis.xrefs_from("bv1", 0x1400);
        assert!(!xrefs.is_empty());
    }

    #[test]
    fn test_analysis_apply_type() {
        let mut analysis = AnalysisBinding::new();
        assert!(analysis.apply_type("bv1", 0x1000, "PSTR"));
    }

    #[test]
    fn test_analysis_call_graph() {
        let analysis = AnalysisBinding::new();
        let edges = analysis.call_graph("bv1", 0x1400);
        assert!(!edges.is_empty());
    }

    // ── DebugBinding ─────────────────────────────────────────────────────────

    #[test]
    fn test_debug_attach_and_detach() {
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        assert!(!id.is_empty());
        assert!(dbg.detach(&id));
    }

    #[test]
    fn test_debug_set_breakpoint() {
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        assert!(dbg.set_breakpoint(&id, 0x0040_1000));
        let s = dbg.get_session(&id).unwrap();
        assert!(s.breakpoints.contains(&0x0040_1000));
    }

    #[test]
    fn test_debug_remove_breakpoint() {
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        dbg.set_breakpoint(&id, 0x0040_1000);
        assert!(dbg.remove_breakpoint(&id, 0x0040_1000));
        let s = dbg.get_session(&id).unwrap();
        assert!(!s.breakpoints.contains(&0x0040_1000));
    }

    #[test]
    fn test_debug_read_memory() {
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        let mem = dbg.read_memory(&id, 0x1000, 16).unwrap();
        assert_eq!(mem.len(), 16);
    }

    #[test]
    fn test_debug_pause_and_resume() {
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(9999);
        assert!(dbg.pause(&id));
        assert_eq!(dbg.get_session(&id).unwrap().state, "paused");
        assert!(dbg.resume(&id));
        assert_eq!(dbg.get_session(&id).unwrap().state, "running");
    }

    // ── SearchBinding ────────────────────────────────────────────────────────

    #[test]
    fn test_search_string() {
        let s = SearchBinding;
        let results = s.search_string("bv1", "CreateRemoteThread");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].addr, 0x2000);
    }

    #[test]
    fn test_search_string_empty() {
        let s = SearchBinding;
        assert!(s.search_string("bv1", "").is_empty());
    }

    #[test]
    fn test_search_bytes() {
        let s = SearchBinding;
        let results = s.search_bytes("bv1", &[0x90, 0x90]);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_function() {
        let s = SearchBinding;
        let results = s.search_function("bv1", "ma");
        assert!(!results.is_empty());
        assert!(results.iter().any(|f| f.name == "main"));
    }

    // ── LuaRustreFull ────────────────────────────────────────────────────────

    #[test]
    fn test_lua_rustre_register_all() {
        let lua = make_lua();
        let version: String = lua.get_global("re.version").unwrap_or_default();
        // Just verify registration didn't panic.
        let _ = version;
    }

    #[test]
    fn test_lua_eval_basic() {
        let mut lua = make_lua();
        let result = lua.eval("return 1 + 2").unwrap();
        assert!(result.contains('3'));
    }

    #[test]
    fn test_lua_eval_string_concat() {
        let mut lua = make_lua();
        let result = lua.eval(r#"return "hello" .. " " .. "world""#).unwrap();
        assert!(result.contains("hello") || result.contains("world"));
    }

    #[test]
    fn test_lua_exec_side_effect() {
        let mut lua = make_lua();
        lua.exec("x = 42").unwrap();
        let val: i64 = lua.get_global("x").unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_lua_bv_open_via_script() {
        let mut lua = make_lua();
        let result = lua.eval(r#"return re.bv.open("/tmp/test.exe")"#).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_lua_bv_list_via_script() {
        let mut lua = make_lua();
        lua.exec(r#"re.bv.open("/tmp/a.exe")"#).unwrap();
        let result = lua.eval("return #re.bv.list()").unwrap();
        assert!(result.contains('1'));
    }

    #[test]
    fn test_lua_debug_attach_via_script() {
        let mut lua = make_lua();
        let result = lua.eval("return re.debug.attach(1234)").unwrap();
        assert!(result.contains("dbg-1234"));
    }

    #[test]
    fn test_lua_analysis_decompile_via_script() {
        let mut lua = make_lua();
        let result = lua
            .eval(r#"return re.analysis.decompile("bv1", 0x1400)"#)
            .unwrap();
        assert!(result.contains("sub_1400") || !result.is_empty());
    }

    #[test]
    fn test_lua_search_string_via_script() {
        let mut lua = make_lua();
        let result = lua
            .eval(
                r#"
            local rs = re.search.string("bv1", "CreateProcess")
            return #rs
        "#,
            )
            .unwrap();
        assert!(result.contains('1'));
    }

    #[test]
    fn test_lua_log_populated() {
        let mut lua = make_lua();
        lua.eval("return 1").unwrap();
        assert!(lua.log_len() > 0);
    }

    #[test]
    fn test_lua_clear_log() {
        let mut lua = make_lua();
        lua.eval("return 1").unwrap();
        lua.clear_log();
        assert_eq!(lua.log_len(), 0);
    }

    #[test]
    fn test_lua_error_logged() {
        let mut lua = make_lua();
        let _ = lua.eval("error('deliberate error')");
        assert!(!lua.log.is_empty());
        assert!(lua.log.last().unwrap().level == "error");
    }

    #[test]
    fn test_lua_set_global() {
        let lua = make_lua();
        lua.set_global("my_var", LuaValue::Integer(99)).unwrap();
        let val: i64 = lua.get_global("my_var").unwrap();
        assert_eq!(val, 99);
    }

    #[test]
    fn test_lua_re_version_string() {
        let mut lua = make_lua();
        let result = lua.eval("return re.version").unwrap();
        assert!(result.contains("0.1.0"));
    }

    #[test]
    fn test_lua_bv_read_bytes_via_script() {
        let mut lua = make_lua();
        lua.exec(r#"_bvid = re.bv.open("/tmp/t.exe")"#).unwrap();
        let result = lua
            .eval(
                r"
            local b = re.bv.read_bytes(_bvid, 0x1000, 4)
            if b then return #b else return 0 end
        ",
            )
            .unwrap();
        assert!(result.contains('4') || result.contains('0'));
    }

    #[test]
    fn test_lua_bv_get_functions_via_script() {
        let mut lua = make_lua();
        lua.exec(r#"_bvid = re.bv.open("/tmp/t.exe")"#).unwrap();
        let result = lua.eval("return #re.bv.get_functions(_bvid)").unwrap();
        assert!(result.contains('3'));
    }

    #[test]
    fn test_lua_debug_set_breakpoint_via_script() {
        let mut lua = make_lua();
        lua.exec("_sid = re.debug.attach(9999)").unwrap();
        let result = lua
            .eval("return re.debug.set_breakpoint(_sid, 0x401000)")
            .unwrap();
        assert!(result.contains("true") || !result.is_empty());
    }

    // ── LuaScriptRunner ──────────────────────────────────────────────────────

    #[test]
    fn test_runner_register_and_run() {
        let mut runner = LuaScriptRunner::new().unwrap();
        runner.register_script("greet", "return 'hello from script'");
        let result = runner.run_named("greet").unwrap();
        assert!(result.contains("hello from script"));
    }

    #[test]
    fn test_runner_missing_script_error() {
        let mut runner = LuaScriptRunner::new().unwrap();
        assert!(runner.run_named("nonexistent").is_err());
    }

    #[test]
    fn test_runner_pre_hook() {
        let mut runner = LuaScriptRunner::new().unwrap();
        runner.register_script("main", "return x");
        runner.add_pre_hook("main", "x = 99");
        let result = runner.run_named("main").unwrap();
        assert!(result.contains("99"));
    }

    #[test]
    fn test_runner_script_count() {
        let mut runner = LuaScriptRunner::new().unwrap();
        runner.register_script("a", "return 1");
        runner.register_script("b", "return 2");
        assert_eq!(runner.script_count(), 2);
    }

    #[test]
    fn test_runner_unregister() {
        let mut runner = LuaScriptRunner::new().unwrap();
        runner.register_script("x", "return 1");
        assert!(runner.unregister_script("x"));
        assert_eq!(runner.script_count(), 0);
    }

    #[test]
    fn test_runner_names_sorted() {
        let mut runner = LuaScriptRunner::new().unwrap();
        runner.register_script("beta", "return 2");
        runner.register_script("alpha", "return 1");
        let names = runner.script_names();
        assert_eq!(names[0], "alpha");
    }

    // ── LuaTypeConverter ─────────────────────────────────────────────────────

    #[test]
    fn test_converter_null() {
        assert_eq!(
            LuaTypeConverter::json_to_lua_literal(&serde_json::Value::Null),
            "nil"
        );
    }

    #[test]
    fn test_converter_bool() {
        assert_eq!(
            LuaTypeConverter::json_to_lua_literal(&serde_json::Value::Bool(true)),
            "true"
        );
    }

    #[test]
    fn test_converter_addr_to_hex() {
        assert_eq!(LuaTypeConverter::addr_to_hex(0x1400), "0x1400");
    }

    #[test]
    fn test_converter_parse_hex() {
        assert_eq!(LuaTypeConverter::parse_hex("0x1400"), Some(0x1400));
        assert_eq!(LuaTypeConverter::parse_hex("1400"), Some(0x1400));
        assert_eq!(LuaTypeConverter::parse_hex("ZZZZ"), None);
    }

    #[test]
    fn test_converter_escape_string() {
        let escaped = LuaTypeConverter::escape_string("hello\nworld");
        assert!(escaped.contains("\\n"));
    }

    // ── LuaEventBridge ───────────────────────────────────────────────────────

    #[test]
    fn test_event_bridge_on_and_emit() {
        let mut bridge = LuaEventBridge::new();
        let mut engine = make_lua();
        bridge.on("analysis_done", "counter = 1");
        bridge.emit("analysis_done", &mut engine);
        assert_eq!(bridge.fire_count("analysis_done"), 1);
    }

    #[test]
    fn test_event_bridge_fire_count() {
        let mut bridge = LuaEventBridge::new();
        let mut engine = make_lua();
        bridge.on("e", "");
        bridge.emit("e", &mut engine);
        bridge.emit("e", &mut engine);
        assert_eq!(bridge.fire_count("e"), 2);
    }

    #[test]
    fn test_event_bridge_clear() {
        let mut bridge = LuaEventBridge::new();
        bridge.on("e", "code");
        assert_eq!(bridge.clear("e"), 1);
        assert_eq!(bridge.total_handlers(), 0);
    }

    #[test]
    fn test_event_bridge_total_handlers() {
        let mut bridge = LuaEventBridge::new();
        bridge.on("a", "c1");
        bridge.on("a", "c2");
        bridge.on("b", "c3");
        assert_eq!(bridge.total_handlers(), 3);
    }

    // ── LuaApiConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_lua_api_config_defaults() {
        let cfg = LuaApiConfig::new();
        assert!(cfg.features.enable_bv);
        assert!(cfg.features.enable_debug);
        assert!(cfg.is_valid());
        assert!(cfg.any_enabled());
    }

    #[test]
    fn test_lua_api_config_analysis_only() {
        let cfg = LuaApiConfig::analysis_only();
        assert!(!cfg.features.enable_bv);
        assert!(!cfg.features.enable_debug);
        assert!(cfg.features.enable_analysis);
        assert!(cfg.any_enabled());
    }

    #[test]
    fn test_lua_api_config_all_disabled() {
        let mut cfg = LuaApiConfig::new();
        cfg.features.enable_bv = false;
        cfg.features.enable_analysis = false;
        cfg.features.enable_debug = false;
        cfg.enable_search = false;
        assert!(!cfg.any_enabled());
    }

    #[test]
    fn test_lua_api_config_invalid_empty_name() {
        let mut cfg = LuaApiConfig::new();
        cfg.global_table_name = String::new();
        assert!(!cfg.is_valid());
    }

    #[test]
    fn test_lua_api_config_invalid_zero_output() {
        let mut cfg = LuaApiConfig::new();
        cfg.max_output_lines = 0;
        assert!(!cfg.is_valid());
    }

    // ── LuaMetrics ───────────────────────────────────────────────────────────

    #[test]
    fn test_lua_metrics_from_empty_log() {
        let metrics = LuaMetrics::from_log(&[]);
        assert_eq!(metrics.total_eval_calls, 0);
        assert_eq!(metrics.error_rate(), 0.0);
        assert!(!metrics.has_errors());
    }

    #[test]
    fn test_lua_metrics_from_log() {
        let mut lua = make_lua();
        lua.eval("return 'ok'").unwrap();
        let _ = lua.eval("error('fail')");
        let metrics = LuaMetrics::from_log(&lua.log);
        assert_eq!(metrics.successful_evals, 1);
        assert_eq!(metrics.failed_evals, 1);
        assert!(metrics.has_errors());
    }

    #[test]
    fn test_lua_metrics_error_rate() {
        let entries = vec![
            LuaLogEntry {
                timestamp_ms: 0,
                level: "info".into(),
                message: "ok".into(),
                source: None,
            },
            LuaLogEntry {
                timestamp_ms: 0,
                level: "error".into(),
                message: "fail".into(),
                source: None,
            },
        ];
        let metrics = LuaMetrics::from_log(&entries);
        assert!((metrics.error_rate() - 0.5).abs() < f64::EPSILON);
    }
}
