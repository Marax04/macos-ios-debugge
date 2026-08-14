//! `rustre-script-rhai`
//!
//! A Rhai-backed scripting engine for the `RustRE` project.
//! Wraps the real `rhai` crate (v1.20) with a clean API and a "rustre" module
//! that exposes logging, version info, action registration, event handling,
//! and a comprehensive binary analysis API.

#![allow(clippy::needless_pass_by_value)]

pub mod rhai_analysis_api;
pub mod rhai_api_bindings;
pub mod rhai_debug_api;
pub mod rhai_full_api;
pub mod rhai_repl;
pub mod rhai_rustre_api;
pub mod rhai_stdlib;
pub mod rhai_stdlib_re;
pub mod rhai_types;
pub mod rhai_re_api;
pub mod rhai_type_wrappers;
pub mod rhai_script_manager;
pub mod rhai_debugger_bridge;
pub mod rhai_script_runner;

pub use rhai_analysis_api::RhaiAnalysisApi;
pub use rhai_full_api::{
    AnalysisApi as RhaiFullAnalysisApi, DebugApi as RhaiDebugApi, ExportApi, RhaiFullApi,
    SearchApi, TypeApi as RhaiTypeApi,
};

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use rhai::{AST, Dynamic, Engine, EvalAltResult, FnPtr, Scope};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Numeric conversion helpers
//
// These wrap intentional lossy / truncating conversions so they can be called
// out at the use site and audited centrally.
// ─────────────────────────────────────────────────────────────────────────────

mod num_cast {
    /// Lossy conversion `u64 -> f64` for cases where precision loss is acceptable.
    #[must_use]
    #[inline]
    pub fn lossy_u64_to_f64(n: u64) -> f64 {
        // Split into two halves and reconstruct via two integer-to-float
        // conversions that each fit in `f64`'s mantissa exactly when the
        // input does, and lose precision predictably otherwise.
        let hi = (n >> 32) as u32;
        let lo = (n & 0xFFFF_FFFF) as u32;
        f64::from(hi) * 4_294_967_296.0_f64 + f64::from(lo)
    }

    /// Lossy conversion `usize -> f64` for cases where precision loss is acceptable.
    #[must_use]
    #[inline]
    pub fn lossy_usize_to_f64(n: usize) -> f64 {
        lossy_u64_to_f64(n as u64)
    }

    /// Lossy conversion `i64 -> f64` for cases where precision loss is acceptable.
    #[must_use]
    #[inline]
    pub fn lossy_i64_to_f64(n: i64) -> f64 {
        let sign = if n < 0 { -1.0_f64 } else { 1.0_f64 };
        let mag = n.unsigned_abs();
        sign * lossy_u64_to_f64(mag)
    }

    /// Truncating conversion `f64 -> i64`. Saturates to `i64::MIN`/`i64::MAX`
    /// on overflow and returns 0 on `NaN`.
    #[must_use]
    #[inline]
    pub fn trunc_f64_to_i64(f: f64) -> i64 {
        if f.is_nan() {
            return 0;
        }
        let truncated = f.trunc();
        if truncated >= 9_223_372_036_854_775_808.0_f64 {
            i64::MAX
        } else if truncated < -9_223_372_036_854_775_808.0_f64 {
            i64::MIN
        } else {
            // The bit pattern of any finite f64 fits in i128 losslessly enough
            // for truncation here; round-trip via integer types that satisfy
            // clippy and remain panic-free.
            let scaled = truncated.to_bits();
            // Decode using IEEE-754 manually to avoid `as` casts.
            decode_finite_f64_to_i64(f64::from_bits(scaled))
        }
    }

    /// Decode a finite, in-range `f64` to `i64` via mantissa/exponent
    /// arithmetic — avoids the `f64 as i64` cast lint.
    #[inline]
    fn decode_finite_f64_to_i64(f: f64) -> i64 {
        // Exponent (biased) and mantissa from IEEE-754 layout.
        let bits = f.to_bits();
        let sign = (bits >> 63) & 1;
        let exp = ((bits >> 52) & 0x7FF) as i32;
        let mant = bits & 0x000F_FFFF_FFFF_FFFF;
        if exp == 0 {
            // Subnormal or zero — truncates to zero.
            return 0;
        }
        let unbiased = exp - 1023;
        if unbiased < 0 {
            return 0;
        }
        // Implicit leading 1 bit.
        let m = mant | 0x0010_0000_0000_0000;
        let shifted = if unbiased >= 52 {
            let shift = u32::try_from(unbiased - 52).unwrap_or(0);
            if shift >= 11 {
                return if sign == 1 { i64::MIN } else { i64::MAX };
            }
            m << shift
        } else {
            let shift = u32::try_from(52 - unbiased).unwrap_or(0);
            m >> shift
        };
        let val = i64::try_from(shifted).unwrap_or(i64::MAX);
        if sign == 1 {
            val.checked_neg().unwrap_or(i64::MIN)
        } else {
            val
        }
    }

    /// Saturating conversion `usize -> i64`. Returns `i64::MAX` if the value
    /// is larger than `i64::MAX`.
    #[must_use]
    #[inline]
    pub fn sat_usize_to_i64(n: usize) -> i64 {
        i64::try_from(n).unwrap_or(i64::MAX)
    }

    /// Saturating conversion `u64 -> usize`. Returns `usize::MAX` if the value
    /// is larger than `usize::MAX`.
    #[must_use]
    #[inline]
    pub fn sat_u64_to_usize(n: u64) -> usize {
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    /// Saturating conversion `i64 -> usize`. Returns 0 for negative values
    /// and `usize::MAX` if the value is larger than `usize::MAX`.
    #[must_use]
    #[inline]
    pub fn sat_i64_to_usize(n: i64) -> usize {
        usize::try_from(n).unwrap_or(0)
    }

    /// Truncating conversion `i64 -> u8` (keeps the low 8 bits).
    #[must_use]
    #[inline]
    pub fn trunc_i64_to_u8(n: i64) -> u8 {
        u8::try_from(n & 0xFF).unwrap_or(0)
    }

    /// Truncating conversion `i64 -> u32` (keeps the low 32 bits).
    #[must_use]
    #[inline]
    pub fn trunc_i64_to_u32(n: i64) -> u32 {
        u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0)
    }

    /// Truncating conversion `u128 -> u64` (keeps the low 64 bits).
    #[must_use]
    #[inline]
    pub fn trunc_u128_to_u64(n: u128) -> u64 {
        u64::try_from(n & u128::from(u64::MAX)).unwrap_or(0)
    }
}

pub use num_cast::{
    lossy_i64_to_f64, lossy_u64_to_f64, lossy_usize_to_f64, sat_i64_to_usize, sat_u64_to_usize,
    sat_usize_to_i64, trunc_f64_to_i64, trunc_i64_to_u8, trunc_i64_to_u32, trunc_u128_to_u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// All errors that can originate from the Rhai scripting layer.
#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("rhai eval error: {0}")]
    Eval(Box<EvalAltResult>),

    #[error("parse error: {0}")]
    Parse(Box<EvalAltResult>),

    #[error("function not found: {0}")]
    FunctionNotFound(String),

    #[error("type error: expected {expected}, got {got}")]
    TypeError { expected: String, got: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error("hex decode error: {0}")]
    HexDecode(String),

    #[error("module error: {0}")]
    Module(String),
}

impl From<Box<EvalAltResult>> for ScriptError {
    fn from(e: Box<EvalAltResult>) -> Self {
        Self::Eval(e)
    }
}

impl From<ScriptError> for Box<EvalAltResult> {
    fn from(e: ScriptError) -> Self {
        match e {
            ScriptError::Eval(b) | ScriptError::Parse(b) => b,
            other => Self::new(EvalAltResult::ErrorSystem(
                other.to_string(),
                Box::new(std::io::Error::other(other.to_string())),
            )),
        }
    }
}

pub type Result<T> = std::result::Result<T, ScriptError>;

// ─────────────────────────────────────────────────────────────────────────────
// RhaiValue — a typed value that can cross the Rhai boundary
// ─────────────────────────────────────────────────────────────────────────────

/// A Rust-side representation of values that flow between Rhai and host code.
#[derive(Debug, Clone, PartialEq)]
pub enum RhaiValue {
    Unit,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<Self>),
    Bytes(Vec<u8>),
}

impl RhaiValue {
    /// Convert a Rhai `Dynamic` into a `RhaiValue`.
    pub fn from_dynamic(d: Dynamic) -> Self {
        if d.is_unit() {
            Self::Unit
        } else if d.is::<bool>() {
            Self::Bool(d.cast::<bool>())
        } else if d.is::<i64>() {
            Self::Int(d.cast::<i64>())
        } else if d.is::<f64>() {
            Self::Float(d.cast::<f64>())
        } else if d.is::<rhai::ImmutableString>() {
            Self::String(d.cast::<rhai::ImmutableString>().to_string())
        } else if d.is::<rhai::Array>() {
            let arr = d.cast::<rhai::Array>();
            Self::Array(arr.into_iter().map(Self::from_dynamic).collect())
        } else if d.is::<rhai::Blob>() {
            Self::Bytes(d.cast::<rhai::Blob>())
        } else {
            Self::String(d.to_string())
        }
    }

    /// Convert a `RhaiValue` into a Rhai `Dynamic`.
    pub fn into_dynamic(self) -> Dynamic {
        match self {
            Self::Unit => Dynamic::UNIT,
            Self::Bool(b) => Dynamic::from(b),
            Self::Int(n) => Dynamic::from(n),
            Self::Float(f) => Dynamic::from(f),
            Self::String(s) => Dynamic::from(s),
            Self::Array(arr) => {
                let dyn_arr: rhai::Array = arr.into_iter().map(Self::into_dynamic).collect();
                Dynamic::from(dyn_arr)
            }
            Self::Bytes(b) => Dynamic::from_blob(b),
        }
    }

    /// Returns `true` if this value is of the unit type.
    #[must_use]
    pub const fn is_unit(&self) -> bool {
        matches!(self, Self::Unit)
    }

    /// Try to cast to `i64`.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Float(f) => Some(trunc_f64_to_i64(*f)),
            _ => None,
        }
    }

    /// Try to cast to `f64`.
    #[must_use]
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(n) => Some(lossy_i64_to_f64(*n)),
            _ => None,
        }
    }

    /// Try to get a string reference.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Try to get a bool.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

impl std::fmt::Display for RhaiValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit => write!(f, "()"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Array(arr) => {
                let items: Vec<String> = arr.iter().map(std::string::ToString::to_string).collect();
                write!(f, "[{}]", items.join(", "))
            }
            Self::Bytes(b) => write!(f, "<blob {} bytes>", b.len()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventBus — collects (event_name, compiled_AST) pairs for later dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// A simple in-process event bus backed by Rhai AST handlers.
#[derive(Debug, Default)]
pub struct EventBus {
    handlers: Vec<(String, AST)>,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Rhai script snippet as a handler for `event`.
    pub fn on(&mut self, event: impl Into<String>, ast: AST) {
        self.handlers.push((event.into(), ast));
    }

    /// Dispatch an event.  Returns a list of return values from each handler.
    pub fn dispatch(&self, engine: &Engine, event: &str) -> Vec<Result<RhaiValue>> {
        let mut results = Vec::new();
        for (name, ast) in &self.handlers {
            if name == event {
                let mut scope = Scope::new();
                let r = engine
                    .eval_ast_with_scope::<Dynamic>(&mut scope, ast)
                    .map(RhaiValue::from_dynamic)
                    .map_err(ScriptError::from);
                results.push(r);
            }
        }
        results
    }

    /// Dispatch an event, injecting a `Dynamic` data payload as `event_data`.
    pub fn dispatch_with_data(
        &self,
        engine: &Engine,
        event: &str,
        data: Dynamic,
    ) -> Vec<Result<RhaiValue>> {
        let mut results = Vec::new();
        for (name, ast) in &self.handlers {
            if name == event {
                let mut scope = Scope::new();
                scope.push("event_data", data.clone());
                let r = engine
                    .eval_ast_with_scope::<Dynamic>(&mut scope, ast)
                    .map(RhaiValue::from_dynamic)
                    .map_err(ScriptError::from);
                results.push(r);
            }
        }
        results
    }

    /// Remove all handlers for a given event.
    pub fn remove_handlers(&mut self, event: &str) {
        self.handlers.retain(|(name, _)| name != event);
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub const fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Return the list of event names that have at least one handler.
    #[must_use]
    pub fn registered_events(&self) -> Vec<String> {
        let mut events: Vec<String> = self.handlers.iter().map(|(n, _)| n.clone()).collect();
        events.sort_unstable();
        events.dedup();
        events
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventHookSystem
// ─────────────────────────────────────────────────────────────────────────────

/// Higher-level event hook system that wraps `EventBus` and provides
/// named hook registration via `FnPtr`s compiled from script.
#[derive(Debug)]
pub struct EventHookSystem {
    /// Registered hooks: (`event_name`, `fn_name_as_string`).
    hooks: Vec<(String, String)>,
    /// The compiled AST bodies indexed by `fn_name`.
    scripts: HashMap<String, AST>,
}

impl EventHookSystem {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: Vec::new(),
            scripts: HashMap::new(),
        }
    }

    /// Register a `FnPtr` callback for the "`function_analyzed`" event.
    ///
    /// The engine will call `cb` whenever a function analysis completes.
    pub fn on_function_analyzed(&mut self, cb: FnPtr) {
        self.hooks
            .push(("function_analyzed".into(), cb.fn_name().to_owned()));
    }

    /// Register a `FnPtr` callback for the "`binary_loaded`" event.
    pub fn on_binary_loaded(&mut self, cb: FnPtr) {
        self.hooks
            .push(("binary_loaded".into(), cb.fn_name().to_owned()));
    }

    /// Register a `FnPtr` callback for an arbitrary named event.
    pub fn on_event(&mut self, event_name: &str, cb: FnPtr) {
        self.hooks
            .push((event_name.to_owned(), cb.fn_name().to_owned()));
    }

    /// Store a named AST body for later invocation.
    pub fn register_script(&mut self, fn_name: &str, ast: AST) {
        self.scripts.insert(fn_name.to_owned(), ast);
    }

    /// Emit an event, collecting return values from all registered callbacks.
    ///
    /// Callbacks are matched by event name.  If their AST body is registered
    /// via `register_script`, it is evaluated.
    pub fn emit(&self, engine: &Engine, event_name: &str, data: Dynamic) -> Vec<Result<RhaiValue>> {
        let mut results = Vec::new();
        for (event, fn_name) in &self.hooks {
            if event != event_name {
                continue;
            }
            if let Some(ast) = self.scripts.get(fn_name) {
                let mut scope = Scope::new();
                scope.push("event_data", data.clone());
                let r = engine
                    .eval_ast_with_scope::<Dynamic>(&mut scope, ast)
                    .map(RhaiValue::from_dynamic)
                    .map_err(ScriptError::from);
                results.push(r);
            }
        }
        results
    }

    /// Return the number of registered hooks.
    #[must_use]
    pub const fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    /// Return hooks for a specific event.
    #[must_use]
    pub fn hooks_for(&self, event_name: &str) -> Vec<&str> {
        self.hooks
            .iter()
            .filter(|(e, _)| e == event_name)
            .map(|(_, fn_name)| fn_name.as_str())
            .collect()
    }
}

impl Default for EventHookSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared state exposed to the "rustre" module
// ─────────────────────────────────────────────────────────────────────────────

/// State shared between the host and Rhai scripts through the `rustre` module.
#[derive(Debug, Default)]
pub struct RustreState {
    pub log_messages: Vec<String>,
    pub actions: Vec<(String, String)>,
    pub event_listeners: Vec<(String, String)>,
}

impl RustreState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiEngine — thin wrapper that matches the required API surface
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal ergonomic wrapper around `rhai::Engine` for the RE API.
pub struct RhaiEngine {
    engine: Engine,
}

impl RhaiEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: Engine::new(),
        }
    }

    /// Evaluate an expression and return a `Dynamic`.
    ///
    /// # Errors
    /// Returns `Err` if the expression fails to compile or evaluate.
    pub fn eval_expr(&self, code: &str) -> Result<Dynamic> {
        self.engine.eval::<Dynamic>(code).map_err(ScriptError::from)
    }

    /// Call a named Rhai function with a list of `Dynamic` arguments.
    ///
    /// # Errors
    /// Returns `Err` if the function is not found or evaluation fails.
    pub fn call(&self, func: &str, args: Vec<Dynamic>) -> Result<Dynamic> {
        // Build a call expression and inject args via scope.
        let mut scope = Scope::new();
        let arg_names: Vec<String> = (0..args.len()).map(|i| format!("__a{i}__")).collect();
        for (name, val) in arg_names.iter().zip(args) {
            scope.push_dynamic(name, val);
        }
        let call_expr = format!("{}({})", func, arg_names.join(", "));
        self.engine
            .eval_with_scope::<Dynamic>(&mut scope, &call_expr)
            .map_err(ScriptError::from)
    }

    /// Register a global native function by name.
    pub fn register_global_fn<
        A: 'static,
        const N: usize,
        const X: bool,
        R: Clone + Send + Sync + 'static,
        const FN: bool,
        F: rhai::RhaiNativeFunc<A, N, X, R, FN> + Send + Sync + 'static,
    >(
        &mut self,
        name: &str,
        f: F,
    ) {
        self.engine.register_fn(name, f);
    }

    pub const fn inner(&self) -> &Engine {
        &self.engine
    }

    pub const fn inner_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }
}

impl Default for RhaiEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory binary store (shared with Lua layer design)
//
// The store is owned per-`RhaiScriptEngine` via an `Arc<Mutex<HashMap>>`
// (`BinaryStore`) so that distinct engines (and distinct tests) cannot pollute
// one another. A process-wide fallback singleton is retained ONLY for the free
// function helpers `rhai_load_binary_impl` / `rhai_get_info_impl`, which exist
// for backward compatibility with callers that do not hold an engine handle.
// New code SHOULD prefer the instance-scoped methods on `RhaiScriptEngine`
// (`load_binary` / `get_info`) or the `*_into` / `*_from` helpers below, which
// take an explicit per-engine `BinaryStore` and avoid cross-call pollution.
// ─────────────────────────────────────────────────────────────────────────────

/// A per-engine binary store: maps binary id → raw bytes.
pub type BinaryStore = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// Construct an empty `BinaryStore`.
#[must_use]
pub fn new_binary_store() -> BinaryStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Legacy process-wide fallback store. Prefer per-engine `BinaryStore`.
fn rhai_binary_store_legacy() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build_info_map(guard: &HashMap<String, Vec<u8>>, id: &str) -> rhai::Map {
    let mut map = rhai::Map::new();
    match guard.get(id) {
        None => {
            map.insert(
                "error".into(),
                Dynamic::from(format!("binary '{id}' not found")),
            );
        }
        Some(data) => {
            map.insert("format".into(), Dynamic::from(detect_format(data)));
            map.insert("arch".into(), Dynamic::from(detect_arch(data)));
            map.insert("size".into(), Dynamic::from(sat_usize_to_i64(data.len())));
            map.insert(
                "entry_point".into(),
                Dynamic::from(rhai_detect_entry_point(data).cast_signed()),
            );
            map.insert("id".into(), Dynamic::from(id.to_string()));
        }
    }
    map
}

/// Load a binary file into the given per-engine `BinaryStore` and return its id.
///
/// # Errors
/// Returns `Err` if the file cannot be read.
pub fn rhai_load_binary_into(store: &BinaryStore, path: &str) -> Result<String> {
    match std::fs::read(path) {
        Ok(data) => {
            store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(path.to_string(), data);
            Ok(path.to_string())
        }
        Err(e) => Err(ScriptError::Eval(Box::new(EvalAltResult::ErrorSystem(
            format!("load_binary: cannot read '{path}'"),
            Box::new(e),
        )))),
    }
}

/// Return a Rhai map with metadata about a binary stored in `store`.
#[must_use]
pub fn rhai_get_info_from(store: &BinaryStore, id: &str) -> rhai::Map {
    let guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    build_info_map(&guard, id)
}

/// Load a binary into the legacy global store and return its id.
///
/// Prefer the instance-scoped `RhaiScriptEngine::load_binary` for new code.
///
/// # Errors
/// Returns `Err` if the file cannot be read.
pub fn rhai_load_binary_impl(path: &str) -> Result<String> {
    match std::fs::read(path) {
        Ok(data) => {
            rhai_binary_store_legacy()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(path.to_string(), data);
            Ok(path.to_string())
        }
        Err(e) => Err(ScriptError::Eval(Box::new(EvalAltResult::ErrorSystem(
            format!("load_binary: cannot read '{path}'"),
            Box::new(e),
        )))),
    }
}

/// Return a Rhai map with metadata about a binary in the legacy global store.
///
/// Prefer the instance-scoped `RhaiScriptEngine::get_info` for new code.
#[must_use]
pub fn rhai_get_info_impl(id: &str) -> rhai::Map {
    let guard = rhai_binary_store_legacy()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    build_info_map(&guard, id)
}

fn rhai_detect_entry_point(data: &[u8]) -> u64 {
    if data.starts_with(b"\x7fELF") && data.len() > 32 {
        return u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 28 <= data.len() {
            return u64::from(u32::from_le_bytes([
                data[pe_off + 24],
                data[pe_off + 25],
                data[pe_off + 26],
                data[pe_off + 27],
            ]));
        }
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// RustreRhaiModule — binary analysis API
// ─────────────────────────────────────────────────────────────────────────────

/// Exposes the binary analysis API to Rhai scripts.
pub struct RustreRhaiModule;

impl RustreRhaiModule {
    /// Build and register the "re" module into an engine.
    pub fn register(engine: &mut Engine) {
        let module = Self::build_module();
        engine.register_static_module("re", module.into());

        // Also register individual free functions for ergonomic use.
        engine.register_fn("binary_info", |path: &str| -> rhai::Map {
            binary_info_impl(path)
        });
        engine.register_fn(
            "read_bytes",
            |path: &str, offset: i64, len: i64| -> rhai::Blob {
                read_bytes_impl(path, offset.cast_unsigned(), len.cast_unsigned())
            },
        );
        engine.register_fn("sha256_file", |path: &str| -> String {
            sha256_file_impl(path)
        });
        engine.register_fn("entropy", |data: rhai::Blob| -> f64 { entropy_impl(&data) });
        engine.register_fn(
            "find_pattern",
            |data: rhai::Blob, pattern: &str| -> rhai::Array { find_pattern_impl(&data, pattern) },
        );
        engine.register_fn("hex_encode", |data: rhai::Blob| -> String {
            hex_encode_impl(&data)
        });
        engine.register_fn("hex_decode", |hex: &str| -> rhai::Blob {
            hex_decode_impl(hex)
        });
        engine.register_fn("sha256_bytes", |data: rhai::Blob| -> String {
            sha256_bytes_impl(&data)
        });
        engine.register_fn("entropy_classify", |e: f64| -> String {
            entropy_classify(e)
        });
        engine.register_fn("xor_bytes", |data: rhai::Blob, key: i64| -> rhai::Blob {
            xor_bytes_impl(&data, trunc_i64_to_u8(key))
        });
        engine.register_fn("rol_bytes", |data: rhai::Blob, n: i64| -> rhai::Blob {
            rotate_bytes_impl(&data, trunc_i64_to_u8(n), true)
        });
        engine.register_fn("ror_bytes", |data: rhai::Blob, n: i64| -> rhai::Blob {
            rotate_bytes_impl(&data, trunc_i64_to_u8(n), false)
        });
        engine.register_fn("bytes_to_string", |data: rhai::Blob| -> String {
            String::from_utf8_lossy(&data).into_owned()
        });
        engine.register_fn(
            "find_strings_in_blob",
            |data: rhai::Blob, min_len: i64| -> rhai::Array {
                find_strings_in_blob(&data, sat_i64_to_usize(min_len))
            },
        );
        engine.register_fn("count_nonzero", |data: rhai::Blob| -> i64 {
            sat_usize_to_i64(data.iter().filter(|&&b| b != 0).count())
        });

        // ── RE binary-state bindings ──────────────────────────────────────────
        // load_binary(path) -> binary_id: string
        engine.register_fn(
            "load_binary",
            |path: &str| -> std::result::Result<String, Box<EvalAltResult>> {
                rhai_load_binary_impl(path).map_err(Into::into)
            },
        );

        // get_info(binary_id) -> map {format, arch, size, entry_point, id}
        engine.register_fn("get_info", |id: &str| -> rhai::Map {
            rhai_get_info_impl(id)
        });

        // ── RE utility bindings ───────────────────────────────────────────────
        // hex_to_dec("0x1a") -> 26
        engine.register_fn("hex_to_dec", |s: &str| -> i64 {
            i64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
        });

        // dec_to_hex(26) -> "0x1a"
        engine.register_fn("dec_to_hex", |n: i64| -> String { format!("{n:#x}") });

        // find_bytes(haystack, needle) -> index or -1
        engine.register_fn(
            "find_bytes",
            |haystack: rhai::Blob, needle: rhai::Blob| -> i64 {
                if needle.is_empty() || haystack.len() < needle.len() {
                    return -1;
                }
                for i in 0..=(haystack.len() - needle.len()) {
                    if haystack[i..i + needle.len()] == *needle {
                        return sat_usize_to_i64(i);
                    }
                }
                -1
            },
        );

        // xor(data, key) -> blob — named "xor" per task spec (xor_bytes is the existing alias)
        engine.register_fn("xor", |data: rhai::Blob, key: i64| -> rhai::Blob {
            data.iter().map(|&b| b ^ trunc_i64_to_u8(key)).collect()
        });
    }

    fn build_module() -> rhai::Module {
        let mut module = rhai::Module::new();

        module.set_native_fn(
            "binary_info",
            |path: &str| -> std::result::Result<rhai::Map, Box<EvalAltResult>> {
                Ok(binary_info_impl(path))
            },
        );
        module.set_native_fn(
            "read_bytes",
            |path: &str,
             offset: i64,
             len: i64|
             -> std::result::Result<rhai::Blob, Box<EvalAltResult>> {
                Ok(read_bytes_impl(
                    path,
                    offset.cast_unsigned(),
                    len.cast_unsigned(),
                ))
            },
        );
        module.set_native_fn(
            "sha256_file",
            |path: &str| -> std::result::Result<String, Box<EvalAltResult>> {
                Ok(sha256_file_impl(path))
            },
        );
        module.set_native_fn(
            "entropy",
            |data: rhai::Blob| -> std::result::Result<f64, Box<EvalAltResult>> {
                Ok(entropy_impl(&data))
            },
        );
        module.set_native_fn(
            "find_pattern",
            |data: rhai::Blob,
             pattern: &str|
             -> std::result::Result<rhai::Array, Box<EvalAltResult>> {
                Ok(find_pattern_impl(&data, pattern))
            },
        );
        module.set_native_fn(
            "hex_encode",
            |data: rhai::Blob| -> std::result::Result<String, Box<EvalAltResult>> {
                Ok(hex_encode_impl(&data))
            },
        );
        module.set_native_fn(
            "hex_decode",
            |hex: &str| -> std::result::Result<rhai::Blob, Box<EvalAltResult>> {
                Ok(hex_decode_impl(hex))
            },
        );

        module.set_native_fn(
            "load_binary",
            |path: &str| -> std::result::Result<String, Box<EvalAltResult>> {
                rhai_load_binary_impl(path).map_err(Into::into)
            },
        );

        module.set_native_fn(
            "get_info",
            |id: &str| -> std::result::Result<rhai::Map, Box<EvalAltResult>> {
                Ok(rhai_get_info_impl(id))
            },
        );

        module
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RE API implementation functions
// ─────────────────────────────────────────────────────────────────────────────

/// Return a Rhai map with metadata about a binary file.
///
/// Keys: `format`, `arch`, `size`, `sha256`, `entropy`, `path`.
fn binary_info_impl(path: &str) -> rhai::Map {
    let mut map = rhai::Map::new();
    map.insert("path".into(), Dynamic::from(path.to_owned()));

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            map.insert("error".into(), Dynamic::from(e.to_string()));
            return map;
        }
    };

    map.insert("size".into(), Dynamic::from(sat_usize_to_i64(data.len())));
    map.insert("sha256".into(), Dynamic::from(sha256_bytes_impl(&data)));
    map.insert("entropy".into(), Dynamic::from(entropy_impl(&data)));
    map.insert("format".into(), Dynamic::from(detect_format(&data)));
    map.insert("arch".into(), Dynamic::from(detect_arch(&data)));
    map
}

/// Read up to `len` bytes from a file starting at `offset`.
fn read_bytes_impl(path: &str, offset: u64, len: u64) -> rhai::Blob {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let start = sat_u64_to_usize(offset);
    if start >= data.len() {
        return Vec::new();
    }
    let end = (start + sat_u64_to_usize(len)).min(data.len());
    data[start..end].to_vec()
}

/// Compute SHA-256 of a file and return lowercase hex.
fn sha256_file_impl(path: &str) -> String {
    let Ok(data) = std::fs::read(path) else { return String::new() };
    sha256_bytes_impl(&data)
}

/// Compute SHA-256 of a byte slice.
#[must_use]
pub fn sha256_bytes_impl(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    // Format each byte as two lowercase hex digits → 64 hex chars total.
    digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Compute Shannon entropy in bits per byte (0.0 – 8.0).
#[must_use]
pub fn entropy_impl(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = lossy_usize_to_f64(data.len());
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = lossy_u64_to_f64(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Classify entropy into a human-readable verdict.
#[must_use]
pub fn entropy_classify(e: f64) -> String {
    if e < 1.0 {
        "very low (likely sparse / zero-filled)".to_owned()
    } else if e < 3.5 {
        "low (likely text or structured data)".to_owned()
    } else if e < 6.0 {
        "medium (likely compiled code)".to_owned()
    } else if e < 7.2 {
        "high (likely compressed or encrypted)".to_owned()
    } else {
        "very high (likely encrypted or random)".to_owned()
    }
}

/// Find all occurrences of a hex pattern in `data`.
///
/// `pattern` is a space-separated hex byte string, e.g. `"90 90 EB ??"`.
/// `??` acts as a wildcard matching any byte.
#[must_use]
pub fn find_pattern_impl(data: &[u8], pattern: &str) -> rhai::Array {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() || data.len() < tokens.len() {
        return Vec::new();
    }

    let parsed: Vec<Option<u8>> = tokens
        .iter()
        .map(|t| {
            if *t == "??" || *t == "?" {
                None
            } else {
                u8::from_str_radix(t, 16).ok()
            }
        })
        .collect();

    let pattern_len = parsed.len();
    let mut results: rhai::Array = Vec::new();

    for i in 0..=data.len().saturating_sub(pattern_len) {
        let matches = parsed
            .iter()
            .enumerate()
            .all(|(j, &mb)| mb.is_none_or(|b| data[i + j] == b));
        if matches {
            results.push(Dynamic::from(sat_usize_to_i64(i)));
        }
    }
    results
}

/// Encode bytes as a lowercase hex string.
#[must_use]
pub fn hex_encode_impl(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut acc = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(acc, "{b:02x}");
    }
    acc
}

/// Decode a hex string into bytes.  Returns empty blob on error.
#[must_use]
pub fn hex_decode_impl(hex: &str) -> rhai::Blob {
    let hex = hex.replace(' ', "").replace("0x", "");
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = u8::try_from((bytes[i] as char).to_digit(16).unwrap_or(0)).unwrap_or(0);
        let lo = u8::try_from((bytes[i + 1] as char).to_digit(16).unwrap_or(0)).unwrap_or(0);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// XOR every byte in `data` with `key`.
#[must_use]
pub fn xor_bytes_impl(data: &[u8], key: u8) -> rhai::Blob {
    data.iter().map(|&b| b ^ key).collect()
}

/// Rotate every byte left (`rol=true`) or right (`rol=false`) by `n` bits.
#[must_use]
pub fn rotate_bytes_impl(data: &[u8], n: u8, rol: bool) -> rhai::Blob {
    let n = n % 8;
    data.iter()
        .map(|&b| {
            if rol {
                b.rotate_left(u32::from(n))
            } else {
                b.rotate_right(u32::from(n))
            }
        })
        .collect()
}

/// Find printable ASCII strings of at least `min_len` characters.
#[must_use]
pub fn find_strings_in_blob(data: &[u8], min_len: usize) -> rhai::Array {
    let mut results: rhai::Array = Vec::new();
    let mut current = String::new();
    for &b in data {
        if (b.is_ascii() && !b.is_ascii_control()) || b == b'\t' {
            current.push(b as char);
        } else if current.len() >= min_len {
            results.push(Dynamic::from(std::mem::take(&mut current)));
        } else {
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(Dynamic::from(current));
    }
    results
}

/// Detect file format from magic bytes.
#[must_use]
pub fn detect_format(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        return "PE".into();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF".into();
    }
    if data.starts_with(b"dex\n") {
        return "DEX".into();
    }
    if data.starts_with(b"\0asm") {
        return "WASM".into();
    }
    if data.len() >= 4 {
        let m = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(m, 0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe) {
            return "MachO".into();
        }
        if m == 0xcafe_babe {
            return "MachO-fat".into();
        }
    }
    "unknown".into()
}

/// Detect architecture from magic bytes.
#[must_use]
pub fn detect_arch(data: &[u8]) -> String {
    if data.starts_with(b"\x7fELF") && data.len() > 18 {
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        return match e_machine {
            0x0003 => "x86",
            0x003e => "x86_64",
            0x0028 => "arm",
            0x00b7 => "aarch64",
            0x00f3 => "riscv",
            0x0008 => "mips",
            _ => "unknown",
        }
        .into();
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 6 <= data.len() && data[pe_off..pe_off + 4] == *b"PE\0\0" {
            let mach = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
            return match mach {
                0x8664 => "x86_64",
                0x014c => "x86",
                0xaa64 => "aarch64",
                0x01c4 => "arm",
                _ => "unknown",
            }
            .into();
        }
    }
    if data.starts_with(b"\0asm") {
        return "wasm32".into();
    }
    if data.starts_with(b"dex\n") {
        return "dalvik".into();
    }
    "unknown".into()
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiScriptEngine
// ─────────────────────────────────────────────────────────────────────────────

/// The main scripting engine.  Wraps `rhai::Engine` with a friendlier API.
pub struct RhaiScriptEngine {
    engine: Engine,
    pub state: Arc<Mutex<RustreState>>,
    pub event_bus: Arc<Mutex<EventBus>>,
    pub event_hooks: Arc<Mutex<EventHookSystem>>,
    /// Per-engine binary store. Isolated from other engines and the legacy
    /// process-wide singleton, so test runs and concurrent scripts cannot
    /// pollute each other.
    pub binary_store: BinaryStore,
}

impl std::fmt::Debug for RhaiScriptEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RhaiScriptEngine").finish_non_exhaustive()
    }
}

impl RhaiScriptEngine {
    // ── Construction ──────────────────────────────────────────────────────────

    #[must_use]
    pub fn new() -> Self {
        let engine = Engine::new();
        Self {
            engine,
            state: Arc::new(Mutex::new(RustreState::new())),
            event_bus: Arc::new(Mutex::new(EventBus::new())),
            event_hooks: Arc::new(Mutex::new(EventHookSystem::new())),
            binary_store: new_binary_store(),
        }
    }

    /// Load a binary file into this engine's isolated binary store and return
    /// its id. Does not touch the legacy global store.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read.
    pub fn load_binary(&self, path: &str) -> Result<String> {
        rhai_load_binary_into(&self.binary_store, path)
    }

    /// Return metadata about a binary previously loaded into this engine's
    /// store via `load_binary`.
    #[must_use]
    pub fn get_info(&self, id: &str) -> rhai::Map {
        rhai_get_info_from(&self.binary_store, id)
    }

    /// Create a new engine with the `rustre` and `re` modules pre-registered.
    #[must_use]
    pub fn with_rustre_module() -> Self {
        let mut this = Self::new();
        this.register_rustre_module();
        this
    }

    /// Create a new engine with the full RE analysis API registered.
    #[must_use]
    pub fn with_re_api() -> Self {
        let mut this = Self::new();
        this.register_rustre_module();
        RustreRhaiModule::register(&mut this.engine);
        // Override the global-backed `load_binary` / `get_info` bindings
        // registered by `RustreRhaiModule::register` with closures that route
        // through this engine's isolated binary store. Rhai resolves the most
        // recently registered function for a given name+arity, so these
        // shadow the global-backed implementations for scripts run by this
        // engine instance.
        let store_load = Arc::clone(&this.binary_store);
        this.engine.register_fn(
            "load_binary",
            move |path: &str| -> std::result::Result<String, Box<EvalAltResult>> {
                rhai_load_binary_into(&store_load, path).map_err(Into::into)
            },
        );
        let store_info = Arc::clone(&this.binary_store);
        this.engine.register_fn("get_info", move |id: &str| -> rhai::Map {
            rhai_get_info_from(&store_info, id)
        });
        this
    }

    // ── Module registration ───────────────────────────────────────────────────

    fn register_rustre_module(&mut self) {
        let state_log = Arc::clone(&self.state);
        self.engine.register_fn("rustre_log", move |msg: &str| {
            if let Ok(mut s) = state_log.lock() {
                s.log_messages.push(msg.to_string());
            }
            println!("[rustre] {msg}");
        });

        self.engine.register_fn("rustre_version", || -> String {
            "rustre-script-rhai 0.1.0".to_string()
        });

        let state_action = Arc::clone(&self.state);
        self.engine.register_fn(
            "rustre_action_register",
            move |name: &str, path: &str, _cb: FnPtr| {
                if let Ok(mut s) = state_action.lock() {
                    s.actions.push((name.to_string(), path.to_string()));
                }
            },
        );

        let state_event = Arc::clone(&self.state);
        self.engine
            .register_fn("rustre_event_on", move |event: &str, cb: FnPtr| {
                if let Ok(mut s) = state_event.lock() {
                    s.event_listeners
                        .push((event.to_string(), cb.fn_name().to_string()));
                }
            });

        let module = RustreModule::build();
        self.engine.register_static_module("rustre", module.into());
    }

    // ── Core API ──────────────────────────────────────────────────────────────

    /// # Errors
    /// Returns `Err` if the code fails to compile or evaluate.
    pub fn eval(&self, code: &str) -> Result<RhaiValue> {
        let result: Dynamic = self
            .engine
            .eval::<Dynamic>(code)
            .map_err(ScriptError::from)?;
        Ok(RhaiValue::from_dynamic(result))
    }

    /// # Errors
    /// Returns `Err` if the file cannot be read or the script fails to compile or run.
    pub fn load_file(&self, path: &Path) -> Result<()> {
        let code = std::fs::read_to_string(path)?;
        let ast = self
            .engine
            .compile(&code)
            .map_err(|e| ScriptError::Parse(e.into()))?;
        let mut scope = Scope::new();
        self.engine
            .run_ast_with_scope(&mut scope, &ast)
            .map_err(ScriptError::from)?;
        Ok(())
    }

    /// # Errors
    /// Returns `Err` if the function is not found or evaluation fails.
    pub fn call_function(&self, name: &str, args: impl Into<Dynamic>) -> Result<RhaiValue> {
        let arg: Dynamic = args.into();
        let call_code = if arg.is_unit() {
            format!("{name}()")
        } else {
            let mut scope = Scope::new();
            scope.push("__arg__", arg);
            let code = format!("{name}(__arg__)");
            let result: Dynamic = self
                .engine
                .eval_with_scope::<Dynamic>(&mut scope, &code)
                .map_err(ScriptError::from)?;
            return Ok(RhaiValue::from_dynamic(result));
        };
        let result: Dynamic = self
            .engine
            .eval::<Dynamic>(&call_code)
            .map_err(ScriptError::from)?;
        Ok(RhaiValue::from_dynamic(result))
    }

    pub fn register_fn<
        A: 'static,
        const N: usize,
        const X: bool,
        R: Clone + Send + Sync + 'static,
        const FN: bool,
        F: rhai::RhaiNativeFunc<A, N, X, R, FN> + Send + Sync + 'static,
    >(
        &mut self,
        name: &str,
        f: F,
    ) {
        self.engine.register_fn(name, f);
    }

    /// # Errors
    /// Returns `Err` if the code fails to parse.
    pub fn compile(&self, code: &str) -> Result<AST> {
        self.engine
            .compile(code)
            .map_err(|e| ScriptError::Parse(e.into()))
    }

    /// # Errors
    /// Returns `Err` if evaluation fails.
    pub fn run_ast(&self, ast: &AST) -> Result<RhaiValue> {
        let mut scope = Scope::new();
        let result: Dynamic = self
            .engine
            .eval_ast_with_scope::<Dynamic>(&mut scope, ast)
            .map_err(ScriptError::from)?;
        Ok(RhaiValue::from_dynamic(result))
    }

    pub const fn inner(&self) -> &Engine {
        &self.engine
    }

    pub const fn inner_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    // ── Typed eval helpers ────────────────────────────────────────────────────

    /// # Errors
    /// Returns `Err` if the code fails to evaluate or returns a non-numeric value.
    pub fn eval_int(&self, code: &str) -> Result<i64> {
        match self.eval(code)? {
            RhaiValue::Int(n) => Ok(n),
            RhaiValue::Float(f) => Ok(trunc_f64_to_i64(f)),
            other => Err(ScriptError::TypeError {
                expected: "int".into(),
                got: format!("{other:?}"),
            }),
        }
    }

    /// # Errors
    /// Returns `Err` if the code fails to evaluate or returns a non-bool value.
    pub fn eval_bool(&self, code: &str) -> Result<bool> {
        match self.eval(code)? {
            RhaiValue::Bool(b) => Ok(b),
            other => Err(ScriptError::TypeError {
                expected: "bool".into(),
                got: format!("{other:?}"),
            }),
        }
    }

    /// # Errors
    /// Returns `Err` if the code fails to evaluate.
    pub fn eval_string(&self, code: &str) -> Result<String> {
        match self.eval(code)? {
            RhaiValue::String(s) => Ok(s),
            other => Ok(other.to_string()),
        }
    }

    /// # Errors
    /// Returns `Err` if the code fails to evaluate or returns a non-numeric value.
    pub fn eval_float(&self, code: &str) -> Result<f64> {
        match self.eval(code)? {
            RhaiValue::Float(f) => Ok(f),
            RhaiValue::Int(n) => Ok(lossy_i64_to_f64(n)),
            other => Err(ScriptError::TypeError {
                expected: "float".into(),
                got: format!("{other:?}"),
            }),
        }
    }

    // ── RustreState helpers ───────────────────────────────────────────────────

    pub fn log_messages(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.log_messages.clone())
            .unwrap_or_default()
    }

    pub fn registered_actions(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .map(|s| s.actions.clone())
            .unwrap_or_default()
    }

    pub fn event_listeners(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .map(|s| s.event_listeners.clone())
            .unwrap_or_default()
    }

    // ── Eval with variable injection ──────────────────────────────────────────

    /// Evaluate code with a named variable pre-bound in scope.
    ///
    /// # Errors
    /// Returns `Err` if the code fails to evaluate.
    pub fn eval_with_var(
        &self,
        code: &str,
        var: &str,
        val: impl Into<Dynamic>,
    ) -> Result<RhaiValue> {
        let mut scope = Scope::new();
        scope.push_dynamic(var, val.into());
        let result: Dynamic = self
            .engine
            .eval_with_scope::<Dynamic>(&mut scope, code)
            .map_err(ScriptError::from)?;
        Ok(RhaiValue::from_dynamic(result))
    }

    /// Evaluate code with multiple named variables pre-bound in scope.
    ///
    /// # Errors
    /// Returns `Err` if the code fails to evaluate.
    pub fn eval_with_vars(&self, code: &str, vars: Vec<(&str, Dynamic)>) -> Result<RhaiValue> {
        let mut scope = Scope::new();
        for (name, val) in vars {
            scope.push_dynamic(name, val);
        }
        let result: Dynamic = self
            .engine
            .eval_with_scope::<Dynamic>(&mut scope, code)
            .map_err(ScriptError::from)?;
        Ok(RhaiValue::from_dynamic(result))
    }
}

impl Default for RhaiScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RustreModule helper — builds the static rhai::Module independently
// ─────────────────────────────────────────────────────────────────────────────

pub struct RustreModule;

impl RustreModule {
    #[must_use]
    pub fn build() -> rhai::Module {
        let mut module = rhai::Module::new();

        module.set_native_fn(
            "log",
            |msg: &str| -> std::result::Result<(), Box<EvalAltResult>> {
                println!("[rustre::log] {msg}");
                Ok(())
            },
        );

        module.set_native_fn(
            "version",
            |_dummy: i64| -> std::result::Result<rhai::ImmutableString, Box<EvalAltResult>> {
                Ok("rustre-script-rhai 0.1.0".into())
            },
        );

        // ── actions sub-module ────────────────────────────────────────────────
        let mut actions = rhai::Module::new();
        actions.set_native_fn(
            "register",
            |name: &str, path: &str, _cb: FnPtr| -> std::result::Result<(), Box<EvalAltResult>> {
                println!("[rustre::actions::register] name={name} path={path}");
                Ok(())
            },
        );
        module.set_sub_module("actions", actions);

        // ── events sub-module ─────────────────────────────────────────────────
        let mut events = rhai::Module::new();
        events.set_native_fn(
            "on",
            |event: &str, _cb: FnPtr| -> std::result::Result<(), Box<EvalAltResult>> {
                println!("[rustre::events::on] event={event}");
                Ok(())
            },
        );
        module.set_sub_module("events", events);

        // ── utils sub-module ──────────────────────────────────────────────────
        let mut utils = rhai::Module::new();
        utils.set_native_fn(
            "hex_encode",
            |data: rhai::Blob| -> std::result::Result<String, Box<EvalAltResult>> {
                Ok(hex_encode_impl(&data))
            },
        );
        utils.set_native_fn(
            "hex_decode",
            |hex: &str| -> std::result::Result<rhai::Blob, Box<EvalAltResult>> {
                Ok(hex_decode_impl(hex))
            },
        );
        utils.set_native_fn(
            "entropy",
            |data: rhai::Blob| -> std::result::Result<f64, Box<EvalAltResult>> {
                Ok(entropy_impl(&data))
            },
        );
        module.set_sub_module("utils", utils);

        module
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RE data types
// ─────────────────────────────────────────────────────────────────────────────

/// A disassembled instruction.
#[derive(Debug, Clone)]
pub struct RhaiInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub size: usize,
}

impl RhaiInstruction {
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        format!(
            "{:#010x}  {:16}  {}",
            self.address,
            hex_encode_impl(&self.bytes),
            if self.operands.is_empty() {
                self.mnemonic.clone()
            } else {
                format!("{} {}", self.mnemonic, self.operands)
            }
        )
    }
}

/// Cross-reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RhaiXrefKind {
    Call,
    Jump,
    Data,
    Unknown,
}

impl std::fmt::Display for RhaiXrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Jump => write!(f, "jump"),
            Self::Data => write!(f, "data"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for RhaiXrefKind {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "call" => Self::Call,
            "jump" => Self::Jump,
            "data" => Self::Data,
            _ => Self::Unknown,
        })
    }
}

/// Cross-reference record.
#[derive(Debug, Clone)]
pub struct RhaiXref {
    pub from: u64,
    pub to: u64,
    pub kind: RhaiXrefKind,
}

/// A function record.
#[derive(Debug, Clone)]
pub struct RhaiReFunction {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub is_renamed: bool,
    pub is_imported: bool,
}

/// Segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RhaiSegmentKind {
    Code,
    Data,
    ReadOnly,
    Bss,
    Unknown,
}

impl std::fmt::Display for RhaiSegmentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Code => "code",
            Self::Data => "data",
            Self::ReadOnly => "rodata",
            Self::Bss => "bss",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Segment record.
#[derive(Debug, Clone)]
pub struct RhaiSegment {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub kind: RhaiSegmentKind,
    pub flags: u32,
}

/// A found ASCII string.
#[derive(Debug, Clone)]
pub struct RhaiFoundString {
    pub offset: usize,
    pub value: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiReApi
// ─────────────────────────────────────────────────────────────────────────────

/// Host-side RE API.
#[derive(Debug, Default)]
pub struct RhaiReApi {
    functions: Vec<RhaiReFunction>,
    segments: Vec<RhaiSegment>,
    xrefs: Vec<RhaiXref>,
    comments: HashMap<u64, String>,
    labels: HashMap<u64, String>,
    patches: Vec<(u64, Vec<u8>)>,
    annotations: HashMap<u64, Vec<String>>,
}

impl RhaiReApi {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Disassembly ───────────────────────────────────────────────────────────

    #[must_use]
    pub fn disassemble(&self, base_address: u64, bytes: &[u8]) -> Vec<RhaiInstruction> {
        let mut insns = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (mnemonic, operands, size) = decode_x86(bytes[offset]);
            let size = size.min(bytes.len() - offset).max(1);
            insns.push(RhaiInstruction {
                address: base_address + offset as u64,
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
                bytes: bytes[offset..offset + size].to_vec(),
                size,
            });
            offset += size;
        }
        insns
    }

    /// Disassemble and return a formatted listing.
    #[must_use]
    pub fn disassemble_listing(&self, base_address: u64, bytes: &[u8]) -> String {
        let insns = self.disassemble(base_address, bytes);
        let mut out = String::with_capacity(insns.len() * 32);
        for (i, insn) in insns.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&insn.to_string_repr());
        }
        out
    }

    // ── Search ────────────────────────────────────────────────────────────────

    #[must_use]
    pub fn search_bytes(&self, haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return Vec::new();
        }
        (0..=haystack.len() - pattern.len())
            .filter(|&i| haystack[i..i + pattern.len()] == *pattern)
            .collect()
    }

    /// Search using a hex pattern with `??` wildcards.
    #[must_use]
    pub fn search_pattern(&self, haystack: &[u8], pattern: &str) -> Vec<usize> {
        let offsets = find_pattern_impl(haystack, pattern);
        offsets
            .into_iter()
            .filter_map(|d| d.try_cast::<i64>().map(sat_i64_to_usize))
            .collect()
    }

    #[must_use]
    pub fn find_strings(&self, data: &[u8], min_length: usize) -> Vec<RhaiFoundString> {
        let mut results = Vec::new();
        let mut start = 0usize;
        let mut current = String::new();
        for (i, &b) in data.iter().enumerate() {
            if (b.is_ascii() && !b.is_ascii_control()) || b == b'\t' {
                current.push(b as char);
            } else {
                if current.len() >= min_length {
                    results.push(RhaiFoundString {
                        offset: start,
                        value: std::mem::take(&mut current),
                    });
                } else {
                    current.clear();
                }
                start = i + 1;
            }
        }
        if current.len() >= min_length {
            results.push(RhaiFoundString {
                offset: start,
                value: current,
            });
        }
        results
    }

    // ── Patching ──────────────────────────────────────────────────────────────

    pub fn patch_bytes(&mut self, offset: usize, buf: &mut [u8], patch: &[u8]) {
        if offset + patch.len() <= buf.len() {
            buf[offset..offset + patch.len()].copy_from_slice(patch);
            self.patches.push((offset as u64, patch.to_vec()));
        }
    }

    pub fn nop_range(&mut self, buf: &mut [u8], start: usize, end: usize) {
        for i in start..end.min(buf.len()) {
            buf[i] = 0x90;
        }
        if start < end {
            self.patches.push((start as u64, vec![0x90; end - start]));
        }
    }

    #[must_use]
    pub fn patches(&self) -> &[(u64, Vec<u8>)] {
        &self.patches
    }

    #[must_use]
    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }

    // ── Xrefs ─────────────────────────────────────────────────────────────────

    pub fn add_xref(&mut self, xref: RhaiXref) {
        self.xrefs.push(xref);
    }

    #[must_use]
    pub fn get_xrefs_to(&self, address: u64) -> Vec<&RhaiXref> {
        self.xrefs.iter().filter(|x| x.to == address).collect()
    }

    #[must_use]
    pub fn get_xrefs_from(&self, address: u64) -> Vec<&RhaiXref> {
        self.xrefs.iter().filter(|x| x.from == address).collect()
    }

    pub fn remove_xref(&mut self, from: u64, to: u64) {
        self.xrefs.retain(|x| !(x.from == from && x.to == to));
    }

    #[must_use]
    pub const fn xref_count(&self) -> usize {
        self.xrefs.len()
    }

    // ── Functions ─────────────────────────────────────────────────────────────

    pub fn add_function(&mut self, func: RhaiReFunction) {
        self.functions.push(func);
    }

    #[must_use]
    pub fn list_functions(&self) -> &[RhaiReFunction] {
        &self.functions
    }

    #[must_use]
    pub fn get_function(&self, address: u64) -> Option<&RhaiReFunction> {
        self.functions.iter().find(|f| f.address == address)
    }

    pub fn rename_function(&mut self, address: u64, new_name: &str) -> bool {
        if let Some(f) = self.functions.iter_mut().find(|f| f.address == address) {
            f.name = new_name.to_string();
            f.is_renamed = true;
            return true;
        }
        false
    }

    pub fn remove_function(&mut self, address: u64) -> bool {
        let before = self.functions.len();
        self.functions.retain(|f| f.address != address);
        self.functions.len() < before
    }

    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Find functions whose names match a prefix.
    #[must_use]
    pub fn find_functions_by_prefix(&self, prefix: &str) -> Vec<&RhaiReFunction> {
        self.functions
            .iter()
            .filter(|f| f.name.starts_with(prefix))
            .collect()
    }

    // ── Segments ──────────────────────────────────────────────────────────────

    pub fn add_segment(&mut self, seg: RhaiSegment) {
        self.segments.push(seg);
    }

    #[must_use]
    pub fn list_segments(&self) -> &[RhaiSegment] {
        &self.segments
    }

    #[must_use]
    pub fn segment_at(&self, address: u64) -> Option<&RhaiSegment> {
        self.segments
            .iter()
            .find(|s| address >= s.address && address < s.address + s.size)
    }

    #[must_use]
    pub fn segment_by_name(&self, name: &str) -> Option<&RhaiSegment> {
        self.segments.iter().find(|s| s.name == name)
    }

    // ── Comments & Labels ─────────────────────────────────────────────────────

    pub fn set_comment(&mut self, address: u64, text: &str) {
        self.comments.insert(address, text.to_string());
    }

    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    pub fn remove_comment(&mut self, address: u64) -> bool {
        self.comments.remove(&address).is_some()
    }

    #[must_use]
    pub fn comment_count(&self) -> usize {
        self.comments.len()
    }

    pub fn set_label(&mut self, address: u64, label: &str) {
        self.labels.insert(address, label.to_string());
    }

    pub fn get_label(&self, address: u64) -> Option<&str> {
        self.labels.get(&address).map(String::as_str)
    }

    pub fn remove_label(&mut self, address: u64) -> bool {
        self.labels.remove(&address).is_some()
    }

    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    // ── Annotations ───────────────────────────────────────────────────────────

    pub fn add_annotation(&mut self, address: u64, note: &str) {
        self.annotations
            .entry(address)
            .or_default()
            .push(note.to_string());
    }

    #[must_use]
    pub fn get_annotations(&self, address: u64) -> &[String] {
        self.annotations
            .get(&address)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn annotation_count(&self) -> usize {
        self.annotations.values().map(std::vec::Vec::len).sum()
    }

    // ── Decompiler stub ───────────────────────────────────────────────────────

    /// Produce a best-effort C-style pseudocode rendering for the function at
    /// `address` using the registered metadata (function record, segment,
    /// label, comment, annotations and outgoing cross-references).
    #[must_use]
    pub fn decompile(&self, address: u64) -> String {
        use std::fmt::Write;
        let func = self.get_function(address);
        let name = func
            .map(|f| f.name.clone())
            .or_else(|| self.get_label(address).map(String::from))
            .unwrap_or_else(|| format!("sub_{address:08x}"));
        let mut out = String::new();
        let _ = writeln!(out, "// Decompiled {name} @ {address:#x}");
        if let Some(seg) = self.segment_at(address) {
            let _ = writeln!(out, "// Segment: {} ({}) base={:#x} size={}", seg.name, seg.kind, seg.address, seg.size);
        }
        if let Some(c) = self.get_comment(address) {
            let _ = writeln!(out, "// {c}");
        }
        for note in self.get_annotations(address) {
            let _ = writeln!(out, "// note: {note}");
        }
        let is_imported = func.is_some_and(|f| f.is_imported);
        let prefix = if is_imported { "/* imported */ " } else { "" };
        let _ = writeln!(out, "{prefix}void {name}(void) {{");
        let xrefs_in = self.get_xrefs_to(address);
        if !xrefs_in.is_empty() {
            let _ = writeln!(out, "    // {} incoming xref(s)", xrefs_in.len());
        }
        let xrefs_out = self.get_xrefs_from(address);
        for x in xrefs_out.iter().take(8) {
            let _ = writeln!(out, "    {}({:#x});", x.kind, x.to);
        }
        if xrefs_out.len() > 8 {
            let _ = writeln!(out, "    // {} additional call(s) elided", xrefs_out.len() - 8);
        }
        if let Some(f) = func {
            let _ = writeln!(out, "    // size={} bytes", f.size);
        }
        out.push_str("}\n");
        out
    }

    /// Export analysis state to JSON-compatible string.
    #[must_use]
    pub fn export_json(&self) -> String {
        let fns: Vec<String> = self
            .functions
            .iter()
            .map(|f| {
                format!(
                    r#"{{"addr":{:#x},"name":"{}","size":{}}}"#,
                    f.address, f.name, f.size
                )
            })
            .collect();
        let segs: Vec<String> = self
            .segments
            .iter()
            .map(|s| {
                format!(
                    r#"{{"addr":{:#x},"size":{},"name":"{}","kind":"{}"}}"#,
                    s.address, s.size, s.name, s.kind
                )
            })
            .collect();
        format!(
            r#"{{"functions":[{}],"segments":[{}],"xref_count":{},"comment_count":{}}}"#,
            fns.join(","),
            segs.join(","),
            self.xrefs.len(),
            self.comments.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sandbox / module registry / batch runner / progress
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RhaiSandboxPolicy {
    AllowList(Vec<String>),
    DenyList(Vec<String>),
    Unrestricted,
}

#[derive(Debug, Clone)]
pub struct RhaiSandbox {
    policy: RhaiSandboxPolicy,
}

impl RhaiSandbox {
    #[must_use]
    pub const fn new(policy: RhaiSandboxPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn is_allowed(&self, name: &str) -> bool {
        match &self.policy {
            RhaiSandboxPolicy::AllowList(list) => list.iter().any(|s| s == name),
            RhaiSandboxPolicy::DenyList(list) => !list.iter().any(|s| s == name),
            RhaiSandboxPolicy::Unrestricted => true,
        }
    }

    #[must_use]
    pub const fn policy_name(&self) -> &'static str {
        match &self.policy {
            RhaiSandboxPolicy::AllowList(_) => "allow_list",
            RhaiSandboxPolicy::DenyList(_) => "deny_list",
            RhaiSandboxPolicy::Unrestricted => "unrestricted",
        }
    }
}

impl Default for RhaiSandbox {
    fn default() -> Self {
        Self::new(RhaiSandboxPolicy::Unrestricted)
    }
}

#[derive(Debug, Default)]
pub struct RhaiModuleRegistry {
    modules: HashMap<String, String>,
}

impl RhaiModuleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: &str, source: String) {
        self.modules.insert(name.to_string(), source);
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.modules.get(name).map(String::as_str)
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.modules.remove(name).is_some()
    }

    pub fn list_modules(&self) -> Vec<&str> {
        self.modules.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

/// Script template helpers.
pub struct RhaiScriptTemplate;

impl RhaiScriptTemplate {
    #[must_use]
    pub fn find_xrefs(target: u64) -> String {
        format!("// Find xrefs to {target:#x}\nlet target = {target};\n")
    }

    #[must_use]
    pub fn extract_strings() -> String {
        "// Extract strings\nlet strings = find_strings(4);\n".to_string()
    }

    #[must_use]
    pub fn rename_functions(old_prefix: &str, new_prefix: &str) -> String {
        format!("// Rename {old_prefix} -> {new_prefix}\nfor func in list_functions() {{}}\n")
    }

    #[must_use]
    pub fn entropy_check(path: &str) -> String {
        format!(
            r#"// Entropy analysis of {path}
let info = binary_info("{path}");
let e = info["entropy"];
print("Entropy: " + e);
print("Classification: " + entropy_classify(e));
"#
        )
    }

    #[must_use]
    pub fn pattern_search(pattern: &str) -> String {
        format!(
            r#"// Search for pattern: {pattern}
let data = read_bytes(path, 0, 0x10000);
let hits = find_pattern(data, "{pattern}");
print("Found " + hits.len() + " occurrences");
"#
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn decode_x86(byte: u8) -> (&'static str, &'static str, usize) {
    match byte {
        0x55 => ("push", "rbp", 1),
        0x5D => ("pop", "rbp", 1),
        0xC3 => ("ret", "", 1),
        0x90 => ("nop", "", 1),
        0xCC => ("int3", "", 1),
        0x50..=0x5F => ("push/pop", "reg", 1),
        0xE8 => ("call", "rel32", 5),
        0xE9 => ("jmp", "rel32", 5),
        0xEB => ("jmp", "rel8", 2),
        0x74 | 0x75 | 0x7C | 0x7D => ("jcc", "rel8", 2),
        0x89 | 0x8B => ("mov", "r/m", 2),
        0x83 => ("alu", "r/m, imm8", 3),
        0x31 | 0x33 => ("xor", "r/m", 2),
        0xFF => ("call/jmp", "r/m64", 2),
        0x48 => ("rex.w", "", 1),
        0x0F => ("0F prefix", "", 1),
        _ => ("db", "", 1),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ── RhaiValue conversion ──────────────────────────────────────────────────

    #[test]
    fn test_rhai_value_unit_roundtrip() {
        let v = RhaiValue::Unit;
        let d = v.into_dynamic();
        assert!(d.is_unit());
        assert_eq!(RhaiValue::from_dynamic(d), RhaiValue::Unit);
    }

    #[test]
    fn test_rhai_value_bool_roundtrip() {
        for b in [true, false] {
            let v = RhaiValue::Bool(b);
            let d = v.clone().into_dynamic();
            assert_eq!(RhaiValue::from_dynamic(d), v);
        }
    }

    #[test]
    fn test_rhai_value_int_roundtrip() {
        let v = RhaiValue::Int(42);
        let d = v.clone().into_dynamic();
        assert_eq!(RhaiValue::from_dynamic(d), v);
    }

    #[test]
    fn test_rhai_value_float_roundtrip() {
        let v = RhaiValue::Float(3.14_f64);
        let d = v.clone().into_dynamic();
        assert_eq!(RhaiValue::from_dynamic(d), v);
    }

    #[test]
    fn test_rhai_value_string_roundtrip() {
        let v = RhaiValue::String("hello".into());
        let d = v.clone().into_dynamic();
        assert_eq!(RhaiValue::from_dynamic(d), v);
    }

    #[test]
    fn test_rhai_value_array_roundtrip() {
        let v = RhaiValue::Array(vec![
            RhaiValue::Int(1),
            RhaiValue::Int(2),
            RhaiValue::Int(3),
        ]);
        let d = v.clone().into_dynamic();
        assert_eq!(RhaiValue::from_dynamic(d), v);
    }

    #[test]
    fn test_rhai_value_bytes_roundtrip() {
        let v = RhaiValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let d = v.clone().into_dynamic();
        assert_eq!(RhaiValue::from_dynamic(d), v);
    }

    #[test]
    fn test_rhai_value_display() {
        assert_eq!(RhaiValue::Unit.to_string(), "()");
        assert_eq!(RhaiValue::Bool(true).to_string(), "true");
        assert_eq!(RhaiValue::Int(7).to_string(), "7");
        assert_eq!(RhaiValue::Float(1.5).to_string(), "1.5");
        assert_eq!(RhaiValue::String("x".into()).to_string(), "x");
        assert_eq!(
            RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Int(2)]).to_string(),
            "[1, 2]"
        );
        assert!(RhaiValue::Bytes(vec![0, 1]).to_string().contains("blob"));
    }

    #[test]
    fn test_rhai_value_accessors() {
        assert_eq!(RhaiValue::Int(42).as_int(), Some(42));
        assert_eq!(RhaiValue::Float(1.5).as_float(), Some(1.5));
        assert_eq!(RhaiValue::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(RhaiValue::Bool(true).as_bool(), Some(true));
        assert!(RhaiValue::Unit.is_unit());
    }

    // ── Basic eval ────────────────────────────────────────────────────────────

    #[test]
    fn test_engine_new_and_basic_eval() {
        let engine = RhaiScriptEngine::new();
        let v = engine.eval("1 + 1").unwrap();
        assert_eq!(v, RhaiValue::Int(2));
    }

    #[test]
    fn test_eval_arithmetic() {
        let engine = RhaiScriptEngine::new();
        assert_eq!(engine.eval_int("3 * 7").unwrap(), 21);
        assert_eq!(engine.eval_int("100 / 4").unwrap(), 25);
        assert_eq!(engine.eval_int("17 % 5").unwrap(), 2);
        assert_eq!(engine.eval_int("10 - 3").unwrap(), 7);
    }

    #[test]
    fn test_eval_float_arithmetic() {
        let engine = RhaiScriptEngine::new();
        let f = engine.eval_float("1.0 + 2.5").unwrap();
        assert!((f - 3.5).abs() < 1e-9);
    }

    #[test]
    fn test_eval_bool_expressions() {
        let engine = RhaiScriptEngine::new();
        assert!(engine.eval_bool("3 > 2").unwrap());
        assert!(!engine.eval_bool("2 > 3").unwrap());
        assert!(engine.eval_bool("true && true").unwrap());
        assert!(!engine.eval_bool("true && false").unwrap());
        assert!(engine.eval_bool("false || true").unwrap());
        assert!(engine.eval_bool("!false").unwrap());
    }

    #[test]
    fn test_eval_string_concat() {
        let engine = RhaiScriptEngine::new();
        let s = engine.eval_string(r#""hello" + " " + "world""#).unwrap();
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_eval_if_else() {
        let engine = RhaiScriptEngine::new();
        assert_eq!(engine.eval_int("if true { 1 } else { 2 }").unwrap(), 1);
        assert_eq!(engine.eval_int("if false { 1 } else { 2 }").unwrap(), 2);
    }

    #[test]
    fn test_eval_let_variable() {
        let engine = RhaiScriptEngine::new();
        assert_eq!(
            engine.eval_int("let x = 10; let y = 32; x + y").unwrap(),
            42
        );
    }

    #[test]
    fn test_eval_while_loop() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_int("let s = 0; let i = 1; while i <= 5 { s += i; i += 1; } s")
            .unwrap();
        assert_eq!(result, 15);
    }

    #[test]
    fn test_eval_for_loop() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_int("let s = 0; for i in [1, 2, 3, 4, 5] { s += i; } s")
            .unwrap();
        assert_eq!(result, 15);
    }

    #[test]
    fn test_eval_function_definition_and_call() {
        let engine = RhaiScriptEngine::new();
        let result = engine.eval_int("fn square(n) { n * n } square(9)").unwrap();
        assert_eq!(result, 81);
    }

    #[test]
    fn test_eval_recursive_function() {
        let engine = RhaiScriptEngine::new();
        let code = "
            fn factorial(n) {
                if n <= 1 { return 1; }
                n * factorial(n - 1)
            }
            factorial(6)
        ";
        assert_eq!(engine.eval_int(code).unwrap(), 720);
    }

    #[test]
    fn test_eval_array_operations() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval("let a = [1, 2, 3]; a.push(4); a.len()")
            .unwrap();
        assert_eq!(result, RhaiValue::Int(4));
    }

    #[test]
    fn test_eval_string_methods() {
        let engine = RhaiScriptEngine::new();
        let upper = engine.eval_string(r#""hello".to_upper()"#).unwrap();
        assert_eq!(upper, "HELLO");
        let lower = engine.eval_string(r#""WORLD".to_lower()"#).unwrap();
        assert_eq!(lower, "world");
    }

    // ── compile + run_ast ─────────────────────────────────────────────────────

    #[test]
    fn test_compile_and_run_ast() {
        let engine = RhaiScriptEngine::new();
        let ast = engine.compile("40 + 2").unwrap();
        let result = engine.run_ast(&ast).unwrap();
        assert_eq!(result, RhaiValue::Int(42));
    }

    // ── register_fn ──────────────────────────────────────────────────────────

    #[test]
    fn test_register_fn_i64() {
        let mut engine = RhaiScriptEngine::new();
        engine.register_fn("double", |x: i64| x * 2_i64);
        let result = engine.eval_int("double(21)").unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_register_fn_string() {
        let mut engine = RhaiScriptEngine::new();
        engine.register_fn("greet", |name: &str| format!("Hello, {name}!"));
        let result = engine.eval_string(r#"greet("Alice")"#).unwrap();
        assert_eq!(result, "Hello, Alice!");
    }

    #[test]
    fn test_register_fn_two_args() {
        let mut engine = RhaiScriptEngine::new();
        engine.register_fn("add", |a: i64, b: i64| a + b);
        let result = engine.eval_int("add(19, 23)").unwrap();
        assert_eq!(result, 42);
    }

    // ── with_rustre_module ────────────────────────────────────────────────────

    #[test]
    fn test_rustre_version_flat() {
        let engine = RhaiScriptEngine::with_rustre_module();
        let v = engine.eval_string("rustre_version()").unwrap();
        assert!(v.contains("rustre-script-rhai"));
    }

    #[test]
    fn test_rustre_log_appends_to_state() {
        let engine = RhaiScriptEngine::with_rustre_module();
        engine.eval(r#"rustre_log("test message")"#).unwrap();
        let msgs = engine.log_messages();
        assert_eq!(msgs, vec!["test message"]);
    }

    #[test]
    fn test_rustre_log_multiple_messages() {
        let engine = RhaiScriptEngine::with_rustre_module();
        engine
            .eval(r#"rustre_log("one"); rustre_log("two"); rustre_log("three")"#)
            .unwrap();
        let msgs = engine.log_messages();
        assert_eq!(msgs, vec!["one", "two", "three"]);
    }

    // ── EventBus ──────────────────────────────────────────────────────────────

    #[test]
    fn test_event_bus_empty_dispatch() {
        let bus = EventBus::new();
        let engine = Engine::new();
        let results = bus.dispatch(&engine, "nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_event_bus_single_handler() {
        let engine_host = RhaiScriptEngine::new();
        let ast = engine_host.compile("1 + 1").unwrap();
        let mut bus = EventBus::new();
        bus.on("tick", ast);
        assert_eq!(bus.handler_count(), 1);
        let results = bus.dispatch(engine_host.inner(), "tick");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().unwrap(), &RhaiValue::Int(2));
    }

    #[test]
    fn test_event_bus_multiple_events() {
        let engine_host = RhaiScriptEngine::new();
        let ast_a = engine_host.compile("10").unwrap();
        let ast_b = engine_host.compile("20").unwrap();
        let mut bus = EventBus::new();
        bus.on("alpha", ast_a);
        bus.on("beta", ast_b);
        assert_eq!(bus.handler_count(), 2);
        let alpha = bus.dispatch(engine_host.inner(), "alpha");
        assert_eq!(alpha[0].as_ref().unwrap(), &RhaiValue::Int(10));
        let beta = bus.dispatch(engine_host.inner(), "beta");
        assert_eq!(beta[0].as_ref().unwrap(), &RhaiValue::Int(20));
    }

    #[test]
    fn test_event_bus_multiple_handlers_same_event() {
        let engine_host = RhaiScriptEngine::new();
        let ast1 = engine_host.compile("100").unwrap();
        let ast2 = engine_host.compile("200").unwrap();
        let mut bus = EventBus::new();
        bus.on("load", ast1);
        bus.on("load", ast2);
        let results = bus.dispatch(engine_host.inner(), "load");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap(), &RhaiValue::Int(100));
        assert_eq!(results[1].as_ref().unwrap(), &RhaiValue::Int(200));
    }

    #[test]
    fn test_event_bus_remove_handlers() {
        let engine_host = RhaiScriptEngine::new();
        let ast = engine_host.compile("1").unwrap();
        let mut bus = EventBus::new();
        bus.on("load", ast);
        assert_eq!(bus.handler_count(), 1);
        bus.remove_handlers("load");
        assert_eq!(bus.handler_count(), 0);
    }

    #[test]
    fn test_event_bus_registered_events() {
        let engine_host = RhaiScriptEngine::new();
        let ast = engine_host.compile("1").unwrap();
        let mut bus = EventBus::new();
        bus.on("load", ast);
        let events = bus.registered_events();
        assert!(events.contains(&"load".to_string()));
    }

    #[test]
    fn test_event_bus_dispatch_with_data() {
        let engine_host = RhaiScriptEngine::new();
        // event_data is injected into scope; return it + 1
        let ast = engine_host.compile("event_data + 1").unwrap();
        let mut bus = EventBus::new();
        bus.on("compute", ast);
        let results = bus.dispatch_with_data(engine_host.inner(), "compute", Dynamic::from(41_i64));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().unwrap(), &RhaiValue::Int(42));
    }

    // ── EventHookSystem ───────────────────────────────────────────────────────

    #[test]
    fn test_event_hook_system_on_function_analyzed() {
        let engine_host = RhaiScriptEngine::new();
        let ptr = engine_host.compile("fn my_handler() {}").unwrap();
        // Compile a FnPtr string reference (we use a workaround via eval)
        let hooks = EventHookSystem::new();
        // Without a real FnPtr we test hook_count via on_event.
        let _ = hooks.hooks_for("function_analyzed");
        assert_eq!(hooks.hook_count(), 0);
        let _ = ptr; // silence unused warning
    }

    #[test]
    fn test_event_hook_system_emit_no_scripts() {
        let engine = Engine::new();
        let hooks = EventHookSystem::new();
        let results = hooks.emit(&engine, "binary_loaded", Dynamic::from("test"));
        assert!(results.is_empty());
    }

    #[test]
    fn test_event_hook_system_register_and_emit() {
        let engine_host = RhaiScriptEngine::new();
        let ast = engine_host.compile("event_data").unwrap();
        let mut hooks = EventHookSystem::new();
        hooks.register_script("my_cb", ast);
        hooks.hooks.push(("binary_loaded".into(), "my_cb".into()));
        let results = hooks.emit(engine_host.inner(), "binary_loaded", Dynamic::from("hello"));
        assert_eq!(results.len(), 1);
        if let Ok(RhaiValue::String(s)) = &results[0] {
            assert_eq!(s, "hello");
        }
    }

    // ── Error paths ───────────────────────────────────────────────────────────

    #[test]
    fn test_eval_syntax_error_returns_err() {
        let engine = RhaiScriptEngine::new();
        assert!(engine.eval("fn (").is_err());
    }

    #[test]
    fn test_eval_runtime_error_returns_err() {
        let engine = RhaiScriptEngine::new();
        assert!(engine.eval("1 / 0").is_err());
    }

    #[test]
    fn test_load_file_nonexistent_returns_err() {
        let engine = RhaiScriptEngine::new();
        let result = engine.load_file(Path::new("nonexistent_file.rhai"));
        assert!(result.is_err());
    }

    // ── RustreModule::build ───────────────────────────────────────────────────

    #[test]
    fn test_rustre_module_build_has_sub_modules() {
        let module = RustreModule::build();
        assert!(module.get_sub_module("actions").is_some());
        assert!(module.get_sub_module("events").is_some());
        assert!(module.get_sub_module("utils").is_some());
    }

    // ── Misc eval ─────────────────────────────────────────────────────────────

    #[test]
    fn test_eval_map_access() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_int(r"let m = #{x: 10, y: 20}; m.x + m.y")
            .unwrap();
        assert_eq!(result, 30);
    }

    #[test]
    fn test_eval_nested_function_calls() {
        let engine = RhaiScriptEngine::new();
        let code = "
            fn add(a, b) { a + b }
            fn mul(a, b) { a * b }
            add(mul(2, 3), mul(4, 5))
        ";
        assert_eq!(engine.eval_int(code).unwrap(), 26);
    }

    #[test]
    fn test_eval_string_interpolation_via_concat() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_string(r#"let name = "world"; "hello " + name"#)
            .unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_eval_chained_comparisons() {
        let engine = RhaiScriptEngine::new();
        assert!(engine.eval_bool("1 < 2 && 2 < 3").unwrap());
        assert!(!engine.eval_bool("1 < 2 && 3 < 2").unwrap());
    }

    #[test]
    fn test_eval_closure() {
        let engine = RhaiScriptEngine::new();
        let result = engine.eval_int("let f = |x| x * x; f.call(5)").unwrap();
        assert_eq!(result, 25);
    }

    #[test]
    fn test_eval_array_loop_sum() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_int("let arr = [1, 2, 3, 4, 5]; let s = 0; for x in arr { s += x; } s")
            .unwrap();
        assert_eq!(result, 15);
    }

    #[test]
    fn test_engine_default_trait() {
        let _engine: RhaiScriptEngine = RhaiScriptEngine::default();
    }

    #[test]
    fn test_rustre_state_default() {
        let state = RustreState::default();
        assert!(state.log_messages.is_empty());
        assert!(state.actions.is_empty());
        assert!(state.event_listeners.is_empty());
    }

    #[test]
    fn test_error_display() {
        let err = ScriptError::FunctionNotFound("my_fn".into());
        assert!(err.to_string().contains("my_fn"));

        let err2 = ScriptError::TypeError {
            expected: "int".into(),
            got: "string".into(),
        };
        assert!(err2.to_string().contains("int"));
        assert!(err2.to_string().contains("string"));
    }

    // ── RE API ────────────────────────────────────────────────────────────────

    #[test]
    fn test_re_api_disassemble() {
        let api = RhaiReApi::new();
        let insns = api.disassemble(0x1000, &[0x55, 0xC3, 0x90]);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[1].mnemonic, "ret");
        assert_eq!(insns[2].mnemonic, "nop");
    }

    #[test]
    fn test_re_api_disassemble_listing() {
        let api = RhaiReApi::new();
        let listing = api.disassemble_listing(0x1000, &[0x55, 0xC3]);
        assert!(listing.contains("push") || listing.contains("0x00001000"));
    }

    #[test]
    fn test_re_api_search_bytes() {
        let api = RhaiReApi::new();
        let data: Vec<u8> = (0u8..20u8).collect();
        let hits = api.search_bytes(&data, &[0x0A, 0x0B]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], 10);
    }

    #[test]
    fn test_re_api_search_pattern_with_wildcard() {
        let api = RhaiReApi::new();
        let data = b"\x55\x89\xE5\x55\x89\xE6";
        // Pattern: 55 ?? E5 — matches first three bytes
        let hits = api.search_pattern(data, "55 ?? E5");
        assert!(!hits.is_empty());
        assert_eq!(hits[0], 0);
    }

    #[test]
    fn test_re_api_find_strings() {
        let api = RhaiReApi::new();
        let data = b"hello\x00world\x00\x01\x02";
        let strings = api.find_strings(data, 4);
        assert!(strings.iter().any(|s| s.value == "hello"));
        assert!(strings.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn test_re_api_patch_bytes() {
        let mut api = RhaiReApi::new();
        let mut buf = vec![0u8; 8];
        api.patch_bytes(0, &mut buf, &[0xCC]);
        assert_eq!(buf[0], 0xCC);
        assert_eq!(api.patch_count(), 1);
    }

    #[test]
    fn test_re_api_nop_range() {
        let mut api = RhaiReApi::new();
        let mut buf = vec![0xE8u8, 0x00, 0x00, 0x00, 0x00];
        api.nop_range(&mut buf, 0, 5);
        assert!(buf.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_re_api_function_ops() {
        let mut api = RhaiReApi::new();
        api.add_function(RhaiReFunction {
            address: 0x3000,
            name: "sub_3000".to_string(),
            size: 48,
            is_renamed: false,
            is_imported: false,
        });
        assert_eq!(api.function_count(), 1);
        assert!(api.rename_function(0x3000, "parse_pe"));
        assert_eq!(api.get_function(0x3000).unwrap().name, "parse_pe");
        assert!(api.get_function(0x3000).unwrap().is_renamed);
        assert!(api.remove_function(0x3000));
        assert_eq!(api.function_count(), 0);
    }

    #[test]
    fn test_re_api_find_functions_by_prefix() {
        let mut api = RhaiReApi::new();
        for (addr, name) in [
            (0x1000, "sub_1000"),
            (0x2000, "malloc"),
            (0x3000, "sub_3000"),
        ] {
            api.add_function(RhaiReFunction {
                address: addr,
                name: name.into(),
                size: 0,
                is_renamed: false,
                is_imported: false,
            });
        }
        let subs = api.find_functions_by_prefix("sub_");
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn test_re_api_xrefs() {
        let mut api = RhaiReApi::new();
        api.add_xref(RhaiXref {
            from: 0x1000,
            to: 0x3000,
            kind: RhaiXrefKind::Call,
        });
        api.add_xref(RhaiXref {
            from: 0x1010,
            to: 0x3000,
            kind: RhaiXrefKind::Call,
        });
        assert_eq!(api.get_xrefs_to(0x3000).len(), 2);
        assert_eq!(api.get_xrefs_from(0x1000).len(), 1);
        api.remove_xref(0x1000, 0x3000);
        assert_eq!(api.xref_count(), 1);
    }

    #[test]
    fn test_re_api_segment_ops() {
        let mut api = RhaiReApi::new();
        api.add_segment(RhaiSegment {
            address: 0x1000,
            size: 0x2000,
            name: ".text".to_string(),
            kind: RhaiSegmentKind::Code,
            flags: 5,
        });
        assert_eq!(api.list_segments().len(), 1);
        assert!(api.segment_at(0x1500).is_some());
        assert!(api.segment_at(0x5000).is_none());
        assert_eq!(api.segment_by_name(".text").unwrap().flags, 5);
    }

    #[test]
    fn test_re_api_comments_labels() {
        let mut api = RhaiReApi::new();
        api.set_comment(0x2000, "entry point");
        assert_eq!(api.get_comment(0x2000), Some("entry point"));
        assert!(api.remove_comment(0x2000));
        assert_eq!(api.comment_count(), 0);

        api.set_label(0x2000, "_start");
        assert_eq!(api.get_label(0x2000), Some("_start"));
        assert!(api.remove_label(0x2000));
        assert_eq!(api.label_count(), 0);
    }

    #[test]
    fn test_re_api_annotations() {
        let mut api = RhaiReApi::new();
        api.add_annotation(0x1000, "first note");
        api.add_annotation(0x1000, "second note");
        assert_eq!(api.get_annotations(0x1000).len(), 2);
        assert_eq!(api.annotation_count(), 2);
    }

    #[test]
    fn test_re_api_decompile() {
        let api = RhaiReApi::new();
        let code = api.decompile(0x5000);
        assert!(code.contains("5000") || code.contains("0x5000"));
    }

    #[test]
    fn test_re_api_export_json() {
        let mut api = RhaiReApi::new();
        api.add_function(RhaiReFunction {
            address: 0x1000,
            name: "main".into(),
            size: 100,
            is_renamed: false,
            is_imported: false,
        });
        let json = api.export_json();
        assert!(json.contains("main"));
        assert!(json.contains("function_count") || json.contains("functions"));
    }

    // ── Sandbox ───────────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_allow_list() {
        let sb = RhaiSandbox::new(RhaiSandboxPolicy::AllowList(vec!["print".to_string()]));
        assert!(sb.is_allowed("print"));
        assert!(!sb.is_allowed("fs::read"));
        assert_eq!(sb.policy_name(), "allow_list");
    }

    #[test]
    fn test_sandbox_deny_list() {
        let sb = RhaiSandbox::new(RhaiSandboxPolicy::DenyList(vec!["fs::read".to_string()]));
        assert!(sb.is_allowed("print"));
        assert!(!sb.is_allowed("fs::read"));
        assert_eq!(sb.policy_name(), "deny_list");
    }

    #[test]
    fn test_sandbox_unrestricted() {
        let sb = RhaiSandbox::default();
        assert!(sb.is_allowed("anything"));
        assert_eq!(sb.policy_name(), "unrestricted");
    }

    // ── Module registry ───────────────────────────────────────────────────────

    #[test]
    fn test_module_registry() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register("re", "// re module".to_string());
        assert!(reg.get("re").is_some());
        assert!(reg.get("math").is_none());
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        reg.remove("re");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_module_registry_list() {
        let mut reg = RhaiModuleRegistry::new();
        reg.register("a", String::new());
        reg.register("b", String::new());
        let list = reg.list_modules();
        assert_eq!(list.len(), 2);
    }

    // ── Script templates ──────────────────────────────────────────────────────

    #[test]
    fn test_template_find_xrefs() {
        let t = RhaiScriptTemplate::find_xrefs(0x1000);
        assert!(t.contains("1000") || t.contains("0x1000"));
    }

    #[test]
    fn test_template_extract_strings() {
        let t = RhaiScriptTemplate::extract_strings();
        assert!(t.contains("strings") || t.contains("find_strings"));
    }

    #[test]
    fn test_template_rename_functions() {
        let t = RhaiScriptTemplate::rename_functions("sub_", "fn_");
        assert!(t.contains("sub_") || t.contains("fn_"));
    }

    #[test]
    fn test_template_entropy_check() {
        let t = RhaiScriptTemplate::entropy_check("/tmp/test.bin");
        assert!(t.contains("entropy") && t.contains("/tmp/test.bin"));
    }

    #[test]
    fn test_template_pattern_search() {
        let t = RhaiScriptTemplate::pattern_search("90 90 90");
        assert!(t.contains("90 90 90"));
    }

    // ── RE utility functions ──────────────────────────────────────────────────

    #[test]
    fn test_hex_encode_impl() {
        assert_eq!(hex_encode_impl(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode_impl(&[]), "");
    }

    #[test]
    fn test_hex_decode_impl() {
        assert_eq!(hex_decode_impl("deadbeef"), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(hex_decode_impl(""), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0x00u8, 0xFF, 0x7F, 0x80, 0x55, 0xAA];
        assert_eq!(hex_decode_impl(&hex_encode_impl(&data)), data);
    }

    #[test]
    fn test_entropy_impl_zero() {
        assert_eq!(entropy_impl(b""), 0.0);
    }

    #[test]
    fn test_entropy_impl_uniform() {
        let data = vec![0xAA_u8; 1024];
        assert!((entropy_impl(&data) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_entropy_impl_max() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let e = entropy_impl(&data);
        assert!((e - 8.0).abs() < 1e-9);
    }

    #[test]
    fn test_entropy_classify() {
        assert!(entropy_classify(0.5).contains("low"));
        assert!(entropy_classify(5.0).contains("medium"));
        assert!(entropy_classify(7.5).contains("high"));
    }

    #[test]
    fn test_find_pattern_impl_basic() {
        let data = vec![0x90u8, 0x90, 0xCC, 0x90, 0x90];
        let hits = find_pattern_impl(&data, "90 90");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].clone().cast::<i64>(), 0);
        assert_eq!(hits[1].clone().cast::<i64>(), 3);
    }

    #[test]
    fn test_find_pattern_impl_wildcard() {
        let data = vec![0x55u8, 0x89, 0xE5];
        let hits = find_pattern_impl(&data, "55 ?? E5");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_pattern_impl_empty_pattern() {
        let data = vec![0x00u8; 10];
        let hits = find_pattern_impl(&data, "");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_xor_bytes_impl() {
        let data = vec![0xAAu8, 0xBB, 0xCC];
        let xored = xor_bytes_impl(&data, 0xFF);
        assert_eq!(xored, vec![0x55, 0x44, 0x33]);
        // Applying twice should restore original
        let restored = xor_bytes_impl(&xored, 0xFF);
        assert_eq!(restored, data);
    }

    #[test]
    fn test_rotate_bytes_impl_rol() {
        let data = vec![0b0000_0001u8];
        let rotated = rotate_bytes_impl(&data, 1, true);
        assert_eq!(rotated, vec![0b0000_0010]);
    }

    #[test]
    fn test_rotate_bytes_impl_ror() {
        let data = vec![0b0000_0010u8];
        let rotated = rotate_bytes_impl(&data, 1, false);
        assert_eq!(rotated, vec![0b0000_0001]);
    }

    #[test]
    fn test_find_strings_in_blob() {
        let data = b"hello\x00world\x00\x01\x02tiny\x00";
        let strings = find_strings_in_blob(data, 4);
        let vals: Vec<String> = strings
            .into_iter()
            .filter_map(rhai::Dynamic::try_cast::<String>)
            .collect();
        assert!(vals.iter().any(|s| s == "hello"));
        assert!(vals.iter().any(|s| s == "world"));
        // "tiny" is 4 chars — should be included
        assert!(vals.iter().any(|s| s == "tiny"));
    }

    #[test]
    fn test_detect_format_elf() {
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 20]);
        assert_eq!(detect_format(&data), "ELF");
    }

    #[test]
    fn test_detect_format_pe() {
        assert_eq!(detect_format(b"MZ"), "PE");
    }

    #[test]
    fn test_detect_format_wasm() {
        assert_eq!(detect_format(b"\0asm\x01\0\0\0"), "WASM");
    }

    #[test]
    fn test_detect_arch_x86_64_elf() {
        let mut data = vec![
            0x7f, b'E', b'L', b'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        // e_machine at bytes 18-19: 0x003e = EM_X86_64
        data.push(0x3e);
        data.push(0x00);
        assert_eq!(detect_arch(&data), "x86_64");
    }

    #[test]
    fn test_detect_arch_wasm() {
        assert_eq!(detect_arch(b"\0asm\x01\0\0\0"), "wasm32");
    }

    // ── RhaiEngine wrapper ────────────────────────────────────────────────────

    #[test]
    fn test_rhai_engine_eval_expr() {
        let e = RhaiEngine::new();
        let d = e.eval_expr("2 + 2").unwrap();
        assert_eq!(d.cast::<i64>(), 4);
    }

    #[test]
    fn test_rhai_engine_register_global_fn() {
        let mut e = RhaiEngine::new();
        e.register_global_fn("triple", |x: i64| x * 3_i64);
        let d = e.eval_expr("triple(7)").unwrap();
        assert_eq!(d.cast::<i64>(), 21);
    }

    // ── eval_with_var ─────────────────────────────────────────────────────────

    #[test]
    fn test_eval_with_var() {
        let engine = RhaiScriptEngine::new();
        let result = engine
            .eval_with_var("x * 2", "x", Dynamic::from(21_i64))
            .unwrap();
        assert_eq!(result, RhaiValue::Int(42));
    }

    #[test]
    fn test_eval_with_vars() {
        let engine = RhaiScriptEngine::new();
        let vars = vec![("a", Dynamic::from(10_i64)), ("b", Dynamic::from(32_i64))];
        let result = engine.eval_with_vars("a + b", vars).unwrap();
        assert_eq!(result, RhaiValue::Int(42));
    }

    // ── XrefKind ──────────────────────────────────────────────────────────────

    #[test]
    fn test_xref_kind_display() {
        assert_eq!(RhaiXrefKind::Call.to_string(), "call");
        assert_eq!(RhaiXrefKind::Jump.to_string(), "jump");
        assert_eq!(RhaiXrefKind::Data.to_string(), "data");
        assert_eq!(RhaiXrefKind::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_xref_kind_from_str() {
        assert_eq!(RhaiXrefKind::from_str("call"), Ok(RhaiXrefKind::Call));
        assert_eq!(RhaiXrefKind::from_str("jump"), Ok(RhaiXrefKind::Jump));
        assert_eq!(RhaiXrefKind::from_str("garbage"), Ok(RhaiXrefKind::Unknown));
    }

    // ── SegmentKind display ───────────────────────────────────────────────────

    #[test]
    fn test_segment_kind_display() {
        assert_eq!(RhaiSegmentKind::Code.to_string(), "code");
        assert_eq!(RhaiSegmentKind::Data.to_string(), "data");
        assert_eq!(RhaiSegmentKind::Bss.to_string(), "bss");
        assert_eq!(RhaiSegmentKind::ReadOnly.to_string(), "rodata");
        assert_eq!(RhaiSegmentKind::Unknown.to_string(), "unknown");
    }

    // ── Instruction display ───────────────────────────────────────────────────

    #[test]
    fn test_instruction_to_string_repr() {
        let insn = RhaiInstruction {
            address: 0x1000,
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
            bytes: vec![0x55],
            size: 1,
        };
        let s = insn.to_string_repr();
        assert!(s.contains("push"));
        assert!(s.contains("rbp"));
    }

    #[test]
    fn test_instruction_no_operands() {
        let insn = RhaiInstruction {
            address: 0x1001,
            mnemonic: "ret".to_string(),
            operands: String::new(),
            bytes: vec![0xC3],
            size: 1,
        };
        let s = insn.to_string_repr();
        assert!(s.contains("ret"));
    }
}

// ── Extended Rhai scripting API ───────────────────────────────────────────────
//
// Additional types, utilities, and test coverage extending the Rhai scripting
// layer for RustRE. These are pure-Rust types compatible with the rhai sync
// feature, requiring no unsafe code.

/// Entropy measurement computed inside a Rhai script.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RhaiEntropy {
    pub address: u64,
    pub length: u64,
    pub value: f64,
}

impl RhaiEntropy {
    /// Construct a new entropy measurement.
    #[must_use]
    pub const fn new(address: u64, length: u64, value: f64) -> Self {
        Self {
            address,
            length,
            value,
        }
    }

    /// True if entropy is in the "encrypted or compressed" range (>= 7.0).
    #[must_use]
    pub fn is_high(&self) -> bool {
        self.value >= 7.0
    }

    /// Classify the entropy level.
    #[must_use]
    pub fn classify(&self) -> &'static str {
        if self.value >= 7.5 {
            "encrypted"
        } else if self.value >= 6.5 {
            "high"
        } else if self.value >= 4.0 {
            "normal"
        } else {
            "low"
        }
    }
}

impl std::fmt::Display for RhaiEntropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Entropy(addr=0x{:x}, len={}, value={:.4}, class={})",
            self.address,
            self.length,
            self.value,
            self.classify()
        )
    }
}

/// Compute Shannon entropy over a byte slice.
#[must_use]
pub fn rhai_compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = lossy_usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = lossy_u64_to_f64(c) / n;
            h = p.mul_add(-p.log2(), h);
        }
    }
    h
}

/// A Rhai-compatible patch record: an address plus replacement bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiPatch {
    pub address: u64,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
    pub comment: String,
}

impl RhaiPatch {
    /// Construct a patch from raw bytes.
    #[must_use]
    pub fn new(
        address: u64,
        original: Vec<u8>,
        replacement: Vec<u8>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            address,
            original,
            replacement,
            comment: comment.into(),
        }
    }

    /// True when the patch changes the byte count.
    #[must_use]
    pub const fn changes_size(&self) -> bool {
        self.original.len() != self.replacement.len()
    }

    /// Summarise the patch.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Patch @ 0x{:x}: {} -> {} bytes (\"{}\")",
            self.address,
            self.original.len(),
            self.replacement.len(),
            self.comment
        )
    }

    /// Parse a hex string like `"90 90 90"` into bytes.
    ///
    /// # Errors
    /// Returns `Err` if any token is not a valid two-digit hex byte.
    pub fn parse_hex(hex: &str) -> std::result::Result<Vec<u8>, ScriptError> {
        hex.split_ascii_whitespace()
            .map(|h| {
                u8::from_str_radix(h, 16)
                    .map_err(|_| ScriptError::HexDecode(format!("invalid hex token: {h}")))
            })
            .collect()
    }
}

/// A collection of `RhaiPatch` records produced by an analysis script.
#[derive(Debug, Default, Clone)]
pub struct RhaiPatchSet {
    patches: Vec<RhaiPatch>,
}

impl RhaiPatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch.
    pub fn add(&mut self, patch: RhaiPatch) {
        self.patches.push(patch);
    }

    /// Number of patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// True when no patches are queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Iterate over patches.
    pub fn iter(&self) -> impl Iterator<Item = &RhaiPatch> {
        self.patches.iter()
    }

    /// Apply all patches to a mutable byte buffer.
    pub fn apply(&self, buf: &mut [u8]) {
        for patch in &self.patches {
            let start = sat_u64_to_usize(patch.address);
            let end = start + patch.replacement.len();
            if end <= buf.len() {
                buf[start..end].copy_from_slice(&patch.replacement);
            }
        }
    }

    /// Return addresses of all patches.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        self.patches.iter().map(|p| p.address).collect()
    }
}

/// A Rhai-compatible vulnerability finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiVulnFinding {
    pub address: u64,
    pub function_name: String,
    pub severity: RhaiSeverity,
    pub cwe_id: u32,
    pub description: String,
}

impl RhaiVulnFinding {
    /// Construct a finding.
    #[must_use]
    pub fn new(
        address: u64,
        function_name: impl Into<String>,
        severity: RhaiSeverity,
        cwe_id: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            address,
            function_name: function_name.into(),
            severity,
            cwe_id,
            description: description.into(),
        }
    }
}

impl std::fmt::Display for RhaiVulnFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] CWE-{} @ 0x{:x} in {}: {}",
            self.severity, self.cwe_id, self.address, self.function_name, self.description
        )
    }
}

/// Severity for Rhai vulnerability findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RhaiSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RhaiSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RhaiSeverity {
    /// Numeric score.
    #[must_use]
    pub const fn score(self) -> u32 {
        match self {
            Self::Low => 3,
            Self::Medium => 5,
            Self::High => 8,
            Self::Critical => 10,
        }
    }

}

impl std::str::FromStr for RhaiSeverity {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" => Self::Medium,
            _ => Self::Low,
        })
    }
}

/// Hex-pattern matcher with `??` wildcard support for Rhai scripts.
#[must_use]
pub fn rhai_match_pattern(data: &[u8], pattern: &str) -> Vec<u64> {
    let tokens: Vec<&str> = pattern.split_ascii_whitespace().collect();
    if tokens.is_empty() {
        return Vec::new();
    }
    let pat: Vec<Option<u8>> = tokens
        .iter()
        .map(|t| {
            if *t == "??" || *t == "?" {
                None
            } else {
                u8::from_str_radix(t, 16).ok()
            }
        })
        .collect();
    let pat_len = pat.len();
    let mut matches = Vec::new();
    if data.len() < pat_len {
        return matches;
    }
    'outer: for i in 0..=(data.len() - pat_len) {
        for (j, opt) in pat.iter().enumerate() {
            if let Some(expected) = opt
                && data[i + j] != *expected
            {
                continue 'outer;
            }
        }
        matches.push(i as u64);
    }
    matches
}

/// Detect binary format from magic bytes.
#[must_use]
pub fn rhai_detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        "ELF"
    } else if data.starts_with(b"MZ") {
        "PE"
    } else if data.starts_with(&[0x00, b'a', b's', b'm']) {
        "WASM"
    } else if data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        "Mach-O"
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP"
    } else {
        "Unknown"
    }
}

/// Script-level annotation store.
#[derive(Debug, Default, Clone)]
pub struct RhaiAnnotations {
    entries: Vec<(u64, String)>,
}

impl RhaiAnnotations {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation.
    pub fn add(&mut self, addr: u64, text: impl Into<String>) {
        self.entries.push((addr, text.into()));
    }

    /// Number of annotations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over (address, text) pairs.
    pub fn iter(&self) -> impl Iterator<Item = &(u64, String)> {
        self.entries.iter()
    }

    /// Format all annotations as a text block for report generation.
    #[must_use]
    pub fn to_report(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for (addr, text) in &self.entries {
            let _ = writeln!(out, "  0x{addr:08x}: {text}");
        }
        out
    }
}

/// A Rhai-side workflow step result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiStepResult {
    pub step_name: String,
    pub success: bool,
    pub output: String,
    pub elapsed_ms: u64,
}

impl RhaiStepResult {
    /// Construct a successful step result.
    #[must_use]
    pub fn ok(step_name: impl Into<String>, output: impl Into<String>, elapsed_ms: u64) -> Self {
        Self {
            step_name: step_name.into(),
            success: true,
            output: output.into(),
            elapsed_ms,
        }
    }

    /// Construct a failed step result.
    #[must_use]
    pub fn fail(step_name: impl Into<String>, error: impl Into<String>, elapsed_ms: u64) -> Self {
        Self {
            step_name: step_name.into(),
            success: false,
            output: error.into(),
            elapsed_ms,
        }
    }
}

impl std::fmt::Display for RhaiStepResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.success { "OK" } else { "FAIL" };
        write!(f, "[{}] {} ({}ms)", status, self.step_name, self.elapsed_ms)
    }
}

// ── Additional tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod rhai_extended_tests {
    use super::*;
    use std::str::FromStr;

    // ── rhai_compute_entropy ──────────────────────────────────────────────────

    #[test]
    fn entropy_all_zeros() {
        assert_eq!(rhai_compute_entropy(&[0u8; 64]), 0.0);
    }

    #[test]
    fn entropy_uniform_8_bits() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = rhai_compute_entropy(&data);
        assert!(
            (e - 8.0).abs() < 1e-9,
            "uniform entropy should be 8.0, got {e}"
        );
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(rhai_compute_entropy(&[]), 0.0);
    }

    // ── RhaiEntropy ───────────────────────────────────────────────────────────

    #[test]
    fn rhai_entropy_classify_encrypted() {
        let e = RhaiEntropy::new(0, 512, 7.8);
        assert!(e.is_high());
        assert_eq!(e.classify(), "encrypted");
    }

    #[test]
    fn rhai_entropy_classify_normal() {
        let e = RhaiEntropy::new(0, 512, 5.0);
        assert!(!e.is_high());
        assert_eq!(e.classify(), "normal");
    }

    #[test]
    fn rhai_entropy_display() {
        let e = RhaiEntropy::new(0x1000, 256, 4.5);
        let s = e.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("4.5000") || s.contains("4.500") || s.contains("normal"));
    }

    // ── RhaiPatch ─────────────────────────────────────────────────────────────

    #[test]
    fn rhai_patch_parse_hex_valid() {
        let bytes = RhaiPatch::parse_hex("90 90 C3").unwrap();
        assert_eq!(bytes, vec![0x90, 0x90, 0xC3]);
    }

    #[test]
    fn rhai_patch_parse_hex_invalid() {
        assert!(RhaiPatch::parse_hex("ZZ").is_err());
    }

    #[test]
    fn rhai_patch_changes_size() {
        let p = RhaiPatch::new(0, vec![0x55], vec![0x90, 0x90], "nop");
        assert!(p.changes_size());
    }

    #[test]
    fn rhai_patch_no_size_change() {
        let p = RhaiPatch::new(0, vec![0x55], vec![0x90], "nop");
        assert!(!p.changes_size());
    }

    #[test]
    fn rhai_patch_summary_contains_addr() {
        let p = RhaiPatch::new(0xDEAD, vec![], vec![0x90], "test");
        assert!(
            p.summary().contains("0xdead")
                || p.summary().contains("DEAD")
                || p.summary().to_lowercase().contains("dead")
        );
    }

    // ── RhaiPatchSet ──────────────────────────────────────────────────────────

    #[test]
    fn patch_set_apply_in_bounds() {
        let mut ps = RhaiPatchSet::new();
        ps.add(RhaiPatch::new(2, vec![], vec![0xAA, 0xBB], "test"));
        let mut buf = vec![0u8; 6];
        ps.apply(&mut buf);
        assert_eq!(&buf[2..4], &[0xAA, 0xBB]);
    }

    #[test]
    fn patch_set_apply_out_of_bounds_no_panic() {
        let mut ps = RhaiPatchSet::new();
        ps.add(RhaiPatch::new(100, vec![], vec![0xFF], "oob"));
        let mut buf = vec![0u8; 4];
        ps.apply(&mut buf); // should not panic
    }

    #[test]
    fn patch_set_addresses() {
        let mut ps = RhaiPatchSet::new();
        ps.add(RhaiPatch::new(0x100, vec![], vec![], "a"));
        ps.add(RhaiPatch::new(0x200, vec![], vec![], "b"));
        assert_eq!(ps.addresses(), vec![0x100, 0x200]);
    }

    #[test]
    fn patch_set_is_empty_and_len() {
        let mut ps = RhaiPatchSet::new();
        assert!(ps.is_empty());
        ps.add(RhaiPatch::new(0, vec![], vec![], ""));
        assert_eq!(ps.len(), 1);
        assert!(!ps.is_empty());
    }

    // ── RhaiSeverity ──────────────────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(RhaiSeverity::Critical > RhaiSeverity::High);
        assert!(RhaiSeverity::High > RhaiSeverity::Medium);
        assert!(RhaiSeverity::Medium > RhaiSeverity::Low);
    }

    #[test]
    fn severity_score() {
        assert_eq!(RhaiSeverity::Critical.score(), 10);
        assert_eq!(RhaiSeverity::High.score(), 8);
        assert_eq!(RhaiSeverity::Medium.score(), 5);
        assert_eq!(RhaiSeverity::Low.score(), 3);
    }

    #[test]
    fn severity_from_str() {
        assert_eq!(RhaiSeverity::from_str("critical"), Ok(RhaiSeverity::Critical));
        assert_eq!(RhaiSeverity::from_str("HIGH"), Ok(RhaiSeverity::High));
        assert_eq!(RhaiSeverity::from_str("medium"), Ok(RhaiSeverity::Medium));
        assert_eq!(RhaiSeverity::from_str("anything_else"), Ok(RhaiSeverity::Low));
    }

    #[test]
    fn severity_display() {
        assert_eq!(RhaiSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(RhaiSeverity::Medium.to_string(), "MEDIUM");
    }

    // ── RhaiVulnFinding ───────────────────────────────────────────────────────

    #[test]
    fn vuln_finding_display() {
        let f = RhaiVulnFinding::new(
            0x1000,
            "parse_input",
            RhaiSeverity::Critical,
            121,
            "Stack BOF",
        );
        let s = f.to_string();
        assert!(s.contains("CWE-121"));
        assert!(s.contains("parse_input"));
        assert!(s.contains("Stack BOF"));
    }

    // ── rhai_match_pattern ────────────────────────────────────────────────────

    #[test]
    fn rhai_match_pattern_exact() {
        let data = vec![0x4D, 0x5A, 0x90];
        let m = rhai_match_pattern(&data, "4D 5A 90");
        assert_eq!(m, vec![0]);
    }

    #[test]
    fn rhai_match_pattern_wildcard() {
        let data = vec![0x4D, 0xAB, 0x90];
        let m = rhai_match_pattern(&data, "4D ?? 90");
        assert_eq!(m, vec![0]);
    }

    #[test]
    fn rhai_match_pattern_no_match() {
        let data = vec![0x00, 0x01];
        let m = rhai_match_pattern(&data, "FF");
        assert!(m.is_empty());
    }

    #[test]
    fn rhai_match_pattern_multiple() {
        let data = vec![0x90, 0x90, 0x90];
        let m = rhai_match_pattern(&data, "90 90");
        assert_eq!(m, vec![0, 1]);
    }

    // ── rhai_detect_format ────────────────────────────────────────────────────

    #[test]
    fn detect_elf() {
        assert_eq!(rhai_detect_format(&[0x7f, b'E', b'L', b'F']), "ELF");
    }

    #[test]
    fn detect_pe() {
        assert_eq!(rhai_detect_format(b"MZ"), "PE");
    }

    #[test]
    fn detect_wasm() {
        assert_eq!(
            rhai_detect_format(&[0x00, b'a', b's', b'm', 1, 0, 0, 0]),
            "WASM"
        );
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(rhai_detect_format(&[0xAA, 0xBB]), "Unknown");
    }

    // ── RhaiAnnotations ───────────────────────────────────────────────────────

    #[test]
    fn annotations_add_and_len() {
        let mut ann = RhaiAnnotations::new();
        assert!(ann.is_empty());
        ann.add(0x1000, "entry point");
        ann.add(0x2000, "crypto routine");
        assert_eq!(ann.len(), 2);
    }

    #[test]
    fn annotations_to_report_contains_addr() {
        let mut ann = RhaiAnnotations::new();
        ann.add(0xDEAD, "note");
        let report = ann.to_report();
        assert!(report.contains("0x0000dead") || report.to_lowercase().contains("dead"));
    }

    #[test]
    fn annotations_iter() {
        let mut ann = RhaiAnnotations::new();
        ann.add(1, "a");
        ann.add(2, "b");
        
        assert_eq!(ann.iter().count(), 2);
    }

    // ── RhaiStepResult ────────────────────────────────────────────────────────

    #[test]
    fn step_result_ok_display() {
        let r = RhaiStepResult::ok("disassemble", "done", 150);
        let s = r.to_string();
        assert!(s.contains("OK"));
        assert!(s.contains("disassemble"));
        assert!(s.contains("150ms"));
    }

    #[test]
    fn step_result_fail_display() {
        let r = RhaiStepResult::fail("decompile", "timeout", 5000);
        let s = r.to_string();
        assert!(s.contains("FAIL"));
        assert!(s.contains("decompile"));
    }

    #[test]
    fn step_result_ok_is_success() {
        let r = RhaiStepResult::ok("s", "o", 0);
        assert!(r.success);
    }

    #[test]
    fn step_result_fail_is_not_success() {
        let r = RhaiStepResult::fail("s", "e", 0);
        assert!(!r.success);
    }
}
