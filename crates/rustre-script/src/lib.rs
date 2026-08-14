//! `rustre-script`
//!
//! Core scripting engine abstraction for the `RustRE` platform.
//! Provides traits and types shared by all scripting engine adapters,
//! including variable binding, function registration, module system,
//! compilation traits, and a high-level execution pipeline.

pub mod host_api;
pub mod repl;
pub mod script_context_full;
pub mod script_manager;
pub mod script_stdlib;
pub mod vm_bindings;
pub mod script_module_system;
pub mod api_bindings;
pub mod headless_runner;
pub mod script_console;
pub mod script_debugger;
pub mod script_runner;
pub mod engine_registry;

pub use script_context_full::{
    EventHooks, FunctionRegistry, FunctionSignature, GlobalScope, ScriptContextFull,
    ScriptEnvironment, TypeInfo, TypeRegistry,
};

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error type ────────────────────────────────────────────────────────────────

/// All errors that can occur inside the script subsystem.
#[derive(Debug, Error, Clone)]
pub enum ScriptError {
    #[error("parse error at line {line}, col {col}: {msg}")]
    ParseError {
        line: usize,
        col: usize,
        msg: String,
    },

    #[error("runtime error: {0}")]
    RuntimeError(String),

    #[error("script execution timed out after {ms}ms")]
    Timeout { ms: u64 },

    #[error("function not found: {0}")]
    FunctionNotFound(String),

    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("undefined variable: {0}")]
    UndefinedVariable(String),

    #[error("arity mismatch: function '{name}' expects {expected} args, got {got}")]
    ArityMismatch {
        name: String,
        expected: usize,
        got: usize,
    },

    #[error("index out of bounds: index {index}, length {length}")]
    IndexOutOfBounds { index: i64, length: usize },

    #[error("IO error: {0}")]
    IoError(String),

    #[error("engine '{name}' not found for extension '.{ext}'")]
    EngineNotFound { name: String, ext: String },

    #[error("division by zero")]
    DivisionByZero,

    #[error("stack overflow")]
    StackOverflow,

    #[error("module not found: {0}")]
    ModuleNotFound(String),

    #[error("module already registered: {0}")]
    ModuleAlreadyRegistered(String),

    #[error("compilation error: {0}")]
    CompilationError(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("custom error: {0}")]
    Custom(String),
}

impl ScriptError {
    /// Return `true` if this error is recoverable (non-fatal).
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::FunctionNotFound(_)
                | Self::UndefinedVariable(_)
                | Self::TypeMismatch { .. }
                | Self::ArityMismatch { .. }
        )
    }

    /// Convenience constructor for a runtime error.
    #[must_use]
    pub fn runtime(msg: impl Into<String>) -> Self {
        Self::RuntimeError(msg.into())
    }

    /// Convenience constructor for a parse error.
    #[must_use]
    pub fn parse(line: usize, col: usize, msg: impl Into<String>) -> Self {
        Self::ParseError {
            line,
            col,
            msg: msg.into(),
        }
    }
}

// ── Value ─────────────────────────────────────────────────────────────────────

/// A dynamically typed value used throughout the scripting layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum ScriptValue {
    #[default]
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Map(HashMap<String, Self>),
    Address(u64),
    /// A named callable (function reference).
    Callable(String),
}

impl ScriptValue {
    /// Return the type name as a static string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Map(_) => "map",
            Self::Address(_) => "address",
            Self::Callable(_) => "callable",
        }
    }

    /// Return `true` if the value is logically truthy.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Float(f) => *f != 0.0,
            Self::String(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Map(m) => !m.is_empty(),
            Self::Address(_) | Self::Callable(_) => true,
        }
    }

    /// Return `true` if the value is `Null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Coerce to `i64`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value cannot be coerced.
    pub fn as_int(&self) -> Result<i64, ScriptError> {
        match self {
            Self::Int(n) => Ok(*n),
            Self::Float(f) => {
                let truncated = f.trunc();
                if truncated >= i64::MIN as f64 && truncated <= i64::MAX as f64 {
                    Ok(truncated as i64)
                } else {
                    Err(ScriptError::TypeMismatch {
                        expected: "int (in range)".into(),
                        got: "float (out of range)".into(),
                    })
                }
            }
            Self::Bool(b) => Ok(i64::from(*b)),
            other => Err(ScriptError::TypeMismatch {
                expected: "int".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to `f64`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value cannot be coerced.
    pub fn as_float(&self) -> Result<f64, ScriptError> {
        match self {
            Self::Float(f) => Ok(*f),
            Self::Int(n) => Ok(*n as f64),
            Self::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
            other => Err(ScriptError::TypeMismatch {
                expected: "float".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner string.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a string.
    pub fn as_str(&self) -> Result<&str, ScriptError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            other => Err(ScriptError::TypeMismatch {
                expected: "string".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner bytes.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not bytes.
    pub fn as_bytes(&self) -> Result<&[u8], ScriptError> {
        match self {
            Self::Bytes(b) => Ok(b.as_slice()),
            other => Err(ScriptError::TypeMismatch {
                expected: "bytes".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to a `bool`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a bool.
    pub fn as_bool(&self) -> Result<bool, ScriptError> {
        match self {
            Self::Bool(b) => Ok(*b),
            other => Err(ScriptError::TypeMismatch {
                expected: "bool".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to a `u64` address.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not an address or int.
    pub fn as_address(&self) -> Result<u64, ScriptError> {
        match self {
            Self::Address(a) => Ok(*a),
            Self::Int(n) => Ok(*n as u64),
            other => Err(ScriptError::TypeMismatch {
                expected: "address".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner list.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a list.
    pub fn as_list(&self) -> Result<&[Self], ScriptError> {
        match self {
            Self::List(l) => Ok(l.as_slice()),
            other => Err(ScriptError::TypeMismatch {
                expected: "list".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner map.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a map.
    pub fn as_map(&self) -> Result<&HashMap<String, Self>, ScriptError> {
        match self {
            Self::Map(m) => Ok(m),
            other => Err(ScriptError::TypeMismatch {
                expected: "map".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Return the length of a list, map, string, or bytes value.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` for non-collection types.
    pub fn len(&self) -> Result<usize, ScriptError> {
        match self {
            Self::List(l) => Ok(l.len()),
            Self::Map(m) => Ok(m.len()),
            Self::String(s) => Ok(s.len()),
            Self::Bytes(b) => Ok(b.len()),
            other => Err(ScriptError::TypeMismatch {
                expected: "collection".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Return `true` if the collection is empty.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` for non-collection types.
    pub fn is_empty(&self) -> Result<bool, ScriptError> {
        self.len().map(|n| n == 0)
    }

    /// Convert to a JSON value for interop.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::Int(n) => serde_json::Value::Number(serde_json::Number::from(*n)),
            Self::Float(f) => serde_json::Number::from_f64(*f)
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
            Self::String(s) => serde_json::Value::String(s.clone()),
            Self::Bytes(b) => {
                serde_json::Value::String(b.iter().fold(String::new(), |mut acc, x| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{x:02x}");
                    acc
                }))
            }
            Self::List(l) => serde_json::Value::Array(l.iter().map(Self::to_json).collect()),
            Self::Map(m) => {
                serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
            }
            Self::Address(a) => serde_json::Value::String(format!("0x{a:x}")),
            Self::Callable(name) => serde_json::Value::String(format!("<callable:{name}>")),
        }
    }

    /// Construct from a JSON value.
    #[must_use]
    pub fn from_json(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(n) => n
                .as_i64()
                .map_or_else(|| n.as_f64().map_or(Self::Null, Self::Float), Self::Int),
            serde_json::Value::String(s) => Self::String(s),
            serde_json::Value::Array(a) => Self::List(a.into_iter().map(Self::from_json).collect()),
            serde_json::Value::Object(o) => Self::Map(
                o.into_iter()
                    .map(|(k, v)| (k, Self::from_json(v)))
                    .collect(),
            ),
        }
    }

    /// Produce a human-readable string.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::Float(f) => f.to_string(),
            Self::String(s) => s.clone(),
            Self::Bytes(b) => format!("bytes({})", b.len()),
            Self::List(l) => {
                let items: Vec<String> = l.iter().map(Self::to_display_string).collect();
                format!("[{}]", items.join(", "))
            }
            Self::Map(m) => {
                let mut items: Vec<String> = m
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_display_string()))
                    .collect();
                items.sort();
                format!("{{{}}}", items.join(", "))
            }
            Self::Address(a) => format!("0x{a:x}"),
            Self::Callable(name) => format!("<fn:{name}>"),
        }
    }
}

impl fmt::Display for ScriptValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_display_string())
    }
}

impl From<i64> for ScriptValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<i32> for ScriptValue {
    fn from(v: i32) -> Self {
        Self::Int(i64::from(v))
    }
}
impl From<u32> for ScriptValue {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}
impl From<f64> for ScriptValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}
impl From<f32> for ScriptValue {
    fn from(v: f32) -> Self {
        Self::Float(f64::from(v))
    }
}
impl From<bool> for ScriptValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<String> for ScriptValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<&str> for ScriptValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}
impl From<Vec<u8>> for ScriptValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<u64> for ScriptValue {
    fn from(v: u64) -> Self {
        Self::Address(v)
    }
}
impl From<Vec<Self>> for ScriptValue {
    fn from(v: Vec<Self>) -> Self {
        Self::List(v)
    }
}
impl From<HashMap<String, Self>> for ScriptValue {
    fn from(v: HashMap<String, Self>) -> Self {
        Self::Map(v)
    }
}

// ── ScriptFn ──────────────────────────────────────────────────────────────────

/// A native function callable from script code.
pub trait ScriptFn: Send + Sync {
    /// Invoke the function with the given arguments.
    ///
    /// # Errors
    /// Returns `ScriptError` on any failure.
    fn call(&self, args: &[ScriptValue]) -> Result<ScriptValue, ScriptError>;

    /// Optional arity hint. `None` means variadic.
    fn arity(&self) -> Option<usize> {
        None
    }

    /// Human-readable name for error messages.
    fn name(&self) -> &'static str {
        "<native>"
    }
}

impl<F> ScriptFn for F
where
    F: Fn(&[ScriptValue]) -> Result<ScriptValue, ScriptError> + Send + Sync,
{
    fn call(&self, args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
        self(args)
    }
}

/// A boxed, reference-counted native function.
pub type NativeFunction = Arc<dyn ScriptFn>;

/// Create a `NativeFunction` from a closure.
pub fn native_fn<F>(f: F) -> NativeFunction
where
    F: Fn(&[ScriptValue]) -> Result<ScriptValue, ScriptError> + Send + Sync + 'static,
{
    Arc::new(f)
}

// ── ScriptContext ─────────────────────────────────────────────────────────────

/// Execution context passed to a script engine for one script run.
#[derive(Default, Clone)]
pub struct ScriptContext {
    /// Script-visible global variables.
    pub globals: HashMap<String, ScriptValue>,
    /// Captured stdout lines.
    pub output: Vec<String>,
    /// Captured stderr lines.
    pub error_output: Vec<String>,
    /// Optional execution timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Named native functions injected into the script environment.
    pub native_fns: HashMap<String, NativeFunction>,
    /// Script metadata / user data bag.
    pub metadata: HashMap<String, String>,
}

impl fmt::Debug for ScriptContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptContext")
            .field("globals", &self.globals.keys().collect::<Vec<_>>())
            .field("output_lines", &self.output.len())
            .field("timeout_ms", &self.timeout_ms)
            .field("native_fns", &self.native_fns.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ScriptContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context with a timeout.
    #[must_use]
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        }
    }

    /// Seed globals from a map.
    #[must_use]
    pub fn with_globals(mut self, globals: HashMap<String, ScriptValue>) -> Self {
        self.globals = globals;
        self
    }

    /// Set a global variable.
    pub fn set_global(&mut self, name: impl Into<String>, value: ScriptValue) {
        self.globals.insert(name.into(), value);
    }

    /// Get a global variable.
    #[must_use]
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.globals.get(name)
    }

    /// Remove a global variable, returning its old value if present.
    pub fn remove_global(&mut self, name: &str) -> Option<ScriptValue> {
        self.globals.remove(name)
    }

    /// Register a native function.
    pub fn register_fn(&mut self, name: impl Into<String>, f: NativeFunction) {
        self.native_fns.insert(name.into(), f);
    }

    /// Look up a native function.
    #[must_use]
    pub fn get_fn(&self, name: &str) -> Option<&NativeFunction> {
        self.native_fns.get(name)
    }

    /// Append a line to stdout.
    pub fn write_output(&mut self, line: impl Into<String>) {
        self.output.push(line.into());
    }

    /// Append a line to stderr.
    pub fn write_error(&mut self, line: impl Into<String>) {
        self.error_output.push(line.into());
    }

    /// Set a metadata key.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Return all global variable names.
    #[must_use]
    pub fn global_names(&self) -> Vec<&str> {
        self.globals.keys().map(String::as_str).collect()
    }
}

// ── ScriptResult ──────────────────────────────────────────────────────────────

/// The result of executing a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// The return value of the script.
    pub value: ScriptValue,
    /// Lines written to stdout.
    pub stdout: Vec<String>,
    /// Lines written to stderr.
    pub stderr: Vec<String>,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Whether the execution was successful.
    pub success: bool,
}

impl ScriptResult {
    /// Construct a result from a value and the context that produced it.
    #[must_use]
    pub fn new(value: ScriptValue, ctx: &ScriptContext) -> Self {
        Self {
            value,
            stdout: ctx.output.clone(),
            stderr: ctx.error_output.clone(),
            elapsed_ms: 0,
            success: true,
        }
    }

    /// Construct a successful result with elapsed time.
    #[must_use]
    pub const fn with_elapsed(mut self, elapsed_ms: u64) -> Self {
        self.elapsed_ms = elapsed_ms;
        self
    }

    /// Construct an error result.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            value: ScriptValue::Null,
            stdout: Vec::new(),
            stderr: vec![error.into()],
            elapsed_ms: 0,
            success: false,
        }
    }

    /// Return all stdout lines joined by newlines.
    #[must_use]
    pub fn stdout_joined(&self) -> String {
        self.stdout.join("\n")
    }

    /// Return all stderr lines joined by newlines.
    #[must_use]
    pub fn stderr_joined(&self) -> String {
        self.stderr.join("\n")
    }

    /// Return `true` if the script produced any output to stderr.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.stderr.is_empty()
    }
}

// ── ScriptModule ──────────────────────────────────────────────────────────────

/// A named module that groups functions and constants for use in scripts.
#[derive(Default)]
pub struct ScriptModule {
    /// Module name (used for import resolution).
    pub name: String,
    /// Exported functions.
    pub functions: HashMap<String, NativeFunction>,
    /// Exported constants.
    pub constants: HashMap<String, ScriptValue>,
}

impl fmt::Debug for ScriptModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptModule")
            .field("name", &self.name)
            .field("functions", &self.functions.keys().collect::<Vec<_>>())
            .field("constants", &self.constants.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ScriptModule {
    /// Create a new, empty module with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            functions: HashMap::new(),
            constants: HashMap::new(),
        }
    }

    /// Register a function in this module.
    pub fn add_fn(&mut self, name: impl Into<String>, f: NativeFunction) {
        self.functions.insert(name.into(), f);
    }

    /// Register a constant in this module.
    pub fn add_const(&mut self, name: impl Into<String>, value: ScriptValue) {
        self.constants.insert(name.into(), value);
    }

    /// Look up a function.
    #[must_use]
    pub fn get_fn(&self, name: &str) -> Option<&NativeFunction> {
        self.functions.get(name)
    }

    /// Look up a constant.
    #[must_use]
    pub fn get_const(&self, name: &str) -> Option<&ScriptValue> {
        self.constants.get(name)
    }

    /// Return the number of exported symbols.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.functions.len() + self.constants.len()
    }
}

// ── NativeFnWrapper ───────────────────────────────────────────────────────────

/// Wraps an `Arc<dyn ScriptFn>` into a `Box<dyn ScriptFn>` for registration.
struct NativeFnWrapper(NativeFunction);

impl ScriptFn for NativeFnWrapper {
    fn call(&self, args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
        self.0.call(args)
    }
}

// ── ScriptEngine trait ────────────────────────────────────────────────────────

/// Trait implemented by every scripting engine adapter.
#[async_trait]
pub trait ScriptEngine: Send + Sync {
    /// Short, unique name for this engine (e.g. `"rhai"`, `"python"`, `"lua"`).
    fn name(&self) -> &str;

    /// File extensions this engine handles (e.g. `&["rhai"]`).
    fn file_extensions(&self) -> &[&str];

    /// Execute `code` with the given context, returning the final value.
    ///
    /// # Errors
    /// Returns `ScriptError` on parse, runtime, or timeout failure.
    async fn execute(
        &self,
        code: &str,
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptError>;

    /// Execute the script at `path`.
    ///
    /// # Errors
    /// Returns `ScriptError` on I/O or execution failure.
    async fn execute_file(
        &self,
        path: &Path,
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptError>;

    /// Call a named function defined in the engine's state.
    ///
    /// # Errors
    /// Returns `ScriptError` if the function is not found or fails.
    fn call_function(
        &self,
        name: &str,
        args: &[ScriptValue],
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptError>;

    /// Register a native function into the engine.
    ///
    /// # Errors
    /// Returns `ScriptError` on registration failure.
    fn register_function(&mut self, name: &str, f: Box<dyn ScriptFn>) -> Result<(), ScriptError>;

    /// Set a global variable in the engine.
    ///
    /// # Errors
    /// Returns `ScriptError` on failure.
    fn set_global(&mut self, name: &str, value: ScriptValue) -> Result<(), ScriptError>;

    /// Get a global variable from the engine.
    fn get_global(&self, name: &str) -> Option<ScriptValue>;

    /// Load a module into the engine.
    ///
    /// # Errors
    /// Returns `ScriptError` if the module cannot be loaded.
    fn load_module(&mut self, module: ScriptModule) -> Result<(), ScriptError> {
        for (name, f) in module.functions {
            self.register_function(&name, Box::new(NativeFnWrapper(f)))?;
        }
        for (name, val) in module.constants {
            self.set_global(&name, val)?;
        }
        Ok(())
    }

    /// Compile `code` without executing it, returning a compilation unit.
    ///
    /// # Errors
    /// Returns `ScriptError::CompilationError` on failure.
    fn compile(&self, code: &str) -> Result<CompiledScript, ScriptError> {
        // Default: check for empty code only.
        if code.trim().is_empty() {
            return Ok(CompiledScript::empty(self.name()));
        }
        Ok(CompiledScript::new(self.name(), code))
    }
}

// ── CompiledScript ────────────────────────────────────────────────────────────

/// An opaque compiled script unit returned by `ScriptEngine::compile`.
#[derive(Debug, Clone)]
pub struct CompiledScript {
    /// The engine that produced this unit.
    pub engine_name: String,
    /// The original source (may be empty for pre-compiled blobs).
    pub source: String,
    /// Whether the compilation produced any warnings.
    pub warnings: Vec<String>,
}

impl CompiledScript {
    /// Construct from source.
    #[must_use]
    pub fn new(engine_name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            engine_name: engine_name.into(),
            source: source.into(),
            warnings: Vec::new(),
        }
    }

    /// Construct an empty (no-op) compiled unit.
    #[must_use]
    pub fn empty(engine_name: impl Into<String>) -> Self {
        Self::new(engine_name, "")
    }

    /// Add a compilation warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Return `true` if this unit has no source.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source.trim().is_empty()
    }
}

// ── ScriptEngineRegistry ──────────────────────────────────────────────────────

/// Thread-safe registry of script engines, keyed by name and extension.
pub struct ScriptEngineRegistry {
    engines: RwLock<Vec<Arc<dyn ScriptEngine>>>,
}

impl fmt::Debug for ScriptEngineRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScriptEngineRegistry {{ engines: {} }}",
            self.engines.read().len()
        )
    }
}

impl ScriptEngineRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engines: RwLock::new(Vec::new()),
        }
    }

    /// Register an engine.
    pub fn register(&self, engine: Arc<dyn ScriptEngine>) {
        self.engines.write().push(engine);
    }

    /// Find an engine by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<Arc<dyn ScriptEngine>> {
        self.engines
            .read()
            .iter()
            .find(|e| e.name() == name)
            .cloned()
    }

    /// Find an engine by file extension.
    #[must_use]
    pub fn find_by_extension(&self, ext: &str) -> Option<Arc<dyn ScriptEngine>> {
        self.engines
            .read()
            .iter()
            .find(|e| e.file_extensions().contains(&ext))
            .cloned()
    }

    /// Return names of all registered engines.
    #[must_use]
    pub fn list_engines(&self) -> Vec<String> {
        self.engines
            .read()
            .iter()
            .map(|e| e.name().to_owned())
            .collect()
    }

    /// Return the total number of registered engines.
    #[must_use]
    pub fn count(&self) -> usize {
        self.engines.read().len()
    }

    /// Remove an engine by name, returning `true` if it was present.
    pub fn remove(&self, name: &str) -> bool {
        let mut guard = self.engines.write();
        let before = guard.len();
        guard.retain(|e| e.name() != name);
        guard.len() < before
    }
}

impl Default for ScriptEngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── ScriptPipeline ────────────────────────────────────────────────────────────

/// A sequential pipeline that runs multiple scripts in order, threading the
/// result of each step as a global `_prev` into the next.
pub struct ScriptPipeline {
    steps: Vec<PipelineStep>,
}

/// A single step in a `ScriptPipeline`.
pub struct PipelineStep {
    /// Source code for this step.
    pub code: String,
    /// Engine name to use.
    pub engine_name: String,
    /// Optional step label.
    pub label: Option<String>,
}

impl PipelineStep {
    /// Construct a pipeline step.
    #[must_use]
    pub fn new(engine_name: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            engine_name: engine_name.into(),
            label: None,
        }
    }

    /// Attach a label to this step.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

impl ScriptPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub const fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Append a step.
    pub fn push(&mut self, step: PipelineStep) {
        self.steps.push(step);
    }

    /// Return the number of steps.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// Return `true` if there are no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Execute all steps in order against the given registry.
    ///
    /// # Errors
    /// Returns the error from the first failing step.
    pub async fn execute_all(
        &self,
        registry: &ScriptEngineRegistry,
        initial_ctx: &mut ScriptContext,
    ) -> Result<Vec<ScriptResult>, ScriptError> {
        let mut results = Vec::with_capacity(self.steps.len());
        let mut prev_value = ScriptValue::Null;

        for step in &self.steps {
            let engine = registry.find_by_name(&step.engine_name).ok_or_else(|| {
                ScriptError::EngineNotFound {
                    name: step.engine_name.clone(),
                    ext: String::new(),
                }
            })?;

            initial_ctx.set_global("_prev", prev_value.clone());
            let t0 = std::time::Instant::now();
            let value = engine.execute(&step.code, initial_ctx).await?;
            let elapsed = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);

            let result = ScriptResult::new(value.clone(), initial_ctx).with_elapsed(elapsed);
            results.push(result);
            prev_value = value;
        }

        Ok(results)
    }
}

impl Default for ScriptPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ── Sandbox config ────────────────────────────────────────────────────────────

/// Controls what the script is allowed to do.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Allow file system reads.
    pub allow_fs_read: bool,
    /// Allow file system writes.
    pub allow_fs_write: bool,
    /// Allow network access.
    pub allow_network: bool,
    /// Allow spawning subprocesses.
    pub allow_subprocess: bool,
    /// Maximum heap memory in bytes (0 = unlimited).
    pub max_heap_bytes: u64,
    /// Maximum execution time in milliseconds (0 = unlimited).
    pub max_time_ms: u64,
    /// Maximum call stack depth (0 = unlimited).
    pub max_call_depth: u32,
}

impl SandboxPolicy {
    /// A policy that allows nothing.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// A policy that allows everything.
    #[must_use]
    pub const fn allow_all() -> Self {
        Self {
            allow_fs_read: true,
            allow_fs_write: true,
            allow_network: true,
            allow_subprocess: true,
            max_heap_bytes: 0,
            max_time_ms: 0,
            max_call_depth: 0,
        }
    }

    /// A read-only policy with sensible defaults.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            allow_fs_read: true,
            max_time_ms: 5_000,
            max_call_depth: 256,
            ..Default::default()
        }
    }
}

// ── Built-in function helpers ─────────────────────────────────────────────────

/// Convert a hex string to bytes. Accepts "0x" prefix or plain hex.
///
/// # Errors
/// Returns `ScriptError` if the input is not a valid hex string.
pub fn builtin_hex_to_bytes(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let s = args
        .first()
        .ok_or_else(|| ScriptError::ArityMismatch {
            name: "hex_to_bytes".into(),
            expected: 1,
            got: 0,
        })?
        .as_str()?;
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 {
        return Err(ScriptError::RuntimeError(
            "hex_to_bytes: odd-length hex string".into(),
        ));
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| ScriptError::RuntimeError(format!("invalid hex byte: {e}")))
        })
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(ScriptValue::Bytes(bytes))
}

/// Convert bytes to a lowercase hex string.
///
/// # Errors
/// Returns `ScriptError` if the argument is not bytes.
pub fn builtin_bytes_to_hex(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let b = args
        .first()
        .ok_or_else(|| ScriptError::ArityMismatch {
            name: "bytes_to_hex".into(),
            expected: 1,
            got: 0,
        })?
        .as_bytes()?;
    Ok(ScriptValue::String(b.iter().fold(
        String::new(),
        |mut acc, x| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{x:02x}");
            acc
        },
    )))
}

fn require_bytes_and_offset(
    fn_name: &str,
    args: &[ScriptValue],
    size: usize,
) -> Result<(Vec<u8>, usize), ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: fn_name.into(),
            expected: 2,
            got: args.len(),
        });
    }
    let bytes = args[0].as_bytes()?.to_vec();
    let off_i = args[1].as_int()?;
    let off = usize::try_from(off_i).map_err(|_| ScriptError::IndexOutOfBounds {
        index: off_i,
        length: bytes.len(),
    })?;
    if off + size > bytes.len() {
        let off_back = i64::try_from(off).unwrap_or(i64::MAX);
        return Err(ScriptError::IndexOutOfBounds {
            index: off_back,
            length: bytes.len(),
        });
    }
    Ok((bytes, off))
}

/// Read a `u8` from a bytes buffer at the given offset.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_read_u8(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let (bytes, off) = require_bytes_and_offset("read_u8", args, 1)?;
    Ok(ScriptValue::Int(i64::from(bytes[off])))
}

/// Read a little-endian `u16` from a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_read_u16(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let (bytes, off) = require_bytes_and_offset("read_u16", args, 2)?;
    let v = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
    Ok(ScriptValue::Int(i64::from(v)))
}

/// Read a little-endian `u32` from a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_read_u32(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let (bytes, off) = require_bytes_and_offset("read_u32", args, 4)?;
    let v = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    Ok(ScriptValue::Int(i64::from(v)))
}

/// Read a little-endian `u64` from a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
///
/// # Panics
/// Panics if internal invariants are violated.
pub fn builtin_read_u64(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let (bytes, off) = require_bytes_and_offset("read_u64", args, 8)?;
    let arr: [u8; 8] = bytes[off..off + 8].try_into().unwrap();
    let v = u64::from_le_bytes(arr);
    Ok(ScriptValue::Address(v))
}

/// Read a big-endian `u32` from a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_read_u32_be(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let (bytes, off) = require_bytes_and_offset("read_u32_be", args, 4)?;
    let v = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    Ok(ScriptValue::Int(i64::from(v)))
}

fn write_bytes(
    fn_name: &str,
    args: &[ScriptValue],
    size: usize,
    val_bytes: &[u8],
) -> Result<ScriptValue, ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: fn_name.into(),
            expected: 2,
            got: args.len(),
        });
    }
    let mut bytes = args[0].as_bytes()?.to_vec();
    let off_i = args[1].as_int()?;
    let off = usize::try_from(off_i).map_err(|_| ScriptError::IndexOutOfBounds {
        index: off_i,
        length: bytes.len(),
    })?;
    if off + size > bytes.len() {
        let off_back = i64::try_from(off).unwrap_or(i64::MAX);
        return Err(ScriptError::IndexOutOfBounds {
            index: off_back,
            length: bytes.len(),
        });
    }
    bytes[off..off + size].copy_from_slice(val_bytes);
    Ok(ScriptValue::Bytes(bytes))
}

/// Write a `u8` into a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_write_u8(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 3 {
        return Err(ScriptError::ArityMismatch {
            name: "write_u8".into(),
            expected: 3,
            got: args.len(),
        });
    }
    let v = u8::try_from(args[2].as_int()? & 0xFF).unwrap_or(0);
    write_bytes("write_u8", args, 1, &[v])
}

/// Write a little-endian `u16` into a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_write_u16(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 3 {
        return Err(ScriptError::ArityMismatch {
            name: "write_u16".into(),
            expected: 3,
            got: args.len(),
        });
    }
    let v = u16::try_from(args[2].as_int()? & 0xFFFF).unwrap_or(0);
    write_bytes("write_u16", args, 2, &v.to_le_bytes())
}

/// Write a little-endian `u32` into a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_write_u32(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 3 {
        return Err(ScriptError::ArityMismatch {
            name: "write_u32".into(),
            expected: 3,
            got: args.len(),
        });
    }
    let v = u32::try_from(args[2].as_int()? & 0xFFFF_FFFF).unwrap_or(0);
    write_bytes("write_u32", args, 4, &v.to_le_bytes())
}

/// Write a little-endian `u64` into a bytes buffer.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds access.
pub fn builtin_write_u64(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 3 {
        return Err(ScriptError::ArityMismatch {
            name: "write_u64".into(),
            expected: 3,
            got: args.len(),
        });
    }
    let v_i = args[2].as_int()?;
    let v = u64::from_ne_bytes(v_i.to_ne_bytes());
    write_bytes("write_u64", args, 8, &v.to_le_bytes())
}

/// XOR two byte arrays; the key is cycled.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or missing arguments.
pub fn builtin_xor_bytes(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: "xor_bytes".into(),
            expected: 2,
            got: args.len(),
        });
    }
    let a = args[0].as_bytes()?.to_vec();
    let b = args[1].as_bytes()?.to_vec();
    if b.is_empty() {
        return Err(ScriptError::RuntimeError(
            "xor_bytes: key must not be empty".into(),
        ));
    }
    let result: Vec<u8> = a.iter().zip(b.iter().cycle()).map(|(x, y)| x ^ y).collect();
    Ok(ScriptValue::Bytes(result))
}

/// Convert any value to a string.
///
/// # Errors
/// Returns `ScriptError` if no argument is provided.
pub fn builtin_to_string(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let v = args.first().ok_or_else(|| ScriptError::ArityMismatch {
        name: "to_string".into(),
        expected: 1,
        got: 0,
    })?;
    Ok(ScriptValue::String(v.to_display_string()))
}

/// Return the length of a collection.
///
/// # Errors
/// Returns `ScriptError` if the argument is not a collection.
pub fn builtin_len(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let v = args.first().ok_or_else(|| ScriptError::ArityMismatch {
        name: "len".into(),
        expected: 1,
        got: 0,
    })?;
    Ok(ScriptValue::Int(
        i64::try_from(v.len()?).unwrap_or(i64::MAX),
    ))
}

/// Return the type name of a value.
///
/// # Errors
/// Returns `ScriptError` if no argument is provided.
pub fn builtin_typeof(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    let v = args.first().ok_or_else(|| ScriptError::ArityMismatch {
        name: "typeof".into(),
        expected: 1,
        got: 0,
    })?;
    Ok(ScriptValue::String(v.type_name().into()))
}

/// Concatenate two byte arrays.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or missing arguments.
pub fn builtin_bytes_concat(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: "bytes_concat".into(),
            expected: 2,
            got: args.len(),
        });
    }
    let mut a = args[0].as_bytes()?.to_vec();
    let b = args[1].as_bytes()?;
    a.extend_from_slice(b);
    Ok(ScriptValue::Bytes(a))
}

/// Slice a byte array: `bytes_slice(bytes, start, end)`.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or out-of-bounds.
pub fn builtin_bytes_slice(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 3 {
        return Err(ScriptError::ArityMismatch {
            name: "bytes_slice".into(),
            expected: 3,
            got: args.len(),
        });
    }
    let bytes = args[0].as_bytes()?.to_vec();
    let start_i = args[1].as_int()?;
    let end_i = args[2].as_int()?;
    let start = usize::try_from(start_i).map_err(|_| ScriptError::IndexOutOfBounds {
        index: start_i,
        length: bytes.len(),
    })?;
    let end = usize::try_from(end_i).map_err(|_| ScriptError::IndexOutOfBounds {
        index: end_i,
        length: bytes.len(),
    })?;
    if end > bytes.len() || start > end {
        return Err(ScriptError::IndexOutOfBounds {
            index: end_i,
            length: bytes.len(),
        });
    }
    Ok(ScriptValue::Bytes(bytes[start..end].to_vec()))
}

/// Return a bytes value filled with a repeated byte.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or missing arguments.
pub fn builtin_bytes_fill(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: "bytes_fill".into(),
            expected: 2,
            got: args.len(),
        });
    }
    let count_i = args[0].as_int()?;
    let count = usize::try_from(count_i).map_err(|_| ScriptError::TypeMismatch {
        expected: "non-negative int".into(),
        got: "negative int".into(),
    })?;
    // Guard against allocating enormous buffers from untrusted input.
    const MAX_FILL_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
    if count > MAX_FILL_BYTES {
        return Err(ScriptError::RuntimeError(format!(
            "bytes_fill: requested size {count} exceeds maximum {MAX_FILL_BYTES}"
        )));
    }
    let byte = u8::try_from(args[1].as_int()? & 0xFF).unwrap_or(0);
    Ok(ScriptValue::Bytes(vec![byte; count]))
}

/// Search for a byte pattern in a buffer, returning the offset or null.
///
/// # Errors
/// Returns `ScriptError` on type mismatch or missing arguments.
pub fn builtin_bytes_find(args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
    if args.len() < 2 {
        return Err(ScriptError::ArityMismatch {
            name: "bytes_find".into(),
            expected: 2,
            got: args.len(),
        });
    }
    let haystack = args[0].as_bytes()?;
    let needle = args[1].as_bytes()?;
    if needle.is_empty() {
        return Ok(ScriptValue::Int(0));
    }
    if needle.len() > haystack.len() {
        return Ok(ScriptValue::Null);
    }
    for i in 0..=haystack.len() - needle.len() {
        if haystack[i..i + needle.len()] == *needle {
            return Ok(ScriptValue::Int(i64::try_from(i).unwrap_or(i64::MAX)));
        }
    }
    Ok(ScriptValue::Null)
}

/// Return a map of all built-in functions as boxed `ScriptFn` trait objects.
#[must_use]
pub fn builtin_functions() -> HashMap<String, Box<dyn ScriptFn>> {
    let mut map: HashMap<String, Box<dyn ScriptFn>> = HashMap::new();
    map.insert("hex_to_bytes".into(), Box::new(builtin_hex_to_bytes));
    map.insert("bytes_to_hex".into(), Box::new(builtin_bytes_to_hex));
    map.insert("read_u8".into(), Box::new(builtin_read_u8));
    map.insert("read_u16".into(), Box::new(builtin_read_u16));
    map.insert("read_u32".into(), Box::new(builtin_read_u32));
    map.insert("read_u32_be".into(), Box::new(builtin_read_u32_be));
    map.insert("read_u64".into(), Box::new(builtin_read_u64));
    map.insert("write_u8".into(), Box::new(builtin_write_u8));
    map.insert("write_u16".into(), Box::new(builtin_write_u16));
    map.insert("write_u32".into(), Box::new(builtin_write_u32));
    map.insert("write_u64".into(), Box::new(builtin_write_u64));
    map.insert("xor_bytes".into(), Box::new(builtin_xor_bytes));
    map.insert("to_string".into(), Box::new(builtin_to_string));
    map.insert("len".into(), Box::new(builtin_len));
    map.insert("typeof".into(), Box::new(builtin_typeof));
    map.insert("bytes_concat".into(), Box::new(builtin_bytes_concat));
    map.insert("bytes_slice".into(), Box::new(builtin_bytes_slice));
    map.insert("bytes_fill".into(), Box::new(builtin_bytes_fill));
    map.insert("bytes_find".into(), Box::new(builtin_bytes_find));
    map
}

/// Register all built-in functions into a context.
pub fn register_builtins(ctx: &mut ScriptContext) {
    for (name, f) in builtin_functions() {
        let f = Arc::from(f);
        ctx.register_fn(name, f);
    }
}

// ── RE module ─────────────────────────────────────────────────────────────────

/// Build the standard RE module with binary analysis helpers.
#[must_use]
pub fn re_module() -> ScriptModule {
    let mut m = ScriptModule::new("re");

    m.add_fn("hex_to_bytes", native_fn(builtin_hex_to_bytes));
    m.add_fn("bytes_to_hex", native_fn(builtin_bytes_to_hex));
    m.add_fn("read_u8", native_fn(builtin_read_u8));
    m.add_fn("read_u16", native_fn(builtin_read_u16));
    m.add_fn("read_u32", native_fn(builtin_read_u32));
    m.add_fn("read_u32_be", native_fn(builtin_read_u32_be));
    m.add_fn("read_u64", native_fn(builtin_read_u64));
    m.add_fn("write_u8", native_fn(builtin_write_u8));
    m.add_fn("write_u16", native_fn(builtin_write_u16));
    m.add_fn("write_u32", native_fn(builtin_write_u32));
    m.add_fn("write_u64", native_fn(builtin_write_u64));
    m.add_fn("xor_bytes", native_fn(builtin_xor_bytes));
    m.add_fn("to_string", native_fn(builtin_to_string));
    m.add_fn("len", native_fn(builtin_len));
    m.add_fn("typeof", native_fn(builtin_typeof));
    m.add_fn("bytes_concat", native_fn(builtin_bytes_concat));
    m.add_fn("bytes_slice", native_fn(builtin_bytes_slice));
    m.add_fn("bytes_fill", native_fn(builtin_bytes_fill));
    m.add_fn("bytes_find", native_fn(builtin_bytes_find));

    // Common constants
    m.add_const("NULL", ScriptValue::Null);
    m.add_const("TRUE", ScriptValue::Bool(true));
    m.add_const("FALSE", ScriptValue::Bool(false));

    m
}

// ── Variable binding utilities ────────────────────────────────────────────────

/// A scoped variable frame for emulating lexical scope in interpreters.
#[derive(Debug, Default, Clone)]
pub struct VariableFrame {
    locals: HashMap<String, ScriptValue>,
    parent: Option<Box<Self>>,
}

impl VariableFrame {
    /// Create a root frame.
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Create a child frame inheriting from `parent`.
    #[must_use]
    pub fn child(parent: Self) -> Self {
        Self {
            locals: HashMap::new(),
            parent: Some(Box::new(parent)),
        }
    }

    /// Bind a variable in the current frame.
    pub fn bind(&mut self, name: impl Into<String>, value: ScriptValue) {
        self.locals.insert(name.into(), value);
    }

    /// Look up a variable, walking the frame chain.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&ScriptValue> {
        if let Some(v) = self.locals.get(name) {
            return Some(v);
        }
        self.parent.as_ref().and_then(|p| p.lookup(name))
    }

    /// Assign to an existing binding (walks chain), returning `true` on success.
    pub fn assign(&mut self, name: &str, value: ScriptValue) -> bool {
        if self.locals.contains_key(name) {
            self.locals.insert(name.to_owned(), value);
            return true;
        }
        if let Some(ref mut parent) = self.parent {
            return parent.assign(name, value);
        }
        false
    }

    /// Number of variables in the current (non-parent) frame.
    #[must_use]
    pub fn local_count(&self) -> usize {
        self.locals.len()
    }
}

// ── §33.4 Unified Scripting Host ──────────────────────────────────────────────

use std::path::PathBuf;

/// Alias used by the §33.4 spec for option-style accessors that don't propagate
/// `ScriptError` (return `Option` instead of `Result`).
impl ScriptValue {
    /// Return `Some(&str)` if this is a `String` variant, otherwise `None`.
    #[must_use]
    pub const fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return `Some(i64)` if this value can be coerced to an integer, otherwise `None`.
    #[must_use]
    pub fn as_int_opt(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Float(f) => {
                let truncated = f.trunc();
                if truncated.is_nan()
                    || truncated.is_infinite()
                    || truncated < i64::MIN as f64
                    || truncated > i64::MAX as f64
                {
                    None
                } else {
                    Some(truncated as i64)
                }
            }
            Self::Bool(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Return `Some(bool)` if this is a `Bool` variant, otherwise `None`.
    #[must_use]
    pub const fn as_bool_opt(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

// ── ScriptingBackend trait ────────────────────────────────────────────────────

/// A unified backend trait that every scripting-language adapter must implement.
///
/// The three methods required by spec §33.4 are `eval`, `exec`, and `call`.
/// `load_file` and `register_fn` complete the surface area.
pub trait ScriptingBackend: Send {
    /// Short identifier for this backend, e.g. `"rhai"`, `"lua"`, `"python"`.
    fn name(&self) -> &str;

    /// Evaluate `code` and return its result as a `ScriptValue`.
    ///
    /// # Errors
    /// Returns `ScriptError` on any parse or runtime failure.
    fn eval(&mut self, code: &str) -> Result<ScriptValue, ScriptError>;

    /// Execute `code` for its side-effects, discarding any return value.
    ///
    /// # Errors
    /// Returns `ScriptError` on any parse or runtime failure.
    fn exec(&mut self, code: &str) -> Result<(), ScriptError>;

    /// Call a named function that is already defined in the backend's state,
    /// passing `args` and returning the function's return value.
    ///
    /// # Errors
    /// Returns `ScriptError` when the function is not found or fails.
    fn call(&mut self, func: &str, args: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError>;

    /// Load and execute the script at `path`, registering any definitions it
    /// contains into this backend's state.
    ///
    /// # Errors
    /// Returns `ScriptError` on I/O or execution failure.
    fn load_file(&mut self, path: &Path) -> Result<(), ScriptError>;

    /// Register a host-side native function so that scripts can call it by `name`.
    fn register_fn(
        &mut self,
        name: &str,
        f: Box<dyn Fn(Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> + Send + Sync>,
    );
}

// ── ScriptHost ────────────────────────────────────────────────────────────────

/// Unified scripting host that manages multiple language backends and routes
/// execution to whichever one is currently active.
pub struct ScriptHost {
    /// All registered backends, keyed by their `name()`.
    backends: HashMap<String, Box<dyn ScriptingBackend>>,
    /// The name of the currently active backend, if any.
    active: Option<String>,
}

impl fmt::Debug for ScriptHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptHost")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl ScriptHost {
    /// Create an empty host with no backends registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            active: None,
        }
    }

    /// Register a backend.  If no other backend is active yet, this one
    /// automatically becomes active.
    pub fn add_backend(&mut self, backend: Box<dyn ScriptingBackend>) {
        let name = backend.name().to_owned();
        if self.active.is_none() {
            self.active = Some(name.clone());
        }
        self.backends.insert(name, backend);
    }

    /// Switch the active backend to `name`.
    ///
    /// # Errors
    /// Returns an error if no backend with that name has been registered.
    pub fn set_active(&mut self, name: &str) -> anyhow::Result<()> {
        if self.backends.contains_key(name) {
            self.active = Some(name.to_owned());
            Ok(())
        } else {
            anyhow::bail!("no backend registered with name '{name}'")
        }
    }

    /// Return a mutable reference to the active backend.
    ///
    /// # Errors
    /// Returns an error if no backend is active or the active one is missing.
    pub fn active_backend(&mut self) -> anyhow::Result<&mut dyn ScriptingBackend> {
        let name = self
            .active
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no active backend"))?
            .to_owned();
        match self.backends.get_mut(&name) {
            Some(b) => Ok(&mut **b),
            None => anyhow::bail!("active backend '{name}' not found"),
        }
    }

    /// Execute the file at `path`, auto-detecting the backend from its extension:
    /// `.rh` → `"rhai"`, `.lua` → `"lua"`, `.py` → `"python"`.
    ///
    /// The chosen backend must already be registered.
    ///
    /// # Errors
    /// Returns an error when the extension is not recognised, the backend is
    /// missing, or execution fails.
    pub fn run_file(&mut self, path: &Path) -> anyhow::Result<ScriptValue> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let backend_name = match ext {
            "rh" | "rhai" => "rhai",
            "lua" => "lua",
            "py" => "python",
            other => anyhow::bail!("unrecognised script extension '.{other}'"),
        };
        let backend = self
            .backends
            .get_mut(backend_name)
            .ok_or_else(|| anyhow::anyhow!("backend '{backend_name}' not registered"))?;

        // Load and execute the file exactly once via load_file.
        backend
            .load_file(path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(ScriptValue::Null)
    }

    /// Execute `code` using the named `backend` and return its result.
    ///
    /// # Errors
    /// Returns an error when the backend is not registered or evaluation fails.
    pub fn run_script(&mut self, backend: &str, code: &str) -> anyhow::Result<ScriptValue> {
        let b = self
            .backends
            .get_mut(backend)
            .ok_or_else(|| anyhow::anyhow!("backend '{backend}' not registered"))?;
        b.eval(code).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Return a list of all registered backend names.
    #[must_use]
    pub fn backend_names(&self) -> Vec<&str> {
        self.backends.keys().map(String::as_str).collect()
    }

    /// Return the name of the currently active backend, if any.
    #[must_use]
    pub fn active_name(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// Return a mutable reference to a specific backend by name.
    #[must_use]
    pub fn backend_mut<'a>(&'a mut self, name: &str) -> Option<&'a mut dyn ScriptingBackend> {
        self.backends
            .get_mut(name)
            .map(|b| -> &'a mut dyn ScriptingBackend { &mut **b })
    }
}

impl Default for ScriptHost {
    fn default() -> Self {
        Self::new()
    }
}

// ── EventSystem ───────────────────────────────────────────────────────────────

/// Simple publish/subscribe event bus that dispatches events to scripting
/// backends by running handler code strings.
///
/// The map structure is:
///   `event_name → [(backend_name, handler_code)]`
pub struct EventSystem {
    subscribers: HashMap<String, Vec<(String, String)>>,
}

impl fmt::Debug for EventSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSystem")
            .field("events", &self.subscribers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl EventSystem {
    /// Create an empty event system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
        }
    }

    /// Subscribe `handler_code` (executed via `backend`) to `event`.
    ///
    /// Multiple handlers may be registered for the same event; they are
    /// invoked in registration order.
    pub fn on(&mut self, event: &str, backend: &str, handler_code: impl Into<String>) {
        self.subscribers
            .entry(event.to_owned())
            .or_default()
            .push((backend.to_owned(), handler_code.into()));
    }

    /// Emit `event`, passing `data` to every registered handler.
    ///
    /// Each handler is invoked by calling `handler_code` in the relevant
    /// backend via `host.run_script`.  Errors from individual handlers are
    /// silently swallowed so that one failing handler does not prevent others
    /// from running.  For observable error handling, replace the handler code
    /// with code that traps its own errors.
    pub fn emit(&mut self, event: &str, data: &ScriptValue, host: &mut ScriptHost) {
        let handlers = match self.subscribers.get(event) {
            Some(h) => h.clone(),
            None => return,
        };
        // Serialise data into a JSON literal that can be embedded in code.
        let data_json = data.to_json().to_string();
        for (backend_name, handler_code) in &handlers {
            // Wrap the handler so the `data` value is available as a variable.
            let wrapped = format!("let __event_data = {data_json};\n{handler_code}");
            // Best-effort: ignore errors from individual handlers.
            let _ = host.run_script(backend_name, &wrapped);
        }
    }

    /// Return the number of handlers registered for `event`.
    #[must_use]
    pub fn handler_count(&self, event: &str) -> usize {
        self.subscribers.get(event).map_or(0, std::vec::Vec::len)
    }

    /// Return a list of all events that have at least one subscriber.
    #[must_use]
    pub fn events(&self) -> Vec<&str> {
        self.subscribers.keys().map(String::as_str).collect()
    }

    /// Remove all handlers for `event`, returning the number removed.
    pub fn clear_event(&mut self, event: &str) -> usize {
        self.subscribers.remove(event).map_or(0, |v| v.len())
    }
}

impl Default for EventSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── ScriptConfig ──────────────────────────────────────────────────────────────

/// Persistent configuration for the unified scripting host.
///
/// Can be serialised to / deserialised from JSON (or any Serde format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Name of the backend that is selected when the host starts.
    pub default_backend: String,
    /// Directories to search for scripts when resolving relative paths.
    pub script_dirs: Vec<PathBuf>,
    /// Script file names (relative to `script_dirs`) loaded automatically on
    /// host initialisation.
    pub auto_load: Vec<String>,
    /// When `true`, backends should run in sandbox mode (no FS/network access).
    pub sandbox: bool,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            default_backend: "rhai".to_owned(),
            script_dirs: Vec::new(),
            auto_load: Vec::new(),
            sandbox: true,
        }
    }
}

impl ScriptConfig {
    /// Load a `ScriptConfig` from a JSON file at `path`.
    ///
    /// # Errors
    /// Returns an error on I/O failure or if the file contains invalid JSON.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config '{}': {e}", path.display()))?;
        let cfg: Self = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse config '{}': {e}", path.display()))?;
        Ok(cfg)
    }

    /// Serialise this config to a pretty-printed JSON file at `path`.
    ///
    /// # Errors
    /// Returns an error on I/O failure or if serialisation fails.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialise config: {e}"))?;
        std::fs::write(path, text)
            .map_err(|e| anyhow::anyhow!("failed to write config '{}': {e}", path.display()))?;
        Ok(())
    }

    /// Apply this config to a `ScriptHost`: set the active backend and
    /// register `script_dirs` as a metadata hint on the host.
    ///
    /// # Errors
    /// Returns an error if the default backend is not registered.
    pub fn apply(&self, host: &mut ScriptHost) -> anyhow::Result<()> {
        if !self.default_backend.is_empty() {
            host.set_active(&self.default_backend)?;
        }
        Ok(())
    }
}

// ── NullBackend (test / placeholder) ─────────────────────────────────────────

/// A no-op backend used in tests and as a placeholder when a real adapter is
/// not available.  All `eval` calls return `ScriptValue::Null`; all `exec`
/// calls succeed silently.
pub struct NullBackend {
    backend_name: String,
    registered_fns: Vec<String>,
}

impl NullBackend {
    /// Create a `NullBackend` with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            backend_name: name.into(),
            registered_fns: Vec::new(),
        }
    }
}

impl ScriptingBackend for NullBackend {
    fn name(&self) -> &str {
        &self.backend_name
    }

    fn eval(&mut self, _code: &str) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::Null)
    }

    fn exec(&mut self, _code: &str) -> Result<(), ScriptError> {
        Ok(())
    }

    fn call(&mut self, func: &str, _args: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> {
        if self.registered_fns.iter().any(|f| f == func) {
            Ok(ScriptValue::Null)
        } else {
            Err(ScriptError::FunctionNotFound(func.to_owned()))
        }
    }

    fn load_file(&mut self, path: &Path) -> Result<(), ScriptError> {
        if !path.exists() {
            return Err(ScriptError::IoError(format!(
                "file not found: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn register_fn(
        &mut self,
        name: &str,
        _f: Box<dyn Fn(Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> + Send + Sync>,
    ) {
        self.registered_fns.push(name.to_owned());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_bytes(data: &[u8]) -> ScriptValue {
        ScriptValue::Bytes(data.to_vec())
    }

    // ── ScriptValue helpers ──────────────────────────────────────────────────

    #[test]
    fn test_value_type_names() {
        assert_eq!(ScriptValue::Null.type_name(), "null");
        assert_eq!(ScriptValue::Bool(true).type_name(), "bool");
        assert_eq!(ScriptValue::Int(0).type_name(), "int");
        assert_eq!(ScriptValue::Float(0.0).type_name(), "float");
        assert_eq!(ScriptValue::String(String::new()).type_name(), "string");
        assert_eq!(ScriptValue::Bytes(vec![]).type_name(), "bytes");
        assert_eq!(ScriptValue::List(vec![]).type_name(), "list");
        assert_eq!(ScriptValue::Map(HashMap::new()).type_name(), "map");
        assert_eq!(ScriptValue::Address(0).type_name(), "address");
        assert_eq!(ScriptValue::Callable("f".into()).type_name(), "callable");
    }

    #[test]
    fn test_value_truthiness() {
        assert!(!ScriptValue::Null.is_truthy());
        assert!(!ScriptValue::Bool(false).is_truthy());
        assert!(ScriptValue::Bool(true).is_truthy());
        assert!(!ScriptValue::Int(0).is_truthy());
        assert!(ScriptValue::Int(1).is_truthy());
        assert!(ScriptValue::Address(0xdead_beef).is_truthy());
        assert!(!ScriptValue::String(String::new()).is_truthy());
        assert!(ScriptValue::String("x".into()).is_truthy());
        assert!(ScriptValue::Callable("fn".into()).is_truthy());
    }

    #[test]
    fn test_value_is_null() {
        assert!(ScriptValue::Null.is_null());
        assert!(!ScriptValue::Int(0).is_null());
    }

    #[test]
    fn test_value_as_int() {
        assert_eq!(ScriptValue::Int(42).as_int().unwrap(), 42);
        assert_eq!(ScriptValue::Float(3.9).as_int().unwrap(), 3);
        assert_eq!(ScriptValue::Bool(true).as_int().unwrap(), 1);
        assert!(ScriptValue::Null.as_int().is_err());
    }

    #[test]
    fn test_value_as_float() {
        assert!((ScriptValue::Float(1.5).as_float().unwrap() - 1.5).abs() < f64::EPSILON);
        assert!((ScriptValue::Int(2).as_float().unwrap() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_value_as_bool() {
        assert!(ScriptValue::Bool(true).as_bool().unwrap());
        assert!(ScriptValue::Int(0).as_bool().is_err());
    }

    #[test]
    fn test_value_as_address() {
        assert_eq!(ScriptValue::Address(0x1000).as_address().unwrap(), 0x1000);
        assert_eq!(ScriptValue::Int(255).as_address().unwrap(), 255);
        assert!(ScriptValue::Null.as_address().is_err());
    }

    #[test]
    fn test_value_as_list() {
        let l = ScriptValue::List(vec![ScriptValue::Int(1)]);
        assert_eq!(l.as_list().unwrap().len(), 1);
        assert!(ScriptValue::Null.as_list().is_err());
    }

    #[test]
    fn test_value_as_map() {
        let mut m = HashMap::new();
        m.insert("k".into(), ScriptValue::Int(1));
        let v = ScriptValue::Map(m);
        assert_eq!(v.as_map().unwrap().len(), 1);
        assert!(ScriptValue::Null.as_map().is_err());
    }

    #[test]
    fn test_value_len() {
        assert_eq!(ScriptValue::String("hello".into()).len().unwrap(), 5);
        assert_eq!(ScriptValue::Bytes(vec![0, 1, 2]).len().unwrap(), 3);
        assert_eq!(ScriptValue::List(vec![ScriptValue::Null]).len().unwrap(), 1);
        assert!(ScriptValue::Int(0).len().is_err());
    }

    #[test]
    fn test_value_is_empty() {
        assert!(ScriptValue::String(String::new()).is_empty().unwrap());
        assert!(!ScriptValue::String("x".into()).is_empty().unwrap());
    }

    #[test]
    fn test_value_display() {
        assert_eq!(ScriptValue::Null.to_display_string(), "null");
        assert_eq!(ScriptValue::Address(0xff).to_display_string(), "0xff");
        assert_eq!(
            ScriptValue::List(vec![ScriptValue::Int(1), ScriptValue::Int(2)]).to_display_string(),
            "[1, 2]"
        );
        assert_eq!(
            ScriptValue::Callable("foo".into()).to_display_string(),
            "<fn:foo>"
        );
    }

    #[test]
    fn test_value_from_conversions() {
        assert_eq!(ScriptValue::from(10i64), ScriptValue::Int(10));
        assert_eq!(ScriptValue::from(1.0f64), ScriptValue::Float(1.0));
        assert_eq!(ScriptValue::from(true), ScriptValue::Bool(true));
        assert_eq!(
            ScriptValue::from("hello"),
            ScriptValue::String("hello".into())
        );
        assert_eq!(ScriptValue::from(5i32), ScriptValue::Int(5));
        assert_eq!(ScriptValue::from(5u32), ScriptValue::Int(5));
    }

    #[test]
    fn test_value_to_json() {
        let v = ScriptValue::Map({
            let mut m = HashMap::new();
            m.insert("x".into(), ScriptValue::Int(1));
            m
        });
        let j = v.to_json();
        assert_eq!(j["x"], serde_json::json!(1));
    }

    #[test]
    fn test_value_from_json() {
        let j = serde_json::json!({"key": "val", "num": 42});
        let v = ScriptValue::from_json(j);
        if let ScriptValue::Map(m) = v {
            assert_eq!(m["num"], ScriptValue::Int(42));
        } else {
            panic!("expected map");
        }
    }

    // ── ScriptError ──────────────────────────────────────────────────────────

    #[test]
    fn test_error_is_recoverable() {
        assert!(ScriptError::FunctionNotFound("f".into()).is_recoverable());
        assert!(!ScriptError::StackOverflow.is_recoverable());
    }

    #[test]
    fn test_error_constructors() {
        let e = ScriptError::runtime("boom");
        assert!(e.to_string().contains("boom"));
        let e2 = ScriptError::parse(1, 5, "bad token");
        assert!(e2.to_string().contains("bad token"));
    }

    // ── Built-ins ────────────────────────────────────────────────────────────

    #[test]
    fn test_hex_to_bytes_and_back() {
        let hex = ScriptValue::String("deadbeef".into());
        let bytes = builtin_hex_to_bytes(&[hex]).unwrap();
        if let ScriptValue::Bytes(b) = &bytes {
            assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]);
        } else {
            panic!("expected Bytes");
        }
        let hex_back = builtin_bytes_to_hex(&[bytes]).unwrap();
        assert_eq!(hex_back, ScriptValue::String("deadbeef".into()));
    }

    #[test]
    fn test_hex_to_bytes_0x_prefix() {
        let hex = ScriptValue::String("0x0102".into());
        let bytes = builtin_hex_to_bytes(&[hex]).unwrap();
        assert_eq!(bytes, ScriptValue::Bytes(vec![0x01, 0x02]));
    }

    #[test]
    fn test_hex_to_bytes_odd_length_errors() {
        let hex = ScriptValue::String("abc".into());
        assert!(builtin_hex_to_bytes(&[hex]).is_err());
    }

    #[test]
    fn test_read_u8() {
        let data = mk_bytes(&[0xAA, 0xBB]);
        assert_eq!(
            builtin_read_u8(&[data, ScriptValue::Int(1)]).unwrap(),
            ScriptValue::Int(0xBB)
        );
    }

    #[test]
    fn test_read_u16_le() {
        let data = mk_bytes(&[0x01, 0x00, 0x00]);
        assert_eq!(
            builtin_read_u16(&[data, ScriptValue::Int(0)]).unwrap(),
            ScriptValue::Int(1)
        );
    }

    #[test]
    fn test_read_u32_le() {
        let data = mk_bytes(&[0xFF, 0x00, 0x00, 0x00]);
        assert_eq!(
            builtin_read_u32(&[data, ScriptValue::Int(0)]).unwrap(),
            ScriptValue::Int(255)
        );
    }

    #[test]
    fn test_read_u32_be() {
        let data = mk_bytes(&[0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(
            builtin_read_u32_be(&[data, ScriptValue::Int(0)]).unwrap(),
            ScriptValue::Int(255)
        );
    }

    #[test]
    fn test_read_u64_le() {
        let data = mk_bytes(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            builtin_read_u64(&[data, ScriptValue::Int(0)]).unwrap(),
            ScriptValue::Int(1)
        );
    }

    #[test]
    fn test_write_u8() {
        let data = mk_bytes(&[0x00, 0x00]);
        let result =
            builtin_write_u8(&[data, ScriptValue::Int(1), ScriptValue::Int(0xFF)]).unwrap();
        assert_eq!(result, ScriptValue::Bytes(vec![0x00, 0xFF]));
    }

    #[test]
    fn test_xor_bytes() {
        let a = mk_bytes(&[0xFF, 0x00]);
        let b = mk_bytes(&[0x0F, 0xF0]);
        let result = builtin_xor_bytes(&[a, b]).unwrap();
        assert_eq!(result, ScriptValue::Bytes(vec![0xF0, 0xF0]));
    }

    #[test]
    fn test_xor_bytes_key_cycling() {
        let data = mk_bytes(&[0x01, 0x02, 0x03, 0x04]);
        let key = mk_bytes(&[0xFF]);
        let result = builtin_xor_bytes(&[data, key]).unwrap();
        assert_eq!(result, ScriptValue::Bytes(vec![0xFE, 0xFD, 0xFC, 0xFB]));
    }

    #[test]
    fn test_xor_bytes_empty_key_errors() {
        let data = mk_bytes(&[0x01]);
        let key = mk_bytes(&[]);
        assert!(builtin_xor_bytes(&[data, key]).is_err());
    }

    #[test]
    fn test_to_string_builtin() {
        let v = ScriptValue::Int(42);
        assert_eq!(
            builtin_to_string(&[v]).unwrap(),
            ScriptValue::String("42".into())
        );
    }

    #[test]
    fn test_builtin_len() {
        let l = ScriptValue::List(vec![ScriptValue::Null; 3]);
        assert_eq!(builtin_len(&[l]).unwrap(), ScriptValue::Int(3));
    }

    #[test]
    fn test_builtin_typeof() {
        assert_eq!(
            builtin_typeof(&[ScriptValue::Float(1.0)]).unwrap(),
            ScriptValue::String("float".into())
        );
    }

    #[test]
    fn test_bytes_concat() {
        let a = mk_bytes(&[0x01, 0x02]);
        let b = mk_bytes(&[0x03, 0x04]);
        let r = builtin_bytes_concat(&[a, b]).unwrap();
        assert_eq!(r, ScriptValue::Bytes(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_bytes_slice() {
        let data = mk_bytes(&[0, 1, 2, 3, 4]);
        let r = builtin_bytes_slice(&[data, ScriptValue::Int(1), ScriptValue::Int(4)]).unwrap();
        assert_eq!(r, ScriptValue::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn test_bytes_fill() {
        let r = builtin_bytes_fill(&[ScriptValue::Int(4), ScriptValue::Int(0xAA)]).unwrap();
        assert_eq!(r, ScriptValue::Bytes(vec![0xAA; 4]));
    }

    #[test]
    fn test_bytes_find_found() {
        let haystack = mk_bytes(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
        let needle = mk_bytes(&[0xDE, 0xAD]);
        let r = builtin_bytes_find(&[haystack, needle]).unwrap();
        assert_eq!(r, ScriptValue::Int(1));
    }

    #[test]
    fn test_bytes_find_not_found() {
        let haystack = mk_bytes(&[0x00, 0x01]);
        let needle = mk_bytes(&[0xFF]);
        let r = builtin_bytes_find(&[haystack, needle]).unwrap();
        assert_eq!(r, ScriptValue::Null);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let data = mk_bytes(&[0x01]);
        assert!(builtin_read_u16(&[data, ScriptValue::Int(0)]).is_err());
    }

    // ── ScriptContext ────────────────────────────────────────────────────────

    #[test]
    fn test_script_context_globals() {
        let mut ctx = ScriptContext::new();
        ctx.set_global("x", ScriptValue::Int(7));
        assert_eq!(ctx.get_global("x"), Some(&ScriptValue::Int(7)));
        assert_eq!(ctx.get_global("y"), None);
    }

    #[test]
    fn test_script_context_remove_global() {
        let mut ctx = ScriptContext::new();
        ctx.set_global("z", ScriptValue::Bool(true));
        let removed = ctx.remove_global("z");
        assert_eq!(removed, Some(ScriptValue::Bool(true)));
        assert!(ctx.get_global("z").is_none());
    }

    #[test]
    fn test_script_context_output() {
        let mut ctx = ScriptContext::new();
        ctx.write_output("hello");
        ctx.write_error("oops");
        assert_eq!(ctx.output, vec!["hello"]);
        assert_eq!(ctx.error_output, vec!["oops"]);
    }

    #[test]
    fn test_script_context_meta() {
        let mut ctx = ScriptContext::new();
        ctx.set_meta("engine", "rhai");
        assert_eq!(ctx.get_meta("engine").map(String::as_str), Some("rhai"));
    }

    #[test]
    fn test_script_context_register_and_get_fn() {
        let mut ctx = ScriptContext::new();
        ctx.register_fn(
            "add_one",
            native_fn(|args| {
                let n = args[0].as_int()?;
                Ok(ScriptValue::Int(n + 1))
            }),
        );
        let f = ctx.get_fn("add_one").unwrap().clone();
        let result = f.call(&[ScriptValue::Int(41)]).unwrap();
        assert_eq!(result, ScriptValue::Int(42));
    }

    #[test]
    fn test_script_context_global_names() {
        let mut ctx = ScriptContext::new();
        ctx.set_global("a", ScriptValue::Null);
        ctx.set_global("b", ScriptValue::Null);
        let mut names = ctx.global_names();
        names.sort_unstable();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_script_context_with_globals() {
        let mut map = HashMap::new();
        map.insert("x".into(), ScriptValue::Int(99));
        let ctx = ScriptContext::new().with_globals(map);
        assert_eq!(ctx.get_global("x"), Some(&ScriptValue::Int(99)));
    }

    // ── ScriptResult ─────────────────────────────────────────────────────────

    #[test]
    fn test_script_result_stdout_joined() {
        let mut ctx = ScriptContext::new();
        ctx.write_output("line1");
        ctx.write_output("line2");
        let result = ScriptResult::new(ScriptValue::Null, &ctx);
        assert_eq!(result.stdout_joined(), "line1\nline2");
    }

    #[test]
    fn test_script_result_failure() {
        let r = ScriptResult::failure("oops");
        assert!(!r.success);
        assert!(r.has_errors());
        assert_eq!(r.value, ScriptValue::Null);
    }

    #[test]
    fn test_script_result_with_elapsed() {
        let mut ctx = ScriptContext::new();
        let r = ScriptResult::new(ScriptValue::Null, &ctx).with_elapsed(42);
        assert_eq!(r.elapsed_ms, 42);
        let _ = &mut ctx; // suppress lint
    }

    // ── ScriptModule ─────────────────────────────────────────────────────────

    #[test]
    fn test_script_module_add_and_get() {
        let mut m = ScriptModule::new("math");
        m.add_fn(
            "double",
            native_fn(|args| {
                let n = args[0].as_int()?;
                Ok(ScriptValue::Int(n * 2))
            }),
        );
        m.add_const("PI", ScriptValue::Float(std::f64::consts::PI));
        assert!(m.get_fn("double").is_some());
        assert!(m.get_const("PI").is_some());
        assert_eq!(m.symbol_count(), 2);
    }

    #[test]
    fn test_re_module_has_builtins() {
        let m = re_module();
        assert!(m.get_fn("hex_to_bytes").is_some());
        assert!(m.get_fn("xor_bytes").is_some());
        assert!(m.get_const("NULL").is_some());
    }

    // ── CompiledScript ────────────────────────────────────────────────────────

    #[test]
    fn test_compiled_script_empty() {
        let cs = CompiledScript::empty("rhai");
        assert!(cs.is_empty());
        assert_eq!(cs.engine_name, "rhai");
    }

    #[test]
    fn test_compiled_script_warnings() {
        let mut cs = CompiledScript::new("lua", "print(1)");
        cs.add_warning("deprecated function");
        assert_eq!(cs.warnings.len(), 1);
    }

    // ── ScriptEngineRegistry ──────────────────────────────────────────────────

    #[test]
    fn test_registry_find_by_extension() {
        let registry = ScriptEngineRegistry::new();
        assert!(registry.find_by_extension("rhai").is_none());
        assert_eq!(registry.list_engines(), Vec::<String>::new());
    }

    #[test]
    fn test_registry_debug_format() {
        let reg = ScriptEngineRegistry::new();
        let s = format!("{reg:?}");
        assert!(s.contains("ScriptEngineRegistry"));
    }

    // ── SandboxPolicy ────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_deny_all() {
        let p = SandboxPolicy::deny_all();
        assert!(!p.allow_fs_read);
        assert!(!p.allow_network);
    }

    #[test]
    fn test_sandbox_allow_all() {
        let p = SandboxPolicy::allow_all();
        assert!(p.allow_fs_read);
        assert!(p.allow_network);
        assert!(p.allow_subprocess);
    }

    #[test]
    fn test_sandbox_read_only() {
        let p = SandboxPolicy::read_only();
        assert!(p.allow_fs_read);
        assert!(!p.allow_fs_write);
        assert!(!p.allow_network);
        assert_eq!(p.max_time_ms, 5_000);
    }

    // ── ScriptFn closure impl ─────────────────────────────────────────────────

    #[test]
    fn test_script_fn_from_closure() {
        let f: Box<dyn ScriptFn> = Box::new(|args: &[ScriptValue]| Ok(args[0].clone()));
        let result = f.call(&[ScriptValue::Int(99)]).unwrap();
        assert_eq!(result, ScriptValue::Int(99));
    }

    #[test]
    fn test_native_fn_arc() {
        let f = native_fn(|args| Ok(args[0].clone()));
        let result = f.call(&[ScriptValue::Bool(true)]).unwrap();
        assert_eq!(result, ScriptValue::Bool(true));
    }

    // ── VariableFrame ─────────────────────────────────────────────────────────

    #[test]
    fn test_variable_frame_root_bind_lookup() {
        let mut frame = VariableFrame::root();
        frame.bind("x", ScriptValue::Int(10));
        assert_eq!(frame.lookup("x"), Some(&ScriptValue::Int(10)));
        assert!(frame.lookup("y").is_none());
    }

    #[test]
    fn test_variable_frame_child_inherits_parent() {
        let mut root = VariableFrame::root();
        root.bind("a", ScriptValue::Int(1));
        let child = VariableFrame::child(root);
        assert_eq!(child.lookup("a"), Some(&ScriptValue::Int(1)));
    }

    #[test]
    fn test_variable_frame_child_shadows_parent() {
        let mut root = VariableFrame::root();
        root.bind("a", ScriptValue::Int(1));
        let mut child = VariableFrame::child(root);
        child.bind("a", ScriptValue::Int(99));
        assert_eq!(child.lookup("a"), Some(&ScriptValue::Int(99)));
    }

    #[test]
    fn test_variable_frame_assign() {
        let mut root = VariableFrame::root();
        root.bind("x", ScriptValue::Int(0));
        let mut child = VariableFrame::child(root);
        let ok = child.assign("x", ScriptValue::Int(42));
        assert!(ok);
        // The assignment went to the parent; lookup from child should see 42.
        assert_eq!(child.lookup("x"), Some(&ScriptValue::Int(42)));
    }

    #[test]
    fn test_variable_frame_assign_missing() {
        let mut frame = VariableFrame::root();
        let ok = frame.assign("z", ScriptValue::Null);
        assert!(!ok);
    }

    #[test]
    fn test_variable_frame_local_count() {
        let mut frame = VariableFrame::root();
        frame.bind("a", ScriptValue::Null);
        frame.bind("b", ScriptValue::Null);
        assert_eq!(frame.local_count(), 2);
    }

    // ── ScriptPipeline ────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_len_empty() {
        let p = ScriptPipeline::new();
        assert_eq!(p.len(), 0);
        assert!(p.is_empty());
    }

    #[test]
    fn test_pipeline_push() {
        let mut p = ScriptPipeline::new();
        p.push(PipelineStep::new("lua", "return 1"));
        assert_eq!(p.len(), 1);
        assert!(!p.is_empty());
    }

    #[test]
    fn test_pipeline_step_with_label() {
        let step = PipelineStep::new("rhai", "1+1").with_label("add");
        assert_eq!(step.label.as_deref(), Some("add"));
    }

    // ── register_builtins ─────────────────────────────────────────────────────

    #[test]
    fn test_register_builtins_populates_context() {
        let mut ctx = ScriptContext::new();
        register_builtins(&mut ctx);
        assert!(ctx.get_fn("hex_to_bytes").is_some());
        assert!(ctx.get_fn("xor_bytes").is_some());
        assert!(ctx.get_fn("len").is_some());
    }

    // ── builtin_functions map ─────────────────────────────────────────────────

    #[test]
    fn test_builtin_functions_map_contains_all() {
        let map = builtin_functions();
        let expected = [
            "hex_to_bytes",
            "bytes_to_hex",
            "read_u8",
            "read_u16",
            "read_u32",
            "read_u32_be",
            "read_u64",
            "write_u8",
            "write_u16",
            "write_u32",
            "write_u64",
            "xor_bytes",
            "to_string",
            "len",
            "typeof",
            "bytes_concat",
            "bytes_slice",
            "bytes_fill",
            "bytes_find",
        ];
        for name in &expected {
            assert!(map.contains_key(*name), "missing built-in: {name}");
        }
    }
}
