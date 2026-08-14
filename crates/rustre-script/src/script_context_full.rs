//! Full-featured scripting context.
//!
//! Provides `ScriptContextFull`, `ScriptEnvironment`, `GlobalScope`,
//! `FunctionRegistry`, `TypeRegistry`, and `EventHooks` for a rich
//! scripting runtime that can be shared across Lua, Python, and Rhai adapters.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{ScriptError, ScriptValue};

// ── TypeInfo ──────────────────────────────────────────────────────────────────

/// Type information stored in the type registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    /// Type name.
    pub name: String,
    /// Kind: "struct", "enum", "alias", "opaque".
    pub kind: String,
    /// Description.
    pub description: String,
    /// Field names (for structs).
    pub fields: Vec<String>,
    /// Variant names (for enums).
    pub variants: Vec<String>,
    /// Whether the type is built-in.
    pub builtin: bool,
}

impl TypeInfo {
    /// Create a struct type.
    #[must_use]
    pub fn struct_type(name: impl Into<String>, fields: Vec<String>) -> Self {
        Self {
            name: name.into(),
            kind: "struct".into(),
            description: String::new(),
            fields,
            variants: Vec::new(),
            builtin: false,
        }
    }

    /// Create an enum type.
    #[must_use]
    pub fn enum_type(name: impl Into<String>, variants: Vec<String>) -> Self {
        Self {
            name: name.into(),
            kind: "enum".into(),
            description: String::new(),
            fields: Vec::new(),
            variants,
            builtin: false,
        }
    }

    /// Return `true` if this type has the given field.
    #[must_use]
    pub fn has_field(&self, field: &str) -> bool {
        self.fields.iter().any(|f| f == field)
    }
}

// ── TypeRegistry ──────────────────────────────────────────────────────────────

/// Registry of types exposed to scripting engines.
#[derive(Debug, Default, Clone)]
pub struct TypeRegistry {
    types: HashMap<String, TypeInfo>,
}

impl TypeRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a type.
    pub fn register(&mut self, info: TypeInfo) {
        self.types.insert(info.name.clone(), info);
    }

    /// Look up a type by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TypeInfo> {
        self.types.get(name)
    }

    /// Return `true` if a type is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// Remove a type.
    pub fn remove(&mut self, name: &str) -> bool {
        self.types.remove(name).is_some()
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Return all registered type names, sorted.
    #[must_use]
    pub fn type_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.types.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

// ── FunctionSignature ─────────────────────────────────────────────────────────

/// Metadata about a registered function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name.
    pub name: String,
    /// Parameter names.
    pub params: Vec<String>,
    /// Return type name.
    pub return_type: String,
    /// Docstring.
    pub doc: String,
    /// Whether the function is variadic.
    pub variadic: bool,
    /// Module this function belongs to.
    pub module: Option<String>,
}

impl FunctionSignature {
    /// Create a minimal signature.
    #[must_use]
    pub fn new(name: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            name: name.into(),
            params,
            return_type: "any".into(),
            doc: String::new(),
            variadic: false,
            module: None,
        }
    }

    /// Return the arity (fixed parameter count).
    #[must_use]
    pub const fn arity(&self) -> usize {
        self.params.len()
    }

    /// Return `true` if the argument count matches this signature.
    #[must_use]
    pub const fn accepts_arity(&self, n: usize) -> bool {
        if self.variadic {
            n >= self.params.len()
        } else {
            n == self.params.len()
        }
    }
}

// ── FunctionRegistry ──────────────────────────────────────────────────────────

/// Shared implementation function for a registered script callable.
pub type ScriptImplFn = Arc<dyn Fn(&[ScriptValue]) -> Result<ScriptValue, ScriptError> + Send + Sync>;

/// Thread-safe registry of callable functions and their signatures.
pub struct FunctionRegistry {
    signatures: RwLock<HashMap<String, FunctionSignature>>,
    /// The actual function implementations.
    impls: RwLock<HashMap<String, ScriptImplFn>>,
}

impl fmt::Debug for FunctionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FunctionRegistry {{ count: {} }}",
            self.signatures.read().len()
        )
    }
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: RwLock::new(HashMap::new()),
            impls: RwLock::new(HashMap::new()),
        }
    }

    /// Register a function with its signature and implementation.
    pub fn register<F>(&self, sig: FunctionSignature, f: F)
    where
        F: Fn(&[ScriptValue]) -> Result<ScriptValue, ScriptError> + Send + Sync + 'static,
    {
        let name = sig.name.clone();
        self.signatures.write().insert(name.clone(), sig);
        self.impls.write().insert(name, Arc::new(f));
    }

    /// Call a function by name.
    ///
    /// # Errors
    /// Returns `ScriptError::FunctionNotFound` if the function does not exist,
    /// or `ScriptError::ArityMismatch` if the argument count is wrong.
    pub fn call(&self, name: &str, args: &[ScriptValue]) -> Result<ScriptValue, ScriptError> {
        let sig_guard = self.signatures.read();
        let sig = sig_guard
            .get(name)
            .ok_or_else(|| ScriptError::FunctionNotFound(name.to_owned()))?;
        if !sig.accepts_arity(args.len()) {
            return Err(ScriptError::ArityMismatch {
                name: name.to_owned(),
                expected: sig.arity(),
                got: args.len(),
            });
        }
        drop(sig_guard);
        let impls_guard = self.impls.read();
        let f = impls_guard
            .get(name)
            .ok_or_else(|| ScriptError::FunctionNotFound(name.to_owned()))?
            .clone();
        drop(impls_guard);
        f(args)
    }

    /// Return `true` if a function is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.signatures.read().contains_key(name)
    }

    /// Return all function names, sorted.
    #[must_use]
    pub fn function_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.signatures.read().keys().cloned().collect();
        names.sort();
        names
    }

    /// Unregister a function.
    pub fn remove(&self, name: &str) -> bool {
        let removed = self.signatures.write().remove(name).is_some();
        self.impls.write().remove(name);
        removed
    }

    /// Number of registered functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.read().len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.read().is_empty()
    }

    /// Look up a function signature.
    #[must_use]
    pub fn get_signature(&self, name: &str) -> Option<FunctionSignature> {
        self.signatures.read().get(name).cloned()
    }
}

// ── GlobalScope ───────────────────────────────────────────────────────────────

/// The global variable scope shared across script executions.
#[derive(Debug, Default, Clone)]
pub struct GlobalScope {
    /// All global variable bindings.
    pub vars: HashMap<String, ScriptValue>,
    /// Whether new global variables are allowed.
    pub allow_new_globals: bool,
    /// Immutable (constant) names — cannot be overwritten.
    pub constants: std::collections::HashSet<String>,
}

impl GlobalScope {
    /// Create a new, empty global scope.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            allow_new_globals: true,
            constants: std::collections::HashSet::new(),
        }
    }

    /// Set a variable in the global scope.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn set(&mut self, name: impl Into<String>, value: ScriptValue) -> Result<(), ScriptError> {
        let name = name.into();
        if self.constants.contains(&name) {
            return Err(ScriptError::PermissionDenied(format!(
                "cannot modify constant '{name}'"
            )));
        }
        if !self.allow_new_globals && !self.vars.contains_key(&name) {
            return Err(ScriptError::PermissionDenied(format!(
                "new global variables are not allowed ('{name}')"
            )));
        }
        self.vars.insert(name, value);
        Ok(())
    }

    /// Get a variable.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ScriptValue> {
        self.vars.get(name)
    }

    /// Define an immutable constant.
    pub fn define_const(&mut self, name: impl Into<String>, value: ScriptValue) {
        let name = name.into();
        self.constants.insert(name.clone());
        self.vars.insert(name, value);
    }

    /// Return `true` if the name is a constant.
    #[must_use]
    pub fn is_const(&self, name: &str) -> bool {
        self.constants.contains(name)
    }

    /// Return all variable names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut n: Vec<&str> = self.vars.keys().map(String::as_str).collect();
        n.sort_unstable();
        n
    }

    /// Remove a non-constant variable.
    pub fn remove(&mut self, name: &str) -> bool {
        if self.constants.contains(name) {
            return false;
        }
        self.vars.remove(name).is_some()
    }

    /// Clear all non-constant variables.
    pub fn clear_vars(&mut self) {
        self.vars.retain(|k, _| self.constants.contains(k));
    }
}

// ── EventHook ─────────────────────────────────────────────────────────────────

/// A hook callback registered for a named scripting event.
pub struct EventHook {
    /// Event name.
    pub event: String,
    /// Hook priority; lower numbers run first.
    pub priority: u32,
    /// The callback.
    pub callback: Arc<dyn Fn(ScriptValue) -> Result<(), ScriptError> + Send + Sync>,
    /// Whether this hook runs only once.
    pub once: bool,
    /// Whether this hook has been consumed (once-hooks).
    pub consumed: bool,
}

impl fmt::Debug for EventHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventHook")
            .field("event", &self.event)
            .field("priority", &self.priority)
            .field("once", &self.once)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl EventHook {
    /// Create a persistent hook.
    #[must_use]
    pub fn new<F>(event: impl Into<String>, priority: u32, f: F) -> Self
    where
        F: Fn(ScriptValue) -> Result<(), ScriptError> + Send + Sync + 'static,
    {
        Self {
            event: event.into(),
            priority,
            callback: Arc::new(f),
            once: false,
            consumed: false,
        }
    }

    /// Create a once-only hook.
    #[must_use]
    pub fn once<F>(event: impl Into<String>, priority: u32, f: F) -> Self
    where
        F: Fn(ScriptValue) -> Result<(), ScriptError> + Send + Sync + 'static,
    {
        Self {
            event: event.into(),
            priority,
            callback: Arc::new(f),
            once: true,
            consumed: false,
        }
    }

    /// Fire the hook, returning its result.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn fire(&mut self, data: ScriptValue) -> Result<(), ScriptError> {
        if self.consumed {
            return Ok(());
        }
        let result = (self.callback)(data);
        if self.once {
            self.consumed = true;
        }
        result
    }
}

/// Thread-safe event hook registry.
#[derive(Debug, Default)]
pub struct EventHooks {
    hooks: RwLock<Vec<EventHook>>,
}

impl EventHooks {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook.
    pub fn register(&self, hook: EventHook) {
        let mut guard = self.hooks.write();
        guard.push(hook);
        guard.sort_by_key(|h| h.priority);
    }

    /// Emit an event, firing all matching hooks.
    ///
    /// Returns the number of hooks fired.
    pub fn emit(&self, event: &str, data: &ScriptValue) -> usize {
        let mut guard = self.hooks.write();
        let mut count = 0;
        for hook in guard.iter_mut() {
            if hook.event == event && !hook.consumed {
                let _ = hook.fire(data.clone());
                count += 1;
            }
        }
        // Evict consumed once-hooks.
        guard.retain(|h| !(h.once && h.consumed));
        count
    }

    /// Number of registered hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.read().len()
    }

    /// Return `true` if there are no hooks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.read().is_empty()
    }

    /// Remove all hooks for the given event.
    pub fn clear_event(&self, event: &str) -> usize {
        let mut guard = self.hooks.write();
        let before = guard.len();
        guard.retain(|h| h.event != event);
        before - guard.len()
    }

    /// Remove all hooks.
    pub fn clear_all(&self) {
        self.hooks.write().clear();
    }

    /// Return the events that have at least one hook.
    #[must_use]
    pub fn active_events(&self) -> Vec<String> {
        let guard = self.hooks.read();
        let mut events: Vec<String> = guard.iter().map(|h| h.event.clone()).collect();
        events.sort();
        events.dedup();
        events
    }
}

// ── ScriptEnvironment ─────────────────────────────────────────────────────────

/// Runtime environment configuration for a scripting session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptEnvironment {
    /// Engine language name.
    pub language: String,
    /// Script working directory.
    pub working_dir: String,
    /// Additional include paths.
    pub include_paths: Vec<String>,
    /// Maximum call stack depth.
    pub max_call_depth: u32,
    /// Maximum execution time in milliseconds (0 = unlimited).
    pub max_time_ms: u64,
    /// Whether sandbox mode is active.
    pub sandbox: bool,
    /// Environment variables visible to scripts.
    pub env_vars: HashMap<String, String>,
    /// Whether to enable debug output.
    pub debug: bool,
    /// Script character encoding.
    pub encoding: String,
}

impl Default for ScriptEnvironment {
    fn default() -> Self {
        Self {
            language: "rhai".into(),
            working_dir: ".".into(),
            include_paths: Vec::new(),
            max_call_depth: 256,
            max_time_ms: 10_000,
            sandbox: true,
            env_vars: HashMap::new(),
            debug: false,
            encoding: "utf-8".into(),
        }
    }
}

impl ScriptEnvironment {
    /// Create with defaults.
    #[must_use]
    pub fn new(language: impl Into<String>) -> Self {
        Self {
            language: language.into(),
            ..Default::default()
        }
    }

    /// Add an include path.
    #[must_use]
    pub fn with_include(mut self, path: impl Into<String>) -> Self {
        self.include_paths.push(path.into());
        self
    }

    /// Disable the sandbox.
    #[must_use]
    pub const fn without_sandbox(mut self) -> Self {
        self.sandbox = false;
        self
    }

    /// Set debug mode.
    #[must_use]
    pub const fn with_debug(mut self) -> Self {
        self.debug = true;
        self
    }
}

// ── ScriptContextFull ─────────────────────────────────────────────────────────

/// Full-featured scripting context combining all subsystems.
///
/// Designed to be shared across multiple scripting engine invocations within
/// the same session.
pub struct ScriptContextFull {
    /// Environment configuration.
    pub env: ScriptEnvironment,
    /// Global scope.
    pub globals: GlobalScope,
    /// Function registry.
    pub functions: FunctionRegistry,
    /// Type registry.
    pub types: TypeRegistry,
    /// Event hooks.
    pub hooks: EventHooks,
    /// Session-level output buffer.
    pub output: Vec<String>,
    /// Session-level error buffer.
    pub errors: Vec<String>,
    /// Execution counter.
    pub exec_count: u64,
    /// Whether the context is frozen (no modifications allowed).
    pub frozen: bool,
}

impl fmt::Debug for ScriptContextFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptContextFull")
            .field("language", &self.env.language)
            .field("exec_count", &self.exec_count)
            .field("globals_count", &self.globals.vars.len())
            .field("functions_count", &self.functions.len())
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

impl Default for ScriptContextFull {
    fn default() -> Self {
        Self::new(ScriptEnvironment::default())
    }
}

impl ScriptContextFull {
    /// Create a new full context.
    #[must_use]
    pub fn new(env: ScriptEnvironment) -> Self {
        Self {
            env,
            globals: GlobalScope::new(),
            functions: FunctionRegistry::new(),
            types: TypeRegistry::new(),
            hooks: EventHooks::new(),
            output: Vec::new(),
            errors: Vec::new(),
            exec_count: 0,
            frozen: false,
        }
    }

    /// Register the standard `RustRE` built-in functions.
    pub fn register_builtins(&mut self) {
        // A minimal selection of built-ins for demonstration.
        let sig = FunctionSignature::new("println", vec!["value".into()]);
        self.functions.register(sig, |args| {
            args.first().map_or(Ok(ScriptValue::Null), |v| {
                Ok(ScriptValue::String(v.to_string()))
            })
        });

        let sig2 = FunctionSignature {
            name: "format_hex".into(),
            params: vec!["addr".into()],
            return_type: "string".into(),
            doc: "Format an address as a hex string.".into(),
            variadic: false,
            module: Some("re".into()),
        };
        self.functions.register(sig2, |args| {
            let addr = args
                .first()
                .and_then(super::ScriptValue::as_int_opt)
                .unwrap_or(0);
            Ok(ScriptValue::String(format!("0x{addr:x}")))
        });

        // Register standard types.
        self.types.register(TypeInfo::struct_type(
            "Address",
            vec!["value".into(), "offset".into()],
        ));
        self.types.register(TypeInfo::enum_type(
            "AnalysisState",
            vec!["NotStarted".into(), "InProgress".into(), "Complete".into()],
        ));
    }

    /// Set a global variable.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn set_global(
        &mut self,
        name: impl Into<String>,
        value: ScriptValue,
    ) -> Result<(), ScriptError> {
        if self.frozen {
            return Err(ScriptError::PermissionDenied("context is frozen".into()));
        }
        self.globals.set(name, value)
    }

    /// Get a global variable.
    #[must_use]
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.globals.get(name)
    }

    /// Write a line to the output buffer.
    pub fn write_output(&mut self, line: impl Into<String>) {
        self.output.push(line.into());
    }

    /// Write a line to the error buffer.
    pub fn write_error(&mut self, line: impl Into<String>) {
        self.errors.push(line.into());
    }

    /// Mark the start of a new script execution.
    pub const fn begin_exec(&mut self) {
        self.exec_count += 1;
    }

    /// Freeze the context (prevent further modifications).
    pub const fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Return the combined output as a single string.
    #[must_use]
    pub fn output_joined(&self) -> String {
        self.output.join("\n")
    }

    /// Return the combined errors as a single string.
    #[must_use]
    pub fn errors_joined(&self) -> String {
        self.errors.join("\n")
    }

    /// Reset the output and error buffers without clearing globals.
    pub fn reset_buffers(&mut self) {
        self.output.clear();
        self.errors.clear();
    }

    /// Emit an event.
    pub fn emit_event(&self, event: &str, data: &ScriptValue) -> usize {
        self.hooks.emit(event, data)
    }

    /// Summary string for diagnostics.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ScriptContextFull[lang={}, execs={}, globals={}, fns={}, types={}, frozen={}]",
            self.env.language,
            self.exec_count,
            self.globals.vars.len(),
            self.functions.len(),
            self.types.len(),
            self.frozen,
        )
    }
}

// ── ContextSerializer ─────────────────────────────────────────────────────────

/// Utility for serialising and deserialising `ScriptContextFull` globals.
pub struct ContextSerializer;

impl ContextSerializer {
    /// Serialise all globals of a context to a JSON string.
    #[must_use]
    pub fn globals_to_json(ctx: &ScriptContextFull) -> String {
        let map: HashMap<String, serde_json::Value> = ctx
            .globals
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();
        serde_json::to_string_pretty(&map).unwrap_or_default()
    }

    /// Deserialise globals from a JSON string into a context.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn globals_from_json(ctx: &mut ScriptContextFull, json: &str) -> Result<(), ScriptError> {
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_str(json).map_err(|e| ScriptError::runtime(e.to_string()))?;
        for (k, v) in map {
            let sv = ScriptValue::from_json(v);
            ctx.set_global(k, sv)?;
        }
        Ok(())
    }

    /// Clone globals from one context into another.
    pub fn clone_globals(src: &ScriptContextFull, dst: &mut ScriptContextFull) -> usize {
        let pairs: Vec<(String, ScriptValue)> = src
            .globals
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let count = pairs.len();
        for (k, v) in pairs {
            let _ = dst.set_global(k, v);
        }
        count
    }
}

// ── ContextDiff ───────────────────────────────────────────────────────────────

/// Represents the difference between two `ScriptContextFull` global scopes.
#[derive(Debug, Clone, Default)]
pub struct ContextDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

impl ContextDiff {
    /// Compute the diff between two contexts' globals.
    #[must_use]
    pub fn compute(before: &ScriptContextFull, after: &ScriptContextFull) -> Self {
        let before_names: std::collections::HashSet<&str> =
            before.globals.vars.keys().map(String::as_str).collect();
        let after_names: std::collections::HashSet<&str> =
            after.globals.vars.keys().map(String::as_str).collect();

        let added: Vec<String> = after_names
            .difference(&before_names)
            .map(std::string::ToString::to_string)
            .collect();
        let removed: Vec<String> = before_names
            .difference(&after_names)
            .map(std::string::ToString::to_string)
            .collect();
        let changed: Vec<String> = before_names
            .intersection(&after_names)
            .filter(|&&k| before.globals.vars.get(k) != after.globals.vars.get(k))
            .map(std::string::ToString::to_string)
            .collect();

        Self {
            added,
            removed,
            changed,
        }
    }

    /// Total number of changes.
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }

    /// Return `true` if there are no differences.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.change_count() == 0
    }
}

// ── ContextPool ───────────────────────────────────────────────────────────────

/// A pool of `ScriptContextFull` instances for multi-session scripting.
#[derive(Debug, Default)]
pub struct ContextPool {
    contexts: HashMap<String, ScriptContextFull>,
    max_size: usize,
}

impl ContextPool {
    /// Create a new pool.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            contexts: HashMap::new(),
            max_size: max_size.max(1),
        }
    }

    /// Acquire a context by ID, creating it if necessary.
    pub fn acquire(&mut self, id: impl Into<String>) -> &mut ScriptContextFull {
        let id = id.into();
        self.contexts
            .entry(id)
            .or_insert_with(|| ScriptContextFull::new(ScriptEnvironment::default()))
    }

    /// Release (remove) a context.
    pub fn release(&mut self, id: &str) -> bool {
        self.contexts.remove(id).is_some()
    }

    /// Number of active contexts.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.contexts.len()
    }

    /// Return `true` if the pool is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.contexts.len() >= self.max_size
    }

    /// Clear all contexts.
    pub fn clear_all(&mut self) {
        self.contexts.clear();
    }

    /// Return all context IDs.
    #[must_use]
    pub fn ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.contexts.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }
}

// ── ContextSnapshot ───────────────────────────────────────────────────────────

/// A snapshot of a `ScriptContextFull`'s globals and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// Snapshotted global variables (serialisable values only).
    pub globals: HashMap<String, serde_json::Value>,
    /// Metadata.
    pub metadata: HashMap<String, String>,
    /// Execution count at snapshot time.
    pub exec_count: u64,
    /// Whether the context was frozen.
    pub frozen: bool,
    /// Language.
    pub language: String,
    /// Snapshot timestamp.
    pub timestamp: u64,
}

impl ContextSnapshot {
    /// Create a snapshot from a `ScriptContextFull`.
    #[must_use]
    pub fn from_ctx(ctx: &ScriptContextFull) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Serialise only the JSON-able globals.
        let globals: HashMap<String, serde_json::Value> = ctx
            .globals
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();
        Self {
            globals,
            metadata: ctx
                .globals
                .vars
                .iter()
                .filter_map(|(k, _)| {
                    ctx.globals
                        .get(k)
                        .and_then(|v| v.as_string().map(|s| (k.clone(), s.to_string())))
                })
                .collect(),
            exec_count: ctx.exec_count,
            frozen: ctx.frozen,
            language: ctx.env.language.clone(),
            timestamp: now,
        }
    }

    /// Number of snapshotted globals.
    #[must_use]
    pub fn global_count(&self) -> usize {
        self.globals.len()
    }
}

// ── ContextMetrics ────────────────────────────────────────────────────────────

/// Accumulated metrics for a `ScriptContextFull`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextMetrics {
    pub total_execs: u64,
    pub total_output_lines: u64,
    pub total_error_lines: u64,
    pub functions_registered: u64,
    pub types_registered: u64,
    pub hooks_fired: u64,
    pub globals_set: u64,
}

impl ContextMetrics {
    /// Create from a context.
    #[must_use]
    pub fn from_ctx(ctx: &ScriptContextFull) -> Self {
        Self {
            total_execs: ctx.exec_count,
            total_output_lines: ctx.output.len() as u64,
            total_error_lines: ctx.errors.len() as u64,
            functions_registered: ctx.functions.len() as u64,
            types_registered: ctx.types.len() as u64,
            hooks_fired: 0,
            globals_set: ctx.globals.vars.len() as u64,
        }
    }

    /// Return `true` if there are any errors.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        self.total_error_lines > 0
    }

    /// Error rate (errors / `total_execs`).
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.total_execs == 0 {
            0.0
        } else {
            self.total_error_lines as f64 / self.total_execs as f64
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ScriptContextFull {
        let mut ctx = ScriptContextFull::default();
        ctx.register_builtins();
        ctx
    }

    // ── TypeInfo / TypeRegistry ──────────────────────────────────────────────

    #[test]
    fn test_type_info_struct() {
        let t = TypeInfo::struct_type("Point", vec!["x".into(), "y".into()]);
        assert_eq!(t.kind, "struct");
        assert!(t.has_field("x"));
        assert!(!t.has_field("z"));
    }

    #[test]
    fn test_type_info_enum() {
        let t = TypeInfo::enum_type("Color", vec!["Red".into(), "Green".into(), "Blue".into()]);
        assert_eq!(t.kind, "enum");
        assert!(t.variants.contains(&"Red".to_string()));
    }

    #[test]
    fn test_type_registry_register_and_get() {
        let mut reg = TypeRegistry::new();
        reg.register(TypeInfo::struct_type("Point", vec![]));
        assert!(reg.contains("Point"));
        assert!(reg.get("Point").is_some());
    }

    #[test]
    fn test_type_registry_remove() {
        let mut reg = TypeRegistry::new();
        reg.register(TypeInfo::struct_type("X", vec![]));
        assert!(reg.remove("X"));
        assert!(!reg.contains("X"));
    }

    #[test]
    fn test_type_registry_type_names() {
        let mut reg = TypeRegistry::new();
        reg.register(TypeInfo::struct_type("Alpha", vec![]));
        reg.register(TypeInfo::struct_type("Beta", vec![]));
        let names = reg.type_names();
        assert!(names.contains(&"Alpha"));
        assert!(names.contains(&"Beta"));
    }

    // ── FunctionSignature ────────────────────────────────────────────────────

    #[test]
    fn test_function_signature_arity() {
        let sig = FunctionSignature::new("test", vec!["a".into(), "b".into()]);
        assert_eq!(sig.arity(), 2);
        assert!(sig.accepts_arity(2));
        assert!(!sig.accepts_arity(1));
    }

    #[test]
    fn test_function_signature_variadic() {
        let sig = FunctionSignature {
            name: "va".into(),
            params: vec!["x".into()],
            return_type: "any".into(),
            doc: String::new(),
            variadic: true,
            module: None,
        };
        assert!(sig.accepts_arity(1));
        assert!(sig.accepts_arity(5));
        assert!(!sig.accepts_arity(0));
    }

    // ── FunctionRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_function_registry_call() {
        let reg = FunctionRegistry::new();
        let sig = FunctionSignature::new("double", vec!["n".into()]);
        reg.register(sig, |args| {
            let n = args[0].as_int().unwrap_or(0);
            Ok(ScriptValue::Int(n * 2))
        });
        let result = reg.call("double", &[ScriptValue::Int(5)]).unwrap();
        assert_eq!(result, ScriptValue::Int(10));
    }

    #[test]
    fn test_function_registry_not_found() {
        let reg = FunctionRegistry::new();
        assert!(matches!(
            reg.call("missing", &[]),
            Err(ScriptError::FunctionNotFound(_))
        ));
    }

    #[test]
    fn test_function_registry_arity_mismatch() {
        let reg = FunctionRegistry::new();
        let sig = FunctionSignature::new("fn", vec!["a".into()]);
        reg.register(sig, |_| Ok(ScriptValue::Null));
        assert!(matches!(
            reg.call("fn", &[]),
            Err(ScriptError::ArityMismatch { .. })
        ));
    }

    #[test]
    fn test_function_registry_remove() {
        let reg = FunctionRegistry::new();
        let sig = FunctionSignature::new("x", vec![]);
        reg.register(sig, |_| Ok(ScriptValue::Null));
        assert!(reg.contains("x"));
        assert!(reg.remove("x"));
        assert!(!reg.contains("x"));
    }

    #[test]
    fn test_function_registry_names() {
        let reg = FunctionRegistry::new();
        reg.register(FunctionSignature::new("b", vec![]), |_| {
            Ok(ScriptValue::Null)
        });
        reg.register(FunctionSignature::new("a", vec![]), |_| {
            Ok(ScriptValue::Null)
        });
        let names = reg.function_names();
        assert_eq!(names[0], "a");
    }

    // ── GlobalScope ──────────────────────────────────────────────────────────

    #[test]
    fn test_global_scope_set_get() {
        let mut scope = GlobalScope::new();
        scope.set("x", ScriptValue::Int(42)).unwrap();
        assert_eq!(scope.get("x"), Some(&ScriptValue::Int(42)));
    }

    #[test]
    fn test_global_scope_constant() {
        let mut scope = GlobalScope::new();
        scope.define_const("PI", ScriptValue::Float(std::f64::consts::PI));
        assert!(scope.is_const("PI"));
        assert!(scope.set("PI", ScriptValue::Float(0.0)).is_err());
    }

    #[test]
    fn test_global_scope_no_new_globals() {
        let mut scope = GlobalScope::new();
        scope.allow_new_globals = false;
        assert!(scope.set("new_var", ScriptValue::Bool(true)).is_err());
    }

    #[test]
    fn test_global_scope_clear_vars() {
        let mut scope = GlobalScope::new();
        scope.define_const("CONST", ScriptValue::Int(1));
        scope.set("var", ScriptValue::Int(2)).unwrap();
        scope.clear_vars();
        assert!(scope.get("CONST").is_some());
        assert!(scope.get("var").is_none());
    }

    #[test]
    fn test_global_scope_remove() {
        let mut scope = GlobalScope::new();
        scope.set("x", ScriptValue::Int(1)).unwrap();
        assert!(scope.remove("x"));
        assert!(scope.get("x").is_none());
    }

    // ── EventHooks ───────────────────────────────────────────────────────────

    #[test]
    fn test_event_hooks_emit() {
        let hooks = EventHooks::new();
        let fired = Arc::new(std::sync::Mutex::new(0u32));
        let fired2 = fired.clone();
        hooks.register(EventHook::new("test", 0, move |_| {
            *fired2.lock().unwrap() += 1;
            Ok(())
        }));
        let count = hooks.emit("test", &ScriptValue::Null);
        assert_eq!(count, 1);
        assert_eq!(*fired.lock().unwrap(), 1);
    }

    #[test]
    fn test_event_hooks_once() {
        let hooks = EventHooks::new();
        let counter = Arc::new(std::sync::Mutex::new(0u32));
        let counter2 = counter.clone();
        hooks.register(EventHook::once("ping", 0, move |_| {
            *counter2.lock().unwrap() += 1;
            Ok(())
        }));
        hooks.emit("ping", &ScriptValue::Null);
        hooks.emit("ping", &ScriptValue::Null);
        // Once-hook should only fire once.
        assert_eq!(*counter.lock().unwrap(), 1);
        assert_eq!(hooks.len(), 0); // Consumed hooks are evicted.
    }

    #[test]
    fn test_event_hooks_clear_event() {
        let hooks = EventHooks::new();
        hooks.register(EventHook::new("e", 0, |_| Ok(())));
        hooks.register(EventHook::new("e", 0, |_| Ok(())));
        assert_eq!(hooks.clear_event("e"), 2);
        assert_eq!(hooks.len(), 0);
    }

    #[test]
    fn test_event_hooks_active_events() {
        let hooks = EventHooks::new();
        hooks.register(EventHook::new("alpha", 0, |_| Ok(())));
        hooks.register(EventHook::new("beta", 0, |_| Ok(())));
        let events = hooks.active_events();
        assert!(events.contains(&"alpha".to_string()));
        assert!(events.contains(&"beta".to_string()));
    }

    // ── ScriptEnvironment ────────────────────────────────────────────────────

    #[test]
    fn test_script_environment_defaults() {
        let env = ScriptEnvironment::new("lua");
        assert_eq!(env.language, "lua");
        assert!(env.sandbox);
    }

    #[test]
    fn test_script_environment_no_sandbox() {
        let env = ScriptEnvironment::new("python").without_sandbox();
        assert!(!env.sandbox);
    }

    #[test]
    fn test_script_environment_include() {
        let env = ScriptEnvironment::new("rhai").with_include("/scripts/lib");
        assert!(env.include_paths.contains(&"/scripts/lib".to_string()));
    }

    // ── ScriptContextFull ────────────────────────────────────────────────────

    #[test]
    fn test_context_full_register_builtins() {
        let ctx = make_ctx();
        assert!(ctx.functions.contains("println"));
        assert!(ctx.functions.contains("format_hex"));
        assert!(ctx.types.contains("Address"));
    }

    #[test]
    fn test_context_full_set_global() {
        let mut ctx = make_ctx();
        ctx.set_global("x", ScriptValue::Int(42)).unwrap();
        assert_eq!(ctx.get_global("x"), Some(&ScriptValue::Int(42)));
    }

    #[test]
    fn test_context_full_frozen_no_set() {
        let mut ctx = make_ctx();
        ctx.freeze();
        assert!(ctx.set_global("x", ScriptValue::Int(1)).is_err());
    }

    #[test]
    fn test_context_full_write_output() {
        let mut ctx = make_ctx();
        ctx.write_output("hello");
        ctx.write_output("world");
        assert_eq!(ctx.output_joined(), "hello\nworld");
    }

    #[test]
    fn test_context_full_write_error() {
        let mut ctx = make_ctx();
        ctx.write_error("error occurred");
        assert!(ctx.errors_joined().contains("error occurred"));
    }

    #[test]
    fn test_context_full_exec_count() {
        let mut ctx = make_ctx();
        assert_eq!(ctx.exec_count, 0);
        ctx.begin_exec();
        ctx.begin_exec();
        assert_eq!(ctx.exec_count, 2);
    }

    #[test]
    fn test_context_full_reset_buffers() {
        let mut ctx = make_ctx();
        ctx.write_output("line");
        ctx.write_error("err");
        ctx.reset_buffers();
        assert!(ctx.output.is_empty());
        assert!(ctx.errors.is_empty());
    }

    #[test]
    fn test_context_full_summary() {
        let ctx = make_ctx();
        let s = ctx.summary();
        assert!(s.contains("ScriptContextFull"));
        assert!(s.contains("rhai"));
    }

    #[test]
    fn test_context_full_emit_event() {
        let ctx = make_ctx();
        ctx.hooks
            .register(EventHook::new("analysis_done", 0, |_| Ok(())));
        let count = ctx.emit_event("analysis_done", &ScriptValue::Null);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_context_full_call_builtin() {
        let ctx = make_ctx();
        let result = ctx
            .functions
            .call("format_hex", &[ScriptValue::Int(0x1000)])
            .unwrap();
        assert_eq!(result, ScriptValue::String("0x1000".into()));
    }

    #[test]
    fn test_context_full_debug() {
        let ctx = make_ctx();
        let s = format!("{ctx:?}");
        assert!(s.contains("ScriptContextFull"));
    }

    // ── ContextPool ──────────────────────────────────────────────────────────

    #[test]
    fn test_pool_acquire_creates_context() {
        let mut pool = ContextPool::new(5);
        let ctx = pool.acquire("session-1");
        ctx.write_output("hello");
        assert_eq!(pool.active_count(), 1);
    }

    #[test]
    fn test_pool_release() {
        let mut pool = ContextPool::new(5);
        pool.acquire("s1");
        assert!(pool.release("s1"));
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_pool_is_full() {
        let mut pool = ContextPool::new(2);
        pool.acquire("a");
        pool.acquire("b");
        assert!(pool.is_full());
    }

    #[test]
    fn test_pool_ids_sorted() {
        let mut pool = ContextPool::new(10);
        pool.acquire("beta");
        pool.acquire("alpha");
        let ids = pool.ids();
        assert_eq!(ids[0], "alpha");
    }

    #[test]
    fn test_pool_clear_all() {
        let mut pool = ContextPool::new(5);
        pool.acquire("a");
        pool.acquire("b");
        pool.clear_all();
        assert_eq!(pool.active_count(), 0);
    }

    // ── ContextSnapshot ──────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_from_ctx() {
        let mut ctx = make_ctx();
        ctx.set_global("x", ScriptValue::Int(42)).unwrap();
        ctx.begin_exec();
        let snap = ContextSnapshot::from_ctx(&ctx);
        assert_eq!(snap.exec_count, 1);
        assert_eq!(snap.language, "rhai");
    }

    #[test]
    fn test_snapshot_global_count() {
        let mut ctx = make_ctx();
        ctx.set_global("a", ScriptValue::Int(1)).unwrap();
        ctx.set_global("b", ScriptValue::Int(2)).unwrap();
        let snap = ContextSnapshot::from_ctx(&ctx);
        // Globals includes the ones we set plus any builtins.
        assert!(snap.global_count() >= 2);
    }

    // ── ContextMetrics ───────────────────────────────────────────────────────

    #[test]
    fn test_metrics_from_ctx() {
        let mut ctx = make_ctx();
        ctx.begin_exec();
        ctx.write_output("line1");
        ctx.write_error("err1");
        let metrics = ContextMetrics::from_ctx(&ctx);
        assert_eq!(metrics.total_execs, 1);
        assert_eq!(metrics.total_output_lines, 1);
        assert_eq!(metrics.total_error_lines, 1);
    }

    #[test]
    fn test_metrics_has_errors() {
        let mut ctx = make_ctx();
        let metrics = ContextMetrics::from_ctx(&ctx);
        assert!(!metrics.has_errors());
        ctx.write_error("oops");
        let metrics2 = ContextMetrics::from_ctx(&ctx);
        assert!(metrics2.has_errors());
    }

    #[test]
    fn test_metrics_error_rate() {
        let mut ctx = make_ctx();
        ctx.begin_exec();
        ctx.begin_exec();
        ctx.write_error("e1");
        let metrics = ContextMetrics::from_ctx(&ctx);
        assert!(metrics.error_rate() > 0.0);
    }

    #[test]
    fn test_metrics_no_execs_zero_error_rate() {
        let ctx = make_ctx();
        let metrics = ContextMetrics::from_ctx(&ctx);
        assert_eq!(metrics.error_rate(), 0.0);
    }

    // ── ContextSerializer ────────────────────────────────────────────────────

    #[test]
    fn test_serializer_globals_to_json() {
        let mut ctx = make_ctx();
        ctx.set_global("x", ScriptValue::Int(42)).unwrap();
        let json = ContextSerializer::globals_to_json(&ctx);
        assert!(json.contains("\"x\""));
    }

    #[test]
    fn test_serializer_globals_from_json() {
        let mut ctx = make_ctx();
        let json = r#"{"y": 99}"#;
        ContextSerializer::globals_from_json(&mut ctx, json).unwrap();
        assert!(ctx.get_global("y").is_some());
    }

    #[test]
    fn test_serializer_clone_globals() {
        let mut src = make_ctx();
        src.set_global("a", ScriptValue::Bool(true)).unwrap();
        let mut dst = ScriptContextFull::default();
        let count = ContextSerializer::clone_globals(&src, &mut dst);
        assert!(count >= 1);
        assert!(dst.get_global("a").is_some());
    }

    // ── ContextDiff ──────────────────────────────────────────────────────────

    #[test]
    fn test_diff_no_changes() {
        let ctx = make_ctx();
        let diff = ContextDiff::compute(&ctx, &ctx);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_added() {
        let before = make_ctx();
        let mut after = make_ctx();
        after.set_global("new_var", ScriptValue::Int(1)).unwrap();
        let diff = ContextDiff::compute(&before, &after);
        assert!(diff.added.contains(&"new_var".to_string()));
    }

    #[test]
    fn test_diff_removed() {
        let mut before = make_ctx();
        before.set_global("gone", ScriptValue::Int(1)).unwrap();
        let after = make_ctx();
        let diff = ContextDiff::compute(&before, &after);
        assert!(diff.removed.contains(&"gone".to_string()));
    }

    #[test]
    fn test_diff_changed() {
        let mut before = make_ctx();
        before.set_global("x", ScriptValue::Int(1)).unwrap();
        let mut after = make_ctx();
        after.set_global("x", ScriptValue::Int(2)).unwrap();
        let diff = ContextDiff::compute(&before, &after);
        assert!(diff.changed.contains(&"x".to_string()));
    }

    #[test]
    fn test_diff_change_count() {
        let before = make_ctx();
        let mut after = make_ctx();
        after.set_global("added1", ScriptValue::Int(1)).unwrap();
        after.set_global("added2", ScriptValue::Int(2)).unwrap();
        let diff = ContextDiff::compute(&before, &after);
        assert_eq!(
            diff.change_count(),
            diff.added.len() + diff.removed.len() + diff.changed.len()
        );
    }
}
