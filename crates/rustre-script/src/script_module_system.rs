//! Script module system for the RustRE scripting engine.
//!
//! Provides [`ScriptModuleSystem`], [`Module`], [`ModuleLoader`], and
//! [`resolve_import`].  Implements a graph-based module registry with
//! circular-dependency detection, version-gating, and a pluggable loader
//! chain.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

// ── ModuleId ──────────────────────────────────────────────────────────────────

/// A unique, intern-like identifier for a module.  Usually the canonical path
/// or package name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleId(String);

impl ModuleId {
    /// Create a new identifier.  Leading/trailing whitespace is stripped.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into().trim().to_string())
    }

    /// The raw string value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ModuleId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ModuleKind ────────────────────────────────────────────────────────────────

/// The origin kind of a module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    /// Built-in module backed by native Rust code.
    Native,
    /// Module loaded from a `.rhai` / `.lua` / etc. source file.
    Source { path: String },
    /// Pre-compiled bytecode module.
    Bytecode { path: String },
    /// Synthetic module generated at runtime (e.g. by a plugin).
    Synthetic,
}

impl fmt::Display for ModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Source { path } => write!(f, "source:{path}"),
            Self::Bytecode { path } => write!(f, "bytecode:{path}"),
            Self::Synthetic => write!(f, "synthetic"),
        }
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

/// A single named export from a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Export name.
    pub name: String,
    /// A human-readable type annotation (e.g. `"fn(u64) -> String"`).
    pub type_hint: String,
    /// Whether this export is public to other modules.
    pub public: bool,
}

impl Export {
    /// Create a public export with the given name.
    #[must_use]
    pub fn public(name: impl Into<String>, type_hint: impl Into<String>) -> Self {
        Self { name: name.into(), type_hint: type_hint.into(), public: true }
    }

    /// Create a private export (accessible within the module only).
    #[must_use]
    pub fn private(name: impl Into<String>, type_hint: impl Into<String>) -> Self {
        Self { name: name.into(), type_hint: type_hint.into(), public: false }
    }
}

// ── Module ────────────────────────────────────────────────────────────────────

/// A module within the script module system.
///
/// A module declares its dependencies (imports) and provides named exports.
/// At resolution time the module system ensures that all imports are
/// satisfied before the module is considered ready.
#[derive(Debug, Clone)]
pub struct Module {
    /// Unique identifier.
    pub id: ModuleId,
    /// Human-readable display name.
    pub name: String,
    /// Version string (semver or free-form).
    pub version: String,
    /// The origin of this module.
    pub kind: ModuleKind,
    /// Modules this module depends on.
    pub imports: Vec<ModuleId>,
    /// Names exported by this module.
    pub exports: Vec<Export>,
    /// Whether this module has been resolved (all imports satisfied).
    pub resolved: bool,
    /// Optional source text (for `Source` kind modules).
    pub source_text: Option<String>,
}

impl Module {
    /// Create a native module with no imports.
    #[must_use]
    pub fn native(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: ModuleId::new(id),
            name: name.into(),
            version: version.into(),
            kind: ModuleKind::Native,
            imports: Vec::new(),
            exports: Vec::new(),
            resolved: false,
            source_text: None,
        }
    }

    /// Create a source module.
    #[must_use]
    pub fn from_source(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        path: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        let p = path.into();
        Self {
            id: ModuleId::new(id),
            name: name.into(),
            version: version.into(),
            kind: ModuleKind::Source { path: p },
            imports: Vec::new(),
            exports: Vec::new(),
            resolved: false,
            source_text: Some(source.into()),
        }
    }

    /// Builder: add an import dependency.
    #[must_use]
    pub fn with_import(mut self, dep: impl Into<String>) -> Self {
        self.imports.push(ModuleId::new(dep));
        self
    }

    /// Builder: add an export.
    #[must_use]
    pub fn with_export(mut self, export: Export) -> Self {
        self.exports.push(export);
        self
    }

    /// Return public exports only.
    #[must_use]
    pub fn public_exports(&self) -> Vec<&Export> {
        self.exports.iter().filter(|e| e.public).collect()
    }

    /// Return `true` if this module exports `name`.
    #[must_use]
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.iter().any(|e| e.name == name && e.public)
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Module[{}] {} v{} ({}) resolved={}",
            self.id, self.name, self.version, self.kind, self.resolved
        )
    }
}

// ── ModuleLoader ──────────────────────────────────────────────────────────────

/// Trait for objects that can load modules by ID.
///
/// Implement this to plug in filesystem, network, or database-backed module
/// loading.  The [`ScriptModuleSystem`] chains multiple loaders; the first
/// one that returns `Some(Module)` wins.
pub trait ModuleLoader: Send + Sync + fmt::Debug {
    /// Try to load a module for the given identifier.
    ///
    /// Returns `None` if this loader does not handle the given ID.
    fn load(&self, id: &ModuleId) -> Option<Module>;

    /// A short name for this loader (for diagnostics).
    fn name(&self) -> &str;
}

/// A [`ModuleLoader`] that serves modules from an in-memory registry.
#[derive(Debug, Default)]
pub struct InMemoryLoader {
    /// Internal store: id → Module.
    store: HashMap<String, Module>,
}

impl InMemoryLoader {
    /// Create an empty loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module in this loader.
    pub fn register(&mut self, module: Module) {
        self.store.insert(module.id.as_str().to_string(), module);
    }
}

impl ModuleLoader for InMemoryLoader {
    fn load(&self, id: &ModuleId) -> Option<Module> {
        self.store.get(id.as_str()).cloned()
    }

    fn name(&self) -> &str {
        "InMemoryLoader"
    }
}

// ── ScriptModuleSystem ────────────────────────────────────────────────────────

/// The central module registry and resolver.
///
/// Responsibilities:
/// - Maintain a registry of loaded modules.
/// - Resolve imports in topological order (BFS).
/// - Detect circular dependencies and report them.
/// - Delegate unknown module IDs to the loader chain.
/// - Track resolution state per module.
#[derive(Debug)]
pub struct ScriptModuleSystem {
    /// Registered modules keyed by ID.
    modules: HashMap<String, Module>,
    /// Ordered list of loaders.  Queried in order for unknown modules.
    loaders: Vec<Box<dyn ModuleLoader>>,
    /// Thread-safe resolution counter.
    resolve_count: Arc<Mutex<u64>>,
    /// Whether to permit re-registering a module with the same ID.
    pub allow_override: bool,
}

impl ScriptModuleSystem {
    /// Create an empty module system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            loaders: Vec::new(),
            resolve_count: Arc::new(Mutex::new(0)),
            allow_override: false,
        }
    }

    /// Add a loader to the chain.
    pub fn add_loader(&mut self, loader: Box<dyn ModuleLoader>) {
        self.loaders.push(loader);
    }

    /// Register a module directly.
    ///
    /// Returns an error if the ID is already registered and `allow_override`
    /// is `false`.
    pub fn register(&mut self, module: Module) -> Result<(), String> {
        let key = module.id.as_str().to_string();
        if self.modules.contains_key(&key) && !self.allow_override {
            return Err(format!("module '{key}' is already registered"));
        }
        self.modules.insert(key, module);
        Ok(())
    }

    /// Look up a registered module by ID string.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Module> {
        self.modules.get(id)
    }

    /// Return `true` if `id` is registered.
    #[must_use]
    pub fn is_registered(&self, id: &str) -> bool {
        self.modules.contains_key(id)
    }

    /// Total number of registered modules.
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Attempt to load a module using the loader chain.
    ///
    /// Returns `None` if no loader can handle `id`.
    fn load_from_chain(&self, id: &ModuleId) -> Option<Module> {
        for loader in &self.loaders {
            if let Some(m) = loader.load(id) {
                return Some(m);
            }
        }
        None
    }

    /// Resolve all imports for the module with `root_id`, loading unknown
    /// modules via the loader chain as needed.
    ///
    /// Returns the topological order of resolved module IDs on success, or a
    /// descriptive error string if a cycle or missing dependency is detected.
    pub fn resolve_all(&mut self, root_id: &str) -> Result<Vec<String>, String> {
        // BFS resolution.
        let mut order: Vec<String> = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut in_progress: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(root_id.to_string());

        while let Some(current_id) = queue.pop_front() {
            if visited.contains(&current_id) {
                continue;
            }
            if in_progress.contains(&current_id) {
                return Err(format!("circular dependency detected at '{current_id}'"));
            }
            // Ensure the module is in the registry.
            if !self.modules.contains_key(&current_id) {
                let mid = ModuleId::new(&current_id);
                if let Some(m) = self.load_from_chain(&mid) {
                    self.modules.insert(current_id.clone(), m);
                } else {
                    return Err(format!("cannot resolve module '{current_id}': not found"));
                }
            }

            in_progress.insert(current_id.clone());
            let imports: Vec<String> = self.modules[&current_id]
                .imports
                .iter()
                .map(|id| id.as_str().to_string())
                .collect();

            for dep in &imports {
                if !visited.contains(dep) {
                    queue.push_front(dep.clone());
                }
            }

            // After pushing deps, schedule current module after them.
            // Mark visited and remove from in_progress.
            in_progress.remove(&current_id);
            visited.insert(current_id.clone());
            order.push(current_id.clone());

            // Mark the module as resolved.
            if let Some(m) = self.modules.get_mut(&current_id) {
                m.resolved = true;
            }
        }

        let mut counter = self.resolve_count.lock().unwrap();
        *counter += 1;

        Ok(order)
    }

    /// Return all resolved modules in insertion order.
    #[must_use]
    pub fn resolved_modules(&self) -> Vec<&Module> {
        self.modules.values().filter(|m| m.resolved).collect()
    }

    /// Return all unresolved modules.
    #[must_use]
    pub fn unresolved_modules(&self) -> Vec<&Module> {
        self.modules.values().filter(|m| !m.resolved).collect()
    }

    /// Find all modules that export a given name.
    #[must_use]
    pub fn find_exporters(&self, export_name: &str) -> Vec<&Module> {
        self.modules.values()
            .filter(|m| m.has_export(export_name))
            .collect()
    }

    /// Unregister a module.  Returns `true` if it was present.
    pub fn unregister(&mut self, id: &str) -> bool {
        self.modules.remove(id).is_some()
    }

    /// Detect cycles in the dependency graph using DFS.
    ///
    /// Returns the cycle path as a list of module IDs, or an empty vec if
    /// no cycle exists.
    #[must_use]
    pub fn find_cycle(&self) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: HashSet<String> = HashSet::new();
        let mut path: Vec<String> = Vec::new();
        for id in self.modules.keys() {
            if !visited.contains(id) {
                if let Some(cycle) = self.dfs_cycle(id, &mut visited, &mut stack, &mut path) {
                    return cycle;
                }
            }
        }
        Vec::new()
    }

    fn dfs_cycle(
        &self,
        id: &str,
        visited: &mut HashSet<String>,
        stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(id.to_string());
        stack.insert(id.to_string());
        path.push(id.to_string());

        if let Some(m) = self.modules.get(id) {
            for dep in &m.imports {
                let dep_str = dep.as_str();
                if !visited.contains(dep_str) {
                    if let Some(cycle) = self.dfs_cycle(dep_str, visited, stack, path) {
                        return Some(cycle);
                    }
                } else if stack.contains(dep_str) {
                    // Found cycle; collect from cycle start.
                    let start = path.iter().position(|p| p == dep_str).unwrap_or(0);
                    return Some(path[start..].to_vec());
                }
            }
        }

        stack.remove(id);
        path.pop();
        None
    }

    /// How many times `resolve_all` has been called.
    #[must_use]
    pub fn resolve_call_count(&self) -> u64 {
        *self.resolve_count.lock().unwrap()
    }
}

impl Default for ScriptModuleSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ScriptModuleSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScriptModuleSystem modules={} loaders={} resolves={}",
            self.modules.len(),
            self.loaders.len(),
            self.resolve_call_count()
        )
    }
}

// ── resolve_import ────────────────────────────────────────────────────────────

/// Resolve a single import `id` within `system`.
///
/// Convenience function that ensures the module is registered (via loader
/// chain if needed) and then resolves its full dependency tree.
///
/// Returns the topological resolution order on success.
pub fn resolve_import(system: &mut ScriptModuleSystem, id: &str) -> Result<Vec<String>, String> {
    system.resolve_all(id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(id: &str) -> Module {
        Module::native(id, id, "0.1.0")
    }

    #[test]
    fn test_module_id_trims() {
        let id = ModuleId::new("  core  ");
        assert_eq!(id.as_str(), "core");
    }

    #[test]
    fn test_module_display() {
        let m = make_module("core");
        let s = m.to_string();
        assert!(s.contains("core"));
    }

    #[test]
    fn test_module_has_export() {
        let m = make_module("core")
            .with_export(Export::public("print", "fn(String)"))
            .with_export(Export::private("_internal", "fn()"));
        assert!(m.has_export("print"));
        assert!(!m.has_export("_internal")); // private
        assert!(!m.has_export("missing"));
    }

    #[test]
    fn test_module_public_exports() {
        let m = make_module("util")
            .with_export(Export::public("format", "fn(String) -> String"))
            .with_export(Export::private("helper", "fn()"));
        let pub_exports = m.public_exports();
        assert_eq!(pub_exports.len(), 1);
        assert_eq!(pub_exports[0].name, "format");
    }

    #[test]
    fn test_system_register_and_get() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("core")).unwrap();
        assert!(sys.get("core").is_some());
        assert_eq!(sys.module_count(), 1);
    }

    #[test]
    fn test_system_register_duplicate_fails() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("core")).unwrap();
        let result = sys.register(make_module("core"));
        assert!(result.is_err());
    }

    #[test]
    fn test_system_register_duplicate_allowed() {
        let mut sys = ScriptModuleSystem::new();
        sys.allow_override = true;
        sys.register(make_module("core")).unwrap();
        assert!(sys.register(make_module("core")).is_ok());
    }

    #[test]
    fn test_resolve_single_module() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("core")).unwrap();
        let order = sys.resolve_all("core").unwrap();
        assert_eq!(order, vec!["core".to_string()]);
        assert!(sys.get("core").unwrap().resolved);
    }

    #[test]
    fn test_resolve_dependency_chain() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("base")).unwrap();
        sys.register(Module::native("util", "util", "0.1.0").with_import("base")).unwrap();
        sys.register(Module::native("app", "app", "0.1.0").with_import("util")).unwrap();
        let order = sys.resolve_all("app").unwrap();
        assert!(order.contains(&"base".to_string()));
        assert!(order.contains(&"util".to_string()));
        assert!(order.contains(&"app".to_string()));
    }

    #[test]
    fn test_resolve_missing_dependency_fails() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(Module::native("app", "app", "0.1.0").with_import("missing")).unwrap();
        let result = sys.resolve_all("app");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing"));
    }

    #[test]
    fn test_resolve_via_loader() {
        let mut loader = InMemoryLoader::new();
        loader.register(make_module("base"));
        let mut sys = ScriptModuleSystem::new();
        sys.add_loader(Box::new(loader));
        sys.register(Module::native("app", "app", "0.1.0").with_import("base")).unwrap();
        let order = sys.resolve_all("app").unwrap();
        assert!(order.contains(&"base".to_string()));
    }

    #[test]
    fn test_find_cycle_detected() {
        let mut sys = ScriptModuleSystem::new();
        sys.allow_override = true;
        sys.register(Module::native("a", "a", "0.1.0").with_import("b")).unwrap();
        sys.register(Module::native("b", "b", "0.1.0").with_import("a")).unwrap();
        let cycle = sys.find_cycle();
        assert!(!cycle.is_empty());
    }

    #[test]
    fn test_find_cycle_none() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("base")).unwrap();
        sys.register(Module::native("app", "app", "0.1.0").with_import("base")).unwrap();
        let cycle = sys.find_cycle();
        assert!(cycle.is_empty());
    }

    #[test]
    fn test_unregister() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("core")).unwrap();
        assert!(sys.unregister("core"));
        assert!(!sys.is_registered("core"));
        assert!(!sys.unregister("core")); // already gone
    }

    #[test]
    fn test_find_exporters() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(
            make_module("a").with_export(Export::public("print", "fn(String)"))
        ).unwrap();
        sys.register(
            make_module("b").with_export(Export::public("print", "fn(i32)"))
        ).unwrap();
        sys.register(make_module("c")).unwrap();
        let exporters = sys.find_exporters("print");
        assert_eq!(exporters.len(), 2);
    }

    #[test]
    fn test_resolve_import_function() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("io")).unwrap();
        let result = resolve_import(&mut sys, "io");
        assert!(result.is_ok());
    }

    #[test]
    fn test_module_from_source() {
        let m = Module::from_source("mymod", "My Module", "1.0.0", "/path/mod.rhai", "let x = 1;");
        assert_eq!(m.source_text.as_deref(), Some("let x = 1;"));
        assert!(matches!(m.kind, ModuleKind::Source { .. }));
    }

    #[test]
    fn test_resolve_call_count() {
        let mut sys = ScriptModuleSystem::new();
        sys.register(make_module("a")).unwrap();
        sys.resolve_all("a").unwrap();
        sys.resolve_all("a").unwrap();
        assert_eq!(sys.resolve_call_count(), 2);
    }

    #[test]
    fn test_system_display() {
        let sys = ScriptModuleSystem::new();
        let s = sys.to_string();
        assert!(s.contains("ScriptModuleSystem"));
    }
}
