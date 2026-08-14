//! Plugin registry for the RustRE platform.
//!
//! Provides [`PluginRegistry`], [`PluginEntry`], [`PluginHandle`],
//! [`register_plugin()`], and [`unload_plugin()`] so that third-party
//! extensions can be attached to, and cleanly removed from, the platform at
//! runtime.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// PluginId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a plugin; typically a reverse-DNS string like
/// `"com.example.my-plugin"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginId(String);

impl PluginId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use] 
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for PluginId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for PluginId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of a registered plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is registered and fully operational.
    Active,
    /// Plugin has been requested to stop but has not yet been removed.
    Stopping,
    /// Plugin failed to initialise or encountered a fatal error.
    Faulted(String),
    /// Plugin is registered but not yet started.
    Dormant,
}

impl fmt::Display for PluginStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Stopping => write!(f, "stopping"),
            Self::Faulted(msg) => write!(f, "faulted: {msg}"),
            Self::Dormant => write!(f, "dormant"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptive metadata declared by a plugin at registration time.
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub id: PluginId,
    pub display_name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    /// List of plugin IDs this plugin depends on.
    pub dependencies: Vec<PluginId>,
}

impl PluginMetadata {
    pub fn new(id: impl Into<String>, display_name: impl Into<String>) -> Self {
        let id = PluginId::new(id);
        Self {
            display_name: display_name.into(),
            id,
            version: "0.1.0".to_string(),
            author: String::new(),
            description: String::new(),
            dependencies: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_dependency(mut self, dep: impl Into<PluginId>) -> Self {
        self.dependencies.push(dep.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait that every plugin object must implement.
pub trait Plugin: Any + Send + Sync + fmt::Debug {
    /// Metadata declared by this plugin.
    fn metadata(&self) -> &PluginMetadata;

    /// Called once when the plugin is activated.
    fn on_load(&self) {}

    /// Called once just before the plugin is removed.
    fn on_unload(&self) {}

    /// Returns a reference to the plugin as `Any` for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Human-readable status string (may include version, state, etc.).
    fn status_line(&self) -> String {
        format!("{} v{}", self.metadata().display_name, self.metadata().version)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Internal registry entry coupling a plugin object with its runtime status.
pub struct PluginEntry {
    pub plugin: Arc<dyn Plugin>,
    pub status: PluginStatus,
    pub load_order: u32,
}

impl fmt::Debug for PluginEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PluginEntry {{ id={}, status={}, order={} }}",
            self.plugin.metadata().id,
            self.status,
            self.load_order,
        )
    }
}

impl PluginEntry {
    pub fn new(plugin: Arc<dyn Plugin>, load_order: u32) -> Self {
        Self { plugin, status: PluginStatus::Dormant, load_order }
    }

    pub fn activate(&mut self) {
        self.plugin.on_load();
        self.status = PluginStatus::Active;
    }

    pub fn deactivate(&mut self) {
        self.status = PluginStatus::Stopping;
        self.plugin.on_unload();
    }

    pub fn fault(&mut self, reason: impl Into<String>) {
        self.status = PluginStatus::Faulted(reason.into());
    }

    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.status == PluginStatus::Active
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight, cloneable reference to a loaded plugin.
///
/// Callers use `PluginHandle` to access the plugin object without holding the
/// registry lock for the entire duration of their work.
#[derive(Clone)]
pub struct PluginHandle {
    pub id: PluginId,
    plugin: Arc<dyn Plugin>,
}

impl PluginHandle {
    fn new(id: PluginId, plugin: Arc<dyn Plugin>) -> Self {
        Self { id, plugin }
    }

    /// Borrow the underlying plugin object.
    #[must_use] 
    pub fn plugin(&self) -> &dyn Plugin {
        self.plugin.as_ref()
    }

    /// Try to downcast the plugin to a concrete type `T`.
    #[must_use] 
    pub fn downcast<T: Plugin>(&self) -> Option<&T> {
        self.plugin.as_any().downcast_ref::<T>()
    }

    /// Display name from the plugin's metadata.
    #[must_use] 
    pub fn display_name(&self) -> &str {
        &self.plugin.metadata().display_name
    }

    /// Version string from the plugin's metadata.
    #[must_use] 
    pub fn version(&self) -> &str {
        &self.plugin.metadata().version
    }
}

impl fmt::Debug for PluginHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PluginHandle({})", self.id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A plugin with the same ID is already registered.
    AlreadyRegistered(PluginId),
    /// No plugin with the given ID could be found.
    NotFound(PluginId),
    /// The requested operation is not valid for the plugin's current status.
    InvalidState { id: PluginId, status: String },
    /// A dependency was missing at load time.
    MissingDependency { plugin: PluginId, dependency: PluginId },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRegistered(id) => write!(f, "plugin '{id}' is already registered"),
            Self::NotFound(id) => write!(f, "plugin '{id}' not found"),
            Self::InvalidState { id, status } => {
                write!(f, "plugin '{id}' cannot be operated in state '{status}'")
            }
            Self::MissingDependency { plugin, dependency } => {
                write!(f, "plugin '{plugin}' requires '{dependency}' which is not registered")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe registry that manages the lifecycle of all loaded plugins.
#[derive(Debug)]
pub struct PluginRegistry {
    entries: RwLock<HashMap<PluginId, PluginEntry>>,
    load_counter: Mutex<u32>,
}

impl PluginRegistry {
    /// Create a new, empty registry.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            load_counter: Mutex::new(0),
        }
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    fn next_order(&self) -> u32 {
        let mut guard = self.load_counter.lock().unwrap();
        let v = *guard;
        *guard += 1;
        v
    }

    // ── Registration ───────────────────────────────────────────────────────

    /// Register `plugin` and activate it immediately.
    ///
    /// Checks that all declared dependencies are already present before
    /// calling `on_load()`.
    pub fn register_plugin(
        &self,
        plugin: &Arc<dyn Plugin>,
    ) -> Result<PluginHandle, RegistryError> {
        let meta = plugin.metadata();
        let id = meta.id.clone();

        // Reject duplicates.
        if self.entries.read().unwrap().contains_key(&id) {
            return Err(RegistryError::AlreadyRegistered(id));
        }

        // Verify dependencies.
        {
            let guard = self.entries.read().unwrap();
            for dep in &meta.dependencies {
                if !guard.contains_key(dep) {
                    return Err(RegistryError::MissingDependency {
                        plugin: id,
                        dependency: dep.clone(),
                    });
                }
            }
        }

        let order = self.next_order();
        let mut entry = PluginEntry::new(Arc::clone(plugin), order);
        entry.activate();

        let handle = PluginHandle::new(id.clone(), Arc::clone(plugin));
        self.entries.write().unwrap().insert(id, entry);
        Ok(handle)
    }

    /// Register a plugin in `Dormant` state without calling `on_load()`.
    ///
    /// Useful when the caller wants fine-grained control over the lifecycle.
    pub fn register_dormant(
        &self,
        plugin: &&Arc<dyn Plugin>,
    ) -> Result<PluginHandle, RegistryError> {
        let id = plugin.metadata().id.clone();
        if self.entries.read().unwrap().contains_key(&id) {
            return Err(RegistryError::AlreadyRegistered(id));
        }
        let order = self.next_order();
        let entry = PluginEntry::new(Arc::clone(plugin), order);
        let handle = PluginHandle::new(id.clone(), Arc::clone(plugin));
        self.entries.write().unwrap().insert(id, entry);
        Ok(handle)
    }

    /// Activate a dormant plugin by calling its `on_load()` hook.
    pub fn activate(&self, id: &PluginId) -> Result<(), RegistryError> {
        let mut guard = self.entries.write().unwrap();
        let entry = guard
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.clone()))?;
        if entry.status != PluginStatus::Dormant {
            return Err(RegistryError::InvalidState {
                id: id.clone(),
                status: entry.status.to_string(),
            });
        }
        entry.activate();
        Ok(())
    }

    // ── Unloading ──────────────────────────────────────────────────────────

    /// Deactivate and remove the plugin with the given ID.
    ///
    /// Calls `on_unload()` before removal.
    pub fn unload_plugin(&self, id: &PluginId) -> Result<(), RegistryError> {
        let mut guard = self.entries.write().unwrap();
        let entry = guard
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.clone()))?;
        entry.deactivate();
        guard.remove(id);
        drop(guard);
        Ok(())
    }

    /// Mark a plugin as faulted without removing it.
    pub fn fault(&self, id: &PluginId, reason: impl Into<String>) -> Result<(), RegistryError> {
        let mut guard = self.entries.write().unwrap();
        let entry = guard
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.clone()))?;
        entry.fault(reason);
        Ok(())
    }

    // ── Query ──────────────────────────────────────────────────────────────

    /// Look up a plugin by ID and return a lightweight handle.
    pub fn get(&self, id: &PluginId) -> Option<PluginHandle> {
        let guard = self.entries.read().unwrap();
        guard.get(id).map(|e| PluginHandle::new(id.clone(), Arc::clone(&e.plugin)))
    }

    /// Returns `true` if a plugin with the given ID is registered.
    pub fn contains(&self, id: &PluginId) -> bool {
        self.entries.read().unwrap().contains_key(id)
    }

    /// Handles for all currently active plugins, ordered by load sequence.
    pub fn active_plugins(&self) -> Vec<PluginHandle> {
        let guard = self.entries.read().unwrap();
        let mut entries: Vec<_> = guard.iter().collect();
        entries.sort_by_key(|(_, e)| e.load_order);
        entries
            .into_iter()
            .map(|(id, e)| PluginHandle::new(id.clone(), Arc::clone(&e.plugin)))
            .collect()
    }

    /// All registered plugin IDs.
    pub fn all_ids(&self) -> Vec<PluginId> {
        self.entries.read().unwrap().keys().cloned().collect()
    }

    /// Number of registered plugins (active + dormant + faulted).
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Returns `true` if no plugins are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Status of the plugin with `id`.
    pub fn status(&self, id: &PluginId) -> Option<PluginStatus> {
        self.entries.read().unwrap().get(id).map(|e| e.status.clone())
    }

    /// Unload all plugins in reverse load order.
    pub fn unload_all(&self) {
        let mut guard = self.entries.write().unwrap();
        let mut entries: Vec<_> = guard.iter_mut().collect();
        entries.sort_by_key(|(_, e)| std::cmp::Reverse(e.load_order));
        for (_, entry) in &mut entries {
            entry.deactivate();
        }
        guard.clear();
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Register `plugin` with `registry` and return a handle.
pub fn register_plugin(
    registry: &PluginRegistry,
    plugin: &Arc<dyn Plugin>,
) -> Result<PluginHandle, RegistryError> {
    registry.register_plugin(plugin)
}

/// Unload the plugin identified by `id` from `registry`.
pub fn unload_plugin(registry: &PluginRegistry, id: &PluginId) -> Result<(), RegistryError> {
    registry.unload_plugin(id)
}

// ─────────────────────────────────────────────────────────────────────────────
// SimplePlugin — a concrete plugin for tests and simple use-cases
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal plugin implementation that stores a payload of type `T`.
#[derive(Debug)]
pub struct SimplePlugin<T: fmt::Debug + Send + Sync + 'static> {
    meta: PluginMetadata,
    pub data: T,
}

impl<T: fmt::Debug + Send + Sync + 'static> SimplePlugin<T> {
    pub const fn new(meta: PluginMetadata, data: T) -> Self {
        Self { meta, data }
    }
}

impl<T: fmt::Debug + Send + Sync + Any + 'static> Plugin for SimplePlugin<T> {
    fn metadata(&self) -> &PluginMetadata {
        &self.meta
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plugin(id: &str) -> Arc<dyn Plugin> {
        let meta = PluginMetadata::new(id, format!("Plugin {id}"))
            .with_version("1.0.0")
            .with_author("test");
        Arc::new(SimplePlugin::new(meta, 42u32))
    }

    #[test]
    fn register_and_find() {
        let reg = PluginRegistry::new();
        let p = make_plugin("com.test.alpha");
        let handle = reg.register_plugin(&p).unwrap();
        assert_eq!(handle.id.as_str(), "com.test.alpha");
        assert_eq!(handle.display_name(), "Plugin com.test.alpha");
        assert!(reg.contains(&handle.id));
    }

    #[test]
    fn register_duplicate_fails() {
        let reg = PluginRegistry::new();
        let p1 = make_plugin("com.test.dup");
        let p2 = make_plugin("com.test.dup");
        reg.register_plugin(&p1).unwrap();
        let err = reg.register_plugin(&p2).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered(_)));
    }

    #[test]
    fn unload_removes_plugin() {
        let reg = PluginRegistry::new();
        let p = make_plugin("com.test.beta");
        let id = PluginId::new("com.test.beta");
        reg.register_plugin(&p).unwrap();
        reg.unload_plugin(&id).unwrap();
        assert!(!reg.contains(&id));
    }

    #[test]
    fn unload_missing_returns_error() {
        let reg = PluginRegistry::new();
        let id = PluginId::new("com.test.ghost");
        let err = reg.unload_plugin(&id).unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn active_plugins_ordered_by_load() {
        let reg = PluginRegistry::new();
        for name in &["a", "b", "c"] {
            reg.register_plugin(&make_plugin(&format!("com.test.{name}"))).unwrap();
        }
        let active = reg.active_plugins();
        assert_eq!(active.len(), 3);
        // Order must match insertion order.
        assert_eq!(active[0].id.as_str(), "com.test.a");
        assert_eq!(active[1].id.as_str(), "com.test.b");
        assert_eq!(active[2].id.as_str(), "com.test.c");
    }

    #[test]
    fn dependency_check_passes() {
        let reg = PluginRegistry::new();
        reg.register_plugin(&make_plugin("com.test.dep")).unwrap();

        let meta = PluginMetadata::new("com.test.requires", "Requires")
            .with_dependency("com.test.dep");
        let p: Arc<dyn Plugin> = Arc::new(SimplePlugin::new(meta, 0u32));
        let result = reg.register_plugin(&p);
        assert!(result.is_ok());
    }

    #[test]
    fn dependency_missing_fails() {
        let reg = PluginRegistry::new();
        let meta = PluginMetadata::new("com.test.orphan", "Orphan")
            .with_dependency("com.test.missing");
        let p: Arc<dyn Plugin> = Arc::new(SimplePlugin::new(meta, 0u32));
        let err = reg.register_plugin(&p).unwrap_err();
        assert!(matches!(err, RegistryError::MissingDependency { .. }));
    }

    #[test]
    fn dormant_then_activate() {
        let reg = PluginRegistry::new();
        let p = make_plugin("com.test.lazy");
        let id = PluginId::new("com.test.lazy");
        reg.register_dormant(&&p).unwrap();
        assert_eq!(reg.status(&id), Some(PluginStatus::Dormant));
        reg.activate(&id).unwrap();
        assert_eq!(reg.status(&id), Some(PluginStatus::Active));
    }

    #[test]
    fn fault_marks_plugin() {
        let reg = PluginRegistry::new();
        let p = make_plugin("com.test.buggy");
        let id = PluginId::new("com.test.buggy");
        reg.register_plugin(&p).unwrap();
        reg.fault(&id, "null pointer").unwrap();
        assert!(matches!(reg.status(&id), Some(PluginStatus::Faulted(_))));
    }

    #[test]
    fn unload_all_clears() {
        let reg = PluginRegistry::new();
        for n in 0..5 {
            reg.register_plugin(&make_plugin(&format!("com.test.{n}"))).unwrap();
        }
        assert_eq!(reg.len(), 5);
        reg.unload_all();
        assert!(reg.is_empty());
    }

    #[test]
    fn free_function_wrappers() {
        let reg = PluginRegistry::new();
        let p = make_plugin("com.test.free");
        let handle = register_plugin(&reg, &p).unwrap();
        unload_plugin(&reg, &handle.id).unwrap();
        assert!(!reg.contains(&handle.id));
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let reg = PluginRegistry::new();
        let id = PluginId::new("com.test.unknown");
        assert!(reg.get(&id).is_none());
    }

    #[test]
    fn plugin_downcast_succeeds() {
        let reg = PluginRegistry::new();
        let meta = PluginMetadata::new("com.test.typed", "Typed");
        let p: Arc<dyn Plugin> = Arc::new(SimplePlugin::new(meta, 99u32));
        reg.register_plugin(&Arc::clone(&p)).unwrap();
        let id = PluginId::new("com.test.typed");
        let handle = reg.get(&id).unwrap();
        let concrete = handle.downcast::<SimplePlugin<u32>>();
        assert!(concrete.is_some());
        assert_eq!(concrete.unwrap().data, 99u32);
    }
}

