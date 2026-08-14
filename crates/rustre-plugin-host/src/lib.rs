//! `rustre-plugin-host`
//!
//! Plugin host — loads, manages the lifecycle, persists plugin state,
//! handles plugin IPC, version compatibility checking, dependency resolution,
//! and sandboxing of plugin operations.

pub mod dynamic_loader;
pub mod hot_reload_engine;
pub mod plugin_event_bus;
pub mod plugin_ipc;
pub mod plugin_lifecycle;
pub mod plugin_permissions;
pub mod plugin_sandbox;
pub mod plugin_sandbox_full;
pub mod wasm_plugin_runtime;
pub mod plugin_capability_model;
pub mod plugin_registry_v2;
pub mod plugin_event_bus_v2;
pub mod plugin_permission_system;

/// Plugin sandbox v2: SandboxPolicy, ApiCallInterceptor, ResourceTracker, SandboxReport.
pub mod plugin_sandbox_v2;

/// Plugin IPC v2: IpcMessage, IpcChannel, MessageQueue, FramedMessage, IpcSerializer.
pub mod plugin_ipc_v2;

/// Native plugin loader: NativePluginLoader, PluginManifest, LoadError, NativePluginRegistry.
pub mod native_plugin_loader;

use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, params};
use rustre_plugin_api::{
    HookRegistry, HostPluginExt, HostPluginRegistry as PluginRegistry, IpcMessage, IpcResponse,
    Plugin, PluginError, PluginManifest, PluginMeta, PluginSettings, PluginState, PluginValue,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced by the plugin host.
#[derive(Debug, Error)]
pub enum HostError {
    #[error("load error: {0}")]
    Load(String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("plugin error: {0}")]
    Plugin(#[from] PluginError),
    #[error("database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("version incompatible: {0}")]
    VersionIncompatible(String),
    #[error("dependency missing: {0}")]
    DependencyMissing(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("sandbox violation: {0}")]
    SandboxViolation(String),
    #[error("timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for HostError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginSource
// ──────────────────────────────────────────────────────────────────────────────

/// Where a plugin comes from.
#[derive(Clone)]
pub enum PluginSource {
    DynLib(PathBuf),
    Inline(Arc<RwLock<dyn Plugin>>),
    BuiltIn(String),
}

impl fmt::Debug for PluginSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DynLib(p) => write!(f, "DynLib({p:?})"),
            Self::Inline(_) => write!(f, "Inline(<plugin>)"),
            Self::BuiltIn(s) => write!(f, "BuiltIn({s})"),
        }
    }
}

impl fmt::Display for PluginSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DynLib(p) => write!(f, "dynlib:{}", p.display()),
            Self::Inline(_) => write!(f, "inline"),
            Self::BuiltIn(s) => write!(f, "builtin:{s}"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginEntry
// ──────────────────────────────────────────────────────────────────────────────

/// Persisted snapshot of a plugin's identity and state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    pub meta: PluginMeta,
    pub state: PluginState,
    pub load_time: u64,
    pub error_message: Option<String>,
    pub load_count: u32,
    pub unload_count: u32,
    pub last_error: Option<String>,
}

impl PluginEntry {
    fn new(meta: PluginMeta, state: PluginState) -> Self {
        Self {
            meta,
            state,
            load_time: unix_now_secs(),
            error_message: None,
            load_count: 1,
            unload_count: 0,
            last_error: None,
        }
    }
}

impl fmt::Display for PluginEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.meta, self.state)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HostEvent
// ──────────────────────────────────────────────────────────────────────────────

/// Events emitted by the plugin host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostEvent {
    PluginLoaded(String),
    PluginUnloaded(String),
    PluginSuspended(String),
    PluginResumed(String),
    PluginError {
        id: String,
        error: String,
    },
    PluginStateChanged {
        id: String,
        old: PluginState,
        new: PluginState,
    },
    IpcCall {
        plugin_id: String,
        method: String,
    },
    IpcResponse {
        plugin_id: String,
        method: String,
        success: bool,
    },
}

impl fmt::Display for HostEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginLoaded(id) => write!(f, "PluginLoaded({id})"),
            Self::PluginUnloaded(id) => write!(f, "PluginUnloaded({id})"),
            Self::PluginSuspended(id) => write!(f, "PluginSuspended({id})"),
            Self::PluginResumed(id) => write!(f, "PluginResumed({id})"),
            Self::PluginError { id, error } => write!(f, "PluginError({id}): {error}"),
            Self::PluginStateChanged { id, old, new } => {
                write!(f, "StateChanged({id}): {old} -> {new}")
            }
            Self::IpcCall { plugin_id, method } => write!(f, "IpcCall({plugin_id}, {method})"),
            Self::IpcResponse {
                plugin_id,
                method,
                success,
            } => {
                write!(f, "IpcResponse({plugin_id}, {method}, ok={success})")
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SandboxConfig
// ──────────────────────────────────────────────────────────────────────────────

/// Controls what a plugin is allowed to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub allow_fs_read: bool,
    pub allow_fs_write: bool,
    pub allow_network: bool,
    pub allow_subprocess: bool,
    pub max_memory_mb: u64,
    pub max_cpu_time_ms: u64,
    pub allowed_hosts: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_fs_read: false,
            allow_fs_write: false,
            allow_network: false,
            allow_subprocess: false,
            max_memory_mb: 128,
            max_cpu_time_ms: 5_000,
            allowed_hosts: Vec::new(),
        }
    }
}

impl SandboxConfig {
    /// Allow everything (trusted plugins only).
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            allow_fs_read: true,
            allow_fs_write: true,
            allow_network: true,
            allow_subprocess: true,
            max_memory_mb: 0,
            max_cpu_time_ms: 0,
            allowed_hosts: Vec::new(),
        }
    }

    /// Read-only file access, no network.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            allow_fs_read: true,
            ..Default::default()
        }
    }

    /// Validate a request against this policy.
    ///
    /// # Errors
    /// Returns `HostError::SandboxViolation` if the request is denied.
    pub fn check_fs_read(&self) -> Result<(), HostError> {
        if !self.allow_fs_read {
            return Err(HostError::SandboxViolation(
                "filesystem read not allowed".into(),
            ));
        }
        Ok(())
    }

    /// Validate a network request.
    ///
    /// # Errors
    /// Returns `HostError::SandboxViolation` if the request is denied.
    pub fn check_network(&self, host: &str) -> Result<(), HostError> {
        if !self.allow_network {
            return Err(HostError::SandboxViolation(
                "network access not allowed".into(),
            ));
        }
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|h| h == host) {
            return Err(HostError::SandboxViolation(format!(
                "host '{host}' not in allowed list"
            )));
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// IPC dispatcher
// ──────────────────────────────────────────────────────────────────────────────

/// Trait implemented by plugin objects that support IPC calls.
pub trait IpcHandler: Send + Sync {
    /// Handle an IPC message and return a response.
    ///
    /// # Errors
    /// Returns `HostError` on protocol or dispatch failure.
    fn handle(&self, msg: IpcMessage) -> Result<IpcResponse, HostError>;
}

/// Boxed handler used by `InProcessIpcDispatcher`.
pub type PluginIpcHandler = Box<dyn Fn(PluginValue) -> Result<PluginValue, HostError> + Send + Sync>;

/// In-process IPC dispatcher — maps method names to handler closures.
pub struct InProcessIpcDispatcher {
    handlers: RwLock<HashMap<String, PluginIpcHandler>>,
}

impl InProcessIpcDispatcher {
    /// Create an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a handler for `method`.
    pub fn register(
        &self,
        method: impl Into<String>,
        handler: impl Fn(PluginValue) -> Result<PluginValue, HostError> + Send + Sync + 'static,
    ) {
        self.handlers
            .write()
            .insert(method.into(), Box::new(handler));
    }

    /// Dispatch a call to the appropriate handler.
    ///
    /// # Errors
    /// Returns `HostError::Ipc` if no handler is registered.
    pub fn dispatch(&self, method: &str, params: PluginValue) -> Result<PluginValue, HostError> {
        let handlers = self.handlers.read();
        let handler = handlers
            .get(method)
            .ok_or_else(|| HostError::Ipc(format!("no handler for method '{method}'")))?;
        handler(params)
    }

    /// Return all registered method names.
    #[must_use]
    pub fn method_names(&self) -> Vec<String> {
        self.handlers.read().keys().cloned().collect()
    }
}

impl Default for InProcessIpcDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InProcessIpcDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InProcessIpcDispatcher {{ methods: {} }}",
            self.handlers.read().len()
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DependencyGraph
// ──────────────────────────────────────────────────────────────────────────────

/// Tracks plugin dependency relationships and validates load order.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    edges: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `plugin_id` as depending on `dependency_id`.
    pub fn add_dependency(
        &mut self,
        plugin_id: impl Into<String>,
        dependency_id: impl Into<String>,
    ) {
        self.edges
            .entry(plugin_id.into())
            .or_default()
            .push(dependency_id.into());
    }

    /// Return all direct dependencies of `plugin_id`.
    #[must_use]
    pub fn dependencies_of(&self, plugin_id: &str) -> Vec<&str> {
        self.edges
            .get(plugin_id)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Check that all dependencies of `plugin_id` are in `loaded`.
    ///
    /// # Errors
    /// Returns `HostError::DependencyMissing` for the first missing dependency.
    pub fn check_dependencies(&self, plugin_id: &str, loaded: &[String]) -> Result<(), HostError> {
        for dep in self.dependencies_of(plugin_id) {
            if !loaded.contains(&dep.to_string()) {
                return Err(HostError::DependencyMissing(dep.to_string()));
            }
        }
        Ok(())
    }

    /// Topologically sort plugin IDs so that dependencies come first.
    ///
    /// # Errors
    /// Returns `HostError::Other` if a cycle is detected.
    pub fn topological_order(&self) -> Result<Vec<String>, HostError> {
        // Collect all nodes: both sources (keys) and leaf targets (values).
        let mut all_nodes: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (k, deps) in &self.edges {
            all_nodes.insert(k.as_str());
            for dep in deps {
                all_nodes.insert(dep.as_str());
            }
        }

        let mut visited: HashMap<&str, bool> = HashMap::with_capacity(all_nodes.len());
        let mut order: Vec<String> = Vec::with_capacity(all_nodes.len());

        for id in all_nodes {
            if !visited.contains_key(id) {
                self.visit(id, &mut visited, &mut order)?;
            }
        }
        Ok(order)
    }

    fn visit<'a>(
        &'a self,
        id: &'a str,
        visited: &mut HashMap<&'a str, bool>,
        order: &mut Vec<String>,
    ) -> Result<(), HostError> {
        if let Some(&in_progress) = visited.get(id) {
            if in_progress {
                return Err(HostError::Other(format!(
                    "dependency cycle detected at '{id}'"
                )));
            }
            return Ok(());
        }
        visited.insert(id, true);
        if let Some(deps) = self.edges.get(id) {
            for dep in deps {
                self.visit(dep, visited, order)?;
            }
        }
        visited.insert(id, false);
        order.push(id.to_string());
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginHealth
// ──────────────────────────────────────────────────────────────────────────────

/// Health status of a loaded plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    pub plugin_id: String,
    pub state: PluginState,
    pub error_count: u32,
    pub last_heartbeat: Option<u64>,
    pub healthy: bool,
}

impl PluginHealth {
    fn new(plugin_id: String, state: PluginState) -> Self {
        Self {
            plugin_id,
            state,
            error_count: 0,
            last_heartbeat: Some(unix_now_secs()),
            healthy: state == PluginState::Active,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginHost
// ──────────────────────────────────────────────────────────────────────────────

/// Central plugin host — manages loading, lifecycle, persistence, IPC, and sandboxing.
pub struct PluginHost {
    registry: PluginRegistry,
    /// Plugins keyed by their canonical short id (manifest `name`).
    ///
    /// The underlying `HostPluginRegistry` keys plugins by `"{name}@{version}"`
    /// (its `meta().id`), which is fine for global uniqueness but inconvenient
    /// for callers that work with the short, stable plugin id. The host owns
    /// this parallel map so lookups, lifecycle calls, and tests can address a
    /// plugin by its name.
    plugins_by_name: RwLock<HashMap<String, Arc<RwLock<dyn Plugin>>>>,
    hook_registry: HookRegistry,
    entries: RwLock<HashMap<String, PluginEntry>>,
    event_log: RwLock<VecDeque<HostEvent>>,
    db: Mutex<Option<Connection>>,
    settings_store: RwLock<HashMap<String, PluginSettings>>,
    sandbox_configs: RwLock<HashMap<String, SandboxConfig>>,
    health_map: RwLock<HashMap<String, PluginHealth>>,
    ipc_dispatchers: RwLock<HashMap<String, Arc<InProcessIpcDispatcher>>>,
    manifests: RwLock<HashMap<String, PluginManifest>>,
    event_log_max: usize,
}

// PluginHost derives Send + Sync through its fields:
// - `Mutex<Option<Connection>>` ensures exclusive access to the SQLite handle.
// All other fields use parking_lot locks.
// No hand-written unsafe impls are needed.

impl PluginHost {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a host backed by an in-memory `SQLite` database.
    ///
    /// # Errors
    /// Returns `HostError` if the database cannot be opened or the schema cannot be created.
    pub fn new_in_memory() -> Result<Self, HostError> {
        let conn = Connection::open_in_memory()?;
        Self::create_schema(&conn)?;
        Ok(Self::with_connection(Some(conn)))
    }

    /// Create a host backed by a file-based `SQLite` database.
    ///
    /// # Errors
    /// Returns `HostError` if the database cannot be opened or the schema cannot be created.
    pub fn new_with_db(path: &std::path::Path) -> Result<Self, HostError> {
        let conn = Connection::open(path)?;
        Self::create_schema(&conn)?;
        Ok(Self::with_connection(Some(conn)))
    }

    /// Create a host without a database (no persistence).
    #[must_use]
    pub fn new_without_db() -> Self {
        Self::with_connection(None)
    }

    fn with_connection(db: Option<Connection>) -> Self {
        Self {
            registry: PluginRegistry::new(),
            plugins_by_name: RwLock::new(HashMap::new()),
            hook_registry: HookRegistry::new(),
            entries: RwLock::new(HashMap::new()),
            event_log: RwLock::new(VecDeque::new()),
            db: Mutex::new(db),
            settings_store: RwLock::new(HashMap::new()),
            sandbox_configs: RwLock::new(HashMap::new()),
            health_map: RwLock::new(HashMap::new()),
            ipc_dispatchers: RwLock::new(HashMap::new()),
            manifests: RwLock::new(HashMap::new()),
            event_log_max: 1024,
        }
    }

    fn create_schema(conn: &Connection) -> Result<(), HostError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS plugin_entries (
                id          TEXT PRIMARY KEY,
                meta_json   TEXT NOT NULL,
                state       TEXT NOT NULL,
                load_time   INTEGER NOT NULL,
                error_msg   TEXT
            );
            CREATE TABLE IF NOT EXISTS plugin_settings (
                id          TEXT PRIMARY KEY,
                settings_json TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    // ── Loading / Unloading ───────────────────────────────────────────────────

    /// Load a plugin from `source`, initialise it with `settings`, and register it.
    ///
    /// # Errors
    /// Returns `HostError` on source resolution failure, initialisation failure, or
    /// duplicate registration.
    pub fn load_plugin(
        &self,
        source: PluginSource,
        settings: PluginSettings,
    ) -> Result<String, HostError> {
        let plugin_arc: Arc<RwLock<dyn Plugin>> = match source {
            PluginSource::Inline(arc) => arc,
            PluginSource::DynLib(ref path) => {
                return Err(HostError::Load(format!(
                    "dynamic library loading not yet implemented for {}",
                    path.display()
                )));
            }
            PluginSource::BuiltIn(ref name) => {
                return Err(HostError::Load(format!(
                    "built-in plugin '{name}' not found"
                )));
            }
        };

        let id = {
            let guard = plugin_arc.write();
            // Use the manifest `name` as the canonical short id. The registry
            // will key the same plugin by `name@version` internally; the host
            // tracks the short id in its own maps for callers.
            let id = guard.manifest().name;
            guard.initialize(&settings)?;
            id
        };

        // Reject duplicates by short id up-front. The underlying registry also
        // enforces uniqueness by `name@version`, but the host's own maps key by
        // short id, so we must guard before mutating any of them.
        if self.plugins_by_name.read().contains_key(&id) {
            return Err(HostError::Plugin(PluginError::AlreadyRegistered(id)));
        }

        self.settings_store
            .write()
            .insert(id.clone(), settings.clone());
        self.registry.register(plugin_arc.clone())?;
        self.plugins_by_name
            .write()
            .insert(id.clone(), plugin_arc.clone());
        self.sandbox_configs.write().entry(id.clone()).or_default();

        let entry = {
            let guard = plugin_arc.read();
            let mut meta = guard.meta();
            // Rewrite the composite `name@version` id to the canonical short
            // id so persisted entries and lookups agree.
            meta.id = id.clone();
            PluginEntry::new(meta, guard.state())
        };

        let health = PluginHealth::new(id.clone(), entry.state);
        self.health_map.write().insert(id.clone(), health);

        if let Err(e) = self.persist_entry(&entry) {
            self.log_event(HostEvent::PluginError {
                id: id.clone(),
                error: e.to_string(),
            });
        }

        if let Err(e) = self.persist_settings(&id, &settings) {
            self.log_event(HostEvent::PluginError {
                id: id.clone(),
                error: e.to_string(),
            });
        }

        self.entries.write().insert(id.clone(), entry);
        self.log_event(HostEvent::PluginLoaded(id.clone()));

        Ok(id)
    }

    /// Unload (shut down and remove) a plugin by ID.
    ///
    /// # Errors
    /// Returns `HostError` if the plugin is not found or shutdown fails.
    pub fn unload_plugin(&self, id: &str) -> Result<(), HostError> {
        let arc = self
            .plugins_by_name
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;

        let old_state = arc.read().state();
        arc.write().shutdown()?;
        let new_state = arc.read().state();

        // The underlying registry keys by `meta().id` (== `name@version`),
        // not by the short canonical id this host exposes. Recompute it for
        // unregistration so the registry can locate and remove the entry.
        let registry_id = arc.read().meta().id;
        self.registry.unregister(&registry_id)?;
        self.plugins_by_name.write().remove(id);
        {
            let mut entries = self.entries.write();
            if let Some(entry) = entries.get_mut(id) {
                entry.unload_count += 1;
                entry.state = PluginState::Unloaded;
                // Persist the Unloaded state to the database before removing
                // the in-memory entry so the database reflects the final state.
                drop(entries); // release write lock before calling persist_entry
                let entry_snapshot = {
                    // Re-acquire just to clone
                    self.entries.read().get(id).cloned()
                };
                if let Some(snap) = entry_snapshot {
                    if let Err(e) = self.persist_entry(&snap) {
                        self.log_event(HostEvent::PluginError {
                            id: id.to_string(),
                            error: e.to_string(),
                        });
                    }
                }
            } else {
                drop(entries);
            }
            self.entries.write().remove(id);
        }
        self.settings_store.write().remove(id);
        self.sandbox_configs.write().remove(id);
        self.health_map.write().remove(id);
        self.ipc_dispatchers.write().remove(id);

        self.log_event(HostEvent::PluginStateChanged {
            id: id.to_string(),
            old: old_state,
            new: new_state,
        });
        self.log_event(HostEvent::PluginUnloaded(id.to_string()));

        Ok(())
    }

    /// Suspend a plugin by ID.
    ///
    /// # Errors
    /// Returns `HostError` if the plugin is not found or suspension fails.
    pub fn suspend_plugin(&self, id: &str) -> Result<(), HostError> {
        let arc = self
            .plugins_by_name
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;
        arc.write().suspend()?;
        self.log_event(HostEvent::PluginSuspended(id.to_string()));
        Ok(())
    }

    /// Resume a suspended plugin by ID.
    ///
    /// # Errors
    /// Returns `HostError` if the plugin is not found or resume fails.
    pub fn resume_plugin(&self, id: &str) -> Result<(), HostError> {
        let arc = self
            .plugins_by_name
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;
        arc.write().resume()?;
        self.log_event(HostEvent::PluginResumed(id.to_string()));
        Ok(())
    }

    // ── Manifest management ───────────────────────────────────────────────────

    /// Register a plugin manifest (does not load the plugin).
    pub fn register_manifest(&self, manifest: PluginManifest) {
        let manifest_id = format!("{}@{}", manifest.name, manifest.version);
        self.manifests.write().insert(manifest_id, manifest);
    }

    /// Retrieve a registered manifest.
    #[must_use]
    pub fn get_manifest(&self, id: &str) -> Option<PluginManifest> {
        self.manifests.read().get(id).cloned()
    }

    /// Return all registered manifests.
    #[must_use]
    pub fn all_manifests(&self) -> Vec<PluginManifest> {
        self.manifests.read().values().cloned().collect()
    }

    // ── IPC ───────────────────────────────────────────────────────────────────

    /// Register an IPC dispatcher for a plugin.
    pub fn register_ipc(
        &self,
        plugin_id: impl Into<String>,
        dispatcher: Arc<InProcessIpcDispatcher>,
    ) {
        self.ipc_dispatchers
            .write()
            .insert(plugin_id.into(), dispatcher);
    }

    /// Call an IPC method on a plugin.
    ///
    /// # Errors
    /// Returns `HostError::Ipc` if no dispatcher is registered or the call fails.
    pub fn ipc_call(
        &self,
        plugin_id: &str,
        method: &str,
        params: PluginValue,
    ) -> Result<PluginValue, HostError> {
        let dispatcher = {
            self.ipc_dispatchers
                .read()
                .get(plugin_id)
                .cloned()
                .ok_or_else(|| HostError::Ipc(format!("no IPC dispatcher for '{plugin_id}'")))?
        };

        self.log_event(HostEvent::IpcCall {
            plugin_id: plugin_id.to_string(),
            method: method.to_string(),
        });

        let result = dispatcher.dispatch(method, params);

        let success = result.is_ok();
        self.log_event(HostEvent::IpcResponse {
            plugin_id: plugin_id.to_string(),
            method: method.to_string(),
            success,
        });

        result
    }

    // ── Sandbox ───────────────────────────────────────────────────────────────

    /// Set the sandbox configuration for a plugin.
    pub fn set_sandbox(&self, plugin_id: impl Into<String>, config: SandboxConfig) {
        self.sandbox_configs
            .write()
            .insert(plugin_id.into(), config);
    }

    /// Get the sandbox configuration for a plugin.
    #[must_use]
    pub fn get_sandbox(&self, plugin_id: &str) -> Option<SandboxConfig> {
        self.sandbox_configs.read().get(plugin_id).cloned()
    }

    /// Check a sandbox policy for filesystem read.
    ///
    /// # Errors
    /// Returns `HostError::SandboxViolation` if the policy denies it.
    pub fn sandbox_check_fs_read(&self, plugin_id: &str) -> Result<(), HostError> {
        match self.sandbox_configs.read().get(plugin_id) {
            Some(cfg) => cfg.check_fs_read(),
            None => Ok(()),
        }
    }

    // ── Health ────────────────────────────────────────────────────────────────

    /// Return the health status of a plugin.
    #[must_use]
    pub fn health(&self, plugin_id: &str) -> Option<PluginHealth> {
        self.health_map.read().get(plugin_id).cloned()
    }

    /// Return health of all loaded plugins.
    #[must_use]
    pub fn all_health(&self) -> Vec<PluginHealth> {
        self.health_map.read().values().cloned().collect()
    }

    /// Record an error for a plugin, incrementing its error count.
    pub fn record_error(&self, plugin_id: &str, error: &str) {
        let mut map = self.health_map.write();
        if let Some(health) = map.get_mut(plugin_id) {
            health.error_count += 1;
            health.healthy = false;
        }
        self.log_event(HostEvent::PluginError {
            id: plugin_id.to_string(),
            error: error.to_string(),
        });
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Reference to the underlying plugin registry.
    #[must_use]
    pub const fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Reference to the hook registry.
    #[must_use]
    pub const fn hook_registry(&self) -> &HookRegistry {
        &self.hook_registry
    }

    /// Snapshot of all plugin entries.
    #[must_use]
    pub fn all_entries(&self) -> Vec<PluginEntry> {
        self.entries.read().values().cloned().collect()
    }

    /// Full event log since the host was created.
    #[must_use]
    pub fn event_log(&self) -> Vec<HostEvent> {
        self.event_log.read().iter().cloned().collect()
    }

    /// Number of plugins currently in the Active state.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.entries
            .read()
            .values()
            .filter(|e| e.state == PluginState::Active)
            .count()
    }

    // ── Settings ──────────────────────────────────────────────────────────────

    /// Retrieve the current settings for the plugin with the given ID.
    ///
    /// # Errors
    /// Returns `HostError` if no plugin with that ID is loaded.
    pub fn get_settings(&self, id: &str) -> Result<PluginSettings, HostError> {
        self.settings_store
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(id.to_string()).into())
    }

    /// Replace the settings for the plugin with the given ID.
    ///
    /// # Errors
    /// Returns `HostError` if no plugin with that ID is loaded.
    pub fn update_settings(&self, id: &str, settings: PluginSettings) -> Result<(), HostError> {
        let mut store = self.settings_store.write();
        if !store.contains_key(id) {
            return Err(PluginError::NotFound(id.to_string()).into());
        }
        self.persist_settings(id, &settings)?;
        store.insert(id.to_string(), settings);
        Ok(())
    }

    // ── Database persistence ──────────────────────────────────────────────────

    fn persist_entry(&self, entry: &PluginEntry) -> Result<(), HostError> {
        let guard = self.db.lock();
        if let Some(conn) = guard.as_ref() {
            let meta_json = serde_json::to_string(&entry.meta).map_err(PluginError::from)?;
            let state_str = entry.state.to_string();
            conn.execute(
                "INSERT OR REPLACE INTO plugin_entries (id, meta_json, state, load_time, error_msg)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.meta.id,
                    meta_json,
                    state_str,
                    entry.load_time as i64,
                    entry.error_message
                ],
            )?;
        }
        Ok(())
    }

    fn persist_settings(&self, id: &str, settings: &PluginSettings) -> Result<(), HostError> {
        let guard = self.db.lock();
        if let Some(conn) = guard.as_ref() {
            let json = serde_json::to_string(settings).map_err(PluginError::from)?;
            conn.execute(
                "INSERT OR REPLACE INTO plugin_settings (id, settings_json) VALUES (?1, ?2)",
                params![id, json],
            )?;
        }
        Ok(())
    }

    /// Load all persisted plugin entries from the database.
    ///
    /// # Errors
    /// Returns `HostError` on database errors.
    pub fn load_persisted_entries(&self) -> Result<Vec<PluginEntry>, HostError> {
        let guard = self.db.lock();
        let conn = match guard.as_ref() {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };
        let mut stmt =
            conn.prepare("SELECT meta_json, state, load_time, error_msg FROM plugin_entries")?;
        let rows = stmt.query_map([], |row| {
            let meta_json: String = row.get(0)?;
            let state_str: String = row.get(1)?;
            let load_time: i64 = row.get(2)?;
            let error_msg: Option<String> = row.get(3)?;
            Ok((meta_json, state_str, load_time, error_msg))
        })?;

        let mut entries = Vec::with_capacity(rows.size_hint().0);
        for row in rows {
            let (meta_json, state_str, load_time, error_message) = row?;
            let meta: PluginMeta =
                serde_json::from_str(&meta_json).map_err(|e| PluginError::Serde(e.to_string()))?;
            let state = match state_str.as_str() {
                "Active" => PluginState::Active,
                "Unloaded" => PluginState::Unloaded,
                "Error" => PluginState::Error,
                "Suspended" => PluginState::Suspended,
                _ => PluginState::Unloaded,
            };
            entries.push(PluginEntry {
                meta,
                state,
                load_time: load_time as u64,
                error_message,
                load_count: 0,
                unload_count: 0,
                last_error: None,
            });
        }
        Ok(entries)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn log_event(&self, event: HostEvent) {
        let mut guard = self.event_log.write();
        if guard.len() >= self.event_log_max {
            guard.pop_front();
        }
        guard.push_back(event);
    }

    /// Return events of a specific type (by Display string prefix).
    #[must_use]
    pub fn events_matching(&self, prefix: &str) -> Vec<HostEvent> {
        self.event_log
            .read()
            .iter()
            .filter(|e| e.to_string().starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PluginHost {{ plugins: {}, db: {} }}",
            self.registry.count(),
            if self.db.lock().is_some() {
                "in-memory"
            } else {
                "none"
            }
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Suppress unused import warning when running tests on non-unix/windows.
const _: Duration = Duration::from_millis(0);

// ──────────────────────────────────────────────────────────────────────────────
// §33 Plugin System — dynamic library loading and permission enforcement
// ──────────────────────────────────────────────────────────────────────────────

use std::path::Path;

// ──────────────────────────────────────────────────────────────────────────────
// PermissionRequest
// ──────────────────────────────────────────────────────────────────────────────

/// A permission that a plugin declares it needs before it may be loaded.
///
/// Each variant corresponds to a class of privileged operation.  The host
/// inspects the manifest's `permissions` list and decides whether to grant
/// them according to the user's trust policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionRequest {
    FsRead { paths: Vec<String> },
    FsWrite { paths: Vec<String> },
    Network { hosts: Vec<String> },
    Subprocess { commands: Vec<String> },
    FullMemoryAccess,
    UnsafeFfi,
}

impl PermissionRequest {
    /// Human-readable name of the permission kind.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::FsRead { .. } => "fs_read",
            Self::FsWrite { .. } => "fs_write",
            Self::Network { .. } => "network",
            Self::Subprocess { .. } => "subprocess",
            Self::FullMemoryAccess => "full_memory_access",
            Self::UnsafeFfi => "unsafe_ffi",
        }
    }

    /// Whether this permission implies elevated (dangerous) trust.
    #[must_use]
    pub const fn is_elevated(&self) -> bool {
        matches!(self, Self::FullMemoryAccess | Self::UnsafeFfi)
    }

    /// Return `true` if the permission covers filesystem access (read or write).
    #[must_use]
    pub const fn is_filesystem(&self) -> bool {
        matches!(self, Self::FsRead { .. } | Self::FsWrite { .. })
    }
}

impl fmt::Display for PermissionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FsRead { paths } => write!(f, "fs_read({})", paths.join(", ")),
            Self::FsWrite { paths } => write!(f, "fs_write({})", paths.join(", ")),
            Self::Network { hosts } => write!(f, "network({})", hosts.join(", ")),
            Self::Subprocess { commands } => write!(f, "subprocess({})", commands.join(", ")),
            Self::FullMemoryAccess => write!(f, "full_memory_access"),
            Self::UnsafeFfi => write!(f, "unsafe_ffi"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ExtensionPoint
// ──────────────────────────────────────────────────────────────────────────────

/// The functional category a plugin extends.
///
/// A single plugin binary can contribute to multiple extension points.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExtensionPoint {
    Loader,
    Architecture,
    AnalysisPass,
    DeobfPass,
    Dissector,
    MemPlugin,
    Decompiler,
    Theme,
    Action { name: String, menu: String },
    View,
    McpTool { tool_name: String },
    Workflow,
    IntelProvider,
    LlmBackend,
}

impl ExtensionPoint {
    /// Returns a stable string tag for this extension point variant.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Architecture => "architecture",
            Self::AnalysisPass => "analysis_pass",
            Self::DeobfPass => "deobf_pass",
            Self::Dissector => "dissector",
            Self::MemPlugin => "mem_plugin",
            Self::Decompiler => "decompiler",
            Self::Theme => "theme",
            Self::Action { .. } => "action",
            Self::View => "view",
            Self::McpTool { .. } => "mcp_tool",
            Self::Workflow => "workflow",
            Self::IntelProvider => "intel_provider",
            Self::LlmBackend => "llm_backend",
        }
    }

    /// Whether this extension point requires UI thread access.
    #[must_use]
    pub const fn requires_ui_thread(&self) -> bool {
        matches!(self, Self::Theme | Self::View | Self::Action { .. })
    }
}

impl fmt::Display for ExtensionPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action { name, menu } => write!(f, "action({menu}/{name})"),
            Self::McpTool { tool_name } => write!(f, "mcp_tool({tool_name})"),
            other => write!(f, "{}", other.tag()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginManifest (§33)
// ──────────────────────────────────────────────────────────────────────────────

/// Declarative manifest shipped alongside every plugin.
///
/// For file-based plugins the manifest is a TOML file; for native (statically
/// linked) plugins it is returned by [`NativePlugin::manifest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest33 {
    /// Reverse-DNS style plugin identifier, e.g. `"com.example.my-plugin"`.
    pub name: String,
    /// Semantic version string, e.g. `"1.2.0"`.
    pub version: String,
    /// Author display name or e-mail.
    pub author: String,
    /// One-line description shown in the plugin manager.
    pub description: String,
    /// Minimum host API version this plugin is compatible with.
    pub min_api_version: String,
    /// Permissions the plugin declares it needs.
    #[serde(default)]
    pub permissions: Vec<PermissionRequest>,
    /// Extension points this plugin contributes to.
    #[serde(default)]
    pub extension_points: Vec<ExtensionPoint>,
}

impl Manifest33 {
    /// Construct a minimal manifest (no permissions, no extension points).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        author: impl Into<String>,
        description: impl Into<String>,
        min_api_version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            author: author.into(),
            description: description.into(),
            min_api_version: min_api_version.into(),
            permissions: Vec::new(),
            extension_points: Vec::new(),
        }
    }

    /// Return `true` if the manifest declares at least one elevated permission.
    #[must_use]
    pub fn has_elevated_permissions(&self) -> bool {
        self.permissions.iter().any(PermissionRequest::is_elevated)
    }

    /// Return all declared extension point tags (deduplicated).
    #[must_use]
    pub fn extension_point_tags(&self) -> Vec<&'static str> {
        let mut tags: Vec<&'static str> = self
            .extension_points
            .iter()
            .map(ExtensionPoint::tag)
            .collect();
        tags.dedup();
        tags
    }

    /// Parse a manifest from a TOML string.
    ///
    /// # Errors
    /// Returns an error if the TOML is malformed or fields are missing.
    pub fn from_toml(toml_str: &str) -> Result<Self, HostError> {
        toml::from_str(toml_str).map_err(|e| HostError::Load(format!("manifest parse error: {e}")))
    }

    /// Serialize this manifest to a TOML string.
    ///
    /// # Errors
    /// Returns an error if serialization fails (should be infallible in practice).
    pub fn to_toml(&self) -> Result<String, HostError> {
        toml::to_string_pretty(self)
            .map_err(|e| HostError::Other(format!("manifest serialize error: {e}")))
    }
}

impl fmt::Display for Manifest33 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{} (by {})", self.name, self.version, self.author)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginMetadata
// ──────────────────────────────────────────────────────────────────────────────

/// Runtime tracking record for a discovered (but not necessarily loaded) plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// The plugin's parsed manifest.
    pub manifest: Manifest33,
    /// Absolute path to the plugin binary or manifest file.
    pub path: PathBuf,
    /// Whether the user has enabled this plugin.
    pub enabled: bool,
    /// Whether the plugin has been successfully loaded into the host.
    pub loaded: bool,
    /// Error message from the most recent load attempt, if any.
    pub load_error: Option<String>,
}

impl PluginMetadata {
    /// Create a new metadata record in the *disabled, not loaded* state.
    #[must_use]
    pub const fn new(manifest: Manifest33, path: PathBuf) -> Self {
        Self {
            manifest,
            path,
            enabled: false,
            loaded: false,
            load_error: None,
        }
    }

    /// Short display name derived from the manifest.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.manifest.name
    }

    /// Whether the plugin is ready to serve requests (enabled **and** loaded).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.enabled && self.loaded && self.load_error.is_none()
    }

    /// Record a load failure.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.load_error = Some(error.into());
        self.loaded = false;
    }

    /// Clear any recorded load error and mark as successfully loaded.
    pub fn mark_loaded(&mut self) {
        self.load_error = None;
        self.loaded = true;
    }
}

impl fmt::Display for PluginMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [enabled={}, loaded={}]",
            self.manifest, self.enabled, self.loaded
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginRegistry (§33)
// ──────────────────────────────────────────────────────────────────────────────

/// Filesystem-backed registry that discovers, tracks, and manages plugins.
///
/// The registry operates on a single plugin directory.  Each plugin is
/// represented by a TOML manifest file (`*.toml`) that lives alongside the
/// plugin binary.
#[derive(Debug)]
pub struct FilePluginRegistry {
    plugins: HashMap<String, PluginMetadata>,
    plugin_dir: PathBuf,
}

impl FilePluginRegistry {
    /// Create a new registry pointing at `plugin_dir`.
    ///
    /// The directory need not exist yet; [`scan_directory`] will create it
    /// if it is missing.
    #[must_use]
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_dir,
        }
    }

    /// Walk `plugin_dir`, find `*.toml` manifest files, and populate the
    /// registry with the discovered metadata.
    ///
    /// Existing entries are preserved; newly found plugins are added in the
    /// *disabled* state.  Returns the number of **new** plugins discovered.
    ///
    /// # Errors
    /// Returns `HostError::Io` if the directory cannot be read.
    pub fn scan_directory(&mut self) -> Result<u32, HostError> {
        if !self.plugin_dir.exists() {
            std::fs::create_dir_all(&self.plugin_dir)?;
            return Ok(0);
        }

        let mut new_count: u32 = 0;

        for entry in std::fs::read_dir(&self.plugin_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Only process *.toml files.
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let toml_str = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    // Non-fatal: log and continue.
                    eprintln!("[plugin-registry] cannot read {}: {e}", path.display());
                    continue;
                }
            };

            let manifest = match Manifest33::from_toml(&toml_str) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[plugin-registry] parse error in {}: {e}", path.display());
                    continue;
                }
            };

            let name = manifest.name.clone();

            // Only insert if we haven't seen this plugin before.
            if let std::collections::hash_map::Entry::Vacant(e) = self.plugins.entry(name) {
                e.insert(PluginMetadata::new(manifest, path));
                new_count += 1;
            }
        }

        Ok(new_count)
    }

    /// Enable the plugin with the given name so it can be loaded.
    ///
    /// # Errors
    /// Returns `HostError::Other` if the plugin is not registered.
    pub fn enable(&mut self, name: &str) -> Result<(), HostError> {
        let meta = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| HostError::Other(format!("plugin '{name}' not found in registry")))?;
        meta.enabled = true;
        Ok(())
    }

    /// Disable the plugin with the given name.
    ///
    /// This does **not** unload an already-loaded plugin; call the host's
    /// `unload_plugin` first if you need a clean shutdown.
    ///
    /// # Errors
    /// Returns `HostError::Other` if the plugin is not registered.
    pub fn disable(&mut self, name: &str) -> Result<(), HostError> {
        let meta = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| HostError::Other(format!("plugin '{name}' not found in registry")))?;
        meta.enabled = false;
        Ok(())
    }

    /// Return metadata for all enabled plugins.
    #[must_use]
    pub fn list_enabled(&self) -> Vec<&PluginMetadata> {
        self.plugins.values().filter(|m| m.enabled).collect()
    }

    /// Return metadata for all plugins that contribute to the given extension
    /// point.
    #[must_use]
    pub fn list_by_extension_point(&self, ep: &ExtensionPoint) -> Vec<&PluginMetadata> {
        self.plugins
            .values()
            .filter(|m| m.manifest.extension_points.contains(ep))
            .collect()
    }

    /// Get a reference to a plugin's metadata by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PluginMetadata> {
        self.plugins.get(name)
    }

    /// Get a mutable reference to a plugin's metadata by name.
    #[must_use]
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PluginMetadata> {
        self.plugins.get_mut(name)
    }

    /// Total number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Absolute path to the plugin directory.
    #[must_use]
    pub fn plugin_dir(&self) -> &Path {
        &self.plugin_dir
    }

    /// Iterate over all registered plugins.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PluginMetadata)> {
        self.plugins.iter().map(|(k, v)| (k.as_str(), v))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PluginSandbox
// ──────────────────────────────────────────────────────────────────────────────

/// Fine-grained permission enforcer built from a plugin's declared permissions.
///
/// Unlike [`SandboxConfig`] (which is a coarse boolean policy), `PluginSandbox`
/// checks each access against the exact paths/hosts listed in the manifest.
#[derive(Debug, Clone)]
pub struct PluginSandbox {
    /// The permissions that were granted to this plugin.
    pub allowed_permissions: Vec<PermissionRequest>,
}

impl PluginSandbox {
    /// Build a sandbox from a set of granted permissions.
    #[must_use]
    pub const fn new(allowed_permissions: Vec<PermissionRequest>) -> Self {
        Self {
            allowed_permissions,
        }
    }

    /// Build a sandbox that grants every permission (for fully-trusted plugins).
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            allowed_permissions: vec![
                PermissionRequest::FullMemoryAccess,
                PermissionRequest::UnsafeFfi,
                PermissionRequest::FsRead {
                    paths: vec!["**".into()],
                },
                PermissionRequest::FsWrite {
                    paths: vec!["**".into()],
                },
                PermissionRequest::Network {
                    hosts: vec!["*".into()],
                },
                PermissionRequest::Subprocess {
                    commands: vec!["*".into()],
                },
            ],
        }
    }

    /// Build a sandbox that denies every permission (safe default).
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allowed_permissions: Vec::new(),
        }
    }

    /// Check whether the plugin may read `path`.
    ///
    /// Returns `true` only if a [`PermissionRequest::FsRead`] entry covers the
    /// requested path (exact match or glob `**` wildcard).
    #[must_use]
    pub fn check_fs_read(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.allowed_permissions.iter().any(|p| {
            if let PermissionRequest::FsRead { paths } = p {
                paths
                    .iter()
                    .any(|allowed| Self::path_matches(allowed, &path_str))
            } else {
                false
            }
        })
    }

    /// Check whether the plugin may write `path`.
    #[must_use]
    pub fn check_fs_write(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.allowed_permissions.iter().any(|p| {
            if let PermissionRequest::FsWrite { paths } = p {
                paths
                    .iter()
                    .any(|allowed| Self::path_matches(allowed, &path_str))
            } else {
                false
            }
        })
    }

    /// Check whether the plugin may open a network connection to `host`.
    #[must_use]
    pub fn check_network(&self, host: &str) -> bool {
        self.allowed_permissions.iter().any(|p| {
            if let PermissionRequest::Network { hosts } = p {
                hosts
                    .iter()
                    .any(|allowed| allowed == "*" || allowed == host)
            } else {
                false
            }
        })
    }

    /// Check whether the plugin may spawn a subprocess named `command`.
    #[must_use]
    pub fn check_subprocess(&self, command: &str) -> bool {
        self.allowed_permissions.iter().any(|p| {
            if let PermissionRequest::Subprocess { commands } = p {
                commands
                    .iter()
                    .any(|allowed| allowed == "*" || allowed == command)
            } else {
                false
            }
        })
    }

    /// Whether the plugin has been granted full memory access.
    #[must_use]
    pub fn has_full_memory_access(&self) -> bool {
        self.allowed_permissions.iter().any(|p| {
            matches!(
                p,
                PermissionRequest::FullMemoryAccess | PermissionRequest::UnsafeFfi
            )
        })
    }

    /// Whether the plugin has been granted unsafe FFI.
    #[must_use]
    pub fn has_unsafe_ffi(&self) -> bool {
        self.allowed_permissions
            .iter()
            .any(|p| matches!(p, PermissionRequest::UnsafeFfi))
    }

    /// Simple path matching: `**` matches everything, otherwise exact string equality.
    fn path_matches(pattern: &str, path: &str) -> bool {
        pattern == "**" || pattern == path
    }
}

impl Default for PluginSandbox {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl fmt::Display for PluginSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let perms: Vec<String> = self
            .allowed_permissions
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        write!(f, "PluginSandbox[{}]", perms.join(", "))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// LoadedPlugin
// ──────────────────────────────────────────────────────────────────────────────

/// A handle to a dynamically loaded plugin library.
///
/// On drop the handle keeps the library mapped; call
/// [`DynamicPluginLoader::unload`] to explicitly release it.
pub struct LoadedPlugin {
    /// The manifest that was used when loading.
    pub manifest: Manifest33,
    /// Path to the shared library that was opened.
    pub path: PathBuf,
    handle: RawLibraryHandle,
}

impl fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoadedPlugin {{ name: {}, path: {:?} }}",
            self.manifest.name, self.path
        )
    }
}

/// Opaque wrapper around a platform-specific dynamic library handle.
enum RawLibraryHandle {
    #[cfg(unix)]
    Unix(*mut libc::c_void),
    #[cfg(windows)]
    Windows(windows_sys::Win32::Foundation::HMODULE),
    Unsupported,
}

impl RawLibraryHandle {
    /// Returns `true` if this handle is the unsupported-platform stub.
    pub(crate) const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported)
    }
}

impl LoadedPlugin {
    /// Construct a placeholder `LoadedPlugin` for platforms where dynamic
    /// loading is not supported.
    #[must_use]
    pub const fn unsupported_stub(path: PathBuf, manifest: Manifest33) -> Self {
        Self {
            manifest,
            path,
            handle: RawLibraryHandle::Unsupported,
        }
    }

    /// Returns `true` if this plugin uses the unsupported-platform stub handle.
    #[must_use]
    pub const fn is_unsupported_stub(&self) -> bool {
        self.handle.is_unsupported()
    }
}

// SAFETY: the handles are only accessed inside DynamicPluginLoader which
// enforces exclusivity through ownership semantics.
unsafe impl Send for RawLibraryHandle {}
unsafe impl Sync for RawLibraryHandle {}

// ──────────────────────────────────────────────────────────────────────────────
// DynamicPluginLoader
// ──────────────────────────────────────────────────────────────────────────────

/// Scaffolding for loading plugin shared libraries at runtime.
///
/// Actual symbol resolution requires `unsafe`.  The public entry points handle
/// the platform dispatch and return a typed error when loading is not supported
/// or the expected symbol is absent.
pub struct DynamicPluginLoader;

/// Signature of the initialisation function every plugin shared library must
/// export as `rustre_plugin_init`.
///
/// The function receives the host API version string and returns an opaque
/// context pointer on success, or a null pointer on failure.
pub type PluginInitFn =
    unsafe extern "C" fn(api_version: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;

impl DynamicPluginLoader {
    /// Attempt to load the shared library at `path` and locate the
    /// `rustre_plugin_init` symbol.
    ///
    /// # Safety
    /// Calling the returned `rustre_plugin_init` symbol is inherently unsafe.
    /// The caller must ensure the library is compatible with the host ABI.
    ///
    /// # Errors
    /// - `HostError::Load` if the library cannot be opened.
    /// - `HostError::SymbolNotFound` if `rustre_plugin_init` is absent.
    /// - `HostError::Other` on unsupported platforms.
    pub fn load_dynamic(path: &Path, manifest: &Manifest33) -> Result<LoadedPlugin, HostError> {
        #[cfg(unix)]
        {
            Self::load_unix(path, manifest)
        }
        #[cfg(windows)]
        {
            Self::load_windows(path, manifest)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, manifest);
            Err(HostError::Other(
                "dynamic library loading is not supported on this platform".into(),
            ))
        }
    }

    /// Release a previously loaded plugin.
    ///
    /// On Unix this calls `dlclose`; on Windows it calls `FreeLibrary`.
    /// After this call `plugin` is consumed and the library handle is invalid.
    pub fn unload(plugin: LoadedPlugin) {
        match plugin.handle {
            #[cfg(unix)]
            RawLibraryHandle::Unix(handle) => {
                if !handle.is_null() {
                    // SAFETY: handle is a valid dlopen handle obtained above.
                    unsafe { libc::dlclose(handle) };
                }
            }
            #[cfg(windows)]
            RawLibraryHandle::Windows(handle) => {
                if !handle.is_null() {
                    // SAFETY: handle is a valid LoadLibrary handle obtained above.
                    unsafe { windows_sys::Win32::Foundation::FreeLibrary(handle) };
                }
            }
            RawLibraryHandle::Unsupported => {}
        }
        // `plugin` is moved and dropped; the LoadedPlugin struct is consumed.
    }

    // ── Platform implementations ──────────────────────────────────────────────

    #[cfg(unix)]
    fn load_unix(path: &Path, manifest: &Manifest33) -> Result<LoadedPlugin, HostError> {
        use std::ffi::CString;

        let path_cstr = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| HostError::Load(format!("invalid path: {e}")))?;

        // SAFETY: path_cstr is a valid NUL-terminated C string.
        let handle = unsafe { libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };

        if handle.is_null() {
            // SAFETY: dlerror returns a valid C string or null.
            let err_msg = unsafe {
                let ptr = libc::dlerror();
                if ptr.is_null() {
                    "unknown dlopen error".to_string()
                } else {
                    std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            return Err(HostError::Load(format!("dlopen failed: {err_msg}")));
        }

        let sym_name = CString::new("rustre_plugin_init").unwrap();

        // SAFETY: handle is valid; sym_name is a valid C string.
        let sym = unsafe { libc::dlsym(handle, sym_name.as_ptr()) };

        if sym.is_null() {
            // Close the handle before returning.
            unsafe { libc::dlclose(handle) };
            return Err(HostError::SymbolNotFound("rustre_plugin_init".into()));
        }

        Ok(LoadedPlugin {
            manifest: manifest.clone(),
            path: path.to_owned(),
            handle: RawLibraryHandle::Unix(handle),
        })
    }

    #[cfg(windows)]
    fn load_windows(path: &Path, manifest: &Manifest33) -> Result<LoadedPlugin, HostError> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: wide is a valid NUL-terminated wide string.
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };

        if handle.is_null() {
            return Err(HostError::Load(format!("LoadLibraryW failed for {}", path.display())));
        }

        // SAFETY: handle is valid; "rustre_plugin_init\0" is a valid ANSI name.
        let sym = unsafe { GetProcAddress(handle, b"rustre_plugin_init\0".as_ptr()) };

        if sym.is_none() {
            // SAFETY: handle is a valid LoadLibrary handle.
            unsafe { FreeLibrary(handle) };
            return Err(HostError::SymbolNotFound("rustre_plugin_init".into()));
        }

        Ok(LoadedPlugin {
            manifest: manifest.clone(),
            path: path.to_owned(),
            handle: RawLibraryHandle::Windows(handle),
        })
    }
}

impl fmt::Debug for DynamicPluginLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DynamicPluginLoader")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NativePlugin trait
// ──────────────────────────────────────────────────────────────────────────────

/// Trait implemented by plugins that are compiled directly into the host binary.
///
/// Native plugins are registered through [`NativePluginRegistry`] and incur no
/// dynamic-loading overhead or FFI boundary.
pub trait NativePlugin: Send + Sync {
    /// Return this plugin's declarative manifest.
    fn manifest(&self) -> Manifest33;

    /// Return the set of extension points this plugin contributes to.
    fn extension_points(&self) -> Vec<ExtensionPoint>;

    /// Human-readable name (defaults to `manifest().name`).
    fn name(&self) -> String {
        self.manifest().name
    }

    /// Short description (defaults to `manifest().description`).
    fn description(&self) -> String {
        self.manifest().description
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NativePluginRegistry
// ──────────────────────────────────────────────────────────────────────────────

/// Registry for plugins that are statically linked into the host binary.
///
/// Unlike [`FilePluginRegistry`], this registry never touches the filesystem
/// and does not require dynamic loading.
pub struct NativePluginRegistry {
    registered: Vec<Box<dyn NativePlugin>>,
}

impl NativePluginRegistry {
    /// Create an empty native plugin registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registered: Vec::new(),
        }
    }

    /// Add a native plugin to the registry.
    pub fn register(&mut self, plugin: Box<dyn NativePlugin>) {
        self.registered.push(plugin);
    }

    /// Return references to all registered native plugins.
    #[must_use]
    pub fn all(&self) -> &[Box<dyn NativePlugin>] {
        &self.registered
    }

    /// Find native plugins that contribute to the given extension point.
    #[must_use]
    pub fn by_extension_point(&self, ep: &ExtensionPoint) -> Vec<&dyn NativePlugin> {
        self.registered
            .iter()
            .filter(|p| p.extension_points().contains(ep))
            .map(std::convert::AsRef::as_ref)
            .collect()
    }

    /// Number of registered native plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registered.len()
    }

    /// Whether the registry contains no plugins.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registered.is_empty()
    }

    /// Return manifests for all registered native plugins.
    #[must_use]
    pub fn manifests(&self) -> Vec<Manifest33> {
        self.registered.iter().map(|p| p.manifest()).collect()
    }
}

impl Default for NativePluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NativePluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NativePluginRegistry {{ count: {} }}",
            self.registered.len()
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_plugin_api::{
        HookPoint, PluginCapability, PluginCategory, PluginMeta, SettingValue, Version,
    };
    use std::any::Any;

    // ── TestPlugin ─────────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct TestPlugin {
        meta: PluginMeta,
        version: Version,
        capability: PluginCapability,
    }

    impl TestPlugin {
        fn new(id: &str, cat: PluginCategory) -> Self {
            Self {
                meta: PluginMeta::new(id.to_string(), id.to_string(), cat.clone()),
                version: Version::new(0, 0, 0),
                capability: cat,
            }
        }
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.meta.name
        }
        fn version(&self) -> &Version {
            &self.version
        }
        fn capabilities(&self) -> Vec<PluginCapability> {
            vec![self.capability.clone()]
        }
        fn manifest(&self) -> PluginManifest {
            PluginManifest::from_meta(self.meta.clone())
        }
        fn init(
            &self,
            _ctx: &mut rustre_plugin_api::PluginContext,
        ) -> Result<(), PluginError> {
            Ok(())
        }
        fn unload(&self, _ctx: &mut rustre_plugin_api::PluginContext) {}
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn make_inline(id: &str) -> PluginSource {
        PluginSource::Inline(Arc::new(RwLock::new(TestPlugin::new(
            id,
            PluginCategory::Loader,
        ))))
    }

    // ── HostError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_host_error_load_display() {
        let e = HostError::Load("bad path".to_string());
        assert!(e.to_string().contains("bad path"));
    }

    #[test]
    fn test_host_error_from_anyhow() {
        let e: HostError = anyhow::anyhow!("oops").into();
        assert!(matches!(e, HostError::Other(_)));
    }

    #[test]
    fn test_host_error_from_plugin_error() {
        let pe = PluginError::NotFound("x".to_string());
        let he: HostError = pe.into();
        assert!(matches!(he, HostError::Plugin(_)));
    }

    #[test]
    fn test_host_error_variants() {
        let e = HostError::VersionIncompatible("v2 required".into());
        assert!(e.to_string().contains("v2"));
        let e2 = HostError::DependencyMissing("dep-x".into());
        assert!(e2.to_string().contains("dep-x"));
        let e3 = HostError::SandboxViolation("blocked".into());
        assert!(e3.to_string().contains("blocked"));
    }

    // ── PluginSource ───────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_source_display_inline() {
        let src = make_inline("com.test.x");
        assert_eq!(src.to_string(), "inline");
    }

    #[test]
    fn test_plugin_source_display_builtin() {
        let src = PluginSource::BuiltIn("pe-loader".to_string());
        assert_eq!(src.to_string(), "builtin:pe-loader");
    }

    #[test]
    fn test_plugin_source_display_dynlib() {
        let src = PluginSource::DynLib(PathBuf::from("/tmp/plugin.so"));
        assert!(src.to_string().contains("plugin.so"));
    }

    #[test]
    fn test_plugin_source_debug() {
        let src = make_inline("x");
        assert!(format!("{src:?}").contains("Inline"));
    }

    // ── PluginEntry ────────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_entry_display() {
        let entry = PluginEntry::new(
            PluginMeta::new(
                "com.test".to_string(),
                "Test".to_string(),
                PluginCategory::Loader,
            ),
            PluginState::Active,
        );
        assert!(entry.to_string().contains("Active"));
        assert!(entry.to_string().contains("Test"));
    }

    // ── HostEvent ──────────────────────────────────────────────────────────────

    #[test]
    fn test_host_event_loaded_display() {
        let ev = HostEvent::PluginLoaded("com.test".to_string());
        assert_eq!(ev.to_string(), "PluginLoaded(com.test)");
    }

    #[test]
    fn test_host_event_unloaded_display() {
        let ev = HostEvent::PluginUnloaded("com.test".to_string());
        assert_eq!(ev.to_string(), "PluginUnloaded(com.test)");
    }

    #[test]
    fn test_host_event_error_display() {
        let ev = HostEvent::PluginError {
            id: "x".to_string(),
            error: "boom".to_string(),
        };
        assert!(ev.to_string().contains("boom"));
    }

    #[test]
    fn test_host_event_state_changed_display() {
        let ev = HostEvent::PluginStateChanged {
            id: "x".to_string(),
            old: PluginState::Loading,
            new: PluginState::Active,
        };
        let s = ev.to_string();
        assert!(s.contains("Loading"));
        assert!(s.contains("Active"));
    }

    #[test]
    fn test_host_event_ipc_display() {
        let ev = HostEvent::IpcCall {
            plugin_id: "p".into(),
            method: "ping".into(),
        };
        assert!(ev.to_string().contains("ping"));
    }

    // ── SandboxConfig ──────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_default_denies_all() {
        let cfg = SandboxConfig::default();
        assert!(!cfg.allow_fs_read);
        assert!(!cfg.allow_network);
    }

    #[test]
    fn test_sandbox_permissive_allows_all() {
        let cfg = SandboxConfig::permissive();
        assert!(cfg.allow_fs_read);
        assert!(cfg.allow_network);
    }

    #[test]
    fn test_sandbox_read_only() {
        let cfg = SandboxConfig::read_only();
        assert!(cfg.allow_fs_read);
        assert!(!cfg.allow_network);
    }

    #[test]
    fn test_sandbox_check_fs_read_denied() {
        let cfg = SandboxConfig::default();
        assert!(cfg.check_fs_read().is_err());
    }

    #[test]
    fn test_sandbox_check_fs_read_allowed() {
        let cfg = SandboxConfig::read_only();
        assert!(cfg.check_fs_read().is_ok());
    }

    #[test]
    fn test_sandbox_check_network_denied() {
        let cfg = SandboxConfig::default();
        assert!(cfg.check_network("example.com").is_err());
    }

    #[test]
    fn test_sandbox_check_network_allowed_no_allowlist() {
        let cfg = SandboxConfig::permissive();
        assert!(cfg.check_network("any-host.com").is_ok());
    }

    #[test]
    fn test_sandbox_check_network_allowlist() {
        let mut cfg = SandboxConfig::permissive();
        cfg.allowed_hosts = vec!["safe.example.com".into()];
        assert!(cfg.check_network("safe.example.com").is_ok());
        assert!(cfg.check_network("evil.com").is_err());
    }

    // ── PluginHost construction ────────────────────────────────────────────────

    #[test]
    fn test_new_in_memory_creates_host() {
        let host = PluginHost::new_in_memory().unwrap();
        assert_eq!(host.registry().count(), 0);
        assert_eq!(host.active_count(), 0);
    }

    #[test]
    fn test_new_without_db_creates_host() {
        let host = PluginHost::new_without_db();
        assert_eq!(host.registry().count(), 0);
    }

    #[test]
    fn test_debug_output() {
        let host = PluginHost::new_without_db();
        let s = format!("{host:?}");
        assert!(s.contains("PluginHost"));
    }

    // ── load_plugin ────────────────────────────────────────────────────────────

    #[test]
    fn test_load_inline_plugin() {
        let host = PluginHost::new_in_memory().unwrap();
        let id = host
            .load_plugin(make_inline("com.test.a"), PluginSettings::new())
            .unwrap();
        assert_eq!(id, "com.test.a");
        assert_eq!(host.registry().count(), 1);
        assert_eq!(host.active_count(), 1);
    }

    #[test]
    fn test_load_plugin_persists_entry() {
        let host = PluginHost::new_in_memory().unwrap();
        host.load_plugin(make_inline("com.test.b"), PluginSettings::new())
            .unwrap();
        assert_eq!(host.all_entries().len(), 1);
    }

    #[test]
    fn test_load_plugin_logs_event() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.test.c"), PluginSettings::new())
            .unwrap();
        let log = host.event_log();
        assert!(
            log.iter()
                .any(|e| matches!(e, HostEvent::PluginLoaded(id) if id == "com.test.c"))
        );
    }

    #[test]
    fn test_load_dynlib_returns_error() {
        let host = PluginHost::new_without_db();
        let result = host.load_plugin(
            PluginSource::DynLib(PathBuf::from("/nonexistent/plugin.so")),
            PluginSettings::new(),
        );
        assert!(matches!(result, Err(HostError::Load(_))));
    }

    #[test]
    fn test_load_builtin_returns_error() {
        let host = PluginHost::new_without_db();
        let result = host.load_plugin(
            PluginSource::BuiltIn("unknown".to_string()),
            PluginSettings::new(),
        );
        assert!(matches!(result, Err(HostError::Load(_))));
    }

    #[test]
    fn test_load_duplicate_plugin_returns_error() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.dup"), PluginSettings::new())
            .unwrap();
        let result = host.load_plugin(make_inline("com.dup"), PluginSettings::new());
        assert!(result.is_err());
    }

    // ── unload_plugin ─────────────────────────────────────────────────────────

    #[test]
    fn test_unload_plugin_removes_from_registry() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.test.d"), PluginSettings::new())
            .unwrap();
        host.unload_plugin("com.test.d").unwrap();
        assert_eq!(host.registry().count(), 0);
    }

    #[test]
    fn test_unload_nonexistent_returns_error() {
        let host = PluginHost::new_without_db();
        let result = host.unload_plugin("com.missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_unload_logs_events() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.test.e"), PluginSettings::new())
            .unwrap();
        host.unload_plugin("com.test.e").unwrap();
        let log = host.event_log();
        assert!(
            log.iter()
                .any(|e| matches!(e, HostEvent::PluginUnloaded(id) if id == "com.test.e"))
        );
    }

    // ── settings ──────────────────────────────────────────────────────────────

    #[test]
    fn test_get_settings_after_load() {
        let host = PluginHost::new_without_db();
        let mut s = PluginSettings::new();
        s.set("foo".to_string(), SettingValue::Bool(true));
        host.load_plugin(make_inline("com.test.f"), s).unwrap();
        let retrieved = host.get_settings("com.test.f").unwrap();
        assert_eq!(retrieved.get_bool("foo"), Some(true));
    }

    #[test]
    fn test_update_settings() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.test.g"), PluginSettings::new())
            .unwrap();
        let mut new_settings = PluginSettings::new();
        new_settings.set("port".to_string(), SettingValue::Int(9090));
        host.update_settings("com.test.g", new_settings).unwrap();
        let retrieved = host.get_settings("com.test.g").unwrap();
        assert_eq!(retrieved.get_int("port"), Some(9090));
    }

    #[test]
    fn test_get_settings_missing_plugin_returns_error() {
        let host = PluginHost::new_without_db();
        let result = host.get_settings("com.missing");
        assert!(result.is_err());
    }

    // ── IPC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_ipc_dispatcher_register_and_call() {
        let dispatcher = Arc::new(InProcessIpcDispatcher::new());
        dispatcher.register("ping", |_| Ok(PluginValue::String("pong".into())));
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.ipc"), PluginSettings::new())
            .unwrap();
        host.register_ipc("com.ipc", dispatcher);
        let result = host.ipc_call("com.ipc", "ping", PluginValue::Null).unwrap();
        assert_eq!(result, PluginValue::String("pong".into()));
    }

    #[test]
    fn test_ipc_no_dispatcher_returns_error() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.noipc"), PluginSettings::new())
            .unwrap();
        let result = host.ipc_call("com.noipc", "ping", PluginValue::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipc_logs_events() {
        let dispatcher = Arc::new(InProcessIpcDispatcher::new());
        dispatcher.register("ping", |_| Ok(PluginValue::Null));
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.log"), PluginSettings::new())
            .unwrap();
        host.register_ipc("com.log", dispatcher);
        let _ = host.ipc_call("com.log", "ping", PluginValue::Null);
        let log = host.event_log();
        assert!(log.iter().any(|e| matches!(e, HostEvent::IpcCall { .. })));
    }

    // ── Sandbox ───────────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_set_and_get() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.sandbox"), PluginSettings::new())
            .unwrap();
        host.set_sandbox("com.sandbox", SandboxConfig::read_only());
        let cfg = host.get_sandbox("com.sandbox").unwrap();
        assert!(cfg.allow_fs_read);
    }

    #[test]
    fn test_sandbox_check_on_plugin() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.s"), PluginSettings::new())
            .unwrap();
        // Default sandbox denies fs read.
        assert!(host.sandbox_check_fs_read("com.s").is_err());
        host.set_sandbox("com.s", SandboxConfig::permissive());
        assert!(host.sandbox_check_fs_read("com.s").is_ok());
    }

    // ── Health ────────────────────────────────────────────────────────────────

    #[test]
    fn test_health_after_load() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.h"), PluginSettings::new())
            .unwrap();
        let h = host.health("com.h").unwrap();
        assert!(h.healthy);
        assert_eq!(h.error_count, 0);
    }

    #[test]
    fn test_health_after_error() {
        let host = PluginHost::new_without_db();
        host.load_plugin(make_inline("com.e"), PluginSettings::new())
            .unwrap();
        host.record_error("com.e", "boom");
        let h = host.health("com.e").unwrap();
        assert!(!h.healthy);
        assert_eq!(h.error_count, 1);
    }

    // ── Manifest ──────────────────────────────────────────────────────────────

    #[test]
    fn test_register_and_get_manifest() {
        let host = PluginHost::new_without_db();
        let meta = PluginMeta::new("m".to_string(), "M".to_string(), PluginCategory::Loader);
        let manifest = PluginManifest::from_meta(meta);
        host.register_manifest(manifest);
        // register_manifest keys by "{name}@{version}" — M@0.0.0 for this test.
        assert!(host.get_manifest("M@0.0.0").is_some());
        assert_eq!(host.all_manifests().len(), 1);
    }

    // ── DependencyGraph ────────────────────────────────────────────────────────

    #[test]
    fn test_dependency_graph_check_ok() {
        let mut g = DependencyGraph::new();
        g.add_dependency("plugin-b", "plugin-a");
        let loaded = vec!["plugin-a".to_string()];
        assert!(g.check_dependencies("plugin-b", &loaded).is_ok());
    }

    #[test]
    fn test_dependency_graph_check_missing() {
        let mut g = DependencyGraph::new();
        g.add_dependency("plugin-b", "plugin-a");
        let loaded: Vec<String> = vec![];
        let result = g.check_dependencies("plugin-b", &loaded);
        assert!(matches!(result, Err(HostError::DependencyMissing(_))));
    }

    #[test]
    fn test_dependency_graph_topological_sort() {
        let mut g = DependencyGraph::new();
        g.add_dependency("c", "b");
        g.add_dependency("b", "a");
        // We just verify the call doesn't panic.
        let _ = g.topological_order();
    }

    #[test]
    fn test_dependency_graph_no_deps() {
        let g = DependencyGraph::new();
        assert_eq!(g.dependencies_of("anything"), Vec::<&str>::new());
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    #[test]
    fn test_load_persisted_entries_empty() {
        let host = PluginHost::new_in_memory().unwrap();
        let entries = host.load_persisted_entries().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_load_persisted_entries_after_load() {
        let host = PluginHost::new_in_memory().unwrap();
        host.load_plugin(make_inline("com.persist"), PluginSettings::new())
            .unwrap();
        let entries = host.load_persisted_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.id, "com.persist");
    }

    // ── §33 PermissionRequest ─────────────────────────────────────────────────

    #[test]
    fn test_permission_request_kind_names() {
        assert_eq!(
            PermissionRequest::FullMemoryAccess.kind_name(),
            "full_memory_access"
        );
        assert_eq!(PermissionRequest::UnsafeFfi.kind_name(), "unsafe_ffi");
        let fs = PermissionRequest::FsRead {
            paths: vec!["/tmp".into()],
        };
        assert_eq!(fs.kind_name(), "fs_read");
    }

    #[test]
    fn test_permission_request_is_elevated() {
        assert!(PermissionRequest::FullMemoryAccess.is_elevated());
        assert!(PermissionRequest::UnsafeFfi.is_elevated());
        assert!(!PermissionRequest::FsRead { paths: vec![] }.is_elevated());
    }

    #[test]
    fn test_permission_request_is_filesystem() {
        assert!(PermissionRequest::FsRead { paths: vec![] }.is_filesystem());
        assert!(PermissionRequest::FsWrite { paths: vec![] }.is_filesystem());
        assert!(!PermissionRequest::Network { hosts: vec![] }.is_filesystem());
    }

    #[test]
    fn test_permission_request_display() {
        let p = PermissionRequest::Network {
            hosts: vec!["example.com".into()],
        };
        assert!(p.to_string().contains("example.com"));
        assert_eq!(
            PermissionRequest::FullMemoryAccess.to_string(),
            "full_memory_access"
        );
    }

    #[test]
    fn test_permission_request_serde_roundtrip() {
        let p = PermissionRequest::FsRead {
            paths: vec!["/tmp/**".into()],
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: PermissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    // ── §33 ExtensionPoint ────────────────────────────────────────────────────

    #[test]
    fn test_extension_point_tags() {
        assert_eq!(ExtensionPoint::Loader.tag(), "loader");
        assert_eq!(ExtensionPoint::Decompiler.tag(), "decompiler");
        assert_eq!(
            ExtensionPoint::Action {
                name: "Run".into(),
                menu: "File".into()
            }
            .tag(),
            "action"
        );
        assert_eq!(
            ExtensionPoint::McpTool {
                tool_name: "my_tool".into()
            }
            .tag(),
            "mcp_tool"
        );
    }

    #[test]
    fn test_extension_point_requires_ui_thread() {
        assert!(ExtensionPoint::Theme.requires_ui_thread());
        assert!(ExtensionPoint::View.requires_ui_thread());
        assert!(
            ExtensionPoint::Action {
                name: "x".into(),
                menu: "y".into()
            }
            .requires_ui_thread()
        );
        assert!(!ExtensionPoint::Loader.requires_ui_thread());
        assert!(!ExtensionPoint::AnalysisPass.requires_ui_thread());
    }

    #[test]
    fn test_extension_point_display() {
        let ep = ExtensionPoint::McpTool {
            tool_name: "scan_binary".into(),
        };
        assert_eq!(ep.to_string(), "mcp_tool(scan_binary)");
        assert_eq!(ExtensionPoint::Loader.to_string(), "loader");
    }

    #[test]
    fn test_extension_point_serde_roundtrip() {
        let ep = ExtensionPoint::Action {
            name: "Disasm".into(),
            menu: "Analyze".into(),
        };
        let json = serde_json::to_string(&ep).unwrap();
        let ep2: ExtensionPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(ep, ep2);
    }

    // ── §33 Manifest33 ────────────────────────────────────────────────────────

    #[test]
    fn test_manifest33_new_fields() {
        let m = Manifest33::new("com.test", "1.0.0", "Alice", "Test plugin", "0.1.0");
        assert_eq!(m.name, "com.test");
        assert_eq!(m.version, "1.0.0");
        assert_eq!(m.author, "Alice");
        assert!(m.permissions.is_empty());
        assert!(m.extension_points.is_empty());
    }

    #[test]
    fn test_manifest33_has_elevated_permissions_false() {
        let m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        assert!(!m.has_elevated_permissions());
    }

    #[test]
    fn test_manifest33_has_elevated_permissions_true() {
        let mut m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        m.permissions.push(PermissionRequest::UnsafeFfi);
        assert!(m.has_elevated_permissions());
    }

    #[test]
    fn test_manifest33_extension_point_tags() {
        let mut m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        m.extension_points.push(ExtensionPoint::Loader);
        m.extension_points.push(ExtensionPoint::AnalysisPass);
        let tags = m.extension_point_tags();
        assert!(tags.contains(&"loader"));
        assert!(tags.contains(&"analysis_pass"));
    }

    #[test]
    fn test_manifest33_display() {
        let m = Manifest33::new("com.example", "2.0.0", "Bob", "desc", "0.1");
        let s = m.to_string();
        assert!(s.contains("com.example"));
        assert!(s.contains("2.0.0"));
        assert!(s.contains("Bob"));
    }

    #[test]
    fn test_manifest33_toml_roundtrip() {
        let mut m = Manifest33::new("com.rt", "1.0.0", "Dev", "A plugin", "0.1");
        m.permissions.push(PermissionRequest::FsRead {
            paths: vec!["/home".into()],
        });
        m.extension_points.push(ExtensionPoint::Loader);
        let toml_str = m.to_toml().unwrap();
        let m2 = Manifest33::from_toml(&toml_str).unwrap();
        assert_eq!(m2.name, "com.rt");
        assert_eq!(m2.extension_points.len(), 1);
        assert_eq!(m2.permissions.len(), 1);
    }

    #[test]
    fn test_manifest33_from_toml_invalid() {
        let result = Manifest33::from_toml("not valid toml }{");
        assert!(result.is_err());
    }

    // ── §33 PluginMetadata ────────────────────────────────────────────────────

    #[test]
    fn test_plugin_metadata_new_state() {
        let m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        let meta = PluginMetadata::new(m, PathBuf::from("/plugins/x.so"));
        assert!(!meta.enabled);
        assert!(!meta.loaded);
        assert!(meta.load_error.is_none());
        assert!(!meta.is_active());
    }

    #[test]
    fn test_plugin_metadata_mark_loaded() {
        let m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        let mut meta = PluginMetadata::new(m, PathBuf::from("/plugins/x.so"));
        meta.enabled = true;
        meta.mark_loaded();
        assert!(meta.is_active());
    }

    #[test]
    fn test_plugin_metadata_set_error() {
        let m = Manifest33::new("x", "1.0", "a", "d", "0.1");
        let mut meta = PluginMetadata::new(m, PathBuf::from("/plugins/x.so"));
        meta.enabled = true;
        meta.mark_loaded();
        meta.set_error("symbol not found");
        assert!(!meta.is_active());
        assert_eq!(meta.load_error.as_deref(), Some("symbol not found"));
    }

    #[test]
    fn test_plugin_metadata_display() {
        let m = Manifest33::new("com.p", "1.0", "a", "d", "0.1");
        let meta = PluginMetadata::new(m, PathBuf::from("/p.so"));
        let s = meta.to_string();
        assert!(s.contains("com.p"));
        assert!(s.contains("enabled=false"));
    }

    // ── §33 FilePluginRegistry ────────────────────────────────────────────────

    #[test]
    fn test_file_plugin_registry_new_empty() {
        let reg = FilePluginRegistry::new(PathBuf::from("/nonexistent/plugins"));
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_file_plugin_registry_scan_creates_dir() {
        let tmp = std::env::temp_dir().join("rustre_plugin_test_scan");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut reg = FilePluginRegistry::new(tmp.clone());
        let count = reg.scan_directory().unwrap();
        assert_eq!(count, 0);
        assert!(tmp.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_file_plugin_registry_scan_finds_toml() {
        let tmp = std::env::temp_dir().join("rustre_plugin_test_toml");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Write a valid manifest.
        let manifest_toml = r#"
name = "com.test.scan"
version = "1.0.0"
author = "Tester"
description = "Scan test"
min_api_version = "0.1"
"#;
        std::fs::write(tmp.join("test-plugin.toml"), manifest_toml).unwrap();

        let mut reg = FilePluginRegistry::new(tmp.clone());
        let count = reg.scan_directory().unwrap();
        assert_eq!(count, 1);
        assert!(reg.get("com.test.scan").is_some());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_file_plugin_registry_enable_disable() {
        let tmp = std::env::temp_dir().join("rustre_plugin_test_enable");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let manifest_toml = r#"
name = "com.test.enable"
version = "1.0.0"
author = "A"
description = "D"
min_api_version = "0.1"
"#;
        std::fs::write(tmp.join("plugin.toml"), manifest_toml).unwrap();

        let mut reg = FilePluginRegistry::new(tmp.clone());
        reg.scan_directory().unwrap();

        reg.enable("com.test.enable").unwrap();
        assert_eq!(reg.list_enabled().len(), 1);

        reg.disable("com.test.enable").unwrap();
        assert_eq!(reg.list_enabled().len(), 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_file_plugin_registry_enable_missing_returns_error() {
        let mut reg = FilePluginRegistry::new(PathBuf::from("/no/such/dir"));
        assert!(reg.enable("nonexistent").is_err());
    }

    #[test]
    fn test_file_plugin_registry_list_by_extension_point() {
        let tmp = std::env::temp_dir().join("rustre_plugin_test_ep");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Inline-insert a plugin with extension point.
        let mut m = Manifest33::new("com.ep.loader", "1.0", "a", "d", "0.1");
        m.extension_points.push(ExtensionPoint::Loader);
        let meta = PluginMetadata::new(m, PathBuf::from("/ep.so"));

        let mut reg = FilePluginRegistry::new(tmp.clone());
        reg.plugins.insert("com.ep.loader".into(), meta);

        let loaders = reg.list_by_extension_point(&ExtensionPoint::Loader);
        assert_eq!(loaders.len(), 1);

        let decompilers = reg.list_by_extension_point(&ExtensionPoint::Decompiler);
        assert_eq!(decompilers.len(), 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── §33 PluginSandbox ─────────────────────────────────────────────────────

    #[test]
    fn test_plugin_sandbox_deny_all() {
        let s = PluginSandbox::deny_all();
        assert!(!s.check_fs_read(Path::new("/etc/passwd")));
        assert!(!s.check_fs_write(Path::new("/tmp/out")));
        assert!(!s.check_network("example.com"));
        assert!(!s.check_subprocess("ls"));
        assert!(!s.has_full_memory_access());
        assert!(!s.has_unsafe_ffi());
    }

    #[test]
    fn test_plugin_sandbox_unrestricted() {
        let s = PluginSandbox::unrestricted();
        assert!(s.check_fs_read(Path::new("/any/path")));
        assert!(s.check_fs_write(Path::new("/any/path")));
        assert!(s.check_network("any.host.com"));
        assert!(s.check_subprocess("rm"));
        assert!(s.has_full_memory_access());
        assert!(s.has_unsafe_ffi());
    }

    #[test]
    fn test_plugin_sandbox_specific_fs_read() {
        let s = PluginSandbox::new(vec![PermissionRequest::FsRead {
            paths: vec!["/tmp/safe".into()],
        }]);
        assert!(s.check_fs_read(Path::new("/tmp/safe")));
        assert!(!s.check_fs_read(Path::new("/etc/shadow")));
    }

    #[test]
    fn test_plugin_sandbox_network_host_matching() {
        let s = PluginSandbox::new(vec![PermissionRequest::Network {
            hosts: vec!["api.example.com".into()],
        }]);
        assert!(s.check_network("api.example.com"));
        assert!(!s.check_network("evil.com"));
    }

    #[test]
    fn test_plugin_sandbox_subprocess_wildcard() {
        let s = PluginSandbox::new(vec![PermissionRequest::Subprocess {
            commands: vec!["*".into()],
        }]);
        assert!(s.check_subprocess("anything"));
    }

    #[test]
    fn test_plugin_sandbox_full_memory_access_via_unsafe_ffi() {
        let s = PluginSandbox::new(vec![PermissionRequest::UnsafeFfi]);
        assert!(s.has_full_memory_access());
        assert!(s.has_unsafe_ffi());
    }

    #[test]
    fn test_plugin_sandbox_display() {
        let s = PluginSandbox::new(vec![PermissionRequest::FullMemoryAccess]);
        assert!(s.to_string().contains("full_memory_access"));
    }

    // ── §33 NativePluginRegistry ──────────────────────────────────────────────

    struct DummyNativePlugin;

    impl NativePlugin for DummyNativePlugin {
        fn manifest(&self) -> Manifest33 {
            Manifest33::new("com.native.dummy", "1.0", "Test", "Dummy", "0.1")
        }
        fn extension_points(&self) -> Vec<ExtensionPoint> {
            vec![ExtensionPoint::AnalysisPass]
        }
    }

    #[test]
    fn test_native_registry_register_and_list() {
        let mut reg = NativePluginRegistry::new();
        assert!(reg.is_empty());
        reg.register(Box::new(DummyNativePlugin));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn test_native_registry_by_extension_point() {
        let mut reg = NativePluginRegistry::new();
        reg.register(Box::new(DummyNativePlugin));

        let passes = reg.by_extension_point(&ExtensionPoint::AnalysisPass);
        assert_eq!(passes.len(), 1);

        let loaders = reg.by_extension_point(&ExtensionPoint::Loader);
        assert_eq!(loaders.len(), 0);
    }

    #[test]
    fn test_native_registry_manifests() {
        let mut reg = NativePluginRegistry::new();
        reg.register(Box::new(DummyNativePlugin));
        let manifests = reg.manifests();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].name, "com.native.dummy");
    }

    #[test]
    fn test_native_registry_debug() {
        let reg = NativePluginRegistry::new();
        assert!(format!("{reg:?}").contains("NativePluginRegistry"));
    }

    #[test]
    fn test_native_plugin_default_methods() {
        let p = DummyNativePlugin;
        assert_eq!(p.name(), "com.native.dummy");
        assert!(p.description().contains("Dummy"));
    }

    // ── multiple plugins ───────────────────────────────────────────────────────

    #[test]
    fn test_multiple_plugins_active_count() {
        let host = PluginHost::new_without_db();
        for i in 0..4 {
            host.load_plugin(make_inline(&format!("com.test.{i}")), PluginSettings::new())
                .unwrap();
        }
        assert_eq!(host.active_count(), 4);
        assert_eq!(host.all_entries().len(), 4);
    }

    #[test]
    fn test_hook_registry_accessible() {
        let host = PluginHost::new_without_db();
        assert_eq!(host.hook_registry().hook_count(HookPoint::OnLoad), 0);
    }

    // ── InProcessIpcDispatcher ─────────────────────────────────────────────────

    #[test]
    fn test_ipc_dispatcher_method_names() {
        let d = InProcessIpcDispatcher::new();
        d.register("ping", |_| Ok(PluginValue::Null));
        d.register("pong", |_| Ok(PluginValue::Null));
        let mut names = d.method_names();
        names.sort();
        assert_eq!(names, vec!["ping", "pong"]);
    }

    #[test]
    fn test_ipc_dispatcher_unknown_method() {
        let d = InProcessIpcDispatcher::new();
        assert!(d.dispatch("unknown", PluginValue::Null).is_err());
    }

    #[test]
    fn test_ipc_dispatcher_debug() {
        let d = InProcessIpcDispatcher::new();
        let s = format!("{d:?}");
        assert!(s.contains("InProcessIpcDispatcher"));
    }
}
