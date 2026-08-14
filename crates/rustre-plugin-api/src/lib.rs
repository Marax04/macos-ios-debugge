// rustre-plugin-api/src/lib.rs
// Complete plugin SDK for RustRE

pub mod abi;
pub mod capabilities_extended;
pub mod host_compat;
pub mod plugin_context_api;
pub mod plugin_view_api;
pub mod plugin_script_api;
pub mod plugin_data_api;
pub mod hot_reload;
pub mod platform_provider;
pub mod plugin_events_full;
pub mod plugin_marketplace;
pub mod plugin_sdk;
pub mod sandbox;
pub mod type_provider;
pub mod plugin_manifest;
pub mod plugin_permission_model;
pub mod plugin_ipc_protocol;

pub use host_compat::{
    HookPoint, HookRegistry, HostPluginExt, HostPluginRegistry, IpcMessage, IpcResponse,
    PluginMeta, PluginSettings, PluginState, PluginValue, SettingValue,
};

/// Convenience alias used by the host: a plugin's category mirrors its
/// primary [`PluginCapability`].
pub type PluginCategory = PluginCapability;

use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

// Use rustre-core typed IDs so that plugin API function records can be
// correlated with the core binary view's function table without an extra
// lookup by address.
pub use rustre_core::ids::FunctionId as CoreFunctionId;

// ─── Version ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }

    #[must_use]
    pub fn is_compatible_with(&self, required: &Self) -> bool {
        self.major == required.major && *self >= *required
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub const RUSTRE_VERSION: Version = Version::new(0, 1, 0);

// ─── Plugin Capability ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginCapability {
    Loader,
    Architecture,
    AnalysisPass,
    Decompiler,
    DebugBackend,
    UiPanel,
    ScriptExtension,
    MlilTransform,
    HlilTransform,
    TypeProvider,
    CallingConvention,
    PlatformProvider,
    SignatureProvider,
    ThemeProvider,
    SymbolProvider,
    DataRenderer,
    Workflow,
    HighlightProvider,
    SidebarProvider,
    NotificationHandler,
    FileModifier,
    ProjectHook,
}

impl PluginCapability {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Architecture => "architecture",
            Self::AnalysisPass => "analysis_pass",
            Self::Decompiler => "decompiler",
            Self::DebugBackend => "debug_backend",
            Self::UiPanel => "ui_panel",
            Self::ScriptExtension => "script_extension",
            Self::MlilTransform => "mlil_transform",
            Self::HlilTransform => "hlil_transform",
            Self::TypeProvider => "type_provider",
            Self::CallingConvention => "calling_convention",
            Self::PlatformProvider => "platform_provider",
            Self::SignatureProvider => "signature_provider",
            Self::ThemeProvider => "theme_provider",
            Self::SymbolProvider => "symbol_provider",
            Self::DataRenderer => "data_renderer",
            Self::Workflow => "workflow",
            Self::HighlightProvider => "highlight_provider",
            Self::SidebarProvider => "sidebar_provider",
            Self::NotificationHandler => "notification_handler",
            Self::FileModifier => "file_modifier",
            Self::ProjectHook => "project_hook",
        }
    }
}

// ─── Plugin Manifest ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PluginManifest {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub author: String,
    pub license: String,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub capabilities: Vec<PluginCapability>,
    pub min_rustre_version: Version,
    pub dependencies: Vec<PluginDependency>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PluginDependency {
    pub name: String,
    pub version_req: String,
    pub optional: bool,
}

impl PluginManifest {
    /// Build a manifest from a host-side [`PluginMeta`] record.
    ///
    /// The textual `version` from the meta is parsed when possible; an
    /// unparseable version defaults to `0.0.0`.
    #[must_use]
    pub fn from_meta(meta: PluginMeta) -> Self {
        let version = Version::parse(&meta.version).unwrap_or(Version::new(0, 0, 0));
        let mut m = Self::new(&meta.name, version);
        m.description = meta.description;
        m.author = meta.author;
        m
    }

    #[must_use]
    pub fn new(name: &str, version: Version) -> Self {
        Self {
            name: name.to_string(),
            version,
            description: String::new(),
            author: String::new(),
            license: "MIT".to_string(),
            homepage: None,
            repository: None,
            capabilities: Vec::new(),
            min_rustre_version: Version::new(0, 1, 0),
            dependencies: Vec::new(),
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    #[must_use]
    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    #[must_use]
    pub fn with_capability(mut self, cap: PluginCapability) -> Self {
        self.capabilities.push(cap);
        self
    }

    #[must_use]
    pub fn with_dependency(mut self, dep: PluginDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    #[must_use]
    pub fn is_compatible(&self) -> bool {
        RUSTRE_VERSION.is_compatible_with(&self.min_rustre_version)
    }
}

// ─── Plugin Errors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PluginError {
    InitFailed(String),
    PermissionDenied(String),
    CapabilityNotSupported(PluginCapability),
    NotFound(String),
    AlreadyRegistered(String),
    Incompatible {
        plugin: String,
        required: Version,
        found: Version,
    },
    DependencyMissing(String),
    LoadError(String),
    UnloadError(String),
    ApiError(String),
    InvalidManifest(String),
    Serde(String),
}

impl std::error::Error for PluginError {}

impl From<serde_json::Error> for PluginError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitFailed(s) => write!(f, "Init failed: {s}"),
            Self::PermissionDenied(s) => write!(f, "Permission denied: {s}"),
            Self::CapabilityNotSupported(c) => {
                write!(f, "Capability not supported: {}", c.as_str())
            }
            Self::NotFound(s) => write!(f, "Not found: {s}"),
            Self::AlreadyRegistered(s) => write!(f, "Already registered: {s}"),
            Self::Incompatible {
                plugin,
                required,
                found,
            } => write!(
                f,
                "Plugin '{plugin}' requires rustre >={required} but found {found}"
            ),
            Self::DependencyMissing(s) => write!(f, "Missing dependency: {s}"),
            Self::LoadError(s) => write!(f, "Load error: {s}"),
            Self::UnloadError(s) => write!(f, "Unload error: {s}"),
            Self::ApiError(s) => write!(f, "API error: {s}"),
            Self::InvalidManifest(s) => write!(f, "Invalid manifest: {s}"),
            Self::Serde(s) => write!(f, "Serde error: {s}"),
        }
    }
}

pub type PluginResult<T> = std::result::Result<T, PluginError>;

// ─── Plugin ID ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginId(pub String);

impl PluginId {
    #[must_use]
    pub fn new(name: &str, version: &Version) -> Self {
        Self(format!("{name}@{version}"))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PluginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── Plugin Permissions ──────────────────────────────────────────────────────

/// Memory-related permission flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub write_memory: bool,
    pub execute_code: bool,
    pub modify_binary: bool,
}

/// Filesystem- and network-related permission flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoPermissions {
    pub read_filesystem: bool,
    pub write_filesystem: bool,
    pub access_network: bool,
}

/// Runtime-host related permission flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimePermissions {
    pub spawn_threads: bool,
    pub use_ui: bool,
    pub access_debugger: bool,
}

/// Analysis / extension permission flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnalysisPermissions {
    pub modify_graph: bool,
    pub register_commands: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PluginPermissions {
    pub memory: MemoryPermissions,
    pub io: IoPermissions,
    pub runtime: RuntimePermissions,
    pub analysis: AnalysisPermissions,
}

impl PluginPermissions {
    #[must_use]
    pub const fn can_write_memory(&self) -> bool {
        self.memory.write_memory
    }
    #[must_use]
    pub const fn can_execute_code(&self) -> bool {
        self.memory.execute_code
    }
    #[must_use]
    pub const fn can_modify_binary(&self) -> bool {
        self.memory.modify_binary
    }
    #[must_use]
    pub const fn can_read_filesystem(&self) -> bool {
        self.io.read_filesystem
    }
    #[must_use]
    pub const fn can_write_filesystem(&self) -> bool {
        self.io.write_filesystem
    }
    #[must_use]
    pub const fn can_access_network(&self) -> bool {
        self.io.access_network
    }
    #[must_use]
    pub const fn can_spawn_threads(&self) -> bool {
        self.runtime.spawn_threads
    }
    #[must_use]
    pub const fn can_use_ui(&self) -> bool {
        self.runtime.use_ui
    }
    #[must_use]
    pub const fn can_access_debugger(&self) -> bool {
        self.runtime.access_debugger
    }
    #[must_use]
    pub const fn can_modify_graph(&self) -> bool {
        self.analysis.modify_graph
    }
    #[must_use]
    pub const fn can_register_commands(&self) -> bool {
        self.analysis.register_commands
    }

    #[must_use]
    pub const fn all() -> Self {
        Self {
            memory: MemoryPermissions {
                write_memory: true,
                execute_code: true,
                modify_binary: true,
            },
            io: IoPermissions {
                read_filesystem: true,
                write_filesystem: true,
                access_network: true,
            },
            runtime: RuntimePermissions {
                spawn_threads: true,
                use_ui: true,
                access_debugger: true,
            },
            analysis: AnalysisPermissions {
                modify_graph: true,
                register_commands: true,
            },
        }
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self {
            io: IoPermissions {
                read_filesystem: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[must_use]
    pub fn analysis_only() -> Self {
        Self {
            io: IoPermissions {
                read_filesystem: true,
                ..Default::default()
            },
            analysis: AnalysisPermissions {
                modify_graph: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Render a comma-separated summary of which permission flags are
    /// currently granted. Useful for error messages and logging.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts: Vec<&'static str> = Vec::with_capacity(11);
        if self.memory.write_memory {
            parts.push("write_memory");
        }
        if self.memory.execute_code {
            parts.push("execute_code");
        }
        if self.io.access_network {
            parts.push("network");
        }
        if self.analysis.modify_graph {
            parts.push("modify_graph");
        }
        if self.io.read_filesystem {
            parts.push("read_fs");
        }
        if self.io.write_filesystem {
            parts.push("write_fs");
        }
        if self.runtime.spawn_threads {
            parts.push("spawn_threads");
        }
        if self.runtime.use_ui {
            parts.push("ui");
        }
        if self.runtime.access_debugger {
            parts.push("debugger");
        }
        if self.analysis.register_commands {
            parts.push("commands");
        }
        if self.memory.modify_binary {
            parts.push("modify_binary");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(",")
        }
    }
}

// ─── Event Bus ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PluginEvent {
    BinaryOpened {
        path: String,
    },
    BinaryAnalyzed,
    FunctionAdded {
        addr: u64,
    },
    FunctionRemoved {
        addr: u64,
    },
    FunctionRenamed {
        addr: u64,
        old: String,
        new: String,
    },
    DataDefined {
        addr: u64,
        size: usize,
    },
    CommentAdded {
        addr: u64,
        comment: String,
    },
    TypeDefined {
        name: String,
    },
    PluginLoaded {
        id: PluginId,
    },
    PluginUnloaded {
        id: PluginId,
    },
    AnalysisStarted,
    AnalysisFinished,
    DebuggerAttached {
        pid: u32,
    },
    DebuggerDetached,
    Breakpoint {
        addr: u64,
    },
    Custom {
        name: String,
        payload: HashMap<String, String>,
    },
}

pub type EventHandler = Box<dyn Fn(&PluginEvent) + Send + Sync + 'static>;

#[derive(Default)]
pub struct EventBus {
    handlers: RwLock<Vec<(String, EventHandler)>>,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    ///
    /// # Panics
    ///
    /// Panics if the handlers lock is poisoned.
    pub fn subscribe(&self, event_name: &str, handler: EventHandler) {
        self.handlers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push((event_name.to_string(), handler));
    }

    pub fn publish(&self, event: &PluginEvent) {
        let event_name = event_name(event);
        for (filter, handler) in self.handlers.read().unwrap_or_else(|e| e.into_inner()).iter() {
            if filter == "*" || filter == event_name {
                handler(event);
            }
        }
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

const fn event_name(event: &PluginEvent) -> &'static str {
    match event {
        PluginEvent::BinaryOpened { .. } => "binary_opened",
        PluginEvent::BinaryAnalyzed => "binary_analyzed",
        PluginEvent::FunctionAdded { .. } => "function_added",
        PluginEvent::FunctionRemoved { .. } => "function_removed",
        PluginEvent::FunctionRenamed { .. } => "function_renamed",
        PluginEvent::DataDefined { .. } => "data_defined",
        PluginEvent::CommentAdded { .. } => "comment_added",
        PluginEvent::TypeDefined { .. } => "type_defined",
        PluginEvent::PluginLoaded { .. } => "plugin_loaded",
        PluginEvent::PluginUnloaded { .. } => "plugin_unloaded",
        PluginEvent::AnalysisStarted => "analysis_started",
        PluginEvent::AnalysisFinished => "analysis_finished",
        PluginEvent::DebuggerAttached { .. } => "debugger_attached",
        PluginEvent::DebuggerDetached => "debugger_detached",
        PluginEvent::Breakpoint { .. } => "breakpoint",
        PluginEvent::Custom { .. } => "custom",
    }
}

// ─── Logger ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

pub struct PluginLogger {
    pub plugin_name: String,
    pub min_level: LogLevel,
    messages: Arc<Mutex<Vec<(LogLevel, String)>>>,
}

impl PluginLogger {
    #[must_use]
    pub fn new(plugin_name: &str) -> Self {
        Self {
            plugin_name: plugin_name.to_string(),
            min_level: LogLevel::Info,
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    ///
    /// # Panics
    ///
    /// Panics if the internal messages mutex is poisoned.
    pub fn log(&self, level: LogLevel, msg: &str) {
        if level >= self.min_level {
            let formatted = format!("[{}][{}] {}", self.plugin_name, level.as_str(), msg);
            self.messages.lock().unwrap().push((level, formatted));
        }
    }

    pub fn trace(&self, msg: &str) {
        self.log(LogLevel::Trace, msg);
    }
    pub fn debug(&self, msg: &str) {
        self.log(LogLevel::Debug, msg);
    }
    pub fn info(&self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }
    pub fn warn(&self, msg: &str) {
        self.log(LogLevel::Warn, msg);
    }
    pub fn error(&self, msg: &str) {
        self.log(LogLevel::Error, msg);
    }

    ///
    /// # Panics
    ///
    /// Panics if the internal messages mutex is poisoned.
    #[must_use]
    pub fn messages(&self) -> Vec<(LogLevel, String)> {
        self.messages.lock().unwrap().clone()
    }

    ///
    /// # Panics
    ///
    /// Panics if the internal messages mutex is poisoned.
    pub fn clear(&self) {
        self.messages.lock().unwrap().clear();
    }
}

// ─── Plugin Storage ──────────────────────────────────────────────────────────

#[derive(Default)]
pub struct PluginStorage {
    data: HashMap<String, Vec<u8>>,
    path: Option<PathBuf>,
}

impl PluginStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            data: HashMap::new(),
            path: Some(path),
        }
    }

    /// # Panics
    ///
    /// Panics if `key` contains the `'='` character, which would corrupt the
    /// persisted store format.
    pub fn set(&mut self, key: &str, value: Vec<u8>) {
        assert!(
            !key.contains('='),
            "PluginStorage key must not contain '=': key was {key:?}"
        );
        self.data.insert(key.to_string(), value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.data.get(key).map(std::vec::Vec::as_slice)
    }

    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.data.remove(key)
    }

    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.data.keys().cloned().collect()
    }

    pub fn set_str(&mut self, key: &str, value: &str) {
        self.set(key, value.as_bytes().to_vec());
    }

    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|v| String::from_utf8_lossy(v).to_string())
    }

    ///
    /// # Errors
    ///
    /// Returns an error if writing the persisted store to disk fails.
    pub fn persist(&self) -> PluginResult<()> {
        use std::fmt::Write as _;
        if let Some(ref path) = self.path {
            let mut lines = Vec::with_capacity(self.data.len());
            for (k, v) in &self.data {
                let mut v_hex = String::with_capacity(v.len() * 2);
                for b in v {
                    write!(v_hex, "{b:02x}").expect("writing to String cannot fail");
                }
                lines.push(format!("{k}={v_hex}"));
            }
            std::fs::write(path, lines.join("\n"))
                .map_err(|e| PluginError::ApiError(e.to_string()))?;
        }
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error if reading or parsing the persisted store fails.
    pub fn load(&mut self) -> PluginResult<()> {
        if let Some(ref path) = self.path.clone()
            && path.exists()
        {
            let content =
                std::fs::read_to_string(path).map_err(|e| PluginError::ApiError(e.to_string()))?;
            for line in content.lines() {
                if let Some((k, v_hex)) = line.split_once('=') {
                    // Guard against odd-length hex strings: each byte needs
                    // exactly two hex digits; an odd-length string would make
                    // `&v_hex[i..i+2]` panic at the last iteration.
                    let bytes: Vec<u8> = if v_hex.len() % 2 != 0 {
                        Vec::new()
                    } else {
                        (0..v_hex.len())
                            .step_by(2)
                            .filter_map(|i| u8::from_str_radix(&v_hex[i..i + 2], 16).ok())
                            .collect()
                    };
                    self.data.insert(k.to_string(), bytes);
                }
            }
        }
        Ok(())
    }
}

// ─── Command Registry ────────────────────────────────────────────────────────

pub type CommandFn = Box<dyn Fn(Vec<String>) -> PluginResult<String> + Send + Sync + 'static>;

pub struct CommandEntry {
    pub name: String,
    pub description: String,
    pub usage: String,
    pub handler: CommandFn,
}

#[derive(Default)]
pub struct CommandRegistry {
    commands: HashMap<String, CommandEntry>,
}

impl CommandRegistry {
    pub fn register(&mut self, name: &str, description: &str, usage: &str, handler: CommandFn) {
        self.commands.insert(
            name.to_string(),
            CommandEntry {
                name: name.to_string(),
                description: description.to_string(),
                usage: usage.to_string(),
                handler,
            },
        );
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the command does not exist or the handler returns an error.
    pub fn dispatch(&self, name: &str, args: Vec<String>) -> PluginResult<String> {
        self.commands
            .get(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))
            .and_then(|e| (e.handler)(args))
    }

    #[must_use]
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.commands
            .values()
            .map(|e| (e.name.as_str(), e.description.as_str()))
            .collect()
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.commands.contains_key(name)
    }
}

// ─── Plugin Context ──────────────────────────────────────────────────────────

pub struct PluginContext {
    pub manifest: PluginManifest,
    pub permissions: PluginPermissions,
    pub logger: PluginLogger,
    pub storage: PluginStorage,
    pub events: Arc<EventBus>,
    pub commands: CommandRegistry,
    pub user_data: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl PluginContext {
    pub fn new(
        manifest: PluginManifest,
        permissions: PluginPermissions,
        events: Arc<EventBus>,
    ) -> Self {
        let logger = PluginLogger::new(&manifest.name);
        Self {
            storage: PluginStorage::new(),
            logger,
            manifest,
            permissions,
            events,
            commands: CommandRegistry::default(),
            user_data: HashMap::new(),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns [`PluginError::PermissionDenied`] when the requested permission is not granted.
    pub fn require_permission(&self, what: &str) -> PluginResult<()> {
        let ok = match what {
            "write_memory" => self.permissions.can_write_memory(),
            "execute_code" => self.permissions.can_execute_code(),
            "access_network" => self.permissions.can_access_network(),
            "modify_graph" => self.permissions.can_modify_graph(),
            "read_filesystem" => self.permissions.can_read_filesystem(),
            "write_filesystem" => self.permissions.can_write_filesystem(),
            "spawn_threads" => self.permissions.can_spawn_threads(),
            "use_ui" => self.permissions.can_use_ui(),
            "access_debugger" => self.permissions.can_access_debugger(),
            "register_commands" => self.permissions.can_register_commands(),
            "modify_binary" => self.permissions.can_modify_binary(),
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(PluginError::PermissionDenied(what.to_string()))
        }
    }

    /// Publish an event to the plugin event bus.
    pub fn publish_event(&self, event: &PluginEvent) {
        self.events.publish(event);
    }

    ///
    /// # Errors
    ///
    /// Returns an error if a command with that name is already registered.
    pub fn register_command(
        &mut self,
        name: &str,
        description: &str,
        usage: &str,
        handler: CommandFn,
    ) -> PluginResult<()> {
        self.require_permission("register_commands")?;
        self.commands.register(name, description, usage, handler);
        Ok(())
    }

    pub fn log_info(&self, msg: &str) {
        self.logger.info(msg);
    }
    pub fn log_warn(&self, msg: &str) {
        self.logger.warn(msg);
    }
    pub fn log_error(&self, msg: &str) {
        self.logger.error(msg);
    }
    pub fn log_debug(&self, msg: &str) {
        self.logger.debug(msg);
    }

    pub fn store_data(&mut self, key: &str, value: Vec<u8>) {
        self.storage.set(key, value);
    }

    #[must_use]
    pub fn retrieve_data(&self, key: &str) -> Option<&[u8]> {
        self.storage.get(key)
    }

    #[must_use]
    pub fn plugin_name(&self) -> &str {
        &self.manifest.name
    }
    #[must_use]
    pub const fn plugin_version(&self) -> &Version {
        &self.manifest.version
    }
    #[must_use]
    pub fn has_capability(&self, cap: &PluginCapability) -> bool {
        self.manifest.capabilities.contains(cap)
    }
}

// ─── Plugin Trait ─────────────────────────────────────────────────────────────

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &Version;
    fn capabilities(&self) -> Vec<PluginCapability>;
    fn manifest(&self) -> PluginManifest;
    ///
    /// # Errors
    ///
    /// Returns an error if plugin initialization fails.
    fn init(&self, ctx: &mut PluginContext) -> PluginResult<()>;
    fn unload(&self, ctx: &mut PluginContext);
    fn as_any(&self) -> &dyn Any;
}

// ─── Sub-Plugin Traits ────────────────────────────────────────────────────────

/// A loader plugin can probe and load binary formats.
pub trait LoaderPlugin: Plugin {
    /// Returns 0-100 confidence score (100 = perfect match).
    fn probe(&self, bytes: &[u8]) -> u8;
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be loaded as a binary view.
    fn load(&self, input: LoaderInput) -> PluginResult<BinaryViewInfo>;
    fn supported_extensions(&self) -> Vec<&str>;
}

#[derive(Debug, Clone)]
pub struct LoaderInput {
    pub path: Option<PathBuf>,
    pub data: Vec<u8>,
    pub base_addr: Option<u64>,
    pub entry_point: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BinaryViewInfo {
    pub arch: String,
    pub platform: String,
    pub entry_point: u64,
    pub base_address: u64,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub start: u64,
    pub length: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Section,
    Label,
    External,
}

/// An architecture plugin provides disassembly and lifting.
pub trait ArchPlugin: Plugin {
    fn arch_name(&self) -> &str;
    fn address_size(&self) -> usize;
    fn default_integer_size(&self) -> usize;
    ///
    /// # Errors
    ///
    /// Returns an error if disassembly fails.
    fn disassemble(&self, data: &[u8], addr: u64) -> PluginResult<Vec<DisasmInsn>>;
    fn is_valid_function_start(&self, data: &[u8]) -> bool;
    ///
    /// # Errors
    ///
    /// Returns an error if the instruction cannot be decoded.
    fn get_instruction_text(&self, data: &[u8], addr: u64) -> PluginResult<String>;
    fn get_flag_role(&self, flag: u32) -> FlagRole;
}

#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub address: u64,
    pub length: usize,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub text: String,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_branch: bool,
    pub is_unconditional_branch: bool,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagRole {
    Zero,
    Sign,
    Overflow,
    Carry,
    Parity,
    Adjust,
    Special,
    Unknown,
}

/// An analysis pass plugin.
pub trait AnalysisPlugin: Plugin {
    fn pass_name(&self) -> &str;
    ///
    /// # Errors
    ///
    /// Returns an error if the analysis pass fails on the given function.
    fn run_on_function(
        &self,
        func: &mut FunctionInfo,
        ctx: &PluginContext,
    ) -> PluginResult<AnalysisReport>;
    ///
    /// # Errors
    ///
    /// Returns an error if the analysis pass fails on the binary.
    fn run_on_binary(&self, ctx: &PluginContext) -> PluginResult<AnalysisReport>;
    fn requires_passes(&self) -> Vec<&str>;
    fn provides_tags(&self) -> Vec<&str>;
}

#[derive(Debug, Clone, Default)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub length: usize,
    pub arch: String,
    pub tags: Vec<String>,
    pub properties: HashMap<String, String>,
    /// Optional typed ID from `rustre-core`'s function table, allowing
    /// plugins to cross-reference this record with the host binary view
    /// without a secondary lookup by address.
    pub core_id: Option<CoreFunctionId>,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisReport {
    pub pass_name: String,
    pub functions_analyzed: usize,
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub address: u64,
    pub kind: FindingKind,
    pub description: String,
    pub confidence: u8,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    Vulnerability,
    CryptoUsage,
    AntiAnalysis,
    NetworkCommunication,
    FileOperation,
    RegistryOperation,
    ProcessOperation,
    Obfuscation,
    Packing,
    Shellcode,
    RansomwareBehavior,
    Credential,
    InfoLeak,
    General,
}

/// A decompiler plugin.
pub trait DecompilerPlugin: Plugin {
    ///
    /// # Errors
    ///
    /// Returns an error if decompilation fails.
    fn decompile_function(
        &self,
        func: &FunctionInfo,
        ctx: &PluginContext,
    ) -> PluginResult<DecompilationResult>;
    fn supported_archs(&self) -> Vec<&str>;
    fn language(&self) -> &str;
}

#[derive(Debug, Clone)]
pub struct DecompilationResult {
    pub code: String,
    pub language: String,
    pub address: u64,
    pub function_name: String,
    pub annotations: Vec<CodeAnnotation>,
}

#[derive(Debug, Clone)]
pub struct CodeAnnotation {
    pub line: usize,
    pub column: usize,
    pub text: String,
    pub kind: AnnotationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationKind {
    Comment,
    Warning,
    Error,
    Info,
    Highlight,
}

/// A debug backend plugin.
pub trait DebugPlugin: Plugin {
    ///
    /// # Errors
    ///
    /// Returns an error if attaching to the debug target fails.
    fn attach(&mut self, target: DebugTarget) -> PluginResult<DebugSession>;
    ///
    /// # Errors
    ///
    /// Returns an error if detaching from the session fails.
    fn detach(&mut self, session: &DebugSession) -> PluginResult<()>;
    fn supported_platforms(&self) -> Vec<&str>;
}

#[derive(Debug, Clone)]
pub enum DebugTarget {
    Pid(u32),
    ProcessName(String),
    RemoteTcp { host: String, port: u16 },
    Core { path: PathBuf },
    Launch { path: PathBuf, args: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct DebugSession {
    pub session_id: String,
    pub target: DebugTarget,
    pub pid: Option<u32>,
}

/// A UI panel plugin (framework-agnostic).
pub trait UiPanelPlugin: Plugin {
    fn panel_title(&self) -> &str;
    fn panel_id(&self) -> &str;
    ///
    /// # Errors
    ///
    /// Returns an error if rendering the UI panel fails.
    fn render(&self, ctx: &PluginContext) -> PluginResult<String>;
    ///
    /// # Errors
    ///
    /// Returns an error if handling the UI action fails.
    fn on_action(
        &mut self,
        action: &str,
        payload: &HashMap<String, String>,
    ) -> PluginResult<String>;
}

/// A script extension plugin.
pub trait ScriptPlugin: Plugin {
    fn language(&self) -> &str;
    fn file_extensions(&self) -> Vec<&str>;
    ///
    /// # Errors
    ///
    /// Returns an error if executing the script fails.
    fn execute(&self, code: &str, ctx: &mut PluginContext) -> PluginResult<String>;
    ///
    /// # Errors
    ///
    /// Returns an error if evaluating the line in the REPL fails.
    fn repl_eval(&self, line: &str, ctx: &mut PluginContext) -> PluginResult<String>;
}

// ─── Plugin Registry ──────────────────────────────────────────────────────────

pub struct PluginRegistry {
    plugins: HashMap<PluginId, Arc<dyn Plugin>>,
    contexts: HashMap<PluginId, PluginContext>,
    load_order: Vec<PluginId>,
    events: Arc<EventBus>,
}

impl PluginRegistry {
    pub fn new(events: Arc<EventBus>) -> Self {
        Self {
            plugins: HashMap::new(),
            contexts: HashMap::new(),
            load_order: Vec::new(),
            events,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if registration fails (e.g. duplicate id).
    pub fn register(
        &mut self,
        plugin: Arc<dyn Plugin>,
        permissions: PluginPermissions,
    ) -> PluginResult<PluginId> {
        let manifest = plugin.manifest();
        let id = PluginId::new(&manifest.name, &manifest.version);

        if self.plugins.contains_key(&id) {
            return Err(PluginError::AlreadyRegistered(id.to_string()));
        }

        if !manifest.is_compatible() {
            return Err(PluginError::Incompatible {
                plugin: manifest.name.clone(),
                required: manifest.min_rustre_version,
                found: RUSTRE_VERSION.clone(),
            });
        }

        let mut ctx = PluginContext::new(manifest, permissions, self.events.clone());
        plugin.init(&mut ctx)?;

        ctx.logger
            .info(&format!("Plugin '{}' initialized", plugin.name()));
        self.events
            .publish(&PluginEvent::PluginLoaded { id: id.clone() });

        self.load_order.push(id.clone());
        self.plugins.insert(id.clone(), plugin);
        self.contexts.insert(id.clone(), ctx);

        Ok(id)
    }

    ///
    /// # Errors
    ///
    /// Returns [`PluginError::NotFound`] if no plugin with that id is registered.
    pub fn unregister(&mut self, id: &PluginId) -> PluginResult<()> {
        let plugin = self
            .plugins
            .remove(id)
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;
        if let Some(mut ctx) = self.contexts.remove(id) {
            plugin.unload(&mut ctx);
        }
        self.load_order.retain(|i| i != id);
        self.events
            .publish(&PluginEvent::PluginUnloaded { id: id.clone() });
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &PluginId) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(id).cloned()
    }

    #[must_use]
    pub fn get_context(&self, id: &PluginId) -> Option<&PluginContext> {
        self.contexts.get(id)
    }

    pub fn get_context_mut(&mut self, id: &PluginId) -> Option<&mut PluginContext> {
        self.contexts.get_mut(id)
    }

    #[must_use]
    pub fn list(&self) -> Vec<&PluginId> {
        self.load_order.iter().collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    #[must_use]
    pub fn find_by_capability(&self, cap: &PluginCapability) -> Vec<Arc<dyn Plugin>> {
        self.plugins
            .values()
            .filter(|p| p.capabilities().contains(cap))
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.values().find(|p| p.name() == name).cloned()
    }

    ///
    /// # Errors
    ///
    /// Returns [`PluginError::LoadError`] because dynamic loading is not implemented.
    pub fn load_from_file(
        &mut self,
        path: &Path,
        permissions: &PluginPermissions,
    ) -> PluginResult<PluginId> {
        // In a real implementation this would:
        // 1. dlopen / LoadLibrary the .so / .dll
        // 2. look up `rustre_plugin_register` symbol
        // 3. call it to get the Plugin trait object with the requested
        //    `permissions` granted to its sandbox.
        // For now return a load error indicating no-op, but include the
        // requested permission summary so the message is actionable.
        Err(PluginError::LoadError(format!(
            "Dynamic loading from '{}' (requested permissions: {}) requires the 'dynamic-plugins' feature",
            path.display(),
            permissions.summary(),
        )))
    }
}

// ─── Plugin Host Manager ─────────────────────────────────────────────────────

pub struct PluginHostManager {
    pub registry: PluginRegistry,
    watch_paths: Vec<PathBuf>,
    auto_permissions: PluginPermissions,
}

impl PluginHostManager {
    pub fn new(events: Arc<EventBus>) -> Self {
        Self {
            registry: PluginRegistry::new(events),
            watch_paths: vec![PathBuf::from("./plugins"), dirs_home_plugins()],
            auto_permissions: PluginPermissions::analysis_only(),
        }
    }

    pub fn add_watch_path(&mut self, path: PathBuf) {
        self.watch_paths.push(path);
    }

    pub const fn set_default_permissions(&mut self, perms: PluginPermissions) {
        self.auto_permissions = perms;
    }

    pub fn scan_and_load(&mut self) -> Vec<PluginResult<PluginId>> {
        let mut results = Vec::new();
        let paths = self.watch_paths.clone();
        for dir in &paths {
            if !dir.exists() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "dll" || ext == "so" || ext == "dylib" {
                    let perms = self.auto_permissions.clone();
                    results.push(self.registry.load_from_file(&path, &perms));
                }
            }
        }
        results
    }

    ///
    /// # Errors
    ///
    /// Returns an error if registration with the underlying registry fails.
    pub fn register_plugin(
        &mut self,
        plugin: Arc<dyn Plugin>,
        permissions: PluginPermissions,
    ) -> PluginResult<PluginId> {
        self.registry.register(plugin, permissions)
    }

    #[must_use]
    pub fn watch_paths(&self) -> &[PathBuf] {
        &self.watch_paths
    }
}

fn dirs_home_plugins() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_or_else(
            |_| PathBuf::from(".rustre/plugins"),
            |home| PathBuf::from(home).join(".rustre").join("plugins"),
        )
}

// ─── Dynamic Library ABI ─────────────────────────────────────────────────────

/// The entry point that every plugin .so/.dll must export.
/// Signature: `extern "C" fn rustre_plugin_register(registry: *mut PluginRegistry)`
pub type PluginRegisterFn = unsafe extern "C" fn(*mut PluginRegistry);

/// Magic bytes at the start of a rustre plugin shared library (documentation only).
pub const PLUGIN_MAGIC: [u8; 8] = *b"RUSTREP\0";

// ─── Concrete Stub Plugin ────────────────────────────────────────────────────

/// A minimal stub plugin useful for testing.
pub struct StubPlugin {
    pub name_val: String,
    pub version_val: Version,
    pub caps: Vec<PluginCapability>,
    pub init_result: bool,
}

impl StubPlugin {
    #[must_use]
    pub fn new(name: &str, version: Version) -> Self {
        Self {
            name_val: name.to_string(),
            version_val: version,
            caps: Vec::new(),
            init_result: true,
        }
    }

    #[must_use]
    pub fn with_capability(mut self, cap: PluginCapability) -> Self {
        self.caps.push(cap);
        self
    }

    #[must_use]
    pub const fn fail_init(mut self) -> Self {
        self.init_result = false;
        self
    }
}

impl Plugin for StubPlugin {
    fn name(&self) -> &str {
        &self.name_val
    }
    fn version(&self) -> &Version {
        &self.version_val
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        self.caps.clone()
    }
    fn manifest(&self) -> PluginManifest {
        PluginManifest::new(&self.name_val, self.version_val.clone())
            .with_description("stub plugin")
    }
    fn init(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        if self.init_result {
            ctx.logger.info("StubPlugin initialized");
            Ok(())
        } else {
            Err(PluginError::InitFailed("Configured to fail".to_string()))
        }
    }
    fn unload(&self, ctx: &mut PluginContext) {
        ctx.logger.info("StubPlugin unloaded");
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─── Stub Loader Plugin ───────────────────────────────────────────────────────

pub struct StubLoaderPlugin {
    pub base: StubPlugin,
    pub confidence_val: u8,
    pub magic: Vec<u8>,
}

impl StubLoaderPlugin {
    #[must_use]
    pub fn new(name: &str, magic: Vec<u8>, confidence: u8) -> Self {
        let mut base = StubPlugin::new(name, Version::new(0, 1, 0));
        base.caps = vec![PluginCapability::Loader];
        Self {
            base,
            confidence_val: confidence,
            magic,
        }
    }
}

impl Plugin for StubLoaderPlugin {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn version(&self) -> &Version {
        self.base.version()
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        self.base.capabilities()
    }
    fn manifest(&self) -> PluginManifest {
        self.base.manifest()
    }
    fn init(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.base.init(ctx)
    }
    fn unload(&self, ctx: &mut PluginContext) {
        self.base.unload(ctx);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl LoaderPlugin for StubLoaderPlugin {
    fn probe(&self, bytes: &[u8]) -> u8 {
        if bytes.starts_with(&self.magic) {
            self.confidence_val
        } else {
            0
        }
    }
    fn load(&self, input: LoaderInput) -> PluginResult<BinaryViewInfo> {
        Ok(BinaryViewInfo {
            arch: "x86_64".to_string(),
            platform: "linux".to_string(),
            entry_point: input.entry_point.unwrap_or(0x1000),
            base_address: input.base_addr.unwrap_or(0),
            sections: Vec::new(),
            symbols: Vec::new(),
        })
    }
    fn supported_extensions(&self) -> Vec<&str> {
        vec!["bin"]
    }
}

// ─── Stub Analysis Plugin ─────────────────────────────────────────────────────

pub struct StubAnalysisPlugin {
    pub base: StubPlugin,
    pub finding_addr: u64,
}

impl StubAnalysisPlugin {
    #[must_use]
    pub fn new(name: &str) -> Self {
        let mut base = StubPlugin::new(name, Version::new(0, 1, 0));
        base.caps = vec![PluginCapability::AnalysisPass];
        Self {
            base,
            finding_addr: 0,
        }
    }
}

impl Plugin for StubAnalysisPlugin {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn version(&self) -> &Version {
        self.base.version()
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        self.base.capabilities()
    }
    fn manifest(&self) -> PluginManifest {
        self.base.manifest()
    }
    fn init(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.base.init(ctx)
    }
    fn unload(&self, ctx: &mut PluginContext) {
        self.base.unload(ctx);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AnalysisPlugin for StubAnalysisPlugin {
    fn pass_name(&self) -> &str {
        self.base.name()
    }
    fn run_on_function(
        &self,
        func: &mut FunctionInfo,
        _ctx: &PluginContext,
    ) -> PluginResult<AnalysisReport> {
        Ok(AnalysisReport {
            pass_name: self.pass_name().to_string(),
            functions_analyzed: 1,
            findings: vec![Finding {
                address: func.address + self.finding_addr,
                kind: FindingKind::General,
                description: "stub finding".to_string(),
                confidence: 50,
                tags: Vec::new(),
            }],
            duration_ms: 0,
        })
    }
    fn run_on_binary(&self, _ctx: &PluginContext) -> PluginResult<AnalysisReport> {
        Ok(AnalysisReport::default())
    }
    fn requires_passes(&self) -> Vec<&str> {
        Vec::new()
    }
    fn provides_tags(&self) -> Vec<&str> {
        Vec::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events() -> Arc<EventBus> {
        Arc::new(EventBus::new())
    }
    fn make_registry() -> PluginRegistry {
        PluginRegistry::new(make_events())
    }

    fn stub(name: &str) -> Arc<dyn Plugin> {
        Arc::new(StubPlugin::new(name, Version::new(0, 1, 0)))
    }

    // ── Version ───────────────────────────────────────────────────────────

    #[test]
    fn test_version_display() {
        let v = Version::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v, Version::new(1, 2, 3));
    }

    #[test]
    fn test_version_compatible() {
        let v = Version::new(0, 2, 0);
        let req = Version::new(0, 1, 0);
        assert!(v.is_compatible_with(&req));
    }

    #[test]
    fn test_version_incompatible_major() {
        let v = Version::new(1, 0, 0);
        let req = Version::new(0, 1, 0);
        assert!(!v.is_compatible_with(&req));
    }

    #[test]
    fn test_version_ordering() {
        assert!(Version::new(1, 0, 0) > Version::new(0, 9, 9));
        assert!(Version::new(0, 2, 0) > Version::new(0, 1, 9));
    }

    // ── Manifest ──────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_builder() {
        let m = PluginManifest::new("test", Version::new(1, 0, 0))
            .with_description("A test plugin")
            .with_author("Alice")
            .with_capability(PluginCapability::Loader);
        assert_eq!(m.name, "test");
        assert_eq!(m.description, "A test plugin");
        assert!(m.capabilities.contains(&PluginCapability::Loader));
    }

    #[test]
    fn test_manifest_compatible() {
        let m = PluginManifest::new("test", Version::new(0, 1, 0));
        assert!(m.is_compatible());
    }

    // ── Plugin Registry ───────────────────────────────────────────────────

    #[test]
    fn test_register_plugin() {
        let mut reg = make_registry();
        let id = reg
            .register(stub("my_plugin"), PluginPermissions::all())
            .unwrap();
        assert!(id.as_str().contains("my_plugin"));
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_register_duplicate_fails() {
        let mut reg = make_registry();
        reg.register(stub("dup"), PluginPermissions::all()).unwrap();
        let r = reg.register(stub("dup"), PluginPermissions::all());
        assert!(r.is_err());
    }

    #[test]
    fn test_unregister_plugin() {
        let mut reg = make_registry();
        let id = reg
            .register(stub("to_remove"), PluginPermissions::all())
            .unwrap();
        reg.unregister(&id).unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_unregister_not_found() {
        let mut reg = make_registry();
        let fake_id = PluginId("fake@0.0.0".to_string());
        assert!(reg.unregister(&fake_id).is_err());
    }

    #[test]
    fn test_find_by_capability() {
        let mut reg = make_registry();
        let loader = Arc::new(
            StubPlugin::new("loader_p", Version::new(0, 1, 0))
                .with_capability(PluginCapability::Loader),
        );
        reg.register(loader, PluginPermissions::all()).unwrap();
        let found = reg.find_by_capability(&PluginCapability::Loader);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_by_capability_empty() {
        let reg = make_registry();
        assert!(
            reg.find_by_capability(&PluginCapability::Decompiler)
                .is_empty()
        );
    }

    #[test]
    fn test_find_by_name() {
        let mut reg = make_registry();
        reg.register(stub("named_plugin"), PluginPermissions::all())
            .unwrap();
        assert!(reg.find_by_name("named_plugin").is_some());
        assert!(reg.find_by_name("unknown").is_none());
    }

    #[test]
    fn test_list_order() {
        let mut reg = make_registry();
        reg.register(stub("alpha"), PluginPermissions::all())
            .unwrap();
        reg.register(stub("beta"), PluginPermissions::all())
            .unwrap();
        let list = reg.list();
        assert_eq!(list.len(), 2);
    }

    // ── Init failure ──────────────────────────────────────────────────────

    #[test]
    fn test_init_failure() {
        let mut reg = make_registry();
        let p = Arc::new(StubPlugin::new("fail", Version::new(0, 1, 0)).fail_init());
        let r = reg.register(p, PluginPermissions::all());
        assert!(r.is_err());
    }

    // ── Plugin Context ────────────────────────────────────────────────────

    #[test]
    fn test_context_permissions_ok() {
        let events = make_events();
        let m = PluginManifest::new("ctx_test", Version::new(0, 1, 0));
        let ctx = PluginContext::new(m, PluginPermissions::all(), events);
        assert!(ctx.require_permission("write_memory").is_ok());
    }

    #[test]
    fn test_context_permissions_denied() {
        let events = make_events();
        let m = PluginManifest::new("ctx_test", Version::new(0, 1, 0));
        let ctx = PluginContext::new(m, PluginPermissions::read_only(), events);
        assert!(ctx.require_permission("write_memory").is_err());
    }

    #[test]
    fn test_context_logger() {
        let events = make_events();
        let m = PluginManifest::new("log_test", Version::new(0, 1, 0));
        let ctx = PluginContext::new(m, PluginPermissions::all(), events);
        ctx.log_info("hello");
        ctx.log_warn("warning");
        let msgs = ctx.logger.messages();
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn test_context_storage() {
        let events = make_events();
        let m = PluginManifest::new("storage_test", Version::new(0, 1, 0));
        let mut ctx = PluginContext::new(m, PluginPermissions::all(), events);
        ctx.store_data("key", b"value".to_vec());
        assert_eq!(ctx.retrieve_data("key"), Some(b"value".as_ref()));
    }

    // ── Event Bus ─────────────────────────────────────────────────────────

    #[test]
    fn test_event_subscribe_publish() {
        let bus = EventBus::new();
        let counter = Arc::new(Mutex::new(0u32));
        let c2 = counter.clone();
        bus.subscribe(
            "binary_opened",
            Box::new(move |_| {
                *c2.lock().unwrap() += 1;
            }),
        );
        bus.publish(&PluginEvent::BinaryOpened {
            path: "/tmp/a.bin".to_string(),
        });
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn test_event_wildcard() {
        let bus = EventBus::new();
        let counter = Arc::new(Mutex::new(0u32));
        let c2 = counter.clone();
        bus.subscribe(
            "*",
            Box::new(move |_| {
                *c2.lock().unwrap() += 1;
            }),
        );
        bus.publish(&PluginEvent::AnalysisStarted);
        bus.publish(&PluginEvent::AnalysisFinished);
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn test_event_bus_handler_count() {
        let bus = EventBus::new();
        bus.subscribe("*", Box::new(|_| {}));
        bus.subscribe("binary_opened", Box::new(|_| {}));
        assert_eq!(bus.handler_count(), 2);
    }

    // ── Logger ────────────────────────────────────────────────────────────

    #[test]
    fn test_logger_levels() {
        let logger = PluginLogger::new("test");
        logger.info("info msg");
        logger.warn("warn msg");
        let msgs = logger.messages();
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn test_logger_min_level() {
        let mut logger = PluginLogger::new("test");
        logger.min_level = LogLevel::Warn;
        logger.debug("should be filtered");
        logger.warn("should pass");
        let msgs = logger.messages();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn test_logger_clear() {
        let logger = PluginLogger::new("test");
        logger.info("msg");
        logger.clear();
        assert!(logger.messages().is_empty());
    }

    // ── Storage ───────────────────────────────────────────────────────────

    #[test]
    fn test_storage_str() {
        let mut s = PluginStorage::new();
        s.set_str("greeting", "hello");
        assert_eq!(s.get_str("greeting"), Some("hello".to_string()));
    }

    #[test]
    fn test_storage_remove() {
        let mut s = PluginStorage::new();
        s.set("k", b"v".to_vec());
        s.remove("k");
        assert!(!s.contains("k"));
    }

    #[test]
    fn test_storage_keys() {
        let mut s = PluginStorage::new();
        s.set("a", vec![1]);
        s.set("b", vec![2]);
        let mut keys = s.keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // ── Commands ──────────────────────────────────────────────────────────

    #[test]
    fn test_command_dispatch() {
        let mut reg = CommandRegistry::default();
        reg.register(
            "hello",
            "say hi",
            "hello [name]",
            Box::new(|args| {
                Ok(format!(
                    "Hello, {}!",
                    args.first().map_or("world", std::string::String::as_str)
                ))
            }),
        );
        let result = reg.dispatch("hello", vec!["Alice".to_string()]).unwrap();
        assert_eq!(result, "Hello, Alice!");
    }

    #[test]
    fn test_command_not_found() {
        let reg = CommandRegistry::default();
        assert!(reg.dispatch("nope", vec![]).is_err());
    }

    #[test]
    fn test_command_list() {
        let mut reg = CommandRegistry::default();
        reg.register("cmd1", "first", "", Box::new(|_| Ok(String::new())));
        reg.register("cmd2", "second", "", Box::new(|_| Ok(String::new())));
        assert_eq!(reg.list().len(), 2);
    }

    // ── Loader Plugin ─────────────────────────────────────────────────────

    #[test]
    fn test_loader_probe_match() {
        let p = StubLoaderPlugin::new("elf_loader", vec![0x7F, b'E', b'L', b'F'], 100);
        assert_eq!(p.probe(&[0x7F, b'E', b'L', b'F', 0, 0]), 100);
    }

    #[test]
    fn test_loader_probe_no_match() {
        let p = StubLoaderPlugin::new("elf_loader", vec![0x7F, b'E', b'L', b'F'], 100);
        assert_eq!(p.probe(b"MZ\x90\x00"), 0);
    }

    // ── Analysis Plugin ───────────────────────────────────────────────────

    #[test]
    fn test_analysis_plugin_run_on_function() {
        let events = make_events();
        let p = StubAnalysisPlugin::new("stub_analysis");
        let ctx = PluginContext::new(p.manifest(), PluginPermissions::all(), events);
        let mut func = FunctionInfo {
            name: "main".to_string(),
            address: 0x1000,
            ..Default::default()
        };
        let report = p.run_on_function(&mut func, &ctx).unwrap();
        assert_eq!(report.functions_analyzed, 1);
        assert!(!report.findings.is_empty());
    }

    // ── Plugin Capabilities ───────────────────────────────────────────────

    #[test]
    fn test_capability_as_str() {
        assert_eq!(PluginCapability::Loader.as_str(), "loader");
        assert_eq!(PluginCapability::Decompiler.as_str(), "decompiler");
        assert_eq!(PluginCapability::UiPanel.as_str(), "ui_panel");
    }

    #[test]
    fn test_plugin_id_display() {
        let id = PluginId::new("myplugin", &Version::new(1, 2, 3));
        assert_eq!(id.to_string(), "myplugin@1.2.3");
    }

    // ── Host Manager ──────────────────────────────────────────────────────

    #[test]
    fn test_host_manager_create() {
        let events = make_events();
        let mgr = PluginHostManager::new(events);
        assert!(!mgr.watch_paths().is_empty());
    }

    #[test]
    fn test_host_manager_register() {
        let events = make_events();
        let mut mgr = PluginHostManager::new(events);
        let id = mgr
            .register_plugin(stub("hosted_plugin"), PluginPermissions::all())
            .unwrap();
        assert!(id.as_str().contains("hosted_plugin"));
    }

    #[test]
    fn test_host_manager_scan_empty_dir() {
        let events = make_events();
        let mut mgr = PluginHostManager::new(events);
        mgr.watch_paths.clear();
        let tmp = std::env::temp_dir().join("rustre_plugin_test_empty_dir");
        let _ = std::fs::create_dir_all(&tmp);
        mgr.add_watch_path(tmp.clone());
        let results = mgr.scan_and_load();
        // No .dll/.so files in empty dir → 0 results
        assert_eq!(results.len(), 0);
        let _ = std::fs::remove_dir(&tmp);
    }

    // ── Permissions ───────────────────────────────────────────────────────

    #[test]
    fn test_permissions_all() {
        let p = PluginPermissions::all();
        assert!(p.can_write_memory());
        assert!(p.can_execute_code());
        assert!(p.can_access_network());
    }

    #[test]
    fn test_permissions_read_only() {
        let p = PluginPermissions::read_only();
        assert!(!p.can_write_memory());
        assert!(p.can_read_filesystem());
    }

    #[test]
    fn test_permissions_analysis_only() {
        let p = PluginPermissions::analysis_only();
        assert!(p.can_modify_graph());
        assert!(!p.can_access_network());
    }
}
