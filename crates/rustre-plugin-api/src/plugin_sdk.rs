//! `plugin_sdk` — Full SDK surface for `RustRE` plugin development.
//!
//! Provides [`PluginSdk`] as the central API object plus supporting types:
//! [`SdkVersion`], [`PluginManifest`], [`PluginCapability`], [`SdkContext`],
//! [`SdkAction`], and [`SdkEvent`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SdkVersion
// ─────────────────────────────────────────────────────────────────────────────

/// A semantic version for the plugin SDK.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SdkVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl SdkVersion {
    /// Current SDK version.
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
        pre: None,
    };

    /// Create a new version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    /// Parse from a string like "1.2.3" or "1.2.3-alpha".
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (core, pre) = s
            .find('-')
            .map_or((s, None), |idx| (&s[..idx], Some(s[idx + 1..].to_string())));
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() < 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
            pre,
        })
    }

    /// Return true if this version is compatible with `required`.
    ///
    /// Compatibility requires the same major version and `self >= required`.
    #[must_use]
    pub fn is_compatible_with(&self, required: &Self) -> bool {
        self.major == required.major && *self >= *required
    }

    /// Return true if this is a pre-release version.
    #[must_use]
    pub const fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }
}

impl fmt::Display for SdkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginCapability
// ─────────────────────────────────────────────────────────────────────────────

/// The capabilities a plugin can declare.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    Custom(String),
}

impl fmt::Display for PluginCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginManifest
// ─────────────────────────────────────────────────────────────────────────────

/// The metadata and requirements of a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: SdkVersion,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
    pub min_sdk_version: SdkVersion,
    pub dependencies: Vec<PluginDependency>,
    pub settings_schema: Option<serde_json::Value>,
    pub homepage: Option<String>,
    pub license: Option<String>,
}

/// A dependency on another plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub plugin_id: String,
    pub min_version: SdkVersion,
    pub optional: bool,
}

impl PluginManifest {
    /// Create a minimal manifest.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: SdkVersion) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version,
            author: String::new(),
            description: String::new(),
            capabilities: Vec::new(),
            min_sdk_version: SdkVersion::new(1, 0, 0),
            dependencies: Vec::new(),
            settings_schema: None,
            homepage: None,
            license: None,
        }
    }

    /// Add a capability.
    pub fn add_capability(&mut self, cap: PluginCapability) {
        self.capabilities.push(cap);
    }

    /// Check if this plugin is compatible with the given SDK version.
    #[must_use]
    pub fn is_sdk_compatible(&self, sdk_version: &SdkVersion) -> bool {
        sdk_version.is_compatible_with(&self.min_sdk_version)
    }

    /// Return true if the plugin has a specific capability.
    #[must_use]
    pub fn has_capability(&self, cap: &PluginCapability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Serialize to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if parsing fails.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SdkContext
// ─────────────────────────────────────────────────────────────────────────────

/// The context provided to a plugin via the SDK.
#[derive(Debug)]
pub struct SdkContext {
    pub sdk_version: SdkVersion,
    pub binary_path: Option<String>,
    pub arch: String,
    pub platform: String,
    pub settings: HashMap<String, SdkSettingValue>,
    pub metadata: HashMap<String, String>,
}

/// A settings value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SdkSettingValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<String>),
}

impl SdkContext {
    /// Create a new context.
    #[must_use]
    pub fn new(arch: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            sdk_version: SdkVersion::CURRENT.clone(),
            binary_path: None,
            arch: arch.into(),
            platform: platform.into(),
            settings: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set a boolean setting.
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.settings
            .insert(key.into(), SdkSettingValue::Bool(value));
    }

    /// Set an integer setting.
    pub fn set_int(&mut self, key: impl Into<String>, value: i64) {
        self.settings
            .insert(key.into(), SdkSettingValue::Int(value));
    }

    /// Set a string setting.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.settings
            .insert(key.into(), SdkSettingValue::String(value.into()));
    }

    /// Get a boolean setting.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.settings.get(key) {
            Some(SdkSettingValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Get an integer setting.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.settings.get(key) {
            Some(SdkSettingValue::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// Get a string setting.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.settings.get(key) {
            Some(SdkSettingValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Add metadata.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SdkAction
// ─────────────────────────────────────────────────────────────────────────────

/// An action that a plugin can register in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkAction {
    pub id: String,
    pub name: String,
    pub description: String,
    pub shortcut: Option<String>,
    pub category: String,
    pub icon: Option<String>,
    pub enabled: bool,
}

impl SdkAction {
    /// Create a new action.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            shortcut: None,
            category: "Plugin".to_string(),
            icon: None,
            enabled: true,
        }
    }

    /// Set a keyboard shortcut.
    #[must_use]
    pub fn with_shortcut(mut self, shortcut: impl Into<String>) -> Self {
        self.shortcut = Some(shortcut.into());
        self
    }

    /// Set the action category.
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    /// Disable the action.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SdkEvent
// ─────────────────────────────────────────────────────────────────────────────

/// An event emitted by the SDK to plugin subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SdkEvent {
    BinaryOpened {
        path: String,
        arch: String,
    },
    BinaryClosed {
        path: String,
    },
    AnalysisStarted,
    AnalysisCompleted {
        duration_ms: u64,
    },
    FunctionRenamed {
        address: u64,
        old_name: String,
        new_name: String,
    },
    CommentAdded {
        address: u64,
        comment: String,
    },
    TypeSet {
        address: u64,
        type_str: String,
    },
    NavigateTo {
        address: u64,
    },
    SelectionChanged {
        address: u64,
    },
    SettingChanged {
        key: String,
        value: serde_json::Value,
    },
    Custom {
        name: String,
        data: serde_json::Value,
    },
}

impl SdkEvent {
    /// Return the event name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BinaryOpened { .. } => "BinaryOpened",
            Self::BinaryClosed { .. } => "BinaryClosed",
            Self::AnalysisStarted => "AnalysisStarted",
            Self::AnalysisCompleted { .. } => "AnalysisCompleted",
            Self::FunctionRenamed { .. } => "FunctionRenamed",
            Self::CommentAdded { .. } => "CommentAdded",
            Self::TypeSet { .. } => "TypeSet",
            Self::NavigateTo { .. } => "NavigateTo",
            Self::SelectionChanged { .. } => "SelectionChanged",
            Self::SettingChanged { .. } => "SettingChanged",
            Self::Custom { .. } => "Custom",
        }
    }

    /// Return true if this event concerns a specific address.
    #[must_use]
    pub const fn address(&self) -> Option<u64> {
        match self {
            Self::FunctionRenamed { address, .. }
            | Self::CommentAdded { address, .. }
            | Self::TypeSet { address, .. }
            | Self::NavigateTo { address }
            | Self::SelectionChanged { address } => Some(*address),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventBus
// ─────────────────────────────────────────────────────────────────────────────

/// A simple synchronous event bus for SDK events.
#[derive(Debug, Default)]
pub struct EventBus {
    pub log: Vec<SdkEvent>,
    pub subscriber_count: usize,
}

impl EventBus {
    /// Create a new event bus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit an event (logs it for testing).
    pub fn emit(&mut self, event: SdkEvent) {
        self.log.push(event);
    }

    /// Return the event count.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.log.len()
    }

    /// Filter events by name.
    #[must_use]
    pub fn events_named(&self, name: &str) -> Vec<&SdkEvent> {
        self.log.iter().filter(|e| e.name() == name).collect()
    }

    /// Clear the event log.
    pub fn clear(&mut self) {
        self.log.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ActionRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of registered SDK actions.
#[derive(Debug, Default)]
pub struct ActionRegistry {
    pub actions: HashMap<String, SdkAction>,
}

impl ActionRegistry {
    /// Create a new registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an action.
    pub fn register(&mut self, action: SdkAction) {
        self.actions.insert(action.id.clone(), action);
    }

    /// Unregister an action by ID.
    pub fn unregister(&mut self, id: &str) {
        self.actions.remove(id);
    }

    /// Return the registered action count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Find an action by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SdkAction> {
        self.actions.get(id)
    }

    /// Return all enabled actions.
    #[must_use]
    pub fn enabled_actions(&self) -> Vec<&SdkAction> {
        self.actions.values().filter(|a| a.enabled).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginSdk — top-level SDK surface
// ─────────────────────────────────────────────────────────────────────────────

/// The primary SDK object provided to plugins at load time.
#[derive(Debug)]
pub struct PluginSdk {
    pub manifest: PluginManifest,
    pub context: SdkContext,
    pub actions: ActionRegistry,
    pub events: EventBus,
    pub initialized: bool,
}

impl PluginSdk {
    /// Create a new SDK instance for a plugin.
    #[must_use]
    pub fn new(manifest: PluginManifest, context: SdkContext) -> Self {
        Self {
            manifest,
            context,
            actions: ActionRegistry::new(),
            events: EventBus::new(),
            initialized: false,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an [`SdkError`] when initialization fails.
    pub fn initialize(&mut self) -> Result<(), SdkError> {
        if self.initialized {
            return Err(SdkError::AlreadyInitialized);
        }
        if !self.manifest.is_sdk_compatible(&self.context.sdk_version) {
            return Err(SdkError::IncompatibleSdkVersion {
                required: self.manifest.min_sdk_version.to_string(),
                provided: self.context.sdk_version.to_string(),
            });
        }
        self.initialized = true;
        self.events.emit(SdkEvent::AnalysisStarted);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an [`SdkError`] when registering the action fails.
    pub fn register_action(&mut self, action: SdkAction) -> Result<(), SdkError> {
        if !self.initialized {
            return Err(SdkError::NotInitialized);
        }
        self.actions.register(action);
        Ok(())
    }

    /// Emit an event.
    pub fn emit_event(&mut self, event: SdkEvent) {
        self.events.emit(event);
    }

    /// Get a setting from the context.
    #[must_use]
    pub fn get_setting(&self, key: &str) -> Option<&SdkSettingValue> {
        self.context.settings.get(key)
    }

    /// Return true if the plugin is initialized.
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.manifest.id
    }

    /// Return the SDK version.
    #[must_use]
    pub const fn sdk_version(&self) -> &SdkVersion {
        &self.context.sdk_version
    }
}

/// Errors produced by the SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    AlreadyInitialized,
    NotInitialized,
    IncompatibleSdkVersion { required: String, provided: String },
    ActionNotFound(String),
    PermissionDenied(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "SDK already initialized"),
            Self::NotInitialized => write!(f, "SDK not initialized"),
            Self::IncompatibleSdkVersion { required, provided } => {
                write!(
                    f,
                    "SDK version mismatch: required {required}, provided {provided}"
                )
            }
            Self::ActionNotFound(id) => write!(f, "action not found: {id}"),
            Self::PermissionDenied(p) => write!(f, "permission denied: {p}"),
        }
    }
}

impl std::error::Error for SdkError {}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> PluginManifest {
        let mut m = PluginManifest::new(
            "com.example.my_plugin",
            "My Plugin",
            SdkVersion::new(1, 0, 0),
        );
        m.add_capability(PluginCapability::AnalysisPass);
        m
    }

    fn sample_context() -> SdkContext {
        SdkContext::new("x86_64", "windows")
    }

    fn sample_sdk() -> PluginSdk {
        PluginSdk::new(sample_manifest(), sample_context())
    }

    // ── SdkVersion ────────────────────────────────────────────────────────────

    #[test]
    fn test_sdk_version_display() {
        let v = SdkVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_sdk_version_display_prerelease() {
        let v = SdkVersion {
            major: 1,
            minor: 0,
            patch: 0,
            pre: Some("beta.1".to_string()),
        };
        assert_eq!(v.to_string(), "1.0.0-beta.1");
    }

    #[test]
    fn test_sdk_version_parse() {
        let v = SdkVersion::parse("2.3.4").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 3);
        assert_eq!(v.patch, 4);
    }

    #[test]
    fn test_sdk_version_parse_prerelease() {
        let v = SdkVersion::parse("1.0.0-alpha").unwrap();
        assert_eq!(v.pre.as_deref(), Some("alpha"));
        assert!(v.is_prerelease());
    }

    #[test]
    fn test_sdk_version_parse_invalid() {
        assert!(SdkVersion::parse("not.a.version").is_none());
        assert!(SdkVersion::parse("1.2").is_none());
    }

    #[test]
    fn test_sdk_version_compatibility_same_major() {
        let sdk = SdkVersion::new(1, 5, 0);
        let req = SdkVersion::new(1, 3, 0);
        assert!(sdk.is_compatible_with(&req));
    }

    #[test]
    fn test_sdk_version_compatibility_different_major() {
        let sdk = SdkVersion::new(2, 0, 0);
        let req = SdkVersion::new(1, 0, 0);
        assert!(!sdk.is_compatible_with(&req));
    }

    #[test]
    fn test_sdk_version_ordering() {
        assert!(SdkVersion::new(1, 2, 0) > SdkVersion::new(1, 1, 9));
        assert!(SdkVersion::new(2, 0, 0) > SdkVersion::new(1, 9, 9));
    }

    // ── PluginCapability ──────────────────────────────────────────────────────

    #[test]
    fn test_capability_display() {
        let cap = PluginCapability::Loader;
        assert!(cap.to_string().contains("Loader"));
    }

    #[test]
    fn test_capability_custom() {
        let cap = PluginCapability::Custom("my_feature".to_string());
        assert!(cap.to_string().contains("my_feature"));
    }

    #[test]
    fn test_capability_equality() {
        assert_eq!(PluginCapability::Decompiler, PluginCapability::Decompiler);
        assert_ne!(PluginCapability::Loader, PluginCapability::Decompiler);
    }

    // ── PluginManifest ────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_has_capability() {
        let m = sample_manifest();
        assert!(m.has_capability(&PluginCapability::AnalysisPass));
        assert!(!m.has_capability(&PluginCapability::Loader));
    }

    #[test]
    fn test_manifest_sdk_compatible() {
        let m = sample_manifest();
        let sdk_ok = SdkVersion::new(1, 0, 0);
        let sdk_old = SdkVersion::new(0, 9, 9);
        assert!(m.is_sdk_compatible(&sdk_ok));
        assert!(!m.is_sdk_compatible(&sdk_old));
    }

    #[test]
    fn test_manifest_serde_roundtrip() {
        let m = sample_manifest();
        let json = m.to_json();
        let back = PluginManifest::from_json(&json).unwrap();
        assert_eq!(back.id, m.id);
    }

    #[test]
    fn test_manifest_multiple_capabilities() {
        let mut m = PluginManifest::new("x", "X", SdkVersion::new(1, 0, 0));
        m.add_capability(PluginCapability::Loader);
        m.add_capability(PluginCapability::TypeProvider);
        assert!(m.has_capability(&PluginCapability::TypeProvider));
    }

    // ── SdkContext ────────────────────────────────────────────────────────────

    #[test]
    fn test_sdk_context_settings() {
        let mut ctx = sample_context();
        ctx.set_bool("debug", true);
        ctx.set_int("max_depth", 10);
        ctx.set_string("output", "result.txt");
        assert_eq!(ctx.get_bool("debug"), Some(true));
        assert_eq!(ctx.get_int("max_depth"), Some(10));
        assert_eq!(ctx.get_string("output"), Some("result.txt"));
    }

    #[test]
    fn test_sdk_context_missing_setting() {
        let ctx = sample_context();
        assert_eq!(ctx.get_bool("missing"), None);
        assert_eq!(ctx.get_int("missing"), None);
    }

    #[test]
    fn test_sdk_context_metadata() {
        let mut ctx = sample_context();
        ctx.set_meta("author", "test");
        assert_eq!(ctx.metadata.get("author").map(String::as_str), Some("test"));
    }

    // ── SdkAction ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sdk_action_new() {
        let a = SdkAction::new("action.id", "Do Something");
        assert!(a.enabled);
        assert_eq!(a.id, "action.id");
    }

    #[test]
    fn test_sdk_action_with_shortcut() {
        let a = SdkAction::new("x", "X").with_shortcut("Ctrl+X");
        assert_eq!(a.shortcut.as_deref(), Some("Ctrl+X"));
    }

    #[test]
    fn test_sdk_action_disabled() {
        let a = SdkAction::new("x", "X").disabled();
        assert!(!a.enabled);
    }

    // ── SdkEvent ──────────────────────────────────────────────────────────────

    #[test]
    fn test_sdk_event_name() {
        assert_eq!(SdkEvent::AnalysisStarted.name(), "AnalysisStarted");
        assert_eq!(
            SdkEvent::NavigateTo { address: 0x1000 }.name(),
            "NavigateTo"
        );
    }

    #[test]
    fn test_sdk_event_address() {
        let ev = SdkEvent::NavigateTo { address: 0x4000 };
        assert_eq!(ev.address(), Some(0x4000));
        assert_eq!(SdkEvent::AnalysisStarted.address(), None);
    }

    #[test]
    fn test_sdk_event_serde() {
        let ev = SdkEvent::FunctionRenamed {
            address: 0x1000,
            old_name: "sub_1000".to_string(),
            new_name: "main".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SdkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name(), "FunctionRenamed");
    }

    // ── EventBus ──────────────────────────────────────────────────────────────

    #[test]
    fn test_event_bus_emit() {
        let mut bus = EventBus::new();
        bus.emit(SdkEvent::AnalysisStarted);
        bus.emit(SdkEvent::AnalysisCompleted { duration_ms: 100 });
        assert_eq!(bus.event_count(), 2);
    }

    #[test]
    fn test_event_bus_filter() {
        let mut bus = EventBus::new();
        bus.emit(SdkEvent::AnalysisStarted);
        bus.emit(SdkEvent::AnalysisStarted);
        bus.emit(SdkEvent::AnalysisCompleted { duration_ms: 50 });
        let started = bus.events_named("AnalysisStarted");
        assert_eq!(started.len(), 2);
    }

    #[test]
    fn test_event_bus_clear() {
        let mut bus = EventBus::new();
        bus.emit(SdkEvent::AnalysisStarted);
        bus.clear();
        assert_eq!(bus.event_count(), 0);
    }

    // ── ActionRegistry ────────────────────────────────────────────────────────

    #[test]
    fn test_action_registry_register() {
        let mut reg = ActionRegistry::new();
        reg.register(SdkAction::new("a1", "Action 1"));
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_action_registry_unregister() {
        let mut reg = ActionRegistry::new();
        reg.register(SdkAction::new("a1", "Action 1"));
        reg.unregister("a1");
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_action_registry_get() {
        let mut reg = ActionRegistry::new();
        reg.register(SdkAction::new("a1", "Action 1"));
        assert!(reg.get("a1").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn test_action_registry_enabled_actions() {
        let mut reg = ActionRegistry::new();
        reg.register(SdkAction::new("a1", "Enabled"));
        reg.register(SdkAction::new("a2", "Disabled").disabled());
        let enabled = reg.enabled_actions();
        assert_eq!(enabled.len(), 1);
    }

    // ── PluginSdk ─────────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_sdk_initialize() {
        let mut sdk = sample_sdk();
        assert!(!sdk.is_initialized());
        sdk.initialize().unwrap();
        assert!(sdk.is_initialized());
    }

    #[test]
    fn test_plugin_sdk_double_initialize() {
        let mut sdk = sample_sdk();
        sdk.initialize().unwrap();
        let result = sdk.initialize();
        assert_eq!(result, Err(SdkError::AlreadyInitialized));
    }

    #[test]
    fn test_plugin_sdk_register_action_requires_init() {
        let mut sdk = sample_sdk();
        let result = sdk.register_action(SdkAction::new("a", "A"));
        assert_eq!(result, Err(SdkError::NotInitialized));
    }

    #[test]
    fn test_plugin_sdk_register_action_after_init() {
        let mut sdk = sample_sdk();
        sdk.initialize().unwrap();
        sdk.register_action(SdkAction::new("a", "A")).unwrap();
        assert_eq!(sdk.actions.count(), 1);
    }

    #[test]
    fn test_plugin_sdk_emit_event() {
        let mut sdk = sample_sdk();
        sdk.initialize().unwrap();
        sdk.emit_event(SdkEvent::NavigateTo { address: 0x1000 });
        assert!(sdk.events.event_count() > 0);
    }

    #[test]
    fn test_plugin_sdk_plugin_id() {
        let sdk = sample_sdk();
        assert_eq!(sdk.plugin_id(), "com.example.my_plugin");
    }

    #[test]
    fn test_plugin_sdk_incompatible_version() {
        let mut manifest = sample_manifest();
        manifest.min_sdk_version = SdkVersion::new(99, 0, 0);
        let mut sdk = PluginSdk::new(manifest, sample_context());
        let result = sdk.initialize();
        assert!(matches!(
            result,
            Err(SdkError::IncompatibleSdkVersion { .. })
        ));
    }

    #[test]
    fn test_sdk_error_display() {
        let e = SdkError::AlreadyInitialized;
        assert!(!e.to_string().is_empty());
    }
}
