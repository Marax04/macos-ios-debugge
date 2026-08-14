//! Compatibility layer for `rustre-plugin-host`.
//!
//! This module provides additional types used by the plugin host crate.
//! These types are re-exported from the crate root so that
//! `rustre_plugin_api::{HookRegistry, IpcMessage, …}` continues to resolve.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::Plugin as ApiPlugin;
use crate::PluginError;

// ─── PluginState ─────────────────────────────────────────────────────────────

/// Lifecycle state for a loaded plugin as tracked by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PluginState {
    Active,
    Suspended,
    Error,
    Loading,
    #[default]
    Unloaded,
}

impl fmt::Display for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Error => write!(f, "Error"),
            Self::Loading => write!(f, "Loading"),
            Self::Unloaded => write!(f, "Unloaded"),
        }
    }
}

// ─── PluginMeta ──────────────────────────────────────────────────────────────

/// Identifying metadata for a plugin (used by the host for persistence).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginMeta {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// Primary category of the plugin.
    #[serde(default)]
    pub category: String,
}

impl PluginMeta {
    /// Build a `PluginMeta` with id, name, and primary category.
    ///
    /// The textual `version` field defaults to `"0.0.0"`; the category is
    /// stored as its stable string identifier (see
    /// [`crate::PluginCapability::as_str`]).
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: crate::PluginCapability,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: "0.0.0".to_string(),
            description: String::new(),
            author: String::new(),
            category: category.as_str().to_string(),
        }
    }
}

impl fmt::Display for PluginMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.name, self.version)
    }
}

// ─── PluginSettings ──────────────────────────────────────────────────────────

/// Free-form settings blob owned by the host for each plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginSettings {
    #[serde(default)]
    pub values: HashMap<String, PluginValue>,
}

impl PluginSettings {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&PluginValue> {
        self.values.get(key)
    }

    pub fn set(&mut self, key: impl Into<String>, value: PluginValue) {
        self.values.insert(key.into(), value);
    }

    /// Retrieve a setting as a boolean, returning `None` if absent or
    /// the value is not a `Bool` variant.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.values.get(key)? {
            PluginValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Retrieve a setting as an integer, returning `None` if absent or
    /// the value is not an `Int` variant.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.values.get(key)? {
            PluginValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// Convenience alias for [`PluginValue`] when used as a settings value.
pub type SettingValue = PluginValue;

// ─── PluginValue ─────────────────────────────────────────────────────────────

/// Dynamically typed value used in IPC and settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PluginValue {
    #[default]
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Map(HashMap<String, Self>),
}

// ─── IPC ─────────────────────────────────────────────────────────────────────

/// A request from one side of the host/plugin boundary to the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    pub method: String,
    pub payload: PluginValue,
}

impl IpcMessage {
    pub fn new(method: impl Into<String>, payload: PluginValue) -> Self {
        Self {
            method: method.into(),
            payload,
        }
    }
}

/// The matching reply to an [`IpcMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub success: bool,
    pub payload: PluginValue,
    pub error: Option<String>,
}

impl IpcResponse {
    #[must_use]
    pub const fn ok(payload: PluginValue) -> Self {
        Self {
            success: true,
            payload,
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            payload: PluginValue::Null,
            error: Some(msg.into()),
        }
    }
}

// ─── HookRegistry ────────────────────────────────────────────────────────────

/// Hook callback type — invoked on a named event.
pub type HookCallback = Box<dyn Fn(&PluginValue) + Send + Sync + 'static>;

/// Registry of named hooks keyed by event name.
#[derive(Default)]
pub struct HookRegistry {
    hooks: RwLock<HashMap<String, Vec<HookCallback>>>,
}

impl HookRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, event: impl Into<String>, callback: HookCallback) {
        self.hooks
            .write()
            .entry(event.into())
            .or_default()
            .push(callback);
    }

    pub fn fire(&self, event: &str, payload: &PluginValue) {
        if let Some(callbacks) = self.hooks.read().get(event) {
            for cb in callbacks {
                cb(payload);
            }
        }
    }

    pub fn event_count(&self) -> usize {
        self.hooks.read().len()
    }

    /// Number of callbacks registered for the given [`HookPoint`].
    #[must_use]
    pub fn hook_count(&self, point: HookPoint) -> usize {
        self.hooks
            .read()
            .get(point.as_str())
            .map_or(0, std::vec::Vec::len)
    }
}

/// Well-known hook points used by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPoint {
    OnLoad,
    OnUnload,
    OnSuspend,
    OnResume,
    OnError,
}

impl HookPoint {
    /// Stable string identifier for the hook point.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnLoad => "on_load",
            Self::OnUnload => "on_unload",
            Self::OnSuspend => "on_suspend",
            Self::OnResume => "on_resume",
            Self::OnError => "on_error",
        }
    }
}

impl fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HookRegistry {{ events: {} }}", self.event_count())
    }
}

// ─── HostPluginRegistry ──────────────────────────────────────────────────────

/// A registry shaped for the host crate: stores `Arc<RwLock<dyn Plugin>>`
/// and keys plugins by their string identifier.
///
/// This is a different type from the public [`crate::PluginRegistry`] which
/// stores `Arc<dyn Plugin>`; the host uses interior mutability instead.
#[derive(Default)]
pub struct HostPluginRegistry {
    plugins: RwLock<HashMap<String, Arc<RwLock<dyn ApiPlugin>>>>,
}

impl HostPluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    ///
    /// # Errors
    ///
    /// Returns [`PluginError::AlreadyRegistered`] if a plugin with the same id is already present.
    pub fn register(&self, plugin: Arc<RwLock<dyn ApiPlugin>>) -> Result<(), PluginError> {
        let id = {
            let guard = plugin.read();
            HostPluginExt::meta(&*guard).id
        };
        let mut map = self.plugins.write();
        if map.contains_key(&id) {
            return Err(PluginError::AlreadyRegistered(id));
        }
        map.insert(id, plugin);
        drop(map);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns [`PluginError::NotFound`] if no plugin with that id is registered.
    pub fn unregister(&self, id: &str) -> Result<(), PluginError> {
        let mut map = self.plugins.write();
        map.remove(id)
            .map(|_| ())
            .ok_or_else(|| PluginError::NotFound(id.to_string()))
    }

    pub fn get(&self, id: &str) -> Option<Arc<RwLock<dyn ApiPlugin>>> {
        self.plugins.read().get(id).cloned()
    }

    pub fn count(&self) -> usize {
        self.plugins.read().len()
    }

    pub fn ids(&self) -> Vec<String> {
        self.plugins.read().keys().cloned().collect()
    }
}

impl fmt::Debug for HostPluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostPluginRegistry {{ plugins: {} }}", self.count())
    }
}

// ─── HostPluginExt ───────────────────────────────────────────────────────────

/// Lifecycle extension methods used by the host.
///
/// These are auto-implemented for every [`Plugin`] in terms of its existing
/// trait methods (`name`, `version`, `manifest`), giving the host crate the
/// `meta()`, `state()`, `initialize()`, `shutdown()`, `suspend()`, and
/// `resume()` methods it relies on.
pub trait HostPluginExt {
    fn meta(&self) -> PluginMeta;
    fn state(&self) -> PluginState;
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    fn initialize(&self, _settings: &PluginSettings) -> Result<(), PluginError>;
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    fn shutdown(&self) -> Result<(), PluginError>;
    ///
    /// # Errors
    ///
    /// Returns an error if suspending fails.
    fn suspend(&self) -> Result<(), PluginError>;
    ///
    /// # Errors
    ///
    /// Returns an error if resuming fails.
    fn resume(&self) -> Result<(), PluginError>;
}

impl<P: ApiPlugin + ?Sized> HostPluginExt for P {
    fn meta(&self) -> PluginMeta {
        let manifest = self.manifest();
        let id = format!("{}@{}", manifest.name, manifest.version);
        let category = self
            .capabilities()
            .first()
            .map(|c| c.as_str().to_string())
            .unwrap_or_default();
        PluginMeta {
            id,
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            description: manifest.description.clone(),
            author: manifest.author,
            category,
        }
    }

    fn state(&self) -> PluginState {
        PluginState::Active
    }

    fn initialize(&self, _settings: &PluginSettings) -> Result<(), PluginError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        Ok(())
    }

    fn suspend(&self) -> Result<(), PluginError> {
        Ok(())
    }

    fn resume(&self) -> Result<(), PluginError> {
        Ok(())
    }
}
