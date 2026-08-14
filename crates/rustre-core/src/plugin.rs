//! Plugin context registry for per-view plugin state.
//!
//! This module provides a type-erased registry that stores plugin state objects
//! keyed by [`PluginId`].  Each entry can hold any `'static + Send + Sync` value
//! via a `Box<dyn Any + Send + Sync>`.
//!
//! # Example
//!
//! ```
//! use rustre_core::plugin::{PluginId, PluginRegistry};
//!
//! let mut reg = PluginRegistry::new();
//! let id = PluginId::new("my-plugin");
//! reg.register(id.clone(), Box::new(42u32));
//! let val = reg.get::<u32>(&id).copied();
//! assert_eq!(val, Some(42));
//! ```

use std::any::Any;
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PluginId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque, string-keyed identifier for a plugin.
///
/// Two `PluginId` values are equal iff their names are byte-for-byte identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginId {
    /// The canonical plugin name / reverse-DNS identifier.
    pub name: String,
}

impl PluginId {
    /// Construct a new `PluginId` from any stringifiable value.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Return the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plugin({})", self.name)
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
// PluginState — type alias for a boxed, type-erased state value
// ─────────────────────────────────────────────────────────────────────────────

/// Type-erased plugin state.
pub type PluginState = Box<dyn Any + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// PluginContext — per-view extension point
// ─────────────────────────────────────────────────────────────────────────────

/// A strongly-typed handle to a single plugin's state within a view.
///
/// Created by [`PluginRegistry::context`].
#[derive(Debug)]
pub struct PluginContext<'reg> {
    /// The plugin's unique identifier.
    pub id: &'reg PluginId,
    /// The type-erased state value, if set.
    pub state: Option<&'reg PluginState>,
}

impl PluginContext<'_> {
    /// Return `true` if state has been set for this plugin.
    #[must_use]
    pub fn has_state(&self) -> bool {
        self.state.is_some()
    }

    /// Downcast the state to a concrete type, returning `None` on mismatch.
    #[must_use]
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.state.and_then(|s| s.downcast_ref::<T>())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry that maps [`PluginId`] → type-erased state.
///
/// This is meant to be embedded inside `BinaryView` or held by an analysis
/// context to allow plugins to store per-view data without requiring the core
/// to know about any concrete plugin type.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    states: HashMap<PluginId, PluginState>,
}

impl PluginRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) plugin state for `id`.
    pub fn register(&mut self, id: PluginId, state: PluginState) {
        self.states.insert(id, state);
    }

    /// Remove plugin state for `id`.  Returns `true` if an entry was present.
    pub fn unregister(&mut self, id: &PluginId) -> bool {
        self.states.remove(id).is_some()
    }

    /// Return `true` if state is registered for `id`.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.states.contains_key(id)
    }

    /// Retrieve the type-erased state for `id`.
    #[must_use]
    pub fn get_raw(&self, id: &PluginId) -> Option<&PluginState> {
        self.states.get(id)
    }

    /// Retrieve mutable type-erased state for `id`.
    #[must_use]
    pub fn get_raw_mut(&mut self, id: &PluginId) -> Option<&mut PluginState> {
        self.states.get_mut(id)
    }

    /// Downcast-retrieve state for `id` as `&T`.
    ///
    /// Returns `None` if the plugin is not registered or the type does not match.
    #[must_use]
    pub fn get<T: 'static>(&self, id: &PluginId) -> Option<&T> {
        self.states.get(id)?.downcast_ref::<T>()
    }

    /// Downcast-retrieve mutable state for `id` as `&mut T`.
    #[must_use]
    pub fn get_mut<T: 'static>(&mut self, id: &PluginId) -> Option<&mut T> {
        self.states.get_mut(id)?.downcast_mut::<T>()
    }

    /// Return a [`PluginContext`] for `id`.
    #[must_use]
    pub fn context<'a>(&'a self, id: &'a PluginId) -> PluginContext<'a> {
        PluginContext {
            id,
            state: self.states.get(id),
        }
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Return `true` if no plugins are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Iterate over all registered plugin IDs.
    pub fn ids(&self) -> impl Iterator<Item = &PluginId> {
        self.states.keys()
    }

    /// Clear all registered plugin state.
    pub fn clear(&mut self) {
        self.states.clear();
    }

    /// Register state for `id` only if no entry currently exists.
    /// Returns `true` if the entry was newly inserted.
    pub fn register_if_absent(&mut self, id: PluginId, state: PluginState) -> bool {
        if let std::collections::hash_map::Entry::Vacant(e) = self.states.entry(id) {
            e.insert(state);
            true
        } else {
            false
        }
    }

    /// Apply `f` to the state for `id`, inserting `default()` first if absent.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn get_or_insert_with<T, F>(&mut self, id: PluginId, default: F) -> &mut T
    where
        T: 'static + Send + Sync,
        F: FnOnce() -> T,
    {
        self.states
            .entry(id)
            .or_insert_with(|| Box::new(default()))
            .downcast_mut::<T>()
            .expect("type mismatch in PluginRegistry::get_or_insert_with")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PluginId ──────────────────────────────────────────────────────────────

    #[test]
    fn plugin_id_equality() {
        let a = PluginId::new("com.example.my-plugin");
        let b = PluginId::new("com.example.my-plugin");
        let c = PluginId::new("com.example.other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn plugin_id_from_str() {
        let id: PluginId = "test".into();
        assert_eq!(id.as_str(), "test");
    }

    #[test]
    fn plugin_id_display() {
        let id = PluginId::new("my-plugin");
        assert_eq!(id.to_string(), "Plugin(my-plugin)");
    }

    // ── PluginRegistry ────────────────────────────────────────────────────────

    #[test]
    fn register_and_get_typed() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("test");
        reg.register(id.clone(), Box::new(42u32));
        assert_eq!(reg.get::<u32>(&id), Some(&42));
    }

    #[test]
    fn register_replaces_existing() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("p");
        reg.register(id.clone(), Box::new(1u32));
        reg.register(id.clone(), Box::new(2u32));
        assert_eq!(reg.get::<u32>(&id), Some(&2));
    }

    #[test]
    fn unregister_returns_presence() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("x");
        reg.register(id.clone(), Box::new("hello"));
        assert!(reg.unregister(&id));
        assert!(!reg.unregister(&id));
        assert!(!reg.contains(&id));
    }

    #[test]
    fn get_wrong_type_returns_none() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("q");
        reg.register(id.clone(), Box::new(99u64));
        assert!(reg.get::<u32>(&id).is_none()); // u32 ≠ u64
        assert!(reg.get::<u64>(&id).is_some());
    }

    #[test]
    fn get_mut_allows_mutation() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("counter");
        reg.register(id.clone(), Box::new(0u32));
        if let Some(v) = reg.get_mut::<u32>(&id) {
            *v += 1;
        }
        assert_eq!(reg.get::<u32>(&id), Some(&1));
    }

    #[test]
    fn context_no_state() {
        let reg = PluginRegistry::new();
        let id = PluginId::new("absent");
        let ctx = reg.context(&id);
        assert!(!ctx.has_state());
        assert!(ctx.get::<u32>().is_none());
    }

    #[test]
    fn context_with_state() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("present");
        reg.register(id.clone(), Box::new(77u32));
        let ctx = reg.context(&id);
        assert!(ctx.has_state());
        assert_eq!(ctx.get::<u32>(), Some(&77));
    }

    #[test]
    fn register_if_absent() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("once");
        assert!(reg.register_if_absent(id.clone(), Box::new(10u32)));
        assert!(!reg.register_if_absent(id.clone(), Box::new(20u32)));
        assert_eq!(reg.get::<u32>(&id), Some(&10)); // not replaced
    }

    #[test]
    fn get_or_insert_with_inserts() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("lazy");
        let val = reg.get_or_insert_with::<u32, _>(id, || 42);
        assert_eq!(*val, 42);
    }

    #[test]
    fn get_or_insert_with_returns_existing() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new("existing");
        reg.register(id.clone(), Box::new(99u32));
        let val = reg.get_or_insert_with::<u32, _>(id, || 0);
        assert_eq!(*val, 99);
    }

    #[test]
    fn len_and_is_empty() {
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        reg.register(PluginId::new("a"), Box::new(1u32));
        reg.register(PluginId::new("b"), Box::new(2u32));
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());
    }

    #[test]
    fn ids_iteration() {
        let mut reg = PluginRegistry::new();
        reg.register(PluginId::new("alpha"), Box::new(1u32));
        reg.register(PluginId::new("beta"), Box::new(2u32));
        let names: std::collections::HashSet<String> =
            reg.ids().map(|id| id.name.clone()).collect();
        assert!(names.contains("alpha"));
        assert!(names.contains("beta"));
    }

    #[test]
    fn clear_empties_registry() {
        let mut reg = PluginRegistry::new();
        reg.register(PluginId::new("a"), Box::new(0u32));
        reg.clear();
        assert!(reg.is_empty());
    }

    #[test]
    fn multiple_types() {
        let mut reg = PluginRegistry::new();
        reg.register(
            PluginId::new("str-plugin"),
            Box::new("hello world".to_string()),
        );
        reg.register(PluginId::new("vec-plugin"), Box::new(vec![1u8, 2, 3]));
        assert_eq!(
            reg.get::<String>(&PluginId::new("str-plugin"))
                .map(String::as_str),
            Some("hello world")
        );
        assert_eq!(
            reg.get::<Vec<u8>>(&PluginId::new("vec-plugin"))
                .map(Vec::len),
            Some(3)
        );
    }
}
