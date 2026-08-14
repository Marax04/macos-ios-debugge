// plugin_registry_v2.rs — Registry of all loaded plugins with dependency resolution

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("plugin {id:?} is already registered")]
    AlreadyRegistered { id: String },
    #[error("plugin {id:?} not found")]
    NotFound { id: String },
    #[error("dependency {dep:?} required by {plugin:?} is not registered")]
    MissingDependency { plugin: String, dep: String },
    #[error("circular dependency detected: {cycle:?}")]
    CircularDependency { cycle: Vec<String> },
    #[error("version conflict: plugin {id:?} requires {dep:?} >= {required}, found {found}")]
    VersionConflict {
        id: String,
        dep: String,
        required: String,
        found: String,
    },
    #[error("plugin {id:?} cannot be unloaded while dependents are active: {dependents:?}")]
    HasActiveDependents { id: String, dependents: Vec<String> },
}

// ─── Versioning ───────────────────────────────────────────────────────────────

/// Simple three-part version (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PluginVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PluginVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(3, '.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }

    pub fn display(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// True if `self` satisfies the minimum version `min`.
    pub fn satisfies(&self, min: &PluginVersion) -> bool {
        if self.major != min.major {
            return self.major > min.major;
        }
        if self.minor != min.minor {
            return self.minor > min.minor;
        }
        self.patch >= min.patch
    }
}

// ─── Capability ───────────────────────────────────────────────────────────────

/// A named capability that a plugin provides or consumes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PluginCapability {
    pub name: String,
    pub version: PluginVersion,
    /// Optional description.
    pub description: String,
}

impl PluginCapability {
    pub fn new(name: impl Into<String>, version: PluginVersion) -> Self {
        Self {
            name: name.into(),
            version,
            description: String::new(),
        }
    }
}

// ─── Dependency specification ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencySpec {
    /// ID of the required plugin.
    pub plugin_id: String,
    /// Minimum version required.
    pub min_version: PluginVersion,
    /// True if this dependency is optional (plugin loads without it).
    pub optional: bool,
}

impl DependencySpec {
    pub fn required(plugin_id: impl Into<String>, min_version: PluginVersion) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            min_version,
            optional: false,
        }
    }

    pub fn optional(plugin_id: impl Into<String>, min_version: PluginVersion) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            min_version,
            optional: true,
        }
    }
}

// ─── Plugin state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginState {
    /// Registered but not yet initialised.
    Registered,
    /// Being initialised.
    Initializing,
    /// Fully loaded and active.
    Active,
    /// Suspended / disabled.
    Suspended,
    /// In the process of being unloaded.
    Unloading,
    /// Failed to load.
    Failed,
    /// Unloaded and removed.
    Unloaded,
}

impl PluginState {
    pub fn is_active(&self) -> bool {
        *self == PluginState::Active
    }

    pub fn can_unload(&self) -> bool {
        matches!(*self, PluginState::Active | PluginState::Suspended | PluginState::Failed)
    }
}

// ─── Plugin metadata ─────────────────────────────────────────────────────────

/// All static metadata for a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMeta {
    /// Unique identifier (e.g. "rustre.arch.x86").
    pub id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Plugin version.
    pub version: PluginVersion,
    /// Short description.
    pub description: String,
    /// Author name / email.
    pub author: String,
    /// SPDX license identifier (e.g. "MIT").
    pub license: String,
    /// URL to documentation or homepage.
    pub homepage: String,
    /// Capabilities this plugin provides.
    pub provides: Vec<PluginCapability>,
    /// Capabilities this plugin requires.
    pub requires: Vec<PluginCapability>,
    /// Explicit plugin dependencies.
    pub dependencies: Vec<DependencySpec>,
    /// Tags / categories.
    pub tags: Vec<String>,
}

impl PluginMeta {
    pub fn new(id: impl Into<String>, display_name: impl Into<String>, version: PluginVersion) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            version,
            description: String::new(),
            author: String::new(),
            license: String::new(),
            homepage: String::new(),
            provides: vec![],
            requires: vec![],
            dependencies: vec![],
            tags: vec![],
        }
    }
}

// ─── Registry entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub meta: PluginMeta,
    pub state: PluginState,
    /// IDs of plugins that depend on this one.
    pub dependents: HashSet<String>,
    /// Load order index (lower = loaded first).
    pub load_order: usize,
    /// Error message if state == Failed.
    pub error_message: Option<String>,
}

// ─── Plugin registry ─────────────────────────────────────────────────────────

/// Thread-safe registry of all known/loaded plugins.
pub struct PluginRegistry {
    entries: Arc<RwLock<HashMap<String, RegistryEntry>>>,
    load_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            load_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Register a new plugin (state = Registered).
    pub fn register(&self, meta: PluginMeta) -> Result<(), RegistryError> {
        let mut entries = self.entries.write().unwrap();
        if entries.contains_key(&meta.id) {
            return Err(RegistryError::AlreadyRegistered { id: meta.id });
        }
        let order = self
            .load_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        entries.insert(
            meta.id.clone(),
            RegistryEntry {
                meta,
                state: PluginState::Registered,
                dependents: HashSet::new(),
                load_order: order,
                error_message: None,
            },
        );
        Ok(())
    }

    /// Validate all required dependencies are registered and version-compatible.
    pub fn validate_dependencies(&self, plugin_id: &str) -> Result<(), RegistryError> {
        let entries = self.entries.read().unwrap();
        let entry = entries
            .get(plugin_id)
            .ok_or_else(|| RegistryError::NotFound { id: plugin_id.to_string() })?;

        for dep in &entry.meta.dependencies {
            if dep.optional {
                continue;
            }
            match entries.get(&dep.plugin_id) {
                None => {
                    return Err(RegistryError::MissingDependency {
                        plugin: plugin_id.to_string(),
                        dep: dep.plugin_id.clone(),
                    })
                }
                Some(dep_entry) => {
                    if !dep_entry.meta.version.satisfies(&dep.min_version) {
                        return Err(RegistryError::VersionConflict {
                            id: plugin_id.to_string(),
                            dep: dep.plugin_id.clone(),
                            required: dep.min_version.display(),
                            found: dep_entry.meta.version.display(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Transition a plugin's state.
    pub fn set_state(&self, plugin_id: &str, state: PluginState) -> Result<(), RegistryError> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(plugin_id)
            .ok_or_else(|| RegistryError::NotFound { id: plugin_id.to_string() })?;
        entry.state = state;
        Ok(())
    }

    pub fn set_error(&self, plugin_id: &str, msg: String) -> Result<(), RegistryError> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(plugin_id)
            .ok_or_else(|| RegistryError::NotFound { id: plugin_id.to_string() })?;
        entry.state = PluginState::Failed;
        entry.error_message = Some(msg);
        Ok(())
    }

    /// Unregister a plugin if it has no active dependents.
    pub fn unregister(&self, plugin_id: &str) -> Result<(), RegistryError> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get(plugin_id)
            .ok_or_else(|| RegistryError::NotFound { id: plugin_id.to_string() })?;

        let active_dependents: Vec<String> = entry
            .dependents
            .iter()
            .filter(|dep_id| {
                entries.get(dep_id.as_str()).map(|e| e.state.is_active()).unwrap_or(false)
            })
            .cloned()
            .collect();

        if !active_dependents.is_empty() {
            return Err(RegistryError::HasActiveDependents {
                id: plugin_id.to_string(),
                dependents: active_dependents,
            });
        }

        entries.remove(plugin_id);
        Ok(())
    }

    /// Wire dependent relationships after all plugins are registered.
    pub fn wire_dependents(&self) {
        let ids: Vec<String> = {
            let entries = self.entries.read().unwrap();
            entries.keys().cloned().collect()
        };
        for id in &ids {
            let deps: Vec<String> = {
                let entries = self.entries.read().unwrap();
                entries[id]
                    .meta
                    .dependencies
                    .iter()
                    .map(|d| d.plugin_id.clone())
                    .collect()
            };
            let mut entries = self.entries.write().unwrap();
            for dep_id in deps {
                if let Some(dep_entry) = entries.get_mut(&dep_id) {
                    dep_entry.dependents.insert(id.clone());
                }
            }
        }
    }

    /// Compute topological load order for all registered plugins.
    pub fn load_order(&self) -> Result<Vec<String>, RegistryError> {
        let entries = self.entries.read().unwrap();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for (id, entry) in entries.iter() {
            in_degree.entry(id).or_insert(0);
            for dep in &entry.meta.dependencies {
                if !dep.optional {
                    *in_degree.entry(id.as_str()).or_insert(0) += 1;
                    adj.entry(dep.plugin_id.as_str())
                        .or_default()
                        .push(id.as_str());
                }
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();
        let mut result: Vec<String> = Vec::new();

        while let Some(id) = queue.pop_front() {
            result.push(id.to_string());
            if let Some(dependents) = adj.get(id) {
                for &dep_id in dependents {
                    let deg = in_degree.get_mut(dep_id).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep_id);
                    }
                }
            }
        }

        if result.len() != entries.len() {
            // Find cycle.
            let visited: HashSet<String> = result.iter().cloned().collect();
            let cycle: Vec<String> = entries
                .keys()
                .filter(|k| !visited.contains(*k))
                .cloned()
                .collect();
            return Err(RegistryError::CircularDependency { cycle });
        }

        Ok(result)
    }

    pub fn get(&self, plugin_id: &str) -> Option<RegistryEntry> {
        self.entries.read().unwrap().get(plugin_id).cloned()
    }

    pub fn all_ids(&self) -> Vec<String> {
        self.entries.read().unwrap().keys().cloned().collect()
    }

    pub fn active_plugins(&self) -> Vec<RegistryEntry> {
        self.entries
            .read()
            .unwrap()
            .values()
            .filter(|e| e.state.is_active())
            .cloned()
            .collect()
    }

    pub fn plugins_by_state(&self, state: PluginState) -> Vec<RegistryEntry> {
        self.entries
            .read()
            .unwrap()
            .values()
            .filter(|e| e.state == state)
            .cloned()
            .collect()
    }

    /// Find plugins that provide a specific capability name.
    pub fn providers_of(&self, capability: &str) -> Vec<RegistryEntry> {
        self.entries
            .read()
            .unwrap()
            .values()
            .filter(|e| e.meta.provides.iter().any(|c| c.name == capability))
            .cloned()
            .collect()
    }

    pub fn plugin_count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> PluginVersion {
        PluginVersion::parse(s).unwrap()
    }

    fn meta(id: &str) -> PluginMeta {
        PluginMeta::new(id, id, v("1.0.0"))
    }

    #[test]
    fn test_register_and_get() {
        let reg = PluginRegistry::new();
        reg.register(meta("foo")).unwrap();
        let entry = reg.get("foo").unwrap();
        assert_eq!(entry.meta.id, "foo");
        assert_eq!(entry.state, PluginState::Registered);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let reg = PluginRegistry::new();
        reg.register(meta("foo")).unwrap();
        assert!(matches!(
            reg.register(meta("foo")),
            Err(RegistryError::AlreadyRegistered { .. })
        ));
    }

    #[test]
    fn test_set_state() {
        let reg = PluginRegistry::new();
        reg.register(meta("foo")).unwrap();
        reg.set_state("foo", PluginState::Active).unwrap();
        assert!(reg.get("foo").unwrap().state.is_active());
    }

    #[test]
    fn test_validate_dependencies_ok() {
        let reg = PluginRegistry::new();
        reg.register(meta("base")).unwrap();

        let mut dep_meta = meta("child");
        dep_meta.dependencies = vec![DependencySpec::required("base", v("1.0.0"))];
        reg.register(dep_meta).unwrap();

        reg.validate_dependencies("child").unwrap();
    }

    #[test]
    fn test_validate_dependencies_missing() {
        let reg = PluginRegistry::new();
        let mut dep_meta = meta("child");
        dep_meta.dependencies = vec![DependencySpec::required("missing", v("1.0.0"))];
        reg.register(dep_meta).unwrap();

        assert!(matches!(
            reg.validate_dependencies("child"),
            Err(RegistryError::MissingDependency { .. })
        ));
    }

    #[test]
    fn test_load_order_no_deps() {
        let reg = PluginRegistry::new();
        reg.register(meta("a")).unwrap();
        reg.register(meta("b")).unwrap();
        let order = reg.load_order().unwrap();
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn test_load_order_with_dep() {
        let reg = PluginRegistry::new();
        reg.register(meta("base")).unwrap();
        let mut child = meta("child");
        child.dependencies = vec![DependencySpec::required("base", v("1.0.0"))];
        reg.register(child).unwrap();
        let order = reg.load_order().unwrap();
        let base_pos = order.iter().position(|s| s == "base").unwrap();
        let child_pos = order.iter().position(|s| s == "child").unwrap();
        assert!(base_pos < child_pos);
    }

    #[test]
    fn test_unregister_no_dependents() {
        let reg = PluginRegistry::new();
        reg.register(meta("foo")).unwrap();
        reg.unregister("foo").unwrap();
        assert!(reg.get("foo").is_none());
    }

    #[test]
    fn test_unregister_blocked_by_active_dependent() {
        let reg = PluginRegistry::new();
        reg.register(meta("base")).unwrap();
        let mut child = meta("child");
        child.dependencies = vec![DependencySpec::required("base", v("1.0.0"))];
        reg.register(child).unwrap();
        reg.wire_dependents();
        reg.set_state("child", PluginState::Active).unwrap();
        assert!(matches!(
            reg.unregister("base"),
            Err(RegistryError::HasActiveDependents { .. })
        ));
    }

    #[test]
    fn test_providers_of() {
        let reg = PluginRegistry::new();
        let mut m = meta("arch_x86");
        m.provides.push(PluginCapability::new("disassembly", v("1.0.0")));
        reg.register(m).unwrap();
        let providers = reg.providers_of("disassembly");
        assert_eq!(providers.len(), 1);
    }

    #[test]
    fn test_active_plugins_filter() {
        let reg = PluginRegistry::new();
        reg.register(meta("a")).unwrap();
        reg.register(meta("b")).unwrap();
        reg.set_state("a", PluginState::Active).unwrap();
        assert_eq!(reg.active_plugins().len(), 1);
    }

    #[test]
    fn test_version_satisfies() {
        let v1 = PluginVersion::new(1, 2, 3);
        assert!(v1.satisfies(&PluginVersion::new(1, 2, 3)));
        assert!(v1.satisfies(&PluginVersion::new(1, 2, 0)));
        assert!(!v1.satisfies(&PluginVersion::new(1, 3, 0)));
        assert!(!v1.satisfies(&PluginVersion::new(2, 0, 0)));
    }

    #[test]
    fn test_plugin_count() {
        let reg = PluginRegistry::new();
        reg.register(meta("x")).unwrap();
        reg.register(meta("y")).unwrap();
        assert_eq!(reg.plugin_count(), 2);
    }
}
