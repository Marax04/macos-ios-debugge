//! Plugin permission model: fine-grained, composable permissions for the
//! `RustRE` plugin sandbox.
//!
//! Provides [`Permission`], [`PermissionSet`], [`PluginPermissionModel`], and
//! [`check_permission`].

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── Permission ────────────────────────────────────────────────────────────────

/// A single, named permission that may be granted or denied.
///
/// Permissions are hierarchical when they contain `/`.  A grant of
/// `"fs"` does **not** automatically grant `"fs/write"` — every
/// permission must be explicitly listed.  This keeps the model simple and
/// auditable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Permission(pub String);

impl Permission {
    /// Construct a permission from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is empty or contains whitespace.
    pub fn new(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        if name.is_empty() {
            return Err("permission name must not be empty".into());
        }
        if name.chars().any(char::is_whitespace) {
            return Err(format!("permission name '{name}' contains whitespace"));
        }
        Ok(Self(name))
    }

    /// Construct without validation (use for well-known constants).
    #[must_use]
    pub fn unchecked(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Return the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the top-level namespace (text before the first `/`).
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.0.split('/').next().unwrap_or(&self.0)
    }

    /// Return `true` when this permission is in the given namespace.
    #[must_use]
    pub fn in_namespace(&self, ns: &str) -> bool {
        self.namespace() == ns
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Permission {
    fn from(s: &str) -> Self {
        Self::unchecked(s)
    }
}

/// Well-known permission constants.
pub mod perms {
    use super::Permission;

    #[must_use] 
    pub fn fs_read() -> Permission { Permission::unchecked("fs/read") }
    #[must_use] 
    pub fn fs_write() -> Permission { Permission::unchecked("fs/write") }
    #[must_use] 
    pub fn net_connect() -> Permission { Permission::unchecked("net/connect") }
    #[must_use] 
    pub fn net_listen() -> Permission { Permission::unchecked("net/listen") }
    #[must_use] 
    pub fn mem_read() -> Permission { Permission::unchecked("mem/read") }
    #[must_use] 
    pub fn mem_write() -> Permission { Permission::unchecked("mem/write") }
    #[must_use] 
    pub fn mem_exec() -> Permission { Permission::unchecked("mem/exec") }
    #[must_use] 
    pub fn proc_spawn() -> Permission { Permission::unchecked("proc/spawn") }
    #[must_use] 
    pub fn proc_kill() -> Permission { Permission::unchecked("proc/kill") }
    #[must_use] 
    pub fn ui_show() -> Permission { Permission::unchecked("ui/show") }
    #[must_use] 
    pub fn ui_input() -> Permission { Permission::unchecked("ui/input") }
    #[must_use] 
    pub fn debug_attach() -> Permission { Permission::unchecked("debug/attach") }
    #[must_use] 
    pub fn debug_read_regs() -> Permission { Permission::unchecked("debug/read_regs") }
    #[must_use] 
    pub fn debug_write_regs() -> Permission { Permission::unchecked("debug/write_regs") }
    #[must_use] 
    pub fn graph_read() -> Permission { Permission::unchecked("graph/read") }
    #[must_use] 
    pub fn graph_write() -> Permission { Permission::unchecked("graph/write") }
    #[must_use] 
    pub fn cmd_register() -> Permission { Permission::unchecked("cmd/register") }
    #[must_use] 
    pub fn script_eval() -> Permission { Permission::unchecked("script/eval") }
    #[must_use] 
    pub fn binary_modify() -> Permission { Permission::unchecked("binary/modify") }
    #[must_use] 
    pub fn type_define() -> Permission { Permission::unchecked("type/define") }

    /// Return all well-known permissions as a `Vec`.
    #[must_use] 
    pub fn all_known() -> Vec<Permission> {
        vec![
            fs_read(), fs_write(), net_connect(), net_listen(),
            mem_read(), mem_write(), mem_exec(), proc_spawn(), proc_kill(),
            ui_show(), ui_input(), debug_attach(), debug_read_regs(), debug_write_regs(),
            graph_read(), graph_write(), cmd_register(), script_eval(),
            binary_modify(), type_define(),
        ]
    }
}

// ── PermissionSet ─────────────────────────────────────────────────────────────

/// An immutable set of [`Permission`]s that can be granted together.
#[derive(Debug, Clone, Default)]
pub struct PermissionSet {
    granted: HashSet<Permission>,
}

impl PermissionSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a set granting all well-known permissions.
    #[must_use]
    pub fn all() -> Self {
        let mut s = Self::new();
        for p in perms::all_known() {
            s.grant(p);
        }
        s
    }

    /// Create a read-only set (`fs/read`, `graph/read`, `mem/read`).
    #[must_use]
    pub fn read_only() -> Self {
        let mut s = Self::new();
        s.grant(perms::fs_read());
        s.grant(perms::graph_read());
        s.grant(perms::mem_read());
        s
    }

    /// Create an analysis-focused set (read + graph/write + type/define).
    #[must_use]
    pub fn analysis() -> Self {
        let mut s = Self::read_only();
        s.grant(perms::graph_write());
        s.grant(perms::type_define());
        s.grant(perms::cmd_register());
        s
    }

    /// Create an empty (deny-all) set.
    #[must_use]
    pub fn none() -> Self {
        Self::new()
    }

    /// Grant a permission.
    pub fn grant(&mut self, p: Permission) {
        self.granted.insert(p);
    }

    /// Revoke a permission, returning `true` if it was present.
    pub fn revoke(&mut self, p: &Permission) -> bool {
        self.granted.remove(p)
    }

    /// Return `true` when the permission is granted.
    #[must_use]
    pub fn has(&self, p: &Permission) -> bool {
        self.granted.contains(p)
    }

    /// Return `true` when `self` is a superset of `other`.
    #[must_use]
    pub fn contains_all(&self, other: &Self) -> bool {
        other.granted.iter().all(|p| self.granted.contains(p))
    }

    /// Return the intersection with `other`.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            granted: self.granted.intersection(&other.granted).cloned().collect(),
        }
    }

    /// Return the union with `other`.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            granted: self.granted.union(&other.granted).cloned().collect(),
        }
    }

    /// Return a sorted list of all granted permissions.
    #[must_use]
    pub fn to_sorted_vec(&self) -> Vec<Permission> {
        let mut v: Vec<Permission> = self.granted.iter().cloned().collect();
        v.sort();
        v
    }

    /// Return the count of granted permissions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.granted.len()
    }

    /// Return `true` when no permissions are granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.granted.is_empty()
    }

    /// Return all permissions in the given namespace.
    #[must_use]
    pub fn namespace(&self, ns: &str) -> Vec<Permission> {
        self.granted.iter().filter(|p| p.in_namespace(ns)).cloned().collect()
    }
}

impl fmt::Display for PermissionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = self.to_sorted_vec();
        v.sort();
        let s: Vec<&str> = v.iter().map(Permission::as_str).collect();
        write!(f, "{{{}}}", s.join(", "))
    }
}

// ── PermissionCheckResult ─────────────────────────────────────────────────────

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionCheckResult {
    /// The permission is granted.
    Granted,
    /// The permission is denied, with a reason.
    Denied { reason: String },
    /// The permission is unknown (not in any policy).
    Unknown,
}

impl PermissionCheckResult {
    /// Return `true` when the result is `Granted`.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Return `true` when the result is `Denied`.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }
}

impl fmt::Display for PermissionCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted => write!(f, "granted"),
            Self::Denied { reason } => write!(f, "denied: {reason}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── PluginPermissionModel ─────────────────────────────────────────────────────

/// The complete permission model for a plugin.
///
/// Permissions flow through four layers (evaluated top-down):
/// 1. **Global deny list** — always denied, regardless of grants.
/// 2. **Grant list** — the superset of permissions the host allows for this plugin.
/// 3. **Plugin request list** — the subset the plugin actually asks for.
/// 4. **Effective set** — intersection of grant list and request list.
///
/// A permission check against the model returns `Granted` iff the
/// permission is in the effective set *and* not in the global deny list.
#[derive(Debug, Clone)]
pub struct PluginPermissionModel {
    /// Plugin identifier (for audit messages).
    pub plugin_id: String,
    /// Permissions the host is willing to grant.
    pub grants: PermissionSet,
    /// Permissions the plugin has requested.
    pub requests: PermissionSet,
    /// Permissions that are always denied (overrides grants).
    pub deny_list: PermissionSet,
    /// Audit log of check events `(permission, result)`.
    audit_log: Vec<(Permission, PermissionCheckResult)>,
}

impl PluginPermissionModel {
    /// Create a model with empty grant, request, and deny sets.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            grants: PermissionSet::new(),
            requests: PermissionSet::new(),
            deny_list: PermissionSet::new(),
            audit_log: Vec::new(),
        }
    }

    /// Create a model granting and requesting all well-known permissions.
    #[must_use]
    pub fn unrestricted(plugin_id: impl Into<String>) -> Self {
        let mut m = Self::new(plugin_id);
        m.grants = PermissionSet::all();
        m.requests = PermissionSet::all();
        m
    }

    /// Compute the effective permission set (grant ∩ request \ deny).
    #[must_use]
    pub fn effective(&self) -> PermissionSet {
        let intersected = self.grants.intersect(&self.requests);
        let mut eff = PermissionSet::new();
        for p in intersected.granted {
            if !self.deny_list.has(&p) {
                eff.grant(p);
            }
        }
        eff
    }

    /// Check a single permission, recording the result in the audit log.
    pub fn check(&mut self, p: &Permission) -> PermissionCheckResult {
        let result = self.check_no_audit(p);
        self.audit_log.push((p.clone(), result.clone()));
        result
    }

    /// Check a permission without recording it in the audit log.
    #[must_use]
    pub fn check_no_audit(&self, p: &Permission) -> PermissionCheckResult {
        if self.deny_list.has(p) {
            return PermissionCheckResult::Denied {
                reason: format!("'{}' is on the global deny list", p.as_str()),
            };
        }
        if !self.grants.has(p) {
            return PermissionCheckResult::Denied {
                reason: format!("'{}' was not granted by the host", p.as_str()),
            };
        }
        if !self.requests.has(p) {
            return PermissionCheckResult::Denied {
                reason: format!("'{}' was not requested by the plugin", p.as_str()),
            };
        }
        PermissionCheckResult::Granted
    }

    /// Return the audit log entries for the given permission.
    #[must_use]
    pub fn audit_entries(&self, p: &Permission) -> Vec<&PermissionCheckResult> {
        self.audit_log
            .iter()
            .filter(|(perm, _)| perm == p)
            .map(|(_, r)| r)
            .collect()
    }

    /// Return the full audit log.
    #[must_use]
    pub fn audit_log(&self) -> &[(Permission, PermissionCheckResult)] {
        &self.audit_log
    }

    /// Clear the audit log.
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    /// Number of denied checks recorded in the audit log.
    #[must_use]
    pub fn denied_count(&self) -> usize {
        self.audit_log.iter().filter(|(_, r)| r.is_denied()).count()
    }

    /// Number of granted checks recorded in the audit log.
    #[must_use]
    pub fn granted_count(&self) -> usize {
        self.audit_log.iter().filter(|(_, r)| r.is_granted()).count()
    }

    /// Return the requested permissions that are not in the grant list.
    #[must_use]
    pub fn over_requested(&self) -> Vec<Permission> {
        self.requests
            .to_sorted_vec()
            .into_iter()
            .filter(|p| !self.grants.has(p))
            .collect()
    }

    /// Return the granted permissions that the plugin never requested.
    #[must_use]
    pub fn unused_grants(&self) -> Vec<Permission> {
        self.grants
            .to_sorted_vec()
            .into_iter()
            .filter(|p| !self.requests.has(p))
            .collect()
    }
}

impl fmt::Display for PluginPermissionModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eff = self.effective();
        write!(
            f,
            "PermModel[{}] effective={} grants={} requests={}",
            self.plugin_id,
            eff.len(),
            self.grants.len(),
            self.requests.len()
        )
    }
}

// ── check_permission ──────────────────────────────────────────────────────────

/// Convenience function: check a permission against a model and return a
/// `bool`.  The check is recorded in the model's audit log.
///
/// This is the primary entry point for enforcement code — callers that need
/// the detailed [`PermissionCheckResult`] should call
/// [`PluginPermissionModel::check`] directly.
pub fn check_permission(model: &mut PluginPermissionModel, p: &Permission) -> bool {
    model.check(p).is_granted()
}

// ── Policy registry ───────────────────────────────────────────────────────────

/// A registry of permission policies, keyed by plugin ID.
///
/// Policies are registered once (during plugin load) and then queried for
/// every permission check at runtime.
#[derive(Debug, Default)]
pub struct PermissionPolicyRegistry {
    policies: HashMap<String, PluginPermissionModel>,
}

impl PermissionPolicyRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a policy for `plugin_id`, replacing any existing one.
    pub fn register(&mut self, model: PluginPermissionModel) {
        self.policies.insert(model.plugin_id.clone(), model);
    }

    /// Remove a policy.
    pub fn remove(&mut self, plugin_id: &str) -> Option<PluginPermissionModel> {
        self.policies.remove(plugin_id)
    }

    /// Return a mutable reference to the model for `plugin_id`.
    #[must_use]
    pub fn get_mut(&mut self, plugin_id: &str) -> Option<&mut PluginPermissionModel> {
        self.policies.get_mut(plugin_id)
    }

    /// Return a shared reference to the model for `plugin_id`.
    #[must_use]
    pub fn get(&self, plugin_id: &str) -> Option<&PluginPermissionModel> {
        self.policies.get(plugin_id)
    }

    /// Check a permission for the given plugin, recording it in the audit log.
    ///
    /// Returns `false` when the plugin is not registered.
    pub fn check(&mut self, plugin_id: &str, p: &Permission) -> bool {
        self.policies
            .get_mut(plugin_id)
            .is_some_and(|m| check_permission(m, p))
    }

    /// Return all plugin IDs.
    #[must_use]
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.policies.keys().map(String::as_str).collect()
    }

    /// Total number of registered policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Return `true` when no policies are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Aggregate audit log entries across all plugins.
    #[must_use]
    pub fn global_denied_count(&self) -> usize {
        self.policies.values().map(PluginPermissionModel::denied_count).sum()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn perm(s: &str) -> Permission {
        Permission::unchecked(s)
    }

    // ── Permission ────────────────────────────────────────────────────────────

    #[test]
    fn test_permission_new_ok() {
        let p = Permission::new("fs/read").unwrap();
        assert_eq!(p.as_str(), "fs/read");
    }

    #[test]
    fn test_permission_empty_fails() {
        assert!(Permission::new("").is_err());
    }

    #[test]
    fn test_permission_whitespace_fails() {
        assert!(Permission::new("fs read").is_err());
    }

    #[test]
    fn test_permission_namespace() {
        assert_eq!(perm("fs/read").namespace(), "fs");
        assert_eq!(perm("standalone").namespace(), "standalone");
    }

    #[test]
    fn test_permission_in_namespace() {
        assert!(perm("debug/attach").in_namespace("debug"));
        assert!(!perm("debug/attach").in_namespace("net"));
    }

    // ── PermissionSet ─────────────────────────────────────────────────────────

    #[test]
    fn test_permission_set_grant_has() {
        let mut s = PermissionSet::new();
        s.grant(perm("fs/read"));
        assert!(s.has(&perm("fs/read")));
        assert!(!s.has(&perm("fs/write")));
    }

    #[test]
    fn test_permission_set_revoke() {
        let mut s = PermissionSet::new();
        s.grant(perm("x"));
        assert!(s.revoke(&perm("x")));
        assert!(!s.has(&perm("x")));
    }

    #[test]
    fn test_permission_set_all() {
        let s = PermissionSet::all();
        assert!(s.has(&perms::fs_read()));
        assert!(s.has(&perms::debug_attach()));
    }

    #[test]
    fn test_permission_set_contains_all() {
        let all = PermissionSet::all();
        let ro = PermissionSet::read_only();
        assert!(all.contains_all(&ro));
        assert!(!ro.contains_all(&all));
    }

    #[test]
    fn test_permission_set_intersect() {
        let mut a = PermissionSet::new();
        a.grant(perm("fs/read"));
        a.grant(perm("fs/write"));

        let mut b = PermissionSet::new();
        b.grant(perm("fs/read"));
        b.grant(perm("net/connect"));

        let c = a.intersect(&b);
        assert!(c.has(&perm("fs/read")));
        assert!(!c.has(&perm("fs/write")));
        assert!(!c.has(&perm("net/connect")));
    }

    #[test]
    fn test_permission_set_union() {
        let mut a = PermissionSet::new();
        a.grant(perm("fs/read"));
        let mut b = PermissionSet::new();
        b.grant(perm("fs/write"));
        let u = a.union(&b);
        assert!(u.has(&perm("fs/read")));
        assert!(u.has(&perm("fs/write")));
    }

    #[test]
    fn test_permission_set_namespace() {
        let s = PermissionSet::all();
        let fs_perms = s.namespace("fs");
        assert!(!fs_perms.is_empty());
        assert!(fs_perms.iter().all(|p| p.in_namespace("fs")));
    }

    // ── PluginPermissionModel ─────────────────────────────────────────────────

    #[test]
    fn test_model_check_granted() {
        let mut m = PluginPermissionModel::new("test");
        m.grants.grant(perm("fs/read"));
        m.requests.grant(perm("fs/read"));
        assert!(check_permission(&mut m, &perm("fs/read")));
    }

    #[test]
    fn test_model_check_not_granted() {
        let mut m = PluginPermissionModel::new("test");
        m.grants.grant(perm("fs/read"));
        // not requested
        assert!(!check_permission(&mut m, &perm("fs/read")));
    }

    #[test]
    fn test_model_check_deny_overrides() {
        let mut m = PluginPermissionModel::new("test");
        m.grants.grant(perm("net/connect"));
        m.requests.grant(perm("net/connect"));
        m.deny_list.grant(perm("net/connect"));
        assert!(!check_permission(&mut m, &perm("net/connect")));
    }

    #[test]
    fn test_model_effective() {
        let mut m = PluginPermissionModel::new("p");
        m.grants.grant(perm("fs/read"));
        m.grants.grant(perm("fs/write"));
        m.requests.grant(perm("fs/read"));
        let eff = m.effective();
        assert!(eff.has(&perm("fs/read")));
        assert!(!eff.has(&perm("fs/write")));
    }

    #[test]
    fn test_model_audit_log() {
        let mut m = PluginPermissionModel::new("p");
        m.grants.grant(perm("fs/read"));
        m.requests.grant(perm("fs/read"));
        check_permission(&mut m, &perm("fs/read"));
        check_permission(&mut m, &perm("fs/write"));
        assert_eq!(m.granted_count(), 1);
        assert_eq!(m.denied_count(), 1);
    }

    #[test]
    fn test_model_over_requested() {
        let mut m = PluginPermissionModel::new("p");
        m.grants.grant(perm("fs/read"));
        m.requests.grant(perm("fs/read"));
        m.requests.grant(perm("net/connect")); // not granted
        let over = m.over_requested();
        assert_eq!(over.len(), 1);
        assert_eq!(over[0], perm("net/connect"));
    }

    #[test]
    fn test_model_unused_grants() {
        let mut m = PluginPermissionModel::new("p");
        m.grants.grant(perm("fs/read"));
        m.grants.grant(perm("fs/write"));
        m.requests.grant(perm("fs/read"));
        let unused = m.unused_grants();
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0], perm("fs/write"));
    }

    // ── PermissionPolicyRegistry ───────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_check() {
        let mut reg = PermissionPolicyRegistry::new();
        let mut model = PluginPermissionModel::new("my.plugin");
        model.grants.grant(perm("graph/read"));
        model.requests.grant(perm("graph/read"));
        reg.register(model);
        assert!(reg.check("my.plugin", &perm("graph/read")));
        assert!(!reg.check("my.plugin", &perm("graph/write")));
    }

    #[test]
    fn test_registry_unknown_plugin_denied() {
        let mut reg = PermissionPolicyRegistry::new();
        assert!(!reg.check("unknown", &perm("fs/read")));
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = PermissionPolicyRegistry::new();
        reg.register(PluginPermissionModel::new("p"));
        assert_eq!(reg.len(), 1);
        reg.remove("p");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_registry_global_denied_count() {
        let mut reg = PermissionPolicyRegistry::new();
        let mut m = PluginPermissionModel::new("p");
        m.check(&perm("missing")); // will be denied
        reg.register(m);
        assert_eq!(reg.global_denied_count(), 1);
    }
}
