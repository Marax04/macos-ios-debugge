// plugin_permission_system.rs — Permission system for plugins

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("plugin {plugin_id:?} does not have permission {perm}")]
    Denied { plugin_id: String, perm: PluginPermission },
    #[error("plugin {plugin_id:?} is not registered in the permission system")]
    UnknownPlugin { plugin_id: String },
    #[error("permission {perm} requires {requires} which is also denied")]
    DependencyDenied { perm: PluginPermission, requires: PluginPermission },
    #[error("permission {0} is not grantable to sandboxed plugins")]
    NotGrantableToSandboxed(PluginPermission),
}

// ─── Permission definitions ───────────────────────────────────────────────────

/// Fine-grained permission that a plugin can request or be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginPermission {
    // File-system access.
    /// Read files from the analysis target.
    ReadBinaryData,
    /// Write annotations / patches to the target.
    WriteBinaryData,
    /// Read files from the host filesystem.
    ReadFilesystem,
    /// Write files to the host filesystem.
    WriteFilesystem,
    /// Create or delete files.
    CreateDeleteFiles,

    // Network access.
    /// Open outbound TCP/UDP connections.
    NetworkOutbound,
    /// Listen on a local port.
    NetworkListen,
    /// DNS resolution only.
    NetworkDns,

    // Process / system.
    /// Spawn child processes.
    SpawnProcess,
    /// Load native shared libraries.
    LoadNativeLibrary,
    /// Access environment variables.
    ReadEnvironment,
    /// Write environment variables.
    WriteEnvironment,
    /// Invoke system calls directly.
    RawSyscall,

    // Plugin host integration.
    /// Subscribe to events on the event bus.
    EventBusSubscribe,
    /// Publish events to the event bus.
    EventBusPublish,
    /// Access the plugin registry (read).
    RegistryRead,
    /// Modify plugin registry state.
    RegistryWrite,
    /// Request capabilities from other plugins.
    CapabilityRequest,
    /// Grant capabilities to other plugins.
    CapabilityGrant,

    // Analysis engine.
    /// Read the disassembly / IR.
    AnalysisRead,
    /// Modify the disassembly / IR.
    AnalysisWrite,
    /// Add or modify comments and labels.
    AnnotationWrite,
    /// Access type information.
    TypeInfoRead,
    /// Modify type information.
    TypeInfoWrite,
    /// Access the call graph.
    CallGraphRead,
    /// Access cross-references.
    XrefRead,

    // Scripting.
    /// Execute Lua scripts.
    ScriptLua,
    /// Execute Python scripts.
    ScriptPython,
    /// Evaluate arbitrary expressions in the host scripting engine.
    ScriptEval,

    // UI (restricted here, not for GUI code).
    /// Register command-palette entries.
    RegisterCommands,
    /// Display modal dialogs.
    ShowDialogs,
}

impl PluginPermission {
    /// All defined permissions.
    pub fn all() -> &'static [PluginPermission] {
        use PluginPermission::*;
        &[
            ReadBinaryData, WriteBinaryData, ReadFilesystem, WriteFilesystem, CreateDeleteFiles,
            NetworkOutbound, NetworkListen, NetworkDns,
            SpawnProcess, LoadNativeLibrary, ReadEnvironment, WriteEnvironment, RawSyscall,
            EventBusSubscribe, EventBusPublish, RegistryRead, RegistryWrite,
            CapabilityRequest, CapabilityGrant,
            AnalysisRead, AnalysisWrite, AnnotationWrite,
            TypeInfoRead, TypeInfoWrite, CallGraphRead, XrefRead,
            ScriptLua, ScriptPython, ScriptEval,
            RegisterCommands, ShowDialogs,
        ]
    }

    /// Permissions that imply `self` (e.g. Write implies Read).
    pub fn implied_by(&self) -> &'static [PluginPermission] {
        use PluginPermission::*;
        match self {
            ReadFilesystem => &[WriteFilesystem, CreateDeleteFiles],
            WriteFilesystem => &[CreateDeleteFiles],
            NetworkDns => &[NetworkOutbound],
            RegistryRead => &[RegistryWrite],
            AnalysisRead => &[AnalysisWrite],
            TypeInfoRead => &[TypeInfoWrite],
            _ => &[],
        }
    }

    /// True if this permission is considered "dangerous" and requires explicit grant.
    pub fn is_dangerous(&self) -> bool {
        use PluginPermission::*;
        matches!(
            self,
            WriteBinaryData
                | WriteFilesystem
                | CreateDeleteFiles
                | NetworkOutbound
                | NetworkListen
                | SpawnProcess
                | LoadNativeLibrary
                | WriteEnvironment
                | RawSyscall
                | RegistryWrite
                | TypeInfoWrite
                | ScriptEval
        )
    }

    /// True if this permission cannot be granted to sandboxed (untrusted) plugins.
    pub fn sandbox_forbidden(&self) -> bool {
        use PluginPermission::*;
        matches!(
            self,
            RawSyscall | LoadNativeLibrary | SpawnProcess | WriteEnvironment | ScriptEval
        )
    }

    pub fn display_name(&self) -> &'static str {
        use PluginPermission::*;
        match self {
            ReadBinaryData => "read:binary",
            WriteBinaryData => "write:binary",
            ReadFilesystem => "read:filesystem",
            WriteFilesystem => "write:filesystem",
            CreateDeleteFiles => "fs:create_delete",
            NetworkOutbound => "net:outbound",
            NetworkListen => "net:listen",
            NetworkDns => "net:dns",
            SpawnProcess => "proc:spawn",
            LoadNativeLibrary => "proc:load_native",
            ReadEnvironment => "env:read",
            WriteEnvironment => "env:write",
            RawSyscall => "sys:raw_syscall",
            EventBusSubscribe => "bus:subscribe",
            EventBusPublish => "bus:publish",
            RegistryRead => "registry:read",
            RegistryWrite => "registry:write",
            CapabilityRequest => "cap:request",
            CapabilityGrant => "cap:grant",
            AnalysisRead => "analysis:read",
            AnalysisWrite => "analysis:write",
            AnnotationWrite => "annotation:write",
            TypeInfoRead => "types:read",
            TypeInfoWrite => "types:write",
            CallGraphRead => "callgraph:read",
            XrefRead => "xref:read",
            ScriptLua => "script:lua",
            ScriptPython => "script:python",
            ScriptEval => "script:eval",
            RegisterCommands => "ui:commands",
            ShowDialogs => "ui:dialogs",
        }
    }
}

impl fmt::Display for PluginPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

// ─── Permission set ───────────────────────────────────────────────────────────

/// A set of permissions, with implied-permission expansion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionSet {
    granted: HashSet<PluginPermission>,
}

impl PermissionSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_all() -> Self {
        let mut s = Self::new();
        for &p in PluginPermission::all() {
            s.grant(p);
        }
        s
    }

    /// Grant a permission, automatically expanding implications.
    pub fn grant(&mut self, perm: PluginPermission) {
        self.granted.insert(perm);
        // If this perm implies others (e.g. WriteFilesystem → ReadFilesystem), grant those too.
        for &other in PluginPermission::all() {
            if other.implied_by().contains(&perm) && !self.granted.contains(&other) {
                self.granted.insert(other);
            }
        }
    }

    pub fn revoke(&mut self, perm: &PluginPermission) {
        self.granted.remove(perm);
    }

    pub fn has(&self, perm: &PluginPermission) -> bool {
        self.granted.contains(perm)
    }

    pub fn count(&self) -> usize {
        self.granted.len()
    }

    pub fn granted_permissions(&self) -> Vec<PluginPermission> {
        let mut v: Vec<PluginPermission> = self.granted.iter().copied().collect();
        v.sort_by_key(|p| p.display_name());
        v
    }

    pub fn dangerous_permissions(&self) -> Vec<PluginPermission> {
        self.granted.iter().copied().filter(|p| p.is_dangerous()).collect()
    }
}

// ─── Plugin permission profile ────────────────────────────────────────────────

/// Trust level for a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Fully trusted: may be granted any permission.
    Trusted,
    /// Standard plugin: dangerous permissions require explicit grant.
    Standard,
    /// Sandboxed / untrusted: sandbox-forbidden permissions are always denied.
    Sandboxed,
}

/// Complete permission profile for one plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPermissionProfile {
    pub plugin_id: String,
    /// Permissions requested in the plugin manifest.
    pub requested: PermissionSet,
    /// Permissions actually granted.
    pub granted: PermissionSet,
    /// Permissions explicitly denied by the host policy.
    pub denied: PermissionSet,
    /// Trust level assigned to this plugin.
    pub trust_level: TrustLevel,
    /// True if the plugin is in a sandbox.
    pub sandboxed: bool,
}

impl PluginPermissionProfile {
    pub fn new(plugin_id: impl Into<String>, trust_level: TrustLevel) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            requested: PermissionSet::new(),
            granted: PermissionSet::new(),
            denied: PermissionSet::new(),
            trust_level,
            sandboxed: trust_level == TrustLevel::Sandboxed,
        }
    }

    pub fn has(&self, perm: &PluginPermission) -> bool {
        self.granted.has(perm) && !self.denied.has(perm)
    }

    /// Deny a specific permission, overriding any grant.
    pub fn deny(&mut self, perm: PluginPermission) {
        self.denied.grant(perm);
        self.granted.revoke(&perm);
    }

    pub fn grant(&mut self, perm: PluginPermission) {
        self.granted.grant(perm);
        self.denied.revoke(&perm);
    }
}

// ─── Permission checker ───────────────────────────────────────────────────────

/// Thread-safe permission checker used at runtime.
pub struct PermissionChecker {
    profiles: Arc<RwLock<HashMap<String, PluginPermissionProfile>>>,
    /// Global deny list: permissions denied to ALL plugins regardless of profile.
    global_deny: Arc<RwLock<PermissionSet>>,
    /// Audit log of permission checks (plugin_id, perm, allowed).
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    audit_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub plugin_id: String,
    pub permission: PluginPermission,
    pub allowed: bool,
}

impl PermissionChecker {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            global_deny: Arc::new(RwLock::new(PermissionSet::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            audit_limit: 4096,
        }
    }

    pub fn with_audit_limit(mut self, limit: usize) -> Self {
        self.audit_limit = limit;
        self
    }

    pub fn add_plugin(&self, profile: PluginPermissionProfile) {
        self.profiles
            .write()
            .unwrap()
            .insert(profile.plugin_id.clone(), profile);
    }

    pub fn global_deny(&self, perm: PluginPermission) {
        self.global_deny.write().unwrap().grant(perm);
    }

    /// Check whether `plugin_id` has `perm`. Returns `Ok(())` or `Err(PermissionError::Denied)`.
    pub fn check(&self, plugin_id: &str, perm: PluginPermission) -> Result<(), PermissionError> {
        // Global deny overrides everything.
        if self.global_deny.read().unwrap().has(&perm) {
            self.record_audit(plugin_id, perm, false);
            return Err(PermissionError::Denied {
                plugin_id: plugin_id.to_string(),
                perm,
            });
        }

        let profiles = self.profiles.read().unwrap();
        let profile = profiles.get(plugin_id).ok_or_else(|| {
            PermissionError::UnknownPlugin { plugin_id: plugin_id.to_string() }
        })?;

        // Sandbox-forbidden check.
        if profile.sandboxed && perm.sandbox_forbidden() {
            self.record_audit(plugin_id, perm, false);
            return Err(PermissionError::NotGrantableToSandboxed(perm));
        }

        let allowed = profile.has(&perm);
        self.record_audit(plugin_id, perm, allowed);

        if allowed {
            Ok(())
        } else {
            Err(PermissionError::Denied {
                plugin_id: plugin_id.to_string(),
                perm,
            })
        }
    }

    /// Grant a permission to a plugin.
    pub fn grant(&self, plugin_id: &str, perm: PluginPermission) -> Result<(), PermissionError> {
        let mut profiles = self.profiles.write().unwrap();
        let profile = profiles.get_mut(plugin_id).ok_or_else(|| {
            PermissionError::UnknownPlugin { plugin_id: plugin_id.to_string() }
        })?;

        if profile.sandboxed && perm.sandbox_forbidden() {
            return Err(PermissionError::NotGrantableToSandboxed(perm));
        }

        profile.grant(perm);
        Ok(())
    }

    /// Deny a permission for a plugin.
    pub fn deny(&self, plugin_id: &str, perm: PluginPermission) -> Result<(), PermissionError> {
        let mut profiles = self.profiles.write().unwrap();
        let profile = profiles.get_mut(plugin_id).ok_or_else(|| {
            PermissionError::UnknownPlugin { plugin_id: plugin_id.to_string() }
        })?;
        profile.deny(perm);
        Ok(())
    }

    /// Apply a manifest request: grant all requested non-dangerous permissions,
    /// deny sandbox-forbidden ones for sandboxed plugins.
    pub fn apply_manifest(
        &self,
        plugin_id: &str,
        requested: &[PluginPermission],
    ) -> Result<Vec<PluginPermission>, PermissionError> {
        let mut auto_granted: Vec<PluginPermission> = Vec::new();
        let mut profiles = self.profiles.write().unwrap();
        let profile = profiles.get_mut(plugin_id).ok_or_else(|| {
            PermissionError::UnknownPlugin { plugin_id: plugin_id.to_string() }
        })?;

        for &perm in requested {
            profile.requested.grant(perm);
            if profile.sandboxed && perm.sandbox_forbidden() {
                profile.deny(perm);
                continue;
            }
            match profile.trust_level {
                TrustLevel::Trusted => {
                    profile.grant(perm);
                    auto_granted.push(perm);
                }
                TrustLevel::Standard => {
                    if !perm.is_dangerous() {
                        profile.grant(perm);
                        auto_granted.push(perm);
                    }
                }
                TrustLevel::Sandboxed => {
                    if !perm.is_dangerous() && !perm.sandbox_forbidden() {
                        profile.grant(perm);
                        auto_granted.push(perm);
                    }
                }
            }
        }
        Ok(auto_granted)
    }

    /// Return the full profile of a plugin.
    pub fn profile(&self, plugin_id: &str) -> Option<PluginPermissionProfile> {
        self.profiles.read().unwrap().get(plugin_id).cloned()
    }

    /// Permissions still pending approval for a plugin (requested but not yet granted/denied).
    pub fn pending_approvals(&self, plugin_id: &str) -> Vec<PluginPermission> {
        let profiles = self.profiles.read().unwrap();
        let profile = match profiles.get(plugin_id) {
            Some(p) => p,
            None => return vec![],
        };
        profile
            .requested
            .granted_permissions()
            .into_iter()
            .filter(|p| !profile.granted.has(p) && !profile.denied.has(p))
            .collect()
    }

    /// Audit log entries.
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().unwrap().clone()
    }

    fn record_audit(&self, plugin_id: &str, perm: PluginPermission, allowed: bool) {
        let mut log = self.audit_log.write().unwrap();
        log.push(AuditEntry {
            plugin_id: plugin_id.to_string(),
            permission: perm,
            allowed,
        });
        if log.len() > self.audit_limit {
            log.remove(0);
        }
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_plugin(id: &str) -> PluginPermissionProfile {
        PluginPermissionProfile::new(id, TrustLevel::Standard)
    }

    fn trusted_plugin(id: &str) -> PluginPermissionProfile {
        PluginPermissionProfile::new(id, TrustLevel::Trusted)
    }

    fn sandboxed_plugin(id: &str) -> PluginPermissionProfile {
        PluginPermissionProfile::new(id, TrustLevel::Sandboxed)
    }

    #[test]
    fn test_grant_and_check() {
        let checker = PermissionChecker::new();
        let mut profile = standard_plugin("p1");
        profile.grant(PluginPermission::AnalysisRead);
        checker.add_plugin(profile);
        assert!(checker.check("p1", PluginPermission::AnalysisRead).is_ok());
    }

    #[test]
    fn test_denied_permission() {
        let checker = PermissionChecker::new();
        checker.add_plugin(standard_plugin("p1"));
        assert!(matches!(
            checker.check("p1", PluginPermission::AnalysisRead),
            Err(PermissionError::Denied { .. })
        ));
    }

    #[test]
    fn test_unknown_plugin() {
        let checker = PermissionChecker::new();
        assert!(matches!(
            checker.check("ghost", PluginPermission::AnalysisRead),
            Err(PermissionError::UnknownPlugin { .. })
        ));
    }

    #[test]
    fn test_global_deny_overrides_grant() {
        let checker = PermissionChecker::new();
        let mut profile = standard_plugin("p1");
        profile.grant(PluginPermission::NetworkOutbound);
        checker.add_plugin(profile);
        checker.global_deny(PluginPermission::NetworkOutbound);
        assert!(checker.check("p1", PluginPermission::NetworkOutbound).is_err());
    }

    #[test]
    fn test_sandbox_forbidden_denied() {
        let checker = PermissionChecker::new();
        let mut profile = sandboxed_plugin("p1");
        // Even if we try to grant directly, sandbox_forbidden check still fires.
        profile.grant(PluginPermission::RawSyscall);
        checker.add_plugin(profile);
        assert!(matches!(
            checker.check("p1", PluginPermission::RawSyscall),
            Err(PermissionError::NotGrantableToSandboxed(_))
        ));
    }

    #[test]
    fn test_apply_manifest_standard_auto_grants_safe() {
        let checker = PermissionChecker::new();
        checker.add_plugin(standard_plugin("p1"));
        let granted = checker
            .apply_manifest("p1", &[PluginPermission::AnalysisRead])
            .unwrap();
        assert!(granted.contains(&PluginPermission::AnalysisRead));
        assert!(checker.check("p1", PluginPermission::AnalysisRead).is_ok());
    }

    #[test]
    fn test_apply_manifest_standard_does_not_auto_grant_dangerous() {
        let checker = PermissionChecker::new();
        checker.add_plugin(standard_plugin("p1"));
        let granted = checker
            .apply_manifest("p1", &[PluginPermission::WriteBinaryData])
            .unwrap();
        assert!(!granted.contains(&PluginPermission::WriteBinaryData));
    }

    #[test]
    fn test_apply_manifest_trusted_grants_dangerous() {
        let checker = PermissionChecker::new();
        checker.add_plugin(trusted_plugin("p1"));
        let granted = checker
            .apply_manifest("p1", &[PluginPermission::WriteBinaryData])
            .unwrap();
        assert!(granted.contains(&PluginPermission::WriteBinaryData));
    }

    #[test]
    fn test_explicit_grant_after_manifest() {
        let checker = PermissionChecker::new();
        checker.add_plugin(standard_plugin("p1"));
        checker.apply_manifest("p1", &[PluginPermission::WriteBinaryData]).unwrap();
        // Not yet granted (dangerous, standard plugin).
        assert!(checker.check("p1", PluginPermission::WriteBinaryData).is_err());
        // Host explicitly grants.
        checker.grant("p1", PluginPermission::WriteBinaryData).unwrap();
        assert!(checker.check("p1", PluginPermission::WriteBinaryData).is_ok());
    }

    #[test]
    fn test_deny_revokes_granted_permission() {
        let checker = PermissionChecker::new();
        let mut profile = standard_plugin("p1");
        profile.grant(PluginPermission::AnalysisRead);
        checker.add_plugin(profile);
        checker.deny("p1", PluginPermission::AnalysisRead).unwrap();
        assert!(checker.check("p1", PluginPermission::AnalysisRead).is_err());
    }

    #[test]
    fn test_implied_permission_expansion() {
        let mut set = PermissionSet::new();
        set.grant(PluginPermission::WriteFilesystem);
        // WriteFilesystem implies ReadFilesystem.
        assert!(set.has(&PluginPermission::ReadFilesystem));
    }

    #[test]
    fn test_audit_log_records_checks() {
        let checker = PermissionChecker::new();
        checker.add_plugin(standard_plugin("p1"));
        let _ = checker.check("p1", PluginPermission::AnalysisRead);
        let log = checker.audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].plugin_id, "p1");
        assert!(!log[0].allowed);
    }

    #[test]
    fn test_permission_set_has_all() {
        let set = PermissionSet::with_all();
        for &p in PluginPermission::all() {
            assert!(set.has(&p), "missing {p}");
        }
    }

    #[test]
    fn test_dangerous_permissions_list() {
        let mut set = PermissionSet::new();
        set.grant(PluginPermission::WriteBinaryData);
        set.grant(PluginPermission::AnalysisRead);
        let dangerous = set.dangerous_permissions();
        assert!(dangerous.contains(&PluginPermission::WriteBinaryData));
        assert!(!dangerous.contains(&PluginPermission::AnalysisRead));
    }
}
