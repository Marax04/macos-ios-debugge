//! Plugin sandboxing and permission model.
//!
//! Defines the [`SandboxPolicy`], [`PermissionSet`], [`SandboxViolation`],
//! and [`PluginSandbox`] that enforces runtime constraints on plugin behavior.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// Permission
// ─────────────────────────────────────────────────────────────────────────────

/// A single permission a plugin may hold.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ReadBinaryView,
    WriteBinaryView,
    FileSystem(PathBuf),
    Network,
    Subprocess,
    Ui,
    LoadLibrary,
    ExecutableMemory,
    Custom(String),
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadBinaryView => f.write_str("read_binary_view"),
            Self::WriteBinaryView => f.write_str("write_binary_view"),
            Self::FileSystem(p) => write!(f, "filesystem:{}", p.display()),
            Self::Network => f.write_str("network"),
            Self::Subprocess => f.write_str("subprocess"),
            Self::Ui => f.write_str("ui"),
            Self::LoadLibrary => f.write_str("load_library"),
            Self::ExecutableMemory => f.write_str("executable_memory"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PermissionSet
// ─────────────────────────────────────────────────────────────────────────────

/// A set of permissions.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PermissionSet {
    inner: Vec<Permission>,
}

impl PermissionSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allow(mut self, p: Permission) -> Self {
        self.inner.push(p);
        self
    }

    pub fn grant(&mut self, p: Permission) {
        self.inner.push(p);
    }

    #[must_use]
    pub fn has(&self, p: &Permission) -> bool {
        self.inner.contains(p)
    }

    #[must_use]
    pub fn has_filesystem(&self, path: &Path) -> bool {
        self.inner.iter().any(|perm| {
            if let Permission::FileSystem(allowed) = perm {
                path.starts_with(allowed)
            } else {
                false
            }
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All permissions as a display string list.
    #[must_use]
    pub fn display_list(&self) -> Vec<String> {
        self.inner.iter().map(ToString::to_string).collect::<Vec<_>>()
    }

    /// Number of unique permissions, ignoring duplicates.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        let set: HashSet<&Permission> = self.inner.iter().collect();
        set.len()
    }
}

/// Predefined permission sets.
impl PermissionSet {
    /// Minimal permissions (read-only binary view).
    #[must_use]
    pub fn read_only() -> Self {
        Self::new().allow(Permission::ReadBinaryView)
    }

    /// Standard analysis plugin permissions.
    #[must_use]
    pub fn standard_analysis() -> Self {
        Self::new()
            .allow(Permission::ReadBinaryView)
            .allow(Permission::WriteBinaryView)
    }

    /// Full trust (all permissions).
    #[must_use]
    pub fn full_trust() -> Self {
        Self::new()
            .allow(Permission::ReadBinaryView)
            .allow(Permission::WriteBinaryView)
            .allow(Permission::Network)
            .allow(Permission::Subprocess)
            .allow(Permission::Ui)
            .allow(Permission::LoadLibrary)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy controlling what a sandboxed plugin may do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub name: String,
    pub permissions: PermissionSet,
    /// Maximum memory (bytes) a plugin may allocate. 0 = unlimited.
    pub max_memory_bytes: u64,
    /// Maximum wall-clock time (ms) per plugin invocation. 0 = unlimited.
    pub max_time_ms: u64,
    /// Maximum number of file handles open simultaneously.
    pub max_open_files: u32,
    /// Whether the plugin may log messages.
    pub allow_logging: bool,
    /// Whether plugin crashes should be caught and reported vs. propagated.
    pub isolate_crashes: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            permissions: PermissionSet::standard_analysis(),
            max_memory_bytes: 256 * 1024 * 1024, // 256 MiB
            max_time_ms: 30_000,                 // 30 seconds
            max_open_files: 16,
            allow_logging: true,
            isolate_crashes: true,
        }
    }
}

impl SandboxPolicy {
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            permissions: PermissionSet::read_only(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn full_trust() -> Self {
        Self {
            name: "full_trust".to_string(),
            permissions: PermissionSet::full_trust(),
            max_memory_bytes: 0,
            max_time_ms: 0,
            max_open_files: 0,
            allow_logging: true,
            isolate_crashes: false,
        }
    }

    #[must_use]
    pub fn allows(&self, p: &Permission) -> bool {
        self.permissions.has(p)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxViolation
// ─────────────────────────────────────────────────────────────────────────────

/// A sandbox policy violation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxViolation {
    pub plugin_id: String,
    pub permission: String,
    pub description: String,
    pub timestamp_ms: u64,
    pub action_taken: ViolationAction,
}

/// What was done in response to a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationAction {
    Denied,
    Terminated,
    Logged,
}

impl fmt::Display for ViolationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied => f.write_str("denied"),
            Self::Terminated => f.write_str("terminated"),
            Self::Logged => f.write_str("logged"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceUsage
// ─────────────────────────────────────────────────────────────────────────────

/// Tracked resource usage for a plugin.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_time_ms: u64,
    pub open_files: u32,
    pub network_bytes_sent: u64,
    pub network_bytes_recv: u64,
    pub messages_sent: u64,
}

impl ResourceUsage {
    #[must_use]
    pub fn exceeds_policy(&self, policy: &SandboxPolicy) -> Vec<String> {
        let mut violations = Vec::new();
        if policy.max_memory_bytes > 0 && self.memory_bytes > policy.max_memory_bytes {
            violations.push(format!(
                "memory: {} > {}",
                self.memory_bytes, policy.max_memory_bytes
            ));
        }
        if policy.max_time_ms > 0 && self.cpu_time_ms > policy.max_time_ms {
            violations.push(format!(
                "time: {} > {}",
                self.cpu_time_ms, policy.max_time_ms
            ));
        }
        if policy.max_open_files > 0 && self.open_files > policy.max_open_files {
            violations.push(format!(
                "open_files: {} > {}",
                self.open_files, policy.max_open_files
            ));
        }
        violations
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginSandbox
// ─────────────────────────────────────────────────────────────────────────────

/// Enforces [`SandboxPolicy`] for a single plugin instance.
pub struct PluginSandbox {
    pub plugin_id: String,
    pub policy: SandboxPolicy,
    pub usage: ResourceUsage,
    pub violations: Vec<SandboxViolation>,
    pub is_active: bool,
    clock_ms: u64,
}

impl PluginSandbox {
    pub fn new(plugin_id: impl Into<String>, policy: SandboxPolicy) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            policy,
            usage: ResourceUsage::default(),
            violations: Vec::new(),
            is_active: true,
            clock_ms: 0,
        }
    }

    /// Check permission.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn check_permission(&mut self, perm: &Permission) -> Result<(), String> {
        if self.policy.allows(perm) {
            Ok(())
        } else {
            let v = SandboxViolation {
                plugin_id: self.plugin_id.clone(),
                permission: format!("{perm}"),
                description: format!("denied: {perm}"),
                timestamp_ms: self.clock_ms,
                action_taken: ViolationAction::Denied,
            };
            self.violations.push(v);
            Err(format!("permission denied: {perm}"))
        }
    }

    /// Alloc memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Record memory allocation. Returns error if over limit.
    pub fn alloc_memory(&mut self, bytes: u64) -> Result<(), String> {
        let new_total = self.usage.memory_bytes + bytes;
        if self.policy.max_memory_bytes > 0 && new_total > self.policy.max_memory_bytes {
            self.record_violation(
                "memory",
                &format!("{} > {}", new_total, self.policy.max_memory_bytes),
            );
            return Err("memory limit exceeded".into());
        }
        self.usage.memory_bytes = new_total;
        Ok(())
    }

    /// Advance clock.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Record time elapsed.
    pub fn advance_clock(&mut self, ms: u64) -> Result<(), String> {
        self.clock_ms += ms;
        self.usage.cpu_time_ms += ms;
        if self.policy.max_time_ms > 0 && self.usage.cpu_time_ms > self.policy.max_time_ms {
            self.record_violation(
                "timeout",
                &format!("{} > {}", self.usage.cpu_time_ms, self.policy.max_time_ms),
            );
            self.is_active = false;
            return Err("time limit exceeded".into());
        }
        Ok(())
    }

    fn record_violation(&mut self, perm: &str, desc: &str) {
        self.violations.push(SandboxViolation {
            plugin_id: self.plugin_id.clone(),
            permission: perm.to_string(),
            description: desc.to_string(),
            timestamp_ms: self.clock_ms,
            action_taken: ViolationAction::Denied,
        });
    }

    #[must_use]
    pub const fn violation_count(&self) -> usize {
        self.violations.len()
    }
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.is_active && self.violations.is_empty()
    }
}

impl fmt::Debug for PluginSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginSandbox")
            .field("plugin_id", &self.plugin_id)
            .field("active", &self.is_active)
            .field("violations", &self.violations.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Permission ---

    #[test]
    fn permission_display_read_binary() {
        assert_eq!(
            format!("{}", Permission::ReadBinaryView),
            "read_binary_view"
        );
    }

    #[test]
    fn permission_display_filesystem() {
        let p = Permission::FileSystem(PathBuf::from("/tmp"));
        assert!(format!("{p}").contains("/tmp"));
    }

    #[test]
    fn permission_display_custom() {
        let p = Permission::Custom("my_perm".into());
        assert!(format!("{p}").contains("my_perm"));
    }

    // --- PermissionSet ---

    #[test]
    fn permission_set_has() {
        let ps = PermissionSet::read_only();
        assert!(ps.has(&Permission::ReadBinaryView));
        assert!(!ps.has(&Permission::Network));
    }

    #[test]
    fn permission_set_filesystem() {
        let mut ps = PermissionSet::new();
        ps.grant(Permission::FileSystem(PathBuf::from("/tmp/rustre")));
        assert!(ps.has_filesystem(Path::new("/tmp/rustre/out.json")));
        assert!(!ps.has_filesystem(Path::new("/etc/passwd")));
    }

    #[test]
    fn permission_set_full_trust_has_network() {
        let ps = PermissionSet::full_trust();
        assert!(ps.has(&Permission::Network));
    }

    #[test]
    fn permission_set_display_list() {
        let ps = PermissionSet::read_only();
        assert!(!ps.display_list().is_empty());
    }

    // --- SandboxPolicy ---

    #[test]
    fn policy_default_allows_read() {
        let p = SandboxPolicy::default();
        assert!(p.allows(&Permission::ReadBinaryView));
    }

    #[test]
    fn policy_default_denies_network() {
        let p = SandboxPolicy::default();
        assert!(!p.allows(&Permission::Network));
    }

    #[test]
    fn policy_full_trust_allows_all() {
        let p = SandboxPolicy::full_trust();
        assert!(p.allows(&Permission::Network));
        assert!(p.allows(&Permission::Subprocess));
    }

    #[test]
    fn policy_read_only() {
        let p = SandboxPolicy::read_only();
        assert!(p.allows(&Permission::ReadBinaryView));
        assert!(!p.allows(&Permission::WriteBinaryView));
    }

    // --- ResourceUsage ---

    #[test]
    fn resource_usage_no_violations() {
        let usage = ResourceUsage {
            memory_bytes: 1024,
            ..Default::default()
        };
        let policy = SandboxPolicy::default();
        assert!(usage.exceeds_policy(&policy).is_empty());
    }

    #[test]
    fn resource_usage_memory_violation() {
        let policy = SandboxPolicy {
            max_memory_bytes: 100,
            ..Default::default()
        };
        let usage = ResourceUsage {
            memory_bytes: 200,
            ..Default::default()
        };
        assert!(!usage.exceeds_policy(&policy).is_empty());
    }

    #[test]
    fn resource_usage_time_violation() {
        let policy = SandboxPolicy {
            max_time_ms: 1000,
            ..Default::default()
        };
        let usage = ResourceUsage {
            cpu_time_ms: 2000,
            ..Default::default()
        };
        assert!(!usage.exceeds_policy(&policy).is_empty());
    }

    // --- PluginSandbox ---

    #[test]
    fn sandbox_allows_granted_perm() {
        let mut sb = PluginSandbox::new("p1", SandboxPolicy::default());
        assert!(sb.check_permission(&Permission::ReadBinaryView).is_ok());
    }

    #[test]
    fn sandbox_denies_ungrant_perm() {
        let mut sb = PluginSandbox::new("p1", SandboxPolicy::default());
        assert!(sb.check_permission(&Permission::Network).is_err());
        assert_eq!(sb.violation_count(), 1);
    }

    #[test]
    fn sandbox_alloc_memory_ok() {
        let mut sb = PluginSandbox::new("p1", SandboxPolicy::default());
        assert!(sb.alloc_memory(1024).is_ok());
        assert_eq!(sb.usage.memory_bytes, 1024);
    }

    #[test]
    fn sandbox_alloc_memory_limit() {
        let policy = SandboxPolicy {
            max_memory_bytes: 512,
            ..Default::default()
        };
        let mut sb = PluginSandbox::new("p1", policy);
        assert!(sb.alloc_memory(600).is_err());
    }

    #[test]
    fn sandbox_advance_clock_ok() {
        let mut sb = PluginSandbox::new("p1", SandboxPolicy::default());
        assert!(sb.advance_clock(100).is_ok());
    }

    #[test]
    fn sandbox_advance_clock_timeout() {
        let policy = SandboxPolicy {
            max_time_ms: 50,
            ..Default::default()
        };
        let mut sb = PluginSandbox::new("p1", policy);
        assert!(sb.advance_clock(100).is_err());
        assert!(!sb.is_active);
    }

    #[test]
    fn sandbox_is_healthy_initially() {
        let sb = PluginSandbox::new("p1", SandboxPolicy::default());
        assert!(sb.is_healthy());
    }

    #[test]
    fn sandbox_unhealthy_after_violation() {
        let mut sb = PluginSandbox::new("p1", SandboxPolicy::default());
        sb.check_permission(&Permission::Network).ok();
        assert!(!sb.is_healthy());
    }

    #[test]
    fn violation_action_display() {
        assert_eq!(format!("{}", ViolationAction::Denied), "denied");
    }
}
