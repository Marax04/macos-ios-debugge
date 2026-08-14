// rustre-plugin-api/src/sandbox.rs
// Plugin sandbox isolation: resource limits, capability enforcement, policy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::{PluginContext, PluginError, PluginResult};

// ─── Capability Bitfield ─────────────────────────────────────────────────────

/// Fine-grained permission bitfield for sandboxed plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(pub u64);

impl CapabilitySet {
    pub const NONE: Self = Self(0);
    pub const READ_MEMORY: Self = Self(1 << 0);
    pub const WRITE_MEMORY: Self = Self(1 << 1);
    pub const EXECUTE_CODE: Self = Self(1 << 2);
    pub const READ_FS: Self = Self(1 << 3);
    pub const WRITE_FS: Self = Self(1 << 4);
    pub const NETWORK: Self = Self(1 << 5);
    pub const SPAWN_THREADS: Self = Self(1 << 6);
    pub const UI: Self = Self(1 << 7);
    pub const DEBUGGER: Self = Self(1 << 8);
    pub const MODIFY_GRAPH: Self = Self(1 << 9);
    pub const REGISTER_CMDS: Self = Self(1 << 10);
    pub const MODIFY_BINARY: Self = Self(1 << 11);
    pub const IPC: Self = Self(1 << 12);
    pub const ENV_VARS: Self = Self(1 << 13);
    pub const DYNAMIC_LOAD: Self = Self(1 << 14);
    pub const SIGNAL: Self = Self(1 << 15);

    /// All capabilities granted.
    pub const ALL: Self = Self(u64::MAX);

    /// Standard analysis-only set.
    #[must_use]
    pub const fn analysis_standard() -> Self {
        Self(Self::READ_MEMORY.0 | Self::READ_FS.0 | Self::MODIFY_GRAPH.0 | Self::REGISTER_CMDS.0)
    }

    /// Combine two capability sets (union).
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection of two capability sets.
    #[inline]
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Check if a specific capability is granted.
    #[inline]
    #[must_use]
    pub const fn has(self, cap: Self) -> bool {
        (self.0 & cap.0) == cap.0
    }

    /// Grant a capability.
    #[inline]
    pub const fn grant(&mut self, cap: Self) {
        self.0 |= cap.0;
    }

    /// Revoke a capability.
    #[inline]
    pub const fn revoke(&mut self, cap: Self) {
        self.0 &= !cap.0;
    }

    /// Return list of human-readable capability names that are set.
    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        let all = [
            (Self::READ_MEMORY, "read_memory"),
            (Self::WRITE_MEMORY, "write_memory"),
            (Self::EXECUTE_CODE, "execute_code"),
            (Self::READ_FS, "read_fs"),
            (Self::WRITE_FS, "write_fs"),
            (Self::NETWORK, "network"),
            (Self::SPAWN_THREADS, "spawn_threads"),
            (Self::UI, "ui"),
            (Self::DEBUGGER, "debugger"),
            (Self::MODIFY_GRAPH, "modify_graph"),
            (Self::REGISTER_CMDS, "register_commands"),
            (Self::MODIFY_BINARY, "modify_binary"),
            (Self::IPC, "ipc"),
            (Self::ENV_VARS, "env_vars"),
            (Self::DYNAMIC_LOAD, "dynamic_load"),
            (Self::SIGNAL, "signal"),
        ];
        all.iter()
            .filter(|(c, _)| self.has(*c))
            .map(|(_, n)| *n)
            .collect()
    }
}

// ─── Sandbox Violation ───────────────────────────────────────────────────────

/// Describes what resource limit or policy was violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    MemoryExceeded {
        used_bytes: usize,
        limit_bytes: usize,
    },
    TimeoutExceeded {
        used_ms: u64,
        limit_ms: u64,
    },
    NetworkDenied {
        destination: Option<String>,
    },
    FilesystemDenied {
        path: String,
        write: bool,
    },
    CapabilityDenied {
        capability: &'static str,
    },
    FileHandleLimitExceeded {
        limit: usize,
    },
    ThreadSpawnDenied,
    DynamicLoadDenied {
        path: String,
    },
    PolicyViolation(String),
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryExceeded {
                used_bytes,
                limit_bytes,
            } => write!(
                f,
                "Memory limit exceeded: used {used_bytes} bytes, limit {limit_bytes} bytes"
            ),
            Self::TimeoutExceeded { used_ms, limit_ms } => write!(
                f,
                "CPU timeout exceeded: used {used_ms}ms, limit {limit_ms}ms"
            ),
            Self::NetworkDenied { destination } => {
                write!(f, "Network access denied (destination: {destination:?})")
            }
            Self::FilesystemDenied { path, write } => write!(
                f,
                "Filesystem {} denied: {}",
                if *write { "write" } else { "read" },
                path
            ),
            Self::CapabilityDenied { capability } => write!(f, "Capability denied: {capability}"),
            Self::FileHandleLimitExceeded { limit } => {
                write!(f, "File handle limit exceeded: max {limit}")
            }
            Self::ThreadSpawnDenied => write!(f, "Thread spawn denied by sandbox"),
            Self::DynamicLoadDenied { path } => write!(f, "Dynamic library load denied: {path}"),
            Self::PolicyViolation(msg) => write!(f, "Policy violation: {msg}"),
        }
    }
}

impl std::error::Error for SandboxViolation {}

pub type SandboxResult<T> = Result<T, SandboxViolation>;

// ─── Resource Limits ─────────────────────────────────────────────────────────

/// Configures the resource limits enforced by the sandbox.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum heap memory in bytes (0 = unlimited).
    pub max_memory_bytes: usize,
    /// Maximum CPU wall-clock time in milliseconds (0 = unlimited).
    pub max_cpu_ms: u64,
    /// Maximum number of simultaneously open file descriptors.
    pub max_file_handles: usize,
    /// Whether outbound network connections are permitted.
    pub network_allowed: bool,
    /// Whether spawning new OS threads is permitted.
    pub threads_allowed: bool,
    /// Maximum number of allocations tracked (0 = unlimited).
    pub max_allocations: usize,
    /// Paths the plugin may read (empty = unrestricted if `READ_FS` granted).
    pub allowed_read_paths: Vec<String>,
    /// Paths the plugin may write (empty = no write paths).
    pub allowed_write_paths: Vec<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MiB
            max_cpu_ms: 5_000,                  // 5 s
            max_file_handles: 64,
            network_allowed: false,
            threads_allowed: false,
            max_allocations: 0,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
        }
    }
}

impl ResourceLimits {
    /// Permissive limits for trusted plugins.
    #[must_use]
    pub const fn trusted() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,
            max_cpu_ms: 60_000,
            max_file_handles: 256,
            network_allowed: true,
            threads_allowed: true,
            max_allocations: 0,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
        }
    }

    /// Very tight limits for untrusted/unknown plugins.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_memory_bytes: 8 * 1024 * 1024,
            max_cpu_ms: 500,
            max_file_handles: 8,
            network_allowed: false,
            threads_allowed: false,
            max_allocations: 1_000,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
        }
    }

    /// Check if a given path is readable.
    #[must_use]
    pub fn is_path_readable(&self, path: &str) -> bool {
        if self.allowed_read_paths.is_empty() {
            return true;
        }
        self.allowed_read_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    /// Check if a given path is writable.
    #[must_use]
    pub fn is_path_writable(&self, path: &str) -> bool {
        if self.allowed_write_paths.is_empty() {
            return false;
        }
        self.allowed_write_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }
}

// ─── Resource Tracker ────────────────────────────────────────────────────────

/// Tracks live resource usage for a sandboxed plugin.
#[derive(Debug, Clone, Default)]
pub struct ResourceTracker {
    /// Current estimated heap usage in bytes.
    pub current_memory_bytes: usize,
    /// Peak heap usage observed so far.
    pub peak_memory_bytes: usize,
    /// Number of allocation events recorded.
    pub allocation_count: usize,
    /// Total bytes allocated over the lifetime of the plugin.
    pub total_allocated_bytes: usize,
    /// Number of currently open file handles.
    pub open_file_handles: usize,
    /// Number of file handles ever opened.
    pub total_file_opens: usize,
    /// Wall-clock time the plugin has spent executing (accumulated).
    pub cpu_time_ms: u64,
    /// Number of network operations attempted (regardless of deny).
    pub network_ops: u64,
    /// Number of sandbox violations triggered.
    pub violation_count: u64,
}

impl ResourceTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a heap allocation of `bytes`.
    pub const fn record_alloc(&mut self, bytes: usize) {
        self.current_memory_bytes = self.current_memory_bytes.saturating_add(bytes);
        self.total_allocated_bytes = self.total_allocated_bytes.saturating_add(bytes);
        self.allocation_count += 1;
        if self.current_memory_bytes > self.peak_memory_bytes {
            self.peak_memory_bytes = self.current_memory_bytes;
        }
    }

    /// Record a heap deallocation of `bytes`.
    pub const fn record_dealloc(&mut self, bytes: usize) {
        self.current_memory_bytes = self.current_memory_bytes.saturating_sub(bytes);
    }

    /// Record opening a file handle.
    pub const fn open_handle(&mut self) {
        self.open_file_handles += 1;
        self.total_file_opens += 1;
    }

    /// Record closing a file handle.
    pub const fn close_handle(&mut self) {
        if self.open_file_handles > 0 {
            self.open_file_handles -= 1;
        }
    }

    /// Accumulate `ms` milliseconds of CPU time.
    pub const fn add_cpu_ms(&mut self, ms: u64) {
        self.cpu_time_ms = self.cpu_time_ms.saturating_add(ms);
    }

    /// Record a network operation attempt.
    pub const fn record_network_op(&mut self) {
        self.network_ops += 1;
    }

    /// Record a sandbox violation.
    pub const fn record_violation(&mut self) {
        self.violation_count += 1;
    }

    /// Check memory against limit (returns Err on violation).
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::MemoryExceeded`] when the tracked memory exceeds the configured limit.
    pub const fn check_memory(&self, limits: &ResourceLimits) -> SandboxResult<()> {
        if limits.max_memory_bytes > 0 && self.current_memory_bytes > limits.max_memory_bytes {
            return Err(SandboxViolation::MemoryExceeded {
                used_bytes: self.current_memory_bytes,
                limit_bytes: limits.max_memory_bytes,
            });
        }
        Ok(())
    }

    /// Check CPU time against limit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::TimeoutExceeded`] when accumulated CPU time exceeds the configured limit.
    pub const fn check_cpu(&self, limits: &ResourceLimits) -> SandboxResult<()> {
        if limits.max_cpu_ms > 0 && self.cpu_time_ms > limits.max_cpu_ms {
            return Err(SandboxViolation::TimeoutExceeded {
                used_ms: self.cpu_time_ms,
                limit_ms: limits.max_cpu_ms,
            });
        }
        Ok(())
    }

    /// Check file handle count against limit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::FileHandleLimitExceeded`] when the open handle count meets or exceeds the limit.
    pub const fn check_handles(&self, limits: &ResourceLimits) -> SandboxResult<()> {
        if self.open_file_handles >= limits.max_file_handles {
            return Err(SandboxViolation::FileHandleLimitExceeded {
                limit: limits.max_file_handles,
            });
        }
        Ok(())
    }
}

// ─── Sandbox Policy ──────────────────────────────────────────────────────────

/// Named profiles that bundle a `ResourceLimits` + `CapabilitySet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxPolicy {
    Strict,
    Standard,
    Trusted,
    Custom {
        limits: ResourceLimitsSnapshot,
        capabilities: CapabilitySet,
    },
}

/// A snapshot of resource limit values (used inside `SandboxPolicy::Custom`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimitsSnapshot {
    pub max_memory_bytes: usize,
    pub max_cpu_ms: u64,
    pub max_file_handles: usize,
    pub network_allowed: bool,
    pub threads_allowed: bool,
}

impl SandboxPolicy {
    #[must_use]
    pub fn limits(&self) -> ResourceLimits {
        match self {
            Self::Strict => ResourceLimits::strict(),
            Self::Standard => ResourceLimits::default(),
            Self::Trusted => ResourceLimits::trusted(),
            Self::Custom { limits, .. } => ResourceLimits {
                max_memory_bytes: limits.max_memory_bytes,
                max_cpu_ms: limits.max_cpu_ms,
                max_file_handles: limits.max_file_handles,
                network_allowed: limits.network_allowed,
                threads_allowed: limits.threads_allowed,
                ..Default::default()
            },
        }
    }

    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        match self {
            Self::Strict => CapabilitySet::analysis_standard().intersect(CapabilitySet(
                CapabilitySet::READ_FS.0 | CapabilitySet::MODIFY_GRAPH.0,
            )),
            Self::Standard => CapabilitySet::analysis_standard(),
            Self::Trusted => CapabilitySet::ALL,
            Self::Custom { capabilities, .. } => *capabilities,
        }
    }
}

// ─── Plugin Sandbox ──────────────────────────────────────────────────────────

/// A sandbox that wraps a plugin and enforces resource + capability limits.
pub struct PluginSandbox {
    pub policy: SandboxPolicy,
    pub limits: ResourceLimits,
    pub capabilities: CapabilitySet,
    tracker: Arc<Mutex<ResourceTracker>>,
    violations: Arc<Mutex<Vec<SandboxViolation>>>,
    wall_start: Option<Instant>,
}

impl PluginSandbox {
    /// Create a sandbox with an explicit policy.
    #[must_use]
    pub fn with_policy(policy: SandboxPolicy) -> Self {
        let limits = policy.limits();
        let caps = policy.capabilities();
        Self {
            policy,
            limits,
            capabilities: caps,
            tracker: Arc::new(Mutex::new(ResourceTracker::new())),
            violations: Arc::new(Mutex::new(Vec::new())),
            wall_start: None,
        }
    }

    /// Create strict sandbox.
    #[must_use]
    pub fn strict() -> Self {
        Self::with_policy(SandboxPolicy::Strict)
    }
    /// Create standard sandbox.
    #[must_use]
    pub fn standard() -> Self {
        Self::with_policy(SandboxPolicy::Standard)
    }
    /// Create trusted sandbox.
    #[must_use]
    pub fn trusted() -> Self {
        Self::with_policy(SandboxPolicy::Trusted)
    }

    /// Record the start of a timed operation.
    pub fn begin_call(&mut self) {
        self.wall_start = Some(Instant::now());
    }

    /// Record the end of a timed operation; accumulates wall time into tracker.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn end_call(&mut self) {
        if let Some(start) = self.wall_start.take() {
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.tracker.lock().unwrap().add_cpu_ms(ms);
        }
    }

    /// Check whether a capability is granted by this sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::CapabilityDenied`] when the requested capability is not granted.
    pub fn check_capability(&self, cap: CapabilitySet) -> SandboxResult<()> {
        if self.capabilities.has(cap) {
            Ok(())
        } else {
            let name = cap.describe().into_iter().next().unwrap_or("unknown");
            Err(SandboxViolation::CapabilityDenied { capability: name })
        }
    }

    /// Check network access.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::NetworkDenied`] when the policy disallows network access.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn check_network(&self, destination: Option<&str>) -> SandboxResult<()> {
        if !self.limits.network_allowed {
            self.tracker.lock().unwrap().record_violation();
            return Err(SandboxViolation::NetworkDenied {
                destination: destination.map(std::string::ToString::to_string),
            });
        }
        self.tracker.lock().unwrap().record_network_op();
        Ok(())
    }

    /// Check filesystem access against the policy.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::FilesystemDenied`] when the path is not allowed by the policy.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn check_filesystem(&self, path: &str, write: bool) -> SandboxResult<()> {
        let ok = if write {
            self.limits.is_path_writable(path)
        } else {
            self.limits.is_path_readable(path)
        };
        if !ok {
            self.tracker.lock().unwrap().record_violation();
            return Err(SandboxViolation::FilesystemDenied {
                path: path.to_string(),
                write,
            });
        }
        Ok(())
    }

    /// Record a heap allocation and check the memory limit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::MemoryExceeded`] when the new total exceeds the configured limit.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn track_alloc(&self, bytes: usize) -> SandboxResult<()> {
        let mut t = self.tracker.lock().unwrap();
        t.record_alloc(bytes);
        t.check_memory(&self.limits)
    }

    /// Record a heap deallocation.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn track_dealloc(&self, bytes: usize) {
        self.tracker.lock().unwrap().record_dealloc(bytes);
    }

    /// Open a file handle, checking the open-handle limit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxViolation::FileHandleLimitExceeded`] when the open handle count meets or exceeds the limit.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn open_file_handle(&self) -> SandboxResult<()> {
        let mut t = self.tracker.lock().unwrap();
        t.check_handles(&self.limits)?;
        t.open_handle();
        drop(t);
        Ok(())
    }

    /// Close a previously opened file handle.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    pub fn close_file_handle(&self) {
        self.tracker.lock().unwrap().close_handle();
    }

    /// Snapshot the current resource usage.
    ///
    /// # Panics
    ///
    /// Panics if the internal tracker mutex is poisoned.
    #[must_use]
    pub fn snapshot(&self) -> ResourceTracker {
        self.tracker.lock().unwrap().clone()
    }

    /// All violations recorded so far.
    ///
    /// # Panics
    ///
    /// Panics if the internal violations mutex is poisoned.
    #[must_use]
    pub fn violations(&self) -> Vec<SandboxViolation> {
        self.violations.lock().unwrap().clone()
    }

    /// Record an explicit violation (used by the wrapper).
    ///
    /// # Panics
    ///
    /// Panics if any internal mutex is poisoned.
    pub fn record_violation(&self, v: SandboxViolation) {
        let mut t = self.tracker.lock().unwrap();
        t.record_violation();
        drop(t);
        self.violations.lock().unwrap().push(v);
    }

    /// True if any violations have been recorded.
    ///
    /// # Panics
    ///
    /// Panics if the internal violations mutex is poisoned.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        !self.violations.lock().unwrap().is_empty()
    }
}

// ─── Sandboxed Plugin Wrapper ────────────────────────────────────────────────

/// Wraps a `Box<dyn Plugin>` + `PluginSandbox`, enforcing limits on every call.
pub struct SandboxedPlugin {
    inner: Box<dyn crate::Plugin>,
    sandbox: PluginSandbox,
}

impl SandboxedPlugin {
    #[must_use]
    pub fn new(plugin: Box<dyn crate::Plugin>, policy: SandboxPolicy) -> Self {
        Self {
            inner: plugin,
            sandbox: PluginSandbox::with_policy(policy),
        }
    }

    /// Initialize the plugin, enforcing time limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the wrapped plugin's `init` fails or if a sandbox limit
    /// (CPU time, memory, etc.) is exceeded during initialization.
    pub fn init(&mut self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.sandbox.begin_call();
        let result = self.inner.init(ctx);
        self.sandbox.end_call();
        // Check accumulated CPU after init
        let tracker = self.sandbox.snapshot();
        if let Err(v) = tracker.check_cpu(&self.sandbox.limits) {
            self.sandbox.record_violation(v.clone());
            return Err(PluginError::PermissionDenied(v.to_string()));
        }
        result
    }

    /// Unload the plugin.
    pub fn unload(&mut self, ctx: &mut PluginContext) {
        self.sandbox.begin_call();
        self.inner.unload(ctx);
        self.sandbox.end_call();
    }

    /// Expose the sandbox for inspection.
    #[must_use]
    pub const fn sandbox(&self) -> &PluginSandbox {
        &self.sandbox
    }
    pub const fn sandbox_mut(&mut self) -> &mut PluginSandbox {
        &mut self.sandbox
    }

    /// Expose the inner plugin name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Check network access on behalf of plugin code.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::PermissionDenied`] when the underlying sandbox denies the operation.
    pub fn check_network(&self, dest: Option<&str>) -> PluginResult<()> {
        self.sandbox
            .check_network(dest)
            .map_err(|v| PluginError::PermissionDenied(v.to_string()))
    }

    /// Check filesystem access on behalf of plugin code.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::PermissionDenied`] when the underlying sandbox denies the operation.
    pub fn check_filesystem(&self, path: &str, write: bool) -> PluginResult<()> {
        self.sandbox
            .check_filesystem(path, write)
            .map_err(|v| PluginError::PermissionDenied(v.to_string()))
    }

    /// Track a memory allocation on behalf of plugin code.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::PermissionDenied`] when the underlying sandbox denies the allocation.
    pub fn track_alloc(&self, bytes: usize) -> PluginResult<()> {
        self.sandbox
            .track_alloc(bytes)
            .map_err(|v| PluginError::PermissionDenied(v.to_string()))
    }
}

// ─── Sandbox Monitor ─────────────────────────────────────────────────────────

/// Aggregates live stats for all sandboxed plugins in a session.
#[derive(Debug, Default)]
pub struct SandboxMonitor {
    entries: HashMap<String, Arc<Mutex<ResourceTracker>>>,
}

impl SandboxMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tracker under a plugin name.
    pub fn register(&mut self, name: String, tracker: Arc<Mutex<ResourceTracker>>) {
        self.entries.insert(name, tracker);
    }

    /// Unregister a plugin.
    pub fn unregister(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// Retrieve a snapshot for a named plugin.
    ///
    /// # Panics
    ///
    /// Panics if the tracker mutex for the named plugin is poisoned.
    #[must_use]
    pub fn snapshot(&self, name: &str) -> Option<ResourceTracker> {
        self.entries.get(name).map(|t| t.lock().unwrap().clone())
    }

    /// Return all plugin names with active trackers.
    #[must_use]
    pub fn plugin_names(&self) -> Vec<&str> {
        self.entries
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Return total memory in use across all sandboxed plugins.
    ///
    /// # Panics
    ///
    /// Panics if any registered tracker mutex is poisoned.
    #[must_use]
    pub fn total_memory_bytes(&self) -> usize {
        self.entries
            .values()
            .map(|t| t.lock().unwrap().current_memory_bytes)
            .sum()
    }

    /// Return total violation count across all sandboxed plugins.
    ///
    /// # Panics
    ///
    /// Panics if any registered tracker mutex is poisoned.
    #[must_use]
    pub fn total_violations(&self) -> u64 {
        self.entries
            .values()
            .map(|t| t.lock().unwrap().violation_count)
            .sum()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CapabilitySet ────────────────────────────────────────────────────

    #[test]
    fn test_capability_has() {
        let mut caps = CapabilitySet::NONE;
        assert!(!caps.has(CapabilitySet::NETWORK));
        caps.grant(CapabilitySet::NETWORK);
        assert!(caps.has(CapabilitySet::NETWORK));
    }

    #[test]
    fn test_capability_revoke() {
        let mut caps = CapabilitySet::ALL;
        caps.revoke(CapabilitySet::NETWORK);
        assert!(!caps.has(CapabilitySet::NETWORK));
        assert!(caps.has(CapabilitySet::READ_FS));
    }

    #[test]
    fn test_capability_union() {
        let a = CapabilitySet::READ_FS;
        let b = CapabilitySet::NETWORK;
        let c = a.union(b);
        assert!(c.has(CapabilitySet::READ_FS));
        assert!(c.has(CapabilitySet::NETWORK));
    }

    #[test]
    fn test_capability_intersect() {
        let a = CapabilitySet(CapabilitySet::READ_FS.0 | CapabilitySet::NETWORK.0);
        let b = CapabilitySet(CapabilitySet::READ_FS.0 | CapabilitySet::WRITE_FS.0);
        let c = a.intersect(b);
        assert!(c.has(CapabilitySet::READ_FS));
        assert!(!c.has(CapabilitySet::NETWORK));
        assert!(!c.has(CapabilitySet::WRITE_FS));
    }

    #[test]
    fn test_capability_describe() {
        let caps = CapabilitySet(CapabilitySet::NETWORK.0 | CapabilitySet::UI.0);
        let desc = caps.describe();
        assert!(desc.contains(&"network"));
        assert!(desc.contains(&"ui"));
        assert!(!desc.contains(&"read_fs"));
    }

    #[test]
    fn test_capability_analysis_standard() {
        let caps = CapabilitySet::analysis_standard();
        assert!(caps.has(CapabilitySet::READ_MEMORY));
        assert!(caps.has(CapabilitySet::READ_FS));
        assert!(!caps.has(CapabilitySet::NETWORK));
    }

    // ── ResourceLimits ───────────────────────────────────────────────────

    #[test]
    fn test_limits_default() {
        let l = ResourceLimits::default();
        assert_eq!(l.max_memory_bytes, 64 * 1024 * 1024);
        assert!(!l.network_allowed);
        assert_eq!(l.max_file_handles, 64);
    }

    #[test]
    fn test_limits_trusted() {
        let l = ResourceLimits::trusted();
        assert!(l.network_allowed);
        assert!(l.threads_allowed);
        assert!(l.max_memory_bytes > 100 * 1024 * 1024);
    }

    #[test]
    fn test_limits_strict() {
        let l = ResourceLimits::strict();
        assert!(!l.network_allowed);
        assert!(l.max_cpu_ms <= 1000);
    }

    #[test]
    fn test_path_readable_unrestricted() {
        let l = ResourceLimits::default();
        assert!(l.is_path_readable("/any/path"));
    }

    #[test]
    fn test_path_readable_restricted() {
        let mut l = ResourceLimits::default();
        l.allowed_read_paths.push("/safe/".to_string());
        assert!(l.is_path_readable("/safe/file.bin"));
        assert!(!l.is_path_readable("/unsafe/file.bin"));
    }

    #[test]
    fn test_path_writable_none_by_default() {
        let l = ResourceLimits::default();
        assert!(!l.is_path_writable("/any/path"));
    }

    #[test]
    fn test_path_writable_allowed() {
        let mut l = ResourceLimits::default();
        l.allowed_write_paths.push("/tmp/plugin_out/".to_string());
        assert!(l.is_path_writable("/tmp/plugin_out/result.txt"));
        assert!(!l.is_path_writable("/etc/shadow"));
    }

    // ── ResourceTracker ──────────────────────────────────────────────────

    #[test]
    fn test_tracker_alloc_dealloc() {
        let mut t = ResourceTracker::new();
        t.record_alloc(1024);
        assert_eq!(t.current_memory_bytes, 1024);
        assert_eq!(t.peak_memory_bytes, 1024);
        t.record_dealloc(512);
        assert_eq!(t.current_memory_bytes, 512);
        assert_eq!(t.peak_memory_bytes, 1024); // peak unchanged
    }

    #[test]
    fn test_tracker_alloc_count() {
        let mut t = ResourceTracker::new();
        t.record_alloc(100);
        t.record_alloc(200);
        assert_eq!(t.allocation_count, 2);
        assert_eq!(t.total_allocated_bytes, 300);
    }

    #[test]
    fn test_tracker_handles() {
        let mut t = ResourceTracker::new();
        t.open_handle();
        t.open_handle();
        assert_eq!(t.open_file_handles, 2);
        t.close_handle();
        assert_eq!(t.open_file_handles, 1);
    }

    #[test]
    fn test_tracker_cpu() {
        let mut t = ResourceTracker::new();
        t.add_cpu_ms(1000);
        t.add_cpu_ms(500);
        assert_eq!(t.cpu_time_ms, 1500);
    }

    #[test]
    fn test_tracker_check_memory_ok() {
        let mut t = ResourceTracker::new();
        t.record_alloc(1024);
        let l = ResourceLimits::default();
        assert!(t.check_memory(&l).is_ok());
    }

    #[test]
    fn test_tracker_check_memory_exceeded() {
        let mut t = ResourceTracker::new();
        t.record_alloc(200 * 1024 * 1024); // 200 MiB
        let l = ResourceLimits::default(); // 64 MiB limit
        assert!(t.check_memory(&l).is_err());
        match t.check_memory(&l).unwrap_err() {
            SandboxViolation::MemoryExceeded {
                used_bytes,
                limit_bytes,
            } => {
                assert!(used_bytes > limit_bytes);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_tracker_check_cpu_exceeded() {
        let mut t = ResourceTracker::new();
        t.add_cpu_ms(10_000); // 10 s
        let l = ResourceLimits::default(); // 5 s limit
        assert!(t.check_cpu(&l).is_err());
    }

    #[test]
    fn test_tracker_check_handles_exceeded() {
        let mut t = ResourceTracker::new();
        for _ in 0..64 {
            t.open_handle();
        }
        let l = ResourceLimits::default(); // max 64
        assert!(t.check_handles(&l).is_err());
    }

    // ── SandboxPolicy ────────────────────────────────────────────────────

    #[test]
    fn test_policy_strict_limits() {
        let policy = SandboxPolicy::Strict;
        let limits = policy.limits();
        assert!(!limits.network_allowed);
        assert!(limits.max_cpu_ms <= 1000);
    }

    #[test]
    fn test_policy_trusted_limits() {
        let policy = SandboxPolicy::Trusted;
        let limits = policy.limits();
        assert!(limits.network_allowed);
        assert!(limits.threads_allowed);
    }

    #[test]
    fn test_policy_standard_capabilities() {
        let policy = SandboxPolicy::Standard;
        let caps = policy.capabilities();
        assert!(caps.has(CapabilitySet::READ_FS));
        assert!(!caps.has(CapabilitySet::NETWORK));
    }

    // ── PluginSandbox ────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_check_capability_ok() {
        let sandbox = PluginSandbox::trusted();
        assert!(sandbox.check_capability(CapabilitySet::NETWORK).is_ok());
    }

    #[test]
    fn test_sandbox_check_capability_denied() {
        let sandbox = PluginSandbox::strict();
        // strict policy does not grant NETWORK
        assert!(sandbox.check_capability(CapabilitySet::NETWORK).is_err());
    }

    #[test]
    fn test_sandbox_check_network_denied() {
        let sandbox = PluginSandbox::strict();
        let result = sandbox.check_network(Some("8.8.8.8:53"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::NetworkDenied { destination } => {
                assert_eq!(destination, Some("8.8.8.8:53".to_string()));
            }
            _ => panic!("wrong violation"),
        }
    }

    #[test]
    fn test_sandbox_check_network_allowed() {
        let sandbox = PluginSandbox::trusted();
        assert!(sandbox.check_network(None).is_ok());
    }

    #[test]
    fn test_sandbox_filesystem_denied() {
        let sandbox = PluginSandbox::strict();
        // strict: allowed_read_paths is empty → all read is allowed
        // but write is denied (no allowed_write_paths)
        let result = sandbox.check_filesystem("/etc/passwd", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_track_alloc_exceeds() {
        let sandbox = PluginSandbox::strict(); // 8 MiB limit
        let result = sandbox.track_alloc(16 * 1024 * 1024);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::MemoryExceeded { .. } => {}
            _ => panic!("wrong violation"),
        }
    }

    #[test]
    fn test_sandbox_track_alloc_ok() {
        let sandbox = PluginSandbox::trusted();
        assert!(sandbox.track_alloc(1024).is_ok());
    }

    #[test]
    fn test_sandbox_open_handles_exceed() {
        let sandbox = PluginSandbox::strict(); // max 8 handles
        for _ in 0..8 {
            let _ = sandbox.open_file_handle();
        }
        // 9th should fail
        let result = sandbox.open_file_handle();
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_record_violation() {
        let sandbox = PluginSandbox::strict();
        assert!(!sandbox.has_violations());
        sandbox.record_violation(SandboxViolation::ThreadSpawnDenied);
        assert!(sandbox.has_violations());
        assert_eq!(sandbox.violations().len(), 1);
    }

    #[test]
    fn test_sandbox_snapshot() {
        let sandbox = PluginSandbox::standard();
        let _ = sandbox.track_alloc(1024);
        let snap = sandbox.snapshot();
        assert_eq!(snap.total_allocated_bytes, 1024);
    }

    // ── SandboxMonitor ───────────────────────────────────────────────────

    #[test]
    fn test_monitor_register_unregister() {
        let mut monitor = SandboxMonitor::new();
        let tracker = Arc::new(Mutex::new(ResourceTracker::new()));
        monitor.register("plugin_a".to_string(), tracker);
        assert!(monitor.plugin_names().contains(&"plugin_a"));
        monitor.unregister("plugin_a");
        assert!(monitor.snapshot("plugin_a").is_none());
    }

    #[test]
    fn test_monitor_total_memory() {
        let mut monitor = SandboxMonitor::new();
        let t1 = Arc::new(Mutex::new(ResourceTracker::new()));
        let t2 = Arc::new(Mutex::new(ResourceTracker::new()));
        t1.lock().unwrap().record_alloc(1000);
        t2.lock().unwrap().record_alloc(2000);
        monitor.register("a".to_string(), t1);
        monitor.register("b".to_string(), t2);
        assert_eq!(monitor.total_memory_bytes(), 3000);
    }

    #[test]
    fn test_monitor_total_violations() {
        let mut monitor = SandboxMonitor::new();
        let t = Arc::new(Mutex::new(ResourceTracker::new()));
        t.lock().unwrap().record_violation();
        t.lock().unwrap().record_violation();
        monitor.register("p".to_string(), t);
        assert_eq!(monitor.total_violations(), 2);
    }

    // ── SandboxViolation Display ─────────────────────────────────────────

    #[test]
    fn test_violation_display_memory() {
        let v = SandboxViolation::MemoryExceeded {
            used_bytes: 200,
            limit_bytes: 100,
        };
        assert!(v.to_string().contains("200"));
        assert!(v.to_string().contains("100"));
    }

    #[test]
    fn test_violation_display_timeout() {
        let v = SandboxViolation::TimeoutExceeded {
            used_ms: 6000,
            limit_ms: 5000,
        };
        assert!(v.to_string().contains("6000"));
    }

    #[test]
    fn test_violation_display_network() {
        let v = SandboxViolation::NetworkDenied {
            destination: Some("example.com".to_string()),
        };
        assert!(v.to_string().contains("example.com"));
    }

    #[test]
    fn test_violation_display_fs() {
        let v = SandboxViolation::FilesystemDenied {
            path: "/etc/shadow".to_string(),
            write: true,
        };
        assert!(v.to_string().contains("write"));
        assert!(v.to_string().contains("/etc/shadow"));
    }
}
