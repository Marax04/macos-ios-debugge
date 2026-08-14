//! `plugin_sandbox_full` — Comprehensive plugin sandbox with resource monitoring,
//! API filtering, permission checks, and reporting.
//!
//! # Key types
//! * [`PluginSandbox`]    — entry-point facade; enforces policy and tracks state.
//! * [`SandboxPolicy`]    — declarative set of rules (allow / deny / quota).
//! * [`ResourceMonitor`]  — tracks CPU time, memory, file handles, and network calls.
//! * [`ApiFilter`]        — intercepts API calls and checks them against policy.
//! * [`PermissionCheck`]  — encodes a single permission-check request and result.
//! * [`SandboxReport`]    — summary of a sandbox run.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SandboxError {
    #[error("permission denied: {0}")]
    Denied(String),
    #[error("quota exceeded: {resource} limit={limit} current={current}")]
    QuotaExceeded {
        resource: String,
        limit: u64,
        current: u64,
    },
    #[error("sandbox is not running (call start() first)")]
    NotRunning,
    #[error("sandbox already running")]
    AlreadyRunning,
    #[error("API call blocked: {0}")]
    ApiBlocked(String),
    #[error("resource monitor error: {0}")]
    Monitor(String),
    #[error("policy conflict: {0}")]
    PolicyConflict(String),
}

pub type SandboxResult<T> = Result<T, SandboxError>;

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// A fine-grained permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ReadBinaryView,
    WriteBinaryView,
    FileSystemRead(PathBuf),
    FileSystemWrite(PathBuf),
    FileSystemReadWrite(PathBuf),
    Network,
    Subprocess,
    Ui,
    LoadLibrary,
    AccessRegistryRead,
    AccessRegistryWrite,
    IpcSend,
    IpcReceive,
    Clipboard,
    ScreenCapture,
    SystemInfo,
    Custom(String),
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadBinaryView => write!(f, "read_binary_view"),
            Self::WriteBinaryView => write!(f, "write_binary_view"),
            Self::FileSystemRead(p) => write!(f, "fs_read:{}", p.display()),
            Self::FileSystemWrite(p) => write!(f, "fs_write:{}", p.display()),
            Self::FileSystemReadWrite(p) => write!(f, "fs_rw:{}", p.display()),
            Self::Network => write!(f, "network"),
            Self::Subprocess => write!(f, "subprocess"),
            Self::Ui => write!(f, "ui"),
            Self::LoadLibrary => write!(f, "load_library"),
            Self::AccessRegistryRead => write!(f, "registry_read"),
            Self::AccessRegistryWrite => write!(f, "registry_write"),
            Self::IpcSend => write!(f, "ipc_send"),
            Self::IpcReceive => write!(f, "ipc_receive"),
            Self::Clipboard => write!(f, "clipboard"),
            Self::ScreenCapture => write!(f, "screen_capture"),
            Self::SystemInfo => write!(f, "system_info"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SandboxPolicy
// ---------------------------------------------------------------------------

/// Resource quotas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuotas {
    /// Maximum CPU milliseconds per run.
    pub max_cpu_ms: u64,
    /// Maximum resident memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum number of open file handles.
    pub max_file_handles: u32,
    /// Maximum network calls per run.
    pub max_network_calls: u32,
    /// Maximum number of API calls.
    pub max_api_calls: u64,
    /// Maximum number of subprocesses spawned.
    pub max_subprocesses: u32,
}

impl Default for ResourceQuotas {
    fn default() -> Self {
        Self {
            max_cpu_ms: 5_000,
            max_memory_bytes: 256 * 1024 * 1024, // 256 MiB
            max_file_handles: 64,
            max_network_calls: 100,
            max_api_calls: 1_000_000,
            max_subprocesses: 0,
        }
    }
}

/// Action to take on a sandbox violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ViolationAction {
    Warn,
    #[default]
    Deny,
    Kill,
}

impl fmt::Display for ViolationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warn => write!(f, "warn"),
            Self::Deny => write!(f, "deny"),
            Self::Kill => write!(f, "kill"),
        }
    }
}

/// Declarative set of sandbox rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub allowed: HashSet<Permission>,
    pub denied: HashSet<Permission>,
    pub quotas: ResourceQuotas,
    pub on_violation: ViolationAction,
    /// API prefixes that are blocked (e.g. "`fs::`", "`net::`").
    pub blocked_api_prefixes: Vec<String>,
    /// Whether unknown permissions default to deny.
    pub deny_unknown: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allowed: HashSet::new(),
            denied: HashSet::new(),
            quotas: ResourceQuotas::default(),
            on_violation: ViolationAction::Deny,
            blocked_api_prefixes: Vec::new(),
            deny_unknown: true,
        }
    }
}

impl SandboxPolicy {
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            deny_unknown: false,
            ..Self::default()
        }
    }

    pub fn allow(&mut self, perm: Permission) {
        self.denied.remove(&perm);
        self.allowed.insert(perm);
    }

    pub fn deny(&mut self, perm: Permission) {
        self.allowed.remove(&perm);
        self.denied.insert(perm);
    }

    pub fn block_api_prefix(&mut self, prefix: impl Into<String>) {
        self.blocked_api_prefixes.push(prefix.into());
    }

    /// Check if `perm` is allowed under this policy.
    #[must_use]
    pub fn check(&self, perm: &Permission) -> bool {
        if self.denied.contains(perm) {
            return false;
        }
        if self.allowed.contains(perm) {
            return true;
        }
        !self.deny_unknown
    }

    /// Check whether a filesystem read against `path` is allowed by any
    /// granted `FileSystemRead` / `FileSystemReadWrite` permission.
    #[must_use]
    pub fn allows_fs_read(&self, path: &Path) -> bool {
        self.allowed.iter().any(|p| match p {
            Permission::FileSystemRead(root) | Permission::FileSystemReadWrite(root) => {
                path.starts_with(root)
            }
            _ => false,
        })
    }

    /// Aggregate granted permissions by their string category for reporting.
    #[must_use]
    pub fn allowed_by_category(&self) -> HashMap<String, usize> {
        let mut out: HashMap<String, usize> = HashMap::new();
        for p in &self.allowed {
            let key = format!("{p}");
            let category = key.split(':').next().unwrap_or(&key).to_string();
            *out.entry(category).or_insert(0) += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ResourceMonitor
// ---------------------------------------------------------------------------

/// Snapshot of resource usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub file_handles: u32,
    pub network_calls: u32,
    pub api_calls: u64,
    pub subprocesses: u32,
}

/// Tracks resource usage during a sandbox run.
#[derive(Debug)]
pub struct ResourceMonitor {
    pub quotas: ResourceQuotas,
    pub current: ResourceSnapshot,
    start_time: Option<Instant>,
    violations: Vec<String>,
}

impl ResourceMonitor {
    #[must_use]
    pub fn new(quotas: ResourceQuotas) -> Self {
        Self {
            quotas,
            current: ResourceSnapshot::default(),
            start_time: None,
            violations: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.current = ResourceSnapshot::default();
    }

    pub fn stop(&mut self) {
        if let Some(t) = self.start_time.take() {
            self.current.cpu_ms += t.elapsed().as_millis() as u64;
        }
    }

    /// Record api call.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn record_api_call(&mut self) -> SandboxResult<()> {
        self.current.api_calls += 1;
        if self.current.api_calls > self.quotas.max_api_calls {
            return Err(SandboxError::QuotaExceeded {
                resource: "api_calls".into(),
                limit: self.quotas.max_api_calls,
                current: self.current.api_calls,
            });
        }
        Ok(())
    }

    /// Record network call.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Record a network call.
    pub fn record_network_call(&mut self) -> SandboxResult<()> {
        self.current.network_calls += 1;
        if u64::from(self.current.network_calls) > u64::from(self.quotas.max_network_calls) {
            return Err(SandboxError::QuotaExceeded {
                resource: "network_calls".into(),
                limit: u64::from(self.quotas.max_network_calls),
                current: u64::from(self.current.network_calls),
            });
        }
        Ok(())
    }

    /// Record file open.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Record a file handle open.
    pub fn record_file_open(&mut self) -> SandboxResult<()> {
        self.current.file_handles += 1;
        if self.current.file_handles > self.quotas.max_file_handles {
            return Err(SandboxError::QuotaExceeded {
                resource: "file_handles".into(),
                limit: u64::from(self.quotas.max_file_handles),
                current: u64::from(self.current.file_handles),
            });
        }
        Ok(())
    }

    /// Record a file handle close.
    pub const fn record_file_close(&mut self) {
        self.current.file_handles = self.current.file_handles.saturating_sub(1);
    }

    /// Set memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn set_memory(&mut self, bytes: u64) -> SandboxResult<()> {
        self.current.memory_bytes = bytes;
        if bytes > self.quotas.max_memory_bytes {
            return Err(SandboxError::QuotaExceeded {
                resource: "memory_bytes".into(),
                limit: self.quotas.max_memory_bytes,
                current: bytes,
            });
        }
        Ok(())
    }

    /// Check cpu.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Check if CPU quota has been exceeded.
    pub fn check_cpu(&mut self) -> SandboxResult<()> {
        if let Some(t) = &self.start_time {
            let elapsed = t.elapsed().as_millis() as u64;
            if elapsed > self.quotas.max_cpu_ms {
                return Err(SandboxError::QuotaExceeded {
                    resource: "cpu_ms".into(),
                    limit: self.quotas.max_cpu_ms,
                    current: elapsed,
                });
            }
        }
        Ok(())
    }

    /// Snapshot the current usage.
    #[must_use]
    pub fn snapshot(&self) -> ResourceSnapshot {
        self.current.clone()
    }

    #[must_use]
    pub fn violations(&self) -> &[String] {
        &self.violations
    }

    pub fn record_violation(&mut self, v: impl Into<String>) {
        self.violations.push(v.into());
    }

    /// Wall-clock time elapsed since `start()` was called, or zero if not started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.map_or(Duration::ZERO, |t| t.elapsed())
    }
}

// ---------------------------------------------------------------------------
// ApiFilter
// ---------------------------------------------------------------------------

/// A single API call interception record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    pub api: String,
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Intercepts plugin API calls and checks them against policy.
#[derive(Debug, Clone, Default)]
pub struct ApiFilter {
    pub blocked_prefixes: Vec<String>,
    pub blocked_exact: HashSet<String>,
    pub allowed_exact: HashSet<String>,
    pub call_log: VecDeque<ApiCallRecord>,
    pub max_log: usize,
}

impl ApiFilter {
    #[must_use]
    pub fn new(max_log: usize) -> Self {
        Self {
            max_log,
            call_log: VecDeque::new(),
            ..Default::default()
        }
    }

    pub fn block_prefix(&mut self, prefix: impl Into<String>) {
        self.blocked_prefixes.push(prefix.into());
    }

    pub fn block_exact(&mut self, api: impl Into<String>) {
        self.blocked_exact.insert(api.into());
    }

    pub fn allow_exact(&mut self, api: impl Into<String>) {
        self.allowed_exact.insert(api.into());
    }

    /// Check.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Check if `api` is permitted.  Returns `Ok(())` or `Err(ApiBlocked)`.
    pub fn check(&mut self, api: &str) -> SandboxResult<()> {
        // Explicit allow wins.
        if self.allowed_exact.contains(api) {
            self.record(api, true, None);
            return Ok(());
        }
        // Explicit exact block.
        if self.blocked_exact.contains(api) {
            self.record(api, false, Some("exact_block"));
            return Err(SandboxError::ApiBlocked(api.into()));
        }
        // Prefix block.
        for prefix in &self.blocked_prefixes {
            if api.starts_with(prefix.as_str()) {
                self.record(api, false, Some("prefix_block"));
                return Err(SandboxError::ApiBlocked(api.into()));
            }
        }
        self.record(api, true, None);
        Ok(())
    }

    fn record(&mut self, api: &str, allowed: bool, reason: Option<&str>) {
        if self.call_log.len() >= self.max_log && self.max_log > 0 {
            self.call_log.pop_front();
        }
        self.call_log.push_back(ApiCallRecord {
            api: api.into(),
            allowed,
            reason: reason.map(std::convert::Into::into),
        });
    }

    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.call_log.iter().filter(|r| !r.allowed).count()
    }

    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.call_log.iter().filter(|r| r.allowed).count()
    }
}

// ---------------------------------------------------------------------------
// PermissionCheck
// ---------------------------------------------------------------------------

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckResult {
    Allowed,
    Denied(String),
    QuotaExceeded(String),
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied(r) => write!(f, "denied: {r}"),
            Self::QuotaExceeded(r) => write!(f, "quota_exceeded: {r}"),
        }
    }
}

/// A single permission-check request and its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub plugin_id: String,
    pub permission: Permission,
    pub result: CheckResult,
    /// Sequence number.
    pub seq: u64,
}

impl fmt::Display for PermissionCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {}: {} → {}",
            self.seq, self.plugin_id, self.permission, self.result
        )
    }
}

// ---------------------------------------------------------------------------
// SandboxReport
// ---------------------------------------------------------------------------

/// Summary of a full sandbox run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxReport {
    pub plugin_id: String,
    pub resource_snapshot: ResourceSnapshot,
    pub permission_checks: Vec<PermissionCheck>,
    pub api_blocks: Vec<String>,
    pub violations: Vec<String>,
    pub healthy: bool,
    pub terminated: bool,
    pub error: Option<String>,
}

impl SandboxReport {
    #[must_use]
    pub fn denied_count(&self) -> usize {
        self.permission_checks
            .iter()
            .filter(|c| matches!(c.result, CheckResult::Denied(_)))
            .count()
    }
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.permission_checks
            .iter()
            .filter(|c| c.result == CheckResult::Allowed)
            .count()
    }
}

impl fmt::Display for SandboxReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SandboxReport[{}]: healthy={} terminated={} {} checks ({} denied) {} api_blocks",
            self.plugin_id,
            self.healthy,
            self.terminated,
            self.permission_checks.len(),
            self.denied_count(),
            self.api_blocks.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PluginSandbox
// ---------------------------------------------------------------------------

/// Main sandbox facade.
pub struct PluginSandbox {
    pub plugin_id: String,
    pub policy: SandboxPolicy,
    /// Operation that may fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub monitor: ResourceMonitor,
    pub api_filter: ApiFilter,
    check_seq: u64,
    check_log: Vec<PermissionCheck>,
    running: bool,
    healthy: bool,
}

impl PluginSandbox {
    pub fn new(plugin_id: impl Into<String>, policy: SandboxPolicy) -> Self {
        let quotas = policy.quotas.clone();
        Self {
            plugin_id: plugin_id.into(),
            policy,
            monitor: ResourceMonitor::new(quotas),
            api_filter: ApiFilter::new(4096),
            check_seq: 0,
            check_log: Vec::new(),
            running: false,
            healthy: true,
        }
    }

    /// Start.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Start the sandbox.
    pub fn start(&mut self) -> SandboxResult<()> {
        if self.running {
            return Err(SandboxError::AlreadyRunning);
        }
        self.running = true;
        self.healthy = true;
        self.monitor.start();
        Ok(())
    }

    /// Stop the sandbox.
    pub fn stop(&mut self) {
        self.running = false;
        self.monitor.stop();
    }

    /// Operation that may fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    pub fn check_permission(&mut self, perm: &Permission) -> SandboxResult<()> {
        let seq = self.check_seq;
        self.check_seq += 1;
        let allowed = self.policy.check(perm);
        let result = if allowed {
            CheckResult::Allowed
        } else {
            let reason = format!("{perm}");
            CheckResult::Denied(reason)
        };
        self.check_log.push(PermissionCheck {
            plugin_id: self.plugin_id.clone(),
            permission: perm.clone(),
            result,
            seq,
        });
        if !allowed {
            self.healthy = self.policy.on_violation != ViolationAction::Kill;
            if self.policy.on_violation == ViolationAction::Kill {
                self.running = false;
            }
            return Err(SandboxError::Denied(format!("{perm}")));
        }
        Ok(())
    }

    /// Check api.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Intercept an API call.
    pub fn check_api(&mut self, api: &str) -> SandboxResult<()> {
        self.api_filter.check(api)
    }

    /// Network call.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Record a network call (permission + quota).
    pub fn network_call(&mut self) -> SandboxResult<()> {
        self.check_permission(&Permission::Network)?;
        self.monitor.record_network_call()
    }

    /// Returns true if the sandbox is healthy (no kill-violations).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// Returns true if the sandbox is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Produce a full report.
    #[must_use]
    pub fn report(&self) -> SandboxReport {
        SandboxReport {
            plugin_id: self.plugin_id.clone(),
            resource_snapshot: self.monitor.snapshot(),
            permission_checks: self.check_log.clone(),
            api_blocks: self
                .api_filter
                .call_log
                .iter()
                .filter(|r| !r.allowed)
                .map(|r| r.api.clone())
                .collect(),
            violations: self.monitor.violations().to_vec(),
            healthy: self.healthy,
            terminated: !self.running,
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_sandbox(id: &str) -> PluginSandbox {
        PluginSandbox::new(id, SandboxPolicy::default())
    }

    // --- SandboxPolicy ---

    #[test]
    fn policy_allow_then_check() {
        let mut p = SandboxPolicy::default();
        p.allow(Permission::ReadBinaryView);
        assert!(p.check(&Permission::ReadBinaryView));
    }

    #[test]
    fn policy_deny_takes_precedence() {
        let mut p = SandboxPolicy::default();
        p.allow(Permission::Network);
        p.deny(Permission::Network);
        assert!(!p.check(&Permission::Network));
    }

    #[test]
    fn policy_deny_unknown_default() {
        let p = SandboxPolicy::default();
        assert!(!p.check(&Permission::Network)); // default = deny unknown
    }

    #[test]
    fn policy_permissive_allows_unknown() {
        let p = SandboxPolicy::permissive();
        assert!(p.check(&Permission::Network));
    }

    #[test]
    fn policy_violation_action_display() {
        assert_eq!(format!("{}", ViolationAction::Deny), "deny");
        assert_eq!(format!("{}", ViolationAction::Warn), "warn");
        assert_eq!(format!("{}", ViolationAction::Kill), "kill");
    }

    // --- ResourceMonitor ---

    #[test]
    fn monitor_api_call_quota() {
        let q = ResourceQuotas {
            max_api_calls: 2,
            ..ResourceQuotas::default()
        };
        let mut mon = ResourceMonitor::new(q);
        mon.record_api_call().unwrap();
        mon.record_api_call().unwrap();
        assert!(matches!(
            mon.record_api_call(),
            Err(SandboxError::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn monitor_network_call_quota() {
        let q = ResourceQuotas {
            max_network_calls: 1,
            ..ResourceQuotas::default()
        };
        let mut mon = ResourceMonitor::new(q);
        mon.record_network_call().unwrap();
        assert!(mon.record_network_call().is_err());
    }

    #[test]
    fn monitor_file_open_close() {
        let mut mon = ResourceMonitor::new(ResourceQuotas::default());
        mon.record_file_open().unwrap();
        assert_eq!(mon.current.file_handles, 1);
        mon.record_file_close();
        assert_eq!(mon.current.file_handles, 0);
    }

    #[test]
    fn monitor_memory_quota() {
        let q = ResourceQuotas {
            max_memory_bytes: 1024,
            ..ResourceQuotas::default()
        };
        let mut mon = ResourceMonitor::new(q);
        assert!(mon.set_memory(2048).is_err());
    }

    #[test]
    fn monitor_snapshot() {
        let mut mon = ResourceMonitor::new(ResourceQuotas::default());
        mon.current.api_calls = 5;
        let snap = mon.snapshot();
        assert_eq!(snap.api_calls, 5);
    }

    #[test]
    fn monitor_start_stop() {
        let mut mon = ResourceMonitor::new(ResourceQuotas::default());
        mon.start();
        mon.stop();
        // Should not panic.
    }

    // --- ApiFilter ---

    #[test]
    fn api_filter_allows_by_default() {
        let mut f = ApiFilter::new(100);
        assert!(f.check("fs::open").is_ok());
    }

    #[test]
    fn api_filter_block_prefix() {
        let mut f = ApiFilter::new(100);
        f.block_prefix("net::");
        assert!(f.check("net::connect").is_err());
        assert!(f.check("fs::open").is_ok());
    }

    #[test]
    fn api_filter_block_exact() {
        let mut f = ApiFilter::new(100);
        f.block_exact("dangerous_fn");
        assert!(f.check("dangerous_fn").is_err());
        assert!(f.check("safe_fn").is_ok());
    }

    #[test]
    fn api_filter_allow_exact_overrides_prefix() {
        let mut f = ApiFilter::new(100);
        f.block_prefix("net::");
        f.allow_exact("net::allowed");
        assert!(f.check("net::allowed").is_ok());
        assert!(f.check("net::other").is_err());
    }

    #[test]
    fn api_filter_counts() {
        let mut f = ApiFilter::new(100);
        f.block_exact("bad");
        f.check("good").unwrap();
        f.check("bad").unwrap_err();
        assert_eq!(f.allowed_count(), 1);
        assert_eq!(f.blocked_count(), 1);
    }

    // --- PermissionCheck ---

    #[test]
    fn permission_check_display() {
        let pc = PermissionCheck {
            plugin_id: "p1".into(),
            permission: Permission::Network,
            result: CheckResult::Denied("network".into()),
            seq: 0,
        };
        let s = format!("{pc}");
        assert!(s.contains("denied"));
        assert!(s.contains("network"));
    }

    #[test]
    fn check_result_display() {
        assert_eq!(format!("{}", CheckResult::Allowed), "allowed");
        assert!(format!("{}", CheckResult::Denied("r".into())).contains("denied"));
        assert!(format!("{}", CheckResult::QuotaExceeded("r".into())).contains("quota_exceeded"));
    }

    // --- SandboxReport ---

    #[test]
    fn sandbox_report_counts() {
        let report = SandboxReport {
            plugin_id: "p1".into(),
            permission_checks: vec![
                PermissionCheck {
                    plugin_id: "p1".into(),
                    permission: Permission::Network,
                    result: CheckResult::Allowed,
                    seq: 0,
                },
                PermissionCheck {
                    plugin_id: "p1".into(),
                    permission: Permission::Subprocess,
                    result: CheckResult::Denied("sub".into()),
                    seq: 1,
                },
            ],
            ..Default::default()
        };
        assert_eq!(report.allowed_count(), 1);
        assert_eq!(report.denied_count(), 1);
    }

    #[test]
    fn sandbox_report_display() {
        let r = SandboxReport {
            plugin_id: "p1".into(),
            healthy: true,
            ..Default::default()
        };
        assert!(format!("{r}").contains("p1"));
    }

    // --- PluginSandbox ---

    #[test]
    fn sandbox_start_stop() {
        let mut sb = default_sandbox("p1");
        sb.start().unwrap();
        assert!(sb.is_running());
        sb.stop();
        assert!(!sb.is_running());
    }

    #[test]
    fn sandbox_double_start_error() {
        let mut sb = default_sandbox("p1");
        sb.start().unwrap();
        assert!(matches!(sb.start(), Err(SandboxError::AlreadyRunning)));
    }

    #[test]
    fn sandbox_check_permission_denied() {
        let mut sb = default_sandbox("p1");
        let r = sb.check_permission(&Permission::Network);
        assert!(r.is_err());
        assert!(!sb.check_log.is_empty());
    }

    #[test]
    fn sandbox_check_permission_allowed() {
        let mut policy = SandboxPolicy::default();
        policy.allow(Permission::ReadBinaryView);
        let mut sb = PluginSandbox::new("p1", policy);
        assert!(sb.check_permission(&Permission::ReadBinaryView).is_ok());
    }

    #[test]
    fn sandbox_kill_on_violation_stops() {
        let policy = SandboxPolicy {
            on_violation: ViolationAction::Kill,
            ..SandboxPolicy::default()
        };
        let mut sb = PluginSandbox::new("p1", policy);
        sb.start().unwrap();
        let _ = sb.check_permission(&Permission::Network);
        assert!(!sb.is_healthy());
    }

    #[test]
    fn sandbox_api_check_blocked() {
        let mut sb = default_sandbox("p1");
        sb.api_filter.block_exact("bad_api");
        assert!(sb.check_api("bad_api").is_err());
    }

    #[test]
    fn sandbox_network_call_no_perm() {
        let mut sb = default_sandbox("p1");
        assert!(sb.network_call().is_err());
    }

    #[test]
    fn sandbox_report_generation() {
        let mut sb = default_sandbox("p1");
        let _ = sb.check_permission(&Permission::Network); // denied
        let report = sb.report();
        assert_eq!(report.denied_count(), 1);
    }

    #[test]
    fn sandbox_healthy_after_warn_violation() {
        let policy = SandboxPolicy {
            on_violation: ViolationAction::Warn,
            ..SandboxPolicy::default()
        };
        let mut sb = PluginSandbox::new("p1", policy);
        let _ = sb.check_permission(&Permission::Network);
        assert!(sb.is_healthy());
    }

    #[test]
    fn permission_display() {
        assert_eq!(format!("{}", Permission::Network), "network");
        assert_eq!(format!("{}", Permission::Custom("x".into())), "custom:x");
    }

    #[test]
    fn resource_quotas_default() {
        let q = ResourceQuotas::default();
        assert!(q.max_cpu_ms > 0);
        assert!(q.max_memory_bytes > 0);
    }

    #[test]
    fn sandbox_check_log_length_after_checks() {
        let mut sb = default_sandbox("p");
        for _ in 0..5 {
            let _ = sb.check_permission(&Permission::Network);
        }
        assert_eq!(sb.check_log.len(), 5);
    }

    #[test]
    fn sandbox_allow_multiple_permissions() {
        let mut policy = SandboxPolicy::default();
        policy.allow(Permission::ReadBinaryView);
        policy.allow(Permission::Clipboard);
        let mut sb = PluginSandbox::new("p", policy);
        assert!(sb.check_permission(&Permission::ReadBinaryView).is_ok());
        assert!(sb.check_permission(&Permission::Clipboard).is_ok());
        assert!(sb.check_permission(&Permission::Network).is_err());
    }

    #[test]
    fn api_filter_log_cap() {
        let mut f = ApiFilter::new(3);
        for i in 0..5 {
            f.check(&format!("api_{i}")).unwrap();
        }
        assert_eq!(f.call_log.len(), 3);
    }

    #[test]
    fn monitor_file_quota_exceeded() {
        let q = ResourceQuotas {
            max_file_handles: 2,
            ..ResourceQuotas::default()
        };
        let mut mon = ResourceMonitor::new(q);
        mon.record_file_open().unwrap();
        mon.record_file_open().unwrap();
        assert!(mon.record_file_open().is_err());
    }

    #[test]
    fn monitor_record_violation_appends() {
        let mut mon = ResourceMonitor::new(ResourceQuotas::default());
        mon.record_violation("test violation");
        assert_eq!(mon.violations().len(), 1);
    }

    #[test]
    fn sandbox_report_api_blocks_populated() {
        let mut sb = default_sandbox("p");
        sb.api_filter.block_exact("bad");
        let _ = sb.check_api("bad");
        let report = sb.report();
        assert!(report.api_blocks.contains(&"bad".to_string()));
    }

    #[test]
    fn policy_block_api_prefix_stored() {
        let mut policy = SandboxPolicy::default();
        policy.block_api_prefix("net::");
        assert!(policy.blocked_api_prefixes.contains(&"net::".to_string()));
    }

    #[test]
    fn permission_filesystem_paths() {
        use std::path::PathBuf;
        let p = Permission::FileSystemRead(PathBuf::from("/tmp/test"));
        let s = format!("{p}");
        assert!(s.contains("fs_read"));
    }

    #[test]
    fn sandbox_sequential_start_stop_start() {
        let mut sb = default_sandbox("p");
        sb.start().unwrap();
        sb.stop();
        assert!(!sb.is_running());
        sb.start().unwrap(); // should succeed again
        assert!(sb.is_running());
    }

    #[test]
    fn check_result_quota_display() {
        let r = CheckResult::QuotaExceeded("memory".into());
        assert!(format!("{r}").contains("memory"));
    }

    #[test]
    fn violation_action_default_is_deny() {
        assert_eq!(ViolationAction::default(), ViolationAction::Deny);
    }
}
