//! Plugin permission system.
//!
//! Implements capability-based security for plugins: FileSystem, Network,
//! Process, Registry, and Memory permissions with request/grant/deny flow
//! and an immutable audit log.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── PermissionKind ───────────────────────────────────────────────────────────

/// Categories of privileged operations a plugin can request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionKind {
    /// Read access to one or more filesystem paths.
    FileSystemRead { paths: Vec<String> },
    /// Write access to one or more filesystem paths.
    FileSystemWrite { paths: Vec<String> },
    /// Outbound network connections to specific hosts/ports.
    Network {
        hosts: Vec<String>,
        ports: Vec<u16>,
    },
    /// Spawn child processes.
    Process { commands: Vec<String> },
    /// Read/write access to Windows registry keys.
    Registry { keys: Vec<String> },
    /// Direct memory read/write (e.g. for a debugger plugin).
    Memory { writable: bool },
    /// Access to the host's IPC/plugin bus.
    IpcBus,
    /// Unrestricted access — trusted plugins only.
    Unrestricted,
}

impl PermissionKind {
    /// Human-readable tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::FileSystemRead { .. } => "fs_read",
            Self::FileSystemWrite { .. } => "fs_write",
            Self::Network { .. } => "network",
            Self::Process { .. } => "process",
            Self::Registry { .. } => "registry",
            Self::Memory { .. } => "memory",
            Self::IpcBus => "ipc_bus",
            Self::Unrestricted => "unrestricted",
        }
    }

    /// Whether this permission is considered high-risk.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Self::Memory { .. }
                | Self::Unrestricted
                | Self::Process { .. }
                | Self::Registry { .. }
        )
    }

    /// Whether this permission involves filesystem access.
    #[must_use]
    pub const fn is_filesystem(&self) -> bool {
        matches!(self, Self::FileSystemRead { .. } | Self::FileSystemWrite { .. })
    }
}

impl fmt::Display for PermissionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystemRead { paths } => write!(f, "fs_read({})", paths.join(", ")),
            Self::FileSystemWrite { paths } => write!(f, "fs_write({})", paths.join(", ")),
            Self::Network { hosts, ports } => {
                write!(f, "network({} hosts, {} ports)", hosts.len(), ports.len())
            }
            Self::Process { commands } => write!(f, "process({})", commands.join(", ")),
            Self::Registry { keys } => write!(f, "registry({})", keys.join(", ")),
            Self::Memory { writable } => write!(f, "memory(writable={writable})"),
            Self::IpcBus => write!(f, "ipc_bus"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
}

// ─── PermissionStatus ─────────────────────────────────────────────────────────

/// Decision on a permission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionStatus {
    /// Not yet decided — request is pending review.
    Pending,
    /// Granted by the host.
    Granted,
    /// Denied by the host.
    Denied,
    /// Revoked after having previously been granted.
    Revoked,
}

impl fmt::Display for PermissionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Granted => write!(f, "Granted"),
            Self::Denied => write!(f, "Denied"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

// ─── PermissionRequest ────────────────────────────────────────────────────────

/// A single permission request made by a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    /// Unique request ID.
    pub id: u64,
    /// ID of the requesting plugin.
    pub plugin_id: String,
    /// The requested capability.
    pub kind: PermissionKind,
    /// Current status of the request.
    pub status: PermissionStatus,
    /// Reason / justification provided by the plugin.
    pub reason: String,
    /// Unix timestamp when the request was created.
    pub created_at: u64,
    /// Unix timestamp when the status was last changed (0 = never).
    pub decided_at: u64,
}

impl PermissionRequest {
    /// Create a new pending request.
    #[must_use]
    pub fn new(
        id: u64,
        plugin_id: impl Into<String>,
        kind: PermissionKind,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id,
            plugin_id: plugin_id.into(),
            kind,
            status: PermissionStatus::Pending,
            reason: reason.into(),
            created_at: unix_now_secs(),
            decided_at: 0,
        }
    }

    /// Whether this request is still awaiting a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == PermissionStatus::Pending
    }

    /// Whether the permission is currently active (granted and not revoked).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == PermissionStatus::Granted
    }
}

impl fmt::Display for PermissionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PermissionRequest[{}] plugin={} kind={} status={}",
            self.id, self.plugin_id, self.kind, self.status
        )
    }
}

// ─── AuditEntry ───────────────────────────────────────────────────────────────

/// An immutable audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Plugin that triggered this event.
    pub plugin_id: String,
    /// Permission request ID involved (0 = n/a).
    pub request_id: u64,
    /// Human-readable description of the event.
    pub event: String,
    /// Whether the action was permitted.
    pub permitted: bool,
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] t={} plugin={} req={} permitted={} — {}",
            self.seq, self.timestamp, self.plugin_id, self.request_id, self.permitted, self.event
        )
    }
}

// ─── PermissionError ──────────────────────────────────────────────────────────

/// Errors from the permission system.
#[derive(Debug, Clone)]
pub enum PermissionError {
    /// A required permission has not been granted.
    NotGranted(PermissionKind),
    /// The request ID does not exist.
    RequestNotFound(u64),
    /// Permission has been revoked.
    Revoked(PermissionKind),
    /// Plugin has no registered permissions.
    PluginNotRegistered(String),
    /// Generic error.
    Other(String),
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGranted(k) => write!(f, "permission not granted: {k}"),
            Self::RequestNotFound(id) => write!(f, "request {id} not found"),
            Self::Revoked(k) => write!(f, "permission revoked: {k}"),
            Self::PluginNotRegistered(s) => write!(f, "plugin '{s}' not registered"),
            Self::Other(s) => write!(f, "permission error: {s}"),
        }
    }
}

impl std::error::Error for PermissionError {}

// ─── PermissionPolicy ─────────────────────────────────────────────────────────

/// Host-side policy that governs how permission requests are handled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPolicy {
    /// If `true`, high-risk permissions are automatically denied.
    pub deny_high_risk: bool,
    /// If `true`, all requests are automatically granted (dev mode).
    pub auto_grant_all: bool,
    /// Specific permission tags that are auto-denied (takes precedence over `auto_grant_all`).
    pub deny_list: Vec<String>,
    /// Specific permission tags that are auto-granted.
    pub allow_list: Vec<String>,
    /// Maximum number of permissions a single plugin may hold.
    pub max_permissions_per_plugin: usize,
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        Self {
            deny_high_risk: true,
            auto_grant_all: false,
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            max_permissions_per_plugin: 20,
        }
    }
}

impl PermissionPolicy {
    /// Strict policy: deny all high-risk, require explicit grant for everything.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            deny_high_risk: true,
            auto_grant_all: false,
            deny_list: vec![
                "unrestricted".into(),
                "memory".into(),
                "process".into(),
                "registry".into(),
            ],
            allow_list: Vec::new(),
            max_permissions_per_plugin: 5,
        }
    }

    /// Permissive policy for development: auto-grant everything.
    #[must_use]
    pub fn dev() -> Self {
        Self {
            deny_high_risk: false,
            auto_grant_all: true,
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            max_permissions_per_plugin: 1000,
        }
    }

    /// Evaluate a request against this policy and return the automatic decision.
    ///
    /// Returns `Some(Granted)` or `Some(Denied)` for automatic decisions,
    /// `None` for manual review required.
    #[must_use]
    pub fn evaluate(&self, kind: &PermissionKind) -> Option<PermissionStatus> {
        // Deny list takes absolute precedence.
        if self.deny_list.iter().any(|d| d == kind.tag()) {
            return Some(PermissionStatus::Denied);
        }
        // High-risk auto-deny.
        if self.deny_high_risk && kind.is_high_risk() {
            return Some(PermissionStatus::Denied);
        }
        // Allow list.
        if self.allow_list.iter().any(|a| a == kind.tag()) {
            return Some(PermissionStatus::Granted);
        }
        // Auto-grant-all mode.
        if self.auto_grant_all {
            return Some(PermissionStatus::Granted);
        }
        None
    }
}

// ─── PermissionManager ────────────────────────────────────────────────────────

/// Central manager for plugin permission requests, grants, denials, and audit logging.
pub struct PermissionManager {
    policy: RwLock<PermissionPolicy>,
    requests: RwLock<HashMap<u64, PermissionRequest>>,
    /// plugin_id → list of active request IDs.
    plugin_grants: RwLock<HashMap<String, Vec<u64>>>,
    audit_log: RwLock<VecDeque<AuditEntry>>,
    next_request_id: Arc<RwLock<u64>>,
    next_audit_seq: Arc<RwLock<u64>>,
    max_audit_entries: usize,
}

impl PermissionManager {
    /// Create a new manager with the given policy.
    #[must_use]
    pub fn new(policy: PermissionPolicy) -> Self {
        Self {
            policy: RwLock::new(policy),
            requests: RwLock::new(HashMap::new()),
            plugin_grants: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(VecDeque::new()),
            next_request_id: Arc::new(RwLock::new(1)),
            next_audit_seq: Arc::new(RwLock::new(1)),
            max_audit_entries: 10_000,
        }
    }

    /// Create with default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(PermissionPolicy::default())
    }

    // ── Request / Grant / Deny ────────────────────────────────────────────

    /// Submit a permission request for `plugin_id`.
    ///
    /// If the policy auto-decides the request, it is resolved immediately and
    /// the result is returned. Otherwise the request is left pending.
    #[must_use]
    pub fn request(
        &self,
        plugin_id: impl Into<String>,
        kind: PermissionKind,
        reason: impl Into<String>,
    ) -> PermissionRequest {
        let id = self.alloc_request_id();
        let pid = plugin_id.into();
        let rsn = reason.into();
        let mut req = PermissionRequest::new(id, pid.clone(), kind.clone(), rsn);

        // Evaluate policy.
        let policy_decision = self.policy.read().unwrap().evaluate(&kind);

        if let Some(status) = policy_decision {
            req.status = status.clone();
            req.decided_at = unix_now_secs();
            if status == PermissionStatus::Granted {
                self.plugin_grants
                    .write()
                    .unwrap()
                    .entry(pid.clone())
                    .or_default()
                    .push(id);
            }
            self.log_audit(
                &pid,
                id,
                format!("auto-{status}: {kind}"),
                status == PermissionStatus::Granted,
            );
        } else {
            self.log_audit(&pid, id, format!("pending: {kind}"), true);
        }

        self.requests.write().unwrap().insert(id, req.clone());
        req
    }

    /// Manually grant a pending request.
    ///
    /// # Errors
    /// Returns `PermissionError::RequestNotFound` if the ID is unknown.
    pub fn grant(&self, request_id: u64) -> Result<(), PermissionError> {
        let mut requests = self.requests.write().unwrap();
        let req = requests
            .get_mut(&request_id)
            .ok_or(PermissionError::RequestNotFound(request_id))?;
        req.status = PermissionStatus::Granted;
        req.decided_at = unix_now_secs();
        let pid = req.plugin_id.clone();
        let kind = req.kind.clone();
        drop(requests);

        self.plugin_grants
            .write()
            .unwrap()
            .entry(pid.clone())
            .or_default()
            .push(request_id);

        self.log_audit(&pid, request_id, format!("granted: {kind}"), true);
        Ok(())
    }

    /// Manually deny a pending request.
    ///
    /// # Errors
    /// Returns `PermissionError::RequestNotFound` if the ID is unknown.
    pub fn deny(&self, request_id: u64) -> Result<(), PermissionError> {
        let mut requests = self.requests.write().unwrap();
        let req = requests
            .get_mut(&request_id)
            .ok_or(PermissionError::RequestNotFound(request_id))?;
        req.status = PermissionStatus::Denied;
        req.decided_at = unix_now_secs();
        let pid = req.plugin_id.clone();
        let kind = req.kind.clone();
        drop(requests);

        self.log_audit(&pid, request_id, format!("denied: {kind}"), false);
        Ok(())
    }

    /// Revoke a previously granted permission.
    ///
    /// # Errors
    /// Returns `PermissionError::RequestNotFound` if unknown.
    pub fn revoke(&self, request_id: u64) -> Result<(), PermissionError> {
        let mut requests = self.requests.write().unwrap();
        let req = requests
            .get_mut(&request_id)
            .ok_or(PermissionError::RequestNotFound(request_id))?;
        req.status = PermissionStatus::Revoked;
        req.decided_at = unix_now_secs();
        let pid = req.plugin_id.clone();
        let kind = req.kind.clone();
        drop(requests);

        // Remove from active grants.
        let mut grants = self.plugin_grants.write().unwrap();
        if let Some(list) = grants.get_mut(&pid) {
            list.retain(|&id| id != request_id);
        }

        self.log_audit(&pid, request_id, format!("revoked: {kind}"), false);
        Ok(())
    }

    // ── Checks ────────────────────────────────────────────────────────────

    /// Check whether `plugin_id` holds an active grant for `kind`.
    ///
    /// Matches are done by permission tag (e.g. `"fs_read"` matches any
    /// `FileSystemRead` permission regardless of paths).
    #[must_use]
    pub fn has_permission(&self, plugin_id: &str, kind: &PermissionKind) -> bool {
        let grants = self.plugin_grants.read().unwrap();
        let requests = self.requests.read().unwrap();
        grants
            .get(plugin_id)
            .map(|ids| {
                ids.iter().any(|&rid| {
                    requests
                        .get(&rid)
                        .map(|r| r.is_active() && r.kind.tag() == kind.tag())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Assert that `plugin_id` has the given permission.
    ///
    /// # Errors
    /// Returns `PermissionError::NotGranted` if the permission is absent.
    pub fn require(&self, plugin_id: &str, kind: &PermissionKind) -> Result<(), PermissionError> {
        if self.has_permission(plugin_id, kind) {
            Ok(())
        } else {
            Err(PermissionError::NotGranted(kind.clone()))
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// All requests for a specific plugin.
    #[must_use]
    pub fn plugin_requests(&self, plugin_id: &str) -> Vec<PermissionRequest> {
        self.requests
            .read()
            .unwrap()
            .values()
            .filter(|r| r.plugin_id == plugin_id)
            .cloned()
            .collect()
    }

    /// All pending requests across all plugins.
    #[must_use]
    pub fn pending_requests(&self) -> Vec<PermissionRequest> {
        self.requests
            .read()
            .unwrap()
            .values()
            .filter(|r| r.is_pending())
            .cloned()
            .collect()
    }

    /// Total number of requests.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requests.read().unwrap().len()
    }

    // ── Audit log ─────────────────────────────────────────────────────────

    /// Recent audit entries (up to `n` most recent).
    #[must_use]
    pub fn recent_audit(&self, n: usize) -> Vec<AuditEntry> {
        let log = self.audit_log.read().unwrap();
        let skip = log.len().saturating_sub(n);
        log.iter().skip(skip).cloned().collect()
    }

    /// All audit entries.
    #[must_use]
    pub fn all_audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_log.read().unwrap().iter().cloned().collect()
    }

    /// Audit entries for a specific plugin.
    #[must_use]
    pub fn audit_for_plugin(&self, plugin_id: &str) -> Vec<AuditEntry> {
        self.audit_log
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.plugin_id == plugin_id)
            .cloned()
            .collect()
    }

    /// Total audit entries logged.
    #[must_use]
    pub fn audit_count(&self) -> usize {
        self.audit_log.read().unwrap().len()
    }

    // ── Policy management ─────────────────────────────────────────────────

    /// Replace the active policy.
    pub fn set_policy(&self, policy: PermissionPolicy) {
        *self.policy.write().unwrap() = policy;
    }

    /// Clone the current policy.
    #[must_use]
    pub fn policy(&self) -> PermissionPolicy {
        self.policy.read().unwrap().clone()
    }

    // ── Internals ─────────────────────────────────────────────────────────

    fn alloc_request_id(&self) -> u64 {
        let mut id = self.next_request_id.write().unwrap();
        let v = *id;
        *id += 1;
        v
    }

    fn log_audit(&self, plugin_id: &str, request_id: u64, event: String, permitted: bool) {
        let seq = {
            let mut s = self.next_audit_seq.write().unwrap();
            let v = *s;
            *s += 1;
            v
        };
        let entry = AuditEntry {
            seq,
            timestamp: unix_now_secs(),
            plugin_id: plugin_id.to_string(),
            request_id,
            event,
            permitted,
        };
        let mut log = self.audit_log.write().unwrap();
        if log.len() >= self.max_audit_entries {
            log.pop_front();
        }
        log.push_back(entry);
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::with_default_policy()
    }
}

impl fmt::Debug for PermissionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PermissionManager {{ requests={}, audit={} }}",
            self.request_count(),
            self.audit_count()
        )
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> PermissionManager {
        PermissionManager::with_default_policy()
    }

    fn fs_read() -> PermissionKind {
        PermissionKind::FileSystemRead {
            paths: vec!["/tmp".into()],
        }
    }

    fn network() -> PermissionKind {
        PermissionKind::Network {
            hosts: vec!["example.com".into()],
            ports: vec![443],
        }
    }

    fn memory_rw() -> PermissionKind {
        PermissionKind::Memory { writable: true }
    }

    // ── PermissionKind ────────────────────────────────────────────────────

    #[test]
    fn test_kind_tag() {
        assert_eq!(fs_read().tag(), "fs_read");
        assert_eq!(network().tag(), "network");
        assert_eq!(memory_rw().tag(), "memory");
        assert_eq!(PermissionKind::Unrestricted.tag(), "unrestricted");
    }

    #[test]
    fn test_kind_is_high_risk() {
        assert!(memory_rw().is_high_risk());
        assert!(PermissionKind::Unrestricted.is_high_risk());
        assert!(!fs_read().is_high_risk());
        assert!(!network().is_high_risk());
    }

    #[test]
    fn test_kind_display() {
        let s = fs_read().to_string();
        assert!(s.contains("fs_read"));
        assert!(s.contains("/tmp"));
    }

    // ── PermissionPolicy ──────────────────────────────────────────────────

    #[test]
    fn test_policy_default_denies_high_risk() {
        let policy = PermissionPolicy::default();
        let decision = policy.evaluate(&memory_rw());
        assert_eq!(decision, Some(PermissionStatus::Denied));
    }

    #[test]
    fn test_policy_dev_grants_all() {
        let policy = PermissionPolicy::dev();
        assert_eq!(policy.evaluate(&fs_read()), Some(PermissionStatus::Granted));
        assert_eq!(policy.evaluate(&network()), Some(PermissionStatus::Granted));
        // Even high-risk in dev mode.
        assert_eq!(policy.evaluate(&memory_rw()), Some(PermissionStatus::Granted));
    }

    #[test]
    fn test_policy_strict() {
        let policy = PermissionPolicy::strict();
        assert_eq!(policy.evaluate(&memory_rw()), Some(PermissionStatus::Denied));
        assert_eq!(policy.evaluate(&PermissionKind::Unrestricted), Some(PermissionStatus::Denied));
    }

    #[test]
    fn test_policy_deny_list_overrides_auto_grant() {
        let mut policy = PermissionPolicy::dev();
        policy.deny_list.push("memory".into());
        assert_eq!(policy.evaluate(&memory_rw()), Some(PermissionStatus::Denied));
    }

    #[test]
    fn test_policy_allow_list() {
        let mut policy = PermissionPolicy::default();
        policy.allow_list.push("fs_read".into());
        assert_eq!(policy.evaluate(&fs_read()), Some(PermissionStatus::Granted));
    }

    // ── request / grant / deny ────────────────────────────────────────────

    #[test]
    fn test_request_auto_denied_high_risk() {
        let mgr = manager();
        let req = mgr.request("plugin-a", memory_rw(), "need memory");
        assert_eq!(req.status, PermissionStatus::Denied);
    }

    #[test]
    fn test_request_pending_when_policy_neutral() {
        let mgr = PermissionManager::new(PermissionPolicy {
            deny_high_risk: false,
            auto_grant_all: false,
            deny_list: vec![],
            allow_list: vec![],
            max_permissions_per_plugin: 10,
        });
        let req = mgr.request("plugin-a", fs_read(), "need files");
        assert_eq!(req.status, PermissionStatus::Pending);
    }

    #[test]
    fn test_grant_pending_request() {
        let mgr = PermissionManager::new(PermissionPolicy {
            deny_high_risk: false,
            auto_grant_all: false,
            deny_list: vec![],
            allow_list: vec![],
            max_permissions_per_plugin: 10,
        });
        let req = mgr.request("plugin-a", fs_read(), "read files");
        mgr.grant(req.id).unwrap();
        assert!(mgr.has_permission("plugin-a", &fs_read()));
    }

    #[test]
    fn test_deny_pending_request() {
        let mgr = PermissionManager::new(PermissionPolicy {
            deny_high_risk: false,
            auto_grant_all: false,
            deny_list: vec![],
            allow_list: vec![],
            max_permissions_per_plugin: 10,
        });
        let req = mgr.request("plugin-a", fs_read(), "read");
        mgr.deny(req.id).unwrap();
        assert!(!mgr.has_permission("plugin-a", &fs_read()));
    }

    #[test]
    fn test_revoke_granted() {
        let mgr = PermissionManager::new(PermissionPolicy::dev());
        let req = mgr.request("plugin-a", fs_read(), "read files");
        assert_eq!(req.status, PermissionStatus::Granted);
        mgr.revoke(req.id).unwrap();
        assert!(!mgr.has_permission("plugin-a", &fs_read()));
    }

    #[test]
    fn test_grant_not_found() {
        let mgr = manager();
        assert!(mgr.grant(9999).is_err());
    }

    #[test]
    fn test_require_ok() {
        let mgr = PermissionManager::new(PermissionPolicy::dev());
        let _ = mgr.request("plugin-a", fs_read(), "r");
        assert!(mgr.require("plugin-a", &fs_read()).is_ok());
    }

    #[test]
    fn test_require_fails() {
        let mgr = manager();
        assert!(mgr.require("plugin-x", &fs_read()).is_err());
    }

    // ── Audit log ─────────────────────────────────────────────────────────

    #[test]
    fn test_audit_log_populated() {
        let mgr = manager();
        let _ = mgr.request("plugin-a", memory_rw(), "need mem");
        assert!(mgr.audit_count() > 0);
    }

    #[test]
    fn test_audit_for_plugin() {
        let mgr = manager();
        let _ = mgr.request("plugin-x", memory_rw(), "x");
        let _ = mgr.request("plugin-y", fs_read(), "y");
        let x_audit = mgr.audit_for_plugin("plugin-x");
        assert!(!x_audit.is_empty());
        assert!(x_audit.iter().all(|e| e.plugin_id == "plugin-x"));
    }

    #[test]
    fn test_audit_entry_display() {
        let entry = AuditEntry {
            seq: 1,
            timestamp: 0,
            plugin_id: "plug".into(),
            request_id: 1,
            event: "granted: fs_read".into(),
            permitted: true,
        };
        let s = format!("{entry}");
        assert!(s.contains("granted"));
        assert!(s.contains("plug"));
    }

    #[test]
    fn test_recent_audit() {
        let mgr = manager();
        for i in 0..10 {
            let _ = mgr.request(format!("p{i}"), fs_read(), "x");
        }
        let recent = mgr.recent_audit(3);
        assert_eq!(recent.len(), 3);
    }

    // ── PermissionRequest display ─────────────────────────────────────────

    #[test]
    fn test_permission_request_display() {
        let req = PermissionRequest::new(1, "plugin-a", fs_read(), "need files");
        let s = format!("{req}");
        assert!(s.contains("plugin-a"));
        assert!(s.contains("Pending"));
    }

    #[test]
    fn test_permission_status_display() {
        assert_eq!(PermissionStatus::Granted.to_string(), "Granted");
        assert_eq!(PermissionStatus::Revoked.to_string(), "Revoked");
    }

    // ── Plugin queries ────────────────────────────────────────────────────

    #[test]
    fn test_plugin_requests_filter() {
        let mgr = manager();
        let _ = mgr.request("pa", memory_rw(), "m");
        let _ = mgr.request("pa", fs_read(), "f");
        let _ = mgr.request("pb", fs_read(), "f");
        let pa = mgr.plugin_requests("pa");
        assert_eq!(pa.len(), 2);
    }

    #[test]
    fn test_pending_requests_list() {
        let mgr = PermissionManager::new(PermissionPolicy {
            deny_high_risk: false,
            auto_grant_all: false,
            deny_list: vec![],
            allow_list: vec![],
            max_permissions_per_plugin: 20,
        });
        let _ = mgr.request("p1", fs_read(), "r1");
        let _ = mgr.request("p2", fs_read(), "r2");
        assert_eq!(mgr.pending_requests().len(), 2);
    }

    #[test]
    fn test_policy_replacement() {
        let mgr = manager();
        mgr.set_policy(PermissionPolicy::dev());
        let req = mgr.request("p", fs_read(), "r");
        assert_eq!(req.status, PermissionStatus::Granted);
    }

    #[test]
    fn test_debug_output() {
        let mgr = manager();
        let s = format!("{mgr:?}");
        assert!(s.contains("PermissionManager"));
    }
}
