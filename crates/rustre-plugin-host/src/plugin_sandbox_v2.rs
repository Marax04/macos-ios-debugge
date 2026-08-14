//! Plugin sandbox — policy enforcement and resource tracking.
//!
//! Implements `PluginSandbox`, `SandboxPolicy`, `ApiCallInterceptor`,
//! `ResourceTracker`, `SandboxViolation`, and `SandboxReport`.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── ApiGroup ──────────────────────────────────────────────────────────────────

/// A group of related APIs that can be permitted or denied as a unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApiGroup {
    FileReadOnly,
    FileReadWrite,
    Network,
    Process,
    Memory,
    All,
}

impl ApiGroup {
    /// Return all specific groups (excluding `All`).
    pub fn all_groups() -> Vec<ApiGroup> {
        vec![
            ApiGroup::FileReadOnly,
            ApiGroup::FileReadWrite,
            ApiGroup::Network,
            ApiGroup::Process,
            ApiGroup::Memory,
        ]
    }

    /// Return a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            ApiGroup::FileReadOnly  => "FileReadOnly",
            ApiGroup::FileReadWrite => "FileReadWrite",
            ApiGroup::Network       => "Network",
            ApiGroup::Process       => "Process",
            ApiGroup::Memory        => "Memory",
            ApiGroup::All           => "All",
        }
    }
}

// ── SandboxPolicy ─────────────────────────────────────────────────────────────

/// Security and resource policy for a sandboxed plugin.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// API groups the plugin is allowed to use.
    pub allowed_apis: Vec<ApiGroup>,
    /// Maximum heap/data memory in bytes.
    pub max_memory_bytes: usize,
    /// Maximum wall-clock CPU time in milliseconds.
    pub max_cpu_time_ms: u64,
    /// Whether the plugin may write to files.
    pub can_write_files: bool,
    /// Whether the plugin may open network connections.
    pub can_network: bool,
}

impl SandboxPolicy {
    /// Create a minimal read-only sandbox.
    pub fn read_only() -> Self {
        Self {
            allowed_apis: vec![ApiGroup::FileReadOnly, ApiGroup::Memory],
            max_memory_bytes: 64 * 1024 * 1024,
            max_cpu_time_ms: 5_000,
            can_write_files: false,
            can_network: false,
        }
    }

    /// Create a fully unrestricted policy (for trusted plugins).
    pub fn unrestricted() -> Self {
        Self {
            allowed_apis: vec![ApiGroup::All],
            max_memory_bytes: usize::MAX,
            max_cpu_time_ms: u64::MAX,
            can_write_files: true,
            can_network: true,
        }
    }

    /// True if the given group is permitted.
    pub fn permits(&self, group: &ApiGroup) -> bool {
        if self.allowed_apis.contains(&ApiGroup::All) { return true; }
        self.allowed_apis.contains(group)
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self { Self::read_only() }
}

// ── ViolationType ─────────────────────────────────────────────────────────────

/// The specific kind of sandbox violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// Plugin called an API it is not permitted to use.
    UnauthorizedApi(String),
    /// Plugin exceeded its memory limit.
    MemoryLimitExceeded,
    /// Plugin exceeded its CPU time limit.
    TimeoutExceeded,
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationType::UnauthorizedApi(api) => write!(f, "UnauthorizedApi({})", api),
            ViolationType::MemoryLimitExceeded  => write!(f, "MemoryLimitExceeded"),
            ViolationType::TimeoutExceeded      => write!(f, "TimeoutExceeded"),
        }
    }
}

// ── SandboxViolation ──────────────────────────────────────────────────────────

/// A recorded sandbox policy violation.
#[derive(Debug, Clone)]
pub struct SandboxViolation {
    pub plugin_id: String,
    pub violation_type: ViolationType,
    pub timestamp_ns: u64,
}

impl SandboxViolation {
    pub fn new(plugin_id: impl Into<String>, violation_type: ViolationType) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Self {
            plugin_id: plugin_id.into(),
            violation_type,
            timestamp_ns: ts,
        }
    }
}

// ── InterceptResult ───────────────────────────────────────────────────────────

/// Result of an API call interception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptResult {
    /// The call is permitted; proceed.
    Allow,
    /// The call is denied; signal a sandbox violation.
    Deny,
}

// ── ApiCallInterceptor ────────────────────────────────────────────────────────

/// Maps API names to their `ApiGroup` for intercept decisions.
pub struct ApiCallInterceptor {
    /// Map from API name to the group it belongs to.
    pub intercepts: HashMap<String, ApiGroup>,
}

impl ApiCallInterceptor {
    pub fn new() -> Self {
        let mut intercepts = HashMap::new();
        // File read-only
        for api in &["ReadFile", "fread", "open_read", "stat", "listdir"] {
            intercepts.insert(api.to_string(), ApiGroup::FileReadOnly);
        }
        // File read-write
        for api in &["WriteFile", "fwrite", "open_write", "unlink", "rename"] {
            intercepts.insert(api.to_string(), ApiGroup::FileReadWrite);
        }
        // Network
        for api in &["connect", "send", "recv", "socket", "bind", "listen"] {
            intercepts.insert(api.to_string(), ApiGroup::Network);
        }
        // Process
        for api in &["CreateProcess", "fork", "exec", "kill", "waitpid"] {
            intercepts.insert(api.to_string(), ApiGroup::Process);
        }
        // Memory
        for api in &["VirtualAlloc", "mmap", "malloc", "mprotect"] {
            intercepts.insert(api.to_string(), ApiGroup::Memory);
        }
        Self { intercepts }
    }

    /// Register an additional API name → group mapping.
    pub fn register(&mut self, api_name: impl Into<String>, group: ApiGroup) {
        self.intercepts.insert(api_name.into(), group);
    }

    /// Check whether a given API call is allowed under `policy`.
    pub fn intercept_call(&self, api_name: &str, policy: &SandboxPolicy) -> InterceptResult {
        match self.intercepts.get(api_name) {
            None => InterceptResult::Allow, // unknown API: allow by default
            Some(group) => {
                if policy.permits(group) {
                    InterceptResult::Allow
                } else {
                    InterceptResult::Deny
                }
            }
        }
    }
}

impl Default for ApiCallInterceptor {
    fn default() -> Self { Self::new() }
}

// ── ResourceTracker ───────────────────────────────────────────────────────────

/// Tracks resource consumption of a running plugin.
#[derive(Debug, Clone, Default)]
pub struct ResourceTracker {
    pub memory_usage: usize,
    pub cpu_time_ms: u64,
    pub file_ops: u32,
    pub network_ops: u32,
    pub alloc_count: u32,
}

impl ResourceTracker {
    pub fn new() -> Self { Self::default() }

    /// Record an allocation of `bytes`.
    pub fn record_alloc(&mut self, bytes: usize) {
        self.memory_usage = self.memory_usage.saturating_add(bytes);
        self.alloc_count += 1;
    }

    /// Record a deallocation of `bytes`.
    pub fn record_dealloc(&mut self, bytes: usize) {
        self.memory_usage = self.memory_usage.saturating_sub(bytes);
    }

    /// Record elapsed CPU time.
    pub fn record_cpu_time(&mut self, ms: u64) {
        self.cpu_time_ms = self.cpu_time_ms.saturating_add(ms);
    }

    /// Record a file operation.
    pub fn record_file_op(&mut self) { self.file_ops += 1; }

    /// Record a network operation.
    pub fn record_network_op(&mut self) { self.network_ops += 1; }

    /// Check whether memory usage exceeds the policy limit.
    pub fn memory_exceeded(&self, policy: &SandboxPolicy) -> bool {
        self.memory_usage > policy.max_memory_bytes
    }

    /// Check whether CPU time exceeds the policy limit.
    pub fn time_exceeded(&self, policy: &SandboxPolicy) -> bool {
        self.cpu_time_ms > policy.max_cpu_time_ms
    }

    pub fn reset(&mut self) { *self = Self::default(); }
}

// ── SandboxReport ─────────────────────────────────────────────────────────────

/// Aggregate report for all activity in a sandbox session.
#[derive(Debug, Clone, Default)]
pub struct SandboxReport {
    pub violations: u32,
    pub allowed: u32,
    pub denied: u32,
    pub violation_log: Vec<SandboxViolation>,
}

impl SandboxReport {
    pub fn new() -> Self { Self::default() }

    pub fn record_allowed(&mut self) { self.allowed += 1; }
    pub fn record_denied(&mut self, v: SandboxViolation) {
        self.denied += 1;
        self.violations += 1;
        self.violation_log.push(v);
    }

    pub fn total_calls(&self) -> u32 { self.allowed + self.denied }
    pub fn denial_rate(&self) -> f64 {
        if self.total_calls() == 0 { 0.0 }
        else { self.denied as f64 / self.total_calls() as f64 }
    }
}

// ── PluginSandbox ─────────────────────────────────────────────────────────────

/// The main sandbox — ties together policy, interceptor, tracker, and reporting.
pub struct PluginSandbox {
    pub plugin_id: String,
    pub policy: SandboxPolicy,
    pub interceptor: ApiCallInterceptor,
    pub tracker: ResourceTracker,
    pub report: SandboxReport,
}

impl PluginSandbox {
    pub fn new(plugin_id: impl Into<String>, policy: SandboxPolicy) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            policy,
            interceptor: ApiCallInterceptor::new(),
            tracker: ResourceTracker::new(),
            report: SandboxReport::new(),
        }
    }

    /// Intercept an API call: check policy, update tracker and report.
    pub fn check_api_call(&mut self, api_name: &str) -> InterceptResult {
        let result = self.interceptor.intercept_call(api_name, &self.policy);
        match result {
            InterceptResult::Allow => {
                self.report.record_allowed();
            }
            InterceptResult::Deny => {
                let v = SandboxViolation::new(
                    &self.plugin_id,
                    ViolationType::UnauthorizedApi(api_name.to_string()),
                );
                self.report.record_denied(v);
            }
        }
        result
    }

    /// Record memory allocation and check limits.
    pub fn alloc(&mut self, bytes: usize) -> InterceptResult {
        self.tracker.record_alloc(bytes);
        if self.tracker.memory_exceeded(&self.policy) {
            let v = SandboxViolation::new(&self.plugin_id, ViolationType::MemoryLimitExceeded);
            self.report.record_denied(v);
            InterceptResult::Deny
        } else {
            self.report.record_allowed();
            InterceptResult::Allow
        }
    }

    /// Record CPU time and check limits.
    pub fn tick_cpu(&mut self, ms: u64) -> InterceptResult {
        self.tracker.record_cpu_time(ms);
        if self.tracker.time_exceeded(&self.policy) {
            let v = SandboxViolation::new(&self.plugin_id, ViolationType::TimeoutExceeded);
            self.report.record_denied(v);
            InterceptResult::Deny
        } else {
            InterceptResult::Allow
        }
    }

    /// Reset tracker and report for a new invocation.
    pub fn reset(&mut self) {
        self.tracker.reset();
        self.report = SandboxReport::new();
    }

    pub fn violation_count(&self) -> u32 { self.report.violations }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ro_sandbox(id: &str) -> PluginSandbox {
        PluginSandbox::new(id, SandboxPolicy::read_only())
    }

    #[test]
    fn allow_permitted_api() {
        let mut sb = ro_sandbox("p1");
        assert_eq!(sb.check_api_call("ReadFile"), InterceptResult::Allow);
    }

    #[test]
    fn deny_unpermitted_api() {
        let mut sb = ro_sandbox("p1");
        assert_eq!(sb.check_api_call("WriteFile"), InterceptResult::Deny);
    }

    #[test]
    fn deny_network_in_readonly_policy() {
        let mut sb = ro_sandbox("p1");
        assert_eq!(sb.check_api_call("connect"), InterceptResult::Deny);
    }

    #[test]
    fn allow_all_in_unrestricted() {
        let mut sb = PluginSandbox::new("p2", SandboxPolicy::unrestricted());
        assert_eq!(sb.check_api_call("WriteFile"), InterceptResult::Allow);
        assert_eq!(sb.check_api_call("connect"),   InterceptResult::Allow);
    }

    #[test]
    fn violation_count_increments() {
        let mut sb = ro_sandbox("p1");
        sb.check_api_call("WriteFile");
        sb.check_api_call("connect");
        assert_eq!(sb.violation_count(), 2);
    }

    #[test]
    fn memory_limit_exceeded() {
        let mut policy = SandboxPolicy::read_only();
        policy.max_memory_bytes = 1024;
        let mut sb = PluginSandbox::new("p1", policy);
        assert_eq!(sb.alloc(512), InterceptResult::Allow);
        assert_eq!(sb.alloc(600), InterceptResult::Deny); // 512+600 > 1024
    }

    #[test]
    fn memory_under_limit() {
        let mut sb = ro_sandbox("p1");
        assert_eq!(sb.alloc(100), InterceptResult::Allow);
    }

    #[test]
    fn cpu_timeout_exceeded() {
        let mut policy = SandboxPolicy::read_only();
        policy.max_cpu_time_ms = 100;
        let mut sb = PluginSandbox::new("p1", policy);
        assert_eq!(sb.tick_cpu(50), InterceptResult::Allow);
        assert_eq!(sb.tick_cpu(60), InterceptResult::Deny); // 50+60 > 100
    }

    #[test]
    fn sandbox_report_totals() {
        let mut sb = ro_sandbox("p1");
        sb.check_api_call("ReadFile");  // allowed
        sb.check_api_call("WriteFile"); // denied
        sb.check_api_call("stat");      // allowed
        assert_eq!(sb.report.allowed, 2);
        assert_eq!(sb.report.denied, 1);
    }

    #[test]
    fn sandbox_report_denial_rate() {
        let mut sb = ro_sandbox("p1");
        sb.check_api_call("WriteFile");
        sb.check_api_call("ReadFile");
        let rate = sb.report.denial_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn sandbox_reset_clears_tracker() {
        let mut sb = ro_sandbox("p1");
        sb.alloc(1024);
        sb.reset();
        assert_eq!(sb.tracker.memory_usage, 0);
        assert_eq!(sb.violation_count(), 0);
    }

    #[test]
    fn api_group_permits_all() {
        let policy = SandboxPolicy::unrestricted();
        assert!(policy.permits(&ApiGroup::Network));
        assert!(policy.permits(&ApiGroup::Process));
    }

    #[test]
    fn api_group_name() {
        assert_eq!(ApiGroup::Network.name(), "Network");
        assert_eq!(ApiGroup::FileReadOnly.name(), "FileReadOnly");
    }

    #[test]
    fn violation_type_display() {
        let v = ViolationType::UnauthorizedApi("WriteFile".to_string());
        assert!(v.to_string().contains("WriteFile"));
        assert_eq!(ViolationType::MemoryLimitExceeded.to_string(), "MemoryLimitExceeded");
    }

    #[test]
    fn resource_tracker_dealloc() {
        let mut t = ResourceTracker::new();
        t.record_alloc(1000);
        t.record_dealloc(400);
        assert_eq!(t.memory_usage, 600);
    }

    #[test]
    fn custom_interceptor_registration() {
        let mut sb = ro_sandbox("p1");
        sb.interceptor.register("my_custom_net_api", ApiGroup::Network);
        assert_eq!(sb.check_api_call("my_custom_net_api"), InterceptResult::Deny);
    }
}
