//! `sandbox_policy` — Fine-grained sandbox execution policies.
//!
//! Provides syscall allow/deny lists, network restrictions, resource limits,
//! and preset policies for common analysis scenarios (Windows malware, Linux
//! malware, Android apps, etc.).  A `PolicyEnforcer` evaluates runtime events
//! against an active `SandboxPolicy` and records every `PolicyViolation` in a
//! timestamped `ViolationLog`.  A `PolicyReport` summarises violation counts
//! per category for post-run review.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SyscallId ────────────────────────────────────────────────────────────────

/// Identifies a system call by its numeric ID and a human-readable name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyscallId {
    /// Platform-specific syscall number.
    pub number: u32,
    /// Symbolic name (e.g., `"NtCreateFile"`, `"read"`, `"openat"`).
    pub name: String,
}

impl SyscallId {
    /// Create a new `SyscallId`.
    #[must_use]
    pub fn new(number: u32, name: impl Into<String>) -> Self {
        Self {
            number,
            name: name.into(),
        }
    }

    /// Convenience constructor for Windows NT native API calls.
    #[must_use]
    pub fn nt(number: u32, name: &str) -> Self {
        Self::new(number, name)
    }

    /// Convenience constructor for Linux syscalls.
    #[must_use]
    pub fn linux(number: u32, name: &str) -> Self {
        Self::new(number, name)
    }
}

impl fmt::Display for SyscallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.number)
    }
}

// ─── NetworkMode ──────────────────────────────────────────────────────────────

/// Network isolation level applied to the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum NetworkMode {
    /// No network access whatsoever.
    #[default]
    Isolated,
    /// Full access to the host network (use with caution).
    HostNetwork,
    /// Traffic is routed through a simulated/instrumented network layer.
    SimulatedNetwork,
    /// Only whitelisted IPs and domains are reachable.
    Filtered,
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolated => write!(f, "isolated"),
            Self::HostNetwork => write!(f, "host_network"),
            Self::SimulatedNetwork => write!(f, "simulated_network"),
            Self::Filtered => write!(f, "filtered"),
        }
    }
}


// ─── SandboxPolicy ────────────────────────────────────────────────────────────

/// Comprehensive policy governing what a sandboxed process may do.
///
/// Use `PolicyBuilder` for ergonomic construction, or pick a `PolicyPreset` and
/// convert it with `PolicyPreset::to_policy()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// System calls explicitly allowed.  Empty means "all allowed".
    pub allowed_syscalls: Vec<SyscallId>,
    /// System calls that are always blocked (overrides `allowed_syscalls`).
    pub denied_syscalls: Vec<SyscallId>,
    /// Outbound connections to these IP addresses are permitted.
    pub allowed_network_ips: Vec<String>,
    /// DNS names that may be resolved / connected to.
    pub allowed_domains: Vec<String>,
    /// Network isolation mode.
    pub network_mode: NetworkMode,
    /// Maximum number of concurrent processes/threads the sandbox may spawn.
    pub max_processes: u32,
    /// Maximum virtual-memory allocation in megabytes.
    pub max_memory_mb: u64,
    /// Maximum disk write in megabytes.
    pub max_disk_mb: u64,
    /// Maximum wall-clock execution time in seconds.
    pub max_run_seconds: u64,
    /// Whether the sandbox process is permitted to write to the filesystem.
    pub allow_file_write: bool,
    /// Whether the sandbox process is permitted to modify the registry.
    pub allow_registry_write: bool,
    /// Whether the sandbox should drop elevated privileges before execution.
    pub drop_privileges: bool,
}

impl SandboxPolicy {
    /// Validate that the policy does not contain contradictory or degenerate
    /// settings.
    ///
    /// # Errors
    /// Returns a description of the first validation problem found.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_run_seconds == 0 {
            return Err("max_run_seconds must be > 0".into());
        }
        if self.max_memory_mb == 0 {
            return Err("max_memory_mb must be > 0".into());
        }
        if self.max_processes == 0 {
            return Err("max_processes must be > 0".into());
        }
        // A deny list entry that is also in the allow list is a logic error.
        for denied in &self.denied_syscalls {
            if self
                .allowed_syscalls
                .iter()
                .any(|a| a.number == denied.number)
            {
                return Err(format!(
                    "syscall {} appears in both allowed and denied lists",
                    denied.name
                ));
            }
        }
        Ok(())
    }

    /// Returns `true` if the given syscall number is explicitly denied.
    #[must_use]
    pub fn is_syscall_denied(&self, number: u32) -> bool {
        self.denied_syscalls.iter().any(|s| s.number == number)
    }

    /// Returns `true` if the given syscall number is allowed under the policy.
    ///
    /// The deny list takes precedence.  If `allowed_syscalls` is empty every
    /// non-denied call is permitted.
    #[must_use]
    pub fn is_syscall_allowed(&self, number: u32) -> bool {
        if self.is_syscall_denied(number) {
            return false;
        }
        if self.allowed_syscalls.is_empty() {
            return true;
        }
        self.allowed_syscalls.iter().any(|s| s.number == number)
    }

    /// Returns `true` if the given IP or domain may be contacted.
    #[must_use]
    pub fn is_network_target_allowed(&self, target: &str) -> bool {
        match self.network_mode {
            NetworkMode::Isolated => false,
            NetworkMode::HostNetwork | NetworkMode::SimulatedNetwork => true,
            NetworkMode::Filtered => {
                self.allowed_network_ips.iter().any(|ip| ip == target)
                    || self
                        .allowed_domains
                        .iter()
                        .any(|d| target == d.as_str() || target.ends_with(&format!(".{d}")))
            }
        }
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        PolicyPreset::Standard.to_policy()
    }
}

// ─── PolicyBuilder ────────────────────────────────────────────────────────────

/// Fluent builder for `SandboxPolicy`.
///
/// ```
/// use rustre_sandbox::sandbox_policy::{PolicyBuilder, NetworkMode};
///
/// let policy = PolicyBuilder::new()
///     .network_mode(NetworkMode::SimulatedNetwork)
///     .max_memory_mb(512)
///     .max_run_seconds(60)
///     .allow_file_write(false)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct PolicyBuilder {
    allowed_syscalls: Vec<SyscallId>,
    denied_syscalls: Vec<SyscallId>,
    allowed_network_ips: Vec<String>,
    allowed_domains: Vec<String>,
    network_mode: Option<NetworkMode>,
    max_processes: Option<u32>,
    max_memory_mb: Option<u64>,
    max_disk_mb: Option<u64>,
    max_run_seconds: Option<u64>,
    allow_file_write: Option<bool>,
    allow_registry_write: Option<bool>,
    drop_privileges: Option<bool>,
}

impl PolicyBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the builder from an existing `PolicyPreset`.
    #[must_use]
    pub fn from_preset(preset: &PolicyPreset) -> Self {
        let base = preset.to_policy();
        Self {
            allowed_syscalls: base.allowed_syscalls,
            denied_syscalls: base.denied_syscalls,
            allowed_network_ips: base.allowed_network_ips,
            allowed_domains: base.allowed_domains,
            network_mode: Some(base.network_mode),
            max_processes: Some(base.max_processes),
            max_memory_mb: Some(base.max_memory_mb),
            max_disk_mb: Some(base.max_disk_mb),
            max_run_seconds: Some(base.max_run_seconds),
            allow_file_write: Some(base.allow_file_write),
            allow_registry_write: Some(base.allow_registry_write),
            drop_privileges: Some(base.drop_privileges),
        }
    }

    /// Append a syscall to the allow list.
    #[must_use]
    pub fn allow_syscall(mut self, sc: SyscallId) -> Self {
        self.allowed_syscalls.push(sc);
        self
    }

    /// Append a syscall to the deny list.
    #[must_use]
    pub fn deny_syscall(mut self, sc: SyscallId) -> Self {
        self.denied_syscalls.push(sc);
        self
    }

    /// Allow an outbound IP address.
    #[must_use]
    pub fn allow_ip(mut self, ip: impl Into<String>) -> Self {
        self.allowed_network_ips.push(ip.into());
        self
    }

    /// Allow a domain (and all its subdomains).
    #[must_use]
    pub fn allow_domain(mut self, domain: impl Into<String>) -> Self {
        self.allowed_domains.push(domain.into());
        self
    }

    /// Set the network isolation mode.
    #[must_use]
    pub const fn network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = Some(mode);
        self
    }

    /// Set the maximum number of processes.
    #[must_use]
    pub const fn max_processes(mut self, n: u32) -> Self {
        self.max_processes = Some(n);
        self
    }

    /// Set the maximum memory in MB.
    #[must_use]
    pub const fn max_memory_mb(mut self, mb: u64) -> Self {
        self.max_memory_mb = Some(mb);
        self
    }

    /// Set the maximum disk write in MB.
    #[must_use]
    pub const fn max_disk_mb(mut self, mb: u64) -> Self {
        self.max_disk_mb = Some(mb);
        self
    }

    /// Set the maximum run time in seconds.
    #[must_use]
    pub const fn max_run_seconds(mut self, secs: u64) -> Self {
        self.max_run_seconds = Some(secs);
        self
    }

    /// Control whether the sandbox process may write files.
    #[must_use]
    pub const fn allow_file_write(mut self, allow: bool) -> Self {
        self.allow_file_write = Some(allow);
        self
    }

    /// Control whether the sandbox process may modify the registry.
    #[must_use]
    pub const fn allow_registry_write(mut self, allow: bool) -> Self {
        self.allow_registry_write = Some(allow);
        self
    }

    /// Control whether privileges are dropped before execution.
    #[must_use]
    pub const fn drop_privileges(mut self, drop: bool) -> Self {
        self.drop_privileges = Some(drop);
        self
    }

    /// Consume the builder and produce a `SandboxPolicy`.
    #[must_use]
    pub fn build(self) -> SandboxPolicy {
        SandboxPolicy {
            allowed_syscalls: self.allowed_syscalls,
            denied_syscalls: self.denied_syscalls,
            allowed_network_ips: self.allowed_network_ips,
            allowed_domains: self.allowed_domains,
            network_mode: self.network_mode.unwrap_or_default(),
            max_processes: self.max_processes.unwrap_or(16),
            max_memory_mb: self.max_memory_mb.unwrap_or(512),
            max_disk_mb: self.max_disk_mb.unwrap_or(256),
            max_run_seconds: self.max_run_seconds.unwrap_or(120),
            allow_file_write: self.allow_file_write.unwrap_or(true),
            allow_registry_write: self.allow_registry_write.unwrap_or(false),
            drop_privileges: self.drop_privileges.unwrap_or(true),
        }
    }
}

// ─── PolicyPreset ─────────────────────────────────────────────────────────────

/// Named policy presets covering the most common analysis scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyPreset {
    /// Maximum isolation — nearly everything denied.
    Strict,
    /// Balanced defaults suitable for general-purpose analysis.
    Standard,
    /// Relaxed policy that allows most activity (useful for benign QA runs).
    Permissive,
    /// Tailored for Windows malware: network access via simulated layer,
    /// registry writes allowed, common injection syscalls monitored.
    WindowsMalware,
    /// Tailored for Linux malware: broad syscall allow list, isolated network,
    /// file writes to /tmp only.
    LinuxMalware,
    /// Tailored for Android APK analysis: Binder IPC calls monitored,
    /// simulated network, no direct host filesystem access.
    AndroidApp,
}

impl PolicyPreset {
    /// Convert the preset into a fully initialised `SandboxPolicy`.
    #[must_use]
    pub fn to_policy(&self) -> SandboxPolicy {
        match self {
            Self::Strict => Self::build_strict(),
            Self::Standard => Self::build_standard(),
            Self::Permissive => Self::build_permissive(),
            Self::WindowsMalware => Self::build_windows_malware(),
            Self::LinuxMalware => Self::build_linux_malware(),
            Self::AndroidApp => Self::build_android_app(),
        }
    }

    // ── Strict ───────────────────────────────────────────────────────────────

    fn build_strict() -> SandboxPolicy {
        // Allow only a minimal set of read-only/safe syscalls on Windows NT.
        let allowed = vec![
            SyscallId::nt(0, "NtReadFile"),
            SyscallId::nt(1, "NtQueryInformationFile"),
            SyscallId::nt(2, "NtQueryDirectoryFile"),
            SyscallId::nt(3, "NtClose"),
            SyscallId::nt(4, "NtAllocateVirtualMemory"),
            SyscallId::nt(5, "NtFreeVirtualMemory"),
            SyscallId::nt(6, "NtQueryVirtualMemory"),
            SyscallId::nt(7, "NtQuerySystemInformation"),
            SyscallId::nt(8, "NtQueryPerformanceCounter"),
            SyscallId::nt(9, "NtDelayExecution"),
            SyscallId::nt(10, "NtGetCurrentProcessorNumber"),
        ];

        let denied = vec![
            SyscallId::nt(100, "NtCreateProcess"),
            SyscallId::nt(101, "NtCreateThread"),
            SyscallId::nt(102, "NtCreateThreadEx"),
            SyscallId::nt(103, "NtWriteVirtualMemory"),
            SyscallId::nt(104, "NtMapViewOfSection"),
            SyscallId::nt(105, "NtOpenProcess"),
            SyscallId::nt(106, "NtCreateFile"),
            SyscallId::nt(107, "NtWriteFile"),
            SyscallId::nt(108, "NtCreateKey"),
            SyscallId::nt(109, "NtSetValueKey"),
            SyscallId::nt(110, "NtLoadDriver"),
            SyscallId::nt(111, "NtSetSystemInformation"),
            SyscallId::nt(112, "NtCreateSection"),
            SyscallId::nt(113, "NtQueueApcThread"),
            SyscallId::nt(114, "NtSuspendProcess"),
        ];

        SandboxPolicy {
            allowed_syscalls: allowed,
            denied_syscalls: denied,
            allowed_network_ips: vec![],
            allowed_domains: vec![],
            network_mode: NetworkMode::Isolated,
            max_processes: 1,
            max_memory_mb: 128,
            max_disk_mb: 0,
            max_run_seconds: 30,
            allow_file_write: false,
            allow_registry_write: false,
            drop_privileges: true,
        }
    }

    // ── Standard ─────────────────────────────────────────────────────────────

    fn build_standard() -> SandboxPolicy {
        // Standard analysis — a reasonable allow list plus the most dangerous
        // syscalls on the deny list.
        let allowed = vec![
            SyscallId::nt(0, "NtReadFile"),
            SyscallId::nt(1, "NtWriteFile"),
            SyscallId::nt(2, "NtCreateFile"),
            SyscallId::nt(3, "NtDeleteFile"),
            SyscallId::nt(4, "NtQueryInformationFile"),
            SyscallId::nt(5, "NtQueryDirectoryFile"),
            SyscallId::nt(6, "NtClose"),
            SyscallId::nt(7, "NtAllocateVirtualMemory"),
            SyscallId::nt(8, "NtFreeVirtualMemory"),
            SyscallId::nt(9, "NtQueryVirtualMemory"),
            SyscallId::nt(10, "NtCreateProcess"),
            SyscallId::nt(11, "NtOpenProcess"),
            SyscallId::nt(12, "NtTerminateProcess"),
            SyscallId::nt(13, "NtCreateKey"),
            SyscallId::nt(14, "NtOpenKey"),
            SyscallId::nt(15, "NtQueryValueKey"),
            SyscallId::nt(16, "NtSetValueKey"),
            SyscallId::nt(17, "NtDelayExecution"),
            SyscallId::nt(18, "NtQuerySystemInformation"),
            SyscallId::nt(19, "NtQueryInformationProcess"),
            SyscallId::nt(20, "NtDuplicateObject"),
            SyscallId::nt(21, "NtCreateSection"),
            SyscallId::nt(22, "NtConnectPort"),
            SyscallId::nt(23, "NtDeviceIoControlFile"),
        ];

        let denied = vec![
            SyscallId::nt(200, "NtLoadDriver"),
            SyscallId::nt(201, "NtSetSystemInformation"),
            SyscallId::nt(202, "NtWriteVirtualMemory"),
            SyscallId::nt(203, "NtCreateThreadEx"),
            SyscallId::nt(204, "NtMapViewOfSection"),
            SyscallId::nt(205, "NtQueueApcThread"),
            SyscallId::nt(206, "NtSuspendProcess"),
            SyscallId::nt(207, "NtDebugActiveProcess"),
        ];

        SandboxPolicy {
            allowed_syscalls: allowed,
            denied_syscalls: denied,
            allowed_network_ips: vec![],
            allowed_domains: vec![],
            network_mode: NetworkMode::SimulatedNetwork,
            max_processes: 16,
            max_memory_mb: 512,
            max_disk_mb: 256,
            max_run_seconds: 120,
            allow_file_write: true,
            allow_registry_write: false,
            drop_privileges: true,
        }
    }

    // ── Permissive ───────────────────────────────────────────────────────────

    const fn build_permissive() -> SandboxPolicy {
        // Deny nothing, allow everything — only limits are resource ceilings.
        SandboxPolicy {
            allowed_syscalls: vec![], // empty = all allowed
            denied_syscalls: vec![],
            allowed_network_ips: vec![],
            allowed_domains: vec![],
            network_mode: NetworkMode::HostNetwork,
            max_processes: 64,
            max_memory_mb: 4096,
            max_disk_mb: 1024,
            max_run_seconds: 300,
            allow_file_write: true,
            allow_registry_write: true,
            drop_privileges: false,
        }
    }

    // ── Windows Malware ──────────────────────────────────────────────────────

    fn build_windows_malware() -> SandboxPolicy {
        // Broad Windows NT allow list — we want to observe behaviour, not block
        // it.  Only the absolute most privileged kernel-entry points are denied.
        let allowed = vec![
            SyscallId::nt(0, "NtReadFile"),
            SyscallId::nt(1, "NtWriteFile"),
            SyscallId::nt(2, "NtCreateFile"),
            SyscallId::nt(3, "NtDeleteFile"),
            SyscallId::nt(4, "NtQueryInformationFile"),
            SyscallId::nt(5, "NtQueryDirectoryFile"),
            SyscallId::nt(6, "NtClose"),
            SyscallId::nt(7, "NtAllocateVirtualMemory"),
            SyscallId::nt(8, "NtFreeVirtualMemory"),
            SyscallId::nt(9, "NtQueryVirtualMemory"),
            SyscallId::nt(10, "NtProtectVirtualMemory"),
            SyscallId::nt(11, "NtWriteVirtualMemory"),
            SyscallId::nt(12, "NtReadVirtualMemory"),
            SyscallId::nt(13, "NtCreateProcess"),
            SyscallId::nt(14, "NtOpenProcess"),
            SyscallId::nt(15, "NtTerminateProcess"),
            SyscallId::nt(16, "NtSuspendProcess"),
            SyscallId::nt(17, "NtResumeProcess"),
            SyscallId::nt(18, "NtCreateThread"),
            SyscallId::nt(19, "NtCreateThreadEx"),
            SyscallId::nt(20, "NtTerminateThread"),
            SyscallId::nt(21, "NtCreateKey"),
            SyscallId::nt(22, "NtOpenKey"),
            SyscallId::nt(23, "NtSetValueKey"),
            SyscallId::nt(24, "NtQueryValueKey"),
            SyscallId::nt(25, "NtDeleteKey"),
            SyscallId::nt(26, "NtDeleteValueKey"),
            SyscallId::nt(27, "NtCreateSection"),
            SyscallId::nt(28, "NtMapViewOfSection"),
            SyscallId::nt(29, "NtUnmapViewOfSection"),
            SyscallId::nt(30, "NtQueueApcThread"),
            SyscallId::nt(31, "NtConnectPort"),
            SyscallId::nt(32, "NtCreateNamedPipeFile"),
            SyscallId::nt(33, "NtDeviceIoControlFile"),
            SyscallId::nt(34, "NtDuplicateObject"),
            SyscallId::nt(35, "NtQueryInformationProcess"),
            SyscallId::nt(36, "NtSetInformationProcess"),
            SyscallId::nt(37, "NtDelayExecution"),
            SyscallId::nt(38, "NtQuerySystemInformation"),
            SyscallId::nt(39, "NtSetSystemTime"),
            SyscallId::nt(40, "NtOpenProcessToken"),
            SyscallId::nt(41, "NtAdjustPrivilegesToken"),
            SyscallId::nt(42, "NtImpersonateThread"),
            SyscallId::nt(43, "NtSetContextThread"),
            SyscallId::nt(44, "NtGetContextThread"),
        ];

        let denied = vec![
            SyscallId::nt(300, "NtLoadDriver"),
            SyscallId::nt(301, "NtSetSystemInformation"),
            SyscallId::nt(302, "NtDebugActiveProcess"),
            SyscallId::nt(303, "NtSystemDebugControl"),
        ];

        SandboxPolicy {
            allowed_syscalls: allowed,
            denied_syscalls: denied,
            allowed_network_ips: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            allowed_domains: vec!["windowsupdate.com".to_string(), "microsoft.com".to_string()],
            network_mode: NetworkMode::SimulatedNetwork,
            max_processes: 32,
            max_memory_mb: 1024,
            max_disk_mb: 512,
            max_run_seconds: 180,
            allow_file_write: true,
            allow_registry_write: true,
            drop_privileges: false,
        }
    }

    // ── Linux Malware ────────────────────────────────────────────────────────

    fn build_linux_malware() -> SandboxPolicy {
        // Linux x86-64 syscall numbers (kernel 5.x).
        let allowed = vec![
            SyscallId::linux(0, "read"),
            SyscallId::linux(1, "write"),
            SyscallId::linux(2, "open"),
            SyscallId::linux(3, "close"),
            SyscallId::linux(4, "stat"),
            SyscallId::linux(5, "fstat"),
            SyscallId::linux(6, "lstat"),
            SyscallId::linux(7, "poll"),
            SyscallId::linux(8, "lseek"),
            SyscallId::linux(9, "mmap"),
            SyscallId::linux(10, "mprotect"),
            SyscallId::linux(11, "munmap"),
            SyscallId::linux(12, "brk"),
            SyscallId::linux(20, "writev"),
            SyscallId::linux(21, "access"),
            SyscallId::linux(22, "pipe"),
            SyscallId::linux(23, "select"),
            SyscallId::linux(32, "dup"),
            SyscallId::linux(33, "dup2"),
            SyscallId::linux(39, "getpid"),
            SyscallId::linux(41, "socket"),
            SyscallId::linux(42, "connect"),
            SyscallId::linux(43, "accept"),
            SyscallId::linux(44, "sendto"),
            SyscallId::linux(45, "recvfrom"),
            SyscallId::linux(49, "bind"),
            SyscallId::linux(50, "listen"),
            SyscallId::linux(56, "clone"),
            SyscallId::linux(57, "fork"),
            SyscallId::linux(59, "execve"),
            SyscallId::linux(60, "exit"),
            SyscallId::linux(61, "wait4"),
            SyscallId::linux(62, "kill"),
            SyscallId::linux(63, "uname"),
            SyscallId::linux(87, "unlink"),
            SyscallId::linux(88, "symlink"),
            SyscallId::linux(89, "readlink"),
            SyscallId::linux(90, "chmod"),
            SyscallId::linux(92, "chown"),
            SyscallId::linux(257, "openat"),
            SyscallId::linux(258, "mkdirat"),
            SyscallId::linux(263, "unlinkat"),
        ];

        let denied = vec![
            SyscallId::linux(175, "init_module"),
            SyscallId::linux(176, "delete_module"),
            SyscallId::linux(317, "seccomp"),
            SyscallId::linux(154, "syslog"),
            SyscallId::linux(169, "reboot"),
        ];

        SandboxPolicy {
            allowed_syscalls: allowed,
            denied_syscalls: denied,
            allowed_network_ips: vec!["8.8.8.8".to_string()],
            allowed_domains: vec![],
            network_mode: NetworkMode::Isolated,
            max_processes: 16,
            max_memory_mb: 512,
            max_disk_mb: 128,
            max_run_seconds: 120,
            allow_file_write: true,
            allow_registry_write: false, // N/A on Linux
            drop_privileges: true,
        }
    }

    // ── Android App ──────────────────────────────────────────────────────────

    fn build_android_app() -> SandboxPolicy {
        // Android runs on Linux so syscall numbers are Linux ARM64/x86 numbers.
        // We allow standard Bionic/Dalvik calls and block kernel-level escalation.
        let allowed = vec![
            SyscallId::linux(0, "read"),
            SyscallId::linux(1, "write"),
            SyscallId::linux(2, "open"),
            SyscallId::linux(3, "close"),
            SyscallId::linux(9, "mmap"),
            SyscallId::linux(10, "mprotect"),
            SyscallId::linux(11, "munmap"),
            SyscallId::linux(41, "socket"),
            SyscallId::linux(42, "connect"),
            SyscallId::linux(44, "sendto"),
            SyscallId::linux(45, "recvfrom"),
            SyscallId::linux(56, "clone"),
            SyscallId::linux(57, "fork"),
            SyscallId::linux(59, "execve"),
            SyscallId::linux(60, "exit"),
            SyscallId::linux(257, "openat"),
            // Binder IPC (Linux ioctl on /dev/binder)
            SyscallId::linux(16, "ioctl"),
            SyscallId::linux(202, "futex"),
            SyscallId::linux(218, "set_tid_address"),
            SyscallId::linux(228, "clock_gettime"),
            SyscallId::linux(231, "exit_group"),
        ];

        let denied = vec![
            SyscallId::linux(175, "init_module"),
            SyscallId::linux(176, "delete_module"),
            SyscallId::linux(169, "reboot"),
            SyscallId::linux(54, "setsockopt"), // prevent raw socket tricks
        ];

        SandboxPolicy {
            allowed_syscalls: allowed,
            denied_syscalls: denied,
            allowed_network_ips: vec![],
            allowed_domains: vec![
                "googleapis.com".to_string(),
                "gstatic.com".to_string(),
                "android.com".to_string(),
            ],
            network_mode: NetworkMode::SimulatedNetwork,
            max_processes: 24,
            max_memory_mb: 256,
            max_disk_mb: 64,
            max_run_seconds: 90,
            allow_file_write: true,
            allow_registry_write: false,
            drop_privileges: true,
        }
    }
}

impl fmt::Display for PolicyPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Standard => write!(f, "standard"),
            Self::Permissive => write!(f, "permissive"),
            Self::WindowsMalware => write!(f, "windows_malware"),
            Self::LinuxMalware => write!(f, "linux_malware"),
            Self::AndroidApp => write!(f, "android_app"),
        }
    }
}

// ─── PolicyViolation ─────────────────────────────────────────────────────────

/// Kinds of policy violation that the `PolicyEnforcer` can detect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    /// A syscall that is on the deny list was attempted.
    SyscallDenied {
        syscall: SyscallId,
        pid: u32,
        ts_ms: u64,
    },
    /// A network connection to a blocked target was attempted.
    NetworkDenied {
        target: String,
        pid: u32,
        ts_ms: u64,
    },
    /// The sandbox process exceeded its memory budget.
    MemoryExceeded {
        used_mb: u64,
        limit_mb: u64,
        ts_ms: u64,
    },
    /// The sandbox process exceeded its disk-write budget.
    DiskExceeded {
        used_mb: u64,
        limit_mb: u64,
        ts_ms: u64,
    },
    /// The sandbox exceeded its wall-clock time limit.
    TimeExceeded {
        elapsed_secs: u64,
        limit_secs: u64,
        ts_ms: u64,
    },
    /// More processes were spawned than the policy permits.
    ProcessLimitExceeded { count: u32, limit: u32, ts_ms: u64 },
}

impl PolicyViolation {
    /// Return the timestamp (ms since sandbox start) of this violation.
    #[must_use]
    pub const fn ts_ms(&self) -> u64 {
        match self {
            Self::SyscallDenied { ts_ms, .. }
            | Self::NetworkDenied { ts_ms, .. }
            | Self::MemoryExceeded { ts_ms, .. }
            | Self::DiskExceeded { ts_ms, .. }
            | Self::TimeExceeded { ts_ms, .. }
            | Self::ProcessLimitExceeded { ts_ms, .. } => *ts_ms,
        }
    }

    /// Short category label for this violation kind.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::SyscallDenied { .. } => "syscall_denied",
            Self::NetworkDenied { .. } => "network_denied",
            Self::MemoryExceeded { .. } => "memory_exceeded",
            Self::DiskExceeded { .. } => "disk_exceeded",
            Self::TimeExceeded { .. } => "time_exceeded",
            Self::ProcessLimitExceeded { .. } => "process_limit_exceeded",
        }
    }

    /// Returns `true` if this is a syscall denial.
    #[must_use]
    pub const fn is_syscall_violation(&self) -> bool {
        matches!(self, Self::SyscallDenied { .. })
    }

    /// Returns `true` if this is a resource-limit violation.
    #[must_use]
    pub const fn is_resource_violation(&self) -> bool {
        matches!(
            self,
            Self::MemoryExceeded { .. }
                | Self::DiskExceeded { .. }
                | Self::TimeExceeded { .. }
                | Self::ProcessLimitExceeded { .. }
        )
    }
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallDenied {
                syscall,
                pid,
                ts_ms,
            } => write!(f, "[{ts_ms}ms] syscall_denied: {} pid={pid}", syscall.name),
            Self::NetworkDenied { target, pid, ts_ms } => {
                write!(f, "[{ts_ms}ms] network_denied: {target} pid={pid}")
            }
            Self::MemoryExceeded {
                used_mb,
                limit_mb,
                ts_ms,
            } => write!(f, "[{ts_ms}ms] memory_exceeded: {used_mb}MB > {limit_mb}MB"),
            Self::DiskExceeded {
                used_mb,
                limit_mb,
                ts_ms,
            } => write!(f, "[{ts_ms}ms] disk_exceeded: {used_mb}MB > {limit_mb}MB"),
            Self::TimeExceeded {
                elapsed_secs,
                limit_secs,
                ts_ms,
            } => write!(
                f,
                "[{ts_ms}ms] time_exceeded: {elapsed_secs}s > {limit_secs}s"
            ),
            Self::ProcessLimitExceeded {
                count,
                limit,
                ts_ms,
            } => write!(f, "[{ts_ms}ms] process_limit_exceeded: {count} > {limit}"),
        }
    }
}

// ─── ViolationLog ─────────────────────────────────────────────────────────────

/// Ordered log of all `PolicyViolation`s raised during a sandbox run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViolationLog {
    entries: Vec<PolicyViolation>,
}

impl ViolationLog {
    /// Create an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a new violation.
    pub fn record(&mut self, v: PolicyViolation) {
        self.entries.push(v);
    }

    /// Iterate over all violations in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &PolicyViolation> {
        self.entries.iter()
    }

    /// Number of recorded violations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no violations were recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all violations for a given category label.
    #[must_use]
    pub fn by_category(&self, category: &str) -> Vec<&PolicyViolation> {
        self.entries
            .iter()
            .filter(|v| v.category() == category)
            .collect()
    }

    /// Return the earliest violation timestamp, or `None` if the log is empty.
    #[must_use]
    pub fn first_ts_ms(&self) -> Option<u64> {
        self.entries.first().map(PolicyViolation::ts_ms)
    }

    /// Return the latest violation timestamp, or `None` if the log is empty.
    #[must_use]
    pub fn last_ts_ms(&self) -> Option<u64> {
        self.entries.last().map(PolicyViolation::ts_ms)
    }

    /// Clear all recorded violations.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ─── PolicyReport ─────────────────────────────────────────────────────────────

/// Summary report generated from a `ViolationLog` after a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReport {
    /// Total violations recorded.
    pub total_violations: usize,
    /// Violations per category label.
    pub by_category: HashMap<String, usize>,
    /// Timestamp of the first violation (ms since sandbox start).
    pub first_violation_ms: Option<u64>,
    /// Timestamp of the last violation.
    pub last_violation_ms: Option<u64>,
    /// Whether any resource limit was exceeded.
    pub resource_limit_hit: bool,
    /// Whether any syscall was denied.
    pub syscall_denied: bool,
    /// Whether any network connection was denied.
    pub network_denied: bool,
    /// Ordered list of all violation display strings.
    pub violation_messages: Vec<String>,
}

impl PolicyReport {
    /// Build a report from a `ViolationLog`.
    #[must_use]
    pub fn from_log(log: &ViolationLog) -> Self {
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut resource_limit_hit = false;
        let mut syscall_denied = false;
        let mut network_denied = false;
        let mut violation_messages = Vec::new();

        for v in log.iter() {
            *by_category.entry(v.category().to_string()).or_insert(0) += 1;
            violation_messages.push(v.to_string());
            if v.is_resource_violation() {
                resource_limit_hit = true;
            }
            if v.is_syscall_violation() {
                syscall_denied = true;
            }
            if matches!(v, PolicyViolation::NetworkDenied { .. }) {
                network_denied = true;
            }
        }

        Self {
            total_violations: log.len(),
            by_category,
            first_violation_ms: log.first_ts_ms(),
            last_violation_ms: log.last_ts_ms(),
            resource_limit_hit,
            syscall_denied,
            network_denied,
            violation_messages,
        }
    }

    /// Returns `true` if the run was completely clean (no violations).
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.total_violations == 0
    }

    /// Returns the count for a specific category, or 0 if none recorded.
    #[must_use]
    pub fn count_for(&self, category: &str) -> usize {
        self.by_category.get(category).copied().unwrap_or(0)
    }
}

// ─── PolicyEnforcer ───────────────────────────────────────────────────────────

/// Runtime enforcer that checks events against a `SandboxPolicy` and records
/// any violations in an internal `ViolationLog`.
#[derive(Debug)]
pub struct PolicyEnforcer {
    policy: SandboxPolicy,
    log: ViolationLog,
    memory_used_mb: u64,
    disk_used_mb: u64,
    process_count: u32,
}

impl PolicyEnforcer {
    /// Create a new enforcer wrapping the given policy.
    #[must_use]
    pub const fn new(policy: SandboxPolicy) -> Self {
        Self {
            policy,
            log: ViolationLog::new(),
            memory_used_mb: 0,
            disk_used_mb: 0,
            process_count: 0,
        }
    }

    /// Access the underlying policy.
    #[must_use]
    pub const fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Access the violation log accumulated so far.
    #[must_use]
    pub const fn log(&self) -> &ViolationLog {
        &self.log
    }

    /// Consume the enforcer and return the violation log.
    #[must_use]
    pub fn into_log(self) -> ViolationLog {
        self.log
    }

    /// Check whether a syscall is permitted.
    ///
    /// Returns `Ok(())` if the syscall is allowed, or records a `SyscallDenied`
    /// violation and returns `Err` if it is blocked.
    ///
    /// # Errors
    /// Returns [`PolicyViolation::SyscallDenied`] if the syscall is not permitted.
    pub fn check_syscall(
        &mut self,
        syscall: SyscallId,
        pid: u32,
        ts_ms: u64,
    ) -> Result<(), PolicyViolation> {
        if !self.policy.is_syscall_allowed(syscall.number) {
            let v = PolicyViolation::SyscallDenied {
                syscall,
                pid,
                ts_ms,
            };
            self.log.record(v.clone());
            return Err(v);
        }
        Ok(())
    }

    /// Check whether a network connection to `target` is permitted.
    ///
    /// Records a `NetworkDenied` violation and returns `Err` if blocked.
    ///
    /// # Errors
    /// Returns [`PolicyViolation::NetworkDenied`] if the target is not allowed.
    pub fn check_network(
        &mut self,
        target: &str,
        pid: u32,
        ts_ms: u64,
    ) -> Result<(), PolicyViolation> {
        if !self.policy.is_network_target_allowed(target) {
            let v = PolicyViolation::NetworkDenied {
                target: target.to_string(),
                pid,
                ts_ms,
            };
            self.log.record(v.clone());
            return Err(v);
        }
        Ok(())
    }

    /// Check current resource usage against policy limits.
    ///
    /// Pass the current memory (MB), disk-write (MB), elapsed (secs), and
    /// process count.  All violations are recorded; the first one encountered is
    /// returned as `Err` if any limit is exceeded.
    ///
    /// # Errors
    /// Returns the first [`PolicyViolation`] encountered if any limit is exceeded.
    pub fn check_resource(
        &mut self,
        memory_mb: u64,
        disk_mb: u64,
        elapsed_secs: u64,
        processes: u32,
        ts_ms: u64,
    ) -> Result<(), PolicyViolation> {
        self.memory_used_mb = memory_mb;
        self.disk_used_mb = disk_mb;
        self.process_count = processes;

        let mut first_err: Option<PolicyViolation> = None;

        if memory_mb > self.policy.max_memory_mb {
            let v = PolicyViolation::MemoryExceeded {
                used_mb: memory_mb,
                limit_mb: self.policy.max_memory_mb,
                ts_ms,
            };
            self.log.record(v.clone());
            first_err.get_or_insert(v);
        }

        if disk_mb > self.policy.max_disk_mb {
            let v = PolicyViolation::DiskExceeded {
                used_mb: disk_mb,
                limit_mb: self.policy.max_disk_mb,
                ts_ms,
            };
            self.log.record(v.clone());
            first_err.get_or_insert(v);
        }

        if elapsed_secs > self.policy.max_run_seconds {
            let v = PolicyViolation::TimeExceeded {
                elapsed_secs,
                limit_secs: self.policy.max_run_seconds,
                ts_ms,
            };
            self.log.record(v.clone());
            first_err.get_or_insert(v);
        }

        if processes > self.policy.max_processes {
            let v = PolicyViolation::ProcessLimitExceeded {
                count: processes,
                limit: self.policy.max_processes,
                ts_ms,
            };
            self.log.record(v.clone());
            first_err.get_or_insert(v);
        }

        first_err.map_or(Ok(()), Err)
    }

    /// Generate a `PolicyReport` from the violations recorded so far.
    #[must_use]
    pub fn report(&self) -> PolicyReport {
        PolicyReport::from_log(&self.log)
    }

    /// Reset all runtime counters and clear the violation log.
    pub fn reset(&mut self) {
        self.log.clear();
        self.memory_used_mb = 0;
        self.disk_used_mb = 0;
        self.process_count = 0;
    }

    /// Current snapshot of tracked memory usage.
    #[must_use]
    pub const fn memory_used_mb(&self) -> u64 {
        self.memory_used_mb
    }

    /// Current snapshot of tracked disk usage.
    #[must_use]
    pub const fn disk_used_mb(&self) -> u64 {
        self.disk_used_mb
    }

    /// Current snapshot of tracked process count.
    #[must_use]
    pub const fn process_count(&self) -> u32 {
        self.process_count
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn sc(n: u32, name: &str) -> SyscallId {
        SyscallId::new(n, name)
    }

    fn strict_enforcer() -> PolicyEnforcer {
        PolicyEnforcer::new(PolicyPreset::Strict.to_policy())
    }

    fn windows_enforcer() -> PolicyEnforcer {
        PolicyEnforcer::new(PolicyPreset::WindowsMalware.to_policy())
    }

    // ── SyscallId ────────────────────────────────────────────────────────────

    #[test]
    fn test_syscall_id_display() {
        let s = SyscallId::new(42, "NtCreateFile");
        assert!(s.to_string().contains("NtCreateFile"));
        assert!(s.to_string().contains("42"));
    }

    #[test]
    fn test_syscall_id_equality() {
        let a = SyscallId::nt(7, "NtClose");
        let b = SyscallId::linux(7, "NtClose");
        assert_eq!(a, b); // same number and name
    }

    // ── NetworkMode ──────────────────────────────────────────────────────────

    #[test]
    fn test_network_mode_display() {
        assert_eq!(NetworkMode::Isolated.to_string(), "isolated");
        assert_eq!(NetworkMode::HostNetwork.to_string(), "host_network");
        assert_eq!(
            NetworkMode::SimulatedNetwork.to_string(),
            "simulated_network"
        );
        assert_eq!(NetworkMode::Filtered.to_string(), "filtered");
    }

    #[test]
    fn test_network_mode_default_is_isolated() {
        assert_eq!(NetworkMode::default(), NetworkMode::Isolated);
    }

    // ── SandboxPolicy validation ──────────────────────────────────────────────

    #[test]
    fn test_policy_validate_ok() {
        let p = PolicyPreset::Standard.to_policy();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_policy_validate_zero_timeout() {
        let mut p = PolicyPreset::Standard.to_policy();
        p.max_run_seconds = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_policy_validate_zero_memory() {
        let mut p = PolicyPreset::Standard.to_policy();
        p.max_memory_mb = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_policy_validate_conflict() {
        let mut p = PolicyPreset::Strict.to_policy();
        // artificially add the same syscall to both lists
        p.denied_syscalls.push(SyscallId::nt(0, "NtReadFile"));
        assert!(p.validate().is_err());
    }

    // ── SandboxPolicy allow/deny logic ────────────────────────────────────────

    #[test]
    fn test_policy_deny_overrides_allow() {
        let mut p = PolicyPreset::Permissive.to_policy();
        p.denied_syscalls.push(sc(99, "BadCall"));
        assert!(!p.is_syscall_allowed(99));
    }

    #[test]
    fn test_policy_empty_allow_list_permits_all_non_denied() {
        let p = PolicyPreset::Permissive.to_policy();
        // allow list is empty → any syscall not explicitly denied should pass
        assert!(p.is_syscall_allowed(9999));
    }

    #[test]
    fn test_policy_network_isolated() {
        let p = PolicyPreset::Strict.to_policy();
        assert!(!p.is_network_target_allowed("1.2.3.4"));
        assert!(!p.is_network_target_allowed("google.com"));
    }

    #[test]
    fn test_policy_network_host_allows_all() {
        let p = PolicyPreset::Permissive.to_policy();
        assert!(p.is_network_target_allowed("192.168.1.1"));
        assert!(p.is_network_target_allowed("evil.com"));
    }

    #[test]
    fn test_policy_network_filtered_ip_match() {
        let p = PolicyBuilder::new()
            .network_mode(NetworkMode::Filtered)
            .allow_ip("10.0.0.1")
            .max_run_seconds(60)
            .max_memory_mb(256)
            .build();
        assert!(p.is_network_target_allowed("10.0.0.1"));
        assert!(!p.is_network_target_allowed("10.0.0.2"));
    }

    #[test]
    fn test_policy_network_filtered_domain_and_subdomain() {
        let p = PolicyBuilder::new()
            .network_mode(NetworkMode::Filtered)
            .allow_domain("example.com")
            .max_run_seconds(60)
            .max_memory_mb(256)
            .build();
        assert!(p.is_network_target_allowed("example.com"));
        assert!(p.is_network_target_allowed("sub.example.com"));
        assert!(!p.is_network_target_allowed("notexample.com"));
    }

    // ── PolicyBuilder ─────────────────────────────────────────────────────────

    #[test]
    fn test_builder_defaults() {
        let p = PolicyBuilder::new().build();
        assert!(p.max_run_seconds > 0);
        assert!(p.max_memory_mb > 0);
    }

    #[test]
    fn test_builder_overrides() {
        let p = PolicyBuilder::new()
            .max_memory_mb(128)
            .max_run_seconds(10)
            .allow_file_write(false)
            .drop_privileges(true)
            .build();
        assert_eq!(p.max_memory_mb, 128);
        assert_eq!(p.max_run_seconds, 10);
        assert!(!p.allow_file_write);
        assert!(p.drop_privileges);
    }

    #[test]
    fn test_builder_from_preset_inherits_syscalls() {
        let p = PolicyBuilder::from_preset(&PolicyPreset::LinuxMalware)
            .max_memory_mb(1024)
            .build();
        assert!(!p.allowed_syscalls.is_empty());
        assert_eq!(p.max_memory_mb, 1024);
    }

    #[test]
    fn test_builder_chained_allow_deny() {
        let p = PolicyBuilder::new()
            .allow_syscall(sc(1, "write"))
            .deny_syscall(sc(99, "bad_call"))
            .max_run_seconds(30)
            .max_memory_mb(64)
            .build();
        assert_eq!(p.allowed_syscalls.len(), 1);
        assert_eq!(p.denied_syscalls.len(), 1);
    }

    // ── PolicyPreset ─────────────────────────────────────────────────────────

    #[test]
    fn test_preset_strict_no_file_write() {
        let p = PolicyPreset::Strict.to_policy();
        assert!(!p.allow_file_write);
        assert!(!p.allow_registry_write);
        assert_eq!(p.network_mode, NetworkMode::Isolated);
    }

    #[test]
    fn test_preset_windows_malware_allows_registry() {
        let p = PolicyPreset::WindowsMalware.to_policy();
        assert!(p.allow_registry_write);
        assert_eq!(p.network_mode, NetworkMode::SimulatedNetwork);
    }

    #[test]
    fn test_preset_linux_malware_has_linux_syscalls() {
        let p = PolicyPreset::LinuxMalware.to_policy();
        assert!(p.allowed_syscalls.iter().any(|s| s.name == "read"));
        assert!(p.allowed_syscalls.iter().any(|s| s.name == "execve"));
    }

    #[test]
    fn test_preset_android_has_ioctl() {
        let p = PolicyPreset::AndroidApp.to_policy();
        assert!(p.allowed_syscalls.iter().any(|s| s.name == "ioctl"));
    }

    #[test]
    fn test_preset_display() {
        assert_eq!(PolicyPreset::WindowsMalware.to_string(), "windows_malware");
        assert_eq!(PolicyPreset::AndroidApp.to_string(), "android_app");
    }

    // ── PolicyViolation ───────────────────────────────────────────────────────

    #[test]
    fn test_violation_category_labels() {
        let v = PolicyViolation::SyscallDenied {
            syscall: sc(1, "X"),
            pid: 1,
            ts_ms: 0,
        };
        assert_eq!(v.category(), "syscall_denied");
        let v = PolicyViolation::NetworkDenied {
            target: "x".into(),
            pid: 1,
            ts_ms: 0,
        };
        assert_eq!(v.category(), "network_denied");
        let v = PolicyViolation::MemoryExceeded {
            used_mb: 1,
            limit_mb: 0,
            ts_ms: 0,
        };
        assert_eq!(v.category(), "memory_exceeded");
    }

    #[test]
    fn test_violation_is_resource() {
        let v = PolicyViolation::MemoryExceeded {
            used_mb: 512,
            limit_mb: 256,
            ts_ms: 1,
        };
        assert!(v.is_resource_violation());
        assert!(!v.is_syscall_violation());
    }

    #[test]
    fn test_violation_display_contains_key_info() {
        let v = PolicyViolation::SyscallDenied {
            syscall: sc(42, "NtLoadDriver"),
            pid: 1234,
            ts_ms: 999,
        };
        let s = v.to_string();
        assert!(s.contains("NtLoadDriver"));
        assert!(s.contains("1234"));
    }

    // ── ViolationLog ─────────────────────────────────────────────────────────

    #[test]
    fn test_violation_log_empty() {
        let log = ViolationLog::new();
        assert!(log.is_empty());
        assert!(log.first_ts_ms().is_none());
    }

    #[test]
    fn test_violation_log_records_and_queries() {
        let mut log = ViolationLog::new();
        log.record(PolicyViolation::NetworkDenied {
            target: "evil.com".into(),
            pid: 1,
            ts_ms: 100,
        });
        log.record(PolicyViolation::SyscallDenied {
            syscall: sc(5, "X"),
            pid: 2,
            ts_ms: 200,
        });
        assert_eq!(log.len(), 2);
        assert_eq!(log.by_category("network_denied").len(), 1);
        assert_eq!(log.by_category("syscall_denied").len(), 1);
        assert_eq!(log.first_ts_ms(), Some(100));
        assert_eq!(log.last_ts_ms(), Some(200));
    }

    #[test]
    fn test_violation_log_clear() {
        let mut log = ViolationLog::new();
        log.record(PolicyViolation::NetworkDenied {
            target: "x".into(),
            pid: 1,
            ts_ms: 1,
        });
        log.clear();
        assert!(log.is_empty());
    }

    // ── PolicyReport ─────────────────────────────────────────────────────────

    #[test]
    fn test_report_clean_when_no_violations() {
        let log = ViolationLog::new();
        let report = PolicyReport::from_log(&log);
        assert!(report.is_clean());
        assert_eq!(report.total_violations, 0);
    }

    #[test]
    fn test_report_counts_categories() {
        let mut log = ViolationLog::new();
        log.record(PolicyViolation::SyscallDenied {
            syscall: sc(1, "A"),
            pid: 1,
            ts_ms: 1,
        });
        log.record(PolicyViolation::SyscallDenied {
            syscall: sc(2, "B"),
            pid: 1,
            ts_ms: 2,
        });
        log.record(PolicyViolation::NetworkDenied {
            target: "x".into(),
            pid: 1,
            ts_ms: 3,
        });
        let report = PolicyReport::from_log(&log);
        assert_eq!(report.count_for("syscall_denied"), 2);
        assert_eq!(report.count_for("network_denied"), 1);
        assert!(report.syscall_denied);
        assert!(report.network_denied);
        assert!(!report.resource_limit_hit);
    }

    #[test]
    fn test_report_resource_flag() {
        let mut log = ViolationLog::new();
        log.record(PolicyViolation::MemoryExceeded {
            used_mb: 1000,
            limit_mb: 512,
            ts_ms: 50,
        });
        let report = PolicyReport::from_log(&log);
        assert!(report.resource_limit_hit);
        assert!(!report.is_clean());
    }

    // ── PolicyEnforcer ────────────────────────────────────────────────────────

    #[test]
    fn test_enforcer_allows_permitted_syscall() {
        let mut e = windows_enforcer();
        // NtReadFile (number 0) is in the WindowsMalware allow list
        assert!(e.check_syscall(sc(0, "NtReadFile"), 100, 0).is_ok());
        assert!(e.log().is_empty());
    }

    #[test]
    fn test_enforcer_denies_blocked_syscall() {
        let mut e = strict_enforcer();
        // NtCreateProcess (100) is on the strict deny list
        let result = e.check_syscall(sc(100, "NtCreateProcess"), 1, 50);
        assert!(result.is_err());
        assert_eq!(e.log().len(), 1);
    }

    #[test]
    fn test_enforcer_network_isolated_always_denied() {
        let mut e = strict_enforcer();
        assert!(e.check_network("1.2.3.4", 1, 0).is_err());
        assert_eq!(e.log().by_category("network_denied").len(), 1);
    }

    #[test]
    fn test_enforcer_resource_all_within_limits() {
        let mut e = windows_enforcer();
        assert!(e.check_resource(100, 10, 60, 4, 1000).is_ok());
        assert!(e.log().is_empty());
    }

    #[test]
    fn test_enforcer_resource_memory_exceeded() {
        let mut e = windows_enforcer();
        let limit = e.policy().max_memory_mb;
        assert!(e.check_resource(limit + 1, 0, 0, 1, 0).is_err());
        assert_eq!(e.log().by_category("memory_exceeded").len(), 1);
    }

    #[test]
    fn test_enforcer_resource_time_exceeded() {
        let mut e = windows_enforcer();
        let limit = e.policy().max_run_seconds;
        assert!(e.check_resource(0, 0, limit + 1, 1, 9999).is_err());
        assert_eq!(e.log().by_category("time_exceeded").len(), 1);
    }

    #[test]
    fn test_enforcer_multiple_resource_violations_all_recorded() {
        let mut e = windows_enforcer();
        let mem_limit = e.policy().max_memory_mb;
        let disk_limit = e.policy().max_disk_mb;
        // Exceed both memory and disk simultaneously
        let _ = e.check_resource(mem_limit + 1, disk_limit + 1, 0, 1, 0);
        assert!(e.log().len() >= 2);
    }

    #[test]
    fn test_enforcer_reset_clears_log_and_counters() {
        let mut e = strict_enforcer();
        let _ = e.check_network("8.8.8.8", 1, 0);
        assert!(!e.log().is_empty());
        e.reset();
        assert!(e.log().is_empty());
        assert_eq!(e.memory_used_mb(), 0);
        assert_eq!(e.disk_used_mb(), 0);
        assert_eq!(e.process_count(), 0);
    }

    #[test]
    fn test_enforcer_report_reflects_log() {
        let mut e = strict_enforcer();
        let _ = e.check_syscall(sc(100, "NtCreateProcess"), 1, 10);
        let _ = e.check_network("1.1.1.1", 1, 20);
        let report = e.report();
        assert!(!report.is_clean());
        assert!(report.syscall_denied);
        assert!(report.network_denied);
    }

    #[test]
    fn test_enforcer_into_log_transfers_ownership() {
        let mut e = strict_enforcer();
        let _ = e.check_network("x", 1, 0);
        let log = e.into_log();
        assert_eq!(log.len(), 1);
    }
}
