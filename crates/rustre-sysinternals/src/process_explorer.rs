//! `process_explorer` — ProcessExplorer-equivalent
//!
//! Process tree, loaded DLLs, open handles, thread list, performance counters,
//! parent-child tracking, security token info, privilege enumeration.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{
    ModuleInfo, ProcessInfo, ProcessTree, SysinternalsError, ThreadInfo, ThreadState,
};

// ─── PrivilegeState ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivilegeState {
    Disabled,
    Enabled,
    EnabledByDefault,
    Removed,
}

impl fmt::Display for PrivilegeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "Disabled"),
            Self::Enabled => write!(f, "Enabled"),
            Self::EnabledByDefault => write!(f, "EnabledByDefault"),
            Self::Removed => write!(f, "Removed"),
        }
    }
}

// ─── TokenPrivilege ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPrivilege {
    pub name: String,
    pub display_name: String,
    pub state: PrivilegeState,
    pub luid_low: u32,
    pub luid_high: u32,
}

impl TokenPrivilege {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        state: PrivilegeState,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            state,
            luid_low: 0,
            luid_high: 0,
        }
    }

    #[must_use]
    pub fn is_dangerous(&self) -> bool {
        const DANGEROUS: &[&str] = &[
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeLoadDriverPrivilege",
            "SeTcbPrivilege",
            "SeCreateTokenPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
        ];
        DANGEROUS.iter().any(|&d| self.name == d)
    }
}

// ─── TokenIntegrityLevel ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TokenIntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    MediumPlus = 3,
    High = 4,
    System = 5,
    Protected = 6,
}

impl fmt::Display for TokenIntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::MediumPlus => write!(f, "MediumPlus"),
            Self::High => write!(f, "High"),
            Self::System => write!(f, "System"),
            Self::Protected => write!(f, "Protected"),
        }
    }
}

// ─── TokenType ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    Primary,
    Impersonation,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => write!(f, "Primary"),
            Self::Impersonation => write!(f, "Impersonation"),
        }
    }
}

// ─── SecurityTokenInfo ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTokenInfo {
    /// Process/thread owner user.
    pub user: String,
    /// Domain (Windows) or empty.
    pub domain: String,
    /// SID string representation.
    pub sid: String,
    /// Token type.
    pub token_type: TokenType,
    /// Integrity level.
    pub integrity_level: TokenIntegrityLevel,
    /// Whether running elevated.
    pub elevated: bool,
    /// All privileges with their state.
    pub privileges: Vec<TokenPrivilege>,
    /// Group SIDs.
    pub groups: Vec<String>,
    /// Session ID.
    pub session_id: u32,
    /// Token source (e.g. "User32" or "Advapi").
    pub token_source: String,
}

impl SecurityTokenInfo {
    #[must_use]
    pub fn new(user: impl Into<String>, domain: impl Into<String>, sid: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            domain: domain.into(),
            sid: sid.into(),
            token_type: TokenType::Primary,
            integrity_level: TokenIntegrityLevel::Medium,
            elevated: false,
            privileges: Vec::new(),
            groups: Vec::new(),
            session_id: 0,
            token_source: String::new(),
        }
    }

    /// Return only enabled/dangerous privileges.
    #[must_use]
    pub fn dangerous_privileges(&self) -> Vec<&TokenPrivilege> {
        self.privileges
            .iter()
            .filter(|p| p.is_dangerous() && p.state != PrivilegeState::Disabled)
            .collect()
    }

    /// Count enabled privileges.
    #[must_use]
    pub fn enabled_privilege_count(&self) -> usize {
        self.privileges
            .iter()
            .filter(|p| {
                p.state == PrivilegeState::Enabled
                    || p.state == PrivilegeState::EnabledByDefault
            })
            .count()
    }
}

// ─── ProcessPerformance ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPerformance {
    pub pid: u32,
    /// User-mode CPU time in nanoseconds.
    pub user_time_ns: u64,
    /// Kernel-mode CPU time in nanoseconds.
    pub kernel_time_ns: u64,
    /// Wall-clock elapsed since process start in seconds.
    pub elapsed_secs: u64,
    /// Peak working set in bytes.
    pub peak_working_set: u64,
    /// Current working set in bytes.
    pub working_set: u64,
    /// Private bytes (non-shared committed).
    pub private_bytes: u64,
    /// Page fault count.
    pub page_faults: u64,
    /// I/O read bytes total.
    pub io_read_bytes: u64,
    /// I/O write bytes total.
    pub io_write_bytes: u64,
    /// I/O other bytes total.
    pub io_other_bytes: u64,
    /// GDI object count (Windows).
    pub gdi_objects: u32,
    /// USER object count (Windows).
    pub user_objects: u32,
    /// Number of open handles.
    pub handle_count: u32,
    /// Number of threads.
    pub thread_count: u32,
}

impl ProcessPerformance {
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            ..Default::default()
        }
    }

    #[must_use]
    pub const fn total_cpu_ns(&self) -> u64 {
        self.user_time_ns.saturating_add(self.kernel_time_ns)
    }

    #[must_use]
    pub const fn total_io_bytes(&self) -> u64 {
        self.io_read_bytes
            .saturating_add(self.io_write_bytes)
            .saturating_add(self.io_other_bytes)
    }

    /// CPU time as a pretty string (HH:MM:SS.mmm).
    #[must_use]
    pub fn cpu_time_human(&self) -> String {
        let total_ms = self.total_cpu_ns() / 1_000_000;
        let ms = total_ms % 1000;
        let secs = (total_ms / 1000) % 60;
        let mins = (total_ms / 60_000) % 60;
        let hours = total_ms / 3_600_000;
        format!("{hours:02}:{mins:02}:{secs:02}.{ms:03}")
    }
}

// ─── DllInfo ─────────────────────────────────────────────────────────────────

/// Extended DLL/module info for the process explorer view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub full_path: String,
    pub description: String,
    pub company_name: String,
    pub product_name: String,
    pub file_version: String,
    pub load_count: u32,
    pub is_64bit: bool,
    pub signed: Option<bool>,
    pub sha256: Option<String>,
    /// Exports count (from PE header).
    pub export_count: u32,
    /// Import count (number of imported DLLs).
    pub import_dll_count: u32,
}

impl DllInfo {
    #[must_use]
    pub fn from_module(m: &ModuleInfo) -> Self {
        Self {
            base: m.base,
            size: m.size,
            name: m.name.clone(),
            full_path: m.path.clone(),
            description: String::new(),
            company_name: String::new(),
            product_name: String::new(),
            file_version: String::new(),
            load_count: 1,
            is_64bit: m.is_64bit,
            signed: m.signed,
            sha256: m.hash_sha256.clone(),
            export_count: 0,
            import_dll_count: 0,
        }
    }

    #[must_use]
    pub fn is_suspicious_path(&self) -> bool {
        let lp = self.full_path.to_lowercase();
        lp.contains("\\temp\\")
            || lp.contains("\\tmp\\")
            || lp.contains("\\appdata\\")
            || lp.contains("\\downloads\\")
    }
}

// ─── HandleEntry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandleType {
    File,
    Directory,
    RegistryKey,
    Process,
    Thread,
    Token,
    Event,
    Semaphore,
    Mutex,
    Section,
    NamedPipe,
    Socket,
    Timer,
    Desktop,
    WindowStation,
    Job,
    IoCompletion,
    Unknown,
}

impl fmt::Display for HandleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::File => "File",
            Self::Directory => "Directory",
            Self::RegistryKey => "Key",
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::Token => "Token",
            Self::Event => "Event",
            Self::Semaphore => "Semaphore",
            Self::Mutex => "Mutex",
            Self::Section => "Section",
            Self::NamedPipe => "NamedPipe",
            Self::Socket => "Socket",
            Self::Timer => "Timer",
            Self::Desktop => "Desktop",
            Self::WindowStation => "WindowStation",
            Self::Job => "Job",
            Self::IoCompletion => "IoCompletion",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl HandleType {
    #[must_use]
    pub fn from_type_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "file" => Self::File,
            "directory" => Self::Directory,
            "key" => Self::RegistryKey,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "token" => Self::Token,
            "event" => Self::Event,
            "semaphore" => Self::Semaphore,
            "mutant" | "mutex" => Self::Mutex,
            "section" => Self::Section,
            "socket" => Self::Socket,
            "timer" | "waitabletimer" => Self::Timer,
            "desktop" => Self::Desktop,
            "windowstation" => Self::WindowStation,
            "job" => Self::Job,
            "iocompletionport" | "iocompletion" => Self::IoCompletion,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleEntry {
    pub handle_value: u64,
    pub pid: u32,
    pub handle_type: HandleType,
    pub type_name: String,
    pub name: String,
    pub object_address: u64,
    pub access_mask: u32,
    pub granted_access: String,
    pub attributes: u32,
    /// Reference count of the underlying kernel object.
    pub ref_count: u32,
    /// Whether the handle is inheritable.
    pub inheritable: bool,
    /// Whether the handle is protected from closing.
    pub protect_from_close: bool,
}

impl HandleEntry {
    #[must_use]
    pub fn new(
        handle_value: u64,
        pid: u32,
        type_name: impl Into<String>,
        name: impl Into<String>,
        access_mask: u32,
    ) -> Self {
        let type_name = type_name.into();
        let handle_type = HandleType::from_type_name(&type_name);
        Self {
            handle_value,
            pid,
            handle_type,
            type_name,
            name: name.into(),
            object_address: 0,
            access_mask,
            granted_access: format!("{access_mask:#010x}"),
            attributes: 0,
            ref_count: 1,
            inheritable: false,
            protect_from_close: false,
        }
    }

    /// True if the handle grants write access (bit 1 or well-known mask).
    #[must_use]
    pub const fn has_write_access(&self) -> bool {
        self.access_mask & 0x4000_0000 != 0   // GENERIC_WRITE
            || self.access_mask & 0x0002 != 0   // FILE_WRITE_DATA / etc
            || self.access_mask & 0x0004 != 0   // FILE_APPEND_DATA
    }
}

// ─── ThreadEntry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEntry {
    pub tid: u32,
    pub pid: u32,
    pub start_address: u64,
    pub start_module: String,
    pub start_function: String,
    pub priority: i32,
    pub base_priority: i32,
    pub state: ThreadState,
    pub wait_reason: String,
    pub cpu_time_user_ns: u64,
    pub cpu_time_kernel_ns: u64,
    pub context_switches: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub teb_address: u64,
    pub is_suspended: bool,
}

impl ThreadEntry {
    #[must_use]
    pub fn from_thread_info(t: &ThreadInfo) -> Self {
        Self {
            tid: t.tid,
            pid: t.pid,
            start_address: t.start_address,
            start_module: String::new(),
            start_function: String::new(),
            priority: t.priority,
            base_priority: t.priority,
            state: t.state,
            wait_reason: t.wait_reason.clone(),
            cpu_time_user_ns: 0,
            cpu_time_kernel_ns: 0,
            context_switches: 0,
            stack_base: 0,
            stack_limit: 0,
            teb_address: 0,
            is_suspended: t.state == ThreadState::Waiting,
        }
    }

    #[must_use]
    pub const fn total_cpu_ns(&self) -> u64 {
        self.cpu_time_user_ns.saturating_add(self.cpu_time_kernel_ns)
    }
}

// ─── ProcessDetail ────────────────────────────────────────────────────────────

/// Security mitigation flags for a process, grouped to avoid struct-excessive-bools.
/// Contains ≤ 3 bool fields so it does not itself trigger the lint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityMitigations {
    /// DEP (Data Execution Prevention) enabled.
    pub dep_enabled: bool,
    /// ASLR (Address Space Layout Randomisation) enabled.
    pub aslr_enabled: bool,
    /// CFG (Control Flow Guard) enabled.
    pub cfg_enabled: bool,
}

/// Full process detail view — the `ProcessExplorer` equivalent of all panes combined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub info: ProcessInfo,
    pub token: Option<SecurityTokenInfo>,
    pub performance: ProcessPerformance,
    pub dlls: Vec<DllInfo>,
    pub handles: Vec<HandleEntry>,
    pub threads: Vec<ThreadEntry>,
    /// Full command line including arguments.
    pub command_line: String,
    /// Working directory at process start.
    pub current_directory: String,
    /// Environment variables.
    pub environment: Vec<(String, String)>,
    /// Parent process name (resolved).
    pub parent_name: String,
    /// Whether the process has a known window (GUI).
    pub has_window: bool,
    /// Main window title if GUI.
    pub window_title: String,
    /// Security mitigations (DEP, ASLR, CFG).
    pub mitigations: SecurityMitigations,
    /// Process is in a Job object.
    pub in_job: bool,
    /// Signature verification result.
    pub is_signed: Option<bool>,
    /// Packed (UPX/etc.) heuristic.
    pub possibly_packed: bool,
    /// Creation timestamp (UNIX epoch seconds).
    pub create_time: u64,
}

impl ProcessDetail {
    #[must_use]
    pub fn from_process_info(info: ProcessInfo) -> Self {
        let cmdline = info.cmdline.clone();
        let cwd = info.cwd.clone();
        let env = info.env_vars.clone();
        let pid = info.pid;
        Self {
            info,
            token: None,
            performance: ProcessPerformance::new(pid),
            dlls: Vec::new(),
            handles: Vec::new(),
            threads: Vec::new(),
            command_line: cmdline,
            current_directory: cwd,
            environment: env,
            parent_name: String::new(),
            has_window: false,
            window_title: String::new(),
            mitigations: SecurityMitigations::default(),
            in_job: false,
            is_signed: None,
            possibly_packed: false,
            create_time: 0,
        }
    }

    /// Populate `dlls` from the `info.modules` list.
    pub fn populate_dlls_from_modules(&mut self) {
        self.dlls = self.info.modules.iter().map(DllInfo::from_module).collect();
    }

    /// Populate `threads` from `info.threads`.
    pub fn populate_threads_from_info(&mut self) {
        self.threads = self
            .info
            .threads
            .iter()
            .map(ThreadEntry::from_thread_info)
            .collect();
    }

    /// Return all enabled dangerous privileges.
    #[must_use]
    pub fn dangerous_privileges(&self) -> Vec<&TokenPrivilege> {
        self.token
            .as_ref()
            .map(|t| t.dangerous_privileges())
            .unwrap_or_default()
    }

    /// Return handles of a specific type.
    #[must_use]
    pub fn handles_of_type(&self, ht: HandleType) -> Vec<&HandleEntry> {
        self.handles
            .iter()
            .filter(|h| h.handle_type == ht)
            .collect()
    }

    /// Compute a simple security score 0-100 (higher = more concerning).
    #[must_use]
    pub fn security_score(&self) -> u32 {
        let mut score: u32 = 0;
        if self.token.as_ref().is_some_and(|t| t.elevated) {
            score += 20;
        }
        if self.token.as_ref().is_some_and(|t| t.integrity_level >= TokenIntegrityLevel::High) {
            score += 10;
        }
        let dangerous = u32::try_from(self.dangerous_privileges().len()).unwrap_or(u32::MAX);
        score += (dangerous * 10).min(30);
        if self.is_signed == Some(false) {
            score += 15;
        }
        if self.possibly_packed {
            score += 15;
        }
        score.min(100)
    }
}

// ─── ProcessExplorer ──────────────────────────────────────────────────────────

/// `ProcessExplorer` — high-level API combining all process inspection features.
pub struct ProcessExplorer {
    /// Cache of process details keyed by PID.
    cache: HashMap<u32, ProcessDetail>,
    /// When the cache was last refreshed.
    last_refresh: Option<SystemTime>,
    /// How long before the cache is considered stale.
    refresh_interval: Duration,
}

impl ProcessExplorer {
    #[must_use]
    pub fn new(refresh_interval: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_interval,
        }
    }

    /// True if cache needs refreshing.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.is_none_or(|t| {
            !t.elapsed().is_ok_and(|e| e < self.refresh_interval)
        })
    }

    /// Insert process details into cache (used by platform backends).
    pub fn cache_insert(&mut self, detail: ProcessDetail) {
        self.cache.insert(detail.info.pid, detail);
        self.last_refresh = Some(SystemTime::now());
    }

    /// Retrieve cached detail for a PID.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessDetail> {
        self.cache.get(&pid)
    }

    /// All cached PIDs.
    #[must_use]
    pub fn all_pids(&self) -> Vec<u32> {
        self.cache.keys().copied().collect()
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Build a process tree from all cached processes.
    pub fn process_tree(&self) -> Result<ProcessTree, SysinternalsError> {
        let infos: Vec<ProcessInfo> = self.cache.values().map(|d| d.info.clone()).collect();
        ProcessTree::from_list(&infos)
    }

    /// Find processes with elevated tokens.
    #[must_use]
    pub fn elevated_processes(&self) -> Vec<&ProcessDetail> {
        self.cache
            .values()
            .filter(|d| d.token.as_ref().is_some_and(|t| t.elevated))
            .collect()
    }

    /// Find processes with dangerous privileges enabled.
    #[must_use]
    pub fn processes_with_dangerous_privileges(&self) -> Vec<&ProcessDetail> {
        self.cache
            .values()
            .filter(|d| !d.dangerous_privileges().is_empty())
            .collect()
    }

    /// Find processes with unsigned main executable.
    #[must_use]
    pub fn unsigned_processes(&self) -> Vec<&ProcessDetail> {
        self.cache
            .values()
            .filter(|d| d.is_signed == Some(false))
            .collect()
    }

    /// Find processes where main executable is in a suspicious path.
    #[must_use]
    pub fn suspicious_path_processes(&self) -> Vec<&ProcessDetail> {
        self.cache
            .values()
            .filter(|d| d.info.in_temp_dir())
            .collect()
    }

    /// Top N by memory working set.
    #[must_use]
    pub fn top_by_memory(&self, n: usize) -> Vec<&ProcessDetail> {
        let mut v: Vec<&ProcessDetail> = self.cache.values().collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.performance.working_set));
        v.truncate(n);
        v
    }

    /// Top N by CPU time.
    #[must_use]
    pub fn top_by_cpu(&self, n: usize) -> Vec<&ProcessDetail> {
        let mut v: Vec<&ProcessDetail> = self.cache.values().collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.performance.total_cpu_ns()));
        v.truncate(n);
        v
    }

    /// Render all processes as CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from(
            "PID,Name,User,Elevated,IntegrityLevel,WorkingSet,HandleCount,ThreadCount,Signed,SecurityScore\n",
        );
        let mut entries: Vec<&ProcessDetail> = self.cache.values().collect();
        entries.sort_by_key(|d| d.info.pid);
        for d in entries {
            let user = d.token.as_ref().map_or("", |t| t.user.as_str());
            let elevated = d.token.as_ref().is_some_and(|t| t.elevated);
            let integrity = d
                .token
                .as_ref()
                .map_or(String::new(), |t| t.integrity_level.to_string());
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{}",
                d.info.pid,
                d.info.name,
                user,
                elevated,
                integrity,
                d.performance.working_set,
                d.performance.handle_count,
                d.performance.thread_count,
                d.is_signed
                    .map_or("unknown", |s| if s { "yes" } else { "no" }),
                d.security_score(),
            );
        }
        out
    }
}

// ─── Platform stub: Windows ──────────────────────────────────────────────────

/// Platform-specific process enumeration functions.
/// These return stubs on all platforms; real implementations live in the
/// platform backends that fill `ProcessExplorer::cache_insert`.
pub struct ProcessEnumerator;

impl ProcessEnumerator {
    /// List all running PIDs (stub).
    #[must_use]
    pub const fn list_pids() -> Vec<u32> {
        #[cfg(target_os = "windows")]
        {
            // Real implementation would call CreateToolhelp32Snapshot / Process32First.
            Vec::new()
        }
        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, read /proc directories.
            Vec::new()
        }
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Get process info for a specific PID (stub).
    pub const fn get_process_info(_pid: u32) -> Result<ProcessInfo, SysinternalsError> {
        Err(SysinternalsError::Unsupported)
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Enumerate loaded modules for a PID (stub).
    pub const fn list_modules(_pid: u32) -> Result<Vec<ModuleInfo>, SysinternalsError> {
        Ok(Vec::new())
    }
}

// ─── Privilege name constants ─────────────────────────────────────────────────

pub mod privilege_names {
    pub const SE_CREATE_TOKEN: &str = "SeCreateTokenPrivilege";
    pub const SE_ASSIGN_PRIMARY_TOKEN: &str = "SeAssignPrimaryTokenPrivilege";
    pub const SE_LOCK_MEMORY: &str = "SeLockMemoryPrivilege";
    pub const SE_INCREASE_QUOTA: &str = "SeIncreaseQuotaPrivilege";
    pub const SE_MACHINE_ACCOUNT: &str = "SeMachineAccountPrivilege";
    pub const SE_TCB: &str = "SeTcbPrivilege";
    pub const SE_SECURITY: &str = "SeSecurityPrivilege";
    pub const SE_TAKE_OWNERSHIP: &str = "SeTakeOwnershipPrivilege";
    pub const SE_LOAD_DRIVER: &str = "SeLoadDriverPrivilege";
    pub const SE_SYSTEM_PROFILE: &str = "SeSystemProfilePrivilege";
    pub const SE_SYSTEMTIME: &str = "SeSystemtimePrivilege";
    pub const SE_PROFILE_SINGLE_PROCESS: &str = "SeProfileSingleProcessPrivilege";
    pub const SE_INCREASE_BASE_PRIORITY: &str = "SeIncreaseBasePriorityPrivilege";
    pub const SE_CREATE_PAGEFILE: &str = "SeCreatePagefilePrivilege";
    pub const SE_CREATE_PERMANENT: &str = "SeCreatePermanentPrivilege";
    pub const SE_BACKUP: &str = "SeBackupPrivilege";
    pub const SE_RESTORE: &str = "SeRestorePrivilege";
    pub const SE_SHUTDOWN: &str = "SeShutdownPrivilege";
    pub const SE_DEBUG: &str = "SeDebugPrivilege";
    pub const SE_AUDIT: &str = "SeAuditPrivilege";
    pub const SE_SYSTEM_ENVIRONMENT: &str = "SeSystemEnvironmentPrivilege";
    pub const SE_CHANGE_NOTIFY: &str = "SeChangeNotifyPrivilege";
    pub const SE_REMOTE_SHUTDOWN: &str = "SeRemoteShutdownPrivilege";
    pub const SE_UNDOCK: &str = "SeUndockPrivilege";
    pub const SE_SYNC_AGENT: &str = "SeSyncAgentPrivilege";
    pub const SE_ENABLE_DELEGATION: &str = "SeEnableDelegationPrivilege";
    pub const SE_MANAGE_VOLUME: &str = "SeManageVolumePrivilege";
    pub const SE_IMPERSONATE: &str = "SeImpersonatePrivilege";
    pub const SE_CREATE_GLOBAL: &str = "SeCreateGlobalPrivilege";
    pub const SE_TRUSTED_CREDMAN_ACCESS: &str = "SeTrustedCredManAccessPrivilege";
    pub const SE_RELABEL: &str = "SeRelabelPrivilege";
    pub const SE_INCREASE_WORKING_SET: &str = "SeIncreaseWorkingSetPrivilege";
    pub const SE_TIME_ZONE: &str = "SeTimeZonePrivilege";
    pub const SE_CREATE_SYMBOLIC_LINK: &str = "SeCreateSymbolicLinkPrivilege";
    pub const SE_DELEGATE_SESSION_USER_IMPERSONATE: &str =
        "SeDelegateSessionUserImpersonatePrivilege";
}

// ─── Well-known SIDs ──────────────────────────────────────────────────────────

pub mod well_known_sids {
    pub const EVERYONE: &str = "S-1-1-0";
    pub const SYSTEM: &str = "S-1-5-18";
    pub const LOCAL_SERVICE: &str = "S-1-5-19";
    pub const NETWORK_SERVICE: &str = "S-1-5-20";
    pub const ADMINISTRATORS: &str = "S-1-5-32-544";
    pub const USERS: &str = "S-1-5-32-545";
    pub const GUESTS: &str = "S-1-5-32-546";
    pub const POWER_USERS: &str = "S-1-5-32-547";
    pub const INTERACTIVE: &str = "S-1-5-4";
    pub const NETWORK: &str = "S-1-5-2";
    pub const BATCH: &str = "S-1-5-3";
    pub const SERVICE: &str = "S-1-5-6";
    pub const CREATOR_OWNER: &str = "S-1-3-0";
    pub const CREATOR_GROUP: &str = "S-1-3-1";
    pub const INTEGRITY_UNTRUSTED: &str = "S-1-16-0";
    pub const INTEGRITY_LOW: &str = "S-1-16-4096";
    pub const INTEGRITY_MEDIUM: &str = "S-1-16-8192";
    pub const INTEGRITY_HIGH: &str = "S-1-16-12288";
    pub const INTEGRITY_SYSTEM: &str = "S-1-16-16384";
    pub const INTEGRITY_PROTECTED: &str = "S-1-16-20480";
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessInfo, ThreadState};

    fn make_detail(pid: u32, name: &str) -> ProcessDetail {
        let info = ProcessInfo::new(pid, 0, name);
        ProcessDetail::from_process_info(info)
    }

    #[test]
    fn test_token_privilege_dangerous() {
        let p = TokenPrivilege::new(
            privilege_names::SE_DEBUG,
            "Debug programs",
            PrivilegeState::Enabled,
        );
        assert!(p.is_dangerous());
    }

    #[test]
    fn test_token_privilege_not_dangerous() {
        let p = TokenPrivilege::new(
            privilege_names::SE_CHANGE_NOTIFY,
            "Bypass traverse checking",
            PrivilegeState::EnabledByDefault,
        );
        assert!(!p.is_dangerous());
    }

    #[test]
    fn test_integrity_level_ordering() {
        assert!(TokenIntegrityLevel::High > TokenIntegrityLevel::Medium);
        assert!(TokenIntegrityLevel::System > TokenIntegrityLevel::High);
        assert!(TokenIntegrityLevel::Low < TokenIntegrityLevel::Medium);
    }

    #[test]
    fn test_handle_type_from_name() {
        assert_eq!(HandleType::from_type_name("File"), HandleType::File);
        assert_eq!(HandleType::from_type_name("Mutant"), HandleType::Mutex);
        assert_eq!(HandleType::from_type_name("Key"), HandleType::RegistryKey);
        assert_eq!(HandleType::from_type_name("XYZ"), HandleType::Unknown);
    }

    #[test]
    fn test_handle_entry_write_access() {
        let h = HandleEntry::new(4, 100, "File", "C:\\data.bin", 0x4000_0002);
        assert!(h.has_write_access());
    }

    #[test]
    fn test_process_performance_cpu_time_human() {
        let mut perf = ProcessPerformance::new(1);
        perf.user_time_ns = 3_661_000_000_000; // 1h 1m 1s
        let s = perf.cpu_time_human();
        assert!(s.starts_with("01:01:01"));
    }

    #[test]
    fn test_process_detail_security_score_elevated() {
        let mut d = make_detail(1, "admin.exe");
        let mut tok = SecurityTokenInfo::new("Administrator", "DOMAIN", "S-1-5-...");
        tok.elevated = true;
        tok.integrity_level = TokenIntegrityLevel::High;
        tok.privileges.push(TokenPrivilege::new(
            privilege_names::SE_DEBUG,
            "Debug",
            PrivilegeState::Enabled,
        ));
        d.token = Some(tok);
        let score = d.security_score();
        assert!(score >= 30);
    }

    #[test]
    fn test_process_detail_populate_dlls() {
        use crate::ModuleInfo;
        let mut info = ProcessInfo::new(42, 0, "app.exe");
        info.modules
            .push(ModuleInfo::new(0x0040_0000, 0x10000, "app.exe", "C:\\app.exe"));
        let mut detail = ProcessDetail::from_process_info(info);
        detail.populate_dlls_from_modules();
        assert_eq!(detail.dlls.len(), 1);
        assert_eq!(detail.dlls[0].name, "app.exe");
    }

    #[test]
    fn test_process_explorer_cache_and_retrieve() {
        let mut explorer = ProcessExplorer::new(Duration::from_mins(1));
        let d = make_detail(100, "svchost.exe");
        explorer.cache_insert(d);
        assert!(explorer.get(100).is_some());
        assert!(explorer.get(999).is_none());
    }

    #[test]
    fn test_process_explorer_top_by_memory() {
        let mut explorer = ProcessExplorer::new(Duration::from_mins(1));
        for pid in 1u32..=5 {
            let mut d = make_detail(pid, "proc");
            d.performance.working_set = u64::from(pid) * 1_000_000;
            explorer.cache_insert(d);
        }
        let top = explorer.top_by_memory(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].performance.working_set >= top[1].performance.working_set);
    }

    #[test]
    fn test_process_explorer_csv() {
        let mut explorer = ProcessExplorer::new(Duration::from_mins(1));
        let d = make_detail(42, "test.exe");
        explorer.cache_insert(d);
        let csv = explorer.to_csv();
        assert!(csv.contains("PID"));
        assert!(csv.contains("test.exe"));
    }

    #[test]
    fn test_dll_info_suspicious_path() {
        let m = crate::ModuleInfo::new(0x1000, 0x1000, "evil.dll", "C:\\Temp\\evil.dll");
        let dll = DllInfo::from_module(&m);
        assert!(dll.is_suspicious_path());
    }

    #[test]
    fn test_security_token_dangerous_privileges() {
        let mut tok = SecurityTokenInfo::new("user", "DOMAIN", "S-1-5-...");
        tok.privileges.push(TokenPrivilege::new(
            privilege_names::SE_IMPERSONATE,
            "Impersonate",
            PrivilegeState::Enabled,
        ));
        tok.privileges.push(TokenPrivilege::new(
            privilege_names::SE_CHANGE_NOTIFY,
            "Notify",
            PrivilegeState::EnabledByDefault,
        ));
        assert_eq!(tok.dangerous_privileges().len(), 1);
        assert_eq!(tok.enabled_privilege_count(), 2);
    }

    #[test]
    fn test_thread_entry_from_thread_info() {
        let t = ThreadInfo::new(10, 1, 0x40_1000, 8, ThreadState::Running);
        let entry = ThreadEntry::from_thread_info(&t);
        assert_eq!(entry.tid, 10);
        assert_eq!(entry.start_address, 0x40_1000);
    }
}
