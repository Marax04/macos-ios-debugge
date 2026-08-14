//! Syscall interception layer for the sandbox VM.
//!
//! Intercepts and logs all system calls made by a sandboxed process, classifies
//! them by category, detects suspicious patterns (privilege escalation, anti-debug
//! tricks, network C2 patterns), and enforces a configurable policy engine.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

// ─── SyscallNumber ────────────────────────────────────────────────────────────

/// Raw syscall number (architecture-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyscallNumber(pub u32);

impl fmt::Display for SyscallNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syscall#{}", self.0)
    }
}

// ─── SyscallCategory ──────────────────────────────────────────────────────────

/// High-level classification of a system call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    /// File system operations: open, read, write, unlink, rename, etc.
    FileSystem,
    /// Network operations: socket, connect, bind, send, recv, etc.
    Network,
    /// Process and thread management: fork, exec, clone, kill, wait, etc.
    Process,
    /// Memory management: mmap, mprotect, brk, munmap, etc.
    Memory,
    /// Inter-process communication: pipe, shmget, msgq, futex, etc.
    Ipc,
    /// Privilege / credential changes: setuid, setgid, capset, etc.
    Privilege,
    /// Security and anti-debug: `ptrace`, `prctl`, `seccomp`, etc.
    Security,
    /// Time and clock: gettimeofday, `clock_gettime`, etc.
    Time,
    /// Device and I/O: ioctl, read/write on device fds, etc.
    Device,
    /// Unknown / uncategorised.
    Unknown,
}

impl fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::Memory => write!(f, "memory"),
            Self::Ipc => write!(f, "ipc"),
            Self::Privilege => write!(f, "privilege"),
            Self::Security => write!(f, "security"),
            Self::Time => write!(f, "time"),
            Self::Device => write!(f, "device"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── SyscallArg ───────────────────────────────────────────────────────────────

/// A single argument passed to a syscall, stored as a u64 raw value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallArg(pub u64);

impl SyscallArg {
    /// Interpret the argument as a signed integer.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0.cast_signed()
    }

    /// Interpret the argument as a pointer (same width as u64 on 64-bit).
    #[must_use]
    pub const fn as_ptr(self) -> u64 {
        self.0
    }

    /// Check if the argument is a null pointer.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if argument represents a file descriptor (small non-negative integer).
    #[must_use]
    pub const fn looks_like_fd(self) -> bool {
        self.0 < 65536
    }
}

// ─── SyscallEvent ─────────────────────────────────────────────────────────────

/// Execution context for a single syscall event (process/thread/timing).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallEventContext {
    /// Monotonic event index.
    pub index: u64,
    /// Milliseconds since sandbox execution start.
    pub ts_ms: u64,
    /// PID of the calling process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
}

impl SyscallEventContext {
    /// Construct a context record.
    #[must_use]
    pub const fn new(index: u64, ts_ms: u64, pid: u32, tid: u32) -> Self {
        Self { index, ts_ms, pid, tid }
    }
}

/// A single system call event captured from the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Monotonic event index (unique per interceptor lifetime).
    pub index: u64,
    /// Milliseconds since sandbox execution start.
    pub ts_ms: u64,
    /// PID of the calling process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Raw syscall number.
    pub number: SyscallNumber,
    /// Human-readable syscall name.
    pub name: String,
    /// High-level category.
    pub category: SyscallCategory,
    /// Arguments (up to 6 for most architectures).
    pub args: Vec<SyscallArg>,
    /// Return value from the syscall (post-interception).
    pub retval: Option<i64>,
    /// Whether this call was blocked by policy.
    pub blocked: bool,
    /// Whether this call was flagged as suspicious.
    pub flagged: bool,
    /// Annotation set by the pattern detector.
    pub annotation: Option<String>,
}

impl SyscallEvent {
    /// Create a new syscall event.
    #[must_use]
    pub fn new(
        ctx: SyscallEventContext,
        number: SyscallNumber,
        name: impl Into<String>,
        category: SyscallCategory,
        args: Vec<SyscallArg>,
    ) -> Self {
        Self {
            index: ctx.index,
            ts_ms: ctx.ts_ms,
            pid: ctx.pid,
            tid: ctx.tid,
            number,
            name: name.into(),
            category,
            args,
            retval: None,
            blocked: false,
            flagged: false,
            annotation: None,
        }
    }

    /// Set the return value.
    pub fn set_retval(&mut self, retval: i64) {
        self.retval = Some(retval);
    }

    /// Mark as blocked.
    pub fn block(&mut self, reason: impl Into<String>) {
        self.blocked = true;
        self.annotation = Some(reason.into());
    }

    /// Mark as flagged with a reason.
    pub fn flag(&mut self, reason: impl Into<String>) {
        self.flagged = true;
        self.annotation = Some(reason.into());
    }
}

// ─── SyscallPattern ──────────────────────────────────────────────────────────

/// A suspicious syscall pattern that the interceptor can detect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallPattern {
    /// Attempt to elevate privileges (setuid(0), setgid(0), capset with elevated caps).
    PrivilegeEscalation,
    /// Anti-debug technique via `ptrace(PTRACE_TRACEME)`.
    AntiDebugPtrace,
    /// Disabling seccomp filters or attempting to bypass sandbox.
    SeccompBypass,
    /// Disabling ASLR or stack canaries via prctl.
    PrctlAbuse,
    /// Opening /proc/self/mem for direct memory access (injection).
    ProcSelfMemAccess,
    /// Rapid sequence of mmap+mprotect+exec (shellcode staging).
    ShellcodeStaging,
    /// Network connection to known C2 port ranges.
    C2NetworkPattern,
    /// Spawning new processes during analysis (lateral movement).
    ProcessSpawnAnomaly,
    /// Excessive read of sensitive paths (/etc/shadow, /etc/passwd).
    SensitiveFileAccess,
    /// Large memory allocation (heap spray preparation).
    HeapSpray,
    /// Repeated failed syscalls (fuzzing or anti-sandbox probing).
    SandboxProbe,
    /// Time-of-check to time-of-use race attempt.
    ToctouRace,
    /// Custom named pattern.
    Custom(String),
}

impl fmt::Display for SyscallPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::AntiDebugPtrace => write!(f, "anti_debug_ptrace"),
            Self::SeccompBypass => write!(f, "seccomp_bypass"),
            Self::PrctlAbuse => write!(f, "prctl_abuse"),
            Self::ProcSelfMemAccess => write!(f, "proc_self_mem_access"),
            Self::ShellcodeStaging => write!(f, "shellcode_staging"),
            Self::C2NetworkPattern => write!(f, "c2_network_pattern"),
            Self::ProcessSpawnAnomaly => write!(f, "process_spawn_anomaly"),
            Self::SensitiveFileAccess => write!(f, "sensitive_file_access"),
            Self::HeapSpray => write!(f, "heap_spray"),
            Self::SandboxProbe => write!(f, "sandbox_probe"),
            Self::ToctouRace => write!(f, "toctou_race"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ─── PatternMatch ─────────────────────────────────────────────────────────────

/// Result of pattern detection on a sequence of events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// The pattern that was detected.
    pub pattern: SyscallPattern,
    /// Indices of events that triggered this match.
    pub event_indices: Vec<u64>,
    /// Confidence score [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable explanation.
    pub explanation: String,
}

impl PatternMatch {
    /// Create a new pattern match.
    #[must_use]
    pub fn new(
        pattern: SyscallPattern,
        event_indices: Vec<u64>,
        confidence: f32,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            pattern,
            event_indices,
            confidence,
            explanation: explanation.into(),
        }
    }
}

// ─── PolicyAction ─────────────────────────────────────────────────────────────

/// What the policy engine should do when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyAction {
    /// Allow the syscall to proceed normally.
    #[default]
    Allow,
    /// Block the syscall and return EPERM to the process.
    Block,
    /// Allow but record a warning in the event log.
    AllowWithWarning,
    /// Redirect the syscall (e.g. redirect file open to a decoy path).
    Redirect(String),
    /// Kill the sandboxed process immediately.
    KillProcess,
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Block => write!(f, "block"),
            Self::AllowWithWarning => write!(f, "allow_with_warning"),
            Self::Redirect(s) => write!(f, "redirect:{s}"),
            Self::KillProcess => write!(f, "kill_process"),
        }
    }
}

// ─── PolicyRule ───────────────────────────────────────────────────────────────

/// A single policy rule that matches syscall events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: String,
    /// Description of what this rule enforces.
    pub description: String,
    /// Match on specific syscall names (empty = match any).
    pub syscall_names: Vec<String>,
    /// Match on specific categories (empty = match any).
    pub categories: Vec<SyscallCategory>,
    /// Action to take when the rule matches.
    pub action: PolicyAction,
    /// Priority: higher values are evaluated first.
    pub priority: u32,
    /// Whether the rule is currently active.
    pub enabled: bool,
}

impl PolicyRule {
    /// Create a new policy rule.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        action: PolicyAction,
        priority: u32,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            syscall_names: vec![],
            categories: vec![],
            action,
            priority,
            enabled: true,
        }
    }

    /// Add a syscall name to match.
    #[must_use]
    pub fn matching_syscall(mut self, name: impl Into<String>) -> Self {
        self.syscall_names.push(name.into());
        self
    }

    /// Add a category to match.
    #[must_use]
    pub fn matching_category(mut self, cat: SyscallCategory) -> Self {
        self.categories.push(cat);
        self
    }

    /// Check if this rule matches a given event.
    #[must_use]
    pub fn matches(&self, event: &SyscallEvent) -> bool {
        if !self.enabled {
            return false;
        }
        let name_match = self.syscall_names.is_empty()
            || self.syscall_names.iter().any(|n| n == &event.name);
        let cat_match = self.categories.is_empty()
            || self.categories.contains(&event.category);
        name_match && cat_match
    }
}

// ─── SyscallPolicy ────────────────────────────────────────────────────────────

/// The full policy engine: a sorted collection of rules.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyscallPolicy {
    rules: Vec<PolicyRule>,
    /// Default action when no rule matches.
    pub default_action: PolicyAction,
}

impl SyscallPolicy {
    /// Create a new, empty policy with a default action.
    #[must_use]
    pub fn new(default_action: PolicyAction) -> Self {
        Self {
            rules: vec![],
            default_action,
        }
    }

    /// Create a permissive policy (allow all by default).
    #[must_use]
    pub fn permissive() -> Self {
        Self::new(PolicyAction::Allow)
    }

    /// Create a restrictive policy (block all by default).
    #[must_use]
    pub fn restrictive() -> Self {
        Self::new(PolicyAction::Block)
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluate the policy for a given event, returning the matching action.
    #[must_use]
    pub fn evaluate(&self, event: &SyscallEvent) -> &PolicyAction {
        for rule in &self.rules {
            if rule.matches(event) {
                return &rule.action;
            }
        }
        &self.default_action
    }

    /// Return the number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Build a sensible default sandbox policy.
    #[must_use]
    pub fn default_sandbox() -> Self {
        let mut policy = Self::permissive();
        policy.add_rule(
            PolicyRule::new(
                "block-privilege-escalation",
                "Block setuid/setgid to root",
                PolicyAction::Block,
                100,
            )
            .matching_syscall("setuid")
            .matching_syscall("setgid"),
        );
        policy.add_rule(
            PolicyRule::new(
                "block-ptrace",
                "Block ptrace (anti-debug)",
                PolicyAction::Block,
                90,
            )
            .matching_syscall("ptrace"),
        );
        policy.add_rule(
            PolicyRule::new(
                "warn-network",
                "Warn on outbound network activity",
                PolicyAction::AllowWithWarning,
                50,
            )
            .matching_category(SyscallCategory::Network),
        );
        policy.add_rule(
            PolicyRule::new(
                "warn-exec",
                "Warn on process exec",
                PolicyAction::AllowWithWarning,
                60,
            )
            .matching_syscall("execve")
            .matching_syscall("execveat"),
        );
        policy
    }
}

// ─── InterceptionResult ───────────────────────────────────────────────────────

/// The result returned by the interceptor after processing a syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionResult {
    /// The processed event.
    pub event: SyscallEvent,
    /// The policy action that was applied.
    pub action: PolicyAction,
    /// Any patterns detected as part of this event.
    pub patterns_detected: Vec<PatternMatch>,
}

impl InterceptionResult {
    /// Returns true if the syscall was blocked.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self.action, PolicyAction::Block | PolicyAction::KillProcess)
    }

    /// Returns true if any suspicious pattern was detected.
    #[must_use]
    pub const fn has_detections(&self) -> bool {
        !self.patterns_detected.is_empty()
    }
}

// ─── SyscallNameTable ────────────────────────────────────────────────────────

/// Maps raw syscall numbers to names and categories.
pub struct SyscallNameTable {
    entries: HashMap<u32, (String, SyscallCategory)>,
}

impl SyscallNameTable {
    /// Build the Linux x86-64 syscall table (subset of well-known calls).
    #[must_use]
    fn defs_io_and_memory() -> &'static [(u32, &'static str, SyscallCategory)] {
        &[
            (0, "read", SyscallCategory::FileSystem),
            (1, "write", SyscallCategory::FileSystem),
            (2, "open", SyscallCategory::FileSystem),
            (3, "close", SyscallCategory::FileSystem),
            (4, "stat", SyscallCategory::FileSystem),
            (5, "fstat", SyscallCategory::FileSystem),
            (6, "lstat", SyscallCategory::FileSystem),
            (8, "lseek", SyscallCategory::FileSystem),
            (9, "mmap", SyscallCategory::Memory),
            (10, "mprotect", SyscallCategory::Memory),
            (11, "munmap", SyscallCategory::Memory),
            (12, "brk", SyscallCategory::Memory),
            (13, "rt_sigaction", SyscallCategory::Process),
            (14, "rt_sigprocmask", SyscallCategory::Process),
            (16, "ioctl", SyscallCategory::Device),
            (17, "pread64", SyscallCategory::FileSystem),
            (18, "pwrite64", SyscallCategory::FileSystem),
            (19, "readv", SyscallCategory::FileSystem),
            (20, "writev", SyscallCategory::FileSystem),
            (21, "access", SyscallCategory::FileSystem),
            (22, "pipe", SyscallCategory::Ipc),
            (32, "dup", SyscallCategory::FileSystem),
            (33, "dup2", SyscallCategory::FileSystem),
            (35, "nanosleep", SyscallCategory::Time),
            (38, "setitimer", SyscallCategory::Time),
            (39, "getpid", SyscallCategory::Process),
            (40, "sendfile", SyscallCategory::Network),
            (41, "socket", SyscallCategory::Network),
            (42, "connect", SyscallCategory::Network),
            (43, "accept", SyscallCategory::Network),
            (44, "sendto", SyscallCategory::Network),
            (45, "recvfrom", SyscallCategory::Network),
            (46, "sendmsg", SyscallCategory::Network),
            (47, "recvmsg", SyscallCategory::Network),
            (48, "shutdown", SyscallCategory::Network),
            (49, "bind", SyscallCategory::Network),
            (50, "listen", SyscallCategory::Network),
            (51, "getsockname", SyscallCategory::Network),
            (52, "getpeername", SyscallCategory::Network),
            (53, "socketpair", SyscallCategory::Network),
            (54, "setsockopt", SyscallCategory::Network),
            (55, "getsockopt", SyscallCategory::Network),
        ]
    }

    fn defs_process_and_security() -> &'static [(u32, &'static str, SyscallCategory)] {
        &[
            (56, "clone", SyscallCategory::Process),
            (57, "fork", SyscallCategory::Process),
            (58, "vfork", SyscallCategory::Process),
            (59, "execve", SyscallCategory::Process),
            (60, "exit", SyscallCategory::Process),
            (61, "wait4", SyscallCategory::Process),
            (62, "kill", SyscallCategory::Process),
            (63, "uname", SyscallCategory::Process),
            (64, "semget", SyscallCategory::Ipc),
            (65, "semop", SyscallCategory::Ipc),
            (66, "semctl", SyscallCategory::Ipc),
            (67, "shmdt", SyscallCategory::Ipc),
            (68, "msgget", SyscallCategory::Ipc),
            (69, "msgsnd", SyscallCategory::Ipc),
            (70, "msgrcv", SyscallCategory::Ipc),
            (71, "msgctl", SyscallCategory::Ipc),
            (72, "fcntl", SyscallCategory::FileSystem),
            (73, "flock", SyscallCategory::FileSystem),
            (74, "fsync", SyscallCategory::FileSystem),
            (76, "truncate", SyscallCategory::FileSystem),
            (77, "ftruncate", SyscallCategory::FileSystem),
            (78, "getdents", SyscallCategory::FileSystem),
            (79, "getcwd", SyscallCategory::FileSystem),
            (80, "chdir", SyscallCategory::FileSystem),
            (81, "fchdir", SyscallCategory::FileSystem),
            (82, "rename", SyscallCategory::FileSystem),
            (83, "mkdir", SyscallCategory::FileSystem),
            (84, "rmdir", SyscallCategory::FileSystem),
            (85, "creat", SyscallCategory::FileSystem),
            (86, "link", SyscallCategory::FileSystem),
            (87, "unlink", SyscallCategory::FileSystem),
            (88, "symlink", SyscallCategory::FileSystem),
            (89, "readlink", SyscallCategory::FileSystem),
            (90, "chmod", SyscallCategory::FileSystem),
            (92, "chown", SyscallCategory::Privilege),
            (95, "umask", SyscallCategory::FileSystem),
            (96, "gettimeofday", SyscallCategory::Time),
            (97, "getrlimit", SyscallCategory::Process),
            (98, "getrusage", SyscallCategory::Process),
            (101, "ptrace", SyscallCategory::Security),
            (102, "getuid", SyscallCategory::Privilege),
            (104, "getgid", SyscallCategory::Privilege),
            (105, "setuid", SyscallCategory::Privilege),
            (106, "setgid", SyscallCategory::Privilege),
            (107, "geteuid", SyscallCategory::Privilege),
            (108, "getegid", SyscallCategory::Privilege),
            (110, "getppid", SyscallCategory::Process),
            (111, "getpgrp", SyscallCategory::Process),
            (125, "mprotect", SyscallCategory::Memory),
            (130, "set_tid_address", SyscallCategory::Process),
            (157, "prctl", SyscallCategory::Security),
            (158, "arch_prctl", SyscallCategory::Security),
            (186, "gettid", SyscallCategory::Process),
            (202, "futex", SyscallCategory::Ipc),
            (228, "clock_gettime", SyscallCategory::Time),
            (231, "exit_group", SyscallCategory::Process),
            (257, "openat", SyscallCategory::FileSystem),
            (258, "mkdirat", SyscallCategory::FileSystem),
            (260, "fchownat", SyscallCategory::Privilege),
            (262, "fstatat", SyscallCategory::FileSystem),
            (263, "unlinkat", SyscallCategory::FileSystem),
            (264, "renameat", SyscallCategory::FileSystem),
            (316, "renameat2", SyscallCategory::FileSystem),
            (317, "seccomp", SyscallCategory::Security),
        ]
    }

    #[must_use] 
    pub fn linux_x86_64() -> Self {
        let mut t = Self { entries: HashMap::new() };
        for &(num, name, ref cat) in Self::defs_io_and_memory().iter().chain(Self::defs_process_and_security()) {
            t.entries.insert(num, (name.to_string(), cat.clone()));
        }
        t
    }

    /// Look up a syscall number, returning (name, category).
    #[must_use]
    pub fn lookup(&self, num: SyscallNumber) -> (String, SyscallCategory) {
        self.entries
            .get(&num.0)
            .cloned()
            .unwrap_or_else(|| (format!("unknown_{}", num.0), SyscallCategory::Unknown))
    }
}

// ─── PatternDetector ─────────────────────────────────────────────────────────

/// Stateful pattern detector that analyses a sliding window of events.
pub struct PatternDetector {
    /// Recent events kept for sequence analysis.
    window: Vec<SyscallEvent>,
    /// Maximum number of recent events to keep.
    window_size: usize,
    /// Counter of consecutive failed syscalls (for sandbox probe detection).
    consecutive_failures: u32,
    /// Count of mmap+exec transitions (shellcode staging).
    mmap_exec_count: u32,
    /// Count of network connect calls in a short burst.
    connect_burst: u32,
}

impl PatternDetector {
    /// Create a detector with a default window of 256 events.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: Vec::with_capacity(256),
            window_size: 256,
            consecutive_failures: 0,
            mmap_exec_count: 0,
            connect_burst: 0,
        }
    }

    /// Push an event and run pattern detection. Returns any matches found.
    pub fn process(&mut self, event: &SyscallEvent) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        self.update_counters(event);

        // --- Privilege escalation ---
        if matches!(event.category, SyscallCategory::Privilege)
            && (event.name == "setuid" || event.name == "setgid")
            && let Some(arg) = event.args.first()
            && arg.0 == 0
        {
            matches.push(PatternMatch::new(
                SyscallPattern::PrivilegeEscalation,
                vec![event.index],
                0.95,
                format!("{} called with uid/gid=0", event.name),
            ));
        }

        // --- Anti-debug ptrace ---
        if event.name == "ptrace"
            && let Some(first_arg) = event.args.first()
            && first_arg.0 == 0
        {
            // PTRACE_TRACEME = 0
            matches.push(PatternMatch::new(
                SyscallPattern::AntiDebugPtrace,
                vec![event.index],
                0.90,
                "ptrace(PTRACE_TRACEME) called — anti-debug trick",
            ));
        }

        // --- Seccomp bypass ---
        if event.name == "prctl"
            && let Some(first_arg) = event.args.first()
            && first_arg.0 == 22
        {
            // PR_SET_SECCOMP = 22
            matches.push(PatternMatch::new(
                SyscallPattern::SeccompBypass,
                vec![event.index],
                0.75,
                "prctl(PR_SET_SECCOMP) — possible seccomp bypass or disable",
            ));
        }

        // --- Shellcode staging (mmap + mprotect with PROT_EXEC) ---
        // PROT_EXEC = 4; arg index 2 for both mmap and mprotect
        if (event.name == "mmap" || event.name == "mprotect")
            && let Some(prot) = event.args.get(2)
            && prot.0 & 4 != 0
        {
            self.mmap_exec_count += 1;
            if self.mmap_exec_count >= 3 {
                let recent: Vec<u64> = self.window.iter().rev().take(3).map(|e| e.index).collect();
                matches.push(PatternMatch::new(
                    SyscallPattern::ShellcodeStaging,
                    recent,
                    0.80,
                    format!("{} with EXEC bit (count={})", event.name, self.mmap_exec_count),
                ));
            }
        }

        // --- C2 network pattern: connect to high ephemeral port ---
        if event.name == "connect" {
            self.connect_burst += 1;
            if self.connect_burst >= 5 {
                let recent: Vec<u64> = self.window.iter().rev().take(5).map(|e| e.index).collect();
                matches.push(PatternMatch::new(
                    SyscallPattern::C2NetworkPattern,
                    recent,
                    0.70,
                    format!("rapid connect burst ({} calls)", self.connect_burst),
                ));
            }
        }

        // --- Sandbox probing: many consecutive failing syscalls ---
        if self.consecutive_failures >= 10 {
            let recent: Vec<u64> = self.window.iter().rev().take(10).map(|e| e.index).collect();
            matches.push(PatternMatch::new(
                SyscallPattern::SandboxProbe,
                recent,
                0.65,
                format!("{} consecutive failed syscalls", self.consecutive_failures),
            ));
            self.consecutive_failures = 0;
        }

        // Push to window.
        self.window.push(event.clone());
        if self.window.len() > self.window_size {
            self.window.remove(0);
        }

        matches
    }

    fn update_counters(&mut self, event: &SyscallEvent) {
        if let Some(rv) = event.retval {
            if rv < 0 {
                self.consecutive_failures += 1;
            } else {
                self.consecutive_failures = 0;
            }
        }
        // Decay burst counter every 20 events
        if self.window.len().is_multiple_of(20) {
            self.connect_burst = self.connect_burst.saturating_sub(1);
        }
    }

    /// Reset all stateful counters.
    pub fn reset(&mut self) {
        self.window.clear();
        self.consecutive_failures = 0;
        self.mmap_exec_count = 0;
        self.connect_burst = 0;
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SyscallInterceptor ───────────────────────────────────────────────────────

/// The main syscall interception layer.
///
/// Maintains a log of all syscall events, applies the policy, and detects
/// suspicious patterns.
pub struct SyscallInterceptor {
    /// Syscall name/category lookup table.
    name_table: SyscallNameTable,
    /// Policy engine.
    policy: RwLock<SyscallPolicy>,
    /// Pattern detector (stateful).
    detector: Mutex<PatternDetector>,
    /// All captured events.
    event_log: Mutex<Vec<SyscallEvent>>,
    /// All pattern matches detected.
    pattern_log: Mutex<Vec<PatternMatch>>,
    /// Monotonic event counter.
    counter: AtomicU64,
}

impl SyscallInterceptor {
    /// Create a new interceptor with the given policy.
    #[must_use]
    pub fn new(policy: SyscallPolicy) -> Self {
        Self {
            name_table: SyscallNameTable::linux_x86_64(),
            policy: RwLock::new(policy),
            detector: Mutex::new(PatternDetector::new()),
            event_log: Mutex::new(Vec::new()),
            pattern_log: Mutex::new(Vec::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// Create an interceptor with the default sandbox policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(SyscallPolicy::default_sandbox())
    }

    /// Intercept a syscall at entry point (before it executes).
    ///
    /// Returns the `InterceptionResult` so the caller can decide whether to
    /// allow or block the call.
    pub fn intercept(
        &self,
        ts_ms: u64,
        pid: u32,
        tid: u32,
        number: SyscallNumber,
        args: Vec<SyscallArg>,
    ) -> InterceptionResult {
        let index = self.counter.fetch_add(1, Ordering::Relaxed);
        let (name, category) = self.name_table.lookup(number);

        let ctx = SyscallEventContext::new(index, ts_ms, pid, tid);
        let mut event = SyscallEvent::new(ctx, number, name, category, args);

        // Evaluate policy.
        let action = {
            let policy = self.policy.read();
            policy.evaluate(&event).clone()
        };

        if action == PolicyAction::Block || action == PolicyAction::KillProcess {
            event.block(format!("blocked by policy: {action}"));
        } else if action == PolicyAction::AllowWithWarning {
            event.flag("policy warning");
        }

        // Run pattern detector.
        let patterns = self.detector.lock().process(&event);
        if !patterns.is_empty() {
            if !event.flagged {
                event.flag(format!("{} patterns detected", patterns.len()));
            }
            self.pattern_log.lock().extend(patterns.clone());
        }

        // Log the event.
        self.event_log.lock().push(event.clone());

        InterceptionResult {
            event,
            action,
            patterns_detected: patterns,
        }
    }

    /// Record the return value for the most recent event from the given (pid, tid).
    pub fn record_return(&self, pid: u32, tid: u32, retval: i64) {
        if let Some(ev) = self.event_log.lock().iter_mut().rev().find(|e| e.pid == pid && e.tid == tid) {
            ev.retval = Some(retval);
        }
    }

    /// Return a snapshot of all captured events.
    #[must_use]
    pub fn events(&self) -> Vec<SyscallEvent> {
        self.event_log.lock().clone()
    }

    /// Return all detected patterns.
    #[must_use]
    pub fn patterns(&self) -> Vec<PatternMatch> {
        self.pattern_log.lock().clone()
    }

    /// Return counts of events per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, u64> {
        let log = self.event_log.lock();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for ev in log.iter() {
            *counts.entry(ev.category.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Return all blocked events.
    #[must_use]
    pub fn blocked_events(&self) -> Vec<SyscallEvent> {
        self.event_log.lock().iter().filter(|e| e.blocked).cloned().collect()
    }

    /// Return all flagged events.
    #[must_use]
    pub fn flagged_events(&self) -> Vec<SyscallEvent> {
        self.event_log.lock().iter().filter(|e| e.flagged).cloned().collect()
    }

    /// Total number of intercepted calls.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Replace the current policy.
    pub fn set_policy(&self, policy: SyscallPolicy) {
        *self.policy.write() = policy;
    }

    /// Reset the interceptor (clear logs and counters).
    pub fn reset(&self) {
        self.event_log.lock().clear();
        self.pattern_log.lock().clear();
        self.detector.lock().reset();
        self.counter.store(0, Ordering::Relaxed);
    }
}

/// A shared, arc-wrapped interceptor for use across async tasks.
pub type SharedInterceptor = Arc<SyscallInterceptor>;

/// Create a new shared interceptor with the default sandbox policy.
#[must_use]
pub fn new_shared_interceptor() -> SharedInterceptor {
    Arc::new(SyscallInterceptor::with_default_policy())
}

// ─── SyscallStats ─────────────────────────────────────────────────────────────

/// Aggregate statistics derived from the interceptor log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallStats {
    pub total_calls: u64,
    pub blocked_calls: u64,
    pub flagged_calls: u64,
    pub pattern_matches: u64,
    pub category_breakdown: HashMap<String, u64>,
    pub top_syscalls: Vec<(String, u64)>,
}

impl SyscallStats {
    /// Compute stats from an interceptor.
    #[must_use]
    pub fn compute(interceptor: &SyscallInterceptor) -> Self {
        let events = interceptor.events();
        let total_calls = events.len() as u64;
        let blocked_calls = events.iter().filter(|e| e.blocked).count() as u64;
        let flagged_calls = events.iter().filter(|e| e.flagged).count() as u64;
        let pattern_matches = interceptor.patterns().len() as u64;
        let category_breakdown = interceptor.category_counts();

        let mut name_counts: HashMap<String, u64> = HashMap::new();
        for ev in &events {
            *name_counts.entry(ev.name.clone()).or_insert(0) += 1;
        }
        let mut top_syscalls: Vec<(String, u64)> = name_counts.into_iter().collect();
        top_syscalls.sort_by(|a, b| b.1.cmp(&a.1));
        top_syscalls.truncate(10);

        Self {
            total_calls,
            blocked_calls,
            flagged_calls,
            pattern_matches,
            category_breakdown,
            top_syscalls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_allow_by_default() {
        let policy = SyscallPolicy::permissive();
        let ev = SyscallEvent::new(
            SyscallEventContext::new(0, 0, 1, 1),
            SyscallNumber(2),
            "open",
            SyscallCategory::FileSystem,
            vec![],
        );
        assert_eq!(*policy.evaluate(&ev), PolicyAction::Allow);
    }

    #[test]
    fn test_policy_block_setuid() {
        let policy = SyscallPolicy::default_sandbox();
        let ev = SyscallEvent::new(
            SyscallEventContext::new(0, 0, 1, 1),
            SyscallNumber(105),
            "setuid",
            SyscallCategory::Privilege,
            vec![],
        );
        assert_eq!(*policy.evaluate(&ev), PolicyAction::Block);
    }

    #[test]
    fn test_interceptor_event_count() {
        let interceptor = SyscallInterceptor::with_default_policy();
        interceptor.intercept(0, 1, 1, SyscallNumber(2), vec![]);
        interceptor.intercept(1, 1, 1, SyscallNumber(1), vec![]);
        assert_eq!(interceptor.total_events(), 2);
    }

    #[test]
    fn test_pattern_detector_privilege_escalation() {
        let mut detector = PatternDetector::new();
        let mut ev = SyscallEvent::new(
            SyscallEventContext::new(0, 0, 1, 1),
            SyscallNumber(105),
            "setuid",
            SyscallCategory::Privilege,
            vec![SyscallArg(0)],
        );
        ev.retval = Some(0);
        let matches = detector.process(&ev);
        assert!(matches.iter().any(|m| m.pattern == SyscallPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_stats_compute() {
        let interceptor = SyscallInterceptor::with_default_policy();
        for _ in 0..5 {
            interceptor.intercept(0, 1, 1, SyscallNumber(2), vec![]);
        }
        let stats = SyscallStats::compute(&interceptor);
        assert_eq!(stats.total_calls, 5);
    }
}
