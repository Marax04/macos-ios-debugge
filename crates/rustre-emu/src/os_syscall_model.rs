//! `os_syscall_model` — Complete OS syscall model for the emulation layer.
//!
//! Provides typed representations of Linux, Windows, and macOS system calls,
//! a dispatch table, and a simple emulation engine that can intercept and
//! simulate syscall behaviour during CPU emulation.
//!
//! Key types:
//! - [`OsSyscallModel`]   — top-level model and dispatcher.
//! - [`LinuxSyscalls`]    — Linux `x86_64` (AMD64) syscall table.
//! - [`WindowsSyscalls`]  — Windows NT syscall table (win10/win11).
//! - [`MacOsSyscalls`]    — macOS / XNU BSD syscall table.
//! - [`SyscallDispatch`]  — routes a raw syscall number to a handler.
//! - [`SyscallEmulator`]  — executes simulated syscalls and returns results.
//!
//! # Relationship to other syscall modules
//!
//! This crate contains three syscall-related modules, each at a different layer:
//!
//! * **`os_syscall_model`** (this module) — *Reference layer*. Multi-OS syscall
//!   number tables (Linux / Windows / macOS), a `SyscallDispatch` lookup table,
//!   `SyscallFilter`, `SyscallInterceptor`, `SyscallStats`, and
//!   `SyscallPatternDetector`. It is standalone (no dependency on the `Emulator`
//!   trait) and can be used purely for static analysis or protocol modelling.
//!
//! * **`syscall_emulation`** — *Register-context layer*. A self-contained
//!   `SyscallEmulator` driven by a `RegisterContext` snapshot. Owns a
//!   `VirtualFs` and `VirtualMemory` and handles Linux x86-64 syscalls without
//!   requiring the `Emulator` trait. Suited for lightweight, single-arch
//!   simulation where the caller manages register I/O.
//!
//! * **`os_emulation`** — *Integration layer*. Implements the `OsEmulator` trait
//!   and wires into `crate::Emulator` via `OsEmuSession`. Supports multiple
//!   architectures (x86-64, x86-32, MIPS) by reading/writing real emulator
//!   registers. The canonical choice when using the full emulation pipeline.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the syscall model layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyscallError {
    #[error("unknown syscall number {0}")]
    UnknownSyscall(u64),
    #[error("invalid argument #{0}: {1}")]
    InvalidArgument(usize, String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("resource not found: {0}")]
    ResourceNotFound(String),
    #[error("emulation not implemented for {0:?}")]
    NotImplemented(String),
    #[error("OS error {0}: {1}")]
    OsError(i64, String),
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallOs
// ─────────────────────────────────────────────────────────────────────────────

/// Operating system whose syscall convention is being modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallOs {
    Linux,
    Windows,
    MacOs,
}

impl fmt::Display for SyscallOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => f.write_str("linux"),
            Self::Windows => f.write_str("windows"),
            Self::MacOs => f.write_str("macos"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a single system call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// Numeric syscall number.
    pub number: u64,
    /// Human-readable name (e.g. `"read"`, `"NtCreateFile"`).
    pub name: String,
    /// OS.
    pub os: SyscallOs,
    /// Number of arguments.
    pub arg_count: usize,
    /// Argument names (for documentation).
    pub arg_names: Vec<String>,
    /// Whether this syscall is commonly used to detect emulators.
    pub evasion_risk: bool,
}

impl SyscallInfo {
    /// Create a new syscall descriptor.
    pub fn new(number: u64, name: impl Into<String>, os: SyscallOs, arg_count: usize) -> Self {
        Self {
            number,
            name: name.into(),
            os,
            arg_count,
            arg_names: Vec::new(),
            evasion_risk: false,
        }
    }

    /// Mark this syscall as an evasion risk.
    #[must_use]
    pub const fn with_evasion_risk(mut self) -> Self {
        self.evasion_risk = true;
        self
    }
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}({})", self.os, self.name, self.number)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallArguments
// ─────────────────────────────────────────────────────────────────────────────

/// The arguments passed to a syscall, stored as raw u64 values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallArguments {
    /// Up to 6 arguments (Linux) / 4 shadow-space (Windows) etc.
    pub args: [u64; 6],
}

impl SyscallArguments {
    /// Create from a slice of up to 6 values.
    #[must_use]
    pub fn from_slice(slice: &[u64]) -> Self {
        let mut args = [0u64; 6];
        let len = slice.len().min(6);
        args[..len].copy_from_slice(&slice[..len]);
        Self { args }
    }

    /// Get argument `n` (0-based).
    #[must_use]
    pub fn get(&self, n: usize) -> u64 {
        self.args.get(n).copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a simulated syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResult {
    /// Return value in the primary register (rax / r0 / eax).
    pub retval: i64,
    /// Whether the call was an error (`retval < 0` on Linux; `NTSTATUS != 0` on Windows).
    pub is_error: bool,
    /// Human-readable description of what happened.
    pub description: String,
}

impl SyscallResult {
    /// Construct a success result.
    pub fn success(retval: i64, description: impl Into<String>) -> Self {
        Self {
            retval,
            is_error: false,
            description: description.into(),
        }
    }

    /// Construct an error result.
    pub fn error(errno: i64, description: impl Into<String>) -> Self {
        Self {
            retval: -errno,
            is_error: true,
            description: description.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxSyscalls
// ─────────────────────────────────────────────────────────────────────────────

/// Linux `x86_64` (AMD64) syscall table (selected subset).
pub struct LinuxSyscalls;

impl LinuxSyscalls {
    /// Raw `(number, name, argc)` table for Linux syscalls.
    const ENTRIES: &'static [(u64, &'static str, usize)] = &[
        (0, "read", 3),
        (1, "write", 3),
        (2, "open", 3),
        (3, "close", 1),
        (4, "stat", 2),
        (5, "fstat", 2),
        (6, "lstat", 2),
        (7, "poll", 3),
        (8, "lseek", 3),
        (9, "mmap", 6),
        (10, "mprotect", 3),
        (11, "munmap", 2),
        (12, "brk", 1),
        (13, "rt_sigaction", 4),
        (14, "rt_sigprocmask", 4),
        (15, "rt_sigreturn", 0),
        (16, "ioctl", 3),
        (17, "pread64", 4),
        (18, "pwrite64", 4),
        (19, "readv", 3),
        (20, "writev", 3),
        (21, "access", 2),
        (22, "pipe", 1),
        (23, "select", 5),
        (24, "sched_yield", 0),
        (25, "mremap", 5),
        (26, "msync", 3),
        (28, "madvise", 3),
        (32, "dup", 1),
        (33, "dup2", 2),
        (35, "nanosleep", 2),
        (38, "setitimer", 3),
        (39, "getpid", 0),
        (40, "sendfile", 4),
        (41, "socket", 3),
        (42, "connect", 3),
        (43, "accept", 3),
        (44, "sendto", 6),
        (45, "recvfrom", 6),
        (49, "bind", 3),
        (50, "listen", 2),
        (51, "getsockname", 3),
        (56, "clone", 5),
        (57, "fork", 0),
        (58, "vfork", 0),
        (59, "execve", 3),
        (60, "exit", 1),
        (61, "wait4", 4),
        (62, "kill", 2),
        (63, "uname", 1),
        (72, "fcntl", 3),
        (79, "getcwd", 2),
        (83, "mkdir", 2),
        (84, "rmdir", 1),
        (85, "creat", 2),
        (86, "link", 2),
        (87, "unlink", 1),
        (88, "symlink", 2),
        (89, "readlink", 3),
        (90, "chmod", 2),
        (91, "fchmod", 2),
        (97, "getrlimit", 2),
        (98, "getrusage", 2),
        (99, "sysinfo", 1),
        (100, "times", 1),
        (102, "getuid", 0),
        (104, "getgid", 0),
        (105, "setuid", 1),
        (106, "setgid", 1),
        (107, "geteuid", 0),
        (108, "getegid", 0),
        (110, "getppid", 0),
        (111, "getpgrp", 0),
        (112, "setsid", 0),
        (131, "sigaltstack", 2),
        (158, "arch_prctl", 2),
        (186, "gettid", 0),
        (202, "futex", 6),
        (218, "set_tid_address", 1),
        (228, "clock_gettime", 2),
        (231, "exit_group", 1),
        (232, "epoll_wait", 4),
        (233, "epoll_ctl", 4),
        (234, "tgkill", 3),
        (257, "openat", 4),
        (261, "futimesat", 3),
        (262, "newfstatat", 4),
        (263, "unlinkat", 3),
        (280, "utimensat", 4),
        (291, "epoll_create1", 1),
        (302, "prlimit64", 4),
        (316, "renameat2", 5),
        (317, "seccomp", 3),
        (318, "getrandom", 3),
        (334, "rseq", 4),
    ];

    /// Return all entries in the Linux syscall table.
    #[must_use]
    pub fn table() -> Vec<SyscallInfo> {
        Self::ENTRIES
            .iter()
            .map(|&(num, name, argc)| SyscallInfo::new(num, name, SyscallOs::Linux, argc))
            .collect()
    }

    /// Look up a syscall by number.
    #[must_use]
    pub fn by_number(n: u64) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.number == n)
    }

    /// Look up a syscall by name.
    #[must_use]
    pub fn by_name(name: &str) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WindowsSyscalls
// ─────────────────────────────────────────────────────────────────────────────

/// Windows NT syscall table (selected subset; Windows 10/11 64-bit).
pub struct WindowsSyscalls;

impl WindowsSyscalls {
    /// Return all entries in the Windows syscall table.
    #[must_use]
    pub fn table() -> Vec<SyscallInfo> {
        let entries: &[(u64, &str, usize)] = &[
            (0x0000, "NtReadFile", 9),
            (0x0001, "NtWriteFile", 9),
            (0x0002, "NtDeviceIoControlFile", 10),
            (0x0003, "NtWaitForSingleObject", 3),
            (0x0004, "NtCreateFile", 11),
            (0x0005, "NtOpenFile", 6),
            (0x0006, "NtClose", 1),
            (0x0007, "NtQueryInformationProcess", 5),
            (0x0008, "NtTerminateProcess", 2),
            (0x0009, "NtCreateSection", 7),
            (0x000A, "NtMapViewOfSection", 10),
            (0x000B, "NtUnmapViewOfSection", 2),
            (0x000C, "NtAllocateVirtualMemory", 6),
            (0x000D, "NtFreeVirtualMemory", 4),
            (0x000E, "NtProtectVirtualMemory", 5),
            (0x000F, "NtQueryVirtualMemory", 6),
            (0x0010, "NtReadVirtualMemory", 5),
            (0x0011, "NtWriteVirtualMemory", 5),
            (0x0012, "NtOpenProcess", 4),
            (0x0013, "NtOpenThread", 4),
            (0x0014, "NtSuspendThread", 2),
            (0x0015, "NtResumeThread", 2),
            (0x0016, "NtTerminateThread", 2),
            (0x0017, "NtGetContextThread", 2),
            (0x0018, "NtSetContextThread", 2),
            (0x0019, "NtCreateThread", 9),
            (0x001A, "NtCreateThreadEx", 11),
            (0x001B, "NtQuerySystemInformation", 4),
            (0x001C, "NtSetSystemInformation", 3),
            (0x001D, "NtRaiseException", 3),
            (0x001E, "NtContinue", 2),
            (0x001F, "NtSetInformationThread", 4),
            (0x0020, "NtQueryInformationThread", 5),
            (0x0021, "NtCreateEvent", 5),
            (0x0022, "NtOpenEvent", 3),
            (0x0023, "NtSetEvent", 2),
            (0x0024, "NtResetEvent", 2),
            (0x0025, "NtWaitForMultipleObjects", 5),
            (0x0026, "NtCreateMutant", 4),
            (0x0027, "NtOpenMutant", 3),
            (0x0028, "NtReleaseMutant", 2),
            (0x0029, "NtCreateSemaphore", 5),
            (0x002A, "NtOpenSemaphore", 3),
            (0x002B, "NtReleaseSemaphore", 3),
            (0x002C, "NtDuplicateObject", 7),
            (0x002D, "NtCreateKey", 7),
            (0x002E, "NtOpenKey", 3),
            (0x002F, "NtDeleteKey", 1),
            (0x0030, "NtDeleteValueKey", 2),
            (0x0031, "NtSetValueKey", 6),
            (0x0032, "NtQueryValueKey", 6),
            (0x0033, "NtEnumerateKey", 6),
            (0x0034, "NtEnumerateValueKey", 6),
            (0x0035, "NtQueryKey", 5),
            (0x0036, "NtFlushKey", 1),
            (0x0037, "NtLoadKey", 2),
            (0x0038, "NtUnloadKey", 1),
            (0x0039, "NtSaveKey", 2),
            (0x003A, "NtLoadRegistryHive", 3),
            (0x003B, "NtUnloadRegistryHive", 1),
        ];
        entries
            .iter()
            .map(|&(num, name, argc)| SyscallInfo::new(num, name, SyscallOs::Windows, argc))
            .collect()
    }

    /// Look up by number.
    #[must_use]
    pub fn by_number(n: u64) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.number == n)
    }

    /// Look up by name.
    #[must_use]
    pub fn by_name(name: &str) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MacOsSyscalls
// ─────────────────────────────────────────────────────────────────────────────

/// macOS / XNU BSD syscall table (selected subset, 64-bit Mach/BSD).
pub struct MacOsSyscalls;

impl MacOsSyscalls {
    /// Return all entries in the macOS syscall table.
    #[must_use]
    pub fn table() -> Vec<SyscallInfo> {
        let entries: &[(u64, &str, usize)] = &[
            (1, "exit", 1),
            (2, "fork", 0),
            (3, "read", 3),
            (4, "write", 3),
            (5, "open", 3),
            (6, "close", 1),
            (7, "wait4", 4),
            (10, "unlink", 1),
            (12, "chdir", 1),
            (14, "mknod", 3),
            (15, "chmod", 2),
            (16, "chown", 3),
            (17, "obreak", 1),
            (18, "getfsstat", 3),
            (20, "getpid", 0),
            (23, "setuid", 1),
            (24, "getuid", 0),
            (25, "geteuid", 0),
            (33, "access", 2),
            (37, "kill", 3),
            (42, "pipe", 0),
            (45, "getgid", 0),
            (46, "getegid", 0),
            (54, "ioctl", 3),
            (58, "execve", 3),
            (59, "umask", 1),
            (60, "chroot", 1),
            (65, "msync", 3),
            (73, "mprotect", 3),
            (74, "madvise", 3),
            (75, "mincore", 3),
            (77, "munmap", 2),
            (78, "mmap", 6),
            (92, "fcntl", 3),
            (96, "socket", 3),
            (97, "connect", 3),
            (98, "bind", 3),
            (99, "setsockopt", 5),
            (100, "listen", 2),
            (116, "getsockopt", 5),
            (117, "write", 3),
            (118, "writev", 3),
            (120, "getsockname", 3),
            (122, "select", 5),
            (126, "sendto", 6),
            (133, "sendmsg", 3),
            (197, "mlock", 2),
            (198, "munlock", 2),
            (199, "undelete", 1),
            (202, "getxattr", 6),
            (203, "fgetxattr", 5),
            (204, "setxattr", 6),
            (205, "fsetxattr", 5),
            (206, "removexattr", 3),
            (207, "fremovexattr", 2),
            (208, "listxattr", 4),
            (209, "flistxattr", 3),
            (266, "nanosleep", 2),
            (274, "stat64", 2),
            (338, "stat", 2),
        ];
        entries
            .iter()
            .map(|&(num, name, argc)| SyscallInfo::new(num, name, SyscallOs::MacOs, argc))
            .collect()
    }

    /// Look up by number.
    #[must_use]
    pub fn by_number(n: u64) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.number == n)
    }

    /// Look up by name.
    #[must_use]
    pub fn by_name(name: &str) -> Option<SyscallInfo> {
        Self::table().into_iter().find(|s| s.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallDispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Routes a raw syscall number to a [`SyscallInfo`] for the configured OS.
#[derive(Debug)]
pub struct SyscallDispatch {
    os: SyscallOs,
    table: HashMap<u64, SyscallInfo>,
}

impl SyscallDispatch {
    /// Create a dispatcher for `os`.
    #[must_use]
    pub fn for_os(os: SyscallOs) -> Self {
        let entries = match os {
            SyscallOs::Linux => LinuxSyscalls::table(),
            SyscallOs::Windows => WindowsSyscalls::table(),
            SyscallOs::MacOs => MacOsSyscalls::table(),
        };
        let mut table = HashMap::new();
        for info in entries {
            table.insert(info.number, info);
        }
        Self { os, table }
    }

    /// Look up a syscall by number.
    ///
    /// # Errors
    /// Returns `SyscallError::UnknownSyscall` if `number` is not in the dispatch table.
    pub fn lookup(&self, number: u64) -> Result<&SyscallInfo, SyscallError> {
        self.table
            .get(&number)
            .ok_or(SyscallError::UnknownSyscall(number))
    }

    /// Return the target OS.
    #[must_use]
    pub const fn os(&self) -> SyscallOs {
        self.os
    }

    /// Return the number of entries in the dispatch table.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.table.len()
    }

    /// Return all syscall names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.table.values().map(|s| s.name.as_str()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallEmulator
// ─────────────────────────────────────────────────────────────────────────────

/// Emulates the effects of common syscalls.
///
/// Maintains a simulated filesystem, file-descriptor table, and memory
/// allocator to handle common syscalls realistically.
pub struct SyscallEmulator {
    os: SyscallOs,
    dispatch: SyscallDispatch,
    /// Simulated open file descriptors: fd → path.
    fds: HashMap<u64, String>,
    /// Simulated filesystem: path → content.
    fs: HashMap<String, Vec<u8>>,
    /// Next file descriptor.
    next_fd: u64,
    /// History of syscalls intercepted.
    history: Vec<SyscallTrace>,
    /// Whether to log syscall traces.
    pub trace_enabled: bool,
}

/// A single syscall trace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTrace {
    /// Syscall number.
    pub number: u64,
    /// Syscall name.
    pub name: String,
    /// Arguments.
    pub args: [u64; 6],
    /// Return value.
    pub retval: i64,
}

impl SyscallEmulator {
    /// Create a new syscall emulator for `os`.
    #[must_use]
    pub fn new(os: SyscallOs) -> Self {
        let mut emu = Self {
            os,
            dispatch: SyscallDispatch::for_os(os),
            fds: HashMap::new(),
            fs: HashMap::new(),
            next_fd: 3, // stdin=0, stdout=1, stderr=2
            history: Vec::new(),
            trace_enabled: false,
        };
        // Pre-populate some virtual files.
        emu.fs.insert(
            "/proc/self/maps".to_owned(),
            b"00400000-00401000 r-xp\n".to_vec(),
        );
        emu.fs.insert(
            "/etc/passwd".to_owned(),
            b"root:x:0:0:root:/root:/bin/sh\n".to_vec(),
        );
        emu.fds.insert(0, "<stdin>".to_owned());
        emu.fds.insert(1, "<stdout>".to_owned());
        emu.fds.insert(2, "<stderr>".to_owned());
        emu
    }

    /// Emulate a syscall.  Returns the result.
    ///
    /// # Errors
    /// Returns `SyscallError` if the syscall is unknown.
    pub fn emulate(
        &mut self,
        number: u64,
        args: &SyscallArguments,
    ) -> Result<SyscallResult, SyscallError> {
        let info = self.dispatch.lookup(number)?.clone();

        let result = match (self.os, info.name.as_str()) {
            (SyscallOs::Linux | SyscallOs::MacOs, "getpid")
            | (SyscallOs::Windows, "NtQueryInformationProcess") => {
                SyscallResult::success(1234, "getpid → 1234")
            }
            (SyscallOs::Linux | SyscallOs::MacOs, "read") => {
                let fd = args.get(0);
                if fd <= 2 {
                    // stdin-like read — return 0 (EOF).
                    SyscallResult::success(0, "read → 0 (EOF)")
                } else if self.fds.contains_key(&fd) {
                    SyscallResult::success(4, "read → 4 bytes")
                } else {
                    SyscallResult::error(9, "EBADF: bad file descriptor")
                }
            }
            (SyscallOs::Linux | SyscallOs::MacOs, "write") => {
                let fd = args.get(0);
                let count = args.get(2);
                if fd <= 2 || self.fds.contains_key(&fd) {
                    SyscallResult::success(count.cast_signed(), format!("write → {count}"))
                } else {
                    SyscallResult::error(9, "EBADF")
                }
            }
            (SyscallOs::Linux | SyscallOs::MacOs, "open") => {
                let fd = self.next_fd;
                self.next_fd += 1;
                self.fds.insert(fd, "<opened>".to_owned());
                SyscallResult::success(fd.cast_signed(), format!("open → fd={fd}"))
            }
            (SyscallOs::Linux | SyscallOs::MacOs, "close") => {
                let fd = args.get(0);
                if self.fds.remove(&fd).is_some() {
                    SyscallResult::success(0, "close → 0")
                } else {
                    SyscallResult::error(9, "EBADF")
                }
            }
            (SyscallOs::Linux | SyscallOs::MacOs, "exit") | (SyscallOs::Linux, "exit_group") => {
                let code = args.get(0);
                SyscallResult::success(0, format!("exit({code})"))
            }
            (SyscallOs::Linux, "brk") => SyscallResult::success(0x1000_0000, "brk → new break"),
            (SyscallOs::Linux, "mmap") => SyscallResult::success(0x7000_0000, "mmap → 0x70000000"),
            (SyscallOs::Linux, "munmap") => SyscallResult::success(0, "munmap → 0"),
            (SyscallOs::Windows, "NtAllocateVirtualMemory") => {
                SyscallResult::success(0, "NtAllocateVirtualMemory → STATUS_SUCCESS")
            }
            (SyscallOs::Windows, "NtClose") => {
                SyscallResult::success(0, "NtClose → STATUS_SUCCESS")
            }
            _ => SyscallResult::success(0, format!("{} → 0 (default)", info.name)),
        };

        if self.trace_enabled {
            self.history.push(SyscallTrace {
                number,
                name: info.name,
                args: args.args,
                retval: result.retval,
            });
        }

        Ok(result)
    }

    /// Return the syscall history.
    #[must_use]
    pub fn history(&self) -> &[SyscallTrace] {
        &self.history
    }

    /// Clear the history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Return the target OS.
    #[must_use]
    pub const fn os(&self) -> SyscallOs {
        self.os
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OsSyscallModel
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level OS syscall model — aggregates all three OS tables and a dispatcher.
pub struct OsSyscallModel {
    /// Dispatch tables for all supported OSes.
    dispatchers: HashMap<SyscallOs, SyscallDispatch>,
    /// Active emulators per OS.
    emulators: HashMap<SyscallOs, SyscallEmulator>,
}

impl OsSyscallModel {
    /// Create a model initialised with all three OS tables.
    #[must_use]
    pub fn new() -> Self {
        let mut dispatchers = HashMap::new();
        let mut emulators = HashMap::new();
        for os in [SyscallOs::Linux, SyscallOs::Windows, SyscallOs::MacOs] {
            dispatchers.insert(os, SyscallDispatch::for_os(os));
            emulators.insert(os, SyscallEmulator::new(os));
        }
        Self {
            dispatchers,
            emulators,
        }
    }

    /// Look up a syscall by OS and number.
    ///
    /// # Errors
    /// Returns `SyscallError::UnknownSyscall` if `number` is not in the table for `os`.
    pub fn lookup(&self, os: SyscallOs, number: u64) -> Result<&SyscallInfo, SyscallError> {
        self.dispatchers[&os].lookup(number)
    }

    /// Emulate a syscall on the given OS.
    ///
    /// # Errors
    /// Returns `SyscallError` if the syscall is unknown.
    ///
    /// # Panics
    /// Panics if no emulator is registered for `os` (should not happen by construction).
    pub fn emulate(
        &mut self,
        os: SyscallOs,
        number: u64,
        args: &SyscallArguments,
    ) -> Result<SyscallResult, SyscallError> {
        self.emulators.get_mut(&os).unwrap().emulate(number, args)
    }

    /// Return the number of entries in a given OS table.
    #[must_use]
    pub fn table_size(&self, os: SyscallOs) -> usize {
        self.dispatchers[&os].entry_count()
    }

    /// Return all evasion-risk syscalls across all OSes.
    #[must_use]
    pub fn evasion_syscalls(&self) -> Vec<SyscallInfo> {
        self.dispatchers
            .values()
            .flat_map(|d| d.table.values())
            .filter(|s| s.evasion_risk)
            .cloned()
            .collect()
    }
}

impl Default for OsSyscallModel {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallFilter
// ─────────────────────────────────────────────────────────────────────────────

/// A filter that allows selectively blocking or monitoring syscalls.
///
/// Used for seccomp-style enforcement during emulation, or to intercept
/// specific syscalls for analysis.
#[derive(Debug, Default)]
pub struct SyscallFilter {
    /// Syscall numbers that should be blocked (return EPERM).
    blocked: std::collections::HashSet<u64>,
    /// Syscall numbers that are always allowed.
    allowed: std::collections::HashSet<u64>,
    /// Default policy: `true` = allow, `false` = block.
    pub default_allow: bool,
}

impl SyscallFilter {
    /// Create a filter that allows everything by default.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            default_allow: true,
            ..Default::default()
        }
    }

    /// Create a filter that blocks everything by default.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            default_allow: false,
            ..Default::default()
        }
    }

    /// Block a specific syscall number.
    pub fn block(&mut self, syscall: u64) -> &mut Self {
        self.blocked.insert(syscall);
        self.allowed.remove(&syscall);
        self
    }

    /// Explicitly allow a syscall number (overrides default-deny).
    pub fn allow(&mut self, syscall: u64) -> &mut Self {
        self.allowed.insert(syscall);
        self.blocked.remove(&syscall);
        self
    }

    /// Check whether `syscall` is permitted.
    #[must_use]
    pub fn is_permitted(&self, syscall: u64) -> bool {
        if self.blocked.contains(&syscall) {
            return false;
        }
        if self.allowed.contains(&syscall) {
            return true;
        }
        self.default_allow
    }

    /// Return the number of blocked syscalls.
    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Return the number of explicitly allowed syscalls.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallStats
// ─────────────────────────────────────────────────────────────────────────────

/// Per-syscall call statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallStats {
    /// Total calls per syscall name.
    pub calls: HashMap<String, u64>,
    /// Total errors per syscall name.
    pub errors: HashMap<String, u64>,
    /// Total syscalls emulated.
    pub total: u64,
}

impl SyscallStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a syscall invocation.
    pub fn record(&mut self, name: &str, is_error: bool) {
        *self.calls.entry(name.to_owned()).or_insert(0) += 1;
        if is_error {
            *self.errors.entry(name.to_owned()).or_insert(0) += 1;
        }
        self.total += 1;
    }

    /// Return the call count for `name`.
    #[must_use]
    pub fn count(&self, name: &str) -> u64 {
        self.calls.get(name).copied().unwrap_or(0)
    }

    /// Return the error count for `name`.
    #[must_use]
    pub fn error_count(&self, name: &str) -> u64 {
        self.errors.get(name).copied().unwrap_or(0)
    }

    /// Return the most frequently called syscall.
    #[must_use]
    pub fn most_frequent(&self) -> Option<(&str, u64)> {
        self.calls
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(name, &c)| (name.as_str(), c))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how syscall arguments are passed for a given OS / architecture.
//
// Note: cannot derive Deserialize because the fields hold `&'static str` /
// `&'static [&'static str]` (string-literal references), which serde cannot
// reconstruct from owned input at runtime. All instances are built via the
// `linux_x86_64()` / `windows_x86_64()` constructors below.
#[derive(Debug, Clone, Serialize)]
pub struct SyscallConvention {
    pub os: SyscallOs,
    /// Register used to pass the syscall number.
    pub syscall_num_reg: &'static str,
    /// Registers used for arguments (up to 6).
    pub arg_regs: &'static [&'static str],
    /// Register that receives the return value.
    pub retval_reg: &'static str,
}

impl SyscallConvention {
    /// Return the Linux x86-64 syscall convention.
    #[must_use]
    pub const fn linux_x86_64() -> Self {
        Self {
            os: SyscallOs::Linux,
            syscall_num_reg: "rax",
            arg_regs: &["rdi", "rsi", "rdx", "r10", "r8", "r9"],
            retval_reg: "rax",
        }
    }

    /// Return the Windows x86-64 syscall convention.
    #[must_use]
    pub const fn windows_x86_64() -> Self {
        Self {
            os: SyscallOs::Windows,
            syscall_num_reg: "rax",
            arg_regs: &["rcx", "rdx", "r8", "r9"],
            retval_reg: "rax",
        }
    }

    /// Return the macOS x86-64 syscall convention.
    #[must_use]
    pub const fn macos_x86_64() -> Self {
        Self {
            os: SyscallOs::MacOs,
            syscall_num_reg: "rax",
            arg_regs: &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            retval_reg: "rax",
        }
    }

    /// Return the argument register for `n`-th argument (0-based).
    #[must_use]
    pub fn arg_reg(&self, n: usize) -> Option<&'static str> {
        self.arg_regs.get(n).copied()
    }
}

impl fmt::Display for SyscallConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SyscallConvention({}, num_reg={}, args=[{}])",
            self.os,
            self.syscall_num_reg,
            self.arg_regs.join(", ")
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallInterceptor — hook individual syscalls for analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Records an intercepted syscall invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInterception {
    pub number: u64,
    pub name: String,
    pub args: [u64; 6],
    pub result: Option<SyscallResult>,
    pub modified: bool,
}

/// Intercepts and optionally overrides syscall behaviour.
#[derive(Debug, Default)]
pub struct SyscallInterceptor {
    /// Syscall numbers to intercept.
    watched: std::collections::HashSet<u64>,
    /// Intercepted calls, in order.
    history: Vec<SyscallInterception>,
    /// Optional override return values: `syscall_num` → `forced_retval`.
    overrides: HashMap<u64, i64>,
}

impl SyscallInterceptor {
    /// Create a new interceptor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch a syscall number.
    pub fn watch(&mut self, number: u64) {
        self.watched.insert(number);
    }

    /// Unwatch a syscall number.
    pub fn unwatch(&mut self, number: u64) {
        self.watched.remove(&number);
    }

    /// Override the return value for `number`.
    pub fn override_retval(&mut self, number: u64, retval: i64) {
        self.overrides.insert(number, retval);
    }

    /// Process a syscall — may modify the result.
    pub fn process(
        &mut self,
        number: u64,
        name: &str,
        args: &SyscallArguments,
        mut result: SyscallResult,
    ) -> SyscallResult {
        if !self.watched.contains(&number) {
            return result;
        }
        let modified = if let Some(&forced) = self.overrides.get(&number) {
            result.retval = forced;
            result.is_error = forced < 0;
            true
        } else {
            false
        };
        self.history.push(SyscallInterception {
            number,
            name: name.to_owned(),
            args: args.args,
            result: Some(result.clone()),
            modified,
        });
        result
    }

    /// Return all intercepted calls.
    #[must_use]
    pub fn history(&self) -> &[SyscallInterception] {
        &self.history
    }

    /// Clear the history.
    pub fn clear(&mut self) {
        self.history.clear();
    }

    /// Return calls for a specific syscall name.
    #[must_use]
    pub fn calls_to(&self, name: &str) -> Vec<&SyscallInterception> {
        self.history.iter().filter(|c| c.name == name).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallGroupings — logical grouping of syscalls by function
// ─────────────────────────────────────────────────────────────────────────────

/// A logical group of related syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallGroup {
    FileIo,
    Memory,
    Process,
    Thread,
    Network,
    Signal,
    Time,
    Security,
    Other,
}

impl fmt::Display for SyscallGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileIo => "file-io",
            Self::Memory => "memory",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Network => "network",
            Self::Signal => "signal",
            Self::Time => "time",
            Self::Security => "security",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Assigns a group to a Linux syscall name.
#[must_use]
pub fn linux_syscall_group(name: &str) -> SyscallGroup {
    match name {
        "read" | "write" | "open" | "close" | "stat" | "fstat" | "lstat" | "lseek" | "ioctl"
        | "pread64" | "pwrite64" | "readv" | "writev" | "access" | "dup" | "dup2" | "pipe"
        | "fcntl" | "openat" | "unlink" | "mkdir" | "rmdir" | "creat" | "link" | "symlink"
        | "readlink" | "chmod" | "fchmod" | "getcwd" => SyscallGroup::FileIo,

        "mmap" | "mprotect" | "munmap" | "brk" | "mremap" | "msync" | "madvise" | "mlock"
        | "munlock" => SyscallGroup::Memory,

        "fork" | "vfork" | "execve" | "exit" | "exit_group" | "wait4" | "getpid" | "getppid"
        | "getpgrp" | "setsid" | "kill" | "tgkill" | "uname" | "getrlimit" | "getrusage"
        | "sysinfo" => SyscallGroup::Process,

        // `clone` straddles the Process / Thread boundary on Linux; it is
        // classified here as a thread-creation primitive since the common
        // libc use is pthread_create(2).
        "clone" | "gettid" | "set_tid_address" | "futex" | "sched_yield" | "nanosleep"
        | "setitimer" => SyscallGroup::Thread,

        "socket" | "connect" | "accept" | "sendto" | "recvfrom" | "bind" | "listen"
        | "getsockname" | "sendfile" | "select" | "poll" | "epoll_wait" | "epoll_ctl"
        | "epoll_create1" => SyscallGroup::Network,

        "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" | "sigaltstack" => SyscallGroup::Signal,

        "clock_gettime" | "times" => SyscallGroup::Time,

        "seccomp" | "getrandom" | "arch_prctl" | "setuid" | "setgid" | "getuid" | "getgid"
        | "geteuid" | "getegid" | "prlimit64" => SyscallGroup::Security,

        _ => SyscallGroup::Other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallPatternDetector — detect characteristic API patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Detects sequences of syscalls that match known patterns (e.g. process injection,
/// network C2, privilege escalation).
#[derive(Debug, Default)]
pub struct SyscallPatternDetector {
    /// Window of recent syscall names.
    window: std::collections::VecDeque<String>,
    window_size: usize,
    /// Patterns detected.
    pub detections: Vec<String>,
}

impl SyscallPatternDetector {
    #[must_use]
    pub const fn new(window_size: usize) -> Self {
        Self {
            window: std::collections::VecDeque::new(),
            window_size,
            detections: Vec::new(),
        }
    }

    pub fn record(&mut self, name: &str) {
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(name.to_owned());
        self.check_patterns();
    }

    fn check_patterns(&mut self) {
        let seq: Vec<&str> = self.window.iter().map(String::as_str).collect();
        // mmap + mprotect + write → shellcode injection pattern
        if seq.windows(3).any(|w| w == ["mmap", "mprotect", "write"])
            && !self.detections.iter().any(|d| d == "shellcode-injection")
        {
            self.detections.push("shellcode-injection".to_owned());
        }
        // fork + execve → process launch
        if seq.windows(2).any(|w| w == ["fork", "execve"])
            && !self.detections.iter().any(|d| d == "process-launch")
        {
            self.detections.push("process-launch".to_owned());
        }
        // socket + connect → network connection
        if seq.windows(2).any(|w| w == ["socket", "connect"])
            && !self.detections.iter().any(|d| d == "network-connect")
        {
            self.detections.push("network-connect".to_owned());
        }
    }

    #[must_use]
    pub fn has_detection(&self, name: &str) -> bool {
        self.detections.iter().any(|d| d == name)
    }

    pub fn clear(&mut self) {
        self.window.clear();
        self.detections.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SyscallOs ─────────────────────────────────────────────────────────────

    #[test]
    fn syscall_os_display() {
        assert_eq!(SyscallOs::Linux.to_string(), "linux");
        assert_eq!(SyscallOs::Windows.to_string(), "windows");
        assert_eq!(SyscallOs::MacOs.to_string(), "macos");
    }

    // ── SyscallInfo ───────────────────────────────────────────────────────────

    #[test]
    fn syscall_info_display() {
        let info = SyscallInfo::new(1, "write", SyscallOs::Linux, 3);
        assert!(info.to_string().contains("write"));
        assert!(info.to_string().contains("linux"));
    }

    #[test]
    fn syscall_info_evasion_risk() {
        let info = SyscallInfo::new(100, "cpuid", SyscallOs::Linux, 0).with_evasion_risk();
        assert!(info.evasion_risk);
    }

    // ── SyscallArguments ──────────────────────────────────────────────────────

    #[test]
    fn syscall_args_from_slice() {
        let args = SyscallArguments::from_slice(&[1, 2, 3]);
        assert_eq!(args.get(0), 1);
        assert_eq!(args.get(2), 3);
        assert_eq!(args.get(5), 0); // unfilled
    }

    #[test]
    fn syscall_args_overflow_truncated() {
        let big = [1u64; 10];
        let args = SyscallArguments::from_slice(&big);
        assert_eq!(args.args.len(), 6);
    }

    // ── SyscallResult ─────────────────────────────────────────────────────────

    #[test]
    fn syscall_result_success() {
        let r = SyscallResult::success(42, "ok");
        assert!(!r.is_error);
        assert_eq!(r.retval, 42);
    }

    #[test]
    fn syscall_result_error() {
        let r = SyscallResult::error(9, "EBADF");
        assert!(r.is_error);
        assert_eq!(r.retval, -9);
    }

    // ── LinuxSyscalls ─────────────────────────────────────────────────────────

    #[test]
    fn linux_syscalls_table_nonempty() {
        assert!(!LinuxSyscalls::table().is_empty());
    }

    #[test]
    fn linux_syscall_by_number_read() {
        let s = LinuxSyscalls::by_number(0).unwrap();
        assert_eq!(s.name, "read");
        assert_eq!(s.arg_count, 3);
    }

    #[test]
    fn linux_syscall_by_name_write() {
        let s = LinuxSyscalls::by_name("write").unwrap();
        assert_eq!(s.number, 1);
    }

    #[test]
    fn linux_syscall_not_found_returns_none() {
        assert!(LinuxSyscalls::by_number(9999).is_none());
    }

    // ── WindowsSyscalls ───────────────────────────────────────────────────────

    #[test]
    fn windows_syscalls_table_nonempty() {
        assert!(!WindowsSyscalls::table().is_empty());
    }

    #[test]
    fn windows_syscall_ntcreatefile() {
        let s = WindowsSyscalls::by_name("NtCreateFile").unwrap();
        assert_eq!(s.number, 0x0004);
    }

    #[test]
    fn windows_syscall_by_number() {
        let s = WindowsSyscalls::by_number(0).unwrap();
        assert_eq!(s.name, "NtReadFile");
    }

    // ── MacOsSyscalls ─────────────────────────────────────────────────────────

    #[test]
    fn macos_syscalls_table_nonempty() {
        assert!(!MacOsSyscalls::table().is_empty());
    }

    #[test]
    fn macos_syscall_exit() {
        let s = MacOsSyscalls::by_number(1).unwrap();
        assert_eq!(s.name, "exit");
    }

    #[test]
    fn macos_syscall_by_name_read() {
        let s = MacOsSyscalls::by_name("read").unwrap();
        assert_eq!(s.number, 3);
    }

    // ── SyscallDispatch ───────────────────────────────────────────────────────

    #[test]
    fn dispatch_linux_lookup() {
        let d = SyscallDispatch::for_os(SyscallOs::Linux);
        let s = d.lookup(60).unwrap();
        assert_eq!(s.name, "exit");
    }

    #[test]
    fn dispatch_unknown_syscall_errors() {
        let d = SyscallDispatch::for_os(SyscallOs::Linux);
        assert!(d.lookup(99999).is_err());
    }

    #[test]
    fn dispatch_entry_count_positive() {
        let d = SyscallDispatch::for_os(SyscallOs::Windows);
        assert!(d.entry_count() > 0);
    }

    #[test]
    fn dispatch_names_contains_read() {
        let d = SyscallDispatch::for_os(SyscallOs::Linux);
        assert!(d.names().contains(&"read"));
    }

    // ── SyscallEmulator ───────────────────────────────────────────────────────

    #[test]
    fn emulator_getpid_ok() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let args = SyscallArguments::default();
        let result = emu.emulate(39, &args).unwrap(); // getpid = 39
        assert!(!result.is_error);
        assert_eq!(result.retval, 1234);
    }

    #[test]
    fn emulator_write_to_stdout() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let args = SyscallArguments::from_slice(&[1, 0xDEAD, 5]); // fd=1, buf, count=5
        let result = emu.emulate(1, &args).unwrap(); // write = 1
        assert!(!result.is_error);
        assert_eq!(result.retval, 5);
    }

    #[test]
    fn emulator_close_bad_fd_errors() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let args = SyscallArguments::from_slice(&[99]); // non-existent fd
        let result = emu.emulate(3, &args).unwrap(); // close = 3
        assert!(result.is_error);
    }

    #[test]
    fn emulator_open_and_close() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let args = SyscallArguments::default();
        let open_result = emu.emulate(2, &args).unwrap(); // open = 2
        assert!(!open_result.is_error);
        let fd = open_result.retval.cast_unsigned();
        let close_args = SyscallArguments::from_slice(&[fd]);
        let close_result = emu.emulate(3, &close_args).unwrap();
        assert!(!close_result.is_error);
    }

    #[test]
    fn emulator_unknown_syscall_errors() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        assert!(emu.emulate(99999, &SyscallArguments::default()).is_err());
    }

    #[test]
    fn emulator_trace_recording() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        emu.trace_enabled = true;
        let _ = emu.emulate(39, &SyscallArguments::default()); // getpid
        assert_eq!(emu.history().len(), 1);
        assert_eq!(emu.history()[0].name, "getpid");
        emu.clear_history();
        assert!(emu.history().is_empty());
    }

    #[test]
    fn emulator_windows_nt_allocate() {
        let mut emu = SyscallEmulator::new(SyscallOs::Windows);
        let args = SyscallArguments::default();
        let r = emu.emulate(0x000C, &args).unwrap(); // NtAllocateVirtualMemory
        assert!(!r.is_error);
    }

    // ── OsSyscallModel ────────────────────────────────────────────────────────

    #[test]
    fn os_syscall_model_lookup_linux() {
        let model = OsSyscallModel::new();
        let s = model.lookup(SyscallOs::Linux, 1).unwrap();
        assert_eq!(s.name, "write");
    }

    #[test]
    fn os_syscall_model_lookup_windows() {
        let model = OsSyscallModel::new();
        let s = model.lookup(SyscallOs::Windows, 0).unwrap();
        assert_eq!(s.name, "NtReadFile");
    }

    #[test]
    fn os_syscall_model_lookup_macos() {
        let model = OsSyscallModel::new();
        let s = model.lookup(SyscallOs::MacOs, 3).unwrap();
        assert_eq!(s.name, "read");
    }

    #[test]
    fn os_syscall_model_table_sizes_positive() {
        let model = OsSyscallModel::new();
        assert!(model.table_size(SyscallOs::Linux) > 0);
        assert!(model.table_size(SyscallOs::Windows) > 0);
        assert!(model.table_size(SyscallOs::MacOs) > 0);
    }

    #[test]
    fn os_syscall_model_emulate_getpid() {
        let mut model = OsSyscallModel::new();
        let args = SyscallArguments::default();
        let r = model.emulate(SyscallOs::Linux, 39, &args).unwrap();
        assert_eq!(r.retval, 1234);
    }

    // ── SyscallError ──────────────────────────────────────────────────────────

    #[test]
    fn syscall_error_display() {
        assert!(
            SyscallError::UnknownSyscall(999)
                .to_string()
                .contains("999")
        );
        assert!(
            SyscallError::PermissionDenied
                .to_string()
                .contains("permission")
        );
        assert!(
            SyscallError::NotImplemented("mmap".into())
                .to_string()
                .contains("mmap")
        );
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn linux_syscall_table_covers_brk_mmap() {
        assert!(LinuxSyscalls::by_name("brk").is_some());
        assert!(LinuxSyscalls::by_name("mmap").is_some());
        assert!(LinuxSyscalls::by_name("munmap").is_some());
    }

    #[test]
    fn linux_syscall_table_covers_networking() {
        assert!(LinuxSyscalls::by_name("socket").is_some());
        assert!(LinuxSyscalls::by_name("connect").is_some());
        assert!(LinuxSyscalls::by_name("bind").is_some());
    }

    #[test]
    fn windows_syscall_table_covers_memory() {
        assert!(WindowsSyscalls::by_name("NtAllocateVirtualMemory").is_some());
        assert!(WindowsSyscalls::by_name("NtFreeVirtualMemory").is_some());
        assert!(WindowsSyscalls::by_name("NtProtectVirtualMemory").is_some());
    }

    #[test]
    fn windows_syscall_table_covers_process() {
        assert!(WindowsSyscalls::by_name("NtOpenProcess").is_some());
        assert!(WindowsSyscalls::by_name("NtTerminateProcess").is_some());
    }

    #[test]
    fn macos_syscall_table_covers_process() {
        assert!(MacOsSyscalls::by_name("fork").is_some());
        assert!(MacOsSyscalls::by_name("execve").is_some());
        assert!(MacOsSyscalls::by_name("exit").is_some());
    }

    #[test]
    fn dispatch_macos_entry_count() {
        let d = SyscallDispatch::for_os(SyscallOs::MacOs);
        assert!(d.entry_count() > 0);
        assert_eq!(d.os(), SyscallOs::MacOs);
    }

    #[test]
    fn emulator_exit_group() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let r = emu
            .emulate(231, &SyscallArguments::from_slice(&[0]))
            .unwrap(); // exit_group
        assert!(!r.is_error);
    }

    #[test]
    fn emulator_brk() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let r = emu.emulate(12, &SyscallArguments::default()).unwrap(); // brk
        assert!(!r.is_error);
        assert_eq!(r.retval, 0x1000_0000);
    }

    #[test]
    fn emulator_mmap() {
        let mut emu = SyscallEmulator::new(SyscallOs::Linux);
        let r = emu.emulate(9, &SyscallArguments::default()).unwrap(); // mmap
        assert!(!r.is_error);
    }

    #[test]
    fn emulator_nt_close() {
        let mut emu = SyscallEmulator::new(SyscallOs::Windows);
        let r = emu.emulate(0x0006, &SyscallArguments::default()).unwrap(); // NtClose
        assert!(!r.is_error);
    }

    #[test]
    fn os_syscall_model_lookup_nonexistent() {
        let model = OsSyscallModel::new();
        assert!(model.lookup(SyscallOs::Linux, 99999).is_err());
    }

    #[test]
    fn syscall_args_get_out_of_range() {
        let args = SyscallArguments::default();
        assert_eq!(args.get(10), 0); // beyond array
    }

    #[test]
    fn syscall_result_description_preserved() {
        let r = SyscallResult::success(0, "custom message");
        assert!(r.description.contains("custom message"));
        let e = SyscallResult::error(1, "EPERM");
        assert!(e.description.contains("EPERM"));
    }
}
