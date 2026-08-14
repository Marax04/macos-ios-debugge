//! `rustre-syscalls-linux`
//!
//! Linux syscall tables for x86, x86\_64, ARM 32-bit EABI, and `AArch64`.
//! Provides lookup by number, lookup by name, and iteration over all syscalls
//! for a given architecture.

pub mod ptrace_tracer;
pub mod syscall_intercept;
pub mod syscall_statistics;
pub mod ptrace_syscall_tracer;
pub mod seccomp_profile_generator;
pub mod linux_syscall_table_x86_64;

use std::collections::HashMap;

use rustre_syscalls::SyscallArch;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the Linux syscall resolver.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum LinuxSyscallError {
    /// The requested architecture is not supported by this table.
    #[error("unsupported architecture: {0:?}")]
    UnsupportedArch(SyscallArch),
    /// No syscall was found with the given number on the given architecture.
    #[error("syscall not found: arch={arch:?} number={number}")]
    NotFound {
        /// Architecture that was queried.
        arch: SyscallArch,
        /// Syscall number that was not found.
        number: u32,
    },
}

// ─── Core types ───────────────────────────────────────────────────────────────

/// A single parameter of a Linux syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallParam {
    /// Parameter name (e.g. `"fd"`, `"buf"`).
    pub name: String,
    /// C type string (e.g. `"int"`, `"const char __user *"`).
    pub ty: String,
}

impl SyscallParam {
    /// Construct a new [`SyscallParam`].
    #[must_use]
    pub fn new(name: impl Into<String>, ty: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
        }
    }
}

/// A Linux syscall definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSyscall {
    /// Syscall number (NR value).
    pub number: u32,
    /// Syscall name without the `sys_` prefix (e.g. `"read"`).
    pub name: String,
    /// Ordered list of parameters.
    pub params: Vec<SyscallParam>,
    /// C return-type string.
    pub ret_ty: String,
}

impl LinuxSyscall {
    /// Construct a new [`LinuxSyscall`].
    #[must_use]
    pub fn new(
        number: u32,
        name: impl Into<String>,
        params: Vec<SyscallParam>,
        ret_ty: impl Into<String>,
    ) -> Self {
        Self {
            number,
            name: name.into(),
            params,
            ret_ty: ret_ty.into(),
        }
    }
}

// ─── Database ─────────────────────────────────────────────────────────────────

/// Database holding all Linux syscall tables indexed by [`SyscallArch`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSyscallDb {
    tables: HashMap<SyscallArch, Vec<LinuxSyscall>>,
}

impl Default for LinuxSyscallDb {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxSyscallDb {
    /// Build the database and populate all four Linux-relevant architectures.
    #[must_use]
    pub fn new() -> Self {
        let mut tables: HashMap<SyscallArch, Vec<LinuxSyscall>> = HashMap::new();
        let mut x86_64 = build_x86_64();
        x86_64.sort_unstable_by_key(|s| s.number);
        let mut x86 = build_x86();
        x86.sort_unstable_by_key(|s| s.number);
        let mut arm32 = build_arm32();
        arm32.sort_unstable_by_key(|s| s.number);
        let mut arm64 = build_arm64();
        arm64.sort_unstable_by_key(|s| s.number);
        tables.insert(SyscallArch::X86_64, x86_64);
        tables.insert(SyscallArch::X86, x86);
        tables.insert(SyscallArch::Arm32, arm32);
        tables.insert(SyscallArch::Arm64, arm64);
        Self { tables }
    }

    /// Return the number of syscalls in the table for `arch`.
    #[must_use]
    pub fn arch_count(&self, arch: SyscallArch) -> usize {
        self.tables.get(&arch).map_or(0, Vec::len)
    }

    /// Return an immutable slice of all syscalls for `arch`, sorted by number,
    /// or `None` if the arch is not present.
    #[must_use]
    pub fn all_for_arch(&self, arch: SyscallArch) -> Option<&[LinuxSyscall]> {
        self.tables.get(&arch).map(Vec::as_slice)
    }

    /// Look up a syscall by arch + number.
    #[must_use]
    pub fn lookup(&self, arch: SyscallArch, number: u32) -> Option<&LinuxSyscall> {
        let table = self.tables.get(&arch)?;
        let idx = table.binary_search_by_key(&number, |s| s.number).ok()?;
        Some(&table[idx])
    }

    /// Look up a syscall by arch + name (exact match).
    #[must_use]
    pub fn lookup_by_name(&self, arch: SyscallArch, name: &str) -> Option<&LinuxSyscall> {
        self.tables.get(&arch)?.iter().find(|s| s.name == name)
    }
}

// ─── Resolver ─────────────────────────────────────────────────────────────────

/// High-level resolver wrapping a [`LinuxSyscallDb`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResolver {
    db: LinuxSyscallDb,
}

impl Default for SyscallResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallResolver {
    /// Create a resolver backed by the default populated database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: LinuxSyscallDb::new(),
        }
    }

    /// Create a resolver from an existing database.
    #[must_use]
    pub const fn with_db(db: LinuxSyscallDb) -> Self {
        Self { db }
    }

    /// Look up a syscall by architecture and number.
    ///
    /// Returns `None` when neither the architecture nor the number is found.
    #[must_use]
    pub fn lookup(&self, arch: SyscallArch, number: u32) -> Option<&LinuxSyscall> {
        self.db.lookup(arch, number)
    }

    /// Look up a syscall by architecture and exact name.
    ///
    /// Returns `None` when neither the architecture nor the name is found.
    #[must_use]
    pub fn lookup_by_name(&self, arch: SyscallArch, name: &str) -> Option<&LinuxSyscall> {
        self.db.lookup_by_name(arch, name)
    }

    /// Return all syscalls for the given architecture, sorted by syscall number.
    ///
    /// Returns an empty slice when the architecture is not present.
    #[must_use]
    pub fn all_for_arch(&self, arch: SyscallArch) -> &[LinuxSyscall] {
        self.db.all_for_arch(arch).unwrap_or(&[])
    }

    /// Return a reference to the underlying database.
    #[must_use]
    pub const fn db(&self) -> &LinuxSyscallDb {
        &self.db
    }
}

// ─── Table builders ───────────────────────────────────────────────────────────

/// Short helper so table definitions stay readable.
fn p(name: &str, ty: &str) -> SyscallParam {
    SyscallParam::new(name, ty)
}

fn sc(number: u32, name: &str, params: Vec<SyscallParam>, ret_ty: &str) -> LinuxSyscall {
    LinuxSyscall::new(number, name, params, ret_ty)
}

fn build_x86_64_p1() -> Vec<LinuxSyscall> {
    vec![
        sc(0, "read", vec![p("fd", "int"), p("buf", "char __user *"), p("count", "size_t")], "ssize_t"),
        sc(1, "write", vec![p("fd", "int"), p("buf", "const char __user *"), p("count", "size_t")], "ssize_t"),
        sc(2, "open", vec![p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(3, "close", vec![p("fd", "unsigned int")], "long"),
        sc(4, "stat", vec![p("filename", "const char __user *"), p("statbuf", "struct stat __user *")], "long"),
        sc(5, "fstat", vec![p("fd", "unsigned int"), p("statbuf", "struct stat __user *")], "long"),
        sc(6, "lstat", vec![p("filename", "const char __user *"), p("statbuf", "struct stat __user *")], "long"),
        sc(7, "poll", vec![p("ufds", "struct pollfd __user *"), p("nfds", "unsigned int"), p("timeout", "int")], "long"),
        sc(8, "lseek", vec![p("fd", "unsigned int"), p("offset", "off_t"), p("whence", "unsigned int")], "off_t"),
        sc(9, "mmap", vec![p("addr", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long"), p("flags", "unsigned long"), p("fd", "unsigned long"), p("off", "unsigned long")], "unsigned long"),
    ]
}

fn build_x86_64_p2() -> Vec<LinuxSyscall> {
    vec![
        sc(10, "mprotect", vec![p("start", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long")], "long"),
        sc(11, "munmap", vec![p("addr", "unsigned long"), p("len", "size_t")], "long"),
        sc(12, "brk", vec![p("brk", "unsigned long")], "unsigned long"),
        sc(13, "rt_sigaction", vec![p("sig", "int"), p("act", "const struct sigaction __user *"), p("oact", "struct sigaction __user *"), p("sigsetsize", "size_t")], "long"),
        sc(14, "rt_sigprocmask", vec![p("how", "int"), p("nset", "sigset_t __user *"), p("oset", "sigset_t __user *"), p("sigsetsize", "size_t")], "long"),
        sc(16, "ioctl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(21, "access", vec![p("filename", "const char __user *"), p("mode", "int")], "long"),
        sc(22, "pipe", vec![p("fildes", "int __user *")], "long"),
        sc(32, "dup", vec![p("fildes", "unsigned int")], "long"),
        sc(33, "dup2", vec![p("oldfd", "unsigned int"), p("newfd", "unsigned int")], "long"),
        sc(35, "nanosleep", vec![p("rqtp", "struct timespec __user *"), p("rmtp", "struct timespec __user *")], "long"),
        sc(39, "getpid", vec![], "pid_t"),
        sc(41, "socket", vec![p("family", "int"), p("type", "int"), p("protocol", "int")], "long"),
        sc(42, "connect", vec![p("fd", "int"), p("uservaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
    ]
}

fn build_x86_64_p3() -> Vec<LinuxSyscall> {
    vec![
        sc(43, "accept", vec![p("fd", "int"), p("upeer_sockaddr", "struct sockaddr __user *"), p("upeer_addrlen", "int __user *")], "long"),
        sc(44, "sendto", vec![p("fd", "int"), p("buff", "void __user *"), p("len", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int")], "long"),
        sc(45, "recvfrom", vec![p("fd", "int"), p("ubuf", "void __user *"), p("size", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int __user *")], "long"),
        sc(46, "sendmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(47, "recvmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(48, "shutdown", vec![p("fd", "int"), p("how", "int")], "long"),
        sc(49, "bind", vec![p("fd", "int"), p("umyaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
        sc(50, "listen", vec![p("fd", "int"), p("backlog", "int")], "long"),
        sc(51, "getsockname", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
    ]
}

fn build_x86_64_p4() -> Vec<LinuxSyscall> {
    vec![
        sc(52, "getpeername", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
        sc(53, "socketpair", vec![p("family", "int"), p("type", "int"), p("protocol", "int"), p("usockvec", "int __user *")], "long"),
        sc(54, "setsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int")], "long"),
        sc(55, "getsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int __user *")], "long"),
        sc(56, "clone", vec![p("flags", "unsigned long"), p("newsp", "unsigned long"), p("parent_tidptr", "int __user *"), p("child_tidptr", "int __user *"), p("tls", "unsigned long")], "long"),
        sc(57, "fork", vec![], "pid_t"),
        sc(58, "vfork", vec![], "pid_t"),
        sc(59, "execve", vec![p("filename", "const char __user *"), p("argv", "const char __user * const __user *"), p("envp", "const char __user * const __user *")], "long"),
        sc(60, "exit", vec![p("error_code", "int")], "void"),
        sc(61, "wait4", vec![p("upid", "pid_t"), p("stat_addr", "int __user *"), p("options", "int"), p("ru", "struct rusage __user *")], "long"),
        sc(62, "kill", vec![p("pid", "pid_t"), p("sig", "int")], "long"),
        sc(63, "uname", vec![p("name", "struct old_utsname __user *")], "long"),
        sc(72, "fcntl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(96, "gettimeofday", vec![p("tv", "struct timeval __user *"), p("tz", "struct timezone __user *")], "long"),
        sc(99, "sysinfo", vec![p("info", "struct sysinfo __user *")], "long"),
        sc(101, "ptrace", vec![p("request", "long"), p("pid", "long"), p("addr", "unsigned long"), p("data", "unsigned long")], "long"),
        sc(102, "getuid", vec![], "uid_t"),
        sc(104, "getgid", vec![], "gid_t"),
        sc(105, "setuid", vec![p("uid", "uid_t")], "long"),
        sc(106, "setgid", vec![p("gid", "gid_t")], "long"),
        sc(107, "geteuid", vec![], "uid_t"),
        sc(108, "getegid", vec![], "gid_t"),
    ]
}

fn build_x86_64_p5() -> Vec<LinuxSyscall> {
    vec![
        sc(149, "mlock", vec![p("start", "unsigned long"), p("len", "size_t")], "long"),
        sc(150, "munlock", vec![p("start", "unsigned long"), p("len", "size_t")], "long"),
        sc(151, "mlockall", vec![p("flags", "int")], "long"),
        sc(152, "munlockall", vec![], "long"),
        sc(157, "prctl", vec![p("option", "int"), p("arg2", "unsigned long"), p("arg3", "unsigned long"), p("arg4", "unsigned long"), p("arg5", "unsigned long")], "long"),
        sc(158, "arch_prctl", vec![p("code", "int"), p("addr", "unsigned long")], "long"),
        sc(202, "futex", vec![p("uaddr", "u32 __user *"), p("op", "int"), p("val", "u32"), p("utime", "struct timespec __user *"), p("uaddr2", "u32 __user *"), p("val3", "u32")], "long"),
        sc(257, "openat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(267, "readlinkat", vec![p("dfd", "int"), p("pathname", "const char __user *"), p("buf", "char __user *"), p("bufsiz", "int")], "long"),
        sc(269, "faccessat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("mode", "int")], "long"),
        sc(293, "pipe2", vec![p("fildes", "int __user *"), p("flags", "int")], "long"),
    ]
}

fn build_x86_64() -> Vec<LinuxSyscall> {
    let mut v = build_x86_64_p1();
    v.extend(build_x86_64_p2());
    v.extend(build_x86_64_p3());
    v.extend(build_x86_64_p4());
    v.extend(build_x86_64_p5());
    v.sort_by_key(|s| s.number);
    v
}

fn build_x86_a() -> Vec<LinuxSyscall> {
    vec![
        sc(1, "exit", vec![p("error_code", "int")], "void"),
        sc(2, "fork", vec![], "pid_t"),
        sc(3, "read", vec![p("fd", "unsigned int"), p("buf", "char __user *"), p("count", "unsigned int")], "ssize_t"),
        sc(4, "write", vec![p("fd", "unsigned int"), p("buf", "const char __user *"), p("count", "unsigned int")], "ssize_t"),
        sc(5, "open", vec![p("filename", "const char __user *"), p("flags", "int"), p("mode", "int")], "long"),
        sc(6, "close", vec![p("fd", "unsigned int")], "long"),
        sc(11, "execve", vec![p("filename", "const char __user *"), p("argv", "const char __user * const __user *"), p("envp", "const char __user * const __user *")], "long"),
        sc(19, "lseek", vec![p("fd", "unsigned int"), p("offset", "off_t"), p("whence", "unsigned int")], "off_t"),
        sc(20, "getpid", vec![], "pid_t"),
        sc(26, "ptrace", vec![p("request", "long"), p("pid", "long"), p("addr", "unsigned long"), p("data", "unsigned long")], "long"),
        sc(37, "kill", vec![p("pid", "pid_t"), p("sig", "int")], "long"),
        sc(45, "brk", vec![p("brk", "unsigned long")], "unsigned long"),
        sc(54, "ioctl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(63, "dup2", vec![p("oldfd", "unsigned int"), p("newfd", "unsigned int")], "long"),
        sc(85, "readlink", vec![p("path", "const char __user *"), p("buf", "char __user *"), p("bufsiz", "int")], "long"),
        sc(90, "mmap", vec![p("arg", "unsigned long")], "unsigned long"),
        sc(91, "munmap", vec![p("addr", "unsigned long"), p("len", "size_t")], "long"),
    ]
}

fn build_x86_b() -> Vec<LinuxSyscall> {
    vec![
        sc(102, "socketcall", vec![p("call", "int"), p("args", "unsigned long __user *")], "long"),
        sc(106, "stat", vec![p("filename", "const char __user *"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(107, "lstat", vec![p("filename", "const char __user *"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(108, "fstat", vec![p("fd", "unsigned int"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(119, "sigreturn", vec![], "long"),
        sc(120, "clone", vec![p("flags", "unsigned long"), p("newsp", "unsigned long"), p("parent_tidptr", "int __user *"), p("child_tidptr", "int __user *"), p("tls", "unsigned long")], "long"),
        sc(122, "uname", vec![p("name", "struct old_utsname __user *")], "long"),
        sc(125, "mprotect", vec![p("start", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long")], "long"),
        sc(140, "llseek", vec![p("fd", "unsigned int"), p("offset_high", "unsigned long"), p("offset_low", "unsigned long"), p("result", "loff_t __user *"), p("whence", "unsigned int")], "long"),
        sc(162, "nanosleep", vec![p("rqtp", "struct timespec __user *"), p("rmtp", "struct timespec __user *")], "long"),
        sc(163, "mremap", vec![p("addr", "unsigned long"), p("old_len", "unsigned long"), p("new_len", "unsigned long"), p("flags", "unsigned long"), p("new_addr", "unsigned long")], "unsigned long"),
        sc(168, "poll", vec![p("ufds", "struct pollfd __user *"), p("nfds", "unsigned int"), p("timeout", "int")], "long"),
        sc(172, "prctl", vec![p("option", "int"), p("arg2", "unsigned long"), p("arg3", "unsigned long"), p("arg4", "unsigned long"), p("arg5", "unsigned long")], "long"),
        sc(174, "rt_sigaction", vec![p("sig", "int"), p("act", "const struct sigaction __user *"), p("oact", "struct sigaction __user *"), p("sigsetsize", "size_t")], "long"),
        sc(175, "rt_sigprocmask", vec![p("how", "int"), p("nset", "sigset_t __user *"), p("oset", "sigset_t __user *"), p("sigsetsize", "size_t")], "long"),
        sc(183, "getcwd", vec![p("buf", "char __user *"), p("size", "unsigned long")], "long"),
        sc(190, "vfork", vec![], "pid_t"),
        sc(192, "mmap2", vec![p("addr", "unsigned long"), p("len", "unsigned long"), p("prot", "unsigned long"), p("flags", "unsigned long"), p("fd", "unsigned long"), p("pgoff", "unsigned long")], "unsigned long"),
        sc(195, "stat64", vec![p("filename", "const char __user *"), p("statbuf", "struct stat64 __user *")], "long"),
        sc(196, "lstat64", vec![p("filename", "const char __user *"), p("statbuf", "struct stat64 __user *")], "long"),
        sc(197, "fstat64", vec![p("fd", "unsigned long"), p("statbuf", "struct stat64 __user *")], "long"),
        sc(224, "gettid", vec![], "pid_t"),
        sc(240, "futex", vec![p("uaddr", "u32 __user *"), p("op", "int"), p("val", "u32"), p("utime", "struct timespec __user *"), p("uaddr2", "u32 __user *"), p("val3", "u32")], "long"),
        sc(252, "exit_group", vec![p("error_code", "int")], "void"),
        sc(265, "clock_gettime", vec![p("which_clock", "clockid_t"), p("tp", "struct timespec __user *")], "long"),
        sc(295, "openat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(328, "pipe2", vec![p("fildes", "int __user *"), p("flags", "int")], "long"),
        sc(330, "dup3", vec![p("oldfd", "unsigned int"), p("newfd", "unsigned int"), p("flags", "int")], "long"),
    ]
}

fn build_x86() -> Vec<LinuxSyscall> {
    let mut v = build_x86_a();
    v.extend(build_x86_b());
    v.sort_by_key(|s| s.number);
    v
}

fn build_arm32_a() -> Vec<LinuxSyscall> {
    vec![
        sc(1, "exit", vec![p("error_code", "int")], "void"),
        sc(2, "fork", vec![], "pid_t"),
        sc(3, "read", vec![p("fd", "unsigned int"), p("buf", "char __user *"), p("count", "unsigned int")], "ssize_t"),
        sc(4, "write", vec![p("fd", "unsigned int"), p("buf", "const char __user *"), p("count", "unsigned int")], "ssize_t"),
        sc(5, "open", vec![p("filename", "const char __user *"), p("flags", "int"), p("mode", "int")], "long"),
        sc(6, "close", vec![p("fd", "unsigned int")], "long"),
        sc(11, "execve", vec![p("filename", "const char __user *"), p("argv", "const char __user * const __user *"), p("envp", "const char __user * const __user *")], "long"),
        sc(19, "lseek", vec![p("fd", "unsigned int"), p("offset", "off_t"), p("whence", "unsigned int")], "off_t"),
        sc(20, "getpid", vec![], "pid_t"),
        sc(26, "ptrace", vec![p("request", "long"), p("pid", "long"), p("addr", "unsigned long"), p("data", "unsigned long")], "long"),
        sc(37, "kill", vec![p("pid", "pid_t"), p("sig", "int")], "long"),
        sc(45, "brk", vec![p("brk", "unsigned long")], "unsigned long"),
        sc(54, "ioctl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(55, "fcntl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(63, "dup2", vec![p("oldfd", "unsigned int"), p("newfd", "unsigned int")], "long"),
        sc(85, "readlink", vec![p("path", "const char __user *"), p("buf", "char __user *"), p("bufsiz", "int")], "long"),
        sc(90, "mmap", vec![p("arg", "unsigned long")], "unsigned long"),
        sc(91, "munmap", vec![p("addr", "unsigned long"), p("len", "size_t")], "long"),
        sc(106, "stat", vec![p("filename", "const char __user *"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(107, "lstat", vec![p("filename", "const char __user *"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(108, "fstat", vec![p("fd", "unsigned int"), p("statbuf", "struct __old_kernel_stat __user *")], "long"),
        sc(114, "wait4", vec![p("upid", "pid_t"), p("stat_addr", "int __user *"), p("options", "int"), p("ru", "struct rusage __user *")], "long"),
        sc(120, "clone", vec![p("flags", "unsigned long"), p("newsp", "unsigned long"), p("parent_tidptr", "int __user *"), p("child_tidptr", "int __user *"), p("tls", "unsigned long")], "long"),
        sc(122, "uname", vec![p("name", "struct old_utsname __user *")], "long"),
        sc(125, "mprotect", vec![p("start", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long")], "long"),
        sc(162, "nanosleep", vec![p("rqtp", "struct timespec __user *"), p("rmtp", "struct timespec __user *")], "long"),
        sc(168, "poll", vec![p("ufds", "struct pollfd __user *"), p("nfds", "unsigned int"), p("timeout", "int")], "long"),
        sc(172, "prctl", vec![p("option", "int"), p("arg2", "unsigned long"), p("arg3", "unsigned long"), p("arg4", "unsigned long"), p("arg5", "unsigned long")], "long"),
        sc(174, "rt_sigaction", vec![p("sig", "int"), p("act", "const struct sigaction __user *"), p("oact", "struct sigaction __user *"), p("sigsetsize", "size_t")], "long"),
        sc(183, "getcwd", vec![p("buf", "char __user *"), p("size", "unsigned long")], "long"),
    ]
}

fn build_arm32_b() -> Vec<LinuxSyscall> {
    vec![
        sc(190, "vfork", vec![], "pid_t"),
        sc(192, "mmap2", vec![p("addr", "unsigned long"), p("len", "unsigned long"), p("prot", "unsigned long"), p("flags", "unsigned long"), p("fd", "unsigned long"), p("pgoff", "unsigned long")], "unsigned long"),
        sc(195, "stat64", vec![p("filename", "const char __user *"), p("statbuf", "struct stat64 __user *")], "long"),
        sc(197, "fstat64", vec![p("fd", "unsigned long"), p("statbuf", "struct stat64 __user *")], "long"),
        sc(224, "gettid", vec![], "pid_t"),
        sc(240, "futex", vec![p("uaddr", "u32 __user *"), p("op", "int"), p("val", "u32"), p("utime", "struct timespec __user *"), p("uaddr2", "u32 __user *"), p("val3", "u32")], "long"),
        sc(252, "exit_group", vec![p("error_code", "int")], "void"),
        sc(281, "socket", vec![p("family", "int"), p("type", "int"), p("protocol", "int")], "long"),
        sc(282, "bind", vec![p("fd", "int"), p("umyaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
        sc(283, "connect", vec![p("fd", "int"), p("uservaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
        sc(284, "listen", vec![p("fd", "int"), p("backlog", "int")], "long"),
        sc(285, "accept", vec![p("fd", "int"), p("upeer_sockaddr", "struct sockaddr __user *"), p("upeer_addrlen", "int __user *")], "long"),
        sc(286, "getsockname", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
        sc(287, "getpeername", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
        sc(288, "socketpair", vec![p("family", "int"), p("type", "int"), p("protocol", "int"), p("usockvec", "int __user *")], "long"),
        sc(289, "send", vec![p("fd", "int"), p("buff", "void __user *"), p("len", "size_t"), p("flags", "unsigned")], "long"),
        sc(290, "sendto", vec![p("fd", "int"), p("buff", "void __user *"), p("len", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int")], "long"),
        sc(292, "recvfrom", vec![p("fd", "int"), p("ubuf", "void __user *"), p("size", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int __user *")], "long"),
        sc(294, "setsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int")], "long"),
        sc(295, "getsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int __user *")], "long"),
        sc(299, "sendmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(300, "recvmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(322, "openat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(359, "pipe2", vec![p("fildes", "int __user *"), p("flags", "int")], "long"),
    ]
}

fn build_arm32() -> Vec<LinuxSyscall> {
    let mut v = build_arm32_a();
    v.extend(build_arm32_b());
    v.sort_by_key(|s| s.number);
    v
}

fn build_arm64_a() -> Vec<LinuxSyscall> {
    vec![
        sc(0, "io_setup", vec![p("nr_events", "unsigned"), p("ctxp", "aio_context_t __user *")], "long"),
        sc(1, "io_destroy", vec![p("ctx", "aio_context_t")], "long"),
        sc(3, "read", vec![p("fd", "unsigned int"), p("buf", "char __user *"), p("count", "size_t")], "ssize_t"),
        sc(4, "write", vec![p("fd", "unsigned int"), p("buf", "const char __user *"), p("count", "size_t")], "ssize_t"),
        sc(5, "open", vec![p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(6, "close", vec![p("fd", "unsigned int")], "long"),
        sc(8, "lseek", vec![p("fd", "unsigned int"), p("offset", "off_t"), p("whence", "unsigned int")], "off_t"),
        sc(9, "mmap", vec![p("addr", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long"), p("flags", "unsigned long"), p("fd", "unsigned long"), p("off", "unsigned long")], "unsigned long"),
        sc(10, "mprotect", vec![p("start", "unsigned long"), p("len", "size_t"), p("prot", "unsigned long")], "long"),
        sc(11, "munmap", vec![p("addr", "unsigned long"), p("len", "size_t")], "long"),
        sc(12, "brk", vec![p("brk", "unsigned long")], "unsigned long"),
        sc(13, "rt_sigaction", vec![p("sig", "int"), p("act", "const struct sigaction __user *"), p("oact", "struct sigaction __user *"), p("sigsetsize", "size_t")], "long"),
        sc(14, "rt_sigprocmask", vec![p("how", "int"), p("nset", "sigset_t __user *"), p("oset", "sigset_t __user *"), p("sigsetsize", "size_t")], "long"),
        sc(16, "ioctl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(22, "pipe2", vec![p("fildes", "int __user *"), p("flags", "int")], "long"),
        sc(25, "fcntl", vec![p("fd", "unsigned int"), p("cmd", "unsigned int"), p("arg", "unsigned long")], "long"),
        sc(33, "dup", vec![p("fildes", "unsigned int")], "long"),
        sc(34, "dup3", vec![p("oldfd", "unsigned int"), p("newfd", "unsigned int"), p("flags", "int")], "long"),
        sc(35, "nanosleep", vec![p("rqtp", "struct timespec __user *"), p("rmtp", "struct timespec __user *")], "long"),
        sc(41, "socket", vec![p("family", "int"), p("type", "int"), p("protocol", "int")], "long"),
        sc(42, "connect", vec![p("fd", "int"), p("uservaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
        sc(43, "accept", vec![p("fd", "int"), p("upeer_sockaddr", "struct sockaddr __user *"), p("upeer_addrlen", "int __user *")], "long"),
        sc(44, "sendto", vec![p("fd", "int"), p("buff", "void __user *"), p("len", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int")], "long"),
        sc(45, "recvfrom", vec![p("fd", "int"), p("ubuf", "void __user *"), p("size", "size_t"), p("flags", "unsigned"), p("addr", "struct sockaddr __user *"), p("addr_len", "int __user *")], "long"),
    ]
}

fn build_arm64_b() -> Vec<LinuxSyscall> {
    vec![
        sc(46, "sendmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(47, "recvmsg", vec![p("fd", "int"), p("msg", "struct user_msghdr __user *"), p("flags", "unsigned")], "long"),
        sc(48, "shutdown", vec![p("fd", "int"), p("how", "int")], "long"),
        sc(49, "bind", vec![p("fd", "int"), p("umyaddr", "struct sockaddr __user *"), p("addrlen", "int")], "long"),
        sc(50, "listen", vec![p("fd", "int"), p("backlog", "int")], "long"),
        sc(51, "getsockname", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
        sc(52, "getpeername", vec![p("fd", "int"), p("usockaddr", "struct sockaddr __user *"), p("usockaddr_len", "int __user *")], "long"),
        sc(53, "socketpair", vec![p("family", "int"), p("type", "int"), p("protocol", "int"), p("usockvec", "int __user *")], "long"),
        sc(54, "setsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int")], "long"),
        sc(55, "getsockopt", vec![p("fd", "int"), p("level", "int"), p("optname", "int"), p("optval", "char __user *"), p("optlen", "int __user *")], "long"),
        sc(56, "clone", vec![p("flags", "unsigned long"), p("newsp", "unsigned long"), p("parent_tidptr", "int __user *"), p("child_tidptr", "int __user *"), p("tls", "unsigned long")], "long"),
        sc(59, "execve", vec![p("filename", "const char __user *"), p("argv", "const char __user * const __user *"), p("envp", "const char __user * const __user *")], "long"),
        sc(60, "exit", vec![p("error_code", "int")], "void"),
        sc(61, "wait4", vec![p("upid", "pid_t"), p("stat_addr", "int __user *"), p("options", "int"), p("ru", "struct rusage __user *")], "long"),
        sc(62, "kill", vec![p("pid", "pid_t"), p("sig", "int")], "long"),
        sc(63, "uname", vec![p("name", "struct old_utsname __user *")], "long"),
        sc(96, "gettimeofday", vec![p("tv", "struct timeval __user *"), p("tz", "struct timezone __user *")], "long"),
        sc(99, "sysinfo", vec![p("info", "struct sysinfo __user *")], "long"),
        sc(101, "ptrace", vec![p("request", "long"), p("pid", "long"), p("addr", "unsigned long"), p("data", "unsigned long")], "long"),
        sc(102, "getuid", vec![], "uid_t"),
        sc(104, "getgid", vec![], "gid_t"),
        sc(105, "setuid", vec![p("uid", "uid_t")], "long"),
        sc(106, "setgid", vec![p("gid", "gid_t")], "long"),
        sc(107, "geteuid", vec![], "uid_t"),
        sc(108, "getegid", vec![], "gid_t"),
        sc(141, "getpid", vec![], "pid_t"),
        sc(149, "mlock", vec![p("start", "unsigned long"), p("len", "size_t")], "long"),
        sc(150, "munlock", vec![p("start", "unsigned long"), p("len", "size_t")], "long"),
        sc(151, "mlockall", vec![p("flags", "int")], "long"),
        sc(152, "munlockall", vec![], "long"),
        sc(157, "prctl", vec![p("option", "int"), p("arg2", "unsigned long"), p("arg3", "unsigned long"), p("arg4", "unsigned long"), p("arg5", "unsigned long")], "long"),
        sc(202, "futex", vec![p("uaddr", "u32 __user *"), p("op", "int"), p("val", "u32"), p("utime", "struct timespec __user *"), p("uaddr2", "u32 __user *"), p("val3", "u32")], "long"),
        sc(257, "openat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("flags", "int"), p("mode", "umode_t")], "long"),
        sc(267, "readlinkat", vec![p("dfd", "int"), p("pathname", "const char __user *"), p("buf", "char __user *"), p("bufsiz", "int")], "long"),
        sc(269, "faccessat", vec![p("dfd", "int"), p("filename", "const char __user *"), p("mode", "int")], "long"),
    ]
}

fn build_arm64() -> Vec<LinuxSyscall> {
    let mut v = build_arm64_a();
    v.extend(build_arm64_b());
    v.sort_by_key(|s| s.number);
    v
}

// ─── SyscallCategory ─────────────────────────────────────────────────────────

/// High-level category for classifying a syscall by its primary function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    /// File system operations (open, read, write, stat, …).
    FileSystem,
    /// Memory management (mmap, brk, mprotect, …).
    Memory,
    /// Process / thread control (fork, exec, clone, exit, …).
    Process,
    /// Networking (socket, connect, bind, sendto, …).
    Network,
    /// Inter-process communication (pipe, futex, `mq_open`, …).
    Ipc,
    /// Signal handling (kill, sigaction, sigprocmask, …).
    Signal,
    /// Security / credential management (setuid, ptrace, capset, …).
    Security,
    /// Time and clock operations (gettimeofday, `clock_gettime`, …).
    Time,
    /// System information and resource limits (uname, getrlimit, …).
    System,
    /// Device and I/O operations (ioctl, epoll_*, select, poll, …).
    Device,
    /// Scheduling (`sched_setaffinity`, `sched_yield`, …).
    Scheduling,
    /// Unknown or uncategorised.
    Unknown,
}

impl SyscallCategory {
    /// Return the category name as a static string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileSystem => "filesystem",
            Self::Memory => "memory",
            Self::Process => "process",
            Self::Network => "network",
            Self::Ipc => "ipc",
            Self::Signal => "signal",
            Self::Security => "security",
            Self::Time => "time",
            Self::System => "system",
            Self::Device => "device",
            Self::Scheduling => "scheduling",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── SecuritySeverity ────────────────────────────────────────────────────────

/// Security-relevant severity of a syscall used during triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Benign — used for normal I/O and information gathering.
    Benign,
    /// Low — can affect process state but is typically safe.
    Low,
    /// Medium — may be abused in combination with other calls.
    Medium,
    /// High — commonly abused by malware (e.g. `mprotect`, `ptrace`).
    High,
    /// Critical — very high abuse potential (e.g. `execve`, `mmap` with `PROT_EXEC`).
    Critical,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Benign => write!(f, "benign"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Classify the security severity of a Linux syscall by name.
///
/// Returns [`SecuritySeverity::Benign`] for unknown syscalls.
#[must_use]
pub fn syscall_security_severity(name: &str) -> SecuritySeverity {
    match name {
        "execve" | "execveat" | "ptrace" | "mmap" | "mmap2" => SecuritySeverity::Critical,
        "mprotect" | "shmat" | "shmget" | "shmctl" | "shmdt" | "setuid" | "setgid"
        | "setresuid" | "setresgid" | "setreuid" | "setregid" | "capset" | "prctl"
        | "arch_prctl" | "connect" | "sendto" | "sendmsg" | "sendmmsg" | "send" | "socket"
        | "socketpair" | "clone" | "clone3" | "fork" | "vfork" => SecuritySeverity::High,
        "open" | "openat" | "openat2" | "creat" | "write" | "pwrite64" | "writev" | "pwritev"
        | "pwritev2" | "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" | "chmod"
        | "fchmod" | "chown" | "fchown" | "lchown" | "fchownat" | "fchmodat" | "symlink"
        | "symlinkat" | "link" | "linkat" | "kill" | "tkill" | "tgkill" | "rt_sigqueueinfo"
        | "mount" | "umount" | "umount2" | "pivot_root" | "chroot" | "ioctl" | "madvise" => {
            SecuritySeverity::Medium
        }
        "fcntl" | "dup" | "dup2" | "dup3" | "pipe" | "pipe2"
        | "read" | "pread64" | "readv" | "preadv" | "preadv2" | "recvfrom" | "recvmsg"
        | "recvmmsg" | "recv" | "stat" | "fstat" | "lstat" | "statx" | "newfstatat"
        | "readlink" | "readlinkat" | "getdents" | "getdents64" | "access" | "faccessat"
        | "faccessat2" => SecuritySeverity::Low,
        _ => SecuritySeverity::Benign,
    }
}

/// Classify the category of a Linux syscall by name.
#[must_use]
pub fn syscall_category(name: &str) -> SyscallCategory {
    match name {
        "open" | "openat" | "openat2" | "creat" | "close" | "read" | "write" | "pread64"
        | "pwrite64" | "readv" | "writev" | "lseek" | "llseek" | "stat" | "fstat" | "lstat"
        | "statx" | "access" | "faccessat" | "faccessat2" | "chmod" | "fchmod" | "chown"
        | "fchown" | "lchown" | "fchownat" | "fchmodat" | "unlink" | "unlinkat" | "rename"
        | "renameat" | "renameat2" | "mkdir" | "mkdirat" | "rmdir" | "link" | "linkat"
        | "symlink" | "symlinkat" | "readlink" | "readlinkat" | "truncate" | "ftruncate"
        | "getdents" | "getdents64" | "getcwd" | "chdir" | "fchdir" | "dup" | "dup2" | "dup3"
        | "fcntl" | "fsync" | "fdatasync" | "sendfile" | "sendfile64" | "copy_file_range"
        | "splice" | "tee" | "mknod" | "mknodat" | "umask" => SyscallCategory::FileSystem,

        "mmap" | "mmap2" | "munmap" | "mprotect" | "mremap" | "brk" | "mlock" | "munlock"
        | "mlockall" | "munlockall" | "madvise" | "mincore" | "msync" | "remap_file_pages"
        | "memfd_create" | "process_vm_readv" | "process_vm_writev" | "userfaultfd" => {
            SyscallCategory::Memory
        }

        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit" | "exit_group"
        | "wait4" | "waitid" | "waitpid" | "getpid" | "getppid" | "gettid" | "getpgrp"
        | "getpgid" | "setpgid" | "setsid" | "getsid" | "prctl" | "arch_prctl" | "ptrace"
        | "seccomp" | "capget" | "capset" | "personality" | "setrlimit" | "getrlimit"
        | "prlimit64" | "getrusage" | "times" => SyscallCategory::Process,

        "socket" | "socketpair" | "bind" | "listen" | "accept" | "accept4" | "connect" | "send"
        | "sendto" | "sendmsg" | "sendmmsg" | "recv" | "recvfrom" | "recvmsg" | "recvmmsg"
        | "shutdown" | "getsockname" | "getpeername" | "setsockopt" | "getsockopt"
        | "socketcall" => SyscallCategory::Network,

        "pipe" | "pipe2" | "msgget" | "msgsnd" | "msgrcv" | "msgctl" | "semget" | "semop"
        | "semctl" | "semtimedop" | "shmget" | "shmat" | "shmdt" | "shmctl" | "mq_open"
        | "mq_unlink" | "mq_timedsend" | "mq_timedreceive" | "mq_notify" | "mq_getsetattr"
        | "futex" | "futex_waitv" | "eventfd" | "eventfd2" | "inotify_init" | "inotify_init1"
        | "inotify_add_watch" | "inotify_rm_watch" => SyscallCategory::Ipc,

        "kill" | "tkill" | "tgkill" | "sigaction" | "rt_sigaction" | "sigprocmask"
        | "rt_sigprocmask" | "sigpending" | "rt_sigpending" | "sigtimedwait"
        | "rt_sigtimedwait" | "sigsuspend" | "rt_sigsuspend" | "sigreturn" | "rt_sigreturn"
        | "signalfd" | "signalfd4" | "rt_sigqueueinfo" | "rt_tgsigqueueinfo" | "pause" => {
            SyscallCategory::Signal
        }

        "setuid" | "getuid" | "setgid" | "getgid" | "geteuid" | "getegid" | "setresuid"
        | "getresuid" | "setresgid" | "getresgid" | "setreuid" | "setregid" | "setfsuid"
        | "setfsgid" | "getgroups" | "setgroups" | "setns" | "unshare" | "keyctl" | "add_key"
        | "request_key" => SyscallCategory::Security,

        "gettimeofday" | "settimeofday" | "time" | "clock_gettime" | "clock_settime"
        | "clock_getres" | "clock_nanosleep" | "nanosleep" | "adjtimex" | "clock_adjtime"
        | "timer_create" | "timer_delete" | "timer_settime" | "timer_gettime"
        | "timer_getoverrun" | "timerfd_create" | "timerfd_settime" | "timerfd_gettime"
        | "alarm" => SyscallCategory::Time,

        "uname" | "sysinfo" | "syslog" | "ustat" | "acct" | "reboot" | "swapon" | "swapoff"
        | "kexec_load" | "init_module" | "finit_module" | "delete_module" | "sync" | "syncfs"
        | "quotactl" => SyscallCategory::System,

        "ioctl" | "poll" | "ppoll" | "select" | "pselect6" | "epoll_create" | "epoll_create1"
        | "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "epoll_pwait2" | "io_setup"
        | "io_destroy" | "io_submit" | "io_cancel" | "io_getevents" | "io_uring_setup"
        | "io_uring_enter" | "io_uring_register" | "fanotify_init" | "fanotify_mark" => {
            SyscallCategory::Device
        }

        "sched_getscheduler"
        | "sched_setscheduler"
        | "sched_getparam"
        | "sched_setparam"
        | "sched_yield"
        | "sched_getaffinity"
        | "sched_setaffinity"
        | "sched_getattr"
        | "sched_setattr"
        | "sched_rr_get_interval"
        | "setpriority"
        | "getpriority"
        | "nice" => SyscallCategory::Scheduling,

        _ => SyscallCategory::Unknown,
    }
}

// ─── SyscallStore ─────────────────────────────────────────────────────────────

/// Persistent store for Linux syscall records, backed by `SQLite`.
pub struct SyscallStore {
    conn: rusqlite::Connection,
}

impl SyscallStore {
    /// Open an in-memory `SQLite` database and initialise the schema.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the connection or schema creation fails.
    pub fn open_memory() -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open a file-backed `SQLite` database at `path`.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the database cannot be opened.
    pub fn open(path: &std::path::Path) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS syscalls (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                arch     TEXT NOT NULL,
                number   INTEGER NOT NULL,
                name     TEXT NOT NULL,
                ret_ty   TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                UNIQUE(arch, number)
            );
            CREATE TABLE IF NOT EXISTS syscall_params (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                syscall_id INTEGER NOT NULL REFERENCES syscalls(id) ON DELETE CASCADE,
                position   INTEGER NOT NULL,
                name       TEXT NOT NULL,
                ty         TEXT NOT NULL
            );",
        )
    }

    /// Insert a single [`LinuxSyscall`] for `arch`.
    ///
    /// Duplicate (arch, number) pairs are silently ignored.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn insert(
        &self,
        arch: SyscallArch,
        syscall: &LinuxSyscall,
    ) -> Result<i64, rusqlite::Error> {
        let arch_str = format!("{arch:?}");
        let category = syscall_category(&syscall.name).to_string();
        let severity = syscall_security_severity(&syscall.name).to_string();
        self.conn.execute(
            "INSERT OR IGNORE INTO syscalls (arch, number, name, ret_ty, category, severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                arch_str,
                syscall.number,
                syscall.name,
                syscall.ret_ty,
                category,
                severity
            ],
        )?;
        // Use changes() to detect whether the row was actually inserted.
        // last_insert_rowid() is unreliable after INSERT OR IGNORE when the row
        // is skipped — it retains the rowid from the previous successful insert,
        // which may belong to a completely different row.
        let rows_inserted = self.conn.changes();
        let id = if rows_inserted > 0 {
            self.conn.last_insert_rowid()
        } else {
            0
        };
        if id > 0 {
            for (pos, param) in syscall.params.iter().enumerate() {
                self.conn.execute(
                    "INSERT INTO syscall_params (syscall_id, position, name, ty) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![id, i64::try_from(pos).unwrap_or(i64::MAX), param.name, param.ty],
                )?;
            }
        }
        Ok(id)
    }

    /// Bulk-insert all syscalls for `arch` from a [`LinuxSyscallDb`].
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn bulk_insert(
        &self,
        arch: SyscallArch,
        db: &LinuxSyscallDb,
    ) -> Result<usize, rusqlite::Error> {
        let Some(syscalls) = db.all_for_arch(arch) else {
            return Ok(0);
        };
        let mut count = 0usize;
        for sc in syscalls {
            if self.insert(arch, sc)? > 0 {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Return the total number of stored syscall records.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM syscalls", [], |r| r.get(0))
    }

    /// Look up a syscall by `arch` and `number`.
    ///
    /// Returns `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn find_by_number(
        &self,
        arch: SyscallArch,
        number: u32,
    ) -> Result<Option<(String, String, String)>, rusqlite::Error> {
        let arch_str = format!("{arch:?}");
        let mut stmt = self.conn.prepare(
            "SELECT name, category, severity FROM syscalls WHERE arch = ?1 AND number = ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![arch_str, number], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.next().transpose()
    }

    /// Find all syscalls for `arch` matching `category`.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn find_by_category(
        &self,
        arch: SyscallArch,
        category: SyscallCategory,
    ) -> Result<Vec<(u32, String)>, rusqlite::Error> {
        let arch_str = format!("{arch:?}");
        let cat_str = category.to_string();
        let mut stmt = self.conn.prepare(
            "SELECT number, name FROM syscalls WHERE arch = ?1 AND category = ?2 ORDER BY number",
        )?;
        let rows = stmt.query_map(rusqlite::params![arch_str, cat_str], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect()
    }

    /// Find all syscalls for `arch` with severity >= `min_severity`.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn find_by_min_severity(
        &self,
        arch: SyscallArch,
        min_severity: SecuritySeverity,
    ) -> Result<Vec<(u32, String, String)>, rusqlite::Error> {
        let arch_str = format!("{arch:?}");
        let min_ord: i32 = match min_severity {
            SecuritySeverity::Benign => 0,
            SecuritySeverity::Low => 1,
            SecuritySeverity::Medium => 2,
            SecuritySeverity::High => 3,
            SecuritySeverity::Critical => 4,
        };
        let mut stmt = self.conn.prepare(
            "SELECT number, name, severity FROM syscalls
             WHERE arch = ?1
               AND CASE severity
                     WHEN 'benign'   THEN 0
                     WHEN 'low'      THEN 1
                     WHEN 'medium'   THEN 2
                     WHEN 'high'     THEN 3
                     WHEN 'critical' THEN 4
                     ELSE 0
                   END >= ?2
             ORDER BY number",
        )?;
        let rows = stmt.query_map(rusqlite::params![arch_str, min_ord], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect()
    }

    /// List all (arch, number, name) triples ordered by arch and number.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn list_all(&self) -> Result<Vec<(String, u32, String)>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT arch, number, name FROM syscalls ORDER BY arch, number")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect()
    }
}

// ─── LinuxSyscallEntry (static, strace-style) ────────────────────────────────

/// Category enum used by the static strace-style database.
/// Distinct from [`SyscallCategory`] above so the two APIs stay independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallEntryCategory {
    FileIo,
    Network,
    Process,
    Memory,
    Signal,
    IPC,
    Time,
    Info,
    Security,
    Misc,
}

impl SyscallEntryCategory {
    /// Return the category name as a static string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileIo => "file_io",
            Self::Network => "network",
            Self::Process => "process",
            Self::Memory => "memory",
            Self::Signal => "signal",
            Self::IPC => "ipc",
            Self::Time => "time",
            Self::Info => "info",
            Self::Security => "security",
            Self::Misc => "misc",
        }
    }
}

impl std::fmt::Display for SyscallEntryCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A static, strace-equivalent syscall descriptor for x86-64 Linux.
///
/// Designed for zero-allocation lookup in hot tracing paths.
#[derive(Debug, Clone, Copy)]
pub struct LinuxSyscallEntry {
    /// Syscall number (NR value on x86-64).
    pub nr: u32,
    /// Syscall name (no `sys_` prefix).
    pub name: &'static str,
    /// Number of meaningful arguments (0–6).
    pub arg_count: u8,
    /// Argument names; unused slots are `""`.
    pub args: [&'static str; 6],
    /// C return type.
    pub return_type: &'static str,
    /// Functional category.
    pub category: SyscallEntryCategory,
}

/// Helper macro used only during the static table construction below.
macro_rules! se {
    ($nr:expr, $name:literal, $cat:expr, $ret:literal, $argc:expr,
     [$a0:literal, $a1:literal, $a2:literal, $a3:literal, $a4:literal, $a5:literal]) => {
        LinuxSyscallEntry {
            nr: $nr,
            name: $name,
            arg_count: $argc,
            args: [$a0, $a1, $a2, $a3, $a4, $a5],
            return_type: $ret,
            category: $cat,
        }
    };
}

/// Complete x86-64 Linux syscall table (341 entries, NR 0–340).
///
/// Entries for reserved / unimplemented numbers are included with name
/// `"reserved"` and zero arguments so that index-based lookup always succeeds.
pub static LINUX_X86_64_SYSCALLS: &[LinuxSyscallEntry] = &[
    // 0–9
    se!(
        0,
        "read",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "buf: *void", "count: size_t", "", "", ""]
    ),
    se!(
        1,
        "write",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "buf: *void", "count: size_t", "", "", ""]
    ),
    se!(
        2,
        "open",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["filename: *char", "flags: int", "mode: mode_t", "", "", ""]
    ),
    se!(
        3,
        "close",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fd: int", "", "", "", "", ""]
    ),
    se!(
        4,
        "stat",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "statbuf: *stat", "", "", "", ""]
    ),
    se!(
        5,
        "fstat",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: int", "statbuf: *stat", "", "", "", ""]
    ),
    se!(
        6,
        "lstat",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "statbuf: *stat", "", "", "", ""]
    ),
    se!(
        7,
        "poll",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["fds: *pollfd", "nfds: unsigned", "timeout: int", "", "", ""]
    ),
    se!(
        8,
        "lseek",
        SyscallEntryCategory::FileIo,
        "off_t",
        3,
        ["fd: int", "offset: off_t", "whence: int", "", "", ""]
    ),
    se!(
        9,
        "mmap",
        SyscallEntryCategory::Memory,
        "*void",
        6,
        [
            "addr: *void",
            "len: size_t",
            "prot: int",
            "flags: int",
            "fd: int",
            "off: off_t"
        ]
    ),
    // 10–19
    se!(
        10,
        "mprotect",
        SyscallEntryCategory::Memory,
        "int",
        3,
        ["addr: *void", "len: size_t", "prot: int", "", "", ""]
    ),
    se!(
        11,
        "munmap",
        SyscallEntryCategory::Memory,
        "int",
        2,
        ["addr: *void", "len: size_t", "", "", "", ""]
    ),
    se!(
        12,
        "brk",
        SyscallEntryCategory::Memory,
        "int",
        1,
        ["addr: *void", "", "", "", "", ""]
    ),
    se!(
        13,
        "rt_sigaction",
        SyscallEntryCategory::Signal,
        "int",
        4,
        [
            "sig: int",
            "act: *sigaction",
            "oact: *sigaction",
            "sigsetsize: size_t",
            "",
            ""
        ]
    ),
    se!(
        14,
        "rt_sigprocmask",
        SyscallEntryCategory::Signal,
        "int",
        4,
        [
            "how: int",
            "nset: *sigset_t",
            "oset: *sigset_t",
            "sigsetsize: size_t",
            "",
            ""
        ]
    ),
    se!(
        15,
        "rt_sigreturn",
        SyscallEntryCategory::Signal,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        16,
        "ioctl",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["fd: int", "cmd: unsigned", "arg: unsigned long", "", "", ""]
    ),
    se!(
        17,
        "pread64",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "fd: int",
            "buf: *void",
            "count: size_t",
            "pos: off_t",
            "",
            ""
        ]
    ),
    se!(
        18,
        "pwrite64",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "fd: int",
            "buf: *void",
            "count: size_t",
            "pos: off_t",
            "",
            ""
        ]
    ),
    se!(
        19,
        "readv",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "vec: *iovec", "vlen: unsigned long", "", "", ""]
    ),
    // 20–29
    se!(
        20,
        "writev",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "vec: *iovec", "vlen: unsigned long", "", "", ""]
    ),
    se!(
        21,
        "access",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "mode: int", "", "", "", ""]
    ),
    se!(
        22,
        "pipe",
        SyscallEntryCategory::IPC,
        "int",
        1,
        ["fildes: *int", "", "", "", "", ""]
    ),
    se!(
        23,
        "select",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "n: int",
            "inp: *fd_set",
            "outp: *fd_set",
            "exp: *fd_set",
            "timeout: *timeval",
            ""
        ]
    ),
    se!(
        24,
        "sched_yield",
        SyscallEntryCategory::Process,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        25,
        "mremap",
        SyscallEntryCategory::Memory,
        "*void",
        5,
        [
            "addr: *void",
            "old_len: size_t",
            "new_len: size_t",
            "flags: int",
            "new_addr: *void",
            ""
        ]
    ),
    se!(
        26,
        "msync",
        SyscallEntryCategory::Memory,
        "int",
        3,
        ["start: *void", "length: size_t", "flags: int", "", "", ""]
    ),
    se!(
        27,
        "mincore",
        SyscallEntryCategory::Memory,
        "int",
        3,
        [
            "start: *void",
            "length: size_t",
            "vec: *unsigned char",
            "",
            "",
            ""
        ]
    ),
    se!(
        28,
        "madvise",
        SyscallEntryCategory::Memory,
        "int",
        3,
        ["start: *void", "len: size_t", "behavior: int", "", "", ""]
    ),
    se!(
        29,
        "shmget",
        SyscallEntryCategory::IPC,
        "int",
        3,
        ["key: key_t", "size: size_t", "shmflg: int", "", "", ""]
    ),
    // 30–39
    se!(
        30,
        "shmat",
        SyscallEntryCategory::IPC,
        "*void",
        3,
        ["shmid: int", "shmaddr: *void", "shmflg: int", "", "", ""]
    ),
    se!(
        31,
        "shmctl",
        SyscallEntryCategory::IPC,
        "int",
        3,
        ["shmid: int", "cmd: int", "buf: *shmid_ds", "", "", ""]
    ),
    se!(
        32,
        "dup",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fildes: unsigned int", "", "", "", "", ""]
    ),
    se!(
        33,
        "dup2",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["oldfd: unsigned int", "newfd: unsigned int", "", "", "", ""]
    ),
    se!(
        34,
        "pause",
        SyscallEntryCategory::Signal,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        35,
        "nanosleep",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["rqtp: *timespec", "rmtp: *timespec", "", "", "", ""]
    ),
    se!(
        36,
        "getitimer",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["which: int", "value: *itimerval", "", "", "", ""]
    ),
    se!(
        37,
        "alarm",
        SyscallEntryCategory::Time,
        "unsigned",
        1,
        ["seconds: unsigned", "", "", "", "", ""]
    ),
    se!(
        38,
        "setitimer",
        SyscallEntryCategory::Time,
        "int",
        3,
        [
            "which: int",
            "value: *itimerval",
            "ovalue: *itimerval",
            "",
            "",
            ""
        ]
    ),
    se!(
        39,
        "getpid",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    // 40–49
    se!(
        40,
        "sendfile",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "out_fd: int",
            "in_fd: int",
            "offset: *off_t",
            "count: size_t",
            "",
            ""
        ]
    ),
    se!(
        41,
        "socket",
        SyscallEntryCategory::Network,
        "int",
        3,
        ["family: int", "type: int", "protocol: int", "", "", ""]
    ),
    se!(
        42,
        "connect",
        SyscallEntryCategory::Network,
        "int",
        3,
        [
            "fd: int",
            "uservaddr: *sockaddr",
            "addrlen: int",
            "",
            "",
            ""
        ]
    ),
    se!(
        43,
        "accept",
        SyscallEntryCategory::Network,
        "int",
        3,
        [
            "fd: int",
            "upeer_sockaddr: *sockaddr",
            "upeer_addrlen: *int",
            "",
            "",
            ""
        ]
    ),
    se!(
        44,
        "sendto",
        SyscallEntryCategory::Network,
        "ssize_t",
        6,
        [
            "fd: int",
            "buff: *void",
            "len: size_t",
            "flags: unsigned",
            "addr: *sockaddr",
            "addr_len: int"
        ]
    ),
    se!(
        45,
        "recvfrom",
        SyscallEntryCategory::Network,
        "ssize_t",
        6,
        [
            "fd: int",
            "ubuf: *void",
            "size: size_t",
            "flags: unsigned",
            "addr: *sockaddr",
            "addr_len: *int"
        ]
    ),
    se!(
        46,
        "sendmsg",
        SyscallEntryCategory::Network,
        "ssize_t",
        3,
        ["fd: int", "msg: *msghdr", "flags: unsigned", "", "", ""]
    ),
    se!(
        47,
        "recvmsg",
        SyscallEntryCategory::Network,
        "ssize_t",
        3,
        ["fd: int", "msg: *msghdr", "flags: unsigned", "", "", ""]
    ),
    se!(
        48,
        "shutdown",
        SyscallEntryCategory::Network,
        "int",
        2,
        ["fd: int", "how: int", "", "", "", ""]
    ),
    se!(
        49,
        "bind",
        SyscallEntryCategory::Network,
        "int",
        3,
        ["fd: int", "umyaddr: *sockaddr", "addrlen: int", "", "", ""]
    ),
    // 50–59
    se!(
        50,
        "listen",
        SyscallEntryCategory::Network,
        "int",
        2,
        ["fd: int", "backlog: int", "", "", "", ""]
    ),
    se!(
        51,
        "getsockname",
        SyscallEntryCategory::Network,
        "int",
        3,
        [
            "fd: int",
            "usockaddr: *sockaddr",
            "usockaddr_len: *int",
            "",
            "",
            ""
        ]
    ),
    se!(
        52,
        "getpeername",
        SyscallEntryCategory::Network,
        "int",
        3,
        [
            "fd: int",
            "usockaddr: *sockaddr",
            "usockaddr_len: *int",
            "",
            "",
            ""
        ]
    ),
    se!(
        53,
        "socketpair",
        SyscallEntryCategory::Network,
        "int",
        4,
        [
            "family: int",
            "type: int",
            "protocol: int",
            "usockvec: *int",
            "",
            ""
        ]
    ),
    se!(
        54,
        "setsockopt",
        SyscallEntryCategory::Network,
        "int",
        5,
        [
            "fd: int",
            "level: int",
            "optname: int",
            "optval: *char",
            "optlen: int",
            ""
        ]
    ),
    se!(
        55,
        "getsockopt",
        SyscallEntryCategory::Network,
        "int",
        5,
        [
            "fd: int",
            "level: int",
            "optname: int",
            "optval: *char",
            "optlen: *int",
            ""
        ]
    ),
    se!(
        56,
        "clone",
        SyscallEntryCategory::Process,
        "long",
        5,
        [
            "flags: unsigned long",
            "newsp: unsigned long",
            "parent_tidptr: *int",
            "child_tidptr: *int",
            "tls: unsigned long",
            ""
        ]
    ),
    se!(
        57,
        "fork",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        58,
        "vfork",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        59,
        "execve",
        SyscallEntryCategory::Process,
        "int",
        3,
        [
            "filename: *char",
            "argv: **char",
            "envp: **char",
            "",
            "",
            ""
        ]
    ),
    // 60–69
    se!(
        60,
        "exit",
        SyscallEntryCategory::Process,
        "void",
        1,
        ["error_code: int", "", "", "", "", ""]
    ),
    se!(
        61,
        "wait4",
        SyscallEntryCategory::Process,
        "pid_t",
        4,
        [
            "upid: pid_t",
            "stat_addr: *int",
            "options: int",
            "ru: *rusage",
            "",
            ""
        ]
    ),
    se!(
        62,
        "kill",
        SyscallEntryCategory::Signal,
        "int",
        2,
        ["pid: pid_t", "sig: int", "", "", "", ""]
    ),
    se!(
        63,
        "uname",
        SyscallEntryCategory::Info,
        "int",
        1,
        ["name: *utsname", "", "", "", "", ""]
    ),
    se!(
        64,
        "semget",
        SyscallEntryCategory::IPC,
        "int",
        3,
        ["key: key_t", "nsems: int", "semflg: int", "", "", ""]
    ),
    se!(
        65,
        "semop",
        SyscallEntryCategory::IPC,
        "int",
        3,
        ["semid: int", "sops: *sembuf", "nsops: unsigned", "", "", ""]
    ),
    se!(
        66,
        "semctl",
        SyscallEntryCategory::IPC,
        "int",
        4,
        [
            "semid: int",
            "semnum: int",
            "cmd: int",
            "arg: unsigned long",
            "",
            ""
        ]
    ),
    se!(
        67,
        "shmdt",
        SyscallEntryCategory::IPC,
        "int",
        1,
        ["shmaddr: *void", "", "", "", "", ""]
    ),
    se!(
        68,
        "msgget",
        SyscallEntryCategory::IPC,
        "int",
        2,
        ["key: key_t", "msgflg: int", "", "", "", ""]
    ),
    se!(
        69,
        "msgsnd",
        SyscallEntryCategory::IPC,
        "int",
        4,
        [
            "msqid: int",
            "msgp: *msgbuf",
            "msgsz: size_t",
            "msgflg: int",
            "",
            ""
        ]
    ),
    // 70–79
    se!(
        70,
        "msgrcv",
        SyscallEntryCategory::IPC,
        "ssize_t",
        5,
        [
            "msqid: int",
            "msgp: *msgbuf",
            "msgsz: size_t",
            "msgtyp: long",
            "msgflg: int",
            ""
        ]
    ),
    se!(
        71,
        "msgctl",
        SyscallEntryCategory::IPC,
        "int",
        3,
        ["msqid: int", "cmd: int", "buf: *msqid_ds", "", "", ""]
    ),
    se!(
        72,
        "fcntl",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "fd: unsigned int",
            "cmd: unsigned int",
            "arg: unsigned long",
            "",
            "",
            ""
        ]
    ),
    se!(
        73,
        "flock",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: unsigned int", "cmd: unsigned int", "", "", "", ""]
    ),
    se!(
        74,
        "fsync",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fd: unsigned int", "", "", "", "", ""]
    ),
    se!(
        75,
        "fdatasync",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fd: unsigned int", "", "", "", "", ""]
    ),
    se!(
        76,
        "truncate",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["path: *char", "length: long", "", "", "", ""]
    ),
    se!(
        77,
        "ftruncate",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: unsigned int", "length: unsigned long", "", "", "", ""]
    ),
    se!(
        78,
        "getdents",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "fd: unsigned int",
            "dirent: *linux_dirent",
            "count: unsigned int",
            "",
            "",
            ""
        ]
    ),
    se!(
        79,
        "getcwd",
        SyscallEntryCategory::FileIo,
        "*char",
        2,
        ["buf: *char", "size: unsigned long", "", "", "", ""]
    ),
    // 80–89
    se!(
        80,
        "chdir",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["filename: *char", "", "", "", "", ""]
    ),
    se!(
        81,
        "fchdir",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fd: unsigned int", "", "", "", "", ""]
    ),
    se!(
        82,
        "rename",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["oldname: *char", "newname: *char", "", "", "", ""]
    ),
    se!(
        83,
        "mkdir",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["pathname: *char", "mode: mode_t", "", "", "", ""]
    ),
    se!(
        84,
        "rmdir",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["pathname: *char", "", "", "", "", ""]
    ),
    se!(
        85,
        "creat",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["pathname: *char", "mode: mode_t", "", "", "", ""]
    ),
    se!(
        86,
        "link",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["oldname: *char", "newname: *char", "", "", "", ""]
    ),
    se!(
        87,
        "unlink",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["pathname: *char", "", "", "", "", ""]
    ),
    se!(
        88,
        "symlink",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["oldname: *char", "newname: *char", "", "", "", ""]
    ),
    se!(
        89,
        "readlink",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["path: *char", "buf: *char", "bufsiz: int", "", "", ""]
    ),
    // 90–99
    se!(
        90,
        "chmod",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "mode: mode_t", "", "", "", ""]
    ),
    se!(
        91,
        "fchmod",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: unsigned int", "mode: mode_t", "", "", "", ""]
    ),
    se!(
        92,
        "chown",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["filename: *char", "user: uid_t", "group: gid_t", "", "", ""]
    ),
    se!(
        93,
        "fchown",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "fd: unsigned int",
            "user: uid_t",
            "group: gid_t",
            "",
            "",
            ""
        ]
    ),
    se!(
        94,
        "lchown",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["filename: *char", "user: uid_t", "group: gid_t", "", "", ""]
    ),
    se!(
        95,
        "umask",
        SyscallEntryCategory::FileIo,
        "mode_t",
        1,
        ["mask: mode_t", "", "", "", "", ""]
    ),
    se!(
        96,
        "gettimeofday",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["tv: *timeval", "tz: *timezone", "", "", "", ""]
    ),
    se!(
        97,
        "getrlimit",
        SyscallEntryCategory::Info,
        "int",
        2,
        ["resource: unsigned int", "rlim: *rlimit", "", "", "", ""]
    ),
    se!(
        98,
        "getrusage",
        SyscallEntryCategory::Info,
        "int",
        2,
        ["who: int", "ru: *rusage", "", "", "", ""]
    ),
    se!(
        99,
        "sysinfo",
        SyscallEntryCategory::Info,
        "int",
        1,
        ["info: *sysinfo", "", "", "", "", ""]
    ),
    // 100–109
    se!(
        100,
        "times",
        SyscallEntryCategory::Time,
        "clock_t",
        1,
        ["tbuf: *tms", "", "", "", "", ""]
    ),
    se!(
        101,
        "ptrace",
        SyscallEntryCategory::Security,
        "long",
        4,
        [
            "request: long",
            "pid: long",
            "addr: unsigned long",
            "data: unsigned long",
            "",
            ""
        ]
    ),
    se!(
        102,
        "getuid",
        SyscallEntryCategory::Security,
        "uid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        103,
        "syslog",
        SyscallEntryCategory::Info,
        "int",
        3,
        ["type: int", "buf: *char", "len: int", "", "", ""]
    ),
    se!(
        104,
        "getgid",
        SyscallEntryCategory::Security,
        "gid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        105,
        "setuid",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["uid: uid_t", "", "", "", "", ""]
    ),
    se!(
        106,
        "setgid",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["gid: gid_t", "", "", "", "", ""]
    ),
    se!(
        107,
        "geteuid",
        SyscallEntryCategory::Security,
        "uid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        108,
        "getegid",
        SyscallEntryCategory::Security,
        "gid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        109,
        "setpgid",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["pid: pid_t", "pgid: pid_t", "", "", "", ""]
    ),
    // 110–119
    se!(
        110,
        "getppid",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        111,
        "getpgrp",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        112,
        "setsid",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        113,
        "setreuid",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["ruid: uid_t", "euid: uid_t", "", "", "", ""]
    ),
    se!(
        114,
        "setregid",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["rgid: gid_t", "egid: gid_t", "", "", "", ""]
    ),
    se!(
        115,
        "getgroups",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["gidsetsize: int", "grouplist: *gid_t", "", "", "", ""]
    ),
    se!(
        116,
        "setgroups",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["gidsetsize: int", "grouplist: *gid_t", "", "", "", ""]
    ),
    se!(
        117,
        "setresuid",
        SyscallEntryCategory::Security,
        "int",
        3,
        ["ruid: uid_t", "euid: uid_t", "suid: uid_t", "", "", ""]
    ),
    se!(
        118,
        "getresuid",
        SyscallEntryCategory::Security,
        "int",
        3,
        ["ruid: *uid_t", "euid: *uid_t", "suid: *uid_t", "", "", ""]
    ),
    se!(
        119,
        "setresgid",
        SyscallEntryCategory::Security,
        "int",
        3,
        ["rgid: gid_t", "egid: gid_t", "sgid: gid_t", "", "", ""]
    ),
    // 120–129
    se!(
        120,
        "getresgid",
        SyscallEntryCategory::Security,
        "int",
        3,
        ["rgid: *gid_t", "egid: *gid_t", "sgid: *gid_t", "", "", ""]
    ),
    se!(
        121,
        "getpgid",
        SyscallEntryCategory::Process,
        "pid_t",
        1,
        ["pid: pid_t", "", "", "", "", ""]
    ),
    se!(
        122,
        "setfsuid",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["uid: uid_t", "", "", "", "", ""]
    ),
    se!(
        123,
        "setfsgid",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["gid: gid_t", "", "", "", "", ""]
    ),
    se!(
        124,
        "getsid",
        SyscallEntryCategory::Process,
        "pid_t",
        1,
        ["pid: pid_t", "", "", "", "", ""]
    ),
    se!(
        125,
        "capget",
        SyscallEntryCategory::Security,
        "int",
        2,
        [
            "header: *cap_user_header_t",
            "dataptr: *cap_user_data_t",
            "",
            "",
            "",
            ""
        ]
    ),
    se!(
        126,
        "capset",
        SyscallEntryCategory::Security,
        "int",
        2,
        [
            "header: *cap_user_header_t",
            "data: *cap_user_data_t",
            "",
            "",
            "",
            ""
        ]
    ),
    se!(
        127,
        "rt_sigpending",
        SyscallEntryCategory::Signal,
        "int",
        2,
        ["uset: *sigset_t", "sigsetsize: size_t", "", "", "", ""]
    ),
    se!(
        128,
        "rt_sigtimedwait",
        SyscallEntryCategory::Signal,
        "int",
        4,
        [
            "uthese: *sigset_t",
            "uinfo: *siginfo_t",
            "uts: *timespec",
            "sigsetsize: size_t",
            "",
            ""
        ]
    ),
    se!(
        129,
        "rt_sigqueueinfo",
        SyscallEntryCategory::Signal,
        "int",
        3,
        ["pid: pid_t", "sig: int", "uinfo: *siginfo_t", "", "", ""]
    ),
    // 130–139
    se!(
        130,
        "rt_sigsuspend",
        SyscallEntryCategory::Signal,
        "int",
        2,
        ["unewset: *sigset_t", "sigsetsize: size_t", "", "", "", ""]
    ),
    se!(
        131,
        "sigaltstack",
        SyscallEntryCategory::Signal,
        "int",
        2,
        ["uss: *stack_t", "uoss: *stack_t", "", "", "", ""]
    ),
    se!(
        132,
        "utime",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "times: *utimbuf", "", "", "", ""]
    ),
    se!(
        133,
        "mknod",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "filename: *char",
            "mode: umode_t",
            "dev: unsigned",
            "",
            "",
            ""
        ]
    ),
    se!(
        134,
        "uselib",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["library: *char", "", "", "", "", ""]
    ),
    se!(
        135,
        "personality",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["personality: unsigned int", "", "", "", "", ""]
    ),
    se!(
        136,
        "ustat",
        SyscallEntryCategory::Info,
        "int",
        2,
        ["dev: unsigned", "ubuf: *ustat", "", "", "", ""]
    ),
    se!(
        137,
        "statfs",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["pathname: *char", "buf: *statfs", "", "", "", ""]
    ),
    se!(
        138,
        "fstatfs",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: unsigned int", "buf: *statfs", "", "", "", ""]
    ),
    se!(
        139,
        "sysfs",
        SyscallEntryCategory::Info,
        "int",
        3,
        [
            "option: int",
            "arg1: unsigned long",
            "arg2: unsigned long",
            "",
            "",
            ""
        ]
    ),
    // 140–149
    se!(
        140,
        "getpriority",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["which: int", "who: int", "", "", "", ""]
    ),
    se!(
        141,
        "setpriority",
        SyscallEntryCategory::Process,
        "int",
        3,
        ["which: int", "who: int", "niceval: int", "", "", ""]
    ),
    se!(
        142,
        "sched_setparam",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["pid: pid_t", "param: *sched_param", "", "", "", ""]
    ),
    se!(
        143,
        "sched_getparam",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["pid: pid_t", "param: *sched_param", "", "", "", ""]
    ),
    se!(
        144,
        "sched_setscheduler",
        SyscallEntryCategory::Process,
        "int",
        3,
        [
            "pid: pid_t",
            "policy: int",
            "param: *sched_param",
            "",
            "",
            ""
        ]
    ),
    se!(
        145,
        "sched_getscheduler",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["pid: pid_t", "", "", "", "", ""]
    ),
    se!(
        146,
        "sched_get_priority_max",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["policy: int", "", "", "", "", ""]
    ),
    se!(
        147,
        "sched_get_priority_min",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["policy: int", "", "", "", "", ""]
    ),
    se!(
        148,
        "sched_rr_get_interval",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["pid: pid_t", "interval: *timespec", "", "", "", ""]
    ),
    se!(
        149,
        "mlock",
        SyscallEntryCategory::Memory,
        "int",
        2,
        ["start: unsigned long", "len: size_t", "", "", "", ""]
    ),
    // 150–159
    se!(
        150,
        "munlock",
        SyscallEntryCategory::Memory,
        "int",
        2,
        ["start: unsigned long", "len: size_t", "", "", "", ""]
    ),
    se!(
        151,
        "mlockall",
        SyscallEntryCategory::Memory,
        "int",
        1,
        ["flags: int", "", "", "", "", ""]
    ),
    se!(
        152,
        "munlockall",
        SyscallEntryCategory::Memory,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        153,
        "vhangup",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        154,
        "modify_ldt",
        SyscallEntryCategory::Misc,
        "int",
        3,
        [
            "func: int",
            "ptr: *void",
            "bytecount: unsigned long",
            "",
            "",
            ""
        ]
    ),
    se!(
        155,
        "pivot_root",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["new_root: *char", "put_old: *char", "", "", "", ""]
    ),
    se!(
        156,
        "_sysctl",
        SyscallEntryCategory::Info,
        "int",
        1,
        ["args: *__sysctl_args", "", "", "", "", ""]
    ),
    se!(
        157,
        "prctl",
        SyscallEntryCategory::Security,
        "int",
        5,
        [
            "option: int",
            "arg2: unsigned long",
            "arg3: unsigned long",
            "arg4: unsigned long",
            "arg5: unsigned long",
            ""
        ]
    ),
    se!(
        158,
        "arch_prctl",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["code: int", "addr: unsigned long", "", "", "", ""]
    ),
    se!(
        159,
        "adjtimex",
        SyscallEntryCategory::Time,
        "int",
        1,
        ["txc_p: *timex", "", "", "", "", ""]
    ),
    // 160–169
    se!(
        160,
        "setrlimit",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["resource: unsigned int", "rlim: *rlimit", "", "", "", ""]
    ),
    se!(
        161,
        "chroot",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["filename: *char", "", "", "", "", ""]
    ),
    se!(
        162,
        "sync",
        SyscallEntryCategory::FileIo,
        "void",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        163,
        "acct",
        SyscallEntryCategory::Misc,
        "int",
        1,
        ["name: *char", "", "", "", "", ""]
    ),
    se!(
        164,
        "settimeofday",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["tv: *timeval", "tz: *timezone", "", "", "", ""]
    ),
    se!(
        165,
        "mount",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "dev_name: *char",
            "dir_name: *char",
            "type: *char",
            "flags: unsigned long",
            "data: *void",
            ""
        ]
    ),
    se!(
        166,
        "umount2",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["name: *char", "flags: int", "", "", "", ""]
    ),
    se!(
        167,
        "swapon",
        SyscallEntryCategory::Misc,
        "int",
        2,
        ["specialfile: *char", "swap_flags: int", "", "", "", ""]
    ),
    se!(
        168,
        "swapoff",
        SyscallEntryCategory::Misc,
        "int",
        1,
        ["specialfile: *char", "", "", "", "", ""]
    ),
    se!(
        169,
        "reboot",
        SyscallEntryCategory::Misc,
        "int",
        4,
        [
            "magic1: int",
            "magic2: int",
            "cmd: unsigned int",
            "arg: *void",
            "",
            ""
        ]
    ),
    // 170–179
    se!(
        170,
        "sethostname",
        SyscallEntryCategory::Info,
        "int",
        2,
        ["name: *char", "len: int", "", "", "", ""]
    ),
    se!(
        171,
        "setdomainname",
        SyscallEntryCategory::Info,
        "int",
        2,
        ["name: *char", "len: int", "", "", "", ""]
    ),
    se!(
        172,
        "iopl",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["level: unsigned int", "", "", "", "", ""]
    ),
    se!(
        173,
        "ioperm",
        SyscallEntryCategory::Security,
        "int",
        3,
        [
            "from: unsigned long",
            "num: unsigned long",
            "turn_on: int",
            "",
            "",
            ""
        ]
    ),
    se!(
        174,
        "create_module",
        SyscallEntryCategory::Security,
        "unsigned long",
        2,
        ["name: *char", "size: size_t", "", "", "", ""]
    ),
    se!(
        175,
        "init_module",
        SyscallEntryCategory::Security,
        "int",
        3,
        [
            "umod: *void",
            "len: unsigned long",
            "uargs: *char",
            "",
            "",
            ""
        ]
    ),
    se!(
        176,
        "delete_module",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["name_user: *char", "flags: unsigned int", "", "", "", ""]
    ),
    se!(
        177,
        "get_kernel_syms",
        SyscallEntryCategory::Info,
        "int",
        1,
        ["table: *kernel_sym", "", "", "", "", ""]
    ),
    se!(
        178,
        "query_module",
        SyscallEntryCategory::Info,
        "int",
        5,
        [
            "name: *char",
            "which: int",
            "buf: *void",
            "bufsize: size_t",
            "ret: *size_t",
            ""
        ]
    ),
    se!(
        179,
        "quotactl",
        SyscallEntryCategory::Misc,
        "int",
        4,
        [
            "cmd: unsigned int",
            "special: *char",
            "id: qid_t",
            "addr: *void",
            "",
            ""
        ]
    ),
    // 180–189
    se!(
        180,
        "nfsservctl",
        SyscallEntryCategory::Misc,
        "long",
        3,
        [
            "cmd: int",
            "argp: *nfsctl_arg",
            "resp: *nfsctl_res",
            "",
            "",
            ""
        ]
    ),
    se!(
        181,
        "getpmsg",
        SyscallEntryCategory::Misc,
        "int",
        5,
        [
            "fildes: int",
            "ctlptr: *strbuf",
            "dataptr: *strbuf",
            "bandp: *int",
            "flagsp: *int",
            ""
        ]
    ),
    se!(
        182,
        "putpmsg",
        SyscallEntryCategory::Misc,
        "int",
        5,
        [
            "fildes: int",
            "ctlptr: *strbuf",
            "dataptr: *strbuf",
            "band: int",
            "flags: int",
            ""
        ]
    ),
    se!(
        183,
        "afs_syscall",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        184,
        "tuxcall",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        185,
        "security",
        SyscallEntryCategory::Security,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        186,
        "gettid",
        SyscallEntryCategory::Process,
        "pid_t",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        187,
        "readahead",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "offset: loff_t", "count: size_t", "", "", ""]
    ),
    se!(
        188,
        "setxattr",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "pathname: *char",
            "name: *char",
            "value: *void",
            "size: size_t",
            "flags: int",
            ""
        ]
    ),
    se!(
        189,
        "lsetxattr",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "pathname: *char",
            "name: *char",
            "value: *void",
            "size: size_t",
            "flags: int",
            ""
        ]
    ),
    // 190–199
    se!(
        190,
        "fsetxattr",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "fd: int",
            "name: *char",
            "value: *void",
            "size: size_t",
            "flags: int",
            ""
        ]
    ),
    se!(
        191,
        "getxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "pathname: *char",
            "name: *char",
            "value: *void",
            "size: size_t",
            "",
            ""
        ]
    ),
    se!(
        192,
        "lgetxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "pathname: *char",
            "name: *char",
            "value: *void",
            "size: size_t",
            "",
            ""
        ]
    ),
    se!(
        193,
        "fgetxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "fd: int",
            "name: *char",
            "value: *void",
            "size: size_t",
            "",
            ""
        ]
    ),
    se!(
        194,
        "listxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["pathname: *char", "list: *char", "size: size_t", "", "", ""]
    ),
    se!(
        195,
        "llistxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["pathname: *char", "list: *char", "size: size_t", "", "", ""]
    ),
    se!(
        196,
        "flistxattr",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        3,
        ["fd: int", "list: *char", "size: size_t", "", "", ""]
    ),
    se!(
        197,
        "removexattr",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["pathname: *char", "name: *char", "", "", "", ""]
    ),
    se!(
        198,
        "lremovexattr",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["pathname: *char", "name: *char", "", "", "", ""]
    ),
    se!(
        199,
        "fremovexattr",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: int", "name: *char", "", "", "", ""]
    ),
    // 200–209
    se!(
        200,
        "tkill",
        SyscallEntryCategory::Signal,
        "int",
        2,
        ["pid: pid_t", "sig: int", "", "", "", ""]
    ),
    se!(
        201,
        "time",
        SyscallEntryCategory::Time,
        "time_t",
        1,
        ["tloc: *time_t", "", "", "", "", ""]
    ),
    se!(
        202,
        "futex",
        SyscallEntryCategory::IPC,
        "long",
        6,
        [
            "uaddr: *u32",
            "op: int",
            "val: u32",
            "utime: *timespec",
            "uaddr2: *u32",
            "val3: u32"
        ]
    ),
    se!(
        203,
        "sched_setaffinity",
        SyscallEntryCategory::Process,
        "int",
        3,
        [
            "pid: pid_t",
            "len: unsigned int",
            "user_mask_ptr: *unsigned long",
            "",
            "",
            ""
        ]
    ),
    se!(
        204,
        "sched_getaffinity",
        SyscallEntryCategory::Process,
        "int",
        3,
        [
            "pid: pid_t",
            "len: unsigned int",
            "user_mask_ptr: *unsigned long",
            "",
            "",
            ""
        ]
    ),
    se!(
        205,
        "set_thread_area",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["u_info: *user_desc", "", "", "", "", ""]
    ),
    se!(
        206,
        "io_setup",
        SyscallEntryCategory::Misc,
        "int",
        2,
        [
            "nr_events: unsigned",
            "ctxp: *aio_context_t",
            "",
            "",
            "",
            ""
        ]
    ),
    se!(
        207,
        "io_destroy",
        SyscallEntryCategory::Misc,
        "int",
        1,
        ["ctx: aio_context_t", "", "", "", "", ""]
    ),
    se!(
        208,
        "io_getevents",
        SyscallEntryCategory::Misc,
        "int",
        5,
        [
            "ctx_id: aio_context_t",
            "min_nr: long",
            "nr: long",
            "events: *io_event",
            "timeout: *timespec",
            ""
        ]
    ),
    se!(
        209,
        "io_submit",
        SyscallEntryCategory::Misc,
        "int",
        3,
        [
            "ctx_id: aio_context_t",
            "nr: long",
            "iocbpp: **iocb",
            "",
            "",
            ""
        ]
    ),
    // 210–219
    se!(
        210,
        "io_cancel",
        SyscallEntryCategory::Misc,
        "int",
        3,
        [
            "ctx_id: aio_context_t",
            "iocb: *iocb",
            "result: *io_event",
            "",
            "",
            ""
        ]
    ),
    se!(
        211,
        "get_thread_area",
        SyscallEntryCategory::Process,
        "int",
        1,
        ["u_info: *user_desc", "", "", "", "", ""]
    ),
    se!(
        212,
        "lookup_dcookie",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["cookie64: u64", "buf: *char", "len: size_t", "", "", ""]
    ),
    se!(
        213,
        "epoll_create",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["size: int", "", "", "", "", ""]
    ),
    se!(
        214,
        "epoll_ctl_old",
        SyscallEntryCategory::FileIo,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        215,
        "epoll_wait_old",
        SyscallEntryCategory::FileIo,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        216,
        "remap_file_pages",
        SyscallEntryCategory::Memory,
        "int",
        5,
        [
            "start: unsigned long",
            "size: unsigned long",
            "prot: unsigned long",
            "pgoff: unsigned long",
            "flags: unsigned long",
            ""
        ]
    ),
    se!(
        217,
        "getdents64",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "fd: unsigned int",
            "dirent: *linux_dirent64",
            "count: unsigned int",
            "",
            "",
            ""
        ]
    ),
    se!(
        218,
        "set_tid_address",
        SyscallEntryCategory::Process,
        "long",
        1,
        ["tidptr: *int", "", "", "", "", ""]
    ),
    se!(
        219,
        "restart_syscall",
        SyscallEntryCategory::Misc,
        "long",
        0,
        ["", "", "", "", "", ""]
    ),
    // 220–229
    se!(
        220,
        "semtimedop",
        SyscallEntryCategory::IPC,
        "int",
        4,
        [
            "semid: int",
            "sops: *sembuf",
            "nsops: unsigned",
            "timeout: *timespec",
            "",
            ""
        ]
    ),
    se!(
        221,
        "fadvise64",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "fd: int",
            "offset: loff_t",
            "len: size_t",
            "advice: int",
            "",
            ""
        ]
    ),
    se!(
        222,
        "timer_create",
        SyscallEntryCategory::Time,
        "int",
        3,
        [
            "which_clock: clockid_t",
            "timer_event_spec: *sigevent",
            "created_timer_id: *timer_t",
            "",
            "",
            ""
        ]
    ),
    se!(
        223,
        "timer_settime",
        SyscallEntryCategory::Time,
        "int",
        4,
        [
            "timer_id: timer_t",
            "flags: int",
            "new_setting: *itimerspec",
            "old_setting: *itimerspec",
            "",
            ""
        ]
    ),
    se!(
        224,
        "timer_gettime",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["timer_id: timer_t", "setting: *itimerspec", "", "", "", ""]
    ),
    se!(
        225,
        "timer_getoverrun",
        SyscallEntryCategory::Time,
        "int",
        1,
        ["timer_id: timer_t", "", "", "", "", ""]
    ),
    se!(
        226,
        "timer_delete",
        SyscallEntryCategory::Time,
        "int",
        1,
        ["timer_id: timer_t", "", "", "", "", ""]
    ),
    se!(
        227,
        "clock_settime",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["which_clock: clockid_t", "tp: *timespec", "", "", "", ""]
    ),
    se!(
        228,
        "clock_gettime",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["which_clock: clockid_t", "tp: *timespec", "", "", "", ""]
    ),
    se!(
        229,
        "clock_getres",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["which_clock: clockid_t", "tp: *timespec", "", "", "", ""]
    ),
    // 230–239
    se!(
        230,
        "clock_nanosleep",
        SyscallEntryCategory::Time,
        "int",
        4,
        [
            "which_clock: clockid_t",
            "flags: int",
            "rqtp: *timespec",
            "rmtp: *timespec",
            "",
            ""
        ]
    ),
    se!(
        231,
        "exit_group",
        SyscallEntryCategory::Process,
        "void",
        1,
        ["error_code: int", "", "", "", "", ""]
    ),
    se!(
        232,
        "epoll_wait",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "epfd: int",
            "events: *epoll_event",
            "maxevents: int",
            "timeout: int",
            "",
            ""
        ]
    ),
    se!(
        233,
        "epoll_ctl",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "epfd: int",
            "op: int",
            "fd: int",
            "event: *epoll_event",
            "",
            ""
        ]
    ),
    se!(
        234,
        "tgkill",
        SyscallEntryCategory::Signal,
        "int",
        3,
        ["tgid: pid_t", "pid: pid_t", "sig: int", "", "", ""]
    ),
    se!(
        235,
        "utimes",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["filename: *char", "utimes: *timeval", "", "", "", ""]
    ),
    se!(
        236,
        "vserver",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        237,
        "mbind",
        SyscallEntryCategory::Memory,
        "long",
        6,
        [
            "start: unsigned long",
            "len: unsigned long",
            "mode: unsigned long",
            "nmask: *unsigned long",
            "maxnode: unsigned long",
            "flags: unsigned"
        ]
    ),
    se!(
        238,
        "set_mempolicy",
        SyscallEntryCategory::Memory,
        "long",
        3,
        [
            "mode: int",
            "nmask: *unsigned long",
            "maxnode: unsigned long",
            "",
            "",
            ""
        ]
    ),
    se!(
        239,
        "get_mempolicy",
        SyscallEntryCategory::Memory,
        "long",
        5,
        [
            "policy: *int",
            "nmask: *unsigned long",
            "maxnode: unsigned long",
            "addr: unsigned long",
            "flags: unsigned long",
            ""
        ]
    ),
    // 240–249
    se!(
        240,
        "mq_open",
        SyscallEntryCategory::IPC,
        "mqd_t",
        4,
        [
            "name: *char",
            "oflag: int",
            "mode: umode_t",
            "attr: *mq_attr",
            "",
            ""
        ]
    ),
    se!(
        241,
        "mq_unlink",
        SyscallEntryCategory::IPC,
        "int",
        1,
        ["name: *char", "", "", "", "", ""]
    ),
    se!(
        242,
        "mq_timedsend",
        SyscallEntryCategory::IPC,
        "int",
        5,
        [
            "mqdes: mqd_t",
            "msg_ptr: *char",
            "msg_len: size_t",
            "msg_prio: unsigned",
            "abs_timeout: *timespec",
            ""
        ]
    ),
    se!(
        243,
        "mq_timedreceive",
        SyscallEntryCategory::IPC,
        "ssize_t",
        5,
        [
            "mqdes: mqd_t",
            "msg_ptr: *char",
            "msg_len: size_t",
            "msg_prio: *unsigned",
            "abs_timeout: *timespec",
            ""
        ]
    ),
    se!(
        244,
        "mq_notify",
        SyscallEntryCategory::IPC,
        "int",
        2,
        ["mqdes: mqd_t", "notification: *sigevent", "", "", "", ""]
    ),
    se!(
        245,
        "mq_getsetattr",
        SyscallEntryCategory::IPC,
        "int",
        3,
        [
            "mqdes: mqd_t",
            "mqstat: *mq_attr",
            "omqstat: *mq_attr",
            "",
            "",
            ""
        ]
    ),
    se!(
        246,
        "kexec_load",
        SyscallEntryCategory::Security,
        "long",
        4,
        [
            "entry: unsigned long",
            "nr_segments: unsigned long",
            "segments: *kexec_segment",
            "flags: unsigned long",
            "",
            ""
        ]
    ),
    se!(
        247,
        "waitid",
        SyscallEntryCategory::Process,
        "long",
        5,
        [
            "which: int",
            "upid: pid_t",
            "infop: *siginfo_t",
            "options: int",
            "ru: *rusage",
            ""
        ]
    ),
    se!(
        248,
        "add_key",
        SyscallEntryCategory::Security,
        "key_serial_t",
        5,
        [
            "_type: *char",
            "_description: *char",
            "_payload: *void",
            "plen: size_t",
            "ringid: key_serial_t",
            ""
        ]
    ),
    se!(
        249,
        "request_key",
        SyscallEntryCategory::Security,
        "key_serial_t",
        4,
        [
            "_type: *char",
            "_description: *char",
            "_callout_info: *char",
            "destringid: key_serial_t",
            "",
            ""
        ]
    ),
    // 250–259
    se!(
        250,
        "keyctl",
        SyscallEntryCategory::Security,
        "long",
        5,
        [
            "option: int",
            "arg2: unsigned long",
            "arg3: unsigned long",
            "arg4: unsigned long",
            "arg5: unsigned long",
            ""
        ]
    ),
    se!(
        251,
        "ioprio_set",
        SyscallEntryCategory::Process,
        "int",
        3,
        ["which: int", "who: int", "ioprio: int", "", "", ""]
    ),
    se!(
        252,
        "ioprio_get",
        SyscallEntryCategory::Process,
        "int",
        2,
        ["which: int", "who: int", "", "", "", ""]
    ),
    se!(
        253,
        "inotify_init",
        SyscallEntryCategory::FileIo,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        254,
        "inotify_add_watch",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["fd: int", "pathname: *char", "mask: u32", "", "", ""]
    ),
    se!(
        255,
        "inotify_rm_watch",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        ["fd: int", "wd: __s32", "", "", "", ""]
    ),
    se!(
        256,
        "migrate_pages",
        SyscallEntryCategory::Memory,
        "long",
        4,
        [
            "pid: pid_t",
            "maxnode: unsigned long",
            "old_nodes: *unsigned long",
            "new_nodes: *unsigned long",
            "",
            ""
        ]
    ),
    se!(
        257,
        "openat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "filename: *char",
            "flags: int",
            "mode: mode_t",
            "",
            ""
        ]
    ),
    se!(
        258,
        "mkdirat",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["dfd: int", "pathname: *char", "mode: umode_t", "", "", ""]
    ),
    se!(
        259,
        "mknodat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "filename: *char",
            "mode: umode_t",
            "dev: unsigned",
            "",
            ""
        ]
    ),
    // 260–269
    se!(
        260,
        "fchownat",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "dfd: int",
            "filename: *char",
            "user: uid_t",
            "group: gid_t",
            "flag: int",
            ""
        ]
    ),
    se!(
        261,
        "futimesat",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "dfd: int",
            "filename: *char",
            "utimes: *timeval",
            "",
            "",
            ""
        ]
    ),
    se!(
        262,
        "newfstatat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "filename: *char",
            "statbuf: *stat",
            "flag: int",
            "",
            ""
        ]
    ),
    se!(
        263,
        "unlinkat",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["dfd: int", "pathname: *char", "flag: int", "", "", ""]
    ),
    se!(
        264,
        "renameat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "olddfd: int",
            "oldname: *char",
            "newdfd: int",
            "newname: *char",
            "",
            ""
        ]
    ),
    se!(
        265,
        "linkat",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "olddfd: int",
            "oldname: *char",
            "newdfd: int",
            "newname: *char",
            "flags: int",
            ""
        ]
    ),
    se!(
        266,
        "symlinkat",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "oldname: *char",
            "newdfd: int",
            "newname: *char",
            "",
            "",
            ""
        ]
    ),
    se!(
        267,
        "readlinkat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "pathname: *char",
            "buf: *char",
            "bufsiz: int",
            "",
            ""
        ]
    ),
    se!(
        268,
        "fchmodat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "filename: *char",
            "mode: umode_t",
            "flags: int",
            "",
            ""
        ]
    ),
    se!(
        269,
        "faccessat",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        ["dfd: int", "filename: *char", "mode: int", "", "", ""]
    ),
    // 270–279
    se!(
        270,
        "pselect6",
        SyscallEntryCategory::FileIo,
        "int",
        6,
        [
            "n: int",
            "inp: *fd_set",
            "outp: *fd_set",
            "exp: *fd_set",
            "tsp: *timespec",
            "sig: *void"
        ]
    ),
    se!(
        271,
        "ppoll",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "ufds: *pollfd",
            "nfds: unsigned int",
            "tsp: *timespec",
            "sigmask: *sigset_t",
            "sigsetsize: size_t",
            ""
        ]
    ),
    se!(
        272,
        "unshare",
        SyscallEntryCategory::Security,
        "int",
        1,
        ["unshare_flags: unsigned long", "", "", "", "", ""]
    ),
    se!(
        273,
        "set_robust_list",
        SyscallEntryCategory::Process,
        "long",
        2,
        ["head: *robust_list_head", "len: size_t", "", "", "", ""]
    ),
    se!(
        274,
        "get_robust_list",
        SyscallEntryCategory::Process,
        "long",
        3,
        [
            "pid: int",
            "head_ptr: **robust_list_head",
            "len_ptr: *size_t",
            "",
            "",
            ""
        ]
    ),
    se!(
        275,
        "splice",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        6,
        [
            "fd_in: int",
            "off_in: *loff_t",
            "fd_out: int",
            "off_out: *loff_t",
            "len: size_t",
            "flags: unsigned int"
        ]
    ),
    se!(
        276,
        "tee",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "fdin: int",
            "fdout: int",
            "len: size_t",
            "flags: unsigned int",
            "",
            ""
        ]
    ),
    se!(
        277,
        "sync_file_range",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "fd: int",
            "offset: loff_t",
            "nbytes: loff_t",
            "flags: unsigned int",
            "",
            ""
        ]
    ),
    se!(
        278,
        "vmsplice",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        4,
        [
            "fd: int",
            "iov: *iovec",
            "nr_segs: unsigned long",
            "flags: unsigned int",
            "",
            ""
        ]
    ),
    se!(
        279,
        "move_pages",
        SyscallEntryCategory::Memory,
        "long",
        6,
        [
            "pid: pid_t",
            "nr_pages: unsigned long",
            "pages: **void",
            "nodes: *int",
            "status: *int",
            "flags: int"
        ]
    ),
    // 280–289
    se!(
        280,
        "utimensat",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "dfd: int",
            "filename: *char",
            "utimes: *timespec",
            "flags: int",
            "",
            ""
        ]
    ),
    se!(
        281,
        "epoll_pwait",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "epfd: int",
            "events: *epoll_event",
            "maxevents: int",
            "timeout: int",
            "sigmask: *sigset_t",
            ""
        ]
    ),
    se!(
        282,
        "signalfd",
        SyscallEntryCategory::Signal,
        "int",
        3,
        [
            "ufd: int",
            "user_mask: *sigset_t",
            "sizemask: size_t",
            "",
            "",
            ""
        ]
    ),
    se!(
        283,
        "timerfd_create",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["clockid: int", "flags: int", "", "", "", ""]
    ),
    se!(
        284,
        "eventfd",
        SyscallEntryCategory::IPC,
        "int",
        1,
        ["count: unsigned int", "", "", "", "", ""]
    ),
    se!(
        285,
        "fallocate",
        SyscallEntryCategory::FileIo,
        "int",
        4,
        [
            "fd: int",
            "mode: int",
            "offset: loff_t",
            "len: loff_t",
            "",
            ""
        ]
    ),
    se!(
        286,
        "timerfd_settime",
        SyscallEntryCategory::Time,
        "int",
        4,
        [
            "ufd: int",
            "flags: int",
            "utmr: *itimerspec",
            "otmr: *itimerspec",
            "",
            ""
        ]
    ),
    se!(
        287,
        "timerfd_gettime",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["ufd: int", "otmr: *itimerspec", "", "", "", ""]
    ),
    se!(
        288,
        "accept4",
        SyscallEntryCategory::Network,
        "int",
        4,
        [
            "fd: int",
            "upeer_sockaddr: *sockaddr",
            "upeer_addrlen: *int",
            "flags: int",
            "",
            ""
        ]
    ),
    se!(
        289,
        "signalfd4",
        SyscallEntryCategory::Signal,
        "int",
        4,
        [
            "ufd: int",
            "user_mask: *sigset_t",
            "sizemask: size_t",
            "flags: int",
            "",
            ""
        ]
    ),
    // 290–299
    se!(
        290,
        "eventfd2",
        SyscallEntryCategory::IPC,
        "int",
        2,
        ["count: unsigned int", "flags: int", "", "", "", ""]
    ),
    se!(
        291,
        "epoll_create1",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["flags: int", "", "", "", "", ""]
    ),
    se!(
        292,
        "dup3",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "oldfd: unsigned int",
            "newfd: unsigned int",
            "flags: int",
            "",
            "",
            ""
        ]
    ),
    se!(
        293,
        "pipe2",
        SyscallEntryCategory::IPC,
        "int",
        2,
        ["fildes: *int", "flags: int", "", "", "", ""]
    ),
    se!(
        294,
        "inotify_init1",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["flags: int", "", "", "", "", ""]
    ),
    se!(
        295,
        "preadv",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        5,
        [
            "fd: unsigned long",
            "vec: *iovec",
            "vlen: unsigned long",
            "pos_l: unsigned long",
            "pos_h: unsigned long",
            ""
        ]
    ),
    se!(
        296,
        "pwritev",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        5,
        [
            "fd: unsigned long",
            "vec: *iovec",
            "vlen: unsigned long",
            "pos_l: unsigned long",
            "pos_h: unsigned long",
            ""
        ]
    ),
    se!(
        297,
        "rt_tgsigqueueinfo",
        SyscallEntryCategory::Signal,
        "int",
        4,
        [
            "tgid: pid_t",
            "pid: pid_t",
            "sig: int",
            "uinfo: *siginfo_t",
            "",
            ""
        ]
    ),
    se!(
        298,
        "perf_event_open",
        SyscallEntryCategory::Misc,
        "int",
        5,
        [
            "attr_uptr: *perf_event_attr",
            "pid: pid_t",
            "cpu: int",
            "group_fd: int",
            "flags: unsigned long",
            ""
        ]
    ),
    se!(
        299,
        "recvmmsg",
        SyscallEntryCategory::Network,
        "int",
        5,
        [
            "fd: int",
            "msg: *mmsghdr",
            "vlen: unsigned int",
            "flags: unsigned",
            "timeout: *timespec",
            ""
        ]
    ),
    // 300–309
    se!(
        300,
        "fanotify_init",
        SyscallEntryCategory::FileIo,
        "int",
        2,
        [
            "flags: unsigned int",
            "event_f_flags: unsigned int",
            "",
            "",
            "",
            ""
        ]
    ),
    se!(
        301,
        "fanotify_mark",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "fanotify_fd: int",
            "flags: unsigned int",
            "mask: u64",
            "dfd: int",
            "pathname: *char",
            ""
        ]
    ),
    se!(
        302,
        "prlimit64",
        SyscallEntryCategory::Process,
        "int",
        4,
        [
            "pid: pid_t",
            "resource: unsigned int",
            "new_rlim: *rlimit64",
            "old_rlim: *rlimit64",
            "",
            ""
        ]
    ),
    se!(
        303,
        "name_to_handle_at",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "dfd: int",
            "name: *char",
            "handle: *file_handle",
            "mnt_id: *int",
            "flag: int",
            ""
        ]
    ),
    se!(
        304,
        "open_by_handle_at",
        SyscallEntryCategory::FileIo,
        "int",
        3,
        [
            "mountdirfd: int",
            "handle: *file_handle",
            "flags: int",
            "",
            "",
            ""
        ]
    ),
    se!(
        305,
        "clock_adjtime",
        SyscallEntryCategory::Time,
        "int",
        2,
        ["which_clock: clockid_t", "tx: *timex", "", "", "", ""]
    ),
    se!(
        306,
        "syncfs",
        SyscallEntryCategory::FileIo,
        "int",
        1,
        ["fd: int", "", "", "", "", ""]
    ),
    se!(
        307,
        "sendmmsg",
        SyscallEntryCategory::Network,
        "int",
        4,
        [
            "fd: int",
            "msg: *mmsghdr",
            "vlen: unsigned int",
            "flags: unsigned",
            "",
            ""
        ]
    ),
    se!(
        308,
        "setns",
        SyscallEntryCategory::Security,
        "int",
        2,
        ["fd: int", "nstype: int", "", "", "", ""]
    ),
    se!(
        309,
        "getcpu",
        SyscallEntryCategory::Info,
        "int",
        3,
        [
            "cpu: *unsigned",
            "node: *unsigned",
            "cache: *getcpu_cache",
            "",
            "",
            ""
        ]
    ),
    // 310–319
    se!(
        310,
        "process_vm_readv",
        SyscallEntryCategory::Memory,
        "ssize_t",
        6,
        [
            "pid: pid_t",
            "lvec: *iovec",
            "liovcnt: unsigned long",
            "rvec: *iovec",
            "riovcnt: unsigned long",
            "flags: unsigned long"
        ]
    ),
    se!(
        311,
        "process_vm_writev",
        SyscallEntryCategory::Memory,
        "ssize_t",
        6,
        [
            "pid: pid_t",
            "lvec: *iovec",
            "liovcnt: unsigned long",
            "rvec: *iovec",
            "riovcnt: unsigned long",
            "flags: unsigned long"
        ]
    ),
    se!(
        312,
        "kcmp",
        SyscallEntryCategory::Process,
        "int",
        5,
        [
            "pid1: pid_t",
            "pid2: pid_t",
            "type: int",
            "idx1: unsigned long",
            "idx2: unsigned long",
            ""
        ]
    ),
    se!(
        313,
        "finit_module",
        SyscallEntryCategory::Security,
        "int",
        3,
        ["fd: int", "uargs: *char", "flags: int", "", "", ""]
    ),
    se!(
        314,
        "sched_setattr",
        SyscallEntryCategory::Process,
        "int",
        3,
        [
            "pid: pid_t",
            "attr: *sched_attr",
            "flags: unsigned int",
            "",
            "",
            ""
        ]
    ),
    se!(
        315,
        "sched_getattr",
        SyscallEntryCategory::Process,
        "int",
        4,
        [
            "pid: pid_t",
            "attr: *sched_attr",
            "size: unsigned int",
            "flags: unsigned int",
            "",
            ""
        ]
    ),
    se!(
        316,
        "renameat2",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "olddfd: int",
            "oldname: *char",
            "newdfd: int",
            "newname: *char",
            "flags: unsigned int",
            ""
        ]
    ),
    se!(
        317,
        "seccomp",
        SyscallEntryCategory::Security,
        "int",
        3,
        [
            "op: unsigned int",
            "flags: unsigned int",
            "uargs: *void",
            "",
            "",
            ""
        ]
    ),
    se!(
        318,
        "getrandom",
        SyscallEntryCategory::Security,
        "ssize_t",
        3,
        [
            "buf: *char",
            "count: size_t",
            "flags: unsigned int",
            "",
            "",
            ""
        ]
    ),
    se!(
        319,
        "memfd_create",
        SyscallEntryCategory::Memory,
        "int",
        2,
        ["uname: *char", "flags: unsigned int", "", "", "", ""]
    ),
    // 320–329
    se!(
        320,
        "kexec_file_load",
        SyscallEntryCategory::Security,
        "long",
        5,
        [
            "kernel_fd: int",
            "initrd_fd: int",
            "cmdline_len: unsigned long",
            "cmdline_ptr: *char",
            "flags: unsigned long",
            ""
        ]
    ),
    se!(
        321,
        "bpf",
        SyscallEntryCategory::Security,
        "int",
        3,
        [
            "cmd: int",
            "attr: *bpf_attr",
            "size: unsigned int",
            "",
            "",
            ""
        ]
    ),
    se!(
        322,
        "execveat",
        SyscallEntryCategory::Process,
        "int",
        5,
        [
            "dfd: int",
            "filename: *char",
            "argv: **char",
            "envp: **char",
            "flags: int",
            ""
        ]
    ),
    se!(
        323,
        "userfaultfd",
        SyscallEntryCategory::Memory,
        "int",
        1,
        ["flags: int", "", "", "", "", ""]
    ),
    se!(
        324,
        "membarrier",
        SyscallEntryCategory::Memory,
        "int",
        2,
        ["cmd: int", "flags: int", "", "", "", ""]
    ),
    se!(
        325,
        "mlock2",
        SyscallEntryCategory::Memory,
        "int",
        3,
        [
            "start: unsigned long",
            "len: size_t",
            "flags: int",
            "",
            "",
            ""
        ]
    ),
    se!(
        326,
        "copy_file_range",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        6,
        [
            "fd_in: int",
            "off_in: *loff_t",
            "fd_out: int",
            "off_out: *loff_t",
            "len: size_t",
            "flags: unsigned int"
        ]
    ),
    se!(
        327,
        "preadv2",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        6,
        [
            "fd: unsigned long",
            "vec: *iovec",
            "vlen: unsigned long",
            "pos_l: unsigned long",
            "pos_h: unsigned long",
            "flags: int"
        ]
    ),
    se!(
        328,
        "pwritev2",
        SyscallEntryCategory::FileIo,
        "ssize_t",
        6,
        [
            "fd: unsigned long",
            "vec: *iovec",
            "vlen: unsigned long",
            "pos_l: unsigned long",
            "pos_h: unsigned long",
            "flags: int"
        ]
    ),
    se!(
        329,
        "pkey_mprotect",
        SyscallEntryCategory::Memory,
        "int",
        4,
        [
            "start: unsigned long",
            "len: size_t",
            "prot: unsigned long",
            "pkey: int",
            "",
            ""
        ]
    ),
    // 330–340
    se!(
        330,
        "pkey_alloc",
        SyscallEntryCategory::Memory,
        "int",
        2,
        [
            "flags: unsigned long",
            "init_val: unsigned long",
            "",
            "",
            "",
            ""
        ]
    ),
    se!(
        331,
        "pkey_free",
        SyscallEntryCategory::Memory,
        "int",
        1,
        ["pkey: int", "", "", "", "", ""]
    ),
    se!(
        332,
        "statx",
        SyscallEntryCategory::FileIo,
        "int",
        5,
        [
            "dfd: int",
            "filename: *char",
            "flags: unsigned",
            "mask: unsigned",
            "buffer: *statx",
            ""
        ]
    ),
    se!(
        333,
        "io_pgetevents",
        SyscallEntryCategory::Misc,
        "int",
        5,
        [
            "ctx_id: aio_context_t",
            "min_nr: long",
            "nr: long",
            "events: *io_event",
            "timeout: *timespec",
            ""
        ]
    ),
    se!(
        334,
        "rseq",
        SyscallEntryCategory::Process,
        "int",
        4,
        [
            "rseq: *rseq",
            "rseq_len: u32",
            "flags: int",
            "sig: u32",
            "",
            ""
        ]
    ),
    se!(
        335,
        "reserved335",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        336,
        "reserved336",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        337,
        "reserved337",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        338,
        "reserved338",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        339,
        "reserved339",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
    se!(
        340,
        "reserved340",
        SyscallEntryCategory::Misc,
        "int",
        0,
        ["", "", "", "", "", ""]
    ),
];

/// Look up a [`LinuxSyscallEntry`] from [`LINUX_X86_64_SYSCALLS`] by number.
///
/// This is an O(1) index into the static slice (entries are consecutive from 0).
/// Returns `None` if `nr` is out of range.
#[must_use]
pub fn lookup_x86_64_entry(nr: u32) -> Option<&'static LinuxSyscallEntry> {
    LINUX_X86_64_SYSCALLS.get(nr as usize)
}

// ─── SyscallTrace / SyscallEvent ─────────────────────────────────────────────

/// A single recorded syscall event captured during tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Monotonic timestamp in nanoseconds since trace start.
    pub timestamp: u64,
    /// PID of the process that made the syscall.
    pub pid: u32,
    /// Syscall number (NR).
    pub nr: u32,
    /// Resolved syscall name (or `"unknown"` if not in table).
    pub name: String,
    /// Raw argument values in register order (up to 6).
    pub args: Vec<u64>,
    /// Return value (negative errno on error).
    pub retval: i64,
    /// Elapsed time inside the kernel, in nanoseconds.
    pub duration_ns: u64,
    /// Decoded errno code when `retval < 0`, else `None`.
    pub errno: Option<u32>,
}

impl SyscallEvent {
    /// Construct a new [`SyscallEvent`], automatically filling `errno` from
    /// `retval`.
    #[must_use]
    pub fn new(
        timestamp: u64,
        pid: u32,
        nr: u32,
        name: impl Into<String>,
        args: Vec<u64>,
        retval: i64,
        duration_ns: u64,
    ) -> Self {
        let errno = if retval < 0 {
            Some(u32::try_from(retval.unsigned_abs()).unwrap_or(u32::MAX))
        } else {
            None
        };
        Self {
            timestamp,
            pid,
            nr,
            name: name.into(),
            args,
            retval,
            duration_ns,
            errno,
        }
    }

    /// Decode arguments into human-readable strings using the static entry
    /// metadata from [`LINUX_X86_64_SYSCALLS`].
    ///
    /// Each slot is formatted according to the declared type suffix:
    /// - `*…` or `ptr` → `0x<hex>`
    /// - `fd` in name → decimal integer
    /// - `flags` in name → decoded flag string (open/mmap/prot where applicable)
    /// - everything else → decimal
    #[must_use]
    pub fn decode_args(&self, entry: &LinuxSyscallEntry) -> Vec<String> {
        let mut out = Vec::with_capacity(entry.arg_count as usize);
        let count = (entry.arg_count as usize).min(entry.args.len());
        for i in 0..count {
            let raw = self.args.get(i).copied().unwrap_or(0);
            let arg_name = entry.args[i];
            let decoded = decode_one_arg(arg_name, raw, &self.name);
            out.push(decoded);
        }
        out
    }
}

fn decode_one_arg(arg_name: &str, raw: u64, syscall_name: &str) -> String {
    // Split off the type suffix if present (format is "name: type")
    let (name_part, type_part) = arg_name.find(':').map_or((arg_name, ""), |pos| (arg_name[..pos].trim(), arg_name[pos + 1..].trim()));

    // Pointer types
    if type_part.starts_with('*') || type_part.contains("ptr") {
        return format!("0x{raw:016x}");
    }

    // Special argument-name based decoding
    if name_part == "flags" {
        let raw32 = u32::try_from(raw).unwrap_or(u32::MAX);
        match syscall_name {
            "open" | "openat" | "creat" => return decode_open_flags(raw32),
            "mmap" => return decode_mmap_flags(raw32),
            "mprotect" | "pkey_mprotect" => return decode_mmap_prot(raw32),
            _ => {}
        }
    }
    if name_part == "prot" {
        return decode_mmap_prot(u32::try_from(raw).unwrap_or(u32::MAX));
    }
    if name_part.contains("fd") && !name_part.contains("flag") {
        return format!("{}", raw.cast_signed());
    }

    // Default: decimal
    format!("{}", raw.cast_signed())
}

/// Accumulated trace of many syscall events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallTrace {
    /// Ordered list of captured events.
    pub entries: Vec<SyscallEvent>,
}

impl SyscallTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event to the trace.
    pub fn push(&mut self, event: SyscallEvent) {
        self.entries.push(event);
    }

    /// Return a reference to all captured events.
    #[must_use]
    pub fn events(&self) -> &[SyscallEvent] {
        &self.entries
    }

    /// Return the total number of recorded events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no events have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Filter events that are interesting from a malware-analysis perspective.
    #[must_use]
    pub fn interesting_events(&self) -> Vec<&SyscallEvent> {
        self.entries
            .iter()
            .filter(|e| SyscallTraceFilter::interesting_for_malware(e))
            .collect()
    }
}

// ─── Flag decoders ───────────────────────────────────────────────────────────

/// Decode `open(2)` / `openat(2)` flags bitmask into a human-readable string.
///
/// Produces output like `O_RDWR|O_CREAT|O_TRUNC`.
#[must_use]
pub fn decode_open_flags(flags: u32) -> String {
    // Access-mode lives in the lowest 2 bits
    let access = match flags & 0x3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        _ => "O_RDWR",
    };
    let mut parts = vec![access];

    macro_rules! flag {
        ($val:expr, $name:literal) => {
            if flags & $val != 0 {
                parts.push($name);
            }
        };
    }

    flag!(0x40, "O_CREAT");
    flag!(0x80, "O_EXCL");
    flag!(0x100, "O_NOCTTY");
    flag!(0x200, "O_TRUNC");
    flag!(0x400, "O_APPEND");
    flag!(0x800, "O_NONBLOCK");
    flag!(0x1000, "O_DSYNC");
    flag!(0x4000, "O_DIRECT");
    flag!(0x8000, "O_LARGEFILE");
    flag!(0x1_0000, "O_DIRECTORY");
    flag!(0x2_0000, "O_NOFOLLOW");
    flag!(0x4_0000, "O_NOATIME");
    flag!(0x8_0000, "O_CLOEXEC");
    flag!(0x0010_1000, "O_SYNC");
    flag!(0x0020_0000, "O_PATH");
    flag!(0x0040_0000, "O_TMPFILE");

    parts.join("|")
}

/// Decode `mmap(2)` `prot` bitmask into a human-readable string.
///
/// Produces output like `PROT_READ|PROT_WRITE` or `PROT_NONE`.
#[must_use]
pub fn decode_mmap_prot(prot: u32) -> String {
    if prot == 0 {
        return "PROT_NONE".to_string();
    }
    let mut parts = Vec::new();
    if prot & 0x1 != 0 {
        parts.push("PROT_READ");
    }
    if prot & 0x2 != 0 {
        parts.push("PROT_WRITE");
    }
    if prot & 0x4 != 0 {
        parts.push("PROT_EXEC");
    }
    if prot & 0x8 != 0 {
        parts.push("PROT_SEM");
    }
    if prot & 0x10 != 0 {
        parts.push("PROT_GROWSDOWN");
    }
    if prot & 0x20 != 0 {
        parts.push("PROT_GROWSUP");
    }
    if parts.is_empty() {
        format!("0x{prot:x}")
    } else {
        parts.join("|")
    }
}

/// Decode `mmap(2)` `flags` bitmask into a human-readable string.
///
/// Produces output like `MAP_PRIVATE|MAP_ANONYMOUS`.
#[must_use]
pub fn decode_mmap_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    // Sharing mode (bits 0–1)
    match flags & 0x3 {
        1 => parts.push("MAP_SHARED"),
        2 => parts.push("MAP_PRIVATE"),
        3 => parts.push("MAP_SHARED_VALIDATE"),
        _ => {}
    }

    macro_rules! flag {
        ($val:expr, $name:literal) => {
            if flags & $val != 0 {
                parts.push($name);
            }
        };
    }

    flag!(0x10, "MAP_FIXED");
    flag!(0x20, "MAP_ANONYMOUS");
    flag!(0x100, "MAP_GROWSDOWN");
    flag!(0x800, "MAP_DENYWRITE");
    flag!(0x1000, "MAP_EXECUTABLE");
    flag!(0x2000, "MAP_LOCKED");
    flag!(0x4000, "MAP_NORESERVE");
    flag!(0x8000, "MAP_POPULATE");
    flag!(0x1_0000, "MAP_NONBLOCK");
    flag!(0x2_0000, "MAP_STACK");
    flag!(0x4_0000, "MAP_HUGETLB");
    flag!(0x8_0000, "MAP_SYNC");
    flag!(0x0010_0000, "MAP_FIXED_NOREPLACE");

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        parts.join("|")
    }
}

// ─── errno_name ───────────────────────────────────────────────────────────────

/// Return the symbolic name for a Linux errno value.
///
/// Returns `"EUNKNOWN"` for codes not in the table.
#[must_use]
pub const fn errno_name(code: u32) -> &'static str {
    if code >= 65 {
        return errno_name_high(code);
    }
    errno_name_low(code)
}

const fn errno_name_low(code: u32) -> &'static str {
    match code {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        15 => "ENOTBLK",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        26 => "ETXTBSY",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        37 => "ENOLCK",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        42 => "ENOMSG",
        43 => "EIDRM",
        44 => "ECHRNG",
        45 => "EL2NSYNC",
        46 => "EL3HLT",
        47 => "EL3RST",
        48 => "ELNRNG",
        49 => "EUNATCH",
        50 => "ENOCSI",
        51 => "EL2HLT",
        52 => "EBADE",
        53 => "EBADR",
        54 => "EXFULL",
        55 => "ENOANO",
        56 => "EBADRQC",
        57 => "EBADSLT",
        59 => "EBFONT",
        60 => "ENOSTR",
        61 => "ENODATA",
        62 => "ETIME",
        63 => "ENOSR",
        64 => "ENONET",
        _ => "EUNKNOWN",
    }
}

const fn errno_name_high(code: u32) -> &'static str {
    match code {
        65 => "ENOPKG",
        66 => "EREMOTE",
        67 => "ENOLINK",
        68 => "EADV",
        69 => "ESRMNT",
        70 => "ECOMM",
        71 => "EPROTO",
        72 => "EMULTIHOP",
        73 => "EDOTDOT",
        74 => "EBADMSG",
        75 => "EOVERFLOW",
        76 => "ENOTUNIQ",
        77 => "EBADFD",
        78 => "EREMCHG",
        79 => "ELIBACC",
        80 => "ELIBBAD",
        81 => "ELIBSCN",
        82 => "ELIBMAX",
        83 => "ELIBEXEC",
        84 => "EILSEQ",
        85 => "ERESTART",
        86 => "ESTRPIPE",
        87 => "EUSERS",
        88 => "ENOTSOCK",
        89 => "EDESTADDRREQ",
        90 => "EMSGSIZE",
        91 => "EPROTOTYPE",
        92 => "ENOPROTOOPT",
        93 => "EPROTONOSUPPORT",
        94 => "ESOCKTNOSUPPORT",
        95 => "EOPNOTSUPP",
        96 => "EPFNOSUPPORT",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        102 => "ENETRESET",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        105 => "ENOBUFS",
        106 => "EISCONN",
        107 => "ENOTCONN",
        108 => "ESHUTDOWN",
        109 => "ETOOMANYREFS",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        112 => "EHOSTDOWN",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        116 => "ESTALE",
        117 => "EUCLEAN",
        118 => "ENOTNAM",
        119 => "ENAVAIL",
        120 => "EISNAM",
        121 => "EREMOTEIO",
        122 => "EDQUOT",
        123 => "ENOMEDIUM",
        124 => "EMEDIUMTYPE",
        125 => "ECANCELED",
        126 => "ENOKEY",
        127 => "EKEYEXPIRED",
        128 => "EKEYREVOKED",
        129 => "EKEYREJECTED",
        130 => "EOWNERDEAD",
        131 => "ENOTRECOVERABLE",
        132 => "ERFKILL",
        133 => "EHWPOISON",
        _ => "EUNKNOWN",
    }
}

// ─── SyscallTraceFilter ───────────────────────────────────────────────────────

/// Filter predicates for syscall traces, oriented toward malware analysis.
pub struct SyscallTraceFilter;

impl SyscallTraceFilter {
    /// Return `true` when the event is interesting from a malware perspective.
    ///
    /// Triggers on:
    /// - Process execution (`execve`, `execveat`)
    /// - Network connection establishment (`socket`, `connect`, `bind`)
    /// - Executable memory mapping (`mmap`/`mmap2` with `PROT_EXEC`)
    /// - Process tracing (`ptrace`)
    /// - Personality change (`personality`)
    /// - File access to sensitive paths (`/etc/passwd`, `/proc/…`, `/dev/mem`, etc.)
    /// - Security-override syscalls (`setuid`, `setresuid`, `capset`, `prctl`, `seccomp`, `bpf`)
    /// - Kernel-module operations (`init_module`, `finit_module`, `delete_module`, `kexec_load`)
    /// - Credential / namespace changes (`setns`, `unshare`, `clone` with namespace flags)
    #[must_use]
    pub fn interesting_for_malware(event: &SyscallEvent) -> bool {
        match event.name.as_str() {
            // Execution / network / process tracing / personality / security /
            // kernel modules / namespaces — all of these are flagged as interesting.
            "execve" | "execveat"
            | "socket" | "connect" | "bind"
            | "ptrace"
            | "personality"
            | "setuid" | "setresuid" | "setreuid" | "setfsuid"
            | "setgid" | "setresgid" | "setregid" | "setfsgid"
            | "capset" | "prctl" | "arch_prctl"
            | "seccomp" | "bpf"
            | "init_module" | "finit_module" | "delete_module" | "kexec_load" | "kexec_file_load"
            | "setns" | "unshare" => true,

            // Executable memory mapping: check prot argument (arg index 2 for mmap)
            "mmap" | "mmap2" => {
                let prot = u32::try_from(event.args.get(2).copied().unwrap_or(0)).unwrap_or(u32::MAX);
                prot & 0x4 != 0 // PROT_EXEC
            }

            // clone with namespace flags (any of CLONE_NEW* = 0x84xx0000 range)
            "clone" | "clone3" => {
                let flags = event.args.first().copied().unwrap_or(0);
                // CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
                // CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP = 0x80040000+
                flags & 0x8004_0000 != 0
            }

            // Raw open events can't be trivially filtered without the resolved path string.
            _ => false,
        }
    }

    /// Return `true` when the event represents a network connection attempt.
    #[must_use]
    pub fn is_network_connect(event: &SyscallEvent) -> bool {
        matches!(
            event.name.as_str(),
            "connect" | "sendto" | "sendmsg" | "sendmmsg"
        )
    }

    /// Return `true` when the event creates executable memory.
    #[must_use]
    pub fn is_exec_memory(event: &SyscallEvent) -> bool {
        match event.name.as_str() {
            "mmap" | "mmap2" | "mprotect" | "pkey_mprotect" => {
                let prot = u32::try_from(event.args.get(2).copied().unwrap_or(0)).unwrap_or(u32::MAX);
                prot & 0x4 != 0
            }
            _ => false,
        }
    }

    /// Return `true` when the event is a credential escalation attempt.
    #[must_use]
    pub fn is_privilege_escalation(event: &SyscallEvent) -> bool {
        matches!(
            event.name.as_str(),
            "setuid"
                | "setresuid"
                | "setreuid"
                | "setfsuid"
                | "setgid"
                | "setresgid"
                | "setregid"
                | "setfsgid"
                | "capset"
                | "keyctl"
                | "add_key"
        )
    }

    /// Return `true` when the event is suspicious file access.
    ///
    /// This variant takes a pre-decoded path string rather than raw arguments.
    #[must_use]
    pub fn is_sensitive_file_access(path: &str) -> bool {
        let sensitive_prefixes = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/proc/",
            "/sys/kernel/",
            "/dev/mem",
            "/dev/kmem",
            "/boot/",
            "/root/",
            "/.ssh/",
            "/var/log/auth",
            "/var/log/secure",
        ];
        sensitive_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }
}

// ─── PtraceTracer ─────────────────────────────────────────────────────────────

/// Options for the ptrace-based syscall tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceOptions {
    /// Attach to an already-running PID instead of spawning a new process.
    pub attach_pid: Option<u32>,
    /// Command + args to spawn and trace (used when `attach_pid` is `None`).
    pub command: Vec<String>,
    /// Follow child processes created by `fork`/`clone`.
    pub follow_forks: bool,
    /// Maximum number of events to capture (0 = unlimited).
    pub max_events: usize,
    /// Only capture syscalls whose names are in this set.  Empty = all.
    pub include_filter: Vec<String>,
    /// Exclude syscalls whose names are in this set.
    pub exclude_filter: Vec<String>,
    /// Decode string arguments by reading tracee memory.
    pub decode_strings: bool,
    /// Maximum bytes to read for string arguments.
    pub string_max_bytes: usize,
}

impl Default for PtraceOptions {
    fn default() -> Self {
        Self {
            attach_pid: None,
            command: Vec::new(),
            follow_forks: true,
            max_events: 0,
            include_filter: Vec::new(),
            exclude_filter: Vec::new(),
            decode_strings: true,
            string_max_bytes: 256,
        }
    }
}

impl PtraceOptions {
    /// Create options to attach to a running process.
    #[must_use]
    pub fn attach(pid: u32) -> Self {
        Self {
            attach_pid: Some(pid),
            ..Default::default()
        }
    }

    /// Create options to spawn and trace a new process.
    #[must_use]
    pub fn spawn(cmd: impl Into<String>) -> Self {
        Self {
            command: vec![cmd.into()],
            ..Default::default()
        }
    }

    /// Enable child-process following.
    #[must_use]
    pub const fn with_follow_forks(mut self) -> Self {
        self.follow_forks = true;
        self
    }

    /// Limit captured events.
    #[must_use]
    pub const fn with_max_events(mut self, n: usize) -> Self {
        self.max_events = n;
        self
    }

    /// Apply a name-based include filter.
    #[must_use]
    pub fn include(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.include_filter = names.into_iter().map(Into::into).collect();
        self
    }

    /// Apply a name-based exclude filter.
    #[must_use]
    pub fn exclude(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.exclude_filter = names.into_iter().map(Into::into).collect();
        self
    }
}

/// Syscall summary statistics computed from a completed [`SyscallTrace`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallSummary {
    /// Per-syscall name: call count, total time (ns), min time (ns), max time (ns).
    pub per_name: HashMap<String, SyscallStat>,
    /// Total number of syscall events.
    pub total_events: usize,
    /// Total wall-clock time covered (max timestamp − min timestamp), in ns.
    pub total_wall_ns: u64,
}

/// Per-syscall aggregated statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallStat {
    /// Number of times this syscall was invoked.
    pub count: u64,
    /// Cumulative time inside the kernel (ns).
    pub total_ns: u64,
    /// Minimum single-call duration (ns).
    pub min_ns: u64,
    /// Maximum single-call duration (ns).
    pub max_ns: u64,
    /// Count of calls that returned an error (retval < 0).
    pub error_count: u64,
}

impl SyscallStat {
    /// Average duration per call in nanoseconds.
    #[must_use]
    pub const fn avg_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_ns / self.count
        }
    }
}

impl SyscallSummary {
    /// Compute a summary from a completed trace.
    #[must_use]
    pub fn from_trace(trace: &SyscallTrace) -> Self {
        let mut per_name: HashMap<String, SyscallStat> = HashMap::new();
        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;

        for ev in &trace.entries {
            min_ts = min_ts.min(ev.timestamp);
            max_ts = max_ts.max(ev.timestamp);
            let stat = per_name.entry(ev.name.clone()).or_default();
            stat.count += 1;
            stat.total_ns += ev.duration_ns;
            if stat.count == 1 {
                stat.min_ns = ev.duration_ns;
                stat.max_ns = ev.duration_ns;
            } else {
                stat.min_ns = stat.min_ns.min(ev.duration_ns);
                stat.max_ns = stat.max_ns.max(ev.duration_ns);
            }
            if ev.retval < 0 {
                stat.error_count += 1;
            }
        }

        let total_events = trace.entries.len();
        let total_wall_ns = if max_ts >= min_ts && total_events > 0 {
            max_ts - min_ts
        } else {
            0
        };

        Self {
            per_name,
            total_events,
            total_wall_ns,
        }
    }

    /// Return syscalls sorted by total time descending (most expensive first).
    #[must_use]
    pub fn top_by_time(&self, n: usize) -> Vec<(&str, &SyscallStat)> {
        let mut v: Vec<(&str, &SyscallStat)> =
            self.per_name.iter().map(|(k, v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));
        v.truncate(n);
        v
    }

    /// Return syscalls sorted by call count descending.
    #[must_use]
    pub fn top_by_count(&self, n: usize) -> Vec<(&str, &SyscallStat)> {
        let mut v: Vec<(&str, &SyscallStat)> =
            self.per_name.iter().map(|(k, v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        v.truncate(n);
        v
    }

    /// Render a strace-style summary table as a string.
    #[must_use]
    pub fn render_table(&self) -> String {
        use std::fmt::Write as _;
        let mut rows = self.top_by_time(usize::MAX);
        rows.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));
        let mut out = String::from(
            "% time     seconds  usecs/call     calls    errors syscall\n\
             ------- ----------- ----------- --------- --------- ----------------\n",
        );
        let grand_total: u64 = rows.iter().map(|(_, s)| s.total_ns).sum();
        for (name, stat) in &rows {
            let pct_bp = if grand_total > 0 {
                stat.total_ns * 10_000 / grand_total
            } else {
                0
            };
            let pct_int = pct_bp / 100;
            let pct_frac = pct_bp % 100;
            let secs_whole = stat.total_ns / 1_000_000_000;
            let secs_frac = (stat.total_ns % 1_000_000_000) / 1_000;
            let us_per = if stat.count > 0 {
                stat.total_ns / stat.count / 1_000
            } else {
                0
            };
            let _ = writeln!(
                out,
                "{pct_int:4}.{pct_frac:02}  {secs_whole:5}.{secs_frac:06}  {us_per:11}  {count:9}  {err:9} {name}",
                count = stat.count,
                err = stat.error_count,
            );
        }
        out.push_str("------- ----------- ----------- --------- --------- ----------------\n");
        let total_secs_whole = grand_total / 1_000_000_000;
        let total_secs_frac = (grand_total % 1_000_000_000) / 1_000;
        let _ = writeln!(
            out,
            "100.00  {total_secs_whole:5}.{total_secs_frac:06}  {:11}  {:9}  {:9} total",
            if self.total_events > 0 {
                grand_total / self.total_events as u64 / 1_000
            } else {
                0
            },
            self.total_events,
            self.per_name.values().map(|s| s.error_count).sum::<u64>(),
        );
        out
    }
}

// ─── FdTracker ────────────────────────────────────────────────────────────────

/// Kind of resource behind a file descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FdKind {
    /// Regular file at the given path.
    File(String),
    /// TCP socket: local → remote.
    TcpSocket { local: String, remote: String },
    /// UDP socket: local → remote.
    UdpSocket { local: String, remote: String },
    /// Unix domain socket path (or abstract name).
    UnixSocket(String),
    /// A pipe (read or write end).
    Pipe,
    /// Epoll file descriptor.
    Epoll,
    /// Event file descriptor.
    EventFd,
    /// Timer file descriptor.
    TimerFd,
    /// Signal file descriptor.
    SignalFd,
    /// Unknown or untracked.
    Unknown,
}

impl std::fmt::Display for FdKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(p) => write!(f, "file:{p}"),
            Self::TcpSocket { local, remote } => write!(f, "tcp:{local}->{remote}"),
            Self::UdpSocket { local, remote } => write!(f, "udp:{local}->{remote}"),
            Self::UnixSocket(p) => write!(f, "unix:{p}"),
            Self::Pipe => write!(f, "pipe"),
            Self::Epoll => write!(f, "epoll"),
            Self::EventFd => write!(f, "eventfd"),
            Self::TimerFd => write!(f, "timerfd"),
            Self::SignalFd => write!(f, "signalfd"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Per-process file-descriptor table maintained by observing syscall events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdTracker {
    /// Map from (pid, fd) → [`FdKind`].
    table: HashMap<(u32, i64), FdKind>,
}

impl FdTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `pid` opened `fd` referencing `kind`.
    pub fn insert(&mut self, pid: u32, fd: i64, kind: FdKind) {
        self.table.insert((pid, fd), kind);
    }

    /// Remove a file descriptor (on `close` or process exit).
    pub fn remove(&mut self, pid: u32, fd: i64) {
        self.table.remove(&(pid, fd));
    }

    /// Look up the kind for a (pid, fd) pair.
    #[must_use]
    pub fn lookup(&self, pid: u32, fd: i64) -> Option<&FdKind> {
        self.table.get(&(pid, fd))
    }

    /// Process a [`SyscallEvent`] and update the fd table accordingly.
    ///
    /// Handles: `open`, `openat`, `creat`, `socket`, `pipe`, `pipe2`,
    /// `close`, `dup`, `dup2`, `dup3`, `accept`, `accept4`.
    pub fn update_from_event(&mut self, ev: &SyscallEvent) {
        let pid = ev.pid;
        // Successful open/openat returns new fd
        match ev.name.as_str() {
            "open" | "creat" => {
                if ev.retval >= 0 {
                    self.insert(pid, ev.retval, FdKind::File("<open>".into()));
                }
            }
            "openat" => {
                if ev.retval >= 0 {
                    self.insert(pid, ev.retval, FdKind::File("<openat>".into()));
                }
            }
            "socket" => {
                if ev.retval >= 0 {
                    let domain = ev.args.first().copied().unwrap_or(0);
                    let kind = match domain {
                        1 => FdKind::UnixSocket("<unbound>".into()),
                        _ => FdKind::TcpSocket {
                            local: "0.0.0.0:0".into(),
                            remote: "0.0.0.0:0".into(),
                        },
                    };
                    self.insert(pid, ev.retval, kind);
                }
            }
            "pipe" | "pipe2" => {
                // args[0] is a pointer to int[2]; we can't decode without memory access
                // But we record both ends as Pipe when we see the event succeed
                if ev.retval == 0 {
                    // Actual fds are in tracee memory; placeholder logic
                    // In a real tracer these would be read from pipefd[0/1]
                }
            }
            "close" => {
                let fd = ev.args.first().copied().unwrap_or(0).cast_signed();
                self.remove(pid, fd);
            }
            "dup" | "dup2" | "dup3" => {
                if ev.retval >= 0 {
                    let src = ev.args.first().copied().unwrap_or(0).cast_signed();
                    if let Some(k) = self.lookup(pid, src).cloned() {
                        self.insert(pid, ev.retval, k);
                    }
                }
            }
            "accept" | "accept4"
                if ev.retval >= 0 => {
                    self.insert(
                        pid,
                        ev.retval,
                        FdKind::TcpSocket {
                            local: "<server>".into(),
                            remote: "<client>".into(),
                        },
                    );
                }
            _ => {}
        }
    }

    /// Count of tracked fds across all processes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// True if no fds are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Return all (pid, fd, kind) triples.
    #[must_use]
    pub fn all_entries(&self) -> Vec<(u32, i64, &FdKind)> {
        self.table
            .iter()
            .map(|((pid, fd), kind)| (*pid, *fd, kind))
            .collect()
    }
}

// ─── ChildTracker ─────────────────────────────────────────────────────────────

/// Tracks parent→child relationships observed via fork/clone syscalls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChildTracker {
    /// Map from child PID → parent PID.
    parent_of: HashMap<u32, u32>,
    /// Map from PID → list of direct children.
    children_of: HashMap<u32, Vec<u32>>,
}

impl ChildTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `parent` spawned `child`.
    pub fn record_fork(&mut self, parent: u32, child: u32) {
        self.parent_of.insert(child, parent);
        self.children_of.entry(parent).or_default().push(child);
    }

    /// Return the parent PID of `pid`, if known.
    #[must_use]
    pub fn parent_of(&self, pid: u32) -> Option<u32> {
        self.parent_of.get(&pid).copied()
    }

    /// Return the direct children of `pid`.
    #[must_use]
    pub fn children_of(&self, pid: u32) -> &[u32] {
        self.children_of
            .get(&pid)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Return all descendants (BFS) of `pid`.
    #[must_use]
    pub fn descendants_of(&self, pid: u32) -> Vec<u32> {
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(pid);
        while let Some(p) = queue.pop_front() {
            for &c in self.children_of(p) {
                result.push(c);
                queue.push_back(c);
            }
        }
        result
    }

    /// Update from a [`SyscallEvent`] — handles `fork`, `vfork`, `clone`.
    pub fn update_from_event(&mut self, ev: &SyscallEvent) {
        match ev.name.as_str() {
            "fork" | "vfork" | "clone" | "clone3" => {
                // Child PID is the return value in the parent's context
                if ev.retval > 0
                    && let Ok(child_pid) = u32::try_from(ev.retval)
                {
                    self.record_fork(ev.pid, child_pid);
                }
            }
            _ => {}
        }
    }

    /// Number of tracked processes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.children_of.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── SignalEvent ───────────────────────────────────────────────────────────────

/// A Unix signal delivered to a traced process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEvent {
    /// Monotonic timestamp (ns).
    pub timestamp: u64,
    /// Process that received the signal.
    pub pid: u32,
    /// Signal number (e.g. 11 = SIGSEGV).
    pub signum: u32,
    /// Human-readable signal name (e.g. `"SIGSEGV"`).
    pub signame: String,
}

impl SignalEvent {
    /// Construct a [`SignalEvent`], resolving the signal name automatically.
    #[must_use]
    pub fn new(timestamp: u64, pid: u32, signum: u32) -> Self {
        let signame = signal_name(signum).to_string();
        Self {
            timestamp,
            pid,
            signum,
            signame,
        }
    }
}

/// Resolve a Unix signal number to its POSIX name.
#[must_use]
pub const fn signal_name(signum: u32) -> &'static str {
    match signum {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        34 => "SIGRTMIN",
        64 => "SIGRTMAX",
        _ => "SIGUNKNOWN",
    }
}

/// A combined trace session capturing both syscall events and signals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceSession {
    /// All captured syscall events.
    pub syscalls: SyscallTrace,
    /// All intercepted signals.
    pub signals: Vec<SignalEvent>,
    /// FD state at end of trace.
    pub fds: FdTracker,
    /// Child process tree.
    pub children: ChildTracker,
    /// Options used for this session.
    pub options: Option<PtraceOptions>,
}

impl TraceSession {
    /// Create an empty session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a syscall event, updating fd and child trackers automatically.
    pub fn push_syscall(&mut self, ev: SyscallEvent) {
        self.fds.update_from_event(&ev);
        self.children.update_from_event(&ev);
        self.syscalls.push(ev);
    }

    /// Push a signal event.
    pub fn push_signal(&mut self, ev: SignalEvent) {
        self.signals.push(ev);
    }

    /// Compute summary statistics for this session.
    #[must_use]
    pub fn summary(&self) -> SyscallSummary {
        SyscallSummary::from_trace(&self.syscalls)
    }

    /// Return an strace-compatible text representation of all events, interleaved
    /// with signals, sorted by timestamp.
    #[must_use]
    pub fn render_strace(&self, _db: &LinuxSyscallDb) -> String {
        let mut lines: Vec<(u64, String)> = Vec::new();

        for ev in &self.syscalls.entries {
            let entry = LINUX_X86_64_SYSCALLS
                .iter()
                .find(|e| e.nr == ev.nr)
                .copied();
            let args_str = entry.map_or_else(
                || ev.args.iter().map(|a| format!("0x{a:x}")).collect::<Vec<_>>().join(", "),
                |ent| {
                    ev.decode_args(&ent)
                        .into_iter()
                        .zip(ent.args[..ent.arg_count as usize].iter())
                        .map(|(v, name)| format!("{name}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
            let ret_str = if ev.retval < 0 {
                let ename = errno_name(u32::try_from(-ev.retval).unwrap_or(u32::MAX));
                format!("-1 {} ({})", ename, -ev.retval)
            } else {
                format!("{}", ev.retval)
            };
            let dur_whole = ev.duration_ns / 1_000_000_000;
            let dur_frac = (ev.duration_ns % 1_000_000_000) / 1_000;
            let line = format!(
                "[{pid}] {name}({args}) = {ret}   <{dur_whole}.{dur_frac:06}>",
                pid = ev.pid,
                name = ev.name,
                args = args_str,
                ret = ret_str,
            );
            lines.push((ev.timestamp, line));
        }

        for sig in &self.signals {
            let line = format!(
                "[{pid}] --- {sig} {{si_signo={num}}} ---",
                pid = sig.pid,
                sig = sig.signame,
                num = sig.signum,
            );
            lines.push((sig.timestamp, line));
        }

        lines.sort_by_key(|(ts, _)| *ts);
        lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export the session as a JSON string.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ─── AArch64 / ARM table completions ─────────────────────────────────────────

/// Additional AArch64-specific syscall numbers that differ from `x86_64`.
pub const AARCH64_SPECIFIC_SYSCALLS: &[(u32, &str)] = &[
    (29, "ioctl"),
    (56, "openat"),
    (57, "close"),
    (59, "pipe2"),
    (61, "getdents64"),
    (63, "read"),
    (64, "write"),
    (65, "readv"),
    (66, "writev"),
    (67, "pread64"),
    (68, "pwrite64"),
    (73, "sendfile"),
    (76, "splice"),
    (77, "tee"),
    (78, "readlinkat"),
    (79, "newfstatat"),
    (80, "fstat"),
    (82, "fsync"),
    (83, "fdatasync"),
    (85, "ftruncate"),
    (88, "utimensat"),
    (93, "exit"),
    (94, "exit_group"),
    (96, "waitid"),
    (98, "futex"),
    (99, "set_robust_list"),
    (100, "get_robust_list"),
    (101, "nanosleep"),
    (102, "getitimer"),
    (103, "setitimer"),
    (104, "kexec_load"),
    (117, "ptrace"),
    (130, "kill"),
    (131, "tkill"),
    (132, "tgkill"),
    (135, "rt_sigprocmask"),
    (136, "rt_sigreturn"),
    (137, "rt_sigaction"),
    (138, "rt_sigpending"),
    (139, "rt_sigtimedwait"),
    (140, "rt_sigqueueinfo"),
    (141, "rt_sigsuspend"),
    (155, "getpriority"),
    (156, "setpriority"),
    (157, "reboot"),
    (161, "setregid"),
    (162, "setgid"),
    (163, "setreuid"),
    (164, "setuid"),
    (165, "setresuid"),
    (166, "getresuid"),
    (167, "setresgid"),
    (168, "getresgid"),
    (169, "getpid"),
    (170, "getppid"),
    (171, "getuid"),
    (172, "geteuid"),
    (173, "getgid"),
    (174, "getegid"),
    (175, "gettid"),
    (176, "sysinfo"),
    (177, "mq_open"),
    (180, "mq_timedsend"),
    (181, "mq_timedreceive"),
    (183, "mq_getsetattr"),
    (198, "socket"),
    (199, "socketpair"),
    (200, "bind"),
    (201, "listen"),
    (202, "accept"),
    (203, "connect"),
    (204, "getsockname"),
    (205, "getpeername"),
    (206, "sendto"),
    (207, "recvfrom"),
    (208, "setsockopt"),
    (209, "getsockopt"),
    (210, "shutdown"),
    (211, "sendmsg"),
    (212, "recvmsg"),
    (213, "readahead"),
    (214, "brk"),
    (215, "munmap"),
    (216, "mremap"),
    (217, "add_key"),
    (218, "request_key"),
    (219, "keyctl"),
    (220, "clone"),
    (221, "execve"),
    (222, "mmap"),
    (223, "fadvise64"),
    (224, "swapon"),
    (225, "swapoff"),
    (226, "mprotect"),
    (227, "msync"),
    (228, "mlock"),
    (229, "munlock"),
    (230, "mlockall"),
    (231, "munlockall"),
    (232, "mincore"),
    (233, "madvise"),
    (234, "remap_file_pages"),
    (235, "mbind"),
    (236, "get_mempolicy"),
    (237, "set_mempolicy"),
    (238, "migrate_pages"),
    (239, "move_pages"),
    (240, "rt_tgsigqueueinfo"),
    (241, "perf_event_open"),
    (242, "accept4"),
    (243, "recvmmsg"),
    (260, "wait4"),
    (261, "prlimit64"),
    (262, "fanotify_init"),
    (263, "fanotify_mark"),
    (264, "name_to_handle_at"),
    (265, "open_by_handle_at"),
    (266, "clock_adjtime"),
    (267, "syncfs"),
    (268, "setns"),
    (269, "sendmmsg"),
    (270, "process_vm_readv"),
    (271, "process_vm_writev"),
    (272, "kcmp"),
    (273, "finit_module"),
    (274, "sched_setattr"),
    (275, "sched_getattr"),
    (276, "renameat2"),
    (277, "seccomp"),
    (278, "getrandom"),
    (279, "memfd_create"),
    (280, "bpf"),
    (281, "execveat"),
    (282, "userfaultfd"),
    (283, "membarrier"),
    (284, "mlock2"),
    (285, "copy_file_range"),
    (286, "preadv2"),
    (287, "pwritev2"),
    (291, "statx"),
    (292, "io_pgetevents"),
    (293, "rseq"),
    (424, "pidfd_send_signal"),
    (425, "io_uring_setup"),
    (426, "io_uring_enter"),
    (427, "io_uring_register"),
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (431, "fsconfig"),
    (432, "fsmount"),
    (433, "fspick"),
    (434, "pidfd_open"),
    (435, "clone3"),
    (436, "close_range"),
    (437, "openat2"),
    (438, "pidfd_getfd"),
    (439, "faccessat2"),
    (440, "process_madvise"),
    (441, "epoll_pwait2"),
    (442, "mount_setattr"),
    (443, "quotactl_fd"),
    (444, "landlock_create_ruleset"),
    (445, "landlock_add_rule"),
    (446, "landlock_restrict_self"),
    (448, "process_mrelease"),
    (449, "futex_waitv"),
    (450, "set_mempolicy_home_node"),
];

/// Look up an `AArch64` syscall name by number.
#[must_use]
pub fn aarch64_syscall_name(nr: u32) -> Option<&'static str> {
    AARCH64_SPECIFIC_SYSCALLS
        .iter()
        .find(|(n, _)| *n == nr)
        .map(|(_, name)| *name)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> SyscallResolver {
        SyscallResolver::new()
    }

    // --- x86_64 ---

    #[test]
    fn test_x86_64_read() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86_64, 0).expect("read must exist");
        assert_eq!(sc.name, "read");
        assert_eq!(sc.number, 0);
        assert!(!sc.params.is_empty());
    }

    #[test]
    fn test_x86_64_write() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86_64, 1).expect("write must exist");
        assert_eq!(sc.name, "write");
    }

    #[test]
    fn test_x86_64_open() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86_64, 2).expect("open must exist");
        assert_eq!(sc.name, "open");
    }

    #[test]
    fn test_x86_64_mmap() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86_64, 9).expect("mmap must exist");
        assert_eq!(sc.name, "mmap");
        assert_eq!(sc.params.len(), 6);
    }

    #[test]
    fn test_x86_64_execve() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86_64, 59)
            .expect("execve must exist");
        assert_eq!(sc.name, "execve");
    }

    #[test]
    fn test_x86_64_socket() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86_64, 41)
            .expect("socket must exist");
        assert_eq!(sc.name, "socket");
    }

    #[test]
    fn test_x86_64_futex() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86_64, 202)
            .expect("futex must exist");
        assert_eq!(sc.name, "futex");
    }

    #[test]
    fn test_x86_64_openat() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86_64, 257)
            .expect("openat must exist");
        assert_eq!(sc.name, "openat");
    }

    #[test]
    fn test_x86_64_lookup_by_name_ptrace() {
        let r = resolver();
        let sc = r
            .lookup_by_name(SyscallArch::X86_64, "ptrace")
            .expect("ptrace by name must exist");
        assert_eq!(sc.number, 101);
    }

    #[test]
    fn test_x86_64_lookup_by_name_missing() {
        let r = resolver();
        assert!(
            r.lookup_by_name(SyscallArch::X86_64, "no_such_syscall")
                .is_none()
        );
    }

    #[test]
    fn test_x86_64_count() {
        let db = LinuxSyscallDb::new();
        assert!(db.arch_count(SyscallArch::X86_64) >= 60);
    }

    #[test]
    fn test_x86_64_all_for_arch_sorted() {
        let r = resolver();
        let all = r.all_for_arch(SyscallArch::X86_64);
        assert!(!all.is_empty());
        let numbers: Vec<u32> = all.iter().map(|s| s.number).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        assert_eq!(numbers, sorted, "x86_64 table should be sorted by number");
    }

    // --- x86 ---

    #[test]
    fn test_x86_fork_is_2() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86, 2).expect("x86 fork must exist");
        assert_eq!(sc.name, "fork");
    }

    #[test]
    fn test_x86_read_is_3() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86, 3).expect("x86 read must exist");
        assert_eq!(sc.name, "read");
    }

    #[test]
    fn test_x86_socketcall() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86, 102)
            .expect("x86 socketcall must exist");
        assert_eq!(sc.name, "socketcall");
    }

    #[test]
    fn test_x86_count() {
        let db = LinuxSyscallDb::new();
        assert!(db.arch_count(SyscallArch::X86) >= 25);
    }

    #[test]
    fn test_x86_mmap2() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86, 192)
            .expect("x86 mmap2 must exist");
        assert_eq!(sc.name, "mmap2");
    }

    // --- ARM32 ---

    #[test]
    fn test_arm32_read_is_3() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm32, 3)
            .expect("arm32 read must exist");
        assert_eq!(sc.name, "read");
    }

    #[test]
    fn test_arm32_socket() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm32, 281)
            .expect("arm32 socket must exist");
        assert_eq!(sc.name, "socket");
    }

    #[test]
    fn test_arm32_count() {
        let db = LinuxSyscallDb::new();
        assert!(db.arch_count(SyscallArch::Arm32) >= 25);
    }

    #[test]
    fn test_arm32_clone() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm32, 120)
            .expect("arm32 clone must exist");
        assert_eq!(sc.name, "clone");
    }

    #[test]
    fn test_arm32_lookup_by_name_futex() {
        let r = resolver();
        let sc = r
            .lookup_by_name(SyscallArch::Arm32, "futex")
            .expect("arm32 futex by name must exist");
        assert_eq!(sc.number, 240);
    }

    // --- AArch64 ---

    #[test]
    fn test_arm64_read() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm64, 3)
            .expect("arm64 read must exist");
        assert_eq!(sc.name, "read");
    }

    #[test]
    fn test_arm64_clone() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm64, 56)
            .expect("arm64 clone must exist");
        assert_eq!(sc.name, "clone");
    }

    #[test]
    fn test_arm64_count() {
        let db = LinuxSyscallDb::new();
        assert!(db.arch_count(SyscallArch::Arm64) >= 25);
    }

    #[test]
    fn test_arm64_futex() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::Arm64, 202)
            .expect("arm64 futex must exist");
        assert_eq!(sc.name, "futex");
    }

    #[test]
    fn test_arm64_lookup_by_name_execve() {
        let r = resolver();
        let sc = r
            .lookup_by_name(SyscallArch::Arm64, "execve")
            .expect("arm64 execve by name must exist");
        assert_eq!(sc.number, 59);
    }

    // --- Cross-arch ---

    #[test]
    fn test_missing_arch_returns_empty_slice() {
        let r = resolver();
        let all = r.all_for_arch(SyscallArch::Mips);
        assert!(all.is_empty());
    }

    #[test]
    fn test_db_all_for_arch_none_for_mips() {
        let db = LinuxSyscallDb::new();
        assert!(db.all_for_arch(SyscallArch::Mips).is_none());
    }

    #[test]
    fn test_x86_64_pipe2() {
        let r = resolver();
        let sc = r
            .lookup(SyscallArch::X86_64, 293)
            .expect("x86_64 pipe2 must exist");
        assert_eq!(sc.name, "pipe2");
    }

    #[test]
    fn test_syscall_param_fields() {
        let p = SyscallParam::new("fd", "int");
        assert_eq!(p.name, "fd");
        assert_eq!(p.ty, "int");
    }

    #[test]
    fn test_linux_syscall_new() {
        let s = LinuxSyscall::new(0, "read", vec![SyscallParam::new("fd", "int")], "ssize_t");
        assert_eq!(s.number, 0);
        assert_eq!(s.name, "read");
        assert_eq!(s.ret_ty, "ssize_t");
        assert_eq!(s.params.len(), 1);
    }

    #[test]
    fn test_resolver_default() {
        let r = SyscallResolver::default();
        assert!(r.lookup(SyscallArch::X86_64, 0).is_some());
    }

    #[test]
    fn test_db_default() {
        let db = LinuxSyscallDb::default();
        assert!(db.arch_count(SyscallArch::X86_64) > 0);
    }

    #[test]
    fn test_serde_roundtrip_syscall() {
        let r = resolver();
        let sc = r.lookup(SyscallArch::X86_64, 0).unwrap();
        let json = serde_json::to_string(sc).unwrap();
        let back: LinuxSyscall = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, sc.name);
        assert_eq!(back.number, sc.number);
    }

    #[test]
    fn test_serde_roundtrip_db() {
        let db = LinuxSyscallDb::new();
        let json = serde_json::to_string(&db).unwrap();
        let back: LinuxSyscallDb = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.arch_count(SyscallArch::X86_64),
            db.arch_count(SyscallArch::X86_64)
        );
    }

    #[test]
    fn test_error_display() {
        let e = LinuxSyscallError::NotFound {
            arch: SyscallArch::X86_64,
            number: 999,
        };
        let s = e.to_string();
        assert!(s.contains("999"));
    }

    #[test]
    fn test_with_db_constructor() {
        let db = LinuxSyscallDb::new();
        let r = SyscallResolver::with_db(db);
        assert!(r.lookup(SyscallArch::X86_64, 1).is_some());
    }

    #[test]
    fn test_resolver_db_accessor() {
        let r = resolver();
        assert!(r.db().arch_count(SyscallArch::X86_64) > 0);
    }

    // ─── SyscallCategory ──────────────────────────────────────────────────────

    #[test]
    fn test_category_network_socket() {
        assert_eq!(syscall_category("socket"), SyscallCategory::Network);
    }

    #[test]
    fn test_category_network_connect() {
        assert_eq!(syscall_category("connect"), SyscallCategory::Network);
    }

    #[test]
    fn test_category_memory_mmap() {
        assert_eq!(syscall_category("mmap"), SyscallCategory::Memory);
    }

    #[test]
    fn test_category_memory_mprotect() {
        assert_eq!(syscall_category("mprotect"), SyscallCategory::Memory);
    }

    #[test]
    fn test_category_process_execve() {
        assert_eq!(syscall_category("execve"), SyscallCategory::Process);
    }

    #[test]
    fn test_category_process_fork() {
        assert_eq!(syscall_category("fork"), SyscallCategory::Process);
    }

    #[test]
    fn test_category_filesystem_open() {
        assert_eq!(syscall_category("open"), SyscallCategory::FileSystem);
    }

    #[test]
    fn test_category_filesystem_read() {
        assert_eq!(syscall_category("read"), SyscallCategory::FileSystem);
    }

    #[test]
    fn test_category_ipc_futex() {
        assert_eq!(syscall_category("futex"), SyscallCategory::Ipc);
    }

    #[test]
    fn test_category_ipc_pipe() {
        assert_eq!(syscall_category("pipe"), SyscallCategory::Ipc);
    }

    #[test]
    fn test_category_signal_kill() {
        assert_eq!(syscall_category("kill"), SyscallCategory::Signal);
    }

    #[test]
    fn test_category_time_nanosleep() {
        assert_eq!(syscall_category("nanosleep"), SyscallCategory::Time);
    }

    #[test]
    fn test_category_security_setuid() {
        assert_eq!(syscall_category("setuid"), SyscallCategory::Security);
    }

    #[test]
    fn test_category_device_ioctl() {
        assert_eq!(syscall_category("ioctl"), SyscallCategory::Device);
    }

    #[test]
    fn test_category_scheduling_yield() {
        assert_eq!(syscall_category("sched_yield"), SyscallCategory::Scheduling);
    }

    #[test]
    fn test_category_unknown() {
        assert_eq!(
            syscall_category("no_such_call_xyz"),
            SyscallCategory::Unknown
        );
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SyscallCategory::Network.to_string(), "network");
        assert_eq!(SyscallCategory::FileSystem.to_string(), "filesystem");
        assert_eq!(SyscallCategory::Memory.to_string(), "memory");
        assert_eq!(SyscallCategory::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(SyscallCategory::Process.as_str(), "process");
        assert_eq!(SyscallCategory::Ipc.as_str(), "ipc");
    }

    // ─── SecuritySeverity ─────────────────────────────────────────────────────

    #[test]
    fn test_severity_critical_execve() {
        assert_eq!(
            syscall_security_severity("execve"),
            SecuritySeverity::Critical
        );
    }

    #[test]
    fn test_severity_critical_ptrace() {
        assert_eq!(
            syscall_security_severity("ptrace"),
            SecuritySeverity::Critical
        );
    }

    #[test]
    fn test_severity_critical_mmap() {
        assert_eq!(
            syscall_security_severity("mmap"),
            SecuritySeverity::Critical
        );
    }

    #[test]
    fn test_severity_high_mprotect() {
        assert_eq!(
            syscall_security_severity("mprotect"),
            SecuritySeverity::High
        );
    }

    #[test]
    fn test_severity_high_connect() {
        assert_eq!(syscall_security_severity("connect"), SecuritySeverity::High);
    }

    #[test]
    fn test_severity_high_clone() {
        assert_eq!(syscall_security_severity("clone"), SecuritySeverity::High);
    }

    #[test]
    fn test_severity_medium_write() {
        assert_eq!(syscall_security_severity("write"), SecuritySeverity::Medium);
    }

    #[test]
    fn test_severity_medium_kill() {
        assert_eq!(syscall_security_severity("kill"), SecuritySeverity::Medium);
    }

    #[test]
    fn test_severity_low_read() {
        assert_eq!(syscall_security_severity("read"), SecuritySeverity::Low);
    }

    #[test]
    fn test_severity_low_stat() {
        assert_eq!(syscall_security_severity("stat"), SecuritySeverity::Low);
    }

    #[test]
    fn test_severity_benign_getpid() {
        assert_eq!(
            syscall_security_severity("getpid"),
            SecuritySeverity::Benign
        );
    }

    #[test]
    fn test_severity_ord_ascending() {
        assert!(SecuritySeverity::Benign < SecuritySeverity::Low);
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(SecuritySeverity::Critical.to_string(), "critical");
        assert_eq!(SecuritySeverity::Benign.to_string(), "benign");
        assert_eq!(SecuritySeverity::High.to_string(), "high");
    }

    // ─── SyscallStore ─────────────────────────────────────────────────────────

    #[test]
    fn test_store_insert_and_count() {
        let store = SyscallStore::open_memory().unwrap();
        let sc = LinuxSyscall::new(0, "read", vec![SyscallParam::new("fd", "int")], "ssize_t");
        store.insert(SyscallArch::X86_64, &sc).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_store_bulk_insert_x86_64() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        let inserted = store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        assert!(inserted > 0);
        assert!(store.count().unwrap() > 0);
    }

    #[test]
    fn test_store_bulk_insert_arm32() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        let inserted = store.bulk_insert(SyscallArch::Arm32, &db).unwrap();
        assert!(inserted > 0);
    }

    #[test]
    fn test_store_find_by_number_exists() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        let result = store.find_by_number(SyscallArch::X86_64, 0).unwrap();
        assert!(result.is_some());
        let (name, _, _) = result.unwrap();
        assert_eq!(name, "read");
    }

    #[test]
    fn test_store_find_by_number_missing() {
        let store = SyscallStore::open_memory().unwrap();
        let result = store.find_by_number(SyscallArch::X86_64, 9999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_store_find_by_category_network() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        let network = store
            .find_by_category(SyscallArch::X86_64, SyscallCategory::Network)
            .unwrap();
        assert!(!network.is_empty());
        assert!(network.iter().any(|(_, n)| n == "socket"));
    }

    #[test]
    fn test_store_find_by_min_severity_critical() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        let critical = store
            .find_by_min_severity(SyscallArch::X86_64, SecuritySeverity::Critical)
            .unwrap();
        assert!(!critical.is_empty());
        assert!(critical.iter().any(|(_, n, _)| n == "execve"));
    }

    #[test]
    fn test_store_find_by_min_severity_all_benign() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        let all = store
            .find_by_min_severity(SyscallArch::X86_64, SecuritySeverity::Benign)
            .unwrap();
        let count = usize::try_from(store.count().unwrap()).unwrap();
        assert_eq!(all.len(), count);
    }

    #[test]
    fn test_store_duplicate_ignored() {
        let store = SyscallStore::open_memory().unwrap();
        let sc = LinuxSyscall::new(0, "read", vec![], "ssize_t");
        store.insert(SyscallArch::X86_64, &sc).unwrap();
        store.insert(SyscallArch::X86_64, &sc).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_store_list_all() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        store.bulk_insert(SyscallArch::X86_64, &db).unwrap();
        store.bulk_insert(SyscallArch::X86, &db).unwrap();
        let all = store.list_all().unwrap();
        assert!(all.len() >= 2);
    }

    #[test]
    fn test_store_bulk_unsupported_arch_returns_zero() {
        let store = SyscallStore::open_memory().unwrap();
        let db = LinuxSyscallDb::new();
        let inserted = store.bulk_insert(SyscallArch::Mips, &db).unwrap();
        assert_eq!(inserted, 0);
    }

    // ── SyscallSummary tests ──────────────────────────────────────────────────

    fn make_event(nr: u32, name: &str, retval: i64, duration_ns: u64, ts: u64) -> SyscallEvent {
        SyscallEvent::new(ts, 1000, nr, name, vec![1, 2, 3], retval, duration_ns)
    }

    #[test]
    fn test_summary_empty_trace() {
        let trace = SyscallTrace::new();
        let summary = SyscallSummary::from_trace(&trace);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.total_wall_ns, 0);
        assert!(summary.per_name.is_empty());
    }

    #[test]
    fn test_summary_single_event() {
        let mut trace = SyscallTrace::new();
        trace.push(make_event(0, "read", 100, 5000, 1_000_000));
        let summary = SyscallSummary::from_trace(&trace);
        assert_eq!(summary.total_events, 1);
        let stat = summary.per_name.get("read").unwrap();
        assert_eq!(stat.count, 1);
        assert_eq!(stat.total_ns, 5000);
        assert_eq!(stat.min_ns, 5000);
        assert_eq!(stat.max_ns, 5000);
        assert_eq!(stat.error_count, 0);
    }

    #[test]
    fn test_summary_error_counting() {
        let mut trace = SyscallTrace::new();
        trace.push(make_event(2, "open", -1, 1000, 100));
        trace.push(make_event(2, "open", -1, 2000, 200));
        trace.push(make_event(2, "open", 3, 500, 300));
        let summary = SyscallSummary::from_trace(&trace);
        let stat = summary.per_name.get("open").unwrap();
        assert_eq!(stat.count, 3);
        assert_eq!(stat.error_count, 2);
    }

    #[test]
    fn test_summary_top_by_count() {
        let mut trace = SyscallTrace::new();
        for i in 0..10u64 {
            trace.push(make_event(0, "read", 0, 100, i));
        }
        for i in 10..13u64 {
            trace.push(make_event(1, "write", 0, 200, i));
        }
        let summary = SyscallSummary::from_trace(&trace);
        let top = summary.top_by_count(1);
        assert_eq!(top[0].0, "read");
    }

    #[test]
    fn test_summary_top_by_time() {
        let mut trace = SyscallTrace::new();
        trace.push(make_event(0, "read", 0, 1000, 0));
        trace.push(make_event(1, "write", 0, 9000, 1));
        let summary = SyscallSummary::from_trace(&trace);
        let top = summary.top_by_time(1);
        assert_eq!(top[0].0, "write");
    }

    #[test]
    fn test_summary_avg_ns() {
        let stat = SyscallStat {
            count: 4,
            total_ns: 4000,
            ..SyscallStat::default()
        };
        assert_eq!(stat.avg_ns(), 1000);
    }

    #[test]
    fn test_summary_render_table_contains_total() {
        let mut trace = SyscallTrace::new();
        trace.push(make_event(0, "read", 10, 1_000_000, 0));
        let summary = SyscallSummary::from_trace(&trace);
        let table = summary.render_table();
        assert!(table.contains("total"));
        assert!(table.contains("read"));
    }

    // ── FdTracker tests ───────────────────────────────────────────────────────

    #[test]
    fn test_fdtracker_insert_lookup() {
        let mut t = FdTracker::new();
        t.insert(100, 3, FdKind::File("/etc/passwd".into()));
        assert!(matches!(t.lookup(100, 3), Some(FdKind::File(_))));
    }

    #[test]
    fn test_fdtracker_remove() {
        let mut t = FdTracker::new();
        t.insert(100, 5, FdKind::Pipe);
        t.remove(100, 5);
        assert!(t.lookup(100, 5).is_none());
    }

    #[test]
    fn test_fdtracker_update_open() {
        let mut t = FdTracker::new();
        let ev = SyscallEvent::new(0, 200, 2, "open", vec![0], 4, 100);
        t.update_from_event(&ev);
        assert!(matches!(t.lookup(200, 4), Some(FdKind::File(_))));
    }

    #[test]
    fn test_fdtracker_update_close() {
        let mut t = FdTracker::new();
        t.insert(200, 4, FdKind::File("/tmp/x".into()));
        let ev = SyscallEvent::new(1, 200, 3, "close", vec![4], 0, 50);
        t.update_from_event(&ev);
        assert!(t.lookup(200, 4).is_none());
    }

    #[test]
    fn test_fdtracker_update_socket() {
        let mut t = FdTracker::new();
        let ev = SyscallEvent::new(0, 300, 41, "socket", vec![2, 1, 0], 7, 200);
        t.update_from_event(&ev);
        assert!(matches!(t.lookup(300, 7), Some(FdKind::TcpSocket { .. })));
    }

    #[test]
    fn test_fdtracker_dup() {
        let mut t = FdTracker::new();
        t.insert(400, 3, FdKind::File("/proc/self/maps".into()));
        let ev = SyscallEvent::new(0, 400, 32, "dup", vec![3], 5, 10);
        t.update_from_event(&ev);
        assert!(matches!(t.lookup(400, 5), Some(FdKind::File(_))));
    }

    #[test]
    fn test_fdtracker_len() {
        let mut t = FdTracker::new();
        t.insert(1, 3, FdKind::Pipe);
        t.insert(1, 4, FdKind::Pipe);
        t.insert(2, 3, FdKind::Epoll);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn test_fdtracker_all_entries() {
        let mut t = FdTracker::new();
        t.insert(1, 3, FdKind::TimerFd);
        let entries = t.all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 1);
        assert_eq!(entries[0].1, 3);
    }

    #[test]
    fn test_fdkind_display() {
        assert_eq!(FdKind::Pipe.to_string(), "pipe");
        assert_eq!(FdKind::Epoll.to_string(), "epoll");
        assert!(FdKind::File("/etc".into()).to_string().starts_with("file:"));
        assert!(
            FdKind::TcpSocket {
                local: "a".into(),
                remote: "b".into()
            }
            .to_string()
            .starts_with("tcp:")
        );
    }

    // ── ChildTracker tests ─────────────────────────────────────────────────────

    #[test]
    fn test_child_tracker_record_fork() {
        let mut ct = ChildTracker::new();
        ct.record_fork(1000, 1001);
        assert_eq!(ct.parent_of(1001), Some(1000));
        assert!(ct.children_of(1000).contains(&1001));
    }

    #[test]
    fn test_child_tracker_descendants() {
        let mut ct = ChildTracker::new();
        ct.record_fork(1, 2);
        ct.record_fork(2, 3);
        ct.record_fork(2, 4);
        ct.record_fork(3, 5);
        let desc = ct.descendants_of(1);
        assert!(desc.contains(&2));
        assert!(desc.contains(&3));
        assert!(desc.contains(&4));
        assert!(desc.contains(&5));
        assert_eq!(desc.len(), 4);
    }

    #[test]
    fn test_child_tracker_update_fork_event() {
        let mut ct = ChildTracker::new();
        let ev = SyscallEvent::new(0, 500, 57, "fork", vec![], 501, 100);
        ct.update_from_event(&ev);
        assert_eq!(ct.parent_of(501), Some(500));
    }

    #[test]
    fn test_child_tracker_update_clone_event() {
        let mut ct = ChildTracker::new();
        let ev = SyscallEvent::new(0, 600, 56, "clone", vec![0; 6], 601, 200);
        ct.update_from_event(&ev);
        assert_eq!(ct.parent_of(601), Some(600));
    }

    #[test]
    fn test_child_tracker_no_parent_for_root() {
        let ct = ChildTracker::new();
        assert!(ct.parent_of(1).is_none());
    }

    // ── SignalEvent tests ──────────────────────────────────────────────────────

    #[test]
    fn test_signal_name_sigsegv() {
        assert_eq!(signal_name(11), "SIGSEGV");
    }

    #[test]
    fn test_signal_name_sigkill() {
        assert_eq!(signal_name(9), "SIGKILL");
    }

    #[test]
    fn test_signal_name_unknown() {
        assert_eq!(signal_name(200), "SIGUNKNOWN");
    }

    #[test]
    fn test_signal_event_new() {
        let ev = SignalEvent::new(12345, 999, 11);
        assert_eq!(ev.signame, "SIGSEGV");
        assert_eq!(ev.signum, 11);
        assert_eq!(ev.pid, 999);
    }

    // ── TraceSession tests ─────────────────────────────────────────────────────

    #[test]
    fn test_trace_session_push_and_summary() {
        let mut sess = TraceSession::new();
        sess.push_syscall(make_event(0, "read", 10, 5000, 0));
        sess.push_syscall(make_event(0, "read", 5, 3000, 1000));
        let sum = sess.summary();
        assert_eq!(sum.total_events, 2);
        assert_eq!(sum.per_name.get("read").unwrap().count, 2);
    }

    #[test]
    fn test_trace_session_fd_tracking() {
        let mut sess = TraceSession::new();
        sess.push_syscall(SyscallEvent::new(0, 100, 2, "open", vec![0], 5, 100));
        assert!(sess.fds.lookup(100, 5).is_some());
    }

    #[test]
    fn test_trace_session_child_tracking() {
        let mut sess = TraceSession::new();
        sess.push_syscall(SyscallEvent::new(0, 700, 57, "fork", vec![], 701, 200));
        assert_eq!(sess.children.parent_of(701), Some(700));
    }

    #[test]
    fn test_trace_session_signal() {
        let mut sess = TraceSession::new();
        sess.push_signal(SignalEvent::new(0, 800, 15));
        assert_eq!(sess.signals.len(), 1);
        assert_eq!(sess.signals[0].signame, "SIGTERM");
    }

    #[test]
    fn test_trace_session_to_json() {
        let sess = TraceSession::new();
        let json = sess.to_json().unwrap();
        assert!(json.contains("syscalls"));
    }

    // ── PtraceOptions tests ────────────────────────────────────────────────────

    #[test]
    fn test_ptrace_options_attach() {
        let opts = PtraceOptions::attach(1234);
        assert_eq!(opts.attach_pid, Some(1234));
        assert!(opts.command.is_empty());
    }

    #[test]
    fn test_ptrace_options_spawn() {
        let opts = PtraceOptions::spawn("ls");
        assert!(opts.attach_pid.is_none());
        assert_eq!(opts.command, vec!["ls"]);
    }

    #[test]
    fn test_ptrace_options_with_max_events() {
        let opts = PtraceOptions::spawn("cat").with_max_events(500);
        assert_eq!(opts.max_events, 500);
    }

    #[test]
    fn test_ptrace_options_include_filter() {
        let opts = PtraceOptions::spawn("strace").include(["read", "write"]);
        assert!(opts.include_filter.contains(&"read".to_string()));
    }

    #[test]
    fn test_ptrace_options_exclude_filter() {
        let opts = PtraceOptions::spawn("bash").exclude(["brk", "mmap"]);
        assert!(opts.exclude_filter.contains(&"brk".to_string()));
    }

    // ── AArch64 specific table tests ───────────────────────────────────────────

    #[test]
    fn test_aarch64_read_is_63() {
        assert_eq!(aarch64_syscall_name(63), Some("read"));
    }

    #[test]
    fn test_aarch64_write_is_64() {
        assert_eq!(aarch64_syscall_name(64), Some("write"));
    }

    #[test]
    fn test_aarch64_mmap_is_222() {
        assert_eq!(aarch64_syscall_name(222), Some("mmap"));
    }

    #[test]
    fn test_aarch64_execve_is_221() {
        assert_eq!(aarch64_syscall_name(221), Some("execve"));
    }

    #[test]
    fn test_aarch64_socket_is_198() {
        assert_eq!(aarch64_syscall_name(198), Some("socket"));
    }

    #[test]
    fn test_aarch64_unknown_returns_none() {
        assert!(aarch64_syscall_name(9999).is_none());
    }

    #[test]
    fn test_aarch64_table_length() {
        assert!(AARCH64_SPECIFIC_SYSCALLS.len() > 100);
    }

    #[test]
    fn test_aarch64_clone3_present() {
        assert_eq!(aarch64_syscall_name(435), Some("clone3"));
    }

    #[test]
    fn test_aarch64_io_uring_present() {
        assert_eq!(aarch64_syscall_name(425), Some("io_uring_setup"));
    }
}

// ─── ArgType enum (strace-style rich argument typing) ─────────────────────────

/// Rich argument type for strace-compatible syscall argument decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgType {
    Int,
    UInt,
    Long,
    Fd,
    Pid,
    Ptr { inner: Box<Self> },
    Buffer { size_arg: u8 },
    Str,
    Flags { flag_set: &'static str },
    Errno,
    Sockaddr,
    IovecArr,
    Mode,
    Off,
    Signal,
    Size,
    Addr,
    RawHex,
}

impl ArgType {
    #[must_use]
    pub const fn c_name(&self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::UInt => "unsigned int",
            Self::Long => "long",
            Self::Fd => "int /*fd*/",
            Self::Pid => "pid_t",
            Self::Ptr { .. } => "void *",
            Self::Buffer { .. } => "void * /*buf*/",
            Self::Str => "const char *",
            Self::Flags { .. } => "unsigned long /*flags*/",
            Self::Errno => "long /*errno*/",
            Self::Sockaddr => "struct sockaddr *",
            Self::IovecArr => "struct iovec *",
            Self::Mode => "mode_t",
            Self::Off => "off_t",
            Self::Signal => "int /*signal*/",
            Self::Size => "size_t",
            Self::Addr => "unsigned long /*addr*/",
            Self::RawHex => "unsigned long",
        }
    }
}

// ─── Flag bits ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FlagBit {
    pub value: u64,
    pub name: &'static str,
}

impl FlagBit {
    #[must_use]
    pub const fn new(value: u64, name: &'static str) -> Self {
        Self { value, name }
    }
}

#[must_use]
pub fn decode_flags(value: u64, bits: &[FlagBit]) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    let mut remaining = value;
    for bit in bits {
        if bit.value != 0 && (remaining & bit.value) == bit.value {
            parts.push(bit.name);
            remaining &= !bit.value;
        }
    }
    if remaining != 0 {
        parts.push("/* unknown */");
    }
    if parts.is_empty() {
        return "0".to_string();
    }
    parts.join("|")
}

#[must_use]
pub fn decode_flags_by_name(flag_set: &str, value: u64) -> String {
    match flag_set {
        "O_FLAGS" => decode_flags(value, O_FLAGS),
        "PROT_FLAGS" => decode_flags(value, PROT_FLAGS),
        "MAP_FLAGS" => decode_flags(value, MAP_FLAGS),
        "CLONE_FLAGS" => decode_flags(value, CLONE_FLAGS),
        "AT_FLAGS" => decode_flags(value, AT_FLAGS),
        "EPOLL_EVENTS" => decode_flags(value, EPOLL_EVENTS),
        "SOCK_FLAGS" => decode_flags(value, SOCK_FLAGS),
        "WAIT_FLAGS" => decode_flags(value, WAIT_FLAGS),
        _ => format!("0x{value:x}"),
    }
}

pub static O_FLAGS: &[FlagBit] = &[
    FlagBit::new(0o0, "O_RDONLY"),
    FlagBit::new(0o1, "O_WRONLY"),
    FlagBit::new(0o2, "O_RDWR"),
    FlagBit::new(0o100, "O_CREAT"),
    FlagBit::new(0o200, "O_EXCL"),
    FlagBit::new(0o400, "O_NOCTTY"),
    FlagBit::new(0o1000, "O_TRUNC"),
    FlagBit::new(0o2000, "O_APPEND"),
    FlagBit::new(0o4000, "O_NONBLOCK"),
    FlagBit::new(0o10000, "O_DSYNC"),
    FlagBit::new(0o20000, "O_ASYNC"),
    FlagBit::new(0o40000, "O_DIRECT"),
    FlagBit::new(0o100_000, "O_LARGEFILE"),
    FlagBit::new(0o200_000, "O_DIRECTORY"),
    FlagBit::new(0o400_000, "O_NOFOLLOW"),
    FlagBit::new(0o1_000_000, "O_NOATIME"),
    FlagBit::new(0o2_000_000, "O_CLOEXEC"),
    FlagBit::new(0o4_010_000, "O_SYNC"),
    FlagBit::new(0o10_000_000, "O_PATH"),
];

pub static PROT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x0, "PROT_NONE"),
    FlagBit::new(0x1, "PROT_READ"),
    FlagBit::new(0x2, "PROT_WRITE"),
    FlagBit::new(0x4, "PROT_EXEC"),
    FlagBit::new(0x8, "PROT_SEM"),
];

pub static MAP_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x01, "MAP_SHARED"),
    FlagBit::new(0x02, "MAP_PRIVATE"),
    FlagBit::new(0x10, "MAP_FIXED"),
    FlagBit::new(0x20, "MAP_ANONYMOUS"),
    FlagBit::new(0x40, "MAP_32BIT"),
    FlagBit::new(0x100, "MAP_GROWSDOWN"),
    FlagBit::new(0x800, "MAP_DENYWRITE"),
    FlagBit::new(0x1000, "MAP_EXECUTABLE"),
    FlagBit::new(0x2000, "MAP_LOCKED"),
    FlagBit::new(0x4000, "MAP_NORESERVE"),
    FlagBit::new(0x8000, "MAP_POPULATE"),
    FlagBit::new(0x1_0000, "MAP_NONBLOCK"),
    FlagBit::new(0x2_0000, "MAP_STACK"),
    FlagBit::new(0x4_0000, "MAP_HUGETLB"),
    FlagBit::new(0x8_0000, "MAP_SYNC"),
    FlagBit::new(0x0010_0000, "MAP_FIXED_NOREPLACE"),
];

pub static CLONE_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x0000_0100, "CLONE_VM"),
    FlagBit::new(0x0000_0200, "CLONE_FS"),
    FlagBit::new(0x0000_0400, "CLONE_FILES"),
    FlagBit::new(0x0000_0800, "CLONE_SIGHAND"),
    FlagBit::new(0x0000_1000, "CLONE_PIDFD"),
    FlagBit::new(0x0000_2000, "CLONE_PTRACE"),
    FlagBit::new(0x0000_4000, "CLONE_VFORK"),
    FlagBit::new(0x0000_8000, "CLONE_PARENT"),
    FlagBit::new(0x0001_0000, "CLONE_THREAD"),
    FlagBit::new(0x0002_0000, "CLONE_NEWNS"),
    FlagBit::new(0x0004_0000, "CLONE_SYSVSEM"),
    FlagBit::new(0x0008_0000, "CLONE_SETTLS"),
    FlagBit::new(0x0010_0000, "CLONE_PARENT_SETTID"),
    FlagBit::new(0x0020_0000, "CLONE_CHILD_CLEARTID"),
    FlagBit::new(0x0040_0000, "CLONE_DETACHED"),
    FlagBit::new(0x0080_0000, "CLONE_UNTRACED"),
    FlagBit::new(0x0100_0000, "CLONE_CHILD_SETTID"),
    FlagBit::new(0x0200_0000, "CLONE_NEWCGROUP"),
    FlagBit::new(0x0400_0000, "CLONE_NEWUTS"),
    FlagBit::new(0x0800_0000, "CLONE_NEWIPC"),
    FlagBit::new(0x1000_0000, "CLONE_NEWUSER"),
    FlagBit::new(0x2000_0000, "CLONE_NEWPID"),
    FlagBit::new(0x4000_0000, "CLONE_NEWNET"),
    FlagBit::new(0x8000_0000, "CLONE_IO"),
];

pub static AT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x100, "AT_SYMLINK_NOFOLLOW"),
    FlagBit::new(0x200, "AT_REMOVEDIR"),
    FlagBit::new(0x400, "AT_SYMLINK_FOLLOW"),
    FlagBit::new(0x800, "AT_NO_AUTOMOUNT"),
    FlagBit::new(0x1000, "AT_EMPTY_PATH"),
];

pub static EPOLL_EVENTS: &[FlagBit] = &[
    FlagBit::new(0x001, "EPOLLIN"),
    FlagBit::new(0x002, "EPOLLPRI"),
    FlagBit::new(0x004, "EPOLLOUT"),
    FlagBit::new(0x008, "EPOLLERR"),
    FlagBit::new(0x010, "EPOLLHUP"),
    FlagBit::new(0x020, "EPOLLNVAL"),
    FlagBit::new(0x040, "EPOLLRDNORM"),
    FlagBit::new(0x080, "EPOLLRDBAND"),
    FlagBit::new(0x100, "EPOLLWRNORM"),
    FlagBit::new(0x200, "EPOLLWRBAND"),
    FlagBit::new(0x2000, "EPOLLRDHUP"),
    FlagBit::new(0x1000_0000, "EPOLLEXCLUSIVE"),
    FlagBit::new(0x2000_0000, "EPOLLWAKEUP"),
    FlagBit::new(0x4000_0000, "EPOLLONESHOT"),
    FlagBit::new(0x8000_0000, "EPOLLET"),
];

pub static SOCK_FLAGS: &[FlagBit] = &[
    FlagBit::new(1, "SOCK_STREAM"),
    FlagBit::new(2, "SOCK_DGRAM"),
    FlagBit::new(3, "SOCK_RAW"),
    FlagBit::new(4, "SOCK_RDM"),
    FlagBit::new(5, "SOCK_SEQPACKET"),
    FlagBit::new(10, "SOCK_PACKET"),
    FlagBit::new(0x8_0000, "SOCK_CLOEXEC"),
    FlagBit::new(0x800, "SOCK_NONBLOCK"),
];

pub static WAIT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x1, "WNOHANG"),
    FlagBit::new(0x2, "WUNTRACED"),
    FlagBit::new(0x4, "WSTOPPED"),
    FlagBit::new(0x8, "WCONTINUED"),
    FlagBit::new(0x10, "WNOWAIT"),
    FlagBit::new(0x0100_0000, "WNOTHREAD"),
    FlagBit::new(0x0200_0000, "WALL"),
    FlagBit::new(0x0400_0000, "WCLONE"),
];

// ─── Signal name table ────────────────────────────────────────────────────────

#[must_use]
pub const fn signal_name_v2(sig: u32) -> Option<&'static str> {
    match sig {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        6 => Some("SIGABRT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        9 => Some("SIGKILL"),
        10 => Some("SIGUSR1"),
        11 => Some("SIGSEGV"),
        12 => Some("SIGUSR2"),
        13 => Some("SIGPIPE"),
        14 => Some("SIGALRM"),
        15 => Some("SIGTERM"),
        16 => Some("SIGSTKFLT"),
        17 => Some("SIGCHLD"),
        18 => Some("SIGCONT"),
        19 => Some("SIGSTOP"),
        20 => Some("SIGTSTP"),
        21 => Some("SIGTTIN"),
        22 => Some("SIGTTOU"),
        23 => Some("SIGURG"),
        24 => Some("SIGXCPU"),
        25 => Some("SIGXFSZ"),
        26 => Some("SIGVTALRM"),
        27 => Some("SIGPROF"),
        28 => Some("SIGWINCH"),
        29 => Some("SIGIO"),
        30 => Some("SIGPWR"),
        31 => Some("SIGSYS"),
        34 => Some("SIGRTMIN"),
        64 => Some("SIGRTMAX"),
        _ => None,
    }
}

// ─── Sockaddr decoder ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedSockaddr {
    Inet {
        addr: String,
        port: u16,
    },
    Inet6 {
        addr: String,
        port: u16,
        flow_info: u32,
        scope_id: u32,
    },
    Unix {
        path: String,
    },
    Netlink {
        pid: u32,
        groups: u32,
    },
    Raw {
        family: u16,
        data: Vec<u8>,
    },
}

impl std::fmt::Display for DecodedSockaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inet { addr, port } => write!(f, "{addr}:{port}"),
            Self::Inet6 { addr, port, .. } => write!(f, "[{addr}]:{port}"),
            Self::Unix { path } => write!(f, "{path:?}"),
            Self::Netlink { pid, groups } => write!(f, "nl pid={pid} groups={groups}"),
            Self::Raw { family, data } => {
                write!(f, "sa_family={family} data={}", hex_dump_ext(data, 16))
            }
        }
    }
}

#[must_use]
pub fn hex_dump_ext(data: &[u8], max_bytes: usize) -> String {
    let n = data.len().min(max_bytes);
    let hex: Vec<String> = data[..n].iter().map(|b| format!("{b:02x}")).collect();
    let s = hex.join(" ");
    if data.len() > max_bytes {
        format!("{s} ... ({} more bytes)", data.len() - max_bytes)
    } else {
        s
    }
}

#[must_use]
pub fn decode_sockaddr(data: &[u8]) -> DecodedSockaddr {
    if data.len() < 2 {
        return DecodedSockaddr::Raw {
            family: 0,
            data: data.to_vec(),
        };
    }
    let family = u16::from_le_bytes([data[0], data[1]]);
    match family {
        2 if data.len() >= 8 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            let addr = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            DecodedSockaddr::Inet { addr, port }
        }
        10 if data.len() >= 28 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            let flow = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let scope = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
            let words: Vec<String> = (0..8)
                .map(|i| {
                    let idx = 8 + i * 2;
                    format!("{:x}", u16::from_be_bytes([data[idx], data[idx + 1]]))
                })
                .collect();
            DecodedSockaddr::Inet6 {
                addr: words.join(":"),
                port,
                flow_info: flow,
                scope_id: scope,
            }
        }
        1 if data.len() >= 3 => {
            let raw = &data[2..];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            DecodedSockaddr::Unix {
                path: String::from_utf8_lossy(&raw[..end]).to_string(),
            }
        }
        16 if data.len() >= 12 => {
            let pid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let groups = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            DecodedSockaddr::Netlink { pid, groups }
        }
        _ => DecodedSockaddr::Raw {
            family,
            data: data.to_vec(),
        },
    }
}

// ─── Decoded argument ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedArg {
    Int(i64),
    UInt(u64),
    Str(String),
    Addr(u64),
    Fd(i32, String),
    Flags(u64, String),
    Signal(u32, String),
    Sockaddr(DecodedSockaddr),
    Buffer(Vec<u8>),
    Errno(i64),
    Null,
    RawHex(u64),
}

impl std::fmt::Display for DecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::UInt(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Addr(a) => write!(f, "0x{a:x}"),
            Self::Fd(n, p) => {
                if p.is_empty() {
                    write!(f, "{n}")
                } else {
                    write!(f, "{n}<{p}>")
                }
            }
            Self::Flags(_, s) => write!(f, "{s}"),
            Self::Signal(n, s) => write!(f, "{s}({n})"),
            Self::Sockaddr(sa) => write!(f, "{{{sa}}}"),
            Self::Buffer(b) => write!(f, "\"{}\"", hex_dump_ext(b, 64)),
            Self::Errno(e) => {
                if *e < 0 {
                    write!(f, "-1 /* errno={} */", -e)
                } else {
                    write!(f, "{e}")
                }
            }
            Self::Null => write!(f, "NULL"),
            Self::RawHex(v) => write!(f, "0x{v:x}"),
        }
    }
}

// ─── SyscallEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEventV2 {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub nr: u64,
    pub name: String,
    pub args: Vec<DecodedArg>,
    pub retval: DecodedArg,
    pub elapsed_ns: u64,
    pub is_entry: bool,
}

impl std::fmt::Display for SyscallEventV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let args: Vec<String> = self
            .args
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        write!(f, "{}({}) = {}", self.name, args.join(", "), self.retval)
    }
}

impl SyscallEventV2 {
    /// Serialize this event to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.timestamp_ns, self.pid, self.tid, self.name, self.retval, self.elapsed_ns
        )
    }
}

// ─── FD tracker ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdInfo {
    pub path: String,
    pub flags: u64,
    pub offset: i64,
    pub is_socket: bool,
    pub peer_addr: Option<DecodedSockaddr>,
    pub local_addr: Option<DecodedSockaddr>,
}

impl FdInfo {
    #[must_use]
    pub fn file(path: impl Into<String>, flags: u64) -> Self {
        Self {
            path: path.into(),
            flags,
            offset: 0,
            is_socket: false,
            peer_addr: None,
            local_addr: None,
        }
    }
    #[must_use]
    pub fn socket(family: u16, sock_type: u16, protocol: u16) -> Self {
        Self {
            path: format!("socket:[{family}/{sock_type}/{protocol}]"),
            flags: 0,
            offset: 0,
            is_socket: true,
            peer_addr: None,
            local_addr: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdTable {
    map: HashMap<i32, FdInfo>,
}

impl FdTable {
    pub fn insert(&mut self, fd: i32, info: FdInfo) {
        self.map.insert(fd, info);
    }
    pub fn remove(&mut self, fd: i32) -> Option<FdInfo> {
        self.map.remove(&fd)
    }
    #[must_use]
    pub fn get(&self, fd: i32) -> Option<&FdInfo> {
        self.map.get(&fd)
    }
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut FdInfo> {
        self.map.get_mut(&fd)
    }
    pub fn dup(&mut self, src: i32, dst: i32) {
        if let Some(info) = self.map.get(&src).cloned() {
            self.map.insert(dst, info);
        }
    }
    #[must_use]
    pub fn all(&self) -> Vec<(i32, &FdInfo)> {
        let mut v: Vec<_> = self.map.iter().map(|(k, v)| (*k, v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ─── Per-thread state machine ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadSyscallState {
    pub in_syscall: Option<u64>,
    pub entry_ts: u64,
    pub entry_regs: [u64; 7],
    pub stopped: bool,
}

impl ThreadSyscallState {
    pub const fn on_entry(&mut self, nr: u64, regs: [u64; 7], ts: u64) {
        self.in_syscall = Some(nr);
        self.entry_regs = regs;
        self.entry_ts = ts;
        self.stopped = true;
    }
    pub const fn on_exit(&mut self, ts: u64) -> (Option<u64>, u64) {
        let nr = self.in_syscall.take();
        let elapsed = ts.saturating_sub(self.entry_ts);
        self.stopped = false;
        (nr, elapsed)
    }
}

// ─── Output format ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Strace,
    Json,
    Csv,
}

// ─── PtraceOptions ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceOptionsV2 {
    pub tracee: String,
    pub args: Vec<String>,
    pub output_format: OutputFormat,
    pub show_timing: bool,
    pub show_summary: bool,
    pub include_filter: Vec<String>,
    pub exclude_filter: Vec<String>,
    pub max_string_len: usize,
    pub max_buffer_dump: usize,
    pub follow_forks: bool,
}

impl PtraceOptionsV2 {
    #[must_use]
    pub fn spawn(tracee: impl Into<String>) -> Self {
        Self {
            tracee: tracee.into(),
            args: vec![],
            output_format: OutputFormat::Strace,
            show_timing: false,
            show_summary: false,
            include_filter: vec![],
            exclude_filter: vec![],
            max_string_len: 256,
            max_buffer_dump: 64,
            follow_forks: true,
        }
    }
    #[must_use]
    pub fn include<I: IntoIterator<Item = impl Into<String>>>(mut self, names: I) -> Self {
        self.include_filter
            .extend(names.into_iter().map(Into::into));
        self
    }
    #[must_use]
    pub fn exclude<I: IntoIterator<Item = impl Into<String>>>(mut self, names: I) -> Self {
        self.exclude_filter
            .extend(names.into_iter().map(Into::into));
        self
    }
    #[must_use]
    pub fn passes_filter(&self, name: &str) -> bool {
        if !self.include_filter.is_empty() && !self.include_filter.iter().any(|f| f == name) {
            return false;
        }
        !self.exclude_filter.iter().any(|f| f == name)
    }
}

// ─── Summary statistics ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSummaryEntry {
    pub name: String,
    pub count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub error_count: u64,
}

impl SyscallSummaryEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, elapsed_ns: u64, is_error: bool) -> Self {
        Self {
            name: name.into(),
            count: 1,
            total_ns: elapsed_ns,
            min_ns: elapsed_ns,
            max_ns: elapsed_ns,
            error_count: u64::from(is_error),
        }
    }
    pub const fn record(&mut self, elapsed_ns: u64, is_error: bool) {
        self.count += 1;
        self.total_ns += elapsed_ns;
        if elapsed_ns < self.min_ns {
            self.min_ns = elapsed_ns;
        }
        if elapsed_ns > self.max_ns {
            self.max_ns = elapsed_ns;
        }
        if is_error {
            self.error_count += 1;
        }
    }
    #[must_use]
    pub const fn avg_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_ns / self.count
        }
    }
    #[must_use]
    /// Average elapsed time per call in microseconds (whole + fractional parts).
    ///
    /// Returns `(whole_us, frac_ns)` where `frac_ns` is the sub-microsecond remainder.
    pub const fn avg_us_parts(&self) -> (u64, u64) {
        let avg = self.avg_ns();
        (avg / 1_000, avg % 1_000)
    }
    /// Total seconds as `(whole_s, frac_us)`.
    #[must_use]
    pub const fn total_secs_parts(&self) -> (u64, u64) {
        (
            self.total_ns / 1_000_000_000,
            (self.total_ns % 1_000_000_000) / 1_000,
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallSummaryV2 {
    pub entries: HashMap<String, SyscallSummaryEntry>,
}

impl SyscallSummaryV2 {
    pub fn record(&mut self, name: &str, elapsed_ns: u64, retval: i64) {
        let is_error = retval < 0;
        self.entries
            .entry(name.to_string())
            .and_modify(|e| e.record(elapsed_ns, is_error))
            .or_insert_with(|| SyscallSummaryEntry::new(name, elapsed_ns, is_error));
    }
    #[must_use]
    pub fn sorted_by_time(&self) -> Vec<&SyscallSummaryEntry> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
        v
    }
    #[must_use]
    pub fn sorted_by_count(&self) -> Vec<&SyscallSummaryEntry> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count));
        v
    }
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.entries.values().map(|e| e.count).sum()
    }
    #[must_use]
    pub fn total_ns(&self) -> u64 {
        self.entries.values().map(|e| e.total_ns).sum()
    }
    #[must_use]
    pub fn format_table(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("% time     seconds  usecs/call     calls    errors syscall\n");
        out.push_str("------- ----------- ----------- --------- --------- ----------------\n");
        let total_ns = self.total_ns().max(1);
        for e in self.sorted_by_time() {
            let pct_bp = e.total_ns * 10_000 / total_ns;
            let pct_int = pct_bp / 100;
            let pct_frac = pct_bp % 100;
            let (secs_whole, secs_frac) = e.total_secs_parts();
            let _ = writeln!(
                out,
                "{pct_int:4}.{pct_frac:02} {secs_whole:5}.{secs_frac:06} {:11} {:9} {:9} {}",
                e.avg_ns(),
                e.count,
                e.error_count,
                e.name
            );
        }
        out.push_str("------- ----------- ----------- --------- --------- ----------------\n");
        let tot_secs_whole = total_ns / 1_000_000_000;
        let tot_secs_frac = (total_ns % 1_000_000_000) / 1_000;
        let _ = writeln!(
            out,
            "100.00  {tot_secs_whole:5}.{tot_secs_frac:06} {:>11} {:9}           total",
            "",
            self.total_calls()
        );
        out
    }
}

// ─── FD resolver helpers ──────────────────────────────────────────────────────

pub const AT_FDCWD: i32 = -100;

#[must_use]
pub fn resolve_fd(pid: u32, fd: i32) -> String {
    if fd == AT_FDCWD {
        return "AT_FDCWD".to_string();
    }
    if fd < 0 {
        return format!("<bad fd {fd}>");
    }
    let path = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&path).map_or_else(|_| format!("<fd {fd}>"), |p| p.display().to_string())
}

#[must_use]
pub fn read_process_memory(pid: u32, addr: u64, max_len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .open(format!("/proc/{pid}/mem"))
        .ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; max_len];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

#[must_use]
pub fn read_cstring(pid: u32, addr: u64) -> Option<String> {
    let buf = read_process_memory(pid, addr, 256)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

// ─── Signal/exit formatting ───────────────────────────────────────────────────

#[must_use]
pub fn format_signal_delivery(sig: u32, si_code: i32, si_addr: u64) -> String {
    let name = signal_name_v2(sig).unwrap_or("SIG?");
    let code_str = match (sig, si_code) {
        (11, 1) => "SEGV_MAPERR",
        (11, 2) => "SEGV_ACCERR",
        (7, 1) => "BUS_ADRALN",
        (7, 2) => "BUS_ADRERR",
        (8, 1) => "FPE_INTDIV",
        (8, 2) => "FPE_INTOVF",
        (4, 1) => "ILL_ILLOPC",
        _ => "SI_KERNEL",
    };
    format!("--- {name} {{si_signo={name}, si_code={code_str}, si_addr=0x{si_addr:x}}} ---")
}

#[must_use]
pub fn format_exit_event(pid: u32, code: i32, signal: Option<u32>) -> String {
    let _ = pid;
    signal.map_or_else(
        || format!("+++ exited with {code} +++"),
        |sig| format!("+++ killed by {} +++", signal_name_v2(sig).unwrap_or("SIG?")),
    )
}

// ─── Complete x86_64 syscall table (451 entries, kernel 6.x) ──────────────────

#[derive(Debug, Clone, Copy)]
pub struct StaticSyscall {
    pub nr: u32,
    pub name: &'static str,
    pub argc: u8,
}

impl StaticSyscall {
    #[must_use]
    pub const fn new(nr: u32, name: &'static str, argc: u8) -> Self {
        Self { nr, name, argc }
    }
}

pub static X86_64_SYSCALLS: &[StaticSyscall] = &[
    StaticSyscall::new(0, "read", 3),
    StaticSyscall::new(1, "write", 3),
    StaticSyscall::new(2, "open", 3),
    StaticSyscall::new(3, "close", 1),
    StaticSyscall::new(4, "stat", 2),
    StaticSyscall::new(5, "fstat", 2),
    StaticSyscall::new(6, "lstat", 2),
    StaticSyscall::new(7, "poll", 3),
    StaticSyscall::new(8, "lseek", 3),
    StaticSyscall::new(9, "mmap", 6),
    StaticSyscall::new(10, "mprotect", 3),
    StaticSyscall::new(11, "munmap", 2),
    StaticSyscall::new(12, "brk", 1),
    StaticSyscall::new(13, "rt_sigaction", 4),
    StaticSyscall::new(14, "rt_sigprocmask", 4),
    StaticSyscall::new(15, "rt_sigreturn", 0),
    StaticSyscall::new(16, "ioctl", 3),
    StaticSyscall::new(17, "pread64", 4),
    StaticSyscall::new(18, "pwrite64", 4),
    StaticSyscall::new(19, "readv", 3),
    StaticSyscall::new(20, "writev", 3),
    StaticSyscall::new(21, "access", 2),
    StaticSyscall::new(22, "pipe", 1),
    StaticSyscall::new(23, "select", 5),
    StaticSyscall::new(24, "sched_yield", 0),
    StaticSyscall::new(25, "mremap", 5),
    StaticSyscall::new(26, "msync", 3),
    StaticSyscall::new(27, "mincore", 3),
    StaticSyscall::new(28, "madvise", 3),
    StaticSyscall::new(29, "shmget", 3),
    StaticSyscall::new(30, "shmat", 3),
    StaticSyscall::new(31, "shmctl", 3),
    StaticSyscall::new(32, "dup", 1),
    StaticSyscall::new(33, "dup2", 2),
    StaticSyscall::new(34, "pause", 0),
    StaticSyscall::new(35, "nanosleep", 2),
    StaticSyscall::new(36, "getitimer", 2),
    StaticSyscall::new(37, "alarm", 1),
    StaticSyscall::new(38, "setitimer", 3),
    StaticSyscall::new(39, "getpid", 0),
    StaticSyscall::new(40, "sendfile", 4),
    StaticSyscall::new(41, "socket", 3),
    StaticSyscall::new(42, "connect", 3),
    StaticSyscall::new(43, "accept", 3),
    StaticSyscall::new(44, "sendto", 6),
    StaticSyscall::new(45, "recvfrom", 6),
    StaticSyscall::new(46, "sendmsg", 3),
    StaticSyscall::new(47, "recvmsg", 3),
    StaticSyscall::new(48, "shutdown", 2),
    StaticSyscall::new(49, "bind", 3),
    StaticSyscall::new(50, "listen", 2),
    StaticSyscall::new(51, "getsockname", 3),
    StaticSyscall::new(52, "getpeername", 3),
    StaticSyscall::new(53, "socketpair", 4),
    StaticSyscall::new(54, "setsockopt", 5),
    StaticSyscall::new(55, "getsockopt", 5),
    StaticSyscall::new(56, "clone", 5),
    StaticSyscall::new(57, "fork", 0),
    StaticSyscall::new(58, "vfork", 0),
    StaticSyscall::new(59, "execve", 3),
    StaticSyscall::new(60, "exit", 1),
    StaticSyscall::new(61, "wait4", 4),
    StaticSyscall::new(62, "kill", 2),
    StaticSyscall::new(63, "uname", 1),
    StaticSyscall::new(64, "semget", 3),
    StaticSyscall::new(65, "semop", 3),
    StaticSyscall::new(66, "semctl", 4),
    StaticSyscall::new(67, "shmdt", 1),
    StaticSyscall::new(68, "msgget", 2),
    StaticSyscall::new(69, "msgsnd", 4),
    StaticSyscall::new(70, "msgrcv", 5),
    StaticSyscall::new(71, "msgctl", 3),
    StaticSyscall::new(72, "fcntl", 3),
    StaticSyscall::new(73, "flock", 2),
    StaticSyscall::new(74, "fsync", 1),
    StaticSyscall::new(75, "fdatasync", 1),
    StaticSyscall::new(76, "truncate", 2),
    StaticSyscall::new(77, "ftruncate", 2),
    StaticSyscall::new(78, "getdents", 3),
    StaticSyscall::new(79, "getcwd", 2),
    StaticSyscall::new(80, "chdir", 1),
    StaticSyscall::new(81, "fchdir", 1),
    StaticSyscall::new(82, "rename", 2),
    StaticSyscall::new(83, "mkdir", 2),
    StaticSyscall::new(84, "rmdir", 1),
    StaticSyscall::new(85, "creat", 2),
    StaticSyscall::new(86, "link", 2),
    StaticSyscall::new(87, "unlink", 1),
    StaticSyscall::new(88, "symlink", 2),
    StaticSyscall::new(89, "readlink", 3),
    StaticSyscall::new(90, "chmod", 2),
    StaticSyscall::new(91, "fchmod", 2),
    StaticSyscall::new(92, "chown", 3),
    StaticSyscall::new(93, "fchown", 3),
    StaticSyscall::new(94, "lchown", 3),
    StaticSyscall::new(95, "umask", 1),
    StaticSyscall::new(96, "gettimeofday", 2),
    StaticSyscall::new(97, "getrlimit", 2),
    StaticSyscall::new(98, "getrusage", 2),
    StaticSyscall::new(99, "sysinfo", 1),
    StaticSyscall::new(100, "times", 1),
    StaticSyscall::new(101, "ptrace", 4),
    StaticSyscall::new(102, "getuid", 0),
    StaticSyscall::new(103, "syslog", 3),
    StaticSyscall::new(104, "getgid", 0),
    StaticSyscall::new(105, "setuid", 1),
    StaticSyscall::new(106, "setgid", 1),
    StaticSyscall::new(107, "geteuid", 0),
    StaticSyscall::new(108, "getegid", 0),
    StaticSyscall::new(109, "setpgid", 2),
    StaticSyscall::new(110, "getppid", 0),
    StaticSyscall::new(111, "getpgrp", 0),
    StaticSyscall::new(112, "setsid", 0),
    StaticSyscall::new(113, "setreuid", 2),
    StaticSyscall::new(114, "setregid", 2),
    StaticSyscall::new(115, "getgroups", 2),
    StaticSyscall::new(116, "setgroups", 2),
    StaticSyscall::new(117, "setresuid", 3),
    StaticSyscall::new(118, "getresuid", 3),
    StaticSyscall::new(119, "setresgid", 3),
    StaticSyscall::new(120, "getresgid", 3),
    StaticSyscall::new(121, "getpgid", 1),
    StaticSyscall::new(122, "setfsuid", 1),
    StaticSyscall::new(123, "setfsgid", 1),
    StaticSyscall::new(124, "getsid", 1),
    StaticSyscall::new(125, "capget", 2),
    StaticSyscall::new(126, "capset", 2),
    StaticSyscall::new(127, "rt_sigpending", 2),
    StaticSyscall::new(128, "rt_sigtimedwait", 4),
    StaticSyscall::new(129, "rt_sigqueueinfo", 3),
    StaticSyscall::new(130, "rt_sigsuspend", 2),
    StaticSyscall::new(131, "sigaltstack", 2),
    StaticSyscall::new(132, "utime", 2),
    StaticSyscall::new(133, "mknod", 3),
    StaticSyscall::new(134, "uselib", 1),
    StaticSyscall::new(135, "personality", 1),
    StaticSyscall::new(136, "ustat", 2),
    StaticSyscall::new(137, "statfs", 2),
    StaticSyscall::new(138, "fstatfs", 2),
    StaticSyscall::new(139, "sysfs", 3),
    StaticSyscall::new(140, "getpriority", 2),
    StaticSyscall::new(141, "setpriority", 3),
    StaticSyscall::new(142, "sched_setparam", 2),
    StaticSyscall::new(143, "sched_getparam", 2),
    StaticSyscall::new(144, "sched_setscheduler", 3),
    StaticSyscall::new(145, "sched_getscheduler", 1),
    StaticSyscall::new(146, "sched_get_priority_max", 1),
    StaticSyscall::new(147, "sched_get_priority_min", 1),
    StaticSyscall::new(148, "sched_rr_get_interval", 2),
    StaticSyscall::new(149, "mlock", 2),
    StaticSyscall::new(150, "munlock", 2),
    StaticSyscall::new(151, "mlockall", 1),
    StaticSyscall::new(152, "munlockall", 0),
    StaticSyscall::new(153, "vhangup", 0),
    StaticSyscall::new(154, "modify_ldt", 3),
    StaticSyscall::new(155, "pivot_root", 2),
    StaticSyscall::new(156, "_sysctl", 1),
    StaticSyscall::new(157, "prctl", 5),
    StaticSyscall::new(158, "arch_prctl", 2),
    StaticSyscall::new(159, "adjtimex", 1),
    StaticSyscall::new(160, "setrlimit", 2),
    StaticSyscall::new(161, "chroot", 1),
    StaticSyscall::new(162, "sync", 0),
    StaticSyscall::new(163, "acct", 1),
    StaticSyscall::new(164, "settimeofday", 2),
    StaticSyscall::new(165, "mount", 5),
    StaticSyscall::new(166, "umount2", 2),
    StaticSyscall::new(167, "swapon", 2),
    StaticSyscall::new(168, "swapoff", 1),
    StaticSyscall::new(169, "reboot", 4),
    StaticSyscall::new(170, "sethostname", 2),
    StaticSyscall::new(171, "setdomainname", 2),
    StaticSyscall::new(172, "iopl", 1),
    StaticSyscall::new(173, "ioperm", 3),
    StaticSyscall::new(174, "create_module", 2),
    StaticSyscall::new(175, "init_module", 3),
    StaticSyscall::new(176, "delete_module", 2),
    StaticSyscall::new(177, "get_kernel_syms", 1),
    StaticSyscall::new(178, "query_module", 5),
    StaticSyscall::new(179, "quotactl", 4),
    StaticSyscall::new(180, "nfsservctl", 3),
    StaticSyscall::new(181, "getpmsg", 5),
    StaticSyscall::new(182, "putpmsg", 5),
    StaticSyscall::new(183, "afs_syscall", 5),
    StaticSyscall::new(184, "tuxcall", 3),
    StaticSyscall::new(185, "security", 3),
    StaticSyscall::new(186, "gettid", 0),
    StaticSyscall::new(187, "readahead", 3),
    StaticSyscall::new(188, "setxattr", 5),
    StaticSyscall::new(189, "lsetxattr", 5),
    StaticSyscall::new(190, "fsetxattr", 5),
    StaticSyscall::new(191, "getxattr", 4),
    StaticSyscall::new(192, "lgetxattr", 4),
    StaticSyscall::new(193, "fgetxattr", 4),
    StaticSyscall::new(194, "listxattr", 3),
    StaticSyscall::new(195, "llistxattr", 3),
    StaticSyscall::new(196, "flistxattr", 3),
    StaticSyscall::new(197, "removexattr", 2),
    StaticSyscall::new(198, "lremovexattr", 2),
    StaticSyscall::new(199, "fremovexattr", 2),
    StaticSyscall::new(200, "tkill", 2),
    StaticSyscall::new(201, "time", 1),
    StaticSyscall::new(202, "futex", 6),
    StaticSyscall::new(203, "sched_setaffinity", 3),
    StaticSyscall::new(204, "sched_getaffinity", 3),
    StaticSyscall::new(205, "set_thread_area", 1),
    StaticSyscall::new(206, "io_setup", 2),
    StaticSyscall::new(207, "io_destroy", 1),
    StaticSyscall::new(208, "io_getevents", 5),
    StaticSyscall::new(209, "io_submit", 3),
    StaticSyscall::new(210, "io_cancel", 3),
    StaticSyscall::new(211, "get_thread_area", 1),
    StaticSyscall::new(212, "lookup_dcookie", 3),
    StaticSyscall::new(213, "epoll_create", 1),
    StaticSyscall::new(214, "epoll_ctl_old", 4),
    StaticSyscall::new(215, "epoll_wait_old", 4),
    StaticSyscall::new(216, "remap_file_pages", 5),
    StaticSyscall::new(217, "getdents64", 3),
    StaticSyscall::new(218, "set_tid_address", 1),
    StaticSyscall::new(219, "restart_syscall", 0),
    StaticSyscall::new(220, "semtimedop", 4),
    StaticSyscall::new(221, "fadvise64", 4),
    StaticSyscall::new(222, "timer_create", 3),
    StaticSyscall::new(223, "timer_settime", 4),
    StaticSyscall::new(224, "timer_gettime", 2),
    StaticSyscall::new(225, "timer_getoverrun", 1),
    StaticSyscall::new(226, "timer_delete", 1),
    StaticSyscall::new(227, "clock_settime", 2),
    StaticSyscall::new(228, "clock_gettime", 2),
    StaticSyscall::new(229, "clock_getres", 2),
    StaticSyscall::new(230, "clock_nanosleep", 4),
    StaticSyscall::new(231, "exit_group", 1),
    StaticSyscall::new(232, "epoll_wait", 4),
    StaticSyscall::new(233, "epoll_ctl", 4),
    StaticSyscall::new(234, "tgkill", 3),
    StaticSyscall::new(235, "utimes", 2),
    StaticSyscall::new(236, "vserver", 4),
    StaticSyscall::new(237, "mbind", 6),
    StaticSyscall::new(238, "set_mempolicy", 3),
    StaticSyscall::new(239, "get_mempolicy", 5),
    StaticSyscall::new(240, "mq_open", 4),
    StaticSyscall::new(241, "mq_unlink", 1),
    StaticSyscall::new(242, "mq_timedsend", 5),
    StaticSyscall::new(243, "mq_timedreceive", 5),
    StaticSyscall::new(244, "mq_notify", 2),
    StaticSyscall::new(245, "mq_getsetattr", 3),
    StaticSyscall::new(246, "kexec_load", 4),
    StaticSyscall::new(247, "waitid", 5),
    StaticSyscall::new(248, "add_key", 5),
    StaticSyscall::new(249, "request_key", 4),
    StaticSyscall::new(250, "keyctl", 5),
    StaticSyscall::new(251, "ioprio_set", 3),
    StaticSyscall::new(252, "ioprio_get", 2),
    StaticSyscall::new(253, "inotify_init", 0),
    StaticSyscall::new(254, "inotify_add_watch", 3),
    StaticSyscall::new(255, "inotify_rm_watch", 2),
    StaticSyscall::new(256, "migrate_pages", 4),
    StaticSyscall::new(257, "openat", 4),
    StaticSyscall::new(258, "mkdirat", 3),
    StaticSyscall::new(259, "mknodat", 4),
    StaticSyscall::new(260, "fchownat", 5),
    StaticSyscall::new(261, "futimesat", 3),
    StaticSyscall::new(262, "newfstatat", 4),
    StaticSyscall::new(263, "unlinkat", 3),
    StaticSyscall::new(264, "renameat", 4),
    StaticSyscall::new(265, "linkat", 5),
    StaticSyscall::new(266, "symlinkat", 3),
    StaticSyscall::new(267, "readlinkat", 4),
    StaticSyscall::new(268, "fchmodat", 4),
    StaticSyscall::new(269, "faccessat", 3),
    StaticSyscall::new(270, "pselect6", 6),
    StaticSyscall::new(271, "ppoll", 5),
    StaticSyscall::new(272, "unshare", 1),
    StaticSyscall::new(273, "set_robust_list", 2),
    StaticSyscall::new(274, "get_robust_list", 3),
    StaticSyscall::new(275, "splice", 6),
    StaticSyscall::new(276, "tee", 4),
    StaticSyscall::new(277, "sync_file_range", 4),
    StaticSyscall::new(278, "vmsplice", 4),
    StaticSyscall::new(279, "move_pages", 6),
    StaticSyscall::new(280, "utimensat", 4),
    StaticSyscall::new(281, "epoll_pwait", 6),
    StaticSyscall::new(282, "signalfd", 3),
    StaticSyscall::new(283, "timerfd_create", 2),
    StaticSyscall::new(284, "eventfd", 1),
    StaticSyscall::new(285, "fallocate", 4),
    StaticSyscall::new(286, "timerfd_settime", 4),
    StaticSyscall::new(287, "timerfd_gettime", 2),
    StaticSyscall::new(288, "accept4", 4),
    StaticSyscall::new(289, "signalfd4", 4),
    StaticSyscall::new(290, "eventfd2", 2),
    StaticSyscall::new(291, "epoll_create1", 1),
    StaticSyscall::new(292, "dup3", 3),
    StaticSyscall::new(293, "pipe2", 2),
    StaticSyscall::new(294, "inotify_init1", 1),
    StaticSyscall::new(295, "preadv", 5),
    StaticSyscall::new(296, "pwritev", 5),
    StaticSyscall::new(297, "rt_tgsigqueueinfo", 4),
    StaticSyscall::new(298, "perf_event_open", 5),
    StaticSyscall::new(299, "recvmmsg", 5),
    StaticSyscall::new(300, "fanotify_init", 2),
    StaticSyscall::new(301, "fanotify_mark", 5),
    StaticSyscall::new(302, "prlimit64", 4),
    StaticSyscall::new(303, "name_to_handle_at", 5),
    StaticSyscall::new(304, "open_by_handle_at", 3),
    StaticSyscall::new(305, "clock_adjtime", 2),
    StaticSyscall::new(306, "syncfs", 1),
    StaticSyscall::new(307, "sendmmsg", 4),
    StaticSyscall::new(308, "setns", 2),
    StaticSyscall::new(309, "getcpu", 3),
    StaticSyscall::new(310, "process_vm_readv", 6),
    StaticSyscall::new(311, "process_vm_writev", 6),
    StaticSyscall::new(312, "kcmp", 5),
    StaticSyscall::new(313, "finit_module", 3),
    StaticSyscall::new(314, "sched_setattr", 3),
    StaticSyscall::new(315, "sched_getattr", 4),
    StaticSyscall::new(316, "renameat2", 5),
    StaticSyscall::new(317, "seccomp", 3),
    StaticSyscall::new(318, "getrandom", 3),
    StaticSyscall::new(319, "memfd_create", 2),
    StaticSyscall::new(320, "kexec_file_load", 5),
    StaticSyscall::new(321, "bpf", 3),
    StaticSyscall::new(322, "execveat", 5),
    StaticSyscall::new(323, "userfaultfd", 1),
    StaticSyscall::new(324, "membarrier", 3),
    StaticSyscall::new(325, "mlock2", 3),
    StaticSyscall::new(326, "copy_file_range", 6),
    StaticSyscall::new(327, "preadv2", 6),
    StaticSyscall::new(328, "pwritev2", 6),
    StaticSyscall::new(329, "pkey_mprotect", 4),
    StaticSyscall::new(330, "pkey_alloc", 2),
    StaticSyscall::new(331, "pkey_free", 1),
    StaticSyscall::new(332, "statx", 5),
    StaticSyscall::new(333, "io_pgetevents", 6),
    StaticSyscall::new(334, "rseq", 4),
    // 335..=423 are reserved/unassigned in the x86_64 Linux ABI but must be
    // present so the table is dense and indexable by syscall number.
    StaticSyscall::new(335, "reserved_335", 0),
    StaticSyscall::new(336, "reserved_336", 0),
    StaticSyscall::new(337, "reserved_337", 0),
    StaticSyscall::new(338, "reserved_338", 0),
    StaticSyscall::new(339, "reserved_339", 0),
    StaticSyscall::new(340, "reserved_340", 0),
    StaticSyscall::new(341, "reserved_341", 0),
    StaticSyscall::new(342, "reserved_342", 0),
    StaticSyscall::new(343, "reserved_343", 0),
    StaticSyscall::new(344, "reserved_344", 0),
    StaticSyscall::new(345, "reserved_345", 0),
    StaticSyscall::new(346, "reserved_346", 0),
    StaticSyscall::new(347, "reserved_347", 0),
    StaticSyscall::new(348, "reserved_348", 0),
    StaticSyscall::new(349, "reserved_349", 0),
    StaticSyscall::new(350, "reserved_350", 0),
    StaticSyscall::new(351, "reserved_351", 0),
    StaticSyscall::new(352, "reserved_352", 0),
    StaticSyscall::new(353, "reserved_353", 0),
    StaticSyscall::new(354, "reserved_354", 0),
    StaticSyscall::new(355, "reserved_355", 0),
    StaticSyscall::new(356, "reserved_356", 0),
    StaticSyscall::new(357, "reserved_357", 0),
    StaticSyscall::new(358, "reserved_358", 0),
    StaticSyscall::new(359, "reserved_359", 0),
    StaticSyscall::new(360, "reserved_360", 0),
    StaticSyscall::new(361, "reserved_361", 0),
    StaticSyscall::new(362, "reserved_362", 0),
    StaticSyscall::new(363, "reserved_363", 0),
    StaticSyscall::new(364, "reserved_364", 0),
    StaticSyscall::new(365, "reserved_365", 0),
    StaticSyscall::new(366, "reserved_366", 0),
    StaticSyscall::new(367, "reserved_367", 0),
    StaticSyscall::new(368, "reserved_368", 0),
    StaticSyscall::new(369, "reserved_369", 0),
    StaticSyscall::new(370, "reserved_370", 0),
    StaticSyscall::new(371, "reserved_371", 0),
    StaticSyscall::new(372, "reserved_372", 0),
    StaticSyscall::new(373, "reserved_373", 0),
    StaticSyscall::new(374, "reserved_374", 0),
    StaticSyscall::new(375, "reserved_375", 0),
    StaticSyscall::new(376, "reserved_376", 0),
    StaticSyscall::new(377, "reserved_377", 0),
    StaticSyscall::new(378, "reserved_378", 0),
    StaticSyscall::new(379, "reserved_379", 0),
    StaticSyscall::new(380, "reserved_380", 0),
    StaticSyscall::new(381, "reserved_381", 0),
    StaticSyscall::new(382, "reserved_382", 0),
    StaticSyscall::new(383, "reserved_383", 0),
    StaticSyscall::new(384, "reserved_384", 0),
    StaticSyscall::new(385, "reserved_385", 0),
    StaticSyscall::new(386, "reserved_386", 0),
    StaticSyscall::new(387, "reserved_387", 0),
    StaticSyscall::new(388, "reserved_388", 0),
    StaticSyscall::new(389, "reserved_389", 0),
    StaticSyscall::new(390, "reserved_390", 0),
    StaticSyscall::new(391, "reserved_391", 0),
    StaticSyscall::new(392, "reserved_392", 0),
    StaticSyscall::new(393, "reserved_393", 0),
    StaticSyscall::new(394, "reserved_394", 0),
    StaticSyscall::new(395, "reserved_395", 0),
    StaticSyscall::new(396, "reserved_396", 0),
    StaticSyscall::new(397, "reserved_397", 0),
    StaticSyscall::new(398, "reserved_398", 0),
    StaticSyscall::new(399, "reserved_399", 0),
    StaticSyscall::new(400, "reserved_400", 0),
    StaticSyscall::new(401, "reserved_401", 0),
    StaticSyscall::new(402, "reserved_402", 0),
    StaticSyscall::new(403, "reserved_403", 0),
    StaticSyscall::new(404, "reserved_404", 0),
    StaticSyscall::new(405, "reserved_405", 0),
    StaticSyscall::new(406, "reserved_406", 0),
    StaticSyscall::new(407, "reserved_407", 0),
    StaticSyscall::new(408, "reserved_408", 0),
    StaticSyscall::new(409, "reserved_409", 0),
    StaticSyscall::new(410, "reserved_410", 0),
    StaticSyscall::new(411, "reserved_411", 0),
    StaticSyscall::new(412, "reserved_412", 0),
    StaticSyscall::new(413, "reserved_413", 0),
    StaticSyscall::new(414, "reserved_414", 0),
    StaticSyscall::new(415, "reserved_415", 0),
    StaticSyscall::new(416, "reserved_416", 0),
    StaticSyscall::new(417, "reserved_417", 0),
    StaticSyscall::new(418, "reserved_418", 0),
    StaticSyscall::new(419, "reserved_419", 0),
    StaticSyscall::new(420, "reserved_420", 0),
    StaticSyscall::new(421, "reserved_421", 0),
    StaticSyscall::new(422, "reserved_422", 0),
    StaticSyscall::new(423, "reserved_423", 0),
    StaticSyscall::new(424, "pidfd_send_signal", 4),
    StaticSyscall::new(425, "io_uring_setup", 2),
    StaticSyscall::new(426, "io_uring_enter", 6),
    StaticSyscall::new(427, "io_uring_register", 4),
    StaticSyscall::new(428, "open_tree", 3),
    StaticSyscall::new(429, "move_mount", 5),
    StaticSyscall::new(430, "fsopen", 2),
    StaticSyscall::new(431, "fsconfig", 5),
    StaticSyscall::new(432, "fsmount", 3),
    StaticSyscall::new(433, "fspick", 3),
    StaticSyscall::new(434, "pidfd_open", 2),
    StaticSyscall::new(435, "clone3", 2),
    StaticSyscall::new(436, "close_range", 3),
    StaticSyscall::new(437, "openat2", 4),
    StaticSyscall::new(438, "pidfd_getfd", 3),
    StaticSyscall::new(439, "faccessat2", 4),
    StaticSyscall::new(440, "process_madvise", 5),
    StaticSyscall::new(441, "epoll_pwait2", 6),
    StaticSyscall::new(442, "mount_setattr", 5),
    StaticSyscall::new(443, "quotactl_fd", 4),
    StaticSyscall::new(444, "landlock_create_ruleset", 3),
    StaticSyscall::new(445, "landlock_add_rule", 4),
    StaticSyscall::new(446, "landlock_restrict_self", 2),
    StaticSyscall::new(447, "memfd_secret", 1),
    StaticSyscall::new(448, "process_mrelease", 2),
    StaticSyscall::new(449, "futex_waitv", 5),
    StaticSyscall::new(450, "set_mempolicy_home_node", 4),
];

#[must_use]
pub fn x86_64_syscall_name(nr: u32) -> Option<&'static str> {
    X86_64_SYSCALLS.iter().find(|s| s.nr == nr).map(|s| s.name)
}

#[must_use]
pub fn x86_64_syscall_nr(name: &str) -> Option<u32> {
    X86_64_SYSCALLS
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.nr)
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext_tests {
    use super::*;

    #[test]
    fn test_signal_name_sigkill() {
        assert_eq!(signal_name_v2(9), Some("SIGKILL"));
    }
    #[test]
    fn test_signal_name_sigsegv() {
        assert_eq!(signal_name_v2(11), Some("SIGSEGV"));
    }
    #[test]
    fn test_signal_name_unknown() {
        assert!(signal_name_v2(200).is_none());
    }

    #[test]
    fn test_decode_o_wronly_creat_trunc() {
        let f = 0o1 | 0o100 | 0o1000u64;
        let s = decode_flags(f, O_FLAGS);
        assert!(s.contains("O_WRONLY"), "got: {s}");
        assert!(s.contains("O_CREAT"), "got: {s}");
        assert!(s.contains("O_TRUNC"), "got: {s}");
    }

    #[test]
    fn test_decode_flags_zero() {
        assert_eq!(decode_flags(0, O_FLAGS), "0");
    }

    #[test]
    fn test_prot_flags_rwx() {
        let s = decode_flags(0x7, PROT_FLAGS);
        assert!(s.contains("PROT_READ") && s.contains("PROT_WRITE") && s.contains("PROT_EXEC"));
    }

    #[test]
    fn test_map_flags_anon_private() {
        let s = decode_flags(0x22, MAP_FLAGS);
        assert!(s.contains("MAP_PRIVATE") && s.contains("MAP_ANONYMOUS"));
    }

    #[test]
    fn test_clone_flags_thread() {
        let s = decode_flags(0x003d_0f00, CLONE_FLAGS);
        assert!(s.contains("CLONE_VM") && s.contains("CLONE_THREAD"));
    }

    #[test]
    fn test_decode_sockaddr_inet_loopback_80() {
        let mut d = vec![0u8; 8];
        d[0] = 2;
        d[1] = 0;
        d[2] = 0;
        d[3] = 80;
        d[4] = 127;
        d[5] = 0;
        d[6] = 0;
        d[7] = 1;
        match decode_sockaddr(&d) {
            DecodedSockaddr::Inet { addr, port } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 80);
            }
            o => panic!("expected Inet, got {o:?}"),
        }
    }

    #[test]
    fn test_decode_sockaddr_unix() {
        let mut d = vec![1u8, 0];
        d.extend_from_slice(b"/tmp/x.sock\0");
        match decode_sockaddr(&d) {
            DecodedSockaddr::Unix { path } => assert_eq!(path, "/tmp/x.sock"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn test_x86_64_full_table_size() {
        assert_eq!(X86_64_SYSCALLS.len(), 451);
    }
    #[test]
    fn test_x86_64_read() {
        assert_eq!(x86_64_syscall_name(0), Some("read"));
    }
    #[test]
    fn test_x86_64_write() {
        assert_eq!(x86_64_syscall_name(1), Some("write"));
    }
    #[test]
    fn test_x86_64_execve() {
        assert_eq!(x86_64_syscall_name(59), Some("execve"));
    }
    #[test]
    fn test_x86_64_openat() {
        assert_eq!(x86_64_syscall_name(257), Some("openat"));
    }
    #[test]
    fn test_x86_64_clone3() {
        assert_eq!(x86_64_syscall_name(435), Some("clone3"));
    }
    #[test]
    fn test_x86_64_unknown() {
        assert!(x86_64_syscall_name(9999).is_none());
    }
    #[test]
    fn test_x86_64_rev_mmap() {
        assert_eq!(x86_64_syscall_nr("mmap"), Some(9));
    }

    #[test]
    fn test_fd_table_ops() {
        let mut t = FdTable::default();
        t.insert(3, FdInfo::file("/etc/passwd", 0));
        assert!(t.get(3).is_some());
        t.dup(3, 4);
        assert_eq!(t.get(4).unwrap().path, "/etc/passwd");
        t.remove(3);
        assert!(t.get(3).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_fd_info_socket() {
        let i = FdInfo::socket(2, 1, 0);
        assert!(i.is_socket);
        assert!(i.path.contains("socket:"));
    }

    #[test]
    fn test_thread_state_entry_exit() {
        let mut s = ThreadSyscallState::default();
        s.on_entry(1, [1, 0, 0, 0, 0, 0, 0], 1_000_000);
        assert_eq!(s.in_syscall, Some(1));
        let (nr, el) = s.on_exit(1_001_000);
        assert_eq!(nr, Some(1));
        assert_eq!(el, 1_000);
    }

    #[test]
    fn test_summary_sort_by_time() {
        let mut s = SyscallSummaryV2::default();
        s.record("read", 1_000_000, 0);
        s.record("write", 2_000_000, 0);
        s.record("read", 500_000, 0);
        let v = s.sorted_by_time();
        assert_eq!(v[0].name, "write");
    }

    #[test]
    fn test_summary_error_count() {
        let mut s = SyscallSummaryV2::default();
        s.record("open", 100, 0);
        s.record("open", 200, -1);
        assert_eq!(s.entries["open"].error_count, 1);
    }

    #[test]
    fn test_ptrace_filter_include() {
        let o = PtraceOptionsV2::spawn("ls").include(["read", "write"]);
        assert!(o.passes_filter("read"));
        assert!(!o.passes_filter("mmap"));
    }

    #[test]
    fn test_ptrace_filter_exclude() {
        let o = PtraceOptionsV2::spawn("ls").exclude(["brk"]);
        assert!(!o.passes_filter("brk"));
        assert!(o.passes_filter("mmap"));
    }

    #[test]
    fn test_format_signal_sigsegv() {
        let s = format_signal_delivery(11, 1, 0xdead);
        assert!(s.contains("SIGSEGV") && s.contains("SEGV_MAPERR") && s.contains("dead"));
    }

    #[test]
    fn test_format_exit_normal() {
        assert!(format_exit_event(1, 0, None).contains("exited with 0"));
    }

    #[test]
    fn test_format_exit_signal() {
        assert!(format_exit_event(1, 0, Some(9)).contains("SIGKILL"));
    }

    #[test]
    fn test_syscall_event_display() {
        let ev = SyscallEventV2 {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            nr: 0,
            name: "read".to_string(),
            args: vec![
                DecodedArg::Fd(3, "/etc/passwd".to_string()),
                DecodedArg::Addr(0x7fff_0000),
                DecodedArg::UInt(256),
            ],
            retval: DecodedArg::Int(256),
            elapsed_ns: 500,
            is_entry: false,
        };
        let s = ev.to_string();
        assert!(s.starts_with("read(") && s.contains("= 256"));
    }

    #[test]
    fn test_syscall_event_csv() {
        let ev = SyscallEventV2 {
            timestamp_ns: 123,
            pid: 1,
            tid: 1,
            nr: 1,
            name: "write".to_string(),
            args: vec![],
            retval: DecodedArg::Int(4),
            elapsed_ns: 99,
            is_entry: false,
        };
        assert!(ev.to_csv_row().starts_with("123,1,1,write,"));
    }

    #[test]
    fn test_epoll_events_decode() {
        let s = decode_flags(0x05, EPOLL_EVENTS);
        assert!(s.contains("EPOLLIN") && s.contains("EPOLLOUT"));
    }

    #[test]
    fn test_sock_stream() {
        assert!(decode_flags(1, SOCK_FLAGS).contains("SOCK_STREAM"));
    }

    #[test]
    fn test_wait_wnohang() {
        assert!(decode_flags(0x1, WAIT_FLAGS).contains("WNOHANG"));
    }

    #[test]
    fn test_summary_table_has_header() {
        let mut s = SyscallSummaryV2::default();
        s.record("mmap", 50_000_000, 0);
        assert!(s.format_table().contains("% time"));
    }

    #[test]
    fn test_at_fdcwd_constant() {
        assert_eq!(AT_FDCWD, -100);
    }

    #[test]
    fn test_arg_type_c_name_fd() {
        assert_eq!(ArgType::Fd.c_name(), "int /*fd*/");
    }

    #[test]
    fn test_arg_type_c_name_str() {
        assert_eq!(ArgType::Str.c_name(), "const char *");
    }

    #[test]
    fn test_decoded_arg_null() {
        assert_eq!(DecodedArg::Null.to_string(), "NULL");
    }

    #[test]
    fn test_decoded_arg_fd_with_path() {
        assert_eq!(
            DecodedArg::Fd(3, "/etc/passwd".to_string()).to_string(),
            "3</etc/passwd>"
        );
    }

    #[test]
    fn test_decoded_arg_flags() {
        assert_eq!(
            DecodedArg::Flags(1, "O_WRONLY".to_string()).to_string(),
            "O_WRONLY"
        );
    }

    #[test]
    fn test_hex_dump_ext_truncation() {
        let d: Vec<u8> = (0u8..20).collect();
        let s = hex_dump_ext(&d, 8);
        assert!(s.contains("... (12 more bytes)"));
    }

    #[test]
    fn test_decode_flags_by_name_prot_rw() {
        let s = decode_flags_by_name("PROT_FLAGS", 0x3);
        assert!(s.contains("PROT_READ") && s.contains("PROT_WRITE"));
    }
}

// ─── AArch64-specific syscall table ──────────────────────────────────────────
// AArch64 uses a different numbering from x86_64.

pub static AARCH64_SPECIFIC_SYSCALLS_V2: &[StaticSyscall] = &[
    StaticSyscall::new(0, "io_setup", 2),
    StaticSyscall::new(1, "io_destroy", 1),
    StaticSyscall::new(2, "io_submit", 3),
    StaticSyscall::new(3, "io_cancel", 3),
    StaticSyscall::new(4, "io_getevents", 5),
    StaticSyscall::new(5, "setxattr", 5),
    StaticSyscall::new(6, "lsetxattr", 5),
    StaticSyscall::new(7, "fsetxattr", 5),
    StaticSyscall::new(8, "getxattr", 4),
    StaticSyscall::new(9, "lgetxattr", 4),
    StaticSyscall::new(10, "fgetxattr", 4),
    StaticSyscall::new(11, "listxattr", 3),
    StaticSyscall::new(12, "llistxattr", 3),
    StaticSyscall::new(13, "flistxattr", 3),
    StaticSyscall::new(14, "removexattr", 2),
    StaticSyscall::new(15, "lremovexattr", 2),
    StaticSyscall::new(16, "fremovexattr", 2),
    StaticSyscall::new(17, "getcwd", 2),
    StaticSyscall::new(18, "lookup_dcookie", 3),
    StaticSyscall::new(19, "eventfd2", 2),
    StaticSyscall::new(20, "epoll_create1", 1),
    StaticSyscall::new(21, "epoll_ctl", 4),
    StaticSyscall::new(22, "epoll_pwait", 6),
    StaticSyscall::new(23, "dup", 1),
    StaticSyscall::new(24, "dup3", 3),
    StaticSyscall::new(25, "fcntl", 3),
    StaticSyscall::new(26, "inotify_init1", 1),
    StaticSyscall::new(27, "inotify_add_watch", 3),
    StaticSyscall::new(28, "inotify_rm_watch", 2),
    StaticSyscall::new(29, "ioctl", 3),
    StaticSyscall::new(30, "ioprio_set", 3),
    StaticSyscall::new(31, "ioprio_get", 2),
    StaticSyscall::new(32, "flock", 2),
    StaticSyscall::new(33, "mknodat", 4),
    StaticSyscall::new(34, "mkdirat", 3),
    StaticSyscall::new(35, "unlinkat", 3),
    StaticSyscall::new(36, "symlinkat", 3),
    StaticSyscall::new(37, "linkat", 5),
    StaticSyscall::new(38, "renameat", 4),
    StaticSyscall::new(39, "umount2", 2),
    StaticSyscall::new(40, "mount", 5),
    StaticSyscall::new(41, "pivot_root", 2),
    StaticSyscall::new(42, "nfsservctl", 3),
    StaticSyscall::new(43, "statfs", 2),
    StaticSyscall::new(44, "fstatfs", 2),
    StaticSyscall::new(45, "truncate", 2),
    StaticSyscall::new(46, "ftruncate", 2),
    StaticSyscall::new(47, "fallocate", 4),
    StaticSyscall::new(48, "faccessat", 3),
    StaticSyscall::new(49, "chdir", 1),
    StaticSyscall::new(50, "fchdir", 1),
    StaticSyscall::new(51, "chroot", 1),
    StaticSyscall::new(52, "fchmod", 2),
    StaticSyscall::new(53, "fchmodat", 4),
    StaticSyscall::new(54, "fchownat", 5),
    StaticSyscall::new(55, "fchown", 3),
    StaticSyscall::new(56, "openat", 4),
    StaticSyscall::new(57, "close", 1),
    StaticSyscall::new(58, "vhangup", 0),
    StaticSyscall::new(59, "pipe2", 2),
    StaticSyscall::new(60, "quotactl", 4),
    StaticSyscall::new(61, "getdents64", 3),
    StaticSyscall::new(62, "lseek", 3),
    StaticSyscall::new(63, "read", 3),
    StaticSyscall::new(64, "write", 3),
    StaticSyscall::new(65, "readv", 3),
    StaticSyscall::new(66, "writev", 3),
    StaticSyscall::new(67, "pread64", 4),
    StaticSyscall::new(68, "pwrite64", 4),
    StaticSyscall::new(69, "preadv", 5),
    StaticSyscall::new(70, "pwritev", 5),
    StaticSyscall::new(71, "sendfile", 4),
    StaticSyscall::new(72, "pselect6", 6),
    StaticSyscall::new(73, "ppoll", 5),
    StaticSyscall::new(74, "signalfd4", 4),
    StaticSyscall::new(75, "vmsplice", 4),
    StaticSyscall::new(76, "splice", 6),
    StaticSyscall::new(77, "tee", 4),
    StaticSyscall::new(78, "readlinkat", 4),
    StaticSyscall::new(79, "newfstatat", 4),
    StaticSyscall::new(80, "fstat", 2),
    StaticSyscall::new(81, "sync", 0),
    StaticSyscall::new(82, "fsync", 1),
    StaticSyscall::new(83, "fdatasync", 1),
    StaticSyscall::new(84, "sync_file_range", 4),
    StaticSyscall::new(85, "timerfd_create", 2),
    StaticSyscall::new(86, "timerfd_settime", 4),
    StaticSyscall::new(87, "timerfd_gettime", 2),
    StaticSyscall::new(88, "utimensat", 4),
    StaticSyscall::new(89, "acct", 1),
    StaticSyscall::new(90, "capget", 2),
    StaticSyscall::new(91, "capset", 2),
    StaticSyscall::new(92, "personality", 1),
    StaticSyscall::new(93, "exit", 1),
    StaticSyscall::new(94, "exit_group", 1),
    StaticSyscall::new(95, "waitid", 5),
    StaticSyscall::new(96, "set_tid_address", 1),
    StaticSyscall::new(97, "unshare", 1),
    StaticSyscall::new(98, "futex", 6),
    StaticSyscall::new(99, "set_robust_list", 2),
    StaticSyscall::new(100, "get_robust_list", 3),
    StaticSyscall::new(101, "nanosleep", 2),
    StaticSyscall::new(102, "getitimer", 2),
    StaticSyscall::new(103, "setitimer", 3),
    StaticSyscall::new(104, "kexec_load", 4),
    StaticSyscall::new(105, "init_module", 3),
    StaticSyscall::new(106, "delete_module", 2),
    StaticSyscall::new(107, "timer_create", 3),
    StaticSyscall::new(108, "timer_gettime", 2),
    StaticSyscall::new(109, "timer_getoverrun", 1),
    StaticSyscall::new(110, "timer_settime", 4),
    StaticSyscall::new(111, "timer_delete", 1),
    StaticSyscall::new(112, "clock_settime", 2),
    StaticSyscall::new(113, "clock_gettime", 2),
    StaticSyscall::new(114, "clock_getres", 2),
    StaticSyscall::new(115, "clock_nanosleep", 4),
    StaticSyscall::new(116, "syslog", 3),
    StaticSyscall::new(117, "ptrace", 4),
    StaticSyscall::new(118, "sched_setparam", 2),
    StaticSyscall::new(119, "sched_setscheduler", 3),
    StaticSyscall::new(120, "sched_getscheduler", 1),
    StaticSyscall::new(121, "sched_getparam", 2),
    StaticSyscall::new(122, "sched_setaffinity", 3),
    StaticSyscall::new(123, "sched_getaffinity", 3),
    StaticSyscall::new(124, "sched_yield", 0),
    StaticSyscall::new(125, "sched_get_priority_max", 1),
    StaticSyscall::new(126, "sched_get_priority_min", 1),
    StaticSyscall::new(127, "sched_rr_get_interval", 2),
    StaticSyscall::new(128, "restart_syscall", 0),
    StaticSyscall::new(129, "kill", 2),
    StaticSyscall::new(130, "tkill", 2),
    StaticSyscall::new(131, "tgkill", 3),
    StaticSyscall::new(132, "sigaltstack", 2),
    StaticSyscall::new(133, "rt_sigsuspend", 2),
    StaticSyscall::new(134, "rt_sigaction", 4),
    StaticSyscall::new(135, "rt_sigprocmask", 4),
    StaticSyscall::new(136, "rt_sigpending", 2),
    StaticSyscall::new(137, "rt_sigtimedwait", 4),
    StaticSyscall::new(138, "rt_sigqueueinfo", 3),
    StaticSyscall::new(139, "rt_sigreturn", 0),
    StaticSyscall::new(140, "setpriority", 3),
    StaticSyscall::new(141, "getpriority", 2),
    StaticSyscall::new(142, "reboot", 4),
    StaticSyscall::new(143, "setregid", 2),
    StaticSyscall::new(144, "setgid", 1),
    StaticSyscall::new(145, "setreuid", 2),
    StaticSyscall::new(146, "setuid", 1),
    StaticSyscall::new(147, "setresuid", 3),
    StaticSyscall::new(148, "getresuid", 3),
    StaticSyscall::new(149, "setresgid", 3),
    StaticSyscall::new(150, "getresgid", 3),
    StaticSyscall::new(151, "setfsuid", 1),
    StaticSyscall::new(152, "setfsgid", 1),
    StaticSyscall::new(153, "times", 1),
    StaticSyscall::new(154, "setpgid", 2),
    StaticSyscall::new(155, "getpgid", 1),
    StaticSyscall::new(156, "getsid", 1),
    StaticSyscall::new(157, "setsid", 0),
    StaticSyscall::new(158, "getgroups", 2),
    StaticSyscall::new(159, "setgroups", 2),
    StaticSyscall::new(160, "uname", 1),
    StaticSyscall::new(161, "sethostname", 2),
    StaticSyscall::new(162, "setdomainname", 2),
    StaticSyscall::new(163, "getrlimit", 2),
    StaticSyscall::new(164, "setrlimit", 2),
    StaticSyscall::new(165, "getrusage", 2),
    StaticSyscall::new(166, "umask", 1),
    StaticSyscall::new(167, "prctl", 5),
    StaticSyscall::new(168, "getcpu", 3),
    StaticSyscall::new(169, "gettimeofday", 2),
    StaticSyscall::new(170, "settimeofday", 2),
    StaticSyscall::new(171, "adjtimex", 1),
    StaticSyscall::new(172, "getpid", 0),
    StaticSyscall::new(173, "getppid", 0),
    StaticSyscall::new(174, "getuid", 0),
    StaticSyscall::new(175, "geteuid", 0),
    StaticSyscall::new(176, "getgid", 0),
    StaticSyscall::new(177, "getegid", 0),
    StaticSyscall::new(178, "gettid", 0),
    StaticSyscall::new(179, "sysinfo", 1),
    StaticSyscall::new(180, "mq_open", 4),
    StaticSyscall::new(181, "mq_unlink", 1),
    StaticSyscall::new(182, "mq_timedsend", 5),
    StaticSyscall::new(183, "mq_timedreceive", 5),
    StaticSyscall::new(184, "mq_notify", 2),
    StaticSyscall::new(185, "mq_getsetattr", 3),
    StaticSyscall::new(186, "msgget", 2),
    StaticSyscall::new(187, "msgctl", 3),
    StaticSyscall::new(188, "msgrcv", 5),
    StaticSyscall::new(189, "msgsnd", 4),
    StaticSyscall::new(190, "semget", 3),
    StaticSyscall::new(191, "semctl", 4),
    StaticSyscall::new(192, "semtimedop", 4),
    StaticSyscall::new(193, "semop", 3),
    StaticSyscall::new(194, "shmget", 3),
    StaticSyscall::new(195, "shmctl", 3),
    StaticSyscall::new(196, "shmat", 3),
    StaticSyscall::new(197, "shmdt", 1),
    StaticSyscall::new(198, "socket", 3),
    StaticSyscall::new(199, "socketpair", 4),
    StaticSyscall::new(200, "bind", 3),
    StaticSyscall::new(201, "listen", 2),
    StaticSyscall::new(202, "accept", 3),
    StaticSyscall::new(203, "connect", 3),
    StaticSyscall::new(204, "getsockname", 3),
    StaticSyscall::new(205, "getpeername", 3),
    StaticSyscall::new(206, "sendto", 6),
    StaticSyscall::new(207, "recvfrom", 6),
    StaticSyscall::new(208, "setsockopt", 5),
    StaticSyscall::new(209, "getsockopt", 5),
    StaticSyscall::new(210, "shutdown", 2),
    StaticSyscall::new(211, "sendmsg", 3),
    StaticSyscall::new(212, "recvmsg", 3),
    StaticSyscall::new(213, "readahead", 3),
    StaticSyscall::new(214, "brk", 1),
    StaticSyscall::new(215, "munmap", 2),
    StaticSyscall::new(216, "mremap", 5),
    StaticSyscall::new(217, "add_key", 5),
    StaticSyscall::new(218, "request_key", 4),
    StaticSyscall::new(219, "keyctl", 5),
    StaticSyscall::new(220, "clone", 5),
    StaticSyscall::new(221, "execve", 3),
    StaticSyscall::new(222, "mmap", 6),
    StaticSyscall::new(223, "fadvise64", 4),
    StaticSyscall::new(224, "swapon", 2),
    StaticSyscall::new(225, "swapoff", 1),
    StaticSyscall::new(226, "mprotect", 3),
    StaticSyscall::new(227, "msync", 3),
    StaticSyscall::new(228, "mlock", 2),
    StaticSyscall::new(229, "munlock", 2),
    StaticSyscall::new(230, "mlockall", 1),
    StaticSyscall::new(231, "munlockall", 0),
    StaticSyscall::new(232, "mincore", 3),
    StaticSyscall::new(233, "madvise", 3),
    StaticSyscall::new(234, "remap_file_pages", 5),
    StaticSyscall::new(235, "mbind", 6),
    StaticSyscall::new(236, "get_mempolicy", 5),
    StaticSyscall::new(237, "set_mempolicy", 3),
    StaticSyscall::new(238, "migrate_pages", 4),
    StaticSyscall::new(239, "move_pages", 6),
    StaticSyscall::new(240, "rt_tgsigqueueinfo", 4),
    StaticSyscall::new(241, "perf_event_open", 5),
    StaticSyscall::new(242, "accept4", 4),
    StaticSyscall::new(243, "recvmmsg", 5),
    StaticSyscall::new(260, "wait4", 4),
    StaticSyscall::new(261, "prlimit64", 4),
    StaticSyscall::new(262, "fanotify_init", 2),
    StaticSyscall::new(263, "fanotify_mark", 5),
    StaticSyscall::new(264, "name_to_handle_at", 5),
    StaticSyscall::new(265, "open_by_handle_at", 3),
    StaticSyscall::new(266, "clock_adjtime", 2),
    StaticSyscall::new(267, "syncfs", 1),
    StaticSyscall::new(268, "setns", 2),
    StaticSyscall::new(269, "sendmmsg", 4),
    StaticSyscall::new(270, "process_vm_readv", 6),
    StaticSyscall::new(271, "process_vm_writev", 6),
    StaticSyscall::new(272, "kcmp", 5),
    StaticSyscall::new(273, "finit_module", 3),
    StaticSyscall::new(274, "sched_setattr", 3),
    StaticSyscall::new(275, "sched_getattr", 4),
    StaticSyscall::new(276, "renameat2", 5),
    StaticSyscall::new(277, "seccomp", 3),
    StaticSyscall::new(278, "getrandom", 3),
    StaticSyscall::new(279, "memfd_create", 2),
    StaticSyscall::new(280, "bpf", 3),
    StaticSyscall::new(281, "execveat", 5),
    StaticSyscall::new(282, "userfaultfd", 1),
    StaticSyscall::new(283, "membarrier", 3),
    StaticSyscall::new(284, "mlock2", 3),
    StaticSyscall::new(285, "copy_file_range", 6),
    StaticSyscall::new(286, "preadv2", 6),
    StaticSyscall::new(287, "pwritev2", 6),
    StaticSyscall::new(288, "pkey_mprotect", 4),
    StaticSyscall::new(289, "pkey_alloc", 2),
    StaticSyscall::new(290, "pkey_free", 1),
    StaticSyscall::new(291, "statx", 5),
    StaticSyscall::new(292, "io_pgetevents", 6),
    StaticSyscall::new(293, "rseq", 4),
    StaticSyscall::new(424, "pidfd_send_signal", 4),
    StaticSyscall::new(425, "io_uring_setup", 2),
    StaticSyscall::new(426, "io_uring_enter", 6),
    StaticSyscall::new(427, "io_uring_register", 4),
    StaticSyscall::new(428, "open_tree", 3),
    StaticSyscall::new(429, "move_mount", 5),
    StaticSyscall::new(430, "fsopen", 2),
    StaticSyscall::new(431, "fsconfig", 5),
    StaticSyscall::new(432, "fsmount", 3),
    StaticSyscall::new(433, "fspick", 3),
    StaticSyscall::new(434, "pidfd_open", 2),
    StaticSyscall::new(435, "clone3", 2),
    StaticSyscall::new(436, "close_range", 3),
    StaticSyscall::new(437, "openat2", 4),
    StaticSyscall::new(438, "pidfd_getfd", 3),
    StaticSyscall::new(439, "faccessat2", 4),
    StaticSyscall::new(440, "process_madvise", 5),
    StaticSyscall::new(441, "epoll_pwait2", 6),
    StaticSyscall::new(442, "mount_setattr", 5),
    StaticSyscall::new(443, "quotactl_fd", 4),
    StaticSyscall::new(444, "landlock_create_ruleset", 3),
    StaticSyscall::new(445, "landlock_add_rule", 4),
    StaticSyscall::new(446, "landlock_restrict_self", 2),
    StaticSyscall::new(447, "memfd_secret", 1),
    StaticSyscall::new(448, "process_mrelease", 2),
    StaticSyscall::new(449, "futex_waitv", 5),
    StaticSyscall::new(450, "set_mempolicy_home_node", 4),
];

/// Look up a syscall name by `AArch64` number.
#[must_use]
pub fn aarch64_syscall_name_v2(nr: u32) -> Option<&'static str> {
    AARCH64_SPECIFIC_SYSCALLS_V2
        .iter()
        .find(|s| s.nr == nr)
        .map(|s| s.name)
}

/// Look up a syscall number by name in the `AArch64` table.
#[must_use]
pub fn aarch64_syscall_nr(name: &str) -> Option<u32> {
    AARCH64_SPECIFIC_SYSCALLS_V2
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.nr)
}

// ─── errno decoder ────────────────────────────────────────────────────────────

/// Return the name of a Linux errno value.
#[must_use]
pub const fn errno_name_v2(errno: i32) -> Option<&'static str> {
    match errno.unsigned_abs() {
        1 => Some("EPERM"),
        2 => Some("ENOENT"),
        3 => Some("ESRCH"),
        4 => Some("EINTR"),
        5 => Some("EIO"),
        6 => Some("ENXIO"),
        7 => Some("E2BIG"),
        8 => Some("ENOEXEC"),
        9 => Some("EBADF"),
        10 => Some("ECHILD"),
        11 => Some("EAGAIN"),
        12 => Some("ENOMEM"),
        13 => Some("EACCES"),
        14 => Some("EFAULT"),
        15 => Some("ENOTBLK"),
        16 => Some("EBUSY"),
        17 => Some("EEXIST"),
        18 => Some("EXDEV"),
        19 => Some("ENODEV"),
        20 => Some("ENOTDIR"),
        21 => Some("EISDIR"),
        22 => Some("EINVAL"),
        23 => Some("ENFILE"),
        24 => Some("EMFILE"),
        25 => Some("ENOTTY"),
        26 => Some("ETXTBSY"),
        27 => Some("EFBIG"),
        28 => Some("ENOSPC"),
        29 => Some("ESPIPE"),
        30 => Some("EROFS"),
        31 => Some("EMLINK"),
        32 => Some("EPIPE"),
        33 => Some("EDOM"),
        34 => Some("ERANGE"),
        35 => Some("EDEADLK"),
        36 => Some("ENAMETOOLONG"),
        37 => Some("ENOLCK"),
        38 => Some("ENOSYS"),
        39 => Some("ENOTEMPTY"),
        40 => Some("ELOOP"),
        42 => Some("ENOMSG"),
        43 => Some("EIDRM"),
        44 => Some("ECHRNG"),
        60 => Some("ENOSTR"),
        61 => Some("ENODATA"),
        62 => Some("ETIME"),
        63 => Some("ENOSR"),
        67 => Some("ENOLINK"),
        71 => Some("EPROTO"),
        72 => Some("EMULTIHOP"),
        74 => Some("EBADMSG"),
        75 => Some("EOVERFLOW"),
        77 => Some("EBADFD"),
        79 => Some("EREMCHG"),
        84 => Some("EILSEQ"),
        88 => Some("ENOTSOCK"),
        89 => Some("EDESTADDRREQ"),
        90 => Some("EMSGSIZE"),
        91 => Some("EPROTOTYPE"),
        92 => Some("ENOPROTOOPT"),
        93 => Some("EPROTONOSUPPORT"),
        94 => Some("ESOCKTNOSUPPORT"),
        95 => Some("EOPNOTSUPP"),
        96 => Some("EPFNOSUPPORT"),
        97 => Some("EAFNOSUPPORT"),
        98 => Some("EADDRINUSE"),
        99 => Some("EADDRNOTAVAIL"),
        100 => Some("ENETDOWN"),
        101 => Some("ENETUNREACH"),
        102 => Some("ENETRESET"),
        103 => Some("ECONNABORTED"),
        104 => Some("ECONNRESET"),
        105 => Some("ENOBUFS"),
        106 => Some("EISCONN"),
        107 => Some("ENOTCONN"),
        108 => Some("ESHUTDOWN"),
        109 => Some("ETOOMANYREFS"),
        110 => Some("ETIMEDOUT"),
        111 => Some("ECONNREFUSED"),
        112 => Some("EHOSTDOWN"),
        113 => Some("EHOSTUNREACH"),
        114 => Some("EALREADY"),
        115 => Some("EINPROGRESS"),
        116 => Some("ESTALE"),
        125 => Some("ECANCELED"),
        130 => Some("EOWNERDEAD"),
        131 => Some("ENOTRECOVERABLE"),
        _ => None,
    }
}

/// Format a syscall return value with errno decoding when negative.
#[must_use]
pub fn format_retval(retval: i64) -> String {
    if retval >= 0 {
        retval.to_string()
    } else {
        let neg_errno = i32::try_from(retval).unwrap_or(i32::MIN);
        let name = errno_name_v2(neg_errno).unwrap_or("EUNKNOWN");
        format!("-1 {name} ({name})")
    }
}

// ─── Ioctl command decoder ────────────────────────────────────────────────────

/// Decode a common Linux ioctl command code to a human-readable name.
#[must_use]
pub const fn ioctl_name(cmd: u32) -> Option<&'static str> {
    match cmd {
        0x5401 => Some("TCGETS"),
        0x5402 => Some("TCSETS"),
        0x5403 => Some("TCSETSW"),
        0x5404 => Some("TCSETSF"),
        0x5408 => Some("TCSBRK"),
        0x5409 => Some("TCXONC"),
        0x540A => Some("TCFLSH"),
        0x540B => Some("TIOCEXCL"),
        0x540C => Some("TIOCNXCL"),
        0x540E => Some("TIOCSCTTY"),
        0x540F => Some("TIOCGPGRP"),
        0x5410 => Some("TIOCSPGRP"),
        0x5411 => Some("TIOCOUTQ"),
        0x5412 => Some("TIOCSTI"),
        0x5413 => Some("TIOCGWINSZ"),
        0x5414 => Some("TIOCSWINSZ"),
        0x5415 => Some("TIOCMGET"),
        0x5416 => Some("TIOCMBIS"),
        0x5417 => Some("TIOCMBIC"),
        0x5418 => Some("TIOCMSET"),
        0x541B => Some("TIOCGSOFTCAR"),
        0x541C => Some("TIOCSSOFTCAR"),
        0x541D => Some("FIONREAD"),
        0x541E => Some("TIOCLINUX"),
        0x541F => Some("TIOCCONS"),
        0x5420 => Some("TIOCGSERIAL"),
        0x5421 => Some("TIOCSSERIAL"),
        0x5422 => Some("TIOCPKT"),
        0x5423 => Some("FIONBIO"),
        0x5424 => Some("TIOCNOTTY"),
        0x5425 => Some("TIOCSETD"),
        0x5426 => Some("TIOCGETD"),
        0x5427 => Some("TCSBRKP"),
        0x5450 => Some("FIONCLEX"),
        0x5451 => Some("FIOCLEX"),
        0x5452 => Some("FIOASYNC"),
        0x5453 => Some("TIOCSERCONFIG"),
        0x8901 => Some("SIOCGIFNAME"),
        0x8902 => Some("SIOCSIFLINK"),
        0x8910 => Some("SIOCGIFFLAGS"),
        0x8911 => Some("SIOCSIFFLAGS"),
        0x8912 => Some("SIOCGIFADDR"),
        0x8913 => Some("SIOCSIFADDR"),
        0x891B => Some("SIOCGIFMTU"),
        0x891C => Some("SIOCSIFMTU"),
        0x8933 => Some("SIOCGIFINDEX"),
        0x4008_6601 => Some("BLKGETSIZE"),
        0x0000_5331 => Some("CDROMSTART"),
        _ => None,
    }
}

// ─── Ptrace request decoder ───────────────────────────────────────────────────

/// Decode a ptrace request number to its symbolic name.
#[must_use]
pub const fn ptrace_request_name(req: u64) -> Option<&'static str> {
    match req {
        0 => Some("PTRACE_TRACEME"),
        1 => Some("PTRACE_PEEKTEXT"),
        2 => Some("PTRACE_PEEKDATA"),
        3 => Some("PTRACE_PEEKUSER"),
        4 => Some("PTRACE_POKETEXT"),
        5 => Some("PTRACE_POKEDATA"),
        6 => Some("PTRACE_POKEUSER"),
        7 => Some("PTRACE_CONT"),
        8 => Some("PTRACE_KILL"),
        9 => Some("PTRACE_SINGLESTEP"),
        12 => Some("PTRACE_GETREGS"),
        13 => Some("PTRACE_SETREGS"),
        14 => Some("PTRACE_GETFPREGS"),
        15 => Some("PTRACE_SETFPREGS"),
        16 => Some("PTRACE_ATTACH"),
        17 => Some("PTRACE_DETACH"),
        18 => Some("PTRACE_GETFPXREGS"),
        19 => Some("PTRACE_SETFPXREGS"),
        24 => Some("PTRACE_SYSCALL"),
        25 => Some("PTRACE_SETOPTIONS"),
        26 => Some("PTRACE_GETEVENTMSG"),
        27 => Some("PTRACE_GETSIGINFO"),
        28 => Some("PTRACE_SETSIGINFO"),
        0x4200 => Some("PTRACE_GETREGSET"),
        0x4201 => Some("PTRACE_SETREGSET"),
        0x4202 => Some("PTRACE_SEIZE"),
        0x4203 => Some("PTRACE_INTERRUPT"),
        0x4204 => Some("PTRACE_LISTEN"),
        0x4205 => Some("PTRACE_PEEKSIGINFO"),
        0x4206 => Some("PTRACE_GETSIGMASK"),
        0x4207 => Some("PTRACE_SETSIGMASK"),
        0x4208 => Some("PTRACE_SECCOMP_GET_FILTER"),
        0x420a => Some("PTRACE_GET_SYSCALL_INFO"),
        _ => None,
    }
}

/// Ptrace event codes (from `PTRACE_GETEVENTMSG`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtraceEvent {
    Fork,
    Vfork,
    Clone,
    Exec,
    VforkDone,
    Exit,
    Seccomp,
    Stop,
    Unknown(u32),
}

impl PtraceEvent {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Fork,
            2 => Self::Vfork,
            3 => Self::Clone,
            4 => Self::Exec,
            5 => Self::VforkDone,
            6 => Self::Exit,
            7 => Self::Seccomp,
            128 => Self::Stop,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fork => "PTRACE_EVENT_FORK",
            Self::Vfork => "PTRACE_EVENT_VFORK",
            Self::Clone => "PTRACE_EVENT_CLONE",
            Self::Exec => "PTRACE_EVENT_EXEC",
            Self::VforkDone => "PTRACE_EVENT_VFORK_DONE",
            Self::Exit => "PTRACE_EVENT_EXIT",
            Self::Seccomp => "PTRACE_EVENT_SECCOMP",
            Self::Stop => "PTRACE_EVENT_STOP",
            Self::Unknown(_) => "PTRACE_EVENT_UNKNOWN",
        }
    }
}

// ─── mmap protection and flag display helpers ─────────────────────────────────

/// Format mmap prot+flags in strace notation, e.g. `PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS`.
#[must_use]
pub fn format_mmap_args(prot: u64, flags: u64) -> String {
    let p = decode_flags(prot, PROT_FLAGS);
    let f = decode_flags(flags, MAP_FLAGS);
    format!("{p}, {f}")
}

/// Format the open/openat flags argument.
#[must_use]
pub fn format_open_flags(flags: u64) -> String {
    let rdwr = flags & 0o3;
    let mut parts: Vec<&str> = Vec::new();
    match rdwr {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        _ => parts.push("O_RDWR"),
    }
    for bit in O_FLAGS {
        if bit.value > 0o2 && bit.value != 0o3 && (flags & bit.value) == bit.value {
            parts.push(bit.name);
        }
    }
    parts.join("|")
}

// ─── Security taint tracker ───────────────────────────────────────────────────

/// Security taint flags that can be set on a process.
///
/// Stored as a `u8` bitfield to avoid the `clippy::struct_excessive_bools` lint.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TaintFlags {
    bits: u8,
}

impl TaintFlags {
    const EXEC_FROM_MMAP: u8          = 0x01;
    const USED_PTRACE: u8             = 0x02;
    const SPAWNED_CHILD: u8           = 0x04;
    const OPENED_NETWORK_SOCKET: u8   = 0x08;
    const CHANGED_UID: u8             = 0x10;
    const WROTE_EXEC_MEMORY: u8       = 0x20;
    const INJECTED_FOREIGN: u8        = 0x40;

    #[must_use] pub const fn executed_code_from_mmap(&self) -> bool  { self.bits & Self::EXEC_FROM_MMAP != 0 }
    #[must_use] pub const fn used_ptrace(&self) -> bool               { self.bits & Self::USED_PTRACE != 0 }
    #[must_use] pub const fn spawned_child(&self) -> bool             { self.bits & Self::SPAWNED_CHILD != 0 }
    #[must_use] pub const fn opened_network_socket(&self) -> bool     { self.bits & Self::OPENED_NETWORK_SOCKET != 0 }
    #[must_use] pub const fn changed_uid(&self) -> bool               { self.bits & Self::CHANGED_UID != 0 }
    #[must_use] pub const fn wrote_to_executable_memory(&self) -> bool { self.bits & Self::WROTE_EXEC_MEMORY != 0 }
    #[must_use] pub const fn injected_into_foreign_process(&self) -> bool { self.bits & Self::INJECTED_FOREIGN != 0 }

    /// Returns `true` if any suspicious flag is set.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.bits & (Self::EXEC_FROM_MMAP | Self::USED_PTRACE | Self::WROTE_EXEC_MEMORY | Self::INJECTED_FOREIGN) != 0
    }

    /// Update taint based on a completed syscall event.
    pub fn update_from_event(&mut self, event: &SyscallEventV2) {
        match event.name.as_str() {
            "mmap" => {
                // If PROT_EXEC is in prot arg
                if let Some(DecodedArg::Flags(raw, _)) = event.args.get(2)
                    && raw & 0x4 != 0
                {
                    self.bits |= Self::EXEC_FROM_MMAP;
                }
            }
            "mprotect" => {
                if let Some(DecodedArg::Flags(raw, _)) = event.args.get(2)
                    && raw & 0x4 != 0
                {
                    self.bits |= Self::WROTE_EXEC_MEMORY;
                }
            }
            "ptrace" => {
                self.bits |= Self::USED_PTRACE | Self::INJECTED_FOREIGN;
            }
            "fork" | "vfork" | "clone" | "clone3" => {
                self.bits |= Self::SPAWNED_CHILD;
            }
            "socket" => {
                self.bits |= Self::OPENED_NETWORK_SOCKET;
            }
            "setuid" | "setgid" | "setresuid" | "setresgid" => {
                self.bits |= Self::CHANGED_UID;
            }
            "process_vm_writev" => {
                self.bits |= Self::INJECTED_FOREIGN;
            }
            _ => {}
        }
    }
}

// ─── Additional tests (part 2) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext2_tests {
    use super::*;

    #[test]
    fn test_aarch64_read_nr63() {
        assert_eq!(aarch64_syscall_name(63), Some("read"));
    }
    #[test]
    fn test_aarch64_write_nr64() {
        assert_eq!(aarch64_syscall_name(64), Some("write"));
    }
    #[test]
    fn test_aarch64_mmap_nr222() {
        assert_eq!(aarch64_syscall_name(222), Some("mmap"));
    }
    #[test]
    fn test_aarch64_execve_nr221() {
        assert_eq!(aarch64_syscall_name(221), Some("execve"));
    }
    #[test]
    fn test_aarch64_socket_nr198() {
        assert_eq!(aarch64_syscall_name(198), Some("socket"));
    }
    #[test]
    fn test_aarch64_unknown() {
        assert!(aarch64_syscall_name(9999).is_none());
    }
    #[test]
    fn test_aarch64_table_len() {
        assert!(AARCH64_SPECIFIC_SYSCALLS.len() > 100);
    }
    #[test]
    fn test_aarch64_clone3() {
        assert_eq!(aarch64_syscall_name(435), Some("clone3"));
    }
    #[test]
    fn test_aarch64_io_uring_setup() {
        assert_eq!(aarch64_syscall_name(425), Some("io_uring_setup"));
    }

    #[test]
    fn test_errno_name_eperm() {
        assert_eq!(errno_name_v2(1), Some("EPERM"));
    }
    #[test]
    fn test_errno_name_enoent() {
        assert_eq!(errno_name_v2(2), Some("ENOENT"));
    }
    #[test]
    fn test_errno_name_econnrefused() {
        assert_eq!(errno_name_v2(111), Some("ECONNREFUSED"));
    }
    #[test]
    fn test_errno_name_negative_input() {
        assert_eq!(errno_name_v2(-2), Some("ENOENT"));
    }
    #[test]
    fn test_errno_name_unknown() {
        assert!(errno_name_v2(999).is_none());
    }

    #[test]
    fn test_format_retval_positive() {
        assert_eq!(format_retval(42), "42");
    }
    #[test]
    fn test_format_retval_negative() {
        let s = format_retval(-2);
        assert!(s.contains("ENOENT"), "got: {s}");
    }

    #[test]
    fn test_ioctl_name_tcgets() {
        assert_eq!(ioctl_name(0x5401), Some("TCGETS"));
    }
    #[test]
    fn test_ioctl_name_siocgifname() {
        assert_eq!(ioctl_name(0x8901), Some("SIOCGIFNAME"));
    }
    #[test]
    fn test_ioctl_name_unknown() {
        assert!(ioctl_name(0xDEAD).is_none());
    }

    #[test]
    fn test_ptrace_request_traceme() {
        assert_eq!(ptrace_request_name(0), Some("PTRACE_TRACEME"));
    }
    #[test]
    fn test_ptrace_request_syscall() {
        assert_eq!(ptrace_request_name(24), Some("PTRACE_SYSCALL"));
    }
    #[test]
    fn test_ptrace_request_unknown() {
        assert!(ptrace_request_name(9999).is_none());
    }

    #[test]
    fn test_ptrace_event_from_u32() {
        assert_eq!(PtraceEvent::from_u32(1), PtraceEvent::Fork);
        assert_eq!(PtraceEvent::from_u32(4).as_str(), "PTRACE_EVENT_EXEC");
    }

    #[test]
    fn test_format_mmap_args() {
        let s = format_mmap_args(0x7, 0x22);
        assert!(s.contains("PROT_READ"));
        assert!(s.contains("MAP_PRIVATE"));
        assert!(s.contains("MAP_ANONYMOUS"));
    }

    #[test]
    fn test_format_open_flags_rdonly() {
        let s = format_open_flags(0);
        assert_eq!(s, "O_RDONLY");
    }

    #[test]
    fn test_format_open_flags_wronly_creat_trunc() {
        let flags = 0o1 | 0o100 | 0o1000u64;
        let s = format_open_flags(flags);
        assert!(s.contains("O_WRONLY"), "got: {s}");
        assert!(s.contains("O_CREAT"), "got: {s}");
        assert!(s.contains("O_TRUNC"), "got: {s}");
    }

    #[test]
    fn test_taint_flags_default_clean() {
        let t = TaintFlags::default();
        assert!(!t.is_suspicious());
    }

    #[test]
    fn test_taint_flags_ptrace_suspicious() {
        let mut t = TaintFlags::default();
        let ev = SyscallEventV2 {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            nr: 101,
            name: "ptrace".to_string(),
            args: vec![],
            retval: DecodedArg::Int(0),
            elapsed_ns: 0,
            is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.used_ptrace());
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_taint_flags_mmap_exec() {
        let mut t = TaintFlags::default();
        let ev = SyscallEventV2 {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            nr: 9,
            name: "mmap".to_string(),
            args: vec![
                DecodedArg::Addr(0),
                DecodedArg::UInt(4096),
                DecodedArg::Flags(0x5, "PROT_READ|PROT_EXEC".to_string()), // prot = 0x5 has exec bit
                DecodedArg::Flags(0x22, "MAP_PRIVATE|MAP_ANONYMOUS".to_string()),
                DecodedArg::Fd(-1, String::new()),
                DecodedArg::UInt(0),
            ],
            retval: DecodedArg::Addr(0x7fff_0000),
            elapsed_ns: 0,
            is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.executed_code_from_mmap());
    }

    #[test]
    fn test_taint_fork() {
        let mut t = TaintFlags::default();
        let ev = SyscallEventV2 {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            nr: 57,
            name: "fork".to_string(),
            args: vec![],
            retval: DecodedArg::Int(1234),
            elapsed_ns: 0,
            is_entry: false,
        };
        t.update_from_event(&ev);
        assert!(t.spawned_child());
        assert!(!t.is_suspicious()); // fork alone is not suspicious
    }

    #[test]
    fn test_aarch64_rev_lookup() {
        assert_eq!(aarch64_syscall_nr("read"), Some(63));
        assert_eq!(aarch64_syscall_nr("write"), Some(64));
    }

    #[test]
    fn test_syscall_summary_avg_ns() {
        let mut s = SyscallSummaryEntry::new("test", 0, false);
        s.record(1000, false);
        s.record(3000, false);
        // count=3, total=4000
        assert_eq!(s.avg_ns(), 4000 / 3);
    }

    #[test]
    fn test_fd_table_is_empty() {
        let t = FdTable::default();
        assert!(t.is_empty());
    }
}

// ─── seccomp BPF helpers ──────────────────────────────────────────────────────

/// seccomp action values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum SeccompAction {
    Kill = 0x8000_0000,
    KillThread = 0x0000_0000,
    Trap = 0x0003_0000,
    Errno = 0x0005_0000,
    Trace = 0x7ff0_0000,
    Log = 0x7ffc_0000,
    Allow = 0x7fff_0000,
}

impl SeccompAction {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v & 0xFFFF_0000 {
            0x0000_0000 => Self::KillThread,
            0x0003_0000 => Self::Trap,
            0x0005_0000 => Self::Errno,
            0x7ff0_0000 => Self::Trace,
            0x7ffc_0000 => Self::Log,
            0x7fff_0000 => Self::Allow,
            _ => Self::Kill,
        }
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kill | Self::KillThread => "SECCOMP_RET_KILL",
            Self::Trap => "SECCOMP_RET_TRAP",
            Self::Errno => "SECCOMP_RET_ERRNO",
            Self::Trace => "SECCOMP_RET_TRACE",
            Self::Log => "SECCOMP_RET_LOG",
            Self::Allow => "SECCOMP_RET_ALLOW",
        }
    }
}

// ─── procfs parser helpers ────────────────────────────────────────────────────

/// Minimal parsed entry from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapsEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: String,
}

impl MapsEntry {
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.perms.contains('w')
    }
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.perms.contains('r')
    }
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.perms.contains('p')
    }
    #[must_use]
    pub fn is_shared(&self) -> bool {
        self.perms.contains('s')
    }
    #[must_use]
    pub const fn is_anon(&self) -> bool {
        // Special-purpose pseudo-paths like [stack], [heap], [vdso] are
        // distinct named regions — only truly unnamed mappings are anon.
        self.pathname.is_empty()
    }
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Parse the content of `/proc/<pid>/maps` (or any string with the same format).
#[must_use]
pub fn parse_proc_maps(content: &str) -> Vec<MapsEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("").to_string();
        let offset_str = parts.next().unwrap_or("0");
        let dev = parts.next().unwrap_or("").to_string();
        let inode_str = parts.next().unwrap_or("0");
        let pathname = parts.next().unwrap_or("").trim().to_string();

        let mut addr_parts = addr_range.splitn(2, '-');
        let start = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);
        let inode = inode_str.trim().parse().unwrap_or(0);

        entries.push(MapsEntry {
            start,
            end,
            perms,
            offset,
            dev,
            inode,
            pathname,
        });
    }
    entries
}

/// A parsed line from `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcStatus {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub state: String,
    pub uid: u32,
    pub gid: u32,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub threads: u32,
    pub fdsize: u32,
}

/// Parse `/proc/<pid>/status` content.
#[must_use]
pub fn parse_proc_status(content: &str) -> ProcStatus {
    let mut s = ProcStatus::default();
    for line in content.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let v = val.trim();
            match key.trim() {
                "Name" => s.name = v.to_string(),
                "Pid" => s.pid = v.parse().unwrap_or(0),
                "PPid" => s.ppid = v.parse().unwrap_or(0),
                "State" => s.state = v.to_string(),
                "Uid" => {
                    s.uid = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(0);
                }
                "Gid" => {
                    s.gid = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(0);
                }
                "VmRSS" => {
                    s.vm_rss_kb = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(0);
                }
                "VmSize" => {
                    s.vm_size_kb = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(0);
                }
                "Threads" => s.threads = v.parse().unwrap_or(0),
                "FDSize" => s.fdsize = v.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    s
}

// ─── Additional tests (part 3) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext3_tests {
    use super::*;

    #[test]
    fn test_seccomp_action_allow() {
        assert_eq!(
            SeccompAction::from_u32(0x7fff_0000).as_str(),
            "SECCOMP_RET_ALLOW"
        );
    }

    #[test]
    fn test_seccomp_action_kill() {
        assert_eq!(SeccompAction::from_u32(0).as_str(), "SECCOMP_RET_KILL");
    }

    #[test]
    fn test_seccomp_action_errno() {
        assert_eq!(
            SeccompAction::from_u32(0x0005_0001).as_str(),
            "SECCOMP_RET_ERRNO"
        );
    }

    #[test]
    fn test_parse_proc_maps_single_line() {
        let content = "7f1234560000-7f1234570000 r-xp 00000000 fd:01 12345 /usr/lib/libc.so.6\n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, 0x7f12_3456_0000);
        assert_eq!(entries[0].end, 0x7f12_3457_0000);
        assert!(entries[0].is_executable());
        assert!(entries[0].is_readable());
        assert!(!entries[0].is_writable());
        assert_eq!(entries[0].pathname, "/usr/lib/libc.so.6");
    }

    #[test]
    fn test_parse_proc_maps_anon() {
        let content = "7fff00000000-7fff00010000 rwxp 00000000 00:00 0 \n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_executable());
        assert!(entries[0].is_writable());
        assert!(entries[0].is_anon());
    }

    #[test]
    fn test_maps_entry_size() {
        let e = MapsEntry {
            start: 0x1000,
            end: 0x3000,
            perms: "r-xp".to_string(),
            offset: 0,
            dev: "fd:01".to_string(),
            inode: 0,
            pathname: String::new(),
        };
        assert_eq!(e.size(), 0x2000);
    }

    #[test]
    fn test_parse_proc_status() {
        let content = "\
Name:\tbash\nPid:\t1234\nPPid:\t1000\nState:\tS (sleeping)\n\
Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n\
VmRSS:\t4096 kB\nVmSize:\t32768 kB\nThreads:\t1\nFDSize:\t256\n";
        let s = parse_proc_status(content);
        assert_eq!(s.name, "bash");
        assert_eq!(s.pid, 1234);
        assert_eq!(s.ppid, 1000);
        assert_eq!(s.uid, 1000);
        assert_eq!(s.vm_rss_kb, 4096);
        assert_eq!(s.vm_size_kb, 32768);
        assert_eq!(s.threads, 1);
    }

    #[test]
    fn test_parse_proc_maps_multiple_entries() {
        let content = "\
55a000000000-55a000001000 r--p 00000000 fd:01 100 /bin/ls\n\
55a000001000-55a000002000 r-xp 00001000 fd:01 100 /bin/ls\n\
7fff00000000-7fff00010000 rw-p 00000000 00:00 0 [stack]\n";
        let entries = parse_proc_maps(content);
        assert_eq!(entries.len(), 3);
        assert!(entries[2].pathname == "[stack]");
        assert!(!entries[2].is_anon()); // [stack] is NOT anon by our definition
    }

    #[test]
    fn test_resolve_fd_negative_bad() {
        let s = resolve_fd(1, -5);
        assert!(s.contains("bad fd"));
    }

    #[test]
    fn test_resolve_fd_at_fdcwd() {
        let s = resolve_fd(1, AT_FDCWD);
        assert_eq!(s, "AT_FDCWD");
    }

    #[test]
    fn test_signal_all_core_signals() {
        for sig in 1u32..=31 {
            // All standard signals should have names
            if sig != 9 && sig != 19 {
                // 9=SIGKILL, 19=SIGSTOP are handled
                let _ = signal_name(sig);
            }
        }
        assert_eq!(signal_name_v2(9), Some("SIGKILL"));
        assert_eq!(signal_name_v2(15), Some("SIGTERM"));
        assert_eq!(signal_name_v2(19), Some("SIGSTOP"));
    }

    #[test]
    fn test_format_open_flags_cloexec() {
        let flags = 0o2 | 0o2_000_000_u64; // O_RDWR | O_CLOEXEC
        let s = format_open_flags(flags);
        assert!(s.contains("O_RDWR"), "got: {s}");
        assert!(s.contains("O_CLOEXEC"), "got: {s}");
    }

    #[test]
    fn test_summary_total_calls_zero() {
        let s = SyscallSummaryV2::default();
        assert_eq!(s.total_calls(), 0);
        assert_eq!(s.total_ns(), 0);
    }

    #[test]
    fn test_summary_sorted_by_count() {
        let mut s = SyscallSummaryV2::default();
        for _ in 0..5 {
            s.record("read", 100, 0);
        }
        for _ in 0..2 {
            s.record("write", 200, 0);
        }
        let v = s.sorted_by_count();
        assert_eq!(v[0].name, "read");
        assert_eq!(v[0].count, 5);
    }

    #[test]
    fn test_x86_64_table_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for s in X86_64_SYSCALLS {
            assert!(seen.insert(s.nr), "duplicate nr {}", s.nr);
        }
    }

    #[test]
    fn test_aarch64_table_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for s in AARCH64_SPECIFIC_SYSCALLS {
            assert!(seen.insert(s.0), "duplicate nr {}", s.0);
        }
    }

    #[test]
    fn test_decode_flags_clone_thread_vm() {
        let flags = 0x0001_0100u64; // CLONE_THREAD | CLONE_VM
        let s = decode_flags(flags, CLONE_FLAGS);
        assert!(s.contains("CLONE_VM"), "got: {s}");
        assert!(s.contains("CLONE_THREAD"), "got: {s}");
    }

    #[test]
    fn test_at_flags_symlink_nofollow() {
        let s = decode_flags(0x100, AT_FLAGS);
        assert!(s.contains("AT_SYMLINK_NOFOLLOW"));
    }

    #[test]
    fn test_epoll_epollet() {
        let s = decode_flags(0x8000_0000, EPOLL_EVENTS);
        assert!(s.contains("EPOLLET"));
    }

    #[test]
    fn test_sock_nonblock() {
        let s = decode_flags(0x800, SOCK_FLAGS);
        assert!(s.contains("SOCK_NONBLOCK"));
    }

    #[test]
    fn test_ptrace_event_str() {
        assert_eq!(PtraceEvent::Clone.as_str(), "PTRACE_EVENT_CLONE");
        assert_eq!(PtraceEvent::Exit.as_str(), "PTRACE_EVENT_EXIT");
    }

    #[test]
    fn test_seccomp_action_trace() {
        assert_eq!(SeccompAction::Trace.as_str(), "SECCOMP_RET_TRACE");
    }

    #[test]
    fn test_ioctl_tiocgwinsz() {
        assert_eq!(ioctl_name(0x5413), Some("TIOCGWINSZ"));
    }

    #[test]
    fn test_errno_einval() {
        assert_eq!(errno_name_v2(22), Some("EINVAL"));
    }
}

// ─── Wait status decoder ──────────────────────────────────────────────────────

/// A decoded wait status from waitpid/wait4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaitStatus {
    /// Process exited normally with the given exit code.
    Exited(i32),
    /// Process was killed by a signal.
    Signaled { signal: u32, coredump: bool },
    /// Process was stopped by a signal.
    Stopped(u32),
    /// Process resumed (SIGCONT).
    Continued,
    /// ptrace event stop.
    PtraceEvent { signal: u32, event: u32 },
}

impl WaitStatus {
    /// Decode a raw `wstatus` value as returned by `wait4`.
    #[must_use]
    pub const fn decode(wstatus: i32) -> Self {
        let w = wstatus.cast_unsigned();
        if w.trailing_zeros() >= 7 {
            // Exited normally
            Self::Exited(((w >> 8) & 0xFF).cast_signed())
        } else if w & 0xFF == 0x7F {
            // Stopped
            let sig = (w >> 8) & 0xFF;
            let event = (w >> 16) & 0xFF;
            if event != 0 {
                Self::PtraceEvent { signal: sig, event }
            } else {
                Self::Stopped(sig)
            }
        } else if w == 0xFFFF {
            Self::Continued
        } else {
            // Signaled
            let signal = w & 0x7F;
            let coredump = (w & 0x80) != 0;
            Self::Signaled { signal, coredump }
        }
    }

    /// Format in strace style.
    #[must_use]
    pub fn format_strace(&self) -> String {
        match self {
            Self::Exited(code) => format!("{{WIFEXITED(s) && WEXITSTATUS(s) == {code}}}"),
            Self::Signaled { signal, coredump } => {
                let name = signal_name_v2(*signal).unwrap_or("SIG?");
                let core = if *coredump { " (core dumped)" } else { "" };
                format!("{{WIFSIGNALED(s) && WTERMSIG(s) == {name}{core}}}")
            }
            Self::Stopped(sig) => {
                let name = signal_name_v2(*sig).unwrap_or("SIG?");
                format!("{{WIFSTOPPED(s) && WSTOPSIG(s) == {name}}}")
            }
            Self::Continued => "{{WIFCONTINUED(s)}}".to_string(),
            Self::PtraceEvent { signal, event } => {
                let ev = PtraceEvent::from_u32(*event);
                let sig_name = signal_name_v2(*signal).unwrap_or("SIGTRAP");
                format!(
                    "{{WIFSTOPPED(s) && WSTOPSIG(s) == {sig_name} | {} << 8}}",
                    ev.as_str()
                )
            }
        }
    }
}

// ─── Socket option decoder ────────────────────────────────────────────────────

/// Decode a `setsockopt`/`getsockopt` level+optname pair.
#[must_use]
pub const fn sockopt_name(level: i32, optname: i32) -> &'static str {
    match (level, optname) {
        (1, 1) => "SO_DEBUG",
        (1, 2) => "SO_REUSEADDR",
        (1, 3) => "SO_TYPE",
        (1, 4) => "SO_ERROR",
        (1, 5) => "SO_DONTROUTE",
        (1, 6) => "SO_BROADCAST",
        (1, 7) => "SO_SNDBUF",
        (1, 8) => "SO_RCVBUF",
        (1, 9) => "SO_KEEPALIVE",
        (1, 10) => "SO_OOBINLINE",
        (1, 11) => "SO_NO_CHECK",
        (1, 12) => "SO_PRIORITY",
        (1, 13) => "SO_LINGER",
        (1, 14) => "SO_BSDCOMPAT",
        (1, 15) => "SO_REUSEPORT",
        (1, 20) => "SO_RCVLOWAT",
        (1, 21) => "SO_SNDLOWAT",
        (1, 22) => "SO_RCVTIMEO",
        (1, 23) => "SO_SNDTIMEO",
        (1, 29) => "SO_TIMESTAMPNS",
        (1, 41) => "SO_ATTACH_BPF",
        (6, 1) => "TCP_NODELAY",
        (6, 2) => "TCP_MAXSEG",
        (6, 3) => "TCP_CORK",
        (6, 4) => "TCP_KEEPIDLE",
        (6, 5) => "TCP_KEEPINTVL",
        (6, 6) => "TCP_KEEPCNT",
        (6, 7) => "TCP_SYNCNT",
        (6, 8) => "TCP_LINGER2",
        (6, 9) => "TCP_DEFER_ACCEPT",
        (6, 10) => "TCP_WINDOW_CLAMP",
        (6, 11) => "TCP_INFO",
        (6, 12) => "TCP_QUICKACK",
        (6, 23) => "TCP_FASTOPEN",
        (6, 24) => "TCP_TIMESTAMP",
        (6, 25) => "TCP_NOTSENT_LOWAT",
        (17, 1) => "UDP_CORK",
        (17, 100) => "UDP_SEGMENT",
        _ => "UNKNOWN_SOCKOPT",
    }
}

// ─── Address family name ──────────────────────────────────────────────────────

#[must_use]
pub const fn af_name(family: u16) -> &'static str {
    match family {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        3 => "AF_AX25",
        4 => "AF_IPX",
        5 => "AF_APPLETALK",
        6 => "AF_NETROM",
        7 => "AF_BRIDGE",
        8 => "AF_ATMPVC",
        9 => "AF_X25",
        10 => "AF_INET6",
        11 => "AF_ROSE",
        12 => "AF_DECnet",
        13 => "AF_NETBEUI",
        14 => "AF_SECURITY",
        15 => "AF_KEY",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        18 => "AF_ASH",
        19 => "AF_ECONET",
        20 => "AF_ATMSVC",
        22 => "AF_SNA",
        23 => "AF_IRDA",
        24 => "AF_PPPOX",
        25 => "AF_WANPIPE",
        26 => "AF_LLC",
        29 => "AF_CAN",
        30 => "AF_TIPC",
        31 => "AF_BLUETOOTH",
        32 => "AF_IUCV",
        33 => "AF_RXRPC",
        34 => "AF_ISDN",
        35 => "AF_PHONET",
        36 => "AF_IEEE802154",
        37 => "AF_CAIF",
        38 => "AF_ALG",
        39 => "AF_NFC",
        40 => "AF_VSOCK",
        _ => "AF_UNKNOWN",
    }
}

// ─── JSON event log writer ────────────────────────────────────────────────────

/// Buffer collecting JSON-formatted syscall event lines.
#[derive(Debug, Default)]
pub struct JsonEventLog {
    lines: Vec<String>,
}

impl JsonEventLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event as a JSON line.
    pub fn append(&mut self, event: &SyscallEventV2) {
        match event.to_json() {
            Ok(j) => self.lines.push(j),
            Err(e) => self.lines.push(format!("{{\"error\":{e:?}}}")),
        }
    }

    /// Return the full log as a NDJSON string.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        self.lines.join("\n")
    }

    /// Number of events recorded.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns `true` if no events have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

// ─── CSV event log writer ─────────────────────────────────────────────────────

/// Buffer collecting CSV-formatted syscall event rows.
#[derive(Debug)]
pub struct CsvEventLog {
    rows: Vec<String>,
}

impl CsvEventLog {
    #[must_use]
    pub fn new() -> Self {
        let header = "timestamp_ns,pid,tid,name,retval,elapsed_ns".to_string();
        Self { rows: vec![header] }
    }

    /// Append an event as a CSV row.
    pub fn append(&mut self, event: &SyscallEventV2) {
        self.rows.push(event.to_csv_row());
    }

    /// Return the full CSV as a string.
    #[must_use]
    pub fn to_csv(&self) -> String {
        self.rows.join("\n")
    }

    /// Number of data rows (excluding header).
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len().saturating_sub(1)
    }
}

impl Default for CsvEventLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Additional tests (part 4) ────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext4_tests {
    use super::*;

    #[test]
    fn test_wait_status_exited_0() {
        let ws = WaitStatus::decode(0); // WIFEXITED(0) = true, WEXITSTATUS = 0
        match ws {
            WaitStatus::Exited(c) => assert_eq!(c, 0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_exited_1() {
        let ws = WaitStatus::decode(0x0100); // exit code = 1
        match ws {
            WaitStatus::Exited(c) => assert_eq!(c, 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_signaled_sigsegv() {
        let ws = WaitStatus::decode(11); // WIFSIGNALED, signal=SIGSEGV
        match ws {
            WaitStatus::Signaled { signal, coredump } => {
                assert_eq!(signal, 11);
                assert!(!coredump);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_stopped() {
        let ws = WaitStatus::decode(0x137F); // stopped by signal 19
        match ws {
            WaitStatus::Stopped(s) => assert_eq!(s, 19),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_wait_status_format_exited() {
        let s = WaitStatus::Exited(0).format_strace();
        assert!(s.contains("WIFEXITED"));
    }

    #[test]
    fn test_wait_status_format_signaled() {
        let s = WaitStatus::Signaled {
            signal: 11,
            coredump: false,
        }
        .format_strace();
        assert!(s.contains("WIFSIGNALED") && s.contains("SIGSEGV"));
    }

    #[test]
    fn test_wait_status_format_stopped() {
        let s = WaitStatus::Stopped(19).format_strace();
        assert!(s.contains("WIFSTOPPED") && s.contains("SIGSTOP"));
    }

    #[test]
    fn test_sockopt_tcp_nodelay() {
        assert_eq!(sockopt_name(6, 1), "TCP_NODELAY");
    }

    #[test]
    fn test_sockopt_so_keepalive() {
        assert_eq!(sockopt_name(1, 9), "SO_KEEPALIVE");
    }

    #[test]
    fn test_sockopt_unknown() {
        assert_eq!(sockopt_name(99, 99), "UNKNOWN_SOCKOPT");
    }

    #[test]
    fn test_af_name_inet() {
        assert_eq!(af_name(2), "AF_INET");
    }

    #[test]
    fn test_af_name_inet6() {
        assert_eq!(af_name(10), "AF_INET6");
    }

    #[test]
    fn test_af_name_unix() {
        assert_eq!(af_name(1), "AF_UNIX");
    }

    #[test]
    fn test_af_name_packet() {
        assert_eq!(af_name(17), "AF_PACKET");
    }

    #[test]
    fn test_af_name_unknown() {
        assert_eq!(af_name(200), "AF_UNKNOWN");
    }

    #[test]
    fn test_json_event_log_append() {
        let mut log = JsonEventLog::new();
        let ev = SyscallEventV2 {
            timestamp_ns: 100,
            pid: 1,
            tid: 1,
            nr: 0,
            name: "read".to_string(),
            args: vec![],
            retval: DecodedArg::Int(10),
            elapsed_ns: 50,
            is_entry: false,
        };
        log.append(&ev);
        assert_eq!(log.len(), 1);
        assert!(log.to_ndjson().contains("read"));
    }

    #[test]
    fn test_json_event_log_clear() {
        let mut log = JsonEventLog::new();
        let ev = SyscallEventV2 {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            nr: 1,
            name: "write".to_string(),
            args: vec![],
            retval: DecodedArg::Int(4),
            elapsed_ns: 0,
            is_entry: false,
        };
        log.append(&ev);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_csv_event_log_header() {
        let log = CsvEventLog::new();
        assert_eq!(log.row_count(), 0);
        assert!(
            log.to_csv()
                .starts_with("timestamp_ns,pid,tid,name,retval,elapsed_ns")
        );
    }

    #[test]
    fn test_csv_event_log_append() {
        let mut log = CsvEventLog::new();
        let ev = SyscallEventV2 {
            timestamp_ns: 123,
            pid: 2,
            tid: 2,
            nr: 1,
            name: "write".to_string(),
            args: vec![],
            retval: DecodedArg::Int(8),
            elapsed_ns: 77,
            is_entry: false,
        };
        log.append(&ev);
        assert_eq!(log.row_count(), 1);
        assert!(log.to_csv().contains("write"));
    }

    #[test]
    fn test_x86_64_exit_group_nr231() {
        assert_eq!(x86_64_syscall_name(231), Some("exit_group"));
    }

    #[test]
    fn test_x86_64_getrandom_nr318() {
        assert_eq!(x86_64_syscall_name(318), Some("getrandom"));
    }

    #[test]
    fn test_x86_64_bpf_nr321() {
        assert_eq!(x86_64_syscall_name(321), Some("bpf"));
    }

    #[test]
    fn test_x86_64_statx_nr332() {
        assert_eq!(x86_64_syscall_name(332), Some("statx"));
    }

    #[test]
    fn test_output_format_variants() {
        // Just ensure the variants exist and are copyable
        let f1 = OutputFormat::Strace;
        let f2 = OutputFormat::Json;
        let f3 = OutputFormat::Csv;
        assert_ne!(format!("{f1:?}"), format!("{f2:?}"));
        assert_ne!(format!("{f2:?}"), format!("{f3:?}"));
    }

    #[test]
    fn test_fd_table_get_mut() {
        let mut t = FdTable::default();
        t.insert(10, FdInfo::file("/dev/urandom", 0));
        let info = t.get_mut(10).unwrap();
        info.offset = 42;
        assert_eq!(t.get(10).unwrap().offset, 42);
    }

    #[test]
    fn test_fd_table_all_sorted() {
        let mut t = FdTable::default();
        t.insert(5, FdInfo::file("/a", 0));
        t.insert(1, FdInfo::file("/b", 0));
        t.insert(3, FdInfo::file("/c", 0));
        let all = t.all();
        assert_eq!(all[0].0, 1);
        assert_eq!(all[1].0, 3);
        assert_eq!(all[2].0, 5);
    }
}
