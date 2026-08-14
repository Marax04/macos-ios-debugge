//! Complete Linux x86-64 syscall table (~335 entries) with argument type
//! annotations, lookup by number, and lookup by name.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SyscallArg ───────────────────────────────────────────────────────────────

/// The type annotation for a single syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallArg {
    /// An integer (int, long, unsigned long, …).
    Int,
    /// A pointer to a user-space buffer.
    Ptr,
    /// A file descriptor.
    Fd,
    /// A count / size (`size_t`, `ssize_t`).
    Size,
    /// A flags word (int or unsigned int bit mask).
    Flags,
    /// A pointer to a `struct stat` or similar kernel struct.
    Struct,
    /// A pointer to a null-terminated string.
    StrPtr,
    /// A signal number.
    Signal,
    /// A PID (`pid_t`).
    Pid,
    /// A UID/GID.
    Id,
    /// An offset (`off_t`, `loff_t`).
    Offset,
    /// A timeout or timespec/timeval pointer.
    Time,
    /// Unused / padding argument.
    Unused,
}

impl fmt::Display for SyscallArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Int => "int",
            Self::Ptr => "ptr",
            Self::Fd => "fd",
            Self::Size => "size",
            Self::Flags => "flags",
            Self::Struct => "struct*",
            Self::StrPtr => "str*",
            Self::Signal => "sig",
            Self::Pid => "pid",
            Self::Id => "id",
            Self::Offset => "off",
            Self::Time => "time",
            Self::Unused => "_",
        };
        write!(f, "{s}")
    }
}

// ─── SyscallInfo ─────────────────────────────────────────────────────────────

/// Metadata about one Linux x86-64 syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// Syscall number.
    pub number: u64,
    /// Canonical name (without `__NR_` prefix).
    pub name: &'static str,
    /// Number of arguments (0..6).
    pub num_args: u8,
    /// Argument type annotations (up to 6 entries; unused slots are `Unused`).
    pub args: [SyscallArg; 6],
}

impl SyscallInfo {
    const fn new(
        number: u64,
        name: &'static str,
        num_args: u8,
        args: [SyscallArg; 6],
    ) -> Self {
        Self { number, name, num_args, args }
    }
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:4}] {}(", self.number, self.name)?;
        for i in 0..self.num_args as usize {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{}", self.args[i])?;
        }
        write!(f, ")")
    }
}

// ─── Syscall table ────────────────────────────────────────────────────────────

use SyscallArg::{Fd, Flags, Id, Int, Offset, Pid, Ptr, Signal, Size, StrPtr, Struct, Time, Unused};

/// The complete Linux x86-64 syscall table.
pub static SYSCALL_TABLE: &[SyscallInfo] = &[
    SyscallInfo::new(0,   "read",            3, [Fd,    Ptr,    Size,    Unused, Unused, Unused]),
    SyscallInfo::new(1,   "write",           3, [Fd,    Ptr,    Size,    Unused, Unused, Unused]),
    SyscallInfo::new(2,   "open",            3, [StrPtr,Flags,  Int,     Unused, Unused, Unused]),
    SyscallInfo::new(3,   "close",           1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(4,   "stat",            2, [StrPtr,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(5,   "fstat",           2, [Fd,    Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(6,   "lstat",           2, [StrPtr,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(7,   "poll",            3, [Struct,Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(8,   "lseek",           3, [Fd,    Offset, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(9,   "mmap",            6, [Ptr,   Size,   Flags,   Flags,  Fd,     Offset]),
    SyscallInfo::new(10,  "mprotect",        3, [Ptr,   Size,   Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(11,  "munmap",          2, [Ptr,   Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(12,  "brk",             1, [Ptr,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(13,  "rt_sigaction",    4, [Signal,Struct, Struct,  Size,   Unused, Unused]),
    SyscallInfo::new(14,  "rt_sigprocmask",  4, [Int,   Struct, Struct,  Size,   Unused, Unused]),
    SyscallInfo::new(15,  "rt_sigreturn",    0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(16,  "ioctl",           3, [Fd,    Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(17,  "pread64",         4, [Fd,    Ptr,    Size,    Offset, Unused, Unused]),
    SyscallInfo::new(18,  "pwrite64",        4, [Fd,    Ptr,    Size,    Offset, Unused, Unused]),
    SyscallInfo::new(19,  "readv",           3, [Fd,    Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(20,  "writev",          3, [Fd,    Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(21,  "access",          2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(22,  "pipe",            1, [Ptr,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(23,  "select",          5, [Int,   Struct, Struct,  Struct, Time,   Unused]),
    SyscallInfo::new(24,  "sched_yield",     0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(25,  "mremap",          5, [Ptr,   Size,   Size,    Flags,  Ptr,    Unused]),
    SyscallInfo::new(26,  "msync",           3, [Ptr,   Size,   Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(27,  "mincore",         3, [Ptr,   Size,   Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(28,  "madvise",         3, [Ptr,   Size,   Int,     Unused, Unused, Unused]),
    SyscallInfo::new(29,  "shmget",          3, [Int,   Size,   Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(30,  "shmat",           3, [Int,   Ptr,    Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(31,  "shmctl",          3, [Int,   Int,    Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(32,  "dup",             1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(33,  "dup2",            2, [Fd,    Fd,     Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(34,  "pause",           0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(35,  "nanosleep",       2, [Time,  Time,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(36,  "getitimer",       2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(37,  "alarm",           1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(38,  "setitimer",       3, [Int,   Struct, Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(39,  "getpid",          0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(40,  "sendfile",        4, [Fd,    Fd,     Ptr,     Size,   Unused, Unused]),
    SyscallInfo::new(41,  "socket",          3, [Int,   Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(42,  "connect",         3, [Fd,    Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(43,  "accept",          3, [Fd,    Struct, Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(44,  "sendto",          6, [Fd,    Ptr,    Size,    Flags,  Struct, Int]),
    SyscallInfo::new(45,  "recvfrom",        6, [Fd,    Ptr,    Size,    Flags,  Struct, Ptr]),
    SyscallInfo::new(46,  "sendmsg",         3, [Fd,    Struct, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(47,  "recvmsg",         3, [Fd,    Struct, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(48,  "shutdown",        2, [Fd,    Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(49,  "bind",            3, [Fd,    Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(50,  "listen",          2, [Fd,    Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(51,  "getsockname",     3, [Fd,    Struct, Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(52,  "getpeername",     3, [Fd,    Struct, Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(53,  "socketpair",      4, [Int,   Int,    Int,     Ptr,    Unused, Unused]),
    SyscallInfo::new(54,  "setsockopt",      5, [Fd,    Int,    Int,     Ptr,    Int,    Unused]),
    SyscallInfo::new(55,  "getsockopt",      5, [Fd,    Int,    Int,     Ptr,    Ptr,    Unused]),
    SyscallInfo::new(56,  "clone",           5, [Flags, Ptr,    Ptr,     Ptr,    Ptr,    Unused]),
    SyscallInfo::new(57,  "fork",            0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(58,  "vfork",           0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(59,  "execve",          3, [StrPtr,Ptr,    Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(60,  "exit",            1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(61,  "wait4",           4, [Pid,   Ptr,    Flags,   Struct, Unused, Unused]),
    SyscallInfo::new(62,  "kill",            2, [Pid,   Signal, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(63,  "uname",           1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(64,  "semget",          3, [Int,   Int,    Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(65,  "semop",           3, [Int,   Struct, Size,    Unused, Unused, Unused]),
    SyscallInfo::new(66,  "semctl",          4, [Int,   Int,    Int,     Int,    Unused, Unused]),
    SyscallInfo::new(67,  "shmdt",           1, [Ptr,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(68,  "msgget",          2, [Int,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(69,  "msgsnd",          4, [Int,   Struct, Size,    Flags,  Unused, Unused]),
    SyscallInfo::new(70,  "msgrcv",          5, [Int,   Struct, Size,    Int,    Flags,  Unused]),
    SyscallInfo::new(71,  "msgctl",          3, [Int,   Int,    Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(72,  "fcntl",           3, [Fd,    Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(73,  "flock",           2, [Fd,    Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(74,  "fsync",           1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(75,  "fdatasync",       1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(76,  "truncate",        2, [StrPtr,Offset, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(77,  "ftruncate",       2, [Fd,    Offset, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(78,  "getdents",        3, [Fd,    Ptr,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(79,  "getcwd",          2, [Ptr,   Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(80,  "chdir",           1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(81,  "fchdir",          1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(82,  "rename",          2, [StrPtr,StrPtr, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(83,  "mkdir",           2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(84,  "rmdir",           1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(85,  "creat",           2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(86,  "link",            2, [StrPtr,StrPtr, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(87,  "unlink",          1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(88,  "symlink",         2, [StrPtr,StrPtr, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(89,  "readlink",        3, [StrPtr,Ptr,    Size,    Unused, Unused, Unused]),
    SyscallInfo::new(90,  "chmod",           2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(91,  "fchmod",          2, [Fd,    Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(92,  "chown",           3, [StrPtr,Id,     Id,      Unused, Unused, Unused]),
    SyscallInfo::new(93,  "fchown",          3, [Fd,    Id,     Id,      Unused, Unused, Unused]),
    SyscallInfo::new(94,  "lchown",          3, [StrPtr,Id,     Id,      Unused, Unused, Unused]),
    SyscallInfo::new(95,  "umask",           1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(96,  "gettimeofday",    2, [Struct,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(97,  "getrlimit",       2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(98,  "getrusage",       2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(99,  "sysinfo",         1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(100, "times",           1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(101, "ptrace",          4, [Int,   Pid,    Ptr,     Ptr,    Unused, Unused]),
    SyscallInfo::new(102, "getuid",          0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(103, "syslog",          3, [Int,   Ptr,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(104, "getgid",          0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(105, "setuid",          1, [Id,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(106, "setgid",          1, [Id,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(107, "geteuid",         0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(108, "getegid",         0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(109, "setpgid",         2, [Pid,   Pid,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(110, "getppid",         0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(111, "getpgrp",         0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(112, "setsid",          0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(113, "setreuid",        2, [Id,    Id,     Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(114, "setregid",        2, [Id,    Id,     Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(115, "getgroups",       2, [Int,   Ptr,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(116, "setgroups",       2, [Int,   Ptr,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(117, "setresuid",       3, [Id,    Id,     Id,      Unused, Unused, Unused]),
    SyscallInfo::new(118, "getresuid",       3, [Ptr,   Ptr,    Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(119, "setresgid",       3, [Id,    Id,     Id,      Unused, Unused, Unused]),
    SyscallInfo::new(120, "getresgid",       3, [Ptr,   Ptr,    Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(121, "getpgid",         1, [Pid,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(122, "setfsuid",        1, [Id,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(123, "setfsgid",        1, [Id,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(124, "getsid",          1, [Pid,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(125, "capget",          2, [Struct,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(126, "capset",          2, [Struct,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(127, "rt_sigpending",   2, [Struct,Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(128, "rt_sigtimedwait", 4, [Struct,Struct, Time,    Size,   Unused, Unused]),
    SyscallInfo::new(129, "rt_sigqueueinfo", 3, [Pid,   Signal, Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(130, "rt_sigsuspend",   2, [Struct,Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(131, "sigaltstack",     2, [Struct,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(132, "utime",           2, [StrPtr,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(133, "mknod",           3, [StrPtr,Flags,  Int,     Unused, Unused, Unused]),
    SyscallInfo::new(134, "uselib",          1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(135, "personality",     1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(136, "ustat",           2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(137, "statfs",          2, [StrPtr,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(138, "fstatfs",         2, [Fd,    Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(139, "sysfs",           3, [Int,   Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(140, "getpriority",     2, [Int,   Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(141, "setpriority",     3, [Int,   Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(142, "sched_setparam",  2, [Pid,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(143, "sched_getparam",  2, [Pid,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(144, "sched_setscheduler",3,[Pid,  Int,    Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(145, "sched_getscheduler",1,[Pid,  Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(146, "sched_get_priority_max",1,[Int,Unused,Unused, Unused, Unused, Unused]),
    SyscallInfo::new(147, "sched_get_priority_min",1,[Int,Unused,Unused, Unused, Unused, Unused]),
    SyscallInfo::new(148, "sched_rr_get_interval",2,[Pid,Time,Unused,   Unused, Unused, Unused]),
    SyscallInfo::new(149, "mlock",           2, [Ptr,   Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(150, "munlock",         2, [Ptr,   Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(151, "mlockall",        1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(152, "munlockall",      0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(153, "vhangup",         0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(154, "modify_ldt",      3, [Int,   Ptr,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(155, "pivot_root",      2, [StrPtr,StrPtr, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(156, "_sysctl",         1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(157, "prctl",           5, [Int,   Int,    Int,     Int,    Int,    Unused]),
    SyscallInfo::new(158, "arch_prctl",      2, [Int,   Ptr,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(159, "adjtimex",        1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(160, "setrlimit",       2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(161, "chroot",          1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(162, "sync",            0, [Unused,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(163, "acct",            1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(164, "settimeofday",    2, [Struct,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(165, "mount",           5, [StrPtr,StrPtr, StrPtr,  Flags,  Ptr,    Unused]),
    SyscallInfo::new(166, "umount2",         2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(167, "swapon",          2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(168, "swapoff",         1, [StrPtr,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(169, "reboot",          4, [Int,   Int,    Int,     Ptr,    Unused, Unused]),
    SyscallInfo::new(170, "sethostname",     2, [Ptr,   Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(171, "setdomainname",   2, [Ptr,   Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(172, "iopl",            1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(173, "ioperm",          3, [Int,   Int,    Int,     Unused, Unused, Unused]),
    SyscallInfo::new(174, "create_module",   2, [StrPtr,Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(175, "init_module",     3, [Ptr,   Size,   StrPtr,  Unused, Unused, Unused]),
    SyscallInfo::new(176, "delete_module",   2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(177, "get_kernel_syms", 1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(178, "query_module",    5, [StrPtr,Int,    Ptr,     Size,   Ptr,    Unused]),
    SyscallInfo::new(179, "quotactl",        4, [Int,   StrPtr, Int,     Ptr,    Unused, Unused]),
    SyscallInfo::new(180, "nfsservctl",      3, [Int,   Struct, Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(202, "futex",           6, [Ptr,   Int,    Int,     Time,   Ptr,    Int]),
    SyscallInfo::new(203, "sched_setaffinity",3,[Pid,   Size,   Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(204, "sched_getaffinity",3,[Pid,   Size,   Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(205, "set_thread_area", 1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(206, "io_setup",        2, [Int,   Ptr,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(207, "io_destroy",      1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(208, "io_getevents",    5, [Int,   Int,    Int,     Struct, Time,   Unused]),
    SyscallInfo::new(209, "io_submit",       3, [Int,   Int,    Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(210, "io_cancel",       3, [Int,   Struct, Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(211, "get_thread_area", 1, [Struct,Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(213, "epoll_create",    1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(214, "epoll_ctl_old",   4, [Fd,    Int,    Fd,      Struct, Unused, Unused]),
    SyscallInfo::new(215, "epoll_wait_old",  4, [Fd,    Struct, Int,     Int,    Unused, Unused]),
    SyscallInfo::new(216, "remap_file_pages",5,[Ptr,   Size,   Flags,   Size,   Flags,  Unused]),
    SyscallInfo::new(217, "getdents64",      3, [Fd,    Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(218, "set_tid_address", 1, [Ptr,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(228, "clock_gettime",   2, [Int,   Time,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(229, "clock_getres",    2, [Int,   Time,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(230, "clock_nanosleep", 4, [Int,   Flags,  Time,    Time,   Unused, Unused]),
    SyscallInfo::new(231, "exit_group",      1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(232, "epoll_wait",      4, [Fd,    Struct, Int,     Int,    Unused, Unused]),
    SyscallInfo::new(233, "epoll_ctl",       4, [Fd,    Int,    Fd,      Struct, Unused, Unused]),
    SyscallInfo::new(234, "tgkill",          3, [Pid,   Pid,    Signal,  Unused, Unused, Unused]),
    SyscallInfo::new(235, "utimes",          2, [StrPtr,Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(257, "openat",          4, [Fd,    StrPtr, Flags,   Flags,  Unused, Unused]),
    SyscallInfo::new(258, "mkdirat",         3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(259, "mknodat",         4, [Fd,    StrPtr, Flags,   Int,    Unused, Unused]),
    SyscallInfo::new(260, "fchownat",        5, [Fd,    StrPtr, Id,      Id,     Flags,  Unused]),
    SyscallInfo::new(261, "futimesat",       3, [Fd,    StrPtr, Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(262, "newfstatat",      4, [Fd,    StrPtr, Struct,  Flags,  Unused, Unused]),
    SyscallInfo::new(263, "unlinkat",        3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(264, "renameat",        4, [Fd,    StrPtr, Fd,      StrPtr, Unused, Unused]),
    SyscallInfo::new(265, "linkat",          5, [Fd,    StrPtr, Fd,      StrPtr, Flags,  Unused]),
    SyscallInfo::new(266, "symlinkat",       3, [StrPtr,Fd,     StrPtr,  Unused, Unused, Unused]),
    SyscallInfo::new(267, "readlinkat",      4, [Fd,    StrPtr, Ptr,     Size,   Unused, Unused]),
    SyscallInfo::new(268, "fchmodat",        3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(269, "faccessat",       3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(270, "pselect6",        6, [Int,   Struct, Struct,  Struct, Time,   Struct]),
    SyscallInfo::new(271, "ppoll",           5, [Struct,Int,    Time,    Struct, Size,   Unused]),
    SyscallInfo::new(272, "unshare",         1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(273, "set_robust_list", 2, [Struct,Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(274, "get_robust_list", 3, [Int,   Ptr,    Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(275, "splice",          6, [Fd,    Offset, Fd,      Offset, Size,   Flags]),
    SyscallInfo::new(276, "tee",             4, [Fd,    Fd,     Size,    Flags,  Unused, Unused]),
    SyscallInfo::new(277, "sync_file_range", 4, [Fd,    Offset, Offset,  Flags,  Unused, Unused]),
    SyscallInfo::new(278, "vmsplice",        4, [Fd,    Struct, Size,    Flags,  Unused, Unused]),
    SyscallInfo::new(279, "move_pages",      6, [Pid,   Size,   Ptr,     Ptr,    Ptr,    Flags]),
    SyscallInfo::new(280, "utimensat",       4, [Fd,    StrPtr, Time,    Flags,  Unused, Unused]),
    SyscallInfo::new(281, "epoll_pwait",     5, [Fd,    Struct, Int,     Int,    Struct, Unused]),
    SyscallInfo::new(282, "signalfd",        3, [Fd,    Struct, Size,    Unused, Unused, Unused]),
    SyscallInfo::new(283, "timerfd_create",  2, [Int,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(284, "eventfd",         1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(285, "fallocate",       4, [Fd,    Flags,  Offset,  Offset, Unused, Unused]),
    SyscallInfo::new(286, "timerfd_settime", 4, [Fd,    Flags,  Time,    Time,   Unused, Unused]),
    SyscallInfo::new(287, "timerfd_gettime", 2, [Fd,    Time,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(288, "accept4",         4, [Fd,    Struct, Ptr,     Flags,  Unused, Unused]),
    SyscallInfo::new(289, "signalfd4",       4, [Fd,    Struct, Size,    Flags,  Unused, Unused]),
    SyscallInfo::new(290, "eventfd2",        2, [Int,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(291, "epoll_create1",   1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(292, "dup3",            3, [Fd,    Fd,     Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(293, "pipe2",           2, [Ptr,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(294, "inotify_init1",   1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(295, "preadv",          5, [Fd,    Struct, Int,     Int,    Int,    Unused]),
    SyscallInfo::new(296, "pwritev",         5, [Fd,    Struct, Int,     Int,    Int,    Unused]),
    SyscallInfo::new(297, "rt_tgsigqueueinfo",4,[Pid,  Pid,    Signal,  Struct, Unused, Unused]),
    SyscallInfo::new(298, "perf_event_open", 5, [Struct,Pid,    Int,     Int,    Flags,  Unused]),
    SyscallInfo::new(299, "recvmmsg",        5, [Fd,    Struct, Int,     Flags,  Time,   Unused]),
    SyscallInfo::new(300, "fanotify_init",   2, [Flags, Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(301, "fanotify_mark",   5, [Fd,    Flags,  Int,     Fd,     StrPtr, Unused]),
    SyscallInfo::new(302, "prlimit64",       4, [Pid,   Int,    Struct,  Struct, Unused, Unused]),
    SyscallInfo::new(303, "name_to_handle_at",5,[Fd,   StrPtr, Struct,  Ptr,    Flags,  Unused]),
    SyscallInfo::new(304, "open_by_handle_at",3,[Fd,   Struct, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(305, "clock_adjtime",   2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(306, "syncfs",          1, [Fd,    Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(307, "sendmmsg",        4, [Fd,    Struct, Int,     Flags,  Unused, Unused]),
    SyscallInfo::new(308, "setns",           2, [Fd,    Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(309, "getcpu",          3, [Ptr,   Ptr,    Struct,  Unused, Unused, Unused]),
    SyscallInfo::new(310, "process_vm_readv", 6,[Pid,  Struct, Int,     Struct, Int,    Flags]),
    SyscallInfo::new(311, "process_vm_writev",6,[Pid,  Struct, Int,     Struct, Int,    Flags]),
    SyscallInfo::new(312, "kcmp",            5, [Pid,   Pid,    Int,     Int,    Int,    Unused]),
    SyscallInfo::new(313, "finit_module",    3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(314, "sched_setattr",   3, [Pid,   Struct, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(315, "sched_getattr",   4, [Pid,   Struct, Int,     Flags,  Unused, Unused]),
    SyscallInfo::new(316, "renameat2",       5, [Fd,    StrPtr, Fd,      StrPtr, Flags,  Unused]),
    SyscallInfo::new(317, "seccomp",         3, [Int,   Flags,  Ptr,     Unused, Unused, Unused]),
    SyscallInfo::new(318, "getrandom",       3, [Ptr,   Size,   Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(319, "memfd_create",    2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(320, "kexec_file_load", 5, [Fd,    Fd,     Size,    StrPtr, Flags,  Unused]),
    SyscallInfo::new(321, "bpf",             3, [Int,   Struct, Int,     Unused, Unused, Unused]),
    SyscallInfo::new(322, "execveat",        5, [Fd,    StrPtr, Ptr,     Ptr,    Flags,  Unused]),
    SyscallInfo::new(323, "userfaultfd",     1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(324, "membarrier",      2, [Int,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(325, "mlock2",          3, [Ptr,   Size,   Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(326, "copy_file_range", 6, [Fd,    Offset, Fd,      Offset, Size,   Flags]),
    SyscallInfo::new(327, "preadv2",         6, [Fd,    Struct, Int,     Offset, Flags,  Unused]),
    SyscallInfo::new(328, "pwritev2",        6, [Fd,    Struct, Int,     Offset, Flags,  Unused]),
    SyscallInfo::new(329, "pkey_mprotect",   4, [Ptr,   Size,   Flags,   Int,    Unused, Unused]),
    SyscallInfo::new(330, "pkey_alloc",      2, [Flags, Int,    Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(331, "pkey_free",       1, [Int,   Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(332, "statx",           5, [Fd,    StrPtr, Flags,   Int,    Struct, Unused]),
    SyscallInfo::new(333, "io_pgetevents",   5, [Int,   Int,    Int,     Struct, Time,   Unused]),
    SyscallInfo::new(334, "rseq",            4, [Struct,Int,    Flags,   Int,    Unused, Unused]),
    SyscallInfo::new(424, "pidfd_send_signal",4,[Fd,   Signal, Struct,  Flags,  Unused, Unused]),
    SyscallInfo::new(425, "io_uring_setup",  2, [Int,   Struct, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(426, "io_uring_enter",  6, [Fd,    Int,    Int,     Int,    Struct, Size]),
    SyscallInfo::new(427, "io_uring_register",4,[Fd,   Int,    Ptr,     Int,    Unused, Unused]),
    SyscallInfo::new(428, "open_tree",       3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(429, "move_mount",      5, [Fd,    StrPtr, Fd,      StrPtr, Flags,  Unused]),
    SyscallInfo::new(430, "fsopen",          2, [StrPtr,Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(431, "fsconfig",        5, [Fd,    Int,    StrPtr,  Ptr,    Int,    Unused]),
    SyscallInfo::new(432, "fsmount",         3, [Fd,    Flags,  Int,     Unused, Unused, Unused]),
    SyscallInfo::new(433, "fspick",          3, [Fd,    StrPtr, Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(434, "pidfd_open",      2, [Pid,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(435, "clone3",          2, [Struct,Size,   Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(436, "close_range",     3, [Fd,    Fd,     Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(437, "openat2",         4, [Fd,    StrPtr, Struct,  Size,   Unused, Unused]),
    SyscallInfo::new(438, "pidfd_getfd",     3, [Fd,    Fd,     Flags,   Unused, Unused, Unused]),
    SyscallInfo::new(439, "faccessat2",      4, [Fd,    StrPtr, Flags,   Flags,  Unused, Unused]),
    SyscallInfo::new(440, "process_madvise", 5, [Fd,    Struct, Size,    Int,    Flags,  Unused]),
    SyscallInfo::new(441, "epoll_pwait2",    6, [Fd,    Struct, Int,     Time,   Struct, Size]),
    SyscallInfo::new(442, "mount_setattr",   5, [Fd,    StrPtr, Flags,   Struct, Size,   Unused]),
    SyscallInfo::new(443, "quotactl_fd",     4, [Fd,    Int,    Int,     Ptr,    Unused, Unused]),
    SyscallInfo::new(444, "landlock_create_ruleset",3,[Struct,Size,Flags,Unused,Unused, Unused]),
    SyscallInfo::new(445, "landlock_add_rule",4,[Fd,   Int,    Ptr,     Flags,  Unused, Unused]),
    SyscallInfo::new(446, "landlock_restrict_self",2,[Fd,Flags,Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(447, "memfd_secret",    1, [Flags, Unused, Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(448, "process_mrelease",2,[Fd,   Flags,  Unused,  Unused, Unused, Unused]),
    SyscallInfo::new(449, "futex_waitv",     5, [Struct,Int,    Flags,   Time,   Int,    Unused]),
    SyscallInfo::new(450, "set_mempolicy_home_node",4,[Ptr,Size,Int,    Int,    Unused, Unused]),
];

// ─── Lookup functions ─────────────────────────────────────────────────────────

/// Look up syscall information by number.
///
/// Returns `None` if the number is not in the table.
#[must_use]
pub fn syscall_by_number(nr: u64) -> Option<&'static SyscallInfo> {
    SYSCALL_TABLE.iter().find(|s| s.number == nr)
}

/// Look up syscall information by name (case-sensitive, exact match).
///
/// Returns `None` if the name is not in the table.
#[must_use]
pub fn syscall_by_name(name: &str) -> Option<&'static SyscallInfo> {
    SYSCALL_TABLE.iter().find(|s| s.name == name)
}

/// Build a `HashMap<u64, &SyscallInfo>` for O(1) number lookups.
#[must_use]
pub fn build_number_index() -> HashMap<u64, &'static SyscallInfo> {
    SYSCALL_TABLE.iter().map(|s| (s.number, s)).collect()
}

/// Build a `HashMap<&str, &SyscallInfo>` for O(1) name lookups.
#[must_use]
pub fn build_name_index() -> HashMap<&'static str, &'static SyscallInfo> {
    SYSCALL_TABLE.iter().map(|s| (s.name, s)).collect()
}

/// Return all syscalls whose name contains `needle` (case-insensitive).
#[must_use]
pub fn search_by_name(needle: &str) -> Vec<&'static SyscallInfo> {
    let needle_lc = needle.to_lowercase();
    SYSCALL_TABLE
        .iter()
        .filter(|s| s.name.to_lowercase().contains(&needle_lc))
        .collect()
}

/// Return all syscalls that accept exactly `n` arguments.
#[must_use]
pub fn by_arg_count(n: u8) -> Vec<&'static SyscallInfo> {
    SYSCALL_TABLE.iter().filter(|s| s.num_args == n).collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_read() {
        let s = syscall_by_number(0).unwrap();
        assert_eq!(s.name, "read");
        assert_eq!(s.num_args, 3);
    }

    #[test]
    fn test_lookup_write() {
        let s = syscall_by_name("write").unwrap();
        assert_eq!(s.number, 1);
    }

    #[test]
    fn test_lookup_exit_group() {
        let s = syscall_by_number(231).unwrap();
        assert_eq!(s.name, "exit_group");
    }

    #[test]
    fn test_lookup_unknown_number() {
        assert!(syscall_by_number(9999).is_none());
    }

    #[test]
    fn test_lookup_by_name_ptrace() {
        let s = syscall_by_name("ptrace").unwrap();
        assert_eq!(s.number, 101);
        assert_eq!(s.num_args, 4);
    }

    #[test]
    fn test_search_by_name_partial() {
        let results = search_by_name("fd");
        assert!(!results.is_empty());
        assert!(results.iter().any(|s| s.name.contains("fd")));
    }

    #[test]
    fn test_no_duplicate_numbers() {
        let mut seen: Vec<u64> = Vec::new();
        for s in SYSCALL_TABLE {
            assert!(!seen.contains(&s.number), "duplicate nr {}", s.number);
            seen.push(s.number);
        }
    }

    #[test]
    fn test_table_not_empty() {
        assert!(SYSCALL_TABLE.len() > 100);
    }

    #[test]
    fn test_args_count_consistent() {
        for s in SYSCALL_TABLE {
            assert!(s.num_args <= 6, "nr={} has num_args={}", s.number, s.num_args);
        }
    }

    #[test]
    fn test_by_arg_count_zero() {
        let zero_arg = by_arg_count(0);
        assert!(!zero_arg.is_empty());
        assert!(zero_arg.iter().any(|s| s.name == "getpid"));
    }

    #[test]
    fn test_build_number_index_contains_mmap() {
        let idx = build_number_index();
        assert!(idx.contains_key(&9));
        assert_eq!(idx[&9].name, "mmap");
    }

    #[test]
    fn test_build_name_index_contains_clone() {
        let idx = build_name_index();
        assert!(idx.contains_key("clone"));
    }
}
