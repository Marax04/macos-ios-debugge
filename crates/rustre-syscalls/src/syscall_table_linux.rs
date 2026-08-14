//! `syscall_table_linux` — Comprehensive Linux syscall tables with typed arguments
//! and kernel-version tracking.
//!
//! Covers all ~350 `x86_64` syscalls (NR 0–448), ARM64/ARM/MIPS subsets,
//! per-argument `ArgKind` typing (all 6 slots), `SyscallCategory`, and
//! optional `KernelVersion` range tracking per entry.
//!
//! # Relationship to `linux_syscall_table`
//!
//! This module is intentionally distinct from [`super::linux_syscall_table`]:
//! - **`syscall_table_linux`** (this module): fullest `x86_64` entry list
//!   (~350 NRs), typed argument slots via `ArgKind`/`SyscallArgs`, kernel
//!   version metadata, compile-time static tables, no serde dependency.
//! - **`linux_syscall_table`**: risk-scored (`RiskLevel`), serde-serialisable
//!   entries, RISC-V64 ABI support, `merge` and `category_stats` helpers,
//!   alias resolution.
//!
//! Use `syscall_table_linux` when you need the most complete entry list,
//! per-argument types, or kernel-version filtering; use `linux_syscall_table`
//! for risk queries, ABI register info, or serde output.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinuxArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
}

impl LinuxArch {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86    => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm    => "arm",
            Self::Arm64  => "arm64",
            Self::Mips   => "mips",
            Self::Mips64 => "mips64",
        }
    }
    #[must_use] 
    pub const fn pointer_size(self) -> u8 {
        match self {
            Self::X86 | Self::Arm | Self::Mips => 4,
            _ => 8,
        }
    }
}

impl fmt::Display for LinuxArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Kernel version
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl KernelVersion {
    #[must_use] 
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }
    pub const V2_6: Self = Self::new(2, 6, 0);
    pub const V3_0:  Self = Self::new(3, 0, 0);
    pub const V4_0:  Self = Self::new(4, 0, 0);
    pub const V5_0:  Self = Self::new(5, 0, 0);
    pub const V6_0:  Self = Self::new(6, 0, 0);
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Argument type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    Size,
    PtrConst,
    PtrMut,
    Fd,
    Pid,
    Uid,
    Gid,
    Mode,
    Flags,
    Signal,
    Offset,
    Unused,
}

impl ArgKind {
    #[must_use] 
    pub const fn is_pointer(self) -> bool {
        matches!(self, Self::PtrConst | Self::PtrMut)
    }
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Int          => "int",
            Self::UnsignedInt  => "unsigned int",
            Self::Long         => "long",
            Self::UnsignedLong => "unsigned long",
            Self::Size         => "size_t",
            Self::PtrConst     => "const void *",
            Self::PtrMut       => "void *",
            Self::Fd           => "int (fd)",
            Self::Pid          => "pid_t",
            Self::Uid          => "uid_t",
            Self::Gid          => "gid_t",
            Self::Mode         => "mode_t",
            Self::Flags        => "unsigned long (flags)",
            Self::Signal       => "int (signal)",
            Self::Offset       => "off_t",
            Self::Unused       => "(unused)",
        }
    }
}

// ---------------------------------------------------------------------------
// SyscallArgs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SyscallArgs {
    pub count: u8,
    pub kinds: [ArgKind; 6],
}

impl SyscallArgs {
    #[must_use] 
    pub const fn new(count: u8, kinds: [ArgKind; 6]) -> Self {
        Self { count, kinds }
    }
    pub const NONE: Self = Self::new(0, [ArgKind::Unused; 6]);

    pub fn iter(&self) -> impl Iterator<Item = ArgKind> + '_ {
        self.kinds[..self.count as usize].iter().copied()
    }
}

// ---------------------------------------------------------------------------
// Syscall category
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    FileSystem,
    Process,
    Memory,
    Network,
    Signal,
    Ipc,
    Time,
    Device,
    Security,
    Misc,
}

impl SyscallCategory {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::FileSystem => "filesystem",
            Self::Process    => "process",
            Self::Memory     => "memory",
            Self::Network    => "network",
            Self::Signal     => "signal",
            Self::Ipc        => "ipc",
            Self::Time       => "time",
            Self::Device     => "device",
            Self::Security   => "security",
            Self::Misc       => "misc",
        }
    }
}

// ---------------------------------------------------------------------------
// LinuxSyscallEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LinuxSyscallEntry {
    pub number: u32,
    pub name: &'static str,
    pub args: SyscallArgs,
    pub category: SyscallCategory,
    pub added_in: Option<KernelVersion>,
    pub removed_in: Option<KernelVersion>,
}

impl LinuxSyscallEntry {
    #[must_use] 
    pub const fn new(
        number: u32,
        name: &'static str,
        args: SyscallArgs,
        category: SyscallCategory,
    ) -> Self {
        Self { number, name, args, category, added_in: None, removed_in: None }
    }

    #[must_use] 
    pub const fn with_version(mut self, added: KernelVersion) -> Self {
        self.added_in = Some(added);
        self
    }

    #[must_use] 
    pub fn active_in(&self, ver: KernelVersion) -> bool {
        let after_add  = self.added_in.is_none_or(|a| ver >= a);
        let before_rem = self.removed_in.is_none_or(|r| ver < r);
        after_add && before_rem
    }
}

// ---------------------------------------------------------------------------
// Macro helpers (compile-time static construction)
// ---------------------------------------------------------------------------

macro_rules! sc {
    ($n:expr, $name:literal, $cat:ident, $cnt:expr, [$($k:ident),*]) => {
        LinuxSyscallEntry::new(
            $n,
            $name,
            SyscallArgs::new($cnt, [$(ArgKind::$k),*]),
            SyscallCategory::$cat,
        )
    };
}

// ---------------------------------------------------------------------------
// x86_64 syscall table (all ~350 entries, Linux kernel 5.x)
// ---------------------------------------------------------------------------

pub static X86_64_SYSCALLS: &[LinuxSyscallEntry] = &[
    sc!(0,  "read",              FileSystem, 3, [Fd,PtrMut,Size,Unused,Unused,Unused]),
    sc!(1,  "write",             FileSystem, 3, [Fd,PtrConst,Size,Unused,Unused,Unused]),
    sc!(2,  "open",              FileSystem, 3, [PtrConst,Flags,Mode,Unused,Unused,Unused]),
    sc!(3,  "close",             FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(4,  "stat",              FileSystem, 2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(5,  "fstat",             FileSystem, 2, [Fd,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(6,  "lstat",             FileSystem, 2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(7,  "poll",              FileSystem, 3, [PtrMut,UnsignedInt,Int,Unused,Unused,Unused]),
    sc!(8,  "lseek",             FileSystem, 3, [Fd,Offset,UnsignedInt,Unused,Unused,Unused]),
    sc!(9,  "mmap",              Memory,     6, [PtrMut,Size,Int,Int,Fd,Offset]),
    sc!(10, "mprotect",          Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(11, "munmap",            Memory,     2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(12, "brk",               Memory,     1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(13, "rt_sigaction",      Signal,     4, [Signal,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(14, "rt_sigprocmask",    Signal,     4, [Int,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(15, "rt_sigreturn",      Signal,     0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(16, "ioctl",             Device,     3, [Fd,UnsignedLong,UnsignedLong,Unused,Unused,Unused]),
    sc!(17, "pread64",           FileSystem, 4, [Fd,PtrMut,Size,Offset,Unused,Unused]),
    sc!(18, "pwrite64",          FileSystem, 4, [Fd,PtrConst,Size,Offset,Unused,Unused]),
    sc!(19, "readv",             FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(20, "writev",            FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(21, "access",            FileSystem, 2, [PtrConst,Int,Unused,Unused,Unused,Unused]),
    sc!(22, "pipe",              FileSystem, 1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(23, "select",            FileSystem, 5, [Int,PtrMut,PtrMut,PtrMut,PtrMut,Unused]),
    sc!(24, "sched_yield",       Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(25, "mremap",            Memory,     5, [PtrMut,Size,Size,Int,PtrMut,Unused]),
    sc!(26, "msync",             Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(27, "mincore",           Memory,     3, [PtrMut,Size,PtrMut,Unused,Unused,Unused]),
    sc!(28, "madvise",           Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(29, "shmget",            Ipc,        3, [Int,Size,Int,Unused,Unused,Unused]),
    sc!(30, "shmat",             Ipc,        3, [Int,PtrConst,Int,Unused,Unused,Unused]),
    sc!(31, "shmctl",            Ipc,        3, [Int,Int,PtrMut,Unused,Unused,Unused]),
    sc!(32, "dup",               FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(33, "dup2",              FileSystem, 2, [Fd,Fd,Unused,Unused,Unused,Unused]),
    sc!(34, "pause",             Signal,     0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(35, "nanosleep",         Time,       2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(36, "getitimer",         Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(37, "alarm",             Time,       1, [UnsignedInt,Unused,Unused,Unused,Unused,Unused]),
    sc!(38, "setitimer",         Time,       3, [Int,PtrConst,PtrMut,Unused,Unused,Unused]),
    sc!(39, "getpid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(40, "sendfile",          Network,    4, [Fd,Fd,PtrMut,Size,Unused,Unused]),
    sc!(41, "socket",            Network,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(42, "connect",           Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(43, "accept",            Network,    3, [Fd,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(44, "sendto",            Network,    6, [Fd,PtrConst,Size,Int,PtrConst,UnsignedInt]),
    sc!(45, "recvfrom",          Network,    6, [Fd,PtrMut,Size,Int,PtrMut,PtrMut]),
    sc!(46, "sendmsg",           Network,    3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(47, "recvmsg",           Network,    3, [Fd,PtrMut,Int,Unused,Unused,Unused]),
    sc!(48, "shutdown",          Network,    2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(49, "bind",              Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(50, "listen",            Network,    2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(51, "getsockname",       Network,    3, [Fd,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(52, "getpeername",       Network,    3, [Fd,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(53, "socketpair",        Network,    4, [Int,Int,Int,PtrMut,Unused,Unused]),
    sc!(54, "setsockopt",        Network,    5, [Fd,Int,Int,PtrConst,UnsignedInt,Unused]),
    sc!(55, "getsockopt",        Network,    5, [Fd,Int,Int,PtrMut,PtrMut,Unused]),
    sc!(56, "clone",             Process,    5, [UnsignedLong,PtrMut,PtrMut,PtrMut,PtrMut,Unused]),
    sc!(57, "fork",              Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(58, "vfork",             Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(59, "execve",            Process,    3, [PtrConst,PtrConst,PtrConst,Unused,Unused,Unused]),
    sc!(60, "exit",              Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(61, "wait4",             Process,    4, [Pid,PtrMut,Int,PtrMut,Unused,Unused]),
    sc!(62, "kill",              Signal,     2, [Pid,Signal,Unused,Unused,Unused,Unused]),
    sc!(63, "uname",             Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(64, "semget",            Ipc,        3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(65, "semop",             Ipc,        3, [Int,PtrMut,Size,Unused,Unused,Unused]),
    sc!(66, "semctl",            Ipc,        4, [Int,Int,Int,UnsignedLong,Unused,Unused]),
    sc!(67, "shmdt",             Ipc,        1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(68, "msgget",            Ipc,        2, [Int,Int,Unused,Unused,Unused,Unused]),
    sc!(69, "msgsnd",            Ipc,        4, [Int,PtrConst,Size,Int,Unused,Unused]),
    sc!(70, "msgrcv",            Ipc,        5, [Int,PtrMut,Size,Long,Int,Unused]),
    sc!(71, "msgctl",            Ipc,        3, [Int,Int,PtrMut,Unused,Unused,Unused]),
    sc!(72, "fcntl",             FileSystem, 3, [Fd,UnsignedInt,UnsignedLong,Unused,Unused,Unused]),
    sc!(73, "flock",             FileSystem, 2, [Fd,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(74, "fsync",             FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(75, "fdatasync",         FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(76, "truncate",          FileSystem, 2, [PtrConst,Long,Unused,Unused,Unused,Unused]),
    sc!(77, "ftruncate",         FileSystem, 2, [Fd,Long,Unused,Unused,Unused,Unused]),
    sc!(78, "getdents",          FileSystem, 3, [Fd,PtrMut,UnsignedInt,Unused,Unused,Unused]),
    sc!(79, "getcwd",            FileSystem, 2, [PtrMut,UnsignedLong,Unused,Unused,Unused,Unused]),
    sc!(80, "chdir",             FileSystem, 1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(81, "fchdir",            FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(82, "rename",            FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(83, "mkdir",             FileSystem, 2, [PtrConst,Mode,Unused,Unused,Unused,Unused]),
    sc!(84, "rmdir",             FileSystem, 1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(85, "creat",             FileSystem, 2, [PtrConst,Mode,Unused,Unused,Unused,Unused]),
    sc!(86, "link",              FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(87, "unlink",            FileSystem, 1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(88, "symlink",           FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(89, "readlink",          FileSystem, 3, [PtrConst,PtrMut,Int,Unused,Unused,Unused]),
    sc!(90, "chmod",             FileSystem, 2, [PtrConst,Mode,Unused,Unused,Unused,Unused]),
    sc!(91, "fchmod",            FileSystem, 2, [Fd,Mode,Unused,Unused,Unused,Unused]),
    sc!(92, "chown",             FileSystem, 3, [PtrConst,Uid,Gid,Unused,Unused,Unused]),
    sc!(93, "fchown",            FileSystem, 3, [Fd,Uid,Gid,Unused,Unused,Unused]),
    sc!(94, "lchown",            FileSystem, 3, [PtrConst,Uid,Gid,Unused,Unused,Unused]),
    sc!(95, "umask",             FileSystem, 1, [Mode,Unused,Unused,Unused,Unused,Unused]),
    sc!(96, "gettimeofday",      Time,       2, [PtrMut,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(97, "getrlimit",         Process,    2, [UnsignedInt,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(98, "getrusage",         Process,    2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(99, "sysinfo",           Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(100,"times",             Time,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(101,"ptrace",            Process,    4, [Long,Pid,UnsignedLong,UnsignedLong,Unused,Unused]),
    sc!(102,"getuid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(103,"syslog",            Misc,       3, [Int,PtrMut,Int,Unused,Unused,Unused]),
    sc!(104,"getgid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(105,"setuid",            Process,    1, [Uid,Unused,Unused,Unused,Unused,Unused]),
    sc!(106,"setgid",            Process,    1, [Gid,Unused,Unused,Unused,Unused,Unused]),
    sc!(107,"geteuid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(108,"getegid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(109,"setpgid",           Process,    2, [Pid,Pid,Unused,Unused,Unused,Unused]),
    sc!(110,"getppid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(111,"getpgrp",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(112,"setsid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(113,"setreuid",          Process,    2, [Uid,Uid,Unused,Unused,Unused,Unused]),
    sc!(114,"setregid",          Process,    2, [Gid,Gid,Unused,Unused,Unused,Unused]),
    sc!(115,"getgroups",         Process,    2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(116,"setgroups",         Process,    2, [Int,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(117,"setresuid",         Process,    3, [Uid,Uid,Uid,Unused,Unused,Unused]),
    sc!(118,"getresuid",         Process,    3, [PtrMut,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(119,"setresgid",         Process,    3, [Gid,Gid,Gid,Unused,Unused,Unused]),
    sc!(120,"getresgid",         Process,    3, [PtrMut,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(121,"getpgid",           Process,    1, [Pid,Unused,Unused,Unused,Unused,Unused]),
    sc!(122,"setfsuid",          Process,    1, [Uid,Unused,Unused,Unused,Unused,Unused]),
    sc!(123,"setfsgid",          Process,    1, [Gid,Unused,Unused,Unused,Unused,Unused]),
    sc!(124,"getsid",            Process,    1, [Pid,Unused,Unused,Unused,Unused,Unused]),
    sc!(125,"capget",            Security,   2, [PtrMut,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(126,"capset",            Security,   2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(127,"rt_sigpending",     Signal,     2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(128,"rt_sigtimedwait",   Signal,     4, [PtrConst,PtrMut,PtrConst,Size,Unused,Unused]),
    sc!(129,"rt_sigqueueinfo",   Signal,     3, [Pid,Signal,PtrConst,Unused,Unused,Unused]),
    sc!(130,"rt_sigsuspend",     Signal,     2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(131,"sigaltstack",       Signal,     2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(132,"utime",             Time,       2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(133,"mknod",             FileSystem, 3, [PtrConst,Mode,UnsignedInt,Unused,Unused,Unused]),
    sc!(134,"uselib",            Misc,       1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(135,"personality",       Process,    1, [UnsignedInt,Unused,Unused,Unused,Unused,Unused]),
    sc!(136,"ustat",             FileSystem, 2, [UnsignedInt,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(137,"statfs",            FileSystem, 2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(138,"fstatfs",           FileSystem, 2, [Fd,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(139,"sysfs",             Misc,       3, [Int,UnsignedLong,UnsignedLong,Unused,Unused,Unused]),
    sc!(140,"getpriority",       Process,    2, [Int,Int,Unused,Unused,Unused,Unused]),
    sc!(141,"setpriority",       Process,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(142,"sched_setparam",    Process,    2, [Pid,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(143,"sched_getparam",    Process,    2, [Pid,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(144,"sched_setscheduler",Process,    3, [Pid,Int,PtrConst,Unused,Unused,Unused]),
    sc!(145,"sched_getscheduler",Process,    1, [Pid,Unused,Unused,Unused,Unused,Unused]),
    sc!(146,"sched_get_priority_max", Process, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(147,"sched_get_priority_min", Process, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(148,"sched_rr_get_interval",  Process, 2, [Pid,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(149,"mlock",             Memory,     2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(150,"munlock",           Memory,     2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(151,"mlockall",          Memory,     1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(152,"munlockall",        Memory,     0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(153,"vhangup",           Device,     0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(154,"modify_ldt",        Misc,       3, [Int,PtrMut,UnsignedLong,Unused,Unused,Unused]),
    sc!(155,"pivot_root",        FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(156,"_sysctl",           Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(157,"prctl",             Process,    5, [Int,UnsignedLong,UnsignedLong,UnsignedLong,UnsignedLong,Unused]),
    sc!(158,"arch_prctl",        Process,    2, [Int,UnsignedLong,Unused,Unused,Unused,Unused]),
    sc!(159,"adjtimex",          Time,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(160,"setrlimit",         Process,    2, [UnsignedInt,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(161,"chroot",            FileSystem, 1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(162,"sync",              FileSystem, 0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(163,"acct",              Misc,       1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(164,"settimeofday",      Time,       2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(165,"mount",             FileSystem, 5, [PtrConst,PtrConst,PtrConst,UnsignedLong,PtrConst,Unused]),
    sc!(166,"umount2",           FileSystem, 2, [PtrConst,Int,Unused,Unused,Unused,Unused]),
    sc!(167,"swapon",            Misc,       2, [PtrConst,Int,Unused,Unused,Unused,Unused]),
    sc!(168,"swapoff",           Misc,       1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(169,"reboot",            Misc,       4, [Int,Int,UnsignedInt,PtrMut,Unused,Unused]),
    sc!(170,"sethostname",       Misc,       2, [PtrConst,Int,Unused,Unused,Unused,Unused]),
    sc!(171,"setdomainname",     Misc,       2, [PtrConst,Int,Unused,Unused,Unused,Unused]),
    sc!(172,"iopl",              Device,     1, [UnsignedInt,Unused,Unused,Unused,Unused,Unused]),
    sc!(173,"ioperm",            Device,     3, [UnsignedLong,UnsignedLong,Int,Unused,Unused,Unused]),
    sc!(174,"create_module",     Misc,       2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(175,"init_module",       Misc,       3, [PtrMut,UnsignedLong,PtrConst,Unused,Unused,Unused]),
    sc!(176,"delete_module",     Misc,       2, [PtrConst,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(177,"get_kernel_syms",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(178,"query_module",      Misc,       5, [PtrConst,Int,PtrMut,Size,PtrMut,Unused]),
    sc!(179,"quotactl",          FileSystem, 4, [UnsignedInt,PtrConst,Int,PtrMut,Unused,Unused]),
    sc!(180,"nfsservctl",        Misc,       3, [Int,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(181,"getpmsg",           Misc,       5, [Int,PtrMut,PtrMut,PtrMut,PtrMut,Unused]),
    sc!(182,"putpmsg",           Misc,       5, [Int,PtrConst,PtrConst,Int,Int,Unused]),
    sc!(183,"afs_syscall",       Misc,       5, [Long,Long,Long,Long,Long,Unused]),
    sc!(184,"tuxcall",           Misc,       3, [UnsignedInt,PtrMut,Int,Unused,Unused,Unused]),
    sc!(185,"security",          Security,   3, [UnsignedInt,PtrMut,Int,Unused,Unused,Unused]),
    sc!(186,"gettid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(187,"readahead",         FileSystem, 3, [Fd,Offset,Size,Unused,Unused,Unused]),
    sc!(188,"setxattr",          FileSystem, 5, [PtrConst,PtrConst,PtrConst,Size,Int,Unused]),
    sc!(189,"lsetxattr",         FileSystem, 5, [PtrConst,PtrConst,PtrConst,Size,Int,Unused]),
    sc!(190,"fsetxattr",         FileSystem, 5, [Fd,PtrConst,PtrConst,Size,Int,Unused]),
    sc!(191,"getxattr",          FileSystem, 4, [PtrConst,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(192,"lgetxattr",         FileSystem, 4, [PtrConst,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(193,"fgetxattr",         FileSystem, 4, [Fd,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(194,"listxattr",         FileSystem, 3, [PtrConst,PtrMut,Size,Unused,Unused,Unused]),
    sc!(195,"llistxattr",        FileSystem, 3, [PtrConst,PtrMut,Size,Unused,Unused,Unused]),
    sc!(196,"flistxattr",        FileSystem, 3, [Fd,PtrMut,Size,Unused,Unused,Unused]),
    sc!(197,"removexattr",       FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(198,"lremovexattr",      FileSystem, 2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(199,"fremovexattr",      FileSystem, 2, [Fd,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(200,"tkill",             Signal,     2, [Pid,Signal,Unused,Unused,Unused,Unused]),
    sc!(201,"time",              Time,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(202,"futex",             Misc,       6, [PtrMut,Int,UnsignedInt,PtrConst,PtrMut,UnsignedInt]),
    sc!(203,"sched_setaffinity", Process,    3, [Pid,Size,PtrConst,Unused,Unused,Unused]),
    sc!(204,"sched_getaffinity", Process,    3, [Pid,Size,PtrMut,Unused,Unused,Unused]),
    sc!(205,"set_thread_area",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(206,"io_setup",          Misc,       2, [UnsignedInt,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(207,"io_destroy",        Misc,       1, [UnsignedLong,Unused,Unused,Unused,Unused,Unused]),
    sc!(208,"io_getevents",      Misc,       5, [UnsignedLong,Long,Long,PtrMut,PtrConst,Unused]),
    sc!(209,"io_submit",         Misc,       3, [UnsignedLong,Long,PtrMut,Unused,Unused,Unused]),
    sc!(210,"io_cancel",         Misc,       3, [UnsignedLong,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(211,"get_thread_area",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(212,"lookup_dcookie",    FileSystem, 3, [UnsignedLong,PtrMut,Size,Unused,Unused,Unused]),
    sc!(213,"epoll_create",      FileSystem, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(214,"epoll_ctl_old",     FileSystem, 4, [Int,Int,Fd,PtrMut,Unused,Unused]),
    sc!(215,"epoll_wait_old",    FileSystem, 4, [Int,PtrMut,Int,Int,Unused,Unused]),
    sc!(216,"remap_file_pages",  Memory,     5, [PtrMut,Size,Int,Size,Int,Unused]),
    sc!(217,"getdents64",        FileSystem, 3, [Fd,PtrMut,UnsignedInt,Unused,Unused,Unused]),
    sc!(218,"set_tid_address",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(219,"restart_syscall",   Misc,       0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(220,"semtimedop",        Ipc,        4, [Int,PtrMut,UnsignedInt,PtrConst,Unused,Unused]),
    sc!(221,"fadvise64",         FileSystem, 4, [Fd,Offset,Size,Int,Unused,Unused]),
    sc!(222,"timer_create",      Time,       3, [Int,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(223,"timer_settime",     Time,       4, [Int,Int,PtrConst,PtrMut,Unused,Unused]),
    sc!(224,"timer_gettime",     Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(225,"timer_getoverrun",  Time,       1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(226,"timer_delete",      Time,       1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(227,"clock_settime",     Time,       2, [Int,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(228,"clock_gettime",     Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(229,"clock_getres",      Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(230,"clock_nanosleep",   Time,       4, [Int,Int,PtrConst,PtrMut,Unused,Unused]),
    sc!(231,"exit_group",        Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(232,"epoll_wait",        FileSystem, 4, [Fd,PtrMut,Int,Int,Unused,Unused]),
    sc!(233,"epoll_ctl",         FileSystem, 4, [Fd,Int,Fd,PtrMut,Unused,Unused]),
    sc!(234,"tgkill",            Signal,     3, [Pid,Pid,Signal,Unused,Unused,Unused]),
    sc!(235,"utimes",            Time,       2, [PtrConst,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(236,"vserver",           Misc,       4, [UnsignedInt,UnsignedInt,UnsignedInt,PtrMut,Unused,Unused]),
    sc!(237,"mbind",             Memory,     6, [PtrMut,UnsignedLong,Int,PtrConst,UnsignedLong,UnsignedInt]),
    sc!(238,"set_mempolicy",     Memory,     3, [Int,PtrConst,UnsignedLong,Unused,Unused,Unused]),
    sc!(239,"get_mempolicy",     Memory,     5, [PtrMut,PtrMut,UnsignedLong,PtrMut,UnsignedLong,Unused]),
    sc!(240,"mq_open",           Ipc,        4, [PtrConst,Int,Mode,PtrMut,Unused,Unused]),
    sc!(241,"mq_unlink",         Ipc,        1, [PtrConst,Unused,Unused,Unused,Unused,Unused]),
    sc!(242,"mq_timedsend",      Ipc,        5, [Int,PtrConst,Size,UnsignedInt,PtrConst,Unused]),
    sc!(243,"mq_timedreceive",   Ipc,        5, [Int,PtrMut,Size,PtrMut,PtrConst,Unused]),
    sc!(244,"mq_notify",         Ipc,        2, [Int,PtrConst,Unused,Unused,Unused,Unused]),
    sc!(245,"mq_getsetattr",     Ipc,        3, [Int,PtrConst,PtrMut,Unused,Unused,Unused]),
    sc!(246,"kexec_load",        Misc,       4, [UnsignedLong,UnsignedLong,PtrMut,UnsignedLong,Unused,Unused]),
    sc!(247,"waitid",            Process,    5, [Int,Pid,PtrMut,Int,PtrMut,Unused]),
    sc!(248,"add_key",           Security,   5, [PtrConst,PtrConst,PtrConst,Size,Int,Unused]),
    sc!(249,"request_key",       Security,   4, [PtrConst,PtrConst,PtrConst,Int,Unused,Unused]),
    sc!(250,"keyctl",            Security,   5, [Int,UnsignedLong,UnsignedLong,UnsignedLong,UnsignedLong,Unused]),
    sc!(251,"ioprio_set",        Process,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(252,"ioprio_get",        Process,    2, [Int,Int,Unused,Unused,Unused,Unused]),
    sc!(253,"inotify_init",      FileSystem, 0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(254,"inotify_add_watch", FileSystem, 3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(255,"inotify_rm_watch",  FileSystem, 2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(256,"migrate_pages",     Memory,     4, [Pid,UnsignedLong,PtrConst,PtrConst,Unused,Unused]),
    sc!(257,"openat",            FileSystem, 4, [Fd,PtrConst,Int,Mode,Unused,Unused]),
    sc!(258,"mkdirat",           FileSystem, 3, [Fd,PtrConst,Mode,Unused,Unused,Unused]),
    sc!(259,"mknodat",           FileSystem, 4, [Fd,PtrConst,Mode,UnsignedInt,Unused,Unused]),
    sc!(260,"fchownat",          FileSystem, 5, [Fd,PtrConst,Uid,Gid,Int,Unused]),
    sc!(261,"futimesat",         Time,       3, [Fd,PtrConst,PtrConst,Unused,Unused,Unused]),
    sc!(262,"newfstatat",        FileSystem, 4, [Fd,PtrConst,PtrMut,Int,Unused,Unused]),
    sc!(263,"unlinkat",          FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(264,"renameat",          FileSystem, 4, [Fd,PtrConst,Fd,PtrConst,Unused,Unused]),
    sc!(265,"linkat",            FileSystem, 5, [Fd,PtrConst,Fd,PtrConst,Int,Unused]),
    sc!(266,"symlinkat",         FileSystem, 3, [PtrConst,Fd,PtrConst,Unused,Unused,Unused]),
    sc!(267,"readlinkat",        FileSystem, 4, [Fd,PtrConst,PtrMut,Int,Unused,Unused]),
    sc!(268,"fchmodat",          FileSystem, 3, [Fd,PtrConst,Mode,Unused,Unused,Unused]),
    sc!(269,"faccessat",         FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(270,"pselect6",          FileSystem, 6, [Int,PtrMut,PtrMut,PtrMut,PtrConst,PtrConst]),
    sc!(271,"ppoll",             FileSystem, 5, [PtrMut,UnsignedInt,PtrConst,PtrConst,Size,Unused]),
    sc!(272,"unshare",           Process,    1, [UnsignedLong,Unused,Unused,Unused,Unused,Unused]),
    sc!(273,"set_robust_list",   Misc,       2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(274,"get_robust_list",   Misc,       3, [Int,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(275,"splice",            FileSystem, 6, [Fd,PtrMut,Fd,PtrMut,Size,UnsignedInt]),
    sc!(276,"tee",               FileSystem, 4, [Fd,Fd,Size,UnsignedInt,Unused,Unused]),
    sc!(277,"sync_file_range",   FileSystem, 4, [Fd,Offset,Offset,UnsignedInt,Unused,Unused]),
    sc!(278,"vmsplice",          FileSystem, 4, [Fd,PtrConst,UnsignedLong,UnsignedInt,Unused,Unused]),
    sc!(279,"move_pages",        Memory,     6, [Pid,UnsignedLong,PtrMut,PtrConst,PtrMut,Int]),
    sc!(280,"utimensat",         Time,       4, [Fd,PtrConst,PtrConst,Int,Unused,Unused]),
    sc!(281,"epoll_pwait",       FileSystem, 5, [Fd,PtrMut,Int,Int,PtrConst,Unused]),
    sc!(282,"signalfd",          Signal,     3, [Fd,PtrConst,Size,Unused,Unused,Unused]),
    sc!(283,"timerfd_create",    Time,       2, [Int,Int,Unused,Unused,Unused,Unused]),
    sc!(284,"eventfd",           Misc,       1, [UnsignedInt,Unused,Unused,Unused,Unused,Unused]),
    sc!(285,"fallocate",         FileSystem, 4, [Fd,Int,Offset,Offset,Unused,Unused]),
    sc!(286,"timerfd_settime",   Time,       4, [Fd,Int,PtrConst,PtrMut,Unused,Unused]),
    sc!(287,"timerfd_gettime",   Time,       2, [Fd,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(288,"accept4",           Network,    4, [Fd,PtrMut,PtrMut,Int,Unused,Unused]),
    sc!(289,"signalfd4",         Signal,     4, [Fd,PtrConst,Size,Int,Unused,Unused]),
    sc!(290,"eventfd2",          Misc,       2, [UnsignedInt,Int,Unused,Unused,Unused,Unused]),
    sc!(291,"epoll_create1",     FileSystem, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(292,"dup3",              FileSystem, 3, [Fd,Fd,Int,Unused,Unused,Unused]),
    sc!(293,"pipe2",             FileSystem, 2, [PtrMut,Int,Unused,Unused,Unused,Unused]),
    sc!(294,"inotify_init1",     FileSystem, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(295,"preadv",            FileSystem, 5, [Fd,PtrConst,Int,UnsignedLong,UnsignedLong,Unused]),
    sc!(296,"pwritev",           FileSystem, 5, [Fd,PtrConst,Int,UnsignedLong,UnsignedLong,Unused]),
    sc!(297,"rt_tgsigqueueinfo", Signal,     4, [Pid,Pid,Signal,PtrConst,Unused,Unused]),
    sc!(298,"perf_event_open",   Misc,       5, [PtrMut,Pid,Int,Fd,UnsignedLong,Unused]),
    sc!(299,"recvmmsg",          Network,    5, [Fd,PtrMut,UnsignedInt,UnsignedInt,PtrConst,Unused]),
    sc!(300,"fanotify_init",     FileSystem, 2, [UnsignedInt,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(301,"fanotify_mark",     FileSystem, 5, [Fd,UnsignedInt,UnsignedLong,Fd,PtrConst,Unused]),
    sc!(302,"prlimit64",         Process,    4, [Pid,UnsignedInt,PtrConst,PtrMut,Unused,Unused]),
    sc!(303,"name_to_handle_at", FileSystem, 5, [Fd,PtrConst,PtrMut,PtrMut,Int,Unused]),
    sc!(304,"open_by_handle_at", FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(305,"clock_adjtime",     Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(306,"syncfs",            FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(307,"sendmmsg",          Network,    4, [Fd,PtrMut,UnsignedInt,UnsignedInt,Unused,Unused]),
    sc!(308,"setns",             Misc,       2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(309,"getcpu",            Misc,       3, [PtrMut,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(310,"process_vm_readv",  Process,    6, [Pid,PtrConst,UnsignedLong,PtrConst,UnsignedLong,UnsignedLong]),
    sc!(311,"process_vm_writev", Process,    6, [Pid,PtrConst,UnsignedLong,PtrConst,UnsignedLong,UnsignedLong]),
    sc!(312,"kcmp",              Process,    5, [Pid,Pid,Int,UnsignedLong,UnsignedLong,Unused]),
    sc!(313,"finit_module",      Misc,       3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(314,"sched_setattr",     Process,    3, [Pid,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(315,"sched_getattr",     Process,    4, [Pid,PtrMut,UnsignedInt,UnsignedInt,Unused,Unused]),
    sc!(316,"renameat2",         FileSystem, 5, [Fd,PtrConst,Fd,PtrConst,UnsignedInt,Unused]),
    sc!(317,"seccomp",           Security,   3, [UnsignedInt,UnsignedInt,PtrConst,Unused,Unused,Unused]),
    sc!(318,"getrandom",         Security,   3, [PtrMut,Size,UnsignedInt,Unused,Unused,Unused]),
    sc!(319,"memfd_create",      Memory,     2, [PtrConst,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(320,"kexec_file_load",   Misc,       5, [Fd,Fd,UnsignedLong,PtrConst,UnsignedLong,Unused]),
    sc!(321,"bpf",               Misc,       3, [Int,PtrMut,UnsignedInt,Unused,Unused,Unused]),
    sc!(322,"execveat",          Process,    5, [Fd,PtrConst,PtrConst,PtrConst,Int,Unused]),
    sc!(323,"userfaultfd",       Memory,     1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(324,"membarrier",        Memory,     2, [Int,Int,Unused,Unused,Unused,Unused]),
    sc!(325,"mlock2",            Memory,     3, [PtrConst,Size,Int,Unused,Unused,Unused]),
    sc!(326,"copy_file_range",   FileSystem, 6, [Fd,PtrMut,Fd,PtrMut,Size,UnsignedInt]),
    sc!(327,"preadv2",           FileSystem, 6, [Fd,PtrConst,Int,UnsignedLong,UnsignedLong,Int]),
    sc!(328,"pwritev2",          FileSystem, 6, [Fd,PtrConst,Int,UnsignedLong,UnsignedLong,Int]),
    sc!(329,"pkey_mprotect",     Memory,     4, [PtrMut,Size,Int,Int,Unused,Unused]),
    sc!(330,"pkey_alloc",        Memory,     2, [UnsignedLong,UnsignedLong,Unused,Unused,Unused,Unused]),
    sc!(331,"pkey_free",         Memory,     1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(332,"statx",             FileSystem, 5, [Fd,PtrConst,UnsignedInt,UnsignedInt,PtrMut,Unused]),
    sc!(333,"io_pgetevents",     Misc,       5, [UnsignedLong,Long,Long,PtrMut,PtrConst,Unused]),
    sc!(334,"rseq",              Misc,       4, [PtrMut,UnsignedInt,Int,UnsignedInt,Unused,Unused]),
    sc!(424,"pidfd_send_signal", Signal,     4, [Fd,Signal,PtrConst,UnsignedInt,Unused,Unused]),
    sc!(425,"io_uring_setup",    Misc,       2, [UnsignedInt,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(426,"io_uring_enter",    Misc,       6, [Fd,UnsignedInt,UnsignedInt,UnsignedInt,PtrConst,Size]),
    sc!(427,"io_uring_register", Misc,       4, [Fd,UnsignedInt,PtrMut,UnsignedInt,Unused,Unused]),
    sc!(428,"open_tree",         FileSystem, 3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(429,"move_mount",        FileSystem, 5, [Fd,PtrConst,Fd,PtrConst,UnsignedInt,Unused]),
    sc!(430,"fsopen",            FileSystem, 2, [PtrConst,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(431,"fsconfig",          FileSystem, 5, [Fd,UnsignedInt,PtrConst,PtrConst,Int,Unused]),
    sc!(432,"fsmount",           FileSystem, 3, [Fd,UnsignedInt,UnsignedInt,Unused,Unused,Unused]),
    sc!(433,"fspick",            FileSystem, 3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(434,"pidfd_open",        Process,    2, [Pid,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(435,"clone3",            Process,    2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(436,"close_range",       FileSystem, 3, [UnsignedInt,UnsignedInt,UnsignedInt,Unused,Unused,Unused]),
    sc!(437,"openat2",           FileSystem, 4, [Fd,PtrConst,PtrConst,Size,Unused,Unused]),
    sc!(438,"pidfd_getfd",       Process,    3, [Fd,Fd,UnsignedInt,Unused,Unused,Unused]),
    sc!(439,"faccessat2",        FileSystem, 4, [Fd,PtrConst,Int,Int,Unused,Unused]),
    sc!(440,"process_madvise",   Process,    5, [Fd,PtrConst,Size,Int,UnsignedInt,Unused]),
    sc!(441,"epoll_pwait2",      FileSystem, 5, [Fd,PtrMut,Int,PtrConst,PtrConst,Unused]),
    sc!(442,"mount_setattr",     FileSystem, 5, [Fd,PtrConst,UnsignedInt,PtrMut,Size,Unused]),
    sc!(443,"quotactl_fd",       FileSystem, 4, [Fd,UnsignedInt,Int,PtrMut,Unused,Unused]),
    sc!(444,"landlock_create_ruleset", Security, 3, [PtrConst,Size,UnsignedInt,Unused,Unused,Unused]),
    sc!(445,"landlock_add_rule",       Security, 4, [Fd,UnsignedInt,PtrConst,UnsignedInt,Unused,Unused]),
    sc!(446,"landlock_restrict_self",  Security, 2, [Fd,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(447,"memfd_secret",      Memory,     1, [UnsignedInt,Unused,Unused,Unused,Unused,Unused]),
    sc!(448,"process_mrelease",  Process,    2, [Fd,UnsignedInt,Unused,Unused,Unused,Unused]),
];

// ---------------------------------------------------------------------------
// ARM64 (aarch64) — representative subset
// ---------------------------------------------------------------------------

pub static ARM64_SYSCALLS: &[LinuxSyscallEntry] = &[
    sc!(0,  "io_setup",          Misc,       2, [UnsignedInt,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(1,  "io_destroy",        Misc,       1, [UnsignedLong,Unused,Unused,Unused,Unused,Unused]),
    sc!(3,  "io_submit",         Misc,       3, [UnsignedLong,Long,PtrMut,Unused,Unused,Unused]),
    sc!(4,  "io_cancel",         Misc,       3, [UnsignedLong,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(5,  "io_getevents",      Misc,       5, [UnsignedLong,Long,Long,PtrMut,PtrConst,Unused]),
    sc!(19, "eventfd2",          Misc,       2, [UnsignedInt,Int,Unused,Unused,Unused,Unused]),
    sc!(20, "epoll_create1",     FileSystem, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(21, "epoll_ctl",         FileSystem, 4, [Fd,Int,Fd,PtrMut,Unused,Unused]),
    sc!(22, "epoll_pwait",       FileSystem, 5, [Fd,PtrMut,Int,Int,PtrConst,Unused]),
    sc!(23, "dup",               FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(24, "dup3",              FileSystem, 3, [Fd,Fd,Int,Unused,Unused,Unused]),
    sc!(25, "fcntl",             FileSystem, 3, [Fd,UnsignedInt,UnsignedLong,Unused,Unused,Unused]),
    sc!(26, "inotify_init1",     FileSystem, 1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(27, "inotify_add_watch", FileSystem, 3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(28, "inotify_rm_watch",  FileSystem, 2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(29, "ioctl",             Device,     3, [Fd,UnsignedLong,UnsignedLong,Unused,Unused,Unused]),
    sc!(32, "flock",             FileSystem, 2, [Fd,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(33, "mknodat",           FileSystem, 4, [Fd,PtrConst,Mode,UnsignedInt,Unused,Unused]),
    sc!(34, "mkdirat",           FileSystem, 3, [Fd,PtrConst,Mode,Unused,Unused,Unused]),
    sc!(35, "unlinkat",          FileSystem, 3, [Fd,PtrConst,Int,Unused,Unused,Unused]),
    sc!(36, "symlinkat",         FileSystem, 3, [PtrConst,Fd,PtrConst,Unused,Unused,Unused]),
    sc!(37, "linkat",            FileSystem, 5, [Fd,PtrConst,Fd,PtrConst,Int,Unused]),
    sc!(38, "renameat",          FileSystem, 4, [Fd,PtrConst,Fd,PtrConst,Unused,Unused]),
    sc!(56, "openat",            FileSystem, 4, [Fd,PtrConst,Int,Mode,Unused,Unused]),
    sc!(57, "close",             FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(59, "pipe2",             FileSystem, 2, [PtrMut,Int,Unused,Unused,Unused,Unused]),
    sc!(61, "getdents64",        FileSystem, 3, [Fd,PtrMut,UnsignedInt,Unused,Unused,Unused]),
    sc!(62, "lseek",             FileSystem, 3, [Fd,Offset,UnsignedInt,Unused,Unused,Unused]),
    sc!(63, "read",              FileSystem, 3, [Fd,PtrMut,Size,Unused,Unused,Unused]),
    sc!(64, "write",             FileSystem, 3, [Fd,PtrConst,Size,Unused,Unused,Unused]),
    sc!(93, "exit",              Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(94, "exit_group",        Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(96, "set_tid_address",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(99, "set_robust_list",   Misc,       2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(100,"get_robust_list",   Misc,       3, [Int,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(101,"nanosleep",         Time,       2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(113,"clock_gettime",     Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(115,"clock_nanosleep",   Time,       4, [Int,Int,PtrConst,PtrMut,Unused,Unused]),
    sc!(117,"clock_adjtime",     Time,       2, [Int,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(131,"tgkill",            Signal,     3, [Pid,Pid,Signal,Unused,Unused,Unused]),
    sc!(160,"uname",             Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(172,"getpid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(173,"getppid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(174,"getuid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(175,"geteuid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(176,"getgid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(177,"getegid",           Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(178,"gettid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(179,"sysinfo",           Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(198,"socket",            Network,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(199,"socketpair",        Network,    4, [Int,Int,Int,PtrMut,Unused,Unused]),
    sc!(200,"bind",              Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(201,"listen",            Network,    2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(202,"accept",            Network,    3, [Fd,PtrMut,PtrMut,Unused,Unused,Unused]),
    sc!(203,"connect",           Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(206,"sendto",            Network,    6, [Fd,PtrConst,Size,Int,PtrConst,UnsignedInt]),
    sc!(207,"recvfrom",          Network,    6, [Fd,PtrMut,Size,Int,PtrMut,PtrMut]),
    sc!(220,"clone",             Process,    5, [UnsignedLong,PtrMut,PtrMut,PtrMut,PtrMut,Unused]),
    sc!(221,"execve",            Process,    3, [PtrConst,PtrConst,PtrConst,Unused,Unused,Unused]),
    sc!(222,"mmap",              Memory,     6, [PtrMut,Size,Int,Int,Fd,Offset]),
    sc!(226,"mprotect",          Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(227,"msync",             Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(228,"mlock",             Memory,     2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(229,"munlock",           Memory,     2, [PtrConst,Size,Unused,Unused,Unused,Unused]),
    sc!(233,"madvise",           Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(261,"prlimit64",         Process,    4, [Pid,UnsignedInt,PtrConst,PtrMut,Unused,Unused]),
    sc!(278,"getrandom",         Security,   3, [PtrMut,Size,UnsignedInt,Unused,Unused,Unused]),
    sc!(281,"memfd_create",      Memory,     2, [PtrConst,UnsignedInt,Unused,Unused,Unused,Unused]),
    sc!(435,"clone3",            Process,    2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
];

// ---------------------------------------------------------------------------
// ARM (32-bit) — representative subset
// ---------------------------------------------------------------------------

pub static ARM_SYSCALLS: &[LinuxSyscallEntry] = &[
    sc!(1,  "exit",              Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(2,  "fork",              Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(3,  "read",              FileSystem, 3, [Fd,PtrMut,Size,Unused,Unused,Unused]),
    sc!(4,  "write",             FileSystem, 3, [Fd,PtrConst,Size,Unused,Unused,Unused]),
    sc!(5,  "open",              FileSystem, 3, [PtrConst,Flags,Mode,Unused,Unused,Unused]),
    sc!(6,  "close",             FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(11, "execve",            Process,    3, [PtrConst,PtrConst,PtrConst,Unused,Unused,Unused]),
    sc!(20, "getpid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(37, "kill",              Signal,     2, [Pid,Signal,Unused,Unused,Unused,Unused]),
    sc!(45, "brk",               Memory,     1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(54, "ioctl",             Device,     3, [Fd,UnsignedInt,UnsignedLong,Unused,Unused,Unused]),
    sc!(90, "mmap",              Memory,     6, [PtrMut,Size,Int,Int,Fd,Offset]),
    sc!(91, "munmap",            Memory,     2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(125,"mprotect",          Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(162,"nanosleep",         Time,       2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(186,"sigaltstack",       Signal,     2, [PtrConst,PtrMut,Unused,Unused,Unused,Unused]),
    sc!(224,"gettid",            Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(240,"futex",             Misc,       6, [PtrMut,Int,UnsignedInt,PtrConst,PtrMut,UnsignedInt]),
    sc!(243,"set_thread_area",   Misc,       1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(252,"exit_group",        Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(281,"socket",            Network,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(283,"bind",              Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(284,"connect",           Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(285,"listen",            Network,    2, [Fd,Int,Unused,Unused,Unused,Unused]),
    sc!(288,"sendto",            Network,    6, [Fd,PtrConst,Size,Int,PtrConst,UnsignedInt]),
    sc!(289,"recvfrom",          Network,    6, [Fd,PtrMut,Size,Int,PtrMut,PtrMut]),
    sc!(374,"getrandom",         Security,   3, [PtrMut,Size,UnsignedInt,Unused,Unused,Unused]),
];

// ---------------------------------------------------------------------------
// MIPS O32 (32-bit) — representative subset (offset base 4000)
// ---------------------------------------------------------------------------

pub static MIPS_SYSCALLS: &[LinuxSyscallEntry] = &[
    sc!(4001, "exit",     Process,    1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(4002, "fork",     Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(4003, "read",     FileSystem, 3, [Fd,PtrMut,Size,Unused,Unused,Unused]),
    sc!(4004, "write",    FileSystem, 3, [Fd,PtrConst,Size,Unused,Unused,Unused]),
    sc!(4005, "open",     FileSystem, 3, [PtrConst,Flags,Mode,Unused,Unused,Unused]),
    sc!(4006, "close",    FileSystem, 1, [Fd,Unused,Unused,Unused,Unused,Unused]),
    sc!(4011, "execve",   Process,    3, [PtrConst,PtrConst,PtrConst,Unused,Unused,Unused]),
    sc!(4020, "getpid",   Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(4037, "kill",     Signal,     2, [Pid,Signal,Unused,Unused,Unused,Unused]),
    sc!(4045, "brk",      Memory,     1, [PtrMut,Unused,Unused,Unused,Unused,Unused]),
    sc!(4054, "ioctl",    Device,     3, [Fd,UnsignedInt,UnsignedLong,Unused,Unused,Unused]),
    sc!(4090, "mmap",     Memory,     6, [PtrMut,Size,Int,Int,Fd,Offset]),
    sc!(4091, "munmap",   Memory,     2, [PtrMut,Size,Unused,Unused,Unused,Unused]),
    sc!(4125, "mprotect", Memory,     3, [PtrMut,Size,Int,Unused,Unused,Unused]),
    sc!(4183, "rt_sigaction", Signal, 4, [Signal,PtrConst,PtrMut,Size,Unused,Unused]),
    sc!(4238, "gettid",   Process,    0, [Unused,Unused,Unused,Unused,Unused,Unused]),
    sc!(4246, "exit_group", Process,  1, [Int,Unused,Unused,Unused,Unused,Unused]),
    sc!(4291, "socket",   Network,    3, [Int,Int,Int,Unused,Unused,Unused]),
    sc!(4293, "bind",     Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(4294, "connect",  Network,    3, [Fd,PtrConst,UnsignedInt,Unused,Unused,Unused]),
    sc!(4353, "getrandom",Security,   3, [PtrMut,Size,UnsignedInt,Unused,Unused,Unused]),
];

// ---------------------------------------------------------------------------
// ArchSyscalls — per-architecture container
// ---------------------------------------------------------------------------

pub struct ArchSyscalls {
    pub arch: LinuxArch,
    pub entries: &'static [LinuxSyscallEntry],
}

impl ArchSyscalls {
    #[must_use] 
    pub fn by_number(&self, nr: u32) -> Option<&LinuxSyscallEntry> {
        self.entries.iter().find(|e| e.number == nr)
    }

    #[must_use] 
    pub fn by_name(&self, name: &str) -> Option<&LinuxSyscallEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn of_category(&self, cat: SyscallCategory) -> impl Iterator<Item = &LinuxSyscallEntry> {
        self.entries.iter().filter(move |e| e.category == cat)
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

pub static ARCH_X86_64: ArchSyscalls = ArchSyscalls { arch: LinuxArch::X86_64, entries: X86_64_SYSCALLS };
pub static ARCH_ARM64:  ArchSyscalls = ArchSyscalls { arch: LinuxArch::Arm64,  entries: ARM64_SYSCALLS  };
pub static ARCH_ARM:    ArchSyscalls = ArchSyscalls { arch: LinuxArch::Arm,    entries: ARM_SYSCALLS    };
pub static ARCH_MIPS:   ArchSyscalls = ArchSyscalls { arch: LinuxArch::Mips,   entries: MIPS_SYSCALLS   };

// ---------------------------------------------------------------------------
// LinuxSyscallTable — top-level lookup
// ---------------------------------------------------------------------------

pub struct LinuxSyscallTable {
    by_arch: HashMap<LinuxArch, &'static ArchSyscalls>,
}

impl LinuxSyscallTable {
    #[must_use] 
    pub fn new() -> Self {
        let mut by_arch: HashMap<LinuxArch, &'static ArchSyscalls> = HashMap::new();
        by_arch.insert(LinuxArch::X86_64, &ARCH_X86_64);
        by_arch.insert(LinuxArch::Arm64,  &ARCH_ARM64);
        by_arch.insert(LinuxArch::Arm,    &ARCH_ARM);
        by_arch.insert(LinuxArch::Mips,   &ARCH_MIPS);
        Self { by_arch }
    }

    #[must_use] 
    pub fn arch(&self, arch: LinuxArch) -> Option<&ArchSyscalls> {
        self.by_arch.get(&arch).copied()
    }

    #[must_use] 
    pub fn lookup(&self, arch: LinuxArch, nr: u32) -> Option<&LinuxSyscallEntry> {
        self.arch(arch)?.by_number(nr)
    }

    #[must_use] 
    pub fn lookup_name(&self, arch: LinuxArch, name: &str) -> Option<&LinuxSyscallEntry> {
        self.arch(arch)?.by_name(name)
    }

    /// Cross-architecture search by syscall name.
    #[must_use] 
    pub fn search_all_arches(&self, name: &str) -> Vec<(LinuxArch, &LinuxSyscallEntry)> {
        let mut results = Vec::new();
        for (&arch, table) in &self.by_arch {
            if let Some(e) = table.by_name(name) {
                results.push((arch, e));
            }
        }
        results
    }

    /// Find syscalls with pointer args (potential attack surface).
    #[must_use] 
    pub fn pointer_syscalls(&self, arch: LinuxArch) -> Vec<&LinuxSyscallEntry> {
        self.arch(arch).map_or_else(Vec::new, |t| {
            t.entries.iter()
                .filter(|e| e.args.iter().any(ArgKind::is_pointer))
                .collect()
        })
    }

    /// Active syscalls for a given kernel version (respects `added_in/removed_in`).
    #[must_use] 
    pub fn active_for_kernel(&self, arch: LinuxArch, ver: KernelVersion) -> Vec<&LinuxSyscallEntry> {
        self.arch(arch).map_or_else(Vec::new, |t| {
            t.entries.iter().filter(|e| e.active_in(ver)).collect()
        })
    }
}

impl Default for LinuxSyscallTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_has_read_at_0() {
        let e = ARCH_X86_64.by_number(0).expect("read must exist at 0");
        assert_eq!(e.name, "read");
        assert_eq!(e.args.count, 3);
    }

    #[test]
    fn x86_64_has_write_at_1() {
        let e = ARCH_X86_64.by_number(1).expect("write must exist at 1");
        assert_eq!(e.name, "write");
    }

    #[test]
    fn lookup_exit_group() {
        let tbl = LinuxSyscallTable::new();
        let e = tbl.lookup(LinuxArch::X86_64, 231).expect("exit_group");
        assert_eq!(e.name, "exit_group");
        assert_eq!(e.category, SyscallCategory::Process);
    }

    #[test]
    fn arm64_read_is_63() {
        let e = ARCH_ARM64.by_number(63).expect("read on arm64");
        assert_eq!(e.name, "read");
    }

    #[test]
    fn mips_base_offset() {
        let e = ARCH_MIPS.by_number(4001).expect("exit on mips");
        assert_eq!(e.name, "exit");
    }

    #[test]
    fn search_all_arches_open() {
        let tbl = LinuxSyscallTable::new();
        let results = tbl.search_all_arches("open");
        assert!(!results.is_empty());
    }

    #[test]
    fn kernel_version_ordering() {
        assert!(KernelVersion::V5_0 > KernelVersion::V4_0);
        assert!(KernelVersion::V6_0 > KernelVersion::V5_0);
    }

    #[test]
    fn x86_64_count_at_least_300() {
        assert!(ARCH_X86_64.count() >= 300);
    }

    #[test]
    fn category_filter_network() {
        let net: Vec<_> = ARCH_X86_64.of_category(SyscallCategory::Network).collect();
        assert!(net.len() >= 10);
        for e in &net {
            assert_eq!(e.category, SyscallCategory::Network);
        }
    }
}
