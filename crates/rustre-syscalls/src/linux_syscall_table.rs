//! `linux_syscall_table` — A structured, queryable Linux syscall table
//! supporting multiple ABI flavours (x86, x86-64, ARM32, ARM64, MIPS, RISC-V).
//!
//! The primary entry point is [`LinuxSyscallTable`]. Individual entries are
//! represented by [`SyscallEntry`], and the ABI variant is expressed through
//! [`SyscallAbi`].
//!
//! # Relationship to `syscall_table_linux`
//!
//! This module is intentionally distinct from [`super::syscall_table_linux`]:
//! - **`linux_syscall_table`** (this module): multi-ABI focus (including
//!   RISC-V64), entries carry `risk: RiskLevel` and `aliases`, serde support,
//!   comprehensive test coverage, `merge` and `category_stats` helpers.
//! - **`syscall_table_linux`**: most comprehensive `x86_64` table (~350 entries),
//!   per-entry kernel version tracking (`KernelVersion`), typed `ArgKind`/
//!   `SyscallArgs` (all 6 argument slots), compile-time static tables.
//!
//! Use `linux_syscall_table` for risk-scored queries, ABI register info, or
//! serde-serialisable entries; use `syscall_table_linux` when you need the
//! fullest `x86_64` table, per-argument types, or kernel-version filtering.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{RiskLevel, SyscallCategory};

// ─── SyscallAbi ───────────────────────────────────────────────────────────────

/// Linux syscall ABI variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallAbi {
    /// `x86` 32-bit (`int 0x80` / `sysenter`).
    X86,
    /// `x86-64` 64-bit (`syscall` instruction).
    X86_64,
    /// ARM 32-bit (`swi 0` / `svc #0`).
    Arm32,
    /// ARM 64-bit / `AArch64` (`svc #0`).
    Arm64,
    /// MIPS 32-bit (`syscall`).
    Mips32,
    /// MIPS 64-bit (`syscall`).
    Mips64,
    /// RISC-V 64-bit (`ecall`).
    Riscv64,
    /// x86 32-bit compatibility layer on x86-64.
    X86Compat,
}

impl fmt::Display for SyscallAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips32 => write!(f, "mips32"),
            Self::Mips64 => write!(f, "mips64"),
            Self::Riscv64 => write!(f, "riscv64"),
            Self::X86Compat => write!(f, "x86_compat"),
        }
    }
}

impl SyscallAbi {
    /// Returns the calling-convention register used to pass the syscall number.
    #[must_use]
    pub const fn syscall_nr_reg(self) -> &'static str {
        match self {
            Self::X86 | Self::X86Compat => "eax",
            Self::X86_64 => "rax",
            Self::Arm32 => "r7",
            Self::Arm64 => "x8",
            Self::Mips32 | Self::Mips64 => "v0",
            Self::Riscv64 => "a7",
        }
    }

    /// Returns the register that holds the return value after the syscall.
    #[must_use]
    pub const fn return_reg(self) -> &'static str {
        match self {
            Self::X86 | Self::X86Compat => "eax",
            Self::X86_64 => "rax",
            Self::Arm32 => "r0",
            Self::Arm64 => "x0",
            Self::Mips32 | Self::Mips64 => "v0",
            Self::Riscv64 => "a0",
        }
    }

    /// Returns up to six argument registers for this ABI (in order).
    #[must_use]
    pub fn arg_regs(self) -> Vec<&'static str> {
        match self {
            Self::X86 | Self::X86Compat => {
                vec!["ebx", "ecx", "edx", "esi", "edi", "ebp"]
            }
            Self::X86_64 => vec!["rdi", "rsi", "rdx", "r10", "r8", "r9"],
            Self::Arm32 => vec!["r0", "r1", "r2", "r3", "r4", "r5"],
            Self::Arm64 => vec!["x0", "x1", "x2", "x3", "x4", "x5"],
            Self::Mips32 | Self::Mips64 => {
                vec!["a0", "a1", "a2", "a3", "a4", "a5"]
            }
            Self::Riscv64 => vec!["a0", "a1", "a2", "a3", "a4", "a5"],
        }
    }

    /// Returns the trap instruction mnemonic for this ABI.
    #[must_use]
    pub const fn trap_instruction(self) -> &'static str {
        match self {
            Self::X86 | Self::X86Compat => "int 0x80",
            Self::X86_64 | Self::Mips32 | Self::Mips64 => "syscall",
            Self::Arm32 | Self::Arm64 => "svc #0",
            Self::Riscv64 => "ecall",
        }
    }

    /// Pointer width in bytes.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::X86 | Self::Arm32 | Self::Mips32 | Self::X86Compat => 4,
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::Riscv64 => 8,
        }
    }
}

// ─── SyscallEntry ─────────────────────────────────────────────────────────────

/// One entry in a [`LinuxSyscallTable`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Syscall number as defined by the kernel headers.
    pub number: u64,
    /// Canonical syscall name (e.g. `"read"`, `"mmap2"`).
    pub name: String,
    /// Semantic category.
    pub category: SyscallCategory,
    /// Security risk level.
    pub risk: RiskLevel,
    /// Number of user-space arguments.
    pub arg_count: u8,
    /// Short human-readable description.
    pub description: String,
    /// Whether this is a kernel-internal or pseudo syscall.
    pub internal: bool,
    /// Alternative names / aliases for this syscall.
    pub aliases: Vec<String>,
}

impl SyscallEntry {
    /// Create a new entry with minimal information.
    #[must_use]
    pub fn new(
        number: u64,
        name: impl Into<String>,
        category: SyscallCategory,
        arg_count: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            number,
            name: name.into(),
            category,
            risk: RiskLevel::Low,
            arg_count,
            description: description.into(),
            internal: false,
            aliases: Vec::new(),
        }
    }

    /// Set the risk level.
    #[must_use]
    pub const fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }

    /// Mark as kernel-internal.
    #[must_use]
    pub const fn internal(mut self) -> Self {
        self.internal = true;
        self
    }

    /// Add an alias.
    #[must_use]
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    /// Returns `true` when this entry matches the given name (including aliases).
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        self.name == name || self.aliases.iter().any(|a| a == name)
    }
}

impl fmt::Display for SyscallEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:4}  {:<32}  {:4} args  {:?}  {}",
            self.number, self.name, self.arg_count, self.category, self.description
        )
    }
}

// ─── LinuxSyscallTable ────────────────────────────────────────────────────────

/// A queryable table of Linux syscall entries for one or more ABIs.
#[derive(Debug, Default)]
pub struct LinuxSyscallTable {
    /// Primary ABI of this table.
    pub abi: Option<SyscallAbi>,
    /// Entries indexed by syscall number.
    by_number: HashMap<u64, SyscallEntry>,
    /// Secondary index: name → number.
    name_index: HashMap<String, u64>,
}

impl LinuxSyscallTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a table for a specific ABI.
    #[must_use]
    pub fn for_abi(abi: SyscallAbi) -> Self {
        Self {
            abi: Some(abi),
            ..Self::default()
        }
    }

    /// Insert a syscall entry.
    pub fn insert(&mut self, entry: SyscallEntry) {
        self.name_index.insert(entry.name.clone(), entry.number);
        for alias in &entry.aliases {
            self.name_index.insert(alias.clone(), entry.number);
        }
        self.by_number.insert(entry.number, entry);
    }

    /// Look up by number.
    #[must_use]
    pub fn lookup_by_number(&self, number: u64) -> Option<&SyscallEntry> {
        self.by_number.get(&number)
    }

    /// Look up by name (including aliases).
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&SyscallEntry> {
        let num = self.name_index.get(name)?;
        self.by_number.get(num)
    }

    /// Return the syscall name for a given number, or `"unknown"`.
    #[must_use]
    pub fn syscall_name(&self, number: u64) -> &str {
        self.by_number
            .get(&number)
            .map_or("unknown", |e| e.name.as_str())
    }

    /// Return all entries sorted by number.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&SyscallEntry> {
        let mut v: Vec<&SyscallEntry> = self.by_number.values().collect();
        v.sort_by_key(|e| e.number);
        v
    }

    /// Return all entries for a given category.
    #[must_use]
    pub fn by_category(&self, cat: SyscallCategory) -> Vec<&SyscallEntry> {
        let mut v: Vec<&SyscallEntry> = self
            .by_number
            .values()
            .filter(|e| e.category == cat)
            .collect();
        v.sort_by_key(|e| e.number);
        v
    }

    /// Return all entries at or above the given risk level.
    #[must_use]
    pub fn by_risk(&self, min_risk: RiskLevel) -> Vec<&SyscallEntry> {
        let mut v: Vec<&SyscallEntry> = self
            .by_number
            .values()
            .filter(|e| e.risk >= min_risk)
            .collect();
        v.sort_by_key(|e| e.number);
        v
    }

    /// Return the number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    /// Returns `true` when the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }

    /// Search for entries whose name contains `substr`.
    #[must_use]
    pub fn search(&self, substr: &str) -> Vec<&SyscallEntry> {
        let mut v: Vec<&SyscallEntry> = self
            .by_number
            .values()
            .filter(|e| e.name.contains(substr) || e.aliases.iter().any(|a| a.contains(substr)))
            .collect();
        v.sort_by_key(|e| e.number);
        v
    }

    /// Merge another table into this one (other takes precedence on conflict).
    pub fn merge(&mut self, other: Self) {
        for (_, entry) in other.by_number {
            self.insert(entry);
        }
    }

    /// Return per-category entry counts.
    #[must_use]
    pub fn category_stats(&self) -> HashMap<SyscallCategory, usize> {
        let mut map: HashMap<SyscallCategory, usize> = HashMap::new();
        for e in self.by_number.values() {
            *map.entry(e.category).or_default() += 1;
        }
        map
    }

    // ── Factory constructors ──────────────────────────────────────────────────

    /// Build the x86-64 Linux syscall table (NR 0–329, selected entries).
    #[must_use]
    pub fn linux_x86_64() -> Self {
        let mut t = Self::for_abi(SyscallAbi::X86_64);
        for &(nr, name, cat, args, desc, risk) in LINUX_X86_64_FULL {
            let e = SyscallEntry::new(nr, name, cat, args, desc).with_risk(risk);
            t.insert(e);
        }
        t
    }

    /// Build the ARM64/AArch64 Linux syscall table.
    #[must_use]
    pub fn linux_arm64() -> Self {
        let mut t = Self::for_abi(SyscallAbi::Arm64);
        for &(nr, name, cat, args, desc, risk) in LINUX_ARM64_FULL {
            let e = SyscallEntry::new(nr, name, cat, args, desc).with_risk(risk);
            t.insert(e);
        }
        t
    }

    /// Build a minimal x86 (32-bit) Linux syscall table.
    #[must_use]
    pub fn linux_x86() -> Self {
        let mut t = Self::for_abi(SyscallAbi::X86);
        for &(nr, name, cat, args, desc, risk) in LINUX_X86_ENTRIES {
            let e = SyscallEntry::new(nr, name, cat, args, desc).with_risk(risk);
            t.insert(e);
        }
        t
    }
}

/// Free-function shortcut matching the module contract.
///
/// Returns the syscall name for the given number in the specified ABI, or
/// `"unknown"` when not found.
#[must_use]
pub fn lookup_by_number(abi: SyscallAbi, number: u64) -> &'static str {
    let table: &[(u64, &str)] = match abi {
        SyscallAbi::X86_64 => LINUX_X86_64_NAMES,
        SyscallAbi::Arm64 => LINUX_ARM64_NAMES,
        SyscallAbi::X86 | SyscallAbi::X86Compat => LINUX_X86_NAMES,
        _ => return "unknown",
    };
    table
        .binary_search_by_key(&number, |&(n, _)| n)
        .map_or("unknown", |i| table[i].1)
}

// ─── Static name tables (binary-search-ready, sorted by number) ──────────────

static LINUX_X86_64_NAMES: &[(u64, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (16, "ioctl"),
    (21, "access"),
    (22, "pipe"),
    (32, "dup"),
    (33, "dup2"),
    (39, "getpid"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (62, "kill"),
    (72, "fcntl"),
    (101, "ptrace"),
    (105, "setuid"),
    (106, "setgid"),
    (157, "prctl"),
    (202, "futex"),
    (217, "getdents64"),
    (231, "exit_group"),
    (257, "openat"),
    (293, "pipe2"),
    (317, "seccomp"),
    (318, "getrandom"),
    (319, "memfd_create"),
    (321, "bpf"),
    (322, "execveat"),
];

static LINUX_ARM64_NAMES: &[(u64, &str)] = &[
    (17, "getcwd"),
    (19, "eventfd2"),
    (20, "epoll_create1"),
    (21, "epoll_ctl"),
    (23, "dup"),
    (24, "dup3"),
    (25, "fcntl"),
    (29, "ioctl"),
    (33, "mknodat"),
    (34, "mkdirat"),
    (35, "unlinkat"),
    (37, "linkat"),
    (39, "umount2"),
    (40, "mount"),
    (56, "openat"),
    (57, "close"),
    (63, "read"),
    (64, "write"),
    (80, "fstat"),
    (93, "exit"),
    (94, "exit_group"),
    (95, "waitid"),
    (98, "futex"),
    (101, "nanosleep"),
    (105, "init_module"),
    (106, "delete_module"),
    (117, "ptrace"),
    (129, "kill"),
    (131, "tgkill"),
    (167, "prctl"),
    (198, "socket"),
    (200, "bind"),
    (201, "listen"),
    (203, "connect"),
    (206, "sendto"),
    (207, "recvfrom"),
    (214, "brk"),
    (215, "munmap"),
    (220, "clone"),
    (221, "execve"),
    (222, "mmap"),
    (226, "mprotect"),
    (261, "prlimit64"),
    (277, "seccomp"),
    (278, "getrandom"),
    (279, "memfd_create"),
    (280, "bpf"),
    (281, "execveat"),
    (291, "statx"),
];

static LINUX_X86_NAMES: &[(u64, &str)] = &[
    (1, "exit"),
    (2, "fork"),
    (3, "read"),
    (4, "write"),
    (5, "open"),
    (6, "close"),
    (7, "waitpid"),
    (10, "unlink"),
    (11, "execve"),
    (12, "chdir"),
    (20, "getpid"),
    (25, "stime"),
    (26, "ptrace"),
    (33, "access"),
    (37, "kill"),
    (39, "mkdir"),
    (40, "rmdir"),
    (41, "dup"),
    (42, "pipe"),
    (45, "brk"),
    (54, "ioctl"),
    (63, "dup2"),
    (64, "getppid"),
    (90, "mmap"),
    (91, "munmap"),
    (102, "socketcall"),
    (125, "mprotect"),
    (162, "nanosleep"),
    (190, "vfork"),
    (192, "mmap2"),
    (224, "gettid"),
    (240, "futex"),
    (252, "exit_group"),
    (295, "openat"),
    (359, "socket"),
];

// ─── Rich entry tables ────────────────────────────────────────────────────────

type EntryRow = (u64, &'static str, SyscallCategory, u8, &'static str, RiskLevel);

static LINUX_X86_64_FULL: &[EntryRow] = &[
    (0,  "read",       SyscallCategory::FileSystem, 3, "Read from file descriptor",         RiskLevel::Low),
    (1,  "write",      SyscallCategory::FileSystem, 3, "Write to file descriptor",           RiskLevel::Low),
    (2,  "open",       SyscallCategory::FileSystem, 3, "Open file",                          RiskLevel::Low),
    (3,  "close",      SyscallCategory::FileSystem, 1, "Close file descriptor",              RiskLevel::Low),
    (4,  "stat",       SyscallCategory::FileSystem, 2, "Get file status",                    RiskLevel::Low),
    (5,  "fstat",      SyscallCategory::FileSystem, 2, "Get file status by fd",              RiskLevel::Low),
    (6,  "lstat",      SyscallCategory::FileSystem, 2, "Get link status",                    RiskLevel::Low),
    (8,  "lseek",      SyscallCategory::FileSystem, 3, "Reposition file offset",             RiskLevel::Low),
    (9,  "mmap",       SyscallCategory::Memory,     6, "Map files into memory",              RiskLevel::Medium),
    (10, "mprotect",   SyscallCategory::Memory,     3, "Set memory protection",              RiskLevel::High),
    (11, "munmap",     SyscallCategory::Memory,     2, "Unmap memory region",                RiskLevel::Low),
    (12, "brk",        SyscallCategory::Memory,     1, "Adjust program data segment",        RiskLevel::Low),
    (16, "ioctl",      SyscallCategory::Device,     3, "Device control",                     RiskLevel::Medium),
    (21, "access",     SyscallCategory::FileSystem, 2, "Check file access permissions",      RiskLevel::Low),
    (32, "dup",        SyscallCategory::FileSystem, 1, "Duplicate file descriptor",          RiskLevel::Low),
    (33, "dup2",       SyscallCategory::FileSystem, 2, "Duplicate fd to specific number",    RiskLevel::Low),
    (39, "getpid",     SyscallCategory::Process,    0, "Get process ID",                     RiskLevel::Low),
    (41, "socket",     SyscallCategory::Network,    3, "Create socket",                      RiskLevel::Medium),
    (42, "connect",    SyscallCategory::Network,    3, "Connect socket",                     RiskLevel::Medium),
    (43, "accept",     SyscallCategory::Network,    3, "Accept connection",                  RiskLevel::Medium),
    (44, "sendto",     SyscallCategory::Network,    6, "Send message",                       RiskLevel::Medium),
    (45, "recvfrom",   SyscallCategory::Network,    6, "Receive message",                    RiskLevel::Medium),
    (56, "clone",      SyscallCategory::Process,    5, "Create child process/thread",        RiskLevel::High),
    (57, "fork",       SyscallCategory::Process,    0, "Fork process",                       RiskLevel::High),
    (58, "vfork",      SyscallCategory::Process,    0, "Fork with copy-on-write semantics",  RiskLevel::High),
    (59, "execve",     SyscallCategory::Process,    3, "Execute program",                    RiskLevel::Critical),
    (60, "exit",       SyscallCategory::Process,    1, "Terminate process",                  RiskLevel::Low),
    (62, "kill",       SyscallCategory::Signal,     2, "Send signal to process",             RiskLevel::High),
    (72, "fcntl",      SyscallCategory::FileSystem, 3, "File control operations",            RiskLevel::Low),
    (101, "ptrace",    SyscallCategory::Process,    4, "Process trace",                      RiskLevel::Critical),
    (157, "prctl",     SyscallCategory::Process,    5, "Process control",                    RiskLevel::Medium),
    (202, "futex",     SyscallCategory::Thread,     6, "Fast user-space mutex",              RiskLevel::Low),
    (231, "exit_group",SyscallCategory::Process,    1, "Exit all threads in group",          RiskLevel::Low),
    (257, "openat",    SyscallCategory::FileSystem, 4, "Open file relative to dir fd",       RiskLevel::Low),
    (317, "seccomp",   SyscallCategory::Security,   3, "Operate on seccomp filter",          RiskLevel::High),
    (318, "getrandom", SyscallCategory::Security,   3, "Get random bytes",                   RiskLevel::Low),
    (319, "memfd_create", SyscallCategory::Memory,  2, "Create anonymous file",              RiskLevel::High),
    (321, "bpf",       SyscallCategory::System,     3, "BPF syscall",                        RiskLevel::Critical),
    (322, "execveat",  SyscallCategory::Process,    5, "Execute program relative to dir fd", RiskLevel::Critical),
];

static LINUX_ARM64_FULL: &[EntryRow] = &[
    (56,  "openat",    SyscallCategory::FileSystem, 4, "Open file relative to dir fd",       RiskLevel::Low),
    (57,  "close",     SyscallCategory::FileSystem, 1, "Close file descriptor",              RiskLevel::Low),
    (63,  "read",      SyscallCategory::FileSystem, 3, "Read from file descriptor",          RiskLevel::Low),
    (64,  "write",     SyscallCategory::FileSystem, 3, "Write to file descriptor",           RiskLevel::Low),
    (80,  "fstat",     SyscallCategory::FileSystem, 2, "Get file status by fd",              RiskLevel::Low),
    (93,  "exit",      SyscallCategory::Process,    1, "Terminate process",                  RiskLevel::Low),
    (94,  "exit_group",SyscallCategory::Process,    1, "Exit all threads in group",          RiskLevel::Low),
    (98,  "futex",     SyscallCategory::Thread,     6, "Fast user-space mutex",              RiskLevel::Low),
    (117, "ptrace",    SyscallCategory::Process,    4, "Process trace",                      RiskLevel::Critical),
    (129, "kill",      SyscallCategory::Signal,     2, "Send signal to process",             RiskLevel::High),
    (167, "prctl",     SyscallCategory::Process,    5, "Process control",                    RiskLevel::Medium),
    (198, "socket",    SyscallCategory::Network,    3, "Create socket",                      RiskLevel::Medium),
    (200, "bind",      SyscallCategory::Network,    3, "Bind socket to address",             RiskLevel::Medium),
    (203, "connect",   SyscallCategory::Network,    3, "Connect socket",                     RiskLevel::Medium),
    (206, "sendto",    SyscallCategory::Network,    6, "Send message",                       RiskLevel::Medium),
    (207, "recvfrom",  SyscallCategory::Network,    6, "Receive message",                    RiskLevel::Medium),
    (214, "brk",       SyscallCategory::Memory,     1, "Adjust program data segment",        RiskLevel::Low),
    (215, "munmap",    SyscallCategory::Memory,     2, "Unmap memory region",                RiskLevel::Low),
    (220, "clone",     SyscallCategory::Process,    5, "Create child process/thread",        RiskLevel::High),
    (221, "execve",    SyscallCategory::Process,    3, "Execute program",                    RiskLevel::Critical),
    (222, "mmap",      SyscallCategory::Memory,     6, "Map files into memory",              RiskLevel::Medium),
    (226, "mprotect",  SyscallCategory::Memory,     3, "Set memory protection",              RiskLevel::High),
    (277, "seccomp",   SyscallCategory::Security,   3, "Operate on seccomp filter",          RiskLevel::High),
    (278, "getrandom", SyscallCategory::Security,   3, "Get random bytes",                   RiskLevel::Low),
    (279, "memfd_create", SyscallCategory::Memory,  2, "Create anonymous file",              RiskLevel::High),
    (280, "bpf",       SyscallCategory::System,     3, "BPF syscall",                        RiskLevel::Critical),
    (281, "execveat",  SyscallCategory::Process,    5, "Execute program relative to dir fd", RiskLevel::Critical),
];

static LINUX_X86_ENTRIES: &[EntryRow] = &[
    (1,   "exit",      SyscallCategory::Process,    1, "Terminate process",                  RiskLevel::Low),
    (2,   "fork",      SyscallCategory::Process,    0, "Fork process",                       RiskLevel::High),
    (3,   "read",      SyscallCategory::FileSystem, 3, "Read from file descriptor",          RiskLevel::Low),
    (4,   "write",     SyscallCategory::FileSystem, 3, "Write to file descriptor",           RiskLevel::Low),
    (5,   "open",      SyscallCategory::FileSystem, 3, "Open file",                          RiskLevel::Low),
    (6,   "close",     SyscallCategory::FileSystem, 1, "Close file descriptor",              RiskLevel::Low),
    (11,  "execve",    SyscallCategory::Process,    3, "Execute program",                    RiskLevel::Critical),
    (20,  "getpid",    SyscallCategory::Process,    0, "Get process ID",                     RiskLevel::Low),
    (26,  "ptrace",    SyscallCategory::Process,    4, "Process trace",                      RiskLevel::Critical),
    (37,  "kill",      SyscallCategory::Signal,     2, "Send signal to process",             RiskLevel::High),
    (45,  "brk",       SyscallCategory::Memory,     1, "Adjust program data segment",        RiskLevel::Low),
    (90,  "mmap",      SyscallCategory::Memory,     6, "Map files into memory",              RiskLevel::Medium),
    (91,  "munmap",    SyscallCategory::Memory,     2, "Unmap memory region",                RiskLevel::Low),
    (125, "mprotect",  SyscallCategory::Memory,     3, "Set memory protection",              RiskLevel::High),
    (162, "nanosleep", SyscallCategory::Time,       2, "High-resolution sleep",              RiskLevel::Low),
    (192, "mmap2",     SyscallCategory::Memory,     6, "Map files (32-bit page offset)",     RiskLevel::Medium),
    (252, "exit_group",SyscallCategory::Process,    1, "Exit all threads in group",          RiskLevel::Low),
    (295, "openat",    SyscallCategory::FileSystem, 4, "Open file relative to dir fd",       RiskLevel::Low),
    (359, "socket",    SyscallCategory::Network,    3, "Create socket",                      RiskLevel::Medium),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_display() {
        assert_eq!(SyscallAbi::X86_64.to_string(), "x86_64");
        assert_eq!(SyscallAbi::Arm64.to_string(), "arm64");
    }

    #[test]
    fn test_abi_syscall_nr_reg() {
        assert_eq!(SyscallAbi::X86_64.syscall_nr_reg(), "rax");
        assert_eq!(SyscallAbi::Arm64.syscall_nr_reg(), "x8");
    }

    #[test]
    fn test_abi_pointer_size() {
        assert_eq!(SyscallAbi::X86_64.pointer_size(), 8);
        assert_eq!(SyscallAbi::X86.pointer_size(), 4);
    }

    #[test]
    fn test_lookup_by_number_x86_64() {
        assert_eq!(lookup_by_number(SyscallAbi::X86_64, 0), "read");
        assert_eq!(lookup_by_number(SyscallAbi::X86_64, 59), "execve");
        assert_eq!(lookup_by_number(SyscallAbi::X86_64, 9999), "unknown");
    }

    #[test]
    fn test_lookup_by_number_arm64() {
        assert_eq!(lookup_by_number(SyscallAbi::Arm64, 63), "read");
        assert_eq!(lookup_by_number(SyscallAbi::Arm64, 221), "execve");
    }

    #[test]
    fn test_lookup_by_number_x86() {
        assert_eq!(lookup_by_number(SyscallAbi::X86, 1), "exit");
        assert_eq!(lookup_by_number(SyscallAbi::X86, 11), "execve");
    }

    #[test]
    fn test_lookup_by_number_unknown_abi() {
        assert_eq!(lookup_by_number(SyscallAbi::Riscv64, 0), "unknown");
    }

    #[test]
    fn test_table_lookup_by_number() {
        let t = LinuxSyscallTable::linux_x86_64();
        let e = t.lookup_by_number(59).unwrap();
        assert_eq!(e.name, "execve");
        assert_eq!(e.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_table_lookup_by_name() {
        let t = LinuxSyscallTable::linux_x86_64();
        let e = t.lookup_by_name("mmap").unwrap();
        assert_eq!(e.number, 9);
    }

    #[test]
    fn test_table_syscall_name() {
        let t = LinuxSyscallTable::linux_x86_64();
        assert_eq!(t.syscall_name(0), "read");
        assert_eq!(t.syscall_name(9999), "unknown");
    }

    #[test]
    fn test_table_by_category() {
        let t = LinuxSyscallTable::linux_x86_64();
        let procs = t.by_category(SyscallCategory::Process);
        assert!(!procs.is_empty());
        assert!(procs.iter().all(|e| e.category == SyscallCategory::Process));
    }

    #[test]
    fn test_table_by_risk() {
        let t = LinuxSyscallTable::linux_x86_64();
        let critical = t.by_risk(RiskLevel::Critical);
        assert!(!critical.is_empty());
        assert!(critical.iter().all(|e| e.risk >= RiskLevel::Critical));
    }

    #[test]
    fn test_table_search() {
        let t = LinuxSyscallTable::linux_x86_64();
        let results = t.search("exec");
        assert!(results.iter().any(|e| e.name == "execve"));
    }

    #[test]
    fn test_entry_matches_name() {
        let mut e = SyscallEntry::new(2, "open", SyscallCategory::FileSystem, 3, "Open");
        e = e.with_alias("open64");
        assert!(e.matches_name("open"));
        assert!(e.matches_name("open64"));
        assert!(!e.matches_name("openat"));
    }

    #[test]
    fn test_table_category_stats() {
        let t = LinuxSyscallTable::linux_x86_64();
        let stats = t.category_stats();
        assert!(stats.contains_key(&SyscallCategory::Process));
        assert!(stats.contains_key(&SyscallCategory::Network));
    }

    #[test]
    fn test_merge() {
        let mut t1 = LinuxSyscallTable::linux_x86_64();
        let t2 = LinuxSyscallTable::linux_arm64();
        let before = t1.len();
        t1.merge(t2);
        assert!(t1.len() > before);
    }

    #[test]
    fn test_arm64_table_not_empty() {
        let t = LinuxSyscallTable::linux_arm64();
        assert!(!t.is_empty());
    }

    #[test]
    fn test_x86_table_execve() {
        let t = LinuxSyscallTable::linux_x86();
        let e = t.lookup_by_number(11).unwrap();
        assert_eq!(e.name, "execve");
    }
}
