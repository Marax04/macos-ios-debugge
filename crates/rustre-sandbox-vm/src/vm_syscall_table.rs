//! Virtual machine syscall table — maps syscall numbers to metadata and
//! handler callbacks for sandbox syscall interception and emulation.

use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Syscall argument types
// ---------------------------------------------------------------------------

/// The type of a syscall argument for documentation and tracing purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgType {
    /// Integer (signed or unsigned, any width).
    Int,
    /// Unsigned integer.
    UInt,
    /// Long integer.
    Long,
    /// Unsigned long integer.
    ULong,
    /// Pointer to untyped memory.
    Ptr,
    /// Pointer to a null-terminated string.
    CStr,
    /// File descriptor.
    Fd,
    /// Flags bitmask.
    Flags,
    /// Size / length value.
    Size,
    /// Offset value.
    Offset,
    /// Signal number.
    Signal,
    /// Process ID.
    Pid,
    /// User ID.
    Uid,
    /// Group ID.
    Gid,
    /// Socket address.
    SockAddr,
    /// Pointer to iovec array.
    IoVec,
    /// Pointer to a timespec struct.
    Timespec,
    /// Unknown / not documented.
    Unknown,
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ArgType::Int      => "int",
            ArgType::UInt     => "unsigned int",
            ArgType::Long     => "long",
            ArgType::ULong    => "unsigned long",
            ArgType::Ptr      => "void *",
            ArgType::CStr     => "const char *",
            ArgType::Fd       => "int (fd)",
            ArgType::Flags    => "flags",
            ArgType::Size     => "size_t",
            ArgType::Offset   => "off_t",
            ArgType::Signal   => "signum",
            ArgType::Pid      => "pid_t",
            ArgType::Uid      => "uid_t",
            ArgType::Gid      => "gid_t",
            ArgType::SockAddr => "struct sockaddr *",
            ArgType::IoVec    => "struct iovec *",
            ArgType::Timespec => "struct timespec *",
            ArgType::Unknown  => "?",
        };
        f.write_str(s)
    }
}

/// Describes a single syscall argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgDesc {
    /// Argument name.
    pub name: String,
    /// Argument type.
    pub ty: ArgType,
    /// Whether this argument is an output parameter (written by the kernel).
    pub is_output: bool,
}

impl ArgDesc {
    pub fn input(name: impl Into<String>, ty: ArgType) -> Self {
        ArgDesc { name: name.into(), ty, is_output: false }
    }
    pub fn output(name: impl Into<String>, ty: ArgType) -> Self {
        ArgDesc { name: name.into(), ty, is_output: true }
    }
}

// ---------------------------------------------------------------------------
// Syscall category
// ---------------------------------------------------------------------------

/// High-level category of a syscall.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    FileSystem,
    Network,
    Process,
    Memory,
    Ipc,
    Signals,
    Time,
    Security,
    Device,
    Scheduling,
    Debug,
    Crypto,
    Other,
}

impl fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SyscallCategory::FileSystem  => "filesystem",
            SyscallCategory::Network     => "network",
            SyscallCategory::Process     => "process",
            SyscallCategory::Memory      => "memory",
            SyscallCategory::Ipc         => "ipc",
            SyscallCategory::Signals     => "signals",
            SyscallCategory::Time        => "time",
            SyscallCategory::Security    => "security",
            SyscallCategory::Device      => "device",
            SyscallCategory::Scheduling  => "scheduling",
            SyscallCategory::Debug       => "debug",
            SyscallCategory::Crypto      => "crypto",
            SyscallCategory::Other       => "other",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// SyscallEntry
// ---------------------------------------------------------------------------

/// Metadata for a single syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Syscall number (ABI-specific).
    pub number: u64,
    /// Canonical name (e.g., "read", "`NtCreateFile`").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered list of argument descriptors.
    pub args: Vec<ArgDesc>,
    /// Return value type.
    pub return_type: ArgType,
    /// Functional category.
    pub category: SyscallCategory,
    /// Whether this syscall is considered sensitive (e.g., exec, mmap exec).
    pub is_sensitive: bool,
    /// Whether this syscall modifies the filesystem.
    pub modifies_fs: bool,
    /// Whether this syscall performs network I/O.
    pub is_network: bool,
    /// Whether this syscall creates a new process or thread.
    pub spawns_process: bool,
    /// Whether this syscall can load additional code (dlopen, mmap exec, etc.).
    pub loads_code: bool,
    /// Tags for custom classification.
    pub tags: Vec<String>,
}

impl SyscallEntry {
    /// Build a minimal entry with only number and name.
    pub fn minimal(number: u64, name: impl Into<String>) -> Self {
        SyscallEntry {
            number,
            name: name.into(),
            description: String::new(),
            args: Vec::new(),
            return_type: ArgType::Long,
            category: SyscallCategory::Other,
            is_sensitive: false,
            modifies_fs: false,
            is_network: false,
            spawns_process: false,
            loads_code: false,
            tags: Vec::new(),
        }
    }

    /// Return the number of input arguments.
    #[must_use] 
    pub fn input_arg_count(&self) -> usize {
        self.args.iter().filter(|a| !a.is_output).count()
    }

    /// Return the number of output arguments.
    #[must_use] 
    pub fn output_arg_count(&self) -> usize {
        self.args.iter().filter(|a| a.is_output).count()
    }

    /// Return a simple prototype string.
    #[must_use] 
    pub fn prototype(&self) -> String {
        let args: Vec<String> = self.args.iter()
            .map(|a| format!("{} {}", a.ty, a.name))
            .collect();
        format!("{} {}({})", self.return_type, self.name, args.join(", "))
    }

    /// Whether this syscall is dangerous from a sandbox perspective.
    #[must_use] 
    pub const fn is_dangerous(&self) -> bool {
        self.is_sensitive || self.spawns_process || self.loads_code
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Result returned by a syscall handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandlerResult {
    /// Allow the syscall to proceed; optionally override the return value.
    Allow { return_value: Option<i64> },
    /// Block the syscall and return the given error code to the guest.
    Block { errno: i32 },
    /// Redirect the syscall to a different number.
    Redirect { new_syscall: u64 },
    /// Terminate the sandboxed process immediately.
    Terminate,
}

impl HandlerResult {
    #[must_use] 
    pub const fn allow() -> Self { HandlerResult::Allow { return_value: None } }
    #[must_use] 
    pub const fn allow_with(ret: i64) -> Self { HandlerResult::Allow { return_value: Some(ret) } }
    #[must_use] 
    pub const fn block(errno: i32) -> Self { HandlerResult::Block { errno } }
    #[must_use] 
    pub const fn terminate() -> Self { HandlerResult::Terminate }
}

/// Context passed to a syscall handler.
#[derive(Debug, Clone)]
pub struct SyscallContext {
    /// The syscall number as seen by the guest.
    pub number: u64,
    /// Raw register arguments (up to 6 on most ABIs).
    pub args: [u64; 6],
    /// Thread ID of the calling thread (if known).
    pub tid: Option<u32>,
    /// Process ID of the calling process (if known).
    pub pid: Option<u32>,
}

impl SyscallContext {
    #[must_use] 
    pub const fn new(number: u64, args: [u64; 6]) -> Self {
        SyscallContext { number, args, tid: None, pid: None }
    }
}

/// A boxed function that handles a syscall.
pub type SyscallHandlerFn = Arc<dyn Fn(&SyscallContext) -> HandlerResult + Send + Sync>;

/// A registered syscall handler.
pub struct SyscallHandler {
    /// Entry metadata.
    pub entry: SyscallEntry,
    /// Optional handler function; if `None` the default policy is applied.
    pub handler: Option<SyscallHandlerFn>,
    /// Whether this handler overrides the default policy.
    pub overrides_policy: bool,
}

impl fmt::Debug for SyscallHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyscallHandler")
            .field("entry", &self.entry)
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

/// The policy applied when no specific handler is registered for a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultPolicy {
    /// Allow all unhandled syscalls.
    AllowAll,
    /// Block all unhandled syscalls with `EPERM`.
    BlockAll,
    /// Allow safe syscalls, block dangerous ones.
    BlockDangerous,
    /// Log and allow.
    LogAndAllow,
}

// ---------------------------------------------------------------------------
// VmSyscallTable
// ---------------------------------------------------------------------------

/// A thread-safe registry mapping syscall numbers to metadata and handlers.
///
/// The table is designed to be populated at setup time and queried at high
/// frequency during tracing.
pub struct VmSyscallTable {
    /// Platform identifier (e.g., "linux-x86_64", "windows-x64").
    pub platform: String,
    /// All registered handlers, keyed by syscall number.
    handlers: RwLock<HashMap<u64, SyscallHandler>>,
    /// Name → number index for fast lookup.
    name_index: RwLock<HashMap<String, u64>>,
    /// Category → numbers index.
    category_index: RwLock<HashMap<SyscallCategory, Vec<u64>>>,
    /// Default policy when no specific handler is found.
    default_policy: DefaultPolicy,
}

impl VmSyscallTable {
    /// Create an empty table for the given platform.
    pub fn new(platform: impl Into<String>, policy: DefaultPolicy) -> Self {
        VmSyscallTable {
            platform: platform.into(),
            handlers: RwLock::new(HashMap::new()),
            name_index: RwLock::new(HashMap::new()),
            category_index: RwLock::new(HashMap::new()),
            default_policy: policy,
        }
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a syscall entry, refusing duplicates instead of silently
    /// overwriting. Useful when initializing a table from multiple sources.
    pub fn register_checked(&self, entry: SyscallEntry) -> Result<()> {
        if self.handlers.read().contains_key(&entry.number) {
            bail!(
                "syscall {} ({}) already registered",
                entry.number,
                entry.name
            );
        }
        self.register(entry);
        Ok(())
    }

    /// Register a batch of entries, aborting on the first duplicate.
    /// On error, entries already inserted in this call are left in place
    /// (callers should snapshot/restore externally if atomicity is needed).
    pub fn register_all_checked(
        &self,
        entries: impl IntoIterator<Item = SyscallEntry>,
    ) -> Result<usize> {
        let mut inserted = 0usize;
        for e in entries {
            self.register_checked(e)?;
            inserted += 1;
        }
        Ok(inserted)
    }

    /// Register a syscall entry without a custom handler.
    pub fn register(&self, entry: SyscallEntry) {
        let num  = entry.number;
        let name = entry.name.clone();
        let cat  = entry.category.clone();
        let handler = SyscallHandler { entry, handler: None, overrides_policy: false };
        self.handlers.write().insert(num, handler);
        self.name_index.write().insert(name, num);
        self.category_index.write().entry(cat).or_default().push(num);
    }

    /// Register a syscall entry with a custom handler function.
    pub fn register_with_handler(
        &self,
        entry: SyscallEntry,
        handler_fn: SyscallHandlerFn,
    ) {
        let num  = entry.number;
        let name = entry.name.clone();
        let cat  = entry.category.clone();
        let handler = SyscallHandler {
            entry,
            handler: Some(handler_fn),
            overrides_policy: true,
        };
        self.handlers.write().insert(num, handler);
        self.name_index.write().insert(name, num);
        self.category_index.write().entry(cat).or_default().push(num);
    }

    /// Remove a syscall from the table.
    pub fn unregister(&self, number: u64) -> bool {
        let removed = self.handlers.write().remove(&number);
        if let Some(h) = &removed {
            self.name_index.write().remove(&h.entry.name);
        }
        removed.is_some()
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Look up a syscall by number.
    pub fn lookup(&self, number: u64) -> Option<SyscallEntry> {
        self.handlers.read().get(&number).map(|h| h.entry.clone())
    }

    /// Look up a syscall by name.
    pub fn lookup_by_name(&self, name: &str) -> Option<SyscallEntry> {
        let num = *self.name_index.read().get(name)?;
        self.lookup(num)
    }

    /// Return all syscall numbers registered for a category.
    pub fn by_category(&self, cat: &SyscallCategory) -> Vec<u64> {
        self.category_index.read().get(cat).cloned().unwrap_or_default()
    }

    /// Return all sensitive syscall entries.
    pub fn sensitive_entries(&self) -> Vec<SyscallEntry> {
        self.handlers.read().values()
            .filter(|h| h.entry.is_sensitive)
            .map(|h| h.entry.clone())
            .collect()
    }

    /// Return all dangerous syscall entries.
    pub fn dangerous_entries(&self) -> Vec<SyscallEntry> {
        self.handlers.read().values()
            .filter(|h| h.entry.is_dangerous())
            .map(|h| h.entry.clone())
            .collect()
    }

    /// Total number of registered syscalls.
    pub fn len(&self) -> usize {
        self.handlers.read().len()
    }

    /// Return `true` if no syscalls are registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.read().is_empty()
    }

    // -----------------------------------------------------------------------
    // Handler dispatch
    // -----------------------------------------------------------------------

    /// Dispatch a syscall, applying the handler or falling back to policy.
    pub fn dispatch(&self, ctx: &SyscallContext) -> HandlerResult {
        let guard = self.handlers.read();
        if let Some(h) = guard.get(&ctx.number) {
            if let Some(ref f) = h.handler {
                return f(ctx);
            }
            // Apply policy based on entry metadata.
            return match self.default_policy {
                DefaultPolicy::AllowAll    => HandlerResult::allow(),
                DefaultPolicy::BlockAll    => HandlerResult::block(1 /* EPERM */),
                DefaultPolicy::BlockDangerous => {
                    if h.entry.is_dangerous() { HandlerResult::block(1) } else { HandlerResult::allow() }
                }
                DefaultPolicy::LogAndAllow => HandlerResult::allow(),
            };
        }
        // Unknown syscall — apply default policy.
        match self.default_policy {
            DefaultPolicy::AllowAll    => HandlerResult::allow(),
            DefaultPolicy::BlockAll    => HandlerResult::block(1),
            DefaultPolicy::BlockDangerous => HandlerResult::block(1),
            DefaultPolicy::LogAndAllow => HandlerResult::allow(),
        }
    }

    // -----------------------------------------------------------------------
    // Batch operations
    // -----------------------------------------------------------------------

    /// Register all entries from an iterator.
    pub fn register_all(&self, entries: impl IntoIterator<Item = SyscallEntry>) {
        for entry in entries { self.register(entry); }
    }

    /// Return all registered entry numbers sorted.
    pub fn all_numbers(&self) -> Vec<u64> {
        let mut nums: Vec<u64> = self.handlers.read().keys().copied().collect();
        nums.sort_unstable();
        nums
    }

    /// Return all registered entry names sorted.
    pub fn all_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.name_index.read().keys().cloned().collect();
        names.sort();
        names
    }
}

// ---------------------------------------------------------------------------
// Platform tables
// ---------------------------------------------------------------------------

/// Build the Linux x86-64 syscall table (a representative subset).
#[must_use] 
pub fn linux_x86_64_table() -> VmSyscallTable {
    use SyscallCategory::{FileSystem, Memory, Process, Network, Signals, Security, Time, Debug};
    use ArgType::{Fd, Ptr, Size, CStr, Flags, Offset, Int, SockAddr, UInt, Signal, Pid, Timespec};

    let table = VmSyscallTable::new("linux-x86_64", DefaultPolicy::BlockDangerous);

    let entries: Vec<SyscallEntry> = vec![
        // File system
        {
            let mut e = SyscallEntry::minimal(0, "read");
            e.description = "Read from a file descriptor".into();
            e.category = FileSystem;
            e.args = vec![
                ArgDesc::input("fd", Fd),
                ArgDesc::output("buf", Ptr),
                ArgDesc::input("count", Size),
            ];
            e
        },
        {
            let mut e = SyscallEntry::minimal(1, "write");
            e.description = "Write to a file descriptor".into();
            e.category = FileSystem;
            e.args = vec![
                ArgDesc::input("fd", Fd),
                ArgDesc::input("buf", Ptr),
                ArgDesc::input("count", Size),
            ];
            e.modifies_fs = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(2, "open");
            e.description = "Open a file".into();
            e.category = FileSystem;
            e.args = vec![
                ArgDesc::input("pathname", CStr),
                ArgDesc::input("flags", Flags),
                ArgDesc::input("mode", Flags),
            ];
            e.modifies_fs = true;
            e.is_sensitive = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(3, "close");
            e.description = "Close a file descriptor".into();
            e.category = FileSystem;
            e.args = vec![ArgDesc::input("fd", Fd)];
            e
        },
        {
            let mut e = SyscallEntry::minimal(4, "stat");
            e.description = "Get file status".into();
            e.category = FileSystem;
            e.args = vec![ArgDesc::input("pathname", CStr), ArgDesc::output("statbuf", Ptr)];
            e
        },
        // Memory
        {
            let mut e = SyscallEntry::minimal(9, "mmap");
            e.description = "Map files or devices into memory".into();
            e.category = Memory;
            e.args = vec![
                ArgDesc::input("addr", Ptr),
                ArgDesc::input("length", Size),
                ArgDesc::input("prot", Flags),
                ArgDesc::input("flags", Flags),
                ArgDesc::input("fd", Fd),
                ArgDesc::input("offset", Offset),
            ];
            e.is_sensitive = true;
            e.loads_code = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(11, "munmap");
            e.description = "Unmap memory".into();
            e.category = Memory;
            e.args = vec![ArgDesc::input("addr", Ptr), ArgDesc::input("length", Size)];
            e
        },
        {
            let mut e = SyscallEntry::minimal(10, "mprotect");
            e.description = "Change memory protection".into();
            e.category = Memory;
            e.args = vec![
                ArgDesc::input("addr", Ptr),
                ArgDesc::input("len", Size),
                ArgDesc::input("prot", Flags),
            ];
            e.is_sensitive = true;
            e
        },
        // Process
        {
            let mut e = SyscallEntry::minimal(57, "fork");
            e.description = "Create a child process".into();
            e.category = Process;
            e.spawns_process = true;
            e.is_sensitive = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(59, "execve");
            e.description = "Execute a program".into();
            e.category = Process;
            e.args = vec![
                ArgDesc::input("filename", CStr),
                ArgDesc::input("argv", Ptr),
                ArgDesc::input("envp", Ptr),
            ];
            e.spawns_process = true;
            e.loads_code = true;
            e.is_sensitive = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(60, "exit");
            e.description = "Terminate the calling process".into();
            e.category = Process;
            e.args = vec![ArgDesc::input("status", Int)];
            e
        },
        {
            let mut e = SyscallEntry::minimal(39, "getpid");
            e.description = "Get process ID".into();
            e.category = Process;
            e
        },
        // Network
        {
            let mut e = SyscallEntry::minimal(41, "socket");
            e.description = "Create a socket".into();
            e.category = Network;
            e.args = vec![
                ArgDesc::input("domain", Int),
                ArgDesc::input("type", Int),
                ArgDesc::input("protocol", Int),
            ];
            e.is_network = true;
            e.is_sensitive = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(42, "connect");
            e.description = "Connect a socket".into();
            e.category = Network;
            e.args = vec![
                ArgDesc::input("sockfd", Fd),
                ArgDesc::input("addr", SockAddr),
                ArgDesc::input("addrlen", UInt),
            ];
            e.is_network = true;
            e.is_sensitive = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(44, "sendto");
            e.description = "Send a message on a socket".into();
            e.category = Network;
            e.is_network = true;
            e
        },
        {
            let mut e = SyscallEntry::minimal(45, "recvfrom");
            e.description = "Receive a message from a socket".into();
            e.category = Network;
            e.is_network = true;
            e
        },
        // Signals
        {
            let mut e = SyscallEntry::minimal(13, "rt_sigaction");
            e.description = "Examine or change signal action".into();
            e.category = Signals;
            e.args = vec![
                ArgDesc::input("sig", Signal),
                ArgDesc::input("act", Ptr),
                ArgDesc::output("oact", Ptr),
            ];
            e
        },
        {
            let mut e = SyscallEntry::minimal(62, "kill");
            e.description = "Send a signal to a process".into();
            e.category = Signals;
            e.args = vec![ArgDesc::input("pid", Pid), ArgDesc::input("sig", Signal)];
            e.is_sensitive = true;
            e
        },
        // Security
        {
            let mut e = SyscallEntry::minimal(318, "getrandom");
            e.description = "Obtain random bytes".into();
            e.category = Security;
            e.args = vec![
                ArgDesc::output("buf", Ptr),
                ArgDesc::input("buflen", Size),
                ArgDesc::input("flags", Flags),
            ];
            e
        },
        {
            let mut e = SyscallEntry::minimal(317, "seccomp");
            e.description = "Operate on Secure Computing state".into();
            e.category = Security;
            e.is_sensitive = true;
            e
        },
        // Time
        {
            let mut e = SyscallEntry::minimal(228, "clock_gettime");
            e.description = "Get time of a clock".into();
            e.category = Time;
            e.args = vec![ArgDesc::input("clk_id", Int), ArgDesc::output("tp", Timespec)];
            e
        },
        // Debug
        {
            let mut e = SyscallEntry::minimal(101, "ptrace");
            e.description = "Process trace".into();
            e.category = Debug;
            e.is_sensitive = true;
            e.loads_code = true;
            e
        },
    ];

    table.register_all(entries);
    table
}

/// Build a minimal Windows x64 syscall table (NT system services).
#[must_use] 
pub fn windows_x64_table() -> VmSyscallTable {
    use SyscallCategory::{FileSystem, Memory, Process};

    let table = VmSyscallTable::new("windows-x64", DefaultPolicy::BlockDangerous);

    let entries: Vec<SyscallEntry> = vec![
        {
            let mut e = SyscallEntry::minimal(0x0001, "NtCreateFile");
            e.category = FileSystem; e.modifies_fs = true; e.is_sensitive = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0006, "NtReadFile");
            e.category = FileSystem; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0008, "NtWriteFile");
            e.category = FileSystem; e.modifies_fs = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0040, "NtAllocateVirtualMemory");
            e.category = Memory; e.is_sensitive = true; e.loads_code = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x004D, "NtProtectVirtualMemory");
            e.category = Memory; e.is_sensitive = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x004E, "NtQueryVirtualMemory");
            e.category = Memory; e
        },
        {
            let mut e = SyscallEntry::minimal(0x004F, "NtFreeVirtualMemory");
            e.category = Memory; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0075, "NtCreateProcess");
            e.category = Process; e.spawns_process = true; e.is_sensitive = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0077, "NtCreateThread");
            e.category = Process; e.spawns_process = true; e.is_sensitive = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x002B, "NtCreateSection");
            e.category = Memory; e.loads_code = true; e.is_sensitive = true; e
        },
        {
            let mut e = SyscallEntry::minimal(0x0028, "NtMapViewOfSection");
            e.category = Memory; e.loads_code = true; e.is_sensitive = true; e
        },
    ];

    table.register_all(entries);
    table
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_type_display() {
        assert_eq!(ArgType::Fd.to_string(), "int (fd)");
        assert_eq!(ArgType::CStr.to_string(), "const char *");
    }

    #[test]
    fn syscall_entry_prototype() {
        let mut e = SyscallEntry::minimal(1, "write");
        e.args = vec![
            ArgDesc::input("fd", ArgType::Fd),
            ArgDesc::input("buf", ArgType::Ptr),
            ArgDesc::input("count", ArgType::Size),
        ];
        let proto = e.prototype();
        assert!(proto.contains("write"));
        assert!(proto.contains("fd"));
        assert!(proto.contains("size_t count"));
    }

    #[test]
    fn table_lookup_by_name() {
        let table = linux_x86_64_table();
        let entry = table.lookup_by_name("read");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().number, 0);
    }

    #[test]
    fn table_sensitive_entries() {
        let table = linux_x86_64_table();
        let sensitive = table.sensitive_entries();
        assert!(!sensitive.is_empty());
        assert!(sensitive.iter().any(|e| e.name == "execve"));
    }

    #[test]
    fn table_dispatch_allow() {
        let table = VmSyscallTable::new("test", DefaultPolicy::AllowAll);
        table.register(SyscallEntry::minimal(99, "dummy"));
        let ctx = SyscallContext::new(99, [0; 6]);
        assert!(matches!(table.dispatch(&ctx), HandlerResult::Allow { .. }));
    }

    #[test]
    fn table_dispatch_block_unknown() {
        let table = VmSyscallTable::new("test", DefaultPolicy::BlockAll);
        let ctx = SyscallContext::new(9999, [0; 6]);
        assert!(matches!(table.dispatch(&ctx), HandlerResult::Block { .. }));
    }

    #[test]
    fn table_dispatch_custom_handler() {
        let table = VmSyscallTable::new("test", DefaultPolicy::AllowAll);
        let handler: SyscallHandlerFn = Arc::new(|_ctx| HandlerResult::block(13));
        table.register_with_handler(SyscallEntry::minimal(1, "custom"), handler);
        let ctx = SyscallContext::new(1, [0; 6]);
        match table.dispatch(&ctx) {
            HandlerResult::Block { errno } => assert_eq!(errno, 13),
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn windows_table_has_expected_entries() {
        let table = windows_x64_table();
        assert!(table.lookup_by_name("NtCreateFile").is_some());
        assert!(table.lookup_by_name("NtCreateProcess").is_some());
    }

    #[test]
    fn linux_table_category_index() {
        let table = linux_x86_64_table();
        let net = table.by_category(&SyscallCategory::Network);
        assert!(!net.is_empty());
    }
}
