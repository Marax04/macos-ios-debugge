//! NT syscall table: static name/number/arg-count database.
//!
//! **Layer**: pure static data.  No interception or hook logic here.
//!
//! [`NtSyscallTable`] is a versioned lookup table that maps syscall numbers to
//! [`NtSyscallEntry`] records.  Pre-built tables are provided for several
//! Windows 10 build numbers.  Functions [`syscall_by_number`] and
//! [`syscall_args`] provide ergonomic entry-points.
//!
//! Relationship to [`crate::nt_syscalls`]: that module provides the *interception
//! model* (SSN detection, `SysEnter` stub pattern matching, call interceptor with
//! block/log/modify support).  This module is the underlying data source it
//! queries — a static SSDT reference table.

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by the NT syscall table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallTableError {
    /// The syscall number was not found in the table.
    NotFound(u32),
    /// The syscall name was not found in the table.
    NameNotFound(String),
    /// An unrecognised Windows build string was given.
    UnknownBuild(String),
}

impl fmt::Display for SyscallTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "syscall {n:#x} not found"),
            Self::NameNotFound(name) => write!(f, "syscall name '{name}' not found"),
            Self::UnknownBuild(b) => write!(f, "unknown Windows build: {b}"),
        }
    }
}

impl std::error::Error for SyscallTableError {}

// ── NtSyscallEntry ────────────────────────────────────────────────────────────

/// A single entry in the NT syscall table.
#[derive(Debug, Clone)]
pub struct NtSyscallEntry {
    /// Syscall number (index into the SSDT).
    pub number: u32,
    /// The NT function name, e.g. `"NtCreateFile"`.
    pub name: &'static str,
    /// Number of arguments consumed from the user-mode stack/registers.
    pub arg_count: u8,
    /// Short human-readable description.
    pub description: &'static str,
    /// Category tag.
    pub category: SyscallCategory,
}

impl NtSyscallEntry {
    const fn new(
        number: u32,
        name: &'static str,
        arg_count: u8,
        description: &'static str,
        category: SyscallCategory,
    ) -> Self {
        Self { number, name, arg_count, description, category }
    }
}

impl fmt::Display for NtSyscallEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}  {:<40}  args={}", self.number, self.name, self.arg_count)
    }
}

// ── SyscallCategory ───────────────────────────────────────────────────────────

/// Category tag for grouping NT syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallCategory {
    File,
    Process,
    Thread,
    Memory,
    Registry,
    Object,
    Security,
    Synchronization,
    IO,
    Network,
    Debug,
    System,
    Token,
    Event,
    Section,
    Port,
    Timer,
    Other,
}

impl fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::File => "file",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Memory => "memory",
            Self::Registry => "registry",
            Self::Object => "object",
            Self::Security => "security",
            Self::Synchronization => "sync",
            Self::IO => "io",
            Self::Network => "network",
            Self::Debug => "debug",
            Self::System => "system",
            Self::Token => "token",
            Self::Event => "event",
            Self::Section => "section",
            Self::Port => "port",
            Self::Timer => "timer",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

// ── Windows build IDs ─────────────────────────────────────────────────────────

/// A specific Windows version for which a syscall table is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsBuild {
    /// Windows 10 1903 (build 18362) x64.
    Win10_1903X64,
    /// Windows 10 2004 (build 19041) x64.
    Win10_2004X64,
    /// Windows 11 21H2 (build 22000) x64.
    Win11_21h2X64,
    /// Windows Server 2019 x64.
    WinServer2019X64,
}

impl WindowsBuild {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Win10_1903X64 => "Win10_1903X64",
            Self::Win10_2004X64 => "Win10_2004X64",
            Self::Win11_21h2X64 => "Win11_21h2X64",
            Self::WinServer2019X64 => "WinServer2019X64",
        }
    }
}

impl fmt::Display for WindowsBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── NtSyscallTable ────────────────────────────────────────────────────────────

/// A versioned NT syscall table for a specific Windows build.
pub struct NtSyscallTable {
    pub build: WindowsBuild,
    by_number: HashMap<u32, NtSyscallEntry>,
    by_name: HashMap<&'static str, u32>,
}

impl NtSyscallTable {
    /// Build the table for a specific Windows version.
    #[must_use]
    pub fn for_build(build: WindowsBuild) -> Self {
        let entries = syscall_entries_for_build(build);
        let capacity = entries.len();
        let mut by_number = HashMap::with_capacity(capacity);
        let mut by_name = HashMap::with_capacity(capacity);
        for e in entries {
            by_name.insert(e.name, e.number);
            by_number.insert(e.number, e);
        }
        Self { build, by_number, by_name }
    }

    /// Look up a syscall entry by number.
    ///
    /// # Errors
    /// Returns [`SyscallTableError::NotFound`] if the number is not in the table.
    pub fn syscall_by_number(&self, number: u32) -> Result<&NtSyscallEntry, SyscallTableError> {
        self.by_number.get(&number).ok_or(SyscallTableError::NotFound(number))
    }

    /// Look up a syscall entry by name.
    ///
    /// # Errors
    /// Returns [`SyscallTableError::NotFound`] if the name is not in the table.
    pub fn syscall_by_name(&self, name: &str) -> Result<&NtSyscallEntry, SyscallTableError> {
        let number = self.by_name.get(name).copied().ok_or_else(|| SyscallTableError::NameNotFound(name.to_string()))?;
        self.syscall_by_number(number)
    }

    /// Return the expected argument count for syscall `number`.
    ///
    /// # Errors
    /// Returns [`SyscallTableError::NotFound`] if the number is not in the table.
    pub fn syscall_args(&self, number: u32) -> Result<u8, SyscallTableError> {
        Ok(self.syscall_by_number(number)?.arg_count)
    }

    /// Return all entries in the table, sorted by syscall number.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&NtSyscallEntry> {
        let mut entries: Vec<&NtSyscallEntry> = self.by_number.values().collect();
        entries.sort_by_key(|e| e.number);
        entries
    }

    /// Return all entries in the given category.
    #[must_use]
    pub fn entries_by_category(&self, category: SyscallCategory) -> Vec<&NtSyscallEntry> {
        let mut entries: Vec<&NtSyscallEntry> = self
            .by_number
            .values()
            .filter(|e| e.category == category)
            .collect();
        entries.sort_by_key(|e| e.number);
        entries
    }

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    /// Return `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }

    /// Return the number for a given name, or `None`.
    #[must_use]
    pub fn number_for_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Find all entries whose name contains `fragment` (case-insensitive).
    #[must_use]
    pub fn search_by_name(&self, fragment: &str) -> Vec<&NtSyscallEntry> {
        let lower = fragment.to_lowercase();
        let mut results: Vec<&NtSyscallEntry> = self
            .by_number
            .values()
            .filter(|e| e.name.to_lowercase().contains(&lower))
            .collect();
        results.sort_by_key(|e| e.number);
        results
    }

    /// Category distribution: returns a map from category to count.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<SyscallCategory, usize> {
        let mut counts = HashMap::with_capacity(18);
        for e in self.by_number.values() {
            *counts.entry(e.category).or_insert(0) += 1;
        }
        counts
    }
}

impl fmt::Debug for NtSyscallTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtSyscallTable {{ build: {}, entries: {} }}", self.build, self.by_number.len())
    }
}

// ── Convenience free functions ────────────────────────────────────────────────

/// Look up a syscall entry by number in the default table (Win10 1903 x64).
///
/// # Errors
/// Returns [`SyscallTableError::NotFound`] if the syscall number is not in the table.
pub fn syscall_by_number(number: u32) -> Result<NtSyscallEntry, SyscallTableError> {
    let table = NtSyscallTable::for_build(WindowsBuild::Win10_1903X64);
    table.syscall_by_number(number).cloned()
}

/// Return the argument count for a syscall number (Win10 1903 x64 default).
///
/// # Errors
/// Returns [`SyscallTableError::NotFound`] if the syscall number is not in the table.
pub fn syscall_args(number: u32) -> Result<u8, SyscallTableError> {
    let table = NtSyscallTable::for_build(WindowsBuild::Win10_1903X64);
    table.syscall_args(number)
}

// ── Syscall table data ────────────────────────────────────────────────────────

/// Windows 10 1903 x64 syscall table (representative subset).
fn base_syscall_entries() -> Vec<NtSyscallEntry> {
    let mut v = base_syscall_entries_lo();
    v.extend(base_syscall_entries_hi());
    v
}

/// Syscall entries 0x0000–0x004F.
fn base_syscall_entries_lo() -> Vec<NtSyscallEntry> {
    use SyscallCategory::{Security, Other, Port, Memory, Synchronization, File, IO, Thread, Event, Object, Registry, System, Process, Token, Section, Timer};
    vec![
        NtSyscallEntry::new(0x0000, "NtAccessCheck", 8, "Check access rights for an object", Security),
        NtSyscallEntry::new(0x0001, "NtWorkerFactoryWorkerReady", 1, "Signal worker factory ready", Other),
        NtSyscallEntry::new(0x0002, "NtAcceptConnectPort", 6, "Accept a connection request on a port", Port),
        NtSyscallEntry::new(0x0003, "NtMapUserPhysicalPagesScatter", 3, "Map physical pages scattered", Memory),
        NtSyscallEntry::new(0x0004, "NtWaitForSingleObject", 3, "Wait for a single kernel object", Synchronization),
        NtSyscallEntry::new(0x0005, "NtCallbackReturn", 3, "Return from user APC callback", Other),
        NtSyscallEntry::new(0x0006, "NtReadFile", 9, "Read data from a file or I/O device", File),
        NtSyscallEntry::new(0x0007, "NtDeviceIoControlFile", 10, "Send control code to a device driver", IO),
        NtSyscallEntry::new(0x0008, "NtWriteFile", 9, "Write data to a file or I/O device", File),
        NtSyscallEntry::new(0x0009, "NtRemoveIoCompletion", 5, "Remove an I/O completion packet", IO),
        NtSyscallEntry::new(0x000A, "NtReleaseSemaphore", 3, "Release a semaphore object", Synchronization),
        NtSyscallEntry::new(0x000B, "NtReplyWaitReceivePort", 4, "Reply and wait on a port", Port),
        NtSyscallEntry::new(0x000C, "NtReplyPort", 2, "Reply to a port message", Port),
        NtSyscallEntry::new(0x000D, "NtSetInformationThread", 4, "Set thread information", Thread),
        NtSyscallEntry::new(0x000E, "NtSetEvent", 2, "Set an event object to signaled", Event),
        NtSyscallEntry::new(0x000F, "NtClose", 1, "Close an object handle", Object),
        NtSyscallEntry::new(0x0010, "NtQueryObject", 5, "Query information about an object", Object),
        NtSyscallEntry::new(0x0011, "NtQueryInformationFile", 5, "Query file information", File),
        NtSyscallEntry::new(0x0012, "NtOpenKey", 3, "Open a registry key", Registry),
        NtSyscallEntry::new(0x0013, "NtEnumerateValueKey", 6, "Enumerate registry value", Registry),
        NtSyscallEntry::new(0x0014, "NtFindAtom", 3, "Find an atom in the atom table", Object),
        NtSyscallEntry::new(0x0015, "NtQueryDefaultLocale", 2, "Query the system default locale", System),
        NtSyscallEntry::new(0x0016, "NtQueryKey", 5, "Query registry key information", Registry),
        NtSyscallEntry::new(0x0017, "NtQueryValueKey", 6, "Query registry value", Registry),
        NtSyscallEntry::new(0x0018, "NtAllocateVirtualMemory", 6, "Allocate virtual memory in a process", Memory),
        NtSyscallEntry::new(0x0019, "NtQueryInformationProcess", 5, "Query process information", Process),
        NtSyscallEntry::new(0x001A, "NtWaitForMultipleObjects32", 5, "Wait for multiple objects (32-bit)", Synchronization),
        NtSyscallEntry::new(0x001B, "NtWriteFileGather", 9, "Gather-write to a file", File),
        NtSyscallEntry::new(0x001C, "NtSetInformationProcess", 4, "Set process information", Process),
        NtSyscallEntry::new(0x001D, "NtCreateKey", 7, "Create or open a registry key", Registry),
        NtSyscallEntry::new(0x001E, "NtFreeVirtualMemory", 4, "Free virtual memory in a process", Memory),
        NtSyscallEntry::new(0x001F, "NtImpersonateClientOfPort", 2, "Impersonate the client of a port", Security),
        NtSyscallEntry::new(0x0020, "NtReleaseMutant", 2, "Release a mutant object", Synchronization),
        NtSyscallEntry::new(0x0021, "NtQueryInformationToken", 5, "Query token information", Token),
        NtSyscallEntry::new(0x0022, "NtRequestWaitReplyPort", 3, "Send request and wait for reply", Port),
        NtSyscallEntry::new(0x0023, "NtQueryVirtualMemory", 6, "Query virtual memory information", Memory),
        NtSyscallEntry::new(0x0024, "NtOpenThreadToken", 4, "Open a thread token", Token),
        NtSyscallEntry::new(0x0025, "NtQueryInformationThread", 5, "Query thread information", Thread),
        NtSyscallEntry::new(0x0026, "NtOpenProcess", 4, "Open a process handle", Process),
        NtSyscallEntry::new(0x0027, "NtSetInformationFile", 5, "Set file information", File),
        NtSyscallEntry::new(0x0028, "NtMapViewOfSection", 10, "Map a view of a section into an address space", Section),
        NtSyscallEntry::new(0x0029, "NtAccessCheckAndAuditAlarm", 11, "Check access and generate audit", Security),
        NtSyscallEntry::new(0x002A, "NtUnmapViewOfSection", 2, "Unmap a view of a section", Section),
        NtSyscallEntry::new(0x002B, "NtReplyWaitReceivePortEx", 5, "Extended reply and wait on port", Port),
        NtSyscallEntry::new(0x002C, "NtTerminateProcess", 2, "Terminate a process", Process),
        NtSyscallEntry::new(0x002D, "NtSetEventBoostPriority", 1, "Set event with priority boost", Event),
        NtSyscallEntry::new(0x002E, "NtReadFileScatter", 9, "Scatter-read from a file", File),
        NtSyscallEntry::new(0x002F, "NtOpenThreadTokenEx", 5, "Open a thread token (extended)", Token),
        NtSyscallEntry::new(0x0030, "NtOpenProcessTokenEx", 4, "Open a process token (extended)", Token),
        NtSyscallEntry::new(0x0031, "NtQueryPerformanceCounter", 2, "Query performance counter", System),
        NtSyscallEntry::new(0x0032, "NtEnumerateKey", 6, "Enumerate registry subkeys", Registry),
        NtSyscallEntry::new(0x0033, "NtOpenFile", 6, "Open a file or I/O device", File),
        NtSyscallEntry::new(0x0034, "NtDelayExecution", 2, "Delay thread execution (sleep)", Thread),
        NtSyscallEntry::new(0x0035, "NtQueryDirectoryFile", 11, "Query directory for file names", File),
        NtSyscallEntry::new(0x0036, "NtQuerySystemInformation", 4, "Query system information", System),
        NtSyscallEntry::new(0x0037, "NtOpenSection", 3, "Open a section object", Section),
        NtSyscallEntry::new(0x0038, "NtQueryTimer", 5, "Query a timer object", Timer),
        NtSyscallEntry::new(0x0039, "NtFsControlFile", 10, "Send a file system control code", IO),
        NtSyscallEntry::new(0x003A, "NtWriteVirtualMemory", 5, "Write to virtual memory of another process", Memory),
        NtSyscallEntry::new(0x003B, "NtCloseObjectAuditAlarm", 3, "Audit object close", Security),
        NtSyscallEntry::new(0x003C, "NtDuplicateObject", 7, "Duplicate an object handle", Object),
        NtSyscallEntry::new(0x003D, "NtQueryAttributesFile", 2, "Query basic attributes of a file", File),
        NtSyscallEntry::new(0x003E, "NtClearEvent", 1, "Clear an event to non-signaled", Event),
        NtSyscallEntry::new(0x003F, "NtReadVirtualMemory", 5, "Read from virtual memory of another process", Memory),
        NtSyscallEntry::new(0x0040, "NtOpenEvent", 3, "Open an event object", Event),
        NtSyscallEntry::new(0x0041, "NtAdjustPrivilegesToken", 6, "Adjust token privileges", Token),
        NtSyscallEntry::new(0x0042, "NtDuplicateToken", 6, "Duplicate a token", Token),
        NtSyscallEntry::new(0x0043, "NtContinue", 2, "Continue execution after exception", Thread),
        NtSyscallEntry::new(0x0044, "NtQueryDefaultUILanguage", 1, "Query default UI language", System),
        NtSyscallEntry::new(0x0045, "NtQueueApcThread", 5, "Queue an APC to a thread", Thread),
        NtSyscallEntry::new(0x0046, "NtYieldExecution", 0, "Yield processor time", Thread),
        NtSyscallEntry::new(0x0047, "NtAddAtom", 3, "Add a string to the atom table", Object),
        NtSyscallEntry::new(0x0048, "NtCreateEvent", 5, "Create an event object", Event),
        NtSyscallEntry::new(0x0049, "NtQueryVolumeInformationFile", 5, "Query volume information", File),
        NtSyscallEntry::new(0x004A, "NtCreateSection", 7, "Create a section object", Section),
        NtSyscallEntry::new(0x004B, "NtFlushBuffersFile", 2, "Flush file buffers", File),
        NtSyscallEntry::new(0x004C, "NtApphelpCacheControl", 2, "Apphelp cache control", Other),
        NtSyscallEntry::new(0x004D, "NtCreateProcessEx", 9, "Create a process (extended)", Process),
        NtSyscallEntry::new(0x004E, "NtCreateThread", 8, "Create a thread", Thread),
        NtSyscallEntry::new(0x004F, "NtIsProcessInJob", 2, "Check whether process is in a job", Process),
    ]
}

/// Syscall entries 0x0050–0x009F.
fn base_syscall_entries_hi() -> Vec<NtSyscallEntry> {
    use SyscallCategory::{Security, Other, Port, Memory, Synchronization, File, IO, Thread, Event, Object, Registry, System, Process, Token, Section, Timer, Debug};
    vec![
        NtSyscallEntry::new(0x0050, "NtProtectVirtualMemory", 5, "Change page protections", Memory),
        NtSyscallEntry::new(0x0051, "NtQuerySection", 5, "Query section object info", Section),
        NtSyscallEntry::new(0x0052, "NtResumeThread", 2, "Resume a thread", Thread),
        NtSyscallEntry::new(0x0053, "NtTerminateThread", 2, "Terminate a thread", Thread),
        NtSyscallEntry::new(0x0054, "NtReadRequestData", 6, "Read port request data", Port),
        NtSyscallEntry::new(0x0055, "NtCreateFile", 11, "Create or open a file", File),
        NtSyscallEntry::new(0x0056, "NtQueryEvent", 5, "Query event object info", Event),
        NtSyscallEntry::new(0x0057, "NtWriteRequestData", 6, "Write port request data", Port),
        NtSyscallEntry::new(0x0058, "NtOpenDirectoryObject", 3, "Open a directory object", Object),
        NtSyscallEntry::new(0x0059, "NtAccessCheckByTypeAndAuditAlarm", 16, "Type-based access check with audit", Security),
        NtSyscallEntry::new(0x005A, "NtWaitForMultipleObjects", 5, "Wait for multiple objects", Synchronization),
        NtSyscallEntry::new(0x005B, "NtSetInformationObject", 4, "Set object information", Object),
        NtSyscallEntry::new(0x005C, "NtCancelIoFile", 2, "Cancel I/O operations", IO),
        NtSyscallEntry::new(0x005D, "NtTraceEvent", 4, "Trace event log entry", Debug),
        NtSyscallEntry::new(0x005E, "NtPowerInformation", 5, "Query or set power information", System),
        NtSyscallEntry::new(0x005F, "NtSetValueKey", 6, "Set a registry value", Registry),
        NtSyscallEntry::new(0x0060, "NtCancelTimer", 2, "Cancel a timer", Timer),
        NtSyscallEntry::new(0x0061, "NtSetTimer", 7, "Set a timer", Timer),
        NtSyscallEntry::new(0x0062, "NtAccessCheckByType", 11, "Type-based access check", Security),
        NtSyscallEntry::new(0x0063, "NtAccessCheckByTypeResultList", 11, "Access check with result list", Security),
        NtSyscallEntry::new(0x0064, "NtAccessCheckByTypeResultListAndAuditAlarm", 16, "Access check list + audit", Security),
        NtSyscallEntry::new(0x0065, "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", 17, "Handle-based access check list + audit", Security),
        NtSyscallEntry::new(0x0066, "NtAcquireProcessActivityReference", 3, "Acquire process activity reference", Process),
        NtSyscallEntry::new(0x0067, "NtAddBootEntry", 2, "Add a boot entry", System),
        NtSyscallEntry::new(0x0068, "NtAddDriverEntry", 2, "Add a driver entry", System),
        NtSyscallEntry::new(0x0069, "NtAdjustGroupsToken", 6, "Adjust token groups", Token),
        NtSyscallEntry::new(0x006A, "NtAdjustTokenClaimsAndDeviceGroups", 10, "Adjust token claims and device groups", Token),
        NtSyscallEntry::new(0x006B, "NtAlertResumeThread", 2, "Alert and resume a thread", Thread),
        NtSyscallEntry::new(0x006C, "NtAlertThread", 1, "Alert a thread", Thread),
        NtSyscallEntry::new(0x006D, "NtAlertThreadByThreadId", 1, "Alert thread by thread ID", Thread),
        NtSyscallEntry::new(0x006E, "NtAlpcAcceptConnectPort", 9, "ALPC accept connect", Port),
        NtSyscallEntry::new(0x006F, "NtAlpcCancelMessage", 3, "ALPC cancel message", Port),
        NtSyscallEntry::new(0x0070, "NtAlpcConnectPort", 11, "ALPC connect to a port", Port),
        NtSyscallEntry::new(0x0071, "NtAlpcCreatePort", 3, "ALPC create port", Port),
        NtSyscallEntry::new(0x0072, "NtAlpcCreatePortSection", 6, "ALPC create port section", Port),
        NtSyscallEntry::new(0x0073, "NtAlpcCreateResourceReserve", 4, "ALPC create resource reserve", Port),
        NtSyscallEntry::new(0x0074, "NtAlpcCreateSectionView", 3, "ALPC create section view", Port),
        NtSyscallEntry::new(0x0075, "NtAlpcCreateSecurityContext", 3, "ALPC create security context", Port),
        NtSyscallEntry::new(0x0076, "NtAlpcDeletePortSection", 3, "ALPC delete port section", Port),
        NtSyscallEntry::new(0x0077, "NtAlpcDeleteResourceReserve", 3, "ALPC delete resource reserve", Port),
        NtSyscallEntry::new(0x0078, "NtAlpcDeleteSectionView", 3, "ALPC delete section view", Port),
        NtSyscallEntry::new(0x0079, "NtAlpcDeleteSecurityContext", 3, "ALPC delete security context", Port),
        NtSyscallEntry::new(0x007A, "NtAlpcDisconnectPort", 2, "ALPC disconnect port", Port),
        NtSyscallEntry::new(0x007B, "NtAlpcImpersonateClientContainerOfPort", 3, "ALPC impersonate container", Security),
        NtSyscallEntry::new(0x007C, "NtAlpcImpersonateClientOfPort", 3, "ALPC impersonate client", Security),
        NtSyscallEntry::new(0x007D, "NtAlpcOpenSenderProcess", 6, "ALPC open sender process", Process),
        NtSyscallEntry::new(0x007E, "NtAlpcOpenSenderThread", 6, "ALPC open sender thread", Thread),
        NtSyscallEntry::new(0x007F, "NtAlpcQueryInformation", 5, "ALPC query information", Port),
        NtSyscallEntry::new(0x0080, "NtAlpcQueryInformationMessage", 6, "ALPC query message information", Port),
        NtSyscallEntry::new(0x0081, "NtAlpcRevokeSecurityContext", 3, "ALPC revoke security context", Security),
        NtSyscallEntry::new(0x0082, "NtAlpcSendWaitReceivePort", 8, "ALPC send/wait/receive", Port),
        NtSyscallEntry::new(0x0083, "NtAlpcSetInformation", 4, "ALPC set information", Port),
        NtSyscallEntry::new(0x0084, "NtAreMappedFilesTheSame", 2, "Check if two mapped files are the same", File),
        NtSyscallEntry::new(0x0085, "NtAssignProcessToJobObject", 2, "Assign process to a job object", Process),
        NtSyscallEntry::new(0x0086, "NtAssociateWaitCompletionPacket", 8, "Associate wait completion packet", IO),
        NtSyscallEntry::new(0x0087, "NtCallEnclave", 4, "Call into an enclave", Security),
        NtSyscallEntry::new(0x0088, "NtCancelIoFileEx", 3, "Cancel I/O extended", IO),
        NtSyscallEntry::new(0x0089, "NtCancelSynchronousIoFile", 3, "Cancel synchronous I/O", IO),
        NtSyscallEntry::new(0x008A, "NtCancelTimer2", 2, "Cancel timer v2", Timer),
        NtSyscallEntry::new(0x008B, "NtCancelWaitCompletionPacket", 2, "Cancel wait completion packet", IO),
        NtSyscallEntry::new(0x008C, "NtCommitComplete", 2, "Commit transaction (complete)", Other),
        NtSyscallEntry::new(0x008D, "NtCommitEnlistment", 2, "Commit enlistment", Other),
        NtSyscallEntry::new(0x008E, "NtCommitTransaction", 2, "Commit a transaction", Other),
        NtSyscallEntry::new(0x008F, "NtCompactKeys", 2, "Compact registry keys", Registry),
        NtSyscallEntry::new(0x0090, "NtCompareObjects", 2, "Compare two object handles", Object),
        NtSyscallEntry::new(0x0091, "NtCompareSigningLevels", 2, "Compare signing levels", Security),
        NtSyscallEntry::new(0x0092, "NtCompareTokens", 3, "Compare two tokens", Token),
        NtSyscallEntry::new(0x0093, "NtCompleteConnectPort", 1, "Complete port connection", Port),
        NtSyscallEntry::new(0x0094, "NtCompressKey", 1, "Compress a registry key", Registry),
        NtSyscallEntry::new(0x0095, "NtConnectPort", 8, "Connect to an LPC port", Port),
        NtSyscallEntry::new(0x0096, "NtContinueEx", 2, "Continue execution (extended)", Thread),
        NtSyscallEntry::new(0x0097, "NtCreateDebugObject", 4, "Create a debug object", Debug),
        NtSyscallEntry::new(0x0098, "NtCreateDirectoryObject", 3, "Create a directory object", Object),
        NtSyscallEntry::new(0x0099, "NtCreateDirectoryObjectEx", 5, "Create directory object (extended)", Object),
        NtSyscallEntry::new(0x009A, "NtCreateEnclave", 9, "Create a secure enclave", Security),
        NtSyscallEntry::new(0x009B, "NtCreateEnlistment", 8, "Create a transaction enlistment", Other),
        NtSyscallEntry::new(0x009C, "NtCreateEventPair", 3, "Create an event pair", Event),
        NtSyscallEntry::new(0x009D, "NtCreateIRTimer", 2, "Create an IR timer", Timer),
        NtSyscallEntry::new(0x009E, "NtCreateIoCompletion", 4, "Create I/O completion port", IO),
        NtSyscallEntry::new(0x009F, "NtCreateJobObject", 3, "Create a job object", Object),
    ]
}

fn syscall_entries_for_build(build: WindowsBuild) -> Vec<NtSyscallEntry> {
    let base = base_syscall_entries();
    // For different builds, some syscall numbers shift; apply minor offsets here.
    match build {
        WindowsBuild::Win10_1903X64 | WindowsBuild::Win10_2004X64 | WindowsBuild::WinServer2019X64 => base,
        WindowsBuild::Win11_21h2X64 => {
            // Win11 adds a few new syscalls at the top; numbers shift up by ~5
            base.into_iter().map(|mut e| {
                e.number = e.number.saturating_add(5);
                e
            }).collect()
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_table() -> NtSyscallTable {
        NtSyscallTable::for_build(WindowsBuild::Win10_1903X64)
    }

    #[test]
    fn test_table_has_entries() {
        let t = default_table();
        assert!(t.len() > 50);
    }

    #[test]
    fn test_syscall_by_number_found() {
        let t = default_table();
        let e = t.syscall_by_number(0x0055).unwrap();
        assert_eq!(e.name, "NtCreateFile");
    }

    #[test]
    fn test_syscall_by_number_not_found() {
        let t = default_table();
        let err = t.syscall_by_number(0xFFFF).unwrap_err();
        assert_eq!(err, SyscallTableError::NotFound(0xFFFF));
    }

    #[test]
    fn test_syscall_by_name() {
        let t = default_table();
        let e = t.syscall_by_name("NtCreateFile").unwrap();
        assert_eq!(e.number, 0x0055);
    }

    #[test]
    fn test_syscall_args_nt_create_file() {
        let t = default_table();
        assert_eq!(t.syscall_args(0x0055).unwrap(), 11);
    }

    #[test]
    fn test_syscall_args_nt_close() {
        let t = default_table();
        assert_eq!(t.syscall_args(0x000F).unwrap(), 1);
    }

    #[test]
    fn test_syscall_by_number_free_fn() {
        let e = syscall_by_number(0x0006).unwrap();
        assert_eq!(e.name, "NtReadFile");
    }

    #[test]
    fn test_syscall_args_free_fn() {
        assert_eq!(syscall_args(0x0006).unwrap(), 9);
    }

    #[test]
    fn test_entries_by_category_file() {
        let t = default_table();
        let file_entries = t.entries_by_category(SyscallCategory::File);
        assert!(!file_entries.is_empty());
        for e in &file_entries {
            assert_eq!(e.category, SyscallCategory::File);
        }
    }

    #[test]
    fn test_entries_by_category_memory() {
        let t = default_table();
        let mem_entries = t.entries_by_category(SyscallCategory::Memory);
        let names: Vec<&str> = mem_entries.iter().map(|e| e.name).collect();
        assert!(names.contains(&"NtAllocateVirtualMemory"));
        assert!(names.contains(&"NtFreeVirtualMemory"));
    }

    #[test]
    fn test_search_by_name() {
        let t = default_table();
        let results = t.search_by_name("VirtualMemory");
        assert!(!results.is_empty());
        for e in &results {
            assert!(e.name.contains("VirtualMemory"));
        }
    }

    #[test]
    fn test_search_by_name_case_insensitive() {
        let t = default_table();
        let lower = t.search_by_name("virtualmemory");
        let upper = t.search_by_name("VIRTUALMEMORY");
        assert_eq!(lower.len(), upper.len());
    }

    #[test]
    fn test_all_entries_sorted() {
        let t = default_table();
        let entries = t.all_entries();
        for w in entries.windows(2) {
            assert!(w[0].number <= w[1].number);
        }
    }

    #[test]
    fn test_number_for_name() {
        let t = default_table();
        assert_eq!(t.number_for_name("NtClose"), Some(0x000F));
        assert!(t.number_for_name("NotExist").is_none());
    }

    #[test]
    fn test_category_counts() {
        let t = default_table();
        let counts = t.category_counts();
        assert!(*counts.get(&SyscallCategory::File).unwrap_or(&0) > 0);
        assert!(*counts.get(&SyscallCategory::Memory).unwrap_or(&0) > 0);
    }

    #[test]
    fn test_win11_numbers_shifted() {
        let t_1903 = NtSyscallTable::for_build(WindowsBuild::Win10_1903X64);
        let t_win11 = NtSyscallTable::for_build(WindowsBuild::Win11_21h2X64);
        let e_1903 = t_1903.syscall_by_name("NtCreateFile").unwrap();
        let e_win11 = t_win11.syscall_by_name("NtCreateFile").unwrap();
        assert_eq!(e_win11.number, e_1903.number + 5);
    }

    #[test]
    fn test_syscall_display() {
        let e = syscall_by_number(0x0055).unwrap();
        let s = e.to_string();
        assert!(s.contains("NtCreateFile"));
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SyscallCategory::File.to_string(), "file");
        assert_eq!(SyscallCategory::Memory.to_string(), "memory");
    }

    #[test]
    fn test_error_display() {
        let e = SyscallTableError::NotFound(0xABCD);
        assert!(e.to_string().contains("abcd"));
    }
}
