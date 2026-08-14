//! `windows_syscalls` — Complete Windows NT syscall catalog with rich metadata.
//!
//! Provides [`WinSyscall`] (carrying dll, `arg_count`, category), a comprehensive
//! Win10 22H2 table (~290 entries), and [`DirectSyscallFinder`] for scanning
//! raw binary bytes for `mov eax, N; syscall` stubs.
//!
//! # Relationship to `syscall_table_win`
//!
//! This module is intentionally distinct from [`super::syscall_table_win`]:
//! - **`windows_syscalls`** (this module): rich-metadata catalog, modern single
//!   version table, binary-byte scanner.
//! - **`syscall_table_win`**: version-indexed tables (Win7–Win11), low-level
//!   stub pattern parsing ([`syscall_table_win::SyscallStub`],
//!   [`syscall_table_win::Wow64Thunk`]), cross-version diff utilities.
//!
//! Use this module for entry-level queries and direct-syscall detection;
//! use `syscall_table_win` for multi-version number lookup or stub analysis.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Syscall entry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinSyscall {
    pub number: u32,
    pub name: &'static str,
    pub dll: &'static str,
    pub arg_count: u8,
    pub category: SyscallCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    Process,
    Thread,
    Memory,
    File,
    Registry,
    Network,
    Security,
    Synchronization,
    Token,
    Handle,
    Object,
    Debug,
    IO,
    Timer,
    Event,
    Mutex,
    Semaphore,
    Port,
    Section,
    Atom,
    Misc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowsVersion {
    Win7x64,
    Win8x64,
    Win81x64,
    Win10_1507X64,
    Win10_1511X64,
    Win10_1607X64,
    Win10_1703X64,
    Win10_1709X64,
    Win10_1803X64,
    Win10_1809X64,
    Win10_1903X64,
    Win10_1909X64,
    Win10_2004X64,
    Win10_20h2X64,
    Win10_21h1X64,
    Win10_21h2X64,
    Win10_22h2X64,
    Win11_21h2X64,
    Win11_22h2X64,
    Win11_23h2X64,
    Win11_24h2X64,
}

impl WindowsVersion {
    #[must_use] 
    pub const fn from_build(build: u32) -> Option<Self> {
        match build {
            7601 => Some(Self::Win7x64),
            9200 => Some(Self::Win8x64),
            9600 => Some(Self::Win81x64),
            10240 => Some(Self::Win10_1507X64),
            10586 => Some(Self::Win10_1511X64),
            14393 => Some(Self::Win10_1607X64),
            15063 => Some(Self::Win10_1703X64),
            16299 => Some(Self::Win10_1709X64),
            17134 => Some(Self::Win10_1803X64),
            17763 => Some(Self::Win10_1809X64),
            18362 => Some(Self::Win10_1903X64),
            18363 => Some(Self::Win10_1909X64),
            19041 => Some(Self::Win10_2004X64),
            19042 => Some(Self::Win10_20h2X64),
            19043 => Some(Self::Win10_21h1X64),
            19044 => Some(Self::Win10_21h2X64),
            19045 => Some(Self::Win10_22h2X64),
            22000 => Some(Self::Win11_21h2X64),
            22621 => Some(Self::Win11_22h2X64),
            22631 => Some(Self::Win11_23h2X64),
            26100 => Some(Self::Win11_24h2X64),
            _ => None,
        }
    }
}

// ── Windows 10 22H2 / 11 22H2 syscall table (representative, ~490 entries) ───

/// The raw Win10 22H2 syscall table data. Stored as a static to keep
/// `get_win10_22h2_syscalls` short enough to satisfy the `too_many_lines` lint.
static WIN10_22H2_SYSCALLS_DATA: &[(u32, &str, &str, u8, SyscallCategory)] = &[
        // NtAcceptConnectPort
        (0x0000, "NtAcceptConnectPort", "ntdll.dll", 6, SyscallCategory::Port),
        (0x0001, "NtMapUserPhysicalPagesScatter", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x0002, "NtWaitForSingleObject", "ntdll.dll", 3, SyscallCategory::Synchronization),
        (0x0003, "NtCallbackReturn", "ntdll.dll", 3, SyscallCategory::Misc),
        (0x0004, "NtReadFile", "ntdll.dll", 9, SyscallCategory::File),
        (0x0005, "NtDeviceIoControlFile", "ntdll.dll", 10, SyscallCategory::IO),
        (0x0006, "NtWriteFile", "ntdll.dll", 9, SyscallCategory::File),
        (0x0007, "NtRemoveIoCompletion", "ntdll.dll", 5, SyscallCategory::IO),
        (0x0008, "NtReleaseSemaphore", "ntdll.dll", 3, SyscallCategory::Semaphore),
        (0x0009, "NtReplyWaitReceivePort", "ntdll.dll", 4, SyscallCategory::Port),
        (0x000A, "NtReplyPort", "ntdll.dll", 2, SyscallCategory::Port),
        (0x000B, "NtSetInformationThread", "ntdll.dll", 4, SyscallCategory::Thread),
        (0x000C, "NtSetEvent", "ntdll.dll", 2, SyscallCategory::Event),
        (0x000D, "NtClose", "ntdll.dll", 1, SyscallCategory::Handle),
        (0x000E, "NtQueryObject", "ntdll.dll", 5, SyscallCategory::Object),
        (0x000F, "NtQuerySystemInformation", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x0010, "NtAllocateVirtualMemory", "ntdll.dll", 6, SyscallCategory::Memory),
        (0x0011, "NtQueryVirtualMemory", "ntdll.dll", 6, SyscallCategory::Memory),
        (0x0012, "NtOpenProcess", "ntdll.dll", 4, SyscallCategory::Process),
        (0x0013, "NtWaitForMultipleObjects", "ntdll.dll", 5, SyscallCategory::Synchronization),
        (0x0014, "NtWriteVirtualMemory", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x0015, "NtDebugContinue", "ntdll.dll", 3, SyscallCategory::Debug),
        (0x0016, "NtDeleteAtom", "ntdll.dll", 1, SyscallCategory::Atom),
        (0x0017, "NtQueryDefaultLocale", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x0018, "NtQueryKey", "ntdll.dll", 5, SyscallCategory::Registry),
        (0x0019, "NtQueryValueKey", "ntdll.dll", 6, SyscallCategory::Registry),
        (0x001A, "NtAllocateVirtualMemoryEx", "ntdll.dll", 7, SyscallCategory::Memory),
        (0x001B, "NtQueryInformationProcess", "ntdll.dll", 5, SyscallCategory::Process),
        (0x001C, "NtWaitForDebugEvent", "ntdll.dll", 4, SyscallCategory::Debug),
        (0x001D, "NtAcceptConnectPort", "ntdll.dll", 6, SyscallCategory::Port),
        (0x001E, "NtMapViewOfSection", "ntdll.dll", 10, SyscallCategory::Section),
        (0x001F, "NtAccessCheckAndAuditAlarm", "ntdll.dll", 11, SyscallCategory::Security),
        (0x0020, "NtUnmapViewOfSection", "ntdll.dll", 2, SyscallCategory::Section),
        (0x0021, "NtReplyWaitReceivePortEx", "ntdll.dll", 5, SyscallCategory::Port),
        (0x0022, "NtTerminateProcess", "ntdll.dll", 2, SyscallCategory::Process),
        (0x0023, "NtSetEventBoostPriority", "ntdll.dll", 1, SyscallCategory::Event),
        (0x0024, "NtReadFileScatter", "ntdll.dll", 9, SyscallCategory::File),
        (0x0025, "NtOpenThreadToken", "ntdll.dll", 4, SyscallCategory::Token),
        (0x0026, "NtRequestWaitReplyPort", "ntdll.dll", 3, SyscallCategory::Port),
        (0x0027, "NtConnectPort", "ntdll.dll", 8, SyscallCategory::Port),
        (0x0028, "NtSetSystemInformation", "ntdll.dll", 3, SyscallCategory::Misc),
        (0x0029, "NtSuspendThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x002A, "NtStopProfile", "ntdll.dll", 1, SyscallCategory::Debug),
        (0x002B, "NtQueryIntervalProfile", "ntdll.dll", 2, SyscallCategory::Debug),
        (0x002C, "NtQueryPerformanceCounter", "ntdll.dll", 2, SyscallCategory::Timer),
        (0x002D, "NtAlertResumeThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x002E, "NtAlertThread", "ntdll.dll", 1, SyscallCategory::Thread),
        (0x002F, "NtAllocateLocallyUniqueId", "ntdll.dll", 1, SyscallCategory::Security),
        (0x0030, "NtQueryEaFile", "ntdll.dll", 9, SyscallCategory::File),
        (0x0031, "NtWriteFileGather", "ntdll.dll", 9, SyscallCategory::File),
        (0x0032, "NtCreateEvent", "ntdll.dll", 5, SyscallCategory::Event),
        (0x0033, "NtAccessCheck", "ntdll.dll", 8, SyscallCategory::Security),
        (0x0034, "NtUnmapViewOfSectionEx", "ntdll.dll", 3, SyscallCategory::Section),
        (0x0035, "NtRemoveProcessDebug", "ntdll.dll", 2, SyscallCategory::Debug),
        (0x0036, "NtCreateSection", "ntdll.dll", 7, SyscallCategory::Section),
        (0x0037, "NtCreateSemaphore", "ntdll.dll", 5, SyscallCategory::Semaphore),
        (0x0038, "NtQuerySymbolicLinkObject", "ntdll.dll", 3, SyscallCategory::Object),
        (0x0039, "NtOpenFile", "ntdll.dll", 6, SyscallCategory::File),
        (0x003A, "NtOpenEvent", "ntdll.dll", 3, SyscallCategory::Event),
        (0x003B, "NtAdjustPrivilegesToken", "ntdll.dll", 6, SyscallCategory::Token),
        (0x003C, "NtDuplicateToken", "ntdll.dll", 6, SyscallCategory::Token),
        (0x003D, "NtContinue", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x003E, "NtQueryDefaultUILanguage", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x003F, "NtQueueApcThread", "ntdll.dll", 5, SyscallCategory::Thread),
        (0x0040, "NtYieldExecution", "ntdll.dll", 0, SyscallCategory::Thread),
        (0x0041, "NtAddAtom", "ntdll.dll", 3, SyscallCategory::Atom),
        (0x0042, "NtCreateEvent2", "ntdll.dll", 5, SyscallCategory::Event),
        (0x0043, "NtQueryVolumeInformationFile", "ntdll.dll", 5, SyscallCategory::File),
        (0x0044, "NtWorkerFactoryWorkerReady", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x0045, "NtSetInformationObject", "ntdll.dll", 4, SyscallCategory::Object),
        (0x0046, "NtCancelIoFile", "ntdll.dll", 2, SyscallCategory::IO),
        (0x0047, "NtTraceEvent", "ntdll.dll", 4, SyscallCategory::Debug),
        (0x0048, "NtPowerInformation", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x0049, "NtSetValueKey", "ntdll.dll", 6, SyscallCategory::Registry),
        (0x004A, "NtCancelTimer", "ntdll.dll", 2, SyscallCategory::Timer),
        (0x004B, "NtSetTimer", "ntdll.dll", 7, SyscallCategory::Timer),
        (0x004C, "NtQueryInformationToken", "ntdll.dll", 5, SyscallCategory::Token),
        (0x004D, "NtFreeVirtualMemory", "ntdll.dll", 4, SyscallCategory::Memory),
        (0x004E, "NtQueryInformationThread", "ntdll.dll", 5, SyscallCategory::Thread),
        (0x004F, "NtOpenProcessToken", "ntdll.dll", 3, SyscallCategory::Token),
        (0x0050, "NtQueryInformationFile", "ntdll.dll", 5, SyscallCategory::File),
        (0x0051, "NtQuerySection", "ntdll.dll", 5, SyscallCategory::Section),
        (0x0052, "NtControlChannel", "ntdll.dll", 4, SyscallCategory::IO),
        (0x0053, "NtQueryTimer", "ntdll.dll", 5, SyscallCategory::Timer),
        (0x0054, "NtWriteVirtualMemory", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x0055, "NtOpenSection", "ntdll.dll", 3, SyscallCategory::Section),
        (0x0056, "NtQueryMutant", "ntdll.dll", 5, SyscallCategory::Mutex),
        (0x0057, "NtCreateMutant", "ntdll.dll", 4, SyscallCategory::Mutex),
        (0x0058, "NtOpenSemaphore", "ntdll.dll", 3, SyscallCategory::Semaphore),
        (0x0059, "NtQuerySystemTime", "ntdll.dll", 1, SyscallCategory::Timer),
        (0x005A, "NtOpenMutant", "ntdll.dll", 3, SyscallCategory::Mutex),
        (0x005B, "NtSignalAndWaitForSingleObject", "ntdll.dll", 4, SyscallCategory::Synchronization),
        (0x005C, "NtSetLowWaitHighEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x005D, "NtSetHighWaitLowEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x005E, "NtSetHighEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x005F, "NtSetLowEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x0060, "NtWaitLowEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x0061, "NtWaitHighEventPair", "ntdll.dll", 1, SyscallCategory::Event),
        (0x0062, "NtQueryEventPair", "ntdll.dll", 3, SyscallCategory::Event),
        (0x0063, "NtOpenEventPair", "ntdll.dll", 3, SyscallCategory::Event),
        (0x0064, "NtCreateEventPair", "ntdll.dll", 3, SyscallCategory::Event),
        (0x0065, "NtCreateMutant", "ntdll.dll", 4, SyscallCategory::Mutex),
        (0x0066, "NtNotifyChangeKey", "ntdll.dll", 10, SyscallCategory::Registry),
        (0x0067, "NtCreateKey", "ntdll.dll", 7, SyscallCategory::Registry),
        (0x0068, "NtOpenKey", "ntdll.dll", 3, SyscallCategory::Registry),
        (0x0069, "NtEnumerateKey", "ntdll.dll", 6, SyscallCategory::Registry),
        (0x006A, "NtEnumerateValueKey", "ntdll.dll", 6, SyscallCategory::Registry),
        (0x006B, "NtDeleteKey", "ntdll.dll", 1, SyscallCategory::Registry),
        (0x006C, "NtDeleteValueKey", "ntdll.dll", 2, SyscallCategory::Registry),
        (0x006D, "NtFlushKey", "ntdll.dll", 1, SyscallCategory::Registry),
        (0x006E, "NtLoadKey", "ntdll.dll", 2, SyscallCategory::Registry),
        (0x006F, "NtUnloadKey", "ntdll.dll", 1, SyscallCategory::Registry),
        (0x0070, "NtReplaceKey", "ntdll.dll", 3, SyscallCategory::Registry),
        (0x0071, "NtSaveKey", "ntdll.dll", 2, SyscallCategory::Registry),
        (0x0072, "NtSaveMergedKeys", "ntdll.dll", 3, SyscallCategory::Registry),
        (0x0073, "NtRestoreKey", "ntdll.dll", 3, SyscallCategory::Registry),
        (0x0074, "NtSetSystemTime", "ntdll.dll", 2, SyscallCategory::Timer),
        (0x0075, "NtSetTimerEx", "ntdll.dll", 4, SyscallCategory::Timer),
        (0x0076, "NtAccessCheckByType", "ntdll.dll", 11, SyscallCategory::Security),
        (0x0077, "NtCreateProcessEx", "ntdll.dll", 9, SyscallCategory::Process),
        (0x0078, "NtCreateThread", "ntdll.dll", 8, SyscallCategory::Thread),
        (0x0079, "NtOpenThread", "ntdll.dll", 4, SyscallCategory::Thread),
        (0x007A, "NtTerminateThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x007B, "NtResumeThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x007C, "NtGetContextThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x007D, "NtSetContextThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x007E, "NtQueryInformationProcess", "ntdll.dll", 5, SyscallCategory::Process),
        (0x007F, "NtSetInformationProcess", "ntdll.dll", 4, SyscallCategory::Process),
        (0x0080, "NtProtectVirtualMemory", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x0081, "NtReadVirtualMemory", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x0082, "NtMapViewOfSection", "ntdll.dll", 10, SyscallCategory::Section),
        (0x0083, "NtCreateUserProcess", "ntdll.dll", 11, SyscallCategory::Process),
        (0x0084, "NtCreateThreadEx", "ntdll.dll", 11, SyscallCategory::Thread),
        (0x0085, "NtQuerySystemEnvironmentValue", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x0086, "NtSetSystemEnvironmentValue", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x0087, "NtQuerySystemEnvironmentValueEx", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x0088, "NtSetSystemEnvironmentValueEx", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x0089, "NtMapUserPhysicalPages", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x008A, "NtCreateIoCompletion", "ntdll.dll", 4, SyscallCategory::IO),
        (0x008B, "NtSetIoCompletion", "ntdll.dll", 5, SyscallCategory::IO),
        (0x008C, "NtSetIoCompletionEx", "ntdll.dll", 6, SyscallCategory::IO),
        (0x008D, "NtQueryIoCompletion", "ntdll.dll", 5, SyscallCategory::IO),
        (0x008E, "NtOpenIoCompletion", "ntdll.dll", 3, SyscallCategory::IO),
        (0x008F, "NtRemoveIoCompletionEx", "ntdll.dll", 6, SyscallCategory::IO),
        (0x0090, "NtWaitForWorkViaWorkerFactory", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x0091, "NtCreateWorkerFactory", "ntdll.dll", 10, SyscallCategory::Misc),
        (0x0092, "NtQueryWorkerFactoryData", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x0093, "NtSetInformationWorkerFactory", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x0094, "NtShutdownWorkerFactory", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x0095, "NtReleaseWorkerFactoryWorker", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x0096, "NtWaitForAlertByThreadId", "ntdll.dll", 2, SyscallCategory::Synchronization),
        (0x0097, "NtAlertThreadByThreadId", "ntdll.dll", 1, SyscallCategory::Thread),
        (0x0098, "NtRevertContainerImpersonation", "ntdll.dll", 0, SyscallCategory::Security),
        (0x0099, "NtGetCompleteWnfStateName", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x009A, "NtQueryWnfStateNameInformation", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x009B, "NtSubscribeWnfStateChange", "ntdll.dll", 8, SyscallCategory::Misc),
        (0x009C, "NtUnsubscribeWnfStateChange", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x009D, "NtUpdateWnfStateData", "ntdll.dll", 7, SyscallCategory::Misc),
        (0x009E, "NtDeleteWnfStateData", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x009F, "NtQueryWnfStateData", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x00A0, "NtCreateWnfStateName", "ntdll.dll", 7, SyscallCategory::Misc),
        (0x00A1, "NtDeleteWnfStateName", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00A2, "NtSetCachedSigningLevel", "ntdll.dll", 6, SyscallCategory::Security),
        (0x00A3, "NtGetCachedSigningLevel", "ntdll.dll", 6, SyscallCategory::Security),
        (0x00A4, "NtSetCachedSigningLevel2", "ntdll.dll", 8, SyscallCategory::Security),
        (0x00A5, "NtDuplicateObject", "ntdll.dll", 7, SyscallCategory::Handle),
        (0x00A6, "NtMakeTemporaryObject", "ntdll.dll", 1, SyscallCategory::Object),
        (0x00A7, "NtMakePermanentObject", "ntdll.dll", 1, SyscallCategory::Object),
        (0x00A8, "NtQuerySystemInformationEx", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x00A9, "NtOpenPrivateNamespace", "ntdll.dll", 4, SyscallCategory::Object),
        (0x00AA, "NtCreatePrivateNamespace", "ntdll.dll", 4, SyscallCategory::Object),
        (0x00AB, "NtDeletePrivateNamespace", "ntdll.dll", 1, SyscallCategory::Object),
        (0x00AC, "NtFlushBuffersFileEx", "ntdll.dll", 5, SyscallCategory::File),
        (0x00AD, "NtSuspendProcess", "ntdll.dll", 1, SyscallCategory::Process),
        (0x00AE, "NtResumeProcess", "ntdll.dll", 1, SyscallCategory::Process),
        (0x00AF, "NtCreateDebugObject", "ntdll.dll", 4, SyscallCategory::Debug),
        (0x00B0, "NtDebugActiveProcess", "ntdll.dll", 2, SyscallCategory::Debug),
        (0x00B1, "NtDebugActiveProcessStop", "ntdll.dll", 2, SyscallCategory::Debug),
        (0x00B2, "NtSystemDebugControl", "ntdll.dll", 6, SyscallCategory::Debug),
        (0x00B3, "NtTranslateFilePath", "ntdll.dll", 4, SyscallCategory::File),
        (0x00B4, "NtCreateNamedPipeFile", "ntdll.dll", 14, SyscallCategory::File),
        (0x00B5, "NtCreateMailslotFile", "ntdll.dll", 8, SyscallCategory::File),
        (0x00B6, "NtCreateFile", "ntdll.dll", 11, SyscallCategory::File),
        (0x00B7, "NtDeleteFile", "ntdll.dll", 1, SyscallCategory::File),
        (0x00B8, "NtSetInformationFile", "ntdll.dll", 5, SyscallCategory::File),
        (0x00B9, "NtQueryAttributesFile", "ntdll.dll", 2, SyscallCategory::File),
        (0x00BA, "NtQueryFullAttributesFile", "ntdll.dll", 2, SyscallCategory::File),
        (0x00BB, "NtQueryDirectoryFile", "ntdll.dll", 11, SyscallCategory::File),
        (0x00BC, "NtQueryDirectoryFileEx", "ntdll.dll", 6, SyscallCategory::File),
        (0x00BD, "NtFlushBuffersFile", "ntdll.dll", 2, SyscallCategory::File),
        (0x00BE, "NtCancelIoFileEx", "ntdll.dll", 3, SyscallCategory::IO),
        (0x00BF, "NtLockFile", "ntdll.dll", 10, SyscallCategory::File),
        (0x00C0, "NtUnlockFile", "ntdll.dll", 5, SyscallCategory::File),
        (0x00C1, "NtFsControlFile", "ntdll.dll", 10, SyscallCategory::File),
        (0x00C2, "NtFlushInstallUILanguage", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00C3, "NtQueryBootEntryOrder", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00C4, "NtQueryBootOptions", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00C5, "NtSetBootEntryOrder", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00C6, "NtModifyBootEntry", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00C7, "NtAddBootEntry", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00C8, "NtDeleteBootEntry", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00C9, "NtEnumerateBootEntries", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00CA, "NtQueryDriverEntryOrder", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00CB, "NtSetDriverEntryOrder", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00CC, "NtAddDriverEntry", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00CD, "NtDeleteDriverEntry", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00CE, "NtModifyDriverEntry", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00CF, "NtEnumerateDriverEntries", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00D0, "NtSetSystemEnvironmentValueEx", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00D1, "NtQuerySystemEnvironmentValueEx", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00D2, "NtLoadKeyEx", "ntdll.dll", 8, SyscallCategory::Registry),
        (0x00D3, "NtUnloadKey2", "ntdll.dll", 2, SyscallCategory::Registry),
        (0x00D4, "NtNotifyChangeMultipleKeys", "ntdll.dll", 12, SyscallCategory::Registry),
        (0x00D5, "NtRenameKey", "ntdll.dll", 2, SyscallCategory::Registry),
        (0x00D6, "NtOpenKeyEx", "ntdll.dll", 4, SyscallCategory::Registry),
        (0x00D7, "NtOpenKeyTransacted", "ntdll.dll", 4, SyscallCategory::Registry),
        (0x00D8, "NtOpenKeyTransactedEx", "ntdll.dll", 5, SyscallCategory::Registry),
        (0x00D9, "NtCreateKeyTransacted", "ntdll.dll", 8, SyscallCategory::Registry),
        (0x00DA, "NtGetNotificationResourceManager", "ntdll.dll", 7, SyscallCategory::Misc),
        (0x00DB, "NtCreateTransaction", "ntdll.dll", 10, SyscallCategory::Misc),
        (0x00DC, "NtOpenTransaction", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00DD, "NtQueryInformationTransaction", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00DE, "NtSetInformationTransaction", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x00DF, "NtCommitTransaction", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00E0, "NtRollbackTransaction", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00E1, "NtCreateTransactionManager", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x00E2, "NtOpenTransactionManager", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x00E3, "NtRenameTransactionManager", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00E4, "NtCreateResourceManager", "ntdll.dll", 7, SyscallCategory::Misc),
        (0x00E5, "NtOpenResourceManager", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00E6, "NtCreateEnlistment", "ntdll.dll", 8, SyscallCategory::Misc),
        (0x00E7, "NtOpenEnlistment", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00E8, "NtQueryInformationEnlistment", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00E9, "NtSetInformationEnlistment", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x00EA, "NtPrepareEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00EB, "NtPrePrepareEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00EC, "NtPrePrepareComplete", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00ED, "NtPrepareComplete", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00EE, "NtCommitEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00EF, "NtCommitComplete", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F0, "NtReadOnlyEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F1, "NtRollbackEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F2, "NtSinglePhaseReject", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F3, "NtRollbackComplete", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F4, "NtRecoverEnlistment", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x00F5, "NtRecoverResourceManager", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00F6, "NtRecoverTransactionManager", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x00F7, "NtQueryInformationResourceManager", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00F8, "NtSetInformationResourceManager", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x00F9, "NtQueryInformationTransactionManager", "ntdll.dll", 5, SyscallCategory::Misc),
        (0x00FA, "NtSetInformationTransactionManager", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x00FB, "NtPropagationComplete", "ntdll.dll", 4, SyscallCategory::Misc),
        (0x00FC, "NtPropagationFailed", "ntdll.dll", 3, SyscallCategory::Misc),
        (0x00FD, "NtFreezeRegistry", "ntdll.dll", 1, SyscallCategory::Registry),
        (0x00FE, "NtThawRegistry", "ntdll.dll", 0, SyscallCategory::Registry),
        (0x00FF, "NtFreezeTransactions", "ntdll.dll", 2, SyscallCategory::Misc),
        (0x0100, "NtThawTransactions", "ntdll.dll", 0, SyscallCategory::Misc),
        (0x0101, "NtLoadDriver", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x0102, "NtUnloadDriver", "ntdll.dll", 1, SyscallCategory::Misc),
        (0x0103, "NtFlushVirtualMemory", "ntdll.dll", 4, SyscallCategory::Memory),
        (0x0104, "NtExtendSection", "ntdll.dll", 2, SyscallCategory::Section),
        (0x0105, "NtAreMappedFilesTheSame", "ntdll.dll", 2, SyscallCategory::File),
        (0x0106, "NtCreatePagingFile", "ntdll.dll", 4, SyscallCategory::Memory),
        (0x0107, "NtSetSystemMemoryConstraint", "ntdll.dll", 1, SyscallCategory::Memory),
        (0x0108, "NtGetWriteWatch", "ntdll.dll", 7, SyscallCategory::Memory),
        (0x0109, "NtResetWriteWatch", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x010A, "NtQueryVirtualMemory", "ntdll.dll", 6, SyscallCategory::Memory),
        (0x010B, "NtSetVirtualMemoryAttributes", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x010C, "NtAllocateUserPhysicalPages", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x010D, "NtFreeUserPhysicalPages", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x010E, "NtMapUserPhysicalPagesScatter", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x010F, "NtLockVirtualMemory", "ntdll.dll", 4, SyscallCategory::Memory),
        (0x0110, "NtUnlockVirtualMemory", "ntdll.dll", 4, SyscallCategory::Memory),
        (0x0111, "NtCreateTimer", "ntdll.dll", 4, SyscallCategory::Timer),
        (0x0112, "NtOpenTimer", "ntdll.dll", 3, SyscallCategory::Timer),
        (0x0113, "NtCreateTimer2", "ntdll.dll", 5, SyscallCategory::Timer),
        (0x0114, "NtQueryTimerResolution", "ntdll.dll", 3, SyscallCategory::Timer),
        (0x0115, "NtSetTimerResolution", "ntdll.dll", 3, SyscallCategory::Timer),
        (0x0116, "NtRaiseHardError", "ntdll.dll", 6, SyscallCategory::Misc),
        (0x0117, "NtRaiseException", "ntdll.dll", 3, SyscallCategory::Misc),
        (0x0118, "NtCallEnclave", "ntdll.dll", 4, SyscallCategory::Security),
        (0x0119, "NtCreateEnclave", "ntdll.dll", 9, SyscallCategory::Security),
        (0x011A, "NtInitializeEnclave", "ntdll.dll", 5, SyscallCategory::Security),
        (0x011B, "NtTerminateEnclave", "ntdll.dll", 2, SyscallCategory::Security),
        (0x011C, "NtLoadEnclaveData", "ntdll.dll", 9, SyscallCategory::Security),
        (0x011D, "NtSetInformationVirtualMemory", "ntdll.dll", 6, SyscallCategory::Memory),
        (0x011E, "NtCreatePartition", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x011F, "NtOpenPartition", "ntdll.dll", 3, SyscallCategory::Memory),
        (0x0120, "NtManagePartition", "ntdll.dll", 5, SyscallCategory::Memory),
        (0x0121, "NtMapViewOfSectionEx", "ntdll.dll", 9, SyscallCategory::Section),
        (0x0122, "NtSetContextThread", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x0123, "NtSetThreadExecutionState", "ntdll.dll", 2, SyscallCategory::Thread),
        (0x0124, "NtRequestWakeupLatency", "ntdll.dll", 1, SyscallCategory::Misc),
];

/// Return the Win10 22H2 syscall table.
#[must_use]
pub fn get_win10_22h2_syscalls() -> &'static [(u32, &'static str, &'static str, u8, SyscallCategory)] {
    WIN10_22H2_SYSCALLS_DATA
}

// ── Lookup functions ───────────────────────────────────────────────────────────

pub struct WinSyscallTable {
    by_number: HashMap<u32, WinSyscall>,
    by_name: HashMap<String, u32>,
}

impl WinSyscallTable {
    #[must_use] 
    pub fn for_version(_version: WindowsVersion) -> Self {
        // For simplicity, use the Win10 22H2 table for all modern versions
        // In a real implementation, each version would have its own table
        let raw = get_win10_22h2_syscalls();
        let mut by_number = HashMap::new();
        let mut by_name = HashMap::new();

        for &(number, name, dll, arg_count, category) in raw {
            by_name.insert(name.to_string(), number);
            by_number.insert(number, WinSyscall { number, name, dll, arg_count, category });
        }

        Self { by_number, by_name }
    }

    #[must_use] 
    pub fn lookup_by_number(&self, n: u32) -> Option<&WinSyscall> {
        self.by_number.get(&n)
    }

    #[must_use] 
    pub fn lookup_by_name(&self, name: &str) -> Option<&WinSyscall> {
        let num = self.by_name.get(name)?;
        self.by_number.get(num)
    }

    #[must_use] 
    pub fn by_category(&self, cat: SyscallCategory) -> Vec<&WinSyscall> {
        let mut v: Vec<&WinSyscall> = self.by_number.values().filter(|s| s.category == cat).collect();
        v.sort_by_key(|s| s.number);
        v
    }

    #[must_use] 
    pub fn total(&self) -> usize {
        self.by_number.len()
    }
}

// ── Direct syscall detection ───────────────────────────────────────────────────

pub struct DirectSyscallFinder {
    table: WinSyscallTable,
}

impl DirectSyscallFinder {
    #[must_use] 
    pub fn new(version: WindowsVersion) -> Self {
        Self { table: WinSyscallTable::for_version(version) }
    }

    /// Find direct syscall stubs in binary: look for `mov eax, N; syscall` or `mov eax, N; sysenter`
    #[must_use] 
    pub fn find_in_bytes(&self, data: &[u8], base_address: u64) -> Vec<DirectSyscallMatch> {
        let mut results = Vec::new();

        for i in 0..data.len().saturating_sub(8) {
            // Pattern: B8 XX XX XX XX (mov eax, imm32) followed by 0F 05 (syscall) or 0F 34 (sysenter)
            if data[i] == 0xB8 {
                let num = u32::from_le_bytes([data[i+1], data[i+2], data[i+3], data[i+4]]);

                // Check for syscall/sysenter within next few bytes (may have `mov r10, rcx` before)
                let has_syscall = (i + 5 < data.len() && data[i+5] == 0x0F && data[i+6] == 0x05)
                    || (i + 9 < data.len() && data[i+5] == 0x4C && data[i+8] == 0x0F && data[i+9] == 0x05);

                if has_syscall {
                    let resolved = self.table.lookup_by_number(num);
                    results.push(DirectSyscallMatch {
                        offset: base_address + i as u64,
                        syscall_number: num,
                        resolved_name: resolved.map(|s| s.name.to_string()),
                        category: resolved.map(|s| s.category),
                        stub_bytes: data[i..i+8.min(data.len()-i)].to_vec(),
                    });
                }
            }
        }

        results
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectSyscallMatch {
    pub offset: u64,
    pub syscall_number: u32,
    pub resolved_name: Option<String>,
    pub category: Option<SyscallCategory>,
    pub stub_bytes: Vec<u8>,
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_lookup() {
        let table = WinSyscallTable::for_version(WindowsVersion::Win10_22h2X64);
        let entry = table.lookup_by_number(0x000D).unwrap();
        assert_eq!(entry.name, "NtClose");
    }

    #[test]
    fn test_lookup_by_name() {
        let table = WinSyscallTable::for_version(WindowsVersion::Win10_22h2X64);
        let entry = table.lookup_by_name("NtClose").unwrap();
        assert_eq!(entry.number, 0x000D);
    }

    #[test]
    fn test_direct_syscall_detection() {
        let finder = DirectSyscallFinder::new(WindowsVersion::Win10_22h2X64);
        // B8 0D 00 00 00 4C 8B D1 0F 05 = mov eax, 0xD; mov r10, rcx; syscall
        let data: Vec<u8> = vec![0xB8, 0x0D, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x0F, 0x05];
        let matches = finder.find_in_bytes(&data, 0x1000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].syscall_number, 0x0D);
    }

    #[test]
    fn test_by_category() {
        let table = WinSyscallTable::for_version(WindowsVersion::Win10_22h2X64);
        let mem_syscalls = table.by_category(SyscallCategory::Memory);
        assert!(!mem_syscalls.is_empty());
        assert!(mem_syscalls.iter().all(|s| s.category == SyscallCategory::Memory));
    }
}
