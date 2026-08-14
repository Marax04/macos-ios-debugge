//! `syscall_table_win` — Windows NT syscall number tables across OS versions.
//!
//! Contains syscall numbers for Windows 7 / 8 / 8.1 / 10 / 11 (x64),
//! ntdll stub pattern recognition, `WoW64` thunk detection, and lookup helpers.
//!
//! # Relationship to `windows_syscalls`
//!
//! This module is intentionally distinct from [`super::windows_syscalls`]:
//! - **`syscall_table_win`** (this module): version-indexed lookup tables
//!   (`NtVersion` enum, Win10/Win11 tables), low-level stub pattern parsing
//!   ([`SyscallStub`], [`Wow64Thunk`]), and cross-version diff utilities.
//! - **`windows_syscalls`**: a richer per-entry catalog (`WinSyscall` carries
//!   dll, `arg_count`, category), modern Win10 22H2 table with ~290 entries,
//!   and binary-scanning via `DirectSyscallFinder`.
//!
//! Use `syscall_table_win` when you need multi-version tables or stub-byte
//! analysis; use `windows_syscalls` when you need richer entry metadata or
//! in-memory byte scanning.

use std::collections::HashMap;

// ── NtVersion ─────────────────────────────────────────────────────────────────

/// Windows NT version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtVersion {
    Windows7,
    Windows8,
    Windows81,
    Windows10_1507,
    Windows10_1511,
    Windows10_1607,
    Windows10_1703,
    Windows10_1709,
    Windows10_1803,
    Windows10_1809,
    Windows10_1903,
    Windows10_1909,
    Windows10_2004,
    Windows10_20H2,
    Windows10_21H1,
    Windows10_21H2,
    Windows11_21H2,
    Windows11_22H2,
    Windows11_23H2,
    Windows11_24H2,
}

impl NtVersion {
    #[must_use] 
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Windows7 => "Windows 7 (6.1)",
            Self::Windows8 => "Windows 8 (6.2)",
            Self::Windows81 => "Windows 8.1 (6.3)",
            Self::Windows10_1507 => "Windows 10 1507 (10240)",
            Self::Windows10_1511 => "Windows 10 1511 (10586)",
            Self::Windows10_1607 => "Windows 10 1607 (14393)",
            Self::Windows10_1703 => "Windows 10 1703 (15063)",
            Self::Windows10_1709 => "Windows 10 1709 (16299)",
            Self::Windows10_1803 => "Windows 10 1803 (17134)",
            Self::Windows10_1809 => "Windows 10 1809 (17763)",
            Self::Windows10_1903 => "Windows 10 1903 (18362)",
            Self::Windows10_1909 => "Windows 10 1909 (18363)",
            Self::Windows10_2004 => "Windows 10 2004 (19041)",
            Self::Windows10_20H2 => "Windows 10 20H2 (19042)",
            Self::Windows10_21H1 => "Windows 10 21H1 (19043)",
            Self::Windows10_21H2 => "Windows 10 21H2 (19044)",
            Self::Windows11_21H2 => "Windows 11 21H2 (22000)",
            Self::Windows11_22H2 => "Windows 11 22H2 (22621)",
            Self::Windows11_23H2 => "Windows 11 23H2 (22631)",
            Self::Windows11_24H2 => "Windows 11 24H2 (26100)",
        }
    }
}

// ── WinSyscallEntry ──────────────────────────────────────────────────────────────

/// A single syscall entry with its number for a specific Windows version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinSyscallEntry {
    pub name: &'static str,
    pub number: u32,
    pub version: NtVersion,
}

// ── Syscall stub patterns ─────────────────────────────────────────────────────

/// x64 ntdll stub flavours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallStubKind {
    /// `mov eax, imm32 ; syscall ; ret` (standard x64).
    StandardX64,
    /// `mov eax, imm32 ; int 2e ; ret` (old-style or `WoW64` path).
    Int2E,
    /// `mov eax, imm32 ; jmp qword ptr [...] ` (indirect/hooked).
    IndirectJmp,
    /// `jmp [rip+off]` (detour hook at first bytes).
    DetourHook,
    /// Patched/unknown pattern.
    Unknown,
}

/// A parsed ntdll syscall stub.
#[derive(Debug, Clone)]
pub struct SyscallStub {
    pub kind: SyscallStubKind,
    pub syscall_number: Option<u32>,
    /// Raw first 32 bytes of the stub.
    pub bytes: Vec<u8>,
}

impl SyscallStub {
    /// Parse up to 32 bytes from a potential ntdll syscall stub.
    #[must_use] 
    pub fn parse(bytes: &[u8]) -> Self {
        let stub = bytes.get(..bytes.len().min(32)).unwrap_or(bytes);
        let bytes_vec = stub.to_vec();

        // Standard pattern: B8 xx xx xx xx 0F 05 C3
        if stub.len() >= 8 && stub[0] == 0xB8 && stub[5] == 0x0F && stub[6] == 0x05 {
            let num = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            return Self { kind: SyscallStubKind::StandardX64, syscall_number: Some(num), bytes: bytes_vec };
        }
        // int 2e pattern: B8 xx xx xx xx CD 2E C3
        if stub.len() >= 8 && stub[0] == 0xB8 && stub[5] == 0xCD && stub[6] == 0x2E {
            let num = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            return Self { kind: SyscallStubKind::Int2E, syscall_number: Some(num), bytes: bytes_vec };
        }
        // Detour: starts with E9 (jmp rel32) or FF 25 (jmp [rip+off])
        if stub.len() >= 2 && (stub[0] == 0xE9 || (stub[0] == 0xFF && stub[1] == 0x25)) {
            return Self { kind: SyscallStubKind::DetourHook, syscall_number: None, bytes: bytes_vec };
        }
        // Indirect jmp: B8 xx xx xx xx FF 25
        if stub.len() >= 7 && stub[0] == 0xB8 && stub[5] == 0xFF && stub[6] == 0x25 {
            let num = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            return Self { kind: SyscallStubKind::IndirectJmp, syscall_number: Some(num), bytes: bytes_vec };
        }
        Self { kind: SyscallStubKind::Unknown, syscall_number: None, bytes: bytes_vec }
    }

    #[must_use] 
    pub const fn is_hooked(&self) -> bool {
        matches!(self.kind, SyscallStubKind::DetourHook | SyscallStubKind::IndirectJmp)
    }
}

// ── WoW64 thunk ───────────────────────────────────────────────────────────────

/// Describes a `WoW64` thunk used to transition 32-bit code to 64-bit NT calls.
#[derive(Debug, Clone)]
pub struct Wow64Thunk {
    /// Syscall number (`WoW64` side, 32-bit process).
    pub syscall_number: u32,
    /// 32-bit stub kind (usually `int 2e` or `sysenter`).
    pub stub_kind: SyscallStubKind,
}

impl Wow64Thunk {
    /// Recognise a `WoW64` 32-bit stub.
    #[must_use] 
    pub fn parse_x86(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 { return None; }
        if bytes[0] == 0xB8 {
            let num = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let kind = if bytes.get(5).copied() == Some(0xCD) && bytes.get(6).copied() == Some(0x2E) {
                SyscallStubKind::Int2E
            } else {
                SyscallStubKind::Unknown
            };
            return Some(Self { syscall_number: num, stub_kind: kind });
        }
        None
    }
}

// ── Windows 10 syscall table (100+ entries) ───────────────────────────────────

static WIN10_SYSCALLS: &[(&str, u32)] = &[
    ("NtAccessCheck", 0x0000),
    ("NtWorkerFactoryWorkerReady", 0x0001),
    ("NtAcceptConnectPort", 0x0002),
    ("NtMapUserPhysicalPagesScatter", 0x0003),
    ("NtWaitForSingleObject", 0x0004),
    ("NtCallbackReturn", 0x0005),
    ("NtReadFile", 0x0006),
    ("NtDeviceIoControlFile", 0x0007),
    ("NtWriteFile", 0x0008),
    ("NtRemoveIoCompletion", 0x0009),
    ("NtReleaseSemaphore", 0x000A),
    ("NtReplyWaitReceivePort", 0x000B),
    ("NtReplyPort", 0x000C),
    ("NtSetInformationThread", 0x000D),
    ("NtSetEvent", 0x000E),
    ("NtClose", 0x000F),
    ("NtQueryObject", 0x0010),
    ("NtQueryInformationFile", 0x0011),
    ("NtOpenKey", 0x0012),
    ("NtEnumerateValueKey", 0x0013),
    ("NtFindAtom", 0x0014),
    ("NtQueryDefaultLocale", 0x0015),
    ("NtQueryKey", 0x0016),
    ("NtQueryValueKey", 0x0017),
    ("NtAllocateVirtualMemory", 0x0018),
    ("NtQueryInformationProcess", 0x0019),
    ("NtWaitForMultipleObjects32", 0x001A),
    ("NtWriteFileGather", 0x001B),
    ("NtSetInformationProcess", 0x001C),
    ("NtCreateKey", 0x001D),
    ("NtFreeVirtualMemory", 0x001E),
    ("NtImpersonateClientOfPort", 0x001F),
    ("NtReleaseMutant", 0x0020),
    ("NtQueryInformationToken", 0x0021),
    ("NtRequestWaitReplyPort", 0x0022),
    ("NtQueryVirtualMemory", 0x0023),
    ("NtOpenThreadToken", 0x0024),
    ("NtQueryInformationThread", 0x0025),
    ("NtOpenProcess", 0x0026),
    ("NtSetInformationFile", 0x0027),
    ("NtMapViewOfSection", 0x0028),
    ("NtAccessCheckAndAuditAlarm", 0x0029),
    ("NtUnmapViewOfSection", 0x002A),
    ("NtReplyWaitReceivePortEx", 0x002B),
    ("NtTerminateProcess", 0x002C),
    ("NtSetEventBoostPriority", 0x002D),
    ("NtReadFileScatter", 0x002E),
    ("NtOpenThreadTokenEx", 0x002F),
    ("NtOpenProcessTokenEx", 0x0030),
    ("NtQueryPerformanceCounter", 0x0031),
    ("NtEnumerateKey", 0x0032),
    ("NtOpenFile", 0x0033),
    ("NtDelayExecution", 0x0034),
    ("NtQueryDirectoryFile", 0x0035),
    ("NtQuerySystemInformation", 0x0036),
    ("NtOpenSection", 0x0037),
    ("NtQueryTimer", 0x0038),
    ("NtFsControlFile", 0x0039),
    ("NtWriteVirtualMemory", 0x003A),
    ("NtCloseObjectAuditAlarm", 0x003B),
    ("NtDuplicateObject", 0x003C),
    ("NtQueryAttributesFile", 0x003D),
    ("NtClearEvent", 0x003E),
    ("NtReadVirtualMemory", 0x003F),
    ("NtOpenEvent", 0x0040),
    ("NtAdjustPrivilegesToken", 0x0041),
    ("NtDuplicateToken", 0x0042),
    ("NtContinue", 0x0043),
    ("NtQueryDefaultUILanguage", 0x0044),
    ("NtQueueApcThread", 0x0045),
    ("NtYieldExecution", 0x0046),
    ("NtAddAtom", 0x0047),
    ("NtCreateEvent", 0x0048),
    ("NtQueryVolumeInformationFile", 0x0049),
    ("NtCreateSection", 0x004A),
    ("NtFlushBuffersFile", 0x004B),
    ("NtApphelpCacheControl", 0x004C),
    ("NtCreateProcessEx", 0x004D),
    ("NtCreateThread", 0x004E),
    ("NtIsProcessInJob", 0x004F),
    ("NtProtectVirtualMemory", 0x0050),
    ("NtQuerySectionMappingInformation", 0x0051),
    ("NtQueryPortInformationProcess", 0x0052),
    ("NtRaiseException", 0x0053),
    ("NtQuerySystemInformationEx", 0x0054),
    ("NtCreateSemaphore", 0x0055),
    ("NtCreateTimer", 0x0056),
    ("NtQueryTimerResolution", 0x0057),
    ("NtQueryLicenseValue", 0x0058),
    ("NtAlertThread", 0x0059),
    ("NtAlertResumeThread", 0x005A),
    ("NtSetInformationObject", 0x005B),
    ("NtCreateKeyTransacted", 0x005C),
    ("NtOpenKeyTransacted", 0x005D),
    ("NtOpenKeyTransactedEx", 0x005E),
    ("NtSetSystemInformation", 0x005F),
    ("NtShutdownSystem", 0x0060),
    ("NtCreateFile", 0x0061),
    ("NtSetContextThread", 0x0062),
    ("NtSetValueKey", 0x0063),
    ("NtLoadDriver", 0x0064),
    ("NtCallEnclave", 0x0065),
    ("NtDeleteKey", 0x0066),
    ("NtDeleteValueKey", 0x0067),
    ("NtSetInformationVirtualMemory", 0x0068),
    ("NtOpenKeyEx", 0x0069),
    ("NtLoadKey", 0x006A),
    ("NtUnloadDriver", 0x006B),
    ("NtFlushKey", 0x006C),
    ("NtRenameKey", 0x006D),
    ("NtSaveKey", 0x006E),
    ("NtSaveMergedKeys", 0x006F),
    ("NtRestoreKey", 0x0070),
    ("NtLoadKey2", 0x0071),
    ("NtLoadKeyEx", 0x0072),
    ("NtNotifyChangeKey", 0x0073),
    ("NtNotifyChangeMultipleKeys", 0x0074),
    ("NtQueryMultipleValueKey", 0x0075),
    ("NtUnloadKey", 0x0076),
    ("NtUnloadKey2", 0x0077),
    ("NtUnloadKeyEx", 0x0078),
    ("NtInitializeRegistry", 0x0079),
    ("NtQueryOpenSubKeys", 0x007A),
    ("NtQueryOpenSubKeysEx", 0x007B),
    ("NtLockRegistryKey", 0x007C),
    ("NtLockProductActivationKeys", 0x007D),
    ("NtFreezeRegistry", 0x007E),
    ("NtThawRegistry", 0x007F),
    ("NtRaiseHardError", 0x0080),
    ("NtQueryInformationJobObject", 0x0081),
    ("NtSetInformationJobObject", 0x0082),
    ("NtCreateJobObject", 0x0083),
    ("NtAssignProcessToJobObject", 0x0084),
    ("NtTerminateJobObject", 0x0085),
    ("NtCreateSymbolicLinkObject", 0x0086),
    ("NtOpenSymbolicLinkObject", 0x0087),
    ("NtQuerySymbolicLinkObject", 0x0088),
    ("NtCreateProcess", 0x0089),
    ("NtSuspendProcess", 0x008A),
    ("NtResumeProcess", 0x008B),
    ("NtSuspendThread", 0x008C),
    ("NtResumeThread", 0x008D),
    ("NtGetContextThread", 0x008E),
    ("NtCreateUserProcess", 0x008F),
    ("NtFlushInstructionCache", 0x0090),
    ("NtFlushWriteBuffer", 0x0091),
    ("NtGetCurrentProcessorNumber", 0x0092),
    ("NtCreateIoCompletion", 0x0093),
    ("NtOpenIoCompletion", 0x0094),
    ("NtQueryIoCompletion", 0x0095),
    ("NtSetIoCompletion", 0x0096),
    ("NtSetIoCompletionEx", 0x0097),
    ("NtRemoveIoCompletionEx", 0x0098),
    ("NtCreateWaitablePort", 0x0099),
    ("NtCreatePort", 0x009A),
    ("NtListenPort", 0x009B),
    ("NtCompleteConnectPort", 0x009C),
    ("NtConnectPort", 0x009D),
    ("NtSecureConnectPort", 0x009E),
    ("NtRequestPort", 0x009F),
    ("NtAlpcCreatePort", 0x00A0),
    ("NtAlpcDisconnectPort", 0x00A1),
    ("NtAlpcQueryInformation", 0x00A2),
    ("NtAlpcSetInformation", 0x00A3),
    ("NtAlpcCreatePortSection", 0x00A4),
    ("NtAlpcDeletePortSection", 0x00A5),
    ("NtAlpcCreateResourceReserve", 0x00A6),
    ("NtAlpcDeleteResourceReserve", 0x00A7),
    ("NtAlpcCreateSectionView", 0x00A8),
    ("NtAlpcDeleteSectionView", 0x00A9),
    ("NtAlpcQueryInformationMessage", 0x00AA),
    ("NtAlpcConnectPort", 0x00AB),
    ("NtAlpcSendWaitReceivePort", 0x00AC),
    ("NtAlpcCancelMessage", 0x00AD),
    ("NtAlpcImpersonateClientOfPort", 0x00AE),
    ("NtAlpcOpenSenderProcess", 0x00AF),
    ("NtAlpcOpenSenderThread", 0x00B0),
    ("NtAlpcConnectPortEx", 0x00B1),
    ("NtAlpcImpersonateClientContainerOfPort", 0x00B2),
    ("NtCreateMutant", 0x00B3),
    ("NtOpenMutant", 0x00B4),
    ("NtQueryMutant", 0x00B5),
    ("NtCreateDebugObject", 0x00B6),
    ("NtDebugActiveProcess", 0x00B7),
    ("NtDebugContinue", 0x00B8),
    ("NtWaitForDebugEvent", 0x00B9),
    ("NtRemoveProcessDebug", 0x00BA),
    ("NtQueryDebugFilterState", 0x00BB),
    ("NtSetDebugFilterState", 0x00BC),
    ("NtSystemDebugControl", 0x00BD),
    ("NtQuerySystemTime", 0x00BE),
    ("NtSetSystemTime", 0x00BF),
    ("NtGetMappedFileName", 0x00C0),
    ("NtCreateToken", 0x00C1),
    ("NtOpenProcessToken", 0x00C2),
    ("NtOpenThreadToken", 0x00C3),
    ("NtFilterToken", 0x00C4),
    ("NtCreateLowBoxToken", 0x00C5),
    ("NtAdjustGroupsToken", 0x00C6),
    ("NtQueryInformationToken", 0x00C7),
    ("NtSetInformationToken", 0x00C8),
    ("NtImpersonateAnonymousToken", 0x00C9),
    ("NtAccessCheckByType", 0x00CA),
    ("NtPrivilegeCheck", 0x00CB),
    ("NtQuerySecurityObject", 0x00CC),
    ("NtSetSecurityObject", 0x00CD),
    ("NtCreateDirectoryObject", 0x00CE),
    ("NtOpenDirectoryObject", 0x00CF),
    ("NtQueryDirectoryObject", 0x00D0),
];

/// Windows 11 syscall table (100+ entries).
static WIN11_SYSCALLS: &[(&str, u32)] = &[
    ("NtAccessCheck", 0x0000),
    ("NtWorkerFactoryWorkerReady", 0x0001),
    ("NtAcceptConnectPort", 0x0002),
    ("NtMapUserPhysicalPagesScatter", 0x0003),
    ("NtWaitForSingleObject", 0x0004),
    ("NtCallbackReturn", 0x0005),
    ("NtReadFile", 0x0006),
    ("NtDeviceIoControlFile", 0x0007),
    ("NtWriteFile", 0x0008),
    ("NtRemoveIoCompletion", 0x0009),
    ("NtReleaseSemaphore", 0x000A),
    ("NtReplyWaitReceivePort", 0x000B),
    ("NtReplyPort", 0x000C),
    ("NtSetInformationThread", 0x000D),
    ("NtSetEvent", 0x000E),
    ("NtClose", 0x000F),
    ("NtQueryObject", 0x0010),
    ("NtQueryInformationFile", 0x0011),
    ("NtOpenKey", 0x0012),
    ("NtEnumerateValueKey", 0x0013),
    ("NtFindAtom", 0x0014),
    ("NtQueryDefaultLocale", 0x0015),
    ("NtQueryKey", 0x0016),
    ("NtQueryValueKey", 0x0017),
    ("NtAllocateVirtualMemory", 0x0018),
    ("NtQueryInformationProcess", 0x0019),
    ("NtWaitForMultipleObjects32", 0x001A),
    ("NtWriteFileGather", 0x001B),
    ("NtSetInformationProcess", 0x001C),
    ("NtCreateKey", 0x001D),
    ("NtFreeVirtualMemory", 0x001E),
    ("NtImpersonateClientOfPort", 0x001F),
    ("NtReleaseMutant", 0x0020),
    ("NtQueryInformationToken", 0x0021),
    ("NtRequestWaitReplyPort", 0x0022),
    ("NtQueryVirtualMemory", 0x0023),
    ("NtOpenThreadToken", 0x0024),
    ("NtQueryInformationThread", 0x0025),
    ("NtOpenProcess", 0x0026),
    ("NtSetInformationFile", 0x0027),
    ("NtMapViewOfSection", 0x0028),
    ("NtAccessCheckAndAuditAlarm", 0x0029),
    ("NtUnmapViewOfSection", 0x002A),
    ("NtReplyWaitReceivePortEx", 0x002B),
    ("NtTerminateProcess", 0x002C),
    ("NtSetEventBoostPriority", 0x002D),
    ("NtReadFileScatter", 0x002E),
    ("NtOpenThreadTokenEx", 0x002F),
    ("NtOpenProcessTokenEx", 0x0030),
    ("NtQueryPerformanceCounter", 0x0031),
    ("NtEnumerateKey", 0x0032),
    ("NtOpenFile", 0x0033),
    ("NtDelayExecution", 0x0034),
    ("NtQueryDirectoryFile", 0x0035),
    ("NtQuerySystemInformation", 0x0036),
    ("NtOpenSection", 0x0037),
    ("NtQueryTimer", 0x0038),
    ("NtFsControlFile", 0x0039),
    ("NtWriteVirtualMemory", 0x003A),
    ("NtCloseObjectAuditAlarm", 0x003B),
    ("NtDuplicateObject", 0x003C),
    ("NtQueryAttributesFile", 0x003D),
    ("NtClearEvent", 0x003E),
    ("NtReadVirtualMemory", 0x003F),
    ("NtOpenEvent", 0x0040),
    ("NtAdjustPrivilegesToken", 0x0041),
    ("NtDuplicateToken", 0x0042),
    ("NtContinue", 0x0043),
    ("NtQueryDefaultUILanguage", 0x0044),
    ("NtQueueApcThread", 0x0045),
    ("NtYieldExecution", 0x0046),
    ("NtAddAtom", 0x0047),
    ("NtCreateEvent", 0x0048),
    ("NtQueryVolumeInformationFile", 0x0049),
    ("NtCreateSection", 0x004A),
    ("NtFlushBuffersFile", 0x004B),
    ("NtApphelpCacheControl", 0x004C),
    ("NtCreateProcessEx", 0x004D),
    ("NtCreateThread", 0x004E),
    ("NtIsProcessInJob", 0x004F),
    ("NtProtectVirtualMemory", 0x0050),
    ("NtRaiseException", 0x0051),
    ("NtQuerySystemInformationEx", 0x0052),
    ("NtCreateSemaphore", 0x0053),
    ("NtCreateTimer", 0x0054),
    ("NtQueryTimerResolution", 0x0055),
    ("NtAlertThread", 0x0056),
    ("NtAlertResumeThread", 0x0057),
    ("NtCreateUserProcess", 0x0058),
    ("NtSetInformationObject", 0x0059),
    ("NtCreateFile", 0x005A),
    ("NtLoadDriver", 0x005B),
    ("NtDeleteKey", 0x005C),
    ("NtSetValueKey", 0x005D),
    ("NtDeleteValueKey", 0x005E),
    ("NtFlushKey", 0x005F),
    ("NtOpenMutant", 0x0060),
    ("NtQueryMutant", 0x0061),
    ("NtCreateMutant", 0x0062),
    ("NtCreateSymbolicLinkObject", 0x0063),
    ("NtOpenSymbolicLinkObject", 0x0064),
    ("NtQuerySymbolicLinkObject", 0x0065),
    ("NtCreateProcess", 0x0066),
    ("NtSuspendProcess", 0x0067),
    ("NtResumeProcess", 0x0068),
    ("NtSuspendThread", 0x0069),
    ("NtResumeThread", 0x006A),
    ("NtGetContextThread", 0x006B),
    ("NtSetContextThread", 0x006C),
    ("NtFlushInstructionCache", 0x006D),
    ("NtGetCurrentProcessorNumber", 0x006E),
    ("NtCreateIoCompletion", 0x006F),
    ("NtOpenIoCompletion", 0x0070),
    ("NtQueryIoCompletion", 0x0071),
    ("NtSetIoCompletion", 0x0072),
    ("NtRemoveIoCompletionEx", 0x0073),
    ("NtAlpcCreatePort", 0x0074),
    ("NtAlpcConnectPort", 0x0075),
    ("NtAlpcSendWaitReceivePort", 0x0076),
    ("NtAlpcDisconnectPort", 0x0077),
    ("NtAlpcQueryInformation", 0x0078),
    ("NtAlpcSetInformation", 0x0079),
    ("NtAlpcCancelMessage", 0x007A),
    ("NtCreateDebugObject", 0x007B),
    ("NtDebugActiveProcess", 0x007C),
    ("NtDebugContinue", 0x007D),
    ("NtWaitForDebugEvent", 0x007E),
    ("NtRemoveProcessDebug", 0x007F),
    ("NtQueryDebugFilterState", 0x0080),
    ("NtSetDebugFilterState", 0x0081),
    ("NtSystemDebugControl", 0x0082),
    ("NtQuerySystemTime", 0x0083),
    ("NtSetSystemTime", 0x0084),
    ("NtQueueApcThreadEx", 0x0085),
    ("NtCreateToken", 0x0086),
    ("NtOpenProcessToken", 0x0087),
    ("NtFilterToken", 0x0088),
    ("NtCreateLowBoxToken", 0x0089),
    ("NtQueryInformationToken", 0x008A),
    ("NtSetInformationToken", 0x008B),
    ("NtImpersonateAnonymousToken", 0x008C),
    ("NtRaiseHardError", 0x008D),
    ("NtQuerySecurityObject", 0x008E),
    ("NtSetSecurityObject", 0x008F),
    ("NtCreateDirectoryObject", 0x0090),
    ("NtOpenDirectoryObject", 0x0091),
    ("NtQueryDirectoryObject", 0x0092),
    ("NtCreateDirectoryObjectEx", 0x0093),
    ("NtSetSystemPowerState", 0x0094),
    ("NtInitiatePowerAction", 0x0095),
    ("NtPrivilegeCheck", 0x0096),
    ("NtAccessCheckByType", 0x0097),
    ("NtAdjustGroupsToken", 0x0098),
    ("NtCompareTokens", 0x0099),
    ("NtGetMappedFileName", 0x009A),
    ("NtRenameKey", 0x009B),
    ("NtLoadKey", 0x009C),
    ("NtSaveKey", 0x009D),
    ("NtRestoreKey", 0x009E),
    ("NtNotifyChangeKey", 0x009F),
    ("NtNotifyChangeMultipleKeys", 0x00A0),
];

// ── WinSyscallTable ────────────────────────────────────────────────────────────

/// A complete syscall table for a specific Windows version.
#[derive(Debug, Clone)]
pub struct WinSyscallTable {
    pub version: NtVersion,
    /// Entries sorted by number.
    entries: Vec<WinSyscallEntry>,
    name_to_num: HashMap<&'static str, u32>,
}

impl WinSyscallTable {
    fn from_static(version: NtVersion, data: &'static [(&'static str, u32)]) -> Self {
        let mut entries: Vec<WinSyscallEntry> = data.iter()
            .map(|&(name, number)| WinSyscallEntry { name, number, version })
            .collect();
        entries.sort_by_key(|e| e.number);
        let name_to_num: HashMap<&'static str, u32> =
            data.iter().map(|&(n, num)| (n, num)).collect();
        Self { version, entries, name_to_num }
    }

    /// Build the Windows 10 table (representative 19H1/19H2 build).
    #[must_use] 
    pub fn windows10() -> Self { Self::from_static(NtVersion::Windows10_1809, WIN10_SYSCALLS) }
    /// Build the Windows 11 table (representative 22H2 build).
    #[must_use] 
    pub fn windows11() -> Self { Self::from_static(NtVersion::Windows11_22H2, WIN11_SYSCALLS) }

    /// Look up syscall number by name.
    #[must_use] 
    pub fn number_by_name(&self, name: &str) -> Option<u32> {
        self.name_to_num.get(name).copied()
    }

    /// Reverse lookup: name by syscall number.
    #[must_use] 
    pub fn name_by_number(&self, number: u32) -> Option<&'static str> {
        self.entries.binary_search_by_key(&number, |e| e.number)
            .ok().map(|i| self.entries[i].name)
    }

    /// All entries.
    #[must_use] 
    pub fn entries(&self) -> &[WinSyscallEntry] { &self.entries }

    /// Number of entries.
    #[must_use] 
    pub const fn len(&self) -> usize { self.entries.len() }

    /// True if table has no entries.
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Return entries whose names contain `substr`.
    #[must_use] 
    pub fn search(&self, substr: &str) -> Vec<&WinSyscallEntry> {
        self.entries.iter().filter(|e| e.name.contains(substr)).collect()
    }

    /// Build a diff: entries present in `self` but with a different number in `other`.
    #[must_use] 
    pub fn diff_numbers<'a>(&'a self, other: &'a Self)
        -> Vec<(&'a str, u32, Option<u32>)>
    {
        let mut diffs = Vec::new();
        for e in &self.entries {
            match other.number_by_name(e.name) {
                Some(n) if n != e.number => diffs.push((e.name, e.number, Some(n))),
                None => diffs.push((e.name, e.number, None)),
                _ => {}
            }
        }
        diffs
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win10_table_at_least_100_entries() {
        let t = WinSyscallTable::windows10();
        assert!(t.len() >= 100);
    }

    #[test]
    fn win11_table_at_least_100_entries() {
        let t = WinSyscallTable::windows11();
        assert!(t.len() >= 100);
    }

    #[test]
    fn win10_lookup_ntclose() {
        let t = WinSyscallTable::windows10();
        assert_eq!(t.number_by_name("NtClose"), Some(0x000F));
    }

    #[test]
    fn win10_reverse_lookup_ntclose() {
        let t = WinSyscallTable::windows10();
        assert_eq!(t.name_by_number(0x000F), Some("NtClose"));
    }

    #[test]
    fn win10_reverse_lookup_missing() {
        let t = WinSyscallTable::windows10();
        assert_eq!(t.name_by_number(0xFFFF), None);
    }

    #[test]
    fn win10_search_alpc() {
        let t = WinSyscallTable::windows10();
        let results = t.search("Alpc");
        assert!(!results.is_empty());
    }

    #[test]
    fn win11_lookup_ntreadfile() {
        let t = WinSyscallTable::windows11();
        assert_eq!(t.number_by_name("NtReadFile"), Some(0x0006));
    }

    #[test]
    fn stub_parse_standard_x64() {
        let bytes = [0xB8u8, 0x3F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3];
        let stub = SyscallStub::parse(&bytes);
        assert_eq!(stub.kind, SyscallStubKind::StandardX64);
        assert_eq!(stub.syscall_number, Some(0x3F));
    }

    #[test]
    fn stub_parse_int2e() {
        let bytes = [0xB8u8, 0x10, 0x00, 0x00, 0x00, 0xCD, 0x2E, 0xC3];
        let stub = SyscallStub::parse(&bytes);
        assert_eq!(stub.kind, SyscallStubKind::Int2E);
        assert_eq!(stub.syscall_number, Some(0x10));
    }

    #[test]
    fn stub_parse_detour_jmp_rel32() {
        let bytes = [0xE9u8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
        let stub = SyscallStub::parse(&bytes);
        assert_eq!(stub.kind, SyscallStubKind::DetourHook);
        assert!(stub.is_hooked());
    }

    #[test]
    fn stub_parse_detour_jmp_indirect() {
        let bytes = [0xFFu8, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let stub = SyscallStub::parse(&bytes);
        assert_eq!(stub.kind, SyscallStubKind::DetourHook);
    }

    #[test]
    fn stub_parse_unknown() {
        let bytes = [0x90u8; 8];
        let stub = SyscallStub::parse(&bytes);
        assert_eq!(stub.kind, SyscallStubKind::Unknown);
        assert!(!stub.is_hooked());
    }

    #[test]
    fn wow64_parse_int2e() {
        let bytes = [0xB8u8, 0x05, 0x00, 0x00, 0x00, 0xCD, 0x2E, 0xC3, 0x90];
        let thunk = Wow64Thunk::parse_x86(&bytes).unwrap();
        assert_eq!(thunk.syscall_number, 5);
        assert_eq!(thunk.stub_kind, SyscallStubKind::Int2E);
    }

    #[test]
    fn wow64_parse_too_short() {
        assert!(Wow64Thunk::parse_x86(&[0xB8u8, 0x05]).is_none());
    }

    #[test]
    fn nt_version_display_win10() {
        assert!(NtVersion::Windows10_1809.display_name().contains("1809"));
    }

    #[test]
    fn nt_version_display_win11() {
        assert!(NtVersion::Windows11_22H2.display_name().contains("22H2"));
    }

    #[test]
    fn win10_entries_sorted_by_number() {
        let t = WinSyscallTable::windows10();
        let nums: Vec<u32> = t.entries().iter().map(|e| e.number).collect();
        let mut sorted = nums.clone();
        sorted.sort_unstable();
        assert_eq!(nums, sorted);
    }

    #[test]
    fn win11_diff_with_win10() {
        let t10 = WinSyscallTable::windows10();
        let t11 = WinSyscallTable::windows11();
        // Some entries will differ in number between builds
        let diffs = t10.diff_numbers(&t11);
        // Not asserting exact count — just that the function runs
        let _ = diffs;
    }
}
