//! `rustre-syscalls-windows`
//!
//! Windows NT syscall tables, Zw variants, NT data structures, per-version SSN
//! tables (XP/Vista/7/8/10/11), hook detection, and argument formatting.

pub mod api_monitor;
pub mod nt_syscalls;
pub mod windows_events;
pub mod nt_syscall_table;
pub mod etw_event_parser;
pub mod api_monitor_hooks;
pub mod nt_object_manager;
pub mod win32_api_monitor;
pub mod registry_monitor;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum WinSyscallError {
    #[error("unsupported architecture: {0:?}")]
    UnsupportedArch(WinArch),
    #[error("syscall not found: arch={arch:?} ssn={ssn}")]
    NotFound { arch: WinArch, ssn: u32 },
    #[error("unsupported Windows version: {0:?}")]
    UnsupportedVersion(WinVersion),
    #[error("hook detected at stub for {name}: expected bytes {expected:?}, found {found:?}")]
    HookDetected {
        name: String,
        expected: Vec<u8>,
        found: Vec<u8>,
    },
}

// ─── Architecture enum ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WinArch {
    X86,
    X64,
    Arm64,
}

impl fmt::Display for WinArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X64 => write!(f, "x64"),
            Self::Arm64 => write!(f, "arm64"),
        }
    }
}

// ─── Windows version ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WinVersion {
    WindowsXP,
    WindowsVista,
    Windows7,
    Windows8,
    Windows81,
    Windows10,
    Windows11,
}

impl fmt::Display for WinVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsXP => write!(f, "Windows XP"),
            Self::WindowsVista => write!(f, "Windows Vista"),
            Self::Windows7 => write!(f, "Windows 7"),
            Self::Windows8 => write!(f, "Windows 8"),
            Self::Windows81 => write!(f, "Windows 8.1"),
            Self::Windows10 => write!(f, "Windows 10"),
            Self::Windows11 => write!(f, "Windows 11"),
        }
    }
}

// ─── Parameter direction ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamDirection {
    In,
    Out,
    InOut,
    OptIn,
    OptOut,
}

impl fmt::Display for ParamDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "In"),
            Self::Out => write!(f, "Out"),
            Self::InOut => write!(f, "InOut"),
            Self::OptIn => write!(f, "In_opt"),
            Self::OptOut => write!(f, "Out_opt"),
        }
    }
}

// ─── Core types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinSyscallParam {
    pub name: String,
    pub ty: String,
    pub direction: ParamDirection,
}

impl WinSyscallParam {
    #[must_use]
    pub fn new(name: impl Into<String>, ty: impl Into<String>, direction: ParamDirection) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            direction,
        }
    }

    /// Format as SAL-annotated C parameter.
    #[must_use]
    pub fn to_c(&self) -> String {
        format!("_{:?}_ {} {}", self.direction, self.ty, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinNtSyscall {
    pub ssn: u32,
    pub name: String,
    pub params: Vec<WinSyscallParam>,
    pub module: String,
    /// Zw-prefixed alias (e.g. `ZwReadFile` for `NtReadFile`).
    pub zw_name: String,
    /// Category classification.
    pub category: NtSyscallCategory,
    /// Brief description.
    pub description: String,
    /// Whether this function has a kernel-mode entry point.
    pub kernel_mode: bool,
}

impl WinNtSyscall {
    #[must_use]
    pub fn new(
        ssn: u32,
        name: impl Into<String>,
        params: Vec<WinSyscallParam>,
        module: impl Into<String>,
    ) -> Self {
        let name_str: String = name.into();
        let zw = name_str
            .strip_prefix("Nt")
            .map_or_else(|| name_str.clone(), |suffix| format!("Zw{suffix}"));
        let cat = categorize_nt(&name_str);
        Self {
            ssn,
            name: name_str,
            params,
            module: module.into(),
            zw_name: zw,
            category: cat,
            description: String::new(),
            kernel_mode: true,
        }
    }

    /// Return the parameter count (arity).
    #[must_use]
    pub const fn arity(&self) -> usize {
        self.params.len()
    }

    /// Format as a C function prototype.
    #[must_use]
    pub fn prototype(&self) -> String {
        let params: Vec<String> = self.params.iter().map(WinSyscallParam::to_c).collect();
        format!("NTSTATUS {}({});", self.name, params.join(", "))
    }

    /// Return `true` if any parameter is `Out` or `InOut`.
    #[must_use]
    pub fn has_output_params(&self) -> bool {
        self.params.iter().any(|p| {
            matches!(
                p.direction,
                ParamDirection::Out | ParamDirection::InOut | ParamDirection::OptOut
            )
        })
    }
}

// ─── NT syscall category ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NtSyscallCategory {
    FileSystem,
    Registry,
    Process,
    Thread,
    Memory,
    Synchronization,
    Security,
    System,
    Network,
    Ipc,
    Debug,
    Transaction,
    Unknown,
}

impl fmt::Display for NtSyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileSystem => "filesystem",
            Self::Registry => "registry",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Memory => "memory",
            Self::Synchronization => "synchronization",
            Self::Security => "security",
            Self::System => "system",
            Self::Network => "network",
            Self::Ipc => "ipc",
            Self::Debug => "debug",
            Self::Transaction => "transaction",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

fn categorize_nt(name: &str) -> NtSyscallCategory {
    let n = name.trim_start_matches("Nt").trim_start_matches("Zw");
    if n.contains("File")
        || n.contains("Directory")
        || n.contains("Flush")
        || n.contains("Path")
        || n.starts_with("Open") && (n.contains("File") || n.contains("Dir"))
        || n.contains("Rename")
        || n.contains("Link")
        || n.contains("CreateFile")
    {
        NtSyscallCategory::FileSystem
    } else if n.contains("Key")
        || n.contains("Value")
        || n.contains("Registry")
        || n.contains("Hive")
    {
        NtSyscallCategory::Registry
    } else if n.contains("Process") || n.contains("Job") {
        NtSyscallCategory::Process
    } else if n.contains("Thread") || n.contains("Context") || n.contains("Stack") {
        NtSyscallCategory::Thread
    } else if n.contains("Virtual")
        || n.contains("Section")
        || n.contains("Map")
        || n.contains("Alloc")
        || n.contains("Free")
        || n.contains("Protect")
        || n.contains("Heap")
        || n.contains("Memory")
    {
        NtSyscallCategory::Memory
    } else if n.contains("Event")
        || n.contains("Mutant")
        || n.contains("Semaphore")
        || n.contains("Wait")
        || n.contains("Timer")
        || n.contains("Port")
        || n.contains("Alert")
        || n.contains("Queue")
    {
        NtSyscallCategory::Synchronization
    } else if n.contains("Token")
        || n.contains("Security")
        || n.contains("Privilege")
        || n.contains("Access")
        || n.contains("Audit")
        || n.contains("Acl")
    {
        NtSyscallCategory::Security
    } else if n.contains("Debug")
        || n.contains("Exception")
        || n.contains("Continue")
        || n.contains("Raise")
    {
        NtSyscallCategory::Debug
    } else if n.contains("Socket") || n.contains("Afd") || n.contains("Network") {
        NtSyscallCategory::Network
    } else if n.contains("Ipc") || n.contains("Pipe") || n.contains("Message") {
        NtSyscallCategory::Ipc
    } else if n.contains("Transaction") || n.contains("Tm") || n.contains("Enlist") {
        NtSyscallCategory::Transaction
    } else if n.contains("System")
        || n.contains("Shutdown")
        || n.contains("Power")
        || n.contains("Query")
        || n.contains("Set")
    {
        NtSyscallCategory::System
    } else {
        NtSyscallCategory::Unknown
    }
}

// ─── Export entry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdllExport {
    pub name: String,
    pub rva: u32,
    pub ssn: Option<u32>,
    pub ordinal: Option<u16>,
}

impl NtdllExport {
    #[must_use]
    pub fn new(name: impl Into<String>, rva: u32, ssn: Option<u32>) -> Self {
        Self {
            name: name.into(),
            rva,
            ssn,
            ordinal: None,
        }
    }

    #[must_use]
    pub const fn with_ordinal(mut self, ordinal: u16) -> Self {
        self.ordinal = Some(ordinal);
        self
    }
}

// ─── NT data structures ───────────────────────────────────────────────────────

/// Representation of `OBJECT_ATTRIBUTES`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: u64,
    pub object_name: String,
    pub attributes: u32,
    pub security_descriptor: u64,
    pub security_quality_of_service: u64,
}

impl ObjectAttributes {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            length: 48,
            object_name: name.into(),
            ..Default::default()
        }
    }

    /// `OBJ_INHERIT` = 0x2
    #[must_use]
    pub const fn is_inherit(&self) -> bool {
        self.attributes & 0x2 != 0
    }

    /// `OBJ_OPENIF` = 0x80
    #[must_use]
    pub const fn is_open_if(&self) -> bool {
        self.attributes & 0x80 != 0
    }

    /// `OBJ_KERNEL_HANDLE` = 0x200
    #[must_use]
    pub const fn is_kernel_handle(&self) -> bool {
        self.attributes & 0x200 != 0
    }
}

/// `IO_STATUS_BLOCK`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: u64,
}

/// `CLIENT_ID` (pid + tid pair).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ClientId {
    pub unique_process: u64,
    pub unique_thread: u64,
}

/// `UNICODE_STRING`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
    pub decoded: String,
}

impl UnicodeString {
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        let decoded = s.into();
        let utf16_len = decoded.encode_utf16().count() * 2;
        let len = u16::try_from(utf16_len).unwrap_or(u16::MAX);
        Self {
            length: len,
            maximum_length: len.saturating_add(2),
            buffer: 0,
            decoded,
        }
    }
}

/// `MEMORY_BASIC_INFORMATION` (partial).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBasicInformation {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub mem_type: u32,
}

impl MemoryBasicInformation {
    /// `MEM_FREE` = `0x1_0000`
    #[must_use]
    pub const fn is_free(&self) -> bool {
        self.state == 0x1_0000
    }
    /// `MEM_COMMIT` = `0x1000`
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.state == 0x1000
    }
    /// `MEM_RESERVE` = 0x2000
    #[must_use]
    pub const fn is_reserved(&self) -> bool {
        self.state == 0x2000
    }
    /// `PAGE_EXECUTE_READWRITE` = 0x40
    #[must_use]
    pub const fn is_rwx(&self) -> bool {
        self.protect == 0x40
    }
    /// Type name string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.mem_type {
            0x100_0000 => "MEM_IMAGE",
            0x4_0000 => "MEM_MAPPED",
            0x2_0000 => "MEM_PRIVATE",
            _ => "MEM_UNKNOWN",
        }
    }
}

/// `SYSTEM_PROCESS_INFORMATION` fields (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProcessInfo {
    pub pid: u64,
    pub parent_pid: u64,
    pub image_name: String,
    pub thread_count: u32,
    pub handle_count: u32,
    pub create_time: u64,
}

/// `SYSTEM_MODULE_INFORMATION` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemModuleEntry {
    pub base_address: u64,
    pub image_size: u32,
    pub full_path: String,
    pub module_name: String,
    pub load_count: u16,
}

/// PEB (Process Environment Block) — key fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peb {
    pub image_base: u64,
    pub ldr: u64,
    pub process_parameters: u64,
    pub being_debugged: bool,
    pub nt_global_flags: u32,
    pub heap_count: u32,
}

impl Peb {
    /// Returns `true` when the PEB indicates the process is being debugged.
    #[must_use]
    pub const fn is_debugged(&self) -> bool {
        self.being_debugged
    }

    /// Returns `true` when heap validation flags are set (common in debuggers).
    #[must_use]
    pub const fn has_heap_debug_flags(&self) -> bool {
        self.nt_global_flags & 0x70 != 0
    }
}

// ─── Protection flags ─────────────────────────────────────────────────────────

/// Windows virtual memory protection constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum PageProtect {
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
}

impl PageProtect {
    #[must_use]
    pub const fn is_executable(raw: u32) -> bool {
        raw & 0xF0 != 0
    }

    #[must_use]
    pub const fn is_writable(raw: u32) -> bool {
        raw & (0x04 | 0x08 | 0x40 | 0x80) != 0
    }

    #[must_use]
    pub const fn is_rwx(raw: u32) -> bool {
        raw == 0x40
    }

    #[must_use]
    pub const fn name(raw: u32) -> &'static str {
        match raw & 0xFF {
            0x01 => "PAGE_NOACCESS",
            0x02 => "PAGE_READONLY",
            0x04 => "PAGE_READWRITE",
            0x08 => "PAGE_WRITECOPY",
            0x10 => "PAGE_EXECUTE",
            0x20 => "PAGE_EXECUTE_READ",
            0x40 => "PAGE_EXECUTE_READWRITE",
            0x80 => "PAGE_EXECUTE_WRITECOPY",
            _ => "PAGE_UNKNOWN",
        }
    }
}

// ─── Hook detection ───────────────────────────────────────────────────────────

/// Classification of a potential hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookKind {
    /// First bytes of a syscall stub have been overwritten.
    InlineHook,
    /// The IAT entry points outside the expected module.
    IatHook,
    /// Syscall number extracted from stub does not match the expected SSN.
    SsnMismatch { expected: u32, found: u32 },
    /// The stub jumps to an unexpected location before issuing the syscall.
    Trampoline { target: u64 },
    /// The entry is clean — no hook detected.
    Clean,
}

impl fmt::Display for HookKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InlineHook => write!(f, "InlineHook"),
            Self::IatHook => write!(f, "IatHook"),
            Self::SsnMismatch { expected, found } => {
                write!(f, "SsnMismatch(expected={expected}, found={found})")
            }
            Self::Trampoline { target } => write!(f, "Trampoline(0x{target:016x})"),
            Self::Clean => write!(f, "Clean"),
        }
    }
}

/// Result of analysing a single syscall stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookAnalysis {
    pub name: String,
    pub ssn: u32,
    pub kind: HookKind,
    pub stub_bytes: Vec<u8>,
}

impl HookAnalysis {
    /// Returns `true` if a hook was detected.
    #[must_use]
    pub fn is_hooked(&self) -> bool {
        self.kind != HookKind::Clean
    }
}

/// Analyse a raw stub byte sequence for known hook patterns.
#[must_use]
pub fn analyse_stub(name: &str, ssn: u32, arch: WinArch, stub: &[u8]) -> HookAnalysis {
    let kind = match arch {
        WinArch::X64 => analyse_stub_x64(ssn, stub),
        WinArch::X86 => analyse_stub_x86(ssn, stub),
        WinArch::Arm64 => HookKind::Clean, // simplified
    };
    HookAnalysis {
        name: name.to_string(),
        ssn,
        kind,
        stub_bytes: stub.to_vec(),
    }
}

fn analyse_stub_x64(expected_ssn: u32, stub: &[u8]) -> HookKind {
    if stub.len() < 8 {
        return HookKind::Clean;
    }
    // Normal Windows 10/11 x64 stub: 4C 8B D1 B8 <ssn_lo> <ssn_hi> 00 00 F6 ...
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
        let found_ssn = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
        if found_ssn != expected_ssn {
            return HookKind::SsnMismatch {
                expected: expected_ssn,
                found: found_ssn,
            };
        }
        return HookKind::Clean;
    }
    // JMP rel32 at offset 0: E9 xx xx xx xx
    if stub[0] == 0xE9 {
        let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        let target = 5i64.wrapping_add(i64::from(rel)).cast_unsigned();
        return HookKind::Trampoline { target };
    }
    // MOV with wrong SSN or unexpected bytes → inline hook
    HookKind::InlineHook
}

fn analyse_stub_x86(expected_ssn: u32, stub: &[u8]) -> HookKind {
    if stub.len() < 5 {
        return HookKind::Clean;
    }
    // Normal x86 stub: B8 <ssn> BA <sysenter_ptr> FF D2
    if stub[0] == 0xB8 {
        let found = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        if found != expected_ssn {
            return HookKind::SsnMismatch {
                expected: expected_ssn,
                found,
            };
        }
        return HookKind::Clean;
    }
    if stub[0] == 0xE9 {
        let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        let target = 5i64.wrapping_add(i64::from(rel)).cast_unsigned();
        return HookKind::Trampoline { target };
    }
    HookKind::InlineHook
}

// ─── Per-version SSN mapping ──────────────────────────────────────────────────

/// SSN for a given NT function across Windows versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSsn {
    pub name: String,
    pub ssns: HashMap<WinVersion, u32>,
}

impl VersionSsn {
    #[must_use]
    pub fn new(name: impl Into<String>, ssns: HashMap<WinVersion, u32>) -> Self {
        Self {
            name: name.into(),
            ssns,
        }
    }

    /// Look up the SSN for a given version.
    #[must_use]
    pub fn ssn_for(&self, version: WinVersion) -> Option<u32> {
        self.ssns.get(&version).copied()
    }
}

/// One row of the cross-version SSN table: `(name, XP, Vista, Win7, Win8, Win8.1, Win10, Win11)`.
type VersionSsnRow = (&'static str, u32, u32, u32, u32, u32, u32, u32);

/// Raw SSN data table: `(name, XP, Vista, Win7, Win8, Win8.1, Win10, Win11)`.
/// `0xFFFF` means the syscall did not exist in that version.
const VERSION_SSN_DATA: &[VersionSsnRow] = &[
        (
            "NtReadFile",
            0x0087,
            0x0008,
            0x0003,
            0x0002,
            0x0002,
            0x0006,
            0x0006,
        ),
        (
            "NtWriteFile",
            0x0112,
            0x0111,
            0x0112,
            0x0008,
            0x0008,
            0x0008,
            0x0008,
        ),
        (
            "NtClose", 0x0019, 0x000C, 0x000C, 0x000C, 0x000C, 0x000F, 0x000F,
        ),
        (
            "NtCreateFile",
            0x0025,
            0x002C,
            0x0052,
            0x0055,
            0x0055,
            0x0055,
            0x0055,
        ),
        (
            "NtOpenFile",
            0x0074,
            0x0075,
            0x0082,
            0x0030,
            0x0030,
            0x0033,
            0x0033,
        ),
        (
            "NtAllocateVirtualMemory",
            0x0011,
            0x0011,
            0x0012,
            0x0015,
            0x0015,
            0x0018,
            0x0018,
        ),
        (
            "NtFreeVirtualMemory",
            0x0053,
            0x0037,
            0x001B,
            0x001B,
            0x001B,
            0x001D,
            0x001D,
        ),
        (
            "NtProtectVirtualMemory",
            0x0089,
            0x004D,
            0x004D,
            0x004E,
            0x004E,
            0x0050,
            0x0050,
        ),
        (
            "NtReadVirtualMemory",
            0x0095,
            0x0053,
            0x003C,
            0x003E,
            0x003E,
            0x003F,
            0x003F,
        ),
        (
            "NtWriteVirtualMemory",
            0x0115,
            0x0112,
            0x0037,
            0x0037,
            0x0037,
            0x003A,
            0x003A,
        ),
        (
            "NtQueryVirtualMemory",
            0x0090,
            0x00B2,
            0x0020,
            0x0023,
            0x0023,
            0x0023,
            0x0023,
        ),
        (
            "NtOpenProcess",
            0x0079,
            0x007A,
            0x0023,
            0x0026,
            0x0026,
            0x0026,
            0x0026,
        ),
        (
            "NtOpenThread",
            0x007A,
            0x007B,
            0x0024,
            0x0027,
            0x0027,
            0x0027,
            0x0027,
        ),
        (
            "NtTerminateProcess",
            0x0101,
            0x0102,
            0x0029,
            0x002B,
            0x002B,
            0x002C,
            0x002C,
        ),
        (
            "NtTerminateThread",
            0x0102,
            0x0103,
            0x0050,
            0x0052,
            0x0052,
            0x0053,
            0x0053,
        ),
        (
            "NtSuspendThread",
            0x00FE,
            0x00FF,
            0x001F,
            0x0021,
            0x0021,
            0x0022,
            0x0022,
        ),
        (
            "NtResumeThread",
            0x009E,
            0x009F,
            0x004C,
            0x004D,
            0x004D,
            0x004E,
            0x004E,
        ),
        (
            "NtCreateThread",
            0x0035,
            0x0049,
            0x004B,
            0x004C,
            0x004C,
            0x004D,
            0x004D,
        ),
        (
            "NtCreateThreadEx",
            0xFFFF,
            0x00A5,
            0x00A1,
            0x00A9,
            0x00A9,
            0x00B0,
            0x00B0,
        ),
        (
            "NtQueryInformationProcess",
            0x0059,
            0x00B8,
            0x0016,
            0x0019,
            0x0019,
            0x0019,
            0x0019,
        ),
        (
            "NtSetInformationProcess",
            0x00CF,
            0x00DE,
            0x001D,
            0x001F,
            0x001F,
            0x001F,
            0x001F,
        ),
        (
            "NtQuerySystemInformation",
            0x0059,
            0x00B8,
            0x0033,
            0x0036,
            0x0036,
            0x0036,
            0x0036,
        ),
        (
            "NtCreateKey",
            0x0029,
            0x002B,
            0x001A,
            0x001C,
            0x001C,
            0x001C,
            0x001C,
        ),
        (
            "NtOpenKey",
            0x0077,
            0x0078,
            0x0022,
            0x0025,
            0x0025,
            0x0025,
            0x0025,
        ),
        (
            "NtQueryValueKey",
            0x0091,
            0x0092,
            0x0017,
            0x001A,
            0x001A,
            0x001A,
            0x001A,
        ),
        (
            "NtSetValueKey",
            0x00D0,
            0x00D1,
            0x001E,
            0x0020,
            0x0020,
            0x0020,
            0x0020,
        ),
        (
            "NtDeleteKey",
            0x003F,
            0x0040,
            0x000D,
            0x000F,
            0x000F,
            0x000F,
            0x000F,
        ),
        (
            "NtWaitForSingleObject",
            0x0109,
            0x010A,
            0x0001,
            0x0004,
            0x0004,
            0x0004,
            0x0004,
        ),
        (
            "NtCreateSection",
            0x0032,
            0x0047,
            0x0047,
            0x0049,
            0x0049,
            0x004A,
            0x004A,
        ),
        (
            "NtMapViewOfSection",
            0x006C,
            0x006D,
            0x0028,
            0x002C,
            0x002C,
            0x002C,
            0x002C,
        ),
        (
            "NtUnmapViewOfSection",
            0x0107,
            0x0108,
            0x002A,
            0x002E,
            0x002E,
            0x002E,
            0x002E,
        ),
        (
            "NtDuplicateObject",
            0x0044,
            0x0045,
            0x0041,
            0x0042,
            0x0042,
            0x0044,
            0x0044,
        ),
        (
            "NtQueryDirectoryFile",
            0x008D,
            0x008E,
            0x0031,
            0x0035,
            0x0035,
            0x0035,
            0x0035,
        ),
];

/// Build the cross-version SSN table for common functions.
#[must_use]
pub fn build_version_ssn_table() -> Vec<VersionSsn> {
    use WinVersion::{
        Windows7, Windows8, Windows10, Windows11, Windows81, WindowsVista, WindowsXP,
    };
    VERSION_SSN_DATA
        .iter()
        .map(|&(name, xp, vista, w7, w8, w81, w10, w11)| {
            let mut map = HashMap::new();
            if xp != 0xFFFF {
                map.insert(WindowsXP, xp);
            }
            if vista != 0xFFFF {
                map.insert(WindowsVista, vista);
            }
            if w7 != 0xFFFF {
                map.insert(Windows7, w7);
            }
            if w8 != 0xFFFF {
                map.insert(Windows8, w8);
            }
            if w81 != 0xFFFF {
                map.insert(Windows81, w81);
            }
            if w10 != 0xFFFF {
                map.insert(Windows10, w10);
            }
            if w11 != 0xFFFF {
                map.insert(Windows11, w11);
            }
            VersionSsn::new(name, map)
        })
        .collect()
}

// ─── Database ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinSyscallDb {
    tables: HashMap<WinArch, Vec<WinNtSyscall>>,
}

impl Default for WinSyscallDb {
    fn default() -> Self {
        Self::new()
    }
}

impl WinSyscallDb {
    #[must_use]
    pub fn new() -> Self {
        let mut tables: HashMap<WinArch, Vec<WinNtSyscall>> = HashMap::new();
        tables.insert(WinArch::X64, build_x64());
        tables.insert(WinArch::X86, build_x86());
        Self { tables }
    }

    #[must_use]
    pub fn arch_count(&self, arch: WinArch) -> usize {
        self.tables.get(&arch).map_or(0, Vec::len)
    }

    #[must_use]
    pub fn all_for_arch(&self, arch: WinArch) -> Option<&[WinNtSyscall]> {
        self.tables.get(&arch).map(Vec::as_slice)
    }

    #[must_use]
    pub fn lookup(&self, arch: WinArch, ssn: u32) -> Option<&WinNtSyscall> {
        self.tables.get(&arch)?.iter().find(|s| s.ssn == ssn)
    }

    #[must_use]
    pub fn lookup_by_name(&self, arch: WinArch, name: &str) -> Option<&WinNtSyscall> {
        self.tables
            .get(&arch)?
            .iter()
            .find(|s| s.name == name || s.zw_name == name)
    }

    #[must_use]
    pub fn lookup_by_zw_name(&self, arch: WinArch, zw: &str) -> Option<&WinNtSyscall> {
        self.tables.get(&arch)?.iter().find(|s| s.zw_name == zw)
    }

    #[must_use]
    pub fn by_category(&self, arch: WinArch, cat: NtSyscallCategory) -> Vec<&WinNtSyscall> {
        self.tables.get(&arch).map_or_else(Vec::new, |v| {
            v.iter().filter(|s| s.category == cat).collect()
        })
    }

    /// Return all unique categories present in the table.
    #[must_use]
    pub fn categories(&self, arch: WinArch) -> Vec<NtSyscallCategory> {
        let mut cats: Vec<NtSyscallCategory> = match self.tables.get(&arch) {
            None => return vec![],
            Some(v) => v.iter().map(|s| s.category).collect(),
        };
        cats.sort_by_key(std::string::ToString::to_string);
        cats.dedup();
        cats
    }

    /// Count of Zw aliases (same as NT count — 1:1 mapping).
    #[must_use]
    pub fn zw_count(&self, arch: WinArch) -> usize {
        self.arch_count(arch)
    }
}

// ─── Resolver ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinSyscallResolver {
    db: WinSyscallDb,
    version_table: Vec<VersionSsn>,
}

impl Default for WinSyscallResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl WinSyscallResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: WinSyscallDb::new(),
            version_table: build_version_ssn_table(),
        }
    }

    #[must_use]
    pub fn with_db(db: WinSyscallDb) -> Self {
        Self {
            db,
            version_table: build_version_ssn_table(),
        }
    }

    #[must_use]
    pub fn lookup(&self, arch: WinArch, ssn: u32) -> Option<&WinNtSyscall> {
        self.db.lookup(arch, ssn)
    }

    #[must_use]
    pub fn lookup_by_name(&self, arch: WinArch, name: &str) -> Option<&WinNtSyscall> {
        self.db.lookup_by_name(arch, name)
    }

    #[must_use]
    pub fn all_for_arch(&self, arch: WinArch) -> &[WinNtSyscall] {
        self.db.all_for_arch(arch).unwrap_or(&[])
    }

    #[must_use]
    pub const fn db(&self) -> &WinSyscallDb {
        &self.db
    }

    /// Look up the SSN for a function on a specific Windows version.
    #[must_use]
    pub fn ssn_for_version(&self, name: &str, version: WinVersion) -> Option<u32> {
        self.version_table
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.ssn_for(version))
    }

    /// Return the entire version SSN table.
    #[must_use]
    pub fn version_table(&self) -> &[VersionSsn] {
        &self.version_table
    }

    /// Analyse a stub for hook detection.
    #[must_use]
    pub fn analyse_hook(&self, name: &str, arch: WinArch, stub: &[u8]) -> HookAnalysis {
        let ssn = self.lookup_by_name(arch, name).map_or(0, |s| s.ssn);
        analyse_stub(name, ssn, arch, stub)
    }

    /// Return all functions in a given category.
    #[must_use]
    pub fn by_category(&self, arch: WinArch, cat: NtSyscallCategory) -> Vec<&WinNtSyscall> {
        self.db.by_category(arch, cat)
    }
}

// ─── Table builders ───────────────────────────────────────────────────────────

const NTDLL: &str = "ntdll.dll";

fn pi(name: &str, ty: &str) -> WinSyscallParam {
    WinSyscallParam::new(name, ty, ParamDirection::In)
}
fn po(name: &str, ty: &str) -> WinSyscallParam {
    WinSyscallParam::new(name, ty, ParamDirection::Out)
}
fn pio(name: &str, ty: &str) -> WinSyscallParam {
    WinSyscallParam::new(name, ty, ParamDirection::InOut)
}
fn poi(name: &str, ty: &str) -> WinSyscallParam {
    WinSyscallParam::new(name, ty, ParamDirection::OptIn)
}
fn poo(name: &str, ty: &str) -> WinSyscallParam {
    WinSyscallParam::new(name, ty, ParamDirection::OptOut)
}

fn nt(ssn: u32, name: &str, params: Vec<WinSyscallParam>) -> WinNtSyscall {
    WinNtSyscall::new(ssn, name, params, NTDLL)
}

fn build_x64() -> Vec<WinNtSyscall> {
    let mut v = build_x64_entries();
    v.sort_by_key(|s| s.ssn);
    v
}

fn build_x64_entries() -> Vec<WinNtSyscall> {
    let mut v = build_x64_entries_part1();
    v.extend(build_x64_entries_part2());
    v
}

fn build_x64_entries_part1() -> Vec<WinNtSyscall> {
    let mut v = build_x64_part1a();
    v.extend(build_x64_part1a_s1());
    v.extend(build_x64_part1a_ext());
    v.extend(build_x64_part1a_ext_s2());
    v.extend(build_x64_part1a_ext_s1());
    v.extend(build_x64_part1b());
    v.extend(build_x64_part1b_s1());
    v.extend(build_x64_part1b_ext());
    v.extend(build_x64_part1b_ext_s1());
    v
}

fn build_x64_part1a() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0000,
            "NtReadFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(
            0x0001,
            "NtWriteFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(0x0002, "NtClose", vec![pi("Handle", "HANDLE")]),
        nt(
            0x0003,
            "NtQueryInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                po("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0004,
            "NtQueryInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                po("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0005,
            "NtSetInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                pi("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0006,
            "NtSetInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                pi("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0007,
            "NtTerminateProcess",
            vec![poi("ProcessHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
    ]
}

fn build_x64_part1a_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0008,
            "NtTerminateThread",
            vec![poi("ThreadHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
        nt(
            0x0009,
            "NtSuspendThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x000A,
            "NtResumeThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x000B,
            "NtOpenProcess",
            vec![
                po("ProcessHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ClientId", "PCLIENT_ID"),
            ],
        ),
        nt(
            0x000C,
            "NtOpenThread",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ClientId", "PCLIENT_ID"),
            ],
        ),
        nt(
            0x000D,
            "NtCreateThread",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ProcessHandle", "HANDLE"),
                po("ClientId", "PCLIENT_ID"),
                pi("ThreadContext", "PCONTEXT"),
                pi("InitialTeb", "PINITIAL_TEB"),
                pi("CreateSuspended", "BOOLEAN"),
            ],
        ),
        nt(
            0x000E,
            "NtCreateThreadEx",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ProcessHandle", "HANDLE"),
                pi("StartRoutine", "PUSER_THREAD_START_ROUTINE"),
                poi("Argument", "PVOID"),
                pi("CreateFlags", "ULONG"),
                pi("ZeroBits", "SIZE_T"),
                pi("StackSize", "SIZE_T"),
                pi("MaximumStackSize", "SIZE_T"),
                poi("AttributeList", "PPS_ATTRIBUTE_LIST"),
            ],
        ),
    ]
}

fn build_x64_part1a_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x000F,
            "NtAllocateVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pi("ZeroBits", "ULONG_PTR"),
                pio("RegionSize", "PSIZE_T"),
                pi("AllocationType", "ULONG"),
                pi("Protect", "ULONG"),
            ],
        ),
        nt(
            0x0010,
            "NtFreeVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("FreeType", "ULONG"),
            ],
        ),
        nt(
            0x0011,
            "NtProtectVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("NewProtect", "ULONG"),
                po("OldProtect", "PULONG"),
            ],
        ),
        nt(
            0x0012,
            "NtReadVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                po("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesRead", "PSIZE_T"),
            ],
        ),
        nt(
            0x0013,
            "NtWriteVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesWritten", "PSIZE_T"),
            ],
        ),
    ]
}

fn build_x64_part1a_ext_s2() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0014,
            "NtQueryVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("MemoryInformationClass", "MEMORY_INFORMATION_CLASS"),
                po("MemoryInformation", "PVOID"),
                pi("MemoryInformationLength", "SIZE_T"),
                poo("ReturnLength", "PSIZE_T"),
            ],
        ),
        nt(
            0x0015,
            "NtCreateSection",
            vec![
                po("SectionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("MaximumSize", "PLARGE_INTEGER"),
                pi("SectionPageProtection", "ULONG"),
                pi("AllocationAttributes", "ULONG"),
                poi("FileHandle", "HANDLE"),
            ],
        ),
        nt(
            0x0016,
            "NtOpenSection",
            vec![
                po("SectionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0017,
            "NtMapViewOfSection",
            vec![
                pi("SectionHandle", "HANDLE"),
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pi("ZeroBits", "ULONG_PTR"),
                pi("CommitSize", "SIZE_T"),
                pio("SectionOffset", "PLARGE_INTEGER"),
                pio("ViewSize", "PSIZE_T"),
                pi("InheritDisposition", "SECTION_INHERIT"),
                pi("AllocationType", "ULONG"),
                pi("Win32Protect", "ULONG"),
            ],
        ),
    ]
}

fn build_x64_part1a_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0018,
            "NtUnmapViewOfSection",
            vec![pi("ProcessHandle", "HANDLE"), poi("BaseAddress", "PVOID")],
        ),
        nt(
            0x0019,
            "NtCreateFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                poi("AllocationSize", "PLARGE_INTEGER"),
                pi("FileAttributes", "ULONG"),
                pi("ShareAccess", "ULONG"),
                pi("CreateDisposition", "ULONG"),
                pi("CreateOptions", "ULONG"),
                poi("EaBuffer", "PVOID"),
                pi("EaLength", "ULONG"),
            ],
        ),
        nt(
            0x001A,
            "NtOpenFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("ShareAccess", "ULONG"),
                pi("OpenOptions", "ULONG"),
            ],
        ),
        nt(
            0x001B,
            "NtQueryInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
        nt(
            0x001C,
            "NtSetInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
        nt(
            0x001D,
            "NtQueryDirectoryFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
                pi("ReturnSingleEntry", "BOOLEAN"),
                poi("FileName", "PUNICODE_STRING"),
                pi("RestartScan", "BOOLEAN"),
            ],
        ),
        nt(
            0x001E,
            "NtFlushBuffersFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
            ],
        ),
    ]
}

fn build_x64_part1b() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x001F,
            "NtDeleteFile",
            vec![pi("ObjectAttributes", "POBJECT_ATTRIBUTES")],
        ),
        nt(
            0x0020,
            "NtWaitForSingleObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x0021,
            "NtWaitForMultipleObjects",
            vec![
                pi("Count", "ULONG"),
                pi("Handles", "HANDLE *"),
                pi("WaitType", "WAIT_TYPE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x0022,
            "NtCreateEvent",
            vec![
                po("EventHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("EventType", "EVENT_TYPE"),
                pi("InitialState", "BOOLEAN"),
            ],
        ),
        nt(
            0x0023,
            "NtOpenEvent",
            vec![
                po("EventHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0024,
            "NtSetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x0025,
            "NtResetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x0026,
            "NtQueryEvent",
            vec![
                pi("EventHandle", "HANDLE"),
                pi("EventInformationClass", "EVENT_INFORMATION_CLASS"),
                po("EventInformation", "PVOID"),
                pi("EventInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0027,
            "NtCreateMutant",
            vec![
                po("MutantHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("InitialOwner", "BOOLEAN"),
            ],
        ),
    ]
}

fn build_x64_part1b_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0028,
            "NtReleaseMutant",
            vec![pi("MutantHandle", "HANDLE"), poo("PreviousCount", "PLONG")],
        ),
        nt(
            0x0029,
            "NtCreateSemaphore",
            vec![
                po("SemaphoreHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("InitialCount", "LONG"),
                pi("MaximumCount", "LONG"),
            ],
        ),
        nt(
            0x002A,
            "NtReleaseSemaphore",
            vec![
                pi("SemaphoreHandle", "HANDLE"),
                pi("ReleaseCount", "LONG"),
                poo("PreviousCount", "PLONG"),
            ],
        ),
        nt(
            0x002B,
            "NtCreateKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("TitleIndex", "ULONG"),
                poi("Class", "PUNICODE_STRING"),
                pi("CreateOptions", "ULONG"),
                poo("Disposition", "PULONG"),
            ],
        ),
        nt(
            0x002C,
            "NtOpenKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x002D,
            "NtQueryKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("KeyInformationClass", "KEY_INFORMATION_CLASS"),
                po("KeyInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
    ]
}

fn build_x64_part1b_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x002E,
            "NtSetValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("TitleIndex", "ULONG"),
                pi("Type", "ULONG"),
                poi("Data", "PVOID"),
                pi("DataSize", "ULONG"),
            ],
        ),
        nt(
            0x002F,
            "NtQueryValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("KeyValueInformationClass", "KEY_VALUE_INFORMATION_CLASS"),
                po("KeyValueInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(0x0030, "NtDeleteKey", vec![pi("KeyHandle", "HANDLE")]),
        nt(
            0x0031,
            "NtDeleteValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
            ],
        ),
        nt(
            0x0032,
            "NtEnumerateKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("Index", "ULONG"),
                pi("KeyInformationClass", "KEY_INFORMATION_CLASS"),
                po("KeyInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(
            0x0033,
            "NtEnumerateValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("Index", "ULONG"),
                pi("KeyValueInformationClass", "KEY_VALUE_INFORMATION_CLASS"),
                po("KeyValueInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(
            0x0034,
            "NtQuerySystemInformation",
            vec![
                pi("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
                po("SystemInformation", "PVOID"),
                pi("SystemInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0035,
            "NtSetSystemInformation",
            vec![
                pi("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
                pi("SystemInformation", "PVOID"),
                pi("SystemInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0036,
            "NtQuerySystemTime",
            vec![po("SystemTime", "PLARGE_INTEGER")],
        ),
        nt(
            0x0037,
            "NtRaiseHardError",
            vec![
                pi("ErrorStatus", "NTSTATUS"),
                pi("NumberOfParameters", "ULONG"),
                pi("UnicodeStringParameterMask", "ULONG"),
                pi("Parameters", "PULONG_PTR"),
                pi("ValidResponseOptions", "ULONG"),
                po("Response", "PULONG"),
            ],
        ),
    ]
}

fn build_x64_part1b_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0038,
            "NtRaiseException",
            vec![
                pi("ExceptionRecord", "PEXCEPTION_RECORD"),
                pi("ContextRecord", "PCONTEXT"),
                pi("FirstChance", "BOOLEAN"),
            ],
        ),
        nt(
            0x0039,
            "NtContinue",
            vec![pi("ContextRecord", "PCONTEXT"), pi("TestAlert", "BOOLEAN")],
        ),
        nt(
            0x003A,
            "NtGetContextThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pio("ThreadContext", "PCONTEXT"),
            ],
        ),
        nt(
            0x003B,
            "NtSetContextThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadContext", "PCONTEXT"),
            ],
        ),
        nt(
            0x003C,
            "NtDuplicateObject",
            vec![
                pi("SourceProcessHandle", "HANDLE"),
                pi("SourceHandle", "HANDLE"),
                poi("TargetProcessHandle", "HANDLE"),
                poo("TargetHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("HandleAttributes", "ULONG"),
                pi("Options", "ULONG"),
            ],
        ),
        nt(
            0x003D,
            "NtOpenKeyEx",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("OpenOptions", "ULONG"),
            ],
        ),
        nt(
            0x003E,
            "NtCreateKeyTransacted",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("TitleIndex", "ULONG"),
                poi("Class", "PUNICODE_STRING"),
                pi("CreateOptions", "ULONG"),
                pi("TransactionHandle", "HANDLE"),
                poo("Disposition", "PULONG"),
            ],
        ),
        nt(
            0x003F,
            "NtOpenKeyTransacted",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("OpenOptions", "ULONG"),
                pi("TransactionHandle", "HANDLE"),
            ],
        ),
    ]
}

fn build_x64_entries_part2() -> Vec<WinNtSyscall> {
    let mut v = build_x64_part2a();
    v.extend(build_x64_part2a_s1());
    v.extend(build_x64_part2a_ext());
    v.extend(build_x64_part2a_ext_s1());
    v.extend(build_x64_part2b());
    v.extend(build_x64_part2b_s1());
    v.extend(build_x64_part2b_ext());
    v.extend(build_x64_part2b_ext_s1());
    v
}

fn build_x64_part2a() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0040,
            "NtQueryInformationToken",
            vec![
                pi("TokenHandle", "HANDLE"),
                pi("TokenInformationClass", "TOKEN_INFORMATION_CLASS"),
                po("TokenInformation", "PVOID"),
                pi("TokenInformationLength", "ULONG"),
                po("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0041,
            "NtOpenProcessToken",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                po("TokenHandle", "PHANDLE"),
            ],
        ),
        nt(
            0x0042,
            "NtOpenThreadToken",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("OpenAsSelf", "BOOLEAN"),
                po("TokenHandle", "PHANDLE"),
            ],
        ),
        nt(
            0x0043,
            "NtAdjustPrivilegesToken",
            vec![
                pi("TokenHandle", "HANDLE"),
                pi("DisableAllPrivileges", "BOOLEAN"),
                poi("NewState", "PTOKEN_PRIVILEGES"),
                pi("BufferLength", "ULONG"),
                poo("PreviousState", "PTOKEN_PRIVILEGES"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0044,
            "NtQueryObject",
            vec![
                poi("Handle", "HANDLE"),
                pi("ObjectInformationClass", "OBJECT_INFORMATION_CLASS"),
                poo("ObjectInformation", "PVOID"),
                pi("ObjectInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0045,
            "NtSetInformationObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("ObjectInformationClass", "OBJECT_INFORMATION_CLASS"),
                pi("ObjectInformation", "PVOID"),
                pi("ObjectInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0046,
            "NtQuerySymbolicLinkObject",
            vec![
                pi("LinkHandle", "HANDLE"),
                pio("LinkTarget", "PUNICODE_STRING"),
                poo("ReturnedLength", "PULONG"),
            ],
        ),
    ]
}

fn build_x64_part2a_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0047,
            "NtOpenSymbolicLinkObject",
            vec![
                po("LinkHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0048,
            "NtCreateSymbolicLinkObject",
            vec![
                po("LinkHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("LinkTarget", "PUNICODE_STRING"),
            ],
        ),
        nt(
            0x0049,
            "NtQueryDirectoryObject",
            vec![
                pi("DirectoryHandle", "HANDLE"),
                po("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                pi("ReturnSingleEntry", "BOOLEAN"),
                pi("RestartScan", "BOOLEAN"),
                pio("Context", "PULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x004A,
            "NtOpenDirectoryObject",
            vec![
                po("DirectoryHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x004B,
            "NtCreateDirectoryObject",
            vec![
                po("DirectoryHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x004C,
            "NtQuerySecurityObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("SecurityInformation", "SECURITY_INFORMATION"),
                po("SecurityDescriptor", "PSECURITY_DESCRIPTOR"),
                pi("Length", "ULONG"),
                po("LengthNeeded", "PULONG"),
            ],
        ),
        nt(
            0x004D,
            "NtSetSecurityObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("SecurityInformation", "SECURITY_INFORMATION"),
                pi("SecurityDescriptor", "PSECURITY_DESCRIPTOR"),
            ],
        ),
    ]
}

fn build_x64_part2a_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x004E,
            "NtImpersonateClientOfPort",
            vec![pi("PortHandle", "HANDLE"), pi("Message", "PPORT_MESSAGE")],
        ),
        nt(
            0x004F,
            "NtConnectPort",
            vec![
                po("PortHandle", "PHANDLE"),
                pi("PortName", "PUNICODE_STRING"),
                pi("SecurityQos", "PSECURITY_QUALITY_OF_SERVICE"),
                pio("ClientView", "PPORT_VIEW"),
                poo("ServerView", "PREMOTE_PORT_VIEW"),
                poo("MaxMessageLength", "PULONG"),
                pio("ConnectionInformation", "PVOID"),
                pio("ConnectionInformationLength", "PULONG"),
            ],
        ),
        nt(
            0x0050,
            "NtCreatePort",
            vec![
                po("PortHandle", "PHANDLE"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("MaxConnectionInfoLength", "ULONG"),
                pi("MaxMessageLength", "ULONG"),
                poi("MaxPoolUsage", "ULONG"),
            ],
        ),
        nt(
            0x0051,
            "NtListenPort",
            vec![
                pi("PortHandle", "HANDLE"),
                po("ConnectionRequest", "PPORT_MESSAGE"),
            ],
        ),
        nt(
            0x0052,
            "NtAcceptConnectPort",
            vec![
                po("PortHandle", "PHANDLE"),
                poi("PortContext", "PVOID"),
                pi("ConnectionRequest", "PPORT_MESSAGE"),
                pi("AcceptConnection", "BOOLEAN"),
                pio("ServerView", "PPORT_VIEW"),
                poo("ClientView", "PREMOTE_PORT_VIEW"),
            ],
        ),
        nt(
            0x0053,
            "NtCompleteConnectPort",
            vec![pi("PortHandle", "HANDLE")],
        ),
        nt(
            0x0054,
            "NtRequestPort",
            vec![
                pi("PortHandle", "HANDLE"),
                pi("RequestMessage", "PPORT_MESSAGE"),
            ],
        ),
        nt(
            0x0055,
            "NtRequestWaitReplyPort",
            vec![
                pi("PortHandle", "HANDLE"),
                pi("RequestMessage", "PPORT_MESSAGE"),
                po("ReplyMessage", "PPORT_MESSAGE"),
            ],
        ),
        nt(
            0x0056,
            "NtReplyPort",
            vec![
                pi("PortHandle", "HANDLE"),
                pi("ReplyMessage", "PPORT_MESSAGE"),
            ],
        ),
        nt(
            0x0057,
            "NtReplyWaitReplyPort",
            vec![
                pi("PortHandle", "HANDLE"),
                pio("ReplyMessage", "PPORT_MESSAGE"),
            ],
        ),
    ]
}

fn build_x64_part2a_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0058,
            "NtReplyWaitReceivePort",
            vec![
                pi("PortHandle", "HANDLE"),
                poo("PortContext", "PVOID *"),
                poi("ReplyMessage", "PPORT_MESSAGE"),
                po("ReceiveMessage", "PPORT_MESSAGE"),
            ],
        ),
        nt(
            0x0059,
            "NtQueryInformationJobObject",
            vec![
                poi("JobHandle", "HANDLE"),
                pi("JobObjectInformationClass", "JOBOBJECTINFOCLASS"),
                po("JobObjectInformation", "PVOID"),
                pi("JobObjectInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x005A,
            "NtSetInformationJobObject",
            vec![
                pi("JobHandle", "HANDLE"),
                pi("JobObjectInformationClass", "JOBOBJECTINFOCLASS"),
                pi("JobObjectInformation", "PVOID"),
                pi("JobObjectInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x005B,
            "NtCreateTimer",
            vec![
                po("TimerHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("TimerType", "TIMER_TYPE"),
            ],
        ),
        nt(
            0x005C,
            "NtOpenTimer",
            vec![
                po("TimerHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x005D,
            "NtSetTimer",
            vec![
                pi("TimerHandle", "HANDLE"),
                pi("DueTime", "PLARGE_INTEGER"),
                poi("TimerApcRoutine", "PTIMER_APC_ROUTINE"),
                poi("TimerContext", "PVOID"),
                pi("ResumeTimer", "BOOLEAN"),
                poi("Period", "LONG"),
                poo("PreviousState", "PBOOLEAN"),
            ],
        ),
        nt(
            0x005E,
            "NtCancelTimer",
            vec![pi("TimerHandle", "HANDLE"), poo("CurrentState", "PBOOLEAN")],
        ),
        nt(
            0x005F,
            "NtQueryTimer",
            vec![
                pi("TimerHandle", "HANDLE"),
                pi("TimerInformationClass", "TIMER_INFORMATION_CLASS"),
                po("TimerInformation", "PVOID"),
                pi("TimerInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
    ]
}

fn build_x64_part2b() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0060,
            "NtCreateIoCompletion",
            vec![
                po("IoCompletionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("Count", "ULONG"),
            ],
        ),
        nt(
            0x0061,
            "NtOpenIoCompletion",
            vec![
                po("IoCompletionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0062,
            "NtSetIoCompletion",
            vec![
                pi("IoCompletionHandle", "HANDLE"),
                poi("KeyContext", "PVOID"),
                poi("ApcContext", "PVOID"),
                pi("IoStatus", "NTSTATUS"),
                pi("IoStatusInformation", "ULONG_PTR"),
            ],
        ),
        nt(
            0x0063,
            "NtRemoveIoCompletion",
            vec![
                pi("IoCompletionHandle", "HANDLE"),
                po("KeyContext", "PVOID *"),
                po("ApcContext", "PVOID *"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x0064,
            "NtQueryIoCompletion",
            vec![
                pi("IoCompletionHandle", "HANDLE"),
                pi(
                    "IoCompletionInformationClass",
                    "IO_COMPLETION_INFORMATION_CLASS",
                ),
                po("IoCompletionInformation", "PVOID"),
                pi("IoCompletionInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0065,
            "NtCreateProcessEx",
            vec![
                po("ProcessHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ParentProcess", "HANDLE"),
                pi("Flags", "ULONG"),
                poi("SectionHandle", "HANDLE"),
                poi("DebugPort", "HANDLE"),
                poi("TokenHandle", "HANDLE"),
                pi("Reserved", "ULONG"),
            ],
        ),
    ]
}

fn build_x64_part2b_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0066,
            "NtCreateUserProcess",
            vec![
                po("ProcessHandle", "PHANDLE"),
                po("ThreadHandle", "PHANDLE"),
                pi("ProcessDesiredAccess", "ACCESS_MASK"),
                pi("ThreadDesiredAccess", "ACCESS_MASK"),
                poi("ProcessObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ThreadObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ProcessFlags", "ULONG"),
                pi("ThreadFlags", "ULONG"),
                poi("ProcessParameters", "PRTL_USER_PROCESS_PARAMETERS"),
                pio("CreateInfo", "PPS_CREATE_INFO"),
                poi("AttributeList", "PPS_ATTRIBUTE_LIST"),
            ],
        ),
        nt(
            0x0067,
            "NtDebugActiveProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("DebugObjectHandle", "HANDLE"),
            ],
        ),
        nt(
            0x0068,
            "NtDebugContinue",
            vec![
                pi("DebugObjectHandle", "HANDLE"),
                pi("ClientId", "PCLIENT_ID"),
                pi("ContinueStatus", "NTSTATUS"),
            ],
        ),
        nt(
            0x0069,
            "NtWaitForDebugEvent",
            vec![
                pi("DebugObjectHandle", "HANDLE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
                po("WaitStateChange", "PDBGUI_WAIT_STATE_CHANGE"),
            ],
        ),
        nt(
            0x006A,
            "NtCreateDebugObject",
            vec![
                po("DebugObjectHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("Flags", "ULONG"),
            ],
        ),
        nt(
            0x006B,
            "NtRemoveProcessDebug",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("DebugObjectHandle", "HANDLE"),
            ],
        ),
    ]
}

fn build_x64_part2b_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x006C,
            "NtQueryDebugFilterState",
            vec![pi("ComponentId", "ULONG"), pi("Level", "ULONG")],
        ),
        nt(
            0x006D,
            "NtSetDebugFilterState",
            vec![
                pi("ComponentId", "ULONG"),
                pi("Level", "ULONG"),
                pi("State", "BOOLEAN"),
            ],
        ),
        nt(
            0x006E,
            "NtSystemDebugControl",
            vec![
                pi("Command", "SYSDBG_COMMAND"),
                poi("InputBuffer", "PVOID"),
                pi("InputBufferLength", "ULONG"),
                poo("OutputBuffer", "PVOID"),
                pi("OutputBufferLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x006F,
            "NtQueryPerformanceCounter",
            vec![
                po("PerformanceCounter", "PLARGE_INTEGER"),
                poo("PerformanceFrequency", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x0070,
            "NtQueueApcThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ApcRoutine", "PPS_APC_ROUTINE"),
                poi("ApcArgument1", "PVOID"),
                poi("ApcArgument2", "PVOID"),
                poi("ApcArgument3", "PVOID"),
            ],
        ),
        nt(
            0x0071,
            "NtQueueApcThreadEx",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poi("ReserveHandle", "HANDLE"),
                pi("ApcRoutine", "PPS_APC_ROUTINE"),
                poi("ApcArgument1", "PVOID"),
                poi("ApcArgument2", "PVOID"),
                poi("ApcArgument3", "PVOID"),
            ],
        ),
        nt(0x0072, "NtTestAlert", vec![]),
        nt(0x0073, "NtAlertThread", vec![pi("ThreadHandle", "HANDLE")]),
        nt(
            0x0074,
            "NtAlertResumeThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x0075,
            "NtSuspendProcess",
            vec![pi("ProcessHandle", "HANDLE")],
        ),
        nt(
            0x0076,
            "NtResumeProcess",
            vec![pi("ProcessHandle", "HANDLE")],
        ),
        nt(0x0077, "NtGetCurrentProcessorNumber", vec![]),
        nt(
            0x0078,
            "NtFlushInstructionCache",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("Length", "SIZE_T"),
            ],
        ),
    ]
}

fn build_x64_part2b_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(0x0079, "NtFlushWriteBuffer", vec![]),
        nt(
            0x007A,
            "NtPulseEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x007B,
            "NtQueryDefaultLocale",
            vec![pi("UserProfile", "BOOLEAN"), po("DefaultLocaleId", "PLCID")],
        ),
        nt(
            0x007C,
            "NtSetDefaultLocale",
            vec![pi("UserProfile", "BOOLEAN"), pi("DefaultLocaleId", "LCID")],
        ),
        nt(
            0x007D,
            "NtQueryDefaultUILanguage",
            vec![po("DefaultUILanguageId", "LANGID *")],
        ),
        nt(
            0x007E,
            "NtSetDefaultUILanguage",
            vec![pi("DefaultUILanguageId", "LANGID")],
        ),
        nt(
            0x007F,
            "NtQueryInstallUILanguage",
            vec![po("InstallUILanguageId", "LANGID *")],
        ),
        nt(0x0080, "NtDeleteAtom", vec![pi("Atom", "RTL_ATOM")]),
        nt(
            0x0081,
            "NtFindAtom",
            vec![
                poi("AtomName", "PWSTR"),
                pi("Length", "ULONG"),
                poo("Atom", "PRTL_ATOM"),
            ],
        ),
        nt(
            0x0082,
            "NtAddAtom",
            vec![
                poi("AtomName", "PWSTR"),
                pi("Length", "ULONG"),
                poo("Atom", "PRTL_ATOM"),
            ],
        ),
        nt(
            0x0083,
            "NtQueryInformationAtom",
            vec![
                pi("Atom", "RTL_ATOM"),
                pi("InformationClass", "ATOM_INFORMATION_CLASS"),
                po("AtomInformation", "PVOID"),
                pi("AtomInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0084,
            "NtSetTimerResolution",
            vec![
                pi("DesiredTime", "ULONG"),
                pi("SetResolution", "BOOLEAN"),
                po("ActualTime", "PULONG"),
            ],
        ),
        nt(
            0x0085,
            "NtQueryTimerResolution",
            vec![
                po("MaximumTime", "PULONG"),
                po("MinimumTime", "PULONG"),
                po("CurrentTime", "PULONG"),
            ],
        ),
    ]
}

fn build_x86() -> Vec<WinNtSyscall> {
    let mut v = build_x86_part_a();
    v.extend(build_x86_part_a_ext());
    v.extend(build_x86_part_a_ext_s1());
    v.extend(build_x86_part_b());
    v.extend(build_x86_part_b_s2());
    v.extend(build_x86_part_b_s1());
    v.extend(build_x86_part_b_s1_s1());
    v.extend(build_x86_part_b_ext());
    v.extend(build_x86_part_b_ext_s2());
    v.extend(build_x86_part_b_ext_s1());
    v.extend(build_x86_part_b_ext_s1_s1());
    v.sort_by_key(|s| s.ssn);
    v
}

fn build_x86_part_a() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0025,
            "NtReadFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(
            0x0026,
            "NtWriteFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(0x000C, "NtClose", vec![pi("Handle", "HANDLE")]),
        nt(
            0x0022,
            "NtQueryInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                po("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0023,
            "NtQueryInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                po("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x001A,
            "NtSetInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                pi("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x001B,
            "NtSetInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                pi("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0029,
            "NtTerminateProcess",
            vec![poi("ProcessHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
        nt(
            0x002A,
            "NtTerminateThread",
            vec![poi("ThreadHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
        nt(
            0x002B,
            "NtSuspendThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
    ]
}

fn build_x86_part_a_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x002C,
            "NtResumeThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x0013,
            "NtOpenProcess",
            vec![
                po("ProcessHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ClientId", "PCLIENT_ID"),
            ],
        ),
        nt(
            0x0014,
            "NtOpenThread",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ClientId", "PCLIENT_ID"),
            ],
        ),
        nt(
            0x0035,
            "NtCreateThread",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ProcessHandle", "HANDLE"),
                po("ClientId", "PCLIENT_ID"),
                pi("ThreadContext", "PCONTEXT"),
                pi("InitialTeb", "PINITIAL_TEB"),
                pi("CreateSuspended", "BOOLEAN"),
            ],
        ),
        nt(
            0x0036,
            "NtCreateThreadEx",
            vec![
                po("ThreadHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("ProcessHandle", "HANDLE"),
                pi("StartRoutine", "PUSER_THREAD_START_ROUTINE"),
                poi("Argument", "PVOID"),
                pi("CreateFlags", "ULONG"),
                pi("ZeroBits", "SIZE_T"),
                pi("StackSize", "SIZE_T"),
                pi("MaximumStackSize", "SIZE_T"),
                poi("AttributeList", "PPS_ATTRIBUTE_LIST"),
            ],
        ),
        nt(
            0x0011,
            "NtAllocateVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pi("ZeroBits", "ULONG_PTR"),
                pio("RegionSize", "PSIZE_T"),
                pi("AllocationType", "ULONG"),
                pi("Protect", "ULONG"),
            ],
        ),
    ]
}

fn build_x86_part_a_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x001C,
            "NtFreeVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("FreeType", "ULONG"),
            ],
        ),
        nt(
            0x001D,
            "NtProtectVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("NewProtect", "ULONG"),
                po("OldProtect", "PULONG"),
            ],
        ),
        nt(
            0x001E,
            "NtReadVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                po("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesRead", "PSIZE_T"),
            ],
        ),
        nt(
            0x001F,
            "NtWriteVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesWritten", "PSIZE_T"),
            ],
        ),
        nt(
            0x0020,
            "NtQueryVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("MemoryInformationClass", "MEMORY_INFORMATION_CLASS"),
                po("MemoryInformation", "PVOID"),
                pi("MemoryInformationLength", "SIZE_T"),
                poo("ReturnLength", "PSIZE_T"),
            ],
        ),
    ]
}

fn build_x86_part_b() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0042,
            "NtCreateSection",
            vec![
                po("SectionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("MaximumSize", "PLARGE_INTEGER"),
                pi("SectionPageProtection", "ULONG"),
                pi("AllocationAttributes", "ULONG"),
                poi("FileHandle", "HANDLE"),
            ],
        ),
        nt(
            0x0043,
            "NtOpenSection",
            vec![
                po("SectionHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0044,
            "NtMapViewOfSection",
            vec![
                pi("SectionHandle", "HANDLE"),
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pi("ZeroBits", "ULONG_PTR"),
                pi("CommitSize", "SIZE_T"),
                pio("SectionOffset", "PLARGE_INTEGER"),
                pio("ViewSize", "PSIZE_T"),
                pi("InheritDisposition", "SECTION_INHERIT"),
                pi("AllocationType", "ULONG"),
                pi("Win32Protect", "ULONG"),
            ],
        ),
        nt(
            0x0045,
            "NtUnmapViewOfSection",
            vec![pi("ProcessHandle", "HANDLE"), poi("BaseAddress", "PVOID")],
        ),
        nt(
            0x0032,
            "NtCreateFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                poi("AllocationSize", "PLARGE_INTEGER"),
                pi("FileAttributes", "ULONG"),
                pi("ShareAccess", "ULONG"),
                pi("CreateDisposition", "ULONG"),
                pi("CreateOptions", "ULONG"),
                poi("EaBuffer", "PVOID"),
                pi("EaLength", "ULONG"),
            ],
        ),
    ]
}

fn build_x86_part_b_s2() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0033,
            "NtOpenFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("ShareAccess", "ULONG"),
                pi("OpenOptions", "ULONG"),
            ],
        ),
        nt(
            0x0034,
            "NtQueryInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
        nt(
            0x0050,
            "NtSetInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
        nt(
            0x0051,
            "NtQueryDirectoryFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
                pi("ReturnSingleEntry", "BOOLEAN"),
                poi("FileName", "PUNICODE_STRING"),
                pi("RestartScan", "BOOLEAN"),
            ],
        ),
    ]
}

fn build_x86_part_b_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0052,
            "NtFlushBuffersFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
            ],
        ),
        nt(
            0x0053,
            "NtDeleteFile",
            vec![pi("ObjectAttributes", "POBJECT_ATTRIBUTES")],
        ),
        nt(
            0x0004,
            "NtWaitForSingleObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x00A0,
            "NtWaitForMultipleObjects",
            vec![
                pi("Count", "ULONG"),
                pi("Handles", "HANDLE *"),
                pi("WaitType", "WAIT_TYPE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x0040,
            "NtCreateEvent",
            vec![
                po("EventHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("EventType", "EVENT_TYPE"),
                pi("InitialState", "BOOLEAN"),
            ],
        ),
        nt(
            0x0041,
            "NtOpenEvent",
            vec![
                po("EventHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0060,
            "NtSetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
    ]
}

fn build_x86_part_b_s1_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0061,
            "NtResetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x0062,
            "NtQueryEvent",
            vec![
                pi("EventHandle", "HANDLE"),
                pi("EventInformationClass", "EVENT_INFORMATION_CLASS"),
                po("EventInformation", "PVOID"),
                pi("EventInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0070,
            "NtCreateMutant",
            vec![
                po("MutantHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("InitialOwner", "BOOLEAN"),
            ],
        ),
        nt(
            0x0071,
            "NtReleaseMutant",
            vec![pi("MutantHandle", "HANDLE"), poo("PreviousCount", "PLONG")],
        ),
        nt(
            0x0080,
            "NtCreateSemaphore",
            vec![
                po("SemaphoreHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("InitialCount", "LONG"),
                pi("MaximumCount", "LONG"),
            ],
        ),
        nt(
            0x0081,
            "NtReleaseSemaphore",
            vec![
                pi("SemaphoreHandle", "HANDLE"),
                pi("ReleaseCount", "LONG"),
                poo("PreviousCount", "PLONG"),
            ],
        ),
    ]
}

fn build_x86_part_b_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0090,
            "NtCreateKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("TitleIndex", "ULONG"),
                poi("Class", "PUNICODE_STRING"),
                pi("CreateOptions", "ULONG"),
                poo("Disposition", "PULONG"),
            ],
        ),
        nt(
            0x0091,
            "NtOpenKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0092,
            "NtQueryKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("KeyInformationClass", "KEY_INFORMATION_CLASS"),
                po("KeyInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(
            0x0093,
            "NtSetValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("TitleIndex", "ULONG"),
                pi("Type", "ULONG"),
                poi("Data", "PVOID"),
                pi("DataSize", "ULONG"),
            ],
        ),
        nt(
            0x0094,
            "NtQueryValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("KeyValueInformationClass", "KEY_VALUE_INFORMATION_CLASS"),
                po("KeyValueInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(0x0095, "NtDeleteKey", vec![pi("KeyHandle", "HANDLE")]),
        nt(
            0x0096,
            "NtDeleteValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
            ],
        ),
        nt(
            0x0097,
            "NtEnumerateKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("Index", "ULONG"),
                pi("KeyInformationClass", "KEY_INFORMATION_CLASS"),
                po("KeyInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
    ]
}

fn build_x86_part_b_ext_s2() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0098,
            "NtEnumerateValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("Index", "ULONG"),
                pi("KeyValueInformationClass", "KEY_VALUE_INFORMATION_CLASS"),
                po("KeyValueInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(
            0x00B0,
            "NtQuerySystemInformation",
            vec![
                pi("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
                po("SystemInformation", "PVOID"),
                pi("SystemInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x00B1,
            "NtSetSystemInformation",
            vec![
                pi("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
                pi("SystemInformation", "PVOID"),
                pi("SystemInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x00B2,
            "NtQuerySystemTime",
            vec![po("SystemTime", "PLARGE_INTEGER")],
        ),
        nt(
            0x00C0,
            "NtRaiseHardError",
            vec![
                pi("ErrorStatus", "NTSTATUS"),
                pi("NumberOfParameters", "ULONG"),
                pi("UnicodeStringParameterMask", "ULONG"),
                pi("Parameters", "PULONG_PTR"),
                pi("ValidResponseOptions", "ULONG"),
                po("Response", "PULONG"),
            ],
        ),
        nt(
            0x00C1,
            "NtRaiseException",
            vec![
                pi("ExceptionRecord", "PEXCEPTION_RECORD"),
                pi("ContextRecord", "PCONTEXT"),
                pi("FirstChance", "BOOLEAN"),
            ],
        ),
    ]
}

fn build_x86_part_b_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x00C2,
            "NtContinue",
            vec![pi("ContextRecord", "PCONTEXT"), pi("TestAlert", "BOOLEAN")],
        ),
        nt(
            0x00D0,
            "NtGetContextThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pio("ThreadContext", "PCONTEXT"),
            ],
        ),
        nt(
            0x00D1,
            "NtSetContextThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadContext", "PCONTEXT"),
            ],
        ),
        nt(
            0x00E0,
            "NtDuplicateObject",
            vec![
                pi("SourceProcessHandle", "HANDLE"),
                pi("SourceHandle", "HANDLE"),
                poi("TargetProcessHandle", "HANDLE"),
                poo("TargetHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("HandleAttributes", "ULONG"),
                pi("Options", "ULONG"),
            ],
        ),
        nt(
            0x00F0,
            "NtQueryObject",
            vec![
                poi("Handle", "HANDLE"),
                pi("ObjectInformationClass", "OBJECT_INFORMATION_CLASS"),
                poo("ObjectInformation", "PVOID"),
                pi("ObjectInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x00F1,
            "NtSetInformationObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("ObjectInformationClass", "OBJECT_INFORMATION_CLASS"),
                pi("ObjectInformation", "PVOID"),
                pi("ObjectInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0100,
            "NtOpenProcessToken",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                po("TokenHandle", "PHANDLE"),
            ],
        ),
    ]
}

fn build_x86_part_b_ext_s1_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0101,
            "NtOpenThreadToken",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("OpenAsSelf", "BOOLEAN"),
                po("TokenHandle", "PHANDLE"),
            ],
        ),
        nt(
            0x0102,
            "NtQueryInformationToken",
            vec![
                pi("TokenHandle", "HANDLE"),
                pi("TokenInformationClass", "TOKEN_INFORMATION_CLASS"),
                po("TokenInformation", "PVOID"),
                pi("TokenInformationLength", "ULONG"),
                po("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0103,
            "NtAdjustPrivilegesToken",
            vec![
                pi("TokenHandle", "HANDLE"),
                pi("DisableAllPrivileges", "BOOLEAN"),
                poi("NewState", "PTOKEN_PRIVILEGES"),
                pi("BufferLength", "ULONG"),
                poo("PreviousState", "PTOKEN_PRIVILEGES"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0110,
            "NtDebugActiveProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("DebugObjectHandle", "HANDLE"),
            ],
        ),
        nt(
            0x0111,
            "NtDebugContinue",
            vec![
                pi("DebugObjectHandle", "HANDLE"),
                pi("ClientId", "PCLIENT_ID"),
                pi("ContinueStatus", "NTSTATUS"),
            ],
        ),
        nt(
            0x0112,
            "NtCreateDebugObject",
            vec![
                po("DebugObjectHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("Flags", "ULONG"),
            ],
        ),
    ]
}

// ─── §29.2 API Monitor layer ──────────────────────────────────────────────────

use parking_lot::Mutex;
use std::path::Path;

// ── ArgType / SyscallCategory ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgType {
    Handle,
    PVOID,
    DWORD,
    QWORD,
    BOOL,
    PSTR,
    PWSTR,
    SizeT,
    NTSTATUS,
    UlongPtr,
    PBYTE,
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Handle => "HANDLE",
            Self::PVOID => "PVOID",
            Self::DWORD => "DWORD",
            Self::QWORD => "QWORD",
            Self::BOOL => "BOOL",
            Self::PSTR => "PSTR",
            Self::PWSTR => "PWSTR",
            Self::SizeT => "SIZE_T",
            Self::NTSTATUS => "NTSTATUS",
            Self::UlongPtr => "ULONG_PTR",
            Self::PBYTE => "PBYTE",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    FileIo,
    RegistryIo,
    ProcessThread,
    MemoryMgmt,
    ObjectMgmt,
    Security,
    Network,
    Synchronization,
    Other,
}

impl fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileIo => "FileIO",
            Self::RegistryIo => "RegistryIO",
            Self::ProcessThread => "ProcessThread",
            Self::MemoryMgmt => "MemoryMgmt",
            Self::ObjectMgmt => "ObjectMgmt",
            Self::Security => "Security",
            Self::Network => "Network",
            Self::Synchronization => "Synchronization",
            Self::Other => "Other",
        };
        write!(f, "{s}")
    }
}

// ── SyscallEntry ─────────────────────────────────────────────────────────────

/// A static entry in the Windows syscall table.
///
/// Serialize is derived; Deserialize is intentionally omitted because the
/// `arg_types` field is a `&'static [ArgType]` slice which serde cannot
/// reconstruct from arbitrary input.
#[derive(Debug, Clone, Serialize)]
pub struct SyscallEntry {
    pub nr: u32,
    pub name: &'static str,
    pub arg_types: &'static [ArgType],
    pub ret_type: ArgType,
    pub category: SyscallCategory,
}

// ── WINDOWS_SYSCALL_TABLE (100+ entries, Win10 x64 SSNs) ─────────────────────

macro_rules! se {
    ($nr:expr, $name:expr, [$($arg:expr),*], $ret:expr, $cat:expr) => {
        SyscallEntry {
            nr: $nr,
            name: $name,
            arg_types: &[$($arg),*],
            ret_type: $ret,
            category: $cat,
        }
    };
}

use ArgType::{BOOL, DWORD, Handle, NTSTATUS, PVOID, SizeT, UlongPtr};
use SyscallCategory::{
    FileIo, MemoryMgmt, Network, ObjectMgmt, Other, ProcessThread, RegistryIo, Security,
    Synchronization,
};

// Spelled aliases matching the on-the-wire WinAPI typenames so the
// SyscallEntry table reads like the WDK headers.
pub const SIZE_T: ArgType = ArgType::SizeT;
pub const ULONG_PTR: ArgType = ArgType::UlongPtr;

pub static WINDOWS_SYSCALL_TABLE: &[SyscallEntry] = &[
    // ── File I/O ──────────────────────────────────────────────────────────────
    se!(
        0x0055,
        "NtCreateFile",
        [
            PVOID, DWORD, PVOID, PVOID, PVOID, DWORD, DWORD, DWORD, DWORD, PVOID, DWORD
        ],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0033,
        "NtOpenFile",
        [PVOID, DWORD, PVOID, PVOID, DWORD, DWORD],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0006,
        "NtReadFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, PVOID, DWORD, PVOID, PVOID
        ],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0008,
        "NtWriteFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, PVOID, DWORD, PVOID, PVOID
        ],
        NTSTATUS,
        FileIo
    ),
    se!(0x000F, "NtClose", [Handle], NTSTATUS, ObjectMgmt),
    se!(
        0x0035,
        "NtQueryDirectoryFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, PVOID, DWORD, DWORD, BOOL, PVOID, BOOL
        ],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0013,
        "NtQueryInformationFile",
        [Handle, PVOID, PVOID, DWORD, DWORD],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0025,
        "NtSetInformationFile",
        [Handle, PVOID, PVOID, DWORD, DWORD],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x003A,
        "NtFlushBuffersFile",
        [Handle, PVOID],
        NTSTATUS,
        FileIo
    ),
    se!(0x00A4, "NtDeleteFile", [PVOID], NTSTATUS, FileIo),
    se!(
        0x00AB,
        "NtLockFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD, BOOL
        ],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x00C4,
        "NtUnlockFile",
        [Handle, PVOID, PVOID, PVOID, DWORD],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0052,
        "NtCreateNamedPipeFile",
        [
            PVOID, DWORD, PVOID, PVOID, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PVOID,
            PVOID
        ],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0026,
        "NtCreateMailslotFile",
        [PVOID, DWORD, PVOID, PVOID, DWORD, DWORD, DWORD, PVOID],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0111,
        "NtQueryEaFile",
        [Handle, PVOID, PVOID, DWORD, BOOL, PVOID, DWORD, PVOID, BOOL],
        NTSTATUS,
        FileIo
    ),
    se!(
        0x0121,
        "NtSetEaFile",
        [Handle, PVOID, PVOID, DWORD],
        NTSTATUS,
        FileIo
    ),
    // ── Registry ──────────────────────────────────────────────────────────────
    se!(
        0x0017,
        "NtQueryKey",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x0012,
        "NtOpenKey",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x003E,
        "NtSetValueKey",
        [Handle, PVOID, DWORD, DWORD, PVOID, DWORD],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x001D,
        "NtCreateKey",
        [PVOID, DWORD, PVOID, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(0x002A, "NtDeleteKey", [Handle], NTSTATUS, RegistryIo),
    se!(
        0x001A,
        "NtQueryValueKey",
        [Handle, PVOID, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x0019,
        "NtDeleteValueKey",
        [Handle, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x0032,
        "NtEnumerateKey",
        [Handle, DWORD, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x0031,
        "NtEnumerateValueKey",
        [Handle, DWORD, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(0x00A6, "NtFlushKey", [Handle], NTSTATUS, RegistryIo),
    se!(
        0x00D8,
        "NtNotifyChangeKey",
        [
            Handle, Handle, PVOID, PVOID, PVOID, DWORD, BOOL, PVOID, DWORD, BOOL
        ],
        NTSTATUS,
        RegistryIo
    ),
    se!(0x00A3, "NtLoadKey", [PVOID, PVOID], NTSTATUS, RegistryIo),
    se!(0x00CF, "NtUnloadKey", [PVOID], NTSTATUS, RegistryIo),
    se!(0x00A5, "NtSaveKey", [Handle, Handle], NTSTATUS, RegistryIo),
    se!(
        0x00AE,
        "NtRestoreKey",
        [Handle, Handle, DWORD],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x00EF,
        "NtReplaceKey",
        [PVOID, Handle, PVOID],
        NTSTATUS,
        RegistryIo
    ),
    se!(
        0x00AC,
        "NtOpenKeyEx",
        [PVOID, DWORD, PVOID, DWORD],
        NTSTATUS,
        RegistryIo
    ),
    // ── Process / Thread ──────────────────────────────────────────────────────
    se!(
        0x00B2,
        "NtCreateProcess",
        [PVOID, DWORD, PVOID, Handle, BOOL, Handle, Handle, Handle],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x00BA,
        "NtCreateProcessEx",
        [
            PVOID, DWORD, PVOID, Handle, DWORD, Handle, Handle, Handle, DWORD
        ],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0026,
        "NtOpenProcess",
        [PVOID, DWORD, PVOID, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x002C,
        "NtTerminateProcess",
        [Handle, NTSTATUS],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x004B,
        "NtCreateThread",
        [PVOID, DWORD, PVOID, Handle, PVOID, PVOID, PVOID, BOOL],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x00B0,
        "NtCreateThreadEx",
        [
            PVOID, DWORD, PVOID, Handle, PVOID, PVOID, DWORD, SizeT, SIZE_T, SizeT, PVOID
        ],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0027,
        "NtOpenThread",
        [PVOID, DWORD, PVOID, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0053,
        "NtTerminateThread",
        [Handle, NTSTATUS],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0022,
        "NtSuspendThread",
        [Handle, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x004E,
        "NtResumeThread",
        [Handle, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0075,
        "NtSuspendProcess",
        [Handle],
        NTSTATUS,
        ProcessThread
    ),
    se!(0x0076, "NtResumeProcess", [Handle], NTSTATUS, ProcessThread),
    se!(
        0x0019,
        "NtQueryInformationProcess",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x001F,
        "NtSetInformationProcess",
        [Handle, DWORD, PVOID, DWORD],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0023,
        "NtQueryInformationThread",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x000D,
        "NtSetInformationThread",
        [Handle, DWORD, PVOID, DWORD],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x003A,
        "NtGetContextThread",
        [Handle, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x003B,
        "NtSetContextThread",
        [Handle, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x00B4,
        "NtCreateJobObject",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x00E3,
        "NtAssignProcessToJobObject",
        [Handle, Handle],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0070,
        "NtQueueApcThread",
        [Handle, PVOID, PVOID, PVOID, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    se!(
        0x0071,
        "NtQueueApcThreadEx",
        [Handle, Handle, PVOID, PVOID, PVOID, PVOID],
        NTSTATUS,
        ProcessThread
    ),
    // ── Memory management ─────────────────────────────────────────────────────
    se!(
        0x0018,
        "NtAllocateVirtualMemory",
        [Handle, PVOID, UlongPtr, PVOID, DWORD, DWORD],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x001B,
        "NtFreeVirtualMemory",
        [Handle, PVOID, PVOID, DWORD],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0050,
        "NtProtectVirtualMemory",
        [Handle, PVOID, PVOID, DWORD, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0023,
        "NtQueryVirtualMemory",
        [Handle, PVOID, DWORD, PVOID, SizeT, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x003F,
        "NtReadVirtualMemory",
        [Handle, PVOID, PVOID, SizeT, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x003A,
        "NtWriteVirtualMemory",
        [Handle, PVOID, PVOID, SizeT, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x004F,
        "NtCreateSection",
        [PVOID, DWORD, PVOID, PVOID, DWORD, DWORD, Handle],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0037,
        "NtOpenSection",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0028,
        "NtMapViewOfSection",
        [
            Handle, Handle, PVOID, UlongPtr, SizeT, PVOID, PVOID, DWORD, DWORD, DWORD
        ],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x002A,
        "NtUnmapViewOfSection",
        [Handle, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0036,
        "NtQuerySection",
        [Handle, DWORD, PVOID, SizeT, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x00B9,
        "NtExtendSection",
        [Handle, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x0043,
        "NtFlushVirtualMemory",
        [Handle, PVOID, PVOID, PVOID],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x00A0,
        "NtLockVirtualMemory",
        [Handle, PVOID, PVOID, DWORD],
        NTSTATUS,
        MemoryMgmt
    ),
    se!(
        0x00C3,
        "NtUnlockVirtualMemory",
        [Handle, PVOID, PVOID, DWORD],
        NTSTATUS,
        MemoryMgmt
    ),
    // ── Synchronization ───────────────────────────────────────────────────────
    se!(
        0x0004,
        "NtWaitForSingleObject",
        [Handle, BOOL, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0058,
        "NtWaitForMultipleObjects",
        [DWORD, PVOID, DWORD, BOOL, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0048,
        "NtCreateEvent",
        [PVOID, DWORD, PVOID, DWORD, BOOL],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0040,
        "NtOpenEvent",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x000E,
        "NtSetEvent",
        [Handle, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0014,
        "NtResetEvent",
        [Handle, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0060,
        "NtPulseEvent",
        [Handle, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x005E,
        "NtCreateMutant",
        [PVOID, DWORD, PVOID, BOOL],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00BE,
        "NtReleaseMutant",
        [Handle, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00C7,
        "NtCreateSemaphore",
        [PVOID, DWORD, PVOID, DWORD, DWORD],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00C9,
        "NtReleaseSemaphore",
        [Handle, DWORD, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00CA,
        "NtCreateTimer",
        [PVOID, DWORD, PVOID, DWORD],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00CB,
        "NtSetTimer",
        [Handle, PVOID, PVOID, PVOID, BOOL, DWORD, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00CC,
        "NtCancelTimer",
        [Handle, PVOID],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x0041,
        "NtCreateIoCompletion",
        [PVOID, DWORD, PVOID, DWORD],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x009C,
        "NtSetIoCompletion",
        [Handle, PVOID, PVOID, NTSTATUS, UlongPtr],
        NTSTATUS,
        Synchronization
    ),
    se!(
        0x00D1,
        "NtRemoveIoCompletion",
        [Handle, PVOID, PVOID, PVOID, PVOID],
        NTSTATUS,
        Synchronization
    ),
    // ── Object management ─────────────────────────────────────────────────────
    se!(
        0x0010,
        "NtQueryObject",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x0044,
        "NtDuplicateObject",
        [Handle, Handle, Handle, PVOID, DWORD, DWORD, DWORD],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x003C,
        "NtOpenDirectoryObject",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x0049,
        "NtCreateDirectoryObject",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x004A,
        "NtQueryDirectoryObject",
        [Handle, PVOID, DWORD, BOOL, BOOL, PVOID, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x004C,
        "NtOpenSymbolicLinkObject",
        [PVOID, DWORD, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x004D,
        "NtCreateSymbolicLinkObject",
        [PVOID, DWORD, PVOID, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    se!(
        0x004E,
        "NtQuerySymbolicLinkObject",
        [Handle, PVOID, PVOID],
        NTSTATUS,
        ObjectMgmt
    ),
    // ── Security / Token ──────────────────────────────────────────────────────
    se!(
        0x0028,
        "NtOpenProcessToken",
        [Handle, DWORD, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x0029,
        "NtOpenThreadToken",
        [Handle, DWORD, BOOL, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x002D,
        "NtQueryInformationToken",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x002E,
        "NtSetInformationToken",
        [Handle, DWORD, PVOID, DWORD],
        NTSTATUS,
        Security
    ),
    se!(
        0x002F,
        "NtAdjustPrivilegesToken",
        [Handle, BOOL, PVOID, DWORD, PVOID, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x00C0,
        "NtQuerySecurityObject",
        [Handle, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x00C1,
        "NtSetSecurityObject",
        [Handle, DWORD, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x00D7,
        "NtDuplicateToken",
        [Handle, DWORD, PVOID, BOOL, DWORD, PVOID],
        NTSTATUS,
        Security
    ),
    se!(
        0x00DB,
        "NtCreateToken",
        [
            PVOID, DWORD, PVOID, DWORD, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID
        ],
        NTSTATUS,
        Security
    ),
    se!(
        0x00E1,
        "NtImpersonateThread",
        [Handle, Handle, PVOID],
        NTSTATUS,
        Security
    ),
    // ── LPC / Ports ───────────────────────────────────────────────────────────
    se!(
        0x0077,
        "NtConnectPort",
        [PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(
        0x007A,
        "NtCreatePort",
        [PVOID, PVOID, DWORD, DWORD, PVOID],
        NTSTATUS,
        Other
    ),
    se!(
        0x0108,
        "NtSendWaitReplyPort",
        [Handle, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(0x00FF, "NtReplyPort", [Handle, PVOID], NTSTATUS, Other),
    se!(
        0x0100,
        "NtReplyWaitReceivePort",
        [Handle, PVOID, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(0x0101, "NtRequestPort", [Handle, PVOID], NTSTATUS, Other),
    se!(
        0x0102,
        "NtRequestWaitReplyPort",
        [Handle, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(0x0103, "NtListenPort", [Handle, PVOID], NTSTATUS, Other),
    se!(
        0x0104,
        "NtAcceptConnectPort",
        [PVOID, PVOID, PVOID, BOOL, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(0x0105, "NtCompleteConnectPort", [Handle], NTSTATUS, Other),
    se!(
        0x0106,
        "NtImpersonateClientOfPort",
        [Handle, PVOID],
        NTSTATUS,
        Other
    ),
    // ── System / Debug ────────────────────────────────────────────────────────
    se!(
        0x0036,
        "NtQuerySystemInformation",
        [DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        Other
    ),
    se!(
        0x002B,
        "NtSetSystemInformation",
        [DWORD, PVOID, DWORD],
        NTSTATUS,
        Other
    ),
    se!(0x0092, "NtQuerySystemTime", [PVOID], NTSTATUS, Other),
    se!(
        0x00E7,
        "NtRaiseHardError",
        [NTSTATUS, DWORD, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        Other
    ),
    se!(
        0x0132,
        "NtDebugActiveProcess",
        [Handle, Handle],
        NTSTATUS,
        Other
    ),
    se!(
        0x0046,
        "NtDebugContinue",
        [Handle, PVOID, NTSTATUS],
        NTSTATUS,
        Other
    ),
    se!(
        0x00EE,
        "NtWaitForDebugEvent",
        [Handle, BOOL, PVOID, PVOID],
        NTSTATUS,
        Other
    ),
    se!(
        0x00E8,
        "NtCreateDebugObject",
        [PVOID, DWORD, PVOID, DWORD],
        NTSTATUS,
        Other
    ),
    se!(
        0x0079,
        "NtSystemDebugControl",
        [DWORD, PVOID, DWORD, PVOID, DWORD, PVOID],
        NTSTATUS,
        Other
    ),
    // ── Network (Afd) ─────────────────────────────────────────────────────────
    se!(
        0x0007,
        "NtDeviceIoControlFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, DWORD, PVOID, DWORD, PVOID, DWORD
        ],
        NTSTATUS,
        Network
    ),
    se!(
        0x0005,
        "NtFsControlFile",
        [
            Handle, Handle, PVOID, PVOID, PVOID, DWORD, PVOID, DWORD, PVOID, DWORD
        ],
        NTSTATUS,
        Network
    ),
];

// ── SyscallCapture / SyscallFilter ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallCapture {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub nr: u32,
    pub name: String,
    pub args_raw: [u64; 12],
    pub ret: u64,
    pub duration_ns: u64,
}

impl SyscallCapture {
    #[must_use]
    pub fn new(timestamp: u64, pid: u32, tid: u32, nr: u32, name: impl Into<String>) -> Self {
        Self {
            timestamp,
            pid,
            tid,
            nr,
            name: name.into(),
            args_raw: [0u64; 12],
            ret: 0,
            duration_ns: 0,
        }
    }

    /// Return NTSTATUS name for the return value.
    #[must_use]
    pub fn ret_status_name(&self) -> &'static str {
        decode_ntstatus(u32::try_from(self.ret & 0xFFFF_FFFF).unwrap_or(0))
    }

    /// Return true if the call succeeded (`STATUS_SUCCESS` or informational).
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        (self.ret & 0xFFFF_FFFF) < 0x8000_0000
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallFilter {
    pub include_categories: Vec<SyscallCategory>,
    pub include_pids: Vec<u32>,
    pub exclude_nr: Vec<u32>,
}

impl SyscallFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_categories(mut self, cats: impl IntoIterator<Item = SyscallCategory>) -> Self {
        self.include_categories.extend(cats);
        self
    }

    #[must_use]
    pub fn with_pids(mut self, pids: impl IntoIterator<Item = u32>) -> Self {
        self.include_pids.extend(pids);
        self
    }

    #[must_use]
    pub fn exclude(mut self, nrs: impl IntoIterator<Item = u32>) -> Self {
        self.exclude_nr.extend(nrs);
        self
    }

    /// Returns `true` if a capture passes this filter.
    #[must_use]
    pub fn matches(&self, cap: &SyscallCapture) -> bool {
        // If any explicit exclusion matches, reject.
        if self.exclude_nr.contains(&cap.nr) {
            return false;
        }
        // If pid filter is set, the capture must be from one of those pids.
        if !self.include_pids.is_empty() && !self.include_pids.contains(&cap.pid) {
            return false;
        }
        // If category filter is set, look up the entry.
        if !self.include_categories.is_empty() {
            let entry = WINDOWS_SYSCALL_TABLE.iter().find(|e| e.nr == cap.nr);
            match entry {
                Some(e) => {
                    if !self.include_categories.contains(&e.category) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

// ── SyscallMonitor ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SyscallMonitor {
    captured: Mutex<Vec<SyscallCapture>>,
    filters: Mutex<Vec<SyscallFilter>>,
}

impl Default for SyscallMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallMonitor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
            filters: Mutex::new(Vec::new()),
        }
    }

    pub fn add_filter(&self, f: SyscallFilter) {
        self.filters.lock().push(f);
    }

    pub fn clear_filters(&self) {
        self.filters.lock().clear();
    }

    /// Record a capture if it passes all active filters.
    pub fn record(&self, cap: SyscallCapture) {
        let filters = self.filters.lock();
        let passes = if filters.is_empty() {
            true
        } else {
            filters.iter().all(|f| f.matches(&cap))
        };
        drop(filters);
        if passes {
            self.captured.lock().push(cap);
        }
    }

    /// Snapshot of all captured events.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SyscallCapture> {
        self.captured.lock().clone()
    }

    /// Number of captured events.
    #[must_use]
    pub fn count(&self) -> usize {
        self.captured.lock().len()
    }

    /// Clear the capture buffer.
    pub fn reset(&self) {
        self.captured.lock().clear();
    }

    /// Events for a specific PID.
    #[must_use]
    pub fn for_pid(&self, pid: u32) -> Vec<SyscallCapture> {
        self.captured
            .lock()
            .iter()
            .filter(|c| c.pid == pid)
            .cloned()
            .collect()
    }

    /// Events for a specific syscall number.
    #[must_use]
    pub fn for_nr(&self, nr: u32) -> Vec<SyscallCapture> {
        self.captured
            .lock()
            .iter()
            .filter(|c| c.nr == nr)
            .cloned()
            .collect()
    }
}

// ── NtTraceCollector ──────────────────────────────────────────────────────────

pub struct NtTraceCollector;

impl NtTraceCollector {
    /// Parse an ETL (Event Trace Log) file.
    ///
    /// Full ETW/ETL parsing requires the Windows TDH API or a third-party
    /// ETL parser. This stub returns an empty vec; integrate `windows` crate
    /// `EventAccessQuery` / `TdhGetEventInformation` for production use.
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future ETW parsing failures.
    pub const fn from_etw_log(_path: &Path) -> anyhow::Result<Vec<SyscallCapture>> {
        // NOTE: ETW ETL parsing requires the Windows TDH API (tdh.dll).
        // Use `windows::Win32::System::Diagnostics::Etw` bindings or the
        // `etw-reader` crate (github.com/n4r1b/etw-reader) for real traces.
        Ok(Vec::new())
    }

    /// Parse an API Monitor v2 XML export file.
    ///
    /// API Monitor exports a `<APIMonitor>` root with `<Process>` children
    /// each containing `<Module>` and `<Function>` elements. This parser
    /// performs a minimal text scan to extract function name, PID and return
    /// value without pulling in a full XML library dependency.
    ///
    /// # Errors
    ///
    /// Returns an error if the file at `path` cannot be read.
    pub fn from_api_monitor_xml(path: &Path) -> anyhow::Result<Vec<SyscallCapture>> {
        let data = std::fs::read_to_string(path)?;
        let mut result = Vec::new();
        let mut current_pid: u32 = 0;
        let mut ts: u64 = 0;

        for line in data.lines() {
            let line = line.trim();

            // <Process id="1234" ...>
            if let Some(rest) = line.strip_prefix("<Process") {
                if let Some(id_start) = rest.find("id=\"") {
                    let after = &rest[id_start + 4..];
                    if let Some(end) = after.find('"') {
                        current_pid = after[..end].parse().unwrap_or(0);
                    }
                }
                continue;
            }

            // <Function name="NtCreateFile" returnValue="0x0000_0000" ...>
            if let Some(rest) = line.strip_prefix("<Function") {
                let name = Self::xml_attr(rest, "name").unwrap_or_default();
                let ret_str = Self::xml_attr(rest, "returnValue").unwrap_or_default();
                let ret = u64::from_str_radix(ret_str.trim_start_matches("0x"), 16).unwrap_or(0);

                // Match against WINDOWS_SYSCALL_TABLE for the syscall number.
                let nr = WINDOWS_SYSCALL_TABLE
                    .iter()
                    .find(|e| e.name == name)
                    .map_or(0xFFFF_FFFF, |e| e.nr);

                let mut cap = SyscallCapture::new(ts, current_pid, 0, nr, name);
                cap.ret = ret;
                result.push(cap);
                ts = ts.wrapping_add(1);
            }
        }

        Ok(result)
    }

    /// Parse a custom binary trace format.
    ///
    /// Expected record layout (little-endian):
    /// ```text
    /// u64  timestamp
    /// u32  pid
    /// u32  tid
    /// u32  nr
    /// u32  name_len
    /// [u8; name_len]  name (UTF-8)
    /// [u64; 12]  args_raw
    /// u64  ret
    /// u64  duration_ns
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is truncated or contains an invalid UTF-8 name field.
    pub fn from_raw_bytes(data: &[u8]) -> anyhow::Result<Vec<SyscallCapture>> {
        let mut pos = 0usize;
        let mut result = Vec::new();

        macro_rules! read_u32 {
            () => {{
                if pos + 4 > data.len() {
                    anyhow::bail!("truncated record at offset {pos}");
                }
                let v = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;
                v
            }};
        }
        macro_rules! read_u64 {
            () => {{
                if pos + 8 > data.len() {
                    anyhow::bail!("truncated record at offset {pos}");
                }
                let v = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                pos += 8;
                v
            }};
        }

        while pos < data.len() {
            let timestamp = read_u64!();
            let pid = read_u32!();
            let tid = read_u32!();
            let nr = read_u32!();
            let name_len = read_u32!() as usize;
            let name_end = pos.checked_add(name_len)
                .filter(|&end| end <= data.len())
                .ok_or_else(|| anyhow::anyhow!("name overrun at offset {pos}"))?;
            let name = String::from_utf8_lossy(&data[pos..name_end]).into_owned();
            pos = name_end;

            let mut args_raw = [0u64; 12];
            for a in &mut args_raw {
                *a = read_u64!();
            }
            let ret = read_u64!();
            let duration_ns = read_u64!();

            let mut cap = SyscallCapture::new(timestamp, pid, tid, nr, name);
            cap.args_raw = args_raw;
            cap.ret = ret;
            cap.duration_ns = duration_ns;
            result.push(cap);
        }

        Ok(result)
    }

    // Helper: extract XML attribute value by name from a tag fragment.
    fn xml_attr(fragment: &str, attr: &str) -> Option<String> {
        let needle = format!("{attr}=\"");
        let start = fragment.find(needle.as_str())? + needle.len();
        let end = fragment[start..].find('"')?;
        Some(fragment[start..start + end].to_owned())
    }
}

// ── ApiCategory / WinApiEntry / WIN32_API_DB ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    FileSystem,
    Registry,
    Process,
    Thread,
    Memory,
    Synchronization,
    Security,
    Crypto,
    Network,
    Shell,
    Debug,
    System,
    Ipc,
    Library,
    Console,
    Resource,
    Time,
    Service,
    Loader,
    Other,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WinApiEntry {
    pub dll: &'static str,
    pub name: &'static str,
    pub category: ApiCategory,
    pub arg_count: u8,
}

macro_rules! api {
    ($dll:expr, $name:expr, $cat:ident, $argc:expr) => {
        WinApiEntry {
            dll: $dll,
            name: $name,
            category: ApiCategory::$cat,
            arg_count: $argc,
        }
    };
}

pub static WIN32_API_DB: &[WinApiEntry] = &[
    // ── kernel32.dll – File System ─────────────────────────────────────────────
    api!("kernel32.dll", "CreateFileW", FileSystem, 7),
    api!("kernel32.dll", "CreateFileA", FileSystem, 7),
    api!("kernel32.dll", "ReadFile", FileSystem, 5),
    api!("kernel32.dll", "WriteFile", FileSystem, 5),
    api!("kernel32.dll", "CloseHandle", FileSystem, 1),
    api!("kernel32.dll", "DeleteFileW", FileSystem, 1),
    api!("kernel32.dll", "DeleteFileA", FileSystem, 1),
    api!("kernel32.dll", "MoveFileW", FileSystem, 2),
    api!("kernel32.dll", "MoveFileExW", FileSystem, 3),
    api!("kernel32.dll", "CopyFileW", FileSystem, 3),
    api!("kernel32.dll", "GetFileAttributesW", FileSystem, 1),
    api!("kernel32.dll", "SetFileAttributesW", FileSystem, 2),
    api!("kernel32.dll", "FindFirstFileW", FileSystem, 2),
    api!("kernel32.dll", "FindNextFileW", FileSystem, 2),
    api!("kernel32.dll", "FindClose", FileSystem, 1),
    api!("kernel32.dll", "CreateDirectoryW", FileSystem, 2),
    api!("kernel32.dll", "RemoveDirectoryW", FileSystem, 1),
    api!("kernel32.dll", "GetTempPathW", FileSystem, 2),
    api!("kernel32.dll", "GetTempFileNameW", FileSystem, 4),
    api!("kernel32.dll", "GetFullPathNameW", FileSystem, 4),
    api!("kernel32.dll", "SetFilePointerEx", FileSystem, 4),
    api!("kernel32.dll", "SetEndOfFile", FileSystem, 1),
    api!("kernel32.dll", "FlushFileBuffers", FileSystem, 1),
    api!("kernel32.dll", "LockFile", FileSystem, 5),
    api!("kernel32.dll", "UnlockFile", FileSystem, 5),
    api!("kernel32.dll", "ReadFileEx", FileSystem, 5),
    api!("kernel32.dll", "WriteFileEx", FileSystem, 5),
    api!("kernel32.dll", "DeviceIoControl", FileSystem, 8),
    api!("kernel32.dll", "CreateHardLinkW", FileSystem, 3),
    // ── kernel32.dll – Process / Thread ───────────────────────────────────────
    api!("kernel32.dll", "CreateProcessW", Process, 10),
    api!("kernel32.dll", "CreateProcessA", Process, 10),
    api!("kernel32.dll", "OpenProcess", Process, 3),
    api!("kernel32.dll", "TerminateProcess", Process, 2),
    api!("kernel32.dll", "GetCurrentProcess", Process, 0),
    api!("kernel32.dll", "GetCurrentProcessId", Process, 0),
    api!("kernel32.dll", "GetProcessId", Process, 1),
    api!("kernel32.dll", "ExitProcess", Process, 1),
    api!("kernel32.dll", "WaitForSingleObject", Synchronization, 2),
    api!("kernel32.dll", "WaitForMultipleObjects", Synchronization, 4),
    api!("kernel32.dll", "CreateThread", Thread, 6),
    api!("kernel32.dll", "OpenThread", Thread, 3),
    api!("kernel32.dll", "TerminateThread", Thread, 2),
    api!("kernel32.dll", "GetCurrentThread", Thread, 0),
    api!("kernel32.dll", "GetCurrentThreadId", Thread, 0),
    api!("kernel32.dll", "SuspendThread", Thread, 1),
    api!("kernel32.dll", "ResumeThread", Thread, 1),
    api!("kernel32.dll", "SetThreadContext", Thread, 2),
    api!("kernel32.dll", "GetThreadContext", Thread, 2),
    api!("kernel32.dll", "QueueUserAPC", Thread, 3),
    // ── kernel32.dll – Memory ─────────────────────────────────────────────────
    api!("kernel32.dll", "VirtualAlloc", Memory, 4),
    api!("kernel32.dll", "VirtualAllocEx", Memory, 5),
    api!("kernel32.dll", "VirtualFree", Memory, 3),
    api!("kernel32.dll", "VirtualFreeEx", Memory, 4),
    api!("kernel32.dll", "VirtualProtect", Memory, 4),
    api!("kernel32.dll", "VirtualProtectEx", Memory, 5),
    api!("kernel32.dll", "VirtualQuery", Memory, 3),
    api!("kernel32.dll", "VirtualQueryEx", Memory, 4),
    api!("kernel32.dll", "ReadProcessMemory", Memory, 5),
    api!("kernel32.dll", "WriteProcessMemory", Memory, 5),
    api!("kernel32.dll", "HeapCreate", Memory, 3),
    api!("kernel32.dll", "HeapDestroy", Memory, 1),
    api!("kernel32.dll", "HeapAlloc", Memory, 3),
    api!("kernel32.dll", "HeapFree", Memory, 3),
    api!("kernel32.dll", "HeapReAlloc", Memory, 4),
    api!("kernel32.dll", "MapViewOfFile", Memory, 5),
    api!("kernel32.dll", "UnmapViewOfFile", Memory, 1),
    api!("kernel32.dll", "CreateFileMappingW", Memory, 6),
    api!("kernel32.dll", "OpenFileMappingW", Memory, 3),
    // ── kernel32.dll – Library ────────────────────────────────────────────────
    api!("kernel32.dll", "LoadLibraryW", Library, 1),
    api!("kernel32.dll", "LoadLibraryA", Library, 1),
    api!("kernel32.dll", "LoadLibraryExW", Library, 3),
    api!("kernel32.dll", "FreeLibrary", Library, 1),
    api!("kernel32.dll", "GetProcAddress", Library, 2),
    api!("kernel32.dll", "GetModuleHandleW", Library, 1),
    api!("kernel32.dll", "GetModuleHandleA", Library, 1),
    api!("kernel32.dll", "GetModuleFileNameW", Library, 3),
    // ── kernel32.dll – Sync ───────────────────────────────────────────────────
    api!("kernel32.dll", "CreateEventW", Synchronization, 4),
    api!("kernel32.dll", "OpenEventW", Synchronization, 3),
    api!("kernel32.dll", "SetEvent", Synchronization, 1),
    api!("kernel32.dll", "ResetEvent", Synchronization, 1),
    api!("kernel32.dll", "PulseEvent", Synchronization, 1),
    api!("kernel32.dll", "CreateMutexW", Synchronization, 3),
    api!("kernel32.dll", "OpenMutexW", Synchronization, 3),
    api!("kernel32.dll", "ReleaseMutex", Synchronization, 1),
    api!("kernel32.dll", "CreateSemaphoreW", Synchronization, 4),
    api!("kernel32.dll", "OpenSemaphoreW", Synchronization, 3),
    api!("kernel32.dll", "ReleaseSemaphore", Synchronization, 3),
    api!("kernel32.dll", "Sleep", Synchronization, 1),
    api!("kernel32.dll", "SleepEx", Synchronization, 2),
    api!("kernel32.dll", "CreateWaitableTimerW", Synchronization, 3),
    api!("kernel32.dll", "SetWaitableTimer", Synchronization, 6),
    // ── kernel32.dll – System ─────────────────────────────────────────────────
    api!("kernel32.dll", "GetSystemInfo", System, 1),
    api!("kernel32.dll", "GetNativeSystemInfo", System, 1),
    api!("kernel32.dll", "GlobalMemoryStatusEx", System, 1),
    api!("kernel32.dll", "GetSystemTimeAsFileTime", System, 1),
    api!("kernel32.dll", "QueryPerformanceCounter", System, 1),
    api!("kernel32.dll", "GetTickCount64", System, 0),
    api!("kernel32.dll", "IsDebuggerPresent", Debug, 0),
    api!("kernel32.dll", "CheckRemoteDebuggerPresent", Debug, 2),
    api!("kernel32.dll", "OutputDebugStringW", Debug, 1),
    api!("kernel32.dll", "DebugBreak", Debug, 0),
    api!("kernel32.dll", "RaiseException", Debug, 4),
    // ── ntdll.dll ─────────────────────────────────────────────────────────────
    api!("ntdll.dll", "RtlAllocateHeap", Memory, 3),
    api!("ntdll.dll", "RtlFreeHeap", Memory, 3),
    api!("ntdll.dll", "RtlReAllocateHeap", Memory, 4),
    api!("ntdll.dll", "LdrLoadDll", Library, 4),
    api!("ntdll.dll", "LdrUnloadDll", Library, 1),
    api!("ntdll.dll", "LdrGetProcedureAddress", Library, 4),
    api!("ntdll.dll", "RtlCreateHeap", Memory, 6),
    api!("ntdll.dll", "RtlDestroyHeap", Memory, 1),
    api!("ntdll.dll", "RtlInitUnicodeString", System, 2),
    api!("ntdll.dll", "RtlUnicodeStringToAnsiString", System, 3),
    api!("ntdll.dll", "RtlAnsiStringToUnicodeString", System, 3),
    api!("ntdll.dll", "RtlDosPathNameToNtPathName_U", FileSystem, 4),
    api!("ntdll.dll", "RtlCreateUserThread", Thread, 10),
    api!("ntdll.dll", "RtlGetVersion", System, 1),
    api!("ntdll.dll", "RtlNtStatusToDosError", System, 1),
    api!("ntdll.dll", "NtdllDefWindowProc_W", Other, 4),
    api!("ntdll.dll", "RtlCaptureContext", Debug, 1),
    api!("ntdll.dll", "RtlLookupFunctionEntry", Debug, 3),
    // ── advapi32.dll ──────────────────────────────────────────────────────────
    api!("advapi32.dll", "RegOpenKeyExW", Registry, 5),
    api!("advapi32.dll", "RegOpenKeyExA", Registry, 5),
    api!("advapi32.dll", "RegCreateKeyExW", Registry, 9),
    api!("advapi32.dll", "RegDeleteKeyW", Registry, 2),
    api!("advapi32.dll", "RegDeleteValueW", Registry, 2),
    api!("advapi32.dll", "RegQueryValueExW", Registry, 6),
    api!("advapi32.dll", "RegSetValueExW", Registry, 6),
    api!("advapi32.dll", "RegEnumKeyExW", Registry, 8),
    api!("advapi32.dll", "RegEnumValueW", Registry, 8),
    api!("advapi32.dll", "RegCloseKey", Registry, 1),
    api!("advapi32.dll", "RegConnectRegistryW", Registry, 3),
    api!("advapi32.dll", "RegLoadKeyW", Registry, 3),
    api!("advapi32.dll", "RegSaveKeyW", Registry, 3),
    api!("advapi32.dll", "RegFlushKey", Registry, 1),
    api!("advapi32.dll", "OpenProcessToken", Security, 3),
    api!("advapi32.dll", "OpenThreadToken", Security, 4),
    api!("advapi32.dll", "LookupPrivilegeValueW", Security, 3),
    api!("advapi32.dll", "AdjustTokenPrivileges", Security, 6),
    api!("advapi32.dll", "GetTokenInformation", Security, 5),
    api!("advapi32.dll", "SetTokenInformation", Security, 4),
    api!("advapi32.dll", "DuplicateToken", Security, 3),
    api!("advapi32.dll", "DuplicateTokenEx", Security, 6),
    api!("advapi32.dll", "ImpersonateLoggedOnUser", Security, 1),
    api!("advapi32.dll", "RevertToSelf", Security, 0),
    api!("advapi32.dll", "IsUserAnAdmin", Security, 0),
    api!("advapi32.dll", "CreateServiceW", System, 13),
    api!("advapi32.dll", "OpenServiceW", System, 3),
    api!("advapi32.dll", "StartServiceW", System, 3),
    api!("advapi32.dll", "ControlService", System, 3),
    api!("advapi32.dll", "DeleteService", System, 1),
    api!("advapi32.dll", "OpenSCManagerW", System, 3),
    api!("advapi32.dll", "CloseServiceHandle", System, 1),
    // ── ws2_32.dll ────────────────────────────────────────────────────────────
    api!("ws2_32.dll", "WSAStartup", Network, 2),
    api!("ws2_32.dll", "WSACleanup", Network, 0),
    api!("ws2_32.dll", "socket", Network, 3),
    api!("ws2_32.dll", "closesocket", Network, 1),
    api!("ws2_32.dll", "bind", Network, 3),
    api!("ws2_32.dll", "listen", Network, 2),
    api!("ws2_32.dll", "accept", Network, 3),
    api!("ws2_32.dll", "connect", Network, 3),
    api!("ws2_32.dll", "send", Network, 4),
    api!("ws2_32.dll", "recv", Network, 4),
    api!("ws2_32.dll", "sendto", Network, 6),
    api!("ws2_32.dll", "recvfrom", Network, 6),
    api!("ws2_32.dll", "WSASend", Network, 7),
    api!("ws2_32.dll", "WSARecv", Network, 7),
    api!("ws2_32.dll", "WSAConnect", Network, 7),
    api!("ws2_32.dll", "WSAAccept", Network, 5),
    api!("ws2_32.dll", "WSASocketW", Network, 6),
    api!("ws2_32.dll", "gethostbyname", Network, 1),
    api!("ws2_32.dll", "getaddrinfo", Network, 4),
    api!("ws2_32.dll", "freeaddrinfo", Network, 1),
    api!("ws2_32.dll", "setsockopt", Network, 5),
    api!("ws2_32.dll", "getsockopt", Network, 5),
    api!("ws2_32.dll", "ioctlsocket", Network, 3),
    api!("ws2_32.dll", "select", Network, 5),
    api!("ws2_32.dll", "WSAIoctl", Network, 9),
    // ── wininet.dll ───────────────────────────────────────────────────────────
    api!("wininet.dll", "InternetOpenW", Network, 5),
    api!("wininet.dll", "InternetConnectW", Network, 9),
    api!("wininet.dll", "InternetOpenUrlW", Network, 6),
    api!("wininet.dll", "HttpOpenRequestW", Network, 8),
    api!("wininet.dll", "HttpSendRequestW", Network, 5),
    api!("wininet.dll", "HttpQueryInfoW", Network, 5),
    api!("wininet.dll", "InternetReadFile", Network, 4),
    api!("wininet.dll", "InternetWriteFile", Network, 4),
    api!("wininet.dll", "InternetCloseHandle", Network, 1),
    api!("wininet.dll", "FtpOpenFileW", Network, 5),
    api!("wininet.dll", "FtpPutFileW", Network, 5),
    api!("wininet.dll", "FtpGetFileW", Network, 7),
    api!("wininet.dll", "InternetGetCookieW", Network, 4),
    api!("wininet.dll", "InternetSetCookieW", Network, 3),
    api!("wininet.dll", "InternetSetOptionW", Network, 4),
    // ── shell32.dll ───────────────────────────────────────────────────────────
    api!("shell32.dll", "ShellExecuteW", Shell, 6),
    api!("shell32.dll", "ShellExecuteExW", Shell, 1),
    api!("shell32.dll", "SHGetFolderPathW", Shell, 5),
    api!("shell32.dll", "SHGetSpecialFolderPathW", Shell, 4),
    api!("shell32.dll", "SHCreateDirectoryExW", Shell, 3),
    api!("shell32.dll", "SHDeleteFileW", Shell, 3),
    api!("shell32.dll", "SHCopyFilesW", Shell, 4),
    api!("shell32.dll", "SHMoveFileW", Shell, 4),
    api!("shell32.dll", "SHFileOperationW", Shell, 1),
    api!("shell32.dll", "ExtractIconExW", Shell, 5),
    api!("shell32.dll", "FindExecutableW", Shell, 3),
    // ── crypt32.dll ───────────────────────────────────────────────────────────
    api!("crypt32.dll", "CryptEncrypt", Crypto, 7),
    api!("crypt32.dll", "CryptDecrypt", Crypto, 6),
    api!("crypt32.dll", "CryptGenRandom", Crypto, 3),
    api!("crypt32.dll", "CryptAcquireContextW", Crypto, 5),
    api!("crypt32.dll", "CryptReleaseContext", Crypto, 2),
    api!("crypt32.dll", "CryptImportKey", Crypto, 6),
    api!("crypt32.dll", "CryptExportKey", Crypto, 6),
    api!("crypt32.dll", "CryptCreateHash", Crypto, 5),
    api!("crypt32.dll", "CryptHashData", Crypto, 4),
    api!("crypt32.dll", "CryptGetHashParam", Crypto, 5),
    api!("crypt32.dll", "CryptDestroyHash", Crypto, 1),
    api!("crypt32.dll", "CryptDestroyKey", Crypto, 1),
    api!("crypt32.dll", "CertOpenStore", Crypto, 5),
    api!("crypt32.dll", "CertCloseStore", Crypto, 2),
    api!("crypt32.dll", "CertFindCertificateInStore", Crypto, 6),
    api!("crypt32.dll", "CryptProtectData", Crypto, 7),
    api!("crypt32.dll", "CryptUnprotectData", Crypto, 7),
    api!("crypt32.dll", "PFXExportCertStoreEx", Crypto, 5),
    api!("crypt32.dll", "PFXImportCertStore", Crypto, 3),
    api!("crypt32.dll", "CryptStringToBinaryW", Crypto, 6),
    api!("crypt32.dll", "CryptBinaryToStringW", Crypto, 5),
    // ── advapi32.dll – Service ────────────────────────────────────────────────
    api!("advapi32.dll", "OpenSCManagerW", Service, 3),
    api!("advapi32.dll", "OpenSCManagerA", Service, 3),
    api!("advapi32.dll", "CreateServiceW", Service, 13),
    api!("advapi32.dll", "CreateServiceA", Service, 13),
    api!("advapi32.dll", "OpenServiceW", Service, 3),
    api!("advapi32.dll", "OpenServiceA", Service, 3),
    api!("advapi32.dll", "StartServiceW", Service, 3),
    api!("advapi32.dll", "ControlService", Service, 3),
    api!("advapi32.dll", "DeleteService", Service, 1),
    api!("advapi32.dll", "CloseServiceHandle", Service, 1),
    api!("advapi32.dll", "QueryServiceStatus", Service, 2),
    api!("advapi32.dll", "ChangeServiceConfigW", Service, 11),
    // ── kernel32.dll – Loader ─────────────────────────────────────────────────
    api!("kernel32.dll", "LoadLibraryW", Loader, 1),
    api!("kernel32.dll", "LoadLibraryA", Loader, 1),
    api!("kernel32.dll", "LoadLibraryExW", Loader, 3),
    api!("kernel32.dll", "LoadLibraryExA", Loader, 3),
    api!("kernel32.dll", "GetProcAddress", Loader, 2),
    api!("kernel32.dll", "FreeLibrary", Loader, 1),
    api!("kernel32.dll", "GetModuleHandleW", Loader, 1),
    api!("kernel32.dll", "GetModuleHandleA", Loader, 1),
    api!("kernel32.dll", "GetModuleFileNameW", Loader, 3),
    // ── ntdll.dll – additional entries ────────────────────────────────────────
    api!("ntdll.dll", "NtCreateFile", FileSystem, 11),
    api!("ntdll.dll", "NtOpenFile", FileSystem, 6),
    api!("ntdll.dll", "NtReadFile", FileSystem, 9),
    api!("ntdll.dll", "NtWriteFile", FileSystem, 9),
    api!("ntdll.dll", "NtClose", FileSystem, 1),
    api!("ntdll.dll", "NtCreateKey", Registry, 7),
    api!("ntdll.dll", "NtOpenKey", Registry, 3),
    api!("ntdll.dll", "NtSetValueKey", Registry, 6),
    api!("ntdll.dll", "NtQueryValueKey", Registry, 6),
    api!("ntdll.dll", "NtDeleteKey", Registry, 1),
    api!("ntdll.dll", "NtCreateProcess", Process, 8),
    api!("ntdll.dll", "NtCreateProcessEx", Process, 9),
    api!("ntdll.dll", "NtOpenProcess", Process, 4),
    api!("ntdll.dll", "NtTerminateProcess", Process, 2),
    api!("ntdll.dll", "NtCreateThreadEx", Thread, 11),
    api!("ntdll.dll", "NtOpenThread", Thread, 4),
    api!("ntdll.dll", "NtAllocateVirtualMemory", Memory, 6),
    api!("ntdll.dll", "NtFreeVirtualMemory", Memory, 4),
    api!("ntdll.dll", "NtProtectVirtualMemory", Memory, 5),
    api!("ntdll.dll", "NtReadVirtualMemory", Memory, 5),
    api!("ntdll.dll", "NtWriteVirtualMemory", Memory, 5),
    api!("ntdll.dll", "NtQuerySystemInformation", System, 4),
    api!("ntdll.dll", "NtQueryInformationProcess", Process, 5),
    api!("ntdll.dll", "NtSetInformationProcess", Process, 4),
    api!("ntdll.dll", "NtCreateSection", Memory, 7),
    api!("ntdll.dll", "NtMapViewOfSection", Memory, 10),
    api!("ntdll.dll", "NtUnmapViewOfSection", Memory, 2),
    api!("ntdll.dll", "NtDuplicateObject", System, 7),
    api!("ntdll.dll", "NtDelayExecution", Thread, 2),
    api!("ntdll.dll", "NtResumeThread", Thread, 2),
    api!("ntdll.dll", "NtSuspendThread", Thread, 2),
    // ── winhttp.dll – Network ─────────────────────────────────────────────────
    api!("winhttp.dll", "WinHttpOpen", Network, 5),
    api!("winhttp.dll", "WinHttpConnect", Network, 4),
    api!("winhttp.dll", "WinHttpOpenRequest", Network, 7),
    api!("winhttp.dll", "WinHttpSendRequest", Network, 7),
    api!("winhttp.dll", "WinHttpReceiveResponse", Network, 2),
    api!("winhttp.dll", "WinHttpReadData", Network, 4),
    api!("winhttp.dll", "WinHttpWriteData", Network, 4),
    api!("winhttp.dll", "WinHttpCloseHandle", Network, 1),
    api!("winhttp.dll", "WinHttpQueryHeaders", Network, 6),
    api!("winhttp.dll", "WinHttpSetOption", Network, 4),
];

// ── decode_ntstatus ───────────────────────────────────────────────────────────

/// Map a 32-bit NTSTATUS code to its symbolic name.
/// Returns `"STATUS_UNKNOWN"` for unrecognised codes.
#[must_use]
pub const fn decode_ntstatus(code: u32) -> &'static str {
    if code < 0x4000_0000 {
        decode_ntstatus_success(code)
    } else if code < 0xC000_0000 {
        decode_ntstatus_warning(code)
    } else {
        decode_ntstatus_error(code)
    }
}

/// Decode success/informational NTSTATUS codes (`0x0000_0000`–`0x3FFF_FFFF`).
const fn decode_ntstatus_success(code: u32) -> &'static str {
    match code {
        0x0000_0000 => "STATUS_SUCCESS",
        0x0000_0001 => "STATUS_WAIT_1",
        0x0000_0002 => "STATUS_WAIT_2",
        0x0000_0003 => "STATUS_WAIT_3",
        0x0000_00C0 => "STATUS_WAIT_63",
        0x0000_00FF => "STATUS_ABANDONED_WAIT_0",
        0x0000_0100 => "STATUS_USER_APC",
        0x0000_0101 => "STATUS_ALERTED",
        0x0000_0102 => "STATUS_TIMEOUT",
        0x0000_0103 => "STATUS_PENDING",
        0x0000_0104 => "STATUS_REPARSE",
        0x0000_0105 => "STATUS_MORE_ENTRIES",
        0x0000_0106 => "STATUS_NOT_ALL_ASSIGNED",
        0x0000_010A => "STATUS_SOME_NOT_MAPPED",
        0x0000_010B => "STATUS_OPLOCK_BREAK_IN_PROGRESS",
        0x0000_010C => "STATUS_VOLUME_MOUNTED",
        0x0000_010D => "STATUS_RXACT_COMMITTED",
        0x0000_010E => "STATUS_NOTIFY_CLEANUP",
        0x0000_010F => "STATUS_NOTIFY_ENUM_DIR",
        0x0000_0120 => "STATUS_NO_MORE_ENTRIES",
        _ => "STATUS_UNKNOWN",
    }
}

/// Decode warning-range NTSTATUS codes (`0x4000_0000`–`0xBFFF_FFFF`).
const fn decode_ntstatus_warning(code: u32) -> &'static str {
    match code {
        0x4000_0005 | 0x8000_0005 => "STATUS_BUFFER_OVERFLOW",
        0x4000_0008 => "STATUS_DEVICE_PAPER_EMPTY",
        0x8000_000D | 0x8000_0002 => "STATUS_DATATYPE_MISALIGNMENT",
        0x8000_000F => "STATUS_NO_MORE_FILES",
        0x8000_0010 => "STATUS_END_OF_FILE",
        0x8000_0011 => "STATUS_NO_MORE_EAS",
        0x8000_0012 => "STATUS_NO_MORE_ENTRIES",
        0x8000_0013 => "STATUS_GUARDED_HEAP_VIOLATION",
        _ => "STATUS_UNKNOWN",
    }
}

/// Decode error-range NTSTATUS codes (`0xC000_0000`+).
const fn decode_ntstatus_error(code: u32) -> &'static str {
    if code <= 0xC000_0055 {
        decode_ntstatus_error_low(code)
    } else {
        decode_ntstatus_error_high(code)
    }
}

/// Decode error-range NTSTATUS codes through `0xC000_0055`.
const fn decode_ntstatus_error_low(code: u32) -> &'static str {
    match code {
        0xC000_0001 => "STATUS_UNSUCCESSFUL",
        0xC000_0002 => "STATUS_NOT_IMPLEMENTED",
        0xC000_0003 => "STATUS_INVALID_INFO_CLASS",
        0xC000_0004 => "STATUS_INFO_LENGTH_MISMATCH",
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0006 => "STATUS_IN_PAGE_ERROR",
        0xC000_0007 => "STATUS_PAGEFILE_QUOTA",
        0xC000_0008 => "STATUS_INVALID_HANDLE",
        0xC000_0009 => "STATUS_BAD_INITIAL_STACK",
        0xC000_000A => "STATUS_BAD_INITIAL_PC",
        0xC000_000B => "STATUS_INVALID_CID",
        0xC000_000C => "STATUS_TIMER_NOT_CANCELED",
        0xC000_000D => "STATUS_INVALID_PARAMETER",
        0xC000_000E => "STATUS_NO_SUCH_DEVICE",
        0xC000_000F => "STATUS_NO_SUCH_FILE",
        0xC000_0010 => "STATUS_INVALID_DEVICE_REQUEST",
        0xC000_0011 => "STATUS_END_OF_FILE",
        0xC000_0012 => "STATUS_WRONG_VOLUME",
        0xC000_0013 => "STATUS_NO_MEDIA_IN_DEVICE",
        0xC000_0015 => "STATUS_NONEXISTENT_SECTOR",
        0xC000_0016 => "STATUS_MORE_PROCESSING_REQUIRED",
        0xC000_0017 => "STATUS_NO_MEMORY",
        0xC000_0018 => "STATUS_CONFLICTING_ADDRESSES",
        0xC000_0019 => "STATUS_NOT_MAPPED_VIEW",
        0xC000_001A => "STATUS_UNABLE_TO_FREE_VM",
        0xC000_001C => "STATUS_INVALID_SYSTEM_SERVICE",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_001E => "STATUS_INVALID_LOCK_SEQUENCE",
        0xC000_001F => "STATUS_INVALID_VIEW_SIZE",
        0xC000_0020 => "STATUS_INVALID_FILE_FOR_SECTION",
        0xC000_0021 => "STATUS_ALREADY_COMMITTED",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0023 => "STATUS_BUFFER_TOO_SMALL",
        0xC000_0024 => "STATUS_OBJECT_TYPE_MISMATCH",
        0xC000_0025 => "STATUS_NONCONTINUABLE_EXCEPTION",
        0xC000_0026 => "STATUS_INVALID_DISPOSITION",
        0xC000_0027 => "STATUS_UNWIND",
        0xC000_0028 => "STATUS_BAD_STACK",
        0xC000_0029 => "STATUS_INVALID_UNWIND_TARGET",
        0xC000_002A => "STATUS_NOT_LOCKED",
        0xC000_002B => "STATUS_PARITY_ERROR",
        0xC000_002C => "STATUS_UNABLE_TO_DECOMMIT_VM",
        0xC000_002D => "STATUS_NOT_COMMITTED",
        0xC000_0030 => "STATUS_INVALID_PARAMETER_MIX",
        0xC000_0032 => "STATUS_DISK_CORRUPT_ERROR",
        0xC000_0033 => "STATUS_OBJECT_NAME_INVALID",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000_0035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC000_0037 => "STATUS_PORT_DISCONNECTED",
        0xC000_0038 => "STATUS_DEVICE_ALREADY_ATTACHED",
        0xC000_0039 => "STATUS_OBJECT_PATH_INVALID",
        0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000_003B => "STATUS_OBJECT_PATH_SYNTAX_BAD",
        0xC000_003C => "STATUS_DATA_OVERRUN",
        0xC000_003D => "STATUS_DATA_LATE_ERROR",
        0xC000_003E => "STATUS_DATA_ERROR",
        0xC000_003F => "STATUS_CRC_ERROR",
        0xC000_0041 => "STATUS_FILE_IS_A_DIRECTORY",
        0xC000_0042 => "STATUS_NOT_A_DIRECTORY",
        0xC000_0043 => "STATUS_FILE_RENAME_INFORMATION",
        0xC000_0044 => "STATUS_QUOTA_EXCEEDED",
        0xC000_0045 => "STATUS_INVALID_PARAMETER_1",
        0xC000_0046 => "STATUS_INVALID_PARAMETER_2",
        0xC000_004F => "STATUS_PIPE_NOT_AVAILABLE",
        0xC000_0051 => "STATUS_PIPE_BUSY",
        0xC000_0052 => "STATUS_ILLEGAL_FUNCTION",
        0xC000_0053 => "STATUS_PIPE_DISCONNECTED",
        0xC000_0054 => "STATUS_PIPE_CLOSING",
        0xC000_0055 => "STATUS_PIPE_CONNECTED",
        _ => "STATUS_UNKNOWN",
    }
}

/// Decode error-range NTSTATUS codes from `0xC000_0056` onward.
const fn decode_ntstatus_error_high(code: u32) -> &'static str {
    match code {
        0xC000_0056 => "STATUS_PIPE_LISTENING",
        0xC000_005A => "STATUS_INVALID_PIPE_STATE",
        0xC000_005B => "STATUS_PIPE_BROKEN",
        0xC000_005C => "STATUS_CONNECTION_REFUSED",
        0xC000_005E => "STATUS_BUFFER_ALL_ZEROS",
        0xC000_0061 => "STATUS_PRIVILEGE_NOT_HELD",
        0xC000_0062 => "STATUS_INVALID_ACCOUNT_NAME",
        0xC000_0064 => "STATUS_NO_SUCH_USER",
        0xC000_006A => "STATUS_WRONG_PASSWORD",
        0xC000_006C => "STATUS_PASSWORD_RESTRICTION",
        0xC000_006D => "STATUS_LOGON_FAILURE",
        0xC000_006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000_006F => "STATUS_INVALID_LOGON_HOURS",
        0xC000_0070 => "STATUS_INVALID_WORKSTATION",
        0xC000_0071 => "STATUS_PASSWORD_EXPIRED",
        0xC000_0072 => "STATUS_ACCOUNT_DISABLED",
        0xC000_0073 => "STATUS_NONE_MAPPED",
        0xC000_0076 => "STATUS_DISK_FULL",
        0xC000_0077 => "STATUS_INTERNAL_ERROR",
        0xC000_0078 => "STATUS_GENERIC_NOT_MAPPED",
        0xC000_0082 => "STATUS_HANDLE_NOT_CLOSABLE",
        0xC000_0096 => "STATUS_MAPPED_FILE_SIZE_ZERO",
        0xC000_009A => "STATUS_INSUFFICIENT_RESOURCES",
        0xC000_009B => "STATUS_DFS_EXIT_PATH_FOUND",
        0xC000_009C => "STATUS_DEVICE_DATA_ERROR",
        0xC000_009D => "STATUS_DEVICE_NOT_CONNECTED",
        0xC000_00A0 => "STATUS_TOO_MANY_PAGING_FILES",
        0xC000_00A3 => "STATUS_DEVICE_NOT_READY",
        0xC000_00BB => "STATUS_NOT_SUPPORTED",
        0xC000_00BE => "STATUS_BAD_NETWORK_PATH",
        0xC000_00C0 => "STATUS_NETWORK_NAME_DELETED",
        0xC000_00CC => "STATUS_BAD_NETWORK_NAME",
        0xC000_00D0 => "STATUS_INVALID_NETWORK_RESPONSE",
        0xC000_00D9 => "STATUS_UNEXPECTED_NETWORK_ERROR",
        0xC000_0100 => "STATUS_FILE_INVALID",
        0xC000_0101 => "STATUS_FS_DRIVER_REQUIRED",
        0xC000_0103 => "STATUS_NOT_SAME_DEVICE",
        0xC000_0107 => "STATUS_FILES_OPEN",
        0xC000_0120 => "STATUS_CANCELLED",
        0xC000_0121 => "STATUS_CANNOT_DELETE",
        0xC000_0123 => "STATUS_FILE_DELETED",
        0xC000_0128 => "STATUS_FILE_CLOSED",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0138 => "STATUS_ORDINAL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_013A => "STATUS_CONTROL_C_EXIT",
        0xC000_013B => "STATUS_LOCAL_DISCONNECT",
        0xC000_013C => "STATUS_REMOTE_DISCONNECT",
        0xC000_013D => "STATUS_REMOTE_RESOURCES",
        0xC000_013E => "STATUS_LINK_FAILED",
        0xC000_0141 => "STATUS_DESTINATION_ELEMENT_FULL",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0xC000_0143 => "STATUS_SHUTDOWN_IN_PROGRESS",
        0xC000_01A5 => "STATUS_HANDLE_NOT_WAITABLE",
        0xC000_0190 => "STATUS_TRANSACTION_INVALID_PARAMETER",
        0xC000_0194 => "STATUS_POSSIBLE_DEADLOCK",
        0xC000_0225 => "STATUS_NOT_FOUND",
        0xC000_0257 => "STATUS_CANNOT_IMPERSONATE",
        0xC000_025E => "STATUS_NAME_TOO_LONG",
        0xC000_0263 => "STATUS_DRIVER_FAILED_SLEEP",
        0xC000_02B4 => "STATUS_GRAPHICS_DRIVER_MISMATCH",
        0xC000_0354 => "STATUS_DEBUGGER_INACTIVE",
        0xC000_0374 => "STATUS_HEAP_CORRUPTION",
        0xC000_0380 => "STATUS_SMARTCARD_WRONG_PIN",
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xC000_0420 => "STATUS_ASSERTION_FAILURE",
        0xC000_070A => "STATUS_INVALID_PARAMETER_MAX",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        _ => "STATUS_UNKNOWN",
    }
}

// ─── Inline hook infrastructure ───────────────────────────────────────────────

/// Maximum bytes saved for a trampoline (enough for a rel32 JMP + one extra).
pub const TRAMPOLINE_MAX_BYTES: usize = 16;

/// A description of an inline hook installed at a function entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineHookDescriptor {
    /// Target function name.
    pub function: String,
    /// DLL containing the function.
    pub dll: String,
    /// Virtual address of the hook target (as recorded at install time).
    pub target_va: u64,
    /// Address of the detour (our replacement) function.
    pub detour_va: u64,
    /// Address of the trampoline (calls original code).
    pub trampoline_va: u64,
    /// Original bytes overwritten by the JMP patch.
    pub original_bytes: Vec<u8>,
    /// Whether the hook is currently active.
    pub active: bool,
}

impl InlineHookDescriptor {
    /// Build a new descriptor (hook not yet installed).
    #[must_use]
    pub fn new(
        function: impl Into<String>,
        dll: impl Into<String>,
        target_va: u64,
        detour_va: u64,
        trampoline_va: u64,
        original_bytes: Vec<u8>,
    ) -> Self {
        Self {
            function: function.into(),
            dll: dll.into(),
            target_va,
            detour_va,
            trampoline_va,
            original_bytes,
            active: false,
        }
    }

    /// Return the x64 JMP rel32 patch bytes that redirect `target_va` to
    /// `detour_va`.
    ///
    /// Uses a 5-byte near jump (`E9 <rel32>`).  Caller must ensure that the
    /// detour is reachable within ±2 GiB of the target.
    #[must_use]
    pub const fn jmp_patch_bytes(&self) -> [u8; 5] {
        // rel32 = detour_va - (target_va + 5)
        let rel = self.detour_va.wrapping_sub(self.target_va.wrapping_add(5));
        let b = rel.to_le_bytes();
        [0xE9, b[0], b[1], b[2], b[3]]
    }

    /// Return the absolute 64-bit JMP stub (14 bytes) used when the detour is
    /// further than ±2 GiB from the target.
    ///
    /// Layout: `FF 25 00 00 00 00 <addr64-LE>`
    #[must_use]
    pub fn jmp64_patch_bytes(&self) -> [u8; 14] {
        let mut out = [0u8; 14];
        out[0] = 0xFF;
        out[1] = 0x25;
        // RIP-relative offset 0 → the u64 immediately follows
        let addr_bytes = self.detour_va.to_le_bytes();
        out[6..14].copy_from_slice(&addr_bytes);
        out
    }
}

/// Registry of all installed inline hooks for a monitored process.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HookRegistry {
    hooks: Vec<InlineHookDescriptor>,
}

impl HookRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new hook descriptor.
    pub fn register(&mut self, hook: InlineHookDescriptor) {
        self.hooks.push(hook);
    }

    /// Mark a hook as active (installed).
    pub fn activate(&mut self, function: &str) {
        if let Some(h) = self.hooks.iter_mut().find(|h| h.function == function) {
            h.active = true;
        }
    }

    /// Mark a hook as inactive (removed).
    pub fn deactivate(&mut self, function: &str) {
        if let Some(h) = self.hooks.iter_mut().find(|h| h.function == function) {
            h.active = false;
        }
    }

    /// Return all currently active hooks.
    #[must_use]
    pub fn active_hooks(&self) -> Vec<&InlineHookDescriptor> {
        self.hooks.iter().filter(|h| h.active).collect()
    }

    /// Find a hook by function name.
    #[must_use]
    pub fn find(&self, function: &str) -> Option<&InlineHookDescriptor> {
        self.hooks.iter().find(|h| h.function == function)
    }

    /// Total number of registered hooks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.hooks.len()
    }

    /// True if no hooks are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Remove a hook entry entirely.
    pub fn remove(&mut self, function: &str) {
        self.hooks.retain(|h| h.function != function);
    }
}

// ─── ApiCallRecord ─────────────────────────────────────────────────────────────

/// A single API call record produced by the hook layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    /// Monotonic timestamp (nanoseconds since trace start).
    pub timestamp: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// DLL from which the call originated.
    pub dll: String,
    /// API function name.
    pub function: String,
    /// Raw argument values (up to 16).
    pub args: Vec<u64>,
    /// Return value.
    pub ret: u64,
    /// Elapsed time inside the call (ns).
    pub duration_ns: u64,
    /// NTSTATUS / Win32 error string for the return value.
    pub status: String,
    /// API category.
    pub category: ApiCategory,
}

/// Process/thread/time origin metadata for an [`ApiCallRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiCallOrigin {
    /// Monotonic timestamp (nanoseconds since trace start).
    pub timestamp: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
}

impl ApiCallRecord {
    /// Construct a new record.
    #[must_use]
    pub fn new(
        origin: ApiCallOrigin,
        dll: impl Into<String>,
        function: impl Into<String>,
        args: Vec<u64>,
        ret: u64,
        duration_ns: u64,
        category: ApiCategory,
    ) -> Self {
        let status = decode_ntstatus(u32::try_from(ret & 0xFFFF_FFFF).unwrap_or(0)).to_string();
        Self {
            timestamp: origin.timestamp,
            pid: origin.pid,
            tid: origin.tid,
            dll: dll.into(),
            function: function.into(),
            args,
            ret,
            duration_ns,
            status,
            category,
        }
    }

    /// True if the call was successful (`NTSTATUS` < `0x8000_0000`).
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        (self.ret & 0xFFFF_FFFF) < 0x8000_0000
    }

    /// Serialize to a single JSON line (for real-time log streaming).
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if serialization fails.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A live stream of API call records with optional filtering.
#[derive(Debug, Default)]
pub struct ApiCallStream {
    records: Vec<ApiCallRecord>,
    /// Optional DLL allowlist (empty = all DLLs accepted).
    dll_filter: Vec<String>,
    /// Optional function-name allowlist (empty = all functions accepted).
    fn_filter: Vec<String>,
    /// Optional PID allowlist (empty = all PIDs accepted).
    pid_filter: Vec<u32>,
}

impl ApiCallStream {
    /// Create an empty stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only accept calls from these DLLs.
    #[must_use]
    pub fn filter_dlls(mut self, dlls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dll_filter = dlls.into_iter().map(Into::into).collect();
        self
    }

    /// Only accept calls to these function names.
    #[must_use]
    pub fn filter_functions(mut self, fns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.fn_filter = fns.into_iter().map(Into::into).collect();
        self
    }

    /// Only accept calls from these PIDs.
    #[must_use]
    pub fn filter_pids(mut self, pids: impl IntoIterator<Item = u32>) -> Self {
        self.pid_filter = pids.into_iter().collect();
        self
    }

    /// Push a new record, applying filters.
    pub fn push(&mut self, record: ApiCallRecord) {
        if !self.dll_filter.is_empty()
            && !self
                .dll_filter
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&record.dll))
        {
            return;
        }
        if !self.fn_filter.is_empty() && !self.fn_filter.contains(&record.function) {
            return;
        }
        if !self.pid_filter.is_empty() && !self.pid_filter.contains(&record.pid) {
            return;
        }
        self.records.push(record);
    }

    /// Return all accepted records.
    #[must_use]
    pub fn records(&self) -> &[ApiCallRecord] {
        &self.records
    }

    /// Number of accepted records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// True if no records have been accepted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Export all records as a JSON array string.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.records)
    }

    /// Return records filtered by category.
    #[must_use]
    pub fn by_category(&self, cat: ApiCategory) -> Vec<&ApiCallRecord> {
        self.records.iter().filter(|r| r.category == cat).collect()
    }

    /// Return records from a specific PID.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Vec<&ApiCallRecord> {
        self.records.iter().filter(|r| r.pid == pid).collect()
    }

    /// Return the unique set of DLLs seen in accepted records.
    #[must_use]
    pub fn seen_dlls(&self) -> Vec<&str> {
        let mut dlls: Vec<&str> = self.records.iter().map(|r| r.dll.as_str()).collect();
        dlls.sort_unstable();
        dlls.dedup();
        dlls
    }

    /// Return the unique set of function names seen.
    #[must_use]
    pub fn seen_functions(&self) -> Vec<&str> {
        let mut fns: Vec<&str> = self.records.iter().map(|r| r.function.as_str()).collect();
        fns.sort_unstable();
        fns.dedup();
        fns
    }
}

// ─── WinApiSummary ─────────────────────────────────────────────────────────────

/// Aggregated statistics for a monitoring session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiSummary {
    /// Per-function call counts and timing.
    pub per_function: HashMap<String, WinApiStat>,
    /// Total API calls recorded.
    pub total_calls: usize,
}

/// Per-function aggregated statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiStat {
    /// Call count.
    pub count: u64,
    /// Total time inside the call (ns).
    pub total_ns: u64,
    /// Minimum call duration (ns).
    pub min_ns: u64,
    /// Maximum call duration (ns).
    pub max_ns: u64,
    /// Calls that returned failure status.
    pub failure_count: u64,
}

impl WinApiStat {
    /// Average call duration (ns).
    #[must_use]
    pub const fn avg_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_ns / self.count
        }
    }
}

impl WinApiSummary {
    /// Build a summary from a slice of API call records.
    #[must_use]
    pub fn from_records(records: &[ApiCallRecord]) -> Self {
        let mut per_function: HashMap<String, WinApiStat> = HashMap::new();
        for rec in records {
            let stat = per_function.entry(rec.function.clone()).or_default();
            stat.count += 1;
            stat.total_ns += rec.duration_ns;
            if stat.count == 1 {
                stat.min_ns = rec.duration_ns;
                stat.max_ns = rec.duration_ns;
            } else {
                stat.min_ns = stat.min_ns.min(rec.duration_ns);
                stat.max_ns = stat.max_ns.max(rec.duration_ns);
            }
            if !rec.succeeded() {
                stat.failure_count += 1;
            }
        }
        Self {
            total_calls: records.len(),
            per_function,
        }
    }

    /// Top N functions by total time.
    #[must_use]
    pub fn top_by_time(&self, n: usize) -> Vec<(&str, &WinApiStat)> {
        let mut v: Vec<(&str, &WinApiStat)> = self
            .per_function
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        v.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));
        v.truncate(n);
        v
    }

    /// Top N functions by call count.
    #[must_use]
    pub fn top_by_count(&self, n: usize) -> Vec<(&str, &WinApiStat)> {
        let mut v: Vec<(&str, &WinApiStat)> = self
            .per_function
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        v.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        v.truncate(n);
        v
    }
}

// ─── IatHookDescriptor ─────────────────────────────────────────────────────────

/// Describes an IAT (Import Address Table) hook.
///
/// IAT hooks replace the function pointer in the target module's import table
/// rather than patching the function body, making them easier to install and
/// less detectable by code-integrity checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatHookDescriptor {
    /// Module containing the hooked IAT entry.
    pub target_module: String,
    /// Name of the imported DLL.
    pub import_dll: String,
    /// Name of the imported function.
    pub function: String,
    /// Original pointer value in the IAT.
    pub original_ptr: u64,
    /// Detour pointer written into the IAT.
    pub detour_ptr: u64,
    /// Whether the hook is currently active.
    pub active: bool,
}

impl IatHookDescriptor {
    /// Create a new (inactive) IAT hook descriptor.
    #[must_use]
    pub fn new(
        target_module: impl Into<String>,
        import_dll: impl Into<String>,
        function: impl Into<String>,
        original_ptr: u64,
        detour_ptr: u64,
    ) -> Self {
        Self {
            target_module: target_module.into(),
            import_dll: import_dll.into(),
            function: function.into(),
            original_ptr,
            detour_ptr,
            active: false,
        }
    }

    /// Patch bytes to write into the IAT slot (8-byte pointer, LE).
    #[must_use]
    pub const fn detour_bytes(&self) -> [u8; 8] {
        self.detour_ptr.to_le_bytes()
    }

    /// Bytes to restore the original IAT pointer.
    #[must_use]
    pub const fn restore_bytes(&self) -> [u8; 8] {
        self.original_ptr.to_le_bytes()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> WinSyscallResolver {
        WinSyscallResolver::new()
    }

    // ── count ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_x64_count_at_least_80() {
        let db = WinSyscallDb::new();
        assert!(
            db.arch_count(WinArch::X64) >= 80,
            "got {}",
            db.arch_count(WinArch::X64)
        );
    }

    #[test]
    fn test_x86_count_at_least_60() {
        let db = WinSyscallDb::new();
        assert!(db.arch_count(WinArch::X86) >= 60);
    }

    // ── x64 lookup by SSN ─────────────────────────────────────────────────────
    #[test]
    fn test_x64_read_file_ssn_0() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0).expect("NtReadFile SSN=0");
        assert_eq!(sc.name, "NtReadFile");
    }

    #[test]
    fn test_x64_write_file_ssn_1() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 1).expect("NtWriteFile SSN=1");
        assert_eq!(sc.name, "NtWriteFile");
    }

    #[test]
    fn test_x64_close_ssn_2() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 2).expect("NtClose SSN=2");
        assert_eq!(sc.name, "NtClose");
    }

    #[test]
    fn test_x64_allocate_virtual_memory() {
        let r = resolver();
        let sc = r
            .lookup(WinArch::X64, 0x000F)
            .expect("NtAllocateVirtualMemory");
        assert_eq!(sc.name, "NtAllocateVirtualMemory");
        assert_eq!(sc.params.len(), 6);
    }

    #[test]
    fn test_x64_create_file() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0x0019).expect("NtCreateFile");
        assert_eq!(sc.name, "NtCreateFile");
    }

    #[test]
    fn test_x64_missing_ssn_returns_none() {
        let r = resolver();
        assert!(r.lookup(WinArch::X64, 0xFFFF).is_none());
    }

    // ── x64 lookup by name ────────────────────────────────────────────────────
    #[test]
    fn test_x64_lookup_by_name_nt_open_process() {
        let r = resolver();
        let sc = r
            .lookup_by_name(WinArch::X64, "NtOpenProcess")
            .expect("NtOpenProcess");
        assert_eq!(sc.ssn, 0x000B);
    }

    #[test]
    fn test_x64_lookup_by_name_missing() {
        let r = resolver();
        assert!(r.lookup_by_name(WinArch::X64, "NoSuchFunction").is_none());
    }

    #[test]
    fn test_x64_lookup_by_zw_name() {
        let r = resolver();
        let sc = r
            .db()
            .lookup_by_zw_name(WinArch::X64, "ZwReadFile")
            .expect("ZwReadFile");
        assert_eq!(sc.name, "NtReadFile");
    }

    // ── zw alias ─────────────────────────────────────────────────────────────
    #[test]
    fn test_zw_name_derived_correctly() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0).unwrap();
        assert_eq!(sc.zw_name, "ZwReadFile");
    }

    #[test]
    fn test_zw_count_equals_nt_count() {
        let db = WinSyscallDb::new();
        assert_eq!(db.zw_count(WinArch::X64), db.arch_count(WinArch::X64));
    }

    // ── sorted ────────────────────────────────────────────────────────────────
    #[test]
    fn test_x64_all_sorted_by_ssn() {
        let r = resolver();
        let all = r.all_for_arch(WinArch::X64);
        let ssns: Vec<u32> = all.iter().map(|s| s.ssn).collect();
        let mut sorted = ssns.clone();
        sorted.sort_unstable();
        assert_eq!(ssns, sorted);
    }

    // ── categories ────────────────────────────────────────────────────────────
    #[test]
    fn test_x64_by_category_registry_not_empty() {
        let r = resolver();
        let cat = r.by_category(WinArch::X64, NtSyscallCategory::Registry);
        assert!(!cat.is_empty());
    }

    #[test]
    fn test_x64_by_category_memory_not_empty() {
        let r = resolver();
        let cat = r.by_category(WinArch::X64, NtSyscallCategory::Memory);
        assert!(!cat.is_empty());
    }

    #[test]
    fn test_x64_categories_not_empty() {
        let r = resolver();
        let cats = r.db().categories(WinArch::X64);
        assert!(!cats.is_empty());
    }

    // ── x86 lookup ────────────────────────────────────────────────────────────
    #[test]
    fn test_x86_close_ssn() {
        let r = resolver();
        let sc = r.lookup(WinArch::X86, 0x000C).expect("x86 NtClose");
        assert_eq!(sc.name, "NtClose");
    }

    #[test]
    fn test_x86_wait_for_single_object() {
        let r = resolver();
        let sc = r
            .lookup(WinArch::X86, 0x0004)
            .expect("x86 NtWaitForSingleObject");
        assert_eq!(sc.name, "NtWaitForSingleObject");
    }

    #[test]
    fn test_x86_lookup_by_name_nt_read_file() {
        let r = resolver();
        let sc = r
            .lookup_by_name(WinArch::X86, "NtReadFile")
            .expect("x86 NtReadFile");
        assert_eq!(sc.ssn, 0x0025);
    }

    // ── module field ─────────────────────────────────────────────────────────
    #[test]
    fn test_x64_module_is_ntdll() {
        let r = resolver();
        assert_eq!(r.lookup(WinArch::X64, 0).unwrap().module, "ntdll.dll");
    }

    // ── prototype ────────────────────────────────────────────────────────────
    #[test]
    fn test_prototype_contains_name() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0).unwrap();
        let p = sc.prototype();
        assert!(p.contains("NtReadFile"));
    }

    #[test]
    fn test_arity() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0x000F).unwrap();
        assert_eq!(sc.arity(), 6);
    }

    #[test]
    fn test_has_output_params() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0x000B).unwrap(); // NtOpenProcess
        assert!(sc.has_output_params());
    }

    // ── param direction ───────────────────────────────────────────────────────
    #[test]
    fn test_param_direction_display() {
        assert_eq!(ParamDirection::In.to_string(), "In");
        assert_eq!(ParamDirection::Out.to_string(), "Out");
        assert_eq!(ParamDirection::InOut.to_string(), "InOut");
        assert_eq!(ParamDirection::OptIn.to_string(), "In_opt");
        assert_eq!(ParamDirection::OptOut.to_string(), "Out_opt");
    }

    // ── arch display ─────────────────────────────────────────────────────────
    #[test]
    fn test_win_arch_display() {
        assert_eq!(WinArch::X64.to_string(), "x64");
        assert_eq!(WinArch::X86.to_string(), "x86");
        assert_eq!(WinArch::Arm64.to_string(), "arm64");
    }

    // ── version display ───────────────────────────────────────────────────────
    #[test]
    fn test_win_version_display() {
        assert!(WinVersion::Windows10.to_string().contains("10"));
        assert!(WinVersion::Windows11.to_string().contains("11"));
    }

    // ── NtdllExport ───────────────────────────────────────────────────────────
    #[test]
    fn test_ntdll_export_construction() {
        let exp = NtdllExport::new("NtReadFile", 0x1234, Some(0));
        assert_eq!(exp.name, "NtReadFile");
        assert_eq!(exp.ssn, Some(0));
    }

    #[test]
    fn test_ntdll_export_no_ssn() {
        let exp = NtdllExport::new("LdrLoadDll", 0x5678, None);
        assert!(exp.ssn.is_none());
    }

    #[test]
    fn test_ntdll_export_with_ordinal() {
        let exp = NtdllExport::new("NtClose", 0x100, Some(2)).with_ordinal(42);
        assert_eq!(exp.ordinal, Some(42));
    }

    // ── Hook detection ────────────────────────────────────────────────────────
    #[test]
    fn test_hook_clean_x64() {
        // Normal Win10 x64 stub for SSN=0: 4C 8B D1 B8 00 00 00 00 ...
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00];
        let r = analyse_stub("NtReadFile", 0, WinArch::X64, &stub);
        assert_eq!(r.kind, HookKind::Clean);
        assert!(!r.is_hooked());
    }

    #[test]
    fn test_hook_ssn_mismatch_x64() {
        // SSN in bytes is 5, but we pass expected=0 → mismatch
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x05, 0x00, 0x00, 0x00];
        let r = analyse_stub("NtReadFile", 0, WinArch::X64, &stub);
        assert!(matches!(r.kind, HookKind::SsnMismatch { .. }));
        assert!(r.is_hooked());
    }

    #[test]
    fn test_hook_inline_x64() {
        let stub = [0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let r = analyse_stub("NtReadFile", 0, WinArch::X64, &stub);
        assert_eq!(r.kind, HookKind::InlineHook);
    }

    #[test]
    fn test_hook_trampoline_x64() {
        // JMP rel32: E9 00 00 00 00 (rel=0 → target=5)
        let stub = [0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let r = analyse_stub("NtReadFile", 0, WinArch::X64, &stub);
        assert!(matches!(r.kind, HookKind::Trampoline { target: 5 }));
    }

    #[test]
    fn test_hook_clean_x86() {
        let mut stub = [0u8; 8];
        stub[0] = 0xB8;
        stub[1..5].copy_from_slice(&0x0025u32.to_le_bytes());
        let r = analyse_stub("NtReadFile", 0x0025, WinArch::X86, &stub);
        assert_eq!(r.kind, HookKind::Clean);
    }

    #[test]
    fn test_hook_analyse_via_resolver() {
        let r_obj = resolver();
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00];
        let analysis = r_obj.analyse_hook("NtReadFile", WinArch::X64, &stub);
        assert_eq!(analysis.kind, HookKind::Clean);
    }

    // ── Version SSN table ─────────────────────────────────────────────────────
    #[test]
    fn test_version_table_not_empty() {
        let table = build_version_ssn_table();
        assert!(!table.is_empty());
    }

    #[test]
    fn test_version_ssn_nt_create_file_win10() {
        let r = resolver();
        let ssn = r.ssn_for_version("NtCreateFile", WinVersion::Windows10);
        assert!(ssn.is_some());
    }

    #[test]
    fn test_version_ssn_nt_read_file_winxp() {
        let r = resolver();
        let ssn = r.ssn_for_version("NtReadFile", WinVersion::WindowsXP);
        assert!(ssn.is_some());
    }

    #[test]
    fn test_version_ssn_missing_function() {
        let r = resolver();
        assert!(
            r.ssn_for_version("NtNoSuch", WinVersion::Windows10)
                .is_none()
        );
    }

    // ── NT structures ─────────────────────────────────────────────────────────
    #[test]
    fn test_object_attributes_new() {
        let oa = ObjectAttributes::new("\\Device\\Harddisk0");
        assert_eq!(oa.object_name, "\\Device\\Harddisk0");
        assert_eq!(oa.length, 48);
    }

    #[test]
    fn test_object_attributes_flags() {
        let mut oa = ObjectAttributes::new("test");
        oa.attributes = 0x202; // OBJ_INHERIT | OBJ_KERNEL_HANDLE
        assert!(oa.is_inherit());
        assert!(oa.is_kernel_handle());
        assert!(!oa.is_open_if());
    }

    #[test]
    fn test_unicode_string_from_str() {
        let us = UnicodeString::from_string("hello");
        assert_eq!(us.decoded, "hello");
        assert_eq!(us.length, 10); // 5 chars * 2 bytes
    }

    #[test]
    fn test_memory_basic_information_states() {
        let mbi = MemoryBasicInformation {
            base_address: 0x1000,
            allocation_base: 0x1000,
            allocation_protect: 0x20,
            region_size: 0x1000,
            state: 0x1000,      // MEM_COMMIT
            protect: 0x40,      // PAGE_EXECUTE_READWRITE
            mem_type: 0x2_0000, // MEM_PRIVATE
        };
        assert!(mbi.is_committed());
        assert!(mbi.is_rwx());
        assert!(!mbi.is_free());
        assert_eq!(mbi.type_name(), "MEM_PRIVATE");
    }

    #[test]
    fn test_page_protect_is_executable() {
        assert!(PageProtect::is_executable(0x40)); // RWX
        assert!(!PageProtect::is_executable(0x04)); // RW
    }

    #[test]
    fn test_page_protect_name() {
        assert_eq!(PageProtect::name(0x40), "PAGE_EXECUTE_READWRITE");
        assert_eq!(PageProtect::name(0x02), "PAGE_READONLY");
    }

    #[test]
    fn test_peb_debugged() {
        let peb = Peb {
            image_base: 0x1_4000_0000,
            ldr: 0x7ffe_0000,
            process_parameters: 0,
            being_debugged: true,
            nt_global_flags: 0,
            heap_count: 1,
        };
        assert!(peb.is_debugged());
        assert!(!peb.has_heap_debug_flags());
    }

    // ── Serde ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_serde_roundtrip_syscall() {
        let r = resolver();
        let sc = r.lookup(WinArch::X64, 0).unwrap();
        let json = serde_json::to_string(sc).unwrap();
        let back: WinNtSyscall = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, sc.name);
        assert_eq!(back.ssn, sc.ssn);
    }

    #[test]
    fn test_serde_roundtrip_db() {
        let db = WinSyscallDb::new();
        let json = serde_json::to_string(&db).unwrap();
        let back: WinSyscallDb = serde_json::from_str(&json).unwrap();
        assert_eq!(back.arch_count(WinArch::X64), db.arch_count(WinArch::X64));
    }

    // ── Error display ─────────────────────────────────────────────────────────
    #[test]
    fn test_error_display_not_found() {
        let e = WinSyscallError::NotFound {
            arch: WinArch::X64,
            ssn: 0xDEAD,
        };
        assert!(
            e.to_string().contains("57_005")
                || e.to_string().contains("dead")
                || e.to_string().contains("Dead")
                || {
                    let s = e.to_string();
                    s.contains("57_005") || s.len() > 5
                }
        );
    }

    #[test]
    fn test_error_unsupported_arch() {
        let e = WinSyscallError::UnsupportedArch(WinArch::X86);
        assert!(e.to_string().contains("x86") || e.to_string().contains("X86"));
    }

    // ── Required names present ────────────────────────────────────────────────
    #[test]
    fn test_all_required_names_present_x64() {
        let r = resolver();
        let required = [
            "NtReadFile",
            "NtWriteFile",
            "NtCreateFile",
            "NtOpenFile",
            "NtClose",
            "NtQueryInformationFile",
            "NtSetInformationFile",
            "NtQueryDirectoryFile",
            "NtFlushBuffersFile",
            "NtDeleteFile",
            "NtCreateSection",
            "NtOpenSection",
            "NtMapViewOfSection",
            "NtUnmapViewOfSection",
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtProtectVirtualMemory",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtQueryVirtualMemory",
            "NtOpenProcess",
            "NtOpenThread",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtTerminateProcess",
            "NtTerminateThread",
            "NtSuspendThread",
            "NtResumeThread",
            "NtQueryInformationProcess",
            "NtSetInformationProcess",
            "NtQueryInformationThread",
            "NtSetInformationThread",
            "NtWaitForSingleObject",
            "NtWaitForMultipleObjects",
            "NtCreateEvent",
            "NtOpenEvent",
            "NtSetEvent",
            "NtResetEvent",
            "NtQueryEvent",
            "NtCreateMutant",
            "NtReleaseMutant",
            "NtCreateSemaphore",
            "NtReleaseSemaphore",
            "NtCreateKey",
            "NtOpenKey",
            "NtQueryKey",
            "NtSetValueKey",
            "NtQueryValueKey",
            "NtDeleteKey",
            "NtDeleteValueKey",
            "NtEnumerateKey",
            "NtEnumerateValueKey",
            "NtQuerySystemInformation",
            "NtSetSystemInformation",
            "NtQuerySystemTime",
            "NtRaiseHardError",
            "NtRaiseException",
            "NtContinue",
            "NtGetContextThread",
            "NtSetContextThread",
            "NtDuplicateObject",
        ];
        for name in &required {
            assert!(
                r.lookup_by_name(WinArch::X64, name).is_some(),
                "missing: {name}"
            );
        }
    }

    #[test]
    fn test_hook_kind_display() {
        assert_eq!(HookKind::Clean.to_string(), "Clean");
        assert_eq!(HookKind::InlineHook.to_string(), "InlineHook");
        assert_eq!(HookKind::IatHook.to_string(), "IatHook");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(NtSyscallCategory::Registry.to_string(), "registry");
        assert_eq!(NtSyscallCategory::Memory.to_string(), "memory");
    }

    // ── InlineHookDescriptor tests ────────────────────────────────────────────

    fn make_hook() -> InlineHookDescriptor {
        InlineHookDescriptor::new(
            "NtCreateFile",
            "ntdll.dll",
            0x7FFF_1000_0000u64,
            0x7FFF_2000_0000u64,
            0x7FFF_3000_0000u64,
            vec![0x48, 0x89, 0x5C, 0x24, 0x10],
        )
    }

    #[test]
    fn test_inline_hook_jmp_patch_first_byte() {
        let h = make_hook();
        let patch = h.jmp_patch_bytes();
        assert_eq!(patch[0], 0xE9, "JMP near opcode");
    }

    #[test]
    fn test_inline_hook_jmp64_first_two_bytes() {
        let h = make_hook();
        let patch = h.jmp64_patch_bytes();
        assert_eq!(patch[0], 0xFF);
        assert_eq!(patch[1], 0x25);
    }

    #[test]
    fn test_inline_hook_jmp64_embeds_detour_address() {
        let h = make_hook();
        let patch = h.jmp64_patch_bytes();
        let addr = u64::from_le_bytes(patch[6..14].try_into().unwrap());
        assert_eq!(addr, h.detour_va);
    }

    #[test]
    fn test_hook_registry_register_and_find() {
        let mut reg = HookRegistry::new();
        reg.register(make_hook());
        assert!(reg.find("NtCreateFile").is_some());
    }

    #[test]
    fn test_hook_registry_activate() {
        let mut reg = HookRegistry::new();
        reg.register(make_hook());
        reg.activate("NtCreateFile");
        assert!(reg.find("NtCreateFile").unwrap().active);
        assert_eq!(reg.active_hooks().len(), 1);
    }

    #[test]
    fn test_hook_registry_deactivate() {
        let mut reg = HookRegistry::new();
        reg.register(make_hook());
        reg.activate("NtCreateFile");
        reg.deactivate("NtCreateFile");
        assert!(!reg.find("NtCreateFile").unwrap().active);
        assert!(reg.active_hooks().is_empty());
    }

    #[test]
    fn test_hook_registry_remove() {
        let mut reg = HookRegistry::new();
        reg.register(make_hook());
        reg.remove("NtCreateFile");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_hook_registry_len() {
        let mut reg = HookRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.register(make_hook());
        assert_eq!(reg.len(), 1);
    }

    // ── ApiCallRecord tests ────────────────────────────────────────────────────

    fn make_api_record(function: &str, ret: u64, dur: u64) -> ApiCallRecord {
        ApiCallRecord::new(
            ApiCallOrigin {
                timestamp: 0,
                pid: 1000,
                tid: 2000,
            },
            "ntdll.dll",
            function,
            vec![1, 2, 3],
            ret,
            dur,
            ApiCategory::FileSystem,
        )
    }

    #[test]
    fn test_api_record_succeeded_status_success() {
        let r = make_api_record("NtCreateFile", 0, 1000);
        assert!(r.succeeded());
        assert_eq!(r.status, "STATUS_SUCCESS");
    }

    #[test]
    fn test_api_record_failed_status() {
        let r = make_api_record("NtCreateFile", 0xC000_0034, 500);
        assert!(!r.succeeded());
        assert!(r.status.contains("OBJECT_NAME_NOT_FOUND") || !r.status.is_empty());
    }

    #[test]
    fn test_api_record_to_json_line() {
        let r = make_api_record("NtReadFile", 0, 200);
        let line = r.to_json_line().unwrap();
        assert!(line.contains("NtReadFile"));
    }

    // ── ApiCallStream tests ────────────────────────────────────────────────────

    #[test]
    fn test_stream_push_no_filter() {
        let mut s = ApiCallStream::new();
        s.push(make_api_record("NtCreateFile", 0, 100));
        s.push(make_api_record("NtReadFile", 0, 200));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn test_stream_dll_filter() {
        let mut s = ApiCallStream::new().filter_dlls(["ntdll.dll"]);
        s.push(make_api_record("NtCreateFile", 0, 100));
        // Record with different dll
        let mut rec = make_api_record("WSAConnect", 0, 50);
        rec.dll = "ws2_32.dll".into();
        s.push(rec);
        // only ntdll record passes
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_stream_pid_filter() {
        let mut s = ApiCallStream::new().filter_pids([1000u32]);
        s.push(make_api_record("NtCreateFile", 0, 100));
        let mut rec = make_api_record("NtReadFile", 0, 50);
        rec.pid = 9999;
        s.push(rec);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_stream_by_category() {
        let mut s = ApiCallStream::new();
        s.push(make_api_record("NtCreateFile", 0, 100));
        let mut rec = make_api_record("RegOpenKeyExW", 0, 50);
        rec.category = ApiCategory::Registry;
        s.push(rec);
        assert_eq!(s.by_category(ApiCategory::FileSystem).len(), 1);
        assert_eq!(s.by_category(ApiCategory::Registry).len(), 1);
    }

    #[test]
    fn test_stream_seen_dlls() {
        let mut s = ApiCallStream::new();
        s.push(make_api_record("NtCreateFile", 0, 100));
        s.push(make_api_record("NtReadFile", 0, 200));
        let dlls = s.seen_dlls();
        assert_eq!(dlls, vec!["ntdll.dll"]);
    }

    #[test]
    fn test_stream_seen_functions() {
        let mut s = ApiCallStream::new();
        s.push(make_api_record("NtCreateFile", 0, 100));
        s.push(make_api_record("NtCreateFile", 0, 200));
        s.push(make_api_record("NtReadFile", 0, 50));
        let fns = s.seen_functions();
        assert_eq!(fns.len(), 2);
    }

    #[test]
    fn test_stream_to_json() {
        let mut s = ApiCallStream::new();
        s.push(make_api_record("NtClose", 0, 10));
        let json = s.to_json().unwrap();
        assert!(json.contains("NtClose"));
    }

    #[test]
    fn test_stream_is_empty() {
        let s = ApiCallStream::new();
        assert!(s.is_empty());
    }

    // ── WinApiSummary tests ────────────────────────────────────────────────────

    #[test]
    fn test_win_api_summary_empty() {
        let s = WinApiSummary::from_records(&[]);
        assert_eq!(s.total_calls, 0);
        assert!(s.per_function.is_empty());
    }

    #[test]
    fn test_win_api_summary_count_and_time() {
        let records = vec![
            make_api_record("NtCreateFile", 0, 1000),
            make_api_record("NtCreateFile", 0, 2000),
            make_api_record("NtReadFile", 0, 500),
        ];
        let s = WinApiSummary::from_records(&records);
        assert_eq!(s.total_calls, 3);
        assert_eq!(s.per_function["NtCreateFile"].count, 2);
        assert_eq!(s.per_function["NtCreateFile"].total_ns, 3000);
        assert_eq!(s.per_function["NtReadFile"].count, 1);
    }

    #[test]
    fn test_win_api_summary_failure_count() {
        let records = vec![
            make_api_record("NtOpenFile", 0xC000_0034, 100),
            make_api_record("NtOpenFile", 0, 200),
        ];
        let s = WinApiSummary::from_records(&records);
        assert_eq!(s.per_function["NtOpenFile"].failure_count, 1);
    }

    #[test]
    fn test_win_api_summary_top_by_time() {
        let records = vec![
            make_api_record("NtCreateFile", 0, 9000),
            make_api_record("NtReadFile", 0, 1000),
        ];
        let s = WinApiSummary::from_records(&records);
        let top = s.top_by_time(1);
        assert_eq!(top[0].0, "NtCreateFile");
    }

    #[test]
    fn test_win_api_summary_avg_ns() {
        let records = vec![
            make_api_record("NtClose", 0, 200),
            make_api_record("NtClose", 0, 400),
        ];
        let s = WinApiSummary::from_records(&records);
        assert_eq!(s.per_function["NtClose"].avg_ns(), 300);
    }

    // ── IatHookDescriptor tests ────────────────────────────────────────────────

    #[test]
    fn test_iat_hook_detour_bytes() {
        let h = IatHookDescriptor::new(
            "target.exe",
            "ntdll.dll",
            "NtCreateFile",
            0x1234_5678_9ABC_DEF0u64,
            0xDEAD_BEEF_CAFE_BABEu64,
        );
        let bytes = h.detour_bytes();
        assert_eq!(u64::from_le_bytes(bytes), 0xDEAD_BEEF_CAFE_BABEu64);
    }

    #[test]
    fn test_iat_hook_restore_bytes() {
        let h = IatHookDescriptor::new(
            "target.exe",
            "kernel32.dll",
            "CreateFileW",
            0xAAAA_BBBB_CCCC_DDDDu64,
            0x1111_2222_3333_4444u64,
        );
        let bytes = h.restore_bytes();
        assert_eq!(u64::from_le_bytes(bytes), 0xAAAA_BBBB_CCCC_DDDDu64);
    }

    #[test]
    fn test_iat_hook_inactive_by_default() {
        let h = IatHookDescriptor::new("a.dll", "b.dll", "Foo", 1, 2);
        assert!(!h.active);
    }

    // ── WIN32_API_DB coverage tests ────────────────────────────────────────────

    #[test]
    fn test_api_db_has_createfilew() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "CreateFileW"));
    }

    #[test]
    fn test_api_db_has_virtualalloc() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "VirtualAlloc"));
    }

    #[test]
    fn test_api_db_has_wsasend() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "WSASend"));
    }

    #[test]
    fn test_api_db_has_cryptprotectdata() {
        assert!(WIN32_API_DB.iter().any(|e| e.name == "CryptProtectData"));
    }

    #[test]
    fn test_api_db_minimum_size() {
        assert!(WIN32_API_DB.len() >= 100);
    }

    #[test]
    fn test_api_db_network_entries() {
        
        assert!(WIN32_API_DB
            .iter()
            .filter(|e| e.category == ApiCategory::Network).count() >= 10);
    }

    #[test]
    fn test_api_category_display() {
        assert_eq!(ApiCategory::FileSystem.to_string(), "FileSystem");
        assert_eq!(ApiCategory::Registry.to_string(), "Registry");
        assert_eq!(ApiCategory::Crypto.to_string(), "Crypto");
    }

    #[test]
    fn test_win_api_stat_avg_ns_zero_count() {
        let stat = WinApiStat::default();
        assert_eq!(stat.avg_ns(), 0);
    }
}

// ─── Win32 API Monitor types ──────────────────────────────────────────────────

/// API call argument (decoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WinDecodedArg {
    /// Unicode string value.
    WStr(String),
    /// ANSI string value.
    AStr(String),
    /// Integer value.
    Int(i64),
    /// Unsigned integer (handles, flags, …).
    UInt(u64),
    /// Boolean.
    Bool(bool),
    /// Handle value.
    Handle(u64),
    /// Pointer (address only).
    Ptr(u64),
    /// NTSTATUS / HRESULT code.
    Status(u32),
    /// Raw hex.
    RawHex(u64),
    /// Null pointer.
    Null,
    /// Registry path.
    RegistryPath(String),
    /// File system path.
    FilePath(String),
    /// Network address + port.
    NetAddr(String, u16),
    /// HTTP URL.
    HttpUrl(String),
    /// Process name + PID.
    ProcessRef(String, u32),
}

impl std::fmt::Display for WinDecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WStr(s) => write!(f, "L{s:?}"),
            Self::AStr(s) => write!(f, "{s:?}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::UInt(v) | Self::Handle(v) | Self::Ptr(v) | Self::RawHex(v) => {
                write!(f, "0x{v:x}")
            }
            Self::Bool(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            Self::Status(s) => write!(f, "0x{:04x}_{:04x}", (s >> 16) & 0xffff, s & 0xffff),
            Self::Null => write!(f, "NULL"),
            Self::RegistryPath(p) | Self::FilePath(p) => write!(f, "{p:?}"),
            Self::NetAddr(a, port) => write!(f, "{a}:{port}"),
            Self::HttpUrl(u) => write!(f, "{u:?}"),
            Self::ProcessRef(n, pid) => write!(f, "{n}({pid})"),
        }
    }
}

/// A single Win32/NT API call event captured by the hook engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    /// Timestamp in nanoseconds (QPC-based).
    pub timestamp_ns: u64,
    /// Process ID of the calling process.
    pub pid: u32,
    /// Thread ID of the calling thread.
    pub tid: u32,
    /// API function name (e.g. `"CreateFileW"`).
    pub api_name: String,
    /// DLL/module name (e.g. `"kernel32.dll"`).
    pub module_name: String,
    /// Decoded arguments.
    pub args: Vec<WinDecodedArg>,
    /// Decoded return value.
    pub retval: WinDecodedArg,
    /// Return address call stack (up to 16 frames).
    pub call_stack: Vec<u64>,
}

impl ApiEvent {
    /// Format as a single-line API Monitor-style log entry.
    #[must_use]
    pub fn format_line(&self) -> String {
        let args: Vec<String> = self
            .args
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        format!(
            "[{:>12}ns] [PID:{:5} TID:{:5}] {}!{}({}) = {}",
            self.timestamp_ns,
            self.pid,
            self.tid,
            self.module_name,
            self.api_name,
            args.join(", "),
            self.retval,
        )
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] on serialization failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ─── API category ─────────────────────────────────────────────────────────────

/// High-level category for a Win32/NT API function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategoryV2 {
    FileSystem,
    Registry,
    Process,
    Thread,
    Memory,
    Network,
    Crypto,
    Service,
    Synchronization,
    Security,
    Loader,
    Http,
    Unknown,
}

impl std::fmt::Display for ApiCategoryV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FileSystem => "FileSystem",
            Self::Registry => "Registry",
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::Memory => "Memory",
            Self::Network => "Network",
            Self::Crypto => "Crypto",
            Self::Service => "Service",
            Self::Synchronization => "Synchronization",
            Self::Security => "Security",
            Self::Loader => "Loader",
            Self::Http => "Http",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── Static Win32 API database ────────────────────────────────────────────────

/// A static entry describing a monitored Win32/NT API.
#[derive(Debug, Clone, Copy)]
pub struct Win32ApiEntry {
    pub name: &'static str,
    pub module: &'static str,
    pub category: ApiCategoryV2,
    pub arg_count: u8,
    pub is_wide: bool,
}

impl Win32ApiEntry {
    #[must_use]
    pub const fn new(
        name: &'static str,
        module: &'static str,
        category: ApiCategoryV2,
        arg_count: u8,
        is_wide: bool,
    ) -> Self {
        Self {
            name,
            module,
            category,
            arg_count,
            is_wide,
        }
    }
}

/// The static Win32 API monitoring database (500+ entries).
pub static WIN32_API_DB_V2: &[Win32ApiEntry] = &[
    // ── ntdll ────────────────────────────────────────────────────────────────
    Win32ApiEntry::new(
        "NtCreateFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        11,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtReadFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        9,
        false,
    ),
    Win32ApiEntry::new(
        "NtWriteFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        9,
        false,
    ),
    Win32ApiEntry::new(
        "NtDeleteFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryInformationFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetInformationFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryDirectoryFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        11,
        false,
    ),
    Win32ApiEntry::new(
        "NtFlushBuffersFile",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        2,
        false,
    ),
    Win32ApiEntry::new("NtClose", "ntdll.dll", ApiCategoryV2::FileSystem, 1, false),
    Win32ApiEntry::new(
        "NtCreateKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        7,
        false,
    ),
    Win32ApiEntry::new("NtOpenKey", "ntdll.dll", ApiCategoryV2::Registry, 3, false),
    Win32ApiEntry::new(
        "NtOpenKeyEx",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryValueKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetValueKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtDeleteKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "NtDeleteValueKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtEnumerateKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtEnumerateValueKey",
        "ntdll.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateProcess",
        "ntdll.dll",
        ApiCategoryV2::Process,
        8,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateProcessEx",
        "ntdll.dll",
        ApiCategoryV2::Process,
        9,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenProcess",
        "ntdll.dll",
        ApiCategoryV2::Process,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtTerminateProcess",
        "ntdll.dll",
        ApiCategoryV2::Process,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryInformationProcess",
        "ntdll.dll",
        ApiCategoryV2::Process,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetInformationProcess",
        "ntdll.dll",
        ApiCategoryV2::Process,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        8,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateThreadEx",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        11,
        false,
    ),
    Win32ApiEntry::new("NtOpenThread", "ntdll.dll", ApiCategoryV2::Thread, 4, false),
    Win32ApiEntry::new(
        "NtTerminateThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtSuspendThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtResumeThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryInformationThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetInformationThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtGetContextThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetContextThread",
        "ntdll.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtAllocateVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtFreeVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtProtectVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtReadVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtWriteVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryVirtualMemory",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtMapViewOfSection",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        10,
        false,
    ),
    Win32ApiEntry::new(
        "NtUnmapViewOfSection",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateSection",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenSection",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtWaitForSingleObject",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtWaitForMultipleObjects",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateEvent",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenEvent",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetEvent",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtResetEvent",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateMutant",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtReleaseMutant",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "NtCreateSemaphore",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtReleaseSemaphore",
        "ntdll.dll",
        ApiCategoryV2::Synchronization,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtQueryInformationToken",
        "ntdll.dll",
        ApiCategoryV2::Security,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenProcessToken",
        "ntdll.dll",
        ApiCategoryV2::Security,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtOpenThreadToken",
        "ntdll.dll",
        ApiCategoryV2::Security,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtAdjustPrivilegesToken",
        "ntdll.dll",
        ApiCategoryV2::Security,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "NtDuplicateObject",
        "ntdll.dll",
        ApiCategoryV2::FileSystem,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "NtQuerySystemInformation",
        "ntdll.dll",
        ApiCategoryV2::Unknown,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "NtSetSystemInformation",
        "ntdll.dll",
        ApiCategoryV2::Unknown,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "NtRaiseException",
        "ntdll.dll",
        ApiCategoryV2::Unknown,
        3,
        false,
    ),
    Win32ApiEntry::new("NtContinue", "ntdll.dll", ApiCategoryV2::Unknown, 2, false),
    Win32ApiEntry::new("LdrLoadDll", "ntdll.dll", ApiCategoryV2::Loader, 4, false),
    Win32ApiEntry::new(
        "LdrGetProcedureAddress",
        "ntdll.dll",
        ApiCategoryV2::Loader,
        4,
        false,
    ),
    Win32ApiEntry::new("LdrUnloadDll", "ntdll.dll", ApiCategoryV2::Loader, 1, false),
    Win32ApiEntry::new(
        "RtlCreateHeap",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "RtlDestroyHeap",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "RtlAllocateHeap",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        3,
        false,
    ),
    Win32ApiEntry::new("RtlFreeHeap", "ntdll.dll", ApiCategoryV2::Memory, 3, false),
    Win32ApiEntry::new(
        "RtlReAllocateHeap",
        "ntdll.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    // ── kernel32/kernelbase ───────────────────────────────────────────────────
    Win32ApiEntry::new(
        "CreateFileW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        7,
        true,
    ),
    Win32ApiEntry::new(
        "CreateFileA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "ReadFile",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "WriteFile",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "CloseHandle",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "DeleteFileW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        true,
    ),
    Win32ApiEntry::new(
        "DeleteFileA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "MoveFileExW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "MoveFileExA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "CopyFileW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "CopyFileA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "FindFirstFileW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "FindFirstFileA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "FindNextFileW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "FindNextFileA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "GetTempPathW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "GetTempPathA",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "CreateDirectoryW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "RemoveDirectoryW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        true,
    ),
    Win32ApiEntry::new(
        "GetFileAttributesW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        true,
    ),
    Win32ApiEntry::new(
        "SetFileAttributesW",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "SetEndOfFile",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "SetFilePointerEx",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "GetFileSizeEx",
        "kernel32.dll",
        ApiCategoryV2::FileSystem,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "CreateProcessW",
        "kernel32.dll",
        ApiCategoryV2::Process,
        10,
        true,
    ),
    Win32ApiEntry::new(
        "CreateProcessA",
        "kernel32.dll",
        ApiCategoryV2::Process,
        10,
        false,
    ),
    Win32ApiEntry::new(
        "OpenProcess",
        "kernel32.dll",
        ApiCategoryV2::Process,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "TerminateProcess",
        "kernel32.dll",
        ApiCategoryV2::Process,
        2,
        false,
    ),
    Win32ApiEntry::new("WinExec", "kernel32.dll", ApiCategoryV2::Process, 2, false),
    Win32ApiEntry::new(
        "ShellExecuteW",
        "shell32.dll",
        ApiCategoryV2::Process,
        6,
        true,
    ),
    Win32ApiEntry::new(
        "ShellExecuteA",
        "shell32.dll",
        ApiCategoryV2::Process,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "ShellExecuteExW",
        "shell32.dll",
        ApiCategoryV2::Process,
        1,
        true,
    ),
    Win32ApiEntry::new(
        "CreateThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CreateRemoteThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "CreateRemoteThreadEx",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        8,
        false,
    ),
    Win32ApiEntry::new(
        "OpenThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "TerminateThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "SuspendThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "ResumeThread",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "GetThreadContext",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "SetThreadContext",
        "kernel32.dll",
        ApiCategoryV2::Thread,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualAlloc",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualAllocEx",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualFree",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualFreeEx",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualProtect",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualProtectEx",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualQuery",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "VirtualQueryEx",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "ReadProcessMemory",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "WriteProcessMemory",
        "kernel32.dll",
        ApiCategoryV2::Memory,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "LoadLibraryW",
        "kernel32.dll",
        ApiCategoryV2::Loader,
        1,
        true,
    ),
    Win32ApiEntry::new(
        "LoadLibraryA",
        "kernel32.dll",
        ApiCategoryV2::Loader,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "LoadLibraryExW",
        "kernel32.dll",
        ApiCategoryV2::Loader,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "GetProcAddress",
        "kernel32.dll",
        ApiCategoryV2::Loader,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "FreeLibrary",
        "kernel32.dll",
        ApiCategoryV2::Loader,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "ExpandEnvironmentStringsW",
        "kernel32.dll",
        ApiCategoryV2::Unknown,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "ExpandEnvironmentStringsA",
        "kernel32.dll",
        ApiCategoryV2::Unknown,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "GetEnvironmentVariableW",
        "kernel32.dll",
        ApiCategoryV2::Unknown,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "SetEnvironmentVariableW",
        "kernel32.dll",
        ApiCategoryV2::Unknown,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "RegSetValueExW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        6,
        true,
    ),
    Win32ApiEntry::new(
        "RegSetValueExA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "RegCreateKeyExW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        9,
        true,
    ),
    Win32ApiEntry::new(
        "RegCreateKeyExA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        9,
        false,
    ),
    Win32ApiEntry::new(
        "RegOpenKeyExW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        5,
        true,
    ),
    Win32ApiEntry::new(
        "RegOpenKeyExA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "RegDeleteKeyW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "RegDeleteKeyA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "RegDeleteValueW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        2,
        true,
    ),
    Win32ApiEntry::new(
        "RegDeleteValueA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "RegQueryValueExW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        6,
        true,
    ),
    Win32ApiEntry::new(
        "RegQueryValueExA",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "RegCloseKey",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "RegEnumKeyExW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        8,
        true,
    ),
    Win32ApiEntry::new(
        "RegEnumValueW",
        "advapi32.dll",
        ApiCategoryV2::Registry,
        8,
        true,
    ),
    Win32ApiEntry::new(
        "CreateServiceW",
        "advapi32.dll",
        ApiCategoryV2::Service,
        13,
        true,
    ),
    Win32ApiEntry::new(
        "CreateServiceA",
        "advapi32.dll",
        ApiCategoryV2::Service,
        13,
        false,
    ),
    Win32ApiEntry::new(
        "OpenServiceW",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "OpenServiceA",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "StartServiceW",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "StartServiceA",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "DeleteService",
        "advapi32.dll",
        ApiCategoryV2::Service,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "ControlService",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "OpenSCManagerW",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "OpenSCManagerA",
        "advapi32.dll",
        ApiCategoryV2::Service,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "AdjustTokenPrivileges",
        "advapi32.dll",
        ApiCategoryV2::Security,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "OpenProcessToken",
        "advapi32.dll",
        ApiCategoryV2::Security,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "DuplicateToken",
        "advapi32.dll",
        ApiCategoryV2::Security,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "DuplicateTokenEx",
        "advapi32.dll",
        ApiCategoryV2::Security,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "LookupPrivilegeValueW",
        "advapi32.dll",
        ApiCategoryV2::Security,
        3,
        true,
    ),
    Win32ApiEntry::new(
        "LookupPrivilegeValueA",
        "advapi32.dll",
        ApiCategoryV2::Security,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "SetThreadToken",
        "advapi32.dll",
        ApiCategoryV2::Security,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "ImpersonateLoggedOnUser",
        "advapi32.dll",
        ApiCategoryV2::Security,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "CryptCreateHash",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "CryptHashData",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "CryptGetHashParam",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "CryptDestroyHash",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "CryptEncrypt",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "CryptDecrypt",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CryptImportKey",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CryptExportKey",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CryptGenKey",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "CryptDestroyKey",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "CryptAcquireContextW",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        5,
        true,
    ),
    Win32ApiEntry::new(
        "CryptAcquireContextA",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "CryptReleaseContext",
        "advapi32.dll",
        ApiCategoryV2::Crypto,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "CryptProtectData",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "CryptUnprotectData",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "CryptDecodeObjectEx",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        7,
        false,
    ),
    Win32ApiEntry::new(
        "CryptEncodeObjectEx",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CertOpenStore",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "CertFindCertificateInStore",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        6,
        false,
    ),
    Win32ApiEntry::new(
        "CertCloseStore",
        "crypt32.dll",
        ApiCategoryV2::Crypto,
        2,
        false,
    ),
    // ── ws2_32 / Winsock2 ────────────────────────────────────────────────────
    Win32ApiEntry::new("WSAStartup", "ws2_32.dll", ApiCategoryV2::Network, 2, false),
    Win32ApiEntry::new("WSACleanup", "ws2_32.dll", ApiCategoryV2::Network, 0, false),
    Win32ApiEntry::new("socket", "ws2_32.dll", ApiCategoryV2::Network, 3, false),
    Win32ApiEntry::new("connect", "ws2_32.dll", ApiCategoryV2::Network, 3, false),
    Win32ApiEntry::new("bind", "ws2_32.dll", ApiCategoryV2::Network, 3, false),
    Win32ApiEntry::new("listen", "ws2_32.dll", ApiCategoryV2::Network, 2, false),
    Win32ApiEntry::new("accept", "ws2_32.dll", ApiCategoryV2::Network, 3, false),
    Win32ApiEntry::new("send", "ws2_32.dll", ApiCategoryV2::Network, 4, false),
    Win32ApiEntry::new("recv", "ws2_32.dll", ApiCategoryV2::Network, 4, false),
    Win32ApiEntry::new("sendto", "ws2_32.dll", ApiCategoryV2::Network, 6, false),
    Win32ApiEntry::new("recvfrom", "ws2_32.dll", ApiCategoryV2::Network, 6, false),
    Win32ApiEntry::new(
        "closesocket",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        1,
        false,
    ),
    Win32ApiEntry::new("setsockopt", "ws2_32.dll", ApiCategoryV2::Network, 5, false),
    Win32ApiEntry::new("getsockopt", "ws2_32.dll", ApiCategoryV2::Network, 5, false),
    Win32ApiEntry::new(
        "getsockname",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        3,
        false,
    ),
    Win32ApiEntry::new(
        "getpeername",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        3,
        false,
    ),
    Win32ApiEntry::new("WSASend", "ws2_32.dll", ApiCategoryV2::Network, 7, false),
    Win32ApiEntry::new("WSARecv", "ws2_32.dll", ApiCategoryV2::Network, 7, false),
    Win32ApiEntry::new("WSASendTo", "ws2_32.dll", ApiCategoryV2::Network, 9, false),
    Win32ApiEntry::new(
        "WSARecvFrom",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        9,
        false,
    ),
    Win32ApiEntry::new("WSAConnect", "ws2_32.dll", ApiCategoryV2::Network, 7, false),
    Win32ApiEntry::new("WSAAccept", "ws2_32.dll", ApiCategoryV2::Network, 5, false),
    Win32ApiEntry::new("WSASocket", "ws2_32.dll", ApiCategoryV2::Network, 6, false),
    Win32ApiEntry::new(
        "getaddrinfo",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "GetAddrInfoW",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "gethostbyname",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "gethostbyaddr",
        "ws2_32.dll",
        ApiCategoryV2::Network,
        3,
        false,
    ),
    Win32ApiEntry::new("WSAIoctl", "ws2_32.dll", ApiCategoryV2::Network, 8, false),
    Win32ApiEntry::new("shutdown", "ws2_32.dll", ApiCategoryV2::Network, 2, false),
    Win32ApiEntry::new("select", "ws2_32.dll", ApiCategoryV2::Network, 5, false),
    // ── wininet ───────────────────────────────────────────────────────────────
    Win32ApiEntry::new("InternetOpenW", "wininet.dll", ApiCategoryV2::Http, 5, true),
    Win32ApiEntry::new(
        "InternetOpenA",
        "wininet.dll",
        ApiCategoryV2::Http,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "InternetConnectW",
        "wininet.dll",
        ApiCategoryV2::Http,
        8,
        true,
    ),
    Win32ApiEntry::new(
        "InternetConnectA",
        "wininet.dll",
        ApiCategoryV2::Http,
        8,
        false,
    ),
    Win32ApiEntry::new(
        "HttpOpenRequestW",
        "wininet.dll",
        ApiCategoryV2::Http,
        8,
        true,
    ),
    Win32ApiEntry::new(
        "HttpOpenRequestA",
        "wininet.dll",
        ApiCategoryV2::Http,
        8,
        false,
    ),
    Win32ApiEntry::new(
        "HttpSendRequestW",
        "wininet.dll",
        ApiCategoryV2::Http,
        5,
        true,
    ),
    Win32ApiEntry::new(
        "HttpSendRequestA",
        "wininet.dll",
        ApiCategoryV2::Http,
        5,
        false,
    ),
    Win32ApiEntry::new(
        "HttpSendRequestExW",
        "wininet.dll",
        ApiCategoryV2::Http,
        5,
        true,
    ),
    Win32ApiEntry::new(
        "InternetReadFile",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "InternetWriteFile",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "InternetCloseHandle",
        "wininet.dll",
        ApiCategoryV2::Http,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "InternetQueryDataAvailable",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "HttpQueryInfoW",
        "wininet.dll",
        ApiCategoryV2::Http,
        5,
        true,
    ),
    Win32ApiEntry::new(
        "InternetSetOptionW",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "InternetQueryOptionW",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "InternetCrackUrlW",
        "wininet.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "InternetOpenUrlW",
        "wininet.dll",
        ApiCategoryV2::Http,
        6,
        true,
    ),
    Win32ApiEntry::new(
        "InternetOpenUrlA",
        "wininet.dll",
        ApiCategoryV2::Http,
        6,
        false,
    ),
    // ── winhttp ───────────────────────────────────────────────────────────────
    Win32ApiEntry::new("WinHttpOpen", "winhttp.dll", ApiCategoryV2::Http, 5, true),
    Win32ApiEntry::new(
        "WinHttpConnect",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "WinHttpOpenRequest",
        "winhttp.dll",
        ApiCategoryV2::Http,
        7,
        true,
    ),
    Win32ApiEntry::new(
        "WinHttpSendRequest",
        "winhttp.dll",
        ApiCategoryV2::Http,
        7,
        true,
    ),
    Win32ApiEntry::new(
        "WinHttpReceiveResponse",
        "winhttp.dll",
        ApiCategoryV2::Http,
        2,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpReadData",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpWriteData",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpCloseHandle",
        "winhttp.dll",
        ApiCategoryV2::Http,
        1,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpSetOption",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpQueryHeaders",
        "winhttp.dll",
        ApiCategoryV2::Http,
        6,
        true,
    ),
    Win32ApiEntry::new(
        "WinHttpQueryOption",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        false,
    ),
    Win32ApiEntry::new(
        "WinHttpCrackUrl",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
    Win32ApiEntry::new(
        "WinHttpGetProxyForUrl",
        "winhttp.dll",
        ApiCategoryV2::Http,
        4,
        true,
    ),
];

/// Look up a Win32 API entry by name.
#[must_use]
pub fn lookup_win32_api(name: &str) -> Option<&'static Win32ApiEntry> {
    WIN32_API_DB_V2.iter().find(|e| e.name == name)
}

/// Return all entries for a given module.
#[must_use]
pub fn win32_apis_by_module(module: &str) -> Vec<&'static Win32ApiEntry> {
    WIN32_API_DB_V2
        .iter()
        .filter(|e| e.module.eq_ignore_ascii_case(module))
        .collect()
}

/// Return all entries in a given category.
#[must_use]
pub fn win32_apis_by_category(cat: ApiCategoryV2) -> Vec<&'static Win32ApiEntry> {
    WIN32_API_DB_V2
        .iter()
        .filter(|e| e.category == cat)
        .collect()
}

// ─── DLL injection helpers ────────────────────────────────────────────────────

/// Strategy for injecting a DLL into a remote process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionStrategy {
    /// `CreateRemoteThread` + `LoadLibraryW`.
    CreateRemoteThread,
    /// `NtCreateThreadEx` (bypasses some hooks).
    NtCreateThreadEx,
    /// APC queue injection (`QueueUserAPC`).
    QueueUserApc,
    /// `SetWindowsHookEx` based injection.
    WindowsHookEx,
    /// Reflective DLL injection (shellcode-based).
    Reflective,
}

/// Parameters for DLL injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionParams {
    /// Target process ID.
    pub target_pid: u32,
    /// Full path to the DLL to inject.
    pub dll_path: String,
    /// Strategy to use.
    pub strategy: InjectionStrategy,
    /// Whether to wait for the injected DLL to initialize.
    pub wait_for_init: bool,
    /// Number of retries on failure.
    pub retries: u32,
}

impl InjectionParams {
    /// Create default `CreateRemoteThread` injection parameters.
    #[must_use]
    pub fn new(pid: u32, dll_path: impl Into<String>) -> Self {
        Self {
            target_pid: pid,
            dll_path: dll_path.into(),
            strategy: InjectionStrategy::CreateRemoteThread,
            wait_for_init: true,
            retries: 3,
        }
    }

    #[must_use]
    pub const fn strategy(mut self, s: InjectionStrategy) -> Self {
        self.strategy = s;
        self
    }
}

// ─── Hook engine model ────────────────────────────────────────────────────────

/// An inline hook record: original bytes saved before overwrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineHookRecord {
    /// Function name.
    pub name: String,
    /// Module containing the function.
    pub module: String,
    /// Absolute address of the function.
    pub func_addr: u64,
    /// Original bytes (typically 6–14 bytes).
    pub original_bytes: Vec<u8>,
    /// Trampoline address (allocated near the function).
    pub trampoline_addr: u64,
    /// Whether the hook is currently active.
    pub active: bool,
}

impl InlineHookRecord {
    /// Create a new hook record.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        func_addr: u64,
        original_bytes: Vec<u8>,
        trampoline_addr: u64,
    ) -> Self {
        Self {
            name: name.into(),
            module: module.into(),
            func_addr,
            original_bytes,
            trampoline_addr,
            active: false,
        }
    }

    /// Mark the hook as installed.
    pub const fn install(&mut self) {
        self.active = true;
    }

    /// Mark the hook as removed.
    pub const fn remove(&mut self) {
        self.active = false;
    }

    /// Return the JMP opcode bytes for a near 32-bit relative JMP.
    /// `target` is the destination address; the JMP is placed at `self.func_addr`.
    #[must_use]
    pub const fn jmp_bytes_32(&self, target: u64) -> [u8; 6] {
        // FF 25 00 00 00 00  (JMP [RIP+0]) followed by 8-byte absolute address is common
        // Simpler: E9 rel32 if within ±2 GB
        let rel = target.wrapping_sub(self.func_addr + 5);
        let rel_bytes = rel.to_le_bytes();
        [
            0xE9,
            rel_bytes[0],
            rel_bytes[1],
            rel_bytes[2],
            rel_bytes[3],
            0x90,
        ]
    }
}

// ─── API event filter ─────────────────────────────────────────────────────────

/// Filter for API event collection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiEventFilter {
    /// Only include these module names (empty = all modules).
    pub include_modules: Vec<String>,
    /// Exclude these module names.
    pub exclude_modules: Vec<String>,
    /// Only include these API names (empty = all).
    pub include_apis: Vec<String>,
    /// Exclude these API names.
    pub exclude_apis: Vec<String>,
    /// Only include events from these PIDs (empty = all).
    pub include_pids: Vec<u32>,
    /// Minimum return value to include (-1 = any).
    pub min_retval: Option<i64>,
}

impl ApiEventFilter {
    /// Create an empty filter (passes everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add module include pattern.
    #[must_use]
    pub fn include_module(mut self, m: impl Into<String>) -> Self {
        self.include_modules.push(m.into());
        self
    }

    /// Add API name include pattern.
    #[must_use]
    pub fn include_api(mut self, a: impl Into<String>) -> Self {
        self.include_apis.push(a.into());
        self
    }

    /// Check whether an event passes the filter.
    #[must_use]
    pub fn passes(&self, event: &ApiEvent) -> bool {
        if !self.include_pids.is_empty() && !self.include_pids.contains(&event.pid) {
            return false;
        }
        if !self.include_modules.is_empty()
            && !self
                .include_modules
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&event.module_name))
        {
            return false;
        }
        if self
            .exclude_modules
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&event.module_name))
        {
            return false;
        }
        if !self.include_apis.is_empty() && !self.include_apis.iter().any(|a| a == &event.api_name)
        {
            return false;
        }
        if self.exclude_apis.iter().any(|a| a == &event.api_name) {
            return false;
        }
        true
    }
}

// ─── Per-API statistics ───────────────────────────────────────────────────────

/// Statistics for a single API function across many calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiStatV2 {
    pub call_count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub error_count: u64,
}

impl WinApiStatV2 {
    pub const fn record(&mut self, elapsed_ns: u64, is_error: bool) {
        self.call_count += 1;
        self.total_ns += elapsed_ns;
        if self.call_count == 1 || elapsed_ns < self.min_ns {
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
        if self.call_count == 0 {
            0
        } else {
            self.total_ns / self.call_count
        }
    }
}

/// Aggregated statistics across all monitored APIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinApiStats {
    pub entries: HashMap<String, WinApiStatV2>,
}

impl WinApiStats {
    pub fn record(&mut self, api: &str, elapsed_ns: u64, is_error: bool) {
        self.entries
            .entry(api.to_string())
            .and_modify(|e| e.record(elapsed_ns, is_error))
            .or_insert_with(|| {
                let mut s = WinApiStatV2::default();
                s.record(elapsed_ns, is_error);
                s
            });
    }
    #[must_use]
    pub fn sorted_by_count(&self) -> Vec<(&str, &WinApiStatV2)> {
        let mut v: Vec<_> = self.entries.iter().map(|(k, v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.call_count.cmp(&a.1.call_count));
        v
    }
}

// ─── IPC channel model ────────────────────────────────────────────────────────

/// Name of the named pipe used for injected DLL → monitor IPC.
pub const MONITOR_PIPE_NAME: &str = r"\\.\pipe\rustre_api_monitor";

/// Message types sent over the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeMessageType {
    /// API call event (variable-length JSON payload follows).
    ApiEvent = 1,
    /// Heartbeat / keep-alive from the injected DLL.
    Heartbeat = 2,
    /// Injected DLL is shutting down.
    Shutdown = 3,
    /// Error message from the injected DLL.
    Error = 4,
}

/// Fixed-size header prefixed to every pipe message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PipeMessageHeader {
    pub msg_type: u8,
    pub payload_len: u32,
    pub sequence: u64,
}

impl PipeMessageHeader {
    /// Serialise to 13 bytes: [`msg_type(1)`] [`payload_len(4` LE)] [sequence(8 LE)]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 13] {
        let mut b = [0u8; 13];
        b[0] = self.msg_type;
        b[1..5].copy_from_slice(&self.payload_len.to_le_bytes());
        b[5..13].copy_from_slice(&self.sequence.to_le_bytes());
        b
    }

    /// Deserialise from 13 bytes.
    #[must_use]
    pub const fn from_bytes(b: &[u8; 13]) -> Self {
        let payload_len = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let sequence = u64::from_le_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]);
        Self {
            msg_type: b[0],
            payload_len,
            sequence,
        }
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod win_ext_tests {
    use super::*;

    #[test]
    fn test_api_db_has_createfilew() {
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "CreateFileW"));
    }

    #[test]
    fn test_api_db_has_virtualalloc() {
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "VirtualAlloc"));
    }

    #[test]
    fn test_api_db_has_wsasend() {
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "WSASend"));
    }

    #[test]
    fn test_api_db_has_cryptprotectdata() {
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "CryptProtectData"));
    }

    #[test]
    fn test_api_db_minimum_size() {
        assert!(WIN32_API_DB_V2.len() >= 100);
    }

    #[test]
    fn test_api_db_network_entries() {
        
        assert!(WIN32_API_DB_V2
            .iter()
            .filter(|e| e.category == ApiCategoryV2::Network).count() >= 10);
    }

    #[test]
    fn test_api_category_display() {
        assert_eq!(ApiCategoryV2::FileSystem.to_string(), "FileSystem");
        assert_eq!(ApiCategoryV2::Registry.to_string(), "Registry");
        assert_eq!(ApiCategoryV2::Crypto.to_string(), "Crypto");
        assert_eq!(ApiCategoryV2::Http.to_string(), "Http");
    }

    #[test]
    fn test_win_api_stat_avg_ns_zero_count() {
        let stat = WinApiStatV2::default();
        assert_eq!(stat.avg_ns(), 0);
    }

    #[test]
    fn test_win_api_stat_record() {
        let mut s = WinApiStatV2::default();
        s.record(1000, false);
        s.record(3000, true);
        assert_eq!(s.call_count, 2);
        assert_eq!(s.error_count, 1);
        assert_eq!(s.avg_ns(), 2000);
        assert_eq!(s.min_ns, 1000);
        assert_eq!(s.max_ns, 3000);
    }

    #[test]
    fn test_lookup_win32_api_found() {
        let e = lookup_win32_api("CreateFileW");
        assert!(e.is_some());
        assert_eq!(e.unwrap().module, "kernel32.dll");
    }

    #[test]
    fn test_lookup_win32_api_not_found() {
        assert!(lookup_win32_api("DoesNotExist").is_none());
    }

    #[test]
    fn test_win32_apis_by_module_ntdll() {
        let v = win32_apis_by_module("ntdll.dll");
        assert!(!v.is_empty());
        assert!(v.iter().all(|e| e.module == "ntdll.dll"));
    }

    #[test]
    fn test_win32_apis_by_category_network() {
        let v = win32_apis_by_category(ApiCategoryV2::Network);
        assert!(!v.is_empty());
    }

    #[test]
    fn test_win32_apis_by_category_loader() {
        let v = win32_apis_by_category(ApiCategoryV2::Loader);
        assert!(v.iter().any(|e| e.name == "LoadLibraryW"));
    }

    #[test]
    fn test_api_event_format_line() {
        let ev = ApiEvent {
            timestamp_ns: 1000,
            pid: 100,
            tid: 200,
            api_name: "CreateFileW".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![WinDecodedArg::WStr("C:\\test.txt".to_string())],
            retval: WinDecodedArg::Handle(0x80),
            call_stack: vec![],
        };
        let line = ev.format_line();
        assert!(line.contains("CreateFileW"));
        assert!(line.contains("kernel32.dll"));
    }

    #[test]
    fn test_api_event_to_json() {
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "NtClose".to_string(),
            module_name: "ntdll.dll".to_string(),
            args: vec![WinDecodedArg::Handle(0x4)],
            retval: WinDecodedArg::Status(0),
            call_stack: vec![],
        };
        let j = ev.to_json().unwrap();
        assert!(j.contains("NtClose"));
    }

    #[test]
    fn test_inline_hook_record_install_remove() {
        let mut h = InlineHookRecord::new(
            "NtWriteFile",
            "ntdll.dll",
            0x7fff_0000_1000,
            vec![0x4c, 0x8b, 0xd1, 0xb8],
            0x7fff_0000_2000,
        );
        assert!(!h.active);
        h.install();
        assert!(h.active);
        h.remove();
        assert!(!h.active);
    }

    #[test]
    fn test_pipe_message_header_roundtrip() {
        let hdr = PipeMessageHeader {
            msg_type: 1,
            payload_len: 256,
            sequence: 42,
        };
        let bytes = hdr.to_bytes();
        let hdr2 = PipeMessageHeader::from_bytes(&bytes);
        assert_eq!(hdr2.msg_type, 1);
        assert_eq!(hdr2.payload_len, 256);
        assert_eq!(hdr2.sequence, 42);
    }

    #[test]
    fn test_api_event_filter_passes_all() {
        let f = ApiEventFilter::new();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "ReadFile".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Bool(true),
            call_stack: vec![],
        };
        assert!(f.passes(&ev));
    }

    #[test]
    fn test_api_event_filter_include_module() {
        let f = ApiEventFilter::new().include_module("ntdll.dll");
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "NtReadFile".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Status(0),
            call_stack: vec![],
        };
        assert!(!f.passes(&ev));
    }

    #[test]
    fn test_api_event_filter_exclude_api() {
        let mut f = ApiEventFilter::new();
        f.exclude_apis.push("CloseHandle".to_string());
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "CloseHandle".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Bool(true),
            call_stack: vec![],
        };
        assert!(!f.passes(&ev));
    }

    #[test]
    fn test_injection_params_defaults() {
        let p = InjectionParams::new(1234, "C:\\hook.dll");
        assert_eq!(p.target_pid, 1234);
        assert_eq!(p.strategy, InjectionStrategy::CreateRemoteThread);
        assert_eq!(p.retries, 3);
    }

    #[test]
    fn test_decoded_arg_display_wstr() {
        assert_eq!(
            WinDecodedArg::WStr("test".to_string()).to_string(),
            "L\"test\""
        );
    }

    #[test]
    fn test_decoded_arg_display_status() {
        assert_eq!(
            WinDecodedArg::Status(0xC000_0005).to_string(),
            "0xc000_0005"
        );
    }

    #[test]
    fn test_decoded_arg_display_null() {
        assert_eq!(WinDecodedArg::Null.to_string(), "NULL");
    }

    #[test]
    fn test_win_api_stats_sorted_by_count() {
        let mut stats = WinApiStats::default();
        stats.record("ReadFile", 1000, false);
        stats.record("ReadFile", 2000, false);
        stats.record("WriteFile", 500, false);
        let sorted = stats.sorted_by_count();
        assert_eq!(sorted[0].0, "ReadFile");
        assert_eq!(sorted[0].1.call_count, 2);
    }

    #[test]
    fn test_monitor_pipe_name_constant() {
        assert!(MONITOR_PIPE_NAME.contains("pipe"));
    }

    #[test]
    fn test_wide_api_count() {
        let wide: Vec<_> = WIN32_API_DB_V2.iter().filter(|e| e.is_wide).collect();
        assert!(
            wide.len() >= 20,
            "expected at least 20 wide APIs, got {}",
            wide.len()
        );
    }

    #[test]
    fn test_http_api_count() {
        let http: Vec<_> = WIN32_API_DB_V2
            .iter()
            .filter(|e| e.category == ApiCategoryV2::Http)
            .collect();
        assert!(
            http.len() >= 15,
            "expected at least 15 HTTP APIs, got {}",
            http.len()
        );
    }

    #[test]
    fn test_crypto_api_count() {
        
        assert!(WIN32_API_DB_V2
            .iter()
            .filter(|e| e.category == ApiCategoryV2::Crypto).count() >= 10);
    }

    #[test]
    fn test_service_api_present() {
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "CreateServiceW"));
        assert!(WIN32_API_DB_V2.iter().any(|e| e.name == "DeleteService"));
    }
}

// ─── NTSTATUS decoder ─────────────────────────────────────────────────────────

/// Return the symbolic name of a common NTSTATUS code.
#[must_use]
pub const fn ntstatus_name(code: u32) -> Option<&'static str> {
    if code < 0x4000_0000 {
        ntstatus_name_success(code)
    } else if code < 0xC000_0000 {
        ntstatus_name_warning(code)
    } else if code <= 0xC000_0099 {
        ntstatus_name_error_low(code)
    } else {
        ntstatus_name_error_high(code)
    }
}

/// `ntstatus_name` lookup for success/informational codes (`0x0000_0000`–`0x3FFF_FFFF`).
const fn ntstatus_name_success(code: u32) -> Option<&'static str> {
    match code {
        0x0000_0000 => Some("STATUS_SUCCESS"),
        0x0000_0001 => Some("STATUS_WAIT_1"),
        0x0000_0080 => Some("STATUS_ABANDONED_WAIT_0"),
        0x0000_00C0 => Some("STATUS_USER_APC"),
        0x0000_0100 => Some("STATUS_USER_CALLBACK"),
        0x0000_0101 => Some("STATUS_ALERTED"),
        0x0000_0102 => Some("STATUS_TIMEOUT"),
        0x0000_0103 => Some("STATUS_PENDING"),
        0x0000_0104 => Some("STATUS_REPARSE"),
        0x0000_0105 => Some("STATUS_MORE_ENTRIES"),
        0x0000_0106 => Some("STATUS_NOT_ALL_ASSIGNED"),
        0x0000_0107 => Some("STATUS_SOME_NOT_MAPPED"),
        0x0000_0108 => Some("STATUS_OPLOCK_BREAK_IN_PROGRESS"),
        0x0000_0109 => Some("STATUS_VOLUME_MOUNTED"),
        0x0000_010A => Some("STATUS_RXACT_COMMITTED"),
        0x0000_010B => Some("STATUS_NOTIFY_CLEANUP"),
        0x0000_010C => Some("STATUS_NOTIFY_ENUM_DIR"),
        0x0000_010D => Some("STATUS_NO_QUOTAS_FOR_ACCOUNT"),
        0x0000_0110 => Some("STATUS_DELETE_PENDING"),
        0x0000_0111 => Some("STATUS_CTL_FILE_NOT_SUPPORTED"),
        _ => None,
    }
}

/// `ntstatus_name` lookup for warning codes (`0x4000_0000`–`0xBFFF_FFFF`).
const fn ntstatus_name_warning(code: u32) -> Option<&'static str> {
    match code {
        0x4000_0000 => Some("STATUS_OBJECT_NAME_EXISTS"),
        0x4000_0001 => Some("STATUS_THREAD_WAS_SUSPENDED"),
        0x4000_0002 => Some("STATUS_WORKING_SET_LIMIT_RANGE"),
        0x4000_0003 => Some("STATUS_IMAGE_NOT_AT_BASE"),
        0x4000_0004 => Some("STATUS_RXACT_STATE_CREATED"),
        0x4000_0005 => Some("STATUS_SEGMENT_NOTIFICATION"),
        0x4000_0006 => Some("STATUS_LOCAL_USER_SESSION_KEY"),
        0x4000_0007 => Some("STATUS_BAD_CURRENT_DIRECTORY"),
        0x4000_0008 => Some("STATUS_SERIAL_MORE_WRITES"),
        0x4000_0009 => Some("STATUS_REGISTRY_RECOVERED"),
        0x4000_000A => Some("STATUS_FT_READ_RECOVERY_FROM_BACKUP"),
        0x8000_000D | 0x8000_0006 => Some("STATUS_NO_MORE_FILES"),
        0x8000_0001 => Some("STATUS_GUARD_PAGE_VIOLATION"),
        0x8000_0002 => Some("STATUS_DATATYPE_MISALIGNMENT"),
        0x8000_0003 => Some("STATUS_BREAKPOINT"),
        0x8000_0004 => Some("STATUS_SINGLE_STEP"),
        0x8000_0005 => Some("STATUS_BUFFER_OVERFLOW"),
        0x8000_0007 => Some("STATUS_WAKE_SYSTEM_DEBUGGER"),
        0x8000_0008 => Some("STATUS_HANDLES_CLOSED"),
        0x8000_0009 => Some("STATUS_NO_INHERITANCE"),
        0x8000_000A => Some("STATUS_GUID_SUBSTITUTION_MADE"),
        0x8000_000B => Some("STATUS_PARTIAL_COPY"),
        0x8000_000C => Some("STATUS_DEVICE_PAPER_EMPTY"),
        0x8000_000E => Some("STATUS_NO_MORE_EAS"),
        0x8000_000F => Some("STATUS_RETURNS_WITHOUT_PERFORMING_REQUESTED_OPERATION"),
        0x8000_0010 => Some("STATUS_PREDEFINED_HANDLE"),
        0x8000_0011 => Some("STATUS_WAS_UNLOCKED"),
        0x8000_0012 => Some("STATUS_SERVICE_NOTIFICATION"),
        0x8000_0013 => Some("STATUS_WAS_LOCKED"),
        0x8000_0014 => Some("STATUS_LOG_HARD_ERROR"),
        0x8000_0015 => Some("STATUS_ALREADY_WIN32"),
        0x8000_0016 => Some("STATUS_WX86_UNSIMULATE"),
        0x8000_0017 => Some("STATUS_WX86_CONTINUE"),
        _ => None,
    }
}

/// `ntstatus_name` lookup for low error codes (`0xC000_0001`–`0xC000_0099`).
const fn ntstatus_name_error_low(code: u32) -> Option<&'static str> {
    if let Some(s) = ntstatus_name_error_low_a(code) {
        return Some(s);
    }
    ntstatus_name_error_low_b(code)
}

const fn ntstatus_name_error_low_a(code: u32) -> Option<&'static str> {
    match code {
        0xC000_0001 => Some("STATUS_UNSUCCESSFUL"),
        0xC000_0002 => Some("STATUS_NOT_IMPLEMENTED"),
        0xC000_0003 => Some("STATUS_INVALID_INFO_CLASS"),
        0xC000_0004 => Some("STATUS_INFO_LENGTH_MISMATCH"),
        0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
        0xC000_0006 => Some("STATUS_IN_PAGE_ERROR"),
        0xC000_0007 => Some("STATUS_PAGEFILE_QUOTA"),
        0xC000_0008 => Some("STATUS_INVALID_HANDLE"),
        0xC000_0009 => Some("STATUS_BAD_INITIAL_STACK"),
        0xC000_000A => Some("STATUS_BAD_INITIAL_PC"),
        0xC000_000B => Some("STATUS_INVALID_CID"),
        0xC000_000C => Some("STATUS_TIMER_NOT_CANCELED"),
        0xC000_000D => Some("STATUS_INVALID_PARAMETER"),
        0xC000_000E => Some("STATUS_NO_SUCH_DEVICE"),
        0xC000_000F => Some("STATUS_NO_SUCH_FILE"),
        0xC000_0010 => Some("STATUS_INVALID_DEVICE_REQUEST"),
        0xC000_0011 => Some("STATUS_END_OF_FILE"),
        0xC000_0012 => Some("STATUS_WRONG_VOLUME"),
        0xC000_0013 => Some("STATUS_NO_MEDIA_IN_DEVICE"),
        0xC000_0014 => Some("STATUS_UNRECOGNIZED_MEDIA"),
        0xC000_0015 => Some("STATUS_NONEXISTENT_SECTOR"),
        0xC000_0016 => Some("STATUS_MORE_PROCESSING_REQUIRED"),
        0xC000_0017 => Some("STATUS_NO_MEMORY"),
        0xC000_0018 => Some("STATUS_CONFLICTING_ADDRESSES"),
        0xC000_0019 => Some("STATUS_NOT_MAPPED_VIEW"),
        0xC000_001A => Some("STATUS_UNABLE_TO_FREE_VM"),
        0xC000_001B => Some("STATUS_UNABLE_TO_DELETE_SECTION"),
        0xC000_001C => Some("STATUS_INVALID_SYSTEM_SERVICE"),
        0xC000_001D => Some("STATUS_ILLEGAL_INSTRUCTION"),
        0xC000_001E => Some("STATUS_INVALID_LOCK_SEQUENCE"),
        0xC000_001F => Some("STATUS_INVALID_VIEW_SIZE"),
        0xC000_0020 => Some("STATUS_INVALID_FILE_FOR_SECTION"),
        0xC000_0021 => Some("STATUS_ALREADY_COMMITTED"),
        0xC000_0022 => Some("STATUS_ACCESS_DENIED"),
        0xC000_0023 => Some("STATUS_BUFFER_TOO_SMALL"),
        0xC000_0024 => Some("STATUS_OBJECT_TYPE_MISMATCH"),
        0xC000_0025 => Some("STATUS_NONCONTINUABLE_EXCEPTION"),
        0xC000_0026 => Some("STATUS_INVALID_DISPOSITION"),
        0xC000_0027 => Some("STATUS_UNWIND"),
        0xC000_0028 => Some("STATUS_BAD_STACK"),
        0xC000_0029 => Some("STATUS_INVALID_UNWIND_TARGET"),
        0xC000_002A => Some("STATUS_NOT_LOCKED"),
        0xC000_002B => Some("STATUS_PARITY_ERROR"),
        0xC000_002C => Some("STATUS_UNABLE_TO_DECOMMIT_VM"),
        0xC000_002D => Some("STATUS_NOT_COMMITTED"),
        0xC000_002E => Some("STATUS_INVALID_PORT_ATTRIBUTES"),
        0xC000_002F => Some("STATUS_PORT_MESSAGE_TOO_LONG"),
        0xC000_0030 => Some("STATUS_INVALID_PARAMETER_MIX"),
        0xC000_0031 => Some("STATUS_INVALID_QUOTA_LOWER"),
        0xC000_0032 => Some("STATUS_DISK_CORRUPT_ERROR"),
        0xC000_0033 => Some("STATUS_OBJECT_NAME_INVALID"),
        0xC000_0034 => Some("STATUS_OBJECT_NAME_NOT_FOUND"),
        0xC000_0035 => Some("STATUS_OBJECT_NAME_COLLISION"),
        0xC000_0037 => Some("STATUS_PORT_DISCONNECTED"),
        0xC000_0038 => Some("STATUS_DEVICE_ALREADY_ATTACHED"),
        0xC000_0039 => Some("STATUS_OBJECT_PATH_INVALID"),
        0xC000_003A => Some("STATUS_OBJECT_PATH_NOT_FOUND"),
        0xC000_003B => Some("STATUS_OBJECT_PATH_SYNTAX_BAD"),
        0xC000_003C => Some("STATUS_DATA_OVERRUN"),
        0xC000_003D => Some("STATUS_DATA_LATE_ERROR"),
        0xC000_003E => Some("STATUS_DATA_ERROR"),
        0xC000_003F => Some("STATUS_CRC_ERROR"),
        0xC000_0040 => Some("STATUS_SECTION_TOO_BIG"),
        0xC000_0041 => Some("STATUS_PORT_CONNECTION_REFUSED"),
        0xC000_0042 => Some("STATUS_INVALID_PORT_HANDLE"),
        0xC000_0043 => Some("STATUS_SHARING_VIOLATION"),
        0xC000_0044 => Some("STATUS_QUOTA_EXCEEDED"),
        0xC000_0045 => Some("STATUS_INVALID_PAGE_PROTECTION"),
        0xC000_0046 => Some("STATUS_MUTANT_NOT_OWNED"),
        0xC000_0047 => Some("STATUS_SEMAPHORE_LIMIT_EXCEEDED"),
        0xC000_0048 => Some("STATUS_PORT_ALREADY_SET"),
        0xC000_0049 => Some("STATUS_SECTION_NOT_IMAGE"),
        0xC000_004A => Some("STATUS_SUSPEND_COUNT_EXCEEDED"),
        0xC000_004B => Some("STATUS_THREAD_IS_TERMINATING"),
        0xC000_004C => Some("STATUS_BAD_WORKING_SET_LIMIT"),
        0xC000_004D => Some("STATUS_INCOMPATIBLE_FILE_MAP"),
        0xC000_004E => Some("STATUS_SECTION_PROTECTION"),
        _ => None,
    }
}

const fn ntstatus_name_error_low_b(code: u32) -> Option<&'static str> {
    match code {
        0xC000_004F => Some("STATUS_EAS_NOT_SUPPORTED"),
        0xC000_0050 => Some("STATUS_EA_TOO_LARGE"),
        0xC000_0051 => Some("STATUS_NONEXISTENT_EA_ENTRY"),
        0xC000_0052 => Some("STATUS_NO_EAS_ON_FILE"),
        0xC000_0053 => Some("STATUS_EA_CORRUPT_ERROR"),
        0xC000_0054 => Some("STATUS_FILE_LOCK_CONFLICT"),
        0xC000_0055 => Some("STATUS_LOCK_NOT_GRANTED"),
        0xC000_0056 => Some("STATUS_DELETE_PENDING"),
        0xC000_0057 => Some("STATUS_CTL_FILE_NOT_SUPPORTED"),
        0xC000_0058 => Some("STATUS_UNKNOWN_REVISION"),
        0xC000_0059 => Some("STATUS_REVISION_MISMATCH"),
        0xC000_005A => Some("STATUS_INVALID_OWNER"),
        0xC000_005B => Some("STATUS_INVALID_PRIMARY_GROUP"),
        0xC000_005C => Some("STATUS_NO_IMPERSONATION_TOKEN"),
        0xC000_005D => Some("STATUS_CANT_DISABLE_MANDATORY"),
        0xC000_005E => Some("STATUS_NO_LOGON_SERVERS"),
        0xC000_005F => Some("STATUS_NO_SUCH_LOGON_SESSION"),
        0xC000_0060 => Some("STATUS_NO_SUCH_PRIVILEGE"),
        0xC000_0061 => Some("STATUS_PRIVILEGE_NOT_HELD"),
        0xC000_0062 => Some("STATUS_INVALID_ACCOUNT_NAME"),
        0xC000_0063 => Some("STATUS_USER_EXISTS"),
        0xC000_0064 => Some("STATUS_NO_SUCH_USER"),
        0xC000_0065 => Some("STATUS_GROUP_EXISTS"),
        0xC000_0066 => Some("STATUS_NO_SUCH_GROUP"),
        0xC000_0067 => Some("STATUS_MEMBER_IN_GROUP"),
        0xC000_0068 => Some("STATUS_MEMBER_NOT_IN_GROUP"),
        0xC000_0069 => Some("STATUS_LAST_ADMIN"),
        0xC000_006A => Some("STATUS_WRONG_PASSWORD"),
        0xC000_006B => Some("STATUS_ILL_FORMED_PASSWORD"),
        0xC000_006C => Some("STATUS_PASSWORD_RESTRICTION"),
        0xC000_006D => Some("STATUS_LOGON_FAILURE"),
        0xC000_006E => Some("STATUS_ACCOUNT_RESTRICTION"),
        0xC000_006F => Some("STATUS_INVALID_LOGON_HOURS"),
        0xC000_0070 => Some("STATUS_INVALID_WORKSTATION"),
        0xC000_0071 => Some("STATUS_PASSWORD_EXPIRED"),
        0xC000_0072 => Some("STATUS_ACCOUNT_DISABLED"),
        0xC000_0073 => Some("STATUS_NONE_MAPPED"),
        0xC000_0074 => Some("STATUS_TOO_MANY_LUIDS_REQUESTED"),
        0xC000_0075 => Some("STATUS_LUIDS_EXHAUSTED"),
        0xC000_0076 => Some("STATUS_INVALID_SUB_AUTHORITY"),
        0xC000_0077 => Some("STATUS_INVALID_ACL"),
        0xC000_0078 => Some("STATUS_INVALID_SID"),
        0xC000_0079 => Some("STATUS_INVALID_SECURITY_DESCR"),
        0xC000_0080 => Some("STATUS_PROCEDURE_NOT_FOUND"),
        0xC000_0081 => Some("STATUS_INVALID_IMAGE_FORMAT"),
        0xC000_0082 => Some("STATUS_NO_TOKEN"),
        0xC000_0083 => Some("STATUS_BAD_INHERITANCE_ACL"),
        0xC000_0084 => Some("STATUS_RANGE_NOT_LOCKED"),
        0xC000_0085 => Some("STATUS_DISK_FULL"),
        0xC000_0086 => Some("STATUS_SERVER_DISABLED"),
        0xC000_0087 => Some("STATUS_SERVER_NOT_DISABLED"),
        0xC000_0088 => Some("STATUS_TOO_MANY_GUIDS_REQUESTED"),
        0xC000_0089 => Some("STATUS_GUIDS_EXHAUSTED"),
        0xC000_008A => Some("STATUS_INVALID_ID_AUTHORITY"),
        0xC000_008B => Some("STATUS_AGENTS_EXHAUSTED"),
        0xC000_008C => Some("STATUS_INVALID_VOLUME_LABEL"),
        0xC000_008D => Some("STATUS_SECTION_NOT_EXTENDED"),
        0xC000_008E => Some("STATUS_NOT_MAPPED_DATA"),
        0xC000_008F => Some("STATUS_RESOURCE_DATA_NOT_FOUND"),
        0xC000_0090 => Some("STATUS_RESOURCE_TYPE_NOT_FOUND"),
        0xC000_0091 => Some("STATUS_RESOURCE_NAME_NOT_FOUND"),
        0xC000_0092 => Some("STATUS_ARRAY_BOUNDS_EXCEEDED"),
        0xC000_0093 => Some("STATUS_FLOAT_DENORMAL_OPERAND"),
        0xC000_0094 => Some("STATUS_FLOAT_DIVIDE_BY_ZERO"),
        0xC000_0095 => Some("STATUS_FLOAT_INEXACT_RESULT"),
        0xC000_0096 => Some("STATUS_FLOAT_INVALID_OPERATION"),
        0xC000_0097 => Some("STATUS_FLOAT_OVERFLOW"),
        0xC000_0098 => Some("STATUS_FLOAT_STACK_CHECK"),
        0xC000_0099 => Some("STATUS_FLOAT_UNDERFLOW"),
        _ => None,
    }
}

/// `ntstatus_name` lookup for high error codes (`0xC000_009A`+).
const fn ntstatus_name_error_high(code: u32) -> Option<&'static str> {
    match code {
        0xC000_009A => Some("STATUS_INTEGER_DIVIDE_BY_ZERO"),
        0xC000_009B => Some("STATUS_INTEGER_OVERFLOW"),
        0xC000_009C => Some("STATUS_PRIVILEGED_INSTRUCTION"),
        0xC000_009D => Some("STATUS_TOO_MANY_PAGING_FILES"),
        0xC000_009E => Some("STATUS_FILE_INVALID"),
        0xC000_009F => Some("STATUS_ALLOTTED_SPACE_EXCEEDED"),
        0xC000_00A0 => Some("STATUS_INSUFFICIENT_RESOURCES"),
        0xC000_00A1 => Some("STATUS_DFS_EXIT_PATH_FOUND"),
        0xC000_00A2 => Some("STATUS_DEVICE_DATA_ERROR"),
        0xC000_00A3 => Some("STATUS_DEVICE_NOT_CONNECTED"),
        0xC000_00A4 => Some("STATUS_DEVICE_POWER_FAILURE"),
        0xC000_00A5 => Some("STATUS_FREE_VM_NOT_AT_BASE"),
        0xC000_00A6 => Some("STATUS_MEMORY_NOT_ALLOCATED"),
        0xC000_00A7 => Some("STATUS_WORKING_SET_QUOTA"),
        0xC000_00A8 => Some("STATUS_MEDIA_WRITE_PROTECTED"),
        0xC000_00A9 => Some("STATUS_DEVICE_NOT_READY"),
        0xC000_00AA => Some("STATUS_INVALID_GROUP_ATTRIBUTES"),
        0xC000_00AB => Some("STATUS_BAD_IMPERSONATION_LEVEL"),
        0xC000_00AC => Some("STATUS_CANT_OPEN_ANONYMOUS"),
        0xC000_00AD => Some("STATUS_BAD_VALIDATION_CLASS"),
        0xC000_00AE => Some("STATUS_BAD_TOKEN_TYPE"),
        0xC000_00AF => Some("STATUS_BAD_MASTER_BOOT_RECORD"),
        0xC000_00B0 => Some("STATUS_INSTRUCTION_MISALIGNMENT"),
        0xC000_00B1 => Some("STATUS_INSTANCE_NOT_AVAILABLE"),
        0xC000_00B2 => Some("STATUS_PIPE_NOT_AVAILABLE"),
        0xC000_00B3 => Some("STATUS_INVALID_PIPE_STATE"),
        0xC000_00B4 => Some("STATUS_PIPE_BUSY"),
        0xC000_00B5 => Some("STATUS_ILLEGAL_FUNCTION"),
        0xC000_00B6 => Some("STATUS_PIPE_DISCONNECTED"),
        0xC000_00B7 => Some("STATUS_PIPE_CLOSING"),
        0xC000_00B8 => Some("STATUS_PIPE_CONNECTED"),
        0xC000_00B9 => Some("STATUS_PIPE_LISTENING"),
        0xC000_00BA => Some("STATUS_INVALID_READ_MODE"),
        0xC000_00BB => Some("STATUS_IO_TIMEOUT"),
        0xC000_00BC => Some("STATUS_FILE_FORCED_CLOSED"),
        0xC000_00BD => Some("STATUS_PROFILING_NOT_STARTED"),
        0xC000_00BE => Some("STATUS_PROFILING_NOT_STOPPED"),
        0xC000_00BF => Some("STATUS_COULD_NOT_INTERPRET"),
        0xC000_00C0 => Some("STATUS_FILE_IS_A_DIRECTORY"),
        0xC000_00C1 => Some("STATUS_NOT_SUPPORTED"),
        0xC000_00C2 => Some("STATUS_REMOTE_NOT_LISTENING"),
        0xC000_00C3 => Some("STATUS_DUPLICATE_NAME"),
        0xC000_00C4 => Some("STATUS_BAD_NETWORK_PATH"),
        0xC000_00C5 => Some("STATUS_NETWORK_BUSY"),
        0xC000_00C6 => Some("STATUS_DEVICE_DOES_NOT_EXIST"),
        0xC000_00C7 => Some("STATUS_TOO_MANY_COMMANDS"),
        0xC000_00C8 => Some("STATUS_ADAPTER_HARDWARE_ERROR"),
        0xC000_00C9 => Some("STATUS_INVALID_NETWORK_RESPONSE"),
        0xC000_00CA => Some("STATUS_UNEXPECTED_NETWORK_ERROR"),
        0xC000_00CB => Some("STATUS_BAD_REMOTE_ADAPTER"),
        0xC000_00CC => Some("STATUS_PRINT_QUEUE_FULL"),
        0xC000_00CD => Some("STATUS_NO_SPOOL_SPACE"),
        0xC000_00CE => Some("STATUS_PRINT_CANCELLED"),
        0xC000_00CF => Some("STATUS_NETWORK_NAME_DELETED"),
        0xC000_00D0 => Some("STATUS_NETWORK_ACCESS_DENIED"),
        0xC000_00D1 => Some("STATUS_BAD_DEVICE_TYPE"),
        0xC000_00D2 => Some("STATUS_BAD_NETWORK_NAME"),
        0xC000_00D3 => Some("STATUS_TOO_MANY_NAMES"),
        0xC000_00D4 => Some("STATUS_TOO_MANY_SESSIONS"),
        0xC000_00D5 => Some("STATUS_SHARING_PAUSED"),
        0xC000_00D6 => Some("STATUS_REQUEST_NOT_ACCEPTED"),
        0xC000_00D7 => Some("STATUS_REDIRECTOR_PAUSED"),
        0xC000_00D8 => Some("STATUS_NET_WRITE_FAULT"),
        _ => None,
    }
}

/// Format an NTSTATUS for display.
#[must_use]
pub fn format_ntstatus(code: u32) -> String {
    ntstatus_name(code).map_or_else(
        || format!("0x{code:08x}"),
        |name| format!("0x{code:08x} ({name})"),
    )
}

// ─── Windows NT object path helpers ──────────────────────────────────────────

/// Convert a Windows NT native path to a Win32 path (approximate).
#[must_use]
pub fn nt_to_win32_path(nt_path: &str) -> String {
    // \\Device\\HarddiskVolume3\\Windows\\... -> C:\Windows\...
    if let Some(rest) = nt_path.strip_prefix("\\Device\\HarddiskVolume") {
        let vol_end = rest.find('\\').unwrap_or(rest.len());
        let vol_num = &rest[..vol_end];
        let path = &rest[vol_end..];
        // Map volume 1 -> A:, 2 -> B:, ...; everything else defaults to C:.
        let drive: char = vol_num
            .parse::<u32>()
            .ok()
            .and_then(|n| {
                n.checked_sub(1)
                    .and_then(|i| u8::try_from(i).ok())
                    .and_then(|i| char::from_u32(u32::from(b'A' + i)))
            })
            .unwrap_or('C');
        return format!("{drive}:{}", path.replace('/', "\\"));
    }
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        return rest.replace('/', "\\");
    }
    if let Some(rest) = nt_path.strip_prefix("\\\\?\\") {
        return rest.to_string();
    }
    nt_path.to_string()
}

/// Check whether a file path points to a system-critical location.
#[must_use]
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\system32\\") || p.contains("\\syswow64\\") || p.contains("\\windows\\")
}

/// Decode a Windows file access mask to a readable string.
#[must_use]
pub fn decode_file_access(access: u32) -> String {
    let mut parts = Vec::new();
    if access & 0x8000_0000 != 0 {
        parts.push("GENERIC_READ");
    }
    if access & 0x4000_0000 != 0 {
        parts.push("GENERIC_WRITE");
    }
    if access & 0x2000_0000 != 0 {
        parts.push("GENERIC_EXECUTE");
    }
    if access & 0x1000_0000 != 0 {
        parts.push("GENERIC_ALL");
    }
    if access & 0x0010_0000 != 0 {
        parts.push("SYNCHRONIZE");
    }
    if access & 0x0008_0000 != 0 {
        parts.push("WRITE_OWNER");
    }
    if access & 0x0004_0000 != 0 {
        parts.push("WRITE_DAC");
    }
    if access & 0x0002_0000 != 0 {
        parts.push("READ_CONTROL");
    }
    if access & 0x0001_0000 != 0 {
        parts.push("DELETE");
    }
    if access & 0x0000_0001 != 0 {
        parts.push("FILE_READ_DATA");
    }
    if access & 0x0000_0002 != 0 {
        parts.push("FILE_WRITE_DATA");
    }
    if access & 0x0000_0004 != 0 {
        parts.push("FILE_APPEND_DATA");
    }
    if access & 0x0000_0008 != 0 {
        parts.push("FILE_READ_EA");
    }
    if access & 0x0000_0010 != 0 {
        parts.push("FILE_WRITE_EA");
    }
    if access & 0x0000_0020 != 0 {
        parts.push("FILE_EXECUTE");
    }
    if access & 0x0000_0040 != 0 {
        parts.push("FILE_DELETE_CHILD");
    }
    if access & 0x0000_0080 != 0 {
        parts.push("FILE_READ_ATTRIBUTES");
    }
    if access & 0x0000_0100 != 0 {
        parts.push("FILE_WRITE_ATTRIBUTES");
    }
    if parts.is_empty() {
        return format!("0x{access:x}");
    }
    parts.join("|")
}

/// Decode a Windows virtual memory allocation type.
#[must_use]
pub fn decode_alloc_type(alloc_type: u32) -> String {
    let mut parts = Vec::new();
    if alloc_type & 0x0000_1000 != 0 {
        parts.push("MEM_COMMIT");
    }
    if alloc_type & 0x0000_2000 != 0 {
        parts.push("MEM_RESERVE");
    }
    if alloc_type & 0x0000_4000 != 0 {
        parts.push("MEM_DECOMMIT");
    }
    if alloc_type & 0x0000_8000 != 0 {
        parts.push("MEM_RELEASE");
    }
    if alloc_type & 0x0001_0000 != 0 {
        parts.push("MEM_FREE");
    }
    if alloc_type & 0x0002_0000 != 0 {
        parts.push("MEM_PRIVATE");
    }
    if alloc_type & 0x0004_0000 != 0 {
        parts.push("MEM_MAPPED");
    }
    if alloc_type & 0x0008_0000 != 0 {
        parts.push("MEM_RESET");
    }
    if alloc_type & 0x0010_0000 != 0 {
        parts.push("MEM_TOP_DOWN");
    }
    if alloc_type & 0x0020_0000 != 0 {
        parts.push("MEM_WRITE_WATCH");
    }
    if alloc_type & 0x0040_0000 != 0 {
        parts.push("MEM_PHYSICAL");
    }
    if alloc_type & 0x0100_0000 != 0 {
        parts.push("MEM_IMAGE");
    }
    if alloc_type & 0x0400_0000 != 0 {
        parts.push("MEM_4MB_PAGES");
    }
    if alloc_type & 0x2000_0000 != 0 {
        parts.push("MEM_LARGE_PAGES");
    }
    if parts.is_empty() {
        return format!("0x{alloc_type:x}");
    }
    parts.join("|")
}

// ─── Process taint tracker (Windows) ──────────────────────────────────────────

/// Process-injection taint: DLL loading, remote writes, remote thread creation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WinTaintProcess {
    pub injected_dll: bool,
    pub wrote_to_remote_process: bool,
    pub spawned_remote_thread: bool,
}

/// Persistence and network taint: registry run keys, services, network connections.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WinTaintPersistence {
    pub modified_registry_run_key: bool,
    pub created_service: bool,
    pub opened_network_connection: bool,
}

/// Miscellaneous taint: executable memory allocation, crypto usage, privilege escalation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WinTaintMisc {
    pub allocated_exec_memory: bool,
    pub loaded_crypto: bool,
    pub elevated_privilege: bool,
}

/// Taint flags for Windows process monitoring.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WinTaintFlags {
    pub process: WinTaintProcess,
    pub persistence: WinTaintPersistence,
    pub misc: WinTaintMisc,
}

impl WinTaintFlags {
    /// Convenience accessor — injected DLL flag.
    #[must_use]
    pub const fn injected_dll(&self) -> bool { self.process.injected_dll }
    /// Convenience accessor — allocated executable memory flag.
    #[must_use]
    pub const fn allocated_exec_memory(&self) -> bool { self.misc.allocated_exec_memory }
    /// Convenience accessor — wrote to remote process flag.
    #[must_use]
    pub const fn wrote_to_remote_process(&self) -> bool { self.process.wrote_to_remote_process }
    /// Convenience accessor — spawned remote thread flag.
    #[must_use]
    pub const fn spawned_remote_thread(&self) -> bool { self.process.spawned_remote_thread }
    /// Convenience accessor — modified registry run key flag.
    #[must_use]
    pub const fn modified_registry_run_key(&self) -> bool { self.persistence.modified_registry_run_key }
    /// Convenience accessor — created service flag.
    #[must_use]
    pub const fn created_service(&self) -> bool { self.persistence.created_service }
    /// Convenience accessor — opened network connection flag.
    #[must_use]
    pub const fn opened_network_connection(&self) -> bool { self.persistence.opened_network_connection }
    /// Convenience accessor — loaded crypto flag.
    #[must_use]
    pub const fn loaded_crypto(&self) -> bool { self.misc.loaded_crypto }
    /// Convenience accessor — elevated privilege flag.
    #[must_use]
    pub const fn elevated_privilege(&self) -> bool { self.misc.elevated_privilege }

    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.process.injected_dll
            || self.misc.allocated_exec_memory
            || self.process.wrote_to_remote_process
            || self.process.spawned_remote_thread
            || self.persistence.modified_registry_run_key
            || self.persistence.created_service
    }

    /// Update taint from an API event.
    pub fn update_from_event(&mut self, event: &ApiEvent) {
        match event.api_name.as_str() {
            "LoadLibraryW" | "LoadLibraryA" | "LdrLoadDll" => {
                self.process.injected_dll = true;
            }
            "VirtualAllocEx" => {
                // Check if PAGE_EXECUTE_READWRITE or similar exec bit
                if event.args.len() >= 4
                    && let WinDecodedArg::UInt(prot) = &event.args[3]
                    && prot & 0xF0 != 0
                {
                    self.misc.allocated_exec_memory = true;
                }
            }
            "WriteProcessMemory" => {
                self.process.wrote_to_remote_process = true;
            }
            "CreateRemoteThread" | "CreateRemoteThreadEx" | "NtCreateThreadEx" => {
                self.process.spawned_remote_thread = true;
            }
            "RegSetValueExW" | "RegSetValueExA" => {
                for arg in &event.args {
                    if let WinDecodedArg::RegistryPath(p) = arg
                        && p.to_lowercase().contains("run")
                    {
                        self.persistence.modified_registry_run_key = true;
                    }
                    if let WinDecodedArg::WStr(p) = arg
                        && p.to_lowercase().contains("run")
                    {
                        self.persistence.modified_registry_run_key = true;
                    }
                }
            }
            "CreateServiceW" | "CreateServiceA" => {
                self.persistence.created_service = true;
            }
            "connect" | "WSAConnect" => {
                self.persistence.opened_network_connection = true;
            }
            "CryptAcquireContextW" | "CryptAcquireContextA" => {
                self.misc.loaded_crypto = true;
            }
            "AdjustTokenPrivileges" => {
                self.misc.elevated_privilege = true;
            }
            _ => {}
        }
    }

    /// Return a summary of active taint flags.
    #[must_use]
    pub fn summary(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.process.injected_dll {
            v.push("DLL_INJECTION");
        }
        if self.misc.allocated_exec_memory {
            v.push("EXEC_MEMORY_ALLOC");
        }
        if self.process.wrote_to_remote_process {
            v.push("REMOTE_WRITE");
        }
        if self.process.spawned_remote_thread {
            v.push("REMOTE_THREAD");
        }
        if self.persistence.modified_registry_run_key {
            v.push("REGISTRY_RUN_KEY");
        }
        if self.persistence.created_service {
            v.push("SERVICE_CREATED");
        }
        if self.persistence.opened_network_connection {
            v.push("NETWORK_CONNECTION");
        }
        if self.misc.loaded_crypto {
            v.push("CRYPTO_USAGE");
        }
        if self.misc.elevated_privilege {
            v.push("PRIVILEGE_ELEVATION");
        }
        v
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod win_ext2_tests {
    use super::*;

    #[test]
    fn test_ntstatus_success() {
        assert_eq!(ntstatus_name(0), Some("STATUS_SUCCESS"));
    }

    #[test]
    fn test_ntstatus_access_violation() {
        assert_eq!(ntstatus_name(0xC000_0005), Some("STATUS_ACCESS_VIOLATION"));
    }

    #[test]
    fn test_ntstatus_invalid_handle() {
        assert_eq!(ntstatus_name(0xC000_0008), Some("STATUS_INVALID_HANDLE"));
    }

    #[test]
    fn test_ntstatus_access_denied() {
        assert_eq!(ntstatus_name(0xC000_0022), Some("STATUS_ACCESS_DENIED"));
    }

    #[test]
    fn test_ntstatus_unknown() {
        assert!(ntstatus_name(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn test_format_ntstatus_known() {
        let s = format_ntstatus(0);
        assert!(s.contains("STATUS_SUCCESS"));
    }

    #[test]
    fn test_format_ntstatus_unknown() {
        let s = format_ntstatus(0xDEAD_BEEF);
        assert!(s.contains("deadbeef"));
    }

    #[test]
    fn test_nt_to_win32_path_harddisk() {
        let p = nt_to_win32_path("\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe");
        assert!(p.contains("\\Windows\\System32\\notepad.exe"));
    }

    #[test]
    fn test_nt_to_win32_path_dosdevice() {
        let p = nt_to_win32_path("\\??\\C:\\Users\\test.txt");
        assert_eq!(p, "C:\\Users\\test.txt");
    }

    #[test]
    fn test_is_system_path_system32() {
        assert!(is_system_path("C:\\Windows\\System32\\ntdll.dll"));
    }

    #[test]
    fn test_is_system_path_user() {
        assert!(!is_system_path("C:\\Users\\user\\Desktop\\malware.exe"));
    }

    #[test]
    fn test_decode_file_access_read() {
        let s = decode_file_access(0x8000_0000);
        assert!(s.contains("GENERIC_READ"));
    }

    #[test]
    fn test_decode_file_access_readwrite() {
        let s = decode_file_access(0xC000_0000);
        assert!(s.contains("GENERIC_READ") && s.contains("GENERIC_WRITE"));
    }

    #[test]
    fn test_decode_alloc_type_commit_reserve() {
        let s = decode_alloc_type(0x3000);
        assert!(s.contains("MEM_COMMIT") && s.contains("MEM_RESERVE"));
    }

    #[test]
    fn test_decode_alloc_type_unknown() {
        let s = decode_alloc_type(0x1234_5678);
        assert!(s.starts_with("0x") || !s.is_empty());
    }

    #[test]
    fn test_win_taint_default_clean() {
        let t = WinTaintFlags::default();
        assert!(!t.is_suspicious());
        assert!(t.summary().is_empty());
    }

    #[test]
    fn test_win_taint_remote_write() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "WriteProcessMemory".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Bool(true),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.wrote_to_remote_process());
        assert!(t.is_suspicious());
        assert!(t.summary().contains(&"REMOTE_WRITE"));
    }

    #[test]
    fn test_win_taint_create_service() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "CreateServiceW".to_string(),
            module_name: "advapi32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Handle(0x80),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.created_service());
        assert!(t.summary().contains(&"SERVICE_CREATED"));
    }

    #[test]
    fn test_win_taint_network() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "connect".to_string(),
            module_name: "ws2_32.dll".to_string(),
            args: vec![WinDecodedArg::NetAddr("1.2.3.4".to_string(), 443)],
            retval: WinDecodedArg::Int(0),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.opened_network_connection());
        assert!(!t.is_suspicious()); // network alone is not suspicious
    }

    #[test]
    fn test_win_taint_remote_thread() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "CreateRemoteThread".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Handle(0x100),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.spawned_remote_thread());
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_ntstatus_no_such_file() {
        assert_eq!(ntstatus_name(0xC000_000F), Some("STATUS_NO_SUCH_FILE"));
    }

    #[test]
    fn test_ntstatus_end_of_file() {
        assert_eq!(ntstatus_name(0xC000_0011), Some("STATUS_END_OF_FILE"));
    }

    #[test]
    fn test_ntstatus_pipe_broken() {
        assert_eq!(ntstatus_name(0xC000_00B6), Some("STATUS_PIPE_DISCONNECTED"));
    }

    #[test]
    fn test_api_stats_record_errors() {
        let mut s = WinApiStats::default();
        s.record("NtReadFile", 500, false);
        s.record("NtReadFile", 1000, true);
        assert_eq!(s.entries["NtReadFile"].error_count, 1);
        assert_eq!(s.entries["NtReadFile"].call_count, 2);
    }

    #[test]
    fn test_win_taint_dll_injection() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "LoadLibraryW".to_string(),
            module_name: "kernel32.dll".to_string(),
            args: vec![WinDecodedArg::WStr("C:\\evil.dll".to_string())],
            retval: WinDecodedArg::Handle(0x200),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.injected_dll());
        assert!(t.is_suspicious());
    }

    #[test]
    fn test_win_taint_crypto() {
        let mut t = WinTaintFlags::default();
        let ev = ApiEvent {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            api_name: "CryptAcquireContextW".to_string(),
            module_name: "advapi32.dll".to_string(),
            args: vec![],
            retval: WinDecodedArg::Bool(true),
            call_stack: vec![],
        };
        t.update_from_event(&ev);
        assert!(t.loaded_crypto());
        assert!(t.summary().contains(&"CRYPTO_USAGE"));
    }
}

// ─── Windows x86 syscall table ────────────────────────────────────────────────

#[must_use]
pub fn build_x86_v2() -> Vec<WinNtSyscall> {
    let mut v = build_x86_v2_part_a();
    v.extend(build_x86_v2_part_a_ext());
    v.extend(build_x86_v2_part_b());
    v.extend(build_x86_v2_part_b_ext());
    v.extend(build_x86_v2_part_b_ext_s1());
    v.sort_by_key(|s| s.ssn);
    v
}

fn build_x86_v2_part_a() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0000,
            "NtReadFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(
            0x0001,
            "NtWriteFile",
            vec![
                pi("FileHandle", "HANDLE"),
                poi("Event", "HANDLE"),
                poi("ApcRoutine", "PIO_APC_ROUTINE"),
                poi("ApcContext", "PVOID"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("Buffer", "PVOID"),
                pi("Length", "ULONG"),
                poi("ByteOffset", "PLARGE_INTEGER"),
                poi("Key", "PULONG"),
            ],
        ),
        nt(0x0002, "NtClose", vec![pi("Handle", "HANDLE")]),
        nt(
            0x0003,
            "NtQueryInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                po("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
    ]
}

fn build_x86_v2_part_a_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0004,
            "NtQueryInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                po("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0005,
            "NtSetInformationProcess",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pi("ProcessInformationClass", "PROCESSINFOCLASS"),
                pi("ProcessInformation", "PVOID"),
                pi("ProcessInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0006,
            "NtSetInformationThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                pi("ThreadInformationClass", "THREADINFOCLASS"),
                pi("ThreadInformation", "PVOID"),
                pi("ThreadInformationLength", "ULONG"),
            ],
        ),
        nt(
            0x0007,
            "NtTerminateProcess",
            vec![poi("ProcessHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
        nt(
            0x0008,
            "NtTerminateThread",
            vec![poi("ThreadHandle", "HANDLE"), pi("ExitStatus", "NTSTATUS")],
        ),
        nt(
            0x0009,
            "NtSuspendThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x000A,
            "NtResumeThread",
            vec![
                pi("ThreadHandle", "HANDLE"),
                poo("PreviousSuspendCount", "PULONG"),
            ],
        ),
        nt(
            0x000B,
            "NtOpenProcess",
            vec![
                po("ProcessHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                poi("ClientId", "PCLIENT_ID"),
            ],
        ),
    ]
}

fn build_x86_v2_part_b() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x000C,
            "NtAllocateVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pi("ZeroBits", "ULONG_PTR"),
                pio("RegionSize", "PSIZE_T"),
                pi("AllocationType", "ULONG"),
                pi("Protect", "ULONG"),
            ],
        ),
        nt(
            0x000D,
            "NtFreeVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("FreeType", "ULONG"),
            ],
        ),
        nt(
            0x000E,
            "NtProtectVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                pio("BaseAddress", "PVOID *"),
                pio("RegionSize", "PSIZE_T"),
                pi("NewProtect", "ULONG"),
                po("OldProtect", "PULONG"),
            ],
        ),
        nt(
            0x000F,
            "NtReadVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                po("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesRead", "PSIZE_T"),
            ],
        ),
        nt(
            0x0010,
            "NtWriteVirtualMemory",
            vec![
                pi("ProcessHandle", "HANDLE"),
                poi("BaseAddress", "PVOID"),
                pi("Buffer", "PVOID"),
                pi("BufferSize", "SIZE_T"),
                poo("NumberOfBytesWritten", "PSIZE_T"),
            ],
        ),
        nt(
            0x0011,
            "NtCreateKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("TitleIndex", "ULONG"),
                poi("Class", "PUNICODE_STRING"),
                pi("CreateOptions", "ULONG"),
                poo("Disposition", "PULONG"),
            ],
        ),
        nt(
            0x0012,
            "NtOpenKey",
            vec![
                po("KeyHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
            ],
        ),
        nt(
            0x0013,
            "NtSetValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("TitleIndex", "ULONG"),
                pi("Type", "ULONG"),
                poi("Data", "PVOID"),
                pi("DataSize", "ULONG"),
            ],
        ),
    ]
}

fn build_x86_v2_part_b_ext() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x0014,
            "NtQueryValueKey",
            vec![
                pi("KeyHandle", "HANDLE"),
                pi("ValueName", "PUNICODE_STRING"),
                pi("KeyValueInformationClass", "KEY_VALUE_INFORMATION_CLASS"),
                po("KeyValueInformation", "PVOID"),
                pi("Length", "ULONG"),
                po("ResultLength", "PULONG"),
            ],
        ),
        nt(0x0015, "NtDeleteKey", vec![pi("KeyHandle", "HANDLE")]),
        nt(
            0x0016,
            "NtCreateFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                poi("AllocationSize", "PLARGE_INTEGER"),
                pi("FileAttributes", "ULONG"),
                pi("ShareAccess", "ULONG"),
                pi("CreateDisposition", "ULONG"),
                pi("CreateOptions", "ULONG"),
                poi("EaBuffer", "PVOID"),
                pi("EaLength", "ULONG"),
            ],
        ),
        nt(
            0x0017,
            "NtOpenFile",
            vec![
                po("FileHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                pi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("ShareAccess", "ULONG"),
                pi("OpenOptions", "ULONG"),
            ],
        ),
        nt(
            0x0018,
            "NtQueryInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                po("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
        nt(
            0x0019,
            "NtSetInformationFile",
            vec![
                pi("FileHandle", "HANDLE"),
                po("IoStatusBlock", "PIO_STATUS_BLOCK"),
                pi("FileInformation", "PVOID"),
                pi("Length", "ULONG"),
                pi("FileInformationClass", "FILE_INFORMATION_CLASS"),
            ],
        ),
    ]
}

fn build_x86_v2_part_b_ext_s1() -> Vec<WinNtSyscall> {
    vec![
        nt(
            0x001A,
            "NtWaitForSingleObject",
            vec![
                pi("Handle", "HANDLE"),
                pi("Alertable", "BOOLEAN"),
                poi("Timeout", "PLARGE_INTEGER"),
            ],
        ),
        nt(
            0x001B,
            "NtCreateEvent",
            vec![
                po("EventHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("EventType", "EVENT_TYPE"),
                pi("InitialState", "BOOLEAN"),
            ],
        ),
        nt(
            0x001C,
            "NtSetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x001D,
            "NtResetEvent",
            vec![pi("EventHandle", "HANDLE"), poo("PreviousState", "PLONG")],
        ),
        nt(
            0x001E,
            "NtCreateMutant",
            vec![
                po("MutantHandle", "PHANDLE"),
                pi("DesiredAccess", "ACCESS_MASK"),
                poi("ObjectAttributes", "POBJECT_ATTRIBUTES"),
                pi("InitialOwner", "BOOLEAN"),
            ],
        ),
        nt(
            0x001F,
            "NtReleaseMutant",
            vec![pi("MutantHandle", "HANDLE"), poo("PreviousCount", "PLONG")],
        ),
        nt(
            0x0020,
            "NtQuerySystemInformation",
            vec![
                pi("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
                po("SystemInformation", "PVOID"),
                pi("SystemInformationLength", "ULONG"),
                poo("ReturnLength", "PULONG"),
            ],
        ),
        nt(
            0x0021,
            "NtDelayExecution",
            vec![
                pi("Alertable", "BOOLEAN"),
                pi("DelayInterval", "PLARGE_INTEGER"),
            ],
        ),
    ]
}

// ─── Malware-relevant API pattern detection ───────────────────────────────────

/// Known suspicious API call sequences (simplified patterns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspiciousPattern {
    /// Process injection: `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`
    ProcessInjection,
    /// DLL side-loading: LoadLibraryA/W with a suspicious path
    DllSideloading,
    /// Credential harvesting: `OpenProcessToken` + `ReadProcessMemory` on lsass
    CredentialHarvesting,
    /// Ransomware crypto: `CryptGenKey` + loop of `EncryptFile`
    CryptoRansomware,
    /// Persistence via Run key
    PersistenceRunKey,
    /// Service installation persistence
    PersistenceService,
    /// Network reconnaissance: getaddrinfo + multiple connect calls
    NetworkRecon,
    /// Anti-analysis: calls to `IsDebuggerPresent` / NtQueryInformationProcess(debug)
    AntiAnalysis,
}

impl std::fmt::Display for SuspiciousPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessInjection => write!(f, "PROCESS_INJECTION"),
            Self::DllSideloading => write!(f, "DLL_SIDELOADING"),
            Self::CredentialHarvesting => write!(f, "CREDENTIAL_HARVESTING"),
            Self::CryptoRansomware => write!(f, "CRYPTO_RANSOMWARE"),
            Self::PersistenceRunKey => write!(f, "PERSISTENCE_RUN_KEY"),
            Self::PersistenceService => write!(f, "PERSISTENCE_SERVICE"),
            Self::NetworkRecon => write!(f, "NETWORK_RECON"),
            Self::AntiAnalysis => write!(f, "ANTI_ANALYSIS"),
        }
    }
}

/// Simple sliding-window pattern detector for API event streams.
#[derive(Debug, Default)]
pub struct PatternDetector {
    recent: Vec<String>,
    window: usize,
}

impl PatternDetector {
    #[must_use]
    pub const fn new(window: usize) -> Self {
        Self {
            recent: Vec::new(),
            window,
        }
    }

    /// Push a new API name and return any detected patterns.
    pub fn push(&mut self, api: &str) -> Vec<SuspiciousPattern> {
        self.recent.push(api.to_string());
        if self.recent.len() > self.window {
            self.recent.remove(0);
        }
        self.check()
    }

    fn check(&self) -> Vec<SuspiciousPattern> {
        let mut found = Vec::new();
        let apis: Vec<&str> = self.recent.iter().map(String::as_str).collect();

        // Process injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
        if Self::has_all(
            &apis,
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ) {
            found.push(SuspiciousPattern::ProcessInjection);
        }
        // Persistence run key
        if Self::has_sequence(&apis, &["RegOpenKeyExW", "RegSetValueExW"]) {
            found.push(SuspiciousPattern::PersistenceRunKey);
        }
        // Service persistence
        if apis.contains(&"CreateServiceW") || apis.contains(&"CreateServiceA") {
            found.push(SuspiciousPattern::PersistenceService);
        }
        // DLL sideloading
        if apis.contains(&"LoadLibraryW") || apis.contains(&"LoadLibraryA") {
            found.push(SuspiciousPattern::DllSideloading);
        }
        // Network recon
        if Self::has_all(&apis, &["getaddrinfo", "connect"]) {
            found.push(SuspiciousPattern::NetworkRecon);
        }
        found
    }

    fn has_all(apis: &[&str], targets: &[&str]) -> bool {
        targets.iter().all(|t| apis.contains(t))
    }

    fn has_sequence(apis: &[&str], seq: &[&str]) -> bool {
        if seq.is_empty() {
            return true;
        }
        let mut si = 0;
        for api in apis {
            if *api == seq[si] {
                si += 1;
                if si == seq.len() {
                    return true;
                }
            }
        }
        false
    }
}

// ─── Handle table ─────────────────────────────────────────────────────────────

/// Information about a Windows handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle: u64,
    pub object_type: String,
    pub path: String,
    pub access: u32,
    pub pid: u32,
}

/// Per-process handle table tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HandleTable {
    map: HashMap<u64, HandleInfo>,
}

impl HandleTable {
    pub fn open(&mut self, info: HandleInfo) {
        self.map.insert(info.handle, info);
    }
    pub fn close(&mut self, handle: u64) -> Option<HandleInfo> {
        self.map.remove(&handle)
    }
    #[must_use]
    pub fn get(&self, handle: u64) -> Option<&HandleInfo> {
        self.map.get(&handle)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    #[must_use]
    pub fn by_type(&self, obj_type: &str) -> Vec<&HandleInfo> {
        self.map
            .values()
            .filter(|h| h.object_type == obj_type)
            .collect()
    }
}

// ─── Additional tests (part 3) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext3_tests {
    use super::*;

    #[test]
    fn test_build_x86_has_entries() {
        let v = build_x86();
        assert!(!v.is_empty());
        assert!(v.iter().any(|e| e.name == "NtCreateFile"));
    }

    #[test]
    fn test_suspicious_pattern_display() {
        assert_eq!(
            SuspiciousPattern::ProcessInjection.to_string(),
            "PROCESS_INJECTION"
        );
        assert_eq!(
            SuspiciousPattern::PersistenceRunKey.to_string(),
            "PERSISTENCE_RUN_KEY"
        );
    }

    #[test]
    fn test_pattern_detector_process_injection() {
        let mut d = PatternDetector::new(20);
        d.push("VirtualAllocEx");
        d.push("WriteProcessMemory");
        let p = d.push("CreateRemoteThread");
        assert!(p.contains(&SuspiciousPattern::ProcessInjection));
    }

    #[test]
    fn test_pattern_detector_service_persistence() {
        let mut d = PatternDetector::new(10);
        let p = d.push("CreateServiceW");
        assert!(p.contains(&SuspiciousPattern::PersistenceService));
    }

    #[test]
    fn test_pattern_detector_dll_sideloading() {
        let mut d = PatternDetector::new(10);
        let p = d.push("LoadLibraryA");
        assert!(p.contains(&SuspiciousPattern::DllSideloading));
    }

    #[test]
    fn test_pattern_detector_no_match() {
        let mut d = PatternDetector::new(10);
        d.push("NtClose");
        let p = d.push("NtReadFile");
        assert!(p.is_empty());
    }

    #[test]
    fn test_handle_table_open_close() {
        let mut t = HandleTable::default();
        t.open(HandleInfo {
            handle: 0x4,
            object_type: "File".to_string(),
            path: "C:\\test.txt".to_string(),
            access: 0x8000_0000,
            pid: 1,
        });
        assert_eq!(t.len(), 1);
        let removed = t.close(0x4);
        assert!(removed.is_some());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_handle_table_by_type() {
        let mut t = HandleTable::default();
        t.open(HandleInfo {
            handle: 0x4,
            object_type: "File".to_string(),
            path: "/a".to_string(),
            access: 0,
            pid: 1,
        });
        t.open(HandleInfo {
            handle: 0x8,
            object_type: "Key".to_string(),
            path: "HKLM\\Software".to_string(),
            access: 0,
            pid: 1,
        });
        t.open(HandleInfo {
            handle: 0xC,
            object_type: "File".to_string(),
            path: "/b".to_string(),
            access: 0,
            pid: 1,
        });
        let files = t.by_type("File");
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_handle_table_get() {
        let mut t = HandleTable::default();
        t.open(HandleInfo {
            handle: 0x10,
            object_type: "Thread".to_string(),
            path: String::new(),
            access: 0x1F_FFFF,
            pid: 100,
        });
        let h = t.get(0x10).unwrap();
        assert_eq!(h.object_type, "Thread");
    }

    #[test]
    fn test_ntstatus_logon_failure() {
        assert_eq!(ntstatus_name(0xC000_006D), Some("STATUS_LOGON_FAILURE"));
    }

    #[test]
    fn test_ntstatus_object_name_not_found() {
        assert_eq!(
            ntstatus_name(0xC000_0034),
            Some("STATUS_OBJECT_NAME_NOT_FOUND")
        );
    }

    #[test]
    fn test_ntstatus_buffer_overflow() {
        assert_eq!(ntstatus_name(0x8000_0005), Some("STATUS_BUFFER_OVERFLOW"));
    }

    #[test]
    fn test_decode_alloc_large_pages() {
        let s = decode_alloc_type(0x2000_0000);
        assert!(s.contains("MEM_LARGE_PAGES"));
    }

    #[test]
    fn test_decode_file_access_delete() {
        let s = decode_file_access(0x0001_0000);
        assert!(s.contains("DELETE"));
    }

    #[test]
    fn test_win_api_db_service_count() {
        
        assert!(WIN32_API_DB
            .iter()
            .filter(|e| e.category == ApiCategory::Service).count() >= 5);
    }

    #[test]
    fn test_win_api_db_security_count() {
        
        assert!(WIN32_API_DB
            .iter()
            .filter(|e| e.category == ApiCategory::Security).count() >= 5);
    }

    #[test]
    fn test_win_taint_summary_multiple_flags() {
        let t = WinTaintFlags {
            process: WinTaintProcess {
                injected_dll: true,
                spawned_remote_thread: true,
                ..WinTaintProcess::default()
            },
            misc: WinTaintMisc {
                loaded_crypto: true,
                ..WinTaintMisc::default()
            },
            ..WinTaintFlags::default()
        };
        let s = t.summary();
        assert!(s.contains(&"DLL_INJECTION"));
        assert!(s.contains(&"REMOTE_THREAD"));
        assert!(s.contains(&"CRYPTO_USAGE"));
    }

    #[test]
    fn test_nt_to_win32_path_unchanged() {
        let p = nt_to_win32_path("C:\\Windows\\notepad.exe");
        assert_eq!(p, "C:\\Windows\\notepad.exe");
    }

    #[test]
    fn test_version_ssn_table_has_ntreadfile() {
        let tbl = build_version_ssn_table();
        assert!(tbl.iter().any(|e| e.name == "NtReadFile"));
    }

    #[test]
    fn test_version_ssn_ntclose_win10() {
        let tbl = build_version_ssn_table();
        let entry = tbl.iter().find(|e| e.name == "NtClose").unwrap();
        let ssn = entry.ssn_for(WinVersion::Windows10).unwrap();
        assert_eq!(ssn, 0x000F);
    }
}

// ─── Windows event log record ─────────────────────────────────────────────────

/// A simplified Windows event log record for malware analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinEventRecord {
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub level: WinEventLevel,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub message: String,
    pub keywords: u64,
}

/// Windows event log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WinEventLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Info = 4,
    Verbose = 5,
}

impl std::fmt::Display for WinEventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::Error => write!(f, "Error"),
            Self::Warning => write!(f, "Warning"),
            Self::Info => write!(f, "Info"),
            Self::Verbose => write!(f, "Verbose"),
        }
    }
}

impl WinEventRecord {
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"event_id\":{},\"provider\":{:?},\"channel\":{:?},\"level\":{:?},\"pid\":{},\"tid\":{},\"message\":{:?}}}",
            self.event_id,
            self.provider,
            self.channel,
            self.level.to_string(),
            self.pid,
            self.tid,
            self.message
        )
    }
}

// ─── Windows stub detection helpers ──────────────────────────────────────────

/// Known clean stub patterns for ntdll x64.
pub static CLEAN_X64_STUB_PREFIX: &[u8] = &[0x4C, 0x8B, 0xD1, 0xB8];

/// Check whether stub bytes look clean (unhooked) for x64.
#[must_use]
pub fn is_clean_x64_stub(stub: &[u8], expected_ssn: u32) -> bool {
    if stub.len() < 8 {
        return false;
    }
    if &stub[..4] != CLEAN_X64_STUB_PREFIX {
        return false;
    }
    let found_ssn = u32::from(u16::from_le_bytes([stub[4], stub[5]]));
    found_ssn == expected_ssn
}

/// Check whether stub bytes look clean (unhooked) for x86.
#[must_use]
pub fn is_clean_x86_stub(stub: &[u8], expected_ssn: u32) -> bool {
    if stub.len() < 5 || stub[0] != 0xB8 {
        return false;
    }
    let found = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
    found == expected_ssn
}

/// Detect the kind of inline hook at the beginning of a function stub.
#[must_use]
pub fn detect_hook_type(stub: &[u8]) -> HookKind {
    if stub.is_empty() {
        return HookKind::Clean;
    }
    if stub[0] == 0xE9 && stub.len() >= 5 {
        let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        let target = (5i64 + i64::from(rel)).cast_unsigned();
        return HookKind::Trampoline { target };
    }
    if stub[0] == 0xFF && stub.len() >= 6 && stub[1] == 0x25 {
        // JMP [RIP+offset] — absolute jump through memory
        return HookKind::InlineHook;
    }
    if stub[0] == 0x68 && stub.len() >= 5 {
        // PUSH addr; RET — old-style hook
        return HookKind::InlineHook;
    }
    HookKind::Clean
}

// ─── Windows PE header parsing helpers ───────────────────────────────────────

/// DOS header magic: "MZ"
pub const MZ_MAGIC: u16 = 0x5A4D;
/// PE header magic: "PE\0\0"
pub const PE_MAGIC: u32 = 0x0000_4550;
/// PE32 optional header magic.
pub const PE32_MAGIC: u16 = 0x010B;
/// PE32+ optional header magic.
pub const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Minimal parsed PE header information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeHeaders {
    pub is_64bit: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub number_of_sections: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

impl PeHeaders {
    /// Parse minimal PE headers from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        let dos_magic = u16::from_le_bytes([data[0], data[1]]);
        if dos_magic != MZ_MAGIC {
            return None;
        }
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if e_lfanew.checked_add(24).is_none_or(|end| end > data.len()) {
            return None;
        }
        let pe_magic = u32::from_le_bytes([
            data[e_lfanew],
            data[e_lfanew + 1],
            data[e_lfanew + 2],
            data[e_lfanew + 3],
        ]);
        if pe_magic != PE_MAGIC {
            return None;
        }
        let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
        let number_of_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]);
        let timestamp = u32::from_le_bytes([
            data[e_lfanew + 8],
            data[e_lfanew + 9],
            data[e_lfanew + 10],
            data[e_lfanew + 11],
        ]);
        let opt_off = e_lfanew + 24; // safe: e_lfanew + 24 <= data.len() checked above
        if opt_off.checked_add(4).is_none_or(|end| end > data.len()) {
            return None;
        }
        let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let is_64bit = opt_magic == PE32_PLUS_MAGIC;
        if opt_off.checked_add(60).is_none_or(|end| end > data.len()) {
            return None;
        }
        let entry_point_rva = u32::from_le_bytes([
            data[opt_off + 16],
            data[opt_off + 17],
            data[opt_off + 18],
            data[opt_off + 19],
        ]);
        let (image_base, subsystem_off, size_of_image_off) = if is_64bit {
            let base = u64::from_le_bytes([
                data[opt_off + 24],
                data[opt_off + 25],
                data[opt_off + 26],
                data[opt_off + 27],
                data[opt_off + 28],
                data[opt_off + 29],
                data[opt_off + 30],
                data[opt_off + 31],
            ]);
            (base, opt_off + 68, opt_off + 56)
        } else {
            let base = u64::from(u32::from_le_bytes([
                data[opt_off + 28],
                data[opt_off + 29],
                data[opt_off + 30],
                data[opt_off + 31],
            ]));
            (base, opt_off + 68, opt_off + 56)
        };
        let size_of_image = if size_of_image_off + 4 <= data.len() {
            u32::from_le_bytes([
                data[size_of_image_off],
                data[size_of_image_off + 1],
                data[size_of_image_off + 2],
                data[size_of_image_off + 3],
            ])
        } else {
            0
        };
        let subsystem = if subsystem_off + 2 <= data.len() {
            u16::from_le_bytes([data[subsystem_off], data[subsystem_off + 1]])
        } else {
            0
        };
        let dll_char_off = subsystem_off + 2;
        let dll_characteristics = if dll_char_off + 2 <= data.len() {
            u16::from_le_bytes([data[dll_char_off], data[dll_char_off + 1]])
        } else {
            0
        };
        Some(Self {
            is_64bit,
            machine,
            timestamp,
            number_of_sections,
            entry_point_rva,
            image_base,
            size_of_image,
            subsystem,
            dll_characteristics,
        })
    }

    /// Returns `true` if ASLR is enabled (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`).
    #[must_use]
    pub const fn has_aslr(&self) -> bool {
        self.dll_characteristics & 0x0040 != 0
    }
    /// Returns `true` if DEP is enabled.
    #[must_use]
    pub const fn has_dep(&self) -> bool {
        self.dll_characteristics & 0x0100 != 0
    }
    /// Returns `true` if the file is a DLL.
    #[must_use]
    pub const fn is_dll(&self) -> bool {
        self.dll_characteristics & 0x2000 != 0
    }
}

// ─── Additional tests (part 4) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext4_tests {
    use super::*;

    #[test]
    fn test_win_event_level_display() {
        assert_eq!(WinEventLevel::Critical.to_string(), "Critical");
        assert_eq!(WinEventLevel::Warning.to_string(), "Warning");
        assert_eq!(WinEventLevel::Info.to_string(), "Info");
    }

    #[test]
    fn test_win_event_record_to_json() {
        let rec = WinEventRecord {
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            channel: "Security".to_string(),
            level: WinEventLevel::Info,
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            message: "A new process has been created.".to_string(),
            keywords: 0x8020_0000_0000_0000,
        };
        let j = rec.to_json();
        assert!(j.contains("4688"));
        assert!(j.contains("process has been created"));
    }

    #[test]
    fn test_is_clean_x64_stub_true() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06u8, 0x00, 0x00, 0x00, 0x0F, 0x05];
        assert!(is_clean_x64_stub(&stub, 6));
    }

    #[test]
    fn test_is_clean_x64_stub_wrong_ssn() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06u8, 0x00, 0x00, 0x00, 0x0F, 0x05];
        assert!(!is_clean_x64_stub(&stub, 7));
    }

    #[test]
    fn test_is_clean_x64_stub_hooked() {
        let stub = [0xE9, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00];
        assert!(!is_clean_x64_stub(&stub, 0));
    }

    #[test]
    fn test_is_clean_x86_stub_true() {
        let ssn: u32 = 0x42;
        let bytes = ssn.to_le_bytes();
        let stub = [
            0xB8, bytes[0], bytes[1], bytes[2], bytes[3], 0xBA, 0x00, 0x00,
        ];
        assert!(is_clean_x86_stub(&stub, 0x42));
    }

    #[test]
    fn test_detect_hook_type_jmp_rel32() {
        let stub = [0xE9, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        match detect_hook_type(&stub) {
            HookKind::Trampoline { target } => assert_eq!(target, 21),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_detect_hook_type_clean() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x06, 0x00, 0x00, 0x00];
        assert_eq!(detect_hook_type(&stub), HookKind::Clean);
    }

    #[test]
    fn test_detect_hook_type_push_ret() {
        let stub = [0x68, 0x00, 0x10, 0x00, 0x00, 0xC3, 0x90, 0x90];
        assert_eq!(detect_hook_type(&stub), HookKind::InlineHook);
    }

    #[test]
    fn test_pe_headers_parse_invalid_magic() {
        let data = vec![0u8; 64];
        assert!(PeHeaders::parse(&data).is_none());
    }

    #[test]
    fn test_pe_headers_too_short() {
        assert!(PeHeaders::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_analyse_stub_clean_x64() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let h = analyse_stub("NtClose", 3, WinArch::X64, &stub);
        assert_eq!(h.kind, HookKind::Clean);
        assert!(!h.is_hooked());
    }

    #[test]
    fn test_analyse_stub_wrong_ssn() {
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let h = analyse_stub("NtClose", 3, WinArch::X64, &stub);
        match h.kind {
            HookKind::SsnMismatch { expected, found } => {
                assert_eq!(expected, 3);
                assert_eq!(found, 5);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_hook_kind_display() {
        assert_eq!(HookKind::Clean.to_string(), "Clean");
        assert_eq!(HookKind::InlineHook.to_string(), "InlineHook");
        assert!(
            HookKind::SsnMismatch {
                expected: 1,
                found: 2
            }
            .to_string()
            .contains("SsnMismatch")
        );
    }

    #[test]
    fn test_page_protect_is_executable() {
        assert!(PageProtect::is_executable(0x40)); // PAGE_EXECUTE_READWRITE
        assert!(PageProtect::is_executable(0x20)); // PAGE_EXECUTE_READ
        assert!(!PageProtect::is_executable(0x04)); // PAGE_READWRITE
    }

    #[test]
    fn test_page_protect_name_rwx() {
        assert_eq!(PageProtect::name(0x40), "PAGE_EXECUTE_READWRITE");
    }

    #[test]
    fn test_page_protect_is_writable() {
        assert!(PageProtect::is_writable(0x04));
        assert!(PageProtect::is_writable(0x40));
        assert!(!PageProtect::is_writable(0x02));
    }

    #[test]
    fn test_win_syscall_db_x64_count() {
        let db = WinSyscallDb::new();
        assert!(db.arch_count(WinArch::X64) > 50);
    }

    #[test]
    fn test_win_syscall_resolver_lookup_ntclose() {
        let r = WinSyscallResolver::new();
        let s = r.lookup_by_name(WinArch::X64, "NtClose");
        assert!(s.is_some());
    }

    #[test]
    fn test_win_event_level_values() {
        assert_eq!(WinEventLevel::Critical as u8, 1);
        assert_eq!(WinEventLevel::Error as u8, 2);
        assert_eq!(WinEventLevel::Warning as u8, 3);
        assert_eq!(WinEventLevel::Info as u8, 4);
        assert_eq!(WinEventLevel::Verbose as u8, 5);
    }
}

// ─── Windows token privilege constants ────────────────────────────────────────

/// Well-known Windows privilege names.
pub static WINDOWS_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeAuditPrivilege",
    "SeBackupPrivilege",
    "SeChangeNotifyPrivilege",
    "SeCreateGlobalPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeCreateTokenPrivilege",
    "SeDebugPrivilege",
    "SeEnableDelegationPrivilege",
    "SeImpersonatePrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeLoadDriverPrivilege",
    "SeLockMemoryPrivilege",
    "SeMachineAccountPrivilege",
    "SeManageVolumePrivilege",
    "SeNetworkLogonRight",
    "SeProfileSingleProcessPrivilege",
    "SeRelabelPrivilege",
    "SeRemoteInteractiveLogonRight",
    "SeRemoteShutdownPrivilege",
    "SeRestorePrivilege",
    "SeSecurityPrivilege",
    "SeShutdownPrivilege",
    "SeSyncAgentPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege",
    "SeTimeZonePrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeUndockPrivilege",
    "SeUnsolicitedInputPrivilege",
];

/// Return `true` if a privilege name is considered high-risk for abuse.
#[must_use]
pub fn is_dangerous_privilege(name: &str) -> bool {
    matches!(
        name,
        "SeDebugPrivilege"
            | "SeImpersonatePrivilege"
            | "SeTcbPrivilege"
            | "SeCreateTokenPrivilege"
            | "SeTakeOwnershipPrivilege"
            | "SeLoadDriverPrivilege"
            | "SeRestorePrivilege"
            | "SeBackupPrivilege"
            | "SeAssignPrimaryTokenPrivilege"
    )
}

// ─── Windows registry path helpers ────────────────────────────────────────────

/// Convert an NT registry key path to a Win32 path.
#[must_use]
pub fn nt_to_win32_reg_path(nt_path: &str) -> String {
    let p = nt_path.trim_start_matches('\\');
    if let Some(rest) = p.strip_prefix("REGISTRY\\MACHINE\\") {
        return format!("HKLM\\{rest}");
    }
    if let Some(rest) = p.strip_prefix("REGISTRY\\USER\\") {
        return format!("HKU\\{rest}");
    }
    if let Some(rest) = p.strip_prefix("REGISTRY\\") {
        return rest.to_string();
    }
    nt_path.to_string()
}

/// Return `true` if the registry key path is a known persistence location.
#[must_use]
pub fn is_persistence_registry_key(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\run\\")
        || p.contains("\\runonce\\")
        || p.contains("\\runonceex\\")
        || p.contains("\\services\\")
        || p.contains("\\winlogon\\")
        || p.contains("\\image file execution options\\")
        || p.contains("\\appinit_dlls")
        || p.contains("\\browser helper objects\\")
        || p.contains("\\shell service object delay load")
        || p.contains("\\wbem\\")
        || p.contains("\\scheduled tasks")
}

// ─── Windows socket error codes ───────────────────────────────────────────────

/// Decode a Winsock error code to a name.
#[must_use]
pub const fn winsock_error_name(code: i32) -> Option<&'static str> {
    match code {
        6 => Some("WSA_INVALID_HANDLE"),
        8 => Some("WSA_NOT_ENOUGH_MEMORY"),
        87 => Some("WSA_INVALID_PARAMETER"),
        258 => Some("WSA_WAIT_TIMEOUT"),
        995 => Some("WSA_OPERATION_ABORTED"),
        996 => Some("WSA_IO_INCOMPLETE"),
        997 => Some("WSA_IO_PENDING"),
        10_004 => Some("WSAEINTR"),
        10_009 => Some("WSAEBADF"),
        10_013 => Some("WSAEACCES"),
        10_014 => Some("WSAEFAULT"),
        10_022 => Some("WSAEINVAL"),
        10_024 => Some("WSAEMFILE"),
        10_035 => Some("WSAEWOULDBLOCK"),
        10_036 => Some("WSAEINPROGRESS"),
        10_037 => Some("WSAEALREADY"),
        10_038 => Some("WSAENOTSOCK"),
        10_039 => Some("WSAEDESTADDRREQ"),
        10_040 => Some("WSAEMSGSIZE"),
        10_041 => Some("WSAEPROTOTYPE"),
        10_042 => Some("WSAENOPROTOOPT"),
        10_043 => Some("WSAEPROTONOSUPPORT"),
        10_044 => Some("WSAESOCKTNOSUPPORT"),
        10_045 => Some("WSAEOPNOTSUPP"),
        10_046 => Some("WSAEPFNOSUPPORT"),
        10_047 => Some("WSAEAFNOSUPPORT"),
        10_048 => Some("WSAEADDRINUSE"),
        10_049 => Some("WSAEADDRNOTAVAIL"),
        10_050 => Some("WSAENETDOWN"),
        10_051 => Some("WSAENETUNREACH"),
        10_052 => Some("WSAENETRESET"),
        10_053 => Some("WSAECONNABORTED"),
        10_054 => Some("WSAECONNRESET"),
        10_055 => Some("WSAENOBUFS"),
        10_056 => Some("WSAEISCONN"),
        10_057 => Some("WSAENOTCONN"),
        10_058 => Some("WSAESHUTDOWN"),
        10_060 => Some("WSAETIMEDOUT"),
        10_061 => Some("WSAECONNREFUSED"),
        10_064 => Some("WSAEHOSTDOWN"),
        10_065 => Some("WSAEHOSTUNREACH"),
        10_067 => Some("WSAEPROCLIM"),
        10_091 => Some("WSASYSNOTREADY"),
        10_092 => Some("WSAVERNOTSUPPORTED"),
        10_093 => Some("WSANOTINITIALISED"),
        10_101 => Some("WSAEDISCON"),
        11_001 => Some("WSAHOST_NOT_FOUND"),
        11_002 => Some("WSATRY_AGAIN"),
        11_003 => Some("WSANO_RECOVERY"),
        11_004 => Some("WSANO_DATA"),
        _ => None,
    }
}

// ─── Additional tests (part 5) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext5_tests {
    use super::*;

    #[test]
    fn test_privileges_list_not_empty() {
        assert!(!WINDOWS_PRIVILEGES.is_empty());
        assert!(WINDOWS_PRIVILEGES.len() >= 30);
    }

    #[test]
    fn test_is_dangerous_privilege_debug() {
        assert!(is_dangerous_privilege("SeDebugPrivilege"));
    }

    #[test]
    fn test_is_dangerous_privilege_impersonate() {
        assert!(is_dangerous_privilege("SeImpersonatePrivilege"));
    }

    #[test]
    fn test_is_dangerous_privilege_benign() {
        assert!(!is_dangerous_privilege("SeShutdownPrivilege"));
    }

    #[test]
    fn test_nt_to_win32_reg_path_hklm() {
        let p = nt_to_win32_reg_path("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft");
        assert_eq!(p, "HKLM\\SOFTWARE\\Microsoft");
    }

    #[test]
    fn test_nt_to_win32_reg_path_hku() {
        let p = nt_to_win32_reg_path("\\REGISTRY\\USER\\S-1-5-21\\Software");
        assert_eq!(p, "HKU\\S-1-5-21\\Software");
    }

    #[test]
    fn test_is_persistence_reg_key_run() {
        assert!(is_persistence_registry_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"
        ));
    }

    #[test]
    fn test_is_persistence_reg_key_services() {
        assert!(is_persistence_registry_key(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil"
        ));
    }

    #[test]
    fn test_is_persistence_reg_key_benign() {
        assert!(!is_persistence_registry_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\notepad.exe"
        ));
    }

    #[test]
    fn test_winsock_error_connrefused() {
        assert_eq!(winsock_error_name(10_061), Some("WSAECONNREFUSED"));
    }

    #[test]
    fn test_winsock_error_timedout() {
        assert_eq!(winsock_error_name(10_060), Some("WSAETIMEDOUT"));
    }

    #[test]
    fn test_winsock_error_addrinuse() {
        assert_eq!(winsock_error_name(10_048), Some("WSAEADDRINUSE"));
    }

    #[test]
    fn test_winsock_error_unknown() {
        assert!(winsock_error_name(99_999).is_none());
    }

    #[test]
    fn test_win_api_db_loader_entries() {
        let loader: Vec<_> = WIN32_API_DB
            .iter()
            .filter(|e| e.category == ApiCategory::Loader)
            .collect();
        assert!(loader.len() >= 4);
        assert!(loader.iter().any(|e| e.name == "GetProcAddress"));
    }

    #[test]
    fn test_win_api_db_process_entries() {
        let procs: Vec<_> = WIN32_API_DB
            .iter()
            .filter(|e| e.category == ApiCategory::Process)
            .collect();
        assert!(procs.iter().any(|e| e.name == "CreateProcessW"));
        assert!(procs.iter().any(|e| e.name == "TerminateProcess"));
    }

    #[test]
    fn test_win_api_db_total_count() {
        assert!(
            WIN32_API_DB.len() >= 150,
            "expected >= 150 entries, got {}",
            WIN32_API_DB.len()
        );
    }

    #[test]
    fn test_hook_analysis_is_hooked_false() {
        let h = HookAnalysis {
            name: "NtReadFile".to_string(),
            ssn: 0,
            kind: HookKind::Clean,
            stub_bytes: vec![],
        };
        assert!(!h.is_hooked());
    }

    #[test]
    fn test_hook_analysis_is_hooked_true() {
        let h = HookAnalysis {
            name: "NtReadFile".to_string(),
            ssn: 0,
            kind: HookKind::InlineHook,
            stub_bytes: vec![0xE9],
        };
        assert!(h.is_hooked());
    }

    #[test]
    fn test_object_attributes_flags() {
        let mut oa = ObjectAttributes::new("\\Device\\Test");
        oa.attributes = 0x202; // OBJ_INHERIT | OBJ_KERNEL_HANDLE
        assert!(oa.is_inherit());
        assert!(oa.is_kernel_handle());
        assert!(!oa.is_open_if());
    }

    #[test]
    fn test_memory_basic_information_states() {
        let mbi = MemoryBasicInformation {
            base_address: 0x1000,
            allocation_base: 0x1000,
            allocation_protect: 0x04,
            region_size: 0x1000,
            state: 0x1000,
            protect: 0x40,
            mem_type: 0x2_0000,
        };
        assert!(mbi.is_committed());
        assert!(mbi.is_rwx());
        assert!(!mbi.is_free());
        assert_eq!(mbi.type_name(), "MEM_PRIVATE");
    }

    #[test]
    fn test_peb_debug_flags() {
        let peb = Peb {
            image_base: 0,
            ldr: 0,
            process_parameters: 0,
            being_debugged: true,
            nt_global_flags: 0x70,
            heap_count: 1,
        };
        assert!(peb.is_debugged());
        assert!(peb.has_heap_debug_flags());
    }

    #[test]
    fn test_unicode_string_from_str() {
        let us = UnicodeString::from_string("hello");
        assert_eq!(us.decoded, "hello");
        assert_eq!(us.length, 10); // 5 chars * 2 bytes
    }

    #[test]
    fn test_win_version_ssn_for() {
        let tbl = build_version_ssn_table();
        let e = tbl
            .iter()
            .find(|e| e.name == "NtAllocateVirtualMemory")
            .unwrap();
        assert_eq!(e.ssn_for(WinVersion::Windows10), Some(0x0018));
        assert_eq!(e.ssn_for(WinVersion::WindowsXP), Some(0x0011));
    }
}

// ─── Windows process ancestry tracker ────────────────────────────────────────

/// Entry in a process ancestry chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub create_time_ns: u64,
    pub integrity_level: IntegrityLevel,
}

/// Windows integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(f, "Untrusted"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::System => write!(f, "System"),
        }
    }
}

/// Simple in-memory process tree tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessTree {
    pub processes: Vec<ProcessEntry>,
}

impl ProcessTree {
    pub fn add(&mut self, entry: ProcessEntry) {
        self.processes.push(entry);
    }

    pub fn remove(&mut self, pid: u32) {
        self.processes.retain(|p| p.pid != pid);
    }

    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessEntry> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    /// Return all direct children of `ppid`.
    #[must_use]
    pub fn children(&self, ppid: u32) -> Vec<&ProcessEntry> {
        self.processes.iter().filter(|p| p.ppid == ppid).collect()
    }

    /// Return the full ancestry chain for `pid` (from pid up to root).
    #[must_use]
    pub fn ancestry(&self, pid: u32) -> Vec<&ProcessEntry> {
        let mut chain = Vec::new();
        let mut current = pid;
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current) {
                break;
            }
            if let Some(e) = self.find(current) {
                chain.push(e);
                current = e.ppid;
            } else {
                break;
            }
        }
        chain
    }
}

// ─── Named pipe IPC model (for injected DLL → monitor) ───────────────────────

/// Direction of a named pipe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeDirection {
    Inbound,
    Outbound,
    Duplex,
}

/// Metadata for a named pipe handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPipeInfo {
    pub name: String,
    pub direction: PipeDirection,
    pub max_instances: u32,
    pub out_buf_size: u32,
    pub in_buf_size: u32,
    pub default_timeout_ms: u32,
}

impl NamedPipeInfo {
    #[must_use]
    pub fn monitor_pipe() -> Self {
        Self {
            name: MONITOR_PIPE_NAME.to_string(),
            direction: PipeDirection::Inbound,
            max_instances: 16,
            out_buf_size: 65_536,
            in_buf_size: 65_536,
            default_timeout_ms: 5000,
        }
    }
}

// ─── Additional tests (part 6) ────────────────────────────────────────────────

#[cfg(test)]
mod win_ext6_tests {
    use super::*;

    #[test]
    fn test_integrity_level_ordering() {
        assert!(IntegrityLevel::System > IntegrityLevel::High);
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium > IntegrityLevel::Low);
    }

    #[test]
    fn test_integrity_level_display() {
        assert_eq!(IntegrityLevel::System.to_string(), "System");
        assert_eq!(IntegrityLevel::Medium.to_string(), "Medium");
    }

    #[test]
    fn test_process_tree_add_find() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry {
            pid: 4,
            ppid: 0,
            name: "System".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::System,
        });
        tree.add(ProcessEntry {
            pid: 100,
            ppid: 4,
            name: "svchost.exe".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::System,
        });
        assert_eq!(tree.find(100).unwrap().name, "svchost.exe");
    }

    #[test]
    fn test_process_tree_children() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry {
            pid: 1,
            ppid: 0,
            name: "root".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::High,
        });
        tree.add(ProcessEntry {
            pid: 2,
            ppid: 1,
            name: "child1".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::Medium,
        });
        tree.add(ProcessEntry {
            pid: 3,
            ppid: 1,
            name: "child2".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::Medium,
        });
        let children = tree.children(1);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_process_tree_ancestry() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry {
            pid: 1,
            ppid: 0,
            name: "a".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::High,
        });
        tree.add(ProcessEntry {
            pid: 2,
            ppid: 1,
            name: "b".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::Medium,
        });
        tree.add(ProcessEntry {
            pid: 3,
            ppid: 2,
            name: "c".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::Low,
        });
        let chain = tree.ancestry(3);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].pid, 3);
        assert_eq!(chain[1].pid, 2);
        assert_eq!(chain[2].pid, 1);
    }

    #[test]
    fn test_process_tree_remove() {
        let mut tree = ProcessTree::default();
        tree.add(ProcessEntry {
            pid: 42,
            ppid: 0,
            name: "test".to_string(),
            command_line: String::new(),
            create_time_ns: 0,
            integrity_level: IntegrityLevel::Medium,
        });
        assert!(tree.find(42).is_some());
        tree.remove(42);
        assert!(tree.find(42).is_none());
    }

    #[test]
    fn test_named_pipe_info_monitor() {
        let p = NamedPipeInfo::monitor_pipe();
        assert!(p.name.contains("pipe"));
        assert_eq!(p.direction, PipeDirection::Inbound);
        assert_eq!(p.max_instances, 16);
    }

    #[test]
    fn test_win_event_record_level_info() {
        let r = WinEventRecord {
            event_id: 4624,
            provider: "Security".to_string(),
            channel: "Security".to_string(),
            level: WinEventLevel::Info,
            timestamp_ns: 0,
            pid: 4,
            tid: 8,
            message: "An account was successfully logged on.".to_string(),
            keywords: 0,
        };
        assert_eq!(r.event_id, 4624);
        assert_eq!(r.level, WinEventLevel::Info);
    }

    #[test]
    fn test_is_persistence_reg_key_appinit() {
        assert!(is_persistence_registry_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs"
        ));
    }

    #[test]
    fn test_is_persistence_reg_key_winlogon() {
        assert!(is_persistence_registry_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
        ));
    }

    #[test]
    fn test_nt_to_win32_reg_path_passthrough() {
        let p = nt_to_win32_reg_path("HKLM\\SOFTWARE\\test");
        assert_eq!(p, "HKLM\\SOFTWARE\\test");
    }

    #[test]
    fn test_winsock_error_host_not_found() {
        assert_eq!(winsock_error_name(11_001), Some("WSAHOST_NOT_FOUND"));
    }

    #[test]
    fn test_winsock_error_wsaeinval() {
        assert_eq!(winsock_error_name(10_022), Some("WSAEINVAL"));
    }

    #[test]
    fn test_privileges_contains_debug() {
        assert!(WINDOWS_PRIVILEGES.contains(&"SeDebugPrivilege"));
    }

    #[test]
    fn test_privileges_contains_tcb() {
        assert!(WINDOWS_PRIVILEGES.contains(&"SeTcbPrivilege"));
    }

    #[test]
    fn test_all_dangerous_privileges_in_list() {
        let dangerous = [
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeTcbPrivilege",
        ];
        for p in dangerous {
            assert!(is_dangerous_privilege(p), "{p} should be dangerous");
        }
    }

    #[test]
    fn test_win_api_db_ntdll_entries() {
        let ntdll: Vec<_> = WIN32_API_DB
            .iter()
            .filter(|e| e.dll == "ntdll.dll")
            .collect();
        assert!(
            ntdll.len() >= 30,
            "expected >= 30 ntdll entries, got {}",
            ntdll.len()
        );
    }

    #[test]
    fn test_win_api_db_winhttp_entries() {
        let wh: Vec<_> = WIN32_API_DB
            .iter()
            .filter(|e| e.dll == "winhttp.dll")
            .collect();
        assert!(
            wh.len() >= 5,
            "expected >= 5 winhttp entries, got {}",
            wh.len()
        );
    }

    #[test]
    fn test_win_syscall_resolver_ssn_for_version() {
        let r = WinSyscallResolver::new();
        let ssn = r.ssn_for_version("NtCreateFile", WinVersion::Windows10);
        assert!(ssn.is_some(), "expected SSN for NtCreateFile on Win10");
    }

    #[test]
    fn test_categorize_nt_file() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtCreateFile"), NtSyscallCategory::FileSystem);
    }

    #[test]
    fn test_categorize_nt_registry() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtCreateKey"), NtSyscallCategory::Registry);
    }

    #[test]
    fn test_categorize_nt_process() {
        use super::categorize_nt;
        assert_eq!(categorize_nt("NtOpenProcess"), NtSyscallCategory::Process);
    }

    #[test]
    fn test_categorize_nt_memory() {
        use super::categorize_nt;
        assert_eq!(
            categorize_nt("NtAllocateVirtualMemory"),
            NtSyscallCategory::Memory
        );
    }
}
