//! Static anti-debug detection: pattern and string scanning.
//!
//! [`StaticAntiDebugDetector`] scans binary data for byte patterns and imported
//! API names known to be used for anti-debugging, anti-VM, and anti-sandbox
//! techniques.  It produces a list of [`DetectionSite`] entries that can then
//! be fed to the [`crate::bypasser::BypassEngine`] for neutralisation.

use serde::{Deserialize, Serialize};

use crate::{AntiDebugTechnique, AntiSandboxTechnique, AntiVmTechnique, PatchStrategy};

// ─────────────────────────────────────────────────────────────────────────────
// DetectionSite
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a single location in binary data where an anti-analysis
/// technique was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSite {
    /// Byte offset of the match in the scanned buffer.
    pub offset: usize,
    /// Length of the matched bytes.
    pub length: usize,
    /// The technique that was detected.
    pub technique: DetectedTechnique,
    /// Recommended patch strategy for this site.
    pub strategy: PatchStrategy,
    /// Human-readable description of what was found.
    pub description: String,
    /// Confidence that this is a true positive (0–100).
    pub confidence: u8,
}

impl DetectionSite {
    /// Create a new detection site.
    #[must_use]
    pub fn new(
        offset: usize,
        length: usize,
        technique: DetectedTechnique,
        strategy: PatchStrategy,
        description: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            offset,
            length,
            technique,
            strategy,
            description: description.into(),
            confidence,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectedTechnique — unified enum
// ─────────────────────────────────────────────────────────────────────────────

/// A detected anti-analysis technique, unified across all categories.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectedTechnique {
    AntiDebug(AntiDebugTechnique),
    AntiVm(AntiVmTechnique),
    AntiSandbox(AntiSandboxTechnique),
}

impl std::fmt::Display for DetectedTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AntiDebug(t) => write!(f, "AntiDebug::{t:?}"),
            Self::AntiVm(t) => write!(f, "AntiVm::{t:?}"),
            Self::AntiSandbox(t) => write!(f, "AntiSandbox::{t:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ANTI_DEBUG_APIS — 60+ API name → technique mappings
// ─────────────────────────────────────────────────────────────────────────────

/// Maps API/symbol names to the anti-debug technique they implement.
///
/// Each entry is `(symbol_name, technique, strategy, confidence)`.
pub static ANTI_DEBUG_APIS: &[(&str, DetectedTechnique, PatchStrategy, u8)] = &[
    // ── IsDebuggerPresent ────────────────────────────────────────────────────
    (
        "IsDebuggerPresent",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::IsDebuggerPresent),
        PatchStrategy::ReturnZero,
        95,
    ),
    (
        "CheckRemoteDebuggerPresent",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::CheckRemoteDebuggerPresent),
        PatchStrategy::ForceFalse,
        90,
    ),
    // ── NtQueryInformationProcess ────────────────────────────────────────────
    (
        "NtQueryInformationProcess",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::NtQueryInformationProcess),
        PatchStrategy::ForceFalse,
        80,
    ),
    (
        "ZwQueryInformationProcess",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::NtQueryInformationProcess),
        PatchStrategy::ForceFalse,
        80,
    ),
    // ── OutputDebugString ────────────────────────────────────────────────────
    (
        "OutputDebugStringA",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::OutputDebugString),
        PatchStrategy::Nop,
        70,
    ),
    (
        "OutputDebugStringW",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::OutputDebugString),
        PatchStrategy::Nop,
        70,
    ),
    // ── Debug exceptions ─────────────────────────────────────────────────────
    (
        "DebugBreak",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::DebugBreak),
        PatchStrategy::Nop,
        85,
    ),
    (
        "DebugBreakProcess",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::DebugBreak),
        PatchStrategy::Nop,
        80,
    ),
    // ── GetTickCount timing ──────────────────────────────────────────────────
    (
        "GetTickCount",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::GetTickCount),
        PatchStrategy::ReturnZero,
        60,
    ),
    (
        "GetTickCount64",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::GetTickCount),
        PatchStrategy::ReturnZero,
        60,
    ),
    (
        "timeGetTime",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::GetTickCount),
        PatchStrategy::ReturnZero,
        55,
    ),
    // ── QueryPerformanceCounter ──────────────────────────────────────────────
    (
        "QueryPerformanceCounter",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::QueryPerformanceCounter),
        PatchStrategy::ReturnZero,
        65,
    ),
    (
        "QueryPerformanceFrequency",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::QueryPerformanceCounter),
        PatchStrategy::ReturnZero,
        55,
    ),
    // ── Hardware breakpoints ─────────────────────────────────────────────────
    (
        "GetThreadContext",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::HardwareBreakpoints),
        PatchStrategy::ForceFalse,
        70,
    ),
    (
        "SetThreadContext",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::HardwareBreakpoints),
        PatchStrategy::ForceFalse,
        65,
    ),
    (
        "NtGetContextThread",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::DrRegisterCheck),
        PatchStrategy::ForceFalse,
        75,
    ),
    (
        "ZwGetContextThread",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::DrRegisterCheck),
        PatchStrategy::ForceFalse,
        75,
    ),
    // ── Timing delays ────────────────────────────────────────────────────────
    (
        "Sleep",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::SleepSkip),
        PatchStrategy::Nop,
        70,
    ),
    (
        "SleepEx",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::SleepSkip),
        PatchStrategy::Nop,
        70,
    ),
    (
        "NtDelayExecution",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::SleepSkip),
        PatchStrategy::Nop,
        75,
    ),
    (
        "WaitForSingleObject",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::TimingDelays),
        PatchStrategy::ReturnZero,
        50,
    ),
    (
        "WaitForSingleObjectEx",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::TimingDelays),
        PatchStrategy::ReturnZero,
        50,
    ),
    // ── Parent process check ─────────────────────────────────────────────────
    (
        "OpenProcess",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::ParentProcess),
        PatchStrategy::ForceFalse,
        40,
    ),
    // ── Heap flags ───────────────────────────────────────────────────────────
    (
        "HeapCreate",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::HeapFlags),
        PatchStrategy::ForceFalse,
        55,
    ),
    (
        "HeapAlloc",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::HeapFlags),
        PatchStrategy::ForceFalse,
        40,
    ),
    (
        "GetProcessHeap",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::ProcessHeap),
        PatchStrategy::ForceFalse,
        60,
    ),
    // ── CloseHandle trap ─────────────────────────────────────────────────────
    (
        "CloseHandle",
        DetectedTechnique::AntiDebug(AntiDebugTechnique::CloseInvalidHandle),
        PatchStrategy::Nop,
        50,
    ),
    // ── User interaction (sandbox) ────────────────────────────────────────────
    (
        "GetCursorPos",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UserInteractionCheck),
        PatchStrategy::ForceFalse,
        65,
    ),
    (
        "GetAsyncKeyState",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UserInteractionCheck),
        PatchStrategy::ForceFalse,
        65,
    ),
    (
        "GetKeyState",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UserInteractionCheck),
        PatchStrategy::ForceFalse,
        55,
    ),
    (
        "BlockInput",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UserInteractionCheck),
        PatchStrategy::Nop,
        70,
    ),
    // ── Screen resolution check ──────────────────────────────────────────────
    (
        "GetSystemMetrics",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::ScreenResolution),
        PatchStrategy::ForceTrue,
        55,
    ),
    (
        "EnumDisplaySettings",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::ScreenResolution),
        PatchStrategy::ForceFalse,
        55,
    ),
    // ── Username / computername ───────────────────────────────────────────────
    (
        "GetUserNameA",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UsernameCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    (
        "GetUserNameW",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UsernameCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    (
        "GetComputerNameA",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UsernameCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    (
        "GetComputerNameW",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::UsernameCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    // ── Domain check ─────────────────────────────────────────────────────────
    (
        "NetGetJoinInformation",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::DomainCheck),
        PatchStrategy::ForceFalse,
        65,
    ),
    (
        "DsGetDcName",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::DomainCheck),
        PatchStrategy::ForceFalse,
        70,
    ),
    // ── VM: VMware ────────────────────────────────────────────────────────────
    (
        "__VMXh",
        DetectedTechnique::AntiVm(AntiVmTechnique::VmwarePortCheck),
        PatchStrategy::ForceFalse,
        90,
    ),
    (
        "VMXh",
        DetectedTechnique::AntiVm(AntiVmTechnique::VmwarePortCheck),
        PatchStrategy::ForceFalse,
        85,
    ),
    // ── VM: process list ─────────────────────────────────────────────────────
    (
        "CreateToolhelp32Snapshot",
        DetectedTechnique::AntiVm(AntiVmTechnique::SuspiciousProcessList),
        PatchStrategy::ForceFalse,
        45,
    ),
    (
        "Process32FirstW",
        DetectedTechnique::AntiVm(AntiVmTechnique::SuspiciousProcessList),
        PatchStrategy::ForceFalse,
        45,
    ),
    (
        "Process32NextW",
        DetectedTechnique::AntiVm(AntiVmTechnique::SuspiciousProcessList),
        PatchStrategy::ForceFalse,
        45,
    ),
    // ── VM: disk size ─────────────────────────────────────────────────────────
    (
        "GetDiskFreeSpaceExA",
        DetectedTechnique::AntiVm(AntiVmTechnique::DiskSizeCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    (
        "GetDiskFreeSpaceExW",
        DetectedTechnique::AntiVm(AntiVmTechnique::DiskSizeCheck),
        PatchStrategy::ForceFalse,
        60,
    ),
    (
        "DeviceIoControl",
        DetectedTechnique::AntiVm(AntiVmTechnique::DiskSizeCheck),
        PatchStrategy::ForceFalse,
        50,
    ),
    // ── VM: CPU count ─────────────────────────────────────────────────────────
    (
        "GetSystemInfo",
        DetectedTechnique::AntiVm(AntiVmTechnique::CpuCountCheck),
        PatchStrategy::ForceFalse,
        40,
    ),
    // ── VM: network adapter ──────────────────────────────────────────────────
    (
        "GetAdaptersInfo",
        DetectedTechnique::AntiVm(AntiVmTechnique::NetworkAdapterCheck),
        PatchStrategy::ForceFalse,
        55,
    ),
    (
        "GetAdaptersAddresses",
        DetectedTechnique::AntiVm(AntiVmTechnique::NetworkAdapterCheck),
        PatchStrategy::ForceFalse,
        55,
    ),
    // ── VM: uptime ────────────────────────────────────────────────────────────
    (
        "GetTickCount",
        DetectedTechnique::AntiVm(AntiVmTechnique::UptimeCheck),
        PatchStrategy::ReturnZero,
        50,
    ),
    // ── Mouse movement ───────────────────────────────────────────────────────
    (
        "SetTimer",
        DetectedTechnique::AntiVm(AntiVmTechnique::MouseMovementCheck),
        PatchStrategy::Nop,
        45,
    ),
    // ── Network connectivity check ───────────────────────────────────────────
    (
        "InternetGetConnectedState",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::NetworkConnectivity),
        PatchStrategy::ReturnOne,
        75,
    ),
    (
        "WinHttpGetProxyForUrl",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::NetworkConnectivity),
        PatchStrategy::ForceFalse,
        60,
    ),
    // ── Recent files ─────────────────────────────────────────────────────────
    (
        "SHGetSpecialFolderPath",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::RecentFileCheck),
        PatchStrategy::ForceFalse,
        50,
    ),
    (
        "SHGetSpecialFolderPathA",
        DetectedTechnique::AntiSandbox(AntiSandboxTechnique::RecentFileCheck),
        PatchStrategy::ForceFalse,
        50,
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// BYTE_PATTERNS — 30+ byte-level patterns for anti-debug / anti-VM
// ─────────────────────────────────────────────────────────────────────────────

/// A byte pattern with its associated anti-analysis category.
pub struct BytePatternEntry {
    /// Human-readable name.
    pub name: &'static str,
    /// Pattern bytes.
    pub pattern: &'static [u8],
    /// Mask bytes (`0xFF` = exact, `0x00` = wildcard).
    pub mask: &'static [u8],
    /// The technique this pattern implements.
    pub technique: DetectedTechnique,
    /// Recommended patch strategy.
    pub strategy: PatchStrategy,
    /// Confidence score.
    pub confidence: u8,
}

/// Static table of byte-level anti-analysis patterns.
pub static BYTE_PATTERNS: &[BytePatternEntry] = &[
    // ── RDTSC ────────────────────────────────────────────────────────────────
    BytePatternEntry {
        name: "rdtsc",
        pattern: &[0x0F, 0x31],
        mask: &[0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
        strategy: PatchStrategy::Nop,
        confidence: 90,
    },
    // ── INT3 software breakpoint ─────────────────────────────────────────────
    BytePatternEntry {
        name: "int3_trap",
        pattern: &[0xCC],
        mask: &[0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::ExceptionBasedChecks),
        strategy: PatchStrategy::Nop,
        confidence: 60,
    },
    // ── IsDebuggerPresent inline: mov eax, [fs:0x30] / test byte[eax+2] ──────
    BytePatternEntry {
        name: "peb_being_debugged_x86",
        pattern: &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::BeingDebugged),
        strategy: PatchStrategy::ForceFalse,
        confidence: 95,
    },
    // ── PEB x64: mov rax, gs:[0x60] ──────────────────────────────────────────
    BytePatternEntry {
        name: "peb_x64",
        pattern: &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::BeingDebugged),
        strategy: PatchStrategy::ForceFalse,
        confidence: 90,
    },
    // ── NtGlobalFlag check: cmp [eax+0x68], 0x70 ─────────────────────────────
    BytePatternEntry {
        name: "nt_global_flag_x86",
        pattern: &[0x83, 0x78, 0x68, 0x70],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::NtGlobalFlag),
        strategy: PatchStrategy::ForceFalse,
        confidence: 85,
    },
    // ── VMware I/O port backdoor: in eax, dx (preceded by VMXh magic) ─────────
    BytePatternEntry {
        name: "vmware_port",
        pattern: &[0x56, 0x4D, 0x58, 0x68], // "VMXh"
        mask: &[0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::VmwarePortCheck),
        strategy: PatchStrategy::ForceFalse,
        confidence: 90,
    },
    // ── CPUID leaf 0x40000000 (hypervisor vendor string) ──────────────────────
    BytePatternEntry {
        name: "cpuid_hypervisor",
        pattern: &[0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::VmwareCpuid),
        strategy: PatchStrategy::Nop,
        confidence: 88,
    },
    // ── CPUID eax=1, check ecx bit 31 (hypervisor flag) ──────────────────────
    BytePatternEntry {
        name: "cpuid_eax1_ecx_bit31",
        pattern: &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::VmwareCpuid),
        strategy: PatchStrategy::Nop,
        confidence: 70,
    },
    // ── HeapFlags: cmp [eax+0x0C], 2 ─────────────────────────────────────────
    BytePatternEntry {
        name: "heap_flags_x86",
        pattern: &[0x83, 0x78, 0x0C, 0x02],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::HeapFlags),
        strategy: PatchStrategy::ForceFalse,
        confidence: 80,
    },
    // ── Heap ForceFlags: cmp [eax+0x10], 0 ───────────────────────────────────
    BytePatternEntry {
        name: "heap_forceflags_x86",
        pattern: &[0x83, 0x78, 0x10, 0x00],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::HeapFlags),
        strategy: PatchStrategy::ForceFalse,
        confidence: 75,
    },
    // ── Timing: two consecutive RDTSC + compare ───────────────────────────────
    BytePatternEntry {
        name: "rdtsc_double",
        pattern: &[0x0F, 0x31, 0x00, 0x00, 0x0F, 0x31],
        mask: &[0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
        strategy: PatchStrategy::Nop,
        confidence: 95,
    },
    // ── SEH-based trap: push offset + xor eax, eax + ret ─────────────────────
    BytePatternEntry {
        name: "seh_chain_trap",
        pattern: &[0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00],
        mask: &[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::SehChain),
        strategy: PatchStrategy::Nop,
        confidence: 80,
    },
    // ── VirtualBox: "VBoxGuest" signature bytes ────────────────────────────────
    BytePatternEntry {
        name: "vbox_guest",
        pattern: b"VBoxGuest",
        mask: &[0xFF; 9],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::VboxRegistry),
        strategy: PatchStrategy::ForceFalse,
        confidence: 88,
    },
    // ── VirtualBox registry key prefix ────────────────────────────────────────
    BytePatternEntry {
        name: "vbox_registry",
        pattern: b"VBOX__",
        mask: &[0xFF; 6],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::VboxRegistry),
        strategy: PatchStrategy::ForceFalse,
        confidence: 90,
    },
    // ── VMware process: "vmtoolsd" ────────────────────────────────────────────
    BytePatternEntry {
        name: "vmtoolsd",
        pattern: b"vmtoolsd",
        mask: &[0xFF; 8],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::SuspiciousProcessList),
        strategy: PatchStrategy::ForceFalse,
        confidence: 85,
    },
    // ── VirtualBox service: "vboxservice" ────────────────────────────────────
    BytePatternEntry {
        name: "vboxservice",
        pattern: b"vboxservice",
        mask: &[0xFF; 11],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::SuspiciousProcessList),
        strategy: PatchStrategy::ForceFalse,
        confidence: 85,
    },
    // ── Sandbox: "cuckoo" process or file ─────────────────────────────────────
    BytePatternEntry {
        name: "cuckoo_artifact",
        pattern: b"cuckoo",
        mask: &[0xFF; 6],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::SandboxArtifacts),
        strategy: PatchStrategy::ForceFalse,
        confidence: 80,
    },
    // ── Sandbox: "wireshark" process name ────────────────────────────────────
    BytePatternEntry {
        name: "wireshark_artifact",
        pattern: b"wireshark",
        mask: &[0xFF; 9],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::SandboxArtifacts),
        strategy: PatchStrategy::ForceFalse,
        confidence: 75,
    },
    // ── Sleep > 4 minutes (0x927C0 = 600000 ms) as u32 little-endian ─────────
    BytePatternEntry {
        name: "long_sleep_4min",
        pattern: &[0xC0, 0x27, 0x09, 0x00],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiSandbox(AntiSandboxTechnique::SleepSkip),
        strategy: PatchStrategy::Nop,
        confidence: 85,
    },
    // ── NtGlobalFlag x64 offset 0xBC ─────────────────────────────────────────
    BytePatternEntry {
        name: "nt_global_flag_x64",
        pattern: &[0x83, 0xB8, 0xBC, 0x00, 0x00, 0x00, 0x70],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::NtGlobalFlag),
        strategy: PatchStrategy::ForceFalse,
        confidence: 90,
    },
    // ── TracerPid: "/proc/self/status" ───────────────────────────────────────
    BytePatternEntry {
        name: "tracer_pid_path",
        pattern: b"TracerPid",
        mask: &[0xFF; 9],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::TracerPid),
        strategy: PatchStrategy::ForceFalse,
        confidence: 90,
    },
    // ── ptrace(PTRACE_TRACEME, …) call ────────────────────────────────────────
    BytePatternEntry {
        name: "ptrace_traceme",
        pattern: b"ptrace",
        mask: &[0xFF; 6],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::Ptrace),
        strategy: PatchStrategy::ReturnZero,
        confidence: 80,
    },
    // ── /proc/self/status path ────────────────────────────────────────────────
    BytePatternEntry {
        name: "proc_self_status",
        pattern: b"/proc/self/status",
        mask: &[0xFF; 17],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::ProcStatus),
        strategy: PatchStrategy::ForceFalse,
        confidence: 85,
    },
    // ── Hyper-V: "Microsoft Hv" CPUID string ─────────────────────────────────
    BytePatternEntry {
        name: "hyperv_string",
        pattern: b"Microsoft Hv",
        mask: &[0xFF; 12],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::HyperVCpuid),
        strategy: PatchStrategy::ForceFalse,
        confidence: 88,
    },
    // ── QEMU: "QEMU" or "KVMKVMKVM" ─────────────────────────────────────────
    BytePatternEntry {
        name: "qemu_string",
        pattern: b"KVMKVMKVM",
        mask: &[0xFF; 9],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::QemuCpuid),
        strategy: PatchStrategy::ForceFalse,
        confidence: 88,
    },
    // ── Screen resolution < 800x600 check pattern ────────────────────────────
    BytePatternEntry {
        name: "small_screen_check",
        pattern: &[0x3D, 0x20, 0x03, 0x00, 0x00], // cmp eax, 0x320 (800)
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiSandbox(AntiSandboxTechnique::ScreenResolution),
        strategy: PatchStrategy::ForceFalse,
        confidence: 70,
    },
    // ── Memory size check: GlobalMemoryStatusEx → dwTotalPhys < 1 GB ─────────
    BytePatternEntry {
        name: "memory_size_check",
        pattern: b"GlobalMemoryStatusEx",
        mask: &[0xFF; 20],
        technique: DetectedTechnique::AntiVm(AntiVmTechnique::DiskSizeCheck),
        strategy: PatchStrategy::ForceFalse,
        confidence: 55,
    },
    // ── NtGlobalFlag via PEB direct access (7B or 70 value) ───────────────────
    BytePatternEntry {
        name: "nt_global_flag_0x70",
        pattern: &[0x3D, 0x70, 0x00, 0x00, 0x00], // cmp eax, 0x70
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::NtGlobalFlag),
        strategy: PatchStrategy::ForceFalse,
        confidence: 80,
    },
    // ── Hardware BP: test DR0..DR3 ────────────────────────────────────────────
    BytePatternEntry {
        name: "debug_register_check",
        pattern: &[0x0F, 0x23, 0xC0], // mov DR0, eax
        mask: &[0xFF, 0xFF, 0xFF],
        technique: DetectedTechnique::AntiDebug(AntiDebugTechnique::DrRegisterCheck),
        strategy: PatchStrategy::Nop,
        confidence: 85,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// StaticAntiDebugDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Scans binary data for known anti-debugging, anti-VM, and anti-sandbox
/// patterns using both byte-pattern matching and string-based API detection.
///
/// ```rust
/// use rustre_deobf_antianti::detector::StaticAntiDebugDetector;
///
/// let detector = StaticAntiDebugDetector::new();
/// let data = b"\x0f\x31\x90IsDebuggerPresent\x00";
/// let sites = detector.scan(data);
/// assert!(!sites.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct StaticAntiDebugDetector {
    /// Minimum confidence threshold for reported detections.
    min_confidence: u8,
}

impl StaticAntiDebugDetector {
    /// Create a detector with default settings (minimum confidence = 40).
    #[must_use]
    pub const fn new() -> Self {
        Self { min_confidence: 40 }
    }

    /// Create a detector with a custom confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(min_confidence: u8) -> Self {
        Self { min_confidence }
    }

    /// Scan `data` and return all detected sites above the confidence threshold.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<DetectionSite> {
        let mut sites = Vec::new();
        self.scan_byte_patterns(data, &mut sites);
        self.scan_api_strings(data, &mut sites);
        sites.sort_by_key(|s| s.offset);
        sites
    }

    fn scan_byte_patterns(&self, data: &[u8], out: &mut Vec<DetectionSite>) {
        for pat in BYTE_PATTERNS {
            if pat.confidence < self.min_confidence {
                continue;
            }
            let plen = pat.pattern.len();
            if plen > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - plen) {
                let window = &data[offset..offset + plen];
                let matched = window
                    .iter()
                    .zip(pat.pattern.iter())
                    .zip(pat.mask.iter())
                    .all(|((b, p), m)| (*m == 0) || (*b & m == *p & m));
                if matched {
                    out.push(DetectionSite::new(
                        offset,
                        plen,
                        pat.technique.clone(),
                        pat.strategy,
                        format!("byte-pattern: {}", pat.name),
                        pat.confidence,
                    ));
                }
            }
        }
    }

    fn scan_api_strings(&self, data: &[u8], out: &mut Vec<DetectionSite>) {
        for (api, technique, strategy, confidence) in ANTI_DEBUG_APIS {
            if *confidence < self.min_confidence {
                continue;
            }
            let needle = api.as_bytes();
            let nlen = needle.len();
            if nlen > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - nlen) {
                if &data[offset..offset + nlen] == needle {
                    out.push(DetectionSite::new(
                        offset,
                        nlen,
                        technique.clone(),
                        *strategy,
                        format!("api-string: {api}"),
                        *confidence,
                    ));
                }
            }
        }
    }

    /// Summarise detections grouped by technique.
    #[must_use]
    pub fn summarize(&self, sites: &[DetectionSite]) -> Vec<(DetectedTechnique, usize)> {
        let mut counts: std::collections::HashMap<String, (DetectedTechnique, usize)> =
            std::collections::HashMap::new();
        for site in sites {
            let key = site.technique.to_string();
            let entry = counts
                .entry(key)
                .or_insert_with(|| (site.technique.clone(), 0));
            entry.1 += 1;
        }
        let mut result: Vec<(DetectedTechnique, usize)> = counts.into_values().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> StaticAntiDebugDetector {
        StaticAntiDebugDetector::new()
    }

    #[test]
    fn test_rdtsc_pattern() {
        let data = [0x90u8, 0x0F, 0x31, 0x90];
        let sites = det().scan(&data);
        assert!(sites.iter().any(|s| matches!(
            &s.technique,
            DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc)
        )));
    }

    #[test]
    fn test_peb_x86_pattern() {
        let data = [0x64u8, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00];
        let sites = det().scan(&data);
        assert!(sites.iter().any(|s| matches!(
            &s.technique,
            DetectedTechnique::AntiDebug(AntiDebugTechnique::BeingDebugged)
        )));
    }

    #[test]
    fn test_api_string_isdebugger() {
        let data = b"call IsDebuggerPresent\x00";
        let sites = det().scan(data);
        assert!(sites.iter().any(|s| matches!(
            &s.technique,
            DetectedTechnique::AntiDebug(AntiDebugTechnique::IsDebuggerPresent)
        )));
    }

    #[test]
    fn test_vbox_string() {
        let data = b"VBoxGuest driver not found";
        let sites = det().scan(data);
        assert!(sites.iter().any(|s| matches!(
            &s.technique,
            DetectedTechnique::AntiVm(AntiVmTechnique::VboxRegistry)
        )));
    }

    #[test]
    fn test_tracer_pid() {
        let data = b"check TracerPid in file";
        let sites = det().scan(data);
        assert!(sites.iter().any(|s| matches!(
            &s.technique,
            DetectedTechnique::AntiDebug(AntiDebugTechnique::TracerPid)
        )));
    }

    #[test]
    fn test_min_confidence_filter() {
        let high_conf_det = StaticAntiDebugDetector::with_min_confidence(90);
        let data = [0x0F, 0x31];
        let sites = high_conf_det.scan(&data);
        // RDTSC has confidence 90, should still match
        assert!(!sites.is_empty());

        let very_high = StaticAntiDebugDetector::with_min_confidence(100);
        let sites2 = very_high.scan(&data);
        // Nothing reaches 100
        assert!(sites2.is_empty());
    }

    #[test]
    fn test_summarize() {
        let data: Vec<u8> = [
            vec![0x0F, 0x31, 0x0F, 0x31], // two RDTSC
            b"IsDebuggerPresent".to_vec(),
        ]
        .concat();
        let sites = det().scan(&data);
        let summary = det().summarize(&sites);
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_detection_site_fields() {
        let site = DetectionSite::new(
            10,
            2,
            DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc),
            PatchStrategy::Nop,
            "test rdtsc",
            90,
        );
        assert_eq!(site.offset, 10);
        assert_eq!(site.length, 2);
        assert_eq!(site.confidence, 90);
    }

    #[test]
    fn test_detected_technique_display() {
        let t = DetectedTechnique::AntiDebug(AntiDebugTechnique::Rdtsc);
        assert!(t.to_string().contains("Rdtsc"));
    }
}
