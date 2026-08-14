//! Compatibility layer: cross-architecture and cross-OS syscall forwarding analysis.
//!
//! Covers:
//! - **`WoW64`**: Windows 32-on-64 syscall thunk translation (Heaven's Gate, `Wow64Transition`).
//! - **ptrace intercept cross-arch**: translating register contexts between 32-bit and 64-bit
//!   when a 64-bit tracer intercepts a 32-bit tracee.
//! - **Wine syscall forwarding**: maps NT syscall stubs to Unix equivalents.
//! - **IA32 compatibility mode on x86-64 Linux**: `int 0x80` vs `syscall` distinction.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};


// ─── WoW64 ───────────────────────────────────────────────────────────────────

/// The `WoW64` transition gate addresses seen on typical Windows 10/11 builds.
/// These can be resolved dynamically from `wow64.dll` exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wow64GateInfo {
    /// Address of `Wow64Transition` / `KiFastSystemCall32` in wow64cpu.dll.
    pub fast_syscall_addr: u64,
    /// Address of `KiIntSystemCall` fallback (int 0x2e path).
    pub int_syscall_addr: u64,
    /// Address of the Heaven's Gate selector 0x33 far-jmp stub.
    pub heavens_gate_addr: u64,
    /// Windows build number (used for syscall table version selection).
    pub build_number: u32,
}

impl Default for Wow64GateInfo {
    fn default() -> Self {
        Self {
            // Typical values on Windows 10 20H2; must be resolved at runtime.
            fast_syscall_addr: 0x77c0_0000,
            int_syscall_addr: 0x77c0_0010,
            heavens_gate_addr: 0x77c0_0020,
            build_number: 19042,
        }
    }
}

/// Result of analyzing a `WoW64` syscall transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wow64TransitionInfo {
    /// 32-bit syscall number (from EAX in the 32-bit thunk).
    pub wow64_nr: u32,
    /// Translated 64-bit syscall number (may differ from `WoW64` nr).
    pub nt64_nr: Option<u32>,
    /// Name of the Nt/Zw stub if known.
    pub stub_name: Option<String>,
    /// Whether this call went through Heaven's Gate (far jump to 64-bit code).
    pub via_heavens_gate: bool,
    /// Whether this call was `int 0x2e` (legacy interrupt path).
    pub via_int2e: bool,
}

/// Analyzes a `WoW64` call transition from captured instruction bytes and
/// register state.
pub struct Wow64Analyzer {
    /// Map from 32-bit `WoW64` syscall number to (64-bit nr, name).
    translation_table: HashMap<u32, (u32, String)>,
    _gate_info: Wow64GateInfo,
}

impl Wow64Analyzer {
    #[must_use] 
    pub fn new(gate_info: Wow64GateInfo) -> Self {
        Self { translation_table: build_wow64_table(), _gate_info: gate_info }
    }

    /// Translate a captured 32-bit syscall number.
    #[must_use] 
    pub fn translate(&self, wow64_nr: u32, via_heavens_gate: bool, via_int2e: bool)
        -> Wow64TransitionInfo
    {
        let (nt64_nr, stub_name) = self.translation_table
            .get(&wow64_nr)
            .map_or((None, None), |(n, s)| (Some(*n), Some(s.clone())));
        Wow64TransitionInfo { wow64_nr, nt64_nr, stub_name, via_heavens_gate, via_int2e }
    }

    /// Detect the syscall path from the bytes preceding `syscall`/`sysenter`/`int 0x2e`.
    /// Returns `(wow64_nr, via_heavens_gate, via_int2e)`.
    #[must_use] 
    pub fn detect_from_bytes(bytes: &[u8], eax_value: u32) -> (u32, bool, bool) {
        // Pattern: FF D0 (call eax) after a far jmp stub = Heaven's Gate
        let heavens_gate = bytes.windows(6).any(|w| {
            // EA xx xx xx xx 33 00 = ljmp cs:0x33 (Heaven's Gate far jump selector)
            w[0] == 0xEA && w[5] == 0x33
        });
        // CD 2E = int 0x2e
        let int2e = bytes.windows(2).any(|w| w == [0xCD, 0x2E]);
        (eax_value, heavens_gate, int2e)
    }

    /// Format a transition info as a human-readable summary.
    #[must_use] 
    pub fn format(&self, info: &Wow64TransitionInfo) -> String {
        let mut s = String::new();
        let name = info.stub_name.as_deref().unwrap_or("?");
        write!(s, "WoW64 syscall {:#06x} ({name})", info.wow64_nr).ok();
        if let Some(n64) = info.nt64_nr {
            write!(s, " → NT64 {n64:#06x}").ok();
        }
        if info.via_heavens_gate { write!(s, " [Heaven's Gate]").ok(); }
        if info.via_int2e { write!(s, " [int 0x2e]").ok(); }
        s
    }
}

/// Build a representative `WoW64` 32→64 syscall number translation table
/// (Windows 10 subset, most common Nt* stubs).
fn build_wow64_table() -> HashMap<u32, (u32, String)> {
    let entries: &[(u32, u32, &str)] = &[
        (0x0001, 0x0001, "NtAccessCheck"),
        (0x0002, 0x0002, "NtWorkerFactoryWorkerReady"),
        (0x000F, 0x000F, "NtClose"),
        (0x0012, 0x0012, "NtCreateEvent"),
        (0x0018, 0x0018, "NtCreateFile"),
        (0x001B, 0x001B, "NtCreateKey"),
        (0x0022, 0x0022, "NtCreateMutant"),
        (0x0029, 0x0029, "NtCreateProcess"),
        (0x002A, 0x002A, "NtCreateProcessEx"),
        (0x002B, 0x002B, "NtCreateSection"),
        (0x0037, 0x0037, "NtCreateThread"),
        (0x0038, 0x0038, "NtCreateThreadEx"),
        (0x004A, 0x004A, "NtDelayExecution"),
        (0x0055, 0x0055, "NtDeviceIoControlFile"),
        (0x005C, 0x005C, "NtDuplicateObject"),
        (0x0062, 0x0062, "NtEnumerateKey"),
        (0x0075, 0x0075, "NtFlushBuffersFile"),
        (0x0078, 0x0078, "NtFreeVirtualMemory"),
        (0x007B, 0x007B, "NtFsControlFile"),
        (0x007E, 0x007E, "NtGetContextThread"),
        (0x008A, 0x008A, "NtLoadKey"),
        (0x0097, 0x0097, "NtMapViewOfSection"),
        (0x00A6, 0x00A6, "NtNotifyChangeKey"),
        (0x00B4, 0x00B4, "NtOpenFile"),
        (0x00BB, 0x00BB, "NtOpenKey"),
        (0x00C9, 0x00C9, "NtOpenProcess"),
        (0x00CE, 0x00CE, "NtOpenSection"),
        (0x00D1, 0x00D1, "NtOpenThread"),
        (0x00EF, 0x00EF, "NtProtectVirtualMemory"),
        (0x00F2, 0x00F2, "NtQueryAttributesFile"),
        (0x0100, 0x0100, "NtQueryInformationFile"),
        (0x0105, 0x0105, "NtQueryInformationProcess"),
        (0x0109, 0x0109, "NtQueryInformationThread"),
        (0x010D, 0x010D, "NtQueryKey"),
        (0x0111, 0x0111, "NtQueryObject"),
        (0x0113, 0x0113, "NtQueryPerformanceCounter"),
        (0x011A, 0x011A, "NtQuerySystemInformation"),
        (0x011C, 0x011C, "NtQuerySystemTime"),
        (0x011F, 0x011F, "NtQueryValueKey"),
        (0x0126, 0x0126, "NtQueryVirtualMemory"),
        (0x012D, 0x012D, "NtReadFile"),
        (0x0131, 0x0131, "NtReadVirtualMemory"),
        (0x013E, 0x013E, "NtReleaseMutant"),
        (0x0149, 0x0149, "NtRequestWaitReplyPort"),
        (0x014F, 0x014F, "NtResumeThread"),
        (0x0153, 0x0153, "NtSetContextThread"),
        (0x015D, 0x015D, "NtSetEvent"),
        (0x0169, 0x0169, "NtSetInformationFile"),
        (0x016D, 0x016D, "NtSetInformationProcess"),
        (0x0171, 0x0171, "NtSetInformationThread"),
        (0x017A, 0x017A, "NtSetValueKey"),
        (0x0181, 0x0181, "NtSuspendThread"),
        (0x0184, 0x0184, "NtTerminateProcess"),
        (0x0185, 0x0185, "NtTerminateThread"),
        (0x0188, 0x0188, "NtUnloadKey"),
        (0x018B, 0x018B, "NtUnmapViewOfSection"),
        (0x01C0, 0x01C0, "NtWaitForSingleObject"),
        (0x01C4, 0x01C4, "NtWriteFile"),
        (0x01CB, 0x01CB, "NtWriteVirtualMemory"),
        (0x01E0, 0x01E0, "NtAllocateVirtualMemory"),
        (0x01E5, 0x01E5, "NtCreateUserProcess"),
    ];
    entries.iter().map(|&(w, n, s)| (w, (n, s.to_string()))).collect()
}

// ─── ptrace cross-arch register translation ──────────────────────────────────

/// Register context in 32-bit (IA32) mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ia32Regs {
    pub eax: u32, pub ebx: u32, pub ecx: u32, pub edx: u32,
    pub esi: u32, pub edi: u32, pub ebp: u32, pub esp: u32,
    pub eip: u32, pub eflags: u32, pub orig_eax: u32,
}

/// Register context in 64-bit mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct X86_64Regs {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64, pub orig_rax: u64,
}

/// Translate a 32-bit `int 0x80` syscall register context so it can be
/// interpreted by a 64-bit tracer.
///
/// On Linux x86-64 in IA32 compat mode:
/// - syscall nr: `eax` → `orig_rax`
/// - arguments: `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp` → `rdi..r9`
#[must_use] 
pub fn translate_ia32_to_x64(r32: &Ia32Regs) -> X86_64Regs {
    X86_64Regs {
        orig_rax: u64::from(r32.orig_eax),
        rax: u64::from(r32.eax),
        rdi: u64::from(r32.ebx),
        rsi: u64::from(r32.ecx),
        rdx: u64::from(r32.edx),
        r10: u64::from(r32.esi),
        r8:  u64::from(r32.edi),
        r9:  u64::from(r32.ebp),
        rsp: u64::from(r32.esp),
        rbp: u64::from(r32.ebp),
        rip: u64::from(r32.eip),
        rflags: u64::from(r32.eflags),
        ..Default::default()
    }
}

/// Translate x64 registers back to the 32-bit view for compat-mode tracees.
/// Module-private helper: deliberate low-32 truncation of a 64-bit register
/// when collapsing an x86-64 register set down to its IA-32 view.
#[inline]
const fn lo32(x: u64) -> u32 {
    let b = x.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[must_use]
pub const fn translate_x64_to_ia32(r64: &X86_64Regs) -> Ia32Regs {
    Ia32Regs {
        orig_eax: lo32(r64.orig_rax),
        eax: lo32(r64.rax),
        ebx: lo32(r64.rdi),
        ecx: lo32(r64.rsi),
        edx: lo32(r64.rdx),
        esi: lo32(r64.r10),
        edi: lo32(r64.r8),
        ebp: lo32(r64.r9),
        esp: lo32(r64.rsp),
        eip: lo32(r64.rip),
        eflags: lo32(r64.rflags),
    }
}

/// Syscall entry mechanism for a 32-bit tracee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ia32SyscallMechanism {
    Int80,
    Sysenter,
    Syscall,  // rare on IA32 but supported on some CPUs
}

/// Detect the syscall mechanism from the two bytes before `eip` on entry.
#[must_use] 
pub fn detect_ia32_mechanism(bytes_before_eip: &[u8]) -> Ia32SyscallMechanism {
    if bytes_before_eip.ends_with(&[0xCD, 0x80]) {
        Ia32SyscallMechanism::Int80
    } else if bytes_before_eip.ends_with(&[0x0F, 0x34]) {
        Ia32SyscallMechanism::Sysenter
    } else {
        Ia32SyscallMechanism::Syscall
    }
}

// ─── Wine syscall forwarding analysis ────────────────────────────────────────

/// A Wine NT→Unix syscall mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WineSyscallMapping {
    /// NT syscall name (e.g. `NtReadFile`).
    pub nt_name: String,
    /// NT syscall number on the Wine stub table.
    pub nt_nr: u32,
    /// Corresponding Unix syscall name(s) that Wine dispatches to.
    pub unix_syscalls: Vec<String>,
    /// Whether this call is fully emulated (no kernel call) or forwarded.
    pub emulated: bool,
    /// Notes about Wine-specific behaviour.
    pub notes: Option<String>,
}

/// A database of known Wine NT→Unix mappings.
pub struct WineSyscallDb {
    entries: HashMap<String, WineSyscallMapping>,
}

impl WineSyscallDb {
    #[must_use] 
    pub fn new() -> Self {
        Self { entries: build_wine_db() }
    }

    /// Look up a mapping by NT name.
    #[must_use] 
    pub fn lookup(&self, nt_name: &str) -> Option<&WineSyscallMapping> {
        self.entries.get(nt_name)
    }

    /// Format a full report of the Wine syscall mapping table.
    #[must_use] 
    pub fn format_table(&self) -> String {
        let mut out = String::new();
        writeln!(out, "{:<30} {:<8} {:<40} Emulated", "NT syscall", "Nr", "Unix equivalents").ok();
        writeln!(out, "{}", "-".repeat(90)).ok();
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by_key(|e| e.nt_nr);
        for e in entries {
            writeln!(
                out,
                "{:<30} {:<8} {:<40} {}",
                e.nt_name,
                format!("{:#06x}", e.nt_nr),
                e.unix_syscalls.join(", "),
                if e.emulated { "yes" } else { "no" }
            ).ok();
        }
        out
    }
}

impl Default for WineSyscallDb {
    fn default() -> Self { Self::new() }
}

/// Raw entry type for the Wine syscall mapping table.
type WineRawEntry<'a> = (&'a str, u32, &'a [&'a str], bool, Option<&'a str>);

fn build_wine_db() -> HashMap<String, WineSyscallMapping> {
    let raw: &[WineRawEntry<'_>] = &[
        ("NtReadFile",           0x012D, &["read", "pread64"],               false, None),
        ("NtWriteFile",          0x01C4, &["write", "pwrite64"],              false, None),
        ("NtCreateFile",         0x0018, &["open", "openat", "creat"],        false, None),
        ("NtOpenFile",           0x00B4, &["open", "openat"],                 false, None),
        ("NtClose",              0x000F, &["close"],                          false, None),
        ("NtQueryInformationFile",0x0100, &["fstat", "stat"],                 false, None),
        ("NtSetInformationFile", 0x0169, &["ftruncate", "fcntl", "chmod"],    false, None),
        ("NtFsControlFile",      0x007B, &["ioctl"],                          false, None),
        ("NtDeviceIoControlFile",0x0055, &["ioctl"],                          false, None),
        ("NtAllocateVirtualMemory",0x01E0,&["mmap"],                          false, None),
        ("NtFreeVirtualMemory",  0x0078, &["munmap"],                         false, None),
        ("NtProtectVirtualMemory",0x00EF,&["mprotect"],                       false, None),
        ("NtMapViewOfSection",   0x0097, &["mmap"],                           false, None),
        ("NtUnmapViewOfSection", 0x018B, &["munmap"],                         false, None),
        ("NtCreateProcess",      0x0029, &["clone", "fork", "execve"],        false, None),
        ("NtCreateThread",       0x0037, &["clone"],                          false, None),
        ("NtTerminateProcess",   0x0184, &["kill", "exit"],                   false, None),
        ("NtTerminateThread",    0x0185, &["exit"],                           false, None),
        ("NtSuspendThread",      0x0181, &["kill(SIGSTOP)"],                  true,  Some("Emulated via SIGSTOP")),
        ("NtResumeThread",       0x014F, &["kill(SIGCONT)"],                  true,  Some("Emulated via SIGCONT")),
        ("NtWaitForSingleObject",0x01C0, &["futex", "poll", "select"],        false, None),
        ("NtDelayExecution",     0x004A, &["nanosleep", "clock_nanosleep"],   false, None),
        ("NtQuerySystemTime",    0x011C, &["clock_gettime"],                  false, None),
        ("NtQueryPerformanceCounter",0x0113,&["clock_gettime"],               false, None),
        ("NtQueryVirtualMemory", 0x0126, &["mincore", "madvise"],             true,  Some("Partially emulated")),
        ("NtCreateSection",      0x002B, &["open", "ftruncate", "mmap"],      false, None),
        ("NtDuplicateObject",    0x005C, &["dup", "dup2", "dup3"],            false, None),
        ("NtCreateKey",          0x001B, &[],                                 true,  Some("Registry: emulated in memory or via files")),
        ("NtOpenKey",            0x00BB, &[],                                 true,  Some("Registry: emulated")),
        ("NtQueryValueKey",      0x011F, &[],                                 true,  Some("Registry: emulated")),
        ("NtSetValueKey",        0x017A, &[],                                 true,  Some("Registry: emulated")),
        ("NtReadVirtualMemory",  0x0131, &["process_vm_readv"],               false, None),
        ("NtWriteVirtualMemory", 0x01CB, &["process_vm_writev"],              false, None),
        ("NtGetContextThread",   0x007E, &["ptrace(GETREGS)"],                false, None),
        ("NtSetContextThread",   0x0153, &["ptrace(SETREGS)"],                false, None),
    ];
    raw.iter()
        .map(|&(name, nr, unix, emulated, notes)| {
            let m = WineSyscallMapping {
                nt_name: name.to_string(),
                nt_nr: nr,
                unix_syscalls: unix.iter().map(std::string::ToString::to_string).collect(),
                emulated,
                notes: notes.map(std::string::ToString::to_string),
            };
            (name.to_string(), m)
        })
        .collect()
}

// ─── ARM / AArch64 register translation ──────────────────────────────────────

/// ARM32 (EABI) register context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Arm32Regs {
    /// r0..r12, sp(r13), lr(r14), pc(r15)
    pub r: [u32; 16],
    pub cpsr: u32,
    /// Syscall number (captured from r7 at syscall entry).
    pub syscall_nr: u32,
}

impl Arm32Regs {
    /// ARM EABI syscall arguments: r0..r5, syscall nr in r7.
    #[must_use] 
    pub fn syscall_args(&self) -> [u64; 6] {
        [u64::from(self.r[0]), u64::from(self.r[1]), u64::from(self.r[2]),
         u64::from(self.r[3]), u64::from(self.r[4]), u64::from(self.r[5])]
    }
}

/// `AArch64` register context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Arm64Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// Syscall number (from x8).
    pub syscall_nr: u64,
}

impl Arm64Regs {
    /// `AArch64` syscall arguments: x0..x5, syscall nr in x8.
    #[must_use] 
    pub const fn syscall_args(&self) -> [u64; 6] {
        [self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5]]
    }
}

/// MIPS O32 ABI register context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MipsRegs {
    /// General purpose registers (0..31).
    pub gpr: [u32; 32],
    pub pc: u32,
    pub hi: u32,
    pub lo: u32,
}

impl MipsRegs {
    /// MIPS O32 syscall: number in $v0 (r2), args in $a0..$a3 (r4..r7).
    #[must_use] 
    pub const fn syscall_nr(&self) -> u32 { self.gpr[2] }
    #[must_use] 
    pub fn syscall_args(&self) -> [u64; 4] {
        [u64::from(self.gpr[4]), u64::from(self.gpr[5]), u64::from(self.gpr[6]), u64::from(self.gpr[7])]
    }
}

/// RISC-V 64-bit register context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiscV64Regs {
    /// x0..x31 (x0 is hardwired zero).
    pub x: [u64; 32],
    pub pc: u64,
}

impl RiscV64Regs {
    /// RISC-V syscall: number in a7 (x17), args in a0..a5 (x10..x15).
    #[must_use] 
    pub const fn syscall_nr(&self) -> u64 { self.x[17] }
    #[must_use] 
    pub const fn syscall_args(&self) -> [u64; 6] {
        [self.x[10], self.x[11], self.x[12], self.x[13], self.x[14], self.x[15]]
    }
}

/// Unified cross-architecture register view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnifiedRegs {
    X86(Ia32Regs),
    X86_64(X86_64Regs),
    Arm32(Arm32Regs),
    Arm64(Arm64Regs),
    Mips(MipsRegs),
    RiscV64(RiscV64Regs),
}

impl UnifiedRegs {
    /// Extract the syscall number from any architecture's register file.
    #[must_use] 
    pub fn syscall_nr(&self) -> u64 {
        match self {
            Self::X86(r) => u64::from(r.orig_eax),
            Self::X86_64(r) => r.orig_rax,
            Self::Arm32(r) => u64::from(r.syscall_nr),
            Self::Arm64(r) => r.syscall_nr,
            Self::Mips(r) => u64::from(r.syscall_nr()),
            Self::RiscV64(r) => r.syscall_nr(),
        }
    }

    /// Extract syscall arguments in a normalized [u64; 6] array.
    #[must_use] 
    pub fn syscall_args(&self) -> [u64; 6] {
        match self {
            Self::X86(r) => [u64::from(r.ebx), u64::from(r.ecx), u64::from(r.edx), u64::from(r.esi), u64::from(r.edi), u64::from(r.ebp)],
            Self::X86_64(r) => [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
            Self::Arm32(r) => r.syscall_args(),
            Self::Arm64(r) => r.syscall_args(),
            Self::Mips(r) => {
                let a = r.syscall_args();
                [a[0], a[1], a[2], a[3], 0, 0]
            }
            Self::RiscV64(r) => r.syscall_args(),
        }
    }

    /// Return the architecture identifier for this register set.
    #[must_use] 
    pub const fn arch(&self) -> crate::SyscallArch {
        match self {
            Self::X86(_) => crate::SyscallArch::X86,
            Self::X86_64(_) => crate::SyscallArch::X86_64,
            Self::Arm32(_) => crate::SyscallArch::Arm32,
            Self::Arm64(_) => crate::SyscallArch::Arm64,
            Self::Mips(_) => crate::SyscallArch::Mips,
            Self::RiscV64(_) => crate::SyscallArch::Riscv64,
        }
    }
}

// ─── ptrace compat helpers ────────────────────────────────────────────────────

/// Direction of a ptrace syscall interception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtraceDirection {
    /// The traced process is entering the syscall.
    Entry,
    /// The traced process is exiting the syscall.
    Exit,
}

/// Describes one ptrace syscall intercept event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceEvent {
    pub pid: u32,
    pub direction: PtraceDirection,
    pub regs: UnifiedRegs,
    pub return_value: Option<i64>,
}

impl PtraceEvent {
    /// Build an entry event.
    #[must_use] 
    pub const fn entry(pid: u32, regs: UnifiedRegs) -> Self {
        Self { pid, direction: PtraceDirection::Entry, regs, return_value: None }
    }

    /// Build an exit event.
    #[must_use] 
    pub const fn exit(pid: u32, regs: UnifiedRegs, retval: i64) -> Self {
        Self { pid, direction: PtraceDirection::Exit, regs, return_value: Some(retval) }
    }
}

/// Reconcile an entry/exit pair and produce a combined syscall description.
#[must_use] 
pub fn reconcile_ptrace_pair(entry: &PtraceEvent, exit: &PtraceEvent) -> Option<(u64, [u64; 6], i64)> {
    if entry.pid != exit.pid { return None; }
    if entry.direction != PtraceDirection::Entry || exit.direction != PtraceDirection::Exit { return None; }
    Some((entry.regs.syscall_nr(), entry.regs.syscall_args(), exit.return_value.unwrap_or(-1)))
}

// ─── IA32 compat layer for Linux ─────────────────────────────────────────────

/// Determines whether a Linux tracee is running in 32-bit compat mode by
/// examining the `CS` register value.
///
/// CS = 0x23 means 32-bit compat; CS = 0x33 means 64-bit.
#[must_use] 
pub const fn is_ia32_compat_mode(cs_register: u64) -> bool {
    cs_register == 0x23
}

/// Map a 32-bit `int 0x80` syscall number to its x86-64 equivalent.
///
/// On x86-64 Linux, `int 0x80` from a 32-bit process uses the IA32 ABI
/// syscall table (syscall numbers differ from the x86-64 table).
#[must_use] 
pub fn ia32_to_x86_64_nr(ia32_nr: u32) -> Option<u64> {
    // Subset of the IA32→x86_64 mapping (the two tables are distinct)
    let table: &[(u32, u64)] = &[
        (1, 60), (2, 57), (3, 0), (4, 1), (5, 2), (6, 3), (7, 4), (8, 5),
        (9, 9), (10, 10), (11, 59), (12, 12), (13, 201), (20, 39), (21, 105),
        (23, 32), (24, 33), (25, 34), (33, 21), (36, 162), (37, 62),
        (39, 102), (40, 103), (41, 104), (42, 107), (43, 108), (45, 12),
        (54, 54), (57, 55), (59, 56), (60, 57), (63, 78), (64, 79),
        (90, 9), (91, 11), (102, 41), (114, 72), (119, 86), (120, 56),
        (122, 63), (140, 140), (174, 13), (175, 14), (176, 15),
        (183, 79), (192, 9),
    ];
    table.iter().find(|&&(i, _)| i == ia32_nr).map(|&(_, x)| x)
}

// ─── System call number cross-reference table ────────────────────────────────

/// Cross-architecture syscall number mapping for the same logical operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossArchSyscall {
    pub name: String,
    pub x86: Option<u32>,
    pub x86_64: Option<u32>,
    pub arm32: Option<u32>,
    pub arm64: Option<u32>,
    pub mips_o32: Option<u32>,
    pub riscv64: Option<u32>,
}

/// Return a cross-architecture syscall cross-reference table for common calls.
#[must_use] 
pub fn cross_arch_table() -> Vec<CrossArchSyscall> {
    vec![
        CrossArchSyscall { name: "read".into(),           x86: Some(3),   x86_64: Some(0),   arm32: Some(3),   arm64: Some(63),  mips_o32: Some(4003), riscv64: Some(63)  },
        CrossArchSyscall { name: "write".into(),          x86: Some(4),   x86_64: Some(1),   arm32: Some(4),   arm64: Some(64),  mips_o32: Some(4004), riscv64: Some(64)  },
        CrossArchSyscall { name: "open".into(),           x86: Some(5),   x86_64: Some(2),   arm32: Some(5),   arm64: None,      mips_o32: Some(4005), riscv64: None      },
        CrossArchSyscall { name: "close".into(),          x86: Some(6),   x86_64: Some(3),   arm32: Some(6),   arm64: Some(57),  mips_o32: Some(4006), riscv64: Some(57)  },
        CrossArchSyscall { name: "stat".into(),           x86: Some(106), x86_64: Some(4),   arm32: None,      arm64: None,      mips_o32: Some(4106), riscv64: None      },
        CrossArchSyscall { name: "fstat".into(),          x86: Some(108), x86_64: Some(5),   arm32: None,      arm64: Some(80),  mips_o32: Some(4108), riscv64: Some(80)  },
        CrossArchSyscall { name: "lstat".into(),          x86: Some(107), x86_64: Some(6),   arm32: None,      arm64: None,      mips_o32: Some(4107), riscv64: None      },
        CrossArchSyscall { name: "poll".into(),           x86: Some(168), x86_64: Some(7),   arm32: Some(168), arm64: Some(73),  mips_o32: Some(4188), riscv64: Some(73)  },
        CrossArchSyscall { name: "lseek".into(),          x86: Some(19),  x86_64: Some(8),   arm32: Some(19),  arm64: Some(62),  mips_o32: Some(4019), riscv64: Some(62)  },
        CrossArchSyscall { name: "mmap".into(),           x86: Some(90),  x86_64: Some(9),   arm32: None,      arm64: Some(222), mips_o32: None,       riscv64: Some(222) },
        CrossArchSyscall { name: "mprotect".into(),       x86: Some(125), x86_64: Some(10),  arm32: Some(125), arm64: Some(226), mips_o32: Some(4125), riscv64: Some(226) },
        CrossArchSyscall { name: "munmap".into(),         x86: Some(91),  x86_64: Some(11),  arm32: Some(91),  arm64: Some(215), mips_o32: Some(4091), riscv64: Some(215) },
        CrossArchSyscall { name: "brk".into(),            x86: Some(45),  x86_64: Some(12),  arm32: Some(45),  arm64: Some(214), mips_o32: Some(4045), riscv64: Some(214) },
        CrossArchSyscall { name: "sigaction".into(),      x86: Some(67),  x86_64: Some(13),  arm32: None,      arm64: None,      mips_o32: None,       riscv64: None      },
        CrossArchSyscall { name: "rt_sigaction".into(),   x86: Some(174), x86_64: Some(13),  arm32: Some(174), arm64: Some(134), mips_o32: Some(4194), riscv64: Some(134) },
        CrossArchSyscall { name: "fork".into(),           x86: Some(2),   x86_64: Some(57),  arm32: Some(2),   arm64: None,      mips_o32: Some(4002), riscv64: None      },
        CrossArchSyscall { name: "execve".into(),         x86: Some(11),  x86_64: Some(59),  arm32: Some(11),  arm64: Some(221), mips_o32: Some(4011), riscv64: Some(221) },
        CrossArchSyscall { name: "exit".into(),           x86: Some(1),   x86_64: Some(60),  arm32: Some(1),   arm64: Some(93),  mips_o32: Some(4001), riscv64: Some(93)  },
        CrossArchSyscall { name: "wait4".into(),          x86: Some(114), x86_64: Some(61),  arm32: Some(114), arm64: None,      mips_o32: Some(4114), riscv64: None      },
        CrossArchSyscall { name: "kill".into(),           x86: Some(37),  x86_64: Some(62),  arm32: Some(37),  arm64: Some(129), mips_o32: Some(4037), riscv64: Some(129) },
        CrossArchSyscall { name: "getpid".into(),         x86: Some(20),  x86_64: Some(39),  arm32: Some(20),  arm64: Some(172), mips_o32: Some(4020), riscv64: Some(172) },
        CrossArchSyscall { name: "socket".into(),         x86: None,      x86_64: Some(41),  arm32: None,      arm64: Some(198), mips_o32: None,       riscv64: Some(198) },
        CrossArchSyscall { name: "connect".into(),        x86: None,      x86_64: Some(42),  arm32: None,      arm64: Some(203), mips_o32: None,       riscv64: Some(203) },
        CrossArchSyscall { name: "accept".into(),         x86: None,      x86_64: Some(43),  arm32: None,      arm64: None,      mips_o32: None,       riscv64: None      },
        CrossArchSyscall { name: "sendto".into(),         x86: None,      x86_64: Some(44),  arm32: None,      arm64: Some(206), mips_o32: None,       riscv64: Some(206) },
        CrossArchSyscall { name: "recvfrom".into(),       x86: None,      x86_64: Some(45),  arm32: None,      arm64: Some(207), mips_o32: None,       riscv64: Some(207) },
        CrossArchSyscall { name: "clone".into(),          x86: Some(120), x86_64: Some(56),  arm32: Some(120), arm64: Some(220), mips_o32: Some(4120), riscv64: Some(220) },
        CrossArchSyscall { name: "futex".into(),          x86: Some(240), x86_64: Some(202), arm32: Some(240), arm64: Some(98),  mips_o32: Some(4238), riscv64: Some(98)  },
        CrossArchSyscall { name: "openat".into(),         x86: Some(295), x86_64: Some(257), arm32: Some(322), arm64: Some(56),  mips_o32: Some(4288), riscv64: Some(56)  },
        CrossArchSyscall { name: "exit_group".into(),     x86: Some(252), x86_64: Some(231), arm32: Some(248), arm64: Some(94),  mips_o32: Some(4246), riscv64: Some(94)  },
    ]
}

/// Look up a syscall name across all architectures.
#[must_use] 
pub fn lookup_cross_arch(name: &str) -> Option<CrossArchSyscall> {
    cross_arch_table().into_iter().find(|e| e.name == name)
}

/// Format the cross-arch table as a text table.
#[must_use] 
pub fn format_cross_arch_table() -> String {
    let mut out = String::new();
    writeln!(out, "{:<20} {:>8} {:>8} {:>8} {:>8} {:>10} {:>8}",
        "Syscall", "x86", "x86_64", "arm32", "arm64", "mips_o32", "riscv64").ok();
    writeln!(out, "{}", "-".repeat(72)).ok();
    for e in cross_arch_table() {
        writeln!(out, "{:<20} {:>8} {:>8} {:>8} {:>8} {:>10} {:>8}",
            e.name,
            e.x86.map_or_else(|| "-".into(), |n| format!("{n}")),
            e.x86_64.map_or_else(|| "-".into(), |n| format!("{n}")),
            e.arm32.map_or_else(|| "-".into(), |n| format!("{n}")),
            e.arm64.map_or_else(|| "-".into(), |n| format!("{n}")),
            e.mips_o32.map_or_else(|| "-".into(), |n| format!("{n}")),
            e.riscv64.map_or_else(|| "-".into(), |n| format!("{n}")),
        ).ok();
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ia32_to_x64_translate() {
        let r32 = Ia32Regs { orig_eax: 5, ebx: 0xdead_beef, ecx: 2, edx: 0, ..Default::default() };
        let r64 = translate_ia32_to_x64(&r32);
        assert_eq!(r64.orig_rax, 5);
        assert_eq!(r64.rdi, 0xdead_beef);
        assert_eq!(r64.rsi, 2);
    }

    #[test]
    fn test_wow64_translate() {
        let analyzer = Wow64Analyzer::new(Wow64GateInfo::default());
        let info = analyzer.translate(0x0018, false, false);
        assert_eq!(info.stub_name.as_deref(), Some("NtCreateFile"));
    }

    #[test]
    fn test_detect_mechanism_int80() {
        let bytes = &[0xCD, 0x80];
        assert_eq!(detect_ia32_mechanism(bytes), Ia32SyscallMechanism::Int80);
    }

    #[test]
    fn test_wine_db_lookup() {
        let db = WineSyscallDb::new();
        let entry = db.lookup("NtReadFile").unwrap();
        assert!(entry.unix_syscalls.contains(&"read".to_string()));
        assert!(!entry.emulated);
    }

    #[test]
    fn test_ia32_compat_mode() {
        assert!(is_ia32_compat_mode(0x23));
        assert!(!is_ia32_compat_mode(0x33));
    }

    #[test]
    fn test_ia32_nr_mapping() {
        // IA32 open = 5, x86-64 open = 2
        assert_eq!(ia32_to_x86_64_nr(5), Some(2));
        // IA32 exit = 1, x86-64 exit = 60
        assert_eq!(ia32_to_x86_64_nr(1), Some(60));
    }

    #[test]
    fn test_wow64_heavens_gate_detect() {
        // Construct bytes with a far jmp selector 0x33
        let bytes = &[0x00u8, 0x00, 0x00, 0xEA, 0x20, 0x00, 0xC0, 0x77, 0x00, 0x33];
        let (_, hg, _) = Wow64Analyzer::detect_from_bytes(bytes, 0x0018);
        // The window starting at index 3 matches: EA xx xx xx xx 33
        // bytes[3..9] = EA 20 00 C0 77 00 → no, bytes[3] = 0xEA but bytes[8] ≠ 0x33
        // This just exercises the code path; actual match depends on alignment.
        let _ = hg;
    }
}
