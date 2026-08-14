//! x86 emulation hooks for shellcode analysis.
//!
//! Provides [`EmulatorHooks`], [`HookType`], the [`HookCallback`] trait, and a
//! collection of concrete hook implementations:
//! - [`TebPebHook`]   — answers FS:[0x30] / GS:[0x60] reads with a fake PEB.
//! - [`WinApiStub`]   — resolves API by name or hash and returns fake handles.
//! - [`SyscallMapper`] — maps syscall numbers to NT function names per OS version.
//! - [`MemoryTracker`] — records written regions, flags self-modification.
//! - [`ApiCallLog`]   — ordered log of all intercepted API calls with arguments.
//! - [`NetworkDetector`] — identifies Winsock initialisation / data-transfer.
//! - [`ExecutionTrace`] — ring buffer of the last 1 000 program counters.

use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// HookType
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of event that triggers a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookType {
    /// A memory read was attempted.
    MemRead,
    /// A memory write was attempted.
    MemWrite,
    /// Code was fetched from memory for execution.
    MemExec,
    /// An instruction is about to execute.
    InsnExec,
    /// A system call is about to be issued.
    SyscallPre,
    /// A system call has returned.
    SyscallPost,
    /// A recognised Windows API stub was called.
    ApiCall,
}

// ─────────────────────────────────────────────────────────────────────────────
// HookEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Data bundled with a hook invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvent {
    /// Program counter at the time of the event.
    pub pc: u64,
    /// Hook kind.
    pub kind: HookType,
    /// Target address (memory access) or syscall number.
    pub address: u64,
    /// Access size in bytes (memory hooks) or 0.
    pub size: usize,
    /// Raw bytes involved, if available.
    pub bytes: Vec<u8>,
    /// Decoded register state snapshot: EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI.
    pub regs: RegisterSnapshot,
}

/// Minimal register snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// HookCallback trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait implemented by every hook.
pub trait HookCallback: Send + Sync {
    /// Human-readable name.
    fn name(&self) -> &str;
    /// Which event types this hook wants to receive.
    fn interest(&self) -> &[HookType];
    /// Called by [`EmulatorHooks`] when a matching event fires.
    /// Returns an optional override value (e.g. bytes to return from a read).
    fn on_event(&mut self, event: &HookEvent) -> HookResult;
}

/// Return value from a hook callback.
#[derive(Debug, Clone, Default)]
pub struct HookResult {
    /// If `Some`, replace the bytes that would normally be read/returned.
    pub override_bytes: Option<Vec<u8>>,
    /// If true, the emulator should halt after this event.
    pub halt: bool,
    /// Optional log line appended to the hook's internal journal.
    pub log_entry: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// EmulatorHooks — dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Central dispatcher: holds all registered [`HookCallback`] implementations
/// and routes events to interested parties.
pub struct EmulatorHooks {
    hooks: Vec<Box<dyn HookCallback>>,
}

impl EmulatorHooks {
    /// Create an empty dispatcher.
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Register a hook implementation.
    pub fn register(&mut self, hook: Box<dyn HookCallback>) {
        self.hooks.push(hook);
    }

    /// Dispatch an event to all interested hooks.
    /// Returns the first non-None override, or None.
    pub fn dispatch(&mut self, event: &HookEvent) -> HookResult {
        let mut combined = HookResult::default();
        for hook in &mut self.hooks {
            if hook.interest().contains(&event.kind) {
                let result = hook.on_event(event);
                if result.halt {
                    combined.halt = true;
                }
                if combined.override_bytes.is_none() {
                    combined.override_bytes = result.override_bytes;
                }
                if let Some(entry) = result.log_entry {
                    if let Some(ref mut existing) = combined.log_entry {
                        existing.push('\n');
                        existing.push_str(&entry);
                    } else {
                        combined.log_entry = Some(entry);
                    }
                }
            }
        }
        combined
    }

    /// Retrieve a hook by name (immutable).
    pub fn get_hook(&self, name: &str) -> Option<&dyn HookCallback> {
        self.hooks.iter()
            .find(|h| h.name() == name)
            .map(|h| h.as_ref())
    }

    /// How many hooks are registered.
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }
}

impl Default for EmulatorHooks {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake PEB layout constants
// ─────────────────────────────────────────────────────────────────────────────

/// Base address of the fake PEB structure in emulator memory space.
pub const FAKE_PEB_BASE: u64 = 0x7FF_E000;

/// Offset of PEB.ImageBaseAddress within the PEB.
pub const PEB_IMAGE_BASE_OFFSET: u64 = 0x08;
/// Offset of PEB.Ldr within the PEB.
pub const PEB_LDR_OFFSET: u64 = 0x0C;
/// Offset of PEB.ProcessParameters within the PEB.
pub const PEB_PROCESS_PARAMS_OFFSET: u64 = 0x10;
/// Offset of PEB.SessionId within the PEB (x86).
pub const PEB_SESSION_ID_OFFSET: u64 = 0x1D4;

/// Address of the fake PEB_LDR_DATA structure.
pub const FAKE_LDR_BASE: u64 = 0x7FF_E100;
/// InMemoryOrderModuleList.Flink offset in LDR_DATA (x86).
pub const LDR_IN_MEMORY_ORDER_FLINK_OFFSET: u64 = 0x14;

// ─────────────────────────────────────────────────────────────────────────────
// TebPebHook
// ─────────────────────────────────────────────────────────────────────────────

/// Intercepts FS:[0x30] / GS:[0x60] memory reads and returns a synthesised PEB.
///
/// The fake PEB contains:
/// - `ImageBaseAddress` → `0x0040_0000` (typical executable base)
/// - `Ldr`              → [`FAKE_LDR_BASE`]
/// - `ProcessParameters`→ a stub process-parameters block
/// - `SessionId`        → `1`
///
/// When the emulator reads from any address in `[FAKE_PEB_BASE, FAKE_PEB_BASE+0x400)`,
/// this hook synthesises the correct 4 bytes.
pub struct TebPebHook {
    /// Number of PEB reads intercepted.
    pub read_count: u64,
    /// Whether to log each interception.
    pub verbose: bool,
}

impl TebPebHook {
    pub fn new(verbose: bool) -> Self {
        Self { read_count: 0, verbose }
    }

    fn peb_bytes_at(offset: u64) -> Option<[u8; 4]> {
        match offset {
            o if o == PEB_IMAGE_BASE_OFFSET => Some(0x0040_0000_u32.to_le_bytes()),
            o if o == PEB_LDR_OFFSET => Some((FAKE_LDR_BASE as u32).to_le_bytes()),
            o if o == PEB_PROCESS_PARAMS_OFFSET => Some(0x0030_0000_u32.to_le_bytes()),
            o if o == PEB_SESSION_ID_OFFSET => Some(1_u32.to_le_bytes()),
            _ => Some(0_u32.to_le_bytes()),
        }
    }

    fn ldr_bytes_at(offset: u64) -> Option<[u8; 4]> {
        // Minimal LDR_DATA: Length=0x28, Initialized=1, InMemoryOrderModuleList → loops back
        match offset {
            0x00 => Some(0x28_u32.to_le_bytes()),     // Length
            0x04 => Some(1_u32.to_le_bytes()),         // Initialized
            o if o == LDR_IN_MEMORY_ORDER_FLINK_OFFSET => {
                // Point at itself for a trivial loop
                Some((FAKE_LDR_BASE as u32 + LDR_IN_MEMORY_ORDER_FLINK_OFFSET as u32).to_le_bytes())
            }
            _ => Some(0_u32.to_le_bytes()),
        }
    }
}

impl HookCallback for TebPebHook {
    fn name(&self) -> &str { "TebPebHook" }

    fn interest(&self) -> &[HookType] {
        &[HookType::MemRead]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        let addr = event.address;

        if addr >= FAKE_PEB_BASE && addr < FAKE_PEB_BASE + 0x400 {
            self.read_count += 1;
            let offset = addr - FAKE_PEB_BASE;
            if let Some(bytes) = Self::peb_bytes_at(offset) {
                let override_bytes = bytes[..event.size.min(4)].to_vec();
                let log = if self.verbose {
                    Some(format!("TebPebHook: PEB read at offset +{:#x} from pc={:#x}", offset, event.pc))
                } else {
                    None
                };
                return HookResult { override_bytes: Some(override_bytes), halt: false, log_entry: log };
            }
        }

        if addr >= FAKE_LDR_BASE && addr < FAKE_LDR_BASE + 0x100 {
            self.read_count += 1;
            let offset = addr - FAKE_LDR_BASE;
            if let Some(bytes) = Self::ldr_bytes_at(offset) {
                let override_bytes = bytes[..event.size.min(4)].to_vec();
                return HookResult {
                    override_bytes: Some(override_bytes),
                    halt: false,
                    log_entry: self.verbose.then(|| format!("TebPebHook: LDR read +{:#x}", offset)),
                };
            }
        }

        HookResult::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WinApiStub
// ─────────────────────────────────────────────────────────────────────────────

/// Maps Windows API names (and common hashes) to stub return values.
///
/// Supported stubs:
/// - `LoadLibraryA`   → returns a fake module handle (0x6000_0000 + sequential).
/// - `GetProcAddress` → resolves from the internal stub table.
/// - `VirtualAlloc`   → returns a new region base (0x3000_0000 + sequential * 0x10000).
/// - `ExitProcess`    → sets the exit flag and requests halt.
/// - `Sleep`          → no-op, logs the requested milliseconds.
/// - `GetTickCount`   → returns a synthetic increasing counter.
/// - `HeapAlloc`      → returns region similar to VirtualAlloc.
/// - `CreateThread`   → logs attempted thread creation, returns fake handle.
#[derive(Default)]
pub struct WinApiStub {
    /// Log of API names called with their ESP value at time of call.
    pub call_log: Vec<(String, u32)>,
    /// Set when `ExitProcess` is intercepted.
    pub exit_requested: bool,
    /// Exit code passed to `ExitProcess`.
    pub exit_code: u32,
    /// Monotonic tick counter returned by `GetTickCount`.
    tick_count: u32,
    /// Next fake module handle index.
    module_handle_index: u32,
    /// Next VirtualAlloc base index.
    valloc_index: u32,
    /// Name → fake address table.
    stub_table: HashMap<String, u64>,
}

impl WinApiStub {
    pub fn new() -> Self {
        let mut stub_table = HashMap::new();
        // Pre-populate with a handful of known addresses so GetProcAddress can answer.
        stub_table.insert("LoadLibraryA".into(), 0x7700_1000);
        stub_table.insert("LoadLibraryW".into(), 0x7700_1010);
        stub_table.insert("GetProcAddress".into(), 0x7700_1020);
        stub_table.insert("VirtualAlloc".into(), 0x7700_1030);
        stub_table.insert("VirtualFree".into(), 0x7700_1040);
        stub_table.insert("ExitProcess".into(), 0x7700_1050);
        stub_table.insert("Sleep".into(), 0x7700_1060);
        stub_table.insert("GetTickCount".into(), 0x7700_1070);
        stub_table.insert("HeapAlloc".into(), 0x7700_1080);
        stub_table.insert("CreateThread".into(), 0x7700_1090);
        stub_table.insert("WSAStartup".into(), 0x7700_10A0);
        stub_table.insert("connect".into(), 0x7700_10B0);
        stub_table.insert("send".into(), 0x7700_10C0);
        stub_table.insert("recv".into(), 0x7700_10D0);
        Self {
            stub_table,
            ..Default::default()
        }
    }

    /// Resolve an API name from the stub table.
    pub fn resolve_name(&self, name: &str) -> Option<u64> {
        self.stub_table.get(name).copied()
    }

    /// Handle a call to a named stub; update internal state and return EAX value.
    pub fn handle_call(&mut self, name: &str, regs: &RegisterSnapshot) -> Option<u32> {
        self.call_log.push((name.to_string(), regs.esp));
        match name {
            "LoadLibraryA" | "LoadLibraryW" => {
                let handle = 0x6000_0000 + self.module_handle_index * 0x1000;
                self.module_handle_index += 1;
                Some(handle)
            }
            "GetProcAddress" => {
                // EBX often holds the target stub address in shellcode after hashing;
                // here we just return a known stub address.
                Some(0x7700_1000)
            }
            "VirtualAlloc" | "HeapAlloc" => {
                let base = 0x3000_0000 + self.valloc_index * 0x1_0000;
                self.valloc_index += 1;
                Some(base)
            }
            "ExitProcess" => {
                self.exit_requested = true;
                self.exit_code = regs.ecx; // stdcall: first arg at ESP+4, simplified here
                None
            }
            "Sleep" => Some(0),
            "GetTickCount" => {
                self.tick_count = self.tick_count.wrapping_add(15);
                Some(self.tick_count)
            }
            "CreateThread" => Some(0x8800_0001),
            "WSAStartup" => Some(0), // WSADATA populated; return 0 = success
            "connect" | "send" | "recv" => Some(0),
            _ => Some(0),
        }
    }
}

impl HookCallback for WinApiStub {
    fn name(&self) -> &str { "WinApiStub" }

    fn interest(&self) -> &[HookType] {
        &[HookType::ApiCall]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        // Decode the API name from log_entry hint or fall back to address lookup.
        let api_name: String = if !event.bytes.is_empty() {
            String::from_utf8_lossy(&event.bytes).trim_end_matches('\0').to_string()
        } else {
            format!("unknown@{:#x}", event.address)
        };

        let eax = self.handle_call(&api_name, &event.regs);
        let halt = self.exit_requested;
        let override_bytes = eax.map(|v| v.to_le_bytes().to_vec());
        let log_entry = Some(format!(
            "WinApiStub: {}(eax={:#x}, ecx={:#x}, edx={:#x}) → {:?}",
            api_name, event.regs.eax, event.regs.ecx, event.regs.edx, eax
        ));
        HookResult { override_bytes, halt, log_entry }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OsVersion + SyscallMapper
// ─────────────────────────────────────────────────────────────────────────────

/// Windows version for syscall-number mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsVersion {
    WindowsXP,
    Windows7,
    Windows10,
}

/// Maps raw syscall numbers (as set in EAX) to NT function names.
///
/// Covers the most common shellcode syscalls:
/// - `NtAllocateVirtualMemory`
/// - `NtWriteVirtualMemory`
/// - `NtCreateThread` / `NtCreateThreadEx`
/// - `NtProtectVirtualMemory`
/// - `NtReadVirtualMemory`
/// - `NtResumeThread`
/// - `NtOpenProcess`
/// - `NtClose`
pub struct SyscallMapper {
    /// Target OS version.
    pub os_version: OsVersion,
    /// Number of syscalls intercepted.
    pub intercept_count: u64,
    /// Ordered list of (syscall_number, resolved_name).
    pub intercept_log: Vec<(u32, String)>,
}

impl SyscallMapper {
    pub fn new(os_version: OsVersion) -> Self {
        Self { os_version, intercept_count: 0, intercept_log: Vec::new() }
    }

    /// Resolve a syscall number to an NT function name.
    pub fn resolve(&self, number: u32) -> Option<&'static str> {
        match self.os_version {
            OsVersion::WindowsXP => Self::resolve_xp(number),
            OsVersion::Windows7 => Self::resolve_win7(number),
            OsVersion::Windows10 => Self::resolve_win10(number),
        }
    }

    fn resolve_xp(n: u32) -> Option<&'static str> {
        match n {
            0x0011 => Some("NtAllocateVirtualMemory"),
            0x0001 => Some("NtAcceptConnectPort"),
            0x0071 => Some("NtWriteVirtualMemory"),
            0x0035 => Some("NtCreateThread"),
            0x0058 => Some("NtProtectVirtualMemory"),
            0x004E => Some("NtReadVirtualMemory"),
            0x0067 => Some("NtResumeThread"),
            0x007A => Some("NtOpenProcess"),
            0x0019 => Some("NtClose"),
            0x00BA => Some("NtCreateSection"),
            0x00B7 => Some("NtMapViewOfSection"),
            _ => None,
        }
    }

    fn resolve_win7(n: u32) -> Option<&'static str> {
        match n {
            0x0015 => Some("NtAllocateVirtualMemory"),
            0x007B => Some("NtWriteVirtualMemory"),
            0x004E => Some("NtCreateThread"),
            0x004D => Some("NtCreateThreadEx"),
            0x004C => Some("NtProtectVirtualMemory"),
            0x003C => Some("NtReadVirtualMemory"),
            0x0052 => Some("NtResumeThread"),
            0x0023 => Some("NtOpenProcess"),
            0x000C => Some("NtClose"),
            0x0055 => Some("NtCreateSection"),
            0x0028 => Some("NtMapViewOfSection"),
            _ => None,
        }
    }

    fn resolve_win10(n: u32) -> Option<&'static str> {
        match n {
            0x0018 => Some("NtAllocateVirtualMemory"),
            0x007A => Some("NtWriteVirtualMemory"),
            0x00C1 => Some("NtCreateThreadEx"),
            0x0050 => Some("NtProtectVirtualMemory"),
            0x003F => Some("NtReadVirtualMemory"),
            0x0053 => Some("NtResumeThread"),
            0x0026 => Some("NtOpenProcess"),
            0x000F => Some("NtClose"),
            0x004A => Some("NtCreateSection"),
            0x0028 => Some("NtMapViewOfSection"),
            0x0025 => Some("NtOpenThread"),
            _ => None,
        }
    }
}

impl HookCallback for SyscallMapper {
    fn name(&self) -> &str { "SyscallMapper" }

    fn interest(&self) -> &[HookType] {
        &[HookType::SyscallPre]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        self.intercept_count += 1;
        let syscall_no = event.regs.eax;
        let name = self.resolve(syscall_no)
            .unwrap_or("unknown_syscall")
            .to_string();
        self.intercept_log.push((syscall_no, name.clone()));
        let log_entry = Some(format!(
            "SyscallMapper: syscall {:#x} ({}) at pc={:#x}",
            syscall_no, name, event.pc
        ));
        HookResult { override_bytes: None, halt: false, log_entry }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryTracker
// ─────────────────────────────────────────────────────────────────────────────

/// A range of addresses [base, base+size).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub base: u64,
    pub size: usize,
}

impl MemRegion {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size as u64
    }

    pub fn overlaps(&self, other: &MemRegion) -> bool {
        self.base < other.base + other.size as u64
            && other.base < self.base + self.size as u64
    }
}

/// Tracks memory writes and detects self-modification (write-then-execute).
pub struct MemoryTracker {
    /// All regions that have been written to.
    pub written_regions: Vec<MemRegion>,
    /// Regions that were written and later executed (self-modification).
    pub self_modified_regions: Vec<MemRegion>,
    /// Total write events observed.
    pub write_count: u64,
    /// Total exec events observed.
    pub exec_count: u64,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            written_regions: Vec::new(),
            self_modified_regions: Vec::new(),
            write_count: 0,
            exec_count: 0,
        }
    }

    fn merge_or_add(&mut self, addr: u64, size: usize) {
        let new_region = MemRegion { base: addr, size };
        // Check if we can extend an existing region.
        for r in &mut self.written_regions {
            if r.base + r.size as u64 == addr {
                r.size += size;
                return;
            }
            if addr + size as u64 == r.base {
                r.base = addr;
                r.size += size;
                return;
            }
            if r.contains(addr) {
                return;
            }
        }
        self.written_regions.push(new_region);
    }

    fn check_self_modify(&mut self, addr: u64, size: usize) {
        let exec_region = MemRegion { base: addr, size };
        for written in &self.written_regions {
            if written.overlaps(&exec_region) {
                if !self.self_modified_regions.contains(written) {
                    self.self_modified_regions.push(*written);
                }
            }
        }
    }

    /// Returns true if any self-modification was detected.
    pub fn has_self_modification(&self) -> bool {
        !self.self_modified_regions.is_empty()
    }
}

impl Default for MemoryTracker {
    fn default() -> Self { Self::new() }
}

impl HookCallback for MemoryTracker {
    fn name(&self) -> &str { "MemoryTracker" }

    fn interest(&self) -> &[HookType] {
        &[HookType::MemWrite, HookType::MemExec]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        match event.kind {
            HookType::MemWrite => {
                self.write_count += 1;
                self.merge_or_add(event.address, event.size.max(1));
            }
            HookType::MemExec => {
                self.exec_count += 1;
                self.check_self_modify(event.address, event.size.max(1));
            }
            _ => {}
        }
        HookResult::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiCallLog
// ─────────────────────────────────────────────────────────────────────────────

/// A single intercepted API call record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    /// Ordinal position in the log.
    pub index: usize,
    /// Program counter of the call instruction.
    pub call_pc: u64,
    /// API name (if resolved).
    pub api_name: String,
    /// Arguments (up to 6) read from the stack.
    pub args: Vec<u32>,
    /// Register state at time of call.
    pub regs: RegisterSnapshot,
}

/// Maintains an ordered log of all API calls with arguments.
#[derive(Default)]
pub struct ApiCallLog {
    pub records: Vec<ApiCallRecord>,
}

impl ApiCallLog {
    pub fn new() -> Self { Self::default() }

    /// Return all records for a given API name.
    pub fn calls_to(&self, api: &str) -> Vec<&ApiCallRecord> {
        self.records.iter().filter(|r| r.api_name == api).collect()
    }

    /// True if the given API was called at least once.
    pub fn was_called(&self, api: &str) -> bool {
        self.records.iter().any(|r| r.api_name == api)
    }

    /// Return the sequence of unique API names called.
    pub fn unique_apis(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in &self.records {
            if seen.insert(r.api_name.clone()) {
                out.push(r.api_name.clone());
            }
        }
        out
    }
}

impl HookCallback for ApiCallLog {
    fn name(&self) -> &str { "ApiCallLog" }

    fn interest(&self) -> &[HookType] {
        &[HookType::ApiCall]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        let api_name = if !event.bytes.is_empty() {
            String::from_utf8_lossy(&event.bytes).trim_end_matches('\0').to_string()
        } else {
            format!("fn@{:#x}", event.address)
        };

        // Try to reconstruct up to 6 args from bytes (pairs of u32 LE).
        let args: Vec<u32> = event.bytes
            .chunks_exact(4)
            .take(6)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        self.records.push(ApiCallRecord {
            index: self.records.len(),
            call_pc: event.pc,
            api_name: api_name.clone(),
            args,
            regs: event.regs.clone(),
        });

        HookResult {
            log_entry: Some(format!("ApiCallLog: #{} {} at {:#x}", self.records.len() - 1, api_name, event.pc)),
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects Winsock-related API calls indicating network activity.
///
/// Triggers on:
/// - `WSAStartup`  — Winsock initialisation
/// - `socket`      — socket creation
/// - `connect`     — outbound connection
/// - `send`        — data transmission
/// - `recv`        — data reception
/// - `WSASend`     — overlapped send
/// - `WSARecv`     — overlapped recv
/// - `closesocket` — socket teardown
#[derive(Default)]
pub struct NetworkDetector {
    pub wsa_started: bool,
    pub socket_count: u32,
    pub connect_count: u32,
    pub send_count: u32,
    pub recv_count: u32,
    pub events: Vec<String>,
}

impl NetworkDetector {
    const NETWORK_APIS: &'static [&'static str] = &[
        "WSAStartup", "socket", "connect", "send", "recv",
        "WSASend", "WSARecv", "closesocket", "bind", "listen", "accept",
        "WSAConnect", "WSASocket",
    ];

    pub fn new() -> Self { Self::default() }

    /// True if any network activity was detected.
    pub fn has_network_activity(&self) -> bool {
        self.wsa_started || self.connect_count > 0 || self.send_count > 0 || self.recv_count > 0
    }
}

impl HookCallback for NetworkDetector {
    fn name(&self) -> &str { "NetworkDetector" }

    fn interest(&self) -> &[HookType] {
        &[HookType::ApiCall]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        let api = String::from_utf8_lossy(&event.bytes).trim_end_matches('\0').to_string();
        if !Self::NETWORK_APIS.contains(&api.as_str()) {
            return HookResult::default();
        }
        let entry = format!("NetworkDetector: {} at pc={:#x}", api, event.pc);
        match api.as_str() {
            "WSAStartup" => self.wsa_started = true,
            "socket" | "WSASocket" => self.socket_count += 1,
            "connect" | "WSAConnect" => self.connect_count += 1,
            "send" | "WSASend" => self.send_count += 1,
            "recv" | "WSARecv" => self.recv_count += 1,
            _ => {}
        }
        self.events.push(entry.clone());
        HookResult { log_entry: Some(entry), ..Default::default() }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionTrace — ring buffer
// ─────────────────────────────────────────────────────────────────────────────

/// Ring buffer holding the last N program counters executed.
pub struct ExecutionTrace {
    /// Underlying ring buffer.
    buffer: VecDeque<u64>,
    /// Maximum number of entries to keep.
    pub capacity: usize,
    /// Total instructions seen (never capped).
    pub total_insns: u64,
}

impl ExecutionTrace {
    /// Create a new trace with the given capacity (default 1000).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            total_insns: 0,
        }
    }

    pub fn new() -> Self { Self::with_capacity(1000) }

    /// Push a PC into the ring buffer.
    pub fn push(&mut self, pc: u64) {
        if self.buffer.len() == self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(pc);
        self.total_insns += 1;
    }

    /// Snapshot of the ring buffer contents.
    pub fn snapshot(&self) -> Vec<u64> {
        self.buffer.iter().copied().collect()
    }

    /// True if `pc` appears in the ring buffer.
    pub fn contains(&self, pc: u64) -> bool {
        self.buffer.contains(&pc)
    }

    /// Detect simple back-edge loops: addresses that appear more than `threshold` times.
    pub fn detect_loops(&self, threshold: usize) -> Vec<(u64, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for &pc in &self.buffer {
            *counts.entry(pc).or_insert(0) += 1;
        }
        let mut loops: Vec<_> = counts.into_iter().filter(|(_, c)| *c > threshold).collect();
        // Drained from a HashMap: tie-break on the address so equally frequent
        // back edges are reported in a reproducible order.
        loops.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        loops
    }

    /// Last recorded PC, if any.
    pub fn last_pc(&self) -> Option<u64> {
        self.buffer.back().copied()
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self { Self::new() }
}

impl HookCallback for ExecutionTrace {
    fn name(&self) -> &str { "ExecutionTrace" }

    fn interest(&self) -> &[HookType] {
        &[HookType::InsnExec]
    }

    fn on_event(&mut self, event: &HookEvent) -> HookResult {
        self.push(event.pc);
        HookResult::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROR13 hash helper (used by test harness)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the ROR13 additive hash over an ASCII string (Windows API hashing).
pub fn ror13_hash(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for b in s.bytes() {
        hash = hash.rotate_right(13).wrapping_add(b as u32);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: HookType, pc: u64, address: u64, size: usize) -> HookEvent {
        HookEvent {
            pc, kind, address, size,
            bytes: Vec::new(),
            regs: RegisterSnapshot::default(),
        }
    }

    fn make_api_event(pc: u64, name: &str, regs: RegisterSnapshot) -> HookEvent {
        HookEvent {
            pc,
            kind: HookType::ApiCall,
            address: 0x7700_1000,
            size: 0,
            bytes: name.as_bytes().to_vec(),
            regs,
        }
    }

    // ── TebPebHook ────────────────────────────────────────────────────────────

    #[test]
    fn test_teb_peb_hook_image_base() {
        let mut hook = TebPebHook::new(false);
        let mut ev = make_event(HookType::MemRead, 0x1000, FAKE_PEB_BASE + PEB_IMAGE_BASE_OFFSET, 4);
        ev.size = 4;
        let result = hook.on_event(&ev);
        assert!(result.override_bytes.is_some());
        let bytes = result.override_bytes.unwrap();
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(val, 0x0040_0000);
    }

    #[test]
    fn test_teb_peb_hook_ldr() {
        let mut hook = TebPebHook::new(false);
        let mut ev = make_event(HookType::MemRead, 0x1000, FAKE_PEB_BASE + PEB_LDR_OFFSET, 4);
        ev.size = 4;
        let result = hook.on_event(&ev);
        let bytes = result.override_bytes.unwrap();
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(val as u64, FAKE_LDR_BASE);
    }

    #[test]
    fn test_teb_peb_hook_session_id() {
        let mut hook = TebPebHook::new(false);
        let mut ev = make_event(HookType::MemRead, 0x1000, FAKE_PEB_BASE + PEB_SESSION_ID_OFFSET, 4);
        ev.size = 4;
        let result = hook.on_event(&ev);
        let bytes = result.override_bytes.unwrap();
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(val, 1);
    }

    #[test]
    fn test_teb_peb_hook_ldr_self_loop() {
        let mut hook = TebPebHook::new(false);
        let flink_addr = FAKE_LDR_BASE + LDR_IN_MEMORY_ORDER_FLINK_OFFSET;
        let mut ev = make_event(HookType::MemRead, 0x1000, flink_addr, 4);
        ev.size = 4;
        let result = hook.on_event(&ev);
        assert!(result.override_bytes.is_some());
    }

    #[test]
    fn test_teb_peb_hook_read_count() {
        let mut hook = TebPebHook::new(false);
        for i in 0..5u64 {
            let mut ev = make_event(HookType::MemRead, 0x1000, FAKE_PEB_BASE + i * 4, 4);
            ev.size = 4;
            hook.on_event(&ev);
        }
        assert_eq!(hook.read_count, 5);
    }

    #[test]
    fn test_teb_peb_hook_ignores_other_addresses() {
        let mut hook = TebPebHook::new(false);
        let ev = make_event(HookType::MemRead, 0x1000, 0x0040_0000, 4);
        let result = hook.on_event(&ev);
        assert!(result.override_bytes.is_none());
        assert_eq!(hook.read_count, 0);
    }

    // ── WinApiStub ────────────────────────────────────────────────────────────

    #[test]
    fn test_winapi_stub_load_library() {
        let mut stub = WinApiStub::new();
        let regs = RegisterSnapshot::default();
        let result = stub.handle_call("LoadLibraryA", &regs);
        assert!(result.is_some());
        assert!(result.unwrap() >= 0x6000_0000);
    }

    #[test]
    fn test_winapi_stub_virtual_alloc_sequential() {
        let mut stub = WinApiStub::new();
        let regs = RegisterSnapshot::default();
        let a = stub.handle_call("VirtualAlloc", &regs).unwrap();
        let b = stub.handle_call("VirtualAlloc", &regs).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_winapi_stub_exit_process_sets_flag() {
        let mut stub = WinApiStub::new();
        let regs = RegisterSnapshot::default();
        stub.handle_call("ExitProcess", &regs);
        assert!(stub.exit_requested);
    }

    #[test]
    fn test_winapi_stub_get_tick_count_increments() {
        let mut stub = WinApiStub::new();
        let regs = RegisterSnapshot::default();
        let t1 = stub.handle_call("GetTickCount", &regs).unwrap();
        let t2 = stub.handle_call("GetTickCount", &regs).unwrap();
        assert!(t2 > t1);
    }

    #[test]
    fn test_winapi_stub_resolve_name() {
        let stub = WinApiStub::new();
        assert!(stub.resolve_name("LoadLibraryA").is_some());
        assert!(stub.resolve_name("VirtualAlloc").is_some());
        assert!(stub.resolve_name("NonExistentApi_Xyz").is_none());
    }

    // ── SyscallMapper ─────────────────────────────────────────────────────────

    #[test]
    fn test_syscall_mapper_xp_alloc() {
        let mapper = SyscallMapper::new(OsVersion::WindowsXP);
        assert_eq!(mapper.resolve(0x0011), Some("NtAllocateVirtualMemory"));
    }

    #[test]
    fn test_syscall_mapper_win7_create_thread_ex() {
        let mapper = SyscallMapper::new(OsVersion::Windows7);
        assert_eq!(mapper.resolve(0x004D), Some("NtCreateThreadEx"));
    }

    #[test]
    fn test_syscall_mapper_win10_protect() {
        let mapper = SyscallMapper::new(OsVersion::Windows10);
        assert_eq!(mapper.resolve(0x0050), Some("NtProtectVirtualMemory"));
    }

    #[test]
    fn test_syscall_mapper_unknown_returns_none() {
        let mapper = SyscallMapper::new(OsVersion::Windows10);
        assert_eq!(mapper.resolve(0xFFFF), None);
    }

    #[test]
    fn test_syscall_mapper_logs_intercepts() {
        let mut mapper = SyscallMapper::new(OsVersion::Windows7);
        let mut ev = make_event(HookType::SyscallPre, 0x1000, 0, 0);
        ev.regs.eax = 0x0015;
        mapper.on_event(&ev);
        assert_eq!(mapper.intercept_count, 1);
        assert_eq!(mapper.intercept_log[0].1, "NtAllocateVirtualMemory");
    }

    // ── MemoryTracker ─────────────────────────────────────────────────────────

    #[test]
    fn test_memory_tracker_no_self_mod_by_default() {
        let tracker = MemoryTracker::new();
        assert!(!tracker.has_self_modification());
    }

    #[test]
    fn test_memory_tracker_detects_self_modification() {
        let mut tracker = MemoryTracker::new();
        // Write at 0x5000
        let write_ev = make_event(HookType::MemWrite, 0x1000, 0x5000, 64);
        tracker.on_event(&write_ev);
        // Execute from same region
        let exec_ev = make_event(HookType::MemExec, 0x1000, 0x5010, 16);
        tracker.on_event(&exec_ev);
        assert!(tracker.has_self_modification());
    }

    #[test]
    fn test_memory_tracker_no_self_mod_different_region() {
        let mut tracker = MemoryTracker::new();
        let write_ev = make_event(HookType::MemWrite, 0x1000, 0x5000, 64);
        tracker.on_event(&write_ev);
        let exec_ev = make_event(HookType::MemExec, 0x1000, 0x9000, 16);
        tracker.on_event(&exec_ev);
        assert!(!tracker.has_self_modification());
    }

    // ── ApiCallLog ────────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_log_records_calls() {
        let mut log = ApiCallLog::new();
        let ev = make_api_event(0x1000, "VirtualAlloc", RegisterSnapshot::default());
        log.on_event(&ev);
        assert!(log.was_called("VirtualAlloc"));
        assert_eq!(log.calls_to("VirtualAlloc").len(), 1);
    }

    #[test]
    fn test_api_call_log_unique_apis() {
        let mut log = ApiCallLog::new();
        log.on_event(&make_api_event(0x1000, "LoadLibraryA", RegisterSnapshot::default()));
        log.on_event(&make_api_event(0x2000, "VirtualAlloc", RegisterSnapshot::default()));
        log.on_event(&make_api_event(0x3000, "LoadLibraryA", RegisterSnapshot::default()));
        let uniq = log.unique_apis();
        assert_eq!(uniq.len(), 2);
    }

    // ── NetworkDetector ───────────────────────────────────────────────────────

    #[test]
    fn test_network_detector_wsa_startup() {
        let mut nd = NetworkDetector::new();
        let ev = make_api_event(0x1000, "WSAStartup", RegisterSnapshot::default());
        nd.on_event(&ev);
        assert!(nd.wsa_started);
        assert!(nd.has_network_activity());
    }

    #[test]
    fn test_network_detector_connect_send() {
        let mut nd = NetworkDetector::new();
        nd.on_event(&make_api_event(0x1000, "connect", RegisterSnapshot::default()));
        nd.on_event(&make_api_event(0x1004, "send", RegisterSnapshot::default()));
        assert_eq!(nd.connect_count, 1);
        assert_eq!(nd.send_count, 1);
    }

    #[test]
    fn test_network_detector_ignores_non_network_apis() {
        let mut nd = NetworkDetector::new();
        nd.on_event(&make_api_event(0x1000, "VirtualAlloc", RegisterSnapshot::default()));
        assert!(!nd.has_network_activity());
    }

    // ── ExecutionTrace ────────────────────────────────────────────────────────

    #[test]
    fn test_execution_trace_capacity_capped() {
        let mut trace = ExecutionTrace::with_capacity(10);
        for i in 0..20u64 {
            trace.push(i);
        }
        assert_eq!(trace.snapshot().len(), 10);
        assert_eq!(trace.total_insns, 20);
    }

    #[test]
    fn test_execution_trace_last_pc() {
        let mut trace = ExecutionTrace::new();
        trace.push(0x1000);
        trace.push(0x1004);
        assert_eq!(trace.last_pc(), Some(0x1004));
    }

    #[test]
    fn test_execution_trace_loop_detection() {
        let mut trace = ExecutionTrace::with_capacity(200);
        for _ in 0..50 {
            trace.push(0x2000);
        }
        trace.push(0x3000);
        let loops = trace.detect_loops(10);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].0, 0x2000);
    }

    // ── EmulatorHooks dispatcher ──────────────────────────────────────────────

    #[test]
    fn test_emulator_hooks_dispatch_routes_correctly() {
        let mut hooks = EmulatorHooks::new();
        hooks.register(Box::new(ExecutionTrace::new()));
        let ev = make_event(HookType::InsnExec, 0x1000, 0x1000, 4);
        let result = hooks.dispatch(&ev);
        assert!(!result.halt);
        // The MemWrite hook should not fire for InsnExec
        hooks.register(Box::new(MemoryTracker::new()));
        let ev2 = make_event(HookType::MemWrite, 0x1000, 0x5000, 8);
        hooks.dispatch(&ev2);
    }

    #[test]
    fn test_emulator_hooks_count() {
        let mut hooks = EmulatorHooks::new();
        assert_eq!(hooks.hook_count(), 0);
        hooks.register(Box::new(ExecutionTrace::new()));
        hooks.register(Box::new(NetworkDetector::new()));
        assert_eq!(hooks.hook_count(), 2);
    }

    // ── ROR13 hash ────────────────────────────────────────────────────────────

    #[test]
    fn test_ror13_hash_deterministic() {
        let h1 = ror13_hash("LoadLibraryA");
        let h2 = ror13_hash("LoadLibraryA");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ror13_hash_differs_for_different_names() {
        assert_ne!(ror13_hash("LoadLibraryA"), ror13_hash("GetProcAddress"));
    }

    #[test]
    fn test_mem_region_contains() {
        let r = MemRegion { base: 0x1000, size: 0x100 };
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
    }

    #[test]
    fn test_mem_region_overlaps() {
        let r1 = MemRegion { base: 0x1000, size: 0x200 };
        let r2 = MemRegion { base: 0x1100, size: 0x200 };
        assert!(r1.overlaps(&r2));
        let r3 = MemRegion { base: 0x2000, size: 0x100 };
        assert!(!r1.overlaps(&r3));
    }
}
