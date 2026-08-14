//! API monitoring hooks: record and replay user-mode API calls via in-memory
//! trampoline descriptors.
//!
//! This module provides [`ApiMonitorHooks`] which manages a registry of
//! [`HookEntry`] records.  Each entry describes one hooked function: the
//! original virtual address, a synthetic trampoline descriptor, the call
//! signature, and a log of every recorded invocation.
//!
//! No OS-level patching is performed here — this module is an **in-process
//! analysis layer** suitable for emulator integration, offline trace analysis,
//! and unit testing.  The actual byte patching (e.g. writing a JMP or INT3
//! at the target address) is the caller's responsibility.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the API monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    /// A hook for this address already exists.
    AlreadyHooked(u64),
    /// No hook was found for the given address.
    NotHooked(u64),
    /// The hook ID was not found.
    HookIdNotFound(u64),
    /// The function name was not found.
    NameNotFound(String),
    /// The trampoline byte buffer is too short.
    TrampolineBufferTooShort { needed: usize, got: usize },
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyHooked(a) => write!(f, "address {a:#x} already hooked"),
            Self::NotHooked(a) => write!(f, "address {a:#x} not hooked"),
            Self::HookIdNotFound(id) => write!(f, "hook id {id} not found"),
            Self::NameNotFound(n) => write!(f, "function '{n}' not found"),
            Self::TrampolineBufferTooShort { needed, got } =>
                write!(f, "trampoline buffer too short: need {needed}, got {got}"),
        }
    }
}

impl std::error::Error for HookError {}

// ── Argument / return value types ─────────────────────────────────────────────

/// A single argument value passed to (or returned from) an API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    Ptr(u64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Null,
}

impl fmt::Display for ArgValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v:#04x}"),
            Self::U16(v) => write!(f, "{v:#06x}"),
            Self::U32(v) => write!(f, "{v:#010x}"),
            Self::U64(v) => write!(f, "{v:#018x}"),
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}"),
            Self::Ptr(v) => write!(f, "ptr({v:#018x})"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s:?}"),
            Self::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Self::Null => write!(f, "NULL"),
        }
    }
}

// ── CallRecord ────────────────────────────────────────────────────────────────

/// A single recorded invocation of a hooked function.
#[derive(Debug, Clone)]
pub struct CallRecord {
    /// Monotonic call sequence number across all hooks.
    pub call_id: u64,
    /// Name of the function that was called.
    pub function_name: String,
    /// Virtual address of the hooked function.
    pub target_address: u64,
    /// Caller's return address (instruction pointer when the call was logged).
    pub caller_address: u64,
    /// Arguments in order.
    pub args: Vec<ArgValue>,
    /// Return value (populated after the call returns).
    pub return_value: Option<ArgValue>,
    /// Process and thread IDs if known.
    pub pid: u32,
    pub tid: u32,
    /// Simple sequential timestamp (call number at time of log).
    pub timestamp: u64,
}

impl fmt::Display for CallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}(", self.call_id, self.function_name)?;
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{arg}")?;
        }
        write!(f, ")")?;
        if let Some(rv) = &self.return_value {
            write!(f, " -> {rv}")?;
        }
        Ok(())
    }
}

// ── ArgumentDescriptor ───────────────────────────────────────────────────────

/// Describes one argument of an API function.
#[derive(Debug, Clone)]
pub struct ArgumentDescriptor {
    pub name: String,
    pub type_name: String,
    /// `true` if this argument is an output pointer.
    pub is_out: bool,
}

impl ArgumentDescriptor {
    pub fn new(name: impl Into<String>, type_name: impl Into<String>, is_out: bool) -> Self {
        Self { name: name.into(), type_name: type_name.into(), is_out }
    }
}

// ── CallingConvention ─────────────────────────────────────────────────────────

/// The calling convention of the hooked function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Windows x64 (first 4 args in rcx, rdx, r8, r9; rest on stack).
    MicrosoftX64,
    /// x86 stdcall (args right-to-left on stack; callee cleans).
    Stdcall,
    /// x86 cdecl (args right-to-left on stack; caller cleans).
    Cdecl,
    /// x86 fastcall (first 2 in ecx/edx, rest on stack).
    Fastcall,
    /// ARM64 AAPCS (first 8 args in x0-x7).
    Aapcs64,
    /// Unknown / not determined.
    Unknown,
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MicrosoftX64 => "ms_x64",
            Self::Stdcall => "stdcall",
            Self::Cdecl => "cdecl",
            Self::Fastcall => "fastcall",
            Self::Aapcs64 => "aapcs64",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ── TrampolineHook ────────────────────────────────────────────────────────────

/// A synthetic trampoline descriptor.
///
/// In a real implementation this would contain the saved original bytes and the
/// address of an allocated trampoline stub.  Here we record only the metadata.
#[derive(Debug, Clone)]
pub struct TrampolineHook {
    /// The virtual address that has been hooked.
    pub target_address: u64,
    /// The address of the synthetic trampoline (allocator-assigned).
    pub trampoline_address: u64,
    /// The original bytes that were overwritten at `target_address` (up to 16).
    pub saved_bytes: Vec<u8>,
    /// `true` if the trampoline is currently active (bytes written).
    pub active: bool,
}

impl TrampolineHook {
    /// Build a trampoline from a target address and a slice of original bytes.
    ///
    /// `trampoline_address` is caller-supplied (e.g. from an allocator).
    #[must_use]
    pub fn new(target_address: u64, trampoline_address: u64, original_bytes: &[u8]) -> Self {
        Self {
            target_address,
            trampoline_address,
            saved_bytes: original_bytes.to_vec(),
            active: false,
        }
    }

    /// Generate a minimal x64 absolute JMP stub (14 bytes) targeting
    /// `hook_handler_address`.  Returns the bytes to write at `target_address`.
    #[must_use]
    pub fn generate_jmp_stub(hook_handler_address: u64) -> Vec<u8> {
        // FF 25 00000000      JMP [RIP+0]
        // <little-endian 64-bit address>
        let mut stub = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        stub.extend_from_slice(&hook_handler_address.to_le_bytes());
        stub
    }

    /// Return `true` if `original_bytes` at the hook site still match the saved bytes.
    #[must_use]
    pub fn validate_saved_bytes(&self, current_bytes: &[u8]) -> bool {
        let len = self.saved_bytes.len().min(current_bytes.len());
        self.saved_bytes[..len] == current_bytes[..len]
    }
}

// ── HookEntry ─────────────────────────────────────────────────────────────────

/// One registered API hook.
#[derive(Debug)]
pub struct HookEntry {
    /// Unique hook ID.
    pub id: u64,
    /// Module name (e.g. `"ntdll.dll"`).
    pub module_name: String,
    /// Function name (e.g. `"NtCreateFile"`).
    pub function_name: String,
    /// Virtual address of the function.
    pub target_address: u64,
    /// Calling convention.
    pub calling_convention: CallingConvention,
    /// Argument descriptors.
    pub args: Vec<ArgumentDescriptor>,
    /// Return type name.
    pub return_type: String,
    /// Trampoline descriptor.
    pub trampoline: TrampolineHook,
    /// Whether this hook is currently enabled.
    pub enabled: bool,
    /// All call records for this hook.
    pub call_log: Vec<CallRecord>,
}

impl HookEntry {
    /// Total number of times this hook has been invoked.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.call_log.len()
    }

    /// Return the most recent call record, if any.
    #[must_use]
    pub fn last_call(&self) -> Option<&CallRecord> {
        self.call_log.last()
    }

    /// Clear the call log.
    pub fn clear_log(&mut self) {
        self.call_log.clear();
    }
}

impl fmt::Display for HookEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}!{} @ {:#018x}  calls={}  enabled={}",
            self.id, self.module_name, self.function_name,
            self.target_address, self.call_log.len(), self.enabled
        )
    }
}

// ── InstallHookParams ─────────────────────────────────────────────────────────

/// Parameters for [`ApiMonitorHooks::install_hook`], bundled to avoid exceeding
/// the argument count lint limit.
pub struct InstallHookParams {
    /// Name of the module containing the target function (e.g. `kernel32.dll`).
    pub module_name: String,
    /// Name of the function to hook (e.g. `CreateFileW`).
    pub function_name: String,
    /// Calling convention used by the target.
    pub calling_convention: CallingConvention,
    /// Argument descriptors for the target function.
    pub args: Vec<ArgumentDescriptor>,
    /// Return type name (e.g. `HANDLE`).
    pub return_type: String,
    /// Bytes currently at `target_address` (used to build the trampoline).
    pub original_bytes: Vec<u8>,
}

impl InstallHookParams {
    /// Construct params from individual values.
    #[must_use]
    pub fn new(
        module_name: impl Into<String>,
        function_name: impl Into<String>,
        calling_convention: CallingConvention,
        args: Vec<ArgumentDescriptor>,
        return_type: impl Into<String>,
        original_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            function_name: function_name.into(),
            calling_convention,
            args,
            return_type: return_type.into(),
            original_bytes: original_bytes.into(),
        }
    }
}

// ── ApiMonitorHooks ───────────────────────────────────────────────────────────

/// Registry of API monitoring hooks.
pub struct ApiMonitorHooks {
    /// All hooks keyed by their unique ID.
    hooks_by_id: HashMap<u64, HookEntry>,
    /// Address → hook ID index.
    hooks_by_address: HashMap<u64, u64>,
    /// (`module_lower`, `function_lower`) → hook ID index.
    hooks_by_name: HashMap<(String, String), u64>,
    /// Monotonic hook-ID counter.
    next_id: u64,
    /// Monotonic call-ID counter (shared across all hooks).
    call_counter: AtomicU64,
    /// Monotonic trampoline address allocator base.
    trampoline_base: u64,
    next_trampoline_offset: u64,
}

impl ApiMonitorHooks {
    /// Create a new registry.  `trampoline_alloc_base` is the virtual address at
    /// which synthetic trampoline stubs will be assigned sequentially (64 bytes
    /// each).
    #[must_use]
    pub fn new(trampoline_alloc_base: u64) -> Self {
        Self {
            hooks_by_id: HashMap::new(),
            hooks_by_address: HashMap::new(),
            hooks_by_name: HashMap::new(),
            next_id: 1,
            call_counter: AtomicU64::new(0),
            trampoline_base: trampoline_alloc_base,
            next_trampoline_offset: 0,
        }
    }

    /// Allocate the next trampoline address (64-byte slots).
    const fn alloc_trampoline_address(&mut self) -> u64 {
        let addr = self.trampoline_base + self.next_trampoline_offset;
        self.next_trampoline_offset += 64;
        addr
    }

    /// Install a hook for the function described by `params` at `target_address`.
    ///
    /// `params.original_bytes` should be the bytes currently at `target_address`
    /// (used to build the trampoline saved-bytes field).
    ///
    /// # Errors
    /// Returns [`HookError::AlreadyHooked`] if the address is already hooked.
    pub fn install_hook(
        &mut self,
        target_address: u64,
        params: InstallHookParams,
    ) -> Result<u64, HookError> {
        if self.hooks_by_address.contains_key(&target_address) {
            return Err(HookError::AlreadyHooked(target_address));
        }
        let id = self.next_id;
        self.next_id += 1;

        let module_name = params.module_name;
        let function_name = params.function_name;
        let trampoline_address = self.alloc_trampoline_address();
        let trampoline = TrampolineHook::new(target_address, trampoline_address, &params.original_bytes);

        let entry = HookEntry {
            id,
            module_name: module_name.clone(),
            function_name: function_name.clone(),
            target_address,
            calling_convention: params.calling_convention,
            args: params.args,
            return_type: params.return_type,
            trampoline,
            enabled: true,
            call_log: Vec::new(),
        };

        self.hooks_by_address.insert(target_address, id);
        self.hooks_by_name.insert(
            (module_name.to_lowercase(), function_name.to_lowercase()),
            id,
        );
        self.hooks_by_id.insert(id, entry);
        Ok(id)
    }

    /// Remove a hook by ID.  Restores enabled state to `false` (caller must
    /// patch original bytes back at `target_address`).
    ///
    /// # Errors
    /// Returns [`HookError::HookIdNotFound`] if the ID does not exist.
    pub fn remove_hook(&mut self, hook_id: u64) -> Result<HookEntry, HookError> {
        let entry = self.hooks_by_id.remove(&hook_id)
            .ok_or(HookError::HookIdNotFound(hook_id))?;
        self.hooks_by_address.remove(&entry.target_address);
        self.hooks_by_name.remove(&(
            entry.module_name.to_lowercase(),
            entry.function_name.to_lowercase(),
        ));
        Ok(entry)
    }

    /// Enable or disable a hook by ID.
    ///
    /// # Errors
    /// Returns [`HookError::HookIdNotFound`] if `hook_id` is not registered.
    pub fn set_enabled(&mut self, hook_id: u64, enabled: bool) -> Result<(), HookError> {
        let entry = self.hooks_by_id.get_mut(&hook_id)
            .ok_or(HookError::HookIdNotFound(hook_id))?;
        entry.enabled = enabled;
        Ok(())
    }

    /// Log a call to the hook identified by `target_address`.
    ///
    /// Returns the assigned `call_id`.
    ///
    /// # Errors
    /// Returns [`HookError::NotHooked`] if the address is not hooked, or
    /// silently returns without logging if the hook is disabled.
    ///
    /// # Panics
    /// Panics if internal index consistency is violated (hook ID found in address
    /// index but not in the main id→entry map, which should never happen).
    pub fn log_call(
        &mut self,
        target_address: u64,
        caller_address: u64,
        args: Vec<ArgValue>,
        return_value: Option<ArgValue>,
        pid: u32,
        tid: u32,
    ) -> Result<u64, HookError> {
        let hook_id = *self.hooks_by_address.get(&target_address)
            .ok_or(HookError::NotHooked(target_address))?;
        let entry = self.hooks_by_id.get_mut(&hook_id).unwrap();
        if !entry.enabled {
            return Ok(0);
        }
        let call_id = self.call_counter.fetch_add(1, Ordering::Relaxed);
        let timestamp = call_id;
        let record = CallRecord {
            call_id,
            function_name: entry.function_name.clone(),
            target_address,
            caller_address,
            args,
            return_value,
            pid,
            tid,
            timestamp,
        };
        entry.call_log.push(record);
        Ok(call_id)
    }

    /// Look up a hook by address.
    #[must_use]
    pub fn hook_by_address(&self, address: u64) -> Option<&HookEntry> {
        let id = self.hooks_by_address.get(&address)?;
        self.hooks_by_id.get(id)
    }

    /// Look up a hook by address (mutable).
    pub fn hook_by_address_mut(&mut self, address: u64) -> Option<&mut HookEntry> {
        let id = *self.hooks_by_address.get(&address)?;
        self.hooks_by_id.get_mut(&id)
    }

    /// Look up a hook by (`module_name`, `function_name`).
    #[must_use]
    pub fn hook_by_name(&self, module: &str, function: &str) -> Option<&HookEntry> {
        let id = self.hooks_by_name.get(&(
            module.to_lowercase(),
            function.to_lowercase(),
        ))?;
        self.hooks_by_id.get(id)
    }

    /// Return all hooks, sorted by ID.
    #[must_use]
    pub fn all_hooks(&self) -> Vec<&HookEntry> {
        let mut hooks: Vec<&HookEntry> = self.hooks_by_id.values().collect();
        hooks.sort_by_key(|h| h.id);
        hooks
    }

    /// Return the total number of installed hooks.
    #[must_use]
    pub fn hook_count(&self) -> usize {
        self.hooks_by_id.len()
    }

    /// Return the total number of logged calls across all hooks.
    #[must_use]
    pub fn total_call_count(&self) -> u64 {
        self.call_counter.load(Ordering::Relaxed)
    }

    /// Return all call records across all hooks, sorted by `call_id`.
    #[must_use]
    pub fn all_call_records(&self) -> Vec<&CallRecord> {
        let mut records: Vec<&CallRecord> = self
            .hooks_by_id
            .values()
            .flat_map(|h| h.call_log.iter())
            .collect();
        records.sort_by_key(|r| r.call_id);
        records
    }

    /// Return call records for a specific function name (case-insensitive).
    #[must_use]
    pub fn calls_for_function(&self, function_name: &str) -> Vec<&CallRecord> {
        let lower = function_name.to_lowercase();
        let mut records: Vec<&CallRecord> = self
            .hooks_by_id
            .values()
            .filter(|h| h.function_name.to_lowercase() == lower)
            .flat_map(|h| h.call_log.iter())
            .collect();
        records.sort_by_key(|r| r.call_id);
        records
    }

    /// Clear the call log for a specific hook.
    ///
    /// # Errors
    /// Returns [`HookError::HookIdNotFound`] if `hook_id` is not registered.
    pub fn clear_log(&mut self, hook_id: u64) -> Result<(), HookError> {
        let entry = self.hooks_by_id.get_mut(&hook_id)
            .ok_or(HookError::HookIdNotFound(hook_id))?;
        entry.call_log.clear();
        Ok(())
    }

    /// Clear all call logs.
    pub fn clear_all_logs(&mut self) {
        for entry in self.hooks_by_id.values_mut() {
            entry.call_log.clear();
        }
        self.call_counter.store(0, Ordering::Relaxed);
    }

    /// Return a summary of all hooks.
    #[must_use]
    pub fn summary(&self) -> HooksSummary {
        let total_calls: usize = self.hooks_by_id.values().map(|h| h.call_log.len()).sum();
        let enabled_count = self.hooks_by_id.values().filter(|h| h.enabled).count();
        HooksSummary {
            total_hooks: self.hooks_by_id.len(),
            enabled_hooks: enabled_count,
            total_logged_calls: total_calls,
        }
    }
}

impl fmt::Debug for ApiMonitorHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.summary();
        write!(
            f,
            "ApiMonitorHooks {{ hooks: {}, enabled: {}, calls: {} }}",
            s.total_hooks, s.enabled_hooks, s.total_logged_calls
        )
    }
}

/// Summary statistics for [`ApiMonitorHooks`].
#[derive(Debug, Clone)]
pub struct HooksSummary {
    pub total_hooks: usize,
    pub enabled_hooks: usize,
    pub total_logged_calls: usize,
}

// ── Well-known Windows API hook builders ──────────────────────────────────────

/// Build a pre-configured [`ApiMonitorHooks`] with descriptors for common
/// `ntdll` / `kernel32` / `ws2_32` functions.
///
/// No actual byte patching is done; callers must supply `original_bytes` and
/// perform patching themselves.
///
/// Addresses are set to well-known placeholder values (`0xFFFF_0000 + index`).
#[must_use]
pub fn build_standard_hooks() -> ApiMonitorHooks {
    let mut monitor = ApiMonitorHooks::new(0x7FFF_0000_0000);
    let stub = TrampolineHook::generate_jmp_stub(0x0);
    install_ntdll_hooks(&mut monitor, &stub);
    install_kernel32_hooks(&mut monitor, &stub);
    install_ws2_hooks(&mut monitor, stub);
    monitor
}

/// Install standard `ntdll.dll` hook descriptors into `monitor`.
fn install_ntdll_hooks(monitor: &mut ApiMonitorHooks, stub: &[u8]) {
    let _ = monitor.install_hook(0xFFFF_0001, InstallHookParams::new(
        "ntdll.dll", "NtCreateFile", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("FileHandle", "PHANDLE", true),
            ArgumentDescriptor::new("DesiredAccess", "ACCESS_MASK", false),
            ArgumentDescriptor::new("ObjectAttributes", "POBJECT_ATTRIBUTES", false),
            ArgumentDescriptor::new("IoStatusBlock", "PIO_STATUS_BLOCK", true),
            ArgumentDescriptor::new("AllocationSize", "PLARGE_INTEGER", false),
            ArgumentDescriptor::new("FileAttributes", "ULONG", false),
            ArgumentDescriptor::new("ShareAccess", "ULONG", false),
            ArgumentDescriptor::new("CreateDisposition", "ULONG", false),
            ArgumentDescriptor::new("CreateOptions", "ULONG", false),
            ArgumentDescriptor::new("EaBuffer", "PVOID", false),
            ArgumentDescriptor::new("EaLength", "ULONG", false),
        ],
        "NTSTATUS", stub.to_vec(),
    ));
    let _ = monitor.install_hook(0xFFFF_0002, InstallHookParams::new(
        "ntdll.dll", "NtReadFile", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("FileHandle", "HANDLE", false),
            ArgumentDescriptor::new("Event", "HANDLE", false),
            ArgumentDescriptor::new("ApcRoutine", "PIO_APC_ROUTINE", false),
            ArgumentDescriptor::new("ApcContext", "PVOID", false),
            ArgumentDescriptor::new("IoStatusBlock", "PIO_STATUS_BLOCK", true),
            ArgumentDescriptor::new("Buffer", "PVOID", true),
            ArgumentDescriptor::new("Length", "ULONG", false),
            ArgumentDescriptor::new("ByteOffset", "PLARGE_INTEGER", false),
            ArgumentDescriptor::new("Key", "PULONG", false),
        ],
        "NTSTATUS", stub.to_vec(),
    ));
    let _ = monitor.install_hook(0xFFFF_0003, InstallHookParams::new(
        "ntdll.dll", "NtWriteFile", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("FileHandle", "HANDLE", false),
            ArgumentDescriptor::new("Event", "HANDLE", false),
            ArgumentDescriptor::new("ApcRoutine", "PIO_APC_ROUTINE", false),
            ArgumentDescriptor::new("ApcContext", "PVOID", false),
            ArgumentDescriptor::new("IoStatusBlock", "PIO_STATUS_BLOCK", true),
            ArgumentDescriptor::new("Buffer", "PVOID", false),
            ArgumentDescriptor::new("Length", "ULONG", false),
            ArgumentDescriptor::new("ByteOffset", "PLARGE_INTEGER", false),
            ArgumentDescriptor::new("Key", "PULONG", false),
        ],
        "NTSTATUS", stub.to_vec(),
    ));
    let _ = monitor.install_hook(0xFFFF_0004, InstallHookParams::new(
        "ntdll.dll", "NtAllocateVirtualMemory", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("ProcessHandle", "HANDLE", false),
            ArgumentDescriptor::new("BaseAddress", "PVOID *", true),
            ArgumentDescriptor::new("ZeroBits", "ULONG_PTR", false),
            ArgumentDescriptor::new("RegionSize", "PSIZE_T", true),
            ArgumentDescriptor::new("AllocationType", "ULONG", false),
            ArgumentDescriptor::new("Protect", "ULONG", false),
        ],
        "NTSTATUS", stub.to_vec(),
    ));
}

/// Install standard `kernel32.dll` hook descriptors into `monitor`.
fn install_kernel32_hooks(monitor: &mut ApiMonitorHooks, stub: &[u8]) {
    let _ = monitor.install_hook(0xFFFF_0010, InstallHookParams::new(
        "kernel32.dll", "CreateFileW", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("lpFileName", "LPCWSTR", false),
            ArgumentDescriptor::new("dwDesiredAccess", "DWORD", false),
            ArgumentDescriptor::new("dwShareMode", "DWORD", false),
            ArgumentDescriptor::new("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES", false),
            ArgumentDescriptor::new("dwCreationDisposition", "DWORD", false),
            ArgumentDescriptor::new("dwFlagsAndAttributes", "DWORD", false),
            ArgumentDescriptor::new("hTemplateFile", "HANDLE", false),
        ],
        "HANDLE", stub.to_vec(),
    ));
    let _ = monitor.install_hook(0xFFFF_0011, InstallHookParams::new(
        "kernel32.dll", "VirtualAlloc", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("lpAddress", "LPVOID", false),
            ArgumentDescriptor::new("dwSize", "SIZE_T", false),
            ArgumentDescriptor::new("flAllocationType", "DWORD", false),
            ArgumentDescriptor::new("flProtect", "DWORD", false),
        ],
        "LPVOID", stub.to_vec(),
    ));
}

/// Install standard `ws2_32.dll` hook descriptors into `monitor`.
fn install_ws2_hooks(monitor: &mut ApiMonitorHooks, stub: Vec<u8>) {
    let _ = monitor.install_hook(0xFFFF_0020, InstallHookParams::new(
        "ws2_32.dll", "connect", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("s", "SOCKET", false),
            ArgumentDescriptor::new("name", "const sockaddr *", false),
            ArgumentDescriptor::new("namelen", "int", false),
        ],
        "int", stub.clone(),
    ));
    let _ = monitor.install_hook(0xFFFF_0021, InstallHookParams::new(
        "ws2_32.dll", "send", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("s", "SOCKET", false),
            ArgumentDescriptor::new("buf", "const char *", false),
            ArgumentDescriptor::new("len", "int", false),
            ArgumentDescriptor::new("flags", "int", false),
        ],
        "int", stub.clone(),
    ));
    let _ = monitor.install_hook(0xFFFF_0022, InstallHookParams::new(
        "ws2_32.dll", "recv", CallingConvention::MicrosoftX64,
        vec![
            ArgumentDescriptor::new("s", "SOCKET", false),
            ArgumentDescriptor::new("buf", "char *", true),
            ArgumentDescriptor::new("len", "int", false),
            ArgumentDescriptor::new("flags", "int", false),
        ],
        "int", stub,
    ));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_monitor() -> ApiMonitorHooks {
        ApiMonitorHooks::new(0x7FFF_0000_0000)
    }

    fn install_simple(monitor: &mut ApiMonitorHooks, addr: u64, name: &str) -> u64 {
        monitor.install_hook(addr, InstallHookParams::new(
            "test.dll", name,
            CallingConvention::MicrosoftX64,
            vec![ArgumentDescriptor::new("arg0", "DWORD", false)],
            "NTSTATUS",
            vec![0x90u8; 8],
        )).unwrap()
    }

    #[test]
    fn test_install_and_count() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        install_simple(&mut m, 0x2000, "Bar");
        assert_eq!(m.hook_count(), 2);
    }

    #[test]
    fn test_install_duplicate_address() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        let err = m.install_hook(0x1000, InstallHookParams::new(
            "test.dll", "Other",
            CallingConvention::MicrosoftX64, vec![], "void", vec![],
        )).unwrap_err();
        assert_eq!(err, HookError::AlreadyHooked(0x1000));
    }

    #[test]
    fn test_log_call_basic() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        let cid = m.log_call(
            0x1000, 0x5555,
            vec![ArgValue::U32(42)],
            Some(ArgValue::U32(0)),
            100, 200,
        ).unwrap();
        assert_eq!(cid, 0);
        let hook = m.hook_by_address(0x1000).unwrap();
        assert_eq!(hook.call_count(), 1);
    }

    #[test]
    fn test_log_call_not_hooked() {
        let mut m = make_monitor();
        let err = m.log_call(0xDEAD, 0, vec![], None, 0, 0).unwrap_err();
        assert_eq!(err, HookError::NotHooked(0xDEAD));
    }

    #[test]
    fn test_remove_hook() {
        let mut m = make_monitor();
        let id = install_simple(&mut m, 0x1000, "Foo");
        let entry = m.remove_hook(id).unwrap();
        assert_eq!(entry.function_name, "Foo");
        assert_eq!(m.hook_count(), 0);
    }

    #[test]
    fn test_remove_hook_not_found() {
        let mut m = make_monitor();
        let err = m.remove_hook(999).unwrap_err();
        assert_eq!(err, HookError::HookIdNotFound(999));
    }

    #[test]
    fn test_set_enabled_false_skips_log() {
        let mut m = make_monitor();
        let id = install_simple(&mut m, 0x1000, "Foo");
        m.set_enabled(id, false).unwrap();
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        let hook = m.hook_by_address(0x1000).unwrap();
        assert_eq!(hook.call_count(), 0);
    }

    #[test]
    fn test_total_call_count() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        install_simple(&mut m, 0x2000, "Bar");
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        m.log_call(0x2000, 0, vec![], None, 0, 0).unwrap();
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        assert_eq!(m.total_call_count(), 3);
    }

    #[test]
    fn test_calls_for_function() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        install_simple(&mut m, 0x2000, "Bar");
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        m.log_call(0x2000, 0, vec![], None, 0, 0).unwrap();
        assert_eq!(m.calls_for_function("Foo").len(), 2);
        assert_eq!(m.calls_for_function("Bar").len(), 1);
    }

    #[test]
    fn test_all_call_records_sorted() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "Foo");
        install_simple(&mut m, 0x2000, "Bar");
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        m.log_call(0x2000, 0, vec![], None, 0, 0).unwrap();
        let records = m.all_call_records();
        assert_eq!(records.len(), 2);
        assert!(records[0].call_id <= records[1].call_id);
    }

    #[test]
    fn test_hook_by_name() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "NtCreateFile");
        let h = m.hook_by_name("test.dll", "NtCreateFile").unwrap();
        assert_eq!(h.target_address, 0x1000);
    }

    #[test]
    fn test_hook_by_name_case_insensitive() {
        let mut m = make_monitor();
        install_simple(&mut m, 0x1000, "NtCreateFile");
        assert!(m.hook_by_name("TEST.DLL", "NTCREATEFILE").is_some());
    }

    #[test]
    fn test_clear_log() {
        let mut m = make_monitor();
        let id = install_simple(&mut m, 0x1000, "Foo");
        m.log_call(0x1000, 0, vec![], None, 0, 0).unwrap();
        m.clear_log(id).unwrap();
        let hook = m.hook_by_address(0x1000).unwrap();
        assert_eq!(hook.call_count(), 0);
    }

    #[test]
    fn test_summary() {
        let mut m = make_monitor();
        let id = install_simple(&mut m, 0x1000, "Foo");
        install_simple(&mut m, 0x2000, "Bar");
        m.set_enabled(id, false).unwrap();
        let s = m.summary();
        assert_eq!(s.total_hooks, 2);
        assert_eq!(s.enabled_hooks, 1);
    }

    #[test]
    fn test_build_standard_hooks() {
        let m = build_standard_hooks();
        assert!(m.hook_count() >= 9);
        assert!(m.hook_by_name("ntdll.dll", "NtCreateFile").is_some());
        assert!(m.hook_by_name("ws2_32.dll", "send").is_some());
    }

    #[test]
    fn test_trampoline_generate_jmp_stub() {
        let stub = TrampolineHook::generate_jmp_stub(0x1122_3344_5566_7788);
        assert_eq!(stub.len(), 14);
        assert_eq!(&stub[0..2], &[0xFF, 0x25]);
    }

    #[test]
    fn test_trampoline_validate_bytes_match() {
        let t = TrampolineHook::new(0x1000, 0x9000, &[0x90, 0x90, 0x90]);
        assert!(t.validate_saved_bytes(&[0x90, 0x90, 0x90]));
        assert!(!t.validate_saved_bytes(&[0xFF, 0x25, 0x00]));
    }

    #[test]
    fn test_call_record_display() {
        let rec = CallRecord {
            call_id: 7,
            function_name: "NtCreateFile".into(),
            target_address: 0x1000,
            caller_address: 0x2000,
            args: vec![ArgValue::Ptr(0xDEAD)],
            return_value: Some(ArgValue::U32(0)),
            pid: 100,
            tid: 200,
            timestamp: 7,
        };
        let s = rec.to_string();
        assert!(s.contains("NtCreateFile"));
        assert!(s.contains("[7]"));
    }

    #[test]
    fn test_arg_value_display() {
        assert_eq!(ArgValue::Null.to_string(), "NULL");
        assert!(ArgValue::Ptr(0xDEAD_BEEF).to_string().starts_with("ptr("));
        assert_eq!(ArgValue::Bool(true).to_string(), "true");
    }
}
