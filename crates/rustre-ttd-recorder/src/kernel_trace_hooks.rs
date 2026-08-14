// kernel_trace_hooks.rs — Kernel trace hook management for TTD recording
// Provides detour-based hook installation, syscall interception, and API call recording.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── ApiArg ──────────────────────────────────────────────────────────────────

/// Typed argument captured at an API call boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiArg {
    Int(i64),
    Uint(u64),
    Pointer(u64),
    String(String),
    Buffer(Vec<u8>),
}

impl ApiArg {
    /// Return the raw numeric value (pointer / integer / uint).  Returns `None` for
    /// `String` and `Buffer` variants.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Int(v) => Some((*v).cast_unsigned()),
            Self::Uint(v) => Some(*v),
            Self::Pointer(v) => Some(*v),
            Self::String(_) | Self::Buffer(_) => None,
        }
    }

    /// Human-readable label for the variant.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "Int",
            Self::Uint(_) => "Uint",
            Self::Pointer(_) => "Pointer",
            Self::String(_) => "String",
            Self::Buffer(_) => "Buffer",
        }
    }

    /// Return the byte length of the contained data (1/8/8/len/len).
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        match self {
            Self::Int(_) | Self::Uint(_) | Self::Pointer(_) => 8,
            Self::String(s) => s.len(),
            Self::Buffer(b) => b.len(),
        }
    }
}

// ─── HookTarget ──────────────────────────────────────────────────────────────

/// Specifies what a hook intercepts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HookTarget {
    Syscall { number: u32 },
    ApiFunction { dll: String, name: String },
    KernelAddress(u64),
    Interrupt(u8),
    Exception(u32),
}

impl HookTarget {
    /// Return a stable string key used in maps.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Syscall { number } => format!("syscall:{number}"),
            Self::ApiFunction { dll, name } => {
                format!("api:{}!{}", dll.to_lowercase(), name.to_lowercase())
            }
            Self::KernelAddress(addr) => format!("addr:{addr:#018x}"),
            Self::Interrupt(n) => format!("int:{n:#04x}"),
            Self::Exception(code) => format!("exc:{code:#010x}"),
        }
    }

    /// Whether this target requires privileged access.
    #[must_use]
    pub const fn requires_privilege(&self) -> bool {
        matches!(
            self,
            Self::Syscall { .. }
                | Self::KernelAddress(_)
                | Self::Interrupt(_)
                | Self::Exception(_)
        )
    }
}

// ─── HookRecord ──────────────────────────────────────────────────────────────

/// A live or deinstalled hook entry.
#[derive(Debug, Clone)]
pub struct HookRecord {
    pub target: HookTarget,
    /// Address of the first instruction that was overwritten.
    pub hook_addr: u64,
    /// Address of the trampoline buffer (copy of original bytes + JMP back).
    pub trampoline_addr: u64,
    /// Original bytes that were overwritten (at most 16).
    pub original_bytes: Vec<u8>,
    /// Number of times the hook has fired.
    pub hit_count: u64,
    /// Whether the hook is currently active.
    pub active: bool,
    /// Monotonically increasing install index.
    pub install_seq: u64,
}

const fn u64_to_i32_rel(v: u64) -> i32 {
    v as i32
}

impl HookRecord {
    /// Build a JMP `rel32` patch targeting `dest` from `src`.
    /// Returns the 5-byte patch.
    #[must_use]
    pub const fn build_jmp_rel32(src: u64, dest: u64) -> [u8; 5] {
        let rel = u64_to_i32_rel(dest.wrapping_sub(src).wrapping_sub(5));
        let rb = rel.to_le_bytes();
        [0xE9, rb[0], rb[1], rb[2], rb[3]]
    }

    /// Return a textual summary of the hook.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] hook@{:#018x} tramp@{:#018x} hits={} active={}",
            self.target.key(),
            self.hook_addr,
            self.trampoline_addr,
            self.hit_count,
            self.active,
        )
    }
}

// ─── SyscallInterceptRecord ──────────────────────────────────────────────────

/// A captured syscall event.
#[derive(Debug, Clone)]
pub struct SyscallInterceptRecord {
    pub syscall_num: u32,
    pub timestamp_ns: u64,
    pub thread_id: u32,
    pub args: [u64; 8],
    pub return_value: u64,
}

impl SyscallInterceptRecord {
    #[must_use]
    pub fn new(syscall_num: u32, thread_id: u32, args: [u64; 8]) -> Self {
        let ts = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        Self {
            syscall_num,
            timestamp_ns: ts,
            thread_id,
            args,
            return_value: 0,
        }
    }

    /// Format as a one-liner for logging.
    #[must_use]
    pub fn to_log_line(&self) -> String {
        let ts = self.timestamp_ns;
        let tid = self.thread_id;
        let sc = self.syscall_num;
        let a = self.args;
        let ret = self.return_value;
        format!(
            "ts={ts} tid={tid} syscall={sc} args=[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}] ret={ret:#x}",
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
        )
    }

    /// Serialize to a compact 88-byte little-endian record.
    ///
    /// Layout: syscall_num(4) + thread_id(4) + timestamp_ns(8) + args(8*8) +
    /// return_value(8) = 88 bytes. The figure used to read 96, which no field
    /// layout produced: `serialize` emitted 88 while `deserialize` demanded 96,
    /// so a record could never be read back.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(88);
        out.extend_from_slice(&self.syscall_num.to_le_bytes());
        out.extend_from_slice(&self.thread_id.to_le_bytes());
        out.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        for a in &self.args {
            out.extend_from_slice(&a.to_le_bytes());
        }
        out.extend_from_slice(&self.return_value.to_le_bytes());
        out
    }

    /// Deserialize from the 88-byte format above.
    #[must_use]
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 88 {
            return None;
        }
        let syscall_num = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let thread_id = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let timestamp_ns = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let mut args = [0u64; 8];
        for (i, arg) in args.iter_mut().enumerate() {
            let base = 16 + i * 8;
            *arg = u64::from_le_bytes(data[base..base + 8].try_into().ok()?);
        }
        let return_value = u64::from_le_bytes(data[80..88].try_into().ok()?);
        Some(Self {
            syscall_num,
            timestamp_ns,
            thread_id,
            args,
            return_value,
        })
    }
}

// ─── ApiCallRecord ───────────────────────────────────────────────────────────

/// A captured API call event with typed arguments.
#[derive(Debug, Clone)]
pub struct ApiCallRecord {
    pub dll: String,
    pub function: String,
    pub args: Vec<ApiArg>,
    pub return_value: u64,
    pub timestamp_ns: u64,
    pub thread_id: u32,
    pub call_addr: u64,
}

impl ApiCallRecord {
    #[must_use]
    pub fn new(dll: &str, function: &str, thread_id: u32, call_addr: u64) -> Self {
        let ts = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            args: Vec::new(),
            return_value: 0,
            timestamp_ns: ts,
            thread_id,
            call_addr,
        }
    }

    pub fn push_arg(&mut self, arg: ApiArg) {
        self.args.push(arg);
    }

    #[must_use]
    pub fn to_log_line(&self) -> String {
        let args_str: Vec<String> = self
            .args
            .iter()
            .map(|a| match a {
                ApiArg::Int(v) => format!("{v}(i64)"),
                ApiArg::Uint(v) => format!("{v:#x}(u64)"),
                ApiArg::Pointer(v) => format!("{v:#018x}(ptr)"),
                ApiArg::String(s) => format!("\"{s}\""),
                ApiArg::Buffer(b) => format!("[{} bytes]", b.len()),
            })
            .collect();
        let ts = self.timestamp_ns;
        let tid = self.thread_id;
        let dll = &self.dll;
        let func = &self.function;
        let args = args_str.join(", ");
        let ret = self.return_value;
        format!("ts={ts} tid={tid} {dll}!{func}({args}) -> {ret:#x}")
    }

    /// Total byte cost of all arguments.
    #[must_use]
    pub fn args_byte_total(&self) -> usize {
        self.args.iter().map(ApiArg::byte_len).sum()
    }
}

// ─── HookDispatchRecord ──────────────────────────────────────────────────────

/// Union of a dispatched hook event, placed into the ring buffer.
#[derive(Debug, Clone)]
pub enum HookDispatchRecord {
    Syscall(SyscallInterceptRecord),
    Api(ApiCallRecord),
    RawAddress { addr: u64, timestamp_ns: u64, hit_seq: u64 },
    Interrupt { vector: u8, timestamp_ns: u64 },
    Exception { code: u32, address: u64, timestamp_ns: u64 },
}

impl HookDispatchRecord {
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Syscall(r) => r.timestamp_ns,
            Self::Api(r) => r.timestamp_ns,
            Self::RawAddress { timestamp_ns, .. }
            | Self::Interrupt { timestamp_ns, .. }
            | Self::Exception { timestamp_ns, .. } => *timestamp_ns,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Syscall(_) => "syscall",
            Self::Api(_) => "api",
            Self::RawAddress { .. } => "addr",
            Self::Interrupt { .. } => "int",
            Self::Exception { .. } => "exc",
        }
    }
}

// ─── HookInstaller ───────────────────────────────────────────────────────────

/// Manages installation and removal of detour hooks.
///
/// On real hardware this would call `VirtualProtect` + `WriteProcessMemory` / mprotect +
/// memcpy.  In this implementation the "memory" is a `HashMap`<u64, Vec<u8>> simulating
/// target pages so the logic compiles and tests correctly on all platforms.
pub struct HookInstaller {
    /// Simulated "target process memory": address -> bytes
    memory: HashMap<u64, Vec<u8>>,
    /// Installed hooks indexed by target key.
    hooks: HashMap<String, HookRecord>,
    /// Allocator cursor for simulated trampoline buffers.
    trampoline_base: u64,
    /// Monotonic counter for `install_seq`.
    install_counter: u64,
    /// Dispatch sink.
    dispatch_sink: Arc<Mutex<Vec<HookDispatchRecord>>>,
}

impl HookInstaller {
    #[must_use]
    pub fn new(dispatch_sink: Arc<Mutex<Vec<HookDispatchRecord>>>) -> Self {
        Self {
            memory: HashMap::new(),
            hooks: HashMap::new(),
            trampoline_base: 0x7FFF_0000_0000u64,
            install_counter: 0,
            dispatch_sink,
        }
    }

    /// Seed simulated memory at `address` with `bytes`.
    pub fn seed_memory(&mut self, address: u64, bytes: Vec<u8>) {
        self.memory.insert(address, bytes);
    }

    /// Read up to `len` bytes from simulated memory starting at `address`.
    #[must_use]
    pub fn read_memory(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        self.memory.get(&address).map(|v| {
            let take = len.min(v.len());
            v[..take].to_vec()
        })
    }

    /// Write bytes into simulated memory at `address`.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> bool {
        if let Some(page) = self.memory.get_mut(&address) {
            let write_len = bytes.len().min(page.len());
            page[..write_len].copy_from_slice(&bytes[..write_len]);
        } else {
            // Create new page
            self.memory.insert(address, bytes.to_vec());
        }
        true
    }

    /// Allocate `size` bytes in the simulated trampoline region.
    fn alloc_trampoline(&mut self, size: usize) -> u64 {
        let addr = self.trampoline_base;
        let placeholder = vec![0xCCu8; size]; // INT3 fill
        self.memory.insert(addr, placeholder);
        self.trampoline_base += (size as u64 + 15) & !15; // 16-byte align
        addr
    }

    /// Install a detour hook at `hook_addr`.
    ///
    /// Steps:
    /// 1. Read 5 original bytes (enough for `JMP rel32`).
    /// 2. Allocate trampoline: original bytes + `JMP` back to `hook_addr+5`.
    /// 3. Overwrite `hook_addr` with `JMP` to `handler_addr`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a hook is already installed for this target or if memory
    /// cannot be read at `hook_addr`.
    pub fn install_detour(
        &mut self,
        target: HookTarget,
        hook_addr: u64,
        handler_addr: u64,
    ) -> Result<(), String> {
        let key = target.key();
        if self.hooks.contains_key(&key) {
            return Err(format!("Hook already installed for {key}"));
        }

        // 1. Save original bytes
        let original_bytes = self
            .read_memory(hook_addr, 5)
            .ok_or_else(|| format!("Cannot read memory at {hook_addr:#018x}"))?;
        if original_bytes.len() < 5 {
            return Err(format!(
                "Not enough bytes at {hook_addr:#018x} (got {})",
                original_bytes.len()
            ));
        }

        // 2. Build trampoline: original 5 bytes + JMP back to hook_addr+5
        let trampoline_addr = self.alloc_trampoline(5 + 5);
        let jmp_back = HookRecord::build_jmp_rel32(trampoline_addr + 5, hook_addr + 5);
        let mut tramp_bytes = original_bytes.clone();
        tramp_bytes.extend_from_slice(&jmp_back);
        self.write_memory(trampoline_addr, &tramp_bytes);

        // 3. Overwrite target with JMP to handler
        let patch = HookRecord::build_jmp_rel32(hook_addr, handler_addr);
        self.write_memory(hook_addr, &patch);

        self.install_counter += 1;
        let record = HookRecord {
            target,
            hook_addr,
            trampoline_addr,
            original_bytes,
            hit_count: 0,
            active: true,
            install_seq: self.install_counter,
        };
        self.hooks.insert(key, record);
        Ok(())
    }

    /// Remove a previously installed hook by restoring the original bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no hook exists for the target or if the hook is already inactive.
    ///
    /// # Panics
    ///
    /// Panics if the hook key is present but the hook record is missing (should not happen).
    pub fn uninstall_detour(&mut self, target: &HookTarget) -> Result<(), String> {
        let key = target.key();
        let (hook_addr, original_bytes) = {
            let record = self
                .hooks
                .get(&key)
                .ok_or_else(|| format!("No hook for {key}"))?;
            if !record.active {
                return Err(format!("Hook {key} is not active"));
            }
            (record.hook_addr, record.original_bytes.clone())
        };
        self.write_memory(hook_addr, &original_bytes);
        self.hooks.get_mut(&key).unwrap().active = false;
        Ok(())
    }

    /// Simulate a hook firing: increments `hit_count` and dispatches a record.
    pub fn dispatch_hook(&mut self, target: &HookTarget, dispatch: HookDispatchRecord) {
        let key = target.key();
        if let Some(rec) = self.hooks.get_mut(&key) {
            rec.hit_count += 1;
        }
        if let Ok(mut sink) = self.dispatch_sink.lock() {
            sink.push(dispatch);
        }
    }

    /// Return all installed hook records (active and inactive).
    #[must_use]
    pub fn all_hooks(&self) -> Vec<&HookRecord> {
        let mut v: Vec<&HookRecord> = self.hooks.values().collect();
        v.sort_by_key(|r| r.install_seq);
        v
    }

    /// Return only active hooks.
    #[must_use]
    pub fn active_hooks(&self) -> Vec<&HookRecord> {
        self.all_hooks()
            .into_iter()
            .filter(|r| r.active)
            .collect()
    }

    /// Total hit count across all hooks.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.hooks.values().map(|r| r.hit_count).sum()
    }
}

// ─── KernelTraceHooks ────────────────────────────────────────────────────────

/// High-level manager coordinating hook installation and dispatch for TTD recording.
pub struct KernelTraceHooks {
    installer: HookInstaller,
    dispatch_sink: Arc<Mutex<Vec<HookDispatchRecord>>>,
    /// Mapping from target key to its designated handler address.
    handler_map: HashMap<String, u64>,
}

impl KernelTraceHooks {
    #[must_use]
    pub fn new() -> Self {
        let sink = Arc::new(Mutex::new(Vec::new()));
        Self {
            installer: HookInstaller::new(Arc::clone(&sink)),
            dispatch_sink: sink,
            handler_map: HashMap::new(),
        }
    }

    /// Seed memory so tests can install hooks without real process memory.
    pub fn seed_memory(&mut self, address: u64, bytes: Vec<u8>) {
        self.installer.seed_memory(address, bytes);
    }

    /// Register a handler address for a hook target.
    pub fn register_handler(&mut self, target: &HookTarget, handler_addr: u64) {
        self.handler_map.insert(target.key(), handler_addr);
    }

    /// Install a hook for `target` at `hook_addr`.  Handler must have been registered.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no handler is registered or if hook installation fails.
    pub fn install(&mut self, target: HookTarget, hook_addr: u64) -> Result<(), String> {
        let key = target.key();
        let handler = *self
            .handler_map
            .get(&key)
            .ok_or_else(|| format!("No handler registered for {key}"))?;
        self.installer.install_detour(target, hook_addr, handler)
    }

    /// Uninstall a hook.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no hook is installed for the target.
    pub fn uninstall(&mut self, target: &HookTarget) -> Result<(), String> {
        self.installer.uninstall_detour(target)
    }

    /// Fire a simulated syscall event.
    pub fn fire_syscall(
        &mut self,
        syscall_num: u32,
        thread_id: u32,
        args: [u64; 8],
        return_value: u64,
    ) {
        let target = HookTarget::Syscall { number: syscall_num };
        let mut rec = SyscallInterceptRecord::new(syscall_num, thread_id, args);
        rec.return_value = return_value;
        self.installer
            .dispatch_hook(&target, HookDispatchRecord::Syscall(rec));
    }

    /// Fire a simulated API call event.
    pub fn fire_api_call(&mut self, record: ApiCallRecord) {
        let target = HookTarget::ApiFunction {
            dll: record.dll.clone(),
            name: record.function.clone(),
        };
        self.installer
            .dispatch_hook(&target, HookDispatchRecord::Api(record));
    }

    /// Drain all dispatched records from the sink.
    #[must_use]
    pub fn drain_records(&self) -> Vec<HookDispatchRecord> {
        self.dispatch_sink.lock().map_or_else(|_| Vec::new(), |mut sink| std::mem::take(&mut *sink))
    }

    /// Peek at records without draining.
    #[must_use]
    pub fn peek_records(&self) -> Vec<HookDispatchRecord> {
        self.dispatch_sink.lock().map_or_else(|_| Vec::new(), |sink| sink.clone())
    }

    #[must_use]
    pub fn active_hook_count(&self) -> usize {
        self.installer.active_hooks().len()
    }

    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.installer.total_hits()
    }
}

impl Default for KernelTraceHooks {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Utility: syscall name table (x86-64 Windows) ────────────────────────────

/// Return the Windows x64 syscall name for a known number.
#[must_use]
pub const fn windows_syscall_name(number: u32) -> Option<&'static str> {
    match number {
        0x00 => Some("NtQuerySystemInformation"),
        0x01 => Some("NtOpenFile"),
        0x02 => Some("NtDeviceIoControlFile"),
        0x03 => Some("NtQueryInformationProcess"),
        0x04 => Some("NtReadFile"),
        0x05 => Some("NtWriteFile"),
        0x06 => Some("NtClose"),
        0x07 => Some("NtCreateFile"),
        0x08 => Some("NtAllocateVirtualMemory"),
        0x09 => Some("NtFreeVirtualMemory"),
        0x0A => Some("NtProtectVirtualMemory"),
        0x0B => Some("NtQueryVirtualMemory"),
        0x0C => Some("NtCreateThread"),
        0x0D => Some("NtTerminateThread"),
        0x0E => Some("NtSuspendThread"),
        0x0F => Some("NtResumeThread"),
        0x10 => Some("NtOpenProcess"),
        0x11 => Some("NtTerminateProcess"),
        0x12 => Some("NtCreateSection"),
        0x13 => Some("NtMapViewOfSection"),
        0x14 => Some("NtUnmapViewOfSection"),
        0x15 => Some("NtOpenKey"),
        0x16 => Some("NtCreateKey"),
        0x17 => Some("NtQueryValueKey"),
        0x18 => Some("NtSetValueKey"),
        0x19 => Some("NtDeleteValueKey"),
        0x1A => Some("NtCreateProcess"),
        0x1B => Some("NtCreateProcessEx"),
        0x1C => Some("NtWaitForSingleObject"),
        0x1D => Some("NtWaitForMultipleObjects"),
        0x1E => Some("NtConnectPort"),
        0x1F => Some("NtRequestWaitReplyPort"),
        _ => None,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sink() -> Arc<Mutex<Vec<HookDispatchRecord>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    // ── ApiArg ──

    #[test]
    fn test_api_arg_as_u64() {
        assert_eq!(ApiArg::Int(-1i64).as_u64(), Some(u64::MAX));
        assert_eq!(ApiArg::Uint(42).as_u64(), Some(42));
        assert_eq!(ApiArg::Pointer(0xDEAD_BEEF).as_u64(), Some(0xDEAD_BEEF));
        assert!(ApiArg::String("x".into()).as_u64().is_none());
        assert!(ApiArg::Buffer(vec![1]).as_u64().is_none());
    }

    #[test]
    fn test_api_arg_byte_len() {
        assert_eq!(ApiArg::Int(0).byte_len(), 8);
        assert_eq!(ApiArg::Uint(0).byte_len(), 8);
        assert_eq!(ApiArg::Pointer(0).byte_len(), 8);
        assert_eq!(ApiArg::String("hello".into()).byte_len(), 5);
        assert_eq!(ApiArg::Buffer(vec![0u8; 12]).byte_len(), 12);
    }

    #[test]
    fn test_api_arg_kind_name() {
        assert_eq!(ApiArg::Int(0).kind_name(), "Int");
        assert_eq!(ApiArg::Uint(0).kind_name(), "Uint");
        assert_eq!(ApiArg::Pointer(0).kind_name(), "Pointer");
        assert_eq!(ApiArg::String(String::new()).kind_name(), "String");
        assert_eq!(ApiArg::Buffer(Vec::new()).kind_name(), "Buffer");
    }

    // ── HookTarget ──

    #[test]
    fn test_hook_target_key_syscall() {
        let t = HookTarget::Syscall { number: 42 };
        assert_eq!(t.key(), "syscall:42");
    }

    #[test]
    fn test_hook_target_key_api() {
        let t = HookTarget::ApiFunction {
            dll: "Kernel32.DLL".into(),
            name: "CreateFileW".into(),
        };
        assert_eq!(t.key(), "api:kernel32.dll!createfilew");
    }

    #[test]
    fn test_hook_target_key_address() {
        let t = HookTarget::KernelAddress(0xFFFF_8000_DEAD_BEEF);
        assert!(t.key().starts_with("addr:"));
    }

    #[test]
    fn test_hook_target_requires_privilege() {
        assert!(HookTarget::Syscall { number: 0 }.requires_privilege());
        assert!(!HookTarget::ApiFunction { dll: "a".into(), name: "b".into() }.requires_privilege());
        assert!(HookTarget::KernelAddress(0).requires_privilege());
        assert!(HookTarget::Interrupt(3).requires_privilege());
        assert!(HookTarget::Exception(0xC000_0005).requires_privilege());
    }

    // ── HookRecord::build_jmp_rel32 ──

    #[test]
    fn test_jmp_rel32_forward() {
        // JMP from 0x1000 to 0x2000  =>  rel = 0x2000 - 0x1000 - 5 = 0x0FFB
        let patch = HookRecord::build_jmp_rel32(0x1000, 0x2000);
        assert_eq!(patch[0], 0xE9);
        let rel = i32::from_le_bytes([patch[1], patch[2], patch[3], patch[4]]);
        assert_eq!(rel, 0x0FFB);
    }

    #[test]
    fn test_jmp_rel32_backward() {
        // JMP from 0x2000 to 0x1000  =>  rel = 0x1000 - 0x2000 - 5 = -0x1005  (negative)
        let patch = HookRecord::build_jmp_rel32(0x2000, 0x1000);
        assert_eq!(patch[0], 0xE9);
        let rel = i32::from_le_bytes([patch[1], patch[2], patch[3], patch[4]]);
        assert_eq!(rel, -0x1005i32);
    }

    // ── SyscallInterceptRecord ──

    #[test]
    fn test_syscall_intercept_roundtrip() {
        let mut rec = SyscallInterceptRecord::new(0x0A, 1234, [1, 2, 3, 4, 5, 6, 7, 8]);
        rec.return_value = 0xCAFE_BABE;
        let bytes = rec.serialize();
        // 4 + 4 + 8 + 8*8 + 8 = 88; the old expectation of 96 matched no layout.
        assert_eq!(bytes.len(), 88);
        let back = SyscallInterceptRecord::deserialize(&bytes).unwrap();
        assert_eq!(back.syscall_num, 0x0A);
        assert_eq!(back.thread_id, 1234);
        assert_eq!(back.return_value, 0xCAFE_BABE);
        assert_eq!(back.args, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_syscall_deserialize_short() {
        assert!(SyscallInterceptRecord::deserialize(&[0u8; 8]).is_none());
    }

    #[test]
    fn test_syscall_log_line() {
        let rec = SyscallInterceptRecord::new(5, 99, [0xAB; 8]);
        let line = rec.to_log_line();
        assert!(line.contains("syscall=5"));
        assert!(line.contains("tid=99"));
    }

    // ── ApiCallRecord ──

    #[test]
    fn test_api_call_log_line() {
        let mut rec = ApiCallRecord::new("ntdll.dll", "NtOpenFile", 42, 0x140001000);
        rec.push_arg(ApiArg::Pointer(0xDEAD_0000));
        rec.push_arg(ApiArg::String("\\Device\\Harddisk0".into()));
        rec.return_value = 0;
        let line = rec.to_log_line();
        assert!(line.contains("ntdll.dll"));
        assert!(line.contains("NtOpenFile"));
        assert!(line.contains("Harddisk0"));
    }

    #[test]
    fn test_api_call_args_byte_total() {
        let mut rec = ApiCallRecord::new("a", "b", 0, 0);
        rec.push_arg(ApiArg::Uint(1));
        rec.push_arg(ApiArg::Buffer(vec![0u8; 100]));
        assert_eq!(rec.args_byte_total(), 108); // 8 + 100
    }

    // ── HookInstaller ──

    #[test]
    fn test_install_and_uninstall() {
        let sink = make_sink();
        let mut inst = HookInstaller::new(Arc::clone(&sink));
        let hook_addr = 0x0001_4000_1000_u64;
        let handler_addr = 0x0001_4001_0000_u64;
        inst.seed_memory(hook_addr, vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57]);

        let target = HookTarget::ApiFunction {
            dll: "foo.dll".into(),
            name: "Bar".into(),
        };
        inst.install_detour(target.clone(), hook_addr, handler_addr)
            .expect("install failed");

        // Patch should be JMP rel32
        let patched = inst.read_memory(hook_addr, 5).unwrap();
        assert_eq!(patched[0], 0xE9);

        // Uninstall restores original bytes
        inst.uninstall_detour(&target).expect("uninstall failed");
        let restored = inst.read_memory(hook_addr, 5).unwrap();
        assert_eq!(restored, vec![0x48, 0x89, 0x5C, 0x24, 0x08]);
    }

    #[test]
    fn test_double_install_fails() {
        let sink = make_sink();
        let mut inst = HookInstaller::new(Arc::clone(&sink));
        let addr = 0x1000u64;
        inst.seed_memory(addr, vec![0x90; 16]);
        let t = HookTarget::Syscall { number: 1 };
        inst.install_detour(t.clone(), addr, 0x2000).unwrap();
        assert!(inst.install_detour(t, addr, 0x3000).is_err());
    }

    #[test]
    fn test_dispatch_increments_hit_count() {
        let sink = make_sink();
        let mut inst = HookInstaller::new(Arc::clone(&sink));
        let addr = 0x1000u64;
        inst.seed_memory(addr, vec![0x90; 16]);
        let t = HookTarget::Syscall { number: 7 };
        inst.install_detour(t.clone(), addr, 0x2000).unwrap();
        let rec = SyscallInterceptRecord::new(7, 0, [0; 8]);
        inst.dispatch_hook(&t, HookDispatchRecord::Syscall(rec.clone()));
        inst.dispatch_hook(&t, HookDispatchRecord::Syscall(rec));
        assert_eq!(inst.hooks[&t.key()].hit_count, 2);
        assert_eq!(inst.total_hits(), 2);
    }

    // ── KernelTraceHooks high-level ──

    #[test]
    fn test_fire_syscall_and_drain() {
        let mut kth = KernelTraceHooks::new();
        let addr = 0x1000u64;
        kth.seed_memory(addr, vec![0x90; 8]);
        let target = HookTarget::Syscall { number: 0x0C };
        kth.register_handler(&target, 0x2000);
        kth.install(target, addr).unwrap();
        kth.fire_syscall(0x0C, 100, [1, 2, 3, 0, 0, 0, 0, 0], 0);
        let records = kth.drain_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), "syscall");
    }

    #[test]
    fn test_fire_api_call_and_drain() {
        let mut kth = KernelTraceHooks::new();
        let addr = 0x4000u64;
        kth.seed_memory(addr, vec![0x90; 8]);
        let target = HookTarget::ApiFunction {
            dll: "kernel32.dll".into(),
            name: "VirtualAlloc".into(),
        };
        kth.register_handler(&target, 0x5000);
        kth.install(target.clone(), addr).unwrap();
        let mut api_rec = ApiCallRecord::new("kernel32.dll", "VirtualAlloc", 1, 0x4000);
        api_rec.push_arg(ApiArg::Pointer(0));
        api_rec.push_arg(ApiArg::Uint(4096));
        api_rec.return_value = 0x1000_0000;
        kth.fire_api_call(api_rec);
        let records = kth.drain_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), "api");
    }

    #[test]
    fn test_no_handler_install_fails() {
        let mut kth = KernelTraceHooks::new();
        let addr = 0x1000u64;
        kth.seed_memory(addr, vec![0x90; 8]);
        let target = HookTarget::Syscall { number: 99 };
        assert!(kth.install(target, addr).is_err());
    }

    #[test]
    fn test_windows_syscall_names() {
        assert_eq!(windows_syscall_name(0x00), Some("NtQuerySystemInformation"));
        assert_eq!(windows_syscall_name(0x07), Some("NtCreateFile"));
        assert!(windows_syscall_name(0xFF).is_none());
    }

    #[test]
    fn test_active_hook_count() {
        let mut kth = KernelTraceHooks::new();
        for i in 0u64..3 {
            let addr = 0x1000 + i * 0x100;
            kth.seed_memory(addr, vec![0x90; 8]);
            let t = HookTarget::Syscall { number: u32::try_from(i).unwrap_or(u32::MAX) };
            kth.register_handler(&t, 0x8000 + i);
            kth.install(t, addr).unwrap();
        }
        assert_eq!(kth.active_hook_count(), 3);
    }
}
